//  arg.c — PTR-010: THE JS->C argument boundary.  A JS number is untrusted
//  input, never a size_t: `(size_t)JS_ToFloat64(...)` turns the `-1` that
//  git.pack leaves in `_rec` after a failed seek into SIZE_MAX, and the
//  `{c[0] + off, c[1]}` that follows starts a slice one byte BELOW the
//  mapping with its head past its term — no callee bounds check can see it.
//  Every conversion goes through the gates here; the arithmetic is abc's.
//  JAB-036: the funnel's qjs half lives here too (refs, throws, registration).
//
//  QJAB-005 — THE RE-ENTRY INVARIANT.  A base pointer taken out of a typed
//  array (JABCViewOf and its JABCDataOf/JABCIdleOf wrappers) is good only
//  until JS runs again: `ArrayBuffer.prototype.transfer()` detaches and FREES
//  the store, a resizable buffer's `.resize()` reallocates it, and either one
//  leaves the leaf writing into dead heap.  So: ONCE A VIEW IS UNWRAPPED, NO
//  LEAF MAY LET JS RUN BEFORE IT IS DONE WITH THE POINTER.  Three JS re-entries
//  hide in code that looks like plain marshalling, and each has ONE answer:
//
//    valueOf / Symbol.toPrimitive on a number arg — the number gates below
//      REFUSE an object outright, so no JS_ToFloat64/JS_ToInt64Ext here can
//      re-enter.  A number crossing this boundary is a number.
//    a property getter or a Proxy trap — JABCGetProp / JS_GetPropertyUint32.
//      Read every property BEFORE the first unwrap; for an array of runs use
//      JABCRunsOf, which collects the elements first and unwraps after.
//    an explicit callback — JS_Call.  A leaf that calls back into JS while it
//      still holds a base RE-ASSERTS every such view with JABCViewSame after
//      each call, and refuses to go on if one moved or was detached.
//
//  `grep JABCViewSame` lists the leaves that cannot reorder their way out.
#include "JABC.h"

//  --- errors ---------------------------------------------------------------

JSValue JABCThrowError(JSContext *ctx, const char *msg) {
    JSValue e = JS_NewError(ctx);
    JS_SetPropertyStr(ctx, e, "message", JS_NewString(ctx, msg));
    return JS_Throw(ctx, e);
}

//  The gates throw the message VALUE (a bare string), as arg.cpp does — an
//  Error would change String(e) for every PTR-010 refusal.
JSValue JABCThrowStr(JSContext *ctx, const char *msg) {
    return JS_Throw(ctx, JS_NewString(ctx, msg));
}

//  --- leaf registration (JAB-008: the BASS bracket) ------------------------

#define JABC_LEAF_MAX 512
static JSCFunction *JABC_LEAVES[JABC_LEAF_MAX];
static int JABC_LEAF_N;

//  The C twin of jab's JABCBassGuarded<F> template: one trampoline, the leaf
//  picked by `magic`, so no leaf leaks a BASS carve set (main maps ABC_BASS
//  once, no call() rewinds).
static JSValue JABCBassTrampoline(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv, int magic) {
    u8 *data = ABC_BASS[1];
    u8 *idle = ABC_BASS[2];
    JSValue r = JABC_LEAVES[magic](ctx, this_val, argc, argv);
    ABC_BASS[1] = data;
    ABC_BASS[2] = idle;
    return r;
}

void JABCApiFn(JSContext *ctx, JSValueConst o, const char *name,
               JSCFunction *f) {
    if (JABC_LEAF_N >= JABC_LEAF_MAX) {
        fprintf(stderr, "too many native functions to install\n");
        return;
    }
    int magic = JABC_LEAF_N++;
    JABC_LEAVES[magic] = f;
    JS_SetPropertyStr(ctx, o, name,
                      JS_NewCFunctionMagic(ctx, JABCBassTrampoline, name, 0,
                                           JS_CFUNC_generic_magic, magic));
}

//  --- values ---------------------------------------------------------------

JSValue JSOfCString(const char *str) {
    return JS_NewString(JABC_CONTEXT, str);
}

JSValue JABCStrOfSlice(JSContext *ctx, u8cs s) {
    return JS_NewStringLen(ctx, (const char *)s[0], $len(s));
}

JSValue JABCBigU64(JSContext *ctx, u64 v) { return JS_NewBigUint64(ctx, v); }

b8 JABCBigU64Of(u64 *out, JSContext *ctx, JSValueConst arg) {
    int64_t v = 0;
    if (!JABCScalar(ctx, arg)) return NO;  //  QJAB-005: no valueOf re-entry
    if (JS_ToInt64Ext(ctx, &v, arg) < 0) return NO;
    *out = (u64)v;
    return YES;
}

JSValue JABCPair(JSContext *ctx, JSValue a, JSValue b) {
    JSValue e[2] = {a, b};
    return JS_NewArrayFrom(ctx, 2, e);
}

JSValue JABCBlob(JSContext *ctx, const u8 *data, size_t n) {
    return JS_NewUint8ArrayCopy(ctx, data, n);
}

//  quickjs-ng 0.16 replaced the free-style ArrayBuffer callback with a
//  realloc-style one (size==0 means free).  Bridge a quickjab free-style
//  freef+opaque pair to it; the bridge record dies with the buffer.
typedef struct {
    JABCFreeFunc *freef;
    void *opaque;
} JABCFreeBridge;

static void *JABCReallocBridge(JSRuntime *rt, void *opaque, void *ptr,
                               size_t size) {
    JABCFreeBridge *b = (JABCFreeBridge *)opaque;
    if (size != 0) return ptr;  //  fixed-length view: no resize, keep as is
    if (b) {
        if (b->freef) b->freef(rt, b->opaque, ptr);
        free(b);
    }
    return NULL;
}

JSValue JABCBytesNoCopy(JSContext *ctx, u8 *p, size_t n, JABCFreeFunc *freef,
                        void *opaque) {
    if (freef == NULL)  //  unmanaged rodata: quickjs must not free/resize it
        return JS_NewUint8Array(ctx, p, n, NULL, NULL, false);
    JABCFreeBridge *b = (JABCFreeBridge *)malloc(sizeof(*b));
    if (b == NULL) return JS_ThrowOutOfMemory(ctx);
    b->freef = freef;
    b->opaque = opaque;
    JSValue v = JS_NewUint8Array(ctx, p, n, JABCReallocBridge, b, false);
    if (JS_IsException(v)) free(b);  //  wrapper did not take ownership
    return v;
}

JSValue JABCSubView(JSContext *ctx, JSValueConst view, size_t off,
                    size_t len) {
    size_t voff = 0, vlen = 0, esz = 0;
    JSValue buf = JS_GetTypedArrayBuffer(ctx, view, &voff, &vlen, &esz);
    if (JS_IsException(buf)) return JS_EXCEPTION;
    JSValue a[3] = {buf, JS_NewInt64(ctx, (int64_t)(voff + off)),
                    JS_NewInt64(ctx, (int64_t)len)};
    JSValue r = JS_NewTypedArray(ctx, 3, a, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(ctx, a[0]);
    JS_FreeValue(ctx, a[1]);
    JS_FreeValue(ctx, a[2]);
    return r;
}

//  --- JS object properties (the JABCSet/JABCGet pair, shared) -------------

JSValue JABCGetProp(JSContext *ctx, JSValueConst o, const char *name) {
    return JS_GetPropertyStr(ctx, o, name);
}

void JABCSetProp(JSContext *ctx, JSValueConst o, const char *name, JSValue v) {
    JS_SetPropertyStr(ctx, o, name, v);
}

//  --- number gates: where a JS number becomes a C one ----------------------

//  QJAB-005: the gate in front of the gates.  `JS_ToFloat64` / `JS_ToInt64Ext`
//  on an OBJECT run its `valueOf` / `Symbol.toPrimitive` — arbitrary JS, in the
//  middle of a leaf that may already hold a raw ArrayBuffer base.  A number arg
//  is a number (or a string, or a BigInt): a primitive, coerced in C.  Refusing
//  the object here closes the valueOf re-entry for EVERY gate below at once.
b8 JABCScalar(JSContext *ctx, JSValueConst arg) {
    if (!JS_IsObject(arg)) return YES;
    JABCThrowStr(ctx, "expected a number, not an object");
    return NO;
}

//  A JS number -> u64.  Rejects NaN (also a missing argument), +-Inf,
//  negative, fractional and anything past 2^53-1, where a double stops
//  counting integers exactly.  The value dies here, while it still prints
//  as itself and not as 18446744073709551615.
b8 JABCu64Of(u64 *out, JSContext *ctx, JSValueConst arg) {
    double d = 0;
    if (!JABCScalar(ctx, arg)) return NO;  //  QJAB-005: no valueOf re-entry
    if (JS_ToFloat64(ctx, &d, arg) < 0) return NO;
    if (!(d >= 0) || d > 9007199254740991.0 || d != (double)(u64)d) {
        JABCThrowStr(ctx, "expected a whole non-negative number");
        return NO;
    }
    *out = (u64)d;
    return YES;
}

//  Where a NEGATIVE sentinel is part of the contract (pack's baseOff = -1
//  means "no base").  Still rejects NaN, +-Inf and fractions — a sentinel is
//  one specific value, not a licence to skip the gate.
b8 JABCi64Of(i64 *out, JSContext *ctx, JSValueConst arg) {
    double d = 0;
    if (!JABCScalar(ctx, arg)) return NO;  //  QJAB-005: no valueOf re-entry
    if (JS_ToFloat64(ctx, &d, arg) < 0) return NO;
    if (!(d >= -9007199254740991.0 && d <= 9007199254740991.0) ||
        d != (double)(i64)d) {
        JABCThrowStr(ctx, "expected a whole number");
        return NO;
    }
    *out = (i64)d;
    return YES;
}

b8 JABCu32Of(u32 *out, JSContext *ctx, JSValueConst arg) {
    u64 v = 0;
    if (!JABCu64Of(&v, ctx, arg)) return NO;
    if (v > 0xffffffffUL) {
        JABCThrowStr(ctx, "number does not fit 32 bits");
        return NO;
    }
    *out = (u32)v;
    return YES;
}

//  QJAB-011: a file descriptor.  JS_ToInt32 turns NaN (a missing argument) and
//  +-Inf into 0 — i.e. STDIN — so every fd leaf gates here instead: whole,
//  non-negative, and inside the kernel's own descriptor range.
b8 JABCFdOf(int *out, JSContext *ctx, JSValueConst arg) {
    u64 v = 0;
    if (!JABCu64Of(&v, ctx, arg)) return NO;
    if (v > 0x7fffffffUL) {
        JABCThrowStr(ctx, "expected a file descriptor");
        return NO;
    }
    *out = (int)v;
    return YES;
}

b8 JABCu8Of(u8 *out, JSContext *ctx, JSValueConst arg) {
    u64 v = 0;
    if (!JABCu64Of(&v, ctx, arg)) return NO;
    if (v > 0xffUL) {
        JABCThrowStr(ctx, "number does not fit a byte");
        return NO;
    }
    *out = (u8)v;
    return YES;
}

//  --- buffers: what actually crosses the boundary -------------------------

//  Shared typed-array unwrap: the VIEW's range (the ArrayBuffer base is not
//  the view's start — a subarray shares the buffer, so a view with
//  byteOffset > 0 would otherwise read the wrong bytes).
b8 JABCViewOf(u8 **base, size_t *len, JSContext *ctx, JSValueConst arg) {
    if (JS_GetTypedArrayType(arg) < 0) {
        JABCThrowStr(ctx, "expected a typed array");
        return NO;
    }
    size_t off = 0, n = 0, esz = 0;
    JSValue ab = JS_GetTypedArrayBuffer(ctx, arg, &off, &n, &esz);
    if (JS_IsException(ab)) return NO;
    size_t whole = 0;
    u8 *p = JS_GetArrayBuffer(ctx, &whole, ab);
    JS_FreeValue(ctx, ab);
    //  A detached/neutered ArrayBuffer yields a NULL bytes ptr (len may be 0).
    if (p == NULL && n != 0) {
        JABCThrowStr(ctx, "detached buffer");
        return NO;
    }
    *base = p + off;
    *len = n;
    return YES;
}

//  QJAB-005: THE re-validate.  A leaf that hands control back to JS (a
//  callback — the one re-entry it cannot reorder away) re-asserts here that
//  the view it still holds a base into is the SAME memory: not detached, not
//  moved by a resize, not swapped for another buffer.  It throws in plain
//  words on a mismatch, so a leaf just stops.  `base`/`len` are what the
//  matching JABCViewOf/JABCDataOf/JABCIdleOf returned.
b8 JABCViewSame(JSContext *ctx, JSValueConst arg, u8 const *base, size_t len) {
    u8 *now = NULL;
    size_t n = 0;
    if (!JABCViewOf(&now, &n, ctx, arg)) return NO;
    if (now != base || n != len) {
        JABCThrowStr(ctx, "the buffer moved while the call was running");
        return NO;
    }
    return YES;
}

void JABCRunsFree(JSValue *view, size_t n, JSContext *ctx) {
    for (size_t i = 0; i < n; i++) {
        JS_FreeValue(ctx, view[i]);
        view[i] = JS_UNDEFINED;
    }
}

//  QJAB-005: a JS array of `n` typed-array runs — COLLECTED, then unwrapped.
//  `JS_GetPropertyUint32` fires a getter or a Proxy trap, i.e. JS, so a leaf
//  that interleaved the reads with the unwraps would let element i+1's getter
//  transfer() element i's store.  Two passes, and the second runs no JS at
//  all.  `view[]` KEEPS a ref to every run — a Proxy hands out fresh arrays,
//  so dropping them early would free the very memory base[] points at.  The
//  caller JABCRunsFree's them once it is done reading the runs.
b8 JABCRunsOf(u8 const **base, size_t *len, JSValue *view, size_t n,
              JSContext *ctx, JSValueConst arr) {
    for (size_t i = 0; i < n; i++) view[i] = JS_UNDEFINED;
    for (size_t i = 0; i < n; i++) {  //  pass 1: JS may run here
        view[i] = JS_GetPropertyUint32(ctx, arr, (uint32_t)i);
        if (JS_IsException(view[i])) {
            view[i] = JS_UNDEFINED;
            JABCRunsFree(view, n, ctx);
            return NO;
        }
    }
    for (size_t i = 0; i < n; i++) {  //  pass 2: no JS runs below
        u8 *b = NULL;
        size_t l = 0;
        if (!JABCViewOf(&b, &l, ctx, view[i])) {
            JABCRunsFree(view, n, ctx);
            return NO;
        }
        base[i] = b;
        len[i] = l;
    }
    return YES;
}

//  A read source: the whole view is DATA, IDLE empty.  Read it with
//  u8bDataC(buf) and walk it with JABCBufAt — never with a pointer.
b8 JABCDataOf(u8b buf, JSContext *ctx, JSValueConst arg) {
    u8 *base = NULL;
    size_t len = 0;
    if (!JABCViewOf(&base, &len, ctx, arg)) return NO;
    u8 **b = (u8 **)buf;  //  the bMap recipe: creators cast
    b[0] = b[1] = base;
    b[2] = b[3] = base + len;
    if (!u8bOK(buf)) {
        JABCThrowStr(ctx, "bad buffer bounds");
        return NO;
    }
    return YES;
}

//  A write target: the whole view is IDLE, DATA empty.  Fill it through
//  u8bIdle(buf) / u8bFeed; the bytes produced are u8bDataLen(buf), never a
//  pointer subtraction at the call site.
b8 JABCIdleOf(u8b buf, JSContext *ctx, JSValueConst arg) {
    u8 *base = NULL;
    size_t len = 0;
    if (!JABCViewOf(&base, &len, ctx, arg)) return NO;
    u8 **b = (u8 **)buf;  //  the bMap recipe: creators cast
    b[0] = b[1] = b[2] = base;
    b[3] = base + len;
    if (!u8bOK(buf)) {
        JABCThrowStr(ctx, "bad buffer bounds");
        return NO;
    }
    return YES;
}

//  A JS-given position INSIDE a slice: the number gate + a bounds check
//  (== length is the empty tail, legal).  Errors read in plain words.
b8 JABCOffOf(size_t *out, u8csc whole, JSContext *ctx, JSValueConst arg) {
    u64 v = 0;
    if (!JABCu64Of(&v, ctx, arg)) return NO;
    if (v > (u64)u8csLen(whole)) {
        JABCThrowStr(ctx, "offset is past the end of the buffer");
        return NO;
    }
    *out = (size_t)v;
    return YES;
}

//  Position a read source's DATA at a JS-given offset: the gate above plus
//  u8bUsed, which returns MISS past the border.  The consumed prefix becomes
//  PAST, so the callee that needs the WHOLE buffer (an OFS-delta chase reads
//  backwards) still has it — u8bDataC for the record, u8bcs for the log.
b8 JABCBufAt(u8b buf, JSContext *ctx, JSValueConst arg) {
    size_t off = 0;
    if (!JABCOffOf(&off, u8bDataC(buf), ctx, arg)) return NO;
    if (u8bUsed(buf, off) != OK) {
        JABCThrowStr(ctx, "offset is past the end of the buffer");
        return NO;
    }
    return YES;
}

//  The write-side twin of JABCBufAt: place a write target's DATA/IDLE
//  boundary at a JS-given offset, so the callee fills u8bIdle(buf) from
//  there and the bytes it produced are u8bDataLen(buf).
b8 JABCBufFed(u8b buf, JSContext *ctx, JSValueConst arg) {
    u64 off = 0;
    if (!JABCu64Of(&off, ctx, arg)) return NO;
    return JABCBufFedAt(buf, ctx, off);
}

//  QJAB-005: the ALREADY-GATED half of JABCBufFed, for a leaf that coerces
//  its offset arg BEFORE unwrapping the view it indexes into (zip.c) — the
//  gate cannot run JS any more, but the ordering says so at the call site.
b8 JABCBufFedAt(u8b buf, JSContext *ctx, u64 off) {
    if (off > (u64)u8csLen(u8bIdleC(buf)) || u8bFed(buf, (size_t)off) != OK) {
        JABCThrowStr(ctx, "offset is past the end of the buffer");
        return NO;
    }
    return YES;
}

//  A JS Buf object ({bytes, _data, _idle} — buf.c) as a real u8b, cursor and
//  all.  The two cursors are JS numbers: gated, then checked against each
//  other and the view (PAST <= DATA <= IDLE <= end) before any read.
//  QJAB-005: the CURSORS ARE READ FIRST.  `_data`/`_idle` are properties, and
//  a property is a getter away from being arbitrary JS — reading them after
//  the `bytes` unwrap would let one of them transfer() the store this very
//  u8b points at.  `view` (when asked for) keeps the OWNED `bytes` value, so a
//  leaf that later calls back into JS can JABCViewSame the very same view
//  instead of re-reading the property and running the getter again.
static b8 JABCBufIn(u8b buf, JSValue *view, JSContext *ctx, JSValueConst arg) {
    if (view != NULL) *view = JS_UNDEFINED;
    if (!JS_IsObject(arg)) {
        JABCThrowStr(ctx, "expected a Buf");
        return NO;
    }
    u64 data = 0, idle = 0;
    JSValue dv = JABCGetProp(ctx, arg, "_data");
    b8 ok = JABCu64Of(&data, ctx, dv);
    JS_FreeValue(ctx, dv);
    if (!ok) return NO;
    JSValue iv = JABCGetProp(ctx, arg, "_idle");
    ok = JABCu64Of(&idle, ctx, iv);
    JS_FreeValue(ctx, iv);
    if (!ok) return NO;
    JSValue bytes = JABCGetProp(ctx, arg, "bytes");
    ok = JABCIdleOf(buf, ctx, bytes);  //  no JS below this line
    if (!ok || view == NULL)
        JS_FreeValue(ctx, bytes);
    else
        *view = bytes;
    if (!ok) return NO;
    //  IDLE first (it is the outer bound), then DATA inside what is left.
    if (data > idle || u8bFed(buf, (size_t)idle) != OK ||
        u8bUsed(buf, (size_t)data) != OK) {
        JABCThrowStr(ctx, "the buffer's cursor is out of range");
        if (view != NULL) {
            JS_FreeValue(ctx, *view);
            *view = JS_UNDEFINED;
        }
        return NO;
    }
    return YES;
}

b8 JABCBufOf(u8b buf, JSContext *ctx, JSValueConst arg) {
    return JABCBufIn(buf, NULL, ctx, arg);
}

b8 JABCBufOfKeep(u8b buf, JSValue *view, JSContext *ctx, JSValueConst arg) {
    return JABCBufIn(buf, view, ctx, arg);
}

//  Hand the advanced cursors back to the JS Buf — a failed run still ate
//  what it ate, so callers write back on every exit path.
void JABCBufBack(JSContext *ctx, JSValueConst bo, u8b buf) {
    JABCSetProp(ctx, bo, "_data", JS_NewFloat64(ctx, (double)u8bPastLen(buf)));
    JABCSetProp(ctx, bo, "_idle", JS_NewFloat64(ctx, (double)u8bBusyLen(buf)));
}

//  Copy a JS-string path argument into a NUL-terminated path buffer.  The
//  cap matches jab's page-sized scratch (a longer path is NOROOM, not a cut).
ok64 JABCPath(path8b path, JSContext *ctx, JSValueConst arg) {
    if (!JS_IsString(arg)) return BADARG;
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, arg);
    if (s == NULL) return BADARG;
    if (len < 1 || len + 1 >= PAGESIZE) {
        JS_FreeCString(ctx, s);
        return NOROOM;
    }
    u8cs src = {(u8 const *)s, (u8 const *)s + len};
    //  QJAB-011: an interior NUL passes the length check above, then the OS
    //  truncates the C path — "safe\0/x" would open "safe".  Refuse the string.
    a_dup(u8c, scan, src);
    if (u8csFind(scan, 0) == OK) {
        JS_FreeCString(ctx, s);
        return BADARG;
    }
    ok64 o = u8bFeed(path, src);
    JS_FreeCString(ctx, s);
    if (o != OK) return o;
    PATHu8bTerm(path);
    return OK;
}
