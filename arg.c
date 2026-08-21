//  arg.c — PTR-010: THE JS->C argument boundary.  A JS number is untrusted
//  input, never a size_t: `(size_t)JS_ToFloat64(...)` turns the `-1` that
//  git.pack leaves in `_rec` after a failed seek into SIZE_MAX, and the
//  `{c[0] + off, c[1]}` that follows starts a slice one byte BELOW the
//  mapping with its head past its term — no callee bounds check can see it.
//  Every conversion goes through the gates here; the arithmetic is abc's.
//  JAB-036: the funnel's qjs half lives here too (refs, throws, registration).
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

JSValue JABCBytesNoCopy(JSContext *ctx, u8 *p, size_t n,
                        JSFreeArrayBufferDataFunc *freef, void *opaque) {
    return JS_NewUint8Array(ctx, p, n, freef, opaque, false);
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

//  --- number gates: the only JS_ToFloat64 callers in the bindings ----------

//  A JS number -> u64.  Rejects NaN (also a missing argument), +-Inf,
//  negative, fractional and anything past 2^53-1, where a double stops
//  counting integers exactly.  The value dies here, while it still prints
//  as itself and not as 18446744073709551615.
b8 JABCu64Of(u64 *out, JSContext *ctx, JSValueConst arg) {
    double d = 0;
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
    size_t off = 0;
    if (!JABCOffOf(&off, u8bIdleC(buf), ctx, arg)) return NO;
    if (u8bFed(buf, off) != OK) {
        JABCThrowStr(ctx, "offset is past the end of the buffer");
        return NO;
    }
    return YES;
}

//  A JS Buf object ({bytes, _data, _idle} — buf.c) as a real u8b, cursor and
//  all.  The two cursors are JS numbers: gated, then checked against each
//  other and the view (PAST <= DATA <= IDLE <= end) before any read.
b8 JABCBufOf(u8b buf, JSContext *ctx, JSValueConst arg) {
    if (!JS_IsObject(arg)) {
        JABCThrowStr(ctx, "expected a Buf");
        return NO;
    }
    JSValue bytes = JABCGetProp(ctx, arg, "bytes");
    b8 ok = JABCIdleOf(buf, ctx, bytes);
    JS_FreeValue(ctx, bytes);
    if (!ok) return NO;
    u64 data = 0, idle = 0;
    JSValue dv = JABCGetProp(ctx, arg, "_data");
    ok = JABCu64Of(&data, ctx, dv);
    JS_FreeValue(ctx, dv);
    if (!ok) return NO;
    JSValue iv = JABCGetProp(ctx, arg, "_idle");
    ok = JABCu64Of(&idle, ctx, iv);
    JS_FreeValue(ctx, iv);
    if (!ok) return NO;
    //  IDLE first (it is the outer bound), then DATA inside what is left.
    if (data > idle || u8bFed(buf, (size_t)idle) != OK ||
        u8bUsed(buf, (size_t)data) != OK) {
        JABCThrowStr(ctx, "the buffer's cursor is out of range");
        return NO;
    }
    return YES;
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
