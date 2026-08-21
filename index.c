//  JAB-036: index.c — the port of jab/index.hpp.
//  INDEX bindings (JS-022): the 3 native leaves an `abc.index` LSM stands on.
//  Each is pure marshalling over ONE abc/dog function — no format logic, no
//  held JS reference (rule #4).
//
//  Leaves (per lane):
//    _findge_<lane>(run, needleHi[, needleLo]) -> index of first elem >= needle
//    _seekrange_<lane>(runs[], loHi[, loLo], hiHi[, hiLo], cb) -> undefined
//    _compact_<lane>(runs[], out) -> [mergedElems, m]
//
//  DOG-027: runs[] is OLDEST-FIRST — HIT breaks equal heads by highest entry
//  pointer.  Not checkable here (bare views, no seqno); the handle asserts it.
#include "JABC.h"
#include "dog/WHIFF.h"  // wh128 (key,val) + wh128Z

//  jab pulls these in through hit.hpp (one TU); here each module instantiates
//  what it uses — the templates are `fun` (static inline), so no clash.
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#undef X
#define X(M, name) M##u64##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##wh128##name
#include "abc/HITx.h"
#undef X

//  QJAB-011: a lane element is a u64 or a wh128, so an odd-byteOffset subarray
//  would hand the leaves misaligned loads (SIGBUS on strict targets).  The same
//  8-byte gate pack.c:256:0X applies to its wh128 regions.
static b8 JABCLaneAligned(JSContext *ctx, void const *base) {
    if (((uintptr_t)base & 7u) == 0) return YES;
    JABCThrowStr(ctx, "index: the lane array is not 8-byte aligned");
    return NO;
}

//  A lane array's backing: base pointer + capacity in ELEMENTS (jab: cont.hpp).
static b8 JABCLaneArr(void **base, size_t *cap, JSContext *ctx,
                      JSValueConst arg, size_t esz) {
    u8 *b[4] = {};
    if (!JABCDataOf(b, ctx, arg)) return NO;
    if (!JABCLaneAligned(ctx, u8bData(b)[0])) return NO;
    *base = (void *)u8bData(b)[0];
    *cap = u8bDataLen(b) / esz;
    return YES;
}

//  `runs.length`, through the PTR-010 number gate (the ref is ours to drop).
static b8 JABCRunsLen(u64 *out, JSContext *ctx, JSValueConst arr) {
    JSValue lv = JABCGetProp(ctx, arr, "length");
    b8 ok = JABCu64Of(out, ctx, lv);
    JS_FreeValue(ctx, lv);
    return ok;
}

//  Read one lane element (the needle / lo / hi) from JS args.  wh128 takes two
//  BigInt args (key, val); u64 one BigInt.  `i` is the first arg index.
static b8 JABCIdxWh128(wh128 *out, JSContext *ctx, JSValueConst *argv,
                       size_t i) {
    return JABCBigU64Of(&out->key, ctx, argv[i]) &&
           JABCBigU64Of(&out->val, ctx, argv[i + 1]);
}
static b8 JABCIdxU64(u64 *out, JSContext *ctx, JSValueConst *argv, size_t i) {
    return JABCBigU64Of(out, ctx, argv[i]);
}

//  YES iff the cb's return value says "stop": exactly `false`, or "enough".
static b8 JABCIdxStop(JSContext *ctx, JSValueConst r) {
    if (JS_IsBool(r)) return JS_ToBool(ctx, r) ? NO : YES;
    if (!JS_IsString(r)) return NO;
    const char *s = JS_ToCString(ctx, r);
    if (s == NULL) return NO;
    b8 stop = strcmp(s, "enough") == 0 ? YES : NO;
    JS_FreeCString(ctx, s);
    return stop;
}

//  --- _findge_<lane>: binary-search a sorted run for the first elem >= needle.
//  Returns the index (0..count); JS reads the element + tests the bound.  ARGN
//  is how many JS args the needle spans (1 scalar / 2 pair); RDNEEDLE fills it.
#define FINDGE_LEAF(L, ARGN, RDNEEDLE)                                     \
    static JABC_FN(jfindge_##L) {                                          \
        if (argc < 1 + (ARGN)) JABC_THROW("_findge_" #L "(run, needle…)"); \
        void *base;                                                        \
        size_t cap;                                                        \
        if (!JABCLaneArr(&base, &cap, ctx, argv[0], sizeof(L))) JABC_FAIL; \
        L needle;                                                          \
        if (!RDNEEDLE) JABC_FAIL;                                          \
        L *bb = (L *)base;                                                 \
        L##cs run = {bb, bb + cap};                                        \
        L const *pos = L##sFindGE(run, &needle);                           \
        return JS_NewFloat64(ctx, (double)(size_t)(pos - bb));             \
    }

//  --- _seekrange_<lane>: heap of run slices -> [lo,hi) -> drain through cb.
//  cb is invoked per hit with the lane element (a BigInt, or a [key,val] pair);
//  its return is a stop signal: false / "enough" stops, truthy / undefined /
//  "more" continues, a throw aborts + propagates (mirror io.readdir(path,cb)).
//  EMIT builds the JS value for one element pointer `top`.
#define SEEKRANGE_LEAF(L, ARGN, RDLO, RDHI, EMIT)                             \
    static JABC_FN(jseekrange_##L) {                                          \
        if (argc < 2 + 2 * (ARGN) || !JS_IsObject(argv[0]))                   \
            JABC_THROW("_seekrange_" #L "(runs[], lo…, hi…, cb)");            \
        u64 N = 0;                                                            \
        if (!JABCRunsLen(&N, ctx, argv[0])) JABC_FAIL;                        \
        if (N > HIT_MAX_RUNS)                                                 \
            JABC_THROW(                                                       \
                "too many index runs: drop them and re-derive the index");    \
        L lo, hi;                                                             \
        if (!RDLO || !RDHI) JABC_FAIL;                                        \
        JSValueConst cb = argv[1 + 2 * (ARGN)];                               \
        if (!JS_IsFunction(ctx, cb))                                          \
            JABC_THROW("_seekrange: cb must be a function");                  \
        L##cs ent[HIT_MAX_RUNS];                                              \
        for (size_t i = 0; i < N; i++) {                                      \
            JSValue el = JS_GetPropertyUint32(ctx, argv[0], (uint32_t)i);     \
            u8 *bb[4] = {};                                                   \
            b8 ok = JABCDataOf(bb, ctx, el);                                  \
            JS_FreeValue(ctx, el);                                            \
            if (!ok) JABC_FAIL;                                               \
            u8 const *const *b = u8bDataC(bb);                                \
            if (!JABCLaneAligned(ctx, b[0])) JABC_FAIL; /* QJAB-011 */        \
            ent[i][0] = (const L *)b[0];                                      \
            ent[i][1] = (const L *)b[1];                                      \
        }                                                                     \
        L##css heap = {ent, ent + N};                                         \
        HIT##L##SeekRange(heap, &lo, &hi);                                    \
        /* DOG-027: drain via the pointer heap; entries stay oldest-first */  \
        L##csp slots[HIT_MAX_RUNS];                                           \
        L##csps ph;                                                           \
        if (HIT##L##Load(ph, slots, heap) != OK)                              \
            JABC_THROW(                                                       \
                "too many index runs: drop them and re-derive the index");    \
        while (!$empty(ph)) {                                                 \
            L const *top = (*ph[0])[0];                                       \
            JSValue el = EMIT;                                                \
            JSValue r = JS_Call(ctx, cb, JS_UNDEFINED, 1, &el);               \
            JS_FreeValue(ctx, el);                                            \
            if (JS_IsException(r)) JABC_FAIL;                                 \
            b8 stop = JABCIdxStop(ctx, r);                                    \
            JS_FreeValue(ctx, r);                                             \
            if (stop) break;                                                  \
            HIT##L##Step(ph);                                                 \
        }                                                                     \
        JABC_UNDEF;                                                           \
    }

//  --- _compact_<lane>: the 1/8 ladder.  `runs[]` is the oldest-first stack of
//  live run slices; `out` is a destination container sized to >= sum(runs).
//  Runs the merge, returns [mergedElems, m] (m youngest runs collapsed).
#define COMPACT_LEAF(L)                                                       \
    static JABC_FN(jcompact_##L) {                                            \
        if (argc < 2 || !JS_IsObject(argv[0]))                                \
            JABC_THROW("_compact_" #L "(runs[], out)");                       \
        u64 N = 0;                                                            \
        if (!JABCRunsLen(&N, ctx, argv[0])) JABC_FAIL;                        \
        if (N > HIT_MAX_RUNS)                                                 \
            JABC_THROW(                                                       \
                "too many index runs: drop them and re-derive the index");    \
        L##cs ent[HIT_MAX_RUNS];                                              \
        for (size_t i = 0; i < N; i++) {                                      \
            JSValue el = JS_GetPropertyUint32(ctx, argv[0], (uint32_t)i);     \
            u8 *bb[4] = {};                                                   \
            b8 ok = JABCDataOf(bb, ctx, el);                                  \
            JS_FreeValue(ctx, el);                                            \
            if (!ok) JABC_FAIL;                                               \
            u8 const *const *b = u8bDataC(bb);                                \
            if (!JABCLaneAligned(ctx, b[0])) JABC_FAIL; /* QJAB-011 */        \
            ent[i][0] = (const L *)b[0];                                      \
            ent[i][1] = (const L *)b[1];                                      \
        }                                                                     \
        u8 *db4[4] = {};                                                      \
        if (!JABCDataOf(db4, ctx, argv[1])) JABC_FAIL;                        \
        u8 *const *d = u8bData(db4);                                          \
        if (!JABCLaneAligned(ctx, d[0])) JABC_FAIL; /* QJAB-011 */            \
        L *base = (L *)d[0];                                                  \
        L##s into = {base, (L *)d[1]};                                        \
        L##css stack = {ent, ent + N};                                        \
        size_t before = $len(stack);                                          \
        if (HIT##L##Compact(stack, into) != OK)                               \
            JABC_THROW("_compact: out too small");                            \
        size_t m = before - $len(stack) + 1;                                  \
        size_t merged = (size_t)((*into) - base);                             \
        if (m < 2) merged = 0; /* nothing collapsed; out is untouched */      \
        return JABCPair(ctx, JS_NewFloat64(ctx, (double)merged),              \
                        JS_NewFloat64(ctx, (double)m));                       \
    }

//  --- wh128: (key,val); needle/lo/hi span 2 BigInt args.  Emit a [key,val]
//  pair; point/range/prefix all order by (key,val).
FINDGE_LEAF(wh128, 2, JABCIdxWh128(&needle, ctx, argv, 1))
SEEKRANGE_LEAF(wh128, 2, JABCIdxWh128(&lo, ctx, argv, 1),
               JABCIdxWh128(&hi, ctx, argv, 3),
               JABCPair(ctx, JABCBigU64(ctx, top->key),
                        JABCBigU64(ctx, top->val)))
COMPACT_LEAF(wh128)

//  --- u64: scalar; needle/lo/hi each one BigInt.  Emit a BigInt.
FINDGE_LEAF(u64, 1, JABCIdxU64(&needle, ctx, argv, 1))
SEEKRANGE_LEAF(u64, 1, JABCIdxU64(&lo, ctx, argv, 1),
               JABCIdxU64(&hi, ctx, argv, 2), JABCBigU64(ctx, *top))
COMPACT_LEAF(u64)

#define INDEX_REG(L)                                    \
    JABC_API_FN(abc, "_findge_" #L, jfindge_##L);       \
    JABC_API_FN(abc, "_seekrange_" #L, jseekrange_##L); \
    JABC_API_FN(abc, "_compact_" #L, jcompact_##L)

ok64 JABCInstallIndex(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    INDEX_REG(wh128);
    INDEX_REG(u64);
    JABC_API_END(abc);
    return OK;
}
