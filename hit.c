//  JAB-036: hit.c — the port of jab/hit.hpp.
//  HIT bindings: bulk ops over SORTED runs (typed arrays), not a container.
//   - sort:      in-place sort of a container's live [0,size) by the lane Z
//                (QSORTx <lane>sSort).
//   - merge:     k-way sorted, deduplicated union of N runs (HITx Merge).
//   - intersect: values present in ALL N runs (HITx Intersect).
//  The heap-of-iterators is a tiny stack array (<= HIT_MAX_RUNS runs, abc/
//  HITx.h; above it the leaf throws — DOG-027); inputs stay alive as JS args;
//  the output is a fresh engine-owned typed array.
//
//  Leaves: _sort_<lane>(arr, size)
//          _merge_<lane>(runs[]) / _isect_<lane>(runs[]) -> Uint8Array
#include "JABC.h"
#include "abc/KV.h"
#include "abc/SHA.h"
#include "dog/WHIFF.h"
#include "dog/git/SHA1.h"

//  DOG-027: the per-lane csSwap supply block is gone — HIT swaps entry
//  POINTERS now, so csSwap is no longer an instantiation prerequisite.

//  QSORTx (sSort) ONLY for lanes abc/dog don't already instantiate.
//  Already present: u8/u16/u32/u64 (INT.h), kv64 (KV.h).  Missing → add:
#define X(M, name) M##kv32##name
#include "abc/QSORTx.h"
#undef X
#define X(M, name) M##wh64##name
#include "abc/QSORTx.h"
#undef X
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#undef X
#define X(M, name) M##sha1##name
#include "abc/QSORTx.h"
#undef X
#define X(M, name) M##sha256##name
#include "abc/QSORTx.h"
#undef X

//  HITx (Merge/Intersect) for every lane — not pre-instantiated anywhere.
#define X(M, name) M##u8##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##u16##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##u32##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##u64##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##kv32##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##kv64##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##wh64##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##wh128##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##sha1##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##sha256##name
#include "abc/HITx.h"
#undef X

//  A lane array's backing: base pointer + capacity in ELEMENTS (jab: cont.hpp).
static b8 JABCLaneArr(void **base, size_t *cap, JSContext *ctx,
                      JSValueConst arg, size_t esz) {
    u8 *b[4] = {};
    if (!JABCDataOf(b, ctx, arg)) return NO;
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

//  The merge output's backing: malloc'd here, owned by the ArrayBuffer from
//  here on — the engine calls this back when the last view dies.
static void JABCHitFree(JSRuntime *rt, void *opaque, void *ptr) { free(ptr); }

//  sort leaf: sort the live [0,n) region in place by the lane Z.
#define SORT_LEAF(L)                                                          \
    static JABC_FN(jsort_##L) {                                               \
        /* JS-101: argc guard — short-armed calls must throw, not read OOB */ \
        if (argc < 2) JABC_THROW("_sort_" #L "(arr, size)");                  \
        u64 n = 0;                                                            \
        if (!JABCu64Of(&n, ctx, argv[1])) JABC_FAIL; /* QJAB-005: size 1st */ \
        void *base;                                                           \
        size_t cap;                                                           \
        if (!JABCLaneArr(&base, &cap, ctx, argv[0], sizeof(L))) JABC_FAIL;    \
        if (n > cap) n = cap;                                                 \
        L *bb = (L *)base;                                                    \
        L##s sl = {bb, bb + n};                                               \
        L##sSort(sl);                                                         \
        JABC_UNDEF;                                                           \
    }

//  Shared k-way run: build the iterator heap from a JS array of typed-array
//  runs, then HIT Merge (isect=0) or Intersect (isect=1) into a fresh output.
#define HIT_RUN(L)                                                             \
    static JSValue JABChit_##L(JSContext *ctx, int argc, JSValueConst *argv,    \
                               int isect) {                                     \
        if (argc < 1 || !JS_IsObject(argv[0]))                                  \
            JABC_THROW("merge/intersect([runs])");                              \
        u64 N = 0;                                                              \
        if (!JABCRunsLen(&N, ctx, argv[0])) JABC_FAIL;                          \
        /* DOG-027: one cap, and above it the leaf just throws */               \
        if (N > HIT_MAX_RUNS)                                                   \
            JABC_THROW("too many index runs: drop them and re-derive the index");\
        /* QJAB-005: COLLECT the runs, then unwrap — an element getter is JS, \
           and JS mid-loop can transfer() a run already taken.  rv[] holds the \
           refs until the last read of ent[] below. */                          \
        JSValue rv[HIT_MAX_RUNS];                                               \
        u8 const *rb[HIT_MAX_RUNS];                                             \
        size_t rn[HIT_MAX_RUNS];                                                \
        if (!JABCRunsOf(rb, rn, rv, N, ctx, argv[0])) JABC_FAIL;                \
        L##cs ent[HIT_MAX_RUNS];                                                \
        size_t total = 0;                                                       \
        for (size_t i = 0; i < N; i++) {                                        \
            ent[i][0] = (const L *)rb[i];                                       \
            ent[i][1] = (const L *)(rb[i] + rn[i]);                             \
            total += rn[i] / sizeof(L);                                         \
        }                                                                       \
        /* destination given (argv[1]) -> write in place, return the count; the \
           caller's container is sized to the Sum upper bound and trimmed on    \
           close (abc.book). */                                                 \
        if (argc >= 2 && JS_GetTypedArrayType(argv[1]) >= 0) {                  \
            u8 *db4[4] = {};                                                    \
            if (!JABCDataOf(db4, ctx, argv[1])) {                               \
                JABCRunsFree(rv, N, ctx);                                       \
                JABC_FAIL;                                                      \
            }                                                                   \
            u8 *const *d = u8bData(db4);                                        \
            ok64 mo = OK;                                                       \
            L *db = (L *)d[0];                                                  \
            /* JAB-009: ABC-015 drains take a BOUNDED slice (head advances past \
               the output), not a bare cursor */                                \
            L##s dst = {db, (L *)d[1]};                                         \
            if ((size_t)$len(d) < total * sizeof(L)) {                          \
                mo = NOROOM;                                                    \
            } else if (N > 0) {                                                 \
                L##css heap = {ent, ent + N};                                   \
                mo = isect ? HIT##L##Intersect(heap, dst, N)                    \
                           : HIT##L##Merge(heap, dst);                          \
            }                                                                   \
            JABCRunsFree(rv, N, ctx);                                           \
            if (mo != OK) JABC_THROW("merge: out too small");                   \
            return JS_NewFloat64(ctx, (double)(size_t)(dst[0] - db));           \
        }                                                                       \
        size_t bytes = total * sizeof(L);                                       \
        u8 *mem = (u8 *)malloc(bytes + 1);   /* +1: malloc(0) is not a buffer */\
        if (mem == NULL) {                                                      \
            JABCRunsFree(rv, N, ctx);                                           \
            JABC_THROW("merge: out of memory");                                 \
        }                                                                       \
        L *ob = (L *)mem;                                                       \
        /* JAB-009: bounded ABC-015 drain slice; total is the exact upper bound*/\
        L##s op = {ob, ob + total};                                             \
        if (N > 0) {                                                            \
            L##css heap = {ent, ent + N};                                       \
            ok64 mo = isect ? HIT##L##Intersect(heap, op, N)                    \
                            : HIT##L##Merge(heap, op);                          \
            if (mo != OK) {                                                     \
                JABCRunsFree(rv, N, ctx);                                       \
                free(mem);                                                      \
                JABC_THROW("merge: out too small");                             \
            }                                                                   \
        }                                                                       \
        JABCRunsFree(rv, N, ctx);                                               \
        size_t cnt = (size_t)(op[0] - ob);                                      \
        JSValue whole = JABCBytesNoCopy(ctx, mem, bytes, JABCHitFree, NULL);    \
        if (JS_IsException(whole)) {                                            \
            free(mem);                                                          \
            JABC_FAIL;                                                          \
        }                                                                       \
        JSValue view = JABCSubView(ctx, whole, 0, cnt * sizeof(L));             \
        JS_FreeValue(ctx, whole);                                               \
        return view;                                                            \
    }                                                                           \
    static JABC_FN(jmerge_##L) { return JABChit_##L(ctx, argc, argv, 0); }      \
    static JABC_FN(jisect_##L) { return JABChit_##L(ctx, argc, argv, 1); }

#define HIT_DEF(L) SORT_LEAF(L) HIT_RUN(L)

HIT_DEF(u8)
HIT_DEF(u16)
HIT_DEF(u32)
HIT_DEF(u64)
HIT_DEF(kv32)
HIT_DEF(kv64)
HIT_DEF(wh64)
HIT_DEF(wh128)
HIT_DEF(sha1)
HIT_DEF(sha256)

#define HIT_REG(L)                                     \
    JABC_API_FN(abc, "_sort_" #L, jsort_##L);          \
    JABC_API_FN(abc, "_merge_" #L, jmerge_##L);        \
    JABC_API_FN(abc, "_isect_" #L, jisect_##L)

ok64 JABCInstallHit(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    HIT_REG(u8);
    HIT_REG(u16);
    HIT_REG(u32);
    HIT_REG(u64);
    HIT_REG(kv32);
    HIT_REG(kv64);
    HIT_REG(wh64);
    HIT_REG(wh128);
    HIT_REG(sha1);
    HIT_REG(sha256);
    JABC_API_END(abc);
    return OK;
}
