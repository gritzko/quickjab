//  JAB-036: heap.c — the port of jab/heap.hpp.
//  HEAP bindings: a binary heap living in a JS-owned typed array's DATA
//  region [0, size).  Each leaf forms a stack-local lane buffer over the
//  backing memory and runs the abc HEAP<lane> op (sift in C, one boundary
//  crossing per call).  Native ordering only — no JS comparator.
//
//  Leaves: _heap_<lane>_push(arr, size, v[, val]) -> newsize
//          _heap_<lane>_pop(arr, size)            -> value | [key,val]
//          _heap_<lane>_feed(arr, size, entries)  -> newsize   (JS-106 bulk)
//  The cursor (size) lives in JS (buffer.watermark); native gets it as an arg.
#include "JABC.h"
#include "abc/KV.h"        // kv32/kv64 (key,val) + Z
#include "abc/SHA.h"       // sha256 (32-byte blob) + sha256Z + Bx slice
#include "dog/WHIFF.h"     // wh64 (=u64) + Z ; wh128 (key,val) + Z
#include "dog/git/SHA1.h"  // sha1 (20-byte blob) + sha1Z + Bx slice

//  Instantiate the HEAP template for each lane (js-side; abc untouched).
#define X(M, name) M##u8##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##u16##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##u32##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##u64##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##kv32##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##kv64##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##wh64##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##wh128##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##sha1##name
#include "abc/HEAPx.h"
#undef X
#define X(M, name) M##sha256##name
#include "abc/HEAPx.h"
#undef X

//  A lane array's backing: base pointer + capacity in ELEMENTS (offset-
//  adjusted via JABCDataOf).  `esz` is sizeof(lane).  (jab: cont.hpp)
static b8 JABCLaneArr(void **base, size_t *cap, JSContext *ctx,
                      JSValueConst arg, size_t esz) {
    u8 *b[4] = {};
    if (!JABCDataOf(b, ctx, arg)) return NO;
    *base = (void *)u8bData(b)[0];
    *cap = u8bDataLen(b) / esz;
    return YES;
}

//  A JS number argument as a plain double (the lane cast follows) — jab's
//  JSValueToNumber, minus the out-param.
//  QJAB-005: the lane array is already unwrapped when `v` is read, so an
//  object's valueOf here would be JS holding a raw base — JABCScalar refuses it.
static b8 JABCNumOf(double *out, JSContext *ctx, JSValueConst arg) {
    if (!JABCScalar(ctx, arg)) return NO;
    return JS_ToFloat64(ctx, out, arg) < 0 ? NO : YES;
}

//  One push/pop leaf pair per lane.  RDV fills `v` from argv[2..]; WRV turns a
//  popped `v` into a JS value.  The cap/buffer/error boilerplate is generated
//  once here and shared across every lane.
//  JS-101: argc guards (NPUSH = push arity) — a short-armed call must throw,
//  not read past the argv[] array.
#define HEAP_DEF(LANE, NPUSH, RDV, WRV)                                        \
    static JABC_FN(jheap_##LANE##_push) {                                      \
        if (argc < NPUSH)                                                      \
            JABC_THROW("_heap_" #LANE "_push(arr, size, v[, val])");           \
        void *base;                                                            \
        size_t cap;                                                            \
        if (!JABCLaneArr(&base, &cap, ctx, argv[0], sizeof(LANE))) JABC_FAIL;  \
        u64 n = 0;                                                             \
        if (!JABCu64Of(&n, ctx, argv[1])) JABC_FAIL;                           \
        if (n >= cap) JABC_THROW("heap: full");                                \
        LANE v;                                                                \
        RDV;                                                                   \
        LANE *bb = (LANE *)base;                                               \
        LANE *buf[4] = {bb, bb, bb + n, bb + cap};                             \
        if (HEAP##LANE##Push(buf, &v) != OK) JABC_THROW("heap: push");         \
        return JS_NewFloat64(ctx, (double)(buf[2] - bb));                      \
    }                                                                          \
    static JABC_FN(jheap_##LANE##_pop) {                                       \
        if (argc < 2) JABC_THROW("_heap_" #LANE "_pop(arr, size)");            \
        void *base;                                                            \
        size_t cap;                                                            \
        if (!JABCLaneArr(&base, &cap, ctx, argv[0], sizeof(LANE))) JABC_FAIL;  \
        u64 n = 0;                                                             \
        if (!JABCu64Of(&n, ctx, argv[1])) JABC_FAIL;                           \
        /* PTR-010: bound the watermark — `bb + n` past the array was a wild   \
           pointer for any n > cap (a -1 cast to size_t included). */          \
        if (n > cap) JABC_THROW("heap: the watermark is past the end");        \
        if (n == 0) JABC_UNDEF;                                                \
        LANE *bb = (LANE *)base;                                               \
        LANE *buf[4] = {bb, bb, bb + n, bb + cap};                             \
        LANE v;                                                                \
        if (HEAP##LANE##Pop(&v, buf) != OK) JABC_UNDEF;                        \
        return (WRV);                                                          \
    }

//  JS-106: bulk push — _heap_<lane>_feed(arr, size, entries) -> newsize.
//  `entries` is any typed array over contiguous LANE elements (e.g. the
//  BigUint64Array view P.scan returns); one boundary crossing, n sifts in C.
#define HEAP_FEED(LANE)                                                        \
    static JABC_FN(jheap_##LANE##_feed) {                                      \
        if (argc < 3) JABC_THROW("heap: feed argc");                           \
        void *base;                                                            \
        size_t cap;                                                            \
        if (!JABCLaneArr(&base, &cap, ctx, argv[0], sizeof(LANE))) JABC_FAIL;  \
        u64 n = 0;                                                             \
        if (!JABCu64Of(&n, ctx, argv[1])) JABC_FAIL;                           \
        u8 *ebb[4] = {};                                                       \
        if (!JABCDataOf(ebb, ctx, argv[2])) JABC_FAIL;                         \
        u8 const *const *eb = u8bDataC(ebb);                                   \
        size_t m = u8bDataLen(ebb) / sizeof(LANE);                             \
        if (u8bDataLen(ebb) != m * sizeof(LANE))                               \
            JABC_THROW("heap: feed align");                                    \
        if (n > cap || m > cap - n) JABC_THROW("heap: full");                  \
        LANE *bb = (LANE *)base;                                               \
        if ((u8c *)bb < eb[1] && eb[0] < (u8c *)(bb + cap))                     \
            JABC_THROW("heap: feed overlap");                                  \
        LANE *buf[4] = {bb, bb, bb + n, bb + cap};                             \
        const LANE *e = (const LANE *)eb[0];                                   \
        for (size_t i = 0; i < m; i++)                                         \
            if (HEAP##LANE##Push(buf, e + i) != OK) JABC_THROW("heap: push");  \
        return JS_NewFloat64(ctx, (double)(buf[2] - bb));                      \
    }

//  Marshal shapes.  A number crosses through JS_ToFloat64, a u64 through the
//  BigInt pair (JABCBigU64Of takes a Number OR a BigInt, as JSValueToUInt64).
#define HEAP_NUM(LANE)                                                     \
    HEAP_DEF(                                                              \
        LANE, 3,                                                           \
        {                                                                  \
            double d_ = 0;                                                 \
            if (!JABCNumOf(&d_, ctx, argv[2])) JABC_FAIL;                  \
            v = (LANE)d_;                                                  \
        },                                                                 \
        JS_NewFloat64(ctx, (double)v))
#define HEAP_U64(LANE)                                                     \
    HEAP_DEF(                                                              \
        LANE, 3,                                                           \
        {                                                                  \
            u64 w_ = 0;                                                    \
            if (!JABCBigU64Of(&w_, ctx, argv[2])) JABC_FAIL;               \
            v = (LANE)w_;                                                  \
        },                                                                 \
        JABCBigU64(ctx, (u64)v))
#define HEAP_PN(LANE)                                                      \
    HEAP_DEF(                                                              \
        LANE, 4,                                                           \
        {                                                                  \
            double k_ = 0;                                                 \
            double v_ = 0;                                                 \
            if (!JABCNumOf(&k_, ctx, argv[2]) ||                           \
                !JABCNumOf(&v_, ctx, argv[3]))                             \
                JABC_FAIL;                                                 \
            v.key = (u32)k_;                                               \
            v.val = (u32)v_;                                               \
        },                                                                 \
        JABCPair(ctx, JS_NewFloat64(ctx, (double)v.key),                   \
                 JS_NewFloat64(ctx, (double)v.val)))
#define HEAP_PB(LANE)                                                      \
    HEAP_DEF(                                                              \
        LANE, 4,                                                           \
        {                                                                  \
            u64 k_ = 0;                                                    \
            u64 v_ = 0;                                                    \
            if (!JABCBigU64Of(&k_, ctx, argv[2]) ||                        \
                !JABCBigU64Of(&v_, ctx, argv[3]))                          \
                JABC_FAIL;                                                 \
            v.key = k_;                                                    \
            v.val = v_;                                                    \
        },                                                                 \
        JABCPair(ctx, JABCBigU64(ctx, (u64)v.key),                         \
                 JABCBigU64(ctx, (u64)v.val)))

//  A blob lane element is a fixed-size byte struct; the JS side passes a
//  Uint8Array of exactly sizeof(LANE).  RDV reads+validates it into `v.data`;
//  WRV returns a fresh Uint8Array copy of the popped struct.
#define HEAP_BLOB(LANE)                                                    \
    HEAP_DEF(                                                              \
        LANE, 3,                                                           \
        {                                                                  \
            u8 *_bb[4] = {};                                               \
            if (!JABCDataOf(_bb, ctx, argv[2])) JABC_FAIL;                 \
            if (u8bDataLen(_bb) != sizeof(LANE))                           \
                JABC_THROW("heap: blob size");                             \
            memcpy(v.data, u8bData(_bb)[0], sizeof(LANE));                 \
        },                                                                 \
        JABCBlob(ctx, v.data, sizeof(LANE)))

HEAP_NUM(u8)
HEAP_NUM(u16)
HEAP_NUM(u32)
HEAP_U64(u64)
HEAP_U64(wh64)
HEAP_PN(kv32)
HEAP_PB(kv64)
HEAP_PB(wh128)
HEAP_BLOB(sha1)
HEAP_BLOB(sha256)

HEAP_FEED(u8)
HEAP_FEED(u16)
HEAP_FEED(u32)
HEAP_FEED(u64)
HEAP_FEED(wh64)
HEAP_FEED(kv32)
HEAP_FEED(kv64)
HEAP_FEED(wh128)
HEAP_FEED(sha1)
HEAP_FEED(sha256)

#define HEAP_REG(LANE)                                            \
    JABC_API_FN(abc, "_heap_" #LANE "_push", jheap_##LANE##_push);  \
    JABC_API_FN(abc, "_heap_" #LANE "_pop", jheap_##LANE##_pop);    \
    JABC_API_FN(abc, "_heap_" #LANE "_feed", jheap_##LANE##_feed)

ok64 JABCInstallHeap(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    HEAP_REG(u8);
    HEAP_REG(u16);
    HEAP_REG(u32);
    HEAP_REG(u64);
    HEAP_REG(kv32);
    HEAP_REG(kv64);
    HEAP_REG(wh64);
    HEAP_REG(wh128);
    HEAP_REG(sha1);
    HEAP_REG(sha256);
    JABC_API_END(abc);
    return OK;
}
