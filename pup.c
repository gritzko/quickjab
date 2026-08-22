//  JAB-036: pup.c — the port of jab/pup.hpp.  PUP bindings (DOG-027): an index
//  IS a dog Pup stack — immutable oldest-first runs + a memtable + the 1/8
//  ladder, all of it in C.  JS holds a handle id plus `dir`/`ext` strings and
//  does nothing but marshalling; the ladder never crosses the boundary.
//
//  Leaves (per lane kv64 / wh128 / u64):
//    _pup_<lane>_open(dir, ext, mode, mem) -> handle (a small integer)
//    _pup_<lane>_put(h, dir, ext, k[, v])  -> undefined  (rw only)
//    _pup_<lane>_commit(h, dir, ext, dur)  -> undefined  (rw only)
//    _pup_mem(h)                           -> memtable row capacity (any lane)
//    _pup_<lane>_get(h, k)                 -> val | undefined (newest wins)
//    _pup_<lane>_range(h, lo, hi, cb)      -> undefined  (cb "enough" stops)
//    _pup_<lane>_seek(h, k) / _next(h)     -> merged pull cursor, ONE per handle
//    _pup_<lane>_count(h)                  -> committed run count
//    _pup_<lane>_run(h, i)                 -> Uint8Array over run i (read-only)
//    _pup_<lane>_drop(h, dir, ext[, i])    -> undefined  (no i = every run)
//    _pup_<lane>_close(h)                  -> undefined
//
//  The per-lane `dogpuplane` (sort/dedup/collapse + compaction merge) is
//  instantiated HERE, the way hit.c instantiates HIT per lane — dog's Pup is
//  generic, the two typed roles come from the binding.  Each leaf STATICALLY
//  knows its lane and passes that `dogpuplane const *` down as an ordinary C
//  parameter: NO state about the lane is ever dicted.
#include "JABC.h"
#include "abc/FILE.h"  //  FILE_PATH_MAX_LEN
#include "abc/KV.h"    //  kv64 (key,val) + kv64Z (KEY-only: a keyed lane)
#include "abc/PRO.h"   //  the call/try/done flow the two lane hooks run in
#include "dog/DOG.h"   //  DOGPup* — the LSM itself
#include "dog/WHIFF.h" //  wh128 (key,val) + wh128Z

//  QSORTx (sSort / InSort / sDedup) for the lanes abc does not instantiate;
//  kv64 comes from KV.h and u64 from INT.h.
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#undef X

//  HITx (the merge heap) is pre-instantiated nowhere — one per pup lane.
#define X(M, name) M##kv64##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##wh128##name
#include "abc/HITx.h"
#undef X
#define X(M, name) M##u64##name
#include "abc/HITx.h"
#undef X

//  DOG-027: open stacks.  The JS handle is an index into this table; the dict
//  behind it is a malloced 64-cell kv64b, freed by _pup_<lane>_close.  EXACTLY
//  64 cells: the memtable's entry is one of them, and no headroom is carved
//  for it — the cap is a damage backstop the 1/8 ladder never approaches.
#define PUP_MAX_OPEN 32
#define PUP_DICT_CELLS HIT_MAX_RUNS

//  QJAB-006: ONE live no-copy view over run `i`'s mapping.  The handle owns
//  the ArrayBuffer (the JS views JS mints all hang off it), so close/drop/put
//  can DETACH it before dog unmaps the bytes — abc.close's move (cont.c:436:B6),
//  minus the munmap: a retained view then reads empty, never freed pages.
//  `base`/`len` say which mapping it wraps; a stale pair re-mints.
typedef struct {
    JSValue buf;
    u8c *base;
    size_t len;
} pupview;

typedef struct {
    Bkv64 pups;
    b8 live;
    b8 rw;
    //  QJAB-005: a range scan calls back into JS while it iterates the
    //  handle's MAPPINGS.  put/commit/drop/close seal, unlink and munmap
    //  those very runs, so they are barred for the length of the scan — the
    //  callback cannot pull the memory out from under the heap it drains.
    b8 busy;
    //  DOG-032: the memtable's size, fixed at open — `pages` whole OS pages
    //  going down to dog, `mem` the row capacity JS reads back as `idx.mem`.
    u32 pages;
    u64 mem;
    //  QJAB-006: the stack's version.  Every leaf that can unmap a run or move
    //  the memtable's rows bumps it; a cursor cut at an older one re-cuts its
    //  entries before it steps, so no pull ever walks a released mapping.
    u64 epoch;
    //  QJAB-006: the live run views, by run index (a run count past the cap is
    //  refused everywhere else too); `nview` keeps the hot put path off the
    //  sweep when the handle handed out nothing.
    pupview view[HIT_MAX_RUNS];
    u32 nview;
} pupslot;

static pupslot JABC_PUPS[PUP_MAX_OPEN];

//  The ONE plain-words error for a stack past the cap (never a bare C code).
#define PUP_TOOMANY "too many index runs: drop them and re-derive the index"

//  QJAB-005: what a range callback is told when it tries to mutate the very
//  handle being scanned.
#define PUP_BUSY "this index is being scanned: finish the range first"

//  DOG-032: a memtable is one mapping and one collapse scratch, so 256 MiB of
//  pages is the damage backstop — a sane bulk run asks for one or two.
#define PUP_MAX_MEM_PAGES (1UL << 16)
#define PUP_TOOBIG "the index memtable is too big: ask for fewer rows"

//  Resolve argv[0] to a live slot, or NULL (the caller throws).
static pupslot *JABCPupSlot(JSContext *ctx, int argc, JSValueConst *argv) {
    if (argc < 1) return NULL;
    u64 h = 0;
    if (!JABCu64Of(&h, ctx, argv[0])) return NULL;
    if (h >= PUP_MAX_OPEN || !JABC_PUPS[h].live) return NULL;
    return &JABC_PUPS[h];
}

//  QJAB-006: blank every live view over this stack — the ArrayBuffer detaches
//  (so a view JS still holds reads empty, length 0) and the handle's ref goes.
static void JABCPupUnview(JSContext *ctx, pupslot *s) {
    if (s->nview == 0) return;
    for (u32 i = 0; i < HIT_MAX_RUNS; i++) {
        pupview *v = &s->view[i];
        if (v->base == NULL) continue;
        JS_DetachArrayBuffer(ctx, v->buf);
        JS_FreeValue(ctx, v->buf);
        v->buf = JS_UNDEFINED;
        v->base = NULL;
        v->len = 0;
    }
    s->nview = 0;
}

//  QJAB-006: the mappings are about to move under their readers — detach the
//  views FIRST (before the unmap, as abc.close does) and bump the epoch, so a
//  cursor cut before this re-cuts its entries instead of stepping into them.
static void JABCPupMoved(JSContext *ctx, pupslot *s) {
    JABCPupUnview(ctx, s);
    s->epoch++;
}

//  QJAB-006: a Uint8Array over run `i`'s bytes.  The ArrayBuffer is the
//  HANDLE's (one per run index, its ref held here), every call mints a fresh
//  view over it, and JABCPupUnview detaches the whole family at once.
static JSValue JABCPupView(JSContext *ctx, pupslot *s, u32 i, u8cs run) {
    size_t len = (size_t)u8csLen(run);
    pupview *v = &s->view[i];
    if (v->base != NULL) {
        //  the app may have detached it itself (a transfer()), and a run index
        //  can name another mapping after a drop — either way, re-mint.
        size_t sz = 0;
        u8 *p = JS_GetArrayBuffer(ctx, &sz, v->buf);
        if (p == NULL) JS_FreeValue(ctx, JS_GetException(ctx));
        if (p != (u8 *)(uintptr_t)v->base || sz != v->len || v->base != run[0] ||
            v->len != len) {
            JS_FreeValue(ctx, v->buf);
            v->buf = JS_UNDEFINED;
            v->base = NULL;
            v->len = 0;
            s->nview--;
        }
    }
    if (v->base == NULL) {
        JSValue ta = JABCBytesNoCopy(ctx, (u8 *)(uintptr_t)run[0], len, NULL,
                                     NULL);
        if (JS_IsException(ta)) return ta;
        JSValue buf = JS_GetTypedArrayBuffer(ctx, ta, NULL, NULL, NULL);
        JS_FreeValue(ctx, ta);  //  the handle keeps the BUFFER, not the view
        if (JS_IsException(buf)) return buf;
        v->buf = buf;
        v->base = run[0];
        v->len = len;
        s->nview++;
    }
    JSValue a[3] = {JS_DupValue(ctx, v->buf), JS_NewInt64(ctx, 0),
                    JS_NewInt64(ctx, (int64_t)len)};
    JSValue r = JS_NewTypedArray(ctx, 3, a, JS_TYPED_ARRAY_UINT8);
    for (u32 k = 0; k < 3; k++) JS_FreeValue(ctx, a[k]);
    return r;
}

//  The lane element needles: pair lanes take ONE BigInt (the key, with the val
//  field at its low bound 0), u64 the scalar itself.
static b8 JABCPupKv64(kv64 *v, JSContext *ctx, JSValueConst arg) {
    v->val = 0;
    return JABCBigU64Of(&v->key, ctx, arg);
}
static b8 JABCPupWh128(wh128 *v, JSContext *ctx, JSValueConst arg) {
    v->val = 0;
    return JABCBigU64Of(&v->key, ctx, arg);
}
static b8 JABCPupU64(u64 *v, JSContext *ctx, JSValueConst arg) {
    return JABCBigU64Of(v, ctx, arg);
}

//  cb's return is a stop signal: false / "enough" stops, anything else goes on
//  (the io.readdir(path, cb) contract).  Borrows `r`.
static b8 JABCPupEnough(JSContext *ctx, JSValueConst r) {
    if (JS_IsBool(r) && JS_ToBool(ctx, r) == 0) return YES;
    if (JS_IsString(r)) {
        size_t n = 0;
        const char *s = JS_ToCStringLen(ctx, &n, r);
        if (s == NULL) return NO;
        b8 stop = (b8)(n == 6 && memcmp(s, "enough", 6) == 0);
        JS_FreeCString(ctx, s);
        return stop;
    }
    return NO;
}

//  Read `dir` and `ext` (plain JS strings on the handle) into path buffers.
#define PUP_PATHS(A)                                          \
    a_pad(u8, dirp, FILE_PATH_MAX_LEN);                       \
    a_pad(u8, extp, FILE_PATH_MAX_LEN);                       \
    if (JABCPath(dirp, ctx, argv[A]) != OK ||                 \
        JABCPath(extp, ctx, argv[(A) + 1]) != OK)             \
    JABC_THROW("the index dir and ext must be strings")

//  --- per-lane value marshalling -------------------------------------------
//  PUP_RD_x     needle reader (out, ctx, arg) -> b8
//  PUP_PUTVAL_x fills the record's val field from argv[4] (pair lanes only)
//  PUP_EMIT_x   JS value for the merged element `top`
//  PUP_GETV_x   JS value _get returns for the matching element `pos`
//  PUP_KEYEQ_x  does `pos` carry `needle`'s key?
#define PUP_RD_kv64 JABCPupKv64
#define PUP_RD_wh128 JABCPupWh128
#define PUP_RD_u64 JABCPupU64

#define PUP_PUTVAL_kv64 \
    if (!JABCBigU64Of(&row.val, ctx, argv[4])) JABC_FAIL
#define PUP_PUTVAL_wh128 \
    if (!JABCBigU64Of(&row.val, ctx, argv[4])) JABC_FAIL
#define PUP_PUTVAL_u64 ((void)0)

#define PUP_EMIT_kv64 \
    JABCPair(ctx, JABCBigU64(ctx, top->key), JABCBigU64(ctx, top->val))
#define PUP_EMIT_wh128 \
    JABCPair(ctx, JABCBigU64(ctx, top->key), JABCBigU64(ctx, top->val))
#define PUP_EMIT_u64 JABCBigU64(ctx, *top)

#define PUP_GETV_kv64 JABCBigU64(ctx, pos->val)
#define PUP_GETV_wh128 JABCBigU64(ctx, pos->val)
#define PUP_GETV_u64 JABCBigU64(ctx, *pos)

#define PUP_KEYEQ_kv64 (pos->key == needle.key)
#define PUP_KEYEQ_wh128 (pos->key == needle.key)
#define PUP_KEYEQ_u64 (*pos == needle)

//  DOG-032: PUP_STABLE_x — the lane needs the STABLE sort at ANY size.  kv64Z
//  is KEY-only, so equal rows differ and newest-wins rides arrival order;
//  wh128Z / u64Z totally order the row, so equal rows are identical and the
//  QSORTx introsort + sDedup say exactly what the insertion sort would.
#define PUP_STABLE_kv64 YES
#define PUP_STABLE_wh128 NO
#define PUP_STABLE_u64 NO

//  --- per-lane leaves -------------------------------------------------------
#define PUP_LEAVES(L)                                                          \
    /*  the lane's typed sort/dedup/collapse: STABLE insertion sort + keep-last\
        dedup on DATA; on collapse, fold PAST+DATA with the ties to DATA */    \
    static ok64 jpup_sync_##L(u8bp mem, b8 collapse) {                         \
        sane(u8bOK(mem));                                                      \
        L *dh = (L *)mem[1];                                                   \
        L *de = (L *)mem[2];                                                   \
        b8 clean = YES;                                                        \
        for (L *p = dh + 1; p < de; p++)                                       \
            if (!L##Z(p - 1, p)) {                                             \
                clean = NO;                                                    \
                break;                                                         \
            }                                                                  \
        if (!clean) {                                                          \
            L##s d = {dh, de};                                                 \
            /*  DOG-032: one page of DATA keeps the stable insertion sort —    \
                a big memtable takes QSORTx's introsort (see PUP_STABLE_x) */  \
            if (PUP_STABLE_##L ||                                              \
                (size_t)(de - dh) * sizeof(L) <= FILESysPage())                \
                QSORT##L##InSort(dh, de);                                      \
            else                                                               \
                L##sSort(d);                                                   \
            L##sDedup(d);                                                      \
            call(u8bShed, mem, (size_t)(de - d[1]) * sizeof(L));               \
        }                                                                      \
        if (!collapse) done;                                                   \
        if (mem[0] == mem[1]) {                                                \
            call(u8bUsedAll, mem);                                             \
            done;                                                              \
        }                                                                      \
        /*  DOG-032: the scratch is the LIVE mapping's size, not a constant —  \
            the memtable is whatever the open sized it to. */                  \
        a_carve(L, scr, (size_t)(u8bTerm(mem) - (u8 *)mem[0]) / sizeof(L));    \
        L##cs runs[2] = {{(L const *)mem[0], (L const *)mem[1]},               \
                         {(L const *)mem[1], (L const *)mem[2]}};              \
        L##css hp = {runs, runs + 2};                                          \
        L *base = L##bIdleHead(scr);                                           \
        L##s into = {base, L##bTerm(scr)};                                     \
        call(HIT##L##Merge, hp, into);                                         \
        u8cs merged = {(u8c *)base, (u8c *)into[0]};                           \
        u8bReset(mem);                                                         \
        call(u8bFeed, mem, merged);                                            \
        call(u8bUsedAll, mem);                                                 \
        done;                                                                  \
    }                                                                          \
    /*  the lane's typed compaction merge — equal keys go to the youngest */   \
    static ok64 jpup_merge_##L(u8s into, u8css srcs) {                         \
        sane($ok(into));                                                       \
        size_t n = (size_t)$len(srcs);                                         \
        if (n > HIT_MAX_RUNS) return HITTOOMANY;                               \
        L##cs runs[HIT_MAX_RUNS];                                              \
        for (size_t i = 0; i < n; i++) {                                       \
            runs[i][0] = (L const *)srcs[0][i][0];                             \
            runs[i][1] = (L const *)srcs[0][i][1];                             \
        }                                                                      \
        L##css hp = {runs, runs + n};                                          \
        L *base = (L *)into[0];                                                \
        L##s dst = {base, (L *)into[1]};                                       \
        call(HIT##L##Merge, hp, dst);                                          \
        into[0] = (u8 *)dst[0];                                                \
        done;                                                                  \
    }                                                                          \
    /*  DOG-035: `row` is the ToC opt-in — a fixed-width sorted lane, so its   \
        runs carry a sparse page index and every read clips it off. */         \
    static dogpuplane const JABC_PUP_LANE_##L = {jpup_sync_##L,                \
                                                 jpup_merge_##L,               \
                                                 (u32)sizeof(L)};              \
    /*  DOG-035: the needle's page — cell `i` covers page `i`, so it is the    \
        LAST cell not greater than the needle.  The ToC step runs ONCE per run \
        per lookup, so cell `i+1` is tested there too: a cell IS a whole record\
        and IS page i+1's first record, so a key match is THE answer, returned \
        from the ToC.  `out` is then exactly page `i`, never wider; a run with \
        no ToC keeps its whole range. */                                       \
    static L const *jpup_page_##L(L##cs out, L##csc run, L##csc toc,           \
                                  L const *key) {                              \
        L##csMv(out, run);                                                     \
        size_t per = DOGPupTocRows((u32)sizeof(L));                            \
        if (per == 0 || $empty(toc)) return NULL;                              \
        L const *c = L##sFindGE(toc, key);                                     \
        size_t i = (size_t)(c - toc[0]);                                       \
        if (c == toc[1] || L##Z(key, c)) i = i ? i - 1 : 0;                    \
        if (i + 1 < (size_t)$len(toc)) {                                       \
            L const *pos = toc[0] + i + 1;                                     \
            L needle = *key;                                                   \
            if (PUP_KEYEQ_##L) return pos;                                     \
        }                                                                      \
        out[0] = run[0] + i * per;                                             \
        if (out[0] > run[1]) out[0] = run[1];                                  \
        if (out[0] + per < out[1]) out[1] = out[0] + per;                      \
        return NULL;                                                           \
    }                                                                          \
    /*  the handle's ONE merged cursor: the entries advance in place, so each  \
        _next re-Loads the pointer heap over them (HITSkipValue's shape).      \
        QJAB-006: the entries are RAW pointers into the runs and the memtable, \
        so the cursor also carries where it stands (`K`, `X` = the bound was   \
        pulled already), whether it is armed at all (`A`) and the stack epoch  \
        it was cut at (`E`) — a mutating leaf moves the rows, and _next re-cuts\
        rather than step into them. */                                         \
    static L##cs JABC_PUPCUR_##L[PUP_MAX_OPEN][HIT_MAX_RUNS];                  \
    static size_t JABC_PUPCURN_##L[PUP_MAX_OPEN];                              \
    static L JABC_PUPCURK_##L[PUP_MAX_OPEN];                                   \
    static b8 JABC_PUPCURX_##L[PUP_MAX_OPEN];                                  \
    static b8 JABC_PUPCURA_##L[PUP_MAX_OPEN];                                  \
    static u64 JABC_PUPCURE_##L[PUP_MAX_OPEN];                                 \
                                                                               \
    /*  the query sources: committed runs oldest->newest, then the memtable's  \
        PAST and DATA — 1 or 2 more HIT runs, never a special-cased path.      \
        DOG-035: `toc` runs parallel to `ent`, empty where there is none. */   \
    static ok64 jpup_src_##L(L##cs *ent, L##cs *toc, size_t *n, kv64b pups) {  \
        sane(ent != NULL && n != NULL);                                        \
        *n = 0;                                                                \
        Bu8cs srcs = {}, tocs = {};                                            \
        call(u8csbAllocate, srcs, HIT_MAX_RUNS);                               \
        try(u8csbAllocate, tocs, HIT_MAX_RUNS);                                \
        nedo {                                                                 \
            u8csbFree(srcs);                                                   \
            return HITTOOMANY;                                                 \
        }                                                                      \
        try(DOGPupAllRunsToc, srcs, tocs, pups, &JABC_PUP_LANE_##L);           \
        nedo {                                                                 \
            u8csbFree(srcs);                                                   \
            u8csbFree(tocs);                                                   \
            return HITTOOMANY;                                                 \
        }                                                                      \
        size_t k = (size_t)u8csbDataLen(srcs);                                 \
        u8cs *sl = u8csbDataHead(srcs);                                        \
        u8cs *tl = u8csbDataHead(tocs);                                        \
        for (size_t i = 0; i < k; i++) {                                       \
            ent[i][0] = (L const *)sl[i][0];                                   \
            ent[i][1] = (L const *)sl[i][1];                                   \
            if (toc == NULL) continue;                                         \
            toc[i][0] = (L const *)tl[i][0];                                   \
            toc[i][1] = (L const *)tl[i][1];                                   \
        }                                                                      \
        *n = k;                                                                \
        u8csbFree(srcs);                                                       \
        u8csbFree(tocs);                                                       \
        done;                                                                  \
    }                                                                          \
                                                                               \
    /*  QJAB-006: cut the handle's cursor from the LIVE sources — every source \
        at the first row past the bound (the seek needle, or the row already   \
        pulled).  _seek cuts once; _next cuts again whenever a put/commit/drop \
        moved the rows the entries pointed at. */                              \
    static ok64 jpup_cut_##L(pupslot *s, size_t h) {                           \
        sane(s != NULL && h < PUP_MAX_OPEN);                                   \
        L##cs *ent = JABC_PUPCUR_##L[h];                                       \
        size_t n = 0;                                                          \
        JABC_PUPCURN_##L[h] = 0;                                               \
        call(jpup_src_##L, ent, NULL, &n, s->pups);                            \
        L const *key = &JABC_PUPCURK_##L[h];                                   \
        b8 pulled = JABC_PUPCURX_##L[h];                                       \
        size_t w = 0;                                                          \
        for (size_t i = 0; i < n; i++) {                                       \
            L const *pos = L##sFindGE(ent[i], key);                            \
            /*  the bound itself is already emitted: skip its whole group */   \
            while (pulled && pos < ent[i][1] && !L##Z(key, pos)) pos++;        \
            if (pos >= ent[i][1]) continue;                                    \
            ent[w][0] = pos;                                                   \
            ent[w][1] = ent[i][1];                                             \
            w++;                                                               \
        }                                                                      \
        JABC_PUPCURN_##L[h] = w;                                               \
        JABC_PUPCURE_##L[h] = s->epoch;                                        \
        done;                                                                  \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_open) {                                          \
        if (argc < 2) JABC_THROW("_pup_" #L "_open(dir, ext, mode, mem)");     \
        PUP_PATHS(0);                                                          \
        b8 rw = YES;                                                           \
        /*  DOG-032: `mem` is the wanted ROW capacity; dog counts PAGES, so    \
            round the rows UP to whole pages and keep what that really is. */  \
        u64 rows = 0;                                                          \
        if (argc >= 4 && !JS_IsUndefined(argv[3]) &&                           \
            !JABCu64Of(&rows, ctx, argv[3]))                                   \
            JABC_THROW("the index memtable size is a row count");              \
        size_t page = FILESysPage();                                           \
        u64 pages = (rows * sizeof(L) + page - 1) / page;                      \
        if (pages == 0) pages = DOG_PUP_MEM_PAGES;                             \
        if (pages > PUP_MAX_MEM_PAGES) JABC_THROW(PUP_TOOBIG);                 \
        if (argc >= 3 && JS_IsString(argv[2])) {                               \
            size_t mn = 0;                                                     \
            const char *mode = JS_ToCStringLen(ctx, &mn, argv[2]);             \
            if (mode == NULL) JABC_FAIL;                                       \
            rw = (b8)(!(mn == 1 && mode[0] == 'r'));                           \
            JS_FreeCString(ctx, mode);                                         \
        }                                                                      \
        int h = -1;                                                            \
        for (int i = 0; i < PUP_MAX_OPEN; i++)                                 \
            if (!JABC_PUPS[i].live) {                                          \
                h = i;                                                         \
                break;                                                         \
            }                                                                  \
        if (h < 0) JABC_THROW("too many open indexes");                        \
        pupslot *s = &JABC_PUPS[h];                                            \
        zero(s->pups);                                                         \
        if (kv64bAllocate(s->pups, PUP_DICT_CELLS) != OK)                      \
            JABC_THROW("cannot allocate the index");                           \
        /*  the dict IS the cap, so a dir that overflows it is exactly a stack \
            past 64 runs — damaged or foreign, and the cure is re-derive. */   \
        if (DOGPupOpenAll(s->pups, $path(dirp), $path(extp)) != OK ||          \
            DOGPupCount(s->pups) > HIT_MAX_RUNS) {                             \
            DOGPupClose(s->pups);                                              \
            JABC_THROW(PUP_TOOMANY);                                           \
        }                                                                      \
        s->live = YES;                                                         \
        s->rw = rw;                                                            \
        s->busy = NO;                                                          \
        s->pages = (u32)pages;                                                 \
        s->mem = (u64)(pages * page / sizeof(L));                              \
        JABC_PUPCURN_##L[h] = 0;                                               \
        JABC_PUPCURA_##L[h] = NO;                                              \
        /*  QJAB-006: the slot is reused, so bump the epoch — a cursor left    \
            armed by the PREVIOUS handle re-cuts before it ever steps. */      \
        JABCPupMoved(ctx, s);                                                  \
        return JS_NewFloat64(ctx, (double)h);                                  \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_put) {                                           \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 4) JABC_THROW("_pup_" #L "_put(h, dir, ext, k[, v])");\
        if (!s->rw) JABC_THROW("this index is open read-only");                \
        if (s->busy) JABC_THROW(PUP_BUSY); /* QJAB-005 */                      \
        PUP_PATHS(1);                                                          \
        L row = {};                                                            \
        if (!PUP_RD_##L(&row, ctx, argv[3])) JABC_FAIL;                        \
        PUP_PUTVAL_##L;                                                        \
        u8cs rec = {(u8c *)&row, (u8c *)(&row + 1)};                           \
        /*  QJAB-006: a put syncs the memtable and a full one SEALS + ladders  \
            — rows move, mappings go.  Detach the views and cut the cursor     \
            loose BEFORE that, never after. */                                 \
        JABCPupMoved(ctx, s);                                                  \
        ok64 o = DOGPupPutMem(s->pups, $path(dirp), $path(extp), rec,          \
                              &JABC_PUP_LANE_##L, s->pages);                   \
        if (o == HITTOOMANY) JABC_THROW(PUP_TOOMANY);                          \
        if (o != OK) JABC_THROW("cannot write to the index");                  \
        JABC_UNDEF;                                                            \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_commit) {                                        \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 3)                                                    \
            JABC_THROW("_pup_" #L "_commit(h, dir, ext[, durable])");          \
        if (!s->rw) JABC_THROW("this index is open read-only");                \
        if (s->busy) JABC_THROW(PUP_BUSY); /* QJAB-005 */                      \
        PUP_PATHS(1);                                                          \
        /*  DOG-032: a bulk run seals with durable=false and ends in ONE       \
            durable commit; absent (jab's binding) IS durable. */              \
        b8 durable = YES;                                                      \
        if (argc >= 4 && JS_IsBool(argv[3]))                                   \
            durable = (b8)(JS_ToBool(ctx, argv[3]) != 0);                      \
        JABCPupMoved(ctx, s); /* QJAB-006: the seal + the ladder unmap runs */ \
        ok64 o = DOGPupCommitAs(s->pups, $path(dirp), $path(extp),             \
                                &JABC_PUP_LANE_##L, durable);                  \
        if (o == HITTOOMANY) JABC_THROW(PUP_TOOMANY);                          \
        if (o != OK) JABC_THROW("cannot commit the index");                    \
        JABC_UNDEF;                                                            \
    }                                                                          \
                                                                               \
    /*  point lookup: newest source first (they arrive oldest-first, so walk   \
        from the END), FindGE the key, accept iff the key matches.             \
        DOG-035: the ToC picks the ONE page that can hold the key first, or    \
        answers from a cell outright — a run is deduped, so a present key sits \
        in that page or nowhere. */                                            \
    static JABC_FN(jpup_##L##_get) {                                           \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 2) JABC_THROW("_pup_" #L "_get(h, k)");               \
        L needle = {};                                                         \
        if (!PUP_RD_##L(&needle, ctx, argv[1])) JABC_FAIL;                     \
        L##cs ent[HIT_MAX_RUNS], toc[HIT_MAX_RUNS];                            \
        size_t n = 0;                                                          \
        if (jpup_src_##L(ent, toc, &n, s->pups) != OK)                         \
            JABC_THROW(PUP_TOOMANY);                                           \
        for (size_t j = n; j > 0; j--) {                                       \
            L##cs win;                                                         \
            L const *cell = jpup_page_##L(win, ent[j - 1], toc[j - 1],         \
                                          &needle);                            \
            if (cell != NULL) {                                                \
                L const *pos = cell;                                           \
                return (PUP_GETV_##L);                                         \
            }                                                                  \
            L const *pos = L##sFindGE(win, &needle);                           \
            if (pos < win[1] && (PUP_KEYEQ_##L)) return (PUP_GETV_##L);        \
        }                                                                      \
        JABC_UNDEF;                                                            \
    }                                                                          \
                                                                               \
    /*  ordered [lo, hi) scan: trim every source to the range, then drain the  \
        pointer heap newest-wins (Tops/AdvanceTops collapse an equal-key group \
        onto its youngest member), streaming through the in-frame cb. */       \
    static JABC_FN(jpup_##L##_range) {                                         \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 4) JABC_THROW("_pup_" #L "_range(h, lo, hi, cb)");    \
        L lo = {}, hi = {};                                                    \
        if (!PUP_RD_##L(&lo, ctx, argv[1])) JABC_FAIL;                         \
        if (!PUP_RD_##L(&hi, ctx, argv[2])) JABC_FAIL;                         \
        if (!JS_IsFunction(ctx, argv[3]))                                      \
            JABC_THROW("the range callback must be a function");               \
        L##cs ent[HIT_MAX_RUNS], toc[HIT_MAX_RUNS];                            \
        size_t n = 0;                                                          \
        if (jpup_src_##L(ent, toc, &n, s->pups) != OK)                         \
            JABC_THROW(PUP_TOOMANY);                                           \
        /*  DOG-035: the ToC narrows the LOWER bound only — SeekRange's own    \
            search then runs over one page instead of the whole run, and a     \
            matching cell makes the start EXACT, not approximate. */           \
        for (size_t i = 0; i < n; i++) {                                       \
            L##cs win;                                                         \
            L const *cell = jpup_page_##L(win, ent[i], toc[i], &lo);           \
            ent[i][0] = cell ? cell : win[0];                                  \
        }                                                                      \
        L##css heap = {ent, ent + n};                                          \
        HIT##L##SeekRange(heap, &lo, &hi);                                     \
        L##csp slots[HIT_MAX_RUNS];                                            \
        L##csps ph;                                                            \
        if (HIT##L##Load(ph, slots, heap) != OK) JABC_THROW(PUP_TOOMANY);      \
        /*  QJAB-005: ent[] points INTO the handle's mappings and the cb below \
            is arbitrary JS — bar the leaves that unmap them for the scan. */  \
        b8 was = s->busy;                                                      \
        s->busy = YES;                                                         \
        while (!$empty(ph)) {                                                  \
            L const *top = (*ph[0])[0];                                        \
            L val = *top;                                                      \
            JSValue el = PUP_EMIT_##L;                                         \
            size_t ntops = HIT##L##Tops(ph);                                   \
            HIT##L##AdvanceTops(ph, ntops);                                    \
            while (!$empty(ph) && !L##Z((*ph[0])[0], &val) &&                  \
                   !L##Z(&val, (*ph[0])[0]))                                   \
                HIT##L##Step(ph);                                              \
            JSValue r = JS_Call(ctx, argv[3], JS_UNDEFINED, 1,                 \
                                (JSValueConst *)&el);                          \
            JS_FreeValue(ctx, el);                                             \
            if (JS_IsException(r)) {                                           \
                s->busy = was;                                                 \
                JABC_FAIL;                                                     \
            }                                                                  \
            b8 stop = JABCPupEnough(ctx, r);                                   \
            JS_FreeValue(ctx, r);                                              \
            if (stop) break;                                                   \
        }                                                                      \
        s->busy = was;                                                         \
        JABC_UNDEF;                                                            \
    }                                                                          \
                                                                               \
    /*  seek: position every source at the first element >= k and keep those   \
        entries on the handle; _next pulls ONE merged row per call. */         \
    static JABC_FN(jpup_##L##_seek) {                                          \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 2) JABC_THROW("_pup_" #L "_seek(h, k)");              \
        size_t h = (size_t)(s - JABC_PUPS);                                    \
        L needle = {};                                                         \
        if (!PUP_RD_##L(&needle, ctx, argv[1])) JABC_FAIL;                     \
        JABC_PUPCURK_##L[h] = needle; /* QJAB-006: the cursor's own bound */   \
        JABC_PUPCURX_##L[h] = NO;     /* inclusive: nothing pulled yet */      \
        JABC_PUPCURA_##L[h] = YES;                                             \
        if (jpup_cut_##L(s, h) != OK) {                                        \
            JABC_PUPCURA_##L[h] = NO;                                          \
            JABC_THROW(PUP_TOOMANY);                                           \
        }                                                                      \
        JABC_UNDEF;                                                            \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_next) {                                          \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s) JABC_THROW("_pup_" #L "_next(h)");                             \
        size_t h = (size_t)(s - JABC_PUPS);                                    \
        if (!JABC_PUPCURA_##L[h]) JABC_UNDEF;                                  \
        /*  QJAB-006: a put/commit since the cut sealed, merged or unmapped    \
            the very rows the entries name — re-cut from the live sources. */  \
        if (JABC_PUPCURE_##L[h] != s->epoch && jpup_cut_##L(s, h) != OK) {     \
            JABC_PUPCURA_##L[h] = NO;                                          \
            JABC_THROW(PUP_TOOMANY);                                           \
        }                                                                      \
        L##cs *ent = JABC_PUPCUR_##L[h];                                       \
        L##css runs = {ent, ent + JABC_PUPCURN_##L[h]};                        \
        L##csp slots[HIT_MAX_RUNS];                                            \
        L##csps ph;                                                            \
        if (HIT##L##Load(ph, slots, runs) != OK) JABC_THROW(PUP_TOOMANY);      \
        JABC_PUPCURN_##L[h] = (size_t)$len(runs); /* Load compacts entries */  \
        if ($empty(ph)) {                                                      \
            JABC_PUPCURA_##L[h] = NO; /* spent: a later put reopens nothing */ \
            JABC_UNDEF;                                                        \
        }                                                                      \
        L const *top = (*ph[0])[0];                                            \
        L val = *top;                                                          \
        JSValue el = PUP_EMIT_##L;                                             \
        size_t ntops = HIT##L##Tops(ph);                                       \
        HIT##L##AdvanceTops(ph, ntops);                                        \
        while (!$empty(ph) && !L##Z((*ph[0])[0], &val) &&                      \
               !L##Z(&val, (*ph[0])[0]))                                       \
            HIT##L##Step(ph);                                                  \
        JABC_PUPCURK_##L[h] = val; /* QJAB-006: where a re-cut resumes from */ \
        JABC_PUPCURX_##L[h] = YES;                                             \
        return el;                                                             \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_count) {                                         \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s) JABC_THROW("_pup_" #L "_count(h)");                            \
        return JS_NewFloat64(ctx, (double)DOGPupCount(s->pups));               \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_run) {                                           \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 2) JABC_THROW("_pup_" #L "_run(h, i)");               \
        u64 i = 0;                                                             \
        if (!JABCu64Of(&i, ctx, argv[1])) JABC_FAIL;                           \
        if (i >= DOGPupCount(s->pups) || i >= HIT_MAX_RUNS)                    \
            JABC_THROW("no such index run");                                   \
        u8cs run = {};                                                         \
        /*  DOG-035: the marker audit reads ROWS — the ToC block is clipped */ \
        DOGPupDataRow(run, s->pups, (u32)i, (u32)sizeof(L));                   \
        if (run[0] == NULL) JABC_THROW("no such index run");                   \
        /*  QJAB-006: the view BORROWS the Pup's mapping, so the HANDLE keeps  \
            its ArrayBuffer and detaches it the moment anything unmaps — a     \
            view held past a put/commit/drop/close reads empty, not freed      \
            pages (it is the marker-audit path). */                            \
        return JABCPupView(ctx, s, (u32)i, run);                               \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_drop) {                                          \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s || argc < 3) JABC_THROW("_pup_" #L "_drop(h, dir, ext[, i])");  \
        if (!s->rw) JABC_THROW("this index is open read-only");                \
        if (s->busy) JABC_THROW(PUP_BUSY); /* QJAB-005 */                      \
        PUP_PATHS(1);                                                          \
        /*  QJAB-006: the dropped run's mapping goes — detach its views, and   \
            the cursor's runs are the dropped ones' too, so it is spent. */    \
        JABCPupMoved(ctx, s);                                                  \
        JABC_PUPCURN_##L[(size_t)(s - JABC_PUPS)] = 0; /* the cursor's runs */ \
        JABC_PUPCURA_##L[(size_t)(s - JABC_PUPS)] = NO;                        \
        if (argc < 4 || JS_IsUndefined(argv[3])) {                             \
            /*  drop() = every run: the family found no marker, re-derives */  \
            if (DOGPupThinTail(s->pups, $path(dirp), $path(extp),              \
                               DOGPupCount(s->pups)) != OK)                    \
                JABC_THROW("cannot drop the index runs");                      \
            JABC_UNDEF;                                                        \
        }                                                                      \
        u64 i = 0;                                                             \
        if (!JABCu64Of(&i, ctx, argv[3])) JABC_FAIL;                           \
        if (DOGPupDropAt(s->pups, $path(dirp), $path(extp), (u32)i) != OK)     \
            JABC_THROW("no such index run");                                   \
        JABC_UNDEF;                                                            \
    }                                                                          \
                                                                               \
    static JABC_FN(jpup_##L##_close) {                                         \
        pupslot *s = JABCPupSlot(ctx, argc, argv);                             \
        if (!s) JABC_THROW("_pup_" #L "_close(h)");                            \
        if (s->busy) JABC_THROW(PUP_BUSY); /* QJAB-005 */                      \
        size_t h = (size_t)(s - JABC_PUPS);                                    \
        /*  QJAB-006: every mapping this handle lent JS goes here — detach the \
            views BEFORE the unmap, the way abc.close moves its own. */        \
        JABCPupMoved(ctx, s);                                                  \
        DOGPupClose(s->pups);                                                  \
        zero(s->pups);                                                         \
        s->live = NO;                                                          \
        JABC_PUPCURN_##L[h] = 0;                                               \
        JABC_PUPCURA_##L[h] = NO;                                              \
        JABC_UNDEF;                                                            \
    }

PUP_LEAVES(kv64)
PUP_LEAVES(wh128)
PUP_LEAVES(u64)

//  DOG-032: the memtable's row capacity — ONE leaf for every lane, since the
//  slot holds it and the rows were already page-rounded at open.
static JABC_FN(jpup_mem) {
    pupslot *s = JABCPupSlot(ctx, argc, argv);
    if (!s) JABC_THROW("_pup_mem(h)");
    return JS_NewFloat64(ctx, (double)s->mem);
}

#define PUP_REG(L)                                                \
    JABC_API_FN(abc, "_pup_" #L "_open", jpup_##L##_open);          \
    JABC_API_FN(abc, "_pup_" #L "_put", jpup_##L##_put);            \
    JABC_API_FN(abc, "_pup_" #L "_commit", jpup_##L##_commit);      \
    JABC_API_FN(abc, "_pup_" #L "_get", jpup_##L##_get);            \
    JABC_API_FN(abc, "_pup_" #L "_range", jpup_##L##_range);        \
    JABC_API_FN(abc, "_pup_" #L "_seek", jpup_##L##_seek);          \
    JABC_API_FN(abc, "_pup_" #L "_next", jpup_##L##_next);          \
    JABC_API_FN(abc, "_pup_" #L "_count", jpup_##L##_count);        \
    JABC_API_FN(abc, "_pup_" #L "_run", jpup_##L##_run);            \
    JABC_API_FN(abc, "_pup_" #L "_drop", jpup_##L##_drop);          \
    JABC_API_FN(abc, "_pup_" #L "_close", jpup_##L##_close)

ok64 JABCInstallPup(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    PUP_REG(kv64);
    PUP_REG(wh128);
    PUP_REG(u64);
    JABC_API_FN(abc, "_pup_mem", jpup_mem);
    JABC_API_END(abc);
    return OK;
}

//  QJAB-006: a handle left open at exit still owns the ArrayBuffers of its
//  live run views — drop them (detached, so nothing can read the mapping the
//  teardown is about to release) while the context is still alive.
ok64 JABCUninstallPup(JSContext *ctx) {
    for (int i = 0; i < PUP_MAX_OPEN; i++) JABCPupUnview(ctx, &JABC_PUPS[i]);
    return OK;
}
