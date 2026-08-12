//  JAB-036: cfold.c — the port of jab/cfold.hpp.  CFOLD (DIS-082) is one
//  file's whole DAG history as a 'V' TLV blob (the APPEND-ONLY weave).  A
//  CFOLD container is a JS-owned u8 buffer holding ONE 'V' blob; the binding
//  parses it zero-copy per call (stateless leaves, like HUNK).  The builders
//  (_cfold_next/_cfold_merge) write a FRESH 'V' blob into a target buffer.
//
//  Hashes are STRINGS (JABC convention): a commit id is the hi64 of the commit
//  sha1, presented as a 16-char hex hashlet.  Every u64<->hex conversion lives
//  here; no u64 ever crosses the boundary as a JS number/BigInt.
#include "JABC.h"
#include "abc/FILE.h"
#include "dog/CFOLD.h"

//  hunk.c's string-or-bytes arg reader (one implementation, three consumers).
b8 JABChunkArgU8(u8s out, JSContext *ctx, JSValueConst v, u8 *tmp, size_t cap);

//  --- u64 <-> 16-char hex hashlet (big-endian: first sha byte = top bits) ---
//  A commit id is be64(sha1[0..8]); its 16 hex chars are the value's hex.  NO
//  when the argument is not a string value (the caller hands the throw back).
static b8 JABCcfoldHi64(u64 *out, JSContext *ctx, JSValueConst v) {
    size_t n = 0;
    const char *b = JS_ToCStringLen(ctx, &n, v);
    if (b == NULL) return NO;
    u64 h = 0;
    u32 got = 0;
    for (size_t i = 0; i < n && got < 16; i++) {
        char c = b[i];
        u32 d;
        if (c >= '0' && c <= '9') d = (u32)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (u32)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (u32)(c - 'A' + 10);
        else break;
        h = (h << 4) | d;
        got++;
    }
    JS_FreeCString(ctx, b);
    *out = h;
    return YES;
}

//  u64 -> a fresh JS string of its 16-char lowercase hex hashlet.
static JSValue JABCcfoldHashlet(JSContext *ctx, u64 h) {
    static const char HX[] = "0123456789abcdef";
    char b[17];
    for (int i = 15; i >= 0; i--) {
        b[i] = HX[h & 0xf];
        h >>= 4;
    }
    b[16] = 0;
    return JS_NewStringLen(ctx, b, 16);
}

//  Parse the 'V' blob in (bv, lv=byte length) into `w`, also reporting the
//  blob base.  NO on a non-array or a malformed/empty blob.
static b8 JABCcfoldAt(cfold *w, u8 **base, JSContext *ctx, JSValueConst bv,
                      JSValueConst lv) {
    u8 *blob[4] = {};
    if (!JABCDataOf(blob, ctx, bv)) return NO;
    size_t len = 0;  //  gated, never past the view
    if (!JABCOffOf(&len, u8bDataC(blob), ctx, lv)) return NO;
    *base = u8bData(blob)[0];
    u8cs bc = {};
    if (len > 0xffffffffUL || u8csSub(u8bDataC(blob), bc, 0, (u32)len) != OK)
        return NO;
    return CFOLDParse(w, bc) == OK;
}

//  A commit HASHLET -> its build index in the 'C' table.  NO when the id was
//  never folded (the caller reports it in plain words).
static b8 JABCcfoldRev(u32 *out, cfold const *w, JSContext *ctx,
                       JSValueConst v) {
    u64 id = 0;
    if (!JABCcfoldHi64(&id, ctx, v)) return NO;
    return CFOLDFindCommit(out, w, id) == OK;
}

//  Read a JS array of hashlet strings into a malloc'd u64 vector; the caller
//  frees it.  *n is the element count (0 => NULL is fine).
static u64 *JABCcfoldIds(u32 *n, JSContext *ctx, JSValueConst v) {
    *n = 0;
    if (!JS_IsObject(v)) return NULL;
    JSValue lv = JABCGetProp(ctx, v, "length");
    u32 an = 0;
    b8 ok = JABCu32Of(&an, ctx, lv);
    JS_FreeValue(ctx, lv);
    if (!ok || an == 0) return NULL;
    u64 *ids = (u64 *)malloc((size_t)an * sizeof(u64));
    if (ids == NULL) return NULL;
    for (u32 i = 0; i < an; i++) {
        JSValue el = JS_GetPropertyUint32(ctx, v, i);
        ids[i] = 0;
        JABCcfoldHi64(&ids[i], ctx, el);
        JS_FreeValue(ctx, el);
    }
    *n = an;
    return ids;
}

//  Emit sink: append each emitted hunk as a TLV 'H' record into a HUNK
//  container's buffer (`into` advances per record).  The JABC rule #4 — C
//  holds no JS closure — holds: the callback is this C leaf, never a JS one.
typedef struct {
    u8s into;
    ok64 err;
} JABCemit;
static ok64 JABCcfoldEmitCb(hunkc *hk, void *vctx) {
    JABCemit *c = (JABCemit *)vctx;
    ok64 o = HUNKu8sFeed(c->into, hk);
    if (o != OK) c->err = o;
    return o;
}

//  _cfold_count(blob, len) -> INDEX entry count (inserts + tombs + chain
//  terminators), 0 for an empty/unbuilt weave.
static JABC_FN(JABCcfoldCount) {
    if (argc < 2) JABC_THROW("cfold._count(blob, len)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        return JS_NewFloat64(ctx, 0);
    return JS_NewFloat64(ctx, (double)(u32)$len(w.idx));
}

//  _cfold_commits(blob, len) -> Array of 16-char hashlet strings, in BUILD
//  order (index i is the commit index every other leaf takes).
static JABC_FN(JABCcfoldCommits) {
    if (argc < 2) JABC_THROW("cfold._commits(blob, len)");
    cfold w = {};
    u8 *base = NULL;
    u32 n = 0;
    if (JABCcfoldAt(&w, &base, ctx, argv[0], argv[1])) n = CFOLDNCommits(&w);
    if (n == 0) return JS_NewArray(ctx);
    JSValue *els = (JSValue *)malloc(n * sizeof(JSValue));
    if (els == NULL) JABC_THROW("cfold.commits: out of memory");
    for (u32 i = 0; i < n; i++) {
        cfcommit c = {};
        if (CFOLDCommitAt(&c, &w, i) != OK) {
            for (u32 j = 0; j < i; j++) JS_FreeValue(ctx, els[j]);
            free(els);
            JABC_THROW("cfold.commits: malformed weave");
        }
        els[i] = JABCcfoldHashlet(ctx, c.id);
    }
    JSValue arr = JS_NewArrayFrom(ctx, (int)n, els);  //  takes the values
    free(els);
    return arr;
}

//  _cfold_next(dest, base|null, baseLen, newBlob, ext, hash, ancestors[])
//  -> blob byte length.  Folds `newBlob` (tokenized by `ext`) onto `base`
//  under commit `hash`, writing a fresh 'V' blob from offset 0 of `dest`.
//  `ancestors` is the new commit's WHOLE CAUSAL CLOSURE (itself excluded) as
//  hashlets.  base NULL/empty => a from-blob weave.
static JABC_FN(JABCcfoldNext) {
    if (argc < 7)
        JABC_THROW(
            "cfold._next(dest, base, baseLen, newBlob, ext, hash, ancestors)");
    u8 *destb[4] = {};
    if (!JABCIdleOf(destb, ctx, argv[0])) JABC_FAIL;
    cfold bw = {};
    cfold *wp = NULL;
    u8 *bbase = NULL;
    if (!JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        if (JABCcfoldAt(&bw, &bbase, ctx, argv[1], argv[2])) wp = &bw;
    }
    u8 *nbb[4] = {};
    if (!JABCDataOf(nbb, ctx, argv[3])) JABC_FAIL;
    u8 exttmp[64];
    u8s ext = {};
    if (!JABChunkArgU8(ext, ctx, argv[4], exttmp, sizeof(exttmp))) JABC_FAIL;
    u64 commit = 0;
    if (!JABCcfoldHi64(&commit, ctx, argv[5])) JABC_FAIL;
    u32 an = 0;
    u64 *ids = JABCcfoldIds(&an, ctx, argv[6]);
    u8 *const dbase = u8bIdle(destb)[0];
    u8s into = {dbase, u8bIdle(destb)[1]};
    u8csc extc = {ext[0], ext[1]};
    u64csc anc = {ids, ids + an};
    ok64 o = CFOLDFold(into, wp, u8bDataC(nbb), extc, commit, anc);
    free(ids);
    if (o == CFOLDBIG)
        JABC_THROW(
            "cfold.fold: the file is too big to weave (over 16 MB of history)");
    if (o != OK) JABC_THROW("cfold.fold: failed (buffer full?)");
    return JS_NewFloat64(ctx, (double)(size_t)(into[0] - dbase));
}

//  _cfold_merge(dest, base, baseLen, hash, ancestors[]) -> blob byte length
//  A merge carries NO content of its own: ONE weave in (both sides are already
//  folded into it), one 'C' record out taking the later L and the intersected
//  ignore-set.  No weave pair, no renumbering.
static JABC_FN(JABCcfoldMerge) {
    if (argc < 5)
        JABC_THROW("cfold._merge(dest, base, baseLen, hash, ancestors)");
    u8 *destb[4] = {};
    if (!JABCIdleOf(destb, ctx, argv[0])) JABC_FAIL;
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[1], argv[2]))
        JABC_THROW("cfold.merge: the base weave is empty or malformed");
    u64 commit = 0;
    if (!JABCcfoldHi64(&commit, ctx, argv[3])) JABC_FAIL;
    u32 an = 0;
    u64 *ids = JABCcfoldIds(&an, ctx, argv[4]);
    u8 *const dbase = u8bIdle(destb)[0];
    u8s into = {dbase, u8bIdle(destb)[1]};
    u64csc anc = {ids, ids + an};
    ok64 o = CFOLDMerge(into, &w, commit, anc);
    free(ids);
    if (o != OK) JABC_THROW("cfold.merge: failed (buffer full?)");
    return JS_NewFloat64(ctx, (double)(size_t)(into[0] - dbase));
}

//  _cfold_alive(blob, len, outIdle) -> bytes written (the last-folded view)
static JABC_FN(JABCcfoldAlive) {
    if (argc < 3) JABC_THROW("cfold._alive(blob, len, outIdle)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        return JS_NewFloat64(ctx, 0);
    u8 *bb[4] = {};
    if (!JABCIdleOf(bb, ctx, argv[2])) JABC_FAIL;
    if (CFOLDAlive(&w, bb) != OK) JABC_THROW("cfold.alive: output buffer full");
    return JS_NewFloat64(ctx, (double)u8bDataLen(bb));
}

//  _cfold_produce(blob, len, revHashlet, outIdle) -> bytes written
//  The file as commit `rev` saw it; visibility is STORED, so no scope bitmap.
static JABC_FN(JABCcfoldProduce) {
    if (argc < 4) JABC_THROW("cfold._produce(blob, len, rev, outIdle)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        return JS_NewFloat64(ctx, 0);
    u32 rev = 0;
    if (!JABCcfoldRev(&rev, &w, ctx, argv[2]))
        JABC_THROW("cfold.produce: no such commit");
    u8 *bb[4] = {};
    if (!JABCIdleOf(bb, ctx, argv[3])) JABC_FAIL;
    if (CFOLDProduce(&w, rev, bb, NULL) != OK)
        JABC_THROW("cfold.produce: output buffer full");
    return JS_NewFloat64(ctx, (double)u8bDataLen(bb));
}

//  _cfold_blame(blob, len, off) -> the 16-char hashlet of the commit that
//  appended the token at body offset `off` (one range binary search).
static JABC_FN(JABCcfoldBlame) {
    if (argc < 3) JABC_THROW("cfold._blame(blob, len, off)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        JABC_THROW("cfold.blame: the weave is empty or malformed");
    u32 off = 0;
    if (!JABCu32Of(&off, ctx, argv[2])) JABC_FAIL;
    u32 ci = 0;
    if (CFOLDBlame(&ci, &w, off) != OK)
        JABC_THROW("cfold.blame: that offset belongs to no commit");
    cfcommit c = {};
    if (CFOLDCommitAt(&c, &w, ci) != OK)
        JABC_THROW("cfold.blame: malformed weave");
    return JABCcfoldHashlet(ctx, c.id);
}

//  _cfold_itermem(blob, len) -> the step cursor length, in u32 elements
static JABC_FN(JABCcfoldIterMem) {
    if (argc < 2) JABC_THROW("cfold._itermem(blob, len)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        return JS_NewFloat64(ctx, 0);
    return JS_NewFloat64(ctx, (double)CFOLDIterMem(&w));
}

//  _cfold_step(blob, len, revHashlet, cursor) -> token record | false
//  One preorder-DFS step at `rev`.  `cursor` is a JS-owned Uint32Array of
//  _cfold_itermem elements, ZERO-FILLED before the first call — the DFS state
//  lives there and C stays stateless.  The record: `text` (a subarray of the
//  blob), `tag`, `off`/`end` (BODY offsets), `alive`.
static JABC_FN(JABCcfoldStep) {
    if (argc < 4) JABC_THROW("cfold._step(blob, len, rev, cursor)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        return JS_NewBool(ctx, false);
    u32 rev = 0;
    if (!JABCcfoldRev(&rev, &w, ctx, argv[2]))
        JABC_THROW("cfold.step: no such commit");
    u8 *curb[4] = {};
    if (!JABCDataOf(curb, ctx, argv[3])) JABC_FAIL;
    size_t nel = u8bDataLen(curb) / sizeof(u32);
    if (nel < CFOLDIterMem(&w))
        JABC_THROW("cfold.step: the cursor is too small (size it by "
                   "_cfold_itermem)");
    u32 *cur = (u32 *)u8bData(curb)[0];
    u32s mem = {cur, cur + nel};
    cfoldtok t = {};
    b8 got = NO;
    if (CFOLDIterNext(&t, &got, &w, rev, mem) != OK)
        JABC_THROW("cfold.step: the weave is malformed");
    if (!got) return JS_NewBool(ctx, false);
    size_t toff = (size_t)(w.body[0] + t.off - (u8c *)base);
    JSValue text = JABCSubView(ctx, argv[0], toff, (size_t)(t.end - t.off));
    if (JS_IsException(text)) JABC_FAIL;
    JSValue o = JS_NewObject(ctx);
    if (JS_IsException(o)) {
        JS_FreeValue(ctx, text);
        JABC_FAIL;
    }
    JABCSetProp(ctx, o, "text", text);
    JABCSetProp(ctx, o, "tag", JS_NewFloat64(ctx, (double)t.tag));
    JABCSetProp(ctx, o, "off", JS_NewFloat64(ctx, (double)t.off));
    JABCSetProp(ctx, o, "end", JS_NewFloat64(ctx, (double)t.end));
    JABCSetProp(ctx, o, "alive", JS_NewBool(ctx, t.alive));
    return o;
}

//  _cfold_emitdiff(blob, len, name, navver, from, to, hunkDest, hunkOff)
//  -> watermark.  Windowed diff from-rev -> to-rev (both COMMIT HASHLETS),
//  emitted as 'H' records (toks carry the per-token diff side) appended into
//  the HUNK container `hunkDest` at hunkOff.
static JABC_FN(JABCcfoldEmitDiff) {
    if (argc < 8)
        JABC_THROW("cfold._emitdiff(blob,len,name,navver,from,to,hunk,off)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        JABC_THROW("cfold.emitDiff: the weave is empty or malformed");
    u8 ntmp[FILE_PATH_MAX_LEN], vtmp[FILE_PATH_MAX_LEN];
    u8s name = {}, nav = {};
    if (!JABChunkArgU8(name, ctx, argv[2], ntmp, sizeof(ntmp))) JABC_FAIL;
    if (!JABChunkArgU8(nav, ctx, argv[3], vtmp, sizeof(vtmp))) JABC_FAIL;
    u32 from = 0, to = 0;
    if (!JABCcfoldRev(&from, &w, ctx, argv[4]))
        JABC_THROW("cfold.emitDiff: no such commit (from)");
    if (!JABCcfoldRev(&to, &w, ctx, argv[5]))
        JABC_THROW("cfold.emitDiff: no such commit (to)");
    u8 *destb[4] = {};
    if (!JABCIdleOf(destb, ctx, argv[6])) JABC_FAIL;
    if (!JABCBufFed(destb, ctx, argv[7])) JABC_FAIL;  //  DATA = [0,off)
    u8cs namec = {name[0], name[1]}, navc = {nav[0], nav[1]};
    JABCemit em = {{u8bIdle(destb)[0], u8bIdle(destb)[1]}, OK};
    ok64 o = CFOLDEmitDiff(&w, namec, navc, from, to, JABCcfoldEmitCb, &em);
    if (o != OK || em.err != OK)
        JABC_THROW("cfold.emitDiff: failed (buffer full?)");
    return JS_NewFloat64(ctx, (double)(u8bDataLen(destb) +
                                       (size_t)(em.into[0] -
                                                u8bIdle(destb)[0])));
}

//  _cfold_emitfull(blob, len, name, scheme, navver, from, to, hunkDest,
//  hunkOff) -> watermark.  Whole-file variant; `scheme` prefixes the URIs.
static JABC_FN(JABCcfoldEmitFull) {
    if (argc < 9)
        JABC_THROW(
            "cfold._emitfull(blob,len,name,scheme,navver,from,to,hunk,off)");
    cfold w = {};
    u8 *base = NULL;
    if (!JABCcfoldAt(&w, &base, ctx, argv[0], argv[1]))
        JABC_THROW("cfold.emitFull: the weave is empty or malformed");
    u8 ntmp[FILE_PATH_MAX_LEN], stmp[FILE_PATH_MAX_LEN],
        vtmp[FILE_PATH_MAX_LEN];
    u8s name = {}, sch = {}, nav = {};
    if (!JABChunkArgU8(name, ctx, argv[2], ntmp, sizeof(ntmp))) JABC_FAIL;
    if (!JABChunkArgU8(sch, ctx, argv[3], stmp, sizeof(stmp))) JABC_FAIL;
    if (!JABChunkArgU8(nav, ctx, argv[4], vtmp, sizeof(vtmp))) JABC_FAIL;
    u32 from = 0, to = 0;
    if (!JABCcfoldRev(&from, &w, ctx, argv[5]))
        JABC_THROW("cfold.emitFull: no such commit (from)");
    if (!JABCcfoldRev(&to, &w, ctx, argv[6]))
        JABC_THROW("cfold.emitFull: no such commit (to)");
    u8 *destb[4] = {};
    if (!JABCIdleOf(destb, ctx, argv[7])) JABC_FAIL;
    if (!JABCBufFed(destb, ctx, argv[8])) JABC_FAIL;  //  DATA = [0,off)
    u8cs namec = {name[0], name[1]}, schc = {sch[0], sch[1]},
         navc = {nav[0], nav[1]};
    JABCemit em = {{u8bIdle(destb)[0], u8bIdle(destb)[1]}, OK};
    ok64 o =
        CFOLDEmitFull(&w, namec, schc, navc, from, to, JABCcfoldEmitCb, &em);
    if (o != OK || em.err != OK)
        JABC_THROW("cfold.emitFull: failed (buffer full?)");
    return JS_NewFloat64(ctx, (double)(u8bDataLen(destb) +
                                       (size_t)(em.into[0] -
                                                u8bIdle(destb)[0])));
}

ok64 JABCInstallCfold(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    JABC_API_FN(abc, "_cfold_count", JABCcfoldCount);
    JABC_API_FN(abc, "_cfold_commits", JABCcfoldCommits);
    JABC_API_FN(abc, "_cfold_next", JABCcfoldNext);
    JABC_API_FN(abc, "_cfold_merge", JABCcfoldMerge);
    JABC_API_FN(abc, "_cfold_alive", JABCcfoldAlive);
    JABC_API_FN(abc, "_cfold_produce", JABCcfoldProduce);
    JABC_API_FN(abc, "_cfold_blame", JABCcfoldBlame);
    JABC_API_FN(abc, "_cfold_itermem", JABCcfoldIterMem);
    JABC_API_FN(abc, "_cfold_step", JABCcfoldStep);
    JABC_API_FN(abc, "_cfold_emitdiff", JABCcfoldEmitDiff);
    JABC_API_FN(abc, "_cfold_emitfull", JABCcfoldEmitFull);
    JABC_API_END(abc);
    return OK;
}
