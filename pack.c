//  JAB-036: pack.c — the port of jab/pack.hpp.
//  PACK — an OFFSET-ADDRESSED git pack log (header + [obj-hdr][zlib] records)
//  in a u8 buffer.  Reads/writes are byte offsets only; sha addressing is the
//  index's job (a wh128 layer above), so this binding never takes a sha.
//
//  GIT-007: PURE marshalling over the dog/git pack-log core.  Every entry
//  resolves a typed array to a u8b (JABCDataOf/JABCIdleOf, PTR-010) and calls
//  ONE dog/git PACK function — no delta/encode/inflate decisions here.
//
//  write: _pack_header(buf,off,count)->end ; _pack_feed(buf,off,type,content,
//         base,baseOff,delta)->end
//  read:  _pack_next(buf,off,dataLen)->objEnd|-1 ;
//         _pack_resolve(buf,recOff,base,delta) -> resolved bytes (Uint8Array) ;
//         _pack_type/_size/_baseoff/_ref/_inflate(buf,recOff,...)
#include "JABC.h"
#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "dog/git/DELT.h"
#include "dog/git/GIT.h"
#include "dog/git/PACK.h"
#include "dog/git/PIDX.h"
#include "dog/git/REPACK.h"
#include "dog/git/ZINF.h"

//  A fresh lowercase-hex JS string over `n` raw bytes (sha shorthand).
static JSValue JABCHexOf(JSContext *ctx, const u8 *bin, size_t n) {
    char *h = (char *)malloc(n * 2 + 1);
    if (h == NULL) return JS_UNDEFINED;
    u8s hx = {(u8 *)h, (u8 *)h + n * 2};
    u8cs b = {(u8 *)bin, (u8 *)bin + n};
    HEXu8sFeedSome(hx, b);
    JSValue v = JS_NewStringLen(ctx, h, n * 2);
    free(h);
    return v;
}

//  _pack_header(buf, off, count) -> off+12
static JABC_FN(JABCpackHeader) {
    if (argc < 3) JABC_THROW("pack._header(buf, off, count)");
    u8 *c[4] = {};
    if (!JABCIdleOf(c, ctx, argv[0])) JABC_FAIL;
    if (!JABCBufFed(c, ctx, argv[1])) JABC_FAIL;  //  DATA = [0,off)
    u32 count = 0;
    if (!JABCu32Of(&count, ctx, argv[2])) JABC_FAIL;
    if (PACKu8sFeedHdr(u8bIdle(c), count) != OK) JABC_THROW("pack: header");
    return JS_NewFloat64(ctx, (double)u8bDataLen(c));
}

//  _pack_count(buf) -> object count (from the 12-byte header)
static JABC_FN(JABCpackCount) {
    if (argc < 1) JABC_THROW("pack._count(buf)");
    u8 *c[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;
    pack_hdr hdr = {};
    if (PACKDrainHdr(u8bDataC(c), &hdr) != OK) JABC_THROW("pack: bad header");
    return JS_NewFloat64(ctx, (double)hdr.count);
}

//  _pack_feed(buf, off, type, content, base, baseOff, delta) -> new write head
//  GIT-007: pure marshalling — resolve the typed arrays and hand the
//  raw|OFS_DELTA decision + emit to the dog/git writer PACKu8sFeedObj.
static JABC_FN(JABCpackFeed) {
    if (argc < 4)
        JABC_THROW(
            "pack._feed(buf, off, type, content, base, baseOff, delta)");
    u8 *logb[4] = {};
    u8 *contentb[4] = {};
    u8 *baseb[4] = {};
    u8 *deltab[4] = {};
    if (!JABCIdleOf(logb, ctx, argv[0])) JABC_FAIL;
    if (!JABCBufFed(logb, ctx, argv[1])) JABC_FAIL;  //  DATA = [0,off)
    size_t off = u8bDataLen(logb);
    u8 type = 0;
    if (!JABCu8Of(&type, ctx, argv[2])) JABC_FAIL;
    if (!JABCDataOf(contentb, ctx, argv[3])) JABC_FAIL;
    //  base (resolved bytes) + baseOff are optional: absent/empty → raw record.
    if (argc > 4 && !JABCDataOf(baseb, ctx, argv[4])) JABC_FAIL;
    i64 bod = -1;  //  -1 = no base (the shim's sentinel)
    if (argc > 5 && !JABCi64Of(&bod, ctx, argv[5])) JABC_FAIL;
    u64 base_off = bod >= 0 ? (u64)bod : (u64)off;
    if (argc > 6 && !JABCIdleOf(deltab, ctx, argv[6])) JABC_FAIL;
    if (PACKu8sFeedObj((u8bp)logb, type, u8bDataC(contentb), u8bDataC(baseb),
                       (u64)off, base_off, (u8bp)deltab, NULL) != OK)
        JABC_THROW("pack: feed (full?)");
    return JS_NewFloat64(ctx, (double)u8bBusyLen(logb));
}

//  Drain the object header at recOff (advancing nothing the caller sees).
//  PTR-010: `rec` is a JS number — git.pack leaves -1 in `_rec` after a failed
//  seek, so the offset is gated and moved by u8bUsed; the consumed prefix is
//  PAST, so `c` still spans the whole log for the callers that need it.
static b8 JABCpackAt(pack_obj *obj, u8 *c[4], JSContext *ctx,
                     JSValueConst bufv, JSValueConst offv) {
    if (!JABCDataOf(c, ctx, bufv)) return NO;
    if (!JABCBufAt(c, ctx, offv)) return NO;
    a_dup(u8 const, from, u8bDataC(c));  //  drain a copy: keep DATA put
    return PACKDrainObjHdr(from, obj) == OK;
}

//  _pack_next(buf, off, dataLen) -> end of the object at off | -1
//  GIT-007: a zlib stream isn't length-delimited, so ask the dog/git resolver
//  where the record ends — no JS-side re-inflate-to-measure.
static JABC_FN(JABCpackNext) {
    if (argc < 3) JABC_THROW("pack._next(buf, off, dataLen)");
    u8 *c[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;
    size_t off = 0, dl = 0;
    if (!JABCOffOf(&off, u8bDataC(c), ctx, argv[1])) JABC_FAIL;
    if (!JABCOffOf(&dl, u8bDataC(c), ctx, argv[2])) JABC_FAIL;
    if (off >= dl) return JS_NewFloat64(ctx, -1);
    u8cs pack = {};  //  [0, dl) — abc bounds-checks
    if (dl > 0xffffffffUL || u8csSub(u8bDataC(c), pack, 0, (u32)dl) != OK)
        JABC_THROW("pack: the data length is out of range");
    u64 end = 0;
    if (PACKRecordEnd(pack, (u64)off, &end) != OK)
        return JS_NewFloat64(ctx, -1);
    return JS_NewFloat64(ctx, (double)(size_t)end);
}

static JABC_FN(JABCpackType) {
    u8 *c[4] = {};
    pack_obj o = {};
    if (argc < 2 || !JABCpackAt(&o, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JS_NewFloat64(ctx, (double)o.type);
}
static JABC_FN(JABCpackSize) {
    u8 *c[4] = {};
    pack_obj o = {};
    if (argc < 2 || !JABCpackAt(&o, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JS_NewFloat64(ctx, (double)o.size);
}
static JABC_FN(JABCpackBaseOff) {
    u8 *c[4] = {};
    pack_obj o = {};
    if (argc < 2 || !JABCpackAt(&o, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    if (o.type != PACK_OBJ_OFS_DELTA) return JS_NewFloat64(ctx, -1);
    //  the record's own offset is what JABCpackAt consumed into PAST
    return JS_NewFloat64(ctx, (double)(u8bPastLen(c) - o.ofs_delta));
}
static JABC_FN(JABCpackRef) {
    u8 *c[4] = {};
    pack_obj o = {};
    if (argc < 2 || !JABCpackAt(&o, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    if (o.type != PACK_OBJ_REF_DELTA) JABC_UNDEF;
    return JABCBlob(ctx, o.ref_delta[0], 20);
}

//  _pack_inflate(buf, recOff, out, outOff) -> bytes inflated (= obj.size)
//  Raw single-record read: drain the header, inflate the one zlib stream.
static JABC_FN(JABCpackInflate) {
    if (argc < 4) JABC_THROW("pack._inflate(buf, recOff, out, outOff)");
    u8 *c[4] = {};
    pack_obj o = {};
    if (!JABCpackAt(&o, c, ctx, argv[0], argv[1]))
        JABC_THROW("pack: bad record");
    u8 *out[4] = {};
    if (!JABCIdleOf(out, ctx, argv[2])) JABC_FAIL;
    if (!JABCBufFed(out, ctx, argv[3])) JABC_FAIL;
    a_dup(u8 const, from, u8bDataC(c));  //  the record, header still on
    pack_obj tmp = {};
    PACKDrainObjHdr(from, &tmp);
    if (PACKInflate(from, u8bIdle(out), tmp.size) != OK)
        JABC_THROW("pack: inflate (out full?)");
    return JS_NewFloat64(ctx, (double)(size_t)tmp.size);
}

//  _pack_resolve(buf, recOff, base, delta) -> resolved object bytes
//  GIT-007: the WHOLE delta chase is the dog/git resolver PACKResolveOfs;
//  base/delta are caller-owned scratch, the result is copied out to a fresh
//  Uint8Array (the chase aliasing stays inside the scratch, never leaks).
static JABC_FN(JABCpackResolve) {
    if (argc < 4) JABC_THROW("pack._resolve(buf, recOff, base, delta)");
    u8 *c[4] = {};
    u8 *base[4] = {};
    u8 *delta[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;
    size_t rec = 0;  //  a position, not a boundary
    if (!JABCOffOf(&rec, u8bDataC(c), ctx, argv[1])) JABC_FAIL;
    if (!JABCIdleOf(base, ctx, argv[2])) JABC_FAIL;   //  OFS-delta
    if (!JABCIdleOf(delta, ctx, argv[3])) JABC_FAIL;  //  reads back
    a_dup(u8 const, pack, u8bDataC(c));
    u8cs out = {};
    u8 type = 0;
    //  JS-055: surface NOROOM distinctly (the wrapper grows scratch); REF_DELTA
    //  stays its own loud fail so detection isn't lost to a grow loop.
    ok64 r =
        PACKResolveOfs(pack, (u64)rec, u8bIdle(base), u8bIdle(delta), out,
                       &type);
    if (r == NOROOM) JABC_THROW("pack: resolve NOROOM");
    if (r == PACKREF) JABC_THROW("pack: resolve ref-delta");
    if (r != OK) JABC_THROW("pack: resolve");
    return JABCBlob(ctx, out[0], (size_t)u8csLen(out));
}

//  _delt_apply(base, delta, out, outOff) -> reconstructed bytes
static JABC_FN(JABCdeltApply) {
    if (argc < 4) JABC_THROW("delt._apply(base, delta, out, outOff)");
    u8 *baseb[4] = {};
    u8 *deltab[4] = {};
    u8 *outb[4] = {};
    if (!JABCDataOf(baseb, ctx, argv[0])) JABC_FAIL;
    if (!JABCDataOf(deltab, ctx, argv[1])) JABC_FAIL;
    if (!JABCIdleOf(outb, ctx, argv[2])) JABC_FAIL;
    if (!JABCBufFed(outb, ctx, argv[3])) JABC_FAIL;
    size_t before = u8bDataLen(outb);
    if (DELTApply(u8bDataC(deltab), u8bDataC(baseb), u8bDataIdle(outb)) != OK)
        JABC_THROW("delt: apply (out full?)");
    return JS_NewFloat64(ctx, (double)(u8bDataLen(outb) - before));
}

//  JS-036: _delt_encode(base, target, out, outOff) -> n delta bytes appended
//  at out[outOff], or -1 on DELTFAIL (delta not smaller than target -> raw).
static JABC_FN(JABCdeltEncode) {
    if (argc < 4) JABC_THROW("delt._encode(base, target, out, outOff)");
    u8 *baseb[4] = {};
    u8 *targetb[4] = {};
    u8 *outb[4] = {};
    if (!JABCDataOf(baseb, ctx, argv[0])) JABC_FAIL;
    if (!JABCDataOf(targetb, ctx, argv[1])) JABC_FAIL;
    if (!JABCIdleOf(outb, ctx, argv[2])) JABC_FAIL;
    if (!JABCBufFed(outb, ctx, argv[3])) JABC_FAIL;  //  DATA = [0,oo)
    size_t before = u8bDataLen(outb);
    ok64 r = DELTEncode(u8bDataC(baseb), u8bDataC(targetb), (u8bp)outb);
    if (r == DELTFAIL) return JS_NewFloat64(ctx, -1);
    if (r != OK) JABC_THROW("delt: encode");
    return JS_NewFloat64(ctx, (double)(u8bDataLen(outb) - before));
}

//  _pack_scan(buf, dataLen, out, base, delta) -> entry count
//  GIT-010: pure marshalling over the dog/git scan-emit PIDXScan.  Walk the
//  whole pack [0, dataLen), resolve+git-sha each object, and drop one wh128
//  `(key=hashlet60|type, val=offset)` entry per object STRAIGHT into the
//  caller's region `out` (a Buf's IDLE), returning the entry count.  Guards,
//  ALL before any write: out must be 8-byte aligned and hold count*16 bytes
//  worst case, so a partial scan never half-fills a reused buffer.
static JABC_FN(JABCpackScan) {
    if (argc < 5) JABC_THROW("pack._scan(buf, dataLen, out, base, delta)");
    u8 *c[4] = {};
    u8 *outb[4] = {};
    u8 *baseb[4] = {};
    u8 *deltab[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;
    size_t dl = 0;
    if (!JABCOffOf(&dl, u8bDataC(c), ctx, argv[1])) JABC_FAIL;
    if (!JABCIdleOf(outb, ctx, argv[2])) JABC_FAIL;
    if (!JABCIdleOf(baseb, ctx, argv[3])) JABC_FAIL;
    if (!JABCIdleOf(deltab, ctx, argv[4])) JABC_FAIL;
    u8cs pack = {};  //  [0, dl) — abc bounds-checks
    if (dl > 0xffffffffUL || u8csSub(u8bDataC(c), pack, 0, (u32)dl) != OK)
        JABC_THROW("pack.scan: the data length is out of range");
    pack_hdr hdr = {};
    a_dup(u8 const, hv, pack);  //  PACKDrainHdr CONSUMES — validate on a copy
    if (PACKDrainHdr(hv, &hdr) != OK) JABC_THROW("pack.scan: bad header");
    u8 *const *out = u8bIdle(outb);
    if (((uintptr_t)out[0] & 7u) != 0)
        JABC_THROW("pack.scan: out not 8-byte aligned (reset the Buf)");
    size_t need = (size_t)hdr.count * sizeof(wh128);
    if (u8bIdleLen(outb) < need) JABC_THROW("pack.scan: out too small");
    //  Bwh128 over the caller's region: emit lands at [out[0], out[1]).
    wh128 *wb = (wh128 *)out[0];
    wh128 *wcap = wb + u8bIdleLen(outb) / sizeof(wh128);
    wh128 *wbuf[4] = {wb, wb, wb, wcap};
    //  PACK-001: 0 = whole pack
    ok64 r = PIDXScan(pack, 0, wbuf, u8bIdle(baseb), u8bIdle(deltab));
    if (r == NOROOM) JABC_THROW("pack.scan: NOROOM");
    if (r == PACKREF) JABC_THROW("pack.scan: ref-delta");
    if (r != OK) JABC_THROW("pack.scan: scan (out full? corrupt?)");
    size_t n = (size_t)(wbuf[2] - wb);  //  emitted entries (DATA grew by n)
    return JS_NewFloat64(ctx, (double)n);
}

//  _pack_feed_emit(type, content, offset, out, outOff) -> 16 (bytes written)
//  GIT-010: the index-on-append twin — git-sha the content the caller JUST
//  fed (no resolve) and write ONE wh128 entry at out[outOff].
static JABC_FN(JABCpackFeedEmit) {
    if (argc < 5)
        JABC_THROW("pack._feed_emit(type, content, offset, out, outOff)");
    u8 type = 0;
    if (!JABCu8Of(&type, ctx, argv[0])) JABC_FAIL;
    u8 *contentb[4] = {};
    u8 *outb[4] = {};
    if (!JABCDataOf(contentb, ctx, argv[1])) JABC_FAIL;
    u64 offset = 0;
    if (!JABCu64Of(&offset, ctx, argv[2])) JABC_FAIL;
    if (!JABCIdleOf(outb, ctx, argv[3])) JABC_FAIL;
    if (!JABCBufFed(outb, ctx, argv[4])) JABC_FAIL;  //  slot at outOff
    u8 *slot = u8bIdle(outb)[0];
    if (((uintptr_t)slot & 7u) != 0)
        JABC_THROW("pack.feedEmit: out slot not 8-byte aligned");
    if (u8bIdleLen(outb) < sizeof(wh128))
        JABC_THROW("pack.feedEmit: out full");
    wh128 *wbuf[4] = {(wh128 *)slot, (wh128 *)slot, (wh128 *)slot,
                      (wh128 *)slot + 1};
    if (PIDXFeedEmit(wbuf, type, u8bDataC(contentb), offset) != OK)
        JABC_THROW("pack.feedEmit: emit");
    return JS_NewFloat64(ctx, (double)sizeof(wh128));
}

//  _git_tree_next(bytes, off) -> {mode, nameStart, nameEnd, sha, nextOff} | null
//  JS-028: ONE pure-marshalling drain of a single tree entry via the dog/git
//  parser GITu8sDrainTree.  The binding holds nothing: it re-slices the
//  caller's typed array from `off`, drains one entry, and reports the name span
//  (positions into `bytes`), the parsed octal mode, the 40-hex sha and the next
//  read offset.  At end-of-tree -> null.
static JABC_FN(JABCgitTreeNext) {
    if (argc < 2) JABC_THROW("git._tree_next(bytes, off)");
    u8 *c[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;
    size_t off = 0;
    if (!JABCOffOf(&off, u8bDataC(c), ctx, argv[1])) JABC_FAIL;
    if (off >= u8bDataLen(c)) return JS_NULL;
    if (!JABCBufAt(c, ctx, argv[1])) JABC_FAIL;
    a_dup(u8 const, obj, u8bDataC(c));  //  drained below; DATA stays put
    u8cs file = {}, sha1 = {};
    u32 mode = 0;
    ok64 r = GITu8sDrainTree(obj, file, sha1, &mode);
    if (r == NODATA) return JS_NULL;
    if (r != OK) JABC_THROW("git.tree: bad tree entry");
    //  Split "<mode> <name>" -> bare name span (positions into the source).
    u8cs name = {};
    GITu8sFileSplit(file, NULL, name);
    JSValue o = JS_NewObject(ctx);
    JABCSetProp(ctx, o, "mode", JS_NewFloat64(ctx, (double)mode));
    //  spans as positions in the SOURCE bytes: PAST is what we skipped to `off`
    size_t base = u8bPastLen(c);
    JABCSetProp(
        ctx, o, "nameStart",
        JS_NewFloat64(ctx,
                      (double)(base + (size_t)(name[0] - u8bDataC(c)[0]))));
    JABCSetProp(
        ctx, o, "nameEnd",
        JS_NewFloat64(ctx,
                      (double)(base + (size_t)(name[1] - u8bDataC(c)[0]))));
    JABCSetProp(ctx, o, "sha", JABCHexOf(ctx, sha1[0], GIT_SHA1_LEN));
    JABCSetProp(
        ctx, o, "nextOff",
        JS_NewFloat64(ctx,
                      (double)(base + (size_t)(obj[0] - u8bDataC(c)[0]))));
    return o;
}

//  _git_parse_commit(bytes) -> {tree, parents[], foster[], author, committer, body}
//  JS-028: eager — commit objects are small.  Drives the dog/git header
//  iterator GITu8sDrainCommit plus GITu8sCommitTree for the tree sha.  No
//  manual git framing in JS — every split is a dog/git drain.
static JABC_FN(JABCgitParseCommit) {
    if (argc < 1) JABC_THROW("git._parse_commit(bytes)");
    u8 *c[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;

    JSValue o = JS_NewObject(ctx);

    //  tree sha (binary -> hex); empty string when absent/malformed.
    a_dup(u8 const, commit, u8bDataC(c));
    u8 tree_sha[GIT_SHA1_LEN] = {};
    if (GITu8sCommitTree(commit, tree_sha) == OK)
        JABCSetProp(ctx, o, "tree", JABCHexOf(ctx, tree_sha, GIT_SHA1_LEN));
    else
        JABCSetProp(ctx, o, "tree", JSOfCString(""));

    //  Walk the headers: collect parents/foster (hex sha values), pick the last
    //  author/committer ident lines; the blank line yields the body.
    JSValue parents = JS_NewArray(ctx);
    JSValue foster = JS_NewArray(ctx);
    JSValue author = JS_UNDEFINED;
    JSValue committer = JS_UNDEFINED;
    JSValue body = JSOfCString("");
    uint32_t np = 0, nf = 0;

    a_dup(u8 const, scan, u8bDataC(c));
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if (field[0] == field[1]) {  //  blank line -> body is the rest
            JS_FreeValue(ctx, body);
            body = JABCStrOfSlice(ctx, value);
            break;
        }
        JSValue hv = JABCStrOfSlice(ctx, value);
        if (u8csEq(field, GIT_FIELD_PARENT))
            JS_SetPropertyUint32(ctx, parents, np++, hv);
        else if (u8csEq(field, GIT_FIELD_FOSTER))
            JS_SetPropertyUint32(ctx, foster, nf++, hv);
        else if (u8csEq(field, GIT_FIELD_AUTHOR)) {
            JS_FreeValue(ctx, author);
            author = hv;
        } else if (u8csEq(field, GIT_FIELD_COMMITTER)) {
            JS_FreeValue(ctx, committer);
            committer = hv;
        } else {
            JS_FreeValue(ctx, hv);  //  qjs: an unused ref is ours to drop
        }
    }

    JABCSetProp(ctx, o, "parents", parents);
    JABCSetProp(ctx, o, "foster", foster);
    JABCSetProp(ctx, o, "author", author);
    JABCSetProp(ctx, o, "committer", committer);
    JABCSetProp(ctx, o, "body", body);
    return o;
}

//  --- JAB-020: git.pack(fd, buf, shard, opts) -> stats ------------------
//
//  ONE call per fetch.  The whole ingest loop lives in dog/git/REPACK.c, so the
//  boundary is crossed once instead of once per object and no pack byte is ever
//  materialised in the JS heap.  `buf` is a JS Buf whose DATA is what the
//  pkt-line reader already ate off the wire; the binding reconstitutes a u8b
//  over it and writes the advanced `_data`/`_idle` back.

//  PTR-010: an absent option falls back to `dflt`; a present one goes through
//  the gate, so a garbage opts.cap can't become a wild size.
static u64 JABCOptNumOf(JSContext *ctx, JSValueConst o, const char *name,
                        u64 dflt) {
    if (!JS_IsObject(o)) return dflt;
    JSValue v = JABCGetProp(ctx, o, name);
    u64 n = dflt;
    if (!JS_IsUndefined(v) && !JS_IsNull(v) && !JABCu64Of(&n, ctx, v)) {
        JS_FreeValue(ctx, JS_GetException(ctx));  //  a bad option is the dflt
        n = dflt;
    }
    JS_FreeValue(ctx, v);
    return n;
}

//  The stats record REPACKRun fills, as a plain JS object.
static JSValue JABCPackStats(JSContext *ctx, repack_stat const *st) {
    JSValue o = JS_NewObject(ctx);
    JABCSetProp(ctx, o, "objects", JS_NewFloat64(ctx, (double)st->objects));
    JABCSetProp(ctx, o, "total", JS_NewFloat64(ctx, (double)st->total));
    JABCSetProp(ctx, o, "raw", JS_NewFloat64(ctx, (double)st->raw));
    JABCSetProp(ctx, o, "ofs", JS_NewFloat64(ctx, (double)st->ofs));
    JABCSetProp(ctx, o, "ref", JS_NewFloat64(ctx, (double)st->ref));
    JABCSetProp(ctx, o, "inBytes", JS_NewFloat64(ctx, (double)st->in_bytes));
    JABCSetProp(ctx, o, "outBytes", JS_NewFloat64(ctx, (double)st->out_bytes));
    JABCSetProp(ctx, o, "log0", JS_NewFloat64(ctx, (double)st->log0));
    JABCSetProp(ctx, o, "logs", JS_NewFloat64(ctx, (double)st->logs));
    JABCSetProp(ctx, o, "logLen", JS_NewFloat64(ctx, (double)st->log_len));
    JABCSetProp(ctx, o, "indexN", JS_NewFloat64(ctx, (double)st->index_n));
    return o;
}

//  Progress: one JS call every `every` objects, the live stats as its arg.
//  A throwing handler stops the run (its exception is re-raised below).
typedef struct {
    JSContext *ctx;
    JSValue fn;
    JSValue exc;
    b8 threw;
} jabc_repack_watch;

static ok64 JABCPackWatch(void *user, repack_stat const *st) {
    jabc_repack_watch *w = (jabc_repack_watch *)user;
    JSValue arg = JABCPackStats(w->ctx, st);
    JSValue r = JS_Call(w->ctx, w->fn, JS_UNDEFINED, 1, (JSValueConst *)&arg);
    JS_FreeValue(w->ctx, arg);
    if (!JS_IsException(r)) {
        JS_FreeValue(w->ctx, r);
        return OK;
    }
    if (!w->threw) {  //  hold the FIRST throw; REPACKRun unwinds to the leaf
        w->exc = JS_GetException(w->ctx);
        w->threw = YES;
    }
    return REPACKFAIL;
}

//  Errors cross the boundary in PLAIN WORDS, never as an ok64 code.
static const char *JABCPackWords(ok64 o) {
    if (o == REPACKTORN)
        return "pack: the stream ended in the middle of a record";
    if (o == REPACKBIG)
        return "pack: an object is too big for the buffer and the log cap";
    if (o == REPACKBASE) return "pack: a delta cites a base that never arrived";
    if (o == REPACKROOM) return "pack: the index region is full";
    if (o == REPACKLOGS) return "pack: the stream needs more logs than allowed";
    if (o == REPACKHDR)
        return "pack: the stream does not start with a pack header";
    if (o == REPACKSUM)
        return "pack: the stream's checksum does not match — it arrived damaged";
    if (o == ZINFFAIL) return "pack: the compressed data is damaged";
    if (o == PACKBADFMT || o == PACKBADOBJ)
        return "pack: malformed pack record";
    if (o == DELTFAIL || o == DELTBADFMT)
        return "pack: a delta could not be applied";
    return "pack: the stream could not be repacked";
}

//  git.pack(fd, buf, shard, opts) -> stats
//    opts.cap     per-log byte cap (default 2^31-1)
//    opts.log0    first `NNNNNNNNNN.keeper` file id in the shard
//    opts.index   caller's wh128 region for the index entries
//    opts.every   progress granularity in objects
//    opts.onStep  progress handler, called with the live stats
static JABC_FN(JABCpackRepack) {
    if (argc < 3) JABC_THROW("git.pack(fd, buf, shard, opts) -> stats");
    i64 fdv = -1;
    if (!JABCi64Of(&fdv, ctx, argv[0])) JABC_FAIL;
    int fd = (int)fdv;
    if (fdv < 0 || fdv != (i64)fd) JABC_THROW("git.pack: bad fd");
    if (!JS_IsObject(argv[1])) JABC_THROW("git.pack: buf must be a Buf");
    u8 *buf[4] = {};  //  cursors gated + checked in arg.c
    if (!JABCBufOf(buf, ctx, argv[1])) JABC_FAIL;

    a_pad(u8, shard, FILE_PATH_MAX_LEN);
    if (JABCPath(shard, ctx, argv[2]) != OK)
        JABC_THROW("git.pack: bad shard path");

    JSValueConst oo = (argc > 3 && JS_IsObject(argv[3])) ? argv[3] : JS_NULL;
    u8 *ixb[4] = {};
    b8 haveix = NO;
    if (JS_IsObject(oo)) {
        JSValue iv = JABCGetProp(ctx, oo, "index");
        haveix = JABCIdleOf(ixb, ctx, iv);
        JS_FreeValue(ctx, iv);
    }
    if (!haveix) {
        if (JS_HasException(ctx)) JABC_FAIL;
        JABC_THROW("git.pack: opts.index (a wh128 region) is required");
    }
    wh128 *ib = (wh128 *)u8bIdle(ixb)[0];
    if (((uintptr_t)ib & 7u) != 0)
        JABC_THROW("git.pack: opts.index is not 8-byte aligned");
    wh128 *icap = ib + u8bIdleLen(ixb) / sizeof(wh128);
    wh128 *ibuf[4] = {ib, ib, ib, icap};

    jabc_repack_watch w = {ctx, JS_UNDEFINED, JS_UNDEFINED, NO};
    if (JS_IsObject(oo)) {
        JSValue cb = JABCGetProp(ctx, oo, "onStep");
        if (JS_IsFunction(ctx, cb))
            w.fn = cb;
        else
            JS_FreeValue(ctx, cb);
    }
    repack_conf conf = {};
    conf.cap = JABCOptNumOf(ctx, oo, "cap", 0);
    conf.log0 = (u32)JABCOptNumOf(ctx, oo, "log0", 0);
    conf.every = JABCOptNumOf(ctx, oo, "every", 0);
    if (!JS_IsUndefined(w.fn)) {
        conf.watch = JABCPackWatch;
        conf.user = &w;
        if (conf.every == 0) conf.every = 100000;
    }

    repack_stat st = {};
    ok64 r = REPACKRun(fd, buf, $path(shard), &conf, ibuf, &st);
    //  Hand the consumed/filled boundaries back to the caller's Buf either
    //  way — a failed run still ate what it ate.
    JABCBufBack(ctx, argv[1], buf);
    JS_FreeValue(ctx, w.fn);
    if (w.threw) return JS_Throw(ctx, w.exc);  //  the handler's own throw
    if (r != OK) JABC_THROW(JABCPackWords(r));
    return JABCPackStats(ctx, &st);
}

ok64 JABCInstallPack(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    JABC_API_FN(abc, "_pack_repack", JABCpackRepack);
    JABC_API_FN(abc, "_git_tree_next", JABCgitTreeNext);
    JABC_API_FN(abc, "_git_parse_commit", JABCgitParseCommit);
    JABC_API_FN(abc, "_pack_header", JABCpackHeader);
    JABC_API_FN(abc, "_pack_count", JABCpackCount);
    JABC_API_FN(abc, "_pack_feed", JABCpackFeed);
    JABC_API_FN(abc, "_pack_next", JABCpackNext);
    JABC_API_FN(abc, "_pack_type", JABCpackType);
    JABC_API_FN(abc, "_pack_size", JABCpackSize);
    JABC_API_FN(abc, "_pack_baseoff", JABCpackBaseOff);
    JABC_API_FN(abc, "_pack_ref", JABCpackRef);
    JABC_API_FN(abc, "_pack_inflate", JABCpackInflate);
    JABC_API_FN(abc, "_pack_resolve", JABCpackResolve);
    JABC_API_FN(abc, "_pack_scan", JABCpackScan);
    JABC_API_FN(abc, "_pack_feed_emit", JABCpackFeedEmit);
    JABC_API_FN(abc, "_delt_apply", JABCdeltApply);
    JABC_API_FN(abc, "_delt_encode", JABCdeltEncode);
    JABC_API_END(abc);
    return OK;
}
