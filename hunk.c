//  JAB-036: hunk.c — the port of jab/hunk.hpp.  A u8-backed LOG of TLV 'H'
//  records (one buffer, many hunks) with a write head and a read cursor.  The
//  JS HUNK object owns both cursors; these leaves are stateless — each
//  reconstructs the slice/record it needs from (buffer, offset) per call.
//
//  Append:  _hunk_feed(buf, off, uri, text, toks) -> newoff   (HUNKu8sFeed)
//           _hunk_dogenize(buf, off, src, ext, uri) -> newoff (tokenize + feed)
//  Walk:    _hunk_next(buf, readOff, dataLen) -> recEnd | -1   (HUNKu8sDrain)
//  Current: _hunk_uri/_text/_toks/_verb/_time(buf, recOff)     (zero-copy)
//  Render:  _hunk_render(buf, recOff, out, outOff, mode) -> n
#include "JABC.h"
#include "abc/FILE.h"
#include "dog/HUNK.h"

//  A u8 slice from a JS string (copied into `tmp`, NUL dropped) or a typed
//  array (zero-copy view).  Shared with ulog.c / cfold.c, one static copy per
//  TU (the .hpp leg had one header-inline twin).
b8 JABChunkArgU8(u8s out, JSContext *ctx, JSValueConst v, u8 *tmp, size_t cap);
b8 JABChunkArgU8(u8s out, JSContext *ctx, JSValueConst v, u8 *tmp, size_t cap) {
    if (JS_IsString(v)) {
        size_t n = 0;
        const char *s = JS_ToCStringLen(ctx, &n, v);
        if (s == NULL) return NO;
        if (n >= cap) n = cap ? cap - 1 : 0;
        if (n) memcpy(tmp, s, n);
        JS_FreeCString(ctx, s);
        out[0] = tmp;
        out[1] = tmp + n;
        return YES;
    }
    //  PTR-010: a typed-array arg — DATA is the whole view, read-only here.
    u8 *b[4] = {};
    if (!JABCDataOf(b, ctx, v)) return NO;
    out[0] = u8bData(b)[0];
    out[1] = u8bData(b)[1];
    return YES;
}

//  _hunk_feed(buf, off, uri, text, toks) -> newoff
static JABC_FN(JABChunkFeed) {
    if (argc < 5) JABC_THROW("hunk.feed(buf, off, uri, text, toks)");
    u8 *buf[4] = {};
    if (!JABCIdleOf(buf, ctx, argv[0])) JABC_FAIL;
    if (!JABCBufFed(buf, ctx, argv[1])) JABC_FAIL;  //  DATA = [0,off)
    u8 uritmp[FILE_PATH_MAX_LEN];
    u8s uri = {};
    u8 *textb[4] = {};
    u8 *toksb[4] = {};
    if (!JABChunkArgU8(uri, ctx, argv[2], uritmp, sizeof(uritmp))) JABC_FAIL;
    if (!JABCDataOf(textb, ctx, argv[3])) JABC_FAIL;
    if (!JABCDataOf(toksb, ctx, argv[4])) JABC_FAIL;
    u8 const *const *text = u8bDataC(textb);
    u8 const *const *toks = u8bDataC(toksb);
    hunk hk = {};
    hk.uri[0] = uri[0];
    hk.uri[1] = uri[1];
    hk.text[0] = text[0];
    hk.text[1] = text[1];
    hk.toks[0] = (tok32c *)toks[0];
    //  JS-092: the END is the toks BYTE-end (toks[1]), not start + tok COUNT.
    hk.toks[1] = (tok32c *)toks[1];
    if (HUNKu8sFeed(u8bIdle(buf), &hk) != OK) JABC_THROW("hunk.feed: out full");
    return JS_NewFloat64(ctx, (double)u8bDataLen(buf));
}

//  _hunk_dogenize(buf, off, source, ext, uri) -> newoff
//  Tokenize source via the ext-selected lexer into a transient toks buffer,
//  then serialize a hunk (text=source, toks, uri).  The toks are malloc'd for
//  the call and freed before return — nothing is held, nothing crosses to JS.
static JABC_FN(JABChunkDogenize) {
    if (argc < 4) JABC_THROW("hunk.dogenize(buf, off, source, ext, uri)");
    u8 *buf[4] = {};
    u8 *sourceb[4] = {};
    if (!JABCIdleOf(buf, ctx, argv[0])) JABC_FAIL;
    if (!JABCBufFed(buf, ctx, argv[1])) JABC_FAIL;  //  DATA = [0,off)
    if (!JABCDataOf(sourceb, ctx, argv[2])) JABC_FAIL;
    u8 const *const *source = u8bDataC(sourceb);
    u8 exttmp[64], uritmp[FILE_PATH_MAX_LEN];
    u8s ext = {}, uri = {};
    if (!JABChunkArgU8(ext, ctx, argv[3], exttmp, sizeof(exttmp))) JABC_FAIL;
    if (argc > 4) {
        if (!JABChunkArgU8(uri, ctx, argv[4], uritmp, sizeof(uritmp)))
            JABC_FAIL;
    }
    size_t srcn = $len(source);
    u32 *tm = (u32 *)malloc((srcn + 1) * sizeof(u32));
    if (tm == NULL) JABC_THROW("hunk.dogenize: oom");
    u32 *tb[4] = {tm, tm, tm, tm + srcn + 1};
    u8cs srcc = {source[0], source[1]};
    u8cs extc = {ext[0], ext[1]};
    ok64 o = HUNKu32bTokenize(tb, srcc, extc);
    if (o != OK) {
        free(tm);
        JABC_THROW("hunk.dogenize: lex");
    }
    hunk hk = {};
    hk.uri[0] = uri[0];
    hk.uri[1] = uri[1];
    hk.text[0] = source[0];
    hk.text[1] = source[1];
    hk.toks[0] = (tok32c *)tb[1];
    hk.toks[1] = (tok32c *)tb[2];
    o = HUNKu8sFeed(u8bIdle(buf), &hk);
    free(tm);
    if (o != OK) JABC_THROW("hunk.dogenize: out full");
    return JS_NewFloat64(ctx, (double)u8bDataLen(buf));
}

//  _hunk_next(buf, readOff, dataLen) -> recEnd | -1
static JABC_FN(JABChunkNext) {
    if (argc < 3) JABC_THROW("hunk._next(buf, readOff, dataLen)");
    u8 *buf[4] = {};
    if (!JABCDataOf(buf, ctx, argv[0])) JABC_FAIL;
    size_t r = 0, dl = 0;
    if (!JABCOffOf(&r, u8bDataC(buf), ctx, argv[1])) JABC_FAIL;
    if (!JABCOffOf(&dl, u8bDataC(buf), ctx, argv[2])) JABC_FAIL;
    if (r >= dl) return JS_NewFloat64(ctx, -1);
    u8cs from = {};  //  [r, dl) — abc bounds-checks
    if (dl > 0xffffffffUL ||
        u8csSub(u8bDataC(buf), from, (u32)r, (u32)dl) != OK)
        JABC_THROW("hunk: the record range is out of range");
    hunk hk = {};
    if (HUNKu8sDrain(from, &hk) != OK) return JS_NewFloat64(ctx, -1);
    return JS_NewFloat64(ctx, (double)(size_t)(from[0] - u8bDataC(buf)[0]));
}

//  Drain the record at recOff; the field accessors below re-drain (cheap TLV
//  walk) so no hunk state is held between calls.
//  PTR-010: the JABCpackAt twin — gate the offset, move DATA with u8bUsed.
static b8 JABChunkAt(hunk *hk, u8 *buf[4], JSContext *ctx, JSValueConst bufv,
                     JSValueConst offv) {
    if (!JABCDataOf(buf, ctx, bufv)) return NO;
    if (!JABCBufAt(buf, ctx, offv)) return NO;
    a_dup(u8 const, from, u8bDataC(buf));  //  drain a copy: keep DATA put
    return HUNKu8sDrain(from, hk) == OK;
}

//  JS-092 (commit: pager edge): an EMPTY uri/text is never written to the TLV
//  (HUNK.c:129), so on drain its slice stays NULL — a NULL-minus-buf offset
//  would then be a wild subview.  Return an empty Uint8Array instead.
//  `buf` is the u8b JABChunkAt filled: buf[0] is the view base (PAST head),
//  which JABCBufAt leaves put — the field offset is measured from it.
static JSValue JABChunkField(JSContext *ctx, JSValueConst buf_arg,
                             u8 *const *buf, u8cs fld) {
    if ($empty(fld) || fld[0] == NULL) return JABCBlob(ctx, (u8 const *)"", 0);
    return JABCSubView(ctx, buf_arg, (size_t)((u8c *)fld[0] - buf[0]),
                       (size_t)$len(fld));
}
static JABC_FN(JABChunkUri) {
    if (argc < 2) JABC_THROW("hunk._uri(buf, recOff)");
    u8 *buf[4] = {};
    hunk hk = {};
    if (!JABChunkAt(&hk, buf, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JABChunkField(ctx, argv[0], buf, hk.uri);
}
static JABC_FN(JABChunkText) {
    if (argc < 2) JABC_THROW("hunk._text(buf, recOff)");
    u8 *buf[4] = {};
    hunk hk = {};
    if (!JABChunkAt(&hk, buf, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JABChunkField(ctx, argv[0], buf, hk.text);
}
//  toks may sit at an unaligned offset in the record, so return a fresh
//  (aligned) Uint32Array copy rather than an alias.
static JABC_FN(JABChunkToks) {
    if (argc < 2) JABC_THROW("hunk._toks(buf, recOff)");
    u8 *buf[4] = {};
    hunk hk = {};
    if (!JABChunkAt(&hk, buf, ctx, argv[0], argv[1])) JABC_UNDEF;
    size_t n = (size_t)$len(hk.toks);
    JSValue nv = JS_NewInt64(ctx, (int64_t)n);
    JSValue ta = JS_NewTypedArray(ctx, 1, &nv, JS_TYPED_ARRAY_UINT32);
    JS_FreeValue(ctx, nv);
    if (JS_IsException(ta)) JABC_FAIL;
    u8 *p = NULL;
    size_t plen = 0;
    if (!JABCViewOf(&p, &plen, ctx, ta)) {
        JS_FreeValue(ctx, ta);
        JABC_FAIL;
    }
    if (p && n) memcpy(p, hk.toks[0], n * sizeof(tok32));
    return ta;
}
static JABC_FN(JABChunkVerb) {
    if (argc < 2) JABC_THROW("hunk._verb(buf, recOff)");
    u8 *buf[4] = {};
    hunk hk = {};
    if (!JABChunkAt(&hk, buf, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JABCBigU64(ctx, (u64)hk.verb);
}
static JABC_FN(JABChunkTime) {
    if (argc < 2) JABC_THROW("hunk._time(buf, recOff)");
    u8 *buf[4] = {};
    hunk hk = {};
    if (!JABChunkAt(&hk, buf, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JABCBigU64(ctx, (u64)hk.ts);
}

//  _hunk_render(buf, recOff, out, outOff, mode) -> bytes written
//  mode: 1 = color (ANSI), 2 = plain, 3 = html.
static JABC_FN(JABChunkRender) {
    if (argc < 5) JABC_THROW("hunk._render(buf, recOff, out, outOff, mode)");
    u8 *buf[4] = {};
    hunk hk = {};
    if (!JABChunkAt(&hk, buf, ctx, argv[0], argv[1]))
        JABC_THROW("hunk.render: bad record");
    u8 *outb[4] = {};
    if (!JABCIdleOf(outb, ctx, argv[2])) JABC_FAIL;
    if (!JABCBufFed(outb, ctx, argv[3])) JABC_FAIL;  //  DATA = [0,oo)
    u32 mode = 0;
    if (!JABCu32Of(&mode, ctx, argv[4])) JABC_FAIL;
    size_t before = u8bDataLen(outb);
    ok64 o;
    if (mode == 3) o = HUNKu8sFeedHtml(u8bIdle(outb), &hk);
    else if (mode == 1) o = HUNKu8sFeedColor(u8bIdle(outb), &hk);
    else o = HUNKu8sFeedText(u8bIdle(outb), &hk);
    if (o != OK) JABC_THROW("hunk.render: out full");
    return JS_NewFloat64(ctx, (double)(u8bDataLen(outb) - before));
}

ok64 JABCInstallHunk(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    JABC_API_FN(abc, "_hunk_feed", JABChunkFeed);
    JABC_API_FN(abc, "_hunk_dogenize", JABChunkDogenize);
    JABC_API_FN(abc, "_hunk_next", JABChunkNext);
    JABC_API_FN(abc, "_hunk_uri", JABChunkUri);
    JABC_API_FN(abc, "_hunk_text", JABChunkText);
    JABC_API_FN(abc, "_hunk_toks", JABChunkToks);
    JABC_API_FN(abc, "_hunk_verb", JABChunkVerb);
    JABC_API_FN(abc, "_hunk_time", JABChunkTime);
    JABC_API_FN(abc, "_hunk_render", JABChunkRender);
    JABC_API_END(abc);
    return OK;
}
