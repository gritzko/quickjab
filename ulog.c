//  JAB-036: ulog.c — the port of jab/ulog.hpp.  ULOG is an append-only
//  (ts, verb, uri) text log with NO index: the third u8 cursor-log family
//  (sibling of HUNK/PACK), built on the stateless ULOGu8sFeed/ULOGu8sDrain row
//  codec.  feed moves the append watermark; the seek* primitives are pure
//  (offset -> offset).  No header (rows start at byte 0); reverse scans start
//  from .end (the watermark).
#include "JABC.h"
#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/RON.h"
#include "dog/DOG.h"
#include "dog/ULOG.h"

//  hunk.c's string-or-bytes arg reader (one implementation, three consumers).
b8 JABChunkArgU8(u8s out, JSContext *ctx, JSValueConst v, u8 *tmp, size_t cap);

//  ULOGu8sDrain leaves rec.uri.data empty (only the parsed components are
//  set), so reconstruct the URI text from the components via URIMake — the
//  inverse of what feed serialized.  Returns the byte length written to out.
static size_t JABCulogUriText(u8 *out, size_t cap, ulogrec *rec) {
    u8s into = {out, out + cap};
    if (URIMake(into, rec->uri.scheme, rec->uri.authority, rec->uri.path,
                rec->uri.query, rec->uri.fragment) != OK)
        return 0;
    return (size_t)(into[0] - out);
}

//  JS-108: the URI text as a JS string, buffer sized from the components —
//  long URIs read back whole (was: URIMake NOROOM on a 2048 pad -> "").
static JSValue JABCulogUriStr(JSContext *ctx, ulogrec *rec) {
    size_t bound = 3 * ($len(rec->uri.scheme) + $len(rec->uri.authority) +
                        $len(rec->uri.path) + $len(rec->uri.query) +
                        $len(rec->uri.fragment)) +
                   16;  //  3x: URIMake may percent-escape; +16: the sigils
    u8 pad[2048];
    u8 *buf = pad;
    if (bound > sizeof(pad)) {
        buf = (u8 *)malloc(bound);
        if (buf == NULL) JABC_THROW("ulog uri: out of memory");
    }
    size_t cap = bound > sizeof(pad) ? bound : sizeof(pad);
    size_t n = JABCulogUriText(buf, cap, rec);
    u8cs s = {buf, buf + n};
    JSValue v = JABCStrOfSlice(ctx, s);
    if (buf != pad) free(buf);
    return v;
}

//  Start offset of the row ending just before `off` (off is a row boundary).
static size_t JABCulogPrevRow(u8 *base, size_t off) {
    if (off == 0) return (size_t)-1;
    size_t j = off - 1;  //  the '\n' that ends the previous row
    while (j > 0 && base[j - 1] != '\n') j--;
    return j;            //  start of that row (after the prior '\n', or 0)
}

//  JS-103: write-side URI gate — check URILexer's ok64 and canonicalise via
//  the DOGCanonURI chokepoint so JS rows match C rows.
static b8 JABCulogUriGate(ulogrecp rec, u8s us) {
    rec->uri.data[0] = us[0];
    rec->uri.data[1] = us[1];
    if (URILexer(&rec->uri) != OK) return NO;
    return DOGCanonURI(&rec->uri) == OK;
}

//  _ulog_feed(buf, off, verb, uri, ts) -> new write head
static JABC_FN(JABCulogFeed) {
    if (argc < 4) JABC_THROW("ulog._feed(buf, off, verb, uri, ts)");
    u8 *c[4] = {};
    if (!JABCIdleOf(c, ctx, argv[0])) JABC_FAIL;
    if (!JABCBufFed(c, ctx, argv[1])) JABC_FAIL;  //  DATA = [0,off)
    u8 vb[16], ub[FILE_PATH_MAX_LEN];
    u8s vs = {}, us = {};
    if (!JABChunkArgU8(vs, ctx, argv[2], vb, sizeof(vb))) JABC_FAIL;
    if (!JABChunkArgU8(us, ctx, argv[3], ub, sizeof(ub))) JABC_FAIL;
    ron60 verb = 0;
    u8cs vsc = {vs[0], vs[1]};
    RONutf8sDrain(&verb, vsc);
    u64 ts = (u64)RONNow();
    if (argc > 4 && !JS_IsUndefined(argv[4]) &&
        !JABCBigU64Of(&ts, ctx, argv[4]))
        JABC_FAIL;
    ulogrec rec = {};
    rec.ts = (ron60)ts;
    rec.verb = verb;
    if (!JABCulogUriGate(&rec, us)) JABC_THROW("ulog._feed: malformed uri");
    if (ULOGu8sFeed(u8bIdle(c), &rec) != OK) JABC_THROW("ulog: feed (full?)");
    return JS_NewFloat64(ctx, (double)u8bDataLen(c));
}

//  _ulog_now() -> BigInt ron60 (a fresh monotonic stamp)
static JABC_FN(JABCulogNow) { return JABCBigU64(ctx, (u64)RONNow()); }

//  _ulog_next(buf, off, dataLen) -> end of the row at off | -1
static JABC_FN(JABCulogNext) {
    if (argc < 3) JABC_THROW("ulog._next(buf, off, dataLen)");
    u8 *c[4] = {};
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;
    size_t off = 0, dl = 0;
    if (!JABCOffOf(&off, u8bDataC(c), ctx, argv[1])) JABC_FAIL;
    if (!JABCOffOf(&dl, u8bDataC(c), ctx, argv[2])) JABC_FAIL;
    if (off >= dl) return JS_NewFloat64(ctx, -1);
    u8cs scan = {};  //  [off, dl) — abc bounds-checks
    if (dl > 0xffffffffUL ||
        u8csSub(u8bDataC(c), scan, (u32)off, (u32)dl) != OK)
        JABC_THROW("ulog: the row range is out of range");
    ulogrec rec = {};
    if (ULOGu8sDrain(scan, &rec) != OK) return JS_NewFloat64(ctx, -1);
    return JS_NewFloat64(ctx, (double)(size_t)(scan[0] - u8bDataC(c)[0]));
}

//  PTR-010: the JABCpackAt twin — gate the offset, move DATA with u8bUsed.
static b8 JABCulogAt(ulogrec *rec, u8 *c[4], JSContext *ctx, JSValueConst bufv,
                     JSValueConst offv) {
    if (!JABCDataOf(c, ctx, bufv)) return NO;
    if (!JABCBufAt(c, ctx, offv)) return NO;
    a_dup(u8 const, scan, u8bDataC(c));  //  drain a copy: keep DATA put
    return ULOGu8sDrain(scan, rec) == OK;
}

static JABC_FN(JABCulogTime) {
    u8 *c[4] = {};
    ulogrec rec = {};
    if (argc < 2 || !JABCulogAt(&rec, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JABCBigU64(ctx, (u64)rec.ts);
}
static JABC_FN(JABCulogVerb) {
    u8 *c[4] = {};
    ulogrec rec = {};
    if (argc < 2 || !JABCulogAt(&rec, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    u8 vb[16];
    u8s into = {vb, vb + sizeof(vb)};
    RONutf8sFeed(into, rec.verb);
    //  JS-108: shared conversion (a verb is RON60, <= 16 bytes by construction)
    u8cs vs = {vb, into[0]};
    return JABCStrOfSlice(ctx, vs);
}
static JABC_FN(JABCulogUri) {
    u8 *c[4] = {};
    ulogrec rec = {};
    if (argc < 2 || !JABCulogAt(&rec, c, ctx, argv[0], argv[1])) JABC_UNDEF;
    return JABCulogUriStr(ctx, &rec);
}

//  Shared scan for the seek* leaves.  kind: 0=verb(==v), 1=time(>=t fwd /
//  <=t rev), 2=uri(prefix pfx[0..plen)).  Returns the match offset, or
//  SIZE_MAX.  Pure — touches no watermark.  Forward scans to dl; reverse
//  walks row boundaries down from `off`.
static size_t JABCulogScan(u8 *base, size_t off, size_t dl, b8 rev, int kind,
                           ron60 v, u64 t, u8c *pfx, size_t plen) {
    size_t cur = off;
    if (!rev) {
        while (cur < dl) {
            u8cs scan = {base + cur, base + dl};
            ulogrec r = {};
            ok64 o = ULOGu8sDrain(scan, &r);
            size_t end = (size_t)((u8c *)scan[0] - base);
            b8 hit = NO;
            if (o == OK) {
                if (kind == 0) hit = (r.verb == v);
                else if (kind == 1) hit = ((u64)r.ts >= t);
                else {
                    u8 ub[2048];
                    size_t ulen = JABCulogUriText(ub, sizeof(ub), &r);
                    hit = (ulen >= plen && memcmp(ub, pfx, plen) == 0);
                }
            }
            if (hit) return cur;
            if (end <= cur) break;
            cur = end;
        }
    } else {
        while (cur > 0) {
            size_t rs = JABCulogPrevRow(base, cur);
            if (rs == (size_t)-1 || rs >= cur) break;
            u8cs scan = {base + rs, base + dl};
            ulogrec r = {};
            b8 hit = NO;
            if (ULOGu8sDrain(scan, &r) == OK) {
                if (kind == 0) hit = (r.verb == v);
                else if (kind == 1) hit = ((u64)r.ts <= t);
                else {
                    u8 ub[2048];
                    size_t ulen = JABCulogUriText(ub, sizeof(ub), &r);
                    hit = (ulen >= plen && memcmp(ub, pfx, plen) == 0);
                }
            }
            if (hit) return rs;
            cur = rs;
        }
    }
    return (size_t)-1;
}

//  Common prologue for the seek leaves: (buf, off, dataLen, arg, rev).
#define ULOG_SEEK_HEAD()                                                  \
    if (argc < 4) JABC_THROW("ulog._seek(buf, off, dataLen, arg, rev)");  \
    u8 *c[4] = {};                                                        \
    if (!JABCDataOf(c, ctx, argv[0])) JABC_FAIL;                          \
    size_t off = 0, dl = 0;                                               \
    if (!JABCOffOf(&off, u8bDataC(c), ctx, argv[1])) JABC_FAIL;           \
    if (!JABCOffOf(&dl, u8bDataC(c), ctx, argv[2])) JABC_FAIL;            \
    b8 rev = argc > 4 && JS_ToBool(ctx, argv[4]) > 0
#define ULOG_SEEK_RET(M)                                            \
    do {                                                            \
        size_t m_ = (M);                                            \
        return JS_NewFloat64(ctx, m_ == (size_t)-1 ? -1 : (double)m_); \
    } while (0)

static JABC_FN(JABCulogSeekVerb) {
    ULOG_SEEK_HEAD();
    u8 vb[16];
    u8s vs = {};
    if (!JABChunkArgU8(vs, ctx, argv[3], vb, sizeof(vb))) JABC_FAIL;
    ron60 target = 0;
    u8cs vsc = {vs[0], vs[1]};
    RONutf8sDrain(&target, vsc);
    ULOG_SEEK_RET(
        JABCulogScan(u8bData(c)[0], off, dl, rev, 0, target, 0, NULL, 0));
}
static JABC_FN(JABCulogSeekTime) {
    ULOG_SEEK_HEAD();
    u64 target = 0;
    if (!JABCBigU64Of(&target, ctx, argv[3])) JABC_FAIL;
    ULOG_SEEK_RET(
        JABCulogScan(u8bData(c)[0], off, dl, rev, 1, 0, target, NULL, 0));
}
static JABC_FN(JABCulogSeekURI) {
    ULOG_SEEK_HEAD();
    u8 pb[2048];
    u8s ps = {};
    if (!JABChunkArgU8(ps, ctx, argv[3], pb, sizeof(pb))) JABC_FAIL;
    ULOG_SEEK_RET(JABCulogScan(u8bData(c)[0], off, dl, rev, 2, 0, 0, ps[0],
                               (size_t)$len(ps)));
}

//  --- booked-log + sidecar-index bindings (approach-(a) prep) ----------
//  ULOGOpen/AppendAt/Close operate on the native file-backed ULOG (a booked
//  mmap `data` + a `wh128` sidecar `idx`), unlike the stateless _ulog_feed
//  above which works over a JS-owned Uint8Array.  The (data, idx) pair must
//  survive across JS calls, so box it on the heap and hand its pointer back
//  as a JS Number handle (JAB-034: still finalizer-less, ported as is).
//  Close frees the box.
typedef struct {
    u8bp data;
    wh128bp idx;
} jabc_ulog;

//  Read a NUL-terminated path8s from a JS string/bytes arg into `pad`.
static b8 JABCulogPath(u8s pad, u8 *tmp, size_t cap, JSContext *ctx,
                       JSValueConst v) {
    u8s p = {};
    if (!JABChunkArgU8(p, ctx, v, tmp, cap)) return NO;
    size_t n = (size_t)(p[1] - p[0]);
    if (n + 1 >= cap) return NO;
    if (n) memcpy(pad[0], p[0], n);
    pad[0][n] = 0;  //  ULOG paths are NUL-terminated
    pad[1] = pad[0] + n + 1;
    return YES;
}

//  _ulog_open(path) -> Number handle (throws on open failure).
static JABC_FN(JABCulogOpen) {
    if (argc < 1) JABC_THROW("ulog._open(path)");
    u8 pb[FILE_PATH_MAX_LEN];
    u8s pad = {pb, pb + sizeof(pb)};
    if (!JABCulogPath(pad, pb, sizeof(pb), ctx, argv[0])) JABC_FAIL;
    path8s path = {pad[0], pad[1]};
    jabc_ulog *h = (jabc_ulog *)calloc(1, sizeof(jabc_ulog));
    if (!h) JABC_THROW("ulog._open: oom");
    ok64 o = ULOGOpen(&h->data, &h->idx, path);
    if (o != OK) {
        free(h);
        JABC_THROW("ulog._open failed");
    }
    return JS_NewFloat64(ctx, (double)(size_t)h);
}

static jabc_ulog *JABCulogHandle(JSContext *ctx, JSValueConst v) {
    double d = 0;
    if (JS_ToFloat64(ctx, &d, v) < 0 || d <= 0) return NULL;
    return (jabc_ulog *)(size_t)d;
}

//  _ulog_append(handle, ts, verb, uri) -> ts written (throws ULOGCLOCK).
//  Arg order = the on-disk row `<ts>\t<verb>\t<uri>`; ts written as-is.
static JABC_FN(JABCulogAppend) {
    if (argc < 4) JABC_THROW("ulog._append(handle, ts, verb, uri)");
    jabc_ulog *h = JABCulogHandle(ctx, argv[0]);
    if (!h) JABC_THROW("ulog._append: bad handle");
    u64 ts = 0;
    if (!JABCBigU64Of(&ts, ctx, argv[1])) JABC_FAIL;
    u8 vb[16], ub[FILE_PATH_MAX_LEN];
    u8s vs = {}, us = {};
    if (!JABChunkArgU8(vs, ctx, argv[2], vb, sizeof(vb))) JABC_FAIL;
    if (!JABChunkArgU8(us, ctx, argv[3], ub, sizeof(ub))) JABC_FAIL;
    ron60 verb = 0;
    u8cs vsc = {vs[0], vs[1]};
    RONutf8sDrain(&verb, vsc);
    ulogrec rec = {};
    rec.ts = (ron60)ts;
    rec.verb = verb;
    if (!JABCulogUriGate(&rec, us)) JABC_THROW("ulog._append: malformed uri");
    if (ULOGAppendAt(h->data, h->idx, &rec) != OK)
        JABC_THROW("ulog._append (clock/full?)");
    return JABCBigU64(ctx, (u64)rec.ts);
}

//  _ulog_count(handle) -> Number of rows.
static JABC_FN(JABCulogCount) {
    if (argc < 1) JABC_THROW("ulog._count(handle)");
    jabc_ulog *h = JABCulogHandle(ctx, argv[0]);
    if (!h) JABC_THROW("ulog._count: bad handle");
    return JS_NewFloat64(ctx, (double)ULOGCount(h->idx));
}

//  _ulog_rowUri(handle, i) -> String (round-trip verification helper).
static JABC_FN(JABCulogRowUri) {
    if (argc < 2) JABC_THROW("ulog._rowUri(handle, i)");
    jabc_ulog *h = JABCulogHandle(ctx, argv[0]);
    if (!h) JABC_THROW("ulog._rowUri: bad handle");
    double d = 0;
    if (JS_ToFloat64(ctx, &d, argv[1]) < 0) JABC_FAIL;
    ulogrec rec = {};
    if (ULOGRow(h->data, h->idx, (u32)d, &rec) != OK) JABC_UNDEF;
    return JABCulogUriStr(ctx, &rec);
}

//  _ulog_rowTime(handle, i) -> BigInt ts (round-trip verification helper).
static JABC_FN(JABCulogRowTime) {
    if (argc < 2) JABC_THROW("ulog._rowTime(handle, i)");
    jabc_ulog *h = JABCulogHandle(ctx, argv[0]);
    if (!h) JABC_THROW("ulog._rowTime: bad handle");
    double d = 0;
    if (JS_ToFloat64(ctx, &d, argv[1]) < 0) JABC_FAIL;
    ulogrec rec = {};
    if (ULOGRow(h->data, h->idx, (u32)d, &rec) != OK) JABC_UNDEF;
    return JABCBigU64(ctx, (u64)rec.ts);
}

//  _ulog_close(handle) -> undefined.  Trims to PAST+DATA, flushes the
//  sidecar sentinel, unmaps, frees the box.
static JABC_FN(JABCulogClose) {
    if (argc < 1) JABC_THROW("ulog._close(handle)");
    jabc_ulog *h = JABCulogHandle(ctx, argv[0]);
    if (!h) JABC_THROW("ulog._close: bad handle");
    ULOGClose(h->data, &h->idx, YES);
    free(h);
    JABC_UNDEF;
}

ok64 JABCInstallUlog(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    JABC_API_FN(abc, "_ulog_feed", JABCulogFeed);
    JABC_API_FN(abc, "_ulog_open", JABCulogOpen);
    JABC_API_FN(abc, "_ulog_append", JABCulogAppend);
    JABC_API_FN(abc, "_ulog_count", JABCulogCount);
    JABC_API_FN(abc, "_ulog_rowUri", JABCulogRowUri);
    JABC_API_FN(abc, "_ulog_rowTime", JABCulogRowTime);
    JABC_API_FN(abc, "_ulog_close", JABCulogClose);
    JABC_API_FN(abc, "_ulog_now", JABCulogNow);
    JABC_API_FN(abc, "_ulog_next", JABCulogNext);
    JABC_API_FN(abc, "_ulog_time", JABCulogTime);
    JABC_API_FN(abc, "_ulog_verb", JABCulogVerb);
    JABC_API_FN(abc, "_ulog_uri", JABCulogUri);
    JABC_API_FN(abc, "_ulog_seekVerb", JABCulogSeekVerb);
    JABC_API_FN(abc, "_ulog_seekTime", JABCulogSeekTime);
    JABC_API_FN(abc, "_ulog_seekURI", JABCulogSeekURI);
    JABC_API_END(abc);
    return OK;
}
