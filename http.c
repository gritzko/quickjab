//  QJAB-004: http.c — abc/HTTP's ragel lexer as two leaves, in net.c's shape.
//  C lexes ONE message head off a byte view (or spells one back); JS owns the
//  buffering, keep-alive, bodies and routing — nothing here holds state.  A
//  head that is not all here yet surfaces as `null` (net.c's EAGAIN-as-`-1`
//  stance), a head the grammar refuses throws in plain words.
#include "JABC.h"
#include "abc/HTTP.h"
#include "abc/PRO.h"

//  A head is bounded: 64 KiB spelled, at most 1024 name/value pairs lexed.
con size_t JHTTP_BYTES = 64UL << 10;
con size_t JHTTP_TOKS = 2048;

//  QJAB-004: one head — the lexer's own slices, its name/value token pairs and
//  the head's byte length (the offset where the body starts).
typedef struct {
    HTTPstate http;
    u8css pairs;
    size_t head;
} jhttp;

//  --- drain (parse) --------------------------------------------------------

//  QJAB-004: lex one head off `in`.  HTTPNONE = the head is truncated (the
//  lexer ran out of input), HTTPBAD = it stopped ON a byte the grammar refuses.
static ok64 jhttp_drain(jhttp *j, u8csc in) {
    sane(j != NULL && in != NULL);
    size_t toks = (size_t)u8csLen(in) / 2 + 4;  //  a header costs 4 bytes min
    a_carve(u8cs, hdrs, toks < JHTTP_TOKS ? toks : JHTTP_TOKS);
    a_dup(u8c, from, in);
    j->http.headers = u8csbIdle(hdrs);
    try(HTTPutf8Drain, from, &j->http);
    nedo {
        a_dup(u8c, tail, j->http.data);  //  what the lexer did NOT reach
        on(HTTPBAD) if ($empty(tail)) fail(HTTPNONE);
        done;
    }
    a_dup(u8cs, pairs, u8csbData(hdrs));
    u8cssDup(j->pairs, pairs);
    //  QJAB-004: the grammar closes a head with CRLF CRLF right behind the
    //  last token it lexed — the request/status line's tail, or a field value.
    u8cs last = {in[0], j->http.version[1]};
    if (j->http.reason[0] != NULL) last[1] = j->http.reason[1];
    if (u8cssLen(pairs) != 0) last[1] = (*$last(pairs))[1];
    j->head = (size_t)u8csLen(last) + 4;
    done;
}

//  An absent component (the lexer never marked it) is `undefined`, as uri.c's
//  absent URI slots are; a present one crosses as a length-exact string.
static JSValue jhttp_str(JSContext *ctx, u8cs s) {
    return s[0] == NULL ? JS_UNDEFINED : JABCStrOfSlice(ctx, s);
}

//  The status line's 3 digits as a Number, via abc's decimal drain.
static JSValue jhttp_code(JSContext *ctx, u8cs s) {
    if (s[0] == NULL) return JS_UNDEFINED;
    a_dup(u8c, code, s);
    u64 n = 0;
    if (u64decdrain(&n, code) != OK) return JS_UNDEFINED;
    return JS_NewFloat64(ctx, (double)n);
}

//  http._drain(Uint8Array) -> null | {method, uri, version, status, reason,
//  headers: [[name, value], …], length}.  null = read more bytes and retry;
//  `length` is the head's byte count, so the body starts there.
static JABC_FN(JABChttpDrain) {
    (void)this_val;
    if (argc < 1) JABC_THROW("http._drain(Uint8Array)");
    u8 *tab[4] = {};
    if (!JABCDataOf(tab, ctx, argv[0])) JABC_FAIL;
    a_dup(u8c, in, u8bDataC(tab));
    jhttp j = {};
    ok64 r = jhttp_drain(&j, in);
    if (r == HTTPNONE) return JS_NULL;  //  the head is not all here yet
    if (r == HTTPBAD) JABC_THROW("http: malformed message head");
    if (r != OK) JABC_THROW("http: the message head has too many headers");
    JSValue o = JS_NewObject(ctx);
    JABCSetProp(ctx, o, "method", jhttp_str(ctx, j.http.method));
    JABCSetProp(ctx, o, "uri", jhttp_str(ctx, j.http.uri));
    JABCSetProp(ctx, o, "version", jhttp_str(ctx, j.http.version));
    JABCSetProp(ctx, o, "status", jhttp_code(ctx, j.http.status_code));
    JABCSetProp(ctx, o, "reason", jhttp_str(ctx, j.http.reason));
    JSValue hs = JS_NewArray(ctx);
    u32 n = 0;
    for (i64 i = 0; i + 1 < (i64)u8cssLen(j.pairs); i += 2)
        JS_SetPropertyUint32(
            ctx, hs, n++,
            JABCPair(ctx, JABCStrOfSlice(ctx, $at(j.pairs, i)),
                     JABCStrOfSlice(ctx, $at(j.pairs, i + 1))));
    JABCSetProp(ctx, o, "headers", hs);
    JABCSetProp(ctx, o, "length", JS_NewFloat64(ctx, (double)j.head));
    return o;
}

//  --- feed (compose) -------------------------------------------------------

//  QJAB-004: `v`'s bytes appended to the `txt` scratch; `out` spans them.  A
//  missing slot stays a NULL slice, which HTTPutf8Feed skips.
static ok64 jhttp_bytes(u8cs out, u8s txt, JSContext *ctx, JSValue v) {
    sane(out != NULL);
    zero$(out);
    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        JS_FreeValue(ctx, v);
        done;
    }
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, v);
    JS_FreeValue(ctx, v);
    if (s == NULL) fail(HTTPBAD);
    u8cs from = {(u8c *)s, (u8c *)s + len};
    out[0] = txt[0];
    try(u8sFeed, txt, from);
    JS_FreeCString(ctx, s);
    out[1] = txt[0];
    done;
}

//  One component of the head object (`head.method`, `head.status`, …).
static ok64 jhttp_slot(u8cs out, u8s txt, JSContext *ctx, JSValueConst head,
                       const char *name) {
    sane(out != NULL);
    call(jhttp_bytes, out, txt, ctx, JABCGetProp(ctx, head, name));
    done;
}

//  head.headers = [[name, value], …] -> the lexer's flat token pair list.
static ok64 jhttp_slots(u8css into, u8s txt, JSContext *ctx,
                        JSValueConst head) {
    sane(into != NULL);
    JSValue hs = JABCGetProp(ctx, head, "headers");
    if (!JS_IsObject(hs)) {  //  no headers at all is a head all the same
        JS_FreeValue(ctx, hs);
        done;
    }
    u32 n = 0;
    JSValue lv = JABCGetProp(ctx, hs, "length");
    if (JS_ToUint32(ctx, &n, lv) < 0) n = 0;
    JS_FreeValue(ctx, lv);
    for (u32 i = 0; i < n; ++i) {
        JSValue pair = JS_GetPropertyUint32(ctx, hs, i);
        u8cs name = {}, val = {};
        try(jhttp_bytes, name, txt, ctx, JS_GetPropertyUint32(ctx, pair, 0));
        then try(jhttp_bytes, val, txt, ctx,
                 JS_GetPropertyUint32(ctx, pair, 1));
        JS_FreeValue(ctx, pair);
        then try(u8cssFeed1, into, name);
        then try(u8cssFeed1, into, val);
        nedo break;
    }
    JS_FreeValue(ctx, hs);
    done;
}

//  QJAB-004: spell one head; `out` ends up over BASS scratch, which lives
//  until the leaf returns (the trampoline rewinds, no call() in between).
static ok64 jhttp_feed(u8cs out, JSContext *ctx, JSValueConst head) {
    sane(out != NULL && ctx != NULL);
    a_carve(u8, txt, JHTTP_BYTES);
    a_carve(u8cs, pairs, JHTTP_TOKS);
    a_carve(u8, spelled, JHTTP_BYTES);
    HTTPstate http = {};
    call(jhttp_slot, http.method, u8bIdle(txt), ctx, head, "method");
    call(jhttp_slot, http.uri, u8bIdle(txt), ctx, head, "uri");
    call(jhttp_slot, http.version, u8bIdle(txt), ctx, head, "version");
    call(jhttp_slot, http.status_code, u8bIdle(txt), ctx, head, "status");
    call(jhttp_slot, http.reason, u8bIdle(txt), ctx, head, "reason");
    call(jhttp_slots, u8csbIdle(pairs), u8bIdle(txt), ctx, head);
    http.headers = u8csbData(pairs);
    call(HTTPutf8Feed, u8bIdle(spelled), &http);
    a_dup(u8c, res, u8bDataC(spelled));
    u8csMv(out, res);
    done;
}

//  http._feed({method, uri, version | version, status, reason} + headers)
//  -> Uint8Array with the spelled head, CRLF CRLF included.
static JABC_FN(JABChttpFeed) {
    (void)this_val;
    if (argc < 1 || !JS_IsObject(argv[0])) JABC_THROW("http._feed(head)");
    u8cs out = {};
    ok64 r = jhttp_feed(out, ctx, argv[0]);
    if (r == SNOROOM) JABC_THROW("http: the message head is over 64K");
    if (r != OK) JABC_THROW("http: the message head cannot be spelled");
    return JABCBlob(ctx, out[0], (size_t)u8csLen(out));
}

ok64 JABCInstallHttp(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(http);
    JABC_API_FN(http, "_drain", JABChttpDrain);
    JABC_API_FN(http, "_feed", JABChttpFeed);
    JABC_API_END(http);
    return OK;
}
