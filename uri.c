//  JAB-036: jab/uri.cpp — abc/URI bindings: parse a URI string into its 8
//  components, compose one from parts, percent-escape/unescape.  A URI is
//  small text, so components cross as JS strings (decoded), not zero-copy
//  views.  The JS `URI` class (embedded below) wraps these leaves.
#include "JABC.h"
#include "abc/URI.h"

//  Set component `name`: undefined when the slot is absent (sigil never
//  appeared), else the decoded string — keeps "/p" (query undefined) distinct
//  from "/p?" (query "").  Presence is the slice pointer being non-NULL, per
//  URIPattern.  URI-009.
static void JABCSetComp(JSContext *ctx, JSValueConst obj, const char *name,
                        u8cs s, b8 present) {
    //  JS-108: the shared length-exact conversion replaced a 2048-byte clamp.
    JABCSetProp(ctx, obj, name,
                present ? JABCStrOfSlice(ctx, s) : JS_UNDEFINED);
}

//  Copy a JS-string arg into `tmp`, fill `out` as a u8cs over it.  URI-009
//  (make side): a non-string arg is an ABSENT component -> NULL slice (no
//  sigil); an empty string is PRESENT-empty -> {tmp,tmp} (a bare `?`/`#`).
static void JABCArgSlice(u8cs out, JSContext *ctx, JSValueConst v, u8 *tmp,
                         size_t cap) {
    out[0] = NULL;
    out[1] = NULL;
    if (!JS_IsString(v)) return;
    out[0] = tmp;
    out[1] = tmp;
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, v);
    if (s == NULL) return;
    if (len > cap - 1) len = cap - 1;
    memcpy(tmp, s, len);
    JS_FreeCString(ctx, s);
    out[1] = tmp + len;
}

//  uri._parse(string) -> {scheme,authority,user,host,port,path,query,fragment}
static JABC_FN(JABCuriParse) {
    if (argc < 1 || !JS_IsString(argv[0])) JABC_THROW("uri.parse(string)");
    u8 buf[4096];
    size_t got = 0;
    const char *s = JS_ToCStringLen(ctx, &got, argv[0]);
    if (s == NULL) JABC_FAIL;
    size_t len = got > sizeof(buf) - 1 ? sizeof(buf) - 1 : got;
    memcpy(buf, s, len);
    JS_FreeCString(ctx, s);
    uri u = {};
    u.data[0] = buf;
    u.data[1] = buf + len;
    if (URILexer(&u) != OK) JABC_THROW("uri.parse: malformed");
    u8 pat = URIPattern(&u);
    JSValue o = JS_NewObject(ctx);
    JABCSetComp(ctx, o, "scheme", u.scheme, (pat & URI_SCHEME) != 0);
    JABCSetComp(ctx, o, "authority", u.authority, (pat & URI_AUTHORITY) != 0);
    JABCSetComp(ctx, o, "user", u.user, (pat & URI_USER) != 0);
    JABCSetComp(ctx, o, "host", u.host, (pat & URI_HOST) != 0);
    JABCSetComp(ctx, o, "port", u.port, (pat & URI_PORT) != 0);
    JABCSetComp(ctx, o, "path", u.path, (pat & URI_PATH) != 0);
    JABCSetComp(ctx, o, "query", u.query, (pat & URI_QUERY) != 0);
    JABCSetComp(ctx, o, "fragment", u.fragment, (pat & URI_FRAGMENT) != 0);
    return o;
}

//  uri._make(scheme, authority, path, query, fragment) -> string
static JABC_FN(JABCuriMake) {
    u8 sb[256], ab[256], pb[1024], qb[512], fb[512], out[4096];
    u8cs scheme, auth, path, query, frag;
    JABCArgSlice(scheme, ctx, argc > 0 ? argv[0] : JS_UNDEFINED, sb,
                 sizeof(sb));
    JABCArgSlice(auth, ctx, argc > 1 ? argv[1] : JS_UNDEFINED, ab,
                 sizeof(ab));
    JABCArgSlice(path, ctx, argc > 2 ? argv[2] : JS_UNDEFINED, pb,
                 sizeof(pb));
    JABCArgSlice(query, ctx, argc > 3 ? argv[3] : JS_UNDEFINED, qb,
                 sizeof(qb));
    JABCArgSlice(frag, ctx, argc > 4 ? argv[4] : JS_UNDEFINED, fb,
                 sizeof(fb));
    u8s into = {out, out + sizeof(out)};
    u8 *base = into[0];
    if (URIMake(into, scheme, auth, path, query, frag) != OK)
        JABC_THROW("uri.make: failed");
    u8cs res = {base, into[0]};
    return JABCStrOfSlice(ctx, res);
}

//  uri._esc(raw) -> percent-encoded ; uri._unesc(esc) -> decoded
static JABC_FN(JABCuriEsc) {
    if (argc < 1) JABC_THROW("uri.escape(string)");
    u8 in[2048], out[4096];
    u8cs raw;
    JABCArgSlice(raw, ctx, argv[0], in, sizeof(in));
    u8s into = {out, out + sizeof(out)};
    u8 *base = into[0];
    if (URIu8sEsc(into, raw) != OK) JABC_THROW("uri.escape: failed");
    u8cs res = {base, into[0]};
    return JABCStrOfSlice(ctx, res);
}

static JABC_FN(JABCuriUnesc) {
    if (argc < 1) JABC_THROW("uri.unescape(string)");
    u8 in[4096], out[4096];
    u8cs esc;
    JABCArgSlice(esc, ctx, argv[0], in, sizeof(in));
    u8s into = {out, out + sizeof(out)};
    u8 *base = into[0];
    if (URIu8sUnesc(into, esc) != OK) JABC_THROW("uri.unescape: failed");
    u8cs res = {base, into[0]};
    return JABCStrOfSlice(ctx, res);
}

//  The JS-facing URI class over the leaves above.
static const char *JABC_URI_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const uri = g.uri;\n"
    "  class URI {\n"
    "    constructor(text) {\n"
    "      this.href = String(text);\n"
    "      const p = uri._parse(this.href);\n"
    "      this.scheme = p.scheme;       this.authority = p.authority;\n"
    "      this.user = p.user;           this.host = p.host;\n"
    "      this.port = p.port;           this.path = p.path;\n"
    "      this.query = p.query;         this.fragment = p.fragment;\n"
    "    }\n"
    "    static make(scheme, authority, path, query, fragment) {\n"
    "      //  URI-009: pass undefined THROUGH (no `|| \"\"`) so an absent part stays\n"
    "      //  absent — _make maps undefined->absent, \"\"->present-empty (`?`/`#`).\n"
    "      return uri._make(scheme, authority, path, query, fragment);\n"
    "    }\n"
    "    static escape(s)   { return uri._esc(String(s)); }\n"
    "    static unescape(s) { return uri._unesc(String(s)); }\n"
    "    toString() { return this.href; }\n"
    "  }\n"
    "  uri.URI = URI;\n"
    "  g.URI = URI;\n"
    "})(this);\n";

ok64 JABCInstallUri(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(uri);
    JABC_API_FN(uri, "_parse", JABCuriParse);
    JABC_API_FN(uri, "_make", JABCuriMake);
    JABC_API_FN(uri, "_esc", JABCuriEsc);
    JABC_API_FN(uri, "_unesc", JABCuriUnesc);
    JABC_API_END(uri);
    JABCExecute(JABC_URI_JS);
    return OK;
}
