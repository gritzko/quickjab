//  JAB-036: jsrcpack.c — the port of jab/jsrcpack.cpp.
#include "JABC.h"

//  JAB-035: the DEFAULT jsrc pack — a deflated ustar behind a 16-byte preamble,
//  embedded by jsrcpack.S (.incbin) when the build was given -DJAB_JSRC (and
//  -DQUICKJAB_JSRC_PACK=ON).  This accessor is the whole native side: it
//  publishes the bytes as the global `jsrcpack` (a no-copy Uint8Array over the
//  binary's own rodata), and the require bootstrap (require.c) does the rest —
//  cache probe, inflate, untar, and the pin of the extracted dir as THE require
//  base (QJAB-002: bundle-only, no climb at all).  No pack -> no .S, no symbol,
//  no global, no bundle: jab as it was.
#ifdef JABC_JSRC_PACK
extern const unsigned char JABC_JSRC_PACK_HEAD[];
extern const unsigned char JABC_JSRC_PACK_TAIL[];
#endif

//  QJAB-001: does the image carry bundle bytes?  Asked BEFORE the installs
//  (main.c parses argv first), so it reads the .incbin span, not a flag.
b8 JABCJsrcPacked(void) {
#ifdef JABC_JSRC_PACK
    return JABC_JSRC_PACK_TAIL > JABC_JSRC_PACK_HEAD;
#else
    return NO;
#endif
}

ok64 JABCInstallJsrcPack(JSContext *ctx, JSValueConst global) {
    (void)ctx;
    (void)global;
#ifdef JABC_JSRC_PACK
    size_t len = (size_t)(JABC_JSRC_PACK_TAIL - JABC_JSRC_PACK_HEAD);
    if (len == 0) return OK;
    //  No free_func: the bytes are the executable image, not an allocation.
    JSValue ta = JABCBytesNoCopy(ctx, (u8 *)JABC_JSRC_PACK_HEAD, len, NULL,
                                 NULL);
    if (JS_IsException(ta)) {
        JSValue e = JS_GetException(ctx);
        JABCReport(e);
        JS_FreeValue(ctx, e);
        return OK;  //  no global -> no floor; the climb alone still resolves
    }
    //  JAB-036: the attribute INVERSION — JSC's ReadOnly|DontDelete is
    //  quickjs's "neither writable nor configurable", i.e. enumerable only.
    JS_DefinePropertyValueStr(ctx, global, "jsrcpack", ta, JS_PROP_ENUMERABLE);
#endif
    return OK;
}
