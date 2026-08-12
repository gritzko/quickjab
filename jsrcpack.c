//  JAB-036: jsrcpack.c — the port of jab/jsrcpack.cpp.
#include "JABC.h"

//  JAB-035: the DEFAULT jsrc pack — a deflated ustar behind a 16-byte preamble,
//  embedded by jsrcpack.S (.incbin) when the build was given -DJAB_JSRC (and
//  -DQUICKJAB_JSRC_PACK=ON).  This accessor is the whole native side: it
//  publishes the bytes as the global `jsrcpack` (a no-copy Uint8Array over the
//  binary's own rodata), and the require bootstrap (require.c) does the rest —
//  cache probe, inflate, untar, and the append of the extracted dir as the LAST
//  jsrc stack entry (the floor).  No pack -> no .S, no symbol, no global, no
//  floor: jab as it was.
#ifdef JABC_JSRC_PACK
extern const unsigned char JABC_JSRC_PACK_HEAD[];
extern const unsigned char JABC_JSRC_PACK_TAIL[];
#endif

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
