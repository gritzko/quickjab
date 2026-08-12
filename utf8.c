#include "JABC.h"
#include "abc/UTF8.h"

//  utf8.encodeInto(str, dst) -> n
//
//  Encode `str` as UTF-8 directly into the caller-owned typed array `dst`,
//  return the byte count written.  No allocation the binding keeps: the buffer
//  is JS-owned, the binding only fills it.  JAB-036: quickjs hands out UTF-8
//  already (lone surrogates -> U+FFFD, jab's policy), so the JSChar walk
//  collapses to a copy cut at a code-point boundary — never a half-written
//  multibyte char, and the return is what fit.
static JABC_FN(JABCutf8EncodeInto) {
    if (argc < 2 || !JS_IsString(argv[0]))
        JABC_THROW("utf8.encodeInto(string, Uint8Array) -> n");
    u8 *dstb[4] = {};
    if (!JABCIdleOf(dstb, ctx, argv[1])) JABC_FAIL;
    size_t cap = u8bIdleLen(dstb);

    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, argv[0]);
    if (s == NULL) JABC_FAIL;
    size_t n = len < cap ? len : cap;
    //  Back off a straddling code point: a continuation byte at `n` means the
    //  char that starts before it does not fit whole.
    while (n > 0 && n < len && ((u8)s[n] & 0xC0) == 0x80) n--;

    u8cs src = {(u8 const *)s, (u8 const *)s + n};
    ok64 o = u8bFeed(dstb, src);
    JS_FreeCString(ctx, s);
    if (o != OK) JABC_THROW("utf8.encodeInto(): the target buffer is too small");
    return JS_NewFloat64(ctx, (double)n);
}

//  utf8.Decode(Uint8Array) -> string
//
//  Validate inbound UTF-8 (rejecting overlong forms, lone surrogates,
//  truncated multibyte, bad continuation bytes and > U+10FFFF via abc's
//  utf8sValid) BEFORE building any JS string, then hand the slice to
//  JABCStrOfSlice (length-explicit, so embedded NULs survive).
static JABC_FN(JABCutf8Decode) {
    if (argc < 1) JABC_THROW("utf8.Decode(Uint8Array) -> string");
    u8 *srcb[4] = {};
    if (!JABCDataOf(srcb, ctx, argv[0])) JABC_FAIL;

    utf8cs scan = {(utf8c *)u8bDataC(srcb)[0], (utf8c *)u8bDataC(srcb)[1]};
    if (utf8sValid(scan) != OK) JABC_THROW("utf8.Decode(): malformed UTF-8");

    return JABCStrOfSlice(ctx, u8bDataC(srcb));
}

ok64 JABCInstallUtf8(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(utf8);
    JABC_API_FN(utf8, "encodeInto", JABCutf8EncodeInto);
    JABC_API_FN(utf8, "Decode", JABCutf8Decode);
    JABC_API_END(utf8);
    return OK;
}
