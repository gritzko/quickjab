//  JAB-036: jab/codec.cpp — hex + sha1/sha256 + the ron60 codec.  Pure byte
//  transforms over abc/HEX, abc/SHA, dog/git/SHA1 and abc/RON; no state.
#include <time.h>

#include "JABC.h"
#include "abc/HEX.h"
#include "abc/RON.h"
#include "abc/SHA.h"
#include "dog/DOG.h"  //  DOGutf8sFeedDate (relative-date formatter, JS-021)
#include "dog/git/SHA1.h"

//  hex.encode(Uint8Array) -> lowercase hex string
static JABC_FN(JABChexEncode) {
    if (argc < 1) JABC_THROW("hex.encode(Uint8Array)");
    u8 *binb[4] = {};
    if (!JABCDataOf(binb, ctx, argv[0])) JABC_FAIL;
    size_t n = u8bDataLen(binb);
    char *h = (char *)malloc(n * 2 + 1);
    if (h == NULL) JABC_THROW("hex.encode: oom");
    u8s hx = {(u8 *)h, (u8 *)h + n * 2};
    HEXu8sFeedSome(hx, u8bDataC(binb));
    u8cs out = {(u8 const *)h, (u8 const *)h + n * 2};
    JSValue v = JABCStrOfSlice(ctx, out);
    free(h);
    return v;
}

//  hex.encodeInto(src, dst) -> hex chars written (provided-buffer form)
static JABC_FN(JABChexEncodeInto) {
    if (argc < 2) JABC_THROW("hex.encodeInto(src, dst)");
    u8 *binb[4] = {};
    u8 *dstb[4] = {};
    if (!JABCDataOf(binb, ctx, argv[0])) JABC_FAIL;
    if (!JABCIdleOf(dstb, ctx, argv[1])) JABC_FAIL;
    HEXu8sFeedSome(u8bIdle(dstb), u8bDataC(binb));
    return JS_NewFloat64(ctx, (double)u8bDataLen(dstb));
}

//  hex.decode(string) -> Uint8Array
static JABC_FN(JABChexDecode) {
    if (argc < 1 || !JS_IsString(argv[0])) JABC_THROW("hex.decode(string)");
    size_t hlen = 0;
    const char *hb = JS_ToCStringLen(ctx, &hlen, argv[0]);
    if (hb == NULL) JABC_FAIL;
    u8cs hex = {(u8 const *)hb, (u8 const *)hb + hlen};
    if ((hlen & 1) || !HEXu8sValid(hex)) {
        JS_FreeCString(ctx, hb);
        JABC_THROW("hex.decode: bad hex");
    }
    size_t n = hlen / 2;
    u8 *p = (u8 *)malloc(n ? n : 1);
    if (p == NULL) {
        JS_FreeCString(ctx, hb);
        JABC_THROW("hex.decode: oom");
    }
    u8s bin = {p, p + n};
    if (n) HEXu8sDrainSome(bin, hex);
    JS_FreeCString(ctx, hb);
    JSValue ta = JABCBlob(ctx, p, n);
    free(p);
    return ta;
}

//  sha1(Uint8Array) -> Uint8Array(20)
static JABC_FN(JABCsha1) {
    if (argc < 1) JABC_THROW("sha1(Uint8Array)");
    u8 *binb[4] = {};
    if (!JABCDataOf(binb, ctx, argv[0])) JABC_FAIL;
    sha1 h = {};
    SHA1Sum(&h, u8bDataC(binb));
    return JABCBlob(ctx, h.data, sizeof(h.data));
}

//  sha256(Uint8Array) -> Uint8Array(32)
static JABC_FN(JABCsha256) {
    if (argc < 1) JABC_THROW("sha256(Uint8Array)");
    u8 *binb[4] = {};
    if (!JABCDataOf(binb, ctx, argv[0])) JABC_FAIL;
    sha256 h = {};
    SHASum(&h, u8bDataC(binb));
    return JABCBlob(ctx, h.data, sizeof(h.data));
}

//  ron.encode(BigInt) -> RON base64 string  (timestamps, verbs, ok64 codes)
static JABC_FN(JABCronEncode) {
    if (argc < 1) JABC_THROW("ron.encode(BigInt)");
    u64 v = 0;
    if (!JABCBigU64Of(&v, ctx, argv[0])) JABC_FAIL;
    u8 b[16];
    u8s into = {b, b + sizeof(b)};
    RONutf8sFeed(into, (ok64)v);
    //  JS-108: shared conversion (RON60 text is <= 10 bytes by construction).
    u8cs s = {b, into[0]};
    return JABCStrOfSlice(ctx, s);
}

//  ron.decode(string) -> BigInt
static JABC_FN(JABCronDecode) {
    if (argc < 1 || !JS_IsString(argv[0])) JABC_THROW("ron.decode(string)");
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, argv[0]);
    if (s == NULL) JABC_FAIL;
    u8 b[32];
    size_t n = len < sizeof(b) - 1 ? len : sizeof(b) - 1;
    memcpy(b, s, n);
    JS_FreeCString(ctx, s);
    u8cs from = {b, b + n};
    ok64 v = 0;
    RONutf8sDrain(&v, from);
    return JABCBigU64(ctx, (u64)v);
}

//  ron time interpretation (JS-021): ron60 IS the ULOG `ts` encoding.  Three
//  thin leaves; the Date-coerce + BigInt sugar lives in JS (JABC_RON_JS).

//  ron._now() -> current ron60 (BigInt), localtime-aligned ms (RONNow).
static JABC_FN(JABCronNow) {
    (void)argc;
    (void)argv;
    return JABCBigU64(ctx, (u64)RONNow());
}

//  ron._ofMs(ms) -> ron60 (BigInt) for a ms-epoch int.  localtime split +
//  RONOfTime, matching RONNow's wall-clock alignment.
static JABC_FN(JABCronOfMs) {
    if (argc < 1) JABC_THROW("ron._ofMs(ms)");
    double msd = 0;
    if (JS_ToFloat64(ctx, &msd, argv[0]) < 0) JABC_FAIL;
    i64 msi = (i64)msd;
    time_t sec = (time_t)(msi / 1000);
    u32 ms = (u32)(((msi % 1000) + 1000) % 1000);  //  floor-mod for pre-epoch
    struct tm tm = {};
    localtime_r(&sec, &tm);
    ron60 r = 0;
    if (RONOfTime(&r, &tm, ms) != OK) JABC_THROW("ron._ofMs: out of range");
    return JABCBigU64(ctx, (u64)r);
}

//  ron._date(ron60) -> relative-date string.  RONToTime -> mktime -> unix
//  secs, now=time(NULL), DOGutf8sFeedDate (the be-log "12:34"/"Tue05" format).
static JABC_FN(JABCronDate) {
    if (argc < 1) JABC_THROW("ron._date(BigInt)");
    u64 v = 0;
    if (!JABCBigU64Of(&v, ctx, argv[0])) JABC_FAIL;
    i64 secs = 0;
    if (v != 0) {
        struct tm tm = {};
        if (RONToTime((ron60)v, &tm, NULL) != OK)
            JABC_THROW("ron._date: bad ron60");
        tm.tm_isdst = -1;  //  let mktime resolve DST (cf. SNIFF)
        time_t s = mktime(&tm);
        secs = (s == (time_t)-1) ? 0 : (i64)s;
    }
    u8 b[16];
    u8s into = {b, b + sizeof(b)};
    if (DOGutf8sFeedDate(into, secs, (i64)time(NULL)) != OK)
        JABC_THROW("ron._date: format failed");
    //  JS-108: shared conversion (a DOG date is <= 16 bytes by construction).
    u8cs s = {b, into[0]};
    return JABCStrOfSlice(ctx, s);
}

//  JS sugar: now() binds the leaf; of() coerces Date->getTime(); date()
//  coerces to BigInt.  No held JS refs (JABC rule #4).
static const char *JABC_RON_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const ron = g.ron;\n"
    "  ron.now = () => ron._now();\n"
    "  ron.of = x => ron._ofMs(x instanceof Date ? x.getTime() : Number(x));\n"
    "  ron.date = r => ron._date(BigInt(r));\n"
    "})(this);\n";

ok64 JABCInstallCodec(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(ron);
    JABC_API_FN(ron, "encode", JABCronEncode);
    JABC_API_FN(ron, "decode", JABCronDecode);
    JABC_API_FN(ron, "_now", JABCronNow);  //  ron.now/of/date sugar: JABC_RON_JS
    JABC_API_FN(ron, "_ofMs", JABCronOfMs);
    JABC_API_FN(ron, "_date", JABCronDate);
    JABC_API_END(ron);
    JABC_API_OBJECT(hex);
    JABC_API_FN(hex, "encode", JABChexEncode);
    JABC_API_FN(hex, "encodeInto", JABChexEncodeInto);
    JABC_API_FN(hex, "decode", JABChexDecode);
    JABC_API_END(hex);
    JABC_API_FN(global, "sha1", JABCsha1);
    JABC_API_FN(global, "sha256", JABCsha256);
    JABCExecute(JABC_RON_JS);
    return OK;
}
