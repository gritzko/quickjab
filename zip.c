//  JAB-036: jab/zip.cpp — raw zlib (de)compression of arbitrary bytes (JS-035),
//  two leaves over dog/git/ZINF plus the size-and-grow sugar in JABC_ZIP_JS.
#include "JABC.h"
#include "dog/git/ZINF.h"

//  NOTE on inflate capacity: ZINFInflate does NOT report NOROOM — when the out
//  region fills it WRAPS next_out and keeps going, then the trailing
//  u8sFed(total_out) silently fails so the head never advances (produced 0).
//  A genuine empty result also yields produced 0.  We disambiguate with a head
//  sentinel: on overflow ZINF wrote the wrapped tail over out[off], so the
//  sentinel is gone; on a real empty result nothing was written.

//  zip._deflate(src, out, outOff) -> bytes produced into out at outOff.
static JABC_FN(JABCzipDeflate) {
    if (argc < 3) JABC_THROW("zip._deflate(src, out, outOff)");
    u8 *srcb[4] = {};
    u8 *outb[4] = {};
    if (!JABCDataOf(srcb, ctx, argv[0])) JABC_FAIL;
    if (!JABCIdleOf(outb, ctx, argv[1])) JABC_FAIL;
    if (!JABCBufFed(outb, ctx, argv[2])) JABC_FAIL;  //  DATA = [0,off)
    size_t before = u8bDataLen(outb);
    if (ZINFDeflate(u8bIdle(outb), u8bDataC(srcb)) != OK)
        JABC_THROW("zip.deflate: failed (out too small?)");
    return JS_NewFloat64(ctx, (double)(u8bDataLen(outb) - before));
}

//  zip._inflate(src, out, outOff) -> bytes produced into out at outOff.
//  Throws NOROOM-style on a too-small out so the JS sugar grows and retries.
static JABC_FN(JABCzipInflate) {
    if (argc < 3) JABC_THROW("zip._inflate(src, out, outOff)");
    u8 *srcb[4] = {};
    u8 *outb[4] = {};
    if (!JABCDataOf(srcb, ctx, argv[0])) JABC_FAIL;
    if (!JABCIdleOf(outb, ctx, argv[1])) JABC_FAIL;
    if (!JABCBufFed(outb, ctx, argv[2])) JABC_FAIL;  //  DATA = [0,off)
    size_t before = u8bDataLen(outb);
    size_t room = u8bIdleLen(outb);
    u8 *head = u8bIdle(outb)[0];
    u8 sentinel = 0;
    if (room) {
        sentinel = (u8)(head[0] ^ 0xa5);
        head[0] = sentinel;
    }
    if (ZINFInflate(u8bIdle(outb), u8bDataC(srcb)) != OK)
        JABC_THROW("zip.inflate: bad zlib stream");
    size_t produced = u8bDataLen(outb) - before;
    //  produced 0 + a non-empty out region whose head was overwritten == ZINF
    //  wrapped (out too small): throw so the sugar grows.
    if (produced == 0 && room && head[0] != sentinel)
        JABC_THROW("zip.inflate: NOROOM (out too small)");
    return JS_NewFloat64(ctx, (double)produced);
}

//  JS sugar: zip.deflate/inflate(bytes, out?) — a fresh sized Uint8Array or a
//  zero-copy write into an out Buf, with grow-and-retry on the NOROOM throw.
static const char *JABC_ZIP_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const zip = g.zip;\n"
    "  const isBuf = (o) => o && typeof o === \"object\" &&\n"
    "    typeof o.idle === \"function\" && typeof o.fed === \"function\";\n"
    "  //  QJAB-011: a zip bomb inflates to any size the stream asks for, so the\n"
    "  //  grow-and-retry needs a hard ceiling CHECKED BEFORE it allocates.\n"
    "  const MAX = 1 << 26;   // 64 MiB of inflated output\n"
    "  const cap0 = (n) => { if (n > MAX) throw \"zip.inflate: output would \"\n"
    "    + \"exceed 64 MiB\"; return n; };\n"
    "\n"
    "  zip.deflate = (bytes, out) => {\n"
    "    if (isBuf(out)) {\n"
    "      const n = zip._deflate(bytes, out.idle(), 0);\n"
    "      out.fed(n);\n"
    "      return n;\n"
    "    }\n"
    "    const cap = bytes.length + (bytes.length >> 10) + 128;\n"
    "    const scratch = new Uint8Array(cap);\n"
    "    const n = zip._deflate(bytes, scratch, 0);\n"
    "    return scratch.slice(0, n);\n"
    "  };\n"
    "\n"
    "  zip.inflate = (bytes, out) => {\n"
    "    if (isBuf(out)) {\n"
    "      let cap = cap0(Math.max(64, bytes.length * 4)), tries = 8;\n"
    "      while (true) {\n"
    "        if (out.room < cap) out.grow(out.cap + (cap - out.room));\n"
    "        try {\n"
    "          const n = zip._inflate(bytes, out.idle(), 0);\n"
    "          out.fed(n);\n"
    "          return n;\n"
    "        } catch (e) {\n"
    "          if (--tries <= 0) throw e;\n"
    "          cap = cap0(cap * 2);\n"
    "        }\n"
    "      }\n"
    "    }\n"
    "    let cap = cap0(Math.max(64, bytes.length * 4)), tries = 8;\n"
    "    while (true) {\n"
    "      const scratch = new Uint8Array(cap);\n"
    "      try {\n"
    "        const n = zip._inflate(bytes, scratch, 0);\n"
    "        return scratch.slice(0, n);\n"
    "      } catch (e) {\n"
    "        if (--tries <= 0) throw e;\n"
    "        cap = cap0(cap * 2);\n"
    "      }\n"
    "    }\n"
    "  };\n"
    "})(this);\n";

ok64 JABCInstallZip(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(zip);
    JABC_API_FN(zip, "_deflate", JABCzipDeflate);  //  sugar: JABC_ZIP_JS
    JABC_API_FN(zip, "_inflate", JABCzipInflate);
    JABC_API_END(zip);
    JABCExecute(JABC_ZIP_JS);
    return OK;
}
