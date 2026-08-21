//  JAB-036: tok.c — the port of jab/tok.cpp + tok.hpp.
//  tok binding — the JS face of dog/tok's TOKLexer.  ONE native leaf,
//  _tok_parse_into(srcBytes, lang, outU8) -> tokenCount, sharing the SAME C
//  core (HUNKu32bTokenize) as HUNK.dogenize — no parse logic is duplicated.
//  The leaf writes the packed tok32 STRAIGHT into the caller's region (a Buf's
//  IDLE or a fresh worst-case scratch); the JS dispatch (tok.parse) returns a
//  zero-copy Uint32Array view over the bytes just written.  See JS-023.
#include "JABC.h"
#include "dog/HUNK.h"

//  A u8 slice from a JS string (copied into `tmp`, NUL dropped) or a typed
//  array (zero-copy view).  jab keeps this in hunk.hpp; each C module carries
//  its own copy (there is no shared jab-side header here).
static b8 JABCArgU8(u8s out, JSContext *ctx, JSValueConst v, u8 *tmp,
                    size_t cap) {
    if (JS_IsString(v)) {
        size_t n = 0;
        const char *s = JS_ToCStringLen(ctx, &n, v);
        if (s == NULL) return NO;
        //  jab truncates to the scratch; QJAB-011: `cap - 1` at cap==0 is
        //  SIZE_MAX, so guard it like the hunk.c twin (hunk.c:24).
        if (n >= cap) n = cap ? cap - 1 : 0;
        if (n) memcpy(tmp, s, n);
        JS_FreeCString(ctx, s);
        out[0] = tmp;
        out[1] = tmp + n;
        return YES;
    }
    //  PTR-010: a typed-array arg — DATA is the whole view, copied out flat
    //  because the caller only reads it (hunk fields are plain slices).
    u8 *b[4] = {};
    if (!JABCDataOf(b, ctx, v)) return NO;
    out[0] = u8bData(b)[0];
    out[1] = u8bData(b)[1];
    return YES;
}

//  _tok_parse_into(srcBytes, lang, outU8) -> tokenCount
//  Mirrors JABChunkDogenize's lex half but writes packed tok32 directly into
//  the caller-owned region `outU8` (a Buf's idle() or a fresh JS scratch),
//  returning the token count.  Guards, ALL before any write:
//   - source > 16 MiB -> throw (24-bit end-offset cap, HUNKTOKOOB);
//   - outU8 not 4-byte aligned -> throw (a u32 view over it must be aligned);
//   - outU8 too small for the worst case ((srcn+1) tok32) -> throw, so a partial
//     lex can never corrupt a reused buffer.
static JABC_FN(JABCtokParseInto) {
    if (argc < 3) JABC_THROW("tok._tok_parse_into(srcBytes, lang, outU8)");
    u8 *sourceb[4] = {};
    if (!JABCDataOf(sourceb, ctx, argv[0])) JABC_FAIL;
    u8 const *const *source = u8bDataC(sourceb);
    size_t srcn = u8bDataLen(sourceb);
    if (srcn > TOK_OFF_MASK)  //  24-bit end offset cap (16 MiB) -> HUNKTOKOOB
        JABC_THROW("tok.parse: source > 16 MiB");
    u8 exttmp[64];
    u8s ext = {};
    if (!JABCArgU8(ext, ctx, argv[1], exttmp, sizeof(exttmp))) JABC_FAIL;
    u8 *outb[4] = {};
    if (!JABCIdleOf(outb, ctx, argv[2])) JABC_FAIL;
    u8 *const *out = u8bIdle(outb);
    //  A zero-copy Uint32Array view over the written bytes needs a 4-aligned
    //  write position; validate before running so a misuse is a clean throw.
    if (((uintptr_t)out[0] & 3u) != 0)
        JABC_THROW("tok.parse: out not 4-byte aligned (reset the Buf)");
    //  (srcn+1) tok32 is the per-byte upper bound on token count (each token
    //  spans >= 1 byte; +1 covers the empty edge).  Require room up front.
    size_t need = (srcn + 1) * sizeof(u32);
    if ($len(out) < need) JABC_THROW("tok.parse: out too small");
    u32 *base = (u32 *)out[0];
    u32 *tb[4] = {base, base, base, base + (srcn + 1)};
    u8cs srcc = {source[0], source[1]};
    u8cs extc = {ext[0], ext[1]};
    ok64 o = HUNKu32bTokenize(tb, srcc, extc);  //  shared core with dogenize
    if (o != OK) JABC_THROW("tok.parse: lex");
    size_t n = (size_t)(tb[2] - tb[1]);  //  tb[1]==base, so this is the count
    return JS_NewFloat64(ctx, (double)n);
}

//  tok.parse(srcBytes, lang, out?) + the pure-JS TokStream cursor.  Decode is
//  bit math over the Uint32Array mirroring tok32Tag/Offset/Side (dog/tok/TOK.h);
//  token i's start = token i-1's end (0 for i==0).  The cursor PINS the source
//  Uint8Array (offsets are positions, not bytes); text() is a zero-copy
//  subarray, str() decodes it via utf8.Decode.
//
//  out (optional, a Buf): tokenize packed tok32 straight into out's IDLE,
//  advance out.fed(n*4), and return a ZERO-COPY Uint32Array view over those
//  bytes — so one Buf can be reused across many parses (reset() between).  The
//  view is valid only while out is not further fed/reset.  Without out, a fresh
//  worst-case scratch is allocated and the result returned as its own (fresh,
//  4-aligned) trimmed Uint32Array — unchanged from before.
static const char *JABC_TOK_JS =
    "\n"
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const tok = g.tok, utf8 = g.utf8;\n"
    "  tok.parse = (bytes, lang, out) => {\n"
    "    lang = lang || \"\";\n"
    "    if (out !== undefined && out !== null) {\n"
    "      //  reuse the caller's Buf: lex into its IDLE, commit, view it zero-copy.\n"
    "      const idle = out.idle();                     // [ _idle, cap ) as a Uint8Array\n"
    "      const n = tok._tok_parse_into(bytes, lang, idle);\n"
    "      out.fed(n * 4);                              // advance the cursor n tok32\n"
    "      //  zero-copy u32 view over the bytes just written (idle head is 4-aligned;\n"
    "      //  the native leaf threw otherwise).\n"
    "      return new Uint32Array(idle.buffer, idle.byteOffset, n);\n"
    "    }\n"
    "    //  no out: a fresh worst-case scratch ((srcLen+1) tok32), trimmed to n.\n"
    "    const scratch = new Uint8Array((bytes.length + 1) * 4);\n"
    "    const n = tok._tok_parse_into(bytes, lang, scratch);\n"
    "    return new Uint32Array(scratch.buffer, 0, n);  // fresh, nothing else aliases\n"
    "  };\n"
    "  class TokStream {\n"
    "    constructor(t32, src) {\n"
    "      this._t = t32;            // Uint32Array of tok32\n"
    "      this._src = src;          // pinned source Uint8Array (positions index it)\n"
    "      this._i = 0;\n"
    "    }\n"
    "    get length() { return this._t.length; }\n"
    "    get _w()  { return this._t[this._i] >>> 0; }\n"
    "    get tag()    { return String.fromCharCode(65 + (this._w >>> 27)); }\n"
    "    get custom() { return (this._w >>> 26) & 1; }\n"
    "    get side()   { return (this._w >>> 24) & 3; }\n"
    "    get end()    { return this._w & 0xFFFFFF; }\n"
    "    get start()  { return this._i > 0 ? (this._t[this._i - 1] & 0xFFFFFF) : 0; }\n"
    "    text(src) {                 // zero-copy subarray over the source bytes\n"
    "      const s = src || this._src;\n"
    "      return s.subarray(this.start, this.end);\n"
    "    }\n"
    "    str(src) { return utf8.Decode(this.text(src)); }\n"
    "    seek(i) { this._i = i | 0; return this; }\n"
    "    next() {\n"
    "      if (this._i + 1 >= this._t.length) return false;\n"
    "      this._i++;\n"
    "      return true;\n"
    "    }\n"
    "  }\n"
    "  tok.TokStream = TokStream;\n"
    "  g.TokStream = TokStream;\n"
    "})(this);\n";

//  tok module install (JS-023): the _tok_parse_into leaf + the embedded
//  TokStream cursor.  No abc.* dependency; the lexer core lives in dog.
ok64 JABCInstallTok(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(tok);
    JABC_API_FN(tok, "_tok_parse_into", JABCtokParseInto);
    JABC_API_END(tok);
    JABCExecute(JABC_TOK_JS);
    return OK;
}
