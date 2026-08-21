//  GIT-032: dirc.c — the READ-ONLY `.git/index` (staging area) leaf.
//
//    dog.readIndex(repo|path) -> {version, entries:[{path, sha, mode,
//                                 stage, size, mtime, ...}]} | null
//
//  One call maps the index, drains it whole and unmaps; dog/git/DIRC
//  does every byte of the parsing, this is marshalling only.  bee never
//  writes an index nor refreshes a stat entry (GIT-032:55).
#include <string.h>

#include "JABC.h"
#include "abc/FILE.h"
#include "abc/PATH.h"
#include "dog/git/DIRC.h"
#include "dog/git/SHA1.h"

//  Errors cross the boundary in PLAIN WORDS, never as ok64 (GIT-032:64).
static const char *JABCdircWords(ok64 r) {
    if (r == DIRCSPLIT)
        return "index: this is a split index, which bee does not read";
    if (r == DIRCBADFMT)
        return "index: not a readable git index (v2/v3/v4, SHA-1 only)";
    if (r == SNOROOM || r == NOROOM)
        return "index: a path in this index is too long to read";
    return "index: this index could not be read";
}

//  Read a short JS string argument into `out`; NO when it is not a
//  string, is empty, or does not fit — never a silent truncation.
static b8 jdirc_str(char *out, size_t cap, JSContext *ctx, JSValueConst v) {
    if (!JS_IsString(v)) return NO;
    size_t n = 0;
    const char *s = JS_ToCStringLen(ctx, &n, v);
    if (s == NULL) return NO;
    //  QJAB-011: an interior NUL fits the length check yet truncates the C
    //  path the OS sees — refuse it here, as arg.c's JABCPath does.
    u8cs src = {(u8 const *)s, (u8 const *)s + n};
    b8 ok = (b8)(n > 0 && n < cap && u8csFind(src, 0) != OK);
    if (ok) {
        memcpy(out, s, n);
        out[n] = 0;
    }
    JS_FreeCString(ctx, s);
    return ok;
}

//  One JS row per entry: the `<path>, <sha>` a tree walk gives, plus
//  the stage slot and the stat cache that lets a clean file skip being
//  hashed (GIT-032:45).
static JSValue jdirc_row(JSContext *ctx, dirc_entry const *e) {
    sha1hex hex = {};
    u8cs hs = {};
    sha1hexFromSha1(&hex, &e->sha);
    sha1hexSlice(hs, &hex);
    a_dup(u8c, path, e->path);
    JSValue row = JS_NewObject(ctx);
    JABCSetProp(ctx, row, "path", JABCStrOfSlice(ctx, path));
    JABCSetProp(ctx, row, "sha", JABCStrOfSlice(ctx, hs));
    JABCSetProp(ctx, row, "mode", JS_NewFloat64(ctx, (double)e->mode));
    JABCSetProp(ctx, row, "stage", JS_NewFloat64(ctx, (double)e->stage));
    JABCSetProp(ctx, row, "size", JS_NewFloat64(ctx, (double)e->size));
    JABCSetProp(ctx, row, "mtime", JS_NewFloat64(ctx, (double)e->mtime));
    JABCSetProp(ctx, row, "mtimeNs", JS_NewFloat64(ctx, (double)e->mtime_ns));
    //  The two bits that make an entry lie about the worktree on purpose.
    JABCSetProp(ctx, row, "assumeValid",
                JS_NewBool(ctx, (e->flags & DIRC_ASSUME_VALID) != 0));
    JABCSetProp(ctx, row, "skipWorktree",
                JS_NewBool(ctx, (e->xflags & DIRC_SKIP_WORKTREE) != 0));
    return row;
}

//  _dirc_read(indexPath) -> {version, entries} | null when there is no
//  such file (a repo that has never staged anything has no index).
static JABC_FN(JABCdircRead) {
    if (argc < 1) JABC_THROW("dog.readIndex(repo|path)");
    char path[FILE_PATH_MAX_LEN];
    if (!jdirc_str(path, sizeof(path), ctx, argv[0]))
        JABC_THROW("index: the path must be a string");
    a_path(ip);
    u8cs ps = {(u8 const *)path, (u8 const *)path + strlen(path)};
    if (PATHu8bFeed(ip, ps) != OK) JABC_THROW("index: that path is too long");

    u8b map = {};
    if (FILEMapOnce(map, $path(ip)) != OK) return JS_NULL;
    a_pad(u8, pad, DIRC_PATH_MAX);
    a_dup(u8c, idx, u8bDataC(map));
    dirc_cur cur = {};
    ok64 r = DIRCOpen(idx, u8bIdle(pad), &cur);
    if (r != OK) {
        FILEUnMapOnce(map);
        JABC_THROW(JABCdircWords(r));
    }

    //  Entries arrive path-ascending, stage-ascending within a path, so
    //  the array keeps the order a k-way merge wants (BEE-022).
    JSValue rows = JS_NewArray(ctx);
    u32 n = 0;
    for (;;) {
        dirc_entry e = {};
        ok64 d = DIRCDrain(&cur, &e);
        if (d == NODATA) break;
        if (d != OK) {
            JS_FreeValue(ctx, rows);
            FILEUnMapOnce(map);
            JABC_THROW(JABCdircWords(d));
        }
        JS_SetPropertyUint32(ctx, rows, n++, jdirc_row(ctx, &e));
    }
    FILEUnMapOnce(map);

    JSValue out = JS_NewObject(ctx);
    JABCSetProp(ctx, out, "version", JS_NewFloat64(ctx, (double)cur.version));
    JABCSetProp(ctx, out, "entries", rows);
    return out;
}

//  The JS surface: `dog` is igno.c's namespace object, so this only
//  joins the path an opened repo already knows to the index file name.
static const char *JABC_DIRC_JS =
    "\n"
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const dog = g.dog;\n"
    "  //  GIT-032: a git.open() handle (its .dir is the .git dir), a\n"
    "  //  .git dir, or the index file itself.\n"
    "  dog.readIndex = function (repo) {\n"
    "    let p = (typeof repo === \"string\") ? repo : repo.dir;\n"
    "    if (!p.endsWith(\"/index\")) p = p + \"/index\";\n"
    "    return dog._dirc_read(p);\n"
    "  };\n"
    "})(this);\n";

ok64 JABCInstallDirc(JSContext *ctx, JSValueConst global) {
    //  Same `dog` namespace igno.c makes; created here when this leaf
    //  installs first.
    JSValue dog = JS_GetPropertyStr(ctx, global, "dog");
    if (!JS_IsObject(dog)) {
        JS_FreeValue(ctx, dog);
        dog = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "dog", JS_DupValue(ctx, dog));
    }
    JABC_API_FN(dog, "_dirc_read", JABCdircRead);
    JABC_API_END(dog);
    JABCExecute(JABC_DIRC_JS);
    return OK;
}
