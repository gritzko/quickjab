//  JAB-036: git.c — the port of jab/git.hpp.
//  GIT-030: the foreign-`.git` READ-ONLY waist — four calls, ODB only.
//
//    git.open(path)        -> handle   (a repo root, a .git dir, or a gitfile)
//    git.getHex(h, hexlet) -> {type, bytes} | null   (6..40 hex, ambiguous throws)
//    git.getSafe(h, sha40) -> {type, bytes} | null   (re-hashed before it returns)
//    git.getTreeDiff(h, a, b) -> Uint8Array | null   (DOG-030, tree-formatted)
//    git.close(h)
//
//  The store itself is dog/git/ODB: one flat struct that maps the pack pairs,
//  grows the resolve scratch and speaks plain words.
//  What is left HERE is binding work only — a slot's lifetime, the pin whose
//  free_func closes a handle nobody closed, string arguments in, Uint8Array
//  copies out, and throws.  jab/git.hpp is the same shim over the same C.
#include <string.h>

#include "JABC.h"
#include "abc/HEX.h"
#include "abc/PRO.h"  //  DOG-030: the call/done flow the tree diff runs in
#include "dog/DOG.h"
#include "dog/git/GIT.h"
#include "dog/git/ODB.h"
#include "dog/git/SHA1.h"

#define GIT_MAX_OPEN 100  //  live repo handles (a board scans every worktree)

//  A slot: the store plus the incarnation counter the pin is checked against.
typedef struct {
    odb o;
    b8 live;
    u32 gen;
} jabc_gits;

static jabc_gits JABC_GITS[GIT_MAX_OPEN];
static u32 JABC_GIT_GEN;

//  The JS-side pin's payload: which slot, and which incarnation of it.
typedef struct {
    u32 gen;
    u32 id;
} jabc_gitpin;

//  Errors cross the boundary in PLAIN WORDS: the sentence a call left in the
//  store when it names a path / hashlet / sha, else the words for its code.
static const char *JABCGitSay(odb *o, ok64 r) {
    return (o && o->say[0]) ? o->say : ODBWords(r);
}

static void JABCGitFree(jabc_gits *s) {
    ODBClose(&s->o);
    s->live = NO;
}

//  The pin's free_func: a handle the JS side dropped without closing.  The
//  generation guard keeps a stale husk off a slot that has been reopened.
static void JABCGitPinFree(JSRuntime *rt, void *opaque, void *ptr) {
    (void)rt;
    (void)opaque;
    jabc_gitpin *p = (jabc_gitpin *)ptr;
    if (p == NULL) return;
    if (p->id < GIT_MAX_OPEN) {
        jabc_gits *s = &JABC_GITS[p->id];
        if (s->live && s->gen == p->gen) JABCGitFree(s);
    }
    free(p);
}

//  argv[0] is the pin: resolve it to a LIVE slot, or NULL (the caller throws).
static jabc_gits *JABCGitOf(JSContext *ctx, JSValueConst v) {
    u8 *b[4] = {};
    if (!JABCDataOf(b, ctx, v)) return NULL;
    if (u8bDataLen(b) != sizeof(jabc_gitpin)) return NULL;
    jabc_gitpin *p = (jabc_gitpin *)u8bData(b)[0];
    if (p == NULL || p->id >= GIT_MAX_OPEN) return NULL;
    jabc_gits *s = &JABC_GITS[p->id];
    if (!s->live || s->gen != p->gen) return NULL;
    return s;
}

//  Read a short JS string argument (a path, a hashlet) into `out`.  NO when it
//  is not a string, is empty, or does not fit — never a silent truncation.
static b8 jgit_str(char *out, size_t cap, JSContext *ctx, JSValueConst v) {
    if (!JS_IsString(v)) return NO;
    size_t n = 0;
    const char *s = JS_ToCStringLen(ctx, &n, v);
    if (s == NULL) return NO;
    b8 ok = (b8)(n > 0 && n < cap);
    if (ok) {
        memcpy(out, s, n);
        out[n] = 0;
    }
    JS_FreeCString(ctx, s);
    return ok;
}

//  {type: "commit"|"tree"|"blob"|"tag", bytes: Uint8Array} — bytes are COPIED
//  out of the store's scratch, never a view onto it.
static JSValue jgit_object(JSContext *ctx, u8 type, u8csc content) {
    u8cs tn = {};
    if (GITTypeName(tn, type) != OK) JABC_THROW(ODBWords(ODBNOTYPE));
    JSValue o = JS_NewObject(ctx);
    JABCSetProp(ctx, o, "type", JABCStrOfSlice(ctx, tn));
    JABCSetProp(ctx, o, "bytes",
                JABCBlob(ctx, content[0], (size_t)u8csLen(content)));
    return o;
}

//  _git_open(path) -> {pin, dir, odb, packs, objects}
static JABC_FN(JABCgitOpen) {
    if (argc < 1) JABC_THROW("git.open(path)");
    char path[FILE_PATH_MAX_LEN];
    if (!jgit_str(path, sizeof(path), ctx, argv[0]))
        JABC_THROW("git.open: the path must be a string");
    int id = -1;
    for (int i = 0; i < GIT_MAX_OPEN; i++)
        if (!JABC_GITS[i].live) {
            id = i;
            break;
        }
    if (id < 0) JABC_THROW(ODBWords(ODBFULL));
    jabc_gits *s = &JABC_GITS[id];
    odb *o = &s->o;
    u8cs ps = {(u8 const *)path, (u8 const *)path + strlen(path)};
    ok64 r = ODBOpen(o, ps);
    if (r != OK) JABC_THROW(JABCGitSay(o, r));
    s->live = YES;
    s->gen = ++JABC_GIT_GEN;

    jabc_gitpin *pin = (jabc_gitpin *)malloc(sizeof(jabc_gitpin));
    if (pin == NULL) {
        JABCGitFree(s);
        JABC_THROW(ODBWords(ODBNOMEM));
    }
    pin->gen = s->gen;
    pin->id = (u32)id;
    JSValue ta =
        JABCBytesNoCopy(ctx, (u8 *)pin, sizeof(*pin), JABCGitPinFree, NULL);
    if (JS_IsException(ta)) {  //  out of memory: the wrapper never took the pin
        free(pin);
        JABCGitFree(s);
        JABC_FAIL;
    }
    u64 objs = 0;
    for (u64 i = 0; i < o->npk; i++) objs += o->pk[i].count;
    JSValue h = JS_NewObject(ctx);
    JABCSetProp(ctx, h, "pin", ta);
    JABCSetProp(ctx, h, "dir", JSOfCString(o->dir));
    JABCSetProp(ctx, h, "odb", JSOfCString(o->objects));
    JABCSetProp(ctx, h, "packs", JS_NewFloat64(ctx, (double)o->npk));
    JABCSetProp(ctx, h, "objects", JS_NewFloat64(ctx, (double)objs));
    return h;
}

//  The shared read: hashlet or full sha in, {type,bytes} | null out.  `safe`
//  re-hashes the object over its loose framing and refuses a mismatch.
static JSValue jgit_read(JSContext *ctx, int argc, JSValueConst *argv,
                         b8 safe) {
    if (argc < 2)
        JABC_THROW(safe ? "git.getSafe(h, sha40)" : "git.getHex(h, hexlet)");
    jabc_gits *s = JABCGitOf(ctx, argv[0]);
    if (s == NULL) {
        //  a non-typed-array pin left a gate's refusal pending: the plain-words
        //  answer is the same either way — this handle is not usable.
        if (JS_HasException(ctx)) JS_FreeValue(ctx, JS_GetException(ctx));
        JABC_THROW(ODBWords(ODBCLOSED));
    }
    char hexlet[64];
    if (!jgit_str(hexlet, sizeof(hexlet), ctx, argv[1]))
        JABC_THROW("git: the object name must be a hex string");
    u8cs hl = {(u8 const *)hexlet, (u8 const *)hexlet + strlen(hexlet)};

    u8cs content = {};
    u8 type = 0;
    sha1 sha = {};
    ok64 r = OK;
    if (safe) {
        //  a safe read is by whole sha only, so the hex is parsed right here
        if (!HEXu8sValid(hl)) JABC_THROW(ODBWords(ODBNOTHEX));
        if (u8csLen(hl) != 40) JABC_THROW(ODBWords(ODBSHA40));
        if (sha1FromHex(&sha, hl) != OK) JABC_THROW(ODBWords(ODBNOTHEX));
        r = ODBSafe(&s->o, &sha, content, &type);
    } else {
        r = ODBHex(&s->o, hl, &sha, content, &type);
    }
    if (r == NODATA) return JS_NULL;
    if (r != OK) JABC_THROW(JABCGitSay(&s->o, r));
    return jgit_object(ctx, type, content);
}

static JABC_FN(JABCgitGet) { return jgit_read(ctx, argc, argv, NO); }
static JABC_FN(JABCgitGetSafe) { return jgit_read(ctx, argc, argv, YES); }

//  DOG-030: BOTH trees are read here, off the same handle, and diffed into
//  BASS; `have` goes NO when the NEW side names no readable tree (-> null).
static ok64 jgit_tree_diff(odb *o, u8csc ha, u8csc hb, u8csp out, b8 *have) {
    sane(o != NULL && out != NULL && have != NULL);
    a_cstr(zero40, "0000000000000000000000000000000000000000");
    *have = NO;
    out[0] = out[1] = NULL;
    u8cs ta = {}, tb = {};
    sha1 sha = {};
    u8 type = 0;
    if (!u8csEq(ha, zero40)) {  //  an all-zero name spells the empty tree
        ok64 r = ODBHex(o, ha, &sha, ta, &type);
        if (r != OK && r != NODATA) return r;
        if (r != OK || type != DOG_OBJ_TREE) done;
    }
    a_ren(anew, ta);  //  the OLD read reuses the very same store scratch
    if (!u8csEq(hb, zero40)) {
        ok64 r = ODBHex(o, hb, &sha, tb, &type);
        if (r != OK && r != NODATA) return r;
        //  an unreadable OLD side reads as the empty tree: all of NEW is new
        if (r != OK || type != DOG_OBJ_TREE) tb[0] = tb[1] = NULL;
    }
    size_t cap = 2 * ((size_t)u8csLen(anew) + (size_t)u8csLen(tb)) + 64;
    a_carve(u8, buf, cap);
    call(GITTreeDiff, buf, anew, tb);
    a_dup(u8c, res, u8bDataC(buf));
    u8csMv(out, res);
    *have = YES;
    done;
}

//  _git_tree_diff(pin, sha40A, sha40B) -> Uint8Array | null.  Marshalling
//  only: two names in, the dog/git diff's bytes out (null = no such tree).
static JABC_FN(JABCgitTreeDiff) {
    if (argc < 3) JABC_THROW("git.getTreeDiff(h, sha40A, sha40B)");
    jabc_gits *s = JABCGitOf(ctx, argv[0]);
    if (s == NULL) {
        if (JS_HasException(ctx)) JS_FreeValue(ctx, JS_GetException(ctx));
        JABC_THROW(ODBWords(ODBCLOSED));
    }
    char ha[64], hb[64];
    if (!jgit_str(ha, sizeof(ha), ctx, argv[1]) ||
        !jgit_str(hb, sizeof(hb), ctx, argv[2]))
        JABC_THROW("git: the object name must be a hex string");
    u8cs sa = {(u8 const *)ha, (u8 const *)ha + strlen(ha)};
    u8cs sb = {(u8 const *)hb, (u8 const *)hb + strlen(hb)};
    u8cs diff = {};
    b8 have = NO;
    ok64 r = jgit_tree_diff(&s->o, sa, sb, diff, &have);
    if (r != OK) JABC_THROW(JABCGitSay(&s->o, r));
    if (!have) return JS_NULL;
    return JABCBlob(ctx, diff[0], (size_t)u8csLen(diff));
}

//  _git_close(pin) — unmap every pack, free the scratch, retire the slot.
static JABC_FN(JABCgitClose) {
    if (argc < 1) JABC_THROW("git.close(h)");
    jabc_gits *s = JABCGitOf(ctx, argv[0]);
    if (JS_HasException(ctx)) JABC_FAIL;
    if (s != NULL) JABCGitFree(s);
    JABC_UNDEF;
}

//  The JS surface: a handle object over the pin.  Refs stay ABOVE this waist
//  (test/gitverify.js reads HEAD/packed-refs as text) — the waist is ODB only.
static const char *JABC_GIT_JS =
    "\n"
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const abc = g.abc;\n"
    "  const git = g.git || (g.git = {});\n"
    "  class GitOdb {\n"
    "    constructor(o) {\n"
    "      this._pin = o.pin;\n"
    "      this.dir = o.dir; this.odb = o.odb;\n"
    "      this.packs = o.packs; this.objects = o.objects;\n"
    "    }\n"
    "    get closed() { return this._pin === null; }\n"
    "    _live() {\n"
    "      if (this._pin === null) throw \"git: this repository handle is "
    "closed\";\n"
    "      return this._pin;\n"
    "    }\n"
    "    //  6..40 hex chars -> {type, bytes} | null; ambiguous throws.\n"
    "    getHex(hexlet) { return abc._git_get(this._live(), hexlet); }\n"
    "    //  the whole 40 -> {type, bytes} | null, re-hashed before it "
    "returns.\n"
    "    getSafe(sha40) { return abc._git_get_safe(this._live(), sha40); }\n"
    "    //  DOG-030: the paired diff of tree `a` against tree `b`, in git tree\n"
    "    //  FORMAT (git.tree(buf) reads it); an all-zero name = the empty tree.\n"
    "    getTreeDiff(a, b) { return abc._git_tree_diff(this._live(), a, b); }\n"
    "    close() {\n"
    "      if (this._pin !== null) { abc._git_close(this._pin); this._pin = "
    "null; }\n"
    "      return this;\n"
    "    }\n"
    "  }\n"
    "  git.open = (path) => new GitOdb(abc._git_open(path));\n"
    "  git.getHex = (h, hexlet) => h.getHex(hexlet);\n"
    "  git.getSafe = (h, sha40) => h.getSafe(sha40);\n"
    "  git.getTreeDiff = (h, a, b) => h.getTreeDiff(a, b);\n"
    "  git.close = (h) => h.close();\n"
    "  git.GitOdb = GitOdb;\n"
    "})(this);\n";

//  Installed AFTER the cont.c bundle: `git` is that bundle's object.
ok64 JABCInstallGit(JSContext *ctx, JSValueConst global) {
    JABC_API_GET(abc);
    JABC_API_FN(abc, "_git_open", JABCgitOpen);
    JABC_API_FN(abc, "_git_get", JABCgitGet);
    JABC_API_FN(abc, "_git_get_safe", JABCgitGetSafe);
    JABC_API_FN(abc, "_git_tree_diff", JABCgitTreeDiff);
    JABC_API_FN(abc, "_git_close", JABCgitClose);
    JABC_API_END(abc);
    JABCExecute(JABC_GIT_JS);
    return OK;
}
