//  JAB-036: io.c — the port of jab/io.cpp; see PORTING.md for the funnel
//  cheat-sheet.  fds are plain numbers; buffers are JS-owned typed arrays.
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "JABC.h"
#include "abc/FILE.h"
#include "abc/PATH.h"

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

//  These are the leaf syscalls — one native call == one tight C operation over
//  a fd and/or a typed array's backing memory.  The cursor logic lives in the
//  JS `Buf` class (buf.c); nothing here holds memory or a JS reference.

//  A JS number as an fd.  NaN / out of range lands on -1, which every FILE
//  call refuses; a real conversion failure leaves the exception pending.
static b8 JABCInt(int *out, JSContext *ctx, JSValueConst v) {
    double d = 0;
    if (JS_ToFloat64(ctx, &d, v) < 0) return NO;
    *out = (d >= (double)INT_MIN && d <= (double)INT_MAX) ? (int)d : -1;
    return YES;
}

//  Copy a JS string argument into a small fixed word ("r"/"rw"/"c"); a
//  non-string leaves the caller's default in place, as jab does.
static void JABCWord(char *out, size_t cap, JSContext *ctx, JSValueConst arg) {
    if (!JS_IsString(arg)) return;
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, arg);
    if (s == NULL) return;
    if (len >= cap) len = cap - 1;
    memcpy(out, s, len);
    out[len] = '\0';
    JS_FreeCString(ctx, s);
}

//  io.open(path, "r"|"rw"|"c") -> fd
static JABC_FN(JABCioOpen) {
    if (argc < 1) JABC_THROW("io.open(path, mode) -> fd");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.open(): bad path");
    char mode[8] = "r";
    if (argc > 1) JABCWord(mode, sizeof(mode), ctx, argv[1]);
    int fd = -1;
    ok64 o;
    if (strcmp(mode, "c") == 0) {
        //  FILECreate sets a sane 0600 mode; FILEOpen passes no mode to
        //  open(2), so an O_CREAT through it would get garbage perms.
        o = FILECreate(&fd, $path(path));
    } else {
        int flags = (strcmp(mode, "rw") == 0) ? O_RDWR : O_RDONLY;
        o = FILEOpen(&fd, $path(path), flags);
    }
    if (o != OK || fd < 0) JABC_THROW(strerror(errno));
    return JS_NewFloat64(ctx, (double)fd);
}

//  io.close(fd)
static JABC_FN(JABCioClose) {
    if (argc < 1) JABC_THROW("io.close(fd)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    FILEClose(&fd);
    JABC_UNDEF;
}

//  io.sync(fd)
static JABC_FN(JABCioSync) {
    if (argc < 1) JABC_THROW("io.sync(fd)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    if (FILESync(&fd) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.size(fd) -> bytes
static JABC_FN(JABCioSize) {
    if (argc < 1) JABC_THROW("io.size(fd)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    size_t sz = 0;
    if (FILESize(&sz, &fd) != OK) JABC_THROW(strerror(errno));
    return JS_NewFloat64(ctx, (double)sz);
}

//  io.resize(fd, n)
static JABC_FN(JABCioResize) {
    if (argc < 2) JABC_THROW("io.resize(fd, n)");
    int fd = -1;
    double n = 0;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    if (JS_ToFloat64(ctx, &n, argv[1]) < 0) JABC_FAIL;
    if (n < 0) JABC_THROW("io.resize(): negative size");
    if (FILEResize(&fd, (size_t)n) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.lock(fd, exclusive?) / io.unlock(fd)
static JABC_FN(JABCioLock) {
    if (argc < 1) JABC_THROW("io.lock(fd, exclusive)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    b8 excl = argc > 1 ? (JS_ToBool(ctx, argv[1]) == 1) : YES;
    if (FILELock(&fd, excl) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}
static JABC_FN(JABCioUnlock) {
    if (argc < 1) JABC_THROW("io.unlock(fd)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    if (FILEUnlock(&fd) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  Marshal a filled `filestat` into a JS {size, mode, kind, mtime, atime}
//  object.  size/mode are plain numbers; kind is a tag string; mtime/atime are
//  ron60 timestamps and cross as BigInt — the same encoding ron.encode /
//  ron.date / the JS dateCol consume (JS-021).  Shared by io.stat / io.lstat.
static JSValue JABCStatObj(JSContext *ctx, const filestat *fs) {
    JSValue obj = JS_NewObject(ctx);
    if (JS_IsException(obj)) return obj;
    JABCSetProp(ctx, obj, "size", JS_NewFloat64(ctx, (double)fs->size));
    JABCSetProp(ctx, obj, "mode", JS_NewFloat64(ctx, (double)fs->mode));
    const char *kind = "other";
    if (fs->kind == FILE_KIND_REG) kind = "reg";
    else if (fs->kind == FILE_KIND_DIR) kind = "dir";
    else if (fs->kind == FILE_KIND_LNK) kind = "lnk";
    JABCSetProp(ctx, obj, "kind", JS_NewString(ctx, kind));
    JABCSetProp(ctx, obj, "mtime", JABCBigU64(ctx, (u64)fs->mtime));
    JABCSetProp(ctx, obj, "atime", JABCBigU64(ctx, (u64)fs->atime));
    return obj;
}

//  io.stat(path) -> {size, mode, kind, mtime, atime}  (follows symlinks)
static JABC_FN(JABCioStat) {
    if (argc < 1) JABC_THROW("io.stat(path)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.stat(): bad path");
    filestat fs = {};
    if (FILEStat(&fs, $path(path)) != OK) JABC_THROW(strerror(errno));
    return JABCStatObj(ctx, &fs);
}

//  io.lstat(path) -> {size, mode, kind, mtime, atime}  (does NOT follow the
//  symlink: a link reports kind "lnk", and a dangling link stats fine — lstat
//  inspects the link itself, never its target).
static JABC_FN(JABCioLStat) {
    if (argc < 1) JABC_THROW("io.lstat(path)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.lstat(): bad path");
    filestat fs = {};
    if (FILELStat(&fs, $path(path)) != OK) JABC_THROW(strerror(errno));
    return JABCStatObj(ctx, &fs);
}

//  io.readlink(path) -> string  (the symlink's target, over FILEReadLink).
//  Reads into a stack path buffer; the target bytes cross as a JS string (no
//  NUL appended by the leaf, so length is exact).  Pure marshalling.
static JABC_FN(JABCioReadLink) {
    if (argc < 1) JABC_THROW("io.readlink(path) -> string");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK)
        JABC_THROW("io.readlink(): bad path");
    a_path(target);
    if (FILEReadLink(target, $path(path)) != OK) JABC_THROW(strerror(errno));
    return JABCStrOfSlice(ctx, u8bDataC(target));
}

//  io.realpath(path) -> string  (the canonical absolute path, over realpath(3):
//  symlinks resolved, `.`/`..` collapsed; the path must exist, else it throws
//  strerror(errno)).  This is the symlink-free spelling io.cwd() reports after
//  io.chdir() — e.g. /tmp -> /private/tmp on macOS.
static JABC_FN(JABCioRealPath) {
    if (argc < 1) JABC_THROW("io.realpath(path) -> string");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK)
        JABC_THROW("io.realpath(): bad path");
    char resolved[PATH_MAX];
    if (realpath((char const *)*$path(path), resolved) == NULL)
        JABC_THROW(strerror(errno));
    return JS_NewString(ctx, resolved);
}

//  io.symlink(target, linkpath) -> create a symlink `linkpath` pointing at
//  `target` (over FILESymLink).  `target` is stored verbatim (may be relative /
//  dangling).  Pure marshalling; throws if linkpath already exists.
static JABC_FN(JABCioSymLink) {
    if (argc < 2) JABC_THROW("io.symlink(target, linkpath)");
    a_pad(u8, target, FILE_PATH_MAX_LEN);
    a_pad(u8, linkpath, FILE_PATH_MAX_LEN);
    if (JABCPath(target, ctx, argv[0]) != OK ||
        JABCPath(linkpath, ctx, argv[1]) != OK)
        JABC_THROW("io.symlink(): bad path");
    if (FILESymLink($path(target), $path(linkpath)) != OK)
        JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.chmod(path, mode) -> set the POSIX permission bits (over FILEChmod).
//  `mode` is the usual octal int (e.g. 0o755); pure marshalling.
static JABC_FN(JABCioChmod) {
    if (argc < 2) JABC_THROW("io.chmod(path, mode)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.chmod(): bad path");
    double dm = 0;
    if (JS_ToFloat64(ctx, &dm, argv[1]) < 0) JABC_FAIL;
    if (dm < 0) JABC_THROW("io.chmod(): negative mode");
    if (FILEChmod($path(path), (u32)dm) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.setMtime(path, ron60) -> stamp a file's atime+mtime to the ron60 instant
//  (over FILESetMtime / utimensat NOFOLLOW: a symlink stamps the link itself).
//  ron60 crosses as a BigInt, like io.stat's mtime and ron.encode (JS-047).
static JABC_FN(JABCioSetMtime) {
    if (argc < 2) JABC_THROW("io.setMtime(path, ron60)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK)
        JABC_THROW("io.setMtime(): bad path");
    u64 ts = 0;
    if (!JABCBigU64Of(&ts, ctx, argv[1])) JABC_FAIL;
    if (FILESetMtime($path(path), (ron60)ts) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.readdir — one entry point over FILEScanDir / FILEDeepScanDir with a
//  POLYMORPHIC 2nd arg.  FILEScanDir delivers each entry as the FULL iterator
//  path (the scanned root + the entry name; '.'/'..' already skipped, dir
//  entries carry a trailing '/').  Every shape emits the path RELATIVE to the
//  scanned root, KEEPING the dir's trailing '/' as the file-vs-dir marker (e.g.
//  "sub/", "sub/child").  At depth 0 the relative path is just the basename, so
//  the one-level form lists "alpha", "sub/".
//
//  The 2nd arg is dispatched in the native frame:
//   - absent              -> form 1, options all default.
//   - a function          -> sugar for {callback: fn} (the directed cb).
//   - an options object    -> {recursive, callback, hidden} (any subset).
//   - anything else        -> a TypeError-style throw.
//  Resulting behaviors:
//   1. io.readdir(path[, {recursive}]) -> string[]   array form (no callback):
//        one level, or — with recursive:true — the flat full subtree via the
//        native FILE_SCAN_DEEP (FILEDeepScanDir).  Dirs marked.
//   2. io.readdir(path, fn|{callback:fn[, recursive]}) -> undefined   cb(name)
//        per entry; the cb return is a directive: "more"/truthy/undefined =
//        continue, "enough"/false = stop the WHOLE scan, "skip" = do not descend
//        into THIS dir but keep scanning its siblings (the prune; meaningful
//        only when recursive is true, a no-op in the one-level form), "recur" =
//        descend into this dir first (the mirror: meaningful only when recursive
//        is false; a no-op once recursive:true already descends the whole tree).
//        The entry is delivered to the cb BEFORE its directive is read, so
//        "skip" prunes the subtree, never the dir entry itself.  The cb runs
//        synchronously inside the scan frame and is never stashed (rule #4); a
//        cb throw aborts the scan and propagates.
//   hidden (default false): basenames starting '.' are SKIPPED, and hidden dirs
//        are NOT descended (the skip returns FILESKIP, which both omits the
//        entry and prunes recursion — for the native deep scan and the per-entry
//        "recur" alike).  hidden:true includes dotfiles and descends hidden dirs.
//
//  Aborts (cb "enough" / a cb throw) leave the scan via a private non-OK code so
//  they unwind FILEScanRecurse without masquerading as a FILE error; the caller
//  tells an abort from a real error by inspecting the context (`stop` / `threw`),
//  never by the code's identity.
con ok64 JABCSCANSTOP = 0x4a414253544f50;  //  "JABSTOP" — binding-private, never RON-decoded

//  Build the root-relative, dir-marked entry name from the full iterator path
//  into the caller's scratch path buffer.  Empty (the root itself) -> NODATA.
static ok64 JABCReaddirRel(path8b out, path8p full, size_t rootlen) {
    a_dup(u8c, data, u8bDataC(full));
    if ($len(data) <= (ssize_t)(rootlen + 1)) return NODATA;
    //  Skip "<root>/" — a_rest does the offset arithmetic with bounds checks.
    a_rest(u8c, rel, data, rootlen + 1);
    b8 slash = (!$empty(rel) && *$last(rel) == '/');
    if (slash) u8csShed1(rel);  //  PATHu8bPush rejects a trailing '/'
    if ($empty(rel)) return NODATA;
    ok64 o = PATHu8bDup(out, rel);
    if (o != OK) return o;
    if (slash) {  //  re-mark the dir
        a_cstr(s, "/");
        o = PATHu8bFeed(out, s);
        if (o != OK) return o;
    }
    return OK;
}

//  Is this entry hidden? — its basename starts with '.'.  Operates on the FULL
//  iterator path: alias its DATA, drop a trailing '/' (dir entries carry one),
//  take the basename, test the first byte.  '.'/'..' are already dropped by the
//  scan, so any leading-dot basename here is a real dotfile / dot-dir.
static b8 JABCReaddirIsHidden(path8p full) {
    a_dup(u8c, data, u8bDataC(full));
    if (!$empty(data) && *$last(data) == '/') u8csShed1(data);
    u8cs base = {};
    PATHu8sBase(base, data);
    return !$empty(base) && $at(base, 0) == '.';
}

typedef struct {
    JSContext *ctx;
    JSValue arr;      //  array-building forms; JS_UNDEFINED for the cb form
    JSValue cb;       //  cb form; JS_UNDEFINED otherwise
    size_t rootlen;   //  byte length of the scanned root (relative-path base)
    uint32_t n;       //  next array index
    b8 recursive;     //  native deep scan in flight ("recur" is a no-op)
    b8 hidden;        //  include dotfiles + descend hidden dirs
    b8 stop;          //  cb said "enough" — abort, but not an error
    b8 threw;         //  cb threw — abort and propagate the pending exception
} JABCReaddirCtx;

//  Emit one entry into the result array (no-callback array form).
static ok64 JABCReaddirEmit(void0p arg, path8p path) {
    JABCReaddirCtx *c = (JABCReaddirCtx *)arg;
    //  Hidden filter: FILESKIP both omits this entry AND prunes the deep scan
    //  from descending into it (a hidden dir).
    if (!c->hidden && JABCReaddirIsHidden(path)) return FILESKIP;
    a_path(rel);
    ok64 o = JABCReaddirRel(rel, path, c->rootlen);
    if (o == NODATA) return OK;
    if (o != OK) return o;
    JS_SetPropertyUint32(c->ctx, c->arr, c->n++,
                         JABCStrOfSlice(c->ctx, u8bDataC(rel)));
    return OK;
}

//  Map a cb's return value onto a scan directive.  "recur" is signalled to the
//  trampoline via *recur (caller descends); the ok64 return drives
//  continue/skip/stop.  Does NOT consume `r`.
static ok64 JABCReaddirDirective(JABCReaddirCtx *c, JSValueConst r, b8 *recur) {
    *recur = NO;
    if (JS_IsString(r)) {
        char tag[8] = "";
        JABCWord(tag, sizeof(tag), c->ctx, r);
        if (strcmp(tag, "enough") == 0) {
            c->stop = YES;
            return JABCSCANSTOP;
        }
        if (strcmp(tag, "recur") == 0) {
            *recur = YES;
            return OK;
        }
        //  "skip" is the mirror of "recur" and rides the SAME FILESKIP the
        //  hidden filter uses: prune this entry's subtree, keep the siblings.
        if (strcmp(tag, "skip") == 0) return FILESKIP;
        return OK;  //  "more" and any other string -> continue
    }
    //  Non-string: false -> stop, truthy/undefined -> continue.
    if (!JS_IsUndefined(r) && JS_ToBool(c->ctx, r) == 0) {
        c->stop = YES;
        return JABCSCANSTOP;
    }
    return OK;
}

//  cb-form trampoline: call cb(name), map the directive, descend on "recur".
static ok64 JABCReaddirCall(void0p arg, path8p path) {
    JABCReaddirCtx *c = (JABCReaddirCtx *)arg;
    //  Hidden filter: FILESKIP omits this entry AND, under a native deep scan
    //  (recursive:true), prunes descent into a hidden dir.  In the per-entry
    //  (recursive:false) form the cb never gets a chance to "recur" into it.
    if (!c->hidden && JABCReaddirIsHidden(path)) return FILESKIP;
    a_path(rel);
    ok64 o = JABCReaddirRel(rel, path, c->rootlen);
    if (o == NODATA) return OK;
    if (o != OK) return o;
    JSValue name = JABCStrOfSlice(c->ctx, u8bDataC(rel));
    JSValue r = JS_Call(c->ctx, c->cb, JS_UNDEFINED, 1, (JSValueConst *)&name);
    JS_FreeValue(c->ctx, name);
    if (JS_IsException(r)) {  //  a cb throw aborts the scan and propagates
        c->threw = YES;
        return JABCSCANSTOP;
    }
    JABCDrainJobs();  //  a C->JS re-entry pumps the job queue, like every other
    b8 recur = NO;
    o = JABCReaddirDirective(c, r, &recur);
    JS_FreeValue(c->ctx, r);
    if (o != OK) return o;  //  "enough"/false
    //  "recur" is a no-op once a native deep scan already descends every dir.
    if (recur && !c->recursive) {
        //  Descend via a NESTED FILEScanDir on the subdir.  The cb form decides
        //  recursion per entry, so FILE_SCAN_DEEP (which descends
        //  unconditionally) can't express it — we hand-roll one nested scan on a
        //  FRESH path buffer (the live iterator buffer must not be re-driven
        //  mid-iteration).  rootlen stays the ORIGINAL root, so nested entries
        //  come out relative ("sub/child").
        a_path(sub);
        ok64 d = PATHu8bDup(sub, u8bDataC(path));
        if (d != OK) return d;
        d = FILEScanDir(sub, JABCReaddirCall, c);
        if (d != OK && d != JABCSCANSTOP) return d;
        if (d == JABCSCANSTOP) return d;  //  propagate stop/throw out of the tree
    }
    return OK;
}

//  Read a boolean property off the options object (absent -> false).
static b8 JABCReaddirOptBool(JSContext *ctx, JSValueConst opts,
                             const char *key) {
    JSValue v = JABCGetProp(ctx, opts, key);
    b8 r = JS_ToBool(ctx, v) == 1;
    JS_FreeValue(ctx, v);
    return r;
}

static JABC_FN(JABCioReaddir) {
    if (argc < 1)
        JABC_THROW("io.readdir(path[, fn|{recursive,callback,hidden}])");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK)
        JABC_THROW("io.readdir(): bad path");
    size_t rootlen = (size_t)u8bDataLen(path);

    //  Dispatch the polymorphic 2nd arg into {cb, recursive, hidden}.  `cb` is
    //  an OWNED ref either way, dropped on every exit below.
    JSValue cb = JS_UNDEFINED;
    b8 recursive = NO, hidden = NO;
    if (argc > 1 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        if (!JS_IsObject(argv[1]))
            JABC_THROW("io.readdir(): 2nd arg must be a function or an options "
                       "object");
        if (JS_IsFunction(ctx, argv[1])) {
            cb = JS_DupValue(ctx, argv[1]);  //  bare fn is sugar for {callback}
        } else {
            recursive = JABCReaddirOptBool(ctx, argv[1], "recursive");
            hidden = JABCReaddirOptBool(ctx, argv[1], "hidden");
            JSValue cbv = JABCGetProp(ctx, argv[1], "callback");
            if (JS_IsFunction(ctx, cbv)) cb = cbv;
            else JS_FreeValue(ctx, cbv);
        }
    }

    //  Callback present -> directed scan, returns undefined.  recursive picks
    //  the native deep scan (FILEDeepScanDir, descends every dir) vs the
    //  one-level scan where the cb decides per-entry "recur" nesting.
    if (!JS_IsUndefined(cb)) {
        JABCReaddirCtx c = {ctx,       JS_UNDEFINED, cb, rootlen, 0,
                            recursive, hidden,       NO, NO};
        ok64 o = recursive ? FILEDeepScanDir(path, JABCReaddirCall, &c)
                           : FILEScanDir(path, JABCReaddirCall, &c);
        JS_FreeValue(ctx, cb);
        if (c.threw) JABC_FAIL;
        if (o != OK && o != JABCSCANSTOP) JABC_THROW(strerror(errno));
        JABC_UNDEF;
    }

    //  No callback -> build the flat result array in this binding frame;
    //  recursive uses the native deep scan, otherwise one level.  Dirs stay
    //  marked.
    JSValue arr = JS_NewArray(ctx);
    if (JS_IsException(arr)) JABC_FAIL;
    JABCReaddirCtx c = {ctx,       arr,    JS_UNDEFINED, rootlen, 0,
                        recursive, hidden, NO,           NO};
    ok64 o = recursive ? FILEDeepScanDir(path, JABCReaddirEmit, &c)
                       : FILEScanDir(path, JABCReaddirEmit, &c);
    if (o != OK) {
        JS_FreeValue(ctx, arr);
        JABC_THROW(strerror(errno));
    }
    return arr;
}

//  io._read(fd, u8) -> n  (0 = EOF).  Single read into the typed array.
static JABC_FN(JABCioRead) {
    if (argc < 2) JABC_THROW("io._read(fd, Uint8Array)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    u8 *tab[4] = {};
    if (!JABCIdleOf(tab, ctx, argv[1])) JABC_FAIL;
    ssize_t n;
    do {
        n = read(fd, u8bIdle(tab)[0], u8bIdleLen(tab));
    } while (n < 0 && errno == EINTR);
    if (n < 0) JABC_THROW(strerror(errno));
    return JS_NewFloat64(ctx, (double)n);
}

//  io._write(fd, u8) -> n.  Single write of the typed array's bytes.
static JABC_FN(JABCioWrite) {
    if (argc < 2) JABC_THROW("io._write(fd, Uint8Array)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    u8 *tab[4] = {};
    if (!JABCDataOf(tab, ctx, argv[1])) JABC_FAIL;
    ssize_t n;
    do {
        n = write(fd, u8bData(tab)[0], u8bDataLen(tab));
    } while (n < 0 && errno == EINTR);
    if (n < 0) JABC_THROW(strerror(errno));
    return JS_NewFloat64(ctx, (double)n);
}

//  JAB-033: a live map wrapper pins one VMA (65530 per process) plus, when it is
//  slotted ("rw"/"c"), one booked fd — costs the collector cannot see.
#define JABC_PIN_MAPS 4096  //  live mappings tolerated before a collection
#define JABC_PIN_FDS 256    //  live booked fds tolerated before a collection
static size_t JABC_PIN_MAP;
static size_t JABC_PIN_FD;
static size_t JABC_PIN_MAP_MARK = JABC_PIN_MAPS;
static size_t JABC_PIN_FD_MARK = JABC_PIN_FDS;

//  JAB-033: one take per wrapper handed to JS, one drop per free_func — so a
//  map released early (io._munmap) still counts until its husk is reaped.
static void JABCPinTake(b8 fd) {
    ++JABC_PIN_MAP;
    if (fd) ++JABC_PIN_FD;
}
static void JABCPinDrop(b8 fd) {
    if (JABC_PIN_MAP) --JABC_PIN_MAP;
    if (fd && JABC_PIN_FD) --JABC_PIN_FD;
}

//  JAB-033: price the pins BEFORE mapping, so what the collector reaps serves
//  this very map; the next mark is one floor further up, so it can't run away.
//  JAB-036: qjs refcounts, so a dropped wrapper munmaps on the spot and the
//  JSReportExtraMemoryCost hint has no counterpart — what stays is the forced
//  sweep, for the views a reference cycle still holds past their last use.
static void JABCPinSweep(void) {
    if (JABC_PIN_MAP < JABC_PIN_MAP_MARK && JABC_PIN_FD < JABC_PIN_FD_MARK)
        return;
    //  Above the mark the reap is not asked for, it is taken: bytes can wait,
    //  an fd cannot — there are 1024 of them and running out is a throw.
    JS_RunGC(JABC_RUNTIME);
    JABC_PIN_MAP_MARK = JABC_PIN_MAP + JABC_PIN_MAPS;
    JABC_PIN_FD_MARK = JABC_PIN_FD + JABC_PIN_FDS;
}

//  What a no-copy mapping's free_func needs, heap-owned and handed to the engine
//  as the ArrayBuffer's opaque.  JAB-036: it carries the BASE too, because
//  quickjs's ArrayBuffer.prototype.transfer (which cont.c's abc.close runs)
//  moves the bytes to a husk with a NULL opaque and neuters the original's
//  `data` — so the buffer still holding this record is the owner, and it frees
//  from `base`, never from the `ptr` the engine hands back.
typedef struct {
    u8 *base;
    size_t len;       //  ABC-023 once-map / anon ram: what to munmap
    uintptr_t ident;  //  ABC-020 (gen, fd) for a slotted FILE map
} JABCMapRec;

static JABCMapRec *JABCMapRecOf(u8 *base, size_t len, uintptr_t ident) {
    JABCMapRec *r = (JABCMapRec *)malloc(sizeof(JABCMapRec));
    if (r != NULL) {
        r->base = base;
        r->len = len;
        r->ident = ident;
    }
    return r;
}

//  ABC-020: per-slot map generation packed above the fd's FILE_MAX_OPEN_BITS, so
//  a stale husk never frees a reused slot (ABA).
static uintptr_t JABC_MAP_GEN[FILE_MAX_OPEN];
static uintptr_t JABCMapIdent(int fd) {
    return (++JABC_MAP_GEN[fd] << FILE_MAX_OPEN_BITS) | (uintptr_t)fd;
}

//  Mapped-file free_func: the JS wrapper's death drives the munmap.
static void JABCMapFree(JSRuntime *rt, void *opaque, void *ptr) {
    (void)rt;
    (void)ptr;
    if (opaque == NULL) return;  //  a transferred husk: the original owns this
    JABCMapRec *r = (JABCMapRec *)opaque;
    JABCPinDrop(YES);
    int fd = (int)(r->ident & (uintptr_t)(FILE_MAX_OPEN - 1));
    u8bp buf = FILE_WANT_BUFS ? FILE_WANT_BUFS[fd] : NULL;
    //  ABC-020: unmap only while this husk's generation still owns the slot.
    if (buf && buf[0] == r->base &&
        (r->ident >> FILE_MAX_OPEN_BITS) == JABC_MAP_GEN[fd])
        FILEUnMap(buf);
    free(r);
}

//  ABC-023: a once-map has no fd and no slot; rebuild its 4-pointer record from
//  (base, length) and let FILEUnMapOnce do the one munmap.
static void JABCMapROFree(JSRuntime *rt, void *opaque, void *ptr) {
    (void)rt;
    (void)ptr;
    if (opaque == NULL) return;  //  a transferred husk: the original owns this
    JABCMapRec *r = (JABCMapRec *)opaque;
    JABCPinDrop(NO);
    u8 *b = r->base;
    u8 *rec[4] = {b, b, b, b};
    if (b) {
        rec[2] += r->len;
        rec[3] += r->len;
    }
    FILEUnMapOnce(rec);
    free(r);
}

//  The largest region io._mmap will hand out: 2 GiB minus one byte.  It is also
//  exactly what quickjs will back (an ArrayBuffer past INT32_MAX is a
//  RangeError), and the JS-side Buf `| 0` cursors in [JAB-007] wrap NEGATIVE at
//  2^31 anyway, so `io.mmap` above us would yield a garbled view from there up.
//  It matches the `MMAP_CAP` ingest.js already refuses at.
#define JABC_MAP_MAX (((size_t)1 << 31) - 1)

//  io._mmap(path, "r"|"rw"|"c", size) -> Uint8Array  (munmap when it dies)
static JABC_FN(JABCioMmap) {
    if (argc < 1) JABC_THROW("io._mmap(path, mode, size)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io._mmap(): bad path");
    char mode[8] = "r";
    if (argc > 1) JABCWord(mode, sizeof(mode), ctx, argv[1]);
    u8bp buf = NULL;
    //  ABC-023: "r" maps into the caller's own buffer — no fd, no booked slot.
    u8 *rob[4] = {};
    ok64 o;
    //  JAB-033: reap dead mappings first — their VMAs and fds serve this map.
    JABCPinSweep();
    if (strcmp(mode, "c") == 0) {
        double sz = 0;
        if (argc > 2 && JS_ToFloat64(ctx, &sz, argv[2]) < 0) JABC_FAIL;
        if (sz < 0) JABC_THROW("io._mmap(): negative size");
        o = FILEMapCreate(&buf, $path(path), (size_t)sz);
    } else if (strcmp(mode, "rw") == 0) {
        o = FILEMapRW(&buf, $path(path));
    } else {
        o = FILEMapOnce(rob, $path(path));
    }
    b8 ro = buf == NULL;
    u8bp map = ro ? rob : buf;
    //  ABC-023: a once-map of an EMPTY file is the empty record (base NULL,
    //  length 0) — an OK result, not a failure; only the slotted paths must map.
    if (o != OK || (!ro && map[0] == NULL)) JABC_THROW(strerror(errno));
    //  Expose the WHOLE mapping (DATA + IDLE): a created file has DATA empty and
    //  everything in IDLE, a mapped existing file has it all in DATA — either
    //  way the container owns the full region.
    size_t mlen = u8bDataLen(map) + u8bIdleLen(map);
    //  ABC-023: nothing is mapped for an empty file, and a NULL base has no
    //  buffer to hand out — a plain empty array, no free_func needed.
    if (ro && mlen == 0) return JABCBlob(ctx, (const u8 *)"", 0);
    //  Refuse oversized mappings HERE, in plain words, rather than let the
    //  engine's own INT32_MAX ArrayBuffer ceiling report it as a RangeError.
    if (mlen > JABC_MAP_MAX) {
        ro ? FILEUnMapOnce(map) : FILEUnMap(buf);
        JABC_THROW("io._mmap(): the file is bigger than 2 GiB, "
                   "which is the largest region jab can map at once");
    }
    //  ABC-023: the read-only record carries the length; ABC-020: the slotted one
    //  gets (gen, fd) identity, not the slot pointer.
    JABCMapRec *rec = JABCMapRecOf(u8bData(map)[0], mlen,
                                   ro ? 0 : JABCMapIdent(FILEBookedFD(buf)));
    if (rec == NULL) {
        ro ? FILEUnMapOnce(map) : FILEUnMap(buf);
        JABC_THROW(strerror(errno));
    }
    JSValue ta = JABCBytesNoCopy(ctx, u8bData(map)[0], mlen,
                                 ro ? JABCMapROFree : JABCMapFree, rec);
    if (JS_IsException(ta)) {  //  out of memory: the wrapper never took the map
        ro ? FILEUnMapOnce(map) : FILEUnMap(buf);
        free(rec);
        JABC_FAIL;
    }
    //  JAB-033: the wrapper now owns the mapping (and the slot's fd, if any).
    JABCPinTake(ro ? NO : YES);
    return ta;
}

//  io._munmap(u8) — ABC-020: release NOW (munmap + close(fd) + fd=-1) the FILE
//  mapping whose base is this view's; a no-op for a non-FILE (ram) or already
//  released mapping.  The free_func stays as an idempotent backstop.
//  ABC-023: a read map has no fd and no slot to find — nothing to release here,
//  its pages go back when the wrapper dies, so this stays a silent no-op.
static JABC_FN(JABCioMunmap) {
    if (argc < 1) JABC_THROW("io._munmap(Uint8Array)");
    u8 *tab[4] = {};
    if (!JABCDataOf(tab, ctx, argv[0])) JABC_FAIL;
    FILEUnMapBase(u8bData(tab)[0]);
    JABC_UNDEF;
}

//  Anonymous-mapping free_func: munmap the whole region, free the record.
static void JABCRamFree(JSRuntime *rt, void *opaque, void *ptr) {
    (void)rt;
    (void)ptr;
    if (opaque == NULL) return;  //  a transferred husk: the original owns this
    JABCMapRec *r = (JABCMapRec *)opaque;
    JABCPinDrop(NO);
    munmap(r->base, r->len);
    free(r);
}

//  io._ram(n) -> Uint8Array  (anonymous mmap, faults in lazily, munmap on death)
static JABC_FN(JABCioRam) {
    if (argc < 1) JABC_THROW("io._ram(n)");
    double dn = 0;
    if (JS_ToFloat64(ctx, &dn, argv[0]) < 0) JABC_FAIL;
    if (dn <= 0) JABC_THROW("io._ram(): size must be > 0");
    size_t n = (size_t)dn;
    //  JAB-033: an anon map costs a VMA too — reap the dead ones first.
    JABCPinSweep();
    void *map = mmap(NULL, n, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (map == MAP_FAILED) JABC_THROW(strerror(errno));
    JABCMapRec *rec = JABCMapRecOf((u8 *)map, n, 0);
    if (rec == NULL) {
        munmap(map, n);
        JABC_THROW(strerror(errno));
    }
    JSValue ta = JABCBytesNoCopy(ctx, (u8 *)map, n, JABCRamFree, rec);
    if (JS_IsException(ta)) {
        munmap(map, n);
        free(rec);
        JABC_FAIL;
    }
    JABCPinTake(NO);  //  JAB-033: the wrapper owns the anon mapping now.
    return ta;
}

//  io._msync(u8) -> flush the typed array's pages (works on the raw range, no
//  buffer-descriptor lookup needed).
static JABC_FN(JABCioMsync) {
    if (argc < 1) JABC_THROW("io._msync(Uint8Array)");
    u8 *tab[4] = {};
    if (!JABCDataOf(tab, ctx, argv[0])) JABC_FAIL;
    if (u8bDataLen(tab) && msync(u8bData(tab)[0], u8bDataLen(tab), MS_SYNC) != 0)
        JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io._truncate(path, bytes) -> resize a file on disk (trim a booked/over-
//  allocated output to its live size).  Reopens by path + ftruncate so no
//  persistent fd/descriptor is held — reconstructed per call.
static JABC_FN(JABCioTruncate) {
    if (argc < 2) JABC_THROW("io._truncate(path, bytes)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK)
        JABC_THROW("io._truncate(): bad path");
    double db = 0;
    if (JS_ToFloat64(ctx, &db, argv[1]) < 0) JABC_FAIL;
    if (db < 0) JABC_THROW("io._truncate(): negative size");
    int fd = -1;
    if (FILEOpen(&fd, $path(path), O_RDWR) != OK || fd < 0)
        JABC_THROW(strerror(errno));
    ok64 o = FILEResize(&fd, (size_t)db);
    FILEClose(&fd);
    if (o != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.cwd() -> string  (the process working directory, via getcwd(3)).
static JABC_FN(JABCioCwd) {
    (void)argv;
    (void)argc;
    a_path(cwd);
    if (FILEGetCwd(cwd) != OK) JABC_THROW(strerror(errno));
    return JABCStrOfSlice(ctx, u8bDataC(cwd));
}

//  io.chdir(path) -> set the process working directory (over chdir(2)).  The
//  cwd getter's setter: mirrors io.mkdir's validation + errno propagation, so on
//  success io.cwd() reflects the new dir and on failure (ENOENT/ENOTDIR/EACCES)
//  it throws strerror(errno) with the cwd unchanged.  The pager (BRO-024)
//  chdir's into a repo before running verbs.
static JABC_FN(JABCioChdir) {
    if (argc < 1) JABC_THROW("io.chdir(path)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.chdir(): bad path");
    if (chdir((char const *)*$path(path)) != 0) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.getenv(name) -> string | undefined.  FILEGetEnv yields an empty slice for
//  an unset (or empty-valued) var; either way we return `undefined`.
static JABC_FN(JABCioGetenv) {
    if (argc < 1 || !JS_IsString(argv[0]))
        JABC_THROW("io.getenv(name) -> string|undefined");
    const char *name = JS_ToCString(ctx, argv[0]);
    if (name == NULL) JABC_FAIL;
    u8cs val = {};
    FILEGetEnv(name, val);
    JS_FreeCString(ctx, name);
    if (u8csEmpty(val)) JABC_UNDEF;
    //  JS-108: length-exact — a >PAGESIZE env value is no longer clamped.
    return JABCStrOfSlice(ctx, val);
}

//  io.getpid() -> number  (this process's PID, via getpid(2)).  JOBQ keys the
//  per-process /tmp queue name on it (core/loop.js _pid) so a dead run's queue
//  is never resumed and two concurrent runs never collide.  No /proc, portable.
static JABC_FN(JABCioGetpid) {
    (void)argv;
    (void)argc;
    return JS_NewFloat64(ctx, (double)getpid());
}

//  io.unlink(path) -> remove a name from the filesystem (over FILEUnLink).  Pure
//  marshalling.  (A file mmap'd before unlink stays valid: the inode lives on
//  while mapped, so the page-cache Buf auto-cleans when dropped — see API.md.)
static JABC_FN(JABCioUnlink) {
    if (argc < 1) JABC_THROW("io.unlink(path)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.unlink(): bad path");
    if (FILEUnLink($path(path)) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.rename(old, new) -> atomic rename within a filesystem (over FILERename).
//  Pure marshalling.  The LSM flush path (JS-022) books a run under a temp name,
//  closes it, then renames it into the final run file so readers never see a
//  half-written run.
static JABC_FN(JABCioRename) {
    if (argc < 2) JABC_THROW("io.rename(old, new)");
    a_pad(u8, oldp, FILE_PATH_MAX_LEN);
    a_pad(u8, newp, FILE_PATH_MAX_LEN);
    if (JABCPath(oldp, ctx, argv[0]) != OK ||
        JABCPath(newp, ctx, argv[1]) != OK)
        JABC_THROW("io.rename(): bad path");
    if (FILERename($path(oldp), $path(newp)) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.mkdir(path) -> create a directory (and parents) over FILEMakeDirP.  Pure
//  marshalling; idempotent (an existing dir is fine).  The index (JS-022) calls
//  it to materialise its run directory before booking the first run.
static JABC_FN(JABCioMkdir) {
    if (argc < 1) JABC_THROW("io.mkdir(path)");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.mkdir(): bad path");
    if (FILEMakeDirP($path(path)) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  io.rmdir(path[, recursive]) -> remove a directory (over FILERmDir).  Plain
//  rmdir by default (empty dir only; ENOTEMPTY otherwise); recursive:true does
//  an rm -rf of the whole subtree.  GET-039: checkout calls it (recursive) to
//  replace a tracked DIR with a leaf on a type-change (dir->file / dir->link),
//  which io.unlink cannot do (unlink throws EISDIR on any directory).
static JABC_FN(JABCioRmdir) {
    if (argc < 1) JABC_THROW("io.rmdir(path[, recursive])");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.rmdir(): bad path");
    bool recursive = argc > 1 ? (JS_ToBool(ctx, argv[1]) == 1) : false;
    if (FILERmDir($path(path), recursive) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  . . . . . . . . process spawn + reap (JS-020) . . . . . . . .
//
//  argv is a JS string[] -> a u8css (slice of u8cs) over per-call STACK scratch:
//  each element's UTF-8 bytes land NUL-terminated in `bytes`, and the matching
//  {head, term} pair (term BEFORE the NUL) goes into `slots`.  Mirrors the
//  WIRECLI.c / dog/HOME.c argv idiom.  FILESpawn re-copies argv internally for
//  execv, so the scratch only has to live across the spawn call.  No held JS ref
//  (rule #4); fds + pid cross the boundary as plain numbers.
#define JABC_ARGV_MAX 256      //  argv element cap (stack slot array)
#define JABC_ARGV_BYTES 65536  //  total argv UTF-8 byte cap (stack scratch)

//  Fill `slots`/`bytes`/`*n` from a JS array argument; returns OK or a code.
//  `slots` is a u8cs[JABC_ARGV_MAX]; `bytes` a u8b over JABC_ARGV_BYTES scratch.
static ok64 JABCBuildArgv(u8cs *slots, size_t *n, path8b bytes, JSContext *ctx,
                          JSValueConst arg) {
    if (!JS_IsArray(arg)) return BADARG;
    int64_t len = 0;
    if (JS_GetLength(ctx, arg, &len) < 0) return BADARG;
    if (len < 1) return BADARG;  //  argv[0] (program name) is mandatory
    if (len > JABC_ARGV_MAX) return NOROOM;
    size_t cnt = (size_t)len;
    for (size_t i = 0; i < cnt; i++) {
        JSValue ev = JS_GetPropertyUint32(ctx, arg, (uint32_t)i);
        if (JS_IsException(ev)) return BADARG;
        if (!JS_IsString(ev)) {
            JS_FreeValue(ctx, ev);
            return BADARG;
        }
        size_t got = 0;
        const char *s = JS_ToCStringLen(ctx, &got, ev);
        JS_FreeValue(ctx, ev);
        if (s == NULL) return BADARG;
        //  Copy into the shared scratch buffer's IDLE; record the slice + NUL.
        size_t room = (size_t)u8bIdleLen(bytes);
        if (got + 1 > room) {
            JS_FreeCString(ctx, s);
            return NOROOM;
        }
        u8 *head = u8bIdleHead(bytes);
        memcpy(head, s, got);
        head[got] = '\0';
        JS_FreeCString(ctx, s);
        u8cs slot = {head, head + got};
        u8csMv(slots[i], slot);
        //  Park the copied bytes + NUL in PAST so the next element gets fresh
        //  IDLE.
        u8bFed(bytes, got + 1);
        u8bUsed(bytes, got + 1);
    }
    *n = cnt;
    return OK;
}

//  io.spawn(path, argv) -> {pid, stdin, stdout}.  Creates pipes for the child's
//  stdin (write fd) and stdout (read fd); stderr is INHERITED from the parent.
//  The caller owns + closes both fds and reaps the pid via io.reap.
static JABC_FN(JABCioSpawn) {
    if (argc < 2) JABC_THROW("io.spawn(path, argv) -> {pid, stdin, stdout}");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK) JABC_THROW("io.spawn(): bad path");
    a_pad(u8, bytes, JABC_ARGV_BYTES);
    u8cs slots[JABC_ARGV_MAX];
    size_t nargs = 0;
    if (JABCBuildArgv(slots, &nargs, bytes, ctx, argv[1]) != OK) {
        if (JS_HasException(ctx)) JABC_FAIL;
        JABC_THROW("io.spawn(): argv must be a non-empty string[]");
    }
    u8css spargv = {slots, slots + nargs};
    u8csc binpath = {$path(path)[0], $path(path)[1]};
    int wfd = -1, rfd = -1;
    pid_t pid = 0;
    if (FILESpawn(binpath, spargv, &wfd, &rfd, &pid) != OK)
        JABC_THROW(strerror(errno));
    JSValue obj = JS_NewObject(ctx);
    if (JS_IsException(obj)) JABC_FAIL;
    JABCSetProp(ctx, obj, "pid", JS_NewFloat64(ctx, (double)pid));
    JABCSetProp(ctx, obj, "stdin", JS_NewFloat64(ctx, (double)wfd));
    JABCSetProp(ctx, obj, "stdout", JS_NewFloat64(ctx, (double)rfd));
    return obj;
}

//  io.spawnFds(path, argv, inFd, outFd) -> pid.  The child dups the supplied fds
//  (`-1` inherits the parent's); the caller still owns + closes them.
static JABC_FN(JABCioSpawnFds) {
    if (argc < 2) JABC_THROW("io.spawnFds(path, argv, inFd, outFd) -> pid");
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    if (JABCPath(path, ctx, argv[0]) != OK)
        JABC_THROW("io.spawnFds(): bad path");
    a_pad(u8, bytes, JABC_ARGV_BYTES);
    u8cs slots[JABC_ARGV_MAX];
    size_t nargs = 0;
    if (JABCBuildArgv(slots, &nargs, bytes, ctx, argv[1]) != OK) {
        if (JS_HasException(ctx)) JABC_FAIL;
        JABC_THROW("io.spawnFds(): argv must be a non-empty string[]");
    }
    u8css spargv = {slots, slots + nargs};
    int inFd = -1, outFd = -1;
    if (argc > 2 && !JABCInt(&inFd, ctx, argv[2])) JABC_FAIL;
    if (argc > 3 && !JABCInt(&outFd, ctx, argv[3])) JABC_FAIL;
    u8csc binpath = {$path(path)[0], $path(path)[1]};
    pid_t pid = 0;
    if (FILESpawnFds(binpath, spargv, inFd, outFd, &pid) != OK)
        JABC_THROW(strerror(errno));
    return JS_NewFloat64(ctx, (double)pid);
}

//  io.reap(pid) -> {code} on a clean exit (any status), {signal} on a signal
//  death (FILESIGNAL).  Exactly one key is set.  Any other non-OK throws.
static JABC_FN(JABCioReap) {
    if (argc < 1) JABC_THROW("io.reap(pid) -> {code}|{signal}");
    int pid = -1;
    if (!JABCInt(&pid, ctx, argv[0])) JABC_FAIL;
    int rc = -1;
    ok64 o = FILEReap((pid_t)pid, &rc);
    if (o != OK && o != FILESIGNAL) JABC_THROW(strerror(errno));
    JSValue obj = JS_NewObject(ctx);
    if (JS_IsException(obj)) JABC_FAIL;
    JABCSetProp(ctx, obj, o == FILESIGNAL ? "signal" : "code",
                JS_NewFloat64(ctx, (double)rc));
    return obj;
}

//  io.isatty(fd) -> bool  (is the fd a terminal? — the color-vs-plain gate)
static JABC_FN(JABCioIsatty) {
    if (argc < 1) JABC_THROW("io.isatty(fd)");
    int fd = -1;
    if (!JABCInt(&fd, ctx, argv[0])) JABC_FAIL;
    return JS_NewBool(ctx, isatty(fd) == 1);
}

//  io.log(...args) -> write strings / typed arrays to stderr + newline.
static JABC_FN(JABCioLog) {
    for (int i = 0; i < argc; i++) {
        if (JS_IsString(argv[i])) {
            size_t got = 0;
            const char *b = JS_ToCStringLen(ctx, &got, argv[i]);
            if (b == NULL) JABC_FAIL;
            u8s span = {(u8 *)b, (u8 *)b + got};
            while ($len(span) > 0) {
                ssize_t w = write(STDERR_FILENO, span[0], $len(span));
                if (w <= 0) break;
                span[0] += w;
            }
            JS_FreeCString(ctx, b);
        } else if (JS_GetTypedArrayType(argv[i]) >= 0) {
            u8 *tab[4] = {};
            if (!JABCDataOf(tab, ctx, argv[i])) JABC_FAIL;
            ssize_t w = write(STDERR_FILENO, u8bData(tab)[0], u8bDataLen(tab));
            (void)w;
        }
    }
    ssize_t w = write(STDERR_FILENO, "\n", 1);
    (void)w;
    JABC_UNDEF;
}

ok64 JABCInstallIo(JSContext *ctx, JSValueConst global) {
    FILEInit();
    JABC_API_OBJECT(io);
    JABC_API_FN(io, "open", JABCioOpen);
    JABC_API_FN(io, "close", JABCioClose);
    JABC_API_FN(io, "sync", JABCioSync);
    JABC_API_FN(io, "size", JABCioSize);
    JABC_API_FN(io, "resize", JABCioResize);
    JABC_API_FN(io, "lock", JABCioLock);
    JABC_API_FN(io, "unlock", JABCioUnlock);
    JABC_API_FN(io, "stat", JABCioStat);
    JABC_API_FN(io, "lstat", JABCioLStat);
    JABC_API_FN(io, "readlink", JABCioReadLink);
    JABC_API_FN(io, "realpath", JABCioRealPath);
    JABC_API_FN(io, "symlink", JABCioSymLink);
    JABC_API_FN(io, "chmod", JABCioChmod);
    JABC_API_FN(io, "setMtime", JABCioSetMtime);
    JABC_API_FN(io, "readdir", JABCioReaddir);
    JABC_API_FN(io, "_read", JABCioRead);
    JABC_API_FN(io, "_write", JABCioWrite);
    JABC_API_FN(io, "_mmap", JABCioMmap);
    JABC_API_FN(io, "_munmap", JABCioMunmap);
    JABC_API_FN(io, "_ram", JABCioRam);
    JABC_API_FN(io, "_msync", JABCioMsync);
    JABC_API_FN(io, "_truncate", JABCioTruncate);
    JABC_API_FN(io, "unlink", JABCioUnlink);
    JABC_API_FN(io, "rename", JABCioRename);
    JABC_API_FN(io, "mkdir", JABCioMkdir);
    JABC_API_FN(io, "rmdir", JABCioRmdir);
    JABC_API_FN(io, "spawn", JABCioSpawn);
    JABC_API_FN(io, "spawnFds", JABCioSpawnFds);
    JABC_API_FN(io, "reap", JABCioReap);
    JABC_API_FN(io, "isatty", JABCioIsatty);
    JABC_API_FN(io, "cwd", JABCioCwd);
    JABC_API_FN(io, "chdir", JABCioChdir);
    JABC_API_FN(io, "getpid", JABCioGetpid);
    JABC_API_FN(io, "getenv", JABCioGetenv);
    JABC_API_FN(io, "log", JABCioLog);
    JABC_API_END(io);
    return OK;
}

//  Close what the JS side no longer owns; runs AFTER the context is gone, so
//  the no-copy free_funcs (munmap) have already fired.
ok64 JABCUninstallIo(void) {
    FILECloseAll();
    return OK;
}
