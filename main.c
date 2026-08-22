#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>  // _NSGetExecutablePath, for process.execPath
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>  // KERN_PROC_PATHNAME, for process.execPath
#endif

#include "JABC.h"
#ifdef QJAB_RPMALLOC
#include "rpmalloc.h"
#endif
#include "abc/PRO.h"
#include "dog/VERSN.h"  // process.version / .build / .build_date

JSRuntime *JABC_RUNTIME;
JSContext *JABC_CONTEXT;
JSValue JABC_GLOBAL;

//  PRO.h globals (one definition for the whole binary).
u8 _pro_depth = 0;
thread_local u8 *ABC_BASS[4] = {};

#ifdef QJAB_RPMALLOC
//  JS-122: ONLY the JS runtime rides rpmalloc (JSMallocFunctions); io/libdog
//  /abc keep musl malloc.  -DQJAB_RPMALLOC=OFF gives the plain-musl leg.
static void *rp_js_calloc(void *opq, size_t n, size_t sz) { return rpcalloc(n, sz); }
static void *rp_js_malloc(void *opq, size_t sz) { return rpmalloc(sz); }
static void rp_js_free(void *opq, void *p) { rpfree(p); }
static void *rp_js_realloc(void *opq, void *p, size_t sz) { return rprealloc(p, sz); }
static size_t rp_js_musable(const void *p) { return rpmalloc_usable_size((void *)p); }
static const JSMallocFunctions RP_MF = {
    rp_js_calloc, rp_js_malloc, rp_js_free, rp_js_realloc, rp_js_musable,
};
#endif

static void JSInit(void) {
#ifdef QJAB_RPMALLOC
    rpmalloc_initialize();
    JABC_RUNTIME = JS_NewRuntime2(&RP_MF, NULL);
#else
    JABC_RUNTIME = JS_NewRuntime();
#endif
    JABC_CONTEXT = JS_NewContext(JABC_RUNTIME);
    JABC_GLOBAL = JS_GetGlobalObject(JABC_CONTEXT);
}

//  Free everything the engine owns, so the leak check can run for real
//  (JAB-036: qjs refcounts, there are no VM singletons to suppress).
static void JSClose(void) {
    JS_FreeValue(JABC_CONTEXT, JABC_GLOBAL);
    JABC_GLOBAL = JS_UNDEFINED;
    JS_FreeContext(JABC_CONTEXT);
    JS_FreeRuntime(JABC_RUNTIME);
    JABC_CONTEXT = NULL;
    JABC_RUNTIME = NULL;
}

//  JAB-036: quickjs queues Promise jobs and nothing pumps them — every JS
//  re-entry drains the queue before returning to C.
void JABCDrainJobs(void) {
    for (;;) {
        JSContext *c = NULL;
        int n = JS_ExecutePendingJob(JABC_RUNTIME, &c);
        if (n <= 0) {
            if (n < 0 && c != NULL) {
                JSValue e = JS_GetException(c);
                JABCReport(e);
                JS_FreeValue(c, e);
            }
            return;
        }
    }
}

//  Report an uncaught JS exception to stderr as `String(value)` — for an
//  Error that is `"<name>: <message>"`.  A debug build appends `.stack`.
void JABCReport(JSValueConst exception) {
    const char *s = JS_ToCString(JABC_CONTEXT, exception);
    if (s == NULL) {  //  value's toString itself threw — nothing printable
        JS_FreeValue(JABC_CONTEXT, JS_GetException(JABC_CONTEXT));
        fprintf(stderr, "JS exception: <unprintable>\n");
        return;
    }
    fprintf(stderr, "JS exception: %s\n", s);
    JS_FreeCString(JABC_CONTEXT, s);
#ifndef NDEBUG
    if (JS_IsObject(exception)) {
        JSValue st = JS_GetPropertyStr(JABC_CONTEXT, exception, "stack");
        if (!JS_IsUndefined(st) && !JS_IsException(st)) {
            const char *t = JS_ToCString(JABC_CONTEXT, st);
            if (t != NULL) {
                fprintf(stderr, "%s\n", t);
                JS_FreeCString(JABC_CONTEXT, t);
            }
        }
        JS_FreeValue(JABC_CONTEXT, st);
    }
#endif
}

//  Evaluate `script` in GLOBAL scope (var/function declarations land on the
//  global object, as jab's `(0,eval)` wrapper does).  Reports a thrown value
//  and answers whether the run succeeded, so a failing script sets the
//  process exit code (CTest).
static b8 JABCEval(const char *script, const char *name) {
    JSValue r = JS_Eval(JABC_CONTEXT, script, strlen(script), name,
                        JS_EVAL_TYPE_GLOBAL);
    b8 ok = YES;
    if (JS_IsException(r)) {
        JSValue e = JS_GetException(JABC_CONTEXT);
        JABCReport(e);
        JS_FreeValue(JABC_CONTEXT, e);
        ok = NO;
    }
    JS_FreeValue(JABC_CONTEXT, r);
    JABCDrainJobs();
    return ok;
}

//  An embedded JS bundle (buf/console/ansi/require): errors are reported, the
//  install carries on — a bundle that fails to load is a build bug, not input.
void JABCExecute(const char *script) { JABCEval(script, "<bundle>"); }

static b8 JABCRun(const char *script) { return JABCEval(script, "<eval>"); }

//  Read a script file and run it; NO on any open/size/OOM/exception failure.
//  The read lives in a worker (not inline in main) so every failure returns
//  to main's shared teardown instead of a bare `return` that would leak the
//  whole JS context (JS-054; cf. the wrapper/worker idiom, CLAUDE.md §5).
static b8 JABCRunFile(const char *script_file) {
    FILE *f = fopen(script_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open %s\n", script_file);
        return NO;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0) {
        fprintf(stderr, "Error: cannot size %s\n", script_file);
        fclose(f);
        return NO;
    }
    rewind(f);
    char *script = (char *)malloc((size_t)len + 1);
    if (!script) {
        fprintf(stderr, "Error: out of memory reading %s\n", script_file);
        fclose(f);
        return NO;
    }
    size_t got = fread(script, 1, (size_t)len, f);
    fclose(f);
    script[got] = '\0';
    b8 ok = JABCEval(script, script_file);
    free(script);
    return ok;
}

//  jab's install order, to the line.  cont installs the `abc` object the
//  container bindings below it attach to, so they follow it.
static void JABCInstallModules(void) {
    JSContext *ctx = JABC_CONTEXT;
    JSValueConst global = JABC_GLOBAL;
    JABCInstallUtf8(ctx, global);
    JABCInstallIo(ctx, global);
    JABCInstallBuf(ctx, global);      //  Buf class over utf8/io leaves
    JABCInstallConsole(ctx, global);  //  console.* over utf8.Encode + io.writeAll
    JABCInstallCont(ctx, global);     //  abc.* containers over io mmap leaves
    JABCInstallHeap(ctx, global);
    JABCInstallHash(ctx, global);
    JABCInstallHit(ctx, global);
    JABCInstallIndex(ctx, global);
    JABCInstallPup(ctx, global);
    JABCInstallHunk(ctx, global);
    JABCInstallPack(ctx, global);
    JABCInstallGit(ctx, global);   //  GIT-030: git.open/getHex/getSafe/close
    JABCInstallUlog(ctx, global);
    JABCInstallCfold(ctx, global);
    JABCInstallWeave(ctx, global);
    JABCInstallTok(ctx, global);   //  tok.parse + TokStream over dog/tok (JS-023)
    JABCInstallUri(ctx, global);   //  URI class over abc/URI
    JABCInstallCodec(ctx, global); //  hex + sha1/sha256 + ron
    JABCInstallZip(ctx, global);   //  zip.deflate/inflate over dog/git/ZINF
    JABCInstallIgno(ctx, global);  //  dog._igno_* over dog/git/IGNO (STATUS-020)
    JABCInstallDirc(ctx, global);  //  dog.readIndex over dog/git/DIRC (GIT-032)
    JABCInstallAnsi(ctx, global);  //  ansi colour helper (pure JS)
    JABCInstallTty(ctx, global);   //  tty.raw/cook/size over abc/FILE (JS-053)
    JABCInstallPol(ctx, global);   //  poll() event loop over abc/POL
    JABCInstallNet(ctx, global);   //  net/dgram + Node timers over pol
    JABCInstallHttp(ctx, global);  //  QJAB-004: http._drain/_feed over abc/HTTP
    JABCInstallFsw(ctx, global);   //  fsw dir watcher over abc/FSW (JAB-031)
    JABCInstallJsrcPack(ctx, global);  //  JAB-035: the embedded jsrc pack
    JABCInstallRequire(ctx, global);   //  sync CommonJS require() (last)
}

#define VERSION_BOILERPLATE "jab v0.1.0\n"

//  Set `name` on the global object to `val` (CONSUMES val).
static void JABCSetGlobal(const char *name, JSValue val) {
    JS_SetPropertyStr(JABC_CONTEXT, JABC_GLOBAL, name, val);
}

//  Build a JS string array from argv[from, argc) and return it.  `head` (e.g.
//  "jab", script path) is prepended when non-NULL — used to shape Node's
//  process.argv = ["jab", script, ...tail].
static JSValue JABCArgvArray(int argc, char **argv, int from, const char *head0,
                             const char *head1) {
    JSValue arr = JS_NewArray(JABC_CONTEXT);
    uint32_t at = 0;
    if (head0 != NULL)
        JS_DefinePropertyValueUint32(JABC_CONTEXT, arr, at++,
                                     JSOfCString(head0), JS_PROP_C_W_E);
    if (head1 != NULL)
        JS_DefinePropertyValueUint32(JABC_CONTEXT, arr, at++,
                                     JSOfCString(head1), JS_PROP_C_W_E);
    for (int i = from; i < argc; i++)
        JS_DefinePropertyValueUint32(JABC_CONTEXT, arr, at++,
                                     JSOfCString(argv[i]), JS_PROP_C_W_E);
    return arr;
}

//  Set a read-only build-metadata string `key` on `proc` from a dog/VERSN
//  slice.  JAB-036: the attribute INVERSION — JSC's ReadOnly|DontDelete is
//  quickjs's "neither writable nor configurable", i.e. enumerable only.
static void JABCProcVersn(JSValueConst proc, const char *key,
                          u8 const *const *v) {
    JS_DefinePropertyValueStr(JABC_CONTEXT, proc, key,
                              JSOfCString((const char *)v[0]),
                              JS_PROP_ENUMERABLE);
}

//  The absolute path of THIS binary, Node's process.execPath: /proc/self/exe on
//  Linux, _NSGetExecutablePath on macOS, sysctl(KERN_PROC_PATHNAME) on FreeBSD
//  (its /proc is optional), realpath(argv[0]) as the last resort
//  (`process.argv[0]` is the literal "jab", so scripts cannot derive it).
//  Returns JS_UNDEFINED when nothing answers.
static JSValue JABCExecPath(const char *argv0) {
    char buf[PATH_MAX];
#ifdef __APPLE__
    char raw[PATH_MAX];
    uint32_t len = sizeof(raw);
    if (_NSGetExecutablePath(raw, &len) == 0 && realpath(raw, buf) != NULL)
        return JSOfCString(buf);
#elif defined(__FreeBSD__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    size_t len = sizeof(buf);
    if (sysctl(mib, 4, buf, &len, NULL, 0) == 0 && len > 1)
        return JSOfCString(buf);
#else
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        return JSOfCString(buf);
    }
#endif
    if (argv0 != NULL && realpath(argv0, buf) != NULL) return JSOfCString(buf);
    return JS_UNDEFINED;
}

//  Expose the script's argv tail to JS: global `args` (tokens after the script
//  path) plus a Node-ish `process = { argv: ["jab", script, ...tail] }`.
//  `tail` is the index of the first token after the script path (== argc when
//  there is none, e.g. under --eval), so `args` is empty in that case.  The
//  same `process` carries the build stamp: `version` / `build` / `build_date`.
static void JABCInstallArgv(int argc, char **argv, int tail,
                            const char *script_file) {
    JABCSetGlobal("args", JABCArgvArray(argc, argv, tail, NULL, NULL));
    JSValue proc = JS_NewObject(JABC_CONTEXT);
    JS_SetPropertyStr(JABC_CONTEXT, proc, "argv",
                      JABCArgvArray(argc, argv, tail, "jab", script_file));
    JSValue exe = JABCExecPath(argc > 0 ? argv[0] : NULL);
    if (!JS_IsUndefined(exe)) JS_SetPropertyStr(JABC_CONTEXT, proc, "execPath", exe);
    JABCProcVersn(proc, "version", VERSNVersion);
    JABCProcVersn(proc, "build", VERSNHash);
    JABCProcVersn(proc, "build_date", VERSNDate);
    JABCSetGlobal("process", proc);
}

//  YES iff `s` ends in the literal ".js" — the script-vs-main entry switch: a
//  `.js` first arg is a SCRIPT, anything else routes to jsrc/main.js (the loop).
static b8 JABCEndsWithJs(const char *s) {
    size_t n = strlen(s);
    return n >= 3 && strcmp(s + n - 3, ".js") == 0;
}

//  YES iff `s` opens with a URI scheme (`<alpha><alnum|+|-|.>*:`) BEFORE any
//  '/': a `scheme:` token (e.g. `diff:view/bro.js`) is a VIEW URI for the loop,
//  never a script file — even when its path tail ends in `.js`.  A bare/relative
//  path (`foo.js`, `./x.js`, `dir/x.js`) has no scheme.  Guards the `.js`-suffix
//  script route below so `jab diff:<file>.js` reaches the loop, not require().
static b8 JABCHasScheme(const char *s) {
    if (s == NULL ||
        !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')))
        return 0;
    for (const char *p = s + 1; *p; p++) {
        char c = *p;
        if (c == ':') return 1;
        if (c == '/') return 0;  // a path slash before any ':' — not a scheme
        b8 ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
        if (!ok) return 0;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (u8bMap(ABC_BASS, ABC_BASS_BYTES) != OK) {
        fprintf(stderr, "ABC_BASS u8bMap failed\n");
        return 1;
    }

    char *eval_code = NULL;
    char *script_file = NULL;
    //  QJAB-001: a build carrying a jsrc bundle has NO script route — its
    //  main.js is the entry, so the first positional is an ARG, not a script.
    b8 packed = JABCJsrcPacked();
    //  Index of the first token after the script path (the argv "tail" exposed
    //  to JS as `args`).  Stays at argc when there is no script file.
    int tail = argc;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            fprintf(stderr, VERSION_BOILERPLATE);
            return 0;
        } else if (strcmp(argv[i], "--eval") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --eval requires a code argument\n");
                return 1;
            }
            eval_code = argv[++i];
        } else {
            //  QJAB-001: packed — the word stays IN the tail (no script path to
            //  splice), so main.js sees every CLI word at process.argv[2:].
            tail = packed ? i : i + 1;
            if (!packed) script_file = argv[i];
            break;
        }
    }

    JSInit();
    JABCInstallModules();
    //  Argv tail reaches JS as `args` + Node-ish `process.argv` (JS-015).
    JABCInstallArgv(argc, argv, tail, script_file);

    int rc = 0;
    if (eval_code != NULL && !JABCRun(eval_code)) rc = 1;

    //  QJAB-002: the first positional decides the entry shape.  A `.js` first arg
    //  is THE SCRIPT (mode 2) — a path off the cwd, run directly via global eval,
    //  with its OWN dir pinned as the one require base; no jsrc/ is consulted.
    //  ANYTHING else — a verb, a `scheme:` URI, a non-.js path, or no arg at all
    //  — routes to main.js (`__main`) with the user's tokens passed through as-is
    //  at argv[2:].  QJAB-001: a PACKED build never takes this branch
    //  (script_file is NULL) — the bundle's main.js runs.
    if (rc == 0) {
        if (script_file != NULL && JABCEndsWithJs(script_file) &&
            !JABCHasScheme(script_file)) {
            JABCSetGlobal("__mainSpec", JSOfCString(script_file));
            if (!JABCRun("__pinScript(__mainSpec)") || !JABCRunFile(script_file))
                rc = 1;
        } else if (eval_code == NULL) {
            //  verb / scheme:URI / non-.js path / bare `jab` → the loop.
            if (!JABCRun("__main()")) rc = 1;
        }
    }

    //  Node-like: once the top-level script returns, drive the event loop until
    //  no fds/timers remain.  pol.run on an already-drained queue is an instant
    //  no-op.  JAB-036 skeleton: the `typeof` guard keeps a stub build (no pol
    //  module yet) from failing every run; it is a no-op once pol.c lands.
    if (rc == 0 && !JABCRun("typeof pol === 'object' && pol.run(pol.NEVER)"))
        rc = 1;

    //  Drop the protected pol router refs + free the poll heap while the
    //  context is still alive (they are JS values).
    JABCUninstallPol(JABC_CONTEXT);
    //  QJAB-006: same shape — pup owns an ArrayBuffer per live run view.
    JABCUninstallPup(JABC_CONTEXT);
    //  Release the context first so the no-copy free_funcs (FILEUnMap/munmap)
    //  run while the FILE subsystem is still alive; then tear it down
    //  (FILECloseAll frees FILE_RW).
    JSClose();
    JABCUninstallIo();
    JABCUninstallIgno();
    u8bUnMap(ABC_BASS);
    return rc;
}
