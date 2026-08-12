# quickjab — the module contract (JAB-036)

Plain-C port of the jab runtime from JavaScriptCore to quickjs-ng.  The engine
is a pinned vendored snapshot in `qjs/`; `dog`+`abc` come from `../jab/dog`.
**`../jab/` is READ-ONLY** — its sources, tests and `lsan.supp` are referenced
in place, never edited.

## File ownership

| file | owner | ports from |
|---|---|---|
| `CMakeLists.txt`, `JABC.h`, `main.c`, `arg.c`, `utf8.c` | W1 (done) | jab `CMakeLists.txt`, `JABC.hpp`, `main.cpp`, `arg.cpp`, `utf8.cpp` |
| `io.c buf.c console.c ansi.c require.c codec.c zip.c uri.c tty.c pol.c net.c fsw.c jsrcpack.c tok.c` | one worker each | the jab `.cpp` of the same name |
| `cont.c` | one worker | jab `cont.cpp` + `cont.hpp` |
| `heap.c hash.c hit.c index.c pup.c hunk.c pack.c ulog.c cfold.c weave.c` | one worker each | the jab `.hpp` of the same name (dog bindings) |

A worker touches **its own `.c` only**.  `CMakeLists.txt`, `JABC.h` and
`main.c` are complete and stable — every module is already listed, declared and
called.  Need something shared that is missing?  Report it; do not add it
locally and do not edit those three.

Each module exposes exactly one entry:

```c
ok64 JABCInstallXxx(JSContext *ctx, JSValueConst global);
```

plus, for two of them, the teardown twin `JABCUninstallPol(JSContext *ctx)`
(runs while the context is alive) and `JABCUninstallIo(void)` (runs after it is
gone).  `main.c` calls the installs in jab's order.  `cont.c` OWNS the global
`abc` object; the ten container bindings attach to it with `JABC_API_GET(abc)`,
so they run after it.  `weave.hpp` has no consumer in jab today — `weave.c` is
listed and installed anyway.

## Funnel cheat-sheet: JSC -> quickjs

| jab (JSC) | quickjab (qjs) |
|---|---|
| `JABC_FN(f)` with `args[]`, `*exception` | `JABC_FN(f)` with `argv[]`, no out-param |
| `JABC_UNDEF` | `JABC_UNDEF` (`return JS_UNDEFINED`) |
| gate failed: `if (!JABCu64Of(...,exception)) JABC_UNDEF;` | `if (!JABCu64Of(&v, ctx, argv[0])) JABC_FAIL;` |
| `JABC_THROW("msg")` (Error) | same — `String(e)` still reads `"Error: msg"` |
| `*ex = JSOfCString("msg")` (bare string) | `JABCThrowStr(ctx, "msg")` — the PTR-010 gates only |
| `JSValueMakeNumber` / `Undefined` / `Null` | `JS_NewFloat64` / `JS_UNDEFINED` / `JS_NULL` |
| `JSValueIsString/Object/Number` | `JS_IsString/JS_IsObject/JS_IsNumber` |
| `JSStringCreateWithUTF8CString` + `JSValueMakeString` | `JS_NewString` / `JSOfCString` |
| `JABCStrOfSlice` (UTF-16 transcode) | `JABCStrOfSlice` = `JS_NewStringLen` (JS-108 collapses: qjs is byte-oriented, bad byte -> U+FFFD, resync +1 — verified) |
| `JSStringGetUTF8CString` into a page | `JS_ToCStringLen` + `JS_FreeCString` (or `JABCPath` for paths) |
| `JSBigIntCreateWithUInt64` / `JSValueToUInt64` | `JABCBigU64` / `JABCBigU64Of` (takes Number AND BigInt) |
| `JSObjectGetProperty` / `SetProperty` | `JABCGetProp` (returns an OWNED value) / `JABCSetProp` (CONSUMES it) |
| `kJSPropertyAttributeReadOnly\|DontDelete` | INVERSION: `JS_DefinePropertyValueStr(..., JS_PROP_ENUMERABLE)` |
| `JSObjectMakeArray` | `JS_NewArray` + `JS_DefinePropertyValueUint32`, or `JABCPair` |
| `JSObjectMakeTypedArray` (copy) | `JABCBlob(ctx, data, n)` |
| `...WithBytesNoCopy(ptr,len,dealloc,ctx)` | `JABCBytesNoCopy(ctx, p, n, free_func, opaque)` — `free_func` replaces the deallocator 1:1, NULL for rodata |
| `GetTypedArrayBuffer` + `WithArrayBufferAndOffset` | `JABCSubView(ctx, view, off, len)` |
| `JSObjectCallAsFunction` | `JS_Call` |
| `JSEvaluateScript` | `JS_Eval(..., JS_EVAL_TYPE_GLOBAL)`; bundles: `JABCExecute` |
| `JSValueProtect` / `Unprotect` | `JS_DupValue` / `JS_FreeValue` |
| `JSReportExtraMemoryCost`, `JSSynchronousGarbageCollectForDebugging` | GONE — refcounting makes wrapper death deterministic; force a sweep with `JS_RunGC(JABC_RUNTIME)` |

Unchanged and already available: the PTR-010 gates (`JABCu64Of`, `JABCi64Of`,
`JABCu32Of`, `JABCu8Of`, `JABCDataOf`, `JABCIdleOf`, `JABCViewOf`, `JABCOffOf`,
`JABCBufAt`, `JABCBufFed`, `JABCBufOf`, `JABCBufBack`, `JABCPath`), the
`JABC_API_OBJECT` / `JABC_API_FN` / `JABC_API_GET` / `JABC_API_END`
registration macros and the JAB-008 BASS bracket (every `JABC_API_FN` leaf runs
through it; no per-leaf wrapper to write).

**THE two rules the JSC leg never had:**

1. **Ownership.**  Every `JSValue` you get from a `JS_New*` / `JS_Get*` /
   `JS_Call` is a REFERENCE you own — `JS_FreeValue(ctx, v)` on every path.
   `argv[i]` and `this_val` are borrowed: never free them, `JS_DupValue` to
   keep one.  Setters (`JS_SetPropertyStr`, `JABCSetProp`, `JABCPair`,
   `JS_DefinePropertyValue*`) CONSUME the value you pass.
2. **Exceptions.**  There is no `*exception`.  A failing call returns
   `JS_EXCEPTION` (or `-1`/`NULL`) with the error pending on the context; hand
   it back with `JABC_FAIL`, and free your temps first.

Promise jobs: `main.c` drains the queue (`JABCDrainJobs`) after every JS entry.
A module that re-enters JS from C (pol/net/fsw trampolines, the io readdir
callback) calls it too.

## Build and test

```sh
cmake -G Ninja -S /home/gritzko/src/journal/quickjab -B ~/tmp/qjab-build
ninja -C ~/tmp/qjab-build
~/tmp/qjab-build/bin/quickjab --eval "io.log('hi')"
ctest --test-dir ~/tmp/qjab-build -R JABC --output-on-failure
```

Never build inside `quickjab/`.  `ctest -R JABC` is jab's own suite, run
against `../jab/test/*.js` UNCHANGED — those files are read-only, a red test is
a port bug.  `ctest` without `-R` also runs dog's and abc's own suites.
`-DJAB_JSRC=<dir> -DQUICKJAB_JSRC_PACK=ON` embeds a default jsrc pack; it needs
a working `io`+`require` first, so it stays OFF.
