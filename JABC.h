#ifndef QUICKJAB_JABC_H
#define QUICKJAB_JABC_H
//  JAB-036: THE C funnel — jab's JABC.hpp dialect ported to quickjs-ng.
//  Model gap absorbed here: JSValues are refcounted (every temp is freed) and
//  an error is the JS_EXCEPTION sentinel plus a pending exception on the
//  context — there is no *exception out-param, so the leaves drop it.
#include <stdlib.h>
#include <string.h>

#include "abc/ABC.h"
#include "quickjs.h"

//  The one runtime / context / global object, owned by main.c.  A module
//  never frees JABC_GLOBAL; installs get the same value as an argument.
extern JSRuntime *JABC_RUNTIME;
extern JSContext *JABC_CONTEXT;
extern JSValue JABC_GLOBAL;

//  JAB-008: PRO.h's ABC_BASS (§6 keeps PRO.h out of headers), declared as
//  PRO.h declares it so a TU may include both.
extern thread_local u8 *ABC_BASS[4];

//  A native binding function.  Its return value IS the JS result; on error it
//  throws on `ctx` and returns JS_EXCEPTION (JABC_THROW / JABC_FAIL).
#define JABC_FN(fn) \
    JSValue fn(JSContext *ctx, JSValueConst this_val, int argc, \
               JSValueConst *argv)

#define JABC_UNDEF return JS_UNDEFINED
//  A gate (JABCu64Of etc.) already threw: hand the sentinel back.
#define JABC_FAIL return JS_EXCEPTION
//  Throw a JS Error with `msg` — jab's JSObjectMakeError, so String(e) reads
//  "Error: <msg>" exactly as on the JSC leg.
#define JABC_THROW(msg) return JABCThrowError(ctx, msg)

//  Register a fresh API object `o` as a global of the same name.  `o` stays a
//  live local ref for the JABC_API_FN calls; JABC_API_END drops it.
#define JABC_API_OBJECT(o)                                       \
    JSValue o = JS_NewObject(ctx);                               \
    JS_SetPropertyStr(ctx, global, #o, JS_DupValue(ctx, o))

//  The container bindings hang off the `abc` object cont.c installed first.
#define JABC_API_GET(o) JSValue o = JS_GetPropertyStr(ctx, global, #o)

#define JABC_API_END(o) JS_FreeValue(ctx, o)

//  Attach native function `f` as method `n` of object `o`.  JAB-008: every
//  leaf is registered through the BASS bracket (JABCApiFn's trampoline).
#define JABC_API_FN(o, n, f) JABCApiFn(ctx, o, n, f)

//  --- errors --------------------------------------------------------------

//  A plain Error (JABC_THROW) and a bare string (the PTR-010 gates throw the
//  message value itself, as arg.cpp does).  Both return JS_EXCEPTION.
JSValue JABCThrowError(JSContext *ctx, const char *msg);
JSValue JABCThrowStr(JSContext *ctx, const char *msg);

//  --- registration --------------------------------------------------------

void JABCApiFn(JSContext *ctx, JSValueConst o, const char *name,
               JSCFunction *f);

//  --- values --------------------------------------------------------------

//  Make a JS string value from a C string (error text / small keys).
JSValue JSOfCString(const char *str);
//  JS-108 collapses under quickjs: the engine is byte-oriented, so a u8 slice
//  is a length-explicit JS_NewStringLen (embedded NULs survive, a bad byte
//  becomes U+FFFD and resyncs by one — jab's policy to the byte).
JSValue JABCStrOfSlice(JSContext *ctx, u8cs s);
//  The u64 <-> BigInt pair; JABCBigU64Of takes a Number OR a BigInt, as
//  JSValueToUInt64 did.
JSValue JABCBigU64(JSContext *ctx, u64 v);
b8 JABCBigU64Of(u64 *out, JSContext *ctx, JSValueConst arg);
//  A two-element JS array (key,val pairs); CONSUMES a and b.
JSValue JABCPair(JSContext *ctx, JSValue a, JSValue b);
//  A fresh engine-owned Uint8Array of `n` bytes copied from `data`.
JSValue JABCBlob(JSContext *ctx, const u8 *data, size_t n);
//  No-copy: a Uint8Array over caller memory.  `freef` replaces the JSC
//  deallocator 1:1 (NULL for rodata), `opaque` rides along to it.
JSValue JABCBytesNoCopy(JSContext *ctx, u8 *p, size_t n,
                        JSFreeArrayBufferDataFunc *freef, void *opaque);
//  A Uint8Array over the SAME buffer as `view` at (off, len) — the subview
//  surgery hunk/hit do (JSObjectGetTypedArrayBuffer + WithArrayBufferAndOffset).
JSValue JABCSubView(JSContext *ctx, JSValueConst view, size_t off, size_t len);

//  --- properties ----------------------------------------------------------

//  JABCGetProp hands back an OWNED value (JS_FreeValue it); JABCSetProp
//  CONSUMES `v`.
JSValue JABCGetProp(JSContext *ctx, JSValueConst o, const char *name);
void JABCSetProp(JSContext *ctx, JSValueConst o, const char *name, JSValue v);

//  --- PTR-010 (arg.c): THE JS->C argument boundary ------------------------
//  A JS number is untrusted input — never cast one to size_t and never add it
//  to a pointer.  These gates gain their bounds from abc (u8bUsed / u8csLen);
//  a binding that builds a slice by hand is a bug, see arg.c for why.
b8 JABCu64Of(u64 *out, JSContext *ctx, JSValueConst arg);
b8 JABCi64Of(i64 *out, JSContext *ctx, JSValueConst arg);
b8 JABCu32Of(u32 *out, JSContext *ctx, JSValueConst arg);
b8 JABCu8Of(u8 *out, JSContext *ctx, JSValueConst arg);
//  The raw typed-array unwrap (the VIEW's range, byteOffset applied).
b8 JABCViewOf(u8 **base, size_t *len, JSContext *ctx, JSValueConst arg);
//  A typed array as a read source (whole view = DATA) / write target (= IDLE).
b8 JABCDataOf(u8b buf, JSContext *ctx, JSValueConst arg);
b8 JABCIdleOf(u8b buf, JSContext *ctx, JSValueConst arg);
//  A JS-given position inside a slice; JABCBufAt moves DATA there (the
//  consumed prefix becomes PAST, so the whole buffer stays reachable).
b8 JABCOffOf(size_t *out, u8csc whole, JSContext *ctx, JSValueConst arg);
b8 JABCBufAt(u8b buf, JSContext *ctx, JSValueConst arg);
b8 JABCBufFed(u8b buf, JSContext *ctx, JSValueConst arg);
//  A JS Buf object ({bytes,_data,_idle}) as a u8b, cursors validated; hand
//  the advanced boundaries back with JABCBufBack.
b8 JABCBufOf(u8b buf, JSContext *ctx, JSValueConst arg);
void JABCBufBack(JSContext *ctx, JSValueConst bo, u8b buf);
//  Copy a JS-string path argument into a NUL-terminated path buffer.
ok64 JABCPath(path8b path, JSContext *ctx, JSValueConst arg);

//  --- entry points (main.c) ----------------------------------------------

//  Run an embedded JS bundle; reports a thrown error to stderr.  Drains the
//  job queue, as every JS re-entry does (JAB-036: qjs queues Promise jobs and
//  nothing else pumps them).
void JABCExecute(const char *script);
//  Report an uncaught exception value to stderr as `String(value)`.  CONSUMES
//  nothing: the caller owns the value.
void JABCReport(JSValueConst exception);
//  Drain the pending job queue; safe to call at any JS boundary.
void JABCDrainJobs(void);

//  --- module installs -----------------------------------------------------
//  One .c per module, one install each, called from main.c in jab's order.
//  A container binding (heap..weave) attaches to the `abc` object cont.c
//  installed, so it runs after JABCInstallCont.

ok64 JABCInstallUtf8(JSContext *ctx, JSValueConst global);
ok64 JABCInstallIo(JSContext *ctx, JSValueConst global);
ok64 JABCInstallBuf(JSContext *ctx, JSValueConst global);
ok64 JABCInstallConsole(JSContext *ctx, JSValueConst global);
ok64 JABCInstallCont(JSContext *ctx, JSValueConst global);
ok64 JABCInstallHeap(JSContext *ctx, JSValueConst global);
ok64 JABCInstallHash(JSContext *ctx, JSValueConst global);
ok64 JABCInstallHit(JSContext *ctx, JSValueConst global);
ok64 JABCInstallIndex(JSContext *ctx, JSValueConst global);
ok64 JABCInstallPup(JSContext *ctx, JSValueConst global);
ok64 JABCInstallHunk(JSContext *ctx, JSValueConst global);
ok64 JABCInstallPack(JSContext *ctx, JSValueConst global);
//  GIT-030: the foreign-.git ODB waist; after cont's bundle, it extends `git`.
ok64 JABCInstallGit(JSContext *ctx, JSValueConst global);
ok64 JABCInstallUlog(JSContext *ctx, JSValueConst global);
ok64 JABCInstallCfold(JSContext *ctx, JSValueConst global);
ok64 JABCInstallWeave(JSContext *ctx, JSValueConst global);
ok64 JABCInstallTok(JSContext *ctx, JSValueConst global);
ok64 JABCInstallUri(JSContext *ctx, JSValueConst global);
ok64 JABCInstallCodec(JSContext *ctx, JSValueConst global);
ok64 JABCInstallZip(JSContext *ctx, JSValueConst global);
//  STATUS-020: the only `dog`-namespace install so far; it creates the object.
ok64 JABCInstallIgno(JSContext *ctx, JSValueConst global);
ok64 JABCInstallAnsi(JSContext *ctx, JSValueConst global);
ok64 JABCInstallTty(JSContext *ctx, JSValueConst global);
ok64 JABCInstallPol(JSContext *ctx, JSValueConst global);
ok64 JABCInstallNet(JSContext *ctx, JSValueConst global);
//  QJAB-004: http._drain/_feed — the abc/HTTP ragel lexer, leaf-only.
ok64 JABCInstallHttp(JSContext *ctx, JSValueConst global);
ok64 JABCInstallFsw(JSContext *ctx, JSValueConst global);
ok64 JABCInstallJsrcPack(JSContext *ctx, JSValueConst global);
ok64 JABCInstallRequire(JSContext *ctx, JSValueConst global);
//  QJAB-001: was this binary built with a jsrc bundle (jsrcpack.c published
//  the bytes)?  A packed build takes its entry from the bundle, not from argv.
b8 JABCJsrcPacked(void);

//  Teardown twins: pol drops its protected router refs while the context is
//  still alive; io closes what the JS side no longer owns (after the context).
ok64 JABCUninstallPol(JSContext *ctx);
ok64 JABCUninstallIo(void);
//  STATUS-020: frees the recycled igno boxes (see igno.c on why they are kept).
ok64 JABCUninstallIgno(void);

#endif
