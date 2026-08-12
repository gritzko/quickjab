//  JAB-036: pol.c — the poll(2) event loop over abc/POL, ported from
//  jab/pol.cpp.  JABC rule #4 holds: C keeps NO per-fd JS closures.  The
//  fd->handler table lives in the embedded JS bundle (like Buf in buf.c); C
//  holds just the two router refs below (the bootstrap points) and routes every
//  ready fd / timer tick through them.  Handlers do their own I/O via io.* —
//  pol carries readiness, not bytes.  See POL.md for the API + contract.
//  v1: one timer (POL keys timers by C callback pointer); many logical timers
//  layer in JS.
#include <math.h>
#include <poll.h>

#include "JABC.h"
#include "abc/POL.h"

//  The ONLY JS state C holds: the two routers, grabbed + pinned at install.
//  JAB-036: a JSValue is refcounted, so "protected" is simply an owned ref
//  that JABCUninstallPol frees while the context is still alive.
static thread_local JSValue JABC_POL_FD;     // pol._fd(fd, revents)->mask
static thread_local JSValue JABC_POL_TIMER;  // pol._timer(ns)->next ms
static thread_local b8 JABC_POL_HELD = NO;   // YES once both refs are owned
//  A handler exception, stashed across the C loop and re-thrown by pol.run.
static thread_local JSValue JABC_POL_EXC;
static thread_local b8 JABC_POL_THREW = NO;
//  YES while POLLoop is on the stack — guards re-entrant pol.init() (which
//  would POLFree the heap out from under the running loop).
static thread_local b8 JABC_POL_RUNNING = NO;

//  Set a numeric constant property (poll bits / time units).  JAB-036: the
//  attribute INVERSION — JSC's ReadOnly is qjs's "enumerable, not writable".
static void JABCNum(JSContext *ctx, JSValueConst o, const char *name,
                    double v) {
    JS_DefinePropertyValueStr(ctx, o, name, JS_NewFloat64(ctx, v),
                              JS_PROP_ENUMERABLE | JS_PROP_CONFIGURABLE);
}

//  Take the pending exception off the context and keep the FIRST one; every
//  later throw is dropped.  The loop stops either way.
static void JABCPolStash(JSContext *ctx) {
    JSValue e = JS_GetException(ctx);
    if (JABC_POL_THREW) {
        JS_FreeValue(ctx, e);
    } else {
        JABC_POL_EXC = e;
        JABC_POL_THREW = YES;
    }
    POLStop();
}

//  Call a pinned router with two number args; return its Number result, or -1
//  if the handler threw (the loop stops and pol.run re-throws).  Every C->JS
//  re-entry drains the pending job queue on the way out.
static double JABCPolCall(JSValueConst fn, double a0, double a1) {
    JSContext *ctx = JABC_CONTEXT;
    JSValue argv[2] = {JS_NewFloat64(ctx, a0), JS_NewFloat64(ctx, a1)};
    JSValue r = JS_Call(ctx, fn, JS_UNDEFINED, 2, argv);
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
    double m = -1;
    if (JS_IsException(r)) {
        JABCPolStash(ctx);
    } else if (JS_ToFloat64(ctx, &m, r) < 0) {
        m = -1;
        JABCPolStash(ctx);
    }
    JS_FreeValue(ctx, r);
    JABCDrainJobs();
    return m;
}

//  fd trampoline — ONE C callback for ALL fds (POL keys fds by tofd, not by
//  pointer).  Route (fd, revents) to JS, return the next interest mask; 0 (or a
//  thrown handler) drops the fd.
static short JABCPolFd(int fd, poller *p) {
    double m = JABCPolCall(JABC_POL_FD, (double)fd, (double)p->revents);
    return m < 0 ? 0 : (short)m;
}

//  timer trampoline (the timercb passed to POLTrackTime) — POL keys timers by
//  this pointer, so one trampoline == one timer.  Return the next period in ms;
//  >= 1h (or a thrown handler) self-removes the timer.
static u32 JABCPolTimer(u64 ns) {
    double ms = JABCPolCall(JABC_POL_TIMER, (double)ns, 0);
    return (ms < 0 || !isfinite(ms)) ? 3600000u : (u32)ms;
}

//  ---- native leaves (the pol bundle wraps these as pol.watch/every/run/...) -

//  pol._watch(fd, events)
static JABC_FN(JABCPolWatch) {
    (void)this_val;
    if (argc < 2) JABC_THROW("pol._watch(fd, events)");
    i32 fd = 0, ev = 0;
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) JABC_FAIL;
    if (JS_ToInt32(ctx, &ev, argv[1]) < 0) JABC_FAIL;
    poller p = {};
    p.callback = JABCPolFd;
    p.tofd = fd;
    p.events = (u16)ev;
    if (POLTrackEvents(fd, p) != OK) JABC_THROW("pol.watch failed");
    JABC_UNDEF;
}

//  pol._more(fd, events)
static JABC_FN(JABCPolMore) {
    (void)this_val;
    if (argc < 2) JABC_THROW("pol._more(fd, events)");
    i32 fd = 0, ev = 0;
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) JABC_FAIL;
    if (JS_ToInt32(ctx, &ev, argv[1]) < 0) JABC_FAIL;
    if (POLAddEvents(fd, (short)ev) != OK) JABC_THROW("pol.more: fd not tracked");
    JABC_UNDEF;
}

//  pol._unwatch(fd)
static JABC_FN(JABCPolUnwatch) {
    (void)this_val;
    if (argc < 1) JABC_THROW("pol._unwatch(fd)");
    i32 fd = 0;
    if (JS_ToInt32(ctx, &fd, argv[0]) < 0) JABC_FAIL;
    POLIgnoreEvents(fd);  //  POLNONE (untracked) is fine — idempotent drop
    JABC_UNDEF;
}

//  pol._every() — arm the single timer (period comes from the handler return)
static JABC_FN(JABCPolEvery) {
    (void)this_val;
    (void)argv;
    (void)argc;
    if (POLTrackTime(JABCPolTimer) != OK) JABC_THROW("pol.every failed");
    JABC_UNDEF;
}

//  pol.sooner(ms) — wake the timer earlier than scheduled
static JABC_FN(JABCPolSooner) {
    (void)this_val;
    if (argc < 1) JABC_THROW("pol.sooner(ms)");
    i32 ms = 0;
    if (JS_ToInt32(ctx, &ms, argv[0]) < 0) JABC_FAIL;
    POLAddTime(ms);  //  POLNONE (no timer) is fine — nothing to advance
    JABC_UNDEF;
}

//  pol._untimer()
static JABC_FN(JABCPolUntimer) {
    (void)this_val;
    (void)argv;
    (void)argc;
    POLIgnoreTime();
    JABC_UNDEF;
}

//  pol._run(ns) — drive the loop; ns < 0 or non-finite => POLNever (forever).
//  Re-throw a handler exception stashed during the run.
static JABC_FN(JABCPolRun) {
    (void)this_val;
    double dns = -1;
    if (argc > 0 && JS_ToFloat64(ctx, &dns, argv[0]) < 0) JABC_FAIL;
    u64 ns = (dns < 0 || !isfinite(dns)) ? POLNever : (u64)dns;
    JABC_POL_RUNNING = YES;
    POLLoop(ns);
    JABC_POL_RUNNING = NO;
    if (JABC_POL_THREW) {  //  surface the first handler throw to run()'s caller
        JSValue e = JABC_POL_EXC;
        JABC_POL_THREW = NO;
        JABC_POL_EXC = JS_UNDEFINED;
        return JS_Throw(ctx, e);  //  CONSUMES e
    }
    JABC_UNDEF;
}

static JABC_FN(JABCPolStop) {
    (void)ctx;
    (void)this_val;
    (void)argv;
    (void)argc;
    POLStop();
    JABC_UNDEF;
}

static JABC_FN(JABCPolSleep) {
    (void)this_val;
    if (argc < 1) JABC_THROW("pol.sleep(ns)");
    double dns = 0;
    if (JS_ToFloat64(ctx, &dns, argv[0]) < 0) JABC_FAIL;
    if (dns > 0) POLSleep((u64)dns);
    JABC_UNDEF;
}

static JABC_FN(JABCPolAny) {
    (void)this_val;
    (void)argv;
    (void)argc;
    return JS_NewBool(ctx, POLAny());
}

static JABC_FN(JABCPolNow) {
    (void)this_val;
    (void)argv;
    (void)argc;
    return JS_NewFloat64(ctx, (double)POLNow());
}

//  pol.init(maxfd) — (re)size the fd table.  Refused while a loop is live.
static JABC_FN(JABCPolInit) {
    (void)this_val;
    i32 mx = 4096;
    if (argc > 0 && JS_ToInt32(ctx, &mx, argv[0]) < 0) JABC_FAIL;
    if (JABC_POL_RUNNING) JABC_THROW("pol.init: called from inside the loop");
    POLFree();
    if (POLInit(mx) != OK) JABC_THROW("pol.init failed");
    JABC_UNDEF;
}

//  The fd->handler table + the wrappers + the two routers live here (the only
//  per-fd state, all JS-owned).  C grabs pol._fd / pol._timer after this runs.
static const char *JABC_POL_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const pol = g.pol;\n"
    "  const table = new Map();     // fd -> handler(fd, revents) -> next mask\n"
    "  let timer = null;            // the single timer handler(ns) -> next ms\n"
    "  pol.default = null;          // catch-all for fds watched without a handler\n"
    "\n"
    "  pol.watch = (fd, events, fn) => { if (fn) table.set(fd, fn); pol._watch(fd, events); return fd; };\n"
    "  pol.more = (fd, events) => { pol._more(fd, events); };\n"
    "  pol.unwatch = (fd) => { table.delete(fd); pol._unwatch(fd); };\n"
    "\n"
    "  //  raw single-timer hook: fn(deadlineNs) -> next ms (>=1h removes).  every/\n"
    "  //  after are sugar; the net timer-wheel drives pol.timer directly.\n"
    "  pol.timer = (fn) => { timer = fn; pol._every(); };\n"
    "  pol.every = (ms, fn) => pol.timer((ns) => { fn(ns); return ms; });\n"
    "  pol.after = (ms, fn) => { pol.timer((ns) => { fn(ns); return 3600001; }); pol.sooner(ms); };\n"
    "  pol.untimer = () => { timer = null; pol._untimer(); };\n"
    "\n"
    "  pol.run = (ns) => pol._run(ns === undefined ? -1 : ns);\n"
    "  pol.init = (maxfd) => { table.clear(); timer = null; pol.default = null; pol._init((maxfd | 0) || 4096); };\n"
    "\n"
    "  //  routers — the ONLY entry points C calls back into (held as protected refs)\n"
    "  pol._fd = (fd, revents) => {\n"
    "    const h = table.get(fd) || pol.default;\n"
    "    if (!h) { table.delete(fd); return 0; }    // unclaimed fd -> drop it\n"
    "    const m = h(fd, revents) | 0;\n"
    "    if (m === 0) table.delete(fd);             // handler released the fd\n"
    "    return m;\n"
    "  };\n"
    "  pol._timer = (ns) => {\n"
    "    if (!timer) return 3600001;                // no timer -> self-remove\n"
    "    const ms = timer(ns) | 0;\n"
    "    if (ms >= 3600000) timer = null;\n"
    "    return ms;\n"
    "  };\n"
    "})(this);\n"
    "\n";

//  Look up a function property of `pol` and keep it as a C-held router ref
//  (JS_GetPropertyStr already hands back the owned reference JSValueProtect
//  used to add).
static JSValue JABCPolGrab(JSContext *ctx, JSValueConst pol, const char *name) {
    return JS_GetPropertyStr(ctx, pol, name);
}

ok64 JABCInstallPol(JSContext *ctx, JSValueConst global) {
    POLInit(4096);  //  default fd table; pol.init() resizes
    JABC_API_OBJECT(pol);
    JABC_API_FN(pol, "_watch", JABCPolWatch);
    JABC_API_FN(pol, "_more", JABCPolMore);
    JABC_API_FN(pol, "_unwatch", JABCPolUnwatch);
    JABC_API_FN(pol, "_every", JABCPolEvery);
    JABC_API_FN(pol, "sooner", JABCPolSooner);
    JABC_API_FN(pol, "_untimer", JABCPolUntimer);
    JABC_API_FN(pol, "_run", JABCPolRun);
    JABC_API_FN(pol, "stop", JABCPolStop);
    JABC_API_FN(pol, "sleep", JABCPolSleep);
    JABC_API_FN(pol, "any", JABCPolAny);
    JABC_API_FN(pol, "now", JABCPolNow);
    JABC_API_FN(pol, "_init", JABCPolInit);

    //  poll(2) interest bits (platform values) + time units (ns)
    JABCNum(ctx, pol, "IN", POLLIN);
    JABCNum(ctx, pol, "OUT", POLLOUT);
    JABCNum(ctx, pol, "ERR", POLLERR);
    JABCNum(ctx, pol, "HUP", POLLHUP);
    JABCNum(ctx, pol, "PRI", POLLPRI);
    JABCNum(ctx, pol, "NVAL", POLLNVAL);
    JABCNum(ctx, pol, "SEC", (double)POLNanosPerSec);
    JABCNum(ctx, pol, "MS", (double)POLNanosPerMSec);
    JABCNum(ctx, pol, "NEVER", -1);  //  pol._run maps < 0 -> POLNever

    JABCExecute(JABC_POL_JS);
    JABC_POL_EXC = JS_UNDEFINED;
    JABC_POL_FD = JABCPolGrab(ctx, pol, "_fd");
    JABC_POL_TIMER = JABCPolGrab(ctx, pol, "_timer");
    JABC_POL_HELD = YES;
    JABC_API_END(pol);
    return OK;
}

//  Called before the context is released (POLFree drops the heap; the router
//  refs must be freed while the context is still alive).
ok64 JABCUninstallPol(JSContext *ctx) {
    if (JABC_POL_HELD) {
        JS_FreeValue(ctx, JABC_POL_FD);
        JS_FreeValue(ctx, JABC_POL_TIMER);
        JABC_POL_HELD = NO;
    }
    if (JABC_POL_THREW) {
        JS_FreeValue(ctx, JABC_POL_EXC);
        JABC_POL_THREW = NO;
    }
    POLFree();
    return OK;
}
