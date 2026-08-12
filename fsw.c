//  JAB-036: fsw.c — the inotify/kqueue dir watcher over abc/FSW, ported from
//  jab/fsw.cpp (JAB-031).  Rule #4 holds: C keeps NO per-watch state; only the
//  fd and the caller's Buf cross.  drain packs (wd, len, name) records; the map
//  + pol wiring are in the bundle below.  FSWPoll gets no binding — pol.run
//  owns the blocking.  See API.md.
#include "JABC.h"
#include "abc/FSW.h"

//  The drain sink: a caller-owned Buf plus the record count.  Lives on the
//  leaf's stack, dies with the call — no memory, no JS refs.
typedef struct JABCFswSink {
    u8bp out;
    u32 n;
} JABCFswSink;

//  JAB-031: one packed record — i32 wd, u32 name length (both LE), name bytes.
//  Room is checked whole, so IDLE never holds a torn record.
//  JAB-032: wd is the real watch descriptor now, and it is SIGNED — FSWOVERFLOW
//  (-1) says the kernel dropped events, so the JS side drops every cache.
static ok64 JABCFswPack(i32 wd, u8cs name, void *ctx) {
    JABCFswSink *s = (JABCFswSink *)ctx;
    u32 len = (u32)u8csLen(name);
    u32 raw = (u32)wd;  //  two's complement on the wire; JS reads it signed
    if (u8bIdleLen(s->out) < sizeof(raw) + sizeof(len) + (size_t)len)
        return FSWNOROOM;
    u8sFeed32(u8bIdle(s->out), &raw);
    u8sFeed32(u8bIdle(s->out), &len);
    u8csc bytes = {name[0], name[1]};
    ok64 o = u8bFeed(s->out, bytes);
    if (o != OK) return o;
    s->n++;
    return OK;
}

//  fsw.init() -> wfd (a pollable fd; hand it to pol.watch(wfd, pol.IN, ...))
static JABC_FN(JABCFswInit) {
    (void)this_val;
    (void)argv;
    (void)argc;
    int wfd = -1;
    if (FSWInit(&wfd) != OK) JABC_THROW("fsw.init: cannot create a watcher");
    return JS_NewFloat64(ctx, (double)wfd);
}

//  fsw.dir(wfd, path) -> wd.  Non-recursive, one dir level.  JAB-032: the wd
//  names this dir in every drained record, so ONE wfd serves a whole tree.
static JABC_FN(JABCFswDir) {
    (void)this_val;
    if (argc < 2) JABC_THROW("fsw.dir(wfd, path)");
    u64 wfd = 0;
    if (!JABCu64Of(&wfd, ctx, argv[0])) JABC_FAIL;
    a_pad(u8, p, FILE_PATH_MAX_LEN);
    if (JABCPath(p, ctx, argv[1]) != OK) JABC_THROW("fsw.dir: bad path");
    i32 wd = 0;
    if (FSWDir((int)wfd, $path(p), &wd) != OK)
        JABC_THROW("fsw.dir: cannot watch that directory");
    return JS_NewFloat64(ctx, (double)wd);
}

//  fsw.drain(wfd, buf) -> record count.  Non-blocking; 0 means nothing queued.
static JABC_FN(JABCFswDrain) {
    (void)this_val;
    if (argc < 2) JABC_THROW("fsw.drain(wfd, buf)");
    u64 wfd = 0;
    if (!JABCu64Of(&wfd, ctx, argv[0])) JABC_FAIL;
    if (!JS_IsObject(argv[1])) JABC_THROW("fsw.drain: buf must be a Buf");
    u8 *buf[4] = {};  //  cursors gated + checked in arg.c
    if (!JABCBufOf(buf, ctx, argv[1])) JABC_FAIL;
    JABCFswSink sink = {buf, 0};
    ok64 o = FSWDrain((int)wfd, JABCFswPack, &sink);
    JABCBufBack(ctx, argv[1], buf);  //  whole records already packed stay visible
    if (o == FSWNOROOM) JABC_THROW("fsw.drain: the buffer is full, events lost");
    if (o != OK) JABC_THROW("fsw.drain: cannot read the watcher");
    return JS_NewFloat64(ctx, (double)sink.n);
}

//  fsw.close(wfd) — closes the watcher fd; on kqueue the pinned dir fds stay
//  open (FSW.md), which is why one wfd per watched dir is the JS default.
static JABC_FN(JABCFswClose) {
    (void)this_val;
    if (argc < 1) JABC_THROW("fsw.close(wfd)");
    u64 wfd = 0;
    if (!JABCu64Of(&wfd, ctx, argv[0])) JABC_FAIL;
    FSWClose((int)wfd);
    JABC_UNDEF;
}

//  JAB-031: all per-watch state lives here.  JAB-032: FSWDir hands back a wd,
//  so ONE watcher fd carries the whole tree and the wd -> dir map does the
//  attribution — no more fd + pol handler + 64 KiB Buf per watched dir.
static const char *JABC_FSW_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const fsw = g.fsw, io = g.io, pol = g.pol;\n"
    "  const HDR = 8;                 // i32 wd + u32 name length, little-endian\n"
    "  const dirs = new Map();        // wd -> watched dir (one shared watcher)\n"
    "  const subs = new Map();        // wd -> handler\n"
    "  let wfd = -1, buf = null, over = null;\n"
    "\n"
    "  //  events were LOST (kernel queue overflow, or a Buf too small for the\n"
    "  //  burst): nothing under this watcher is trustworthy, so every watched dir\n"
    "  //  gets a bare rescan (\"\" name) unless fsw.onoverflow claimed the fact.\n"
    "  const lost = () => {\n"
    "    if (over) { over(); return; }\n"
    "    dirs.forEach((d, w) => { const h = subs.get(w); if (h) h(\"\", d); });\n"
    "  };\n"
    "\n"
    "  //  parse a drained Buf into [{wd, name}]; name is a BARE basename, and is\n"
    "  //  \"\" on kqueue (no filename in the event) — a \"rescan this dir\" signal.\n"
    "  //  wd is SIGNED: fsw.OVERFLOW (-1) means the kernel DROPPED events.\n"
    "  fsw.OVERFLOW = -1;\n"
    "  fsw.records = (buf) => {\n"
    "    const b = buf.data ? buf.data() : buf;\n"
    "    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);\n"
    "    const out = [];\n"
    "    for (let o = 0; o + HDR <= b.byteLength; ) {\n"
    "      const wd = dv.getInt32(o, true), len = dv.getUint32(o + 4, true);\n"
    "      if (o + HDR + len > b.byteLength) break;\n"
    "      out.push({ wd: wd, name: g.utf8.Decode(b.subarray(o + HDR, o + HDR + len)) });\n"
    "      o += HDR + len;\n"
    "    }\n"
    "    return out;\n"
    "  };\n"
    "\n"
    "  //  fsw.watch(dir, fn) -> wd; fn(name, dir) per event (\"\" name => rescan the\n"
    "  //  dir).  Every watch rides ONE watcher fd, armed lazily on the first call.\n"
    "  fsw.watch = (dir, fn) => {\n"
    "    if (wfd < 0) {\n"
    "      wfd = fsw.init();\n"
    "      buf = io.buf(1 << 16);\n"
    "      pol.watch(wfd, pol.IN, (fd) => {\n"
    "        for (;;) {                       // drain to empty: one Buf, many bites\n"
    "          let n = 0;\n"
    "          //  a full Buf is the SAME fact as a kernel overflow — events were\n"
    "          //  lost — so it takes the same path instead of escaping as a throw.\n"
    "          try { n = fsw.drain(fd, buf.reset()); } catch (e) { lost(); break; }\n"
    "          if (n === 0) break;\n"
    "          const rows = fsw.records(buf);\n"
    "          for (let i = 0; i < rows.length; i++) {\n"
    "            const r = rows[i];\n"
    "            if (r.wd === fsw.OVERFLOW) { lost(); continue; }\n"
    "            const d = dirs.get(r.wd), h = subs.get(r.wd);\n"
    "            if (h) h(r.name, d);\n"
    "          }\n"
    "        }\n"
    "        return pol.IN;\n"
    "      });\n"
    "    }\n"
    "    const wd = fsw.dir(wfd, dir);\n"
    "    dirs.set(wd, dir);\n"
    "    subs.set(wd, fn);\n"
    "    return wd;\n"
    "  };\n"
    "\n"
    "  //  fsw.onoverflow(fn) — one callback for \"the kernel dropped events\";\n"
    "  //  without it every watched dir gets a bare rescan (\"\" name) instead.\n"
    "  fsw.onoverflow = (fn) => { over = fn; };\n"
    "\n"
    "  //  fsw.unwatch(wd) — forget one dir.  The inotify watch itself stays (no\n"
    "  //  FSWUndir, ABC-013), so events still arrive; they are simply unclaimed.\n"
    "  fsw.unwatch = (wd) => { dirs.delete(wd); subs.delete(wd); };\n"
    "\n"
    "  //  fsw.stop() — tear the shared watcher down (every watch dies with it).\n"
    "  fsw.stop = () => {\n"
    "    if (wfd < 0) return;\n"
    "    pol.unwatch(wfd); fsw.close(wfd);\n"
    "    wfd = -1; buf = null; dirs.clear(); subs.clear();\n"
    "  };\n"
    "})(this);\n"
    "\n";

ok64 JABCInstallFsw(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(fsw);
    JABC_API_FN(fsw, "init", JABCFswInit);
    JABC_API_FN(fsw, "dir", JABCFswDir);
    JABC_API_FN(fsw, "drain", JABCFswDrain);
    JABC_API_FN(fsw, "close", JABCFswClose);
    JABCExecute(JABC_FSW_JS);
    JABC_API_END(fsw);
    return OK;
}
