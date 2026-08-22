//  JAB-036: net.c — net/dgram + timers, ported from jab/net.cpp.  A Node-style
//  async API built on `pol`.  The native side is leaf-only (socket syscalls
//  returning bare fds, like io.*); the per-socket buffers, the EventEmitter
//  dispatch, and the setTimeout/setInterval timer wheel all live in the
//  embedded JS bundle.  Sockets register their fd with pol.watch; readiness
//  drives 'data'/'drain'/'connection'; nothing here holds memory or a JS
//  reference.  Address form is a `tcp://host:port` URI (parsed by abc/NET);
//  EAGAIN on a nonblocking socket surfaces to JS as -1, never a throw.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "JABC.h"
#include "abc/NET.h"
#include "abc/TCP.h"
#include "abc/UDP.h"

//  Mark an fd nonblocking so the pol loop never wedges on a slow peer.
static void JABCNonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

//  Copy a JS-string URI argument into `buf` (NUL-terminated); return its byte
//  length, 0 when the argument is not a string or does not fit.
static size_t JABCUri(char *buf, size_t cap, JSContext *ctx,
                      JSValueConst arg) {
    buf[0] = '\0';
    if (!JS_IsString(arg)) return 0;
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, arg);
    if (s == NULL) return 0;
    if (len == 0 || len + 1 > cap) {
        len = 0;
    } else {
        memcpy(buf, s, len);
        buf[len] = '\0';
    }
    JS_FreeCString(ctx, s);
    return len;
}

//  net._listen(uri) -> fd  (TCP bind+listen, nonblocking)
static JABC_FN(JABCNetListen) {
    (void)this_val;
    if (argc < 1) JABC_THROW("net._listen(uri)");
    char uri[256];
    size_t n = JABCUri(uri, sizeof(uri), ctx, argv[0]);
    if (n == 0) JABC_THROW("net._listen: bad uri");
    u8cs addr = {(u8 *)uri, (u8 *)uri + n};
    int fd = -1;
    if (TCPListen(&fd, addr) != OK || fd < 0) JABC_THROW(strerror(errno));
    JABCNonblock(fd);
    return JS_NewFloat64(ctx, (double)fd);
}

//  net._connect(uri) -> fd  (TCP connect; abc connect is synchronous, then we
//  flip the fd nonblocking — v1 limitation, see POL.md)
static JABC_FN(JABCNetConnect) {
    (void)this_val;
    if (argc < 1) JABC_THROW("net._connect(uri)");
    char uri[256];
    size_t n = JABCUri(uri, sizeof(uri), ctx, argv[0]);
    if (n == 0) JABC_THROW("net._connect: bad uri");
    u8csc addr = {(u8 *)uri, (u8 *)uri + n};
    int fd = -1;
    if (TCPConnect(&fd, addr, YES) != OK || fd < 0) JABC_THROW(strerror(errno));
    JABCNonblock(fd);
    return JS_NewFloat64(ctx, (double)fd);
}

//  net._accept(sfd) -> cfd, or -1 if nothing pending (EAGAIN/spurious)
static JABC_FN(JABCNetAccept) {
    (void)this_val;
    if (argc < 1) JABC_THROW("net._accept(sfd)");
    int sfd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&sfd, ctx, argv[0])) JABC_FAIL;
    int cfd = -1;
    aNETraw(caddr);
    if (TCPAccept(&cfd, caddr, sfd) != OK || cfd < 0)
        return JS_NewFloat64(ctx, -1);  //  no connection ready right now
    JABCNonblock(cfd);
    return JS_NewFloat64(ctx, (double)cfd);
}

//  net._recv(fd, u8) -> n  (n>0 bytes, 0 = EOF, -1 = would-block)
static JABC_FN(JABCNetRecv) {
    (void)this_val;
    if (argc < 2) JABC_THROW("net._recv(fd, Uint8Array)");
    int fd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&fd, ctx, argv[0])) JABC_FAIL;
    u8 *tab[4] = {};
    if (!JABCIdleOf(tab, ctx, argv[1])) JABC_FAIL;
    ssize_t n;
    do {
        n = recv(fd, u8bIdle(tab)[0], u8bIdleLen(tab), 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return JS_NewFloat64(ctx, -1);
        JABC_THROW(strerror(errno));
    }
    return JS_NewFloat64(ctx, (double)n);
}

//  net._send(fd, u8) -> n  (bytes written, or -1 = would-block).  MSG_NOSIGNAL
//  turns a write to a closed peer into EPIPE instead of SIGPIPE.
static JABC_FN(JABCNetSend) {
    (void)this_val;
    if (argc < 2) JABC_THROW("net._send(fd, Uint8Array)");
    int fd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&fd, ctx, argv[0])) JABC_FAIL;
    u8 *tab[4] = {};
    if (!JABCDataOf(tab, ctx, argv[1])) JABC_FAIL;
    ssize_t n;
    do {
        n = send(fd, u8bData(tab)[0], u8bDataLen(tab), MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return JS_NewFloat64(ctx, -1);
        JABC_THROW(strerror(errno));
    }
    return JS_NewFloat64(ctx, (double)n);
}

//  net._shutwr(fd) — half-close the write side (send FIN), keep reading.  This
//  is what socket.end() maps to; the fd is closed only once the peer FINs too.
static JABC_FN(JABCNetShutwr) {
    (void)this_val;
    if (argc < 1) JABC_THROW("net._shutwr(fd)");
    int fd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&fd, ctx, argv[0])) JABC_FAIL;
    (void)shutdown(fd, SHUT_WR);
    JABC_UNDEF;
}

//  net._close(fd)
static JABC_FN(JABCNetClose) {
    (void)this_val;
    if (argc < 1) JABC_THROW("net._close(fd)");
    int fd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&fd, ctx, argv[0])) JABC_FAIL;
    (void)close(fd);
    JABC_UNDEF;
}

//  --- dgram (UDP) leaves: connectionless, sender address surfaced per datagram

//  dgram._bind(uri) -> fd  (UDP bind, nonblocking)
static JABC_FN(JABCDgramBind) {
    (void)this_val;
    if (argc < 1) JABC_THROW("dgram._bind(uri)");
    char uri[256];
    size_t n = JABCUri(uri, sizeof(uri), ctx, argv[0]);
    if (n == 0) JABC_THROW("dgram._bind: bad uri");
    u8cs addr = {(u8 *)uri, (u8 *)uri + n};
    int fd = -1;
    if (UDPBind(&fd, addr) != OK || fd < 0) JABC_THROW(strerror(errno));
    JABCNonblock(fd);
    return JS_NewFloat64(ctx, (double)fd);
}

//  dgram._recv(fd, u8) -> {n, address, port}, or null if nothing pending
static JABC_FN(JABCDgramRecv) {
    (void)this_val;
    if (argc < 2) JABC_THROW("dgram._recv(fd, Uint8Array)");
    int fd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&fd, ctx, argv[0])) JABC_FAIL;
    u8 *tab[4] = {};
    if (!JABCIdleOf(tab, ctx, argv[1])) JABC_FAIL;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    ssize_t n;
    do {
        n = recvfrom(fd, u8bIdle(tab)[0], u8bIdleLen(tab), 0,
                     (struct sockaddr *)&ss, &sl);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return JS_NULL;
        JABC_THROW(strerror(errno));
    }
    char host[NI_MAXHOST] = "", serv[NI_MAXSERV] = "";
    getnameinfo((struct sockaddr *)&ss, sl, host, sizeof(host), serv,
                sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
    JSValue o = JS_NewObject(ctx);
    JABCSetProp(ctx, o, "n", JS_NewFloat64(ctx, (double)n));
    JABCSetProp(ctx, o, "address", JSOfCString(host));
    JABCSetProp(ctx, o, "port", JS_NewFloat64(ctx, (double)atoi(serv)));
    return o;
}

//  dgram._send(fd, u8, host, port) -> n  (resolve + sendto), or -1 = would-block
static JABC_FN(JABCDgramSend) {
    (void)this_val;
    if (argc < 4) JABC_THROW("dgram._send(fd, u8, host, port)");
    //  QJAB-005: EVERY scalar arg is coerced BEFORE the view is unwrapped —
    //  the port's valueOf is JS, and JS mid-leaf can transfer() the payload
    //  out from under the sendto below (_recv/_send have the same shape).
    int fd = 0;  //  QJAB-011: NaN/Inf/negative is not fd 0
    if (!JABCFdOf(&fd, ctx, argv[0])) JABC_FAIL;
    char host[NETmaxhost] = "", port[NETmaxserv] = "";
    if (JABCUri(host, sizeof(host), ctx, argv[2]) == 0)
        JABC_THROW("dgram._send: bad host");
    u64 p = 0;
    if (!JABCu64Of(&p, ctx, argv[3])) JABC_FAIL;
    if (p > 65535) JABC_THROW("dgram._send: bad port");
    snprintf(port, sizeof(port), "%d", (int)p);
    u8 *tab[4] = {};
    if (!JABCDataOf(tab, ctx, argv[1])) JABC_FAIL;
    struct addrinfo hints = {}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL)
        JABC_THROW("dgram._send: resolve failed");
    ssize_t n;
    do {
        n = sendto(fd, u8bData(tab)[0], u8bDataLen(tab), 0, res->ai_addr,
                   res->ai_addrlen);
    } while (n < 0 && errno == EINTR);
    freeaddrinfo(res);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return JS_NewFloat64(ctx, -1);
        JABC_THROW(strerror(errno));
    }
    return JS_NewFloat64(ctx, (double)n);
}

//  The EventEmitter, net.createServer/connect + Socket, dgram, and the Node
//  timer wheel (setTimeout/setInterval over the single pol timer) all live in JS.
static const char *JABC_NET_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const pol = g.pol, io = g.io, utf8 = g.utf8, Buf = g.Buf, net = g.net, dgram = g.dgram;\n"
    "\n"
    "  // --- minimal Node EventEmitter ---\n"
    "  class Emitter {\n"
    "    constructor() { this._ev = {}; }\n"
    "    on(name, fn) { (this._ev[name] = this._ev[name] || []).push(fn); return this; }\n"
    "    once(name, fn) { const w = (...a) => { this.off(name, w); fn.apply(null, a); }; return this.on(name, w); }\n"
    "    off(name, fn) { const a = this._ev[name]; if (a) { const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); } return this; }\n"
    "    emit(name) { const a = this._ev[name]; if (!a) return false;\n"
    "      const args = Array.prototype.slice.call(arguments, 1);\n"
    "      for (const fn of a.slice()) fn.apply(null, args); return true; }\n"
    "  }\n"
    "  g.Emitter = Emitter;\n"
    "\n"
    "  // --- Socket: a fd + a read/write Buf, registered with pol ---\n"
    "  class Socket extends Emitter {\n"
    "    constructor(fd) {\n"
    "      super();\n"
    "      this.fd = fd;\n"
    "      this._rb = io.buf(64 << 10);     // read buffer (recycled per 'data' tick)\n"
    "      this._wb = io.buf(64 << 10);     // write FIFO\n"
    "      this._readEnded = false;     // peer FIN seen (recv 0)\n"
    "      this._ending = false;        // end() called: finish writing then shutwr\n"
    "      this._wrShut = false;        // our FIN sent (shutdown SHUT_WR)\n"
    "      this._closed = false;\n"
    "    }\n"
    "    _register() { pol.watch(this.fd, pol.IN, (fd, rev) => this._poll(rev)); return this; }\n"
    "\n"
    "    _poll(revents) {\n"
    "      if (revents & (pol.ERR | pol.NVAL)) { this.emit(\"error\", \"socket error\"); this._doClose(); return 0; }\n"
    "      if (revents & pol.OUT) this._flush();\n"
    "      if (revents & pol.IN) {\n"
    "        this._rb.reset();\n"
    "        const n = net._recv(this.fd, this._rb.idle());\n"
    "        if (n > 0) { this._rb.fed(n); this.emit(\"data\", this._rb.data()); }\n"
    "        else if (n === 0) this._readEnd();   // EOF (n<0 = EAGAIN: nothing)\n"
    "      }\n"
    "      if ((revents & pol.HUP) && !(revents & pol.IN)) this._readEnd();\n"
    "      return this._mask();\n"
    "    }\n"
    "    //  peer closed its write side: surface 'end', then finish our own write side\n"
    "    //  (Node default, no allowHalfOpen) so the fd eventually closes.\n"
    "    _readEnd() { if (this._readEnded) return; this._readEnded = true; this.emit(\"end\"); this.end(); }\n"
    "    _flush() {\n"
    "      while (this._wb.size > 0) {\n"
    "        const n = net._send(this.fd, this._wb.data());\n"
    "        if (n < 0) break;                    // would-block: try again next tick\n"
    "        this._wb.skip(n);                    // consume what went out\n"
    "      }\n"
    "      if (this._wb.size === 0) {\n"
    "        this._wb.reset();\n"
    "        this.emit(\"drain\");\n"
    "        if (this._ending && !this._wrShut) { this._wrShut = true; net._shutwr(this.fd); }\n"
    "      }\n"
    "    }\n"
    "    _mask() {\n"
    "      if (this._closed) return 0;\n"
    "      if (this._readEnded && this._wrShut) { this._doClose(); return 0; }  // both sides done\n"
    "      let m = 0;\n"
    "      if (!this._readEnded) m |= pol.IN;                          // still reading\n"
    "      if (this._wb.size > 0 || (this._ending && !this._wrShut)) m |= pol.OUT;  // flush / FIN pending\n"
    "      return m || pol.IN;\n"
    "    }\n"
    "    _doClose() { if (this._closed) return; this._closed = true; net._close(this.fd); this.emit(\"close\"); }\n"
    "\n"
    "    write(data) {\n"
    "      if (this._closed || this._ending) return false;\n"
    "      const u = (typeof data === \"string\") ? utf8.Encode(data)\n"
    "              : (data instanceof Buf) ? data.data() : data;\n"
    "      if (u.length > this._wb.room) {        // grow the FIFO if backed up\n"
    "        this._wb.shift();\n"
    "        // JS-104: geometric growth — amortized O(n) total copy under backpressure\n"
    "        if (u.length > this._wb.room) this._wb.grow(Math.max(this._wb.cap * 2, this._wb.size + u.length));\n"
    "      }\n"
    "      this._wb.feed(u);\n"
    "      pol.more(this.fd, pol.OUT);            // ask the loop to drain it\n"
    "      return this._wb.size < (256 << 10);    // false = backpressure (Node hint)\n"
    "    }\n"
    "    end(data) {\n"
    "      if (data != null) this.write(data);\n"
    "      this._ending = true;\n"
    "      if (!this._closed) { try { pol.more(this.fd, pol.OUT); } catch (e) {} }  // force a close tick\n"
    "      return this;\n"
    "    }\n"
    "    destroy() { this._ending = true; this._doClose(); return this; }\n"
    "  }\n"
    "  g.Socket = Socket;\n"
    "\n"
    "  // --- net.createServer / connect ---\n"
    "  class Server extends Emitter {\n"
    "    constructor() { super(); this.fd = -1; }\n"
    "    listen(port, host, cb) {\n"
    "      if (typeof host === \"function\") { cb = host; host = undefined; }\n"
    "      host = host || \"0.0.0.0\";\n"
    "      this.fd = net._listen(\"tcp://\" + host + \":\" + port);\n"
    "      if (cb) this.on(\"listening\", cb);\n"
    "      pol.watch(this.fd, pol.IN, (fd) => {\n"
    "        for (;;) {\n"
    "          const cfd = net._accept(fd);\n"
    "          if (cfd < 0) break;                // drained the backlog\n"
    "          this.emit(\"connection\", new Socket(cfd)._register());\n"
    "        }\n"
    "        return pol.IN;\n"
    "      });\n"
    "      g.setTimeout(() => this.emit(\"listening\"), 0);\n"
    "      return this;\n"
    "    }\n"
    "    close() { if (this.fd >= 0) { pol.unwatch(this.fd); net._close(this.fd); this.fd = -1; this.emit(\"close\"); } return this; }\n"
    "  }\n"
    "  net.createServer = (onConn) => { const s = new Server(); if (onConn) s.on(\"connection\", onConn); return s; };\n"
    "  net.connect = (port, host, cb) => {\n"
    "    if (typeof host === \"function\") { cb = host; host = undefined; }\n"
    "    host = host || \"127.0.0.1\";\n"
    "    const s = new Socket(net._connect(\"tcp://\" + host + \":\" + port))._register();\n"
    "    if (cb) s.once(\"connect\", cb);\n"
    "    g.setTimeout(() => s.emit(\"connect\"), 0);   // connect resolved synchronously\n"
    "    return s;\n"
    "  };\n"
    "  net.createConnection = net.connect;\n"
    "\n"
    "  // --- dgram (UDP): connectionless, 'message' carries the sender rinfo ---\n"
    "  class Dgram extends Emitter {\n"
    "    constructor(type) { super(); this.type = type || \"udp4\"; this.fd = -1; this._rb = io.buf(64 << 10); }\n"
    "    bind(port, addr, cb) {\n"
    "      if (typeof addr === \"function\") { cb = addr; addr = undefined; }\n"
    "      addr = addr || \"0.0.0.0\";\n"
    "      this.fd = dgram._bind(\"udp://\" + addr + \":\" + port);\n"
    "      if (cb) this.on(\"listening\", cb);\n"
    "      pol.watch(this.fd, pol.IN, (fd) => {\n"
    "        for (;;) {\n"
    "          if (this.fd < 0) return 0;       // closed by a prior 'message' handler\n"
    "          this._rb.reset();\n"
    "          const r = dgram._recv(fd, this._rb.idle());\n"
    "          if (!r) break;                   // EAGAIN: drained\n"
    "          this._rb.fed(r.n);\n"
    "          this.emit(\"message\", this._rb.data(), { address: r.address, port: r.port });\n"
    "        }\n"
    "        return this.fd < 0 ? 0 : pol.IN;\n"
    "      });\n"
    "      g.setTimeout(() => this.emit(\"listening\"), 0);\n"
    "      return this;\n"
    "    }\n"
    "    send(data, port, host) {\n"
    "      const u = (typeof data === \"string\") ? utf8.Encode(data)\n"
    "              : (data instanceof Buf) ? data.data() : data;\n"
    "      dgram._send(this.fd, u, host || \"127.0.0.1\", port);\n"
    "      return this;\n"
    "    }\n"
    "    close() { if (this.fd >= 0) { pol.unwatch(this.fd); net._close(this.fd); this.fd = -1; this.emit(\"close\"); } return this; }\n"
    "  }\n"
    "  dgram.createSocket = (type, onMsg) => {\n"
    "    if (typeof type === \"object\" && type) { onMsg = onMsg || type.onMessage; type = type.type; }\n"
    "    const s = new Dgram(type);\n"
    "    if (onMsg) s.on(\"message\", onMsg);\n"
    "    return s;\n"
    "  };\n"
    "\n"
    "  // --- Node timers over the single pol timer (a JS timer wheel) ---\n"
    "  const TW = new Map();        // id -> { dueNs, periodNs, fn, args }\n"
    "  let twId = 1, twOn = false;\n"
    "  const MS = 1e6;              // ns per ms\n"
    "  function twTick() {\n"
    "    const now = pol.now();\n"
    "    const due = [];\n"
    "    for (const e of TW) if (e[1].dueNs <= now) due.push(e);\n"
    "    for (const [id, t] of due) {\n"
    "      if (t.periodNs > 0) t.dueNs = pol.now() + t.periodNs; else TW.delete(id);\n"
    "      t.fn.apply(null, t.args);              // a throw propagates out of pol.run (Node: uncaught)\n"
    "    }\n"
    "    if (TW.size === 0) { twOn = false; return 3600001; }   // remove the pol timer\n"
    "    let soon = Infinity;\n"
    "    for (const t of TW.values()) if (t.dueNs < soon) soon = t.dueNs;\n"
    "    const ms = Math.ceil((soon - pol.now()) / MS);\n"
    "    return ms < 1 ? 1 : ms;\n"
    "  }\n"
    "  function twArm(ms) { if (!twOn) { twOn = true; pol.timer(twTick); } pol.sooner(ms < 1 ? 1 : ms | 0); }\n"
    "  g.setTimeout = (fn, ms, ...args) => { ms = Math.max(0, +ms || 0); const id = twId++;\n"
    "    TW.set(id, { dueNs: pol.now() + ms * MS, periodNs: 0, fn, args }); twArm(ms); return id; };\n"
    "  g.setInterval = (fn, ms, ...args) => { ms = Math.max(1, +ms || 1); const id = twId++;\n"
    "    TW.set(id, { dueNs: pol.now() + ms * MS, periodNs: ms * MS, fn, args }); twArm(ms); return id; };\n"
    "  g.clearTimeout = (id) => { TW.delete(id); };\n"
    "  g.clearInterval = g.clearTimeout;\n"
    "  g.setImmediate = (fn, ...args) => g.setTimeout(fn, 0, ...args);\n"
    "})(this);\n"
    "\n";

ok64 JABCInstallNet(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(net);
    JABC_API_FN(net, "_listen", JABCNetListen);
    JABC_API_FN(net, "_connect", JABCNetConnect);
    JABC_API_FN(net, "_accept", JABCNetAccept);
    JABC_API_FN(net, "_recv", JABCNetRecv);
    JABC_API_FN(net, "_send", JABCNetSend);
    JABC_API_FN(net, "_shutwr", JABCNetShutwr);
    JABC_API_FN(net, "_close", JABCNetClose);
    JABC_API_OBJECT(dgram);
    JABC_API_FN(dgram, "_bind", JABCDgramBind);
    JABC_API_FN(dgram, "_recv", JABCDgramRecv);
    JABC_API_FN(dgram, "_send", JABCDgramSend);
    signal(SIGPIPE, SIG_IGN);  //  a write to a closed peer -> EPIPE, not a signal
    JABCExecute(JABC_NET_JS);
    JABC_API_END(dgram);
    JABC_API_END(net);
    return OK;
}
