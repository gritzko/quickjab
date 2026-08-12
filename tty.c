//  JAB-036: jab/tty.cpp — terminal-CONTROL leaves (JS-053) over abc/ANSI's
//  ANSI* POSIX wrappers; distinct from ansi.* (styling).  STATELESS like every
//  JABC leaf: tty.raw RETURNS the saved termios as a fresh Uint8Array that JS
//  holds and tty.cook takes back — no C-side per-fd table.
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "JABC.h"
#include "abc/ANSI.h"

//  A JS number as an fd; JS_ToFloat64 leaves the error pending on failure.
static b8 JABCttyInt(int *out, JSContext *ctx, JSValueConst v) {
    double d = 0;
    if (JS_ToFloat64(ctx, &d, v) < 0) return NO;
    *out = (int)d;
    return YES;
}

//  Set a numeric property on an object (the {rows, cols} record).
static void JABCttySetNum(JSContext *ctx, JSValueConst o, const char *k,
                          double v) {
    JABCSetProp(ctx, o, k, JS_NewFloat64(ctx, v));
}

//  tty.raw(fd) -> Uint8Array  (the saved termios; pass it to tty.cook to
//  restore).  Enters raw mode (BRO.c flags: ECHO|ICANON|ISIG|IEXTEN,
//  IXON|ICRNL|BRKINT|INPCK|ISTRIP, OPOST cleared; VMIN=0 VTIME=1).
static JABC_FN(JABCttyRaw) {
    if (argc < 1) JABC_THROW("tty.raw(fd) -> savedTermios");
    int fd = 0;
    if (!JABCttyInt(&fd, ctx, argv[0])) JABC_FAIL;
    size_t n = ANSITtyTermiosSize();
    u8 *p = (u8 *)malloc(n ? n : 1);
    if (p == NULL) JABC_THROW("tty.raw: out of memory");
    u8s saved = {p, p + n};
    if (ANSIRaw(fd, saved) != OK) {
        free(p);
        JABC_THROW(strerror(errno));
    }
    JSValue ta = JABCBlob(ctx, p, n);
    free(p);
    return ta;
}

//  tty.cook(fd, saved) -> restore termios from the bytes tty.raw returned.
static JABC_FN(JABCttyCook) {
    if (argc < 2) JABC_THROW("tty.cook(fd, savedTermios)");
    int fd = 0;
    if (!JABCttyInt(&fd, ctx, argv[0])) JABC_FAIL;
    u8 *savedb[4] = {};
    if (!JABCDataOf(savedb, ctx, argv[1])) JABC_FAIL;
    if (u8bDataLen(savedb) != ANSITtyTermiosSize())
        JABC_THROW("tty.cook: saved termios has wrong size");
    if (ANSICook(fd, u8bDataC(savedb)) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

//  tty.size(fd?) -> {rows, cols}  (ioctl TIOCGWINSZ; default fd is stdout).
static JABC_FN(JABCttySize) {
    int fd = STDOUT_FILENO;
    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        if (!JABCttyInt(&fd, ctx, argv[0])) JABC_FAIL;
    }
    u16 rows = 0, cols = 0;
    if (ANSITtySize(fd, &rows, &cols) != OK) JABC_THROW(strerror(errno));
    JSValue obj = JS_NewObject(ctx);
    JABCttySetNum(ctx, obj, "rows", (double)rows);
    JABCttySetNum(ctx, obj, "cols", (double)cols);
    return obj;
}

//  tty.openpty() -> {master, slave}  (test support: a fresh pty pair; the
//  caller owns + io.close()s both fds).
static JABC_FN(JABCttyOpenPty) {
    (void)argc;
    (void)argv;
    int master = -1, slave = -1;
    if (ANSIOpenPty(&master, &slave) != OK) JABC_THROW(strerror(errno));
    JSValue obj = JS_NewObject(ctx);
    JABCttySetNum(ctx, obj, "master", (double)master);
    JABCttySetNum(ctx, obj, "slave", (double)slave);
    return obj;
}

//  tty.setSize(fd, rows, cols) -> ioctl TIOCSWINSZ (test support: stamp a
//  winsize on a pty so tty.size can read it back).
static JABC_FN(JABCttySetSize) {
    if (argc < 3) JABC_THROW("tty.setSize(fd, rows, cols)");
    int fd = 0;
    double rows = 0, cols = 0;
    if (!JABCttyInt(&fd, ctx, argv[0])) JABC_FAIL;
    if (JS_ToFloat64(ctx, &rows, argv[1]) < 0) JABC_FAIL;
    if (JS_ToFloat64(ctx, &cols, argv[2]) < 0) JABC_FAIL;
    if (ANSISetSize(fd, (u16)rows, (u16)cols) != OK) JABC_THROW(strerror(errno));
    JABC_UNDEF;
}

ok64 JABCInstallTty(JSContext *ctx, JSValueConst global) {
    JABC_API_OBJECT(tty);
    JABC_API_FN(tty, "raw", JABCttyRaw);
    JABC_API_FN(tty, "cook", JABCttyCook);
    JABC_API_FN(tty, "size", JABCttySize);
    JABC_API_FN(tty, "openpty", JABCttyOpenPty);
    JABC_API_FN(tty, "setSize", JABCttySetSize);
    JABC_API_END(tty);
    return OK;
}
