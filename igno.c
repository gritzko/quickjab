//  STATUS-020: igno.c — the three per-FILE .gitignore leaves under `dog`.
//  One handle = one mmapped `.gitignore`; the chain/prefix walk lives in JS.
#include "JABC.h"
#include "abc/FILE.h"
#include "dog/git/IGNO.h"

//  STATUS-020: the handle box — one heap igno_set, handed to JS as a Number
//  (JAB-034: still finalizer-less, the _ulog_open precedent).
typedef struct jabc_igno {
    igno_set set;
    struct jabc_igno *next;  //  link while parked on the recycle list
} jabc_igno;

//  STATUS-020: a closed box is RETAINED and recycled, never handed back to
//  the allocator — that is what makes a double-close safe instead of a UAF.
static jabc_igno *JABC_IGNO_FREE;

static jabc_igno *JABCignoHandle(JSContext *ctx, JSValueConst v) {
    double d = 0;
    if (JS_ToFloat64(ctx, &d, v) < 0 || d <= 0) return NULL;
    return (jabc_igno *)(size_t)d;
}

//  STATUS-020: a live box always holds a mapping (IGNOSetOpen returns OK only
//  after FILEMapRO), so `buf == NULL` IS the closed/parked state — no flag.
static void JABCignoPark(jabc_igno *box) {
    box->next = JABC_IGNO_FREE;
    JABC_IGNO_FREE = box;
}

//  STATUS-020: _igno_open(gitignorePath) -> Number handle, 0 when the file is
//  absent or unreadable (the common case: JS skips that level, no exception).
static JABC_FN(JABCignoOpen) {
    if (argc < 1) JABC_THROW("dog._igno_open(gitignorePath)");
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, argv[0]);
    if (s == NULL) JABC_FAIL;
    if (len < 1 || len + 2 >= FILE_PATH_MAX_LEN) {
        JS_FreeCString(ctx, s);
        JABC_THROW("igno: that .gitignore path is not usable");
    }
    jabc_igno *box = JABC_IGNO_FREE;
    if (box != NULL) JABC_IGNO_FREE = box->next;
    else box = (jabc_igno *)calloc(1, sizeof(jabc_igno));
    if (box == NULL) {
        JS_FreeCString(ctx, s);
        JABC_THROW("igno: out of memory");
    }
    //  STATUS-020: IGNOSetOpen mmaps the named file; a non-OK code is the
    //  absent/unreadable case, which is normal — hand JS a 0 handle.
    u8cs path = {(u8 const *)s, (u8 const *)s + len};
    ok64 o = IGNOSetOpen(&box->set, path);
    JS_FreeCString(ctx, s);
    if (o != OK) {
        JABCignoPark(box);
        return JS_NewFloat64(ctx, 0);
    }
    return JS_NewFloat64(ctx, (double)(size_t)box);
}

//  STATUS-020: _igno_match(h, path, isDir) -> -1 none / 0 negated / 1 ignore.
//  Includes git's dir-prefix rule; the one transient alloc is the cstring.
static JABC_FN(JABCignoMatch) {
    if (argc < 2) JABC_THROW("dog._igno_match(handle, path, isDir)");
    jabc_igno *box = JABCignoHandle(ctx, argv[0]);
    if (box == NULL) JABC_THROW("igno: that match handle is not open");
    size_t len = 0;
    const char *s = JS_ToCStringLen(ctx, &len, argv[1]);
    if (s == NULL) JABC_FAIL;
    b8 is_dir = (argc > 2 && JS_ToBool(ctx, argv[2]) > 0) ? YES : NO;
    u8cs rel = {(u8 const *)s, (u8 const *)s + len};
    i32 d = IGNOSetDecide(&box->set, rel, is_dir);
    JS_FreeCString(ctx, s);
    return JS_NewFloat64(ctx, (double)d);
}

//  STATUS-020: _igno_close(h) -> undefined.  Idempotent: a 0 handle is a
//  no-op, so JS may null its slot and close again (the _ulog_close shape).
static JABC_FN(JABCignoClose) {
    if (argc < 1) JABC_THROW("dog._igno_close(handle)");
    jabc_igno *box = JABCignoHandle(ctx, argv[0]);
    if (box == NULL || box->set.buf == NULL) JABC_UNDEF;  //  0 / already closed
    IGNOSetClose(&box->set);
    JABCignoPark(box);
    JABC_UNDEF;
}

//  STATUS-020: teardown twin — drop the recycled boxes at exit (a box still
//  open when the process ends keeps its mapping, as an unclosed ulog does).
ok64 JABCUninstallIgno(void) {
    while (JABC_IGNO_FREE != NULL) {
        jabc_igno *box = JABC_IGNO_FREE;
        JABC_IGNO_FREE = box->next;
        free(box);
    }
    return OK;
}

ok64 JABCInstallIgno(JSContext *ctx, JSValueConst global) {
    //  JAB-038: the `dog` namespace object.  Created here when this is the
    //  first dog-family install; the mass move of libdog leaves is JAB-038's.
    JSValue dog = JS_GetPropertyStr(ctx, global, "dog");
    if (!JS_IsObject(dog)) {
        JS_FreeValue(ctx, dog);
        dog = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, global, "dog", JS_DupValue(ctx, dog));
    }
    JABC_API_FN(dog, "_igno_open", JABCignoOpen);
    JABC_API_FN(dog, "_igno_match", JABCignoMatch);
    JABC_API_FN(dog, "_igno_close", JABCignoClose);
    JABC_API_END(dog);
    return OK;
}
