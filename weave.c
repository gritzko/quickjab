//  JAB-036: weave.c — jab/weave.hpp has NO backing C API any more: DIS-082
//  retired the columnar 'W' weave for CFOLD's append-only 'V' blob, dog/WEAVE.h
//  is gone from libdog, and jab installs no weave leaf (cont.cpp never calls
//  JABCWeaveInstall, so weave.hpp is dead text that no longer compiles).
//  The JABCweave test is test/weave.js — the CFOLD family, ported in cfold.c.
//  This install stays a no-op until a WEAVE C API exists to bind.
#include "JABC.h"

ok64 JABCInstallWeave(JSContext *ctx, JSValueConst global) {
    (void)ctx;
    (void)global;
    return OK;
}
