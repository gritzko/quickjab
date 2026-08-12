//  JAB-036: jab/ansi.cpp — a pure embedded-JS bundle (SGR codes are just
//  bytes), ported verbatim; no native leaf, no abc/ANSI link.
#include "JABC.h"

static const char *JABC_ANSI_JS =
    "(function (g) {\n"
    "  \"use strict\";\n"
    "  const E = \"\\x1b[\", R = E + \"0m\";\n"
    "  const wrap = (n) => (s) => E + n + \"m\" + s + R;\n"
    "  g.ansi = {\n"
    "    reset: R,\n"
    "    bold: wrap(1), dim: wrap(2), italic: wrap(3), under: wrap(4), rev: wrap(7),\n"
    "    black: wrap(30), red: wrap(31), green: wrap(32), yellow: wrap(33),\n"
    "    blue: wrap(34), magenta: wrap(35), cyan: wrap(36), white: wrap(37),\n"
    "    grey: wrap(90),\n"
    "    sgr: (n) => E + n + \"m\",          // raw escape for any other code\n"
    "  };\n"
    "})(this);\n";

ok64 JABCInstallAnsi(JSContext *ctx, JSValueConst global) {
    (void)ctx;
    (void)global;
    JABCExecute(JABC_ANSI_JS);
    return OK;
}
