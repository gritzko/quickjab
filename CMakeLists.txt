cmake_minimum_required(VERSION 3.20)
project(quickjab C)

#  JAB-036: the plain-C port of the jab runtime onto quickjs-ng.  The engine is
#  a pinned vendored snapshot under qjs/; dog+abc are the in-tree dog/
#  submodule (libdog), the API suite is the in-tree test/ submodule (shared
#  with jab — its jsrcpack.js case requires `../jsrcpack.js`, so the packer
#  pair jsrcpack.js/.S sits at the repo root in BOTH).  STANDALONE: the jab
#  tree is not referenced at all.
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
set(CMAKE_EXPORT_COMPILE_COMMANDS on)
set(DOG_BIN_DIR ${CMAKE_BINARY_DIR}/bin)
include(CTest)

#  The API suite is the in-tree test/ submodule, SHARED with jab (same cases,
#  same names): jab mounts the very same repo at its test/.
set(JAB_TEST ${CMAKE_CURRENT_SOURCE_DIR}/test)
set(DOG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dog)
set(ABC_DIR ${DOG_DIR}/abc)

#  curl is a hard dependency of the build (abc carries CURL.c); named here so a
#  missing libcurl-dev shows on the first lines of configure output.
find_package(CURL REQUIRED)

#  JAB-005: abc is NESTED in dog; dog's guarded add_subdirectory(abc) provides
#  abc-core, and `-I${DOG_DIR}` resolves "abc/...".
if(NOT TARGET dog)
    add_subdirectory(${DOG_DIR} dog)
endif()

#  The engine: vendored quickjs-ng (qjs/VERSION.pin).  Its CMakeLists owns its
#  own flags; we only consume the `qjs` library target.
add_subdirectory(qjs)

#  SODIUM_INCLUDE_DIR is cached by abc's find_path; jab TUs reach sodium
#  headers via ABC.h -> NACL.h.
#  "dog/..." resolves via -I${CMAKE_CURRENT_SOURCE_DIR} (dog is in-tree now),
#  "abc/..." via -I${DOG_DIR}.
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DOG_DIR}
    ${SODIUM_INCLUDE_DIR}
)

#  abc/POL.c and NET/TCP/UDP.c are stripped from abc-core (grouped with CURL);
#  abc/FSW.c is in no abc library either (JAB-031) — all compiled straight in,
#  as jab does, for the socket/loop/watcher leaves.
set(QUICKJAB_SRC
    main.c arg.c utf8.c
    io.c buf.c console.c ansi.c require.c codec.c zip.c uri.c tty.c
    jsrcpack.c cont.c tok.c
    heap.c hash.c hit.c index.c pup.c hunk.c pack.c git.c ulog.c cfold.c weave.c
    igno.c
    pol.c ${ABC_DIR}/POL.c
    net.c ${ABC_DIR}/NET.c ${ABC_DIR}/TCP.c ${ABC_DIR}/UDP.c
    fsw.c ${ABC_DIR}/FSW.c)

#  JS-122: rpmalloc 1.4.5 (one vendored .c) as the JS runtime's allocator.
#  OFF = plain musl, the leg ASAN/leak CI needs (rpmalloc masks poisoning).
option(QJAB_RPMALLOC "JS-122: rpmalloc as the JS runtime allocator" ON)
if(QJAB_RPMALLOC)
    list(APPEND QUICKJAB_SRC rpmalloc.c)
endif()

add_executable(quickjab ${QUICKJAB_SRC})
if(QJAB_RPMALLOC)
    target_compile_definitions(quickjab PRIVATE QJAB_RPMALLOC)
endif()
target_link_libraries(quickjab qjs dog abc-core ${sodium})
set_target_properties(quickjab PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${DOG_BIN_DIR})

#  JAB-035: -DJAB_JSRC=<dir> embeds that tree as the DEFAULT jsrc pack.  The
#  packer is the binary itself, so it needs a WORKING io+require — hence the
#  extra gate: OFF until those modules land.  Turn both on together:
#      cmake -DJAB_JSRC=<dir> -DQUICKJAB_JSRC_PACK=ON
option(QUICKJAB_JSRC_PACK
    "JAB-036: embed a default jsrc pack (needs a working io+require; OFF until then)"
    OFF)
if(JAB_JSRC AND QUICKJAB_JSRC_PACK)
    enable_language(ASM)
    get_filename_component(JAB_JSRC_DIR "${JAB_JSRC}" ABSOLUTE)
    if(NOT IS_DIRECTORY ${JAB_JSRC_DIR})
        message(FATAL_ERROR "JAB_JSRC is not a directory: ${JAB_JSRC_DIR}")
    endif()
    set(JAB_PACK ${CMAKE_CURRENT_BINARY_DIR}/jsrc.pack)
    add_executable(quickjab_boot ${QUICKJAB_SRC})
    if(QJAB_RPMALLOC)
        target_compile_definitions(quickjab_boot PRIVATE QJAB_RPMALLOC)
    endif()
    target_link_libraries(quickjab_boot qjs dog abc-core ${sodium})
    file(GLOB_RECURSE JAB_JSRC_FILES CONFIGURE_DEPENDS ${JAB_JSRC_DIR}/*)
    list(FILTER JAB_JSRC_FILES EXCLUDE REGEX "^${CMAKE_BINARY_DIR}/")

    #  The packer runs as an EXPLICIT path and requires nothing: a build box
    #  has no jsrc/ to climb to.
    add_custom_command(OUTPUT ${JAB_PACK}
        COMMAND quickjab_boot ${CMAKE_CURRENT_SOURCE_DIR}/jsrcpack.js
            ${JAB_JSRC_DIR} ${JAB_PACK}
        DEPENDS quickjab_boot ${CMAKE_CURRENT_SOURCE_DIR}/jsrcpack.js
            ${JAB_JSRC_FILES}
        COMMENT "JAB-035: packing ${JAB_JSRC_DIR}")
    add_custom_target(quickjab_jsrc_pack DEPENDS ${JAB_PACK})
    target_sources(quickjab PRIVATE jsrcpack.S)
    add_dependencies(quickjab quickjab_jsrc_pack)
    set_source_files_properties(jsrcpack.S PROPERTIES
        OBJECT_DEPENDS ${JAB_PACK})
    target_compile_definitions(quickjab PRIVATE
        JABC_JSRC_PACK JABC_JSRC_PACK_FILE="${JAB_PACK}")
endif()

#  ---------------------------------------------------------------------------
#  jab's API suite, UNCHANGED: same test names, same TIMEOUTs and properties,
#  the .js files read in place from ${JAB_TEST}.  jab's jabc_test.cpp harness is
#  NOT here: it is a C++ TU built against the JSC C-API internals.
#  ---------------------------------------------------------------------------

# End-to-end: the binary runs an inline Buf+utf8 round-trip; any failed
# assertion throws, which the runner turns into a non-zero exit (CTest fails).
add_test(NAME JABCe2e COMMAND quickjab --eval
    "let b=io.buf(16);b.feedStr('hié');if(b.size!==4)throw 'size';if(utf8.Decode(b.data())!=='hié')throw 'roundtrip';if(b.take(1)[0]!==104)throw 'take';if(b.size!==3)throw 'consume'")

# Container bindings (abc.* HEAP/HASH over all lanes) — each .js throws on a
# failed assertion, which the runner turns into a non-zero exit.
add_test(NAME JABCheap COMMAND quickjab ${JAB_TEST}/heap.js)
add_test(NAME JABChash COMMAND quickjab ${JAB_TEST}/hash.js)
add_test(NAME JABCmmap COMMAND quickjab ${JAB_TEST}/mmap.js)
add_test(NAME JABCmmapfd COMMAND quickjab ${JAB_TEST}/mmapfd.js)
# JAB-033: a mapping pins a VMA (and, for "rw", a booked fd) that the byte-only
# collector cannot see; both counts must plateau over a map-and-drop loop.
add_test(NAME JABCmmapvma COMMAND quickjab ${JAB_TEST}/mmapvma.js)
add_test(NAME JABCstat COMMAND quickjab ${JAB_TEST}/stat.js)
add_test(NAME JABCreaddir COMMAND quickjab ${JAB_TEST}/readdir.js)
add_test(NAME JABCchdir COMMAND quickjab ${JAB_TEST}/chdir.js)
add_test(NAME JABCsha COMMAND quickjab ${JAB_TEST}/sha.js)
add_test(NAME JABChit COMMAND quickjab ${JAB_TEST}/hit.js)
add_test(NAME JABCindex COMMAND quickjab ${JAB_TEST}/index.js)
# DOG-032: the sized memtable — same rows, same answers at 4 KiB and 1 MiB.
add_test(NAME JABCpupMem COMMAND quickjab ${JAB_TEST}/pupmem.js)
add_test(NAME JABChunk COMMAND quickjab ${JAB_TEST}/hunk.js)
add_test(NAME JABCtok COMMAND quickjab ${JAB_TEST}/tok.js)
add_test(NAME JABCuri COMMAND quickjab ${JAB_TEST}/uri.js)
add_test(NAME JABCcodec COMMAND quickjab ${JAB_TEST}/codec.js)
add_test(NAME JABCrequire COMMAND quickjab ${JAB_TEST}/require.js)
add_test(NAME JABCpack COMMAND quickjab ${JAB_TEST}/pack.js)
add_test(NAME JABCpackidx COMMAND quickjab ${JAB_TEST}/packidx.js)
#  JAB-020: the one-call stream ingest (git.pack) over a synthetic pack.
add_test(NAME JABCrepack COMMAND quickjab ${JAB_TEST}/repack.js)
add_test(NAME JABCgit COMMAND quickjab ${JAB_TEST}/git.js)
add_test(NAME JABCulog COMMAND quickjab ${JAB_TEST}/ulog.js)
# ULOG-002/001: native ULOGOpen/AppendAt/Close bindings (booked log + sidecar).
add_test(NAME JABCulogBook COMMAND quickjab ${JAB_TEST}/ulog_book.js)
add_test(NAME JABCweave COMMAND quickjab ${JAB_TEST}/weave.js)
# STATUS-020: the three dog._igno_* leaves.  Gated like JABCzip — the shared
# .js is the jab leg's to land, and jab is READ-ONLY here.
if(EXISTS ${JAB_TEST}/igno.js)
    add_test(NAME JABCigno COMMAND quickjab ${JAB_TEST}/igno.js)
    set_tests_properties(JABCigno PROPERTIES
        ENVIRONMENT "LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan.supp")
endif()
# JAB-008: binding-boundary BASS rewind — a 256KB fold x1500 in one process
# (pre-fix the un-rewound arena drained at ~iter 960: "out full?").
add_test(NAME JABCbass COMMAND quickjab ${JAB_TEST}/bass.js)
# JAB-008: probe sized to finish in ~7s post-fix; 10s cap is a hard order.
set_tests_properties(JABCbass PROPERTIES TIMEOUT 10)
add_test(NAME JABCansi COMMAND quickjab ${JAB_TEST}/ansi.js)
add_test(NAME JABCconsole COMMAND quickjab ${JAB_TEST}/console.js)
add_test(NAME JABCtty COMMAND quickjab ${JAB_TEST}/tty.js)
add_test(NAME JABCpol COMMAND quickjab ${JAB_TEST}/pol.js)
# JAB-031: fsw — arm a temp dir, create a file, drain the name (inotify).
add_test(NAME JABCfsw COMMAND quickjab ${JAB_TEST}/fsw.js)
set_tests_properties(JABCfsw PROPERTIES TIMEOUT 20)
add_test(NAME JABCnet COMMAND quickjab ${JAB_TEST}/net.js)
add_test(NAME JABCnetGrow COMMAND quickjab ${JAB_TEST}/netgrow.js)
# JS-035: the zip test is a beagle-owned file — absent standalone, so gated.
if(EXISTS ${CMAKE_SOURCE_DIR}/test/js/get/zip.js)
    add_test(NAME JABCzip COMMAND quickjab ${CMAKE_SOURCE_DIR}/test/js/get/zip.js)
    set_tests_properties(JABCzip PROPERTIES
        ENVIRONMENT "LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan.supp")
endif()

# QJAB-002 mode 1: a PACKED build is bundle-ONLY — the bundle's main.js owns
# argv, so an external `.js` entry never runs and a missing one is the bundle's
# error, not the runtime's.  The three tests that assert that ENTRY path
# (argv, the bareword `here` idiom, the failed-open teardown) are unpacked-only.
set(JAB_SCRIPT_ENTRY ON)
if(JAB_JSRC AND QUICKJAB_JSRC_PACK)
    set(JAB_SCRIPT_ENTRY OFF)
endif()

# Script argv reaches JS: run a generated script with a tail of args and grep the
# JSON it logs to stderr (`args` + Node-shaped `process.argv`) — JS-015.
if(JAB_SCRIPT_ENTRY)
    add_test(NAME JABCargv
        COMMAND ${JAB_TEST}/run-015.sh $<TARGET_FILE:quickjab>)

    # JAB-001: `quickjab <bareword>` resolves via the upward `jsrc/`-scan and
    # patches process.argv[1] (the `here` idiom), distinct from explicit-path eval.
    add_test(NAME JABCrequireJsrc
        COMMAND ${JAB_TEST}/run-055.sh $<TARGET_FILE:quickjab>)
endif()

# JAB-035: the pack FORMAT (preamble + a deterministic ustar) over the very
# packer cmake runs at build time — every build, packed or not.
add_test(NAME JABCjsrcPack COMMAND quickjab ${JAB_TEST}/jsrcpack.js)

# JAB-035: the floor end-to-end, in a scratch HOME (no jsrc anywhere, and the
# real ~/.cache untouched).
if(JAB_JSRC AND QUICKJAB_JSRC_PACK)
    #  QJAB-002: a packed build is bundle-ONLY, so the floor is asserted in
    #  `--bundle` mode — a user jsrc/ never wins (jab keeps the STACK reading).
    add_test(NAME JABCjsrcFloor
        COMMAND ${JAB_TEST}/run-035.sh $<TARGET_FILE:quickjab> --bundle)
else()
    add_test(NAME JABCjsrcNoFloor
        COMMAND ${JAB_TEST}/run-035.sh $<TARGET_FILE:quickjab> --nofloor)
endif()

# GIT-030: the git ODB waist ladder; gated — the test lands with the jab tree.
if(EXISTS ${JAB_TEST}/gitodb.js)
    add_test(NAME JABCgitOdb COMMAND quickjab ${JAB_TEST}/gitodb.js)
endif()

# JS-054: error-exit paths must run the same teardown as success, so a failed
# script-file open frees the JS context.  Deliberately NOT in the suppression
# group below — the broad suppression would mask the leak.  Script-entry, so
# unpacked-only (see JAB_SCRIPT_ENTRY): a bundle answers a bad path itself.
if(JAB_SCRIPT_ENTRY)
    add_test(NAME JABCleakExit
        COMMAND ${JAB_TEST}/run-054.sh $<TARGET_FILE:quickjab>)
endif()

# JS-064: a bareword run (the resident be/ loop) must be LSan-clean on the
# normal exit.  Like JABCleakExit, NOT in the suppression group.
add_test(NAME JABCleakLoop
    COMMAND ${JAB_TEST}/run-064.sh $<TARGET_FILE:quickjab>)

# jab's group suppresses JavaScriptCore's lazily-initialised singletons; the
# quickjs engine frees everything on JS_FreeRuntime, so the file is inherited
# only to keep the property set identical to jab's (JABCtestCpp is absent).
set(JABC_SUPPRESSED JABCe2e JABCheap JABChash JABCmmap JABCstat JABCreaddir JABCsha JABChit JABCindex JABCpupMem JABChunk JABCtok JABCuri JABCcodec JABCrequire JABCpack JABCpackidx JABCrepack JABCgit JABCulog JABCulogBook JABCweave JABCbass JABCansi JABCconsole JABCtty JABCpol JABCfsw JABCnet JABCjsrcPack)
if(JAB_SCRIPT_ENTRY)
    list(APPEND JABC_SUPPRESSED JABCargv JABCrequireJsrc)
endif()
set_tests_properties(${JABC_SUPPRESSED} PROPERTIES
    ENVIRONMENT "LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan.supp")

# The BUNDLED TREE's own suites.  A -DJAB_JSRC tree may ship `test/*/run.sh`
# (beagle-lite does): each is a standalone shell suite that takes the runtime in
# $LITEJAB, so register one ctest per dir pointed at the binary we just packed
# it into.  No bundle, no tests — and a tree without `test/` registers nothing.
if(JAB_JSRC AND QUICKJAB_JSRC_PACK)
    file(GLOB JAB_JSRC_SUITES ${JAB_JSRC_DIR}/test/*/run.sh)
    foreach(SUITE ${JAB_JSRC_SUITES})
        get_filename_component(SUITE_DIR ${SUITE} DIRECTORY)
        get_filename_component(SUITE_NAME ${SUITE_DIR} NAME)
        add_test(NAME JSRC${SUITE_NAME} COMMAND sh ${SUITE})
        #  They build git fixtures under ~/tmp and drive real ptys; the binary
        #  under test is THIS build's, never a `jab` off the PATH.
        set_tests_properties(JSRC${SUITE_NAME} PROPERTIES
            ENVIRONMENT "LITEJAB=$<TARGET_FILE:quickjab>" TIMEOUT 600)
    endforeach()
endif()
