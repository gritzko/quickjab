/*  JAB-035: the default jsrc pack, embedded verbatim between two symbols
    (jsrcpack.cpp reads them).  JABC_JSRC_PACK_FILE is the cmake-built path.  */
#if defined(__APPLE__)
# define JABC_SYM(n) _##n
	.const
#else
# define JABC_SYM(n) n
	.section .rodata
#endif
	.balign 16
	.globl JABC_SYM(JABC_JSRC_PACK_HEAD)
JABC_SYM(JABC_JSRC_PACK_HEAD):
	.incbin JABC_JSRC_PACK_FILE
	.globl JABC_SYM(JABC_JSRC_PACK_TAIL)
JABC_SYM(JABC_JSRC_PACK_TAIL):

#if defined(__linux__)
	.section .note.GNU-stack,"",@progbits
#endif
