/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib_strbuf.h - definitions for routines which use the common string buffers
 */

#include <ntp_types.h>

/*
 * Sizes of things
 */
#define	LIB_NUMBUFS	20
#define	LIB_BUFLENGTH	80

/*
 * Macro to get a pointer to the next buffer
 */
#define	LIB_GETBUF(buf) \
	do { \
		if (!lib_inited) \
			init_lib(); \
		buf = &lib_stringbuf[lib_nextbuf][0]; \
		if (++lib_nextbuf >= LIB_NUMBUFS) \
			lib_nextbuf = 0; \
	} while (0)

extern char lib_stringbuf[LIB_NUMBUFS][LIB_BUFLENGTH];
extern int lib_nextbuf;
extern int lib_inited;

void init_lib P((void));
