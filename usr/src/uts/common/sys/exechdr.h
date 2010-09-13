/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1995-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_EXECHDR_H
#define	_SYS_EXECHDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/inttypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * format of the exec header
 * known by kernel and by user programs
 */
struct exec {
	unsigned	a_dynamic:1;	/* has a __DYNAMIC */
	unsigned	a_toolversion:7; /* version of toolset used to */
					/* create this file */
	unsigned char	a_machtype;	/* machine type */
	uint16_t 	a_magic;	/* magic number */
	uint32_t	a_text;		/* size of text segment */
	uint32_t	a_data;		/* size of initialized data */
	uint32_t	a_bss;		/* size of uninitialized data */
	uint32_t	a_syms;		/* size of symbol table */
	uint32_t	a_entry;	/* entry point */
	uint32_t	a_trsize;	/* size of text relocation */
	uint32_t	a_drsize;	/* size of data relocation */
};

#define	OMAGIC	0407		/* old impure format */
#define	NMAGIC	0410		/* read-only text */
#define	ZMAGIC	0413		/* demand load format */

/* machine types */

#define	M_OLDSUN2	0	/* old sun-2 executable files */
#define	M_68010		1	/* runs on either 68010 or 68020 */
#define	M_68020		2	/* runs only on 68020 */
#define	M_SPARC		3	/* runs only on SPARC */

#define	TV_SUN2_SUN3	0
#define	TV_SUN4		1

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_EXECHDR_H */
