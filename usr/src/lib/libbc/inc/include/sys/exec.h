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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1985 by Sun Microsystems, Inc.
 */

#ifndef _sys_exec_h
#define _sys_exec_h

/*
 * format of the exec header
 * known by kernel and by user programs
 */
struct exec {
#ifdef sun
	unsigned char	a_dynamic:1;	/* has a __DYNAMIC */
	unsigned char	a_toolversion:7;/* version of toolset used to create this file */
	unsigned char	a_machtype;	/* machine type */
	unsigned short	a_magic;	/* magic number */
#else
	unsigned long	a_magic;	/* magic number */
#endif
	unsigned long	a_text;		/* size of text segment */
	unsigned long	a_data;		/* size of initialized data */
	unsigned long	a_bss;		/* size of uninitialized data */
	unsigned long	a_syms;		/* size of symbol table */
	unsigned long	a_entry;	/* entry point */
	unsigned long	a_trsize;	/* size of text relocation */
	unsigned long	a_drsize;	/* size of data relocation */
};

#define	OMAGIC	0407		/* old impure format */
#define	NMAGIC	0410		/* read-only text */
#define	ZMAGIC	0413		/* demand load format */

/* machine types */

#ifdef sun
#define M_OLDSUN2	0	/* old sun-2 executable files */
#define M_68010		1	/* runs on either 68010 or 68020 */
#define M_68020		2	/* runs only on 68020 */
#define M_SPARC		3	/* runs only on SPARC */

#define TV_SUN2_SUN3	0
#define TV_SUN4		1
#endif sun

#endif /*!_sys_exec_h*/
