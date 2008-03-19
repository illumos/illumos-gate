/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	A_DOT_OUT_DOT_H
#define	A_DOT_OUT_DOT_H

struct exec {
#ifdef	sun
	unsigned char	a_dynamic:1;	/* has a __DYNAMIC */
	unsigned char	a_toolversion:7; /* version of toolset used to create */
					/*	this file */
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

/*
 * Version of struct exec intended to allow LP64 code to
 * examine a 32-bit definition.
 */
struct exec32 {
#ifdef	sun
	unsigned char	a_dynamic:1;	/* has a __DYNAMIC */
	unsigned char	a_toolversion:7; /* version of toolset used to create */
					/*	this file */
	unsigned char	a_machtype;	/* machine type */
	unsigned short	a_magic;	/* magic number */
#else
	unsigned int	a_magic;	/* magic number */
#endif
	unsigned int	a_text;		/* size of text segment */
	unsigned int	a_data;		/* size of initialized data */
	unsigned int	a_bss;		/* size of uninitialized data */
	unsigned int	a_syms;		/* size of symbol table */
	unsigned int	a_entry;	/* entry point */
	unsigned int	a_trsize;	/* size of text relocation */
	unsigned int	a_drsize;	/* size of data relocation */
};

/*
 * Macros for identifying an a.out format file.
 */
#define	M_SPARC	3			/* runs only on SPARC */
#define	OMAGIC	0407			/* old impure format */
#define	NMAGIC	0410			/* read-only text */
#define	ZMAGIC	0413			/* demand load format */

#define	N_BADMAG(x) \
	((x).a_magic != OMAGIC && (x).a_magic != NMAGIC && \
	(x).a_magic != ZMAGIC)

/*
 * Page size for a.out (used to overide machdep.h definition).
 */
#ifndef	M_SEGSIZE
#define	M_SEGSIZE	0x2000		/* 8k */
#endif

#endif	/* A_DOT_OUT_DOT_H */
