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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * SunOS 4.x a.out format -- 32-bit sparc only
 */

#ifndef _A_OUT_H
#define	_A_OUT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__sparcv8)

/* contents of <sys/exec.h> included */

/*
 * format of the exec header
 * known by kernel and by user programs
 */
struct exec {
	unsigned char	a_dynamic:1;	/* has a __DYNAMIC */
	unsigned char	a_toolversion:7;
			/* version of toolset used to create this file */
	unsigned char	a_machtype;	/* machine type */
	unsigned short	a_magic;	/* magic number */
	unsigned int	a_text;		/* size of text segment */
	unsigned int	a_data;		/* size of initialized data */
	unsigned int	a_bss;		/* size of uninitialized data */
	unsigned int	a_syms;		/* size of symbol table */
	unsigned int	a_entry;	/* entry point */
	unsigned int	a_trsize;	/* size of text relocation */
	unsigned int	a_drsize;	/* size of data relocation */
};

#define	OMAGIC	0407		/* old impure format */
#define	NMAGIC	0410		/* read-only text */
#define	ZMAGIC	0413		/* demand load format */

/* machine types */

#define	M_OLDSUN2	0	/* old sun-2 executable files */
#define	M_SPARC		3	/* runs only on SPARC */

#define	TV_SUN2_SUN3	0
#define	TV_SUN4		1
/* end <sys/exec.h> */

/*
 * memory management parameters
 */

#define	PAGSIZ		0x02000
#define	SEGSIZ		PAGSIZ
#define	OLD_PAGSIZ	0x00800	/*  Page   size under Release 2.0 */
#define	OLD_SEGSIZ	0x08000	/* Segment size under Release 2.0 */

/*
 * returns 1 if an object file type is invalid, i.e., if the other macros
 * defined below will not yield the correct offsets.  Note that a file may
 * have N_BADMAG(x) = 0 and may be fully linked, but still may not be
 * executable.
 */

#define	N_BADMAG(x) \
	((x).a_magic != OMAGIC && (x).a_magic != NMAGIC && \
	(x).a_magic != ZMAGIC)

/*
 * relocation parameters. These are architecture-dependent
 * and can be deduced from the machine type.  They are used
 * to calculate offsets of segments within the object file;
 * See N_TXTOFF(x), etc. below.
 */

#define	N_PAGSIZ(x) \
	((x).a_machtype == M_OLDSUN2? OLD_PAGSIZ : PAGSIZ)
#define	N_SEGSIZ(x) \
	((x).a_machtype == M_OLDSUN2? OLD_SEGSIZ : SEGSIZ)

/*
 * offsets of various sections of an object file.
 */

#define	N_TXTOFF(x) \
	/* text segment */ \
	((x).a_machtype == M_OLDSUN2 \
	? ((x).a_magic == ZMAGIC ? N_PAGSIZ(x) : sizeof (struct exec)) \
	: ((x).a_magic == ZMAGIC ? 0 : sizeof (struct exec)))

#define	N_DATOFF(x)   /* data segment */	\
	(N_TXTOFF(x) + (x).a_text)

#define	N_TRELOFF(x)  /* text reloc'n */	\
	(N_DATOFF(x) + (x).a_data)

#define	N_DRELOFF(x) /* data relocation */	\
	(N_TRELOFF(x) + (x).a_trsize)

#define	N_SYMOFF(x) \
	/* symbol table */ \
	(N_TXTOFF(x)+(x).a_text+(x).a_data+(x).a_trsize+(x).a_drsize)

#define	N_STROFF(x) \
	/* string table */ \
	(N_SYMOFF(x) + (x).a_syms)

/*
 * Macros which take exec structures as arguments and tell where the
 * various pieces will be loaded.
 */

#define	_N_BASEADDR(x) \
	(((x).a_magic == ZMAGIC) && ((x).a_entry < N_PAGSIZ(x)) ? \
	    0 : N_PAGSIZ(x))

#define	N_TXTADDR(x) \
	((x).a_machtype == M_OLDSUN2 ? N_SEGSIZ(x) : _N_BASEADDR(x))

#define	N_DATADDR(x) \
	(((x).a_magic == OMAGIC)? (N_TXTADDR(x)+(x).a_text) \
	: (N_SEGSIZ(x)+((N_TXTADDR(x)+(x).a_text-1) & ~(N_SEGSIZ(x)-1))))

#define	N_BSSADDR(x)  (N_DATADDR(x)+(x).a_data)

/*
 * Format of a relocation datum.
 */

/*
 * Sparc relocation types
 */

enum reloc_type
{
	RELOC_8,	RELOC_16,	RELOC_32,	/* simplest relocs    */
	RELOC_DISP8,	RELOC_DISP16,	RELOC_DISP32,	/* Disp's (pc-rel)    */
	RELOC_WDISP30,	RELOC_WDISP22,		/* SR word disp's	*/
	RELOC_HI22,	RELOC_22,		/* SR 22-bit relocs   */
	RELOC_13,	RELOC_LO10,		/* SR 13&10-bit relocs */
	RELOC_SFA_BASE,	RELOC_SFA_OFF13,		/* SR S.F.A. relocs   */
	RELOC_BASE10,	RELOC_BASE13,	RELOC_BASE22,	/* base_relative pic */
	RELOC_PC10,	RELOC_PC22,			/* special pc-rel pic */
	RELOC_JMP_TBL,				/* jmp_tbl_rel in pic */
	RELOC_SEGOFF16,				/* ShLib offset-in-seg */
	RELOC_GLOB_DAT, RELOC_JMP_SLOT, RELOC_RELATIVE /* rtld relocs	*/
};

/*
 * Format of a relocation datum.
 */

struct reloc_info_sparc	/* used when header.a_machtype == M_SPARC */
{
	unsigned int	r_address;
				/* relocation addr (offset in segment) */
	unsigned int	r_index   :24;	/* segment index or symbol index */
	unsigned int	r_extern  : 1;	/* if F, r_index==SEG#; if T, SYM idx */
	int			  : 2;	/* <unused> */
	enum reloc_type r_type    : 5;	/* type of relocation to perform */
	int		r_addend;	/* addend for relocation value */
};



/*
 * Format of a symbol table entry
 */
struct	nlist {
	union {
		char	*n_name;	/* for use when in-core */
		int	n_strx;		/* index into file string table */
	} n_un;
	unsigned char	n_type;		/* type flag (N_TEXT,..)  */
	char	n_other;		/* unused */
	short	n_desc;			/* see <stab.h> */
	unsigned int	n_value;	/* value of symbol (or sdb offset) */
};

/*
 * Simple values for n_type.
 */
#define	N_UNDF	0x0		/* undefined */
#define	N_ABS	0x2		/* absolute */
#define	N_TEXT	0x4		/* text */
#define	N_DATA	0x6		/* data */
#define	N_BSS	0x8		/* bss */
#define	N_COMM	0x12		/* common (internal to ld) */
#define	N_FN	0x1e		/* file name symbol */

#define	N_EXT	01		/* external bit, or'ed in */
#define	N_TYPE	0x1e		/* mask for all the type bits */

/*
 * Dbx entries have some of the N_STAB bits set.
 * These are given in <stab.h>
 */
#define	N_STAB	0xe0		/* if any of these bits set, a dbx symbol */

/*
 * Format for namelist values.
 */
#define	N_FORMAT	"%08x"

/*
 * secondary sections.
 * this stuff follows the string table.
 * not even its presence or absence is noted in the
 * exec header (?). the secondary header gives
 * the number of sections. following it is an
 * array of "extra_nsects" int's which give the
 * sizeof of the individual sections. the presence of
 * even the header is optional.
 */

#define	EXTRA_MAGIC	1040		/* taxing concept  */
#define	EXTRA_IDENT	0		/* ident's in 0th extra section */

struct extra_sections {
		int	extra_magic;		/* should be EXTRA_MAGIC */
		int	extra_nsects;		/* number of extra sections */
};

#endif	/* defined(__sparcv8) */

#ifdef __cplusplus
}
#endif

#endif /* _A_OUT_H */
