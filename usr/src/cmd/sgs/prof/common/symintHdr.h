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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * symintHdr.h -- symbol information interface, Header file.
 *
 * these headers are the definitions used by the set of
 * routines which provide an interface to access symbol
 * information stored in the object file.
 *
 */
	/* protect against multiple inclusion */
#ifndef _SYMINTHDR_H
#define	_SYMINTHDR_H



#include <libelf.h>
#include <sys/elf.h>
#include "dwarf.h"


/*
 * PROF_DEBUG - compilation-time debug flag
 *
 * if this is defined, we include debugging code.
 *
 * there are three levels: none, 1, and 2.
 *
 * none --	(PROF_DEBUG is undefined.)
 * 		no debugging code is generated.
 *
 * 1 --		(PROF_DEBUG == 1.)
 * 		assertion code is generated, only.
 *
 * 2 --		(PROF_DEBUG == anything else.)
 * 		both assertion code and debug() code
 * 		are generated.
 */

#ifndef PROF_DEBUG
#define	NDEBUG
#elif  PROF_DEBUG == 1
#undef NDEBUG
#else	/* == 2, anything else */
#undef NDEBUG
#endif

#include "assert.h"

/*
 * Types
 *
 * - caCOVWORD is used for all entries in the coverage structure.  This
 *   includes the number of basic blocks, each line number in the line
 *   number array, and each execution count in the count array.  The size
 *   (number of bytes) of the coverage structure may be found in the symbol
 *   table.
 */
typedef unsigned char	BYTES_1;
typedef unsigned short	BYTES_2;
typedef unsigned int	BYTES_4;
typedef unsigned long	BYTES_LONG;		/* ``long'' is 4 bytes, too */
typedef BYTES_LONG	caCOVWORD;
typedef unsigned char	BOOLEAN;

/*
 *	Type of base address - used in dump.c and soqueue.c.
 */
typedef unsigned long   TYPE_BASEAD;

/*
 *	Macros
 */
#define	SYMBOL_IS_FUNC(sym_p)	\
	(((sym_p)->ps_dbg.pd_symtag == TAG_subroutine) || \
	((sym_p)->ps_dbg.pd_symtag == TAG_global_subroutine))
#define	SYMBOL_NAME(sym_p)	(sym_p)->ps_dbg.pd_name
#define	SYMBOL_LINES_P(sym_p)	(sym_p)->ps_dbg.pd_line_p
#define	SYMBOL_LASTLN_P(sym_p)	(sym_p)->ps_dbg.pd_lali_p

#define	ISYMBOL_IS_FUNC(sym_p, index)	SYMBOL_IS_FUNC(&((sym_p)[(index)]))
#define	ISYMBOL_NAME(sym_p, index)	SYMBOL_NAME(&((sym_p)[(index)]))
#define	ISYMBOL_LINES(sym_p, index)	SYMBOL_LINES(&((sym_p)[(index)]))
#define	ISYMBOL_LASTLN(sym_p, index)	SYMBOL_LASTLN(&((sym_p)[(index)]))

typedef struct {
	unsigned char	pe_ident[EI_NIDENT];
	Elf32_Half	pe_type;
} PROF_MAGIC;

#define	PROF_MAGIC_FAKE_STRING	"fake prof magic"


#define	COV_PREFIX	"__coverage."


/*
 * ``primitive'' definitions used in
 * subsequent structures.
 */

typedef	unsigned char		LEN1;

typedef	unsigned short		LEN2;

typedef	unsigned long int	LEN4;

typedef	unsigned long int	ADDR;

typedef	LEN2			DBG_TAG;

/*
 * object ``replacing'' a symbol table entry - PROF_SYMBOL.
 *
 * a PROF_SYMBOL will contain or direct us to all the information
 * needed by the profilers, for a given symbol.
 */
typedef struct symint_prof_symbol
	PROF_SYMBOL;

struct symint_prof_symbol {
	Elf32_Sym	ps_sym;		/* normal symbol entry */
};


/*
 * structure to replace LDFILE - PROF_FILE.
 */
typedef struct symint_prof_file
	PROF_FILE;


/*
 * symint_prof_file contains a primary and an (optional) auxiliary
 * symbol table, which we wish to treat as a single logical symbol table.
 * In this logical table, the data from the auxiliary table preceeds that
 * from the primary. Symbol indices start at [0], which is the first item
 * in the auxiliary table if there is one. The sole purpose for this is so
 * that we can treat the combination of .SUNW_ldynsym and .dynsym sections
 * as a logically single entity.
 *
 * Both tables must share the same string table section.
 */
struct symint_prof_file {
	int		pf_fildes;	/* file descriptor */
	Elf		*pf_elf_p;	/* elf descriptor */
	Elf32_Ehdr	*pf_elfhd_p;	/* elf header */
	Elf_Data	*pf_snmdat_p;	/* section names data */
	Elf_Data	*pf_symdat_pri_p; /* primary symbol table data */
	Elf_Data	*pf_symdat_aux_p; /* auxiliary symbol table data */
	Elf32_Word	pf_symstr_ndx;	 /* Section index of string table */
	int		pf_nstsyms;	/* total # symbols in both tables */
	int		pf_nstsyms_aux;	/* # symbols in auxiliary table */

	Elf32_Shdr	*pf_shdarr_p;	/* complete array of section hdrs */

	PROF_SYMBOL	*pf_symarr_p;	/* P_S array w/symbols of interest */
	int		pf_nsyms;	/* number of symbols of interest */
};

#endif /* _SYMINTHDR_H */
