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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"


/* * * * * *
 * symintHdr.h -- symbol information interface, Header file.
 * 
 * these headers are the definitions used by the set of
 * routines which provide an interface to access symbol
 * information stored in the object file.
 * 
 */
	/* protect against multiple inclusion */
#ifndef SYMINT_HDR
#define SYMINT_HDR



#include "libelf.h"
#include "sys/elf.h"
#include "dwarf.h"



/* * * * * *
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
#	define NDEBUG
#	define debug(s)
#	define debugsd(s1,d1)
#	define debugp1(s)
#	define debugp2(s,t)
#	define debugp3(s,t,u)
#	define debugsn(s,t,u)

#elif  PROF_DEBUG == 1 
#	undef  NDEBUG
#	define debug(s1)
#	define debugsd(s1,d1)
#	define debugp1(s1)
#	define debugp2(s1,s2)
#	define debugp3(s1,s2,s3)

#else	/* == 2, anything else */
#	undef  NDEBUG
#	define debug(s1)		s1
#	define debugsd(s1,d1)		fprintf(stderr,"%s%d",s1,d1);
#	define debugp1(s1)		fprintf(stderr,"%s",s1);
#	define debugp2(s1,s2)		fprintf(stderr,"%s%s",s1,s2);
#	define debugp3(s1,s2,s3)	fprintf(stderr,"%s%s%s",s1,s2,s3);

#endif

#include "assert.h"



/* * * * * *
 * TARGETPROFILER - #define symbol to indicate whether
 * the target profiler is ``prof'' or ``lprof''.
 * 
 * values:
 * 	2 => prof
 * 	1 => lprof
 */


	/* default: prof. */
#ifndef TARGETPROFILER
# define TARGETPROFILER	2
#endif

#if  TARGETPROFILER == 2
#  define isPROF	1
#  define whenPROF(s)	s
#  undef  isLPROF
#  define whenLPROF(s)
#else
#  define isLPROF	1
#  define whenLPROF(s)	s
#  undef  isPROF
#  define whenPROF(s)
#endif




/*
*	Types
*
*	- caCOVWORD is used for all entries in the coverage structure.  This
*	includes the number of basic blocks, each line number in the line
*	number array, and each execution count in the count array.  The size
*	(number of bytes) of the coverage structure may be found in the symbol
*	table.
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

#define SYMBOL_IS_FUNC(sym_p)	\
	(((sym_p)->ps_dbg.pd_symtag == TAG_subroutine)		\
	|| ((sym_p)->ps_dbg.pd_symtag == TAG_global_subroutine))
#define SYMBOL_NAME(sym_p)	(sym_p)->ps_dbg.pd_name
#define SYMBOL_LINES_P(sym_p)	(sym_p)->ps_dbg.pd_line_p
#define SYMBOL_LASTLN_P(sym_p)	(sym_p)->ps_dbg.pd_lali_p

#define ISYMBOL_IS_FUNC(sym_p, index)	SYMBOL_IS_FUNC(&((sym_p)[(index)]))
#define ISYMBOL_NAME(sym_p, index)	SYMBOL_NAME(&((sym_p)[(index)]))
#define ISYMBOL_LINES(sym_p, index)	SYMBOL_LINES(&((sym_p)[(index)]))
#define ISYMBOL_LASTLN(sym_p, index)	SYMBOL_LASTLN(&((sym_p)[(index)]))

typedef struct {
	unsigned char   pe_ident[EI_NIDENT];
	Elf32_Half      pe_type;
} PROF_MAGIC;

#define PROF_MAGIC_FAKE_STRING	"fake prof magic"


#define COV_PREFIX	"__coverage."




/* * * * * *
 * ``primitive'' definitions used in
 * subsequent structures.
 */

typedef	unsigned char		LEN1;

typedef	unsigned short		LEN2;

typedef	unsigned long int	LEN4;

typedef	unsigned long int	ADDR;

typedef	LEN2			DBG_TAG;



#ifdef isLPROF

/* * * * * *
 * structure recording debug info for a symbol - PROF_DEBUGE.
 * (PROFiling DEBUG data Entry.)
 * (also, definitions related to PROF_DEBUGE..)
 * 
 * DEBUGE - this structure records debugging information
 * relevant to profiling - specifically to Lprof.
 * This information is distilled from the debug section
 * and line section entries.
 * 
 * LINE - this structure captures line information for
 * the symbol.  it is incorporated into DEBUGE.
 */
typedef LEN4	PROF_LINE;

typedef struct symint_prof_debuge
	PROF_DEBUGE;

/* ***> ** Hm.. i don't think many of these fields are needed.
	** pdname, pd_size are available from symtab entry;
	** pd_lowpc, pd_highpc would be used merely to get pd_line/lali_p.
	** Hence, we'll go with less and see what happens! rjp Nov-23-1988

struct symint_prof_debuge {
	char		*pd_name;	?* symbol name or file name *?
	DBG_TAG		pd_symtag;	?* symbol tag *?
	union {
		ADDR	pd_lowpc;	?* entry address or NULL (inline) *?
		LEN4	pd_size;	?* struct size (coverage structure) *?
	} u;
	ADDR		pd_highpc;	?* exit address or NULL *?
	PROF_LINE	*pd_line_p;	?* pointer into line section for this
					   symbol (null if debug level < 2)*?
	PROF_LINE	*pd_lali_p;	?* pointer to last line for function
					   symbol (null if debug level < 2)*?
	PROF_DEBUGE	*pd_file_p;	?* pointer to next file symbol,
					   for files, OR pointer to owner
					   file (otherwise) *?
};
** ***> */

struct symint_prof_debuge {
	char		*pd_name;	/* symbol name or file name */

	DBG_TAG		pd_symtag;	/* symbol tag */

	PROF_LINE	*pd_line_p;	/* pointer to copy of line section
					for this symbol - actual line number
					section is not aligned.
					(null if debug level < 2) */
	PROF_LINE	*pd_lali_p;	/* pointer to last line for function
					   symbol (null if debug level < 2)*/
	PROF_DEBUGE	*pd_file_p;	/* pointer to next file symbol,
					   for files, OR pointer to owner
					   file (otherwise) */
};

#endif

/* * * * * *
 * object ``replacing'' a symbol table entry - PROF_SYMBOL.
 * 
 * a PROF_SYMBOL will contain or direct us to all the information
 * needed by the profilers, for a given symbol.
 */
typedef struct symint_prof_symbol
	PROF_SYMBOL;

struct symint_prof_symbol {
#ifdef isLPROF
		PROF_DEBUGE	ps_dbg;		/* symbol debug entry */
#endif
		Elf32_Sym	ps_sym;		/* normal symbol entry */
};




/* * * * * *
 * structure to replace LDFILE - PROF_FILE.
 */
typedef struct symint_prof_file
	PROF_FILE;

struct symint_prof_file {
	int		pf_fildes;	/* file descriptor */
	Elf		*pf_elf_p;	/* elf descriptor */
	Elf32_Ehdr	*pf_elfhd_p;	/* elf header */
	Elf32_Shdr	*pf_snmshd_p;	/* section names header */
	Elf_Data	*pf_snmdat_p;	/* section names data */
	Elf32_Shdr	*pf_symshd_p;	/* symbol table header */
	Elf_Data	*pf_symdat_p;	/* symbol table data */
	Elf32_Shdr	*pf_strshd_p;	/* symbol strings header */
	Elf_Data	*pf_strdat_p;	/* symbol strings data */
	char		*pf_symstr_p;	/* symbol table strings */
	int		pf_nstsyms;	/* number of symbols in symbol table */
	Elf32_Shdr	*pf_debugshd_p;	/* debug header */
	Elf_Data	*pf_debugdat_p;	/* debug data */
	Elf32_Shdr	*pf_lineshd_p;	/* line header */
	Elf_Data	*pf_linedat_p;	/* line data */

	Elf32_Shdr	*pf_shdarr_p;	/* complete array of section hdrs */

	PROF_SYMBOL	*pf_symarr_p;	/* P_S array w/symbols of interest */
	int		pf_nsyms;	/* number of symbols of interest */
};






#endif
