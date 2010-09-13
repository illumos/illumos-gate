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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	File: symintLoad.c
 *	Date: 12/15/88
 *
 *	This file provides code to build the profiling symbol array
 *	(array of PROF_SYMBOL).  This array contains all of the
 *	symbol table information plus selected debug information for
 *	each file and each function that has a coverage array.
 *
 *	The symbol table contains entries for every file, every
 *	function, and every coverage array.  The debug information
 *	has corresponding entries except that there are no entries
 *	for the coverage arrays.  (This may change later.)
 *
 *	The algorithm for building the profiling symbol array
 *	consists of scanning the symbol table for file, function,
 *	and coverage array entries and building an entry for each.
 *	The construction of an entry is constrained by the
 *	following factors:
 *
 *		- An entry is built for every file.
 *
 *		- An entry is built for a function only if there
 *		is a corresponding coverage array for the function.
 *
 *		- Entries must be ordered in the sense that each
 *		non-file entry points to its owner file and each
 *		file entry points to the next file (or null).
 *
 *		- The assembler specification (see C Issue 5 3B2
 *		Assembler System Test Specification by Howe, p. 28)
 *		states that all local symbols follow their file
 *		symbol in the symbol table.  This allows us to relate
 *		a function and its coverage array to the file that
 *		contains it.
 *
 *		- For each symbol included in the profiling symbol
 *		array, all corresponding symbol table information must
 *		be present together with selected debug information.
 *		Therefore, the correspondence between a symbol table
 *		entry and a debug entry must be established.
 *
 *		- Although duplicate (static) function names may appear,
 *		the names are unique within a given file.  Also, the
 *		value (address) of each function is included in both
 *		the symbol table information and the debug information.
 *		This provides a verifable correspondence between these
 *		information sets.
 *
 */

#include "string.h"
#include "symint.h"
#include "debug.h"

static PROF_FILE	*profPtr;

/* LINTED: set but not used */
static int	prstsym_size;	/* size of a symbol table symbol */

static PROF_SYMBOL	*prsym_list_p = 0;	/* the list to return. */

/*
 * _symintLoad(proffilePtr)
 * proffilePtr	- PROF_FILE pointer returned by _symintOpen().
 *
 * returns PROF_SYMBOL * - pointer to the malloc-ed array of
 *			   symbol information entries, or
 *			   NULL if fails.
 *
 *
 * This routine builds the interface data structure from the data
 * already loaded during _symintOpen().
 *
 * Prof:
 *
 * 	1. Allocate a duplicate copy of the symbol table
 *	   data.  (For Prof, a PROF_SYMBOL is just
 *	   a structure containing an Elf32_Sym!)
 *
 * 	2. Set internal parameters to reflect this.
 *
 *
 * Problems are dealt with by issuing an _err_exit().
 *
 */
PROF_SYMBOL *
_symintLoad(PROF_FILE *proffilePtr)
{
	Elf_Data	*symdat_pri_p;
	Elf_Data	*symdat_aux_p;
	PROF_SYMBOL	*symlist;

	DEBUG_LOC("_symintLoad: top");

	profPtr = proffilePtr;

	/*
	 * sanity checks.
	 */
	DEBUG_EXP(printf("profPtr = %x\n", profPtr));
	DEBUG_EXP(printf("profPtr->pf_symdat_p = %x\n",
	    profPtr->pf_symdat_pri_p));
	DEBUG_EXP(printf("profPtr->pf_nstsyms = %x\n", profPtr->pf_nstsyms));

	assert(profPtr != 0);
	assert(profPtr->pf_symdat_pri_p != 0);
	assert(profPtr->pf_nstsyms != 0);

	symdat_pri_p = profPtr->pf_symdat_pri_p;
	symdat_aux_p = profPtr->pf_symdat_aux_p;
	DEBUG_EXP(printf("symdat_pri_p->d_size = %x\n", symdat_pri_p->d_size));

	prstsym_size = (symdat_pri_p->d_size / profPtr->pf_nstsyms);
	DEBUG_EXP(printf("_symintLoad: prstsym_size = %d\n",
	    prstsym_size));

	/*
	 * alloc a new copy of the array, and
	 *  do a bit-wise copy since the structures
	 *  ARE THE SAME SIZE & (effectively) HAVE THE SAME FIELDS!
	 *  Set the descriptive `parameters' accordingly.
	 *
	 * If there is an auxiliary symbol table (.SUNW_ldynsym) augmenting
	 * the dynamic symbol table (.dynsym), then we copy both tables
	 * into our copy, with the auxiliary coming first.
	 *
	 * (We'll take a copy, to simplify the 'Drop' logic.)
	 */

	{
	size_t st_size;	/* size of symbol table data */

	st_size = symdat_pri_p->d_size;
	if (profPtr->pf_nstsyms_aux != 0)
		st_size += symdat_aux_p->d_size;

	NO_DEBUG_LOC("_symintLoad: before malloc for symbol list (PROF)");
	prsym_list_p = symlist = (PROF_SYMBOL *)_Malloc(st_size, 1);
	NO_DEBUG_LOC("_symintLoad: after malloc for symbol list (PROF)");

	if (profPtr->pf_nstsyms_aux > 0) {
		NO_DEBUG_LOC("_symintLoad: before memcpy for "
		    "auxiliary symbol list (PROF)");
		(void) memcpy(symlist, symdat_aux_p->d_buf,
		    symdat_aux_p->d_size);
		symlist += profPtr->pf_nstsyms_aux;
	}

	NO_DEBUG_LOC("_symintLoad: before memcpy for symbol list (PROF)");
	(void) memcpy(symlist, symdat_pri_p->d_buf, symdat_pri_p->d_size);

	profPtr->pf_nsyms = profPtr->pf_nstsyms;
	}

	DEBUG_LOC("_symintLoad: bottom");
	return (prsym_list_p);
}
