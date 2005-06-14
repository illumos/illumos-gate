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

#include "symint.h"

#include <stdio.h>
#include <fcntl.h>
#include "debug.h"

/* * * * * *
 * symintFcns.c -- symbol information interface routines.
 * 
 * these routines form a symbol information access
 * interface, for the profilers to get at object file
 * information.  this interface was designed to aid
 * in the COFF to ELF conversion of prof, lprof and friends.
 * 
 */


/* * * * * *
 * _symintOpen(aout_name)
 * aout_name 	- char string file name of object file
 * 		  to open.
 * 
 * returns PROF_FILE * - pointer to the PROF_FILE structure built,
 * 			 or NULL if fails.
 */

/* * * * * *
 * 
 * .H 3 "Executable File Open and Close"
 * 
 * Under COFF, the routine ldopen, given a file name, returns a pointer to a
 * structure called an LDFILE.  This descriptor is then passed to each of
 * the library routines (such as read header, read symbol table entry, etc)
 * to access the information contained in the file.  These calls are spread
 * throughout the profiling code.
 * 
 * Under ELF, the file must be opened using a system open call.  The file
 * descriptor is then passed to a routine which returns a pointer to an
 * Elf structure.  This pointer is then passed along to another routine which
 * returns a different pointer which is in turn passed along to another
 * routine.  In an attempt to avoid disturbing the current format of the
 * code (by having to pass around different types of pointers), we plan to
 * build a PROF_FILE descriptor which will then be passed around in the
 * same way as the pointer to LDFILE.
 * 
 * Thus, for ELF, an open will consist of opening the file and extracting
 * enough from it to fill in the PROF_FILE structure.  The code for the
 * open is as follows; the code for building the symbol table (extracting
 * information from the sections to fill an array of PROF_SYMBOLS) has
 * yet to be written.
 * 
 */


/* * * * * *
 * #defines and globals.
 */

#define	SCN_NAME_DEBUG	".debug"	/* debug information section */
#define	SCN_NAME_LINE	".line"		/* line number section */
#define	SCN_NAME_SYM	".symtab"	/* symbol table entry section */
#define	SCN_NAME_SST	".strtab"	/* symbol table string table */


static char
	*fail_open_s =	"Unable to open file",
	*fail_begin_s =	"Unable to read (begin) file",
	*fail_ehdr_s =	"Unable to get elf header in",
	*fail_sec_s =	"Unable to get section",
	*fail_shd_s =	"Unable to get header for section",
	*fail_dat_s =	"Unable to get data for section",
	*fail_sym_s =	"Cannot find symbol table section in",
	*fail_line_s =	"Cannot find line number section in",
	*fail_debug_s =	"Cannot find debug section in",
	*fail_pfsym_s =	"Unable to process symbols in",
	*fail_buf_s =	"Data buffer is null for section"
	;

/* * * * * *
 * this routine loads the symbols into the PROF_SYMBOL
 * array.
 */
extern  PROF_SYMBOL *	_symintLoad();	/* NULL or ptr */


/* * * * * *
 * this points at the name of the executable.
 */
static  char *executableName;





/* * * * * *
 * section_data_p() - return ptr to section data,
 * 	given section ptr and name of section.
 */

static
Elf_Data *
section_data_p(sec_p, str)

Elf_Scn *sec_p;
char	*str;
{
	Elf_Data *dat_p;
	
	if ((dat_p = elf_getdata(sec_p, NULL)) == NULL)
		_err_exit("%s %s in %s.", fail_dat_s, str, executableName);
	return(dat_p);
}






PROF_FILE *
_symintOpen(aout_name)

char	*aout_name; {


/*
*	Elf file open operation
*
* 	- point at executable's name, globally
*	- open file
*	- align to current version
*	- read the elf descriptor and header
*	- read header-names section descriptor, header, and data
*	- allocate space for all the section hdrs (pf_shdarr_p).
*	- set a pointer to the header-names buffer
*	- search the section headers for
*		- debug section header and data
*		- line section header and data
*		- symbol table header, data, strings, and number of symbols
*	  and copy each section hdr into our array.
* 	- populate the PROF_SYMBOL array and anchor it in (pf_symarr_p).
*/

	PROF_FILE	*pfile_p;	/* PROF_FILE ptr to return. */

	Elf		*telf_p;
	Elf_Scn		*tscn_p;
	Elf32_Shdr	*tshd_p;
	int		k;

	executableName = aout_name;

	DEBUG_LOC("_symintOpen: top");
	if(aout_name==NULL){
		_err_exit("name of executable is null\n");
	}
	DEBUG_EXP(printf("Attempting to open %s\n", aout_name));
	pfile_p = (PROF_FILE *) _Malloc( sizeof(PROF_FILE), 1);

	if ((pfile_p->pf_fildes = open(aout_name, O_RDONLY)) == -1)
		_err_exit("%s %s.", fail_open_s, aout_name);
	if ((elf_version(EV_CURRENT)) == EV_NONE)
		_err_exit("Elf library out of date");
	if (
		(pfile_p->pf_elf_p
			= elf_begin(
				pfile_p->pf_fildes,
				ELF_C_READ,
				(Elf *) 0
			)
		) == NULL
	)
		_err_exit("%s %s.", fail_begin_s, aout_name);

	DEBUG_EXP(printf("elfkind = %d\n", elf_kind(pfile_p->pf_elf_p)));
	if ((pfile_p->pf_elfhd_p = elf32_getehdr(pfile_p->pf_elf_p)) == NULL)
		_err_exit("%s %s.", fail_ehdr_s, aout_name);

	DEBUG_LOC("_symintOpen: after call to getehdr");
	telf_p = pfile_p->pf_elf_p;

	tscn_p = elf_getscn(telf_p, k = pfile_p->pf_elfhd_p->e_shstrndx);
	if (tscn_p == NULL)
		_err_exit("%s %d in %s.", fail_sec_s, k, aout_name);

	if ((pfile_p->pf_snmshd_p = elf32_getshdr(tscn_p)) == NULL)
		_err_exit("%s %s in %s.", fail_shd_s, "header names", aout_name);
	if ((pfile_p->pf_snmdat_p = elf_getdata(tscn_p, NULL)) == NULL)
		_err_exit("%s %s in %s.", fail_dat_s, "header names", aout_name);
	
	DEBUG_EXP(printf("Address of data header = 0x%lx\n",pfile_p->pf_snmdat_p));
	DEBUG_EXP(printf("d_buf     = 0x%lx\n",pfile_p->pf_snmdat_p->d_buf));
	DEBUG_EXP(printf("d_type    = %d\n",pfile_p->pf_snmdat_p->d_type));
	DEBUG_EXP(printf("d_size    = %d\n",pfile_p->pf_snmdat_p->d_size));
	DEBUG_EXP(printf("d_off     = %d\n",pfile_p->pf_snmdat_p->d_off));
	DEBUG_EXP(printf("d_align   = %d\n",pfile_p->pf_snmdat_p->d_align));
	DEBUG_EXP(printf("d_version = %d\n",pfile_p->pf_snmdat_p->d_version));

	if (pfile_p->pf_snmdat_p->d_buf == NULL)
		_err_exit("%s %s in %s.", fail_buf_s, "header names", aout_name);

	DEBUG_LOC("_symintOpen: after call to getdata (for header names)");

	pfile_p->pf_shdarr_p = (Elf32_Shdr *)
			_Malloc( pfile_p->pf_elfhd_p->e_shentsize,
			        pfile_p->pf_elfhd_p->e_shnum );

	{
	char	*shdnms_p = (char *) pfile_p->pf_snmdat_p->d_buf;

	char	*dest_p = (char *) pfile_p->pf_shdarr_p ;
	int	shdsize = pfile_p->pf_elfhd_p->e_shentsize ;
	int	i;
	char	*s;

	i = 0;
	tscn_p = 0;
	DEBUG_EXP(printf("Section header entry size = %d\n",shdsize));
	DEBUG_EXP(printf("First section header name = %s\n",&shdnms_p[1]));
	while ((tscn_p = elf_nextscn(telf_p, tscn_p)) != NULL) {
		if ((tshd_p = elf32_getshdr(tscn_p)) == NULL)
			_err_exit("%s %d in %s.", fail_shd_s, i, aout_name);

		memcpy( dest_p, tshd_p, shdsize );
		dest_p += shdsize ;

		s = &shdnms_p[tshd_p->sh_name];
		DEBUG_EXP(printf("index of section name = %d\n",tshd_p->sh_name));
		DEBUG_EXP(printf("_symintOpen: reading section %s\n",s));
		if (strcmp(s, SCN_NAME_DEBUG) == 0) {
			DEBUG_LOC("_symintOpen: found debug section");
			pfile_p->pf_debugshd_p = tshd_p;
			pfile_p->pf_debugdat_p = section_data_p(tscn_p,"debug");
		} else if (strcmp(s, SCN_NAME_LINE) == 0) {
			DEBUG_LOC("_symintOpen: found line section");
			pfile_p->pf_lineshd_p = tshd_p;
			pfile_p->pf_linedat_p = section_data_p(tscn_p, "line");
		} else if (strcmp(s, SCN_NAME_SYM) == 0) {
			DEBUG_LOC("_symintOpen: found symbol section");
			pfile_p->pf_symshd_p = tshd_p;
			pfile_p->pf_symdat_p = section_data_p(tscn_p, "symtab");
			pfile_p->pf_nstsyms =
				tshd_p->sh_size / tshd_p->sh_entsize;
		} else if (strcmp(s, SCN_NAME_SST) == 0) {
			DEBUG_LOC("_symintOpen: found symbol table strings");
			pfile_p->pf_strshd_p = tshd_p;
			pfile_p->pf_strdat_p = section_data_p(tscn_p, "strtab");
			pfile_p->pf_symstr_p = pfile_p->pf_strdat_p->d_buf;
		}

		i++;
	}
	}

	if (!pfile_p->pf_symdat_p) {
		_err_exit("%s %s.", fail_sym_s, executableName);
	}
#if isLPROF
	if (!pfile_p->pf_linedat_p) {
		_err_exit("%s %s.", fail_line_s, executableName);
	}
	if (!pfile_p->pf_debugdat_p) {
		_err_exit("%s %s.", fail_debug_s, executableName);
	}
#endif

	DEBUG_LOC("_symintOpen: after for loop that reads the sections");

	DEBUG_LOC("_symintOpen: before call to _symintLoad");

	if ((pfile_p->pf_symarr_p = _symintLoad(pfile_p)) == NULL)
		_err_exit("%s %s.", fail_pfsym_s, executableName);

	DEBUG_LOC("_symintOpen: after call to _symintLoad");

	/*
	*	At this point we might want to include some consistency
	*	checks to be sure all is well.  For example, we can check
	*	symbol table consistency by comparing "the product of the
	*	number of symbols and the size of each symbol" to "the
	*	length of the symbol table data".
	*
	*	Also, NULL may be a proper value (e.g., the debugger
	*	information when there is none) for some things that
	*	we cannot afford to be without.  We should check these
	*	at this point also.
	*/

	DEBUG_LOC("_symintOpen: bottom");
	return( pfile_p );
}

