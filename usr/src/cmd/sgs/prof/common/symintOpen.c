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

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include "symint.h"
#include "debug.h"

/*
 * symintFcns.c -- symbol information interface routines.
 *
 * these routines form a symbol information access
 * interface, for the profilers to get at object file
 * information.  this interface was designed to aid
 * in the COFF to ELF conversion of prof, lprof and friends.
 *
 */


/*
 * _symintOpen(aout_name)
 * aout_name 	- char string file name of object file
 *		to open.
 *
 * returns PROF_FILE * - pointer to the PROF_FILE structure built,
 *			or NULL if fails.
 */

/*
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

/*
 * globals
 */


static char
	*fail_open_s =	"Unable to open file",
	*fail_begin_s =	"Unable to read (begin) file",
	*fail_ehdr_s =	"Unable to get elf header in",
	*fail_sec_s =	"Unable to get section",
	*fail_shd_s =	"Unable to get header for section",
	*fail_dat_s =	"Unable to get data for section",
	*fail_sym_s =	"Cannot find symbol table section in",
	*fail_pfsym_s =	"Unable to process symbols in",
	*fail_buf_s =	"Data buffer is null for section",
	*fail_sym32_s =	"Cannot handle more than 2^32 symbols"
	;


/*
 * this points at the name of the executable.
 */
static  char *executableName;



/*
 * section_data_p() - return ptr to section data,
 * 	given section ptr and name of section.
 */

static Elf_Data *
section_data_p(Elf_Scn *sec_p, char *str)
{
	Elf_Data *dat_p;

	if ((dat_p = elf_getdata(sec_p, NULL)) == NULL)
		_err_exit("%s %s in %s.", fail_dat_s, str, executableName);
	return (dat_p);
}


PROF_FILE *
_symintOpen(char *aout_name)
{
/*
 * Elf file open operation
 *
 * - point at executable's name, globally
 * - open file
 * - align to current version
 * - read the elf descriptor and header
 * - read header-names section descriptor, header, and data
 * - allocate space for all the section hdrs (pf_shdarr_p).
 * - set a pointer to the header-names buffer
 * - search the section headers for
 *	- debug section header and data
 *	- line section header and data
 *	- symbol table header, data, strings, and number of symbols
 *	  and copy each section hdr into our array.
 *  - populate the PROF_SYMBOL array and anchor it in (pf_symarr_p).
 */

	PROF_FILE	*pfile_p;	/* PROF_FILE ptr to return. */

	Elf		*telf_p;
	Elf_Scn		*tscn_p;
	Elf32_Shdr	*tshd_p;
	int		k;
	Elf64_Xword	nsyms_pri = 0, nsyms_aux = 0;

	executableName = aout_name;

	DEBUG_LOC("_symintOpen: top");
	if (aout_name == NULL) {
		_err_exit("name of executable is null\n");
	}
	DEBUG_EXP(printf("Attempting to open %s\n", aout_name));
	pfile_p = _Malloc(sizeof (PROF_FILE), 1);

	if ((pfile_p->pf_fildes = open(aout_name, O_RDONLY)) == -1)
		_err_exit("%s %s.", fail_open_s, aout_name);
	if ((elf_version(EV_CURRENT)) == EV_NONE)
		_err_exit("Elf library out of date");
	if ((pfile_p->pf_elf_p = elf_begin(pfile_p->pf_fildes,
	    ELF_C_READ, (Elf *)NULL)) == NULL)
		_err_exit("%s %s.", fail_begin_s, aout_name);

	DEBUG_EXP(printf("elfkind = %d\n", elf_kind(pfile_p->pf_elf_p)));
	if ((pfile_p->pf_elfhd_p = elf32_getehdr(pfile_p->pf_elf_p)) == NULL)
		_err_exit("%s %s.", fail_ehdr_s, aout_name);

	DEBUG_LOC("_symintOpen: after call to getehdr");
	telf_p = pfile_p->pf_elf_p;

	tscn_p = elf_getscn(telf_p, k = pfile_p->pf_elfhd_p->e_shstrndx);
	if (tscn_p == NULL)
		_err_exit("%s %d in %s.", fail_sec_s, k, aout_name);

	if (elf32_getshdr(tscn_p) == NULL)
		_err_exit("%s %s in %s.", fail_shd_s, "header names",
		    aout_name);
	if ((pfile_p->pf_snmdat_p = elf_getdata(tscn_p, NULL)) == NULL)
		_err_exit("%s %s in %s.", fail_dat_s, "header names",
		    aout_name);

	DEBUG_EXP(printf("Address of data header = 0x%lx\n",
	    pfile_p->pf_snmdat_p));
	DEBUG_EXP(printf("d_buf     = 0x%lx\n",
	    pfile_p->pf_snmdat_p->d_buf));
	DEBUG_EXP(printf("d_type    = %d\n",
	    pfile_p->pf_snmdat_p->d_type));
	DEBUG_EXP(printf("d_size    = %d\n",
	    pfile_p->pf_snmdat_p->d_size));
	DEBUG_EXP(printf("d_off     = %d\n",
	    pfile_p->pf_snmdat_p->d_off));
	DEBUG_EXP(printf("d_align   = %d\n",
	    pfile_p->pf_snmdat_p->d_align));
	DEBUG_EXP(printf("d_version = %d\n",
	    pfile_p->pf_snmdat_p->d_version));

	if (pfile_p->pf_snmdat_p->d_buf == NULL)
		_err_exit("%s %s in %s.", fail_buf_s, "header names",
		    aout_name);

	DEBUG_LOC("_symintOpen: after call to getdata (for header names)");

	pfile_p->pf_shdarr_p = _Malloc(pfile_p->pf_elfhd_p->e_shentsize,
	    pfile_p->pf_elfhd_p->e_shnum);

	{
#ifdef DEBUG
	char	*shdnms_p = (char *)pfile_p->pf_snmdat_p->d_buf;
#endif

	char	*dest_p = (char *)pfile_p->pf_shdarr_p;
	int	shdsize = pfile_p->pf_elfhd_p->e_shentsize;
	int	i = 0;
	int		symtab_found = 0;

	tscn_p = 0;
	DEBUG_EXP(printf("Section header entry size = %d\n", shdsize));
	DEBUG_EXP(printf("First section header name = %s\n", &shdnms_p[1]));
	pfile_p->pf_symdat_aux_p = NULL;
	/*
	 * Scan the section headers looking for a symbol table. Our
	 * preference is to use .symtab, because it contains the full
	 * set of symbols. If we find it, we stop looking immediately
	 * and use it. In the absence of a .symtab section, we are
	 * willing to use the dynamic symbol table (.dynsym), possibly
	 * augmented by the .SUNW_ldynsym, which contains local symbols.
	 */
	while ((tscn_p = elf_nextscn(telf_p, tscn_p)) != NULL) {
		if ((tshd_p = elf32_getshdr(tscn_p)) == NULL)
			_err_exit("%s %d in %s.", fail_shd_s, i, aout_name);
		i++;

		(void) memcpy(dest_p, tshd_p, shdsize);
		dest_p += shdsize;

		DEBUG_EXP(printf("index of section name = %d\n",
		    tshd_p->sh_name));
		DEBUG_EXP(printf("_symintOpen: reading section %s\n",
		    &shdnms_p[tshd_p->sh_name]));

		if (symtab_found)
			continue;
		switch (tshd_p->sh_type) {
		case SHT_SYMTAB:
			DEBUG_LOC("_symintOpen: found symbol section");
			pfile_p->pf_symstr_ndx = tshd_p->sh_link;
			pfile_p->pf_symdat_pri_p =
			    section_data_p(tscn_p, "symtab");
			nsyms_pri = tshd_p->sh_size / tshd_p->sh_entsize;
			/* Throw away .SUNW_ldynsym. It is for .dynsym only */
			nsyms_aux = 0;
			pfile_p->pf_symdat_aux_p = NULL;
			/* We have found the best symbol table. Stop looking */
			symtab_found = 1;
			break;

		case SHT_DYNSYM:
			/* We will use .dynsym if no .symtab is found */
			DEBUG_LOC("_symintOpen: found dynamic symbol section");
			pfile_p->pf_symstr_ndx = tshd_p->sh_link;
			pfile_p->pf_symdat_pri_p =
			    section_data_p(tscn_p, "dynsym");
			nsyms_pri = tshd_p->sh_size / tshd_p->sh_entsize;
			break;

		case SHT_SUNW_LDYNSYM:
			/* Auxiliary table, used with .dynsym */
			DEBUG_LOC("_symintOpen: found dynamic symbol section");
			pfile_p->pf_symdat_aux_p =
			    section_data_p(tscn_p, "SUNW_ldynsym");
			nsyms_aux = tshd_p->sh_size / tshd_p->sh_entsize;
			break;
		}

	}
	}

	if (pfile_p->pf_symdat_pri_p == NULL || pfile_p->pf_symstr_ndx == 0)
		_err_exit("%s %s.", fail_sym_s, executableName);

	pfile_p->pf_nstsyms = (int)(nsyms_pri + nsyms_aux);
	pfile_p->pf_nstsyms_aux = (int)nsyms_aux;
	if ((nsyms_pri + nsyms_aux) != (Elf64_Xword)pfile_p->pf_nstsyms)
		_err_exit("%s %s.", fail_sym32_s, executableName);


	DEBUG_LOC("_symintOpen: after for loop that reads the sections");

	DEBUG_LOC("_symintOpen: before call to _symintLoad");

	if ((pfile_p->pf_symarr_p = _symintLoad(pfile_p)) == NULL)
		_err_exit("%s %s.", fail_pfsym_s, executableName);

	DEBUG_LOC("_symintOpen: after call to _symintLoad");

	/*
	 * At this point we might want to include some consistency
	 * checks to be sure all is well.  For example, we can check
	 * symbol table consistency by comparing "the product of the
	 * number of symbols and the size of each symbol" to "the
	 * length of the symbol table data".
	 *
	 * Also, NULL may be a proper value (e.g., the debugger
	 * information when there is none) for some things that
	 * we cannot afford to be without.  We should check these
	 * at this point also.
	 */

	DEBUG_LOC("_symintOpen: bottom");
	return (pfile_p);
}
