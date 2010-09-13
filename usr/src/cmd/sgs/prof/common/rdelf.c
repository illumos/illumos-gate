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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ELF support routines for processing versioned mon.out files.
 */

#include <stdlib.h>
#include <string.h>
#include "profv.h"

bool
is_shared_obj(char *name)
{
	int		fd;
	Elf		*elf;
	GElf_Ehdr	ehdr;

	if ((fd = open(name, O_RDONLY)) == -1) {
		(void) fprintf(stderr, "%s: can't open `%s'\n", cmdname, name);
		exit(ERR_ELF);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "%s: libelf out of date\n", cmdname);
		exit(ERR_ELF);
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		(void) fprintf(stderr, "%s: elf_begin failed\n", cmdname);
		exit(ERR_ELF);
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		(void) fprintf(stderr, "%s: can't read ELF header of %s\n",
								cmdname, name);
		exit(ERR_ELF);
	}

	(void) elf_end(elf);
	(void) close(fd);

	if (ehdr.e_type == ET_DYN)
		return (TRUE);
	else
		return (FALSE);
}

static void
rm_dups(nltype *nl, size_t *nfuncs)
{
	size_t	i, prev = 0, ndx = 0;
	int	prev_type, prev_bind, cur_type;

	for (i = 1; i < *nfuncs; i++) {
		/*
		 * If current value is different from prev, proceed.
		 */
		if (nl[prev].value < nl[i].value) {
			prev = i;
			continue;
		}

		/*
		 * If current and prev have the syminfo, rm the latter.
		 */
		if (nl[prev].info == nl[i].info) {
			nl[i].name = NULL;
			continue;
		}

		prev_type = ELF_ST_TYPE(nl[prev].info);
		prev_bind = ELF_ST_BIND(nl[prev].info);
		cur_type = ELF_ST_TYPE(nl[i].info);

		/*
		 * Remove the one with STT_NOTYPE and keep the other.
		 */
		if (prev_type != cur_type) {
			if (prev_type != STT_NOTYPE)
				nl[i].name = NULL;
			else {
				nl[prev].name = NULL;
				prev = i;
			}
			continue;
		}

		/*
		 * If they have the same type, take the stronger bound
		 * function
		 */
		if (prev_bind != STB_WEAK)
			nl[i].name = NULL;
		else {
			nl[prev].name = NULL;
			prev = i;
		}
	}


	/*
	 * Actually remove the cleared symbols from namelist. We're not
	 * truncating namelist by realloc, though.
	 */
	for (i = 0; (i < *nfuncs) && (nl[i].name != NULL); i++)
		;

	ndx = i;
	for (i = ndx + 1; i < *nfuncs; i++) {
		if (nl[i].name) {
			nl[ndx] = nl[i];
			ndx++;
		}
	}

	*nfuncs = ndx;
}

int
cmp_by_address(const void *arg1, const void *arg2)
{
	nltype *a = (nltype *)arg1;
	nltype *b = (nltype *)arg2;

	if (a->value < b->value)
		return (-1);
	else if (a->value > b->value)
		return (1);
	else
		return (0);
}

static int
is_function(Elf *elf, GElf_Sym *sym)
{
	Elf_Scn		*scn;
	GElf_Shdr	shdr;

	/*
	 * With dynamic linking, it is possible that certain undefined
	 * symbols exist in the objects. The actual definition will be
	 * found elsewhere, so we'll just skip it for this object.
	 */
	if (sym->st_shndx == SHN_UNDEF)
		return (0);

	if (GELF_ST_TYPE(sym->st_info) == STT_FUNC) {
		if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL)
			return (1);

		if (GELF_ST_BIND(sym->st_info) == STB_WEAK)
			return (1);

		if (gflag && GELF_ST_BIND(sym->st_info) == STB_LOCAL)
			return (1);
	}

	/*
	 * It's not a function; determine if it's in an executable section.
	 */
	if (GELF_ST_TYPE(sym->st_info) != STT_NOTYPE)
		return (0);

	/*
	 * If it isn't global, and it isn't weak, and it isn't
	 * a 'local with the gflag set', then get out.
	 */
	if (GELF_ST_BIND(sym->st_info) != STB_GLOBAL &&
			GELF_ST_BIND(sym->st_info) != STB_WEAK &&
			!(gflag && GELF_ST_BIND(sym->st_info) == STB_LOCAL))
		return (0);

	if (sym->st_shndx >= SHN_LORESERVE)
		return (0);

	scn = elf_getscn(elf, sym->st_shndx);
	(void) gelf_getshdr(scn, &shdr);

	if (!(shdr.sh_flags & SHF_EXECINSTR))
		return (0);

	return (1);
}

static void
fetch_symtab(Elf *elf, char *filename, mod_info_t *module)
{
	Elf_Scn		*scn = NULL, *sym_pri = NULL, *sym_aux = NULL;
	GElf_Word	strndx = 0;
	size_t		i, nsyms, nfuncs;
	GElf_Xword	nsyms_pri, nsyms_aux = 0;
	Elf_Data	*symdata_pri, *symdata_aux;
	nltype		*nl, *npe;
	int		symtab_found = 0;


	/*
	 * Scan the section headers looking for a symbol table. Our
	 * preference is to use .symtab, because it contains the full
	 * set of symbols. If we find it, we stop looking immediately
	 * and use it. In the absence of a .symtab section, we are
	 * willing to use the dynamic symbol table (.dynsym), possibly
	 * augmented by the .SUNW_ldynsym, which contains local symbols.
	 */
	while ((symtab_found == 0) && ((scn = elf_nextscn(elf, scn)) != NULL)) {

		GElf_Shdr shdr;

		if (gelf_getshdr(scn, &shdr) == NULL)
			continue;

		switch (shdr.sh_type) {
		case SHT_SYMTAB:
			nsyms_pri = shdr.sh_size / shdr.sh_entsize;
			strndx = shdr.sh_link;
			sym_pri = scn;
			/* Throw away .SUNW_ldynsym. It is for .dynsym only */
			nsyms_aux = 0;
			sym_aux = NULL;
			/* We have found the best symbol table. Stop looking */
			symtab_found = 1;
			break;

		case SHT_DYNSYM:
			/* We will use .dynsym if no .symtab is found */
			nsyms_pri = shdr.sh_size / shdr.sh_entsize;
			strndx = shdr.sh_link;
			sym_pri = scn;
			break;

		case SHT_SUNW_LDYNSYM:
			/* Auxiliary table, used with .dynsym */
			nsyms_aux = shdr.sh_size / shdr.sh_entsize;
			sym_aux = scn;
			break;
		}
	}

	if (sym_pri == NULL || strndx == 0) {
		(void) fprintf(stderr, "%s: missing symbol table in %s\n",
						    cmdname, filename);
		exit(ERR_ELF);
	}

	nsyms = (size_t)(nsyms_pri + nsyms_aux);
	if ((nsyms_pri + nsyms_aux) != (GElf_Xword)nsyms) {
		(void) fprintf(stderr,
		    "%s: can't handle more than 2^32 symbols", cmdname);
		exit(ERR_INPUT);
	}

	if ((symdata_pri = elf_getdata(sym_pri, NULL)) == NULL) {
		(void) fprintf(stderr, "%s: can't read symbol data from %s\n",
		    cmdname, filename);
		exit(ERR_ELF);
	}

	if ((sym_aux != NULL) &&
	    ((symdata_aux = elf_getdata(sym_aux, NULL)) == NULL)) {
		(void) fprintf(stderr,
		    "%s: can't read .SUNW_ldynsym symbol data from %s\n",
		    cmdname, filename);
		exit(ERR_ELF);
	}

	if ((npe = nl = (nltype *) calloc(nsyms, sizeof (nltype))) == NULL) {
		(void) fprintf(stderr, "%s: can't alloc %x bytes for symbols\n",
					cmdname, nsyms * sizeof (nltype));
		exit(ERR_ELF);
	}

	/*
	 * Now we need to cruise through the symbol table eliminating
	 * all non-functions from consideration, and making strings
	 * real.
	 */
	nfuncs = 0;

	for (i = 1; i < nsyms; i++) {
		GElf_Sym	gsym;
		char		*name;

		/*
		 * Look up the symbol. In the case where we have a
		 * .SUNW_ldynsym/.dynsym pair, we treat them as a single
		 * logical table, with the data in .SUNW_ldynsym coming
		 * before the data in .dynsym.
		 */
		if (i >= nsyms_aux)
			(void) gelf_getsym(symdata_pri, i - nsyms_aux, &gsym);
		else
			(void) gelf_getsym(symdata_aux, i, &gsym);

		name = elf_strptr(elf, strndx, gsym.st_name);

		/*
		 * We're interested in this symbol if it's a function
		 */
		if (is_function(elf, &gsym)) {

			npe->name = name;
			npe->value = gsym.st_value;
			npe->size = gsym.st_size;
			npe->info = gsym.st_info;

			npe++;
			nfuncs++;
		}

		if (strcmp(name, PRF_END) == 0)
			module->data_end = gsym.st_value;
	}

	if (npe == nl) {
		(void) fprintf(stderr, "%s: no valid functions in %s\n",
						    cmdname, filename);
		exit(ERR_INPUT);
	}

	/*
	 * And finally, sort the symbols by increasing address
	 * and remove the duplicates.
	 */
	qsort(nl, nfuncs, sizeof (nltype), cmp_by_address);
	rm_dups(nl, &nfuncs);

	module->nl = nl;
	module->nfuncs = nfuncs;
}

static GElf_Addr
get_txtorigin(Elf *elf, char *filename)
{
	GElf_Ehdr	ehdr;
	GElf_Phdr	phdr;
	GElf_Half	ndx;
	GElf_Addr	txt_origin = 0;
	bool		first_load_seg = TRUE;

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		(void) fprintf(stderr, "%s: can't read ELF header of %s\n",
						    cmdname, filename);
		exit(ERR_ELF);
	}

	for (ndx = 0; ndx < ehdr.e_phnum; ndx++) {
		if (gelf_getphdr(elf, ndx, &phdr) == NULL)
			continue;

		if ((phdr.p_type == PT_LOAD) && !(phdr.p_flags & PF_W)) {
			if (first_load_seg || phdr.p_vaddr < txt_origin)
				txt_origin = phdr.p_vaddr;

			if (first_load_seg)
				first_load_seg = FALSE;
		}
	}

	return (txt_origin);
}

void
get_syms(char *filename, mod_info_t *mi)
{
	int		fd;
	Elf		*elf;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		exit(ERR_SYSCALL);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "%s: libelf out of date\n", cmdname);
		exit(ERR_ELF);
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		(void) fprintf(stderr, "%s: elf_begin failed\n", cmdname);
		exit(ERR_ELF);
	}

	if (gelf_getclass(elf) != ELFCLASS64) {
		(void) fprintf(stderr, "%s: unsupported mon.out format for "
				    "this class of object\n", cmdname);
		exit(ERR_ELF);
	}

	mi->txt_origin = get_txtorigin(elf, filename);

	fetch_symtab(elf, filename, mi);
}
