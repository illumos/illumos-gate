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

#include	"gprof.h"
#include	<stdlib.h>
#include	<sys/file.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<string.h>
#include	<sysexits.h>
#include	<libelf.h>
#include	"gelf.h"

#ifdef DEBUG
static void	debug_dup_del(nltype *, nltype *);

#define	DPRINTF(msg, file)	if (debug & ELFDEBUG) \
					(void) printf(msg, file);

#define	PRINTF(msg)		if (debug & ELFDEBUG) \
					(void) printf(msg);

#define	DEBUG_DUP_DEL(keeper, louser)	if (debug & ELFDEBUG) \
						debug_dup_del(keeper, louser);

#else
#define	DPRINTF(msg, file)
#define	PRINTF(msg)
#define	DEBUG_DUP_DEL(keeper, louser)
#endif

size_t	textbegin, textsize;

/* Prototype definitions first */

static void	process(char *filename, int fd);
static void	get_symtab(Elf *elf, mod_info_t *module);
static void	get_textseg(Elf *elf, int fd);
static void	save_aout_info(char *);

static void
fatal_error(char *error)
{
	(void) fprintf(stderr,
	    "Fatal ELF error: %s (%s)\n", error, elf_errmsg(-1));
	exit(EX_SOFTWARE);
}

bool
is_shared_obj(char *name)
{
	int		fd;
	Elf		*elf;
	GElf_Ehdr	ehdr;

	if ((fd = open(name, O_RDONLY)) == -1) {
		(void) fprintf(stderr, "%s: can't open `%s'\n", whoami, name);
		exit(EX_NOINPUT);
	}

	if (elf_version(EV_CURRENT) == EV_NONE)
		fatal_error("libelf is out of date");

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		fatal_error("can't read as ELF file");

	if (gelf_getehdr(elf, &ehdr) == NULL)
		fatal_error("can't read ehdr");

	(void) elf_end(elf);
	(void) close(fd);

	if (ehdr.e_type == ET_DYN)
		return (TRUE);
	else
		return (FALSE);
}

static void
save_aout_info(char *aoutname)
{
	struct stat		buf;
	extern fl_info_t	aout_info;

	if (stat(aoutname, &buf) == -1) {
		(void) fprintf(stderr, "%s: can't get info on `%s'\n",
		    whoami, aoutname);
		exit(EX_NOINPUT);
	}

	aout_info.dev = buf.st_dev;
	aout_info.ino = buf.st_ino;
	aout_info.mtime = buf.st_mtime;
	aout_info.size = buf.st_size;
}

void
getnfile(char *aoutname)
{
	int	fd;

	DPRINTF(" Attempting to open %s  \n", aoutname);
	if ((fd = open((aoutname), O_RDONLY)) == -1) {
		(void) fprintf(stderr, "%s: can't open `%s'\n",
		    whoami, aoutname);
		exit(EX_NOINPUT);
	}
	process(aoutname, fd);
	save_aout_info(aoutname);

	(void) close(fd);
}

static GElf_Addr
get_txtorigin(Elf *elf)
{
	GElf_Ehdr	ehdr;
	GElf_Phdr	phdr;
	GElf_Half	ndx;
	GElf_Addr	txt_origin = 0;
	bool		first_load_seg = TRUE;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		fatal_error("can't read ehdr");

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
process_namelist(mod_info_t *module)
{
	int		fd;
	Elf		*elf;

	if ((fd = open(module->name, O_RDONLY)) == -1) {
		(void) fprintf(stderr, "%s: can't read %s\n",
		    whoami, module->name);
		(void) fprintf(stderr, "Exiting due to error(s)...\n");
		exit(EX_NOINPUT);
	}

	/*
	 * libelf's version already verified in processing a.out,
	 * so directly do elf_begin()
	 */
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		fatal_error("can't read as ELF file");

	module->next = NULL;
	module->txt_origin = get_txtorigin(elf);
	get_symtab(elf, module);
	module->active = TRUE;
}

/*
 * Get the ELF header and,  if it exists, call get_symtab()
 * to begin processing of the file; otherwise, return from
 * processing the file with a warning.
 */
static void
process(char *filename, int fd)
{
	Elf			*elf;
	extern bool		cflag;
	extern bool		Bflag;

	if (elf_version(EV_CURRENT) == EV_NONE)
		fatal_error("libelf is out of date");

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		fatal_error("can't read as ELF file");

	if (gelf_getclass(elf) == ELFCLASS64)
		Bflag = TRUE;

	/*
	 * Initialize active modules list. Note that we set the end
	 * address while reading the symbol table, in get_symtab
	 */
	modules.id = 1;
	modules.next = NULL;
	modules.txt_origin = get_txtorigin(elf);
	modules.load_base = modules.txt_origin;
	if ((modules.name = malloc(strlen(filename) + 1)) == NULL) {
		(void) fprintf(stderr, "%s: can't malloc %d bytes",
		    whoami, strlen(filename) + 1);
		exit(EX_UNAVAILABLE);
	}
	(void) strcpy(modules.name, filename);

	get_symtab(elf, &modules);

	modules.load_end = modules.data_end;
	modules.active = TRUE;
	n_modules = 1;

	if (cflag)
		get_textseg(elf, fd);
}

static void
get_textseg(Elf *elf, int fd)
{
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	GElf_Half i;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		fatal_error("can't read ehdr");

	for (i = 0; i < ehdr.e_phnum; i++) {

		if (gelf_getphdr(elf, i, &phdr) == NULL)
			continue;

		if (!(phdr.p_flags & PF_W) && (phdr.p_filesz > textsize)) {
			size_t chk;

			/*
			 * We could have multiple loadable text segments;
			 * keep the largest we find.
			 */
			if (textspace)
				free(textspace);

			/*
			 * gprof is a 32-bit program;  if this text segment
			 * has a > 32-bit offset or length, it's too big.
			 */
			chk = (size_t)phdr.p_vaddr + (size_t)phdr.p_filesz;
			if (phdr.p_vaddr + phdr.p_filesz != (GElf_Xword)chk)
				fatal_error("text segment too large for -c");

			textbegin = (size_t)phdr.p_vaddr;
			textsize = (size_t)phdr.p_filesz;

			textspace = malloc(textsize);

			if (lseek(fd, (off_t)phdr.p_offset, SEEK_SET) !=
			    (off_t)phdr.p_offset)
				fatal_error("cannot seek to text section");

			if (read(fd, textspace, textsize) != textsize)
				fatal_error("cannot read text");
		}
	}

	if (textsize == 0)
		fatal_error("can't find text segment");
}

#ifdef DEBUG
static void
debug_dup_del(nltype * keeper, nltype * louser)
{
	(void) printf("remove_dup_syms: discarding sym %s over sym %s\n",
	    louser->name, keeper->name);
}
#endif /* DEBUG */

static void
remove_dup_syms(nltype *nl, sztype *sym_count)
{
	int	i;
	int	index;
	int	nextsym;
	nltype *orig_list;

	if ((orig_list = malloc(sizeof (nltype) * *sym_count)) == NULL) {
		(void) fprintf(stderr,
		    "gprof: remove_dup_syms: malloc failed\n");
		(void) fprintf(stderr, "Exiting due to error(s)...\n");
		exit(EX_UNAVAILABLE);
	}
	(void) memcpy(orig_list, nl, sizeof (nltype) * *sym_count);

	for (i = 0, index = 0, nextsym = 1; nextsym < *sym_count; nextsym++) {
		int	i_type;
		int	n_bind;
		int	n_type;

		/*
		 * If orig_list[nextsym] points to a new symvalue, then we
		 * will copy our keeper and move on to the next symbol.
		 */
		if ((orig_list + i)->value < (orig_list + nextsym)->value) {
			*(nl + index++) = *(orig_list +i);
			i = nextsym;
			continue;
		}

		/*
		 * If these two symbols have the same info, then we
		 * keep the first and keep checking for dups.
		 */
		if ((orig_list + i)->syminfo ==
		    (orig_list + nextsym)->syminfo) {
			DEBUG_DUP_DEL(orig_list + i, orig_list + nextsym);
			continue;
		}
		n_bind = ELF32_ST_BIND((orig_list + nextsym)->syminfo);
		i_type = ELF32_ST_TYPE((orig_list + i)->syminfo);
		n_type = ELF32_ST_TYPE((orig_list + nextsym)->syminfo);

		/*
		 * If they have the same type we take the stronger
		 * bound function.
		 */
		if (i_type == n_type) {
			if (n_bind == STB_WEAK) {
				DEBUG_DUP_DEL((orig_list + i),
				    (orig_list + nextsym));
				continue;
			}
			DEBUG_DUP_DEL((orig_list + nextsym),
			    (orig_list + i));
			i = nextsym;
			continue;
		}

		/*
		 * If the first symbol isn't of type NOTYPE then it must
		 * be the keeper.
		 */
		if (i_type != STT_NOTYPE) {
			DEBUG_DUP_DEL((orig_list + i),
			    (orig_list + nextsym));
			continue;
		}

		/*
		 * Throw away the first one and take the new
		 * symbol
		 */
		DEBUG_DUP_DEL((orig_list + nextsym), (orig_list + i));
		i = nextsym;
	}

	if (i < *sym_count) {
		if ((orig_list + i)->value > (nl + index - 1)->value)
			*(nl + index++) = *(orig_list + i);
	}

	*sym_count = index;
}

/*
 * compare either by name or by value for sorting.
 * This is the comparison function called by qsort to
 * sort the symbols either by name or value when requested.
 */
static int
compare(const void *arg1, const void *arg2)
{
	nltype *a = (nltype *)arg1;
	nltype *b = (nltype *)arg2;

	if (a->value > b->value)
		return (1);
	else
		return ((a->value == b->value) - 1);
}

static int
is_function(Elf *elf, GElf_Sym *sym)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;

	/*
	 * With shared objects, it is possible we come across a function
	 * that's global, but is undefined. The definition is probably
	 * elsewhere, so we'll have to skip it as far as this object is
	 * concerned.
	 */
	if (sym->st_shndx == SHN_UNDEF)
		return (0);

	if (GELF_ST_TYPE(sym->st_info) == STT_FUNC) {
		if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL)
			return (1);

		if (GELF_ST_BIND(sym->st_info) == STB_WEAK)
			return (1);

		if (!aflag && GELF_ST_BIND(sym->st_info) == STB_LOCAL)
			return (1);
	}

	/*
	 * It's not a function; determine if it's in an executable section.
	 */
	if (GELF_ST_TYPE(sym->st_info) != STT_NOTYPE)
		return (0);

	/*
	 * If it isn't global, and it isn't weak, and it either isn't
	 * local or the "all flag" isn't set, then get out.
	 */
	if (GELF_ST_BIND(sym->st_info) != STB_GLOBAL &&
	    GELF_ST_BIND(sym->st_info) != STB_WEAK &&
	    (GELF_ST_BIND(sym->st_info) != STB_LOCAL || aflag))
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
get_symtab(Elf *elf, mod_info_t *module)
{
	Elf_Scn		*scn = NULL, *sym_pri = NULL, *sym_aux = NULL;
	GElf_Word	strndx = 0;
	sztype		nsyms, i;
	Elf_Data	*symdata_pri;
	Elf_Data	*symdata_aux = NULL;
	GElf_Xword	nsyms_pri = 0, nsyms_aux = 0;
	nltype		*etext = NULL;
	nltype		*l_nl, *l_npe;
	sztype		l_nname;
	extern sztype	total_names;
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

	if (sym_pri == NULL || strndx == 0)
		fatal_error("can't find symbol table.\n");

	nsyms = (sztype)(nsyms_pri + nsyms_aux);
	if ((nsyms_pri + nsyms_aux) != (GElf_Xword)nsyms)
		fatal_error(
		    "32-bit gprof cannot handle more than 2^32 symbols");

	if ((symdata_pri = elf_getdata(sym_pri, NULL)) == NULL)
		fatal_error("can't read symbol data.\n");

	if ((sym_aux != NULL) &&
	    ((symdata_aux = elf_getdata(sym_aux, NULL)) == NULL))
		fatal_error("can't read .SUNW_ldynsym symbol data.\n");

	if ((l_nl = l_npe = (nltype *)calloc(nsyms + PRF_SYMCNT,
	    sizeof (nltype))) == NULL)
		fatal_error("cannot allocate symbol data.\n");

	/*
	 * Now we need to cruise through the symbol table eliminating
	 * all non-functions from consideration, and making strings
	 * real.
	 */
	l_nname = 0;

	for (i = 1; i < nsyms; i++) {
		GElf_Sym gsym;
		char *name;

		/*
		 * Look up the symbol. In the case where we have a
		 * .SUNW_ldynsym/.dynsym pair, we treat them as a single
		 * logical table, with the data from .SUNW_ldynsym coming
		 * before the data in .dynsym.
		 */
		if (i >= nsyms_aux)
			(void) gelf_getsym(symdata_pri, i - nsyms_aux, &gsym);
		else
			(void) gelf_getsym(symdata_aux, i, &gsym);

		name = elf_strptr(elf, strndx, gsym.st_name);

		/*
		 * We're interested in this symbol if it's a function or
		 * if it's the symbol "_etext"
		 */
		if (is_function(elf, &gsym) || strcmp(name, PRF_ETEXT) == 0) {

			l_npe->name = name;
			l_npe->value = gsym.st_value;
			l_npe->sz = gsym.st_size;
			l_npe->syminfo = gsym.st_info;
			l_npe->module = module;

			if (strcmp(name, PRF_ETEXT) == 0)
				etext = l_npe;

			if (lflag == TRUE &&
			    GELF_ST_BIND(gsym.st_info) == STB_LOCAL) {
				/*
				 * If the "locals only" flag is on, then
				 * we add the local symbols to the
				 * exclusion lists.
				 */
				addlist(Elist, name);
				addlist(elist, name);
			}
			DPRINTF("Index %lld:", l_nname);
			DPRINTF("\tValue: 0x%llx\t", l_npe->value);
			DPRINTF("Name: %s \n", l_npe->name);
			l_npe++;
			l_nname++;
		}

		if (strcmp(name, PRF_END) == 0)
			module->data_end = gsym.st_value;
	}

	if (l_npe == l_nl)
		fatal_error("no valid functions found");

	/*
	 * Finally, we need to construct some dummy entries.
	 */
	if (etext) {
		l_npe->name = PRF_EXTSYM;
		l_npe->value = etext->value + 1;
		l_npe->syminfo = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
		l_npe->module = module;
		l_npe++;
		l_nname++;
	}

	l_npe->name = PRF_MEMTERM;
	l_npe->value = (pctype)-1;
	l_npe->syminfo = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
	l_npe->module = module;
	l_npe++;
	l_nname++;

	/*
	 * We're almost done;  all we need to do is sort the symbols
	 * and then remove the duplicates.
	 */
	qsort(l_nl, (size_t)l_nname, sizeof (nltype), compare);
	remove_dup_syms(l_nl, &l_nname);

	module->nl = l_nl;
	module->npe = l_npe;
	module->nname = l_nname;

	total_names += l_nname;
}
