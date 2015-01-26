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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2011 Jason King.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "dis_target.h"
#include "dis_util.h"

/*
 * Standard ELF disassembler target.
 *
 * We only support disassembly of ELF files, though this target interface could
 * be extended in the future.  Each basic type (target, func, section) contains
 * enough information to uniquely identify the location within the file.  The
 * interfaces use libelf(3LIB) to do the actual processing of the file.
 */

/*
 * Symbol table entry type.  We maintain our own symbol table sorted by address,
 * with the symbol name already resolved against the ELF symbol table.
 */
typedef struct sym_entry {
	GElf_Sym	se_sym;		/* value of symbol */
	char		*se_name;	/* name of symbol */
	int		se_shndx;	/* section where symbol is located */
} sym_entry_t;

/*
 * Create a map of the virtual address ranges of every section.  This will
 * allow us to create dummpy mappings for unassigned addresses.  Otherwise
 * multiple sections with unassigned addresses will appear to overlap and
 * mess up symbol resolution (which uses the virtual address).
 */
typedef struct dis_shnmap {
	const char 	*dm_name;	/* name of section */
	uint64_t	dm_start;	/* virtual address of section */
	size_t		dm_length;	/* address length */
	boolean_t	dm_mapped;	/* did we assign the mapping */
} dis_shnmap_t;

/*
 * Target data structure.  This structure keeps track of the ELF file
 * information, a few bits of pre-processed section index information, and
 * sorted versions of the symbol table.  We also keep track of the last symbol
 * looked up, as the majority of lookups remain within the same symbol.
 */
struct dis_tgt {
	Elf		*dt_elf;	/* libelf handle */
	Elf		*dt_elf_root;	/* main libelf handle (for archives) */
	const char	*dt_filename;	/* name of file */
	int		dt_fd;		/* underlying file descriptor */
	size_t		dt_shstrndx;	/* section index of .shstrtab */
	size_t		dt_symidx;	/* section index of symbol table */
	sym_entry_t	*dt_symcache;	/* last symbol looked up */
	sym_entry_t	*dt_symtab;	/* sorted symbol table */
	int		dt_symcount;	/* # of symbol table entries */
	struct dis_tgt	*dt_next;	/* next target (for archives) */
	Elf_Arhdr	*dt_arhdr;	/* archive header (for archives) */
	dis_shnmap_t	*dt_shnmap;	/* section address map */
	size_t		dt_shncount;	/* # of sections in target */
};

/*
 * Function data structure.  We resolve the symbol and lookup the associated ELF
 * data when building this structure.  The offset is calculated based on the
 * section's starting address.
 */
struct dis_func {
	sym_entry_t	*df_sym;	/* symbol table reference */
	Elf_Data	*df_data;	/* associated ELF data */
	size_t		df_offset;	/* offset within data */
};

/*
 * Section data structure.  We store the entire section header so that we can
 * determine some properties (such as whether or not it contains text) after
 * building the structure.
 */
struct dis_scn {
	GElf_Shdr	ds_shdr;
	const char	*ds_name;
	Elf_Data	*ds_data;
};

/* Lifted from Psymtab.c, omitting STT_TLS */
#define	DATA_TYPES      \
	((1 << STT_OBJECT) | (1 << STT_FUNC) | (1 << STT_COMMON))
#define	IS_DATA_TYPE(tp)	(((1 << (tp)) & DATA_TYPES) != 0)

/*
 * Save the virtual address range for this section and select the
 * best section to use as the symbol table.  We prefer SHT_SYMTAB
 * over SHT_DYNSYM.
 */
/* ARGSUSED */
static void
tgt_scn_init(dis_tgt_t *tgt, dis_scn_t *scn, void *data)
{
	int *index = data;

	*index += 1;

	tgt->dt_shnmap[*index].dm_name = scn->ds_name;
	tgt->dt_shnmap[*index].dm_start = scn->ds_shdr.sh_addr;
	tgt->dt_shnmap[*index].dm_length = scn->ds_shdr.sh_size;
	tgt->dt_shnmap[*index].dm_mapped = B_FALSE;

	/*
	 * Prefer SHT_SYMTAB over SHT_DYNSYM
	 */
	if (scn->ds_shdr.sh_type == SHT_DYNSYM && tgt->dt_symidx == 0)
		tgt->dt_symidx = *index;
	else if (scn->ds_shdr.sh_type == SHT_SYMTAB)
		tgt->dt_symidx = *index;
}

static int
sym_compare(const void *a, const void *b)
{
	const sym_entry_t *syma = a;
	const sym_entry_t *symb = b;
	const char *aname = syma->se_name;
	const char *bname = symb->se_name;

	if (syma->se_sym.st_value < symb->se_sym.st_value)
		return (-1);

	if (syma->se_sym.st_value > symb->se_sym.st_value)
		return (1);

	/*
	 * Prefer functions over non-functions
	 */
	if (GELF_ST_TYPE(syma->se_sym.st_info) !=
	    GELF_ST_TYPE(symb->se_sym.st_info)) {
		if (GELF_ST_TYPE(syma->se_sym.st_info) == STT_FUNC)
			return (-1);
		if (GELF_ST_TYPE(symb->se_sym.st_info) == STT_FUNC)
			return (1);
	}

	/*
	 * For symbols with the same address and type, we sort them according to
	 * a hierarchy:
	 *
	 * 	1. weak symbols (common name)
	 * 	2. global symbols (external name)
	 * 	3. local symbols
	 */
	if (GELF_ST_BIND(syma->se_sym.st_info) !=
	    GELF_ST_BIND(symb->se_sym.st_info)) {
		if (GELF_ST_BIND(syma->se_sym.st_info) == STB_WEAK)
			return (-1);
		if (GELF_ST_BIND(symb->se_sym.st_info) == STB_WEAK)
			return (1);

		if (GELF_ST_BIND(syma->se_sym.st_info) == STB_GLOBAL)
			return (-1);
		if (GELF_ST_BIND(symb->se_sym.st_info) == STB_GLOBAL)
			return (1);
	}

	/*
	 * As a last resort, if we have multiple symbols of the same type at the
	 * same address, prefer the version with the fewest leading underscores.
	 */
	if (aname == NULL)
		return (-1);
	if (bname == NULL)
		return (1);

	while (*aname == '_' && *bname == '_') {
		aname++;
		bname++;
	}

	if (*bname == '_')
		return (-1);
	if (*aname == '_')
		return (1);

	/*
	 * Prefer the symbol with the smaller size.
	 */
	if (syma->se_sym.st_size < symb->se_sym.st_size)
		return (-1);
	if (syma->se_sym.st_size > symb->se_sym.st_size)
		return (1);

	/*
	 * We really do have two identical symbols for some reason.  Just report
	 * them as equal, and to the lucky one go the spoils.
	 */
	return (0);
}

/*
 * Construct an optimized symbol table sorted by starting address.
 */
static void
construct_symtab(dis_tgt_t *tgt)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	Elf_Data *symdata;
	int i;
	GElf_Word *symshndx = NULL;
	int symshndx_size;
	sym_entry_t *sym;
	sym_entry_t *p_symtab = NULL;
	int nsym = 0; /* count of symbols we're not interested in */

	/*
	 * Find the symshndx section, if any
	 */
	for (scn = elf_nextscn(tgt->dt_elf, NULL); scn != NULL;
	    scn = elf_nextscn(tgt->dt_elf, scn)) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			break;
		if (shdr.sh_type == SHT_SYMTAB_SHNDX &&
		    shdr.sh_link == tgt->dt_symidx) {
			Elf_Data	*data;

			if ((data = elf_getdata(scn, NULL)) != NULL) {
				symshndx = (GElf_Word *)data->d_buf;
				symshndx_size = data->d_size /
				    sizeof (GElf_Word);
				break;
			}
		}
	}

	if ((scn = elf_getscn(tgt->dt_elf, tgt->dt_symidx)) == NULL)
		die("%s: failed to get section information", tgt->dt_filename);
	if (gelf_getshdr(scn, &shdr) == NULL)
		die("%s: failed to get section header", tgt->dt_filename);
	if (shdr.sh_entsize == 0)
		die("%s: symbol table has zero size", tgt->dt_filename);

	if ((symdata = elf_getdata(scn, NULL)) == NULL)
		die("%s: failed to get symbol table", tgt->dt_filename);

	tgt->dt_symcount = symdata->d_size / gelf_fsize(tgt->dt_elf, ELF_T_SYM,
	    1, EV_CURRENT);

	p_symtab = safe_malloc(tgt->dt_symcount * sizeof (sym_entry_t));

	for (i = 0, sym = p_symtab; i < tgt->dt_symcount; i++) {
		if (gelf_getsym(symdata, i, &(sym->se_sym)) == NULL) {
			warn("%s: gelf_getsym returned NULL for %d",
			    tgt->dt_filename, i);
			nsym++;
			continue;
		}

		/*
		 * We're only interested in data symbols.
		 */
		if (!IS_DATA_TYPE(GELF_ST_TYPE(sym->se_sym.st_info))) {
			nsym++;
			continue;
		}

		if (sym->se_sym.st_shndx == SHN_XINDEX && symshndx != NULL) {
			if (i > symshndx_size) {
				warn("%s: bad SHNX_XINDEX %d",
				    tgt->dt_filename, i);
				sym->se_shndx = -1;
			} else {
				sym->se_shndx = symshndx[i];
			}
		} else {
			sym->se_shndx = sym->se_sym.st_shndx;
		}

		/* Deal with symbols with special section indicies */
		if (sym->se_shndx == SHN_ABS) {
			/*
			 * If st_value == 0, references to these
			 * symbols in code are modified in situ
			 * thus we will never attempt to look
			 * them up.
			 */
			if (sym->se_sym.st_value == 0) {
				/*
				 * References to these symbols in code
				 * are modified in situ by the runtime
				 * linker and no code on disk will ever
				 * attempt to look them up.
				 */
				nsym++;
				continue;
			} else {
				/*
				 * If st_value != 0, (such as examining
				 * something in /system/object/.../object)
				 * the values should resolve to a value
				 * within an existing section (such as
				 * .data).  This also means it never needs
				 * to have st_value mapped.
				 */
				sym++;
				continue;
			}
		}

		/*
		 * Ignore the symbol if it has some other special
		 * section index
		 */
		if (sym->se_shndx == SHN_UNDEF ||
		    sym->se_shndx >= SHN_LORESERVE) {
			nsym++;
			continue;
		}

		if ((sym->se_name = elf_strptr(tgt->dt_elf, shdr.sh_link,
		    (size_t)sym->se_sym.st_name)) == NULL) {
			warn("%s: failed to lookup symbol %d name",
			    tgt->dt_filename, i);
			nsym++;
			continue;
		}

		/*
		 * If we had to map this section, its symbol value
		 * also needs to be mapped.
		 */
		if (tgt->dt_shnmap[sym->se_shndx].dm_mapped)
			sym->se_sym.st_value +=
			    tgt->dt_shnmap[sym->se_shndx].dm_start;

		sym++;
	}

	tgt->dt_symcount -= nsym;
	tgt->dt_symtab = realloc(p_symtab, tgt->dt_symcount *
	    sizeof (sym_entry_t));

	qsort(tgt->dt_symtab, tgt->dt_symcount, sizeof (sym_entry_t),
	    sym_compare);
}

/*
 * Assign virtual address ranges for sections that need it
 */
static void
create_addrmap(dis_tgt_t *tgt)
{
	uint64_t addr;
	int i;

	if (tgt->dt_shnmap == NULL)
		return;

	/* find the greatest used address */
	for (addr = 0, i = 1; i < tgt->dt_shncount; i++)
		if (tgt->dt_shnmap[i].dm_start > addr)
			addr = tgt->dt_shnmap[i].dm_start +
			    tgt->dt_shnmap[i].dm_length;

	addr = P2ROUNDUP(addr, 0x1000);

	/*
	 * Assign section a starting address beyond the largest mapped section
	 * if no address was given.
	 */
	for (i = 1; i < tgt->dt_shncount; i++) {
		if (tgt->dt_shnmap[i].dm_start != 0)
			continue;

		tgt->dt_shnmap[i].dm_start = addr;
		tgt->dt_shnmap[i].dm_mapped = B_TRUE;
		addr = P2ROUNDUP(addr + tgt->dt_shnmap[i].dm_length, 0x1000);
	}
}

/*
 * Create a target backed by an ELF file.
 */
dis_tgt_t *
dis_tgt_create(const char *file)
{
	dis_tgt_t *tgt, *current;
	int idx;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Arhdr *arhdr = NULL;
	int cmd;

	if (elf_version(EV_CURRENT) == EV_NONE)
		die("libelf(3ELF) out of date");

	tgt = safe_malloc(sizeof (dis_tgt_t));

	if ((tgt->dt_fd = open(file, O_RDONLY)) < 0) {
		warn("%s: failed opening file, reason: %s", file,
		    strerror(errno));
		free(tgt);
		return (NULL);
	}

	if ((tgt->dt_elf_root =
	    elf_begin(tgt->dt_fd, ELF_C_READ, NULL)) == NULL) {
		warn("%s: invalid or corrupt ELF file", file);
		dis_tgt_destroy(tgt);
		return (NULL);
	}

	current = tgt;
	cmd = ELF_C_READ;
	while ((elf = elf_begin(tgt->dt_fd, cmd, tgt->dt_elf_root)) != NULL) {
		size_t shnum = 0;

		if (elf_kind(tgt->dt_elf_root) == ELF_K_AR &&
		    (arhdr = elf_getarhdr(elf)) == NULL) {
			warn("%s: malformed archive", file);
			dis_tgt_destroy(tgt);
			return (NULL);
		}

		/*
		 * Make sure that this Elf file is sane
		 */
		if (gelf_getehdr(elf, &ehdr) == NULL) {
			if (arhdr != NULL) {
				/*
				 * For archives, we drive on in the face of bad
				 * members.  The "/" and "//" members are
				 * special, and should be silently ignored.
				 */
				if (strcmp(arhdr->ar_name, "/") != 0 &&
				    strcmp(arhdr->ar_name, "//") != 0)
					warn("%s[%s]: invalid file type",
					    file, arhdr->ar_name);
				cmd = elf_next(elf);
				(void) elf_end(elf);
				continue;
			}

			warn("%s: invalid file type", file);
			dis_tgt_destroy(tgt);
			return (NULL);
		}

		/*
		 * If we're seeing a new Elf object, then we have an
		 * archive. In this case, we create a new target, and chain it
		 * off the master target.  We can later iterate over these
		 * targets using dis_tgt_next().
		 */
		if (current->dt_elf != NULL) {
			dis_tgt_t *next = safe_malloc(sizeof (dis_tgt_t));
			next->dt_elf_root = tgt->dt_elf_root;
			next->dt_fd = -1;
			current->dt_next = next;
			current = next;
		}
		current->dt_elf = elf;
		current->dt_arhdr = arhdr;

		if (elf_getshdrstrndx(elf, &current->dt_shstrndx) == -1) {
			warn("%s: failed to get section string table for "
			    "file", file);
			dis_tgt_destroy(tgt);
			return (NULL);
		}

		if (elf_getshdrnum(elf, &shnum) == -1) {
			warn("%s: failed to get number of sections in file",
			    file);
			dis_tgt_destroy(tgt);
			return (NULL);
		}

		current->dt_shnmap = safe_malloc(sizeof (dis_shnmap_t) *
		    shnum);
		current->dt_shncount = shnum;

		idx = 0;
		dis_tgt_section_iter(current, tgt_scn_init, &idx);
		current->dt_filename = file;

		create_addrmap(current);
		if (current->dt_symidx != 0)
			construct_symtab(current);

		cmd = elf_next(elf);
	}

	/*
	 * Final sanity check.  If we had an archive with no members, then bail
	 * out with a nice message.
	 */
	if (tgt->dt_elf == NULL) {
		warn("%s: empty archive\n", file);
		dis_tgt_destroy(tgt);
		return (NULL);
	}

	return (tgt);
}

/*
 * Return the filename associated with the target.
 */
const char *
dis_tgt_name(dis_tgt_t *tgt)
{
	return (tgt->dt_filename);
}

/*
 * Return the archive member name, if any.
 */
const char *
dis_tgt_member(dis_tgt_t *tgt)
{
	if (tgt->dt_arhdr)
		return (tgt->dt_arhdr->ar_name);
	else
		return (NULL);
}

/*
 * Return the Elf_Ehdr associated with this target.  Needed to determine which
 * disassembler to use.
 */
void
dis_tgt_ehdr(dis_tgt_t *tgt, GElf_Ehdr *ehdr)
{
	(void) gelf_getehdr(tgt->dt_elf, ehdr);
}

/*
 * Return the next target in the list, if this is an archive.
 */
dis_tgt_t *
dis_tgt_next(dis_tgt_t *tgt)
{
	return (tgt->dt_next);
}

/*
 * Destroy a target and free up any associated memory.
 */
void
dis_tgt_destroy(dis_tgt_t *tgt)
{
	dis_tgt_t *current, *next;

	current = tgt->dt_next;
	while (current != NULL) {
		next = current->dt_next;
		if (current->dt_elf)
			(void) elf_end(current->dt_elf);
		if (current->dt_symtab)
			free(current->dt_symtab);
		free(current);
		current = next;
	}

	if (tgt->dt_elf)
		(void) elf_end(tgt->dt_elf);
	if (tgt->dt_elf_root)
		(void) elf_end(tgt->dt_elf_root);

	if (tgt->dt_symtab)
		free(tgt->dt_symtab);

	free(tgt);
}

/*
 * Given an address, return the section it is in and set the offset within
 * the section.
 */
const char *
dis_find_section(dis_tgt_t *tgt, uint64_t addr, off_t *offset)
{
	int i;

	for (i = 1; i < tgt->dt_shncount; i++) {
		if ((addr >= tgt->dt_shnmap[i].dm_start) &&
		    (addr < tgt->dt_shnmap[i].dm_start +
		    tgt->dt_shnmap[i].dm_length)) {
			*offset = addr - tgt->dt_shnmap[i].dm_start;
			return (tgt->dt_shnmap[i].dm_name);
		}
	}

	*offset = 0;
	return (NULL);
}

/*
 * Given an address, returns the name of the corresponding symbol, as well as
 * the offset within that symbol.  If no matching symbol is found, then NULL is
 * returned.
 *
 * If 'cache_result' is specified, then we keep track of the resulting symbol.
 * This cached result is consulted first on subsequent lookups in order to avoid
 * unecessary lookups.  This flag should be used for resolving the current PC,
 * as the majority of addresses stay within the current function.
 */
const char *
dis_tgt_lookup(dis_tgt_t *tgt, uint64_t addr, off_t *offset, int cache_result,
    size_t *size, int *isfunc)
{
	int lo, hi, mid;
	sym_entry_t *sym, *osym, *match;
	int found;

	*offset = 0;
	*size = 0;
	if (isfunc != NULL)
		*isfunc = 0;

	if (tgt->dt_symcache != NULL &&
	    addr >= tgt->dt_symcache->se_sym.st_value &&
	    addr < tgt->dt_symcache->se_sym.st_value +
	    tgt->dt_symcache->se_sym.st_size) {
		sym = tgt->dt_symcache;
		*offset = addr - sym->se_sym.st_value;
		*size = sym->se_sym.st_size;
		if (isfunc != NULL)
			*isfunc = (GELF_ST_TYPE(sym->se_sym.st_info) ==
			    STT_FUNC);
		return (sym->se_name);
	}

	lo = 0;
	hi = (tgt->dt_symcount - 1);
	found = 0;
	match = osym = NULL;
	while (lo <= hi) {
		mid = (lo + hi) / 2;

		sym = &tgt->dt_symtab[mid];

		if (addr >= sym->se_sym.st_value &&
		    addr < sym->se_sym.st_value + sym->se_sym.st_size &&
		    (!found || sym->se_sym.st_value > osym->se_sym.st_value)) {
			osym = sym;
			found = 1;
		} else if (addr == sym->se_sym.st_value) {
			/*
			 * Particularly for .plt objects, it's possible to have
			 * a zero sized object.  We want to return this, but we
			 * want it to be a last resort.
			 */
			match = sym;
		}

		if (addr < sym->se_sym.st_value)
			hi = mid - 1;
		else
			lo = mid + 1;
	}

	if (!found) {
		if (match)
			osym = match;
		else
			return (NULL);
	}

	/*
	 * Walk backwards to find the best match.
	 */
	do {
		sym = osym;

		if (osym == tgt->dt_symtab)
			break;

		osym = osym - 1;
	} while ((sym->se_sym.st_value == osym->se_sym.st_value) &&
	    (addr >= osym->se_sym.st_value) &&
	    (addr < osym->se_sym.st_value + osym->se_sym.st_size));

	if (cache_result)
		tgt->dt_symcache = sym;

	*offset = addr - sym->se_sym.st_value;
	*size = sym->se_sym.st_size;
	if (isfunc)
		*isfunc = (GELF_ST_TYPE(sym->se_sym.st_info) == STT_FUNC);

	return (sym->se_name);
}

/*
 * Given an address, return the starting offset of the next symbol in the file.
 * Only needed on variable length instruction architectures.
 */
off_t
dis_tgt_next_symbol(dis_tgt_t *tgt, uint64_t addr)
{
	sym_entry_t *sym;

	sym = (tgt->dt_symcache != NULL) ? tgt->dt_symcache : tgt->dt_symtab;

	while (sym != (tgt->dt_symtab + tgt->dt_symcount)) {
		if (sym->se_sym.st_value >= addr)
			return (sym->se_sym.st_value - addr);
		sym++;
	}

	return (0);
}

/*
 * Iterate over all sections in the target, executing the given callback for
 * each.
 */
void
dis_tgt_section_iter(dis_tgt_t *tgt, section_iter_f func, void *data)
{
	dis_scn_t sdata;
	Elf_Scn *scn;
	int idx;

	for (scn = elf_nextscn(tgt->dt_elf, NULL), idx = 1; scn != NULL;
	    scn = elf_nextscn(tgt->dt_elf, scn), idx++) {

		if (gelf_getshdr(scn, &sdata.ds_shdr) == NULL) {
			warn("%s: failed to get section %d header",
			    tgt->dt_filename, idx);
			continue;
		}

		if ((sdata.ds_name = elf_strptr(tgt->dt_elf, tgt->dt_shstrndx,
		    sdata.ds_shdr.sh_name)) == NULL) {
			warn("%s: failed to get section %d name",
			    tgt->dt_filename, idx);
			continue;
		}

		if ((sdata.ds_data = elf_getdata(scn, NULL)) == NULL) {
			warn("%s: failed to get data for section '%s'",
			    tgt->dt_filename, sdata.ds_name);
			continue;
		}

		/*
		 * dis_tgt_section_iter is also used before the section map
		 * is initialized, so only check when we need to.  If the
		 * section map is uninitialized, it will return 0 and have
		 * no net effect.
		 */
		if (sdata.ds_shdr.sh_addr == 0)
			sdata.ds_shdr.sh_addr = tgt->dt_shnmap[idx].dm_start;

		func(tgt, &sdata, data);
	}
}

/*
 * Return 1 if the given section contains text, 0 otherwise.
 */
int
dis_section_istext(dis_scn_t *scn)
{
	return ((scn->ds_shdr.sh_type == SHT_PROGBITS) &&
	    (scn->ds_shdr.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)));
}

/*
 * Return a pointer to the section data.
 */
void *
dis_section_data(dis_scn_t *scn)
{
	return (scn->ds_data->d_buf);
}

/*
 * Return the size of the section data.
 */
size_t
dis_section_size(dis_scn_t *scn)
{
	return (scn->ds_data->d_size);
}

/*
 * Return the address for the given section.
 */
uint64_t
dis_section_addr(dis_scn_t *scn)
{
	return (scn->ds_shdr.sh_addr);
}

/*
 * Return the name of the current section.
 */
const char *
dis_section_name(dis_scn_t *scn)
{
	return (scn->ds_name);
}

/*
 * Create an allocated copy of the given section
 */
dis_scn_t *
dis_section_copy(dis_scn_t *scn)
{
	dis_scn_t *new;

	new = safe_malloc(sizeof (dis_scn_t));
	(void) memcpy(new, scn, sizeof (dis_scn_t));

	return (new);
}

/*
 * Free section memory
 */
void
dis_section_free(dis_scn_t *scn)
{
	free(scn);
}

/*
 * Iterate over all functions in the target, executing the given callback for
 * each one.
 */
void
dis_tgt_function_iter(dis_tgt_t *tgt, function_iter_f func, void *data)
{
	int i;
	sym_entry_t *sym;
	dis_func_t df;
	Elf_Scn *scn;
	GElf_Shdr	shdr;

	for (i = 0, sym = tgt->dt_symtab; i < tgt->dt_symcount; i++, sym++) {

		/* ignore non-functions */
		if ((GELF_ST_TYPE(sym->se_sym.st_info) != STT_FUNC) ||
		    (sym->se_name == NULL) ||
		    (sym->se_sym.st_size == 0) ||
		    (sym->se_shndx >= SHN_LORESERVE))
			continue;

		/* get the ELF data associated with this function */
		if ((scn = elf_getscn(tgt->dt_elf, sym->se_shndx)) == NULL ||
		    gelf_getshdr(scn, &shdr) == NULL ||
		    (df.df_data = elf_getdata(scn, NULL)) == NULL ||
		    df.df_data->d_size == 0) {
			warn("%s: failed to read section %d",
			    tgt->dt_filename, sym->se_shndx);
			continue;
		}

		if (tgt->dt_shnmap[sym->se_shndx].dm_mapped)
			shdr.sh_addr = tgt->dt_shnmap[sym->se_shndx].dm_start;

		/*
		 * Verify that the address lies within the section that we think
		 * it does.
		 */
		if (sym->se_sym.st_value < shdr.sh_addr ||
		    (sym->se_sym.st_value + sym->se_sym.st_size) >
		    (shdr.sh_addr + shdr.sh_size)) {
			warn("%s: bad section %d for address %p",
			    tgt->dt_filename, sym->se_sym.st_shndx,
			    sym->se_sym.st_value);
			continue;
		}

		df.df_sym = sym;
		df.df_offset = sym->se_sym.st_value - shdr.sh_addr;

		func(tgt, &df, data);
	}
}

/*
 * Return the data associated with a given function.
 */
void *
dis_function_data(dis_func_t *func)
{
	return ((char *)func->df_data->d_buf + func->df_offset);
}

/*
 * Return the size of a function.
 */
size_t
dis_function_size(dis_func_t *func)
{
	return (func->df_sym->se_sym.st_size);
}

/*
 * Return the address of a function.
 */
uint64_t
dis_function_addr(dis_func_t *func)
{
	return (func->df_sym->se_sym.st_value);
}

/*
 * Return the name of the function
 */
const char *
dis_function_name(dis_func_t *func)
{
	return (func->df_sym->se_name);
}

/*
 * Return a copy of a function.
 */
dis_func_t *
dis_function_copy(dis_func_t *func)
{
	dis_func_t *new;

	new = safe_malloc(sizeof (dis_func_t));
	(void) memcpy(new, func, sizeof (dis_func_t));

	return (new);
}

/*
 * Free function memory
 */
void
dis_function_free(dis_func_t *func)
{
	free(func);
}
