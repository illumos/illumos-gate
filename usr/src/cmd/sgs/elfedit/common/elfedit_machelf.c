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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * ELFCLASS specific code for elfedit, built once for each class
 */
#include	<stdlib.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<_machelf.h>
#include	<libelf.h>
#include	<strings.h>
#include	<sgs.h>
#include	"msg.h"
#include	"_elfedit.h"



/*
 * Look up the elfedit_symtab_t that corresponds to the symbol table
 * referenced by the sh_link field of the given auxiliary section.
 *
 * entry:
 *	obj_state - Partially constructed object state from
 *		elfedit_init_obj_state().
 *	auxsec - Section that is associated with the symbol table section
 *
 * exit:
 *	Returns the pointer to the elfedit_symtab_t entry that is
 *	referenced by the auxiliary section. If not found,
 *	outputs a debug message, and returns NULL.
 */
static elfedit_symtab_t *
get_symtab(elfedit_obj_state_t *obj_state, elfedit_section_t *auxsec)
{
	elfedit_symtab_t *symtab = obj_state->os_symtab;
	Word	sh_link = auxsec->sec_shdr->sh_link;
	Word	i;

	for (i = 0; i < obj_state->os_symtabnum; i++, symtab++)
		if (symtab->symt_shndx == sh_link)
			return (symtab);

	/*
	 * If we don't return above, it doesn't reference a valid
	 * symbol table. Issue warning.
	 */
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_AUX_LINK),
	    EC_WORD(auxsec->sec_shndx), auxsec->sec_name,
	    EC_WORD(sh_link));

	return (NULL);
}


/*
 * Fill in state.elf.obj_state with a a dynamically allocated
 * elfedit_obj_state_t struct of the appropriate ELFCLASS.
 * This pre-chewed form is fed to each command, reducing the amount
 * of ELF boilerplate code each command needs to contain.
 *
 * entry:
 *	file - Name of file to process
 *	fd - Descriptor of open file which has been successfully
 *		processed by elf_begin().
 *	elf - Elf handle returned by elf_begin
 *
 * exit:
 *	An elfedit_obj_state_t struct of the appropriate ELFCLASS has
 *	been dynamically allocated, and state.elf.obj_state references it.
 *	On failure, this routine does not return to the caller.
 *
 * note: The resulting elfedit_obj_state_t is allocated from a single
 *	piece of memory, such that a single call to free() suffices
 *	to release it as well as any memory it references.
 */
#ifdef _ELF64
void
elfedit64_init_obj_state(const char *file, int fd, Elf *elf)
#else
void
elfedit32_init_obj_state(const char *file, int fd, Elf *elf)
#endif
{
#define	INITIAL_SYMTABNDX_ALLOC	5

	/*
	 * These macros are used to call functions from libelf.
	 *
	 * LIBELF_FAIL encapsulates the common way in which we handle
	 * all of these errors: libelf_fail_name is set and execution
	 * jumps to the libelf_failure label for handling.
	 *
	 * LIBELF is used for the common case in which the function returns
	 * NULL for failure and something else for success.
	 */
#define	LIBELF_FAIL(_name) { libelf_fail_name = _name; goto libelf_failure; }
#define	LIBELF(_libelf_expr, _name) \
	if ((_libelf_expr) == NULL) \
		LIBELF_FAIL(_name)

	const char *libelf_fail_name;	/* Used for LIBELF errors */

	Elf_Scn			*scn;
	Elf_Data		*data;
	uint_t			ndx;
	size_t			len, os_size, secarr_size;
	char			*names = 0;
	size_t			names_len;
	elfedit_section_t	*_cache;
	elfedit_obj_state_t	tstate;
	elfedit_obj_state_t	*obj_state = NULL;
	Word			*symtabndx = NULL;
	Word			symtabndx_size = 0;
	elfedit_symtab_t	*symtab;

	tstate.os_file = file;
	tstate.os_fd = fd;
	tstate.os_elf = elf;
	tstate.os_dynndx = SHN_UNDEF;
	tstate.os_symtabnum = 0;

	LIBELF(tstate.os_ehdr = elf_getehdr(tstate.os_elf),
	    MSG_ORIG(MSG_ELF_GETEHDR))

	/* Program header array count and address */
	if (elf_getphdrnum(tstate.os_elf, &tstate.os_phnum) == -1)
		LIBELF_FAIL(MSG_ORIG(MSG_ELF_GETPHDRNUM))
	if (tstate.os_phnum > 0) {
		LIBELF((tstate.os_phdr = elf_getphdr(tstate.os_elf)),
		    MSG_ORIG(MSG_ELF_GETPHDR))
	} else {
		tstate.os_phdr = NULL;
	}

	if (elf_getshdrnum(tstate.os_elf, &tstate.os_shnum) == -1)
		LIBELF_FAIL(MSG_ORIG(MSG_ELF_GETSHDRNUM))

	/*
	 * Obtain the .shstrtab data buffer to provide the required section
	 * name strings.
	 */
	if (elf_getshdrstrndx(tstate.os_elf, &tstate.os_shstrndx) == -1)
		LIBELF_FAIL(MSG_ORIG(MSG_ELF_GETSHDRSTRNDX))
	LIBELF((scn = elf_getscn(tstate.os_elf, tstate.os_shstrndx)),
	    MSG_ORIG(MSG_ELF_GETSCN))
	LIBELF((data = elf_getdata(scn, NULL)), MSG_ORIG(MSG_ELF_GETDATA))
	names = data->d_buf;
	names_len = (names == NULL) ? 0 : data->d_size;

	/*
	 * Count the number of symbol tables and capture their indexes.
	 * Find the dynamic section.
	 */
	for (ndx = 1, scn = NULL; scn = elf_nextscn(tstate.os_elf, scn);
	    ndx++) {
		Shdr *shdr;

		LIBELF(shdr = elf_getshdr(scn), MSG_ORIG(MSG_ELF_GETSHDR));

		switch (shdr->sh_type) {
		case SHT_DYNAMIC:
			/* Save index of dynamic section for use below */
			tstate.os_dynndx = ndx;
			break;

		case SHT_SYMTAB:
		case SHT_DYNSYM:
		case SHT_SUNW_LDYNSYM:
			if (symtabndx_size <= tstate.os_symtabnum) {
				symtabndx_size = (symtabndx_size == 0) ?
				    INITIAL_SYMTABNDX_ALLOC :
				    (symtabndx_size * 2);
				symtabndx = elfedit_realloc(
				    MSG_INTL(MSG_ALLOC_SYMTABOS), symtabndx,
				    symtabndx_size * sizeof (symtabndx[0]));
			}
			symtabndx[tstate.os_symtabnum++] = ndx;
			break;
		}
	}

	/*
	 * Allocate space to hold the state. We allocate space for everything
	 * in one chunk to make releasing it easy:
	 *	(1) elfedit_obj_state_t struct
	 *	(2) The array of elfedit_section_t items referenced from
	 *		the elfedit_obj_state_t struct.
	 *	(3) The array of elfedit_symtab_t items referenced from
	 *		the elfedit_obj_state_t struct.
	 *	(4) The file name.
	 *
	 * Note that we round up the size of (1) and (2) to a double boundary
	 * to ensure proper alignment of (2) and (3). (4) can align on any
	 * boundary.
	 */
	os_size = S_DROUND(sizeof (tstate));
	secarr_size = (tstate.os_shnum * sizeof (elfedit_section_t));
	secarr_size = S_DROUND(secarr_size);
	len = strlen(tstate.os_file) + 1;
	obj_state = elfedit_malloc(MSG_INTL(MSG_ALLOC_OBJSTATE),
	    os_size + secarr_size +
	    (tstate.os_symtabnum * sizeof (elfedit_symtab_t)) + len);
	*obj_state = tstate;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	obj_state->os_secarr = (elfedit_section_t *)
	    ((char *)obj_state + os_size);
	if (obj_state->os_symtabnum == 0) {
		obj_state->os_symtab = NULL;
	} else {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		obj_state->os_symtab = (elfedit_symtab_t *)
		    ((char *)obj_state->os_secarr + secarr_size);
		obj_state->os_file =
		    (char *)(obj_state->os_symtab + tstate.os_symtabnum);
		(void) strncpy((char *)obj_state->os_file, tstate.os_file, len);
	}

	/*
	 * Fill in obj_state->os_secarr with information for each section.
	 * At the same time, fill in obj_state->os_symtab with the symbol
	 * table related data.
	 */
	bzero(obj_state->os_secarr, sizeof (obj_state->os_secarr[0]));
	_cache = obj_state->os_secarr;
	LIBELF(scn = elf_getscn(tstate.os_elf, 0),
	    MSG_ORIG(MSG_ELF_GETSCN));
	_cache->sec_scn = scn;
	LIBELF(_cache->sec_shdr = elf_getshdr(scn), MSG_ORIG(MSG_ELF_GETSHDR));
	_cache->sec_name = (_cache->sec_shdr->sh_name < names_len) ?
	    (names + _cache->sec_shdr->sh_name) : MSG_INTL(MSG_UNKNOWNSECNAM);
	_cache++;

	if (obj_state->os_symtab != NULL) {
		bzero(obj_state->os_symtab,
		    sizeof (obj_state->os_symtab[0]) * obj_state->os_symtabnum);
		for (ndx = 0; ndx < obj_state->os_symtabnum; ndx++)
			obj_state->os_symtab[ndx].symt_shndx = symtabndx[ndx];
		free(symtabndx);
	}

	for (ndx = 1, scn = NULL; scn = elf_nextscn(tstate.os_elf, scn);
	    ndx++, _cache++) {
		_cache->sec_shndx = ndx;
		_cache->sec_scn = scn;
		LIBELF(_cache->sec_shdr = elf_getshdr(scn),
		    MSG_ORIG(MSG_ELF_GETSHDR))
		_cache->sec_data = elf_getdata(scn, NULL);
		_cache->sec_name = (_cache->sec_shdr->sh_name < names_len) ?
		    (names + _cache->sec_shdr->sh_name) :
		    MSG_INTL(MSG_UNKNOWNSECNAM);

		switch (_cache->sec_shdr->sh_type) {
		case SHT_SYMTAB_SHNDX:
			symtab = get_symtab(obj_state, _cache);
			symtab->symt_xshndx = ndx;
			break;

		case SHT_SUNW_syminfo:
			symtab = get_symtab(obj_state, _cache);
			symtab->symt_syminfo = ndx;
			break;

		case SHT_SUNW_versym:
			symtab = get_symtab(obj_state, _cache);
			symtab->symt_versym = ndx;
			break;
		}
	}

	/*
	 * Sanity check the symbol tables, and discard any auxiliary
	 * sections without enough elements.
	 */
	symtab = obj_state->os_symtab;
	for (ndx = 0; ndx < obj_state->os_symtabnum; ndx++, symtab++) {
		elfedit_section_t	*symsec;
		Word			symsec_cnt, aux_cnt;

		symsec = &obj_state->os_secarr[symtab->symt_shndx];
		symsec_cnt = symsec->sec_shdr->sh_size / sizeof (Sym);

		/* Extended section indexes */
		if (symtab->symt_xshndx != SHN_UNDEF) {
			_cache = &obj_state->os_secarr[symtab->symt_xshndx];
			aux_cnt = _cache->sec_shdr->sh_size / sizeof (Word);
			if (symsec_cnt > aux_cnt)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_AUX_SIZE),
				    EC_WORD(ndx), _cache->sec_name,
				    EC_WORD(aux_cnt),
				    EC_WORD(symsec->sec_shndx),
				    symsec->sec_name, EC_WORD(aux_cnt));
		}

		/* Syminfo */
		if (symtab->symt_syminfo != SHN_UNDEF) {
			_cache = &obj_state->os_secarr[symtab->symt_syminfo];
			aux_cnt = _cache->sec_shdr->sh_size / sizeof (Syminfo);
			if (symsec_cnt > aux_cnt)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_AUX_SIZE),
				    EC_WORD(ndx), _cache->sec_name,
				    EC_WORD(aux_cnt),
				    EC_WORD(symsec->sec_shndx),
				    symsec->sec_name, EC_WORD(aux_cnt));
		}

		/* Versym */
		if (symtab->symt_versym != SHN_UNDEF) {
			_cache = &obj_state->os_secarr[symtab->symt_versym];
			aux_cnt = _cache->sec_shdr->sh_size / sizeof (Versym);
			if (symsec_cnt > aux_cnt)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_AUX_SIZE),
				    EC_WORD(ndx), _cache->sec_name,
				    EC_WORD(aux_cnt),
				    EC_WORD(symsec->sec_shndx),
				    symsec->sec_name, EC_WORD(aux_cnt));
		}
	}

	/*
	 * If this object has a dynsym section with a FLAGS_1 field,
	 * then set the DF_1_EDITED bit. elfedit allows changes that
	 * can break the resulting program, so knowing that a file was
	 * edited can be helpful when encountering a core file or other
	 * unexpected failure in the field. A single bit can't tell you
	 * what was changed, but it will alert you to the possibility that
	 * some additional questions might be in order.
	 */
	if (obj_state->os_dynndx != SHN_UNDEF) {
		Word			i;
		Word			numdyn;
		elfedit_section_t	*dynsec;
		elfedit_dyn_elt_t	flags_1_elt;
		elfedit_dyn_elt_t	null_elt;
		Dyn			*dyn;

		dynsec = &obj_state->os_secarr[obj_state->os_dynndx];
		dyn = (Dyn *) dynsec->sec_data->d_buf;
		numdyn = dynsec->sec_shdr->sh_size /
		    dynsec->sec_shdr->sh_entsize;
		elfedit_dyn_elt_init(&flags_1_elt);
		elfedit_dyn_elt_init(&null_elt);
		for (i = 0; i < numdyn; i++) {

			switch (dyn[i].d_tag) {
			case DT_NULL:
				/*
				 * Remember state of the first DT_NULL. If there
				 * are more than one (i.e. the first one is not
				 * in the final spot), and there is no flags1,
				 * then we will turn the first one into a
				 * DT_FLAGS_1.
				 */
				if (!null_elt.dn_seen)
					elfedit_dyn_elt_save(&null_elt, i,
					    &dyn[i]);
				break;

			case DT_FLAGS_1:
				elfedit_dyn_elt_save(&flags_1_elt, i, &dyn[i]);
				break;
			}
		}
		/* If don't have a flags1 field, can we make one from a NULL? */
		if (!flags_1_elt.dn_seen && null_elt.dn_seen &&
		    (null_elt.dn_ndx < (numdyn - 1))) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_NULL2DYNFL1),
			    EC_WORD(obj_state->os_dynndx),
			    dynsec->sec_name, EC_WORD(null_elt.dn_ndx));
			flags_1_elt.dn_seen = 1;
			flags_1_elt.dn_ndx = null_elt.dn_ndx;
			flags_1_elt.dn_dyn.d_tag = DT_FLAGS_1;
			flags_1_elt.dn_dyn.d_un.d_val = 0;
		}
		/*
		 * If there is a flags 1 field, add the edit flag if
		 * it is not present, and report it's presence otherwise.
		 */
		if (flags_1_elt.dn_seen) {
			if (flags_1_elt.dn_dyn.d_un.d_val & DF_1_EDITED) {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_SEEDYNFLG),
				    EC_WORD(obj_state->os_dynndx),
				    dynsec->sec_name,
				    EC_WORD(flags_1_elt.dn_ndx));
			} else {
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_ADDDYNFLG),
				    EC_WORD(obj_state->os_dynndx),
				    dynsec->sec_name,
				    EC_WORD(flags_1_elt.dn_ndx));
				flags_1_elt.dn_dyn.d_un.d_val |= DF_1_EDITED;
				dyn[flags_1_elt.dn_ndx] = flags_1_elt.dn_dyn;
				elfedit_modified_data(dynsec);
			}
		}
	}

#ifdef _ELF64
	state.elf.obj_state.s64 = obj_state;
#else
	state.elf.obj_state.s32 = obj_state;
#endif
	return;

libelf_failure:
	/*
	 * Control comes here if there is an error with LIBELF.
	 *
	 * entry:
	 *	libelf_fail_name - Name of failing libelf function
	 *	tstate.os_file - Name of ELF file being processed
	 *	tstate.os_fd - Descriptor of open ELF file
	 *
	 * exit:
	 *	- dynamic memory is released if necessary
	 *	- The error issued
	 */
	if (obj_state != NULL)
		free(obj_state);
	(void) close(tstate.os_fd);
	elfedit_elferr(tstate.os_file, libelf_fail_name);
#undef INITIAL_SYMTABNDX_ALLOC
#undef LIBELF_FAIL
#undef LIBELF
}
