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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<libintl.h>
#include	<machdep.h>
#include	<libelf.h>
#include	<link.h>
#include	<strings.h>
#include	<ctype.h>
#include	"msg.h"
#include	<elfedit.h>
#include	<conv.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>



/*
 * ELFCLASS specific code that would otherwise be found in util.c
 */




/*
 * When you modify ELF constructs, you need to tell libelf that you've
 * done so. Otherwise, the changes may not be flushed back to the
 * output file.
 *
 * The elfedit_modified_*() functions exist to simplify the calls to
 * the underlying elf_flag*() functions.
 */
void
elfedit_modified_ehdr(elfedit_obj_state_t *obj_state)
{
	(void) elf_flagehdr(obj_state->os_elf, ELF_C_SET, ELF_F_DIRTY);
}

void
elfedit_modified_phdr(elfedit_obj_state_t *obj_state)
{
	(void) elf_flagphdr(obj_state->os_elf, ELF_C_SET, ELF_F_DIRTY);
}

void
elfedit_modified_shdr(elfedit_section_t *s)
{
	(void) elf_flagshdr(s->sec_scn, ELF_C_SET, ELF_F_DIRTY);
}

void
elfedit_modified_data(elfedit_section_t *s)
{
	(void) elf_flagdata(s->sec_data, ELF_C_SET, ELF_F_DIRTY);
}



/*
 * Prepare an elfedit_dyn_elt_t structure for use.
 */
void
elfedit_dyn_elt_init(elfedit_dyn_elt_t *elt)
{
	elt->dn_seen = 0;
}

/*
 * Given a dynamic section item, save it in the given elfedit_dyn_elt_t
 * structure and mark that structure to show that it is present.
 */
void
elfedit_dyn_elt_save(elfedit_dyn_elt_t *elt, Word ndx, Dyn *dyn)
{
	elt->dn_seen = 1;
	elt->dn_ndx = ndx;
	elt->dn_dyn = *dyn;
}


/*
 * Return the index of the first section that has the given name.
 *
 * entry:
 *	obj_state - Object state.
 *	shnam - Name of desired section
 *
 * exit:
 *	On success, returns the section index. On failure, an error
 *	is issued, and this routine does not return to the caller.
 */
Word
elfedit_name_to_shndx(elfedit_obj_state_t *obj_state, const char *shnam)
{
	elfedit_section_t *sec = obj_state->os_secarr;
	Word	ndx;
	Word	shnum = obj_state->os_shnum;

	for (ndx = 0; ndx < shnum; ndx++, sec++) {
		if (strcmp(shnam, sec->sec_name) == 0) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_SHNAM2NDX),
			    EC_WORD(sec->sec_shndx), sec->sec_name, shnam);
			return (ndx);
		}
	}

	/* If didn't return in loop above, the name doesn't match */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSECNAM), shnam);
	/*NOTREACHED*/
	return (SHN_UNDEF);
}



/*
 * Return the index of the first section that has the given type.
 *
 * entry:
 *	obj_state - Object state.
 *	shtype - Type of desired section
 *
 * exit:
 *	On success, returns the section index. On failure, an error
 *	is issued, and this routine does not return to the caller.
 */
Word
elfedit_type_to_shndx(elfedit_obj_state_t *obj_state, Word shtype)
{
	Conv_inv_buf_t inv_buf;
	elfedit_section_t *sec = obj_state->os_secarr;
	Word	ndx;
	Word	shnum = obj_state->os_shnum;

	for (ndx = 0; ndx < shnum; ndx++, sec++) {
		if (shtype == sec->sec_shdr->sh_type) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_SHNAM2NDX),
			    EC_WORD(sec->sec_shndx), sec->sec_name,
			    conv_sec_type(obj_state->os_ehdr->e_machine,
			    shtype, 0, &inv_buf));
			return (ndx);
		}
	}

	/* If didn't return in loop above, the name doesn't match */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSECTYP),
	    conv_sec_type(obj_state->os_ehdr->e_machine, shtype, 0, &inv_buf));
	/*NOTREACHED*/
	return (SHN_UNDEF);
}



/*
 * Locate the index of the first symbol that has the given name
 *
 * entry:
 *	obj_state - Object state.
 *	symsec - Symbol section
 *	strsec = String section
 *	name - String giving name of symbol to lookup
 *	msg_type - ELFEDIT_MSG_ type code to use with message
 *		issued if name does not exist in symbol table.
 *	ret_symndx - Address of variable to receive index.
 *
 * exit:
 *	On success, issues debug message, sets *ret_symndx, and returns
 *	True (1).
 *
 *	On failure, issues a message using msg_type to determine
 *	the type of message sent. If the message does not take control away
 *	from the caller, False (0) is returned.
 *
 * note:
 *	Although the string table is referenced by the sh_link field of
 *	the symbol table, we require the user to supply it rather than
 *	look it up. The reason for this is that the caller will usually
 *	have looked it up, and we wish to avoid multiple debug messages
 *	from being issued to that effect.
 */
int
elfedit_name_to_symndx(elfedit_section_t *symsec, elfedit_section_t *strsec,
    const char *name, elfedit_msg_t msg_type, Word *ret_symndx)

{
	Sym	*sym = (Sym *) symsec->sec_data->d_buf;
	Word	cnt = symsec->sec_shdr->sh_size / symsec->sec_shdr->sh_entsize;
	Word	ndx, offset;
	const char	*curname;

	for (ndx = 0; ndx < cnt; ndx++) {
		offset = sym[ndx].st_name;

		curname = elfedit_offset_to_str(strsec, offset,
		    ELFEDIT_MSG_ERR, 0);
		if (strcmp(curname, name) == 0) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_SYMNAM2NDX),
			    EC_WORD(symsec->sec_shndx),
			    symsec->sec_name, EC_WORD(ndx), name);
			*ret_symndx = ndx;
			return (1);
		}
	}

	/* If didn't return in loop above, the name doesn't match */
	elfedit_msg(msg_type, MSG_INTL(MSG_ERR_NOSYM),
	    EC_WORD(symsec->sec_shndx), symsec->sec_name, name);
	/*NOTREACHED*/
	return (0);		/* lint */
}


/*
 * Given a section index, turn it into a descriptive string.
 *	- If it is one of the special reserved indexes, the
 *		symbolic name is returned.
 *	- If it is a regular section, in range for the file,
 *		the name associated with the section is returned.
 *	- Otherwise, the number is formatted as numeric ASCII.
 *
 * exit:
 *	A pointer to the static buffer containing the name is
 *	returned. This pointer is valid until the next call
 *	to elfedit_shndx_to_name(), and which point it may
 *	be overwritten.
 */
const char *
elfedit_shndx_to_name(elfedit_obj_state_t *obj_state, Word shndx)
{
	/*
	 * This routine can be called twice within a single C statement,
	 * so we use alternating buffers on each call to allow this
	 * without requiring the caller to supply a buffer (the size of
	 * which they don't know).
	 */
	static char buf1[64], buf2[64];
	static char *buf;

	if ((obj_state->os_ehdr->e_machine == EM_AMD64) &&
	    (shndx == SHN_AMD64_LCOMMON))
		return (MSG_ORIG(MSG_SHN_AMD64_LCOMMON));

	switch (shndx) {
	case SHN_UNDEF:
		return (MSG_ORIG(MSG_SHN_UNDEF));
	case SHN_SUNW_IGNORE:
		return (MSG_ORIG(MSG_SHN_SUNW_IGNORE));
	case SHN_BEFORE:
		return (MSG_ORIG(MSG_SHN_BEFORE));
	case SHN_AFTER:
		return (MSG_ORIG(MSG_SHN_AFTER));
	case SHN_AMD64_LCOMMON:
		if (obj_state->os_ehdr->e_machine == EM_AMD64)
			return (MSG_ORIG(MSG_SHN_AMD64_LCOMMON));
		break;
	case SHN_ABS:
		return (MSG_ORIG(MSG_SHN_ABS));
	case SHN_COMMON:
		return (MSG_ORIG(MSG_SHN_COMMON));
	case SHN_XINDEX:
		return (MSG_ORIG(MSG_SHN_XINDEX));
	}


	/*
	 * If it is outside of the reserved area, and inside the
	 * range of section indexes in the ELF file, then show
	 * the section name.
	 */
	if ((shndx < obj_state->os_shnum) &&
	    ((shndx < SHN_LORESERVE) || (shndx > SHN_HIRESERVE)))
		return (obj_state->os_secarr[shndx].sec_name);

	/* Switch buffers */
	buf = (buf == buf1) ? buf2 : buf1;

	/*
	 * If we haven't identified it by now, format the
	 * number in a static buffer and return that.
	 */
	(void) snprintf(buf, sizeof (buf1),
	    MSG_ORIG(MSG_FMT_WORDVAL), shndx);
	return (buf);
}


/*
 * Locate the arbitrary section specified by shndx for this object.
 *
 * exit:
 *	Returns section descriptor on success. On failure, does not return.
 */
elfedit_section_t *
elfedit_sec_get(elfedit_obj_state_t *obj_state, Word shndx)
{
	elfedit_section_t *sec;

	if ((shndx == 0) || (shndx >= obj_state->os_shnum))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADSECNDX),
		    EC_WORD(shndx), EC_WORD(obj_state->os_shnum - 1));

	sec = &obj_state->os_secarr[shndx];

	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDSEC),
	    EC_WORD(shndx), sec->sec_name);
	return (sec);
}


/*
 * Locate the capabilities section for this object
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	cap - Address of variable to recieve pointer to capabilities
 *		section data buffer.
 *	num - Address of variable to receive number of items
 *		referenced by cap.
 *
 * exit:
 *	On success, returns section descriptor, and sets the
 *	variables referenced by cap and num.  On failure,
 *	does not return.
 */
elfedit_section_t *
elfedit_sec_getcap(elfedit_obj_state_t *obj_state, Cap **cap, Word *num)
{
	Word cnt;
	elfedit_section_t *cache;

	for (cnt = 1; cnt < obj_state->os_shnum; cnt++) {
		cache = &obj_state->os_secarr[cnt];
		if (cache->sec_shdr->sh_type == SHT_SUNW_cap) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_FNDCAP),
			    EC_WORD(cnt), cache->sec_name);
			*cap = (Cap *) cache->sec_data->d_buf;
			*num = cache->sec_shdr->sh_size /
			    cache->sec_shdr->sh_entsize;
			return (cache);
		}
	}

	/* If here, this object has no capabilities section */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOCAP));

	/*NOTREACHED*/
	return (NULL);
}


/*
 * Locate the dynamic section for this object
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	dyn - Address of variable to recieve pointer to dynamic
 *		section data buffer.
 *	numdyn - Address of variable to receive number of items
 *		referenced by dyn.
 *
 * exit:
 *	On success, returns section descriptor, and sets the
 *	variables referenced by dyn and numdyn.  On failure,
 *	does not return.
 */
elfedit_section_t *
elfedit_sec_getdyn(elfedit_obj_state_t *obj_state, Dyn **dyn, Word *num)
{
	elfedit_section_t *cache;

	if (obj_state->os_dynndx != SHN_UNDEF) {
		cache = &obj_state->os_secarr[obj_state->os_dynndx];
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDDYN),
		    EC_WORD(cache->sec_shndx), cache->sec_name);
		*dyn = (Dyn *) cache->sec_data->d_buf;
		*num = cache->sec_shdr->sh_size / cache->sec_shdr->sh_entsize;
		return (cache);
	}

	/* If here, this object has no dynamic section */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NODYN));

	/*NOTREACHED*/
	return (NULL);
}


/*
 * Locate the syminfo section for this object
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	syminfo - Address of variable to recieve pointer to syminfo
 *		section data buffer.
 *	num - Address of variable to receive number of items
 *		referenced by syminfo.
 *
 * exit:
 *	On success, returns section descriptor, and sets the
 *	variables referenced by syminfo and num.  On failure,
 *	does not return.
 */
elfedit_section_t *
elfedit_sec_getsyminfo(elfedit_obj_state_t *obj_state, Syminfo **syminfo,
    Word *num)
{
	Word cnt;
	elfedit_section_t *cache;

	for (cnt = 1; cnt < obj_state->os_shnum; cnt++) {
		cache = &obj_state->os_secarr[cnt];
		if (cache->sec_shdr->sh_type == SHT_SUNW_syminfo) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_FNDSYMINFO),
			    EC_WORD(cnt), cache->sec_name);
			*syminfo = (Syminfo *) cache->sec_data->d_buf;
			*num = cache->sec_shdr->sh_size /
			    cache->sec_shdr->sh_entsize;
			return (cache);
		}
	}

	/* If here, this object has no syminfo section */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSYMINFO));

	/*NOTREACHED*/
	return (NULL);
}


/*
 * Check the given section to see if it is a known symbol table type.
 *
 * entry:
 *	sec - Section to check
 *	issue_err - True if this routine should issue an error and
 *		not return to the caller if sec is not a symbol table.
 *	atoui_list - NULL, or address of variable to receive a pointer to
 *		an array of elfedit_atoui_sym_t items describing the
 *		type of symbol table found. This array is useful for
 *		doing command completion.
 *
 * exit:
 *	If sec is a symbol table:
 *		- If atoui_list is non-NULL, *atoui_list is set to the
 *		  appropriate ELFEDIT_CONST_xx list of items.
 *		- True (1) is returned
 *	If sec is not a symbol table and issue_err is True:
 *		- An error is issued, and this routine does not
 *			return to the caller.
 *	Otherwise:
 *		- If atoui_list is non-NULL, *atoui_list is set to NULL.
 *		- False (0) is returned
 */
int
elfedit_sec_issymtab(elfedit_section_t *sec, int issue_err,
    elfedit_atoui_sym_t **atoui_list)
{
	elfedit_const_t		const_type;
	int			ret = 1;

	/* Is the section a symbol table? */
	switch (sec->sec_shdr->sh_type) {
	case SHT_SYMTAB:
		const_type = ELFEDIT_CONST_SHT_SYMTAB;
		break;
	case SHT_DYNSYM:
		const_type = ELFEDIT_CONST_SHT_DYNSYM;
		break;
	case SHT_SUNW_LDYNSYM:
		const_type = ELFEDIT_CONST_SHT_LDYNSYM;
		break;
	default:
		if (issue_err)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_NOTSYMTAB),
			    EC_WORD(sec->sec_shndx), sec->sec_name);
		ret = 0;
		break;
	}

	if (atoui_list != NULL)
		*atoui_list = (ret == 0) ? NULL :
		    elfedit_const_to_atoui(const_type);

	return (ret);
}



/*
 * Locate a symbol table section for this object
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	by_index - If True, we want to locate the section with the
 *		section index given by index. If False, we return
 *		the section with the name given by name.
 *	index, name - Key to search for. See by_index.
 *	sym - Address of variable to recieve pointer to symbol
 *		section data buffer.
 *	numsym - Address of variable to receive number of symbols
 *		referenced by sym.
 *	aux_info - Address of variable to receive pointer to the
 *		elfedit_symtab_t struct that ties the symbol table and
 *		its related auxiliary sections together. NULL if this
 *		information is not required.
 *
 * exit:
 *	On success, returns section descriptor, and sets the
 *	variables referenced by sym, and numsym. On failure,
 *	does not return.
 */
elfedit_section_t *
elfedit_sec_getsymtab(elfedit_obj_state_t *obj_state, int by_index,
    Word index, const char *name, Sym **sym, Word *num,
    elfedit_symtab_t **aux_info)
{
	Word			ndx;
	elfedit_section_t	*symsec = NULL;
	elfedit_symtab_t	*symtab;
	const char 		*type_name;

	/* If looking it up by index, make sure the index is in range */
	if (by_index && (index >= obj_state->os_shnum))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADSECNDX),
		    EC_WORD(index), EC_WORD(obj_state->os_shnum - 1));

	/*
	 * Look at each known symbol table in turn until the desired
	 * one is hit, or there are no more.
	 */
	symtab = obj_state->os_symtab;
	for (ndx = 0; ndx < obj_state->os_symtabnum; ndx++, symtab++) {
		elfedit_section_t *s =
		    &obj_state->os_secarr[symtab->symt_shndx];

		if ((by_index && (symtab->symt_shndx == index)) ||
		    (!by_index && (strcmp(s->sec_name, name) == 0))) {
				symsec = s;
				break;
		}
	}

	/* Did we get a section? */
	if (symsec == NULL)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSYMTAB));

	/* Got it. Report to the user and return the necessary data */
	(void) elfedit_sec_issymtab(symsec, 1, NULL);
	type_name = elfedit_atoconst_value_to_str(ELFEDIT_CONST_SHT_ALLSYMTAB,
	    symsec->sec_shdr->sh_type, 1);
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDSYMTAB),
	    EC_WORD(symsec->sec_shndx), symsec->sec_name, type_name);
	*sym = (Sym *) symsec->sec_data->d_buf;
	*num = symsec->sec_shdr->sh_size / symsec->sec_shdr->sh_entsize;
	if (aux_info != NULL)
		*aux_info = symtab;
	return (symsec);
}



/*
 * Locate the extended symbol index section associated with a symbol
 * table section.
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	symsec - Symbol table section for which extended index
 *		index section is required.
 *	xshndx - Address of variable to recieve pointer to section index
 *		array data buffer.
 *	numxshndx - Address of variable to receive number of indices
 *		referenced by ndx.
 *
 * exit:
 *	On success, returns extended index section descriptor, and sets the
 *	variables referenced by xshndx, and numxshndx. On failure,
 *	does not return.
 *
 * note:
 *	Since the extended section index is found in the sec_xshndx field
 *	of the elfedit_section_t, the caller may be tempted to bypass this
 *	routine and access it directly. That temptation should be resisted,
 *	as this routine performs useful error checking, and also handles
 *	the issuing of the standard MSG_DEBUG messages.
 */
elfedit_section_t *
elfedit_sec_getxshndx(elfedit_obj_state_t *obj_state,
    elfedit_section_t *symsec, Word **xshndx, Word *num)
{
	elfedit_section_t	*xshndxsec;
	elfedit_symtab_t	*symtab;
	Word			ndx;

	/* Sanity check: symsec must be a symbol table */
	(void) elfedit_sec_issymtab(symsec, 1, NULL);

	symtab = obj_state->os_symtab;
	for (ndx = 0; ndx < obj_state->os_symtabnum; ndx++, symtab++)
		if (symsec->sec_shndx == symtab->symt_shndx)
			break;

	/*
	 * Issue error if the symbol table lacks an extended index section.
	 * The caller won't ask unless they encounter an SHN_XINDEX value,
	 * in which case the lack of the index section denotes a corrupt
	 * ELF file.
	 */
	if ((ndx == obj_state->os_symtabnum) ||
	    (symtab->symt_xshndx == SHN_UNDEF))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOXSHSEC),
		    EC_WORD(symsec->sec_shndx), symsec->sec_name);

	/* Got it. Report to the user and return the necessary data */
	xshndxsec = &obj_state->os_secarr[symtab->symt_xshndx];
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDXSHNDX),
	    EC_WORD(symsec->sec_shndx), symsec->sec_name,
	    EC_WORD(xshndxsec->sec_shndx), xshndxsec->sec_name);
	*xshndx = (Word *) xshndxsec->sec_data->d_buf;
	*num = xshndxsec->sec_shdr->sh_size / xshndxsec->sec_shdr->sh_entsize;
	return (xshndxsec);
}



/*
 * Locate the versym section associated with a symbol table section.
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	symsec - Symbol table section for which extended index
 *		index section is required.
 *	versym - Address of variable to recieve pointer to section index
 *		array data buffer.
 *	numversym - Address of variable to receive number of indices
 *		referenced by ndx.
 *
 * exit:
 *	On success, returns versym section descriptor, and sets the
 *	variables referenced by versym, and numversym. On failure,
 *	does not return.
 *
 * note:
 *	Since the versym section index is found in the sec_versym field
 *	of the elfedit_section_t, the caller may be tempted to bypass this
 *	routine and access it directly. That temptation should be resisted,
 *	as this routine performs useful error checking, and also handles
 *	the issuing of the standard MSG_DEBUG messages.
 */
elfedit_section_t *
elfedit_sec_getversym(elfedit_obj_state_t *obj_state,
    elfedit_section_t *symsec, Versym **versym, Word *num)
{
	elfedit_section_t	*versymsec;
	elfedit_symtab_t	*symtab;
	Word			ndx;

	/* Sanity check: symsec must be a symbol table */
	(void) elfedit_sec_issymtab(symsec, 1, NULL);

	symtab = obj_state->os_symtab;
	for (ndx = 0; ndx < obj_state->os_symtabnum; ndx++, symtab++)
		if (symsec->sec_shndx == symtab->symt_shndx)
			break;
	/*
	 * Issue error if the symbol table lacks a versym section.
	 * The caller won't ask unless they see a non-null
	 * aux.symtab.sec_versym, so this should not be a problem.
	 */
	if ((ndx == obj_state->os_symtabnum) ||
	    (symtab->symt_versym == SHN_UNDEF))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOVERSYMSEC),
		    EC_WORD(symsec->sec_shndx), symsec->sec_name);

	/* Got it. Report to the user and return the necessary data */
	versymsec = &obj_state->os_secarr[symtab->symt_versym];
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDVERSYM),
	    EC_WORD(symsec->sec_shndx), symsec->sec_name,
	    EC_WORD(versymsec->sec_shndx), versymsec->sec_name);
	*versym = (Versym *) versymsec->sec_data->d_buf;
	*num = versymsec->sec_shdr->sh_size / versymsec->sec_shdr->sh_entsize;
	return (versymsec);
}



/*
 * Locate the string table specified by shndx for this object.
 *
 * exit:
 *	Returns section descriptor on success. On failure, does not return.
 */
elfedit_section_t *
elfedit_sec_getstr(elfedit_obj_state_t *obj_state, Word shndx)
{
	elfedit_section_t *strsec;

	if ((shndx == 0) || (shndx >= obj_state->os_shnum))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_STRSHNDX),
		    EC_WORD(shndx), EC_WORD(obj_state->os_shnum - 1));

	strsec = &obj_state->os_secarr[shndx];
	if (strsec->sec_shdr->sh_type != SHT_STRTAB)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOTSTRSH),
		    EC_WORD(shndx), strsec->sec_name);

	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDSTRTAB),
	    EC_WORD(shndx), strsec->sec_name);
	return (strsec);
}


/*
 * Returns the offset of the specified string from within
 * the given section.
 *
 * entry:
 *	sec - Descriptor for section
 *	tail_ign - If non-zero, the # of characters at the end of the
 *		section that should be ignored and not searched.
 *	str - String we are looking for.
 *	ret_offset - Address of variable to receive result
 *
 * exit:
 *	Returns 1 for success, and 0 for failure. If successful, *ret_offset
 *	is set to the offset of the found string within the section.
 */
int
elfedit_sec_findstr(elfedit_section_t *sec, Word tail_ign,
    const char *str, Word *ret_offset)
{
	int		str_fch = *str;	/* First character in str */
	Word		len;		/* # characters in table */
	char		*s;		/* ptr to strings within table */
	const char	*tail;		/* 1 past final character of table */


	/* Size of the section, minus the reserved part (if any) at the end */
	len = sec->sec_shdr->sh_size - tail_ign;

	/*
	 * Move through the section character by character looking for
	 * a match. Moving character by character instead of skipping
	 * from NULL terminated string to string allows us to use
	 * the tails longer strings (i.e. we want "bar", and "foobar" exists).
	 * We look at the first character manually before calling strcmp()
	 * to lower the cost of this approach.
	 */
	s = (char *)sec->sec_data->d_buf;
	tail = s + len;
	for (; s <= tail; s++) {
		if ((*s == str_fch) && (strcmp(s, str) == 0)) {
			*ret_offset = s - (char *)sec->sec_data->d_buf;
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_EXISTSTR),
			    EC_WORD(sec->sec_shndx), sec->sec_name,
			    EC_WORD(*ret_offset), s);
			return (1);
		}
	}

	/* Didn't find it. Report failure */
	return (0);
}


/*
 * Locate the DT_SUNW_STRPAD element of the given dynamic section if
 * it exists.
 *
 * entry:
 *	dynsec - Dynamic section descriptor
 *	dyn_strpad - Address of variable to receive the results.
 *		The caller is responsible for calling elfedit_dyn_elt_init()
 *		on this variable beforehand.
 *
 * exit:
 *	The dynamic section is searched, and if a DT_SUNW_STRPAD element
 *	is found, dyn_strpad is updated via elfedit_dyn_elt_save() to
 *	reference it.
 *
 *	Returns the final value of dyn_strpad->dn_seen.
 */
int
elfedit_dynstr_getpad(elfedit_section_t *dynsec, elfedit_dyn_elt_t *dyn_strpad)
{
	Dyn	*dyn = (Dyn *) dynsec->sec_data->d_buf;
	Word numdyn = dynsec->sec_shdr->sh_size / dynsec->sec_shdr->sh_entsize;
	Word i;

	/* Go through dynamic section tags and find the STRPAD entry */
	for (i = 0; i < numdyn; i++) {
		if (dyn[i].d_tag == DT_SUNW_STRPAD) {
			elfedit_dyn_elt_save(dyn_strpad, i, &dyn[i]);
			break;
		}
	}

	return (dyn_strpad->dn_seen);
}



/*
 * Given references to the dynamic section, its string table,
 * and the DT_SUNW_STRPAD entry of the dynamic section, returns
 * the offset of the specified string from within the given string table,
 * adding it if possible.
 *
 * entry:
 *	dynsec - Dynamic section descriptor
 *	strsec - Descriptor for string table assocated with dynamic section
 *	dyn_strpad - DT_SUNW_STRPAD element from dynamic section
 *	str - String we are looking for.
 *
 * exit:
 *	On success, the offset of the given string within the string
 *	table is returned. If the string does not exist within the table,
 *	but there is a valid DT_SUNW_STRPAD reserved section, then we
 *	add the string, and update the dynamic section STRPAD element
 *	to reflect the space we use.
 *
 *	This routine does not return on failure.
 */
Word
elfedit_dynstr_insert(elfedit_section_t *dynsec, elfedit_section_t *strsec,
    elfedit_dyn_elt_t *dyn_strpad, const char *str)
{
	Word	ins_off;	/* Table offset to 1st reserved byte */
	char	*s;		/* ptr to strings within table */
	Word	len;		/* Length of str inc. NULL byte */
	Word	tail_ign;	/* # reserved bytes at end of strtab */


	tail_ign = dyn_strpad->dn_seen ? dyn_strpad->dn_dyn.d_un.d_val : 0;

	/* Does the string already existin the string table? */
	if (elfedit_sec_findstr(strsec, tail_ign, str, &len))
		return (len);

	/*
	 * The desired string does not already exist. Do we have
	 * room to add it?
	 */
	len = strlen(str) + 1;
	if (!dyn_strpad->dn_seen || (len > dyn_strpad->dn_dyn.d_un.d_val))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSTRPAD),
		    EC_WORD(strsec->sec_shdr->sh_link),
		    strsec->sec_name);


	/*
	 * We will add the string at the first byte of the reserved NULL
	 * area at the end. The DT_SUNW_STRPAD dynamic element gives us
	 * the size of that reserved space.
	 */
	ins_off = strsec->sec_shdr->sh_size - tail_ign;
	s = ((char *)strsec->sec_data->d_buf) + ins_off;

	/* Announce the operation */
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_ADDSTR),
	    EC_WORD(strsec->sec_shndx), strsec->sec_name,
	    EC_WORD(ins_off), EC_WORD(len),
	    EC_WORD(dyn_strpad->dn_dyn.d_un.d_val), str);

	/*
	 * Copy the string into the pad area at the end, and
	 * mark the data area as dirty so libelf will flush our
	 * changes to the string data.
	 */
	(void) strncpy(s, str, dyn_strpad->dn_dyn.d_un.d_val);
	elfedit_modified_data(strsec);

	/* Update the DT_STRPAD dynamic entry */
	dyn_strpad->dn_dyn.d_un.d_val -= len;
	((Dyn *) dynsec->sec_data->d_buf)[dyn_strpad->dn_ndx] =
	    dyn_strpad->dn_dyn;
	elfedit_modified_data(dynsec);

	return (ins_off);
}


/*
 * Test to see if a call to elfedit_strtab_insert() will succeed.
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	strsec - Descriptor for string table
 *	dynsec - NULL, or descriptor for dynamic section. Providing
 *		a non-NULL value here will prevent elfedit_strtab_insert()
 *		from looking it up, and the duplicate debug message that
 *		would result.
 *	str - String we are looking for.
 *
 * exit:
 *	If the string exists within the string table, or if an attempt
 *	to insert it will be successful, quietly return. Otherwise, throw
 *	the error elfedit_strtab_insert() would throw under the
 *	same circumstances.
 *
 */
void
elfedit_strtab_insert_test(elfedit_obj_state_t *obj_state,
    elfedit_section_t *strsec, elfedit_section_t *dynsec, const char *str)
{
	Word	len;		/* Length of str inc. NULL byte */
	int			is_dynstr = 0;
	Word			tail_ign = 0;


	/*
	 * The dynstr is a special case, because we can add strings
	 * to it under certain circumstances. So, we look for the
	 * dynamic section, and if it exists, compare its sh_link to
	 * the string section index. If they match, it is the dynstr,
	 * and we use elfedit_dynstr_insert() to do the work.
	 */
	if (dynsec == NULL) {
		if (obj_state->os_dynndx != SHN_UNDEF) {
			dynsec = &obj_state->os_secarr[obj_state->os_dynndx];
			if ((dynsec->sec_shdr->sh_type == SHT_DYNAMIC) &&
			    (strsec->sec_shndx == dynsec->sec_shdr->sh_link)) {
				is_dynstr = 1;
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_FNDDYN),
				    EC_WORD(dynsec->sec_shndx),
				    dynsec->sec_name);
			}
		}
	} else {
		if (strsec->sec_shndx == dynsec->sec_shdr->sh_link)
			is_dynstr = 1;
	}


	if (is_dynstr) {
		elfedit_dyn_elt_t dyn_strpad;

		/* Determine the size of the STRPAD area, if any */
		elfedit_dyn_elt_init(&dyn_strpad);
		if (elfedit_dynstr_getpad(dynsec, &dyn_strpad) != 0)
			tail_ign = dyn_strpad.dn_dyn.d_un.d_val;
	}

	/*
	 * If the string is already in the string table, we
	 * can't fail.
	 */
	if (elfedit_sec_findstr(strsec, tail_ign, str, &len) != 0)
		return;

	/*
	 * It's not in the table, but if this is the dynstr, and
	 * there is enough room, we will be able to add it.
	 */
	if (is_dynstr && (tail_ign > strlen(str)))
		return;

	/* Can't do it. Issue error */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSTRPAD),
	    EC_WORD(strsec->sec_shdr->sh_link), strsec->sec_name);
}


/*
 * Returns the offset of the specified string from within
 * the given string table, adding it if possible.
 *
 * entry:
 *	obj_state - Object state for open object to query.
 *	strsec - Descriptor for string table
 *	dynsec - NULL, or descriptor for dynamic section. Providing
 *		a non-NULL value here will prevent elfedit_strtab_insert()
 *		from looking it up, and the duplicate debug message that
 *		would result.
 *	str - String we are looking for.
 *
 * exit:
 *	On success, the offset of the given string within the string
 *	table is returned. If the string does not exist within the table,
 *	and it is possible to add it, elfedit_strtab_insert() will
 *	add the string, and then return the offset.
 *
 *	If the string does not exist in the string table, and cannot
 *	be added, this routine issues an error message and does not
 *	return to the caller.
 */
Word
elfedit_strtab_insert(elfedit_obj_state_t *obj_state, elfedit_section_t *strsec,
    elfedit_section_t *dynsec, const char *str)
{
	Word	len;		/* Length of str inc. NULL byte */
	int			is_dynstr = 0;
	elfedit_dyn_elt_t	dyn_strpad;


	/*
	 * The dynstr is a special case, because we can add strings
	 * to it under certain circumstances. So, we look for the
	 * dynamic section, and if it exists, compare its sh_link to
	 * the string section index. If they match, it is the dynstr,
	 * and we use elfedit_dynstr_insert() to do the work.
	 */
	if (dynsec == NULL) {
		if (obj_state->os_dynndx != SHN_UNDEF) {
			dynsec = &obj_state->os_secarr[obj_state->os_dynndx];
			if ((dynsec->sec_shdr->sh_type == SHT_DYNAMIC) &&
			    (strsec->sec_shndx == dynsec->sec_shdr->sh_link)) {
				is_dynstr = 1;
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_FNDDYN),
				    EC_WORD(dynsec->sec_shndx),
				    dynsec->sec_name);
			}
		}
	} else {
		if (strsec->sec_shndx == dynsec->sec_shdr->sh_link)
			is_dynstr = 1;
	}

	if (is_dynstr) {
		elfedit_dyn_elt_init(&dyn_strpad);
		(void) elfedit_dynstr_getpad(dynsec, &dyn_strpad);
		return (elfedit_dynstr_insert(dynsec, strsec,
		    &dyn_strpad, str));
	}

	/*
	 * This is not the dynstr, so we are limited to strings that
	 * already exist within it. Try to find one.
	 */
	if (elfedit_sec_findstr(strsec, 0, str, &len))
		return (len);

	/* Can't do it. Issue error */
	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOSTRPAD),
	    EC_WORD(strsec->sec_shdr->sh_link), strsec->sec_name);
	/*NOTREACHED*/

	return (0);
}


/*
 * Return the string found at the given offset within the specified
 * string table.
 *
 * entry:
 *	strsec - Section descriptor for string table section
 *	offset - Offset of desired string in string table
 *	msg_type - ELFEDIT_MSG_ type code to use with message
 *		issued if offset is out of range for the symbol table.
 *	debug_msg - True if should issue debug message for string found.
 *
 * exit:
 *	If the offset is within the section, the string pointer
 *	is returned. Otherwise an error is issued using msg_type
 *	to determine the type of message. If this routine retains
 *	control after the message is issued, a safe string is returned.
 */
const char *
elfedit_offset_to_str(elfedit_section_t *strsec, Word offset,
    elfedit_msg_t msg_type, int debug_msg)
{
	const char *str;

	/* Make sure it is a string table section */
	if (strsec->sec_shdr->sh_type != SHT_STRTAB)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOTSTRSH),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name);

	/* Ensure the offset is in range */
	if (offset >= strsec->sec_data->d_size) {
		elfedit_msg(msg_type, MSG_INTL(MSG_ERR_BADSTROFF),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(offset), EC_WORD(strsec->sec_data->d_size - 1));
		/*
		 * If the msg_type is a type that returns, give the
		 * user a safe string to use.
		 */
		str = MSG_INTL(MSG_BADSYMOFFSETNAM);
	} else {
		/* Return the string */
		str = ((const char *)strsec->sec_data->d_buf) + offset;
	}

	if (debug_msg)
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_FNDSTR),
		    EC_WORD(strsec->sec_shndx), strsec->sec_name,
		    EC_WORD(offset), str);
	return (str);
}


/*
 * Given a string table section, and a dynamic section entry
 * that supplies a string offset, return the string found at
 * the given offset. This routine is a convenience wrapper on
 * elfedit_offset_to_str().
 *
 * exit:
 *	As per elfedit_offset_to_str().
 */
const char *
elfedit_dyn_offset_to_str(elfedit_section_t *strsec, elfedit_dyn_elt_t *dynelt)
{
	return (elfedit_offset_to_str(strsec, dynelt->dn_dyn.d_un.d_val,
	    ELFEDIT_MSG_ERR, 0));
}


/*
 * Given a section, fabricate a string for the form:
 *
 *	"[#: name]"
 *
 * as used at the beginning of debug messages. A pointer to static
 * memory is returned, and is good until the next such call.
 */
const char *
elfedit_sec_msgprefix(elfedit_section_t *sec)
{
	static char	*buf;
	static size_t	bufsize;

	size_t		need;

	need = 64 + strlen(sec->sec_name);
	if (need > bufsize) {
		buf = elfedit_realloc(MSG_INTL(MSG_ALLOC_SECMSGPRE), buf, need);
		bufsize = need;
	}

	(void) snprintf(buf, bufsize, MSG_ORIG(MSG_FMT_SECMSGPRE),
	    EC_WORD(sec->sec_shndx), sec->sec_name);

	return (buf);
}
