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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<stdio.h>
#include	<string.h>
#include	<link.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Determine whether a (COMDAT) group has already been encountered.  If so,
 * indicate that the group descriptor has an overriding group (gd_oisc).  This
 * indication triggers the ld_place_section() to discard this group, while the
 * gd_oisc information provides for complete diagnostics of the override.
 * Otherwise, this is the first occurrence of this group, therefore the group
 * descriptor is saved for future comparisons.
 */
static uintptr_t
gpavl_loaded(Ofl_desc *ofl, Group_desc *gdp)
{
	Isd_node	isd, *isdp;
	avl_tree_t	*avlt;
	avl_index_t	where;

	/*
	 * Create a groups avl tree if required.
	 */
	if ((avlt = ofl->ofl_groups) == NULL) {
		if ((avlt = libld_calloc(sizeof (avl_tree_t), 1)) == NULL)
			return (S_ERROR);
		avl_create(avlt, isdavl_compare, sizeof (Isd_node),
		    SGSOFFSETOF(Isd_node, isd_avl));
		ofl->ofl_groups = avlt;
	}

	/*
	 * An SHT_GROUP section is identified by the name of its signature
	 * symbol rather than section name. Although the section names are
	 * often unique, this is not required, and some compilers set it to
	 * a generic name like ".group".
	 */
	isd.isd_name = gdp->gd_name;
	isd.isd_hash = sgs_str_hash(isd.isd_name);

	if ((isdp = avl_find(avlt, &isd, &where)) != NULL) {
		gdp->gd_oisc = isdp->isd_isp;
		return (1);
	}

	/*
	 * This is a new group - so keep it.
	 */
	if ((isdp = libld_calloc(sizeof (Isd_node), 1)) == NULL)
		return (S_ERROR);

	isdp->isd_name = isd.isd_name;
	isdp->isd_hash = isd.isd_hash;
	isdp->isd_isp = gdp->gd_isc;

	avl_insert(avlt, isdp, where);
	return (0);
}

Group_desc *
ld_get_group(Ofl_desc *ofl, Is_desc *isp)
{
	Ifl_desc	*ifl = isp->is_file;
	uint_t		scnndx = isp->is_scnndx;
	Group_desc	*gdp;
	Aliste		idx;

	/*
	 * Scan the GROUP sections associated with this file to find the
	 * matching group section.
	 */
	for (ALIST_TRAVERSE(ifl->ifl_groups, idx, gdp)) {
		size_t	ndx;
		Word	*data;

		if (isp->is_shdr->sh_type == SHT_GROUP) {
			if (isp->is_scnndx == gdp->gd_isc->is_scnndx)
				return (gdp);
			continue;
		}

		data = gdp->gd_data;
		for (ndx = 1; ndx < gdp->gd_cnt; ndx++) {
			if (data[ndx] == scnndx)
				return (gdp);
		}
	}

	ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_ELF_NOGROUPSECT),
	    ifl->ifl_name, EC_WORD(isp->is_scnndx), isp->is_name);
	return (NULL);
}

/*
 * When creating a .debug_macro section, in an attempt to make certain DWARF
 * macro information shareable, the GNU compiler must construct group sections
 * with a repeatable signature symbol while nevertheless having no actual
 * symbol to refer to (because it relates to macros).
 *
 * We use this as yet another way to clue ourselves in that sloppy relocation
 * will likely be required.
 *
 * The format of these gensym'd names is:
 *    wm<offset size>.<encoded path name>.<lineno>.<32byte hash>
 * Where the encoded file name may be absent.
 */
static boolean_t
is_header_gensym(const char *name)
{
	const char	*c = NULL;
	size_t		len = strlen(name);

	/* No room for leader, hash, and periods */
	if (len < 37)
		return (B_FALSE);

	if ((strncmp(name, "wm4.", 4) != 0) &&
	    strncmp(name, "wm8.", 4) != 0)
		return (B_FALSE);

	c = &name[len - 33];
	if (*c++ != '.')
		return (B_FALSE);

	for (; *c != '\0'; c++) {
		if (!(((*c >= 'a') && (*c <= 'f')) ||
		    ((*c >= '0') && (*c <= '9')))) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

uintptr_t
ld_group_process(Is_desc *gisc, Ofl_desc *ofl)
{
	Ifl_desc	*gifl = gisc->is_file;
	Shdr		*sshdr, *gshdr = gisc->is_shdr;
	Is_desc		*isc;
	Sym		*sym;
	const char	*str;
	Group_desc	gd;
	size_t		ndx;
	int		gnu_stt_section;

	/*
	 * Confirm that the sh_link points to a valid section.
	 */
	if ((gshdr->sh_link == SHN_UNDEF) ||
	    (gshdr->sh_link >= gifl->ifl_shnum) ||
	    ((isc = gifl->ifl_isdesc[gshdr->sh_link]) == NULL)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHLINK),
		    gifl->ifl_name, EC_WORD(gisc->is_scnndx),
		    gisc->is_name, EC_XWORD(gshdr->sh_link));
		return (0);
	}
	if (gshdr->sh_entsize == 0) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHENTSIZE),
		    gifl->ifl_name, EC_WORD(gisc->is_scnndx), gisc->is_name,
		    EC_XWORD(gshdr->sh_entsize));
		return (0);
	}

	/*
	 * Get the associated symbol table.  Sanity check the sh_info field
	 * (which points to the signature symbol table entry) against the size
	 * of the symbol table.
	 */
	sshdr = isc->is_shdr;
	sym = (Sym *)isc->is_indata->d_buf;

	if ((sshdr->sh_info == SHN_UNDEF) ||
	    (gshdr->sh_info >= (Word)(sshdr->sh_size / sshdr->sh_entsize)) ||
	    ((isc = gifl->ifl_isdesc[sshdr->sh_link]) == NULL)) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
		    gifl->ifl_name, EC_WORD(gisc->is_scnndx), gisc->is_name,
		    EC_XWORD(gshdr->sh_info));
		return (0);
	}

	sym += gshdr->sh_info;

	/*
	 * Get the symbol name from the associated string table.
	 */
	str = (char *)isc->is_indata->d_buf;
	str += sym->st_name;

	/*
	 * The GNU assembler can use section symbols as the signature symbol
	 * as described by this comment in the gold linker (found via google):
	 *
	 *	It seems that some versions of gas will create a section group
	 *	associated with a section symbol, and then fail to give a name
	 *	to the section symbol.  In such a case, use the name of the
	 *	section.
	 *
	 * In order to support such objects, we do the same.
	 */
	gnu_stt_section = ((sym->st_name == 0) || (*str == '\0')) &&
	    (ELF_ST_TYPE(sym->st_info) == STT_SECTION);
	if (gnu_stt_section)
		str = gisc->is_name;


	/*
	 * Generate a group descriptor.
	 */
	gd.gd_isc = gisc;
	gd.gd_oisc = NULL;
	gd.gd_name = str;
	gd.gd_data = gisc->is_indata->d_buf;
	gd.gd_cnt = gisc->is_indata->d_size / sizeof (Word);

	/*
	 * If the signature symbol is a name generated by the GNU compiler to
	 * refer to a header, we need sloppy relocation.
	 */
	if (is_header_gensym(str)) {
		if ((ofl->ofl_flags1 & FLG_OF1_NRLXREL) == 0)
			ofl->ofl_flags1 |= FLG_OF1_RLXREL;
		DBG_CALL(Dbg_sec_gnu_comdat(ofl->ofl_lml, gisc, TRUE,
		    (ofl->ofl_flags1 & FLG_OF1_RLXREL) != 0));
	}

	/*
	 * Validate the section indices within the group.  If this is a COMDAT
	 * group, mark each section as COMDAT.
	 */
	for (ndx = 1; ndx < gd.gd_cnt; ndx++) {
		Word	gndx;

		if ((gndx = gd.gd_data[ndx]) >= gifl->ifl_shnum) {
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_GRP_INVALNDX), gifl->ifl_name,
			    EC_WORD(gisc->is_scnndx), gisc->is_name, ndx, gndx);
			return (0);
		}

		if (gd.gd_data[0] & GRP_COMDAT)
			gifl->ifl_isdesc[gndx]->is_flags |= FLG_IS_COMDAT;
	}

	/*
	 * If this is a COMDAT group, determine whether this group has already
	 * been encountered, or whether this is the first instance of the group.
	 */
	if ((gd.gd_data[0] & GRP_COMDAT) &&
	    (gpavl_loaded(ofl, &gd) == S_ERROR))
		return (S_ERROR);

	/*
	 * Associate the group descriptor with this input file.
	 */
	if (alist_append(&(gifl->ifl_groups), &gd, sizeof (Group_desc),
	    AL_CNT_IFL_GROUPS) == NULL)
		return (S_ERROR);

	return (1);
}
