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

#include	<stdio.h>
#include	<string.h>
#include	<link.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Define an AVL node for maintain group names, together with a compare function
 * for the Grp_node AVL tree.
 */
typedef struct {
	const char	*gn_name;	/* group name */
	avl_node_t	gn_avl;		/* avl book-keeping (see SGSOFFSETOF) */
	uint_t		gn_hash;	/* group name hash value */
} Grp_node;

static int
gnavl_compare(const void * n1, const void * n2)
{
	uint_t		hash1, hash2;
	const char	*st1, *st2;
	int		rc;

	hash1 = ((Grp_node *)n1)->gn_hash;
	hash2 = ((Grp_node *)n2)->gn_hash;

	if (hash1 > hash2)
		return (1);
	if (hash1 < hash2)
		return (-1);

	st1 = ((Grp_node *)n1)->gn_name;
	st2 = ((Grp_node *)n2)->gn_name;

	rc = strcmp(st1, st2);
	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}

/*
 * Determine whether a (COMDAT) group has already been encountered.  If so,
 * tag the new group having the same name as discardable.
 */
static uintptr_t
gpavl_loaded(Ofl_desc *ofl, Group_desc * gdp)
{
	Grp_node	gpn, *gpnp;
	avl_tree_t	*avlt;
	avl_index_t	where;

	/*
	 * Create an avl tree if required.
	 */
	if ((avlt = ofl->ofl_groups) == 0) {
		if ((avlt = calloc(sizeof (avl_tree_t), 1)) == NULL)
			return (S_ERROR);
		avl_create(avlt, gnavl_compare, sizeof (Grp_node),
		    SGSOFFSETOF(Grp_node, gn_avl));
		ofl->ofl_groups = avlt;
	}

	gpn.gn_name = gdp->gd_symname;
	gpn.gn_hash = sgs_str_hash(gdp->gd_symname);

	if ((gpnp = avl_find(avlt, &gpn, &where)) != NULL) {
		gdp->gd_flags |= GRP_FLG_DISCARD;
		return (1);
	}

	/*
	 * This is a new group, save it.
	 */
	if ((gpnp = calloc(sizeof (Grp_node), 1)) == NULL)
		return (S_ERROR);

	gpnp->gn_name = gpn.gn_name;
	gpnp->gn_hash = gpn.gn_hash;

	avl_insert(avlt, gpnp, where);
	return (0);
}

Group_desc *
ld_get_group(Ofl_desc *ofl, Is_desc *isp)
{
	Ifl_desc	*ifl = isp->is_file;
	Elf		*elf = ifl->ifl_elf;
	uint_t		scnndx = isp->is_scnndx;
	Group_desc	*gdp;
	Aliste		idx;

	/*
	 * If this is the first SHF_GROUP section encountered for this file,
	 * establish what group sections exist.
	 */
	if (ifl->ifl_groups == NULL) {
		Elf_Scn	*scn = 0;

		while (scn = elf_nextscn(elf, scn)) {
			Shdr		*shdr, *_shdr;
			Sym		*sym;
			Elf_Scn		*_scn;
			Elf_Data	*data;
			Group_desc	gd;

			shdr = elf_getshdr(scn);
			if (shdr->sh_type != SHT_GROUP)
				continue;

			/*
			 * Confirm that the sh_link points to a valid section.
			 */
			if ((shdr->sh_link == SHN_UNDEF) ||
			    (shdr->sh_link >= ifl->ifl_shnum)) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_FIL_INVSHLINK),
				    ifl->ifl_name, elf_strptr(elf,
				    ifl->ifl_shstrndx, shdr->sh_name),
				    EC_XWORD(shdr->sh_link));
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			if (shdr->sh_entsize == 0) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_FIL_INVSHENTSIZE),
				    ifl->ifl_name, elf_strptr(elf,
				    ifl->ifl_shstrndx, shdr->sh_name),
				    EC_XWORD(shdr->sh_entsize));
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			/*
			 * Get associated symbol table.
			 */
			_scn = elf_getscn(elf, shdr->sh_link);
			_shdr = elf_getshdr(_scn);

			/*
			 * Sanity check the sh_link field (which points to
			 * a symbol table entry) against the size of the
			 * symbol table.
			 */
			if ((shdr->sh_info == SHN_UNDEF) ||
			    (shdr->sh_info >= (Word)(_shdr->sh_size /
			    _shdr->sh_entsize))) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_FIL_INVSHINFO),
				    ifl->ifl_name, elf_strptr(elf,
				    ifl->ifl_shstrndx, shdr->sh_name),
				    EC_XWORD(shdr->sh_info));
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			data = elf_getdata(_scn, 0);
			sym = data->d_buf;
			sym += shdr->sh_info;
			data = elf_getdata(scn, 0);

			gd.gd_gsectname =
			    elf_strptr(elf, ifl->ifl_shstrndx, shdr->sh_name);
			gd.gd_symname =
			    elf_strptr(elf, _shdr->sh_link, sym->st_name);
			gd.gd_scnndx = elf_ndxscn(scn);
			gd.gd_data = data->d_buf;
			gd.gd_cnt = data->d_size / sizeof (Word);
			gd.gd_flags = 0;

			/*
			 * If this group is a COMDAT group, determine whether
			 * this 'signature' symbol has already been detected.
			 */
			if ((gd.gd_data[0] & GRP_COMDAT) &&
			    (ELF_ST_BIND(sym->st_info) != STB_LOCAL) &&
			    (sym->st_shndx != SHN_UNDEF) &&
			    (gpavl_loaded(ofl, &gd) == S_ERROR))
				return ((Group_desc *)S_ERROR);

			if (alist_append(&(ifl->ifl_groups),
			    &gd, sizeof (Group_desc), AL_CNT_IFL_GROUPS) == 0)
				return ((Group_desc *)S_ERROR);
		}
	}

	/*
	 * Scan the GROUP sections associated with this file to find the
	 * matching group section.
	 */
	for (ALIST_TRAVERSE(ifl->ifl_groups, idx, gdp)) {
		size_t	ndx;
		Word *	data;

		if (isp->is_shdr->sh_type == SHT_GROUP) {
			if (isp->is_scnndx == gdp->gd_scnndx)
				return (gdp);
			continue;
		}

		data = gdp->gd_data;
		for (ndx = 1; ndx < gdp->gd_cnt; ndx++) {
			if (data[ndx] == scnndx)
				return (gdp);
		}
	}

	eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_ELF_NOGROUPSECT),
	    ifl->ifl_name, isp->is_name);
	ofl->ofl_flags |= FLG_OF_FATAL;
	return (0);
}
