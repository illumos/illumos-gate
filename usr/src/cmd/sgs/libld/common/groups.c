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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<link.h>
#include	"debug.h"
#include	"msg.h"
#include	"_libld.h"


/*
 * Given a group signature symbol - scan through the global list
 * of GROUP sections to determine if we have a conflict/discard.
 * If this is the first time we see a group signature - add it to the
 * global list.
 *
 * Returns:
 *		0	-	Group kept and added to global list.
 *		1	-	Group should be discarded.
 */
uintptr_t
scan_global_groups(Group_desc * gdesc, Ofl_desc * ofl)
{
	Group_desc *	_gdesc;
	Listnode *	lnp;

	/*
	 * Scan through global list - if we find a group of the
	 * same name - we return 0 saying this new group should
	 * be discarded (since only COMDAT's get here currently).
	 */
	for (LIST_TRAVERSE(&ofl->ofl_groups, lnp, _gdesc))
		if (strcmp(_gdesc->gd_symname, gdesc->gd_symname) == 0) {
			gdesc->gd_flags |= GRP_FLG_DISCARD;
			return (1);
		}

	if (list_appendc(&ofl->ofl_groups, gdesc) == 0)
		return (S_ERROR);

	return (0);
}


Group_desc *
get_group_desc(Ofl_desc *ofl, Is_desc *isp)
{
	Ifl_desc	*ifl = isp->is_file;
	Elf		*elf = ifl->ifl_elf;
	uint_t		scnndx = isp->is_scnndx;
	Group_desc	*gdesc;
	Listnode	*lnp;


	/*
	 * If this is the first section of with the SHF_GROUP flag
	 * set - then we havn't yet scanned for - and found our
	 * group sections.  If thats so - do it now.
	 */
	if (ifl->ifl_groups.head == 0) {
		Elf_Scn		*scn = 0;
		while (scn = elf_nextscn(elf, scn)) {
			Shdr		*shdr;
			Shdr		*_shdr;
			Sym		*sym;
			const char	*symname;
			Elf_Scn		*_scn;
			Elf_Data	*data;

			shdr = elf_getshdr(scn);
			if (shdr->sh_type != SHT_GROUP)
				continue;

			/*
			 * Confirm that the sh_link points to a
			 * valid section.
			 */
			if ((shdr->sh_link == SHN_UNDEF) ||
			    (shdr->sh_link >= ifl->ifl_shnum)) {
				eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVSHLINK),
					ifl->ifl_name, elf_strptr(elf,
					ifl->ifl_shstrndx,
					shdr->sh_name),
					EC_XWORD(shdr->sh_link));
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			if (shdr->sh_entsize == 0) {
				eprintf(ERR_FATAL,
					MSG_INTL(MSG_FIL_INVSHENTSIZE),
					ifl->ifl_name, elf_strptr(elf,
					ifl->ifl_shstrndx,
					shdr->sh_name),
					EC_XWORD(shdr->sh_entsize));
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			/*
			 * Get associated symbol table
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
				eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
					ifl->ifl_name, elf_strptr(elf,
					ifl->ifl_shstrndx,
					shdr->sh_name),
					EC_XWORD(shdr->sh_info));
				ofl->ofl_flags |= FLG_OF_FATAL;
				continue;
			}

			data = elf_getdata(_scn, 0);
			sym = data->d_buf;
			sym += shdr->sh_info;
			symname = elf_strptr(elf, _shdr->sh_link, sym->st_name);

			if ((gdesc = libld_calloc(sizeof (Group_desc), 1)) == 0)
				return ((Group_desc *)S_ERROR);

			gdesc->gd_gsectname = elf_strptr(elf,
				ifl->ifl_shstrndx, shdr->sh_name);
			gdesc->gd_symname = symname;
			gdesc->gd_sym = sym;
			gdesc->gd_scn = scn;
			data = elf_getdata(scn, 0);
			gdesc->gd_groupdata = data->d_buf;
			gdesc->gd_gdcnt = data->d_size / sizeof (Word);
			/*
			 * If this group is a COMDAT group - then we
			 * need to find the 'signature' symbol to determine
			 * if this is group is to be kept or discarded.
			 */
			if (gdesc->gd_groupdata[0] & GRP_COMDAT) {
				if ((ELF_ST_BIND(sym->st_info) != STB_LOCAL) &&
				    (sym->st_shndx != SHN_UNDEF)) {
					if (scan_global_groups(gdesc, ofl)
					    == S_ERROR)
						return ((Group_desc *)S_ERROR);
				}
			}
			if (list_appendc(&ifl->ifl_groups, gdesc) == 0)
				return ((Group_desc *)S_ERROR);
		}
	}

	/*
	 * Now we scan through the GROUP sections associated with
	 * this file - to find the matching group section.
	 */
	for (LIST_TRAVERSE(&ifl->ifl_groups, lnp, gdesc)) {
		size_t	i;
		Word *	gdata;
		if (isp->is_shdr->sh_type == SHT_GROUP) {
			if ((size_t)isp->is_scnndx ==
			    elf_ndxscn(gdesc->gd_scn)) {
				isp->is_group = gdesc;
				return (gdesc);
			}
			continue;
		}

		gdata = gdesc->gd_groupdata;
		for (i = 1; i < gdesc->gd_gdcnt; i++) {
			if (gdata[i] == scnndx) {
				isp->is_group = gdesc;
				return (gdesc);
			}
		}
	}
	eprintf(ERR_FATAL, MSG_INTL(MSG_ELF_NOGROUPSECT), ifl->ifl_name,
		isp->is_name);
	ofl->ofl_flags |= FLG_OF_FATAL;
	return ((Group_desc *)0);
}
