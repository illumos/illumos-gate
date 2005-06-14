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
 *	Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	"_debug.h"
#include	"msg.h"
#include	"libld.h"


static int
comparegotsym(Gottable * gtp1, Gottable * gtp2)
{
	Gotndx *	gnp1 = &gtp1->gt_gndx;
	Gotndx *	gnp2 = &gtp2->gt_gndx;

	if (gnp1->gn_gotndx > gnp2->gn_gotndx)
		return (1);
	if (gnp1->gn_gotndx < gnp2->gn_gotndx)
		return (-1);

	return (0);
}

void
Dbg_got_display(Gottable * gtp, Ofl_desc *ofl)
{
	Word	gotndx;

	if (DBG_NOTCLASS(DBG_GOT))
		return;

	if (ofl->ofl_gotcnt == M_GOT_XNumber)
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_GOT_TITLE), EC_WORD(ofl->ofl_gotcnt));

	if (DBG_NOTDETAIL())
		return;

	qsort((char *)gtp, ofl->ofl_gotcnt, sizeof (Gottable),
		(int(*)(const void *, const void *))comparegotsym);

	dbg_print(MSG_ORIG(MSG_GOT_COLUMNS));

	for (gotndx = 0; gotndx < ofl->ofl_gotcnt; gotndx++, gtp++) {
		Sym_desc	*sdp;
		const char	*refstr, *name;
		Gotndx		*gnp = &gtp->gt_gndx;

		if ((sdp = gtp->gt_sym) == 0)
			continue;

		if (sdp->sd_flags & FLG_SY_SMGOT)
			refstr = MSG_ORIG(MSG_GOT_SMALL_PIC);
		else
			refstr = MSG_ORIG(MSG_GOT_PIC);

		if (sdp->sd_name)
			name = _Dbg_sym_dem(sdp->sd_name);
		else
			name = MSG_INTL(MSG_STR_UNKNOWN);

		if ((sdp->sd_sym->st_shndx == SHN_UNDEF) ||
		    (sdp->sd_file == 0)) {
			dbg_print(MSG_ORIG(MSG_GOT_FORMAT1),
			    EC_SWORD(gnp->gn_gotndx), refstr,
			    EC_LWORD(gnp->gn_addend), name);
		} else {
			dbg_print(MSG_ORIG(MSG_GOT_FORMAT2),
			    EC_SWORD(gnp->gn_gotndx), refstr,
			    EC_LWORD(gnp->gn_addend),
			    sdp->sd_file->ifl_name, name);
		}
	}
}


#if	!defined(_ELF64)
void
Gelf_got_title(uchar_t class)
{
	if (class == ELFCLASS64)
		dbg_print(MSG_ORIG(MSG_GOT_ECOLUMNS_64));
	else
		dbg_print(MSG_ORIG(MSG_GOT_ECOLUMNS));
}

void
Gelf_got_entry(GElf_Ehdr *ehdr, Sword gotndx, GElf_Addr addr, GElf_Xword value,
	GElf_Word rshtype, void *rel, const char *sname)
{
	GElf_Word	rtype;
	GElf_Sxword	addend;
	const char	*rstring, * fmt;

	if (rel) {
		if (rshtype == SHT_RELA) {
			/* LINTED */
			rtype = (GElf_Word)GELF_R_TYPE(
			    ((GElf_Rela *)rel)->r_info);
			addend = ((GElf_Rela *)rel)->r_addend;
		} else {
			/* LINTED */
			rtype = (GElf_Word)GELF_R_TYPE(
			    ((GElf_Rel *)rel)->r_info);
			addend = 0;
		}
		rstring = conv_reloc_type_str(ehdr->e_machine, rtype);
	} else {
		addend = 0;
		rstring = MSG_ORIG(MSG_STR_EMPTY);
	}

	if (sname)
		sname = _Dbg_sym_dem(sname);
	else
		sname = MSG_ORIG(MSG_STR_EMPTY);

	if ((int)ehdr->e_ident[EI_CLASS] == ELFCLASS64)
		fmt = MSG_ORIG(MSG_GOT_EFORMAT_64);
	else
		fmt = MSG_ORIG(MSG_GOT_EFORMAT);

	dbg_print(fmt, EC_SWORD(gotndx), EC_ADDR(addr), EC_XWORD(value),
	    rstring, EC_SXWORD(addend), sname);
}
#endif	/* !defined(_ELF64) */
