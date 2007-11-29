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

#include	<stdio.h>
#include	"_debug.h"
#include	"msg.h"
#include	"libld.h"


static int
Dbg_got_compare(Gottable *gtp1, Gottable *gtp2)
{
	Gotndx	*gnp1 = &gtp1->gt_gndx;
	Gotndx	*gnp2 = &gtp2->gt_gndx;

	if (gnp1->gn_gotndx > gnp2->gn_gotndx)
		return (1);
	if (gnp1->gn_gotndx < gnp2->gn_gotndx)
		return (-1);

	return (0);
}

void
Dbg_got_display(Ofl_desc *ofl, Off goff, int stage)
{
	Lm_list		*lml = ofl->ofl_lml;
	Gottable	*gtp = ofl->ofl_gottable;
	Word		gotndx;
	Xword		*gptr;

	if (DBG_NOTCLASS(DBG_C_GOT))
		return;

	if (ofl->ofl_gotcnt == M_GOT_XNumber)
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_GOT_INFO), EC_WORD(ofl->ofl_gotcnt));

	if (DBG_NOTDETAIL())
		return;

	qsort((char *)gtp, ofl->ofl_gotcnt, sizeof (Gottable),
	    (int(*)(const void *, const void *))Dbg_got_compare);

	if (stage == 0)
		dbg_print(lml, MSG_INTL(MSG_GOT_COLUMNS1));
	else
		dbg_print(lml, MSG_INTL(MSG_GOT_COLUMNS2));

	gptr = (Xword *)ofl->ofl_osgot->os_outdata->d_buf;

	for (gotndx = 0; gotndx < ofl->ofl_gotcnt; gotndx++, gtp++, gptr++) {
		Sym_desc	*sdp = gtp->gt_sym;
		const char	*refstr, *name;
		Gotndx		*gnp = &gtp->gt_gndx;
		Lword		gotaddval;
		Off		off = goff + (gotndx * M_GOT_ENTSIZE);
		char		index[INDEX_STR_SIZE];

		(void) snprintf(index, INDEX_STR_SIZE, MSG_ORIG(MSG_GOT_INDEX),
		    EC_SWORD(gnp->gn_gotndx));

		if (sdp == 0)
			refstr = MSG_ORIG(MSG_STR_EMPTY);
		else if (sdp->sd_flags & FLG_SY_SMGOT)
			refstr = MSG_ORIG(MSG_GOT_SMALL_PIC);
		else
			refstr = MSG_ORIG(MSG_GOT_BIG_PIC);

		if (sdp == 0)
			name = MSG_ORIG(MSG_STR_EMPTY);
		else if (sdp->sd_name)
			name = Dbg_demangle_name(sdp->sd_name);
		else
			name = MSG_INTL(MSG_STR_UNKNOWN);

		if (stage == 0)
			gotaddval = gnp->gn_addend;
		else
			gotaddval = *gptr;

		if ((sdp == 0) || (sdp->sd_sym->st_shndx == SHN_UNDEF) ||
		    (sdp->sd_file == 0)) {
			dbg_print(lml, MSG_INTL(MSG_GOT_FORMAT1), index,
			    refstr, EC_OFF(off), EC_XWORD(gotaddval), name);
		} else {
			dbg_print(lml, MSG_INTL(MSG_GOT_FORMAT2), index,
			    refstr, EC_OFF(off), EC_XWORD(gotaddval),
			    sdp->sd_file->ifl_name, name);
		}
	}
}

void
Elf_got_title(Lm_list *lml)
{
	dbg_print(lml, MSG_INTL(MSG_GOT_TITLE));
}

void
Elf_got_entry(Lm_list *lml, Sword ndx, Addr addr, Xword value, Half mach,
    Word type, void *reloc, const char *name)
{
	Rela		*rela;
	Rel		*rel;
	const char	*str;
	Conv_inv_buf_t	inv_buf;
	char		index[INDEX_STR_SIZE];

	(void) snprintf(index, INDEX_STR_SIZE, MSG_ORIG(MSG_GOT_INDEX),
	    EC_SWORD(ndx));

	if (reloc) {
		if (type == SHT_RELA) {
			rela = (Rela *)reloc;
			str = conv_reloc_type(mach, ELF_R_TYPE(rela->r_info),
			    0, &inv_buf);
		} else {
			rel = (Rel *)reloc;
			str = conv_reloc_type(mach, ELF_R_TYPE(rel->r_info),
			    0, &inv_buf);
		}

		if (name)
			name = Elf_demangle_name(name);
		else
			name = MSG_ORIG(MSG_STR_EMPTY);

		dbg_print(lml, MSG_INTL(MSG_GOT_ENTRY_RE), index, EC_ADDR(addr),
		    EC_XWORD(value), str, name);
	} else
		dbg_print(lml, MSG_INTL(MSG_GOT_ENTRY_NR), index, EC_ADDR(addr),
		    EC_XWORD(value));
}
