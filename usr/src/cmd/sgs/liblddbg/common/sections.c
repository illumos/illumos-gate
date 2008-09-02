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
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"
#include	"_string_table.h"

void
Dbg_sec_strtab(Lm_list *lml, Os_desc *osp, Str_tbl *stp)
{
	uint_t	cnt;

	if (DBG_NOTCLASS(DBG_C_STRTAB))
		return;

	if (!osp)
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	if (stp->st_flags & FLG_STTAB_COMPRESS)
		dbg_print(lml, MSG_INTL(MSG_SEC_STRTAB_COMP), osp->os_name,
		    EC_XWORD(stp->st_fullstrsize), EC_XWORD(stp->st_strsize));
	else
		dbg_print(lml, MSG_INTL(MSG_SEC_STRTAB_STND), osp->os_name,
		    EC_XWORD(stp->st_fullstrsize));

	if ((DBG_NOTDETAIL()) ||
	    ((stp->st_flags & FLG_STTAB_COMPRESS) == 0))
		return;

	dbg_print(lml, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(lml, MSG_INTL(MSG_SEC_STRTAB_HD), osp->os_name,
	    stp->st_hbckcnt);

	for (cnt = 0; cnt < stp->st_hbckcnt; cnt++) {
		Str_hash	*strhash = stp->st_hashbcks[cnt];

		if (strhash == 0)
			continue;

		dbg_print(lml, MSG_INTL(MSG_SEC_STRTAB_BCKT), cnt);

		while (strhash) {
			size_t	stroff = strhash->hi_mstr->sm_strlen -
			    strhash->hi_strlen;

			if (stroff == 0) {
				dbg_print(lml, MSG_INTL(MSG_SEC_STRTAB_MSTR),
				    EC_XWORD(strhash->hi_refcnt),
				    strhash->hi_mstr->sm_str);
			} else {
				dbg_print(lml, MSG_INTL(MSG_SEC_STRTAB_SUFSTR),
				    EC_XWORD(strhash->hi_refcnt),
				    &strhash->hi_mstr->sm_str[stroff],
				    strhash->hi_mstr->sm_str);
			}

			strhash = strhash->hi_next;
		}
	}
}

void
Dbg_sec_genstr_compress(Lm_list *lml, const char *os_name,
    Xword raw_size, Xword merge_size)
{
	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SEC_GENSTR_COMP), os_name,
	    EC_XWORD(raw_size), EC_XWORD(merge_size));
}

void
Dbg_sec_unsup_strmerge(Lm_list *lml, Is_desc *isp)
{
	const char *str;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	/*
	 * We can only merge string table sections with single byte
	 * (char) characters. For any other (wide) character types,
	 * issue a message so the user will understand why these
	 * sections are not being picked up.
	 */
	if ((isp->is_shdr->sh_entsize > 1) ||
	    (isp->is_shdr->sh_addralign > 1)) {
		str = (isp->is_file != NULL) ? isp->is_file->ifl_name :
		    MSG_INTL(MSG_STR_NULL);
		dbg_print(lml, MSG_INTL(MSG_SEC_STRMERGE_UNSUP),
		    isp->is_name, str, EC_XWORD(isp->is_shdr->sh_addralign),
		    EC_XWORD(isp->is_shdr->sh_entsize));
	}
}

void
Dbg_sec_in(Lm_list *lml, Is_desc *isp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	if (isp->is_flags & FLG_IS_GNSTRMRG) {
		/*
		 * This section was generated because we have 1 or
		 * more SHF_MERGE|SHF_STRINGS input sections that we
		 * wish to merge. This new section will ultimately
		 * end up replacing those sections once it has been filled
		 * with their strings (merged and compressed) and relocations
		 * have been redirected.
		 */
		dbg_print(lml, MSG_INTL(MSG_SEC_INPUT_GENSTR), isp->is_name);
	} else {
		/* Standard input section */
		str = (isp->is_file != NULL) ? isp->is_file->ifl_name :
		    MSG_INTL(MSG_STR_NULL);
		dbg_print(lml, MSG_INTL(MSG_SEC_INPUT), isp->is_name, str);
	}
}

void
Dbg_sec_added(Lm_list *lml, Os_desc *osp, Sg_desc *sgp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(lml, MSG_INTL(MSG_SEC_ADDED), osp->os_name, str);
}

void
Dbg_sec_created(Lm_list *lml, Os_desc *osp, Sg_desc *sgp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(lml, MSG_INTL(MSG_SEC_CREATED), osp->os_name, str);
}

void
Dbg_sec_discarded(Lm_list *lml, Is_desc *isp, Is_desc *disp)
{
	if (DBG_NOTCLASS(DBG_C_SECTIONS | DBG_C_UNUSED))
		return;

	if ((isp->is_flags & FLG_IS_INSTRMRG) &&
	    (disp->is_flags & FLG_IS_GNSTRMRG)) {
		/*
		 * This SHF_MERGE|SHF_STRINGS input section is being
		 * discarded in favor of the generated merged string section.
		 */
		dbg_print(lml, MSG_INTL(MSG_SEC_STRMERGE_DISCARDED),
		    isp->is_name, isp->is_file->ifl_name);
	} else {
		/* Generic section discard */
		dbg_print(lml, MSG_INTL(MSG_SEC_DISCARDED), isp->is_name,
		    isp->is_file->ifl_name, disp->is_name,
		    disp->is_file->ifl_name);
	}
}

void
Dbg_sec_group(Lm_list *lml, Is_desc *isp, Group_desc *gdp)
{
	const char	*comdat;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	if (gdp->gd_data[0] & GRP_COMDAT)
		comdat = MSG_ORIG(MSG_STR_COMDAT);
	else
		comdat = MSG_ORIG(MSG_STR_EMPTY);

	if (isp->is_shdr->sh_type == SHT_GROUP) {
		dbg_print(lml, MSG_INTL(MSG_SEC_GRP_DEFINE), isp->is_name,
		    isp->is_file->ifl_name, comdat, gdp->gd_name);
	} else {
		dbg_print(lml, MSG_INTL(MSG_SEC_GRP_MEMBER), isp->is_name,
		    isp->is_file->ifl_name, comdat, gdp->gd_name);
	}

	if (gdp->gd_oisc) {
		dbg_print(lml, MSG_INTL(MSG_SEC_GRP_DISCARDED), isp->is_name,
		    isp->is_file->ifl_name, gdp->gd_name,
		    gdp->gd_oisc->is_file->ifl_name);
	}
}

void
Dbg_sec_order_list(Ofl_desc *ofl, int flag)
{
	Os_desc		*osp;
	Is_desc		*isp1;
	Listnode	*lnp1, *lnp2;
	Lm_list		*lml = ofl->ofl_lml;
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);

	/*
	 * If the flag == 0, then the routine is called before sorting.
	 */
	if (flag == 0)
		str = MSG_INTL(MSG_ORD_SORT_BEFORE);
	else
		str = MSG_INTL(MSG_ORD_SORT_AFTER);

	for (LIST_TRAVERSE(&ofl->ofl_ordered, lnp1, osp)) {
		Sort_desc	*sort = osp->os_sort;

		dbg_print(lml, str, osp->os_name);
		dbg_print(lml, MSG_INTL(MSG_ORD_HDR_1),
		    EC_WORD(sort->st_beforecnt), EC_WORD(sort->st_aftercnt),
		    EC_WORD(sort->st_ordercnt));

		for (LIST_TRAVERSE(&osp->os_isdescs, lnp2, isp1)) {
			Word		link;
			Ifl_desc	*ifl = isp1->is_file;
			Is_desc		*isp2;
			const char	*msg;

			if ((isp1->is_flags & FLG_IS_ORDERED) == 0) {
				dbg_print(lml, MSG_INTL(MSG_ORD_TITLE_0),
				    isp1->is_name, isp1->is_file->ifl_name);
				continue;
			}

			if (isp1->is_shdr->sh_flags & SHF_ORDERED) {
				link = isp1->is_shdr->sh_info;
				msg = MSG_ORIG(MSG_SH_INFO);
			} else {
				/* SHF_LINK_ORDER */
				link = isp1->is_shdr->sh_link;
				msg = MSG_ORIG(MSG_SH_LINK);
			}

			if (link == SHN_BEFORE) {
				dbg_print(lml, MSG_INTL(MSG_ORD_TITLE_1),
				    isp1->is_name, isp1->is_file->ifl_name,
				    msg);
				continue;
			}

			if (link == SHN_AFTER) {
				dbg_print(lml, MSG_INTL(MSG_ORD_TITLE_2),
				    isp1->is_name, isp1->is_file->ifl_name,
				    msg);
				continue;
			}

			isp2 = ifl->ifl_isdesc[link];
			dbg_print(lml, MSG_INTL(MSG_ORD_TITLE_3),
			    isp1->is_name, ifl->ifl_name, msg, isp2->is_name,
			    EC_WORD(isp2->is_keyident));
		}
	}
	Dbg_util_nl(lml, DBG_NL_STD);
}

/*
 * Error message string table.
 */
static const Msg order_errors[] = {
	MSG_ORD_ERR_INFORANGE,		/* MSG_INTL(MSG_ORD_ERR_INFORANGE) */
	MSG_ORD_ERR_ORDER,		/* MSG_INTL(MSG_ORD_ERR_ORDER) */
	MSG_ORD_ERR_LINKRANGE,		/* MSG_INTL(MSG_ORD_ERR_LINKRANGE) */
	MSG_ORD_ERR_FLAGS,		/* MSG_INTL(MSG_ORD_ERR_FLAGS) */
	MSG_ORD_ERR_CYCLIC,		/* MSG_INTL(MSG_ORD_ERR_CYCLIC) */
	MSG_ORD_ERR_LINKINV		/* MSG_INTL(MSG_ORD_ERR_LINKINV) */
};

void
Dbg_sec_order_error(Lm_list *lml, Ifl_desc *ifl, Word ndx, int error)
{
	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (error == 0)
		return;

	dbg_print(lml, MSG_INTL(MSG_ORD_ERR_TITLE),
	    ifl->ifl_isdesc[ndx]->is_name, ifl->ifl_name);

	if (error)
		dbg_print(lml, MSG_INTL(order_errors[error - 1]));
}

void
Dbg_sec_redirected(Lm_list *lml, const char *oname, const char *nname)
{
	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SEC_REDIRECTED), oname, nname);
}

void
Dbg_sec_gnu_comdat(Lm_list *lml, const char *name, uint_t comdat, uint_t relax)
{
	const char	*fmt;

	if (DBG_NOTCLASS(DBG_C_SECTIONS))
		return;

	if (comdat && relax)
		fmt = MSG_INTL(MSG_SEC_GNU_COMDAT_1);
	else if (comdat)
		fmt = MSG_INTL(MSG_SEC_GNU_COMDAT_2);
	else
		fmt = MSG_INTL(MSG_SEC_GNU_COMDAT_3);

	dbg_print(lml, fmt, name);
}
