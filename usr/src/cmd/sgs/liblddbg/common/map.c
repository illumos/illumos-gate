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

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

static const char
	*Dbg_decl =	NULL;

void
Dbg_map_set_atsign(Boolean new)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	if (new)
		Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_4);
	else
		Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_5);
}

void
Dbg_map_set_equal(Boolean new)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	if (new)
		Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_1);
	else
		Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_2);
}

void
Dbg_map_version(Lm_list *lml, const char *version, const char *name, int scope)
{
	const char	*str, *scp;

	if (DBG_NOTCLASS(DBG_C_MAP | DBG_C_SYMBOLS))
		return;

	str = MSG_INTL(MSG_MAP_SYM_SCOPE);
	if (scope)
		scp = MSG_ORIG(MSG_SYM_GLOBAL);
	else
		scp = MSG_ORIG(MSG_SYM_LOCAL);

	if (version)
		dbg_print(lml, MSG_INTL(MSG_MAP_SYM_VER_1), str, version,
		    Dbg_demangle_name(name), scp);
	else
		dbg_print(lml, MSG_INTL(MSG_MAP_SYM_VER_2), str,
		    Dbg_demangle_name(name), scp);
}

void
Dbg_map_size_new(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_SYM_SIZE), Dbg_demangle_name(name),
	    MSG_INTL(MSG_STR_ADD));
}

void
Dbg_map_size_old(Ofl_desc *ofl, Sym_desc *sdp)
{
	Conv_inv_buf_t	inv_buf;
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_SYM_SIZE), sdp->sd_name,
	    MSG_INTL(MSG_STR_UP_1));

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(lml, ELF_DBG_LD, MSG_INTL(MSG_STR_UP_2),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_map_symbol(Ofl_desc *ofl, Sym_desc *sdp)
{
	Conv_inv_buf_t	inv_buf;
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_MAP | DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(lml, ELF_DBG_LD, MSG_INTL(MSG_STR_ENTERED),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym, sdp->sd_aux ?
	    sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_map_dash(Lm_list *lml, const char *name, Sdf_desc *sdf)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	if (sdf->sdf_flags & FLG_SDF_SONAME)
		str = MSG_INTL(MSG_MAP_CNT_DEF_1);
	else
		str = MSG_INTL(MSG_MAP_CNT_DEF_2);

	dbg_print(lml, str, name, sdf->sdf_soname);
}

void
Dbg_map_sort_orig(Lm_list *lml, Sg_desc *sgp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(lml, MSG_INTL(MSG_MAP_SORTSEG), str);
}

void
Dbg_map_sort_fini(Lm_list *lml, Sg_desc *sgp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(lml, MSG_INTL(MSG_MAP_SEGSORT), str);
}

void
Dbg_map_parse(Lm_list *lml, const char *file)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_MAPFILE), file);
}

void
Dbg_map_ent(Lm_list *lml, Boolean new, Ent_desc *enp, Ofl_desc *ofl)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_MAP_DIR));
	Dbg_ent_entry(lml, ofl->ofl_dehdr->e_machine, enp);
	if (new)
		Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_3);
}

void
Dbg_map_pipe(Lm_list *lml, Sg_desc *sgp, const char *sec_name, const Word ndx)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_SEC_ORDER), sgp->sg_name, sec_name,
	    EC_WORD(ndx));
}

void
Dbg_map_seg(Ofl_desc *ofl, int ndx, Sg_desc *sgp)
{
	Lm_list	*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	if (Dbg_decl) {
		dbg_print(lml, MSG_ORIG(MSG_FMT_STR), Dbg_decl);
		Dbg_seg_desc_entry(ofl->ofl_lml,
		    ofl->ofl_dehdr->e_machine, ndx, sgp);
		Dbg_util_nl(lml, DBG_NL_STD);
		Dbg_decl = NULL;
	}
}
