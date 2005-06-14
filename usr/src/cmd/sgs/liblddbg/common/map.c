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
 *	Copyright (c) 2000 by Sun Microsystems, Inc.
 *	All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

static const char
	*_Dbg_decl =	NULL;

void
Dbg_map_version(const char *version, const char *name, int scope)
{
	const char	*str, *scp;

	if (DBG_NOTCLASS(DBG_MAP | DBG_SYMBOLS))
		return;

	str = MSG_INTL(MSG_MAP_SYM_SCOPE);
	if (scope)
		scp = MSG_ORIG(MSG_SYM_GLOBAL);
	else
		scp = MSG_ORIG(MSG_SYM_LOCAL);

	if (version)
		dbg_print(MSG_INTL(MSG_MAP_SYM_VER_1), str, version,
		    _Dbg_sym_dem(name), scp);
	else
		dbg_print(MSG_INTL(MSG_MAP_SYM_VER_2), str,
		    _Dbg_sym_dem(name), scp);
}

void
Dbg_map_size_new(const char *name)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	dbg_print(MSG_INTL(MSG_MAP_SYM_SIZE), _Dbg_sym_dem(name),
	    MSG_INTL(MSG_STR_ADD));
}

void
Dbg_map_size_old(Ehdr *ehdr, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	dbg_print(MSG_INTL(MSG_MAP_SYM_SIZE), sdp->sd_name,
	    MSG_INTL(MSG_STR_UP_1));

	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_UP_2), ehdr, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
	    conv_deftag_str(sdp->sd_ref));
}

/*
 * Provide for printing mapfile entered symbols when symbol debugging hasn't
 * been enabled.
 */
void
Dbg_map_symbol(Ehdr *ehdr, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (DBG_NOTCLASS(DBG_SYMBOLS))
		Elf_sym_table_entry(MSG_INTL(MSG_STR_ENTERED), ehdr,
		    sdp->sd_sym,
		    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
		    conv_deftag_str(sdp->sd_ref));
}

void
Dbg_map_dash(const char *name, Sdf_desc *sdf)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_MAP))
		return;

	if (sdf->sdf_flags & FLG_SDF_SONAME)
		str = MSG_INTL(MSG_MAP_CNT_DEF_1);
	else
		str = MSG_INTL(MSG_MAP_CNT_DEF_2);

	dbg_print(str, name, sdf->sdf_soname);
}

void
Dbg_map_sort_orig(Sg_desc *sgp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(MSG_INTL(MSG_MAP_SORTSEG), str);
}

void
Dbg_map_sort_fini(Sg_desc *sgp)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(MSG_INTL(MSG_MAP_SEGSORT), str);
}

void
Dbg_map_parse(const char *file)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_MAP_MAPFILE), file);
}

void
Dbg_map_equal(Boolean new)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	if (new)
		_Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_1);
	else
		_Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_2);
}

void
Dbg_map_ent(Boolean new, Ent_desc *enp, Ofl_desc *ofl)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	dbg_print(MSG_INTL(MSG_MAP_MAP_DIR));
	_Dbg_ent_entry(ofl->ofl_e_machine, enp);
	if (new)
		_Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_3);
}

void
Dbg_map_atsign(Boolean new)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	if (new)
		_Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_4);
	else
		_Dbg_decl = MSG_INTL(MSG_MAP_SEG_DECL_5);
}

void
Dbg_map_pipe(Sg_desc *sgp, const char *sec_name, const Word ndx)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	dbg_print(MSG_INTL(MSG_MAP_SEC_ORDER), sgp->sg_name, sec_name,
	    EC_WORD(ndx));
}

void
Dbg_map_seg(Half mach, int ndx, Sg_desc *sgp)
{
	if (DBG_NOTCLASS(DBG_MAP))
		return;

	if (_Dbg_decl) {
		dbg_print(MSG_ORIG(MSG_FMT_STR), _Dbg_decl);
		_Dbg_seg_desc_entry(mach, ndx, sgp);
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		_Dbg_decl = NULL;
	}
}
