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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"


/*
 * Report change in input enable status caused by evaluating
 * $if/$elif control directives.
 */
void
Dbg_map_pass(Lm_list *lml, Boolean enable, const char *file,
    Lineno lineno, const char *directive)
{
	const char *fmt;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	fmt = enable ? MSG_INTL(MSG_MAP_PASS) : MSG_INTL(MSG_MAP_NOPASS);
	dbg_print(lml, fmt, file, EC_LINENO(lineno), directive);
}

/*
 * Report entry/removal of boolean identifier from conditional expression
 * known values.
 */
void
Dbg_map_cexp_id(Lm_list *lml, Boolean add, const char *file,
    Lineno lineno, const char *id)
{
	const char *fmt;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	fmt = add ? MSG_INTL(MSG_MAP_ID_ADD) : MSG_INTL(MSG_MAP_ID_CLEAR);
	dbg_print(lml, fmt, file, EC_LINENO(lineno), id);
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
Dbg_map_size_new(Lm_list *lml, const char *symname, const char *segname,
    Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_SYM_SIZE), EC_LINENO(lineno), segname,
	    Dbg_demangle_name(symname), MSG_INTL(MSG_STR_ADDING));
}

void
Dbg_map_size_old(Ofl_desc *ofl, Sym_desc *sdp, const char *segname,
    Lineno lineno)
{
	Conv_inv_buf_t	inv_buf;
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_SYM_SIZE), EC_LINENO(lineno), segname,
	    sdp->sd_name, MSG_INTL(MSG_STR_UP_1));

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(lml, ELF_DBG_LD, MSG_INTL(MSG_STR_UP_2),
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
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
	    ofl->ofl_dehdr->e_ident[EI_OSABI],  ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

/*
 * Object version dependency. In the v1 syntax, this is the 'dash' operator.
 * In the v2 syntax, the DEPEND_VERSIONS directive.
 */
void
Dbg_map_dv(Lm_list *lml, const char *obj_name, Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_DV), EC_LINENO(lineno), obj_name);
}

/*
 * Add a version to an object dependency
 */
void
Dbg_map_dv_entry(Lm_list *lml, Lineno lineno, int require, const char *version)
{
	const char *attr;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	attr = require ? MSG_INTL(MSG_STR_REQUIRE) : MSG_INTL(MSG_STR_ALLOW);
	dbg_print(lml, MSG_INTL(MSG_MAP_DV_ENTRY), attr, version,
	    EC_LINENO(lineno));
}

void
Dbg_map_sort_title(Lm_list *lml, Boolean orig)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (orig) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_MAP_SORT_TITLE));
		dbg_print(lml, MSG_INTL(MSG_MAP_SORT_TITLE_O));
	} else {
		dbg_print(lml, MSG_INTL(MSG_MAP_SORT_TITLE_S));
	}
}

void
Dbg_map_sort_seg(Lm_list *lml, uchar_t osabi, Half mach, Sg_desc *sgp)
{
	const char	*type_str;
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;
	if (DBG_NOTDETAIL())
		return;

	type_str = conv_phdr_type(osabi, mach, sgp->sg_phdr.p_type,
	    0, &inv_buf);

	if (sgp->sg_name) {
		if (sgp->sg_flags & FLG_SG_P_VADDR) {
			dbg_print(lml, MSG_ORIG(MSG_MAP_SORT_SEG_V),
			    type_str, sgp->sg_name,
			    EC_ADDR(sgp->sg_phdr.p_vaddr));
		} else if (sgp->sg_flags & FLG_SG_ORDERED) {
			/*
			 * All FLG_SG_ORDERED have adjacent sg_id values
			 * that start at SGID_TEXT. Subtract out the base
			 * in order to present the order values based at 0.
			 */
			dbg_print(lml, MSG_ORIG(MSG_MAP_SORT_SEG_O),
			    type_str, sgp->sg_name,
			    EC_WORD(sgp->sg_id - SGID_TEXT));
		} else {
			dbg_print(lml, MSG_ORIG(MSG_MAP_SORT_SEG_NAME),
			    type_str, sgp->sg_name);
		}
	} else {
		dbg_print(lml, MSG_ORIG(MSG_MAP_SORT_SEG), type_str);
	}
}

void
Dbg_map_parse(Lm_list *lml, const char *file, int version)
{
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_MAPFILE), file, EC_WORD(version),
	    conv_mapfile_version(version, 0, &inv_buf));
}

void
Dbg_map_ent(Lm_list *lml, Ent_desc *enp, Ofl_desc *ofl, Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_EC), EC_LINENO(lineno));
	Dbg_ent_entry(lml, ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, enp);
}

void
Dbg_map_ent_ord_title(Lm_list *lml, const char *segname)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_ENT_ORD_TITLE), segname);
}

void
Dbg_map_seg_os_order(Lm_list *lml, Sg_desc *sgp, const char *sec_name,
    Word ndx, Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_OS_ORDER), EC_LINENO(lineno),
	    sgp->sg_name, sec_name, EC_WORD(ndx));
}

void
Dbg_map_seg(Ofl_desc *ofl, dbg_state_t dbg_state, int ndx, Sg_desc *sgp,
    Lineno lineno)
{
	Lm_list	*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_SEG), EC_LINENO(lineno),
	    Dbg_state_str(dbg_state));
	Dbg_seg_desc_entry(ofl->ofl_lml, ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, ndx, sgp, FALSE);
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_map_seg_order(Ofl_desc *ofl, uchar_t osabi, Half mach,
    dbg_state_t dbg_state, Lineno lineno)
{
	Lm_list	*lml = ofl->ofl_lml;
	Aliste		idx;
	Sg_desc		*sgp;
	Conv_inv_buf_t	inv_buf;
	const char	*type_str;

	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_SEG_ORDER), EC_LINENO(lineno),
	    EC_XWORD(aplist_nitems(ofl->ofl_segs_order)),
	    Dbg_state_str(dbg_state));
	for (APLIST_TRAVERSE(ofl->ofl_segs_order, idx, sgp)) {
		type_str = conv_phdr_type(osabi, mach, sgp->sg_phdr.p_type,
		    0, &inv_buf);
		dbg_print(lml, MSG_ORIG(MSG_MAP_SORT_SEG_NAME), type_str,
		    sgp->sg_name);
	}
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_map_post_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_POST_TITLE));
}

void
Dbg_map_hdr_noalloc(Lm_list *lml, Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MAP_HDR_NOALLOC), EC_LINENO(lineno));
}
