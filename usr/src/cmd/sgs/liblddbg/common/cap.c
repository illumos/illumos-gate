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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2022 Oxide Computer Company
 */

#include	<stdio.h>
#include	<debug.h>
#include	<libld.h>
#include	<conv.h>
#include	"msg.h"
#include	"_debug.h"

void
Dbg_cap_candidate(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_CANDIDATE), name);
}

void
Dbg_cap_filter(Lm_list *lml, const char *dir, Rt_map *flmp)
{
	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	if (flmp)
		dbg_print(lml, MSG_INTL(MSG_CAP_FILTER_1), dir, NAME(flmp));
	else
		dbg_print(lml, MSG_INTL(MSG_CAP_FILTER_2), dir);
}

void
Dbg_cap_identical(Lm_list *lml, const char *file1, const char *file2)
{
	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_IDENTICAL), file1, file2);
}

void
Dbg_cap_val(Lm_list *lml, Syscapset *sys, Syscapset *alt, Half mach)
{
	Conv_cap_val_buf_t	cap_val_buf;

	if ((sys->sc_plat == NULL) && (sys->sc_mach == NULL) &&
	    (sys->sc_hw_2 == 0) && (sys->sc_hw_1 == 0) &&
	    (sys->sc_sf_1 == 0))
		return;

	Dbg_util_nl(lml, DBG_NL_FRC);

	/*
	 * Print any capabilities in precedence order.
	 */
	if (sys->sc_plat) {
		dbg_print(lml, MSG_INTL(MSG_CAP_SYS_PLAT), sys->sc_plat);
	}
	if (sys->sc_mach) {
		dbg_print(lml, MSG_INTL(MSG_CAP_SYS_MACH), sys->sc_mach);
	}
	if (sys->sc_hw_3) {
		dbg_print(lml, MSG_INTL(MSG_CAP_SYS_HW_3),
		    conv_cap_val_hw3(sys->sc_hw_3, mach, 0,
		    &cap_val_buf.cap_val_hw3_buf));
	}
	if (sys->sc_hw_2) {
		dbg_print(lml, MSG_INTL(MSG_CAP_SYS_HW_2),
		    conv_cap_val_hw2(sys->sc_hw_2, mach, 0,
		    &cap_val_buf.cap_val_hw2_buf));
	}
	if (sys->sc_hw_1) {
		dbg_print(lml, MSG_INTL(MSG_CAP_SYS_HW_1),
		    conv_cap_val_hw1(sys->sc_hw_1, mach, 0,
		    &cap_val_buf.cap_val_hw1_buf));
	}
	if (sys->sc_sf_1) {
		dbg_print(lml, MSG_INTL(MSG_CAP_SYS_SF_1),
		    conv_cap_val_sf1(sys->sc_sf_1, mach, 0,
		    &cap_val_buf.cap_val_sf1_buf));
	}

	if (alt != sys) {
		Dbg_util_nl(lml, DBG_NL_FRC);
		if (alt->sc_plat != sys->sc_plat) {
			dbg_print(lml, MSG_INTL(MSG_CAP_ALT_PLAT),
			    alt->sc_plat);
		}
		if (alt->sc_mach != sys->sc_mach) {
			dbg_print(lml, MSG_INTL(MSG_CAP_ALT_MACH),
			    alt->sc_mach);
		}
		if (alt->sc_hw_3 != sys->sc_hw_3) {
			dbg_print(lml, MSG_INTL(MSG_CAP_ALT_HW_3),
			    conv_cap_val_hw3(alt->sc_hw_3, mach, 0,
			    &cap_val_buf.cap_val_hw3_buf));
		}
		if (alt->sc_hw_2 != sys->sc_hw_2) {
			dbg_print(lml, MSG_INTL(MSG_CAP_ALT_HW_2),
			    conv_cap_val_hw2(alt->sc_hw_2, mach, 0,
			    &cap_val_buf.cap_val_hw2_buf));
		}
		if (alt->sc_hw_1 != sys->sc_hw_1) {
			dbg_print(lml, MSG_INTL(MSG_CAP_ALT_HW_1),
			    conv_cap_val_hw1(alt->sc_hw_1, mach, 0,
			    &cap_val_buf.cap_val_hw1_buf));
		}
		if (alt->sc_sf_1 != sys->sc_sf_1) {
			dbg_print(lml, MSG_INTL(MSG_CAP_ALT_SF_1),
			    conv_cap_val_sf1(alt->sc_sf_1, mach, 0,
			    &cap_val_buf.cap_val_sf1_buf));
		}
	}

	Dbg_util_nl(lml, DBG_NL_FRC);
}

/*
 * This version takes a pointer to a Capmask, and will report the exclusion
 * bits if they exist.
 */
void
Dbg_cap_ptr_entry(Lm_list *lml, dbg_state_t dbg_state, Xword tag,
    const char *ptr)
{
	Conv_inv_buf_t		inv_buf;

	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_SEC_ENTRY), Dbg_state_str(dbg_state),
	    conv_cap_tag(tag, 0, &inv_buf), ptr);
}

/*
 * This version takes a pointer to a CapMask, and will report the exclusion
 * bits if they exist.
 */
void
Dbg_cap_val_entry(Lm_list *lml, dbg_state_t dbg_state, Xword tag, Xword val,
    Half mach)
{
	Conv_inv_buf_t		inv_buf;
	Conv_cap_val_buf_t	cap_val_buf;

	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_SEC_ENTRY), Dbg_state_str(dbg_state),
	    conv_cap_tag(tag, 0, &inv_buf), conv_cap_val(tag, val, mach, 0,
	    &cap_val_buf));
}

void
Dbg_cap_sec_title(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_CAP_SEC_TITLE), name);
}

void
Dbg_cap_mapfile_title(Lm_list *lml, Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP | DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_CAP), EC_LINENO(lineno));
}

void
Dbg_cap_id(Lm_list *lml, Lineno lineno, const char *oid, const char *nid)
{
	Dbg_cap_mapfile_title(lml, lineno);
	Dbg_cap_ptr_entry(lml, DBG_STATE_CURRENT, CA_SUNW_ID, oid);
	Dbg_cap_ptr_entry(lml, DBG_STATE_NEW, CA_SUNW_ID, nid);
	Dbg_cap_ptr_entry(lml, DBG_STATE_RESOLVED, CA_SUNW_ID, nid);
}

void
Dbg_cap_post_title(Lm_list *lml, int *title)
{
	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	if ((*title)++ == 0)
		dbg_print(lml, MSG_INTL(MSG_CAP_POST_TITLE));
}

void
Elf_cap_title(Lm_list *lml)
{
	dbg_print(lml, MSG_INTL(MSG_CAP_ELF_TITLE));
}

void
Elf_cap_entry(Lm_list *lml, Cap *cap, int ndx, const char *str, size_t str_size,
    Half mach)
{
	Conv_inv_buf_t		inv_buf;
	Conv_cap_val_buf_t	cap_val_buf;
	char			index[INDEX_STR_SIZE];

	(void) snprintf(index, INDEX_STR_SIZE, MSG_ORIG(MSG_FMT_INDEX), ndx);

	switch (cap->c_tag) {
	case CA_SUNW_PLAT:
	case CA_SUNW_MACH:
	case CA_SUNW_ID:
		/* If offset is in range, format as a string */
		if (str && (cap->c_un.c_ptr < str_size)) {
			str += cap->c_un.c_ptr;
			break;
		}
		/*FALLTHROUGH*/
	default:
		/* Format numerically */
		str = conv_cap_val(cap->c_tag, cap->c_un.c_val, mach, 0,
		    &cap_val_buf);
	}

	dbg_print(lml, MSG_INTL(MSG_CAP_ELF_ENTRY), index,
	    conv_cap_tag(cap->c_tag, 0, &inv_buf), str);
}
