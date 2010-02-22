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

#include	<stdio.h>
#include	<debug.h>
#include	<libld.h>
#include	<conv.h>
#include	"msg.h"
#include	"_debug.h"

void
Dbg_cap_hw_candidate(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_HW_CANDIDATE), name);
}

void
Dbg_cap_hw_filter(Lm_list *lml, const char *dir, Rt_map *flmp)
{
	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	if (flmp)
		dbg_print(lml, MSG_INTL(MSG_CAP_HWFILTR_1), dir, NAME(flmp));
	else
		dbg_print(lml, MSG_INTL(MSG_CAP_HWFILTR_2), dir);
}

void
Dbg_cap_val_hw1(Lm_list *lml, Xword val, Half mach)
{
	Conv_cap_val_hw1_buf_t cap_val_hw1_buf;

	Dbg_util_nl(lml, DBG_NL_FRC);
	dbg_print(lml, MSG_INTL(MSG_CAP_VAL_HW1),
	    conv_cap_val_hw1(val, mach, 0, &cap_val_hw1_buf));
	Dbg_util_nl(lml, DBG_NL_FRC);
}

void
Dbg_cap_entry(Lm_list *lml, dbg_state_t dbg_state, Xword tag, Xword val,
    Half mach)
{
	Conv_inv_buf_t		inv_buf;
	Conv_cap_val_buf_t	cap_val_buf;

	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_ENTRY), Dbg_state_str(dbg_state),
	    conv_cap_tag(tag, 0, &inv_buf), conv_cap_val(tag, val, mach,
	    &cap_val_buf));
}

/*
 * This version takes a pointer to a CapMask, and will report the exclusion
 * bits if they exist.
 */
void
Dbg_cap_entry2(Lm_list *lml, dbg_state_t dbg_state, Xword tag, CapMask *cmp,
    Half mach)
{
	Conv_inv_buf_t		inv_buf;
	Conv_cap_val_buf_t	cap_val_buf1, cap_val_buf2;

	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	/* If there is no exclusion mask, use the simpler format */
	if (cmp->cm_exclude == 0) {
		dbg_print(lml, MSG_INTL(MSG_CAP_ENTRY),
		    Dbg_state_str(dbg_state), conv_cap_tag(tag, 0, &inv_buf),
		    conv_cap_val(tag, cmp->cm_value, mach, &cap_val_buf1));
		return;
	}


	dbg_print(lml, MSG_INTL(MSG_CAP_ENTRY_EXC), Dbg_state_str(dbg_state),
	    conv_cap_tag(tag, 0, &inv_buf),
	    conv_cap_val(tag, cmp->cm_value, mach, &cap_val_buf1),
	    conv_cap_val(tag, cmp->cm_exclude, mach, &cap_val_buf2));
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
Dbg_cap_out_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_CAP_OUT_TITLE));
}

void
Dbg_cap_mapfile_title(Lm_list *lml, Lineno lineno)
{
	if (DBG_NOTCLASS(DBG_C_MAP | DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_CAP), EC_LINENO(lineno));
}

void
Elf_cap_title(Lm_list *lml)
{
	dbg_print(lml, MSG_INTL(MSG_CAP_ELF_TITLE));
}

void
Elf_cap_entry(Lm_list *lml, Cap *cap, int ndx, Half mach)
{
	Conv_inv_buf_t		inv_buf;
	Conv_cap_val_buf_t	cap_val_buf;
	char			index[INDEX_STR_SIZE];

	(void) snprintf(index, INDEX_STR_SIZE, MSG_ORIG(MSG_FMT_INDEX), ndx);
	dbg_print(lml, MSG_INTL(MSG_CAP_ELF_ENTRY), index,
	    conv_cap_tag(cap->c_tag, 0, &inv_buf),
	    conv_cap_val(cap->c_tag, cap->c_un.c_val, mach, &cap_val_buf));
}
