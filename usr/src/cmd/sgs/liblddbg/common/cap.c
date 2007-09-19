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

static const Msg captype[] = {
	MSG_STR_INITIAL,		/* MSG_INTL(MSG_STR_INITIAL) */
	MSG_STR_IGNORE,			/* MSG_INTL(MSG_STR_IGNORE) */
	MSG_STR_OLD,			/* MSG_INTL(MSG_STR_OLD) */
	MSG_STR_NEW,			/* MSG_INTL(MSG_STR_NEW) */
	MSG_STR_RESOLVED		/* MSG_INTL(MSG_STR_RESOLVED) */
};

void
Dbg_cap_mapfile(Lm_list *lml, Xword tag, Xword val, Half mach)
{
	if (DBG_NOTCLASS(DBG_C_MAP | DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_MAP_CAP));
	Dbg_cap_sec_entry(lml, DBG_CAP_INITIAL, tag, val, mach);
}

void
Dbg_cap_sec_entry(Lm_list *lml, uint_t type, Xword tag, Xword val, Half mach)
{
	Conv_inv_buf_t		inv_buf;
	Conv_cap_val_buf_t	cap_val_buf;

	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	dbg_print(lml, MSG_INTL(MSG_CAP_SEC_ENTRY), MSG_INTL(captype[type]),
	    conv_cap_tag(tag, &inv_buf), conv_cap_val(tag, val, mach,
	    &cap_val_buf));
}

void
Dbg_cap_sec_title(Ofl_desc *ofl)
{
	Lm_list	*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_CAP))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_CAP_SEC_TITLE), ofl->ofl_name);
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
	    conv_cap_tag(cap->c_tag, &inv_buf),
	    conv_cap_val(cap->c_tag, cap->c_un.c_val, mach, &cap_val_buf));
}
