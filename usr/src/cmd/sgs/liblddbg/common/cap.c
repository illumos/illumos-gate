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

#include	"_synonyms.h"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

#if	!defined(_ELF64)

void
Dbg_cap_hw_candidate(const char *name)
{
	if (DBG_NOTCLASS(DBG_CAP | DBG_FILES))
		return;

	dbg_print(MSG_INTL(MSG_CAP_HW_CANDIDATE), name);
}

void
Dbg_cap_hw_filter(const char *dir, const char *filtee)
{
	if (DBG_NOTCLASS(DBG_CAP | DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	if (filtee)
		dbg_print(MSG_INTL(MSG_CAP_HWFILTR_1), dir, filtee);
	else
		dbg_print(MSG_INTL(MSG_CAP_HWFILTR_2), dir);
}

void
Dbg_cap_sec_title(const char *file)
{
	if (DBG_NOTCLASS(DBG_CAP))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_CAP_SEC_TITLE), file);
}

void
Gelf_cap_title(void)
{
	dbg_print(MSG_INTL(MSG_CAP_ELF_TITLE));
}

void
Gelf_cap_print(GElf_Cap * cap, int ndx, Half mach)
{
	char	index[10];

	(void) sprintf(index, MSG_ORIG(MSG_FMT_INDEX), ndx);
	dbg_print(MSG_INTL(MSG_CAP_ELF_ENTRY), index,
	    conv_captag_str(cap->c_tag),
	    conv_capval_str(cap->c_tag, cap->c_un.c_val, mach));
}

#endif

static const Msg captype[] = {
	MSG_STR_INITIAL,		/* MSG_INTL(MSG_STR_INITIAL) */
	MSG_STR_IGNORE,			/* MSG_INTL(MSG_STR_IGNORE) */
	MSG_STR_OLD,			/* MSG_INTL(MSG_STR_OLD) */
	MSG_STR_NEW,			/* MSG_INTL(MSG_STR_NEW) */
	MSG_STR_RESOLVED		/* MSG_INTL(MSG_STR_RESOLVED) */
};

void
Dbg_cap_sec_entry(uint_t type, Xword tag, Xword val, Half mach)
{
	if (DBG_NOTCLASS(DBG_CAP))
		return;

	dbg_print(MSG_INTL(MSG_CAP_SEC_ENTRY), MSG_INTL(captype[type]),
	    conv_captag_str(tag), conv_capval_str(tag, val, mach));
}

void
Dbg_cap_mapfile(Xword tag, Xword val, Half mach)
{
	if (DBG_NOTCLASS(DBG_MAP | DBG_CAP))
		return;

	dbg_print(MSG_INTL(MSG_MAP_CAP));
	Dbg_cap_sec_entry(DBG_CAP_INITIAL, tag, val, mach);
}

void
Dbg_cap_hw_1(Xword val, Half mach)
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_CAP_HW_1), conv_hwcap_1_str(val, mach));
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}
