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

#include	<sgs.h>
#include	<stdio.h>
#include	<debug.h>
#include	<conv.h>
#include	<_debug.h>
#include	<msg.h>

/*
 * Print out the dynamic section entries.
 */
void
Elf_dyn_title(Lm_list *lml)
{
	dbg_print(lml, MSG_INTL(MSG_DYN_TITLE));
}

void
Elf_dyn_entry(Lm_list *lml, Dyn *dyn, int ndx, const char *name, Half mach)
{
	Conv_inv_buf_t	inv_buf;
	char		index[INDEX_STR_SIZE];

	(void) snprintf(index, sizeof (index), MSG_ORIG(MSG_FMT_INDEX), ndx);
	dbg_print(lml, MSG_INTL(MSG_DYN_ENTRY), index,
	    conv_dyn_tag(dyn->d_tag, mach, 0, &inv_buf),
	    EC_XWORD(dyn->d_un.d_val), name);
}

/*
 * Variant of Elf_dyn_entry() specifically for DT_NULL. Handles the
 * case of multiple adjacent DT_NULL entries by displaying them on
 * a single line using an index range instead of a single index.
 */
void
Elf_dyn_null_entry(Lm_list *lml, Dyn *dyn, int start_ndx, int end_ndx)
{
	Conv_inv_buf_t	inv_buf;
	char		index[2 * INDEX_STR_SIZE];

	if (start_ndx == end_ndx) {
		Elf_dyn_entry(lml, dyn, start_ndx, MSG_ORIG(MSG_STR_EMPTY), 0);
	} else {
		(void) snprintf(index, sizeof (index),
		    MSG_ORIG(MSG_FMT_INDEX_RANGE), start_ndx, end_ndx);
		dbg_print(lml, MSG_INTL(MSG_DYN_ENTRY), index,
		    conv_dyn_tag(DT_NULL, 0, 0, &inv_buf),
		    EC_XWORD(dyn->d_un.d_val), MSG_ORIG(MSG_STR_EMPTY));
	}
}
