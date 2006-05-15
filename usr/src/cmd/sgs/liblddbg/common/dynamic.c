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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
	char	index[INDEX_STR_SIZE];

	(void) snprintf(index, INDEX_STR_SIZE, MSG_ORIG(MSG_FMT_INDEX), ndx);
	dbg_print(lml, MSG_INTL(MSG_DYN_ENTRY), index,
	    conv_dyn_tag(dyn->d_tag, mach, 0), EC_XWORD(dyn->d_un.d_val), name);
}
