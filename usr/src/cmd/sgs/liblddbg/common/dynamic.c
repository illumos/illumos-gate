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
 *	Copyright (c) 2000,2001 by Sun Microsystems, Inc.
 *	All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<link.h>
#include	<stdio.h>
#include	"msg.h"
#include	"_debug.h"

/*
 * Print out the dynamic section entries.
 */
void
Gelf_dyn_title()
{
	dbg_print(MSG_INTL(MSG_DYN_TITLE));
}

void
Gelf_dyn_print(GElf_Dyn * dyn, int ndx, const char * name, Half mach)
{
	char	index[10];

	(void) sprintf(index, MSG_ORIG(MSG_FMT_INDEX), ndx);
	dbg_print(MSG_INTL(MSG_DYN_ENTRY), index,
	    /* LINTED */
	    conv_dyntag_str((Sword)dyn->d_tag, mach),
	    EC_XWORD(dyn->d_un.d_val), name);
}
