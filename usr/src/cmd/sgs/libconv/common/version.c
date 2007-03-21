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

/*
 * String conversion routine for version flag entries.
 */
#include	<stdio.h>
#include	"_conv.h"
#include	"version_msg.h"

const char *
conv_ver_flags(Half flags)
{
	if (flags & VER_FLG_WEAK)
		return (MSG_ORIG(MSG_VER_FLG_WEAK));
	else if (flags & VER_FLG_BASE)
		return (MSG_ORIG(MSG_VER_FLG_BASE));
	else
		return (MSG_ORIG(MSG_GBL_NULL));
}


/*
 * Format a version index as contained in a VERSYM section
 */
const char *
conv_ver_index(Versym verndx)
{
	static Conv_inv_buf_t	string;

	/* Special case versions starting at VER_NDX_LORESERVE */
	if (verndx == VER_NDX_ELIMINATE)
		return (MSG_ORIG(MSG_VERSYM_ELIMINATE));

	/* format as numeric */
	(void) snprintf(string, sizeof (string), MSG_ORIG(MSG_VERSYM_FMT),
	    EC_HALF(verndx));
	return (string);
}
