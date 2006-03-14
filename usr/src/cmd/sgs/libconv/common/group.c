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

#include	<string.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"group_msg.h"

#define	FLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_GPH_ZERO_SIZE + \
		MSG_GPH_LDSO_SIZE + \
		MSG_GPH_FIRST_SIZE + \
		MSG_GPH_PARENT_SIZE + \
		MSG_GPH_FILTEE_SIZE + \
		MSG_GPH_INITIAL_SIZE + \
		MSG_GPH_STICKY_SIZE + \
		CONV_INV_STRSIZE + MSG_GBL_CSQBRKT_SIZE

/*
 * String conversion routine for Grp_hdl flags.
 */
const char *
conv_grphdl_flags(uint_t flags)
{
	static char	string[FLAGSZ];
	static Val_desc vda[] = {
		{ GPH_ZERO,		MSG_ORIG(MSG_GPH_ZERO) },
		{ GPH_LDSO,		MSG_ORIG(MSG_GPH_LDSO) },
		{ GPH_FIRST,		MSG_ORIG(MSG_GPH_FIRST) },
		{ GPH_PARENT,		MSG_ORIG(MSG_GPH_PARENT) },
		{ GPH_FILTEE,		MSG_ORIG(MSG_GPH_FILTEE) },
		{ GPH_INITIAL,		MSG_ORIG(MSG_GPH_INITIAL) },
		{ GPH_STICKY,		MSG_ORIG(MSG_GPH_STICKY) },
		{ 0,			0 }
	};

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));
	if (conv_expn_field(string, FLAGSZ, vda, flags, flags, 0, 0))
		(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), FLAGSZ);

	return ((const char *)string);
}
