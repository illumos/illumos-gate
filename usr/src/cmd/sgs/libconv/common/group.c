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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<string.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"group_msg.h"

#define	FLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_GPH_INITIAL_SIZE + \
		MSG_GPH_ZERO_SIZE + \
		MSG_GPH_LDSO_SIZE + \
		MSG_GPH_FIRST_SIZE + \
		MSG_GPH_PARENT_SIZE + \
		MSG_GPH_FILTEE_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

/*
 * String conversion routine for Grp_hdl flags.
 */
const char *
conv_grphdrflags_str(uint_t flags)
{
	static	char	string[FLAGSZ] = { '\0' };

	(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	if (flags & GPH_INITIAL)
		(void) strcat(string, MSG_ORIG(MSG_GPH_INITIAL));
	if (flags & GPH_ZERO)
		(void) strcat(string, MSG_ORIG(MSG_GPH_ZERO));
	if (flags & GPH_LDSO)
		(void) strcat(string, MSG_ORIG(MSG_GPH_LDSO));
	if (flags & GPH_FIRST)
		(void) strcat(string, MSG_ORIG(MSG_GPH_FIRST));
	if (flags & GPH_PARENT)
		(void) strcat(string, MSG_ORIG(MSG_GPH_PARENT));
	if (flags & GPH_FILTEE)
		(void) strcat(string, MSG_ORIG(MSG_GPH_FILTEE));
	if (flags & GPH_STICKY)
		(void) strcat(string, MSG_ORIG(MSG_GPH_STICKY));

	(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

	return ((const char *)string);
}
