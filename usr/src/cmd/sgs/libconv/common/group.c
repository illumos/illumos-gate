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

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_GPH_ZERO_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_LDSO_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_FIRST_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_PARENT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_FILTEE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_INITIAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_STICKY_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

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
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}
