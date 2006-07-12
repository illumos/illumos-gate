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

/*
 * String conversion routine for segment flags.
 */
#include	<string.h>
#include	<libld.h>
#include	"_conv.h"
#include	"segments_msg.h"

#define	SEGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_FLG_SG_VADDR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_PADDR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_LENGTH_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_ALIGN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_ROUND_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_FLAGS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_TYPE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_ORDER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_NOHDR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_EMPTY_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_KEY_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_DISABLED_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_SG_PHREQ_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_STRSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

const char *
conv_seg_flags(Half flags)
{
	static char	string[SEGSZ];
	static Val_desc vda[] = {
		{ FLG_SG_VADDR,		MSG_ORIG(MSG_FLG_SG_VADDR) },
		{ FLG_SG_PADDR,		MSG_ORIG(MSG_FLG_SG_PADDR) },
		{ FLG_SG_LENGTH,	MSG_ORIG(MSG_FLG_SG_LENGTH) },
		{ FLG_SG_ALIGN,		MSG_ORIG(MSG_FLG_SG_ALIGN) },
		{ FLG_SG_ROUND,		MSG_ORIG(MSG_FLG_SG_ROUND) },
		{ FLG_SG_FLAGS,		MSG_ORIG(MSG_FLG_SG_FLAGS) },
		{ FLG_SG_TYPE,		MSG_ORIG(MSG_FLG_SG_TYPE) },
		{ FLG_SG_ORDER,		MSG_ORIG(MSG_FLG_SG_ORDER) },
		{ FLG_SG_NOHDR,		MSG_ORIG(MSG_FLG_SG_NOHDR) },
		{ FLG_SG_EMPTY,		MSG_ORIG(MSG_FLG_SG_EMPTY) },
		{ FLG_SG_KEY,		MSG_ORIG(MSG_FLG_SG_KEY) },
		{ FLG_SG_DISABLED,	MSG_ORIG(MSG_FLG_SG_DISABLED) },
		{ FLG_SG_PHREQ,		MSG_ORIG(MSG_FLG_SG_PHREQ) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { string, sizeof (string), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)string);
}
