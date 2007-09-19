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
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_seg_flags_buf_t is large enough:
 *
 * SEGSZ is the real minimum size of the buffer required by conv_seg_flags().
 * However, Conv_seg_flags_buf_t uses CONV_SEG_FLAGS_BUFSIZE to set the
 * buffer size. We do things this way because the definition of SEGSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_SEG_FLAGS_BUFSIZE < SEGSZ) && !defined(__lint)
#error "CONV_SEG_FLAGS_BUFSIZE is not large enough"
#endif

const char *
conv_seg_flags(Half flags, Conv_seg_flags_buf_t *seg_flags_buf)
{
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
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (seg_flags_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = seg_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, 0);

	return ((const char *)seg_flags_buf->buf);
}
