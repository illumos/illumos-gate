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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routines for syminfo attributes.
 */
#include	<stdio.h>
#include	<_machelf.h>
#include	"_conv.h"
#include	"syminfo_msg.h"



#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_SYMINFO_FLG_DIRECT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_COPY_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_LAZYLOAD_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SYMINFO_FLG_DIRECTBIND_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_syminfo_flags_buf_t is large enough:
 *
 * FLAGSZ is the real minimum size of the buffer required by
 * conv_syminfo_flags(). However, Conv_syminfo_flags_buf_t uses
 * CONV_SYMINFO_FLAGS_BUFSIZE to set the buffer size. We do things
 * this way because the definition of FLAGSZ uses information that
 * is not available in the environment of other programs that include
 * the conv.h header file.
 */
#if (CONV_SYMINFO_FLAGS_BUFSIZE != FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAGSZ
#include "report_bufsize.h"
#error "CONV_SYMINFO_FLAGS_BUFSIZE does not match FLAGSZ"
#endif

const char *
conv_syminfo_flags(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_syminfo_flags_buf_t *syminfo_flags_buf)
{
	static Val_desc vda[] = {
		{ SYMINFO_FLG_DIRECT,	MSG_ORIG(MSG_SYMINFO_FLG_DIRECT) },
		{ SYMINFO_FLG_COPY,	MSG_ORIG(MSG_SYMINFO_FLG_COPY) },
		{ SYMINFO_FLG_LAZYLOAD,	MSG_ORIG(MSG_SYMINFO_FLG_LAZYLOAD) },
		{ SYMINFO_FLG_DIRECTBIND,
		    MSG_ORIG(MSG_SYMINFO_FLG_DIRECTBIND) },
		{ SYMINFO_FLG_NOEXTDIRECT,
		    MSG_ORIG(MSG_SYMINFO_FLG_NOEXTDIRECT) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (syminfo_flags_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = syminfo_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	conv_arg.prefix = conv_arg.suffix = NULL;
	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)syminfo_flags_buf->buf);
}
