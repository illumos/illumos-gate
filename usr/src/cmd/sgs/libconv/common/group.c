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

#include	<string.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"group_msg.h"

#define	HDLSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_GPH_ZERO_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_LDSO_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_FIRST_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_FILTEE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_INITIAL_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPH_NOPENDLAZY_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE	+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_grphdl_flags_buf_t is large enough:
 *
 * HDLSZ is the real minimum size of the buffer required by conv_grphdl_flags().
 * However, Conv_grphdl_flags_buf_t uses CONV_GRPHDL_FLAGS_BUFSIZE to set the
 * buffer size. We do things this way because the definition of HDLSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_GRPHDL_FLAGS_BUFSIZE < HDLSZ) && !defined(__lint)
#error "CONV_GRPHDL_FLAGS_BUFSIZE is not large enough"
#endif

/*
 * String conversion routine for Grp_hdl flags.
 */
const char *
conv_grphdl_flags(uint_t flags, Conv_grphdl_flags_buf_t *grphdl_flags_buf)
{
	static Val_desc vda[] = {
		{ GPH_ZERO,		MSG_ORIG(MSG_GPH_ZERO) },
		{ GPH_LDSO,		MSG_ORIG(MSG_GPH_LDSO) },
		{ GPH_FIRST,		MSG_ORIG(MSG_GPH_FIRST) },
		{ GPH_FILTEE,		MSG_ORIG(MSG_GPH_FILTEE) },
		{ GPH_INITIAL,		MSG_ORIG(MSG_GPH_INITIAL) },
		{ GPH_NOPENDLAZY,	MSG_ORIG(MSG_GPH_NOPENDLAZY) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (grphdl_flags_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.buf = grphdl_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)grphdl_flags_buf->buf);
}

#define	DESCSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_GPD_DLSYM_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPD_RELOC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPD_ADDEPS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPD_PARENT_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPD_FILTER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPD_PROMOTE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_GPD_REMOVE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE	+ CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_grpdesc_flags_buf_t is large enough:
 *
 * DESCSZ is the real min size of the buffer required by conv_grpdesc_flags().
 * However, Conv_grpdesc_flags_buf_t uses CONV_GRPDESC_FLAGS_BUFSIZE to set the
 * buffer size. We do things this way because the definition of DESCSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_GRPDESC_FLAGS_BUFSIZE < DESCSZ) && !defined(__lint)
#error "CONV_GRPDESC_FLAGS_BUFSIZE is not large enough"
#endif

/*
 * String conversion routine for Grp_desc flags.
 */
const char *
conv_grpdesc_flags(uint_t flags, Conv_grpdesc_flags_buf_t *grpdesc_flags_buf)
{
	static Val_desc vda[] = {
		{ GPD_DLSYM,		MSG_ORIG(MSG_GPD_DLSYM) },
		{ GPD_RELOC,		MSG_ORIG(MSG_GPD_RELOC) },
		{ GPD_ADDEPS,		MSG_ORIG(MSG_GPD_ADDEPS) },
		{ GPD_PARENT,		MSG_ORIG(MSG_GPD_PARENT) },
		{ GPD_FILTER,		MSG_ORIG(MSG_GPD_FILTER) },
		{ GPD_PROMOTE,		MSG_ORIG(MSG_GPD_PROMOTE) },
		{ GPD_REMOVE,		MSG_ORIG(MSG_GPD_REMOVE) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (grpdesc_flags_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.buf = grpdesc_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg);

	return ((const char *)grpdesc_flags_buf->buf);
}
