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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * String conversion routine for segment flags.
 */
#include	<string.h>
#include	<libld.h>
#include	"_conv.h"
#include	"entry_msg.h"

#define	ENTSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_FLG_EC_BUILTIN_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_EC_USED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_EC_CATCHALL_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_ent_flags_buf_t is large enough:
 *
 * ENTSZ is the real minimum size of the buffer required by conv_ent_flags().
 * However, Conv_ent_flags_buf_t uses CONV_ENT_FLAGS_BUFSIZE to set the
 * buffer size. We do things this way because the definition of ENTSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_ENT_FLAGS_BUFSIZE != ENTSZ) && !defined(__lint)
#define	REPORT_BUFSIZE ENTSZ
#include "report_bufsize.h"
#error "CONV_ENT_FLAGS_BUFSIZE does not match ENTSZ"
#endif

const char *
conv_ent_flags(ec_flags_t flags, Conv_ent_flags_buf_t *ent_flags_buf)
{
	static Val_desc vda[] = {
		{ FLG_EC_BUILTIN,	MSG_FLG_EC_BUILTIN },
		{ FLG_EC_USED,		MSG_FLG_EC_USED },
		{ FLG_EC_CATCHALL,	MSG_FLG_EC_CATCHALL },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (ent_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = ent_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, vda, 0);

	return ((const char *)ent_flags_buf->buf);
}


#define	ECFSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_TYP_ECF_PATH_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_TYP_ECF_BASENAME_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_TYP_ECF_OBJNAME_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_FLG_ECF_ARMEMBER_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_ent_flags_buf_t is large enough:
 *
 * ENTSZ is the real minimum size of the buffer required by conv_ent_flags().
 * However, Conv_ent_flags_buf_t uses CONV_ENT_FLAGS_BUFSIZE to set the
 * buffer size. We do things this way because the definition of ENTSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_ENT_FILES_FLAGS_BUFSIZE != ECFSZ) && !defined(__lint)
#define	REPORT_BUFSIZE ECFSZ
#include "report_bufsize.h"
#error "CONV_ENT_FILES_FLAGS_BUFSIZE does not match ECFSZ"
#endif

/*
 * Make a string representation of the End_desc_file edf_flags field.
 */
const char *
conv_ent_files_flags(Word flags, Conv_fmt_flags_t fmt_flags,
    Conv_ent_files_flags_buf_t *flags_buf)
{
	static const Msg	types[] = {
		MSG_TYP_ECF_PATH, MSG_TYP_ECF_BASENAME, MSG_TYP_ECF_OBJNAME
	};
#if TYP_ECF_NUM != (TYP_ECF_OBJNAME + 1)
#error "types has grown"
#endif

	static Val_desc vda[] = {
		{ FLG_ECF_ARMEMBER,	MSG_FLG_ECF_ARMEMBER },
		{ 0,			0 }
	};

	static const char *leading_str_arr[2];
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (flags_buf->buf), leading_str_arr };

	Word	type_idx;

	type_idx = flags & TYP_ECF_MASK;
	if (type_idx < TYP_ECF_NUM) {
		leading_str_arr[0] = MSG_ORIG(types[type_idx]);
		flags &= ~TYP_ECF_MASK;
	} else {
		leading_str_arr[0] = NULL;
	}

	conv_arg.buf = flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;

	(void) conv_expn_field(&conv_arg, vda, fmt_flags);

	return (conv_arg.buf);
}
