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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * String conversion routine for .dynamic tag entries.
 */
#include	<stdio.h>
#include	<string.h>
#include	<sys/elf_SPARC.h>
#include	"rtld.h"
#include	"_conv.h"
#include	"dynamic_msg.h"



const char *
conv_dyn_posflag1(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_posflag1_buf_t *dyn_posflag1_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_posflag1_buf->buf) };
	static CONV_EXPN_FIELD_ARG conv_arg_alt = {
	    NULL, sizeof (dyn_posflag1_buf->buf), NULL, 0, 0,
	    MSG_ORIG(MSG_STR_EMPTY), NULL, MSG_ORIG(MSG_STR_EMPTY) };

	CONV_EXPN_FIELD_ARG	*arg;

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	CONV_XWORD_64TEST(flags, fmt_flags, &dyn_posflag1_buf->inv_buf);

	arg = (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP) ?
	    &conv_arg_alt : &conv_arg;
	arg->buf = dyn_posflag1_buf->buf;
	arg->oflags = arg->rflags = flags;
	(void) conv_expn_field(arg, conv_dyn_posflag1_strings(fmt_flags),
	    fmt_flags);

	return ((const char *)dyn_posflag1_buf);
}

const char *
conv_dyn_flag(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_flag_buf_t *dyn_flag_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_flag_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	CONV_XWORD_64TEST(flags, fmt_flags, &dyn_flag_buf->inv_buf);

	conv_arg.buf = dyn_flag_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		conv_arg.prefix = conv_arg.suffix = NULL;
	}
	(void) conv_expn_field(&conv_arg, conv_dyn_flag_strings(fmt_flags),
	    fmt_flags);

	return ((const char *)dyn_flag_buf->buf);
}

const char *
conv_dyn_flag1(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_flag1_buf_t *dyn_flag1_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_flag1_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	CONV_XWORD_64TEST(flags, fmt_flags, &dyn_flag1_buf->inv_buf);

	conv_arg.oflags = conv_arg.rflags = flags;
	conv_arg.buf = dyn_flag1_buf->buf;
	(void) conv_expn_field(&conv_arg, conv_dyn_flag1_strings(fmt_flags),
	    fmt_flags);

	return ((const char *)dyn_flag1_buf->buf);
}

const char *
conv_dyn_feature1(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_dyn_feature1_buf_t *dyn_feature1_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (dyn_feature1_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	CONV_XWORD_64TEST(flags, fmt_flags, &dyn_feature1_buf->inv_buf);

	conv_arg.buf = dyn_feature1_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_DUMP) {
		conv_arg.prefix = conv_arg.suffix = MSG_ORIG(MSG_STR_EMPTY);
	} else {
		conv_arg.prefix = conv_arg.suffix = NULL;
	}
	(void) conv_expn_field(&conv_arg,
	    conv_dyn_feature1_strings(fmt_flags), fmt_flags);

	return ((const char *)dyn_feature1_buf->buf);
}

const char *
conv_dyn_tag(Xword tag, uchar_t osabi, Half mach, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	CONV_XWORD_64TEST(tag, fmt_flags, inv_buf);
	return (conv_map_ds(osabi, mach, tag,
	    conv_dyn_tag_strings(osabi, mach, fmt_flags), fmt_flags, inv_buf));
}
