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
 * String conversion routines for section attributes.
 */
#include	<string.h>
#include	<sys/param.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<_conv.h>
#include	<sections_msg.h>



const char *
conv_sec_flags(uchar_t osabi, Half mach, Xword flags,
    Conv_fmt_flags_t fmt_flags, Conv_sec_flags_buf_t *sec_flags_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (sec_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	CONV_XWORD_64TEST(flags, fmt_flags, &sec_flags_buf->inv_buf);

	conv_arg.buf = sec_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field2(&conv_arg, osabi, mach,
	    conv_sec_flags_strings(fmt_flags), fmt_flags);

	return ((const char *)sec_flags_buf->buf);
}

const char *
conv_sec_linkinfo(Word info, Xword flags, Conv_inv_buf_t *inv_buf)
{
	if (flags & ALL_SHF_ORDER) {
		if (info == SHN_BEFORE)
			return (MSG_ORIG(MSG_SHN_BEFORE));
		else if (info == SHN_AFTER)
			return (MSG_ORIG(MSG_SHN_AFTER));
	}

	CONV_XWORD_64TEST(flags, 0, inv_buf);
	(void) conv_invalid_val(inv_buf, info, CONV_FMT_DECIMAL);
	return ((const char *)inv_buf->buf);
}
