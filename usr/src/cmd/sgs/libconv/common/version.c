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

/*
 * String conversion routine for version flag entries.
 */
#include	<stdio.h>
#include	"_conv.h"
#include	"version_msg.h"

#define	VERFLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_VER_FLG_WEAK_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_VER_FLG_BASE_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_VER_FLG_INFO_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_ver_flags_buf_t is large enough:
 *
 * VERFLAGSZ is the real minimum size of the buffer required by
 * conv_ver_flags(). However, Conv_ver_flags_buf_t uses CONV_VER_FLAGS_BUFSIZE
 * to set the buffer size. We do things this way because the definition of
 * VERFLAGSZ uses information that is not available in the environment of
 * other programs that include the conv.h header file.
 */
#if (CONV_VER_FLAGS_BUFSIZE != VERFLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE VERFLAGSZ
#include "report_bufsize.h"
#error "CONV_VER_FLAGS_BUFSIZE does not match VERFLAGSZ"
#endif

const char *
conv_ver_flags(Half flags, Conv_fmt_flags_t fmt_flags,
    Conv_ver_flags_buf_t *ver_flags_buf)
{
	static Val_desc vda[] = {
		{ VER_FLG_WEAK,		MSG_ORIG(MSG_VER_FLG_WEAK) },
		{ VER_FLG_BASE,		MSG_ORIG(MSG_VER_FLG_BASE) },
		{ VER_FLG_INFO,		MSG_ORIG(MSG_VER_FLG_INFO) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (ver_flags_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_NULL));

	conv_arg.buf = ver_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)ver_flags_buf->buf);
}


/*
 * Format a version index as contained in a VERSYM section
 *
 * entry:
 *	verndx - Version index to format
 *	gnuver - If True (non-zero), the version rules used by the
 *		GNU ld are assumed. If False (0), Solaris ld rules apply.
 */
const char *
conv_ver_index(Versym verndx, int gnuver, Conv_inv_buf_t *inv_buf)
{
	const char		*fmt;

	/* Special case versions starting at VER_NDX_LORESERVE */
	if (verndx == VER_NDX_ELIMINATE)
		return (MSG_ORIG(MSG_VERSYM_ELIMINATE));

	/*
	 * The GNU style of versioning uses the top bit of the
	 * 16-bit version index (0x8000) as a "hidden bit". A
	 * hidden symbol is supposed to be ignored by the linker.
	 */
	if (gnuver && (verndx & 0x8000)) {
		verndx &= ~0x8000;
		fmt = MSG_ORIG(MSG_VERSYM_GNUH_FMT);
	} else {
		fmt = MSG_ORIG(MSG_VERSYM_FMT);
	}

	/* format as numeric */
	(void) snprintf(inv_buf->buf, sizeof (inv_buf->buf),
	    fmt, EC_HALF(verndx));
	return (inv_buf->buf);
}
