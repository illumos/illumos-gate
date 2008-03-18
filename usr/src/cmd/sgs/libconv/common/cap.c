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
 * String conversion routine for hardware capabilities types.
 */
#include	<strings.h>
#include	<stdio.h>
#include	<_machelf.h>
#include	<elfcap.h>
#include	"cap_msg.h"
#include	"_conv.h"

static int
conv_cap_1(Xword val, char *str, size_t len, Half mach,
    Conv_fmt_flags_t fmt_flags, elfcap_to_str_func_t *fptr)
{
	size_t	_len;
	int do_bkt = (fmt_flags & CONV_FMT_NOBKT) == 0;

	/*
	 * Note that for the purposes of this routine, I consider
	 * CONV_FMT_NOBKT to mean no brackets, or anything that
	 * is placed outside of them. We also drop the hex version
	 * of the flags that are put in front of the opening bracket.
	 */
	if (do_bkt) {
		_len = sprintf(str, MSG_ORIG(MSG_GBL_OSQBRKT), EC_XWORD(val));

		len -= _len;
		str += _len;
	}

	if ((*fptr)(ELFCAP_STYLE_UC, val, str, len, ELFCAP_FMT_SNGSPACE,
	    mach) != 0)
		return (0);

	if (do_bkt) {
		_len = strlen(str);
		if ((len - _len) >= MSG_GBL_CSQBRKT_SIZE) {
			str += _len;
			(void) strcpy(str, MSG_ORIG(MSG_GBL_CSQBRKT));
		}
	}
	return (1);
}

const char *
conv_cap_val_hw1(Xword val, Half mach, Conv_fmt_flags_t fmt_flags,
    Conv_cap_val_hw1_buf_t *cap_val_hw1_buf)
{
	if (val == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	if (conv_cap_1(val, cap_val_hw1_buf->buf, sizeof (cap_val_hw1_buf->buf),
	    mach, fmt_flags, elfcap_hw1_to_str) == 0)
		return (conv_invalid_val(&cap_val_hw1_buf->inv_buf, val, 0));
	return ((const char *)cap_val_hw1_buf->buf);
}

const char *
conv_cap_val_sf1(Xword val, Half mach, Conv_fmt_flags_t fmt_flags,
    Conv_cap_val_sf1_buf_t *cap_val_sf1_buf)
{
	if (val == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	if (conv_cap_1(val, cap_val_sf1_buf->buf, sizeof (cap_val_sf1_buf->buf),
	    mach, fmt_flags, elfcap_sf1_to_str) == 0)
		return (conv_invalid_val(&cap_val_sf1_buf->inv_buf, val, 0));
	return ((const char *)cap_val_sf1_buf->buf);
}

const char *
conv_cap_tag(Xword tag, Conv_inv_buf_t *inv_buf)
{
	static const Msg	tags[] = {
		MSG_CA_SUNW_NULL,	MSG_CA_SUNW_HW_1,
		MSG_CA_SUNW_SF_1
	};

	if (tag <= CA_SUNW_SF_1)
		return (MSG_ORIG(tags[tag]));
	else
		return (conv_invalid_val(inv_buf, tag, 0));
}

const char *
conv_cap_val(Xword tag, Xword val, Half mach, Conv_cap_val_buf_t *cap_val_buf)
{
	if (tag == CA_SUNW_HW_1)
		return (conv_cap_val_hw1(val, mach, 0,
		    &cap_val_buf->cap_val_hw1_buf));
	else if (tag == CA_SUNW_SF_1)
		return (conv_cap_val_sf1(val, mach, 0,
		    &cap_val_buf->cap_val_sf1_buf));
	else
		return (conv_invalid_val(&cap_val_buf->inv_buf, val, 0));
}
