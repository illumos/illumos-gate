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
 * String conversion routine for hardware capabilities types.
 */
#include	<strings.h>
#include	<stdio.h>
#include	<sys/machelf.h>
#include	<elfcap.h>
#include	"_conv.h"
#include	"cap_msg.h"

static int
conv_cap_1(Xword val, char *str, size_t len, Half mach,
    int (*fptr)(uint64_t, char *, size_t, int, ushort_t))
{
	size_t	_len;

	_len = sprintf(str, MSG_ORIG(MSG_GBL_OSQBRKT), EC_XWORD(val));

	len -= _len;
	str += _len;

	if ((*fptr)(val, str, len, CAP_FMT_DBLSPACE, mach) != 0)
		return (0);

	_len = strlen(str);
	if ((len - _len) >= MSG_GBL_CSQBRKT_SIZE) {
		str += _len;
		(void) strcpy(str, MSG_ORIG(MSG_GBL_CSQBRKT));
	}
	return (1);
}

/*
 * Establish a buffer size based on the maximum number of hardware capabilities
 * that exist.  See common/elfcap.
 */
#define	HW1SZ	200

const char *
conv_cap_val_hw1(Xword val, Half mach)
{
	static char	string[HW1SZ];

	if (val == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	if (conv_cap_1(val, string, HW1SZ, mach, hwcap_1_val2str) == 0)
		return (conv_invalid_val(string, HW1SZ, val, 0));
	return ((const char *)string);
}

/*
 * Establish a buffer size based on the maximum number of software capabilities
 * that exist.  See common/elfcap.
 */
#define	SF1SZ	50

const char *
conv_cap_val_sf1(Xword val, Half mach)
{
	static char	string[SF1SZ];

	if (val == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	if (conv_cap_1(val, string, SF1SZ, mach, sfcap_1_val2str) == 0)
		return (conv_invalid_val(string, SF1SZ, val, 0));
	return ((const char *)string);
}

const char *
conv_cap_tag(Xword tag)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	tags[] = {
		MSG_CA_SUNW_NULL,	MSG_CA_SUNW_HW_1,
		MSG_CA_SUNW_SF_1
	};

	if (tag <= CA_SUNW_SF_1)
		return (MSG_ORIG(tags[tag]));
	else
		return (conv_invalid_val(string, CONV_INV_STRSIZE, tag, 0));
}

const char *
conv_cap_val(Xword tag, Xword val, Half mach)
{
	static char	string[CONV_INV_STRSIZE];

	if (tag == CA_SUNW_HW_1)
		return (conv_cap_val_hw1(val, mach));
	else if (tag == CA_SUNW_SF_1)
		return (conv_cap_val_sf1(val, mach));
	else
		return (conv_invalid_val(string, CONV_INV_STRSIZE, val, 0));
}
