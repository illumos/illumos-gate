/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routine for hardware capabilities types.
 */
#include	<strings.h>
#include	<stdio.h>
#include	<limits.h>
#include	<sys/machelf.h>
#include	<elfcap.h>
#include	"_conv.h"
#include	"cap_msg.h"

void
conv_cap_1_str(uint64_t val, char *str, size_t len, ushort_t mach,
    int (*fptr)(uint64_t, char *, size_t, int, ushort_t))
{
	size_t	_len;

	_len = sprintf(str, MSG_ORIG(MSG_GBL_OSQBRKT), EC_XWORD(val));

	len -= _len;
	str += _len;

	if ((*fptr)(val, str, len, CAP_FMT_DBLSPACE, mach) == 0) {
		_len = strlen(str);

		if ((len - _len) >= MSG_GBL_CSQBRKT_SIZE) {
			str += _len;
			(void) strcpy(str, MSG_ORIG(MSG_GBL_CSQBRKT));
		}
	}
}

#define	HW1SZ	100

const char *
conv_hwcap_1_str(uint64_t val, ushort_t mach)
{
	static char	string[HW1SZ] = { '\0' };

	if (val == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_cap_1_str(val, string, HW1SZ, mach, hwcap_1_val2str);
	return ((const char *)string);
}

#define	SF1SZ	40

const char *
conv_sfcap_1_str(uint64_t val, ushort_t mach)
{
	static char	string[SF1SZ] = { '\0' };

	if (val == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_cap_1_str(val, string, SF1SZ, mach, sfcap_1_val2str);
	return ((const char *)string);
}

static const Msg cap_tags[] = {
	MSG_CA_SUNW_NULL,	MSG_CA_SUNW_HW_1,	MSG_CA_SUNW_SF_1
};

const char *
conv_captag_str(uint64_t tag)
{
	static char	string[STRSIZE] = { '\0' };

	if (tag <= CA_SUNW_SF_1)
		return (MSG_ORIG(cap_tags[tag]));
	else
		return (conv_invalid_str(string, STRSIZE, tag, 0));
}

const char *
conv_capval_str(uint64_t tag, uint64_t val, ushort_t mach)
{
	static char	string[STRSIZE] = { '\0' };

	if (tag == CA_SUNW_HW_1)
		return (conv_hwcap_1_str(val, mach));
	else if (tag == CA_SUNW_SF_1)
		return (conv_sfcap_1_str(val, mach));
	else
		return (conv_invalid_str(string, STRSIZE, val, 0));
}
