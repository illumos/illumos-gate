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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <mcamd_api.h>

static const char *const _mcamd_proplist[] = {
	MCAMD_PROPSTR_NUM,
	MCAMD_PROPSTR_BASE_ADDR,
	MCAMD_PROPSTR_LIM_ADDR,
	MCAMD_PROPSTR_MASK,
	MCAMD_PROPSTR_DRAM_ILEN,
	MCAMD_PROPSTR_DRAM_ILSEL,
	MCAMD_PROPSTR_DRAM_HOLE,
	MCAMD_PROPSTR_DRAM_CONFIG,
	MCAMD_PROPSTR_ACCESS_WIDTH,
	MCAMD_PROPSTR_LODIMM,
	MCAMD_PROPSTR_UPDIMM,
	MCAMD_PROPSTR_CSBANKMAP,
	MCAMD_PROPSTR_SIZE,
	MCAMD_PROPSTR_CSBANK_INTLV,
	MCAMD_PROPSTR_CS0,
	MCAMD_PROPSTR_CS1,
	MCAMD_PROPSTR_CS2,
	MCAMD_PROPSTR_CS3,
	MCAMD_PROPSTR_REV,
	MCAMD_PROPSTR_DISABLED_CS,
};

static const int _mcamd_nprop = sizeof (_mcamd_proplist) /
    sizeof (_mcamd_proplist[0]);

const char *
mcamd_get_propname(uint_t code)
{
	if (code < _mcamd_nprop)
		return (_mcamd_proplist[code]);
	else
		return (NULL);
}
