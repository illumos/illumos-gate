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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <mcamd_api.h>

static struct mcproptostr {
	mcamd_propcode_t code;
	const char *name;
} _propstrings[] = {
	/*
	 * Common codes
	 */
	{ MCAMD_PROP_NUM, MCAMD_PROPSTR_NUM },
	{ MCAMD_PROP_SIZE, MCAMD_PROPSTR_SIZE },
	{ MCAMD_PROP_BASE_ADDR, MCAMD_PROPSTR_BASE_ADDR },
	/*
	 * Memory controller properties
	 */
	{ MCAMD_PROP_REV, MCAMD_PROPSTR_REV },
	{ MCAMD_PROP_LIM_ADDR, MCAMD_PROPSTR_LIM_ADDR },
	{ MCAMD_PROP_ILEN, MCAMD_PROPSTR_ILEN },
	{ MCAMD_PROP_ILSEL, MCAMD_PROPSTR_ILSEL },
	{ MCAMD_PROP_CSINTLVFCTR, MCAMD_PROPSTR_CSINTLVFCTR },
	{ MCAMD_PROP_ACCESS_WIDTH, MCAMD_PROPSTR_ACCESS_WIDTH },
	{ MCAMD_PROP_CSBANKMAPREG, MCAMD_PROPSTR_CSBANKMAPREG },
	{ MCAMD_PROP_BANKSWZL, MCAMD_PROPSTR_BANKSWZL },
	{ MCAMD_PROP_DRAMHOLE_SIZE, MCAMD_PROPSTR_DRAMHOLE_SIZE },
	{ MCAMD_PROP_MOD64MUX, MCAMD_PROPSTR_MOD64MUX },
	{ MCAMD_PROP_SPARECS, MCAMD_PROPSTR_SPARECS },
	{ MCAMD_PROP_BADCS, MCAMD_PROPSTR_BADCS },
	/*
	 * Chip-select properties
	 */
	{ MCAMD_PROP_MASK, MCAMD_PROPSTR_MASK },
	{ MCAMD_PROP_CSBE, MCAMD_PROPSTR_CSBE },
	{ MCAMD_PROP_SPARE, MCAMD_PROPSTR_SPARE },
	{ MCAMD_PROP_TESTFAIL, MCAMD_PROPSTR_TESTFAIL },
	{ MCAMD_PROP_CSDIMM1, MCAMD_PROPSTR_CSDIMM1 },
	{ MCAMD_PROP_CSDIMM2, MCAMD_PROPSTR_CSDIMM2 },
	{ MCAMD_PROP_DIMMRANK, MCAMD_PROPSTR_DIMMRANK },
};

static const int _nprop = sizeof (_propstrings) /
    sizeof (struct mcproptostr);

const char *
mcamd_get_propname(mcamd_propcode_t code)
{
	int i;

	for (i = 0; i < _nprop; i++) {
		if (_propstrings[i].code == code)
			return (_propstrings[i].name);
	}

	return (NULL);
}
