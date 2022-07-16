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
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 * Copyright 2022 Oxide Computer Company
 */

#pragma weak _getisax = getisax

#include "lint.h"
#include <sys/types.h>
#include <sys/auxv.h>

extern long ___getauxval(int type);

/*
 * Return the 'hwcap' vector of bits in the AT_SUN_HWCAP and AT_SUN_HWCAP2 aux
 * vector entries. Therefore there are two words of bits here.
 *
 * As a convenience, the routine returns the maximum number of array alements
 * that may contain non-zero values.
 */
uint_t
getisax(uint32_t *array, uint_t n)
{
	int i;
	static uint32_t auxv_hwcap;
	static uint32_t auxv_hwcap_2;
	static uint32_t auxv_hwcap_3;

	if (auxv_hwcap == 0) {
		auxv_hwcap = (uint32_t)___getauxval(AT_SUN_HWCAP);
		auxv_hwcap_2 = (uint32_t)___getauxval(AT_SUN_HWCAP2);
		auxv_hwcap_3 = (uint32_t)___getauxval(AT_SUN_HWCAP3);
	}

	if (n > 0) {
		if (n >= 1)
			array[0] = auxv_hwcap;
		if (n >= 2)
			array[1] = auxv_hwcap_2;
		if (n >= 3)
			array[2] = auxv_hwcap_3;
		for (i = 3; i < n; i++)
			array[i] = 0;
	}

	if (auxv_hwcap == 0) {
		return (0);
	}

	return (n >= 3 ? 3 : n);
}
