/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This is meant for scripts to determine what kind of hardware support we
 * actually have for output files and related. Currently the tests don't
 * supports CPUs that somehow have xsave support, but don't have AVX support and
 * thus ymm registers. xsu_hwsupport() requires that we have the XSAVE feature
 * and only returns XMM if it doesn't exist, hence why this is considered a
 * failure below.
 */

#include <stdio.h>
#include <stdlib.h>
#include "xsave_util.h"

int
main(void)
{
	uint32_t hwsup = xsu_hwsupport();

	switch (hwsup) {
	case XSU_YMM:
		(void) printf("ymm\n");
		break;
	case XSU_ZMM:
		(void) printf("zmm\n");
		break;
	default:
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}
