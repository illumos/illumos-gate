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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/feature_tests.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <zone.h>

/*
 * Common routines for ptools.
 */

int
proc_snprintf(char *_RESTRICT_KYWD s, size_t n,
    const char *_RESTRICT_KYWD fmt, ...)
{
	static boolean_t ptools_zroot_valid = B_FALSE;
	static const char *ptools_zroot = NULL;
	va_list args;
	int ret, nret = 0;

	if (ptools_zroot_valid == B_FALSE) {
		ptools_zroot_valid = B_TRUE;
		ptools_zroot = zone_get_nroot();
	}

	if (ptools_zroot != NULL) {
		nret = snprintf(s, n, "%s", ptools_zroot);
		if (nret > n)
			return (nret);
	}
	va_start(args, fmt);
	ret = vsnprintf(s + nret, n - nret, fmt, args);
	va_end(args);

	return (ret + nret);
}
