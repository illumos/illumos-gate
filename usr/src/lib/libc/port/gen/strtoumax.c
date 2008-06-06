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

#include "lint.h"
#include <inttypes.h>
#include <sys/types.h>
#include <stdlib.h>

/*
 * Added for SUSv3 standard
 */

uintmax_t
strtoumax(const char *nptr, char **endptr, int base)
{
	return ((uintmax_t)strtoull(nptr, endptr, base));
}

#if !defined(_LP64)

/*
 * 32-bit shadow function of strtoumax.
 * When using the c89 compiler the largest int is 32-bits hence
 * this function.  The pragma redefine_extname in inttypes.h selects
 * the proper routine at compile time for the user application.
 * NOTE: this function is only available in the 32-bit library.
 */

uint32_t
_strtoumax_c89(const char *nptr, char **endptr, int base)
{
	return ((uint32_t)strtoul(nptr, endptr, base));
}
#endif
