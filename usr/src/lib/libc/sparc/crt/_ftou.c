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
#include <sys/types.h>
#include "libc.h"

unsigned
__dtou(double d)
{
	/* Convert double to unsigned. */

	int id;

	/*
	 * id = d is correct if 0 <= d < 2**31, and good enough if d is NaN
	 * or d < 0 or d >= 2**32.  Otherwise, since the result (int)d of
	 * converting 2**31 <= d < 2**32 is unknown, adjust d before the
	 * conversion.
	 */

	if (d >= 2147483648.0)
		id = 0x80000000 | (int)(d - 2147483648.0);
	else
		id = (int)d;
	return ((unsigned)id);
}

unsigned
__ftou(float d)
{
	/* Convert float to unsigned. */

	int id;
	/*
	 * id = d is correct if 0 <= d < 2**31, and good enough if d is NaN
	 * or d < 0 or d >= 2**32.  Otherwise, since the result (int)d of
	 * converting 2**31 <= d < 2**32 is unknown, adjust d before the
	 * conversion.
	 */

	if (d >= 2147483648.0)
		id = 0x80000000 | (int)(d - 2147483648.0);
	else
		id = (int)d;
	return ((unsigned)id);
}
