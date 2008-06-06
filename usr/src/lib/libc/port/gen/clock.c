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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>
#include <sys/times.h>
#include <time.h>
#include <sys/param.h>	/* for HZ (clock frequency in Hz) */

#define	TIMES(B)	(B.tms_utime+B.tms_stime+B.tms_cutime+B.tms_cstime)


clock_t
clock(void)
{
	struct tms buffer;
	static int Hz = 0;
	static clock_t first;
	extern int gethz(void);		/* XXX should be in a header file! */

	if (times(&buffer) == (clock_t)-1)
		return ((clock_t)-1);
	if (Hz == 0) {
		if ((Hz = gethz()) == 0)
			Hz = HZ;
		first = TIMES(buffer);
	}

	return ((TIMES(buffer) - first) * (CLOCKS_PER_SEC/Hz));
}
