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


/* sysinit loadable module */

#include <sys/types.h>

#define	V1	0x38d4419a
#define	V1_K1	0x7a5fd043
#define	V1_K2	0x65cb612e

static int32_t t[3] = { V1, V1_K1, V1_K2 };

extern ulong_t  _bdhs34;
extern char    *_hs1107;

#define	A	16807
#define	M	2147483647
#define	Q	127773
#define	R	2836

#define	x() if ((s = ((A*(s%Q)) - (R*(s/Q)))) <= 0) s += M

void
sysinit(void)
{
	char *cp;
	char d[10];
	int32_t s, v;
	int i;

	s = t[1];
	x();
	if (t[2] == s) {
		x();
		s %= 1000000000;
	}
	else
		s = 0;

	for (v = s, i = 0; i < 10; i++) {
		d[i] = v % 10;
		v /= 10;
		if (v == 0)
			break;
	}
	for (cp = _hs1107; i >= 0; i--)
		*cp++ = d[i] + '0';
	*cp = 0;
	_bdhs34 = (ulong_t)s + (ulong_t)&_bdhs34;
}
