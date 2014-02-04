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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

extern void __vcos(int, double *, int, double *, int);

#if !defined(LIBMVEC_SO_BUILD)
#if defined(ARCH_v8plusa) || defined(ARCH_v8plusb) || defined(ARCH_v9a) || defined(ARCH_v9b)
#define CHECK_ULTRA3
#endif
#endif	/* !defined(LIBMVEC_SO_BUILD) */

#ifdef CHECK_ULTRA3
#include <strings.h>
#define sysinfo _sysinfo
#include <sys/systeminfo.h>

#define BUFLEN	257

static int use_ultra3 = 0;

extern void __vcos_ultra3(int, double *, int, double *, int);
#endif

#pragma weak vcos_ = __vcos_

/* just invoke the serial function */
void
__vcos_(int *n, double *x, int *stridex, double *y, int *stridey)
{
#ifdef CHECK_ULTRA3
	int		u;
	char	buf[BUFLEN];

	u = use_ultra3;
	if (!u) {
		/* use __vcos_ultra3 on Cheetah (and ???) */
		if (sysinfo(SI_ISALIST, buf, BUFLEN) > 0 && !strncmp(buf, "sparcv9+vis2", 12))
			u = 3;
		else
			u = 1;
		use_ultra3 = u;
	}
	if (u & 2)
		__vcos_ultra3(*n, x, *stridex, y, *stridey);
	else
#endif
	__vcos(*n, x, *stridex, y, *stridey);
}
