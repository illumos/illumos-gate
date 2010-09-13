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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/*
 * This file tests for 8 bytes alignment on all allocations.
 *
 * cc -O -o align align.c -lmtmalloc
 */

#define	N 100	/* big enough to hold results */

main(int argc, char ** argv)
{
	int i = 0;
	char *bar[N];

	while (i < 20) {
		bar[i] = malloc(1<<i);
		if ((uintptr_t)bar[i] & 7) {
			fprintf(stderr, "Address %p is not 8 byte aligned\n",
				bar[i]);
			fprintf(stderr, "Allocation size %d\n", 1<<i);
		}
		i++;
	}

	i = 0;
	while (i < 20) {
		free(bar[i]);
		i++;
	}
}
