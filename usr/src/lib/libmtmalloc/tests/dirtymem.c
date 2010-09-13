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
#include <unistd.h>
#include <sys/types.h>
#include "mtmalloc.h"

/*
 * This file tests for reference after free
 *
 * cc -O -o dirtymem dirtymem.c -lmtmalloc -I../common
 */

struct a_struct {
	int a;
	char *b;
	double c;
} struct_o_death;


main(int argc, char ** argv)
{
	struct a_struct *foo, *leak;
	int ncpus = sysconf(_SC_NPROCESSORS_CONF);

	mallocctl(MTDEBUGPATTERN, 1);
	foo = (struct a_struct *)malloc(sizeof (struct_o_death));

	free(foo);
	foo->a = 4;

	/*
	 * We have to make sure we allocate from the same pool
	 * as the last time. Turn the rotor with malloc until
	 * we get back to where we started.
	 */
	while (ncpus-- > 1)
		leak = malloc(sizeof (struct_o_death));

	fprintf(stderr, "malloc struct again\n");
	fprintf(stderr, "we should dump core\n");
	foo = malloc(sizeof (struct_o_death));

	exit(0);
}
