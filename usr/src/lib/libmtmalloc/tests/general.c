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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread.h>

/*
 * This file contains a general health check for the libmtmalloc.so.1 lib.
 * It creates NCPUS worth of threads and has eadch perform 1000000 random
 * small allocs and then free them.
 *
 * cc -O -o general general.c -lmtmalloc
 */
#define	N	1000000

void *be_thread(void *);

main(int argc, char ** argv)
{
	int i;
	thread_t tid[512];	/* We'll never have more than that! hah */

	i = sysconf(_SC_NPROCESSORS_CONF);
	srand(getpid());

	while (i)
		thr_create(NULL, 1<<23, be_thread, NULL, THR_BOUND, &tid[i--]);

	while (thr_join(NULL, NULL, NULL) == 0);

	exit(0);
}

/* ARGSUSED */
void *
be_thread(void * foo)
{
	int i = N;
	char *bar[N];

	while (i--)
		bar[i] = malloc(rand()%64);

	i = N;
	while (i--)
		free(bar[i]);
}
