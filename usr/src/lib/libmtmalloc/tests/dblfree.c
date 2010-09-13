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
#include "mtmalloc.h"

/*
 * test double free. The first double free should be fine.
 * the next double free should result in a core dump.
 *
 * cc -O -o dblfree dblfree.c -I../common -lmtmalloc
 */

main(int argc, char ** argv)
{
	char *foo;

	foo = malloc(10);
	free(foo);

	mallocctl(MTDOUBLEFREE, 1);

	printf("Double free coming up\n");
	printf("This should NOT dump core.\n");
	free(foo);

	foo = malloc(10);
	free(foo);

	mallocctl(MTDOUBLEFREE, 0);

	printf("Double free coming up\n");
	printf("This should dump core.\n");

	free(foo);
}
