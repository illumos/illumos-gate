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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* memory allocation functions */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern	char	*argv0;	/* command name (must be set in main function) */

char	*stralloc(char *s);
void	*mymalloc(size_t size);
void	*mycalloc(size_t nelem, size_t size);
void	*myrealloc(void *p, size_t size);
static void *alloctest(void *p);

/* allocate a string */

char *
stralloc(char *s)
{
	return (strcpy(mymalloc(strlen(s) + 1), s));
}

/* version of malloc that only returns if successful */

void *
mymalloc(size_t size)
{
	return (alloctest(malloc(size)));
}

/* version of calloc that only returns if successful */

void *
mycalloc(size_t nelem, size_t size)
{
	return (alloctest(calloc(nelem, size)));
}

/* version of realloc that only returns if successful */

void *
myrealloc(void *p, size_t size)
{
	return (alloctest(realloc(p, size)));
}

/* check for memory allocation failure */

static void *
alloctest(void *p)
{
	if (p == NULL) {
		(void) fprintf(stderr, "\n%s: out of storage\n", argv0);
		exit(1);
	}
	return (p);
}
