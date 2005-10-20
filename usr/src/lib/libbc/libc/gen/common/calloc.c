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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <malloc.h>

/*
 * calloc - allocate and clear memory block
 */
#define CHARPERINT (sizeof(int)/sizeof(char))

#ifdef	S5EMUL
#define	ptr_t	void*
#define	free_t	void
#define	free_return(x)	(x)
#else
#define	ptr_t	char*
#define	free_t	int
#define	free_return(x)	return (x)
#endif

ptr_t
calloc(unsigned num, unsigned size)
{
	ptr_t mp;
	ptr_t	malloc();

	num *= size;
	mp = malloc(num);
	if (mp == NULL)
		return(NULL);
	bzero(mp, num);
	return ((ptr_t)(mp));
}

free_t
cfree(ptr_t p, unsigned num, unsigned size)
{
	free_return(free(p));
}
