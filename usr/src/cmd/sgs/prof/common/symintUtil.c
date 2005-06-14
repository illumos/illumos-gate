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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
*	file: symintUtil.c
*	desc: utilities for symint code
*	date: 11/08/88
*/
#include <stdio.h>
#include <sys/types.h>
#include "debug.h"

/*
*	_Malloc and _Realloc are used to monitor the allocation
*	of memory.  If failure occurs, we detect it and exit.
*/

void *
_Malloc(item_count, item_size)
uint item_count;
uint item_size;
{
	char *malloc();
	register void *p;

	if ((p = (void *) calloc(item_count, item_size)) == NULL) {
		DEBUG_EXP(printf("- size=%d, count=%d\n", item_size, item_count));
		_err_exit("calloc: Out of space");
	}
	return (p);
}

void *
_Realloc(pointer, size)
void *pointer;
uint size;
{
	char *realloc();
	register void *p;

	if ((p = (void *) realloc(pointer, size)) == NULL) {
		_err_exit("realloc: Out of space");
	}
	return (p);
}

