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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_LIBAUDIO_IMPL_H
#define	_MULTIMEDIA_LIBAUDIO_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libaudio.h>
#include <archdep.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Useful defines
 *
 * CALLOC - allocate memory and clear it
 *		foo = CALLOC(15, char *);		-- alloc 15 ptrs
 *
 * MALLOC - allocate memory
 *		foo = MALLOC(struct foobar);		-- alloc 1 foobar
 *
 * REALLOC - re-allocate a larger amount of memory
 *		foo = REALLOC(foo, 10, struct foo);	-- extend to 10 foos
 *
 * FREE - de-allocate memory
 *
 * NOTE: These routines all operate on objects they can take the size of,
 *	 rather than byte counts.
 *
 *
 * XXX - the (long) in the following defines is used to make
 * XXX   lint shut up about pointer alignment problems.
 */
#define	MALLOC(type)	\
	(type *)(long)malloc(sizeof (type))
#define	CALLOC(number, type) \
	(type *)(long)calloc((unsigned)(number), sizeof (type))
#define	REALLOC(ptr, number, type) \
	(type *)(long)realloc((char *)(ptr), (unsigned)(number) * sizeof (type))
#define	FREE(ptr)	\
	(void) free((char *)(ptr))

/*
 * START_C_FUNC - declare this function with C linkage
 * END_C_FUNC - put at the end of the function
 */
#define	START_C_FUNC	extern "C" {
#define	END_C_FUNC	}

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_LIBAUDIO_IMPL_H */
