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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	SUCCESS 1
#define	FAILURE 0

/* Error class flags */
#define	Err_general 0
#define	Err_Syntax 1
#define	Err_Static 2
#define	Err_Semantic 3
#define	Err_Intern 4
#define	Err_Usage 5


#define	_malloc(type, n) \
(type *)my_malloc(sizeof (type)*(n), __FILE__, __LINE__)

#define	_calloc(type, n) \
(type *)my_calloc((n), sizeof (type), __FILE__, __LINE__)

#define	_realloc(ptr, type, n) \
(type *)my_realloc(ptr, sizeof (type)*(n), __FILE__, __LINE__)


#define	max(a, b)  ((a) > (b) ? (a) : (b))

void *my_malloc(unsigned size, char *file, int line);
void *my_calloc(unsigned n, unsigned size, char *file, int line);
void *my_realloc(void *ptr, unsigned size, char *file, int line);
void Error(char *fmt, ...);
static void _Internal(char *sourcefile, int sourceline, char *fmt);

extern int lineNumber;
extern int lexdebug;
extern int ErrorCount;

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_H */
