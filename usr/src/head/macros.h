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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_MACROS_H
#define	_MACROS_H

#include <sys/types.h>
#include <sys/stat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	numeric() is useful in while's, if's, etc., but don't use *p++
 *	max() and min() depend on the types of the operands
 *	abs() is absolute value
 */
#define	numeric(c)		((c) >= '0' && (c) <= '9')
#define	max(a, b) 		((a) < (b) ? (b) : (a))
#define	min(a, b) 		((a) > (b) ? (b) : (a))
#define	abs(x)			((x) >= 0 ? (x) : -(x))

#define	compare(str1, str2)	strcmp((str1), (str2))
#define	equal(str1, str2)	(strcmp((str1), (str2)) == 0)
#define	length(str)		strlen(str)
#define	size(str)		(strlen(str) + 1)

/*
 *	The global variable Statbuf is available for use as a stat(II)
 *	structure.  Note that "stat.h" is included here and should
 *	not be included elsewhere.
 *	Exists(file) returns 0 if the file does not exist;
 *	the flags word if it does (the flags word is always non-zero).
 */

extern struct stat Statbuf;
#define	exists(file)		(stat(file, &Statbuf) < 0 ? 0 : Statbuf.st_mode)

/*
 *	SAVE() and RSTR() use local data in nested blocks.
 *	Make sure that they nest cleanly.
 */
#define	SAVE(name, place)	{ int place = name;
#define	RSTR(name, place)	name = place; }

/*
 *	Use: DEBUG(sum,d) which becomes fprintf(stderr,"sum = %d\n",sum)
 */
#define	DEBUG(var, type)	fprintf(stderr, #var "= %" #type "\n", var)

/*
 *	Use of ERRABORT() will cause libS.a internal
 *	errors to cause aborts
 */
#define	ERRABORT()	_error() { abort(); }

/*
 *	Use of USXALLOC() is required to force all calls to alloc()
 *	(e.g., from libS.a) to call xalloc().
 */
#define	NONBLANK(p)	while (*(p) == ' ' || *(p) == '\t') (p)++

/*
 *	A global null string.
 */
extern char	Null[1];

/*
 *	A global error message string.
 */
extern char	Error[128];

#ifdef	__cplusplus
}
#endif

#endif	/* _MACROS_H */
