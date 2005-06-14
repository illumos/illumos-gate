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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/* Maximum number of digits in any integer representation */
#define	MAXDIGS 11

/* Maximum total number of digits in E format */
#if u3b || M32
#define	MAXECVT 17
#else
#define	MAXECVT 18
#endif

/* Maximum number of digits after decimal point in F format */
#define	MAXFCVT 60

/* Maximum significant figures in a floating-point number */
#define	MAXFSIG MAXECVT

/* Maximum number of characters in an exponent */
#if u3b || M32
#define	MAXESIZ 5
#else
#define	MAXESIZ 4
#endif

/* Maximum (positive) exponent */
#if u3b || M32
#define	MAXEXP 310
#else
#define	MAXEXP 40
#endif

/* Data type for flags */
typedef char bool;

/* Convert a digit character to the corresponding number */
#define	tonumber(x) ((x)-'0')

/* Convert a number between 0 and 9 to the corresponding digit */
#define	todigit(x) ((x)+'0')

/* Max and Min macros */
#define	max(a, b) ((a) > (b)? (a): (b))
#define	min(a, b) ((a) < (b)? (a): (b))
