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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PRINT_H
#define	_PRINT_H

#include "file64.h"
#include <floatingpoint.h>
#include <thread.h>
#include <synch.h>
#include <stdio.h>
#include "stdiom.h"

#ifdef	__cplusplus
extern "C" {
#endif

extern ssize_t
_doprnt(const char *format, va_list in_args, FILE *iop);

extern ssize_t
_ndoprnt(const char *format, va_list in_args, FILE *iop, int flag);

extern ssize_t
_wndoprnt(const wchar_t *format, va_list in_args, FILE *iop, int flag);

extern void
__aconvert(double arg, int ndigits, int *exp, int *sign, char *buf);

extern void
__qaconvert(long double *arg, int ndigits, int *exp, int *sign, char *buf);

/* Maximum number of digits in any integer representation */
#define	MAXDIGS 11

/* Maximum number of digits in any long long representation */
#define	MAXLLDIGS 22

/* Maximum total number of digits in E format */
#define	MAXECVT (DECIMAL_STRING_LENGTH-1)

/* Maximum number of digits after decimal point in F format */
#define	MAXFCVT (DECIMAL_STRING_LENGTH-1)

/* Maximum significant figures in a floating-point number	*/
/* DECIMAL_STRING_LENGTH in floatingpoint.h is max buffer size	*/
#define	MAXFSIG (DECIMAL_STRING_LENGTH-1)

/* Maximum number of characters in an exponent */
#define	MAXESIZ 7		/* Max for quadruple precision */

/* Maximum (positive) exponent */
#define	MAXEXP 4950		/* Max for quadruple precision */

/* Number of hex digits in a fp type when normalized with a leading 1 */
#define	HEXFP_SINGLE_DIG	7
#define	HEXFP_DOUBLE_DIG	14
#define	HEXFP_EXTENDED_DIG	17
#define	HEXFP_QUAD_DIG		29

/* Data type for flags */
typedef char bool;

/* Convert a digit character to the corresponding number */
#define	tonumber(x) ((x)-'0')

/* Convert a number between 0 and 9 to the corresponding digit */
#define	todigit(x) ((x)+'0')

/* Max and Min macros */
#define	max(a, b) ((a) > (b)? (a): (b))
#define	min(a, b) ((a) < (b)? (a): (b))

/* Max neg. long long */
#define	HIBITLL	(1ULL << 63)

#ifdef	__cplusplus
}
#endif

#endif	/* _PRINT_H */
