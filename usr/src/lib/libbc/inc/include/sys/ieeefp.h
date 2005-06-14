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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 */

/*
 * Definitions for constants and types for IEEE floating point.
 */

#ifndef _sys_ieeefp_h
#define _sys_ieeefp_h


/*	Sun TYPES for IEEE floating point.	*/

#ifdef sparc
enum fp_direction_type 		/* rounding direction */
	{
	fp_nearest	= 0,
	fp_tozero	= 1,
	fp_positive	= 2,
	fp_negative	= 3
	} ;
#endif
#ifdef i386
enum fp_direction_type 		/* rounding direction */
	{
	fp_nearest	= 0,
	fp_negative	= 1,
	fp_positive	= 2,
	fp_tozero	= 3
	} ;
#endif
#ifdef mc68000
enum fp_direction_type 		/* rounding direction */
	{
	fp_nearest	= 0,
	fp_tozero	= 1,
	fp_negative	= 2,
	fp_positive	= 3
	} ;
#endif

#ifdef i386
enum fp_precision_type		/* extended rounding precision */
	{
	fp_single	= 0,
	fp_precision_3	= 1,
	fp_double	= 2,
	fp_extended	= 3
	} ;
#else
enum fp_precision_type		/* extended rounding precision */
	{
	fp_extended	= 0,
	fp_single	= 1,
	fp_double	= 2,
	fp_precision_3	= 3
	} ;
#endif

#ifdef i386
enum fp_exception_type		/* exceptions according to bit number */
	{
	fp_invalid	= 0,
	fp_denormalized	= 1,
	fp_division	= 2,
	fp_overflow	= 3,
	fp_underflow	= 4,
	fp_inexact	= 5
	} ;
#else
enum fp_exception_type		/* exceptions according to bit number */
	{
	fp_inexact	= 0,
	fp_division	= 1,
	fp_underflow	= 2,
	fp_overflow	= 3,
	fp_invalid	= 4
	} ;
#endif

enum fp_class_type		/* floating-point classes */
	{
	fp_zero		= 0,
	fp_subnormal	= 1,
	fp_normal	= 2,
	fp_infinity   	= 3,
	fp_quiet	= 4,
	fp_signaling	= 5
	} ;

#endif /*!_sys_ieeefp_h*/
