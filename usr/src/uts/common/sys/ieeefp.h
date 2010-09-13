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

#ifndef _SYS_IEEEFP_H
#define	_SYS_IEEEFP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.0 1.6	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sun types for IEEE floating point.
 */

#if defined(__sparc)

enum fp_direction_type {	/* rounding direction */
	fp_nearest	= 0,
	fp_tozero	= 1,
	fp_positive	= 2,
	fp_negative	= 3
};

enum fp_precision_type {	/* extended rounding precision */
	fp_extended	= 0,
	fp_single	= 1,
	fp_double	= 2,
	fp_precision_3	= 3
};

enum fp_exception_type {	/* exceptions according to bit number */
	fp_inexact	= 0,
	fp_division	= 1,
	fp_underflow	= 2,
	fp_overflow	= 3,
	fp_invalid	= 4
};

enum fp_trap_enable_type {	/* trap enable bits according to bit number */
	fp_trap_inexact	= 0,
	fp_trap_division	= 1,
	fp_trap_underflow	= 2,
	fp_trap_overflow	= 3,
	fp_trap_invalid	= 4
};

#elif defined(__i386) || defined(__amd64)

enum fp_direction_type {	/* rounding direction */
	fp_nearest	= 0,
	fp_negative	= 1,
	fp_positive	= 2,
	fp_tozero	= 3
};

enum fp_precision_type {	/* extended rounding precision */
	fp_single	= 0,
	fp_precision_3	= 1,
	fp_double	= 2,
	fp_extended	= 3
};

enum fp_exception_type {	/* exceptions according to bit number */
	fp_invalid	= 0,
	fp_denormalized	= 1,
	fp_division	= 2,
	fp_overflow	= 3,
	fp_underflow	= 4,
	fp_inexact	= 5
};

enum fp_trap_enable_type {	/* trap enable bits according to bit number */
	fp_trap_invalid	= 0,
	fp_trap_denormalized	= 1,
	fp_trap_division	= 2,
	fp_trap_overflow	= 3,
	fp_trap_underflow	= 4,
	fp_trap_inexact	= 5
};

#endif	/* __i386 || __amd64 */

enum fp_class_type {		/* floating-point classes */
	fp_zero		= 0,
	fp_subnormal	= 1,
	fp_normal	= 2,
	fp_infinity   	= 3,
	fp_quiet	= 4,
	fp_signaling	= 5
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IEEEFP_H */
