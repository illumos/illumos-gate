/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _XPG6_H
#define	_XPG6_H

/*
 * The bits in lib/libc/inc/xpg6.h fpgroup may use as per PSARC/2003/486.
 */

/*
 * If set, math library entry points present in SUSv2 deal with exceptional
 * cases as per SUSv3 spec where math_errhandling is set to MATH_ERREXCEPT;
 * otherwise they behave as per SUSv2 spec.
 */
#define	_C99SUSv3_math_errexcept		0x00000400
/*
 * If set, pow(+/-1,+/-Inf) & pow(1,NaN) return 1; otherwise NaN is returned.
 * Analogous comment applies to powf and powl.
 */
#define	_C99SUSv3_pow_treats_Inf_as_an_even_int	0x00000080
/*
 * If set, logb(subnormal) returns (double) ilogb(subnormal); otherwise
 * logb(subnormal) returns logb(DBL_MIN).  Analogous comment applies to
 * logbf and logbl.
 */
#define	_C99SUSv3_logb_subnormal_is_like_ilogb	0x00000040
/*
 * If set, ilogb(0/+Inf/-Inf/NaN) raises FE_INVALID as per SUSv3; otherwise
 * no exception is raised.  Analogous comment applies to ilogbf and ilogbl.
 */
#define	_C99SUSv3_ilogb_0InfNaN_raises_invalid	0x00000020

/*
 * __xpg6 = _C99SUSv3_mode_OFF disables C99/SUSv3 standards conformance mode.
 */
#define	_C99SUSv3_mode_OFF	0xFFFF0000

#if !defined(_ASM)
extern unsigned int __xpg6;
#endif

#endif /* _XPG6_H */
