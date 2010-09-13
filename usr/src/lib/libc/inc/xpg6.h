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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _XPG6_H
#define	_XPG6_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is an OS/Net Consolidation PRIVATE header.
 */

/*
 * __xpg6 (C99/SUSv3) was first introduced in Solaris 10.
 *
 * C99/SUSv3 behavior control bits for __xpg6 variable defined
 * in port/gen/xpg6.c.
 * Use these with extreme care.
 *
 * Please follow these basic rules for using these bits and
 * don't convolute their meaning.
 *
 * The basic idea here is the upper 16 bits (default_off)
 * enable/disable existing Solaris behaviors that conflict with
 * the C99 or SUSv3 standards.  When these bits are on you
 * are restoring an existing Solaris behavior and no longer
 * in strict C99/SUSv3 conformance mode.
 *
 * The lower 16 bits (default_on) are C99/SUSv3 behaviors
 * which are strictly conforming behaviors as far as the
 * C99/SUSv3 standards are concerned.  When these bits are on
 * you are in C99/SUSv3 conforming mode.  When these bits are off
 * you have turned off C99/SUSv3 conforming mode and are using
 * previous Solaris behavior.
 *
 * _C99SUSv3_mode_ON and _C99SUSv3_mode_OFF are two meta-definitions
 * which are the most likely modes to run Solaris in.
 * However, this frame work allows for other possible behaviors.
 *
 * The default mode of libc is _C99SUSv3_mode_OFF.
 * A C99/SUSv3 conforming application should be compiled
 * with the XPG6 standards conforming C compiler utility (c99) which
 * adds an object file that contains an alternate definition
 * for __xpg6 (_C99SUSv3_mode_ON) thus enabling C99/SUSv3 standards
 * conforming mode.
 */

#define	_C99SUSv3_default_off_reserved15	0x80000000
#define	_C99SUSv3_default_off_reserved14	0x40000000
#define	_C99SUSv3_default_off_reserved13	0x20000000
#define	_C99SUSv3_default_off_reserved12	0x10000000
#define	_C99SUSv3_default_off_reserved11	0x08000000
#define	_C99SUSv3_default_off_reserved10	0x04000000
#define	_C99SUSv3_default_off_reserved09	0x02000000
#define	_C99SUSv3_default_off_reserved08	0x01000000
#define	_C99SUSv3_default_off_reserved07	0x00800000
#define	_C99SUSv3_default_off_reserved06	0x00400000
#define	_C99SUSv3_default_off_reserved05	0x00200000
#define	_C99SUSv3_default_off_reserved04	0x00100000
#define	_C99SUSv3_default_off_reserved03	0x00080000
#define	_C99SUSv3_default_off_reserved02	0x00040000
#define	_C99SUSv3_default_off_reserved01	0x00020000
/*
 * If set then %f & %F print Inf/NaN;
 *	  else print inf/nan & INF/NAN, respectively.
 */
#define	_C99SUSv3_mixed_case_Inf_and_NaN	0x00010000

#define	_C99SUSv3_default_on_reserved15		0x00008000
#define	_C99SUSv3_default_on_reserved14		0x00004000
#define	_C99SUSv3_default_on_reserved13		0x00002000
#define	_C99SUSv3_default_on_reserved12		0x00001000
#define	_C99SUSv3_default_on_reserved11		0x00000800
/*
 * If set, math library entry points present in SUSv2 deal with exceptional
 * cases as per SUSv3 spec where math_errhandling is set to MATH_ERREXCEPT;
 * otherwise they behave as per SUSv2 spec.
 */
#define	_C99SUSv3_math_errexcept		0x00000400
/*
 * If set, when filename is a null pointer, freopen(NULL, mode, ...) will
 * attempt to change the mode of the stream to that specified by mode, as if
 * the name of the file currently associated with the stream had been used;
 * otherwise freopen(NULL, ...) will fail.
 */
#define	_C99SUSv3_freopen_NULL_filename		0x00000200
/*
 * If set,
 *	- strfmon() uses int_* members for %i
 *	- strfmon() handles the case n_sep_by_space == 2 as SUSv3 expects,
 *	which is different from it does in non SUSv3 mode.
 */
#define	_C99SUSv3_strfmon			0x00000100
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
 * If set, the range for strptime() and getdate() %S specifier is [0-60]
 * seconds; otherwise the range is [0-61] seconds.
 */
#define	_C99SUSv3_strptime_seconds		0x00000010

#define	_C99SUSv3_default_on_reserved03		0x00000008

/*
 * Use SUSv3 version numbers for _SC_VERSION and _SC_XOPEN_XCU_VERSION.
 */
#define	_C99SUSv3_XPG6_sysconf_version		0x00000004
/*
 * Include /usr/xpg6/bin in PATH.
 */
#define	_C99SUSv3_XPG6_pathing			0x00000002
/*
 * If set strtod() and wcstod() recognize hex floating point constants.
 */
#define	_C99SUSv3_recognize_hexfp		0x00000001

/*
 * __xpg6 = _C99SUSv3_mode_ON   enables C99/SUSv3 standards conformance mode.
 * __xpg6 = _C99SUSv3_mode_OFF disables C99/SUSv3 standards conformance mode.
 */

#define	_C99SUSv3_mode_ON	0x0000FFFF
#define	_C99SUSv3_mode_OFF	0xFFFF0000

#if !defined(_ASM)
extern unsigned int __xpg6;
#endif

#endif /* _XPG6_H */
