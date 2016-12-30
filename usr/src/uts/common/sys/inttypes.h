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

#ifndef _SYS_INTTYPES_H
#define	_SYS_INTTYPES_H

/*
 * This header, <sys/inttypes.h>, contains (through nested inclusion) the
 * vast majority of the facilities specified for <inttypes.h> as defined
 * by the ISO C Standard, ISO/IEC 9899:1999 Programming language - C.
 *
 * Kernel/Driver developers are encouraged to include this file to access
 * the fixed size types, limits and utility macros. Application developers
 * should use the standard defined header <inttypes.h>.
 */

#include <sys/feature_tests.h>
#include <sys/int_types.h>
#if !defined(_XOPEN_SOURCE) || defined(_XPG6) || defined(__EXTENSIONS__)
#include <sys/int_limits.h>
#include <sys/int_const.h>
#include <sys/int_fmtio.h>
#endif

#endif /* _SYS_INTTYPES_H */
