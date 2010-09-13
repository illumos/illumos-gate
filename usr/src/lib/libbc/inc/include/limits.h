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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*	from S5R2 1.1	*/

#ifndef	__sys_limits_h
#define	__sys_limits_h

#define	CHAR_BIT		 0x8
#define	SCHAR_MIN		-0x80
#define	SCHAR_MAX		 0x7F
#define	UCHAR_MAX		 0xFF
#define	CHAR_MIN		-0x80
#define	CHAR_MAX		 0x7F
#define	SHRT_MIN		-0x8000
#define	SHRT_MAX		 0x7FFF
#define	USHRT_MAX		 0xFFFF
#define	INT_MIN			-0x80000000
#define	INT_MAX			 0x7FFFFFFF
#define	UINT_MAX		 0xFFFFFFFF
#define	LONG_MIN		-0x80000000
#define	LONG_MAX		 0x7FFFFFFF
#define	ULONG_MAX		 0xFFFFFFFF
#define	MB_LEN_MAX		4

/*
 * All POSIX systems must support the following values
 * A system may support less restrictive values
 */
#define	_POSIX_ARG_MAX		4096
#define	_POSIX_CHILD_MAX	6
#define	_POSIX_LINK_MAX		8
#define	_POSIX_MAX_CANON	255
#define	_POSIX_MAX_INPUT	255
#define	_POSIX_NAME_MAX		14
#define	_POSIX_NGROUPS_MAX	0
#define	_POSIX_OPEN_MAX		16
#define	_POSIX_PATH_MAX		255
#define	_POSIX_PIPE_BUF		512

#define	NGROUPS_MAX		16	/* Must match <sys/param.h> NGROUPS */
#endif	/* !__sys_limits_h */
