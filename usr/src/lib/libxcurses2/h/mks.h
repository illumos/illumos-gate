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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MKS header file.  Defines that make programming easier for us.
 * Includes MKS-specific things and posix routines.
 *
 * Copyright 1985, 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/mks.h 1.233 1995/09/28 19:45:19 mark Exp $
 */

#ifndef	__M_MKS_H__
#define	__M_MKS_H__

/*
 * This should be a feature test macro defined in the Makefile or
 * cc command line.
 */
#ifndef	MKS
#define	MKS	1
#endif

typedef	void	(*_sigfun_t)(int);

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <wchar.h>

#define	M_TERMINFO_DIR		"/usr/share/lib/terminfo"
#define	M_CURSES_VERSION	"MKS I/XCU 4.3 Curses"

/*
 * MKS-specific library entry points.
 */
#if defined(_LP64)
extern void	m_crcposix(unsigned int *, const unsigned char *, size_t);
#else
extern void	m_crcposix(unsigned long *, const unsigned char *, size_t);
#endif

#endif	/* __M_MKS_H__ */
