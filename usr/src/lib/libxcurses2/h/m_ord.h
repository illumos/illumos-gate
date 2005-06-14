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
 * m_ord.h
 *
 * Copyright 1986, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/m_ord.h 1.15 1994/05/29 16:17:02 mark Exp $
 */

#ifndef __M_M_ORD_H__
#define	__M_M_ORD_H__

#ifndef UCHAR_MAX
#include <limits.h>
#endif

/*
 * Used with CURSES in order to decern whether or not 'x' is a byte
 * or a KEY_xxxx macro, which are defined to be values greater than
 * UCHAR_MAX.
 */
#define	m_ischarset(x)	((unsigned)(x) <= UCHAR_MAX)

/* ASCII based macros */
/*
 * m_ord(c) : convert alpha character(case insensitive) to an an ordinal value.
 *            if c is an alphabetic character (A-Z,a-z), this returns
 *            a number between 1 and 26
 * m_chr(i) : convert an ordinal value to its corresponding alpha character
 *            using the reverse mapping as m_ord().
 *            if i is a number between 1 and 26 it returns the corresponding
 *            alphabetic character A to Z
 */
#include <ctype.h>

#define	m_ord(c) \
	((m_ischarset(c) && ('A' <= toupper(c) && toupper(c) <= 'Z')) ? \
	(toupper(c) - '@') : -1)
#define	m_chr(c)	((1 <= c && c <= 26) ? (c + '@') : -1)

#endif /* __M_M_ORD_H__ */
