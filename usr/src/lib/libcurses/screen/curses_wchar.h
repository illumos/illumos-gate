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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


#ifndef	_CURSES_WCHAR_H
#define	_CURSES_WCHAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	P00	WCHAR_CS0	/* Code Set 0 */
#define	P11	WCHAR_CS1	/* Code Set 1 */
#define	P01	WCHAR_CS2	/* Code Set 2 */
#define	P10	WCHAR_CS3	/* Code Set 3 */

#ifdef __STDC__
#define	_ctype __ctype
#endif
extern unsigned char _ctype[];

#define	_mbyte  _ctype[520]

#ifdef	__cplusplus
}
#endif

#endif /* _CURSES_WCHAR_H */
