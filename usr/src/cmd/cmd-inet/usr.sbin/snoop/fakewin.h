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
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

#ifndef _FAKEWIN_H
#define	_FAKEWIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines appropriate macros so that
 * we can use the same codebase for Unix, DOS, and Windows.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _WINDOWS
#include <tklib.h>

#define	malloc		_fmalloc
#define	calloc		_fcalloc
#define	free		_ffree
#define	strdup		_fstrdup
#define	strcpy		_fstrcpy
#define	strcmp		_fstrcmp
#define	strchr		_fstrchr
#define	sprintf		wsprintf
#define	vsprintf	wvsprintf
#define	memcpy		_fmemcpy
#define	strlen		_fstrlen
#else
#define	LPSTR	char *
#endif

#if !defined(_WINDOWS) && !defined(_MSDOS)
#define	_TKFAR
#endif

#ifndef	_WINDOWS
#define	_TKPASCAL
#define	__export
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_FAKEWIN_H */
