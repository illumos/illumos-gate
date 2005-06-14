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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#ifndef	_DEFLT_H
#define	_DEFLT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEFLT	"/etc/default"

/*
 * Following for defcntl(3).
 * If you add new args, make sure that the default is:
 *	OFF	new-improved-feature-off, i.e. current state of affairs
 *	ON	new-improved-feature-on
 * or that you change the code for deflt(3) to have the old value as the
 * default.  (for compatibility).
 */

/* ... cmds */
#define	DC_GETFLAGS	0	/* get current flags */
#define	DC_SETFLAGS	1	/* set flags */

/* ... args */
#define	DC_CASE		0001	/* ON: respect case; OFF: ignore case */
#define	DC_NOREWIND	0002	/* ON: don't rewind in defread */
				/* OFF: do rewind in defread */
#define	DC_STRIP_QUOTES	0004	/* ON: strip quotes; OFF: leave quotes */

#define	DC_STD		((0) | (DC_CASE))

#ifdef __STDC__
extern int defcntl(int, int);
extern int defopen(char *);
extern char *defread(char *);
#else
extern int defcntl();
extern int defopen();
extern char *defread();
#endif

#define	TURNON(flags, mask)	((flags) |= (mask))
#define	TURNOFF(flags, mask)	((flags) &= ~(mask))
#define	ISON(flags, mask)	(((flags) & (mask)) == (mask))
#define	ISOFF(flags, mask)	(((flags) & (mask)) != (mask))

#ifdef	__cplusplus
}
#endif

#endif	/* _DEFLT_H */
