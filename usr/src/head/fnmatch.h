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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * Copyright 1985, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 */

#ifndef	_FNMATCH_H
#define	_FNMATCH_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	FNM_PATHNAME	0x01	/* Slash in str only matches slash in pattern */
#define	FNM_NOESCAPE	0x02	/* Disable '\'-quoting of metacharacters */
#define	FNM_PERIOD	0x04	/* Leading period in string must be exactly */
				/* matched by period in pattern	*/
#define	FNM_IGNORECASE	0x08	/* Ignore case when making comparisons */
#define	FNM_CASEFOLD	0x08	/* Ignore case when making comparisons */
				/* (for FreeBSD/Linux compatibility) */
#define	FNM_LEADING_DIR	0x10	/* Match if pattern matches initial segment */
				/* of str which is followed by a slash */

#define	FNM_NOMATCH	1	/* string doesnt match the specified pattern */
#define	FNM_ERROR	2	/* error occured */
#define	FNM_NOSYS	3	/* Function (XPG4) not supported */

extern int fnmatch(const char *, const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _FNMATCH_H */
