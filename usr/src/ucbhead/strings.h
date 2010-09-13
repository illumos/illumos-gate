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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * External function definitions
 * for routines described in string(3).
 */

#ifndef	_STRINGS_H
#define	_STRINGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__STDC__)
extern	char *index(char *, char);
extern	char *rindex(char *, char);
extern	int bcmp(const void *, const void *, size_t);
extern	void bcopy(const void *, void *, size_t);
extern	void bzero(void *, size_t);
#else
extern	char	*index();
extern	char	*rindex();
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _STRINGS_H */
