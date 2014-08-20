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
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_TIUSER_H
#define	_TIUSER_H

/*
 * TLI user interface definitions.
 */

#include <sys/tiuser.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_REENTRANT) || defined(_TS_ERRNO) || \
	_POSIX_C_SOURCE - 0 >= 199506L
extern int	*__t_errno(void);
#define	t_errno	(*(__t_errno()))
#else
extern int t_errno;
#endif	/* defined(_REENTRANT) || defined(_TS_ERRNO) */

#ifdef	__cplusplus
}
#endif

#endif	/* _TIUSER_H */
