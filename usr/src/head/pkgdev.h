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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _PKGDEV_H
#define	_PKGDEV_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

struct pkgdev {
	int			rdonly;
	int			mntflg;
	longlong_t	capacity; /* number of 512-blocks on device */
	char		*name;
	char		*dirname;
	char		*pathname;
	char		*mount;
	char		*fstyp;
	char		*cdevice;
	char		*bdevice;
	char		*norewind;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _PKGDEV_H */
