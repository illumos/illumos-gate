/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
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

#ifndef	_SYS_UN_H
#define	_SYS_UN_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _SA_FAMILY_T
#define	_SA_FAMILY_T
typedef	unsigned short sa_family_t;
#endif

/*
 * Definitions for UNIX IPC domain.
 */
struct	sockaddr_un {
	sa_family_t	sun_family;		/* AF_UNIX */
	char		sun_path[108];		/* path name (gag) */
};

#if (!defined(_XOPEN_SOURCE) && !defined(_POSIX_C_SOURCE)) || \
    defined(__EXTENSIONS__)
/*
 * NOTE: If we ever go to BSD-style sun_len + sun_family, this macro needs to
 * change.
 *
 * Also, include a strlen() prototype, and we have to protect it w.r.t.
 * UNIX{98,03}.  And because there's strlen, we need size_t as well.
 */
#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef	unsigned long	size_t;		/* size of something in bytes */
#else
typedef	unsigned int	size_t;		/* (historical version) */
#endif
#endif	/* _SIZE_T */

extern size_t strlen(const char *);

#define	SUN_LEN(su)	(sizeof (sa_family_t) + strlen((su)->sun_path))

#endif	/* (!defined(_XOPEN_SOURCE) && !defined(_POSIX_C_SOURCE)) || ... */

#ifdef _KERNEL
int	unp_discard();
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_UN_H */
