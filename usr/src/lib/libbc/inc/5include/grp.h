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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__grp_h
#define	__grp_h

#include <sys/types.h>

/*
 * We have to make this POSIX.1 compatible header compatible with SunOS
 * Release 4.0.x and the BSD interface provided by /usr/include/grp.h
 * so we have a filler to make the gid_t gr_gid field here match the
 * int gr_gid field there.
 * This will all go away in a later release when gid_t is enlarged.
 * Until then watch out for big- vs. little-endian problems in the filler.
 */
struct	group { /* see getgrent(3) */
	char	*gr_name;
	char	*gr_passwd;
#if defined(mc68000) || defined(sparc)
	short	gr_gid_filler;
#endif
	gid_t	gr_gid;
#if defined(i386)
	short	gr_gid_filler;
#endif
	char	**gr_mem;
};

#ifndef	_POSIX_SOURCE
struct group *getgrent();
#endif

struct group *getgrgid(/* gid_t gid */);
struct group *getgrnam(/* char *name */);

#endif	/* !__grp_h */
