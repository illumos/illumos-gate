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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__pwd_h
#define	__pwd_h

#include <sys/types.h>

/*
 * We have to make this POSIX.1 compatible header compatible with SunOS
 * Release 4.0.x and the BSD interface provided by /usr/include/pwd.h
 * so we have fillers to make the gid_t pw_gid field here match the
 * int pw_gid field there and the uid_t pw_uid field here match the
 * int pw_uid field there.
 * This will all go away in a later release when gid_t is enlarged.
 * Until then watch out for big- vs. little-endian problems in the filler.
 */
struct passwd {
	char	*pw_name;
	char	*pw_passwd;
#if defined(mc68000) || defined(sparc)
	short	pw_uid_filler;
#endif
	uid_t	pw_uid;
#if defined(i386)
	short	pw_uid_filler;
#endif
#if defined(mc68000) || defined(sparc)
	short	pw_gid_filler;
#endif
	gid_t	pw_gid;
#if defined(i386)
	short	pw_gid_filler;
#endif
	char	*pw_age;
	char	*pw_comment;
	char	*pw_gecos;
	char	*pw_dir;
	char	*pw_shell;
};


#ifndef	_POSIX_SOURCE
extern struct passwd *getpwent();

struct comment {
        char    *c_dept;
        char    *c_name;
        char    *c_acct;
        char    *c_bin;
};

#endif

struct passwd *getpwuid(/* uid_t uid */);
struct passwd *getpwnam(/* char *name */);

#endif	/* !__pwd_h */
