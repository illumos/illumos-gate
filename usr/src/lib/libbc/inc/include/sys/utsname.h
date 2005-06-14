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
/*	from S5R2 6.1	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__sys_utsname_h
#define	__sys_utsname_h

struct utsname {
	char	sysname[9];
	char	nodename[9];
	char	nodeext[65-9];  /* extends nodename to MAXHOSTNAMELEN+1 chars */
	char	release[9];
	char	version[9];
	char	machine[9];
};

#ifdef	KERNEL
extern struct utsname utsname;
#else
int	uname(/* struct utsname *name */);
#endif

#endif	/* !__sys_utsname_h */
