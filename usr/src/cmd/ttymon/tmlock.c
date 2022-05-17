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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include	<unistd.h>
#include	<string.h>
#include	<sys/termios.h>
#include	"tmextern.h"

/* -------------------------------------------------------- */
/* the follwing are here so we can use routines in ulockf.c */
int	Debug = 0;
char	*Bnptr;
/* dummies for using uucp .o routines */
/*VARARGS*/
/*ARGSUSED*/
void
assert(char *s1, char *s2, int i1, char *s3, int i2)
{
}

void
cleanup(void)
{
}

void
logent(char *s1 __unused, char *s2 __unused)
{
	/* so we can load ulockf() */
}

/*
 *	lastname	- If the path name starts with "/dev/",
 *			  return the rest of the string.
 *			- Otherwise, return the last token of the path name
 */
char *
lastname(char *name)
{
	char	*sp, *p;

	sp = name;
	if (strncmp(sp, "/dev/", 5) == 0)
		sp += 5;
	else
		while ((p = (char *)strchr(sp, '/')) != NULL) {
			sp = ++p;
		}
	return (sp);
}

/*
 *	tm_lock(fd)	- set advisory lock on the device
 */
int
tm_lock(int fd)
{
	return (fd_mklock(fd));
}

/*
 *	tm_checklock	- check if advisory lock is on
 */
int
tm_checklock(int fd)
{
	return (fd_cklock(fd));
}

/*
 * check_session(fd) - check if a session established on fd
 *		       return 1 if session exists, otherwise, return 0.
 *
 */
int
check_session(int fd)
{
	pid_t	sid;

	if (ioctl(fd, TIOCGSID, &sid) == -1)
		return (0);
	else if (sid == 0)
		return (0);
	else
		return (1);
}
