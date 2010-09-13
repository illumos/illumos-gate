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
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	accton - calls syscall with super-user privileges
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <errno.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdlib.h>

uid_t	admuid;
struct	passwd *pwd;

void ckfile(char *);

int
main(int argc, char **argv)
{
	uid_t	uid;

	uid = getuid();
	if ((pwd = getpwnam("adm")) == NULL) {
		perror("cannot determine adm's uid"), exit(1);
	}
	admuid = pwd->pw_uid;
	if (uid == ROOT || uid == admuid) {
		if (setuid(ROOT) == ERR) {
			perror("cannot setuid (check command mode and owner)");
			exit(1);
		}
		if (argv[1])
			ckfile(argv[1]);
		if (acct(argc > 1 ? argv[1] : 0) < 0) {
			perror(argv[1]), exit(1);
		}
		exit(0);

	}
	fprintf(stderr, "%s: permission denied\n", argv[0]);
	exit(1);
}

void
ckfile(char *admfile)
{
	struct stat		stbuf;
	struct stat	*s = &stbuf;
	int fd;

	if ((fd = open(admfile, O_RDONLY|O_CREAT, 0644)) == ERR) {
		perror("creat"), exit(1);
	}

	if (fstat(fd, s) == ERR) {
		perror("fstat");
		exit(1);
	}

	if (s->st_uid != admuid || s->st_gid != (gid_t)admuid)
		if (fchown(fd, admuid, (gid_t)admuid) == ERR) {
			perror("cannot change owner"), exit(1);
		}

	/* was if(s->st_mode & 0777 != 0664) */
	if ((s->st_mode & S_IAMB) != S_IRUSR|S_IWUSR|S_IRGRP|S_IWUSR|S_IROTH)
	    if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWUSR|S_IROTH) == ERR) {
			perror("cannot chmod"), exit(1);
	    }

	(void) close(fd);
}
