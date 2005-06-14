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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <syscall.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include "compat.h"	/* for UTMPX_MAGIC_FLAG */

extern int errno;

int creat_com(char *path, int mode)
{
	int ret=0;
	int fd, fd2;
	char buf[MAXPATHLEN+100];

	if (strcmp(path, "/etc/mtab") == 0 ||
	    strcmp(path, "/etc/fstab") == 0) {
		errno = ENOENT;
		return(-1);
	}
	if (strcmp(path, "/var/adm/utmp") == 0 ||
	    strcmp(path, "/var/adm/wtmp") == 0) {
                        strcpy(buf, path);
			strcat(buf, "x");
			if ((fd = _syscall(SYS_creat, buf, mode)) >= 0) {
				fd2 = UTMPX_MAGIC_FLAG;
				fd_add(fd, fd2);
			}
			return(fd);
	} else if (strcmp(path, "/etc/utmp") == 0) {
		strcpy(buf, "/var/adm/utmpx");
		if ((fd = _syscall(SYS_creat, buf, mode)) >= 0) {
			fd2 = UTMPX_MAGIC_FLAG;
			fd_add(fd, fd2);
		}
		return(fd);
	} else
		return(_syscall(SYS_creat, path, mode));
}
