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
#include <sys/errno.h>

int unlink(char *path)
{
	int ret;
	char buf[256];
	extern int errno;
	char dot[2] = {'.','\n'};

	if (path == (char *) 0) {
		errno = EFAULT;
		return(-1);
	} else if (strcmp(path, "") == 0)
		path = dot;

	else if (strcmp(path, "/var/adm/utmp") == 0 ||
	    strcmp(path, "/var/adm/wtmp") == 0 ||
	    strcmp(path, "/etc/utmp") == 0) {
		if (strcmp(path, "/etc/utmp") == 0 ||
			strcmp(path, "/var/adm/utmp") == 0)
			strcpy(buf, "/var/adm/utmpx");
		else
			strcpy(buf, "/var/adm/wtmpx");
		ret = _syscall(SYS_unlink, buf);
	} else
		ret = _syscall(SYS_unlink, path);
	
	return (ret);
}	
