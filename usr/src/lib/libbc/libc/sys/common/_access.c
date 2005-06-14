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
#include <sys/param.h>

int access_com(char *path, int mode)
{
	int ret=0;
	char buf[MAXPATHLEN+100];

	if (strcmp(path, "/etc/mtab") == 0 ||
	    strcmp(path, "/etc/fstab") == 0) {
		if (mode == W_OK || mode == X_OK)
			return(-1);
		else return(0);
	} else if (strcmp(path, "/var/adm/utmp") == 0 ||
	    strcmp(path, "/var/adm/wtmp") == 0) {
			strcpy(buf, path);
			strcat(buf, "x");
			return(_syscall(SYS_access, buf, mode));
	} else if (strcmp(path, "/etc/utmp") == 0) {
		strcpy(buf, "/var/adm/utmpx");
		return(_syscall(SYS_access, buf, mode));
	} else
		return(_syscall(SYS_access, path, mode));
}
