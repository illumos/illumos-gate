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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/syscall.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/param.h>

int
access_com(char *path, int mode)
{
	if (strcmp(path, "/etc/mtab") == 0 ||
	    strcmp(path, "/etc/fstab") == 0) {
		if (mode == W_OK || mode == X_OK)
			return (-1);
		else
			return (0);
	}

	if (strcmp(path, "/etc/utmp") == 0 ||
	    strcmp(path, "/var/adm/utmp") == 0)
		path = "/var/adm/utmpx";
	else if (strcmp(path, "/var/adm/wtmp") == 0)
		path = "/var/adm/wtmpx";

	return (_syscall(SYS_faccessat, AT_FDCWD, path, mode, 0));
}
