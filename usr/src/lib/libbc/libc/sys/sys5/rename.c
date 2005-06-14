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

int rename(path1, path2)
char *path1, *path2;
{
	int ret;
	char buf1[256];
	char buf2[256];

	if (strcmp(path1, "/var/adm/utmp") == 0 ||
		strcmp(path1, "/var/adm/wtmp") == 0 ||
		strcmp(path1, "/etc/utmp") == 0) {
		if (strcmp(path1, "/etc/utmp") == 0 ||
		    strcmp(path1, "/var/adm/utmp") == 0)
			strcpy(path1, "/var/adm/utmpx");
		else
			strcpy(path1, "/var/adm/wtmpx");
		strcpy(buf2, path2);
		strcat(buf2, "x");
		ret = _syscall(SYS_rename, buf1, buf2);
	} else
		ret = _syscall(SYS_rename, path1, path2);

	return(ret);
}	
