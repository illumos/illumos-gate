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
 * Copyright 1984 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pwd.h>

int
getpw(int uid, char buf[])
{
	struct passwd *pw;
	char numbuf[20];

	pw = getpwuid(uid);
	if(pw == 0)
		return (1);
	strcpy(buf, pw->pw_name);
	strcat(buf, ":");
	strcat(buf, pw->pw_passwd);
	strcat(buf, ":");
	sprintf(numbuf, "%d", pw->pw_uid);
	strcat(buf, numbuf);
	strcat(buf, ":");
	sprintf(numbuf, "%d", pw->pw_gid);
	strcat(buf, numbuf);
	strcat(buf, ":");
	strcat(buf, pw->pw_gecos);
	strcat(buf, ":");
	strcat(buf, pw->pw_dir);
	strcat(buf, ":");
	strcat(buf, pw->pw_shell);
	return (0);
}
