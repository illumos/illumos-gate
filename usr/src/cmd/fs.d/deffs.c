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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990, 1991, 1997 SMI	*/
/* All Rights Reserved							*/

#include <stdio.h>
#include <deflt.h>
#include <string.h>

#define	LOCAL		"/etc/default/fs"
#define	REMOTE		"/etc/dfs/fstypes"

/*
 * This is used to figure out the default file system type if "-F FStype"
 * is not specified with the file system command and no entry in the
 * /etc/vfstab matches the specified special.
 * If the first character of the "special" is a "/" (eg, "/dev/dsk/c0d1s2"),
 * returns the default local filesystem type.
 * Otherwise (eg, "server:/path/name" or "resource"), returns the default
 * remote filesystem type.
 */
char	*
default_fstype(char *special)
{
	char	*deffs = NULL;
	static	char	buf[BUFSIZ];
	FILE	*fp;

	if (*special == '/') {
		if (defopen(LOCAL) == 0) {
			deffs = defread("LOCAL=");
			defopen(NULL);	/* close default file */
		}
	} else {
		if ((fp = fopen(REMOTE, "r")) != NULL) {
			if (fgets(buf, sizeof (buf), fp) != NULL)
				deffs = strtok(buf, " \t\n");
			fclose(fp);
		}
		if (deffs == NULL)
			deffs = "nfs";
	}

	return (deffs != NULL ? deffs : "ufs");
}
