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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include "pkglocale.h"
#include "pkglib.h"

int
rrmdir(char *a_path)
{
	char	path[PATH_MAX+13];
	int	i;
	int	status;

	/*
	 * For some reason, a simple "rm -rf" will remove the contents
	 * of the directory, but will fail to remove the directory itself
	 * with "No such file or directory" when running the pkg commands
	 * under a virtual root via the "chroot" command.  This has been
	 * seen so far only with the `pkgremove' command, and when the
	 * the directory is NFS mounted from a 4.x server.  This should
	 * probably be revisited at a later time, but for now we'll just
	 * remove the directory contents first, then the directory.
	 */

	/* do not allow removal of all root files via blank path */

	if ((a_path == NULL) || (*a_path == '\0')) {
		(void) fprintf(stderr,
		    pkg_gt("warning: rrmdir(path==NULL): nothing deleted\n"));
		return (0);
	}

	/*
	 * first generate path with slash-star at the end and attempt to remove
	 * all files first. If successful then remove with just the path only.
	 */

	(void) snprintf(path, sizeof (path), "%s/", a_path);
	i = e_ExecCmdList(&status, (char **)NULL, (char *)NULL,
		"/bin/rm", "rm", "-rf", path, (char *)NULL);

	if (access(a_path, F_OK) == 0) {
		i = e_ExecCmdList(&status, (char **)NULL, (char *)NULL,
			"/bin/rmdir", "rmdir", a_path, (char *)NULL);
	}

	/* return 0 if last command successful, else return 1 */
	return ((i == 0 && status == 0) ? 0 : 1);
}
