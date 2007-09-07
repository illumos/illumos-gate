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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Attach a STREAMS or door based file descriptor to an object in the file
 * system name space.
 */
#pragma weak fattach = _fattach
#include "synonyms.h"
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stropts.h>
#include <sys/door.h>
#include <sys/fs/namenode.h>
#include <sys/mount.h>
#include <unistd.h>
#include <string.h>
#include "libc.h"

int
fattach(int fildes, const char *path)
{
	struct namefd  namefdp;
	struct door_info dinfo;
	int	s;
	char buf[MAXPATHLEN];

	/* Only STREAMS and doors allowed to be mounted */
	if ((s = isastream(fildes)) == 1 || __door_info(fildes, &dinfo) == 0) {
		namefdp.fd = fildes;
		if (path == NULL || *path == '\0') {
			errno = ENOENT;
			return (-1);
		} else if (*path != '/') {
			/*
			 * The mount point must be an absolute path.
			 */
			if (getcwd(buf, sizeof (buf)) == NULL) {
				/* errno already set */
				return (-1);
			}
			/*
			 * The kernel will truncate the path if it would have
			 * turned into something more than MAXPATHLEN bytes.
			 * So we do the same here.
			 */
			if (strlcat(buf, "/",  sizeof (buf)) >= sizeof (buf) ||
			    strlcat(buf, path, sizeof (buf)) >= sizeof (buf)) {
				errno = ENAMETOOLONG;
				return (-1);
			}
			path = buf;
		}
		return (mount((char *)NULL, path, MS_DATA|MS_NOMNTTAB,
		    (const char *)"namefs", (char *)&namefdp,
		    sizeof (struct namefd), NULL, 0));
	} else if (s == 0) {
		/* Not a STREAM */
		errno = EINVAL;
		return (-1);
	} else {
		/* errno already set */
		return (-1);
	}
}
