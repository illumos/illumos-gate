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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <regex.h>
#include <errno.h>
#include <stdarg.h>
#include <libdevinfo.h>
#include <sys/modctl.h>
#include <syslog.h>

#include <assert.h>


struct finddevhdl {
	int	npaths;
	int	curpath;
	char	**paths;
};


int
device_exists(const char *devname)
{
	int	rv;

	rv = modctl(MODDEVEXISTS, devname, strlen(devname));
	return ((rv == 0) ? 1 : 0);
}

int
finddev_readdir(const char *dir, finddevhdl_t *handlep)
{
	struct finddevhdl	*handle;
	int			n;
	int			rv;
	int64_t			bufsiz;
	char			*pathlist;
	char			*p;
	int			len;

	*handlep = NULL;
	handle = calloc(1, sizeof (struct finddevhdl));
	if (handle == NULL)
		return (ENOMEM);

	handle->npaths = 0;
	handle->curpath = 0;
	handle->paths = NULL;

	rv = modctl(MODDEVREADDIR, dir, strlen(dir), NULL, &bufsiz);
	if (rv != 0) {
		free(handle);
		return (rv);
	}

	for (;;) {
		assert(bufsiz != 0);
		if ((pathlist = malloc(bufsiz)) == NULL) {
			free(handle);
			return (ENOMEM);
		}

		rv = modctl(MODDEVREADDIR, dir, strlen(dir),
		    pathlist, &bufsiz);
		if (rv == 0) {
			for (n = 0, p = pathlist;
			    (len = strlen(p)) > 0; p += len+1) {
				n++;
			}
			handle->npaths = n;
			handle->paths = calloc(n, sizeof (char *));
			if (handle->paths == NULL) {
				free(handle);
				free(pathlist);
				return (ENOMEM);
			}
			for (n = 0, p = pathlist;
			    (len = strlen(p)) > 0; p += len+1, n++) {
				handle->paths[n] = strdup(p);
				if (handle->paths[n] == NULL) {
					finddev_close((finddevhdl_t)handle);
					free(pathlist);
					return (ENOMEM);
				}
			}
			*handlep = (finddevhdl_t)handle;
			free(pathlist);
			return (0);
		}
		free(pathlist);
		switch (errno) {
		case EAGAIN:
			break;
		case ENOENT:
		default:
			free(handle);
			return (errno);
		}
	}
	/*NOTREACHED*/
}

void
finddev_close(finddevhdl_t arg)
{
	struct finddevhdl *handle = (struct finddevhdl *)arg;
	int i;

	for (i = 0; i < handle->npaths; i++) {
		if (handle->paths[i])
			free(handle->paths[i]);
	}
	free(handle->paths);
	free(handle);
}

const char *
finddev_next(finddevhdl_t arg)
{
	struct finddevhdl *handle = (struct finddevhdl *)arg;
	const char *path = NULL;

	if (handle->curpath < handle->npaths) {
		path = handle->paths[handle->curpath];
		handle->curpath++;
	}
	return (path);
}
