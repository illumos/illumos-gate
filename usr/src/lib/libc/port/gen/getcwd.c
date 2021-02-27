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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * getcwd() returns the pathname of the current working directory.
 * On error, a NULL pointer is returned and errno is set.
 */

#pragma weak _getcwd = getcwd

#include "lint.h"
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *
getcwd(char *pathname, size_t size)
{
	int alloc = 0;

	if (size == 0 && pathname == NULL) {
		/*
		 * If no size was provided, start with a buffer that should
		 * accommodate any normal path and, if it is not big enough,
		 * keep doubling it to try and make enough space.
		 *
		 * Any non-global zone path is longer when observed from the
		 * global zone, and some filesystems, including ZFS, support
		 * paths much longer than MAXPATHLEN/_PC_PATH_MAX.
		 *
		 * To protect against unbounded memory usage, cap to 128KiB.
		 * This is an arbitrary limit which is far bigger than the
		 * length of any practical path on the system.
		 */
		if ((size = pathconf(".", _PC_PATH_MAX)) == -1)
			size = MAXPATHLEN;

		while (size <= 0x20000) {
			if ((pathname = reallocf(pathname, size)) == NULL) {
				errno = ENOMEM;
				return (NULL);
			}
			if (syscall(SYS_getcwd, pathname, size) == 0) {
				char *ret;

				/*
				 * Shrink the buffer to the length actually
				 * required to hold the final path.
				 */
				ret = realloc(pathname, strlen(pathname) + 1);
				if (ret == NULL)
					return (pathname);

				return (ret);
			}
			if (errno != ERANGE)
				break;
			size <<= 1;
		}
		free(pathname);
		return (NULL);
	}

	if (size == 0) {
		errno = EINVAL;
		return (NULL);
	}

	if (pathname == NULL)  {
		if ((pathname = malloc(size)) == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
		alloc = 1;
	}

	if (syscall(SYS_getcwd, pathname, size) == 0)
		return (pathname);

	if (alloc)
		free(pathname);

	return (NULL);
}
