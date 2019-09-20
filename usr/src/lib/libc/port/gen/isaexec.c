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
 */

/*
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#pragma weak _isaexec = isaexec

#include "lint.h"
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>

/*
 * This is a utility routine to allow wrapper programs to simply
 * implement the isalist exec algorithms.  See PSARC/1997/220.
 */
int
isaexec(const char *execname, char *const *argv, char *const *envp)
{
	const char *fname;
	char *isalist;
	char *pathname;
	char *str;
	char *lasts;
	size_t isalen = 255;		/* wild guess */
	size_t len;
	int saved_errno;

	/*
	 * Extract the isalist(5) for userland from the kernel.
	 */
	isalist = malloc(isalen);
	do {
		long ret = sysinfo(SI_ISALIST, isalist, isalen);
		if (ret == -1l) {
			free(isalist);
			errno = ENOENT;
			return (-1);
		}
		if (ret > isalen) {
			isalen = ret;
			isalist = reallocf(isalist, isalen);
		} else {
			break;
		}
	} while (isalist != NULL);

	if (isalist == NULL) {
		/*
		 * Then either a malloc or a realloc failed.
		 */
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * Allocate a full pathname buffer.  The sum of the lengths of the
	 * 'path' and isalist strings is guaranteed to be big enough.
	 */
	len = strlen(execname) + isalen;
	if ((pathname = malloc(len)) == NULL) {
		free(isalist);
		errno = EAGAIN;
		return (-1);
	}

	/*
	 * Break the exec name into directory and file name components.
	 */
	(void) strcpy(pathname, execname);
	if ((str = strrchr(pathname, '/')) != NULL) {
		*++str = '\0';
		fname = execname + (str - pathname);
	} else {
		fname = execname;
		*pathname = '\0';
	}
	len = strlen(pathname);

	/*
	 * For each name in the isa list, look for an executable file
	 * with the given file name in the corresponding subdirectory.
	 * If it's there, exec it.  If it's not there, or the exec
	 * fails, then run the next version ..
	 */
	str = strtok_r(isalist, " ", &lasts);
	saved_errno = ENOENT;
	do {
		(void) strcpy(pathname + len, str);
		(void) strcat(pathname + len, "/");
		(void) strcat(pathname + len, fname);
		if (access(pathname, X_OK) == 0) {
			/*
			 * File exists and is marked executable.  Attempt
			 * to execute the file from the subdirectory,
			 * using the user-supplied argv and envp.
			 */
			(void) execve(pathname, argv, envp);

			/*
			 * If we failed to exec because of a temporary
			 * resource shortage, it's better to let our
			 * caller handle it (free memory, sleep for a while,
			 * or whatever before retrying) rather than drive
			 * on to run the "less capable" version.
			 */
			if (errno == EAGAIN) {
				saved_errno = errno;
				break;
			}
		}
	} while ((str = strtok_r(NULL, " ", &lasts)) != NULL);

	free(pathname);
	free(isalist);

	errno = saved_errno;
	return (-1);
}
