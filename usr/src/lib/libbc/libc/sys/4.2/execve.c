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

#include "chkpath.h"
#include <string.h>
#include <sys/file.h>
#include <sys/syscall.h>

int
execve(char *file, char **argv, char **arge)
{
	char *c;
	char path[256];


	CHKNULL(file);
	if (strncmp(file, "/usr/ucb", strlen("/usr/ucb")) == 0) {
		if (_syscall(SYS_faccessat, AT_FDCWD, file, F_OK, 0) == -1) {
			strcpy(path, "/usr/bin");
			strcat(path, strrchr(file, '/'));
			file = path;
		}
	}
	else if (strncmp(file, "/bin", strlen("/bin")) == 0 ||
		strncmp(file, "/usr/bin", strlen("/usr/bin")) == 0) {
		strcpy(path, "/usr/ucb");
		strcat(path, strrchr(file, '/'));
		if (_syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0) == 0) 
			file = path;
	}
	else if (strncmp(file, "/usr/5bin", strlen("/usr/5bin")) == 0) {
		strcpy(path, "/usr/bin");
		strcat(path, strrchr(file, '/'));
		if (_syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0) == 0)
			file = path;
		else {
			strcpy(path, "/usr/ucb");
			strcat(path, strrchr(file, '/'));
			if (_syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0)
			    == 0)
				file = path;
		}
	}		
	
	return (_syscall(SYS_execve, file, argv, arge));
}
