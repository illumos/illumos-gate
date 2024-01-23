/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 *	execve(file, argv, envp)
 */

#pragma weak _execve = execve

#include "lint.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/execx.h>

int
execve(const char *file, char *const argv[], char *const envp[])
{
	return (execvex((uintptr_t)file, argv, envp, 0));
}
