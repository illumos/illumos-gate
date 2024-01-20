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

#include "lint.h"
#include <sys/types.h>
#include <sys/execx.h>

int
fexecve(int fd, char *const argv[], char *const envp[])
{
	return (execvex((uintptr_t)fd, argv, envp, EXEC_DESCRIPTOR));
}
