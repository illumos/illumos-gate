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
 * Copyright 1993 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

#include <unistd.h>
#include <spawn.h>

#include <vroot/vroot.h>
#include <vroot/args.h>

/*
 * Try to spawn one candidate path. Returning 1 stops the path search,
 * either because the command has been spawned or because the error
 * needs to be dealt with by the caller. Returning 0 moves on to the
 * next candidate.
 */
static int spawn_thunk(char *path)
{
	int err = posix_spawn(&vroot_args.spawn.pid, path, NULL,
	    vroot_args.spawn.attr, vroot_args.spawn.argv,
	    vroot_args.spawn.environ);

	if (err == 0)
		return (1);
	vroot_args.spawn.pid = -1;
	errno = err;
	switch (errno) {
		case ETXTBSY:
		case ENOEXEC: return (1);
		default: return (0);
	}
}

pid_t spawn_vroot(char *path, char **argv, char **environ,
    posix_spawnattr_t *attr, pathpt vroot_path, pathpt vroot_vroot)
{
	vroot_args.spawn.argv = argv;
	vroot_args.spawn.environ = environ;
	vroot_args.spawn.attr = attr;
	vroot_args.spawn.pid = -1;
	translate_with_thunk(path, spawn_thunk, vroot_path, vroot_vroot, rw_read);
	return (vroot_args.spawn.pid);
}
