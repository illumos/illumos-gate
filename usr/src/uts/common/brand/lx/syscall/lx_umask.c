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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/lx_misc.h>
#include <lx_syscall.h>

/* From usr/src/uts/common/syscall/umask.c */
extern int umask(int);

/*
 * Just do what umask() does, but for the given process.
 */
static int
lx_clone_umask_cb(proc_t *pp, void *arg)
{
	mode_t cmask = (mode_t)(intptr_t)arg;
	mode_t orig;

	orig = PTOU(pp)->u_cmask;
	PTOU(pp)->u_cmask = (mode_t)(cmask & PERMMASK);
	return ((int)orig);
}

long
lx_umask(mode_t cmask)
{
	lx_proc_data_t *lproc = ttolxproc(curthread);

	/* Handle the rare case of being in a CLONE_FS clone group */
	if (lx_clone_grp_member(lproc, LX_CLONE_FS)) {
		int omask;

		omask = lx_clone_grp_walk(lproc, LX_CLONE_FS, lx_clone_umask_cb,
		    (void *)(intptr_t)cmask);
		return (omask);
	}

	return (umask(cmask));
}
