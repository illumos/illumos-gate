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
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 */
/*
 * Copyright (c) 2013 Joyent, Inc.  All Rights reserved.
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <sys/mkdev.h>

#include "libproc.h"
#include "Pcontrol.h"
#include "proc_fd.h"

/*
 * Pfdinfo.c - obtain open file information.
 */

/*
 * Allocate an fd_info structure and stick it on the list.
 * (Unless one already exists.)  The list is sorted in
 * reverse order.  We will traverse it in that order later.
 * This makes the usual ordered insert *fast*.
 */
fd_info_t *
Pfd2info(struct ps_prochandle *P, int fd)
{
	fd_info_t	*fip = list_next(&P->fd_head);
	fd_info_t	*next;
	int i;

	if (fip == NULL) {
		list_link(&P->fd_head, NULL);
		fip = list_next(&P->fd_head);
	}

	for (i = 0; i < P->num_fd; i++, fip = list_next(fip)) {
		if (fip->fd_info == NULL)
			continue;

		if (fip->fd_info->pr_fd == fd) {
			return (fip);
		}
		if (fip->fd_info->pr_fd < fd) {
			break;
		}
	}

	next = fip;
	if ((fip = calloc(1, sizeof (*fip))) == NULL)
		return (NULL);

	list_link(fip, next ? next : (void *)&(P->fd_head));
	P->num_fd++;
	return (fip);
}

static int
fdwalk_cb(const prfdinfo_t *info, void *arg)
{
	struct ps_prochandle *P = arg;
	fd_info_t *fip;

	fip = Pfd2info(P, info->pr_fd);
	if (fip == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	if (fip->fd_info == NULL)
		fip->fd_info = proc_fdinfo_dup(info);

	if (fip->fd_info == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	return (0);
}

/*
 * Attempt to load the open file information from a live process.
 */
static void
load_fdinfo(struct ps_prochandle *P)
{
	/*
	 * In the unlikely case there are *no* file descriptors open,
	 * we will keep rescanning the proc directory, which will be empty.
	 * This is an edge case it isn't worth adding additional state to
	 * to eliminate.
	 */
	if (P->num_fd > 0)
		return;

	if (P->state == PS_DEAD || P->state == PS_IDLE)
		return;

	proc_fdwalk(P->pid, fdwalk_cb, P);
}

int
Pfdinfo_iter(struct ps_prochandle *P, proc_fdinfo_f *func, void *cd)
{
	fd_info_t *fip;
	int rv;

	/* Make sure we have live data, if appropriate */
	load_fdinfo(P);

	/* NB: We walk the list backwards. */

	for (fip = list_prev(&P->fd_head);
	    fip != (void *)&P->fd_head && fip != NULL;
	    fip = list_prev(fip)) {
		if ((rv = func(cd, fip->fd_info)) != 0)
			return (rv);
	}
	return (0);
}
