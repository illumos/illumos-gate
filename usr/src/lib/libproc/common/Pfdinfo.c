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
		if (fip->fd_info.pr_fd == fd) {
			return (fip);
		}
		if (fip->fd_info.pr_fd < fd) {
			break;
		}
	}

	next = fip;
	if ((fip = calloc(1, sizeof (*fip))) == NULL)
		return (NULL);

	fip->fd_info.pr_fd = fd;
	list_link(fip, next ? next : (void *)&(P->fd_head));
	P->num_fd++;
	return (fip);
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
	if (P->num_fd > 0) {
		return;
	}

	if (P->state != PS_DEAD && P->state != PS_IDLE) {
		char dir_name[PATH_MAX];
		char path[PATH_MAX];
		struct dirent *ent;
		DIR	*dirp;
		int	fd;

		/*
		 * Try to get the path information first.
		 */
		(void) snprintf(dir_name, sizeof (dir_name),
		    "%s/%d/path", procfs_path, (int)P->pid);
		dirp = opendir(dir_name);
		if (dirp == NULL) {
			return;
		}
		ent = NULL;
		while ((ent = readdir(dirp)) != NULL) {
			fd_info_t	*fip;
			prfdinfo_t	*info;
			int		len;
			struct stat64	stat;

			if (!isdigit(ent->d_name[0]))
				continue;

			fd = atoi(ent->d_name);

			fip = Pfd2info(P, fd);
			info = &fip->fd_info;
			info->pr_fd = fd;

			if (pr_fstat64(P, fd, &stat) == 0) {
				info->pr_mode = stat.st_mode;
				info->pr_uid = stat.st_uid;
				info->pr_gid = stat.st_gid;
				info->pr_major = major(stat.st_dev);
				info->pr_minor = minor(stat.st_dev);
				info->pr_rmajor = major(stat.st_rdev);
				info->pr_rminor = minor(stat.st_rdev);
				info->pr_size = stat.st_size;
				info->pr_ino = stat.st_ino;
			}

			info->pr_fileflags = pr_fcntl(P, fd, F_GETXFL, 0);
			info->pr_fdflags = pr_fcntl(P, fd, F_GETFD, 0);
			info->pr_offset = pr_llseek(P, fd, 0, SEEK_CUR);

			/* attempt to determine the path to it */
			(void) snprintf(path, sizeof (path),
			    "%s/%d/path/%d", procfs_path, (int)P->pid, fd);
			len = readlink(path, info->pr_path,
			    sizeof (info->pr_path) - 1);

			if (len < 0) {
				info->pr_path[0] = 0;
			} else {
				info->pr_path[len] = 0;
			}
		}
		(void) closedir(dirp);

	}
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
		if ((rv = func(cd, &fip->fd_info)) != 0)
			return (rv);
	}
	return (0);
}
