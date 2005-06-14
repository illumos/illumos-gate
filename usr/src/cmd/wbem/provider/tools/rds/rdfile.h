/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RDFILE_H
#define	_RDFILE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_PROCFS_PATH	40
#define	NUM_RESERVED_FD	10

typedef struct fd {
	int	fd_fd;
	int	fd_flags;
	char	fd_name[MAX_PROCFS_PATH];
} fd_t;

typedef struct fds {
	pid_t	fds_pid;
	fd_t	*fds_psinfo;
	fd_t	*fds_usage;
	fd_t	*fds_lpsinfo;
	fd_t	*fds_lusage;
	struct fds *fds_next;
} fds_t;

extern void fd_init(int);
extern void fd_exit();
extern fd_t *fd_open(char *, int, fd_t *);
extern int fd_getfd(fd_t *);
extern void fd_close(fd_t *);
extern void fd_closeall();
extern void fd_update();
extern fds_t *fds_get(pid_t);
extern void fds_rm(pid_t);
extern int fd_count();

#ifdef	__cplusplus
}
#endif

#endif	/* _RDFILE_H */
