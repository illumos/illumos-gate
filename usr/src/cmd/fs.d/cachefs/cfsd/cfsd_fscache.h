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
 * Copyright (c) 1994-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CFSD_FSCACHE_H
#define	_CFSD_FSCACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	CFS_MAXMNTOPTLEN	MAXPATHLEN * 4

typedef struct cfsd_fscache_object {
	char	i_name[MAXNAMELEN];		/* fscache name */
	char	i_cachepath[MAXPATHLEN];	/* cache pathname */
	int	i_fscacheid;			/* fscache identifier */

	char	i_mntpt[MAXPATHLEN];		/* mount point */
	char	i_backfs[MAXPATHLEN * 2];	/* back file system */
	char	i_backpath[MAXPATHLEN];		/* back file system path */
	char	i_backfstype[MAXNAMELEN];	/* back file system type */
	char	i_cfsopt[CFS_MAXMNTOPTLEN];	/* cachefs mount options */
	char	i_bfsopt[CFS_MAXMNTOPTLEN];	/* backfs mount options */

	mutex_t		i_lock;			/* synchronizing lock */
	int		i_refcnt;		/* refs to object */
	volatile int	i_disconnectable:1;	/* 1 if okay to disconnect */
	volatile int	i_mounted:1;		/* 1 if fs is mounted */
	volatile int	i_threaded:1;		/* 1 if thread running */
	volatile int	i_connected:1;		/* 1 if connected */
	volatile int	i_reconcile:1;		/* 1 if reconciling */
	volatile int	i_changes:1;		/* 1 if changes to push back */
	volatile int	i_simdis:1;		/* 1 means sim disconnect */
	volatile int	i_tryunmount:1;		/* 1 if should try unmount */
	volatile int	i_backunmount:1;	/* 1 if need to umount backfs */
	time_t		i_time_state;		/* time of last dis/connect */
	time_t		i_time_mnt;		/* time of last u/mount */
	int		i_modify;		/* changed when modified */

	int		i_ofd;			/* message file descriptor */

	thread_t	i_threadid;		/* id of thread, if running */
	cond_t		i_cvwait;		/* cond var to wait on */

	off_t		i_again_offset;		/* offset to head modify op */
	int		i_again_seq;		/* seq num of head modify op */
	struct cfsd_fscache_object *i_next;	/* next fscache object */
} cfsd_fscache_object_t;

cfsd_fscache_object_t *cfsd_fscache_create(const char *name,
    const char *cachepath, int fscacheid);
void cfsd_fscache_destroy(cfsd_fscache_object_t *fscache_object_p);

void fscache_lock(cfsd_fscache_object_t *fscache_object_p);
void fscache_unlock(cfsd_fscache_object_t *fscache_object_p);

void fscache_setup(cfsd_fscache_object_t *fscache_object_p);
void fscache_process(cfsd_fscache_object_t *fscache_object_p);
int fscache_simdisconnect(cfsd_fscache_object_t *fscache_object_p,
    int disconnect);
int fscache_unmount(cfsd_fscache_object_t *fscache_object_p, int);
void fscache_server_alive(cfsd_fscache_object_t *fscache_object_p,
    cfsd_kmod_object_t *kmod_object_p);
int fscache_pingserver(cfsd_fscache_object_t *fscache_object_p);
int fscache_roll(cfsd_fscache_object_t *fscache_object_p,
    cfsd_kmod_object_t *kmod_object_p);
int fscache_rollone(cfsd_fscache_object_t *fscache_object_p,
    cfsd_kmod_object_t *kmod_object_p,
    cfsd_maptbl_object_t *maptbl_object_p,
    cfsd_logfile_object_t *logfile_object_p,
    ulong_t seq);
int fscache_addagain(cfsd_fscache_object_t *fscache_object_p,
    cfsd_logfile_object_t *logfile_object_p,
    ulong_t nseq);
void fscache_fsproblem(cfsd_fscache_object_t *fscache_object_p,
    cfsd_kmod_object_t *kmod_object_p);
void fscache_changes(cfsd_fscache_object_t *fscache_object_p, int tt);

#ifdef	__cplusplus
}
#endif

#endif	/* _CFSD_FSCACHE_H */
