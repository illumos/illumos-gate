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

#ifndef	_MHD_LOCAL_H
#define	_MHD_LOCAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/time.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>

#include <metamhd.h>
#include <thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * millisecond time
 */
typedef	u_longlong_t	mhd_msec_t;

/*
 * drive record
 */
typedef	uint_t	mhd_state_t;
#define	DRIVE_IDLE		0x0000	/* exclusive state */
#define	DRIVE_ERRORED		0x0001	/* exclusive state */
#define	DRIVE_IDLING		0x0002	/* exclusive state */
#define	DRIVE_RESERVING		0x0004	/* exclusive state */
#define	DRIVE_FAILFASTING	0x0008	/* exclusive state */
#define	DRIVE_RELEASING		0x0010	/* exclusive state */
#define	DRIVE_EXCLUSIVE_STATES	0x00ff	/* all exclusive states */
#define	DRIVE_PROBING		0x0100
#define	DRIVE_STATUSING		0x0200
#define	DRIVE_SERIALING		0x0400
#define	DRIVE_VTOCING		0x0800
#define	DRIVE_CINFOING		0x1000
#define	DRIVE_IDENTING		(DRIVE_SERIALING | DRIVE_VTOCING | \
				    DRIVE_CINFOING)
#define	DRIVE_IS_IDLE(dp)	(((dp)->dr_state == DRIVE_IDLE) || \
				    ((dp)->dr_state == DRIVE_ERRORED))
typedef struct mhd_drive {
	struct mhd_drive_set *dr_sp;	/* back pointer to set */
	char		*dr_rname;	/* raw device name */
	char		*dr_rname0;	/* slice 0 raw device name */
	cond_t		dr_cv;		/* synchronization */
	thread_t	dr_thread;	/* daemon thread */
	int		dr_fd;		/* open slice 0 */
	mhd_state_t	dr_state;	/* drive state */
	int		dr_errnum;	/* errno for DRIVE_ERRORED */
	mhd_msec_t	dr_time;	/* last successful probe time */
	mhd_drive_id_t	dr_drive_id;	/* unique drive identifier */
} mhd_drive_t;

/*
 * drive list
 */
typedef	struct mhd_drive_list {
	mhd_drive_t	**dl_drives;	/* allocated list */
	size_t		dl_alloc;	/* amount allocated */
	size_t		dl_ndrive;	/* amount used */
} mhd_drive_list_t;
#define	MHD_NULL_LIST	{ NULL, 0, 0 }

/*
 * drive set
 */
typedef	struct mhd_drive_set {
	char		*sr_name;	/* set name */
	mutex_t		sr_mx;		/* set mutex */
	cond_t		sr_cv;		/* synchronization */
	mhd_opts_t	sr_options;	/* common options */
	mhd_mhiargs_t	sr_timeouts;	/* reservation timeouts */
	mhd_ff_mode_t	sr_ff_mode;	/* failfast mode */
	int		sr_ff;		/* failfast device descriptor */
	mhd_drive_list_t sr_drives;	/* drives in set */
} mhd_drive_set_t;

/*
 * debug stuff
 */
#define	MHD_DEBUG	0
#ifdef	MHD_DEBUG
extern	int	mhd_debug;
#define	MHDPRINTF(n)	if (mhd_debug > 0) mhd_eprintf n
#define	MHDPRINTF1(n)	if (mhd_debug > 1) mhd_eprintf n
#define	MHDPRINTF2(n)	if (mhd_debug > 2) mhd_eprintf n
#else	/* ! MHD_DEBUG */
#define	MHDPRINTF(n)
#define	MHDPRINTF1(n)
#define	MHDPRINTF2(n)
#endif	/* ! MHD_DEBUG */

/*
 * extern functions
 */
/* mhd_drive.c */
extern	const mhd_drive_list_t	mhd_null_list;
extern	void		mhd_add_drive(mhd_drive_list_t *dlp, mhd_drive_t *dp);
extern	void		mhd_del_drive(mhd_drive_list_t *dlp, mhd_drive_t *dp);
extern	void		mhd_free_list(mhd_drive_list_t *dlp);
extern	int		mhd_state(mhd_drive_t *dp, mhd_state_t new_state,
			    mhd_error_t *mhep);
extern	int		mhd_state_set(mhd_drive_t *dp, mhd_state_t new_state,
			    mhd_error_t *mhep);
extern	int		mhd_idle(mhd_drive_t *dp, mhd_error_t *mhep);
extern	mhd_drive_t	*mhd_create_drive(mhd_drive_set_t *defaultsp,
			    char *rname, int *fdp, mhd_error_t *mhep);
extern	int		mhd_create_drives(char *path, mhd_error_t *mhep);

/* mhd_error.c */
extern	void		mhd_clrerror(mhd_error_t *mhep);
extern	int		mhd_error(mhd_error_t *mhep, int errnum, char *name);
/*PRINTFLIKE2*/
extern	void		mhde_perror(mhd_error_t *mhep, const char *fmt, ...);
/*PRINTFLIKE1*/
extern	void		mhd_perror(const char *fmt, ...);
/*PRINTFLIKE1*/
extern	void		mhd_eprintf(const char *fmt, ...);

/* mhd_failfast.c */
extern	int		mhd_ff_disarm(mhd_drive_set_t *sp, mhd_error_t *mhep);
extern	int		mhd_ff_open(mhd_drive_set_t *sp, mhd_error_t *mhep);
extern	int		mhd_ff_close(mhd_drive_set_t *sp, mhd_error_t *mhep);
extern	int		mhd_ff_rearm(mhd_drive_set_t *sp, mhd_error_t *mhep);
extern	void		mhd_ff_die(mhd_drive_set_t *sp);
extern	void		mhd_ff_check(mhd_drive_set_t *sp);

/* mhd_init.c */
extern	void		mhd_exit(int eval);
extern	int		mhd_init(struct svc_req *rqstp, int amode,
			    mhd_error_t *mhep);

/* mhd_ioctl.c */
extern	int		tk_own(mhd_set_t *mhsp, mhd_error_t *mhep);
extern	int		rel_own(mhd_set_t *mhsp, mhd_error_t *mhep);
extern	int		get_status(mhd_status_args_t *argsp,
			    mhd_status_res_t *resp);

/* mhd_mem.c */
extern	void		*Malloc(size_t s);
extern	void		*Zalloc(size_t s);
extern	void		*Realloc(void *p, size_t s);
extern	void		*Calloc(size_t n, size_t s);
extern	char		*Strdup(const char *p);
extern	void		Free(void *p);

/* mhd_set.c */
extern	void		mhd_add_drive_to_set(mhd_drive_set_t *sp,
			    mhd_drive_t *dp);
extern	void		mhd_del_drive_from_set(mhd_drive_t *dp);
extern	mhd_drive_set_t	*mhd_create_set(mhd_set_t *mhsp, mhd_opts_t options,
			    mhd_drive_list_t *dlp, mhd_error_t *mhep);
extern	mhd_drive_t	*mhd_find_drive(char *rname);
extern	int		mhd_list_drives(char *path, mhd_did_flags_t flags,
			    mhd_list_res_t *resultsp, mhd_error_t *mhep);
extern	int		mhd_release_drives(mhd_set_t *mhsp, mhd_opts_t options,
			    mhd_error_t *mhep);
extern	int		mhd_reserve_drives(mhd_set_t *mhsp,
			    mhd_mhiargs_t *timeoutp, mhd_ff_mode_t ff_mode,
			    mhd_opts_t options, mhd_error_t *mhep);
extern	int		mhd_status_drives(mhd_set_t *mhsp, mhd_opts_t options,
			    mhd_drive_status_t **status, mhd_error_t *mhep);

/* mhd_synch.c */
extern	void		mhd_cv_init(cond_t *cvp);
extern	void		mhd_cv_destroy(cond_t *cvp);
extern	void		mhd_cv_wait(cond_t *cvp, mutex_t *mp);
extern	void		mhd_cv_timedwait(cond_t *cvp, mutex_t *mp,
			    mhd_msec_t to);
extern	void		mhd_cv_broadcast(cond_t *cvp);
extern	void		mhd_mx_init(mutex_t *mp);
extern	void		mhd_mx_destroy(mutex_t *mp);
extern	void		mhd_mx_lock(mutex_t *mp);
extern	void		mhd_mx_unlock(mutex_t *mp);
extern	void		mhd_rw_rdlock(rwlock_t *rwlp);
extern	void		mhd_rw_wrlock(rwlock_t *rwlp);
extern	void		mhd_rw_unlock(rwlock_t *rwlp);

/* mhd_time.c */
extern	mhd_msec_t	mhd_time();

#ifdef	__cplusplus
}
#endif

#endif	/* _MHD_LOCAL_H */
