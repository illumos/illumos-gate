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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_FLOCK_H
#define	_SYS_FLOCK_H

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/t_lock.h>		/* for <sys/callb.h> */
#include <sys/callb.h>
#include <sys/param.h>
#include <sys/zone.h>
#if defined(_KERNEL)
#include <sys/file.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Private declarations and instrumentation for local locking.
 */

/*
 * The flag passed to fs_frlock() may be ORed together with either
 * `F_REMOTELOCK' or `F_PXFSLOCK'.  Since this flag is initialized using the
 * `f_flag' field in the `file' structure, and that field is an unsigned short,
 * we do not use the first 2 bytes.
 */
#define	F_REMOTELOCK	(0x01 << 16) /* Set if NLM lock */
#define	F_PXFSLOCK	(0x02 << 16) /* Clustering: set if PXFS lock */

/*
 * The command passed to reclock() is made by ORing together one or more of
 * the following values.
 */

#define	INOFLCK		0x01	/* Vnode is locked when reclock() is called. */
#define	SETFLCK		0x02	/* Set a file lock. */
#define	SLPFLCK		0x04	/* Wait if blocked. */
#define	RCMDLCK		0x08	/* F_REMOTELOCK specified */
#define	PCMDLCK		0x10	/* Clustering: F_PXFSLOCK specified */
#define	NBMLCK		0x20	/* non-blocking mandatory locking */

/*
 * Special pid value that can be passed to cleanlocks().  It means that
 * cleanlocks() should flush all locks for the given sysid, not just the
 * locks owned by a specific process.
 */

#define	IGN_PID		(-1)

/* file locking structure (connected to vnode) */

#define	l_end		l_len

/*
 * The lock manager is allowed to use unsigned offsets and lengths, though
 * regular Unix processes are still required to use signed offsets and
 * lengths.
 */
typedef ulong_t u_off_t;

#define	MAX_U_OFF_T	((u_off_t)~0)
#define	MAX_U_OFFSET_T	((u_offset_t)~0)

/*
 * define MAXEND as the largest positive value the signed offset_t will hold.
 */
#define	MAXEND		MAXOFFSET_T

/*
 * Definitions for accessing the l_pad area of struct flock.  The
 * descriminant of the pad_info_t union is the fcntl command used in
 * conjunction with the flock struct.
 */

typedef union {
	int	pi_pad[4];		/* (original pad area) */
	int	pi_has_rmt;		/* F_HASREMOTELOCKS */
} pad_info_t;

#define	l_has_rmt(flockp)	(((pad_info_t *)((flockp)->l_pad))->pi_has_rmt)

/*
 * Optional callbacks for blocking lock requests.  Each function is called
 * twice.
 * The first call is after the request is put in the "sleeping" list, but
 *   before waiting.  At most one callback may return a callb_cpr_t object;
 *   the others must return NULL.  If a callb_cpr_t is returned, the thread
 *   will be marked as safe to suspend while waiting for the lock.
 * The second call is after the request wakes up.  Note that the request
 *   might not have been granted at the second call (e.g., the request was
 *   signalled).
 * New callbacks should be added to the head of the list.  For the first
 * call the list is walked in order.  For the second call the list is
 * walked backwards (in case the callbacks need to reacquire locks).
 */

typedef enum {FLK_BEFORE_SLEEP, FLK_AFTER_SLEEP} flk_cb_when_t;

struct flk_callback {
	struct flk_callback *cb_next;	/* circular linked list */
	struct flk_callback *cb_prev;
	callb_cpr_t	*(*cb_callback)(flk_cb_when_t, void *);	/* fcn ptr */
	void		*cb_data;	/* ptr to callback data */
};

typedef struct flk_callback flk_callback_t;

/*
 * This structure members are not used any more inside the kernel.
 * The structure is used for casting some pointer assignments only.
 */

typedef struct filock {
	kcondvar_t cv;
	struct	flock set;	/* contains type, start, and end */
	struct	{
		int granted_flag;	/* granted flag */
		struct filock *blk;	/* for sleeping locks only */
		struct attacher *blocking_list;
		struct attacher *my_attacher;
	}	stat;
	struct	filock *prev;
	struct	filock *next;
} filock_t;

#define	FLP_DELAYED_FREE	-1	/* special value for granted_flag */

/* structure that contains list of locks to be granted */

#define	MAX_GRANT_LOCKS		52

typedef struct grant_lock {
	struct filock *grant_lock_list[MAX_GRANT_LOCKS];
	struct grant_lock *next;
} grant_lock_t;

/*
 * Provide a way to cleanly enable and disable Network Lock Manager locking
 * requests (i.e., requests from remote clients):
 *    FLK_NLM_SHUTTING_DOWN: Forces all blocked NLM requests to bail out
 *	and return ENOLCK.
 *    FLK_NLM_DOWN: Clears all granted NLM server locks.  Both status
 *	codes cause new NLM lock requests to fail immediately with ENOLCK.
 *    FLK_NLM_UP: Changes the state of all locks to UP, after a server has
 *	shutdown and is restarting on the same node.
 */

/*
 * Enumerated type of the four possible states an NLM server can be in.
 */
typedef enum {
	FLK_NLM_UP,
	FLK_NLM_SHUTTING_DOWN,
	FLK_NLM_DOWN,
	FLK_NLM_UNKNOWN
} flk_nlm_status_t;

/*
 * Provide a way to cleanly enable and disable lock manager locking
 * requests (i.e., requests from remote clients).  FLK_WAKEUP_SLEEPERS
 * forces all blocked lock manager requests to bail out and return ENOLCK.
 * FLK_LOCKMGR_DOWN clears all granted lock manager locks.  Both status
 * codes cause new lock manager requests to fail immediately with ENOLCK.
 */

typedef enum {
    FLK_LOCKMGR_UP,
    FLK_WAKEUP_SLEEPERS,
    FLK_LOCKMGR_DOWN
} flk_lockmgr_status_t;

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

/*
 * The following structure is used to hold a list of locks returned
 * by the F_ACTIVELIST or F_SLEEPINGLIST commands to fs_frlock.
 *
 * N.B. The lists returned by these commands are dynamically
 * allocated and must be freed by the caller.  The vnodes returned
 * in the lists are held and must be released when the caller is done.
 */

typedef struct locklist {
	struct vnode *ll_vp;
	struct flock64 ll_flock;
	struct locklist *ll_next;
} locklist_t;

#define	FLK_QUERY_ACTIVE	0x1
#define	FLK_QUERY_SLEEPING	0x2

#if defined(_KERNEL)
int	ofdlock(file_t *, int, struct flock64 *, int, u_offset_t);
void	ofdcleanlock(file_t *);
#endif
int	reclock(struct vnode *, struct flock64 *, int, int, u_offset_t,
		flk_callback_t *);
int	chklock(struct vnode *, int, u_offset_t, ssize_t, int,
		caller_context_t *);
int	convoff(struct vnode *, struct flock64 *, int, offset_t);
void	cleanlocks(struct vnode *, pid_t, int);
locklist_t *flk_get_sleeping_locks(int sysid, pid_t pid);
locklist_t *flk_get_active_locks(int sysid, pid_t pid);
locklist_t *flk_active_locks_for_vp(const struct vnode *vp);
locklist_t *flk_active_nbmand_locks_for_vp(const struct vnode *vp);
locklist_t *flk_active_nbmand_locks(pid_t pid);
void	flk_free_locklist(locklist_t *);
int	flk_convert_lock_data(struct vnode *, struct flock64 *,
		u_offset_t *, u_offset_t *, offset_t);
int	flk_check_lock_data(u_offset_t, u_offset_t, offset_t);
int	flk_has_remote_locks(struct vnode *vp);
void	flk_set_lockmgr_status(flk_lockmgr_status_t status);
int	flk_sysid_has_locks(int sysid, int chklck);
int	flk_has_remote_locks_for_sysid(vnode_t *vp, int);
void	flk_init_callback(flk_callback_t *,
		callb_cpr_t *(*)(flk_cb_when_t, void *), void *);
void	flk_add_callback(flk_callback_t *,
		callb_cpr_t *(*)(flk_cb_when_t, void *), void *,
		flk_callback_t *);
void	flk_del_callback(flk_callback_t *);
callb_cpr_t *flk_invoke_callbacks(flk_callback_t *, flk_cb_when_t);

/* Zones hooks */
extern	zone_key_t flock_zone_key;

void	*flk_zone_init(zoneid_t);
void	flk_zone_fini(zoneid_t, void *);

/* Clustering hooks */
void	cl_flk_set_nlm_status(int nlmid, flk_nlm_status_t nlm_state);
void	cl_flk_remove_locks_by_sysid(int sysid);
int	cl_flk_has_remote_locks_for_nlmid(struct vnode *vp, int nlmid);
void	cl_flk_change_nlm_state_to_unknown(int nlmid);
void	cl_flk_delete_pxfs_locks(struct vfs *vfsp, int pxfsid);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FLOCK_H */
