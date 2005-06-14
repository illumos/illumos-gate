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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_UFS_PANIC_H
#define	_SYS_FS_UFS_PANIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

/*
 * failures have an associated state
 *  making them bit values simplifies state transition validity checking
 */

typedef enum ufs_failure_states {
	/* initial states, set mostly by thread encountering failure */
	UF_UNDEF	= 0x0000,	/* freshly-allocated memory */
	UF_INIT		= 0x0001,	/* being created */
	UF_QUEUE	= 0x0002,	/* queued for fix thread */

	/* transitional states, set mostly by fix failure thread */
	UF_TRYLCK	= 0x0010,	/* attempting to be locked */
	UF_LOCKED	= 0x0020,	/* error lock set */
	UF_UMOUNT	= 0x0040,	/* attempting to be unmounted */
	UF_FIXING	= 0x0080,	/* fsck started; attempting unlock */

	/* terminal states, once in this state, fix failure thread is done */
	UF_FIXED	= 0x0100,	/* no problemo, man */
	UF_NOTFIX	= 0x0200,	/* can't fix; shouldn't panic */
	UF_REPLICA	= 0x0400,	/* replica panic; fix original only */
	UF_PANIC	= 0x0800,	/* gave up/exceeded limits/can't fix */
					/* not strictly a terminal state, */
					/* because we will do some actions */
					/* if we find a failure in this state */
					/* but those actions will be terminal */

	/* handy, but used only as terminators and placeholders */
	UF_ILLEGAL	= 0xffff,	/* invalid state */
	UF_ALLSTATES	= 0x0ff3	/* all possible state */
} ufs_failure_states_t;

/*
 * each manifestation of a fault (ie. "panic") is
 * associated with a distinct ufs_failure event
 */

typedef struct ufs_failure
{
	struct ufs_failure	*uf_chain[2];	/* protected by ufs_elock mux */
	struct ufs_failure	*uf_orig;	/* if duplicate event, */
						/* here's the original */
	struct ufs_failure	*uf_master;	/* if sharing a logged device */
						/* here's the master failure */
	struct buf		*uf_bp;		/* ptr to buf containing sb */
	kmutex_t		*uf_vfs_lockp;	/* ptr to vfs_lock */
	struct vfs_ufsfx	*uf_vfs_ufsfxp;	/* ptr to fix-on-panic per fs */
	struct vfs		*uf_vfsp;	/* ptr to vfs */
	struct ufsvfs		*uf_ufsvfsp;	/* to match if unmounted */
	dev_t			 uf_dev;	/* device id */
	ufs_failure_states_t	 uf_s;		/* current failure state */
	int			 uf_flags;	/* internal flags */
	time_t			 uf_begin_tm;	/* when did panic begin? */
	time_t			 uf_end_tm;	/* ... end? */
	time_t			 uf_entered_tm;	/* ... was state entered? */
	struct lockfs		 uf_lf;		/* needed to set lockfs lock */
	int			 uf_lf_err;	/* errno if lockfs fails  */
	long			 uf_retry;	/* seconds */
	unsigned		 uf_counter;	/* of state-specific actions */
	kmutex_t		 uf_mutex;	/* protects struct body */
	char		uf_fsname[MAXMNTLEN];	/* for post-unmount errors */
						/* after ufsvfsp is free'd */
	char uf_panic_str[LOCKFS_MAXCOMMENTLEN]; /* original panic message */
						/* XXX could be smaller */
} ufs_failure_t;

#define	uf_next	uf_chain[0]
#define	uf_prev	uf_chain[1]
#define	uf_fs	uf_bp->b_un.b_fs

/*
 * per-filesystem panic event state
 */
typedef struct vfs_ufsfx {
	long		 fx_flags;		/* see ufs_panic.h for the */
	ufs_failure_t	*fx_current;		/* currently being fixed */
} vfs_ufsfx_t;

/*
 * External entry points
 *
 *  ufs_fault(vnode_t *, char *fmt, ...)
 *	replaces calls to cmn_err(CE_PANIC, char *fmt, ...)
 *  	The vnode is any vnode in the filesystem.
 *	ufs_fault returns an errno to bubble up.
 *  ufsfx_init()
 *	is called at modload time to set global values etc.
 *  ufsfx_mount()
 *	is called at mount time to do per-fs initialization
 *	returns 0 (ok) or errno
 *  ufsfx_unmount()
 *	is called at unmount time to prevent spinning on work
 *	to fix an unmounted fs
 *  ufsfx_lockfs()
 *  ufsfx_unlockfs()
 *      are called at upon (un)locking of a fs for coordination
 *  ufsfx_get_failure_qlen()
 *	is called by the hlock thread to coordinate with the fix
 *	failure thread
 */

/*PRINTFLIKE2*/
int	ufs_fault(vnode_t *, char *fmt, ...) __KPRINTFLIKE(2);
void	ufsfx_init(void);
int	ufsfx_mount(struct ufsvfs *, int);
void	ufsfx_unmount(struct ufsvfs *);
void	ufsfx_lockfs(struct ufsvfs *);
void	ufsfx_unlockfs(struct ufsvfs *);
int	ufsfx_get_failure_qlen(void);

extern struct ufs_q ufs_fix;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_PANIC_H */
