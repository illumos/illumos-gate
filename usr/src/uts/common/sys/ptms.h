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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_PTMS_H
#define	_SYS_PTMS_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Structures and definitions supporting the pseudo terminal
 * drivers. This structure is private and should not be used by any
 * applications.
 */
struct pt_ttys {
	queue_t *ptm_rdq; 	/* master's read queue pointer */
	queue_t *pts_rdq; 	/* slave's read queue pointer */
	mblk_t	*pt_nullmsg;	/* 0-bytes message block for pts close */
	pid_t	 pt_pid;	/* process id (for debugging) */
	minor_t	 pt_minor;	/* Minor number of this pty */
	int	 pt_refcnt;	/* reference count for ptm_rdq/pts_rdq uses */
	ushort_t pt_state;	/* state of master/slave pair */
	kcondvar_t pt_cv;	/* condition variable for exclusive access */
	kmutex_t pt_lock;	/* Per-element lock */
	zoneid_t pt_zoneid;	/* Zone membership for this pty */
	uid_t	 pt_ruid;	/* Real owner of pty */
	gid_t	 pt_rgid;	/* Real group owner of pty */
};

/*
 * pt_state values
 */
#define	PTLOCK		0x01	/* master/slave pair is locked */
#define	PTMOPEN 	0x02  	/* master side is open */
#define	PTSOPEN 	0x04	/* slave side is open */
#define	PTSTTY		0x08	/* slave side is tty */

/*
 * Multi-threading primitives.
 * Values of pt_refcnt: -1 if a writer is accessing the struct
 *			0  if no one is reading or writing
 *			> 0 equals to the number of readers accessing the struct
 */
#define	PT_ENTER_READ(p) {			\
	mutex_enter(&(p)->pt_lock);		\
	while ((p)->pt_refcnt < 0)		\
		cv_wait(&((p)->pt_cv), &(p)->pt_lock);	\
	(p)->pt_refcnt++;			\
	mutex_exit(&(p)->pt_lock);		\
}

#define	PT_ENTER_WRITE(p) {			\
	mutex_enter(&(p)->pt_lock);		\
	while ((p)->pt_refcnt != 0)		\
		cv_wait(&((p)->pt_cv), &(p)->pt_lock);	\
	(p)->pt_refcnt = -1;			\
	mutex_exit(&(p)->pt_lock);		\
}

#define	PT_EXIT_READ(p) {			\
	mutex_enter(&(p)->pt_lock);		\
	ASSERT((p)->pt_refcnt > 0);		\
	if ((--((p)->pt_refcnt)) == 0)		\
		cv_broadcast(&(p)->pt_cv);	\
	mutex_exit(&(p)->pt_lock);		\
}

#define	PT_EXIT_WRITE(p) {			\
	mutex_enter(&(p)->pt_lock);		\
	ASSERT((p)->pt_refcnt == -1);		\
	(p)->pt_refcnt = 0;			\
	cv_broadcast(&(p)->pt_cv);		\
	mutex_exit(&(p)->pt_lock);		\
}

/*
 * ptms_lock and pt_cnt are defined in ptms_conf.c
 */
extern kmutex_t		ptms_lock;
extern dev_info_t 	*pts_dip;	/* private copy of devinfo ptr */

extern void ptms_init(void);
extern struct pt_ttys *pt_ttys_alloc(void);
extern void ptms_close(struct pt_ttys *, uint_t);
extern struct pt_ttys *ptms_minor2ptty(minor_t);
extern int ptms_attach_slave(void);
extern int ptms_minor_valid(minor_t ptmin, uid_t *uid, gid_t *gid);
extern int ptms_minor_exists(minor_t ptmin);
extern void ptms_set_owner(minor_t ptmin, uid_t uid, gid_t gid);
extern major_t ptms_slave_attached(void);

#ifdef DEBUG
extern void ptms_log(char *, uint_t);
extern void ptms_logp(char *, uintptr_t);
#define	DDBG(a, b) ptms_log(a, b)
#define	DDBGP(a, b) ptms_logp(a, b)
#else
#define	DDBG(a, b)
#define	DDBGP(a, b)
#endif

#endif /* _KERNEL */

typedef struct pt_own {
	uid_t	pto_ruid;
	gid_t	pto_rgid;
} pt_own_t;

/*
 * ioctl commands
 *
 *  ISPTM: Determines whether the file descriptor is that of an open master
 *	   device. Return code of zero indicates that the file descriptor
 *	   represents master device.
 *
 * UNLKPT: Unlocks the master and slave devices.  It returns 0 on success. On
 *	   failure, the errno is set to EINVAL indicating that the master
 *	   device is not open.
 *
 *  ZONEPT: Sets the zoneid of the pair of master and slave devices.  It
 *	    returns 0 upon success.  Used to force a pty 'into' a zone upon
 *	    zone entry.
 *
 * PT_OWNER: Sets uid and gid for slave device.  It returns 0 on success.
 *
 */
#define	ISPTM		(('P'<<8)|1)	/* query for master */
#define	UNLKPT		(('P'<<8)|2)	/* unlock master/slave pair */
#define	PTSSTTY		(('P'<<8)|3)	/* set tty flag */
#define	ZONEPT		(('P'<<8)|4)	/* set zone of master/slave pair */
#define	OWNERPT		(('P'<<8)|5)	/* set owner/group for slave device */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PTMS_H */
