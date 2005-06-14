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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_FS_UFS_QUOTA_H
#define	_SYS_FS_UFS_QUOTA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Lock order for the quota sub-system:
 *
 *  vfs_dqrwlock > ip.i_contents > dq_cachelock > dquot.dq_lock > dq_freelock
 *  vfs_dqrwlock > ip.i_contents > dq_cachelock >                 dq_freelock
 *  vfs_dqrwlock > ip.i_contents >                dquot.dq_lock > dq_freelock
 *  vfs_dqrwlock > ip.i_contents >                                dq_freelock
 *  vfs_dqrwlock > ip.i_contents > dq_cachelock > dquot.dq_lock > qip.i_contents
 */

/*
 * The following constants define the default amount of time given a user
 * before the soft limits are treated as hard limits (usually resulting
 * in an allocation failure). These may be  modified by the quotactl
 * system call with the Q_SETQLIM or Q_SETQUOTA commands.
 */

#define	DQ_FTIMELIMIT	(7 * 24*60*60)		/* 1 week */
#define	DQ_BTIMELIMIT	(7 * 24*60*60)		/* 1 week */

/*
 * The dqblk structure defines the format of the disk quota file
 * (as it appears on disk) - the file is an array of these structures
 * indexed by user number.  The setquota sys call establishes the inode
 * for each quota file (a pointer is retained in the mount structure).
 */

struct dqblk {
	uint32_t  dqb_bhardlimit; /* absolute limit on disk blks alloc */
	uint32_t  dqb_bsoftlimit; /* preferred limit on disk blks */
	uint32_t  dqb_curblocks;  /* current block count */
	uint32_t  dqb_fhardlimit; /* maximum # allocated files + 1 */
	uint32_t  dqb_fsoftlimit; /* preferred file limit */
	uint32_t  dqb_curfiles;   /* current # allocated files */
	uint32_t  dqb_btimelimit; /* time limit for excessive disk use */
	uint32_t  dqb_ftimelimit; /* time limit for excessive files */
};

#define	dqoff(UID)	(((offset_t)(UID) * sizeof (struct dqblk)))

/*
 * The dquot structure records disk usage for a user on a filesystem.
 * There is one allocated for each quota that exists on any filesystem
 * for the current user. A cache is kept of recently used entries.
 * Active inodes have a pointer to the dquot associated with them.
 */
struct  dquot {
	struct dquot *dq_forw, *dq_back; /* hash list, MUST be first entry */
	struct dquot *dq_freef, *dq_freeb; /* free list */
	short	dq_flags;
#define	DQ_ERROR	0x01		/* An error occurred reading dq */
#define	DQ_MOD		0x04		/* this quota modified since read */
#define	DQ_BLKS		0x10		/* has been warned about blk limit */
#define	DQ_FILES	0x20		/* has been warned about file limit */
#define	DQ_TRANS	0x40		/* logging ufs operation started */
	ulong_t	dq_cnt;			/* count of active references */
	uid_t	dq_uid;			/* user this applies to */
	struct ufsvfs *dq_ufsvfsp;	/* filesystem this relates to */
	offset_t dq_mof;		/* master disk offset of quota record */
	struct dqblk dq_dqb;		/* actual usage & quotas */
#ifdef _KERNEL
	kmutex_t	dq_lock;	/* per dq structure lock */
#endif /* _KERNEL */
};

#define	dq_bhardlimit	dq_dqb.dqb_bhardlimit
#define	dq_bsoftlimit	dq_dqb.dqb_bsoftlimit
#define	dq_curblocks	dq_dqb.dqb_curblocks
#define	dq_fhardlimit	dq_dqb.dqb_fhardlimit
#define	dq_fsoftlimit	dq_dqb.dqb_fsoftlimit
#define	dq_curfiles	dq_dqb.dqb_curfiles
#define	dq_btimelimit	dq_dqb.dqb_btimelimit
#define	dq_ftimelimit	dq_dqb.dqb_ftimelimit

/*
 * flags for vfs_qflags in ufsvfs struct
 */
#define	MQ_ENABLED	0x01		/* quotas are enabled */

#if defined(_KERNEL)

/*
 * dquot chach hash chain headers
 */
#define	NDQHASH		64			/* smallish power of two */
#define	DQHASH(uid, mp) \
	(((uintptr_t)(mp) + (unsigned)(uid)) & (NDQHASH-1))

struct	dqhead {
	struct	dquot	*dqh_forw;	/* MUST be first */
	struct	dquot	*dqh_back;	/* MUST be second */
};

extern struct dqhead dqhead[NDQHASH];

extern struct dquot *dquot, *dquotNDQUOT;
extern int ndquot;
extern krwlock_t dq_rwlock;		/* quota sub-system init lock */
extern int quotas_initialized;		/* quota sub-system init flag */

extern void qtinit();
extern void qtinit2();
extern struct dquot *getinoquota(struct inode *);
extern int chkdq(struct inode *ip, long, int, struct cred *, char **errp,
		size_t *lenp);
extern int chkiq(struct ufsvfs *, int, struct inode *, uid_t, int,
		struct cred *, char **errp, size_t *lenp);
extern void dqrele(struct dquot *);
extern int closedq(struct ufsvfs *, struct cred *);
extern int qsync(struct ufsvfs *);

extern int getdiskquota(uid_t, struct ufsvfs *, int, struct dquot **);
extern void dqput(struct dquot *);
extern void dqupdate(struct dquot *);
extern void dqinval(struct dquot *);
extern void invalidatedq(struct ufsvfs *);

extern int quotactl(struct vnode *, intptr_t, int flag, struct cred *);

#endif	/* _KERNEL */

/*
 * Definitions for the 'quotactl' system call.
 */
#define	Q_QUOTAON	1	/* turn quotas on */
#define	Q_QUOTAOFF	2	/* turn quotas off */
#define	Q_SETQUOTA	3	/* set disk limits & usage */
#define	Q_GETQUOTA	4	/* get disk limits & usage */
#define	Q_SETQLIM	5	/* set disk limits only */
#define	Q_SYNC		6	/* update disk copy of quota usages */
#define	Q_ALLSYNC	7	/* update disk copy of quota usages for all */

#ifdef _SYSCALL32
/* ILP32 compatible structure for LP64 kernel. */
struct quotctl32 {
	int		op;
	uid_t		uid;
	uint32_t	addr;
};
#endif /* SYSCALL32 */

struct quotctl {
	int	op;
	uid_t	uid;
	caddr_t	addr;
};

#define	Q_QUOTACTL	0x00030189	/* ioctl command for quotactl */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_QUOTA_H */
