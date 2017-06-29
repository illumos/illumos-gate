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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef	_SYS_FS_FIFONODE_H
#define	_SYS_FS_FIFONODE_H

#if defined(_KERNEL)
#include <sys/vfs_opreg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Each FIFOFS object is identified by a struct fifonode/vnode pair.
 * This is also the hierarchy
 * flk_lock protects:
 *		fn_mp
 *		fn_tail
 *		fn_count
 *		fn_flag
 *		fn_wcnt
 *		fn_rcnt
 *		fn_open
 *		fn_rsynccnt
 *		fn_wsynccnt
 *		fn_wwaitcnt
 *		fn_atime
 *		fn_mtime
 *		fn_ctime
 *		fn_insync
 *		flk_ref
 *		flk_ocsync
 * ftable lock protects		- actually this is independent
 *		fifoalloc[]
 *		fn_nextp
 *		fn_backp
 */
typedef struct fifolock {
	kmutex_t	flk_lock;	/* fifo lock */
	int		flk_ref;	/* number of fifonodes using this */
	short		flk_ocsync;	/* sync open/close */
	kcondvar_t	flk_wait_cv;	/* conditional for flk_ocsync */
	uint_t		flk_fill[4];	/* cache align lock structure */
} fifolock_t;

typedef struct fifonode fifonode_t;

struct fifonode {
	struct vnode	*fn_vnode;	/* represents the fifo/pipe */
	struct vnode	*fn_realvp;	/* node being shadowed by fifo */
	ino_t		fn_ino;		/* node id for pipes */
	fifonode_t	*fn_dest;	/* the other end of a pipe */
	struct msgb	*fn_mp;		/* message waiting to be read */
	struct msgb	*fn_tail;	/* last message to read */
	fifolock_t	*fn_lock;	/* pointer to per fifo lock */
	uint_t		fn_count;	/* Number of bytes on fn_mp */
	kcondvar_t	fn_wait_cv;	/* fifo conditional variable */
	ushort_t	fn_wcnt;	/* number of writers */
	ushort_t	fn_rcnt;	/* number of readers */
	ushort_t	fn_open;	/* open count of node */
	ushort_t	fn_wsynccnt;	/* fifos waiting for open write sync */
	ushort_t	fn_rsynccnt;	/* fifos waiting for open read sync */
	ushort_t	fn_wwaitcnt;	/* threads waiting to write data */
	time_t		fn_atime;	/* access times */
	time_t		fn_mtime;	/* modification time */
	time_t		fn_ctime;	/* change time */
	fifonode_t	*fn_nextp;	/* next link in the linked list */
	fifonode_t	*fn_backp;	/* back link in linked list */
	struct cred	*fn_pcredp;	/* credential associated with peer */
	pid_t		fn_cpid;	/* original peer pid */
	int		fn_insync;
	uint_t		fn_flag;	/* flags as defined below */
};


typedef struct fifodata {
	fifolock_t	fifo_lock;
	fifonode_t	fifo_fnode[2];
} fifodata_t;

/*
 * Valid flags for fifonodes.
 */
#define	ISPIPE		0x0001	/* fifonode is that of a pipe */
#define	FIFOSEND	0x0002	/* file descriptor at stream head of pipe */
#define	FIFOOPEN	0x0004	/* fifo is opening */
#define	FIFOCLOSE	0x0008	/* fifo is closing */
#define	FIFOCONNLD	0x0010	/* connld pushed on pipe */
#define	FIFOFAST	0x0020	/* FIFO in fast mode */
#define	FIFOWANTR	0x0040	/* reader waiting for data */
#define	FIFOWANTW	0x0080	/* writer waiting to write */
#define	FIFOSETSIG	0x0100	/* I_SETSIG ioctl was issued */
#define	FIFOHIWATW	0x0200	/* We have gone over hi water mark */
#define	FIFORWBUSY	0x0400	/* Fifo is busy in read or write */
#define	FIFOPOLLW	0x0800	/* process waiting on poll write */
#define	FIFOPOLLR	0x1000	/* process waiting on poll read */
#define	FIFOISOPEN	0x2000	/* pipe is open */
#define	FIFOSYNC	0x4000	/* FIFO is waiting for open sync */
#define	FIFOWOCR	0x8000	/* Write open occurred */
#define	FIFOROCR	0x10000	/* Read open occurred */
/*
 * process waiting on poll read on band data
 * this can only occur if we go to streams
 * mode
 */
#define	FIFOPOLLRBAND	0x20000
#define	FIFOSTAYFAST	0x40000	/* don't turn into stream mode */
#define	FIFOWAITMODE	0x80000	/* waiting for the possibility to change mode */

#define	FIFOHIWAT	(16 * 1024)
#define	FIFOLOWAT	(0)

/*
 * Macros to convert a vnode to a fifnode, and vice versa.
 */
#define	VTOF(vp) ((struct fifonode *)((vp)->v_data))
#define	FTOV(fp) ((fp)->fn_vnode)

#if defined(_KERNEL)

/*
 * Fifohiwat defined as a variable is to allow tuning of the high
 * water mark if needed. It is not meant to be released.
 */
#if FIFODEBUG
extern int Fifohiwat;
#else /* FIFODEBUG */
#define	Fifohiwat	FIFOHIWAT
#endif /* FIFODEBUG */

extern struct vnodeops *fifo_vnodeops;
extern const struct fs_operation_def fifo_vnodeops_template[];
extern struct kmem_cache *fnode_cache;
extern struct kmem_cache *pipe_cache;

struct vfssw;
struct queue;

extern int	fifoinit(int, char *);
extern int	fifo_stropen(vnode_t **, int, cred_t *, int, int);
extern int	fifo_open(vnode_t **, int, cred_t *, caller_context_t *);
extern int	fifo_close(vnode_t *, int, int, offset_t, cred_t *,
			caller_context_t *);
extern void	fifo_cleanup(vnode_t *, int);
extern void	fiforemove(fifonode_t *);
extern ino_t	fifogetid(void);
extern vnode_t	*fifovp(vnode_t *, cred_t *);
extern void	makepipe(vnode_t **, vnode_t **);
extern void	fifo_fastflush(fifonode_t *);
extern void	fifo_vfastoff(vnode_t *);
extern void	fifo_fastoff(fifonode_t *);
extern struct streamtab *fifo_getinfo();
extern void	fifo_wakereader(fifonode_t *, fifolock_t *);
extern void	fifo_wakewriter(fifonode_t *, fifolock_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_FIFONODE_H */
