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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */
/* Copyright 2015 Joyent, Inc. */

#ifndef _SYS_FILE_H
#define	_SYS_FILE_H

#include <sys/t_lock.h>
#ifdef _KERNEL
#include <sys/model.h>
#include <sys/user.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * fio locking:
 *   f_rwlock	protects f_vnode and f_cred
 *   f_tlock	protects the rest
 *
 *   The purpose of locking in this layer is to keep the kernel
 *   from panicing if, for example, a thread calls close() while
 *   another thread is doing a read().  It is up to higher levels
 *   to make sure 2 threads doing I/O to the same file don't
 *   screw each other up.
 */
/*
 * One file structure is allocated for each open/creat/pipe call.
 * Main use is to hold the read/write pointer (and OFD locks) associated with
 * each open file.
 */
typedef struct file {
	kmutex_t	f_tlock;	/* short term lock */
	ushort_t	f_flag;
	ushort_t	f_flag2;	/* extra flags (FSEARCH, FEXEC) */
	struct vnode	*f_vnode;	/* pointer to vnode structure */
	offset_t	f_offset;	/* read/write character pointer */
	struct cred	*f_cred;	/* credentials of user who opened it */
	struct f_audit_data	*f_audit_data;	/* file audit data */
	int		f_count;	/* reference count */
	struct filock *f_filock;	/* ptr to single lock_descriptor_t */
} file_t;

/*
 * fpollinfo struct - used by poll caching to track who has polled the fd
 */
typedef struct fpollinfo {
	struct _kthread		*fp_thread;	/* thread caching poll info */
	struct fpollinfo	*fp_next;
} fpollinfo_t;

/* f_flag */

#define	FOPEN		0xffffffff
#define	FREAD		0x01	/* <sys/aiocb.h> LIO_READ must be identical */
#define	FWRITE		0x02	/* <sys/aiocb.h> LIO_WRITE must be identical */
#define	FNDELAY		0x04
#define	FAPPEND		0x08
#define	FSYNC		0x10	/* file (data+inode) integrity while writing */
#define	FREVOKED	0x20	/* Object reuse Revoked file */
#define	FDSYNC		0x40	/* file data only integrity while writing */
#define	FNONBLOCK	0x80

#define	FMASK		0xa0ff	/* all flags that can be changed by F_SETFL */

/* open-only modes */

#define	FCREAT		0x0100
#define	FTRUNC		0x0200
#define	FEXCL		0x0400
#define	FASYNC		0x1000	/* asyncio in progress pseudo flag */
#define	FOFFMAX		0x2000	/* large file */
#define	FXATTR		0x4000	/* open as extended attribute */
#define	FNOCTTY		0x0800
#define	FRSYNC		0x8000	/* sync read operations at same level of */
				/* integrity as specified for writes by */
				/* FSYNC and FDSYNC flags */

#define	FNODSYNC	0x10000 /* fsync pseudo flag */

#define	FNOFOLLOW	0x20000	/* don't follow symlinks */
#define	FNOLINKS	0x40000	/* don't allow multiple hard links */
#define	FIGNORECASE	0x80000 /* request case-insensitive lookups */
#define	FXATTRDIROPEN	0x100000  /* only opening hidden attribute directory */

/* f_flag2 (open-only) */

#define	FSEARCH		0x200000	/* O_SEARCH = 0x200000 */
#define	FEXEC		0x400000	/* O_EXEC = 0x400000 */

#define	FCLOEXEC	0x800000	/* O_CLOEXEC = 0x800000 */

#ifdef _KERNEL

/*
 * This is a flag that is set on f_flag2, but is never user-visible
 */
#define	FEPOLLED	0x8000

/*
 * Fake flags for driver ioctl calls to inform them of the originating
 * process' model.  See <sys/model.h>
 *
 * Part of the Solaris 2.6+ DDI/DKI
 */
#define	FMODELS	DATAMODEL_MASK	/* Note: 0x0ff00000 */
#define	FILP32	DATAMODEL_ILP32
#define	FLP64	DATAMODEL_LP64
#define	FNATIVE	DATAMODEL_NATIVE

/*
 * Large Files: The macro gets the offset maximum (refer to LFS API doc)
 * corresponding to a file descriptor. We had the choice of storing
 * this value in file descriptor. Right now we only have two
 * offset maximums one if MAXOFF_T and other is MAXOFFSET_T. It is
 * inefficient to store these two values in a separate member in
 * file descriptor. To avoid wasting spaces we define this macro.
 * The day there are more than two offset maximum we may want to
 * rewrite this macro.
 */

#define	OFFSET_MAX(fd)	((fd->f_flag & FOFFMAX) ? MAXOFFSET_T : MAXOFF32_T)

/*
 * Fake flag => internal ioctl call for layered drivers.
 * Note that this flag deliberately *won't* fit into
 * the f_flag field of a file_t.
 *
 * Part of the Solaris 2.x DDI/DKI.
 */
#define	FKIOCTL		0x80000000	/* ioctl addresses are from kernel */

/*
 * Fake flag => this time to specify that the open(9E)
 * comes from another part of the kernel, not userland.
 *
 * Part of the Solaris 2.x DDI/DKI.
 */
#define	FKLYR		0x40000000	/* layered driver call */

#endif	/* _KERNEL */

/* miscellaneous defines */

#ifndef L_SET
#define	L_SET	0	/* for lseek */
#endif /* L_SET */

/*
 * For flock(3C).  These really don't belong here but for historical reasons
 * the interface defines them to be here.
 */
#define	LOCK_SH	1
#define	LOCK_EX	2
#define	LOCK_NB	4
#define	LOCK_UN	8

#if !defined(_STRICT_SYMBOLS)
extern int flock(int, int);
#endif

#if defined(_KERNEL)

/*
 * Routines dealing with user per-open file flags and
 * user open files.
 */
struct proc;	/* forward reference for function prototype */
struct vnodeops;
struct vattr;

extern file_t *getf(int);
extern void releasef(int);
extern void areleasef(int, uf_info_t *);
#ifndef	_BOOT
extern void closeall(uf_info_t *);
#endif
extern void flist_fork(uf_info_t *, uf_info_t *);
extern int closef(file_t *);
extern int closeandsetf(int, file_t *);
extern int ufalloc_file(int, file_t *);
extern int ufalloc(int);
extern int ufcanalloc(struct proc *, uint_t);
extern int falloc(struct vnode *, int, file_t **, int *);
extern void finit(void);
extern void unfalloc(file_t *);
extern void setf(int, file_t *);
extern int f_getfd_error(int, int *);
extern char f_getfd(int);
extern int f_setfd_error(int, int);
extern void f_setfd(int, char);
extern int f_getfl(int, int *);
extern int f_badfd(int, int *, int);
extern int fassign(struct vnode **, int, int *);
extern void fcnt_add(uf_info_t *, int);
extern void close_exec(uf_info_t *);
extern void clear_stale_fd(void);
extern void clear_active_fd(int);
extern void free_afd(afd_t *afd);
extern int fgetstartvp(int, char *, struct vnode **);
extern int fsetattrat(int, char *, int, struct vattr *);
extern int fisopen(struct vnode *);
extern void delfpollinfo(int);
extern void addfpollinfo(int);
extern int sock_getfasync(struct vnode *);
extern int files_can_change_zones(void);
#ifdef DEBUG
/* The following functions are only used in ASSERT()s */
extern void checkwfdlist(struct vnode *, fpollinfo_t *);
extern void checkfpollinfo(void);
extern int infpollinfo(int);
#endif	/* DEBUG */

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FILE_H */
