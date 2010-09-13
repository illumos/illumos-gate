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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_FILE_H
#define	_SYS_FILE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One file structure is allocated for each open/creat/pipe call.
 * Main use is to hold the read/write pointer associated with
 * each open file.
 */

typedef struct file
{
	struct file  *f_next;		/* pointer to next entry */
	struct file  *f_prev;		/* pointer to previous entry */
	ushort_t f_flag;
	cnt_t	f_count;		/* reference count */
	struct vnode *f_vnode;		/* pointer to vnode structure */
	off_t	f_offset;		/* read/write character pointer */
	struct	cred *f_cred;		/* credentials of user who opened it */
	struct	aioreq *f_aiof;		/* aio file list forward link	*/
	struct	aioreq *f_aiob;		/* aio file list backward link	*/
/* #ifdef MERGE */
	struct	file *f_slnk;		/* XENIX semaphore queue */
/* #endif MERGE */
} file_t;


#ifndef _SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

/* flags - see also fcntl.h */

#ifndef FOPEN
#define	FOPEN	0xFFFFFFFF
#define	FREAD	0x01
#define	FWRITE	0x02
#define	FNDELAY	0x04
#define	FAPPEND	0x08
#define	FSYNC	0x10
#define	FNONBLOCK	0x80	/* Non-blocking flag (POSIX).	*/

#define	FMASK	0xff		/* should be disjoint from FASYNC */

/* open only modes */

#define	FCREAT	0x100
#define	FTRUNC	0x200
#define	FEXCL	0x400
#define	FNOCTTY	0x800		/* don't allocate controlling tty (POSIX). */
#define	FASYNC	0x1000		/* asyncio is in progress */
#define	FPRIV	0x1000		/* open with private access */

/* file descriptor flags */
#define	FCLOSEXEC	001	/* close on exec */
#endif

/* record-locking options. */
#define	F_ULOCK		0	/* Unlock a previously locked region */
#define	F_LOCK		1	/* Lock a region for exclusive use */
#define	F_TLOCK		2	/* Test and lock a region for exclusive use */
#define	F_TEST		3	/* Test a region for other processes locks */

/*
 * flock operations.
 */
#define	LOCK_SH		1	/* shared lock */
#define	LOCK_EX		2	/* exclusive lock */
#define	LOCK_NB		4	/* don't block when locking */
#define	LOCK_UN		8	/* unlock */

/*
 * Access call.
 */
#define	F_OK		0	/* does file exist */
#define	X_OK		1	/* is it executable by caller */
#define	W_OK		2	/* writable by caller */
#define	R_OK		4	/* readable by caller */

/*
 * Lseek call.
 */
#ifndef L_SET
#define	L_SET		0	/* absolute offset */
#define	L_INCR		1	/* relative to current offset */
#define	L_XTND		2	/* relative to end of file */
#endif


/* miscellaneous defines */

#define	NULLFP ((struct file *)0)

/*
 * Count of number of entries in file list.
 */
extern unsigned int filecnt;

/*
 * routines dealing with user per-open file flags and
 * user open files.  getf() is declared in systm.h.  It
 * probably belongs here.
 */
#if defined(__STDC__)
extern void setf(int, file_t *);
extern void setpof(int, char);
extern char getpof(int);
extern int fassign(struct vnode **, int, int *);
#else
extern void setf(), setpof();
extern char getpof();
extern int fassign();
#endif

extern off_t lseek();

#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	!defined(__PRAGMA_REDEFINE_EXTNAME))
#if defined(__STDC__)
extern off64_t lseek64(int, off64_t, int);
#else
extern off64_t llseek64();
#endif
#endif  /* _LARGEFILE64_SOURCE... */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FILE_H */
