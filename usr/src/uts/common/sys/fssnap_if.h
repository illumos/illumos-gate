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

#ifndef	_SYS_FSSNAP_IF_H
#define	_SYS_FSSNAP_IF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/fssnap.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl's for communicating between the user and the fssnapctl device.
 * Also used to communicate between fssnapctl and the file system.
 * Pack fiosnapcreate for amd64 to make struct size same as x86.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct fiosnapcreate {
	int	rootfiledesc;	/* IN  fd for root of fs to be snapshotted */
	int	backfiledesc;	/* IN  backing store file for snapshot data */
	uint_t	snapshotnumber;	/* OUT snapshot number created */
	uint_t	chunksize;	/* IN  chunk size, 0 == fs defined */
	u_offset_t	maxsize; /* IN  maximum size of backing file */
	char	backfilename[MAXPATHLEN];	/* IN  for bookkeeping */
	int	error;		/* OUT error code */
};

struct fiosnapcreate_multi {
	int	rootfiledesc;	/* IN  fd for root of fs to be snapshotted */
	uint_t	snapshotnumber;	/* OUT snapshot number created */
	uint_t	chunksize;	/* IN  chunk size, 0 == fs defined */
	u_offset_t	maxsize; /* IN  max size of entire backing store */
	char	backfilename[MAXPATHLEN];	/* IN  for bookkeeping */
	int	error;		/* OUT error code */
	int	backfilecount;	/* IN  number of backing store files */
	u_offset_t	backfilesize; /* IN maximum size of each backfile */
	int	backfiledesc[1]; /* IN  backing store files for snapshot data */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

struct fiosnapdelete {
	int	rootfiledesc;	/* IN  fd for root of fs to be unsnapshotted */
	uint_t	snapshotnumber;	/* OUT snapshot number deleted */
	int	error;		/* OUT error code */
};

/* ioctl error returns */
#define	FIOCOW_EREADONLY (1)	/* read only file system */
#define	FIOCOW_EBUSY	(2)	/* snapshot already enabled */
#define	FIOCOW_EULOCK	(3)	/* file system is locked */
#define	FIOCOW_EWLOCK	(4)	/* file system could not be write locked */
#define	FIOCOW_EFLUSH	(5)	/* file system could not be flushed */
#define	FIOCOW_ECLEAN	(6)	/* file system may not be stable */
#define	FIOCOW_ENOULOCK	(7)	/* file system could not be unlocked */
#define	FIOCOW_ECHUNKSZ	(8)	/* chunksize is less than fs fragment size */
#define	FIOCOW_ECREATE	(9)	/* could not allocate/create snapshot */
#define	FIOCOW_EBITMAP	(10)	/* error scanning file system bitmaps */
#define	FIOCOW_EBACKFILE (11)	/* bad backing file path passed in */

/*
 * make the control device minor number high so minor numbers match
 * snapshot numbers.
 */
#define	SNAP_CTL_MINOR	(L_MAXMIN32)
#define	SNAP_NAME	"fssnap"
#define	SNAP_CTL_NODE	"ctl"
#define	SNAP_CTL_NAME	SNAP_NAME SNAP_CTL_NODE
#define	SNAP_BLOCK_NAME	SNAP_NAME
#define	SNAP_CHAR_NAME	"r" SNAP_NAME

/* kstat names */
#define	FSSNAP_KSTAT_HIGHWATER		"highwater"
#define	FSSNAP_KSTAT_MNTPT		"mountpoint"
#define	FSSNAP_KSTAT_BFNAME		"bfname"
#define	FSSNAP_KSTAT_NUM		"numericstats"

/* numericstats kstat names */
#define	FSSNAP_KSTAT_NUM_STATE		"state"
#define	FSSNAP_KSTAT_NUM_BFSIZE		"bfsize"
#define	FSSNAP_KSTAT_NUM_MAXSIZE	"maxsize"
#define	FSSNAP_KSTAT_NUM_CHUNKSIZE	"chunksize"
#define	FSSNAP_KSTAT_NUM_CREATETIME	"createtime"

#if defined(_KERNEL)
/*
 * snapshot operations implemented by the loadable snapshot subsystem
 */
struct fssnap_operations {
	void *(*fssnap_create)(chunknumber_t, uint_t, u_offset_t,
	    struct vnode *, int, struct vnode **, char *, u_offset_t);
	void (*fssnap_set_candidate)(void *, chunknumber_t);
	int (*fssnap_is_candidate)(void *, u_offset_t);
	int  (*fssnap_create_done)(void *);
	int (*fssnap_delete)(void *);
	void (*fssnap_strategy)(void *, struct buf *);
};


/* global variables to manage interface operations */
extern struct fssnap_operations snapops;

/* External functions called by file systems that use snapshots */
extern int fssnap_init(void);
extern int fssnap_fini(void);
extern void *fssnap_create(chunknumber_t, uint_t, u_offset_t, struct vnode *,
    int, struct vnode **, char *, u_offset_t);
extern void fssnap_set_candidate(void *, chunknumber_t);
extern int fssnap_is_candidate(void *, u_offset_t);
extern int  fssnap_create_done(void *);
extern int fssnap_delete(void *);
extern void fssnap_strategy(void *, struct buf *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FSSNAP_IF_H */
