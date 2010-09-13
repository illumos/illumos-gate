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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_MNTFS_MNTDATA_H
#define	_SYS_MNTFS_MNTDATA_H

#include <sys/vnode.h>
#include <sys/poll.h>
#include <sys/mnttab.h>
#include <sys/zone.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mntelem {
	/* Metadata. */
	struct mntelem 	*mnte_next;
	struct mntelem 	*mnte_prev;
	timespec_t	mnte_birth;
	timespec_t	mnte_death;
	timespec_t	mnte_vfs_ctime;
	int		mnte_refcnt;
	/* Payload. */
	int		mnte_hidden;
	char		*mnte_text;
	size_t		mnte_text_size;
	struct extmnttab mnte_tab;
} mntelem_t;

typedef struct mntsnap {
	timespec_t mnts_time;		/* Time of this snapshot. */
	timespec_t mnts_last_mtime;	/* mnttab modification time. */
	mntelem_t *mnts_first;		/* First element in this snapshot. */
	mntelem_t *mnts_next;		/* Next element to use. */
	int mnts_flags;			/* flags; see below. */
	size_t mnts_nmnts;		/* # of elements in this snapshot. */
	size_t mnts_text_size;		/* Text size for this snapshot. */
	size_t mnts_foffset;		/* File offset of last read(). */
	size_t mnts_ieoffset;		/* Offset of last read() in element. */
} mntsnap_t;

typedef struct mntnode {
	vnode_t *mnt_vnode;	/* vnode for this mntnode */
	vnode_t *mnt_mountvp;	/* vnode mounted on */
	krwlock_t mnt_contents;	/* protects mnt_flags, mnt_read & mnt_ioctl */
	uint_t mnt_flags;	/* flags; see below */
	mntsnap_t mnt_read;	/* data for read() */
	mntsnap_t mnt_ioctl;	/* data for ioctl() */
} mntnode_t;

/*
 * Conversion macros.
 */
#define	VTOM(vp)	((struct mntnode *)(vp)->v_data)
#define	MTOV(pnp)	((pnp)->mnt_vnode)
#define	MTOD(pnp)	((struct mntdata *)MTOV(pnp)->v_vfsp->vfs_data)

#define	MNTFS_ELEM_IS_DEAD(x)	((x)->mnte_death.tv_sec || \
				(x)->mnte_death.tv_nsec)
#define	MNTFS_ELEM_IS_ALIVE(x)	!MNTFS_ELEM_IS_DEAD(x)

#if defined(_KERNEL)

typedef struct mntdata {
	zone_ref_t mnt_zone_ref;	/* zone for mount point */
	uint_t mnt_nopen;		/* count of vnodes open */
	size_t mnt_size;		/* size of last normal snapshot */
	size_t mnt_hidden_size;		/* size of last hidden snapshot */
	timespec_t mnt_mtime;		/* mtime at last normal snapshot */
	timespec_t mnt_hidden_mtime;	/* mtime at last hidden snapshot */
	struct mntnode mnt_node;	/* embedded mntnode */
} mntdata_t;

/*
 * Value for a mntsnap_t's mnts_flags.
 */
#define	MNTS_SHOWHIDDEN	0x1	/* This snapshot contains hidden mounts. */
#define	MNTS_REWIND	0x2	/* This snapshot must be refreshed. */
/*
 * Values for a mntnode_t's mnt_flags.
 */
#define	MNT_SHOWHIDDEN	0x1	/* Include MS_NOMNTTAB mounts in snapshots. */

extern	struct vnodeops	*mntvnodeops;
extern	void mntfs_getmntopts(struct vfs *, char **, size_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MNTFS_MNTDATA_H */
