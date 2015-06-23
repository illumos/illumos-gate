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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_UFS_FILIO_H
#define	_SYS_FS_UFS_FILIO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * _FIOIO
 *
 * struct for _FIOIO ioctl():
 *	Input:
 *		fio_ino	- inode number
 *		fio_gen	- generation number
 *	Output:
 *		fio_fd	- readonly file descriptor
 *
 */

struct fioio {
	ino_t	fio_ino;	/* input : inode number */
	int	fio_gen;	/* input : generation number */
	int	fio_fd;		/* output: readonly file descriptor */
};

#if defined(_SYSCALL32)

struct fioio32 {
	ino32_t	fio_ino;	/* input : inode number */
	int32_t	fio_gen;	/* input : generation number */
	int32_t	fio_fd;		/* output: readonly file descriptor */
};

#endif	/* _SYSCALL32 */

/*
 * _FIOTUNE
 */
struct fiotune {
	int	maxcontig;	/* cluster and directio size */
	int	rotdelay;	/* skip blocks between contig allocations */
	int	maxbpg;		/* currently defaults to 2048 */
	int	minfree;	/* %age to reserve for root */
	int	optim;		/* space or time */
};

/*
 * UFS Logging
 */
typedef struct fiolog {
	uint_t	nbytes_requested;
	uint_t	nbytes_actual;
	int	error;
} fiolog_t;

#define	FIOLOG_ENONE	0
#define	FIOLOG_ETRANS	1
#define	FIOLOG_EROFS	2
#define	FIOLOG_EULOCK	3
#define	FIOLOG_EWLOCK	4
#define	FIOLOG_ECLEAN	5
#define	FIOLOG_ENOULOCK	6

#if defined(_KERNEL)

extern	int	ufs_fiosatime(struct vnode *, struct timeval *, int,
		struct cred *);
extern	int	ufs_fiosdio(struct vnode *, uint_t *, int flag, struct cred *);
extern	int	ufs_fiogdio(struct vnode *, uint_t *, int flag, struct cred *);
extern	int	ufs_fioio(struct vnode *, struct fioio *, int, struct cred *);
extern	int	ufs_fioisbusy(struct vnode *, int *, struct cred *);
extern	int	ufs_fiodirectio(struct vnode *, int, struct cred *);
extern	int	ufs_fiotune(struct vnode *, struct fiotune *, struct cred *);
extern	int	ufs_fiologenable(vnode_t *, fiolog_t *, cred_t *, int);
extern	int	ufs_fiologdisable(vnode_t *, fiolog_t *, cred_t *, int);
extern	int	ufs_fioislog(vnode_t *, uint32_t *, cred_t *, int);
extern	int	ufs_fio_holey(vnode_t *, int, offset_t *);
extern	int	ufs_mark_compressed(struct vnode *vp);

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_FILIO_H */
