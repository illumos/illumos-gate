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

#ifndef _SYS_LOCKFS_H
#define	_SYS_LOCKFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _SYSCALL32
/*
 * ILP32 version of lockfs, used in ufs_ioctl() to support 32-bit app in
 * LP64 kernel
 */
struct lockfs32 {
	uint32_t	lf_lock;	/* desired lock */
	uint32_t	lf_flags;	/* misc flags */
	uint32_t	lf_key;		/* lock key */
	uint32_t	lf_comlen;	/* length of comment */
	uint32_t	lf_comment;	/* address of comment */
};
#endif /* _SYSCALL32 */

struct lockfs {
	ulong_t		lf_lock;	/* desired lock */
	ulong_t		lf_flags;	/* misc flags */
	ulong_t		lf_key;		/* lock key */
	ulong_t		lf_comlen;	/* length of comment */
	caddr_t		lf_comment;	/* address of comment */
};

/*
 * lf_lock and lf_locking
 */
#define	LOCKFS_ULOCK	0	/* unlock */
#define	LOCKFS_WLOCK	1	/* write  lock */
#define	LOCKFS_NLOCK	2	/* name   lock */
#define	LOCKFS_DLOCK	3	/* delete lock */
#define	LOCKFS_HLOCK	4	/* hard   lock */
#define	LOCKFS_ELOCK	5	/* error  lock */
#define	LOCKFS_ROELOCK	6	/* error  lock (read-only) - unimplemented */
#define	LOCKFS_MAXLOCK	6	/* maximum lock number */

/*
 * lf_flags
 */
#define	LOCKFS_BUSY	0x00000001	/* lock is being set */
#define	LOCKFS_MOD	0x00000002	/* file system modified */

#define	LOCKFS_MAXCOMMENTLEN	1024	/* maximum comment length */

/*
 * some nice checking macros
 */

#define	LOCKFS_IS_BUSY(LF)	((LF)->lf_flags & LOCKFS_BUSY)
#define	LOCKFS_IS_MOD(LF)	((LF)->lf_flags & LOCKFS_MOD)

#define	LOCKFS_CLR_BUSY(LF)	((LF)->lf_flags &= ~LOCKFS_BUSY)
#define	LOCKFS_CLR_MOD(LF)	((LF)->lf_flags &= ~LOCKFS_MOD)

#define	LOCKFS_SET_MOD(LF)	((LF)->lf_flags |= LOCKFS_MOD)
#define	LOCKFS_SET_BUSY(LF)	((LF)->lf_flags |= LOCKFS_BUSY)

#define	LOCKFS_IS_WLOCK(LF)	((LF)->lf_lock == LOCKFS_WLOCK)
#define	LOCKFS_IS_HLOCK(LF)	((LF)->lf_lock == LOCKFS_HLOCK)
#define	LOCKFS_IS_ROELOCK(LF)	((LF)->lf_lock == LOCKFS_ROELOCK)
#define	LOCKFS_IS_ELOCK(LF)	((LF)->lf_lock == LOCKFS_ELOCK)
#define	LOCKFS_IS_ULOCK(LF)	((LF)->lf_lock == LOCKFS_ULOCK)
#define	LOCKFS_IS_NLOCK(LF)	((LF)->lf_lock == LOCKFS_NLOCK)
#define	LOCKFS_IS_DLOCK(LF)	((LF)->lf_lock == LOCKFS_DLOCK)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LOCKFS_H */
