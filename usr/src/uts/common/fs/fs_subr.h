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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_SUBR_H
#define	_SYS_FS_SUBR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <vm/page.h>
#include <sys/acl.h>
#include <sys/share.h>
#include <sys/flock.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Utilities shared among file system implementations.
 */

#ifdef	_KERNEL

extern int	fs_nosys();
extern int	fs_inval();
extern int	fs_notdir();
extern int	fs_nosys_map(struct vnode *, offset_t, struct as *, caddr_t *,
			size_t, uchar_t, uchar_t, uint_t, struct cred *);
extern int	fs_nosys_addmap(struct vnode *, offset_t, struct as *, caddr_t,
			size_t, uchar_t, uchar_t, uint_t, struct cred *);
extern int	fs_nosys_poll(struct vnode *, short, int, short *,
			struct pollhead **);

extern int	fs_sync(struct vfs *, short, cred_t *);
extern int	fs_rwlock(vnode_t *, int, caller_context_t *);
extern void	fs_rwunlock(vnode_t *, int, caller_context_t *);
extern int	fs_cmp(vnode_t *, vnode_t *);
extern int	fs_seek(vnode_t *, offset_t, offset_t *);
extern int	fs_frlock(vnode_t *, int, struct flock64 *, int, offset_t,
			struct flk_callback *, cred_t *);
extern int	fs_setfl(vnode_t *, int, int, cred_t *);
extern int	fs_poll(vnode_t *, short, int, short *, struct pollhead **);
extern int	fs_pathconf(struct vnode *, int, ulong_t *, struct cred *);
extern void	clkset(time_t);
extern void	fs_dispose(struct vnode *, page_t *, int, int, struct cred *);
extern void	fs_nodispose(struct vnode *, page_t *, int, int, struct cred *);
extern int	fs_fab_acl(struct vnode *, vsecattr_t *, int flag, cred_t *);
extern int	fs_shrlock(struct vnode *, int, struct shrlock *, int,
			cred_t *);
extern int	fs_vnevent_nosupport(vnode_t *, vnevent_t);
extern int	fs_vnevent_support(vnode_t *, vnevent_t);
extern int	fs_acl_nontrivial(struct vnode *vp, struct cred *cr);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FS_SUBR_H */
