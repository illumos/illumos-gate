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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SHARE_H
#define	_SYS_SHARE_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Maximum size of a shrlock owner.
 * Must be large enough to handle a netobj.
 */
#define	MAX_SHR_OWNER_LEN	1024

/*
 * Contents of shrlock owner field for local share requests
 */
struct shr_locowner {
	pid_t	sl_pid;
	int	sl_id;
};

struct shrlock {
	short	s_access;
	short	s_deny;
	int32_t	s_sysid;	/* 0 if local otherwise passed by lm */
	pid_t	s_pid;		/* 0 if remote otherwise local pid */
	int	s_own_len;	/* if 0 and F_UNSHARE matching sysid */
	caddr_t	s_owner;	/* variable length opaque owner */
};

struct shrlocklist {
	struct shrlock *shr;
	struct shrlocklist *next;
};

#if defined(_KERNEL)
struct flock64;

extern int add_share(struct vnode *, struct shrlock *);
extern int del_share(struct vnode *, struct shrlock *);
extern void cleanshares(struct vnode *, pid_t);
extern void cleanshares_by_sysid(struct vnode *, int32_t);
extern int shr_has_remote_shares(vnode_t *, int32_t);
extern int proc_has_nbmand_share_on_vp(vnode_t *, pid_t);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SHARE_H */
