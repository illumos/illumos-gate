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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NFS_LM_H
#define	_NFS_LM_H

/*
 * Interface definitions for the NFSv2/v3 lock manager.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/cred.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <rpc/rpc.h>

#ifdef _KERNEL

/*
 * Common interfaces.
 */

struct exportinfo;

/*
 * The numeric sysid is used to identify a host and transport.
 *
 * The local locking code uses (pid, sysid) to uniquely identify a process.
 * This means that the client-side code must doctor up the sysid before
 * registering a lock, so that the local locking code doesn't confuse a
 * remote process with a local process just because they have the same pid.
 * We currently do this by ORing LM_SYSID_CLIENT into the sysid before
 * registering a lock.
 *
 * If you change LM_SYSID and LM_SYSID_MAX, be sure to pick values so that
 * LM_SYSID_MAX > LM_SYSID using signed arithmetic, and don't use zero.
 * You may also need a different way to tag lock manager locks that are
 * registered locally.
 */
#define	LM_SYSID	((sysid_t)0x0001)
#define	LM_SYSID_MAX	((sysid_t)0x3FFF)
#define	LM_SYSID_CLIENT	((sysid_t)0x4000)
#define	LM_NOSYSID	((sysid_t)-1)

/*
 * Struct used to represent a host.
 */
struct lm_sysid;

/*
 * Given a knetconfig and network address, returns a reference to the
 * associated lm_sysid.  The 3rd argument is the hostname to assign to the
 * lm_sysid.  The 4th argument is an output parameter.  It is set non-zero
 * if the returned lm_sysid has a different protocol
 * (knetconfig::knc_proto) than what was requested.
 */
extern struct lm_sysid	  *lm_get_sysid(struct knetconfig *, struct netbuf *,
				char *, bool_t *);
extern void		   lm_rel_sysid(struct lm_sysid *);

/*
 * Return the integer sysid for the given lm_sysid.
 */
extern sysid_t		   lm_sysidt(struct lm_sysid *);

extern void		   lm_free_config(struct knetconfig *);

extern void		   lm_cprsuspend(void);
extern void		   lm_cprresume(void);

/*
 * Client-side interfaces.
 */

extern int		   lm_frlock(struct vnode *vp, int cmd,
				struct flock64 *flk, int flag,
				u_offset_t offset, struct cred *cr,
				netobj *fh, struct flk_callback *);
extern int		   lm_has_sleep(const struct vnode *);
extern void		   lm_register_lock_locally(vnode_t *,
				struct lm_sysid *, struct flock64 *, int,
				u_offset_t);
extern int		   lm_safelock(vnode_t *, const struct flock64 *,
				cred_t *);
extern int		   lm_safemap(const vnode_t *);
extern int		   lm_shrlock(struct vnode *vp, int cmd,
				struct shrlock *shr, int flag, netobj *fh);
extern int		   lm4_frlock(struct vnode *vp, int cmd,
				struct flock64 *flk, int flag,
				u_offset_t offset, struct cred *cr,
				netobj *fh, struct flk_callback *);
extern int		   lm4_shrlock(struct vnode *vp, int cmd,
				struct shrlock *shr, int flag, netobj *fh);

/*
 * Server-side interfaces.
 */

extern void		   lm_unexport(struct exportinfo *);

/*
 * Clustering: functions to encode the nlmid of the node where this NLM
 * server is running in the l_sysid of the flock struct or the s_sysid
 * field of the shrlock struct (respectively).
 */
extern void		   lm_set_nlmid_flk(int *);
extern void		   lm_set_nlmid_shr(int32_t *);
/* Hook for deleting all mandatory NFSv4 file locks held by a remote client */
extern void (*lm_remove_file_locks)(int);

/*
 * The following global variable is the node id of the node where this
 * NLM server is running.
 */
extern int lm_global_nlmid;

/*
 * End of clustering hooks.
 */

/*
 * Return non-zero if the given local vnode is in use.
 */
extern int lm_vp_active(const struct vnode *);

extern sysid_t		   lm_alloc_sysidt(void);
extern void		   lm_free_sysidt(sysid_t);

#endif /* _KERNEL */

#ifdef __STDC__
extern int lm_shutdown(void);
#else
extern int lm_shutdown();
#endif /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* _NFS_LM_H */
