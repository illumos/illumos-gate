/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy is of the CDDL is also available via the Internet
 * at http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NFS Lock Manager, client-side
 * Note: depends on (links with) klmmod
 *
 * This file contains all the external entry points of klmops.
 * Basically, this is the "glue" to the BSD nlm code.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/flock.h>

#include <nfs/lm.h>
#include <rpcsvc/nlm_prot.h>
#include "nlm_impl.h"


static struct modlmisc modlmisc = {
	&mod_miscops, "lock mgr calls"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};



/*
 * ****************************************************************
 * module init, fini, info
 */
int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	/* Don't unload. */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*
 * ****************************************************************
 * Stubs listed in modstubs.s
 * These are called from fs/nfs
 */

/*
 * NFSv2 lock/unlock.  Called by nfs_frlock()
 * Uses NLM version 1 (NLM_VERS)
 */
int
lm_frlock(struct vnode *vp, int cmd, struct flock64 *flk, int flags,
    u_offset_t off, struct cred *cr, struct netobj *fh,
    struct flk_callback *flcb)
{
	return (nlm_frlock(vp, cmd, flk, flags, off,
	    cr, fh, flcb, NLM_VERS));
}

/*
 * NFSv3 lock/unlock.  Called by nfs3_frlock()
 * Uses NLM version 4 (NLM4_VERS)
 */
int
lm4_frlock(struct vnode *vp, int cmd, struct flock64 *flk, int flags,
	u_offset_t off, struct cred *cr, struct netobj *fh,
	struct flk_callback *flcb)
{
	int err;
	err = nlm_frlock(vp, cmd, flk, flags, off,
	    cr, fh, flcb, NLM4_VERS);
	return (err);
}

/*
 * NFSv2 shrlk/unshrlk.  See nfs_shrlock
 * Uses NLM version 3 (NLM_VERSX)
 */
int
lm_shrlock(struct vnode *vp, int cmd,
    struct shrlock *shr, int flags, struct netobj *fh)
{
	return (nlm_shrlock(vp, cmd, shr, flags, fh, NLM_VERSX));
}

/*
 * NFSv3 shrlk/unshrlk.  See nfs3_shrlock
 * Uses NLM version 4 (NLM4_VERS)
 */
int
lm4_shrlock(struct vnode *vp, int cmd,
    struct shrlock *shr, int flags, struct netobj *fh)
{
	return (nlm_shrlock(vp, cmd, shr, flags, fh, NLM4_VERS));
}

/*
 * Helper for lm_frlock, lm4_frlock, nfs_lockrelease
 * After getting a lock from a remote lock manager,
 * register the lock locally.
 */
void
lm_register_lock_locally(struct vnode *vp, struct lm_sysid *ls,
    struct flock64 *flk, int flags, u_offset_t offset)
{
	nlm_register_lock_locally(vp, (struct nlm_host *)ls,
	    flk, flags, offset);
}

/*
 * Old RPC service dispatch functions, no longer used.
 * Here only to satisfy modstubs.s references.
 */
void
lm_nlm_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	_NOTE(ARGUNUSED(req, xprt))
}

void
lm_nlm4_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	_NOTE(ARGUNUSED(req, xprt))
}

/*
 * Old internal functions used for reclaiming locks
 * our NFS client holds after some server restarts.
 * The new NLM code does this differently, so these
 * are here only to satisfy modstubs.s references.
 */
void
lm_nlm_reclaim(struct vnode *vp, struct flock64 *flkp)
{
	_NOTE(ARGUNUSED(vp, flkp))
}

void
lm_nlm4_reclaim(struct vnode *vp, struct flock64 *flkp)
{
	_NOTE(ARGUNUSED(vp, flkp))
}
