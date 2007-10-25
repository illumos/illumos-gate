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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/gfs.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <fs/fs_subr.h>
#include <sys/contract.h>
#include <sys/contract_impl.h>
#include <sys/ctfs.h>
#include <sys/ctfs_impl.h>
#include <sys/file.h>
#include <sys/policy.h>

/*
 * CTFS routines for the /system/contract/<type>/bundle vnode.
 * CTFS routines for the /system/contract/<type>/pbundle vnode.
 * CTFS routines for the /system/contract/<type>/<ctid>/events vnode.
 */

/*
 * ctfs_endpoint_open
 *
 * Called by the VOP_OPEN entry points to perform some common checks
 * and set up the endpoint listener, if not already done.
 */
static int
ctfs_endpoint_open(ctfs_endpoint_t *endpt, ct_equeue_t *q, int flag)
{
	if ((flag & ~FNONBLOCK) != (FREAD | FOFFMAX))
		return (EINVAL);

	mutex_enter(&endpt->ctfs_endpt_lock);
	if ((endpt->ctfs_endpt_flags & CTFS_ENDPT_SETUP) == 0) {
		endpt->ctfs_endpt_flags |= CTFS_ENDPT_SETUP;
		if (flag & FNONBLOCK)
			endpt->ctfs_endpt_flags |= CTFS_ENDPT_NBLOCK;
		cte_add_listener(q, &endpt->ctfs_endpt_listener);
	}
	mutex_exit(&endpt->ctfs_endpt_lock);

	return (0);
}

/*
 * ctfs_endpoint inactive
 *
 * Called by the VOP_INACTIVE entry points to perform common listener
 * cleanup.
 */
static void
ctfs_endpoint_inactive(ctfs_endpoint_t *endpt)
{
	mutex_enter(&endpt->ctfs_endpt_lock);
	if (endpt->ctfs_endpt_flags & CTFS_ENDPT_SETUP) {
		endpt->ctfs_endpt_flags = 0;
		cte_remove_listener(&endpt->ctfs_endpt_listener);
	}
	mutex_exit(&endpt->ctfs_endpt_lock);
}

/*
 * ctfs_endpoint_ioctl
 *
 * Implements the common VOP_IOCTL handling for the event endpoints.
 * rprivchk, if true, indicates that event receive requests should
 * check the provided credentials.  This distinction exists because
 * contract endpoints perform their privilege checks at open-time, and
 * process bundle queue listeners by definition may view all events
 * their queues contain.
 */
static int
ctfs_endpoint_ioctl(ctfs_endpoint_t *endpt, int cmd, intptr_t arg, cred_t *cr,
    zone_t *zone, int rprivchk)
{
	uint64_t id, zuniqid;

	zuniqid = zone->zone_uniqid;

	switch (cmd) {
	case CT_ERESET:
		cte_reset_listener(&endpt->ctfs_endpt_listener);
		break;
	case CT_ERECV:
		/*
		 * We pass in NULL for the cred when reading from
		 * process bundle queues and contract queues because
		 * the privilege check was performed at open time.
		 */
		return (cte_get_event(&endpt->ctfs_endpt_listener,
		    endpt->ctfs_endpt_flags & CTFS_ENDPT_NBLOCK,
		    (void *)arg, rprivchk ? cr : NULL, zuniqid, 0));
	case CT_ECRECV:
		return (cte_get_event(&endpt->ctfs_endpt_listener,
		    endpt->ctfs_endpt_flags & CTFS_ENDPT_NBLOCK,
		    (void *)arg, rprivchk ? cr : NULL, zuniqid, 1));
	case CT_ENEXT:
		if (copyin((void *)arg, &id, sizeof (uint64_t)))
			return (EFAULT);
		return (cte_next_event(&endpt->ctfs_endpt_listener, id));
	case CT_ERELIABLE:
		return (cte_set_reliable(&endpt->ctfs_endpt_listener, cr));
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * ctfs_endpoint_poll
 *
 * Called by the VOP_POLL entry points.
 */
static int
ctfs_endpoint_poll(ctfs_endpoint_t *endpt, short events, int anyyet,
    short *reventsp, pollhead_t **php)
{
	if ((events & POLLIN) && endpt->ctfs_endpt_listener.ctl_position) {
		*reventsp = POLLIN;
	} else {
		*reventsp = 0;
		if (!anyyet)
			*php = &endpt->ctfs_endpt_listener.ctl_pollhead;
	}

	return (0);
}

/*
 * ctfs_create_evnode
 *
 * Creates and returns a new evnode.
 */
vnode_t *
ctfs_create_evnode(vnode_t *pvp)
{
	vnode_t *vp;
	ctfs_evnode_t *evnode;
	ctfs_cdirnode_t *cdirnode = pvp->v_data;

	vp = gfs_file_create(sizeof (ctfs_evnode_t), pvp, ctfs_ops_event);
	evnode = vp->v_data;

	/*
	 * We transitively have a hold on the contract through our
	 * parent directory.
	 */
	evnode->ctfs_ev_contract = cdirnode->ctfs_cn_contract;

	return (vp);
}

/*
 * ctfs_ev_access - VOP_ACCESS entry point
 *
 * You only get to access event files for contracts you or your
 * effective user id owns, unless you have a privilege.
 */
/*ARGSUSED*/
static int
ctfs_ev_access(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *cct)
{
	ctfs_evnode_t *evnode = vp->v_data;
	contract_t *ct = evnode->ctfs_ev_contract;
	int error;

	if (mode & (VWRITE | VEXEC))
		return (EACCES);

	if (error = secpolicy_contract_observer(cr, ct))
		return (error);

	return (0);
}

/*
 * ctfs_ev_open - VOP_OPEN entry point
 *
 * Performs the same privilege checks as ctfs_ev_access, and then calls
 * ctfs_endpoint_open to perform the common endpoint initialization.
 */
/* ARGSUSED */
static int
ctfs_ev_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *cct)
{
	ctfs_evnode_t *evnode = (*vpp)->v_data;
	contract_t *ct = evnode->ctfs_ev_contract;
	int error;

	if (error = secpolicy_contract_observer(cr, ct))
		return (error);

	/*
	 * See comment in ctfs_bu_open.
	 */
	return (ctfs_endpoint_open(&evnode->ctfs_ev_listener,
	    &evnode->ctfs_ev_contract->ct_events, flag));
}

/*
 * ctfs_ev_inactive - VOP_INACTIVE entry point
 */
/* ARGSUSED */
static void
ctfs_ev_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	ctfs_evnode_t *evnode;
	vnode_t *pvp = gfs_file_parent(vp);

	/*
	 * We must destroy the endpoint before releasing the parent; otherwise
	 * we will try to destroy a contract with active listeners.  To prevent
	 * this, we grab an extra hold on the parent.
	 */
	VN_HOLD(pvp);
	if ((evnode = gfs_file_inactive(vp)) != NULL) {
		ctfs_endpoint_inactive(&evnode->ctfs_ev_listener);
		kmem_free(evnode, sizeof (ctfs_evnode_t));
	}
	VN_RELE(pvp);
}

/*
 * ctfs_ev_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_ev_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	ctfs_evnode_t *evnode = vp->v_data;

	vap->va_type = VREG;
	vap->va_mode = 0444;
	vap->va_nlink = 1;
	vap->va_size = 0;
	vap->va_ctime = evnode->ctfs_ev_contract->ct_ctime;
	mutex_enter(&evnode->ctfs_ev_contract->ct_events.ctq_lock);
	vap->va_atime = vap->va_mtime =
	    evnode->ctfs_ev_contract->ct_events.ctq_atime;
	mutex_exit(&evnode->ctfs_ev_contract->ct_events.ctq_lock);
	ctfs_common_getattr(vp, vap);

	return (0);
}

/*
 * ctfs_ev_ioctl - VOP_IOCTL entry point
 */
/* ARGSUSED */
static int
ctfs_ev_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	ctfs_evnode_t *evnode = vp->v_data;

	return (ctfs_endpoint_ioctl(&evnode->ctfs_ev_listener, cmd, arg, cr,
	    VTOZONE(vp), 0));
}

/*
 * ctfs_ev_poll - VOP_POLL entry point
 */
/*ARGSUSED*/
static int
ctfs_ev_poll(
	vnode_t *vp,
	short events,
	int anyyet,
	short *reventsp,
	pollhead_t **php,
	caller_context_t *ct)
{
	ctfs_evnode_t *evnode = vp->v_data;

	return (ctfs_endpoint_poll(&evnode->ctfs_ev_listener, events, anyyet,
	    reventsp, php));
}

const fs_operation_def_t ctfs_tops_event[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_ev_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .vop_ioctl = ctfs_ev_ioctl } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_ev_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_ev_access } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = ctfs_ev_inactive } },
	{ VOPNAME_POLL,		{ .vop_poll = ctfs_ev_poll } },
	{ NULL, NULL }
};

/*
 * ctfs_create_pbundle
 *
 * Creates and returns a bunode for a /system/contract/<type>/pbundle
 * file.
 */
vnode_t *
ctfs_create_pbundle(vnode_t *pvp)
{
	vnode_t *vp;
	ctfs_bunode_t *bundle;

	vp = gfs_file_create(sizeof (ctfs_bunode_t), pvp, ctfs_ops_bundle);
	bundle = vp->v_data;
	bundle->ctfs_bu_queue =
	    contract_type_pbundle(ct_types[gfs_file_index(pvp)], curproc);

	return (vp);
}

/*
 * ctfs_create_bundle
 *
 * Creates and returns a bunode for a /system/contract/<type>/bundle
 * file.
 */
vnode_t *
ctfs_create_bundle(vnode_t *pvp)
{
	vnode_t *vp;
	ctfs_bunode_t *bundle;

	vp = gfs_file_create(sizeof (ctfs_bunode_t), pvp, ctfs_ops_bundle);
	bundle = vp->v_data;
	bundle->ctfs_bu_queue =
	    contract_type_bundle(ct_types[gfs_file_index(pvp)]);

	return (vp);
}

/*
 * ctfs_bu_open - VOP_OPEN entry point
 */
/* ARGSUSED */
static int
ctfs_bu_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	ctfs_bunode_t *bunode = (*vpp)->v_data;

	/*
	 * This assumes we are only ever called immediately after a
	 * VOP_LOOKUP.  We could clone ourselves here, but doing so
	 * would make /proc/pid/fd accesses less useful.
	 */
	return (ctfs_endpoint_open(&bunode->ctfs_bu_listener,
	    bunode->ctfs_bu_queue, flag));
}

/*
 * ctfs_bu_inactive - VOP_INACTIVE entry point
 */
/* ARGSUSED */
static void
ctfs_bu_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	ctfs_bunode_t *bunode;
	vnode_t *pvp = gfs_file_parent(vp);

	/*
	 * See comments in ctfs_ev_inactive() above.
	 */
	VN_HOLD(pvp);
	if ((bunode = gfs_file_inactive(vp)) != NULL) {
		ctfs_endpoint_inactive(&bunode->ctfs_bu_listener);
		kmem_free(bunode, sizeof (ctfs_bunode_t));
	}
	VN_RELE(pvp);
}

/*
 * ctfs_bu_getattr - VOP_GETATTR entry point
 */
/* ARGSUSED */
static int
ctfs_bu_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	ctfs_bunode_t *bunode = vp->v_data;

	vap->va_type = VREG;
	vap->va_mode = 0444;
	vap->va_nodeid = gfs_file_index(vp);
	vap->va_nlink = 1;
	vap->va_size = 0;
	vap->va_ctime.tv_sec = vp->v_vfsp->vfs_mtime;
	vap->va_ctime.tv_nsec = 0;
	mutex_enter(&bunode->ctfs_bu_queue->ctq_lock);
	vap->va_mtime = vap->va_atime = bunode->ctfs_bu_queue->ctq_atime;
	mutex_exit(&bunode->ctfs_bu_queue->ctq_lock);
	ctfs_common_getattr(vp, vap);

	return (0);
}

/*
 * ctfs_bu_ioctl - VOP_IOCTL entry point
 */
/* ARGSUSED */
static int
ctfs_bu_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	ctfs_bunode_t *bunode = vp->v_data;

	return (ctfs_endpoint_ioctl(&bunode->ctfs_bu_listener, cmd, arg, cr,
	    VTOZONE(vp), bunode->ctfs_bu_queue->ctq_listno == CTEL_BUNDLE));
}

/*
 * ctfs_bu_poll - VOP_POLL entry point
 */
/*ARGSUSED*/
static int
ctfs_bu_poll(
	vnode_t *vp,
	short events,
	int anyyet,
	short *reventsp,
	pollhead_t **php,
	caller_context_t *ct)
{
	ctfs_bunode_t *bunode = vp->v_data;

	return (ctfs_endpoint_poll(&bunode->ctfs_bu_listener, events, anyyet,
	    reventsp, php));
}

const fs_operation_def_t ctfs_tops_bundle[] = {
	{ VOPNAME_OPEN,		{ .vop_open = ctfs_bu_open } },
	{ VOPNAME_CLOSE,	{ .vop_close = ctfs_close } },
	{ VOPNAME_IOCTL,	{ .vop_ioctl = ctfs_bu_ioctl } },
	{ VOPNAME_GETATTR,	{ .vop_getattr = ctfs_bu_getattr } },
	{ VOPNAME_ACCESS,	{ .vop_access = ctfs_access_readonly } },
	{ VOPNAME_READDIR,	{ .error = fs_notdir } },
	{ VOPNAME_LOOKUP,	{ .error = fs_notdir } },
	{ VOPNAME_INACTIVE,	{ .vop_inactive = ctfs_bu_inactive } },
	{ VOPNAME_POLL,		{ .vop_poll = ctfs_bu_poll } },
	{ NULL, NULL }
};
