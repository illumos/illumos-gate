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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/cred.h>
#include <sys/mount.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <fs/fs_subr.h>
#include <sys/fs/autofs.h>
#include <sys/callb.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <sys/door.h>
#include <sys/fs/mntdata.h>
#include <nfs/mount.h>
#include <rpc/clnt.h>
#include <rpcsvc/autofs_prot.h>
#include <nfs/rnode.h>
#include <sys/utsname.h>
#include <sys/schedctl.h>

/*
 * Autofs and Zones:
 *
 * Zones are delegated the responsibility of managing their own autofs mounts
 * and maps.  Each zone runs its own copy of automountd, with its own timeouts,
 * and other logically "global" parameters.  kRPC and virtualization in the
 * loopback transport (tl) will prevent a zone from communicating with another
 * zone's automountd.
 *
 * Each zone has its own "rootfnnode" and associated tree of auto nodes.
 *
 * Each zone also has its own set of "unmounter" kernel threads; these are
 * created and run within the zone's context (ie, they are created via
 * zthread_create()).
 *
 * Cross-zone mount triggers are disallowed.  There is a check in
 * auto_trigger_mount() to this effect; EPERM is returned to indicate that the
 * mount is not owned by the caller.
 *
 * autofssys() enables a caller in the global zone to clean up in-kernel (as
 * well as regular) autofs mounts via the unmount_tree() mechanism.  This is
 * routinely done when all mounts are removed as part of zone shutdown.
 */
#define	TYPICALMAXPATHLEN	64

static kmutex_t autofs_nodeid_lock;

/* max number of unmount threads running */
static int autofs_unmount_threads = 5;
static int autofs_unmount_thread_timer = 120;	/* in seconds */

static int auto_perform_link(fnnode_t *, struct linka *, cred_t *);
static int auto_perform_actions(fninfo_t *, fnnode_t *,
    action_list *, cred_t *);
static int auto_getmntpnt(vnode_t *, char *, vnode_t **, cred_t *);
static int auto_lookup_request(fninfo_t *, char *, struct linka *,
    bool_t, bool_t *, cred_t *);
static int auto_mount_request(fninfo_t *, char *, action_list **, cred_t *,
    bool_t);

/*
 * Clears the MF_INPROG flag, and wakes up those threads sleeping on
 * fn_cv_mount if MF_WAITING is set.
 */
void
auto_unblock_others(
	fnnode_t *fnp,
	uint_t operation)		/* either MF_INPROG or MF_LOOKUP */
{
	ASSERT(operation & (MF_INPROG | MF_LOOKUP));
	fnp->fn_flags &= ~operation;
	if (fnp->fn_flags & MF_WAITING) {
		fnp->fn_flags &= ~MF_WAITING;
		cv_broadcast(&fnp->fn_cv_mount);
	}
}

int
auto_wait4mount(fnnode_t *fnp)
{
	int error;
	k_sigset_t smask;

	AUTOFS_DPRINT((4, "auto_wait4mount: fnp=%p\n", (void *)fnp));

	mutex_enter(&fnp->fn_lock);
	while (fnp->fn_flags & (MF_INPROG | MF_LOOKUP)) {
		/*
		 * There is a mount or a lookup in progress.
		 */
		fnp->fn_flags |= MF_WAITING;
		sigintr(&smask, 1);
		if (!cv_wait_sig(&fnp->fn_cv_mount, &fnp->fn_lock)) {
			/*
			 * Decided not to wait for operation to
			 * finish after all.
			 */
			sigunintr(&smask);
			mutex_exit(&fnp->fn_lock);
			return (EINTR);
		}
		sigunintr(&smask);
	}
	error = fnp->fn_error;

	if (error == EINTR) {
		/*
		 * The thread doing the mount got interrupted, we need to
		 * try again, by returning EAGAIN.
		 */
		error = EAGAIN;
	}
	mutex_exit(&fnp->fn_lock);

	AUTOFS_DPRINT((5, "auto_wait4mount: fnp=%p error=%d\n", (void *)fnp,
	    error));
	return (error);
}

int
auto_lookup_aux(fnnode_t *fnp, char *name, cred_t *cred)
{
	struct fninfo *fnip;
	struct linka link;
	bool_t mountreq = FALSE;
	int error = 0;

	fnip = vfstofni(fntovn(fnp)->v_vfsp);
	bzero(&link, sizeof (link));
	error = auto_lookup_request(fnip, name, &link, TRUE, &mountreq, cred);
	if (!error) {
		if (link.link != NULL || link.link != '\0') {
			/*
			 * This node should be a symlink
			 */
			error = auto_perform_link(fnp, &link, cred);
		} else if (mountreq) {
			/*
			 * The automount daemon is requesting a mount,
			 * implying this entry must be a wildcard match and
			 * therefore in need of verification that the entry
			 * exists on the server.
			 */
			mutex_enter(&fnp->fn_lock);
			AUTOFS_BLOCK_OTHERS(fnp, MF_INPROG);
			fnp->fn_error = 0;

			/*
			 * Unblock other lookup requests on this node,
			 * this is needed to let the lookup generated by
			 * the mount call to complete. The caveat is
			 * other lookups on this node can also get by,
			 * i.e., another lookup on this node that occurs
			 * while this lookup is attempting the mount
			 * would return a positive result no matter what.
			 * Therefore two lookups on the this node could
			 * potentially get disparate results.
			 */
			AUTOFS_UNBLOCK_OTHERS(fnp, MF_LOOKUP);
			mutex_exit(&fnp->fn_lock);
			/*
			 * auto_new_mount_thread fires up a new thread which
			 * calls automountd finishing up the work
			 */
			auto_new_mount_thread(fnp, name, cred);

			/*
			 * At this point, we are simply another thread
			 * waiting for the mount to complete
			 */
			error = auto_wait4mount(fnp);
			if (error == AUTOFS_SHUTDOWN)
				error = ENOENT;
		}
	}

	if (link.link)
		kmem_free(link.link, strlen(link.link) + 1);
	if (link.dir)
		kmem_free(link.dir, strlen(link.dir) + 1);
	mutex_enter(&fnp->fn_lock);
	fnp->fn_error = error;

	/*
	 * Notify threads waiting for lookup/mount that
	 * it's done.
	 */
	if (mountreq) {
		AUTOFS_UNBLOCK_OTHERS(fnp, MF_INPROG);
	} else {
		AUTOFS_UNBLOCK_OTHERS(fnp, MF_LOOKUP);
	}
	mutex_exit(&fnp->fn_lock);
	return (error);
}

/*
 * Starting point for thread to handle mount requests with automountd.
 * XXX auto_mount_thread() is not suspend-safe within the scope of
 * the present model defined for cpr to suspend the system. Calls
 * made by the auto_mount_thread() that have been identified to be unsafe
 * are (1) RPC client handle setup and client calls to automountd which
 * can block deep down in the RPC library, (2) kmem_alloc() calls with the
 * KM_SLEEP flag which can block if memory is low, and (3) VFS_*(), and
 * lookuppnvp() calls which can result in over the wire calls to servers.
 * The thread should be completely reevaluated to make it suspend-safe in
 * case of future updates to the cpr model.
 */
static void
auto_mount_thread(struct autofs_callargs *argsp)
{
	struct fninfo 		*fnip;
	fnnode_t 		*fnp;
	vnode_t 		*vp;
	char 			*name;
	size_t 			namelen;
	cred_t 			*cred;
	action_list		*alp = NULL;
	int 			error;
	callb_cpr_t 		cprinfo;
	kmutex_t 		auto_mount_thread_cpr_lock;

	mutex_init(&auto_mount_thread_cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cprinfo, &auto_mount_thread_cpr_lock,
	    callb_generic_cpr, "auto_mount_thread");

	fnp = argsp->fnc_fnp;
	vp = fntovn(fnp);
	fnip = vfstofni(vp->v_vfsp);
	name = argsp->fnc_name;
	cred = argsp->fnc_cred;
	ASSERT(crgetzoneid(argsp->fnc_cred) == fnip->fi_zoneid);

	error = auto_mount_request(fnip, name, &alp, cred, TRUE);
	if (!error)
		error = auto_perform_actions(fnip, fnp, alp, cred);
	mutex_enter(&fnp->fn_lock);
	fnp->fn_error = error;

	/*
	 * Notify threads waiting for mount that
	 * it's done.
	 */
	AUTOFS_UNBLOCK_OTHERS(fnp, MF_INPROG);
	mutex_exit(&fnp->fn_lock);

	VN_RELE(vp);
	crfree(argsp->fnc_cred);
	namelen = strlen(argsp->fnc_name) + 1;
	kmem_free(argsp->fnc_name, namelen);
	kmem_free(argsp, sizeof (*argsp));

	mutex_enter(&auto_mount_thread_cpr_lock);
	CALLB_CPR_EXIT(&cprinfo);
	mutex_destroy(&auto_mount_thread_cpr_lock);
	zthread_exit();
	/* NOTREACHED */
}

static int autofs_thr_success = 0;

/*
 * Creates new thread which calls auto_mount_thread which does
 * the bulk of the work calling automountd, via 'auto_perform_actions'.
 */
void
auto_new_mount_thread(fnnode_t *fnp, char *name, cred_t *cred)
{
	struct autofs_callargs *argsp;

	argsp = kmem_alloc(sizeof (*argsp), KM_SLEEP);
	VN_HOLD(fntovn(fnp));
	argsp->fnc_fnp = fnp;
	argsp->fnc_name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(argsp->fnc_name, name);
	argsp->fnc_origin = curthread;
	crhold(cred);
	argsp->fnc_cred = cred;

	(void) zthread_create(NULL, 0, auto_mount_thread, argsp, 0,
	    minclsyspri);
	autofs_thr_success++;
}

#define	DOOR_BUF_ALIGN		(1024*1024)
#define	DOOR_BUF_MULTIPLIER	3
#define	DOOR_BUF_DEFAULT_SZ	(DOOR_BUF_MULTIPLIER * DOOR_BUF_ALIGN)
int	doorbuf_defsz = DOOR_BUF_DEFAULT_SZ;

/*ARGSUSED*/
int
auto_calldaemon(
	zoneid_t 		zoneid,
	int			which,
	xdrproc_t		xarg_func,
	void 			*argsp,
	xdrproc_t		xresp_func,
	void 			*resp,
	int			reslen,
	bool_t 			hard)	/* retry forever? */
{
	int			 retry;
	int			 error = 0;
	k_sigset_t		 smask;
	door_arg_t		 door_args;
	door_handle_t		 dh;
	XDR			 xdrarg;
	XDR			 xdrres;
	struct autofs_globals 	*fngp = NULL;
	void			*orp = NULL;
	int			 orl;
	int			 rlen = 0;	/* MUST be initialized */
	autofs_door_args_t	*xdr_argsp;
	int			 xdr_len = 0;
	int			 printed_not_running_msg = 0;
	klwp_t			*lwp = ttolwp(curthread);

	/*
	 * We know that the current thread is doing work on
	 * behalf of its own zone, so it's ok to use
	 * curproc->p_zone.
	 */
	ASSERT(zoneid == getzoneid());
	if (zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN) {
		/*
		 * There's no point in trying to talk to
		 * automountd.  Plus, zone_shutdown() is
		 * waiting for us.
		 */
		return (ECONNREFUSED);
	}

	do {
		retry = 0;
		mutex_enter(&autofs_minor_lock);
		fngp = zone_getspecific(autofs_key, curproc->p_zone);
		mutex_exit(&autofs_minor_lock);
		if (fngp == NULL) {
			if (hard) {
				AUTOFS_DPRINT((5,
				    "auto_calldaemon: "\
				    "failed to get door handle\n"));
				if (!printed_not_running_msg) {
					printed_not_running_msg = 1;
					zprintf(zoneid, "automountd not "\
					    "running, retrying\n");
				}
				delay(hz);
				retry = 1;
			} else {
				/*
				 * There is no global data so no door.
				 * There's no point in attempting to talk
				 * to automountd if we can't get the door
				 * handle.
				 */
				return (ECONNREFUSED);
			}
		}
	} while (retry);

	if (printed_not_running_msg) {
		fngp->fng_printed_not_running_msg = printed_not_running_msg;
	}

	ASSERT(fngp != NULL);

	if (argsp != NULL && (xdr_len = xdr_sizeof(xarg_func, argsp)) == 0)
		return (EINVAL);
	xdr_argsp = kmem_zalloc(xdr_len + sizeof (*xdr_argsp), KM_SLEEP);
	xdr_argsp->xdr_len = xdr_len;
	xdr_argsp->cmd = which;

	if (argsp) {
		xdrmem_create(&xdrarg, (char *)&xdr_argsp->xdr_arg,
		    xdr_argsp->xdr_len, XDR_ENCODE);

		if (!(*xarg_func)(&xdrarg, argsp)) {
			kmem_free(xdr_argsp, xdr_len + sizeof (*xdr_argsp));
			return (EINVAL);
		}
	}

	/*
	 * We're saving off the original pointer and length due to the
	 * possibility that the results buffer returned by the door
	 * upcall can be different then what we passed in. This is because
	 * the door will allocate new memory if the results buffer passed
	 * in isn't large enough to hold what we need to send back.
	 * In this case we need to free the memory originally allocated
	 * for that buffer.
	 */
	if (resp)
		rlen = xdr_sizeof(xresp_func, resp);
	orl = (rlen == 0) ? doorbuf_defsz : MAX(rlen, doorbuf_defsz);
	orp = kmem_zalloc(orl, KM_SLEEP);

	do {
		retry = 0;
		mutex_enter(&fngp->fng_autofs_daemon_lock);
		dh = fngp->fng_autofs_daemon_dh;
		if (dh)
			door_ki_hold(dh);
		mutex_exit(&fngp->fng_autofs_daemon_lock);

		if (dh == NULL) {
			if (orp)
				kmem_free(orp, orl);
			kmem_free(xdr_argsp, xdr_len + sizeof (*xdr_argsp));
			return (ENOENT);
		}
		door_args.data_ptr = (char *)xdr_argsp;
		door_args.data_size = sizeof (*xdr_argsp) + xdr_argsp->xdr_len;
		door_args.desc_ptr = NULL;
		door_args.desc_num = 0;
		door_args.rbuf = orp ? (char *)orp : NULL;
		door_args.rsize = orl;

		sigintr(&smask, 1);
		error =
		    door_ki_upcall_limited(dh, &door_args, NULL, SIZE_MAX, 0);
		sigunintr(&smask);

		door_ki_rele(dh);

		/*
		 * Handle daemon errors
		 */
		if (!error) {
			/*
			 * Upcall successful. Let's check for soft errors
			 * from the daemon. We only recover from overflow
			 * type scenarios. Any other errors, we return to
			 * the caller.
			 */
			autofs_door_res_t *adr =
			    (autofs_door_res_t *)door_args.rbuf;

			if (door_args.rbuf != NULL) {
				int	 nl;

				switch (error = adr->res_status) {
				case 0:	/* no error; continue */
					break;

				case EOVERFLOW:
					/*
					 * orig landing buf not big enough.
					 * xdr_len in XDR_BYTES_PER_UNIT
					 */
					if ((nl = adr->xdr_len) > 0 &&
					    (btopr(nl) < freemem/64)) {
						if (orp)
							kmem_free(orp, orl);
						orp = kmem_zalloc(nl, KM_SLEEP);
						orl = nl;
						retry = 1;
						break;
					}
					/*FALLTHROUGH*/

				default:
					kmem_free(xdr_argsp,
					    xdr_len + sizeof (*xdr_argsp));
					if (orp)
						kmem_free(orp, orl);
					return (error);
				}
			}
			continue;
		}

		/*
		 * no daemon errors; now process door/comm errors (if any)
		 */
		switch (error) {
		case EINTR:
			/*
			 * interrupts should be handled properly by the
			 * door upcall. If the door doesn't handle the
			 * interupt completely then we need to bail out.
			 */
			if (lwp && (ISSIG(curthread,
			    JUSTLOOKING) || MUSTRETURN(curproc, curthread))) {
				if (ISSIG(curthread, FORREAL) ||
				    lwp->lwp_sysabort ||
				    MUSTRETURN(curproc, curthread)) {
					lwp->lwp_sysabort = 0;
					return (EINTR);
				}
			}
			/*
			 * We may have gotten EINTR for other reasons
			 * like the door being revoked on us. Instead
			 * of trying to extract this out of the door
			 * handle, sleep and try again, if still
			 * revoked we will get EBADF next time
			 * through.
			 *
			 * If we have a pending cancellation and we don't
			 * have cancellation disabled, we will get EINTR
			 * forever, no matter how many times we retry,
			 * so just get out now if this is the case.
			 */
			if (schedctl_cancel_pending())
				break;
			/* FALLTHROUGH */
		case EAGAIN:    /* process may be forking */
			/*
			 * Back off for a bit
			 */
			delay(hz);
			retry = 1;
			break;
		case EBADF:	/* Invalid door */
		case EINVAL:    /* Not a door, wrong target */
			/*
			 * A fatal door error, if our failing door
			 * handle is the current door handle, clean
			 * up our state.
			 */
			mutex_enter(&fngp->fng_autofs_daemon_lock);
			if (dh == fngp->fng_autofs_daemon_dh) {
				door_ki_rele(fngp->fng_autofs_daemon_dh);
				fngp->fng_autofs_daemon_dh = NULL;
			}
			mutex_exit(&fngp->fng_autofs_daemon_lock);
			AUTOFS_DPRINT((5, "auto_calldaemon error=%d\n", error));
			if (hard) {
				if (!fngp->fng_printed_not_running_msg) {
					fngp->fng_printed_not_running_msg = 1;
					zprintf(zoneid, "automountd not "
					    "running, retrying\n");
				}
				delay(hz);
				retry = 1;
				break;
			} else {
				error = ECONNREFUSED;
				kmem_free(xdr_argsp,
				    xdr_len + sizeof (*xdr_argsp));
				if (orp)
					kmem_free(orp, orl);
				return (error);
			}
		default:	/* Unknown must be fatal */
			error = ENOENT;
			kmem_free(xdr_argsp, xdr_len + sizeof (*xdr_argsp));
			if (orp)
				kmem_free(orp, orl);
			return (error);
		}
	} while (retry);

	if (fngp->fng_printed_not_running_msg == 1) {
		fngp->fng_printed_not_running_msg = 0;
		zprintf(zoneid, "automountd OK\n");
	}

	if (orp && orl) {
		autofs_door_res_t	*door_resp;
		door_resp = (autofs_door_res_t *)door_args.rbuf;

		if ((void *)door_args.rbuf != orp)
			kmem_free(orp, orl);

		xdrmem_create(&xdrres, (char *)&door_resp->xdr_res,
		    door_resp->xdr_len, XDR_DECODE);

		if (!((*xresp_func)(&xdrres, resp)))
			error = EINVAL;
		kmem_free(door_args.rbuf, door_args.rsize);
	}
	kmem_free(xdr_argsp, xdr_len + sizeof (*xdr_argsp));
	return (error);
}

static int
auto_null_request(zoneid_t zoneid, bool_t hard)
{
	int error;

	AUTOFS_DPRINT((4, "\tauto_null_request\n"));

	error = auto_calldaemon(zoneid, NULLPROC,
	    xdr_void, NULL, xdr_void, NULL, 0, hard);

	AUTOFS_DPRINT((5, "\tauto_null_request: error=%d\n", error));
	return (error);
}

static int
auto_lookup_request(
	fninfo_t *fnip,
	char *key,
	struct linka *lnp,
	bool_t hard,
	bool_t *mountreq,
	cred_t *cred)
{
	int 				error;
	struct autofs_globals 		*fngp;
	struct autofs_lookupargs	 reqst;
	autofs_lookupres 		*resp;
	struct linka 			*p;


	AUTOFS_DPRINT((4, "auto_lookup_equest: path=%s name=%s\n",
	    fnip->fi_path, key));

	fngp = vntofn(fnip->fi_rootvp)->fn_globals;

	reqst.map = fnip->fi_map;
	reqst.path = fnip->fi_path;

	if (fnip->fi_flags & MF_DIRECT)
		reqst.name = fnip->fi_key;
	else
		reqst.name = key;
	AUTOFS_DPRINT((4, "auto_lookup_request: using key=%s\n", reqst.name));

	reqst.subdir = fnip->fi_subdir;
	reqst.opts = fnip->fi_opts;
	reqst.isdirect = fnip->fi_flags & MF_DIRECT ? TRUE : FALSE;
	reqst.uid = crgetuid(cred);

	resp = kmem_zalloc(sizeof (*resp), KM_SLEEP);

	error = auto_calldaemon(fngp->fng_zoneid, AUTOFS_LOOKUP,
	    xdr_autofs_lookupargs, &reqst, xdr_autofs_lookupres,
	    (void *)resp, sizeof (autofs_lookupres), hard);

	if (error) {
		xdr_free(xdr_autofs_lookupres, (char *)resp);
		kmem_free(resp, sizeof (*resp));
		return (error);
	}

	if (!error) {
		fngp->fng_verbose = resp->lu_verbose;
		switch (resp->lu_res) {
		case AUTOFS_OK:
			switch (resp->lu_type.action) {
			case AUTOFS_MOUNT_RQ:
				lnp->link = NULL;
				lnp->dir = NULL;
				*mountreq = TRUE;
				break;

			case AUTOFS_LINK_RQ:
			p = &resp->lu_type.lookup_result_type_u.lt_linka;
				lnp->dir = kmem_alloc(strlen(p->dir) + 1,
				    KM_SLEEP);
				(void) strcpy(lnp->dir, p->dir);
				lnp->link = kmem_alloc(strlen(p->link) + 1,
				    KM_SLEEP);
				(void) strcpy(lnp->link, p->link);
				break;

			case AUTOFS_NONE:
				lnp->link = NULL;
				lnp->dir = NULL;
				break;

			default:
				auto_log(fngp->fng_verbose, fngp->fng_zoneid,
				    CE_WARN, "auto_lookup_request: bad action "
				    "type %d", resp->lu_res);
				error = ENOENT;
			}
			break;

		case AUTOFS_NOENT:
			error = ENOENT;
			break;

		default:
			error = ENOENT;
			auto_log(fngp->fng_verbose, fngp->fng_zoneid, CE_WARN,
			    "auto_lookup_request: unknown result: %d",
			    resp->lu_res);
			break;
		}
	}
done:
	xdr_free(xdr_autofs_lookupres, (char *)resp);
	kmem_free(resp, sizeof (*resp));
	AUTOFS_DPRINT((5, "auto_lookup_request: path=%s name=%s error=%d\n",
	    fnip->fi_path, key, error));
	return (error);
}

static int
auto_mount_request(
	fninfo_t *fnip,
	char *key,
	action_list **alpp,
	cred_t *cred,
	bool_t hard)
{
	int 			error;
	struct autofs_globals 	*fngp;
	autofs_lookupargs 	reqst;
	autofs_mountres		*xdrres = NULL;

	AUTOFS_DPRINT((4, "auto_mount_request: path=%s name=%s\n",
	    fnip->fi_path, key));

	fngp = vntofn(fnip->fi_rootvp)->fn_globals;
	reqst.map = fnip->fi_map;
	reqst.path = fnip->fi_path;

	if (fnip->fi_flags & MF_DIRECT)
		reqst.name = fnip->fi_key;
	else
		reqst.name = key;

	AUTOFS_DPRINT((4, "auto_mount_request: using key=%s\n", reqst.name));

	reqst.subdir = fnip->fi_subdir;
	reqst.opts = fnip->fi_opts;
	reqst.isdirect = fnip->fi_flags & MF_DIRECT ? TRUE : FALSE;
	reqst.uid = crgetuid(cred);

	xdrres = kmem_zalloc(sizeof (*xdrres), KM_SLEEP);

	error = auto_calldaemon(fngp->fng_zoneid, AUTOFS_MNTINFO,
	    xdr_autofs_lookupargs, &reqst, xdr_autofs_mountres,
	    (void *)xdrres, sizeof (autofs_mountres), hard);

	if (!error) {
		fngp->fng_verbose = xdrres->mr_verbose;
		switch (xdrres->mr_type.status) {
		case AUTOFS_ACTION:
			error = 0;
			/*
			 * Save the action list since it is used by
			 * the caller. We NULL the action list pointer
			 * in 'result' so that xdr_free() will not free
			 * the list.
			 */
			*alpp = xdrres->mr_type.mount_result_type_u.list;
			xdrres->mr_type.mount_result_type_u.list = NULL;
			break;
		case AUTOFS_DONE:
			error = xdrres->mr_type.mount_result_type_u.error;
			break;
		default:
			error = ENOENT;
			auto_log(fngp->fng_verbose, fngp->fng_zoneid, CE_WARN,
			    "auto_mount_request: unknown status %d",
			    xdrres->mr_type.status);
			break;
		}
	}

	xdr_free(xdr_autofs_mountres, (char *)xdrres);
	kmem_free(xdrres, sizeof (*xdrres));


	AUTOFS_DPRINT((5, "auto_mount_request: path=%s name=%s error=%d\n",
	    fnip->fi_path, key, error));
	return (error);
}


static int
auto_send_unmount_request(
	fninfo_t *fnip,
	umntrequest *ul,
	bool_t hard)
{
	int 	error;
	umntres	xdrres;

	struct autofs_globals *fngp = vntofn(fnip->fi_rootvp)->fn_globals;

	AUTOFS_DPRINT((4, "\tauto_send_unmount_request: fstype=%s "
	    " mntpnt=%s\n", ul->fstype, ul->mntpnt));

	bzero(&xdrres, sizeof (umntres));
	error = auto_calldaemon(fngp->fng_zoneid, AUTOFS_UNMOUNT,
	    xdr_umntrequest, (void *)ul, xdr_umntres, (void *)&xdrres,
	    sizeof (umntres), hard);

	if (!error)
		error = xdrres.status;

	AUTOFS_DPRINT((5, "\tauto_send_unmount_request: error=%d\n", error));

	return (error);
}

static int
auto_perform_link(fnnode_t *fnp, struct linka *linkp, cred_t *cred)
{
	vnode_t *vp;
	size_t len;
	char *tmp;

	AUTOFS_DPRINT((3, "auto_perform_link: fnp=%p dir=%s link=%s\n",
	    (void *)fnp, linkp->dir, linkp->link));

	len = strlen(linkp->link) + 1;		/* include '\0' */
	tmp = kmem_zalloc(len, KM_SLEEP);
	(void) kcopy(linkp->link, tmp, len);
	mutex_enter(&fnp->fn_lock);
	fnp->fn_symlink = tmp;
	fnp->fn_symlinklen = (uint_t)len;
	fnp->fn_flags |= MF_THISUID_MATCH_RQD;
	crhold(cred);
	fnp->fn_cred = cred;
	mutex_exit(&fnp->fn_lock);

	vp = fntovn(fnp);
	vp->v_type = VLNK;

	return (0);
}

static void
auto_free_autofs_args(struct mounta *m)
{
	autofs_args	*aargs = (autofs_args *)m->dataptr;

	if (aargs->addr.buf)
		kmem_free(aargs->addr.buf, aargs->addr.len);
	if (aargs->path)
		kmem_free(aargs->path, strlen(aargs->path) + 1);
	if (aargs->opts)
		kmem_free(aargs->opts, strlen(aargs->opts) + 1);
	if (aargs->map)
		kmem_free(aargs->map, strlen(aargs->map) + 1);
	if (aargs->subdir)
		kmem_free(aargs->subdir, strlen(aargs->subdir) + 1);
	if (aargs->key)
		kmem_free(aargs->key, strlen(aargs->key) + 1);
	kmem_free(aargs, sizeof (*aargs));
}

static void
auto_free_action_list(action_list *alp)
{
	struct	mounta	*m;
	action_list	*lastalp;
	char		*fstype;

	m = &alp->action.action_list_entry_u.mounta;
	while (alp != NULL) {
		fstype = alp->action.action_list_entry_u.mounta.fstype;
		m = &alp->action.action_list_entry_u.mounta;
		if (m->dataptr) {
			if (strcmp(fstype, "autofs") == 0) {
				auto_free_autofs_args(m);
			}
		}
		if (m->spec)
			kmem_free(m->spec, strlen(m->spec) + 1);
		if (m->dir)
			kmem_free(m->dir, strlen(m->dir) + 1);
		if (m->fstype)
			kmem_free(m->fstype, strlen(m->fstype) + 1);
		if (m->optptr)
			kmem_free(m->optptr, m->optlen);
		lastalp = alp;
		alp = alp->next;
		kmem_free(lastalp, sizeof (*lastalp));
	}
}

static boolean_t
auto_invalid_autofs(fninfo_t *dfnip, fnnode_t *dfnp, action_list *p)
{
	struct mounta *m;
	struct autofs_args *argsp;
	vnode_t *dvp;
	char buff[AUTOFS_MAXPATHLEN];
	size_t len;
	struct autofs_globals *fngp;

	fngp = dfnp->fn_globals;
	dvp = fntovn(dfnp);

	m = &p->action.action_list_entry_u.mounta;
	/*
	 * Make sure we aren't geting passed NULL values or a "dir" that
	 * isn't "." and doesn't begin with "./".
	 *
	 * We also only want to perform autofs mounts, so make sure
	 * no-one is trying to trick us into doing anything else.
	 */
	if (m->spec == NULL || m->dir == NULL || m->dir[0] != '.' ||
	    (m->dir[1] != '/' && m->dir[1] != '\0') ||
	    m->fstype == NULL || strcmp(m->fstype, "autofs") != 0 ||
	    m->dataptr == NULL || m->datalen != sizeof (struct autofs_args) ||
	    m->optptr == NULL)
		return (B_TRUE);
	/*
	 * We also don't like ".."s in the pathname.  Symlinks are
	 * handled by the fact that we'll use NOFOLLOW when we do
	 * lookup()s.
	 */
	if (strstr(m->dir, "/../") != NULL ||
	    (len = strlen(m->dir)) > sizeof ("/..") - 1 &&
	    m->dir[len] == '.' && m->dir[len - 1] == '.' &&
	    m->dir[len - 2] == '/')
		return (B_TRUE);
	argsp = (struct autofs_args *)m->dataptr;
	/*
	 * We don't want NULL values here either.
	 */
	if (argsp->addr.buf == NULL || argsp->path == NULL ||
	    argsp->opts == NULL || argsp->map == NULL || argsp->subdir == NULL)
		return (B_TRUE);
	/*
	 * We know what the claimed pathname *should* look like:
	 *
	 * If the parent (dfnp) is a mount point (VROOT), then
	 * the path should be (dfnip->fi_path + m->dir).
	 *
	 * Else, we know we're only two levels deep, so we use
	 * (dfnip->fi_path + dfnp->fn_name + m->dir).
	 *
	 * Furthermore, "." only makes sense if dfnp is a
	 * trigger node.
	 *
	 * At this point it seems like the passed-in path is
	 * redundant.
	 */
	if (dvp->v_flag & VROOT) {
		if (m->dir[1] == '\0' && !(dfnp->fn_flags & MF_TRIGGER))
			return (B_TRUE);
		(void) snprintf(buff, sizeof (buff), "%s%s",
		    dfnip->fi_path, m->dir + 1);
	} else {
		(void) snprintf(buff, sizeof (buff), "%s/%s%s",
		    dfnip->fi_path, dfnp->fn_name, m->dir + 1);
	}
	if (strcmp(argsp->path, buff) != 0) {
		auto_log(fngp->fng_verbose, fngp->fng_zoneid,
		    CE_WARN, "autofs: expected path of '%s', "
		    "got '%s' instead.", buff, argsp->path);
		return (B_TRUE);
	}
	return (B_FALSE); /* looks OK */
}

/*
 * auto_invalid_action will validate the action_list received.  If all is good
 * this function returns FALSE, if there is a problem it returns TRUE.
 */
static boolean_t
auto_invalid_action(fninfo_t *dfnip, fnnode_t *dfnp, action_list *alistpp)
{

	/*
	 * Before we go any further, this better be a mount request.
	 */
	if (alistpp->action.action != AUTOFS_MOUNT_RQ)
		return (B_TRUE);
	return (auto_invalid_autofs(dfnip, dfnp, alistpp));

}

static int
auto_perform_actions(
	fninfo_t *dfnip,
	fnnode_t *dfnp,
	action_list *alp,
	cred_t *cred)	/* Credentials of the caller */
{

	action_list *p;
	struct mounta		*m, margs;
	struct autofs_args 		*argsp;
	int 			error, success = 0;
	vnode_t 		*mvp, *dvp, *newvp;
	fnnode_t 		*newfnp, *mfnp;
	int 			auto_mount = 0;
	int 			save_triggers = 0;
	int 			update_times = 0;
	char 			*mntpnt;
	char 			buff[AUTOFS_MAXPATHLEN];
	timestruc_t 		now;
	struct autofs_globals 	*fngp;
	cred_t 			*zcred;

	AUTOFS_DPRINT((4, "auto_perform_actions: alp=%p\n", (void *)alp));

	fngp = dfnp->fn_globals;
	dvp = fntovn(dfnp);

	/*
	 * As automountd running in a zone may be compromised, and this may be
	 * an attack, we can't trust everything passed in by automountd, and we
	 * need to do argument verification.  We'll issue a warning and drop
	 * the request if it doesn't seem right.
	 */

	for (p = alp; p != NULL; p = p->next) {
		if (auto_invalid_action(dfnip, dfnp, p)) {
			/*
			 * This warning should be sent to the global zone,
			 * since presumably the zone administrator is the same
			 * as the attacker.
			 */
			cmn_err(CE_WARN, "autofs: invalid action list received "
			    "by automountd in zone %s.",
			    curproc->p_zone->zone_name);
			/*
			 * This conversation is over.
			 */
			xdr_free(xdr_action_list, (char *)alp);
			return (EINVAL);
		}
	}

	zcred = zone_get_kcred(getzoneid());
	ASSERT(zcred != NULL);

	if (vn_mountedvfs(dvp) != NULL) {
		/*
		 * The daemon successfully mounted a filesystem
		 * on the AUTOFS root node.
		 */
		mutex_enter(&dfnp->fn_lock);
		dfnp->fn_flags |= MF_MOUNTPOINT;
		ASSERT(dfnp->fn_dirents == NULL);
		mutex_exit(&dfnp->fn_lock);
		success++;
	} else {
		/*
		 * Clear MF_MOUNTPOINT.
		 */
		mutex_enter(&dfnp->fn_lock);
		if (dfnp->fn_flags & MF_MOUNTPOINT) {
			AUTOFS_DPRINT((10, "autofs: clearing mountpoint "
			    "flag on %s.", dfnp->fn_name));
			ASSERT(dfnp->fn_dirents == NULL);
			ASSERT(dfnp->fn_trigger == NULL);
		}
		dfnp->fn_flags &= ~MF_MOUNTPOINT;
		mutex_exit(&dfnp->fn_lock);
	}

	for (p = alp; p != NULL; p = p->next) {

		vfs_t *vfsp;	/* dummy argument */
		vfs_t *mvfsp;

		auto_mount = 0;

		m = &p->action.action_list_entry_u.mounta;
		argsp = (struct autofs_args *)m->dataptr;
		ASSERT(strcmp(m->fstype, "autofs") == 0);
		/*
		 * use the parent directory's timeout since it's the
		 * one specified/inherited by automount.
		 */
		argsp->mount_to = dfnip->fi_mount_to;
		/*
		 * The mountpoint is relative, and it is guaranteed to
		 * begin with "."
		 *
		 */
		ASSERT(m->dir[0] == '.');
		if (m->dir[0] == '.' && m->dir[1] == '\0') {
			/*
			 * mounting on the trigger node
			 */
			mvp = dvp;
			VN_HOLD(mvp);
			goto mount;
		}
		/*
		 * ignore "./" in front of mountpoint
		 */
		ASSERT(m->dir[1] == '/');
		mntpnt = m->dir + 2;

		AUTOFS_DPRINT((10, "\tdfnip->fi_path=%s\n", dfnip->fi_path));
		AUTOFS_DPRINT((10, "\tdfnip->fi_flags=%x\n", dfnip->fi_flags));
		AUTOFS_DPRINT((10, "\tmntpnt=%s\n", mntpnt));

		if (dfnip->fi_flags & MF_DIRECT) {
			AUTOFS_DPRINT((10, "\tDIRECT\n"));
			(void) sprintf(buff, "%s/%s", dfnip->fi_path, mntpnt);
		} else {
			AUTOFS_DPRINT((10, "\tINDIRECT\n"));
			(void) sprintf(buff, "%s/%s/%s",
			    dfnip->fi_path, dfnp->fn_name, mntpnt);
		}

		if (vn_mountedvfs(dvp) == NULL) {
			/*
			 * Daemon didn't mount anything on the root
			 * We have to create the mountpoint if it
			 * doesn't exist already
			 *
			 * We use the caller's credentials in case a
			 * UID-match is required
			 * (MF_THISUID_MATCH_RQD).
			 */
			rw_enter(&dfnp->fn_rwlock, RW_WRITER);
			error = auto_search(dfnp, mntpnt, &mfnp, cred);
			if (error == 0) {
				/*
				 * AUTOFS mountpoint exists
				 */
				if (vn_mountedvfs(fntovn(mfnp)) != NULL) {
					cmn_err(CE_PANIC,
					    "auto_perform_actions:"
					    " mfnp=%p covered", (void *)mfnp);
				}
			} else {
				/*
				 * Create AUTOFS mountpoint
				 */
				ASSERT((dfnp->fn_flags & MF_MOUNTPOINT) == 0);
				error = auto_enter(dfnp, mntpnt, &mfnp, cred);
				ASSERT(mfnp->fn_linkcnt == 1);
				mfnp->fn_linkcnt++;
			}
			if (!error)
				update_times = 1;
			rw_exit(&dfnp->fn_rwlock);
			ASSERT(error != EEXIST);
			if (!error) {
				/*
				 * mfnp is already held.
				 */
				mvp = fntovn(mfnp);
			} else {
				auto_log(fngp->fng_verbose, fngp->fng_zoneid,
				    CE_WARN, "autofs: mount of %s "
				    "failed - can't create"
				    " mountpoint.", buff);
				continue;
			}
		} else {
			/*
			 * Find mountpoint in VFS mounted here. If not
			 * found, fail the submount, though the overall
			 * mount has succeeded since the root is
			 * mounted.
			 */
			if (error = auto_getmntpnt(dvp, mntpnt, &mvp, kcred)) {
				auto_log(fngp->fng_verbose, fngp->fng_zoneid,
				    CE_WARN, "autofs: mount of %s "
				    "failed - mountpoint doesn't"
				    " exist.", buff);
				continue;
			}
			if (mvp->v_type == VLNK) {
				auto_log(fngp->fng_verbose, fngp->fng_zoneid,
				    CE_WARN, "autofs: %s symbolic "
				    "link: not a valid mountpoint "
				    "- mount failed", buff);
				VN_RELE(mvp);
				error = ENOENT;
				continue;
			}
		}
mount:
		m->flags |= MS_SYSSPACE | MS_OPTIONSTR;

		/*
		 * Copy mounta struct here so we can substitute a
		 * buffer that is large enough to hold the returned
		 * option string, if that string is longer than the
		 * input option string.
		 * This can happen if there are default options enabled
		 * that were not in the input option string.
		 */
		bcopy(m, &margs, sizeof (*m));
		margs.optptr = kmem_alloc(MAX_MNTOPT_STR, KM_SLEEP);
		margs.optlen = MAX_MNTOPT_STR;
		(void) strcpy(margs.optptr, m->optptr);
		margs.dir = argsp->path;

		/*
		 * We use the zone's kcred because we don't want the
		 * zone to be able to thus do something it wouldn't
		 * normally be able to.
		 */
		error = domount(NULL, &margs, mvp, zcred, &vfsp);
		kmem_free(margs.optptr, MAX_MNTOPT_STR);
		if (error != 0) {
			auto_log(fngp->fng_verbose, fngp->fng_zoneid,
			    CE_WARN, "autofs: domount of %s failed "
			    "error=%d", buff, error);
			VN_RELE(mvp);
			continue;
		}
		VFS_RELE(vfsp);

		/*
		 * If mountpoint is an AUTOFS node, then I'm going to
		 * flag it that the Filesystem mounted on top was
		 * mounted in the kernel so that the unmount can be
		 * done inside the kernel as well.
		 * I don't care to flag non-AUTOFS mountpoints when an
		 * AUTOFS in-kernel mount was done on top, because the
		 * unmount routine already knows that such case was
		 * done in the kernel.
		 */
		if (vfs_matchops(dvp->v_vfsp, vfs_getops(mvp->v_vfsp))) {
			mfnp = vntofn(mvp);
			mutex_enter(&mfnp->fn_lock);
			mfnp->fn_flags |= MF_IK_MOUNT;
			mutex_exit(&mfnp->fn_lock);
		}

		(void) vn_vfswlock_wait(mvp);
		mvfsp = vn_mountedvfs(mvp);
		if (mvfsp != NULL) {
			vfs_lock_wait(mvfsp);
			vn_vfsunlock(mvp);
			error = VFS_ROOT(mvfsp, &newvp);
			vfs_unlock(mvfsp);
			if (error) {
				/*
				 * We've dropped the locks, so let's
				 * get the mounted vfs again in case
				 * it changed.
				 */
				(void) vn_vfswlock_wait(mvp);
				mvfsp = vn_mountedvfs(mvp);
				if (mvfsp != NULL) {
					error = dounmount(mvfsp, 0, CRED());
					if (error) {
						cmn_err(CE_WARN,
						    "autofs: could not unmount"
						    " vfs=%p", (void *)mvfsp);
					}
				} else
					vn_vfsunlock(mvp);
				VN_RELE(mvp);
				continue;
			}
		} else {
			vn_vfsunlock(mvp);
			VN_RELE(mvp);
			continue;
		}

		auto_mount = vfs_matchops(dvp->v_vfsp,
		    vfs_getops(newvp->v_vfsp));
		newfnp = vntofn(newvp);
		newfnp->fn_parent = dfnp;

		/*
		 * At this time we want to save the AUTOFS filesystem
		 * as a trigger node. (We only do this if the mount
		 * occurred on a node different from the root.
		 * We look at the trigger nodes during
		 * the automatic unmounting to make sure we remove them
		 * as a unit and remount them as a unit if the
		 * filesystem mounted at the root could not be
		 * unmounted.
		 */
		if (auto_mount && (error == 0) && (mvp != dvp)) {
			save_triggers++;
			/*
			 * Add AUTOFS mount to hierarchy
			 */
			newfnp->fn_flags |= MF_TRIGGER;
			rw_enter(&newfnp->fn_rwlock, RW_WRITER);
			newfnp->fn_next = dfnp->fn_trigger;
			rw_exit(&newfnp->fn_rwlock);
			rw_enter(&dfnp->fn_rwlock, RW_WRITER);
			dfnp->fn_trigger = newfnp;
			rw_exit(&dfnp->fn_rwlock);
			/*
			 * Don't VN_RELE(newvp) here since dfnp now
			 * holds reference to it as its trigger node.
			 */
			AUTOFS_DPRINT((10, "\tadding trigger %s to %s\n",
			    newfnp->fn_name, dfnp->fn_name));
			AUTOFS_DPRINT((10, "\tfirst trigger is %s\n",
			    dfnp->fn_trigger->fn_name));
			if (newfnp->fn_next != NULL)
				AUTOFS_DPRINT((10, "\tnext trigger is %s\n",
				    newfnp->fn_next->fn_name));
			else
				AUTOFS_DPRINT((10, "\tno next trigger\n"));
		} else
			VN_RELE(newvp);

		if (!error)
			success++;

		if (update_times) {
			gethrestime(&now);
			dfnp->fn_atime = dfnp->fn_mtime = now;
		}

		VN_RELE(mvp);
	}

	if (save_triggers) {
		/*
		 * Make sure the parent can't be freed while it has triggers.
		 */
		VN_HOLD(dvp);
	}

	crfree(zcred);

done:
	/*
	 * Return failure if daemon didn't mount anything, and all
	 * kernel mounts attempted failed.
	 */
	error = success ? 0 : ENOENT;

	if (alp != NULL) {
		if ((error == 0) && save_triggers) {
			/*
			 * Save action_list information, so that we can use it
			 * when it comes time to remount the trigger nodes
			 * The action list is freed when the directory node
			 * containing the reference to it is unmounted in
			 * unmount_tree().
			 */
			mutex_enter(&dfnp->fn_lock);
			ASSERT(dfnp->fn_alp == NULL);
			dfnp->fn_alp = alp;
			mutex_exit(&dfnp->fn_lock);
		} else {
			/*
			 * free the action list now,
			 */
			xdr_free(xdr_action_list, (char *)alp);
		}
	}
	AUTOFS_DPRINT((5, "auto_perform_actions: error=%d\n", error));
	return (error);
}

fnnode_t *
auto_makefnnode(
	vtype_t type,
	vfs_t *vfsp,
	char *name,
	cred_t *cred,
	struct autofs_globals *fngp)
{
	fnnode_t *fnp;
	vnode_t *vp;
	char *tmpname;
	timestruc_t now;
	/*
	 * autofs uses odd inode numbers
	 * automountd uses even inode numbers
	 *
	 * To preserve the age-old semantics that inum+devid is unique across
	 * the system, this variable must be global across zones.
	 */
	static ino_t nodeid = 3;

	fnp = kmem_zalloc(sizeof (*fnp), KM_SLEEP);
	fnp->fn_vnode = vn_alloc(KM_SLEEP);

	vp = fntovn(fnp);
	tmpname = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(tmpname, name);
	fnp->fn_name = &tmpname[0];
	fnp->fn_namelen = (int)strlen(tmpname) + 1;	/* include '\0' */
	fnp->fn_uid = crgetuid(cred);
	fnp->fn_gid = crgetgid(cred);
	/*
	 * ".." is added in auto_enter and auto_mount.
	 * "." is added in auto_mkdir and auto_mount.
	 */
	/*
	 * Note that fn_size and fn_linkcnt are already 0 since
	 * we used kmem_zalloc to allocated fnp
	 */
	fnp->fn_mode = AUTOFS_MODE;
	gethrestime(&now);
	fnp->fn_atime = fnp->fn_mtime = fnp->fn_ctime = now;
	fnp->fn_ref_time = now.tv_sec;
	mutex_enter(&autofs_nodeid_lock);
	fnp->fn_nodeid = nodeid;
	nodeid += 2;
	fnp->fn_globals = fngp;
	fngp->fng_fnnode_count++;
	mutex_exit(&autofs_nodeid_lock);
	vn_setops(vp, auto_vnodeops);
	vp->v_type = type;
	vp->v_data = (void *)fnp;
	vp->v_vfsp = vfsp;
	mutex_init(&fnp->fn_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&fnp->fn_rwlock, NULL, RW_DEFAULT, NULL);
	cv_init(&fnp->fn_cv_mount, NULL, CV_DEFAULT, NULL);
	vn_exists(vp);
	return (fnp);
}


void
auto_freefnnode(fnnode_t *fnp)
{
	vnode_t *vp = fntovn(fnp);

	AUTOFS_DPRINT((4, "auto_freefnnode: fnp=%p\n", (void *)fnp));

	ASSERT(fnp->fn_linkcnt == 0);
	ASSERT(vp->v_count == 0);
	ASSERT(fnp->fn_dirents == NULL);
	ASSERT(fnp->fn_parent == NULL);

	vn_invalid(vp);
	kmem_free(fnp->fn_name, fnp->fn_namelen);
	if (fnp->fn_symlink) {
		ASSERT(fnp->fn_flags & MF_THISUID_MATCH_RQD);
		kmem_free(fnp->fn_symlink, fnp->fn_symlinklen);
	}
	if (fnp->fn_cred)
		crfree(fnp->fn_cred);
	mutex_destroy(&fnp->fn_lock);
	rw_destroy(&fnp->fn_rwlock);
	cv_destroy(&fnp->fn_cv_mount);
	vn_free(vp);

	mutex_enter(&autofs_nodeid_lock);
	fnp->fn_globals->fng_fnnode_count--;
	mutex_exit(&autofs_nodeid_lock);
	kmem_free(fnp, sizeof (*fnp));
}

void
auto_disconnect(
	fnnode_t *dfnp,
	fnnode_t *fnp)
{
	fnnode_t *tmp, **fnpp;
	vnode_t *vp = fntovn(fnp);
	timestruc_t now;

	AUTOFS_DPRINT((4,
	    "auto_disconnect: dfnp=%p fnp=%p linkcnt=%d\n v_count=%d",
	    (void *)dfnp, (void *)fnp, fnp->fn_linkcnt, vp->v_count));

	ASSERT(RW_WRITE_HELD(&dfnp->fn_rwlock));
	ASSERT(fnp->fn_linkcnt == 1);

	if (vn_mountedvfs(vp) != NULL) {
		cmn_err(CE_PANIC, "auto_disconnect: vp %p mounted on",
		    (void *)vp);
	}

	/*
	 * Decrement by 1 because we're removing the entry in dfnp.
	 */
	fnp->fn_linkcnt--;
	fnp->fn_size--;

	/*
	 * only changed while holding parent's (dfnp) rw_lock
	 */
	fnp->fn_parent = NULL;

	fnpp = &dfnp->fn_dirents;
	for (;;) {
		tmp = *fnpp;
		if (tmp == NULL) {
			cmn_err(CE_PANIC,
			    "auto_disconnect: %p not in %p dirent list",
			    (void *)fnp, (void *)dfnp);
		}
		if (tmp == fnp) {
			*fnpp = tmp->fn_next; 	/* remove it from the list */
			ASSERT(vp->v_count == 0);
			/* child had a pointer to parent ".." */
			dfnp->fn_linkcnt--;
			dfnp->fn_size--;
			break;
		}
		fnpp = &tmp->fn_next;
	}

	mutex_enter(&fnp->fn_lock);
	gethrestime(&now);
	fnp->fn_atime = fnp->fn_mtime = now;
	mutex_exit(&fnp->fn_lock);

	AUTOFS_DPRINT((5, "auto_disconnect: done\n"));
}

int
auto_enter(fnnode_t *dfnp, char *name, fnnode_t **fnpp, cred_t *cred)
{
	struct fnnode *cfnp, **spp;
	vnode_t *dvp = fntovn(dfnp);
	ushort_t offset = 0;
	ushort_t diff;

	AUTOFS_DPRINT((4, "auto_enter: dfnp=%p, name=%s ", (void *)dfnp, name));

	ASSERT(RW_WRITE_HELD(&dfnp->fn_rwlock));

	cfnp = dfnp->fn_dirents;
	if (cfnp == NULL) {
		/*
		 * offset = 0 for '.' and offset = 1 for '..'
		 */
		spp = &dfnp->fn_dirents;
		offset = 2;
	}

	for (; cfnp; cfnp = cfnp->fn_next) {
		if (strcmp(cfnp->fn_name, name) == 0) {
			mutex_enter(&cfnp->fn_lock);
			if (cfnp->fn_flags & MF_THISUID_MATCH_RQD) {
				/*
				 * "thisuser" kind of node, need to
				 * match CREDs as well
				 */
				mutex_exit(&cfnp->fn_lock);
				if (crcmp(cfnp->fn_cred, cred) == 0)
					return (EEXIST);
			} else {
				mutex_exit(&cfnp->fn_lock);
				return (EEXIST);
			}
		}

		if (cfnp->fn_next != NULL) {
			diff = (ushort_t)
			    (cfnp->fn_next->fn_offset - cfnp->fn_offset);
			ASSERT(diff != 0);
			if (diff > 1 && offset == 0) {
				offset = (ushort_t)cfnp->fn_offset + 1;
				spp = &cfnp->fn_next;
			}
		} else if (offset == 0) {
			offset = (ushort_t)cfnp->fn_offset + 1;
			spp = &cfnp->fn_next;
		}
	}

	*fnpp = auto_makefnnode(VDIR, dvp->v_vfsp, name, cred,
	    dfnp->fn_globals);
	if (*fnpp == NULL)
		return (ENOMEM);

	/*
	 * I don't hold the mutex on fnpp because I created it, and
	 * I'm already holding the writers lock for it's parent
	 * directory, therefore nobody can reference it without me first
	 * releasing the writers lock.
	 */
	(*fnpp)->fn_offset = offset;
	(*fnpp)->fn_next = *spp;
	*spp = *fnpp;
	(*fnpp)->fn_parent = dfnp;
	(*fnpp)->fn_linkcnt++;	/* parent now holds reference to entry */
	(*fnpp)->fn_size++;

	/*
	 * dfnp->fn_linkcnt and dfnp->fn_size protected by dfnp->rw_lock
	 */
	dfnp->fn_linkcnt++;	/* child now holds reference to parent '..' */
	dfnp->fn_size++;

	dfnp->fn_ref_time = gethrestime_sec();

	AUTOFS_DPRINT((5, "*fnpp=%p\n", (void *)*fnpp));
	return (0);
}

int
auto_search(fnnode_t *dfnp, char *name, fnnode_t **fnpp, cred_t *cred)
{
	vnode_t *dvp;
	fnnode_t *p;
	int error = ENOENT, match = 0;

	AUTOFS_DPRINT((4, "auto_search: dfnp=%p, name=%s...\n",
	    (void *)dfnp, name));

	dvp = fntovn(dfnp);
	if (dvp->v_type != VDIR) {
		cmn_err(CE_PANIC, "auto_search: dvp=%p not a directory",
		    (void *)dvp);
	}

	ASSERT(RW_LOCK_HELD(&dfnp->fn_rwlock));
	for (p = dfnp->fn_dirents; p != NULL; p = p->fn_next) {
		if (strcmp(p->fn_name, name) == 0) {
			mutex_enter(&p->fn_lock);
			if (p->fn_flags & MF_THISUID_MATCH_RQD) {
				/*
				 * "thisuser" kind of node
				 * Need to match CREDs as well
				 */
				mutex_exit(&p->fn_lock);
				match = crcmp(p->fn_cred, cred) == 0;
			} else {
				/*
				 * No need to check CRED
				 */
				mutex_exit(&p->fn_lock);
				match = 1;
			}
		}
		if (match) {
			error = 0;
			if (fnpp) {
				*fnpp = p;
				VN_HOLD(fntovn(*fnpp));
			}
			break;
		}
	}

	AUTOFS_DPRINT((5, "auto_search: error=%d\n", error));
	return (error);
}

/*
 * If dvp is mounted on, get path's vnode in the mounted on
 * filesystem.  Path is relative to dvp, ie "./path".
 * If successful, *mvp points to a the held mountpoint vnode.
 */
/* ARGSUSED */
static int
auto_getmntpnt(
	vnode_t *dvp,
	char *path,
	vnode_t **mvpp,		/* vnode for mountpoint */
	cred_t *cred)
{
	int error = 0;
	vnode_t *newvp;
	char namebuf[TYPICALMAXPATHLEN];
	struct pathname lookpn;
	vfs_t *vfsp;

	AUTOFS_DPRINT((4, "auto_getmntpnt: path=%s\n", path));

	if (error = vn_vfsrlock_wait(dvp))
		return (error);

	/*
	 * Now that we have the vfswlock, check to see if dvp
	 * is still mounted on.  If not, then just bail out as
	 * there is no need to remount the triggers since the
	 * higher level mount point has gotten unmounted.
	 */
	vfsp = vn_mountedvfs(dvp);
	if (vfsp == NULL) {
		vn_vfsunlock(dvp);
		error = EBUSY;
		goto done;
	}
	/*
	 * Since mounted on, lookup "path" in the new filesystem,
	 * it is important that we do the filesystem jump here to
	 * avoid lookuppn() calling auto_lookup on dvp and deadlock.
	 */
	error = VFS_ROOT(vfsp, &newvp);
	vn_vfsunlock(dvp);
	if (error)
		goto done;

	/*
	 * We do a VN_HOLD on newvp just in case the first call to
	 * lookuppnvp() fails with ENAMETOOLONG.  We should still have a
	 * reference to this vnode for the second call to lookuppnvp().
	 */
	VN_HOLD(newvp);

	/*
	 * Now create the pathname struct so we can make use of lookuppnvp,
	 * and pn_getcomponent.
	 * This code is similar to lookupname() in fs/lookup.c.
	 */
	error = pn_get_buf(path, UIO_SYSSPACE, &lookpn,
	    namebuf, sizeof (namebuf));
	if (error == 0) {
		error = lookuppnvp(&lookpn, NULL, NO_FOLLOW, NULLVPP,
		    mvpp, rootdir, newvp, cred);
	} else
		VN_RELE(newvp);
	if (error == ENAMETOOLONG) {
		/*
		 * This thread used a pathname > TYPICALMAXPATHLEN bytes long.
		 * newvp is VN_RELE'd by this call to lookuppnvp.
		 *
		 * Using 'rootdir' in a zone's context is OK here: we already
		 * ascertained that there are no '..'s in the path, and we're
		 * not following symlinks.
		 */
		if ((error = pn_get(path, UIO_SYSSPACE, &lookpn)) == 0) {
			error = lookuppnvp(&lookpn, NULL, NO_FOLLOW, NULLVPP,
			    mvpp, rootdir, newvp, cred);
			pn_free(&lookpn);
		} else
			VN_RELE(newvp);
	} else {
		/*
		 * Need to release newvp here since we held it.
		 */
		VN_RELE(newvp);
	}

done:
	AUTOFS_DPRINT((5, "auto_getmntpnt: path=%s *mvpp=%p error=%d\n",
	    path, (void *)*mvpp, error));
	return (error);
}

#define	DEEPER(x) (((x)->fn_dirents != NULL) || \
			(vn_mountedvfs(fntovn((x)))) != NULL)

/*
 * The caller, should have already VN_RELE'd its reference to the
 * root vnode of this filesystem.
 */
static int
auto_inkernel_unmount(vfs_t *vfsp)
{
	vnode_t *cvp = vfsp->vfs_vnodecovered;
	int error;

	AUTOFS_DPRINT((4,
	    "auto_inkernel_unmount: devid=%lx mntpnt(%p) count %u\n",
	    vfsp->vfs_dev, (void *)cvp, cvp->v_count));

	ASSERT(vn_vfswlock_held(cvp));

	/*
	 * Perform the unmount
	 * The mountpoint has already been locked by the caller.
	 */
	error = dounmount(vfsp, 0, kcred);

	AUTOFS_DPRINT((5, "auto_inkernel_unmount: exit count %u\n",
	    cvp->v_count));
	return (error);
}

/*
 * unmounts trigger nodes in the kernel.
 */
static void
unmount_triggers(fnnode_t *fnp, action_list **alp)
{
	fnnode_t *tp, *next;
	int error = 0;
	vfs_t *vfsp;
	vnode_t *tvp;

	AUTOFS_DPRINT((4, "unmount_triggers: fnp=%p\n", (void *)fnp));
	ASSERT(RW_WRITE_HELD(&fnp->fn_rwlock));

	*alp = fnp->fn_alp;
	next = fnp->fn_trigger;
	while ((tp = next) != NULL) {
		tvp = fntovn(tp);
		ASSERT(tvp->v_count >= 2);
		next = tp->fn_next;
		/*
		 * drop writer's lock since the unmount will end up
		 * disconnecting this node from fnp and needs to acquire
		 * the writer's lock again.
		 * next has at least a reference count >= 2 since it's
		 * a trigger node, therefore can not be accidentally freed
		 * by a VN_RELE
		 */
		rw_exit(&fnp->fn_rwlock);

		vfsp = tvp->v_vfsp;

		/*
		 * Its parent was holding a reference to it, since this
		 * is a trigger vnode.
		 */
		VN_RELE(tvp);
		if (error = auto_inkernel_unmount(vfsp)) {
			cmn_err(CE_PANIC, "unmount_triggers: "
			    "unmount of vp=%p failed error=%d",
			    (void *)tvp, error);
		}
		/*
		 * reacquire writer's lock
		 */
		rw_enter(&fnp->fn_rwlock, RW_WRITER);
	}

	/*
	 * We were holding a reference to our parent.  Drop that.
	 */
	VN_RELE(fntovn(fnp));
	fnp->fn_trigger = NULL;
	fnp->fn_alp = NULL;

	AUTOFS_DPRINT((5, "unmount_triggers: finished\n"));
}

/*
 * This routine locks the mountpoint of every trigger node if they're
 * not busy, or returns EBUSY if any node is busy.
 */
static boolean_t
triggers_busy(fnnode_t *fnp)
{
	int done;
	int lck_error = 0;
	fnnode_t *tp, *t1p;
	vfs_t *vfsp;

	ASSERT(RW_WRITE_HELD(&fnp->fn_rwlock));

	for (tp = fnp->fn_trigger; tp != NULL; tp = tp->fn_next) {
		AUTOFS_DPRINT((10, "\ttrigger: %s\n", tp->fn_name));
		/* MF_LOOKUP should never be set on trigger nodes */
		ASSERT((tp->fn_flags & MF_LOOKUP) == 0);
		vfsp = fntovn(tp)->v_vfsp;

		/*
		 * The vn_vfsunlock will be done in auto_inkernel_unmount.
		 */
		lck_error = vn_vfswlock(vfsp->vfs_vnodecovered);

		if (lck_error != 0 || (tp->fn_flags & MF_INPROG) ||
		    DEEPER(tp) || ((fntovn(tp))->v_count) > 2) {
			/*
			 * couldn't lock it because it's busy,
			 * It is mounted on or has dirents?
			 * If reference count is greater than two, then
			 * somebody else is holding a reference to this vnode.
			 * One reference is for the mountpoint, and the second
			 * is for the trigger node.
			 */
			AUTOFS_DPRINT((10, "\ttrigger busy\n"));

			/*
			 * Unlock previously locked mountpoints
			 */
			for (done = 0, t1p = fnp->fn_trigger; !done;
			    t1p = t1p->fn_next) {
				/*
				 * Unlock all nodes previously
				 * locked. All nodes up to 'tp'
				 * were successfully locked. If 'lck_err' is
				 * set, then 'tp' was not locked, and thus
				 * should not be unlocked. If
				 * 'lck_err' is not set, then 'tp' was
				 * successfully locked, and it should
				 * be unlocked.
				 */
				if (t1p != tp || !lck_error) {
					vfsp = fntovn(t1p)->v_vfsp;
					vn_vfsunlock(vfsp->vfs_vnodecovered);
				}
				done = (t1p == tp);
			}
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * It is the caller's responsibility to grab the VVFSLOCK.
 * Releases the VVFSLOCK upon return.
 */
static int
unmount_node(vnode_t *cvp, int force)
{
	int error = 0;
	fnnode_t *cfnp;
	vfs_t *vfsp;
	umntrequest ul;
	fninfo_t *fnip;

	AUTOFS_DPRINT((4, "\tunmount_node cvp=%p\n", (void *)cvp));

	ASSERT(vn_vfswlock_held(cvp));
	cfnp = vntofn(cvp);
	vfsp = vn_mountedvfs(cvp);

	if (force || cfnp->fn_flags & MF_IK_MOUNT) {
		/*
		 * Mount was performed in the kernel, so
		 * do an in-kernel unmount. auto_inkernel_unmount()
		 * will vn_vfsunlock(cvp).
		 */
		error = auto_inkernel_unmount(vfsp);
	} else {
		zone_t *zone = NULL;
		refstr_t *mntpt, *resource;
		size_t mntoptslen;

		/*
		 * Get the mnttab information of the node
		 * and ask the daemon to unmount it.
		 */
		bzero(&ul, sizeof (ul));
		mntfs_getmntopts(vfsp, &ul.mntopts, &mntoptslen);
		if (ul.mntopts == NULL) {
			auto_log(cfnp->fn_globals->fng_verbose,
			    cfnp->fn_globals->fng_zoneid, CE_WARN,
			    "unmount_node: no memory");
			vn_vfsunlock(cvp);
			error = ENOMEM;
			goto done;
		}
		if (mntoptslen > AUTOFS_MAXOPTSLEN)
			ul.mntopts[AUTOFS_MAXOPTSLEN - 1] = '\0';

		mntpt = vfs_getmntpoint(vfsp);
		ul.mntpnt = (char *)refstr_value(mntpt);
		resource = vfs_getresource(vfsp);
		ul.mntresource = (char *)refstr_value(resource);

		fnip = vfstofni(cvp->v_vfsp);
		ul.isdirect = fnip->fi_flags & MF_DIRECT ? TRUE : FALSE;

		/*
		 * Since a zone'd automountd's view of the autofs mount points
		 * differs from those in the kernel, we need to make sure we
		 * give it consistent mount points.
		 */
		ASSERT(fnip->fi_zoneid == getzoneid());
		zone = curproc->p_zone;

		if (fnip->fi_zoneid != GLOBAL_ZONEID) {
			if (ZONE_PATH_VISIBLE(ul.mntpnt, zone)) {
				ul.mntpnt =
				    ZONE_PATH_TRANSLATE(ul.mntpnt, zone);
			}
			if (ZONE_PATH_VISIBLE(ul.mntresource, zone)) {
				ul.mntresource =
				    ZONE_PATH_TRANSLATE(ul.mntresource, zone);
			}
		}

		ul.fstype = vfssw[vfsp->vfs_fstype].vsw_name;
		vn_vfsunlock(cvp);

		error = auto_send_unmount_request(fnip, &ul, FALSE);
		kmem_free(ul.mntopts, mntoptslen);
		refstr_rele(mntpt);
		refstr_rele(resource);
	}

done:
	AUTOFS_DPRINT((5, "\tunmount_node cvp=%p error=%d\n", (void *)cvp,
	    error));
	return (error);
}

/*
 * return EBUSY if any thread is holding a reference to this vnode
 * other than us. Result of this function cannot be relied on, since
 * it doesn't follow proper locking rules (i.e. vp->v_vfsmountedhere
 * and fnp->fn_trigger can change throughout this function). However
 * it's good enough for rough estimation.
 */
static int
check_auto_node(vnode_t *vp)
{
	fnnode_t *fnp;
	int error = 0;
	/*
	 * number of references to expect for
	 * a non-busy vnode.
	 */
	uint_t count;

	AUTOFS_DPRINT((4, "\tcheck_auto_node vp=%p ", (void *)vp));
	fnp = vntofn(vp);

	count = 1;		/* we are holding a reference to vp */
	if (fnp->fn_flags & MF_TRIGGER) {
		/*
		 * parent holds a pointer to us (trigger)
		 */
		count++;
	}
	if (fnp->fn_trigger != NULL) {
		/*
		 * The trigger nodes have a hold on us.
		 */
		count++;
	}
	if (vn_ismntpt(vp)) {
		/*
		 * File system is mounted on us.
		 */
		count++;
	}
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count > 0);
	if (vp->v_flag & VROOT)
		count++;
	AUTOFS_DPRINT((10, "\tcount=%u ", vp->v_count));
	if (vp->v_count > count)
		error = EBUSY;
	mutex_exit(&vp->v_lock);

	AUTOFS_DPRINT((5, "\tcheck_auto_node error=%d ", error));
	return (error);
}

/*
 * rootvp is the root of the AUTOFS filesystem.
 * If rootvp is busy (v_count > 1) returns EBUSY.
 * else removes every vnode under this tree.
 * ASSUMPTION: Assumes that the only node which can be busy is
 * the root vnode. This filesystem better be two levels deep only,
 * the root and its immediate subdirs.
 * The daemon will "AUTOFS direct-mount" only one level below the root.
 */
static void
unmount_autofs(vnode_t *rootvp)
{
	fnnode_t *fnp, *rootfnp, *nfnp;

	AUTOFS_DPRINT((4, "\tunmount_autofs rootvp=%p ", (void *)rootvp));

	/*
	 * Remove all its immediate subdirectories.
	 */
	rootfnp = vntofn(rootvp);
	rw_enter(&rootfnp->fn_rwlock, RW_WRITER);
	for (fnp = rootfnp->fn_dirents; fnp != NULL; fnp = nfnp) {
		ASSERT(fntovn(fnp)->v_count == 0);
		ASSERT(fnp->fn_dirents == NULL);
		ASSERT(fnp->fn_linkcnt == 2);
		fnp->fn_linkcnt--;
		auto_disconnect(rootfnp, fnp);
		nfnp = fnp->fn_next;
		auto_freefnnode(fnp);
	}
	rw_exit(&rootfnp->fn_rwlock);
}

/*
 * If a node matches all unmount criteria, do:
 *     destroy subordinate trigger node(s) if there is any
 *     unmount filesystem mounted on top of the node if there is any
 *
 * Function should be called with locked fnp's mutex. The mutex is
 * unlocked before return from function.
 */
static int
try_unmount_node(fnnode_t *fnp, boolean_t force)
{
	boolean_t	trigger_unmount = B_FALSE;
	action_list	*alp = NULL;
	vnode_t		*vp;
	int		error = 0;
	fninfo_t	*fnip;
	vfs_t		*vfsp;
	struct autofs_globals *fngp;

	AUTOFS_DPRINT((10, "\ttry_unmount_node: processing node %p\n",
	    (void *)fnp));

	ASSERT(MUTEX_HELD(&fnp->fn_lock));

	fngp = fnp->fn_globals;
	vp = fntovn(fnp);
	fnip = vfstofni(vp->v_vfsp);

	/*
	 * If either a mount, lookup or another unmount of this subtree is in
	 * progress, don't attempt to unmount at this time.
	 */
	if (fnp->fn_flags & (MF_INPROG | MF_LOOKUP)) {
		mutex_exit(&fnp->fn_lock);
		return (EBUSY);
	}

	/*
	 * Bail out if someone else is holding reference to this vnode.
	 * This check isn't just an optimization (someone is probably
	 * just about to trigger mount). It is necessary to prevent a deadlock
	 * in domount() called from auto_perform_actions() if unmount of
	 * trigger parent fails. domount() calls lookupname() to resolve
	 * special in mount arguments. Special is set to a map name in case
	 * of autofs triggers (i.e. auto_ws.sun.com). Thus if current
	 * working directory is set to currently processed node, lookupname()
	 * calls into autofs vnops in order to resolve special, which deadlocks
	 * the process.
	 *
	 * Note: This should be fixed. Autofs shouldn't pass the map name
	 * in special and avoid useless lookup with potentially disasterous
	 * consequence.
	 */
	if (check_auto_node(vp) == EBUSY) {
		mutex_exit(&fnp->fn_lock);
		return (EBUSY);
	}

	/*
	 * If not forced operation, back out if node has been referenced
	 * recently.
	 */
	if (!force &&
	    fnp->fn_ref_time + fnip->fi_mount_to > gethrestime_sec()) {
		mutex_exit(&fnp->fn_lock);
		return (EBUSY);
	}

	/* block mounts/unmounts on the node */
	AUTOFS_BLOCK_OTHERS(fnp, MF_INPROG);
	fnp->fn_error = 0;
	mutex_exit(&fnp->fn_lock);

	/* unmount next level triggers if there are any */
	rw_enter(&fnp->fn_rwlock, RW_WRITER);
	if (fnp->fn_trigger != NULL) {
		trigger_unmount = B_TRUE;

		if (triggers_busy(fnp)) {
			rw_exit(&fnp->fn_rwlock);
			mutex_enter(&fnp->fn_lock);
			AUTOFS_UNBLOCK_OTHERS(fnp, MF_INPROG);
			mutex_exit(&fnp->fn_lock);
			return (EBUSY);
		}

		/*
		 * At this point, we know all trigger nodes are locked,
		 * and they're not busy or mounted on.
		 *
		 * Attempt to unmount all trigger nodes, save the
		 * action_list in case we need to remount them later.
		 * The action_list will be freed later if there was no
		 * need to remount the trigger nodes.
		 */
		unmount_triggers(fnp, &alp);
	}
	rw_exit(&fnp->fn_rwlock);

	(void) vn_vfswlock_wait(vp);

	vfsp = vn_mountedvfs(vp);
	if (vfsp != NULL) {
		/* vn_vfsunlock(vp) is done inside unmount_node() */
		error = unmount_node(vp, force);
		if (error == ECONNRESET) {
			if (vn_mountedvfs(vp) == NULL) {
				/*
				 * The filesystem was unmounted before the
				 * daemon died. Unfortunately we can not
				 * determine whether all the cleanup work was
				 * successfully finished (i.e. update mnttab,
				 * or notify NFS server of the unmount).
				 * We should not retry the operation since the
				 * filesystem has already been unmounted, and
				 * may have already been removed from mnttab,
				 * in such case the devid/rdevid we send to
				 * the daemon will not be matched. So we have
				 * to be content with the partial unmount.
				 * Since the mountpoint is no longer covered, we
				 * clear the error condition.
				 */
				error = 0;
				auto_log(fngp->fng_verbose, fngp->fng_zoneid,
				    CE_WARN, "autofs: automountd "
				    "connection dropped when unmounting %s/%s",
				    fnip->fi_path, (fnip->fi_flags & MF_DIRECT)
				    ? "" : fnp->fn_name);
			}
		}
	} else {
		vn_vfsunlock(vp);
		/* Destroy all dirents of fnp if we unmounted its triggers */
		if (trigger_unmount)
			unmount_autofs(vp);
	}

	/* If unmount failed, we got to remount triggers */
	if (error != 0) {
		if (trigger_unmount) {
			int	ret;

			ASSERT((fnp->fn_flags & MF_THISUID_MATCH_RQD) == 0);

			/*
			 * The action list was free'd by auto_perform_actions
			 */
			ret = auto_perform_actions(fnip, fnp, alp, CRED());
			if (ret != 0) {
				auto_log(fngp->fng_verbose, fngp->fng_zoneid,
				    CE_WARN, "autofs: can't remount triggers "
				    "fnp=%p error=%d", (void *)fnp, ret);
			}
		}
		mutex_enter(&fnp->fn_lock);
		AUTOFS_UNBLOCK_OTHERS(fnp, MF_INPROG);
		mutex_exit(&fnp->fn_lock);
	} else {
		/* Free the action list here */
		if (trigger_unmount)
			xdr_free(xdr_action_list, (char *)alp);

		/*
		 * Other threads may be waiting for this unmount to
		 * finish. We must let it know that in order to
		 * proceed, it must trigger the mount itself.
		 */
		mutex_enter(&fnp->fn_lock);
		fnp->fn_flags &= ~MF_IK_MOUNT;
		if (fnp->fn_flags & MF_WAITING)
			fnp->fn_error = EAGAIN;
		AUTOFS_UNBLOCK_OTHERS(fnp, MF_INPROG);
		mutex_exit(&fnp->fn_lock);
	}

	return (error);
}

/*
 * This is an implementation of depth-first search in a tree rooted by
 * start_fnp and composed from fnnodes. Links between tree levels are
 * fn_dirents, fn_trigger in fnnode_t and v_mountedvfs in vnode_t (if
 * mounted vfs is autofs). The algorithm keeps track of visited nodes
 * by means of a timestamp (fn_unmount_ref_time).
 *
 * Upon top-down traversal of the tree we apply following locking scheme:
 *	lock fn_rwlock of current node
 *	grab reference to child's vnode (VN_HOLD)
 *	unlock fn_rwlock
 *	free reference to current vnode (VN_RELE)
 * Similar locking scheme is used for down-top and left-right traversal.
 *
 * Algorithm examines the most down-left node in tree, which hasn't been
 * visited yet. From this follows that nodes are processed in bottom-up
 * fashion.
 *
 * Function returns either zero if unmount of root node was successful
 * or error code (mostly EBUSY).
 */
int
unmount_subtree(fnnode_t *rootfnp, boolean_t force)
{
	fnnode_t	*currfnp; /* currently examined node in the tree */
	fnnode_t	*lastfnp; /* previously processed node */
	fnnode_t	*nextfnp; /* next examined node in the tree */
	vnode_t		*curvp;
	vnode_t		*newvp;
	vfs_t		*vfsp;
	time_t		timestamp;

	ASSERT(fntovn(rootfnp)->v_type != VLNK);
	AUTOFS_DPRINT((10, "unmount_subtree: root=%p (%s)\n", (void *)rootfnp,
	    rootfnp->fn_name));

	/*
	 * Timestamp, which visited nodes are marked with, to distinguish them
	 * from unvisited nodes.
	 */
	timestamp = gethrestime_sec();
	currfnp = lastfnp = rootfnp;

	/* Loop until we examine all nodes in the tree */
	mutex_enter(&currfnp->fn_lock);
	while (currfnp != rootfnp || rootfnp->fn_unmount_ref_time < timestamp) {
		curvp = fntovn(currfnp);
		AUTOFS_DPRINT((10, "\tunmount_subtree: entering node %p (%s)\n",
		    (void *)currfnp, currfnp->fn_name));

		/*
		 * New candidate for processing must have been already visited,
		 * by us because we want to process tree nodes in bottom-up
		 * order.
		 */
		if (currfnp->fn_unmount_ref_time == timestamp &&
		    currfnp != lastfnp) {
			(void) try_unmount_node(currfnp, force);
			lastfnp = currfnp;
			mutex_enter(&currfnp->fn_lock);
			/*
			 * Fall through to next if-branch to pick
			 * sibling or parent of this node.
			 */
		}

		/*
		 * If this node has been already visited, it means that it's
		 * dead end and we need to pick sibling or parent as next node.
		 */
		if (currfnp->fn_unmount_ref_time >= timestamp ||
		    curvp->v_type == VLNK) {
			mutex_exit(&currfnp->fn_lock);
			/*
			 * Obtain parent's readers lock before grabbing
			 * reference to sibling.
			 */
			rw_enter(&currfnp->fn_parent->fn_rwlock, RW_READER);
			if ((nextfnp = currfnp->fn_next) != NULL) {
				VN_HOLD(fntovn(nextfnp));
				rw_exit(&currfnp->fn_parent->fn_rwlock);
				VN_RELE(curvp);
				currfnp = nextfnp;
				mutex_enter(&currfnp->fn_lock);
				continue;
			}
			rw_exit(&currfnp->fn_parent->fn_rwlock);

			/*
			 * All descendants and siblings were visited. Perform
			 * bottom-up move.
			 */
			nextfnp = currfnp->fn_parent;
			VN_HOLD(fntovn(nextfnp));
			VN_RELE(curvp);
			currfnp = nextfnp;
			mutex_enter(&currfnp->fn_lock);
			continue;
		}

		/*
		 * Mark node as visited. Note that the timestamp could have
		 * been updated by somebody else in the meantime.
		 */
		if (currfnp->fn_unmount_ref_time < timestamp)
			currfnp->fn_unmount_ref_time = timestamp;

		/*
		 * Don't descent below nodes, which are being unmounted/mounted.
		 *
		 * We need to hold both locks at once: fn_lock because we need
		 * to read MF_INPROG and fn_rwlock to prevent anybody from
		 * modifying fn_trigger until its used to traverse triggers
		 * below.
		 *
		 * Acquire fn_rwlock in non-blocking mode to avoid deadlock.
		 * If it can't be acquired, then acquire locks in correct
		 * order.
		 */
		if (!rw_tryenter(&currfnp->fn_rwlock, RW_READER)) {
			mutex_exit(&currfnp->fn_lock);
			rw_enter(&currfnp->fn_rwlock, RW_READER);
			mutex_enter(&currfnp->fn_lock);
		}
		if (currfnp->fn_flags & MF_INPROG) {
			rw_exit(&currfnp->fn_rwlock);
			continue;
		}
		mutex_exit(&currfnp->fn_lock);

		/*
		 * Examine descendants in this order: triggers, dirents, autofs
		 * mounts.
		 */

		if ((nextfnp = currfnp->fn_trigger) != NULL) {
			VN_HOLD(fntovn(nextfnp));
			rw_exit(&currfnp->fn_rwlock);
			VN_RELE(curvp);
			currfnp = nextfnp;
			mutex_enter(&currfnp->fn_lock);
			continue;
		}

		if ((nextfnp = currfnp->fn_dirents) != NULL) {
			VN_HOLD(fntovn(nextfnp));
			rw_exit(&currfnp->fn_rwlock);
			VN_RELE(curvp);
			currfnp = nextfnp;
			mutex_enter(&currfnp->fn_lock);
			continue;
		}
		rw_exit(&currfnp->fn_rwlock);

		(void) vn_vfswlock_wait(curvp);
		vfsp = vn_mountedvfs(curvp);
		if (vfsp != NULL &&
		    vfs_matchops(vfsp, vfs_getops(curvp->v_vfsp))) {
			/*
			 * Deal with /xfn/host/jurassic alikes here...
			 *
			 * We know this call to VFS_ROOT is safe to call while
			 * holding VVFSLOCK, since it resolves to a call to
			 * auto_root().
			 */
			if (VFS_ROOT(vfsp, &newvp)) {
				cmn_err(CE_PANIC,
				    "autofs: VFS_ROOT(vfs=%p) failed",
				    (void *)vfsp);
			}
			vn_vfsunlock(curvp);
			VN_RELE(curvp);
			currfnp = vntofn(newvp);
			mutex_enter(&currfnp->fn_lock);
			continue;
		}
		vn_vfsunlock(curvp);
		mutex_enter(&currfnp->fn_lock);
	}

	/*
	 * Now we deal with the root node (currfnp's mutex is unlocked
	 * in try_unmount_node()).
	 */
	return (try_unmount_node(currfnp, force));
}

/*
 * XXX unmount_tree() is not suspend-safe within the scope of
 * the present model defined for cpr to suspend the system. Calls made
 * by the unmount_tree() that have been identified to be unsafe are
 * (1) RPC client handle setup and client calls to automountd which can
 * block deep down in the RPC library, (2) kmem_alloc() calls with the
 * KM_SLEEP flag which can block if memory is low, and (3) VFS_*() and
 * VOP_*() calls which can result in over the wire calls to servers.
 * The thread should be completely reevaluated to make it suspend-safe in
 * case of future updates to the cpr model.
 */
void
unmount_tree(struct autofs_globals *fngp, boolean_t force)
{
	callb_cpr_t	cprinfo;
	kmutex_t	unmount_tree_cpr_lock;
	fnnode_t	*root, *fnp, *next;

	mutex_init(&unmount_tree_cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cprinfo, &unmount_tree_cpr_lock, callb_generic_cpr,
	    "unmount_tree");

	/*
	 * autofssys() will be calling in from the global zone and doing
	 * work on the behalf of the given zone, hence we can't always
	 * assert that we have the right credentials, nor that the
	 * caller is always in the correct zone.
	 *
	 * We do, however, know that if this is a "forced unmount"
	 * operation (which autofssys() does), then we won't go down to
	 * the krpc layers, so we don't need to fudge with the
	 * credentials.
	 */
	ASSERT(force || fngp->fng_zoneid == getzoneid());

	/*
	 * If automountd is not running in this zone,
	 * don't attempt unmounting this round.
	 */
	if (force || auto_null_request(fngp->fng_zoneid, FALSE) == 0) {
		/*
		 * Iterate over top level autofs filesystems and call
		 * unmount_subtree() for each of them.
		 */
		root = fngp->fng_rootfnnodep;
		rw_enter(&root->fn_rwlock, RW_READER);
		for (fnp = root->fn_dirents; fnp != NULL; fnp = next) {
			VN_HOLD(fntovn(fnp));
			rw_exit(&root->fn_rwlock);
			(void) unmount_subtree(fnp, force);
			rw_enter(&root->fn_rwlock, RW_READER);
			next = fnp->fn_next;
			VN_RELE(fntovn(fnp));
		}
		rw_exit(&root->fn_rwlock);
	}

	mutex_enter(&unmount_tree_cpr_lock);
	CALLB_CPR_EXIT(&cprinfo);
	mutex_destroy(&unmount_tree_cpr_lock);
}

static void
unmount_zone_tree(struct autofs_globals *fngp)
{
	AUTOFS_DPRINT((5, "unmount_zone_tree started. Thread created.\n"));

	unmount_tree(fngp, B_FALSE);
	mutex_enter(&fngp->fng_unmount_threads_lock);
	fngp->fng_unmount_threads--;
	mutex_exit(&fngp->fng_unmount_threads_lock);

	AUTOFS_DPRINT((5, "unmount_zone_tree done. Thread exiting.\n"));

	zthread_exit();
	/* NOTREACHED */
}

void
auto_do_unmount(struct autofs_globals *fngp)
{
	callb_cpr_t cprinfo;
	clock_t timeleft;
	zone_t *zone = curproc->p_zone;

	CALLB_CPR_INIT(&cprinfo, &fngp->fng_unmount_threads_lock,
	    callb_generic_cpr, "auto_do_unmount");

	for (;;) {	/* forever */
		mutex_enter(&fngp->fng_unmount_threads_lock);
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
newthread:
		mutex_exit(&fngp->fng_unmount_threads_lock);
		timeleft = zone_status_timedwait(zone, ddi_get_lbolt() +
		    autofs_unmount_thread_timer * hz, ZONE_IS_SHUTTING_DOWN);
		mutex_enter(&fngp->fng_unmount_threads_lock);

		if (timeleft != -1) {	/* didn't time out */
			ASSERT(zone_status_get(zone) >= ZONE_IS_SHUTTING_DOWN);
			/*
			 * zone is exiting... don't create any new threads.
			 * fng_unmount_threads_lock is released implicitly by
			 * the below.
			 */
			CALLB_CPR_SAFE_END(&cprinfo,
			    &fngp->fng_unmount_threads_lock);
			CALLB_CPR_EXIT(&cprinfo);
			zthread_exit();
			/* NOTREACHED */
		}
		if (fngp->fng_unmount_threads < autofs_unmount_threads) {
			fngp->fng_unmount_threads++;
			CALLB_CPR_SAFE_END(&cprinfo,
			    &fngp->fng_unmount_threads_lock);
			mutex_exit(&fngp->fng_unmount_threads_lock);

			(void) zthread_create(NULL, 0, unmount_zone_tree, fngp,
			    0, minclsyspri);
		} else
			goto newthread;
	}
	/* NOTREACHED */
}

/*
 * Is nobrowse specified in option string?
 * opts should be a null ('\0') terminated string.
 * Returns non-zero if nobrowse has been specified.
 */
int
auto_nobrowse_option(char *opts)
{
	char *buf;
	char *p;
	char *t;
	int nobrowse = 0;
	int last_opt = 0;
	size_t len;

	len = strlen(opts) + 1;
	p = buf = kmem_alloc(len, KM_SLEEP);
	(void) strcpy(buf, opts);
	do {
		if (t = strchr(p, ','))
			*t++ = '\0';
		else
			last_opt++;
		if (strcmp(p, MNTOPT_NOBROWSE) == 0)
			nobrowse = 1;
		else if (strcmp(p, MNTOPT_BROWSE) == 0)
			nobrowse = 0;
		p = t;
	} while (!last_opt);
	kmem_free(buf, len);

	return (nobrowse);
}

/*
 * used to log warnings only if automountd is running
 * with verbose mode set
 */

void
auto_log(int verbose, zoneid_t zoneid, int level, const char *fmt, ...)
{
	va_list	args;

	if (verbose) {
		va_start(args, fmt);
		vzcmn_err(zoneid, level, fmt, args);
		va_end(args);
	}
}

#ifdef DEBUG
static int autofs_debug = 0;

/*
 * Utilities used by both client and server
 * Standard levels:
 * 0) no debugging
 * 1) hard failures
 * 2) soft failures
 * 3) current test software
 * 4) main procedure entry points
 * 5) main procedure exit points
 * 6) utility procedure entry points
 * 7) utility procedure exit points
 * 8) obscure procedure entry points
 * 9) obscure procedure exit points
 * 10) random stuff
 * 11) all <= 1
 * 12) all <= 2
 * 13) all <= 3
 * ...
 */
/* PRINTFLIKE2 */
void
auto_dprint(int level, const char *fmt, ...)
{
	va_list args;

	if (autofs_debug == level ||
	    (autofs_debug > 10 && (autofs_debug - 10) >= level)) {
		va_start(args, fmt);
		(void) vprintf(fmt, args);
		va_end(args);
	}
}
#endif /* DEBUG */
