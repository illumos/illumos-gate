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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * vnode ops for the /dev/ipnet directory
 *	The lookup is based on the ipnetif nodes held
 *	in the ipnet module. We also override readdir
 *	in order to delete ipnet nodes no longer in use.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/policy.h>
#include <inet/ipnet.h>
#include <sys/zone.h>

struct vnodeops		*devipnet_vnodeops;

static void
devipnet_fill_vattr(struct vattr *vap, dev_t dev)
{
	timestruc_t now;

	*vap = sdev_vattr_chr;
	vap->va_rdev = dev;
	vap->va_mode |= 0666;

	gethrestime(&now);
	vap->va_atime = now;
	vap->va_mtime = now;
	vap->va_ctime = now;
}

/*
 * Check if an ipnet sdev_node is still valid.
 */
int
devipnet_validate(struct sdev_node *dv)
{
	dev_t	dev;

	dev = ipnet_if_getdev(dv->sdev_name, getzoneid());
	if (dev == (dev_t)-1)
		return (SDEV_VTOR_INVALID);
	if (getminor(SDEVTOV(dv)->v_rdev) != getminor(dev))
		return (SDEV_VTOR_STALE);
	return (SDEV_VTOR_VALID);
}

/*
 * This callback is invoked from devname_lookup_func() to create
 * an ipnet entry when the node is not found in the cache.
 */
/*ARGSUSED*/
static int
devipnet_create_rvp(struct sdev_node *ddv, char *nm,
    void **arg, cred_t *cred, void *whatever, char *whichever)
{
	dev_t		dev;
	struct vattr	*vap = (struct vattr *)arg;
	int		err = 0;

	if ((dev = ipnet_if_getdev(nm, getzoneid())) == (dev_t)-1)
		err = ENOENT;
	else
		devipnet_fill_vattr(vap, dev);

	return (err);
}

/*
 * Lookup for /dev/ipnet directory
 *	If the entry does not exist, the devipnet_create_rvp() callback
 *	is invoked to create it. Nodes do not persist across reboot.
 */
/*ARGSUSED3*/
static int
devipnet_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	struct sdev_node *dv;
	struct vnode *rvp = NULL;
	int error;

	error = devname_lookup_func(sdvp, nm, vpp, cred, devipnet_create_rvp,
	    SDEV_VATTR);

	if (error == 0) {
		switch ((*vpp)->v_type) {
		case VCHR:
			dv = VTOSDEV(VTOS(*vpp)->s_realvp);
			ASSERT(VOP_REALVP(SDEVTOV(dv), &rvp, NULL) == ENOSYS);
			break;
		case VDIR:
			dv = VTOSDEV(*vpp);
			break;
		default:
			cmn_err(CE_PANIC, "devipnet_lookup: Unsupported node "
			    "type: %p: %d", (void *)(*vpp), (*vpp)->v_type);
			break;
		}
		ASSERT(SDEV_HELD(dv));
	}

	return (error);
}

static void
devipnet_filldir_entry(const char *name, void *arg, dev_t dev)
{
	struct sdev_node *ddv = arg;
	struct vattr vattr;
	struct sdev_node *dv;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));

	if ((dv = sdev_cache_lookup(ddv, (char *)name)) == NULL) {
		devipnet_fill_vattr(&vattr, dev);
		if (sdev_mknode(ddv, (char *)name, &dv, &vattr, NULL, NULL,
		    kcred, SDEV_READY) != 0)
			return;
	}
	SDEV_SIMPLE_RELE(dv);
}

static void
devipnet_filldir(struct sdev_node *ddv)
{
	sdev_node_t	*dv, *next;

	ASSERT(RW_READ_HELD(&ddv->sdev_contents));
	if (rw_tryupgrade(&ddv->sdev_contents) == NULL) {
		rw_exit(&ddv->sdev_contents);
		rw_enter(&ddv->sdev_contents, RW_WRITER);
		/*
		 * We've been made a zombie while we weren't looking. We'll bail
		 * if that's the case.
		 */
		if (ddv->sdev_state == SDEV_ZOMBIE) {
			rw_exit(&ddv->sdev_contents);
			return;
		}
	}

	for (dv = SDEV_FIRST_ENTRY(ddv); dv; dv = next) {
		next = SDEV_NEXT_ENTRY(ddv, dv);

		/* validate and prune only ready nodes */
		if (dv->sdev_state != SDEV_READY)
			continue;
		switch (devipnet_validate(dv)) {
		case SDEV_VTOR_VALID:
		case SDEV_VTOR_SKIP:
			continue;
		case SDEV_VTOR_INVALID:
		case SDEV_VTOR_STALE:
			sdcmn_err12(("devipnet_filldir: destroy invalid "
			    "node: %s(%p)\n", dv->sdev_name, (void *)dv));
			break;
		}

		if (SDEVTOV(dv)->v_count > 0)
			continue;
		SDEV_HOLD(dv);
		/* remove the cache node */
		(void) sdev_cache_update(ddv, &dv, dv->sdev_name,
		    SDEV_CACHE_DELETE);
		SDEV_RELE(dv);
	}

	ipnet_walk_if(devipnet_filldir_entry, ddv, getzoneid());

	rw_downgrade(&ddv->sdev_contents);
}

/*
 * Display all instantiated ipnet device nodes.
 */
/* ARGSUSED */
static int
devipnet_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred,
    int *eofp, caller_context_t *ct, int flags)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);

	if (uiop->uio_offset == 0)
		devipnet_filldir(sdvp);

	return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
}

/*
 * We override lookup and readdir to build entries based on the
 * in kernel ipnet table.
 */
const fs_operation_def_t devipnet_vnodeops_tbl[] = {
	VOPNAME_READDIR,	{ .vop_readdir = devipnet_readdir },
	VOPNAME_LOOKUP,		{ .vop_lookup = devipnet_lookup },
	VOPNAME_CREATE,		{ .error = fs_nosys },
	VOPNAME_REMOVE,		{ .error = fs_nosys },
	VOPNAME_MKDIR,		{ .error = fs_nosys },
	VOPNAME_RMDIR,		{ .error = fs_nosys },
	VOPNAME_SYMLINK,	{ .error = fs_nosys },
	VOPNAME_SETSECATTR,	{ .error = fs_nosys },
	NULL,			NULL
};
