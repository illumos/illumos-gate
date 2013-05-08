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
 * vnode ops for the /dev/pts directory
 *	The lookup is based on the internal pty table. We also
 *	override readdir in order to delete pts nodes no longer
 *	in use.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/policy.h>
#include <sys/ptms.h>
#include <sys/stat.h>
#include <sys/vfs_opreg.h>

#define	DEVPTS_UID_DEFAULT	0
#define	DEVPTS_GID_DEFAULT	3
#define	DEVPTS_DEVMODE_DEFAULT	(0620)

#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')

static vattr_t devpts_vattr = {
	AT_TYPE|AT_MODE|AT_UID|AT_GID,		/* va_mask */
	VCHR,					/* va_type */
	S_IFCHR | DEVPTS_DEVMODE_DEFAULT,	/* va_mode */
	DEVPTS_UID_DEFAULT,			/* va_uid */
	DEVPTS_GID_DEFAULT,			/* va_gid */
	0					/* 0 hereafter */
};

struct vnodeops		*devpts_vnodeops;

struct vnodeops *
devpts_getvnodeops(void)
{
	return (devpts_vnodeops);
}

/*
 * Convert string to minor number. Some care must be taken
 * as we are processing user input. Catch cases like
 * /dev/pts/4foo and /dev/pts/-1
 */
static int
devpts_strtol(const char *nm, minor_t *mp)
{
	long uminor = 0;
	char *endptr = NULL;

	if (nm == NULL || !isdigit(*nm))
		return (EINVAL);

	*mp = 0;
	if (ddi_strtol(nm, &endptr, 10, &uminor) != 0 ||
	    *endptr != '\0' || uminor < 0) {
		return (EINVAL);
	}

	*mp = (minor_t)uminor;
	return (0);
}

/*
 * Check if a pts sdev_node is still valid - i.e. it represents a current pty.
 * This serves two purposes
 *	- only valid pts nodes are returned during lookup() and readdir().
 *	- since pts sdev_nodes are not actively destroyed when a pty goes
 *	  away, we use the validator to do deferred cleanup i.e. when such
 *	  nodes are encountered during subsequent lookup() and readdir().
 */
/*ARGSUSED*/
int
devpts_validate(struct sdev_node *dv)
{
	minor_t min;
	uid_t uid;
	gid_t gid;
	timestruc_t now;
	char *nm = dv->sdev_name;

	ASSERT(dv->sdev_state == SDEV_READY);

	/* validate only READY nodes */
	if (dv->sdev_state != SDEV_READY) {
		sdcmn_err(("dev fs: skipping: node not ready %s(%p)",
		    nm, (void *)dv));
		return (SDEV_VTOR_SKIP);
	}

	if (devpts_strtol(nm, &min) != 0) {
		sdcmn_err7(("devpts_validate: not a valid minor: %s\n", nm));
		return (SDEV_VTOR_INVALID);
	}

	/*
	 * Check if pts driver is attached
	 */
	if (ptms_slave_attached() == (major_t)-1) {
		sdcmn_err7(("devpts_validate: slave not attached\n"));
		return (SDEV_VTOR_INVALID);
	}

	if (ptms_minor_valid(min, &uid, &gid) == 0) {
		if (ptms_minor_exists(min)) {
			sdcmn_err7(("devpts_validate: valid in different zone "
			    "%s\n", nm));
			return (SDEV_VTOR_SKIP);
		} else {
			sdcmn_err7(("devpts_validate: %s not valid pty\n",
			    nm));
			return (SDEV_VTOR_INVALID);
		}
	}

	ASSERT(dv->sdev_attr);
	if (dv->sdev_attr->va_uid != uid || dv->sdev_attr->va_gid != gid) {
		dv->sdev_attr->va_uid = uid;
		dv->sdev_attr->va_gid = gid;
		gethrestime(&now);
		dv->sdev_attr->va_atime = now;
		dv->sdev_attr->va_mtime = now;
		dv->sdev_attr->va_ctime = now;
		sdcmn_err7(("devpts_validate: update uid/gid/times%s\n", nm));
	}

	return (SDEV_VTOR_VALID);
}

/*
 * This callback is invoked from devname_lookup_func() to create
 * a pts entry when the node is not found in the cache.
 */
/*ARGSUSED*/
static int
devpts_create_rvp(struct sdev_node *ddv, char *nm,
    void **arg, cred_t *cred, void *whatever, char *whichever)
{
	minor_t min;
	major_t maj;
	uid_t uid;
	gid_t gid;
	timestruc_t now;
	struct vattr *vap = (struct vattr *)arg;

	if (devpts_strtol(nm, &min) != 0) {
		sdcmn_err7(("devpts_create_rvp: not a valid minor: %s\n", nm));
		return (-1);
	}

	/*
	 * Check if pts driver is attached and if it is
	 * get the major number.
	 */
	maj = ptms_slave_attached();
	if (maj == (major_t)-1) {
		sdcmn_err7(("devpts_create_rvp: slave not attached\n"));
		return (-1);
	}

	/*
	 * Only allow creation of ptys allocated to our zone
	 */
	if (!ptms_minor_valid(min, &uid, &gid)) {
		sdcmn_err7(("devpts_create_rvp: %s not valid pty"
		    "or not valid in this zone\n", nm));
		return (-1);
	}


	/*
	 * This is a valid pty (at least at this point in time).
	 * Create the node by setting the attribute. The rest
	 * is taken care of by devname_lookup_func().
	 */
	*vap = devpts_vattr;
	vap->va_rdev = makedevice(maj, min);
	vap->va_uid = uid;
	vap->va_gid = gid;
	gethrestime(&now);
	vap->va_atime = now;
	vap->va_mtime = now;
	vap->va_ctime = now;

	return (0);
}

/*
 * Clean pts sdev_nodes that are no longer valid.
 */
static void
devpts_prunedir(struct sdev_node *ddv)
{
	struct vnode *vp;
	struct sdev_node *dv, *next = NULL;
	int (*vtor)(struct sdev_node *) = NULL;

	ASSERT(ddv->sdev_flags & SDEV_VTOR);

	vtor = (int (*)(struct sdev_node *))sdev_get_vtor(ddv);
	ASSERT(vtor);

	if (rw_tryupgrade(&ddv->sdev_contents) == NULL) {
		rw_exit(&ddv->sdev_contents);
		rw_enter(&ddv->sdev_contents, RW_WRITER);
	}

	for (dv = SDEV_FIRST_ENTRY(ddv); dv; dv = next) {
		next = SDEV_NEXT_ENTRY(ddv, dv);

		/* validate and prune only ready nodes */
		if (dv->sdev_state != SDEV_READY)
			continue;

		switch (vtor(dv)) {
		case SDEV_VTOR_VALID:
		case SDEV_VTOR_SKIP:
			continue;
		case SDEV_VTOR_INVALID:
		case SDEV_VTOR_STALE:
			sdcmn_err7(("prunedir: destroy invalid "
			    "node: %s(%p)\n", dv->sdev_name, (void *)dv));
			break;
		}
		vp = SDEVTOV(dv);
		if (vp->v_count > 0)
			continue;
		SDEV_HOLD(dv);
		/* remove the cache node */
		(void) sdev_cache_update(ddv, &dv, dv->sdev_name,
		    SDEV_CACHE_DELETE);
		SDEV_RELE(dv);
	}
	rw_downgrade(&ddv->sdev_contents);
}

/*
 * Lookup for /dev/pts directory
 *	If the entry does not exist, the devpts_create_rvp() callback
 *	is invoked to create it. Nodes do not persist across reboot.
 *
 * There is a potential denial of service here via
 * fattach on top of a /dev/pts node - any permission changes
 * applied to the node, apply to the fattached file and not
 * to the underlying pts node. As a result when the previous
 * user fdetaches, the pts node is still owned by the previous
 * owner. To prevent this we don't allow fattach() on top of a pts
 * node. This is done by a modification in the namefs filesystem
 * where we check if the underlying node has the /dev/pts vnodeops.
 * We do this via VOP_REALVP() on the underlying specfs node.
 * sdev_nodes currently don't have a realvp. If a realvp is ever
 * created for sdev_nodes, then VOP_REALVP() will return the
 * actual realvp (possibly a ufs vnode). This will defeat the check
 * in namefs code which checks if VOP_REALVP() returns a devpts
 * node. We add an ASSERT here in /dev/pts lookup() to check for
 * this condition. If sdev_nodes ever get a VOP_REALVP() entry point,
 * change the code in the namefs filesystem code (in nm_mount()) to
 * access the realvp of the specfs node directly instead of using
 * VOP_REALVP().
 */
/*ARGSUSED3*/
static int
devpts_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	struct sdev_node *dv;
	struct vnode *rvp = NULL;
	int error;

	error = devname_lookup_func(sdvp, nm, vpp, cred, devpts_create_rvp,
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
			cmn_err(CE_PANIC, "devpts_lookup: Unsupported node "
			    "type: %p: %d", (void *)(*vpp), (*vpp)->v_type);
			break;
		}
		ASSERT(SDEV_HELD(dv));
	}

	return (error);
}

/*
 * We allow create to find existing nodes
 *	- if the node doesn't exist - EROFS
 *	- creating an existing dir read-only succeeds, otherwise EISDIR
 *	- exclusive creates fail - EEXIST
 */
/*ARGSUSED2*/
static int
devpts_create(struct vnode *dvp, char *nm, struct vattr *vap, vcexcl_t excl,
    int mode, struct vnode **vpp, struct cred *cred, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	int error;
	struct vnode *vp;

	*vpp = NULL;

	error = devpts_lookup(dvp, nm, &vp, NULL, 0, NULL, cred, ct, NULL,
	    NULL);
	if (error == 0) {
		if (excl == EXCL)
			error = EEXIST;
		else if (vp->v_type == VDIR && (mode & VWRITE))
			error = EISDIR;
		else
			error = VOP_ACCESS(vp, mode, 0, cred, ct);

		if (error) {
			VN_RELE(vp);
		} else
			*vpp = vp;
	} else if (error == ENOENT) {
		error = EROFS;
	}

	return (error);
}

/*
 * Display all instantiated pts (slave) device nodes.
 * A /dev/pts entry will be created only after the first lookup of the slave
 * device succeeds.
 */
/*ARGSUSED4*/
static int
devpts_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred,
    int *eofp, caller_context_t *ct, int flags)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	if (uiop->uio_offset == 0) {
		devpts_prunedir(sdvp);
	}

	return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
}


static int
devpts_set_id(struct sdev_node *dv, struct vattr *vap, int protocol)
{
	ASSERT((protocol & AT_UID) || (protocol & AT_GID));
	ptms_set_owner(getminor(SDEVTOV(dv)->v_rdev),
	    vap->va_uid, vap->va_gid);
	return (0);

}

/*ARGSUSED4*/
static int
devpts_setattr(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cred, caller_context_t *ctp)
{
	ASSERT((vp->v_type == VCHR) || (vp->v_type == VDIR));
	return (devname_setattr_func(vp, vap, flags, cred,
	    devpts_set_id, AT_UID|AT_GID));
}


/*
 * We override lookup and readdir to build entries based on the
 * in kernel pty table. Also override setattr/setsecattr to
 * avoid persisting permissions.
 */
const fs_operation_def_t devpts_vnodeops_tbl[] = {
	VOPNAME_READDIR,	{ .vop_readdir = devpts_readdir },
	VOPNAME_LOOKUP,		{ .vop_lookup = devpts_lookup },
	VOPNAME_CREATE,		{ .vop_create = devpts_create },
	VOPNAME_SETATTR,	{ .vop_setattr = devpts_setattr },
	VOPNAME_REMOVE,		{ .error = fs_nosys },
	VOPNAME_MKDIR,		{ .error = fs_nosys },
	VOPNAME_RMDIR,		{ .error = fs_nosys },
	VOPNAME_SYMLINK,	{ .error = fs_nosys },
	VOPNAME_SETSECATTR,	{ .error = fs_nosys },
	NULL,			NULL
};
