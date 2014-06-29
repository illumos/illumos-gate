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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * vnode ops for the /dev/net directory
 *
 *	The lookup is based on the internal vanity naming node table.  We also
 *	override readdir in order to delete net nodes no longer	in-use.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/dls.h>

static const char *devnet_zpath = "/dev/net/zone/";
struct vnodeops		*devnet_vnodeops;

static zoneid_t
devnet_nodetozone(sdev_node_t *dv)
{
	char *zname = NULL, *dup;
	zone_t *zone;
	int duplen;
	zoneid_t zid;

	/*
	 * If in a non-global zone, always return it's zid no matter what the
	 * node is.
	 */
	zid = getzoneid();
	if (zid != GLOBAL_ZONEID)
		return (zid);

	/*
	 * If it doesn't have /dev/net/zone/ then it can't be a specific zone
	 * we're targetting.
	 */
	if (strncmp(devnet_zpath, dv->sdev_path, strlen(devnet_zpath)) != 0)
		return (GLOBAL_ZONEID);

	if (dv->sdev_vnode->v_type == VDIR) {
		zone = zone_find_by_name(dv->sdev_name);
	} else {
		/* Non directories have the form /dev/net/zone/%z/%s */
		dup = strdup(dv->sdev_path);
		duplen = strlen(dup);
		zname = strrchr(dup, '/');
		*zname = '\0';
		zname--;
		zname = strrchr(dup, '/');
		zname++;
		zone = zone_find_by_name(zname);
		kmem_free(dup, duplen + 1);
	}
	if (zone == NULL)
		return (GLOBAL_ZONEID);
	zid = zone->zone_id;
	zone_rele(zone);
	return (zid);
}

static int
devnet_mkdir(struct sdev_node *ddv, char *name)
{
	sdev_node_t *dv;
	struct vattr va;
	int ret;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	dv = sdev_cache_lookup(ddv, name);
	if (dv != NULL) {
		SDEV_SIMPLE_RELE(dv);
		return (EEXIST);
	}

	va = *sdev_getdefault_attr(VDIR);
	gethrestime(&va.va_atime);
	va.va_mtime = va.va_atime;
	va.va_ctime = va.va_atime;

	ret = sdev_mknode(ddv, name, &dv, &va, NULL, NULL, kcred, SDEV_READY);
	if (ret != 0)
		return (ret);
	SDEV_SIMPLE_RELE(dv);
	return (0);
}

/*
 * We basically need to walk down the directory path to determine what we should
 * do. At the top level of /dev/net, only the directory /dev/net/zone is valid,
 * and it is always valid. Following on that, /dev/net/zone/%zonename is valid
 * if and only if we can look up that zone name. If it's not, or it's some other
 * name, then it's SDEV_VTOR_INVALID.
 */
static int
devnet_dirvalidate(struct sdev_node *dv)
{
	zone_t *zonep;
	char *path = "/dev/net/zone";

	if (strcmp(path, dv->sdev_path) == 0)
		return (SDEV_VTOR_VALID);

	zonep = zone_find_by_name(dv->sdev_name);
	if (zonep == NULL)
		return (SDEV_VTOR_INVALID);
	zone_rele(zonep);
	return (SDEV_VTOR_VALID);
}

/*
 * Check if a net sdev_node is still valid - i.e. it represents a current
 * network link.
 * This serves two purposes
 *	- only valid net nodes are returned during lookup() and readdir().
 *	- since net sdev_nodes are not actively destroyed when a network link
 *	  goes away, we use the validator to do deferred cleanup i.e. when such
 *	  nodes are encountered during subsequent lookup() and readdir().
 */
int
devnet_validate(struct sdev_node *dv)
{
	datalink_id_t linkid;
	zoneid_t zoneid;

	ASSERT(dv->sdev_state == SDEV_READY);

	if (dv->sdev_vnode->v_type == VDIR)
		return (devnet_dirvalidate(dv));

	if (strncmp(devnet_zpath, dv->sdev_path, strlen(devnet_zpath)) == 0) {
		ASSERT(SDEV_IS_GLOBAL(dv));
		zoneid = devnet_nodetozone(dv);
	} else {
		zoneid = getzoneid();
	}

	if (dls_mgmt_get_linkid_in_zone(dv->sdev_name, &linkid, zoneid) != 0)
		return (SDEV_VTOR_INVALID);
	if (zoneid == GLOBAL_ZONEID)
		return (SDEV_VTOR_VALID);
	return (zone_check_datalink(&zoneid, linkid) == 0 ?
	    SDEV_VTOR_VALID : SDEV_VTOR_INVALID);
}

/*
 * This callback is invoked from devname_lookup_func() to create
 * a net entry when the node is not found in the cache.
 */
static int
devnet_create_rvp(const char *nm, struct vattr *vap, dls_dl_handle_t *ddhp,
    zoneid_t zid)
{
	timestruc_t now;
	dev_t dev;
	int error;

	if ((error = dls_devnet_open_in_zone(nm, ddhp, &dev, zid)) != 0) {
		sdcmn_err12(("devnet_create_rvp: not a valid vanity name "
		    "network node: %s\n", nm));
		return (error);
	}

	/*
	 * This is a valid network device (at least at this point in time).
	 * Create the node by setting the attribute; the rest is taken care
	 * of by devname_lookup_func().
	 */
	*vap = sdev_vattr_chr;
	vap->va_mode |= 0666;
	vap->va_rdev = dev;

	gethrestime(&now);
	vap->va_atime = now;
	vap->va_mtime = now;
	vap->va_ctime = now;
	return (0);
}

/*
 * Lookup for /dev/net directory
 *	If the entry does not exist, the devnet_create_rvp() callback
 *	is invoked to create it.  Nodes do not persist across reboot.
 */
/*ARGSUSED3*/
static int
devnet_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	struct sdev_node *ddv = VTOSDEV(dvp);
	struct sdev_node *dv = NULL;
	dls_dl_handle_t ddh = NULL;
	zone_t *zone;
	struct vattr vattr;
	int nmlen;
	int error = ENOENT;

	if (SDEVTOV(ddv)->v_type != VDIR)
		return (ENOTDIR);

	if (!SDEV_IS_GLOBAL(ddv) && crgetzoneid(cred) == GLOBAL_ZONEID)
		return (EPERM);

	/*
	 * Empty name or ., return node itself.
	 */
	nmlen = strlen(nm);
	if ((nmlen == 0) || ((nmlen == 1) && (nm[0] == '.'))) {
		*vpp = SDEVTOV(ddv);
		VN_HOLD(*vpp);
		return (0);
	}

	/*
	 * .., return the parent directory
	 */
	if ((nmlen == 2) && (strcmp(nm, "..") == 0)) {
		*vpp = SDEVTOV(ddv->sdev_dotdot);
		VN_HOLD(*vpp);
		return (0);
	}

	rw_enter(&ddv->sdev_contents, RW_WRITER);

	/*
	 * ZOMBIED parent does not allow new node creation, bail out early.
	 */
	if (ddv->sdev_state == SDEV_ZOMBIE)
		goto failed;

	/*
	 * directory cache lookup:
	 */
	if ((dv = sdev_cache_lookup(ddv, nm)) != NULL) {
		ASSERT(dv->sdev_state == SDEV_READY);
		if (!(dv->sdev_flags & SDEV_ATTR_INVALID))
			goto found;
	}

	if (SDEV_IS_GLOBAL(ddv)) {
		/*
		 * Check for /dev/net/zone
		 */
		if (strcmp("zone", nm) == 0 && strcmp("/dev/net",
		    ddv->sdev_path) == 0) {
			(void) devnet_mkdir(ddv, nm);
			dv = sdev_cache_lookup(ddv, nm);
			ASSERT(dv != NULL);
			goto found;
		}

		/*
		 * Check for /dev/net/zone/%z. We can't use devnet_zpath due to
		 * its trailing slash.
		 */
		if (strcmp("/dev/net/zone", ddv->sdev_path) == 0) {
			zone = zone_find_by_name(nm);
			if (zone == NULL)
				goto failed;
			(void) devnet_mkdir(ddv, nm);
			zone_rele(zone);
			dv = sdev_cache_lookup(ddv, nm);
			ASSERT(dv != NULL);
			goto found;
		}
	} else if (strcmp("/dev/net", ddv->sdev_path) != 0) {
		goto failed;
	}

	/*
	 * We didn't find what we were looking for. What that is depends a lot
	 * on what directory we're in.
	 */

	error = devnet_create_rvp(nm, &vattr, &ddh, devnet_nodetozone(ddv));
	if (error != 0)
		goto failed;

	error = sdev_mknode(ddv, nm, &dv, &vattr, NULL, NULL, cred, SDEV_READY);
	if (error != 0) {
		dls_devnet_close(ddh);
		goto failed;
	}

	ASSERT(dv != NULL);

	rw_enter(&dv->sdev_contents, RW_WRITER);
	if (dv->sdev_flags & SDEV_ATTR_INVALID) {
		/*
		 * SDEV_ATTR_INVALID means that this device has been
		 * detached, and its dev_t might've been changed too.
		 * Therefore, sdev_node's 'vattr' needs to be updated.
		 */
		SDEVTOV(dv)->v_rdev = vattr.va_rdev;
		ASSERT(dv->sdev_attr != NULL);
		dv->sdev_attr->va_rdev = vattr.va_rdev;
		dv->sdev_flags &= ~SDEV_ATTR_INVALID;
	}
	ASSERT(dv->sdev_private == NULL);
	dv->sdev_private = ddh;
	rw_exit(&dv->sdev_contents);

found:
	ASSERT(SDEV_HELD(dv));
	rw_exit(&ddv->sdev_contents);
	return (sdev_to_vp(dv, vpp));

failed:
	rw_exit(&ddv->sdev_contents);

	if (dv != NULL)
		SDEV_RELE(dv);

	*vpp = NULL;
	return (error);
}

static int
devnet_filldir_datalink(datalink_id_t linkid, void *arg)
{
	struct sdev_node	*ddv = arg;
	struct vattr		vattr;
	struct sdev_node	*dv;
	dls_dl_handle_t		ddh = NULL;
	char			link[MAXLINKNAMELEN];

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));

	if (dls_mgmt_get_linkinfo(linkid, link, NULL, NULL, NULL) != 0)
		return (0);

	if ((dv = sdev_cache_lookup(ddv, (char *)link)) != NULL)
		goto found;

	if (devnet_create_rvp(link, &vattr, &ddh, devnet_nodetozone(arg)) != 0)
		return (0);

	ASSERT(ddh != NULL);
	dls_devnet_close(ddh);

	if (sdev_mknode(ddv, (char *)link, &dv, &vattr, NULL, NULL, kcred,
	    SDEV_READY) != 0) {
		return (0);
	}

	/*
	 * As there is no reference holding the network device, it could be
	 * detached. Set SDEV_ATTR_INVALID so that the 'vattr' will be updated
	 * later.
	 */
	rw_enter(&dv->sdev_contents, RW_WRITER);
	dv->sdev_flags |= SDEV_ATTR_INVALID;
	rw_exit(&dv->sdev_contents);

found:
	SDEV_SIMPLE_RELE(dv);
	return (0);
}

/*
 * Fill in all the entries for the current zone.
 */
static void
devnet_fillzone(struct sdev_node *ddv, zoneid_t zid)
{
	datalink_id_t	linkid;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	if (zid == GLOBAL_ZONEID) {
		ASSERT(SDEV_IS_GLOBAL(ddv));
		linkid = DATALINK_INVALID_LINKID;
		do {
			linkid = dls_mgmt_get_next(linkid, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLMGMT_ACTIVE);
			if (linkid != DATALINK_INVALID_LINKID)
				(void) devnet_filldir_datalink(linkid, ddv);
		} while (linkid != DATALINK_INVALID_LINKID);
	} else {
		(void) zone_datalink_walk(zid,  devnet_filldir_datalink, ddv);
	}
}

/*
 * Callback for zone_walk when filling up /dev/net/zone/...
 */
static int
devnet_fillzdir_cb(zone_t *zonep, void *arg)
{
	sdev_node_t *ddv = arg;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));
	(void) devnet_mkdir(ddv, zonep->zone_name);
	return (0);
}

/*
 * Fill in a directory that isn't the top level /dev/net.
 */
static void
devnet_fillzdir(struct sdev_node *ddv)
{
	zone_t *zonep;
	char *path = "/dev/net/zone";

	if (strcmp(path, ddv->sdev_path) == 0) {
		(void) zone_walk(devnet_fillzdir_cb, ddv);
		return;
	}

	zonep = zone_find_by_name(ddv->sdev_name);
	if (zonep == NULL)
		return;
	devnet_fillzone(ddv, zonep->zone_id);
	zone_rele(zonep);
}

static void
devnet_filldir(struct sdev_node *ddv)
{
	int ret;
	sdev_node_t *dv, *next;

	ASSERT(RW_READ_HELD(&ddv->sdev_contents));
	if (rw_tryupgrade(&ddv->sdev_contents) == NULL) {
		rw_exit(&ddv->sdev_contents);
		rw_enter(&ddv->sdev_contents, RW_WRITER);
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

		switch (devnet_validate(dv)) {
		case SDEV_VTOR_VALID:
		case SDEV_VTOR_SKIP:
			continue;
		case SDEV_VTOR_INVALID:
		case SDEV_VTOR_STALE:
			sdcmn_err12(("devnet_filldir: destroy invalid "
			    "node: %s(%p)\n", dv->sdev_name, (void *)dv));
			break;
		}

		if (SDEVTOV(dv)->v_count > 0)
			continue;

		SDEV_HOLD(dv);

		/*
		 * Clean out everything underneath before we remove ourselves.
		 */
		if (SDEVTOV(ddv)->v_type == VDIR) {
			ret = sdev_cleandir(dv, NULL, 0);
			ASSERT(ret == 0);
		}
		/* remove the cache node */
		(void) sdev_cache_update(ddv, &dv, dv->sdev_name,
		    SDEV_CACHE_DELETE);
		SDEV_RELE(dv);
	}

	if (strcmp(ddv->sdev_path, "/dev/net") != 0) {
		devnet_fillzdir(ddv);
		goto done;
	}

	if (((ddv->sdev_flags & SDEV_BUILD) == 0) && !dls_devnet_rebuild())
		goto done;

	if (SDEV_IS_GLOBAL(ddv)) {
		devnet_fillzone(ddv, GLOBAL_ZONEID);
		(void) devnet_mkdir(ddv, "zone");
	} else {
		devnet_fillzone(ddv, getzoneid());
	}

	ddv->sdev_flags &= ~SDEV_BUILD;
done:
	rw_downgrade(&ddv->sdev_contents);
}

/*
 * Display all instantiated network datalink device nodes.
 * A /dev/net entry will be created only after the first lookup of
 * the network datalink device succeeds.
 */
/*ARGSUSED4*/
static int
devnet_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred,
    int *eofp, caller_context_t *ct, int flags)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);

	ASSERT(sdvp);

	if (crgetzoneid(cred) == GLOBAL_ZONEID && !SDEV_IS_GLOBAL(sdvp))
		return (EPERM);

	if (uiop->uio_offset == 0)
		devnet_filldir(sdvp);

	return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
}

/*
 * This callback is invoked from devname_inactive_func() to release
 * the net entry which was held in devnet_create_rvp().
 */
static void
devnet_inactive_callback(struct vnode *dvp)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	dls_dl_handle_t ddh;

	if (dvp->v_type == VDIR)
		return;

	ASSERT(dvp->v_type == VCHR);
	rw_enter(&sdvp->sdev_contents, RW_WRITER);
	ddh = sdvp->sdev_private;
	sdvp->sdev_private = NULL;
	sdvp->sdev_flags |= SDEV_ATTR_INVALID;
	rw_exit(&sdvp->sdev_contents);

	/*
	 * "ddh" (sdev_private) could be NULL if devnet_lookup fails.
	 */
	if (ddh != NULL)
		dls_devnet_close(ddh);
}

/*ARGSUSED*/
static void
devnet_inactive(struct vnode *dvp, struct cred *cred, caller_context_t *ct)
{
	devname_inactive_func(dvp, cred, devnet_inactive_callback);
}

/*
 * We override lookup and readdir to build entries based on the
 * in kernel vanity naming node table.
 */
const fs_operation_def_t devnet_vnodeops_tbl[] = {
	VOPNAME_READDIR,	{ .vop_readdir = devnet_readdir },
	VOPNAME_LOOKUP,		{ .vop_lookup = devnet_lookup },
	VOPNAME_INACTIVE,	{ .vop_inactive = devnet_inactive },
	VOPNAME_CREATE,		{ .error = fs_nosys },
	VOPNAME_REMOVE,		{ .error = fs_nosys },
	VOPNAME_MKDIR,		{ .error = fs_nosys },
	VOPNAME_RMDIR,		{ .error = fs_nosys },
	VOPNAME_SYMLINK,	{ .error = fs_nosys },
	VOPNAME_SETSECATTR,	{ .error = fs_nosys },
	NULL,			NULL
};
