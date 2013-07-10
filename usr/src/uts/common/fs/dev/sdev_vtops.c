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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * vnode ops for the /dev/vt directory
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/policy.h>
#include <sys/stat.h>
#include <sys/vfs_opreg.h>
#include <sys/tty.h>
#include <sys/vt_impl.h>
#include <sys/note.h>

/* warlock in this file only cares about variables shared by vt and devfs */
_NOTE(SCHEME_PROTECTS_DATA("Do not care", sdev_node vattr vnode))

#define	DEVVT_UID_DEFAULT	SDEV_UID_DEFAULT
#define	DEVVT_GID_DEFAULT	(0)
#define	DEVVT_DEVMODE_DEFAULT	(0600)
#define	DEVVT_ACTIVE_NAME	"active"
#define	DEVVT_CONSUSER_NAME	"console_user"

#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')

/* attributes for VT nodes */
static vattr_t devvt_vattr = {
	AT_TYPE|AT_MODE|AT_UID|AT_GID,		/* va_mask */
	VCHR,					/* va_type */
	S_IFCHR | DEVVT_DEVMODE_DEFAULT,	/* va_mode */
	DEVVT_UID_DEFAULT,			/* va_uid */
	DEVVT_GID_DEFAULT,			/* va_gid */
	0					/* 0 hereafter */
};

struct vnodeops		*devvt_vnodeops;

struct vnodeops *
devvt_getvnodeops(void)
{
	return (devvt_vnodeops);
}

static int
devvt_str2minor(const char *nm, minor_t *mp)
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
 * Validate that a node is up-to-date and correct.
 * A validator may not update the node state or
 * contents as a read lock permits entry by
 * multiple threads.
 */
int
devvt_validate(struct sdev_node *dv)
{
	minor_t min;
	char *nm = dv->sdev_name;
	int rval;

	ASSERT(dv->sdev_state == SDEV_READY);
	ASSERT(RW_LOCK_HELD(&(dv->sdev_dotdot)->sdev_contents));

	/* validate only READY nodes */
	if (dv->sdev_state != SDEV_READY) {
		sdcmn_err(("dev fs: skipping: node not ready %s(%p)",
		    nm, (void *)dv));
		return (SDEV_VTOR_SKIP);
	}

	if (vt_wc_attached() == (major_t)-1)
		return (SDEV_VTOR_INVALID);

	if (strcmp(nm, DEVVT_ACTIVE_NAME) == 0) {
		char *link = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		(void) vt_getactive(link, MAXPATHLEN);
		rval = (strcmp(link, dv->sdev_symlink) == 0) ?
		    SDEV_VTOR_VALID : SDEV_VTOR_STALE;
		kmem_free(link, MAXPATHLEN);
		return (rval);
	}

	if (strcmp(nm, DEVVT_CONSUSER_NAME) == 0) {
		char *link = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		(void) vt_getconsuser(link, MAXPATHLEN);
		rval = (strcmp(link, dv->sdev_symlink) == 0) ?
		    SDEV_VTOR_VALID : SDEV_VTOR_STALE;
		kmem_free(link, MAXPATHLEN);
		return (rval);
	}

	if (devvt_str2minor(nm, &min) != 0) {
		return (SDEV_VTOR_INVALID);
	}

	if (vt_minor_valid(min) == B_FALSE)
		return (SDEV_VTOR_INVALID);

	return (SDEV_VTOR_VALID);
}

/*
 * This callback is invoked from devname_lookup_func() to create
 * a entry when the node is not found in the cache.
 */
/*ARGSUSED*/
static int
devvt_create_rvp(struct sdev_node *ddv, char *nm,
    void **arg, cred_t *cred, void *whatever, char *whichever)
{
	minor_t min;
	major_t maj;
	struct vattr *vap = (struct vattr *)arg;

	if ((maj = vt_wc_attached()) == (major_t)-1)
		return (SDEV_VTOR_INVALID);

	if (strcmp(nm, DEVVT_ACTIVE_NAME) == 0) {
		(void) vt_getactive((char *)*arg, MAXPATHLEN);
		return (0);
	}

	if (strcmp(nm, DEVVT_CONSUSER_NAME) == 0) {
		(void) vt_getconsuser((char *)*arg, MAXPATHLEN);
		return (0);
	}
	if (devvt_str2minor(nm, &min) != 0)
		return (-1);

	if (vt_minor_valid(min) == B_FALSE)
		return (-1);

	*vap = devvt_vattr;
	vap->va_rdev = makedevice(maj, min);

	return (0);
}

/*ARGSUSED3*/
static int
devvt_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	struct sdev_node *dv;
	struct vnode *rvp = NULL;
	int type, error;

	if ((strcmp(nm, DEVVT_ACTIVE_NAME) == 0) ||
	    (strcmp(nm, DEVVT_CONSUSER_NAME) == 0)) {
		type = SDEV_VLINK;
	} else {
		type = SDEV_VATTR;
	}

/* Give warlock a more clear call graph */
#ifndef __lock_lint
	error = devname_lookup_func(sdvp, nm, vpp, cred,
	    devvt_create_rvp, type);
#else
	devvt_create_rvp(0, 0, 0, 0, 0, 0);
#endif

	if (error == 0) {
		switch ((*vpp)->v_type) {
		case VCHR:
			dv = VTOSDEV(VTOS(*vpp)->s_realvp);
			ASSERT(VOP_REALVP(SDEVTOV(dv), &rvp, NULL) == ENOSYS);
			break;
		case VDIR:
		case VLNK:
			dv = VTOSDEV(*vpp);
			break;
		default:
			cmn_err(CE_PANIC, "devvt_lookup: Unsupported node "
			    "type: %p: %d", (void *)(*vpp), (*vpp)->v_type);
			break;
		}
		ASSERT(SDEV_HELD(dv));
	}

	return (error);
}

static void
devvt_create_snode(struct sdev_node *ddv, char *nm, struct cred *cred, int type)
{
	int error;
	struct sdev_node *sdv = NULL;
	struct vattr vattr;
	struct vattr *vap = &vattr;
	major_t maj;
	minor_t min;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));

	if ((maj = vt_wc_attached()) == (major_t)-1)
		return;

	if (strcmp(nm, DEVVT_ACTIVE_NAME) != 0 &&
	    strcmp(nm, DEVVT_CONSUSER_NAME) != 0 &&
	    devvt_str2minor(nm, &min) != 0)
		return;

	error = sdev_mknode(ddv, nm, &sdv, NULL, NULL, NULL, cred, SDEV_INIT);
	if (error || !sdv) {
		return;
	}

	mutex_enter(&sdv->sdev_lookup_lock);
	SDEV_BLOCK_OTHERS(sdv, SDEV_LOOKUP);
	mutex_exit(&sdv->sdev_lookup_lock);

	if (type & SDEV_VATTR) {
		*vap = devvt_vattr;
		vap->va_rdev = makedevice(maj, min);
		error = sdev_mknode(ddv, nm, &sdv, vap, NULL,
		    NULL, cred, SDEV_READY);
	} else if (type & SDEV_VLINK) {
		char *link = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

		(void) vt_getactive(link, MAXPATHLEN);
		*vap = sdev_vattr_lnk;
		vap->va_size = strlen(link);
		error = sdev_mknode(ddv, nm, &sdv, vap, NULL,
		    (void *)link, cred, SDEV_READY);

		kmem_free(link, MAXPATHLEN);
	}

	if (error != 0) {
		SDEV_RELE(sdv);
		return;
	}

	mutex_enter(&sdv->sdev_lookup_lock);
	SDEV_UNBLOCK_OTHERS(sdv, SDEV_LOOKUP);
	mutex_exit(&sdv->sdev_lookup_lock);

}

static void
devvt_rebuild_stale_link(struct sdev_node *ddv, struct sdev_node *dv)
{
	char *link;

	ASSERT(RW_WRITE_HELD(&ddv->sdev_contents));

	ASSERT((strcmp(dv->sdev_name, DEVVT_ACTIVE_NAME) == 0) ||
	    (strcmp(dv->sdev_name, DEVVT_CONSUSER_NAME) == 0));

	link = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (strcmp(dv->sdev_name, DEVVT_ACTIVE_NAME) == 0) {
		(void) vt_getactive(link, MAXPATHLEN);
	} else if (strcmp(dv->sdev_name, DEVVT_CONSUSER_NAME) == 0) {
		(void) vt_getconsuser(link, MAXPATHLEN);
	}

	if (strcmp(link, dv->sdev_symlink) != 0) {
		strfree(dv->sdev_symlink);
		dv->sdev_symlink = strdup(link);
		dv->sdev_attr->va_size = strlen(link);
	}
	kmem_free(link, MAXPATHLEN);
}

/*
 * First step in refreshing directory contents.
 * Remove each invalid entry and rebuild the link
 * reference for each stale entry.
 */
static void
devvt_prunedir(struct sdev_node *ddv)
{
	struct vnode *vp;
	struct sdev_node *dv, *next = NULL;
	int (*vtor)(struct sdev_node *) = NULL;

	ASSERT(ddv->sdev_flags & SDEV_VTOR);

	vtor = (int (*)(struct sdev_node *))sdev_get_vtor(ddv);
	ASSERT(vtor);

	for (dv = SDEV_FIRST_ENTRY(ddv); dv; dv = next) {
		next = SDEV_NEXT_ENTRY(ddv, dv);

		switch (vtor(dv)) {
		case SDEV_VTOR_VALID:
			break;
		case SDEV_VTOR_SKIP:
			break;
		case SDEV_VTOR_INVALID:
			vp = SDEVTOV(dv);
			if (vp->v_count != 0)
				break;
			/* remove the cached node */
			SDEV_HOLD(dv);
			(void) sdev_cache_update(ddv, &dv,
			    dv->sdev_name, SDEV_CACHE_DELETE);
			SDEV_RELE(dv);
			break;
		case SDEV_VTOR_STALE:
			devvt_rebuild_stale_link(ddv, dv);
			break;
		}
	}
}

static void
devvt_cleandir(struct vnode *dvp, struct cred *cred)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	struct sdev_node *dv, *next = NULL;
	int min, cnt;
	char found = 0;

	mutex_enter(&vc_lock);
	cnt = VC_INSTANCES_COUNT;
	mutex_exit(&vc_lock);

/* We have to fool warlock this way, otherwise it will complain */
#ifndef	__lock_lint
	if (rw_tryupgrade(&sdvp->sdev_contents) == NULL) {
		rw_exit(&sdvp->sdev_contents);
		rw_enter(&sdvp->sdev_contents, RW_WRITER);
	}
#else
	rw_enter(&sdvp->sdev_contents, RW_WRITER);
#endif

	/* 1.  prune invalid nodes and rebuild stale symlinks */
	devvt_prunedir(sdvp);

	/* 2. create missing nodes */
	for (min = 0; min < cnt; min++) {
		char nm[16];

		if (vt_minor_valid(min) == B_FALSE)
			continue;

		(void) snprintf(nm, sizeof (nm), "%d", min);
		found = 0;
		for (dv = SDEV_FIRST_ENTRY(sdvp); dv; dv = next) {
			next = SDEV_NEXT_ENTRY(sdvp, dv);

			/* validate only ready nodes */
			if (dv->sdev_state != SDEV_READY)
				continue;
			if (strcmp(nm, dv->sdev_name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			devvt_create_snode(sdvp, nm, cred, SDEV_VATTR);
		}
	}

	/* 3. create active link node and console user link node */
	found = 0;
	for (dv = SDEV_FIRST_ENTRY(sdvp); dv; dv = next) {
		next = SDEV_NEXT_ENTRY(sdvp, dv);

		/* validate only ready nodes */
		if (dv->sdev_state != SDEV_READY)
			continue;
		if ((strcmp(dv->sdev_name, DEVVT_ACTIVE_NAME) == NULL))
			found |= 0x01;
		if ((strcmp(dv->sdev_name, DEVVT_CONSUSER_NAME) == NULL))
			found |= 0x02;

		if ((found & 0x01) && (found & 0x02))
			break;
	}
	if (!(found & 0x01))
		devvt_create_snode(sdvp, DEVVT_ACTIVE_NAME, cred, SDEV_VLINK);
	if (!(found & 0x02))
		devvt_create_snode(sdvp, DEVVT_CONSUSER_NAME, cred, SDEV_VLINK);

#ifndef	__lock_lint
	rw_downgrade(&sdvp->sdev_contents);
#else
	rw_exit(&sdvp->sdev_contents);
#endif
}

/*ARGSUSED4*/
static int
devvt_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred,
    int *eofp, caller_context_t *ct, int flags)
{
	if (uiop->uio_offset == 0) {
		devvt_cleandir(dvp, cred);
	}

	return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
}

/*
 * We allow create to find existing nodes
 *	- if the node doesn't exist - EROFS
 *	- creating an existing dir read-only succeeds, otherwise EISDIR
 *	- exclusive creates fail - EEXIST
 */
/*ARGSUSED2*/
static int
devvt_create(struct vnode *dvp, char *nm, struct vattr *vap, vcexcl_t excl,
    int mode, struct vnode **vpp, struct cred *cred, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	int error;
	struct vnode *vp;

	*vpp = NULL;

	if ((error = devvt_lookup(dvp, nm, &vp, NULL, 0, NULL, cred, ct, NULL,
	    NULL)) != 0) {
		if (error == ENOENT)
			error = EROFS;
		return (error);
	}

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

	return (error);
}

const fs_operation_def_t devvt_vnodeops_tbl[] = {
	VOPNAME_READDIR,	{ .vop_readdir = devvt_readdir },
	VOPNAME_LOOKUP,		{ .vop_lookup = devvt_lookup },
	VOPNAME_CREATE,		{ .vop_create = devvt_create },
	VOPNAME_REMOVE,		{ .error = fs_nosys },
	VOPNAME_MKDIR,		{ .error = fs_nosys },
	VOPNAME_RMDIR,		{ .error = fs_nosys },
	VOPNAME_SYMLINK,	{ .error = fs_nosys },
	VOPNAME_SETSECATTR,	{ .error = fs_nosys },
	NULL,			NULL
};
