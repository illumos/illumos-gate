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
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

/* vnode ops for the /dev/zvol directory */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/sunldi.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/sdev_impl.h>
#include <sys/zfs_ioctl.h>
#include <sys/policy.h>
#include <sys/stat.h>
#include <sys/vfs_opreg.h>

struct vnodeops	*devzvol_vnodeops;
static uint64_t devzvol_gen = 0;
static uint64_t devzvol_zclist;
static size_t devzvol_zclist_size;
static ldi_ident_t devzvol_li;
static ldi_handle_t devzvol_lh;
static kmutex_t devzvol_mtx;
static boolean_t devzvol_isopen;
static major_t devzvol_major;

/*
 * we need to use ddi_mod* since fs/dev gets loaded early on in
 * startup(), and linking fs/dev to fs/zfs would drag in a lot of
 * other stuff (like drv/random) before the rest of the system is
 * ready to go
 */
ddi_modhandle_t zfs_mod;
int (*szcm)(char *);
int (*szn2m)(char *, minor_t *);

int
sdev_zvol_create_minor(char *dsname)
{
	if (szcm == NULL)
		return (-1);
	return ((*szcm)(dsname));
}

int
sdev_zvol_name2minor(char *dsname, minor_t *minor)
{
	if (szn2m == NULL)
		return (-1);
	return ((*szn2m)(dsname, minor));
}

int
devzvol_open_zfs()
{
	int rc;
	dev_t dv;

	devzvol_li = ldi_ident_from_anon();
	if (ldi_open_by_name("/dev/zfs", FREAD | FWRITE, kcred,
	    &devzvol_lh, devzvol_li))
		return (-1);
	if (zfs_mod == NULL && ((zfs_mod = ddi_modopen("fs/zfs",
	    KRTLD_MODE_FIRST, &rc)) == NULL)) {
		return (rc);
	}
	ASSERT(szcm == NULL && szn2m == NULL);
	if ((szcm = (int (*)(char *))
	    ddi_modsym(zfs_mod, "zvol_create_minor", &rc)) == NULL) {
		cmn_err(CE_WARN, "couldn't resolve zvol_create_minor");
		return (rc);
	}
	if ((szn2m = (int(*)(char *, minor_t *))
	    ddi_modsym(zfs_mod, "zvol_name2minor", &rc)) == NULL) {
		cmn_err(CE_WARN, "couldn't resolve zvol_name2minor");
		return (rc);
	}
	if (ldi_get_dev(devzvol_lh, &dv))
		return (-1);
	devzvol_major = getmajor(dv);
	return (0);
}

void
devzvol_close_zfs()
{
	szcm = NULL;
	szn2m = NULL;
	(void) ldi_close(devzvol_lh, FREAD|FWRITE, kcred);
	ldi_ident_release(devzvol_li);
	if (zfs_mod != NULL) {
		(void) ddi_modclose(zfs_mod);
		zfs_mod = NULL;
	}
}

int
devzvol_handle_ioctl(int cmd, zfs_cmd_t *zc, size_t *alloc_size)
{
	uint64_t cookie;
	int size = 8000;
	int unused;
	int rc;

	if (cmd != ZFS_IOC_POOL_CONFIGS)
		mutex_enter(&devzvol_mtx);
	if (!devzvol_isopen) {
		if ((rc = devzvol_open_zfs()) == 0) {
			devzvol_isopen = B_TRUE;
		} else {
			if (cmd != ZFS_IOC_POOL_CONFIGS)
				mutex_exit(&devzvol_mtx);
			return (ENXIO);
		}
	}
	cookie = zc->zc_cookie;
again:
	zc->zc_nvlist_dst = (uint64_t)(intptr_t)kmem_alloc(size,
	    KM_SLEEP);
	zc->zc_nvlist_dst_size = size;
	rc = ldi_ioctl(devzvol_lh, cmd, (intptr_t)zc, FKIOCTL, kcred,
	    &unused);
	if (rc == ENOMEM) {
		int newsize;
		newsize = zc->zc_nvlist_dst_size;
		ASSERT(newsize > size);
		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, size);
		size = newsize;
		zc->zc_cookie = cookie;
		goto again;
	}
	if (alloc_size == NULL)
		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, size);
	else
		*alloc_size = size;
	if (cmd != ZFS_IOC_POOL_CONFIGS)
		mutex_exit(&devzvol_mtx);
	return (rc);
}

/* figures out if the objset exists and returns its type */
int
devzvol_objset_check(char *dsname, dmu_objset_type_t *type)
{
	boolean_t	ispool;
	zfs_cmd_t	*zc;
	int rc;

	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);
	(void) strlcpy(zc->zc_name, dsname, MAXPATHLEN);

	ispool = (strchr(dsname, '/') == NULL) ? B_TRUE : B_FALSE;
	if (!ispool && sdev_zvol_name2minor(dsname, NULL) == 0) {
		sdcmn_err13(("found cached minor node"));
		if (type)
			*type = DMU_OST_ZVOL;
		kmem_free(zc, sizeof (zfs_cmd_t));
		return (0);
	}
	rc = devzvol_handle_ioctl(ispool ? ZFS_IOC_POOL_STATS :
	    ZFS_IOC_OBJSET_STATS, zc, NULL);
	if (type && rc == 0)
		*type = (ispool) ? DMU_OST_ZFS :
		    zc->zc_objset_stats.dds_type;
	kmem_free(zc, sizeof (zfs_cmd_t));
	return (rc);
}

/*
 * returns what the zfs dataset name should be, given the /dev/zvol
 * path and an optional name; otherwise NULL
 */
char *
devzvol_make_dsname(const char *path, const char *name)
{
	char *dsname;
	const char *ptr;
	int dslen;

	if (strcmp(path, ZVOL_DIR) == 0)
		return (NULL);
	if (name && (strcmp(name, ".") == 0 || strcmp(name, "..") == 0))
		return (NULL);
	ptr = path + strlen(ZVOL_DIR);
	if (strncmp(ptr, "/dsk", 4) == 0)
		ptr += strlen("/dsk");
	else if (strncmp(ptr, "/rdsk", 5) == 0)
		ptr += strlen("/rdsk");
	else
		return (NULL);
	if (*ptr == '/')
		ptr++;

	dslen = strlen(ptr);
	if (dslen)
		dslen++;			/* plus null */
	if (name)
		dslen += strlen(name) + 1;	/* plus slash */
	dsname = kmem_zalloc(dslen, KM_SLEEP);
	if (*ptr) {
		(void) strlcpy(dsname, ptr, dslen);
		if (name)
			(void) strlcat(dsname, "/", dslen);
	}
	if (name)
		(void) strlcat(dsname, name, dslen);
	return (dsname);
}

/*
 * check if the zvol's sdev_node is still valid, which means make
 * sure the zvol is still valid.  zvol minors aren't proactively
 * destroyed when the zvol is destroyed, so we use a validator to clean
 * these up (in other words, when such nodes are encountered during
 * subsequent lookup() and readdir() operations) so that only valid
 * nodes are returned.  The ordering between devname_lookup_func and
 * devzvol_validate is a little inefficient in the case of invalid
 * or stale nodes because devname_lookup_func calls
 * devzvol_create_{dir, link}, then the validator says it's invalid,
 * and then the node gets cleaned up.
 */
int
devzvol_validate(struct sdev_node *dv)
{
	dmu_objset_type_t do_type;
	char *dsname;
	char *nm = dv->sdev_name;
	int rc;

	sdcmn_err13(("validating ('%s' '%s')", dv->sdev_path, nm));
	/*
	 * validate only READY nodes; if someone is sitting on the
	 * directory of a dataset that just got destroyed we could
	 * get a zombie node which we just skip.
	 */
	if (dv->sdev_state != SDEV_READY) {
		sdcmn_err13(("skipping '%s'", nm));
		return (SDEV_VTOR_SKIP);
	}

	if ((strcmp(dv->sdev_path, ZVOL_DIR "/dsk") == 0) ||
	    (strcmp(dv->sdev_path, ZVOL_DIR "/rdsk") == 0))
		return (SDEV_VTOR_VALID);
	dsname = devzvol_make_dsname(dv->sdev_path, NULL);
	if (dsname == NULL)
		return (SDEV_VTOR_INVALID);

	rc = devzvol_objset_check(dsname, &do_type);
	sdcmn_err13(("  '%s' rc %d", dsname, rc));
	if (rc != 0) {
		kmem_free(dsname, strlen(dsname) + 1);
		return (SDEV_VTOR_INVALID);
	}
	sdcmn_err13(("  v_type %d do_type %d",
	    SDEVTOV(dv)->v_type, do_type));
	if ((SDEVTOV(dv)->v_type == VLNK && do_type != DMU_OST_ZVOL) ||
	    ((SDEVTOV(dv)->v_type == VBLK || SDEVTOV(dv)->v_type == VCHR) &&
	    do_type != DMU_OST_ZVOL) ||
	    (SDEVTOV(dv)->v_type == VDIR && do_type == DMU_OST_ZVOL)) {
		kmem_free(dsname, strlen(dsname) + 1);
		return (SDEV_VTOR_STALE);
	}
	if (SDEVTOV(dv)->v_type == VLNK) {
		char *ptr, *link;
		long val = 0;
		minor_t lminor, ominor;

		rc = sdev_getlink(SDEVTOV(dv), &link);
		ASSERT(rc == 0);

		ptr = strrchr(link, ':') + 1;
		rc = ddi_strtol(ptr, NULL, 10, &val);
		kmem_free(link, strlen(link) + 1);
		ASSERT(rc == 0 && val != 0);
		lminor = (minor_t)val;
		if (sdev_zvol_name2minor(dsname, &ominor) < 0 ||
		    ominor != lminor) {
			kmem_free(dsname, strlen(dsname) + 1);
			return (SDEV_VTOR_STALE);
		}
	}
	kmem_free(dsname, strlen(dsname) + 1);
	return (SDEV_VTOR_VALID);
}

/*
 * creates directories as needed in response to a readdir
 */
void
devzvol_create_pool_dirs(struct vnode *dvp)
{
	zfs_cmd_t	*zc;
	nvlist_t *nv = NULL;
	nvpair_t *elem = NULL;
	size_t size;
	int pools = 0;
	int rc;

	sdcmn_err13(("devzvol_create_pool_dirs"));
	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);
	mutex_enter(&devzvol_mtx);
	zc->zc_cookie = devzvol_gen;

	rc = devzvol_handle_ioctl(ZFS_IOC_POOL_CONFIGS, zc, &size);
	switch (rc) {
		case 0:
			/* new generation */
			ASSERT(devzvol_gen != zc->zc_cookie);
			devzvol_gen = zc->zc_cookie;
			if (devzvol_zclist)
				kmem_free((void *)(uintptr_t)devzvol_zclist,
				    devzvol_zclist_size);
			devzvol_zclist = zc->zc_nvlist_dst;
			devzvol_zclist_size = size;
			break;
		case EEXIST:
			/*
			 * no change in the configuration; still need
			 * to do lookups in case we did a lookup in
			 * zvol/rdsk but not zvol/dsk (or vice versa)
			 */
			kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst,
			    size);
			break;
		default:
			kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst,
			    size);
			goto out;
	}
	rc = nvlist_unpack((char *)(uintptr_t)devzvol_zclist,
	    devzvol_zclist_size, &nv, 0);
	if (rc) {
		ASSERT(rc == 0);
		kmem_free((void *)(uintptr_t)devzvol_zclist,
		    devzvol_zclist_size);
		devzvol_gen = 0;
		devzvol_zclist = NULL;
		devzvol_zclist_size = 0;
		goto out;
	}
	mutex_exit(&devzvol_mtx);
	while ((elem = nvlist_next_nvpair(nv, elem)) != NULL) {
		struct vnode *vp;
		ASSERT(dvp->v_count > 0);
		rc = VOP_LOOKUP(dvp, nvpair_name(elem), &vp, NULL, 0,
		    NULL, kcred, NULL, 0, NULL);
		/* should either work, or not be visible from a zone */
		ASSERT(rc == 0 || rc == ENOENT);
		if (rc == 0)
			VN_RELE(vp);
		pools++;
	}
	nvlist_free(nv);
	mutex_enter(&devzvol_mtx);
	if (devzvol_isopen && pools == 0) {
		/* clean up so zfs can be unloaded */
		devzvol_close_zfs();
		devzvol_isopen = B_FALSE;
	}
out:
	mutex_exit(&devzvol_mtx);
	kmem_free(zc, sizeof (zfs_cmd_t));
}

/*ARGSUSED3*/
static int
devzvol_create_dir(struct sdev_node *ddv, char *nm, void **arg,
    cred_t *cred, void *whatever, char *whichever)
{
	timestruc_t now;
	struct vattr *vap = (struct vattr *)arg;

	sdcmn_err13(("create_dir (%s) (%s) '%s'", ddv->sdev_name,
	    ddv->sdev_path, nm));
	ASSERT(strncmp(ddv->sdev_path, ZVOL_DIR,
	    strlen(ZVOL_DIR)) == 0);
	*vap = *sdev_getdefault_attr(VDIR);
	gethrestime(&now);
	vap->va_atime = now;
	vap->va_mtime = now;
	vap->va_ctime = now;
	return (0);
}

/*ARGSUSED3*/
static int
devzvol_create_link(struct sdev_node *ddv, char *nm,
    void **arg, cred_t *cred, void *whatever, char *whichever)
{
	minor_t minor;
	char *pathname = (char *)*arg;
	int rc;
	char *dsname;
	char *x;
	char str[MAXNAMELEN];
	sdcmn_err13(("create_link (%s) (%s) '%s'", ddv->sdev_name,
	    ddv->sdev_path, nm));
	dsname = devzvol_make_dsname(ddv->sdev_path, nm);
	rc = sdev_zvol_create_minor(dsname);
	if ((rc != 0 && rc != EEXIST && rc != EBUSY) ||
	    sdev_zvol_name2minor(dsname, &minor)) {
		sdcmn_err13(("devzvol_create_link %d", rc));
		kmem_free(dsname, strlen(dsname) + 1);
		return (-1);
	}
	kmem_free(dsname, strlen(dsname) + 1);

	/*
	 * This is a valid zvol; create a symlink that points to the
	 * minor which was created under /devices/pseudo/zfs@0
	 */
	*pathname = '\0';
	for (x = ddv->sdev_path; x = strchr(x, '/'); x++)
		(void) strcat(pathname, "../");
	(void) snprintf(str, sizeof (str), ZVOL_PSEUDO_DEV "%u", minor);
	(void) strncat(pathname, str, MAXPATHLEN);
	if (strncmp(ddv->sdev_path, ZVOL_FULL_RDEV_DIR,
	    strlen(ZVOL_FULL_RDEV_DIR)) == 0)
		(void) strcat(pathname, ",raw");
	return (0);
}

/* Clean zvol sdev_nodes that are no longer valid.  */
static void
devzvol_prunedir(struct sdev_node *ddv)
{
	struct sdev_node *dv;

	ASSERT(RW_READ_HELD(&ddv->sdev_contents));

	sdcmn_err13(("prunedir '%s'", ddv->sdev_name));
	ASSERT(strncmp(ddv->sdev_path, ZVOL_DIR, strlen(ZVOL_DIR)) == 0);
	if (rw_tryupgrade(&ddv->sdev_contents) == 0) {
		rw_exit(&ddv->sdev_contents);
		rw_enter(&ddv->sdev_contents, RW_WRITER);
	}

	dv = SDEV_FIRST_ENTRY(ddv);
	while (dv) {
		sdcmn_err13(("sdev_name '%s'", dv->sdev_name));

		switch (devzvol_validate(dv)) {
		case SDEV_VTOR_VALID:
		case SDEV_VTOR_SKIP:
			dv = SDEV_NEXT_ENTRY(ddv, dv);
			continue;
		case SDEV_VTOR_INVALID:
			sdcmn_err7(("prunedir: destroy invalid "
			    "node: %s\n", dv->sdev_name));
			break;
		}

		if ((SDEVTOV(dv)->v_type == VDIR) &&
		    (sdev_cleandir(dv, NULL, 0) != 0)) {
			dv = SDEV_NEXT_ENTRY(ddv, dv);
			continue;
		}
		SDEV_HOLD(dv);
		/* remove the cache node */
		sdev_cache_update(ddv, &dv, dv->sdev_name,
		    SDEV_CACHE_DELETE);
		SDEV_RELE(dv);
		dv = SDEV_FIRST_ENTRY(ddv);
	}
	rw_downgrade(&ddv->sdev_contents);
}

/*
 * This function is used to create a dir or dev inside a zone's /dev when the
 * zone has a zvol that is dynamically created within the zone (i.e. inside
 * of a delegated dataset.  Since there is no /devices tree within a zone,
 * we create the chr/blk devices directly inside the zone's /dev instead of
 * making symlinks.
 */
static int
devzvol_mk_ngz_node(struct sdev_node *parent, char *nm)
{
	struct vattr vattr;
	timestruc_t now;
	enum vtype expected_type = VDIR;
	dmu_objset_type_t do_type;
	struct sdev_node *dv = NULL;
	int res;
	char *dsname;

	bzero(&vattr, sizeof (vattr));
	gethrestime(&now);
	vattr.va_mask = AT_TYPE|AT_MODE|AT_UID|AT_GID;
	vattr.va_uid = SDEV_UID_DEFAULT;
	vattr.va_gid = SDEV_GID_DEFAULT;
	vattr.va_type = VNON;
	vattr.va_atime = now;
	vattr.va_mtime = now;
	vattr.va_ctime = now;

	if ((dsname = devzvol_make_dsname(parent->sdev_path, nm)) == NULL)
		return (ENOENT);

	if (devzvol_objset_check(dsname, &do_type) != 0) {
		kmem_free(dsname, strlen(dsname) + 1);
		return (ENOENT);
	}
	if (do_type == DMU_OST_ZVOL)
		expected_type = VBLK;

	if (expected_type == VDIR) {
		vattr.va_type = VDIR;
		vattr.va_mode = SDEV_DIRMODE_DEFAULT;
	} else {
		minor_t minor;
		dev_t devnum;
		int rc;

		rc = sdev_zvol_create_minor(dsname);
		if ((rc != 0 && rc != EEXIST && rc != EBUSY) ||
		    sdev_zvol_name2minor(dsname, &minor)) {
			kmem_free(dsname, strlen(dsname) + 1);
			return (ENOENT);
		}

		devnum = makedevice(devzvol_major, minor);
		vattr.va_rdev = devnum;

		if (strstr(parent->sdev_path, "/rdsk/") != NULL)
			vattr.va_type = VCHR;
		else
			vattr.va_type = VBLK;
		vattr.va_mode = SDEV_DEVMODE_DEFAULT;
	}
	kmem_free(dsname, strlen(dsname) + 1);

	rw_enter(&parent->sdev_contents, RW_WRITER);

	res = sdev_mknode(parent, nm, &dv, &vattr,
	    NULL, NULL, kcred, SDEV_READY);
	rw_exit(&parent->sdev_contents);
	if (res != 0)
		return (ENOENT);

	SDEV_RELE(dv);
	return (0);
}

/*ARGSUSED*/
static int
devzvol_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	enum vtype expected_type = VDIR;
	struct sdev_node *parent = VTOSDEV(dvp);
	char *dsname;
	dmu_objset_type_t do_type;
	int error;

	sdcmn_err13(("devzvol_lookup '%s' '%s'", parent->sdev_path, nm));
	*vpp = NULL;
	/* execute access is required to search the directory */
	if ((error = VOP_ACCESS(dvp, VEXEC, 0, cred, ct)) != 0)
		return (error);

	rw_enter(&parent->sdev_contents, RW_READER);
	if (SDEV_IS_GLOBAL(parent)) {
		/*
		 * During iter_datasets, don't create GZ dev when running in
		 * NGZ.  We can't return ENOENT here since that could
		 * incorrectly trigger the creation of the dev from the
		 * recursive call through prof_filldir during iter_datasets.
		 */
		if (getzoneid() != GLOBAL_ZONEID) {
			rw_exit(&parent->sdev_contents);
			return (EPERM);
		}
	} else {
		int res;

		rw_exit(&parent->sdev_contents);

		/*
		 * If we're in the global zone and reach down into a non-global
		 * zone's /dev/zvol then this action could trigger the creation
		 * of all of the zvol devices for every zone into the non-global
		 * zone's /dev tree. This could be a big security hole. To
		 * prevent this, disallow the global zone from looking inside
		 * a non-global zones /dev/zvol. This behavior is similar to
		 * delegated datasets, which cannot be used by the global zone.
		 */
		if (getzoneid() == GLOBAL_ZONEID)
			return (EPERM);

		res = prof_lookup(dvp, nm, vpp, cred);

		/*
		 * We won't find a zvol that was dynamically created inside
		 * a NGZ, within a delegated dataset, in the zone's dev profile
		 * but prof_lookup will also find it via sdev_cache_lookup.
		 */
		if (res == ENOENT) {
			/*
			 * We have to create the sdev node for the dymamically
			 * created zvol.
			 */
			if (devzvol_mk_ngz_node(parent, nm) != 0)
				return (ENOENT);
			res = prof_lookup(dvp, nm, vpp, cred);
		}

		return (res);
	}

	dsname = devzvol_make_dsname(parent->sdev_path, nm);
	rw_exit(&parent->sdev_contents);
	sdcmn_err13(("rvp dsname %s", dsname ? dsname : "(null)"));
	if (dsname) {
		error = devzvol_objset_check(dsname, &do_type);
		if (error != 0) {
			error = ENOENT;
			goto out;
		}
		if (do_type == DMU_OST_ZVOL)
			expected_type = VLNK;
	}
	/*
	 * the callbacks expect:
	 *
	 * parent->sdev_path		   nm
	 * /dev/zvol			   {r}dsk
	 * /dev/zvol/{r}dsk		   <pool name>
	 * /dev/zvol/{r}dsk/<dataset name> <last ds component>
	 *
	 * sdev_name is always last path component of sdev_path
	 */
	if (expected_type == VDIR) {
		error = devname_lookup_func(parent, nm, vpp, cred,
		    devzvol_create_dir, SDEV_VATTR);
	} else {
		error = devname_lookup_func(parent, nm, vpp, cred,
		    devzvol_create_link, SDEV_VLINK);
	}
	sdcmn_err13(("devzvol_lookup %d %d", expected_type, error));
	ASSERT(error || ((*vpp)->v_type == expected_type));
out:
	if (dsname)
		kmem_free(dsname, strlen(dsname) + 1);
	sdcmn_err13(("devzvol_lookup %d", error));
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
devzvol_create(struct vnode *dvp, char *nm, struct vattr *vap, vcexcl_t excl,
    int mode, struct vnode **vpp, struct cred *cred, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	int error;
	struct vnode *vp;

	*vpp = NULL;

	error = devzvol_lookup(dvp, nm, &vp, NULL, 0, NULL, cred, ct, NULL,
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

void sdev_iter_snapshots(struct vnode *dvp, char *name);

void
sdev_iter_datasets(struct vnode *dvp, int arg, char *name)
{
	zfs_cmd_t	*zc;
	int rc;

	sdcmn_err13(("iter name is '%s' (arg %x)", name, arg));
	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);
	(void) strcpy(zc->zc_name, name);

	while ((rc = devzvol_handle_ioctl(arg, zc, B_FALSE)) == 0) {
		struct vnode *vpp;
		char *ptr;

		sdcmn_err13(("  name %s", zc->zc_name));
		if (strchr(zc->zc_name, '$') || strchr(zc->zc_name, '%'))
			goto skip;
		ptr = strrchr(zc->zc_name, '/') + 1;
		rc = devzvol_lookup(dvp, ptr, &vpp, NULL, 0, NULL,
		    kcred, NULL, NULL, NULL);
		if (rc == 0) {
			VN_RELE(vpp);
		} else if (rc == ENOENT) {
			goto skip;
		} else {
			/*
			 * EBUSY == problem with zvols's dmu holds?
			 * EPERM when in a NGZ and traversing up and out.
			 */
			goto skip;
		}
		if (arg == ZFS_IOC_DATASET_LIST_NEXT &&
		    zc->zc_objset_stats.dds_type != DMU_OST_ZFS)
			sdev_iter_snapshots(dvp, zc->zc_name);
skip:
		(void) strcpy(zc->zc_name, name);
	}
	kmem_free(zc, sizeof (zfs_cmd_t));
}

void
sdev_iter_snapshots(struct vnode *dvp, char *name)
{
	sdev_iter_datasets(dvp, ZFS_IOC_SNAPSHOT_LIST_NEXT, name);
}

/*ARGSUSED4*/
static int
devzvol_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred,
    int *eofp, caller_context_t *ct_unused, int flags_unused)
{
	struct sdev_node *sdvp = VTOSDEV(dvp);
	char *ptr;

	sdcmn_err13(("zv readdir of '%s' %s'", sdvp->sdev_path,
	    sdvp->sdev_name));

	if (strcmp(sdvp->sdev_path, ZVOL_DIR) == 0) {
		struct vnode *vp;

		rw_exit(&sdvp->sdev_contents);
		(void) devname_lookup_func(sdvp, "dsk", &vp, cred,
		    devzvol_create_dir, SDEV_VATTR);
		VN_RELE(vp);
		(void) devname_lookup_func(sdvp, "rdsk", &vp, cred,
		    devzvol_create_dir, SDEV_VATTR);
		VN_RELE(vp);
		rw_enter(&sdvp->sdev_contents, RW_READER);
		return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
	}
	if (uiop->uio_offset == 0)
		devzvol_prunedir(sdvp);
	ptr = sdvp->sdev_path + strlen(ZVOL_DIR);
	if ((strcmp(ptr, "/dsk") == 0) || (strcmp(ptr, "/rdsk") == 0)) {
		rw_exit(&sdvp->sdev_contents);
		devzvol_create_pool_dirs(dvp);
		rw_enter(&sdvp->sdev_contents, RW_READER);
		return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
	}

	ptr = strchr(ptr + 1, '/') + 1;
	rw_exit(&sdvp->sdev_contents);
	sdev_iter_datasets(dvp, ZFS_IOC_DATASET_LIST_NEXT, ptr);
	rw_enter(&sdvp->sdev_contents, RW_READER);
	return (devname_readdir_func(dvp, uiop, cred, eofp, 0));
}

const fs_operation_def_t devzvol_vnodeops_tbl[] = {
	VOPNAME_READDIR,	{ .vop_readdir = devzvol_readdir },
	VOPNAME_LOOKUP,		{ .vop_lookup = devzvol_lookup },
	VOPNAME_CREATE,		{ .vop_create = devzvol_create },
	VOPNAME_RENAME,		{ .error = fs_nosys },
	VOPNAME_MKDIR,		{ .error = fs_nosys },
	VOPNAME_RMDIR,		{ .error = fs_nosys },
	VOPNAME_REMOVE,		{ .error = fs_nosys },
	VOPNAME_SYMLINK,	{ .error = fs_nosys },
	NULL,			NULL
};
