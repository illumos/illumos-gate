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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/vdev.h>
#include <sys/dmu.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/nvpair.h>
#include <sys/pathname.h>
#include <sys/mount.h>
#include <sys/sdt.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ctldir.h>

#include "zfs_namecheck.h"

extern struct modlfs zfs_modlfs;

extern void zfs_init(void);
extern void zfs_fini(void);

ldi_ident_t zfs_li = NULL;
dev_info_t *zfs_dip;

typedef int zfs_ioc_func_t(zfs_cmd_t *);
typedef int zfs_secpolicy_func_t(const char *, const char *, cred_t *);

typedef struct zfs_ioc_vec {
	zfs_ioc_func_t		*zvec_func;
	zfs_secpolicy_func_t	*zvec_secpolicy;
	enum {
		no_name,
		pool_name,
		dataset_name
	}			zvec_namecheck;
} zfs_ioc_vec_t;

/* _NOTE(PRINTFLIKE(4)) - this is printf-like, but lint is too whiney */
void
__dprintf(const char *file, const char *func, int line, const char *fmt, ...)
{
	const char *newfile;
	char buf[256];
	va_list adx;

	/*
	 * Get rid of annoying "../common/" prefix to filename.
	 */
	newfile = strrchr(file, '/');
	if (newfile != NULL) {
		newfile = newfile + 1; /* Get rid of leading / */
	} else {
		newfile = file;
	}

	va_start(adx, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, adx);
	va_end(adx);

	/*
	 * To get this data, use the zfs-dprintf probe as so:
	 * dtrace -q -n 'zfs-dprintf \
	 *	/stringof(arg0) == "dbuf.c"/ \
	 *	{printf("%s: %s", stringof(arg1), stringof(arg3))}'
	 * arg0 = file name
	 * arg1 = function name
	 * arg2 = line number
	 * arg3 = message
	 */
	DTRACE_PROBE4(zfs__dprintf,
	    char *, newfile, char *, func, int, line, char *, buf);
}

/*
 * Policy for top-level read operations (list pools).  Requires no privileges,
 * and can be used in the local zone, as there is no associated dataset.
 */
/* ARGSUSED */
static int
zfs_secpolicy_none(const char *unused1, const char *unused2, cred_t *cr)
{
	return (0);
}

/*
 * Policy for dataset read operations (list children, get statistics).  Requires
 * no privileges, but must be visible in the local zone.
 */
/* ARGSUSED */
static int
zfs_secpolicy_read(const char *dataset, const char *unused, cred_t *cr)
{
	if (INGLOBALZONE(curproc) ||
	    zone_dataset_visible(dataset, NULL))
		return (0);

	return (ENOENT);
}

static int
zfs_dozonecheck(const char *dataset, cred_t *cr)
{
	uint64_t zoned;
	int writable = 1;

	/*
	 * The dataset must be visible by this zone -- check this first
	 * so they don't see EPERM on something they shouldn't know about.
	 */
	if (!INGLOBALZONE(curproc) &&
	    !zone_dataset_visible(dataset, &writable))
		return (ENOENT);

	if (dsl_prop_get_integer(dataset, "zoned", &zoned, NULL))
		return (ENOENT);

	if (INGLOBALZONE(curproc)) {
		/*
		 * If the fs is zoned, only root can access it from the
		 * global zone.
		 */
		if (secpolicy_zfs(cr) && zoned)
			return (EPERM);
	} else {
		/*
		 * If we are in a local zone, the 'zoned' property must be set.
		 */
		if (!zoned)
			return (EPERM);

		/* must be writable by this zone */
		if (!writable)
			return (EPERM);
	}
	return (0);
}

/*
 * Policy for dataset write operations (create children, set properties, etc).
 * Requires SYS_MOUNT privilege, and must be writable in the local zone.
 */
/* ARGSUSED */
int
zfs_secpolicy_write(const char *dataset, const char *unused, cred_t *cr)
{
	int error;

	if (error = zfs_dozonecheck(dataset, cr))
		return (error);

	return (secpolicy_zfs(cr));
}

/*
 * Policy for operations that want to write a dataset's parent:
 * create, destroy, snapshot, clone, restore.
 */
static int
zfs_secpolicy_parent(const char *dataset, const char *unused, cred_t *cr)
{
	char parentname[MAXNAMELEN];
	char *cp;

	/*
	 * Remove the @bla or /bla from the end of the name to get the parent.
	 */
	(void) strncpy(parentname, dataset, sizeof (parentname));
	cp = strrchr(parentname, '@');
	if (cp != NULL) {
		cp[0] = '\0';
	} else {
		cp = strrchr(parentname, '/');
		if (cp == NULL)
			return (ENOENT);
		cp[0] = '\0';

	}

	return (zfs_secpolicy_write(parentname, unused, cr));
}

/*
 * Policy for dataset write operations (create children, set properties, etc).
 * Requires SYS_MOUNT privilege, and must be writable in the local zone.
 */
static int
zfs_secpolicy_setprop(const char *dataset, const char *prop, cred_t *cr)
{
	int error;

	if (error = zfs_dozonecheck(dataset, cr))
		return (error);

	if (strcmp(prop, "zoned") == 0) {
		/*
		 * Disallow setting of 'zoned' from within a local zone.
		 */
		if (!INGLOBALZONE(curproc))
			return (EPERM);
	}

	return (secpolicy_zfs(cr));
}

/*
 * Security policy for setting the quota.  This is the same as
 * zfs_secpolicy_write, except that the local zone may not change the quota at
 * the zone-property setpoint.
 */
/* ARGSUSED */
static int
zfs_secpolicy_quota(const char *dataset, const char *unused, cred_t *cr)
{
	int error;

	if (error = zfs_dozonecheck(dataset, cr))
		return (error);

	if (!INGLOBALZONE(curproc)) {
		uint64_t zoned;
		char setpoint[MAXNAMELEN];
		int dslen;
		/*
		 * Unprivileged users are allowed to modify the quota
		 * on things *under* (ie. contained by) the thing they
		 * own.
		 */
		if (dsl_prop_get_integer(dataset, "zoned", &zoned, setpoint))
			return (EPERM);
		if (!zoned) /* this shouldn't happen */
			return (EPERM);
		dslen = strlen(dataset);
		if (dslen <= strlen(setpoint))
			return (EPERM);
	}

	return (secpolicy_zfs(cr));
}

/*
 * Policy for pool operations - create/destroy pools, add vdevs, etc.  Requires
 * SYS_CONFIG privilege, which is not available in a local zone.
 */
/* ARGSUSED */
static int
zfs_secpolicy_config(const char *unused, const char *unused2, cred_t *cr)
{
	if (secpolicy_sys_config(cr, B_FALSE) != 0)
		return (EPERM);

	return (0);
}

/*
 * Returns the nvlist as specified by the user in the zfs_cmd_t.
 */
static int
get_config(zfs_cmd_t *zc, nvlist_t **nvp)
{
	char *packed;
	size_t size;
	int error;
	nvlist_t *config = NULL;

	/*
	 * Read in and unpack the user-supplied nvlist.  By this point, we know
	 * that the user has the SYS_CONFIG privilege, so allocating arbitrary
	 * sized regions of memory should not be a problem.
	 */
	if ((size = zc->zc_config_src_size) == 0)
		return (EINVAL);

	packed = kmem_alloc(size, KM_SLEEP);

	if ((error = xcopyin((void *)(uintptr_t)zc->zc_config_src, packed,
	    size)) != 0) {
		kmem_free(packed, size);
		return (error);
	}

	if ((error = nvlist_unpack(packed, size, &config, 0)) != 0) {
		kmem_free(packed, size);
		return (error);
	}

	kmem_free(packed, size);

	*nvp = config;
	return (0);
}

static int
zfs_ioc_pool_create(zfs_cmd_t *zc)
{
	int error;
	nvlist_t *config;

	if ((error = get_config(zc, &config)) != 0)
		return (error);

	error = spa_create(zc->zc_name, config, zc->zc_root[0] == '\0' ?
	    NULL : zc->zc_root);

	nvlist_free(config);

	return (error);
}

static int
zfs_ioc_pool_destroy(zfs_cmd_t *zc)
{
	return (spa_destroy(zc->zc_name));
}

static int
zfs_ioc_pool_import(zfs_cmd_t *zc)
{
	int error;
	nvlist_t *config;
	uint64_t guid;

	if ((error = get_config(zc, &config)) != 0)
		return (error);

	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) != 0 ||
	    guid != zc->zc_pool_guid)
		error = EINVAL;
	else
		error = spa_import(zc->zc_name, config,
		    zc->zc_root[0] == '\0' ? NULL : zc->zc_root);

	nvlist_free(config);

	return (error);
}

static int
zfs_ioc_pool_export(zfs_cmd_t *zc)
{
	return (spa_export(zc->zc_name));
}

static int
zfs_ioc_pool_configs(zfs_cmd_t *zc)
{
	nvlist_t *configs;
	char *packed = NULL;
	size_t size = 0;
	int error;

	if ((configs = spa_all_configs(&zc->zc_cookie)) == NULL)
		return (EEXIST);

	VERIFY(nvlist_pack(configs, &packed, &size, NV_ENCODE_NATIVE, 0) == 0);

	if (size > zc->zc_config_dst_size)
		error = ENOMEM;
	else
		error = xcopyout(packed, (void *)(uintptr_t)zc->zc_config_dst,
		    size);

	zc->zc_config_dst_size = size;

	kmem_free(packed, size);
	nvlist_free(configs);

	return (error);
}

static int
zfs_ioc_pool_guid(zfs_cmd_t *zc)
{
	spa_t *spa;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error == 0) {
		zc->zc_pool_guid = spa_guid(spa);
		spa_close(spa, FTAG);
	}
	return (error);
}

static int
zfs_ioc_pool_stats(zfs_cmd_t *zc)
{
	nvlist_t *config;
	char *packed = NULL;
	size_t size = 0;
	int error;

	error = spa_get_stats(zc->zc_name, &config);

	if (config != NULL) {
		VERIFY(nvlist_pack(config, &packed, &size,
		    NV_ENCODE_NATIVE, 0) == 0);

		if (size > zc->zc_config_dst_size)
			error = ENOMEM;
		else if (xcopyout(packed, (void *)(uintptr_t)zc->zc_config_dst,
		    size))
			error = EFAULT;

		zc->zc_config_dst_size = size;

		kmem_free(packed, size);
		nvlist_free(config);
	} else {
		ASSERT(error != 0);
	}

	return (error);
}

/*
 * Try to import the given pool, returning pool stats as appropriate so that
 * user land knows which devices are available and overall pool health.
 */
static int
zfs_ioc_pool_tryimport(zfs_cmd_t *zc)
{
	nvlist_t *tryconfig, *config;
	char *packed = NULL;
	size_t size = 0;
	int error;

	if ((error = get_config(zc, &tryconfig)) != 0)
		return (error);

	config = spa_tryimport(tryconfig);

	nvlist_free(tryconfig);

	if (config == NULL)
		return (EINVAL);

	VERIFY(nvlist_pack(config, &packed, &size, NV_ENCODE_NATIVE, 0) == 0);

	if (size > zc->zc_config_dst_size)
		error = ENOMEM;
	else
		error = xcopyout(packed, (void *)(uintptr_t)zc->zc_config_dst,
		    size);

	zc->zc_config_dst_size = size;

	kmem_free(packed, size);
	nvlist_free(config);

	return (error);
}

static int
zfs_ioc_pool_scrub(zfs_cmd_t *zc)
{
	spa_t *spa;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error == 0) {
		error = spa_scrub(spa, zc->zc_cookie, B_FALSE);
		spa_close(spa, FTAG);
	}
	return (error);
}

static int
zfs_ioc_pool_freeze(zfs_cmd_t *zc)
{
	spa_t *spa;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error == 0) {
		spa_freeze(spa);
		spa_close(spa, FTAG);
	}
	return (error);
}

static int
zfs_ioc_vdev_add(zfs_cmd_t *zc)
{
	spa_t *spa;
	int error;
	nvlist_t *config;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);

	if ((error = get_config(zc, &config)) == 0) {
		error = spa_vdev_add(spa, config);
		nvlist_free(config);
	}

	spa_close(spa, FTAG);
	return (error);
}

/* ARGSUSED */
static int
zfs_ioc_vdev_remove(zfs_cmd_t *zc)
{
	return (ENOTSUP);
}

static int
zfs_ioc_vdev_online(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *path = zc->zc_prop_value;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);
	error = vdev_online(spa, path);
	spa_close(spa, FTAG);
	return (error);
}

static int
zfs_ioc_vdev_offline(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *path = zc->zc_prop_value;
	int istmp = zc->zc_cookie;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);
	error = vdev_offline(spa, path, istmp);
	spa_close(spa, FTAG);
	return (error);
}

static int
zfs_ioc_vdev_attach(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *path = zc->zc_prop_value;
	int replacing = zc->zc_cookie;
	nvlist_t *config;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);

	if ((error = get_config(zc, &config)) == 0) {
		error = spa_vdev_attach(spa, path, config, replacing);
		nvlist_free(config);
	}

	spa_close(spa, FTAG);
	return (error);
}

static int
zfs_ioc_vdev_detach(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *path = zc->zc_prop_value;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);

	error = spa_vdev_detach(spa, path, 0, B_FALSE);

	spa_close(spa, FTAG);
	return (error);
}

static int
zfs_ioc_vdev_setpath(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *path = zc->zc_prop_value;
	uint64_t guid = zc->zc_pool_guid;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);

	error = spa_vdev_setpath(spa, guid, path);

	spa_close(spa, FTAG);
	return (error);
}


static int
zfs_ioc_objset_stats(zfs_cmd_t *zc)
{
	objset_t *os = NULL;
	int error;
	nvlist_t *nv;
	size_t sz;
	char *buf;

retry:
	error = dmu_objset_open(zc->zc_name, DMU_OST_ANY,
	    DS_MODE_STANDARD | DS_MODE_READONLY, &os);
	if (error != 0) {
		/*
		 * This is ugly: dmu_objset_open() can return EBUSY if
		 * the objset is held exclusively. Fortunately this hold is
		 * only for a short while, so we retry here.
		 * This avoids user code having to handle EBUSY,
		 * for example for a "zfs list".
		 */
		if (error == EBUSY) {
			delay(1);
			goto retry;
		}
		return (error);
	}

	dmu_objset_stats(os, &zc->zc_objset_stats);

	if (zc->zc_config_src != NULL &&
	    (error = dsl_prop_get_all(os, &nv)) == 0) {
		VERIFY(nvlist_size(nv, &sz, NV_ENCODE_NATIVE) == 0);
		if (sz > zc->zc_config_src_size) {
			zc->zc_config_src_size = sz;
			error = ENOMEM;
		} else {
			buf = kmem_alloc(sz, KM_SLEEP);
			VERIFY(nvlist_pack(nv, &buf, &sz,
			    NV_ENCODE_NATIVE, 0) == 0);
			error = xcopyout(buf,
			    (void *)(uintptr_t)zc->zc_config_src, sz);
			kmem_free(buf, sz);
		}
		nvlist_free(nv);
	}

	if (!error && zc->zc_objset_stats.dds_type == DMU_OST_ZVOL)
		error = zvol_get_stats(zc, os);

	dmu_objset_close(os);
	return (error);
}

static int
zfs_ioc_dataset_list_next(zfs_cmd_t *zc)
{
	objset_t *os;
	int error;
	char *p;

retry:
	error = dmu_objset_open(zc->zc_name, DMU_OST_ANY,
	    DS_MODE_STANDARD | DS_MODE_READONLY, &os);
	if (error != 0) {
		/*
		 * This is ugly: dmu_objset_open() can return EBUSY if
		 * the objset is held exclusively. Fortunately this hold is
		 * only for a short while, so we retry here.
		 * This avoids user code having to handle EBUSY,
		 * for example for a "zfs list".
		 */
		if (error == EBUSY) {
			delay(1);
			goto retry;
		}
		if (error == ENOENT)
			error = ESRCH;
		return (error);
	}

	p = strrchr(zc->zc_name, '/');
	if (p == NULL || p[1] != '\0')
		(void) strlcat(zc->zc_name, "/", sizeof (zc->zc_name));
	p = zc->zc_name + strlen(zc->zc_name);

	do {
		error = dmu_dir_list_next(os,
		    sizeof (zc->zc_name) - (p - zc->zc_name), p,
		    NULL, &zc->zc_cookie);
		if (error == ENOENT)
			error = ESRCH;
	} while (error == 0 && !INGLOBALZONE(curproc) &&
	    !zone_dataset_visible(zc->zc_name, NULL));

	/*
	 * If it's a hidden dataset (ie. with a '$' in its name), don't
	 * try to get stats for it.  Userland will skip over it.
	 */
	if (error == 0 && strchr(zc->zc_name, '$') == NULL)
		error = zfs_ioc_objset_stats(zc); /* fill in the stats */

	dmu_objset_close(os);
	return (error);
}

static int
zfs_ioc_snapshot_list_next(zfs_cmd_t *zc)
{
	objset_t *os;
	int error;

retry:
	error = dmu_objset_open(zc->zc_name, DMU_OST_ANY,
	    DS_MODE_STANDARD | DS_MODE_READONLY, &os);
	if (error != 0) {
		/*
		 * This is ugly: dmu_objset_open() can return EBUSY if
		 * the objset is held exclusively. Fortunately this hold is
		 * only for a short while, so we retry here.
		 * This avoids user code having to handle EBUSY,
		 * for example for a "zfs list".
		 */
		if (error == EBUSY) {
			delay(1);
			goto retry;
		}
		if (error == ENOENT)
			error = ESRCH;
		return (error);
	}

	/*
	 * A dataset name of maximum length cannot have any snapshots,
	 * so exit immediately.
	 */
	if (strlcat(zc->zc_name, "@", sizeof (zc->zc_name)) >= MAXNAMELEN) {
		dmu_objset_close(os);
		return (ESRCH);
	}

	error = dmu_snapshot_list_next(os,
	    sizeof (zc->zc_name) - strlen(zc->zc_name),
	    zc->zc_name + strlen(zc->zc_name), NULL, &zc->zc_cookie);
	if (error == ENOENT)
		error = ESRCH;

	if (error == 0)
		error = zfs_ioc_objset_stats(zc); /* fill in the stats */

	dmu_objset_close(os);
	return (error);
}

static int
zfs_ioc_set_prop(zfs_cmd_t *zc)
{
	return (dsl_prop_set(zc->zc_name, zc->zc_prop_name,
	    zc->zc_intsz, zc->zc_numints, zc->zc_prop_value));
}

static int
zfs_ioc_set_quota(zfs_cmd_t *zc)
{
	return (dsl_dir_set_quota(zc->zc_name, zc->zc_cookie));
}

static int
zfs_ioc_set_reservation(zfs_cmd_t *zc)
{
	return (dsl_dir_set_reservation(zc->zc_name, zc->zc_cookie));
}

static int
zfs_ioc_set_volsize(zfs_cmd_t *zc)
{
	return (zvol_set_volsize(zc));
}

static int
zfs_ioc_set_volblocksize(zfs_cmd_t *zc)
{
	return (zvol_set_volblocksize(zc));
}

static int
zfs_ioc_create_minor(zfs_cmd_t *zc)
{
	return (zvol_create_minor(zc));
}

static int
zfs_ioc_remove_minor(zfs_cmd_t *zc)
{
	return (zvol_remove_minor(zc));
}

/*
 * Search the vfs list for a specified resource.  Returns a pointer to it
 * or NULL if no suitable entry is found. The caller of this routine
 * is responsible for releasing the returned vfs pointer.
 */
static vfs_t *
zfs_get_vfs(const char *resource)
{
	struct vfs *vfsp;
	struct vfs *vfs_found = NULL;

	vfs_list_read_lock();
	vfsp = rootvfs;
	do {
		if (strcmp(refstr_value(vfsp->vfs_resource), resource) == 0) {
			VFS_HOLD(vfsp);
			vfs_found = vfsp;
			break;
		}
		vfsp = vfsp->vfs_next;
	} while (vfsp != rootvfs);
	vfs_list_unlock();
	return (vfs_found);
}

static void
zfs_create_cb(objset_t *os, void *arg, dmu_tx_t *tx)
{
	zfs_cmd_t *zc = arg;
	zfs_create_fs(os, (cred_t *)(uintptr_t)zc->zc_cred, tx);
}

static int
zfs_ioc_create(zfs_cmd_t *zc)
{
	objset_t *clone;
	int error = 0;
	void (*cbfunc)(objset_t *os, void *arg, dmu_tx_t *tx);
	dmu_objset_type_t type = zc->zc_objset_type;

	switch (type) {

	case DMU_OST_ZFS:
		cbfunc = zfs_create_cb;
		break;

	case DMU_OST_ZVOL:
		cbfunc = zvol_create_cb;
		break;

	default:
		return (EINVAL);
	}

	if (zc->zc_filename[0] != '\0') {
		/*
		 * We're creating a clone of an existing snapshot.
		 */
		zc->zc_filename[sizeof (zc->zc_filename) - 1] = '\0';
		if (dataset_namecheck(zc->zc_filename, NULL, NULL) != 0)
			return (EINVAL);

		error = dmu_objset_open(zc->zc_filename, type,
		    DS_MODE_STANDARD | DS_MODE_READONLY, &clone);
		if (error)
			return (error);
		error = dmu_objset_create(zc->zc_name, type, clone, NULL, NULL);
		dmu_objset_close(clone);
	} else if (strchr(zc->zc_name, '@') != 0) {
		/*
		 * We're taking a snapshot of an existing dataset.
		 */
		error = dmu_objset_create(zc->zc_name, type, NULL, NULL, NULL);
	} else {
		/*
		 * We're creating a new dataset.
		 */
		if (type == DMU_OST_ZVOL) {

			if ((error = zvol_check_volblocksize(zc)) != 0)
				return (error);

			if ((error = zvol_check_volsize(zc,
			    zc->zc_volblocksize)) != 0)
				return (error);
		}
		error = dmu_objset_create(zc->zc_name, type, NULL, cbfunc, zc);
	}
	return (error);
}

static int
zfs_ioc_destroy(zfs_cmd_t *zc)
{
	if (strchr(zc->zc_name, '@') != NULL &&
	    zc->zc_objset_type == DMU_OST_ZFS) {
		vfs_t *vfsp;
		int err;

		/*
		 * Snapshots under .zfs control must be unmounted
		 * before they can be destroyed.
		 */
		if ((vfsp = zfs_get_vfs(zc->zc_name)) != NULL) {
			/*
			 * Always force the unmount for snapshots.
			 */
			int flag = MS_FORCE;

			if ((err = vn_vfswlock(vfsp->vfs_vnodecovered)) != 0) {
				VFS_RELE(vfsp);
				return (err);
			}
			VFS_RELE(vfsp);
			if ((err = dounmount(vfsp, flag, kcred)) != 0)
				return (err);
		}
	}

	return (dmu_objset_destroy(zc->zc_name));
}

static int
zfs_ioc_rollback(zfs_cmd_t *zc)
{
	return (dmu_objset_rollback(zc->zc_name));
}

static int
zfs_ioc_rename(zfs_cmd_t *zc)
{
	zc->zc_prop_value[sizeof (zc->zc_prop_value) - 1] = '\0';
	if (dataset_namecheck(zc->zc_prop_value, NULL, NULL) != 0)
		return (EINVAL);

	if (strchr(zc->zc_name, '@') != NULL &&
	    zc->zc_objset_type == DMU_OST_ZFS) {
		vfs_t *vfsp;
		int err;

		/*
		 * Snapshots under .zfs control must be unmounted
		 * before they can be renamed.
		 */
		if ((vfsp = zfs_get_vfs(zc->zc_name)) != NULL) {
			/*
			 * Always force the unmount for snapshots.
			 */
			int flag = MS_FORCE;

			if ((err = vn_vfswlock(vfsp->vfs_vnodecovered)) != 0) {
				VFS_RELE(vfsp);
				return (err);
			}
			VFS_RELE(vfsp);
			if ((err = dounmount(vfsp, flag, kcred)) != 0)
				return (err);
		}
	}

	return (dmu_objset_rename(zc->zc_name, zc->zc_prop_value));
}

static int
zfs_ioc_recvbackup(zfs_cmd_t *zc)
{
	file_t *fp;
	int error, fd;

	fd = zc->zc_cookie;
	fp = getf(fd);
	if (fp == NULL)
		return (EBADF);
	error = dmu_recvbackup(&zc->zc_begin_record, &zc->zc_cookie,
	    fp->f_vnode, fp->f_offset);
	releasef(fd);
	return (error);
}

static int
zfs_ioc_sendbackup(zfs_cmd_t *zc)
{
	objset_t *fromsnap = NULL;
	objset_t *tosnap;
	file_t *fp;
	int error;

	error = dmu_objset_open(zc->zc_name, DMU_OST_ANY,
	    DS_MODE_STANDARD | DS_MODE_READONLY, &tosnap);
	if (error)
		return (error);

	if (zc->zc_prop_value[0] != '\0') {
		error = dmu_objset_open(zc->zc_prop_value, DMU_OST_ANY,
		    DS_MODE_STANDARD | DS_MODE_READONLY, &fromsnap);
		if (error) {
			dmu_objset_close(tosnap);
			return (error);
		}
	}

	fp = getf(zc->zc_cookie);
	if (fp == NULL) {
		dmu_objset_close(tosnap);
		if (fromsnap)
			dmu_objset_close(fromsnap);
		return (EBADF);
	}

	error = dmu_sendbackup(tosnap, fromsnap, fp->f_vnode);

	releasef(zc->zc_cookie);
	if (fromsnap)
		dmu_objset_close(fromsnap);
	dmu_objset_close(tosnap);
	return (error);
}

static zfs_ioc_vec_t zfs_ioc_vec[] = {
	{ zfs_ioc_pool_create,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_pool_destroy,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_pool_import,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_pool_export,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_pool_configs,		zfs_secpolicy_none,	no_name },
	{ zfs_ioc_pool_guid,		zfs_secpolicy_read,	pool_name },
	{ zfs_ioc_pool_stats,		zfs_secpolicy_read,	pool_name },
	{ zfs_ioc_pool_tryimport,	zfs_secpolicy_config,	no_name },
	{ zfs_ioc_pool_scrub,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_pool_freeze,		zfs_secpolicy_config,	no_name },
	{ zfs_ioc_vdev_add,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_vdev_remove,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_vdev_online,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_vdev_offline,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_vdev_attach,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_vdev_detach,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_vdev_setpath,		zfs_secpolicy_config,	pool_name },
	{ zfs_ioc_objset_stats,		zfs_secpolicy_read,	dataset_name },
	{ zfs_ioc_dataset_list_next,	zfs_secpolicy_read,	dataset_name },
	{ zfs_ioc_snapshot_list_next,	zfs_secpolicy_read,	dataset_name },
	{ zfs_ioc_set_prop,		zfs_secpolicy_setprop,	dataset_name },
	{ zfs_ioc_set_quota,		zfs_secpolicy_quota,	dataset_name },
	{ zfs_ioc_set_reservation,	zfs_secpolicy_write,	dataset_name },
	{ zfs_ioc_set_volsize,		zfs_secpolicy_config,	dataset_name },
	{ zfs_ioc_set_volblocksize,	zfs_secpolicy_config,	dataset_name },
	{ zfs_ioc_create_minor,		zfs_secpolicy_config,	dataset_name },
	{ zfs_ioc_remove_minor,		zfs_secpolicy_config,	dataset_name },
	{ zfs_ioc_create,		zfs_secpolicy_parent,	dataset_name },
	{ zfs_ioc_destroy,		zfs_secpolicy_parent,	dataset_name },
	{ zfs_ioc_rollback,		zfs_secpolicy_write,	dataset_name },
	{ zfs_ioc_rename,		zfs_secpolicy_write,	dataset_name },
	{ zfs_ioc_recvbackup,		zfs_secpolicy_write,	dataset_name },
	{ zfs_ioc_sendbackup,		zfs_secpolicy_write,	dataset_name },
};

static int
zfsdev_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cr, int *rvalp)
{
	zfs_cmd_t *zc;
	uint_t vec;
	int error;

	if (getminor(dev) != 0)
		return (zvol_ioctl(dev, cmd, arg, flag, cr, rvalp));

	vec = cmd - ZFS_IOC;

	if (vec >= sizeof (zfs_ioc_vec) / sizeof (zfs_ioc_vec[0]))
		return (EINVAL);

	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);

	error = xcopyin((void *)arg, zc, sizeof (zfs_cmd_t));

	if (error == 0) {
		zc->zc_cred = (uintptr_t)cr;
		zc->zc_dev = dev;
		error = zfs_ioc_vec[vec].zvec_secpolicy(zc->zc_name,
		    zc->zc_prop_name, cr);
	}

	/*
	 * Ensure that all pool/dataset names are valid before we pass down to
	 * the lower layers.
	 */
	if (error == 0) {
		zc->zc_name[sizeof (zc->zc_name) - 1] = '\0';
		switch (zfs_ioc_vec[vec].zvec_namecheck) {
		case pool_name:
			if (pool_namecheck(zc->zc_name, NULL, NULL) != 0)
				error = EINVAL;
			break;

		case dataset_name:
			if (dataset_namecheck(zc->zc_name, NULL, NULL) != 0)
				error = EINVAL;
			break;
		}
	}

	if (error == 0)
		error = zfs_ioc_vec[vec].zvec_func(zc);

	if (error == 0 || error == ENOMEM) {
		int rc = xcopyout(zc, (void *)arg, sizeof (zfs_cmd_t));
		if (error == 0)
			error = rc;
	}

	kmem_free(zc, sizeof (zfs_cmd_t));
	return (error);
}

static int
zfs_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "zfs", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	zfs_dip = dip;

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
zfs_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (spa_busy() || zfs_busy() || zvol_busy())
		return (DDI_FAILURE);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	zfs_dip = NULL;

	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
zfs_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = zfs_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * OK, so this is a little weird.
 *
 * /dev/zfs is the control node, i.e. minor 0.
 * /dev/zvol/[r]dsk/pool/dataset are the zvols, minor > 0.
 *
 * /dev/zfs has basically nothing to do except serve up ioctls,
 * so most of the standard driver entry points are in zvol.c.
 */
static struct cb_ops zfs_cb_ops = {
	zvol_open,	/* open */
	zvol_close,	/* close */
	zvol_strategy,	/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	zvol_read,	/* read */
	zvol_write,	/* write */
	zfsdev_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* streamtab */
	D_NEW | D_MP | D_64BIT,		/* Driver compatibility flag */
	CB_REV,		/* version */
	zvol_aread,	/* async read */
	zvol_awrite,	/* async write */
};

static struct dev_ops zfs_dev_ops = {
	DEVO_REV,	/* version */
	0,		/* refcnt */
	zfs_info,	/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	zfs_attach,	/* attach */
	zfs_detach,	/* detach */
	nodev,		/* reset */
	&zfs_cb_ops,	/* driver operations */
	NULL		/* no bus operations */
};

static struct modldrv zfs_modldrv = {
	&mod_driverops, "ZFS storage pool version 1", &zfs_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&zfs_modlfs,
	(void *)&zfs_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	spa_init(FREAD | FWRITE);
	zfs_init();
	zvol_init();

	if ((error = mod_install(&modlinkage)) != 0) {
		zvol_fini();
		zfs_fini();
		spa_fini();
		return (error);
	}

	error = ldi_ident_from_mod(&modlinkage, &zfs_li);
	ASSERT(error == 0);

	return (0);
}

int
_fini(void)
{
	int error;

	if (spa_busy() || zfs_busy() || zvol_busy())
		return (EBUSY);

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	zvol_fini();
	zfs_fini();
	spa_fini();

	ldi_ident_release(zfs_li);
	zfs_li = NULL;

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
