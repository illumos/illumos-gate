/*
 *
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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <alloca.h>
#include <limits.h>
#include <fm/topo_mod.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <sys/stat.h>

#include <topo_method.h>
#include <topo_subr.h>
#include <libzfs.h>
#include <zfs.h>
#include <pthread.h>

static int zfs_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void zfs_rele(topo_mod_t *, tnode_t *);
static int zfs_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

const topo_method_t zfs_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, zfs_fmri_nvl2str },
	{ NULL }
};

static const topo_modops_t zfs_ops =
	{ zfs_enum, zfs_rele };
static const topo_modinfo_t zfs_info =
	{ ZFS, FM_FMRI_SCHEME_ZFS, ZFS_VERSION, &zfs_ops };

static libzfs_handle_t *g_zfs = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_refcount = 0;

int
zfs_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOZFSDEBUG"))
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing zfs builtin\n");

	if (version != ZFS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &zfs_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register zfs: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	(void) pthread_mutex_lock(&g_lock);
	if (g_refcount == 0) {
		if ((g_zfs = libzfs_init()) == NULL) {
			(void) pthread_mutex_unlock(&g_lock);
			topo_mod_dprintf(mod, "libzfs_init() failed");
			topo_mod_unregister(mod);
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}
	}
	g_refcount++;
	(void) pthread_mutex_unlock(&g_lock);

	return (0);
}

void
zfs_fini(topo_mod_t *mod)
{
	(void) pthread_mutex_lock(&g_lock);
	g_refcount--;
	if (g_refcount == 0) {
		libzfs_fini(g_zfs);
		g_zfs = NULL;
	}
	(void) pthread_mutex_unlock(&g_lock);
	topo_mod_unregister(mod);
}


/*ARGSUSED*/
int
zfs_enum(topo_mod_t *mod, tnode_t *pnode, const char *name, topo_instance_t min,
    topo_instance_t max, void *notused1, void *notused2)
{
	/*
	 * Methods are registered, but there is no enumeration.  Should
	 * enumeration be added be sure to cater for global vs non-global
	 * zones.
	 */
	(void) topo_method_register(mod, pnode, zfs_methods);
	return (0);
}

/*ARGSUSED*/
static void
zfs_rele(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

typedef struct cbdata {
	uint64_t	cb_guid;
	zpool_handle_t	*cb_pool;
} cbdata_t;

static int
find_pool(zpool_handle_t *zhp, void *data)
{
	cbdata_t *cbp = data;

	if (zpool_get_prop_int(zhp, ZPOOL_PROP_GUID, NULL) == cbp->cb_guid) {
		cbp->cb_pool = zhp;
		return (1);
	}

	zpool_close(zhp);

	return (0);
}

static ssize_t
fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	uint64_t pool_guid, vdev_guid;
	cbdata_t cb;
	ssize_t len;
	const char *name;
	char guidbuf[64];

	(void) nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_POOL, &pool_guid);

	/*
	 * Attempt to convert the pool guid to a name.
	 */
	cb.cb_guid = pool_guid;
	cb.cb_pool = NULL;

	if (zpool_iter(g_zfs, find_pool, &cb) == 1) {
		name = zpool_get_name(cb.cb_pool);
	} else {
		(void) snprintf(guidbuf, sizeof (guidbuf), "%llx", pool_guid);
		name = guidbuf;
	}

	if (nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_VDEV, &vdev_guid) == 0)
		len = snprintf(buf, buflen, "%s://pool=%s/vdev=%llx",
		    FM_FMRI_SCHEME_ZFS, name, vdev_guid);
	else
		len = snprintf(buf, buflen, "%s://pool=%s",
		    FM_FMRI_SCHEME_ZFS, name);

	if (cb.cb_pool)
		zpool_close(cb.cb_pool);

	return (len);
}

/*ARGSUSED*/
static int
zfs_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	ssize_t len;
	char *name = NULL;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((len = fmri_nvl2str(nvl, NULL, 0)) == 0 ||
	    (name = topo_mod_alloc(mod, len + 1)) == NULL ||
	    fmri_nvl2str(nvl, name, len + 1) == 0) {
		if (name != NULL)
			topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(fmristr, "fmri-string", name) != 0) {
		topo_mod_free(mod, name, len + 1);
		nvlist_free(fmristr);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, name, len + 1);
	*out = fmristr;

	return (0);
}
