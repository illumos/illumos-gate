/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <devid.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/zfs_ioctl.h>

#include "zfs_namecheck.h"
#include "libzfs_impl.h"

/*
 * Validate the given pool name, optionally putting an extended error message in
 * 'buf'.
 */
static int
zpool_name_valid(const char *pool, char *buf, size_t buflen)
{
	namecheck_err_t why;
	char what;

	if (strlen(pool) >= ZPOOL_MAXNAMELEN) {
		if (buf)
			(void) snprintf(buf, buflen,
			    dgettext(TEXT_DOMAIN, "name is too long"));
		return (FALSE);
	}

	if (pool_namecheck(pool, &why, &what) != 0) {
		if (buf != NULL) {
			switch (why) {
			case NAME_ERR_INVALCHAR:
				(void) snprintf(buf, buflen,
				    dgettext(TEXT_DOMAIN, "invalid character "
				    "'%c' in pool name"), what);
				break;

			case NAME_ERR_NOLETTER:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "name must begin with a letter"), buflen);
				break;

			case NAME_ERR_RESERVED:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "name is reserved\n"
				    "pool name may have been omitted"), buflen);
				break;

			case NAME_ERR_DISKLIKE:
				(void) strlcpy(buf, dgettext(TEXT_DOMAIN,
				    "pool name is reserved\n"
				    "pool name may have been omitted"), buflen);
				break;
			}
		}
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Set the pool-wide health based on the vdev state of the root vdev.
 */
void
set_pool_health(nvlist_t *config)
{
	nvlist_t *nvroot;
	vdev_stat_t *vs;
	uint_t vsc;
	char *health;

	verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);
	verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &vsc) == 0);

	switch (vs->vs_state) {

	case VDEV_STATE_CLOSED:
	case VDEV_STATE_CANT_OPEN:
	case VDEV_STATE_OFFLINE:
		health = dgettext(TEXT_DOMAIN, "FAULTED");
		break;

	case VDEV_STATE_DEGRADED:
		health = dgettext(TEXT_DOMAIN, "DEGRADED");
		break;

	case VDEV_STATE_HEALTHY:
		health = dgettext(TEXT_DOMAIN, "ONLINE");
		break;

	default:
		zfs_baderror(vs->vs_state);
	}

	verify(nvlist_add_string(config, ZPOOL_CONFIG_POOL_HEALTH,
	    health) == 0);
}

/*
 * Open a handle to the given pool, even if the pool is currently in the FAULTED
 * state.
 */
zpool_handle_t *
zpool_open_canfail(const char *pool)
{
	zpool_handle_t *zhp;
	nvlist_t *newconfig;
	int error;

	/*
	 * Make sure the pool name is valid.
	 */
	if (!zpool_name_valid(pool, NULL, 0)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot open '%s': invalid "
		    "pool name"), pool);
		return (NULL);
	}

	zhp = zfs_malloc(sizeof (zpool_handle_t));

	(void) strlcpy(zhp->zpool_name, pool, sizeof (zhp->zpool_name));

	if ((error = zpool_refresh_stats(zhp, NULL, &newconfig)) != 0) {
		if (error == ENOENT || error == EINVAL) {
			zfs_error(dgettext(TEXT_DOMAIN, "cannot open '%s': no "
			    "such pool"), pool);
			free(zhp);
			return (NULL);
		} else {
			zhp->zpool_state = POOL_STATE_UNAVAIL;
		}
	} else {
		zhp->zpool_state = POOL_STATE_ACTIVE;
	}

	return (zhp);
}

/*
 * Like the above, but silent on error.  Used when iterating over pools (because
 * the configuration cache may be out of date).
 */
zpool_handle_t *
zpool_open_silent(const char *pool)
{
	zpool_handle_t *zhp;
	nvlist_t *newconfig;
	int error;

	zhp = zfs_malloc(sizeof (zpool_handle_t));

	(void) strlcpy(zhp->zpool_name, pool, sizeof (zhp->zpool_name));

	if ((error = zpool_refresh_stats(zhp, NULL, &newconfig)) != 0) {
		if (error == ENOENT || error == EINVAL) {
			free(zhp);
			return (NULL);
		} else {
			zhp->zpool_state = POOL_STATE_UNAVAIL;
		}
	} else {
		zhp->zpool_state = POOL_STATE_ACTIVE;
	}

	return (zhp);
}

/*
 * Similar to zpool_open_canfail(), but refuses to open pools in the faulted
 * state.
 */
zpool_handle_t *
zpool_open(const char *pool)
{
	zpool_handle_t *zhp;

	if ((zhp = zpool_open_canfail(pool)) == NULL)
		return (NULL);

	if (zhp->zpool_state == POOL_STATE_UNAVAIL) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot open ' %s': pool is "
		    "currently unavailable\n"), zhp->zpool_name);
		zfs_error(dgettext(TEXT_DOMAIN, "run 'zpool status -v %s' for "
		    "detailed information\n"), zhp->zpool_name);
		zpool_close(zhp);
		return (NULL);
	}

	return (zhp);
}

/*
 * Close the handle.  Simply frees the memory associated with the handle.
 */
void
zpool_close(zpool_handle_t *zhp)
{
	if (zhp->zpool_config)
		nvlist_free(zhp->zpool_config);
	free(zhp);
}

/*
 * Return the name of the pool.
 */
const char *
zpool_get_name(zpool_handle_t *zhp)
{
	return (zhp->zpool_name);
}

/*
 * Return the GUID of the pool.
 */
uint64_t
zpool_get_guid(zpool_handle_t *zhp)
{
	uint64_t guid;

	verify(nvlist_lookup_uint64(zhp->zpool_config, ZPOOL_CONFIG_POOL_GUID,
	    &guid) == 0);
	return (guid);
}

/*
 * Return the amount of space currently consumed by the pool.
 */
uint64_t
zpool_get_space_used(zpool_handle_t *zhp)
{
	nvlist_t *nvroot;
	vdev_stat_t *vs;
	uint_t vsc;

	verify(nvlist_lookup_nvlist(zhp->zpool_config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);
	verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &vsc) == 0);

	return (vs->vs_alloc);
}

/*
 * Return the total space in the pool.
 */
uint64_t
zpool_get_space_total(zpool_handle_t *zhp)
{
	nvlist_t *nvroot;
	vdev_stat_t *vs;
	uint_t vsc;

	verify(nvlist_lookup_nvlist(zhp->zpool_config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);
	verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &vsc) == 0);

	return (vs->vs_space);
}

/*
 * Return the alternate root for this pool, if any.
 */
int
zpool_get_root(zpool_handle_t *zhp, char *buf, size_t buflen)
{
	zfs_cmd_t zc = { 0 };

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	if (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0 ||
	    zc.zc_objset_stats.dds_altroot[0] == '\0')
		return (-1);

	(void) strlcpy(buf, zc.zc_objset_stats.dds_altroot, buflen);

	return (0);
}

/*
 * Return the state of the pool (ACTIVE or UNAVAILABLE)
 */
int
zpool_get_state(zpool_handle_t *zhp)
{
	return (zhp->zpool_state);
}

/*
 * Create the named pool, using the provided vdev list.  It is assumed
 * that the consumer has already validated the contents of the nvlist, so we
 * don't have to worry about error semantics.
 */
int
zpool_create(const char *pool, nvlist_t *nvroot, const char *altroot)
{
	zfs_cmd_t zc = { 0 };
	char *packed;
	size_t len;
	int err;
	char reason[64];

	if (!zpool_name_valid(pool, reason, sizeof (reason))) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': %s"),
		    pool, reason);
		return (-1);
	}

	if (altroot != NULL && altroot[0] != '/') {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': alternate "
		    "root '%s' must be a complete path"), pool, altroot);
		return (-1);
	}

	if ((err = nvlist_size(nvroot, &len, NV_ENCODE_NATIVE)) != 0)
		zfs_baderror(err);

	packed = zfs_malloc(len);

	if ((err = nvlist_pack(nvroot, &packed, &len,
	    NV_ENCODE_NATIVE, 0)) != 0)
		zfs_baderror(err);

	(void) strlcpy(zc.zc_name, pool, sizeof (zc.zc_name));
	zc.zc_config_src = (uint64_t)(uintptr_t)packed;
	zc.zc_config_src_size = len;

	if (altroot != NULL)
		(void) strlcpy(zc.zc_root, altroot, sizeof (zc.zc_root));

	if (ioctl(zfs_fd, ZFS_IOC_POOL_CREATE, &zc) != 0) {
		switch (errno) {
		case EEXIST:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "pool exists"), pool);
			break;

		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "permission denied"), pool);
			break;

		case EBUSY:
			/*
			 * This can happen if the user has specified the same
			 * device multiple times.  We can't reliably detect this
			 * until we try to add it and see we already have a
			 * label.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "one or more vdevs refer to the same device"),
			    pool);
			break;

		case EOVERFLOW:
			/*
			 * This occurrs when one of the devices is below
			 * SPA_MINDEVSIZE.  Unfortunately, we can't detect which
			 * device was the problem device since there's no
			 * reliable way to determine device size from userland.
			 */
			{
				char buf[64];

				zfs_nicenum(SPA_MINDEVSIZE, buf, sizeof (buf));

				zfs_error(dgettext(TEXT_DOMAIN, "cannot "
				    "create '%s': one or more devices is less "
				    "than the minimum size (%s)"), pool,
				    buf);
			}
			break;

		case ENAMETOOLONG:
			/*
			 * One of the vdevs has exceeded VDEV_SPEC_MAX length in
			 * its plaintext representation.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "too many devices in a single vdev"), pool);
			break;

		case EIO:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "I/O error on one or more devices"), pool);
			break;

		case ENXIO:
			/*
			 * This is unlikely to happen since we've verified that
			 * all the devices can be opened from userland, but it's
			 * still possible in some circumstances.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "one or more devices is unavailable"), pool);
			break;

		case ENOSPC:
			/*
			 * This can occur if we were incapable of writing to a
			 * file vdev because the underlying filesystem is out of
			 * space.  This is very similar to EOVERFLOW, but we'll
			 * produce a slightly different message.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot create '%s': "
			    "one or more devices is out of space"), pool);
			break;

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	free(packed);

	/*
	 * If this is an alternate root pool, then we automatically set the
	 * moutnpoint of the root dataset to be '/'.
	 */
	if (altroot != NULL) {
		zfs_handle_t *zhp;

		verify((zhp = zfs_open(pool, ZFS_TYPE_ANY)) != NULL);
		verify(zfs_prop_set(zhp, ZFS_PROP_MOUNTPOINT, "/") == 0);

		zfs_close(zhp);
	}

	return (0);
}

/*
 * Destroy the given pool.  It is up to the caller to ensure that there are no
 * datasets left in the pool.
 */
int
zpool_destroy(zpool_handle_t *zhp)
{
	zfs_cmd_t zc = { 0 };
	zfs_handle_t *zfp = NULL;

	if (zhp->zpool_state == POOL_STATE_ACTIVE &&
	    (zfp = zfs_open(zhp->zpool_name, ZFS_TYPE_FILESYSTEM)) == NULL)
		return (-1);

	if (zpool_remove_zvol_links(zhp) != NULL)
		return (-1);

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));

	if (ioctl(zfs_fd, ZFS_IOC_POOL_DESTROY, &zc) != 0) {
		switch (errno) {
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': permission denied"),
			    zhp->zpool_name);
			break;

		case EBUSY:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': pool busy"),
			    zhp->zpool_name);
			break;

		case ENOENT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': no such pool"),
			    zhp->zpool_name);
			break;

		case EROFS:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot destroy '%s': one or more devices is "
			    "read only, or '/' is mounted read only"),
			    zhp->zpool_name);
			break;

		default:
			zfs_baderror(errno);
		}

		if (zfp)
			zfs_close(zfp);
		return (-1);
	}

	if (zfp) {
		remove_mountpoint(zfp);
		zfs_close(zfp);
	}

	return (0);
}

/*
 * Add the given vdevs to the pool.  The caller must have already performed the
 * necessary verification to ensure that the vdev specification is well-formed.
 */
int
zpool_add(zpool_handle_t *zhp, nvlist_t *nvroot)
{
	char *packed;
	size_t len;
	zfs_cmd_t zc;

	verify(nvlist_size(nvroot, &len, NV_ENCODE_NATIVE) == 0);

	packed = zfs_malloc(len);

	verify(nvlist_pack(nvroot, &packed, &len, NV_ENCODE_NATIVE, 0) == 0);

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	zc.zc_config_src = (uint64_t)(uintptr_t)packed;
	zc.zc_config_src_size = len;

	if (ioctl(zfs_fd, ZFS_IOC_VDEV_ADD, &zc) != 0) {
		switch (errno) {
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot add to '%s': "
			    "permission denied"), zhp->zpool_name);
			break;

		case EBUSY:
			/*
			 * This can happen if the user has specified the same
			 * device multiple times.  We can't reliably detect this
			 * until we try to add it and see we already have a
			 * label.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot add to '%s': "
			    "one or more vdevs refer to the same device"),
			    zhp->zpool_name);
			break;

		case ENAMETOOLONG:
			/*
			 * One of the vdevs has exceeded VDEV_SPEC_MAX length in
			 * its plaintext representation.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot add to '%s': "
			    "too many devices in a single vdev"),
			    zhp->zpool_name);
			break;

		case ENXIO:
			/*
			 * This is unlikely to happen since we've verified that
			 * all the devices can be opened from userland, but it's
			 * still possible in some circumstances.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "cannot add to '%s': "
			    "one or more devices is unavailable"),
			    zhp->zpool_name);
			break;

		case EOVERFLOW:
			/*
			 * This occurrs when one of the devices is below
			 * SPA_MINDEVSIZE.  Unfortunately, we can't detect which
			 * device was the problem device since there's no
			 * reliable way to determine device size from userland.
			 */
			{
				char buf[64];

				zfs_nicenum(SPA_MINDEVSIZE, buf, sizeof (buf));

				zfs_error(dgettext(TEXT_DOMAIN, "cannot "
				    "add to '%s': one or more devices is less "
				    "than the minimum size (%s)"),
				    zhp->zpool_name, buf);
			}
			break;

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	free(packed);

	return (0);
}

/*
 * Exports the pool from the system.  The caller must ensure that there are no
 * mounted datasets in the pool.
 */
int
zpool_export(zpool_handle_t *zhp)
{
	zfs_cmd_t zc = { 0 };

	if (zpool_remove_zvol_links(zhp) != 0)
		return (-1);

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));

	if (ioctl(zfs_fd, ZFS_IOC_POOL_EXPORT, &zc) != 0) {
		switch (errno) {
		case EPERM:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot export '%s': permission denied"),
			    zhp->zpool_name);
			break;

		case EBUSY:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot export '%s': pool is in use"),
			    zhp->zpool_name);
			break;

		case ENOENT:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot export '%s': no such pool"),
			    zhp->zpool_name);
			break;

		default:
			zfs_baderror(errno);
		}

		return (-1);
	}

	return (0);
}

/*
 * Import the given pool using the known configuration.  The configuration
 * should have come from zpool_find_import().  The 'newname' and 'altroot'
 * parameters control whether the pool is imported with a different name or with
 * an alternate root, respectively.
 */
int
zpool_import(nvlist_t *config, const char *newname, const char *altroot)
{
	zfs_cmd_t zc;
	char *packed;
	size_t len;
	char *thename;
	char *origname;
	int ret;

	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &origname) == 0);

	if (newname != NULL) {
		if (!zpool_name_valid(newname, NULL, 0)) {
			zfs_error(dgettext(TEXT_DOMAIN, "cannot import '%s': "
			    "invalid pool name"), newname);
			return (-1);
		}
		thename = (char *)newname;
	} else {
		thename = origname;
	}

	if (altroot != NULL && altroot[0] != '/') {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot import '%s': alternate "
		    "root '%s' must be a complete path"), thename,
		    altroot);
		return (-1);
	}

	(void) strlcpy(zc.zc_name, thename, sizeof (zc.zc_name));

	if (altroot != NULL)
		(void) strlcpy(zc.zc_root, altroot, sizeof (zc.zc_root));
	else
		zc.zc_root[0] = '\0';

	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    &zc.zc_pool_guid) == 0);

	verify(nvlist_size(config, &len, NV_ENCODE_NATIVE) == 0);

	packed = zfs_malloc(len);

	verify(nvlist_pack(config, &packed, &len, NV_ENCODE_NATIVE, 0) == 0);

	zc.zc_config_src = (uint64_t)(uintptr_t)packed;
	zc.zc_config_src_size = len;

	ret = 0;
	if (ioctl(zfs_fd, ZFS_IOC_POOL_IMPORT, &zc) != 0) {
		char desc[1024];
		if (newname == NULL)
			(void) snprintf(desc, sizeof (desc),
			    dgettext(TEXT_DOMAIN, "cannot import '%s'"),
			    thename);
		else
			(void) snprintf(desc, sizeof (desc),
			    dgettext(TEXT_DOMAIN, "cannot import '%s' as '%s'"),
			    origname, thename);

		switch (errno) {
		case EEXIST:
			/*
			 * A pool with that name already exists.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "%s: pool exists"),
			    desc);
			break;

		case EPERM:
			/*
			 * The user doesn't have permission to create pools.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "%s: permission "
			    "denied"), desc);
			break;

		case ENXIO:
		case EDOM:
			/*
			 * Device is unavailable, or vdev sum didn't match.
			 */
			zfs_error(dgettext(TEXT_DOMAIN, "%s: one or more "
			    "devices is unavailable"),
			    desc);
			break;

		default:
			zfs_baderror(errno);
		}

		ret = -1;
	} else {
		zpool_handle_t *zhp;
		/*
		 * This should never fail, but play it safe anyway.
		 */
		if ((zhp = zpool_open_silent(thename)) != NULL) {
			ret = zpool_create_zvol_links(zhp);
			zpool_close(zhp);
		}
	}

	free(packed);
	return (ret);
}

/*
 * Scrub the pool.
 */
int
zpool_scrub(zpool_handle_t *zhp, pool_scrub_type_t type)
{
	zfs_cmd_t zc = { 0 };
	char msg[1024];

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	zc.zc_cookie = type;

	if (ioctl(zfs_fd, ZFS_IOC_POOL_SCRUB, &zc) == 0)
		return (0);

	(void) snprintf(msg, sizeof (msg),
	    dgettext(TEXT_DOMAIN, "cannot scrub %s"), zc.zc_name);

	switch (errno) {
	    case EPERM:
		/*
		 * No permission to scrub this pool.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: permission denied"), msg);
		break;

	    case EBUSY:
		/*
		 * Resilver in progress.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: currently resilvering"),
		    msg);
		break;

	    default:
		zfs_baderror(errno);
	}
	return (-1);
}

/*
 * Bring the specified vdev online
 */
int
zpool_vdev_online(zpool_handle_t *zhp, const char *path)
{
	zfs_cmd_t zc = { 0 };
	char msg[1024];

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	(void) snprintf(zc.zc_prop_value, sizeof (zc.zc_prop_value),
	    "%s%s", path[0] == '/' ? "" : "/dev/dsk/", path);

	if (ioctl(zfs_fd, ZFS_IOC_VDEV_ONLINE, &zc) == 0)
		return (0);

	(void) snprintf(msg, sizeof (msg),
	    dgettext(TEXT_DOMAIN, "cannot online %s"), zc.zc_prop_value);

	switch (errno) {
	    case ENODEV:
		/*
		 * Device doesn't exist
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: device not in pool"), msg);
		break;

	    case EPERM:
		/*
		 * No permission to bring this vdev online.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: permission denied"), msg);
		break;

	    default:
		zfs_baderror(errno);
	}
	return (-1);
}

/*
 * Take the specified vdev offline
 */
int
zpool_vdev_offline(zpool_handle_t *zhp, const char *path)
{
	zfs_cmd_t zc = { 0 };
	char msg[1024];

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	(void) snprintf(zc.zc_prop_value, sizeof (zc.zc_prop_value),
	    "%s%s", path[0] == '/' ? "" : "/dev/dsk/", path);

	if (ioctl(zfs_fd, ZFS_IOC_VDEV_OFFLINE, &zc) == 0)
		return (0);

	(void) snprintf(msg, sizeof (msg),
	    dgettext(TEXT_DOMAIN, "cannot offline %s"), zc.zc_prop_value);

	switch (errno) {
	    case ENODEV:
		/*
		 * Device doesn't exist
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: device not in pool"), msg);
		break;

	    case EPERM:
		/*
		 * No permission to take this vdev offline.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: permission denied"), msg);
		break;

	    case EBUSY:
		/*
		 * There are no other replicas of this device.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: no valid replicas"), msg);
		break;

	    default:
		zfs_baderror(errno);
	}
	return (-1);
}

/*
 * Attach new_disk (fully described by nvroot) to old_disk.
 * If 'replacing' is specified, tne new disk will replace the old one.
 */
int
zpool_vdev_attach(zpool_handle_t *zhp,
    const char *old_disk, const char *new_disk, nvlist_t *nvroot, int replacing)
{
	zfs_cmd_t zc = { 0 };
	char msg[1024];
	char *packed;
	int ret;
	size_t len;

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	(void) snprintf(zc.zc_prop_value, sizeof (zc.zc_prop_value),
	    "%s%s", old_disk[0] == '/' ? "" : "/dev/dsk/", old_disk);
	zc.zc_cookie = replacing;

	verify(nvlist_size(nvroot, &len, NV_ENCODE_NATIVE) == 0);

	packed = zfs_malloc(len);

	verify(nvlist_pack(nvroot, &packed, &len, NV_ENCODE_NATIVE, 0) == 0);

	zc.zc_config_src = (uint64_t)(uintptr_t)packed;
	zc.zc_config_src_size = len;

	ret = ioctl(zfs_fd, ZFS_IOC_VDEV_ATTACH, &zc);

	free(packed);

	if (ret == 0)
		return (0);

	if (replacing)
		(void) snprintf(msg, sizeof (msg), dgettext(TEXT_DOMAIN,
		    "cannot replace %s with %s"), old_disk, new_disk);
	else
		(void) snprintf(msg, sizeof (msg), dgettext(TEXT_DOMAIN,
		    "cannot attach %s to %s"), new_disk, old_disk);

	switch (errno) {
	    case EPERM:
		/*
		 * No permission to mess with the config.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: permission denied"), msg);
		break;

	    case ENODEV:
		/*
		 * Device doesn't exist.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: %s not in pool"),
		    msg, old_disk);
		break;

	    case ENOTSUP:
		/*
		 * Can't attach to or replace this type of vdev.
		 */
		if (replacing)
			zfs_error(dgettext(TEXT_DOMAIN,
			    "%s: cannot replace a replacing device"), msg);
		else
			zfs_error(dgettext(TEXT_DOMAIN,
			    "%s: attach is only applicable to mirrors"), msg);
		break;

	    case EINVAL:
		/*
		 * The new device must be a single disk.
		 */
		zfs_error(dgettext(TEXT_DOMAIN,
		    "%s: <new_device> must be a single disk"), msg);
		break;

	    case ENXIO:
		/*
		 * This is unlikely to happen since we've verified that
		 * all the devices can be opened from userland, but it's
		 * still possible in some circumstances.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: %s is unavailable"),
		    msg, new_disk);
		break;

	    case EBUSY:
		/*
		 * The new device is is use.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: %s busy"), msg, new_disk);
		break;

	    case EOVERFLOW:
		/*
		 * The new device is too small.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: %s is too small"),
		    msg, new_disk);
		break;

	    case EDOM:
		/*
		 * The new device has a different alignment requirement.
		 */
		zfs_error(dgettext(TEXT_DOMAIN,
		    "%s: devices have different sector alignment"), msg);
		break;

	    case ENAMETOOLONG:
		/*
		 * The resulting top-level vdev spec won't fit in the label.
		 */
		zfs_error(dgettext(TEXT_DOMAIN,
		    "%s: too many devices in a single vdev"), msg);
		break;

	    default:
		zfs_baderror(errno);
	}

	return (1);
}

/*
 * Detach the specified device.
 */
int
zpool_vdev_detach(zpool_handle_t *zhp, const char *path)
{
	zfs_cmd_t zc = { 0 };
	char msg[1024];

	(void) strlcpy(zc.zc_name, zhp->zpool_name, sizeof (zc.zc_name));
	(void) snprintf(zc.zc_prop_value, sizeof (zc.zc_prop_value),
	    "%s%s", path[0] == '/' ? "" : "/dev/dsk/", path);

	if (ioctl(zfs_fd, ZFS_IOC_VDEV_DETACH, &zc) == 0)
		return (0);

	(void) snprintf(msg, sizeof (msg),
	    dgettext(TEXT_DOMAIN, "cannot detach %s"), zc.zc_prop_value);

	switch (errno) {
	    case EPERM:
		/*
		 * No permission to mess with the config.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: permission denied"), msg);
		break;

	    case ENODEV:
		/*
		 * Device doesn't exist.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: device not in pool"), msg);
		break;

	    case ENOTSUP:
		/*
		 * Can't detach from this type of vdev.
		 */
		zfs_error(dgettext(TEXT_DOMAIN,
		    "%s: only applicable to mirror and replacing vdevs"), msg);
		break;

	    case EBUSY:
		/*
		 * There are no other replicas of this device.
		 */
		zfs_error(dgettext(TEXT_DOMAIN, "%s: no valid replicas"), msg);
		break;

	    default:
		zfs_baderror(errno);
	}

	return (1);
}

static int
do_zvol(zfs_handle_t *zhp, void *data)
{
	int linktype = (int)(uintptr_t)data;
	int ret;

	/*
	 * We check for volblocksize intead of ZFS_TYPE_VOLUME so that we
	 * correctly handle snapshots of volumes.
	 */
	if (zhp->zfs_volblocksize != 0) {
		if (linktype)
			ret = zvol_create_link(zhp->zfs_name);
		else
			ret = zvol_remove_link(zhp->zfs_name);
	}

	ret = zfs_iter_children(zhp, do_zvol, data);

	zfs_close(zhp);
	return (ret);
}

/*
 * Iterate over all zvols in the pool and make any necessary minor nodes.
 */
int
zpool_create_zvol_links(zpool_handle_t *zhp)
{
	zfs_handle_t *zfp;
	int ret;

	/*
	 * If the pool is unavailable, just return success.
	 */
	if ((zfp = make_dataset_handle(zhp->zpool_name)) == NULL)
		return (0);

	ret = zfs_iter_children(zfp, do_zvol, (void *)TRUE);

	zfs_close(zfp);
	return (ret);
}

/*
 * Iterate over all zvols in the poool and remove any minor nodes.
 */
int
zpool_remove_zvol_links(zpool_handle_t *zhp)
{
	zfs_handle_t *zfp;
	int ret;

	/*
	 * If the pool is unavailable, just return success.
	 */
	if ((zfp = make_dataset_handle(zhp->zpool_name)) == NULL)
		return (0);

	ret = zfs_iter_children(zfp, do_zvol, (void *)FALSE);

	zfs_close(zfp);
	return (ret);
}
