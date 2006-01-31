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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Pool import support functions.
 *
 * To import a pool, we rely on reading the configuration information from the
 * ZFS label of each device.  If we successfully read the label, then we
 * organize the configuration information in the following hierarchy:
 *
 * 	pool guid -> toplevel vdev guid -> label txg
 *
 * Duplicate entries matching this same tuple will be discarded.  Once we have
 * examined every device, we pick the best label txg config for each toplevel
 * vdev.  We then arrange these toplevel vdevs into a complete pool config, and
 * update any paths that have changed.  Finally, we attempt to import the pool
 * using our derived config, and record the results.
 */

#include <devid.h>
#include <dirent.h>
#include <errno.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/vdev_impl.h>

#include "libzfs.h"
#include "libzfs_impl.h"

/*
 * Intermediate structures used to gather configuration information.
 */
typedef struct config_entry {
	uint64_t		ce_txg;
	nvlist_t		*ce_config;
	struct config_entry	*ce_next;
} config_entry_t;

typedef struct vdev_entry {
	uint64_t		ve_guid;
	config_entry_t		*ve_configs;
	struct vdev_entry	*ve_next;
} vdev_entry_t;

typedef struct pool_entry {
	uint64_t		pe_guid;
	vdev_entry_t		*pe_vdevs;
	struct pool_entry	*pe_next;
} pool_entry_t;

typedef struct name_entry {
	const char		*ne_name;
	uint64_t		ne_guid;
	struct name_entry	*ne_next;
} name_entry_t;

typedef struct pool_list {
	pool_entry_t		*pools;
	name_entry_t		*names;
} pool_list_t;

static char *
get_devid(const char *path)
{
	int fd;
	ddi_devid_t devid;
	char *minor, *ret;

	if ((fd = open(path, O_RDONLY)) < 0)
		return (NULL);

	minor = NULL;
	ret = NULL;
	if (devid_get(fd, &devid) == 0) {
		if (devid_get_minor_name(fd, &minor) == 0)
			ret = devid_str_encode(devid, minor);
		if (minor != NULL)
			devid_str_free(minor);
		devid_free(devid);
	}
	(void) close(fd);

	return (ret);
}


/*
 * Go through and fix up any path and/or devid information for the given vdev
 * configuration.
 */
static void
fix_paths(nvlist_t *nv, name_entry_t *names)
{
	nvlist_t **child;
	uint_t c, children;
	uint64_t guid;
	name_entry_t *ne, *best;
	char *path, *devid;
	int matched;

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			fix_paths(child[c], names);
		return;
	}

	/*
	 * This is a leaf (file or disk) vdev.  In either case, go through
	 * the name list and see if we find a matching guid.  If so, replace
	 * the path and see if we can calculate a new devid.
	 *
	 * There may be multiple names associated with a particular guid, in
	 * which case we have overlapping slices or multiple paths to the same
	 * disk.  If this is the case, then we want to pick the path that is
	 * the most similar to the original, where "most similar" is the number
	 * of matching characters starting from the end of the path.  This will
	 * preserve slice numbers even if the disks have been reorganized, and
	 * will also catch preferred disk names if multiple paths exist.
	 */
	verify(nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) == 0);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) != 0)
		path = NULL;

	matched = 0;
	best = NULL;
	for (ne = names; ne != NULL; ne = ne->ne_next) {
		if (ne->ne_guid == guid) {
			const char *src, *dst;
			int count;

			if (path == NULL) {
				best = ne;
				break;
			}

			src = ne->ne_name + strlen(ne->ne_name) - 1;
			dst = path + strlen(path) - 1;
			for (count = 0; src >= ne->ne_name && dst >= path;
			    src--, dst--, count++)
				if (*src != *dst)
					break;

			/*
			 * At this point, 'count' is the number of characters
			 * matched from the end.
			 */
			if (count > matched || best == NULL) {
				best = ne;
				matched = count;
			}
		}
	}

	if (best == NULL)
		return;

	verify(nvlist_add_string(nv, ZPOOL_CONFIG_PATH, best->ne_name) == 0);

	if ((devid = get_devid(best->ne_name)) == NULL) {
		(void) nvlist_remove_all(nv, ZPOOL_CONFIG_DEVID);
	} else {
		verify(nvlist_add_string(nv, ZPOOL_CONFIG_DEVID, devid) == 0);
		devid_str_free(devid);
	}
}

/*
 * Add the given configuration to the list of known devices.
 */
static void
add_config(pool_list_t *pl, const char *path, nvlist_t *config)
{
	uint64_t pool_guid, vdev_guid, top_guid, txg;
	pool_entry_t *pe;
	vdev_entry_t *ve;
	config_entry_t *ce;
	name_entry_t *ne;

	/*
	 * If we have a valid config but cannot read any of these fields, then
	 * it means we have a half-initialized label.  In vdev_label_init()
	 * we write a label with txg == 0 so that we can identify the device
	 * in case the user refers to the same disk later on.  If we fail to
	 * create the pool, we'll be left with a label in this state
	 * which should not be considered part of a valid pool.
	 */
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    &pool_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID,
	    &vdev_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_TOP_GUID,
	    &top_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
	    &txg) != 0 || txg == 0) {
		nvlist_free(config);
		return;
	}

	/*
	 * First, see if we know about this pool.  If not, then add it to the
	 * list of known pools.
	 */
	for (pe = pl->pools; pe != NULL; pe = pe->pe_next) {
		if (pe->pe_guid == pool_guid)
			break;
	}

	if (pe == NULL) {
		pe = zfs_malloc(sizeof (pool_entry_t));
		pe->pe_guid = pool_guid;
		pe->pe_next = pl->pools;
		pl->pools = pe;
	}

	/*
	 * Second, see if we know about this toplevel vdev.  Add it if its
	 * missing.
	 */
	for (ve = pe->pe_vdevs; ve != NULL; ve = ve->ve_next) {
		if (ve->ve_guid == top_guid)
			break;
	}

	if (ve == NULL) {
		ve = zfs_malloc(sizeof (vdev_entry_t));
		ve->ve_guid = top_guid;
		ve->ve_next = pe->pe_vdevs;
		pe->pe_vdevs = ve;
	}

	/*
	 * Third, see if we have a config with a matching transaction group.  If
	 * so, then we do nothing.  Otherwise, add it to the list of known
	 * configs.
	 */
	for (ce = ve->ve_configs; ce != NULL; ce = ce->ce_next) {
		if (ce->ce_txg == txg)
			break;
	}

	if (ce == NULL) {
		ce = zfs_malloc(sizeof (config_entry_t));
		ce->ce_txg = txg;
		ce->ce_config = config;
		ce->ce_next = ve->ve_configs;
		ve->ve_configs = ce;
	} else {
		nvlist_free(config);
	}

	/*
	 * At this point we've successfully added our config to the list of
	 * known configs.  The last thing to do is add the vdev guid -> path
	 * mappings so that we can fix up the configuration as necessary before
	 * doing the import.
	 */
	ne = zfs_malloc(sizeof (name_entry_t));

	ne->ne_name = zfs_strdup(path);
	ne->ne_guid = vdev_guid;
	ne->ne_next = pl->names;
	pl->names = ne;
}

/*
 * Convert our list of pools into the definitive set of configurations.  We
 * start by picking the best config for each toplevel vdev.  Once that's done,
 * we assemble the toplevel vdevs into a full config for the pool.  We make a
 * pass to fix up any incorrect paths, and then add it to the main list to
 * return to the user.
 */
static nvlist_t *
get_configs(pool_list_t *pl)
{
	pool_entry_t *pe, *penext;
	vdev_entry_t *ve, *venext;
	config_entry_t *ce, *cenext;
	nvlist_t *ret, *config, *tmp, *nvtop, *nvroot;
	int config_seen;
	uint64_t best_txg;
	char *name;
	zfs_cmd_t zc = { 0 };
	uint64_t guid;
	char *packed;
	size_t len;
	int err;

	verify(nvlist_alloc(&ret, 0, 0) == 0);

	for (pe = pl->pools; pe != NULL; pe = penext) {
		uint_t c;
		uint_t children = 0;
		uint64_t id;
		nvlist_t **child = NULL;

		penext = pe->pe_next;

		verify(nvlist_alloc(&config, NV_UNIQUE_NAME, 0) == 0);
		config_seen = FALSE;

		/*
		 * Iterate over all toplevel vdevs.  Grab the pool configuration
		 * from the first one we find, and then go through the rest and
		 * add them as necessary to the 'vdevs' member of the config.
		 */
		for (ve = pe->pe_vdevs; ve != NULL; ve = venext) {
			venext = ve->ve_next;

			/*
			 * Determine the best configuration for this vdev by
			 * selecting the config with the latest transaction
			 * group.
			 */
			best_txg = 0;
			for (ce = ve->ve_configs; ce != NULL;
			    ce = ce->ce_next) {

				if (ce->ce_txg > best_txg)
					tmp = ce->ce_config;
			}

			if (!config_seen) {
				/*
				 * Copy the relevant pieces of data to the pool
				 * configuration:
				 *
				 * 	pool guid
				 * 	name
				 * 	pool state
				 */
				uint64_t state;

				verify(nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_GUID, &guid) == 0);
				verify(nvlist_add_uint64(config,
				    ZPOOL_CONFIG_POOL_GUID, guid) == 0);
				verify(nvlist_lookup_string(tmp,
				    ZPOOL_CONFIG_POOL_NAME, &name) == 0);
				verify(nvlist_add_string(config,
				    ZPOOL_CONFIG_POOL_NAME, name) == 0);
				verify(nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_STATE, &state) == 0);
				verify(nvlist_add_uint64(config,
				    ZPOOL_CONFIG_POOL_STATE, state) == 0);

				config_seen = TRUE;
			}

			/*
			 * Add this top-level vdev to the child array.
			 */
			verify(nvlist_lookup_nvlist(tmp,
			    ZPOOL_CONFIG_VDEV_TREE, &nvtop) == 0);
			verify(nvlist_lookup_uint64(nvtop, ZPOOL_CONFIG_ID,
			    &id) == 0);
			if (id >= children) {
				nvlist_t **newchild;

				newchild = zfs_malloc((id + 1) *
				    sizeof (nvlist_t *));

				for (c = 0; c < children; c++)
					newchild[c] = child[c];

				free(child);
				child = newchild;
				children = id + 1;
			}
			verify(nvlist_dup(nvtop, &child[id], 0) == 0);

			/*
			 * Go through and free all config information.
			 */
			for (ce = ve->ve_configs; ce != NULL; ce = cenext) {
				cenext = ce->ce_next;

				nvlist_free(ce->ce_config);
				free(ce);
			}

			/*
			 * Free this vdev entry, since it has now been merged
			 * into the main config.
			 */
			free(ve);
		}

		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		/*
		 * Look for any missing top-level vdevs.  If this is the case,
		 * create a faked up 'missing' vdev as a placeholder.  We cannot
		 * simply compress the child array, because the kernel performs
		 * certain checks to make sure the vdev IDs match their location
		 * in the configuration.
		 */
		for (c = 0; c < children; c++)
			if (child[c] == NULL) {
				nvlist_t *missing;
				verify(nvlist_alloc(&missing, NV_UNIQUE_NAME,
				    0) == 0);
				verify(nvlist_add_string(missing,
				    ZPOOL_CONFIG_TYPE, VDEV_TYPE_MISSING) == 0);
				verify(nvlist_add_uint64(missing,
				    ZPOOL_CONFIG_ID, c) == 0);
				verify(nvlist_add_uint64(missing,
				    ZPOOL_CONFIG_GUID, 0ULL) == 0);
				child[c] = missing;
			}

		/*
		 * Put all of this pool's top-level vdevs into a root vdev.
		 */
		verify(nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) == 0);
		verify(nvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE,
		    VDEV_TYPE_ROOT) == 0);
		verify(nvlist_add_uint64(nvroot, ZPOOL_CONFIG_ID, 0ULL) == 0);
		verify(nvlist_add_uint64(nvroot, ZPOOL_CONFIG_GUID, guid) == 0);
		verify(nvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
		    child, children) == 0);

		for (c = 0; c < children; c++)
			nvlist_free(child[c]);
		free(child);

		/*
		 * Go through and fix up any paths and/or devids based on our
		 * known list of vdev GUID -> path mappings.
		 */
		fix_paths(nvroot, pl->names);

		/*
		 * Add the root vdev to this pool's configuration.
		 */
		verify(nvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    nvroot) == 0);
		nvlist_free(nvroot);

		/*
		 * Free this pool entry.
		 */
		free(pe);

		/*
		 * Determine if this pool is currently active, in which case we
		 * can't actually import it.
		 */
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		(void) strlcpy(zc.zc_name, name, sizeof (zc.zc_name));
		if (ioctl(zfs_fd, ZFS_IOC_POOL_GUID, &zc) == 0 &&
		    guid == zc.zc_pool_guid) {
			nvlist_free(config);
			continue;
		}

		/*
		 * Try to do the import in order to get vdev state.
		 */
		if ((err = nvlist_size(config, &len, NV_ENCODE_NATIVE)) != 0)
			zfs_baderror(err);

		packed = zfs_malloc(len);

		if ((err = nvlist_pack(config, &packed, &len,
		    NV_ENCODE_NATIVE, 0)) != 0)
			zfs_baderror(err);

		nvlist_free(config);
		config = NULL;

		zc.zc_config_src_size = len;
		zc.zc_config_src = (uint64_t)(uintptr_t)packed;

		zc.zc_config_dst_size = 2 * len;
		zc.zc_config_dst = (uint64_t)(uintptr_t)
		    zfs_malloc(zc.zc_config_dst_size);

		while ((err = ioctl(zfs_fd, ZFS_IOC_POOL_TRYIMPORT,
		    &zc)) != 0 && errno == ENOMEM) {
			free((void *)(uintptr_t)zc.zc_config_dst);
			zc.zc_config_dst = (uint64_t)(uintptr_t)
			    zfs_malloc(zc.zc_config_dst_size);
		}

		free(packed);

		if (err)
			zfs_baderror(errno);

		verify(nvlist_unpack((void *)(uintptr_t)zc.zc_config_dst,
		    zc.zc_config_dst_size, &config, 0) == 0);

		set_pool_health(config);

		/*
		 * Add this pool to the list of configs.
		 */
		verify(nvlist_add_nvlist(ret, name, config) == 0);

		nvlist_free(config);

		free((void *)(uintptr_t)zc.zc_config_dst);
	}

	return (ret);
}

/*
 * Return the offset of the given label.
 */
static uint64_t
label_offset(size_t size, int l)
{
	return (l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : size - VDEV_LABELS * sizeof (vdev_label_t)));
}

/*
 * Given a file descriptor, read the label information and return an nvlist
 * describing the configuration, if there is one.
 */
nvlist_t *
zpool_read_label(int fd)
{
	struct stat64 statbuf;
	int l;
	vdev_label_t *label;
	nvlist_t *config;
	uint64_t version, state, txg;

	if (fstat64(fd, &statbuf) == -1)
		return (NULL);

	label = zfs_malloc(sizeof (vdev_label_t));

	for (l = 0; l < VDEV_LABELS; l++) {
		if (pread(fd, label, sizeof (vdev_label_t),
		    label_offset(statbuf.st_size, l)) != sizeof (vdev_label_t))
			continue;

		if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
		    sizeof (label->vl_vdev_phys.vp_nvlist), &config, 0) != 0)
			continue;

		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_VERSION,
		    &version) != 0 || version != UBERBLOCK_VERSION) {
			nvlist_free(config);
			continue;
		}

		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
		    &state) != 0 || state > POOL_STATE_EXPORTED) {
			nvlist_free(config);
			continue;
		}

		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
		    &txg) != 0 || txg == 0) {
			nvlist_free(config);
			continue;
		}

		free(label);
		return (config);
	}

	free(label);
	return (NULL);
}

/*
 * Given a list of directories to search, find all pools stored on disk.  This
 * includes partial pools which are not available to import.  If no args are
 * given (argc is 0), then the default directory (/dev/dsk) is searched.
 */
nvlist_t *
zpool_find_import(int argc, char **argv)
{
	int i;
	DIR *dirp;
	struct dirent64 *dp;
	char path[MAXPATHLEN];
	struct stat64 statbuf;
	nvlist_t *ret, *config;
	static char *default_dir = "/dev/dsk";
	int fd;
	pool_list_t pools = { 0 };

	if (argc == 0) {
		argc = 1;
		argv = &default_dir;
	}

	/*
	 * Go through and read the label configuration information from every
	 * possible device, organizing the information according to pool GUID
	 * and toplevel GUID.
	 */
	for (i = 0; i < argc; i++) {
		if (argv[i][0] != '/') {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot open '%s': must be an absolute path"),
			    argv[i]);
			return (NULL);
		}

		if ((dirp = opendir(argv[i])) == NULL) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot open '%s': %s"), argv[i],
			    strerror(errno));
			return (NULL);
		}

		/*
		 * This is not MT-safe, but we have no MT consumers of libzfs
		 */
		while ((dp = readdir64(dirp)) != NULL) {

			(void) snprintf(path, sizeof (path), "%s/%s",
			    argv[i], dp->d_name);

			if (stat64(path, &statbuf) != 0)
				continue;

			/*
			 * Ignore directories (which includes "." and "..").
			 */
			if (S_ISDIR(statbuf.st_mode))
				continue;

			if ((fd = open64(path, O_RDONLY)) < 0)
				continue;

			config = zpool_read_label(fd);

			(void) close(fd);

			if (config != NULL)
				add_config(&pools, path, config);
		}
	}

	ret = get_configs(&pools);

	return (ret);
}

int
find_guid(nvlist_t *nv, uint64_t guid)
{
	uint64_t tmp;
	nvlist_t **child;
	uint_t c, children;

	verify(nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &tmp) == 0);
	if (tmp == guid)
		return (TRUE);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			if (find_guid(child[c], guid))
				return (TRUE);
	}

	return (FALSE);
}

/*
 * Determines if the pool is in use.  If so, it returns TRUE and the state of
 * the pool as well as the name of the pool.  Both strings are allocated and
 * must be freed by the caller.
 */
int
zpool_in_use(int fd, pool_state_t *state, char **namestr)
{
	nvlist_t *config;
	char *name;
	int ret;
	zfs_cmd_t zc = { 0 };
	uint64_t guid, vdev_guid;
	zpool_handle_t *zhp;
	nvlist_t *pool_config;
	uint64_t stateval;

	if ((config = zpool_read_label(fd)) == NULL)
		return (FALSE);

	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &name) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    &stateval) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    &guid) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID,
	    &vdev_guid) == 0);

	switch (stateval) {
	case POOL_STATE_EXPORTED:
		ret = TRUE;
		break;

	case POOL_STATE_ACTIVE:
		/*
		 * For an active pool, we have to determine if it's really part
		 * of an active pool (in which case the pool will exist and the
		 * guid will be the same), or whether it's part of an active
		 * pool that was disconnected without being explicitly exported.
		 *
		 * We use the direct ioctl() first to avoid triggering an error
		 * message if the pool cannot be opened.
		 */
		(void) strlcpy(zc.zc_name, name, sizeof (zc.zc_name));
		if (ioctl(zfs_fd, ZFS_IOC_POOL_GUID, &zc) == 0 &&
		    guid == zc.zc_pool_guid) {
			/*
			 * Because the device may have been removed while
			 * offlined, we only report it as active if the vdev is
			 * still present in the config.  Otherwise, pretend like
			 * it's not in use.
			 */
			if ((zhp = zpool_open_canfail(name)) != NULL &&
			    (pool_config = zpool_get_config(zhp, NULL))
			    != NULL) {
				nvlist_t *nvroot;

				verify(nvlist_lookup_nvlist(pool_config,
				    ZPOOL_CONFIG_VDEV_TREE, &nvroot) == 0);
				ret = find_guid(nvroot, vdev_guid);
			} else {
				ret = FALSE;
			}
		} else {
			stateval = POOL_STATE_POTENTIALLY_ACTIVE;
			ret = TRUE;
		}
		break;

	default:
		ret = FALSE;
	}


	if (ret) {
		*namestr = zfs_strdup(name);
		*state = (pool_state_t)stateval;
	}

	nvlist_free(config);
	return (ret);
}
