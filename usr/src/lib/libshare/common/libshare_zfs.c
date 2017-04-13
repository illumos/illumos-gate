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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <stdio.h>
#include <libzfs.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <libshare.h>
#include "libshare_impl.h"
#include <libintl.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <assert.h>

extern sa_share_t _sa_add_share(sa_group_t, char *, int, int *, uint64_t);
extern sa_group_t _sa_create_zfs_group(sa_group_t, char *);
extern char *sa_fstype(char *);
extern void set_node_attr(void *, char *, char *);
extern int sa_is_share(void *);
extern void sa_update_sharetab_ts(sa_handle_t);

/*
 * File system specific code for ZFS. The original code was stolen
 * from the "zfs" command and modified to better suit this library's
 * usage.
 */

typedef struct get_all_cbdata {
	zfs_handle_t	**cb_handles;
	size_t		cb_alloc;
	size_t		cb_used;
	uint_t		cb_types;
} get_all_cbdata_t;

/*
 * sa_zfs_init(impl_handle)
 *
 * Initialize an access handle into libzfs.  The handle needs to stay
 * around until sa_zfs_fini() in order to maintain the cache of
 * mounts.
 */

int
sa_zfs_init(sa_handle_impl_t impl_handle)
{
	impl_handle->zfs_libhandle = libzfs_init();
	if (impl_handle->zfs_libhandle != NULL) {
		libzfs_print_on_error(impl_handle->zfs_libhandle, B_TRUE);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * sa_zfs_fini(impl_handle)
 *
 * cleanup data structures and the libzfs handle used for accessing
 * zfs file share info.
 */

void
sa_zfs_fini(sa_handle_impl_t impl_handle)
{
	if (impl_handle->zfs_libhandle != NULL) {
		if (impl_handle->zfs_list != NULL) {
			zfs_handle_t **zhp = impl_handle->zfs_list;
			size_t i;

			/*
			 * Contents of zfs_list need to be freed so we
			 * don't lose ZFS handles.
			 */
			for (i = 0; i < impl_handle->zfs_list_count; i++) {
				zfs_close(zhp[i]);
			}
			free(impl_handle->zfs_list);
			impl_handle->zfs_list = NULL;
			impl_handle->zfs_list_count = 0;
		}

		libzfs_fini(impl_handle->zfs_libhandle);
		impl_handle->zfs_libhandle = NULL;
	}
}

/*
 * get_one_filesystem(zfs_handle_t, data)
 *
 * an iterator function called while iterating through the ZFS
 * root. It accumulates into an array of file system handles that can
 * be used to derive info about those file systems.
 *
 * Note that as this function is called, we close all zhp handles that
 * are not going to be places into the cp_handles list. We don't want
 * to close the ones we are keeping, but all others would be leaked if
 * not closed here.
 */

static int
get_one_filesystem(zfs_handle_t *zhp, void *data)
{
	get_all_cbdata_t *cbp = data;
	zfs_type_t type = zfs_get_type(zhp);

	/*
	 * Interate over any nested datasets.
	 */
	if (type == ZFS_TYPE_FILESYSTEM &&
	    zfs_iter_filesystems(zhp, get_one_filesystem, data) != 0) {
		zfs_close(zhp);
		return (1);
	}

	/*
	 * Skip any datasets whose type does not match.
	 */
	if ((type & cbp->cb_types) == 0) {
		zfs_close(zhp);
		return (0);
	}

	if (cbp->cb_alloc == cbp->cb_used) {
		zfs_handle_t **handles;

		if (cbp->cb_alloc == 0)
			cbp->cb_alloc = 64;
		else
			cbp->cb_alloc *= 2;

		handles = (zfs_handle_t **)calloc(1,
		    cbp->cb_alloc * sizeof (void *));

		if (handles == NULL) {
			zfs_close(zhp);
			return (0);
		}
		if (cbp->cb_handles) {
			bcopy(cbp->cb_handles, handles,
			    cbp->cb_used * sizeof (void *));
			free(cbp->cb_handles);
		}

		cbp->cb_handles = handles;
	}

	cbp->cb_handles[cbp->cb_used++] = zhp;

	return (0);
}

/*
 * get_all_filesystems(zfs_handle_t ***fslist, size_t *count)
 *
 * iterate through all ZFS file systems starting at the root. Returns
 * a count and an array of handle pointers. Allocating is only done
 * once. The caller does not need to free since it will be done at
 * sa_zfs_fini() time.
 */

static void
get_all_filesystems(sa_handle_impl_t impl_handle,
    zfs_handle_t ***fslist, size_t *count)
{
	get_all_cbdata_t cb = { 0 };
	cb.cb_types = ZFS_TYPE_FILESYSTEM;

	if (impl_handle->zfs_list != NULL) {
		*fslist = impl_handle->zfs_list;
		*count = impl_handle->zfs_list_count;
		return;
	}

	(void) zfs_iter_root(impl_handle->zfs_libhandle,
	    get_one_filesystem, &cb);

	impl_handle->zfs_list = *fslist = cb.cb_handles;
	impl_handle->zfs_list_count = *count = cb.cb_used;
}

/*
 * mountpoint_compare(a, b)
 *
 * compares the mountpoint on two zfs file systems handles.
 * returns values following strcmp() model.
 */

static int
mountpoint_compare(const void *a, const void *b)
{
	zfs_handle_t **za = (zfs_handle_t **)a;
	zfs_handle_t **zb = (zfs_handle_t **)b;
	char mounta[MAXPATHLEN];
	char mountb[MAXPATHLEN];

	verify(zfs_prop_get(*za, ZFS_PROP_MOUNTPOINT, mounta,
	    sizeof (mounta), NULL, NULL, 0, B_FALSE) == 0);
	verify(zfs_prop_get(*zb, ZFS_PROP_MOUNTPOINT, mountb,
	    sizeof (mountb), NULL, NULL, 0, B_FALSE) == 0);

	return (strcmp(mounta, mountb));
}

/*
 * return legacy mountpoint.  Caller provides space for mountpoint and
 * dataset.
 */
int
get_legacy_mountpoint(const char *path, char *dataset, size_t dlen,
    char *mountpoint, size_t mlen)
{
	FILE *fp;
	struct mnttab entry;

	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		return (1);
	}

	while (getmntent(fp, &entry) == 0) {

		if (entry.mnt_fstype == NULL ||
		    strcmp(entry.mnt_fstype, MNTTYPE_ZFS) != 0)
			continue;

		if (strcmp(entry.mnt_mountp, path) == 0) {
			if (mlen > 0)
				(void) strlcpy(mountpoint, entry.mnt_mountp,
				    mlen);
			if (dlen > 0)
				(void) strlcpy(dataset, entry.mnt_special,
				    dlen);
			break;
		}
	}
	(void) fclose(fp);
	return (1);
}


/*
 * Verifies that a specific zfs filesystem handle meets the criteria necessary
 * to be used by libshare operations. See get_zfs_dataset.
 */
static char *
verify_zfs_handle(zfs_handle_t *hdl, const char *path, boolean_t search_mnttab)
{
	char mountpoint[ZFS_MAXPROPLEN];
	char canmount[ZFS_MAXPROPLEN] = { 0 };
	/* must have a mountpoint */
	if (zfs_prop_get(hdl, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
		/* no mountpoint */
		return (NULL);
	}

	/* mountpoint must be a path */
	if (strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) == 0 ||
	    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0) {
		/*
		 * Search mmttab for mountpoint and get dataset.
		 */

		if (search_mnttab == B_TRUE &&
		    get_legacy_mountpoint(path, mountpoint,
		    sizeof (mountpoint), NULL, 0) == 0) {
			return (strdup(mountpoint));
		}
		return (NULL);
	}

	/* canmount must be set */
	if (zfs_prop_get(hdl, ZFS_PROP_CANMOUNT, canmount,
	    sizeof (canmount), NULL, NULL, 0, B_FALSE) != 0 ||
	    strcmp(canmount, "off") == 0)
		return (NULL);

	/*
	 * have a mountable handle but want to skip those marked none
	 * and legacy
	 */
	if (strcmp(mountpoint, path) == 0) {
		return (strdup((char *)zfs_get_name(hdl)));
	}

	return (NULL);
}

/*
 * get_zfs_dataset(impl_handle, path)
 *
 * get the name of the ZFS dataset the path is equivalent to.  The
 * dataset name is used for get/set of ZFS properties since libzfs
 * requires a dataset to do a zfs_open().
 */

static char *
get_zfs_dataset(sa_handle_impl_t impl_handle, char *path,
    boolean_t search_mnttab)
{
	size_t i, count = 0;
	zfs_handle_t **zlist;
	char *cutpath;
	zfs_handle_t *handle_from_path;
	char *ret = NULL;

	/*
	 * First we optimistically assume that the mount path for the filesystem
	 * is the same as the name of the filesystem (minus some number of
	 * leading slashes). If this is true, then zfs_open should properly open
	 * the filesystem. We duplicate the error checking done later in the
	 * function for consistency. If anything fails, we resort to the
	 * (extremely slow) search of all the filesystems.
	 */
	cutpath = path + strspn(path, "/");

	assert(impl_handle->zfs_libhandle != NULL);
	libzfs_print_on_error(impl_handle->zfs_libhandle, B_FALSE);
	handle_from_path = zfs_open(impl_handle->zfs_libhandle, cutpath,
	    ZFS_TYPE_FILESYSTEM);
	libzfs_print_on_error(impl_handle->zfs_libhandle, B_TRUE);
	if (handle_from_path != NULL) {
		ret = verify_zfs_handle(handle_from_path, path, search_mnttab);
		zfs_close(handle_from_path);
		if (ret != NULL) {
			return (ret);
		}
	}
	/*
	 * Couldn't find a filesystem optimistically, check all the handles we
	 * can.
	 */
	get_all_filesystems(impl_handle, &zlist, &count);
	for (i = 0; i < count; i++) {
		assert(zlist[i]);
		if ((ret = verify_zfs_handle(zlist[i], path,
		    search_mnttab)) != NULL)
			return (ret);
	}

	/* Couldn't find a matching dataset */
	return (NULL);
}

/*
 * get_zfs_property(dataset, property)
 *
 * Get the file system property specified from the ZFS dataset.
 */

static char *
get_zfs_property(char *dataset, zfs_prop_t property)
{
	zfs_handle_t *handle = NULL;
	char shareopts[ZFS_MAXPROPLEN];
	libzfs_handle_t *libhandle;

	libhandle = libzfs_init();
	if (libhandle != NULL) {
		handle = zfs_open(libhandle, dataset, ZFS_TYPE_FILESYSTEM);
		if (handle != NULL) {
			if (zfs_prop_get(handle, property, shareopts,
			    sizeof (shareopts), NULL, NULL, 0,
			    B_FALSE) == 0) {
				zfs_close(handle);
				libzfs_fini(libhandle);
				return (strdup(shareopts));
			}
			zfs_close(handle);
		}
		libzfs_fini(libhandle);
	}
	return (NULL);
}

/*
 * sa_zfs_is_shared(handle, path)
 *
 * Check to see if the ZFS path provided has the sharenfs option set
 * or not.
 */

int
sa_zfs_is_shared(sa_handle_t sahandle, char *path)
{
	int ret = 0;
	char *dataset;
	zfs_handle_t *handle = NULL;
	char shareopts[ZFS_MAXPROPLEN];
	libzfs_handle_t *libhandle;

	dataset = get_zfs_dataset((sa_handle_t)sahandle, path, B_FALSE);
	if (dataset != NULL) {
		libhandle = libzfs_init();
		if (libhandle != NULL) {
			handle = zfs_open(libhandle, dataset,
			    ZFS_TYPE_FILESYSTEM);
			if (handle != NULL) {
				if (zfs_prop_get(handle, ZFS_PROP_SHARENFS,
				    shareopts, sizeof (shareopts), NULL, NULL,
				    0, B_FALSE) == 0 &&
				    strcmp(shareopts, "off") != 0) {
					ret = 1; /* it is shared */
				}
				zfs_close(handle);
			}
			libzfs_fini(libhandle);
		}
		free(dataset);
	}
	return (ret);
}

/*
 * find_or_create_group(handle, groupname, proto, *err)
 *
 * While walking the ZFS tree, we need to add shares to a defined
 * group. If the group doesn't exist, create it first, making sure it
 * is marked as a ZFS group.
 *
 * Note that all ZFS shares are in a subgroup of the top level group
 * called "zfs".
 */

static sa_group_t
find_or_create_group(sa_handle_t handle, char *groupname, char *proto, int *err)
{
	sa_group_t group;
	sa_optionset_t optionset;
	int ret = SA_OK;

	/*
	 * we check to see if the "zfs" group exists. Since this
	 * should be the top level group, we don't want the
	 * parent. This is to make sure the zfs group has been created
	 * and to created if it hasn't been.
	 */
	group = sa_get_group(handle, groupname);
	if (group == NULL) {
		group = sa_create_group(handle, groupname, &ret);

		/* make sure this is flagged as a ZFS group */
		if (group != NULL)
			ret = sa_set_group_attr(group, "zfs", "true");
	}
	if (group != NULL) {
		if (proto != NULL) {
			optionset = sa_get_optionset(group, proto);
			if (optionset == NULL)
				optionset = sa_create_optionset(group, proto);
		}
	}
	if (err != NULL)
		*err = ret;
	return (group);
}

/*
 * find_or_create_zfs_subgroup(groupname, optstring, *err)
 *
 * ZFS shares will be in a subgroup of the "zfs" master group.  This
 * function looks to see if the groupname exists and returns it if it
 * does or else creates a new one with the specified name and returns
 * that.  The "zfs" group will exist before we get here, but we make
 * sure just in case.
 *
 * err must be a valid pointer.
 */

static sa_group_t
find_or_create_zfs_subgroup(sa_handle_t handle, char *groupname, char *proto,
    char *optstring, int *err)
{
	sa_group_t group = NULL;
	sa_group_t zfs;
	char *name;
	char *options;

	/* start with the top-level "zfs" group */
	zfs = sa_get_group(handle, "zfs");
	*err = SA_OK;
	if (zfs != NULL) {
		for (group = sa_get_sub_group(zfs); group != NULL;
		    group = sa_get_next_group(group)) {
			name = sa_get_group_attr(group, "name");
			if (name != NULL && strcmp(name, groupname) == 0) {
				/* have the group so break out of here */
				sa_free_attr_string(name);
				break;
			}
			if (name != NULL)
				sa_free_attr_string(name);
		}

		if (group == NULL) {
			/*
			 * Need to create the sub-group since it doesn't exist
			 */
			group = _sa_create_zfs_group(zfs, groupname);
			if (group == NULL) {
				*err = SA_NO_MEMORY;
				return (NULL);
			}
			set_node_attr(group, "zfs", "true");
		}
		if (strcmp(optstring, "on") == 0)
			optstring = "rw";
		options = strdup(optstring);
		if (options != NULL) {
			*err = sa_parse_legacy_options(group, options,
			    proto);
			/* If no optionset, add one. */
			if (sa_get_optionset(group, proto) == NULL)
				(void) sa_create_optionset(group, proto);

			/*
			 * Do not forget to update an optionset of
			 * the parent group so that it contains
			 * all protocols its subgroups have.
			 */
			if (sa_get_optionset(zfs, proto) == NULL)
				(void) sa_create_optionset(zfs, proto);

			free(options);
		} else {
			*err = SA_NO_MEMORY;
		}
	}
	return (group);
}

/*
 * zfs_construct_resource(share, name, base, dataset)
 *
 * Add a resource to the share using name as a template. If name ==
 * NULL, then construct a name based on the dataset value.
 * name.
 */
static void
zfs_construct_resource(sa_share_t share, char *dataset)
{
	char buff[SA_MAX_RESOURCE_NAME + 1];
	int ret = SA_OK;

	(void) snprintf(buff, SA_MAX_RESOURCE_NAME, "%s", dataset);
	sa_fix_resource_name(buff);
	(void) sa_add_resource(share, buff, SA_SHARE_TRANSIENT, &ret);
}

/*
 * zfs_inherited(handle, source, sourcestr)
 *
 * handle case of inherited share{nfs,smb}. Pulled out of sa_get_zfs_shares
 * for readability.
 */
static int
zfs_inherited(sa_handle_t handle, sa_share_t share, char *sourcestr,
    char *shareopts, char *mountpoint, char *proto, char *dataset)
{
	int doshopt = 0;
	int err = SA_OK;
	sa_group_t group;
	sa_resource_t resource;
	uint64_t features;

	/*
	 * Need to find the "real" parent sub-group. It may not be
	 * mounted, but it was identified in the "sourcestr"
	 * variable. The real parent not mounted can occur if
	 * "canmount=off and sharenfs=on".
	 */
	group = find_or_create_zfs_subgroup(handle, sourcestr, proto,
	    shareopts, &doshopt);
	if (group != NULL) {
		/*
		 * We may need the first share for resource
		 * prototype. We only care about it if it has a
		 * resource that sets a prefix value.
		 */
		if (share == NULL)
			share = _sa_add_share(group, mountpoint,
			    SA_SHARE_TRANSIENT, &err,
			    (uint64_t)SA_FEATURE_NONE);
		/*
		 * some options may only be on shares. If the opt
		 * string contains one of those, we put it just on the
		 * share.
		 */
		if (share != NULL && doshopt == SA_PROP_SHARE_ONLY) {
			char *options;
			options = strdup(shareopts);
			if (options != NULL) {
				set_node_attr(share, "dataset", dataset);
				err = sa_parse_legacy_options(share, options,
				    proto);
				set_node_attr(share, "dataset", NULL);
				free(options);
			}
			if (sa_get_optionset(group, proto) == NULL)
				(void) sa_create_optionset(group, proto);
		}
		features = sa_proto_get_featureset(proto);
		if (share != NULL && features & SA_FEATURE_RESOURCE) {
			/*
			 * We have a share and the protocol requires
			 * that at least one resource exist (probably
			 * SMB). We need to make sure that there is at
			 * least one.
			 */
			resource = sa_get_share_resource(share, NULL);
			if (resource == NULL) {
				zfs_construct_resource(share, dataset);
			}
		}
	} else {
		err = SA_NO_MEMORY;
	}
	return (err);
}

/*
 * zfs_notinherited(group, share, mountpoint, shareopts, proto, dataset,
 *     grouperr)
 *
 * handle case where this is the top of a sub-group in ZFS. Pulled out
 * of sa_get_zfs_shares for readability. We need the grouperr from the
 * creation of the subgroup to know whether to add the public
 * property, etc. to the specific share.
 */
static int
zfs_notinherited(sa_group_t group, sa_share_t share, char *mountpoint,
    char *shareopts, char *proto, char *dataset, int grouperr)
{
	int err = SA_OK;
	sa_resource_t resource;
	uint64_t features;

	set_node_attr(group, "zfs", "true");
	if (share == NULL)
		share = _sa_add_share(group, mountpoint, SA_SHARE_TRANSIENT,
		    &err, (uint64_t)SA_FEATURE_NONE);

	if (err != SA_OK)
		return (err);

	if (strcmp(shareopts, "on") == 0)
		shareopts = "";
	if (shareopts != NULL) {
		char *options;
		if (grouperr == SA_PROP_SHARE_ONLY) {
			/*
			 * Some properties may only be on shares, but
			 * due to the ZFS sub-groups being artificial,
			 * we sometimes get this and have to deal with
			 * it. We do it by attempting to put it on the
			 * share.
			 */
			options = strdup(shareopts);
			if (options != NULL) {
				err = sa_parse_legacy_options(share,
				    options, proto);
				free(options);
			}
		}
		/* Unmark the share's changed state */
		set_node_attr(share, "changed", NULL);
	}
	features = sa_proto_get_featureset(proto);
	if (share != NULL && features & SA_FEATURE_RESOURCE) {
		/*
		 * We have a share and the protocol requires that at
		 * least one resource exist (probably SMB). We need to
		 * make sure that there is at least one.
		 */
		resource = sa_get_share_resource(share, NULL);
		if (resource == NULL) {
			zfs_construct_resource(share, dataset);
		}
	}
	return (err);
}

/*
 * zfs_grp_error(err)
 *
 * Print group create error, but only once. If err is 0 do the
 * print else don't.
 */

static void
zfs_grp_error(int err)
{
	if (err == 0) {
		/* only print error once */
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Cannot create ZFS subgroup during initialization:"
		    " %s\n"), sa_errorstr(SA_SYSTEM_ERR));
	}
}

/*
 * zfs_process_share(handle, share, mountpoint, proto, source,
 *     shareopts, sourcestr)
 *
 * Creates the subgroup, if necessary and adds shares, resources
 * and properties.
 */
int
sa_zfs_process_share(sa_handle_t handle, sa_group_t group, sa_share_t share,
    char *mountpoint, char *proto, zprop_source_t source, char *shareopts,
    char *sourcestr, char *dataset)
{
	int err = SA_OK;

	if (source & ZPROP_SRC_INHERITED) {
		err = zfs_inherited(handle, share, sourcestr, shareopts,
		    mountpoint, proto, dataset);
	} else {
		group = find_or_create_zfs_subgroup(handle, dataset, proto,
		    shareopts, &err);
		if (group == NULL) {
			static boolean_t reported_error = B_FALSE;
			/*
			 * There is a problem, but we can't do
			 * anything about it at this point so we issue
			 * a warning and move on.
			 */
			zfs_grp_error(reported_error);
			reported_error = B_TRUE;
		}
		set_node_attr(group, "zfs", "true");
		/*
		 * Add share with local opts via zfs_notinherited.
		 */
		err = zfs_notinherited(group, share, mountpoint, shareopts,
		    proto, dataset, err);
	}
	return (err);
}

/*
 * Walk the mnttab for all zfs mounts and determine which are
 * shared. Find or create the appropriate group/sub-group to contain
 * the shares.
 *
 * All shares are in a sub-group that will hold the properties. This
 * allows representing the inherited property model.
 *
 * One area of complication is if "sharenfs" is set at one level of
 * the directory tree and "sharesmb" is set at a different level, the
 * a sub-group must be formed at the lower level for both
 * protocols. That is the nature of the problem in CR 6667349.
 */
static int
sa_get_zfs_share_common(sa_handle_t handle, zfs_handle_t *fs_handle, char *path,
    sa_group_t zfsgroup)
{
	boolean_t smb, nfs;
	boolean_t smb_inherited, nfs_inherited;
	char nfsshareopts[ZFS_MAXPROPLEN];
	char smbshareopts[ZFS_MAXPROPLEN];
	char nfssourcestr[ZFS_MAXPROPLEN];
	char smbsourcestr[ZFS_MAXPROPLEN];
	char mountpoint[ZFS_MAXPROPLEN];
	int err = SA_OK;
	zprop_source_t source;
	sa_share_t share;
	char *dataset;

	source = ZPROP_SRC_ALL;
	/* If no mountpoint, skip. */
	if (zfs_prop_get(fs_handle, ZFS_PROP_MOUNTPOINT,
	    mountpoint, sizeof (mountpoint), NULL, NULL, 0,
	    B_FALSE) != 0)
		return (SA_SYSTEM_ERR);

	if (path != NULL)
		(void) strncpy(path, mountpoint, sizeof (mountpoint));
	/*
	 * zfs_get_name value must not be freed. It is just a
	 * pointer to a value in the handle.
	 */
	if ((dataset = (char *)zfs_get_name(fs_handle)) == NULL)
		return (SA_SYSTEM_ERR);

	/*
	 * only deal with "mounted" file systems since
	 * unmounted file systems can't actually be shared.
	 */

	if (!zfs_is_mounted(fs_handle, NULL))
		return (SA_SYSTEM_ERR);

	nfs = nfs_inherited = B_FALSE;

	if (zfs_prop_get(fs_handle, ZFS_PROP_SHARENFS, nfsshareopts,
	    sizeof (nfsshareopts), &source, nfssourcestr,
	    ZFS_MAXPROPLEN, B_FALSE) == 0 &&
	    strcmp(nfsshareopts, "off") != 0) {
		if (source & ZPROP_SRC_INHERITED)
			nfs_inherited = B_TRUE;
		else
			nfs = B_TRUE;
	}

	smb = smb_inherited = B_FALSE;
	if (zfs_prop_get(fs_handle, ZFS_PROP_SHARESMB, smbshareopts,
	    sizeof (smbshareopts), &source, smbsourcestr,
	    ZFS_MAXPROPLEN, B_FALSE) == 0 &&
	    strcmp(smbshareopts, "off") != 0) {
		if (source & ZPROP_SRC_INHERITED)
			smb_inherited = B_TRUE;
		else
			smb = B_TRUE;
	}

	/*
	 * If the mountpoint is already shared, it must be a
	 * non-ZFS share. We want to remove the share from its
	 * parent group and reshare it under ZFS.
	 */
	share = sa_find_share(handle, mountpoint);
	if (share != NULL &&
	    (nfs || smb || nfs_inherited || smb_inherited)) {
		err = sa_remove_share(share);
		share = NULL;
	}

	/*
	 * At this point, we have the information needed to
	 * determine what to do with the share.
	 *
	 * If smb or nfs is set, we have a new sub-group.
	 * If smb_inherit and/or nfs_inherit is set, then
	 * place on an existing sub-group. If both are set,
	 * the existing sub-group is the closest up the tree.
	 */
	if (nfs || smb) {
		/*
		 * Non-inherited is the straightforward
		 * case. sa_zfs_process_share handles it
		 * directly. Make sure that if the "other"
		 * protocol is inherited, that we treat it as
		 * non-inherited as well.
		 */
		if (nfs || nfs_inherited) {
			err = sa_zfs_process_share(handle, zfsgroup,
			    share, mountpoint, "nfs",
			    0, nfsshareopts,
			    nfssourcestr, dataset);
			share = sa_find_share(handle, mountpoint);
		}
		if (smb || smb_inherited) {
			err = sa_zfs_process_share(handle, zfsgroup,
			    share, mountpoint, "smb",
			    0, smbshareopts,
			    smbsourcestr, dataset);
		}
	} else if (nfs_inherited || smb_inherited) {
		char *grpdataset;
		/*
		 * If we only have inherited groups, it is
		 * important to find the closer of the two if
		 * the protocols are set at different
		 * levels. The closest sub-group is the one we
		 * want to work with.
		 */
		if (nfs_inherited && smb_inherited) {
			if (strcmp(nfssourcestr, smbsourcestr) <= 0)
				grpdataset = nfssourcestr;
			else
				grpdataset = smbsourcestr;
		} else if (nfs_inherited) {
			grpdataset = nfssourcestr;
		} else if (smb_inherited) {
			grpdataset = smbsourcestr;
		}
		if (nfs_inherited) {
			err = sa_zfs_process_share(handle, zfsgroup,
			    share, mountpoint, "nfs",
			    ZPROP_SRC_INHERITED, nfsshareopts,
			    grpdataset, dataset);
			share = sa_find_share(handle, mountpoint);
		}
		if (smb_inherited) {
			err = sa_zfs_process_share(handle, zfsgroup,
			    share, mountpoint, "smb",
			    ZPROP_SRC_INHERITED, smbshareopts,
			    grpdataset, dataset);
		}
	}
	return (err);
}

/*
 * Handles preparing generic objects such as the libzfs handle and group for
 * sa_get_one_zfs_share, sa_get_zfs_share_for_name, and sa_get_zfs_shares.
 */
static int
prep_zfs_handle_and_group(sa_handle_t handle, char *groupname,
    libzfs_handle_t **zfs_libhandle, sa_group_t *zfsgroup, int *err)
{
	/*
	 * If we can't access libzfs, don't bother doing anything.
	 */
	*zfs_libhandle = ((sa_handle_impl_t)handle)->zfs_libhandle;
	if (*zfs_libhandle == NULL)
		return (SA_SYSTEM_ERR);

	*zfsgroup = find_or_create_group(handle, groupname, NULL, err);
	return (SA_OK);
}

/*
 * The O.G. zfs share preparation function. This initializes all zfs shares for
 * use with libshare.
 */
int
sa_get_zfs_shares(sa_handle_t handle, char *groupname)
{
	sa_group_t zfsgroup;
	zfs_handle_t **zlist;
	size_t count = 0;
	libzfs_handle_t *zfs_libhandle;
	int err;

	if ((err = prep_zfs_handle_and_group(handle, groupname, &zfs_libhandle,
	    &zfsgroup, &err)) != SA_OK) {
		return (err);
	}
	/* Not an error, this could be a legacy condition */
	if (zfsgroup == NULL)
		return (SA_OK);

	/*
	 * need to walk the mounted ZFS pools and datasets to
	 * find shares that are possible.
	 */
	get_all_filesystems((sa_handle_impl_t)handle, &zlist, &count);
	qsort(zlist, count, sizeof (void *), mountpoint_compare);

	for (int i = 0; i < count; i++) {
		err = sa_get_zfs_share_common(handle, zlist[i], NULL, zfsgroup);
	}
	/*
	 * Don't need to free the "zlist" variable since it is only a
	 * pointer to a cached value that will be freed when
	 * sa_fini() is called.
	 */
	return (err);
}

/*
 * Initializes only the handles specified in the sharearg for use with libshare.
 * This is used as a performance optimization relative to sa_get_zfs_shares.
 */
int
sa_get_one_zfs_share(sa_handle_t handle, char *groupname,
    sa_init_selective_arg_t *sharearg, char ***paths, size_t *paths_len)
{
	sa_group_t zfsgroup;
	libzfs_handle_t *zfs_libhandle;
	int err;

	if ((err = prep_zfs_handle_and_group(handle, groupname, &zfs_libhandle,
	    &zfsgroup, &err)) != SA_OK) {
		return (err);
	}
	/* Not an error, this could be a legacy condition */
	if (zfsgroup == NULL)
		return (SA_OK);

	*paths_len = sharearg->zhandle_len;
	*paths = malloc(sizeof (char *) * (*paths_len));
	for (int i = 0; i < sharearg->zhandle_len; ++i) {
		zfs_handle_t *fs_handle =
		    ((zfs_handle_t **)(sharearg->zhandle_arr))[i];
		if (fs_handle == NULL) {
			return (SA_SYSTEM_ERR);
		}
		(*paths)[i] = malloc(sizeof (char) * ZFS_MAXPROPLEN);
		err |= sa_get_zfs_share_common(handle, fs_handle, (*paths)[i],
		    zfsgroup);
	}
	return (err);
}

/*
 * Initializes only the share with the specified sharename for use with
 * libshare.
 */
int
sa_get_zfs_share_for_name(sa_handle_t handle, char *groupname,
    const char *sharename, char *outpath)
{
	sa_group_t zfsgroup;
	libzfs_handle_t *zfs_libhandle;
	int err;

	if ((err = prep_zfs_handle_and_group(handle, groupname, &zfs_libhandle,
	    &zfsgroup, &err)) != SA_OK) {
		return (err);
	}
	/* Not an error, this could be a legacy condition */
	if (zfsgroup == NULL)
		return (SA_OK);

	zfs_handle_t *fs_handle = zfs_open(zfs_libhandle,
	    sharename + strspn(sharename, "/"), ZFS_TYPE_DATASET);
	if (fs_handle == NULL)
		return (SA_SYSTEM_ERR);

	err = sa_get_zfs_share_common(handle, fs_handle, outpath, zfsgroup);
	zfs_close(fs_handle);
	return (err);
}



#define	COMMAND		"/usr/sbin/zfs"

/*
 * sa_zfs_set_sharenfs(group, path, on)
 *
 * Update the "sharenfs" property on the path. If on is true, then set
 * to the properties on the group or "on" if no properties are
 * defined. Set to "off" if on is false.
 */

int
sa_zfs_set_sharenfs(sa_group_t group, char *path, int on)
{
	int ret = SA_NOT_IMPLEMENTED;
	char *command;

	command = malloc(ZFS_MAXPROPLEN * 2);
	if (command != NULL) {
		char *opts = NULL;
		char *dataset = NULL;
		FILE *pfile;
		sa_handle_impl_t impl_handle;
		/* for now, NFS is always available for "zfs" */
		if (on) {
			opts = sa_proto_legacy_format("nfs", group, 1);
			if (opts != NULL && strlen(opts) == 0) {
				free(opts);
				opts = strdup("on");
			}
		}

		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		assert(impl_handle != NULL);
		if (impl_handle != NULL)
			dataset = get_zfs_dataset(impl_handle, path, B_FALSE);
		else
			ret = SA_SYSTEM_ERR;

		if (dataset != NULL) {
			(void) snprintf(command, ZFS_MAXPROPLEN * 2,
			    "%s set sharenfs=\"%s\" %s", COMMAND,
			    opts != NULL ? opts : "off", dataset);
			pfile = popen(command, "r");
			if (pfile != NULL) {
				ret = pclose(pfile);
				if (ret != 0)
					ret = SA_SYSTEM_ERR;
			}
		}
		if (opts != NULL)
			free(opts);
		if (dataset != NULL)
			free(dataset);
		free(command);
	}
	return (ret);
}

/*
 * add_resources(share, opt)
 *
 * Add resource properties to those in "opt".  Resources are prefixed
 * with name=resourcename.
 */
static char *
add_resources(sa_share_t share, char *opt)
{
	char *newopt = NULL;
	char *propstr;
	sa_resource_t resource;

	newopt = strdup(opt);
	if (newopt == NULL)
		return (newopt);

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL;
	    resource = sa_get_next_resource(resource)) {
		char *name;
		size_t size;

		name = sa_get_resource_attr(resource, "name");
		if (name == NULL) {
			free(newopt);
			return (NULL);
		}
		size = strlen(name) + strlen(opt) + sizeof ("name=") + 1;
		newopt = calloc(1, size);
		if (newopt != NULL)
			(void) snprintf(newopt, size, "%s,name=%s", opt, name);
		sa_free_attr_string(name);
		free(opt);
		opt = newopt;
		propstr = sa_proto_legacy_format("smb", resource, 0);
		if (propstr == NULL) {
			free(opt);
			return (NULL);
		}
		size = strlen(propstr) + strlen(opt) + 2;
		newopt = calloc(1, size);
		if (newopt != NULL)
			(void) snprintf(newopt, size, "%s,%s", opt, propstr);
		free(opt);
		opt = newopt;
	}
	return (opt);
}

/*
 * sa_zfs_set_sharesmb(group, path, on)
 *
 * Update the "sharesmb" property on the path. If on is true, then set
 * to the properties on the group or "on" if no properties are
 * defined. Set to "off" if on is false.
 */

int
sa_zfs_set_sharesmb(sa_group_t group, char *path, int on)
{
	int ret = SA_NOT_IMPLEMENTED;
	char *command;
	sa_share_t share;

	/* In case SMB not enabled */
	if (sa_get_optionset(group, "smb") == NULL)
		return (SA_NOT_SUPPORTED);

	command = malloc(ZFS_MAXPROPLEN * 2);
	if (command != NULL) {
		char *opts = NULL;
		char *dataset = NULL;
		FILE *pfile;
		sa_handle_impl_t impl_handle;

		if (on) {
			char *newopt;

			share = sa_get_share(group, NULL);
			opts = sa_proto_legacy_format("smb", share, 1);
			if (opts != NULL && strlen(opts) == 0) {
				free(opts);
				opts = strdup("on");
			}
			newopt = add_resources(opts, share);
			free(opts);
			opts = newopt;
		}

		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		assert(impl_handle != NULL);
		if (impl_handle != NULL)
			dataset = get_zfs_dataset(impl_handle, path, B_FALSE);
		else
			ret = SA_SYSTEM_ERR;

		if (dataset != NULL) {
			(void) snprintf(command, ZFS_MAXPROPLEN * 2,
			    "echo %s set sharesmb=\"%s\" %s", COMMAND,
			    opts != NULL ? opts : "off", dataset);
			pfile = popen(command, "r");
			if (pfile != NULL) {
				ret = pclose(pfile);
				if (ret != 0)
					ret = SA_SYSTEM_ERR;
			}
		}
		if (opts != NULL)
			free(opts);
		if (dataset != NULL)
			free(dataset);
		free(command);
	}
	return (ret);
}

/*
 * sa_zfs_update(group)
 *
 * call back to ZFS to update the share if necessary.
 * Don't do it if it isn't a real change.
 */
int
sa_zfs_update(sa_group_t group)
{
	sa_optionset_t protopt;
	sa_group_t parent;
	char *command;
	char *optstring;
	int ret = SA_OK;
	int doupdate = 0;
	FILE *pfile;

	if (sa_is_share(group))
		parent = sa_get_parent_group(group);
	else
		parent = group;

	if (parent != NULL) {
		command = malloc(ZFS_MAXPROPLEN * 2);
		if (command == NULL)
			return (SA_NO_MEMORY);

		*command = '\0';
		for (protopt = sa_get_optionset(parent, NULL); protopt != NULL;
		    protopt = sa_get_next_optionset(protopt)) {

			char *proto = sa_get_optionset_attr(protopt, "type");
			char *path;
			char *dataset = NULL;
			char *zfsopts = NULL;

			if (sa_is_share(group)) {
				path = sa_get_share_attr((sa_share_t)group,
				    "path");
				if (path != NULL) {
					sa_handle_impl_t impl_handle;

					impl_handle = sa_find_group_handle(
					    group);
					if (impl_handle != NULL)
						dataset = get_zfs_dataset(
						    impl_handle, path, B_FALSE);
					else
						ret = SA_SYSTEM_ERR;

					sa_free_attr_string(path);
				}
			} else {
				dataset = sa_get_group_attr(group, "name");
			}
			/* update only when there is an optstring found */
			doupdate = 0;
			if (proto != NULL && dataset != NULL) {
				optstring = sa_proto_legacy_format(proto,
				    group, 1);
				zfsopts = get_zfs_property(dataset,
				    ZFS_PROP_SHARENFS);

				if (optstring != NULL && zfsopts != NULL) {
					if (strcmp(optstring, zfsopts) != 0)
						doupdate++;
				}
				if (doupdate) {
					if (optstring != NULL &&
					    strlen(optstring) > 0) {
						(void) snprintf(command,
						    ZFS_MAXPROPLEN * 2,
						    "%s set share%s=%s %s",
						    COMMAND, proto,
						    optstring, dataset);
					} else {
						(void) snprintf(command,
						    ZFS_MAXPROPLEN * 2,
						    "%s set share%s=on %s",
						    COMMAND, proto,
						    dataset);
					}
					pfile = popen(command, "r");
					if (pfile != NULL)
						ret = pclose(pfile);
					switch (ret) {
					default:
					case 1:
						ret = SA_SYSTEM_ERR;
						break;
					case 2:
						ret = SA_SYNTAX_ERR;
						break;
					case 0:
						break;
					}
				}
				if (optstring != NULL)
					free(optstring);
				if (zfsopts != NULL)
					free(zfsopts);
			}
			if (proto != NULL)
				sa_free_attr_string(proto);
			if (dataset != NULL)
				free(dataset);
		}
		free(command);
	}
	return (ret);
}

/*
 * sa_group_is_zfs(group)
 *
 * Given the group, determine if the zfs attribute is set.
 */

int
sa_group_is_zfs(sa_group_t group)
{
	char *zfs;
	int ret = 0;

	zfs = sa_get_group_attr(group, "zfs");
	if (zfs != NULL) {
		ret = 1;
		sa_free_attr_string(zfs);
	}
	return (ret);
}

/*
 * sa_path_is_zfs(path)
 *
 * Check to see if the file system path represents is of type "zfs".
 */

int
sa_path_is_zfs(char *path)
{
	char *fstype;
	int ret = 0;

	fstype = sa_fstype(path);
	if (fstype != NULL && strcmp(fstype, "zfs") == 0)
		ret = 1;
	if (fstype != NULL)
		sa_free_fstype(fstype);
	return (ret);
}

int
sa_sharetab_fill_zfs(sa_share_t share, share_t *sh, char *proto)
{
	char *path;

	/* Make sure path is valid */

	path = sa_get_share_attr(share, "path");
	if (path != NULL) {
		(void) memset(sh, 0, sizeof (sh));
		(void) sa_fillshare(share, proto, sh);
		sa_free_attr_string(path);
		return (0);
	} else
		return (1);
}

#define	SMAX(i, j)	\
	if ((j) > (i)) { \
		(i) = (j); \
	}

int
sa_share_zfs(sa_share_t share, sa_resource_t resource, char *path, share_t *sh,
    void *exportdata, zfs_share_op_t operation)
{
	libzfs_handle_t *libhandle;
	sa_group_t group;
	sa_handle_t sahandle;
	char *dataset;
	int err = EINVAL;
	int i, j;
	char newpath[MAXPATHLEN];
	char *pathp;

	/*
	 * First find the dataset name
	 */
	if ((group = sa_get_parent_group(share)) == NULL)  {
		return (EINVAL);
	}
	if ((sahandle = sa_find_group_handle(group)) == NULL) {
		return (EINVAL);
	}

	/*
	 * If get_zfs_dataset fails, see if it is a subdirectory
	 */

	pathp = path;
	while ((dataset = get_zfs_dataset(sahandle, pathp, B_TRUE)) == NULL) {
		char *p;

		if (pathp == path) {
			(void) strlcpy(newpath, path, sizeof (newpath));
			pathp = newpath;
		}

		/*
		 * Make sure only one leading '/' This condition came
		 * about when using HAStoragePlus which insisted on
		 * putting an extra leading '/' in the ZFS path
		 * name. The problem is fixed in other areas, but this
		 * will catch any other ways that a double slash might
		 * get introduced.
		 */
		while (*pathp == '/' && *(pathp + 1) == '/')
			pathp++;

		/*
		 * chop off part of path, but if we are at root then
		 * make sure path is a /
		 */
		if ((strlen(pathp) > 1) && (p = strrchr(pathp, '/'))) {
			if (pathp == p) {
				*(p + 1) = '\0';  /* skip over /, root case */
			} else {
				*p = '\0';
			}
		} else {
			return (EINVAL);
		}
	}

	libhandle = libzfs_init();
	if (libhandle != NULL) {
		char *resource_name;

		i = (sh->sh_path ? strlen(sh->sh_path) : 0);
		sh->sh_size = i;

		j = (sh->sh_res ? strlen(sh->sh_res) : 0);
		sh->sh_size += j;
		SMAX(i, j);

		j = (sh->sh_fstype ? strlen(sh->sh_fstype) : 0);
		sh->sh_size += j;
		SMAX(i, j);

		j = (sh->sh_opts ? strlen(sh->sh_opts) : 0);
		sh->sh_size += j;
		SMAX(i, j);

		j = (sh->sh_descr ? strlen(sh->sh_descr) : 0);
		sh->sh_size += j;
		SMAX(i, j);

		resource_name = sa_get_resource_attr(resource, "name");

		err = zfs_deleg_share_nfs(libhandle, dataset, path,
		    resource_name, exportdata, sh, i, operation);
		if (err == SA_OK)
			sa_update_sharetab_ts(sahandle);
		else
			err = errno;
		if (resource_name)
			sa_free_attr_string(resource_name);

		libzfs_fini(libhandle);
	}
	free(dataset);
	return (err);
}

/*
 * sa_get_zfs_handle(handle)
 *
 * Given an sa_handle_t, return the libzfs_handle_t *. This is only
 * used internally by libzfs. Needed in order to avoid including
 * libshare_impl.h in libzfs.
 */

libzfs_handle_t *
sa_get_zfs_handle(sa_handle_t handle)
{
	sa_handle_impl_t implhandle = (sa_handle_impl_t)handle;

	return (implhandle->zfs_libhandle);
}

/*
 * sa_get_zfs_info(libzfs, path, mountpoint, dataset)
 *
 * Find the ZFS dataset and mountpoint for a given path
 */
int
sa_zfs_get_info(libzfs_handle_t *libzfs, char *path, char *mountpointp,
    char *datasetp)
{
	get_all_cbdata_t cb = { 0 };
	int i;
	char mountpoint[ZFS_MAXPROPLEN];
	char dataset[ZFS_MAXPROPLEN];
	char canmount[ZFS_MAXPROPLEN];
	char *dp;
	int count;
	int ret = 0;

	cb.cb_types = ZFS_TYPE_FILESYSTEM;

	if (libzfs == NULL)
		return (0);

	(void) zfs_iter_root(libzfs, get_one_filesystem, &cb);
	count = cb.cb_used;

	qsort(cb.cb_handles, count, sizeof (void *), mountpoint_compare);
	for (i = 0; i < count; i++) {
		/* must have a mountpoint */
		if (zfs_prop_get(cb.cb_handles[i], ZFS_PROP_MOUNTPOINT,
		    mountpoint, sizeof (mountpoint),
		    NULL, NULL, 0, B_FALSE) != 0) {
			/* no mountpoint */
			continue;
		}

		/* mountpoint must be a path */
		if (strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) == 0 ||
		    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0) {
			/*
			 * Search mmttab for mountpoint
			 */

			if (get_legacy_mountpoint(path, dataset,
			    ZFS_MAXPROPLEN, mountpoint,
			    ZFS_MAXPROPLEN) == 0) {
				ret = 1;
				break;
			}
			continue;
		}

		/* canmount must be set */
		canmount[0] = '\0';
		if (zfs_prop_get(cb.cb_handles[i], ZFS_PROP_CANMOUNT, canmount,
		    sizeof (canmount), NULL, NULL, 0, B_FALSE) != 0 ||
		    strcmp(canmount, "off") == 0)
			continue;

		/*
		 * have a mountable handle but want to skip those marked none
		 * and legacy
		 */
		if (strcmp(mountpoint, path) == 0) {
			dp = (char *)zfs_get_name(cb.cb_handles[i]);
			if (dp != NULL) {
				if (datasetp != NULL)
					(void) strcpy(datasetp, dp);
				if (mountpointp != NULL)
					(void) strcpy(mountpointp, mountpoint);
				ret = 1;
			}
			break;
		}

	}

	return (ret);
}

/*
 * This method builds values for "sharesmb" property from the
 * nvlist argument. The values are returned in sharesmb_val variable.
 */
static int
sa_zfs_sprintf_new_prop(nvlist_t *nvl, char *sharesmb_val)
{
	char cur_val[MAXPATHLEN];
	char *name, *val;
	nvpair_t *cur;
	int err = 0;

	cur = nvlist_next_nvpair(nvl, NULL);
	while (cur != NULL) {
		name = nvpair_name(cur);
		err = nvpair_value_string(cur, &val);
		if ((err != 0) || (name == NULL) || (val == NULL))
			return (-1);

		(void) snprintf(cur_val, MAXPATHLEN, "%s=%s,", name, val);
		(void) strlcat(sharesmb_val, cur_val, MAXPATHLEN);

		cur = nvlist_next_nvpair(nvl, cur);
	}

	return (0);
}

/*
 * This method builds values for "sharesmb" property from values
 * already existing on the share. The properties set via sa_zfs_sprint_new_prop
 * method are passed in sharesmb_val. If a existing property is already
 * set via sa_zfs_sprint_new_prop method, then they are not appended
 * to the sharesmb_val string. The returned sharesmb_val string is a combination
 * of new and existing values for 'sharesmb' property.
 */
static int
sa_zfs_sprintf_existing_prop(zfs_handle_t *handle, char *sharesmb_val)
{
	char shareopts[ZFS_MAXPROPLEN], cur_val[MAXPATHLEN];
	char *token, *last, *value;

	if (zfs_prop_get(handle, ZFS_PROP_SHARESMB, shareopts,
	    sizeof (shareopts), NULL, NULL, 0, B_FALSE) != 0)
		return (-1);

	if (strstr(shareopts, "=") == NULL)
		return (0);

	for (token = strtok_r(shareopts, ",", &last); token != NULL;
	    token = strtok_r(NULL, ",", &last)) {
		value = strchr(token, '=');
		if (value == NULL)
			return (-1);
		*value++ = '\0';

		(void) snprintf(cur_val, MAXPATHLEN, "%s=", token);
		if (strstr(sharesmb_val, cur_val) == NULL) {
			(void) strlcat(cur_val, value, MAXPATHLEN);
			(void) strlcat(cur_val, ",", MAXPATHLEN);
			(void) strlcat(sharesmb_val, cur_val, MAXPATHLEN);
		}
	}

	return (0);
}

/*
 * Sets the share properties on a ZFS share. For now, this method sets only
 * the "sharesmb" property.
 *
 * This method includes building a comma seperated name-value string to be
 * set on the "sharesmb" property of a ZFS share. This name-value string is
 * build in 2 steps:
 *    - New property values given as name-value pair are set first.
 *    - Existing optionset properties, which are not part of the new properties
 *	passed in step 1, are appended to the newly set properties.
 */
int
sa_zfs_setprop(sa_handle_t handle, char *path, nvlist_t *nvl)
{
	zfs_handle_t *z_fs;
	libzfs_handle_t *z_lib;
	char sharesmb_val[MAXPATHLEN];
	char *dataset, *lastcomma;

	if (nvlist_empty(nvl))
		return (0);

	if ((handle == NULL) || (path == NULL))
		return (-1);

	if ((dataset = get_zfs_dataset(handle, path, B_FALSE)) == NULL)
		return (-1);

	if ((z_lib = libzfs_init()) == NULL) {
		free(dataset);
		return (-1);
	}

	z_fs = zfs_open(z_lib, dataset, ZFS_TYPE_DATASET);
	if (z_fs == NULL) {
		free(dataset);
		libzfs_fini(z_lib);
		return (-1);
	}

	bzero(sharesmb_val, MAXPATHLEN);
	if (sa_zfs_sprintf_new_prop(nvl, sharesmb_val) != 0) {
		free(dataset);
		zfs_close(z_fs);
		libzfs_fini(z_lib);
		return (-1);
	}

	if (sa_zfs_sprintf_existing_prop(z_fs, sharesmb_val) != 0) {
		free(dataset);
		zfs_close(z_fs);
		libzfs_fini(z_lib);
		return (-1);
	}

	lastcomma = strrchr(sharesmb_val, ',');
	if ((lastcomma != NULL) && (lastcomma[1] == '\0'))
		*lastcomma = '\0';

	(void) zfs_prop_set(z_fs, zfs_prop_to_name(ZFS_PROP_SHARESMB),
	    sharesmb_val);
	free(dataset);
	zfs_close(z_fs);
	libzfs_fini(z_lib);

	return (0);
}
