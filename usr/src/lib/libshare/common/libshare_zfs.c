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

#include "libfsmgt.h"
#include <libzfs.h>
#include <string.h>
#include <libshare.h>
#include "libshare_impl.h"

extern sa_share_t _sa_add_share(sa_group_t, char *, int, int *);
extern sa_group_t _sa_create_zfs_group(sa_group_t, char *);
extern char *sa_fstype(char *);
extern void set_node_attr(void *, char *, char *);
extern int sa_is_share(void *);
/*
 * File system specific code for ZFS
 */

/*
 * get_zfs_dataset(path)
 *
 * get the name of the ZFS dataset the path is equivalent to.  The
 * dataset name is used for get/set of ZFS properties since libzfs
 * requires a dataset to do a zfs_open().
 */

static char *
get_zfs_dataset(char *path)
{
	fs_mntlist_t *list;
	fs_mntlist_t *cur;
	int err;
	char *dataset = NULL;

	list = fs_get_filtered_mount_list(NULL, NULL, "zfs", NULL,
					    NULL, 0, &err);
	for (cur = list; cur != NULL; cur = cur->next) {
	    if (strcmp(path, cur->mountp) == 0 ||
		strncmp(path, cur->mountp, strlen(cur->mountp)) == 0) {
		/*
		 * we want the longest resource so keep trying. This
		 * check avoids dropping out on a partial match. ZFS
		 * resources are ordered when mounted in order to
		 * ensure inheritence of properties.
		 */
		dataset = cur->resource;
	    }
	}
	if (dataset != NULL) {
	    dataset = strdup(dataset);
	}
	fs_free_mount_list(list);
	return (dataset);
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
				FALSE) == 0) {
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
 * sa_zfs_is_shared(path)
 *
 * Check to see if the ZFS path provided has the sharenfs option set
 * or not.
 */

int
sa_zfs_is_shared(char *path)
{
	int ret = 0;
	char *dataset;
	zfs_handle_t *handle = NULL;
	char shareopts[ZFS_MAXPROPLEN];
	libzfs_handle_t *libhandle;

	dataset = get_zfs_dataset(path);
	if (dataset != NULL) {
	    libhandle = libzfs_init();
	    if (libhandle != NULL) {
		handle = zfs_open(libhandle, dataset, ZFS_TYPE_FILESYSTEM);
		if (handle != NULL) {
		    if (zfs_prop_get(handle, ZFS_PROP_SHARENFS, shareopts,
					sizeof (shareopts), NULL, NULL, 0,
					FALSE) == 0 &&
			strcmp(shareopts, "off") != 0)
			ret = 1; /* it is shared */
		    zfs_close(handle);
		}
		libzfs_fini(libhandle);
	    }
	    free(dataset);
	}
	return (ret);
}

/*
 * find_or_create_group(groupname, proto, *err)
 *
 * While walking the ZFS tree, we need to add shares to a defined
 * group. If the group doesn't exist, create it first, making sure it
 * is marked as a ZFS group.
 *
 * Not that all ZFS shares are in a subgroup of the top level group
 * "zfs".
 */

static sa_group_t
find_or_create_group(char *groupname, char *proto, int *err)
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
	group = sa_get_group(groupname);
	if (group == NULL) {
	    group = sa_create_group(groupname, &ret);
	    if (group != NULL)
		ret = sa_set_group_attr(group, "zfs", "true");
	}
	if (group != NULL) {
	    if (proto != NULL) {
		optionset = sa_get_optionset(group, proto);
		if (optionset == NULL) {
		    optionset = sa_create_optionset(group, proto);
		} else {
		    char **protolist;
		    int numprotos, i;
		    numprotos = sa_get_protocols(&protolist);
		    for (i = 0; i < numprotos; i++) {
			optionset = sa_create_optionset(group, protolist[i]);
		    }
		    if (protolist != NULL)
			free(protolist);
		}
	    }
	}
	if (err != NULL)
	    *err = ret;
	return (group);
}

/*
 * sa_get_zfs_shares(groupname)
 *
 * Walk the mnttab for all zfs mounts and determine which are
 * shared. Find or create the appropriate group/sub-group to contain
 * the shares.
 *
 * All shares are in a sub-group that will hold the properties. This
 * allows representing the inherited property model.
 */

int
sa_get_zfs_shares(char *groupname)
{
	sa_group_t group;
	sa_group_t zfsgroup;
	int legacy = 0;
	int err;
	fs_mntlist_t *list;
	fs_mntlist_t *cur;
	zfs_handle_t *handle = NULL;
	char shareopts[ZFS_MAXPROPLEN];
	sa_share_t share;
	zfs_source_t source;
	char sourcestr[ZFS_MAXPROPLEN];
	libzfs_handle_t *libhandle;

	/*
	 * if we can't access libzfs, don't bother doing anything.
	 */
	libhandle = libzfs_init();
	if (libhandle == NULL)
	    return (SA_SYSTEM_ERR);

	zfsgroup = find_or_create_group(groupname, "nfs", &err);
	if (zfsgroup != NULL) {
		/*
		 * need to walk the mounted ZFS pools and datasets to
		 * find shares that are possible.
		 */
	    list = fs_get_filtered_mount_list(NULL, NULL, "zfs", NULL,
					    NULL, 0, &err);
	    group = zfsgroup;
	    for (cur = list; cur != NULL; cur = cur->next) {
		handle = zfs_open(libhandle, cur->resource,
				    ZFS_TYPE_FILESYSTEM);
		if (handle != NULL) {
		    source = ZFS_SRC_ALL;
		    if (zfs_prop_get(handle, ZFS_PROP_SHARENFS, shareopts,
					sizeof (shareopts), &source, sourcestr,
					ZFS_MAXPROPLEN,
					FALSE) == 0 &&
			strcmp(shareopts, "off") != 0) {
			/* it is shared so add to list */
			share = sa_find_share(cur->mountp);
			err = SA_OK;
			if (share != NULL) {
				/*
				 * A zfs file system had been shared
				 * through tradiditional methods
				 * (share/dfstab or added to a non-zfs
				 * group.  Now it has been added to a
				 * ZFS group via the zfs
				 * command. Remove from previous
				 * config and setup with current
				 * options.
				 */
			    err = sa_remove_share(share);
			    share = NULL;
			}
			if (err == SA_OK) {
			    if (source & ZFS_SRC_INHERITED) {
				share = _sa_add_share(group, cur->mountp,
							SA_SHARE_TRANSIENT,
							&err);
			    } else {
				group = _sa_create_zfs_group(zfsgroup,
								cur->resource);
				set_node_attr(group, "zfs", "true");
				share = _sa_add_share(group, cur->mountp,
							SA_SHARE_TRANSIENT,
							&err);
				if (err == SA_OK) {
				    char *options;
				    if (strcmp(shareopts, "on") != 0) {
					options = strdup(shareopts);
					if (options != NULL) {
					    err = sa_parse_legacy_options(group,
									options,
									"nfs");
					    free(options);
					}
					/* unmark the share's changed state */
					set_node_attr(share, "changed", NULL);
				    }
				}
			    }
			}
		    }
		}
	    }
	    if (list != NULL)
		fs_free_mount_list(list);
	}
	if (libhandle != NULL)
	    libzfs_fini(libhandle);
	return (legacy);
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
	    char *dataset;
	    FILE *pfile;
	    /* for now, NFS is always available for "zfs" */
	    if (on) {
		opts = sa_proto_legacy_format("nfs", group, 1);
		if (opts != NULL && strlen(opts) == 0) {
		    free(opts);
		    opts = strdup("on");
		}
	    }
	    dataset = get_zfs_dataset(path);
	    if (dataset != NULL) {
		(void) snprintf(command, ZFS_MAXPROPLEN * 2,
				"%s set sharenfs=\"%s\" %s", COMMAND,
				opts != NULL ? opts : "off",
				dataset);
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
		    path = sa_get_share_attr((sa_share_t)group, "path");
		    if (path != NULL) {
			dataset = get_zfs_dataset(path);
			sa_free_attr_string(path);
		    }
		} else {
		    dataset = sa_get_group_attr(group, "name");
		}
		/* update only when there is an optstring found */
		doupdate = 0;
		if (proto != NULL && dataset != NULL) {
		    optstring = sa_proto_legacy_format(proto, group, 1);
		    zfsopts = get_zfs_property(dataset, ZFS_PROP_SHARENFS);

		    if (optstring != NULL && zfsopts != NULL) {
			if (strcmp(optstring, zfsopts) != 0)
			    doupdate++;
		    }

		    if (doupdate) {
			if (optstring != NULL && strlen(optstring) > 0) {
			    (void) snprintf(command, ZFS_MAXPROPLEN * 2,
					    "%s set sharenfs=%s %s", COMMAND,
					    optstring, dataset);
			} else {
			    (void) snprintf(command, ZFS_MAXPROPLEN * 2,
					    "%s set sharenfs=on %s", COMMAND,
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
		    if (optstring != NULL) {
			free(optstring);
		    }
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
	if (fstype != NULL && strcmp(fstype, "zfs") == 0) {
	    ret = 1;
	}
	if (fstype != NULL)
	    sa_free_fstype(fstype);
	return (ret);
}
