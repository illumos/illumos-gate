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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the functions used to support the ZFS integration
 * with zones.  This includes validation (e.g. zonecfg dataset), cloning,
 * file system creation and destruction.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <libgen.h>
#include <libzonecfg.h>
#include <sys/mnttab.h>
#include <libzfs.h>
#include <sys/mntent.h>

#include "zoneadm.h"

libzfs_handle_t *g_zfs;

typedef struct zfs_mount_data {
	char		*match_name;
	zfs_handle_t	*match_handle;
} zfs_mount_data_t;

typedef struct zfs_snapshot_data {
	char	*match_name;
	int	len;
	int	max;
} zfs_snapshot_data_t;

/*
 * A ZFS file system iterator call-back function which is used to validate
 * datasets imported into the zone.
 */
/* ARGSUSED */
static int
check_zvol(zfs_handle_t *zhp, void *unused)
{
	int ret;

	if (zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
		/*
		 * TRANSLATION_NOTE
		 * zfs and dataset are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("cannot verify zfs dataset %s: "
		    "volumes cannot be specified as a zone dataset resource\n"),
		    zfs_get_name(zhp));
		ret = -1;
	} else {
		ret = zfs_iter_children(zhp, check_zvol, NULL);
	}

	zfs_close(zhp);

	return (ret);
}

/*
 * A ZFS file system iterator call-back function which returns the
 * zfs_handle_t for a ZFS file system on the specified mount point.
 */
static int
match_mountpoint(zfs_handle_t *zhp, void *data)
{
	int			res;
	zfs_mount_data_t	*cbp;
	char			mp[ZFS_MAXPROPLEN];

	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		zfs_close(zhp);
		return (0);
	}

	/* First check if the dataset is mounted. */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTED, mp, sizeof (mp), NULL, NULL,
	    0, B_FALSE) != 0 || strcmp(mp, "no") == 0) {
		zfs_close(zhp);
		return (0);
	}

	/* Now check mount point. */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mp, sizeof (mp), NULL, NULL,
	    0, B_FALSE) != 0) {
		zfs_close(zhp);
		return (0);
	}

	cbp = (zfs_mount_data_t *)data;

	if (strcmp(mp, "legacy") == 0) {
		/* If legacy, must look in mnttab for mountpoint. */
		FILE		*fp;
		struct mnttab	entry;
		const char	*nm;

		nm = zfs_get_name(zhp);
		if ((fp = fopen(MNTTAB, "r")) == NULL) {
			zfs_close(zhp);
			return (0);
		}

		while (getmntent(fp, &entry) == 0) {
			if (strcmp(nm, entry.mnt_special) == 0) {
				if (strcmp(entry.mnt_mountp, cbp->match_name)
				    == 0) {
					(void) fclose(fp);
					cbp->match_handle = zhp;
					return (1);
				}
				break;
			}
		}
		(void) fclose(fp);

	} else if (strcmp(mp, cbp->match_name) == 0) {
		cbp->match_handle = zhp;
		return (1);
	}

	/* Iterate over any nested datasets. */
	res = zfs_iter_filesystems(zhp, match_mountpoint, data);
	zfs_close(zhp);
	return (res);
}

/*
 * Get ZFS handle for the specified mount point.
 */
static zfs_handle_t *
mount2zhandle(char *mountpoint)
{
	zfs_mount_data_t	cb;

	cb.match_name = mountpoint;
	cb.match_handle = NULL;
	(void) zfs_iter_root(g_zfs, match_mountpoint, &cb);
	return (cb.match_handle);
}

/*
 * Check if there is already a file system (zfs or any other type) mounted on
 * path.
 */
static boolean_t
is_mountpnt(char *path)
{
	FILE		*fp;
	struct mnttab	entry;

	if ((fp = fopen(MNTTAB, "r")) == NULL)
		return (B_FALSE);

	while (getmntent(fp, &entry) == 0) {
		if (strcmp(path, entry.mnt_mountp) == 0) {
			(void) fclose(fp);
			return (B_TRUE);
		}
	}

	(void) fclose(fp);
	return (B_FALSE);
}

/*
 * Run the brand's pre-snapshot hook before we take a ZFS snapshot of the zone.
 */
static int
pre_snapshot(char *presnapbuf)
{
	int status;

	/* No brand-specific handler */
	if (presnapbuf[0] == '\0')
		return (Z_OK);

	/* Run the hook */
	status = do_subproc_interactive(presnapbuf);
	if ((status = subproc_status(gettext("brand-specific presnapshot"),
	    status, B_FALSE)) != ZONE_SUBPROC_OK)
		return (Z_ERR);

	return (Z_OK);
}

/*
 * Run the brand's post-snapshot hook after we take a ZFS snapshot of the zone.
 */
static int
post_snapshot(char *postsnapbuf)
{
	int status;

	/* No brand-specific handler */
	if (postsnapbuf[0] == '\0')
		return (Z_OK);

	/* Run the hook */
	status = do_subproc_interactive(postsnapbuf);
	if ((status = subproc_status(gettext("brand-specific postsnapshot"),
	    status, B_FALSE)) != ZONE_SUBPROC_OK)
		return (Z_ERR);

	return (Z_OK);
}

/*
 * This is a ZFS snapshot iterator call-back function which returns the
 * highest number of SUNWzone snapshots that have been taken.
 */
static int
get_snap_max(zfs_handle_t *zhp, void *data)
{
	int			res;
	zfs_snapshot_data_t	*cbp;

	if (zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT) {
		zfs_close(zhp);
		return (0);
	}

	cbp = (zfs_snapshot_data_t *)data;

	if (strncmp(zfs_get_name(zhp), cbp->match_name, cbp->len) == 0) {
		char	*nump;
		int	num;

		nump = (char *)(zfs_get_name(zhp) + cbp->len);
		num = atoi(nump);
		if (num > cbp->max)
			cbp->max = num;
	}

	res = zfs_iter_snapshots(zhp, get_snap_max, data);
	zfs_close(zhp);
	return (res);
}

/*
 * Take a ZFS snapshot to be used for cloning the zone.
 */
static int
take_snapshot(zfs_handle_t *zhp, char *snapshot_name, int snap_size,
    char *presnapbuf, char *postsnapbuf)
{
	int			res;
	char			template[ZFS_MAXNAMELEN];
	zfs_snapshot_data_t	cb;

	/*
	 * First we need to figure out the next available name for the
	 * zone snapshot.  Look through the list of zones snapshots for
	 * this file system to determine the maximum snapshot name.
	 */
	if (snprintf(template, sizeof (template), "%s@SUNWzone",
	    zfs_get_name(zhp)) >=  sizeof (template))
		return (Z_ERR);

	cb.match_name = template;
	cb.len = strlen(template);
	cb.max = 0;

	if (zfs_iter_snapshots(zhp, get_snap_max, &cb) != 0)
		return (Z_ERR);

	cb.max++;

	if (snprintf(snapshot_name, snap_size, "%s@SUNWzone%d",
	    zfs_get_name(zhp), cb.max) >= snap_size)
		return (Z_ERR);

	if (pre_snapshot(presnapbuf) != Z_OK)
		return (Z_ERR);
	res = zfs_snapshot(g_zfs, snapshot_name, B_FALSE);
	if (post_snapshot(postsnapbuf) != Z_OK)
		return (Z_ERR);

	if (res != 0)
		return (Z_ERR);
	return (Z_OK);
}

/*
 * We are using an explicit snapshot from some earlier point in time so
 * we need to validate it.  Run the brand specific hook.
 */
static int
validate_snapshot(char *snapshot_name, char *snap_path, char *validsnapbuf)
{
	int status;
	char cmdbuf[MAXPATHLEN];

	/* No brand-specific handler */
	if (validsnapbuf[0] == '\0')
		return (Z_OK);

	/* pass args - snapshot_name & snap_path */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "%s %s %s", validsnapbuf,
	    snapshot_name, snap_path) >= sizeof (cmdbuf)) {
		zerror("Command line too long");
		return (Z_ERR);
	}

	/* Run the hook */
	status = do_subproc_interactive(cmdbuf);
	if ((status = subproc_status(gettext("brand-specific validatesnapshot"),
	    status, B_FALSE)) != ZONE_SUBPROC_OK)
		return (Z_ERR);

	return (Z_OK);
}

/*
 * Remove the sw inventory file from inside this zonepath that we picked up out
 * of the snapshot.
 */
static int
clean_out_clone()
{
	int err;
	zone_dochandle_t handle;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zperror(cmd_to_str(CMD_CLONE), B_TRUE);
		return (Z_ERR);
	}

	if ((err = zonecfg_get_handle(target_zone, handle)) != Z_OK) {
		errno = err;
		zperror(cmd_to_str(CMD_CLONE), B_TRUE);
		zonecfg_fini_handle(handle);
		return (Z_ERR);
	}

	zonecfg_rm_detached(handle, B_FALSE);
	zonecfg_fini_handle(handle);

	return (Z_OK);
}

/*
 * Make a ZFS clone on zonepath from snapshot_name.
 */
static int
clone_snap(char *snapshot_name, char *zonepath)
{
	int		res = Z_OK;
	int		err;
	zfs_handle_t	*zhp;
	zfs_handle_t	*clone;
	nvlist_t	*props = NULL;

	if ((zhp = zfs_open(g_zfs, snapshot_name, ZFS_TYPE_SNAPSHOT)) == NULL)
		return (Z_NO_ENTRY);

	(void) printf(gettext("Cloning snapshot %s\n"), snapshot_name);

	if (nvlist_alloc(&props, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_SHARENFS),
	    "off") != 0) {
		if (props != NULL)
			nvlist_free(props);
		(void) fprintf(stderr, gettext("could not create ZFS clone "
		    "%s: out of memory\n"), zonepath);
		return (Z_ERR);
	}

	err = zfs_clone(zhp, zonepath, props);
	zfs_close(zhp);

	nvlist_free(props);

	if (err != 0)
		return (Z_ERR);

	/* create the mountpoint if necessary */
	if ((clone = zfs_open(g_zfs, zonepath, ZFS_TYPE_DATASET)) == NULL)
		return (Z_ERR);

	/*
	 * The clone has been created so we need to print a diagnostic
	 * message if one of the following steps fails for some reason.
	 */
	if (zfs_mount(clone, NULL, 0) != 0) {
		(void) fprintf(stderr, gettext("could not mount ZFS clone "
		    "%s\n"), zfs_get_name(clone));
		res = Z_ERR;

	} else if (clean_out_clone() != Z_OK) {
		(void) fprintf(stderr, gettext("could not remove the "
		    "software inventory from ZFS clone %s\n"),
		    zfs_get_name(clone));
		res = Z_ERR;
	}

	zfs_close(clone);
	return (res);
}

/*
 * This function takes a zonepath and attempts to determine what the ZFS
 * file system name (not mountpoint) should be for that path.  We do not
 * assume that zonepath is an existing directory or ZFS fs since we use
 * this function as part of the process of creating a new ZFS fs or clone.
 *
 * The way this works is that we look at the parent directory of the zonepath
 * to see if it is a ZFS fs.  If it is, we get the name of that ZFS fs and
 * append the last component of the zonepath to generate the ZFS name for the
 * zonepath.  This matches the algorithm that ZFS uses for automatically
 * mounting a new fs after it is created.
 *
 * Although a ZFS fs can be mounted anywhere, we don't worry about handling
 * all of the complexity that a user could possibly configure with arbitrary
 * mounts since there is no way to generate a ZFS name from a random path in
 * the file system.  We only try to handle the automatic mounts that ZFS does
 * for each file system.  ZFS restricts this so that a new fs must be created
 * in an existing parent ZFS fs.  It then automatically mounts the new fs
 * directly under the mountpoint for the parent fs using the last component
 * of the name as the mountpoint directory.
 *
 * For example:
 *    Name			Mountpoint
 *    space/eng/dev/test/zone1	/project1/eng/dev/test/zone1
 *
 * Return Z_OK if the path mapped to a ZFS file system name, otherwise return
 * Z_ERR.
 */
static int
path2name(char *zonepath, char *zfs_name, int len)
{
	int		res;
	char		*bnm, *dnm, *dname, *bname;
	zfs_handle_t	*zhp;
	struct stat	stbuf;

	/*
	 * We need two tmp strings to handle paths directly in / (e.g. /foo)
	 * since dirname will overwrite the first char after "/" in this case.
	 */
	if ((bnm = strdup(zonepath)) == NULL)
		return (Z_ERR);

	if ((dnm = strdup(zonepath)) == NULL) {
		free(bnm);
		return (Z_ERR);
	}

	bname = basename(bnm);
	dname = dirname(dnm);

	/*
	 * This is a quick test to save iterating over all of the zfs datasets
	 * on the system (which can be a lot).  If the parent dir is not in a
	 * ZFS fs, then we're done.
	 */
	if (stat(dname, &stbuf) != 0 || !S_ISDIR(stbuf.st_mode) ||
	    strcmp(stbuf.st_fstype, MNTTYPE_ZFS) != 0) {
		free(bnm);
		free(dnm);
		return (Z_ERR);
	}

	/* See if the parent directory is its own ZFS dataset. */
	if ((zhp = mount2zhandle(dname)) == NULL) {
		/*
		 * The parent is not a ZFS dataset so we can't automatically
		 * create a dataset on the given path.
		 */
		free(bnm);
		free(dnm);
		return (Z_ERR);
	}

	res = snprintf(zfs_name, len, "%s/%s", zfs_get_name(zhp), bname);

	free(bnm);
	free(dnm);
	zfs_close(zhp);
	if (res >= len)
		return (Z_ERR);

	return (Z_OK);
}

/*
 * A ZFS file system iterator call-back function used to determine if the
 * file system has dependents (snapshots & clones).
 */
/* ARGSUSED */
static int
has_dependent(zfs_handle_t *zhp, void *data)
{
	zfs_close(zhp);
	return (1);
}

/*
 * Given a snapshot name, get the file system path where the snapshot lives.
 * A snapshot name is of the form fs_name@snap_name.  For example, snapshot
 * pl/zones/z1@SUNWzone1 would have a path of
 * /pl/zones/z1/.zfs/snapshot/SUNWzone1.
 */
static int
snap2path(char *snap_name, char *path, int len)
{
	char		*p;
	zfs_handle_t	*zhp;
	char		mp[ZFS_MAXPROPLEN];

	if ((p = strrchr(snap_name, '@')) == NULL)
		return (Z_ERR);

	/* Get the file system name from the snap_name. */
	*p = '\0';
	zhp = zfs_open(g_zfs, snap_name, ZFS_TYPE_DATASET);
	*p = '@';
	if (zhp == NULL)
		return (Z_ERR);

	/* Get the file system mount point. */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mp, sizeof (mp), NULL, NULL,
	    0, B_FALSE) != 0) {
		zfs_close(zhp);
		return (Z_ERR);
	}
	zfs_close(zhp);

	p++;
	if (snprintf(path, len, "%s/.zfs/snapshot/%s", mp, p) >= len)
		return (Z_ERR);

	return (Z_OK);
}

/*
 * Clone a pre-existing ZFS snapshot, either by making a direct ZFS clone, if
 * possible, or by copying the data from the snapshot to the zonepath.
 */
int
clone_snapshot_zfs(char *snap_name, char *zonepath, char *validatesnap)
{
	int	err = Z_OK;
	char	clone_name[MAXPATHLEN];
	char	snap_path[MAXPATHLEN];

	if (snap2path(snap_name, snap_path, sizeof (snap_path)) != Z_OK) {
		(void) fprintf(stderr, gettext("unable to find path for %s.\n"),
		    snap_name);
		return (Z_ERR);
	}

	if (validate_snapshot(snap_name, snap_path, validatesnap) != Z_OK)
		return (Z_NO_ENTRY);

	/*
	 * The zonepath cannot be ZFS cloned, try to copy the data from
	 * within the snapshot to the zonepath.
	 */
	if (path2name(zonepath, clone_name, sizeof (clone_name)) != Z_OK) {
		if ((err = clone_copy(snap_path, zonepath)) == Z_OK)
			if (clean_out_clone() != Z_OK)
				(void) fprintf(stderr,
				    gettext("could not remove the "
				    "software inventory from %s\n"), zonepath);

		return (err);
	}

	if ((err = clone_snap(snap_name, clone_name)) != Z_OK) {
		if (err != Z_NO_ENTRY) {
			/*
			 * Cloning the snapshot failed.  Fall back to trying
			 * to install the zone by copying from the snapshot.
			 */
			if ((err = clone_copy(snap_path, zonepath)) == Z_OK)
				if (clean_out_clone() != Z_OK)
					(void) fprintf(stderr,
					    gettext("could not remove the "
					    "software inventory from %s\n"),
					    zonepath);
		} else {
			/*
			 * The snapshot is unusable for some reason so restore
			 * the zone state to configured since we were unable to
			 * actually do anything about getting the zone
			 * installed.
			 */
			int tmp;

			if ((tmp = zone_set_state(target_zone,
			    ZONE_STATE_CONFIGURED)) != Z_OK) {
				errno = tmp;
				zperror2(target_zone,
				    gettext("could not set state"));
			}
		}
	}

	return (err);
}

/*
 * Attempt to clone a source_zone to a target zonepath by using a ZFS clone.
 */
int
clone_zfs(char *source_zonepath, char *zonepath, char *presnapbuf,
    char *postsnapbuf)
{
	zfs_handle_t	*zhp;
	char		clone_name[MAXPATHLEN];
	char		snap_name[MAXPATHLEN];

	/*
	 * Try to get a zfs handle for the source_zonepath.  If this fails
	 * the source_zonepath is not ZFS so return an error.
	 */
	if ((zhp = mount2zhandle(source_zonepath)) == NULL)
		return (Z_ERR);

	/*
	 * Check if there is a file system already mounted on zonepath.  If so,
	 * we can't clone to the path so we should fall back to copying.
	 */
	if (is_mountpnt(zonepath)) {
		zfs_close(zhp);
		(void) fprintf(stderr,
		    gettext("A file system is already mounted on %s,\n"
		    "preventing use of a ZFS clone.\n"), zonepath);
		return (Z_ERR);
	}

	/*
	 * Instead of using path2name to get the clone name from the zonepath,
	 * we could generate a name from the source zone ZFS name.  However,
	 * this would mean we would create the clone under the ZFS fs of the
	 * source instead of what the zonepath says.  For example,
	 *
	 * source_zonepath		zonepath
	 * /pl/zones/dev/z1		/pl/zones/deploy/z2
	 *
	 * We don't want the clone to be under "dev", we want it under
	 * "deploy", so that we can leverage the normal attribute inheritance
	 * that ZFS provides in the fs hierarchy.
	 */
	if (path2name(zonepath, clone_name, sizeof (clone_name)) != Z_OK) {
		zfs_close(zhp);
		return (Z_ERR);
	}

	if (take_snapshot(zhp, snap_name, sizeof (snap_name), presnapbuf,
	    postsnapbuf) != Z_OK) {
		zfs_close(zhp);
		return (Z_ERR);
	}
	zfs_close(zhp);

	if (clone_snap(snap_name, clone_name) != Z_OK) {
		/* Clean up the snapshot we just took. */
		if ((zhp = zfs_open(g_zfs, snap_name, ZFS_TYPE_SNAPSHOT))
		    != NULL) {
			if (zfs_unmount(zhp, NULL, 0) == 0)
				(void) zfs_destroy(zhp);
			zfs_close(zhp);
		}

		return (Z_ERR);
	}

	(void) printf(gettext("Instead of copying, a ZFS clone has been "
	    "created for this zone.\n"));

	return (Z_OK);
}

/*
 * Attempt to create a ZFS file system for the specified zonepath.
 * We either will successfully create a ZFS file system and get it mounted
 * on the zonepath or we don't.  The caller doesn't care since a regular
 * directory is used for the zonepath if no ZFS file system is mounted there.
 */
void
create_zfs_zonepath(char *zonepath)
{
	zfs_handle_t	*zhp;
	char		zfs_name[MAXPATHLEN];
	nvlist_t	*props = NULL;

	if (path2name(zonepath, zfs_name, sizeof (zfs_name)) != Z_OK)
		return;

	if (nvlist_alloc(&props, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_SHARENFS),
	    "off") != 0) {
		if (props != NULL)
			nvlist_free(props);
		(void) fprintf(stderr, gettext("cannot create ZFS dataset %s: "
		    "out of memory\n"), zfs_name);
	}

	if (zfs_create(g_zfs, zfs_name, ZFS_TYPE_FILESYSTEM, props) != 0 ||
	    (zhp = zfs_open(g_zfs, zfs_name, ZFS_TYPE_DATASET)) == NULL) {
		(void) fprintf(stderr, gettext("cannot create ZFS dataset %s: "
		    "%s\n"), zfs_name, libzfs_error_description(g_zfs));
		nvlist_free(props);
		return;
	}

	nvlist_free(props);

	if (zfs_mount(zhp, NULL, 0) != 0) {
		(void) fprintf(stderr, gettext("cannot mount ZFS dataset %s: "
		    "%s\n"), zfs_name, libzfs_error_description(g_zfs));
		(void) zfs_destroy(zhp);
	} else {
		if (chmod(zonepath, S_IRWXU) != 0) {
			(void) fprintf(stderr, gettext("file system %s "
			    "successfully created, but chmod %o failed: %s\n"),
			    zfs_name, S_IRWXU, strerror(errno));
			(void) destroy_zfs(zonepath);
		} else {
			(void) printf(gettext("A ZFS file system has been "
			    "created for this zone.\n"));
		}
	}

	zfs_close(zhp);
}

/*
 * If the zonepath is a ZFS file system, attempt to destroy it.  We return Z_OK
 * if we were able to zfs_destroy the zonepath, otherwise we return Z_ERR
 * which means the caller should clean up the zonepath in the traditional
 * way.
 */
int
destroy_zfs(char *zonepath)
{
	zfs_handle_t	*zhp;
	boolean_t	is_clone = B_FALSE;
	char		origin[ZFS_MAXPROPLEN];

	if ((zhp = mount2zhandle(zonepath)) == NULL)
		return (Z_ERR);

	/*
	 * We can't destroy the file system if it has dependents.
	 */
	if (zfs_iter_dependents(zhp, B_TRUE, has_dependent, NULL) != 0 ||
	    zfs_unmount(zhp, NULL, 0) != 0) {
		zfs_close(zhp);
		return (Z_ERR);
	}

	/*
	 * This might be a clone.  Try to get the snapshot so we can attempt
	 * to destroy that as well.
	 */
	if (zfs_prop_get(zhp, ZFS_PROP_ORIGIN, origin, sizeof (origin), NULL,
	    NULL, 0, B_FALSE) == 0)
		is_clone = B_TRUE;

	if (zfs_destroy(zhp) != 0) {
		/*
		 * If the destroy fails for some reason, try to remount
		 * the file system so that we can use "rm -rf" to clean up
		 * instead.
		 */
		(void) zfs_mount(zhp, NULL, 0);
		zfs_close(zhp);
		return (Z_ERR);
	}

	/*
	 * If the zone has ever been moved then the mountpoint dir will not be
	 * cleaned up by the zfs_destroy().  To handle this case try to clean
	 * it up now but don't worry if it fails, that will be normal.
	 */
	(void) rmdir(zonepath);

	(void) printf(gettext("The ZFS file system for this zone has been "
	    "destroyed.\n"));

	if (is_clone) {
		zfs_handle_t	*ohp;

		/*
		 * Try to clean up the snapshot that the clone was taken from.
		 */
		if ((ohp = zfs_open(g_zfs, origin,
		    ZFS_TYPE_SNAPSHOT)) != NULL) {
			if (zfs_iter_dependents(ohp, B_TRUE, has_dependent,
			    NULL) == 0 && zfs_unmount(ohp, NULL, 0) == 0)
				(void) zfs_destroy(ohp);
			zfs_close(ohp);
		}
	}

	zfs_close(zhp);
	return (Z_OK);
}

/*
 * Return true if the path is its own zfs file system.  We determine this
 * by stat-ing the path to see if it is zfs and stat-ing the parent to see
 * if it is a different fs.
 */
boolean_t
is_zonepath_zfs(char *zonepath)
{
	int res;
	char *path;
	char *parent;
	struct statvfs64 buf1, buf2;

	if (statvfs64(zonepath, &buf1) != 0)
		return (B_FALSE);

	if (strcmp(buf1.f_basetype, "zfs") != 0)
		return (B_FALSE);

	if ((path = strdup(zonepath)) == NULL)
		return (B_FALSE);

	parent = dirname(path);
	res = statvfs64(parent, &buf2);
	free(path);

	if (res != 0)
		return (B_FALSE);

	if (buf1.f_fsid == buf2.f_fsid)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Implement the fast move of a ZFS file system by simply updating the
 * mountpoint.  Since it is file system already, we don't have the
 * issue of cross-file system copying.
 */
int
move_zfs(char *zonepath, char *new_zonepath)
{
	int		ret = Z_ERR;
	zfs_handle_t	*zhp;

	if ((zhp = mount2zhandle(zonepath)) == NULL)
		return (Z_ERR);

	if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
	    new_zonepath) == 0) {
		/*
		 * Clean up the old mount point.  We ignore any failure since
		 * the zone is already successfully mounted on the new path.
		 */
		(void) rmdir(zonepath);
		ret = Z_OK;
	}

	zfs_close(zhp);

	return (ret);
}

/*
 * Validate that the given dataset exists on the system, and that neither it nor
 * its children are zvols.
 *
 * Note that we don't do anything with the 'zoned' property here.  All
 * management is done in zoneadmd when the zone is actually rebooted.  This
 * allows us to automatically set the zoned property even when a zone is
 * rebooted by the administrator.
 */
int
verify_datasets(zone_dochandle_t handle)
{
	int return_code = Z_OK;
	struct zone_dstab dstab;
	zfs_handle_t *zhp;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zprop_source_t srctype;

	if (zonecfg_setdsent(handle) != Z_OK) {
		/*
		 * TRANSLATION_NOTE
		 * zfs and dataset are literals that should not be translated.
		 */
		(void) fprintf(stderr, gettext("could not verify zfs datasets: "
		    "unable to enumerate datasets\n"));
		return (Z_ERR);
	}

	while (zonecfg_getdsent(handle, &dstab) == Z_OK) {

		if ((zhp = zfs_open(g_zfs, dstab.zone_dataset_name,
		    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME)) == NULL) {
			(void) fprintf(stderr, gettext("could not verify zfs "
			    "dataset %s: %s\n"), dstab.zone_dataset_name,
			    libzfs_error_description(g_zfs));
			return_code = Z_ERR;
			continue;
		}

		if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, propbuf,
		    sizeof (propbuf), &srctype, source,
		    sizeof (source), 0) == 0 &&
		    (srctype == ZPROP_SRC_INHERITED)) {
			(void) fprintf(stderr, gettext("could not verify zfs "
			    "dataset %s: mountpoint cannot be inherited\n"),
			    dstab.zone_dataset_name);
			return_code = Z_ERR;
			zfs_close(zhp);
			continue;
		}

		if (zfs_get_type(zhp) == ZFS_TYPE_VOLUME) {
			(void) fprintf(stderr, gettext("cannot verify zfs "
			    "dataset %s: volumes cannot be specified as a "
			    "zone dataset resource\n"),
			    dstab.zone_dataset_name);
			return_code = Z_ERR;
		}

		if (zfs_iter_children(zhp, check_zvol, NULL) != 0)
			return_code = Z_ERR;

		zfs_close(zhp);
	}
	(void) zonecfg_enddsent(handle);

	return (return_code);
}

/*
 * Verify that the ZFS dataset exists, and its mountpoint
 * property is set to "legacy".
 */
int
verify_fs_zfs(struct zone_fstab *fstab)
{
	zfs_handle_t *zhp;
	char propbuf[ZFS_MAXPROPLEN];

	if ((zhp = zfs_open(g_zfs, fstab->zone_fs_special,
	    ZFS_TYPE_DATASET)) == NULL) {
		(void) fprintf(stderr, gettext("could not verify fs %s: "
		    "could not access zfs dataset '%s'\n"),
		    fstab->zone_fs_dir, fstab->zone_fs_special);
		return (Z_ERR);
	}

	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		(void) fprintf(stderr, gettext("cannot verify fs %s: "
		    "'%s' is not a file system\n"),
		    fstab->zone_fs_dir, fstab->zone_fs_special);
		zfs_close(zhp);
		return (Z_ERR);
	}

	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, propbuf, sizeof (propbuf),
	    NULL, NULL, 0, 0) != 0 || strcmp(propbuf, "legacy") != 0) {
		(void) fprintf(stderr, gettext("could not verify fs %s: "
		    "zfs '%s' mountpoint is not \"legacy\"\n"),
		    fstab->zone_fs_dir, fstab->zone_fs_special);
		zfs_close(zhp);
		return (Z_ERR);
	}

	zfs_close(zhp);
	return (Z_OK);
}

int
init_zfs(void)
{
	if ((g_zfs = libzfs_init()) == NULL) {
		(void) fprintf(stderr, gettext("failed to initialize ZFS "
		    "library\n"));
		return (Z_ERR);
	}

	return (Z_OK);
}
