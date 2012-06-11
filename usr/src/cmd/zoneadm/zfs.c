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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

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
#include <values.h>
#include <strings.h>
#include <assert.h>

#include "zoneadm.h"

libzfs_handle_t *g_zfs;

typedef struct zfs_mount_data {
	char		*match_name;
	zfs_handle_t	*match_handle;
} zfs_mount_data_t;

typedef struct zfs_snapshot_data {
	char	*match_name;	/* zonename@SUNWzone */
	int	len;		/* strlen of match_name */
	int	max;		/* highest digit appended to snap name */
	int	num;		/* number of snapshots to rename */
	int	cntr;		/* counter for renaming snapshots */
} zfs_snapshot_data_t;

typedef struct clone_data {
	zfs_handle_t	*clone_zhp;	/* clone dataset to promote */
	time_t		origin_creation; /* snapshot creation time of clone */
	const char	*snapshot;	/* snapshot of dataset being demoted */
} clone_data_t;

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
	status = do_subproc(presnapbuf);
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
	status = do_subproc(postsnapbuf);
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

		cbp->num++;
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
	res = zfs_snapshot(g_zfs, snapshot_name, B_FALSE, NULL);
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
	status = do_subproc(cmdbuf);
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

	/*
	 * We turn off zfs SHARENFS and SHARESMB properties on the
	 * zoneroot dataset in order to prevent the GZ from sharing
	 * NGZ data by accident.
	 */
	if ((nvlist_alloc(&props, NV_UNIQUE_NAME, 0) != 0) ||
	    (nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_SHARENFS),
	    "off") != 0) ||
	    (nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_SHARESMB),
	    "off") != 0)) {
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
 * This callback function is used to iterate through a snapshot's dependencies
 * to find a filesystem that is a direct clone of the snapshot being iterated.
 */
static int
get_direct_clone(zfs_handle_t *zhp, void *data)
{
	clone_data_t	*cd = data;
	char		origin[ZFS_MAXNAMELEN];
	char		ds_path[ZFS_MAXNAMELEN];

	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		zfs_close(zhp);
		return (0);
	}

	(void) strlcpy(ds_path, zfs_get_name(zhp), sizeof (ds_path));

	/* Make sure this is a direct clone of the snapshot we're iterating. */
	if (zfs_prop_get(zhp, ZFS_PROP_ORIGIN, origin, sizeof (origin), NULL,
	    NULL, 0, B_FALSE) != 0 || strcmp(origin, cd->snapshot) != 0) {
		zfs_close(zhp);
		return (0);
	}

	if (cd->clone_zhp != NULL)
		zfs_close(cd->clone_zhp);

	cd->clone_zhp = zhp;
	return (1);
}

/*
 * A ZFS file system iterator call-back function used to determine the clone
 * to promote.  This function finds the youngest (i.e. last one taken) snapshot
 * that has a clone.  If found, it returns a reference to that clone in the
 * callback data.
 */
static int
find_clone(zfs_handle_t *zhp, void *data)
{
	clone_data_t	*cd = data;
	time_t		snap_creation;
	int		zret = 0;

	/* If snapshot has no clones, skip it */
	if (zfs_prop_get_int(zhp, ZFS_PROP_NUMCLONES) == 0) {
		zfs_close(zhp);
		return (0);
	}

	cd->snapshot = zfs_get_name(zhp);

	/* Get the creation time of this snapshot */
	snap_creation = (time_t)zfs_prop_get_int(zhp, ZFS_PROP_CREATION);

	/*
	 * If this snapshot's creation time is greater than (i.e. younger than)
	 * the current youngest snapshot found, iterate this snapshot to
	 * get the right clone.
	 */
	if (snap_creation >= cd->origin_creation) {
		/*
		 * Iterate the dependents of this snapshot to find a clone
		 * that's a direct dependent.
		 */
		if ((zret = zfs_iter_dependents(zhp, B_FALSE, get_direct_clone,
		    cd)) == -1) {
			zfs_close(zhp);
			return (1);
		} else if (zret == 1) {
			/*
			 * Found a clone, update the origin_creation time
			 * in the callback data.
			 */
			cd->origin_creation = snap_creation;
		}
	}

	zfs_close(zhp);
	return (0);
}

/*
 * A ZFS file system iterator call-back function used to remove standalone
 * snapshots.
 */
/* ARGSUSED */
static int
rm_snap(zfs_handle_t *zhp, void *data)
{
	/* If snapshot has clones, something is wrong */
	if (zfs_prop_get_int(zhp, ZFS_PROP_NUMCLONES) != 0) {
		zfs_close(zhp);
		return (1);
	}

	if (zfs_unmount(zhp, NULL, 0) == 0) {
		(void) zfs_destroy(zhp, B_FALSE);
	}

	zfs_close(zhp);
	return (0);
}

/*
 * A ZFS snapshot iterator call-back function which renames snapshots.
 */
static int
rename_snap(zfs_handle_t *zhp, void *data)
{
	int			res;
	zfs_snapshot_data_t	*cbp;
	char			template[ZFS_MAXNAMELEN];

	cbp = (zfs_snapshot_data_t *)data;

	/*
	 * When renaming snapshots with the iterator, the iterator can see
	 * the same snapshot after we've renamed up in the namespace.  To
	 * prevent this we check the count for the number of snapshots we have
	 * to rename and stop at that point.
	 */
	if (cbp->cntr >= cbp->num) {
		zfs_close(zhp);
		return (0);
	}

	if (zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT) {
		zfs_close(zhp);
		return (0);
	}

	/* Only rename the snapshots we automatically generate when we clone. */
	if (strncmp(zfs_get_name(zhp), cbp->match_name, cbp->len) != 0) {
		zfs_close(zhp);
		return (0);
	}

	(void) snprintf(template, sizeof (template), "%s%d", cbp->match_name,
	    cbp->max++);

	res = (zfs_rename(zhp, template, B_FALSE, B_FALSE) != 0);
	if (res != 0)
		(void) fprintf(stderr, gettext("failed to rename snapshot %s "
		    "to %s: %s\n"), zfs_get_name(zhp), template,
		    libzfs_error_description(g_zfs));

	cbp->cntr++;

	zfs_close(zhp);
	return (res);
}

/*
 * Rename the source dataset's snapshots that are automatically generated when
 * we clone a zone so that there won't be a name collision when we promote the
 * cloned dataset.  Once the snapshots have been renamed, then promote the
 * clone.
 *
 * The snapshot rename process gets the highest number on the snapshot names
 * (the format is zonename@SUNWzoneXX where XX are digits) on both the source
 * and clone datasets, then renames the source dataset snapshots starting at
 * the next number.
 */
static int
promote_clone(zfs_handle_t *src_zhp, zfs_handle_t *cln_zhp)
{
	zfs_snapshot_data_t	sd;
	char			nm[ZFS_MAXNAMELEN];
	char			template[ZFS_MAXNAMELEN];

	(void) strlcpy(nm, zfs_get_name(cln_zhp), sizeof (nm));
	/*
	 * Start by getting the clone's snapshot max which we use
	 * during the rename of the original dataset's snapshots.
	 */
	(void) snprintf(template, sizeof (template), "%s@SUNWzone", nm);
	sd.match_name = template;
	sd.len = strlen(template);
	sd.max = 0;

	if (zfs_iter_snapshots(cln_zhp, get_snap_max, &sd) != 0)
		return (Z_ERR);

	/*
	 * Now make sure the source's snapshot max is at least as high as
	 * the clone's snapshot max.
	 */
	(void) snprintf(template, sizeof (template), "%s@SUNWzone",
	    zfs_get_name(src_zhp));
	sd.match_name = template;
	sd.len = strlen(template);
	sd.num = 0;

	if (zfs_iter_snapshots(src_zhp, get_snap_max, &sd) != 0)
		return (Z_ERR);

	/*
	 * Now rename the source dataset's snapshots so there's no
	 * conflict when we promote the clone.
	 */
	sd.max++;
	sd.cntr = 0;
	if (zfs_iter_snapshots(src_zhp, rename_snap, &sd) != 0)
		return (Z_ERR);

	/* close and reopen the clone dataset to get the latest info */
	zfs_close(cln_zhp);
	if ((cln_zhp = zfs_open(g_zfs, nm, ZFS_TYPE_FILESYSTEM)) == NULL)
		return (Z_ERR);

	if (zfs_promote(cln_zhp) != 0) {
		(void) fprintf(stderr, gettext("failed to promote %s: %s\n"),
		    nm, libzfs_error_description(g_zfs));
		return (Z_ERR);
	}

	zfs_close(cln_zhp);
	return (Z_OK);
}

/*
 * Promote the youngest clone.  That clone will then become the origin of all
 * of the other clones that were hanging off of the source dataset.
 */
int
promote_all_clones(zfs_handle_t *zhp)
{
	clone_data_t	cd;
	char		nm[ZFS_MAXNAMELEN];

	cd.clone_zhp = NULL;
	cd.origin_creation = 0;
	cd.snapshot = NULL;

	if (zfs_iter_snapshots(zhp, find_clone, &cd) != 0) {
		zfs_close(zhp);
		return (Z_ERR);
	}

	/* Nothing to promote. */
	if (cd.clone_zhp == NULL)
		return (Z_OK);

	/* Found the youngest clone to promote.  Promote it. */
	if (promote_clone(zhp, cd.clone_zhp) != 0) {
		zfs_close(cd.clone_zhp);
		zfs_close(zhp);
		return (Z_ERR);
	}

	/* close and reopen the main dataset to get the latest info */
	(void) strlcpy(nm, zfs_get_name(zhp), sizeof (nm));
	zfs_close(zhp);
	if ((zhp = zfs_open(g_zfs, nm, ZFS_TYPE_FILESYSTEM)) == NULL)
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
				(void) zfs_destroy(zhp, B_FALSE);
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

	/* Check if the dataset already exists. */
	if ((zhp = zfs_open(g_zfs, zfs_name, ZFS_TYPE_DATASET)) != NULL) {
		zfs_close(zhp);
		return;
	}

	/*
	 * We turn off zfs SHARENFS and SHARESMB properties on the
	 * zoneroot dataset in order to prevent the GZ from sharing
	 * NGZ data by accident.
	 */
	if ((nvlist_alloc(&props, NV_UNIQUE_NAME, 0) != 0) ||
	    (nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_SHARENFS),
	    "off") != 0) ||
	    (nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_SHARESMB),
	    "off") != 0)) {
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
		(void) zfs_destroy(zhp, B_FALSE);
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

	if (promote_all_clones(zhp) != 0)
		return (Z_ERR);

	/* Now cleanup any snapshots remaining. */
	if (zfs_iter_snapshots(zhp, rm_snap, NULL) != 0) {
		zfs_close(zhp);
		return (Z_ERR);
	}

	/*
	 * We can't destroy the file system if it has still has dependents.
	 * There shouldn't be any at this point, but we'll double check.
	 */
	if (zfs_iter_dependents(zhp, B_TRUE, has_dependent, NULL) != 0) {
		(void) fprintf(stderr, gettext("zfs destroy %s failed: the "
		    "dataset still has dependents\n"), zfs_get_name(zhp));
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

	if (zfs_unmount(zhp, NULL, 0) != 0) {
		(void) fprintf(stderr, gettext("zfs unmount %s failed: %s\n"),
		    zfs_get_name(zhp), libzfs_error_description(g_zfs));
		zfs_close(zhp);
		return (Z_ERR);
	}

	if (zfs_destroy(zhp, B_FALSE) != 0) {
		/*
		 * If the destroy fails for some reason, try to remount
		 * the file system so that we can use "rm -rf" to clean up
		 * instead.
		 */
		(void) fprintf(stderr, gettext("zfs destroy %s failed: %s\n"),
		    zfs_get_name(zhp), libzfs_error_description(g_zfs));
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
				(void) zfs_destroy(ohp, B_FALSE);
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

/*
 * Destroy the specified mnttab structure that was created by mnttab_dup().
 * NOTE: The structure's mnt_time field isn't freed.
 */
static void
mnttab_destroy(struct mnttab *tabp)
{
	assert(tabp != NULL);

	free(tabp->mnt_mountp);
	free(tabp->mnt_special);
	free(tabp->mnt_fstype);
	free(tabp->mnt_mntopts);
	free(tabp);
}

/*
 * Duplicate the specified mnttab structure.  The mnt_mountp and mnt_time
 * fields aren't duplicated.  This function returns a pointer to the new mnttab
 * structure or NULL if an error occurred.  If an error occurs, then this
 * function sets errno to reflect the error.  mnttab structures created by
 * this function should be destroyed via mnttab_destroy().
 */
static struct mnttab *
mnttab_dup(const struct mnttab *srcp)
{
	struct mnttab *retval;

	assert(srcp != NULL);

	retval = (struct mnttab *)calloc(1, sizeof (*retval));
	if (retval == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	if (srcp->mnt_special != NULL) {
		retval->mnt_special = strdup(srcp->mnt_special);
		if (retval->mnt_special == NULL)
			goto err;
	}
	if (srcp->mnt_fstype != NULL) {
		retval->mnt_fstype = strdup(srcp->mnt_fstype);
		if (retval->mnt_fstype == NULL)
			goto err;
	}
	retval->mnt_mntopts = (char *)malloc(MAX_MNTOPT_STR * sizeof (char));
	if (retval->mnt_mntopts == NULL)
		goto err;
	if (srcp->mnt_mntopts != NULL) {
		if (strlcpy(retval->mnt_mntopts, srcp->mnt_mntopts,
		    MAX_MNTOPT_STR * sizeof (char)) >= MAX_MNTOPT_STR *
		    sizeof (char)) {
			mnttab_destroy(retval);
			errno = EOVERFLOW; /* similar to mount(2) behavior */
			return (NULL);
		}
	} else {
		retval->mnt_mntopts[0] = '\0';
	}
	return (retval);

err:
	mnttab_destroy(retval);
	errno = ENOMEM;
	return (NULL);
}

/*
 * Determine whether the specified ZFS dataset's mountpoint property is set
 * to "legacy".  If the specified dataset does not have a legacy mountpoint,
 * then the string pointer to which the mountpoint argument points is assigned
 * a dynamically-allocated string containing the dataset's mountpoint
 * property.  If the dataset's mountpoint property is "legacy" or a libzfs
 * error occurs, then the string pointer to which the mountpoint argument
 * points isn't modified.
 *
 * This function returns B_TRUE if it doesn't encounter any fatal errors.
 * It returns B_FALSE if it encounters a fatal error and sets errno to the
 * appropriate error code.
 */
static boolean_t
get_zfs_non_legacy_mountpoint(const char *dataset_name, char **mountpoint)
{
	zfs_handle_t *zhp;
	char propbuf[ZFS_MAXPROPLEN];

	assert(dataset_name != NULL);
	assert(mountpoint != NULL);

	if ((zhp = zfs_open(g_zfs, dataset_name, ZFS_TYPE_DATASET)) == NULL) {
		errno = EINVAL;
		return (B_FALSE);
	}
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, propbuf, sizeof (propbuf),
	    NULL, NULL, 0, 0) != 0) {
		zfs_close(zhp);
		errno = EINVAL;
		return (B_FALSE);
	}
	zfs_close(zhp);
	if (strcmp(propbuf, "legacy") != 0) {
		if ((*mountpoint = strdup(propbuf)) == NULL) {
			errno = ENOMEM;
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}


/*
 * This zonecfg_find_mounts() callback records information about mounts of
 * interest in a zonepath.  It also tallies the number of zone
 * root overlay mounts and the number of unexpected mounts found.
 * This function outputs errors using zerror() if it finds unexpected
 * mounts.  cookiep should point to an initialized zone_mounts_t structure.
 *
 * This function returns zero on success and a nonzero value on failure.
 */
static int
zone_mounts_cb(const struct mnttab *mountp, void *cookiep)
{
	zone_mounts_t *mounts;
	const char *zone_mount_dir;

	assert(mountp != NULL);
	assert(cookiep != NULL);

	mounts = (zone_mounts_t *)cookiep;
	zone_mount_dir = mountp->mnt_mountp + mounts->zonepath_len;
	if (strcmp(zone_mount_dir, "/root") == 0) {
		/*
		 * Check for an overlay mount.  If we already detected a /root
		 * mount, then the current mount must be an overlay mount.
		 */
		if (mounts->root_mnttab != NULL) {
			mounts->num_root_overlay_mounts++;
			return (0);
		}

		/*
		 * Store the root mount's mnttab information in the
		 * zone_mounts_t structure for future use.
		 */
		if ((mounts->root_mnttab = mnttab_dup(mountp)) == NULL) {
			zperror(cmd_to_str(CMD_MOVE), B_FALSE);
			return (-1);
		}

		/*
		 * Determine if the filesystem is a ZFS filesystem with a
		 * non-legacy mountpoint.  If it is, then set the root
		 * filesystem's mnttab's mnt_mountp field to a non-NULL
		 * value, which will serve as a flag to indicate this special
		 * condition.
		 */
		if (strcmp(mountp->mnt_fstype, MNTTYPE_ZFS) == 0 &&
		    get_zfs_non_legacy_mountpoint(mountp->mnt_special,
		    &mounts->root_mnttab->mnt_mountp) != B_TRUE) {
			zperror(cmd_to_str(CMD_MOVE), B_FALSE);
			return (-1);
		}
	} else {
		/*
		 * An unexpected mount was found.  Notify the user.
		 */
		if (mounts->num_unexpected_mounts == 0)
			zerror(gettext("These file systems are mounted on "
			    "subdirectories of %s.\n"), mounts->zonepath);
		mounts->num_unexpected_mounts++;
		(void) zfm_print(mountp, NULL);
	}
	return (0);
}

/*
 * Initialize the specified zone_mounts_t structure for the given zonepath.
 * If this function succeeds, it returns zero and the specified zone_mounts_t
 * structure contains information about mounts in the specified zonepath.
 * The function returns a nonzero value if it fails.  The zone_mounts_t
 * structure doesn't need be destroyed via zone_mounts_destroy() if this
 * function fails.
 */
int
zone_mounts_init(zone_mounts_t *mounts, const char *zonepath)
{
	assert(mounts != NULL);
	assert(zonepath != NULL);

	bzero(mounts, sizeof (*mounts));
	if ((mounts->zonepath = strdup(zonepath)) == NULL) {
		zerror(gettext("the process ran out of memory while checking "
		    "for mounts in zonepath %s."), zonepath);
		return (-1);
	}
	mounts->zonepath_len = strlen(zonepath);
	if (zonecfg_find_mounts((char *)zonepath, zone_mounts_cb, mounts) ==
	    -1) {
		zerror(gettext("an error occurred while checking for mounts "
		    "in zonepath %s."), zonepath);
		zone_mounts_destroy(mounts);
		return (-1);
	}
	return (0);
}

/*
 * Destroy the memory used by the specified zone_mounts_t structure's fields.
 * This function doesn't free the memory occupied by the structure itself
 * (i.e., it doesn't free the parameter).
 */
void
zone_mounts_destroy(zone_mounts_t *mounts)
{
	assert(mounts != NULL);

	free(mounts->zonepath);
	if (mounts->root_mnttab != NULL)
		mnttab_destroy(mounts->root_mnttab);
}

/*
 * Mount a moving zone's root filesystem (if it had a root filesystem mount
 * prior to the move) using the specified zonepath.  mounts should refer to
 * the zone_mounts_t structure describing the zone's mount information.
 *
 * This function returns zero if the mount succeeds and a nonzero value
 * if it doesn't.
 */
int
zone_mount_rootfs(zone_mounts_t *mounts, const char *zonepath)
{
	char zoneroot[MAXPATHLEN];
	struct mnttab *mtab;
	int flags;

	assert(mounts != NULL);
	assert(zonepath != NULL);

	/*
	 * If there isn't a root filesystem, then don't do anything.
	 */
	mtab = mounts->root_mnttab;
	if (mtab == NULL)
		return (0);

	/*
	 * Determine the root filesystem's new mountpoint.
	 */
	if (snprintf(zoneroot, sizeof (zoneroot), "%s/root", zonepath) >=
	    sizeof (zoneroot)) {
		zerror(gettext("Zonepath %s is too long.\n"), zonepath);
		return (-1);
	}

	/*
	 * If the root filesystem is a non-legacy ZFS filesystem (i.e., if it's
	 * mnt_mountp field is non-NULL), then make the filesystem's new
	 * mount point its mountpoint property and mount the filesystem.
	 */
	if (mtab->mnt_mountp != NULL) {
		zfs_handle_t *zhp;

		if ((zhp = zfs_open(g_zfs, mtab->mnt_special,
		    ZFS_TYPE_DATASET)) == NULL) {
			zerror(gettext("could not get ZFS handle for the zone's"
			    " root filesystem"));
			return (-1);
		}
		if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
		    zoneroot) != 0) {
			zerror(gettext("could not modify zone's root "
			    "filesystem's mountpoint property"));
			zfs_close(zhp);
			return (-1);
		}
		if (zfs_mount(zhp, mtab->mnt_mntopts, 0) != 0) {
			zerror(gettext("unable to mount zone root %s: %s"),
			    zoneroot, libzfs_error_description(g_zfs));
			if (zfs_prop_set(zhp,
			    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
			    mtab->mnt_mountp) != 0)
				zerror(gettext("unable to restore zone's root "
				    "filesystem's mountpoint property"));
			zfs_close(zhp);
			return (-1);
		}
		zfs_close(zhp);
		return (0);
	}

	/*
	 * The root filesystem is either a legacy-mounted ZFS filesystem or
	 * a non-ZFS filesystem.  Use mount(2) to mount the root filesystem.
	 */
	if (mtab->mnt_mntopts != NULL)
		flags = MS_OPTIONSTR;
	else
		flags = 0;
	if (mount(mtab->mnt_special, zoneroot, flags, mtab->mnt_fstype, NULL, 0,
	    mtab->mnt_mntopts, MAX_MNTOPT_STR * sizeof (char)) != 0) {
		flags = errno;
		zerror(gettext("unable to mount zone root %s: %s"), zoneroot,
		    strerror(flags));
		return (-1);
	}
	return (0);
}

/*
 * Unmount a moving zone's root filesystem (if such a mount exists) using the
 * specified zonepath.  mounts should refer to the zone_mounts_t structure
 * describing the zone's mount information.  If force is B_TRUE, then if the
 * unmount fails, then the function will try to forcibly unmount the zone's root
 * filesystem.
 *
 * This function returns zero if the unmount (forced or otherwise) succeeds;
 * otherwise, it returns a nonzero value.
 */
int
zone_unmount_rootfs(zone_mounts_t *mounts, const char *zonepath,
    boolean_t force)
{
	char zoneroot[MAXPATHLEN];
	struct mnttab *mtab;
	int err;

	assert(mounts != NULL);
	assert(zonepath != NULL);

	/*
	 * If there isn't a root filesystem, then don't do anything.
	 */
	mtab = mounts->root_mnttab;
	if (mtab == NULL)
		return (0);

	/*
	 * Determine the root filesystem's mountpoint.
	 */
	if (snprintf(zoneroot, sizeof (zoneroot), "%s/root", zonepath) >=
	    sizeof (zoneroot)) {
		zerror(gettext("Zonepath %s is too long.\n"), zonepath);
		return (-1);
	}

	/*
	 * If the root filesystem is a non-legacy ZFS fileystem, then unmount
	 * the filesystem via libzfs.
	 */
	if (mtab->mnt_mountp != NULL) {
		zfs_handle_t *zhp;

		if ((zhp = zfs_open(g_zfs, mtab->mnt_special,
		    ZFS_TYPE_DATASET)) == NULL) {
			zerror(gettext("could not get ZFS handle for the zone's"
			    " root filesystem"));
			return (-1);
		}
		if (zfs_unmount(zhp, zoneroot, 0) != 0) {
			if (force && zfs_unmount(zhp, zoneroot, MS_FORCE) ==
			    0) {
				zfs_close(zhp);
				return (0);
			}
			zerror(gettext("unable to unmount zone root %s: %s"),
			    zoneroot, libzfs_error_description(g_zfs));
			zfs_close(zhp);
			return (-1);
		}
		zfs_close(zhp);
		return (0);
	}

	/*
	 * Use umount(2) to unmount the root filesystem.  If this fails, then
	 * forcibly unmount it if the force flag is set.
	 */
	if (umount(zoneroot) != 0) {
		if (force && umount2(zoneroot, MS_FORCE) == 0)
			return (0);
		err = errno;
		zerror(gettext("unable to unmount zone root %s: %s"), zoneroot,
		    strerror(err));
		return (-1);
	}
	return (0);
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
