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

/*
 * Routines to manage ZFS mounts.  We separate all the nasty routines that have
 * to deal with the OS.  The main entry points are:
 *
 * 	zfs_is_mounted()
 * 	zfs_mount()
 * 	zfs_unmount()
 * 	zfs_unmountall()
 *
 * These functions are used by mount and unmount, and when changing a
 * filesystem's mountpoint.  This file also contains the functions used to
 * manage sharing filesystems via NFS:
 *
 * 	zfs_is_shared()
 * 	zfs_share()
 * 	zfs_unshare()
 * 	zfs_unshareall()
 */

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <zone.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <libzfs.h>

#include "libzfs_impl.h"


/*
 * The following two files are opened as part of zfs_init().  It's OK to for
 * the sharetab to be NULL, but mnttab must always be non-NULL;
 */
FILE *mnttab_file;
FILE *sharetab_file;

/*
 * Search the sharetab for the given mountpoint, returning TRUE if it is found.
 */
static int
is_shared(const char *mountpoint)
{
	char buf[MAXPATHLEN], *tab;

	if (sharetab_file == NULL)
		return (0);

	(void) fseek(sharetab_file, 0, SEEK_SET);

	while (fgets(buf, sizeof (buf), sharetab_file) != NULL) {

		/* the mountpoint is the first entry on each line */
		if ((tab = strchr(buf, '\t')) != NULL) {
			*tab = '\0';
			if (strcmp(buf, mountpoint) == 0)
				return (1);
		}
	}

	return (0);
}

/*
 * Returns TRUE if the specified directory is empty.  If we can't open the
 * directory at all, return TRUE so that the mount can fail with a more
 * informative error message.
 */
static int
dir_is_empty(const char *dirname)
{
	DIR *dirp;
	struct dirent64 *dp;

	if ((dirp = opendir(dirname)) == NULL)
		return (TRUE);

	while ((dp = readdir64(dirp)) != NULL) {

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		(void) closedir(dirp);
		return (FALSE);
	}

	(void) closedir(dirp);
	return (TRUE);
}

/*
 * Checks to see if the mount is active.  If the filesystem is mounted, we fill
 * in 'where' with the current mountpoint, and return 1.  Otherwise, we return
 * 0.
 */
int
zfs_is_mounted(zfs_handle_t *zhp, char **where)
{
	struct mnttab search = { 0 }, entry;

	/*
	 * Search for the entry in /etc/mnttab.  We don't bother getting the
	 * mountpoint, as we can just search for the special device.  This will
	 * also let us find mounts when the mountpoint is 'legacy'.
	 */
	search.mnt_special = (char *)zfs_get_name(zhp);

	rewind(mnttab_file);
	if (getmntany(mnttab_file, &entry, &search) != 0)
		return (FALSE);

	if (where != NULL)
		*where = zfs_strdup(entry.mnt_mountp);

	return (TRUE);
}

/*
 * Mount the given filesystem.
 */
int
zfs_mount(zfs_handle_t *zhp, const char *options, int flags)
{
	struct stat buf;
	char mountpoint[ZFS_MAXPROPLEN];
	char mntopts[MNT_LINE_MAX];

	if (options == NULL)
		mntopts[0] = '\0';
	else
		(void) strlcpy(mntopts, options, sizeof (mntopts));

	/* ignore non-filesystems */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, FALSE) != 0)
		return (0);

	/* return success if there is no mountpoint set */
	if (strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) == 0 ||
	    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0)
		return (0);

	/*
	 * If the 'zoned' property is set, and we're in the global zone, simply
	 * return success.
	 */
	if (zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		char zonename[ZONENAME_MAX];
		if (getzonenamebyid(getzoneid(), zonename,
		    sizeof (zonename)) < 0) {
			zfs_error(dgettext(TEXT_DOMAIN, "internal error: "
			    "cannot determine current zone"));
			return (1);
		}

		if (strcmp(zonename, "global") == 0)
			return (0);
	}

	/* Create the directory if it doesn't already exist */
	if (lstat(mountpoint, &buf) != 0) {
		if (mkdirp(mountpoint, 0755) != 0) {
			zfs_error(dgettext(TEXT_DOMAIN, "cannot mount '%s': "
			    "unable to create mountpoint"), mountpoint);
			return (1);
		}
	}

	/*
	 * Determine if the mountpoint is empty.  If so, refuse to perform the
	 * mount.  We don't perform this check if MS_OVERLAY is specified, which
	 * would defeat the point.  We also avoid this check if 'remount' is
	 * specified.
	 */
	if ((flags & MS_OVERLAY) == 0 &&
	    strstr(mntopts, MNTOPT_REMOUNT) == NULL &&
	    !dir_is_empty(mountpoint)) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot mount '%s': "
		    "directory is not empty"), mountpoint);
		zfs_error(dgettext(TEXT_DOMAIN, "use legacy mountpoint to "
		    "allow this behavior, or use the -O flag"));
		return (1);
	}

	/* perform the mount */
	if (mount(zfs_get_name(zhp), mountpoint, MS_OPTIONSTR | flags,
	    MNTTYPE_ZFS, NULL, 0, mntopts, sizeof (mntopts)) != 0) {
		/*
		 * Generic errors are nasty, but there are just way too many
		 * from mount(), and they're well-understood.  We pick a few
		 * common ones to improve upon.
		 */
		switch (errno) {
		case EBUSY:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot mount '%s': "
			    "mountpoint '%s' is busy"), zhp->zfs_name,
			    mountpoint);
			break;
		case EPERM:
		case EACCES:
			zfs_error(dgettext(TEXT_DOMAIN, "cannot mount '%s': "
			    "permission denied"), zhp->zfs_name,
			    mountpoint);
			break;
		default:
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot mount '%s': %s"),
			    mountpoint, strerror(errno));
			break;
		}
		return (1);
	}

	return (0);
}

/*
 * Unmount the given filesystem.
 */
int
zfs_unmount(zfs_handle_t *zhp, const char *mountpoint, int flags)
{
	struct mnttab search = { 0 }, entry;

	/* check to see if need to unmount the filesystem */
	search.mnt_special = (char *)zfs_get_name(zhp);
	rewind(mnttab_file);
	if (mountpoint != NULL || ((zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) &&
	    getmntany(mnttab_file, &entry, &search) == 0)) {

		if (mountpoint == NULL)
			mountpoint = entry.mnt_mountp;

		/*
		 * Always unshare the filesystem first.
		 */
		if (zfs_unshare(zhp, mountpoint) != 0)
			return (-1);

		/*
		 * Try to unmount the filesystem.  There is no reason to try a
		 * forced unmount because the vnodes will still carry a
		 * reference to the underlying dataset, so we can't destroy it
		 * anyway.
		 *
		 * In the unmount case, we print out a slightly more informative
		 * error message, though we'll be relying on the poor error
		 * semantics from the kernel.
		 */
		if (umount2(mountpoint, flags) != 0) {
			zfs_error(dgettext(TEXT_DOMAIN,
			    "cannot unmount '%s': %s"),
			    mountpoint, strerror(errno));
			return (-1);
		}

		/*
		 * Don't actually destroy the underlying directory
		 */
	}

	return (0);
}

/*
 * Unmount this filesystem and any children inheriting the mountpoint property.
 * To do this, just act like we're changing the mountpoint property, but don't
 * remount the filesystems afterwards.
 */
int
zfs_unmountall(zfs_handle_t *zhp, int flags)
{
	prop_changelist_t *clp;
	int ret;

	clp = changelist_gather(zhp, ZFS_PROP_MOUNTPOINT, flags);
	if (clp == NULL)
		return (-1);

	ret = changelist_prefix(clp);
	changelist_free(clp);

	return (ret);
}

/*
 * Check to see if the filesystem is currently shared.
 */
int
zfs_is_shared(zfs_handle_t *zhp, char **where)
{
	char *mountpoint;

	if (!zfs_is_mounted(zhp, &mountpoint))
		return (FALSE);

	if (is_shared(mountpoint)) {
		if (where != NULL)
			*where = mountpoint;
		else
			free(mountpoint);
		return (TRUE);
	} else {
		free(mountpoint);
		return (FALSE);
	}
}

/*
 * Share the given filesystem according to the options in 'sharenfs'.  We rely
 * on share(1M) to the dirty work for us.
 */
int
zfs_share(zfs_handle_t *zhp)
{
	char mountpoint[ZFS_MAXPROPLEN];
	char shareopts[ZFS_MAXPROPLEN];
	char buf[MAXPATHLEN];
	FILE *fp;

	/* ignore non-filesystems */
	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM)
		return (0);

	/* return success if there is no mountpoint set */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT,
	    mountpoint, sizeof (mountpoint), NULL, NULL, 0, FALSE) != 0 ||
	    strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) == 0 ||
	    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0)
		return (0);

	/* return success if there are no share options */
	if (zfs_prop_get(zhp, ZFS_PROP_SHARENFS, shareopts, sizeof (shareopts),
	    NULL, NULL, 0, FALSE) != 0 ||
	    strcmp(shareopts, "off") == 0)
		return (0);

	/*
	 * If the 'zoned' property is set, simply return success since:
	 * 1. in a global zone, a dataset should not be shared if it's
	 *    managed in a local zone.
	 * 2. in a local zone, NFS server is not available.
	 */
	if (zfs_prop_get_int(zhp, ZFS_PROP_ZONED)) {
		return (0);
	}

	/*
	 * Invoke the share(1M) command.  We always do this, even if it's
	 * currently shared, as the options may have changed.
	 */
	if (strcmp(shareopts, "on") == 0)
		(void) snprintf(buf, sizeof (buf), "/usr/sbin/share "
		    "-F nfs \"%s\" 2>&1", mountpoint);
	else
		(void) snprintf(buf, sizeof (buf), "/usr/sbin/share "
		    "-F nfs -o \"%s\" \"%s\" 2>&1", shareopts,
		    mountpoint);

	if ((fp = popen(buf, "r")) == NULL) {
		zfs_error(dgettext(TEXT_DOMAIN, "cannot share '%s': "
		    "share(1M) failed"), zfs_get_name(zhp));
		return (-1);
	}

	/*
	 * share(1M) should only produce output if there is some kind
	 * of error.  All output begins with "share_nfs: ", so we trim
	 * this off to get to the real error.
	 */
	if (fgets(buf, sizeof (buf), fp) != NULL) {
		char *colon = strchr(buf, ':');

		while (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		if (colon == NULL)
			zfs_error(dgettext(TEXT_DOMAIN, "cannot share "
			    "'%s': share(1M) failed"),
			    zfs_get_name(zhp));
		else
			zfs_error(dgettext(TEXT_DOMAIN, "cannot share "
			    "'%s': %s"), zfs_get_name(zhp),
			    colon + 2);

		verify(pclose(fp) != 0);
		return (-1);
	}

	verify(pclose(fp) == 0);

	return (0);
}

/*
 * Unshare the given filesystem.
 */
int
zfs_unshare(zfs_handle_t *zhp, const char *mountpoint)
{
	char buf[MAXPATHLEN];
	struct mnttab search = { 0 }, entry;

	/* check to see if need to unmount the filesystem */
	search.mnt_special = (char *)zfs_get_name(zhp);
	rewind(mnttab_file);
	if (mountpoint != NULL || ((zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) &&
	    getmntany(mnttab_file, &entry, &search) == 0)) {

		if (mountpoint == NULL)
			mountpoint = entry.mnt_mountp;

		if (is_shared(mountpoint)) {
			FILE *fp;

			(void) snprintf(buf, sizeof (buf),
			    "/usr/sbin/unshare  \"%s\" 2>&1",
			    mountpoint);

			if ((fp = popen(buf, "r")) == NULL) {
				zfs_error(dgettext(TEXT_DOMAIN, "cannot "
				    "unshare '%s': unshare(1M) failed"),
				    zfs_get_name(zhp));
				return (-1);
			}

			/*
			 * unshare(1M) should only produce output if there is
			 * some kind of error.  All output begins with "unshare
			 * nfs: ", so we trim this off to get to the real error.
			 */
			if (fgets(buf, sizeof (buf), fp) != NULL) {
				char *colon = strchr(buf, ':');

				while (buf[strlen(buf) - 1] == '\n')
					buf[strlen(buf) - 1] = '\0';

				if (colon == NULL)
					zfs_error(dgettext(TEXT_DOMAIN,
					    "cannot unshare '%s': unshare(1M) "
					    "failed"), zfs_get_name(zhp));
				else
					zfs_error(dgettext(TEXT_DOMAIN,
					    "cannot unshare '%s': %s"),
					    zfs_get_name(zhp), colon + 2);

				verify(pclose(fp) != 0);
				return (-1);
			}

			verify(pclose(fp) == 0);
		}
	}

	return (0);
}

/*
 * Same as zfs_unmountall(), but for unshares.
 */
int
zfs_unshareall(zfs_handle_t *zhp)
{
	prop_changelist_t *clp;
	int ret;

	clp = changelist_gather(zhp, ZFS_PROP_SHARENFS, 0);
	if (clp == NULL)
		return (-1);

	ret = changelist_unshare(clp);
	changelist_free(clp);

	return (ret);
}

/*
 * Remove the mountpoint associated with the current dataset, if necessary.
 * We only remove the underlying directory if:
 *
 *	- The mountpoint is not 'none' or 'legacy'
 *	- The mountpoint is non-empty
 *	- The mountpoint is the default or inherited
 *	- The 'zoned' property is set, or we're in a local zone
 *
 * Any other directories we leave alone.
 */
void
remove_mountpoint(zfs_handle_t *zhp)
{
	char mountpoint[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t sourcetype;
	char zonename[ZONENAME_MAX];

	/* ignore non-filesystems */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), &sourcetype, source, sizeof (source),
	    FALSE) != 0)
		return;

	if (getzonenamebyid(getzoneid(), zonename, sizeof (zonename)) < 0)
		zfs_fatal(dgettext(TEXT_DOMAIN, "internal error: "
		    "cannot determine current zone"));

	if (strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) != 0 &&
	    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) != 0 &&
	    (sourcetype == ZFS_SRC_DEFAULT ||
	    sourcetype == ZFS_SRC_INHERITED) &&
	    (!zfs_prop_get_int(zhp, ZFS_PROP_ZONED) ||
	    strcmp(zonename, "global") != 0)) {

		/*
		 * Try to remove the directory, silently ignoring any errors.
		 * The filesystem may have since been removed or moved around,
		 * and this isn't really useful to the administrator in any
		 * way.
		 */
		(void) rmdir(mountpoint);
	}
}
