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
/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfstab.h>
#include <sys/lofi.h>
#include <sys/ramdisk.h>
#include <sys/fssnap_if.h>
#include "libadm.h"

/*
 * Globals:
 *	getfullrawname - returns a fully-qualified raw device name
 *	getfullblkname - returns a fully-qualified block device name
 *
 * These two routines take a device pathname and return corresponding
 * the raw or block device name.
 *
 * First the device name is fully qualified:
 * 	If the device name does not start with a '/' or starts with
 *	'./' then the current working directory is added to the beginning
 *	of the pathname.
 *
 *	If the device name starts with a '../' then all but the last
 *	sub-directory of the current working directory is added to the
 *	the beginning of the pathname.
 *
 * Second if the fully-qualified device name given is the raw/block
 * device that is being asked for then the fully-qualified device name is
 * returned.
 *
 * Third if an entry is found in /etc/vfstab which matches the given name
 * then the corresponding raw/block device is returned.  This allows
 * non-standard names to be converted (.i.e., block device "/dev/joe" can
 * be converted to raw device "/dev/fred", via this mechanism).
 *
 * Last standard names are converted.  Standard names are those
 * with a '/dsk/' for block or '/rdsk/' for raw sub-directory components
 * in the device name. Or, the filename component has an 'r' for raw or
 * no 'r' for block (e.g., rsd0a <=> sd0a).
 *
 * Caveat:
 * It is assumed that the block and raw devices have the
 * same device number, and this is used to verify the conversion
 * happened corretly.  If this happens not to be true, due to mapping
 * of minor numbers or sometheing, then entries can be put in the
 * the '/etc/vfstab' file to over-ride this checking.
 *
 *
 * Return Values:
 * 	raw/block device name	- (depending on which routine is used)
 *	null string		- When the conversion failed
 *	null pointer		- malloc problems
 *
 * It is up to the user of these routines to free the memory, of
 * the device name or null string returned by these library routines,
 * when appropriate by the application.
 */
#define	GET_BLK	0
#define	GET_RAW	1

static int test_if_blk(char *, dev_t);
static int test_if_raw(char *, dev_t);
static char *getblkcomplete(char *, struct stat64 *);
static char *getrawcomplete(char *, struct stat64 *);

/*
 * getfullname() - Builds a fully qualified pathname.
 *		   This handles . and .. as well.
 *		   NOTE: This is different from realpath(3C) because
 *			 it does not follow links.
 */
static char *
getfullname(char *path)
{
	char	cwd[MAXPATHLEN];
	char	*c;
	char	*wa;
	size_t	len;

	if (*path == '/')
		return (strdup(path));

	if (getcwd(cwd, sizeof (cwd)) == NULL)
		return (strdup(""));

	/* handle . and .. */
	if (strncmp(path, "./", 2) == 0) {
		/* strip the ./ from the given path */
		path += 2;
	} else if (strncmp(path, "../", 3) == 0) {
		/* strip the last directory component from cwd */
		c = strrchr(cwd, '/');
		*c = '\0';

		/* strip the ../ from the given path */
		path += 3;
	}

	/*
	 * Adding 2 takes care of slash and null terminator.
	 */
	len = strlen(cwd) + strlen(path) + 2;
	if ((wa = malloc(len)) == NULL)
		return (NULL);

	(void) strcpy(wa, cwd);
	(void) strcat(wa, "/");
	(void) strcat(wa, path);

	return (wa);
}

/*
 * test the path/fname to see if is blk special
 */
static int
test_if_blk(char *new_path, dev_t raw_dev)
{
	struct stat64	buf;

	/* check if we got a char special file */
	if (stat64(new_path, &buf) != 0)
		return (0);

	if (!S_ISBLK(buf.st_mode))
		return (0);

	if (raw_dev != buf.st_rdev)
		return (0);

	return (1);
}

/*
 * test the path/fname to see if is char special
 */
static int
test_if_raw(char *new_path, dev_t blk_dev)
{
	struct stat64	buf;

	/* check if we got a char special file */
	if (stat64(new_path, &buf) != 0)
		return (0);

	if (!S_ISCHR(buf.st_mode))
		return (0);

	if (blk_dev != buf.st_rdev)
		return (0);

	return (1);
}

/*
 * complete getblkrawname() for blk->raw to handle volmgt devices
 */

static char *
getblkcomplete(char *cp, struct stat64 *dat)
{
	char 		*dp;
	char		*new_path;
	char		c;

	/* ok, so we either have a bad device or a floppy */

	/* try the rfd# form */
	if ((dp = strstr(cp, "/rfd")) != NULL) {
		if ((new_path = malloc(strlen(cp))) == NULL)
			return (NULL);

		c = *++dp;			/* save the 'r' */
		*dp = '\0';			/* replace it with a null */
		(void) strcpy(new_path, cp);	/* save first part of it */
		*dp++ = c;			/* give the 'r' back */
		(void) strcat(new_path, dp);	/* copy, skipping the 'r' */

		if (test_if_blk(new_path, dat->st_rdev))
			return (new_path);

		free(new_path);
		return (strdup(""));
	}

	/* try the rdiskette form */
	if ((dp = strstr(cp, "/rdiskette")) != NULL) {
		if ((new_path = malloc(strlen(cp))) == NULL)
			return (NULL);

		c = *++dp;			/* save the 'r' */
		*dp = '\0';			/* replace it with a null */
		(void) strcpy(new_path, cp);	/* save first part of it */
		*dp++ = c;			/* give the 'r' back */
		(void) strcat(new_path, dp);	/* copy, skipping the 'r' */

		if (test_if_blk(new_path, dat->st_rdev))
			return (new_path);

		free(new_path);
		return (strdup(""));
	}

	/* no match found */
	return (strdup(""));
}

/*
 * complete getfullrawname() for raw->blk to handle volmgt devices
 */

static char *
getrawcomplete(char *cp, struct stat64 *dat)
{
	char 		*dp;
	char		*new_path;
	char		c;

	/* ok, so we either have a bad device or a floppy */

	/* try the fd# form */
	if ((dp = strstr(cp, "/fd")) != NULL) {
		/* malloc path for new_path to hold raw */
		if ((new_path = malloc(strlen(cp)+2)) == NULL)
			return (NULL);

		c = *++dp;			/* save the 'f' */
		*dp = '\0';			/* replace it with a null */
		(void) strcpy(new_path, cp);	/* save first part of it */
		*dp = c;			/* put the 'f' back */
		(void) strcat(new_path, "r");	/* insert an 'r' */
		(void) strcat(new_path, dp);	/* copy the rest */

		if (test_if_raw(new_path, dat->st_rdev))
			return (new_path);

		free(new_path);
	}

	/* try the diskette form */
	if ((dp = strstr(cp, "/diskette")) != NULL) {
		/* malloc path for new_path to hold raw */
		if ((new_path = malloc(strlen(cp)+2)) == NULL)
			return (NULL);

		c = *++dp;			/* save at 'd' */
		*dp = '\0';			/* replace it with a null */
		(void) strcpy(new_path, cp);	/* save first part */
		*dp = c;			/* put the 'd' back */
		(void) strcat(new_path, "r");	/* insert an 'r' */
		(void) strcat(new_path, dp);	/* copy the rest */

		if (test_if_raw(new_path, dat->st_rdev))
			return (new_path);

		free(new_path);
		return (strdup(""));
	}

	/* failed to build raw name, return null string */
	return (strdup(""));



}

static char *
getvfsspecial(char *path, int raw_special)
{
	FILE		*fp;
	struct vfstab	vp;
	struct vfstab	ref_vp;

	if ((fp = fopen("/etc/vfstab", "r")) == NULL)
		return (NULL);

	(void) memset(&ref_vp, 0, sizeof (struct vfstab));

	if (raw_special)
		ref_vp.vfs_special = path;
	else
		ref_vp.vfs_fsckdev = path;

	if (getvfsany(fp, &vp, &ref_vp)) {
		(void) fclose(fp);
		return (NULL);
	}

	(void) fclose(fp);

	if (raw_special)
		return (vp.vfs_fsckdev);

	return (vp.vfs_special);
}

/*
 * change the device name to a block device name
 */
char *
getfullblkname(char *cp)
{
	struct stat64	buf;
	char		*dp;
	char		*new_path;
	dev_t		raw_dev;

	if (cp == NULL)
		return (strdup(""));

	/*
	 * Create a fully qualified name.
	 */
	if ((cp = getfullname(cp)) == NULL)
		return (NULL);

	if (*cp == '\0')
		return (cp);

	if (stat64(cp, &buf) != 0) {
		free(cp);
		return (strdup(""));
	}

	if (S_ISBLK(buf.st_mode))
		return (cp);

	if (!S_ISCHR(buf.st_mode)) {
		free(cp);
		return (strdup(""));
	}

	if ((dp = getvfsspecial(cp, GET_BLK)) != NULL) {
		free(cp);
		return (strdup(dp));
	}

	raw_dev = buf.st_rdev;

	/*
	 * We have a raw device name, go find the block name.
	 */
	if ((dp = strstr(cp, "/rdsk/")) == NULL &&
	    (dp = strstr(cp, "/" LOFI_CHAR_NAME "/")) == NULL &&
	    (dp = strstr(cp, "/" RD_CHAR_NAME "/")) == NULL &&
	    (dp = strstr(cp, "/" SNAP_CHAR_NAME "/")) == NULL &&
	    (dp = strrchr(cp, '/')) == NULL) {
		/* this is not really possible */
		free(cp);
		return (strdup(""));
	}
	dp++;
	if (*dp != 'r') {
		dp = getblkcomplete(cp, &buf);
		free(cp);
		return (dp);
	}
	if ((new_path = malloc(strlen(cp))) == NULL) {
		free(cp);
		return (NULL);
	}
	(void) strncpy(new_path, cp, dp - cp);

	/* fill in the rest of the unraw name */
	(void) strcpy(new_path + (dp - cp), dp + 1);

	if (test_if_blk(new_path, raw_dev)) {
		free(cp);
		/* block name was found, return it here */
		return (new_path);
	}
	free(new_path);

	dp = getblkcomplete(cp, &buf);
	free(cp);
	return (dp);
}

/*
 * change the device name to a raw devname
 */
char *
getfullrawname(char *cp)
{
	struct stat64	buf;
	char		*dp;
	char		*new_path;
	dev_t		blk_dev;

	if (cp == NULL)
		return (strdup(""));

	/*
	 * Create a fully qualified name.
	 */
	if ((cp = getfullname(cp)) == NULL)
		return (NULL);

	if (*cp == '\0')
		return (cp);

	if (stat64(cp, &buf) != 0) {
		free(cp);
		return (strdup(""));
	}

	if (S_ISCHR(buf.st_mode))
		return (cp);

	if (!S_ISBLK(buf.st_mode)) {
		free(cp);
		return (strdup(""));
	}

	blk_dev = buf.st_rdev;

	if ((dp = getvfsspecial(cp, GET_RAW)) != NULL) {
		free(cp);
		return (strdup(dp));
	}

	/*
	 * We have a block device name, go find the raw name.
	 */
	if ((dp = strstr(cp, "/dsk/")) == NULL &&
	    (dp = strstr(cp, "/" LOFI_BLOCK_NAME "/")) == NULL &&
	    (dp = strstr(cp, "/" RD_BLOCK_NAME "/")) == NULL &&
	    (dp = strstr(cp, "/" SNAP_BLOCK_NAME "/")) == NULL &&
	    (dp = strrchr(cp, '/')) == NULL) {
		/* this is not really possible */
		free(cp);
		return (strdup(""));
	}
	dp++;

	if ((new_path = malloc(strlen(cp)+2)) == NULL) {
		free(cp);
		return (NULL);
	}
	(void) strncpy(new_path, cp, dp - cp);
	/* fill in the rest of the raw name */
	new_path[dp - cp] = 'r';
	(void) strcpy(new_path + (dp - cp) + 1, dp);

	if (test_if_raw(new_path, blk_dev)) {
		free(cp);
		return (new_path);
	}
	free(new_path);

	dp = getrawcomplete(cp, &buf);
	free(cp);
	return (dp);
}
