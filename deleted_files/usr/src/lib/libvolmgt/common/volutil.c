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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<dirent.h>
#include	<fcntl.h>
#include	<string.h>
#include	<errno.h>
#include	<limits.h>
#include	<unistd.h>
#ifdef	DEBUG_IOCTL
#include	<sys/mkdev.h>
#endif
#include	<volmgt.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/vol.h>
#include	"volmgt_private.h"




const char	*volctl_name(void);

/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_running: check to see if volume management is running.
 *
 * arguments:
 *	none.
 *
 * return value(s):
 *	TRUE if volume management is running, FALSE if not.
 *
 * preconditions:
 *	none.
 */
int
volmgt_running(void)
{
	const char	*volctl_dev = volctl_name();
	int		res;


#ifdef	DEBUG
	denter("volmgt_running: entering\n");
#endif
	res = volmgt_inuse((char *)volctl_dev);
#ifdef	DEBUG
	dexit("volmgt_running: returning %s\n", res ? "TRUE" : "FALSE");
#endif
	return (res);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_inuse: check to see if volume management is currently
 *	managing a particular device.
 *
 * arguments:
 *	path - the name of the device in /dev.  For example,
 *	  "/dev/rdiskette".
 *
 * return value(s):
 *	TRUE if volume management is managing the device, FALSE if not.
 *
 * preconditions:
 *	none.
 */
int
volmgt_inuse(char *path)
{
	const char	*volctl_dev = volctl_name();
	struct stat64	sb;
	int		fd = -1;
	int		ret_val;



#ifdef	DEBUG
	denter("volmgt_inuse(%s): entering\n",
	    path != NULL ? path : "<null string>");
#endif
#ifdef	DEBUG_STAT
	dprintf("volmgt_inuse: stat()ing \"%s\"\n", path);
#endif
	if (stat64(path, &sb) < 0) {
		ret_val = FALSE;
		goto dun;
	}

#ifdef	DEBUG_OPEN
	dprintf("volmgt_inuse: open()ing \"%s\"\n", volctl_dev);
#endif
	if ((fd = open(volctl_dev, O_RDWR)) < 0) {
#ifdef	DEBUG
		perror(volctl_dev);
#endif
		ret_val = FALSE;
		goto dun;
	}

#ifdef	DEBUG_IOCTL
	dprintf("volmgt_inuse: ioctl(%s, VOLIOCINUSE)\n", volctl_dev);
#endif
	if (ioctl(fd, VOLIOCINUSE, sb.st_rdev) < 0) {
		ret_val = FALSE;
		goto dun;
	}
	ret_val = TRUE;
dun:
	if (fd >= 0) {
		(void) close(fd);
	}
#ifdef	DEBUG
	dexit("volmgt_inuse: returning %s\n", ret_val ? "TRUE" : "FALSE");
#endif
	return (ret_val);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_check: have volume management look at its devices to check
 *	for media having arrived.  Since volume management can't
 *	automatically check all types of devices, this function is provided
 *	to allow applications to cause the check to happen automatically.
 *
 * arguments:
 *	path - the name of the device in /dev.  For example,
 *	  /dev/rdiskette.  If path is NULL, all "checkable" devices are
 *	  checked.
 *
 * return value(s):
 *	TRUE if media was found in the device, FALSE if not.
 *
 * preconditions:
 *	volume management must be running.
 */
int
volmgt_check(char *path)
{
	const char	*volctl_dev = volctl_name();
	struct stat64	sb;
	int		fd = -1;
	int		ret_val;



#ifdef	DEBUG
	denter("volmgt_check(%s): entering\n",
	    path != NULL ? path : "<null string>");
#endif

	if (path != NULL) {
#ifdef	DEBUG_STAT
		dprintf("volmgt_check: stat()ing \"%s\"\n", path);
#endif
		if (stat64(path, &sb) < 0) {
			ret_val = FALSE;
			goto dun;
		}
	}

#ifdef	DEBUG_OPEN
	dprintf("volmgt_check: open()ing \"%s\"\n", volctl_dev);
#endif
	if ((fd = open(volctl_dev, O_RDWR)) < 0) {
#ifdef	DEBUG
		perror(volctl_dev);
#endif
		ret_val = FALSE;
		goto dun;
	}

	/* if "no device" specified, that means "all devices" */
	if (path == NULL) {
		sb.st_rdev = NODEV;
	}

#ifdef	DEBUG_IOCTL
	dprintf("volmgt_check: ioctl(%s, VOLIOCCHECK)\n", volctl_dev);
#endif
	if (ioctl(fd, VOLIOCCHECK, sb.st_rdev) < 0) {
		ret_val = FALSE;
		goto dun;
	}
	ret_val = TRUE;
dun:
	if (fd >= 0) {
		(void) close(fd);
	}
#ifdef	DEBUG
	dexit("volmgt_check: returning %s\n",
	    ret_val != NULL ? "TRUE" : "FALSE");
#endif
	return (ret_val);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_ownspath: check to see if the given path is contained in
 *	the volume management name space.
 *
 * arguments:
 *	path - string containing the path.
 *
 * return value(s):
 *	TRUE if the path is owned by volume management, FALSE if not.
 *	Will return FALSE if volume management isn't running.
 *
 * preconditions:
 *	none.
 */
int
volmgt_ownspath(char *path)
{
	static const char	*vold_root = NULL;
	static uint		vold_root_len;
	int			ret_val;



	if (vold_root == NULL) {
		vold_root = volmgt_root();
		vold_root_len = strlen(vold_root);
	}

	if (strncmp(path, vold_root, vold_root_len) == 0) {
		ret_val = TRUE;
	} else {
		ret_val = FALSE;
	}
	return (ret_val);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_root: return the root of where the volume management
 *	name space is mounted.
 *
 * arguments:
 *	none.
 *
 * return value(s):
 *	Returns a pointer to a static string containing the path to the
 *	volume management root (e.g. "/vol").
 *	Will return NULL if volume management isn't running.
 *
 * preconditions:
 *	none.
 */
const char *
volmgt_root(void)
{
	static char	vold_root[MAXPATHLEN+1] = "";
	struct vol_str	vstr;
	const char	*volctl_dev = volctl_name();
	int		fd = -1;


	vstr.data = vold_root;
	vstr.data_len = MAXPATHLEN;

#ifdef	DEBUG
	denter("volmgt_root: entering\n");
#endif

	if (*vold_root != NULLC) {
		goto dun;
	}

#ifdef	DEBUG_OPEN
	dprintf("volmgt_root: open()ing \"%s\"\n", volctl_dev);
#endif
	if ((fd = open(volctl_dev, O_RDWR)) < 0) {
#ifdef	DEBUG
		perror(volctl_dev);
#endif
		/* a guess is better than nothing? */
		(void) strncpy(vold_root, DEFAULT_ROOT, MAXPATHLEN);
		goto dun;
	}

#ifdef	DEBUG_IOCTL
	dprintf("volmgt_root: ioctl(%s, VOLIOCROOT)\n", volctl_dev);
#endif
	if (ioctl(fd, VOLIOCROOT, &vstr) < 0) {
#ifdef	DEBUG
		dprintf(
		"volmgt_root: ioctl(VOLIOCROOT) on \"%s\" failed (errno %d)\n",
		    volctl_dev, errno);
#endif
		(void) strncpy(vold_root, DEFAULT_ROOT, MAXPATHLEN);
		goto dun;
	}

dun:
	if (fd >= 0) {
		(void) close(fd);
	}
#ifdef	DEBUG
	dexit("volmgt_root: returning \"%s\"\n", vold_root);
#endif
	return ((const char *)vold_root);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_symname: Returns the volume management symbolic name
 *	for a given device.  If an application wants to determine
 *	what the symbolic name (e.g. "floppy0") for the /dev/rdiskette
 *	device would be, this is the function to use.
 *
 * arguments:
 *	path - a string containing the /dev device name.  For example,
 *	"/dev/diskette" or "/dev/rdiskette".
 *
 *	Note: must be a block- or char-spcl device, and have a non-zero
 *	st_rdev (real device) stat() value.
 *
 * return value(s):
 *	pointer to a string containing the symbolic name.
 *
 *	NULL indicates that volume management isn't managing that device.
 *
 *	The string must be free(3)'d.
 *
 * preconditions:
 *	none.
 */
char *
volmgt_symname(char *path)
{
	const char		*volctl_dev = volctl_name();
	int			fd = -1;
	struct stat64 		sb;
	struct vioc_symname	sn;
	char			*result = NULL;
	char			symbuf[VOL_SYMNAME_LEN+1] = "";



#ifdef	DEBUG
	denter("volmgt_symname(%s): entering\n", path ? path : "<null ptr>");
#endif

	/* just in case */
	if (path == NULL) {
#ifdef	DEBUG
		dprintf("volmgt_symname error: input path is null!\n");
#endif
		errno = EFAULT;
		goto dun;
	}

#ifdef	DEBUG_STAT
	dprintf("volmgt_symname: stat()ing \"%s\"\n", path);
#endif
	if (stat64(path, &sb) != 0) {
#ifdef	DEBUG
		dprintf("volmgt_symname error: can't stat \"%s\" (errno %d)\n",
		    path, errno);
#endif
		goto dun;
	}

	/* ensure we have a spcl device with a non-zero st_rdev */
	if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode)) {
#ifdef	DEBUG
		dprintf("volmgt_symname error: %s not blk- or chr-spcl\n",
		    path);
#endif
		errno = EINVAL;
		goto dun;
	}
	if (sb.st_rdev == (dev_t)0) {
#ifdef	DEBUG
		dprintf("volmgt_symname error: dev_t of %s is zero!\n",
		    path);
#endif
		errno = EINVAL;
	}

#ifdef	DEBUG_OPEN
	dprintf("volmgt_symname: open()ing \"%s\"\n", volctl_dev);
#endif
	if ((fd = open(volctl_dev, O_RDWR)) < 0) {
#ifdef	DEBUG
		dprintf("volmgt_symname error: can't open \"%s\" (errno %d)\n",
		    volctl_dev, errno);
#endif
		goto dun;
	}

	sn.sn_dev = sb.st_rdev;
	sn.sn_symname = symbuf;
	sn.sn_pathlen = VOL_SYMNAME_LEN;
#ifdef	DEBUG_IOCTL
	dprintf(
	    "volmgt_symname: ioctl(%s, VOLIOCSYMNAME, {%d.%d, %#x, %d})ing\n",
	    volctl_dev, major(sn.sn_dev), minor(sn.sn_dev), sn.sn_symname,
	    sn.sn_pathlen);
#endif
	if (ioctl(fd, VOLIOCSYMNAME, &sn) == 0) {
		result = strdup(symbuf);
	}
#ifdef	DEBUG
	else {
		dprintf(
		    "volmgt_symname: ioctl(VOLIOCSYMNAME) failed (errno %d)\n",
		    errno);
	}
#endif

dun:
	if (fd >= 0) {
		(void) close(fd);
	}

#ifdef	DEBUG
	dexit("volmgt_symname: returning \"%s\"\n",
	    result != NULL ? result : "<null ptr>");
#endif

	return (result);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_symdev: Returns the device given the volume management
 *	symbolic name. If an application wants to determine
 *	what the device associated with a particular symbolic name
 *	might be, this is the function to use.
 *
 * arguments:
 *	path - a string containing the symbolic device name.  For example,
 *	"cdrom0" or "floppy0".
 *
 * return value(s):
 *	pointer to a string containing the /dev name.
 *
 *	NULL indicates that volume management isn't managing that device.
 *
 *	The string must be free(3)'d.
 *
 * preconditions:
 *	none.
 */
char *
volmgt_symdev(char *symname)
{
	const char		*volctl_dev = volctl_name();
	int			fd = -1;
	struct vioc_symdev	sd;
	char			*result = NULL;
	char			devbuf[VOL_SYMDEV_LEN+1] = "";


#ifdef	DEBUG
	denter("volmgt_symdev(%s): entering\n", symname);
#endif

#ifdef	DEBUG_OPEN
	dprintf("volmgt_symdev: open()ing \"%s\"\n", volctl_dev);
#endif
	if ((fd = open(volctl_dev, O_RDWR)) < 0) {
#ifdef	DEBUG
		dprintf("volmgt_symdev error: can't open \"%s\" (errno %d)\n",
		    volctl_dev, errno);
#endif
		goto dun;
	}

	sd.sd_symname = symname;
	sd.sd_symnamelen = strlen(symname);
	sd.sd_symdevname = devbuf;
	sd.sd_pathlen = VOL_SYMDEV_LEN;
#ifdef	DEBUG_IOCTL
	dprintf("volmgt_symdev: ioctl(%s, VOLIOCSYMDEV)\n", volctl_dev);
	dprintf("sd.sd_symname = %s\n", sd.sd_symname);
	dprintf("sd.sd_symnamelen = %d\n", sd.sd_symnamelen);
	dprintf("sd.sd_symdevname = %s\n", sd.sd_symdevname);
	dprintf("sd.sd_pathlen = %d\n", sd.sd_pathlen);
	dprintf("---- make the ioctl for VOLIOCSYMDEV ----\n");
#endif

	if (ioctl(fd, VOLIOCSYMDEV, &sd) == 0) {
		result = strdup(devbuf);
	}

#ifdef	DEBUG
	else {
		dprintf(
		    "volmgt_symdev: VOLIOCSYMDEV ioctl failed (errno %d)\n",
		    errno);
	}
#endif

dun:
	if (fd >= 0) {
		(void) close(fd);
	}

#ifdef	DEBUG
	dexit("volmgt_symdev: returning \"%s\"\n",
	    result != NULL ? result : "<null ptr>");
#endif

	return (result);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	volmgt_feat_enabled: check to see if a volume management feature
 *	is available
 *
 * arguments:
 *	feat_str - a string containing the feature to be checked for
 *
 * return value(s):
 *	return non-zero if the specified feature is available in
 *	volume management, else return zero
 *
 * preconditions:
 *	none.
 */


/*
 * the following is a lit of the "feature" available in volmgt
 *
 * this list is meant to be updated when new features (that users may
 * want to use) are added to volmgt
 *
 * note: feature strings added should be all lower case, and spaces are
 * discouraged
 *
 * (see psarc/1995/138 for more info)
 */
static char	*volmgt_feat_list[] = {
#ifdef	DIRECT_DEV_ACCESS_WORKING
	"direct-dev-access",		/* access through /dev co-exists */
#endif
	"floppy-summit-interfaces",	/* volmgt_{acquire,release} */
	NULL
};


int
volmgt_feature_enabled(char *feat_str)
{
	int	i;
	char	*cp;
	int	res = 0;


	/* ensure no hoser can core dump us */
	if (feat_str == NULL) {
		errno = EFAULT;
		return (0);	/* I guess this isn't a match */
	}

	/* ensure feat string passed in is all lower case (as feats are) */
	for (cp = feat_str; *cp != NULLC; cp++) {
		if (isupper(*cp)) {
			*cp = _tolower(*cp);
		}
	}

	/* now scan for a match */
	for (i = 0; volmgt_feat_list[i] != NULL; i++) {
		if (strcmp(volmgt_feat_list[i], feat_str) == 0) {
			res++;
			break;
		}
	}

	return (res);
}
