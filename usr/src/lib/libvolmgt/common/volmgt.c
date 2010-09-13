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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include	<sys/mkdev.h>
#include	<volmgt.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	"volmgt_private.h"

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
	/* vold is dead */
	return (FALSE);
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
/* ARGSUSED */
int
volmgt_inuse(char *path)
{
	return (FALSE);
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
/* ARGSUSED */
int
volmgt_check(char *path)
{
	return (FALSE);
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
/* ARGSUSED */
int
volmgt_ownspath(char *path)
{
	return (FALSE);
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
	static const char *vold_root = "/dev";

	return (vold_root);
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
/* ARGSUSED */
char *
volmgt_symname(char *path)
{
	return (NULL);
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
/* ARGSUSED */
char *
volmgt_symdev(char *symname)
{
	return (NULL);
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
	return (0);
}
/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	uncommitted
 *
 * description:
 *	volmgt_acquire: try to acquire the volmgt advisory device reservation
 *	for a specific device.
 *
 * arguments:
 *	dev - a device name to attempt reserving.  This string can be:
 *		- a full path name to a device
 *		- a symbolic device name (e.g. floppy0)
 *
 *	id  - a reservation string that hopefully describes the application
 *		making this reservation.
 *
 *	pid - a pointer to a pid_t type.  If this argument is not NULL
 *		and the requested device is already reserved, the process
 *		id of the reservation owner will be returned in this
 *		location.
 *
 *	ovr - an override indicator.  If set to non-zero, the caller requests
 *		that this reservation be made unconditionally.
 *
 *	err - the address of a pointer to a string which is to receive the
 *		id argument used when the current device was reserved.  This
 *		is only used when the current reservation attempt fails due
 *		to an already existing reservation for this device.
 *
 * return value(s):
 *	A non-zero indicator if successful.
 *
 *	A zero indicator if unsuccessful.  If errno is EBUSY, then the err
 *	argument will be set to point to the string that the process currently
 *	holding the reservation supplied when reserving the device.  It is up
 *	to the caller to release the storage occupied by the string via
 *	free(3C) when no longer needed.
 *
 * preconditions:
 *	none
 */
/* ARGSUSED */
int
volmgt_acquire(char *dev, char *id, int ovr, char **err, pid_t *pidp)
{
	return (0);
}


/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	uncommitted
 *
 * description:
 *	volmgt_release: try to release the volmgt advisory device reservation
 *	for a specific device.
 *
 * arguments:
 *	dev - a device name to attempt reserving.  This string can be:
 *		- a full path name to a device
 *		- a symbolic device name (e.g. floppy0)
 *
 * return value(s):
 *	A non-zero indicator if successful
 *	A zero indicator if unsuccessful
 *
 * preconditions:
 *	none
 */
int
volmgt_release(char *dev)
{
	return (0);
}


/*
 * returns the "value" of the attribute.
 * If the attribute is boolean and is TRUE,
 * "true" is returned.  If the boolean is
 * FALSE, NULL is returned.  If the attribute
 * doesn't exist, NULL is returned.  The pointer
 * returned by media_getattr has been malloc'd and
 * it is the callers responsibility to free it.
 */
/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	media_getattr: returns the value for an attribute for a piece of
 * 	removable media.
 *
 * arguments:
 *	path - Path to the media in /vol.  Can be the block or character
 *		device.
 *
 *	attr - name of the attribute.
 *
 * return value(s):
 *	returns NULL or a pointer to a string that contains the value for
 * 	the requested attribute.
 *
 *	NULL can mean:
 *	 - the media doesn't exist
 *	 - there is no more space for malloc(3)
 *	 - the attribute doesn't exist for the named media
 *	 - the attribute is a boolean and is FALSE
 *
 *	the pointer to the string must be free'd with free(3).
 *
 * preconditions:
 *	volume management (vold) must be running.
 */
/* ARGSUSED */
char *
media_getattr(char *vol_path, char *attr)
{
	return (NULL);
}


/*
 * sets the attribute "attr" to value "value".
 *
 * If value == "" the flag is
 * considered to be a TRUE boolean.
 *
 * If value == 0, it is considered to be a FALSE boolean.
 * returns TRUE on success, FALSE on failure.
 *
 * Can fail for reasons of permission, or if you
 * write a read-only attribute.
 */

/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	media_setattr: set an attribute for a piece of media to a
 *	particular value.
 *
 * arguments:
 *	path - Path to the media in /vol.  Can be the block or character
 *		device.
 *
 *	attr - name of the attribute.
 *
 *	value - value of the attribute.  If value == "", the flag is
 *		considered to be a boolean that is TRUE.  If value == 0, it
 *		is considered to be a FALSE boolean.
 *
 * return value(s):
 *	TRUE on success, FALSE for failure.
 *
 *	Can fail because:
 *		- don't have permission to set the attribute because caller
 *		  is not the owner of the media and attribute is a "system"
 *		  attribute.
 *
 *		- don't have permission to set the attribute because the
 *		  attribute is a "system" attribute and is read-only.
 *
 * preconditions:
 *	volume management must be running.
 */
/* ARGSUSED */
int
media_setattr(char *vol_path, char *attr, char *value)
{
	return (FALSE);
}


/*
 * Returns the "id" of a volume.  If the returned value
 * & VOLID_TMP, the volume is temporary and this value
 * cannot be relied upon across reboots.
 */
/*
 * arc approved interface
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	media_getid: return the "id" of a piece of media.
 *
 * arguments:
 *	path - Path to the media in /vol.  Can be the block or character
 *		device.
 * return value(s):
 *	returns a u_longlong_t that is the "id" of the volume.
 *
 * preconditions:
 *	volume management must be running.
 */
u_longlong_t
media_getid(char *vol_path)
{
	return (0);
}
/*
 * arc approved interface (pending)
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	media_findname: try to come up with the character device when
 *	provided with a starting point.  This interface provides the
 *	application programmer to provide "user friendly" names and
 *	easily determine the "/vol" name.
 *
 * arguments:
 *	start - a string describing a device.  This string can be:
 *		- a full path name to a device (insures it's a
 *		  character device by using getfullrawname()).
 *		- a full path name to a volume management media name
 *		  with partitions (will return the lowest numbered
 *		  raw partition.
 *		- the name of a piece of media (e.g. "fred").
 *		- a symbolic device name (e.g. floppy0, cdrom0, etc)
 *		- a name like "floppy" or "cdrom".  Will pick the lowest
 *		  numbered device with media in it.
 *
 * return value(s):
 *	A pointer to a string that contains the character device
 *	most appropriate to the "start" argument.
 *
 *	NULL indicates that we were unable to find media based on "start".
 *
 *	The string must be free(3)'d.
 *
 * preconditions:
 *	none.
 */
/* ARGSUSED */
char *
media_findname(char *start)
{
	/*
	 * Eventually should implement using HAL interfaces.
	 * In the short term however, return NULL for aliases,
	 * and self for absolute pathnames.
	 */
	if (start[0] == '/') {
		return (strdup(start));
	} else {
		return (NULL);
	}
}

struct alias {
	char	*alias;
	char	*name;
};

/*
 * "old" aliases -- used to be used when vold wasn't running
 */
static struct alias device_aliases[] = {
	{ "fd", "/dev/rdiskette" },
	{ "fd0", "/dev/rdiskette" },
	{ "fd1", "/dev/rdiskette1" },
	{ "diskette", "/dev/rdiskette" },
	{ "diskette0", "/dev/rdiskette0" },
	{ "diskette1", "/dev/rdiskette1" },
	{ "rdiskette", "/dev/rdiskette" },
	{ "rdiskette0", "/dev/rdiskette0" },
	{ "rdiskette1", "/dev/rdiskette1" },
	{ "floppy", "/dev/rdiskette" },
	{ "floppy0", "/dev/rdiskette0" },
	{ "floppy1", "/dev/rdiskette1" },
	{ "cd", "cdrom0" },
	{ "cd0", "cdrom0" },
	{ "cd1", "cdrom1" },
	{ NULL, NULL }
};

/*
 * This is an ON Consolidation Private interface.
 */
/* ARGSUSED */
char *
_media_oldaliases(char *start)
{
	struct alias	*s;
	char		*p;
	char		*res = NULL;

	for (s = device_aliases; s->alias != NULL; s++) {
		if (strcmp(start, s->alias) == 0) {
			res = strdup(s->name);
			break;
		}
	}

	return (res);
}


/*
 * This is an ON Consolidation Private interface.
 *
 * Print out the aliases available to the program user.  Changes
 * depending in whether volume management is running.
 */
void
_media_printaliases(void)
{
}
