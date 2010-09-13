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
 * Copyright (c) 1993, by Sun Microsystems, Inc.
 */

#ifndef	_VOLMGT_H
#define	_VOLMGT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * volmgt_check:
 *	have volume management look at its devices to check
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
 */
int volmgt_check(char *path);

/*
 * volmgt_inuse:
 *	check to see if volume management is currently
 *	managing a particular device.
 *
 * arguments:
 *	path - the name of the device in /dev.  For example,
 *	  "/dev/rdiskette".
 *
 * return value(s):
 *	TRUE if volume management is managing the device, FALSE if not.
 */
int volmgt_inuse(char *path);

/*
 * volmgt_running:
 *	check to see if volume management is running.
 *
 * arguments:
 *	none.
 *
 * return value(s):
 *	TRUE if volume management is running, FALSE if not.
 */
int volmgt_running(void);

/*
 * volmgt_symname:
 *	Returns the volume management symbolic name
 *	for a given device.  If an application wants to determine
 *	what the symbolic name (e.g. "floppy0") for the /dev/rdiskette
 *	device would be, this is the function to use.
 *
 * arguments:
 *	path - a string containing the /dev device name.  For example,
 *	"/dev/diskette" or "/dev/rdiskette".
 *
 * return value(s):
 *	pointer to a string containing the symbolic name.
 *
 *	NULL indicates that volume management isn't managing that device.
 *
 *	The string must be free(3)'d.
 */
char 	*volmgt_symname(char *path);

/*
 * volmgt_symdev:
 *	Returns the device given the volume management
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
 */
char 	*volmgt_symdev(char *symname);

/*
 * volmgt_ownspath:
 *	check to see if the given path is contained in
 *	the volume management name space.
 *
 * arguments:
 *	path - string containing the path.
 *
 * return value(s):
 *	TRUE if the path is owned by volume management, FALSE if not.
 *	Will return FALSE if volume management isn't running.
 *
 */
int	volmgt_ownspath(char *path);

/*
 * volmgt_root:
 *	return the root of where the volume management
 *	name space is mounted.
 *
 * arguments:
 *	none.
 *
 * return value(s):
 *	Returns a pointer to a string containing the path to the
 *	volume management root (e.g. "/vol").
 *	Will return NULL if volume management isn't running.
 */
const char 	*volmgt_root(void);

/*
 * media_findname:
 *	try to come up with the character device when
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
 */
char 	*media_findname(char *start);

/*
 * media_getattr:
 *	returns the value for an attribute for a piece of
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
 */
char *media_getattr(char *path, char *attr);

/*
 * media_setattr:
 *	set an attribute for a piece of media to a
 *	particular value.
 *
 * arguments:
 *	path - Path to the media in /vol.  Can be the block or character
 *		device.
 *
 *	attr - name of the attribute.
 *
 *	value - value of the attribute.  If value == "", the flag is
 *	    considered to be a boolean that is TRUE.  If value == 0, it
 *	    is considered to be a FALSE boolean.
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
 */
int	media_setattr(char *path, char *attr, char *value);

/*
 * media_getid:
 *	return the "id" of a piece of media.
 *
 * arguments:
 *	path - Path to the media in /vol.  Can be the block or character
 *		device.
 * return value(s):
 *	returns a u_longlong_t that is the "id" of the volume.
 *
 */
u_longlong_t	media_getid(char *path);

/*
 * volmgt_feature_enabled:
 *	check to see if a volume management feature is available
 *
 * arguments:
 *	feat_str - a string containing the feature to be checked for
 *
 * return value(s):
 *	returns non-zero if the specified feature is available
 *	in volume management, else return zero
 */
int	volmgt_feature_enabled(char *feat_str);

/*
 * volmgt_acquire
 *	try to acquire the volmgt advisory device reservation
 *	for a specific device. -- if volmgt isn't running then try to
 *	reserve the device specified
 *
 * arguments:
 *	dev - a device name to attempt reserving.  This string can be:
 *		- a full path name to a device in /vol if volmgt is running
 *		- a symbolic device name (e.g. floppy0) if volmgt is running
 *		- a /dev pathname if volmgt is not running
 *
 *	id  - a reservation string that hopefully describes the application
 *		making this reservation.
 *
 *	ovr - an override indicator.  If set to non-zero, the caller requests
 *		that this reservation be made unconditionally.
 *
 *	err - the address of a char ptr that will updated to point to the
 *		id argument used when the current device was reserved.  This
 *		is only used when the current reservation attempt fails due
 *		to an already existing reservation for this device.
 *
 *	pidp - a pointer to a pid_t type.  If this argument is not NULL
 *		and the requested device is already reserved, the process
 *		id of the reservation owner will be returned in this
 *		location.
 *
 *
 * return value(s):
 *	A non-zero indicator if successful.
 *
 *	A zero indicator if unsuccessful.  If errno is EBUSY, then the err
 *	argument will be set to point to the string that the process currently
 *	holding the reservation supplied when reserving the device.  It is up
 *	to the caller to release the storage occupied by the string via
 *	free(3C) when no longer needed.
 */
int	volmgt_acquire(char *dev, char *id, int ovr, char **err, pid_t *pidp);

/*
 * the max length for the "id" string in volmgt_acquire
 */
#define	VOL_RSV_MAXIDLEN	256

/*
 * volmgt_release:
 *	try to release the volmgt advisory device reservation
 *	for a specific device.
 *
 * arguments:
 *	dev - a device name to attempt reserving.  This string can be:
 *		- a full path name to a device in /vol if volmgt is running
 *		- a symbolic device name (e.g. floppy0) if volmgt is running
 *		- a /dev pathname if volmgt is not running
 *
 * return value(s):
 *	A non-zero indicator if successful
 *	A zero indicator if unsuccessful
 *
 * preconditions:
 *	none
 */
int	volmgt_release(char *dev);

#ifdef	__cplusplus
}
#endif

#endif	/* _VOLMGT_H */
