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

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/vol.h>
#include <errno.h>

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
char *
media_getattr(char *vol_path, char *attr)
{
	int			fd = -1;
	struct stat64		sb;
	char 			valuebuf[MAX_ATTR_LEN+1];
	struct vioc_gattr	ga;
	char			*res;


	if ((fd = open(vol_path, O_RDONLY|O_NDELAY)) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = NULL;
		goto dun;
	}

	if (fstat64(fd, &sb) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = NULL;
		goto dun;
	}

	/* ensure we have either a blk- or char-spcl device */
	if (!S_ISBLK(sb.st_mode) && !S_ISCHR(sb.st_mode)) {
#ifdef	DEBUG
		(void) fprintf(stderr,
		    "media_getattr: %s not a block or raw device\n",
		    vol_path);
#endif
		res = NULL;
		goto dun;
	}

	ga.ga_value = valuebuf;
	ga.ga_val_len = MAX_ATTR_LEN;
	ga.ga_attr = attr;
	ga.ga_attr_len = strlen(attr);

	/* try to get the attribute */
	if (ioctl(fd, VOLIOCGATTR, &ga) < 0) {
		/* errno ENOENT here just means prop not found */
#ifdef	DEBUG
		if (errno != ENOENT) {
			perror(vol_path);
		}
#endif
		res = NULL;
		goto dun;
	}

	/* successfully got the attribute */
	res = strdup(valuebuf);

dun:
	if (fd >= 0) {
		(void) close(fd);
	}
	return (res);
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
int
media_setattr(char *vol_path, char *attr, char *value)
{
	int			fd = -1;
	struct stat64		sb;
	struct vioc_sattr	sa;
	int			res;


	if ((fd = open(vol_path, O_RDONLY|O_NDELAY)) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = FALSE;
		goto dun;
	}

	if (fstat64(fd, &sb) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = FALSE;
		goto dun;
	}

	/* ensure we have either a blk- or char-spcl device */
	if (!S_ISBLK(sb.st_mode) && !S_ISCHR(sb.st_mode)) {
#ifdef	DEBUG
		(void) fprintf(stderr,
		    "media_setattr: %s not a block or raw device\n",
		    vol_path);
#endif
		res = FALSE;
		goto dun;
	}

	sa.sa_attr = attr;
	sa.sa_attr_len = strlen(attr);
	sa.sa_value = value;
	sa.sa_value_len = strlen(value);

	/* try to set the attribute */
	if (ioctl(fd, VOLIOCSATTR, &sa) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = FALSE;
		goto dun;
	}

	/* successfully set the attribute */
	res = TRUE;

dun:
	if (fd >= 0) {
		(void) close(fd);
	}
	return (res);
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
	int			fd = -1;
	struct stat64		sb;
	char 			path[MAXNAMELEN+1];
	struct vioc_info	info;
	u_longlong_t		res;


	if ((fd = open(vol_path, O_RDONLY|O_NDELAY)) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = 0;
		goto dun;

	}

	if (fstat64(fd, &sb) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = 0;
		goto dun;
	}

	/* ensure we have either a blk- or char-spcl device */
	if (!S_ISBLK(sb.st_mode) && !S_ISCHR(sb.st_mode)) {
#ifdef	DEBUG
		(void) fprintf(stderr,
		    "media_getid: %s not a block or raw device\n",
		    vol_path);
#endif
		res = 0;
		goto dun;
	}

	memset(path, 0, MAXNAMELEN+1);
	info.vii_devpath = path;
	info.vii_pathlen = MAXNAMELEN;

	/* try to get the id */
	if (ioctl(fd, VOLIOCINFO, &info) < 0) {
#ifdef	DEBUG
		perror(vol_path);
#endif
		res = 0;
		goto dun;
	}

	/* successfully got the id */
	res = info.vii_id;

dun:
	if (fd >= 0) {
		(void) close(fd);
	}
	return (res);
}
