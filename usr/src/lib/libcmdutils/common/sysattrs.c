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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <attr.h>
#include <fcntl.h>
#include <errno.h>
#include "libcmdutils.h"

/*
 * Returns the status of attempting to obtain the extended system
 * attributes in the specified view.
 *
 * Note: If obtaining status for an extended attribute file, the caller must
 * chdir into the hidden directory prior to calling sysattr_status().
 *
 * Returns 1 if the extended system attributes were obtained, otherwise
 * returns 0.
 */
int
sysattr_status(const char *file, xattr_view_t view)
{
	nvlist_t	*response = NULL;
	int		saveerrno;
	int		status;

	status = getattrat(AT_FDCWD, view, file, &response);

	saveerrno = errno;
	if (response)
		(void) nvlist_free(response);
	errno = saveerrno;

	return (status == 0);
}

/*
 * Returns the type of the specified in file.  If the file name matches
 * the name of either a read-only or read-write extended system attribute
 * file then sysattr_type() returns the type of file:
 *	return value	file type
 *	------------	---------
 *	_RO_SATTR	read-only extended system attribute file
 *	_RW_SATTR	read-write extended system attribute file
 *	_NOT_SATTR	neither a read-only or read-write extended system
 *			attribute file.
 */
int
sysattr_type(char *file)
{
	if (file == NULL) {
		errno = ENOENT;
		return (_NOT_SATTR);
	}

	if (strcmp(basename(file), file) != 0) {
		errno = EINVAL;
		return (_NOT_SATTR);
	}

	errno = 0;
	if (strcmp(file, VIEW_READONLY) == 0) {
		return (_RO_SATTR);
	} else if (strcmp(file, VIEW_READWRITE) == 0) {
		return (_RW_SATTR);
	} else {
		return (_NOT_SATTR);
	}
}

/*
 * Call sysattr_support() instead of pathconf(file, _PC_SATTR_ENABLED) or
 * pathconf(file, _PC_SATTR_EXISTS) so that if pathconf() fails over NFS, we
 * can still try to figure out if extended system attributes are supported by
 * testing for a valid extended system attribute file.
 *
 * 'name' can have the values _PC_SATTR_ENABLED or _PC_SATTR_EXISTS.
 *
 * Returns 1 if the underlying file system supports extended system attributes,
 * otherwise, returns -1.
 */
int
sysattr_support(const char *file, int name)
{
	int	rc;

	errno = 0;
	if ((name != _PC_SATTR_ENABLED) &&
	    (name != _PC_SATTR_EXISTS)) {
		errno = EINVAL;
		return (-1);
	}
	if (((rc = pathconf(file, name)) == 1) || (errno != EINVAL)) {
		return (rc);
	}
	return (sysattr_status(file, XATTR_VIEW_READONLY));
}
