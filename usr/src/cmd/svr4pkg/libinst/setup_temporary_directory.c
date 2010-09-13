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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <pwd.h>

/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include "install.h"
#include "libinst.h"
#include "libadm.h"
#include "messages.h"

/*
 * Name:	setup_temporary_directory
 * Description:	create a temporary directory from specified components
 *		and return full path to the directory created
 * Arguments:	r_dirname - pointer to handle to string - on success,
 *			the full path to the temporary directory created
 *			is returned in this handle
 *		a_tmpdir - pointer to string representing the directory into
 *			which the new temporary directory should be created
 *		a_suffix - pointer to string representing the 5-character
 *			suffix to be used as the first part of the temporary
 *			directory name invented
 * Returns:	boolean_t
 *			== B_TRUE - temporary directory created, path returned
 *			== B_FALSE - failed to create temporary directory
 *				'errno' is set to the failure reason
 * NOTE:    	Any path returned is placed in new storage for the
 *		calling function. The caller must use 'free' to dispose
 *		of the storage once the path is no longer needed.
 */

boolean_t
setup_temporary_directory(char **r_dirname, char *a_tmpdir, char *a_suffix)
{
	char	*dirname;

	/* entry assertions */

	assert(a_tmpdir != (char *)NULL);

	/* error if no pointer provided to return temporary name in */

	if (r_dirname == (char **)NULL) {
		errno = EFAULT;			/* bad address */
		return (B_FALSE);
	}

	/* generate temporary directory name */

	dirname = tempnam(a_tmpdir, a_suffix);
	if (dirname == (char *)NULL) {
		return (B_FALSE);
	}

	/* create the temporary directory */

	if (mkdir(dirname, 0755) != 0) {
		return (B_FALSE);
	}

	echoDebug(DBG_SETUP_TEMPDIR, dirname);

	*r_dirname = dirname;

	return (B_TRUE);
}
