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


/*
 * System includes
 */

#include <stdio.h>
#include <time.h>
#include <wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <ulimit.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include <pwd.h>


/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include "libinst.h"
#include "libadm.h"
#include "messages.h"

/*
 * Name:	unpack_package_from_stream
 * Description:	unpack a package from a stream into a temporary directory
 * Arguments:	a_idsName - pointer to string representing the input data
 *			stream containing the package to unpack
 *		a_pkginst - pointer to string representing the name of
 *			the package to unpack from the specified stream
 *		a_tempDir - pointer to string representing the path to a
 *			directory into which the package will be unpacked
 * Returns:	boolean_t
 *			== B_TRUE - package successfully unpacked from stream
 *			== B_FALSE - failed to unpack package from stream
 */

boolean_t
unpack_package_from_stream(char *a_idsName, char *a_pkginst, char *a_tempDir)
{
	int		dparts;
	char		instdir[PATH_MAX];

	/* entry assertions */

	assert(a_idsName != (char *)NULL);
	assert(a_pkginst != (char *)NULL);
	assert(a_tempDir != (char *)NULL);

	/* entry debug information */

	echoDebug(DBG_UNPACKSTRM_ENTRY);
	echoDebug(DBG_UNPACKSTRM_ARGS, a_pkginst, a_idsName, a_tempDir);

	/* find the specified package in the datastream */

	dparts = ds_findpkg(a_idsName, a_pkginst);
	if (dparts < 1) {
		progerr(gettext(ERR_DSARCH), a_pkginst);
		return (B_FALSE);
		/*NOTREACHED*/
	}

	/*
	 * read in next part from stream, even if we decide
	 * later that we don't need it
	 */

	/* create directory to hold this package instance */

	if (snprintf(instdir, sizeof (instdir), "%s/%s", a_tempDir, a_pkginst)
	    >= PATH_MAX) {
		progerr(ERR_CREATE_PATH_2, a_tempDir, a_pkginst);
		return (B_FALSE);
	}

	switch (fmkdir(instdir, 0755)) {
	case 0:	/* directory created */
		break;
	case 1: /* could not remove existing non-directory node */
		progerr(ERR_REMOVE, instdir, strerror(errno));
		return (B_FALSE);
	case 2: /* could not create specified new directory */
	default:
		progerr(ERR_UNPACK_FMKDIR, instdir, strerror(errno));
		return (B_FALSE);
	}

	/* unpack package instance from stream to dir created */

	echoDebug(DBG_UNPACKSTRM_UNPACKING, a_pkginst, a_idsName, instdir);

	if (chdir(instdir)) {
		progerr(ERR_CHDIR, instdir);
		return (B_FALSE);
	}

	while (dparts--) {
		if (ds_next(a_idsName, instdir)) {
			progerr(ERR_UNPACK_DSREAD, dparts+1, a_idsName, instdir,
				a_pkginst);
			return (B_FALSE);
		}
	}

	if (chdir(get_PKGADM())) {
		progerr(gettext(ERR_CHDIR), get_PKGADM());
		return (B_FALSE);
	}

	return (B_TRUE);
}
