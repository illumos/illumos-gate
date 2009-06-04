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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <pkglocs.h>
#include <pkglib.h>
#include "libinst.h"

#define	ERR_INVALID_CAS	"%d is an invalid class action script type."
#define	ERR_NO_NONE	"Cannot find the default archive install script."
#define	ERR_NO_PATH	"No paths for finding class action scripts."

/* setlist.c */
extern struct cl_attr **cl_Classes;
extern int cl_NClasses;
extern char *cl_nam(int idx);

static int pkg_has_arch;

/* Return the install class action script associated with this class index */
char *
cl_iscript(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		return (cl_Classes[idx]->inst_script);
	return (NULL);
}

/*
 * This resets an input class action script pointer and the various
 * codes that are associated with special treatment available to a class
 * action script. It returns 1 if there was a script there in the first
 * place and 0 if there wasn't.
 */
int
cl_deliscript(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		if (cl_Classes[idx]->inst_script) {
			free(cl_Classes[idx]->inst_script);
			cl_Classes[idx]->inst_script = NULL;
			cl_Classes[idx]->src_verify = DEFAULT;
			cl_Classes[idx]->dst_verify = DEFAULT;
			cl_Classes[idx]->relpath_2_CAS = DEFAULT;

		} else
			return (0);
	return (1);
}

/* Return the remove class action script associated with this class index */
char *
cl_rscript(int idx)
{
	if (cl_Classes && idx >= 0 && idx < cl_NClasses)
		return (cl_Classes[idx]->rem_script);
	return (NULL);
}

/*
 * This scans the admin directories for the class acton scripts associated
 * with the classes to be installed. It will look for install or remove
 * scripts and place appropriate pointers into the cl_Classes list. There's
 * no reason why it couldn't look for both except that I haven't seen a
 * need for it yet.
 */
void
find_CAS(int CAS_type, char *pkgbin, char *instdir)
{
	int i;
	char path[PATH_MAX];

	if (instdir == NULL || pkgbin == NULL) {
		progerr(gettext(ERR_NO_PATH));
		quit(99);
	}

	if (CAS_type == I_ONLY) {
		for (i = 0; i < cl_NClasses; i++) {
			/*
			 * Locate appropriate installation class action
			 * script, if any; look on media for script,
			 * since it might be on the system due to a
			 * previous installation.
			 */
			(void) sprintf(path, "%s/install/i.%s", instdir,
			    cl_nam(i));
			if (access(path, R_OK) == 0) {
				(void) sprintf(path, "%s/i.%s", pkgbin,
				    cl_nam(i));
				cl_Classes[i]->inst_script = qstrdup(path);
				continue;
			}

			(void) sprintf(path, "%s/i.%s", PKGSCR, cl_nam(i));
			if (access(path, R_OK) == 0) {
				cl_Classes[i]->inst_script = qstrdup(path);
				continue;
			}

			/*
			 * Provide CAS to uncompress and distribute a
			 * compressed cpio archive for those older packages
			 * that don't include their own. This is the first
			 * point at which we know, it's an old package
			 * without all the various pkginfo items set.
			 * The default script is provided for all classes
			 * in an old package which do not have their own
			 * class action script. These are the criteria used
			 * by the script that packs the archives.
			 */
			(void) sprintf(path, "%s/%s", PKGSCR, DEF_NONE_SCR);
			if (pkg_has_arch &&
			    cl_Classes[i]->inst_script == NULL) {

				cl_Classes[i]->src_verify = NOVERIFY;
				cl_Classes[i]->dst_verify = QKVERIFY;
				cl_Classes[i]->relpath_2_CAS = REL_2_CAS;

				if (access(path, R_OK) == 0) {
					cl_Classes[i]->inst_script =
					    qstrdup(path);
					continue;
				} else {
					progerr(gettext(ERR_NO_NONE));
					quit(99);
				}

			}
		}
	} else if (CAS_type == R_ONLY) {
		for (i = 0; i < cl_NClasses; i++) {
			(void) sprintf(path, "%s/install/r.%s", instdir,
			    cl_nam(i));
			if (access(path, R_OK) == 0) {
				(void) sprintf(path, "%s/r.%s", pkgbin,
				    cl_nam(i));
				cl_Classes[i]->rem_script = qstrdup(path);
				continue;
			}

			(void) sprintf(path, "%s/r.%s", PKGSCR, cl_nam(i));
			if (access(path, R_OK) == 0) {
				cl_Classes[i]->rem_script = qstrdup(path);
				continue;
			}
		}
	} else {
		progerr(gettext(ERR_INVALID_CAS), CAS_type);
		quit(99);
	}
}

/*
 * This function deals with the special case of an old WOS package
 * with a compressed cpio'd file set but no class action script.
 * We find out it doesn't have a CAS later in find_CAS() and deal
 * with it then. The only reason for this variable is to let
 * findscripts() know to get the default script if it can't find it in
 * the usual places.
 */
void
is_WOS_arch(void)
{
	pkg_has_arch++;
}
