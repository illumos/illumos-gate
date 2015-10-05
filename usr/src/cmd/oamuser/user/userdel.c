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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <pwd.h>
#include <project.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <userdefs.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include "users.h"
#include "messages.h"
#include "funcs.h"

/*
 *  userdel [-r ] login
 *
 *	This command deletes user logins.  Arguments are:
 *
 *	-r - when given, this option removes home directory & its contents
 *
 *	login - a string of printable chars except colon (:)
 */

extern int check_perm(), isbusy(), get_default_zfs_flags();
extern int rm_files(), call_passmgmt(), edit_group();

static char *logname;			/* login name to delete */
static char *nargv[20];		/* arguments for execvp of passmgmt */

char *cmdname;

int
main(int argc, char **argv)
{
	int ch, ret = 0, rflag = 0;
	int zfs_flags = 0, argindex, tries;
	struct passwd *pstruct;
	struct stat statbuf;
#ifndef att
	FILE *pwf;		/* fille ptr for opened passwd file */
#endif
	char *usertype = NULL;
	int rc;

	cmdname = argv[0];

	if (geteuid() != 0) {
		errmsg(M_PERM_DENIED);
		exit(EX_NO_PERM);
	}

	opterr = 0;			/* no print errors from getopt */
	usertype = getusertype(argv[0]);

	while ((ch = getopt(argc, argv, "r")) != EOF) {
		switch (ch) {
			case 'r':
				rflag++;
				break;
			case '?':
				if (is_role(usertype))
					errmsg(M_DRUSAGE);
				else
					errmsg(M_DUSAGE);
				exit(EX_SYNTAX);
		}
	}

	if (optind != argc - 1) {
		if (is_role(usertype))
			errmsg(M_DRUSAGE);
		else
			errmsg(M_DUSAGE);
		exit(EX_SYNTAX);
	}

	logname = argv[optind];

#ifdef att
	pstruct = getpwnam(logname);
#else
	/*
	 * Do this with fgetpwent to make sure we are only looking on local
	 * system (since passmgmt only works on local system).
	 */
	if ((pwf = fopen("/etc/passwd", "r")) == NULL) {
		errmsg(M_OOPS, "open", "/etc/passwd");
		exit(EX_FAILURE);
	}
	while ((pstruct = fgetpwent(pwf)) != NULL)
		if (strcmp(pstruct->pw_name, logname) == 0)
			break;

	fclose(pwf);
#endif

	if (pstruct == NULL) {
		errmsg(M_EXIST, logname);
		exit(EX_NAME_NOT_EXIST);
	}

	if (isbusy(logname)) {
		errmsg(M_BUSY, logname, "remove");
		exit(EX_BUSY);
	}

	/* that's it for validations - now do the work */
	/* set up arguments to  passmgmt in nargv array */
	nargv[0] = PASSMGMT;
	nargv[1] = "-d";	/* delete */
	argindex = 2;		/* next argument */

	/* finally - login name */
	nargv[argindex++] = logname;

	/* set the last to null */
	nargv[argindex++] = NULL;

	/* remove home directory */
	if (rflag) {
		/* Check Permissions */
		if (stat(pstruct->pw_dir, &statbuf)) {
			errmsg(M_OOPS, "find status about home directory",
			    strerror(errno));
			exit(EX_HOMEDIR);
		}

		if (check_perm(statbuf, pstruct->pw_uid, pstruct->pw_gid,
		    S_IWOTH|S_IXOTH) != 0) {
			errmsg(M_NO_PERM, logname, pstruct->pw_dir);
			exit(EX_HOMEDIR);
		}
		zfs_flags = get_default_zfs_flags();

		if (rm_files(pstruct->pw_dir, logname, zfs_flags) != EX_SUCCESS)
			exit(EX_HOMEDIR);
	}

	/* now call passmgmt */
	ret = PEX_FAILED;
	for (tries = 3; ret != PEX_SUCCESS && tries--; ) {
		switch (ret = call_passmgmt(nargv)) {
		case PEX_SUCCESS:
			ret = edit_group(logname, (char *)0, (int **)0, 1);
			if (ret != EX_SUCCESS)
				errmsg(M_UPDATE, "deleted");
			break;

		case PEX_BUSY:
			break;

		case PEX_HOSED_FILES:
			errmsg(M_HOSED_FILES);
			exit(EX_INCONSISTENT);
			break;

		case PEX_SYNTAX:
		case PEX_BADARG:
			/* should NEVER occur that passmgmt usage is wrong */
			if (is_role(usertype))
				errmsg(M_DRUSAGE);
			else
				errmsg(M_DUSAGE);
			exit(EX_SYNTAX);
			break;

		case PEX_BADUID:
		/*
		 * uid is used - shouldn't happen but print message anyway
		 */
			errmsg(M_UID_USED, pstruct->pw_uid);
			exit(EX_ID_EXISTS);
			break;

		case PEX_BADNAME:
			/* invalid loname */
			errmsg(M_USED, logname);
			exit(EX_NAME_EXISTS);
			break;

		default:
			errmsg(M_UPDATE, "deleted");
			exit(ret);
			break;
		}
	}
	if (tries == 0)
		errmsg(M_UPDATE, "deleted");

/*
 * Now, remove this user from all project entries
 */

	rc = edit_project(logname, (char *)0, (projid_t **)0, 1);
	if (rc != EX_SUCCESS) {
		errmsg(M_UPDATE, "modified");
		exit(rc);
	}

	exit(ret);
	/*NOTREACHED*/
}
