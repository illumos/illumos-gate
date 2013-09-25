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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013 RackTop Systems.
 */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<limits.h>
#include	<userdefs.h>
#include	<users.h>
#include	<errno.h>
#include	<libcmdutils.h>
#include	"messages.h"

extern int errmsg();
extern int valid_gid(), add_group();

/*
 *  groupadd [-g gid [-o]] group
 *
 *	This command adds new groups to the system.  Arguments are:
 *
 *	gid - a gid_t less than MAXUID
 *	group - a string of printable characters excluding colon(:) and less
 *		than MAXGLEN characters long.
 */

char *cmdname = "groupadd";

int
main(int argc, char *argv[])
{
	int ch;				/* return from getopt */
	gid_t gid;			/* group id */
	int oflag = 0;	/* flags */
	int rc;
	char *gidstr = NULL;	/* gid from command line */
	char *grpname;			/* group name from command line */
	int warning;

	while ((ch = getopt(argc, argv, "g:o")) != EOF)
		switch (ch) {
			case 'g':
				gidstr = optarg;
				break;
			case 'o':
				oflag++;
				break;
			case '?':
				errmsg(M_AUSAGE);
				exit(EX_SYNTAX);
		}

	if ((oflag && !gidstr) || optind != argc - 1) {
		errmsg(M_AUSAGE);
		exit(EX_SYNTAX);
	}

	grpname = argv[optind];

	switch (valid_gname(grpname, NULL, &warning)) {
	case INVALID:
		errmsg(M_GRP_INVALID, grpname);
		exit(EX_BADARG);
		/*NOTREACHED*/
	case NOTUNIQUE:
		errmsg(M_GRP_USED, grpname);
		exit(EX_NAME_EXISTS);
		/*NOTREACHED*/
	}
	if (warning)
		warningmsg(warning, grpname);

	if (gidstr) {
		/* Given a gid string - validate it */
		char *ptr;

		errno = 0;
		gid = (gid_t)strtol(gidstr, &ptr, 10);

		if (*ptr || errno == ERANGE) {
			errmsg(M_GID_INVALID, gidstr);
			exit(EX_BADARG);
		}

		switch (valid_gid(gid, NULL)) {
		case RESERVED:
			errmsg(M_RESERVED, gid);
			break;

		case NOTUNIQUE:
			if (!oflag) {
				errmsg(M_GRP_USED, gidstr);
				exit(EX_ID_EXISTS);
			}
			break;

		case INVALID:
			errmsg(M_GID_INVALID, gidstr);
			exit(EX_BADARG);

		case TOOBIG:
			errmsg(M_TOOBIG, gid);
			exit(EX_BADARG);

		}

	} else {

		if (findnextgid(DEFRID+1, MAXUID, &gid) != 0) {
			errmsg(M_GID_INVALID, "default id");
			exit(EX_ID_EXISTS);
		}

	}

	if ((rc = add_group(grpname, gid)) != EX_SUCCESS)
		errmsg(M_UPDATE, "created");

	return (rc);
}
