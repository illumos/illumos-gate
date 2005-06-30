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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <userdefs.h>
#include <users.h>
#include <errno.h>
#include "messages.h"

/*
 *  groupmod -g gid [-o] | -n name group
 *
 *	This command modifies groups on the system.  Arguments are:
 *
 *	gid - a gid_t less than UID_MAX
 *	name - a string of printable characters excluding colon (:) and less
 *		than MAXGLEN characters long.
 *	group - a string of printable characters excluding colon(:) and less
 *		than MAXGLEN characters long.
 */

extern int valid_gid(), mod_group();
extern void errmsg();

char *cmdname = "groupmod";

int
main(int argc, char *argv[])
{
	int ch;				/* return from getopt */
	gid_t gid;			/* group id */
	int oflag = 0;			/* flags */
	int valret;			/* return from valid_gid() */
	char *gidstr = NULL;		/* gid from command line */
	char *newname = NULL;		/* new group name with -n option */
	char *grpname;			/* group name from command line */
	int warning;

	oflag = 0;	/* flags */

	while ((ch = getopt(argc, argv, "g:on:")) != EOF)  {
		switch (ch) {
			case 'g':
				gidstr = optarg;
				break;
			case 'o':
				oflag++;
				break;
			case 'n':
				newname = optarg;
				break;
			case '?':
				errmsg(M_MUSAGE);
				exit(EX_SYNTAX);
		}
	}

	if ((oflag && !gidstr) || optind != argc - 1) {
		errmsg(M_MUSAGE);
		exit(EX_SYNTAX);
	}

	grpname = argv[optind];

	if (gidstr) {
		/* convert gidstr to integer */
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
			/*NOTREACHED*/

		case TOOBIG:
			errmsg(M_TOOBIG, gid);
			exit(EX_BADARG);
			/*NOTREACHED*/

		}

	} else gid = -1;

	if (newname) {
		switch (valid_gname(newname, NULL, &warning)) {
		case INVALID:
			errmsg(M_GRP_INVALID, newname);
			exit(EX_BADARG);
		case NOTUNIQUE:
			errmsg(M_GRP_USED, newname);
			exit(EX_NAME_EXISTS);
		}
		if (warning)
			warningmsg(warning, newname);
	}

	if ((valret = mod_group(grpname, gid, newname)) != EX_SUCCESS) {
		if (valret == EX_NAME_NOT_EXIST)
			errmsg(M_NO_GROUP, grpname);
		else
			errmsg(M_UPDATE, "modified");
	}

	return (valret);
}
