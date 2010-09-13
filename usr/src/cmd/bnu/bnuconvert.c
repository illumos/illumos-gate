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

#include	"uucp.h"

int
main(argc, argv)
int argc;
char **argv;
{
	char fdgrade();
	DIR *machdir, *spooldir;
	char machname[MAXFULLNAME];
	char file1[NAMESIZE+1], file2[NAMESIZE+1];
	struct cs_struct svdcfile;
	int c;

	(void) strcpy(Progname, "bnuconvert");

	Uid = getuid();
	Euid = geteuid();
	if (Uid == 0)
		(void) setuid(UUCPUID);

	while ((c = getopt(argc, argv, "x:")) != EOF)
		switch(c) {
		case 'x':
			Debug = atoi(optarg);
			if (Debug < 0)
				Debug = 1;
			break;
		default:
			(void) fprintf(stderr, "usage: bnuconvert [-xLEVEL]\n");
			exit(-1);
		}

	DEBUG(5, "Progname (%s): STARTED\n", Progname);

	/* find the default directory to queue to */

	if (eaccess(GRADES, 04) != -1) 
		svdcfile.grade = fdgrade();
	else 
		svdcfile.grade = D_QUEUE;

	DEBUG(5, "All jobs will be placed in directory (%c) ", svdcfile.grade);
	DEBUG(5, "under each remote name in the spool area.%c\n", NULLCHAR);

	if ((spooldir = opendir(SPOOL)) == NULL) {
		(void) fprintf(stderr, "CAN'T OPEN (%s): errno (%d)\n",
			SPOOL, errno);
		exit(1);
	}

	while (gdirf(spooldir, file1, SPOOL)) {

		(void) sprintf(Rmtname, "%s", file1);
		(void) sprintf(machname, "%s/%s", SPOOL, file1);
		DEBUG(9, "File1 is (%s)\n", file1);
		DEBUG(9, "Rmtname is (%s)\n", Rmtname);
		DEBUG(9, "Machname is (%s)\n", machname);

		if (chdir(machname) != 0) {
			(void) fprintf(stderr, "CAN'T CHDIR (%s): errno (%d)\n",
				machname, errno);
			exit(1);
		}

		if ((machdir = opendir(machname)) == NULL) {
			(void) fprintf(stderr, "CAN'T OPEN (%s): errno (%d)\n",
				machname, errno);
				continue;
		}

		DEBUG(7, "Directory: %s\n", machname);

		while (gnamef(machdir, file2) == TRUE) {

			DEBUG(9, "File read from (%s) ", machname);
			DEBUG(9, "is (%s)\n", file2);

			if (!EQUALSN(file2, "C.",2))
				continue;

			/* build a saved C. file structure */

			(void) strncpy(svdcfile.file, file2, NAMESIZE-1);
			(void) sprintf(svdcfile.sys, "%s/%c", Rmtname, svdcfile.grade);

			DEBUG(9, "Rmtname is (%s)\n", Rmtname);
			DEBUG(9, "Default directory to queue to is (%c)\n", svdcfile.grade);
			DEBUG(7, "Directory to queue to is (%s)\n", svdcfile.sys);

			/* place any and all D. files related to the
			** C. file in the proper spool area.
			*/

			putdfiles(svdcfile);

			/* Now queue the C. file */

			wfcommit(svdcfile.file, svdcfile.file, svdcfile.sys);
		}
		closedir(machdir);
	}
	closedir(spooldir);
	return (0);
}
/* a dummy cleanup function to satisfy a .o file */
void cleanup() {}
