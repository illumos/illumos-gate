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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "wish.h"

main(argc, argv)
int argc;
char *argv[];
{
	FILE *fp, *nfp;
	char *home,  *penv, *fname;
	char *mname, item[BUFSIZ], buf[BUFSIZ];
	char hpath[PATHSIZ], spath[PATHSIZ], tpath[PATHSIZ];
	int comp_len, found = 0;
	int tmpfd = -1;

	if (argc < 2) {
		fprintf(stderr, "Arguments invalid\n");
		return (FAIL);
	}

	/* Initialize arguments needed to delete installation script */
	mname = argv[1];
	penv = argv[2];

	home = getenv(penv);
	if (strcmp(penv, "HOME") == 0)
		sprintf(spath, "%s/pref/services", home);
	else
		sprintf(spath, "%s/lib/services", home);

	sprintf(item, "`echo 'name=\"%s\"';", mname);
	comp_len = strlen(item);

	/* Update the service file */
	sprintf(tpath, "/tmp/servXXXXXX");
	if ((tmpfd = mkstemp(tpath)) == -1) {
		fprintf(stderr, "Cannot open file %s", tpath);
		return (FAIL);
	}
	(void) close(tmpfd);
	if ((fp = fopen(spath, "r")) == NULL) {
		fprintf(stderr, "Cannot open file %s", spath);
		(void) unlink(tpath);
		return (FAIL);
	}

	if ((nfp = fopen(tpath, "w+")) == NULL) {
		fprintf(stderr, "Cannot open file %s", tpath);
		(void) unlink(tpath);
		return (FAIL);
	}

	while (fp && (fgets(buf, sizeof (buf), fp) != NULL)) {
		if (found)
			fputs(buf, nfp);
		else if (strncmp(buf, item, comp_len))
			fputs(buf, nfp);
		else {
			found++;
			fname = strtok(buf, "=");
			fname = strtok(NULL, "'");
			fname = strtok(NULL, "'");
			fname = strtok(NULL, "$");
			fname = strtok(NULL, "`");
			sprintf(hpath, "%s%s", home, &fname[strlen(penv)]);
		}
	}

	rewind(nfp);
	fclose(fp);

	if ((fp = fopen(spath, "w")) == NULL) {
		fprintf(stderr, "Cannot open file %s", spath);
		(void) unlink(tpath);
		return (FAIL);
	}
	while (nfp && (fgets(buf, sizeof (buf), nfp) != NULL))
		fputs(buf, fp);
	fclose(fp);
	fclose(nfp);

	/* if file exists, delete it */
	if (found && (access(hpath, 00) == 0))
		unlink(hpath);
	unlink(tpath);
	return (SUCCESS);
}
