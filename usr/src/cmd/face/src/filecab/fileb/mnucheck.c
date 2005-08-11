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

#include	<stdio.h>
#include 	<string.h>
#include 	<ctype.h>
#include	<stdlib.h>
#include	"wish.h"


#define FAILURE	4
#define EXISTS  2
#define INVALID 3
#define SUCCESS 0

char	*string=NULL;
char	*name=NULL;

int
main(int argc, char **argv)
{

	int     ret;
	int 	opt;
	char	hpath[PATHSIZ], path[PATHSIZ], *home, *vmsys, *str;
	FILE    *fp, *nfp;

	home=getenv("HOME");
	vmsys=getenv("VMSYS");

	while((opt=getopt(argc,argv,"s:n:")) != EOF)
		switch(opt) {
		case 's':
			string=optarg;
			break;
		case 'n':
			name=optarg;
			break;
		}

	if (string == NULL || strlen(string) == 0)
		return(INVALID);

	str = string;
	for (; *str != '\0'; str++)
		if ( ! isprint(*str))
			return(FAILURE);

	if (strcmp(string,name) == 0)
		return(SUCCESS);

	snprintf(hpath, sizeof (hpath), "%s/pref/services",home);
	snprintf(path, sizeof (path), "%s/lib/services",vmsys);

	if(access(hpath, 00) == 0) {
		if ((fp=fopen(hpath, "r")) == NULL) {
			fprintf(stderr, "Cannot open file %s",hpath);
			return(FAILURE);
		}

		if (mread(fp)) {
			fclose(fp);
			return(EXISTS);
		}

	}
	if(access(path, 00) == 0) {
		if ((nfp=fopen(path,"r")) == NULL) {
			fprintf(stderr, "Cannot open file %s",path);
			return(FAILURE);
		}

		if (mread(nfp)) {
			fclose(nfp);
			return(EXISTS);
		}
	}
	fclose(fp);
	fclose(nfp);
	return(SUCCESS);
}

int
mread(FILE *fp)
{
	char buf[BUFSIZ], *label, *mname;

	while(fp && (fgets(buf, BUFSIZ,fp) != NULL)) {
		if (*buf == '\n' || *buf == '#' )
			continue;

		label=strtok(buf, "=");
		if (strcmp(label,"`echo 'name") != 0)
			continue;

		mname=strtok(NULL,"\"");
		if (strcmp(mname,string) == 0)
			return(EXISTS);
	}
	return(SUCCESS);
}
