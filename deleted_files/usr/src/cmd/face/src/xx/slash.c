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

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	int c, fromstr;
	char *sptr;
	FILE *fp;
	char *ifile;
	int errflag;

	errflag = 0;	
	ifile = NULL;
	while((c = getopt(argc, argv, "f:")) != EOF) {
		switch(c) {
		case 'f':
			ifile = optarg;
			break;
		case '?':
			errflag++;
			break;
		}
	}

	if (errflag)
		exit(1);
	if (ifile) {				/* from a file */
		if ((fp = fopen(ifile, "r")) == NULL)
			exit(1);
		fromstr = 0;
	}
	else if (optind == argc) { 		/* from stdin */
		fp = stdin;
		fromstr = 0;
	}
	else {					/* from a string */
		fromstr = 1;
		sptr = argv[1];
	}

	for (; ;) {
		if (fromstr)
			c = *sptr++;
		else
			c = fgetc(fp);
		switch(c) {
		case '\\':
			printf("\\\\");
			break;
		case '$':
			printf("\\$");
			break;
		case '`':
			printf("\\`");
			break;
		case '\'':
			printf("\\'");
			break;
		case '"':
			printf("\\\"");
			break;
		case '&':
			printf("\\&");
			break;
		case '[':
			printf("\\[");
			break;
		case ']':
			printf("\\]");
			break;
		case '<':
			printf("\\<");
			break;
		case '>':
			printf("\\>");
			break;
		case ';':
			printf("\\;");
			break;
		case '\0':
		case EOF:
			exit(0);
		default:
			putchar(c);
			break;
		}
	}
}

