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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	"wish.h"
#include	"terror.h"

#define PADNUM	20

/* 
 * read in the file
 */
char *
readfile(file, trans_nl)
char *file;
int trans_nl;
{
	FILE *fp;
	register int retval, padding, ch;
	register char *tptr;
	char *text;
	unsigned int bufsize;
	struct stat statbuf;

	if (access(file, 0) < 0)
		return(NULL);
	if ((fp = fopen(file, "r")) == NULL || fstat(fileno(fp), &statbuf) < 0) {
		error(NOPEN, file);
		return(NULL);
	}

	if ((text = malloc(bufsize = statbuf.st_size + PADNUM + 1)) == NULL)
		fatal(NOMEM, NULL);

	padding = PADNUM;
	for (tptr = text; (ch = getc(fp)) != EOF; tptr++) {
		if ((*tptr = ch) == '\n' && trans_nl == TRUE) { 
			*tptr = ' ';
			if (tptr == text)
				continue;
			switch(*(tptr - 1)) {	/* check char before newline */
			case '.':
			case '?':
			case ':':
			case '!':
				/* add an extra blank */
				if (padding-- <= 0) {
					/* just in case */
					unsigned offset;

					offset = tptr - text;
					if ((text = realloc(text, bufsize += PADNUM)) == NULL)
						fatal(NOMEM, NULL);
					padding = PADNUM;
					tptr = text + offset;
				}
				*(++tptr) = ' ';
				break;
			default:
				;
			}
		}
	}
	*tptr = '\0';
	fclose(fp);
	return(text);
}
