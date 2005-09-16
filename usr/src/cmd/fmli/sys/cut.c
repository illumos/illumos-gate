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

#include <stdio.h>	/* make: cc cut.c */
#include <ctype.h>
#include "wish.h"
#include "ctl.h"
#include "eval.h"
#include "moremacros.h"
#include "message.h"
#include "sizes.h"

/* cut : cut and paste columns of a table (projection of a relation) */
/* Release 1.5; handles single backspaces as produced by nroff    */

# define NFIELDS 1024	/* max no of fields or resulting line length */
# define BACKSPACE '\b'

int strcmp(), atoi();
void exit();
char *getastr();	/* rjk */

static char usage[] = "Usage: fmlcut [-s] [-d<char>] {-c<list> | -f<list>} file ...";
static char cflist[] = "bad list for c/f option";

int
cmd_cut(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	extern int 	optind;
	extern char	*optarg;
	register int	c;
	register char	*p1, *rbuf;
	register char	*p, *list;
	register int	i;
	int	del = '\t';
	int	num, j, count, poscnt, r, s;
	int	endflag, supflag, cflag, fflag, backflag, filenr;
	int	sel[NFIELDS];
	char  	buf[BUFSIZ];	
	char	*p2, outbuf[NFIELDS];
	FILE	*inptr;
	int	fromfile;	/* rjk */

	supflag = cflag = fflag = r = num = s = 0;
	for (i = 0; i < NFIELDS; i++)
		sel[i] = 0;

	optind = 1;
	optarg = NULL;
	while((c = getopt(argc, argv, "c:d:f:s")) != EOF)
		switch(c) {
			case 'c':
				if (fflag)
					return(diag(cflist));
				cflag++;
				list = optarg;
				break;
			case 'd':
				if (strlen(optarg) > 1)
					diag("no delimiter");
				else
					del = (int)*optarg;
				break;
			case 'f':
				if (cflag)
					return(diag(usage));
				fflag++;
				list = optarg;
				break;
			case 's':
				supflag++;
				break;
			case '?':
				return(diag(usage));
		}

	argv = &argv[optind];
	argc -= optind;

	if (!(cflag || fflag))
		return(diag(cflist));

	do {
		p = list;
		switch(*p) {
			case '-':
				if (r)
					return(diag(cflist));
				r = 1;
				if (num == 0)
					s = 1;
				else {
					s = num;
					num = 0;
				}
				break;
			case '\0' :
			case ','  :
				if (num >= NFIELDS)
					return(diag(cflist));
				if (r) {
					if (num == 0)
						num = NFIELDS - 1;
					if (num < s)
						return(diag(cflist));
					for (j = s; j <= num; j++)
						sel[j] = 1;
				} else
					sel[num] = (num > 0 ? 1 : 0);
				s = num = r = 0;
				if (*p == '\0')
					continue;
				break;
			default:
				if (!isdigit(*p))
					return(diag(cflist));
				num = atoi(p);
				while (isdigit(*list))
					list++;
				continue;
		}
		list++;
	}while (*p != '\0');
	for (j=0; j < NFIELDS && !sel[j]; j++);
	if (j >= NFIELDS)
		return(diag("no fields"));

	filenr = 0;
	do {	/* for all input files */
		if ( argc == 0 || strcmp(argv[filenr],"-") == 0 )
			fromfile = 0;
		else {
			/* rjk */
			if ((inptr = fopen(argv[filenr], "r")) == NULL) {
				char errbuf[PATHSIZ + 50];

				sprintf(errbuf, "fmlcut: WARNING: cannot open %s\n", argv[filenr]);
				mess_temp(errbuf);
				continue;
			}
			else
				fromfile++;
		}
		endflag = 0;
		do {	/* for all lines of a file */
			count = poscnt = backflag = 0;
			p1 = &outbuf[0] - 1 ;
			p2 = p1;
			rbuf = buf;
			/* rjk ... from a file or form Instr) */
			if (fromfile ? ((fgets(buf, BUFSIZ, inptr)) == NULL) :
			   (getastr(buf, BUFSIZ, instr) == NULL || buf[0] == '\0')) {
				endflag = 1;
				continue;
			}
			do { 	/* for all char of the line */
				if (rbuf >= &buf[NFIELDS])
					return(diag("line too long"));
				if (*rbuf != '\n')
					*++p1 = *rbuf;
				if (cflag && (*rbuf == BACKSPACE))
					backflag++;
				else if (!backflag)
					poscnt += 1;
				else
					backflag--;
				if ( backflag > 1 )
					return(diag("cannot handle multiple adjacent backspaces\n"));
				if (*rbuf == '\n' && count > 0  || *rbuf == del || cflag) {
					count += 1;
					if (fflag)
						poscnt = count;
					if (sel[poscnt])
						p2 = p1;
					else
						p1 = p2;
				}
			} while (*rbuf++ != '\n');
			if ( !endflag && (count > 0 || !supflag)) {
				if (*p1 == del && !sel[count])
					*p1 = '\0'; /*suppress trailing delimiter*/
				else
					*++p1 = '\0';
				putastr(outbuf, outstr);	/* rjk */
				putac('\n', outstr);		/* rjk */
			}
		} while (!endflag);
		if (fromfile)
			fclose(inptr);
	} while (++filenr < argc);
	return(SUCCESS);	/* rjk */
}


int
diag(s)
char	*s;
{
	/* for now
	fprintf(stderr, "fmlcut: ERROR: %s\n", s);
	exit(2);
	*/
	mess_temp(s);
	mess_lock();
	return(FAIL);
}
