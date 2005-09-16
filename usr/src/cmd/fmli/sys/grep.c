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
/*
 * fmlgrep -- print lines matching (or not matching) a pattern
 *
 *	status returns:
 *		TRUE - ok, and some matches
 *		FALSE - no matches or error 
 */

#include <stdio.h>
#include <ctype.h>
#include "wish.h"
#include "ctl.h"
#include "eval.h"
#include "moremacros.h"
#include "message.h"

/*
 * define some macros for rexexp.h
 */

char errstr[][64] = {
	"Range endpoint too large." ,
	"Bad number." ,
	"``\\digit'' out of range." ,
	"Illegal or missing delimiter." ,
	"No remembered search string." ,
	"\\( \\) imbalance." ,
	"Too many \\(." ,
	"More than 2 numbers given in \\{ \\}." ,
	"} expected after \\." ,
	"First number exceeds second in \\{ \\}." ,
	"[ ] imbalance." ,
	"Regular expression overflow." ,
	"Unknown regexp error code!!" ,
	NULL
};

/*
 * Macros for FMLI i/o and FMLI error messages (rjk)
 */ 
static	char	tmpbuf[BUFSIZ];		/* for formatting purposes */

#define PRINTF(x, y)	{ \
				 sprintf(tmpbuf, x, y); \
				 putastr(tmpbuf, Outstr); \
				}

#define	errmsg(msg, arg)	{ \
				 sprintf(tmpbuf, msg, arg); \
				 mess_temp(tmpbuf); \
				}
#define ESIZE	256
#define	BLKSIZE	512

static void execute();
static int succeed();
static int fgetl();

char	*strrchr();

static  FILE	*temp;
static	long	lnum;
static	char	linebuf[BUFSIZ];
char	prntbuf[BUFSIZ];
static	char	expbuf[ESIZE];
static	int	nflag;
static	int	bflag;
static	int	lflag;
static	int	cflag;
static	int	vflag;
static	int	sflag;
static	int	iflag;
static	int	errflg;
static	int	nfile;
static	long	tln;
static	int	nsucc;
static	int	nchars;
static	int	nlflag;

static IOSTRUCT *Instr;
static IOSTRUCT *Outstr;

int
cmd_grep(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	int	c;
	char	*arg;
	extern int	optind;
	void		regerr();

	prntbuf[0] = expbuf[0] = linebuf[0] = '\0';
	nflag = bflag = lflag = cflag = vflag = nchars = 0;
	sflag = iflag = errflg = nfile = nsucc = 0;
	lnum = tln = 0;
	optind = 1;

	while((c=getopt(argc, argv, "blcnsvi")) != EOF)
		switch(c) {
		case 'v':
			vflag++;
			break;
		case 'c':
			cflag++;
			break;
		case 'n':
			nflag++;
			break;
		case 'b':
			bflag++;
			break;
		case 's':
			sflag++;
			break;
		case 'l':
			lflag++;
			break;
		case 'i':
			iflag++;
			break;
		case '?':
			errflg++;
		}

	if(errflg || (optind >= argc)) {
		errmsg("Usage: fmlgrep -blcnsvi pattern file . . .\n",
			(char *)NULL);
		/* exit(2); */
		return(FAIL);	/* rjk */
	}
	Instr = instr;		/* rjk */
	Outstr = outstr;	/* rjk */

	argv = &argv[optind];
	argc -= optind;
	nfile = argc - 1;

	if (strrchr(*argv,'\n')) {
		regerr(41);
		return(FAIL);	/* rjk */
	}

	if (iflag) {
		for(arg = *argv; *arg != NULL; ++arg)
			*arg = (char)tolower((int)((unsigned char)*arg));
	}

	compile(*argv, expbuf, &expbuf[ESIZE], '\0', regerr);

	if (--argc == 0)
		execute(NULL);
	else
		while (argc-- > 0)
			execute(*++argv);

	/* exit(nsucc == 2 ? 2 : nsucc == 0); */
	return((nsucc == 2 || nsucc == 0) ? FAIL : SUCCESS);
}

static void
execute(file)
char *file;
{
	char *lbuf;
	int i, fromfile;
	char *getastr();	/* rjk */

	fromfile = 0;
	if (file != NULL) { 	/* rjk */
		if ( (temp = fopen(file, "r")) == NULL) {
			if (!sflag)
				errmsg("fmlgrep: can't open %s\n", file);
			nsucc = 2;
			return;
		}
		fromfile++;
	}

	lnum = 0;
	tln = 0;


	/* rjk (from a file OR from Instr) */
	while(fromfile ? ((nchars = fgetl(prntbuf, BUFSIZ, temp)) != 0) :
	   (getastr(prntbuf, BUFSIZ, Instr) && (nchars = strlen(prntbuf)) != 0)) {
		if(nchars == BUFSIZ - 1  &&  prntbuf[nchars-1] != '\n')
			continue;

		if(prntbuf[nchars-1] == '\n') {
			nlflag = 1;
			prntbuf[nchars-1] = '\0';
		} else
			nlflag = 0;

		lnum++;

		if (iflag) {
			for(i=0, lbuf=linebuf; i < nchars; i++, lbuf++)
				*lbuf = (char)tolower((int)(unsigned char)prntbuf[i]);
			*lbuf = '\0';
			lbuf = linebuf;
		} else
			lbuf = prntbuf;

		if((step(lbuf, expbuf) ^ vflag) && succeed(file) == 1) 
			break;	/* lflag only once */
	}
	if (fromfile)	/* rjk */
		fclose(temp);

	if (cflag) {
		if (nfile>1)
			PRINTF("%s:", file);
		PRINTF("%ld\n", tln);
	}
	return;
}

static int
succeed(f)
char *f;
{
	nsucc = (nsucc == 2) ? 2 : 1;
	if (cflag) {
		tln++;
		return(0);
	}
	if (lflag) {
		PRINTF("%s\n", f);
		return(1);
	}

	if (nfile > 1)	/* print filename */
		PRINTF("%s:", f);

	if (bflag)	/* print block number */
		PRINTF("%ld:", (ftell(temp)-1)/BLKSIZE);

	if (nflag)	/* print line number */
		PRINTF("%ld:", lnum);

	if (nlflag)
		prntbuf[nchars-1] = '\n';

	/* fwrite(prntbuf, 1, nchars, stdout); old */
	PRINTF(prntbuf, NULL);		/* rjk */
	return(0);
}

void
regerr(err)
int err;
{
	errmsg("fmlgrep: RE error %d: ", err);
	switch(err) {
		case 11:
			err = 0;
			break;
		case 16:
			err = 1;
			break;
		case 25:
			err = 2;
			break;
		case 36:
			err = 3;
			break;
		case 41:
			err = 4;
			break;
		case 42:
			err = 5;
			break;
		case 43:
			err = 6;
			break;
		case 44:
			err = 7;
			break;
		case 45:
			err = 8;
			break;
		case 46:
			err = 9;
			break;
		case 49:
			err = 10;
			break;
		case 50:
			err = 11;
			break;
		default:
			err = 12;
			break;
	}

	errmsg("%s\n", errstr[err]);
	/* exit(2); */
}

/*
 * The following code is a modified version of the fgets() stdio
 * routine.  The reason why it is used instead of fgets() is that
 * we need to know how many characters we read into the buffer.
 * Thus that value is returned here instead of the value of s1.
 */
#define MIN(x, y)	(x < y ? x : y)
#define _BUFSYNC(iop)	if ((long) _bufendtab[fileno(iop)] - (long) iop->_ptr <   \
				( iop->_cnt < 0 ? 0 : iop->_cnt ) )  \
					_bufsync(iop)

extern int _filbuf();
extern char *memccpy();

static int
fgetl(ptr, size, iop)
char *ptr;
int size;
FILE *iop;
{
	char *p, *ptr0 = ptr;
	int n;

	for (size--; size > 0; size -= n) {
		if (iop->_cnt <= 0) { /* empty buffer */
			if (_filbuf(iop) == EOF) {
				if (ptr0 == ptr)
					return (NULL);
				break; /* no more data */
			}
			iop->_ptr--;
			iop->_cnt++;
		}
		n = MIN(size, iop->_cnt);
		if ((p = memccpy(ptr, (char *) iop->_ptr, '\n', n)) != NULL)
			n = p - ptr;
		ptr += n;
		iop->_cnt -= n;
		iop->_ptr += n;
		_BUFSYNC(iop);
		if (p != NULL)
			break; /* found '\n' in buffer */
	}
	*ptr = '\0';
	return (ptr-ptr0);
}
