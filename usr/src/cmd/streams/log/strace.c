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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/strlog.h>

#define	CTLSIZE sizeof (struct log_ctl)
#define	DATSIZE 8192
#define	LOGDEV "/dev/log"
#define	MAXTID 50

static int errflg = 0;	/* set if error in argument parsing */
static int infile = 0;  /* set if using standard input for arguments */
static int log;

static void prlog(FILE *log, struct log_ctl *lp, char *dp);
static int getid(int ac, char **av, struct trace_ids *tp);
static int convarg(char *ap);
static char *getarg(void);

#define	numeric(c) ((c <= '9') && (c >= '0'))

static int
convarg(char *ap)
{
	short ids[2];

	if (!ap)
		return (-2);
	if (numeric(*ap))
		return (atoi(ap));
	if (strcmp(ap, "all") == 0)
		return (-1);
	errflg = 1;
	return (-2);
}

static char *
getarg(void)
{
	static char argbuf[40];
	static int eofflg = 0;
	char *ap;
	int c;

	if (eofflg) {
		infile = 0;
		return (NULL);
	}

	ap = argbuf;

	/*
	 * Scan to first significant character in standard input.
	 * If EOF is encountered turn off standard input scanning and
	 * return NULL
	 */
	while ((c = getchar()) == ' ' || c == '\n' || c == '\t')
		;
	if (c == EOF) {
		infile = 0;
		eofflg++;
		return (NULL);
	}
	/*
	 * collect token until whitespace is encountered.  Don't do anything
	 * with EOF here as it will be caught the next time around.
	 */
	while (1) {
		*ap++ = c;
		if ((c = getchar()) == ' ' || c == '\n' ||
		    c == '\t' || c == EOF) {
			if (c == EOF) eofflg++;
			*ap = '\0';
			return (argbuf);
		}
	}
}


static int
getid(int ac, char **av, struct trace_ids *tp)
{
	static int index = 1;

	/*
	 * if inside of standard input scan take arguments from there.
	 */
retry:
	if (infile) {
		tp->ti_mid = convarg(getarg());
		tp->ti_sid = convarg(getarg());
		tp->ti_level = convarg(getarg());
		if (errflg)
			return (0);
		/*
		 * if the previous operations encountered EOF, infile
		 * will be set to zero.  The trace_ids structure must
		 * then be loaded from the command line arguments.
		 * Otherwise, the structure is now valid and should
		 * be returned.
		 */
		if (infile)
			return (1);
	}
	/*
	 * if we get here we are either taking arguments from the
	 * command line argument list or we hit end of file on standard
	 * input and should return to finish off the command line arguments
	 */
	if (index >= ac)
		return (0);

	/*
	 * if a '-' is present, start parsing from standard input
	 */
	if (strcmp(av[index], "-") == 0) {
		infile = 1;
		index++;
		goto retry;
	}

	/*
	 * Parsing from command line, make sure there are
	 * at least 3 arguments remaining.
	 */
	if ((index+2) >= ac)
		return (0);

	tp->ti_mid = convarg(av[index++]);
	tp->ti_sid = convarg(av[index++]);
	tp->ti_level = convarg(av[index++]);

	if (errflg)
		return (0);
	return (1);
}

int
main(int ac, char *av[])
{
	int  n;
	char cbuf[CTLSIZE];
	char dbuf[DATSIZE];
	struct strioctl istr;
	struct strbuf ctl, dat;
	struct log_ctl *lp = (struct log_ctl *)cbuf;
	struct trace_ids tid[MAXTID];
	struct trace_ids *tp;
	int ntid;
	int val;
	int flag;

	ctl.buf = cbuf;
	ctl.maxlen = CTLSIZE;
	dat.buf = dbuf;
	dat.len = dat.maxlen = DATSIZE;

	log = open(LOGDEV, O_RDWR);
	if (log < 0) {
		fprintf(stderr, "ERROR: unable to open %s\n", LOGDEV);
		return (1);
	}

	tp = tid;
	ntid = 0;

	if (ac == 1) {
		ntid++;
		tid[0].ti_mid = -1;
		tid[0].ti_sid = -1;
		tid[0].ti_level = -1;
	} else {
		while (getid(ac, av, tp)) {
			ntid++;
			tp++;
		}
	}

	if (errflg)
		return (errflg);

	istr.ic_cmd = I_TRCLOG;
	istr.ic_dp = (char *)tid;
	istr.ic_len = ntid * sizeof (struct trace_ids);
	istr.ic_timout = 0;
	if (ioctl(log, I_STR, &istr) < 0) {
		fprintf(stderr, "ERROR: tracer already exists\n");
		return (1);
	}

	setbuf(stdout, (char *)NULL);
	flag = 0;
	while (getmsg(log, &ctl, &dat, &flag) >= 0) {
		flag = 0;
		lp = (struct log_ctl *)cbuf;
		prlog(stdout, lp, dbuf);
	}

	return (0);
}

static void
prlog(FILE *log, struct log_ctl *lp, char *dp)
{
	char *ts;
	int *args;
	char *ap;
	time_t t = (time_t)lp->ttime;

	ts = ctime(&t);
	ts[19] = '\0';
	fprintf(log, "%06d %s %08x %2d %s%s%s %d %d %s\n",
	    lp->seq_no, (ts+11), lp->ltime, lp->level,
	    ((lp->flags & SL_FATAL) ? "F" : "."),
	    ((lp->flags & SL_NOTIFY) ? "N" : "."),
	    ((lp->flags & SL_ERROR) ? "E" : "."),
	    lp->mid, lp->sid, dp);
}
