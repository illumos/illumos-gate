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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/strlog.h>
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/stropts.h"
#include "sys/strlog.h"

#define	CTLSIZE sizeof (struct log_ctl)
#define	DATSIZE 8192
#define	ADMSTR "root"
#define	LOGDEV "/dev/log"
#define	ERRFILE "/var/adm/streams/error.xxxxx"
#define	NSECDAY 86400
#define	LOGDEFAULT "/var/adm/streams"
#define	DIRECTORY 040000
#define	ACCESS 07

static void prlog(FILE *log, struct log_ctl *lp, char *dp, int flag);
static void makefile(char *name, time_t time);
static FILE *logfile(FILE *log, struct log_ctl *lp);
static void prlog(FILE *log, struct log_ctl *lp, char *dp, int flag);

static char *errfile;

static void
makefile(char *name, time_t time)
{
	char *r;
	struct tm *tp;

	tp = localtime(&time);
	r = &(name[strlen(name) - 5]);
	(void) sprintf(r, "%02d-%02d", (tp->tm_mon+1), tp->tm_mday);
}

static FILE *
logfile(FILE *log, struct log_ctl *lp)
{
	static time_t lasttime = 0;
	time_t newtime;

	errfile = ERRFILE;
	newtime = lp->ttime - timezone;

	/*
	 * If it is a new day make a new log file
	 */
	if (((newtime/NSECDAY) != (lasttime/NSECDAY)) || !log) {
		if (log)
			(void) fclose(log);
		lasttime = newtime;
		makefile(errfile, lp->ttime);
		return (fopen(errfile, "a+"));
	}
	lasttime = newtime;
	return (log);
}


/*ARGSUSED*/
int
main(int ac, char *av[])
{
	int fd;
	char cbuf[CTLSIZE];
	char dbuf[DATSIZE];	/* must start on word boundary */
	char mailcmd[40];
	int flag;
	struct strbuf ctl;
	struct strbuf dat;
	struct strioctl istr;
	struct stat stbuf;
	struct log_ctl *lp;
	FILE *pfile;
	FILE *log;
	char *logname;

	ctl.buf = cbuf;
	ctl.maxlen = CTLSIZE;
	dat.buf = dbuf;
	dat.maxlen = dat.len = DATSIZE;
	fd = open(LOGDEV, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "ERROR: unable to open %s\n", LOGDEV);
		return (1);
	}

	logname = LOGDEFAULT;
	if (stat(logname, &stbuf) < 0 || !(stbuf.st_mode & DIRECTORY)) {
		fprintf(stderr, "ERROR: %s not a directory\n", logname);
		return (1);
	}

	if (access(logname, ACCESS) < 0) {
		fprintf(stderr, "ERROR: cannot access directory %s\n",
		    logname);
		return (1);
	}

	istr.ic_cmd = I_ERRLOG;
	istr.ic_timout = istr.ic_len = 0;
	istr.ic_dp = NULL;
	if (ioctl(fd, I_STR, &istr) < 0) {
		fprintf(stderr, "ERROR: error logger already exists\n");
		return (1);
	}

	log = NULL;
	flag = 0;
	while (getmsg(fd, &ctl, &dat, &flag) >= 0) {
		flag = 0;
		lp = (struct log_ctl *)cbuf;
		log = logfile(log, lp);
		if (log == NULL) {
			fprintf(stderr, "ERROR: unable to open %s\n", errfile);
			return (1);
		} else {
			prlog(log, lp, dbuf, 1);
			(void) fflush(log);
		}

		if (!(lp->flags & SL_NOTIFY)) continue;
		(void) sprintf(mailcmd, "mail %s", ADMSTR);
		if ((pfile = popen(mailcmd, "w")) != NULL) {
			fprintf(pfile, "Streams Error Logger message "
			    "notification:\n\n");
			prlog(pfile, lp, dbuf, 0);
			(void) pclose(pfile);
		}
	}

	return (0);
}

static void
prlog(FILE *log, struct log_ctl *lp, char *dp, int flag)
{
	char *ts;
	time_t t = (time_t)lp->ttime;

	ts = ctime(&t);
	ts[19] = '\0';
	if (flag) {
		fprintf(log, "%06d %s %08x %s%s%s ", lp->seq_no, (ts+11),
		    lp->ltime,
		    ((lp->flags & SL_FATAL) ? "F" : "."),
		    ((lp->flags & SL_NOTIFY) ? "N" : "."),
		    ((lp->flags & SL_TRACE) ? "T" : "."));
		fprintf(log, "%d %d %s\n", lp->mid, lp->sid, dp);
	} else {
		fprintf(log, "%06d %s\n", lp->seq_no, dp);
	}
}
