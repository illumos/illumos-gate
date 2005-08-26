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
/*
 * wtmpfix - adjust wtmpx file and remove date changes.
 *	wtmpfix <wtmpx1 >wtmpx2
 *
 *	code are added to really fix wtmpx if it is corrupted ..
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <utmpx.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>
#include <stdlib.h>

#define	MAXRUNTIME	3600	/* time out after 1 hour */
#define	DAYEPOCH	(60 * 60 * 24)
#define	wout(f, w)	 fwrite(w, sizeof (struct utmpx), 1, f);

FILE	*Wtmpx, *Opw;
FILE	*fp;
char	Ofile[]	= "/tmp/wXXXXXX";
static char time_buf[50];

struct	dtab
{
	off_t	d_off1;		/* file offset start */
	off_t	d_off2;		/* file offset stop */
	time_t	d_adj;		/* time adjustment */
	struct dtab *d_ndp;	/* next record */
};

struct	dtab	*Fdp;		/* list header */
struct	dtab	*Ldp;		/* list trailer */

time_t 	lastmonth, nextmonth;
off_t	recno;

struct	utmpx	Ut, Ut2;

int	year, month;
int 	ch;
int	n;
int	multimode;		/* multi user mode	 WHCC */

static int winp(FILE *, struct utmpx *);
static void mkdtab(off_t);
static void setdtab(off_t, struct utmpx *, struct utmpx *);
static void adjust(off_t, struct utmpx *);
static int invalid(char *);
static void intr(int) __NORETURN;
static void scanfile(void);
static int inrange(void);
static void wabort(int);

int
main(int argc, char **argv)
{
	time_t tloc;
	struct tm *tmp;
	int fd;

	(void) setlocale(LC_ALL, "");
	setbuf(stdout, NULL);
	alarm(MAXRUNTIME);

	if (signal(SIGALRM, wabort) == SIG_ERR) {
		perror("signal");
		return (1);
	}
	if (signal(SIGINT, intr) == SIG_ERR) {
		perror("signal");
		return (1);
	}

	time(&tloc);
	tmp = localtime(&tloc);
	year = tmp->tm_year;
	month = tmp->tm_mon + 1;
	lastmonth = ((year + 1900 - 1970) * 365 +
	    (month - 1) * 30) * DAYEPOCH;
	nextmonth = ((year + 1900 - 1970) * 365 +
	    (month + 1) * 30) * DAYEPOCH;

	if (argc < 2) {
		argv[argc] = "-";
		argc++;
	}

	if ((fd = mkstemp(Ofile)) == -1) {
		fprintf(stderr, "cannot make temporary: %s\n", Ofile);
		intr(0);
	}

	if ((Opw = fdopen(fd, "w")) == NULL) {
		fprintf(stderr, "cannot open temporary: %s\n", Ofile);
		intr(0);
	}

	while (--argc > 0) {
		argv++;
		if (strcmp(*argv, "-") == 0)
			Wtmpx = stdin;
		else if ((Wtmpx = fopen(*argv, "r")) == NULL) {
			fprintf(stderr, "Cannot open: %s\n", *argv);
			intr(0);
		}
		scanfile();

		if (Wtmpx != stdin)
			fclose(Wtmpx);
	}
	fclose(Opw);

	if ((Opw = fopen(Ofile, "r")) == NULL) {
		fprintf(stderr, "Cannot read from temp: %s\n", Ofile);
		intr(0);
	}
	recno = 0;
	while (winp(Opw, &Ut)) {
		adjust(recno, &Ut);
		recno += sizeof (struct utmpx);
		wout(stdout, &Ut);
	}
	fclose(Opw);
	unlink(Ofile);
	return (0);
}

static int
winp(FILE *f, struct utmpx *w)
{
	if (fread(w, sizeof (struct utmpx), 1, f) != 1)
		return (0);
	if ((w->ut_type >= EMPTY) && (w->ut_type <= UTMAXTYPE))
		return (1);
	else {
		fprintf(stderr, "Bad file at offset %ld\n",
			ftell(f) - sizeof (struct utmpx));
		cftime(time_buf, DATE_FMT, &w->ut_xtime);
		fprintf(stderr, "%-12s %-8s %lu %s",
			w->ut_line, w->ut_user, w->ut_xtime, time_buf);
		intr(0);
	}
	/* NOTREACHED */
}

static void
mkdtab(off_t p)
{

	struct dtab *dp;

	dp = Ldp;
	if (dp == NULL) {
		dp = calloc(sizeof (struct dtab), 1);
		if (dp == NULL) {
			fprintf(stderr, "out of core\n");
			intr(0);
		}
		Fdp = Ldp = dp;
	}
	dp->d_off1 = p;
}

static void
setdtab(off_t p, struct utmpx *w1, struct utmpx *w2)
{
	struct dtab *dp;

	if ((dp = Ldp) == NULL) {
		fprintf(stderr, "no dtab\n");
		intr(0);
	}
	dp->d_off2 = p;
	dp->d_adj = w2->ut_xtime - w1->ut_xtime;
	if ((Ldp = calloc(sizeof (struct dtab), 1)) == NULL) {
		fprintf(stderr, "out of core\n");
		intr(0);
	}
	Ldp->d_off1 = dp->d_off1;
	dp->d_ndp = Ldp;
}

static void
adjust(off_t p, struct utmpx *w)
{

	off_t pp;
	struct dtab *dp;

	pp = p;

	for (dp = Fdp; dp != NULL; dp = dp->d_ndp) {
		if (dp->d_adj == 0)
			continue;
		if (pp >= dp->d_off1 && pp < dp->d_off2)
			w->ut_xtime += dp->d_adj;
	}
}

/*
 *	invalid() determines whether the name field adheres to
 *	the criteria set forth in acctcon1.  If the name violates
 *	conventions, it returns a truth value meaning the name is
 *	invalid; if the name is okay, it returns false indicating
 *	the name is not invalid.
 */

static int
invalid(char *name)
{
	int	i;

	for (i = 0; i < NSZ; i++) {
		if (name[i] == '\0')
			return (VALID);
		if (! (isalnum(name[i]) || (name[i] == '$') ||
		    (name[i] == ' ') || (name[i] == '.') ||
		    (name[i] == '_') || (name[i] == '-'))) {
			return (INVALID);
		}
	}
	return (VALID);
}

static void
intr(int sig)
{
	signal(SIGINT, SIG_IGN);
	unlink(Ofile);
	exit(1);
}

/*
 * scanfile:
 * 1)  	reads the file, to see if the record is within reasonable
 * 	range; if not, then it will scan the file, delete foreign stuff.
 * 2)   enter setdtab if in multiuser mode
 * 3)   change bad login names to INVALID
 */

static void
scanfile()
{
	while ((n = fread(&Ut, sizeof (Ut), 1, Wtmpx)) > 0) {
		if (n == 0) {
			unlink(Ofile);
			exit(0);
		}
		if (!inrange()) {
			for (;;) {
				if (fseek(Wtmpx,
				    -(off_t)sizeof (Ut), 1) != 0) {
					perror("seek error\n");
					exit(1);
				}
				if ((ch = getc(Wtmpx)) == EOF) {
					perror("read\n");
					exit(1);
				}
				fprintf(stderr, "checking offset %lo\n",
				    ftell(Wtmpx));
				if (fread(&Ut, sizeof (Ut), 1, Wtmpx) == 0) {
					exit(1);
				}
				if (inrange())
					break;
			}
		}
		/* Now we have a good utmpx record, do more processing */

#define	UTYPE	Ut.ut_type
#define	ULINE	Ut.ut_line

			if (recno == 0 || UTYPE == BOOT_TIME)
				mkdtab(recno);
			if (UTYPE == RUN_LVL) {
				if (strncmp(ULINE, "run-level S", 11) == 0)
					multimode = 0;
				if (strncmp(ULINE, "run-level 2", 11) == 0)
					multimode++;
			}
			if (invalid(Ut.ut_name)) {
				fprintf(stderr,
				    "wtmpfix: logname \"%*.*s\" changed "
				    "to \"INVALID\"\n", OUTPUT_NSZ,
				    OUTPUT_NSZ, Ut.ut_name);
				(void) strncpy(Ut.ut_name, "INVALID", NSZ);
			}
			if (UTYPE == OLD_TIME) {
				if (!winp(Wtmpx, &Ut2)) {
					fprintf(stderr, "Input truncated at "
					    "offset %ld\n", recno);
					intr(0);
				}
				if (Ut2.ut_type != NEW_TIME) {
					fprintf(stderr, "New date expected at "
					    "offset %ld", recno);
					intr(0);
				}
				if (multimode)  /* multiuser */
					setdtab(recno, &Ut, &Ut2);
				recno += (2 * sizeof (struct utmpx));
				wout(Opw, &Ut);
				wout(Opw, &Ut2);
				continue;
			}
			wout(Opw, &Ut);
			recno += sizeof (struct utmpx);
	}
}

static int
inrange()
{
	if ((strcmp(Ut.ut_line, RUNLVL_MSG) == 0) ||
	    (strcmp(Ut.ut_line, BOOT_MSG) == 0) ||
	    (strcmp(Ut.ut_line, "acctg on") == 0) ||
	    (strcmp(Ut.ut_line, OTIME_MSG) == 0) ||
	    (strcmp(Ut.ut_line, NTIME_MSG) == 0))
			return (1);

	if (Ut.ut_id != 0 &&
		Ut.ut_xtime > 0 &&
		Ut.ut_xtime > lastmonth &&
		Ut.ut_xtime < nextmonth &&
		Ut.ut_type >= EMPTY &&
		Ut.ut_type <= UTMAXTYPE &&
		Ut.ut_pid >= 0)
		return (1);

	return (0);
}

static void
wabort(int sig)
{
	fprintf(stderr, "give up\n");
	exit(1);
}
