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

/*
 *	acctcon1 [-p] [-t] [-l file] [-o file] <wtmpx-file >ctmp-file
 *	-p	print input only, no processing
 *	-t	test mode: use latest time found in input, rather than
 *		current time when computing times of lines still on
 *		(only way to get repeatable data from old files)
 *	-l file	causes output of line usage summary
 *	-o file	causes first/last/reboots report to be written to file
 *	reads input (normally /var/adm/wtmpx), produces
 *	list of sessions, sorted by ending time in ctmp.h/ascii format
 *	A_TSIZE is max # distinct ttys
 */

#include <sys/types.h>
#include "acctdef.h"
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <utmpx.h>
#include <locale.h>
#include <stdlib.h>

int	a_tsize	= A_TSIZE;
int	tsize	= -1;	/* used slots in tbuf table */
struct  utmpx	wb;	/* record structure read into */
struct	ctmp	cb;	/* record structure written out of */

struct tbuf {
	char	tline[LSZ];	/* /dev/...  */
	char	tname[NSZ];	/* user name */
	time_t	ttime;		/* start time */
	dev_t	tdev;		/* device */
	int	tlsess;		/* # complete sessions */
	int	tlon;		/* # times on (ut_type of 7) */
	int	tloff;		/* # times off (ut_type != 7) */
	long	ttotal;		/* total time used on this line */
} * tbuf;

#define DATE_FMT	"%a %b %e %H:%M:%S %Y\n"
int	nsys;
struct sys {
	char	sname[LSZ];	/* reasons for ACCOUNTING records */
	char	snum;		/* number of times encountered */
} sy[NSYS];

time_t	datetime;	/* old time if date changed, otherwise 0 */
time_t	firstime;
time_t	lastime;
int	ndates;		/* number of times date changed */
int	exitcode;
char	*report	= NULL;
char	*replin = NULL;
int	printonly;
int	tflag;

static char time_buf[50];
uid_t	namtouid();
dev_t	lintodev();
static size_t wread(void);
static int valid(void);
static void fixup(FILE *);
static void loop(void);
static void bootshut(void);
static int iline(void);
static void upall(void);
static void update(struct tbuf *);
static void printrep(void);
static void printlin(void);
static void prctmp(struct ctmp *);

int
main(int argc, char **argv) 
{
	char *prog = argv[0];

	(void)setlocale(LC_ALL, "");
	while (--argc > 0 && **++argv == '-')
		switch(*++*argv) {
		case 'l':
			if (--argc > 0)
				replin = *++argv;
			continue;
		case 'o':
			if (--argc > 0)
				report = *++argv;
			continue;
		case 'p':
			printonly++;
			continue;
		case 't':
			tflag++;
			continue;
		default:
			fprintf(stderr, "usage: %s [-p] [-t] [-l lineuse] [-o reboot]\n", prog);
			exit(1);

		}

	if ((tbuf = (struct tbuf *) calloc(a_tsize,
		sizeof (struct tbuf))) == NULL) {
		fprintf(stderr, "acctcon1: Cannot allocate memory\n");
		exit(3);
	}

	if (printonly) {
		while (wread()) {
			if (valid()) {
				printf("%.*s\t%.*s\t%lu",
				    sizeof (wb.ut_line),
				    wb.ut_line,
				    sizeof (wb.ut_name),
				    wb.ut_name,
				    wb.ut_xtime);
				cftime(time_buf, DATE_FMT, &wb.ut_xtime);
				printf("\t%s", time_buf);
			} else
				fixup(stdout);
			
		}
		exit(exitcode);
	}

	while (wread()) {
		if (firstime == 0)
			firstime = wb.ut_xtime;
		if (valid())
			loop();
		else
			fixup(stderr);
	}
	wb.ut_name[0] = '\0';
	strcpy(wb.ut_line, "acctcon1");
	wb.ut_type = ACCOUNTING;
	if (tflag)
		wb.ut_xtime = lastime;
	else
		time(&wb.ut_xtime);
	loop();
	if (report != NULL)
		printrep();
	if (replin != NULL)
		printlin();
	exit(exitcode);
}

static size_t
wread()
{
	return (fread(&wb, sizeof(wb), 1, stdin) == 1);
	
}

/*
 * valid: check input wtmp record, return 1 if looks OK
 */
static int
valid()
{
	int i, c;

	/* XPG say that user names should not start with a "-". */
        if ((c = wb.ut_name[0]) == '-')
		return(0);

	for (i = 0; i < NSZ; i++) {
		c = wb.ut_name[i];
		if (isalnum(c) || c == '$' || c == ' ' || c == '_' || c == '-')
			continue;
		else if (c == '\0')
			break;
		else
			return(0);
	}

	if((wb.ut_type >= EMPTY) && (wb.ut_type <= UTMAXTYPE))
		return(1);

	return(0);
}

/*
 *	fixup assumes that V6 wtmp (16 bytes long) is mixed in with
 *	V7 records (20 bytes each)
 *
 *	Starting with Release 5.0 of UNIX, this routine will no
 *	longer reset the read pointer.  This has a snowball effect
 *	On the following records until the offset corrects itself.
 *	If a message is printed from here, it should be regarded as
 *	a bad record and not as a V6 record.
 */
static void
fixup(FILE *stream)
{
	fprintf(stream, "bad wtmpx: offset %lu.\n", ftell(stdin)-sizeof(wb));
	fprintf(stream, "bad record is:  %.*s\t%.*s\t%lu",
	    sizeof (wb.ut_line),
	    wb.ut_line,
	    sizeof (wb.ut_name),
	    wb.ut_name,
	    wb.ut_xtime);
	cftime(time_buf, DATE_FMT, &wb.ut_xtime);
	fprintf(stream, "\t%s", time_buf);
#ifdef	V6
	fseek(stdin, (long)-4, 1);
#endif
	exitcode = 1;
}

static void
loop()
{
	int timediff;
	struct tbuf *tp;

	if(wb.ut_line[0] == '\0' )	/* It's an init admin process */
		return;			/* no connect accounting data here */
	switch(wb.ut_type) {
	case OLD_TIME:
		datetime = wb.ut_xtime;
		return;
	case NEW_TIME:
		if(datetime == 0)
			return;
		timediff = wb.ut_xtime - datetime;
		for (tp = tbuf; tp <= &tbuf[tsize]; tp++)
			tp->ttime += timediff;
		datetime = 0;
		ndates++;
		return;
	case BOOT_TIME:
		upall();
		/* FALLTHROUGH */
	case ACCOUNTING:
	case RUN_LVL:
		lastime = wb.ut_xtime;
		bootshut();
		return;
	case USER_PROCESS:
	case LOGIN_PROCESS:
	case INIT_PROCESS:
	case DEAD_PROCESS:
		update(&tbuf[iline()]);
		return;
	case EMPTY:
		return;
	default:
		cftime(time_buf, DATE_FMT, &wb.ut_xtime);
		fprintf(stderr, "acctcon1: invalid type %d for %s %s %s",
		    wb.ut_type,
		    wb.ut_name,
		    wb.ut_line,
		    time_buf);
	}
}

/*
 * bootshut: record reboot (or shutdown)
 * bump count, looking up wb.ut_line in sy table
 */
static void
bootshut()
{
	int i;

	for (i = 0; i < nsys && !EQN(wb.ut_line, sy[i].sname); i++)
		;
	if (i >= nsys) {
		if (++nsys > NSYS) {
			fprintf(stderr,
				"acctcon1: recompile with larger NSYS\n");
			nsys = NSYS;
			return;
		}
		CPYN(sy[i].sname, wb.ut_line);
	}
	sy[i].snum++;
}

/*
 * iline: look up/enter current line name in tbuf, return index
 * (used to avoid system dependencies on naming)
 */
static int
iline()
{
	int i;

	for (i = 0; i <= tsize; i++)
		if (EQN(wb.ut_line, tbuf[i].tline))
			return(i);
	if (++tsize >= a_tsize) {
		a_tsize = a_tsize + A_TSIZE;
		if ((tbuf = (struct tbuf *) realloc(tbuf, a_tsize *
			sizeof (struct tbuf))) == NULL) {
			fprintf(stderr, "acctcon1: Cannot reallocate memory\n");
			exit(2);
		}
	}

	CPYN(tbuf[tsize].tline, wb.ut_line);
	tbuf[tsize].tdev = lintodev(wb.ut_line);
	return(tsize);
}

static void
upall()
{
	struct tbuf *tp;

	wb.ut_type = INIT_PROCESS;	/* fudge a logoff for reboot record */
	for (tp = tbuf; tp <= &tbuf[tsize]; tp++)
		update(tp);
}

/*
 * update tbuf with new time, write ctmp record for end of session
 */
static void
update(struct tbuf *tp)
{
	time_t	told,	/* last time for tbuf record */
		tnew;	/* time of this record */
			/* Difference is connect time */

	told = tp->ttime;
	tnew = wb.ut_xtime;
	cftime(time_buf, DATE_FMT, &told);
	fprintf(stderr, "The old time is: %s", time_buf);
	cftime(time_buf, DATE_FMT, &tnew);
	fprintf(stderr, "the new time is: %s", time_buf);
	if (told > tnew) {
		cftime(time_buf, DATE_FMT, &told);
		fprintf(stderr, "acctcon1: bad times: old: %s", time_buf);
		cftime(time_buf, DATE_FMT, &tnew);
		fprintf(stderr, "new: %s", time_buf);
		exitcode = 1;
		tp->ttime = tnew;
		return;
	}
	tp->ttime = tnew;
	switch(wb.ut_type) {
	case USER_PROCESS:
		tp->tlsess++;
		if(tp->tname[0] != '\0') { /* Someone logged in without */
					   /* logging off. Put out record. */
			cb.ct_tty = tp->tdev;
			CPYN(cb.ct_name, tp->tname);
			cb.ct_uid = namtouid(cb.ct_name);
			cb.ct_start = told;
			if (pnpsplit(cb.ct_start, (ulong_t)(tnew-told),
			    cb.ct_con) == 0) {
				fprintf(stderr, "acctcon1: could not calculate prime/non-prime hours\n");

				exit(1);
			}
			prctmp(&cb);
			tp->ttotal += tnew-told;
		}
		else	/* Someone just logged in */
			tp->tlon++;
		CPYN(tp->tname, wb.ut_name);
		break;
	case INIT_PROCESS:
	case LOGIN_PROCESS:
	case DEAD_PROCESS:
		tp->tloff++;
		if(tp->tname[0] != '\0') { /* Someone logged off */
			/* Set up and print ctmp record */
			cb.ct_tty = tp->tdev;
			CPYN(cb.ct_name, tp->tname);
			cb.ct_uid = namtouid(cb.ct_name);
			cb.ct_start = told;
			if (pnpsplit(cb.ct_start, (ulong_t)(tnew-told),
			    cb.ct_con) == 0) {
				fprintf(stderr, "acctcon1: could not calculate prime/non-prime hours\n");
				exit(1);
			}
			prctmp(&cb);
			tp->ttotal += tnew-told;
			tp->tname[0] = '\0';
		}
	}
}

static void
printrep()
{
	int i;

	freopen(report, "w", stdout);
	cftime(time_buf, DATE_FMT, &firstime);
	printf("from %s", time_buf);
	cftime(time_buf, DATE_FMT, &lastime);
	printf("to   %s", time_buf);
	if (ndates)
		printf("%d\tdate change%c\n",ndates,(ndates>1 ? 's' : '\0'));
	for (i = 0; i < nsys; i++)
		printf("%d\t%.*s\n", sy[i].snum,
		    sizeof (sy[i].sname), sy[i].sname);
}

/*
 *	print summary of line usage
 *	accuracy only guaranteed for wtmpx file started fresh
 */
static void
printlin()
{
	struct tbuf *tp;
	double timet, timei;
	double ttime;
	int tsess, ton, toff;

	freopen(replin, "w", stdout);
	ttime = 0.0;
	tsess = ton = toff = 0;
	timet = MINS(lastime-firstime);
	printf("TOTAL DURATION IS %.0f MINUTES\n", timet);
	printf("LINE         MINUTES  PERCENT  # SESS  # ON  # OFF\n");
	for (tp = tbuf; tp <= &tbuf[tsize]; tp++) {
		timei = MINS(tp->ttotal);
		ttime += timei;
		tsess += tp->tlsess;
		ton += tp->tlon;
		toff += tp->tloff;
		printf("%-*.*s %-7.0f  %-7.0f  %-6d  %-4d  %-5d\n",
		    OUTPUT_LSZ,
		    OUTPUT_LSZ,
		    tp->tline,
		    timei,
		    (timet > 0.)? 100*timei/timet : 0.,
		    tp->tlsess,
		    tp->tlon,
		    tp->tloff);
	}
	printf("TOTALS       %-7.0f  --       %-6d  %-4d  %-5d\n",
	    ttime, tsess, ton, toff);
}

static void
prctmp(struct ctmp *t)
{

	printf("%u\t%ld\t%.*s\t%lu\t%lu\t%lu",
	    t->ct_tty,
	    t->ct_uid,
	    OUTPUT_NSZ,
	    t->ct_name,
	    t->ct_con[0],
	    t->ct_con[1],
	    t->ct_start);
	cftime(time_buf, DATE_FMT, &t->ct_start);
	printf("\t%s", time_buf);
}
