/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>

#define	NSEC_TO_TICK(nsec)	((nsec) / nsec_per_tick)
#define	NSEC_TO_TICK_ROUNDUP(nsec) NSEC_TO_TICK((nsec) + \
	nsec_per_tick/2)
#define	NANOSEC	1000000000

char	fname[20];
static int hz;
int nsec_per_tick;

void printt(char *, hrtime_t);
void hmstime(char[]);
void diag(char *);

int
main(int argc, char **argv)
{
	struct	tms buffer, obuffer;
	int	status;
	register pid_t	p;
	int	c;
	hrtime_t before, after, timediff;
	char	stime[9], etime[9];
	char	cmd[80];
	int	pflg = 0, sflg = 0, oflg = 0;
	char	aopt[25];
	FILE	*pipin;
	char	ttyid[12], line[150];
	char	eol;
	char	fld[20][12];
	int	iline = 0, i, nfld;
	int	ichar, iblok;
	long	chars = 0, bloks = 0;

	aopt[0] = '\0';			/* terminate the string #1245107 */

	hz = sysconf(_SC_CLK_TCK);
	nsec_per_tick = NANOSEC / hz;

	/* check options; */
	while ((c = getopt(argc, argv, "sopfhkmrt")) != EOF)
		switch (c)  {
		case 's':  sflg++;  break;
		case 'o':  oflg++;  break;
		case 'p':  pflg++;  break;

		case 'f':  strcat(aopt, "-f ");  break;
		case 'h':  strcat(aopt, "-h ");  break;
		case 'k':  strcat(aopt, "-k ");  break;
		case 'm':  strcat(aopt, "-m ");  break;
		case 'r':  strcat(aopt, "-r ");  break;
		case 't':  strcat(aopt, "-t ");  break;

		case '?':  diag("Usage: timex [-s][-o][-p[-fhkmrt]] cmd");
				break;
		}
	if (optind >= argc)	diag("Missing command");

	/*
	 * Check to see if accounting is installed and print a somewhat
	 * meaninful message if not.
	 */
	if (((oflg+pflg) != 0) && (access("/usr/bin/acctcom", 01) == -1)) {
		oflg = 0;
		pflg = 0;
		fprintf(stderr,
		    "Information from -p and -o options not available\n");
		fprintf(stderr,
		    " because process accounting is not operational.\n");
	}

	if (sflg) {
		sprintf(fname, "/tmp/tmx%ld", getpid());
		sprintf(cmd, "/usr/lib/sa/sadc 1 1 %s", fname);
		system(cmd);
	}
	if (pflg + oflg) hmstime(stime);
	before = gethrtime();
	(void) times(&obuffer);
	if ((p = fork()) == (pid_t)-1) diag("Try again.\n");
	if (p == 0) {
		setgid(getgid());
		execvp(*(argv+optind), (argv+optind));
		fprintf(stderr, "%s: %s\n", *(argv+optind), strerror(errno));
		exit(1);
	}
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	while (wait(&status) != p)
		;
	if ((status&0377) != 0)
		fprintf(stderr, "Command terminated abnormally.\n");
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	(void) times(&buffer);
	after = gethrtime();
	timediff = after - before;
	if (pflg + oflg) hmstime(etime);
	if (sflg) system(cmd);

	fprintf(stderr, "\n");
	printt("real", NSEC_TO_TICK_ROUNDUP(timediff));
	printt("user", (hrtime_t)buffer.tms_cutime - (hrtime_t)
	    obuffer.tms_cutime);
	printt("sys ", (hrtime_t)buffer.tms_cstime - (hrtime_t)
	    obuffer.tms_cstime);
	fprintf(stderr, "\n");

	if (oflg+pflg) {
		if (isatty(0))
			sprintf(ttyid, "-l %s", ttyname(0)+5);
		sprintf(cmd, "acctcom -S %s -E %s -u %s %s -i %s",
		    stime, etime, getpwuid(getuid())->pw_name, ttyid, aopt);
		pipin = popen(cmd, "r");
		while (fscanf(pipin, "%[^\n]%1c", line, &eol) > 1) {
			if (pflg)
				fprintf(stderr, "%s\n", line);
			if (oflg)  {
				nfld = sscanf(line,
				    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
				    fld[0], fld[1], fld[2], fld[3], fld[4],
				    fld[5], fld[6], fld[7], fld[8], fld[9],
				    fld[10], fld[11], fld[12], fld[13], fld[14],
				    fld[15], fld[16], fld[17], fld[18],
				    fld[19]);
				if (++iline == 3)
					for (i = 0; i < nfld; i++)  {
						if (strcmp(fld[i], "CHARS")
						    == 0)
							ichar = i+2;
						if (strcmp(fld[i], "BLOCKS")
						    == 0)
							iblok = i+2;
					}
				if (iline > 4)  {
					chars += atol(fld[ichar]);
					bloks += atol(fld[iblok]);
				}
			}
		}
		pclose(pipin);

		if (oflg)
			if (iline > 4)
				fprintf(stderr,
				    "\nCHARS TRNSFD = %ld\n"
				    "BLOCKS READ  = %ld\n", chars, bloks);
			else
				fprintf(stderr,
				    "\nNo process records found!\n");
	}

	if (sflg)  {
		sprintf(cmd, "/usr/bin/sar -ubdycwaqvmpgrk -f %s 1>&2", fname);
		system(cmd);
		unlink(fname);
	}
	return (status>>8);
}

void
printt(char *label, hrtime_t ticks) {
	long tk;		/* number of ticks   */
	long ss;		/* number of seconds */
	long mm;		/* number of minutes */
	long hh;		/* number of hours   */
	longlong_t total = ticks;

	tk	= total % HZ;	/* ticks % HZ		*/
	total /= HZ;
	ss	= total % 60;	/* ticks / HZ % 60	*/
	total /= 60;
	mm	= total % 60;	/* ticks / HZ / 60 % 60 */
	hh	= total / 60;	/* ticks / HZ / 60 / 60 */

	fprintf(stderr, "%s", label);

	/*
	 * A negative sign indicates either time travelling backward
	 * or an overflow in time travelling forward.
	 * A positive sign indicates either time travelling forward
	 * or an overflow in time travelling backward.
	 */
	if (ticks < 0) {
		fprintf(stderr, "%1c", '-');
	} else {
		fprintf(stderr, "%1c", ' ');
	}

	/*
	 * We display either nothing or the absolute value of the
	 * number of calculated hours.
	 */
	if (hh == 0) {
		fprintf(stderr, "%7c",   ' ');
	} else {
		fprintf(stderr, "%7ld:", (hh > 0) ? hh : hh * -1);
	}

	/*
	 * We display either nothing or the absolute value of the
	 * number of calculated minutes.  If the value is a single-
	 * digit value, we would pad a '0' before it.
	 */
	if (mm == 0) {
		if (hh == 0) {
			fprintf(stderr, "%1c", ' ');
		} else {
			fprintf(stderr, "0:");
		}
	} else if (mm > -10 && mm < 10) {
			fprintf(stderr, "0%ld:", (mm > 0) ? mm : mm * -1);
	} else {
			fprintf(stderr, "%2ld:", (mm > 0) ? mm : mm * -1);
	}

	/*
	 * We display the absolute value of the number of
	 * calculated seconds.  If the value is a single-
	 * digit value, we would pad a '0' before it.
	 */
	if (ss > -10 && ss < 10) {
		fprintf(stderr, "%ld.0", (ss > 0) ? ss : ss * -1);
	} else {
		fprintf(stderr, "%2ld.", (ss > 0) ? ss : ss * -1);
	}

	/*
	 * We display the absolute value of the number of calculated ticks.
	 */
	fprintf(stderr, "%ld", (tk > 0) ? tk : tk * -1);

	fprintf(stderr, "\n");
}

/*
 * hmstime() sets current time in hh:mm:ss string format in stime;
 */

void
hmstime(char stime[])
{
	char	*ltime;
	time_t tme;

	tme = time((time_t *)0);
	ltime = ctime(&tme);
	strncpy(stime, ltime+11, 8);
	stime[8] = '\0';
}

void
diag(char *s)
{
	fprintf(stderr, "%s\n", s);
	unlink(fname);
	exit(1);
}
