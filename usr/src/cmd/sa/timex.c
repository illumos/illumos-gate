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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

char	fname[20];
static int hz;
static int nsec_per_tick;

void printt(char *, hrtime_t);
void hmstime(char[]);
void usage();

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

	aopt[0] = '\0';

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

		case '?':  usage();
				break;
		}
	if (optind >= argc) {
		fprintf(stderr, "timex: Missing command\n");
		usage();
	}

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
	if ((p = fork()) == (pid_t)-1) {
		perror("Fork Failed");
		(void) unlink(fname);
		exit(EXIT_FAILURE);
	}
	if (p == 0) {
		setgid(getgid());
		execvp(*(argv+optind), (argv+optind));
		fprintf(stderr, "%s: %s\n", *(argv+optind), strerror(errno));
		exit(EXIT_FAILURE);
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
	printt("user", buffer.tms_cutime - obuffer.tms_cutime);
	printt("sys ", buffer.tms_cstime - obuffer.tms_cstime);
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
	exit(WEXITSTATUS(status));
}

void
printt(char *label, hrtime_t ticks)
{
	long tk;	/* number of leftover ticks   */
	long ss;	/* number of seconds */
	long mm;	/* number of minutes */
	long hh;	/* number of hours   */
	longlong_t total = ticks;

	tk	= total % hz;	/* ticks % hz		*/
	total	/= hz;
	ss	= total % 60;	/* ticks / hz % 60	*/
	total	/= 60;
	mm	= total % 60;	/* ticks / hz / 60 % 60 */
	hh	= total / 60;	/* ticks / hz / 60 / 60 */

	(void) fprintf(stderr, "%s ", label);

	/* Display either padding or the elapsed hours */
	if (hh == 0L) {
		(void) fprintf(stderr, "%6c", ' ');
	} else {
		(void) fprintf(stderr, "%5ld:", hh);
	}

	/*
	 * Display either nothing or the elapsed minutes, zero
	 * padding (if hours > 0) or space padding (if not).
	 */
	if (mm == 0L && hh == 0L) {
		(void) fprintf(stderr, "%3c", ' ');
	} else if (mm != 0L && hh == 0L) {
		(void) fprintf(stderr, "%2ld:", mm);
	} else {
		(void) fprintf(stderr, "%02ld:", mm);
	}

	/*
	 * Display the elapsed seconds; seconds are always
	 * zero padded.
	 */
	if (hh == 0L && mm == 0L) {
		(void) fprintf(stderr, "%2ld.", ss);
	} else {
		(void) fprintf(stderr, "%02ld.", ss);
	}

	/* Display hundredths of a second. */
	(void) fprintf(stderr, "%02ld\n", tk * 100/hz);
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
usage()
{
	fprintf(stderr, "Usage: timex [-o] [-p [-fhkmrt]] [-s] command\n");
	unlink(fname);
	exit(EXIT_FAILURE);
}
