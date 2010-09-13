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
 *	Time a command
 */

#include	<stdio.h>
#include	<signal.h>
#include	<errno.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<libintl.h>
#include	<locale.h>
#include	<limits.h>
#include	<sys/types.h>
#include	<sys/times.h>
#include	<sys/wait.h>

/*
 * The following use of HZ/10 will work correctly only if HZ is a multiple
 * of 10.  However the only values for HZ now in use are 100 for the 3B
 * and 60 for other machines.
 *
 * The first value was HZ/10. Since HZ should be gotten from sysconf()
 * it is dynamically initialized at entry to the main program.
 */
static clock_t quant[] = { 10, 10, 10, 6, 10, 6, 10, 10, 10 };
static char *pad  = "000      ";
static char *sep  = "\0\0.\0:\0:\0\0";
static char *nsep = "\0\0.\0 \0 \0\0";

static void usage(void);
static void printt(char *, clock_t);

int
main(int argc, char **argv)
{
	struct tms	buffer;
	pid_t		p;
	int		status;
	int		pflag		= 0;
	int		c;
	int		clock_tick	= CLK_TCK;
	clock_t		before, after;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "p")) != EOF)
		switch (c) {
		case 'p':
			pflag++;
			break;
		case '?':
			usage();
		}

	argc -= optind;
	argv += optind;

	/*
	 * time(1) is only accurate to a tenth of a second.  We need to
	 * determine the number of clock ticks in a tenth of a second in
	 * order to later divide away what we don't care about.
	 */
	quant[0] = clock_tick/10;

	before = times(&buffer);
	if (argc < 1)
		usage();
	p = fork();
	if (p == (pid_t)-1) {
		perror("time");
		exit(2);
	}
	if (p == (pid_t)0) {
		(void) execvp(argv[0], &argv[0]);
		perror(argv[0]);
		if (errno == ENOENT)
			exit(127);
		else
			exit(126);
	}
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	while (wait(&status) != p);
	if ((status & 0377) != '\0')
		(void) fprintf(stderr, "time: %s\n",
		    gettext("command terminated abnormally."));
	after = times(&buffer);
	(void) fprintf(stderr, "\n");
	if (pflag)
		(void) fprintf(stderr, "real %.2f\nuser %.2f\nsys %.2f\n",
		    (double)(after-before)/clock_tick,
		    (double)buffer.tms_cutime/clock_tick,
		    (double)buffer.tms_cstime/clock_tick);
	else {
		printt("real", (after-before));
		printt("user", buffer.tms_cutime);
		printt("sys ", buffer.tms_cstime);
	}

	return ((status & 0xff00)
		? (status >> 8)
		: ((status & 0x00ff) ? ((status & ~WCOREFLG) | 0200) : 0));
}


static void
printt(char *s, clock_t a)
{
	int i;
	char digit[9];
	char c;
	int nonzero;

	a /= quant[0];	/* Divide away the accuracy we don't care about */

	/*
	 * We now have the number of tenths of seconds elapsed in terms of
	 * ticks. Loop through to determine the actual digits.
	 */
	for (i = 1; i < 9; i++) {
		digit[i] = a % quant[i];
		a /= quant[i];
	}
	(void) fprintf(stderr, s);
	nonzero = 0;
	while (--i > 0) {
		c = (digit[i] != 0) ? digit[i]+'0' : (nonzero ? '0': pad[i]);
		if (c != '\0')
			(void) putc(c, stderr);
		nonzero |= digit[i];
		c = nonzero?sep[i]:nsep[i];
		if (c != '\0')
			(void) putc(c, stderr);
	}
	(void) fprintf(stderr, "\n");
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: time [-p] utility [argument...]\n"));
	exit(1);
}
