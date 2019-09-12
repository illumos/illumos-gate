/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Robert Mustacchi
 */

#include <locale.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <math.h>
#include <limits.h>
#include <time.h>
#include <libintl.h>

/*
 * This implements the sleep(1) command. It allows for a number of extensions
 * that match both the GNU implementation and parts of what ksh93 used to
 * provide. Mainly:
 *
 *  o Fractional seconds
 *  o Suffixes that change the amount of time
 */

typedef struct {
	char		sm_char;
	uint64_t	sm_adj;
} sleep_map_t;

static const sleep_map_t sleep_map[] = {
	{ 's', 1 },
	{ 'm', 60 },
	{ 'h', 60 * 60 },
	{ 'd', 60 * 60 * 24 },
	{ 'w', 60 * 60 * 24 * 7 },
	{ 'y', 60 * 60 * 24 * 365 },
	{ '\0', 0 }
};

static void
sleep_sigalrm(int sig)
{
	/*
	 * Note, the normal exit(2) function is not Async-Signal-Safe.
	 */
	_exit(0);
}

int
main(int argc, char *argv[])
{
	int c;
	long double d, sec, frac;
	char *eptr;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) signal(SIGALRM, sleep_sigalrm);

	while ((c = getopt(argc, argv, ":")) != -1) {
		switch (c) {
		case '?':
			warnx(gettext("illegal option -- %c"), optopt);
			(void) fprintf(stderr,
			    gettext("Usage: sleep time[suffix]\n"));
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		warnx(gettext("only one operand is supported"));
		(void) fprintf(stderr, gettext("Usage: sleep time[suffix]\n"));
		exit(EXIT_FAILURE);
	}

	errno = 0;
	d = strtold(argv[0], &eptr);
	if (errno != 0 || (eptr[0] != '\0' && eptr[1] != '\0') ||
	    eptr == argv[0] || d == NAN) {
		errx(EXIT_FAILURE, gettext("failed to parse time '%s'"),
		    argv[0]);
	}

	if (d < 0.0) {
		errx(EXIT_FAILURE,
		    gettext("time interval '%s', cannot be negative"), argv[0]);
	}

	if (eptr[0] != '\0') {
		int i;
		for (i = 0; sleep_map[i].sm_char != '\0'; i++) {
			if (sleep_map[i].sm_char == eptr[0]) {
				d *= sleep_map[i].sm_adj;
				break;
			}
		}

		if (sleep_map[i].sm_char == '\0') {
			errx(EXIT_FAILURE, gettext("failed to parse time %s"),
			    argv[0]);
		}
	}

	/*
	 * If we have no time, then we're done. Short circuit.
	 */
	if (d == 0) {
		exit(EXIT_SUCCESS);
	}

	/*
	 * Split this apart into the fractional and seconds parts to make it
	 * easier to work with.
	 */
	frac = modfl(d, &sec);

	/*
	 * We may have a rather large double value. Chop it up in units of
	 * INT_MAX.
	 */
	while (sec > 0 || frac != 0) {
		struct timespec ts;

		if (frac != 0) {
			frac *= NANOSEC;
			ts.tv_nsec = (long)frac;
			frac = 0;
		} else {
			ts.tv_nsec = 0;
		}

		/*
		 * We have a floating point number of fractional seconds. We
		 * need to convert that to nanoseconds.
		 */
		if (sec > (float)INT_MAX) {
			ts.tv_sec = INT_MAX;
		} else {
			ts.tv_sec = (time_t)sec;
		}
		sec -= ts.tv_sec;

		if (nanosleep(&ts, NULL) != 0) {
			err(EXIT_FAILURE, gettext("nanosleep failed"));
		}
	}

	return (0);
}
