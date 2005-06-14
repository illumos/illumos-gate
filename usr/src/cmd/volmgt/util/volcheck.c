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
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to kick volume management so it can check to see
 * if media has been inserted.
 *
 * Exit codes:
 *	-1	- error
 *	0	- no media found
 *	1	- media found
 *
 */

#include	<stdio.h>
#include	<unistd.h>
#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<locale.h>
#include	<fcntl.h>

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/vol.h>

char	*prog_name;
void	usage();

#define	MAX_TIME	28800	/* 8 hours */
#define	MIN_INTVL	1
#define	DEFAULT_INTVL	2

int	poll_time;	/* total number of seconds to poll the device */
int	poll_interval = DEFAULT_INTVL;	/* interval to poll (seconds) */
int	verbose;

int	work(int, char **);


void
main(int argc, char **argv)
{
	extern char 	*optarg;
	extern int	optind;
	int		c;
	char		*av[1];
	int		rval;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	/* process arguments */
	while ((c = getopt(argc, argv, "t:i:v")) != EOF) {
		switch (c) {
		case 't':
			poll_time = atoi(optarg);
			if (poll_time > MAX_TIME) {
				fprintf(stderr, gettext(
				    "Maximum time allowed is %d seconds\n"),
				    MAX_TIME);
				exit(-1);
			}
			break;
		case 'i':
			poll_interval = atoi(optarg);
			if (poll_interval < MIN_INTVL) {
				fprintf(stderr, gettext(
				    "Minimum interval is %d seconds\n"),
				    MIN_INTVL);
				exit(-1);
			}
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			exit(-1);
		}
	}

	if (argc == optind) {
		/*
		 * If there's no argument, use the default
		 * device for checking.
		 */
		av[0] = NULL;
		rval = work(1, av);
	} else {
		rval = work(argc - optind, &argv[optind]);
	}

	exit(rval);
}

void
usage()
{
	fprintf(stderr,
	    gettext("usage: %s [-t #secs -i #secs] [-v] [path]\n"), prog_name);
	fprintf(stderr,
	    gettext("If path is not supplied all media is checked\n"));
}

/*
 * Open the volume management control device and send the dev_t of
 * the device the user has named.
 *
 * It might be nice to someday parse the /etc/vold.conf file and
 * let the user specify "symbolic" device names.  We don't do
 * that yet.
 */
int
work(int ac, char **av)
{
	extern int	volmgt_check(char *);

	int		i;
	int		rval;



	if (poll_time > 0) {

		/* this is the time'd case. */
		while (poll_time > 0) {
			for (i = 0; i < ac; i++) {

				rval = volmgt_check(av[i]);
				if (verbose && av[i]) {
					if (rval) {
						printf(gettext(
						    "%s has media\n"), av[i]);
					} else {
						printf(gettext(
						    "%s has no media\n"),
						    av[i]);
					}
				}
				if (verbose && (av[i] == NULL)) {
					if (rval) {
						printf(gettext(
						    "media was found\n"));
					} else {
						printf(gettext(
						    "no media was found\n"));
					}
				}
			}
			sleep(poll_interval);
			poll_time -= poll_interval;
		}
		rval = 0;   /* doesn't really make sense in the timed case */
	} else {

		/* this is the one-shot case */
		for (i = 0; i < ac; i++) {
			rval = volmgt_check(av[i]);
			if (verbose && av[i]) {
				if (rval) {
					printf(gettext(
					    "%s has media\n"), av[i]);
				} else {
					printf(gettext(
					    "%s has no media\n"),
					    av[i]);
				}
			}
			if (verbose && (av[i] == NULL)) {
				if (rval) {
					printf(gettext(
					    "media was found\n"));
				} else {
					printf(gettext(
					    "no media was found\n"));
				}
			}
		}
	}
	return (rval);
}
