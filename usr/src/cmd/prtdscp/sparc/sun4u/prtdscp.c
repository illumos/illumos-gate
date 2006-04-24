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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libintl.h>
#include <locale.h>
#include <libdscp.h>

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#define	OPT_SP		1
#define	OPT_DOMAIN	2

static void	usage(void);
static void	parse_options(int, char **, int *);
static int	get_address(int, char *);
static void	trace(char *, ...);
static void	err(char *, ...);
static char	*dscp_strerror(int);

static int	verbose = 0;

int
main(int argc, char **argv)
{
	int	options;
	char	saddr[INET_ADDRSTRLEN];
	char	daddr[INET_ADDRSTRLEN];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	parse_options(argc, argv, &options);

	/*
	 * Get the desired IP addresses.
	 */
	if ((options & OPT_SP) != 0) {
		trace(gettext("Looking up SP address...\n"));
		if (get_address(DSCP_ADDR_REMOTE, saddr) < 0) {
			err(gettext("SP Address lookup failed. Aborting.\n"));
			exit(-1);
		}
	}
	if ((options & OPT_DOMAIN) != 0) {
		trace(gettext("Looking up domain address...\n"));
		if (get_address(DSCP_ADDR_LOCAL, daddr) < 0) {
			err(gettext("Domain Address lookup failed. "
			    "Aborting.\n"));
			exit(-1);
		}
	}

	/*
	 * Print the IP addresses.
	 */
	if (options == OPT_SP) {
		(void) printf("%s\n", saddr);
	} else if (options == OPT_DOMAIN) {
		(void) printf("%s\n", daddr);
	} else {
		(void) printf(gettext("Domain Address: %s\n"), daddr);
		(void) printf(gettext("SP Address: %s\n"), saddr);
	}

	return (0);
}

/*
 * parse_options()
 *
 *	Parse the commandline options.
 */
static void
parse_options(int argc, char **argv, int *options)
{
	int		i;
	int		c;
	extern int	opterr;
	extern int	optopt;

	/*
	 * Unless told otherwise, print everything.
	 */
	*options = (OPT_SP | OPT_DOMAIN);

	/*
	 * Skip this routine if no options exist.
	 */
	if (argc == 1) {
		return;
	}

	/*
	 * Scan for the -h option separately, so that
	 * other commandline options are ignored.
	 */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			usage();
			exit(0);
		}
	}

	/*
	 * Disable the built-in error reporting, so that
	 * error messages can be properly internationalized.
	 */
	opterr = 0;

	/*
	 * The main loop for parsing options.
	 */
	while ((c = getopt(argc, argv, "vsd")) != -1) {
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 's':
			if (*options == OPT_DOMAIN) {
				err(gettext("cannot use -s and -d together"));
				usage();
				exit(-1);
			}
			*options = OPT_SP;
			break;
		case 'd':
			if (*options == OPT_SP) {
				err(gettext("cannot use -s and -d together"));
				usage();
				exit(-1);
			}
			*options = OPT_DOMAIN;
			break;
		default:
			err(gettext("invalid option -%c"), optopt);
			usage();
			exit(-1);
		}
	}
}

/*
 * usage()
 *
 *	Print a brief synopsis of the program's usage.
 */
static void
usage(void)
{
	(void) printf(gettext("Usage:  prtdscp -h \n"));
	(void) printf(gettext("        prtdscp [-v] [-s|-d]\n"));
}

/*
 * get_address()
 *
 *	Retrieve a DSCP IP address using libdscp.
 */
static int
get_address(int which, char *addr)
{
	int			len;
	int			error;
	struct sockaddr_in	*sin;
	struct sockaddr		saddr;

	error = dscpAddr(0, which, &saddr, &len);
	if (error != DSCP_OK) {
		trace(gettext("dscpAddr() failed: %s"), dscp_strerror(error));
		return (-1);
	}

	/* LINTED pointer cast may result in improper alignment */
	sin = (struct sockaddr_in *)&saddr;
	if (inet_ntop(AF_INET, &(sin->sin_addr), addr, sizeof (*sin)) == NULL) {
		trace(gettext("address string conversion failed."));
		return (-1);
	}

	return (0);
}

/*
 * trace()
 *
 *	Print tracing statements to stderr when in verbose mode.
 */
/*PRINTFLIKE1*/
static void
trace(char *fmt, ...)
{
	va_list	args;

	if (verbose != 0) {
		va_start(args, fmt);
		(void) vfprintf(stderr, fmt, args);
		va_end(args);
	}
}

/*
 * err()
 *
 *	Print error messages to stderr.
 */
/*PRINTFLIKE1*/
static void
err(char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);

	(void) fprintf(stderr, gettext("ERROR: "));
	(void) vfprintf(stderr, fmt, args);
	(void) fprintf(stderr, "\n");

	va_end(args);
}

/*
 * dscp_strerror()
 *
 *	Convert a DSCP error value into a localized string.
 */
static char *
dscp_strerror(int error)
{
	switch (error) {
	case DSCP_OK:
		return (gettext("Success."));
	case DSCP_ERROR:
		return (gettext("General error."));
	case DSCP_ERROR_ALREADY:
		return (gettext("Socket already bound."));
	case DSCP_ERROR_INVALID:
		return (gettext("Invalid arguments."));
	case DSCP_ERROR_NOENT:
		return (gettext("No entry found."));
	case DSCP_ERROR_DB:
		return (gettext("Error reading database."));
	case DSCP_ERROR_REJECT:
		return (gettext("Connection rejected."));
	default:
		return (gettext("Unknown failure."));
	}
}
