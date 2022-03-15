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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <libilb.h>
#include "ilbadm.h"

/*
 * Error strings for error values returned by ilbadm functions
 */
const char *
ilbadm_errstr(ilbadm_status_t rc)
{
	switch (rc) {
	case ILBADM_OK:
		return (gettext("no error"));
	case ILBADM_FAIL:
		return (gettext("processing of command failed"));
	case ILBADM_ENOMEM:
		return (gettext("memory allocation failure"));
	case ILBADM_EINVAL:
		return (gettext("invalid value  - refer to ilbadm(8)"));
	case ILBADM_HCPRINT:
		return (gettext("failed to print healthcheck values"));
	case ILBADM_INVAL_AF:
		return (gettext("address family is invalid"));
	case ILBADM_INVAL_PORT:
		return (gettext("port value is invalid"));
	case ILBADM_INVAL_SRVID:
		return (gettext("server ID is invalid"));
	case ILBADM_INVAL_ADDR:
		return (gettext("address is invalid"));
	case ILBADM_INVAL_ARGS:
		return (gettext("invalid/incompatible keywords - refer to"
		    " ilbadm(8)"));
	case ILBADM_ENOSGNAME:
		return (gettext("servergroup name missing"));
	case ILBADM_ENORULE:
		return (gettext("rule name missing or specified"
		    " rule not found"));
	case ILBADM_ENOSERVER:
		return (gettext("server name missing or specified"
		    " server not found"));
	case ILBADM_INVAL_ALG:
		return (gettext("LB algorithm is invalid"));
	case ILBADM_ENOPROTO:
		return (gettext("protocol does not exist in"
		    " protocol database"));
	case ILBADM_ENOSERVICE:
		return (gettext("servicename does not exist in nameservices"));
	case ILBADM_INVAL_OPER:
		return (gettext("operation type is invalid"));
	case ILBADM_INVAL_KEYWORD:
		return (gettext("keyword is invalid - please refer"
		    " to ilbadm(8)"));
	case ILBADM_ASSIGNREQ:
		return (gettext("assignment '=' missing"));
	case ILBADM_NORECURSIVE:
		return (gettext("recursive import not allowed"));
	case ILBADM_INVAL_COMMAND:
		return (gettext("subcommand is invalid - please refer"
		    " to ilbadm(8)"));
	case ILBADM_ENOPROXY:
		return (gettext("proxy-src is missing"));
	case ILBADM_INVAL_PROXY:
		return (gettext("proxy-src not allowed"));
	case ILBADM_ENOOPTION:
		return (gettext("mandatory argument(s) missing - refer"
		    " to ilbadm(8)"));
	case ILBADM_TOOMANYIPADDR:
		return (gettext("address range contains more than 255"
		    " IP addresses"));
	case ILBADM_EXPORTFAIL:
		return (gettext("could not export servergroup because"
		    " of lack of space"));
	case ILBADM_INVAL_SYNTAX:
		return (gettext("syntax failure - refer to ilbadm(8)"));
	case ILBADM_NOKEYWORD_VAL:
		return (gettext("missing value"));
	case ILBADM_LIBERR:
		return (gettext("library error"));
	default:
		return (gettext("unknown error"));


	}
}

/* PRINTFLIKE1 */
void
ilbadm_err(const char *format, ...)
{
	/* similar to warn() of dladm.c */
	va_list alist;

	(void) fprintf(stderr, "ilbadm: ");

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, "\n");
}

void
Usage(char *name)
{
	(void) fprintf(stderr, gettext("Usage:\n"));
	print_cmdlist_short(basename(name), stderr);
	exit(1);
}

static void
print_version(char *name)
{
	(void) printf("%s %s\n", basename(name), ILBADM_VERSION);
	(void) printf(gettext(ILBADM_COPYRIGHT));
	exit(0);
}

void
unknown_opt(char **argv, int optind)
{
	ilbadm_err(gettext("bad or misplaced option %s"), argv[optind]);
	exit(1);
}

void
incomplete_cmdline(char *name)
{
	ilbadm_err(gettext("the command line is incomplete "
	    "(more arguments expected)"));
	Usage(name);
}

static void
bad_importfile(char *name, char *filename)
{
	ilbadm_err(gettext("file %s cannot be opened for reading"), filename);
	Usage(name);
}

int
main(int argc, char *argv[])
{
	ilbadm_status_t	rc;
	int		c;
	int		fd = -1;
	int		flags = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* handle global options (-?, -V) first */
	while ((c = getopt(argc, argv, ":V:?")) != -1) {
		switch ((char)c) {
		case 'V': print_version(argv[0]);
			/* not reached */
			break;
		case '?':
			Usage(argv[0]);
			/* not reached */
			break;
		default: unknown_opt(argv, optind - 1);
			/* not reached */
			break;
		}
	}

	if (optind >= argc)
		incomplete_cmdline(argv[0]);

	/*
	 * we can import from a given file (argv[2]) or from
	 * stdin (if no file given)
	 */
	if (strcasecmp(argv[1], "import-config") == 0 ||
	    strcasecmp(argv[1], "import-cf") == 0) {
		int shift = 0;

		if (argc > 2 && strcmp(argv[2], "-p") == 0) {
			shift++;
			flags |= ILBADM_IMPORT_PRESERVE;
		}

		if (argc - shift < 3)
			fd = 0;
		else
			if ((fd = open(argv[2+shift], O_RDONLY)) == -1)
				bad_importfile(argv[0], argv[2+shift]);
	}

	argv++;
	argc--;

	/*
	 * re-set optind for next callers of getopt() - they all believe they're
	 * the first.
	 */
	optind = 1;
	optopt = 0;

	rc = ilbadm_import(fd, argc, argv, flags);

	/*
	 * The error messages have been printed out, using
	 * ilbadm_errstr() and ilb_errstr(), before we get here.
	 * So just set the exit value
	 */
	if (rc != ILBADM_OK)
		return (1);
	/* success */
	return (0);
}
