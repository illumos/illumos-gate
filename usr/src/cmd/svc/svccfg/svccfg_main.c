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

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * svccfg - modify service configuration repository
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/zone.h>

#include <errno.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zone.h>

#include "svccfg.h"

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

#define	MAX_CMD_LINE_SZ	2048

static const char *myname;
int g_verbose = 0;
int g_do_zone = 0;
char g_zonename[ZONENAME_MAX];
const char *fmri;

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage:\tsvccfg [-v] [-z zone] [-s FMRI] [-f file]\n"
	    "\tsvccfg [-v] [-z zone] [-s FMRI] <command> [args]\n"));
	exit(UU_EXIT_USAGE);
}

void *
safe_malloc(size_t sz)
{
	void *p;

	if ((p = calloc(1, sz)) == NULL)
		uu_die(gettext("Out of memory.\n"));

	return (p);
}

char *
safe_strdup(const char *cp)
{
	char *result;

	result = strdup(cp);
	if (result == NULL)
		uu_die(gettext("Out of memory.\n"));

	return (result);
}

/*
 * Send a message to the user.  If we're interactive, send it to stdout.
 * Otherwise send it to stderr.
 */
static void
vmessage(const char *fmt, va_list va)
{
	int interactive = est->sc_cmd_flags & SC_CMD_IACTIVE;
	FILE *strm = interactive ? stdout : stderr;
	const char *ptr;

	if (!interactive) {
		if (est->sc_cmd_file == NULL)
			(void) fprintf(stderr, "%s: ", myname);
		else
			(void) fprintf(stderr, "%s (%s, line %d): ", myname,
			    est->sc_cmd_filename, est->sc_cmd_lineno - 1);
	}

	if (vfprintf(strm, fmt, va) < 0 && interactive)
		uu_die(gettext("printf() error"));

	ptr = strchr(fmt, '\0');
	if (*(ptr - 1) != '\n')
		(void) fprintf(strm, ": %s.\n", strerror(errno));
}

/*
 * Display a warning.  Should usually be predicated by g_verbose.
 */
/* PRINTFLIKE1 */
void
warn(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vmessage(fmt, va);
	va_end(va);
}

/*
 * Syntax error.
 */
void
synerr(int com)
{
	if (est->sc_cmd_flags & SC_CMD_IACTIVE) {
		help(com);
		return;
	}

	warn(gettext("Syntax error.\n"));

	if ((est->sc_cmd_flags & SC_CMD_DONT_EXIT) == 0)
		exit(1);
}

/*
 * Semantic error.  Display the warning and exit if we're not interactive.
 */
/* PRINTFLIKE1 */
void
semerr(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vmessage(fmt, va);
	va_end(va);

	if ((est->sc_cmd_flags & (SC_CMD_IACTIVE | SC_CMD_DONT_EXIT)) == 0)
		exit(1);
}

/*ARGSUSED*/
static void
initialize(int argc, char *argv[])
{
	myname = uu_setpname(argv[0]);
	(void) atexit(lscf_cleanup);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) lxml_init();
	internal_init();
	engine_init();
	lscf_init();			/* must follow engine_init() */
	tmpl_init();
}

int
main(int argc, char *argv[])
{
	char *cmd, *command_file = NULL;
	char *fmri = NULL;
	int c;

	while ((c = getopt(argc, argv, "vf:s:z:")) != EOF) {
		switch (c) {
		case 'v':
			g_verbose = 1;
			break;

		case 's':
			fmri = optarg;
			break;

		case 'f':
			command_file = optarg;
			break;

		case 'z':
			if (getzoneid() != GLOBAL_ZONEID) {
				uu_die(gettext("svccfg -z may only be used "
				    "from the global zone\n"));
			}

			if (strlcpy(g_zonename, optarg, sizeof (g_zonename)) >=
			    sizeof (g_zonename)) {
				uu_die(gettext(
				    "The provided zone name is too long, "
				    "max %zd\n"), sizeof (g_zonename) - 1);
			}
			g_do_zone = 1;
			break;

		default:
			usage();
			break;
		}
	}

	initialize(argc, argv);

	if (fmri != NULL)
		lscf_select(fmri);

	if (command_file != NULL)
		return (engine_source(command_file, 0));

	if (optind == argc) {
		if (isatty(fileno(stdin)))
			return (engine_interp());
		else
			return (engine_source("-", 0));
	}

	/*
	 * Knit together remaining arguments into a single statement.
	 */
	cmd = safe_malloc(MAX_CMD_LINE_SZ);
	for (c = optind; c < argc; c++) {
		(void) strlcat(cmd, argv[c], MAX_CMD_LINE_SZ);
		(void) strlcat(cmd, " ", MAX_CMD_LINE_SZ);
	}

	return (engine_exec(cmd));
}
