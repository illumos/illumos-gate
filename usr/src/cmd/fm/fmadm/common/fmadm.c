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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include <fmadm.h>

static const char *g_pname;
static fmd_adm_t *g_adm;
static int g_quiet;

/*PRINTFLIKE1*/
void
note(const char *format, ...)
{
	va_list ap;

	if (g_quiet)
		return; /* suppress notices if -q specified */

	(void) fprintf(stdout, "%s: ", g_pname);
	va_start(ap, format);
	(void) vfprintf(stdout, format, ap);
	va_end(ap);
}

static void
vwarn(const char *format, va_list ap)
{
	int err = errno;

	(void) fprintf(stderr, "%s: ", g_pname);

	if (format != NULL)
		(void) vfprintf(stderr, format, ap);

	errno = err; /* restore errno for fmd_adm_errmsg() */

	if (format == NULL)
		(void) fprintf(stderr, "%s\n", fmd_adm_errmsg(g_adm));
	else if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", fmd_adm_errmsg(g_adm));
}

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vwarn(format, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
die(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vwarn(format, ap);
	va_end(ap);

	fmd_adm_close(g_adm);
	exit(FMADM_EXIT_ERROR);
}

static const struct cmd {
	int (*cmd_func)(fmd_adm_t *, int, char *[]);
	const char *cmd_name;
	const char *cmd_usage;
	const char *cmd_desc;
} cmds[] = {
{ cmd_config, "config", NULL, "display fault manager configuration" },
{ cmd_faulty, "faulty", "[-afgiprsv] [-u <uuid>] [-n <max_fault>]",
	"display list of faulty resources" },
{ cmd_flush, "flush", "<fmri> ...", "flush cached state for resource" },
{ cmd_gc, "gc", "<module>", NULL },
{ cmd_load, "load", "<path>", "load specified fault manager module" },
{ cmd_repair, "repair", "<fmri>|<uuid>", "record repair to resource(s)" },
{ cmd_reset, "reset", "[-s serd] <module>", "reset module or sub-component" },
{ cmd_rotate, "rotate", "<logname>", "rotate log file" },
{ cmd_unload, "unload", "<module>", "unload specified fault manager module" },
{ NULL, NULL, NULL }
};

static int
usage(FILE *fp)
{
	const struct cmd *cp;
	char buf[256];

	(void) fprintf(fp,
	    "Usage: %s [-P prog] [-q] [cmd [args ... ]]\n\n", g_pname);

	for (cp = cmds; cp->cmd_name != NULL; cp++) {
		if (cp->cmd_desc == NULL)
			continue;

		if (cp->cmd_usage != NULL) {
			(void) snprintf(buf, sizeof (buf), "%s %s %s",
			    g_pname, cp->cmd_name, cp->cmd_usage);
		} else {
			(void) snprintf(buf, sizeof (buf), "%s %s",
			    g_pname, cp->cmd_name);
		}
		(void) fprintf(fp, "\t%-30s - %s\n", buf, cp->cmd_desc);
	}

	return (FMADM_EXIT_USAGE);
}

static uint32_t
getu32(const char *name, const char *s)
{
	u_longlong_t val;
	char *p;

	errno = 0;
	val = strtoull(s, &p, 0);

	if (errno != 0 || p == s || *p != '\0' || val > UINT32_MAX) {
		(void) fprintf(stderr, "%s: invalid %s argument -- %s\n",
		    g_pname, name, s);
		exit(FMADM_EXIT_USAGE);
	}

	return ((uint32_t)val);
}

int
main(int argc, char *argv[])
{
	const struct cmd *cp;
	uint32_t program;
	const char *p;
	int c, err;

	if ((p = strrchr(argv[0], '/')) == NULL)
		g_pname = argv[0];
	else
		g_pname = p + 1;

	if ((p = getenv("FMD_PROGRAM")) != NULL)
		program = getu32("$FMD_PROGRAM", p);
	else
		program = FMD_ADM_PROGRAM;

	while ((c = getopt(argc, argv, "P:q")) != EOF) {
		switch (c) {
		case 'P':
			program = getu32("program", optarg);
			break;
		case 'q':
			g_quiet++;
			break;
		default:
			return (usage(stderr));
		}
	}

	if (optind >= argc)
		return (usage(stdout));

	for (cp = cmds; cp->cmd_name != NULL; cp++) {
		if (strcmp(cp->cmd_name, argv[optind]) == 0)
			break;
	}

	if (cp->cmd_name == NULL) {
		(void) fprintf(stderr, "%s: illegal subcommand -- %s\n",
		    g_pname, argv[optind]);
		return (usage(stderr));
	}

	if ((g_adm = fmd_adm_open(NULL, program, FMD_ADM_VERSION)) == NULL)
		die(NULL); /* fmd_adm_errmsg() has enough info */

	argc -= optind;
	argv += optind;

	optind = 1; /* reset optind so subcommands can getopt() */

	err = cp->cmd_func(g_adm, argc, argv);
	fmd_adm_close(g_adm);
	return (err == FMADM_EXIT_USAGE ? usage(stderr) : err);
}
