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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <locale.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif

#include <ns.h>
#include <list.h>

extern char *optarg;
extern int optind, opterr, optopt;
extern char *getenv(const char *);


static void
Usage(char *name)
{
	(void) fprintf(stderr,
		gettext("Usage: %s [-k key] [list|(printer) ...]\n"),
		name);
	exit(1);
}

static int
display_kvp(char *key, char *value)
{
	int rc = -1;

	if (value != NULL) {
		rc = 0;
		(void) printf("\n\t%s=%s", key, value);
	} else
		(void) printf(gettext("\n\t%s - undefined"), key);

	return (rc);
}


static int
display_value(ns_printer_t *printer, char *name, char **keys)
{
	int rc = -1;

	if (printer != NULL) {
		rc = 0;
		(void) printf("%s:", name);
		if (keys != NULL) {
			while (*keys != NULL) {
				char *string = ns_get_value_string(*keys,
							printer);
				rc += display_kvp(*keys, string);
				keys++;
			}
		} else {
			ns_kvp_t **list = printer->attributes;

			for (list = printer->attributes;
			    (list != NULL && *list != NULL); list++) {
				char *string;
				if (((*list)->key[0] == '\t') ||
				    ((*list)->key[0] == ' '))
					continue;

				string = ns_get_value_string((*list)->key,
							    printer);
				rc += display_kvp((*list)->key, string);
			}
		}
		(void) printf("\n");
	} else
		(void) printf(gettext("%s: Not Found\n"), name);

	return (rc);
}


/*
 *  main() calls the appropriate routine to parse the command line arguments
 *	and then calls the local remove routine, followed by the remote remove
 *	routine to remove jobs.
 */
int
main(int ac, char *av[])
{
	char *program;
	int c;
	char **keys = NULL;
	char *ns = NULL;
	int exit_code = 0;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((program = strrchr(av[0], '/')) == NULL)
		program = av[0];
	else
		program++;

	openlog(program, LOG_PID, LOG_LPR);
	while ((c = getopt(ac, av, "k:t:n:")) != EOF)
		switch (c) {
		case 'k':
		case 't':
			keys = (char **)list_append((void **)keys,
						    (void *)optarg);
			break;
		case 'n':
			ns = optarg;
			break;
		default:
			Usage(program);
		}

	if (optind >= ac)
		Usage(program);

	ns = normalize_ns_name(ns);

	while (optind < ac) {
		char *name = av[optind++];

		if (strcmp(name, "list") == 0) {
			ns_printer_t **printers = ns_printer_get_list(ns);

			while (printers != NULL && *printers != NULL) {
				exit_code += display_value(*printers,
						(*printers)->name, keys);
				printers++;
			}
		} else
			exit_code = display_value(ns_printer_get_name(name, ns),
						name, keys);


	}
	return (exit_code);
}
