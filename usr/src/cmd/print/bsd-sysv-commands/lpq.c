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
 *
 */

/* $Id: lpq.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <papi.h>
#include "common.h"

static void
usage(char *program)
{
	char *name;

	if ((name = strrchr(program, '/')) == NULL)
		name = program;
	else
		name++;

	fprintf(stdout, gettext("Usage: %s [-P printer] (user|id ...)\n"),
			name);
	exit(1);
}

static void
clear_screen()
{
	static char buf[32];

	/* quick and dirty for now, this should be fixed real soon */
	if (buf[0] == '\0') {
		FILE *fp = popen("/bin/tput clear", "r");
		if (fp != NULL) {
			fgets(buf, sizeof (buf), fp);
			fclose(fp);
		}
	}
	printf("%s", buf);
}

int
main(int ac, char *av[])
{
	char *printer = NULL;
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	int format = 3;	/* lpq short format */
	int interval = 0;
	int num_jobs;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "EP:l")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_REQUIRED;
			break;
		case 'P':
			printer = optarg;
			break;
		case 'l':
			format = 4;	/* lpq long format */
			break;
		default:
			usage(av[0]);
		}

	if ((optind < ac) && (av[optind][0] == '+'))
		interval = atoi(av[optind++]);

	if ((printer == NULL) &&
	    ((printer = getenv("PRINTER")) == NULL) &&
	    ((printer = getenv("LPDEST")) == NULL))
		printer = DEFAULT_DEST;

	status = papiServiceCreate(&svc, printer, NULL, NULL, cli_auth_callback,
					encryption, NULL);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext(
			"Failed to contact service for %s: %s\n"), printer,
			verbose_papi_message(svc, status));
		papiServiceDestroy(svc);
		exit(1);
	}

	do {
		if (interval != 0)
			clear_screen();

		num_jobs = berkeley_queue_report(svc, stdout, printer, format,
					ac - optind, &av[optind]);

		if ((interval != 0) && (num_jobs > 0))
			sleep(interval);
	} while ((interval > 0) && (num_jobs > 0));

	papiServiceDestroy(svc);

	return (0);
}
