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

/* $Id: cancel.c 147 2006-04-25 16:51:06Z njacobs $ */

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

	fprintf(stdout, "Usage: %s [-u user] (printer|request-id ...)\n", name);
	exit(1);
}

int
main(int ac, char *av[])
{
	int exit_code = 0;
	char *user = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "Eu:")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_REQUIRED;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage(av[0]);
		}

	for (c = optind; c < ac; c++) {
		papi_status_t status;
		papi_service_t svc = NULL;
		papi_job_t *jobs = NULL;
		char *printer = NULL;
		int32_t id = -1;

		(void) get_printer_id(av[c], &printer, &id);

		status = papiServiceCreate(&svc, printer, user, NULL,
					cli_auth_callback, encryption, NULL);
		if (status != PAPI_OK) {
			fprintf(stderr, gettext(
				"Failed to contact service for %s: %s\n"),
				printer, verbose_papi_message(svc, status));
			exit(1);
		}

#define	OUT	((status == PAPI_OK) ? stdout : stderr)

		if (id != -1) {	/* it's a job */
			char *mesg = "cancelled";

			status = papiJobCancel(svc, printer, id);
			if (status != PAPI_OK) {
				mesg = verbose_papi_message(svc, status);
				exit_code = 1;
			}
			fprintf(OUT, "%s-%d: %s\n", printer, id, mesg);
		} else {	/* it's a printer */
			status = papiPrinterPurgeJobs(svc, printer, &jobs);
			if (status != PAPI_OK) {
				fprintf(stderr, gettext("PurgeJobs %s: %s\n"),
					printer,
					verbose_papi_message(svc, status));
				exit_code = 1;
			}

			while ((jobs != NULL) && (*jobs != NULL))
				fprintf(OUT, "%s-%d: %s\n", printer,
					papiJobGetId(*jobs++), "cancelled");

			papiJobListFree(jobs);
		}

		papiServiceDestroy(svc);
	}

	return (exit_code);
}
