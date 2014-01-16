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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* $Id: lpmove.c 146 2006-03-24 00:26:54Z njacobs $ */

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

	fprintf(stdout,
	    gettext("Usage: %s [request-id] (destination)\n"
	    "       %s (source) (destination)\n"), name, name);
	exit(1);
}

static int
move_job(papi_service_t svc, char *src, int32_t id, char *dest)
{
	int result = 0;
	papi_status_t status;
	char *mesg = gettext("moved");

	status = papiJobMove(svc, src, id, dest);
	if (status != PAPI_OK) {
		mesg = (char *)verbose_papi_message(svc, status);
		result = -1;
	}
	fprintf(stderr, gettext("%s-%d to %s: %s\n"), src, id, dest, mesg);

	return (result);
}

int
main(int ac, char *av[])
{
	int exit_code = 0;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	char *destination = NULL;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "E:")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_REQUIRED;
			break;
		default:
			usage(av[0]);
		}

	if (optind >= ac - 1)
		usage(av[0]);

	destination = av[--ac];

	for (c = optind; c < ac; c++) {
		papi_status_t status;
		papi_service_t svc = NULL;
		papi_job_t *jobs = NULL;
		char *printer = NULL;
		int32_t id = -1;

		(void) get_printer_id(av[c], &printer, &id);

		status = papiServiceCreate(&svc, printer, NULL, NULL,
		    cli_auth_callback, encryption, NULL);
		if (status != PAPI_OK) {
			fprintf(stderr, gettext(
			    "Failed to contact service for %s: %s\n"),
			    printer, verbose_papi_message(svc, status));
			exit(1);
		}

		if (id != -1) {	/* it's a job */
			if (move_job(svc, printer, id, destination) < 0)
				exit_code = 1;
		} else {	/* it's a printer */
			char message[128];
			int count = 0;

			snprintf(message, sizeof (message), "moved jobs to %s",
			    destination);
			status = papiPrinterPause(svc, printer, message);
			if (status != PAPI_OK) {
				/*
				 * If the user is denied the permission
				 * to disable then return appropriate msg
				 */
				char *result = NULL;

				result = papiServiceGetStatusMessage(svc);

				if (result != NULL) {
					/*
					 * Check if user is denied
					 * the permission
					 */
					if (strstr(result, "permission denied")
					    != NULL) {
						/*
						 * user is denied
						 * permission
						 */
						fprintf(stderr, "UX:lpmove: ");
						fprintf(stderr,
						    gettext("ERROR: "));
						fprintf(stderr, gettext("You "
						    "aren't allowed to do"
						    " that."));
						fprintf(stderr, "\n\t");
						fprintf(stderr,
						    gettext("TO FIX"));
						fprintf(stderr, ": ");
						fprintf(stderr, gettext("You "
						    "must be logged in as "
						    "\"lp\" or \"root\"."));
						fprintf(stderr, "\n");
						exit_code = 1;
					} else {
						fprintf(stderr, gettext(
						    "Reject %s: %s\n"),
						    printer,
						    verbose_papi_message(
						    svc, status));
						exit_code = 1;
					}
				} else {
					fprintf(stderr, gettext(
					    "Reject %s: %s\n"),
					    printer,
					    verbose_papi_message(svc, status));
					exit_code = 1;
				}
			} else {
				printf(gettext(
				    "destination %s is not accepting"\
				    " requests\n"), printer);

				status = papiPrinterListJobs(svc, printer, NULL,
				    0, 0, &jobs);
				if (status != PAPI_OK) {
					fprintf(stderr, gettext("Jobs %s:"\
					    " %s\n"),
					    printer,
					    verbose_papi_message(svc, status));
					exit_code = 1;
				}

				printf(gettext("move in progress ...\n"));
				while ((jobs != NULL) && (*jobs != NULL)) {
					id = papiJobGetId(*jobs++);
					if (move_job(svc, printer,
					    id, destination) < 0)
						exit_code = 1;
					else
						count++;
				}
				printf(gettext(
				    "total of %d requests moved"\
				    " from %s to %s\n"),
				    count, printer, destination);

				papiJobListFree(jobs);
			}
		}

		papiServiceDestroy(svc);
	}

	return (exit_code);
}
