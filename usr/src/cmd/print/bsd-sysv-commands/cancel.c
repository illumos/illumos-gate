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
 *
 */

/* $Id: cancel.c 147 2006-04-25 16:51:06Z njacobs $ */


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
cancel_jobs_for_user(char *user, papi_encryption_t encryption, char *pname) {

	papi_status_t status;
	papi_service_t svc = NULL;
	char **printers = NULL;
	int i, exit_code;

	if (pname == NULL) {
		status = papiServiceCreate(&svc, NULL, user, NULL,
		    cli_auth_callback, encryption, NULL);
		printers = interest_list(svc);
		papiServiceDestroy(svc);
	} else {
		list_append(&printers, strdup(pname));
	}

	if (printers == NULL)
		exit(0);

	for (i = 0; printers[i] != NULL; i++) {
		char *printer = printers[i];

		status = papiServiceCreate(&svc, printer, user, NULL,
		    cli_auth_callback, encryption, NULL);

		if (status != PAPI_OK) {
			fprintf(stderr, gettext(
			    "Failed to contact service for %s: %s\n"),
			    printer, verbose_papi_message(svc, status));
			exit(1);
		}
		exit_code = berkeley_cancel_request(svc, stdout, printer, 1,
		    &user);

		papiServiceDestroy(svc);
		if (exit_code != 0)
			break;
	}
	free(printers);
	return (exit_code);
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

	if (ac == 1)
		usage(av[0]);

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
			fprintf(stderr,
			    gettext("Failed to contact service for %s: %s\n"),
			    printer, verbose_papi_message(svc, status));
			exit(1);
		}

#define	OUT	((status == PAPI_OK) ? stdout : stderr)

		if (id != -1) {	/* it's a job */
			char *mesg = "cancelled";

			status = papiJobCancel(svc, printer, id);
			if (status == PAPI_NOT_AUTHORIZED) {
				mesg = papiStatusString(status);
				exit_code = 1;
			} else if (status != PAPI_OK) {
				mesg = verbose_papi_message(svc, status);
				exit_code = 1;
			}
			fprintf(OUT, "%s-%d: %s\n", printer, id, mesg);

		} else {	/* it's a printer */
			if (user == NULL) {

				/* Remove first job from printer */

				status = papiPrinterListJobs(svc, printer,
				    NULL, NULL, 0, &jobs);

				if (status != PAPI_OK) {
					fprintf(stderr, gettext(
					    "ListJobs %s: %s\n"), printer,
					    verbose_papi_message(svc, status));
					exit_code = 1;
				}

				if (jobs != NULL && *jobs != NULL) {
					char *mesg = "cancelled";
					id = papiJobGetId(*jobs);

					status = papiJobCancel(svc,
					    printer, id);

					if (status == PAPI_NOT_AUTHORIZED) {
						mesg = papiStatusString(status);
						exit_code = 1;
					} else if (status != PAPI_OK) {
						mesg = verbose_papi_message(
						    svc, status);
						exit_code = 1;
					}
					fprintf(OUT, "%s-%d: %s\n", printer,
					    id, mesg);

				}
				papiJobListFree(jobs);

			} else {
				/* Purging user's print jobs */
				exit_code = cancel_jobs_for_user(user,
				    encryption, printer);
			}
		}
		papiServiceDestroy(svc);
	}

	if (optind == ac)
		exit_code = cancel_jobs_for_user(user, encryption, NULL);

	return (exit_code);
}
