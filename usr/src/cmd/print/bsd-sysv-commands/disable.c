
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
 * Copyright 2017 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: disable.c 146 2006-03-24 00:26:54Z njacobs $ */


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
	    gettext("Usage: %s [-c] [-W] [-r reason] destination ...\n"),
	    name);
	exit(1);
}

static void
cancel_active_job(papi_service_t svc, char *dest)
{
	papi_status_t status;
	papi_job_t *j = NULL;
	char *req_attrs[] = { "job-state", "job-id", NULL };

	status = papiPrinterListJobs(svc, dest, req_attrs, 0, 0, &j);
	if ((status == PAPI_OK) && (j != NULL)) {
		int i;

		for (i = 0; j[i] != NULL; j++) {
			papi_attribute_t **a = papiJobGetAttributeList(j[i]);
			int state = 0;

			if (a == NULL)
				continue;

			(void) papiAttributeListGetInteger(a, NULL,
			    "job-state", &state);
			if (state & 0x082A) { /* If state is RS_ACTIVE */
				int32_t id = papiJobGetId(j[i]);

				(void) papiJobCancel(svc, dest, id);
			}
		}
		papiJobListFree(j);
	}
}

int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	int exit_status = 0;
	int cancel = 0;
	char *reason = NULL;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "EcWr:")) != EOF)
		switch (c) {
		case 'c':	/* cancel active job first */
			cancel = 1;
			break;
		case 'W':	/* wait for active request, not implemented */
			break;
		case 'r':	/* reason */
			reason = optarg;
			break;
		case 'E':
			encryption = PAPI_ENCRYPT_NEVER;
			break;
		default:
			usage(av[0]);
		}

	if (ac <= optind)
		usage(av[0]);

	while (optind < ac) {
		char *printer = av[optind++];

		status = papiServiceCreate(&svc, printer, NULL, NULL,
		    cli_auth_callback, encryption, NULL);
		if (status != PAPI_OK) {
			fprintf(stderr, gettext(
			    "Failed to contact service for %s: %s\n"),
			    printer, verbose_papi_message(svc, status));
			exit_status = 1;
		}

		status = papiPrinterDisable(svc, printer, reason);
		if (status == PAPI_OK) {
			printf(gettext("printer \"%s\" now disabled\n"),
			    printer);
		} else if (status == PAPI_NOT_ACCEPTING) {
			fprintf(stderr, gettext(
			    "Destination \"%s\" was already disabled.\n"),
			    printer);
			exit_status = 1;
		} else {
			/* The operation is not supported in lpd protocol */
			if (status == PAPI_OPERATION_NOT_SUPPORTED) {
				fprintf(stderr,
				    verbose_papi_message(svc, status));
			} else {
				fprintf(stderr, gettext("disable: %s: %s\n"),
				    printer, verbose_papi_message(svc, status));
			}
			exit_status = 1;
		}

		if (cancel != 0)
			cancel_active_job(svc, printer);

		papiServiceDestroy(svc);
	}

	return (exit_status);
}
