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

/* $Id: enable.c 146 2006-03-24 00:26:54Z njacobs $ */

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

	fprintf(stdout,
		gettext("Usage: %s destination ...\n"),
		name);
	exit(1);
}

int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	int exit_status = 0;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "E")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_ALWAYS;
			break;
		default:
			usage(av[0]);
		}

	if (ac == optind)
		usage(av[0]);

	for (c = optind; c < ac; c++) {
		char *printer = av[c];

		status = papiServiceCreate(&svc, printer, NULL, NULL,
					cli_auth_callback, encryption, NULL);
		if (status != PAPI_OK) {
			fprintf(stderr, gettext(
				"Failed to contact service for %s: %s\n"),
				printer, verbose_papi_message(svc, status));
			exit_status = 1;
		}

		status = papiPrinterEnable(svc, printer);
		if (status != PAPI_OK) {
			fprintf(stderr, gettext("enable: %s: %s\n"), printer,
				verbose_papi_message(svc, status));
			exit_status = 1;
		}

		papiServiceDestroy(svc);
	}

	return (exit_status);
}
