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

/* $Id: lprm.c 146 2006-03-24 00:26:54Z njacobs $ */

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

int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	char *printer = NULL;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "EP:")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_REQUIRED;
			break;
		case 'P':
			printer = optarg;
			break;
		default:
			usage(av[0]);
		}

	if ((printer == NULL) &&
	    ((printer = getenv("PRINTER")) == NULL) &&
	    ((printer = getenv("LPDEST")) == NULL))
		printer = DEFAULT_DEST;

	status = papiServiceCreate(&svc, printer, NULL, NULL, cli_auth_callback,
					encryption, NULL);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext(
			"Failed to contact service for %s: %s\n"),
			printer, verbose_papi_message(svc, status));
		papiServiceDestroy(svc);
		return (1);
	}

	berkeley_cancel_request(svc, stdout, printer,
				ac - optind, &av[optind]);

	papiServiceDestroy(svc);

	return (0);
}
