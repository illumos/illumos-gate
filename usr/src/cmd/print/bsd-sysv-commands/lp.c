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

/* $Id: lp.c 179 2006-07-17 18:24:07Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <papi.h>
#include "common.h"

#ifdef HAVE_LIBMAGIC	/* for mimetype auto-detection */
#include <magic.h>
#endif /* HAVE_LIBMAGIC */

static void
usage(char *program)
{
	char *name;

	if ((name = strrchr(program, '/')) == NULL)
		name = program;
	else
		name++;

	fprintf(stdout,
		gettext("Usage: %s [-c] [-m] [-p] [-s] [-w] [-d destination]  "
			"[-f form-name] [-H special-handling] [-n number] "
			"[-o option] [-P page-list] [-q priority-level]  "
			"[-S character-set | print-wheel]  [-t title] [-v] "
			"[-T content-type [-r]] [-y mode-list] [file...]\n"),
		name);
	exit(1);
}

int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_attribute_t **list = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	papi_job_t job = NULL;
	char prefetch[3];
	int prefetch_len = sizeof (prefetch);
	char *printer = NULL;
	char b = PAPI_TRUE;
	int copy = 0;
	int silent = 0;
	int dump = 0;
	int validate = 0;
	int modify = -1;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "DEH:P:S:T:cd:f:i:mn:o:pq:rst:Vwy:")) != EOF)
		switch (c) {
		case 'H':	/* handling */
			if (strcasecmp(optarg, "hold") == 0)
				papiAttributeListAddString(&list,
					PAPI_ATTR_EXCL,
					"job-hold-until", "indefinite");
			else if (strcasecmp(optarg, "immediate") == 0)
				papiAttributeListAddString(&list,
					PAPI_ATTR_EXCL,
					"job-hold-until", "no-hold");
			else
				papiAttributeListAddString(&list,
					PAPI_ATTR_EXCL,
					"job-hold-until", optarg);
			break;
		case 'P': {	/* page list */
			char buf[BUFSIZ];

			snprintf(buf, sizeof (buf), "page-ranges=%s", optarg);
			papiAttributeListFromString(&list,
					PAPI_ATTR_EXCL, buf);
			}
			break;
		case 'S':	/* charset */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"lp-charset", optarg);
			break;
		case 'T':	/* type */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"document-format",
					lp_type_to_mime_type(optarg));
			break;
		case 'D':	/* dump */
			dump = 1;
			break;
		case 'c':	/* copy */
			copy = 1;
			break;
		case 'd':	/* destination */
			printer = optarg;
			break;
		case 'f':	/* form */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"form", optarg);
			break;
		case 'i':	/* modify job */
			if ((get_printer_id(optarg, &printer, &modify) < 0) ||
			    (modify < 0)) {
				fprintf(stderr,
					gettext("invalid request id: %s\n"),
					optarg);
				exit(1);
			}
			break;
		case 'm':	/* mail when complete */
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
				"rfc-1179-mail", 1);
			break;
		case 'n':	/* copies */
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
					"copies", atoi(optarg));
			break;
		case 'o':	/* lp "options" */
			papiAttributeListFromString(&list,
					PAPI_ATTR_REPLACE, optarg);
			break;
		case 'p':	/* Solaris - notification */
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
				"rfc-1179-mail", 1);
			break;
		case 'q': {	/* priority */
			int i = atoi(optarg);

			i = 100 - (i * 2.5);
			if ((i < 1) || (i > 100)) {
				fprintf(stderr, gettext(
				    "priority must be between 0 and 39.\n"));
				exit(1);
			}
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
					"job-priority", i);
			}
			break;
		case 'r':	/* "raw" mode */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"document-format",
					"application/octet-stream");
			papiAttributeListAddString(&list, PAPI_ATTR_APPEND,
					"stty", "raw");
			break;
		case 's':	/* suppress message */
			silent = 1;
			break;
		case 't':	/* title */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"job-name", optarg);
			break;
		case 'V':	/* validate */
			validate = 1;
			break;
		case 'w':
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
				"rfc-1179-mail", 1);
			break;
		case 'y':	/* lp "modes" */
			papiAttributeListAddString(&list, PAPI_ATTR_APPEND,
					"lp-modes", optarg);
			break;
		case 'E':
			encryption = PAPI_ENCRYPT_REQUIRED;
			break;
		default:
			usage(av[0]);
		}

	/* convert "banner", "nobanner" to "job-sheet" */
	if (papiAttributeListGetBoolean(list, NULL, "banner", &b) == PAPI_OK) {
		(void) papiAttributeListDelete(&list, "banner");
		if (b == PAPI_FALSE)
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
						"job-sheets", "none");
	}

	if ((printer == NULL) &&
	    ((printer = getenv("PRINTER")) == NULL) &&
	    ((printer = getenv("LPDEST")) == NULL))
		printer = DEFAULT_DEST;

	if (((optind + 1) == ac) && (strcmp(av[optind], "-") == 0))
		optind = ac;

	if (modify == -1) {
		char *document_format = "text/plain";

		if (optind != ac) {
			/* get the mime type of the file data */
#ifdef MAGIC_MIME
			magic_t ms = NULL;

			if ((ms = magic_open(MAGIC_MIME)) != NULL) {
				document_format = magic_file(ms, av[optind]);
				magic_close(ms);
			}
#else
			if (is_postscript(av[optind]) == 1)
				document_format = "application/postscript";
#endif
		} else {
			if (is_postscript_stream(0, prefetch, &prefetch_len)
						== 1)
				document_format = "application/postscript";
		}

		papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL, "copies", 1);
		papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", document_format);
		papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"job-sheets", "standard");
	}

	status = papiServiceCreate(&svc, printer, NULL, NULL, cli_auth_callback,
					encryption, NULL);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext(
			"Failed to contact service for %s: %s\n"), printer,
			verbose_papi_message(svc, status));
		exit(1);
	}

	if (dump != 0) {
		printf("requesting attributes:\n");
		papiAttributeListPrint(stdout, list, "\t");
		printf("\n");
	}

	if (modify != -1)
		status = papiJobModify(svc, printer, modify, list, &job);
	else if (optind == ac)	/* no file list, use stdin */
		status = jobSubmitSTDIN(svc, printer, prefetch, prefetch_len,
					list, &job);
	else if (validate == 1)	/* validate the request can be processed */
		status = papiJobValidate(svc, printer, list,
					NULL, &av[optind], &job);
	else if (copy == 0)	/* reference the files in the job, default */
		status = papiJobSubmitByReference(svc, printer, list,
					NULL, &av[optind], &job);
	else			/* copy the files before return, -c */
		status = papiJobSubmit(svc, printer, list,
					NULL, &av[optind], &job);

	papiAttributeListFree(list);

	if (status != PAPI_OK) {
		fprintf(stderr, gettext("%s: %s\n"), printer,
			verbose_papi_message(svc, status));
		papiJobFree(job);
		papiServiceDestroy(svc);
		exit(1);
	}

	if (((silent == 0) || (dump != 0)) &&
	    ((list = papiJobGetAttributeList(job)) != NULL)) {
		int32_t id = 0;

		papiAttributeListGetString(list, NULL,
					"printer-name", &printer);
		papiAttributeListGetInteger(list, NULL, "job-id", &id);
		printf(gettext("request id is %s-%d "), printer, id);
		if (ac != optind)
			printf("(%d file(s))\n", ac - optind);
		else
			printf("(standard input)\n");

		if (dump != 0) {
			printf("job attributes:\n");
			papiAttributeListPrint(stdout, list, "\t");
			printf("\n");
		}
	}

	papiJobFree(job);
	papiServiceDestroy(svc);

	return (0);
}
