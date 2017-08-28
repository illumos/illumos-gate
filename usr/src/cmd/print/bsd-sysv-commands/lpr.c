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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: lpr.c 146 2006-03-24 00:26:54Z njacobs $ */

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
		gettext("Usage: %s [-P printer] [-# copies] [-C class] "
				"[-J job] [-T title] "
				"[-p [-i indent] [-w width]] "
				"[-1|-2|-3|-4 font] [-m] [-h] [-s] "
				"[-filter_option] [file ..]\n"), name);
	exit(1);
}

int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_attribute_t **list = NULL;
	papi_job_t job = NULL;
	int exit_code = 0;
	char *printer = NULL;
	char prefetch[3];
	int prefetch_len = sizeof (prefetch);
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	int dump = 0;
	int validate = 0;
	int copy = 1;	/* default is to copy the data */
	char *document_format = "text/plain";
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av,
			"EP:#:C:DVJ:T:w:i:hplrstdgvcfmn1:2:3:4:")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_REQUIRED;
			break;
		case 'P':
			printer = optarg;
			break;
		case '#':
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
					"copies", atoi(optarg));
			break;
		case 'C':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"rfc-1179-class", optarg);
			break;
		case 'D':
			dump = 1;
			break;
		case 'J':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"job-name", optarg);
			break;
		case 'T':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"pr-title", optarg);
			break;
		case 'p':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-pr");
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
					"pr-filter", 1);
			break;
		case 'i':
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
					"pr-indent", atoi(optarg));
			break;
		case 'w':
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
					"pr-width", atoi(optarg));
			break;
		case 'h':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
					"job-sheets", "none");
			break;
		case 'l':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/octet-stream");
			break;
		case 'o':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/postscript");
			break;
		case 'c':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-cif");
			break;
		case 'd':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-dvi");
			break;
		case 'f':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-fortran");
			break;
		case 'g':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-plot");
			break;
		case 'n':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-ditroff");
			break;
		case 't':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-troff");
			break;
		case 'v':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", "application/x-raster");
			break;
		case 'm':
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
				"rfc-1179-mail", 1);
			break;
		case 'r':
			break;
		case 's':
			copy = 0;
			break;
		case 'V':	/* validate */
			validate = 1;
			break;
		case '1':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"rfc-1179-font-r", optarg);
			break;
		case '2':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"rfc-1179-font-i", optarg);
			break;
		case '3':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"rfc-1179-font-b", optarg);
			break;
		case '4':
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"rfc-1179-font-s", optarg);
			break;
		default:
			usage(av[0]);
		}

	if ((printer == NULL) &&
	    ((printer = getenv("PRINTER")) == NULL) &&
	    ((printer = getenv("LPDEST")) == NULL))
		printer = DEFAULT_DEST;

	if (((optind + 1) == ac) && (strcmp(av[optind], "-") == 0))
		optind = ac;

	if (optind != ac) {
		/* get the mime type of the file data */
#ifdef MAGIC_MIME
		magic_t ms;

		if ((ms = magic_open(MAGIC_MIME)) != NULL) {
			document_format = magic_file(ms, av[optind]);
			magic_close(ms);
		}
#else
		if (is_postscript(av[optind]) == 1)
			document_format = "application/postscript";
#endif
	} else {
		if (is_postscript_stream(0, prefetch, &prefetch_len) == 1)
			document_format = "application/postscript";
	}

	papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL, "copies", 1);
	papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"document-format", document_format);
	papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
				"job-sheets", "standard");

	status = papiServiceCreate(&svc, printer, NULL, NULL, cli_auth_callback,
					encryption, NULL);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext(
			"Failed to contact service for %s: %s\n"), printer,
			verbose_papi_message(svc, status));
		exit(1);
	}

	if (validate == 1)	/* validate the request can be processed */
		status = papiJobValidate(svc, printer, list,
					NULL, &av[optind], &job);
	else if (optind == ac)	/* no file list, use stdin */
		status = jobSubmitSTDIN(svc, printer, prefetch, prefetch_len,
					list, &job);
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

	if (dump != 0) {
		list = papiJobGetAttributeList(job);
		printf("job attributes:\n");
		papiAttributeListPrint(stdout, list, "\t");
		printf("\n");
	}

	papiJobFree(job);
	papiServiceDestroy(svc);

	return (exit_code);
}
