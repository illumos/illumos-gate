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

/* $Id: in.lpd.c 170 2006-05-20 05:58:49Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>

#include <papi.h>
#include "common.h"

#define	ACK(fp)		{ (void) fputc('\0', fp); (void) fflush(fp); }
#define	NACK(fp)	{ (void) fputc('\1', fp); (void) fflush(fp); }

/*
 * This file contains the front-end of the BSD Print Protocol adaptor.  This
 * code assumes a BSD Socket interface to the networking side.
 */

void
fatal(FILE *fp, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	vfprintf(fp, fmt, ap);
	va_end(ap);
}

static void
cleanup(char **files)
{
	if (files != NULL) {
		int i;

		for (i = 0; files[i] != NULL; i++)
			unlink(files[i]);
	}
}

static void
berkeley_receive_files(papi_service_t svc, FILE *ifp, FILE *ofp)
{
	char line[BUFSIZ];
	char **files = NULL;	/* the job data files */

	/* This should actually implement transfer job from RFC-1179 */
	ACK(ofp);

	while (fgets(line, sizeof (line), ifp) != NULL) {
		switch (line[0]) {
		case 0x01:	/* Abort */
			cleanup(files);
			break;
		case 0x02:	/* Receive control file */

			break;
		case 0x03: {	/* Receive data file */
			char file[] = "lpdXXXXXX";
			int fd;

			fd = mkstemp(file);

			list_append(&files, strdup(file));
			}
			break;
		default:
			fatal(ofp, "protocol screwup");
			cleanup(files);
			break;
		}
	}

	cleanup(files);
}

static void
berkeley_transfer_files(papi_service_t svc, FILE *ifp, FILE *ofp,
		char *printer)
{
	papi_status_t status;
	papi_printer_t p = NULL;
	char *keys[] = { "printer-is-accepting", NULL };

	status = papiPrinterQuery(svc, printer, keys, NULL, &p);
	if ((status == PAPI_OK) && (p != NULL)) {
		papi_attribute_t **attrs = papiPrinterGetAttributeList(p);
		char accepting = PAPI_FALSE;

		papiAttributeListGetBoolean(attrs, NULL,
				"printer-is-accepting", &accepting);

		if (accepting == PAPI_TRUE)
			berkeley_receive_files(svc, ifp, ofp);
		else
			NACK(ofp);

		papiPrinterFree(p);
	} else
		NACK(ofp);
}

/*
 * This is the entry point for this program.  The program takes the
 * following options:
 * 	(none)
 */
int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	FILE	*ifp = stdin,
		*ofp = stdout;
	int	c;
	char	buf[BUFSIZ],
		**args,
		*printer;

	openlog("bsd-gw", LOG_PID, LOG_LPR);

	while ((c = getopt(ac, av, "d")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_ALWAYS;
			break;
		case 'd':
		default:
			;
		}

	if (fgets(buf, sizeof (buf), ifp) == NULL) {
		if (feof(ifp) == 0)
			syslog(LOG_ERR, "Error reading from connection: %s",
				strerror(errno));
		exit(1);
	}

	if ((buf[0] < 1) || (buf[0] > 5)) {
		fatal(ofp, "Invalid protocol request (%d): %c%s\n",
			buf[0], buf[0], buf);
		exit(1);
	}

	args = strsplit(&buf[1], "\t\n ");
	printer = *args++;

	if (printer == NULL) {
		fatal(ofp, "Can't determine requested printer");
		exit(1);
	}

	status = papiServiceCreate(&svc, printer, NULL, NULL, NULL,
					encryption, NULL);
	if (status != PAPI_OK) {
		fatal(ofp, "Failed to contact service for %s: %s\n", printer,
			verbose_papi_message(svc, status));
		exit(1);
	}

#ifdef HAVE_IS_SYSTEM_LABELED
	if (is_system_labeled()) {
		int fd = fileno(ifp);

		(void) papiServiceSetPeer(svc, fd);
	}
#endif

	switch (buf[0]) {
	case '\1':	/* restart printer */
		ACK(ofp);	/* there is no equivalent */
		break;
	case '\2':	/* transfer job(s) */
		berkeley_transfer_files(svc, ifp, ofp, printer);
		break;
	case '\3':	/* show queue (short) */
	case '\4': {	/* show queue (long) */
		int count;

		for (count = 0; args[count] != 0; count++);

		berkeley_queue_report(svc, ofp, printer, buf[0], count, args);
		}
		break;
	case '\5': {	/* cancel job(s) */
		char *requestor = *args++;
		int count;

		status = papiServiceSetUserName(svc, requestor);
		for (count = 0; args[count] != 0; count++);

		berkeley_cancel_request(svc, ofp, printer, count, args);
		}
		break;
	default:
		fatal(ofp, "unsupported protocol request (%c), %s",
			buf[0], &buf[1]);
	}

	(void) fflush(ofp);

	syslog(LOG_DEBUG, "protocol request(%d) for %s completed: %s",
		buf[0], printer, papiStatusString(status));
	syslog(LOG_DEBUG, "detail: %s", verbose_papi_message(svc, status));

	papiServiceDestroy(svc);

	return (0);
}
