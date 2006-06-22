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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>

#include <ns.h>


static ns_printer_t *printer_object = NULL;
static FILE *lfp = NULL;


static void
log_printf(char *fmt, ...)
{
	if (lfp != NULL) {
		va_list	ap;

		va_start(ap, fmt);
		(void) vfprintf(lfp, fmt, ap);
		va_end(ap);
		(void) fflush(lfp);
	}
}


int
test_spooler_available(const char *printer)
{
	int rc = 0;
	char *tmp;

	if ((printer_object = ns_printer_get_name(printer, NULL)) == NULL)
		return (-1);

	if ((tmp = ns_get_value_string("test-log", printer_object)) != NULL)
		lfp = fopen(tmp, "a+");

	if (((tmp = ns_get_value_string("test-spooler-available",
					printer_object)) != NULL) &&
			(strcasecmp(tmp, "false") == 0))
		rc = -1;

	log_printf("test_spooler_available(%s): "
		"test-spooler-available = %s (%d)\n",
		(printer ? printer : "NULL"), (tmp ? tmp : "NULL"), rc);

	return (rc);
}


int
test_spooler_accepting_jobs(const char *printer)
{
	int rc = 0;
	char *tmp;

	if (((tmp = ns_get_value_string("test-accepting", printer_object))
			!= NULL) && (strcasecmp(tmp, "false") == 0))
		rc = -1;

	log_printf(
		"test_spooler_accepting_jobs(%s): test-accepting = %s (%d)\n",
		(printer ? printer : "NULL"), (tmp ? tmp : "NULL"), rc);

	return (rc);
}


int
test_client_access(const char *printer, const char *host)
{
	int rc = 0;
	char *tmp;

	if (((tmp = ns_get_value_string("test-access", printer_object))
			!= NULL) && (strcasecmp(tmp, "false") == 0))
		rc = -1;

	log_printf("test_client_access(%s, %s): test-access = %s (%d)\n",
		(printer ? printer : "NULL"), (host ? host : "NULL"),
		(tmp ? tmp : "NULL"), rc);

	return (rc);
}


char *
test_temp_dir(const char *printer, const char *host)
{
	char *tmp;

	if ((tmp = ns_get_value_string("test-dir", printer_object)) == NULL)
		tmp = strdup("/tmp");

	log_printf("test_temp_dir(%s, %s): test-dir = %s\n",
		(printer ? printer : "NULL"), (host ? host : "NULL"),
		(tmp ? tmp : "NULL"));

	return (tmp);
}


int
test_restart_printer(const char *printer)
{
	int rc = 0;
	char *tmp;

	if (((tmp = ns_get_value_string("test-restart", printer_object))
			!= NULL) && (strcasecmp(tmp, "false") == 0))
		rc = -1;

	log_printf("test_restart_printer(%s): test-restart = %s (%d)\n",
		(printer ? printer : "NULL"), (tmp ? tmp : "NULL"), rc);

	return (rc);
}


int
test_submit_job(const char *printer, const char *host, char *cf,
		    char **df_list)
{
	FILE *fp;
	char *tmp;

	if (((tmp = ns_get_value_string("test-submit", printer_object))
			!= NULL) && (strcasecmp(tmp, "false") == 0))
		return (-1);

	df_list[0][0] = 'c';
	if ((fp = fopen(df_list[0], "w")) != 0) {
		(void) fprintf(fp, "%s", cf);
		(void) fclose(fp);
	}
	df_list[0][0] = 'c';

	log_printf("test_submit_job(%s, %s): test-submit = %s\n",
		(printer ? printer : "NULL"), (host ? host : "NULL"),
		(tmp ? tmp : "NULL"));
	log_printf("\tcontrol = %s\n", df_list[0]);
	df_list[0][0] = 'd';
	while (*df_list != NULL)
		log_printf("\tdata = %s\n", *df_list++);

	return (0);
}


int
test_show_queue(const char *printer, FILE *ofp, const int type,
			const char **list)
{
	char	*file = NULL;
	FILE	*fp;

	if (((file = ns_get_value_string("test-show-queue-file",
					printer_object)) != NULL) &&
			((fp = fopen(file, "r+")) != NULL)) {
		char buf[1024];

		while (fgets(buf, sizeof (buf), fp) != NULL)
			(void) fputs(buf, ofp);
		(void) fclose(fp);
	} else
		(void) fprintf(ofp, "no entries\n");

	log_printf("test_show_queue(%s, 0x%x, %s):\n",
		(printer ? printer : "NULL"), ofp,
		(type == 3 ? "short" : "long"));
	log_printf("\tfile = %s\n", (file ? file : "NULL"));
	while (*list != NULL)
		log_printf("\tjob or user = %s\n", *list++);

	return (0);
}


int
test_cancel_job(const char *printer, FILE *ofp, const char *user,
			const char *host, const char **list)
{
	char *file = NULL;

	if ((file = ns_get_value_string("test-cancel-job-file", printer_object))
			!= NULL)

	if (file != NULL) {
		FILE *fp;
		char buf[1024];

		if ((fp = fopen(file, "r+")) != NULL) {
			while (fgets(buf, sizeof (buf), fp) != NULL)
				(void) fputs(buf, ofp);
			(void) fclose(fp);
		}
	}

	log_printf("test_cancel_job(%s, 0x%x, %s, %s):\n",
		(printer ? printer : "NULL"), ofp, (user ? user : "NULL"),
		(host ? host : "NULL"));
	while (*list != NULL)
		log_printf("\tjob or user = %s\n", *list++);

	return (0);
}
