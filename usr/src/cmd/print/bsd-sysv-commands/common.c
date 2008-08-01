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

/* $Id: common.c 162 2006-05-08 14:17:44Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <alloca.h>
#include <string.h>
#include <libintl.h>
#include <ctype.h>
#include <pwd.h>
#include <papi.h>
#include "common.h"

#ifndef HAVE_GETPASSPHRASE	/* some systems don't have getpassphrase() */
#define	getpassphrase getpass
#endif

/* give the most verbose error message to the caller */
char *
verbose_papi_message(papi_service_t svc, papi_status_t status)
{
	char *mesg;

	mesg = papiServiceGetStatusMessage(svc);

	if (mesg == NULL)
		mesg = papiStatusString(status);

	return (mesg);
}

static int
match_job(int id, char *user, int ac, char *av[])
{
	int i;

	for (i = 0; i < ac; i++)
		if (strcmp("-", av[i]) == 0)
			return (0);	/* "current" user match */
		else if ((isdigit(av[i][0]) != 0) && (id == atoi(av[i])))
			return (0);	/* job-id match */
		else if (strcmp(user, av[i]) == 0)
			return (0);	/* user match */

	return (-1);
}

static struct {
	char *mime_type;
	char *lp_type;
} type_map[] = {
	{ "text/plain", "simple" },
	{ "application/octet-stream", "raw" },
	{ "application/octet-stream", "any" },
	{ "application/postscript", "postscript" },
	{ "application/postscript", "ps" },
	{ "application/x-cif", "cif" },
	{ "application/x-dvi", "dvi" },
	{ "application/x-plot", "plot" },
	{ "application/x-ditroff", "troff" },
	{ "application/x-troff", "otroff" },
	{ "application/x-pr", "pr" },
	{ "application/x-fortran", "fortran" },
	{ "application/x-raster", "raster" },
	{ NULL, NULL}
};

char *
lp_type_to_mime_type(char *lp_type)
{
	int i;

	if (lp_type == NULL)
		return ("application/octet-stream");

	for (i = 0; type_map[i].lp_type != NULL; i++)
		if (strcasecmp(type_map[i].lp_type, lp_type) == 0)
			return (type_map[i].mime_type);

	return (lp_type);
}

/*
 * to support job/printer status
 */
static char *
state_string(int state)
{
	switch (state) {
	case 3:
		return (gettext("idle"));
	case 4:
		return (gettext("processing"));
	case 5:
		return (gettext("stopped"));
	default:
		return (gettext("unknown"));
	}
}

static char *_rank_suffixes[] = {
	"th", "st", "nd", "rd", "th", "th", "th", "th", "th", "th"
};

static char *
rank_string(const int rank)
{
	static char buf[12];

	if (rank < 0)
		snprintf(buf, sizeof (buf), gettext("invalid"));
	else if (rank == 0)
		snprintf(buf, sizeof (buf), gettext("active"));
	else if ((rank > 10) && (rank < 14))
		sprintf(buf, "%dth", rank);
	else
		sprintf(buf, "%d%s", rank, _rank_suffixes[rank % 10]);

	return (buf);
}

static void
printer_state_line(FILE *fp, papi_printer_t p, int num_jobs, char *name)
{
	papi_attribute_t **list = papiPrinterGetAttributeList(p);
	int state = 0;
	char *reason = "";

	(void) papiAttributeListGetInteger(list, NULL,
				"printer-state", &state);
	(void) papiAttributeListGetString(list, NULL,
				"printer-state-reasons", &reason);
	(void) papiAttributeListGetString(list, NULL,
				"printer-name", &name);

	if ((state != 0x03) || (num_jobs != 0)) {
		fprintf(fp, "%s: %s", name, state_string(state));
		if (state == 0x05) /* stopped */
			fprintf(fp, ": %s\n", reason);
		else
			fprintf(fp, "\n");
	} else
		fprintf(fp, "no entries\n");
}

static void
print_header(FILE *fp)
{
	fprintf(fp, gettext("Rank\tOwner\t Job\tFile(s)\t\t\t\tTotal Size\n"));
}

static void
print_job_line(FILE *fp, int count, papi_job_t job, int fmt, int ac, char *av[])
{
	papi_attribute_t **list = papiJobGetAttributeList(job);
	int copies = 1, id = 0, rank = count, size = 0;
	char *name = "print job";
	char *user = "nobody";
	char *host = "localhost";
	char *suffix = "k";

	(void) papiAttributeListGetInteger(list, NULL,
					"job-id", &id);
	(void) papiAttributeListGetInteger(list, NULL,
					"job-id-requested", &id);
	(void) papiAttributeListGetString(list, NULL,
					"job-originating-user-name", &user);
	(void) papiAttributeListGetString(list, NULL,
					"job-originating-host-name", &host);

	/* if we are looking and it doesn't match, return early */
	if ((ac > 0) && (match_job(id, user, ac, av) < 0))
		return;

	(void) papiAttributeListGetInteger(list, NULL,
					"copies", &copies);
	(void) papiAttributeListGetInteger(list, NULL,
					"number-of-intervening-jobs", &rank);

	if (papiAttributeListGetInteger(list, NULL, "job-octets", &size)
			== PAPI_OK)
		suffix = "bytes";
	else
		(void) papiAttributeListGetInteger(list, NULL,
					"job-k-octets", &size);
	(void) papiAttributeListGetString(list, NULL,
					"job-name", &name);

	size *= copies;

	if (fmt == 3) {
		fprintf(fp, gettext("%s\t%-8.8s %d\t%-32.32s%d %s\n"),
			rank_string(++rank), user, id, name, size, suffix);
	} else
		fprintf(fp, gettext(
			"\n%s: %s\t\t\t\t[job %d %s]\n\t%-32.32s\t%d %s\n"),
			user, rank_string(++rank), id, host, name, size,
			suffix);
}

/*
 * to support job cancelation
 */
static void
cancel_job(papi_service_t svc, FILE *fp, char *printer, papi_job_t job,
		int ac, char *av[])
{
	papi_status_t status;
	papi_attribute_t **list = papiJobGetAttributeList(job);
	int id = 0;
	int rid = 0;
	char *user = "";
	char *mesg = gettext("cancelled");

	papiAttributeListGetInteger(list, NULL,
					"job-id", &id);
	papiAttributeListGetInteger(list, NULL,
					"job-id-requested", &rid);
	papiAttributeListGetString(list, NULL,
					"job-originating-user-name", &user);

	/* if we are looking and it doesn't match, return early */
	if ((ac > 0) && (match_job(id, user, ac, av) < 0) &&
	    (match_job(rid, user, ac, av) < 0))
		return;

	status = papiJobCancel(svc, printer, id);
	if (status != PAPI_OK)
		mesg = papiStatusString(status);

	fprintf(fp, "%s-%d: %s\n", printer, id, mesg);
}

int
berkeley_queue_report(papi_service_t svc, FILE *fp, char *dest, int fmt,
		int ac, char *av[])
{
	papi_status_t status;
	papi_printer_t p = NULL;
	papi_job_t *jobs = NULL;
	char *pattrs[] = { "printer-name", "printer-state",
			"printer-state-reasons", NULL };
	char *jattrs[] = { "job-name", "job-octets", "job-k-octets", "job-id",
			"job-originating-user-name", "job-id-requested",
			"job-originating-host-name",
			"number-of-intervening-jobs", NULL };
	int num_jobs = 0;

	status = papiPrinterQuery(svc, dest, pattrs, NULL, &p);
	if (status != PAPI_OK) {
		fprintf(fp, gettext(
			"Failed to query service for state of %s: %s\n"),
			dest, verbose_papi_message(svc, status));
		return (-1);
	}

	status = papiPrinterListJobs(svc, dest, jattrs, PAPI_LIST_JOBS_ALL,
					0, &jobs);
	if (status != PAPI_OK) {
		fprintf(fp, gettext(
			"Failed to query service for jobs on %s: %s\n"),
			dest, verbose_papi_message(svc, status));
		return (-1);
	}
	if (jobs != NULL) {
		while (jobs[num_jobs] != NULL)
			num_jobs++;
	}

	printer_state_line(fp, p, num_jobs, dest);
	if (num_jobs > 0) {
		int i;

		if (fmt == 3)
			print_header(fp);
		for (i = 0; jobs[i] != NULL; i++)
			print_job_line(fp, i, jobs[i], fmt, ac, av);
	}

	papiPrinterFree(p);
	papiJobListFree(jobs);

	return (num_jobs);
}

int
berkeley_cancel_request(papi_service_t svc, FILE *fp, char *dest,
		int ac, char *av[])
{
	papi_status_t status;
	papi_job_t *jobs = NULL;
	char *jattrs[] = { "job-originating-user-name", "job-id",
			"job-id-requested", NULL };

	status = papiPrinterListJobs(svc, dest, jattrs, PAPI_LIST_JOBS_ALL,
					0, &jobs);

	if (status != PAPI_OK) {
		fprintf(fp, gettext("Failed to query service for %s: %s\n"),
			dest, verbose_papi_message(svc, status));
		return (-1);
	}

	/* cancel the job(s) */
	if (jobs != NULL) {
		int i;

		for (i = 0; jobs[i] != NULL; i++)
			cancel_job(svc, fp, dest, jobs[i], ac, av);
	}

	papiJobListFree(jobs);

	return (0);
}

int
get_printer_id(char *name, char **printer, int *id)
{
	int result = -1;

	if (name != NULL) {
		char *p = strrchr(name, '-');

		*printer = name;
		if (p != NULL) {
			char *s = NULL;

			*id = strtol(p + 1, &s, 10);
			if (s[0] != '\0')
				*id = -1;
			else
				*p = '\0';
			result = 0;
		} else
			*id = -1;
	}

	return (result);
}

/*
 * strsplit() splits a string into a NULL terminated array of substrings
 * determined by a seperator.  The original string is modified, and newly
 * allocated space is only returned for the array itself.  If more than
 * 1024 substrings exist, they will be ignored.
 */
char **
strsplit(char *string, const char *seperators)
{
	char	*list[BUFSIZ],
		**result;
	int	length = 0;

	if ((string == NULL) || (seperators == NULL))
		return (NULL);

	(void) memset(list, 0, sizeof (list));
	for (list[length] = strtok(string, seperators);
		(list[length] != NULL) && (length < (BUFSIZ - 2));
		list[length] = strtok(NULL, seperators))
			length++;

	if ((result = (char **)calloc(length+1, sizeof (char *))) != NULL)
		(void) memcpy(result, list, length * sizeof (char *));

	return (result);
}

papi_status_t
jobSubmitSTDIN(papi_service_t svc, char *printer, char *prefetch, int len,
		papi_attribute_t **list, papi_job_t *job)
{
	papi_status_t status;
	papi_stream_t stream = NULL;
	int rc;
	char buf[BUFSIZ];

	status = papiJobStreamOpen(svc, printer, list, NULL, &stream);

	if (len > 0)
		status = papiJobStreamWrite(svc, stream, prefetch, len);

	while ((status == PAPI_OK) && ((rc = read(0, buf, sizeof (buf))) > 0))
		status = papiJobStreamWrite(svc, stream, buf, rc);

	if (status == PAPI_OK)
		status = papiJobStreamClose(svc, stream, job);

	return (status);
}

/*
 * is_postscript() will detect if the file passed in contains postscript
 * data.  A one is returned if the file contains postscript, zero is returned
 * if the file is not postscript, and -1 is returned if an error occurs
 */
#define	PS_MAGIC	"%!"
#define	PC_PS_MAGIC	"^D%!"
int
is_postscript_stream(int fd, char *buf, int *len)
{
	if ((*len = read(fd, buf, *len)) < 0) {
		close(fd);
		return (-1);
	}

	if ((strncmp(buf, PS_MAGIC, sizeof (PS_MAGIC) - 1) == 0) ||
	    (strncmp(buf, PC_PS_MAGIC, sizeof (PC_PS_MAGIC) - 1) == 0))
		return (1);
	else
		return (0);
}

int
is_postscript(const char *file)
{
	int rc = -1;
	int fd;

	if ((fd = open(file, O_RDONLY)) >= 0) {
		char buf[3];
		int len = sizeof (buf);

		rc = is_postscript_stream(fd, buf, &len);
		close(fd);
	}

	return (rc);
}

static char **
all_list(papi_service_t svc)
{
	papi_status_t status;
	papi_printer_t printer = NULL;
	char *list[] = { "member-names", NULL };
	char **result = NULL;

	status = papiPrinterQuery(svc, "_all", list, NULL, &printer);
	if ((status == PAPI_OK) && (printer != NULL)) {
		papi_attribute_t **attributes =
					papiPrinterGetAttributeList(printer);
		if (attributes != NULL) {
			void *iter = NULL;
			char *value = NULL;

			for (status = papiAttributeListGetString(attributes,
						&iter, "member-names", &value);
				status == PAPI_OK;
				status = papiAttributeListGetString(attributes,
						&iter, NULL, &value))
					list_append(&result, strdup(value));
		}
		papiPrinterFree(printer);
	}

	return (result);
}

static char **
printers_list(papi_service_t svc)
{
	papi_status_t status;
	papi_printer_t *printers = NULL;
	char *keys[] = { "printer-name", NULL };
	char **result = NULL;

	status = papiPrintersList(svc, keys, NULL, &printers);
	if ((status == PAPI_OK) && (printers != NULL)) {
		int i;

		for (i = 0; printers[i] != NULL; i++) {
			papi_attribute_t **attributes =
				papiPrinterGetAttributeList(printers[i]);
			char *name = NULL;

			(void) papiAttributeListGetString(attributes, NULL,
						"printer-name", &name);
			if ((name != NULL) && (strcmp(name, "_default") != 0))
				list_append(&result, strdup(name));
		}
		papiPrinterListFree(printers);
	}

	return (result);
}

char **
interest_list(papi_service_t svc)
{
	static char been_here;
	static char **result;

	if (been_here == 0) {	/* only do this once */
		been_here = 1;

		if ((result = all_list(svc)) == NULL)
			result = printers_list(svc);
	}

	return (result);
}

char *
localhostname()
{
	static char *result;

	if (result == NULL) {
		static char buf[256];

		if (gethostname(buf, sizeof (buf)) == 0)
			result = buf;
	}

	return (result);
}

int
cli_auth_callback(papi_service_t svc, void *app_data)
{
	char prompt[BUFSIZ];
	char *user, *svc_name, *passphrase;

	/* get the name of the service we are contacting */
	if ((svc_name = papiServiceGetServiceName(svc)) == NULL)
		return (-1);

	/* find our who we are supposed to be */
	if ((user = papiServiceGetUserName(svc)) == NULL) {
		struct passwd *pw;

		if ((pw = getpwuid(getuid())) != NULL)
			user = pw->pw_name;
		else
			user = "nobody";
	}

	/* build the prompt string */
	snprintf(prompt, sizeof (prompt),
		gettext("passphrase for %s to access %s: "), user, svc_name);

	/* ask for the passphrase */
	if ((passphrase = getpassphrase(prompt)) != NULL)
		papiServiceSetPassword(svc, passphrase);

	return (0);
}
