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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: lpd-query.c 155 2006-04-26 02:34:54Z ktou $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <regex.h>

#include <papi_impl.h>

/* The string is modified by this call */
static char *
regvalue(regmatch_t match, char *string)
{
	char *result = NULL;

	if (match.rm_so != match.rm_eo) {
		result = string + match.rm_so;
		*(result + (match.rm_eo - match.rm_so)) = '\0';
	}

	return (result);
}

/*
 * Print job entries start with:
 * 	(user):	(rank)			[job (number) (...)]
 *   (user) is the job-owner's user name
 *   (rank) is the rank in queue. (active, 1st, 2nd, ...)
 *   (number) is the job number
 *   (...) is an optional hostname
 *   some servers will use whitespace a little differently than is displayed
 *   above.  The regular expression below makes whitespace optional in some
 *   places.
 */
static char *job_expr = "^(.*[[:alnum:]]):[[:space:]]+([[:alnum:]]+)[[:space:]]+[[][[:space:]]*job[[:space:]]*([[:digit:]]+)[[:space:]]*(.*)]";
static regex_t job_re;

/*
 * Print job entries for remote windows printer start with:
 *	Owner Status Jobname Job-Id Size Pages Priority
 *    e.g:
 *    Owner   Status        Jobname      Job-Id  Size  Pages Priority
 *    ------------------------------------------------------------
 *    root (10.3. Waiting   /etc/release  2	 240   1     4
 *
 *    Owner is the job-owner's user name
 *    Status is the job-status (printing, waiting, error)
 *    Jobname is the name of the job to be printed
 *    Job-Id is the id of the job queued to be printed
 *    Size is the size of the job in bytes
 *    Pages is the number of pages of the job
 *    Priority is the job-priority
 */
static char *wjob_expr = "^([[:alnum:]]+)[[:space:]]*[(](.*)[)]*[[:space:]]+([[:alnum:]]+)[[:space:]]+(.*)([[:alnum:]]+)(.*)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:digit:]]+)";
static regex_t wjob_re;

/*
 * Windows job header is in the following format
 * Owner  Status    Jobname      Job-Id    Size   Pages  Priority
 * --------------------------------------------------------------
 */
static char *whjob_expr = "Owner       Status         Jobname          Job-Id    Size   Pages  Priority";
static regex_t whjob_re;

static char *wline_expr = "----------";
static regex_t wline_re;

/*
 * status line(s) for "processing" printers will contain one of the following:
 *	ready and printing
 *	Printing
 */
static char *proc_expr = "(ready and printing|printing)";
static regex_t proc_re;

/*
 * status line(s) for "idle" printers will contain one of the following:
 *	no entries
 *	(printer) is ready
 *	idle
 */
static char *idle_expr = "(no entries|is ready| idle)";
static regex_t idle_re;

/*
 * Printer state reason
 *	Paused
 */
static char *state_reason_expr = "(Paused)";
static regex_t state_reason_re;

/*
 * document line(s)
 *	(copies) copies of (name)		(size) bytes
 *	(name)		(size) bytes
 *   document lines can be in either format above.
 *   (copies) is the number of copies of the document to print
 *   (name) is the name of the document: /etc/motd, ...
 *   (size) is the number of bytes in the document data
 */
static char *doc1_expr = "[[:space:]]+(([[:digit:]]+) copies of )([^[:space:]]+)[[:space:]]*([[:digit:]]+) bytes";
static char *doc2_expr = "[[:space:]]+()([^[:space:]]+)[[:space:]]*([[:digit:]]+) bytes";
static regex_t doc1_re;
static regex_t doc2_re;

static void
parse_lpd_job(service_t *svc, job_t **job, int fd, char *line, int len)
{
	papi_attribute_t **attributes = NULL;
	regmatch_t matches[10];
	char *s;
	int octets = 0;
	int flag = 0;

	/*
	 * job_re and wjob_re were compiled in the calling function
	 * first check for solaris jobs
	 * if there is no-match check for windows jobs
	 */

	if (regexec(&job_re, line, (size_t)5, matches, 0) == REG_NOMATCH) {
		if (regexec(&wjob_re, line, (size_t)10, matches, 0)
		    == REG_NOMATCH)
			return;
		else
			flag = 1;
	}

	if (flag == 1) {
		/* Windows job */
		/* first match is job-id */
		if ((s = regvalue(matches[1], line)) == NULL)
			s = "nobody";
		papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
		    "job-originating-user-name", s);

		if ((s = regvalue(matches[4], line)) == NULL)
			s = "unknown";
		papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
		    "job-name", s);
		papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
		    "job-file-names", s);

		if ((s = regvalue(matches[7], line)) == NULL)
			s = "0";
		papiAttributeListAddInteger(&attributes, PAPI_ATTR_REPLACE,
		    "job-id", atoi(s));

		if ((s = regvalue(matches[8], line)) == NULL)
			s = "0";
		octets = atoi(s);
		papiAttributeListAddInteger(&attributes,
		    PAPI_ATTR_APPEND, "job-file-sizes", atoi(s));

	} else {
		/* Solaris job */
		if ((s = regvalue(matches[1], line)) == NULL)
			s = "nobody";
		papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
		    "job-originating-user-name", s);

		if ((s = regvalue(matches[2], line)) == NULL)
			s = "0";
		papiAttributeListAddInteger(&attributes, PAPI_ATTR_REPLACE,
		    "number-of-intervening-jobs", atoi(s) - 1);

		if ((s = regvalue(matches[3], line)) == NULL)
			s = "0";
		papiAttributeListAddInteger(&attributes, PAPI_ATTR_REPLACE,
		    "job-id", atoi(s));

		if ((s = regvalue(matches[4], line)) == NULL)
			s = svc->uri->host;
		papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
		    "job-originating-host-name", s);
	}

	while ((fdgets(line, len, fd) != NULL) &&
	    (regexec(&job_re, line, (size_t)0, NULL, 0) == REG_NOMATCH) &&
	    (regexec(&wjob_re, line, (size_t)0, NULL, 0) == REG_NOMATCH)) {
		int size = 0, copies = 1;
		/* process copies/documents */

		/* doc1_re and doc2_re were compiled in the calling function */
		if ((regexec(&doc1_re, line, (size_t)4, matches, 0) != 0) &&
		    (regexec(&doc2_re, line, (size_t)4, matches, 0) != 0))
			continue;

		if ((s = regvalue(matches[1], line)) == NULL)
			s = "1";
		if ((copies = atoi(s)) < 1)
			copies = 1;

		if ((s = regvalue(matches[2], line)) == NULL)
			s = "unknown";
		papiAttributeListAddString(&attributes,
		    PAPI_ATTR_APPEND, "job-name", s);
		papiAttributeListAddString(&attributes,
		    PAPI_ATTR_APPEND, "job-file-names", s);

		if ((s = regvalue(matches[3], line)) == NULL)
			s = "0";
		size = atoi(s);

		papiAttributeListAddInteger(&attributes,
		    PAPI_ATTR_APPEND, "job-file-sizes", size);

		octets += (size * copies);
	}

	papiAttributeListAddInteger(&attributes, PAPI_ATTR_APPEND,
	    "job-k-octets", octets/1024);
	papiAttributeListAddInteger(&attributes, PAPI_ATTR_APPEND,
	    "job-octets", octets);
	papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
	    "printer-name", queue_name_from_uri(svc->uri));

	if ((*job = (job_t *)calloc(1, sizeof (**job))) != NULL)
		(*job)->attributes = attributes;
}

void
parse_lpd_query(service_t *svc, int fd)
{
	papi_attribute_t **attributes = NULL;
	cache_t *cache = NULL;
	int state = 0x03; /* idle */
	char line[128];
	char status[1024];
	char *s;

	papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
	    "printer-name", queue_name_from_uri(svc->uri));

	if (uri_to_string(svc->uri, status, sizeof (status)) == 0)
		papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
		    "printer-uri-supported", status);

	/*
	 * on most systems, status is a single line, but some appear to
	 * return multi-line status messages.  To get the "best" possible
	 * printer-state-reason, we accumulate the text until we hit the
	 * first print job entry.
	 *
	 * Print job entries start with:
	 * 	user:	rank			[job number ...]
	 */
	(void) regcomp(&job_re, job_expr, REG_EXTENDED|REG_ICASE);

	/*
	 * For remote windows printers
	 * Print job entries start with:
	 *  Owner  Status  Jobname  Job-Id  Size  Pages  Priority
	 */
	(void) regcomp(&wjob_re, wjob_expr, REG_EXTENDED|REG_ICASE);
	(void) regcomp(&whjob_re, whjob_expr, REG_EXTENDED|REG_ICASE);
	(void) regcomp(&wline_re, wline_expr, REG_EXTENDED|REG_ICASE);

	status[0] = '\0';

	while ((fdgets(line, sizeof (line), fd) != NULL) &&
	    (regexec(&job_re, line, (size_t)0, NULL, 0) == REG_NOMATCH) &&
	    (regexec(&wjob_re, line, (size_t)0, NULL, 0) == REG_NOMATCH)) {
		/*
		 * When windows job queue gets queried following header
		 * should not get printed
		 * Owner Status Jobname Job-Id Size Pages Priority
		 * -----------------------------------------------
		 */
		if ((regexec(&whjob_re, line, (size_t)0, NULL, 0)
		    == REG_NOMATCH) && (regexec(&wline_re, line, (size_t)0, NULL, 0)
		    == REG_NOMATCH))
			strlcat(status, line, sizeof (status));
	}

	/* chop off trailing whitespace */
	s = status + strlen(status) - 1;
	while ((s > status) && (isspace(*s) != 0))
		*s-- = '\0';

	papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
	    "printer-state-reasons", status);

	(void) regcomp(&proc_re, proc_expr, REG_EXTENDED|REG_ICASE);
	(void) regcomp(&idle_re, idle_expr, REG_EXTENDED|REG_ICASE);
	(void) regcomp(&state_reason_re, state_reason_expr,
	    REG_EXTENDED|REG_ICASE);

	if ((regexec(&proc_re, status, (size_t)0, NULL, 0) == 0) ||
	    (regexec(&state_reason_re, status, (size_t)0, NULL, 0) ==
	    REG_NOMATCH))
		state = 0x04; /* processing */
	else if (regexec(&idle_re, status, (size_t)0, NULL, 0) == 0)
		state = 0x03; /* idle */
	else
		state = 0x05; /* stopped */

	papiAttributeListAddInteger(&attributes, PAPI_ATTR_REPLACE,
	    "printer-state", state);

	if ((cache = (cache_t *)calloc(1, sizeof (*cache))) == NULL)
		return;

	if ((cache->printer = (printer_t *)calloc(1, sizeof (*cache->printer)))
	    == NULL)
		return;

	cache->printer->attributes = attributes;
	svc->cache = cache;

	(void) regcomp(&doc1_re, doc1_expr, REG_EXTENDED|REG_ICASE);
	(void) regcomp(&doc2_re, doc2_expr, REG_EXTENDED|REG_ICASE);
	/* process job related entries */
	while (line[0] != '\0') {
		job_t *job = NULL;

		parse_lpd_job(svc, &job, fd, line, sizeof (line));
		if (job == NULL)
			break;
		list_append(&cache->jobs, job);
	}

	time(&cache->timestamp);
}

void
cache_update(service_t *svc)
{
	int fd;

	if (svc->cache != NULL)	/* this should be time based */
		return;

	if (svc == NULL)
		return;

	if ((fd = lpd_open(svc, 'q', NULL, 15)) < 0)
		return;

	parse_lpd_query(svc, fd);

	close(fd);
}

papi_status_t
lpd_find_printer_info(service_t *svc, printer_t **printer)
{
	papi_status_t result = PAPI_BAD_ARGUMENT;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	cache_update(svc);

	if (svc->cache != NULL) {
		*printer = svc->cache->printer;
		result = PAPI_OK;
	} else
		result = PAPI_NOT_FOUND;

	return (result);
}

papi_status_t
lpd_find_jobs_info(service_t *svc, job_t ***jobs)
{
	papi_status_t result = PAPI_BAD_ARGUMENT;

	if (svc != NULL) {
		cache_update(svc);

		if (svc->cache != NULL) {
			*jobs = svc->cache->jobs;
			result = PAPI_OK;
		}
	}

	return (result);
}

papi_status_t
lpd_find_job_info(service_t *svc, int job_id, job_t **job)
{
	papi_status_t result = PAPI_BAD_ARGUMENT;
	job_t **jobs;

	if (lpd_find_jobs_info(svc, &jobs) != PAPI_OK) {
		int i;

		*job = NULL;
		for (i = 0; ((*job == NULL) && (jobs[i] != NULL)); i++) {
			int id = -1;

			papiAttributeListGetInteger(jobs[i]->attributes, NULL,
			    "job-id", &id);
			if (id == job_id)
				*job = jobs[i];
		}

		if (*job != NULL)
			result = PAPI_OK;
	}

	return (result);
}

void
cache_free(cache_t *item)
{
	if (item != NULL) {
		if (item->printer != NULL)
			papiPrinterFree((papi_printer_t *)item->printer);
		if (item->jobs != NULL)
			papiJobListFree((papi_job_t *)item->jobs);
		free(item);
	}
}
