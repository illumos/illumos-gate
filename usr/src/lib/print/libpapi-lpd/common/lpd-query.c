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

/* $Id: lpd-query.c 155 2006-04-26 02:34:54Z ktou $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	__EXTENSIONS__	/* for strtok_r() */
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

#include <papi_impl.h>

static void
parse_lpd_job_entry(service_t *svc, int fd, job_t **job)
{
	char *iter = NULL;
	char line[128];
	papi_attribute_t **attributes = NULL;
	char *p;
	int octets = 0;

	*job = NULL;

	if (fdgets(line, sizeof (line), fd) == NULL)
		return;
	/*
	 * 1st line...
	 *	 user: rank			[job (ID)(host)]\n
	 */
	if ((p = strtok_r(line, ": ", &iter)) == NULL)	 /* user: ... */
		return; /* invalid format */
	papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
				"job-originating-user-name", p);

	p = strtok_r(NULL, "\t ", &iter);	/* ...rank... */
	papiAttributeListAddInteger(&attributes, PAPI_ATTR_REPLACE,
				"number-of-intervening-jobs", atoi(p) - 1);
	p = strtok_r(NULL, " ", &iter);		/* ...[job ... */
	if ((p = strtok_r(NULL, "]\n", &iter)) == NULL)	/* ...(id)(hostname)] */
		return;
	while (isspace(*p)) p++;
	papiAttributeListAddInteger(&attributes, PAPI_ATTR_REPLACE,
				"job-id", atoi(p));
	while (isdigit(*(++p)));
	while (isspace(*p)) p++;
	papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
				"job-originating-host-name", p);

	/*
	 * rest-o-lines
	 *	[(num) copies of ]file			size bytes\n
	 */
	while ((fdgets(line, sizeof (line), fd) != NULL) && (line[0] != '\n')) {
		int copies, size;
		char *q;

		/* find the number of copies */
		if ((p = strstr(line, "copies of")) != NULL) {
			copies = atoi(line);
			p += 9;
		} else {
			copies = 1;
			p = line;
		}
		papiAttributeListAddInteger(&attributes, PAPI_ATTR_EXCL,
				"copies", copies);

		/* eat the leading whitespace */
		while (isspace(*p) != 0)
			p++;
		if ((q = strstr(p, " bytes\n")) != NULL) {
			/* back up to the beginning of the size */
			do { q--; } while (isdigit(*q) != 0);

			/* seperate the name and size */
			*q = '\0';
			q++;

			size = atoi(q);

			papiAttributeListAddString(&attributes,
				PAPI_ATTR_APPEND, "job-name", p);
			papiAttributeListAddString(&attributes,
				PAPI_ATTR_APPEND, "job-file-names", p);
			papiAttributeListAddInteger(&attributes,
				PAPI_ATTR_APPEND, "job-file-sizes", size);

			octets += (size * copies);
		}
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

static void
parse_lpd_job_entries(service_t *svc, int fd)
{
	job_t *job = NULL;

	do {
		parse_lpd_job_entry(svc, fd, &job);
		list_append(&svc->cache->jobs, job);
	} while (job != NULL);

}


void
parse_lpd_query(service_t *svc, int fd)
{
	papi_attribute_t **attributes = NULL;
	cache_t *cache = NULL;
	int state = 0x03; /* idle */
	char line[128];
	char buf[1024];

	/* get the status line */
	if (fdgets(line, sizeof (line), fd) == NULL)
		return;	/* this should not happen. */

	papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
			"printer-name", queue_name_from_uri(svc->uri));

	if (uri_to_string(svc->uri, buf, sizeof (buf)) == 0)
		papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
				"printer-uri-supported", buf);

	papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
			"printer-state-reasons", line);

	if (strstr(line, "ready and printing") != NULL)
		state = 0x04; /* processing */
	else if ((strstr(line, "no entries") != NULL) ||
		 (strstr(line, "is ready") != NULL))
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

	if (fdgets(line, sizeof (line), fd) != NULL) {
		/* get the jobs */
		parse_lpd_job_entries(svc, fd);
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

	if ((fd = lpd_open(svc, 'q', NULL, 3)) < 0)
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
