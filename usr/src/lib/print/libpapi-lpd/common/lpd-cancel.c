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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: lpd-cancel.c 155 2006-04-26 02:34:54Z ktou $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	__EXTENSIONS__	/* for strtok_r() */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <papi_impl.h>

papi_status_t
lpd_cancel_job(service_t *svc, int id)
{
	papi_status_t status = PAPI_INTERNAL_ERROR;
	int fd;
	char *list[2];
	char buf[128];	/* this should be overkill */

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	snprintf(buf, sizeof (buf), "%d", id);
	list[0] = buf;
	list[1] = NULL;

	if ((fd = lpd_open(svc, 'c', list, 15)) < 0)
		return (PAPI_INTERNAL_ERROR);

	memset(buf, 0, sizeof (buf));
	if (fdgets(buf, sizeof (buf), fd) != NULL) {
		if (buf[0] == '\0')
			status = PAPI_NOT_FOUND;
		else if (strstr(buf, "permission denied") != NULL)
			status = PAPI_NOT_AUTHORIZED;
		else if ((strstr(buf, "cancelled") != NULL) ||
			 (strstr(buf, "removed") != NULL))
			status = PAPI_OK;
	} else
		status = PAPI_NOT_FOUND;

	close(fd);

	return (status);
}

papi_status_t
lpd_purge_jobs(service_t *svc, job_t ***jobs)
{
	papi_status_t status = PAPI_INTERNAL_ERROR;
	int fd;
	char *queue;
	char buf[256];

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	if ((fd = lpd_open(svc, 'c', NULL, 15)) < 0)
		return (PAPI_INTERNAL_ERROR);

	queue = queue_name_from_uri(svc->uri);

	status = PAPI_OK;
	memset(buf, 0, sizeof (buf));
	while (fdgets(buf, sizeof (buf), fd) != NULL) {
		/* if we canceled it, add it to the list */
		if ((strstr(buf, "cancelled") != NULL) ||
		    (strstr(buf, "removed") != NULL)) {
			job_t *job;
			papi_attribute_t **attributes = NULL;
			char *ptr, *iter = NULL;
			int id;

			ptr = strtok_r(buf, ":", &iter);
			papiAttributeListAddString(&attributes, PAPI_ATTR_EXCL,
					"job-name", ptr);
			id = atoi(ptr);
			papiAttributeListAddInteger(&attributes, PAPI_ATTR_EXCL,
					"job-id", id);
			papiAttributeListAddString(&attributes, PAPI_ATTR_EXCL,
					"job-printer", queue);

			if ((job = (job_t *)calloc(1, (sizeof (*job))))
					!= NULL) {
				job->attributes = attributes;
				list_append(jobs, job);
			} else
				papiAttributeListFree(attributes);
		} else if (strstr(buf, "permission denied") != NULL)
			status = PAPI_NOT_AUTHORIZED;
	}
	close(fd);

	return (status);
}
