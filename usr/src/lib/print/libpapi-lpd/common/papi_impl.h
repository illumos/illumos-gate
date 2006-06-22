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

#ifndef _PAPI_IMPL_H
#define	_PAPI_IMPL_H

/* $Id: papi_impl.h 161 2006-05-03 04:32:59Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <papi.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <sys/types.h>
#include <stdarg.h>
#include <uri.h>

typedef struct {
	papi_attribute_t **attributes;
} printer_t;

typedef struct job {
	papi_attribute_t **attributes;
} job_t;

typedef struct stream {
	job_t  *job;		/* describes current job */
	int fd;			/* the fd to write to */
	char *metadata;		/* the converted metadata */
	char *dfname;		/* the stream data (if we can't stream) */

} stream_t;

typedef struct {	/* used for query operations only */
	time_t timestamp;
	printer_t *printer;
	job_t **jobs;
} cache_t;

typedef struct {
	papi_attribute_t **attributes;		/* extra info */
	uri_t *uri;				/* printer uri */
	cache_t *cache;				/* printer/job cache */
	int (*authCB)(papi_service_t svc, void *app_data);	/* unused */
	void *app_data;				/* unused */
} service_t;


extern papi_status_t service_fill_in(service_t *svc, char *name);
extern void detailed_error(service_t *svc, char *fmt, ...);
extern char *queue_name_from_uri(uri_t *uri);
extern char *fdgets(char *buf, size_t len, int fd);


/* lpd operations */
	/* open a connection to remote print service */
extern int lpd_open(service_t *svc, char type, char **args,
				int timeout);
	/* job cancelation */
extern papi_status_t lpd_purge_jobs(service_t *svc, job_t ***jobs);
extern papi_status_t lpd_cancel_job(service_t *svc, int job_id);
	/* job submission */
extern papi_status_t lpd_submit_job(service_t *svc, char *metadata,
				papi_attribute_t ***attributes, int *fd);
extern papi_status_t lpd_job_add_attributes(service_t *svc,
				papi_attribute_t **attributes,
				char **metadata,
				papi_attribute_t ***used_attributes);
extern papi_status_t lpd_job_add_files(service_t *svc,
				papi_attribute_t **attributes, char **files,
				char **metadata,
				papi_attribute_t ***used_attributes);
	/* query cache lookup routines */
extern papi_status_t lpd_find_printer_info(service_t *svc, printer_t **result);
extern papi_status_t lpd_find_job_info(service_t *svc, int job_id, job_t **job);
extern papi_status_t lpd_find_jobs_info(service_t *svc, job_t ***jobs);


#ifdef __cplusplus
}
#endif

#endif /* _PAPI_IMPL_H */
