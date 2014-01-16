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

#ifndef _PAPI_IMPL_H
#define	_PAPI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <papi.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <sys/types.h>
#include <stdarg.h>

/* lpsched include files */
#include <lp.h>
#include <msgs.h>
#include <printers.h>
#include <requests.h>


/*
 * Implementation specific types/prototypes/definitions follow
 *
 *
 * Ex:
 */

typedef struct {
	papi_attribute_t **attributes;
	int (*authCB)(papi_service_t svc, void *app_data);
	void *app_data;
	MESG *md;
	char *msgbuf;
	size_t msgbuf_size;
} service_t;

typedef struct job {
	papi_attribute_t **attributes;	/* job attributes */
} job_t;

typedef struct {
	papi_attribute_t **attributes;	/* queue attributes */
} printer_t;

typedef struct {
	int fd;
	REQUEST *request;
	char *meta_data_file;
	char added;
} job_stream_t;

extern void lpsched_read_job_configuration(service_t *svc, job_t *j,
				char *file);
extern void lpsched_request_to_job(REQUEST *r, job_t *j);

extern void job_status_to_attributes(job_t *job, char *req_id, char *user,
				char *slabel, size_t size, time_t date,
				short state, char *destination, char *form,
				char *charset, short rank, char *file);
extern papi_status_t addLPString(papi_attribute_t ***list,
					int flags, char *name, char *value);
extern papi_status_t papiAttributeListAddLPStrings(papi_attribute_t ***list,
					int flags, char *name, char **values);
extern void papiAttributeListGetLPString(papi_attribute_t **attributes,
			char *key, char **string);
extern void papiAttributeListGetLPStrings(papi_attribute_t **attributes,
			char *key, char ***string);

extern papi_status_t lpsched_printer_configuration_to_attributes(
				service_t *svc, printer_t *p, char *dest);
extern papi_status_t lpsched_class_configuration_to_attributes(service_t *svc,
	printer_t *p, char *dest);
extern papi_status_t class_status_to_attributes(printer_t *p, char *printer,
	short status, char *reject_reason, long reject_date);
extern papi_status_t lpsched_reject_printer(papi_service_t svc,
	char *printer, char *message);
extern papi_status_t lpsched_accept_printer(papi_service_t svc,
	char *printer);
extern papi_status_t lpsched_disable_printer(papi_service_t svc,
	char *printer, char *message);
extern papi_status_t lpsched_enable_printer(papi_service_t svc,
	char *printer);
extern papi_status_t lpsched_status_to_papi_status(int status);
extern papi_status_t job_attributes_to_lpsched_request(papi_service_t svc,
	REQUEST *r, papi_attribute_t **attributes);
extern papi_status_t lpsched_alloc_files(papi_service_t svc, int number,
	char **prefix);
extern papi_status_t lpsched_commit_job(papi_service_t svc, char *job,
	char **tmp);
extern papi_status_t lpsched_start_change(papi_service_t svc,
	char *printer, int32_t job_id, char **tmp);
extern papi_status_t lpsched_end_change(papi_service_t svc,
	char *printer, int32_t job_id);
extern papi_status_t printer_status_to_attributes(printer_t *p, char *printer,
	char *form, char *character_set, char *reject_reason,
	char *disable_reason, short status, char *request_id, long enable_date,
	long reject_date);
extern papi_status_t lpsched_remove_printer(papi_service_t svc, char *dest);
extern papi_status_t lpsched_remove_class(papi_service_t svc, char *dest);
extern papi_status_t lpsched_add_modify_printer(papi_service_t svc, char *dest,
	papi_attribute_t **attributes, int type);
extern papi_status_t lpsched_add_modify_class(papi_service_t svc, char *dest,
	papi_attribute_t **attributes);

extern void lpsched_service_information(papi_attribute_t ***attrs);
extern void lpsched_request_to_job_attributes(REQUEST *r, job_t *j);
extern void detailed_error(service_t *svc, char *fmt, ...);
extern char *banner_type(unsigned short banner);
extern char *mime_type_to_lp_type(char *mime_type);
extern char *lp_type_to_mime_type(char *lp_type);
extern char *fifo_name_from_uri(char *uri);
extern char *printer_name_from_uri_id(char *uri, int32_t id);

extern int snd_msg(service_t *svc, int type, ...);
extern int rcv_msg(service_t *svc, int type, ...);

#ifdef __cplusplus
}
#endif

#endif /* _PAPI_IMPL_H */
