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

#include <http.h>
#include <ipp.h>

/*
 * Implementation specific types/prototypes/definitions follow
 *
 *
 * Ex:
 */
typedef enum {
	TRANSFER_ENCODING_CHUNKED,
	TRANSFER_ENCODING_LENGTH
} http_transfer_encoding_t;

typedef struct {
	papi_attribute_t **attributes;
	char *name;
	char *user;
	char *password;
	int (*authCB)(papi_service_t svc, void *app_data);
	papi_encryption_t encryption;
	void *app_data;
	uri_t *uri;
	char *post;
	http_t *connection;
	http_transfer_encoding_t transfer_encoding;
} service_t;

typedef struct job {
	papi_attribute_t **attributes;
} job_t;

typedef struct {
	papi_attribute_t **attributes;
} printer_t;

/* IPP glue interfaces */
extern ssize_t ipp_request_read(void *fd, void *buffer, size_t length);
extern ssize_t ipp_request_write(void *fd, void *buffer, size_t length);
extern papi_status_t ipp_send_request(service_t *svc,
				papi_attribute_t **request,
				papi_attribute_t ***response);
extern papi_status_t ipp_send_request_with_file(service_t *svc,
				papi_attribute_t **request,
				papi_attribute_t ***response, char *file);
extern papi_status_t ipp_send_initial_request_block(service_t *svc,
				papi_attribute_t **request, ssize_t file_size);
extern papi_status_t ipp_status_info(service_t *svc,
				papi_attribute_t **response);
extern void ipp_initialize_request(service_t *svc,
				papi_attribute_t ***request, uint16_t type);
extern void ipp_initialize_operational_attributes(service_t *svc,
				papi_attribute_t ***op,
				char *printer, int job_id);
extern papi_status_t ipp_to_papi_status(uint16_t status);
extern papi_status_t http_to_papi_status(http_status_t status);

/* service related interfaces */
extern void detailed_error(service_t *svc, char *fmt, ...);
extern papi_status_t service_connect(service_t *svc, char *service_name);

#ifdef __cplusplus
}
#endif

#endif /* _PAPI_IMPL_H */
