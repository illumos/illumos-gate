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

/*
 * Implementation specific types/prototypes/definitions follow
 *
 *
 * Ex:
 */

typedef struct {
	papi_attribute_t **attributes;
	void *so_handle;
	void *svc_handle;
	char *name;
	char *user;
	char *password;
	int (*authCB)(papi_service_t svc, void *app_data);
	papi_encryption_t encryption;
	void *app_data;
	uri_t *uri;
	int peer_fd;
} service_t;

typedef struct job {
	service_t *svc;
	papi_job_t *job;
} job_t;

typedef struct {
	service_t *svc;
	papi_printer_t *printer;
	papi_attribute_t **attributes;
	char svc_is_internal;
} printer_t;

extern papi_status_t psm_open(service_t *svc, char *name);
extern void *psm_sym(service_t *svc, char *name);
extern void psm_close(void *handle);
extern void detailed_error(service_t *svc, char *fmt, ...);
extern papi_status_t service_connect(service_t *svc, char *uri);
extern papi_attribute_t **getprinterentry(char *ns);
extern papi_attribute_t **getprinterbyname(char *name, char *ns);
extern int setprinterentry(int stayopen, char *ns);
extern int endprinterentry(int stayopen);



extern void list_remove();

#ifdef __cplusplus
}
#endif

#endif /* _PAPI_IMPL_H */
