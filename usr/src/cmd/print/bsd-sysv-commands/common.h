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

#ifndef _BSD_SYSV_COMMON_H
#define	_BSD_SYSV_COMMON_H

/* $Id: common.h 162 2006-05-08 14:17:44Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <papi.h>

#include <config-site.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern char **strsplit(char *string, const char *seperators);
extern char *verbose_papi_message(papi_service_t svc, papi_status_t status);

extern int berkeley_cancel_request(papi_service_t svc, FILE *fp, char *dest,
		int ac, char *av[]);

extern int get_printer_id(char *name, char **printer, int *id);

extern int berkeley_queue_report(papi_service_t svc, FILE *fp, char *dest,
		int fmt, int ac, char *av[]);

extern papi_status_t jobSubmitSTDIN(papi_service_t svc, char *printer,
				char *prefetch, int len,
				papi_attribute_t **list, papi_job_t *job);

extern char **interest_list(papi_service_t svc);
extern char *localhostname();
extern char *lp_type_to_mime_type(char *lp_type);
extern int is_postscript(const char *file);
extern int is_postscript_stream(int fd, char *buf, int *len);

extern int cli_auth_callback(papi_service_t svc, void *app_data);

#ifdef	__cplusplus
}
#endif

#endif /* _BSD_SYSV_COMMON_H */
