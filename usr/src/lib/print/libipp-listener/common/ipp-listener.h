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

#ifndef	_IPP_LISTENER_H
#define	_IPP_LISTENER_H

/* $Id: ipp-listener.h 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <ipp.h>

/* exported functions */
extern papi_status_t ipp_configure_operation(papi_attribute_t ***list,
						char *operation, char *type);
extern papi_status_t ipp_process_request(papi_attribute_t **request,
					papi_attribute_t ***response,
					ipp_reader_t iread, void *fd);

/* shared internal functions */
extern char *ipp_svc_status_mesg(papi_service_t svc, papi_status_t status);
extern char *destination_from_printer_uri(char *);
extern void get_printer_id(papi_attribute_t **attributes, char **printer,
			int *id);
extern void ipp_operations_supported(papi_attribute_t ***list,
			papi_attribute_t **request);
extern void get_string_list(papi_attribute_t **attributes, char *name,
			char ***values);
extern void add_default_attributes(papi_attribute_t ***attributes);
extern void papi_to_ipp_printer_group(papi_attribute_t ***response,
			papi_attribute_t **request, int flags,
			papi_printer_t p);
extern void papi_to_ipp_job_group(papi_attribute_t ***response,
			papi_attribute_t **request, int flags, papi_job_t j);
extern void massage_response(papi_attribute_t **request,
			papi_attribute_t **response);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_LISTENER_H */
