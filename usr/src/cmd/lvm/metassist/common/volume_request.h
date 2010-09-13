/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VOLUME_REQUEST_H
#define	_VOLUME_REQUEST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "volume_devconfig.h"

/*
 * request_t - struct to hold a layout request
 */
typedef struct request {
	/*
	 * The devconfig_t representing the disk set at the top of the
	 * request hierarchy.  This hierarchy represents the requested
	 * volume configuration, as read from the volume-request.
	 */
	devconfig_t *diskset_req;

	/*
	 * The devconfig_t representing the disk set at the top of the
	 * resulting proposed volume hierarchy.  This hierarchy
	 * represents the volume configuration proposed by the layout
	 * engine.  This configuration will eventually be converted to
	 * a volume-spec.
	 */
	devconfig_t *diskset_config;
} request_t;

/*
 * Constructor: Create a request_t struct. This request_t must be
 * freed.
 *
 * @param       request
 *              RETURN: a pointer to a new request_t
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
extern int new_request(request_t **request);

/*
 * Free memory (recursively) allocated to a request_t struct
 *
 * @param       arg
 *              pointer to the request_t struct to free
 */
extern void free_request(void *arg);

/*
 * Set the disk set at the top of the request hierarchy
 *
 * @param       request
 *              The request_t representing the request to modify
 *
 * @param       diskset
 *              The devconfig_t representing the toplevel (disk set)
 *              device in the volume request hierarchy
 */
extern void request_set_diskset_req(request_t *request, devconfig_t *diskset);

/*
 * Get the disk set at the top of the request hierarchy
 *
 * @param       request
 *              The request_t representing the request to examine
 *
 * @return      The devconfig_t representing the toplevel (disk set)
 *              device in the volume request hierarchy
 */
extern devconfig_t *request_get_diskset_req(request_t *request);

/*
 * Set/get the disk set at the top of the proposed volume hierarchy
 *
 * @param       request
 *              The request_t representing the request to modify
 *
 * @param       diskset
 *              The devconfig_t representing the toplevel (disk set)
 *              device in the proposed volume hierarchy
 */
extern void request_set_diskset_config(
	request_t *request, devconfig_t *diskset);

/*
 * Get the disk set at the top of the request hierarchy
 *
 * @param       request
 *              The request_t representing the request to examine
 *
 * @return      The devconfig_t representing the toplevel (disk set)
 *              device in the proposed volume hierarchy
 */
extern devconfig_t *request_get_diskset_config(request_t *request);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_REQUEST_H */
