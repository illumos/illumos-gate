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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include "volume_request.h"
#include "volume_error.h"

/*
 * Methods which manipulate a request_t struct
 */

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
int
new_request(
	request_t **request)
{
	int error;
	devconfig_t *diskset_req;
	devconfig_t *diskset_config;

	*request = (request_t *)calloc(1, sizeof (request_t));
	if (*request == NULL) {
	    (void) volume_set_error(gettext("new_request calloc() failed\n"));
	    return (-1);
	}

	/* Create a new diskset_req */
	if ((error = new_devconfig(&diskset_req, TYPE_DISKSET)) != 0) {
	    free_request(*request);
	    return (error);
	}
	request_set_diskset_req(*request, diskset_req);

	/* Create a new diskset_config */
	if ((error = new_devconfig(&diskset_config, TYPE_DISKSET)) != 0) {
	    free_request(*request);
	    return (error);
	}
	request_set_diskset_config(*request, diskset_config);

	return (0);
}

/*
 * Free memory (recursively) allocated to a request_t struct
 *
 * @param       arg
 *              pointer to the request_t struct to free
 */
void
free_request(
	void *arg)
{
	request_t *request = (request_t *)arg;

	if (request == NULL) {
	    return;
	}

	/* Free the diskset_req */
	if (request->diskset_req != NULL) {
	    free_devconfig(request->diskset_req);
	}

	/* Free the diskset_config */
	if (request->diskset_config != NULL) {
	    free_devconfig(request->diskset_config);
	}

	/* Free the devconfig itself */
	free(request);
}

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
void
request_set_diskset_req(
	request_t *request,
	devconfig_t *diskset)
{
	request->diskset_req = diskset;
}

/*
 * Get the disk set at the top of the request hierarchy
 *
 * @param       request
 *              The request_t representing the request to examine
 *
 * @return      The devconfig_t representing the toplevel (disk set)
 *              device in the volume request hierarchy
 */
devconfig_t *
request_get_diskset_req(
	request_t *request)
{
	return (request->diskset_req);
}

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
void
request_set_diskset_config(
	request_t *request,
	devconfig_t *diskset)
{
	request->diskset_config = diskset;
}

/*
 * Get the disk set at the top of the request hierarchy
 *
 * @param       request
 *              The request_t representing the request to examine
 *
 * @return      The devconfig_t representing the toplevel (disk set)
 *              device in the proposed volume hierarchy
 */
devconfig_t *
request_get_diskset_config(
	request_t *request)
{
	return (request->diskset_config);
}
