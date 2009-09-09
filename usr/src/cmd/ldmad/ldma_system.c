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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Logical Domains System Agent
 */

#include <errno.h>
#include <libds.h>
#include <stdio.h>
#include <strings.h>
#include <sys/utsname.h>

#include "ldma.h"

#define	LDMA_MODULE	LDMA_NAME_SYSTEM

#define	LDMA_NVERSIONS	(sizeof (ldma_versions) / sizeof (ds_ver_t))
#define	LDMA_NHANDLERS	(sizeof (ldma_handlers) / sizeof (ldma_msg_handler_t))

static ldm_msg_func_t ldma_sys_get_sysinfo;

static ds_ver_t ldma_versions[] = { { 1, 0 } };

static ldma_msg_handler_t ldma_handlers[] = {
	{ LDMA_MSGSYS_GET_SYSINFO, ldma_sys_get_sysinfo }
};

ldma_agent_info_t ldma_system_info = {
	LDMA_NAME_SYSTEM,
	ldma_versions, LDMA_NVERSIONS,
	ldma_handlers, LDMA_NHANDLERS
};

/*ARGSUSED*/
static ldma_request_status_t
ldma_sys_get_sysinfo(ds_ver_t *ver, ldma_message_header_t *request,
    size_t request_dlen, ldma_message_header_t **replyp, size_t *reply_dlenp)
{
	ldma_message_header_t *reply;
	struct utsname name;
	size_t syslen, nodlen, rellen, maclen, verlen;
	size_t rlen;
	char *data;
	int status;

	LDMA_DBG("GET_SYSINFO");

	if (request->msg_info != 0 || request_dlen != 0) {
		status = LDMA_REQ_INVALID;
		goto done;
	}

	if (uname(&name) == -1) {
		LDMA_DBG("GET_SYSINFO: uname failed with error %d", errno);
		status = LDMA_REQ_FAILED;
		goto done;
	}

	syslen = strlen(name.sysname) + 1;
	nodlen = strlen(name.nodename) + 1;
	rellen = strlen(name.release) + 1;
	verlen = strlen(name.version) + 1;
	maclen = strlen(name.machine) + 1;

	rlen = syslen + nodlen + rellen + verlen + maclen;

	reply = ldma_alloc_result_msg(request, rlen);

	if (reply == NULL) {
		status = LDMA_REQ_FAILED;
		goto done;
	}

	reply->msg_info = rlen;

	data = LDMA_HDR2DATA(reply);

	(void) strcpy(data, name.sysname);
	data += syslen;

	(void) strcpy(data, name.nodename);
	data += nodlen;

	(void) strcpy(data, name.release);
	data += rellen;

	(void) strcpy(data, name.version);
	data += verlen;

	(void) strcpy(data, name.machine);

	LDMA_DBG("GET_SYSINFO: return info=%u, {%s, %s, %s, %s, %s}", rlen,
	    name.sysname, name.nodename, name.release, name.version,
	    name.machine);

	*replyp = reply;
	*reply_dlenp = rlen;

	return (LDMA_REQ_COMPLETED);

done:
	LDMA_DBG("GET_SYSINFO: return error %d", status);
	return (status);
}
