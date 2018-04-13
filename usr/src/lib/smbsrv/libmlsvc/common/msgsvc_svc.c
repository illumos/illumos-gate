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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Message Service
 */

#include <syslog.h>
#include <stdlib.h>

#include <libmlrpc/libmlrpc.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/msgsvc.ndl>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>

static int msgsvcsend_NetrSendMessage(void *, ndr_xa_t *);

static ndr_stub_table_t msgsvcsend_stub_table[] = {
	{ msgsvcsend_NetrSendMessage, MSGSVCSEND_OPNUM_NetrSendMessage },
	{0}
};

static ndr_service_t msgsvcsend_service = {
	"MSGSVC",			/* name */
	"Message Service",		/* desc */
	"\\msgsvc",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"5a7b91f8-ff00-11d0-a9b200c04fb6e6fc",	0,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(msgsvcsend_interface),	/* interface ti */
	msgsvcsend_stub_table		/* stub_table */
};

void
msgsvcsend_initialize(void)
{
	(void) ndr_svc_register(&msgsvcsend_service);
}

static int
msgsvcsend_NetrSendMessage(void *arg, ndr_xa_t *mxa)
{
	msgsvcsend_NetrSendMessage_t *param = arg;

	if (!ndr_is_admin(mxa)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	if (param->from == NULL || param->to == NULL || param->text == NULL) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	syslog(LOG_INFO, "%s to %s: %s", param->from,  param->to, param->text);
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}
