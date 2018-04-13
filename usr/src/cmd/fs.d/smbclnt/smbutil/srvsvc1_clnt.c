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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * A few excerpts from lib/smbsrv/libmlsvc
 * See longer comment in srvsvc1.ndl
 */

#include <sys/errno.h>
#include <stdio.h>
#include <time.h>
#include <strings.h>
#include <time.h>

#include <libmlrpc/libmlrpc.h>
#include "srvsvc1_clnt.h"

static ndr_service_t srvsvc_service = {
	"SRVSVC",			/* name */
	"Server services",		/* desc */
	"\\srvsvc",			/* endpoint */
	"\\PIPE\\ntsvcs",		/* sec_addr_port */
	"4b324fc8-1670-01d3-1278-5a47bf6ee188", 3,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(srvsvc_interface),	/* interface_ti */
	NULL				/* stub_table */
};

/*
 * srvsvc_initialize
 *
 * This function registers the SRVSVC RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
srvsvc1_initialize(void)
{
	static int init_done;
	if (init_done)
		return;
	init_done = 1;
	(void) ndr_svc_register(&srvsvc_service);
}

/*
 * Client-side stub for NetServerGetInfo
 */
int
srvsvc_net_server_getinfo(mlrpc_handle_t *handle, char *server,
	int level, union mslm_NetServerGetInfo_ru *resp)
{
	struct mslm_NetServerGetInfo arg;
	int len, opnum, rc;

	opnum = SRVSVC_OPNUM_NetServerGetInfo;
	bzero(&arg, sizeof (arg));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(handle, len);
	if (arg.servername == NULL)
		return (ENOMEM);

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.level = level;

	rc = ndr_rpc_call(handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0))
		return (EIO);

	*resp = arg.result.ru;
	return (0);
}

/*
 * Client-side stub for NetShareEnum
 */
int
srvsvc_net_share_enum(mlrpc_handle_t *handle, char *server,
	int level, union mslm_NetShareEnum_ru *resp)
{
	/* Any enum result type is OK for nres. */
	struct mslm_NetShareInfo_0_result nres;
	struct mslm_NetShareEnum arg;
	int len, opnum, rc;

	opnum = SRVSVC_OPNUM_NetShareEnum;
	bzero(&nres, sizeof (nres));
	bzero(&arg, sizeof (arg));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(handle, len);
	if (arg.servername == NULL)
		return (ENOMEM);

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.level = level;
	arg.result.level = level;
	arg.result.ru.bufptr0 = &nres;
	arg.prefmaxlen = 0xFFFFFFFF;
	arg.resume_handle = NULL;

	rc = ndr_rpc_call(handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0))
		return (EIO);

	*resp = arg.result.ru;
	return (0);
}
