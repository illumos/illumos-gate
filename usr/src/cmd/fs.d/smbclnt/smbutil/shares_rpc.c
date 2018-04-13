/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Share enumeration using Remote Procedure Call (RPC)
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libmlrpc/libmlrpc.h>
#include <netsmb/smbfs_api.h>
#include "srvsvc1_clnt.h"
#include "common.h"

int
share_enum_rpc(struct smb_ctx *ctx, char *server)
{
	mlrpc_handle_t handle;
	ndr_service_t *svc;
	union mslm_NetShareEnum_ru res;
	struct mslm_NetShareInfo_1 *nsi1;
	int err, i, count;

	/*
	 * Create an RPC handle using the smb_ctx we already have.
	 * Just local allocation and initialization.
	 */
	srvsvc1_initialize();
	svc = ndr_svc_lookup_name("srvsvc");
	if (svc == NULL)
		return (ENOENT);

	err = mlrpc_clh_create(&handle, ctx);
	if (err)
		return (err);

	/*
	 * Try to bind to the RPC service.  If it fails,
	 * just return the error and the caller will
	 * fall back to RAP.
	 */
	err = mlrpc_clh_bind(&handle, svc);
	if (err)
		goto out;

	err = srvsvc_net_share_enum(&handle, server, 1, &res);
	if (err)
		goto out;

	/* Print the header line. */
	view_print_share(NULL, 0, NULL);

	/* Print the share list. */
	count = res.bufptr1->entriesread;
	i = 0, nsi1 = res.bufptr1->entries;
	while (i < count) {
		/* Convert UTF-8 to local code set? */
		view_print_share((char *)nsi1->shi1_netname,
		    nsi1->shi1_type, (char *)nsi1->shi1_comment);
		i++, nsi1++;
	}

out:
	(void) mlrpc_clh_free(&handle);
	return (err);
}
