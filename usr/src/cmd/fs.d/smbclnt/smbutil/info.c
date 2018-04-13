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
 * Show information about the remote server, as offered by
 * NetServerGetInfo with SERVER_INFO_101
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>

#include <libmlrpc/libmlrpc.h>
#include <netsmb/smb_lib.h>
#include "srvsvc1_clnt.h"
#include "common.h"


static int get_info(smb_ctx_t *);

void
info_usage(void)
{
	printf(gettext("usage: smbutil info [connection options] //"
	    "[workgroup;][user[:password]@]server\n"));
	exit(1);
}

int
cmd_info(int argc, char *argv[])
{
	struct smb_ctx *ctx;
	int error, err2, opt;

	if (argc < 2)
		info_usage();

	error = smb_ctx_alloc(&ctx);
	if (error)
		return (error);

	error = smb_ctx_scan_argv(ctx, argc, argv,
	    SMBL_SERVER, SMBL_SERVER, USE_WILDCARD);
	if (error)
		goto out;

	error = smb_ctx_readrc(ctx);
	if (error)
		goto out;

	while ((opt = getopt(argc, argv, STDPARAM_OPT)) != EOF) {
		if (opt == '?')
			info_usage();
		error = smb_ctx_opt(ctx, opt, optarg);
		if (error)
			goto out;
	}

	smb_ctx_setshare(ctx, "IPC$", USE_IPC);

	/*
	 * Resolve the server address,
	 * setup derived defaults.
	 */
	error = smb_ctx_resolve(ctx);
	if (error)
		goto out;

	/*
	 * Have server, share, etc. from above:
	 * smb_ctx_scan_argv, option settings.
	 * Get the session and tree.
	 */
again:
	error = smb_ctx_get_ssn(ctx);
	if (error == EAUTH) {
		err2 = smb_get_authentication(ctx);
		if (err2 == 0)
			goto again;
	}
	if (error) {
		smb_error(gettext("//%s: login failed"),
		    error, ctx->ct_fullserver);
		goto out;
	}

	error = smb_ctx_get_tree(ctx);
	if (error) {
		smb_error(gettext("//%s/%s: tree connect failed"),
		    error, ctx->ct_fullserver, ctx->ct_origshare);
		goto out;
	}

	/*
	 * Have IPC$ tcon.  Get the server info.
	 */
	error = get_info(ctx);
	if (error)
		smb_error("cannot get server info.", error);

out:
	smb_ctx_free(ctx);
	return (error);
}

int
get_info(smb_ctx_t *ctx)
{
	char pf_unk[32];
	mlrpc_handle_t handle;
	ndr_service_t *svc;
	union mslm_NetServerGetInfo_ru res;
	struct mslm_SERVER_INFO_101 *sv101;
	char *platform_name;
	int err;

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

	err = srvsvc_net_server_getinfo(&handle,
	    ctx->ct_fullserver, 101, &res);
	if (err)
		goto out;

	sv101 = res.info101;

	switch (sv101->sv101_platform_id) {
	case SV_PLATFORM_ID_DOS:
		platform_name = "DOS";
		break;
	case SV_PLATFORM_ID_OS2:
		platform_name = "OS2";
		break;
	case SV_PLATFORM_ID_NT:
		platform_name = "NT";
		break;
	case SV_PLATFORM_ID_OSF:
		platform_name = "OSF";
		break;
	case SV_PLATFORM_ID_VMS:
		platform_name = "VMS";
		break;
	default:
		platform_name = pf_unk;
		snprintf(pf_unk, sizeof (pf_unk), "(%d)",
		    sv101->sv101_platform_id);
		break;
	}

	printf("server info:\n");
	printf(" platform_id %s\n", platform_name);
	printf(" vers.major  %d\n", sv101->sv101_version_major);
	printf(" vers.minor  %d\n", sv101->sv101_version_minor);

	if (smb_verbose)
		printf(" type_flags  0x%x\n", sv101->sv101_type);

	printf(" name    \"%s\"\n", sv101->sv101_name);
	printf(" comment \"%s\"\n", sv101->sv101_comment);

out:
	(void) mlrpc_clh_free(&handle);
	return (err);
}
