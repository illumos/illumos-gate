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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * smbutil "discon" sub-command to disconnect a session
 * (mostly for usr/src/test/smbclient-tests)
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sysexits.h>
#include <libintl.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include "common.h"

void
discon_usage(void)
{
	printf(gettext("usage: smbutil discon [connection options] "
	    "//[workgroup;][user@]server\n"));
	exit(1);
}

int
cmd_discon(int argc, char *argv[])
{
	struct smb_ctx *ctx;
	int error, opt;

	if (argc < 2)
		discon_usage();

	error = smb_ctx_alloc(&ctx);
	if (error != 0)
		return (error);

	error = smb_ctx_scan_argv(ctx, argc, argv,
	    SMBL_SERVER, SMBL_SERVER, USE_WILDCARD);
	if (error != 0)
		goto out;

	error = smb_ctx_readrc(ctx);
	if (error != 0)
		goto out;

	while ((opt = getopt(argc, argv, STDPARAM_OPT)) != EOF) {
		if (opt == '?')
			discon_usage();
		error = smb_ctx_opt(ctx, opt, optarg);
		if (error != 0)
			goto out;
	}

	/*
	 * Resolve the server address,
	 * setup derived defaults.
	 */
	error = smb_ctx_resolve(ctx);
	if (error != 0)
		goto out;

	/*
	 * Have server, user, etc. from above:
	 * smb_ctx_scan_argv, option settings.
	 *
	 * Lookup a session without creating.
	 * (First part of smb_ctx_get_ssn)
	 * If we find the session, kill it.
	 */
	error = smb_ctx_findvc(ctx);
	if (error == ENOENT) {
		/* Already gone. We're done. */
		if (smb_debug)
			fprintf(stderr, "session not found\n");
		error = 0;
		goto out;
	}
	if (error == 0) {
		/* Found session.  Kill it. */
		error = smb_ctx_kill(ctx);
	}

	if (error != 0) {
		smb_error(gettext("//%s: discon failed"),
		    error, ctx->ct_fullserver);
	}

out:
	smb_ctx_free(ctx);
	return (error);
}
