/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: view.c,v 1.9 2004/12/13 00:25:39 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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

static int use_rap;

void
view_usage(void)
{
	printf(gettext("usage: smbutil view [connection options] //"
	    "[workgroup;][user[:password]@]server\n"));
	exit(1);
}

int
cmd_view(int argc, char *argv[])
{
	struct smb_ctx *ctx;
	int error, err2, opt;

	if (argc < 2)
		view_usage();

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
			view_usage();
		/*
		 * This is an undocumented option, just for testing.
		 * Use the old LanMan Remote API Protocol (RAP) for
		 * enumerating shares.
		 */
		if (opt == 'B') {
			use_rap++;
			continue;
		}
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
	 * Have IPC$ tcon, now list shares.
	 * Try RPC; if that fails, do RAP.
	 */
	if (!use_rap)
		error = share_enum_rpc(ctx, ctx->ct_fullserver);
	if (error || use_rap)
		error = share_enum_rap(ctx);

out:
	smb_ctx_free(ctx);
	return (0);
}

#ifdef I18N	/* not defined, put here so xgettext(1) can find strings */
static char *shtype[] = {
	gettext("disk"),
	gettext("printer"),
	gettext("device"),	/* Communications device */
	gettext("IPC"),		/* Inter process communication */
	gettext("unknown")
};
#else
static char *shtype[] = {
	"disk",
	"printer",
	"device",		/* Communications device */
	"IPC",			/* IPC Inter process communication */
	"unknown"
};
#endif

/*
 * Print one line of the share list, or
 * if SHARE is null, print the header line.
 */
void
view_print_share(char *share, int type, char *comment)
{
	char *stname;
	int stindex;

	if (share == NULL) {
		printf(gettext("Share        Type       Comment\n"));
		printf("-------------------------------\n");
		return;
	}

	stindex = type & STYPE_MASK;
	if (stindex > STYPE_UNKNOWN)
		stindex = STYPE_UNKNOWN;
	stname = gettext(shtype[stindex]);

	if (comment == NULL)
		comment = "";

	printf("%-12s %-10s %s\n", share, stname, comment);
}
