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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <netsmb/smb_netshareenum.h>

#include "common.h"

int enum_shares(smb_ctx_t *);
void print_shares(int, int, struct share_info *);

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
		return (error);

	error = smb_ctx_readrc(ctx);
	if (error)
		return (error);

	while ((opt = getopt(argc, argv, STDPARAM_OPT)) != EOF) {
		if (opt == '?')
			view_usage();
		error = smb_ctx_opt(ctx, opt, optarg);
		if (error)
			return (error);
	}

	smb_ctx_setshare(ctx, "IPC$", USE_IPC);

	/*
	 * Resolve the server address,
	 * setup derived defaults.
	 */
	error = smb_ctx_resolve(ctx);
	if (error)
		return (error);

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
		return (error);
	}

	error = smb_ctx_get_tree(ctx);
	if (error) {
		smb_error(gettext("//%s/%s: tree connect failed"),
		    error, ctx->ct_fullserver, ctx->ct_origshare);
		return (error);
	}

	/*
	 * Have IPC$ tcon, now list shares.
	 */
	error = enum_shares(ctx);
	if (error) {
		smb_error("cannot list shares", error);
		return (error);
	}

	smb_ctx_free(ctx);
	return (0);
}

#ifdef I18N	/* not defined, put here so xgettext(1) can find strings */
static char *shtype[] = {
	gettext("disk"),
	gettext("printer"),
	gettext("device"),	/* Communications device */
	gettext("IPC"), 	/* Inter process communication */
	gettext("unknown")
};
#else
static char *shtype[] = {
	"disk",
	"printer",
	"device",		/* Communications device */
	"IPC",  		/* IPC Inter process communication */
	"unknown"
};
#endif

int
enum_shares(smb_ctx_t *ctx)
{
	struct share_info *share_info;
	int error, entries, total;

	/*
	 * XXX: Later, try RPC first,
	 * then fall back to RAP...
	 */
	error = smb_netshareenum(ctx, &entries, &total, &share_info);
	if (error) {
		smb_error(gettext("unable to list resources"), error);
		return (error);
	}
	print_shares(entries, total, share_info);
	return (0);
}

void
print_shares(int entries, int total,
	struct share_info *share_info)
{
	struct share_info *ep;
	int i;

	printf(gettext("Share        Type       Comment\n"));
	printf("-------------------------------\n");

	for (ep = share_info, i = 0; i < entries; i++, ep++) {
		int sti = ep->type & STYPE_MASK;
		if (sti > STYPE_UNKNOWN)
			sti = STYPE_UNKNOWN;
		printf("%-12s %-10s %s\n", ep->netname,
		    gettext(shtype[sti]),
		    ep->remark ? ep->remark : "");
		free(ep->netname);
		free(ep->remark);
	}
	printf(gettext("\n%d shares listed from %d available\n"),
	    entries, total);

	free(share_info);
}
