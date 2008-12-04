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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sysexits.h>
#include <libintl.h>

#include <cflib.h>
#include <netsmb/smb_lib.h>
#include <netsmb/smb_netshareenum.h>

#include "common.h"

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
cmd_view(int argc, char *argv[])
{
	struct smb_ctx sctx, *ctx = &sctx;
	struct share_info *share_info, *ep;
	int error, opt, i, entries, total;

	if (argc < 2)
		view_usage();
	error = smb_ctx_init(ctx, argc, argv, SMBL_VC, SMBL_VC, SMB_ST_ANY);
	if (error)
		exit(error);
	error = smb_ctx_readrc(ctx);
	if (error)
		exit(error);
	if (smb_rc)
		rc_close(smb_rc);
	while ((opt = getopt(argc, argv, STDPARAM_OPT)) != EOF) {
		switch (opt) {
		case STDPARAM_ARGS:
			error = smb_ctx_opt(ctx, opt, optarg);
			if (error)
				exit(error);
			break;
		default:
			view_usage();
			/*NOTREACHED*/
		}
	}
#ifdef APPLE
	if (loadsmbvfs())
		fprintf(stderr, gettext("SMB filesystem is not available"));
#endif
reauth:
	smb_ctx_setshare(ctx, "IPC$", SMB_ST_ANY);
	error = smb_ctx_resolve(ctx);
	if (error)
		exit(error);
	error = smb_ctx_lookup(ctx, SMBL_SHARE, SMBLK_CREATE);
	if (ctx->ct_flags & SMBCF_KCFOUND && smb_autherr(error)) {
		ctx->ct_ssn.ioc_password[0] = '\0';
		goto reauth;
	}
	if (error) {
		smb_error(gettext("could not login to server %s"),
		    error, ctx->ct_ssn.ioc_srvname);
		exit(error);
	}
	printf(gettext("Share        Type       Comment\n"));
	printf("-------------------------------\n");
	error = smb_netshareenum(ctx, &entries, &total, &share_info);
	if (error) {
		smb_error(gettext("unable to list resources"), error);
		exit(error);
	}
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
	smb_ctx_done(ctx);
#ifdef APPLE
	smb_save2keychain(ctx);
#endif
	return (0);
}


void
view_usage(void)
{
	printf(gettext("usage: smbutil view [connection options] //"
	    "[workgroup;][user[:password]@]server\n"));
	exit(1);
}
