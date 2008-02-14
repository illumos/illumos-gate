/*
 * Copyright (c) 2001, Apple Computer, Inc.
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
 * $Id: status.c,v 1.2 2001/08/18 05:44:50 conrad Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sysexits.h>
#include <libintl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <cflib.h>

#include <netsmb/netbios.h>
#include <netsmb/smb_lib.h>
#include <netsmb/nb_lib.h>

#include "common.h"


int
cmd_status(int argc, char *argv[])
{
	struct nb_ctx *ctx;
	struct sockaddr *sap;
	char *hostname;
	char servername[SMB_MAXSRVNAMELEN + 1];
	char workgroupname[SMB_MAXUSERNAMELEN + 1];
	int error, opt;

	if (argc < 2)
		status_usage();
	error = nb_ctx_create(&ctx);
	if (error) {
		smb_error(gettext("unable to create nbcontext"), error);
		exit(1);
	}
	if (smb_open_rcfile(NULL) == 0) {
		if (nb_ctx_readrcsection(smb_rc, ctx, "default", 0) != 0)
			exit(1);
		rc_close(smb_rc);
	}
	while ((opt = getopt(argc, argv, "")) != EOF) {
		switch (opt) {
		default:
			status_usage();
			/*NOTREACHED*/
		}
	}
	if (optind >= argc)
		status_usage();

	hostname = argv[argc - 1];
	error = nb_resolvehost_in(hostname, &sap);
	if (error) {
		smb_error(gettext(
		    "unable to resolve DNS hostname %s"), error, hostname);
		exit(1);
	}
	if ((ctx->nb_flags & NBCF_NS_ENABLE) == 0) {
		fprintf(stderr,
		    gettext("nbns_enable=false, cannot get status\n"));
		exit(1);
	}
	servername[0] = (char)0;
	workgroupname[0] = (char)0;
	error = nbns_getnodestatus(sap, ctx, servername, workgroupname);
	if (error) {
		smb_error(
		    gettext("unable to get status from %s"), error, hostname);
		exit(1);
	}

	if (workgroupname[0]) {
		printf(gettext("Workgroup: %s\n"), workgroupname);
	}
	if (servername[0]) {
		printf(gettext("Server: %s\n"), servername);
	}

	return (0);
}


void
status_usage(void)
{
	printf(gettext("usage: smbutil status hostname\n"));
	exit(1);
}
