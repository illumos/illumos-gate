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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Test program for opening an SMB connection directly.
 */

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>

#include <netsmb/smb_lib.h>

extern char *optarg;
extern int optind, opterr, optopt;
extern int smb_iod_connect(struct smb_ctx *);

static char *server;

static void
tconn_usage(void)
{
	printf("usage: tconn [-d domain][-u user][-p passwd] server\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c, error, aflags;
	struct smb_ctx *ctx = NULL;
	char *dom = NULL;
	char *usr = NULL;
	char *pw = NULL;
	char *secopt = NULL;
	struct addrinfo *ai;

	while ((c = getopt(argc, argv, "vd:p:s:u:")) != -1) {
		switch (c) {
		case 'v':
			smb_debug = 1;
			smb_verbose = 1;
			break;

		case 'd':
			dom = optarg;
			break;
		case 'u':
			usr = optarg;
			break;
		case 'p':
			pw = optarg;
			break;
		case 's':
			secopt = optarg;
			break;
		case '?':
			tconn_usage();
			break;
		}
	}
	if (optind >= argc)
		tconn_usage();
	server = argv[optind];

	if (pw != NULL && (dom == NULL || usr == NULL)) {
		fprintf(stderr, "%s: -p arg requires -d dom -u usr\n",
		    argv[0]);
		tconn_usage();
	}

	/*
	 * This section is intended to demonstrate how an
	 * RPC client library might use this interface.
	 */
	error = smb_ctx_alloc(&ctx);
	if (error) {
		fprintf(stderr, "%s: smb_ctx_alloc failed\n", argv[0]);
		goto out;
	}

	/*
	 * Set server, share, domain, user
	 * (in the ctx handle).
	 */
	smb_ctx_setfullserver(ctx, server);
	smb_ctx_setshare(ctx, "IPC$", USE_IPC);
	if (dom)
		smb_ctx_setdomain(ctx, dom, B_TRUE);
	if (usr)
		smb_ctx_setuser(ctx, usr, B_TRUE);
	if (pw)
		smb_ctx_setpassword(ctx, pw, NULL);

	/*
	 * Hackish option to override the Authentication Type flags.
	 * Sorry about exposing the flag values here, but this is
	 * really a programmer's test tool.  See smbfs_api.h for
	 * the SMB_AT_... flag values.
	 */
	if (secopt != NULL) {
		aflags = atoi(secopt);
		if (aflags < 1 || aflags > 0x1f) {
			fprintf(stderr, "%s: -s {0..31}\n", argv[0]);
			tconn_usage();
		}
		smb_ctx_setauthflags(ctx, aflags);
	}

	/*
	 * Resolve the server address,
	 * setup derived defaults.
	 */
	error = smb_ctx_resolve(ctx);
	if (error) {
		fprintf(stderr, "%s: smb_ctx_resolve failed\n", argv[0]);
		goto out;
	}

	if ((ai = ctx->ct_addrinfo) == NULL) {
		fprintf(stderr, "%s: no ct_addrinfo\n", argv[0]);
		goto out;
	}
	memcpy(&ctx->ct_srvaddr, ai->ai_addr, ai->ai_addrlen);

	/*
	 * If this code were in smbutil or mount_smbfs, it would
	 * get system and $HOME/.nsmbrc settings here, like this:
	 */
	error = smb_iod_connect(ctx);
	if (error) {
		fprintf(stderr, "%s: smb_iod_connect failed\n", argv[0]);
		goto out;
	}

	printf("Yea, we connected!\n");

out:
	smb_ctx_free(ctx);

	return ((error) ? 1 : 0);
}
