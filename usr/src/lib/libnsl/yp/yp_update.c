/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * YP updater interface
 */
#include "mt.h"
#include <stdio.h>
#include <rpc/rpc.h>
#include "yp_b.h"
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/ypupd.h>
#include <sys/types.h>
#include <stdlib.h>

#define	WINDOW (60*60)
#define	TOTAL_TIMEOUT	300

#ifdef DEBUG
#define	debugging 1
#define	debug(msg)  (void) fprintf(stderr, "%s\n", msg);
#else
#define	debugging 0
#define	debug(msg)
#endif
extern AUTH *authdes_seccreate();

int
yp_update(char *domain, char *map, unsigned op, char *key, int keylen,
							char *data, int datalen)
{
	struct ypupdate_args args;
	uint_t rslt;
	struct timeval total;
	CLIENT *client;
	char *ypmaster;
	char ypmastername[MAXNETNAMELEN+1];
	enum clnt_stat stat;
	uint_t proc;

	switch (op) {
	case YPOP_DELETE:
		proc = YPU_DELETE;
		break;
	case YPOP_INSERT:
		proc = YPU_INSERT;
		break;
	case YPOP_CHANGE:
		proc = YPU_CHANGE;
		break;
	case YPOP_STORE:
		proc = YPU_STORE;
		break;
	default:
		return (YPERR_BADARGS);
	}
	if (yp_master(domain, map, &ypmaster) != 0) {
		debug("no master found");
		return (YPERR_BADDB);
	}

	client = clnt_create(ypmaster, YPU_PROG, YPU_VERS, "circuit_n");
	if (client == NULL) {
#ifdef DEBUG
		/* CONSTCOND */
		if (debugging) {
			clnt_pcreateerror("client create failed");
		}
#endif /* DEBUG */
		free(ypmaster);
		return (YPERR_RPC);
	}

	if (!host2netname(ypmastername, ypmaster, domain)) {
		clnt_destroy(client);
		free(ypmaster);
		return (YPERR_BADARGS);
	}
	client->cl_auth = authdes_seccreate(ypmastername, WINDOW,
				ypmaster, NULL);
	free(ypmaster);
	if (client->cl_auth == NULL) {
		debug("auth create failed");
		clnt_destroy(client);
		return (YPERR_RPC);
	}

	args.mapname = map;
	args.key.yp_buf_len = keylen;
	args.key.yp_buf_val = key;
	args.datum.yp_buf_len = datalen;
	args.datum.yp_buf_val = data;

	total.tv_sec = TOTAL_TIMEOUT;
	total.tv_usec = 0;
	clnt_control(client, CLSET_TIMEOUT, (char *)&total);
	stat = clnt_call(client, proc,
		xdr_ypupdate_args, (char *)&args,
		xdr_u_int, (char *)&rslt, total);

	if (stat != RPC_SUCCESS) {
#ifdef DEBUG
		debug("ypupdate RPC call failed");
		/* CONSTCOND */
		if (debugging)
			clnt_perror(client, "ypupdate call failed");
#endif /* DEBUG */
		rslt = YPERR_RPC;
	}
	auth_destroy(client->cl_auth);
	clnt_destroy(client);
	return (rslt);
}
