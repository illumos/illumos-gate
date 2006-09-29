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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines to handle getnet* calls in nscd
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "cache.h"

#define	nam_db	ctx->nsc_db[0]
#define	addr_db	ctx->nsc_db[1]

#define	NSC_NAME_NETWORKS_BYNAME	"getnetbyname"
#define	NSC_NAME_NETWORKS_BYADDR	"getnetbyaddr"

static int netaddr_compar(const void *, const void *);
static uint_t netaddr_gethash(nss_XbyY_key_t *, int);
static void netaddr_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

void
net_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_NETWORKS;
	ctx->db_count = 2;
	ctx->file_name = "/etc/inet/networks";

	nam_db = make_cache(nsc_key_ces,
			NSS_DBOP_NETWORKS_BYNAME,
			NSC_NAME_NETWORKS_BYNAME,
			NULL, NULL, NULL, nsc_ht_default, -1);

	addr_db = make_cache(nsc_key_other,
			NSS_DBOP_NETWORKS_BYADDR,
			NSC_NAME_NETWORKS_BYADDR,
			netaddr_compar,
			netaddr_getlogstr,
			netaddr_gethash, nsc_ht_default, -1);
}

static void
netaddr_getlogstr(char *name, char *whoami, size_t len, nss_XbyY_args_t *argp) {
	if (argp->key.netaddr.type == AF_INET) {
		uint32_t	net;
		uchar_t		*up;

		net = htonl(argp->key.netaddr.net);
		up = (uchar_t *)&net;

		if (up[0])
			(void) snprintf(whoami, len, "%s [key=%d.%d.%d.%d]",
				name,
				up[0], up[1], up[2], up[3]);
		else if (up[1])
			(void) snprintf(whoami, len, "%s [key=%d.%d.%d]",
				name,
				up[1], up[2], up[3]);
		else if (up[2])
			(void) snprintf(whoami, len, "%s [key=%d.%d]",
				name,
				up[2], up[3]);
		else
			(void) snprintf(whoami, len, "%s [key=%d]",
				name,
				up[3]);
	} else {
		(void) snprintf(whoami, len, "%s [key=%d, %d]",
			name,
			argp->key.netaddr.net, argp->key.netaddr.type);
	}
}

static int
netaddr_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;

	if (e1->key.netaddr.type > e2->key.netaddr.type)
		return (1);
	else if (e1->key.netaddr.type < e2->key.netaddr.type)
		return (-1);

	return (_NSC_INT_KEY_CMP(e1->key.netaddr.net, e2->key.netaddr.net));
}

static uint_t
netaddr_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(&key->netaddr.net,
			sizeof (key->netaddr.net), htsize));
}
