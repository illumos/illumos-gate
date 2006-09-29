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
 * Routines to handle ether_*to* calls in nscd
 */

#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
#include "cache.h"

#define	host_db	ctx->nsc_db[0]
#define	addr_db	ctx->nsc_db[1]

#define	NSC_NAME_ETHERS_HOSTTON	"ether_hostton"
#define	NSC_NAME_ETHERS_NTOHOST	"ether_ntohost"

static void ether_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);
static int ether_compar(const void *, const void *);
static uint_t ether_gethash(nss_XbyY_key_t *, int);

void
ether_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_ETHERS;
	ctx->file_name = "/etc/ethers";
	ctx->db_count = 2;
	host_db = make_cache(nsc_key_cis,
			NSS_DBOP_ETHERS_HOSTTON,
			NSC_NAME_ETHERS_HOSTTON,
			NULL, NULL, NULL, nsc_ht_default, -1);

	addr_db = make_cache(nsc_key_other,
			NSS_DBOP_ETHERS_NTOHOST,
			NSC_NAME_ETHERS_NTOHOST,
			ether_compar,
			ether_getlogstr,
			ether_gethash, nsc_ht_default, -1);
}

static int
ether_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	if (ether_cmp(e1->key.ether, e2->key.ether) != 0) {
		res = memcmp(e1->key.ether, e2->key.ether,
			sizeof (struct ether_addr));
		return (_NSC_INT_KEY_CMP(res, 0));
	}
	return (0);
}

static uint_t
ether_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(key->ether, sizeof (struct ether_addr),
			htsize));
}

static void
ether_getlogstr(char *name, char *whoami, size_t len, nss_XbyY_args_t *argp) {
	struct ether_addr *e;
	e = (struct ether_addr *)argp->key.ether;
	(void) snprintf(whoami, len, "%s [key=%x:%x:%x:%x:%x:%x]",
			name,
			e->ether_addr_octet[0], e->ether_addr_octet[1],
			e->ether_addr_octet[2], e->ether_addr_octet[3],
			e->ether_addr_octet[4], e->ether_addr_octet[5]);
}
