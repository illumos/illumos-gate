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
 * Routines to handle gethost* calls in nscd
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "cache.h"

#define	hnam_db	ctx->nsc_db[0]
#define	addr_db	ctx->nsc_db[1]

#define	NSC_NAME_HOSTS_BYNAME	"gethostbyname"
#define	NSC_NAME_HOSTS_BYADDR	"gethostbyaddr"

static int hostaddr_compar(const void *, const void *);
static uint_t hostaddr_gethash(nss_XbyY_key_t *, int);
static void hostaddr_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

void
host_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_HOSTS;
	ctx->db_count = 2;
	ctx->file_name = "/etc/inet/hosts";

	hnam_db = make_cache(nsc_key_cis,
			NSS_DBOP_HOSTS_BYNAME,
			NSC_NAME_HOSTS_BYNAME,
			NULL, NULL, NULL, nsc_ht_default, -1);

	addr_db = make_cache(nsc_key_other,
			NSS_DBOP_HOSTS_BYADDR,
			NSC_NAME_HOSTS_BYADDR,
			hostaddr_compar,
			hostaddr_getlogstr,
			hostaddr_gethash, nsc_ht_default, -1);
}

static void
hostaddr_getlogstr(char *name, char *whoami, size_t len,
			nss_XbyY_args_t *argp) {
	char addr[INET6_ADDRSTRLEN];

	if (inet_ntop(argp->key.hostaddr.type, argp->key.hostaddr.addr, addr,
			sizeof (addr)) == NULL) {
		(void) snprintf(whoami, len, "%s", name);
	} else {
		(void) snprintf(whoami, len, "%s [key=%s, addrtype=%d]",
			name, addr, argp->key.hostaddr.type);
	}
}

static int
hostaddr_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;
	l1 = e1->key.hostaddr.len;
	l2 = e2->key.hostaddr.len;
	res = memcmp(e1->key.hostaddr.addr, e2->key.hostaddr.addr,
		(l2 > l1)?l1:l2);
	return ((res) ? _NSC_INT_KEY_CMP(res, 0) : _NSC_INT_KEY_CMP(l1, l2));
}

static uint_t
hostaddr_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(key->hostaddr.addr,
			key->hostaddr.len, htsize));
}
