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
 * Routines to handle getipnode* calls in nscd. Note that the
 * getnodeby* APIs were renamed getipnodeby*. The interfaces
 * related to them in the nscd will remain as getnode*.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inet/ip6.h>
#include "cache.h"

static int ipaddr_compar(const void *, const void *);
static uint_t ipaddr_gethash(nss_XbyY_key_t *, int);
static void ipaddr_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

static int ipname_compar(const void *, const void *);
static uint_t ipname_gethash(nss_XbyY_key_t *, int);
static void ipname_getlogstr(char *, char *, size_t, nss_XbyY_args_t *);

#define	nnam_db	ctx->nsc_db[0]
#define	addr_db	ctx->nsc_db[1]

#define	NSC_NAME_IPNODES_BYNAME	"getipnodebyname"
#define	NSC_NAME_IPNODES_BYADDR	"getipnodebyaddr"

void
ipnode_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_IPNODES;
	ctx->file_name = "/etc/inet/ipnodes";
	ctx->db_count = 2;
	nnam_db = make_cache(nsc_key_other,
			NSS_DBOP_IPNODES_BYNAME,
			NSC_NAME_IPNODES_BYNAME,
			ipname_compar,
			ipname_getlogstr,
			ipname_gethash, nsc_ht_default, -1);

	addr_db = make_cache(nsc_key_other,
			NSS_DBOP_IPNODES_BYADDR,
			NSC_NAME_IPNODES_BYADDR,
			ipaddr_compar,
			ipaddr_getlogstr,
			ipaddr_gethash, nsc_ht_default, -1);
}

static int
ipaddr_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;

	if (e1->key.hostaddr.type > e2->key.hostaddr.type)
		return (1);
	else if (e1->key.hostaddr.type < e2->key.hostaddr.type)
		return (-1);

	l1 = e1->key.hostaddr.len;
	l2 = e2->key.hostaddr.len;
	res = memcmp(e1->key.hostaddr.addr, e2->key.hostaddr.addr,
		(l2 > l1)?l1:l2);
	return ((res) ? _NSC_INT_KEY_CMP(res, 0) : _NSC_INT_KEY_CMP(l1, l2));
}

static uint_t
ipaddr_gethash(nss_XbyY_key_t *key, int htsize) {
	return (db_gethash(key->hostaddr.addr,
		key->hostaddr.len, htsize));
}

static void
ipaddr_getlogstr(char *name, char *whoami, size_t len, nss_XbyY_args_t *argp) {
	char addr[INET6_ADDRSTRLEN];

	if (inet_ntop(argp->key.hostaddr.type, argp->key.hostaddr.addr, addr,
			sizeof (addr)) == NULL) {
		(void) snprintf(whoami, len, "%s", name);
	} else {
		(void) snprintf(whoami, len, "%s [key=%s addrtype=%d]",
			name,
			addr, argp->key.hostaddr.type);
	}
}

static int
ipname_compar(const void *n1, const void *n2) {
	nsc_entry_t	*e1, *e2;
	int		res, l1, l2;

	e1 = (nsc_entry_t *)n1;
	e2 = (nsc_entry_t *)n2;

	if (e1->key.ipnode.af_family > e2->key.ipnode.af_family)
		return (1);
	else if (e1->key.ipnode.af_family < e2->key.ipnode.af_family)
		return (-1);

	l1 = strlen(e1->key.ipnode.name);
	l2 = strlen(e2->key.ipnode.name);
	res = strncasecmp(e1->key.ipnode.name, e2->key.ipnode.name,
		(l1 > l2)?l1:l2);
	return (_NSC_INT_KEY_CMP(res, 0));
}

static uint_t
ipname_gethash(nss_XbyY_key_t *key, int htsize) {
	return (cis_gethash(key->ipnode.name, htsize));
}

static void
ipname_getlogstr(char *name, char *whoami, size_t len, nss_XbyY_args_t *argp) {
	(void) snprintf(whoami, len, "%s [key=%s:af=%d:flags=%d]",
			name,
			argp->key.ipnode.name,
			argp->key.ipnode.af_family,
			argp->key.ipnode.flags);
}
