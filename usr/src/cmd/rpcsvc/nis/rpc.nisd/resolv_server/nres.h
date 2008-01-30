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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Taken from 4.1.3 ypserv resolver code. */

#ifndef _NRES_H
#define	_NRES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <arpa/nameser.h>
#include "rpc_as.h"

#ifdef __cplusplus
extern "C" {
#endif

#if PACKETSZ > 1024
#define	MAXPACKET	PACKETSZ
#else
#define	MAXPACKET	1024
#endif
#define	REVERSE_PTR 1
#define	REVERSE_A	2

struct nres {
	rpc_as		nres_rpc_as;
	struct cache_ent *userinfo;
	void		(*done) (void *, struct hostent *,
					ulong_t, struct cache_ent *, int);
	int		af_type;	/* AF_INET or AF_INET6 */
	int		qtype;		/* query type: T_A, T_AAAA, T_PTR */

	int		h_errno;
	int		reverse;	/* used for gethostbyaddr */
	struct in_addr	theaddr;	/* gethostbyaddr */
	struct in6_addr	theaddr6;	/* gethostbyaddr IPv6 */
	char		name[MAXDNAME + 1];	/* gethostbyame name */
	char		search_name[2 * MAXDNAME + 2];
	int		search_index;	/* 0 up as we chase path */
	char		question[MAXPACKET];
	char		answer[MAXPACKET];
	int		using_tcp;	/* 0 ->udp in use */
	int		udp_socket;
	int		tcp_socket;
	int		got_nodata;	/* no_data rather than name_not_found */
	int		question_len;
	int		answer_len;
	int		current_ns;
	int		retries;
	int		ttl;		/* ttl value from response */
	int		tried_asis;	/* Tried name look up as-is */
};

extern struct netconfig *udp_nconf4;
extern struct netconfig *udp_nconf6;

extern int nres_xmit(struct nres *);
extern struct hostent *nres_getanswer(struct nres *);
extern int nres_search(struct nres *);
extern int nres_rcv(struct nres *);
extern int nres_chkreply(struct nres *);
extern struct nres *nres_gethostbyname(char *,
    void (*)(void *, struct hostent *, ulong_t, struct cache_ent *, int),
    struct cache_ent *);
extern struct nres *nres_gethostbyaddr(char *, int, int,
    void (*)(void *, struct hostent *, ulong_t, struct cache_ent *, int),
    struct cache_ent *);

#ifdef __cplusplus
}
#endif

#endif	/* _NRES_H */
