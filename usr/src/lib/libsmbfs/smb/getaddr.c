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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Functions to get list of addresses (TCP and/or NetBIOS)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include "charsets.h"
#include "private.h"

static char smb_port[16] = "445";

void
dump_addrinfo(struct addrinfo *ai)
{
	int i;

	if (ai == NULL) {
		printf("ai==NULL\n");
		return;
	}

	for (i = 0; ai; i++, ai = ai->ai_next) {
		printf("ai[%d]: af=%d, len=%d", i,
		    ai->ai_family, ai->ai_addrlen);
		dump_sockaddr(ai->ai_addr);
		if (ai->ai_canonname) {
			printf("ai[%d]: cname=\"%s\"\n",
			    i, ai->ai_canonname);
		}
	}
}

void
dump_sockaddr(struct sockaddr *sa)
{
	char paddrbuf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int af = sa->sa_family;
	const char *ip;

	printf(" saf=%d,", af);
	switch (af) {
	case AF_NETBIOS: /* see nbns_rq.c */
	case AF_INET:
		sin = (void *)sa;
		ip = inet_ntop(AF_INET, &sin->sin_addr,
		    paddrbuf, sizeof (paddrbuf));
		break;
	case AF_INET6:
		sin6 = (void *)sa;
		ip = inet_ntop(AF_INET6, &sin6->sin6_addr,
		    paddrbuf, sizeof (paddrbuf));
		break;
	default:
		ip = "?";
		break;
	}
	printf(" IP=%s\n", ip);
}


/*
 * SMB client name resolution - normal, and/or NetBIOS.
 * Returns an EAI_xxx error number like getaddrinfo(3)
 */
int
smb_ctx_getaddr(struct smb_ctx *ctx)
{
	struct nb_ctx	*nbc = ctx->ct_nb;
	struct addrinfo hints, *res;
	char *srvaddr_str;
	int gaierr;

	if (ctx->ct_fullserver == NULL || ctx->ct_fullserver[0] == '\0')
		return (EAI_NONAME);

	if (ctx->ct_addrinfo != NULL) {
		freeaddrinfo(ctx->ct_addrinfo);
		ctx->ct_addrinfo = NULL;
	}

	/*
	 * If the user specified an address, use it,
	 * and don't do NetBIOS lookup.
	 */
	if (ctx->ct_srvaddr_s) {
		srvaddr_str = ctx->ct_srvaddr_s;
		nbc->nb_flags &= ~NBCF_NS_ENABLE;
	} else
		srvaddr_str = ctx->ct_fullserver;

	/*
	 * Default the server name we'll use in the
	 * protocol (i.e. NTLM, tree connect).
	 */
	strlcpy(ctx->ct_srvname, ctx->ct_fullserver,
	    sizeof (ctx->ct_srvname));

	/*
	 * Try to lookup the host address using the
	 * normal name-to-IP address mechanisms.
	 * If that fails, we MAY try NetBIOS.
	 */
	memset(&hints, 0, sizeof (hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	gaierr = getaddrinfo(srvaddr_str, smb_port, &hints, &res);
	if (gaierr == 0) {
		ctx->ct_addrinfo = res;
		return (0);
	}

	/*
	 * If we really want to support NetBIOS, we should add
	 * an AF_NETBIOS entry to the address list here.
	 * For now, let's just skip NetBIOS.
	 * (Can we just kill NetBIOS?  Please? :)
	 */
#if 0	/* XXX Just kill NetBIOS? */
	/*
	 * If regular IP name lookup failed, try NetBIOS,
	 * but only if given a valid NetBIOS name and if
	 * NetBIOS name lookup is enabled.
	 */
	if (nbc->nb_flags & NBCF_NS_ENABLE) {
		int gaierr2 = nbns_getaddrinfo(ctx->ct_fullserver, nbc, &res);
		if (gaierr2 == 0) {
			if (res->ai_canonname)
				strlcpy(ctx->ct_srvname,
				    res->ai_canonname,
				    sizeof (ctx->ct_srvname));
			ctx->ct_addrinfo = res;
			return (0);
		}
	}
#endif

	/*
	 * Return the original error from getaddrinfo
	 */
	if (smb_verbose) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "getaddrinfo: %s: %s"), 0,
		    ctx->ct_fullserver,
		    gai_strerror(gaierr));
	}
	return (gaierr);
}
