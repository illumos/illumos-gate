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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nss_netdir.h
 *
 * Defines structures that are shared between the OSNET-private
 * _get_hostserv_inetnetdir_byYY() interfaces and the public
 * interfaces gethostbyYY()/getservbyYY() and netdir_getbyYY().
 * Ideally, this header file should never be visible to developers
 * outside of the OSNET build.
 */

#ifndef _NSS_NETDIR_H
#define	_NSS_NETDIR_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	NSS_HOST,
	NSS_SERV,
	NETDIR_BY,
	NETDIR_BY_NOSRV,		/* bypass service lookup */
	NETDIR_BY6,
	NETDIR_BY_NOSRV6,		/* bypass service lookup */
	NSS_HOST6
} nss_netdir_op_t;

struct nss_netdirbyname_in {
	nss_netdir_op_t	op_t;
	union {
		struct nd_hostserv *nd_hs;
		union {
			struct {
				const char	*name;
				char	*buf;
				int	buflen;
			} host;
			struct {
				const char	*name;
				char	*buf;
				int	buflen;
				int	af_family;	/* for ipnode */
				int	flags;		/* for ipnode */
			} host6;
			struct {
				const char	*name;
				const char	*proto;
				char	*buf;
				int	buflen;
			} serv;
		} nss;
	} arg;
};

union nss_netdirbyname_out {
	struct nd_addrlist **nd_alist;
	union {
		struct {
			struct hostent *hent;
			int	*herrno_p;
		} host;
		struct servent *serv;
	} nss;
};

struct nss_netdirbyaddr_in {
	nss_netdir_op_t	op_t;
	union {
		struct netbuf *nd_nbuf;
		union {
			struct {
				const char	*addr;
				int	len;
				int	type;
				char	*buf;
				int	buflen;
			} host;
			struct {
				int	port;
				const char	*proto;
				char	*buf;
				int	buflen;
			} serv;
		} nss;
	} arg;
};

union nss_netdirbyaddr_out {
	struct nd_hostservlist **nd_hslist;
	union {
		struct {
			struct hostent *hent;
			int	*herrno_p;
		} host;
		struct servent *serv;
	} nss;
};

int __classic_netdir_getbyname(struct netconfig *,
		struct nd_hostserv *, struct nd_addrlist **);
int __classic_netdir_getbyaddr(struct netconfig *,
		struct nd_hostservlist **, struct netbuf *);
int _get_hostserv_inetnetdir_byname(struct netconfig *,
		struct nss_netdirbyname_in *, union nss_netdirbyname_out *);
int _get_hostserv_inetnetdir_byaddr(struct netconfig *,
		struct nss_netdirbyaddr_in *, union nss_netdirbyaddr_out *);
int __inet_netdir_options(struct netconfig *,
		int option, int fd, char *par);
struct netbuf *__inet_uaddr2taddr(struct netconfig *, char *);
char *__inet_taddr2uaddr(struct netconfig *, struct netbuf *);

#ifdef	__cplusplus
}
#endif

#endif /* _NSS_NETDIR_H */
