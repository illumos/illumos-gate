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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Joyent, Inc.
 *
 * This file defines and implements the re-entrant getipnodebyname(),
 * getipnodebyaddr(), and freehostent() routines for IPv6. These routines
 * follow use the netdir_getbyYY() (see netdir_inet.c).
 *
 * lib/libnsl/nss/getipnodeby.c
 */

#include "mt.h"
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <nss_netdir.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdir.h>
#include <thread.h>
#include <synch.h>
#include <fcntl.h>
#include <sys/time.h>
#include "nss.h"

#define	IPV6_LITERAL_CHAR	':'

/*
 * The number of nanoseconds getipnodebyname() waits before getting
 * fresh interface count information with SIOCGLIFNUM.  The default is
 * five minutes.
 */
#define	IFNUM_TIMEOUT	((hrtime_t)300 * NANOSEC)

/*
 * Bits in the bitfield returned by getipnodebyname_processflags().
 *
 * IPNODE_WANTIPV6	The user wants IPv6 addresses returned.
 * IPNODE_WANTIPV4	The user wants IPv4 addresses returned.
 * IPNODE_IPV4IFNOIPV6	The user only wants IPv4 addresses returned if no IPv6
 *			addresses are returned.
 * IPNODE_LOOKUPIPNODES	getipnodebyname() needs to lookup the name in ipnodes.
 * IPNODE_LOOKUPHOSTS	getipnodebyname() needs to lookup the name in hosts.
 * IPNODE_ISLITERAL	The name supplied is a literal address string.
 * IPNODE_UNMAP		The user doesn't want v4 mapped addresses if no IPv6
 * 			interfaces are plumbed on the system.
 */
#define	IPNODE_WANTIPV6		0x00000001u
#define	IPNODE_WANTIPV4		0x00000002u
#define	IPNODE_IPV4IFNOIPV6	0x00000004u
#define	IPNODE_LOOKUPIPNODES	0x00000008u
#define	IPNODE_LOOKUPHOSTS	0x00000010u
#define	IPNODE_LITERAL		0x00000020u
#define	IPNODE_UNMAP		0x00000040u
#define	IPNODE_IPV4		(IPNODE_WANTIPV4 | IPNODE_IPV4IFNOIPV6)

/*
 * The private flag between libsocket and libnsl. See
 * lib/libsocket/inet/getaddrinfo.c for more information.
 */
#define	AI_ADDRINFO	0x8000

/*
 * The default set of bits corresponding to a getipnodebyname() flags
 * argument of AI_DEFAULT.
 */
#define	IPNODE_DEFAULT (IPNODE_WANTIPV6 | IPNODE_IPV4 | \
	IPNODE_LOOKUPIPNODES | IPNODE_LOOKUPHOSTS)

extern struct netconfig *__rpc_getconfip(char *);

static struct hostent *__mapv4tov6(struct hostent *, struct hostent *,
    nss_XbyY_buf_t *, int);
struct hostent *__mappedtov4(struct hostent *, int *);
static struct hostent *__filter_addresses(int, struct hostent *);
static int __find_mapped(struct hostent *, int);
static nss_XbyY_buf_t *__IPv6_alloc(int);
static void __IPv6_cleanup(nss_XbyY_buf_t *);
static int __ai_addrconfig(int, boolean_t);


#ifdef PIC
struct hostent *
_uncached_getipnodebyname(const char *nam, struct hostent *result,
	char *buffer, int buflen, int af_family, int flags, int *h_errnop)
{
	return (_switch_getipnodebyname_r(nam, result, buffer, buflen,
	    af_family, flags, h_errnop));
}

struct hostent *
_uncached_getipnodebyaddr(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	if (type == AF_INET)
		return (_switch_gethostbyaddr_r(addr, length, type,
		    result, buffer, buflen, h_errnop));
	else if (type == AF_INET6)
		return (_switch_getipnodebyaddr_r(addr, length, type,
		    result, buffer, buflen, h_errnop));
	return (NULL);
}
#endif

/*
 * Given a name, an address family, and a set of flags, return a
 * bitfield that getipnodebyname() will use.
 */
static uint_t
getipnodebyname_processflags(const char *name, int af, int flags)
{
	uint_t		ipnode_bits = IPNODE_DEFAULT;
	boolean_t	ipv6configured = B_FALSE;
	boolean_t	ipv4configured = B_FALSE;

	/*
	 * If AI_ADDRCONFIG is specified, we need to determine the number of
	 * addresses of each address family configured on the system as
	 * appropriate.
	 *
	 * When trying to determine which addresses should be used for
	 * addrconfig, we first ignore loopback devices. This generally makes
	 * sense as policy, as most of these queries will be trying to go
	 * off-box and one should not have an IPv6 loopback address suggest that
	 * we can now send IPv6 traffic off the box or the equivalent with IPv4.
	 * However, it's possible that no non-loopback interfaces are up on the
	 * box. In those cases, we then check which interfaces are up and
	 * consider loopback devices. While this isn't to the letter of RFC 3493
	 * (which itself is a bit vague in this case, as is SUS), it matches
	 * expected user behavior in these situations.
	 */
	if (flags & AI_ADDRCONFIG) {
		boolean_t hv4, hv6;

		hv4 = __ai_addrconfig(AF_INET, B_FALSE) > 0;
		hv6 = __ai_addrconfig(AF_INET6, B_FALSE) > 0;

		if (hv4 == B_FALSE && hv6 == B_FALSE) {
			hv4 = __ai_addrconfig(AF_INET, B_TRUE) > 0;
			hv6 = __ai_addrconfig(AF_INET6, B_TRUE) > 0;
		}

		ipv6configured = (af == AF_INET6 && hv6);
		ipv4configured = (af == AF_INET || (flags & AI_V4MAPPED)) &&
		    hv4;
	}

	/*
	 * Determine what kinds of addresses the user is interested
	 * in getting back.
	 */
	switch (af) {
	case AF_INET6:
		if ((flags & AI_ADDRCONFIG) && !ipv6configured)
			ipnode_bits &= ~IPNODE_WANTIPV6;

		if (flags & AI_V4MAPPED) {
			if ((flags & AI_ADDRCONFIG) && !ipv4configured) {
				ipnode_bits &= ~IPNODE_IPV4;
			} else if (flags & AI_ALL) {
				ipnode_bits &= ~IPNODE_IPV4IFNOIPV6;
			}
			if ((flags & AI_ADDRCONFIG) && !ipv6configured &&
			    (flags & AI_ADDRINFO)) {
				ipnode_bits |= IPNODE_UNMAP;
			}
		} else {
			ipnode_bits &= ~IPNODE_IPV4;
		}
		break;
	case AF_INET:
		if ((flags & AI_ADDRCONFIG) && !ipv4configured)
			ipnode_bits &= ~IPNODE_IPV4;
		ipnode_bits &= ~IPNODE_WANTIPV6;
		ipnode_bits &= ~IPNODE_IPV4IFNOIPV6;
		break;
	default:
		ipnode_bits = 0;
		break;
	}

	/*
	 * If we're not looking for IPv4 addresses, don't bother looking
	 * in hosts.
	 */
	if (!(ipnode_bits & IPNODE_WANTIPV4))
		ipnode_bits &= ~IPNODE_LOOKUPHOSTS;

	/*
	 * Determine if name is a literal IP address.  This will
	 * further narrow down what type of lookup we're going to do.
	 */
	if (strchr(name, IPV6_LITERAL_CHAR) != NULL) {
		/* Literal IPv6 address */
		ipnode_bits |= IPNODE_LITERAL;
		/*
		 * In s9 we accepted the literal without filtering independent
		 * of what family was passed in hints.  We continue to do
		 * this.
		 */
		ipnode_bits |= (IPNODE_WANTIPV6 | IPNODE_WANTIPV4);
		ipnode_bits &= ~IPNODE_LOOKUPHOSTS;
	} else if (inet_addr(name) != 0xffffffffU) {
		/* Literal IPv4 address */
		ipnode_bits |= (IPNODE_LITERAL | IPNODE_WANTIPV4);
		ipnode_bits &= ~IPNODE_WANTIPV6;
		ipnode_bits &= ~IPNODE_LOOKUPIPNODES;
	}
	return (ipnode_bits);
}

struct hostent *
getipnodebyname(const char *name, int af, int flags, int *error_num)
{
	struct hostent		*hp = NULL;
	nss_XbyY_buf_t		*buf4 = NULL;
	nss_XbyY_buf_t		*buf6 = NULL;
	struct netconfig	*nconf;
	struct nss_netdirbyname_in	nssin;
	union nss_netdirbyname_out	nssout;
	int			ret;
	uint_t			ipnode_bits;

	if ((nconf = __rpc_getconfip("udp")) == NULL &&
	    (nconf = __rpc_getconfip("tcp")) == NULL) {
		*error_num = NO_RECOVERY;
		return (NULL);
	}

	ipnode_bits = getipnodebyname_processflags(name, af, flags);

	/* Make sure we have something to look up. */
	if (!(ipnode_bits & (IPNODE_WANTIPV6 | IPNODE_WANTIPV4))) {
		*error_num = HOST_NOT_FOUND;
		goto cleanup;
	}

	/*
	 * Perform the requested lookups.  We always look through
	 * ipnodes first for both IPv4 and IPv6 addresses.  Depending
	 * on what was returned and what was needed, we either filter
	 * out the garbage, or ask for more using hosts.
	 */
	if (ipnode_bits & IPNODE_LOOKUPIPNODES) {
		if ((buf6 = __IPv6_alloc(NSS_BUFLEN_IPNODES)) == NULL) {
			*error_num = NO_RECOVERY;
			goto cleanup;
		}
		nssin.op_t = NSS_HOST6;
		nssin.arg.nss.host6.name = name;
		nssin.arg.nss.host6.buf = buf6->buffer;
		nssin.arg.nss.host6.buflen = buf6->buflen;
		nssin.arg.nss.host6.af_family = af;
		nssin.arg.nss.host6.flags = flags;
		nssout.nss.host.hent = buf6->result;
		nssout.nss.host.herrno_p = error_num;
		ret = _get_hostserv_inetnetdir_byname(nconf, &nssin, &nssout);
		if (ret != ND_OK) {
			__IPv6_cleanup(buf6);
			buf6 = NULL;
		} else if (ipnode_bits & IPNODE_WANTIPV4) {
			/*
			 * buf6 may have all that we need if we either
			 * only wanted IPv4 addresses if there were no
			 * IPv6 addresses returned, or if there are
			 * IPv4-mapped addresses in buf6.  If either
			 * of these are true, then there's no need to
			 * look in hosts.
			 */
			if (ipnode_bits & IPNODE_IPV4IFNOIPV6 ||
			    __find_mapped(buf6->result, 0) != 0) {
				ipnode_bits &= ~IPNODE_LOOKUPHOSTS;
			} else if (!(ipnode_bits & IPNODE_WANTIPV6)) {
				/*
				 * If all we're looking for are IPv4
				 * addresses and there are none in
				 * buf6 then buf6 is now useless.
				 */
				__IPv6_cleanup(buf6);
				buf6 = NULL;
			}
		}
	}
	if (ipnode_bits & IPNODE_LOOKUPHOSTS) {
		if ((buf4 = __IPv6_alloc(NSS_BUFLEN_HOSTS)) == NULL) {
			*error_num = NO_RECOVERY;
			goto cleanup;
		}
		nssin.op_t = NSS_HOST;
		nssin.arg.nss.host.name = name;
		nssin.arg.nss.host.buf = buf4->buffer;
		nssin.arg.nss.host.buflen = buf4->buflen;
		nssout.nss.host.hent = buf4->result;
		nssout.nss.host.herrno_p = error_num;
		ret = _get_hostserv_inetnetdir_byname(nconf, &nssin, &nssout);
		if (ret != ND_OK) {
			__IPv6_cleanup(buf4);
			buf4 = NULL;
		}
	}

	if (buf6 == NULL && buf4 == NULL) {
		*error_num = HOST_NOT_FOUND;
		goto cleanup;
	}

	/* Extract the appropriate addresses from the returned buffer(s). */
	switch (af) {
	case AF_INET6: {
		if (buf4 != NULL) {
			nss_XbyY_buf_t *mergebuf;

			/*
			 * The IPv4 results we have need to be
			 * converted to IPv4-mapped addresses,
			 * conditionally merged with the IPv6
			 * results, and the end result needs to be
			 * re-ordered.
			 */
			mergebuf = __IPv6_alloc(NSS_BUFLEN_IPNODES);
			if (mergebuf == NULL) {
				*error_num = NO_RECOVERY;
				goto cleanup;
			}
			hp = __mapv4tov6(buf4->result,
			    ((buf6 != NULL) ? buf6->result : NULL),
			    mergebuf, 1);
			if (hp != NULL)
				order_haddrlist_af(AF_INET6, hp->h_addr_list);
			else
				*error_num = NO_RECOVERY;
			free(mergebuf);
		}

		if (buf4 == NULL && buf6 != NULL) {
			hp = buf6->result;

			/*
			 * We have what we need in buf6, but we may need
			 * to filter out some addresses depending on what
			 * is being asked for.
			 */
			if (!(ipnode_bits & IPNODE_WANTIPV4))
				hp = __filter_addresses(AF_INET, buf6->result);
			else if (!(ipnode_bits & IPNODE_WANTIPV6))
				hp = __filter_addresses(AF_INET6, buf6->result);

			/*
			 * We've been asked to unmap v4 addresses. This
			 * situation implies IPNODE_WANTIPV4 and
			 * !IPNODE_WANTIPV6.
			 */
			if (hp != NULL && (ipnode_bits & IPNODE_UNMAP)) {
				/*
				 * Just set hp to a new value, cleanup: will
				 * free the old one
				 */
				hp = __mappedtov4(hp, error_num);
			} else if (hp == NULL)
				*error_num = NO_ADDRESS;
		}

		break;
	}

	case AF_INET:
		/* We could have results in buf6 or buf4, not both */
		if (buf6 != NULL) {
			/*
			 * Extract the IPv4-mapped addresses from buf6
			 * into hp.
			 */
			hp = __mappedtov4(buf6->result, error_num);
		} else {
			/* We have what we need in buf4. */
			hp = buf4->result;
			if (ipnode_bits & IPNODE_LITERAL) {
				/*
				 * There is a special case here for literal
				 * IPv4 address strings.  The hosts
				 * front-end sets h_aliases to a one
				 * element array containing a single NULL
				 * pointer (in ndaddr2hent()), while
				 * getipnodebyname() requires h_aliases to
				 * be a NULL pointer itself.  We're not
				 * going to change the front-end since it
				 * needs to remain backward compatible for
				 * gethostbyname() and friends.  Just set
				 * h_aliases to NULL here instead.
				 */
				hp->h_aliases = NULL;
			}
		}

		break;

	default:
		break;
	}

cleanup:
	/*
	 * Free the memory we allocated, but make sure we don't free
	 * the memory we're returning to the caller.
	 */
	if (buf6 != NULL) {
		if (buf6->result == hp)
			buf6->result = NULL;
		__IPv6_cleanup(buf6);
	}
	if (buf4 != NULL) {
		if (buf4->result == hp)
			buf4->result = NULL;
		__IPv6_cleanup(buf4);
	}
	(void) freenetconfigent(nconf);

	return (hp);
}

/*
 * This is the IPv6 interface for "gethostbyaddr".
 */
struct hostent *
getipnodebyaddr(const void *src, size_t len, int type, int *error_num)
{
	struct in6_addr *addr6 = 0;
	struct in_addr *addr4 = 0;
	nss_XbyY_buf_t *buf = 0;
	nss_XbyY_buf_t *res = 0;
	struct netconfig *nconf;
	struct hostent *hp = 0;
	struct	nss_netdirbyaddr_in nssin;
	union	nss_netdirbyaddr_out nssout;
	int neterr;
	char tmpbuf[64];

	if (type == AF_INET6) {
		if ((addr6 = (struct in6_addr *)src) == NULL) {
			*error_num = HOST_NOT_FOUND;
			return (NULL);
		}
	} else if (type == AF_INET) {
		if ((addr4 = (struct in_addr *)src) == NULL) {
			*error_num = HOST_NOT_FOUND;
			return (NULL);
		}
	} else {
		*error_num = HOST_NOT_FOUND;
		return (NULL);
	}
	/*
	 * Specific case: query for "::"
	 */
	if (type == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(addr6)) {
		*error_num = HOST_NOT_FOUND;
		return (NULL);
	}
	/*
	 * Step 1: IPv4-mapped address  or IPv4 Compat
	 */
	if ((type == AF_INET6 && len == 16) &&
	    ((IN6_IS_ADDR_V4MAPPED(addr6)) ||
	    (IN6_IS_ADDR_V4COMPAT(addr6)))) {
		if ((buf = __IPv6_alloc(NSS_BUFLEN_IPNODES)) == 0) {
			*error_num = NO_RECOVERY;
			return (NULL);
		}
		if ((nconf = __rpc_getconfip("udp")) == NULL &&
		    (nconf = __rpc_getconfip("tcp")) == NULL) {
			*error_num = NO_RECOVERY;
			__IPv6_cleanup(buf);
			return (NULL);
		}
		nssin.op_t = NSS_HOST6;
		if (IN6_IS_ADDR_V4COMPAT(addr6)) {
			(void) memcpy(tmpbuf, addr6, sizeof (*addr6));
			tmpbuf[10] = 0xffU;
			tmpbuf[11] = 0xffU;
			nssin.arg.nss.host.addr = (const char *)tmpbuf;
		} else {
			nssin.arg.nss.host.addr = (const char *)addr6;
		}
		nssin.arg.nss.host.len = sizeof (struct in6_addr);
		nssin.arg.nss.host.type = AF_INET6;
		nssin.arg.nss.host.buf = buf->buffer;
		nssin.arg.nss.host.buflen = buf->buflen;

		nssout.nss.host.hent = buf->result;
		nssout.nss.host.herrno_p = error_num;
		/*
		 * We pass in nconf and let the implementation of the
		 * long-named func decide whether to use the switch based on
		 * nc_nlookups.
		 */
		neterr =
		    _get_hostserv_inetnetdir_byaddr(nconf, &nssin, &nssout);

		(void) freenetconfigent(nconf);
		if (neterr != ND_OK) {
			/* Failover case, try hosts db for v4 address */
			if (!gethostbyaddr_r(((char *)addr6) + 12,
			    sizeof (in_addr_t), AF_INET, buf->result,
			    buf->buffer, buf->buflen, error_num)) {
				__IPv6_cleanup(buf);
				return (NULL);
			}
			/* Found one, now format it into mapped/compat addr */
			if ((res = __IPv6_alloc(NSS_BUFLEN_IPNODES)) == 0) {
				__IPv6_cleanup(buf);
				*error_num = NO_RECOVERY;
				return (NULL);
			}
			/* Convert IPv4 to mapped/compat address w/name */
			hp = res->result;
			(void) __mapv4tov6(buf->result, 0, res,
			    IN6_IS_ADDR_V4MAPPED(addr6));
			__IPv6_cleanup(buf);
			free(res);
			return (hp);
		}
		/*
		 * At this point, we'll have a v4mapped hostent. If that's
		 * what was passed in, just return. If the request was a compat,
		 * twiggle the two bytes to make the mapped address a compat.
		 */
		hp = buf->result;
		if (IN6_IS_ADDR_V4COMPAT(addr6)) {
			/* LINTED pointer cast */
			addr6 = (struct in6_addr *)hp->h_addr_list[0];
			addr6->s6_addr[10] = 0;
			addr6->s6_addr[11] = 0;
		}
		free(buf);
		return (hp);
	}
	/*
	 * Step 2: AF_INET, v4 lookup. Since we're going to search the
	 * ipnodes (v6) path first, we need to treat this as a v4mapped
	 * address. nscd(1m) caches v4 from ipnodes as mapped v6's. The
	 * switch backend knows to lookup v4's (not v4mapped) from the
	 * name services.
	 */
	if (type == AF_INET) {
		struct in6_addr v4mapbuf;
		addr6 = &v4mapbuf;

		IN6_INADDR_TO_V4MAPPED(addr4, addr6);
		if ((nconf = __rpc_getconfip("udp")) == NULL &&
		    (nconf = __rpc_getconfip("tcp")) == NULL) {
			*error_num = NO_RECOVERY;
			return (NULL);
		}
		if ((buf = __IPv6_alloc(NSS_BUFLEN_IPNODES)) == 0) {
			*error_num = NO_RECOVERY;
			freenetconfigent(nconf);
			return (NULL);
		}
		nssin.op_t = NSS_HOST6;
		nssin.arg.nss.host.addr = (const char *)addr6;
		nssin.arg.nss.host.len = sizeof (struct in6_addr);
		nssin.arg.nss.host.type = AF_INET6;
		nssin.arg.nss.host.buf = buf->buffer;
		nssin.arg.nss.host.buflen = buf->buflen;

		nssout.nss.host.hent = buf->result;
		nssout.nss.host.herrno_p = error_num;
		/*
		 * We pass in nconf and let the implementation of the
		 * long-named func decide whether to use the switch based on
		 * nc_nlookups.
		 */
		neterr =
		    _get_hostserv_inetnetdir_byaddr(nconf, &nssin, &nssout);

		(void) freenetconfigent(nconf);
		if (neterr != ND_OK) {
			/* Failover case, try hosts db for v4 address */
			hp = buf->result;
			if (!gethostbyaddr_r(src, len, type, buf->result,
			    buf->buffer, buf->buflen, error_num)) {
				__IPv6_cleanup(buf);
				return (NULL);
			}
			free(buf);
			return (hp);
		}
		if ((hp = __mappedtov4(buf->result, error_num)) == NULL) {
			__IPv6_cleanup(buf);
			return (NULL);
		}
		__IPv6_cleanup(buf);
		return (hp);
	}
	/*
	 * Step 3: AF_INET6, plain vanilla v6 getipnodebyaddr() call.
	 */
	if (type == AF_INET6) {
		if ((nconf = __rpc_getconfip("udp")) == NULL &&
		    (nconf = __rpc_getconfip("tcp")) == NULL) {
			*error_num = NO_RECOVERY;
			return (NULL);
		}
		if ((buf = __IPv6_alloc(NSS_BUFLEN_IPNODES)) == 0) {
			*error_num = NO_RECOVERY;
			freenetconfigent(nconf);
			return (NULL);
		}
		nssin.op_t = NSS_HOST6;
		nssin.arg.nss.host.addr = (const char *)addr6;
		nssin.arg.nss.host.len = len;
		nssin.arg.nss.host.type = type;
		nssin.arg.nss.host.buf = buf->buffer;
		nssin.arg.nss.host.buflen = buf->buflen;

		nssout.nss.host.hent = buf->result;
		nssout.nss.host.herrno_p = error_num;
		/*
		 * We pass in nconf and let the implementation of the
		 * long-named func decide whether to use the switch based on
		 * nc_nlookups.
		 */
		neterr =
		    _get_hostserv_inetnetdir_byaddr(nconf, &nssin, &nssout);

		(void) freenetconfigent(nconf);
		if (neterr != ND_OK) {
			__IPv6_cleanup(buf);
			return (NULL);
		}
		free(buf);
		return (nssout.nss.host.hent);
	}
	/*
	 * If we got here, unknown type.
	 */
	*error_num = HOST_NOT_FOUND;
	return (NULL);
}

void
freehostent(struct hostent *hent)
{
	free(hent);
}

static int
__ai_addrconfig(int af, boolean_t loopback)
{
	struct lifnum	lifn;
	struct lifconf	lifc;
	struct lifreq	*lifp, *buf = NULL;
	size_t		bufsize;
	hrtime_t	now, *then;
	static hrtime_t	then4, then6; /* the last time we updated ifnum# */
	static int	ifnum4 = -1, ifnum6 = -1, iflb4 = 0, iflb6 = 0;
	int		*num, *lb;
	int 		nlifr, count = 0;


	switch (af) {
	case AF_INET:
		num = &ifnum4;
		then = &then4;
		lb = &iflb4;
		break;
	case AF_INET6:
		num = &ifnum6;
		then = &then6;
		lb = &iflb6;
		break;
	default:
		return (0);
	}

	/*
	 * We don't need to check this every time someone does a name
	 * lookup.  Do it every IFNUM_TIMEOUT for each address family.
	 *
	 * There's no need to protect all of this with a lock.  The
	 * worst that can happen is that we update the interface count
	 * twice instead of once.  That's no big deal.
	 */
	now = gethrtime();
	if (*num == -1 || ((now - *then) >= IFNUM_TIMEOUT)) {
		lifn.lifn_family = af;
		/*
		 * We want to determine if this machine knows anything
		 * at all about the address family; the status of the
		 * interface is less important. Hence, set
		 * 'lifn_flags' to zero.
		 */
		lifn.lifn_flags = 0;
again:
		if (nss_ioctl(af, SIOCGLIFNUM, &lifn) < 0)
			goto fail;

		if (lifn.lifn_count == 0) {
			*lb = 0;
			*num = 0;
			*then = now;
			return (*num);
		}

		/*
		 * Pad the interface count to detect when additional
		 * interfaces have been configured between SIOCGLIFNUM
		 * and SIOCGLIFCONF.
		 */
		lifn.lifn_count += 4;

		bufsize = lifn.lifn_count * sizeof (struct lifreq);
		if ((buf = realloc(buf, bufsize)) == NULL)
			goto fail;

		lifc.lifc_family = af;
		lifc.lifc_flags = 0;
		lifc.lifc_len = bufsize;
		lifc.lifc_buf = (caddr_t)buf;
		if (nss_ioctl(af, SIOCGLIFCONF, &lifc) < 0)
			goto fail;

		nlifr = lifc.lifc_len / sizeof (struct lifreq);
		if (nlifr >= lifn.lifn_count)
			goto again;
		/*
		 * Do not include any loopback addresses, 127.0.0.1 for AF_INET
		 * and ::1 for AF_INET6, while counting the number of available
		 * IPv4 or IPv6 addresses. (RFC 3493 requires this, whenever
		 * AI_ADDRCONFIG flag is set) However, if the loopback flag is
		 * set to true we'll include it in the output.
		 */
		for (lifp = buf; lifp < buf + nlifr; lifp++) {
			switch (af) {
			case AF_INET: {
				struct sockaddr_in *in;

				in = (struct sockaddr_in *)&lifp->lifr_addr;
				if (ntohl(in->sin_addr.s_addr) ==
				    INADDR_LOOPBACK) {
					count++;
				}
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6 *in6;

				in6 = (struct sockaddr_in6 *)&lifp->lifr_addr;
				if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr))
					count++;
				break;
			}
			}
		}
		*num = nlifr - count;
		*lb = count;
		*then = now;
		free(buf);
	}
	if (loopback == B_TRUE)
		return (*num + *lb);
	else
		return (*num);
fail:
	free(buf);
	/*
	 * If the process is running without the NET_ACCESS basic privilege,
	 * pretend we still have inet/inet6 interfaces.
	 */
	if (errno == EACCES)
		return (1);
	return (-1);
}

/*
 * This routine will either convert an IPv4 address to a mapped or compat
 * IPv6 (if he6 == NULL) or merge IPv6 (he6) addresses with mapped
 * v4 (he4) addresses. In either case, the results are returned in res.
 * Caller must provide all buffers.
 * Inputs:
 * 		he4	pointer to IPv4 buffer
 *		he6	pointer to IPv6 buffer (NULL if not merging v4/v6
 *		res	pointer to results buffer
 *		mapped	mapped == 1, map IPv4 : mapped == 0, compat IPv4
 *			mapped flag is ignored if he6 != NULL
 *
 * The results are packed into the res->buffer as follows:
 * <--------------- buffer + buflen -------------------------------------->
 * |-----------------|-----------------|----------------|----------------|
 * | pointers vector | pointers vector | aliases grow   | addresses grow |
 * | for addresses   | for aliases     |                |                |
 * | this way ->     | this way ->     | <- this way    |<- this way     |
 * |-----------------|-----------------|----------------|----------------|
 * | grows in PASS 1 | grows in PASS2  | grows in PASS2 | grows in PASS 1|
 */
static struct hostent *
__mapv4tov6(struct hostent *he4, struct hostent *he6, nss_XbyY_buf_t *res,
		int mapped)
{
	char	*buffer, *limit;
	int	buflen = res->buflen;
	struct	in6_addr *addr6p;
	char	*buff_locp;
	struct	hostent *host;
	int	count = 0, len, i;
	char	*h_namep;

	if (he4 == NULL || res == NULL) {
		return (NULL);
	}
	limit = res->buffer + buflen;
	host = (struct hostent *)res->result;
	buffer = res->buffer;

	buff_locp = (char *)ROUND_DOWN(limit, sizeof (struct in6_addr));
	host->h_addr_list = (char **)ROUND_UP(buffer, sizeof (char **));
	if ((char *)host->h_addr_list >= limit ||
	    buff_locp <= (char *)host->h_addr_list) {
		return (NULL);
	}
	if (he6 == NULL) {
		/*
		 * If he6==NULL, map the v4 address into the v6 address format.
		 * This is used for getipnodebyaddr() (single address, mapped or
		 * compatible) or for v4 mapped for getipnodebyname(), which
		 * could be multiple addresses. This could also be a literal
		 * address string, which is why there is a inet_addr() call.
		 */
		for (i = 0; he4->h_addr_list[i] != NULL; i++) {
			buff_locp -= sizeof (struct in6_addr);
			if (buff_locp <=
			    (char *)&(host->h_addr_list[count + 1])) {
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
				return (NULL);
			}
			/* LINTED pointer cast */
			addr6p = (struct in6_addr *)buff_locp;
			host->h_addr_list[count] = (char *)addr6p;
			bzero(addr6p->s6_addr, sizeof (struct in6_addr));
			if (mapped) {
				addr6p->s6_addr[10] = 0xff;
				addr6p->s6_addr[11] = 0xff;
			}
			bcopy((char *)he4->h_addr_list[i],
			    &addr6p->s6_addr[12], sizeof (struct in_addr));
			++count;
		}
		/*
		 * Set last array element to NULL and add cname as first alias
		 */
		host->h_addr_list[count] = NULL;
		host->h_aliases = host->h_addr_list + count + 1;
		count = 0;
		if ((int)(inet_addr(he4->h_name)) != -1) {
		/*
		 * Literal address string, since we're mapping, we need the IPv6
		 * V4 mapped literal address string for h_name.
		 */
			char	tmpstr[128];
			(void) inet_ntop(AF_INET6, host->h_addr_list[0], tmpstr,
			    sizeof (tmpstr));
			buff_locp -= (len = strlen(tmpstr) + 1);
			h_namep = tmpstr;
			if (buff_locp <= (char *)(host->h_aliases))
				return (NULL);
			bcopy(h_namep, buff_locp, len);
			host->h_name = buff_locp;
			host->h_aliases = NULL; /* no aliases for literal */
			host->h_length = sizeof (struct in6_addr);
			host->h_addrtype = AF_INET6;
			return (host); 		/* we're done, return result */
		}
		/*
		 * Not a literal address string, so just copy h_name.
		 */
		buff_locp -= (len = strlen(he4->h_name) + 1);
		h_namep = he4->h_name;
		if (buff_locp <= (char *)(host->h_aliases))
			return (NULL);
		bcopy(h_namep, buff_locp, len);
		host->h_name = buff_locp;
		/*
		 * Pass 2 (IPv4 aliases):
		 */
		for (i = 0; he4->h_aliases[i] != NULL; i++) {
			buff_locp -= (len = strlen(he4->h_aliases[i]) + 1);
			if (buff_locp <=
			    (char *)&(host->h_aliases[count + 1])) {
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
				return (NULL);
			}
			host->h_aliases[count] = buff_locp;
			bcopy((char *)he4->h_aliases[i], buff_locp, len);
			++count;
		}
		host->h_aliases[count] = NULL;
		host->h_length = sizeof (struct in6_addr);
		host->h_addrtype = AF_INET6;
		return (host);
	} else {
		/*
		 * Merge IPv4 mapped addresses with IPv6 addresses. The
		 * IPv6 address will go in first, followed by the v4 mapped.
		 *
		 * Pass 1 (IPv6 addresses):
		 */
		for (i = 0; he6->h_addr_list[i] != NULL; i++) {
			buff_locp -= sizeof (struct in6_addr);
			if (buff_locp <=
			    (char *)&(host->h_addr_list[count + 1])) {
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
				return (NULL);
			}
			host->h_addr_list[count] = buff_locp;
			bcopy((char *)he6->h_addr_list[i], buff_locp,
			    sizeof (struct in6_addr));
			++count;
		}
		/*
		 * Pass 1 (IPv4 mapped addresses):
		 */
		for (i = 0; he4->h_addr_list[i] != NULL; i++) {
			buff_locp -= sizeof (struct in6_addr);
			if (buff_locp <=
			    (char *)&(host->h_addr_list[count + 1])) {
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
				return (NULL);
			}
			/* LINTED pointer cast */
			addr6p = (struct in6_addr *)buff_locp;
			host->h_addr_list[count] = (char *)addr6p;
			bzero(addr6p->s6_addr, sizeof (struct in6_addr));
			addr6p->s6_addr[10] = 0xff;
			addr6p->s6_addr[11] = 0xff;
			bcopy(he4->h_addr_list[i], &addr6p->s6_addr[12],
			    sizeof (struct in_addr));
			++count;
		}
		/*
		 * Pass 2 (IPv6 aliases, host name first). We start h_aliases
		 * one after where h_addr_list array ended. This is where cname
		 * is put, followed by all aliases. Reset count to 0, for index
		 * in the h_aliases array.
		 */
		host->h_addr_list[count] = NULL;
		host->h_aliases = host->h_addr_list + count + 1;
		count = 0;
		buff_locp -= (len = strlen(he6->h_name) + 1);
		if (buff_locp <= (char *)(host->h_aliases))
			return (NULL);
		bcopy(he6->h_name, buff_locp, len);
		host->h_name = buff_locp;
		for (i = 0; he6->h_aliases[i] != NULL; i++) {
			buff_locp -= (len = strlen(he6->h_aliases[i]) + 1);
			if (buff_locp <=
			    (char *)&(host->h_aliases[count + 1])) {
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
				return (NULL);
			}
			host->h_aliases[count] = buff_locp;
			bcopy((char *)he6->h_aliases[i], buff_locp, len);
			++count;
		}
		/*
		 * Pass 2 (IPv4 aliases):
		 */
		for (i = 0; he4->h_aliases[i] != NULL; i++) {
			buff_locp -= (len = strlen(he4->h_aliases[i]) + 1);
			if (buff_locp <=
			    (char *)&(host->h_aliases[count + 1])) {
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
				return (NULL);
			}
			host->h_aliases[count] = buff_locp;
			bcopy((char *)he4->h_aliases[i], buff_locp, len);
			++count;
		}
		host->h_aliases[count] = NULL;
		host->h_length = sizeof (struct in6_addr);
		host->h_addrtype = AF_INET6;
		return (host);
	}
}

/*
 * This routine will convert a mapped v4 hostent (AF_INET6) to a
 * AF_INET hostent. If no mapped addrs found, then a NULL is returned.
 * If mapped addrs found, then a new buffer is alloc'd and all the v4 mapped
 * addresses are extracted and copied to it. On sucess, a pointer to a new
 * hostent is returned.
 * There are two possible errors in which case a NULL is returned.
 * One of two error codes are returned:
 *
 * NO_RECOVERY - a malloc failed or the like for which there's no recovery.
 * NO_ADDRESS - after filtering all the v4, there was nothing left!
 *
 * Inputs:
 *              he              pointer to hostent with mapped v4 addresses
 *              filter_error    pointer to return error code
 * Return:
 *		pointer to a malloc'd hostent with v4 addresses.
 *
 * The results are packed into the res->buffer as follows:
 * <--------------- buffer + buflen -------------------------------------->
 * |-----------------|-----------------|----------------|----------------|
 * | pointers vector | pointers vector | aliases grow   | addresses grow |
 * | for addresses   | for aliases     |                |                |
 * | this way ->     | this way ->     | <- this way    |<- this way     |
 * |-----------------|-----------------|----------------|----------------|
 * | grows in PASS 1 | grows in PASS2  | grows in PASS2 | grows in PASS 1|
 */
struct hostent *
__mappedtov4(struct hostent *he, int *extract_error)
{
	char	*buffer, *limit;
	nss_XbyY_buf_t *res;
	int	buflen = NSS_BUFLEN_HOSTS;
	struct	in_addr *addr4p;
	char	*buff_locp;
	struct	hostent *host;
	int	count = 0, len, i;
	char	*h_namep;

	if (he == NULL) {
		*extract_error = NO_ADDRESS;
		return (NULL);
	}
	if ((__find_mapped(he, 0)) == 0) {
		*extract_error = NO_ADDRESS;
		return (NULL);
	}
	if ((res = __IPv6_alloc(NSS_BUFLEN_HOSTS)) == 0) {
		*extract_error = NO_RECOVERY;
		return (NULL);
	}
	limit = res->buffer + buflen;
	host = (struct hostent *)res->result;
	buffer = res->buffer;

	buff_locp = (char *)ROUND_DOWN(limit, sizeof (struct in_addr));
	host->h_addr_list = (char **)ROUND_UP(buffer, sizeof (char **));
	if ((char *)host->h_addr_list >= limit ||
	    buff_locp <= (char *)host->h_addr_list)
		goto cleanup;
	/*
	 * "Unmap" the v4 mapped address(es) into a v4 hostent format.
	 * This is used for getipnodebyaddr() (single address) or for
	 * v4 mapped for getipnodebyname(), which could be multiple
	 * addresses. This could also be a literal address string,
	 * which is why there is a inet_addr() call.
	 */
	for (i = 0; he->h_addr_list[i] != NULL; i++) {
		/* LINTED pointer cast */
		if (!IN6_IS_ADDR_V4MAPPED((struct in6_addr *)
		    he->h_addr_list[i]))
			continue;
		buff_locp -= sizeof (struct in6_addr);
		/*
		 * Has to be room for the pointer to the address we're
		 * about to add, as well as the final NULL ptr.
		 */
		if (buff_locp <=
		    (char *)&(host->h_addr_list[count + 1]))
			goto cleanup;
		/* LINTED pointer cast */
		addr4p = (struct in_addr *)buff_locp;
		host->h_addr_list[count] = (char *)addr4p;
		bzero((char *)&addr4p->s_addr,
		    sizeof (struct in_addr));
		/* LINTED pointer cast */
		IN6_V4MAPPED_TO_INADDR(
		    (struct in6_addr *)he->h_addr_list[i], addr4p);
		++count;
	}
	/*
	 * Set last array element to NULL and add cname as first alias
	 */
	host->h_addr_list[count] = NULL;
	host->h_aliases = host->h_addr_list + count + 1;
	count = 0;
	/* Copy official host name */
	buff_locp -= (len = strlen(he->h_name) + 1);
	h_namep = he->h_name;
	if (buff_locp <= (char *)(host->h_aliases))
		goto cleanup;
	bcopy(h_namep, buff_locp, len);
	host->h_name = buff_locp;
	/*
	 * Pass 2 (IPv4 aliases):
	 */
	if (he->h_aliases != NULL) {
		for (i = 0; he->h_aliases[i] != NULL; i++) {
			buff_locp -= (len = strlen(he->h_aliases[i]) + 1);
			/*
			 * Has to be room for the pointer to the address we're
			 * about to add, as well as the final NULL ptr.
			 */
			if (buff_locp <=
			    (char *)&(host->h_aliases[count + 1]))
				goto cleanup;
			host->h_aliases[count] = buff_locp;
			bcopy((char *)he->h_aliases[i], buff_locp, len);
			++count;
		}
	}
	host->h_aliases[count] = NULL;
	host->h_length = sizeof (struct in_addr);
	host->h_addrtype = AF_INET;
	free(res);
	return (host);
cleanup:
	*extract_error = NO_RECOVERY;
	(void) __IPv6_cleanup(res);
	return (NULL);
}

/*
 * This routine takes as input a pointer to a hostent and filters out
 * the type of addresses specified by the af argument.  AF_INET
 * indicates that the caller wishes to filter out IPv4-mapped
 * addresses, and AF_INET6 indicates that the caller wishes to filter
 * out IPv6 addresses which aren't IPv4-mapped.  If filtering would
 * result in all addresses being filtered out, a NULL pointer is returned.
 * Otherwise, the he pointer passed in is returned, even if no addresses
 * were filtered out.
 */
static struct hostent *
__filter_addresses(int af, struct hostent *he)
{
	struct in6_addr	**in6addrlist, **in6addr;
	boolean_t	isipv4mapped;
	int		i = 0;

	if (he == NULL)
		return (NULL);

	in6addrlist = (struct in6_addr **)he->h_addr_list;
	for (in6addr = in6addrlist; *in6addr != NULL; in6addr++) {
		isipv4mapped = IN6_IS_ADDR_V4MAPPED(*in6addr);

		if ((af == AF_INET && !isipv4mapped) ||
		    (af == AF_INET6 && isipv4mapped)) {
			if (in6addrlist[i] != *in6addr)
				in6addrlist[i] = *in6addr;
			i++;
		}
	}

	if (i == 0) {
		/* We filtered everything out. */
		return (NULL);
	} else {
		/* NULL terminate the list and return the hostent */
		in6addrlist[i] = NULL;
		return (he);
	}
}

/*
 * This routine searches a hostent for v4 mapped IPv6 addresses.
 * he		hostent structure to seach
 * find_both	flag indicating if only want mapped or both map'd and v6
 * return values:
 * 			0 = No mapped addresses
 *			1 = Mapped v4 address found (returns on first one found)
 *			2 = Both v6 and v4 mapped are present
 *
 * If hostent passed in with no addresses, zero will be returned.
 */

static int
__find_mapped(struct hostent *he, int find_both)
{
	int i;
	int mapd_found = 0;
	int v6_found = 0;

	for (i = 0; he->h_addr_list[i] != NULL; i++) {
		/* LINTED pointer cast */
		if (IN6_IS_ADDR_V4MAPPED(
				(struct in6_addr *)he->h_addr_list[i])) {
			if (find_both)
				mapd_found = 1;
			else
				return (1);
		} else {
			v6_found = 1;
		}
		/* save some iterations once both found */
		if (mapd_found && v6_found)
			return (2);
	}
	return (mapd_found);
}

/*
 * This routine was added specifically for the IPv6 getipnodeby*() APIs. This
 * separates the result pointer (ptr to hostent+data buf) from the
 * nss_XbyY_buf_t ptr (required for nsswitch API). The returned hostent ptr
 * can be passed to freehostent() and freed independently.
 *
 *   bufp->result    bufp->buffer
 *		|		|
 *		V		V
 *		------------------------------------------------...--
 *		|struct hostent	|addresses		     aliases |
 *		------------------------------------------------...--
 *		|               |<--------bufp->buflen-------------->|
 */

#define	ALIGN(x) ((((long)(x)) + sizeof (long) - 1) & ~(sizeof (long) - 1))

static nss_XbyY_buf_t *
__IPv6_alloc(int bufsz)
{
	nss_XbyY_buf_t *bufp;

	if ((bufp = malloc(sizeof (nss_XbyY_buf_t))) == NULL)
		return (NULL);

	if ((bufp->result = malloc(ALIGN(sizeof (struct hostent)) + bufsz)) ==
	    NULL) {
		free(bufp);
		return (NULL);
	}
	bufp->buffer = (char *)(bufp->result) + sizeof (struct hostent);
	bufp->buflen = bufsz;
	return (bufp);
}

/*
 * This routine is use only for error return cleanup. This will free the
 * hostent pointer, so don't use for successful returns.
 */
static void
__IPv6_cleanup(nss_XbyY_buf_t *bufp)
{
	if (bufp == NULL)
		return;
	if (bufp->result != NULL)
		free(bufp->result);
	free(bufp);
}
