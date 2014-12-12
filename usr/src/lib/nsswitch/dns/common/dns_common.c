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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 *	dns_common.c
 */

#include "dns_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>

#pragma weak	dn_expand
#pragma weak	res_ninit
#pragma weak	res_ndestroy
#pragma weak	res_nsearch
#pragma weak	res_nclose
#pragma weak	ns_get16
#pragma weak	ns_get32
#pragma weak	__ns_get16
#pragma weak	__ns_get32

#define	DNS_ALIASES	0
#define	DNS_ADDRLIST	1
#define	DNS_MAPDLIST	2

#ifndef	tolower
#define	tolower(c) ((c) >= 'A' && (c) <= 'Z' ? (c) | 0x20 : (c))
#endif

static int
dns_netdb_aliases(from_list, to_list, aliaspp, type, count, af_type)
	char	**from_list, **to_list,	**aliaspp;
	int	type, *count, af_type;
{
	char		*fstr;
	int		cnt = 0;
	size_t		len;

	*count = 0;
	if ((char *)to_list >= *aliaspp)
		return (NSS_STR_PARSE_ERANGE);

	for (fstr = from_list[cnt]; fstr != NULL; fstr = from_list[cnt]) {
		if (type == DNS_ALIASES)
			len = strlen(fstr) + 1;
		else
			len = (af_type == AF_INET) ? sizeof (struct in_addr)
						: sizeof (struct in6_addr);
		*aliaspp -= len;
		to_list[cnt] = *aliaspp;
		if (*aliaspp <= (char *)&to_list[cnt+1])
			return (NSS_STR_PARSE_ERANGE);
		if (type == DNS_MAPDLIST) {
			/* LINTED: E_BAD_PTR_CAST_ALIGN */
			struct in6_addr *addr6p = (struct in6_addr *)*aliaspp;

			(void) memset(addr6p, '\0', sizeof (struct in6_addr));
			(void) memcpy(&addr6p->s6_addr[12], fstr,
					sizeof (struct in_addr));
			addr6p->s6_addr[10] = 0xffU;
			addr6p->s6_addr[11] = 0xffU;
			++cnt;
		} else {
			(void) memcpy (*aliaspp, fstr, len);
			++cnt;
		}
	}
	to_list[cnt] = NULL;

	*count = cnt;
	if (cnt == 0)
		return (NSS_STR_PARSE_PARSE);

	return (NSS_STR_PARSE_SUCCESS);
}


int
ent2result(he, argp, af_type)
	struct hostent		*he;
	nss_XbyY_args_t		*argp;
	int			af_type;
{
	char		*buffer, *limit;
	int		buflen = argp->buf.buflen;
	int		ret, count;
	size_t len;
	struct hostent 	*host;
	struct in_addr	*addrp;
	struct in6_addr	*addrp6;

	limit = argp->buf.buffer + buflen;
	host = (struct hostent *)argp->buf.result;
	buffer = argp->buf.buffer;

	/* h_addrtype and h_length */
	host->h_addrtype = af_type;
	host->h_length = (af_type == AF_INET) ? sizeof (struct in_addr)
					: sizeof (struct in6_addr);

	/* h_name */
	len = strlen(he->h_name) + 1;
	host->h_name = buffer;
	if (host->h_name + len >= limit)
		return (NSS_STR_PARSE_ERANGE);
	(void) memcpy(host->h_name, he->h_name, len);
	buffer += len;

	/* h_addr_list */
	if (af_type == AF_INET) {
		addrp = (struct in_addr *)ROUND_DOWN(limit, sizeof (*addrp));
		host->h_addr_list = (char **)
				ROUND_UP(buffer, sizeof (char **));
		ret = dns_netdb_aliases(he->h_addr_list, host->h_addr_list,
			(char **)&addrp, DNS_ADDRLIST, &count, af_type);
		if (ret != NSS_STR_PARSE_SUCCESS)
			return (ret);
		/* h_aliases */
		host->h_aliases = host->h_addr_list + count + 1;
		ret = dns_netdb_aliases(he->h_aliases, host->h_aliases,
			(char **)&addrp, DNS_ALIASES, &count, af_type);
	} else {
		addrp6 = (struct in6_addr *)
			ROUND_DOWN(limit, sizeof (*addrp6));
		host->h_addr_list = (char **)
			ROUND_UP(buffer, sizeof (char **));
		if (he->h_addrtype == AF_INET && af_type == AF_INET6) {
			ret = dns_netdb_aliases(he->h_addr_list,
				host->h_addr_list, (char **)&addrp6,
				DNS_MAPDLIST, &count, af_type);
		} else {
			ret = dns_netdb_aliases(he->h_addr_list,
				host->h_addr_list, (char **)&addrp6,
				DNS_ADDRLIST, &count, af_type);
		}
		if (ret != NSS_STR_PARSE_SUCCESS)
			return (ret);
		/* h_aliases */
		host->h_aliases = host->h_addr_list + count + 1;
		ret = dns_netdb_aliases(he->h_aliases, host->h_aliases,
			(char **)&addrp6, DNS_ALIASES, &count, af_type);
	}
	if (ret == NSS_STR_PARSE_PARSE)
		ret = NSS_STR_PARSE_SUCCESS;

	return (ret);
}

/*
 * Convert the hostent structure into string in the following
 * format:
 *
 * IP-address official-host-name nicknames ...
 *
 * If more than one IP-addresses matches the official-host-name,
 * the above line will be followed by:
 * IP-address-1 official-host-name
 * IP-address-2 official-host-name
 * ...
 *
 * This is so that the str2hostent function in libnsl
 * can convert the string back to the original hostent
 * data.
 */
int
ent2str(
	struct hostent	*hp,
	nss_XbyY_args_t *ap,
	int		af_type)
{
	char		**p;
	char		obuf[INET6_ADDRSTRLEN];
	void		*addr;
	struct in_addr	in4;
	int		af;
	int		n;
	const char	*res;
	char		**q;
	int		l = ap->buf.buflen;
	char		*s = ap->buf.buffer;

	/*
	 * for "hosts" lookup, we only want address type of
	 * AF_INET. For "ipnodes", we can have both AF_INET
	 * and AF_INET6.
	 */
	if (af_type == AF_INET && hp->h_addrtype != AF_INET)
		return (NSS_STR_PARSE_PARSE);

	for (p = hp->h_addr_list; *p != 0; p++) {

		if (p != hp->h_addr_list) {
			*s = '\n';
			s++;
			l--;
		}

		if (hp->h_addrtype == AF_INET6) {
			/* LINTED: E_BAD_PTR_CAST_ALIGN */
			if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)*p)) {
				/* LINTED: E_BAD_PTR_CAST_ALIGN */
				IN6_V4MAPPED_TO_INADDR((struct in6_addr *)*p,
				    &in4);
				af = AF_INET;
				addr = &in4;
			} else {
				af = AF_INET6;
				addr = *p;
			}
		} else {
			af = AF_INET;
			addr = *p;
		}
		res = inet_ntop(af, addr, obuf, sizeof (obuf));
		if (res == NULL)
			return (NSS_STR_PARSE_PARSE);

		if ((n = snprintf(s, l, "%s", res)) >= l)
			return (NSS_STR_PARSE_ERANGE);
		l -= n;
		s += n;
		if (hp->h_name != NULL && *hp->h_name != '\0') {
			if ((n = snprintf(s, l, " %s", hp->h_name)) >= l)
				return (NSS_STR_PARSE_ERANGE);
			l -= n;
			s += n;
		}
		if (p == hp->h_addr_list) {
			for (q = hp->h_aliases; q && *q; q++) {
				if ((n = snprintf(s, l, " %s", *q)) >= l)
					return (NSS_STR_PARSE_ERANGE);
				l -= n;
				s += n;
			}
		}
	}

	ap->returnlen = s - ap->buf.buffer;
	return (NSS_STR_PARSE_SUCCESS);
}

nss_backend_t *
_nss_dns_constr(dns_backend_op_t ops[], int n_ops)
{
	dns_backend_ptr_t	be;

	if ((be = (dns_backend_ptr_t)malloc(sizeof (*be))) == 0)
		return (0);

	be->ops = ops;
	be->n_ops = n_ops;
	return ((nss_backend_t *)be);
}

/*
 * name_is_alias(aliases_ptr, name_ptr)
 * Verify name matches an alias in the provided aliases list.
 *
 * Within DNS there should be only one canonical name, aliases should
 * all refer to the one canonical.  However alias chains do occur and
 * pre BIND 9 servers may also respond with multiple CNAMEs.  This
 * routine checks if a given name has been provided as a CNAME in the
 * response.  This assumes that the chains have been sent in-order.
 *
 * INPUT:
 *  aliases_ptr: space separated list of alias names.
 *  name_ptr: name to look for in aliases_ptr list.
 * RETURNS: NSS_SUCCESS or NSS_NOTFOUND
 *  NSS_SUCCESS indicates that the name is listed in the collected aliases.
 */
static nss_status_t
name_is_alias(char *aliases_ptr, char *name_ptr) {
	char *host_ptr;
	/* Loop through alias string and compare it against host string. */
	while (*aliases_ptr != '\0') {
		host_ptr = name_ptr;

		/* Compare name with alias. */
		while (tolower(*host_ptr) == tolower(*aliases_ptr) &&
		    *host_ptr != '\0') {
			host_ptr++;
			aliases_ptr++;
		}

		/*
		 * If name was exhausted and the next character in the
		 * alias is either the end-of-string or space
		 * character then we have a match.
		 */
		if (*host_ptr == '\0' &&
		    (*aliases_ptr == '\0' || *aliases_ptr == ' ')) {
			return (NSS_SUCCESS);
		}

		/* Alias did not match, step over remainder of alias. */
		while (*aliases_ptr != ' ' && *aliases_ptr != '\0')
			aliases_ptr++;
		/* Step over separator character. */
		while (*aliases_ptr == ' ') aliases_ptr++;
	}
	return (NSS_NOTFOUND);
}

static int
_nss_has_interfaces(boolean_t *v4, boolean_t *v6)
{
	struct ifaddrs *ifp, *i;
	struct in_addr in4;
	struct in6_addr in6;
	const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

	*v4 = *v6 = B_FALSE;

	if (getifaddrs(&ifp) != 0)
		return (-1);

	for (i = ifp; i != NULL; i = i->ifa_next) {
		if (i->ifa_flags & IFF_LOOPBACK)
			continue;
		if ((i->ifa_flags & IFF_UP) == 0)
			continue;

		if (i->ifa_addr->sa_family == AF_INET) {
			if (*v4 != B_FALSE)
				continue;

			if (((struct sockaddr_in *)i->ifa_addr)->
			    sin_addr.s_addr == INADDR_ANY)
				continue;
			*v4 = B_TRUE;
		}

		if (i->ifa_addr->sa_family == AF_INET6) {
			if (*v6 != B_FALSE)
				continue;

			if (memcmp(&in6addr_any,
			    &((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr,
			    sizeof (struct in6_addr)) == 0)
				continue;
			*v6 = B_TRUE;
		}
	}

	freeifaddrs(ifp);
	return (0);
}

/*
 * nss_dns_gethost_withttl(void *buffer, size_t bufsize, int ipnode)
 *      nss2 get hosts/ipnodes with ttl backend DNS search engine.
 *
 * This API is given a pointer to a packed buffer, and the buffer size
 * It's job is to perform the appropriate res_nsearch, extract the
 * results and build a unmarshalled hosts/ipnodes result buffer.
 * Additionally in the extended results a nssuint_t ttl is placed.
 * This ttl is the lessor of the ttl's extracted from the result.
 *
 * RETURNS:  NSS_SUCCESS or NSS_ERROR
 *	If an NSS_ERROR result is returned, nscd is expected
 *	to resubmit the gethosts request using the old style
 *	nsswitch lookup format.
 */

nss_status_t
_nss_dns_gethost_withttl(void *buffer, size_t bufsize, int ipnode)
{
	/* nss buffer variables */
	nss_pheader_t	*pbuf = (nss_pheader_t *)buffer;
	nss_XbyY_args_t	arg;
	char		*dbname;
	int		dbop;
	nss_status_t	sret;
	size_t		bsize, blen;
	char		*bptr;
	/* resolver query variables */
	struct __res_state stat, *statp;	/* dns state block */
	union msg {
		uchar_t	buf[NS_MAXMSG];		/* max legal DNS answer size */
		HEADER	h;
	} resbuf;
	char aliases[NS_MAXMSG];		/* set of aliases */
	const char	*name;
	int		qtype;
	/* answer parsing variables */
	HEADER		*hp;
	uchar_t		*cp;	/* current location in message */
	uchar_t		*bom;	/* start of message */
	uchar_t		*eom;	/* end of message */
	uchar_t		*eor;	/* end of record */
	int		ancount, qdcount;
	int		type, class;
	nssuint_t	nttl, ttl, *pttl;	/* The purpose of this API */
	int		n, ret;
	const char	*np;
	/* temporary buffers */
	char		nbuf[INET6_ADDRSTRLEN];	/* address parser */
	char		host[MAXHOSTNAMELEN];	/* result host name */
	char		ans[MAXHOSTNAMELEN];	/* record name */
	char		aname[MAXHOSTNAMELEN];	/* alias result (C_NAME) */
	/* misc variables */
	int		af;
	char		*ap, *apc;
	int		hlen = 0, alen, iplen, len, isans;
	boolean_t	has_v4 = B_FALSE, has_v6 = B_FALSE;
	int		flags, family, pass2 = 0;

	statp = &stat;
	(void) memset(statp, '\0', sizeof (struct __res_state));
	if (res_ninit(statp) == -1) {
		return (NSS_ERROR);
	}

	ap = apc = (char *)aliases;
	alen = 0;
	ttl = (nssuint_t)0xFFFFFFF;		/* start w/max, find smaller */

	/* save space for ttl otherwise, why bother... */
	bsize = pbuf->data_len - sizeof (nssuint_t);
	bptr = (char *)buffer + pbuf->data_off;
	blen = 0;
	sret = nss_packed_getkey(buffer, bufsize, &dbname, &dbop, &arg);
	if (sret != NSS_SUCCESS) {
		res_ndestroy(statp);
		return (NSS_ERROR);
	}

	/*
	 * There may be flags set when we are handling ipnode. There are three
	 * different values for flags:
	 *
	 *  o AI_V4MAPPED
	 *  o AI_ALL
	 *  o AI_ADDRCONFIG
	 *
	 * The first two only have a meaning when af_family is ipv6. The latter
	 * means something in both cases. These flags are documented in
	 * getipnodebyname(3SOCKET), though the combinations leave a little
	 * something to be desired. It would be great if we could actually use
	 * getipnodebyname directly here since it already knows how to handle
	 * this kind of logic; however, we're not quite so lucky. Ideally we
	 * would add such an interface to libresolv.so.2 to handle this kind of
	 * thing, but that's rather painful as well. We'll summarize what has to
	 * happen below:
	 *
	 * AI_ALL is only meaningful when AI_V4MAPPED is also specified. Both
	 * are ignored if the family is not AF_INET6
	 *
	 * family == AF_INET, flags | AI_ADDRCONFIG
	 *  - lookup A records iff we have v4 plumbed
	 * family == AF_INET, !(flags | AI_ADDRCONFIG)
	 *  - lookup A records
	 * family == AF_INET6, flags == 0 || flags == AI_ALL
	 *  - lookup AAAA records
	 * family == AF_INET6, flags | AI_V4MAPPED
	 *  - lookup AAAA, if none, lookup A
	 * family == AF_INET6, flags | AI_ADDRCONFIG
	 *  - lookup AAAA records if ipv6
	 * family == AF_INET6, flags | AI_V4MAPPED && flags | AI_ALL
	 *  - lookup AAAA records, lookup A records
	 * family == AF_INET6, flags | AI_V4MAPPED && flags | AI_ADDRCONFIG
	 *  - lookup AAAA records if ipv6
	 *  - If no AAAA && ipv4 exists, lookup A
	 * family == AF_INET6, flags | AI_V4MAPPED && flags | AI_ADDRCONFIG &&
	 * flags | AI_ALL
	 *  - lookup AAAA records if ipv6
	 *  - loookup A records if ipv4
	 */
	if (ipnode) {
		/* initially only handle the simple cases */
		name = arg.key.ipnode.name;
		flags = arg.key.ipnode.flags;
		family = arg.key.ipnode.af_family;
		if (flags != 0) {
			/*
			 * Figure out our first pass. We'll determine if we need
			 * to do a second pass afterwards once we successfully
			 * finish our first pass.
			 */
			if ((flags & AI_ADDRCONFIG) != 0) {
				if (_nss_has_interfaces(&has_v4, &has_v6) !=
				    0) {
					res_ndestroy(statp);
					return (NSS_ERROR);
				}
				/* Impossible situations... */
				if (family == AF_INET && has_v4 == B_FALSE) {
					res_ndestroy(statp);
					return (NSS_NOTFOUND);
				}
				if (family == AF_INET6 && has_v6 == B_FALSE &&
				    !(flags & AI_V4MAPPED)) {
					res_ndestroy(statp);
					return (NSS_NOTFOUND);
				}
				if (family == AF_INET6 && has_v6)
					qtype = T_AAAA;
				if (family == AF_INET || (family == AF_INET6 &&
				    has_v6 == B_FALSE && flags & AI_V4MAPPED))
					qtype = T_A;
			} else {
				has_v4 = has_v6 = B_TRUE;
				if (family == AF_INET6)
					qtype = T_AAAA;
				else
					qtype = T_A;
			}
		} else {
			if (family == AF_INET6)
				qtype = T_AAAA;
			else
				qtype = T_A;
		}
	} else {
		name = arg.key.name;
		qtype = T_A;
	}

searchagain:
	ret = res_nsearch(statp, name, C_IN, qtype, resbuf.buf, NS_MAXMSG);
	if (ret == -1) {
		/*
		 * We want to continue on unless we got NO_RECOVERY. Otherwise,
		 * HOST_NOT_FOUND, TRY_AGAIN, and NO_DATA all suggest to me that
		 * we should keep going.
		 */
		if (statp->res_h_errno == NO_RECOVERY) {
			/* else lookup error - handle in general code */
			res_ndestroy(statp);
			return (NSS_ERROR);
		}

		/*
		 * We found something on our first pass. Make sure that we do
		 * not clobber this information. This ultimately means that we
		 * were successful.
		 */
		if (pass2 == 2)
			goto out;

		/*
		 * If we're on the second pass (eg. we need to check both for A
		 * and AAAA records), or we were only ever doing a search for
		 * one type of record and are not supposed to do a second pass,
		 * then we need to return that we couldn't find anything to the
		 * user.
		 */
		if (pass2 == 1 || flags == 0 || family == AF_INET ||
		    (family == AF_INET6 && !(flags & AI_V4MAPPED))) {
			pbuf->p_herrno = HOST_NOT_FOUND;
			pbuf->p_status = NSS_NOTFOUND;
			pbuf->data_len = 0;
			res_ndestroy(statp);
			return (NSS_NOTFOUND);
		}

		/*
		 * If we were only requested to search for flags on an IPv6
		 * interface or we have no IPv4 interface, we stick to only
		 * doing a single pass and bail now.
		 */
		if ((flags & AI_ADDRCONFIG) && !(flags & AI_ALL) &&
		    has_v4 == B_FALSE) {
			pbuf->p_herrno = HOST_NOT_FOUND;
			pbuf->p_status = NSS_NOTFOUND;
			pbuf->data_len = 0;
			res_ndestroy(statp);
			return (NSS_NOTFOUND);
		}
		qtype = T_A;
		flags = 0;
		pass2 = 1;
		goto searchagain;
	}

	cp = resbuf.buf;
	hp = (HEADER *)&resbuf.h;
	bom = cp;
	eom = cp + ret;

	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	cp += HFIXEDSZ;
	if (qdcount != 1) {
		res_ndestroy(statp);
		return (NSS_ERROR);
	}
	n = dn_expand(bom, eom, cp, host, MAXHOSTNAMELEN);
	if (n < 0) {
		res_ndestroy(statp);
		return (NSS_ERROR);
	} else
		hlen = strlen(host);
	/* no host name is an error, return */
	if (hlen <= 0) {
		res_ndestroy(statp);
		return (NSS_ERROR);
	}
	cp += n + QFIXEDSZ;
	if (cp > eom) {
		res_ndestroy(statp);
		return (NSS_ERROR);
	}
	while (ancount-- > 0 && cp < eom && blen < bsize) {
		n = dn_expand(bom, eom, cp, ans, MAXHOSTNAMELEN);
		if (n > 0) {
			/*
			 * Check that the expanded name is either the
			 * name we asked for or a learned alias.
			 */
			if ((isans = strncasecmp(host, ans, hlen)) != 0 &&
			    (alen == 0 || name_is_alias(aliases, ans)
			    == NSS_NOTFOUND)) {
				res_ndestroy(statp);
				return (NSS_ERROR);	/* spoof? */
			}
		}
		cp += n;
		/* bounds check */
		type = ns_get16(cp);			/* type */
		cp += INT16SZ;
		class = ns_get16(cp);			/* class */
		cp += INT16SZ;
		nttl = (nssuint_t)ns_get32(cp);		/* ttl in sec */
		if (nttl < ttl)
			ttl = nttl;
		cp += INT32SZ;
		n = ns_get16(cp);			/* len */
		cp += INT16SZ;
		if (class != C_IN) {
			cp += n;
			continue;
		}
		eor = cp + n;
		if (type == T_CNAME) {
			/*
			 * The name looked up is really an alias and the
			 * canonical name should be in the RDATA.
			 * A canonical name may have several aliases but an
			 * alias should only have one canonical name.
			 * However multiple CNAMEs and CNAME chains do exist!
			 *
			 * Just error out on attempted buffer overflow exploit,
			 * generic code will syslog.
			 *
			 */
			n = dn_expand(bom, eor, cp, aname, MAXHOSTNAMELEN);
			if (n > 0 && (len = strlen(aname)) > 0) {
				if (isans == 0) { /* host matched ans. */
					/*
					 * Append host to alias list.
					 */
					if (alen + hlen + 2 > NS_MAXMSG) {
						res_ndestroy(statp);
						return (NSS_ERROR);
					}
					*apc++ = ' ';
					alen++;
					(void) strlcpy(apc, host,
					    NS_MAXMSG - alen);
					alen += hlen;
					apc += hlen;
				}
				/*
				 * Overwrite host with canonical name.
				 */
				if (strlcpy(host, aname, MAXHOSTNAMELEN) >=
				    MAXHOSTNAMELEN) {
					res_ndestroy(statp);
					return (NSS_ERROR);
				}
				hlen = len;
			}
			cp += n;
			continue;
		}
		if (type != qtype) {
			cp += n;
			continue;
		}
		/* check data size */
		if ((type == T_A && n != INADDRSZ) ||
		    (type == T_AAAA && n != IN6ADDRSZ)) {
			cp += n;
			continue;
		}
		af = (type == T_A ? AF_INET : AF_INET6);
		np = inet_ntop(af, (void *)cp, nbuf, INET6_ADDRSTRLEN);
		if (np == NULL) {
			res_ndestroy(statp);
			return (NSS_ERROR);
		}
		cp += n;
		/* append IP host aliases to results */
		iplen = strlen(np);
		/* ip <SP> hostname [<SP>][aliases] */
		len = iplen + 2 + hlen + alen;
		if (alen > 0)
			len++;
		if (blen + len > bsize) {
			res_ndestroy(statp);
			return (NSS_ERROR);
		}
		(void) strlcpy(bptr, np, bsize - blen);
		blen += iplen;
		bptr += iplen;
		*bptr++ = ' ';
		blen++;
		(void) strlcpy(bptr, host, bsize - blen);
		blen += hlen;
		bptr += hlen;
		if (alen > 0) {
			*bptr++ = ' ';
			blen++;
			(void) strlcpy(bptr, ap, bsize - blen);
			blen += alen;
			bptr += alen;
		}
		*bptr++ = '\n';
		blen++;
	}

	/* Depending on our flags we may need to go back another time. */
	if (qtype == T_AAAA && family == AF_INET6 &&
	    ((flags & AI_V4MAPPED) != 0) && ((flags & AI_ALL) != 0) &&
	    has_v4 == B_TRUE) {
		qtype = T_A;
		pass2 = 2; /* Indicate that we found data this pass */
		goto searchagain;
	}

	/* Presumably the buffer is now filled. */
	len = ROUND_UP(blen, sizeof (nssuint_t));
	/* still room? */
	if (len + sizeof (nssuint_t) > pbuf->data_len) {
		/* sigh, no, what happened? */
		res_ndestroy(statp);
		return (NSS_ERROR);
	}
out:
	pbuf->ext_off = pbuf->data_off + len;
	pbuf->ext_len = sizeof (nssuint_t);
	pbuf->data_len = blen;
	pttl = (nssuint_t *)((void *)((char *)pbuf + pbuf->ext_off));
	*pttl = ttl;
	res_ndestroy(statp);
	return (NSS_SUCCESS);
}
