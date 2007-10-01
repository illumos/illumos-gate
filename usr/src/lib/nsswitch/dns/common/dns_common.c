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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	dns_common.c
 */

#include "dns_common.h"

#pragma weak	dn_expand
#pragma weak	res_ninit
#pragma weak	res_nsearch
#pragma weak	res_nclose
#pragma weak	ns_get16
#pragma weak	ns_get32
#pragma weak	__ns_get16
#pragma weak	__ns_get32

#define	DNS_ALIASES	0
#define	DNS_ADDRLIST	1
#define	DNS_MAPDLIST	2

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
 * __res_ndestroy is a simplified version of the non-public function
 * res_ndestroy in libresolv.so.2. Before res_ndestroy can be made
 * public, __res_ndestroy will be used to make sure the memory pointed
 * by statp->_u._ext.ext is freed after res_nclose() is called.
 */
static void
__res_ndestroy(res_state statp) {
	res_nclose(statp);
	if (statp->_u._ext.ext != NULL)
		free(statp->_u._ext.ext);
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
 * ***Currently the first version of this API only performs simple
 *    single res_nsearch lookups for with T_A or T_AAAA results.
 *    Other searches are deferred to the generic API w/t ttls.
 *
 *    This function is not a generic res_* operation.  It only performs
 *    a single T_A or T_AAAA lookups***
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
	int		hlen = 0, alen, iplen, len;

	statp = &stat;
	(void) memset(statp, '\0', sizeof (struct __res_state));
	if (res_ninit(statp) == -1)
		return (NSS_ERROR);

	ap = apc = (char *)aliases;
	alen = 0;
	ttl = (nssuint_t)0xFFFFFFF;		/* start w/max, find smaller */

	/* save space for ttl otherwise, why bother... */
	bsize = pbuf->data_len - sizeof (nssuint_t);
	bptr = (char *)buffer + pbuf->data_off;
	blen = 0;
	sret = nss_packed_getkey(buffer, bufsize, &dbname, &dbop, &arg);
	if (sret != NSS_SUCCESS) {
		__res_ndestroy(statp);
		return (NSS_ERROR);
	}

	if (ipnode) {
		/* initially only handle the simple cases */
		if (arg.key.ipnode.flags != 0) {
			__res_ndestroy(statp);
			return (NSS_ERROR);
		}
		name = arg.key.ipnode.name;
		if (arg.key.ipnode.af_family == AF_INET6)
			qtype = T_AAAA;
		else
			qtype = T_A;
	} else {
		name = arg.key.name;
		qtype = T_A;
	}
	ret = res_nsearch(statp, name, C_IN, qtype, resbuf.buf, NS_MAXMSG);
	if (ret == -1) {
		if (statp->res_h_errno == HOST_NOT_FOUND) {
			pbuf->p_herrno = HOST_NOT_FOUND;
			pbuf->p_status = NSS_NOTFOUND;
			pbuf->data_len = 0;
			__res_ndestroy(statp);
			return (NSS_NOTFOUND);
		}
		/* else lookup error - handle in general code */
		__res_ndestroy(statp);
		return (NSS_ERROR);
	}

	cp = resbuf.buf;
	hp = (HEADER *)&resbuf.h;
	bom = cp;
	eom = cp + ret;

	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	cp += HFIXEDSZ;
	if (qdcount != 1) {
		__res_ndestroy(statp);
		return (NSS_ERROR);
	}
	n = dn_expand(bom, eom, cp, host, MAXHOSTNAMELEN);
	if (n < 0) {
		__res_ndestroy(statp);
		return (NSS_ERROR);
	} else
		hlen = strlen(host);
	/* no host name is an error, return */
	if (hlen <= 0) {
		__res_ndestroy(statp);
		return (NSS_ERROR);
	}
	cp += n + QFIXEDSZ;
	if (cp > eom) {
		__res_ndestroy(statp);
		return (NSS_ERROR);
	}
	while (ancount-- > 0 && cp < eom && blen < bsize) {
		n = dn_expand(bom, eom, cp, ans, MAXHOSTNAMELEN);
		if (n > 0) {
			if (strncasecmp(host, ans, hlen) != 0) {
				__res_ndestroy(statp);
				return (NSS_ERROR);	/* spoof? */
			}
		}
		cp += n;
		/* bounds check */
		type = ns_get16(cp);			/* type */
		cp += INT16SZ;
		class = ns_get16(cp);			/* class */
		cp += INT16SZ;
		nttl = (nssuint_t)ns_get32(cp);	/* ttl in sec */
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
			/* add an alias to the alias list */
			n = dn_expand(bom, eor, cp, aname, MAXHOSTNAMELEN);
			if (n > 0) {
				len = strlen(aname);
				if (len > 0) {
					/*
					 * Just error out if there is an
					 * attempted buffer overflow exploit
					 * generic code will do a syslog
					 */
					if (alen + len + 2 > NS_MAXMSG) {
						__res_ndestroy(statp);
						return (NSS_ERROR);
					}
					*apc++ = ' ';
					alen++;
					(void) strlcpy(apc, aname, len + 1);
					alen += len;
					apc += len;
				}
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
			__res_ndestroy(statp);
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
			__res_ndestroy(statp);
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
	/* Presumably the buffer is now filled. */
	len = ROUND_UP(blen, sizeof (nssuint_t));
	/* still room? */
	if (len + sizeof (nssuint_t) > pbuf->data_len) {
		/* sigh, no, what happened? */
		__res_ndestroy(statp);
		return (NSS_ERROR);
	}
	pbuf->ext_off = pbuf->data_off + len;
	pbuf->ext_len = sizeof (nssuint_t);
	pbuf->data_len = blen;
	pttl = (nssuint_t *)((void *)((char *)pbuf + pbuf->ext_off));
	*pttl = ttl;
	__res_ndestroy(statp);
	return (NSS_SUCCESS);
}
