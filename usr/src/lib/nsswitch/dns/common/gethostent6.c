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
/*
 *	gethostent6.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is the DNS backend for IPv6 addresses.
 * getbyname() is a local routine, but getbyaddr() actually shares the
 * same codes as the one in gethostent.c.
 */

#define	endhostent	res_endhostent

#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include "dns_common.h"

/*
 * If the DNS name service switch routines are used in a binary that depends
 * on an older libresolv (libresolv.so.1, say), then having nss_dns.so.1 or
 * libnss_dns.a depend on a newer libresolv (libresolv.so.2) will cause
 * relocation problems. In particular, copy relocation of the _res structure
 * (which changes in size from libresolv.so.1 to libresolv.so.2) could
 * cause corruption, and result in a number of strange problems, including
 * core dumps. Hence, we check if a libresolv is already loaded.
 */


#pragma weak	res_endhostent

extern struct hostent *_gethostbyname(int *, const char *);
extern struct hostent *_nss_dns_gethostbyname2(int *, const char *);

typedef union {
	long al;
	char ac;
} align;


static void
_endhostent(errp)
	nss_status_t	*errp;
{
	int	ret;

	ret = endhostent();
	if (ret == 0)
		*errp = NSS_SUCCESS;
	else
		*errp = NSS_UNAVAIL;
}


#ifdef	RNDUP
#undef	RNDUP
#endif
#define	RNDUP(x)	((1 + (((x)-1)/sizeof (void *))) * sizeof (void *))

#ifdef	PTROFF
#undef	PTROFF
#endif
#define	PTROFF(p, o)	(((o) == 0) ? 0 : (void *)((char *)(p) + (o)))


/*
 * Make a copy of h->h_name.
 */
static char *
cloneName(struct hostent *h, int *outerr) {

	char	*name;
	int	len;
	int	error, *errp;

	if (outerr)
		errp = outerr;
	else
		errp = &error;

	if (h == 0 || h->h_name == 0) {
		*errp = 0;
		return (0);
	}

	len = strlen(h->h_name);

	if ((name = malloc(len+1)) == 0) {
		*errp = 1;
		return (0);
	}

	(void) memcpy(name, h->h_name, len+1);

	*errp = 0;
	return (name);
}


/*
 * Copy the h->h_addr_list[] array to a new array, and append the
 * moreAddrs[] list. If h->h_addr_list[] contains IPv4 addresses,
 * convert them to v4 mapped IPv6 addresses.
 *
 * Note: The pointers to the addresses in the moreAddrs[] array are copied,
 *       but not the IP addresses themselves.
 */
static struct in6_addr **
cloneAddrList(struct hostent *h, struct in6_addr **moreAddrs, int *outerr) {

	struct in6_addr	**addrArray, *addrList;
	int		domap, addrlen, i, j, addrCount, moreAddrCount = 0;

	int	error, *errp;

	if (outerr)
		errp = outerr;
	else
		errp = &error;

	if (h == 0 || h->h_addr_list == 0) {
		*errp = 0;
		return (0);
	}

	/* Should we map v4 to IPv6 ? */
	domap = (h->h_length == sizeof (struct in_addr)) &&
		(h->h_addrtype == AF_INET);

	/* If mapping, make sure we allocate enough memory for addresses */
	addrlen = h->h_length;
	if (domap && addrlen < sizeof (struct in6_addr))
		addrlen = sizeof (struct in6_addr);

	for (addrCount = 0; h->h_addr_list[addrCount]; addrCount++);

	if (moreAddrs != 0) {
		for (moreAddrCount = 0; moreAddrs[moreAddrCount];
			moreAddrCount++);
	}

	if ((addrArray = malloc((addrCount+moreAddrCount+1)*sizeof (addrList) +
				addrCount*addrlen)) == 0) {
		*errp = 1;
		return (0);
	}

	addrList = PTROFF(addrArray, (addrCount+moreAddrCount+1) *
					sizeof (addrList));

	for (i = 0; i < addrCount; i++) {
		addrArray[i] = addrList;
		if (domap) {
			/* LINTED: E_BAD_PTR_CAST_ALIGN */
			IN6_INADDR_TO_V4MAPPED(
			(struct in_addr *)h->h_addr_list[i], addrArray[i]);
		} else {
			(void) memcpy(addrArray[i], h->h_addr_list[i],
				addrlen);
		}
		addrList = PTROFF(addrList, addrlen);
	}

	for (j = 0; j < moreAddrCount; j++, i++) {
		addrArray[i] = moreAddrs[j];
	}

	/* Last pointer should be NULL */
	addrArray[i] = 0;

	*errp = 0;
	return (addrArray);
}


/*
 * Create a new alias array that is is a copy of h->h_aliases[] plus
 * the aliases in mergeAliases[] which aren't duplicates of any alias
 * in h->h_aliases[].
 *
 * Note 1: Only the string pointers (NOT the strings) in the mergeAliases[]
 *         array are copied.
 *
 * Note 2: The duplicate aliases in mergeAliases[] are replaced by NULL
 *         pointers.
 */
static char **
cloneAliasList(struct hostent *h, char **mergeAliases, int *outerr) {

	char	**aliasArray, *aliasList;
	int	i, j, aliasCount, mergeAliasCount = 0, realMac = 0;
	int	stringSize = 0;
	int	error, *errp;

	if (outerr)
		errp = outerr;
	else
		errp = &error;


	if (h == 0 || h->h_aliases == 0) {
		*errp = 0;
		return (0);
	}

	for (aliasCount = 0; h->h_aliases[aliasCount]; aliasCount++) {
		stringSize += RNDUP(strlen(h->h_aliases[aliasCount])+1);
	}

	if (mergeAliases != 0) {
		for (; mergeAliases[mergeAliasCount]; mergeAliasCount++) {
			int	countThis = 1;
			/* Skip duplicates */
			for (j = 0; j < aliasCount; j++) {
				if (strcmp(mergeAliases[mergeAliasCount],
						h->h_aliases[j]) == 0) {
					countThis = 0;
					break;
				}
			}
			if (countThis)
				realMac++;
			else
				mergeAliases[mergeAliasCount] = 0;
		}
	}

	if ((aliasArray = malloc((aliasCount+realMac+1)*sizeof (char **)+
				stringSize)) == 0) {
		*errp = 1;
		return (0);
	}

	aliasList = PTROFF(aliasArray,
				(aliasCount+realMac+1)*sizeof (char **));
	for (i = 0; i < aliasCount; i++) {
		int	len = strlen(h->h_aliases[i]);
		aliasArray[i] = aliasList;
		(void) memcpy(aliasArray[i], h->h_aliases[i], len+1);
		aliasList = PTROFF(aliasList, RNDUP(len+1));
	}

	for (j = 0; j < mergeAliasCount; j++) {
		if (mergeAliases[j] != 0) {
			aliasArray[i++] = mergeAliases[j];
		}
	}

	aliasArray[i] = 0;

	*errp = 0;
	return (aliasArray);
}

/*ARGSUSED*/
static nss_status_t
getbyname(be, a)
	dns_backend_ptr_t	be;
	void			*a;
{
	struct hostent	*he = NULL;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	int		ret, mt_disabled;
	sigset_t	oldmask;
	int		converr = 0, gotv6 = 0;
	struct hostent	v6he;
	struct hostent	mhe;
	char		*v6Name = 0;
	struct in6_addr	**v6Addrs = 0, **mergeAddrs = 0;
	char		**v6Aliases = 0, **mergeAliases = 0;
	int		v6_h_errno;
	int		old_retry;
	int		af = argp->key.ipnode.af_family;
	int		flags = argp->key.ipnode.flags;

	switch_resolver_setup(&mt_disabled, &oldmask, &old_retry);

	/* Now get the AAAA records */
	if (af == AF_INET6)
		he = _nss_dns_gethostbyname2(&argp->h_errno,
					argp->key.ipnode.name);
	if (he != NULL) {
		/*
		 * pointer in "he" is part of a static pthread key in libresolv
		 * It should be treated as read only.
		 * So clone a copy first.
		 */
		v6Name = cloneName(he, &converr);
		if (converr) {
			argp->h_errno = HOST_NOT_FOUND;
			argp->erange = 1;
			switch_resolver_reset(mt_disabled, oldmask, old_retry);
			return (_herrno2nss(argp->h_errno));
		}
		v6Addrs = cloneAddrList(he, 0, &converr);
		if (converr) {
			if (v6Name != 0)
				free(v6Name);
			argp->h_errno = HOST_NOT_FOUND;
			argp->erange = 1;
			switch_resolver_reset(mt_disabled, oldmask, old_retry);
			return (_herrno2nss(argp->h_errno));
		}
		v6Aliases = cloneAliasList(he, 0, &converr);
		if (converr) {
			if (v6Name != 0)
				free(v6Name);
			if (v6Addrs != 0)
				free(v6Addrs);
			argp->h_errno = HOST_NOT_FOUND;
			argp->erange = 1;
			switch_resolver_reset(mt_disabled, oldmask, old_retry);
			return (_herrno2nss(argp->h_errno));
		}
		v6_h_errno = argp->h_errno;
		gotv6 = 1;
	}

	/*
	 * The conditions to search "A" records:
	 * 1. af is AF_INET
	 * 2. if af is AF_INET6
	 *    then flags are either
	 *	1) (AI_ALL | AI_V4MAPPED) or
	 *	2) AI_V4MAPPED and he == NULL
	 *	    (No V6 addresses found or no search for V6 at all)
	 */

	/* Get the A records, and store the information */
	if ((af == AF_INET) ||
	    ((af == AF_INET6) &&
		((flags & (AI_ALL | AI_V4MAPPED)) ||
		((flags & AI_V4MAPPED) && he == NULL))))
		he = _gethostbyname(&argp->h_errno, argp->key.ipnode.name);
	else
		he = NULL;

	/* Merge the results */
	if (he != NULL) {
		mhe = *he;
		mergeAddrs = cloneAddrList(he, v6Addrs, &converr);
		if (converr) {
			if (v6Name != 0)
				free(v6Name);
			if (v6Addrs != 0)
				free(v6Addrs);
			if (v6Aliases != 0)
				free(v6Aliases);
			argp->h_errno = HOST_NOT_FOUND;
			argp->erange = 1;
			switch_resolver_reset(mt_disabled, oldmask,
						old_retry);
			return (_herrno2nss(argp->h_errno));
		}
		mhe.h_addr_list = (char **)mergeAddrs;

		mergeAliases = cloneAliasList(he, v6Aliases, &converr);
		if (converr) {
			if (v6Name != 0)
				free(v6Name);
			if (v6Addrs != 0)
				free(v6Addrs);
			if (v6Aliases != 0)
				free(v6Aliases);
			if (mergeAddrs != 0)
				free(mergeAddrs);
			argp->h_errno = HOST_NOT_FOUND;
			argp->erange = 1;
			switch_resolver_reset(mt_disabled, oldmask,
						old_retry);
			return (_herrno2nss(argp->h_errno));
		}
		mhe.h_aliases = mergeAliases;

		/* reset h_length, h_addrtype */
		mhe.h_length = sizeof (struct in6_addr);
		mhe.h_addrtype = AF_INET6;
		he = &mhe;

	} else if (gotv6) {
		v6he.h_name = v6Name;
		v6he.h_length = sizeof (struct in6_addr);
		v6he.h_addrtype = AF_INET6;
		v6he.h_addr_list = (char **)v6Addrs;
		v6he.h_aliases = v6Aliases;
		he = &v6he;
		argp->h_errno = v6_h_errno;
	}

	if (he != NULL) {
		/*
		 * if asked to return data in string,
		 * convert the hostent structure into
		 * string data
		 */
		if (argp->buf.result == NULL) {
			ret = ent2str(he, a, AF_INET6);
			if (ret == NSS_STR_PARSE_SUCCESS)
				argp->returnval = argp->buf.buffer;
		} else {
			ret = ent2result(he, a, AF_INET6);
			if (ret == NSS_STR_PARSE_SUCCESS)
				argp->returnval = argp->buf.result;
		}

		if (ret != NSS_STR_PARSE_SUCCESS) {
			argp->h_errno = HOST_NOT_FOUND;
			if (ret == NSS_STR_PARSE_ERANGE) {
				argp->erange = 1;
			}
		}
	}

	if (v6Name != 0)
		free(v6Name);
	if (v6Addrs != 0)
		free(v6Addrs);
	if (v6Aliases != 0)
		free(v6Aliases);
	if (mergeAddrs != 0)
		free(mergeAddrs);
	if (mergeAliases != 0)
		free(mergeAliases);

	switch_resolver_reset(mt_disabled, oldmask, old_retry);

	return (_herrno2nss(argp->h_errno));
}


extern nss_status_t __nss_dns_getbyaddr(dns_backend_ptr_t, void *);

static nss_status_t
getbyaddr(be, a)
	dns_backend_ptr_t	be;
	void			*a;
{
	/* uses the same getbyaddr from IPv4 */
	return (__nss_dns_getbyaddr(be, a));
}


/*ARGSUSED*/
static nss_status_t
_nss_dns_getent(be, args)
	dns_backend_ptr_t	be;
	void			*args;
{
	return (NSS_UNAVAIL);
}


/*ARGSUSED*/
static nss_status_t
_nss_dns_setent(be, dummy)
	dns_backend_ptr_t	be;
	void			*dummy;
{
	/* XXXX not implemented at this point */
	return (NSS_UNAVAIL);
}


/*ARGSUSED*/
static nss_status_t
_nss_dns_endent(be, dummy)
	dns_backend_ptr_t	be;
	void			*dummy;
{
	/* XXXX not implemented at this point */
	return (NSS_UNAVAIL);
}


/*ARGSUSED*/
static nss_status_t
_nss_dns_destr(be, dummy)
	dns_backend_ptr_t	be;
	void			*dummy;
{
	nss_status_t	errp;

	if (be != 0) {
		/* === Should change to invoke ops[ENDENT] ? */
		sigset_t	oldmask, newmask;
		int		mt_disabled = 1;

		if (enable_mt == 0 || (mt_disabled = (*enable_mt)()) != 0) {
			(void) sigfillset(&newmask);
			_thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
			_mutex_lock(&one_lane);
		}

		_endhostent(&errp);

		if (mt_disabled) {
			_mutex_unlock(&one_lane);
			_thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);
		} else {
			(void) (*disable_mt)();
		}

		free(be);
	}
	return (NSS_SUCCESS);   /* In case anyone is dumb enough to check */
}



static dns_backend_op_t ipnodes_ops[] = {
	_nss_dns_destr,
	_nss_dns_endent,
	_nss_dns_setent,
	_nss_dns_getent,
	getbyname,
	getbyaddr,
};

/*ARGSUSED*/
nss_backend_t *
_nss_dns_ipnodes_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_dns_constr(ipnodes_ops,
		sizeof (ipnodes_ops) / sizeof (ipnodes_ops[0])));
}

/*
 * optional NSS2 packed backend gethostsbyipnode with ttl
 * entry point.
 *
 * Returns:
 *	NSS_SUCCESS - successful
 *	NSS_NOTFOUND - successful but nothing found
 *	NSS_ERROR - fallback to NSS backend lookup mode
 * If successful, buffer will be filled with valid data
 *
 */

/*ARGSUSED*/
nss_status_t
_nss_get_dns_ipnodes_name(dns_backend_ptr_t *be, void **bufp, size_t *sizep)
{
	return (_nss_dns_gethost_withttl(*bufp, *sizep, 1));
}
