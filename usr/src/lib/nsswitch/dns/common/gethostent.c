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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * gethostent.c
 *
 * In order to avoid duplicating libresolv code here, and since libresolv.so.2
 * provides res_-equivalents of the getXbyY and {set,get}Xent, lets call
 * re_gethostbyaddr() and so on from this file. Among other things, this
 * should help us avoid problems like the one described in bug 1264386,
 * where the internal getanswer() acquired new functionality in BIND 4.9.3,
 * but the local copy of getanswer() in this file wasn't updated, so that new
 * functionality wasn't available to the name service switch.
 */

#define	gethostbyaddr	res_gethostbyaddr
#define	gethostbyname	res_gethostbyname
#define	gethostbyname2	res_gethostbyname2
#define	sethostent	res_sethostent
#define	endhostent	res_endhostent

#include "dns_common.h"

extern char *inet_ntoa(struct in_addr in);

struct hostent *_gethostbyname(int *h_errnop, const char *name);
static struct hostent *_gethostbyaddr(int *h_errnop, const char *addr,
    int len, int type);
struct hostent *_nss_dns_gethostbyname2(int *h_errnop, const char *name);

#pragma weak	res_gethostbyname
#pragma weak	res_gethostbyname2
#pragma weak	res_gethostbyaddr
#pragma weak	res_sethostent
#pragma weak	res_endhostent

nss_backend_t *_nss_dns_constr(dns_backend_op_t ops[], int n_ops);
nss_status_t __nss_dns_getbyaddr(dns_backend_ptr_t, void *);

typedef union {
	long al;
	char ac;
} align;

/*
 * Internet Name Domain Server (DNS) only implementation.
 */
static struct hostent *
_gethostbyaddr(int *h_errnop, const char *addr, int len, int type)
{
	struct hostent	*hp;

	hp = gethostbyaddr(addr, len, type);
	*h_errnop = *get_h_errno();
	return (hp);
}

struct hostent *
_nss_dns_gethostbyname2(int *h_errnop, const char *name)
{
	struct hostent *hp;

	hp = gethostbyname2(name, AF_INET6);
	*h_errnop = *get_h_errno();
	return (hp);
}

struct hostent *
_gethostbyname(int *h_errnop, const char *name)
{
	struct hostent *hp;

	hp = gethostbyname(name);
	*h_errnop = *get_h_errno();
	return (hp);
}

static void
_sethostent(errp, stayopen)
	nss_status_t	*errp;
	int		stayopen;
{
	int	ret;

	ret = sethostent(stayopen);
	if (ret == 0)
		*errp = NSS_SUCCESS;
	else
		*errp = NSS_UNAVAIL;
}

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


/*ARGSUSED*/
static nss_status_t
getbyname(be, a)
	dns_backend_ptr_t	be;
	void			*a;
{
	struct hostent	*he;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	int		ret, mt_disabled;
	int		old_retry;
	sigset_t	oldmask;

	switch_resolver_setup(&mt_disabled, &oldmask, &old_retry);

	he = _gethostbyname(&argp->h_errno, argp->key.name);
	if (he != NULL) {
		if (argp->buf.result == NULL) {
			/*
			 * if asked to return data in string,
			 * convert the hostent structure into
			 * string data
			 */
			ret = ent2str(he, a, AF_INET);
			if (ret == NSS_STR_PARSE_SUCCESS)
				argp->returnval = argp->buf.buffer;
		} else {
			ret = ent2result(he, a, AF_INET);
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

	switch_resolver_reset(mt_disabled, oldmask, old_retry);

	return (_herrno2nss(argp->h_errno));
}



/*ARGSUSED*/
static nss_status_t
getbyaddr(be, a)
	dns_backend_ptr_t	be;
	void			*a;
{
	return (__nss_dns_getbyaddr(be, a));
}


/*
 * Exposing a DNS backend specific interface so that it doesn't conflict
 * with other getbyaddr() routines from other switch backends.
 */
/*ARGSUSED*/
nss_status_t
__nss_dns_getbyaddr(be, a)
	dns_backend_ptr_t	be;
	void			*a;
{
	struct hostent	*he;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	int		ret, mt_disabled;
	struct in_addr	unmapv4;
	sigset_t	oldmask;
	int		af, addrlen;
	void		*addrp;
	int		old_retry;

	switch_resolver_setup(&mt_disabled, &oldmask, &old_retry);

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)argp->key.hostaddr.addr)) {
		addrp = &unmapv4;
		addrlen = sizeof (unmapv4);
		af = AF_INET;
		(void) memcpy(addrp, &argp->key.hostaddr.addr[12], addrlen);
	} else {
		addrp = (void *)argp->key.hostaddr.addr;
		addrlen = argp->key.hostaddr.len;
		af = argp->key.hostaddr.type;
	}
	he = _gethostbyaddr(&argp->h_errno, addrp, addrlen, af);

	if (he != NULL) {
		/*
		 * if asked to return data in string, convert
		 * the hostent structure into string data
		 */
		if (argp->buf.result == NULL)
			ret = ent2str(he, a, argp->key.hostaddr.type);
		else
			ret = ent2result(he, a, argp->key.hostaddr.type);

		if (ret == NSS_STR_PARSE_SUCCESS) {
			if (argp->buf.result == NULL)
				argp->returnval = argp->buf.buffer;
			else
				argp->returnval = argp->buf.result;
		} else {
			argp->h_errno = HOST_NOT_FOUND;
			if (ret == NSS_STR_PARSE_ERANGE)
				argp->erange = 1;
		}
	}

	switch_resolver_reset(mt_disabled, oldmask, old_retry);

	return (_herrno2nss(argp->h_errno));
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
	nss_status_t	errp;

	sigset_t	oldmask, newmask;
	int		mt_disabled = 1;

	/*
	 * Try to enable MT; if not, we have to single-thread libresolv
	 * access
	 */
	if (enable_mt == 0 || (mt_disabled = (*enable_mt)()) != 0) {
		(void) sigfillset(&newmask);
		(void) thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
		(void) mutex_lock(&one_lane);
	}

	_sethostent(&errp, 1);

	if (mt_disabled) {
		(void) mutex_unlock(&one_lane);
		(void) thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);
	} else {
		(void) (*disable_mt)();
	}

	return (errp);
}


/*ARGSUSED*/
static nss_status_t
_nss_dns_endent(be, dummy)
	dns_backend_ptr_t	be;
	void			*dummy;
{
	nss_status_t	errp;

	sigset_t	oldmask, newmask;
	int		mt_disabled = 1;

	/*
	 * Try to enable MT; if not, we have to single-thread libresolv
	 * access
	 */
	if (enable_mt == 0 || (mt_disabled = (*enable_mt)()) != 0) {
		(void) sigfillset(&newmask);
		(void) thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
		(void) mutex_lock(&one_lane);
	}

	_endhostent(&errp);

	if (mt_disabled) {
		(void) mutex_unlock(&one_lane);
		(void) thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);
	} else {
		(void) (*disable_mt)();
	}

	return (errp);
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
			(void) thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
			(void) mutex_lock(&one_lane);
		}

		_endhostent(&errp);

		if (mt_disabled) {
			(void) mutex_unlock(&one_lane);
			(void) thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);
		} else {
			(void) (*disable_mt)();
		}

		free(be);
	}
	return (NSS_SUCCESS);   /* In case anyone is dumb enough to check */
}


static dns_backend_op_t host_ops[] = {
	_nss_dns_destr,
	_nss_dns_endent,
	_nss_dns_setent,
	_nss_dns_getent,
	getbyname,
	getbyaddr,
};

/*ARGSUSED*/
nss_backend_t *
_nss_dns_hosts_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_dns_constr(host_ops,
		sizeof (host_ops) / sizeof (host_ops[0])));
}

/*
 * optional NSS2 packed backend gethostsbyname with ttl
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
_nss_get_dns_hosts_name(dns_backend_ptr_t *be, void **bufp, size_t *sizep)
{
	return (_nss_dns_gethost_withttl(*bufp, *sizep, 0));
}
