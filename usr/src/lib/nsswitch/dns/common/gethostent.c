/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1993, 1998-2000 by Sun Microsystems, Inc.
 * All rights reserved.
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
		ret = ent2result(he, a, AF_INET);
		if (ret == NSS_STR_PARSE_SUCCESS) {
			argp->returnval = argp->buf.result;
		} else {
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
nss_status_t
__nss_dns_getbyaddr(be, a)
	dns_backend_ptr_t	be;
	void			*a;
{
	size_t	n;
	struct hostent	*he, *he2;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	int		ret, save_h_errno, mt_disabled;
	char		**ans, hbuf[MAXHOSTNAMELEN];
	char		dst[INET6_ADDRSTRLEN];
	struct in_addr	unmapv4;
	sigset_t	oldmask;
	int		af, addrlen;
	void		*addrp;
	int		old_retry;

	switch_resolver_setup(&mt_disabled, &oldmask, &old_retry);

	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)argp->key.hostaddr.addr)) {
		addrp = &unmapv4;
		addrlen = sizeof (unmapv4);
		af = AF_INET;
		memcpy(addrp, &argp->key.hostaddr.addr[12], addrlen);
	} else {
		addrp = (void *)argp->key.hostaddr.addr;
		addrlen = argp->key.hostaddr.len;
		af = argp->key.hostaddr.type;
	}
	he = _gethostbyaddr(&argp->h_errno, addrp, addrlen, af);

	if (he != NULL) {
		if (strlen(he->h_name) >= MAXHOSTNAMELEN)
			ret = NSS_STR_PARSE_ERANGE;
		else {
			/* save a copy of the (alleged) hostname */
			(void) strcpy(hbuf, he->h_name);
			n = strlen(hbuf);
			if (n < MAXHOSTNAMELEN-1 && hbuf[n-1] != '.') {
				(void) strcat(hbuf, ".");
			}
			ret = ent2result(he, a, argp->key.hostaddr.type);
			save_h_errno = argp->h_errno;
		}
		if (ret == NSS_STR_PARSE_SUCCESS) {
			/*
			 * check to make sure by doing a forward query
			 * We use _gethostbyname() to avoid the stack, and
			 * then we throw the result from argp->h_errno away,
			 * becase we don't care.  And besides you want the
			 * return code from _gethostbyaddr() anyway.
			 */

			if (af == AF_INET)
				he2 = _gethostbyname(&argp->h_errno, hbuf);
			else
				he2 = _nss_dns_gethostbyname2(&argp->h_errno,
					hbuf);
			if (he2 != (struct hostent *)NULL) {

				/* until we prove name and addr match */
				argp->h_errno = HOST_NOT_FOUND;
				for (ans = he2->h_addr_list; *ans; ans++)
					if (memcmp(*ans, addrp,	addrlen) ==
						0) {
					argp->h_errno = save_h_errno;
					argp->returnval = argp->buf.result;
					break;
						}
			} else {

				/*
				 * What to do if _gethostbyname() fails ???
				 * We assume they are doing something stupid
				 * like registering addresses but not names
				 * (some people actually think that provides
				 * some "security", through obscurity).  So for
				 * these poor lost souls, because we can't
				 * PROVE spoofing and because we did try (and
				 * we don't want a bug filed on this), we let
				 * this go.  And return the name from byaddr.
				 */
				argp->h_errno = save_h_errno;
				argp->returnval = argp->buf.result;
			}
			/* we've been spoofed, make sure to log it. */
			if (argp->h_errno == HOST_NOT_FOUND) {
				if (argp->key.hostaddr.type == AF_INET)
		syslog(LOG_NOTICE, "gethostbyaddr: %s != %s",
		hbuf, inet_ntoa(*(struct in_addr *)argp->key.hostaddr.addr));
				else
		syslog(LOG_NOTICE, "gethostbyaddr: %s != %s",
		hbuf, inet_ntop(AF_INET6, (void *) argp->key.hostaddr.addr,
		dst, sizeof (dst)));
			}
		} else {
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
		_thr_sigsetmask(SIG_SETMASK, &newmask, &oldmask);
		_mutex_lock(&one_lane);
	}

	_sethostent(&errp, 1);

	if (mt_disabled) {
		_mutex_unlock(&one_lane);
		_thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);
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
