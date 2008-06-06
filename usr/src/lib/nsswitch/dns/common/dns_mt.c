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
 * dns_mt.c
 *
 * This file contains all the MT related routines for the DNS backend.
 */

#include "dns_common.h"
#include <dlfcn.h>

/*
 * If the DNS name service switch routines are used in a binary that depends
 * on an older libresolv (libresolv.so.1, say), then having nss_dns.so.1 or
 * libnss_dns.a depend on a newer libresolv (libresolv.so.2) will cause
 * relocation problems. In particular, copy relocation of the _res structure
 * (which changes in size from libresolv.so.1 to libresolv.so.2) could
 * cause corruption, and result in a number of strange problems, including
 * core dumps. Hence, we check if a libresolv is already loaded.
 */

#pragma init(_nss_dns_init)
static void	_nss_dns_init(void);

extern struct hostent *res_gethostbyname(const char *);
#pragma weak	res_gethostbyname

#define		RES_SET_NO_HOSTS_FALLBACK	"__res_set_no_hosts_fallback"
extern void	__res_set_no_hosts_fallback(void);
#pragma weak	__res_set_no_hosts_fallback

#define		RES_UNSET_NO_HOSTS_FALLBACK	"__res_unset_no_hosts_fallback"
extern void	__res_unset_no_hosts_fallback(void);
#pragma weak	__res_unset_no_hosts_fallback

#define		RES_GET_RES	"__res_get_res"
extern struct __res_state	*__res_get_res(void);
#pragma weak	__res_get_res

#define		RES_ENABLE_MT			"__res_enable_mt"
extern int	__res_enable_mt(void);
#pragma weak	__res_enable_mt

#define		RES_DISABLE_MT			"__res_disable_mt"
extern int	__res_disable_mt(void);
#pragma weak	__res_disable_mt

#define		RES_GET_H_ERRNO			"__res_get_h_errno"
extern int	*__res_get_h_errno();
#pragma weak	__res_get_h_errno

#define		__H_ERRNO			"__h_errno"
extern int	*__h_errno(void);
#pragma weak	__h_errno

#define		RES_OVERRIDE_RETRY		"__res_override_retry"
extern int	__res_override_retry(int);
#pragma weak	__res_override_retry

static void	__fallback_set_no_hosts(void);
static int	*__fallback_h_errno(void);
static int	__fallback_override_retry(int);
static int	__is_mt_safe(void);

void	(*set_no_hosts_fallback)(void) = __fallback_set_no_hosts;
void	(*unset_no_hosts_fallback)(void) = __fallback_set_no_hosts;
struct __res_state	*(*set_res_retry)() = 0;
int	(*enable_mt)() = 0;
int	(*disable_mt)() = 0;
int	*(*get_h_errno)(void) = 0;
int	(*override_retry)(int) = 0;

/* Usually set from the Makefile */
#ifndef	NSS_DNS_LIBRESOLV
#define	NSS_DNS_LIBRESOLV	"libresolv.so.2"
#endif

/* From libresolv */
extern	int	h_errno;

mutex_t	one_lane = DEFAULTMUTEX;

void
_nss_dns_init(void)
{
	void		*reslib, (*f_void_ptr)();

	/* If no libresolv library, then load one */
	if (res_gethostbyname == 0) {
		if ((reslib =
		    dlopen(NSS_DNS_LIBRESOLV, RTLD_LAZY|RTLD_GLOBAL)) != 0) {
			/* Turn off /etc/hosts fall back in libresolv */
			if ((f_void_ptr = (void (*)(void))dlsym(reslib,
			    RES_SET_NO_HOSTS_FALLBACK)) != 0) {
				set_no_hosts_fallback = f_void_ptr;
			}
			if ((f_void_ptr = (void (*)(void))dlsym(reslib,
			    RES_SET_NO_HOSTS_FALLBACK)) != 0) {
				unset_no_hosts_fallback = f_void_ptr;
			}
			/* Set number of resolver retries */
			if ((override_retry = (int (*)(int))dlsym(reslib,
			    RES_OVERRIDE_RETRY)) == 0) {
				set_res_retry =
				    (struct __res_state *(*)(void))dlsym(reslib,
				    RES_GET_RES);
				override_retry = __fallback_override_retry;
			}
			/*
			 * Select h_errno retrieval function. A BIND 8.2.2
			 * libresolv.so.2 will have __h_errno, a BIND 8.1.2
			 * one will have __res_get_h_errno, and other
			 * versions may have nothing at all.
			 *
			 * Also try to bind to the relevant MT enable/disable
			 * functions which are also dependent on the version
			 * of the BIND libresolv.so.2 being used.
			 */
			if ((get_h_errno = (int *(*)(void))dlsym(reslib,
			    __H_ERRNO)) != 0) {
				/* BIND 8.2.2 libresolv.so.2 is MT safe. */
				enable_mt = __is_mt_safe;
				disable_mt = __is_mt_safe;
			} else {
				if ((get_h_errno =
				    (int *(*)(void))dlsym(reslib,
				    RES_GET_H_ERRNO)) == 0) {
					get_h_errno = __fallback_h_errno;
				}
				/*
				 * Pre-BIND 8.2.2 was not MT safe.  Try to
				 * bind the MT enable/disable functions.
				 */
				if ((enable_mt = (int (*)(void))dlsym(reslib,
				    RES_ENABLE_MT)) != 0 &&
				    (disable_mt = (int (*)(void))dlsym(reslib,
				    RES_DISABLE_MT)) == 0) {
					enable_mt = 0;
				}
			}
		}
	} else {
		/* Libresolv already loaded */
		if ((f_void_ptr = __res_set_no_hosts_fallback) != 0) {
			set_no_hosts_fallback = f_void_ptr;
		}
		if ((f_void_ptr = __res_unset_no_hosts_fallback) != 0) {
			unset_no_hosts_fallback = f_void_ptr;
		}
		if ((override_retry = __res_override_retry) == 0) {
			set_res_retry = __res_get_res;
			override_retry = __fallback_override_retry;
		}
		if ((get_h_errno = __h_errno) == 0 &&
		    (get_h_errno = __res_get_h_errno) == 0) {
			get_h_errno = __fallback_h_errno;
		}
		if (get_h_errno == __h_errno) {
			enable_mt = __is_mt_safe;
			disable_mt = __is_mt_safe;
		} else {
			if ((enable_mt = __res_enable_mt) != 0 &&
			    (disable_mt = __res_disable_mt) == 0) {
				enable_mt = 0;
			}
		}
	}
}


/*
 *
 * Integration of BIND 8.1.2 introduced two new Sun private functions,
 * __res_enable_mt() and __res_disable_mt(), that enabled and disabled
 * MT mode per-thread. These functions are in the private libresolv.so.2
 * interface, and intended for use by nss_dns.so.1.
 *
 * BIND 8.2.2 removed the need for those two functions.  As similar
 * functionality was provided in BIND further up the stack. However the
 * functions remain to satisfy any application that directly called upon
 * them.  Only, __res_enable_mt() was modified to return failure.
 * Indicated by a non-zero return value.  So that those unconventional
 * applications would not then presume that res_send() and friends are
 * MT-safe, when in fact they are not.
 *
 * To prevent nss_dns from locking inappropriately __is_mt_safe() is
 * called in place of __res_enable_mt() and __res_disable_mt() if BIND
 * 8.2.2 libresolv.so.2 being used.  __is_mt_safe() returns success
 * indicated by a return code of zero. Signifying that no locking is
 * necessary.
 *
 * MT applications making calls to gethostby*_r() or getipnodeby*()
 * linked to libresolv.so.1 or linked statically with pre-BIND 8.2.2
 * libresolv.a, doubtful as we don't ship a static version, would require
 * locking within the nsswitch back-end.  Hence the mechanism can not
 * simply be removed.
 *
 */
static int
__is_mt_safe(void) {
	return (0);
}


/*
 * Return pointer to the global h_errno variable
 */
static int *
__fallback_h_errno(void) {
	return (&h_errno);
}


/*
 * This function is called when the resolver library doesn't provide its
 * own function to establish an override retry. If we can get a pointer
 * to the per-thread _res (i.e., set_res_retry != 0), we set the retries
 * directly, and return the previous number of retries. Otherwise, there's
 * nothing to do.
 */
static int
__fallback_override_retry(int retry) {
	struct __res_state	*res;
	int			old_retry = 0;

	if (set_res_retry != 0) {
		res = set_res_retry();
		old_retry = res->retry;
		res->retry = retry;
	}
	return (old_retry);
}


static void
__fallback_set_no_hosts(void) {
}


/*
 * Common code to enable/disable MT mode, set/unset no-/etc/hosts fallback,
 * and to set the number of retries.
 */
void
switch_resolver_setup(int *mt_disabled, sigset_t *oldmask, int *old_retry) {

	/*
	 * Try to enable MT mode. If that isn't possible, mask signals,
	 * and mutex_lock.
	 */
	*mt_disabled = 1;
	if (enable_mt == 0 || (*mt_disabled = (*enable_mt)()) != 0) {
		sigset_t	newmask;
		(void) sigfillset(&newmask);
		(void) thr_sigsetmask(SIG_SETMASK, &newmask, oldmask);
		(void) mutex_lock(&one_lane);
	}

	/*
	 * Disable any fallback to /etc/hosts (or /etc/inet/ipnodes, when
	 * libresolv knows about that file).
	 */
	(*set_no_hosts_fallback)();

	/*
	 * The NS switch wants to handle retries on its own.
	 */
	*old_retry = (*override_retry)(1);
}


void
switch_resolver_reset(int mt_disabled, sigset_t oldmask, int old_retry) {

	if (mt_disabled) {
		(void) mutex_unlock(&one_lane);
		(void) thr_sigsetmask(SIG_SETMASK, &oldmask, NULL);
	} else {
		(void) (*disable_mt)();
	}

	(*unset_no_hosts_fallback)();

	(void) (*override_retry)(old_retry);
}
