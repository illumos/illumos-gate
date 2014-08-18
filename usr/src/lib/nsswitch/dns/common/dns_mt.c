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
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

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

#define	RES_SET_NO_HOSTS_FALLBACK	"__joy_res_set_no_hosts_fallback"
extern void	__joy_res_set_no_hosts_fallback(void);

#define	RES_UNSET_NO_HOSTS_FALLBACK	"__joy_res_unset_no_hosts_fallback"
extern void	__joy_res_unset_no_hosts_fallback(void);

#define		RES_GET_RES	"__res_get_res"
extern struct __res_state	*__res_get_res(void);

#define		RES_ENABLE_MT			"__res_enable_mt"
extern int	__res_enable_mt(void);

#define		RES_DISABLE_MT			"__res_disable_mt"
extern int	__res_disable_mt(void);

#define		RES_GET_H_ERRNO			"__res_get_h_errno"
extern int	*__res_get_h_errno();

#define		__H_ERRNO			"__joy_h_errno"
extern int	*__joy_h_errno(void);

#define		RES_OVERRIDE_RETRY		"__joy_res_override_retry"
extern int	__joy_res_override_retry(int);

static void	__fallback_set_no_hosts(void);
static int	__is_mt_safe(void);

void	(*set_no_hosts_fallback)(void) = __fallback_set_no_hosts;
void	(*unset_no_hosts_fallback)(void) = __fallback_set_no_hosts;
struct __res_state	*(*set_res_retry)() = 0;
int	(*enable_mt)() = __is_mt_safe;
int	(*disable_mt)() = __is_mt_safe;
int	*(*get_h_errno)(void) = __joy_h_errno;
int	(*override_retry)(int) = __joy_res_override_retry;

/* Usually set from the Makefile */
#ifndef	NSS_DNS_LIBRESOLV
#define	NSS_DNS_LIBRESOLV	"libresolv.so.2"
#endif

/* From libresolv */
extern	int	h_errno;

mutex_t	one_lane = DEFAULTMUTEX;

/* Because we link against libresolv_joy.so.2, this is relatively easy. */
void
_nss_dns_init(void)
{
	enable_mt = __is_mt_safe;
	disable_mt = __is_mt_safe;
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
