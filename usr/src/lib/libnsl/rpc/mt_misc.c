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
 *	Define and initialize MT data for libnsl.
 *	The _libnsl_lock_init() function below is the library's .init handler.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <unistd.h>
#include <rpc/rpc.h>
#include <sys/time.h>
#include <stdlib.h>
#include <syslog.h>

extern	mutex_t	_ti_userlock;

sigset_t fillset;		/* from sigfillset() */

rwlock_t	svc_lock;	/* protects the services list (svc.c) */
rwlock_t	svc_fd_lock;	/* protects svc_fdset and the xports[] array */
rwlock_t	rpcbaddr_cache_lock; /* protects the RPCBIND address cache */
static rwlock_t	*rwlock_table[] = {
	&svc_lock,
	&svc_fd_lock,
	&rpcbaddr_cache_lock
};

mutex_t	authdes_lock;		/* protects authdes cache (svcauth_des.c) */
mutex_t	authnone_lock;		/* auth_none.c serialization */
mutex_t	authsvc_lock;		/* protects the Auths list (svc_auth.c) */
mutex_t	clntraw_lock;		/* clnt_raw.c serialization */
mutex_t	dname_lock;		/* domainname and domain_fd (getdname.c) */
				/*	and default_domain (rpcdname.c) */
mutex_t	dupreq_lock;		/* dupreq variables (svc_dg.c) */
mutex_t	keyserv_lock;		/* protects first_time and hostname */
				/*	(key_call.c) */
mutex_t	libnsl_trace_lock;	/* serializes rpc_trace() (rpc_trace.c) */
mutex_t	loopnconf_lock;		/* loopnconf (rpcb_clnt.c) */
mutex_t	ops_lock;		/* serializes ops initializations */
mutex_t	portnum_lock;		/* protects ``port'' static in bindresvport() */
mutex_t	proglst_lock;		/* protects proglst list (svc_simple.c) */
mutex_t	rpcsoc_lock;		/* serializes clnt_com_create() (rpc_soc.c) */
mutex_t	svcraw_lock;		/* svc_raw.c serialization */
mutex_t	xprtlist_lock;		/* xprtlist (svc_generic.c) */
mutex_t serialize_pkey;		/* serializes calls to public key routines */
mutex_t	svc_thr_mutex;		/* protects thread related variables */
mutex_t	svc_mutex;		/* protects service handle free lists */
mutex_t	svc_exit_mutex;		/* used for clean mt exit */

static mutex_t	*mutex_table[] = {
	&authdes_lock,
	&authnone_lock,
	&authsvc_lock,
	&clntraw_lock,
	&dname_lock,
	&dupreq_lock,
	&keyserv_lock,
	&libnsl_trace_lock,
	&loopnconf_lock,
	&ops_lock,
	&portnum_lock,
	&proglst_lock,
	&rpcsoc_lock,
	&svcraw_lock,
	&xprtlist_lock,
	&serialize_pkey,
	&svc_thr_mutex,
	&svc_mutex,
	&svc_exit_mutex
};

cond_t	svc_thr_fdwait;		/* threads wait on this for work */

static void
_libnsl_prefork()
{
	(void) mutex_lock(&_ti_userlock);
}

static void
_libnsl_child_atfork()
{
	(void) mutex_unlock(&_ti_userlock);
}

static void
_libnsl_parent_atfork()
{
	(void) mutex_unlock(&_ti_userlock);
}

#pragma init(_libnsl_lock_init)

void
_libnsl_lock_init()
{
	int	i;

	(void) sigfillset(&fillset);

	for (i = 0; i <  (sizeof (mutex_table) / sizeof (mutex_table[0])); i++)
		(void) mutex_init(mutex_table[i], 0, (void *) 0);

	for (i = 0; i < (sizeof (rwlock_table) / sizeof (rwlock_table[0])); i++)
		(void) rwlock_init(rwlock_table[i], 0, (void *) 0);

	(void) cond_init(&svc_thr_fdwait, USYNC_THREAD, 0);

	/*
	 * There is no way to unregister these atfork functions,
	 * but we don't need to.  The dynamic linker and libc take
	 * care of unregistering them if/when the library is unloaded.
	 */
	(void) pthread_atfork(_libnsl_prefork,
		_libnsl_parent_atfork, _libnsl_child_atfork);
}

#pragma fini(_libnsl_fini)

void _key_call_fini(void);

void
_libnsl_fini()
{
	_key_call_fini();
}

#undef	rpc_createerr

struct rpc_createerr rpc_createerr;

struct rpc_createerr *
__rpc_createerr()
{
	static pthread_key_t rce_key = PTHREAD_ONCE_KEY_NP;
	struct rpc_createerr *rce_addr;

	if (thr_main())
		return (&rpc_createerr);
	rce_addr = thr_get_storage(&rce_key, sizeof (*rce_addr), free);
	if (rce_addr == NULL) {
		syslog(LOG_ERR, "__rpc_createerr : out of memory.");
		return (&rpc_createerr);
	}
	return (rce_addr);
}

#undef rpc_callerr

struct rpc_err rpc_callerr;

struct rpc_err *
__rpc_callerr(void)
{
	static pthread_key_t rpc_callerr_key = PTHREAD_ONCE_KEY_NP;
	struct rpc_err *tsd;

	if (thr_main())
		return (&rpc_callerr);
	tsd = thr_get_storage(&rpc_callerr_key, sizeof (struct rpc_err), free);
	if (tsd == NULL) {
		syslog(LOG_ERR, "__rpc_callerr : out of memory.");
		return (&rpc_callerr);
	}
	return (tsd);
}
