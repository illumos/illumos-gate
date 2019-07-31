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
 * rpcb_stat.c
 * Allows for gathering of statistics
 *
 * Copyright (c) 1990 by Sun Microsystems, Inc.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <netconfig.h>
#include <rpc/rpc.h>
#include <rpc/rpcb_prot.h>
#include <sys/stat.h>
#ifdef PORTMAP
#include <rpc/pmap_prot.h>
#endif
#include <stdlib.h>
#include <atomic.h>
#include <assert.h>
#include <thread.h>
#include <synch.h>
#include <string.h>
#include "rpcbind.h"

static rpcb_stat_byvers inf;
static rwlock_t inf_lock = DEFAULTRWLOCK;

void
rpcbs_procinfo(int rtype, rpcproc_t proc)
{
	assert(rtype >= 0 && rtype < RPCBVERS_STAT);

#ifdef PORTMAP
	if ((rtype == RPCBVERS_2_STAT) && (proc > rpcb_highproc_2))
		return;
#else
	assert(rtype != RPCBVERS_2_STAT);
#endif

	if ((rtype == RPCBVERS_3_STAT) && (proc > rpcb_highproc_3))
		return;

	if ((rtype == RPCBVERS_4_STAT) && (proc > rpcb_highproc_4))
		return;

	atomic_add_int((uint_t *)&inf[rtype].info[proc], 1);
}

void
rpcbs_set(int rtype, bool_t success)
{
	assert(rtype >= 0 && rtype < RPCBVERS_STAT);

	if (success == FALSE)
		return;

	atomic_add_int((uint_t *)&inf[rtype].setinfo, 1);
}

void
rpcbs_unset(int rtype, bool_t success)
{
	assert(rtype >= 0 && rtype < RPCBVERS_STAT);

	if (success == FALSE)
		return;

	atomic_add_int((uint_t *)&inf[rtype].unsetinfo, 1);
}

void
rpcbs_getaddr(int rtype, rpcprog_t prog, rpcvers_t vers, char *netid,
    char *uaddr)
{
	rpcbs_addrlist *al;
	rpcbs_addrlist *s;
	rpcbs_addrlist *wal;
	struct netconfig *nconf;

	assert(rtype >= 0 && rtype < RPCBVERS_STAT);

	/*
	 * First try with read lock only.
	 */
	(void) rw_rdlock(&inf_lock);
	for (s = al = inf[rtype].addrinfo; al; al = al->next) {
		if ((al->prog == prog) && (al->vers == vers) &&
		    (strcmp(al->netid, netid) == 0)) {
			(void) rw_unlock(&inf_lock);

			if ((uaddr == NULL) || (uaddr[0] == '\0'))
				atomic_add_int((uint_t *)&al->failure, 1);
			else
				atomic_add_int((uint_t *)&al->success, 1);

			return;
		}
	}
	(void) rw_unlock(&inf_lock);

	/*
	 * If not found, we will likely need to add a new entry,
	 * so pre-allocate it, and then try to search again with write lock.
	 */
	nconf = rpcbind_get_conf(netid);
	if (nconf == NULL) {
		return;
	}

	al = (rpcbs_addrlist *) malloc(sizeof (rpcbs_addrlist));
	if (al == NULL) {
		return;
	}

	al->prog = prog;
	al->vers = vers;
	al->netid = nconf->nc_netid;
	if ((uaddr == NULL) || (uaddr[0] == '\0')) {
		al->failure = 1;
		al->success = 0;
	} else {
		al->failure = 0;
		al->success = 1;
	}

	(void) rw_wrlock(&inf_lock);
	for (wal = inf[rtype].addrinfo; wal != s; wal = wal->next) {
		if ((wal->prog == prog) && (wal->vers == vers) &&
		    (strcmp(wal->netid, netid) == 0)) {
			(void) rw_unlock(&inf_lock);

			free(al);

			if ((uaddr == NULL) || (uaddr[0] == '\0'))
				atomic_add_int((uint_t *)&wal->failure, 1);
			else
				atomic_add_int((uint_t *)&wal->success, 1);

			return;
		}
	}

	al->next = inf[rtype].addrinfo;
	inf[rtype].addrinfo = al;
	(void) rw_unlock(&inf_lock);
}

/*
 * rpcbproc - rpcbind proc number on which this was called
 */
void
rpcbs_rmtcall(int rtype, rpcproc_t rpcbproc, rpcprog_t prog, rpcvers_t vers,
    rpcproc_t proc, char *netid, rpcblist_ptr rbl)
{
	rpcbs_rmtcalllist *rl;
	rpcbs_rmtcalllist *s;
	rpcbs_rmtcalllist *wrl;
	struct netconfig *nconf;

	assert(rtype >= 0 && rtype < RPCBVERS_STAT);

	/*
	 * First try with read lock only.
	 */
	(void) rw_rdlock(&inf_lock);
	for (s = rl = inf[rtype].rmtinfo; rl; rl = rl->next) {
		if ((rl->prog == prog) && (rl->vers == vers) &&
		    (rl->proc == proc) && (strcmp(rl->netid, netid) == 0)) {
			(void) rw_unlock(&inf_lock);

			if ((rbl == NULL) || (rbl->rpcb_map.r_vers != vers))
				atomic_add_int((uint_t *)&rl->failure, 1);
			else
				atomic_add_int((uint_t *)&rl->success, 1);
			if (rpcbproc == RPCBPROC_INDIRECT)
				atomic_add_int((uint_t *)&rl->indirect, 1);

			return;
		}
	}
	(void) rw_unlock(&inf_lock);

	/*
	 * If not found, we will likely need to add a new entry,
	 * so pre-allocate it, and then try to search again with write lock.
	 */
	nconf = rpcbind_get_conf(netid);
	if (nconf == NULL) {
		return;
	}

	rl = (rpcbs_rmtcalllist *) malloc(sizeof (rpcbs_rmtcalllist));
	if (rl == NULL) {
		return;
	}

	rl->prog = prog;
	rl->vers = vers;
	rl->proc = proc;
	rl->netid = nconf->nc_netid;
	if ((rbl == NULL) || (rbl->rpcb_map.r_vers != vers)) {
		rl->failure = 1;
		rl->success = 0;
	} else {
		rl->failure = 0;
		rl->success = 1;
	}
	rl->indirect = rpcbproc == RPCBPROC_INDIRECT ? 1 : 0;

	(void) rw_wrlock(&inf_lock);
	for (wrl = inf[rtype].rmtinfo; wrl != s; wrl = wrl->next) {
		if ((wrl->prog == prog) && (wrl->vers == vers) &&
		    (wrl->proc == proc) && (strcmp(wrl->netid, netid) == 0)) {
			(void) rw_unlock(&inf_lock);

			free(rl);

			if ((rbl == NULL) || (rbl->rpcb_map.r_vers != vers))
				atomic_add_int((uint_t *)&wrl->failure, 1);
			else
				atomic_add_int((uint_t *)&wrl->success, 1);
			if (rpcbproc == RPCBPROC_INDIRECT)
				atomic_add_int((uint_t *)&wrl->indirect, 1);

			return;
		}
	}

	rl->next = inf[rtype].rmtinfo;
	inf[rtype].rmtinfo = rl;
	(void) rw_unlock(&inf_lock);
}

/* ARGSUSED */
bool_t
rpcbproc_getstat(void *argp, rpcb_stat_byvers **result)
{
	/*
	 * inf_lock is unlocked in xdr_rpcb_stat_byvers_ptr()
	 */
	(void) rw_rdlock(&inf_lock);
	*result = &inf;
	return (TRUE);
}

bool_t
xdr_rpcb_stat_byvers_ptr(XDR *xdrs, rpcb_stat_byvers **objp)
{
	if (xdrs->x_op == XDR_FREE) {
		/*
		 * inf_lock is locked in rpcbproc_getstat()
		 */
		(void) rw_unlock(&inf_lock);
		return (TRUE);
	}

	return (xdr_rpcb_stat_byvers(xdrs, (rpcb_stat *)*objp));
}
