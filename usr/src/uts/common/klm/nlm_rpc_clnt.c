/*
 * Copyright (c) 2008 Isilon Inc http://www.isilon.com/
 * Authors: Doug Rabson <dfr@rabson.org>
 * Developed with Red Inc: Alfred Perlstein <alfred@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Client-side RPC wrappers (nlm_..._rpc)
 * Called from nlm_client.c
 *
 * Source code derived from FreeBSD nlm_advlock.c
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/flock.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/queue.h>

#include <rpcsvc/nlm_prot.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>

#include "nlm_impl.h"

static void
nlm_convert_to_nlm_lock(struct nlm_lock *dst, struct nlm4_lock *src)
{
	dst->caller_name = src->caller_name;
	dst->fh = src->fh;
	dst->oh = src->oh;
	dst->svid = src->svid;
	dst->l_offset = src->l_offset;
	dst->l_len = src->l_len;
}

static void
nlm_convert_to_nlm4_holder(struct nlm4_holder *dst, struct nlm_holder *src)
{
	dst->exclusive = src->exclusive;
	dst->svid = src->svid;
	dst->oh = src->oh;
	dst->l_offset = src->l_offset;
	dst->l_len = src->l_len;
}

static void
nlm_convert_to_nlm4_res(struct nlm4_res *dst, struct nlm_res *src)
{
	dst->cookie = src->cookie;
	dst->stat.stat = (enum nlm4_stats) src->stat.stat;
}

enum clnt_stat
nlm_test_rpc(nlm4_testargs *args, nlm4_testres *res,
    CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS) {
		return (nlm4_test_4(args, res, client));
	} else {
		nlm_testargs args1;
		nlm_testres res1;
		enum clnt_stat stat;

		args1.cookie = args->cookie;
		args1.exclusive = args->exclusive;
		nlm_convert_to_nlm_lock(&args1.alock, &args->alock);
		(void) memset(&res1, 0, sizeof (res1));

		stat = nlm_test_1(&args1, &res1, client);

		if (stat == RPC_SUCCESS) {
			res->cookie = res1.cookie;
			res->stat.stat = (enum nlm4_stats) res1.stat.stat;
			if (res1.stat.stat == nlm_denied)
				nlm_convert_to_nlm4_holder(
				    &res->stat.nlm4_testrply_u.holder,
				    &res1.stat.nlm_testrply_u.holder);
		}

		return (stat);
	}
}

enum clnt_stat
nlm_lock_rpc(nlm4_lockargs *args, nlm4_res *res,
    CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS) {
		return (nlm4_lock_4(args, res, client));
	} else {
		nlm_lockargs args1;
		nlm_res res1;
		enum clnt_stat stat;

		args1.cookie = args->cookie;
		args1.block = args->block;
		args1.exclusive = args->exclusive;
		nlm_convert_to_nlm_lock(&args1.alock, &args->alock);
		args1.reclaim = args->reclaim;
		args1.state = args->state;
		(void) memset(&res1, 0, sizeof (res1));

		stat = nlm_lock_1(&args1, &res1, client);

		if (stat == RPC_SUCCESS) {
			nlm_convert_to_nlm4_res(res, &res1);
		}

		return (stat);
	}
}

enum clnt_stat
nlm_cancel_rpc(nlm4_cancargs *args, nlm4_res *res,
    CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS) {
		return (nlm4_cancel_4(args, res, client));
	} else {
		nlm_cancargs args1;
		nlm_res res1;
		enum clnt_stat stat;

		args1.cookie = args->cookie;
		args1.block = args->block;
		args1.exclusive = args->exclusive;
		nlm_convert_to_nlm_lock(&args1.alock, &args->alock);
		(void) memset(&res1, 0, sizeof (res1));

		stat = nlm_cancel_1(&args1, &res1, client);

		if (stat == RPC_SUCCESS) {
			nlm_convert_to_nlm4_res(res, &res1);
		}

		return (stat);
	}
}

enum clnt_stat
nlm_unlock_rpc(nlm4_unlockargs *args, nlm4_res *res,
    CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS) {
		return (nlm4_unlock_4(args, res, client));
	} else {
		nlm_unlockargs args1;
		nlm_res res1;
		enum clnt_stat stat;

		args1.cookie = args->cookie;
		nlm_convert_to_nlm_lock(&args1.alock, &args->alock);
		(void) memset(&res1, 0, sizeof (res1));

		stat = nlm_unlock_1(&args1, &res1, client);

		if (stat == RPC_SUCCESS) {
			nlm_convert_to_nlm4_res(res, &res1);
		}

		return (stat);
	}
}

enum clnt_stat
nlm_null_rpc(CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS)
		return (nlm4_null_4(NULL, NULL, client));

	return (nlm_null_1(NULL, NULL, client));
}

/*
 * Share reservations
 */

static void
nlm_convert_to_nlm_share(struct nlm_share *dst, struct nlm4_share *src)
{

	dst->caller_name = src->caller_name;
	dst->fh = src->fh;
	dst->oh = src->oh;
	dst->mode = src->mode;
	dst->access = src->access;
}

static void
nlm_convert_to_nlm4_shres(struct nlm4_shareres *dst,
	struct nlm_shareres *src)
{
	dst->cookie = src->cookie;
	dst->stat = (enum nlm4_stats) src->stat;
	dst->sequence = src->sequence;
}


enum clnt_stat
nlm_share_rpc(nlm4_shareargs *args, nlm4_shareres *res,
    CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS) {
		return (nlm4_share_4(args, res, client));
	} else {
		nlm_shareargs args3;
		nlm_shareres res3;
		enum clnt_stat stat;

		args3.cookie = args->cookie;
		nlm_convert_to_nlm_share(&args3.share, &args->share);
		args3.reclaim = args->reclaim;
		(void) memset(&res3, 0, sizeof (res3));

		stat = nlm_share_3(&args3, &res3, client);

		if (stat == RPC_SUCCESS) {
			nlm_convert_to_nlm4_shres(res, &res3);
		}

		return (stat);
	}
}

enum clnt_stat
nlm_unshare_rpc(nlm4_shareargs *args, nlm4_shareres *res,
    CLIENT *client, rpcvers_t vers)
{
	if (vers == NLM4_VERS) {
		return (nlm4_unshare_4(args, res, client));
	} else {
		nlm_shareargs args3;
		nlm_shareres res3;
		enum clnt_stat stat;

		args3.cookie = args->cookie;
		nlm_convert_to_nlm_share(&args3.share, &args->share);
		args3.reclaim = args->reclaim;
		(void) memset(&res3, 0, sizeof (res3));

		stat = nlm_unshare_3(&args3, &res3, client);

		if (stat == RPC_SUCCESS) {
			nlm_convert_to_nlm4_shres(res, &res3);
		}

		return (stat);
	}
}
