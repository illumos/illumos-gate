/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file transport.c
 * Oracle elects to have and use the contents of transport.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <sys/ksynch.h>
#include <sys/list.h>
#include <sys/rds.h>
#include <sys/sysmacros.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/loop.h>
#include <sys/ib/clients/rdsv3/rdsv3_impl.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

struct rdsv3_transport *transports[RDS_TRANS_COUNT];
krwlock_t		trans_sem; /* this was a semaphore */

int
rdsv3_trans_register(struct rdsv3_transport *trans)
{
	RDSV3_DPRINTF4("rdsv3_trans_register", "Enter(trans: %p)", trans);

	rw_enter(&trans_sem, RW_WRITER);

	if (transports[trans->t_type]) {
		cmn_err(CE_WARN,
		    "RDSV3 Transport type %d already registered\n",
		    trans->t_type);
		rw_exit(&trans_sem);
		return (1);
	} else {
		transports[trans->t_type] = trans;
		RDSV3_DPRINTF2("rdsv3_trans_register",
		    "Registered RDS/%s transport\n", trans->t_name);
	}

	rw_exit(&trans_sem);

	RDSV3_DPRINTF4("rdsv3_trans_register", "Return(trans: %p)", trans);

	return (0);
}

void
rdsv3_trans_unregister(struct rdsv3_transport *trans)
{
	RDSV3_DPRINTF4("rdsv3_trans_register", "Enter(trans: %p)", trans);

	rw_enter(&trans_sem, RW_WRITER);

	transports[trans->t_type] = NULL;

	rw_exit(&trans_sem);

	RDSV3_DPRINTF4("rdsv3_trans_register", "Return(trans: %p)", trans);
}

struct rdsv3_transport *
rdsv3_trans_get_preferred(uint32_be_t addr)
{
	struct rdsv3_transport *ret = NULL;
	int i;

	RDSV3_DPRINTF4("rdsv3_trans_get_preferred", "Enter(addr: %x)",
	    ntohl(addr));

	if (rdsv3_isloopback(addr))
		return (&rdsv3_loop_transport);

	rw_enter(&trans_sem, RW_READER);
	for (i = 0; i < RDS_TRANS_COUNT; i++) {
		if (transports[i] &&
		    transports[i]->laddr_check(addr) == 0) {
			ret = transports[i];
			break;
		}
	}
	rw_exit(&trans_sem);

	RDSV3_DPRINTF4("rdsv3_trans_get_preferred",
	    "Return(addr: %x, ret: %p)", ntohl(addr), ret);

	return (ret);
}

/*
 * This returns the number of stats entries in the snapshot and only
 * copies them using the iter if there is enough space for them.  The
 * caller passes in the global stats so that we can size and copy while
 * holding the lock.
 */
/* ARGSUSED */
unsigned int
rdsv3_trans_stats_info_copy(struct rdsv3_info_iterator *iter,
    unsigned int avail)
{
	struct rdsv3_transport *trans;
	unsigned int total = 0;
	unsigned int part;
	int i;

	rw_enter(&trans_sem, RW_READER);

	for (i = 0; i < RDS_TRANS_COUNT; i++) {
		trans = transports[i];
		if (!trans || !trans->stats_info_copy)
			continue;

		part = trans->stats_info_copy(iter, avail);
		avail -= min(avail, part);
		total += part;
	}

	rw_exit(&trans_sem);

	return (total);
}
