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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
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

list_t			transports;
krwlock_t		trans_sem; /* this was a semaphore */

int
rdsv3_trans_register(struct rdsv3_transport *trans)
{
	RDSV3_DPRINTF4("rdsv3_trans_register", "Enter(trans: %p)", trans);

	rw_enter(&trans_sem, RW_WRITER);

	list_insert_tail(&transports, trans);

	rw_exit(&trans_sem);

	RDSV3_DPRINTF4("rdsv3_trans_register", "Return(trans: %p)", trans);

	return (0);
}

void
rdsv3_trans_unregister(struct rdsv3_transport *trans)
{
	RDSV3_DPRINTF4("rdsv3_trans_register", "Enter(trans: %p)", trans);

	rw_enter(&trans_sem, RW_WRITER);

	list_remove(&transports, trans);

	rw_exit(&trans_sem);

	RDSV3_DPRINTF4("rdsv3_trans_register", "Return(trans: %p)", trans);
}

struct rdsv3_transport *
rdsv3_trans_get_preferred(uint32_be_t addr)
{
	struct rdsv3_transport *trans;
	struct rdsv3_transport *ret = NULL;

	RDSV3_DPRINTF4("rdsv3_trans_get_preferred", "Enter(addr: %x)",
	    ntohl(addr));

	if (rdsv3_isloopback(addr))
		return (&rdsv3_loop_transport);

	rw_enter(&trans_sem, RW_READER);
	RDSV3_FOR_EACH_LIST_NODE(trans, &transports, t_item) {
		if (trans->laddr_check(addr) == 0) {
			ret = trans;
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
	/*
	 * XXX - Add this when we port info (info.c)
	 */
	return (0);
}
