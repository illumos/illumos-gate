/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file ib_sysctl.c
 * Oracle elects to have and use the contents of ib_sysctl.c under and governed
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
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

unsigned long rdsv3_ib_sysctl_max_send_wr = RDSV3_IB_DEFAULT_SEND_WR;
unsigned long rdsv3_ib_sysctl_max_recv_wr = RDSV3_IB_DEFAULT_RECV_WR;
unsigned long rdsv3_ib_sysctl_max_recv_allocation = RDSV3_IB_MAX_RECV_ALLOC;
/* hardware will fail CQ creation long before this */

unsigned long rdsv3_ib_sysctl_max_unsig_wrs = 16;

unsigned long rdsv3_ib_sysctl_max_unsig_bytes = (16 << 20);

unsigned long rdsv3_max_bcopy_size;

/*
 * This sysctl does nothing.
 *
 * Backwards compatibility with RDS 3.0 wire protocol
 * disables initial FC credit exchange.
 * If it's ever possible to drop 3.0 support,
 * setting this to 1 and moving init/refill of send/recv
 * rings from ib_cm_connect_complete() back into ib_setup_qp()
 * will cause credits to be added before protocol negotiation.
 */
unsigned int rdsv3_ib_sysctl_flow_control = 0;

void
rdsv3_ib_sysctl_exit(void)
{
}

int
rdsv3_ib_sysctl_init(void)
{
	RDSV3_DPRINTF2("rdsv3_ib_sysctl_init",
	    "rdsv3_ib_sysctl_max_send_wr = 0x%lx "
	    "rdsv3_ib_sysctl_max_recv_wr = 0x%lx "
	    "rdsv3_ib_sysctl_max_recv_allocation = 0x%lx "
	    "rdsv3_ib_sysctl_max_unsig_wrs = 0x%lx "
	    "rdsv3_ib_sysctl_max_unsig_bytes = 0x%lx "
	    "rdsv3_ib_sysctl_flow_control = 0x%x",
	    rdsv3_ib_sysctl_max_send_wr,
	    rdsv3_ib_sysctl_max_recv_wr,
	    rdsv3_ib_sysctl_max_recv_allocation,
	    rdsv3_ib_sysctl_max_unsig_wrs,
	    rdsv3_ib_sysctl_max_unsig_bytes,
	    rdsv3_ib_sysctl_flow_control);

	rdsv3_max_bcopy_size = rdsv3_ib_sysctl_max_send_wr * RDSV3_FRAG_SIZE;
	return (0);
}
