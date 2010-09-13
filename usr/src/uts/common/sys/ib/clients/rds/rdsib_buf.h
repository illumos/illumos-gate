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
/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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
/*
 * Sun elects to include this software in Sun product
 * under the OpenIB BSD license.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RDSIB_BUF_H
#define	_RDSIB_BUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rds_sendbuf_state_s {
	RDS_SNDBUF_FREE			= 0,
	RDS_SNDBUF_PENDING		= 1,
	RDS_SNDBUF_ERROR		= 2
} rds_sendbuf_state_t;

/* Receive buffer states */
typedef enum rds_recvbuf_state_s {
	RDS_RCVBUF_FREE		= 0,
	RDS_RCVBUF_POSTED	= 1,
	RDS_RCVBUF_ONSOCKQ	= 2
} rds_recvbuf_state_t;

/*
 * RDS Buffer
 *
 * nextp - Ptr to the next buffer
 * ep - Endpoint that is using this buffer
 * ds - Data segment for SGL
 * state - rds_sendbuf_state for send buffers and rds_recvbuf_state for
 *         receive buffers.
 * frtn - Message freeing routine, for use by esballoc(9F), only used
 *        by receive buffers
 */
typedef struct rds_buf_s {
	struct rds_buf_s	*buf_nextp;
	struct rds_ep_s		*buf_ep;
	ibt_wr_ds_t		buf_ds;
	uint8_t			buf_state;
	frtn_t			buf_frtn;
} rds_buf_t;

/*
 * RDS Buffer pool
 *
 * lock - Synchronize access
 * nbuffers - SQ depth for send buffer pool and RQ depth for receive buffer
 *	pool
 * nbusy - Number of buffers in the SQ or RQ
 * nfree - Number of buffers in the pool(between headp and tailp).
 * headp - First available buffer
 * tailp - Last available buffer
 * memp - pointer to the memory allocated for the buffer pool,
 *        valid only for send pools.
 * memsize - size of the memory allocated (valid for send pools only).
 * cv - condition variable to wait for buffers
 * cv_count - Number of buffers that are being waited on.
 * sqpoll_pending - Flag to indicate that sendCQ handler is running.
 *
 * cv, cv_count and sqpoll_pending are only used when 'rds_no_interrupts'
 * is set.
 */
typedef struct rds_bufpool_s {
	kmutex_t		pool_lock;
	uint32_t		pool_nbuffers;
	uint32_t		pool_nbusy;
	uint32_t		pool_nfree;
	rds_buf_t		*pool_headp;
	rds_buf_t		*pool_tailp;
	uint8_t			*pool_memp;
	uint_t			pool_memsize;
	rds_buf_t		*pool_bufmemp;
	kcondvar_t		pool_cv;
	uint_t			pool_cv_count;
	boolean_t		pool_sqpoll_pending;
} rds_bufpool_t;

/* Global pools of buffers */
rds_bufpool_t		rds_dpool; /* data pool */
rds_bufpool_t		rds_cpool; /* ctrl pool */

/* defined in rds_buf.c */
int rds_init_recv_caches(rds_state_t *statep);
void rds_free_recv_caches(rds_state_t *statep);
int rds_init_send_pool(struct rds_ep_s *ep, ib_guid_t hca_guid);
int rds_reinit_send_pool(struct rds_ep_s *ep, ib_guid_t hca_guid);
void rds_free_send_pool(struct rds_ep_s *ep);
int rds_init_recv_pool(struct rds_ep_s *ep);
void rds_free_recv_pool(struct rds_ep_s *ep);
void rds_free_buf(rds_bufpool_t *pool, rds_buf_t *bp, uint_t nbuf);
rds_buf_t *rds_get_buf(rds_bufpool_t *pool, uint_t nbuf, uint_t *nret);
rds_buf_t *rds_get_send_buf(struct rds_ep_s *ep, uint_t nbufs);
void rds_free_send_buf(struct rds_ep_s *ep, rds_buf_t *headp,
    rds_buf_t *tailp, uint_t nbuf, boolean_t lock);
void rds_free_recv_buf(rds_buf_t *bp, uint_t nbuf);
boolean_t rds_is_sendq_empty(struct rds_ep_s *ep, uint_t);
boolean_t rds_is_recvq_empty(struct rds_ep_s *ep, boolean_t);

#ifdef __cplusplus
}
#endif

#endif	/* _RDSIB_BUF_H */
