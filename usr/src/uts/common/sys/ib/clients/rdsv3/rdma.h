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

#ifndef _RDSV3_RDMA_H
#define	_RDSV3_RDMA_H

#include <sys/rds.h>
#include <sys/uio.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>

struct rdsv3_mr {
	/* for AVL tree */
	avl_node_t		r_rb_node;
	atomic_t		r_refcount;
	uint32_t		r_key;

	/* A copy of the creation flags */
	unsigned int		r_use_once:1;
	unsigned int		r_invalidate:1;
	unsigned int		r_write:1;

	/*
	 * This is for RDS_MR_DEAD.
	 * It would be nice & consistent to make this part of the above
	 * bit field here, but we need to use test_and_set_bit.
	 */
	unsigned long		r_state;
	/* back pointer to the socket that owns us */
	struct rdsv3_sock	*r_sock;
	struct rdsv3_transport	*r_trans;
	void			*r_trans_private;
};

/* Flags for mr->r_state */
#define	RDSV3_MR_DEAD		0

struct rdsv3_rdma_sg {
	ddi_umem_cookie_t umem_cookie;
	struct rdsv3_iovec iovec;
	ibt_send_wr_t	swr;
	ibt_mi_hdl_t	mihdl;
	ibt_hca_hdl_t	hca_hdl;
};

struct rdsv3_rdma_op {
	uint32_t		r_key;
	uint64_t		r_remote_addr;
	unsigned int		r_write:1;
	unsigned int		r_fence:1;
	unsigned int		r_notify:1;
	unsigned int		r_recverr:1;
	unsigned int		r_mapped:1;
	struct rdsv3_notifier	*r_notifier;
	unsigned int		r_bytes;
	unsigned int		r_nents;
	unsigned int		r_count;
	struct rdsv3_scatterlist  *r_sg;
	struct rdsv3_rdma_sg	r_rdma_sg[1];
};

static inline rdsv3_rdma_cookie_t
rdsv3_rdma_make_cookie(uint32_t r_key, uint32_t offset)
{
	return (r_key | (((uint64_t)offset) << 32));
}

static inline uint32_t
rdsv3_rdma_cookie_key(rdsv3_rdma_cookie_t cookie)
{
	return ((uint32_t)cookie);
}

static inline uint32_t
rdsv3_rdma_cookie_offset(rdsv3_rdma_cookie_t cookie)
{
	return (cookie >> 32);
}

int rdsv3_get_mr(struct rdsv3_sock *rs, const void *optval, int optlen);
int rdsv3_get_mr_for_dest(struct rdsv3_sock *rs, const void *optval,
    int optlen);
int rdsv3_free_mr(struct rdsv3_sock *rs, const void *optval, int optlen);
void rdsv3_rdma_drop_keys(struct rdsv3_sock *rs);
int rdsv3_cmsg_rdma_args(struct rdsv3_sock *rs, struct rdsv3_message *rm,
    struct cmsghdr *cmsg);
int rdsv3_cmsg_rdma_dest(struct rdsv3_sock *rs, struct rdsv3_message *rm,
    struct cmsghdr *cmsg);
int rdsv3_cmsg_rdma_map(struct rdsv3_sock *rs, struct rdsv3_message *rm,
    struct cmsghdr *cmsg);
void rdsv3_rdma_free_op(struct rdsv3_rdma_op *ro);
void rdsv3_rdma_send_complete(struct rdsv3_message *rm, int);

extern void __rdsv3_put_mr_final(struct rdsv3_mr *mr);
static inline void rdsv3_mr_put(struct rdsv3_mr *mr)
{
	if (atomic_dec_and_test(&mr->r_refcount))
		__rdsv3_put_mr_final(mr);
}

#endif /* _RDSV3_RDMA_H */
