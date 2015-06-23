/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file rdma.c
 * Oracle elects to have and use the contents of rdma.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2007 Oracle.  All rights reserved.
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
#include <sys/ib/clients/of/rdma/ib_verbs.h>
#include <sys/ib/clients/of/rdma/ib_addr.h>
#include <sys/ib/clients/of/rdma/rdma_cm.h>

#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

#define	DMA_TO_DEVICE 0
#define	DMA_FROM_DEVICE 1
#define	RB_CLEAR_NODE(nodep) AVL_SETPARENT(nodep, nodep);

/*
 * XXX
 *  - build with sparse
 *  - should we limit the size of a mr region?  let transport return failure?
 *  - should we detect duplicate keys on a socket?  hmm.
 *  - an rdma is an mlock, apply rlimit?
 */

/*
 * get the number of pages by looking at the page indices that the start and
 * end addresses fall in.
 *
 * Returns 0 if the vec is invalid.  It is invalid if the number of bytes
 * causes the address to wrap or overflows an unsigned int.  This comes
 * from being stored in the 'length' member of 'struct rdsv3_scatterlist'.
 */
static unsigned int
rdsv3_pages_in_vec(struct rds_iovec *vec)
{
	if ((vec->addr + vec->bytes <= vec->addr) ||
	    (vec->bytes > (uint64_t)UINT_MAX)) {
		return (0);
	}

	return (((vec->addr + vec->bytes + PAGESIZE - 1) >>
	    PAGESHIFT) - (vec->addr >> PAGESHIFT));
}

static struct rdsv3_mr *
rdsv3_mr_tree_walk(struct avl_tree *root, uint32_t key,
	struct rdsv3_mr *insert)
{
	struct rdsv3_mr *mr;
	avl_index_t where;

	mr = avl_find(root, &key, &where);
	if ((mr == NULL) && (insert != NULL)) {
		avl_insert(root, (void *)insert, where);
		atomic_inc_32(&insert->r_refcount);
		return (NULL);
	}

	return (mr);
}

/*
 * Destroy the transport-specific part of a MR.
 */
static void
rdsv3_destroy_mr(struct rdsv3_mr *mr)
{
	struct rdsv3_sock *rs = mr->r_sock;
	void *trans_private = NULL;
	avl_node_t *np;

	RDSV3_DPRINTF5("rdsv3_destroy_mr",
	    "RDS: destroy mr key is %x refcnt %u",
	    mr->r_key, atomic_get(&mr->r_refcount));

	if (test_and_set_bit(RDSV3_MR_DEAD, &mr->r_state))
		return;

	mutex_enter(&rs->rs_rdma_lock);
	np = &mr->r_rb_node;
	if (AVL_XPARENT(np) != np)
		avl_remove(&rs->rs_rdma_keys, mr);
	trans_private = mr->r_trans_private;
	mr->r_trans_private = NULL;
	mutex_exit(&rs->rs_rdma_lock);

	if (trans_private)
		mr->r_trans->free_mr(trans_private, mr->r_invalidate);
}

void
__rdsv3_put_mr_final(struct rdsv3_mr *mr)
{
	rdsv3_destroy_mr(mr);
	kmem_free(mr, sizeof (*mr));
}

/*
 * By the time this is called we can't have any more ioctls called on
 * the socket so we don't need to worry about racing with others.
 */
void
rdsv3_rdma_drop_keys(struct rdsv3_sock *rs)
{
	struct rdsv3_mr *mr;
	struct avl_node *node;

	/* Release any MRs associated with this socket */
	mutex_enter(&rs->rs_rdma_lock);
	while ((node = avl_first(&rs->rs_rdma_keys))) {
		mr = container_of(node, struct rdsv3_mr, r_rb_node);
		if (mr->r_trans == rs->rs_transport)
			mr->r_invalidate = 0;
		avl_remove(&rs->rs_rdma_keys, &mr->r_rb_node);
		RB_CLEAR_NODE(&mr->r_rb_node)
		mutex_exit(&rs->rs_rdma_lock);
		rdsv3_destroy_mr(mr);
		rdsv3_mr_put(mr);
		mutex_enter(&rs->rs_rdma_lock);
	}
	mutex_exit(&rs->rs_rdma_lock);

	if (rs->rs_transport && rs->rs_transport->flush_mrs)
		rs->rs_transport->flush_mrs();
}

static int
__rdsv3_rdma_map(struct rdsv3_sock *rs, struct rds_get_mr_args *args,
	uint64_t *cookie_ret, struct rdsv3_mr **mr_ret)
{
	struct rdsv3_mr *mr = NULL, *found;
	void *trans_private;
	rds_rdma_cookie_t cookie;
	unsigned int nents = 0;
	int ret;

	if (rs->rs_bound_addr == 0) {
		ret = -ENOTCONN; /* XXX not a great errno */
		goto out;
	}

	if (!rs->rs_transport->get_mr) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	mr = kmem_zalloc(sizeof (struct rdsv3_mr), KM_NOSLEEP);
	if (!mr) {
		ret = -ENOMEM;
		goto out;
	}

	mr->r_refcount = 1;
	RB_CLEAR_NODE(&mr->r_rb_node);
	mr->r_trans = rs->rs_transport;
	mr->r_sock = rs;

	if (args->flags & RDS_RDMA_USE_ONCE)
		mr->r_use_once = 1;
	if (args->flags & RDS_RDMA_INVALIDATE)
		mr->r_invalidate = 1;
	if (args->flags & RDS_RDMA_READWRITE)
		mr->r_write = 1;

	/*
	 * Obtain a transport specific MR. If this succeeds, the
	 * s/g list is now owned by the MR.
	 * Note that dma_map() implies that pending writes are
	 * flushed to RAM, so no dma_sync is needed here.
	 */
	trans_private = rs->rs_transport->get_mr(&args->vec, nents, rs,
	    &mr->r_key);

	if (IS_ERR(trans_private)) {
		ret = PTR_ERR(trans_private);
		goto out;
	}

	mr->r_trans_private = trans_private;

	/*
	 * The user may pass us an unaligned address, but we can only
	 * map page aligned regions. So we keep the offset, and build
	 * a 64bit cookie containing <R_Key, offset> and pass that
	 * around.
	 */
	cookie = rdsv3_rdma_make_cookie(mr->r_key, args->vec.addr & ~PAGEMASK);
	if (cookie_ret)
		*cookie_ret = cookie;

	/*
	 * copy value of cookie to user address at args->cookie_addr
	 */
	if (args->cookie_addr) {
		ret = ddi_copyout((void *)&cookie,
		    (void *)((intptr_t)args->cookie_addr),
		    sizeof (rds_rdma_cookie_t), 0);
		if (ret != 0) {
			ret = -EFAULT;
			goto out;
		}
	}

	RDSV3_DPRINTF5("__rdsv3_rdma_map",
	    "RDS: get_mr mr 0x%p addr 0x%llx key 0x%x",
	    mr, args->vec.addr, mr->r_key);
	/*
	 * Inserting the new MR into the rbtree bumps its
	 * reference count.
	 */
	mutex_enter(&rs->rs_rdma_lock);
	found = rdsv3_mr_tree_walk(&rs->rs_rdma_keys, mr->r_key, mr);
	mutex_exit(&rs->rs_rdma_lock);

	ASSERT(!(found && found != mr));

	if (mr_ret) {
		atomic_inc_32(&mr->r_refcount);
		*mr_ret = mr;
	}

	ret = 0;
out:
	if (mr)
		rdsv3_mr_put(mr);
	return (ret);
}

int
rdsv3_get_mr(struct rdsv3_sock *rs, const void *optval, int optlen)
{
	struct rds_get_mr_args args;

	if (optlen != sizeof (struct rds_get_mr_args))
		return (-EINVAL);

#if 1
	bcopy((struct rds_get_mr_args *)optval, &args,
	    sizeof (struct rds_get_mr_args));
#else
	if (ddi_copyin(optval, &args, optlen, 0))
		return (-EFAULT);
#endif

	return (__rdsv3_rdma_map(rs, &args, NULL, NULL));
}

int
rdsv3_get_mr_for_dest(struct rdsv3_sock *rs, const void *optval,
    int optlen)
{
	struct rds_get_mr_for_dest_args args;
	struct rds_get_mr_args new_args;

	if (optlen != sizeof (struct rds_get_mr_for_dest_args))
		return (-EINVAL);

#if 1
	bcopy((struct rds_get_mr_for_dest_args *)optval, &args,
	    sizeof (struct rds_get_mr_for_dest_args));
#else
	if (ddi_copyin(optval, &args, optlen, 0))
		return (-EFAULT);
#endif

	/*
	 * Initially, just behave like get_mr().
	 * TODO: Implement get_mr as wrapper around this
	 *	 and deprecate it.
	 */
	new_args.vec = args.vec;
	new_args.cookie_addr = args.cookie_addr;
	new_args.flags = args.flags;

	return (__rdsv3_rdma_map(rs, &new_args, NULL, NULL));
}

/*
 * Free the MR indicated by the given R_Key
 */
int
rdsv3_free_mr(struct rdsv3_sock *rs, const void *optval, int optlen)
{
	struct rds_free_mr_args args;
	struct rdsv3_mr *mr;

	if (optlen != sizeof (struct rds_free_mr_args))
		return (-EINVAL);

#if 1
	bcopy((struct rds_free_mr_args *)optval, &args,
	    sizeof (struct rds_free_mr_args));
#else
	if (ddi_copyin((struct rds_free_mr_args *)optval, &args,
	    sizeof (struct rds_free_mr_args), 0))
		return (-EFAULT);
#endif

	/* Special case - a null cookie means flush all unused MRs */
	if (args.cookie == 0) {
		if (!rs->rs_transport || !rs->rs_transport->flush_mrs)
			return (-EINVAL);
		rs->rs_transport->flush_mrs();
		return (0);
	}

	/*
	 * Look up the MR given its R_key and remove it from the rbtree
	 * so nobody else finds it.
	 * This should also prevent races with rdsv3_rdma_unuse.
	 */
	mutex_enter(&rs->rs_rdma_lock);
	mr = rdsv3_mr_tree_walk(&rs->rs_rdma_keys,
	    rdsv3_rdma_cookie_key(args.cookie), NULL);
	if (mr) {
		avl_remove(&rs->rs_rdma_keys, &mr->r_rb_node);
		RB_CLEAR_NODE(&mr->r_rb_node);
		if (args.flags & RDS_RDMA_INVALIDATE)
			mr->r_invalidate = 1;
	}
	mutex_exit(&rs->rs_rdma_lock);

	if (!mr)
		return (-EINVAL);

	/*
	 * call rdsv3_destroy_mr() ourselves so that we're sure it's done
	 * by time we return.  If we let rdsv3_mr_put() do it it might not
	 * happen until someone else drops their ref.
	 */
	rdsv3_destroy_mr(mr);
	rdsv3_mr_put(mr);
	return (0);
}

/*
 * This is called when we receive an extension header that
 * tells us this MR was used. It allows us to implement
 * use_once semantics
 */
void
rdsv3_rdma_unuse(struct rdsv3_sock *rs, uint32_t r_key, int force)
{
	struct rdsv3_mr *mr;
	int zot_me = 0;

	RDSV3_DPRINTF4("rdsv3_rdma_unuse", "Enter rkey: 0x%x", r_key);

	mutex_enter(&rs->rs_rdma_lock);
	mr = rdsv3_mr_tree_walk(&rs->rs_rdma_keys, r_key, NULL);
	if (!mr) {
		RDSV3_DPRINTF4("rdsv3_rdma_unuse",
		    "rdsv3: trying to unuse MR with unknown r_key %u!", r_key);
		mutex_exit(&rs->rs_rdma_lock);
		return;
	}

	if (mr->r_use_once || force) {
		avl_remove(&rs->rs_rdma_keys, &mr->r_rb_node);
		RB_CLEAR_NODE(&mr->r_rb_node);
		zot_me = 1;
	} else {
		atomic_inc_32(&mr->r_refcount);
	}
	mutex_exit(&rs->rs_rdma_lock);

	/*
	 * May have to issue a dma_sync on this memory region.
	 * Note we could avoid this if the operation was a RDMA READ,
	 * but at this point we can't tell.
	 */
	if (mr->r_trans->sync_mr)
		mr->r_trans->sync_mr(mr->r_trans_private, DMA_FROM_DEVICE);

	/*
	 * If the MR was marked as invalidate, this will
	 * trigger an async flush.
	 */
	if (zot_me)
		rdsv3_destroy_mr(mr);
	rdsv3_mr_put(mr);
	RDSV3_DPRINTF4("rdsv3_rdma_unuse", "Return");
}

void
rdsv3_rdma_free_op(struct rdsv3_rdma_op *ro)
{
	unsigned int i;

	/* deallocate RDMA resources on rdsv3_message */
	for (i = 0; i < ro->r_nents; i++) {
		ddi_umem_unlock(ro->r_rdma_sg[i].umem_cookie);
	}

	if (ro->r_notifier)
		kmem_free(ro->r_notifier, sizeof (*ro->r_notifier));
	kmem_free(ro, sizeof (*ro));
}

/*
 * args is a pointer to an in-kernel copy in the sendmsg cmsg.
 */
static struct rdsv3_rdma_op *
rdsv3_rdma_prepare(struct rdsv3_sock *rs, struct rds_rdma_args *args)
{
	struct rds_iovec vec;
	struct rdsv3_rdma_op *op = NULL;
	unsigned int nr_bytes;
	struct rds_iovec *local_vec;
	unsigned int nr;
	unsigned int i;
	ddi_umem_cookie_t umem_cookie;
	size_t umem_len;
	caddr_t umem_addr;
	int ret;

	if (rs->rs_bound_addr == 0) {
		ret = -ENOTCONN; /* XXX not a great errno */
		goto out;
	}

	if (args->nr_local > (uint64_t)UINT_MAX) {
		ret = -EMSGSIZE;
		goto out;
	}

	op = kmem_zalloc(offsetof(struct rdsv3_rdma_op,
	    r_rdma_sg[args->nr_local]), KM_NOSLEEP);
	if (op == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	op->r_write = !!(args->flags & RDS_RDMA_READWRITE);
	op->r_fence = !!(args->flags & RDS_RDMA_FENCE);
	op->r_notify = !!(args->flags & RDS_RDMA_NOTIFY_ME);
	op->r_recverr = rs->rs_recverr;

	if (op->r_notify || op->r_recverr) {
		/*
		 * We allocate an uninitialized notifier here, because
		 * we don't want to do that in the completion handler. We
		 * would have to use GFP_ATOMIC there, and don't want to deal
		 * with failed allocations.
		 */
		op->r_notifier = kmem_alloc(sizeof (struct rdsv3_notifier),
		    KM_NOSLEEP);
		if (!op->r_notifier) {
			ret = -ENOMEM;
			goto out;
		}
		op->r_notifier->n_user_token = args->user_token;
		op->r_notifier->n_status = RDS_RDMA_SUCCESS;
	}

	/*
	 * The cookie contains the R_Key of the remote memory region, and
	 * optionally an offset into it. This is how we implement RDMA into
	 * unaligned memory.
	 * When setting up the RDMA, we need to add that offset to the
	 * destination address (which is really an offset into the MR)
	 * FIXME: We may want to move this into ib_rdma.c
	 */
	op->r_key = rdsv3_rdma_cookie_key(args->cookie);
	op->r_remote_addr = args->remote_vec.addr +
	    rdsv3_rdma_cookie_offset(args->cookie);

	nr_bytes = 0;

	RDSV3_DPRINTF5("rdsv3_rdma_prepare",
	    "RDS: rdma prepare nr_local %llu rva %llx rkey %x",
	    (unsigned long long)args->nr_local,
	    (unsigned long long)args->remote_vec.addr,
	    op->r_key);

	local_vec = (struct rds_iovec *)(unsigned long) args->local_vec_addr;

	/* pin the scatter list of user buffers */
	for (i = 0; i < args->nr_local; i++) {
		if (ddi_copyin(&local_vec[i], &vec,
		    sizeof (struct rds_iovec), 0)) {
			ret = -EFAULT;
			goto out;
		}

		nr = rdsv3_pages_in_vec(&vec);
		if (nr == 0) {
			RDSV3_DPRINTF2("rdsv3_rdma_prepare",
			    "rdsv3_pages_in_vec returned 0");
			ret = -EINVAL;
			goto out;
		}

		rs->rs_user_addr = vec.addr;
		rs->rs_user_bytes = vec.bytes;

		/* pin user memory pages */
		umem_len = ptob(btopr(vec.bytes +
		    ((uintptr_t)vec.addr & PAGEOFFSET)));
		umem_addr = (caddr_t)((uintptr_t)vec.addr & ~PAGEOFFSET);
		ret = umem_lockmemory(umem_addr, umem_len,
		    DDI_UMEMLOCK_WRITE | DDI_UMEMLOCK_READ,
		    &umem_cookie, NULL, NULL);
		if (ret != 0) {
			RDSV3_DPRINTF2("rdsv3_rdma_prepare",
			    "umem_lockmemory() returned %d", ret);
			ret = -EFAULT;
			goto out;
		}
		op->r_rdma_sg[i].umem_cookie = umem_cookie;
		op->r_rdma_sg[i].iovec = vec;
		nr_bytes += vec.bytes;

		RDSV3_DPRINTF5("rdsv3_rdma_prepare",
		    "RDS: nr_bytes %u nr %u vec.bytes %llu vec.addr %llx",
		    nr_bytes, nr, vec.bytes, vec.addr);
	}
	op->r_nents = i;

	if (nr_bytes > args->remote_vec.bytes) {
		RDSV3_DPRINTF2("rdsv3_rdma_prepare",
		    "RDS nr_bytes %u remote_bytes %u do not match",
		    nr_bytes, (unsigned int) args->remote_vec.bytes);
		ret = -EINVAL;
		goto out;
	}
	op->r_bytes = nr_bytes;

	ret = 0;
out:
	if (ret) {
		if (op)
			rdsv3_rdma_free_op(op);
		op = ERR_PTR(ret);
	}
	return (op);
}

#define	CEIL(x, y)	(((x) + (y) - 1) / (y))

/*
 * The application asks for a RDMA transfer.
 * Extract all arguments and set up the rdma_op
 */
int
rdsv3_cmsg_rdma_args(struct rdsv3_sock *rs, struct rdsv3_message *rm,
	struct cmsghdr *cmsg)
{
	struct rdsv3_rdma_op *op;
	/* uint64_t alignment on the buffer */
	uint64_t buf[CEIL(CMSG_LEN(sizeof (struct rds_rdma_args)),
	    sizeof (uint64_t))];

	if (cmsg->cmsg_len != CMSG_LEN(sizeof (struct rds_rdma_args)) ||
	    rm->m_rdma_op != NULL)
		return (-EINVAL);

	ASSERT(sizeof (buf) >= cmsg->cmsg_len && ((uintptr_t)buf & 0x7) == 0);

	bcopy(CMSG_DATA(cmsg), (char *)buf, cmsg->cmsg_len);
	op = rdsv3_rdma_prepare(rs, (struct rds_rdma_args *)buf);

	if (IS_ERR(op))
		return (PTR_ERR(op));
	rdsv3_stats_inc(s_send_rdma);
	rm->m_rdma_op = op;
	return (0);
}

/*
 * The application wants us to pass an RDMA destination (aka MR)
 * to the remote
 */
int
rdsv3_cmsg_rdma_dest(struct rdsv3_sock *rs, struct rdsv3_message *rm,
	struct cmsghdr *cmsg)
{
	struct rdsv3_mr *mr;
	uint32_t r_key;
	int err = 0;

	if (cmsg->cmsg_len != CMSG_LEN(sizeof (rds_rdma_cookie_t)) ||
	    rm->m_rdma_cookie != 0)
		return (-EINVAL);

	(void) memcpy(&rm->m_rdma_cookie, CMSG_DATA(cmsg),
	    sizeof (rm->m_rdma_cookie));

	/*
	 * We are reusing a previously mapped MR here. Most likely, the
	 * application has written to the buffer, so we need to explicitly
	 * flush those writes to RAM. Otherwise the HCA may not see them
	 * when doing a DMA from that buffer.
	 */
	r_key = rdsv3_rdma_cookie_key(rm->m_rdma_cookie);

	mutex_enter(&rs->rs_rdma_lock);
	mr = rdsv3_mr_tree_walk(&rs->rs_rdma_keys, r_key, NULL);
	if (!mr)
		err = -EINVAL;	/* invalid r_key */
	else
		atomic_inc_32(&mr->r_refcount);
	mutex_exit(&rs->rs_rdma_lock);

	if (mr) {
		mr->r_trans->sync_mr(mr->r_trans_private, DMA_TO_DEVICE);
		rm->m_rdma_mr = mr;
	}
	return (err);
}

/*
 * The application passes us an address range it wants to enable RDMA
 * to/from. We map the area, and save the <R_Key,offset> pair
 * in rm->m_rdma_cookie. This causes it to be sent along to the peer
 * in an extension header.
 */
int
rdsv3_cmsg_rdma_map(struct rdsv3_sock *rs, struct rdsv3_message *rm,
	struct cmsghdr *cmsg)
{
	/* uint64_t alignment on the buffer */
	uint64_t buf[CEIL(CMSG_LEN(sizeof (struct rds_get_mr_args)),
	    sizeof (uint64_t))];
	int status;

	if (cmsg->cmsg_len != CMSG_LEN(sizeof (struct rds_get_mr_args)) ||
	    rm->m_rdma_cookie != 0)
		return (-EINVAL);

	ASSERT(sizeof (buf) >= cmsg->cmsg_len && ((uintptr_t)buf & 0x7) == 0);

	bcopy(CMSG_DATA(cmsg), (char *)buf, cmsg->cmsg_len);
	status = __rdsv3_rdma_map(rs, (struct rds_get_mr_args *)buf,
	    &rm->m_rdma_cookie, &rm->m_rdma_mr);

	return (status);
}
