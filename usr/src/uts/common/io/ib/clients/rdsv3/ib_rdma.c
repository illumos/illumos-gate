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
#include <sys/rds.h>
#include <netinet/in.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

/*
 * This is stored as mr->r_trans_private.
 */
struct rdsv3_ib_mr {
	struct rdsv3_ib_device	*device;
	struct rdsv3_ib_mr_pool	*pool;
	struct ib_fmr		*fmr;
	struct list		list;
	unsigned int		remap_count;

	struct rdsv3_scatterlist	*sg;
	unsigned int		sg_len;
	uint64_t		*dma;
	int			sg_dma_len;

	/* DDI pinned memory */
	ddi_umem_cookie_t	umem_cookie;
	/* IBTF type definitions */
	ibt_fmr_pool_hdl_t	fmr_pool_hdl;
	ibt_ma_hdl_t		rc_ma_hdl;
	ibt_mr_hdl_t		rc_fmr_hdl;
	ibt_pmr_desc_t		rc_mem_desc;
};

/*
 * Our own little FMR pool
 */
struct rdsv3_ib_mr_pool {
	struct mutex		flush_lock;	/* serialize fmr invalidate */
	struct rdsv3_work_s	flush_worker;	/* flush worker */

	kmutex_t		list_lock;	/* protect variables below */
	atomic_t		item_count;	/* total # of MRs */
	atomic_t		dirty_count;	/* # dirty of MRs */
	/* MRs that have reached their max_maps limit */
	struct list		drop_list;
	struct list		free_list;	/* unused MRs */
	struct list		clean_list;	/* unused & unamapped MRs */
	atomic_t		free_pinned;	/* memory pinned by free MRs */
	unsigned long		max_items;
	unsigned long		max_items_soft;
	unsigned long		max_free_pinned;
};

static int rdsv3_ib_flush_mr_pool(struct rdsv3_ib_device *rds_ibdev,
	ibt_fmr_pool_hdl_t pool_hdl, int free_all);
static void rdsv3_ib_teardown_mr(struct rdsv3_ib_mr *ibmr);
static void rdsv3_ib_mr_pool_flush_worker(struct rdsv3_work_s *work);
static struct rdsv3_ib_mr *rdsv3_ib_alloc_fmr(struct rdsv3_ib_device
	*rds_ibdev);
static int rdsv3_ib_map_fmr(struct rdsv3_ib_device *rds_ibdev,
	struct rdsv3_ib_mr *ibmr, struct buf *bp, unsigned int nents);

static struct rdsv3_ib_device *
rdsv3_ib_get_device(uint32_be_t ipaddr)
{
	struct rdsv3_ib_device *rds_ibdev;
	struct rdsv3_ib_ipaddr *i_ipaddr;

	RDSV3_DPRINTF4("rdsv3_ib_get_device", "Enter: ipaddr: 0x%x", ipaddr);

	RDSV3_FOR_EACH_LIST_NODE(rds_ibdev, &rdsv3_ib_devices, list) {
		mutex_enter(&rds_ibdev->spinlock);
		RDSV3_FOR_EACH_LIST_NODE(i_ipaddr, &rds_ibdev->ipaddr_list,
		    list) {
			if (i_ipaddr->ipaddr == ipaddr) {
				mutex_exit(&rds_ibdev->spinlock);
				return (rds_ibdev);
			}
		}
		mutex_exit(&rds_ibdev->spinlock);
	}

	RDSV3_DPRINTF4("rdsv3_ib_get_device", "Return: ipaddr: 0x%x", ipaddr);

	return (NULL);
}

static int
rdsv3_ib_add_ipaddr(struct rdsv3_ib_device *rds_ibdev, uint32_be_t ipaddr)
{
	struct rdsv3_ib_ipaddr *i_ipaddr;

	RDSV3_DPRINTF4("rdsv3_ib_add_ipaddr", "rds_ibdev: %p ipaddr: %x",
	    rds_ibdev, ipaddr);

	i_ipaddr = kmem_alloc(sizeof (*i_ipaddr), KM_NOSLEEP);
	if (!i_ipaddr)
		return (-ENOMEM);

	i_ipaddr->ipaddr = ipaddr;

	mutex_enter(&rds_ibdev->spinlock);
	list_insert_tail(&rds_ibdev->ipaddr_list, i_ipaddr);
	mutex_exit(&rds_ibdev->spinlock);

	return (0);
}

static void
rdsv3_ib_remove_ipaddr(struct rdsv3_ib_device *rds_ibdev, uint32_be_t ipaddr)
{
	struct rdsv3_ib_ipaddr *i_ipaddr, *next;

	RDSV3_DPRINTF4("rdsv3_ib_remove_ipaddr", "rds_ibdev: %p, ipaddr: %x",
	    rds_ibdev, ipaddr);

	mutex_enter(&rds_ibdev->spinlock);
	RDSV3_FOR_EACH_LIST_NODE_SAFE(i_ipaddr, next, &rds_ibdev->ipaddr_list,
	    list) {
		if (i_ipaddr->ipaddr == ipaddr) {
			list_remove_node(&i_ipaddr->list);
			kmem_free(i_ipaddr, sizeof (*i_ipaddr));
			break;
		}
	}
	mutex_exit(&rds_ibdev->spinlock);

	RDSV3_DPRINTF4("rdsv3_ib_remove_ipaddr",
	    "Return: rds_ibdev: %p, ipaddr: %x", rds_ibdev, ipaddr);
}

int
rdsv3_ib_update_ipaddr(struct rdsv3_ib_device *rds_ibdev, uint32_be_t ipaddr)
{
	struct rdsv3_ib_device *rds_ibdev_old;

	RDSV3_DPRINTF4("rdsv3_ib_update_ipaddr", "rds_ibdev: %p, ipaddr: %x",
	    rds_ibdev, ipaddr);

	rds_ibdev_old = rdsv3_ib_get_device(ipaddr);
	if (rds_ibdev_old)
		rdsv3_ib_remove_ipaddr(rds_ibdev_old, ipaddr);

	return (rdsv3_ib_add_ipaddr(rds_ibdev, ipaddr));
}

void
rdsv3_ib_add_conn(struct rdsv3_ib_device *rds_ibdev,
    struct rdsv3_connection *conn)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;

	RDSV3_DPRINTF4("rdsv3_ib_add_conn", "rds_ibdev: %p, conn: %p",
	    rds_ibdev, conn);

	/* conn was previously on the nodev_conns_list */
	mutex_enter(&ib_nodev_conns_lock);
	ASSERT(!list_is_empty(&ib_nodev_conns));
	ASSERT(list_link_active(&ic->ib_node));
	list_remove_node(&ic->ib_node);

	mutex_enter(&rds_ibdev->spinlock);
	list_insert_tail(&rds_ibdev->conn_list, ic);
	mutex_exit(&rds_ibdev->spinlock);
	mutex_exit(&ib_nodev_conns_lock);

	ic->rds_ibdev = rds_ibdev;
}

void
rdsv3_ib_remove_conn(struct rdsv3_ib_device *rds_ibdev,
    struct rdsv3_connection *conn)
{
	struct rdsv3_ib_connection *ic = conn->c_transport_data;

	RDSV3_DPRINTF4("rdsv3_ib_remove_conn", "rds_ibdev: %p, conn: %p",
	    rds_ibdev, conn);

	/* place conn on nodev_conns_list */
	mutex_enter(&ib_nodev_conns_lock);

	mutex_enter(&rds_ibdev->spinlock);
	ASSERT(list_link_active(&ic->ib_node));
	list_remove_node(&ic->ib_node);
	mutex_exit(&rds_ibdev->spinlock);

	list_insert_tail(&ib_nodev_conns, ic);

	mutex_exit(&ib_nodev_conns_lock);

	ic->rds_ibdev = NULL;

	RDSV3_DPRINTF4("rdsv3_ib_remove_conn",
	    "Return: rds_ibdev: %p, conn: %p", rds_ibdev, conn);
}

void
__rdsv3_ib_destroy_conns(struct list *list, kmutex_t *list_lock)
{
	struct rdsv3_ib_connection *ic, *_ic;
	list_t tmp_list;

	RDSV3_DPRINTF4("__rdsv3_ib_destroy_conns", "Enter: list: %p", list);

	/* avoid calling conn_destroy with irqs off */
	mutex_enter(list_lock);
	list_splice(list, &tmp_list);
	mutex_exit(list_lock);

	RDSV3_FOR_EACH_LIST_NODE_SAFE(ic, _ic, &tmp_list, ib_node) {
		rdsv3_conn_destroy(ic->conn);
	}

	RDSV3_DPRINTF4("__rdsv3_ib_destroy_conns", "Return: list: %p", list);
}

void
rdsv3_ib_destroy_mr_pool(struct rdsv3_ib_device *rds_ibdev)
{
	RDSV3_DPRINTF4("rdsv3_ib_destroy_mr_pool", "Enter: ibdev: %p",
	    rds_ibdev);

	if (rds_ibdev->fmr_pool_hdl == NULL)
		return;

	(void) rdsv3_ib_flush_mr_pool(rds_ibdev, rds_ibdev->fmr_pool_hdl, 1);
	(void) ibt_destroy_fmr_pool(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    rds_ibdev->fmr_pool_hdl);
}

#define	IB_FMR_MAX_BUF_SIZE	0x1000000	/* 16MB max buf */
int
rdsv3_ib_create_mr_pool(struct rdsv3_ib_device *rds_ibdev)
{
	uint_t h_page_sz;
	ibt_fmr_pool_attr_t fmr_attr;
	ibt_status_t ibt_status;
	ibt_hca_hdl_t hca_hdl;

	RDSV3_DPRINTF4("rdsv3_ib_create_mr_pool",
	    "Enter: ibdev: %p", rds_ibdev);

	hca_hdl = ib_get_ibt_hca_hdl(rds_ibdev->dev);
	/* get hca attributes */
	ibt_status = ibt_query_hca(hca_hdl, &rds_ibdev->hca_attr);
	if (ibt_status != IBT_SUCCESS) {
		return (-ENOMEM);
	}

	/* setup FMR pool attributes */
	h_page_sz = rds_ibdev->hca_attr.hca_page_sz * 1024;

	fmr_attr.fmr_max_pages_per_fmr = (IB_FMR_MAX_BUF_SIZE / h_page_sz) + 2;
	fmr_attr.fmr_pool_size = RDSV3_FMR_POOL_SIZE;
	fmr_attr.fmr_dirty_watermark = 128;
	fmr_attr.fmr_cache = B_FALSE;
	fmr_attr.fmr_flags = IBT_MR_NOSLEEP  | IBT_MR_ENABLE_LOCAL_WRITE |
	    IBT_MR_ENABLE_REMOTE_WRITE | IBT_MR_ENABLE_REMOTE_READ;
	fmr_attr.fmr_page_sz = h_page_sz;
	fmr_attr.fmr_func_hdlr = NULL;
	fmr_attr.fmr_func_arg = (void *) NULL;

	/* create the FMR pool */
	ibt_status = ibt_create_fmr_pool(hca_hdl, rds_ibdev->pd->ibt_pd,
	    &fmr_attr, &rds_ibdev->fmr_pool_hdl);
	if (ibt_status != IBT_SUCCESS) {
		return (-ENOMEM);
	}
	rds_ibdev->max_fmrs = fmr_attr.fmr_pool_size;
	rds_ibdev->fmr_message_size = fmr_attr.fmr_max_pages_per_fmr;
	return (0);
}

void
rdsv3_ib_get_mr_info(struct rdsv3_ib_device *rds_ibdev,
	struct rdsv3_info_rdma_connection *iinfo)
{
	iinfo->rdma_mr_max = rds_ibdev->max_fmrs;
	iinfo->rdma_mr_size = rds_ibdev->fmr_message_size;
}

static void
rdsv3_umem_cb(ddi_umem_cookie_t *umem_cookie)
{
	/* LINTED E_FUNC_SET_NOT_USED */
	ddi_umem_cookie_t *cp = umem_cookie;
	RDSV3_DPRINTF5("rdsv3_umem_cb", "Enter: umem_cookie %p", umem_cookie);
	/* all umem_cookies are freed at socket fd close */
	/* there should be no umem_cookies when clearing the addr space */
}

struct umem_callback_ops rdsv3_umem_cbops = {
	UMEM_CALLBACK_VERSION,
	rdsv3_umem_cb,
};

void *
rdsv3_ib_get_mr(struct rdsv3_iovec *args, unsigned long nents,
	struct rdsv3_sock *rs, uint32_t *key_ret)
{
	struct rdsv3_ib_device *rds_ibdev;
	struct rdsv3_ib_mr *ibmr = NULL;
	ddi_umem_cookie_t umem_cookie;
	size_t umem_len;
	caddr_t umem_addr;
	int umem_flags;
	int ret;
	struct buf *bp;

	RDSV3_DPRINTF4("rdsv3_ib_get_mr", "Enter: args.addr: %p", args->addr);

	rds_ibdev = rdsv3_ib_get_device(rs->rs_bound_addr);

	if (rds_ibdev == NULL)
		return (void *)(PTR_ERR(-EFAULT));

	ibmr = rdsv3_ib_alloc_fmr(rds_ibdev);
	if (IS_ERR(ibmr))
		return (ibmr);

	/* pin user memory pages */
	umem_len   = ptob(btopr(args->bytes +
	    ((uintptr_t)args->addr & PAGEOFFSET)));
	umem_addr  = (caddr_t)((uintptr_t)args->addr & ~PAGEOFFSET);
	umem_flags = (DDI_UMEMLOCK_WRITE | DDI_UMEMLOCK_READ |
	    DDI_UMEMLOCK_LONGTERM);
	ret = umem_lockmemory(umem_addr, umem_len, umem_flags,
	    &umem_cookie, &rdsv3_umem_cbops, NULL);
	if (ret != 0) {
		kmem_free((void *) ibmr, sizeof (*ibmr));
		ibmr = ERR_PTR(ret);
		return (ibmr);
	}

	/* transpose umem_cookie to buf structure for rdsv3_ib_map_fmr() */
	bp = ddi_umem_iosetup(umem_cookie, 0, umem_len,
	    B_WRITE, 0, 0, NULL, DDI_UMEM_SLEEP);

	ret = rdsv3_ib_map_fmr(rds_ibdev, ibmr, bp, nents);
	freerbuf(bp);	/* free bp */
	if (ret == 0) {
		ibmr->umem_cookie = umem_cookie;
		*key_ret = (uint32_t)ibmr->rc_mem_desc.pmd_rkey;
		ibmr->device = rds_ibdev;
		RDSV3_DPRINTF4("rdsv3_ib_get_mr",
		    "Return: ibmr: %p umem_cookie %p", ibmr, ibmr->umem_cookie);
		return (ibmr);
	} else { /* error return */
		RDSV3_DPRINTF1("rdsv3_ib_get_mr", "map_fmr failed (errno=%d)\n",
		    ret);
		ddi_umem_unlock(umem_cookie);
		kmem_free((void *)ibmr, sizeof (*ibmr));
		return (ERR_PTR(ret));
	}
}

static struct rdsv3_ib_mr *
rdsv3_ib_alloc_fmr(struct rdsv3_ib_device *rds_ibdev)
{
	struct rdsv3_ib_mr *ibmr;

	RDSV3_DPRINTF4("rdsv3_ib_alloc_fmr", "Enter: ibdev: %p", rds_ibdev);

	if (rds_ibdev->fmr_pool_hdl) {
		ibmr = (struct rdsv3_ib_mr *)kmem_zalloc(sizeof (*ibmr),
		    KM_SLEEP);
		ibmr->fmr_pool_hdl = rds_ibdev->fmr_pool_hdl;
		return (ibmr);
	}
	return (struct rdsv3_ib_mr *)(PTR_ERR(-ENOMEM));
}

static int
rdsv3_ib_map_fmr(struct rdsv3_ib_device *rds_ibdev, struct rdsv3_ib_mr *ibmr,
	struct buf *bp, unsigned int nents)
{
	ibt_va_attr_t va_attr;
	ibt_reg_req_t reg_req;
	uint_t paddr_list_len;
	uint_t page_sz;
	ibt_status_t ibt_status;
	/* LINTED E_FUNC_SET_NOT_USED */
	unsigned int l_nents = nents;

	RDSV3_DPRINTF4("rdsv3_ib_map_fmr", "Enter: ibmr: %p", ibmr);
	RDSV3_DPRINTF4("rdsv3_ib_map_fmr", "buf addr: %p", bp->b_un.b_addr);

	/* setup ibt_map_mem_area attributes */
	bzero(&va_attr, sizeof (ibt_va_attr_t));
	va_attr.va_buf   = bp;
	va_attr.va_flags = IBT_VA_FMR | IBT_VA_BUF;

	page_sz = rds_ibdev->hca_attr.hca_page_sz * 1024; /* in kbytes */
	paddr_list_len = (bp->b_bcount / page_sz) + 2; /* start + end pg */

	/* map user buffer to HCA address */
	ibt_status = ibt_map_mem_area(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    &va_attr, paddr_list_len, &reg_req, &ibmr->rc_ma_hdl);
	if (ibt_status != IBT_SUCCESS) {
		return (-ENOMEM);
	}

	/*  use a free entry from FMR pool to register the specified memory */
	ibt_status = ibt_register_physical_fmr(
	    ib_get_ibt_hca_hdl(rds_ibdev->dev), ibmr->fmr_pool_hdl,
	    &reg_req.fn_arg, &ibmr->rc_fmr_hdl, &ibmr->rc_mem_desc);
	if (ibt_status != IBT_SUCCESS) {
		(void) ibt_unmap_mem_area(ib_get_ibt_hca_hdl(rds_ibdev->dev),
		    ibmr->rc_ma_hdl);
		if (ibt_status == IBT_INSUFF_RESOURCE) {
			return (-ENOBUFS);
		}
		return (-EINVAL);
	}
	RDSV3_DPRINTF4("rdsv3_ib_map_fmr", "Return: ibmr: %p rkey: 0x%x",
	    ibmr, (uint32_t)ibmr->rc_mem_desc.pmd_rkey);
	return (0);
}

void
rdsv3_ib_sync_mr(void *trans_private, int direction)
{
	/* LINTED E_FUNC_SET_NOT_USED */
	void *l_trans_private = trans_private;
	/* LINTED E_FUNC_SET_NOT_USED */
	int l_direction = direction;

	/* FMR Sync not needed in Solaris on PCI-ex systems */

	RDSV3_DPRINTF4("rdsv3_ib_sync_mr", "Enter:");
}

void
rdsv3_ib_flush_mrs(void)
{
	struct rdsv3_ib_device *rds_ibdev;

	RDSV3_DPRINTF4("rdsv3_ib_flush_mrs", "Enter:");

	RDSV3_FOR_EACH_LIST_NODE(rds_ibdev, &rdsv3_ib_devices, list) {
		if (rds_ibdev->fmr_pool_hdl) {
			(void) rdsv3_ib_flush_mr_pool(rds_ibdev,
			    rds_ibdev->fmr_pool_hdl, 0);
		}
	}
}

static void
__rdsv3_ib_teardown_mr(struct rdsv3_ib_mr *ibmr)
{
	RDSV3_DPRINTF4("__rdsv3_ib_teardown_mr",
	    "Enter: ibmr: %p umem_cookie %p", ibmr, ibmr->umem_cookie);

	/* unpin memory pages */
	(void) ddi_umem_unlock(ibmr->umem_cookie);
}

void
rdsv3_ib_free_mr(void *trans_private, int invalidate)
{
	struct rdsv3_ib_mr *ibmr = trans_private;
	struct rdsv3_ib_device *rds_ibdev = ibmr->device;

	RDSV3_DPRINTF4("rdsv3_ib_free_mr", "Enter: ibmr: %p inv: %d",
	    ibmr, invalidate);

	/* return the fmr to the IBTF pool */
	/* the final punch will come from the ibt_flush_fmr_pool() */
	(void) ibt_deregister_fmr(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    ibmr->rc_fmr_hdl);
	(void) ibt_unmap_mem_area(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    ibmr->rc_ma_hdl);
	__rdsv3_ib_teardown_mr(ibmr);
	if (invalidate) {
		rds_ibdev = ibmr->device;
		(void) rdsv3_ib_flush_mr_pool(rds_ibdev,
		    rds_ibdev->fmr_pool_hdl, 0);
	}
	kmem_free((void *) ibmr, sizeof (*ibmr));
}

static int
rdsv3_ib_flush_mr_pool(struct rdsv3_ib_device *rds_ibdev,
    ibt_fmr_pool_hdl_t pool_hdl, int free_all)
{
	/* LINTED E_FUNC_SET_NOT_USED */
	int l_free_all = free_all;

	RDSV3_DPRINTF4("rdsv3_ib_flush_mr_pool", "Enter: pool: %p", pool_hdl);

	rdsv3_ib_stats_inc(s_ib_rdma_mr_pool_flush);

	(void) ibt_flush_fmr_pool(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    pool_hdl);
	return (0);
}
