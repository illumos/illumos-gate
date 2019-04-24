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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file implements the Work Queue Entry (WQE) management in IBMF.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

extern int ibmf_trace_level;
extern int ibmf_send_wqes_per_port, ibmf_recv_wqes_per_port;

#define	IBMF_INIT_SG_ELEMENT(sg, mem, lkey, size)	{ \
	(sg).ds_va = (ib_vaddr_t)(uintptr_t)(mem);	\
	(sg).ds_key = (lkey);				\
	(sg).ds_len = (size);				\
}

#define	IBMF_ADDR_TO_SEND_WR_ID(ptr, id)		\
	(id) = (ibt_wrid_t)(uintptr_t)(ptr)

#define	IBMF_ADDR_TO_RECV_WR_ID(ptr, id)		 \
	(id) = ((ibt_wrid_t)(uintptr_t)(ptr) | IBMF_RCV_CQE)

#define	IBMF_INIT_RMPP_HDR(hdrp, ver, type, respt, flg, status, seg, lennwl) { \
	(hdrp)->rmpp_version = (ver);			\
	(hdrp)->rmpp_type = (type);			\
	(hdrp)->rmpp_resp_time = (respt);		\
	(hdrp)->rmpp_flags = (flg);			\
	(hdrp)->rmpp_status = (status);			\
	(hdrp)->rmpp_segnum = (h2b32(seg));		\
	(hdrp)->rmpp_pyldlen_nwl = (h2b32(lennwl));	\
}

static int ibmf_send_wqe_cache_constructor(void *buf, void *cdrarg,
    int kmflags);
static void ibmf_send_wqe_cache_destructor(void *buf, void *cdrarg);
static int ibmf_recv_wqe_cache_constructor(void *buf, void *cdrarg,
    int kmflags);
static void ibmf_recv_wqe_cache_destructor(void *buf, void *cdrarg);
static int ibmf_i_extend_wqe_mem(ibmf_ci_t *cip,
    ibmf_qp_handle_t ibmf_qp_handle, ibmf_wqe_mgt_t *wqe_mgt,
    boolean_t block);

/*
 * ibmf_send_wqe_cache_constructor():
 *	Constructor for the kmem cache used for send WQEs for special QPs
 */
/* ARGSUSED */
static int
ibmf_send_wqe_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	ibmf_send_wqe_t		*send_wqe = (ibmf_send_wqe_t *)buf;
	ibmf_ci_t		*cip = (ibmf_ci_t *)cdrarg;
	ibmf_wqe_mgt_t		*wqe_mgt;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_send_wqe_cache_constructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_send_wqe_cache_constructor() enter, buf = %p, cdarg = %p\n",
	    tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqe))

	/* initialize send WQE context */
	send_wqe->send_sg_mem =
	    (ib_vaddr_t)(uintptr_t)vmem_alloc(cip->ci_wqe_ib_vmem,
	    IBMF_MEM_PER_WQE, kmflags == KM_SLEEP ? VM_SLEEP : VM_NOSLEEP);
	if (send_wqe->send_sg_mem == 0) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_send_wqe_cache_constructor_err, IBMF_TNF_ERROR, "",
		    "ibmf_send_wqe_cache_constructor(): %s\n", tnf_string, msg,
		    "Failed vmem allocation in send WQE cache constructor");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_send_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
		    "ibmf_send_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&cip->ci_wqe_mutex);
	wqe_mgt = cip->ci_wqe_mgt_list;

	/* Look for the WQE management struct that includes this address */
	while (wqe_mgt != NULL) {
		mutex_enter(&wqe_mgt->wqes_mutex);
		if ((send_wqe->send_sg_mem >= wqe_mgt->wqes_ib_mem) &&
		    (send_wqe->send_sg_mem < (wqe_mgt->wqes_ib_mem +
		    wqe_mgt->wqes_kmem_sz))) {
			mutex_exit(&wqe_mgt->wqes_mutex);
			break;
		}
		mutex_exit(&wqe_mgt->wqes_mutex);
		wqe_mgt = wqe_mgt->wqe_mgt_next;
	}

	if (wqe_mgt == NULL) {
		mutex_exit(&cip->ci_wqe_mutex);
		vmem_free(cip->ci_wqe_ib_vmem,
		    (void *)(uintptr_t)send_wqe->send_sg_mem, IBMF_MEM_PER_WQE);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_send_wqe_cache_constructor_err, IBMF_TNF_ERROR, "",
		    "ibmf_send_wqe_cache_constructor(): %s\n", tnf_string, msg,
		    "Address not found in WQE mgt list");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_send_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
		    "ibmf_send_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&wqe_mgt->wqes_mutex);

	send_wqe->send_mem = (caddr_t)((uintptr_t)wqe_mgt->wqes_kmem +
	    (uintptr_t)(send_wqe->send_sg_mem - wqe_mgt->wqes_ib_mem));
	bzero(send_wqe->send_mem, IBMF_MEM_PER_WQE);
	send_wqe->send_sg_lkey = wqe_mgt->wqes_ib_lkey;
	send_wqe->send_mem_hdl = wqe_mgt->wqes_ib_mem_hdl;
	send_wqe->send_wqe_flags = 0;
	send_wqe->send_wqe_next = NULL;

	mutex_exit(&wqe_mgt->wqes_mutex);
	mutex_exit(&cip->ci_wqe_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_send_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_send_wqe_cache_constructor() exit\n");

	return (0);
}

/*
 * ibmf_send_wqe_cache_destructor():
 *	Destructor for send WQE kmem cache for special QPs
 */
/* ARGSUSED */
static void
ibmf_send_wqe_cache_destructor(void *buf, void *cdrarg)
{
	ibmf_send_wqe_t		*send_wqe = (ibmf_send_wqe_t *)buf;
	ibmf_ci_t		*cip = (ibmf_ci_t *)cdrarg;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_send_wqe_cache_destructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_send_wqe_cache_destructor() enter, buf = %p, cdarg = %p\n",
	    tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqe))

	/* Free the vmem allocated for the WQE */
	vmem_free(cip->ci_wqe_ib_vmem,
	    (void *)(uintptr_t)send_wqe->send_sg_mem, IBMF_MEM_PER_WQE);
	send_wqe->send_mem = NULL;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_send_wqe_cache_destructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_send_wqe_cache_destructor() exit\n");
}

/*
 * ibmf_recv_wqe_cache_constructor():
 *	Constructor for receive WQE kmem cache for special QPs
 */
/* ARGSUSED */
static int
ibmf_recv_wqe_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	ibmf_recv_wqe_t		*recv_wqe = (ibmf_recv_wqe_t *)buf;
	ibmf_ci_t		*cip = (ibmf_ci_t *)cdrarg;
	ibmf_wqe_mgt_t		*wqe_mgt;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_recv_wqe_cache_constructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_recv_wqe_cache_constructor() enter, buf = %p, cdarg = %p\n",
	    tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqe))

	/* initialize recv WQE context */
	recv_wqe->recv_sg_mem =
	    (ib_vaddr_t)(uintptr_t)vmem_alloc(cip->ci_wqe_ib_vmem,
	    IBMF_MEM_PER_WQE, kmflags == KM_SLEEP ? VM_SLEEP : VM_NOSLEEP);
	if (recv_wqe->recv_sg_mem == 0) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_recv_wqe_cache_constructor_err, IBMF_TNF_ERROR, "",
		    "ibmf_recv_wqe_cache_constructor(): %s\n", tnf_string, msg,
		    "Failed vmem allocation in receive WQE cache constructor");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_recv_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
		    "ibmf_recv_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&cip->ci_wqe_mutex);
	wqe_mgt = cip->ci_wqe_mgt_list;

	/* Look for the WQE management struct that includes this address */
	while (wqe_mgt != NULL) {
		mutex_enter(&wqe_mgt->wqes_mutex);
		if ((recv_wqe->recv_sg_mem >= wqe_mgt->wqes_ib_mem) &&
		    (recv_wqe->recv_sg_mem < (wqe_mgt->wqes_ib_mem +
		    wqe_mgt->wqes_kmem_sz))) {
			mutex_exit(&wqe_mgt->wqes_mutex);
			break;
		}
		mutex_exit(&wqe_mgt->wqes_mutex);
		wqe_mgt = wqe_mgt->wqe_mgt_next;
	}

	if (wqe_mgt == NULL) {
		mutex_exit(&cip->ci_wqe_mutex);
		vmem_free(cip->ci_wqe_ib_vmem,
		    (void *)(uintptr_t)recv_wqe->recv_sg_mem, IBMF_MEM_PER_WQE);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_recv_wqe_cache_constructor_err, IBMF_TNF_ERROR, "",
		    "ibmf_recv_wqe_cache_constructor(): %s\n", tnf_string, msg,
		    "Address not found in WQE mgt list");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_recv_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
		    "ibmf_recv_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&wqe_mgt->wqes_mutex);

	recv_wqe->recv_mem = (caddr_t)((uintptr_t)wqe_mgt->wqes_kmem +
	    (uintptr_t)(recv_wqe->recv_sg_mem - wqe_mgt->wqes_ib_mem));
	bzero(recv_wqe->recv_mem, IBMF_MEM_PER_WQE);
	recv_wqe->recv_sg_lkey = wqe_mgt->wqes_ib_lkey;
	recv_wqe->recv_mem_hdl = wqe_mgt->wqes_ib_mem_hdl;
	recv_wqe->recv_wqe_next = NULL;
	recv_wqe->recv_msg = NULL;
	recv_wqe->recv_wqe_flags = 0;

	mutex_exit(&wqe_mgt->wqes_mutex);
	mutex_exit(&cip->ci_wqe_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_recv_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_recv_wqe_cache_constructor() exit\n");

	return (0);
}

/*
 * ibmf_recv_wqe_cache_destructor():
 *	Destructor for receive WQE kmem cache for special QPs
 */
/* ARGSUSED */
static void
ibmf_recv_wqe_cache_destructor(void *buf, void *cdrarg)
{
	ibmf_recv_wqe_t		*recv_wqe = (ibmf_recv_wqe_t *)buf;
	ibmf_ci_t		*cip = (ibmf_ci_t *)cdrarg;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_recv_wqe_cache_destructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_recv_wqe_cache_destructor() enter, buf = %p, cdarg = %p\n",
	    tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqe))

	/* Free the vmem allocated for the WQE */
	vmem_free(cip->ci_wqe_ib_vmem,
	    (void *)(uintptr_t)recv_wqe->recv_sg_mem, IBMF_MEM_PER_WQE);
	recv_wqe->recv_mem = NULL;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_recv_wqe_cache_destructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_recv_wqe_cache_destructor() exit\n");
}

/*
 * ibmf_altqp_send_wqe_cache_constructor():
 *	Constructor for the kmem cache used for send WQEs for alternate QPs
 */
/* ARGSUSED */
int
ibmf_altqp_send_wqe_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	ibmf_send_wqe_t	*send_wqe = (ibmf_send_wqe_t *)buf;
	ibmf_alt_qp_t	*qp_ctx = (ibmf_alt_qp_t *)cdrarg;
	ibmf_wqe_mgt_t	*wqe_mgt;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_altqp_send_wqe_cache_constructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_send_wqe_cache_constructor() enter, buf = %p, "
	    "cdarg = %p\n", tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqe))

	/* initialize send WQE context */
	send_wqe->send_sg_mem = (ib_vaddr_t)(uintptr_t)vmem_alloc(
	    qp_ctx->isq_wqe_ib_vmem, IBMF_MEM_PER_WQE,
	    kmflags == KM_SLEEP ? VM_SLEEP : VM_NOSLEEP);
	if (send_wqe->send_sg_mem == 0) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_altqp_send_wqe_cache_constructor_err, IBMF_TNF_ERROR,
		    "", "ibmf_altqp_send_wqe_cache_constructor(): %s\n",
		    tnf_string, msg, "Failed vmem allocation in "
		    "alternate QP send WQE cache constructor");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_altqp_send_wqe_cache_constructor_end, IBMF_TNF_TRACE,
		    "", "ibmf_altqp_send_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&qp_ctx->isq_wqe_mutex);
	wqe_mgt = qp_ctx->isq_wqe_mgt_list;

	/* Look for the WQE management struct that includes this address */
	while (wqe_mgt != NULL) {
		mutex_enter(&wqe_mgt->wqes_mutex);
		if ((send_wqe->send_sg_mem >= wqe_mgt->wqes_ib_mem) &&
		    (send_wqe->send_sg_mem < (wqe_mgt->wqes_ib_mem +
		    wqe_mgt->wqes_kmem_sz))) {
			mutex_exit(&wqe_mgt->wqes_mutex);
			break;
		}
		mutex_exit(&wqe_mgt->wqes_mutex);
		wqe_mgt = wqe_mgt->wqe_mgt_next;
	}

	if (wqe_mgt == NULL) {
		mutex_exit(&qp_ctx->isq_wqe_mutex);
		vmem_free(qp_ctx->isq_wqe_ib_vmem,
		    (void *)(uintptr_t)send_wqe->send_sg_mem, IBMF_MEM_PER_WQE);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_altqp_send_wqe_cache_constructor_err, IBMF_TNF_ERROR,
		    "", "ibmf_altqp_send_wqe_cache_constructor(): %s\n",
		    tnf_string, msg, "Address not found in WQE mgt list");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_altqp_send_wqe_cache_constructor_end,
		    IBMF_TNF_TRACE, "",
		    "ibmf_altqp_send_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&wqe_mgt->wqes_mutex);

	send_wqe->send_mem = (caddr_t)((uintptr_t)wqe_mgt->wqes_kmem +
	    (uintptr_t)(send_wqe->send_sg_mem - wqe_mgt->wqes_ib_mem));
	bzero(send_wqe->send_mem, IBMF_MEM_PER_WQE);
	send_wqe->send_sg_lkey = wqe_mgt->wqes_ib_lkey;
	send_wqe->send_mem_hdl = wqe_mgt->wqes_ib_mem_hdl;
	send_wqe->send_wqe_flags = 0;

	mutex_exit(&wqe_mgt->wqes_mutex);
	mutex_exit(&qp_ctx->isq_wqe_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_send_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_send_wqe_cache_constructor() exit\n");

	return (0);
}

/*
 * ibmf_altqp_send_wqe_cache_destructor():
 *	Destructor for send WQE kmem cache for alternate QPs
 */
/* ARGSUSED */
void
ibmf_altqp_send_wqe_cache_destructor(void *buf, void *cdrarg)
{
	ibmf_send_wqe_t	*send_wqe = (ibmf_send_wqe_t *)buf;
	ibmf_alt_qp_t	*qp_ctx = (ibmf_alt_qp_t *)cdrarg;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_send_wqe_cache_destructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_send_wqe_cache_destructor() enter, buf = %p, "
	    "cdarg = %p\n", tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqe))

	/* Free the vmem allocated for the WQE */
	vmem_free(qp_ctx->isq_wqe_ib_vmem,
	    (void *)(uintptr_t)send_wqe->send_sg_mem, IBMF_MEM_PER_WQE);
	send_wqe->send_mem = NULL;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_send_wqe_cache_destructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_send_wqe_cache_destructor() exit\n");
}

/*
 * ibmf_altqp_recv_wqe_cache_constructor():
 *	Constructor for receive WQE kmem cache for alternate QPs
 */
/* ARGSUSED */
int
ibmf_altqp_recv_wqe_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	ibmf_recv_wqe_t	*recv_wqe = (ibmf_recv_wqe_t *)buf;
	ibmf_alt_qp_t	*qp_ctx = (ibmf_alt_qp_t *)cdrarg;
	ibmf_wqe_mgt_t	*wqe_mgt;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_recv_wqe_cache_constructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_recv_wqe_cache_constructor() enter, buf = %p, "
	    "cdarg = %p\n", tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqe))

	/* initialize recv WQE context */
	recv_wqe->recv_sg_mem = (ib_vaddr_t)(uintptr_t)vmem_alloc(
	    qp_ctx->isq_wqe_ib_vmem, IBMF_MEM_PER_WQE,
	    kmflags == KM_SLEEP ? VM_SLEEP : VM_NOSLEEP);
	if (recv_wqe->recv_sg_mem == 0) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_altqp_recv_wqe_cache_constructor_err, IBMF_TNF_ERROR,
		    "", "ibmf_altqp_recv_wqe_cache_constructor(): %s\n",
		    tnf_string, msg,
		    "Failed vmem allocation in recv WQE cache constructor");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_altqp_recv_wqe_cache_constructor_end, IBMF_TNF_TRACE,
		    "", "ibmf_altqp_recv_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&qp_ctx->isq_wqe_mutex);
	wqe_mgt = qp_ctx->isq_wqe_mgt_list;

	/* Look for the WQE management struct that includes this address */
	while (wqe_mgt != NULL) {
		mutex_enter(&wqe_mgt->wqes_mutex);
		if ((recv_wqe->recv_sg_mem >= wqe_mgt->wqes_ib_mem) &&
		    (recv_wqe->recv_sg_mem < (wqe_mgt->wqes_ib_mem +
		    wqe_mgt->wqes_kmem_sz))) {
			mutex_exit(&wqe_mgt->wqes_mutex);
			break;
		}
		mutex_exit(&wqe_mgt->wqes_mutex);
		wqe_mgt = wqe_mgt->wqe_mgt_next;
	}

	if (wqe_mgt == NULL) {
		mutex_exit(&qp_ctx->isq_wqe_mutex);
		vmem_free(qp_ctx->isq_wqe_ib_vmem,
		    (void *)(uintptr_t)recv_wqe->recv_sg_mem, IBMF_MEM_PER_WQE);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_recv_wqe_cache_constructor_err, IBMF_TNF_ERROR, "",
		    "ibmf_altqp_recv_wqe_cache_constructor(): %s\n",
		    tnf_string, msg, "Address not found in WQE mgt list");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_recv_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
		    "ibmf_recv_wqe_cache_constructor() exit\n");
		return (-1);
	}

	mutex_enter(&wqe_mgt->wqes_mutex);

	recv_wqe->recv_mem = (caddr_t)((uintptr_t)wqe_mgt->wqes_kmem +
	    (uintptr_t)(recv_wqe->recv_sg_mem - wqe_mgt->wqes_ib_mem));
	bzero(recv_wqe->recv_mem, IBMF_MEM_PER_WQE);
	recv_wqe->recv_sg_lkey = wqe_mgt->wqes_ib_lkey;
	recv_wqe->recv_mem_hdl = wqe_mgt->wqes_ib_mem_hdl;
	recv_wqe->recv_wqe_flags = 0;

	mutex_exit(&wqe_mgt->wqes_mutex);
	mutex_exit(&qp_ctx->isq_wqe_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_recv_wqe_cache_constructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_recv_wqe_cache_constructor() exit\n");

	return (0);
}

/*
 * ibmf_altqp_recv_wqe_cache_destructor():
 *	Destructor for receive WQE kmem cache for alternate QPs
 */
/* ARGSUSED */
void
ibmf_altqp_recv_wqe_cache_destructor(void *buf, void *cdrarg)
{
	ibmf_recv_wqe_t	*recv_wqe = (ibmf_recv_wqe_t *)buf;
	ibmf_alt_qp_t	*qp_ctx = (ibmf_alt_qp_t *)cdrarg;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_recv_wqe_cache_destructor_start, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_recv_wqe_cache_destructor() enter, buf = %p, "
	    "cdarg = %p\n", tnf_opaque, buf, buf, tnf_opaque, cdrarg, cdrarg);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqe))

	/* Free the vmem allocated for the WQE */
	vmem_free(qp_ctx->isq_wqe_ib_vmem,
	    (void *)(uintptr_t)recv_wqe->recv_sg_mem, IBMF_MEM_PER_WQE);
	recv_wqe->recv_mem = NULL;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_altqp_recv_wqe_cache_destructor_end, IBMF_TNF_TRACE, "",
	    "ibmf_altqp_recv_wqe_cache_destructor() exit\n");
}

/*
 * ibmf_i_init_wqes():
 *	Create the kmem cache for send and receive WQEs
 */
int
ibmf_i_init_wqes(ibmf_ci_t *cip)
{
	ibt_status_t		status;
	ibt_mr_hdl_t		mem_hdl;
	ibt_mr_desc_t		mem_desc;
	ibt_mr_attr_t		mem_attr;
	ibmf_wqe_mgt_t		*wqe_mgtp;
	char			string[128];

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_wqes_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_wqes() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	/*
	 * Allocate memory for the WQE management structure
	 */
	wqe_mgtp = kmem_zalloc(sizeof (ibmf_wqe_mgt_t), KM_SLEEP);
	mutex_init(&wqe_mgtp->wqes_mutex, NULL, MUTEX_DRIVER, NULL);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wqe_mgtp))

	/*
	 * Allocate memory for the WQEs to be used by the special QPs on this CI
	 * There are two special QPs per CI port
	 */
	wqe_mgtp->wqes_kmem_sz = cip->ci_nports * 2 *
	    ((IBMF_MEM_PER_WQE * ibmf_send_wqes_per_port) +
	    (IBMF_MEM_PER_WQE * ibmf_recv_wqes_per_port));
	wqe_mgtp->wqes_kmem =
	    kmem_zalloc(wqe_mgtp->wqes_kmem_sz, KM_SLEEP);

	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)wqe_mgtp->wqes_kmem;
	mem_attr.mr_len = wqe_mgtp->wqes_kmem_sz;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	mem_attr.mr_as = NULL;

	/* Register the allocated memory */
	status = ibt_register_mr(cip->ci_ci_handle, cip->ci_pd, &mem_attr,
	    &mem_hdl, &mem_desc);
	if (status != IBT_SUCCESS) {
		kmem_free(wqe_mgtp->wqes_kmem,
		    wqe_mgtp->wqes_kmem_sz);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_init_wqes_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_init_wqes(): %s, status = %d\n", tnf_string, msg,
		    "register of WQE mem failed", tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_init_wqes_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_init_wqes() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	/* Store the memory registration information */
	wqe_mgtp->wqes_ib_mem = mem_desc.md_vaddr;
	wqe_mgtp->wqes_ib_lkey = mem_desc.md_lkey;
	wqe_mgtp->wqes_ib_mem_hdl = mem_hdl;

	/* Create a vmem arena for the IB virtual address space */
	bzero(string, 128);
	(void) sprintf(string, "ibmf_%016" PRIx64 "_wqes", cip->ci_node_guid);
	cip->ci_wqe_ib_vmem = vmem_create(string,
	    (void *)(uintptr_t)wqe_mgtp->wqes_ib_mem, wqe_mgtp->wqes_kmem_sz,
	    sizeof (uint64_t), NULL, NULL, NULL, 0, VM_SLEEP);

	mutex_enter(&cip->ci_wqe_mutex);
	cip->ci_wqe_mgt_list = wqe_mgtp;
	mutex_exit(&cip->ci_wqe_mutex);

	bzero(string, 128);
	(void) sprintf(string, "ibmf_%016" PRIx64 "_swqe", cip->ci_node_guid);
	/* create a kmem cache for the send WQEs */
	cip->ci_send_wqes_cache = kmem_cache_create(string,
	    sizeof (ibmf_send_wqe_t), 0, ibmf_send_wqe_cache_constructor,
	    ibmf_send_wqe_cache_destructor, NULL, (void *)cip, NULL, 0);

	bzero(string, 128);
	(void) sprintf(string, "ibmf_%016" PRIx64 "_rwqe", cip->ci_node_guid);
	/* create a kmem cache for the receive WQEs */
	cip->ci_recv_wqes_cache = kmem_cache_create(string,
	    sizeof (ibmf_recv_wqe_t), 0, ibmf_recv_wqe_cache_constructor,
	    ibmf_recv_wqe_cache_destructor, NULL, (void *)cip, NULL, 0);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_wqes_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_wqes() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_fini_wqes():
 *	Destroy the kmem cache for send and receive WQEs
 */
void
ibmf_i_fini_wqes(ibmf_ci_t *cip)
{
	ibmf_wqe_mgt_t	*wqe_mgt;
	ibt_mr_hdl_t	wqe_ib_mem_hdl;
	void		*wqe_kmem;
	uint64_t	wqe_kmem_sz;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_wqes_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_wqes() enter, cip = %p\n",
	    tnf_opaque, cip, cip);

	mutex_enter(&cip->ci_wqe_mutex);

	wqe_mgt = cip->ci_wqe_mgt_list;
	while (wqe_mgt != NULL) {
		/* Remove the WQE mgt struct from the list */
		cip->ci_wqe_mgt_list = wqe_mgt->wqe_mgt_next;
		mutex_exit(&cip->ci_wqe_mutex);

		mutex_enter(&wqe_mgt->wqes_mutex);
		wqe_ib_mem_hdl = wqe_mgt->wqes_ib_mem_hdl;
		wqe_kmem = wqe_mgt->wqes_kmem;
		wqe_kmem_sz = wqe_mgt->wqes_kmem_sz;
		mutex_exit(&wqe_mgt->wqes_mutex);

		/* Deregister the memory allocated for the WQEs */
		(void) ibt_deregister_mr(cip->ci_ci_handle, wqe_ib_mem_hdl);

		/* Free the kmem allocated for the WQEs */
		kmem_free(wqe_kmem, wqe_kmem_sz);

		/* Destroy the mutex */
		mutex_destroy(&wqe_mgt->wqes_mutex);

		/* Free the WQE management structure */
		kmem_free(wqe_mgt, sizeof (ibmf_wqe_mgt_t));

		mutex_enter(&cip->ci_wqe_mutex);
		wqe_mgt = cip->ci_wqe_mgt_list;
	}

	mutex_exit(&cip->ci_wqe_mutex);

	/* Destroy the kmem_cache for the send WQE */
	kmem_cache_destroy(cip->ci_send_wqes_cache);
	/* Destroy the kmem_cache for the receive WQE */
	kmem_cache_destroy(cip->ci_recv_wqes_cache);

	/*
	 * Destroy the vmem arena for the WQEs
	 * This must be done after the kmem_cache_destroy() calls since
	 * the cache destructors call vmem_free()
	 */
	vmem_destroy((void *)cip->ci_wqe_ib_vmem);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_wqes_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_wqes() exit\n");
}

/*
 * ibmf_i_init_altqp_wqes():
 *	Create the kmem cache for send and receive WQEs used by alternate QPs
 */
int
ibmf_i_init_altqp_wqes(ibmf_alt_qp_t *qp_ctx)
{
	ibt_status_t		status;
	ibt_mr_hdl_t		mem_hdl;
	ibt_mr_desc_t		mem_desc;
	ibt_mr_attr_t		mem_attr;
	ibmf_wqe_mgt_t		*wqe_mgtp;
	char			string[128];

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_altqp_wqes_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_altqp_wqes() enter, qp_ctx = %p\n",
	    tnf_opaque, qp, qp_ctx);

	/*
	 * Allocate memory for the WQE management structure
	 */
	wqe_mgtp = kmem_zalloc(sizeof (ibmf_wqe_mgt_t), KM_SLEEP);
	mutex_init(&wqe_mgtp->wqes_mutex, NULL, MUTEX_DRIVER, NULL);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wqe_mgtp))

	/*
	 * Allocate memory for all the WQEs to be used by this alternate QP
	 */
	wqe_mgtp->wqes_kmem_sz = (IBMF_MEM_PER_WQE * ibmf_send_wqes_per_port) +
	    (IBMF_MEM_PER_WQE * ibmf_recv_wqes_per_port);
	wqe_mgtp->wqes_kmem = kmem_zalloc(wqe_mgtp->wqes_kmem_sz, KM_SLEEP);

	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)wqe_mgtp->wqes_kmem;
	mem_attr.mr_len = wqe_mgtp->wqes_kmem_sz;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	mem_attr.mr_as = NULL;

	/* Register the allocated memory */
	status = ibt_register_mr(qp_ctx->isq_client_hdl->ic_myci->ci_ci_handle,
	    qp_ctx->isq_client_hdl->ic_myci->ci_pd, &mem_attr, &mem_hdl,
	    &mem_desc);
	if (status != IBT_SUCCESS) {
		kmem_free(wqe_mgtp->wqes_kmem, wqe_mgtp->wqes_kmem_sz);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_init_altqp_wqes_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_init_altqp_wqes(): %s, status = %d\n",
		    tnf_string, msg,
		    "register of WQE mem failed", tnf_uint, status, status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_init_altqp_wqes_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_init_altqp_wqes() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	/* Store the memory registration information */
	wqe_mgtp->wqes_ib_mem = mem_desc.md_vaddr;
	wqe_mgtp->wqes_ib_lkey = mem_desc.md_lkey;
	wqe_mgtp->wqes_ib_mem_hdl = mem_hdl;

	/* Create a vmem arena for the IB virtual address space */
	bzero(string, 128);
	(void) sprintf(string, "ibmf_%016" PRIx64 "_%x_wqes",
	    qp_ctx->isq_client_hdl->ic_client_info.ci_guid, qp_ctx->isq_qpn);
	qp_ctx->isq_wqe_ib_vmem = vmem_create(string,
	    (void *)(uintptr_t)wqe_mgtp->wqes_ib_mem, wqe_mgtp->wqes_kmem_sz,
	    sizeof (uint64_t), NULL, NULL, NULL, 0, VM_SLEEP);

	bzero(string, 128);
	/*
	 * CAUTION: Do not exceed 32 characters for the kmem cache name, else,
	 * mdb does not exit (bug 4878751). There is some connection between
	 * mdb walkers and kmem_caches with the limitation likely to be in the
	 * mdb code.
	 */
	(void) sprintf(string, "ibmf%016" PRIx64 "_%xs",
	    qp_ctx->isq_client_hdl->ic_client_info.ci_guid, qp_ctx->isq_qpn);
	/* create a kmem cache for the send WQEs */
	qp_ctx->isq_send_wqes_cache = kmem_cache_create(string,
	    sizeof (ibmf_send_wqe_t), 0, ibmf_altqp_send_wqe_cache_constructor,
	    ibmf_altqp_send_wqe_cache_destructor, NULL, (void *)qp_ctx,
	    NULL, 0);

	bzero(string, 128);
	(void) sprintf(string, "ibmf%016" PRIx64 "_%xr",
	    qp_ctx->isq_client_hdl->ic_client_info.ci_guid, qp_ctx->isq_qpn);
	/* create a kmem cache for the receive WQEs */
	qp_ctx->isq_recv_wqes_cache = kmem_cache_create(string,
	    sizeof (ibmf_recv_wqe_t), 0, ibmf_altqp_recv_wqe_cache_constructor,
	    ibmf_altqp_recv_wqe_cache_destructor, NULL, (void *)qp_ctx,
	    NULL, 0);

	mutex_enter(&qp_ctx->isq_wqe_mutex);
	qp_ctx->isq_wqe_mgt_list = wqe_mgtp;
	mutex_exit(&qp_ctx->isq_wqe_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_altqp_wqes_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_altqp_wqes() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_fini_altqp_wqes():
 *	Destroy the kmem cache for send and receive WQEs for alternate QPs
 */
void
ibmf_i_fini_altqp_wqes(ibmf_alt_qp_t *qp_ctx)
{
	ibmf_wqe_mgt_t	*wqe_mgt;
	ibt_mr_hdl_t	wqe_ib_mem_hdl;
	void		*wqe_kmem;
	uint64_t	wqe_kmem_sz;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_wqes_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_wqes() enter, qp_ctx = %p\n",
	    tnf_opaque, qp, qp_ctx);

	mutex_enter(&qp_ctx->isq_wqe_mutex);
	wqe_mgt = qp_ctx->isq_wqe_mgt_list;
	while (wqe_mgt != NULL) {
		/* Remove the WQE mgt struct from the list */
		qp_ctx->isq_wqe_mgt_list = wqe_mgt->wqe_mgt_next;
		mutex_exit(&qp_ctx->isq_wqe_mutex);

		mutex_enter(&wqe_mgt->wqes_mutex);
		wqe_ib_mem_hdl = wqe_mgt->wqes_ib_mem_hdl;
		wqe_kmem = wqe_mgt->wqes_kmem;
		wqe_kmem_sz = wqe_mgt->wqes_kmem_sz;
		mutex_exit(&wqe_mgt->wqes_mutex);

		/* Deregister the memory allocated for the WQEs */
		(void) ibt_deregister_mr(
		    qp_ctx->isq_client_hdl->ic_myci->ci_ci_handle,
		    wqe_ib_mem_hdl);

		/* Free the kmem allocated for the WQEs */
		kmem_free(wqe_kmem, wqe_kmem_sz);

		/* Destroy the WQE mgt struct mutex */
		mutex_destroy(&wqe_mgt->wqes_mutex);

		/* Free the WQE management structure */
		kmem_free(wqe_mgt, sizeof (ibmf_wqe_mgt_t));

		mutex_enter(&qp_ctx->isq_wqe_mutex);
		wqe_mgt = qp_ctx->isq_wqe_mgt_list;
	}

	mutex_exit(&qp_ctx->isq_wqe_mutex);

	/* Destroy the kmem_cache for the send WQE */
	kmem_cache_destroy(qp_ctx->isq_send_wqes_cache);
	/* Destroy the kmem_cache for the receive WQE */
	kmem_cache_destroy(qp_ctx->isq_recv_wqes_cache);

	/*
	 * Destroy the vmem arena for the WQEs
	 * This must be done after the kmem_cache_destroy() calls since
	 * the cache destructors call vmem_free()
	 */
	vmem_destroy((void *)qp_ctx->isq_wqe_ib_vmem);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_fini_wqes_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_fini_wqes() exit\n");
}

/*
 * ibmf_i_init_send_wqe():
 *	Initialize a send WQE
 */
/* ARGSUSED */
void
ibmf_i_init_send_wqe(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    ibt_wr_ds_t *sglp, ibmf_send_wqe_t *wqep, ibt_ud_dest_hdl_t ud_dest,
    ibt_qp_hdl_t ibt_qp_handle, ibmf_qp_handle_t ibmf_qp_handle)
{
	ibmf_msg_bufs_t	*ipbufs = &msgimplp->im_msgbufs_send;
	ibmf_msg_bufs_t	*hdr_ipbufs;
	ib_mad_hdr_t	*ibmadhdrp;
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ibmf_rmpp_hdr_t	*rmpp_hdr;
	ibt_send_wr_t	*swrp;
	uchar_t		*buf;
	size_t		data_sz, offset;
	uint32_t	cl_hdr_sz, cl_hdr_off;

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_send_wqe_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_send_wqe() enter, "
	    "clientp = %p, msg = %p, sglp = %p , wqep = %p, qp_hdl = %p\n",
	    tnf_opaque, clientp, clientp, tnf_opaque, msg, msgimplp,
	    tnf_opaque, sglp, sglp, tnf_opaque, wqep, wqep,
	    tnf_opaque, qp_hdl, ibmf_qp_handle);

	_NOTE(ASSUMING_PROTECTED(*wqep))
	_NOTE(ASSUMING_PROTECTED(*sglp))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrp))

	swrp = &wqep->send_wr;
	/* use send wqe pointer as the WR ID */
	IBMF_ADDR_TO_SEND_WR_ID(wqep, swrp->wr_id);
	ASSERT(swrp->wr_id != NULL);
	swrp->wr_flags = IBT_WR_NO_FLAGS;
	swrp->wr_opcode = IBT_WRC_SEND;
	swrp->wr_trans = IBT_UD_SRV;
	wqep->send_client = clientp;
	wqep->send_msg = msgimplp;

	IBMF_INIT_SG_ELEMENT(sglp[0], wqep->send_mem, wqep->send_sg_lkey,
	    IBMF_MAD_SIZE);

	bzero(wqep->send_mem, IBMF_MAD_SIZE);
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP) {
		buf = (uchar_t *)ipbufs->im_bufs_cl_data +
		    (rmpp_ctx->rmpp_ns - 1) * rmpp_ctx->rmpp_pkt_data_sz;
		data_sz = (rmpp_ctx->rmpp_ns == rmpp_ctx->rmpp_num_pkts) ?
		    rmpp_ctx->rmpp_last_pkt_sz : rmpp_ctx->rmpp_pkt_data_sz;
	} else {
		buf = ipbufs->im_bufs_cl_data;
		data_sz = ipbufs->im_bufs_cl_data_len;
	}

	/*
	 * We pick the correct msgbuf based on the nature of the transaction.
	 * Where the send msgbuf is available, we pick it to provide the
	 * context of the outgoing MAD. Note that if this is a termination
	 * context, then  the send buffer is invalid even if the sequenced
	 * flags is set because the termination message only has a receive
	 * buffer set up.
	 */
	if ((msgimplp->im_flags & IBMF_MSG_FLAGS_SEQUENCED) &&
	    ((msgimplp->im_flags & IBMF_MSG_FLAGS_TERMINATION) == 0)) {
		hdr_ipbufs = &msgimplp->im_msgbufs_send;
	} else if (msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) {
		hdr_ipbufs = &msgimplp->im_msgbufs_recv;
	} else if (msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP) {
		hdr_ipbufs = &msgimplp->im_msgbufs_send;
	} else {
		if (msgimplp->im_unsolicited == B_TRUE) {
			hdr_ipbufs = &msgimplp->im_msgbufs_recv;
		} else {
			hdr_ipbufs = &msgimplp->im_msgbufs_send;
		}
	}

	bcopy((void *)hdr_ipbufs->im_bufs_mad_hdr,
	    (void *)wqep->send_mem, sizeof (ib_mad_hdr_t));

	/*
	 * For unsolicited messages, we only have the sender's MAD at hand.
	 * So, we must flip the response bit in the method for the outgoing MAD.
	 */
	ibmadhdrp = (ib_mad_hdr_t *)wqep->send_mem;
	if (msgimplp->im_unsolicited == B_TRUE) {
		ibmadhdrp->R_Method = IBMF_FLIP_RESP_BIT(ibmadhdrp->R_Method);
	}

	offset = sizeof (ib_mad_hdr_t);

	if ((msgimplp->im_flags & IBMF_MSG_FLAGS_SEND_RMPP) ||
	    (msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP)) {

		rmpp_hdr = (ibmf_rmpp_hdr_t *)
		    ((uintptr_t)wqep->send_mem + offset);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rmpp_hdr));

		IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_init_send_wqe,
		    IBMF_TNF_TRACE, "",
		    "ibmf_init_send_wqe: msgimplp = %p, rmpp_type = %d,"
		    " next_seg = %d, num_pkts = %d\n",
		    tnf_opaque, msgimplp, msgimplp,
		    tnf_opaque, rmpp_type, rmpp_ctx->rmpp_type,
		    tnf_opaque, next_seg, rmpp_ctx->rmpp_ns,
		    tnf_opaque, num_pkts, rmpp_ctx->rmpp_num_pkts);

		/*
		 * Initialize the RMPP header
		 */
		rmpp_ctx->rmpp_flags = IBMF_RMPP_FLAGS_ACTIVE;

		/* first, last packet flags set only for type DATA */
		if (rmpp_ctx->rmpp_type == IBMF_RMPP_TYPE_DATA) {

			if (rmpp_ctx->rmpp_ns == 1)
				rmpp_ctx->rmpp_flags |=
				    IBMF_RMPP_FLAGS_FIRST_PKT;
			else
				rmpp_ctx->rmpp_respt = IBMF_RMPP_DEFAULT_RRESPT;

			if (rmpp_ctx->rmpp_ns == rmpp_ctx->rmpp_num_pkts)
				rmpp_ctx->rmpp_flags |=
				    IBMF_RMPP_FLAGS_LAST_PKT;
		} else {
			data_sz = 0;
			rmpp_ctx->rmpp_respt = IBMF_RMPP_TERM_RRESPT;
		}

		IBMF_INIT_RMPP_HDR(rmpp_hdr,
		    IBMF_RMPP_VERSION, rmpp_ctx->rmpp_type,
		    rmpp_ctx->rmpp_respt, rmpp_ctx->rmpp_flags,
		    rmpp_ctx->rmpp_status, rmpp_ctx->rmpp_word3,
		    rmpp_ctx->rmpp_word4)

		IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_i_init_send_wqe,
		    IBMF_TNF_TRACE, "",
		    "ibmf_init_send_wqe: msgimplp = %p, rmpp_type = %d,"
		    " rmpp_flags = 0x%x, rmpp_segnum = %d, pyld_nwl = %d\n",
		    tnf_opaque, msgimplp, msgimplp,
		    tnf_opaque, rmpp_type, rmpp_hdr->rmpp_type,
		    tnf_opaque, rmpp_flags, rmpp_hdr->rmpp_flags,
		    tnf_opaque, rmpp_segnum, b2h32(rmpp_hdr->rmpp_segnum),
		    tnf_opaque, pyld_nwl, b2h32(rmpp_hdr->rmpp_pyldlen_nwl));

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(rmpp_hdr));
	}

	/* determine offset to start class header */
	ibmf_i_mgt_class_to_hdr_sz_off(
	    hdr_ipbufs->im_bufs_mad_hdr->MgmtClass,
	    &cl_hdr_sz, &cl_hdr_off);
	offset += cl_hdr_off;
	if (hdr_ipbufs->im_bufs_cl_hdr != NULL) {
		bcopy((void *)hdr_ipbufs->im_bufs_cl_hdr,
		    (void *)((uintptr_t)wqep->send_mem + offset),
		    hdr_ipbufs->im_bufs_cl_hdr_len);
		offset += hdr_ipbufs->im_bufs_cl_hdr_len;
	}
	bcopy((void *)buf, (void *)((uintptr_t)wqep->send_mem + offset),
	    data_sz);
	swrp->wr_sgl = sglp;
	swrp->wr_nds = 1;
	swrp->wr.ud.udwr_dest = ud_dest;
	wqep->send_port_num = clientp->ic_client_info.port_num;
	wqep->send_qp_handle = ibt_qp_handle;
	wqep->send_ibmf_qp_handle = ibmf_qp_handle;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*swrp))

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_send_wqe_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_send_wqe() exit\n");
}

/*
 * ibmf_i_init_recv_wqe():
 *	Initialize a receive WQE
 */
void
ibmf_i_init_recv_wqe(ibmf_qp_t *qpp, ibt_wr_ds_t *sglp,
    ibmf_recv_wqe_t *wqep, ibt_qp_hdl_t ibt_qp_handle,
    ibmf_qp_handle_t ibmf_qp_handle)
{
	ibt_recv_wr_t		*rwrp;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_recv_wqe_start,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_recv_wqe() enter, "
	    "qpp = %p, sglp = %p , wqep = %p, ud_dest = %p, qp_hdl = %p\n",
	    tnf_opaque, qpp, qpp, tnf_opaque, sglp, sglp, tnf_opaque,
	    wqep, wqep, tnf_opaque, qp_hdl, ibmf_qp_handle);

	_NOTE(ASSUMING_PROTECTED(*wqep))
	_NOTE(ASSUMING_PROTECTED(*sglp))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rwrp))

	rwrp = &wqep->recv_wr;

	/*
	 * we set a bit in the WR ID to be able to easily distinguish
	 * between send completions and recv completions
	 */
	IBMF_ADDR_TO_RECV_WR_ID(wqep, rwrp->wr_id);

	IBMF_INIT_SG_ELEMENT(sglp[0], wqep->recv_mem, wqep->recv_sg_lkey,
	    sizeof (ib_grh_t) + IBMF_MAD_SIZE);

	rwrp->wr_sgl = sglp;
	rwrp->wr_nds = IBMF_MAX_RQ_WR_SGL_ELEMENTS;
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		wqep->recv_port_num = qpp->iq_port_num;
	} else {
		ibmf_alt_qp_t	*altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		wqep->recv_port_num = altqp->isq_port_num;
	}
	wqep->recv_qpp = qpp;
	wqep->recv_qp_handle = ibt_qp_handle;
	wqep->recv_ibmf_qp_handle = ibmf_qp_handle;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rwrp))

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_init_recv_wqe_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_init_recv_wqe() exit\n");
}

/*
 * ibmf_i_extend_wqe_cache():
 *	Extend the kmem WQE cache
 */
int
ibmf_i_extend_wqe_cache(ibmf_ci_t *cip, ibmf_qp_handle_t ibmf_qp_handle,
    boolean_t block)
{
	ibmf_wqe_mgt_t		*wqe_mgt;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_extend_wqe_cache_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_extend_wqe_cache() enter, cip = %p, qp_hdl = %p, "
	    " block = %d\n", tnf_opaque, cip, cip, tnf_opaque, qp_hdl,
	    ibmf_qp_handle, tnf_uint, block, block);

	/*
	 * Allocate memory for the WQE management structure
	 */
	wqe_mgt = kmem_zalloc(sizeof (ibmf_wqe_mgt_t),
	    (block == B_TRUE ? KM_SLEEP : KM_NOSLEEP));
	if (wqe_mgt == NULL) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_extend_wqe_cache_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_extend_wqe_cache(): %s\n",
		    tnf_string, msg, "wqe mgt alloc failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_extend_wqe_cache_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_extend_wqe_cache() exit\n");
		return (IBMF_NO_RESOURCES);
	}
	mutex_init(&wqe_mgt->wqes_mutex, NULL, MUTEX_DRIVER, NULL);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wqe_mgt))

	/* Allocate and register more WQE memory */
	if (ibmf_i_extend_wqe_mem(cip, ibmf_qp_handle, wqe_mgt,
	    block) != IBMF_SUCCESS) {
		mutex_destroy(&wqe_mgt->wqes_mutex);
		kmem_free(wqe_mgt, sizeof (ibmf_wqe_mgt_t));
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_extend_wqe_cache_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_extend_wqe_cache(): %s\n",
		    tnf_string, msg, "extension of WQE pool failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_extend_wqe_cache_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_extend_wqe_cache() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_extend_wqe_cache_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_extend_wqe_cache() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_extend_wqe_mem():
 *	Allocate and register more WQE memory, and expand the VMEM arena
 */
static int
ibmf_i_extend_wqe_mem(ibmf_ci_t *cip, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_wqe_mgt_t *wqe_mgt, boolean_t block)
{
	ibt_status_t		status;
	ibt_mr_hdl_t		mem_hdl;
	ibt_mr_desc_t		mem_desc;
	ibt_mr_attr_t		mem_attr;
	ibmf_alt_qp_t		*qp_ctx;
	ibmf_wqe_mgt_t		*pwqe_mgt;
	vmem_t			*wqe_vmem_arena;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wqe_mgt))

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_extend_wqe_cache_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_extend_wqe_cache() enter, cip = %p, qp_hdl = %p"
	    "wqe_mgt = %p, block = %d\n",
	    tnf_opaque, cip, cip, tnf_opaque, qp_hdl, ibmf_qp_handle,
	    tnf_opaque, wqe_mgt, wqe_mgt, tnf_uint, block, block);

	/*
	 * Allocate more memory for the WQEs to be used by the
	 * specified QP
	 */
	wqe_mgt->wqes_kmem_sz = cip->ci_nports * 2 *
	    ((IBMF_MEM_PER_WQE * ibmf_send_wqes_per_port) +
	    (IBMF_MEM_PER_WQE * ibmf_recv_wqes_per_port));
	wqe_mgt->wqes_kmem = kmem_zalloc(wqe_mgt->wqes_kmem_sz,
	    (block == B_TRUE ? KM_SLEEP : KM_NOSLEEP));
	if (wqe_mgt->wqes_kmem == NULL) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_extend_wqe_mem_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_extend_wqe_mem(): %s\n",
		    tnf_string, msg, "extension of WQE pool failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_extend_wqe_mem_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_extend_wqe_mem() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)wqe_mgt->wqes_kmem;
	mem_attr.mr_len = wqe_mgt->wqes_kmem_sz;
	mem_attr.mr_flags = (block == B_TRUE ? IBT_MR_SLEEP : IBT_MR_NOSLEEP)
	    | IBT_MR_ENABLE_LOCAL_WRITE;
	mem_attr.mr_as = NULL;

	/* Register the allocated memory */
	status = ibt_register_mr(cip->ci_ci_handle, cip->ci_pd,
	    &mem_attr, &mem_hdl, &mem_desc);
	if (status != IBT_SUCCESS) {
		kmem_free(wqe_mgt->wqes_kmem, wqe_mgt->wqes_kmem_sz);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_extend_wqe_mem_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_extend_wqe_mem(): %s\n",
		    tnf_string, msg, "wqe extension MR failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_extend_wqe_mem_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_extend_wqe_mem() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	/* Store the memory registration information */
	wqe_mgt->wqes_ib_mem = mem_desc.md_vaddr;
	wqe_mgt->wqes_ib_lkey = mem_desc.md_lkey;
	wqe_mgt->wqes_ib_mem_hdl = mem_hdl;

	/* Get the VMEM arena based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		wqe_vmem_arena = cip->ci_wqe_ib_vmem;
	} else {
		qp_ctx = (ibmf_alt_qp_t *)ibmf_qp_handle;
		wqe_vmem_arena = qp_ctx->isq_wqe_ib_vmem;
	}

	/* Add these addresses to the vmem arena */
	if (vmem_add(wqe_vmem_arena, (void *)(uintptr_t)wqe_mgt->wqes_ib_mem,
	    wqe_mgt->wqes_kmem_sz,
	    (block == B_TRUE ? VM_SLEEP : VM_NOSLEEP)) == NULL) {
		(void) ibt_deregister_mr(cip->ci_ci_handle,
		    wqe_mgt->wqes_ib_mem_hdl);
		kmem_free(wqe_mgt->wqes_kmem, wqe_mgt->wqes_kmem_sz);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_extend_wqe_mem_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_extend_wqe_mem(): %s\n",
		    tnf_string, msg, "wqe extension vmem_add failed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_extend_wqe_mem_end, IBMF_TNF_TRACE, "",
		    "ibmf_i_extend_wqe_mem() exit\n");
		return (IBMF_NO_RESOURCES);
	}

	/* Get the WQE management pointers based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&cip->ci_wqe_mutex);
		pwqe_mgt = cip->ci_wqe_mgt_list;

		/* Add the new wqe management struct to the end of the list */
		while (pwqe_mgt->wqe_mgt_next != NULL)
			pwqe_mgt = pwqe_mgt->wqe_mgt_next;
		pwqe_mgt->wqe_mgt_next = wqe_mgt;

		mutex_exit(&cip->ci_wqe_mutex);
	} else {
		mutex_enter(&qp_ctx->isq_wqe_mutex);
		pwqe_mgt = qp_ctx->isq_wqe_mgt_list;

		/* Add the new wqe management struct to the end of the list */
		while (pwqe_mgt->wqe_mgt_next != NULL)
			pwqe_mgt = pwqe_mgt->wqe_mgt_next;
		pwqe_mgt->wqe_mgt_next = wqe_mgt;

		mutex_exit(&qp_ctx->isq_wqe_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_extend_wqe_mem_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_extend_wqe_mem() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_alloc_send_resources():
 *	Allocate send resources (the send WQE)
 */
int
ibmf_i_alloc_send_resources(ibmf_ci_t *cip, ibmf_msg_impl_t *msgimplp,
    boolean_t block, ibmf_send_wqe_t **swqepp)
{
	ibmf_send_wqe_t		*send_wqep;
	struct kmem_cache	*kmem_cachep;
	ibmf_qp_handle_t	ibmf_qp_handle = msgimplp->im_qp_hdl;
	ibmf_alt_qp_t		*altqp;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_alloc_send_resources_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_alloc_send_resources() enter, cip = %p, msg = %p, "
	    " block = %d\n", tnf_opaque, cip, cip, tnf_opaque, msg,
	    msgimplp, tnf_uint, block, block);

	/* Get the WQE kmem cache pointer based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT)
		kmem_cachep = cip->ci_send_wqes_cache;
	else {
		altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		kmem_cachep = altqp->isq_send_wqes_cache;
	}

	/*
	 * Allocate a send WQE from the send WQE kmem cache
	 * Do not block here as we are holding the msgimpl mutex.
	 */
	send_wqep = kmem_cache_alloc(kmem_cachep, KM_NOSLEEP);
	if (send_wqep == NULL) {
		/*
		 * Attempt to extend the cache and then retry the
		 * kmem_cache_alloc()
		 * The block argument (third) is set to B_FALSE.
		 */
		if (ibmf_i_extend_wqe_cache(cip, ibmf_qp_handle, B_FALSE) ==
		    IBMF_NO_RESOURCES) {
			mutex_enter(&cip->ci_mutex);
			IBMF_ADD32_PORT_KSTATS(cip, swqe_allocs_failed, 1);
			mutex_exit(&cip->ci_mutex);
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_alloc_send_resources_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_alloc_send_resources(): %s\n",
			    tnf_string, msg, "alloc send_wqe failed");
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_alloc_send_resources_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_alloc_send_resources() exit\n");
			return (IBMF_NO_RESOURCES);
		} else {
			send_wqep = kmem_cache_alloc(kmem_cachep, KM_NOSLEEP);
			if (send_wqep == NULL) {
				/* Allocation failed again. Give up here. */
				mutex_enter(&cip->ci_mutex);
				IBMF_ADD32_PORT_KSTATS(cip, swqe_allocs_failed,
				    1);
				mutex_exit(&cip->ci_mutex);
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_alloc_send_resources_err,
				    IBMF_TNF_ERROR, "",
				    "ibmf_i_alloc_send_resources(): %s\n",
				    tnf_string, msg, "alloc send_wqe failed");
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_alloc_send_resources_end,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_alloc_send_resources() exit\n");
				return (IBMF_NO_RESOURCES);
			}
		}
	}

	mutex_enter(&cip->ci_mutex);
	IBMF_ADD32_PORT_KSTATS(cip, send_wqes_alloced, 1);
	mutex_exit(&cip->ci_mutex);
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&cip->ci_mutex);
		cip->ci_wqes_alloced++;
		mutex_exit(&cip->ci_mutex);
	} else {
		mutex_enter(&altqp->isq_mutex);
		altqp->isq_wqes_alloced++;
		mutex_exit(&altqp->isq_mutex);
	}

	send_wqep->send_msg = msgimplp;
	*swqepp = send_wqep;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_alloc_send_resources_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_alloc_send_resources() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_i_free_send_resources():
 *	Free send resources (just the send WQE)
 */
/* ARGSUSED */
void
ibmf_i_free_send_resources(ibmf_ci_t *cip, ibmf_msg_impl_t *msgimplp,
    ibmf_send_wqe_t *swqep)
{
	struct kmem_cache	*kmem_cachep;
	ibmf_qp_handle_t	ibmf_qp_handle = msgimplp->im_qp_hdl;
	ibmf_alt_qp_t		*altqp;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_free_send_resources_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_free_send_resources() enter, cip = %p, msg = %p, "
	    " swqep = %p\n", tnf_opaque, cip, cip, tnf_opaque, msg,
	    msgimplp, tnf_opaque, swqep, swqep);

	/* Get the WQE kmem cache pointer based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT)
		kmem_cachep = cip->ci_send_wqes_cache;
	else {
		altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		kmem_cachep = altqp->isq_send_wqes_cache;
	}

	/* return the send WQE to the kmem cache */
	kmem_cache_free(kmem_cachep, swqep);

	mutex_enter(&cip->ci_mutex);
	IBMF_SUB32_PORT_KSTATS(cip, send_wqes_alloced, 1);
	mutex_exit(&cip->ci_mutex);
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&cip->ci_mutex);
		cip->ci_wqes_alloced--;
		if (cip->ci_wqes_alloced == 0)
			cv_signal(&cip->ci_wqes_cv);
		mutex_exit(&cip->ci_mutex);
	} else {
		mutex_enter(&altqp->isq_mutex);
		altqp->isq_wqes_alloced--;
		if (altqp->isq_wqes_alloced == 0)
			cv_signal(&altqp->isq_wqes_cv);
		mutex_exit(&altqp->isq_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_free_send_resources_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_free_send_resources() exit\n");
}
