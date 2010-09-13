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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>

#include <sys/ib/clients/eoib/enx_impl.h>

/*
 * Module (static) info passed to IBTL during ibt_attach
 */
static ibt_clnt_modinfo_t eibnx_clnt_modinfo = {
	IBTI_V_CURR,
	IBT_GENERIC,
	eibnx_async_handler,
	NULL,
	"EoIB Nexus"
};

ib_gid_t enx_advertise_mgid;
ib_gid_t enx_solicit_mgid;

/*
 * Static function declarations
 */
static int eibnx_state_init(void);
static int eibnx_setup_txbufs(eibnx_thr_info_t *);
static int eibnx_setup_rxbufs(eibnx_thr_info_t *);
static int eibnx_join_solicit_mcg(eibnx_thr_info_t *);
static int eibnx_join_advertise_mcg(eibnx_thr_info_t *);
static int eibnx_rb_ibt_init(eibnx_t *);
static void eibnx_rb_state_init(void);
static void eibnx_rb_setup_txbufs(eibnx_thr_info_t *);
static void eibnx_rb_setup_rxbufs(eibnx_thr_info_t *);
static void eibnx_rb_join_solicit_mcg(eibnx_thr_info_t *);
static void eibnx_rb_join_advertise_mcg(eibnx_thr_info_t *);

/*
 * eibnx_ibt_init() is expected to be called during the nexus driver's
 * attach time; given that there is only one instance of the nexus
 * driver allowed, and no threads are active before the initialization
 * is complete, we don't really have to acquire any driver specific mutex
 * within this routine.
 */
int
eibnx_ibt_init(eibnx_t *ss)
{
	eibnx_hca_t *hca_list;
	eibnx_hca_t *hca_tail;
	eibnx_hca_t *hca;
	uint_t num_hcas;
	ib_guid_t *hca_guids;
	ibt_status_t ret;
	int i;

	/*
	 * Do per-state initialization
	 */
	(void) eibnx_state_init();

	/*
	 * Attach to IBTL
	 */
	if ((ret = ibt_attach(&eibnx_clnt_modinfo, ss->nx_dip, ss,
	    &ss->nx_ibt_hdl)) != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_attach() failed, ret=%d", ret);
		eibnx_rb_state_init();
		return (ENX_E_FAILURE);
	}

	/*
	 * Get the list of HCA guids on the system
	 */
	if ((num_hcas = ibt_get_hca_list(&hca_guids)) == 0) {
		ENX_DPRINTF_VERBOSE("no HCAs found on the system");
		if ((ret = ibt_detach(ss->nx_ibt_hdl)) != IBT_SUCCESS) {
			ENX_DPRINTF_ERR("ibt_detach() failed, ret=%d", ret);
		}
		ss->nx_ibt_hdl = NULL;
		return (ENX_E_FAILURE);
	}

	/*
	 * Open the HCAs and store the handles
	 */
	hca_list = hca_tail = NULL;
	for (i = 0; i < num_hcas; i++) {
		/*
		 * If we cannot open a HCA, allocate a protection domain
		 * on it or get portinfo on it, print an error and move on
		 * to the next HCA.  Otherwise, queue it up in our hca list
		 */
		if ((hca = eibnx_prepare_hca(hca_guids[i])) == NULL)
			continue;

		if (hca_tail) {
			hca_tail->hc_next = hca;
		} else {
			hca_list = hca;
		}
		hca_tail = hca;
	}

	/*
	 * Free the HCA guid list we've allocated via ibt_get_hca_list()
	 */
	ibt_free_hca_list(hca_guids, num_hcas);

	/*
	 * Put the hca list in the state structure
	 */
	mutex_enter(&ss->nx_lock);
	ss->nx_hca = hca_list;
	mutex_exit(&ss->nx_lock);

	/*
	 * Register for subnet notices
	 */
	ibt_register_subnet_notices(ss->nx_ibt_hdl,
	    eibnx_subnet_notices_handler, ss);

	return (ENX_E_SUCCESS);
}

static int
eibnx_state_init(void)
{
	eibnx_t *ss = enx_global_ss;
	kthread_t *kt;

	/*
	 * Initialize synchronization primitives
	 */
	mutex_init(&ss->nx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ss->nx_nodeq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ss->nx_nodeq_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&ss->nx_busop_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ss->nx_busop_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Initialize well-known mgids: there must be a better way to
	 * do this instead of having to express every single gid as a
	 * tuple of two 8-byte integer quantities.
	 */
	enx_solicit_mgid.gid_prefix = EIB_GUID_SOLICIT_PREFIX;
	enx_solicit_mgid.gid_guid = 0;
	enx_advertise_mgid.gid_prefix = EIB_GUID_ADVERTISE_PREFIX;
	enx_advertise_mgid.gid_guid = 0;

	/*
	 * Start up the eoib node creation thread
	 */
	kt = thread_create(NULL, 0, eibnx_create_eoib_node, NULL, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->nx_nodeq_kt_did = kt->t_did;

	return (ENX_E_SUCCESS);
}

/*
 * Locate the two multicast groups: the All-EoIB-GWs-GID and
 * All-EoIB-ENodes-GID.  Make sure the MTU is something that
 * we can work with and Qkey is as expected.
 */
int
eibnx_find_mgroups(eibnx_thr_info_t *info)
{
	ibt_hca_portinfo_t *pi = info->ti_pi;
	ibt_mcg_attr_t mcg_attr;
	ib_gid_t rgid;
	ibt_status_t ret;
	uint_t entries;

	mutex_enter(&info->ti_mcg_lock);

	if ((info->ti_mcg_status & ENX_MCGS_FOUND) == ENX_MCGS_FOUND) {
		mutex_exit(&info->ti_mcg_lock);
		return (ENX_E_SUCCESS);
	}

	/*
	 * Request GID defining this port
	 */
	rgid = pi->p_sgid_tbl[0];

	/*
	 * First, locate the multicast group to use for sending solicit
	 * requests to the GW
	 */
	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));
	mcg_attr.mc_mgid = enx_solicit_mgid;
	mcg_attr.mc_pkey = (ib_pkey_t)EIB_ADMIN_PKEY;
	mcg_attr.mc_qkey = (ib_qkey_t)EIB_FIP_QKEY;

	if ((ret = ibt_query_mcg(rgid, &mcg_attr, 1, &info->ti_solicit_mcg,
	    &entries)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("solicit mcg (gid=%llx.%llx) not found, "
		    "ibt_query_mcg() returned %d", enx_solicit_mgid.gid_prefix,
		    enx_solicit_mgid.gid_guid, ret);
		goto find_mgroups_fail;
	}

	/*
	 * Make sure the multicast mtu isn't bigger than the port mtu
	 * and the multicast group's qkey is the same as EIB_FIP_QKEY.
	 */
	if (info->ti_solicit_mcg->mc_mtu > pi->p_mtu) {
		ENX_DPRINTF_WARN("solicit mcg (gid=%llx.%llx) mtu too big, "
		    "0x%x > 0x%x", enx_solicit_mgid.gid_prefix,
		    enx_solicit_mgid.gid_guid, info->ti_solicit_mcg->mc_mtu,
		    pi->p_mtu);
		goto find_mgroups_fail;
	}
	if (info->ti_solicit_mcg->mc_qkey != EIB_FIP_QKEY) {
		ENX_DPRINTF_WARN("solicit mcg (gid=%llx.%llx) qkey bad, "
		    "actual=0x%x, expected=0x%x", enx_solicit_mgid.gid_prefix,
		    enx_solicit_mgid.gid_guid, info->ti_solicit_mcg->mc_qkey,
		    EIB_FIP_QKEY);
		goto find_mgroups_fail;
	}

	/*
	 * Now, locate the multicast group for receiving discover
	 * advertisements from the GW
	 */
	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));
	mcg_attr.mc_mgid = enx_advertise_mgid;
	mcg_attr.mc_pkey = (ib_pkey_t)EIB_ADMIN_PKEY;
	mcg_attr.mc_qkey = (ib_qkey_t)EIB_FIP_QKEY;

	if ((ret = ibt_query_mcg(rgid, &mcg_attr, 1, &info->ti_advertise_mcg,
	    &entries)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("advertise mcg (gid=%llx.%llx) not found, "
		    "ibt_query_mcg() returned %d",
		    enx_advertise_mgid.gid_prefix,
		    enx_advertise_mgid.gid_guid, ret);
		goto find_mgroups_fail;
	}

	/*
	 * Verify the multicast group's mtu and qkey as before
	 */
	if (info->ti_advertise_mcg->mc_mtu > pi->p_mtu) {
		ENX_DPRINTF_WARN("advertise mcg (gid=%llx.%llx) mtu too big, "
		    "0x%x > 0x%x", enx_advertise_mgid.gid_prefix,
		    enx_advertise_mgid.gid_guid,
		    info->ti_advertise_mcg->mc_mtu, pi->p_mtu);
		goto find_mgroups_fail;
	}
	if (info->ti_advertise_mcg->mc_qkey != EIB_FIP_QKEY) {
		ENX_DPRINTF_WARN("advertise mcg (gid=%llx.%llx) qkey bad, "
		    "actual=0x%x, expected=0x%x",
		    enx_advertise_mgid.gid_prefix, enx_advertise_mgid.gid_guid,
		    info->ti_advertise_mcg->mc_qkey, EIB_FIP_QKEY);
		goto find_mgroups_fail;
	}

	info->ti_mcg_status |= ENX_MCGS_FOUND;
	mutex_exit(&info->ti_mcg_lock);

	return (ENX_E_SUCCESS);

find_mgroups_fail:
	if (info->ti_advertise_mcg) {
		ibt_free_mcg_info(info->ti_advertise_mcg, 1);
		info->ti_advertise_mcg = NULL;
	}
	if (info->ti_solicit_mcg) {
		ibt_free_mcg_info(info->ti_solicit_mcg, 1);
		info->ti_solicit_mcg = NULL;
	}
	mutex_exit(&info->ti_mcg_lock);

	return (ENX_E_FAILURE);
}

/*
 * Allocate and setup a single completion queue for tx and rx
 */
int
eibnx_setup_cq(eibnx_thr_info_t *info)
{
	ibt_hca_attr_t hca_attr;
	ibt_cq_attr_t cq_attr;
	ibt_status_t ret;
	uint_t sz;

	/*
	 * Get this HCA's attributes
	 */
	ret = ibt_query_hca(info->ti_hca, &hca_attr);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_query_hca(hca_hdl=0x%llx) failed, ret=%d",
		    info->ti_hca, ret);
		return (ENX_E_FAILURE);
	}

	/*
	 * Allocate a completion queue for our sends and receives
	 */
	cq_attr.cq_sched = NULL;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;
	cq_attr.cq_size = (hca_attr.hca_max_cq_sz < ENX_CQ_SIZE) ?
	    hca_attr.hca_max_cq_sz : ENX_CQ_SIZE;

	ret = ibt_alloc_cq(info->ti_hca, &cq_attr, &info->ti_cq_hdl, &sz);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_alloc_cq(hca_hdl=0x%llx, cq_sz=0x%lx) "
		    "failed, ret=%d", info->ti_hca, cq_attr.cq_size, ret);
		return (ENX_E_FAILURE);
	}

	/*
	 * Set up other parameters for collecting completion information
	 */
	info->ti_cq_sz = sz;
	info->ti_wc = kmem_zalloc(sizeof (ibt_wc_t) * sz, KM_SLEEP);

	return (ENX_E_SUCCESS);
}

/*
 * Allocate and setup the UD channel parameters
 */
int
eibnx_setup_ud_channel(eibnx_thr_info_t *info)
{
	ibt_ud_chan_alloc_args_t alloc_attr;
	ibt_ud_chan_query_attr_t query_attr;
	ibt_status_t ret;

	/*
	 * Protect against arbitrary additions to the chan_alloc_args
	 * and chan_query_attr structures (make sure the ones we don't
	 * use are zero'd).
	 */
	bzero(&alloc_attr, sizeof (ibt_ud_chan_alloc_args_t));
	bzero(&query_attr, sizeof (ibt_ud_chan_query_attr_t));

	/*
	 * This ud channel is not going to be used by the nexus driver
	 * to send any LSO packets, so we won't need the IBT_USES_LSO flag.
	 */
	alloc_attr.ud_flags = IBT_ALL_SIGNALED;
	alloc_attr.ud_hca_port_num = info->ti_pi->p_port_num;

	ret = ibt_pkey2index(info->ti_hca, info->ti_pi->p_port_num,
	    (ib_pkey_t)EIB_ADMIN_PKEY, &(alloc_attr.ud_pkey_ix));
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_pkey2index(hca_hdl=0x%llx, "
		    "port_num=0x%x, pkey=0x%x) failed, ret=%d",
		    info->ti_hca, info->ti_pi->p_port_num,
		    EIB_ADMIN_PKEY, ret);
		return (ENX_E_FAILURE);
	}

	alloc_attr.ud_sizes.cs_sq = ENX_NUM_SWQE;
	alloc_attr.ud_sizes.cs_rq = ENX_NUM_RWQE;
	alloc_attr.ud_sizes.cs_sq_sgl = 1;
	alloc_attr.ud_sizes.cs_rq_sgl = 1;
	alloc_attr.ud_sizes.cs_inline = 0;

	alloc_attr.ud_qkey = EIB_FIP_QKEY;
	alloc_attr.ud_scq = info->ti_cq_hdl;
	alloc_attr.ud_rcq = info->ti_cq_hdl;
	alloc_attr.ud_pd = info->ti_pd;

	ret = ibt_alloc_ud_channel(info->ti_hca, IBT_ACHAN_NO_FLAGS,
	    &alloc_attr, &info->ti_chan, NULL);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_alloc_ud_channel(hca_hdl=0x%llx, "
		    "cs_sq=0x%lx, cs_rq=0x%lx) failed, ret=%d",
		    info->ti_hca, alloc_attr.ud_sizes.cs_sq,
		    alloc_attr.ud_sizes.cs_rq, ret);
		return (ENX_E_FAILURE);
	}

	ret = ibt_query_ud_channel(info->ti_chan, &query_attr);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_query_ud_channel(chan_hdl=0x%llx) "
		    "failed, ret=%d", info->ti_chan, ret);
		if ((ret = ibt_free_channel(info->ti_chan)) != IBT_SUCCESS) {
			ENX_DPRINTF_WARN("ibt_free_channel(chan_hdl=0x%llx) "
			    "failed, ret=%d", info->ti_chan, ret);
		}
		info->ti_chan = NULL;
		return (ENX_E_FAILURE);
	}
	info->ti_qpn = query_attr.ud_qpn;

	return (ENX_E_SUCCESS);
}

/*
 * Set up the transmit buffers for communicating with the gateway. Since
 * the EoIB Nexus driver only exchanges control messages with the
 * gateway, we don't really need too much space.
 */
static int
eibnx_setup_txbufs(eibnx_thr_info_t *info)
{
	eibnx_tx_t *snd_p = &info->ti_snd;
	eibnx_wqe_t *swqe;
	ibt_mr_attr_t attr;
	ibt_mr_desc_t desc;
	ib_memlen_t tx_bufsz;
	ibt_status_t ret;
	ibt_ud_dest_hdl_t dest;
	uint8_t	*buf;
	uint_t mtu = (128 << info->ti_pi->p_mtu);
	int i;

	/*
	 * Allocate for the tx buf
	 */
	tx_bufsz = ENX_NUM_SWQE * mtu;
	snd_p->tx_vaddr = (ib_vaddr_t)(uintptr_t)kmem_zalloc(tx_bufsz,
	    KM_SLEEP);

	/*
	 * Register the memory region with IBTF for use
	 */
	attr.mr_vaddr = snd_p->tx_vaddr;
	attr.mr_len = tx_bufsz;
	attr.mr_as = NULL;
	attr.mr_flags = IBT_MR_SLEEP;
	if ((ret = ibt_register_mr(info->ti_hca, info->ti_pd, &attr,
	    &snd_p->tx_mr, &desc)) != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_register_mr() failed for tx "
		    "region (0x%llx, 0x%llx) with ret=%d",
		    attr.mr_vaddr, attr.mr_len, ret);
		kmem_free((void *)(uintptr_t)(snd_p->tx_vaddr), tx_bufsz);
		return (ENX_E_FAILURE);
	}
	snd_p->tx_lkey = desc.md_lkey;

	/*
	 * Now setup the send wqes
	 */
	buf = (uint8_t *)(uintptr_t)(snd_p->tx_vaddr);
	for (i = 0; i < ENX_NUM_SWQE; i++) {
		swqe = &snd_p->tx_wqe[i];

		/*
		 * Allocate a UD destination handle
		 */
		ret = ibt_alloc_ud_dest(info->ti_hca, IBT_UD_DEST_NO_FLAGS,
		    info->ti_pd, &dest);
		if (ret != IBT_SUCCESS) {
			ENX_DPRINTF_ERR("ibt_alloc_ud_dest(hca_hdl=0x%llx) "
			    "failed, ret=%d", info->ti_hca, ret);
			eibnx_rb_setup_txbufs(info);
			return (ENX_E_FAILURE);
		}

		/*
		 * We set up everything in the send wqes except initialize
		 * the UD destination and the state of the entry. The ds_len
		 * should also be adjusted correctly. All this should be
		 * done later in the appropriate routines, before posting.
		 */
		swqe->qe_type = ENX_QETYP_SWQE;
		swqe->qe_bufsz = mtu;
		swqe->qe_sgl.ds_va = (ib_vaddr_t)(uintptr_t)buf;
		swqe->qe_sgl.ds_key = snd_p->tx_lkey;
		swqe->qe_sgl.ds_len = swqe->qe_bufsz;
		swqe->qe_wr.send.wr_id = (ibt_wrid_t)(uintptr_t)swqe;
		swqe->qe_wr.send.wr_flags = IBT_WR_NO_FLAGS;
		swqe->qe_wr.send.wr_trans = IBT_UD_SRV;
		swqe->qe_wr.send.wr_opcode = IBT_WRC_SEND;
		swqe->qe_wr.send.wr_nds = 1;
		swqe->qe_wr.send.wr_sgl = &swqe->qe_sgl;
		swqe->qe_wr.send.wr.ud.udwr_dest = dest;

		mutex_init(&swqe->qe_lock, NULL, MUTEX_DRIVER, NULL);
		swqe->qe_flags = 0;

		buf += mtu;
	}

	return (ENX_E_SUCCESS);
}

/*
 * Set up bufs for receiving gateway advertisements
 */
static int
eibnx_setup_rxbufs(eibnx_thr_info_t *info)
{
	eibnx_rx_t *rcv_p = &info->ti_rcv;
	eibnx_wqe_t *rwqe;
	ibt_mr_attr_t attr;
	ibt_mr_desc_t desc;
	ib_memlen_t rx_bufsz;
	ibt_status_t ret;
	uint8_t	*buf;
	uint_t mtu = (128 << info->ti_pi->p_mtu);
	int i;

	/*
	 * Allocate for the rx buf
	 */
	rx_bufsz = ENX_NUM_RWQE * (mtu + ENX_GRH_SZ);
	rcv_p->rx_vaddr = (ib_vaddr_t)(uintptr_t)kmem_zalloc(rx_bufsz,
	    KM_SLEEP);

	attr.mr_vaddr = rcv_p->rx_vaddr;
	attr.mr_len = rx_bufsz;
	attr.mr_as = NULL;
	attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	if ((ret = ibt_register_mr(info->ti_hca, info->ti_pd, &attr,
	    &rcv_p->rx_mr, &desc)) != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_register_mr() failed for rx "
		    "region (0x%llx, 0x%llx) with ret=%d",
		    attr.mr_vaddr, attr.mr_len, ret);
		kmem_free((void *)(uintptr_t)(rcv_p->rx_vaddr), rx_bufsz);
		return (ENX_E_FAILURE);
	}
	rcv_p->rx_lkey = desc.md_lkey;

	buf = (uint8_t *)(uintptr_t)(rcv_p->rx_vaddr);
	for (i = 0; i < ENX_NUM_RWQE; i++) {
		rwqe = &rcv_p->rx_wqe[i];

		rwqe->qe_type = ENX_QETYP_RWQE;
		rwqe->qe_bufsz = mtu + ENX_GRH_SZ;
		rwqe->qe_sgl.ds_va = (ib_vaddr_t)(uintptr_t)buf;
		rwqe->qe_sgl.ds_key = rcv_p->rx_lkey;
		rwqe->qe_sgl.ds_len = rwqe->qe_bufsz;
		rwqe->qe_wr.recv.wr_id = (ibt_wrid_t)(uintptr_t)rwqe;
		rwqe->qe_wr.recv.wr_nds = 1;
		rwqe->qe_wr.recv.wr_sgl = &rwqe->qe_sgl;

		mutex_init(&rwqe->qe_lock, NULL, MUTEX_DRIVER, NULL);
		rwqe->qe_flags = 0;

		buf += (mtu + ENX_GRH_SZ);
	}

	return (ENX_E_SUCCESS);
}

/*
 * Set up transmit and receive buffers and post the receive buffers
 */
int
eibnx_setup_bufs(eibnx_thr_info_t *info)
{
	eibnx_rx_t *rcv_p = &info->ti_rcv;
	eibnx_wqe_t *rwqe;
	ibt_status_t ret;
	int i;

	if (eibnx_setup_txbufs(info) != ENX_E_SUCCESS)
		return (ENX_E_FAILURE);

	if (eibnx_setup_rxbufs(info) != ENX_E_SUCCESS) {
		eibnx_rb_setup_txbufs(info);
		return (ENX_E_FAILURE);
	}

	for (i = 0; i < ENX_NUM_RWQE; i++) {
		rwqe = &rcv_p->rx_wqe[i];

		mutex_enter(&rwqe->qe_lock);

		rwqe->qe_flags |= (ENX_QEFL_INUSE | ENX_QEFL_POSTED);
		ret = ibt_post_recv(info->ti_chan, &(rwqe->qe_wr.recv), 1,
		    NULL);

		mutex_exit(&rwqe->qe_lock);

		if (ret != IBT_SUCCESS) {
			ENX_DPRINTF_ERR("ibt_post_recv(chan_hdl=0x%llx) "
			    "failed, ret=%d", info->ti_chan, ret);

			ret = ibt_flush_channel(info->ti_chan);
			if (ret != IBT_SUCCESS) {
				ENX_DPRINTF_WARN("ibt_flush_channel"
				    "(chan_hdl=0x%llx) failed, ret=%d",
				    info->ti_chan, ret);
			}

			eibnx_rb_setup_rxbufs(info);
			eibnx_rb_setup_txbufs(info);
			return (ENX_E_FAILURE);
		}
	}

	return (ENX_E_SUCCESS);
}

/*
 * Set up the completion queue handler.  While we don't quit if  we cannot
 * use soft interrupts, that path is really unreliable and untested.
 */
int
eibnx_setup_cq_handler(eibnx_thr_info_t *info)
{
	eibnx_t *ss = enx_global_ss;
	ibt_status_t ret;
	int rv;

	/*
	 * We'll try to use a softintr if possible.  If not, it's not
	 * fatal, we'll try and use the completion handler directly from
	 * the interrupt handler.
	 */

	rv = ddi_intr_add_softint(ss->nx_dip, &info->ti_softint_hdl,
	    EIB_SOFTPRI_ADM, eibnx_comp_handler, info);
	if (rv != DDI_SUCCESS) {
		ENX_DPRINTF_WARN("ddi_intr_add_softint(dip=0x%llx) "
		    "failed, ret=%d", ss->nx_dip, rv);
	}

	ibt_set_cq_handler(info->ti_cq_hdl, eibnx_comp_intr, info);

	ret = ibt_enable_cq_notify(info->ti_cq_hdl, IBT_NEXT_COMPLETION);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_enable_cq_notify(cq_hdl=0x%llx) "
		    "failed, ret=%d", info->ti_cq_hdl, ret);
		if (info->ti_softint_hdl) {
			(void) ddi_intr_remove_softint(info->ti_softint_hdl);
			info->ti_softint_hdl = NULL;
		}
		return (ENX_E_FAILURE);
	}

	return (ENX_E_SUCCESS);
}

/*
 * Join the solicit multicast group (All-EoIB-GWs-GID) as a full member
 */
static int
eibnx_join_solicit_mcg(eibnx_thr_info_t *info)
{
	ib_gid_t rgid = info->ti_pi->p_sgid_tbl[0];
	ibt_mcg_attr_t mcg_attr;
	ibt_mcg_info_t mcg_info;
	ibt_status_t ret;

	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));

	mcg_attr.mc_mgid = enx_solicit_mgid;
	mcg_attr.mc_qkey = (ib_qkey_t)EIB_FIP_QKEY;
	mcg_attr.mc_pkey = (ib_pkey_t)EIB_ADMIN_PKEY;
	mcg_attr.mc_join_state = IB_MC_JSTATE_FULL;
	mcg_attr.mc_flow = info->ti_solicit_mcg->mc_adds_vect.av_flow;
	mcg_attr.mc_tclass = info->ti_solicit_mcg->mc_adds_vect.av_tclass;
	mcg_attr.mc_sl = info->ti_solicit_mcg->mc_adds_vect.av_srvl;
	mcg_attr.mc_scope = IB_MC_SCOPE_SUBNET_LOCAL;

	/*
	 * We only need to send to solicit mcg, so we only need to join
	 * the multicast group, no need to attach our qp to it
	 */
	ret = ibt_join_mcg(rgid, &mcg_attr, &mcg_info, NULL, NULL);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_join_mcg() failed for solicit "
		    "mgid=%llx.%llx, ret=%x", enx_solicit_mgid.gid_prefix,
		    enx_solicit_mgid.gid_guid, ret);
		return (ENX_E_FAILURE);
	}

	/*
	 * We can throw away the old mcg info we got when we queried
	 * for the mcg and use the new one. They both should be the
	 * same, really.
	 */
	if (info->ti_solicit_mcg) {
		bcopy(&mcg_info, info->ti_solicit_mcg,
		    sizeof (ibt_mcg_info_t));
	}

	return (ENX_E_SUCCESS);
}

/*
 * Join and attach to the advertise multicast group (All-EoIB-ENodes-GID)
 * to receive unsolicitied advertisements from the gateways.
 */
static int
eibnx_join_advertise_mcg(eibnx_thr_info_t *info)
{
	ib_gid_t rgid = info->ti_pi->p_sgid_tbl[0];
	ibt_mcg_attr_t mcg_attr;
	ibt_mcg_info_t mcg_info;
	ibt_status_t ret;

	if (info->ti_chan == NULL)
		return (ENX_E_FAILURE);

	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));

	mcg_attr.mc_mgid = enx_advertise_mgid;
	mcg_attr.mc_qkey = (ib_qkey_t)EIB_FIP_QKEY;
	mcg_attr.mc_pkey = (ib_pkey_t)EIB_ADMIN_PKEY;
	mcg_attr.mc_join_state = IB_MC_JSTATE_FULL;
	mcg_attr.mc_flow = info->ti_advertise_mcg->mc_adds_vect.av_flow;
	mcg_attr.mc_tclass = info->ti_advertise_mcg->mc_adds_vect.av_tclass;
	mcg_attr.mc_sl = info->ti_advertise_mcg->mc_adds_vect.av_srvl;
	mcg_attr.mc_scope = IB_MC_SCOPE_SUBNET_LOCAL;

	ret = ibt_join_mcg(rgid, &mcg_attr, &mcg_info, NULL, NULL);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_join_mcg() failed for advertise "
		    "mgid=%llx.%llx, ret=%x", enx_advertise_mgid.gid_prefix,
		    enx_advertise_mgid.gid_guid, ret);
		return (ENX_E_FAILURE);
	}

	/*
	 * We can throw away the old mcg info we got when we queried
	 * for the mcg and use the new one. They both should be the
	 * same, really.
	 */
	if (info->ti_advertise_mcg) {
		bcopy(&mcg_info, info->ti_advertise_mcg,
		    sizeof (ibt_mcg_info_t));
	}

	/*
	 * Since we need to receive advertisements, we'll attach our qp
	 * to the advertise mcg
	 */
	ret = ibt_attach_mcg(info->ti_chan, info->ti_advertise_mcg);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_attach_mcg(chan_hdl=0x%llx, "
		    "advt_mcg=0x%llx) failed, ret=%d", info->ti_chan,
		    info->ti_advertise_mcg, ret);
		return (ENX_E_FAILURE);
	}

	return (ENX_E_SUCCESS);
}

/*
 * Join the multicast groups we're interested in
 */
int
eibnx_join_mcgs(eibnx_thr_info_t *info)
{
	mutex_enter(&info->ti_mcg_lock);

	/*
	 * We should've located the mcg first
	 */
	if ((info->ti_mcg_status & ENX_MCGS_FOUND) == 0) {
		mutex_exit(&info->ti_mcg_lock);
		return (ENX_E_FAILURE);
	}

	/*
	 * If we're already joined to the mcgs, we must leave first
	 */
	if ((info->ti_mcg_status & ENX_MCGS_JOINED) == ENX_MCGS_JOINED) {
		mutex_exit(&info->ti_mcg_lock);
		return (ENX_E_FAILURE);
	}

	/*
	 * Join the two mcgs
	 */
	if (eibnx_join_advertise_mcg(info) != ENX_E_SUCCESS) {
		mutex_exit(&info->ti_mcg_lock);
		return (ENX_E_FAILURE);
	}
	if (eibnx_join_solicit_mcg(info) != ENX_E_SUCCESS) {
		eibnx_rb_join_advertise_mcg(info);
		mutex_exit(&info->ti_mcg_lock);
		return (ENX_E_FAILURE);
	}

	info->ti_mcg_status |= ENX_MCGS_JOINED;
	mutex_exit(&info->ti_mcg_lock);

	return (ENX_E_SUCCESS);
}

int
eibnx_rejoin_mcgs(eibnx_thr_info_t *info)
{
	/*
	 * Lookup the MCGs again and join them
	 */
	eibnx_rb_join_mcgs(info);
	eibnx_rb_find_mgroups(info);

	if (eibnx_find_mgroups(info) != ENX_E_SUCCESS)
		return (ENX_E_FAILURE);

	if (eibnx_join_mcgs(info) != ENX_E_SUCCESS)
		return (ENX_E_FAILURE);

	return (ENX_E_SUCCESS);
}

int
eibnx_ibt_fini(eibnx_t *ss)
{
	return (eibnx_rb_ibt_init(ss));
}

static int
eibnx_rb_ibt_init(eibnx_t *ss)
{
	eibnx_hca_t *hca;
	eibnx_hca_t *hca_next;
	eibnx_hca_t *hca_list;
	ibt_status_t	ret;

	/*
	 * Disable subnet notices callbacks
	 */
	ibt_register_subnet_notices(ss->nx_ibt_hdl, NULL, NULL);

	/*
	 * Remove the hca list from the state structure
	 */
	mutex_enter(&ss->nx_lock);
	hca_list = ss->nx_hca;
	ss->nx_hca = NULL;
	mutex_exit(&ss->nx_lock);

	/*
	 * For each HCA in the list, free up the portinfo/port structs,
	 * free the pd, close the hca handle and release the hca struct.
	 * If something goes wrong, try to put back whatever good remains
	 * back on the hca list and return failure.
	 */
	for (hca = hca_list; hca; hca = hca_next) {
		hca_next = hca->hc_next;
		if (eibnx_cleanup_hca(hca) != ENX_E_SUCCESS) {
			mutex_enter(&ss->nx_lock);
			ss->nx_hca = hca_next;
			mutex_exit(&ss->nx_lock);
			return (ENX_E_FAILURE);
		}
	}

	if ((ret = ibt_detach(ss->nx_ibt_hdl)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_detach(ibt_hdl=0x%llx) "
		    "failed, ret=%d", ss->nx_ibt_hdl, ret);
		return (ENX_E_FAILURE);
	}
	ss->nx_ibt_hdl = NULL;

	eibnx_rb_state_init();

	return (ENX_E_SUCCESS);
}

static void
eibnx_rb_state_init(void)
{
	eibnx_t *ss = enx_global_ss;
	kt_did_t thr_id;

	/*
	 * Ask the eoib node creation thread to die and wait for
	 * it to happen
	 */
	mutex_enter(&ss->nx_nodeq_lock);

	thr_id = ss->nx_nodeq_kt_did;
	ss->nx_nodeq_thr_die = 1;
	ss->nx_nodeq_kt_did = 0;

	cv_signal(&ss->nx_nodeq_cv);
	mutex_exit(&ss->nx_nodeq_lock);

	if (thr_id) {
		thread_join(thr_id);
	}

	cv_destroy(&ss->nx_busop_cv);
	mutex_destroy(&ss->nx_busop_lock);
	cv_destroy(&ss->nx_nodeq_cv);
	mutex_destroy(&ss->nx_nodeq_lock);
	mutex_destroy(&ss->nx_lock);
}

void
eibnx_rb_find_mgroups(eibnx_thr_info_t *info)
{
	mutex_enter(&info->ti_mcg_lock);
	if ((info->ti_mcg_status & ENX_MCGS_FOUND) == ENX_MCGS_FOUND) {
		if (info->ti_advertise_mcg) {
			ibt_free_mcg_info(info->ti_advertise_mcg, 1);
			info->ti_advertise_mcg = NULL;
		}
		if (info->ti_solicit_mcg) {
			ibt_free_mcg_info(info->ti_solicit_mcg, 1);
			info->ti_solicit_mcg = NULL;
		}
		info->ti_mcg_status &= (~ENX_MCGS_FOUND);
	}
	mutex_exit(&info->ti_mcg_lock);
}

void
eibnx_rb_setup_cq(eibnx_thr_info_t *info)
{
	ibt_status_t ret;

	if (info->ti_wc && info->ti_cq_sz)
		kmem_free(info->ti_wc, sizeof (ibt_wc_t) * info->ti_cq_sz);

	info->ti_cq_sz = 0;
	info->ti_wc = NULL;

	if (info->ti_cq_hdl) {
		ret = ibt_free_cq(info->ti_cq_hdl);
		if (ret != IBT_SUCCESS) {
			ENX_DPRINTF_WARN("ibt_free_cq(cq_hdl=0x%llx) "
			    "failed, ret=%d", info->ti_cq_hdl, ret);
		}
		info->ti_cq_hdl = NULL;
	}
}

void
eibnx_rb_setup_ud_channel(eibnx_thr_info_t *info)
{
	ibt_status_t ret;

	if ((ret = ibt_free_channel(info->ti_chan)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_free_channel(chan=0x%llx) "
		    "failed, ret=%d", info->ti_chan, ret);
	}
	info->ti_chan = NULL;
	info->ti_qpn = 0;
}

static void
eibnx_rb_setup_txbufs(eibnx_thr_info_t *info)
{
	eibnx_tx_t *snd_p = &info->ti_snd;
	eibnx_wqe_t *swqe;
	ibt_status_t ret;
	int i;
	uint_t mtu = (128 << info->ti_pi->p_mtu);

	/*
	 * Release any UD destination handle we may have allocated.  Note that
	 * the per swqe lock would've been initialized only if we were able to
	 * allocate the UD dest handle.
	 */
	for (i = 0; i < ENX_NUM_SWQE; i++) {
		swqe = &snd_p->tx_wqe[i];

		if (swqe->qe_wr.send.wr.ud.udwr_dest) {
			mutex_destroy(&swqe->qe_lock);

			ret =
			    ibt_free_ud_dest(swqe->qe_wr.send.wr.ud.udwr_dest);
			if (ret != IBT_SUCCESS) {
				ENX_DPRINTF_WARN("ibt_free_ud_dest(dest=0x%llx)"
				    " failed, ret=%d",
				    swqe->qe_wr.send.wr.ud.udwr_dest, ret);
			}
		}
	}

	/*
	 * Clear all the workq entries
	 */
	bzero(snd_p->tx_wqe, sizeof (eibnx_wqe_t) * ENX_NUM_SWQE);

	/*
	 * Clear Lkey and deregister any memory region we may have
	 * registered earlier
	 */
	snd_p->tx_lkey = 0;
	if (snd_p->tx_mr) {
		if ((ret = ibt_deregister_mr(info->ti_hca,
		    snd_p->tx_mr)) != IBT_SUCCESS) {
			ENX_DPRINTF_WARN("ibt_deregister_TXmr(hca_hdl=0x%llx,"
			    "mr=0x%llx) failed, ret=%d", info->ti_hca,
			    snd_p->tx_mr, ret);
		}
		snd_p->tx_mr = NULL;
	}

	/*
	 * Release any memory allocated for the tx bufs
	 */
	if (snd_p->tx_vaddr) {
		kmem_free((void *)(uintptr_t)(snd_p->tx_vaddr),
		    ENX_NUM_SWQE * mtu);
		snd_p->tx_vaddr = 0;
	}

}

static void
eibnx_rb_setup_rxbufs(eibnx_thr_info_t *info)
{
	eibnx_rx_t *rcv_p = &info->ti_rcv;
	eibnx_wqe_t *rwqe;
	ibt_status_t ret;
	uint_t mtu = (128 << info->ti_pi->p_mtu);
	int i;

	for (i = 0; i < ENX_NUM_RWQE; i++) {
		rwqe = &rcv_p->rx_wqe[i];
		mutex_destroy(&rwqe->qe_lock);
	}
	bzero(rcv_p->rx_wqe, sizeof (eibnx_wqe_t) * ENX_NUM_RWQE);

	rcv_p->rx_lkey = 0;

	if ((ret = ibt_deregister_mr(info->ti_hca,
	    rcv_p->rx_mr)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_deregister_RXmr(hca_hdl=0x%llx,"
		    "mr=0x%llx) failed, ret=%d", info->ti_hca,
		    rcv_p->rx_mr, ret);
	}
	rcv_p->rx_mr = NULL;

	kmem_free((void *)(uintptr_t)(rcv_p->rx_vaddr),
	    ENX_NUM_RWQE * (mtu + ENX_GRH_SZ));
	rcv_p->rx_vaddr = 0;
}

void
eibnx_rb_setup_bufs(eibnx_thr_info_t *info)
{
	ibt_status_t ret;

	if ((ret = ibt_flush_channel(info->ti_chan)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_flush_channel(chan_hdl=0x%llx) "
		    "failed, ret=%d", info->ti_chan, ret);
	}

	eibnx_rb_setup_rxbufs(info);

	eibnx_rb_setup_txbufs(info);
}

void
eibnx_rb_setup_cq_handler(eibnx_thr_info_t *info)
{
	ibt_set_cq_handler(info->ti_cq_hdl, NULL, NULL);

	if (info->ti_softint_hdl) {
		(void) ddi_intr_remove_softint(info->ti_softint_hdl);
		info->ti_softint_hdl = NULL;
	}
}

static void
eibnx_rb_join_solicit_mcg(eibnx_thr_info_t *info)
{
	ib_gid_t rgid = info->ti_pi->p_sgid_tbl[0];
	ib_gid_t rsvd_gid;
	ibt_status_t ret;

	rsvd_gid.gid_prefix = 0;
	rsvd_gid.gid_guid = 0;

	ret = ibt_leave_mcg(rgid, enx_solicit_mgid,
	    rsvd_gid, IB_MC_JSTATE_FULL);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_leave_mcg(slct_mgid=%llx.%llx) "
		    "failed, ret=%d", enx_solicit_mgid.gid_prefix,
		    enx_solicit_mgid.gid_guid, ret);
	}
}

static void
eibnx_rb_join_advertise_mcg(eibnx_thr_info_t *info)
{
	ib_gid_t rgid = info->ti_pi->p_sgid_tbl[0];
	ib_gid_t rsvd_gid;
	ibt_status_t ret;

	ret = ibt_detach_mcg(info->ti_chan, info->ti_advertise_mcg);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_detach_mcg(chan_hdl=0x%llx, "
		    "advt_mcg=0x%llx) failed, ret=%d",
		    info->ti_chan, info->ti_advertise_mcg, ret);
	}

	rsvd_gid.gid_prefix = 0;
	rsvd_gid.gid_guid = 0;

	ret = ibt_leave_mcg(rgid, enx_advertise_mgid,
	    rsvd_gid, IB_MC_JSTATE_FULL);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_leave_mcg(advt_mgid=%llx.%llx) "
		    "failed, ret=%d", enx_advertise_mgid.gid_prefix,
		    enx_advertise_mgid.gid_guid, ret);
	}
}

void
eibnx_rb_join_mcgs(eibnx_thr_info_t *info)
{
	mutex_enter(&info->ti_mcg_lock);
	if ((info->ti_mcg_status & ENX_MCGS_JOINED) == ENX_MCGS_JOINED) {
		eibnx_rb_join_solicit_mcg(info);
		eibnx_rb_join_advertise_mcg(info);

		info->ti_mcg_status &= (~ENX_MCGS_JOINED);
	}
	mutex_exit(&info->ti_mcg_lock);
}

eibnx_hca_t *
eibnx_prepare_hca(ib_guid_t hca_guid)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_hca_t *hca;
	eibnx_port_t *port;
	eibnx_port_t *port_tail;
	ibt_hca_hdl_t hca_hdl;
	ibt_pd_hdl_t pd_hdl;
	ibt_hca_portinfo_t *pi;
	uint_t num_pi;
	uint_t size_pi;
	ibt_hca_attr_t hca_attr;
	ibt_status_t ret;
	int i;

	ret = ibt_open_hca(ss->nx_ibt_hdl, hca_guid, &hca_hdl);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_open_hca(hca_guid=0x%llx) "
		    "failed, ret=%d", hca_guid, ret);
		return (NULL);
	}

	bzero(&hca_attr, sizeof (ibt_hca_attr_t));
	if ((ret = ibt_query_hca(hca_hdl, &hca_attr)) != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_query_hca(hca_hdl=0x%llx, "
		    "hca_guid=0x%llx) failed, ret=%d",
		    hca_hdl, hca_guid, ret);

		if ((ret = ibt_close_hca(hca_hdl)) != IBT_SUCCESS) {
			ENX_DPRINTF_WARN("ibt_close_hca(hca_hdl=0x%llx) "
			    "failed, ret=%d", hca_hdl, ret);
		}
		return (NULL);
	}

	ret = ibt_alloc_pd(hca_hdl, IBT_PD_NO_FLAGS, &pd_hdl);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_alloc_pd(hca_hdl=0x%llx, "
		    "hca_guid=0x%llx) failed, ret=%d",
		    hca_hdl, hca_guid, ret);

		if ((ret = ibt_close_hca(hca_hdl)) != IBT_SUCCESS) {
			ENX_DPRINTF_WARN("ibt_close_hca(hca_hdl=0x%llx) "
			    "failed, ret=%d", hca_hdl, ret);
		}
		return (NULL);
	}

	/*
	 * We have all the information we want about this hca, create
	 * a new struct and return it.
	 */
	hca = kmem_zalloc(sizeof (eibnx_hca_t), KM_SLEEP);
	hca->hc_next = NULL;
	hca->hc_guid = hca_guid;
	hca->hc_hdl = hca_hdl;
	hca->hc_pd = pd_hdl;
	hca->hc_port = port_tail = NULL;

	for (i = 0; i < hca_attr.hca_nports; i++) {
		ret = ibt_query_hca_ports(hca_hdl, i + 1, &pi,
		    &num_pi, &size_pi);
		if (ret != IBT_SUCCESS) {
			ENX_DPRINTF_WARN("ibt_query_hca_ports(hca_hdl=0x%llx, "
			    "port=0x%x) failed, ret=%d", hca_hdl, i + 1, ret);
		} else {
			port = kmem_zalloc(sizeof (eibnx_port_t), KM_SLEEP);
			port->po_next = NULL;
			port->po_pi = pi;
			port->po_pi_size = size_pi;

			if (port_tail) {
				port_tail->po_next = port;
			} else {
				hca->hc_port = port;
			}
			port_tail = port;
		}
	}

	/*
	 * If we couldn't query about any ports on the HCA, return failure
	 */
	if (hca->hc_port == NULL) {
		ENX_DPRINTF_ERR("all hca port queries failed for "
		    "hca_guid=0x%llx", hca_guid);
		(void) eibnx_cleanup_hca(hca);
		return (NULL);
	}

	return (hca);
}

int
eibnx_cleanup_hca(eibnx_hca_t *hca)
{
	eibnx_port_t *port;
	eibnx_port_t *port_next;
	ibt_status_t ret;

	for (port = hca->hc_port; port; port = port_next) {
		port_next = port->po_next;

		ibt_free_portinfo(port->po_pi, port->po_pi_size);
		kmem_free(port, sizeof (eibnx_port_t));
	}

	if ((ret = ibt_free_pd(hca->hc_hdl, hca->hc_pd)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_free_pd(hca_hdl=0x%lx, pd_hd=0x%lx) "
		    "failed, ret=%d", hca->hc_hdl, hca->hc_pd, ret);
		return (ENX_E_FAILURE);
	}

	if ((ret = ibt_close_hca(hca->hc_hdl)) != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_close_hca(hca_hdl=0x%lx) failed, "
		    "ret=%d", hca->hc_hdl, ret);
		return (ENX_E_FAILURE);
	}

	kmem_free(hca, sizeof (eibnx_hca_t));

	return (ENX_E_SUCCESS);
}
