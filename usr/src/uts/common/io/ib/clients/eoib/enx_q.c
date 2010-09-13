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
 * Acquire an SWQE
 */

/*ARGSUSED*/
eibnx_wqe_t *
eibnx_acquire_swqe(eibnx_thr_info_t *info, int flag)
{
	eibnx_wqe_t *wqe = NULL;
	eibnx_tx_t *snd_p = &info->ti_snd;
	int i;

	for (i = 0; i < ENX_NUM_SWQE; i++) {
		wqe = &(snd_p->tx_wqe[i]);

		mutex_enter(&wqe->qe_lock);
		if ((wqe->qe_flags & ENX_QEFL_INUSE) == 0) {
			wqe->qe_flags |= ENX_QEFL_INUSE;
			mutex_exit(&wqe->qe_lock);
			break;
		}
		mutex_exit(&wqe->qe_lock);
	}

	/*
	 * We probably have enough swqe entries for doing our solicitations.
	 * If we find it not enough in practice, we need to implement some
	 * sort of dynamic allocation.
	 */
	if (i == ENX_NUM_SWQE)
		wqe = NULL;

	return (wqe);
}

/*
 * Return a SWQE from completion. We may have to release
 * it or keep it.
 */
void
eibnx_return_swqe(eibnx_wqe_t *wqe)
{
	ASSERT(wqe->qe_type == ENX_QETYP_SWQE);

	mutex_enter(&wqe->qe_lock);

	/*
	 * This send wqe is from the completion queue.  We need to
	 * clear the 'posted' flag first.
	 */
	ASSERT((wqe->qe_flags & ENX_QEFL_POSTED) == ENX_QEFL_POSTED);
	wqe->qe_flags &= (~ENX_QEFL_POSTED);

	/*
	 * See if we need to release this send wqe back to the pool
	 * on completion. We may not need to do so if, for example,
	 * this were a swqe acquired specifically for a particular gw.
	 */
	if (wqe->qe_flags & ENX_QEFL_RELONCOMP) {
		wqe->qe_sgl.ds_len = wqe->qe_bufsz;
		wqe->qe_flags &= (~ENX_QEFL_INUSE);

		wqe->qe_flags &= (~ENX_QEFL_RELONCOMP);
	}

	mutex_exit(&wqe->qe_lock);
}

/*
 * Return a RWQE from completion. We probably have to repost it.
 */
void
eibnx_return_rwqe(eibnx_thr_info_t *info, eibnx_wqe_t *wqe)
{
	ibt_status_t ret;

	ASSERT(wqe->qe_type == ENX_QETYP_RWQE);

	mutex_enter(&wqe->qe_lock);

	/*
	 * We should never need to free an rwqe on completion.
	 */
	ASSERT((wqe->qe_flags & ENX_QEFL_RELONCOMP) == 0);

	/*
	 * An rwqe is always in-use and posted, so we only need to make
	 * sure the ds_len is adjusted back to the value it's supposed
	 * to have.
	 */
	wqe->qe_sgl.ds_len = wqe->qe_bufsz;

	/*
	 * Repost the recv wqe
	 */
	ret = ibt_post_recv(info->ti_chan, &(wqe->qe_wr.recv), 1, NULL);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_post_recv(chan_hdl=0x%llx) failed, "
		    "ret=%d", info->ti_chan, ret);
	}

	mutex_exit(&wqe->qe_lock);
}

/*
 * Release an SWQE that was acquired earlier.
 */
void
eibnx_release_swqe(eibnx_wqe_t *wqe)
{
	ASSERT(wqe->qe_type == ENX_QETYP_SWQE);

	mutex_enter(&wqe->qe_lock);

	/*
	 * Make sure this swqe is in use. Since this routine may also be
	 * called when we're trying to cleanup the eoib nodes, we
	 * should clear all flag bits.
	 */
	ASSERT((wqe->qe_flags & ENX_QEFL_INUSE) == ENX_QEFL_INUSE);
	wqe->qe_flags = 0;

	mutex_exit(&wqe->qe_lock);
}

/*
 * Insert the passed child to the head of the queue
 */
void
eibnx_enqueue_child(eibnx_thr_info_t *info, eibnx_gw_info_t *gwi,
    char *node_name, dev_info_t *dip)
{
	eibnx_child_t *ch;
	eibnx_child_t *new_ch;

	new_ch = kmem_zalloc(sizeof (eibnx_child_t), KM_SLEEP);
	new_ch->ch_dip = dip;
	new_ch->ch_node_name = node_name;
	new_ch->ch_gwi = gwi;

	mutex_enter(&info->ti_child_lock);

	/*
	 * Search existing children to see if we already have this
	 * child.  If so, simply update its dip and node_name
	 */
	for (ch = info->ti_child; ch; ch = ch->ch_next) {
		if (ch->ch_gwi->gw_portid == gwi->gw_portid) {
			ch->ch_dip = dip;
			if (ch->ch_node_name) {
				kmem_free(ch->ch_node_name, MAXNAMELEN);
			}
			ch->ch_node_name = node_name;
			kmem_free(new_ch, sizeof (eibnx_child_t));
			return;
		}
	}

	/*
	 * If not, add the new child to the list of children
	 */
	new_ch->ch_next = info->ti_child;
	info->ti_child = new_ch;

	mutex_exit(&info->ti_child_lock);
}

int
eibnx_update_child(eibnx_thr_info_t *info, eibnx_gw_info_t *gwi,
    dev_info_t *dip)
{
	eibnx_child_t *ch;

	mutex_enter(&info->ti_child_lock);
	for (ch = info->ti_child; ch; ch = ch->ch_next) {
		if (ch->ch_gwi->gw_portid == gwi->gw_portid) {
			if (ch->ch_dip != dip) {
				ENX_DPRINTF_DEBUG("updating child dip for "
				    "gw portid 0x%x to 0x%llx",
				    gwi->gw_portid, dip);
				ch->ch_dip = dip;
			}
			mutex_exit(&info->ti_child_lock);

			return (ENX_E_SUCCESS);
		}
	}
	mutex_exit(&info->ti_child_lock);

	return (ENX_E_FAILURE);
}

dev_info_t *
eibnx_find_child_dip_by_inst(eibnx_thr_info_t *info, int inst)
{
	eibnx_child_t *ch;
	dev_info_t *dip = NULL;

	mutex_enter(&info->ti_child_lock);
	for (ch = info->ti_child; ch != NULL; ch = ch->ch_next) {
		dip = ch->ch_dip;
		if (ddi_get_instance(dip) == inst)
			break;
	}
	mutex_exit(&info->ti_child_lock);

	return (dip);
}

dev_info_t *
eibnx_find_child_dip_by_gw(eibnx_thr_info_t *info, uint16_t gw_portid)
{
	eibnx_child_t *ch;
	dev_info_t *dip = NULL;

	mutex_enter(&info->ti_child_lock);
	for (ch = info->ti_child; ch != NULL; ch = ch->ch_next) {
		dip = ch->ch_dip;
		if (ch->ch_gwi->gw_portid == gw_portid)
			break;
	}
	mutex_exit(&info->ti_child_lock);

	return (dip);
}

/*
 * See if the passed gateway is already found in our list.  Note
 * that we assume that the gateway port id uniquely identifies each
 * gateway.
 */
eibnx_gw_info_t *
eibnx_find_gw_in_gwlist(eibnx_thr_info_t *info, eibnx_gw_info_t *gwi)
{
	eibnx_gw_info_t *lgw = NULL;

	mutex_enter(&info->ti_gw_lock);
	for (lgw = info->ti_gw; lgw; lgw = lgw->gw_next) {
		if (lgw->gw_portid == gwi->gw_portid)
			break;
	}
	mutex_exit(&info->ti_gw_lock);

	return (lgw);
}

/*
 * Add a newly discovered gateway to the gateway list.  Since we'll
 * need to send unicast solicitations to this gateway soon, we'll
 * also grab a swqe entry, and initialize basic gw adress parameters
 * such as the gid, qpn, qkey and pkey of the GW.  When we eventually
 * get to sending the unicast to this gateway for the first time,
 * we'll discover the path to this gateway using these parameters
 * and modify the ud destination handle appropriately.
 */
eibnx_gw_info_t *
eibnx_add_gw_to_gwlist(eibnx_thr_info_t *info, eibnx_gw_info_t *gwi,
    ibt_wc_t *wc, uint8_t *recv_buf)
{
	eibnx_gw_info_t *new_gwi;
	eibnx_wqe_t *wqe;
	ib_grh_t *grh;
	ib_gid_t sgid;
	clock_t timeout_usecs;

	/*
	 * For now, we'll simply do KM_NOSLEEP allocation, since this code
	 * is called from within rx processing
	 */
	new_gwi = kmem_zalloc(sizeof (eibnx_gw_info_t), KM_NOSLEEP);
	if (new_gwi == NULL) {
		ENX_DPRINTF_WARN("no memory, gw port_id 0x%x "
		    "will be ignored by hca_guid=0x%llx, port=0x%x",
		    gwi->gw_portid, info->ti_hca_guid,
		    info->ti_pi->p_port_num);
		return (NULL);
	}

	/*
	 * We also need to acquire a send wqe to do unicast solicitations
	 * to this gateway later on. We should've enough pre-allocated swqes
	 * to do this without sleeping.
	 */
	if ((wqe = eibnx_acquire_swqe(info, KM_NOSLEEP)) == NULL) {
		ENX_DPRINTF_WARN("no swqe available, gw port_id 0x%x "
		    "will be ignored by hca_guid=0x%llx, port=0x%x",
		    gwi->gw_portid, info->ti_hca_guid,
		    info->ti_pi->p_port_num);
		kmem_free(new_gwi, sizeof (eibnx_gw_info_t));
		return (NULL);
	}

	/*
	 * Initialize gw state and wqe information.
	 */
	new_gwi->gw_next = NULL;
	new_gwi->gw_swqe = wqe;
	new_gwi->gw_state = gwi->gw_state;

	/*
	 * Set up gateway advertisement monitoring parameters. Since we
	 * always need to check against a timeout value of 2.5 * gw_adv_period,
	 * we'll keep this pre-calculated value as well.
	 */
	mutex_init(&new_gwi->gw_adv_lock, NULL, MUTEX_DRIVER, NULL);
	new_gwi->gw_adv_flag = gwi->gw_adv_flag;
	new_gwi->gw_adv_last_lbolt = ddi_get_lbolt64();
	timeout_usecs = gwi->gw_adv_period * 1000;
	timeout_usecs = ((timeout_usecs << 2) + timeout_usecs) >> 1;
	new_gwi->gw_adv_timeout_ticks = drv_usectohz(timeout_usecs);

	/*
	 * Initialize gateway address information. Note that if the message has
	 * a GRH, we'll use the subnet prefix, otherwise we'll assume that the
	 * gateway is in the same subnet as ourselves.
	 */
	new_gwi->gw_addr.ga_vect = NULL;
	if (wc->wc_flags & IBT_WC_GRH_PRESENT) {
		grh = (ib_grh_t *)(uintptr_t)recv_buf;
		new_gwi->gw_addr.ga_gid.gid_prefix =
		    ntohll(grh->SGID.gid_prefix);
	} else {
		sgid = info->ti_pi->p_sgid_tbl[0];
		new_gwi->gw_addr.ga_gid.gid_prefix =
		    sgid.gid_prefix;
	}
	new_gwi->gw_addr.ga_gid.gid_guid = gwi->gw_guid;
	new_gwi->gw_addr.ga_qpn = gwi->gw_ctrl_qpn;
	new_gwi->gw_addr.ga_qkey = EIB_FIP_QKEY;
	new_gwi->gw_addr.ga_pkey = EIB_ADMIN_PKEY;

	/*
	 * Initialize gateway parameters received via the advertisement
	 */
	new_gwi->gw_system_guid = gwi->gw_system_guid;
	new_gwi->gw_guid = gwi->gw_guid;
	new_gwi->gw_adv_period = gwi->gw_adv_period;
	new_gwi->gw_ka_period = gwi->gw_ka_period;
	new_gwi->gw_vnic_ka_period = gwi->gw_vnic_ka_period;
	new_gwi->gw_ctrl_qpn = gwi->gw_ctrl_qpn;
	new_gwi->gw_lid = gwi->gw_lid;
	new_gwi->gw_portid = gwi->gw_portid;
	new_gwi->gw_num_net_vnics = gwi->gw_num_net_vnics;
	new_gwi->gw_is_host_adm_vnics = gwi->gw_is_host_adm_vnics;
	new_gwi->gw_sl = gwi->gw_sl;
	new_gwi->gw_n_rss_qpn = gwi->gw_n_rss_qpn;
	new_gwi->gw_flag_ucast_advt = gwi->gw_flag_ucast_advt;
	new_gwi->gw_flag_available = gwi->gw_flag_available;
	bcopy(gwi->gw_system_name, new_gwi->gw_system_name,
	    sizeof (new_gwi->gw_system_name));
	bcopy(gwi->gw_port_name, new_gwi->gw_port_name,
	    sizeof (new_gwi->gw_port_name));
	bcopy(gwi->gw_vendor_id, new_gwi->gw_vendor_id,
	    sizeof (new_gwi->gw_vendor_id));

	/*
	 * Queue up the new gwi and return it
	 */
	mutex_enter(&info->ti_gw_lock);
	new_gwi->gw_next = info->ti_gw;
	info->ti_gw = new_gwi;
	mutex_exit(&info->ti_gw_lock);

	return (new_gwi);
}

/*
 * Update old data for the gateway in our list with the new data.
 */
void
eibnx_replace_gw_in_gwlist(eibnx_thr_info_t *info, eibnx_gw_info_t *orig_gwi,
    eibnx_gw_info_t *new_gwi, ibt_wc_t *wc, uint8_t *recv_buf,
    boolean_t *gwi_changed)
{
	ib_sn_prefix_t new_gw_sn_prefix;
	ib_grh_t *grh;
	ib_gid_t sgid;
	boolean_t changed = B_FALSE;
	boolean_t gw_addr_changed = B_TRUE;

	/*
	 * We'll update all info received in the new advertisement in
	 * the original gwi and also move the gw_state to that of the state
	 * in the new gwi.
	 */
	mutex_enter(&info->ti_gw_lock);

	orig_gwi->gw_state = new_gwi->gw_state;

	/*
	 * The guids shouldn't really change for the "same" gateway
	 */
	if (new_gwi->gw_system_guid != orig_gwi->gw_system_guid) {
		ENX_DPRINTF_WARN("gateway system guid changed for the "
		    "*same* gateway from 0x%llx to 0x%llx",
		    orig_gwi->gw_system_guid, new_gwi->gw_system_guid);

		orig_gwi->gw_system_guid = new_gwi->gw_system_guid;
		changed = B_TRUE;
	}
	if (new_gwi->gw_guid != orig_gwi->gw_guid) {
		ENX_DPRINTF_WARN("gateway guid changed for the "
		    "*same* gateway from 0x%llx to 0x%llx",
		    orig_gwi->gw_guid, new_gwi->gw_guid);

		orig_gwi->gw_guid = new_gwi->gw_guid;
		changed = B_TRUE;
		gw_addr_changed = B_TRUE;
	}

	if (new_gwi->gw_adv_period != orig_gwi->gw_adv_period) {
		ENX_DPRINTF_DEBUG("gateway adv period changed "
		    "from 0x%lx to 0x%lx", orig_gwi->gw_adv_period,
		    new_gwi->gw_adv_period);

		orig_gwi->gw_adv_period = new_gwi->gw_adv_period;
		changed = B_TRUE;
	}
	if (new_gwi->gw_ka_period != orig_gwi->gw_ka_period) {
		ENX_DPRINTF_DEBUG("gateway ka period changed "
		    "from 0x%lx to 0x%lx", orig_gwi->gw_ka_period,
		    new_gwi->gw_ka_period);

		orig_gwi->gw_ka_period = new_gwi->gw_ka_period;
		changed = B_TRUE;
	}
	if (new_gwi->gw_vnic_ka_period != orig_gwi->gw_vnic_ka_period) {
		ENX_DPRINTF_DEBUG("vnic ka period changed "
		    "from 0x%lx to 0x%lx", orig_gwi->gw_vnic_ka_period,
		    new_gwi->gw_vnic_ka_period);

		orig_gwi->gw_vnic_ka_period = new_gwi->gw_vnic_ka_period;
		changed = B_TRUE;
	}
	if (new_gwi->gw_ctrl_qpn != orig_gwi->gw_ctrl_qpn) {
		ENX_DPRINTF_DEBUG("gateway control qpn changed "
		    "from 0x%lx to 0x%lx", orig_gwi->gw_ctrl_qpn,
		    new_gwi->gw_ctrl_qpn);

		orig_gwi->gw_ctrl_qpn = new_gwi->gw_ctrl_qpn;
		changed = B_TRUE;
	}
	if (new_gwi->gw_lid != orig_gwi->gw_lid) {
		ENX_DPRINTF_DEBUG("gateway lid changed from 0x%x to 0x%x",
		    orig_gwi->gw_lid, new_gwi->gw_lid);

		orig_gwi->gw_lid = new_gwi->gw_lid;
		changed = B_TRUE;
		gw_addr_changed = B_TRUE;
	}

	/*
	 * The identity of the gateway is currently defined by its portid,
	 * so this cannot be different or eibnx_find_gw_in_gwlist() wouldn't
	 * have thought it's the same.  For now though, we'll treat it
	 * like any other parameter, and flag it if we find this different.
	 */
	if (new_gwi->gw_portid != orig_gwi->gw_portid) {
		ENX_DPRINTF_WARN("gateway portid changed for the *same* "
		    "gateway from 0x%x to 0x%x", orig_gwi->gw_portid,
		    new_gwi->gw_portid);

		orig_gwi->gw_portid = new_gwi->gw_portid;
		changed = B_TRUE;
	}

	if (new_gwi->gw_is_host_adm_vnics != orig_gwi->gw_is_host_adm_vnics) {
		ENX_DPRINTF_DEBUG("host adm vnics changed from 0x%x to 0x%x",
		    orig_gwi->gw_is_host_adm_vnics,
		    new_gwi->gw_is_host_adm_vnics);

		orig_gwi->gw_is_host_adm_vnics = new_gwi->gw_is_host_adm_vnics;
		changed = B_TRUE;
	}
	if (new_gwi->gw_sl != orig_gwi->gw_sl) {
		ENX_DPRINTF_DEBUG("gateway sl changed from 0x%x to 0x%x",
		    orig_gwi->gw_sl, new_gwi->gw_sl);

		orig_gwi->gw_sl = new_gwi->gw_sl;
		changed = B_TRUE;
	}
	if (new_gwi->gw_n_rss_qpn != orig_gwi->gw_n_rss_qpn) {
		ENX_DPRINTF_DEBUG("gateway n_rss_qpn changed from 0x%x to 0x%x",
		    orig_gwi->gw_n_rss_qpn, new_gwi->gw_n_rss_qpn);

		orig_gwi->gw_n_rss_qpn = new_gwi->gw_n_rss_qpn;
		changed = B_TRUE;
	}

	/*
	 * The gw_flag_ucast_advt and gw_flag_available are expected to
	 * change over time (and even gw_num_net_vnics could change, but
	 * it's of no use to us presently), and we shouldn't trigger any
	 * flag for these
	 */
	orig_gwi->gw_flag_ucast_advt = new_gwi->gw_flag_ucast_advt;
	orig_gwi->gw_flag_available = new_gwi->gw_flag_available;
	orig_gwi->gw_num_net_vnics = new_gwi->gw_num_net_vnics;

	if (strncmp((const char *)new_gwi->gw_system_name,
	    (const char *)orig_gwi->gw_system_name, EIB_GW_SYSNAME_LEN) != 0) {
		ENX_DPRINTF_DEBUG("gateway system name changed from %s to %s",
		    orig_gwi->gw_system_name, new_gwi->gw_system_name);

		bcopy(new_gwi->gw_system_name, orig_gwi->gw_system_name,
		    EIB_GW_SYSNAME_LEN);
		changed = B_TRUE;
	}
	if (strncmp((const char *)new_gwi->gw_port_name,
	    (const char *)orig_gwi->gw_port_name, EIB_GW_PORTNAME_LEN) != 0) {
		ENX_DPRINTF_DEBUG("gateway port name changed from %s to %s",
		    orig_gwi->gw_port_name, new_gwi->gw_port_name);

		bcopy(new_gwi->gw_port_name, orig_gwi->gw_port_name,
		    EIB_GW_PORTNAME_LEN);
		changed = B_TRUE;
	}
	if (strncmp((const char *)new_gwi->gw_vendor_id,
	    (const char *)orig_gwi->gw_vendor_id, EIB_GW_VENDOR_LEN) != 0) {
		ENX_DPRINTF_DEBUG("vendor id changed from %s to %s",
		    orig_gwi->gw_vendor_id, new_gwi->gw_vendor_id);

		bcopy(new_gwi->gw_vendor_id, orig_gwi->gw_vendor_id,
		    EIB_GW_VENDOR_LEN);
		changed = B_TRUE;
	}

	/*
	 * See if the subnet prefix for the gateway has changed
	 */
	if (wc->wc_flags & IBT_WC_GRH_PRESENT) {
		grh = (ib_grh_t *)(uintptr_t)recv_buf;
		new_gw_sn_prefix = ntohll(grh->SGID.gid_prefix);
	} else {
		sgid = info->ti_pi->p_sgid_tbl[0];
		new_gw_sn_prefix = sgid.gid_prefix;
	}
	if (new_gw_sn_prefix != orig_gwi->gw_addr.ga_gid.gid_prefix) {
		ENX_DPRINTF_WARN("subnet prefix changed from 0x%llx to 0x%llx",
		    orig_gwi->gw_addr.ga_gid.gid_prefix, new_gw_sn_prefix);

		changed = B_TRUE;
		gw_addr_changed = B_TRUE;
	}

	/*
	 * If the gateway address has changed in any way, clear the current
	 * address vector and update the gateway guid and gateway qpn. The
	 * address vector will be created the next time a unicast solicit
	 * is attempted for this gateway.
	 */
	if (gw_addr_changed) {
		if (orig_gwi->gw_addr.ga_vect != NULL) {
			kmem_free(orig_gwi->gw_addr.ga_vect,
			    sizeof (ibt_adds_vect_t));
			orig_gwi->gw_addr.ga_vect = NULL;
		}
		orig_gwi->gw_addr.ga_gid.gid_prefix = new_gw_sn_prefix;
		orig_gwi->gw_addr.ga_gid.gid_guid = new_gwi->gw_guid;
		orig_gwi->gw_addr.ga_qpn = new_gwi->gw_ctrl_qpn;
		orig_gwi->gw_addr.ga_qkey = EIB_FIP_QKEY;
		orig_gwi->gw_addr.ga_pkey = EIB_ADMIN_PKEY;
	}

	mutex_exit(&info->ti_gw_lock);

	if (gwi_changed) {
		*gwi_changed = changed;
	}
}

/*
 * Queue up a node for EoIB instantiation and wake up the thread
 * that creates eoib nodes.
 */
void
eibnx_queue_for_creation(eibnx_thr_info_t *info, eibnx_gw_info_t *gwi)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_nodeq_t *new_node;

	/*
	 * For now, we'll simply do KM_NOSLEEP allocation, since this
	 * code is called from within rx processing
	 */
	new_node = kmem_zalloc(sizeof (eibnx_nodeq_t), KM_NOSLEEP);
	if (new_node == NULL) {
		ENX_DPRINTF_WARN("no memory, eoib node will not be "
		    "created for hca_guid=0x%llx, hca_port=0x%x, "
		    "gw_port_id=0x%x", info->ti_hca_guid,
		    info->ti_pi->p_port_num, gwi->gw_portid);
		return;
	}
	new_node->nc_info = info;
	new_node->nc_gwi = gwi;

	/*
	 * If the eoib node creation thread is dying (or dead), don't
	 * queue up any more requests for creation
	 */
	mutex_enter(&ss->nx_nodeq_lock);
	if (ss->nx_nodeq_thr_die) {
		kmem_free(new_node, sizeof (eibnx_nodeq_t));
	} else {
		new_node->nc_next = ss->nx_nodeq;
		ss->nx_nodeq = new_node;
		cv_signal(&ss->nx_nodeq_cv);
	}
	mutex_exit(&ss->nx_nodeq_lock);
}
