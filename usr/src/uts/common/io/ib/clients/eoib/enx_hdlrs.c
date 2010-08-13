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
#include <sys/sunndi.h>
#include <sys/ksynch.h>
#include <sys/callb.h>
#include <sys/ib/mgt/sm_attr.h>		/* SM_INIT_TYPE_REPLY_... */

#include <sys/ib/clients/eoib/enx_impl.h>

/*
 * Static function declarations
 */
static void eibnx_gw_is_alive(eibnx_gw_info_t *);
static void eibnx_gw_is_aware(eibnx_thr_info_t *, eibnx_gw_info_t *, boolean_t);
static void eibnx_process_rx(eibnx_thr_info_t *, ibt_wc_t *, eibnx_wqe_t *);
static void eibnx_handle_wcerr(uint8_t, eibnx_wqe_t *, eibnx_thr_info_t *);
static void eibnx_handle_login_ack(eibnx_thr_info_t *, uint8_t *);
static void eibnx_handle_gw_rebirth(eibnx_thr_info_t *, uint16_t);
static void eibnx_handle_gw_info_update(eibnx_thr_info_t *, uint16_t, void *);
static int eibnx_replace_portinfo(eibnx_thr_info_t *, ibt_hca_portinfo_t *,
    uint_t);
static void eibnx_handle_port_events(ibt_hca_hdl_t, uint8_t);
static void eibnx_handle_hca_attach(ib_guid_t);
static void eibnx_handle_hca_detach(ib_guid_t);

/*
 * NDI event handle we need
 */
extern ndi_event_hdl_t enx_ndi_event_hdl;

/*
 * SM's init type reply flags
 */
#define	ENX_PORT_ATTR_LOADED(itr)				\
	(((itr) & SM_INIT_TYPE_REPLY_NO_LOAD_REPLY) == 0)
#define	ENX_PORT_ATTR_NOT_PRESERVED(itr)			\
	(((itr) & SM_INIT_TYPE_PRESERVE_CONTENT_REPLY) == 0)
#define	ENX_PORT_PRES_NOT_PRESERVED(itr)			\
	(((itr) & SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY) == 0)

/*
 * Port monitor progress flags (all flag values should be non-zero)
 */
#define	ENX_MON_LINKSTATE_UP		0x01
#define	ENX_MON_FOUND_MCGS		0x02
#define	ENX_MON_SETUP_CQ		0x04
#define	ENX_MON_SETUP_UD_CHAN		0x08
#define	ENX_MON_SETUP_BUFS		0x10
#define	ENX_MON_SETUP_CQ_HDLR		0x20
#define	ENX_MON_JOINED_MCGS		0x40
#define	ENX_MON_MULTICAST_SLCT		0x80
#define	ENX_MON_MAX			0xFF

/*
 * Per-port thread to solicit, monitor and discover EoIB gateways
 * and create the corresponding EoIB driver instances on the host.
 */
void
eibnx_port_monitor(eibnx_thr_info_t *info)
{
	clock_t solicit_period_ticks;
	clock_t deadline;
	kmutex_t ci_lock;
	callb_cpr_t ci;
	char thr_name[MAXNAMELEN];

	(void) snprintf(thr_name, MAXNAMELEN, ENX_PORT_MONITOR,
	    info->ti_pi->p_port_num);

	mutex_init(&ci_lock, NULL, MUTEX_DRIVER, NULL);
	CALLB_CPR_INIT(&ci, &ci_lock, callb_generic_cpr, thr_name);

	info->ti_progress = 0;

	/*
	 * If the port is not active yet, wait for a port up event. The
	 * async handler, when it sees a port-up event, is expected to
	 * update the port_monitor's portinfo structure's p_linkstate
	 * and wake us up with ENX_EVENT_LINK_UP.
	 */
	while (info->ti_pi->p_linkstate != IBT_PORT_ACTIVE) {
		mutex_enter(&info->ti_event_lock);
		while ((info->ti_event &
		    (ENX_EVENT_LINK_UP | ENX_EVENT_DIE)) == 0) {
			mutex_enter(&ci_lock);
			CALLB_CPR_SAFE_BEGIN(&ci);
			mutex_exit(&ci_lock);

			cv_wait(&info->ti_event_cv, &info->ti_event_lock);

			mutex_enter(&ci_lock);
			CALLB_CPR_SAFE_END(&ci, &ci_lock);
			mutex_exit(&ci_lock);
		}
		if (info->ti_event & ENX_EVENT_DIE) {
			mutex_exit(&info->ti_event_lock);
			goto port_monitor_exit;
		}
		info->ti_event &= (~ENX_EVENT_LINK_UP);
		mutex_exit(&info->ti_event_lock);
	}
	info->ti_progress |= ENX_MON_LINKSTATE_UP;

	/*
	 * Locate the multicast groups for sending solicit requests
	 * to the GW and receiving advertisements from the GW. If
	 * either of the mcg is not present, wait for them to be
	 * created by the GW.
	 */
	while (eibnx_find_mgroups(info) != ENX_E_SUCCESS) {
		mutex_enter(&info->ti_event_lock);
		while ((info->ti_event &
		    (ENX_EVENT_MCGS_AVAILABLE | ENX_EVENT_DIE)) == 0) {
			mutex_enter(&ci_lock);
			CALLB_CPR_SAFE_BEGIN(&ci);
			mutex_exit(&ci_lock);

			cv_wait(&info->ti_event_cv, &info->ti_event_lock);

			mutex_enter(&ci_lock);
			CALLB_CPR_SAFE_END(&ci, &ci_lock);
			mutex_exit(&ci_lock);
		}
		if (info->ti_event & ENX_EVENT_DIE) {
			mutex_exit(&info->ti_event_lock);
			goto port_monitor_exit;
		}
		info->ti_event &= (~ENX_EVENT_MCGS_AVAILABLE);
		mutex_exit(&info->ti_event_lock);
	}
	info->ti_progress |= ENX_MON_FOUND_MCGS;

	/*
	 * Setup a shared CQ
	 */
	if (eibnx_setup_cq(info) != ENX_E_SUCCESS) {
		ENX_DPRINTF_ERR("eibnx_setup_cq() failed, terminating "
		    "port monitor for (hca_guid=0x%llx, port_num=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		goto port_monitor_exit;
	}
	info->ti_progress |= ENX_MON_SETUP_CQ;

	/*
	 * Setup UD channel
	 */
	if (eibnx_setup_ud_channel(info) != ENX_E_SUCCESS) {
		ENX_DPRINTF_ERR("eibnx_setup_ud_channel() failed, terminating "
		    "port monitor for (hca_guid=0x%llx, port_num=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		goto port_monitor_exit;
	}
	info->ti_progress |= ENX_MON_SETUP_UD_CHAN;

	/*
	 * Allocate/initialize any tx/rx buffers
	 */
	if (eibnx_setup_bufs(info) != ENX_E_SUCCESS) {
		ENX_DPRINTF_ERR("eibnx_setup_bufs() failed, terminating "
		    "port monitor for (hca_guid=0x%llx, port_num=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		goto port_monitor_exit;
	}
	info->ti_progress |= ENX_MON_SETUP_BUFS;

	/*
	 * Setup completion handler
	 */
	if (eibnx_setup_cq_handler(info) != ENX_E_SUCCESS) {
		ENX_DPRINTF_ERR("eibnx_setup_cq_handler() failed, terminating "
		    "port monitor for (hca_guid=0x%llx, port_num=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		goto port_monitor_exit;
	}
	info->ti_progress |= ENX_MON_SETUP_CQ_HDLR;

	/*
	 * Join EoIB multicast groups
	 */
	if (eibnx_join_mcgs(info) != ENX_E_SUCCESS) {
		ENX_DPRINTF_ERR("eibnx_join_mcgs() failed, terminating ",
		    "port monitor for (hca_guid=0x%llx, port_num=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		goto port_monitor_exit;
	}
	info->ti_progress |= ENX_MON_JOINED_MCGS;

	/*
	 * Send SOLICIT pkt to the EoIB multicast group
	 */
	if (eibnx_fip_solicit_mcast(info) != ENX_E_SUCCESS) {
		ENX_DPRINTF_ERR("eibnx_fip_solicit_mcast() failed, terminating "
		    "port monitor for (hca_guid=0x%llx, port_num=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		goto port_monitor_exit;
	}
	info->ti_progress |= ENX_MON_MULTICAST_SLCT;

	mutex_enter(&info->ti_event_lock);

	solicit_period_ticks = drv_usectohz(ENX_DFL_SOLICIT_PERIOD_USEC);

periodic_solicit:
	deadline = ddi_get_lbolt() + solicit_period_ticks;
	while ((info->ti_event & (ENX_EVENT_TIMED_OUT | ENX_EVENT_DIE)) == 0) {
		mutex_enter(&ci_lock);
		CALLB_CPR_SAFE_BEGIN(&ci);
		mutex_exit(&ci_lock);

		if (cv_timedwait(&info->ti_event_cv, &info->ti_event_lock,
		    deadline) == -1) {
			info->ti_event |= ENX_EVENT_TIMED_OUT;
		}

		mutex_enter(&ci_lock);
		CALLB_CPR_SAFE_END(&ci, &ci_lock);
		mutex_exit(&ci_lock);
	}

	if (info->ti_event & ENX_EVENT_DIE) {
		mutex_exit(&info->ti_event_lock);
		goto port_monitor_exit;
	}

	if (info->ti_event & ENX_EVENT_TIMED_OUT) {
		if (eibnx_fip_solicit_ucast(info,
		    &solicit_period_ticks) != ENX_E_SUCCESS) {
			ENX_DPRINTF_WARN("failed to send solicit ucast to "
			    "gateways (hca_guid=0x%llx, port_num=0x%x)",
			    info->ti_hca_guid, info->ti_pi->p_port_num);
		}
		info->ti_event &= ~ENX_EVENT_TIMED_OUT;
	}

	goto periodic_solicit;

port_monitor_exit:
	if (info->ti_progress & ENX_MON_MULTICAST_SLCT) {
		eibnx_cleanup_port_nodes(info);
		info->ti_progress &= (~ENX_MON_MULTICAST_SLCT);
	}
	if (info->ti_progress & ENX_MON_JOINED_MCGS) {
		eibnx_rb_join_mcgs(info);
		info->ti_progress &= (~ENX_MON_JOINED_MCGS);
	}
	if (info->ti_progress & ENX_MON_SETUP_CQ_HDLR) {
		eibnx_rb_setup_cq_handler(info);
		info->ti_progress &= (~ENX_MON_SETUP_CQ_HDLR);
	}
	if (info->ti_progress & ENX_MON_SETUP_BUFS) {
		eibnx_rb_setup_bufs(info);
		info->ti_progress &= (~ENX_MON_SETUP_BUFS);
	}
	if (info->ti_progress & ENX_MON_SETUP_UD_CHAN) {
		eibnx_rb_setup_ud_channel(info);
		info->ti_progress &= (~ENX_MON_SETUP_UD_CHAN);
	}
	if (info->ti_progress & ENX_MON_SETUP_CQ) {
		eibnx_rb_setup_cq(info);
		info->ti_progress &= (~ENX_MON_SETUP_CQ);
	}
	if (info->ti_progress & ENX_MON_FOUND_MCGS) {
		eibnx_rb_find_mgroups(info);
		info->ti_progress &= (~ENX_MON_FOUND_MCGS);
	}

	mutex_enter(&ci_lock);
	CALLB_CPR_EXIT(&ci);
	mutex_destroy(&ci_lock);
}

/*
 * Async subnet notices handler registered with IBTF
 */
/*ARGSUSED*/
void
eibnx_subnet_notices_handler(void *arg, ib_gid_t gid,
    ibt_subnet_event_code_t sn_evcode, ibt_subnet_event_t *sn_event)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	ib_gid_t notice_gid;

	switch (sn_evcode) {
	case IBT_SM_EVENT_MCG_CREATED:
		notice_gid = sn_event->sm_notice_gid;

		if ((notice_gid.gid_prefix == enx_solicit_mgid.gid_prefix &&
		    notice_gid.gid_guid == enx_solicit_mgid.gid_guid) ||
		    (notice_gid.gid_prefix == enx_advertise_mgid.gid_prefix &&
		    notice_gid.gid_guid == enx_advertise_mgid.gid_guid)) {

			mutex_enter(&ss->nx_lock);
			for (ti = ss->nx_thr_info; ti; ti = ti->ti_next) {
				mutex_enter(&ti->ti_event_lock);
				ti->ti_event |= ENX_EVENT_MCGS_AVAILABLE;
				cv_broadcast(&ti->ti_event_cv);
				mutex_exit(&ti->ti_event_lock);
			}
			mutex_exit(&ss->nx_lock);
		}
		break;

	case IBT_SM_EVENT_MCG_DELETED:
		break;

	default:
		break;
	}
}

/*
 * Async event handler registered with IBTF
 */
/*ARGSUSED*/
void
eibnx_async_handler(void *clnt_pvt, ibt_hca_hdl_t hca,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	switch (code) {
	case IBT_ERROR_CATASTROPHIC_CHAN:
	case IBT_ERROR_INVALID_REQUEST_CHAN:
	case IBT_ERROR_ACCESS_VIOLATION_CHAN:
	case IBT_ERROR_CQ:
	case IBT_ERROR_CATASTROPHIC_SRQ:
		ENX_DPRINTF_ERR("ibt ERROR event 0x%x received "
		    "(hca_guid=0x%llx)", code, event->ev_hca_guid);
		break;

	case IBT_ERROR_PORT_DOWN:
		ENX_DPRINTF_WARN("ibt PORT_DOWN event received "
		    "(hca_guid=0x%llx, port_num=0x%x)",
		    event->ev_hca_guid, event->ev_port);
		break;

	case IBT_EVENT_PORT_UP:
		ENX_DPRINTF_WARN("ibt PORT_UP event received "
		    "(hca_guid=0x%llx, port_num=0x%x)",
		    event->ev_hca_guid, event->ev_port);
		eibnx_handle_port_events(hca, event->ev_port);
		break;

	case IBT_PORT_CHANGE_EVENT:
		ENX_DPRINTF_WARN("ibt PORT_CHANGE event received "
		    "(hca_guid=0x%llx, port_num=0x%x)",
		    event->ev_hca_guid, event->ev_port);
		eibnx_handle_port_events(hca, event->ev_port);
		break;

	case IBT_CLNT_REREG_EVENT:
		ENX_DPRINTF_WARN("ibt CLNT_REREG event received "
		    "(hca_guid=0x%llx, port_num=0x%x)",
		    event->ev_hca_guid, event->ev_port);
		eibnx_handle_port_events(hca, event->ev_port);
		break;

	case IBT_HCA_ATTACH_EVENT:
		ENX_DPRINTF_VERBOSE("ibt HCA_ATTACH event received "
		    "(new hca_guid=0x%llx)", event->ev_hca_guid);
		eibnx_handle_hca_attach(event->ev_hca_guid);
		break;

	case IBT_HCA_DETACH_EVENT:
		ENX_DPRINTF_VERBOSE("ibt HCA_DETACH event received "
		    "(target hca_guid=0x%llx)", event->ev_hca_guid);
		eibnx_handle_hca_detach(event->ev_hca_guid);
		break;

	default:
		ENX_DPRINTF_VERBOSE("ibt UNSUPPORTED event 0x%x received "
		    "(hca_guid=0x%llx)", code, event->ev_hca_guid);
		break;
	}
}

boolean_t
eibnx_is_gw_dead(eibnx_gw_info_t *gwi)
{
	int64_t cur_lbolt;

	cur_lbolt = ddi_get_lbolt64();

	mutex_enter(&gwi->gw_adv_lock);
	if ((cur_lbolt - gwi->gw_adv_last_lbolt) > gwi->gw_adv_timeout_ticks) {
		gwi->gw_adv_flag = ENX_GW_DEAD;
		mutex_exit(&gwi->gw_adv_lock);
		return (B_TRUE);
	}
	mutex_exit(&gwi->gw_adv_lock);

	return (B_FALSE);
}

static void
eibnx_gw_is_alive(eibnx_gw_info_t *gwi)
{
	/*
	 * We've just received a multicast advertisement from this
	 * gateway.  Multicast or unicast, this means that the gateway
	 * is alive. Record this timestamp (in ticks).
	 */
	mutex_enter(&gwi->gw_adv_lock);
	gwi->gw_adv_last_lbolt = ddi_get_lbolt64();
	if (gwi->gw_adv_flag == ENX_GW_DEAD) {
		gwi->gw_adv_flag = ENX_GW_ALIVE;
	}
	mutex_exit(&gwi->gw_adv_lock);
}

static void
eibnx_gw_is_aware(eibnx_thr_info_t *info, eibnx_gw_info_t *gwi,
    boolean_t gwi_changed)
{
	eib_gw_info_t eib_gwi;
	boolean_t post_rebirth_event = B_FALSE;

	/*
	 * We're here when we receive a unicast advertisement from a
	 * gateway. If this gateway was discovered earlier but was in
	 * a dead state, this means it has come back alive and become
	 * aware of us.  We may need to inform any EoIB children
	 * waiting for notification.  Note that if this gateway is
	 * being discovered for the first time now, we wouldn't have
	 * created the binding eoib node for it (we will do that when
	 * we return from this routine), so the "rebirth" and "gw info
	 * update" event postings will be NOPs.
	 */
	mutex_enter(&gwi->gw_adv_lock);
	gwi->gw_adv_last_lbolt = ddi_get_lbolt64();
	if (gwi->gw_adv_flag != ENX_GW_AWARE) {
		post_rebirth_event = B_TRUE;
	}
	gwi->gw_adv_flag = ENX_GW_AWARE;
	mutex_exit(&gwi->gw_adv_lock);

	/*
	 * If we have a gateway information update event, we post that
	 * first, so any rebirth event processed later will have the
	 * correct gateway information.
	 */
	if (gwi_changed) {
		eib_gwi.gi_system_guid = gwi->gw_system_guid;
		eib_gwi.gi_guid = gwi->gw_guid;
		eib_gwi.gi_sn_prefix = gwi->gw_addr.ga_gid.gid_prefix;
		eib_gwi.gi_adv_period = gwi->gw_adv_period;
		eib_gwi.gi_ka_period = gwi->gw_ka_period;
		eib_gwi.gi_vnic_ka_period = gwi->gw_vnic_ka_period;
		eib_gwi.gi_ctrl_qpn = gwi->gw_ctrl_qpn;
		eib_gwi.gi_lid = gwi->gw_lid;
		eib_gwi.gi_portid = gwi->gw_portid;
		eib_gwi.gi_num_net_vnics = gwi->gw_num_net_vnics;
		eib_gwi.gi_flag_available = gwi->gw_flag_available;
		eib_gwi.gi_is_host_adm_vnics = gwi->gw_is_host_adm_vnics;
		eib_gwi.gi_sl = gwi->gw_sl;
		eib_gwi.gi_n_rss_qpn = gwi->gw_n_rss_qpn;
		bcopy(gwi->gw_system_name, eib_gwi.gi_system_name,
		    EIB_GW_SYSNAME_LEN);
		bcopy(gwi->gw_port_name, eib_gwi.gi_port_name,
		    EIB_GW_PORTNAME_LEN);
		bcopy(gwi->gw_vendor_id, eib_gwi.gi_vendor_id,
		    EIB_GW_VENDOR_LEN);

		eibnx_handle_gw_info_update(info, eib_gwi.gi_portid, &eib_gwi);
	}
	if (post_rebirth_event) {
		eibnx_handle_gw_rebirth(info, gwi->gw_portid);
	}
}

/*
 * Thread to create eoib nodes and online instances
 */
void
eibnx_create_eoib_node(void)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_nodeq_t *node;
	kmutex_t ci_lock;
	callb_cpr_t ci;

	mutex_init(&ci_lock, NULL, MUTEX_DRIVER, NULL);
	CALLB_CPR_INIT(&ci, &ci_lock, callb_generic_cpr, ENX_NODE_CREATOR);

wait_for_node_to_create:
	mutex_enter(&ss->nx_nodeq_lock);

	while ((ss->nx_nodeq == NULL) && (ss->nx_nodeq_thr_die == 0)) {
		mutex_enter(&ci_lock);
		CALLB_CPR_SAFE_BEGIN(&ci);
		mutex_exit(&ci_lock);

		cv_wait(&ss->nx_nodeq_cv, &ss->nx_nodeq_lock);

		mutex_enter(&ci_lock);
		CALLB_CPR_SAFE_END(&ci, &ci_lock);
		mutex_exit(&ci_lock);
	}

	/*
	 * If this is not really a work item, but a request for us to
	 * die, throwaway all pending work requests and just die.
	 */
	if (ss->nx_nodeq_thr_die) {
		while (ss->nx_nodeq) {
			node = ss->nx_nodeq;
			ss->nx_nodeq = node->nc_next;
			node->nc_next = NULL;

			kmem_free(node, sizeof (eibnx_nodeq_t));
		}
		mutex_exit(&ss->nx_nodeq_lock);

		mutex_enter(&ci_lock);
		CALLB_CPR_EXIT(&ci);
		mutex_destroy(&ci_lock);

		return;
	}

	/*
	 * Grab the first node entry from the queue
	 */
	ASSERT(ss->nx_nodeq != NULL);
	node = ss->nx_nodeq;
	ss->nx_nodeq = node->nc_next;
	node->nc_next = NULL;

	mutex_exit(&ss->nx_nodeq_lock);

	(void) eibnx_configure_node(node->nc_info, node->nc_gwi, NULL);

	kmem_free(node, sizeof (eibnx_nodeq_t));
	goto wait_for_node_to_create;

	/*NOTREACHED*/
}

/*
 * Tx and Rx completion interrupt handler. Guaranteed to be single
 * threaded and nonreentrant for this CQ.
 */
void
eibnx_comp_intr(ibt_cq_hdl_t cq_hdl, void *arg)
{
	eibnx_thr_info_t *info = arg;

	if (info->ti_cq_hdl != cq_hdl) {
		ENX_DPRINTF_DEBUG("eibnx_comp_intr: "
		    "cq_hdl(0x%llx) != info->ti_cq_hdl(0x%llx), "
		    "ignoring completion", cq_hdl, info->ti_cq_hdl);
		return;
	}

	ASSERT(info->ti_softint_hdl != NULL);

	(void) ddi_intr_trigger_softint(info->ti_softint_hdl, NULL);
}

/*
 * Send and Receive completion handler functions for EoIB nexus
 */

/*ARGSUSED*/
uint_t
eibnx_comp_handler(caddr_t arg1, caddr_t arg2)
{
	eibnx_thr_info_t *info = (eibnx_thr_info_t *)arg1;
	ibt_wc_t *wc;
	eibnx_wqe_t *wqe;
	ibt_status_t ret;
	uint_t polled;
	int i;

	/*
	 * Make sure the port monitor isn't killed if we're in the completion
	 * handler. If the port monitor thread is already being killed, we'll
	 * stop processing completions.
	 */
	mutex_enter(&info->ti_event_lock);
	if (info->ti_event & (ENX_EVENT_DIE | ENX_EVENT_COMPLETION)) {
		mutex_exit(&info->ti_event_lock);
		return ((uint_t)ENX_E_SUCCESS);
	}
	info->ti_event |= ENX_EVENT_COMPLETION;
	mutex_exit(&info->ti_event_lock);

	/*
	 * Re-arm the notification callback before we start polling
	 * the completion queue.  There's nothing much we can do if the
	 * enable_cq_notify fails - we issue a warning and move on.
	 */
	ret = ibt_enable_cq_notify(info->ti_cq_hdl, IBT_NEXT_COMPLETION);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_enable_cq_notify(cq_hdl=0x%llx) "
		    "failed, ret=%d", info->ti_cq_hdl, ret);
	}

	/*
	 * Handle tx and rx completions
	 */
	while ((ret = ibt_poll_cq(info->ti_cq_hdl, info->ti_wc, info->ti_cq_sz,
	    &polled)) == IBT_SUCCESS) {
		for (wc = info->ti_wc, i = 0; i < polled; i++, wc++) {
			wqe = (eibnx_wqe_t *)(uintptr_t)wc->wc_id;
			if (wc->wc_status != IBT_WC_SUCCESS) {
				eibnx_handle_wcerr(wc->wc_status, wqe, info);
			} else if (wqe->qe_type == ENX_QETYP_RWQE) {
				eibnx_process_rx(info, wc, wqe);
				eibnx_return_rwqe(info, wqe);
			} else {
				eibnx_return_swqe(wqe);
			}
		}
	}

	/*
	 * On the way out, make sure we wake up any pending death requestor
	 * for the port-monitor thread. Note that we need to do a cv_broadcast()
	 * here since there could be multiple threads sleeping on the event cv
	 * and we want to make sure all waiters get a chance to see if it's
	 * their turn.
	 */
	mutex_enter(&info->ti_event_lock);
	info->ti_event &= (~ENX_EVENT_COMPLETION);
	cv_broadcast(&info->ti_event_cv);
	mutex_exit(&info->ti_event_lock);

	return (DDI_INTR_CLAIMED);
}

/*
 * Rx processing code
 */
static void
eibnx_process_rx(eibnx_thr_info_t *info, ibt_wc_t *wc, eibnx_wqe_t *wqe)
{
	eibnx_gw_msg_t msg;
	eibnx_gw_info_t *gwi;
	eibnx_gw_info_t *orig_gwi;
	eibnx_gw_info_t *new_gwi;
	uint_t orig_gw_state;
	uint8_t *pkt = (uint8_t *)(uintptr_t)(wqe->qe_sgl.ds_va);
	boolean_t gwi_changed;

	/*
	 * We'll simply drop any packet (including broadcast advertisements
	 * from gws) we receive before we've done our solicitation broadcast.
	 */
	if (info->ti_mcast_done == 0) {
		return;
	}

	/*
	 * Skip the GRH and parse the message in the packet
	 */
	if (eibnx_fip_parse_pkt(pkt + ENX_GRH_SZ, &msg) != ENX_E_SUCCESS) {
		return;
	}

	/*
	 * If it was a login ack for one of our children, we need to pass
	 * it on to the child
	 */
	if (msg.gm_type == FIP_VNIC_LOGIN_ACK) {
		eibnx_handle_login_ack(info, pkt);
		return;
	}

	/*
	 * Other than that, we only handle gateway advertisements
	 */
	if (msg.gm_type != FIP_GW_ADVERTISE_MCAST &&
	    msg.gm_type != FIP_GW_ADVERTISE_UCAST) {
		return;
	}

	gwi = &msg.u.gm_info;

	/*
	 * State machine to create eoib instances. Whether this advertisement
	 * is from a new gateway or an old gateway that we already know about,
	 * if this was a unicast response to our earlier solicitation and it's
	 * the first time we're receiving it from this gateway, we're ready to
	 * login, so we create the EoIB instance for it.
	 */
	orig_gwi = eibnx_find_gw_in_gwlist(info, gwi);
	if (orig_gwi == NULL) {
		if (gwi->gw_flag_available == 0) {
			gwi->gw_state = ENX_GW_STATE_UNAVAILABLE;
			gwi->gw_adv_flag = ENX_GW_ALIVE;
			(void) eibnx_add_gw_to_gwlist(info, gwi, wc, pkt);
		} else if (gwi->gw_flag_ucast_advt == 0) {
			gwi->gw_state = ENX_GW_STATE_AVAILABLE;
			gwi->gw_adv_flag = ENX_GW_ALIVE;
			(void) eibnx_add_gw_to_gwlist(info, gwi, wc, pkt);
		} else {
			gwi->gw_state = ENX_GW_STATE_READY_TO_LOGIN;
			gwi->gw_adv_flag = ENX_GW_AWARE;
			if ((new_gwi = eibnx_add_gw_to_gwlist(info, gwi,
			    wc, pkt)) != NULL) {
				eibnx_queue_for_creation(info, new_gwi);
			}
		}
	} else {
		orig_gw_state = orig_gwi->gw_state;
		if (gwi->gw_flag_available == 0) {
			gwi->gw_state = ENX_GW_STATE_UNAVAILABLE;
			eibnx_replace_gw_in_gwlist(info, orig_gwi, gwi,
			    wc, pkt, NULL);
			eibnx_gw_is_alive(orig_gwi);

		} else if (gwi->gw_flag_ucast_advt == 0) {
			if (orig_gw_state == ENX_GW_STATE_UNAVAILABLE) {
				gwi->gw_state = ENX_GW_STATE_AVAILABLE;
			} else {
				gwi->gw_state = orig_gw_state;
			}
			eibnx_replace_gw_in_gwlist(info, orig_gwi, gwi,
			    wc, pkt, NULL);
			eibnx_gw_is_alive(orig_gwi);

		} else {
			gwi->gw_state = ENX_GW_STATE_READY_TO_LOGIN;
			eibnx_replace_gw_in_gwlist(info, orig_gwi, gwi,
			    wc, pkt, &gwi_changed);
			eibnx_gw_is_aware(info, orig_gwi, gwi_changed);

			if (orig_gw_state != ENX_GW_STATE_READY_TO_LOGIN)
				eibnx_queue_for_creation(info, orig_gwi);
		}
	}
}

/*ARGSUSED*/
static void
eibnx_handle_wcerr(uint8_t wcerr, eibnx_wqe_t *wqe, eibnx_thr_info_t *info)
{
	/*
	 * Currently, all we do is report
	 */
	switch (wcerr) {
	case IBT_WC_WR_FLUSHED_ERR:
		ENX_DPRINTF_VERBOSE("IBT_WC_WR_FLUSHED_ERR seen "
		    "(hca_guid=0x%llx, port_num=0x%x, wqe_type=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num, wqe->qe_type);
		break;

	case IBT_WC_LOCAL_CHAN_OP_ERR:
		ENX_DPRINTF_ERR("IBT_WC_LOCAL_CHAN_OP_ERR seen "
		    "(hca_guid=0x%llx, port_num=0x%x, wqe_type=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num, wqe->qe_type);
		break;

	case IBT_WC_LOCAL_PROTECT_ERR:
		ENX_DPRINTF_ERR("IBT_WC_LOCAL_PROTECT_ERR seen "
		    "(hca_guid=0x%llx, port_num=0x%x, wqe_type=0x%x)",
		    info->ti_hca_guid, info->ti_pi->p_port_num, wqe->qe_type);
		break;
	}
}

static void
eibnx_handle_login_ack(eibnx_thr_info_t *info, uint8_t *pkt)
{
	eibnx_t *ss = enx_global_ss;
	fip_login_ack_t *ack;
	fip_desc_vnic_login_t *login;
	ddi_eventcookie_t cookie;
	dev_info_t *rdip;
	uint16_t vnic_id;
	uint16_t inst;
	int ret;

	/*
	 * When we get login acknowledgements, we simply invoke the
	 * appropriate EoIB driver callback to process it on behalf
	 * of the driver instance. We will let the callback do error
	 * checks.
	 */
	ack = (fip_login_ack_t *)(pkt + ENX_GRH_SZ);
	login = &(ack->ak_vnic_login);
	vnic_id = ntohs(login->vl_vnic_id);
	inst = EIB_DEVI_INSTANCE(vnic_id);

	if ((rdip = eibnx_find_child_dip_by_inst(info, inst)) == NULL) {
		ENX_DPRINTF_DEBUG("no eoib child with instance 0x%x found "
		    "for (hca_guid=0x%llx, port_num=0x%x)", inst,
		    info->ti_hca_guid, info->ti_pi->p_port_num);
		return;
	}

	ret = ndi_event_retrieve_cookie(enx_ndi_event_hdl, rdip,
	    EIB_NDI_EVENT_LOGIN_ACK, &cookie, NDI_EVENT_NOPASS);
	if (ret != NDI_SUCCESS) {
		ENX_DPRINTF_WARN("no login-ack cookie for (hca_guid=0x%llx, "
		    "port_num=0x%x, eoib_inst=0x%x), ret=%d", info->ti_hca_guid,
		    info->ti_pi->p_port_num, inst, ret);
		return;
	}

	(void) ndi_post_event(ss->nx_dip, rdip, cookie, (void *)pkt);
}

static void
eibnx_handle_gw_rebirth(eibnx_thr_info_t *info, uint16_t portid)
{
	eibnx_t *ss = enx_global_ss;
	ddi_eventcookie_t cookie;
	dev_info_t *rdip;
	int ret;

	if ((rdip = eibnx_find_child_dip_by_gw(info, portid)) == NULL) {
		ENX_DPRINTF_WARN("no eoib child bound to gw portid 0x%x "
		    "found for (hca_guid=0x%llx, port_num=0x%x)",
		    portid, info->ti_hca_guid, info->ti_pi->p_port_num);
		return;
	}

	ret = ndi_event_retrieve_cookie(enx_ndi_event_hdl, rdip,
	    EIB_NDI_EVENT_GW_AVAILABLE, &cookie, NDI_EVENT_NOPASS);
	if (ret != NDI_SUCCESS) {
		ENX_DPRINTF_WARN("no gw-available cookie for (hca_guid=0x%llx, "
		    "port_num=0x%x, gw_portid=0x%x), ret=%d", info->ti_hca_guid,
		    info->ti_pi->p_port_num, portid, ret);
		return;
	}

	(void) ndi_post_event(ss->nx_dip, rdip, cookie, NULL);
}

static void
eibnx_handle_gw_info_update(eibnx_thr_info_t *info, uint16_t portid,
    void *new_gw_info)
{
	eibnx_t *ss = enx_global_ss;
	ddi_eventcookie_t cookie;
	dev_info_t *rdip;
	int ret;

	if ((rdip = eibnx_find_child_dip_by_gw(info, portid)) == NULL) {
		ENX_DPRINTF_WARN("no eoib child bound to gw portid 0x%x "
		    "found for (hca_guid=0x%llx, port_num=0x%x)",
		    portid, info->ti_hca_guid, info->ti_pi->p_port_num);
		return;
	}

	ret = ndi_event_retrieve_cookie(enx_ndi_event_hdl, rdip,
	    EIB_NDI_EVENT_GW_INFO_UPDATE, &cookie, NDI_EVENT_NOPASS);
	if (ret != NDI_SUCCESS) {
		ENX_DPRINTF_WARN("no gw-info-update cookie for "
		    "(hca_guid=0x%llx, port_num=0x%x, gw_portid=0x%x), "
		    "ret=%d", info->ti_hca_guid, info->ti_pi->p_port_num,
		    portid, ret);
		return;
	}

	(void) ndi_post_event(ss->nx_dip, rdip, cookie, new_gw_info);
}

static int
eibnx_replace_portinfo(eibnx_thr_info_t *ti, ibt_hca_portinfo_t *new_pi,
    uint_t new_size_pi)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_hca_t *hca;
	eibnx_port_t *port;

	mutex_enter(&ss->nx_lock);

	for (hca = ss->nx_hca; hca; hca = hca->hc_next) {
		if (hca->hc_hdl == ti->ti_hca)
			break;
	}

	if (hca == NULL) {
		ENX_DPRINTF_WARN("hca hdl (0x%llx) not found in hca list",
		    ti->ti_hca);
		mutex_exit(&ss->nx_lock);
		return (ENX_E_FAILURE);
	}

	for (port = hca->hc_port; port; port = port->po_next) {
		if (port->po_pi == ti->ti_pi) {
			ibt_free_portinfo(port->po_pi, port->po_pi_size);
			port->po_pi = new_pi;
			port->po_pi_size = new_size_pi;
			ti->ti_pi = port->po_pi;
			break;
		}
	}

	if (port == NULL) {
		ENX_DPRINTF_WARN("portinfo (0x%llx) not found in hca list",
		    ti->ti_pi);
		mutex_exit(&ss->nx_lock);
		return (ENX_E_FAILURE);
	}

	mutex_exit(&ss->nx_lock);

	return (ENX_E_SUCCESS);
}

static void
eibnx_handle_port_events(ibt_hca_hdl_t ev_hca, uint8_t ev_portnum)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	ibt_hca_portinfo_t *pi;
	ibt_status_t ret;
	uint_t num_pi;
	uint_t size_pi;
	uint8_t itr;

	/*
	 * Find the port monitor thread that matches the event hca and
	 * portnum
	 */
	mutex_enter(&ss->nx_lock);
	for (ti = ss->nx_thr_info; ti; ti = ti->ti_next) {
		if ((ti->ti_hca == ev_hca) &&
		    (ti->ti_pi->p_port_num == ev_portnum)) {
			break;
		}
	}
	mutex_exit(&ss->nx_lock);

	if (ti == NULL)
		return;

	/*
	 * See if we need to rejoin the mcgs for this port and do so if true
	 */
	ret = ibt_query_hca_ports(ev_hca, ev_portnum, &pi, &num_pi, &size_pi);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_WARN("ibt_query_hca_ports() failed with %d", ret);
		return;
	} else if (num_pi != 1 || pi->p_linkstate != IBT_PORT_ACTIVE) {
		ENX_DPRINTF_WARN("ibt_query_hca_ports(port_num=%d) failed, "
		    "num_pi=%d, linkstate=0x%x", ev_portnum, num_pi,
		    pi->p_linkstate);
		ibt_free_portinfo(pi, size_pi);
		return;
	}

	itr = pi->p_init_type_reply;
	if (ENX_PORT_ATTR_LOADED(itr) && ENX_PORT_ATTR_NOT_PRESERVED(itr)) {
		/*
		 * If our port's base lid has changed, we need to replace
		 * the saved portinfo in our lists with the new one before
		 * going further.
		 */
		if (ti->ti_pi->p_base_lid != pi->p_base_lid) {
			if (eibnx_replace_portinfo(ti, pi, size_pi) ==
			    ENX_E_SUCCESS) {
				pi = NULL;
				size_pi = 0;
			}
		}
	}

	/*
	 * If the port monitor was stuck waiting for the link to come up,
	 * let it know that it is up now.
	 */
	mutex_enter(&ti->ti_event_lock);
	if ((ti->ti_progress & ENX_MON_LINKSTATE_UP) != ENX_MON_LINKSTATE_UP) {
		ti->ti_pi->p_linkstate = IBT_PORT_ACTIVE;
		ti->ti_event |= ENX_EVENT_LINK_UP;
		cv_broadcast(&ti->ti_event_cv);
	}
	mutex_exit(&ti->ti_event_lock);

	if (ENX_PORT_PRES_NOT_PRESERVED(itr)) {
		if (ti->ti_progress & ENX_MON_JOINED_MCGS)
			(void) eibnx_rejoin_mcgs(ti);
	}

	if (pi != NULL)
		ibt_free_portinfo(pi, size_pi);
}

static void
eibnx_handle_hca_attach(ib_guid_t new_hca_guid)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	eibnx_hca_t *hca;
	eibnx_port_t *port;

	/*
	 * All we need to do is to start a port monitor for all the ports
	 * on the new HCA.  To do this, go through our current port monitors
	 * and see if we already have a monitor for this HCA - if so, print
	 * a warning and return.
	 */
	mutex_enter(&ss->nx_lock);
	for (ti = ss->nx_thr_info; ti; ti = ti->ti_next) {
		if (ti->ti_hca_guid == new_hca_guid) {
			ENX_DPRINTF_VERBOSE("hca (guid=0x%llx) already "
			    "attached", new_hca_guid);
			mutex_exit(&ss->nx_lock);
			return;
		}
	}
	mutex_exit(&ss->nx_lock);

	/*
	 * If we don't have it in our list, process the HCA and start the
	 * port monitors
	 */
	if ((hca = eibnx_prepare_hca(new_hca_guid)) != NULL) {
		mutex_enter(&ss->nx_lock);

		hca->hc_next = ss->nx_hca;
		ss->nx_hca = hca;

		for (port = hca->hc_port; port; port = port->po_next) {
			ti = eibnx_start_port_monitor(hca, port);

			ti->ti_next = ss->nx_thr_info;
			ss->nx_thr_info = ti;
		}
		mutex_exit(&ss->nx_lock);
	}
}

static void
eibnx_handle_hca_detach(ib_guid_t del_hca_guid)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	eibnx_thr_info_t *ti_stop_list = NULL;
	eibnx_thr_info_t *ti_prev;
	eibnx_thr_info_t *ti_next;
	eibnx_hca_t *hca;
	eibnx_hca_t *hca_prev;

	/*
	 * We need to locate all monitor threads for this HCA and stop them
	 */
	mutex_enter(&ss->nx_lock);
	ti_prev = NULL;
	for (ti = ss->nx_thr_info; ti; ti = ti_next) {
		ti_next = ti->ti_next;

		if (ti->ti_hca_guid != del_hca_guid) {
			ti_prev = ti;
		} else {
			/*
			 * Take it out from the good list
			 */
			if (ti_prev)
				ti_prev->ti_next = ti_next;
			else
				ss->nx_thr_info = ti_next;

			/*
			 * And put it in the to-stop list
			 */
			ti->ti_next = ti_stop_list;
			ti_stop_list = ti;
		}
	}
	mutex_exit(&ss->nx_lock);

	/*
	 * Ask all the port_monitor threads to die.
	 */
	for (ti = ti_stop_list; ti; ti = ti_next) {
		ti_next = ti->ti_next;
		eibnx_stop_port_monitor(ti);
	}

	/*
	 * Now, locate the HCA in our list and release all HCA related
	 * resources.
	 */
	mutex_enter(&ss->nx_lock);
	hca_prev = NULL;
	for (hca = ss->nx_hca; hca; hca = hca->hc_next) {
		if (hca->hc_guid != del_hca_guid) {
			hca_prev = hca;
		} else {
			if (hca_prev) {
				hca_prev->hc_next = hca->hc_next;
			} else {
				ss->nx_hca = hca->hc_next;
			}
			hca->hc_next = NULL;
			break;
		}
	}
	mutex_exit(&ss->nx_lock);

	if (hca) {
		(void) eibnx_cleanup_hca(hca);
	}
}
