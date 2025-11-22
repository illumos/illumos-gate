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
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/ib/clients/eoib/enx_impl.h>

static char *eibnx_make_nodename(eibnx_thr_info_t *, uint16_t);

/*
 * This routine is only called when the port-monitor thread is
 * about to die.  Between the time the first mcast solicitation
 * was done by the port-monitor thread and the time it is asked
 * to die, a lot of things could've happened and we need to
 * cleanup all of it.
 */
void
eibnx_cleanup_port_nodes(eibnx_thr_info_t *info)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_nodeq_t *node;
	eibnx_nodeq_t *prev;
	eibnx_gw_info_t *gwi;
	eibnx_gw_info_t *gw_list;
	eibnx_gw_info_t *nxt_gwi;
	eibnx_child_t *child;
	eibnx_child_t *nxt_child;
	eibnx_child_t *children;

	/*
	 * Since we would've already stopped processing completions for
	 * this thread's work queue, we don't have to worry about requests
	 * coming in for creation of new eoib nodes.  However, there may
	 * be pending node creation requests for this port (thr_info)
	 * that we will have to drop.
	 */
	mutex_enter(&ss->nx_nodeq_lock);
	prev = NULL;
	node = ss->nx_nodeq;
	while (node != NULL) {
		eibnx_nodeq_t *next = node->nc_next;

		if (node->nc_info != info) {
			prev = node;
		} else {
			if (prev == NULL) {
				ss->nx_nodeq = node->nc_next;
			} else {
				prev->nc_next = node->nc_next;
			}
			kmem_free(node, sizeof (eibnx_nodeq_t));
		}
		node = next;
	}
	mutex_exit(&ss->nx_nodeq_lock);

	/*
	 * Now go through the list of all children and free up any
	 * resource we might've allocated;  note that the child dips
	 * could've been offlined/removed by now, so we don't do
	 * anything with them.
	 */
	mutex_enter(&info->ti_child_lock);
	children = info->ti_child;
	info->ti_child = NULL;
	mutex_exit(&info->ti_child_lock);

	for (child = children; child; child = nxt_child) {
		nxt_child = child->ch_next;

		if (child->ch_node_name) {
			kmem_free(child->ch_node_name, MAXNAMELEN);
		}
		kmem_free(child, sizeof (eibnx_child_t));
	}

	/*
	 * Return all the swqes we've acquired for the gateway unicast
	 * solicitations, free any address vectors we've allocated and
	 * finally free the gw entries from the list.
	 */
	mutex_enter(&info->ti_gw_lock);
	gw_list = info->ti_gw;
	info->ti_gw = NULL;
	mutex_exit(&info->ti_gw_lock);

	for (gwi = gw_list; gwi; gwi = nxt_gwi) {
		nxt_gwi = gwi->gw_next;

		eibnx_release_swqe((eibnx_wqe_t *)(gwi->gw_swqe));
		if ((gwi->gw_addr).ga_vect) {
			kmem_free((gwi->gw_addr).ga_vect,
			    sizeof (ibt_adds_vect_t));
			(gwi->gw_addr).ga_vect = NULL;
		}
		mutex_destroy(&gwi->gw_adv_lock);

		kmem_free(gwi, sizeof (eibnx_gw_info_t));
	}
}

/*
 * Communicate all the details we received about the gateway (via the
 * advertisement control message) to the eoib instance we're creating.
 */
void
eibnx_create_node_props(dev_info_t *dip, eibnx_thr_info_t *info,
    eibnx_gw_info_t *gwi)
{
	int ret;

	ret = ndi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_HCA_GUID,
	    info->ti_hca_guid);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int64() failed to set "
		    "%s property to 0x%llx for child dip 0x%llx, ret=%d",
		    EIB_PROP_HCA_GUID, info->ti_hca_guid, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_HCA_PORTNUM,
	    info->ti_pi->p_port_num);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_HCA_PORTNUM, info->ti_pi->p_port_num, dip, ret);
	}

	ret = ndi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SYS_GUID,
	    gwi->gw_system_guid);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int64() failed to set "
		    "%s property to 0x%llx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_SYS_GUID, gwi->gw_system_guid, dip, ret);
	}

	ret = ndi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_GW_GUID,
	    gwi->gw_guid);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int64() failed to set "
		    "%s property to 0x%llx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_GUID, gwi->gw_guid, dip, ret);
	}

	ret = ndi_prop_update_int64(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SN_PREFIX,
	    (gwi->gw_addr).ga_gid.gid_prefix);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int64() failed to set "
		    "%s property to 0x%llx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_SN_PREFIX, (gwi->gw_addr).ga_gid.gid_prefix,
		    dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_ADV_PERIOD,
	    gwi->gw_adv_period);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_ADV_PERIOD, gwi->gw_adv_period, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_KA_PERIOD,
	    gwi->gw_ka_period);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_KA_PERIOD, gwi->gw_ka_period, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_VNIC_KA_PERIOD,
	    gwi->gw_vnic_ka_period);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_VNIC_KA_PERIOD, gwi->gw_vnic_ka_period, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_CTRL_QPN,
	    gwi->gw_ctrl_qpn);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_CTRL_QPN, gwi->gw_ctrl_qpn, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_LID,
	    gwi->gw_lid);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_LID, gwi->gw_lid, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_PORTID,
	    gwi->gw_portid);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_PORTID, gwi->gw_portid, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    EIB_PROP_GW_NUM_NET_VNICS, gwi->gw_num_net_vnics);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_NUM_NET_VNICS, gwi->gw_num_net_vnics, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_AVAILABLE,
	    gwi->gw_flag_available);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_AVAILABLE, gwi->gw_flag_available, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_HOST_VNICS,
	    gwi->gw_is_host_adm_vnics);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_HOST_VNICS, gwi->gw_is_host_adm_vnics,
		    dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SL,
	    gwi->gw_sl);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_SL, gwi->gw_sl, dip, ret);
	}

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip, EIB_PROP_GW_N_RSS_QPN,
	    gwi->gw_n_rss_qpn);
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_int() failed to set "
		    "%s property to 0x%lx for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_N_RSS_QPN, gwi->gw_n_rss_qpn, dip, ret);
	}

	ret = ndi_prop_update_string(DDI_DEV_T_NONE, dip, EIB_PROP_GW_SYS_NAME,
	    (char *)(gwi->gw_system_name));
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_string() failed to set "
		    "%s property to '%s' for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_SYS_NAME, gwi->gw_system_name, dip, ret);
	}

	ret = ndi_prop_update_string(DDI_DEV_T_NONE, dip, EIB_PROP_GW_PORT_NAME,
	    (char *)(gwi->gw_port_name));
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_string() failed to set "
		    "%s property to '%s' for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_PORT_NAME, gwi->gw_port_name, dip, ret);
	}

	ret = ndi_prop_update_string(DDI_DEV_T_NONE, dip, EIB_PROP_GW_VENDOR_ID,
	    (char *)(gwi->gw_vendor_id));
	if (ret != DDI_PROP_SUCCESS) {
		ENX_DPRINTF_WARN("ndi_prop_update_string() failed to set "
		    "%s property to '%s' for child dip 0x%llx, ret=%d",
		    EIB_PROP_GW_VENDOR_ID, gwi->gw_vendor_id, dip, ret);
	}
}

int
eibnx_name_child(dev_info_t *child, char *name, size_t namesz)
{
	char *node_name;

	if ((node_name = ddi_get_parent_data(child)) == NULL) {
		ENX_DPRINTF_ERR("ddi_get_parent_data(child=0x%llx) "
		    "returned NULL", child);
		return (DDI_NOT_WELL_FORMED);
	}

	/*
	 * Skip the name and "@" part in the eoib node path and copy the
	 * address part out to the caller.
	 */
	(void) strlcpy(name, node_name + strlen(EIB_DRV_NAME) + 1, namesz);

	return (DDI_SUCCESS);
}

/*
 * Synchronization functions to mark/clear the in-progress status of
 * bus config/unconfig operations
 */

void
eibnx_busop_inprog_enter(eibnx_t *ss)
{
	mutex_enter(&ss->nx_busop_lock);

	while (ss->nx_busop_flags & NX_FL_BUSOP_INPROG)
		cv_wait(&ss->nx_busop_cv, &ss->nx_busop_lock);

	ss->nx_busop_flags |= NX_FL_BUSOP_INPROG;

	mutex_exit(&ss->nx_busop_lock);
}

void
eibnx_busop_inprog_exit(eibnx_t *ss)
{
	mutex_enter(&ss->nx_busop_lock);

	ss->nx_busop_flags &= (~NX_FL_BUSOP_INPROG);

	cv_broadcast(&ss->nx_busop_cv);
	mutex_exit(&ss->nx_busop_lock);
}

eibnx_thr_info_t *
eibnx_start_port_monitor(eibnx_hca_t *hca, eibnx_port_t *port)
{
	eibnx_thr_info_t *ti;
	kthread_t *kt;
	dev_info_t *hca_dip;
	const char *hca_drv_name;
	int hca_drv_inst;

	ti = kmem_zalloc(sizeof (eibnx_thr_info_t), KM_SLEEP);

	mutex_init(&ti->ti_mcg_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ti->ti_gw_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ti->ti_child_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ti->ti_event_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ti->ti_event_cv, NULL, CV_DEFAULT, NULL);

	ti->ti_next = NULL;
	ti->ti_hca_guid = hca->hc_guid;
	ti->ti_hca = hca->hc_hdl;
	ti->ti_pd = hca->hc_pd;
	ti->ti_pi = port->po_pi;
	ti->ti_ident = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	/*
	 * Prepare the "ident" for EoIB nodes from this port monitor.  To
	 * associate eoib instances with the corresponding HCA nodes easily,
	 * and to make sure eoib instance numbers do not change when
	 * like-for-like HCA replacements are made, tie up the ident to
	 * HCA driver name, HCA driver instance and the HCA port number.
	 * The eoib node address is later composed using this ident and
	 * the gateway port ids after discovery.
	 */
	if ((hca_dip = ibtl_ibnex_hcaguid2dip(ti->ti_hca_guid)) == NULL) {
		ENX_DPRINTF_WARN("ibtl_ibnex_hcaguid2dip(hca_guid=0x%llx) "
		    "returned NULL", ti->ti_hca_guid);
	} else if ((hca_drv_name = ddi_driver_name(hca_dip)) == NULL) {
		ENX_DPRINTF_WARN("hca driver name NULL for "
		    "hca_guid=0x%llx, hca_dip=0x%llx",
		    ti->ti_hca_guid, hca_dip);
	} else if ((hca_drv_inst = ddi_get_instance(hca_dip)) < 0) {
		ENX_DPRINTF_ERR("hca driver instance (%d) invalid for "
		    "hca_guid=0x%llx, hca_dip=0x%llx",
		    ti->ti_hca_guid, hca_dip);
	} else {
		(void) snprintf(ti->ti_ident, MAXNAMELEN, "%s%d,%x",
		    hca_drv_name, hca_drv_inst, ti->ti_pi->p_port_num);
	}

	kt = thread_create(NULL, 0, eibnx_port_monitor,
	    ti, 0, &p0, TS_RUN, minclsyspri);

	ti->ti_kt_did = kt->t_did;

	return (ti);
}

void
eibnx_stop_port_monitor(eibnx_thr_info_t *ti)
{
	/*
	 * Tell the port monitor thread to stop and wait for it to
	 * happen.  Before marking it for death, make sure there
	 * aren't any completions being processed.
	 */
	mutex_enter(&ti->ti_event_lock);
	while (ti->ti_event & ENX_EVENT_COMPLETION) {
		cv_wait(&ti->ti_event_cv, &ti->ti_event_lock);
	}
	ti->ti_event |= ENX_EVENT_DIE;
	cv_broadcast(&ti->ti_event_cv);
	mutex_exit(&ti->ti_event_lock);

	thread_join(ti->ti_kt_did);

	/*
	 * Destroy synchronization primitives initialized for this ti
	 */
	cv_destroy(&ti->ti_event_cv);
	mutex_destroy(&ti->ti_event_lock);
	mutex_destroy(&ti->ti_child_lock);
	mutex_destroy(&ti->ti_gw_lock);
	mutex_destroy(&ti->ti_mcg_lock);

	kmem_free(ti->ti_ident, MAXNAMELEN);
	kmem_free(ti, sizeof (eibnx_thr_info_t));
}

void
eibnx_terminate_monitors(void)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti_list;
	eibnx_thr_info_t *ti;
	eibnx_thr_info_t *ti_next;

	mutex_enter(&ss->nx_lock);
	ti_list = ss->nx_thr_info;
	ss->nx_thr_info = NULL;
	mutex_exit(&ss->nx_lock);

	/*
	 * Ask all the port_monitor threads to die. Before marking them
	 * for death, make sure there aren't any completions being
	 * processed by the thread.
	 */
	for (ti = ti_list; ti; ti = ti_next) {
		ti_next = ti->ti_next;
		eibnx_stop_port_monitor(ti);
	}

	mutex_enter(&ss->nx_lock);
	ss->nx_monitors_up = B_FALSE;
	mutex_exit(&ss->nx_lock);
}

int
eibnx_configure_node(eibnx_thr_info_t *ti, eibnx_gw_info_t *gwi,
    dev_info_t **childp)
{
	eibnx_t *ss = enx_global_ss;
	dev_info_t *child_dip;
	char *node_name;
	int ret;

	/*
	 * Prepare the new node's name
	 */
	if ((node_name = eibnx_make_nodename(ti, gwi->gw_portid)) == NULL)
		return (ENX_E_FAILURE);

	ndi_devi_enter(ss->nx_dip);

	if (child_dip = ndi_devi_findchild(ss->nx_dip, node_name)) {
		ret = eibnx_update_child(ti, gwi, child_dip);
		if (ret == ENX_E_SUCCESS) {
			ndi_devi_exit(ss->nx_dip);
			kmem_free(node_name, MAXNAMELEN);

			if (childp) {
				*childp = child_dip;
			}
			return (ENX_E_SUCCESS);
		}
	}

	/*
	 * If the node does not already exist, we may need to create it
	 */
	if (child_dip == NULL) {
		ndi_devi_alloc_sleep(ss->nx_dip, EIB_DRV_NAME,
		    (pnode_t)DEVI_SID_NODEID, &child_dip);

		ddi_set_parent_data(child_dip, node_name);
		eibnx_create_node_props(child_dip, ti, gwi);
	}

	/*
	 * Whether there was no devinfo node at all for the given node name or
	 * we had a devinfo node, but it wasn't in our list of eoib children,
	 * we'll try to online the instance here.
	 */
	ENX_DPRINTF_DEBUG("onlining %s", node_name);
	ret = ndi_devi_online(child_dip, 0);
	if (ret != NDI_SUCCESS) {
		ENX_DPRINTF_ERR("ndi_devi_online(node_name=%s) failed "
		    "with ret=0x%x", node_name, ret);

		ddi_set_parent_data(child_dip, NULL);
		(void) ndi_devi_free(child_dip);

		ndi_devi_exit(ss->nx_dip);
		kmem_free(node_name, MAXNAMELEN);

		return (ENX_E_FAILURE);
	}

	eibnx_enqueue_child(ti, gwi, node_name, child_dip);

	ndi_devi_exit(ss->nx_dip);

	if (childp) {
		*childp = child_dip;
	}

	return (ENX_E_SUCCESS);
}

int
eibnx_unconfigure_node(eibnx_thr_info_t *ti, eibnx_gw_info_t *gwi)
{
	/*
	 * To unconfigure an eoib node, we only need to set the child's
	 * dip to NULL.  When the node gets configured again, we either
	 * find the dip for the pathname and set it in this child, or
	 * allocate a new dip and set it in this child.
	 */
	return (eibnx_update_child(ti, gwi, NULL));
}

int
eibnx_locate_node_name(char *devname, eibnx_thr_info_t **ti_p,
    eibnx_gw_info_t **gwi_p)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	eibnx_gw_info_t *gwi;
	char name[MAXNAMELEN];

	/*
	 * Locate the port monitor thread info and gateway info
	 * that corresponds to the supplied devname.
	 */
	mutex_enter(&ss->nx_lock);
	for (ti = ss->nx_thr_info; ti; ti = ti->ti_next) {
		if (ti->ti_ident[0] == '\0')
			continue;

		mutex_enter(&ti->ti_gw_lock);
		for (gwi = ti->ti_gw; gwi; gwi = gwi->gw_next) {
			(void) snprintf(name, MAXNAMELEN,
			    "%s@%s,%x", EIB_DRV_NAME, ti->ti_ident,
			    gwi->gw_portid);

			if (strcmp(name, devname) == 0)
				break;
		}
		mutex_exit(&ti->ti_gw_lock);

		if (gwi) {
			break;
		}
	}
	mutex_exit(&ss->nx_lock);

	if (ti == NULL || gwi == NULL) {
		return (ENX_E_FAILURE);
	}

	*ti_p = ti;
	*gwi_p = gwi;

	return (ENX_E_SUCCESS);
}

int
eibnx_locate_unconfigured_node(eibnx_thr_info_t **ti_p, eibnx_gw_info_t **gwi_p)
{
	eibnx_t *ss = enx_global_ss;
	eibnx_thr_info_t *ti;
	eibnx_child_t *ch;

	mutex_enter(&ss->nx_lock);
	for (ti = ss->nx_thr_info; ti; ti = ti->ti_next) {
		mutex_enter(&ti->ti_child_lock);
		for (ch = ti->ti_child; ch; ch = ch->ch_next) {
			if (ch->ch_dip == NULL) {
				*ti_p = ti;
				*gwi_p = ch->ch_gwi;

				mutex_exit(&ti->ti_child_lock);
				mutex_exit(&ss->nx_lock);

				return (ENX_E_SUCCESS);
			}
		}
		mutex_exit(&ti->ti_child_lock);
	}
	mutex_exit(&ss->nx_lock);

	return (ENX_E_FAILURE);
}

static char *
eibnx_make_nodename(eibnx_thr_info_t *info, uint16_t gw_portid)
{
	char *name;

	if (info->ti_ident[0] == '\0')
		return (NULL);

	name = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(name, MAXNAMELEN, "%s@%s,%x", EIB_DRV_NAME,
	    info->ti_ident, gw_portid);

	return (name);
}
