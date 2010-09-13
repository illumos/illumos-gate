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
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#include <sys/ib/clients/eoib/eib_impl.h>

/*
 * Declarations private to this file
 */
static void eib_rb_mac_start(eib_t *, eib_vnic_t *);

/*
 * This set of routines are used to set/clear the condition that the
 * caller is about to do something that affects the state of the nic.
 * If there's already someone doing either a start or a stop (possibly
 * due to the async handler, a plumb or a dlpi_open happening, or an
 * unplumb or dlpi_close coming in), we wait until that's done.
 */
void
eib_mac_set_nic_state(eib_t *ss, uint_t flags)
{
	eib_node_state_t *ns = ss->ei_node_state;

	mutex_enter(&ns->ns_lock);

	while ((ns->ns_nic_state & EIB_NIC_STARTING) ||
	    (ns->ns_nic_state & EIB_NIC_STOPPING)) {
		cv_wait(&ns->ns_cv, &ns->ns_lock);
	}
	ns->ns_nic_state |= flags;

	mutex_exit(&ns->ns_lock);
}

void
eib_mac_clr_nic_state(eib_t *ss, uint_t flags)
{
	eib_node_state_t *ns = ss->ei_node_state;

	mutex_enter(&ns->ns_lock);

	ns->ns_nic_state &= (~flags);

	cv_broadcast(&ns->ns_cv);
	mutex_exit(&ns->ns_lock);
}

void
eib_mac_upd_nic_state(eib_t *ss, uint_t clr_flags, uint_t set_flags)
{
	eib_node_state_t *ns = ss->ei_node_state;

	mutex_enter(&ns->ns_lock);

	ns->ns_nic_state &= (~clr_flags);
	ns->ns_nic_state |= set_flags;

	cv_broadcast(&ns->ns_cv);
	mutex_exit(&ns->ns_lock);
}

uint_t
eib_mac_get_nic_state(eib_t *ss)
{
	eib_node_state_t *ns = ss->ei_node_state;
	uint_t nic_state;

	mutex_enter(&ns->ns_lock);
	nic_state = ns->ns_nic_state;
	mutex_exit(&ns->ns_lock);

	return (nic_state);
}

void
eib_mac_link_state(eib_t *ss, link_state_t new_link_state,
    boolean_t force)
{
	eib_node_state_t *ns = ss->ei_node_state;
	boolean_t state_changed = B_FALSE;

	mutex_enter(&ns->ns_lock);

	/*
	 * We track the link state only if the current link state is
	 * not unknown.  Obviously therefore, the first calls to set
	 * the link state from eib_mac_start() have to pass an explicit
	 * 'force' flag to force the state change tracking.
	 */
	if (ns->ns_link_state != LINK_STATE_UNKNOWN)
		force = B_TRUE;

	if ((force) && (new_link_state != ns->ns_link_state)) {
		ns->ns_link_state = new_link_state;
		state_changed = B_TRUE;
	}
	mutex_exit(&ns->ns_lock);

	if (state_changed) {
		EIB_DPRINTF_DEBUG(ss->ei_instance,
		    "eib_mac_link_state: changing link state to %d",
		    new_link_state);

		mac_link_update(ss->ei_mac_hdl, new_link_state);
	} else  {
		EIB_DPRINTF_DEBUG(ss->ei_instance,
		    "eib_mac_link_state: link state already %d",
		    new_link_state);
	}
}

void
eib_mac_link_up(eib_t *ss, boolean_t force)
{
	eib_mac_link_state(ss, LINK_STATE_UP, force);
}

void
eib_mac_link_down(eib_t *ss, boolean_t force)
{
	eib_mac_link_state(ss, LINK_STATE_DOWN, force);
}

int
eib_mac_start(eib_t *ss)
{
	eib_vnic_t *vnic0 = NULL;
	eib_login_data_t *ld;
	int err;

	/*
	 * Perform HCA related initializations
	 */
	if (eib_ibt_hca_init(ss) != EIB_E_SUCCESS)
		goto start_fail;

	/*
	 * Make sure port is up. Also record the port base lid if it's up.
	 */
	if (eib_mac_hca_portstate(ss, &ss->ei_props->ep_blid,
	    &err) != EIB_E_SUCCESS) {
		goto start_fail;
	}

	/*
	 * Set up tx and rx buffer pools
	 */
	if (eib_rsrc_setup_bufs(ss, &err) != EIB_E_SUCCESS)
		goto start_fail;

	/*
	 * Set up admin qp for logins and logouts
	 */
	if (eib_adm_setup_qp(ss, &err) != EIB_E_SUCCESS)
		goto start_fail;

	/*
	 * Create the vnic for physlink (instance 0)
	 */
	if (eib_vnic_create(ss, 0, 0, &vnic0, &err) != EIB_E_SUCCESS)
		goto start_fail;

	/*
	 * Update the mac layer about the correct values for MTU and
	 * unicast MAC address.  Note that we've already verified that the
	 * vhub mtu (plus the eoib encapsulation header) is not greater
	 * than our port mtu, so we can go ahead and report the vhub mtu
	 * (of vnic0) directly.
	 */
	ld = &(vnic0->vn_login_data);
	(void) mac_maxsdu_update(ss->ei_mac_hdl, ld->ld_vhub_mtu);
	mac_unicst_update(ss->ei_mac_hdl, ld->ld_assigned_mac);

	/*
	 * Report that the link is up and ready
	 */
	eib_mac_link_up(ss, B_TRUE);
	return (0);

start_fail:
	eib_rb_mac_start(ss, vnic0);
	eib_mac_link_down(ss, B_TRUE);
	return (err);
}

void
eib_mac_stop(eib_t *ss)
{
	eib_vnic_t *vnic;
	link_state_t cur_link_state = ss->ei_node_state->ns_link_state;
	int ndx;

	/*
	 * Stopping an EoIB device instance is somewhat different from starting
	 * it. Between the time the device instance was started and the call to
	 * eib_m_stop() now, a number of vnics could've been created. All of
	 * these will need to be destroyed before we can stop the device.
	 */
	for (ndx = EIB_MAX_VNICS - 1; ndx >= 0; ndx--) {
		if ((vnic = ss->ei_vnic[ndx]) != NULL)
			eib_vnic_delete(ss, vnic);
	}

	/*
	 * And now, to undo the things we did in start (other than creation
	 * of vnics itself)
	 */
	eib_rb_mac_start(ss, NULL);

	/*
	 * Now that we're completed stopped, there's no mac address assigned
	 * to us.  Update the mac layer with this information. Note that we
	 * can let the old max mtu information remain as-is, since we're likely
	 * to get that same mtu on a later plumb.
	 */
	mac_unicst_update(ss->ei_mac_hdl, eib_zero_mac);

	/*
	 * If our link state was up when the eib_m_stop() callback was called,
	 * we'll mark the link state as unknown now.  Otherwise, we'll leave
	 * the link state as-is (down).
	 */
	if (cur_link_state == LINK_STATE_UP)
		eib_mac_link_state(ss, LINK_STATE_UNKNOWN, B_TRUE);
}

int
eib_mac_multicast(eib_t *ss, boolean_t add, uint8_t *mcast_mac)
{
	int ret = EIB_E_SUCCESS;
	int err = 0;

	/*
	 * If it's a broadcast group join, each vnic needs to and is always
	 * joined to the broadcast address, so we return success immediately.
	 * If it's a broadcast group leave, we fail immediately for the same
	 * reason as above.
	 */
	if (bcmp(mcast_mac, eib_broadcast_mac, ETHERADDRL) == 0) {
		if (add)
			return (0);
		else
			return (EINVAL);
	}

	if (ss->ei_vnic[0]) {
		if (add) {
			ret = eib_vnic_join_data_mcg(ss, ss->ei_vnic[0],
			    mcast_mac, B_FALSE, &err);
		} else {
			eib_vnic_leave_data_mcg(ss, ss->ei_vnic[0], mcast_mac);
			ret = EIB_E_SUCCESS;
		}
	}

	if (ret == EIB_E_SUCCESS)
		return (0);
	else
		return (err);
}

int
eib_mac_promisc(eib_t *ss, boolean_t set)
{
	int ret = EIB_E_SUCCESS;
	int err = 0;

	if (ss->ei_vnic[0]) {
		if (set) {
			ret = eib_vnic_join_data_mcg(ss, ss->ei_vnic[0],
			    eib_zero_mac, B_FALSE, &err);
		} else {
			eib_vnic_leave_data_mcg(ss, ss->ei_vnic[0],
			    eib_zero_mac);
			ret = EIB_E_SUCCESS;
		}
	}

	if (ret == EIB_E_SUCCESS)
		return (0);
	else
		return (err);
}

int
eib_mac_tx(eib_t *ss, mblk_t *mp)
{
	eib_ether_hdr_t evh;
	eib_vnic_t *vnic = NULL;
	eib_wqe_t *swqe = NULL;
	boolean_t failed_vnic;
	int found;
	int ret;

	/*
	 * Grab a send wqe.  If we cannot get one, wake up a service
	 * thread to monitor the swqe status and let the mac layer know
	 * as soon as we have enough tx wqes to start the traffic again.
	 */
	if ((swqe = eib_rsrc_grab_swqe(ss, EIB_WPRI_LO)) == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_mac_tx: "
		    "no swqe available, holding tx until resource "
		    "becomes available");
		eib_rsrc_txwqes_needed(ss);
		return (EIB_E_FAILURE);
	}

	/*
	 * Determine dmac, smac and vlan information
	 */
	eib_data_parse_ether_hdr(mp, &evh);

	/*
	 * Lookup the {smac, vlan} tuple in our vnic list. If it isn't
	 * there, this is obviously a new packet on a vnic/vlan that
	 * we haven't been informed about. So go ahead and file a request
	 * to create a new vnic. This is obviously not a clean thing to
	 * do - we should be informed when a vnic/vlan is being created
	 * and should be given a proper opportunity to login to the gateway
	 * and do the creation.  But we don't have that luxury now, and
	 * this is the next best thing to do.  Note that we return failure
	 * from here, so tx flow control should prevent further packets
	 * from coming in until the vnic creation has completed.
	 */
	found = eib_data_lookup_vnic(ss, evh.eh_smac, evh.eh_vlan, &vnic,
	    &failed_vnic);
	if (found != EIB_E_SUCCESS) {
		uint8_t *m = evh.eh_smac;

		/*
		 * Return the swqe back to the pool
		 */
		eib_rsrc_return_swqe(ss, swqe, NULL);

		/*
		 * If we had previously tried creating this vnic and had
		 * failed, we'll simply drop the packets on this vnic.
		 * Otherwise, we'll queue up a request to create this vnic.
		 */
		if (failed_vnic) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_mac_tx: "
			    "vnic creation for mac=%x:%x:%x:%x:%x:%x "
			    "vlan=0x%x failed previously, dropping pkt",
			    m[0], m[1], m[2], m[3], m[4], m[5], evh.eh_vlan);
			return (EIB_E_SUCCESS);
		} else {
			eib_vnic_need_new(ss, evh.eh_smac, evh.eh_vlan);
			return (EIB_E_FAILURE);
		}
	}

	/*
	 * We'll try to setup the destination in the swqe for this dmac
	 * and vlan.  If we don't succeed, there's no need to undo any
	 * vnic-creation we might've made above (if we didn't find the
	 * vnic corresponding to the {smac, vlan} originally). Note that
	 * this is not a resource issue, so we'll issue a warning and
	 * drop the packet, but won't return failure from here.
	 */
	ret = eib_vnic_setup_dest(vnic, swqe, evh.eh_dmac, evh.eh_vlan);
	if (ret != EIB_E_SUCCESS) {
		uint8_t *dmac;

		dmac = evh.eh_dmac;
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_mac_tx: "
		    "eib_vnic_setup_dest() failed for mac=%x:%x:%x:%x:%x:%x, "
		    "vlan=0x%x, dropping pkt", dmac[0], dmac[1], dmac[2],
		    dmac[3], dmac[4], dmac[5]);

		eib_rsrc_return_swqe(ss, swqe, NULL);
		return (EIB_E_SUCCESS);
	}

	/*
	 * The only reason why this would fail is if we needed LSO buffer(s)
	 * to prepare this frame and couldn't find enough of those.
	 */
	ret = eib_data_prepare_frame(vnic, swqe, mp, &evh);
	if (ret != EIB_E_SUCCESS) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_mac_tx: "
		    "eib_data_prepare_frame() failed (no LSO bufs?), "
		    "holding tx until resource becomes available");

		eib_rsrc_return_swqe(ss, swqe, NULL);
		eib_rsrc_lsobufs_needed(ss);
		return (EIB_E_FAILURE);
	}

	eib_data_post_tx(vnic, swqe);

	return (EIB_E_SUCCESS);
}

int
eib_mac_hca_portstate(eib_t *ss, ib_lid_t *blid, int *err)
{
	ibt_hca_portinfo_t *pi;
	ibt_status_t ret;
	uint_t num_pi;
	uint_t sz_pi;

	ret = ibt_query_hca_ports(ss->ei_hca_hdl, ss->ei_props->ep_port_num,
	    &pi, &num_pi, &sz_pi);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_query_hca_ports(hca_hdl=0x%llx, "
		    "port=0x%x) failed, ret=%d", ss->ei_hca_hdl,
		    ss->ei_props->ep_port_num, ret);
		goto mac_hca_portstate_fail;
	}
	if (num_pi != 1) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_query_hca_ports(hca_hdl=0x%llx, "
		    "port=0x%x) returned num_pi=%d", ss->ei_hca_hdl,
		    ss->ei_props->ep_port_num, num_pi);
		goto mac_hca_portstate_fail;
	}

	if (pi->p_linkstate != IBT_PORT_ACTIVE)
		goto mac_hca_portstate_fail;

	/*
	 * Return the port's base lid if asked
	 */
	if (blid) {
		*blid = pi->p_base_lid;
	}

	ibt_free_portinfo(pi, sz_pi);
	return (EIB_E_SUCCESS);

mac_hca_portstate_fail:
	if (pi) {
		ibt_free_portinfo(pi, sz_pi);
	}
	if (err) {
		*err = ENETDOWN;
	}
	return (EIB_E_FAILURE);
}

static void
eib_rb_mac_start(eib_t *ss, eib_vnic_t *vnic0)
{
	int ntries;

	/*
	 * If vnic0 is non-null, delete it
	 */
	if (vnic0) {
		eib_rb_vnic_create(ss, vnic0, ~0);
	}

	/*
	 * At this point, we're pretty much done with all communication that
	 * we need to do for vnic-logout, etc. so we can get rid of any address
	 * vectors we might've allocated to send control/data packets.
	 */
	eib_ibt_free_avects(ss);

	/*
	 * Tear down the rest of it
	 */
	if (ss->ei_admin_chan) {
		eib_rb_adm_setup_qp(ss);
	}

	/*
	 * If (say) the network layer has been holding onto our rx buffers, we
	 * wait a reasonable time for it to hand them back to us.  If we don't
	 * get it still, we have nothing to do but avoid rolling back hca init
	 * since we cannot unregister the memory, release the pd or close the
	 * hca.  We'll try to reuse it if there's a plumb again.
	 */
	for (ntries = 0; ntries < EIB_MAX_ATTEMPTS; ntries++) {
		eib_rb_rsrc_setup_bufs(ss, B_FALSE);
		if ((ss->ei_tx == NULL) && (ss->ei_rx == NULL) &&
		    (ss->ei_lso == NULL)) {
			break;
		}

		delay(drv_usectohz(EIB_DELAY_HALF_SECOND));
	}

	if (ntries == EIB_MAX_ATTEMPTS) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_rb_mac_start: "
		    "bufs outstanding, tx=0x%llx, rx=0x%llx, lso=0x%llx",
		    ss->ei_tx, ss->ei_rx, ss->ei_lso);
	} else if (ss->ei_hca_hdl) {
		eib_rb_ibt_hca_init(ss, ~0);
	}
	ss->ei_props->ep_blid = 0;

	/*
	 * Pending vnic creation requests (and failed-vnic records) will have
	 * to be cleaned up in any case
	 */
	eib_flush_vnic_reqs(ss);
}
