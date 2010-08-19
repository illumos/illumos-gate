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
#include <sys/dlpi.h>			/* HCKSUM_INET_FULL_V4 */
#include <sys/pattr.h>			/* HCK_FULLCKSUM */
#include <sys/ib/mgt/sm_attr.h>		/* SM_INIT_TYPE_REPLY_... */

#include <sys/ib/clients/eoib/eib_impl.h>

/*
 * Declarations private to this file
 */
static void eib_ibt_reset_partitions(eib_t *);
static void eib_ibt_wakeup_sqd_waiters(eib_t *, ibt_channel_hdl_t);
static int eib_ibt_chan_pkey(eib_t *, eib_chan_t *, ib_pkey_t, boolean_t,
    boolean_t *);
static boolean_t eib_ibt_has_chan_pkey_changed(eib_t *, eib_chan_t *);
static boolean_t eib_ibt_has_any_pkey_changed(eib_t *);
static int eib_ibt_fill_avect(eib_t *, eib_avect_t *, ib_lid_t);
static void eib_ibt_record_srate(eib_t *);

/*
 * Definitions private to this file
 */

/*
 * SM's init type reply flags
 */
#define	EIB_PORT_ATTR_LOADED(itr)				\
	(((itr) & SM_INIT_TYPE_REPLY_NO_LOAD_REPLY) == 0)
#define	EIB_PORT_ATTR_NOT_PRESERVED(itr)			\
	(((itr) & SM_INIT_TYPE_PRESERVE_CONTENT_REPLY) == 0)
#define	EIB_PORT_PRES_NOT_PRESERVED(itr)			\
	(((itr) & SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY) == 0)

/*
 * eib_ibt_hca_init() initialization progress flags
 */
#define	EIB_HCAINIT_HCA_OPENED		0x01
#define	EIB_HCAINIT_ATTRS_ALLOCD	0x02
#define	EIB_HCAINIT_HCA_PORTS_QUERIED	0x04
#define	EIB_HCAINIT_PD_ALLOCD		0x08
#define	EIB_HCAINIT_CAPAB_RECORDED	0x10

int
eib_ibt_hca_init(eib_t *ss)
{
	ibt_status_t ret;
	ibt_hca_portinfo_t *pi;
	uint_t num_pi;
	uint_t sz_pi;
	uint_t progress = 0;

	if (ss->ei_hca_hdl)
		return (EIB_E_SUCCESS);

	/*
	 * Open the HCA
	 */
	ret = ibt_open_hca(ss->ei_ibt_hdl, ss->ei_props->ep_hca_guid,
	    &ss->ei_hca_hdl);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_open_hca(hca_guid=0x%llx) "
		    "failed, ret=%d", ss->ei_props->ep_hca_guid, ret);
		goto ibt_hca_init_fail;
	}
	progress |= EIB_HCAINIT_HCA_OPENED;

	/*
	 * Query and store HCA attributes
	 */
	ss->ei_hca_attrs = kmem_zalloc(sizeof (ibt_hca_attr_t), KM_SLEEP);
	progress |= EIB_HCAINIT_ATTRS_ALLOCD;

	ret = ibt_query_hca(ss->ei_hca_hdl, ss->ei_hca_attrs);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_query_hca(hca_hdl=0x%llx, "
		    "hca_guid=0x%llx) failed, ret=%d",
		    ss->ei_hca_hdl, ss->ei_props->ep_hca_guid, ret);
		goto ibt_hca_init_fail;
	}

	/*
	 * At this point, we don't even care about the linkstate, we only want
	 * to record our invariant base port guid and mtu
	 */
	ret = ibt_query_hca_ports(ss->ei_hca_hdl, ss->ei_props->ep_port_num,
	    &pi, &num_pi, &sz_pi);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_query_hca_ports(hca_hdl=0x%llx, "
		    "port=0x%x) failed, ret=%d", ss->ei_hca_hdl,
		    ss->ei_props->ep_port_num, ret);
		goto ibt_hca_init_fail;
	}
	if (num_pi != 1) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_query_hca_ports(hca_hdl=0x%llx, "
		    "port=0x%x) returned num_pi=%d", ss->ei_hca_hdl,
		    ss->ei_props->ep_port_num, num_pi);
		ibt_free_portinfo(pi, sz_pi);
		goto ibt_hca_init_fail;
	}

	ss->ei_props->ep_sgid = pi->p_sgid_tbl[0];
	ss->ei_props->ep_mtu = (128 << pi->p_mtu);
	ibt_free_portinfo(pi, sz_pi);

	progress |= EIB_HCAINIT_HCA_PORTS_QUERIED;

	/*
	 * Allocate a protection domain for all our transactions
	 */
	ret = ibt_alloc_pd(ss->ei_hca_hdl, IBT_PD_NO_FLAGS, &ss->ei_pd_hdl);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "ibt_alloc_pd(hca_hdl=0x%llx, "
		    "hca_guid=0x%llx) failed, ret=%d",
		    ss->ei_hca_hdl, ss->ei_props->ep_hca_guid, ret);
		goto ibt_hca_init_fail;
	}
	progress |= EIB_HCAINIT_PD_ALLOCD;

	/*
	 * Finally, record the capabilities
	 */
	ss->ei_caps = kmem_zalloc(sizeof (eib_caps_t), KM_SLEEP);
	eib_ibt_record_capab(ss, ss->ei_hca_attrs, ss->ei_caps);
	eib_ibt_record_srate(ss);

	progress |= EIB_HCAINIT_CAPAB_RECORDED;

	return (EIB_E_SUCCESS);

ibt_hca_init_fail:
	eib_rb_ibt_hca_init(ss, progress);
	return (EIB_E_FAILURE);
}

void
eib_ibt_link_mod(eib_t *ss)
{
	eib_node_state_t *ns = ss->ei_node_state;
	ibt_hca_portinfo_t *pi;
	ibt_status_t ret;
	uint8_t vn0_mac[ETHERADDRL];
	boolean_t all_zombies = B_FALSE;
	boolean_t all_need_rejoin = B_FALSE;
	uint_t num_pi;
	uint_t sz_pi;
	uint8_t itr;

	if (ns->ns_link_state == LINK_STATE_UNKNOWN)
		return;

	/*
	 * See if we can get the port attributes or we're as good as down.
	 */
	ret = ibt_query_hca_ports(ss->ei_hca_hdl, ss->ei_props->ep_port_num,
	    &pi, &num_pi, &sz_pi);
	if ((ret != IBT_SUCCESS) || (pi->p_linkstate != IBT_PORT_ACTIVE)) {
		ibt_free_portinfo(pi, sz_pi);
		eib_mac_link_down(ss, B_FALSE);
		return;
	}

	/*
	 * If the SM re-initialized the port attributes, but did not preserve
	 * the old attributes, we need to check more.
	 */
	itr = pi->p_init_type_reply;
	if (EIB_PORT_ATTR_LOADED(itr) && EIB_PORT_ATTR_NOT_PRESERVED(itr)) {
		/*
		 * We're just coming back up; if we see that our base lid
		 * or sgid table has changed, we'll update these and try to
		 * restart all active vnics. If any of the vnic pkeys have
		 * changed, we'll reset the affected channels to the new pkey.
		 */
		if (bcmp(pi->p_sgid_tbl, &ss->ei_props->ep_sgid,
		    sizeof (ib_gid_t)) != 0) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_link_mod: port sgid table changed "
			    "(old %llx.%llx != new %llx.%llx), "
			    "all vnics are zombies now.",
			    ss->ei_props->ep_sgid.gid_prefix,
			    ss->ei_props->ep_sgid.gid_guid,
			    pi->p_sgid_tbl[0].gid_prefix,
			    pi->p_sgid_tbl[0].gid_guid);

			ss->ei_props->ep_sgid = pi->p_sgid_tbl[0];
			all_zombies = B_TRUE;

		} else if (ss->ei_props->ep_blid != pi->p_base_lid) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_link_mod: port base lid changed "
			    "(old 0x%x != new 0x%x), "
			    "all vnics are zombies now.",
			    ss->ei_props->ep_blid, pi->p_base_lid);

			ss->ei_props->ep_blid = pi->p_base_lid;
			all_zombies = B_TRUE;

		} else if (eib_ibt_has_any_pkey_changed(ss)) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_link_mod: pkey has changed for vnic(s), "
			    "resetting all partitions");

			eib_ibt_reset_partitions(ss);
		}
	}

	if (pi) {
		ibt_free_portinfo(pi, sz_pi);
	}

	/*
	 * If the SM hasn't preserved our presence in MCGs, we need to
	 * rejoin all of them.
	 */
	if (EIB_PORT_PRES_NOT_PRESERVED(itr)) {
		EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_ibt_link_mod: "
		    "hca_guid=0x%llx, port=0x%x presence not preserved in SM, "
		    "rejoining all mcgs", ss->ei_props->ep_hca_guid,
		    ss->ei_props->ep_port_num);

		all_need_rejoin = B_TRUE;
	}

	/*
	 * Before we do the actual work of restarting/rejoining, we need to
	 * see if the GW is reachable at this point of time.  If not, we
	 * still continue to keep our link "down."  Whenever the GW becomes
	 * reachable again, we'll restart/rejoin all the vnics that we've
	 * just marked.
	 */
	mutex_enter(&ss->ei_vnic_lock);
	if (all_zombies) {
		ss->ei_zombie_vnics = ss->ei_active_vnics;
	}
	if (all_need_rejoin) {
		ss->ei_rejoin_vnics = ss->ei_active_vnics;
	}
	if (ss->ei_gw_unreachable) {
		mutex_exit(&ss->ei_vnic_lock);

		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_link_mod: "
		    "gateway (gw_port=0x%x) unreachable for "
		    "hca_guid=0x%llx, port=0x%x, link state down",
		    ss->ei_gw_props->pp_gw_portid, ss->ei_props->ep_hca_guid,
		    ss->ei_props->ep_port_num);

		eib_mac_link_down(ss, B_FALSE);
		return;
	}
	mutex_exit(&ss->ei_vnic_lock);

	/*
	 * Try to awaken the dead if possible
	 */
	bcopy(eib_zero_mac, vn0_mac, ETHERADDRL);
	if (all_zombies) {
		EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_ibt_link_mod: "
		    "hca_guid=0x%llx, hca_port=0x%x, gw_port=0x%x, "
		    "attempting to resurrect zombies",
		    ss->ei_props->ep_hca_guid, ss->ei_props->ep_port_num,
		    ss->ei_gw_props->pp_gw_portid);

		eib_vnic_resurrect_zombies(ss, vn0_mac);
	}

	/*
	 * Re-join the mcgs if we need to
	 */
	if (all_need_rejoin) {
		EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_ibt_link_mod: "
		    "hca_guid=0x%llx, hca_port=0x%x, gw_port=0x%x, "
		    "attempting to rejoin mcgs",
		    ss->ei_props->ep_hca_guid, ss->ei_props->ep_port_num,
		    ss->ei_gw_props->pp_gw_portid);

		eib_vnic_rejoin_mcgs(ss);
	}

	/*
	 * If we've restarted the zombies because the gateway went down and
	 * came back, it is possible our unicast mac address changed from
	 * what it was earlier. If so, we need to update our unicast address
	 * with the mac layer before marking the link up.
	 */
	if (bcmp(vn0_mac, eib_zero_mac, ETHERADDRL) != 0)
		mac_unicst_update(ss->ei_mac_hdl, vn0_mac);

	/*
	 * Notify the link state up if required
	 */
	eib_mac_link_up(ss, B_FALSE);
}

int
eib_ibt_modify_chan_pkey(eib_t *ss, eib_chan_t *chan, ib_pkey_t pkey)
{
	/*
	 * Make sure the channel pkey and index are set to what we need
	 */
	return (eib_ibt_chan_pkey(ss, chan, pkey, B_TRUE, NULL));
}

eib_avect_t *
eib_ibt_hold_avect(eib_t *ss, ib_lid_t dlid, uint8_t sl)
{
	uint_t ndx = dlid % EIB_AV_NBUCKETS;	/* simple hashing */
	eib_avect_t *av;
	eib_avect_t *prev;
	int ret;

	mutex_enter(&ss->ei_av_lock);

	/*
	 * See if we have the address vector
	 */
	prev = NULL;
	for (av = ss->ei_av[ndx]; av; av = av->av_next) {
		prev = av;
		if ((av->av_vect).av_dlid == dlid)
			break;
	}

	/*
	 * If we don't have it, create a new one and chain it to
	 * the same bucket
	 */
	if (av == NULL) {
		av = kmem_zalloc(sizeof (eib_avect_t), KM_NOSLEEP);
		if (av == NULL) {
			mutex_exit(&ss->ei_av_lock);
			EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_hold_avect: "
			    "no memory, could not allocate address vector");
			return (NULL);
		}

		ret = EIB_E_FAILURE;
		if (!eib_wa_no_av_discover)
			ret = eib_ibt_fill_avect(ss, av, dlid);

		if (ret != EIB_E_SUCCESS) {
			(av->av_vect).av_srate = IBT_SRATE_10;
			(av->av_vect).av_srvl = sl;
			(av->av_vect).av_port_num = ss->ei_props->ep_port_num;
			(av->av_vect).av_send_grh = B_FALSE;
			(av->av_vect).av_dlid = dlid;
			(av->av_vect).av_src_path = 0;	/* we use base lid */
		}

		if (prev)
			prev->av_next = av;
		else
			ss->ei_av[ndx] = av;
	}

	/*
	 * Increment the address vector reference count before returning
	 */
	(av->av_ref)++;

	mutex_exit(&ss->ei_av_lock);

	return (av);
}

static int
eib_ibt_fill_avect(eib_t *ss, eib_avect_t *av, ib_lid_t dlid)
{
	ibt_node_info_t ni;
	ibt_path_attr_t attr;
	ibt_path_info_t path;
	ibt_status_t ret;
	ib_gid_t dgid;

	if ((ret = ibt_lid_to_node_info(dlid, &ni)) != IBT_SUCCESS) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_fill_avect: "
		    "ibt_lid_to_node_info(dlid=0x%x) failed, ret=%d",
		    dlid, ret);
		return (EIB_E_FAILURE);
	}
	dgid.gid_prefix = ss->ei_gw_props->pp_gw_sn_prefix;
	dgid.gid_guid = ni.n_port_guid;

	/*
	 * Get the reversible path information for this destination
	 */
	bzero(&attr, sizeof (ibt_path_info_t));
	attr.pa_sgid = ss->ei_props->ep_sgid;
	attr.pa_dgids = &dgid;
	attr.pa_num_dgids = 1;

	bzero(&path, sizeof (ibt_path_info_t));
	ret = ibt_get_paths(ss->ei_ibt_hdl, IBT_PATH_NO_FLAGS,
	    &attr, 1, &path, NULL);
	if ((ret != IBT_SUCCESS) || (path.pi_hca_guid == 0)) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_fill_avect: "
		    "ibt_get_paths(dgid=%llx.%llx) failed, ret=%d",
		    dgid.gid_prefix, dgid.gid_guid);
		return (EIB_E_FAILURE);
	}

	/*
	 * Fill in the address vector
	 */
	bcopy(&path.pi_prim_cep_path.cep_adds_vect, &av->av_vect,
	    sizeof (ibt_adds_vect_t));

	return (EIB_E_SUCCESS);
}

void
eib_ibt_release_avect(eib_t *ss, eib_avect_t *av)
{
	mutex_enter(&ss->ei_av_lock);

	ASSERT(av->av_ref > 0);
	(av->av_ref)--;

	mutex_exit(&ss->ei_av_lock);
}

void
eib_ibt_free_avects(eib_t *ss)
{
	eib_avect_t *av;
	eib_avect_t *av_next;
	int ndx;

	mutex_enter(&ss->ei_av_lock);
	for (ndx = 0; ndx < EIB_AV_NBUCKETS; ndx++) {
		for (av = ss->ei_av[ndx]; av; av = av_next) {
			av_next = av->av_next;

			ASSERT(av->av_ref == 0);
			kmem_free(av, sizeof (eib_avect_t));
		}
		ss->ei_av[ndx] = NULL;
	}
	mutex_exit(&ss->ei_av_lock);
}

/*ARGSUSED*/
void
eib_ibt_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	eib_t *ss = (eib_t *)clnt_private;
	eib_event_t *evi;
	uint_t ev_code;

	ev_code = EIB_EV_NONE;

	switch (code) {
	case IBT_EVENT_SQD:
		EIB_DPRINTF_VERBOSE(ss->ei_instance,
		    "eib_ibt_async_handler: got IBT_EVENT_SQD");
		eib_ibt_wakeup_sqd_waiters(ss, event->ev_chan_hdl);
		break;

	case IBT_EVENT_PORT_UP:
		if (event->ev_port == ss->ei_props->ep_port_num) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_async_handler: got IBT_EVENT_PORT_UP");
			ev_code = EIB_EV_PORT_UP;
		}
		break;

	case IBT_ERROR_PORT_DOWN:
		if (event->ev_port == ss->ei_props->ep_port_num) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_async_handler: got IBT_ERROR_PORT_DOWN");
			ev_code = EIB_EV_PORT_DOWN;
		}
		break;

	case IBT_CLNT_REREG_EVENT:
		if (event->ev_port == ss->ei_props->ep_port_num) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_async_handler: got IBT_CLNT_REREG_EVENT");
			ev_code = EIB_EV_CLNT_REREG;
		}
		break;

	case IBT_PORT_CHANGE_EVENT:
		if ((event->ev_port == ss->ei_props->ep_port_num) &&
		    (event->ev_port_flags & IBT_PORT_CHANGE_PKEY)) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_async_handler: "
			    "got IBT_PORT_CHANGE_EVENT(PKEY_CHANGE)");
			ev_code = EIB_EV_PKEY_CHANGE;
		} else if ((event->ev_port == ss->ei_props->ep_port_num) &&
		    (event->ev_port_flags & IBT_PORT_CHANGE_SGID)) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_ibt_async_handler: "
			    "got IBT_PORT_CHANGE_EVENT(SGID_CHANGE)");
			ev_code = EIB_EV_SGID_CHANGE;
		}
		break;

	case IBT_HCA_ATTACH_EVENT:
		/*
		 * For HCA attach, after a new HCA is plugged in and
		 * configured using cfgadm, an explicit plumb will need
		 * to be run, so we don't need to do anything here.
		 */
		EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_ibt_async_handler: "
		    "got IBT_HCA_ATTACH_EVENT");
		break;

	case IBT_HCA_DETACH_EVENT:
		/*
		 * Before an HCA unplug, cfgadm is expected to trigger
		 * any rcm scripts to unplumb the EoIB instances on the
		 * card. If so, we should not be holding any hca resource,
		 * since we don't do ibt_open_hca() until plumb time. However,
		 * if an earlier unplumb hadn't cleaned up the hca resources
		 * properly because the network layer hadn't returned the
		 * buffers at that time, we could be holding hca resources.
		 * We'll try to release them here, and protect the code from
		 * racing with some other plumb/unplumb operation.
		 */
		EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_ibt_async_handler: "
		    "got IBT_HCA_DETACH_EVENT");

		eib_mac_set_nic_state(ss, EIB_NIC_STOPPING);
		eib_rb_rsrc_setup_bufs(ss, B_FALSE);
		if (ss->ei_tx || ss->ei_rx || ss->ei_lso) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_events_handler: nw layer still holding "
			    "hca resources, could not detach HCA");
		} else if (ss->ei_hca_hdl) {
			eib_rb_ibt_hca_init(ss, ~0);
		}
		eib_mac_clr_nic_state(ss, EIB_NIC_STOPPING);

		break;
	}

	if (ev_code != EIB_EV_NONE) {
		evi = kmem_zalloc(sizeof (eib_event_t), KM_NOSLEEP);
		if (evi == NULL) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_ibt_async_handler: "
			    "no memory, could not handle event 0x%lx", ev_code);
		} else {
			evi->ev_code = ev_code;
			evi->ev_arg = NULL;
			eib_svc_enqueue_event(ss, evi);
		}
	}
}

/*ARGSUSED*/
void
eib_ibt_record_capab(eib_t *ss, ibt_hca_attr_t *hca_attrs, eib_caps_t *caps)
{
	uint_t max_swqe = EIB_DATA_MAX_SWQE;
	uint_t max_rwqe = EIB_DATA_MAX_RWQE;

	/*
	 * Checksum
	 */
	caps->cp_cksum_flags = 0;
	if ((!eib_wa_no_cksum_offload) &&
	    (hca_attrs->hca_flags & IBT_HCA_CKSUM_FULL)) {
		caps->cp_cksum_flags =
		    HCK_FULLCKSUM | HCKSUM_INET_FULL_V4;
		    /* HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM; */
	}

	/*
	 * Reserved L-Key
	 */
	if (hca_attrs->hca_flags2 & IBT_HCA2_RES_LKEY) {
		caps->cp_resv_lkey_capab = 1;
		caps->cp_resv_lkey = hca_attrs->hca_reserved_lkey;
	}

	/*
	 * LSO
	 */
	caps->cp_lso_maxlen = 0;
	if (!eib_wa_no_lso) {
		if (hca_attrs->hca_max_lso_size > EIB_LSO_MAXLEN) {
			caps->cp_lso_maxlen = EIB_LSO_MAXLEN;
		} else {
			caps->cp_lso_maxlen = hca_attrs->hca_max_lso_size;
		}
	}

	/*
	 * SGL
	 *
	 * Translating virtual address regions into physical regions
	 * for using the Reserved LKey feature results in a wr sgl that
	 * is a little longer. Since failing ibt_map_mem_iov() is costly,
	 * we'll record a high-water mark (65%) when we should stop
	 * trying to use Reserved LKey
	 */
	if (hca_attrs->hca_flags & IBT_HCA_WQE_SIZE_INFO) {
		caps->cp_max_sgl = hca_attrs->hca_ud_send_sgl_sz;
	} else {
		caps->cp_max_sgl = hca_attrs->hca_max_sgl;
	}
	if (caps->cp_max_sgl > EIB_MAX_SGL) {
		caps->cp_max_sgl = EIB_MAX_SGL;
	}
	caps->cp_hiwm_sgl = (caps->cp_max_sgl * 65) / 100;

	/*
	 * SWQE/RWQE: meet max chan size and max cq size limits (leave room
	 * to avoid cq overflow event)
	 */
	if (max_swqe > hca_attrs->hca_max_chan_sz)
		max_swqe = hca_attrs->hca_max_chan_sz;
	if (max_swqe > (hca_attrs->hca_max_cq_sz - 1))
		max_swqe = hca_attrs->hca_max_cq_sz - 1;
	caps->cp_max_swqe = max_swqe;

	if (max_rwqe > hca_attrs->hca_max_chan_sz)
		max_rwqe = hca_attrs->hca_max_chan_sz;
	if (max_rwqe > (hca_attrs->hca_max_cq_sz - 1))
		max_rwqe = hca_attrs->hca_max_cq_sz - 1;
	caps->cp_max_rwqe = max_rwqe;
}

void
eib_rb_ibt_hca_init(eib_t *ss, uint_t progress)
{
	ibt_status_t ret;

	if (progress & EIB_HCAINIT_CAPAB_RECORDED) {
		if (ss->ei_caps) {
			kmem_free(ss->ei_caps, sizeof (eib_caps_t));
			ss->ei_caps = NULL;
		}
	}

	if (progress & EIB_HCAINIT_PD_ALLOCD) {
		if (ss->ei_pd_hdl) {
			ret = ibt_free_pd(ss->ei_hca_hdl, ss->ei_pd_hdl);
			if (ret != IBT_SUCCESS) {
				EIB_DPRINTF_WARN(ss->ei_instance,
				    "eib_rb_ibt_hca_init: "
				    "ibt_free_pd(hca_hdl=0x%lx, pd_hdl=0x%lx) "
				    "failed, ret=%d", ss->ei_hca_hdl,
				    ss->ei_pd_hdl, ret);
			}
			ss->ei_pd_hdl = NULL;
		}
	}

	if (progress & EIB_HCAINIT_HCA_PORTS_QUERIED) {
		ss->ei_props->ep_mtu = 0;
		bzero(&ss->ei_props->ep_sgid, sizeof (ib_gid_t));
	}

	if (progress & EIB_HCAINIT_ATTRS_ALLOCD) {
		kmem_free(ss->ei_hca_attrs, sizeof (ibt_hca_attr_t));
		ss->ei_hca_attrs = NULL;
	}

	if (progress & EIB_HCAINIT_HCA_OPENED) {
		ret = ibt_close_hca(ss->ei_hca_hdl);
		if (ret != IBT_SUCCESS) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "ibt_close_hca(hca_hdl=0x%lx) failed, "
			    "ret=%d", ss->ei_hca_hdl, ret);
		}
		ss->ei_hca_hdl = NULL;
	}
}

static void
eib_ibt_reset_partitions(eib_t *ss)
{
	eib_vnic_t *vnic;
	eib_chan_t *chan = NULL;
	uint64_t av;
	int inst = 0;

	/*
	 * We already have the vhub pkey recorded in our eib_chan_t.
	 * We only need to make sure our pkey index still matches it.
	 * If not, modify the channel appropriately and update our
	 * records.
	 */
	if ((chan = ss->ei_admin_chan) != NULL)
		(void) eib_ibt_modify_chan_pkey(ss, chan, chan->ch_pkey);

	mutex_enter(&ss->ei_vnic_lock);
	av = ss->ei_active_vnics;
	while ((inst = EIB_FIND_LSB_SET(av)) != -1) {
		if ((vnic = ss->ei_vnic[inst]) != NULL) {
			if ((chan = vnic->vn_ctl_chan) != NULL) {
				(void) eib_ibt_modify_chan_pkey(ss, chan,
				    chan->ch_pkey);
			}
			if ((chan = vnic->vn_data_chan) != NULL) {
				(void) eib_ibt_modify_chan_pkey(ss, chan,
				    chan->ch_pkey);
			}
		}
		av &= (~((uint64_t)1 << inst));
	}
	mutex_exit(&ss->ei_vnic_lock);
}

static void
eib_ibt_wakeup_sqd_waiters(eib_t *ss, ibt_channel_hdl_t ev_chan_hdl)
{
	eib_vnic_t *vnic;
	eib_chan_t *chan = NULL;
	uint64_t av;
	int inst = 0;

	/*
	 * See if this channel has been waiting for its queue to drain.
	 *
	 * Note that since this is especially likely to be called during
	 * logging in to the gateway, we also need to check the vnic
	 * currently being created.
	 */
	mutex_enter(&ss->ei_vnic_lock);

	if ((vnic = ss->ei_vnic_pending) != NULL) {
		chan = vnic->vn_ctl_chan;
		if ((chan) && (chan->ch_chan == ev_chan_hdl))
			goto wakeup_sqd_waiters;

		chan = vnic->vn_data_chan;
		if ((chan) && (chan->ch_chan == ev_chan_hdl))
			goto wakeup_sqd_waiters;
	}

	av = ss->ei_active_vnics;
	while ((inst = EIB_FIND_LSB_SET(av)) != -1) {
		if ((vnic = ss->ei_vnic[inst]) != NULL) {
			chan = vnic->vn_ctl_chan;
			if (chan->ch_chan == ev_chan_hdl)
				break;

			chan = vnic->vn_data_chan;
			if (chan->ch_chan == ev_chan_hdl)
				break;
		}
		av &= (~((uint64_t)1 << inst));
	}

wakeup_sqd_waiters:
	if (chan) {
		mutex_enter(&chan->ch_cep_lock);
		chan->ch_cep_state = IBT_STATE_SQD;
		cv_broadcast(&chan->ch_cep_cv);
		mutex_exit(&chan->ch_cep_lock);
	}

	mutex_exit(&ss->ei_vnic_lock);
}

static int
eib_ibt_chan_pkey(eib_t *ss, eib_chan_t *chan, ib_pkey_t new_pkey,
    boolean_t set, boolean_t *pkey_changed)
{
	ibt_qp_info_t qp_attr;
	ibt_status_t ret;
	uint16_t new_pkey_ix;

	ret = ibt_pkey2index(ss->ei_hca_hdl, ss->ei_props->ep_port_num,
	    new_pkey, &new_pkey_ix);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_chan_pkey: "
		    "ibt_pkey2index(hca_hdl=0x%llx, port_num=0x%x, "
		    "pkey=0x%x) failed, ret=%d",
		    ss->ei_hca_hdl, ss->ei_props->ep_port_num, new_pkey, ret);
		return (EIB_E_FAILURE);
	}

	/*
	 * If the pkey and the pkey index we have already matches the
	 * new one, nothing to do.
	 */
	mutex_enter(&chan->ch_pkey_lock);
	if ((chan->ch_pkey == new_pkey) && (chan->ch_pkey_ix == new_pkey_ix)) {
		if (pkey_changed) {
			*pkey_changed = B_FALSE;
		}
		mutex_exit(&chan->ch_pkey_lock);
		return (EIB_E_SUCCESS);
	}
	if (pkey_changed) {
		*pkey_changed = B_TRUE;
	}
	mutex_exit(&chan->ch_pkey_lock);

	/*
	 * Otherwise, if we're asked only to test if the pkey index
	 * supplied matches the one recorded in the channel, return
	 * success, but don't set the pkey.
	 */
	if (!set) {
		return (EIB_E_SUCCESS);
	}

	/*
	 * Otherwise, we need to change channel pkey.  Pause the
	 * channel sendq first.
	 */
	ret = ibt_pause_sendq(chan->ch_chan, IBT_CEP_SET_SQD_EVENT);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_chan_pkey: "
		    "ibt_pause_sendq(chan_hdl=0x%llx) failed, ret=%d",
		    chan->ch_chan, ret);
		return (EIB_E_FAILURE);
	}

	/*
	 * Wait for the channel to enter the IBT_STATE_SQD state
	 */
	mutex_enter(&chan->ch_cep_lock);
	while (chan->ch_cep_state != IBT_STATE_SQD)
		cv_wait(&chan->ch_cep_cv, &chan->ch_cep_lock);
	mutex_exit(&chan->ch_cep_lock);

	/*
	 * Modify the qp with the supplied pkey index and unpause the channel
	 * If either of these operations fail, we'll leave the channel in
	 * the paused state and fail.
	 */
	bzero(&qp_attr, sizeof (ibt_qp_info_t));

	qp_attr.qp_trans = IBT_UD_SRV;
	qp_attr.qp_current_state = IBT_STATE_SQD;
	qp_attr.qp_state = IBT_STATE_SQD;
	qp_attr.qp_transport.ud.ud_pkey_ix = new_pkey_ix;

	/*
	 * Modify the qp to set the new pkey index, then unpause the
	 * channel and put it in RTS state and update the new values
	 * in our records
	 */
	mutex_enter(&chan->ch_pkey_lock);

	ret = ibt_modify_qp(chan->ch_chan,
	    IBT_CEP_SET_STATE | IBT_CEP_SET_PKEY_IX, &qp_attr, NULL);
	if (ret != IBT_SUCCESS) {
		mutex_exit(&chan->ch_pkey_lock);
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_chan_pkey: "
		    "ibt_modify_qp(chan_hdl=0x%llx, IBT_CEP_SET_PKEY_IX) "
		    "failed for new_pkey_ix=0x%x, ret=%d",
		    chan->ch_chan, new_pkey_ix, ret);
		return (EIB_E_FAILURE);
	}

	if ((ret = ibt_unpause_sendq(chan->ch_chan)) != IBT_SUCCESS) {
		mutex_exit(&chan->ch_pkey_lock);
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_ibt_chan_pkey: "
		    "ibt_unpause_sendq(chan_hdl=0x%llx) failed, ret=%d",
		    chan->ch_chan, ret);
		return (EIB_E_FAILURE);
	}

	chan->ch_pkey = new_pkey;
	chan->ch_pkey_ix = new_pkey_ix;
	mutex_exit(&chan->ch_pkey_lock);

	return (EIB_E_SUCCESS);
}

static boolean_t
eib_ibt_has_chan_pkey_changed(eib_t *ss, eib_chan_t *chan)
{
	boolean_t changed;
	int ret;

	/*
	 * Don't modify the pkey, just ask if the pkey index for the channel's
	 * pkey has changed for any reason.  If we fail, assume that the pkey
	 * has changed.
	 */
	ret = eib_ibt_chan_pkey(ss, chan, chan->ch_pkey, B_FALSE, &changed);
	if (ret != EIB_E_SUCCESS)
		changed = B_TRUE;

	return (changed);
}

static boolean_t
eib_ibt_has_any_pkey_changed(eib_t *ss)
{
	eib_vnic_t *vnic;
	eib_chan_t *chan = NULL;
	uint64_t av;
	int inst = 0;

	/*
	 * Return true if the pkey index of any our pkeys (of the channels
	 * of all active vnics) has changed.
	 */

	chan = ss->ei_admin_chan;
	if ((chan) && (eib_ibt_has_chan_pkey_changed(ss, chan)))
		return (B_TRUE);

	mutex_enter(&ss->ei_vnic_lock);
	av = ss->ei_active_vnics;
	while ((inst = EIB_FIND_LSB_SET(av)) != -1) {
		if ((vnic = ss->ei_vnic[inst]) != NULL) {
			chan = vnic->vn_ctl_chan;
			if ((chan) && (eib_ibt_has_chan_pkey_changed(ss, chan)))
				return (B_TRUE);

			chan = vnic->vn_data_chan;
			if ((chan) && (eib_ibt_has_chan_pkey_changed(ss, chan)))
				return (B_TRUE);
		}
		av &= (~((uint64_t)1 << inst));
	}
	mutex_exit(&ss->ei_vnic_lock);

	return (B_FALSE);
}

/*
 * This routine is currently used simply to derive and record the port
 * speed from the loopback path information (for debug purposes).  For
 * EoIB, currently the srate used in address vectors to IB neighbors
 * and the gateway is fixed at IBT_SRATE_10. Eventually though, this
 * information (and sl) has to come from the gateway for all destinations
 * in the vhub table.
 */
static void
eib_ibt_record_srate(eib_t *ss)
{
	ib_gid_t sgid = ss->ei_props->ep_sgid;
	ibt_srate_t srate = IBT_SRATE_10;
	ibt_path_info_t path;
	ibt_path_attr_t path_attr;
	ibt_status_t ret;
	uint8_t num_paths;

	bzero(&path_attr, sizeof (path_attr));
	path_attr.pa_dgids = &sgid;
	path_attr.pa_num_dgids = 1;
	path_attr.pa_sgid = sgid;

	ret = ibt_get_paths(ss->ei_ibt_hdl, IBT_PATH_NO_FLAGS,
	    &path_attr, 1, &path, &num_paths);
	if (ret == IBT_SUCCESS && num_paths >= 1) {
		switch (srate = path.pi_prim_cep_path.cep_adds_vect.av_srate) {
		case IBT_SRATE_2:
		case IBT_SRATE_10:
		case IBT_SRATE_30:
		case IBT_SRATE_5:
		case IBT_SRATE_20:
		case IBT_SRATE_40:
		case IBT_SRATE_60:
		case IBT_SRATE_80:
		case IBT_SRATE_120:
			break;
		default:
			srate = IBT_SRATE_10;
		}
	}

	ss->ei_props->ep_srate = srate;

	EIB_DPRINTF_DEBUG(ss->ei_instance, "eib_ibt_record_srate: "
	    "srate = %d", srate);
}
