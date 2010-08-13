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
 * The Ethernet Over Infiniband driver
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
 * Driver entry point declarations
 */
static int eib_attach(dev_info_t *, ddi_attach_cmd_t);
static int eib_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * MAC callbacks
 */
static int eib_m_stat(void *, uint_t, uint64_t *);
static int eib_m_start(void *);
static void eib_m_stop(void *);
static int eib_m_promisc(void *, boolean_t);
static int eib_m_multicast(void *, boolean_t, const uint8_t *);
static int eib_m_unicast(void *, const uint8_t *);
static mblk_t *eib_m_tx(void *, mblk_t *);
static boolean_t eib_m_getcapab(void *, mac_capab_t, void *);
static int eib_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int eib_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void eib_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

/*
 * Devops definition
 */
DDI_DEFINE_STREAM_OPS(eib_ops, nulldev, nulldev, eib_attach, eib_detach,
    nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

/*
 * Module Driver Info
 */
static struct modldrv eib_modldrv = {
	&mod_driverops,		/* Driver module */
	"EoIB Driver",		/* Driver name and version */
	&eib_ops,		/* Driver ops */
};

/*
 * Module Linkage
 */
static struct modlinkage eib_modlinkage = {
	MODREV_1, (void *)&eib_modldrv, NULL
};

/*
 * GLDv3 entry points
 */
#define	EIB_M_CALLBACK_FLAGS	\
	(MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO)
static mac_callbacks_t eib_m_callbacks = {
	EIB_M_CALLBACK_FLAGS,
	eib_m_stat,
	eib_m_start,
	eib_m_stop,
	eib_m_promisc,
	eib_m_multicast,
	eib_m_unicast,
	eib_m_tx,
	NULL,
	NULL,
	eib_m_getcapab,
	NULL,
	NULL,
	eib_m_setprop,
	eib_m_getprop,
	eib_m_propinfo
};

/*
 * Async handler callback for ibt events
 */
static ibt_clnt_modinfo_t eib_clnt_modinfo = {
	IBTI_V_CURR,
	IBT_NETWORK,
	eib_ibt_async_handler,
	NULL,
	EIB_DRV_NAME
};

/*
 * Driver State Pointer
 */
void *eib_state;

/*
 * Declarations private to this file
 */
static int eib_state_init(eib_t *);
static int eib_add_event_callbacks(eib_t *);
static int eib_register_with_mac(eib_t *, dev_info_t *);
static void eib_rb_attach(eib_t *, uint_t);
static void eib_rb_state_init(eib_t *);
static void eib_rb_add_event_callbacks(eib_t *);
static void eib_rb_register_with_mac(eib_t *);

/*
 * Definitions private to this file
 */
#define	EIB_ATTACH_STATE_ALLOCD		0x01
#define	EIB_ATTACH_PROPS_PARSED		0x02
#define	EIB_ATTACH_STATE_INIT_DONE	0x04
#define	EIB_ATTACH_IBT_ATT_DONE		0x08
#define	EIB_ATTACH_EV_CBS_ADDED		0x10
#define	EIB_ATTACH_REGISTER_MAC_DONE	0x20

int
_init()
{
	int ret;

	if (ddi_name_to_major(EIB_DRV_NAME) == (major_t)-1)
		return (ENODEV);

	if ((ret = ddi_soft_state_init(&eib_state, sizeof (eib_t), 0)) != 0)
		return (ret);

	mac_init_ops(&eib_ops, EIB_DRV_NAME);
	if ((ret = mod_install(&eib_modlinkage)) != 0) {
		mac_fini_ops(&eib_ops);
		ddi_soft_state_fini(&eib_state);
		return (ret);
	}

	eib_debug_init();

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&eib_modlinkage, modinfop));
}

int
_fini()
{
	int ret;

	if ((ret = mod_remove(&eib_modlinkage)) != 0)
		return (ret);

	eib_debug_fini();

	mac_fini_ops(&eib_ops);
	ddi_soft_state_fini(&eib_state);

	return (ret);
}

static int
eib_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	eib_t *ss;
	ibt_status_t ret;
	int instance;
	uint_t progress = 0;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Allocate softstate for this instance
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(eib_state, instance) == DDI_FAILURE)
		goto attach_fail;

	progress |= EIB_ATTACH_STATE_ALLOCD;

	ss = ddi_get_soft_state(eib_state, instance);
	ss->ei_dip = dip;
	ss->ei_instance = (uint_t)instance;

	/*
	 * Parse the node properties and get the gateway parameters
	 * for this instance
	 */
	if (eib_get_props(ss) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "eib_attach: eib_get_props() failed");
		goto attach_fail;
	}
	progress |= EIB_ATTACH_PROPS_PARSED;

	/*
	 * Do per-state initialization
	 */
	if (eib_state_init(ss) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "eib_attach: eib_state_init() failed");
		goto attach_fail;
	}
	progress |= EIB_ATTACH_STATE_INIT_DONE;

	/*
	 * Attach to IBTL
	 */
	if ((ret = ibt_attach(&eib_clnt_modinfo, ss->ei_dip, ss,
	    &ss->ei_ibt_hdl)) != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "eib_attach: ibt_attach() failed, ret=%d", ret);
		goto attach_fail;
	}
	progress |= EIB_ATTACH_IBT_ATT_DONE;

	/*
	 * Register NDI event callbacks with EoIB nexus
	 */
	if (eib_add_event_callbacks(ss) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "eib_attach: eib_add_event_callbacks() failed");
		goto attach_fail;
	}
	progress |= EIB_ATTACH_EV_CBS_ADDED;

	/*
	 * Register with mac layer
	 */
	if (eib_register_with_mac(ss, dip) != EIB_E_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance,
		    "eib_attach: eib_register_with_mac() failed");
		goto attach_fail;
	}
	progress |= EIB_ATTACH_REGISTER_MAC_DONE;

	return (DDI_SUCCESS);

attach_fail:
	eib_rb_attach(ss, progress);
	return (DDI_FAILURE);
}

static int
eib_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	eib_t *ss;
	int instance;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	ss = ddi_get_soft_state(eib_state, instance);

	/*
	 * If we had not cleaned up rx buffers (and hca resources) during
	 * unplumb because they were stuck with the nw layer at the time,
	 * we can try to clean them up now before doing the detach.
	 */
	eib_mac_set_nic_state(ss, EIB_NIC_STOPPING);

	eib_rb_rsrc_setup_bufs(ss, B_FALSE);
	if (ss->ei_tx || ss->ei_rx || ss->ei_lso) {
		EIB_DPRINTF_WARN(ss->ei_instance,
		    "eib_detach: buffers still not returned "
		    "(tx=0x%llx, rx=0x%llx, lso=0x%llx), could "
		    "not detach", ss->ei_tx, ss->ei_rx, ss->ei_lso);
		eib_mac_clr_nic_state(ss, EIB_NIC_STOPPING);
		return (DDI_FAILURE);
	}
	if (ss->ei_hca_hdl) {
		eib_rb_ibt_hca_init(ss, ~0);
	}
	eib_mac_clr_nic_state(ss, EIB_NIC_STOPPING);

	eib_rb_attach(ss, ~0);

	return (DDI_SUCCESS);
}

static int
eib_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	eib_t *ss = arg;
	eib_stats_t *stats = ss->ei_stats;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ss->ei_props->ep_ifspeed;
		break;

	case MAC_STAT_OBYTES:
		*val = stats->st_obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = stats->st_opkts;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = stats->st_brdcstxmit;
		break;

	case MAC_STAT_MULTIXMT:
		*val = stats->st_multixmit;
		break;

	case MAC_STAT_OERRORS:
		*val = stats->st_oerrors;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = stats->st_noxmitbuf;
		break;

	case MAC_STAT_RBYTES:
		*val = stats->st_rbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = stats->st_ipkts;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = stats->st_brdcstrcv;
		break;

	case MAC_STAT_MULTIRCV:
		*val = stats->st_multircv;
		break;

	case MAC_STAT_IERRORS:
		*val = stats->st_ierrors;
		break;

	case MAC_STAT_NORCVBUF:
		*val = stats->st_norcvbuf;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

static int
eib_m_start(void *arg)
{
	eib_t *ss = arg;
	int ret = -1;

	eib_mac_set_nic_state(ss, EIB_NIC_STARTING);

	if ((ss->ei_node_state->ns_nic_state & EIB_NIC_STARTED) == 0)
		ret = eib_mac_start(ss);

	if (ret == 0)
		eib_mac_upd_nic_state(ss, EIB_NIC_STARTING, EIB_NIC_STARTED);
	else
		eib_mac_clr_nic_state(ss, EIB_NIC_STARTING);

	return (ret);
}

static void
eib_m_stop(void *arg)
{
	eib_t *ss = arg;

	eib_mac_set_nic_state(ss, EIB_NIC_STOPPING);

	if ((ss->ei_node_state->ns_nic_state & EIB_NIC_STARTED) != 0)
		eib_mac_stop(ss);

	eib_mac_clr_nic_state(ss, EIB_NIC_STARTED|EIB_NIC_STOPPING);
}

static int
eib_m_promisc(void *arg, boolean_t flag)
{
	eib_t *ss = arg;

	if ((ss->ei_node_state->ns_nic_state & EIB_NIC_STARTED) == 0)
		return (0);

	return (eib_mac_promisc(ss, flag));
}

static int
eib_m_multicast(void *arg, boolean_t add, const uint8_t *mcast_mac)
{
	eib_t *ss = arg;

	if ((ss->ei_node_state->ns_nic_state & EIB_NIC_STARTED) == 0)
		return (0);

	/*
	 * We don't have any knowledge which of the vnics built on top of
	 * the physlink is this multicast group relevant for.  We'll join
	 * it for vnic0 for now.
	 *
	 * Since the tx routine in EoIB currently piggy backs all multicast
	 * traffic over the broadcast channel, and all vnics are joined to
	 * the broadcast address when they're created, everyone should receive
	 * all multicast traffic anyway.
	 *
	 * On the rx side, we'll check if the incoming multicast address is
	 * either on the vnic's list of mcgs joined to (which will only be the
	 * broadcast address) or on vnic0's list of mcgs.  If we find a match,
	 * we let the packet come through.
	 *
	 * This isn't perfect, but it's the best we can do given that we don't
	 * have any vlan information corresponding to this multicast address.
	 *
	 * Also, for now we'll use the synchronous multicast joins and
	 * leaves instead of the asynchronous mechanism provided by
	 * ibt_join_mcg() since that involves additional complexity for failed
	 * joins and removals.
	 */
	return (eib_mac_multicast(ss, add, (uint8_t *)mcast_mac));
}

static int
eib_m_unicast(void *arg, const uint8_t *macaddr)
{
	eib_t *ss = arg;
	eib_vnic_t *vnic;

	if ((ss->ei_node_state->ns_nic_state & EIB_NIC_STARTED) == 0)
		return (0);

	mutex_enter(&ss->ei_vnic_lock);

	vnic = ss->ei_vnic[0];
	if (bcmp(macaddr, vnic->vn_login_data.ld_assigned_mac,
	    ETHERADDRL) == 0) {
		mutex_exit(&ss->ei_vnic_lock);
		return (0);
	}

	mutex_exit(&ss->ei_vnic_lock);

	return (EINVAL);
}

static mblk_t *
eib_m_tx(void *arg, mblk_t *mp)
{
	eib_t *ss = arg;
	mblk_t *next;

	/*
	 * If the nic hasn't been started, drop the message(s)
	 */
	if ((ss->ei_node_state->ns_nic_state & EIB_NIC_STARTED) == 0) {
		freemsgchain(mp);
		return (NULL);
	}

	for (; mp != NULL; mp = next) {
		/*
		 * Detach this message from the message chain
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Attempt to send the message; if we fail (likely due
		 * to lack of resources), reattach this message to the
		 * chain and return the unsent chain back.  When we're
		 * ready to send again, we'll issue a mac_tx_update().
		 */
		if (eib_mac_tx(ss, mp) != EIB_E_SUCCESS) {
			mp->b_next = next;
			break;
		}
	}

	return (mp);
}

static boolean_t
eib_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	eib_t *ss = arg;
	eib_caps_t *caps = ss->ei_caps;
	eib_caps_t s_caps;
	ibt_hca_attr_t hca_attrs;
	ibt_status_t ret;

	/*
	 * If we haven't been plumbed yet, try getting the hca attributes
	 * and figure out the capabilities now
	 */
	if (caps == NULL) {
		ASSERT(ss->ei_props != NULL);

		ret = ibt_query_hca_byguid(ss->ei_props->ep_hca_guid,
		    &hca_attrs);
		if (ret == IBT_SUCCESS) {
			eib_ibt_record_capab(ss, &hca_attrs, &s_caps);
			caps = &s_caps;
		}
	}

	if ((caps != NULL) && (cap == MAC_CAPAB_HCKSUM)) {
		uint32_t *tx_flags = cap_data;

		if (caps->cp_cksum_flags == 0) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance,
			    "eib_m_getcapab: hw cksum disabled, cksum_flags=0");
			return (B_FALSE);
		}

		*tx_flags = caps->cp_cksum_flags;

		return (B_TRUE);

	} else if ((caps != NULL) && (cap == MAC_CAPAB_LSO)) {
		mac_capab_lso_t *cap_lso = cap_data;

		/*
		 * If the HCA supports LSO, it will advertise a non-zero
		 * "max lso size" parameter. Also, LSO relies on hw
		 * checksum being available.  Finally, if the HCA
		 * doesn't provide the reserved-lkey capability, LSO
		 * will adversely affect the performance.  So, we'll
		 * enable LSO only if we have a non-zero max lso size,
		 * support checksum offload and provide reserved lkey.
		 */
		if (caps->cp_lso_maxlen == 0 ||
		    caps->cp_cksum_flags == 0 ||
		    caps->cp_resv_lkey_capab == 0) {
			EIB_DPRINTF_VERBOSE(ss->ei_instance, "eib_m_getcapab: "
			    "LSO disabled, lso_maxlen=0x%lx, "
			    "cksum_flags=0x%lx, resv_lkey_capab=%d",
			    caps->cp_lso_maxlen,
			    caps->cp_cksum_flags,
			    caps->cp_resv_lkey_capab);
			return (B_FALSE);
		}

		cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		cap_lso->lso_basic_tcp_ipv4.lso_max = caps->cp_lso_maxlen - 1;

		return (B_TRUE);
	}

	return (B_FALSE);
}

/*ARGSUSED*/
static int
eib_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	return (ENOTSUP);
}

static int
eib_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	eib_t *ss = arg;
	link_duplex_t duplex = LINK_DUPLEX_FULL;
	uint64_t speed = ss->ei_props->ep_ifspeed;
	int err = 0;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		ASSERT(pr_valsize >= sizeof (link_duplex_t));
		bcopy(&duplex, pr_val, sizeof (link_duplex_t));
		break;

	case MAC_PROP_SPEED:
		ASSERT(pr_valsize >= sizeof (uint64_t));
		bcopy(&speed, pr_val, sizeof (speed));
		break;

	case MAC_PROP_PRIVATE:
		if (strcmp(pr_name, EIB_DLPROP_GW_EPORT_STATE) == 0) {
			if (ss->ei_gw_eport_state == FIP_EPORT_UP) {
				(void) snprintf(pr_val, pr_valsize,
				    "%s", "up");
			} else {
				(void) snprintf(pr_val, pr_valsize,
				    "%s", "down");
			}
		} else if (strcmp(pr_name, EIB_DLPROP_HCA_GUID) == 0) {
			(void) snprintf(pr_val, pr_valsize, "%llX",
			    (u_longlong_t)ss->ei_props->ep_hca_guid);

		} else if (strcmp(pr_name, EIB_DLPROP_PORT_GUID) == 0) {
			(void) snprintf(pr_val, pr_valsize, "%llX",
			    (u_longlong_t)((ss->ei_props->ep_sgid).gid_guid));
		}
		break;

	default:
		err = ENOTSUP;
		break;
	}

	return (err);
}

/*ARGSUSED*/
static void
eib_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_range_uint32(prh, ETHERMTU, ETHERMTU);
		break;

	case MAC_PROP_PRIVATE:
		if (strcmp(pr_name, EIB_DLPROP_GW_EPORT_STATE) == 0) {
			mac_prop_info_set_default_str(prh, "up ");
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else if (strcmp(pr_name, EIB_DLPROP_HCA_GUID) == 0) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else if (strcmp(pr_name, EIB_DLPROP_PORT_GUID) == 0) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;
	}
}

static int
eib_state_init(eib_t *ss)
{
	kthread_t *kt;

	/*
	 * Initialize synchronization primitives
	 */
	mutex_init(&ss->ei_vnic_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ss->ei_av_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ss->ei_ev_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ss->ei_rxpost_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ss->ei_vnic_req_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ss->ei_ka_vnics_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ss->ei_vnic_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ss->ei_ev_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ss->ei_rxpost_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ss->ei_vnic_req_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ss->ei_ka_vnics_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Create a node state structure and initialize
	 */
	ss->ei_node_state = kmem_zalloc(sizeof (eib_node_state_t), KM_SLEEP);
	ss->ei_node_state->ns_link_state = LINK_STATE_UNKNOWN;
	mutex_init(&ss->ei_node_state->ns_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ss->ei_node_state->ns_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Allocate for gathering statistics
	 */
	ss->ei_stats = kmem_zalloc(sizeof (eib_stats_t), KM_SLEEP);

	/*
	 * Start up service threads
	 */
	kt = thread_create(NULL, 0, eib_events_handler, ss, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->ei_events_handler = kt->t_did;

	kt = thread_create(NULL, 0, eib_refill_rwqes, ss, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->ei_rwqes_refiller = kt->t_did;

	kt = thread_create(NULL, 0, eib_vnic_creator, ss, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->ei_vnic_creator = kt->t_did;

	kt = thread_create(NULL, 0, eib_manage_keepalives, ss, 0,
	    &p0, TS_RUN, minclsyspri);
	ss->ei_keepalives_manager = kt->t_did;

	/*
	 * Set default state of gw eport
	 */
	ss->ei_gw_eport_state = FIP_EPORT_UP;

	/*
	 * Do static initializations of common structures
	 */
	eib_reserved_gid.gid_prefix = 0;
	eib_reserved_gid.gid_guid = 0;

	return (EIB_E_SUCCESS);
}

static int
eib_add_event_callbacks(eib_t *ss)
{
	int ret;
	ddi_eventcookie_t login_ack_evc;
	ddi_eventcookie_t gw_alive_evc;
	ddi_eventcookie_t gw_info_evc;

	/*
	 * Add callback for receiving vnic login acks from the gateway
	 */
	if ((ret = ddi_get_eventcookie(ss->ei_dip, EIB_NDI_EVENT_LOGIN_ACK,
	    &login_ack_evc)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_add_event_callbacks: "
		    "ddi_get_eventcookie(LOGIN_ACK) failed, ret=%d", ret);
		return (EIB_E_FAILURE);
	}
	if ((ret = ddi_add_event_handler(ss->ei_dip, login_ack_evc,
	    eib_login_ack_cb, ss, &ss->ei_login_ack_cb)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_add_event_callbacks: "
		    "ddi_add_event_handler(LOGIN_ACK) failed, ret=%d", ret);
		return (EIB_E_FAILURE);
	}

	/*
	 * Add callback for receiving status on gateway transitioning from
	 * not-available to available
	 */
	if ((ret = ddi_get_eventcookie(ss->ei_dip, EIB_NDI_EVENT_GW_AVAILABLE,
	    &gw_alive_evc)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_add_event_callbacks: "
		    "ddi_get_eventcookie(GW_AVAILABLE) failed, ret=%d", ret);
		(void) ddi_remove_event_handler(ss->ei_login_ack_cb);
		return (EIB_E_FAILURE);
	}
	if ((ret = ddi_add_event_handler(ss->ei_dip, gw_alive_evc,
	    eib_gw_alive_cb, ss, &ss->ei_gw_alive_cb)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_add_event_callbacks: "
		    "ddi_add_event_handler(GW_AVAILABLE) failed, ret=%d", ret);
		(void) ddi_remove_event_handler(ss->ei_login_ack_cb);
		return (EIB_E_FAILURE);
	}

	/*
	 * Add callback for receiving gateway info update
	 */
	if ((ret = ddi_get_eventcookie(ss->ei_dip, EIB_NDI_EVENT_GW_INFO_UPDATE,
	    &gw_info_evc)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_add_event_callbacks: "
		    "ddi_get_eventcookie(GW_INFO_UPDATE) failed, ret=%d", ret);
		(void) ddi_remove_event_handler(ss->ei_gw_alive_cb);
		(void) ddi_remove_event_handler(ss->ei_login_ack_cb);
		return (EIB_E_FAILURE);
	}
	if ((ret = ddi_add_event_handler(ss->ei_dip, gw_info_evc,
	    eib_gw_info_cb, ss, &ss->ei_gw_info_cb)) != DDI_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_add_event_callbacks: "
		    "ddi_add_event_handler(GW_INFO) failed, ret=%d", ret);
		(void) ddi_remove_event_handler(ss->ei_gw_alive_cb);
		(void) ddi_remove_event_handler(ss->ei_login_ack_cb);
		return (EIB_E_FAILURE);
	}

	return (EIB_E_SUCCESS);
}

static int
eib_register_with_mac(eib_t *ss, dev_info_t *dip)
{
	mac_register_t *macp;
	int ret;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_register_with_mac: "
		    "mac_alloc(MAC_VERSION=%d) failed", MAC_VERSION);
		return (EIB_E_FAILURE);
	}

	/*
	 * Note that when we register with mac during attach, we don't
	 * have the mac address yet (we'll get that after we login into
	 * the gateway) so we'll simply register a zero macaddr that
	 * we'll overwrite later during plumb, in eib_m_start(). Likewise,
	 * we'll also update the max-sdu with the correct MTU after we
	 * figure it out when we login to the gateway during plumb.
	 */
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = ss;
	macp->m_dip = dip;
	macp->m_src_addr = eib_zero_mac;
	macp->m_callbacks = &eib_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = eib_pvt_props;

	ret = mac_register(macp, &ss->ei_mac_hdl);
	mac_free(macp);

	if (ret != 0) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_register_with_mac: "
		    "mac_register() failed, ret=%d", ret);
		return (EIB_E_FAILURE);
	}

	return (EIB_E_SUCCESS);
}

static void
eib_rb_attach(eib_t *ss, uint_t progress)
{
	ibt_status_t ret;
	int instance;

	if (progress & EIB_ATTACH_REGISTER_MAC_DONE)
		eib_rb_register_with_mac(ss);

	if (progress & EIB_ATTACH_EV_CBS_ADDED)
		eib_rb_add_event_callbacks(ss);

	if (progress & EIB_ATTACH_IBT_ATT_DONE) {
		ret = ibt_detach(ss->ei_ibt_hdl);
		if (ret != IBT_SUCCESS) {
			EIB_DPRINTF_WARN(ss->ei_instance, "eib_rb_attach: "
			    "ibt_detach() failed, ret=%d", ret);
		}
		ss->ei_ibt_hdl = NULL;
	}

	if (progress & EIB_ATTACH_STATE_INIT_DONE)
		eib_rb_state_init(ss);

	if (progress & EIB_ATTACH_PROPS_PARSED)
		eib_rb_get_props(ss);

	if (progress & EIB_ATTACH_STATE_ALLOCD) {
		instance = ddi_get_instance(ss->ei_dip);
		ddi_soft_state_free(eib_state, instance);
	}
}

static void
eib_rb_state_init(eib_t *ss)
{
	/*
	 * Terminate service threads
	 */
	if (ss->ei_keepalives_manager) {
		eib_stop_manage_keepalives(ss);
		ss->ei_keepalives_manager = 0;
	}
	if (ss->ei_vnic_creator) {
		eib_stop_vnic_creator(ss);
		ss->ei_vnic_creator = 0;
	}
	if (ss->ei_rwqes_refiller) {
		eib_stop_refill_rwqes(ss);
		ss->ei_rwqes_refiller = 0;
	}
	if (ss->ei_events_handler) {
		eib_stop_events_handler(ss);
		ss->ei_events_handler = 0;
	}

	/*
	 * Remove space allocated for gathering statistics
	 */
	if (ss->ei_stats) {
		kmem_free(ss->ei_stats, sizeof (eib_stats_t));
		ss->ei_stats = NULL;
	}

	/*
	 * Remove space allocated for keeping node state
	 */
	if (ss->ei_node_state) {
		cv_destroy(&ss->ei_node_state->ns_cv);
		mutex_destroy(&ss->ei_node_state->ns_lock);
		kmem_free(ss->ei_node_state, sizeof (eib_node_state_t));
		ss->ei_node_state = NULL;
	}

	/*
	 * Finally, destroy all synchronization resources
	 */
	cv_destroy(&ss->ei_ka_vnics_cv);
	cv_destroy(&ss->ei_vnic_req_cv);
	cv_destroy(&ss->ei_rxpost_cv);
	cv_destroy(&ss->ei_ev_cv);
	cv_destroy(&ss->ei_vnic_cv);
	mutex_destroy(&ss->ei_ka_vnics_lock);
	mutex_destroy(&ss->ei_vnic_req_lock);
	mutex_destroy(&ss->ei_rxpost_lock);
	mutex_destroy(&ss->ei_ev_lock);
	mutex_destroy(&ss->ei_av_lock);
	mutex_destroy(&ss->ei_vnic_lock);
}

static void
eib_rb_add_event_callbacks(eib_t *ss)
{
	ddi_eventcookie_t evc;

	if (ddi_get_eventcookie(ss->ei_dip, EIB_NDI_EVENT_GW_INFO_UPDATE,
	    &evc) == DDI_SUCCESS) {
		(void) ddi_remove_event_handler(ss->ei_gw_info_cb);
		ss->ei_gw_info_cb = NULL;
	}

	if (ddi_get_eventcookie(ss->ei_dip, EIB_NDI_EVENT_GW_AVAILABLE,
	    &evc) == DDI_SUCCESS) {
		(void) ddi_remove_event_handler(ss->ei_gw_alive_cb);
		ss->ei_gw_alive_cb = NULL;
	}

	if (ddi_get_eventcookie(ss->ei_dip, EIB_NDI_EVENT_LOGIN_ACK,
	    &evc) == DDI_SUCCESS) {
		(void) ddi_remove_event_handler(ss->ei_login_ack_cb);
		ss->ei_login_ack_cb = NULL;
	}
}

static void
eib_rb_register_with_mac(eib_t *ss)
{
	int ret;

	if ((ret = mac_unregister(ss->ei_mac_hdl)) != 0) {
		EIB_DPRINTF_WARN(ss->ei_instance,
		    "eib_rb_register_with_mac: "
		    "mac_unregister() failed, ret=%d", ret);
	}

	ss->ei_mac_hdl = NULL;
}
