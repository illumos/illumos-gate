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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * - General Introduction:
 *
 * This file contains the implementation of the MAC client kernel
 * API and related code. The MAC client API allows a kernel module
 * to gain access to a MAC instance (physical NIC, link aggregation, etc).
 * It allows a MAC client to associate itself with a MAC address,
 * VLANs, callback functions for data traffic and for promiscuous mode.
 * The MAC client API is also used to specify the properties associated
 * with a MAC client, such as bandwidth limits, priority, CPUS, etc.
 * These properties are further used to determine the hardware resources
 * to allocate to the various MAC clients.
 *
 * - Primary MAC clients:
 *
 * The MAC client API refers to "primary MAC clients". A primary MAC
 * client is a client which "owns" the primary MAC address of
 * the underlying MAC instance. The primary MAC address is called out
 * since it is associated with specific semantics: the primary MAC
 * address is the MAC address which is assigned to the IP interface
 * when it is plumbed, and the primary MAC address is assigned
 * to VLAN data-links. The primary address of a MAC instance can
 * also change dynamically from under the MAC client, for example
 * as a result of a change of state of a link aggregation. In that
 * case the MAC layer automatically updates all data-structures which
 * refer to the current value of the primary MAC address. Typical
 * primary MAC clients are dls, aggr, and xnb. A typical non-primary
 * MAC client is the vnic driver.
 *
 * - Virtual Switching:
 *
 * The MAC layer implements a virtual switch between the MAC clients
 * (primary and non-primary) defined on top of the same underlying
 * NIC (physical, link aggregation, etc). The virtual switch is
 * VLAN-aware, i.e. it allows multiple MAC clients to be member
 * of one or more VLANs, and the virtual switch will distribute
 * multicast tagged packets only to the member of the corresponding
 * VLANs.
 *
 * - Upper vs Lower MAC:
 *
 * Creating a VNIC on top of a MAC instance effectively causes
 * two MAC instances to be layered on top of each other, one for
 * the VNIC(s), one for the underlying MAC instance (physical NIC,
 * link aggregation, etc). In the code below we refer to the
 * underlying NIC as the "lower MAC", and we refer to VNICs as
 * the "upper MAC".
 *
 * - Pass-through for VNICs:
 *
 * When VNICs are created on top of an underlying MAC, this causes
 * a layering of two MAC instances. Since the lower MAC already
 * does the switching and demultiplexing to its MAC clients, the
 * upper MAC would simply have to pass packets to the layer below
 * or above it, which would introduce overhead. In order to avoid
 * this overhead, the MAC layer implements a pass-through mechanism
 * for VNICs. When a VNIC opens the lower MAC instance, it saves
 * the MAC client handle it optains from the MAC layer. When a MAC
 * client opens a VNIC (upper MAC), the MAC layer detects that
 * the MAC being opened is a VNIC, and gets the MAC client handle
 * that the VNIC driver obtained from the lower MAC. This exchange
 * is done through a private capability between the MAC layer
 * and the VNIC driver. The upper MAC then returns that handle
 * directly to its MAC client. Any operation done by the upper
 * MAC client is now done on the lower MAC client handle, which
 * allows the VNIC driver to be completely bypassed for the
 * performance sensitive data-path.
 *
 * - Secondary MACs for VNICs:
 *
 * VNICs support multiple upper mac clients to enable support for
 * multiple MAC addresses on the VNIC. When the VNIC is created the
 * initial mac client is the primary upper mac. Any additional mac
 * clients are secondary macs. These are kept in sync with the primary
 * (for things such as the rx function and resource control settings)
 * using the same private capability interface between the MAC layer
 * and the VNIC layer.
 *
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/id_space.h>
#include <sys/esunddi.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/modhash.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_soft_ring.h>
#include <sys/mac_stat.h>
#include <sys/dls.h>
#include <sys/dld.h>
#include <sys/modctl.h>
#include <sys/fs/dv_node.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/sdt.h>
#include <sys/mac_flow.h>
#include <sys/ddi_intr_impl.h>
#include <sys/disp.h>
#include <sys/sdt.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>
#include <sys/vlan.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/exacct.h>
#include <sys/exacct_impl.h>
#include <inet/nd.h>
#include <sys/ethernet.h>

kmem_cache_t	*mac_client_impl_cache;
kmem_cache_t	*mac_promisc_impl_cache;

static boolean_t mac_client_single_rcvr(mac_client_impl_t *);
static flow_entry_t *mac_client_swap_mciflent(mac_client_impl_t *);
static flow_entry_t *mac_client_get_flow(mac_client_impl_t *,
    mac_unicast_impl_t *);
static void mac_client_remove_flow_from_list(mac_client_impl_t *,
    flow_entry_t *);
static void mac_client_add_to_flow_list(mac_client_impl_t *, flow_entry_t *);
static void mac_rename_flow_names(mac_client_impl_t *, const char *);
static void mac_virtual_link_update(mac_impl_t *);
static int mac_client_datapath_setup(mac_client_impl_t *, uint16_t,
    uint8_t *, mac_resource_props_t *, boolean_t, mac_unicast_impl_t *);
static void mac_client_datapath_teardown(mac_client_handle_t,
    mac_unicast_impl_t *, flow_entry_t *);
static int mac_resource_ctl_set(mac_client_handle_t, mac_resource_props_t *);

/* ARGSUSED */
static int
i_mac_client_impl_ctor(void *buf, void *arg, int kmflag)
{
	int	i;
	mac_client_impl_t	*mcip = buf;

	bzero(buf, MAC_CLIENT_IMPL_SIZE);
	mutex_init(&mcip->mci_tx_cb_lock, NULL, MUTEX_DRIVER, NULL);
	mcip->mci_tx_notify_cb_info.mcbi_lockp = &mcip->mci_tx_cb_lock;

	ASSERT(mac_tx_percpu_cnt >= 0);
	for (i = 0; i <= mac_tx_percpu_cnt; i++) {
		mutex_init(&mcip->mci_tx_pcpu[i].pcpu_tx_lock, NULL,
		    MUTEX_DRIVER, NULL);
	}
	cv_init(&mcip->mci_tx_cv, NULL, CV_DRIVER, NULL);

	return (0);
}

/* ARGSUSED */
static void
i_mac_client_impl_dtor(void *buf, void *arg)
{
	int	i;
	mac_client_impl_t *mcip = buf;

	ASSERT(mcip->mci_promisc_list == NULL);
	ASSERT(mcip->mci_unicast_list == NULL);
	ASSERT(mcip->mci_state_flags == 0);
	ASSERT(mcip->mci_tx_flag == 0);

	mutex_destroy(&mcip->mci_tx_cb_lock);

	ASSERT(mac_tx_percpu_cnt >= 0);
	for (i = 0; i <= mac_tx_percpu_cnt; i++) {
		ASSERT(mcip->mci_tx_pcpu[i].pcpu_tx_refcnt == 0);
		mutex_destroy(&mcip->mci_tx_pcpu[i].pcpu_tx_lock);
	}
	cv_destroy(&mcip->mci_tx_cv);
}

/* ARGSUSED */
static int
i_mac_promisc_impl_ctor(void *buf, void *arg, int kmflag)
{
	mac_promisc_impl_t	*mpip = buf;

	bzero(buf, sizeof (mac_promisc_impl_t));
	mpip->mpi_mci_link.mcb_objp = buf;
	mpip->mpi_mci_link.mcb_objsize = sizeof (mac_promisc_impl_t);
	mpip->mpi_mi_link.mcb_objp = buf;
	mpip->mpi_mi_link.mcb_objsize = sizeof (mac_promisc_impl_t);
	return (0);
}

/* ARGSUSED */
static void
i_mac_promisc_impl_dtor(void *buf, void *arg)
{
	mac_promisc_impl_t	*mpip = buf;

	ASSERT(mpip->mpi_mci_link.mcb_objp != NULL);
	ASSERT(mpip->mpi_mci_link.mcb_objsize == sizeof (mac_promisc_impl_t));
	ASSERT(mpip->mpi_mi_link.mcb_objp == mpip->mpi_mci_link.mcb_objp);
	ASSERT(mpip->mpi_mi_link.mcb_objsize == sizeof (mac_promisc_impl_t));

	mpip->mpi_mci_link.mcb_objp = NULL;
	mpip->mpi_mci_link.mcb_objsize = 0;
	mpip->mpi_mi_link.mcb_objp = NULL;
	mpip->mpi_mi_link.mcb_objsize = 0;

	ASSERT(mpip->mpi_mci_link.mcb_flags == 0);
	mpip->mpi_mci_link.mcb_objsize = 0;
}

void
mac_client_init(void)
{
	ASSERT(mac_tx_percpu_cnt >= 0);

	mac_client_impl_cache = kmem_cache_create("mac_client_impl_cache",
	    MAC_CLIENT_IMPL_SIZE, 0, i_mac_client_impl_ctor,
	    i_mac_client_impl_dtor, NULL, NULL, NULL, 0);
	ASSERT(mac_client_impl_cache != NULL);

	mac_promisc_impl_cache = kmem_cache_create("mac_promisc_impl_cache",
	    sizeof (mac_promisc_impl_t), 0, i_mac_promisc_impl_ctor,
	    i_mac_promisc_impl_dtor, NULL, NULL, NULL, 0);
	ASSERT(mac_promisc_impl_cache != NULL);
}

void
mac_client_fini(void)
{
	kmem_cache_destroy(mac_client_impl_cache);
	kmem_cache_destroy(mac_promisc_impl_cache);
}

/*
 * Return the lower MAC client handle from the VNIC driver for the
 * specified VNIC MAC instance.
 */
mac_client_impl_t *
mac_vnic_lower(mac_impl_t *mip)
{
	mac_capab_vnic_t cap;
	mac_client_impl_t *mcip;

	VERIFY(i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_VNIC, &cap));
	mcip = cap.mcv_mac_client_handle(cap.mcv_arg);

	return (mcip);
}

/*
 * Update the secondary macs
 */
void
mac_vnic_secondary_update(mac_impl_t *mip)
{
	mac_capab_vnic_t cap;

	VERIFY(i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_VNIC, &cap));
	cap.mcv_mac_secondary_update(cap.mcv_arg);
}

/*
 * Return the MAC client handle of the primary MAC client for the
 * specified MAC instance, or NULL otherwise.
 */
mac_client_impl_t *
mac_primary_client_handle(mac_impl_t *mip)
{
	mac_client_impl_t *mcip;

	if (mip->mi_state_flags & MIS_IS_VNIC)
		return (mac_vnic_lower(mip));

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	for (mcip = mip->mi_clients_list; mcip != NULL;
	    mcip = mcip->mci_client_next) {
		if (MCIP_DATAPATH_SETUP(mcip) && mac_is_primary_client(mcip))
			return (mcip);
	}
	return (NULL);
}

/*
 * Open a MAC specified by its MAC name.
 */
int
mac_open(const char *macname, mac_handle_t *mhp)
{
	mac_impl_t	*mip;
	int		err;

	/*
	 * Look up its entry in the global hash table.
	 */
	if ((err = mac_hold(macname, &mip)) != 0)
		return (err);

	/*
	 * Hold the dip associated to the MAC to prevent it from being
	 * detached. For a softmac, its underlying dip is held by the
	 * mi_open() callback.
	 *
	 * This is done to be more tolerant with some defective drivers,
	 * which incorrectly handle mac_unregister() failure in their
	 * xxx_detach() routine. For example, some drivers ignore the
	 * failure of mac_unregister() and free all resources that
	 * that are needed for data transmition.
	 */
	e_ddi_hold_devi(mip->mi_dip);

	if (!(mip->mi_callbacks->mc_callbacks & MC_OPEN)) {
		*mhp = (mac_handle_t)mip;
		return (0);
	}

	/*
	 * The mac perimeter is used in both mac_open and mac_close by the
	 * framework to single thread the MC_OPEN/MC_CLOSE of drivers.
	 */
	i_mac_perim_enter(mip);
	mip->mi_oref++;
	if (mip->mi_oref != 1 || ((err = mip->mi_open(mip->mi_driver)) == 0)) {
		*mhp = (mac_handle_t)mip;
		i_mac_perim_exit(mip);
		return (0);
	}
	mip->mi_oref--;
	ddi_release_devi(mip->mi_dip);
	mac_rele(mip);
	i_mac_perim_exit(mip);
	return (err);
}

/*
 * Open a MAC specified by its linkid.
 */
int
mac_open_by_linkid(datalink_id_t linkid, mac_handle_t *mhp)
{
	dls_dl_handle_t	dlh;
	int		err;

	if ((err = dls_devnet_hold_tmp(linkid, &dlh)) != 0)
		return (err);

	dls_devnet_prop_task_wait(dlh);

	err = mac_open(dls_devnet_mac(dlh), mhp);

	dls_devnet_rele_tmp(dlh);
	return (err);
}

/*
 * Open a MAC specified by its link name.
 */
int
mac_open_by_linkname(const char *link, mac_handle_t *mhp)
{
	datalink_id_t	linkid;
	int		err;

	if ((err = dls_mgmt_get_linkid(link, &linkid)) != 0)
		return (err);
	return (mac_open_by_linkid(linkid, mhp));
}

/*
 * Close the specified MAC.
 */
void
mac_close(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	i_mac_perim_enter(mip);
	/*
	 * The mac perimeter is used in both mac_open and mac_close by the
	 * framework to single thread the MC_OPEN/MC_CLOSE of drivers.
	 */
	if (mip->mi_callbacks->mc_callbacks & MC_OPEN) {
		ASSERT(mip->mi_oref != 0);
		if (--mip->mi_oref == 0) {
			if ((mip->mi_callbacks->mc_callbacks & MC_CLOSE))
				mip->mi_close(mip->mi_driver);
		}
	}
	i_mac_perim_exit(mip);
	ddi_release_devi(mip->mi_dip);
	mac_rele(mip);
}

/*
 * Misc utility functions to retrieve various information about a MAC
 * instance or a MAC client.
 */

const mac_info_t *
mac_info(mac_handle_t mh)
{
	return (&((mac_impl_t *)mh)->mi_info);
}

dev_info_t *
mac_devinfo_get(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_dip);
}

void *
mac_driver(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_driver);
}

const char *
mac_name(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_name);
}

int
mac_type(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_type->mt_type);
}

int
mac_nativetype(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_type->mt_nativetype);
}

char *
mac_client_name(mac_client_handle_t mch)
{
	return (((mac_client_impl_t *)mch)->mci_name);
}

minor_t
mac_minor(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_minor);
}

/*
 * Return the VID associated with a MAC client. This function should
 * be called for clients which are associated with only one VID.
 */
uint16_t
mac_client_vid(mac_client_handle_t mch)
{
	uint16_t		vid = VLAN_ID_NONE;
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	flow_desc_t		flow_desc;

	if (mcip->mci_nflents == 0)
		return (vid);

	ASSERT(MCIP_DATAPATH_SETUP(mcip) && mac_client_single_rcvr(mcip));

	mac_flow_get_desc(mcip->mci_flent, &flow_desc);
	if ((flow_desc.fd_mask & FLOW_LINK_VID) != 0)
		vid = flow_desc.fd_vid;

	return (vid);
}

/*
 * Return whether the specified MAC client corresponds to a VLAN VNIC.
 */
boolean_t
mac_client_is_vlan_vnic(mac_client_handle_t mch)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;

	return (((mcip->mci_state_flags & MCIS_IS_VNIC) != 0) &&
	    ((mcip->mci_flent->fe_type & FLOW_PRIMARY_MAC) != 0));
}

/*
 * Return the link speed associated with the specified MAC client.
 *
 * The link speed of a MAC client is equal to the smallest value of
 * 1) the current link speed of the underlying NIC, or
 * 2) the bandwidth limit set for the MAC client.
 *
 * Note that the bandwidth limit can be higher than the speed
 * of the underlying NIC. This is allowed to avoid spurious
 * administration action failures or artifically lowering the
 * bandwidth limit of a link that may  have temporarily lowered
 * its link speed due to hardware problem or administrator action.
 */
static uint64_t
mac_client_ifspeed(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;
	uint64_t nic_speed;

	nic_speed = mac_stat_get((mac_handle_t)mip, MAC_STAT_IFSPEED);

	if (nic_speed == 0) {
		return (0);
	} else {
		uint64_t policy_limit = (uint64_t)-1;

		if (MCIP_RESOURCE_PROPS_MASK(mcip) & MRP_MAXBW)
			policy_limit = MCIP_RESOURCE_PROPS_MAXBW(mcip);

		return (MIN(policy_limit, nic_speed));
	}
}

/*
 * Return the link state of the specified client. If here are more
 * than one clients of the underying mac_impl_t, the link state
 * will always be UP regardless of the link state of the underlying
 * mac_impl_t. This is needed to allow the MAC clients to continue
 * to communicate with each other even when the physical link of
 * their mac_impl_t is down.
 */
static uint64_t
mac_client_link_state(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;
	uint16_t vid;
	mac_client_impl_t *mci_list;
	mac_unicast_impl_t *mui_list, *oth_mui_list;

	/*
	 * Returns LINK_STATE_UP if there are other MAC clients defined on
	 * mac_impl_t which share same VLAN ID as that of mcip. Note that
	 * if 'mcip' has more than one VID's then we match ANY one of the
	 * VID's with other MAC client's VID's and return LINK_STATE_UP.
	 */
	rw_enter(&mcip->mci_rw_lock, RW_READER);
	for (mui_list = mcip->mci_unicast_list; mui_list != NULL;
	    mui_list = mui_list->mui_next) {
		vid = mui_list->mui_vid;
		for (mci_list = mip->mi_clients_list; mci_list != NULL;
		    mci_list = mci_list->mci_client_next) {
			if (mci_list == mcip)
				continue;
			for (oth_mui_list = mci_list->mci_unicast_list;
			    oth_mui_list != NULL; oth_mui_list = oth_mui_list->
			    mui_next) {
				if (vid == oth_mui_list->mui_vid) {
					rw_exit(&mcip->mci_rw_lock);
					return (LINK_STATE_UP);
				}
			}
		}
	}
	rw_exit(&mcip->mci_rw_lock);

	return (mac_stat_get((mac_handle_t)mip, MAC_STAT_LINK_STATE));
}

/*
 * These statistics are consumed by dladm show-link -s <vnic>,
 * dladm show-vnic -s and netstat. With the introduction of dlstat,
 * dladm show-link -s and dladm show-vnic -s witll be EOL'ed while
 * netstat will consume from kstats introduced for dlstat. This code
 * will be removed at that time.
 */

/*
 * Return the statistics of a MAC client. These statistics are different
 * then the statistics of the underlying MAC which are returned by
 * mac_stat_get().
 */
uint64_t
mac_client_stat_get(mac_client_handle_t mch, uint_t stat)
{
	mac_client_impl_t 	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t 		*mip = mcip->mci_mip;
	flow_entry_t 		*flent = mcip->mci_flent;
	mac_soft_ring_set_t 	*mac_srs;
	mac_rx_stats_t		*mac_rx_stat;
	mac_tx_stats_t		*mac_tx_stat;
	int i;
	uint64_t val = 0;

	mac_srs = (mac_soft_ring_set_t *)(flent->fe_tx_srs);
	mac_tx_stat = &mac_srs->srs_tx.st_stat;

	switch (stat) {
	case MAC_STAT_LINK_STATE:
		val = mac_client_link_state(mcip);
		break;
	case MAC_STAT_LINK_UP:
		val = (mac_client_link_state(mcip) == LINK_STATE_UP);
		break;
	case MAC_STAT_PROMISC:
		val = mac_stat_get((mac_handle_t)mip, MAC_STAT_PROMISC);
		break;
	case MAC_STAT_LOWLINK_STATE:
		val = mac_stat_get((mac_handle_t)mip, MAC_STAT_LOWLINK_STATE);
		break;
	case MAC_STAT_IFSPEED:
		val = mac_client_ifspeed(mcip);
		break;
	case MAC_STAT_MULTIRCV:
		val = mcip->mci_misc_stat.mms_multircv;
		break;
	case MAC_STAT_BRDCSTRCV:
		val = mcip->mci_misc_stat.mms_brdcstrcv;
		break;
	case MAC_STAT_MULTIXMT:
		val = mcip->mci_misc_stat.mms_multixmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		val = mcip->mci_misc_stat.mms_brdcstxmt;
		break;
	case MAC_STAT_OBYTES:
		val = mac_tx_stat->mts_obytes;
		break;
	case MAC_STAT_OPACKETS:
		val = mac_tx_stat->mts_opackets;
		break;
	case MAC_STAT_OERRORS:
		val = mac_tx_stat->mts_oerrors;
		break;
	case MAC_STAT_IPACKETS:
		for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
			mac_srs = (mac_soft_ring_set_t *)flent->fe_rx_srs[i];
			mac_rx_stat = &mac_srs->srs_rx.sr_stat;
			val += mac_rx_stat->mrs_intrcnt +
			    mac_rx_stat->mrs_pollcnt + mac_rx_stat->mrs_lclcnt;
		}
		break;
	case MAC_STAT_RBYTES:
		for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
			mac_srs = (mac_soft_ring_set_t *)flent->fe_rx_srs[i];
			mac_rx_stat = &mac_srs->srs_rx.sr_stat;
			val += mac_rx_stat->mrs_intrbytes +
			    mac_rx_stat->mrs_pollbytes +
			    mac_rx_stat->mrs_lclbytes;
		}
		break;
	case MAC_STAT_IERRORS:
		for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
			mac_srs = (mac_soft_ring_set_t *)flent->fe_rx_srs[i];
			mac_rx_stat = &mac_srs->srs_rx.sr_stat;
			val += mac_rx_stat->mrs_ierrors;
		}
		break;
	default:
		val = mac_driver_stat_default(mip, stat);
		break;
	}

	return (val);
}

/*
 * Return the statistics of the specified MAC instance.
 */
uint64_t
mac_stat_get(mac_handle_t mh, uint_t stat)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	uint64_t	val;
	int		ret;

	/*
	 * The range of stat determines where it is maintained.  Stat
	 * values from 0 up to (but not including) MAC_STAT_MIN are
	 * mainteined by the mac module itself.  Everything else is
	 * maintained by the driver.
	 *
	 * If the mac_impl_t being queried corresponds to a VNIC,
	 * the stats need to be queried from the lower MAC client
	 * corresponding to the VNIC. (The mac_link_update()
	 * invoked by the driver to the lower MAC causes the *lower
	 * MAC* to update its mi_linkstate, and send a notification
	 * to its MAC clients. Due to the VNIC passthrough,
	 * these notifications are sent to the upper MAC clients
	 * of the VNIC directly, and the upper mac_impl_t of the VNIC
	 * does not have a valid mi_linkstate.
	 */
	if (stat < MAC_STAT_MIN && !(mip->mi_state_flags & MIS_IS_VNIC)) {
		/* these stats are maintained by the mac module itself */
		switch (stat) {
		case MAC_STAT_LINK_STATE:
			return (mip->mi_linkstate);
		case MAC_STAT_LINK_UP:
			return (mip->mi_linkstate == LINK_STATE_UP);
		case MAC_STAT_PROMISC:
			return (mip->mi_devpromisc != 0);
		case MAC_STAT_LOWLINK_STATE:
			return (mip->mi_lowlinkstate);
		default:
			ASSERT(B_FALSE);
		}
	}

	/*
	 * Call the driver to get the given statistic.
	 */
	ret = mip->mi_getstat(mip->mi_driver, stat, &val);
	if (ret != 0) {
		/*
		 * The driver doesn't support this statistic.  Get the
		 * statistic's default value.
		 */
		val = mac_driver_stat_default(mip, stat);
	}
	return (val);
}

/*
 * Query hardware rx ring corresponding to the pseudo ring.
 */
uint64_t
mac_pseudo_rx_ring_stat_get(mac_ring_handle_t handle, uint_t stat)
{
	return (mac_rx_ring_stat_get(handle, stat));
}

/*
 * Query hardware tx ring corresponding to the pseudo ring.
 */
uint64_t
mac_pseudo_tx_ring_stat_get(mac_ring_handle_t handle, uint_t stat)
{
	return (mac_tx_ring_stat_get(handle, stat));
}

/*
 * Utility function which returns the VID associated with a flow entry.
 */
uint16_t
i_mac_flow_vid(flow_entry_t *flent)
{
	flow_desc_t	flow_desc;

	mac_flow_get_desc(flent, &flow_desc);

	if ((flow_desc.fd_mask & FLOW_LINK_VID) != 0)
		return (flow_desc.fd_vid);
	return (VLAN_ID_NONE);
}

/*
 * Verify the validity of the specified unicast MAC address. Returns B_TRUE
 * if the address is valid, B_FALSE otherwise (multicast address, or incorrect
 * length.
 */
boolean_t
mac_unicst_verify(mac_handle_t mh, const uint8_t *addr, uint_t len)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Verify the address. No lock is needed since mi_type and plugin
	 * details don't change after mac_register().
	 */
	if ((len != mip->mi_type->mt_addr_length) ||
	    (mip->mi_type->mt_ops.mtops_unicst_verify(addr,
	    mip->mi_pdata)) != 0) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

void
mac_sdu_get(mac_handle_t mh, uint_t *min_sdu, uint_t *max_sdu)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (min_sdu != NULL)
		*min_sdu = mip->mi_sdu_min;
	if (max_sdu != NULL)
		*max_sdu = mip->mi_sdu_max;
}

void
mac_sdu_get2(mac_handle_t mh, uint_t *min_sdu, uint_t *max_sdu,
    uint_t *multicast_sdu)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (min_sdu != NULL)
		*min_sdu = mip->mi_sdu_min;
	if (max_sdu != NULL)
		*max_sdu = mip->mi_sdu_max;
	if (multicast_sdu != NULL)
		*multicast_sdu = mip->mi_sdu_multicast;
}

/*
 * Update the MAC unicast address of the specified client's flows. Currently
 * only one unicast MAC unicast address is allowed per client.
 */
static void
mac_unicast_update_client_flow(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;
	flow_entry_t *flent = mcip->mci_flent;
	mac_address_t *map = mcip->mci_unicast;
	flow_desc_t flow_desc;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(flent != NULL);

	mac_flow_get_desc(flent, &flow_desc);
	ASSERT(flow_desc.fd_mask & FLOW_LINK_DST);

	bcopy(map->ma_addr, flow_desc.fd_dst_mac, map->ma_len);
	mac_flow_set_desc(flent, &flow_desc);

	/*
	 * The v6 local addr (used by mac protection) needs to be
	 * regenerated because our mac address has changed.
	 */
	mac_protect_update_v6_local_addr(mcip);

	/*
	 * A MAC client could have one MAC address but multiple
	 * VLANs. In that case update the flow entries corresponding
	 * to all VLANs of the MAC client.
	 */
	for (flent = mcip->mci_flent_list; flent != NULL;
	    flent = flent->fe_client_next) {
		mac_flow_get_desc(flent, &flow_desc);
		if (!(flent->fe_type & FLOW_PRIMARY_MAC ||
		    flent->fe_type & FLOW_VNIC_MAC))
			continue;

		bcopy(map->ma_addr, flow_desc.fd_dst_mac, map->ma_len);
		mac_flow_set_desc(flent, &flow_desc);
	}
}

/*
 * Update all clients that share the same unicast address.
 */
void
mac_unicast_update_clients(mac_impl_t *mip, mac_address_t *map)
{
	mac_client_impl_t *mcip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/*
	 * Find all clients that share the same unicast MAC address and update
	 * them appropriately.
	 */
	for (mcip = mip->mi_clients_list; mcip != NULL;
	    mcip = mcip->mci_client_next) {
		/*
		 * Ignore clients that don't share this MAC address.
		 */
		if (map != mcip->mci_unicast)
			continue;

		/*
		 * Update those clients with same old unicast MAC address.
		 */
		mac_unicast_update_client_flow(mcip);
	}
}

/*
 * Update the unicast MAC address of the specified VNIC MAC client.
 *
 * Check whether the operation is valid. Any of following cases should fail:
 *
 * 1. It's a VLAN type of VNIC.
 * 2. The new value is current "primary" MAC address.
 * 3. The current MAC address is shared with other clients.
 * 4. The new MAC address has been used. This case will be valid when
 *    client migration is fully supported.
 */
int
mac_vnic_unicast_set(mac_client_handle_t mch, const uint8_t *addr)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	mac_address_t *map = mcip->mci_unicast;
	int err;

	ASSERT(!(mip->mi_state_flags & MIS_IS_VNIC));
	ASSERT(mcip->mci_state_flags & MCIS_IS_VNIC);
	ASSERT(mcip->mci_flags != MAC_CLIENT_FLAGS_PRIMARY);

	i_mac_perim_enter(mip);

	/*
	 * If this is a VLAN type of VNIC, it's using "primary" MAC address
	 * of the underlying interface. Must fail here. Refer to case 1 above.
	 */
	if (bcmp(map->ma_addr, mip->mi_addr, map->ma_len) == 0) {
		i_mac_perim_exit(mip);
		return (ENOTSUP);
	}

	/*
	 * If the new address is the "primary" one, must fail. Refer to
	 * case 2 above.
	 */
	if (bcmp(addr, mip->mi_addr, map->ma_len) == 0) {
		i_mac_perim_exit(mip);
		return (EACCES);
	}

	/*
	 * If the address is shared by multiple clients, must fail. Refer
	 * to case 3 above.
	 */
	if (mac_check_macaddr_shared(map)) {
		i_mac_perim_exit(mip);
		return (EBUSY);
	}

	/*
	 * If the new address has been used, must fail for now. Refer to
	 * case 4 above.
	 */
	if (mac_find_macaddr(mip, (uint8_t *)addr) != NULL) {
		i_mac_perim_exit(mip);
		return (ENOTSUP);
	}

	/*
	 * Update the MAC address.
	 */
	err = mac_update_macaddr(map, (uint8_t *)addr);

	if (err != 0) {
		i_mac_perim_exit(mip);
		return (err);
	}

	/*
	 * Update all flows of this MAC client.
	 */
	mac_unicast_update_client_flow(mcip);

	i_mac_perim_exit(mip);
	return (0);
}

/*
 * Program the new primary unicast address of the specified MAC.
 *
 * Function mac_update_macaddr() takes care different types of underlying
 * MAC. If the underlying MAC is VNIC, the VNIC driver must have registerd
 * mi_unicst() entry point, that indirectly calls mac_vnic_unicast_set()
 * which will take care of updating the MAC address of the corresponding
 * MAC client.
 *
 * This is the only interface that allow the client to update the "primary"
 * MAC address of the underlying MAC. The new value must have not been
 * used by other clients.
 */
int
mac_unicast_primary_set(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	mac_address_t *map;
	int err;

	/* verify the address validity */
	if (!mac_unicst_verify(mh, addr, mip->mi_type->mt_addr_length))
		return (EINVAL);

	i_mac_perim_enter(mip);

	/*
	 * If the new value is the same as the current primary address value,
	 * there's nothing to do.
	 */
	if (bcmp(addr, mip->mi_addr, mip->mi_type->mt_addr_length) == 0) {
		i_mac_perim_exit(mip);
		return (0);
	}

	if (mac_find_macaddr(mip, (uint8_t *)addr) != 0) {
		i_mac_perim_exit(mip);
		return (EBUSY);
	}

	map = mac_find_macaddr(mip, mip->mi_addr);
	ASSERT(map != NULL);

	/*
	 * Update the MAC address.
	 */
	if (mip->mi_state_flags & MIS_IS_AGGR) {
		mac_capab_aggr_t aggr_cap;

		/*
		 * If the mac is an aggregation, other than the unicast
		 * addresses programming, aggr must be informed about this
		 * primary unicst address change to change its mac address
		 * policy to be user-specified.
		 */
		ASSERT(map->ma_type == MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED);
		VERIFY(i_mac_capab_get(mh, MAC_CAPAB_AGGR, &aggr_cap));
		err = aggr_cap.mca_unicst(mip->mi_driver, addr);
		if (err == 0)
			bcopy(addr, map->ma_addr, map->ma_len);
	} else {
		err = mac_update_macaddr(map, (uint8_t *)addr);
	}

	if (err != 0) {
		i_mac_perim_exit(mip);
		return (err);
	}

	mac_unicast_update_clients(mip, map);

	/*
	 * Save the new primary MAC address in mac_impl_t.
	 */
	bcopy(addr, mip->mi_addr, mip->mi_type->mt_addr_length);

	i_mac_perim_exit(mip);

	if (err == 0)
		i_mac_notify(mip, MAC_NOTE_UNICST);

	return (err);
}

/*
 * Return the current primary MAC address of the specified MAC.
 */
void
mac_unicast_primary_get(mac_handle_t mh, uint8_t *addr)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	rw_enter(&mip->mi_rw_lock, RW_READER);
	bcopy(mip->mi_addr, addr, mip->mi_type->mt_addr_length);
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Return the secondary MAC address for the specified handle
 */
void
mac_unicast_secondary_get(mac_client_handle_t mh, uint8_t *addr)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mh;

	ASSERT(mcip->mci_unicast != NULL);
	bcopy(mcip->mci_unicast->ma_addr, addr, mcip->mci_unicast->ma_len);
}

/*
 * Return information about the use of the primary MAC address of the
 * specified MAC instance:
 *
 * - if client_name is non-NULL, it must point to a string of at
 *   least MAXNAMELEN bytes, and will be set to the name of the MAC
 *   client which uses the primary MAC address.
 *
 * - if in_use is non-NULL, used to return whether the primary MAC
 *   address is currently in use.
 */
void
mac_unicast_primary_info(mac_handle_t mh, char *client_name, boolean_t *in_use)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	mac_client_impl_t *cur_client;

	if (in_use != NULL)
		*in_use = B_FALSE;
	if (client_name != NULL)
		bzero(client_name, MAXNAMELEN);

	/*
	 * The mi_rw_lock is used to protect threads that don't hold the
	 * mac perimeter to get a consistent view of the mi_clients_list.
	 * Threads that modify the list must hold both the mac perimeter and
	 * mi_rw_lock(RW_WRITER)
	 */
	rw_enter(&mip->mi_rw_lock, RW_READER);
	for (cur_client = mip->mi_clients_list; cur_client != NULL;
	    cur_client = cur_client->mci_client_next) {
		if (mac_is_primary_client(cur_client) ||
		    (mip->mi_state_flags & MIS_IS_VNIC)) {
			rw_exit(&mip->mi_rw_lock);
			if (in_use != NULL)
				*in_use = B_TRUE;
			if (client_name != NULL) {
				bcopy(cur_client->mci_name, client_name,
				    MAXNAMELEN);
			}
			return;
		}
	}
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Return the current destination MAC address of the specified MAC.
 */
boolean_t
mac_dst_get(mac_handle_t mh, uint8_t *addr)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	rw_enter(&mip->mi_rw_lock, RW_READER);
	if (mip->mi_dstaddr_set)
		bcopy(mip->mi_dstaddr, addr, mip->mi_type->mt_addr_length);
	rw_exit(&mip->mi_rw_lock);
	return (mip->mi_dstaddr_set);
}

/*
 * Add the specified MAC client to the list of clients which opened
 * the specified MAC.
 */
static void
mac_client_add(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/* add VNIC to the front of the list */
	rw_enter(&mip->mi_rw_lock, RW_WRITER);
	mcip->mci_client_next = mip->mi_clients_list;
	mip->mi_clients_list = mcip;
	mip->mi_nclients++;
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Remove the specified MAC client from the list of clients which opened
 * the specified MAC.
 */
static void
mac_client_remove(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;
	mac_client_impl_t **prev, *cclient;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	rw_enter(&mip->mi_rw_lock, RW_WRITER);
	prev = &mip->mi_clients_list;
	cclient = *prev;
	while (cclient != NULL && cclient != mcip) {
		prev = &cclient->mci_client_next;
		cclient = *prev;
	}
	ASSERT(cclient != NULL);
	*prev = cclient->mci_client_next;
	mip->mi_nclients--;
	rw_exit(&mip->mi_rw_lock);
}

static mac_unicast_impl_t *
mac_client_find_vid(mac_client_impl_t *mcip, uint16_t vid)
{
	mac_unicast_impl_t *muip = mcip->mci_unicast_list;

	while ((muip != NULL) && (muip->mui_vid != vid))
		muip = muip->mui_next;

	return (muip);
}

/*
 * Return whether the specified (MAC address, VID) tuple is already used by
 * one of the MAC clients associated with the specified MAC.
 */
static boolean_t
mac_addr_in_use(mac_impl_t *mip, uint8_t *mac_addr, uint16_t vid)
{
	mac_client_impl_t *client;
	mac_address_t *map;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	for (client = mip->mi_clients_list; client != NULL;
	    client = client->mci_client_next) {

		/*
		 * Ignore clients that don't have unicast address.
		 */
		if (client->mci_unicast_list == NULL)
			continue;

		map = client->mci_unicast;

		if ((bcmp(mac_addr, map->ma_addr, map->ma_len) == 0) &&
		    (mac_client_find_vid(client, vid) != NULL)) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Generate a random MAC address. The MAC address prefix is
 * stored in the array pointed to by mac_addr, and its length, in bytes,
 * is specified by prefix_len. The least significant bits
 * after prefix_len bytes are generated, and stored after the prefix
 * in the mac_addr array.
 */
int
mac_addr_random(mac_client_handle_t mch, uint_t prefix_len,
    uint8_t *mac_addr, mac_diag_t *diag)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	size_t addr_len = mip->mi_type->mt_addr_length;

	if (prefix_len >= addr_len) {
		*diag = MAC_DIAG_MACPREFIXLEN_INVALID;
		return (EINVAL);
	}

	/* check the prefix value */
	if (prefix_len > 0) {
		bzero(mac_addr + prefix_len, addr_len - prefix_len);
		if (!mac_unicst_verify((mac_handle_t)mip, mac_addr,
		    addr_len)) {
			*diag = MAC_DIAG_MACPREFIX_INVALID;
			return (EINVAL);
		}
	}

	/* generate the MAC address */
	if (prefix_len < addr_len) {
		(void) random_get_pseudo_bytes(mac_addr +
		    prefix_len, addr_len - prefix_len);
	}

	*diag = 0;
	return (0);
}

/*
 * Set the priority range for this MAC client. This will be used to
 * determine the absolute priority for the threads created for this
 * MAC client using the specified "low", "medium" and "high" level.
 * This will also be used for any subflows on this MAC client.
 */
#define	MAC_CLIENT_SET_PRIORITY_RANGE(mcip, pri) {			\
	(mcip)->mci_min_pri = FLOW_MIN_PRIORITY(MINCLSYSPRI,	\
	    MAXCLSYSPRI, (pri));					\
	(mcip)->mci_max_pri = FLOW_MAX_PRIORITY(MINCLSYSPRI,	\
	    MAXCLSYSPRI, (mcip)->mci_min_pri);				\
	}

/*
 * MAC client open entry point. Return a new MAC client handle. Each
 * MAC client is associated with a name, specified through the 'name'
 * argument.
 */
int
mac_client_open(mac_handle_t mh, mac_client_handle_t *mchp, char *name,
    uint16_t flags)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_client_impl_t	*mcip;
	int			err = 0;
	boolean_t		share_desired;
	flow_entry_t		*flent = NULL;

	share_desired = (flags & MAC_OPEN_FLAGS_SHARES_DESIRED) != 0;
	*mchp = NULL;

	i_mac_perim_enter(mip);

	if (mip->mi_state_flags & MIS_IS_VNIC) {
		/*
		 * The underlying MAC is a VNIC. Return the MAC client
		 * handle of the lower MAC which was obtained by
		 * the VNIC driver when it did its mac_client_open().
		 */

		mcip = mac_vnic_lower(mip);

		/*
		 * Note that multiple mac clients share the same mcip in
		 * this case.
		 */
		if (flags & MAC_OPEN_FLAGS_EXCLUSIVE)
			mcip->mci_state_flags |= MCIS_EXCLUSIVE;

		if (flags & MAC_OPEN_FLAGS_MULTI_PRIMARY)
			mcip->mci_flags |= MAC_CLIENT_FLAGS_MULTI_PRIMARY;

		mip->mi_clients_list = mcip;
		i_mac_perim_exit(mip);
		*mchp = (mac_client_handle_t)mcip;

		DTRACE_PROBE2(mac__client__open__nonallocated, mac_impl_t *,
		    mcip->mci_mip, mac_client_impl_t *, mcip);

		return (err);
	}

	mcip = kmem_cache_alloc(mac_client_impl_cache, KM_SLEEP);

	mcip->mci_mip = mip;
	mcip->mci_upper_mip = NULL;
	mcip->mci_rx_fn = mac_pkt_drop;
	mcip->mci_rx_arg = NULL;
	mcip->mci_rx_p_fn = NULL;
	mcip->mci_rx_p_arg = NULL;
	mcip->mci_p_unicast_list = NULL;
	mcip->mci_direct_rx_fn = NULL;
	mcip->mci_direct_rx_arg = NULL;
	mcip->mci_vidcache = MCIP_VIDCACHE_INVALID;

	mcip->mci_unicast_list = NULL;

	if ((flags & MAC_OPEN_FLAGS_IS_VNIC) != 0)
		mcip->mci_state_flags |= MCIS_IS_VNIC;

	if ((flags & MAC_OPEN_FLAGS_EXCLUSIVE) != 0)
		mcip->mci_state_flags |= MCIS_EXCLUSIVE;

	if ((flags & MAC_OPEN_FLAGS_IS_AGGR_PORT) != 0)
		mcip->mci_state_flags |= MCIS_IS_AGGR_PORT;

	if (mip->mi_state_flags & MIS_IS_AGGR)
		mcip->mci_state_flags |= MCIS_IS_AGGR;

	if ((flags & MAC_OPEN_FLAGS_USE_DATALINK_NAME) != 0) {
		datalink_id_t	linkid;

		ASSERT(name == NULL);
		if ((err = dls_devnet_macname2linkid(mip->mi_name,
		    &linkid)) != 0) {
			goto done;
		}
		if ((err = dls_mgmt_get_linkinfo(linkid, mcip->mci_name, NULL,
		    NULL, NULL)) != 0) {
			/*
			 * Use mac name if dlmgmtd is not available.
			 */
			if (err == EBADF) {
				(void) strlcpy(mcip->mci_name, mip->mi_name,
				    sizeof (mcip->mci_name));
				err = 0;
			} else {
				goto done;
			}
		}
		mcip->mci_state_flags |= MCIS_USE_DATALINK_NAME;
	} else {
		ASSERT(name != NULL);
		if (strlen(name) > MAXNAMELEN) {
			err = EINVAL;
			goto done;
		}
		(void) strlcpy(mcip->mci_name, name, sizeof (mcip->mci_name));
	}

	if (flags & MAC_OPEN_FLAGS_MULTI_PRIMARY)
		mcip->mci_flags |= MAC_CLIENT_FLAGS_MULTI_PRIMARY;

	if (flags & MAC_OPEN_FLAGS_NO_UNICAST_ADDR)
		mcip->mci_state_flags |= MCIS_NO_UNICAST_ADDR;

	mac_protect_init(mcip);

	/* the subflow table will be created dynamically */
	mcip->mci_subflow_tab = NULL;

	mcip->mci_misc_stat.mms_multircv = 0;
	mcip->mci_misc_stat.mms_brdcstrcv = 0;
	mcip->mci_misc_stat.mms_multixmt = 0;
	mcip->mci_misc_stat.mms_brdcstxmt = 0;

	/* Create an initial flow */

	err = mac_flow_create(NULL, NULL, mcip->mci_name, NULL,
	    mcip->mci_state_flags & MCIS_IS_VNIC ? FLOW_VNIC_MAC :
	    FLOW_PRIMARY_MAC, &flent);
	if (err != 0)
		goto done;
	mcip->mci_flent = flent;
	FLOW_MARK(flent, FE_MC_NO_DATAPATH);
	flent->fe_mcip = mcip;
	/*
	 * Place initial creation reference on the flow. This reference
	 * is released in the corresponding delete action viz.
	 * mac_unicast_remove after waiting for all transient refs to
	 * to go away. The wait happens in mac_flow_wait.
	 */
	FLOW_REFHOLD(flent);

	/*
	 * Do this ahead of the mac_bcast_add() below so that the mi_nclients
	 * will have the right value for mac_rx_srs_setup().
	 */
	mac_client_add(mcip);

	mcip->mci_share = NULL;
	if (share_desired)
		i_mac_share_alloc(mcip);

	/*
	 * We will do mimimal datapath setup to allow a MAC client to
	 * transmit or receive non-unicast packets without waiting
	 * for mac_unicast_add.
	 */
	if (mcip->mci_state_flags & MCIS_NO_UNICAST_ADDR) {
		if ((err = mac_client_datapath_setup(mcip, VLAN_ID_NONE,
		    NULL, NULL, B_TRUE, NULL)) != 0) {
			goto done;
		}
	}

	DTRACE_PROBE2(mac__client__open__allocated, mac_impl_t *,
	    mcip->mci_mip, mac_client_impl_t *, mcip);

	*mchp = (mac_client_handle_t)mcip;
	i_mac_perim_exit(mip);
	return (0);

done:
	i_mac_perim_exit(mip);
	mcip->mci_state_flags = 0;
	mcip->mci_tx_flag = 0;
	kmem_cache_free(mac_client_impl_cache, mcip);
	return (err);
}

/*
 * Close the specified MAC client handle.
 */
void
mac_client_close(mac_client_handle_t mch, uint16_t flags)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	flow_entry_t		*flent;

	i_mac_perim_enter(mip);

	if (flags & MAC_CLOSE_FLAGS_EXCLUSIVE)
		mcip->mci_state_flags &= ~MCIS_EXCLUSIVE;

	if ((mcip->mci_state_flags & MCIS_IS_VNIC) &&
	    !(flags & MAC_CLOSE_FLAGS_IS_VNIC)) {
		/*
		 * This is an upper VNIC client initiated operation.
		 * The lower MAC client will be closed by the VNIC driver
		 * when the VNIC is deleted.
		 */

		i_mac_perim_exit(mip);
		return;
	}

	/* If we have only setup up minimal datapth setup, tear it down */
	if (mcip->mci_state_flags & MCIS_NO_UNICAST_ADDR) {
		mac_client_datapath_teardown((mac_client_handle_t)mcip, NULL,
		    mcip->mci_flent);
		mcip->mci_state_flags &= ~MCIS_NO_UNICAST_ADDR;
	}

	/*
	 * Remove the flent associated with the MAC client
	 */
	flent = mcip->mci_flent;
	mcip->mci_flent = NULL;
	FLOW_FINAL_REFRELE(flent);

	/*
	 * MAC clients must remove the unicast addresses and promisc callbacks
	 * they added before issuing a mac_client_close().
	 */
	ASSERT(mcip->mci_unicast_list == NULL);
	ASSERT(mcip->mci_promisc_list == NULL);
	ASSERT(mcip->mci_tx_notify_cb_list == NULL);

	i_mac_share_free(mcip);
	mac_protect_fini(mcip);
	mac_client_remove(mcip);

	i_mac_perim_exit(mip);
	mcip->mci_subflow_tab = NULL;
	mcip->mci_state_flags = 0;
	mcip->mci_tx_flag = 0;
	kmem_cache_free(mac_client_impl_cache, mch);
}

/*
 * Set the rx bypass receive callback.
 */
boolean_t
mac_rx_bypass_set(mac_client_handle_t mch, mac_direct_rx_t rx_fn, void *arg1)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/*
	 * If the mac_client is a VLAN, we should not do DLS bypass and
	 * instead let the packets come up via mac_rx_deliver so the vlan
	 * header can be stripped.
	 */
	if (mcip->mci_nvids > 0)
		return (B_FALSE);

	/*
	 * These are not accessed directly in the data path, and hence
	 * don't need any protection
	 */
	mcip->mci_direct_rx_fn = rx_fn;
	mcip->mci_direct_rx_arg = arg1;
	return (B_TRUE);
}

/*
 * Enable/Disable rx bypass. By default, bypass is assumed to be enabled.
 */
void
mac_rx_bypass_enable(mac_client_handle_t mch)
{
	((mac_client_impl_t *)mch)->mci_state_flags &= ~MCIS_RX_BYPASS_DISABLE;
}

void
mac_rx_bypass_disable(mac_client_handle_t mch)
{
	((mac_client_impl_t *)mch)->mci_state_flags |= MCIS_RX_BYPASS_DISABLE;
}

/*
 * Set the receive callback for the specified MAC client. There can be
 * at most one such callback per MAC client.
 */
void
mac_rx_set(mac_client_handle_t mch, mac_rx_t rx_fn, void *arg)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t	*mip = mcip->mci_mip;
	mac_impl_t	*umip = mcip->mci_upper_mip;

	/*
	 * Instead of adding an extra set of locks and refcnts in
	 * the datapath at the mac client boundary, we temporarily quiesce
	 * the SRS and related entities. We then change the receive function
	 * without interference from any receive data thread and then reenable
	 * the data flow subsequently.
	 */
	i_mac_perim_enter(mip);
	mac_rx_client_quiesce(mch);

	mcip->mci_rx_fn = rx_fn;
	mcip->mci_rx_arg = arg;
	mac_rx_client_restart(mch);
	i_mac_perim_exit(mip);

	/*
	 * If we're changing the rx function on the primary mac of a vnic,
	 * make sure any secondary macs on the vnic are updated as well.
	 */
	if (umip != NULL) {
		ASSERT((umip->mi_state_flags & MIS_IS_VNIC) != 0);
		mac_vnic_secondary_update(umip);
	}
}

/*
 * Reset the receive callback for the specified MAC client.
 */
void
mac_rx_clear(mac_client_handle_t mch)
{
	mac_rx_set(mch, mac_pkt_drop, NULL);
}

void
mac_secondary_dup(mac_client_handle_t smch, mac_client_handle_t dmch)
{
	mac_client_impl_t *smcip = (mac_client_impl_t *)smch;
	mac_client_impl_t *dmcip = (mac_client_impl_t *)dmch;
	flow_entry_t *flent = dmcip->mci_flent;

	/* This should only be called to setup secondary macs */
	ASSERT((flent->fe_type & FLOW_PRIMARY_MAC) == 0);

	mac_rx_set(dmch, smcip->mci_rx_fn, smcip->mci_rx_arg);
	dmcip->mci_promisc_list = smcip->mci_promisc_list;

	/*
	 * Duplicate the primary mac resources to the secondary.
	 * Since we already validated the resource controls when setting
	 * them on the primary, we can ignore errors here.
	 */
	(void) mac_resource_ctl_set(dmch, MCIP_RESOURCE_PROPS(smcip));
}

/*
 * Called when removing a secondary MAC. Currently only clears the promisc_list
 * since we share the primary mac's promisc_list.
 */
void
mac_secondary_cleanup(mac_client_handle_t mch)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	flow_entry_t *flent = mcip->mci_flent;

	/* This should only be called for secondary macs */
	ASSERT((flent->fe_type & FLOW_PRIMARY_MAC) == 0);
	mcip->mci_promisc_list = NULL;
}

/*
 * Walk the MAC client subflow table and updates their priority values.
 */
static int
mac_update_subflow_priority_cb(flow_entry_t *flent, void *arg)
{
	mac_flow_update_priority(arg, flent);
	return (0);
}

void
mac_update_subflow_priority(mac_client_impl_t *mcip)
{
	(void) mac_flow_walk(mcip->mci_subflow_tab,
	    mac_update_subflow_priority_cb, mcip);
}

/*
 * Modify the TX or RX ring properties. We could either just move around
 * rings, i.e add/remove rings given to a client. Or this might cause the
 * client to move from hardware based to software or the other way around.
 * If we want to reset this property, then we clear the mask, additionally
 * if the client was given a non-default group we remove all rings except
 * for 1 and give it back to the default group.
 */
int
mac_client_set_rings_prop(mac_client_impl_t *mcip, mac_resource_props_t *mrp,
    mac_resource_props_t *tmrp)
{
	mac_impl_t		*mip = mcip->mci_mip;
	flow_entry_t		*flent = mcip->mci_flent;
	uint8_t			*mac_addr;
	int			err = 0;
	mac_group_t		*defgrp;
	mac_group_t		*group;
	mac_group_t		*ngrp;
	mac_resource_props_t	*cmrp = MCIP_RESOURCE_PROPS(mcip);
	uint_t			ringcnt;
	boolean_t		unspec;

	if (mcip->mci_share != NULL)
		return (EINVAL);

	if (mrp->mrp_mask & MRP_RX_RINGS) {
		unspec = mrp->mrp_mask & MRP_RXRINGS_UNSPEC;
		group = flent->fe_rx_ring_group;
		defgrp = MAC_DEFAULT_RX_GROUP(mip);
		mac_addr = flent->fe_flow_desc.fd_dst_mac;

		/*
		 * No resulting change. If we are resetting on a client on
		 * which there was no rx rings property. For dynamic group
		 * if we are setting the same number of rings already set.
		 * For static group if we are requesting a group again.
		 */
		if (mrp->mrp_mask & MRP_RINGS_RESET) {
			if (!(tmrp->mrp_mask & MRP_RX_RINGS))
				return (0);
		} else {
			if (unspec) {
				if (tmrp->mrp_mask & MRP_RXRINGS_UNSPEC)
					return (0);
			} else if (mip->mi_rx_group_type ==
			    MAC_GROUP_TYPE_DYNAMIC) {
				if ((tmrp->mrp_mask & MRP_RX_RINGS) &&
				    !(tmrp->mrp_mask & MRP_RXRINGS_UNSPEC) &&
				    mrp->mrp_nrxrings == tmrp->mrp_nrxrings) {
					return (0);
				}
			}
		}
		/* Resetting the prop */
		if (mrp->mrp_mask & MRP_RINGS_RESET) {
			/*
			 * We will just keep one ring and give others back if
			 * we are not the primary. For the primary we give
			 * all the rings in the default group except the
			 * default ring. If it is a static group, then
			 * we don't do anything, but clear the MRP_RX_RINGS
			 * flag.
			 */
			if (group != defgrp) {
				if (mip->mi_rx_group_type ==
				    MAC_GROUP_TYPE_DYNAMIC) {
					/*
					 * This group has reserved rings
					 * that need to be released now,
					 * so does the group.
					 */
					MAC_RX_RING_RELEASED(mip,
					    group->mrg_cur_count);
					MAC_RX_GRP_RELEASED(mip);
					if ((flent->fe_type &
					    FLOW_PRIMARY_MAC) != 0) {
						if (mip->mi_nactiveclients ==
						    1) {
							(void)
							    mac_rx_switch_group(
							    mcip, group,
							    defgrp);
							return (0);
						} else {
							cmrp->mrp_nrxrings =
							    group->
							    mrg_cur_count +
							    defgrp->
							    mrg_cur_count - 1;
						}
					} else {
						cmrp->mrp_nrxrings = 1;
					}
					(void) mac_group_ring_modify(mcip,
					    group, defgrp);
				} else {
					/*
					 * If this is a static group, we
					 * need to release the group. The
					 * client will remain in the same
					 * group till some other client
					 * needs this group.
					 */
					MAC_RX_GRP_RELEASED(mip);
				}
			/* Let check if we can give this an excl group */
			} else if (group == defgrp) {
				ngrp = 	mac_reserve_rx_group(mcip, mac_addr,
				    B_TRUE);
				/* Couldn't give it a group, that's fine */
				if (ngrp == NULL)
					return (0);
				/* Switch to H/W */
				if (mac_rx_switch_group(mcip, defgrp, ngrp) !=
				    0) {
					mac_stop_group(ngrp);
					return (0);
				}
			}
			/*
			 * If the client is in the default group, we will
			 * just clear the MRP_RX_RINGS and leave it as
			 * it rather than look for an exclusive group
			 * for it.
			 */
			return (0);
		}

		if (group == defgrp && ((mrp->mrp_nrxrings > 0) || unspec)) {
			ngrp = 	mac_reserve_rx_group(mcip, mac_addr, B_TRUE);
			if (ngrp == NULL)
				return (ENOSPC);

			/* Switch to H/W */
			if (mac_rx_switch_group(mcip, defgrp, ngrp) != 0) {
				mac_release_rx_group(mcip, ngrp);
				return (ENOSPC);
			}
			MAC_RX_GRP_RESERVED(mip);
			if (mip->mi_rx_group_type == MAC_GROUP_TYPE_DYNAMIC)
				MAC_RX_RING_RESERVED(mip, ngrp->mrg_cur_count);
		} else if (group != defgrp && !unspec &&
		    mrp->mrp_nrxrings == 0) {
			/* Switch to S/W */
			ringcnt = group->mrg_cur_count;
			if (mac_rx_switch_group(mcip, group, defgrp) != 0)
				return (ENOSPC);
			if (tmrp->mrp_mask & MRP_RX_RINGS) {
				MAC_RX_GRP_RELEASED(mip);
				if (mip->mi_rx_group_type ==
				    MAC_GROUP_TYPE_DYNAMIC) {
					MAC_RX_RING_RELEASED(mip, ringcnt);
				}
			}
		} else if (group != defgrp && mip->mi_rx_group_type ==
		    MAC_GROUP_TYPE_DYNAMIC) {
			ringcnt = group->mrg_cur_count;
			err = mac_group_ring_modify(mcip, group, defgrp);
			if (err != 0)
				return (err);
			/*
			 * Update the accounting. If this group
			 * already had explicitly reserved rings,
			 * we need to update the rings based on
			 * the new ring count. If this group
			 * had not explicitly reserved rings,
			 * then we just reserve the rings asked for
			 * and reserve the group.
			 */
			if (tmrp->mrp_mask & MRP_RX_RINGS) {
				if (ringcnt > group->mrg_cur_count) {
					MAC_RX_RING_RELEASED(mip,
					    ringcnt - group->mrg_cur_count);
				} else {
					MAC_RX_RING_RESERVED(mip,
					    group->mrg_cur_count - ringcnt);
				}
			} else {
				MAC_RX_RING_RESERVED(mip, group->mrg_cur_count);
				MAC_RX_GRP_RESERVED(mip);
			}
		}
	}
	if (mrp->mrp_mask & MRP_TX_RINGS) {
		unspec = mrp->mrp_mask & MRP_TXRINGS_UNSPEC;
		group = flent->fe_tx_ring_group;
		defgrp = MAC_DEFAULT_TX_GROUP(mip);

		/*
		 * For static groups we only allow rings=0 or resetting the
		 * rings property.
		 */
		if (mrp->mrp_ntxrings > 0 &&
		    mip->mi_tx_group_type != MAC_GROUP_TYPE_DYNAMIC) {
			return (ENOTSUP);
		}
		if (mrp->mrp_mask & MRP_RINGS_RESET) {
			if (!(tmrp->mrp_mask & MRP_TX_RINGS))
				return (0);
		} else {
			if (unspec) {
				if (tmrp->mrp_mask & MRP_TXRINGS_UNSPEC)
					return (0);
			} else if (mip->mi_tx_group_type ==
			    MAC_GROUP_TYPE_DYNAMIC) {
				if ((tmrp->mrp_mask & MRP_TX_RINGS) &&
				    !(tmrp->mrp_mask & MRP_TXRINGS_UNSPEC) &&
				    mrp->mrp_ntxrings == tmrp->mrp_ntxrings) {
					return (0);
				}
			}
		}
		/* Resetting the prop */
		if (mrp->mrp_mask & MRP_RINGS_RESET) {
			if (group != defgrp) {
				if (mip->mi_tx_group_type ==
				    MAC_GROUP_TYPE_DYNAMIC) {
					ringcnt = group->mrg_cur_count;
					if ((flent->fe_type &
					    FLOW_PRIMARY_MAC) != 0) {
						mac_tx_client_quiesce(
						    (mac_client_handle_t)
						    mcip);
						mac_tx_switch_group(mcip,
						    group, defgrp);
						mac_tx_client_restart(
						    (mac_client_handle_t)
						    mcip);
						MAC_TX_GRP_RELEASED(mip);
						MAC_TX_RING_RELEASED(mip,
						    ringcnt);
						return (0);
					}
					cmrp->mrp_ntxrings = 1;
					(void) mac_group_ring_modify(mcip,
					    group, defgrp);
					/*
					 * This group has reserved rings
					 * that need to be released now.
					 */
					MAC_TX_RING_RELEASED(mip, ringcnt);
				}
				/*
				 * If this is a static group, we
				 * need to release the group. The
				 * client will remain in the same
				 * group till some other client
				 * needs this group.
				 */
				MAC_TX_GRP_RELEASED(mip);
			} else if (group == defgrp &&
			    (flent->fe_type & FLOW_PRIMARY_MAC) == 0) {
				ngrp = mac_reserve_tx_group(mcip, B_TRUE);
				if (ngrp == NULL)
					return (0);
				mac_tx_client_quiesce(
				    (mac_client_handle_t)mcip);
				mac_tx_switch_group(mcip, defgrp, ngrp);
				mac_tx_client_restart(
				    (mac_client_handle_t)mcip);
			}
			/*
			 * If the client is in the default group, we will
			 * just clear the MRP_TX_RINGS and leave it as
			 * it rather than look for an exclusive group
			 * for it.
			 */
			return (0);
		}

		/* Switch to H/W */
		if (group == defgrp && ((mrp->mrp_ntxrings > 0) || unspec)) {
			ngrp = 	mac_reserve_tx_group(mcip, B_TRUE);
			if (ngrp == NULL)
				return (ENOSPC);
			mac_tx_client_quiesce((mac_client_handle_t)mcip);
			mac_tx_switch_group(mcip, defgrp, ngrp);
			mac_tx_client_restart((mac_client_handle_t)mcip);
			MAC_TX_GRP_RESERVED(mip);
			if (mip->mi_tx_group_type == MAC_GROUP_TYPE_DYNAMIC)
				MAC_TX_RING_RESERVED(mip, ngrp->mrg_cur_count);
		/* Switch to S/W */
		} else if (group != defgrp && !unspec &&
		    mrp->mrp_ntxrings == 0) {
			/* Switch to S/W */
			ringcnt = group->mrg_cur_count;
			mac_tx_client_quiesce((mac_client_handle_t)mcip);
			mac_tx_switch_group(mcip, group, defgrp);
			mac_tx_client_restart((mac_client_handle_t)mcip);
			if (tmrp->mrp_mask & MRP_TX_RINGS) {
				MAC_TX_GRP_RELEASED(mip);
				if (mip->mi_tx_group_type ==
				    MAC_GROUP_TYPE_DYNAMIC) {
					MAC_TX_RING_RELEASED(mip, ringcnt);
				}
			}
		} else if (group != defgrp && mip->mi_tx_group_type ==
		    MAC_GROUP_TYPE_DYNAMIC) {
			ringcnt = group->mrg_cur_count;
			err = mac_group_ring_modify(mcip, group, defgrp);
			if (err != 0)
				return (err);
			/*
			 * Update the accounting. If this group
			 * already had explicitly reserved rings,
			 * we need to update the rings based on
			 * the new ring count. If this group
			 * had not explicitly reserved rings,
			 * then we just reserve the rings asked for
			 * and reserve the group.
			 */
			if (tmrp->mrp_mask & MRP_TX_RINGS) {
				if (ringcnt > group->mrg_cur_count) {
					MAC_TX_RING_RELEASED(mip,
					    ringcnt - group->mrg_cur_count);
				} else {
					MAC_TX_RING_RESERVED(mip,
					    group->mrg_cur_count - ringcnt);
				}
			} else {
				MAC_TX_RING_RESERVED(mip, group->mrg_cur_count);
				MAC_TX_GRP_RESERVED(mip);
			}
		}
	}
	return (0);
}

/*
 * When the MAC client is being brought up (i.e. we do a unicast_add) we need
 * to initialize the cpu and resource control structure in the
 * mac_client_impl_t from the mac_impl_t (i.e if there are any cached
 * properties before the flow entry for the unicast address was created).
 */
static int
mac_resource_ctl_set(mac_client_handle_t mch, mac_resource_props_t *mrp)
{
	mac_client_impl_t 	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = (mac_impl_t *)mcip->mci_mip;
	mac_impl_t		*umip = mcip->mci_upper_mip;
	int			err = 0;
	flow_entry_t		*flent = mcip->mci_flent;
	mac_resource_props_t	*omrp, *nmrp = MCIP_RESOURCE_PROPS(mcip);

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	err = mac_validate_props(mcip->mci_state_flags & MCIS_IS_VNIC ?
	    mcip->mci_upper_mip : mip, mrp);
	if (err != 0)
		return (err);

	/*
	 * Copy over the existing properties since mac_update_resources
	 * will modify the client's mrp. Currently, the saved property
	 * is used to determine the difference between existing and
	 * modified rings property.
	 */
	omrp = kmem_zalloc(sizeof (*omrp), KM_SLEEP);
	bcopy(nmrp, omrp, sizeof (*omrp));
	mac_update_resources(mrp, MCIP_RESOURCE_PROPS(mcip), B_FALSE);
	if (MCIP_DATAPATH_SETUP(mcip)) {
		/*
		 * We support rings only for primary client when there are
		 * multiple clients sharing the same MAC address (e.g. VLAN).
		 */
		if (mrp->mrp_mask & MRP_RX_RINGS ||
		    mrp->mrp_mask & MRP_TX_RINGS) {

			if ((err = mac_client_set_rings_prop(mcip, mrp,
			    omrp)) != 0) {
				if (omrp->mrp_mask & MRP_RX_RINGS) {
					nmrp->mrp_mask |= MRP_RX_RINGS;
					nmrp->mrp_nrxrings = omrp->mrp_nrxrings;
				} else {
					nmrp->mrp_mask &= ~MRP_RX_RINGS;
					nmrp->mrp_nrxrings = 0;
				}
				if (omrp->mrp_mask & MRP_TX_RINGS) {
					nmrp->mrp_mask |= MRP_TX_RINGS;
					nmrp->mrp_ntxrings = omrp->mrp_ntxrings;
				} else {
					nmrp->mrp_mask &= ~MRP_TX_RINGS;
					nmrp->mrp_ntxrings = 0;
				}
				if (omrp->mrp_mask & MRP_RXRINGS_UNSPEC)
					omrp->mrp_mask |= MRP_RXRINGS_UNSPEC;
				else
					omrp->mrp_mask &= ~MRP_RXRINGS_UNSPEC;

				if (omrp->mrp_mask & MRP_TXRINGS_UNSPEC)
					omrp->mrp_mask |= MRP_TXRINGS_UNSPEC;
				else
					omrp->mrp_mask &= ~MRP_TXRINGS_UNSPEC;
				kmem_free(omrp, sizeof (*omrp));
				return (err);
			}

			/*
			 * If we modified the rings property of the primary
			 * we need to update the property fields of its
			 * VLANs as they inherit the primary's properites.
			 */
			if (mac_is_primary_client(mcip)) {
				mac_set_prim_vlan_rings(mip,
				    MCIP_RESOURCE_PROPS(mcip));
			}
		}
		/*
		 * We have to set this prior to calling mac_flow_modify.
		 */
		if (mrp->mrp_mask & MRP_PRIORITY) {
			if (mrp->mrp_priority == MPL_RESET) {
				MAC_CLIENT_SET_PRIORITY_RANGE(mcip,
				    MPL_LINK_DEFAULT);
			} else {
				MAC_CLIENT_SET_PRIORITY_RANGE(mcip,
				    mrp->mrp_priority);
			}
		}

		mac_flow_modify(mip->mi_flow_tab, flent, mrp);
		if (mrp->mrp_mask & MRP_PRIORITY)
			mac_update_subflow_priority(mcip);

		/* Apply these resource settings to any secondary macs */
		if (umip != NULL) {
			ASSERT((umip->mi_state_flags & MIS_IS_VNIC) != 0);
			mac_vnic_secondary_update(umip);
		}
	}
	kmem_free(omrp, sizeof (*omrp));
	return (0);
}

static int
mac_unicast_flow_create(mac_client_impl_t *mcip, uint8_t *mac_addr,
    uint16_t vid, boolean_t is_primary, boolean_t first_flow,
    flow_entry_t **flent, mac_resource_props_t *mrp)
{
	mac_impl_t	*mip = (mac_impl_t *)mcip->mci_mip;
	flow_desc_t	flow_desc;
	char		flowname[MAXFLOWNAMELEN];
	int		err;
	uint_t		flent_flags;

	/*
	 * First unicast address being added, create a new flow
	 * for that MAC client.
	 */
	bzero(&flow_desc, sizeof (flow_desc));

	ASSERT(mac_addr != NULL ||
	    (mcip->mci_state_flags & MCIS_NO_UNICAST_ADDR));
	if (mac_addr != NULL) {
		flow_desc.fd_mac_len = mip->mi_type->mt_addr_length;
		bcopy(mac_addr, flow_desc.fd_dst_mac, flow_desc.fd_mac_len);
	}
	flow_desc.fd_mask = FLOW_LINK_DST;
	if (vid != 0) {
		flow_desc.fd_vid = vid;
		flow_desc.fd_mask |= FLOW_LINK_VID;
	}

	/*
	 * XXX-nicolas. For now I'm keeping the FLOW_PRIMARY_MAC
	 * and FLOW_VNIC. Even though they're a hack inherited
	 * from the SRS code, we'll keep them for now. They're currently
	 * consumed by mac_datapath_setup() to create the SRS.
	 * That code should be eventually moved out of
	 * mac_datapath_setup() and moved to a mac_srs_create()
	 * function of some sort to keep things clean.
	 *
	 * Also, there's no reason why the SRS for the primary MAC
	 * client should be different than any other MAC client. Until
	 * this is cleaned-up, we support only one MAC unicast address
	 * per client.
	 *
	 * We set FLOW_PRIMARY_MAC for the primary MAC address,
	 * FLOW_VNIC for everything else.
	 */
	if (is_primary)
		flent_flags = FLOW_PRIMARY_MAC;
	else
		flent_flags = FLOW_VNIC_MAC;

	/*
	 * For the first flow we use the mac client's name - mci_name, for
	 * subsequent ones we just create a name with the vid. This is
	 * so that we can add these flows to the same flow table. This is
	 * fine as the flow name (except for the one with the mac client's
	 * name) is not visible. When the first flow is removed, we just replace
	 * its fdesc with another from the list, so we will still retain the
	 * flent with the MAC client's flow name.
	 */
	if (first_flow) {
		bcopy(mcip->mci_name, flowname, MAXFLOWNAMELEN);
	} else {
		(void) sprintf(flowname, "%s%u", mcip->mci_name, vid);
		flent_flags = FLOW_NO_STATS;
	}

	if ((err = mac_flow_create(&flow_desc, mrp, flowname, NULL,
	    flent_flags, flent)) != 0)
		return (err);

	mac_misc_stat_create(*flent);
	FLOW_MARK(*flent, FE_INCIPIENT);
	(*flent)->fe_mcip = mcip;

	/*
	 * Place initial creation reference on the flow. This reference
	 * is released in the corresponding delete action viz.
	 * mac_unicast_remove after waiting for all transient refs to
	 * to go away. The wait happens in mac_flow_wait.
	 * We have already held the reference in mac_client_open().
	 */
	if (!first_flow)
		FLOW_REFHOLD(*flent);
	return (0);
}

/* Refresh the multicast grouping for this VID. */
int
mac_client_update_mcast(void *arg, boolean_t add, const uint8_t *addrp)
{
	flow_entry_t		*flent = arg;
	mac_client_impl_t	*mcip = flent->fe_mcip;
	uint16_t		vid;
	flow_desc_t		flow_desc;

	mac_flow_get_desc(flent, &flow_desc);
	vid = (flow_desc.fd_mask & FLOW_LINK_VID) != 0 ?
	    flow_desc.fd_vid : VLAN_ID_NONE;

	/*
	 * We don't call mac_multicast_add()/mac_multicast_remove() as
	 * we want to add/remove for this specific vid.
	 */
	if (add) {
		return (mac_bcast_add(mcip, addrp, vid,
		    MAC_ADDRTYPE_MULTICAST));
	} else {
		mac_bcast_delete(mcip, addrp, vid);
		return (0);
	}
}

static void
mac_update_single_active_client(mac_impl_t *mip)
{
	mac_client_impl_t *client = NULL;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	rw_enter(&mip->mi_rw_lock, RW_WRITER);
	if (mip->mi_nactiveclients == 1) {
		/*
		 * Find the one active MAC client from the list of MAC
		 * clients. The active MAC client has at least one
		 * unicast address.
		 */
		for (client = mip->mi_clients_list; client != NULL;
		    client = client->mci_client_next) {
			if (client->mci_unicast_list != NULL)
				break;
		}
		ASSERT(client != NULL);
	}

	/*
	 * mi_single_active_client is protected by the MAC impl's read/writer
	 * lock, which allows mac_rx() to check the value of that pointer
	 * as a reader.
	 */
	mip->mi_single_active_client = client;
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Set up the data path. Called from i_mac_unicast_add after having
 * done all the validations including making sure this is an active
 * client (i.e that is ready to process packets.)
 */
static int
mac_client_datapath_setup(mac_client_impl_t *mcip, uint16_t vid,
    uint8_t *mac_addr, mac_resource_props_t *mrp, boolean_t isprimary,
    mac_unicast_impl_t *muip)
{
	mac_impl_t	*mip = mcip->mci_mip;
	boolean_t	mac_started = B_FALSE;
	boolean_t	bcast_added = B_FALSE;
	boolean_t	nactiveclients_added = B_FALSE;
	flow_entry_t	*flent;
	int		err = 0;
	boolean_t	no_unicast;

	no_unicast = mcip->mci_state_flags & MCIS_NO_UNICAST_ADDR;

	if ((err = mac_start((mac_handle_t)mip)) != 0)
		goto bail;

	mac_started = B_TRUE;

	/* add the MAC client to the broadcast address group by default */
	if (mip->mi_type->mt_brdcst_addr != NULL) {
		err = mac_bcast_add(mcip, mip->mi_type->mt_brdcst_addr, vid,
		    MAC_ADDRTYPE_BROADCAST);
		if (err != 0)
			goto bail;
		bcast_added = B_TRUE;
	}

	/*
	 * If this is the first unicast address addition for this
	 * client, reuse the pre-allocated larval flow entry associated with
	 * the MAC client.
	 */
	flent = (mcip->mci_nflents == 0) ? mcip->mci_flent : NULL;

	/* We are configuring the unicast flow now */
	if (!MCIP_DATAPATH_SETUP(mcip)) {

		if (mrp != NULL) {
			MAC_CLIENT_SET_PRIORITY_RANGE(mcip,
			    (mrp->mrp_mask & MRP_PRIORITY) ? mrp->mrp_priority :
			    MPL_LINK_DEFAULT);
		}
		if ((err = mac_unicast_flow_create(mcip, mac_addr, vid,
		    isprimary, B_TRUE, &flent, mrp)) != 0)
			goto bail;

		mip->mi_nactiveclients++;
		nactiveclients_added = B_TRUE;

		/*
		 * This will allocate the RX ring group if possible for the
		 * flow and program the software classifier as needed.
		 */
		if ((err = mac_datapath_setup(mcip, flent, SRST_LINK)) != 0)
			goto bail;

		if (no_unicast)
			goto done_setup;
		/*
		 * The unicast MAC address must have been added successfully.
		 */
		ASSERT(mcip->mci_unicast != NULL);
		/*
		 * Push down the sub-flows that were defined on this link
		 * hitherto. The flows are added to the active flow table
		 * and SRS, softrings etc. are created as needed.
		 */
		mac_link_init_flows((mac_client_handle_t)mcip);
	} else {
		mac_address_t *map = mcip->mci_unicast;

		ASSERT(!no_unicast);
		/*
		 * A unicast flow already exists for that MAC client,
		 * this flow must be the same mac address but with
		 * different VID. It has been checked by mac_addr_in_use().
		 *
		 * We will use the SRS etc. from the mci_flent. Note that
		 * We don't need to create kstat for this as except for
		 * the fdesc, everything will be used from in the 1st flent.
		 */

		if (bcmp(mac_addr, map->ma_addr, map->ma_len) != 0) {
			err = EINVAL;
			goto bail;
		}

		if ((err = mac_unicast_flow_create(mcip, mac_addr, vid,
		    isprimary, B_FALSE, &flent, NULL)) != 0) {
			goto bail;
		}
		if ((err = mac_flow_add(mip->mi_flow_tab, flent)) != 0) {
			FLOW_FINAL_REFRELE(flent);
			goto bail;
		}

		/* update the multicast group for this vid */
		mac_client_bcast_refresh(mcip, mac_client_update_mcast,
		    (void *)flent, B_TRUE);

	}

	/* populate the shared MAC address */
	muip->mui_map = mcip->mci_unicast;

	rw_enter(&mcip->mci_rw_lock, RW_WRITER);
	muip->mui_next = mcip->mci_unicast_list;
	mcip->mci_unicast_list = muip;
	rw_exit(&mcip->mci_rw_lock);

done_setup:
	/*
	 * First add the flent to the flow list of this mcip. Then set
	 * the mip's mi_single_active_client if needed. The Rx path assumes
	 * that mip->mi_single_active_client will always have an associated
	 * flent.
	 */
	mac_client_add_to_flow_list(mcip, flent);
	if (nactiveclients_added)
		mac_update_single_active_client(mip);
	/*
	 * Trigger a renegotiation of the capabilities when the number of
	 * active clients changes from 1 to 2, since some of the capabilities
	 * might have to be disabled. Also send a MAC_NOTE_LINK notification
	 * to all the MAC clients whenever physical link is DOWN.
	 */
	if (mip->mi_nactiveclients == 2) {
		mac_capab_update((mac_handle_t)mip);
		mac_virtual_link_update(mip);
	}
	/*
	 * Now that the setup is complete, clear the INCIPIENT flag.
	 * The flag was set to avoid incoming packets seeing inconsistent
	 * structures while the setup was in progress. Clear the mci_tx_flag
	 * by calling mac_tx_client_block. It is possible that
	 * mac_unicast_remove was called prior to this mac_unicast_add which
	 * could have set the MCI_TX_QUIESCE flag.
	 */
	if (flent->fe_rx_ring_group != NULL)
		mac_rx_group_unmark(flent->fe_rx_ring_group, MR_INCIPIENT);
	FLOW_UNMARK(flent, FE_INCIPIENT);
	FLOW_UNMARK(flent, FE_MC_NO_DATAPATH);
	mac_tx_client_unblock(mcip);
	return (0);
bail:
	if (bcast_added)
		mac_bcast_delete(mcip, mip->mi_type->mt_brdcst_addr, vid);

	if (nactiveclients_added)
		mip->mi_nactiveclients--;

	if (mac_started)
		mac_stop((mac_handle_t)mip);

	return (err);
}

/*
 * Return the passive primary MAC client, if present. The passive client is
 * a stand-by client that has the same unicast address as another that is
 * currenly active. Once the active client goes away, the passive client
 * becomes active.
 */
static mac_client_impl_t *
mac_get_passive_primary_client(mac_impl_t *mip)
{
	mac_client_impl_t	*mcip;

	for (mcip = mip->mi_clients_list; mcip != NULL;
	    mcip = mcip->mci_client_next) {
		if (mac_is_primary_client(mcip) &&
		    (mcip->mci_flags & MAC_CLIENT_FLAGS_PASSIVE_PRIMARY) != 0) {
			return (mcip);
		}
	}
	return (NULL);
}

/*
 * Add a new unicast address to the MAC client.
 *
 * The MAC address can be specified either by value, or the MAC client
 * can specify that it wants to use the primary MAC address of the
 * underlying MAC. See the introductory comments at the beginning
 * of this file for more more information on primary MAC addresses.
 *
 * Note also the tuple (MAC address, VID) must be unique
 * for the MAC clients defined on top of the same underlying MAC
 * instance, unless the MAC_UNICAST_NODUPCHECK is specified.
 *
 * In no case can a client use the PVID for the MAC, if the MAC has one set.
 */
int
i_mac_unicast_add(mac_client_handle_t mch, uint8_t *mac_addr, uint16_t flags,
    mac_unicast_handle_t *mah, uint16_t vid, mac_diag_t *diag)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	int			err;
	uint_t			mac_len = mip->mi_type->mt_addr_length;
	boolean_t		check_dups = !(flags & MAC_UNICAST_NODUPCHECK);
	boolean_t		fastpath_disabled = B_FALSE;
	boolean_t		is_primary = (flags & MAC_UNICAST_PRIMARY);
	boolean_t		is_unicast_hw = (flags & MAC_UNICAST_HW);
	mac_resource_props_t	*mrp;
	boolean_t		passive_client = B_FALSE;
	mac_unicast_impl_t	*muip;
	boolean_t		is_vnic_primary =
	    (flags & MAC_UNICAST_VNIC_PRIMARY);

	/* when VID is non-zero, the underlying MAC can not be VNIC */
	ASSERT(!((mip->mi_state_flags & MIS_IS_VNIC) && (vid != 0)));

	/*
	 * Can't unicast add if the client asked only for minimal datapath
	 * setup.
	 */
	if (mcip->mci_state_flags & MCIS_NO_UNICAST_ADDR)
		return (ENOTSUP);

	/*
	 * Check for an attempted use of the current Port VLAN ID, if enabled.
	 * No client may use it.
	 */
	if (mip->mi_pvid != 0 && vid == mip->mi_pvid)
		return (EBUSY);

	/*
	 * Check whether it's the primary client and flag it.
	 */
	if (!(mcip->mci_state_flags & MCIS_IS_VNIC) && is_primary && vid == 0)
		mcip->mci_flags |= MAC_CLIENT_FLAGS_PRIMARY;

	/*
	 * is_vnic_primary is true when we come here as a VLAN VNIC
	 * which uses the primary mac client's address but with a non-zero
	 * VID. In this case the MAC address is not specified by an upper
	 * MAC client.
	 */
	if ((mcip->mci_state_flags & MCIS_IS_VNIC) && is_primary &&
	    !is_vnic_primary) {
		/*
		 * The address is being set by the upper MAC client
		 * of a VNIC. The MAC address was already set by the
		 * VNIC driver during VNIC creation.
		 *
		 * Note: a VNIC has only one MAC address. We return
		 * the MAC unicast address handle of the lower MAC client
		 * corresponding to the VNIC. We allocate a new entry
		 * which is flagged appropriately, so that mac_unicast_remove()
		 * doesn't attempt to free the original entry that
		 * was allocated by the VNIC driver.
		 */
		ASSERT(mcip->mci_unicast != NULL);

		/* Check for VLAN flags, if present */
		if ((flags & MAC_UNICAST_TAG_DISABLE) != 0)
			mcip->mci_state_flags |= MCIS_TAG_DISABLE;

		if ((flags & MAC_UNICAST_STRIP_DISABLE) != 0)
			mcip->mci_state_flags |= MCIS_STRIP_DISABLE;

		if ((flags & MAC_UNICAST_DISABLE_TX_VID_CHECK) != 0)
			mcip->mci_state_flags |= MCIS_DISABLE_TX_VID_CHECK;

		/*
		 * Ensure that the primary unicast address of the VNIC
		 * is added only once unless we have the
		 * MAC_CLIENT_FLAGS_MULTI_PRIMARY set (and this is not
		 * a passive MAC client).
		 */
		if ((mcip->mci_flags & MAC_CLIENT_FLAGS_VNIC_PRIMARY) != 0) {
			if ((mcip->mci_flags &
			    MAC_CLIENT_FLAGS_MULTI_PRIMARY) == 0 ||
			    (mcip->mci_flags &
			    MAC_CLIENT_FLAGS_PASSIVE_PRIMARY) != 0) {
				return (EBUSY);
			}
			mcip->mci_flags |= MAC_CLIENT_FLAGS_PASSIVE_PRIMARY;
			passive_client = B_TRUE;
		}

		mcip->mci_flags |= MAC_CLIENT_FLAGS_VNIC_PRIMARY;

		/*
		 * Create a handle for vid 0.
		 */
		ASSERT(vid == 0);
		muip = kmem_zalloc(sizeof (mac_unicast_impl_t), KM_SLEEP);
		muip->mui_vid = vid;
		*mah = (mac_unicast_handle_t)muip;
		/*
		 * This will be used by the caller to defer setting the
		 * rx functions.
		 */
		if (passive_client)
			return (EAGAIN);
		return (0);
	}

	/* primary MAC clients cannot be opened on top of anchor VNICs */
	if ((is_vnic_primary || is_primary) &&
	    i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_ANCHOR_VNIC, NULL)) {
		return (ENXIO);
	}

	/*
	 * If this is a VNIC/VLAN, disable softmac fast-path.
	 */
	if (mcip->mci_state_flags & MCIS_IS_VNIC) {
		err = mac_fastpath_disable((mac_handle_t)mip);
		if (err != 0)
			return (err);
		fastpath_disabled = B_TRUE;
	}

	/*
	 * Return EBUSY if:
	 *  - there is an exclusively active mac client exists.
	 *  - this is an exclusive active mac client but
	 *	a. there is already active mac clients exist, or
	 *	b. fastpath streams are already plumbed on this legacy device
	 *  - the mac creator has disallowed active mac clients.
	 */
	if (mip->mi_state_flags & (MIS_EXCLUSIVE|MIS_NO_ACTIVE)) {
		if (fastpath_disabled)
			mac_fastpath_enable((mac_handle_t)mip);
		return (EBUSY);
	}

	if (mcip->mci_state_flags & MCIS_EXCLUSIVE) {
		ASSERT(!fastpath_disabled);
		if (mip->mi_nactiveclients != 0)
			return (EBUSY);

		if ((mip->mi_state_flags & MIS_LEGACY) &&
		    !(mip->mi_capab_legacy.ml_active_set(mip->mi_driver))) {
			return (EBUSY);
		}
		mip->mi_state_flags |= MIS_EXCLUSIVE;
	}

	mrp = kmem_zalloc(sizeof (*mrp), KM_SLEEP);
	if (is_primary && !(mcip->mci_state_flags & (MCIS_IS_VNIC |
	    MCIS_IS_AGGR_PORT))) {
		/*
		 * Apply the property cached in the mac_impl_t to the primary
		 * mac client. If the mac client is a VNIC or an aggregation
		 * port, its property should be set in the mcip when the
		 * VNIC/aggr was created.
		 */
		mac_get_resources((mac_handle_t)mip, mrp);
		(void) mac_client_set_resources(mch, mrp);
	} else if (mcip->mci_state_flags & MCIS_IS_VNIC) {
		/*
		 * This is a primary VLAN client, we don't support
		 * specifying rings property for this as it inherits the
		 * rings property from its MAC.
		 */
		if (is_vnic_primary) {
			mac_resource_props_t	*vmrp;

			vmrp = MCIP_RESOURCE_PROPS(mcip);
			if (vmrp->mrp_mask & MRP_RX_RINGS ||
			    vmrp->mrp_mask & MRP_TX_RINGS) {
				if (fastpath_disabled)
					mac_fastpath_enable((mac_handle_t)mip);
				kmem_free(mrp, sizeof (*mrp));
				return (ENOTSUP);
			}
			/*
			 * Additionally we also need to inherit any
			 * rings property from the MAC.
			 */
			mac_get_resources((mac_handle_t)mip, mrp);
			if (mrp->mrp_mask & MRP_RX_RINGS) {
				vmrp->mrp_mask |= MRP_RX_RINGS;
				vmrp->mrp_nrxrings = mrp->mrp_nrxrings;
			}
			if (mrp->mrp_mask & MRP_TX_RINGS) {
				vmrp->mrp_mask |= MRP_TX_RINGS;
				vmrp->mrp_ntxrings = mrp->mrp_ntxrings;
			}
		}
		bcopy(MCIP_RESOURCE_PROPS(mcip), mrp, sizeof (*mrp));
	}

	muip = kmem_zalloc(sizeof (mac_unicast_impl_t), KM_SLEEP);
	muip->mui_vid = vid;

	if (is_primary || is_vnic_primary) {
		mac_addr = mip->mi_addr;
	} else {

		/*
		 * Verify the validity of the specified MAC addresses value.
		 */
		if (!mac_unicst_verify((mac_handle_t)mip, mac_addr, mac_len)) {
			*diag = MAC_DIAG_MACADDR_INVALID;
			err = EINVAL;
			goto bail_out;
		}

		/*
		 * Make sure that the specified MAC address is different
		 * than the unicast MAC address of the underlying NIC.
		 */
		if (check_dups && bcmp(mip->mi_addr, mac_addr, mac_len) == 0) {
			*diag = MAC_DIAG_MACADDR_NIC;
			err = EINVAL;
			goto bail_out;
		}
	}

	/*
	 * Set the flags here so that if this is a passive client, we
	 * can return  and set it when we call mac_client_datapath_setup
	 * when this becomes the active client. If we defer to using these
	 * flags to mac_client_datapath_setup, then for a passive client,
	 * we'd have to store the flags somewhere (probably fe_flags)
	 * and then use it.
	 */
	if (!MCIP_DATAPATH_SETUP(mcip)) {
		if (is_unicast_hw) {
			/*
			 * The client requires a hardware MAC address slot
			 * for that unicast address. Since we support only
			 * one unicast MAC address per client, flag the
			 * MAC client itself.
			 */
			mcip->mci_state_flags |= MCIS_UNICAST_HW;
		}

		/* Check for VLAN flags, if present */
		if ((flags & MAC_UNICAST_TAG_DISABLE) != 0)
			mcip->mci_state_flags |= MCIS_TAG_DISABLE;

		if ((flags & MAC_UNICAST_STRIP_DISABLE) != 0)
			mcip->mci_state_flags |= MCIS_STRIP_DISABLE;

		if ((flags & MAC_UNICAST_DISABLE_TX_VID_CHECK) != 0)
			mcip->mci_state_flags |= MCIS_DISABLE_TX_VID_CHECK;
	} else {
		/*
		 * Assert that the specified flags are consistent with the
		 * flags specified by previous calls to mac_unicast_add().
		 */
		ASSERT(((flags & MAC_UNICAST_TAG_DISABLE) != 0 &&
		    (mcip->mci_state_flags & MCIS_TAG_DISABLE) != 0) ||
		    ((flags & MAC_UNICAST_TAG_DISABLE) == 0 &&
		    (mcip->mci_state_flags & MCIS_TAG_DISABLE) == 0));

		ASSERT(((flags & MAC_UNICAST_STRIP_DISABLE) != 0 &&
		    (mcip->mci_state_flags & MCIS_STRIP_DISABLE) != 0) ||
		    ((flags & MAC_UNICAST_STRIP_DISABLE) == 0 &&
		    (mcip->mci_state_flags & MCIS_STRIP_DISABLE) == 0));

		ASSERT(((flags & MAC_UNICAST_DISABLE_TX_VID_CHECK) != 0 &&
		    (mcip->mci_state_flags & MCIS_DISABLE_TX_VID_CHECK) != 0) ||
		    ((flags & MAC_UNICAST_DISABLE_TX_VID_CHECK) == 0 &&
		    (mcip->mci_state_flags & MCIS_DISABLE_TX_VID_CHECK) == 0));

		/*
		 * Make sure the client is consistent about its requests
		 * for MAC addresses. I.e. all requests from the clients
		 * must have the MAC_UNICAST_HW flag set or clear.
		 */
		if ((mcip->mci_state_flags & MCIS_UNICAST_HW) != 0 &&
		    !is_unicast_hw ||
		    (mcip->mci_state_flags & MCIS_UNICAST_HW) == 0 &&
		    is_unicast_hw) {
			err = EINVAL;
			goto bail_out;
		}
	}
	/*
	 * Make sure the MAC address is not already used by
	 * another MAC client defined on top of the same
	 * underlying NIC. Unless we have MAC_CLIENT_FLAGS_MULTI_PRIMARY
	 * set when we allow a passive client to be present which will
	 * be activated when the currently active client goes away - this
	 * works only with primary addresses.
	 */
	if ((check_dups || is_primary || is_vnic_primary) &&
	    mac_addr_in_use(mip, mac_addr, vid)) {
		/*
		 * Must have set the multiple primary address flag when
		 * we did a mac_client_open AND this should be a primary
		 * MAC client AND there should not already be a passive
		 * primary. If all is true then we let this succeed
		 * even if the address is a dup.
		 */
		if ((mcip->mci_flags & MAC_CLIENT_FLAGS_MULTI_PRIMARY) == 0 ||
		    (mcip->mci_flags & MAC_CLIENT_FLAGS_PRIMARY) == 0 ||
		    mac_get_passive_primary_client(mip) != NULL) {
			*diag = MAC_DIAG_MACADDR_INUSE;
			err = EEXIST;
			goto bail_out;
		}
		ASSERT((mcip->mci_flags &
		    MAC_CLIENT_FLAGS_PASSIVE_PRIMARY) == 0);
		mcip->mci_flags |= MAC_CLIENT_FLAGS_PASSIVE_PRIMARY;
		kmem_free(mrp, sizeof (*mrp));

		/*
		 * Stash the unicast address handle, we will use it when
		 * we set up the passive client.
		 */
		mcip->mci_p_unicast_list = muip;
		*mah = (mac_unicast_handle_t)muip;
		return (0);
	}

	err = mac_client_datapath_setup(mcip, vid, mac_addr, mrp,
	    is_primary || is_vnic_primary, muip);
	if (err != 0)
		goto bail_out;

	kmem_free(mrp, sizeof (*mrp));
	*mah = (mac_unicast_handle_t)muip;
	return (0);

bail_out:
	if (fastpath_disabled)
		mac_fastpath_enable((mac_handle_t)mip);
	if (mcip->mci_state_flags & MCIS_EXCLUSIVE) {
		mip->mi_state_flags &= ~MIS_EXCLUSIVE;
		if (mip->mi_state_flags & MIS_LEGACY) {
			mip->mi_capab_legacy.ml_active_clear(
			    mip->mi_driver);
		}
	}
	kmem_free(mrp, sizeof (*mrp));
	kmem_free(muip, sizeof (mac_unicast_impl_t));
	return (err);
}

/*
 * Wrapper function to mac_unicast_add when we want to have the same mac
 * client open for two instances, one that is currently active and another
 * that will become active when the current one is removed. In this case
 * mac_unicast_add will return EGAIN and we will save the rx function and
 * arg which will be used when we activate the passive client in
 * mac_unicast_remove.
 */
int
mac_unicast_add_set_rx(mac_client_handle_t mch, uint8_t *mac_addr,
    uint16_t flags, mac_unicast_handle_t *mah,  uint16_t vid, mac_diag_t *diag,
    mac_rx_t rx_fn, void *arg)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	uint_t			err;

	err = mac_unicast_add(mch, mac_addr, flags, mah, vid, diag);
	if (err != 0 && err != EAGAIN)
		return (err);
	if (err == EAGAIN) {
		if (rx_fn != NULL) {
			mcip->mci_rx_p_fn = rx_fn;
			mcip->mci_rx_p_arg = arg;
		}
		return (0);
	}
	if (rx_fn != NULL)
		mac_rx_set(mch, rx_fn, arg);
	return (err);
}

int
mac_unicast_add(mac_client_handle_t mch, uint8_t *mac_addr, uint16_t flags,
    mac_unicast_handle_t *mah, uint16_t vid, mac_diag_t *diag)
{
	mac_impl_t *mip = ((mac_client_impl_t *)mch)->mci_mip;
	uint_t err;

	i_mac_perim_enter(mip);
	err = i_mac_unicast_add(mch, mac_addr, flags, mah, vid, diag);
	i_mac_perim_exit(mip);

	return (err);
}

static void
mac_client_datapath_teardown(mac_client_handle_t mch, mac_unicast_impl_t *muip,
    flow_entry_t *flent)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	boolean_t		no_unicast;

	/*
	 * If we have not added a unicast address for this MAC client, just
	 * teardown the datapath.
	 */
	no_unicast = mcip->mci_state_flags & MCIS_NO_UNICAST_ADDR;

	if (!no_unicast) {
		/*
		 * We would have initialized subflows etc. only if we brought
		 * up the primary client and set the unicast unicast address
		 * etc. Deactivate the flows. The flow entry will be removed
		 * from the active flow tables, and the associated SRS,
		 * softrings etc will be deleted. But the flow entry itself
		 * won't be destroyed, instead it will continue to be archived
		 * off the  the global flow hash list, for a possible future
		 * activation when say IP is plumbed again.
		 */
		mac_link_release_flows(mch);
	}
	mip->mi_nactiveclients--;
	mac_update_single_active_client(mip);

	/* Tear down the data path */
	mac_datapath_teardown(mcip, mcip->mci_flent, SRST_LINK);

	/*
	 * Prevent any future access to the flow entry through the mci_flent
	 * pointer by setting the mci_flent to NULL. Access to mci_flent in
	 * mac_bcast_send is also under mi_rw_lock.
	 */
	rw_enter(&mip->mi_rw_lock, RW_WRITER);
	flent = mcip->mci_flent;
	mac_client_remove_flow_from_list(mcip, flent);

	if (mcip->mci_state_flags & MCIS_DESC_LOGGED)
		mcip->mci_state_flags &= ~MCIS_DESC_LOGGED;

	/*
	 * This is the last unicast address being removed and there shouldn't
	 * be any outbound data threads at this point coming down from mac
	 * clients. We have waited for the data threads to finish before
	 * starting dld_str_detach. Non-data threads must access TX SRS
	 * under mi_rw_lock.
	 */
	rw_exit(&mip->mi_rw_lock);

	/*
	 * Don't use FLOW_MARK with FE_MC_NO_DATAPATH, as the flow might
	 * contain other flags, such as FE_CONDEMNED, which we need to
	 * cleared. We don't call mac_flow_cleanup() for this unicast
	 * flow as we have a already cleaned up SRSs etc. (via the teadown
	 * path). We just clear the stats and reset the initial callback
	 * function, the rest will be set when we call mac_flow_create,
	 * if at all.
	 */
	mutex_enter(&flent->fe_lock);
	ASSERT(flent->fe_refcnt == 1 && flent->fe_mbg == NULL &&
	    flent->fe_tx_srs == NULL && flent->fe_rx_srs_cnt == 0);
	flent->fe_flags = FE_MC_NO_DATAPATH;
	flow_stat_destroy(flent);
	mac_misc_stat_delete(flent);

	/* Initialize the receiver function to a safe routine */
	flent->fe_cb_fn = (flow_fn_t)mac_pkt_drop;
	flent->fe_cb_arg1 = NULL;
	flent->fe_cb_arg2 = NULL;

	flent->fe_index = -1;
	mutex_exit(&flent->fe_lock);

	if (mip->mi_type->mt_brdcst_addr != NULL) {
		ASSERT(muip != NULL || no_unicast);
		mac_bcast_delete(mcip, mip->mi_type->mt_brdcst_addr,
		    muip != NULL ? muip->mui_vid : VLAN_ID_NONE);
	}

	if (mip->mi_nactiveclients == 1) {
		mac_capab_update((mac_handle_t)mip);
		mac_virtual_link_update(mip);
	}

	if (mcip->mci_state_flags & MCIS_EXCLUSIVE) {
		mip->mi_state_flags &= ~MIS_EXCLUSIVE;

		if (mip->mi_state_flags & MIS_LEGACY)
			mip->mi_capab_legacy.ml_active_clear(mip->mi_driver);
	}

	mcip->mci_state_flags &= ~MCIS_UNICAST_HW;

	if (mcip->mci_state_flags & MCIS_TAG_DISABLE)
		mcip->mci_state_flags &= ~MCIS_TAG_DISABLE;

	if (mcip->mci_state_flags & MCIS_STRIP_DISABLE)
		mcip->mci_state_flags &= ~MCIS_STRIP_DISABLE;

	if (mcip->mci_state_flags & MCIS_DISABLE_TX_VID_CHECK)
		mcip->mci_state_flags &= ~MCIS_DISABLE_TX_VID_CHECK;

	if (muip != NULL)
		kmem_free(muip, sizeof (mac_unicast_impl_t));
	mac_protect_cancel_timer(mcip);
	mac_protect_flush_dhcp(mcip);

	bzero(&mcip->mci_misc_stat, sizeof (mcip->mci_misc_stat));
	/*
	 * Disable fastpath if this is a VNIC or a VLAN.
	 */
	if (mcip->mci_state_flags & MCIS_IS_VNIC)
		mac_fastpath_enable((mac_handle_t)mip);
	mac_stop((mac_handle_t)mip);
}

/*
 * Remove a MAC address which was previously added by mac_unicast_add().
 */
int
mac_unicast_remove(mac_client_handle_t mch, mac_unicast_handle_t mah)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_unicast_impl_t *muip = (mac_unicast_impl_t *)mah;
	mac_unicast_impl_t *pre;
	mac_impl_t *mip = mcip->mci_mip;
	flow_entry_t		*flent;
	uint16_t mui_vid;

	i_mac_perim_enter(mip);
	if (mcip->mci_flags & MAC_CLIENT_FLAGS_VNIC_PRIMARY) {
		/*
		 * Called made by the upper MAC client of a VNIC.
		 * There's nothing much to do, the unicast address will
		 * be removed by the VNIC driver when the VNIC is deleted,
		 * but let's ensure that all our transmit is done before
		 * the client does a mac_client_stop lest it trigger an
		 * assert in the driver.
		 */
		ASSERT(muip->mui_vid == 0);

		mac_tx_client_flush(mcip);

		if ((mcip->mci_flags & MAC_CLIENT_FLAGS_PASSIVE_PRIMARY) != 0) {
			mcip->mci_flags &= ~MAC_CLIENT_FLAGS_PASSIVE_PRIMARY;
			if (mcip->mci_rx_p_fn != NULL) {
				mac_rx_set(mch, mcip->mci_rx_p_fn,
				    mcip->mci_rx_p_arg);
				mcip->mci_rx_p_fn = NULL;
				mcip->mci_rx_p_arg = NULL;
			}
			kmem_free(muip, sizeof (mac_unicast_impl_t));
			i_mac_perim_exit(mip);
			return (0);
		}
		mcip->mci_flags &= ~MAC_CLIENT_FLAGS_VNIC_PRIMARY;

		if (mcip->mci_state_flags & MCIS_TAG_DISABLE)
			mcip->mci_state_flags &= ~MCIS_TAG_DISABLE;

		if (mcip->mci_state_flags & MCIS_STRIP_DISABLE)
			mcip->mci_state_flags &= ~MCIS_STRIP_DISABLE;

		if (mcip->mci_state_flags & MCIS_DISABLE_TX_VID_CHECK)
			mcip->mci_state_flags &= ~MCIS_DISABLE_TX_VID_CHECK;

		kmem_free(muip, sizeof (mac_unicast_impl_t));
		i_mac_perim_exit(mip);
		return (0);
	}

	ASSERT(muip != NULL);

	/*
	 * We are removing a passive client, we haven't setup the datapath
	 * for this yet, so nothing much to do.
	 */
	if ((mcip->mci_flags & MAC_CLIENT_FLAGS_PASSIVE_PRIMARY) != 0) {

		ASSERT((mcip->mci_flent->fe_flags & FE_MC_NO_DATAPATH) != 0);
		ASSERT(mcip->mci_p_unicast_list == muip);

		mcip->mci_flags &= ~MAC_CLIENT_FLAGS_PASSIVE_PRIMARY;

		mcip->mci_p_unicast_list = NULL;
		mcip->mci_rx_p_fn = NULL;
		mcip->mci_rx_p_arg = NULL;

		mcip->mci_state_flags &= ~MCIS_UNICAST_HW;

		if (mcip->mci_state_flags & MCIS_TAG_DISABLE)
			mcip->mci_state_flags &= ~MCIS_TAG_DISABLE;

		if (mcip->mci_state_flags & MCIS_STRIP_DISABLE)
			mcip->mci_state_flags &= ~MCIS_STRIP_DISABLE;

		if (mcip->mci_state_flags & MCIS_DISABLE_TX_VID_CHECK)
			mcip->mci_state_flags &= ~MCIS_DISABLE_TX_VID_CHECK;

		kmem_free(muip, sizeof (mac_unicast_impl_t));
		i_mac_perim_exit(mip);
		return (0);
	}
	/*
	 * Remove the VID from the list of client's VIDs.
	 */
	pre = mcip->mci_unicast_list;
	if (muip == pre) {
		mcip->mci_unicast_list = muip->mui_next;
	} else {
		while ((pre->mui_next != NULL) && (pre->mui_next != muip))
			pre = pre->mui_next;
		ASSERT(pre->mui_next == muip);
		rw_enter(&mcip->mci_rw_lock, RW_WRITER);
		pre->mui_next = muip->mui_next;
		rw_exit(&mcip->mci_rw_lock);
	}

	if (!mac_client_single_rcvr(mcip)) {
		/*
		 * This MAC client is shared by more than one unicast
		 * addresses, so we will just remove the flent
		 * corresponding to the address being removed. We don't invoke
		 * mac_rx_classify_flow_rem() since the additional flow is
		 * not associated with its own separate set of SRS and rings,
		 * and these constructs are still needed for the remaining
		 * flows.
		 */
		flent = mac_client_get_flow(mcip, muip);
		ASSERT(flent != NULL);

		/*
		 * The first one is disappearing, need to make sure
		 * we replace it with another from the list of
		 * shared clients.
		 */
		if (flent == mcip->mci_flent)
			flent = mac_client_swap_mciflent(mcip);
		mac_client_remove_flow_from_list(mcip, flent);
		mac_flow_remove(mip->mi_flow_tab, flent, B_FALSE);
		mac_flow_wait(flent, FLOW_DRIVER_UPCALL);

		/*
		 * The multicast groups that were added by the client so
		 * far must be removed from the brodcast domain corresponding
		 * to the VID being removed.
		 */
		mac_client_bcast_refresh(mcip, mac_client_update_mcast,
		    (void *)flent, B_FALSE);

		if (mip->mi_type->mt_brdcst_addr != NULL) {
			mac_bcast_delete(mcip, mip->mi_type->mt_brdcst_addr,
			    muip->mui_vid);
		}

		FLOW_FINAL_REFRELE(flent);
		ASSERT(!(mcip->mci_state_flags & MCIS_EXCLUSIVE));
		/*
		 * Enable fastpath if this is a VNIC or a VLAN.
		 */
		if (mcip->mci_state_flags & MCIS_IS_VNIC)
			mac_fastpath_enable((mac_handle_t)mip);
		mac_stop((mac_handle_t)mip);
		i_mac_perim_exit(mip);
		return (0);
	}

	mui_vid = muip->mui_vid;
	mac_client_datapath_teardown(mch, muip, flent);

	if ((mcip->mci_flags & MAC_CLIENT_FLAGS_PRIMARY) && mui_vid == 0) {
		mcip->mci_flags &= ~MAC_CLIENT_FLAGS_PRIMARY;
	} else {
		i_mac_perim_exit(mip);
		return (0);
	}

	/*
	 * If we are removing the primary, check if we have a passive primary
	 * client that we need to activate now.
	 */
	mcip = mac_get_passive_primary_client(mip);
	if (mcip != NULL) {
		mac_resource_props_t	*mrp;
		mac_unicast_impl_t	*muip;

		mcip->mci_flags &= ~MAC_CLIENT_FLAGS_PASSIVE_PRIMARY;
		mrp = kmem_zalloc(sizeof (*mrp), KM_SLEEP);

		/*
		 * Apply the property cached in the mac_impl_t to the
		 * primary mac client.
		 */
		mac_get_resources((mac_handle_t)mip, mrp);
		(void) mac_client_set_resources(mch, mrp);
		ASSERT(mcip->mci_p_unicast_list != NULL);
		muip = mcip->mci_p_unicast_list;
		mcip->mci_p_unicast_list = NULL;
		if (mac_client_datapath_setup(mcip, VLAN_ID_NONE,
		    mip->mi_addr, mrp, B_TRUE, muip) == 0) {
			if (mcip->mci_rx_p_fn != NULL) {
				mac_rx_set(mch, mcip->mci_rx_p_fn,
				    mcip->mci_rx_p_arg);
				mcip->mci_rx_p_fn = NULL;
				mcip->mci_rx_p_arg = NULL;
			}
		} else {
			kmem_free(muip, sizeof (mac_unicast_impl_t));
		}
		kmem_free(mrp, sizeof (*mrp));
	}
	i_mac_perim_exit(mip);
	return (0);
}

/*
 * Multicast add function invoked by MAC clients.
 */
int
mac_multicast_add(mac_client_handle_t mch, const uint8_t *addr)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	flow_entry_t		*flent = mcip->mci_flent_list;
	flow_entry_t		*prev_fe = NULL;
	uint16_t		vid;
	int			err = 0;

	/* Verify the address is a valid multicast address */
	if ((err = mip->mi_type->mt_ops.mtops_multicst_verify(addr,
	    mip->mi_pdata)) != 0)
		return (err);

	i_mac_perim_enter(mip);
	while (flent != NULL) {
		vid = i_mac_flow_vid(flent);

		err = mac_bcast_add((mac_client_impl_t *)mch, addr, vid,
		    MAC_ADDRTYPE_MULTICAST);
		if (err != 0)
			break;
		prev_fe = flent;
		flent = flent->fe_client_next;
	}

	/*
	 * If we failed adding, then undo all, rather than partial
	 * success.
	 */
	if (flent != NULL && prev_fe != NULL) {
		flent = mcip->mci_flent_list;
		while (flent != prev_fe->fe_client_next) {
			vid = i_mac_flow_vid(flent);
			mac_bcast_delete((mac_client_impl_t *)mch, addr, vid);
			flent = flent->fe_client_next;
		}
	}
	i_mac_perim_exit(mip);
	return (err);
}

/*
 * Multicast delete function invoked by MAC clients.
 */
void
mac_multicast_remove(mac_client_handle_t mch, const uint8_t *addr)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	flow_entry_t		*flent;
	uint16_t		vid;

	i_mac_perim_enter(mip);
	for (flent = mcip->mci_flent_list; flent != NULL;
	    flent = flent->fe_client_next) {
		vid = i_mac_flow_vid(flent);
		mac_bcast_delete((mac_client_impl_t *)mch, addr, vid);
	}
	i_mac_perim_exit(mip);
}

/*
 * When a MAC client desires to capture packets on an interface,
 * it registers a promiscuous call back with mac_promisc_add().
 * There are three types of promiscuous callbacks:
 *
 * * MAC_CLIENT_PROMISC_ALL
 *   Captures all packets sent and received by the MAC client,
 *   the physical interface, as well as all other MAC clients
 *   defined on top of the same MAC.
 *
 * * MAC_CLIENT_PROMISC_FILTERED
 *   Captures all packets sent and received by the MAC client,
 *   plus all multicast traffic sent and received by the phyisical
 *   interface and the other MAC clients.
 *
 * * MAC_CLIENT_PROMISC_MULTI
 *   Captures all broadcast and multicast packets sent and
 *   received by the MAC clients as well as the physical interface.
 *
 * In all cases, the underlying MAC is put in promiscuous mode.
 */
int
mac_promisc_add(mac_client_handle_t mch, mac_client_promisc_type_t type,
    mac_rx_t fn, void *arg, mac_promisc_handle_t *mphp, uint16_t flags)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	mac_promisc_impl_t *mpip;
	mac_cb_info_t	*mcbi;
	int rc;

	i_mac_perim_enter(mip);

	if ((rc = mac_start((mac_handle_t)mip)) != 0) {
		i_mac_perim_exit(mip);
		return (rc);
	}

	if ((mcip->mci_state_flags & MCIS_IS_VNIC) &&
	    type == MAC_CLIENT_PROMISC_ALL) {
		/*
		 * The function is being invoked by the upper MAC client
		 * of a VNIC. The VNIC should only see the traffic
		 * it is entitled to.
		 */
		type = MAC_CLIENT_PROMISC_FILTERED;
	}


	/*
	 * Turn on promiscuous mode for the underlying NIC.
	 * This is needed even for filtered callbacks which
	 * expect to receive all multicast traffic on the wire.
	 *
	 * Physical promiscuous mode should not be turned on if
	 * MAC_PROMISC_FLAGS_NO_PHYS is set.
	 */
	if ((flags & MAC_PROMISC_FLAGS_NO_PHYS) == 0) {
		if ((rc = i_mac_promisc_set(mip, B_TRUE)) != 0) {
			mac_stop((mac_handle_t)mip);
			i_mac_perim_exit(mip);
			return (rc);
		}
	}

	mpip = kmem_cache_alloc(mac_promisc_impl_cache, KM_SLEEP);

	mpip->mpi_type = type;
	mpip->mpi_fn = fn;
	mpip->mpi_arg = arg;
	mpip->mpi_mcip = mcip;
	mpip->mpi_no_tx_loop = ((flags & MAC_PROMISC_FLAGS_NO_TX_LOOP) != 0);
	mpip->mpi_no_phys = ((flags & MAC_PROMISC_FLAGS_NO_PHYS) != 0);
	mpip->mpi_strip_vlan_tag =
	    ((flags & MAC_PROMISC_FLAGS_VLAN_TAG_STRIP) != 0);
	mpip->mpi_no_copy = ((flags & MAC_PROMISC_FLAGS_NO_COPY) != 0);

	mcbi = &mip->mi_promisc_cb_info;
	mutex_enter(mcbi->mcbi_lockp);

	mac_callback_add(&mip->mi_promisc_cb_info, &mcip->mci_promisc_list,
	    &mpip->mpi_mci_link);
	mac_callback_add(&mip->mi_promisc_cb_info, &mip->mi_promisc_list,
	    &mpip->mpi_mi_link);

	mutex_exit(mcbi->mcbi_lockp);

	*mphp = (mac_promisc_handle_t)mpip;

	if (mcip->mci_state_flags & MCIS_IS_VNIC) {
		mac_impl_t *umip = mcip->mci_upper_mip;

		ASSERT(umip != NULL);
		mac_vnic_secondary_update(umip);
	}

	i_mac_perim_exit(mip);

	return (0);
}

/*
 * Remove a multicast address previously aded through mac_promisc_add().
 */
void
mac_promisc_remove(mac_promisc_handle_t mph)
{
	mac_promisc_impl_t *mpip = (mac_promisc_impl_t *)mph;
	mac_client_impl_t *mcip = mpip->mpi_mcip;
	mac_impl_t *mip = mcip->mci_mip;
	mac_cb_info_t *mcbi;
	int rv;

	i_mac_perim_enter(mip);

	/*
	 * Even if the device can't be reset into normal mode, we still
	 * need to clear the client promisc callbacks. The client may want
	 * to close the mac end point and we can't have stale callbacks.
	 */
	if (!(mpip->mpi_no_phys)) {
		if ((rv = i_mac_promisc_set(mip, B_FALSE)) != 0) {
			cmn_err(CE_WARN, "%s: failed to switch OFF promiscuous"
			    " mode because of error 0x%x", mip->mi_name, rv);
		}
	}
	mcbi = &mip->mi_promisc_cb_info;
	mutex_enter(mcbi->mcbi_lockp);
	if (mac_callback_remove(mcbi, &mip->mi_promisc_list,
	    &mpip->mpi_mi_link)) {
		VERIFY(mac_callback_remove(&mip->mi_promisc_cb_info,
		    &mcip->mci_promisc_list, &mpip->mpi_mci_link));
		kmem_cache_free(mac_promisc_impl_cache, mpip);
	} else {
		mac_callback_remove_wait(&mip->mi_promisc_cb_info);
	}

	if (mcip->mci_state_flags & MCIS_IS_VNIC) {
		mac_impl_t *umip = mcip->mci_upper_mip;

		ASSERT(umip != NULL);
		mac_vnic_secondary_update(umip);
	}

	mutex_exit(mcbi->mcbi_lockp);
	mac_stop((mac_handle_t)mip);

	i_mac_perim_exit(mip);
}

/*
 * Reference count the number of active Tx threads. MCI_TX_QUIESCE indicates
 * that a control operation wants to quiesce the Tx data flow in which case
 * we return an error. Holding any of the per cpu locks ensures that the
 * mci_tx_flag won't change.
 *
 * 'CPU' must be accessed just once and used to compute the index into the
 * percpu array, and that index must be used for the entire duration of the
 * packet send operation. Note that the thread may be preempted and run on
 * another cpu any time and so we can't use 'CPU' more than once for the
 * operation.
 */
#define	MAC_TX_TRY_HOLD(mcip, mytx, error)				\
{									\
	(error) = 0;							\
	(mytx) = &(mcip)->mci_tx_pcpu[CPU->cpu_seqid & mac_tx_percpu_cnt]; \
	mutex_enter(&(mytx)->pcpu_tx_lock);				\
	if (!((mcip)->mci_tx_flag & MCI_TX_QUIESCE)) {			\
		(mytx)->pcpu_tx_refcnt++;				\
	} else {							\
		(error) = -1;						\
	}								\
	mutex_exit(&(mytx)->pcpu_tx_lock);				\
}

/*
 * Release the reference. If needed, signal any control operation waiting
 * for Tx quiescence. The wait and signal are always done using the
 * mci_tx_pcpu[0]'s lock
 */
#define	MAC_TX_RELE(mcip, mytx) {					\
	mutex_enter(&(mytx)->pcpu_tx_lock);				\
	if (--(mytx)->pcpu_tx_refcnt == 0 &&				\
	    (mcip)->mci_tx_flag & MCI_TX_QUIESCE) {			\
		mutex_exit(&(mytx)->pcpu_tx_lock);			\
		mutex_enter(&(mcip)->mci_tx_pcpu[0].pcpu_tx_lock);	\
		cv_signal(&(mcip)->mci_tx_cv);				\
		mutex_exit(&(mcip)->mci_tx_pcpu[0].pcpu_tx_lock);	\
	} else {							\
		mutex_exit(&(mytx)->pcpu_tx_lock);			\
	}								\
}

/*
 * Send function invoked by MAC clients.
 */
mac_tx_cookie_t
mac_tx(mac_client_handle_t mch, mblk_t *mp_chain, uintptr_t hint,
    uint16_t flag, mblk_t **ret_mp)
{
	mac_tx_cookie_t		cookie = NULL;
	int			error;
	mac_tx_percpu_t		*mytx;
	mac_soft_ring_set_t	*srs;
	flow_entry_t		*flent;
	boolean_t		is_subflow = B_FALSE;
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	mac_srs_tx_t		*srs_tx;

	/*
	 * Check whether the active Tx threads count is bumped already.
	 */
	if (!(flag & MAC_TX_NO_HOLD)) {
		MAC_TX_TRY_HOLD(mcip, mytx, error);
		if (error != 0) {
			freemsgchain(mp_chain);
			return (NULL);
		}
	}

	/*
	 * If mac protection is enabled, only the permissible packets will be
	 * returned by mac_protect_check().
	 */
	if ((mcip->mci_flent->
	    fe_resource_props.mrp_mask & MRP_PROTECT) != 0 &&
	    (mp_chain = mac_protect_check(mch, mp_chain)) == NULL)
		goto done;

	if (mcip->mci_subflow_tab != NULL &&
	    mcip->mci_subflow_tab->ft_flow_count > 0 &&
	    mac_flow_lookup(mcip->mci_subflow_tab, mp_chain,
	    FLOW_OUTBOUND, &flent) == 0) {
		/*
		 * The main assumption here is that if in the event
		 * we get a chain, all the packets will be classified
		 * to the same Flow/SRS. If this changes for any
		 * reason, the following logic should change as well.
		 * I suppose the fanout_hint also assumes this .
		 */
		ASSERT(flent != NULL);
		is_subflow = B_TRUE;
	} else {
		flent = mcip->mci_flent;
	}

	srs = flent->fe_tx_srs;
	/*
	 * This is to avoid panics with PF_PACKET that can call mac_tx()
	 * against an interface that is not capable of sending. A rewrite
	 * of the mac datapath is required to remove this limitation.
	 */
	if (srs == NULL) {
		freemsgchain(mp_chain);
		goto done;
	}

	srs_tx = &srs->srs_tx;
	if (srs_tx->st_mode == SRS_TX_DEFAULT &&
	    (srs->srs_state & SRS_ENQUEUED) == 0 &&
	    mip->mi_nactiveclients == 1 && mp_chain->b_next == NULL) {
		uint64_t	obytes;

		/*
		 * Since dls always opens the underlying MAC, nclients equals
		 * to 1 means that the only active client is dls itself acting
		 * as a primary client of the MAC instance. Since dls will not
		 * send tagged packets in that case, and dls is trusted to send
		 * packets for its allowed VLAN(s), the VLAN tag insertion and
		 * check is required only if nclients is greater than 1.
		 */
		if (mip->mi_nclients > 1) {
			if (MAC_VID_CHECK_NEEDED(mcip)) {
				int	err = 0;

				MAC_VID_CHECK(mcip, mp_chain, err);
				if (err != 0) {
					freemsg(mp_chain);
					mcip->mci_misc_stat.mms_txerrors++;
					goto done;
				}
			}
			if (MAC_TAG_NEEDED(mcip)) {
				mp_chain = mac_add_vlan_tag(mp_chain, 0,
				    mac_client_vid(mch));
				if (mp_chain == NULL) {
					mcip->mci_misc_stat.mms_txerrors++;
					goto done;
				}
			}
		}

		obytes = (mp_chain->b_cont == NULL ? MBLKL(mp_chain) :
		    msgdsize(mp_chain));

		MAC_TX(mip, srs_tx->st_arg2, mp_chain, mcip);
		if (mp_chain == NULL) {
			cookie = NULL;
			SRS_TX_STAT_UPDATE(srs, opackets, 1);
			SRS_TX_STAT_UPDATE(srs, obytes, obytes);
		} else {
			mutex_enter(&srs->srs_lock);
			cookie = mac_tx_srs_no_desc(srs, mp_chain,
			    flag, ret_mp);
			mutex_exit(&srs->srs_lock);
		}
	} else {
		cookie = srs_tx->st_func(srs, mp_chain, hint, flag, ret_mp);
	}

done:
	if (is_subflow)
		FLOW_REFRELE(flent);

	if (!(flag & MAC_TX_NO_HOLD))
		MAC_TX_RELE(mcip, mytx);

	return (cookie);
}

/*
 * mac_tx_is_blocked
 *
 * Given a cookie, it returns if the ring identified by the cookie is
 * flow-controlled or not. If NULL is passed in place of a cookie,
 * then it finds out if any of the underlying rings belonging to the
 * SRS is flow controlled or not and returns that status.
 */
/* ARGSUSED */
boolean_t
mac_tx_is_flow_blocked(mac_client_handle_t mch, mac_tx_cookie_t cookie)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_soft_ring_set_t *mac_srs;
	mac_soft_ring_t *sringp;
	boolean_t blocked = B_FALSE;
	mac_tx_percpu_t *mytx;
	int err;
	int i;

	/*
	 * Bump the reference count so that mac_srs won't be deleted.
	 * If the client is currently quiesced and we failed to bump
	 * the reference, return B_TRUE so that flow control stays
	 * as enabled.
	 *
	 * Flow control will then be disabled once the client is no
	 * longer quiesced.
	 */
	MAC_TX_TRY_HOLD(mcip, mytx, err);
	if (err != 0)
		return (B_TRUE);

	if ((mac_srs = MCIP_TX_SRS(mcip)) == NULL) {
		MAC_TX_RELE(mcip, mytx);
		return (B_FALSE);
	}

	mutex_enter(&mac_srs->srs_lock);
	/*
	 * Only in the case of TX_FANOUT and TX_AGGR, the underlying
	 * softring (s_ring_state) will have the HIWAT set. This is
	 * the multiple Tx ring flow control case. For all other
	 * case, SRS (srs_state) will store the condition.
	 */
	if (mac_srs->srs_tx.st_mode == SRS_TX_FANOUT ||
	    mac_srs->srs_tx.st_mode == SRS_TX_AGGR) {
		if (cookie != NULL) {
			sringp = (mac_soft_ring_t *)cookie;
			mutex_enter(&sringp->s_ring_lock);
			if (sringp->s_ring_state & S_RING_TX_HIWAT)
				blocked = B_TRUE;
			mutex_exit(&sringp->s_ring_lock);
		} else {
			for (i = 0; i < mac_srs->srs_tx_ring_count; i++) {
				sringp = mac_srs->srs_tx_soft_rings[i];
				mutex_enter(&sringp->s_ring_lock);
				if (sringp->s_ring_state & S_RING_TX_HIWAT) {
					blocked = B_TRUE;
					mutex_exit(&sringp->s_ring_lock);
					break;
				}
				mutex_exit(&sringp->s_ring_lock);
			}
		}
	} else {
		blocked = (mac_srs->srs_state & SRS_TX_HIWAT);
	}
	mutex_exit(&mac_srs->srs_lock);
	MAC_TX_RELE(mcip, mytx);
	return (blocked);
}

/*
 * Check if the MAC client is the primary MAC client.
 */
boolean_t
mac_is_primary_client(mac_client_impl_t *mcip)
{
	return (mcip->mci_flags & MAC_CLIENT_FLAGS_PRIMARY);
}

void
mac_ioctl(mac_handle_t mh, queue_t *wq, mblk_t *bp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int cmd = ((struct iocblk *)bp->b_rptr)->ioc_cmd;

	if ((cmd == ND_GET && (mip->mi_callbacks->mc_callbacks & MC_GETPROP)) ||
	    (cmd == ND_SET && (mip->mi_callbacks->mc_callbacks & MC_SETPROP))) {
		/*
		 * If ndd props were registered, call them.
		 * Note that ndd ioctls are Obsolete
		 */
		mac_ndd_ioctl(mip, wq, bp);
		return;
	}

	/*
	 * Call the driver to handle the ioctl.  The driver may not support
	 * any ioctls, in which case we reply with a NAK on its behalf.
	 */
	if (mip->mi_callbacks->mc_callbacks & MC_IOCTL)
		mip->mi_ioctl(mip->mi_driver, wq, bp);
	else
		miocnak(wq, bp, 0, EINVAL);
}

/*
 * Return the link state of the specified MAC instance.
 */
link_state_t
mac_link_get(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_linkstate);
}

/*
 * Add a mac client specified notification callback. Please see the comments
 * above mac_callback_add() for general information about mac callback
 * addition/deletion in the presence of mac callback list walkers
 */
mac_notify_handle_t
mac_notify_add(mac_handle_t mh, mac_notify_t notify_fn, void *arg)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_notify_cb_t		*mncb;
	mac_cb_info_t		*mcbi;

	/*
	 * Allocate a notify callback structure, fill in the details and
	 * use the mac callback list manipulation functions to chain into
	 * the list of callbacks.
	 */
	mncb = kmem_zalloc(sizeof (mac_notify_cb_t), KM_SLEEP);
	mncb->mncb_fn = notify_fn;
	mncb->mncb_arg = arg;
	mncb->mncb_mip = mip;
	mncb->mncb_link.mcb_objp = mncb;
	mncb->mncb_link.mcb_objsize = sizeof (mac_notify_cb_t);
	mncb->mncb_link.mcb_flags = MCB_NOTIFY_CB_T;

	mcbi = &mip->mi_notify_cb_info;

	i_mac_perim_enter(mip);
	mutex_enter(mcbi->mcbi_lockp);

	mac_callback_add(&mip->mi_notify_cb_info, &mip->mi_notify_cb_list,
	    &mncb->mncb_link);

	mutex_exit(mcbi->mcbi_lockp);
	i_mac_perim_exit(mip);
	return ((mac_notify_handle_t)mncb);
}

void
mac_notify_remove_wait(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_cb_info_t	*mcbi = &mip->mi_notify_cb_info;

	mutex_enter(mcbi->mcbi_lockp);
	mac_callback_remove_wait(&mip->mi_notify_cb_info);
	mutex_exit(mcbi->mcbi_lockp);
}

/*
 * Remove a mac client specified notification callback
 */
int
mac_notify_remove(mac_notify_handle_t mnh, boolean_t wait)
{
	mac_notify_cb_t	*mncb = (mac_notify_cb_t *)mnh;
	mac_impl_t	*mip = mncb->mncb_mip;
	mac_cb_info_t	*mcbi;
	int		err = 0;

	mcbi = &mip->mi_notify_cb_info;

	i_mac_perim_enter(mip);
	mutex_enter(mcbi->mcbi_lockp);

	ASSERT(mncb->mncb_link.mcb_objp == mncb);
	/*
	 * If there aren't any list walkers, the remove would succeed
	 * inline, else we wait for the deferred remove to complete
	 */
	if (mac_callback_remove(&mip->mi_notify_cb_info,
	    &mip->mi_notify_cb_list, &mncb->mncb_link)) {
		kmem_free(mncb, sizeof (mac_notify_cb_t));
	} else {
		err = EBUSY;
	}

	mutex_exit(mcbi->mcbi_lockp);
	i_mac_perim_exit(mip);

	/*
	 * If we failed to remove the notification callback and "wait" is set
	 * to be B_TRUE, wait for the callback to finish after we exit the
	 * mac perimeter.
	 */
	if (err != 0 && wait) {
		mac_notify_remove_wait((mac_handle_t)mip);
		return (0);
	}

	return (err);
}

/*
 * Associate resource management callbacks with the specified MAC
 * clients.
 */

void
mac_resource_set_common(mac_client_handle_t mch, mac_resource_add_t add,
    mac_resource_remove_t remove, mac_resource_quiesce_t quiesce,
    mac_resource_restart_t restart, mac_resource_bind_t bind,
    void *arg)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;

	mcip->mci_resource_add = add;
	mcip->mci_resource_remove = remove;
	mcip->mci_resource_quiesce = quiesce;
	mcip->mci_resource_restart = restart;
	mcip->mci_resource_bind = bind;
	mcip->mci_resource_arg = arg;
}

void
mac_resource_set(mac_client_handle_t mch, mac_resource_add_t add, void *arg)
{
	/* update the 'resource_add' callback */
	mac_resource_set_common(mch, add, NULL, NULL, NULL, NULL, arg);
}

/*
 * Sets up the client resources and enable the polling interface over all the
 * SRS's and the soft rings of the client
 */
void
mac_client_poll_enable(mac_client_handle_t mch)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_soft_ring_set_t	*mac_srs;
	flow_entry_t		*flent;
	int			i;

	flent = mcip->mci_flent;
	ASSERT(flent != NULL);

	mcip->mci_state_flags |= MCIS_CLIENT_POLL_CAPABLE;
	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		mac_srs = (mac_soft_ring_set_t *)flent->fe_rx_srs[i];
		ASSERT(mac_srs->srs_mcip == mcip);
		mac_srs_client_poll_enable(mcip, mac_srs);
	}
}

/*
 * Tears down the client resources and disable the polling interface over all
 * the SRS's and the soft rings of the client
 */
void
mac_client_poll_disable(mac_client_handle_t mch)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_soft_ring_set_t	*mac_srs;
	flow_entry_t		*flent;
	int			i;

	flent = mcip->mci_flent;
	ASSERT(flent != NULL);

	mcip->mci_state_flags &= ~MCIS_CLIENT_POLL_CAPABLE;
	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		mac_srs = (mac_soft_ring_set_t *)flent->fe_rx_srs[i];
		ASSERT(mac_srs->srs_mcip == mcip);
		mac_srs_client_poll_disable(mcip, mac_srs);
	}
}

/*
 * Associate the CPUs specified by the given property with a MAC client.
 */
int
mac_cpu_set(mac_client_handle_t mch, mac_resource_props_t *mrp)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	int err = 0;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	if ((err = mac_validate_props(mcip->mci_state_flags & MCIS_IS_VNIC ?
	    mcip->mci_upper_mip : mip, mrp)) != 0) {
		return (err);
	}
	if (MCIP_DATAPATH_SETUP(mcip))
		mac_flow_modify(mip->mi_flow_tab, mcip->mci_flent, mrp);

	mac_update_resources(mrp, MCIP_RESOURCE_PROPS(mcip), B_FALSE);
	return (0);
}

/*
 * Apply the specified properties to the specified MAC client.
 */
int
mac_client_set_resources(mac_client_handle_t mch, mac_resource_props_t *mrp)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	int err = 0;

	i_mac_perim_enter(mip);

	if ((mrp->mrp_mask & MRP_MAXBW) || (mrp->mrp_mask & MRP_PRIORITY)) {
		err = mac_resource_ctl_set(mch, mrp);
		if (err != 0)
			goto done;
	}

	if (mrp->mrp_mask & (MRP_CPUS|MRP_POOL)) {
		err = mac_cpu_set(mch, mrp);
		if (err != 0)
			goto done;
	}

	if (mrp->mrp_mask & MRP_PROTECT) {
		err = mac_protect_set(mch, mrp);
		if (err != 0)
			goto done;
	}

	if ((mrp->mrp_mask & MRP_RX_RINGS) || (mrp->mrp_mask & MRP_TX_RINGS))
		err = mac_resource_ctl_set(mch, mrp);

done:
	i_mac_perim_exit(mip);
	return (err);
}

/*
 * Return the properties currently associated with the specified MAC client.
 */
void
mac_client_get_resources(mac_client_handle_t mch, mac_resource_props_t *mrp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_resource_props_t	*mcip_mrp = MCIP_RESOURCE_PROPS(mcip);

	bcopy(mcip_mrp, mrp, sizeof (mac_resource_props_t));
}

/*
 * Return the effective properties currently associated with the specified
 * MAC client.
 */
void
mac_client_get_effective_resources(mac_client_handle_t mch,
    mac_resource_props_t *mrp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_resource_props_t	*mcip_mrp = MCIP_EFFECTIVE_PROPS(mcip);

	bcopy(mcip_mrp, mrp, sizeof (mac_resource_props_t));
}

/*
 * Pass a copy of the specified packet to the promiscuous callbacks
 * of the specified MAC.
 *
 * If sender is NULL, the function is being invoked for a packet chain
 * received from the wire. If sender is non-NULL, it points to
 * the MAC client from which the packet is being sent.
 *
 * The packets are distributed to the promiscuous callbacks as follows:
 *
 * - all packets are sent to the MAC_CLIENT_PROMISC_ALL callbacks
 * - all broadcast and multicast packets are sent to the
 *   MAC_CLIENT_PROMISC_FILTER and MAC_CLIENT_PROMISC_MULTI.
 *
 * The unicast packets of MAC_CLIENT_PROMISC_FILTER callbacks are dispatched
 * after classification by mac_rx_deliver().
 */

static void
mac_promisc_dispatch_one(mac_promisc_impl_t *mpip, mblk_t *mp,
    boolean_t loopback)
{
	mblk_t *mp_copy, *mp_next;

	if (!mpip->mpi_no_copy || mpip->mpi_strip_vlan_tag) {
		mp_copy = copymsg(mp);
		if (mp_copy == NULL)
			return;

		if (mpip->mpi_strip_vlan_tag) {
			mp_copy = mac_strip_vlan_tag_chain(mp_copy);
			if (mp_copy == NULL)
				return;
		}
		mp_next = NULL;
	} else {
		mp_copy = mp;
		mp_next = mp->b_next;
	}
	mp_copy->b_next = NULL;

	mpip->mpi_fn(mpip->mpi_arg, NULL, mp_copy, loopback);
	if (mp_copy == mp)
		mp->b_next = mp_next;
}

/*
 * Return the VID of a packet. Zero if the packet is not tagged.
 */
static uint16_t
mac_ether_vid(mblk_t *mp)
{
	struct ether_header *eth = (struct ether_header *)mp->b_rptr;

	if (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
		struct ether_vlan_header *t_evhp =
		    (struct ether_vlan_header *)mp->b_rptr;
		return (VLAN_ID(ntohs(t_evhp->ether_tci)));
	}

	return (0);
}

/*
 * Return whether the specified packet contains a multicast or broadcast
 * destination MAC address.
 */
static boolean_t
mac_is_mcast(mac_impl_t *mip, mblk_t *mp)
{
	mac_header_info_t hdr_info;

	if (mac_header_info((mac_handle_t)mip, mp, &hdr_info) != 0)
		return (B_FALSE);
	return ((hdr_info.mhi_dsttype == MAC_ADDRTYPE_BROADCAST) ||
	    (hdr_info.mhi_dsttype == MAC_ADDRTYPE_MULTICAST));
}

/*
 * Send a copy of an mblk chain to the MAC clients of the specified MAC.
 * "sender" points to the sender MAC client for outbound packets, and
 * is set to NULL for inbound packets.
 */
void
mac_promisc_dispatch(mac_impl_t *mip, mblk_t *mp_chain,
    mac_client_impl_t *sender)
{
	mac_promisc_impl_t *mpip;
	mac_cb_t *mcb;
	mblk_t *mp;
	boolean_t is_mcast, is_sender;

	MAC_PROMISC_WALKER_INC(mip);
	for (mp = mp_chain; mp != NULL; mp = mp->b_next) {
		is_mcast = mac_is_mcast(mip, mp);
		/* send packet to interested callbacks */
		for (mcb = mip->mi_promisc_list; mcb != NULL;
		    mcb = mcb->mcb_nextp) {
			mpip = (mac_promisc_impl_t *)mcb->mcb_objp;
			is_sender = (mpip->mpi_mcip == sender);

			if (is_sender && mpip->mpi_no_tx_loop)
				/*
				 * The sender doesn't want to receive
				 * copies of the packets it sends.
				 */
				continue;

			/* this client doesn't need any packets (bridge) */
			if (mpip->mpi_fn == NULL)
				continue;

			/*
			 * For an ethernet MAC, don't displatch a multicast
			 * packet to a non-PROMISC_ALL callbacks unless the VID
			 * of the packet matches the VID of the client.
			 */
			if (is_mcast &&
			    mpip->mpi_type != MAC_CLIENT_PROMISC_ALL &&
			    !mac_client_check_flow_vid(mpip->mpi_mcip,
			    mac_ether_vid(mp)))
				continue;

			if (is_sender ||
			    mpip->mpi_type == MAC_CLIENT_PROMISC_ALL ||
			    is_mcast)
				mac_promisc_dispatch_one(mpip, mp, is_sender);
		}
	}
	MAC_PROMISC_WALKER_DCR(mip);
}

void
mac_promisc_client_dispatch(mac_client_impl_t *mcip, mblk_t *mp_chain)
{
	mac_impl_t		*mip = mcip->mci_mip;
	mac_promisc_impl_t	*mpip;
	boolean_t		is_mcast;
	mblk_t			*mp;
	mac_cb_t		*mcb;

	/*
	 * The unicast packets for the MAC client still
	 * need to be delivered to the MAC_CLIENT_PROMISC_FILTERED
	 * promiscuous callbacks. The broadcast and multicast
	 * packets were delivered from mac_rx().
	 */
	MAC_PROMISC_WALKER_INC(mip);
	for (mp = mp_chain; mp != NULL; mp = mp->b_next) {
		is_mcast = mac_is_mcast(mip, mp);
		for (mcb = mcip->mci_promisc_list; mcb != NULL;
		    mcb = mcb->mcb_nextp) {
			mpip = (mac_promisc_impl_t *)mcb->mcb_objp;
			if (mpip->mpi_type == MAC_CLIENT_PROMISC_FILTERED &&
			    !is_mcast) {
				mac_promisc_dispatch_one(mpip, mp, B_FALSE);
			}
		}
	}
	MAC_PROMISC_WALKER_DCR(mip);
}

/*
 * Return the margin value currently assigned to the specified MAC instance.
 */
void
mac_margin_get(mac_handle_t mh, uint32_t *marginp)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	rw_enter(&(mip->mi_rw_lock), RW_READER);
	*marginp = mip->mi_margin;
	rw_exit(&(mip->mi_rw_lock));
}

/*
 * mac_info_get() is used for retrieving the mac_info when a DL_INFO_REQ is
 * issued before a DL_ATTACH_REQ. we walk the i_mac_impl_hash table and find
 * the first mac_impl_t with a matching driver name; then we copy its mac_info_t
 * to the caller. we do all this with i_mac_impl_lock held so the mac_impl_t
 * cannot disappear while we are accessing it.
 */
typedef struct i_mac_info_state_s {
	const char	*mi_name;
	mac_info_t	*mi_infop;
} i_mac_info_state_t;

/*ARGSUSED*/
static uint_t
i_mac_info_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	i_mac_info_state_t *statep = arg;
	mac_impl_t *mip = (mac_impl_t *)val;

	if (mip->mi_state_flags & MIS_DISABLED)
		return (MH_WALK_CONTINUE);

	if (strcmp(statep->mi_name,
	    ddi_driver_name(mip->mi_dip)) != 0)
		return (MH_WALK_CONTINUE);

	statep->mi_infop = &mip->mi_info;
	return (MH_WALK_TERMINATE);
}

boolean_t
mac_info_get(const char *name, mac_info_t *minfop)
{
	i_mac_info_state_t state;

	rw_enter(&i_mac_impl_lock, RW_READER);
	state.mi_name = name;
	state.mi_infop = NULL;
	mod_hash_walk(i_mac_impl_hash, i_mac_info_walker, &state);
	if (state.mi_infop == NULL) {
		rw_exit(&i_mac_impl_lock);
		return (B_FALSE);
	}
	*minfop = *state.mi_infop;
	rw_exit(&i_mac_impl_lock);
	return (B_TRUE);
}

/*
 * To get the capabilities that MAC layer cares about, such as rings, factory
 * mac address, vnic or not, it should directly invoke this function.  If the
 * link is part of a bridge, then the only "capability" it has is the inability
 * to do zero copy.
 */
boolean_t
i_mac_capab_get(mac_handle_t mh, mac_capab_t cap, void *cap_data)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	if (mip->mi_bridge_link != NULL)
		return (cap == MAC_CAPAB_NO_ZCOPY);
	else if (mip->mi_callbacks->mc_callbacks & MC_GETCAPAB)
		return (mip->mi_getcapab(mip->mi_driver, cap, cap_data));
	else
		return (B_FALSE);
}

/*
 * Capability query function. If number of active mac clients is greater than
 * 1, only limited capabilities can be advertised to the caller no matter the
 * driver has certain capability or not. Else, we query the driver to get the
 * capability.
 */
boolean_t
mac_capab_get(mac_handle_t mh, mac_capab_t cap, void *cap_data)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	/*
	 * if mi_nactiveclients > 1, only MAC_CAPAB_LEGACY, MAC_CAPAB_HCKSUM,
	 * MAC_CAPAB_NO_NATIVEVLAN and MAC_CAPAB_NO_ZCOPY can be advertised.
	 */
	if (mip->mi_nactiveclients > 1) {
		switch (cap) {
		case MAC_CAPAB_NO_ZCOPY:
			return (B_TRUE);
		case MAC_CAPAB_LEGACY:
		case MAC_CAPAB_HCKSUM:
		case MAC_CAPAB_NO_NATIVEVLAN:
			break;
		default:
			return (B_FALSE);
		}
	}

	/* else get capab from driver */
	return (i_mac_capab_get(mh, cap, cap_data));
}

boolean_t
mac_sap_verify(mac_handle_t mh, uint32_t sap, uint32_t *bind_sap)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_type->mt_ops.mtops_sap_verify(sap, bind_sap,
	    mip->mi_pdata));
}

mblk_t *
mac_header(mac_handle_t mh, const uint8_t *daddr, uint32_t sap, mblk_t *payload,
    size_t extra_len)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	const uint8_t	*hdr_daddr;

	/*
	 * If the MAC is point-to-point with a fixed destination address, then
	 * we must always use that destination in the MAC header.
	 */
	hdr_daddr = (mip->mi_dstaddr_set ? mip->mi_dstaddr : daddr);
	return (mip->mi_type->mt_ops.mtops_header(mip->mi_addr, hdr_daddr, sap,
	    mip->mi_pdata, payload, extra_len));
}

int
mac_header_info(mac_handle_t mh, mblk_t *mp, mac_header_info_t *mhip)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_type->mt_ops.mtops_header_info(mp, mip->mi_pdata,
	    mhip));
}

int
mac_vlan_header_info(mac_handle_t mh, mblk_t *mp, mac_header_info_t *mhip)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	boolean_t	is_ethernet = (mip->mi_info.mi_media == DL_ETHER);
	int		err = 0;

	/*
	 * Packets should always be at least 16 bit aligned.
	 */
	ASSERT(IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)));

	if ((err = mac_header_info(mh, mp, mhip)) != 0)
		return (err);

	/*
	 * If this is a VLAN-tagged Ethernet packet, then the SAP in the
	 * mac_header_info_t as returned by mac_header_info() is
	 * ETHERTYPE_VLAN. We need to grab the ethertype from the VLAN header.
	 */
	if (is_ethernet && (mhip->mhi_bindsap == ETHERTYPE_VLAN)) {
		struct ether_vlan_header *evhp;
		uint16_t sap;
		mblk_t *tmp = NULL;
		size_t size;

		size = sizeof (struct ether_vlan_header);
		if (MBLKL(mp) < size) {
			/*
			 * Pullup the message in order to get the MAC header
			 * infomation. Note that this is a read-only function,
			 * we keep the input packet intact.
			 */
			if ((tmp = msgpullup(mp, size)) == NULL)
				return (EINVAL);

			mp = tmp;
		}
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		sap = ntohs(evhp->ether_type);
		(void) mac_sap_verify(mh, sap, &mhip->mhi_bindsap);
		mhip->mhi_hdrsize = sizeof (struct ether_vlan_header);
		mhip->mhi_tci = ntohs(evhp->ether_tci);
		mhip->mhi_istagged = B_TRUE;
		freemsg(tmp);

		if (VLAN_CFI(mhip->mhi_tci) != ETHER_CFI)
			return (EINVAL);
	} else {
		mhip->mhi_istagged = B_FALSE;
		mhip->mhi_tci = 0;
	}

	return (0);
}

mblk_t *
mac_header_cook(mac_handle_t mh, mblk_t *mp)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	if (mip->mi_type->mt_ops.mtops_ops & MTOPS_HEADER_COOK) {
		if (DB_REF(mp) > 1) {
			mblk_t *newmp = copymsg(mp);
			if (newmp == NULL)
				return (NULL);
			freemsg(mp);
			mp = newmp;
		}
		return (mip->mi_type->mt_ops.mtops_header_cook(mp,
		    mip->mi_pdata));
	}
	return (mp);
}

mblk_t *
mac_header_uncook(mac_handle_t mh, mblk_t *mp)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	if (mip->mi_type->mt_ops.mtops_ops & MTOPS_HEADER_UNCOOK) {
		if (DB_REF(mp) > 1) {
			mblk_t *newmp = copymsg(mp);
			if (newmp == NULL)
				return (NULL);
			freemsg(mp);
			mp = newmp;
		}
		return (mip->mi_type->mt_ops.mtops_header_uncook(mp,
		    mip->mi_pdata));
	}
	return (mp);
}

uint_t
mac_addr_len(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_type->mt_addr_length);
}

/* True if a MAC is a VNIC */
boolean_t
mac_is_vnic(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_state_flags & MIS_IS_VNIC);
}

mac_handle_t
mac_get_lower_mac_handle(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	ASSERT(mac_is_vnic(mh));
	return (((vnic_t *)mip->mi_driver)->vn_lower_mh);
}

boolean_t
mac_is_vnic_primary(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	ASSERT(mac_is_vnic(mh));
	return (((vnic_t *)mip->mi_driver)->vn_addr_type ==
	    VNIC_MAC_ADDR_TYPE_PRIMARY);
}

void
mac_update_resources(mac_resource_props_t *nmrp, mac_resource_props_t *cmrp,
    boolean_t is_user_flow)
{
	if (nmrp != NULL && cmrp != NULL) {
		if (nmrp->mrp_mask & MRP_PRIORITY) {
			if (nmrp->mrp_priority == MPL_RESET) {
				cmrp->mrp_mask &= ~MRP_PRIORITY;
				if (is_user_flow) {
					cmrp->mrp_priority =
					    MPL_SUBFLOW_DEFAULT;
				} else {
					cmrp->mrp_priority = MPL_LINK_DEFAULT;
				}
			} else {
				cmrp->mrp_mask |= MRP_PRIORITY;
				cmrp->mrp_priority = nmrp->mrp_priority;
			}
		}
		if (nmrp->mrp_mask & MRP_MAXBW) {
			if (nmrp->mrp_maxbw == MRP_MAXBW_RESETVAL) {
				cmrp->mrp_mask &= ~MRP_MAXBW;
				cmrp->mrp_maxbw = 0;
			} else {
				cmrp->mrp_mask |= MRP_MAXBW;
				cmrp->mrp_maxbw = nmrp->mrp_maxbw;
			}
		}
		if (nmrp->mrp_mask & MRP_CPUS)
			MAC_COPY_CPUS(nmrp, cmrp);

		if (nmrp->mrp_mask & MRP_POOL) {
			if (strlen(nmrp->mrp_pool) == 0) {
				cmrp->mrp_mask &= ~MRP_POOL;
				bzero(cmrp->mrp_pool, sizeof (cmrp->mrp_pool));
			} else {
				cmrp->mrp_mask |= MRP_POOL;
				(void) strncpy(cmrp->mrp_pool, nmrp->mrp_pool,
				    sizeof (cmrp->mrp_pool));
			}

		}

		if (nmrp->mrp_mask & MRP_PROTECT)
			mac_protect_update(nmrp, cmrp);

		/*
		 * Update the rings specified.
		 */
		if (nmrp->mrp_mask & MRP_RX_RINGS) {
			if (nmrp->mrp_mask & MRP_RINGS_RESET) {
				cmrp->mrp_mask &= ~MRP_RX_RINGS;
				if (cmrp->mrp_mask & MRP_RXRINGS_UNSPEC)
					cmrp->mrp_mask &= ~MRP_RXRINGS_UNSPEC;
				cmrp->mrp_nrxrings = 0;
			} else {
				cmrp->mrp_mask |= MRP_RX_RINGS;
				cmrp->mrp_nrxrings = nmrp->mrp_nrxrings;
			}
		}
		if (nmrp->mrp_mask & MRP_TX_RINGS) {
			if (nmrp->mrp_mask & MRP_RINGS_RESET) {
				cmrp->mrp_mask &= ~MRP_TX_RINGS;
				if (cmrp->mrp_mask & MRP_TXRINGS_UNSPEC)
					cmrp->mrp_mask &= ~MRP_TXRINGS_UNSPEC;
				cmrp->mrp_ntxrings = 0;
			} else {
				cmrp->mrp_mask |= MRP_TX_RINGS;
				cmrp->mrp_ntxrings = nmrp->mrp_ntxrings;
			}
		}
		if (nmrp->mrp_mask & MRP_RXRINGS_UNSPEC)
			cmrp->mrp_mask |= MRP_RXRINGS_UNSPEC;
		else if (cmrp->mrp_mask & MRP_RXRINGS_UNSPEC)
			cmrp->mrp_mask &= ~MRP_RXRINGS_UNSPEC;

		if (nmrp->mrp_mask & MRP_TXRINGS_UNSPEC)
			cmrp->mrp_mask |= MRP_TXRINGS_UNSPEC;
		else if (cmrp->mrp_mask & MRP_TXRINGS_UNSPEC)
			cmrp->mrp_mask &= ~MRP_TXRINGS_UNSPEC;
	}
}

/*
 * i_mac_set_resources:
 *
 * This routine associates properties with the primary MAC client of
 * the specified MAC instance.
 * - Cache the properties in mac_impl_t
 * - Apply the properties to the primary MAC client if exists
 */
int
i_mac_set_resources(mac_handle_t mh, mac_resource_props_t *mrp)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_client_impl_t	*mcip;
	int			err = 0;
	uint32_t		resmask, newresmask;
	mac_resource_props_t	*tmrp, *umrp;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	err = mac_validate_props(mip, mrp);
	if (err != 0)
		return (err);

	umrp = kmem_zalloc(sizeof (*umrp), KM_SLEEP);
	bcopy(&mip->mi_resource_props, umrp, sizeof (*umrp));
	resmask = umrp->mrp_mask;
	mac_update_resources(mrp, umrp, B_FALSE);
	newresmask = umrp->mrp_mask;

	if (resmask == 0 && newresmask != 0) {
		/*
		 * Bandwidth, priority, cpu or pool link properties configured,
		 * must disable fastpath.
		 */
		if ((err = mac_fastpath_disable((mac_handle_t)mip)) != 0) {
			kmem_free(umrp, sizeof (*umrp));
			return (err);
		}
	}

	/*
	 * Since bind_cpu may be modified by mac_client_set_resources()
	 * we use a copy of bind_cpu and finally cache bind_cpu in mip.
	 * This allows us to cache only user edits in mip.
	 */
	tmrp = kmem_zalloc(sizeof (*tmrp), KM_SLEEP);
	bcopy(mrp, tmrp, sizeof (*tmrp));
	mcip = mac_primary_client_handle(mip);
	if (mcip != NULL && (mcip->mci_state_flags & MCIS_IS_AGGR_PORT) == 0) {
		err = mac_client_set_resources((mac_client_handle_t)mcip, tmrp);
	} else if ((mrp->mrp_mask & MRP_RX_RINGS ||
	    mrp->mrp_mask & MRP_TX_RINGS)) {
		mac_client_impl_t	*vmcip;

		/*
		 * If the primary is not up, we need to check if there
		 * are any VLANs on this primary. If there are then
		 * we need to set this property on the VLANs since
		 * VLANs follow the primary they are based on. Just
		 * look for the first VLAN and change its properties,
		 * all the other VLANs should be in the same group.
		 */
		for (vmcip = mip->mi_clients_list; vmcip != NULL;
		    vmcip = vmcip->mci_client_next) {
			if ((vmcip->mci_flent->fe_type & FLOW_PRIMARY_MAC) &&
			    mac_client_vid((mac_client_handle_t)vmcip) !=
			    VLAN_ID_NONE) {
				break;
			}
		}
		if (vmcip != NULL) {
			mac_resource_props_t	*omrp;
			mac_resource_props_t	*vmrp;

			omrp = kmem_zalloc(sizeof (*omrp), KM_SLEEP);
			bcopy(MCIP_RESOURCE_PROPS(vmcip), omrp, sizeof (*omrp));
			/*
			 * We dont' call mac_update_resources since we
			 * want to take only the ring properties and
			 * not all the properties that may have changed.
			 */
			vmrp = MCIP_RESOURCE_PROPS(vmcip);
			if (mrp->mrp_mask & MRP_RX_RINGS) {
				if (mrp->mrp_mask & MRP_RINGS_RESET) {
					vmrp->mrp_mask &= ~MRP_RX_RINGS;
					if (vmrp->mrp_mask &
					    MRP_RXRINGS_UNSPEC) {
						vmrp->mrp_mask &=
						    ~MRP_RXRINGS_UNSPEC;
					}
					vmrp->mrp_nrxrings = 0;
				} else {
					vmrp->mrp_mask |= MRP_RX_RINGS;
					vmrp->mrp_nrxrings = mrp->mrp_nrxrings;
				}
			}
			if (mrp->mrp_mask & MRP_TX_RINGS) {
				if (mrp->mrp_mask & MRP_RINGS_RESET) {
					vmrp->mrp_mask &= ~MRP_TX_RINGS;
					if (vmrp->mrp_mask &
					    MRP_TXRINGS_UNSPEC) {
						vmrp->mrp_mask &=
						    ~MRP_TXRINGS_UNSPEC;
					}
					vmrp->mrp_ntxrings = 0;
				} else {
					vmrp->mrp_mask |= MRP_TX_RINGS;
					vmrp->mrp_ntxrings = mrp->mrp_ntxrings;
				}
			}
			if (mrp->mrp_mask & MRP_RXRINGS_UNSPEC)
				vmrp->mrp_mask |= MRP_RXRINGS_UNSPEC;

			if (mrp->mrp_mask & MRP_TXRINGS_UNSPEC)
				vmrp->mrp_mask |= MRP_TXRINGS_UNSPEC;

			if ((err = mac_client_set_rings_prop(vmcip, mrp,
			    omrp)) != 0) {
				bcopy(omrp, MCIP_RESOURCE_PROPS(vmcip),
				    sizeof (*omrp));
			} else {
				mac_set_prim_vlan_rings(mip, vmrp);
			}
			kmem_free(omrp, sizeof (*omrp));
		}
	}

	/* Only update the values if mac_client_set_resources succeeded */
	if (err == 0) {
		bcopy(umrp, &mip->mi_resource_props, sizeof (*umrp));
		/*
		 * If bandwidth, priority or cpu link properties cleared,
		 * renable fastpath.
		 */
		if (resmask != 0 && newresmask == 0)
			mac_fastpath_enable((mac_handle_t)mip);
	} else if (resmask == 0 && newresmask != 0) {
		mac_fastpath_enable((mac_handle_t)mip);
	}
	kmem_free(tmrp, sizeof (*tmrp));
	kmem_free(umrp, sizeof (*umrp));
	return (err);
}

int
mac_set_resources(mac_handle_t mh, mac_resource_props_t *mrp)
{
	int err;

	i_mac_perim_enter((mac_impl_t *)mh);
	err = i_mac_set_resources(mh, mrp);
	i_mac_perim_exit((mac_impl_t *)mh);
	return (err);
}

/*
 * Get the properties cached for the specified MAC instance.
 */
void
mac_get_resources(mac_handle_t mh, mac_resource_props_t *mrp)
{
	mac_impl_t 		*mip = (mac_impl_t *)mh;
	mac_client_impl_t	*mcip;

	mcip = mac_primary_client_handle(mip);
	if (mcip != NULL) {
		mac_client_get_resources((mac_client_handle_t)mcip, mrp);
		return;
	}
	bcopy(&mip->mi_resource_props, mrp, sizeof (mac_resource_props_t));
}

/*
 * Get the effective properties from the primary client of the
 * specified MAC instance.
 */
void
mac_get_effective_resources(mac_handle_t mh, mac_resource_props_t *mrp)
{
	mac_impl_t 		*mip = (mac_impl_t *)mh;
	mac_client_impl_t	*mcip;

	mcip = mac_primary_client_handle(mip);
	if (mcip != NULL) {
		mac_client_get_effective_resources((mac_client_handle_t)mcip,
		    mrp);
		return;
	}
	bzero(mrp, sizeof (mac_resource_props_t));
}

int
mac_set_pvid(mac_handle_t mh, uint16_t pvid)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	mac_client_impl_t *mcip;
	mac_unicast_impl_t *muip;

	i_mac_perim_enter(mip);
	if (pvid != 0) {
		for (mcip = mip->mi_clients_list; mcip != NULL;
		    mcip = mcip->mci_client_next) {
			for (muip = mcip->mci_unicast_list; muip != NULL;
			    muip = muip->mui_next) {
				if (muip->mui_vid == pvid) {
					i_mac_perim_exit(mip);
					return (EBUSY);
				}
			}
		}
	}
	mip->mi_pvid = pvid;
	i_mac_perim_exit(mip);
	return (0);
}

uint16_t
mac_get_pvid(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_pvid);
}

uint32_t
mac_get_llimit(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_llimit);
}

uint32_t
mac_get_ldecay(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_ldecay);
}

/*
 * Rename a mac client, its flow, and the kstat.
 */
int
mac_rename_primary(mac_handle_t mh, const char *new_name)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_client_impl_t	*cur_clnt = NULL;
	flow_entry_t		*fep;

	i_mac_perim_enter(mip);

	/*
	 * VNICs: we need to change the sys flow name and
	 * the associated flow kstat.
	 */
	if (mip->mi_state_flags & MIS_IS_VNIC) {
		mac_client_impl_t *mcip = mac_vnic_lower(mip);
		ASSERT(new_name != NULL);
		mac_rename_flow_names(mcip, new_name);
		mac_stat_rename(mcip);
		goto done;
	}
	/*
	 * This mac may itself be an aggr link, or it may have some client
	 * which is an aggr port. For both cases, we need to change the
	 * aggr port's mac client name, its flow name and the associated flow
	 * kstat.
	 */
	if (mip->mi_state_flags & MIS_IS_AGGR) {
		mac_capab_aggr_t aggr_cap;
		mac_rename_fn_t rename_fn;
		boolean_t ret;

		ASSERT(new_name != NULL);
		ret = i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_AGGR,
		    (void *)(&aggr_cap));
		ASSERT(ret == B_TRUE);
		rename_fn = aggr_cap.mca_rename_fn;
		rename_fn(new_name, mip->mi_driver);
		/*
		 * The aggr's client name and kstat flow name will be
		 * updated below, i.e. via mac_rename_flow_names.
		 */
	}

	for (cur_clnt = mip->mi_clients_list; cur_clnt != NULL;
	    cur_clnt = cur_clnt->mci_client_next) {
		if (cur_clnt->mci_state_flags & MCIS_IS_AGGR_PORT) {
			if (new_name != NULL) {
				char *str_st = cur_clnt->mci_name;
				char *str_del = strchr(str_st, '-');

				ASSERT(str_del != NULL);
				bzero(str_del + 1, MAXNAMELEN -
				    (str_del - str_st + 1));
				bcopy(new_name, str_del + 1,
				    strlen(new_name));
			}
			fep = cur_clnt->mci_flent;
			mac_rename_flow(fep, cur_clnt->mci_name);
			break;
		} else if (new_name != NULL &&
		    cur_clnt->mci_state_flags & MCIS_USE_DATALINK_NAME) {
			mac_rename_flow_names(cur_clnt, new_name);
			break;
		}
	}

	/* Recreate kstats associated with aggr pseudo rings */
	if (mip->mi_state_flags & MIS_IS_AGGR)
		mac_pseudo_ring_stat_rename(mip);

done:
	i_mac_perim_exit(mip);
	return (0);
}

/*
 * Rename the MAC client's flow names
 */
static void
mac_rename_flow_names(mac_client_impl_t *mcip, const char *new_name)
{
	flow_entry_t	*flent;
	uint16_t	vid;
	char		flowname[MAXFLOWNAMELEN];
	mac_impl_t	*mip = mcip->mci_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/*
	 * Use mi_rw_lock to ensure that threads not in the mac perimeter
	 * see a self-consistent value for mci_name
	 */
	rw_enter(&mip->mi_rw_lock, RW_WRITER);
	(void) strlcpy(mcip->mci_name, new_name, sizeof (mcip->mci_name));
	rw_exit(&mip->mi_rw_lock);

	mac_rename_flow(mcip->mci_flent, new_name);

	if (mcip->mci_nflents == 1)
		return;

	/*
	 * We have to rename all the others too, no stats to destroy for
	 * these.
	 */
	for (flent = mcip->mci_flent_list; flent != NULL;
	    flent = flent->fe_client_next) {
		if (flent != mcip->mci_flent) {
			vid = i_mac_flow_vid(flent);
			(void) sprintf(flowname, "%s%u", new_name, vid);
			mac_flow_set_name(flent, flowname);
		}
	}
}


/*
 * Add a flow to the MAC client's flow list - i.e list of MAC/VID tuples
 * defined for the specified MAC client.
 */
static void
mac_client_add_to_flow_list(mac_client_impl_t *mcip, flow_entry_t *flent)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));
	/*
	 * The promisc Rx data path walks the mci_flent_list. Protect by
	 * using mi_rw_lock
	 */
	rw_enter(&mcip->mci_rw_lock, RW_WRITER);

	mcip->mci_vidcache = MCIP_VIDCACHE_INVALID;

	/* Add it to the head */
	flent->fe_client_next = mcip->mci_flent_list;
	mcip->mci_flent_list = flent;
	mcip->mci_nflents++;

	/*
	 * Keep track of the number of non-zero VIDs addresses per MAC
	 * client to avoid figuring it out in the data-path.
	 */
	if (i_mac_flow_vid(flent) != VLAN_ID_NONE)
		mcip->mci_nvids++;

	rw_exit(&mcip->mci_rw_lock);
}

/*
 * Remove a flow entry from the MAC client's list.
 */
static void
mac_client_remove_flow_from_list(mac_client_impl_t *mcip, flow_entry_t *flent)
{
	flow_entry_t	*fe = mcip->mci_flent_list;
	flow_entry_t	*prev_fe = NULL;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));
	/*
	 * The promisc Rx data path walks the mci_flent_list. Protect by
	 * using mci_rw_lock
	 */
	rw_enter(&mcip->mci_rw_lock, RW_WRITER);
	mcip->mci_vidcache = MCIP_VIDCACHE_INVALID;

	while ((fe != NULL) && (fe != flent)) {
		prev_fe = fe;
		fe = fe->fe_client_next;
	}

	ASSERT(fe != NULL);
	if (prev_fe == NULL) {
		/* Deleting the first node */
		mcip->mci_flent_list = fe->fe_client_next;
	} else {
		prev_fe->fe_client_next = fe->fe_client_next;
	}
	mcip->mci_nflents--;

	if (i_mac_flow_vid(flent) != VLAN_ID_NONE)
		mcip->mci_nvids--;

	rw_exit(&mcip->mci_rw_lock);
}

/*
 * Check if the given VID belongs to this MAC client.
 */
boolean_t
mac_client_check_flow_vid(mac_client_impl_t *mcip, uint16_t vid)
{
	flow_entry_t	*flent;
	uint16_t	mci_vid;
	uint32_t	cache = mcip->mci_vidcache;

	/*
	 * In hopes of not having to touch the mci_rw_lock, check to see if
	 * this vid matches our cached result.
	 */
	if (MCIP_VIDCACHE_ISVALID(cache) && MCIP_VIDCACHE_VID(cache) == vid)
		return (MCIP_VIDCACHE_BOOL(cache) ? B_TRUE : B_FALSE);

	/* The mci_flent_list is protected by mci_rw_lock */
	rw_enter(&mcip->mci_rw_lock, RW_WRITER);
	for (flent = mcip->mci_flent_list; flent != NULL;
	    flent = flent->fe_client_next) {
		mci_vid = i_mac_flow_vid(flent);
		if (vid == mci_vid) {
			mcip->mci_vidcache = MCIP_VIDCACHE_CACHE(vid, B_TRUE);
			rw_exit(&mcip->mci_rw_lock);
			return (B_TRUE);
		}
	}

	mcip->mci_vidcache = MCIP_VIDCACHE_CACHE(vid, B_FALSE);
	rw_exit(&mcip->mci_rw_lock);
	return (B_FALSE);
}

/*
 * Get the flow entry for the specified <MAC addr, VID> tuple.
 */
static flow_entry_t *
mac_client_get_flow(mac_client_impl_t *mcip, mac_unicast_impl_t *muip)
{
	mac_address_t *map = mcip->mci_unicast;
	flow_entry_t *flent;
	uint16_t vid;
	flow_desc_t flow_desc;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	mac_flow_get_desc(mcip->mci_flent, &flow_desc);
	if (bcmp(flow_desc.fd_dst_mac, map->ma_addr, map->ma_len) != 0)
		return (NULL);

	for (flent = mcip->mci_flent_list; flent != NULL;
	    flent = flent->fe_client_next) {
		vid = i_mac_flow_vid(flent);
		if (vid == muip->mui_vid) {
			return (flent);
		}
	}

	return (NULL);
}

/*
 * Since mci_flent has the SRSs, when we want to remove it, we replace
 * the flow_desc_t in mci_flent with that of an existing flent and then
 * remove that flent instead of mci_flent.
 */
static flow_entry_t *
mac_client_swap_mciflent(mac_client_impl_t *mcip)
{
	flow_entry_t	*flent = mcip->mci_flent;
	flow_tab_t	*ft = flent->fe_flow_tab;
	flow_entry_t	*flent1;
	flow_desc_t	fl_desc;
	char		fl_name[MAXFLOWNAMELEN];
	int		err;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));
	ASSERT(mcip->mci_nflents > 1);

	/* get the next flent following the primary flent  */
	flent1 = mcip->mci_flent_list->fe_client_next;
	ASSERT(flent1 != NULL && flent1->fe_flow_tab == ft);

	/*
	 * Remove the flent from the flow table before updating the
	 * flow descriptor as the hash depends on the flow descriptor.
	 * This also helps incoming packet classification avoid having
	 * to grab fe_lock. Access to fe_flow_desc of a flent not in the
	 * flow table is done under the fe_lock so that log or stat functions
	 * see a self-consistent fe_flow_desc. The name and desc are specific
	 * to a flow, the rest are shared by all the clients, including
	 * resource control etc.
	 */
	mac_flow_remove(ft, flent, B_TRUE);
	mac_flow_remove(ft, flent1, B_TRUE);

	bcopy(&flent->fe_flow_desc, &fl_desc, sizeof (flow_desc_t));
	bcopy(flent->fe_flow_name, fl_name, MAXFLOWNAMELEN);

	/* update the primary flow entry */
	mutex_enter(&flent->fe_lock);
	bcopy(&flent1->fe_flow_desc, &flent->fe_flow_desc,
	    sizeof (flow_desc_t));
	bcopy(&flent1->fe_flow_name, &flent->fe_flow_name, MAXFLOWNAMELEN);
	mutex_exit(&flent->fe_lock);

	/* update the flow entry that is to be freed */
	mutex_enter(&flent1->fe_lock);
	bcopy(&fl_desc, &flent1->fe_flow_desc, sizeof (flow_desc_t));
	bcopy(fl_name, &flent1->fe_flow_name, MAXFLOWNAMELEN);
	mutex_exit(&flent1->fe_lock);

	/* now reinsert the flow entries in the table */
	err = mac_flow_add(ft, flent);
	ASSERT(err == 0);

	err = mac_flow_add(ft, flent1);
	ASSERT(err == 0);

	return (flent1);
}

/*
 * Return whether there is only one flow entry associated with this
 * MAC client.
 */
static boolean_t
mac_client_single_rcvr(mac_client_impl_t *mcip)
{
	return (mcip->mci_nflents == 1);
}

int
mac_validate_props(mac_impl_t *mip, mac_resource_props_t *mrp)
{
	boolean_t		reset;
	uint32_t		rings_needed;
	uint32_t		rings_avail;
	mac_group_type_t	gtype;
	mac_resource_props_t	*mip_mrp;

	if (mrp == NULL)
		return (0);

	if (mrp->mrp_mask & MRP_PRIORITY) {
		mac_priority_level_t	pri = mrp->mrp_priority;

		if (pri < MPL_LOW || pri > MPL_RESET)
			return (EINVAL);
	}

	if (mrp->mrp_mask & MRP_MAXBW) {
		uint64_t maxbw = mrp->mrp_maxbw;

		if (maxbw < MRP_MAXBW_MINVAL && maxbw != 0)
			return (EINVAL);
	}
	if (mrp->mrp_mask & MRP_CPUS) {
		int i, j;
		mac_cpu_mode_t	fanout;

		if (mrp->mrp_ncpus > ncpus)
			return (EINVAL);

		for (i = 0; i < mrp->mrp_ncpus; i++) {
			for (j = 0; j < mrp->mrp_ncpus; j++) {
				if (i != j &&
				    mrp->mrp_cpu[i] == mrp->mrp_cpu[j]) {
					return (EINVAL);
				}
			}
		}

		for (i = 0; i < mrp->mrp_ncpus; i++) {
			cpu_t *cp;
			int rv;

			mutex_enter(&cpu_lock);
			cp = cpu_get(mrp->mrp_cpu[i]);
			if (cp != NULL)
				rv = cpu_is_online(cp);
			else
				rv = 0;
			mutex_exit(&cpu_lock);
			if (rv == 0)
				return (EINVAL);
		}

		fanout = mrp->mrp_fanout_mode;
		if (fanout < 0 || fanout > MCM_CPUS)
			return (EINVAL);
	}

	if (mrp->mrp_mask & MRP_PROTECT) {
		int err = mac_protect_validate(mrp);
		if (err != 0)
			return (err);
	}

	if (!(mrp->mrp_mask & MRP_RX_RINGS) &&
	    !(mrp->mrp_mask & MRP_TX_RINGS)) {
		return (0);
	}

	/*
	 * mip will be null when we come from mac_flow_create or
	 * mac_link_flow_modify. In the latter case it is a user flow,
	 * for which we don't support rings. In the former we would
	 * have validated the props beforehand (i_mac_unicast_add ->
	 * mac_client_set_resources -> validate for the primary and
	 * vnic_dev_create -> mac_client_set_resources -> validate for
	 * a vnic.
	 */
	if (mip == NULL)
		return (0);

	/*
	 * We don't support setting rings property for a VNIC that is using a
	 * primary address (VLAN)
	 */
	if ((mip->mi_state_flags & MIS_IS_VNIC) &&
	    mac_is_vnic_primary((mac_handle_t)mip)) {
		return (ENOTSUP);
	}

	mip_mrp = &mip->mi_resource_props;
	/*
	 * The rings property should be validated against the NICs
	 * resources
	 */
	if (mip->mi_state_flags & MIS_IS_VNIC)
		mip = (mac_impl_t *)mac_get_lower_mac_handle((mac_handle_t)mip);

	reset = mrp->mrp_mask & MRP_RINGS_RESET;
	/*
	 * If groups are not supported, return error.
	 */
	if (((mrp->mrp_mask & MRP_RX_RINGS) && mip->mi_rx_groups == NULL) ||
	    ((mrp->mrp_mask & MRP_TX_RINGS) && mip->mi_tx_groups == NULL)) {
		return (EINVAL);
	}
	/*
	 * If we are just resetting, there is no validation needed.
	 */
	if (reset)
		return (0);

	if (mrp->mrp_mask & MRP_RX_RINGS) {
		rings_needed = mrp->mrp_nrxrings;
		/*
		 * We just want to check if the number of additional
		 * rings requested is available.
		 */
		if (mip_mrp->mrp_mask & MRP_RX_RINGS) {
			if (mrp->mrp_nrxrings > mip_mrp->mrp_nrxrings)
				/* Just check for the additional rings */
				rings_needed -= mip_mrp->mrp_nrxrings;
			else
				/* We are not asking for additional rings */
				rings_needed = 0;
		}
		rings_avail = mip->mi_rxrings_avail;
		gtype = mip->mi_rx_group_type;
	} else {
		rings_needed = mrp->mrp_ntxrings;
		/* Similarly for the TX rings */
		if (mip_mrp->mrp_mask & MRP_TX_RINGS) {
			if (mrp->mrp_ntxrings > mip_mrp->mrp_ntxrings)
				/* Just check for the additional rings */
				rings_needed -= mip_mrp->mrp_ntxrings;
			else
				/* We are not asking for additional rings */
				rings_needed = 0;
		}
		rings_avail = mip->mi_txrings_avail;
		gtype = mip->mi_tx_group_type;
	}

	/* Error if the group is dynamic .. */
	if (gtype == MAC_GROUP_TYPE_DYNAMIC) {
		/*
		 * .. and rings specified are more than available.
		 */
		if (rings_needed > rings_avail)
			return (EINVAL);
	} else {
		/*
		 * OR group is static and we have specified some rings.
		 */
		if (rings_needed > 0)
			return (EINVAL);
	}
	return (0);
}

/*
 * Send a MAC_NOTE_LINK notification to all the MAC clients whenever the
 * underlying physical link is down. This is to allow MAC clients to
 * communicate with other clients.
 */
void
mac_virtual_link_update(mac_impl_t *mip)
{
	if (mip->mi_linkstate != LINK_STATE_UP)
		i_mac_notify(mip, MAC_NOTE_LINK);
}

/*
 * For clients that have a pass-thru MAC, e.g. VNIC, we set the VNIC's
 * mac handle in the client.
 */
void
mac_set_upper_mac(mac_client_handle_t mch, mac_handle_t mh,
    mac_resource_props_t *mrp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = (mac_impl_t *)mh;

	mcip->mci_upper_mip = mip;
	/* If there are any properties, copy it over too */
	if (mrp != NULL) {
		bcopy(mrp, &mip->mi_resource_props,
		    sizeof (mac_resource_props_t));
	}
}

/*
 * Mark the mac as being used exclusively by the single mac client that is
 * doing some control operation on this mac. No further opens of this mac
 * will be allowed until this client calls mac_unmark_exclusive. The mac
 * client calling this function must already be in the mac perimeter
 */
int
mac_mark_exclusive(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	ASSERT(MAC_PERIM_HELD(mh));
	/*
	 * Look up its entry in the global hash table.
	 */
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	if (mip->mi_state_flags & MIS_DISABLED) {
		rw_exit(&i_mac_impl_lock);
		return (ENOENT);
	}

	/*
	 * A reference to mac is held even if the link is not plumbed.
	 * In i_dls_link_create() we open the MAC interface and hold the
	 * reference. There is an additional reference for the mac_open
	 * done in acquiring the mac perimeter
	 */
	if (mip->mi_ref != 2) {
		rw_exit(&i_mac_impl_lock);
		return (EBUSY);
	}

	ASSERT(!(mip->mi_state_flags & MIS_EXCLUSIVE_HELD));
	mip->mi_state_flags |= MIS_EXCLUSIVE_HELD;
	rw_exit(&i_mac_impl_lock);
	return (0);
}

void
mac_unmark_exclusive(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	ASSERT(MAC_PERIM_HELD(mh));

	rw_enter(&i_mac_impl_lock, RW_WRITER);
	/* 1 for the creation and another for the perimeter */
	ASSERT(mip->mi_ref == 2 && (mip->mi_state_flags & MIS_EXCLUSIVE_HELD));
	mip->mi_state_flags &= ~MIS_EXCLUSIVE_HELD;
	rw_exit(&i_mac_impl_lock);
}

/*
 * Set the MTU for the specified MAC.
 */
int
mac_set_mtu(mac_handle_t mh, uint_t new_mtu, uint_t *old_mtu_arg)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	uint_t old_mtu;
	int rv = 0;

	i_mac_perim_enter(mip);

	if (!(mip->mi_callbacks->mc_callbacks & (MC_SETPROP|MC_GETPROP))) {
		rv = ENOTSUP;
		goto bail;
	}

	old_mtu = mip->mi_sdu_max;

	if (new_mtu == 0 || new_mtu < mip->mi_sdu_min) {
		rv = EINVAL;
		goto bail;
	}

	rw_enter(&mip->mi_rw_lock, RW_READER);
	if (mip->mi_mtrp != NULL && new_mtu < mip->mi_mtrp->mtr_mtu) {
		rv = EBUSY;
		rw_exit(&mip->mi_rw_lock);
		goto bail;
	}
	rw_exit(&mip->mi_rw_lock);

	if (old_mtu != new_mtu) {
		rv = mip->mi_callbacks->mc_setprop(mip->mi_driver,
		    "mtu", MAC_PROP_MTU, sizeof (uint_t), &new_mtu);
		if (rv != 0)
			goto bail;
		rv = mac_maxsdu_update(mh, new_mtu);
		ASSERT(rv == 0);
	}

bail:
	i_mac_perim_exit(mip);

	if (rv == 0 && old_mtu_arg != NULL)
		*old_mtu_arg = old_mtu;
	return (rv);
}

/*
 * Return the RX h/w information for the group indexed by grp_num.
 */
void
mac_get_hwrxgrp_info(mac_handle_t mh, int grp_index, uint_t *grp_num,
    uint_t *n_rings, uint_t *rings, uint_t *type, uint_t *n_clnts,
    char *clnts_name)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	mac_grp_client_t *mcip;
	uint_t i = 0, index = 0;
	mac_ring_t	*ring;

	/* Revisit when we implement fully dynamic group allocation */
	ASSERT(grp_index >= 0 && grp_index < mip->mi_rx_group_count);

	rw_enter(&mip->mi_rw_lock, RW_READER);
	*grp_num = mip->mi_rx_groups[grp_index].mrg_index;
	*type = mip->mi_rx_groups[grp_index].mrg_type;
	*n_rings = mip->mi_rx_groups[grp_index].mrg_cur_count;
	ring = mip->mi_rx_groups[grp_index].mrg_rings;
	for (index = 0; index < mip->mi_rx_groups[grp_index].mrg_cur_count;
	    index++) {
		rings[index] = ring->mr_index;
		ring = ring->mr_next;
	}
	/* Assuming the 1st is the default group */
	index = 0;
	if (grp_index == 0) {
		(void) strlcpy(clnts_name, "<default,mcast>,",
		    MAXCLIENTNAMELEN);
		index += strlen("<default,mcast>,");
	}
	for (mcip = mip->mi_rx_groups[grp_index].mrg_clients; mcip != NULL;
	    mcip = mcip->mgc_next) {
		int name_len = strlen(mcip->mgc_client->mci_name);

		/*
		 * MAXCLIENTNAMELEN is the buffer size reserved for client
		 * names.
		 * XXXX Formating the client name string needs to be moved
		 * to user land when fixing the size of dhi_clnts in
		 * dld_hwgrpinfo_t. We should use n_clients * client_name for
		 * dhi_clntsin instead of MAXCLIENTNAMELEN
		 */
		if (index + name_len >= MAXCLIENTNAMELEN) {
			index = MAXCLIENTNAMELEN;
			break;
		}
		bcopy(mcip->mgc_client->mci_name, &(clnts_name[index]),
		    name_len);
		index += name_len;
		clnts_name[index++] = ',';
		i++;
	}

	/* Get rid of the last , */
	if (index > 0)
		clnts_name[index - 1] = '\0';
	*n_clnts = i;
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Return the TX h/w information for the group indexed by grp_num.
 */
void
mac_get_hwtxgrp_info(mac_handle_t mh, int grp_index, uint_t *grp_num,
    uint_t *n_rings, uint_t *rings, uint_t *type, uint_t *n_clnts,
    char *clnts_name)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	mac_grp_client_t *mcip;
	uint_t i = 0, index = 0;
	mac_ring_t	*ring;

	/* Revisit when we implement fully dynamic group allocation */
	ASSERT(grp_index >= 0 && grp_index <= mip->mi_tx_group_count);

	rw_enter(&mip->mi_rw_lock, RW_READER);
	*grp_num = mip->mi_tx_groups[grp_index].mrg_index > 0 ?
	    mip->mi_tx_groups[grp_index].mrg_index : grp_index;
	*type = mip->mi_tx_groups[grp_index].mrg_type;
	*n_rings = mip->mi_tx_groups[grp_index].mrg_cur_count;
	ring = mip->mi_tx_groups[grp_index].mrg_rings;
	for (index = 0; index < mip->mi_tx_groups[grp_index].mrg_cur_count;
	    index++) {
		rings[index] = ring->mr_index;
		ring = ring->mr_next;
	}
	index = 0;
	/* Default group has an index of -1 */
	if (mip->mi_tx_groups[grp_index].mrg_index < 0) {
		(void) strlcpy(clnts_name, "<default>,",
		    MAXCLIENTNAMELEN);
		index += strlen("<default>,");
	}
	for (mcip = mip->mi_tx_groups[grp_index].mrg_clients; mcip != NULL;
	    mcip = mcip->mgc_next) {
		int name_len = strlen(mcip->mgc_client->mci_name);

		/*
		 * MAXCLIENTNAMELEN is the buffer size reserved for client
		 * names.
		 * XXXX Formating the client name string needs to be moved
		 * to user land when fixing the size of dhi_clnts in
		 * dld_hwgrpinfo_t. We should use n_clients * client_name for
		 * dhi_clntsin instead of MAXCLIENTNAMELEN
		 */
		if (index + name_len >= MAXCLIENTNAMELEN) {
			index = MAXCLIENTNAMELEN;
			break;
		}
		bcopy(mcip->mgc_client->mci_name, &(clnts_name[index]),
		    name_len);
		index += name_len;
		clnts_name[index++] = ',';
		i++;
	}

	/* Get rid of the last , */
	if (index > 0)
		clnts_name[index - 1] = '\0';
	*n_clnts = i;
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Return the group count for RX or TX.
 */
uint_t
mac_hwgrp_num(mac_handle_t mh, int type)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	/*
	 * Return the Rx and Tx group count; for the Tx we need to
	 * include the default too.
	 */
	return (type == MAC_RING_TYPE_RX ? mip->mi_rx_group_count :
	    mip->mi_tx_groups != NULL ? mip->mi_tx_group_count + 1 : 0);
}

/*
 * The total number of free TX rings for this MAC.
 */
uint_t
mac_txavail_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_txrings_avail);
}

/*
 * The total number of free RX rings for this MAC.
 */
uint_t
mac_rxavail_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_rxrings_avail);
}

/*
 * The total number of reserved RX rings on this MAC.
 */
uint_t
mac_rxrsvd_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_rxrings_rsvd);
}

/*
 * The total number of reserved TX rings on this MAC.
 */
uint_t
mac_txrsvd_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_txrings_rsvd);
}

/*
 * Total number of free RX groups on this MAC.
 */
uint_t
mac_rxhwlnksavail_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_rxhwclnt_avail);
}

/*
 * Total number of RX groups reserved on this MAC.
 */
uint_t
mac_rxhwlnksrsvd_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_rxhwclnt_used);
}

/*
 * Total number of free TX groups on this MAC.
 */
uint_t
mac_txhwlnksavail_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_txhwclnt_avail);
}

/*
 * Total number of TX groups reserved on this MAC.
 */
uint_t
mac_txhwlnksrsvd_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return (mip->mi_txhwclnt_used);
}

/*
 * Initialize the rings property for a mac client. A non-0 value for
 * rxring or txring specifies the number of rings required, a value
 * of MAC_RXRINGS_NONE/MAC_TXRINGS_NONE specifies that it doesn't need
 * any RX/TX rings and a value of MAC_RXRINGS_DONTCARE/MAC_TXRINGS_DONTCARE
 * means the system can decide whether it can give any rings or not.
 */
void
mac_client_set_rings(mac_client_handle_t mch, int rxrings, int txrings)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_resource_props_t	*mrp = MCIP_RESOURCE_PROPS(mcip);

	if (rxrings != MAC_RXRINGS_DONTCARE) {
		mrp->mrp_mask |= MRP_RX_RINGS;
		mrp->mrp_nrxrings = rxrings;
	}

	if (txrings != MAC_TXRINGS_DONTCARE) {
		mrp->mrp_mask |= MRP_TX_RINGS;
		mrp->mrp_ntxrings = txrings;
	}
}
