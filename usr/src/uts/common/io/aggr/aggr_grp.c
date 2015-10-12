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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

/*
 * IEEE 802.3ad Link Aggregation -- Link Aggregation Groups.
 *
 * An instance of the structure aggr_grp_t is allocated for each
 * link aggregation group. When created, aggr_grp_t objects are
 * entered into the aggr_grp_hash hash table maintained by the modhash
 * module. The hash key is the linkid associated with the link
 * aggregation group.
 *
 * A set of MAC ports are associated with each association group.
 *
 * Aggr pseudo TX rings
 * --------------------
 * The underlying ports (NICs) in an aggregation can have TX rings. To
 * enhance aggr's performance, these TX rings are made available to the
 * aggr layer as pseudo TX rings. The concept of pseudo rings are not new.
 * They are already present and implemented on the RX side. It is called
 * as pseudo RX rings. The same concept is extended to the TX side where
 * each TX ring of an underlying port is reflected in aggr as a pseudo
 * TX ring. Thus each pseudo TX ring will map to a specific hardware TX
 * ring. Even in the case of a NIC that does not have a TX ring, a pseudo
 * TX ring is given to the aggregation layer.
 *
 * With this change, the outgoing stack depth looks much better:
 *
 * mac_tx() -> mac_tx_aggr_mode() -> mac_tx_soft_ring_process() ->
 * mac_tx_send() -> aggr_ring_rx() -> <driver>_ring_tx()
 *
 * Two new modes are introduced to mac_tx() to handle aggr pseudo TX rings:
 * SRS_TX_AGGR and SRS_TX_BW_AGGR.
 *
 * In SRS_TX_AGGR mode, mac_tx_aggr_mode() routine is called. This routine
 * invokes an aggr function, aggr_find_tx_ring(), to find a (pseudo) TX
 * ring belonging to a port on which the packet has to be sent.
 * aggr_find_tx_ring() first finds the outgoing port based on L2/L3/L4
 * policy and then uses the fanout_hint passed to it to pick a TX ring from
 * the selected port.
 *
 * In SRS_TX_BW_AGGR mode, mac_tx_bw_mode() function is called where
 * bandwidth limit is applied first on the outgoing packet and the packets
 * allowed to go out would call mac_tx_aggr_mode() to send the packet on a
 * particular TX ring.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/disp.h>
#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/stat.h>
#include <sys/modhash.h>
#include <sys/id_space.h>
#include <sys/strsun.h>
#include <sys/cred.h>
#include <sys/dlpi.h>
#include <sys/zone.h>
#include <sys/mac_provider.h>
#include <sys/dls.h>
#include <sys/vlan.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>

static int aggr_m_start(void *);
static void aggr_m_stop(void *);
static int aggr_m_promisc(void *, boolean_t);
static int aggr_m_multicst(void *, boolean_t, const uint8_t *);
static int aggr_m_unicst(void *, const uint8_t *);
static int aggr_m_stat(void *, uint_t, uint64_t *);
static void aggr_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t aggr_m_capab_get(void *, mac_capab_t, void *);
static int aggr_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void aggr_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static aggr_port_t *aggr_grp_port_lookup(aggr_grp_t *, datalink_id_t);
static int aggr_grp_rem_port(aggr_grp_t *, aggr_port_t *, boolean_t *,
    boolean_t *);

static void aggr_grp_capab_set(aggr_grp_t *);
static boolean_t aggr_grp_capab_check(aggr_grp_t *, aggr_port_t *);
static uint_t aggr_grp_max_sdu(aggr_grp_t *);
static uint32_t aggr_grp_max_margin(aggr_grp_t *);
static boolean_t aggr_grp_sdu_check(aggr_grp_t *, aggr_port_t *);
static boolean_t aggr_grp_margin_check(aggr_grp_t *, aggr_port_t *);

static int aggr_add_pseudo_rx_group(aggr_port_t *, aggr_pseudo_rx_group_t *);
static void aggr_rem_pseudo_rx_group(aggr_port_t *, aggr_pseudo_rx_group_t *);
static int aggr_pseudo_disable_intr(mac_intr_handle_t);
static int aggr_pseudo_enable_intr(mac_intr_handle_t);
static int aggr_pseudo_start_ring(mac_ring_driver_t, uint64_t);
static void aggr_pseudo_stop_ring(mac_ring_driver_t);
static int aggr_addmac(void *, const uint8_t *);
static int aggr_remmac(void *, const uint8_t *);
static mblk_t *aggr_rx_poll(void *, int);
static void aggr_fill_ring(void *, mac_ring_type_t, const int,
    const int, mac_ring_info_t *, mac_ring_handle_t);
static void aggr_fill_group(void *, mac_ring_type_t, const int,
    mac_group_info_t *, mac_group_handle_t);

static kmem_cache_t	*aggr_grp_cache;
static mod_hash_t	*aggr_grp_hash;
static krwlock_t	aggr_grp_lock;
static uint_t		aggr_grp_cnt;
static id_space_t	*key_ids;

#define	GRP_HASHSZ		64
#define	GRP_HASH_KEY(linkid)	((mod_hash_key_t)(uintptr_t)linkid)
#define	AGGR_PORT_NAME_DELIMIT '-'

static uchar_t aggr_zero_mac[] = {0, 0, 0, 0, 0, 0};

#define	AGGR_M_CALLBACK_FLAGS	\
	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_PROPINFO)

static mac_callbacks_t aggr_m_callbacks = {
	AGGR_M_CALLBACK_FLAGS,
	aggr_m_stat,
	aggr_m_start,
	aggr_m_stop,
	aggr_m_promisc,
	aggr_m_multicst,
	NULL,
	NULL,
	NULL,
	aggr_m_ioctl,
	aggr_m_capab_get,
	NULL,
	NULL,
	aggr_m_setprop,
	NULL,
	aggr_m_propinfo
};

/*ARGSUSED*/
static int
aggr_grp_constructor(void *buf, void *arg, int kmflag)
{
	aggr_grp_t *grp = buf;

	bzero(grp, sizeof (*grp));
	mutex_init(&grp->lg_lacp_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&grp->lg_lacp_cv, NULL, CV_DEFAULT, NULL);
	rw_init(&grp->lg_tx_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&grp->lg_port_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&grp->lg_port_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&grp->lg_tx_flowctl_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&grp->lg_tx_flowctl_cv, NULL, CV_DEFAULT, NULL);
	grp->lg_link_state = LINK_STATE_UNKNOWN;
	return (0);
}

/*ARGSUSED*/
static void
aggr_grp_destructor(void *buf, void *arg)
{
	aggr_grp_t *grp = buf;

	if (grp->lg_tx_ports != NULL) {
		kmem_free(grp->lg_tx_ports,
		    grp->lg_tx_ports_size * sizeof (aggr_port_t *));
	}

	mutex_destroy(&grp->lg_lacp_lock);
	cv_destroy(&grp->lg_lacp_cv);
	mutex_destroy(&grp->lg_port_lock);
	cv_destroy(&grp->lg_port_cv);
	rw_destroy(&grp->lg_tx_lock);
	mutex_destroy(&grp->lg_tx_flowctl_lock);
	cv_destroy(&grp->lg_tx_flowctl_cv);
}

void
aggr_grp_init(void)
{
	aggr_grp_cache = kmem_cache_create("aggr_grp_cache",
	    sizeof (aggr_grp_t), 0, aggr_grp_constructor,
	    aggr_grp_destructor, NULL, NULL, NULL, 0);

	aggr_grp_hash = mod_hash_create_idhash("aggr_grp_hash",
	    GRP_HASHSZ, mod_hash_null_valdtor);
	rw_init(&aggr_grp_lock, NULL, RW_DEFAULT, NULL);
	aggr_grp_cnt = 0;

	/*
	 * Allocate an id space to manage key values (when key is not
	 * specified). The range of the id space will be from
	 * (AGGR_MAX_KEY + 1) to UINT16_MAX, because the LACP protocol
	 * uses a 16-bit key.
	 */
	key_ids = id_space_create("aggr_key_ids", AGGR_MAX_KEY + 1, UINT16_MAX);
	ASSERT(key_ids != NULL);
}

void
aggr_grp_fini(void)
{
	id_space_destroy(key_ids);
	rw_destroy(&aggr_grp_lock);
	mod_hash_destroy_idhash(aggr_grp_hash);
	kmem_cache_destroy(aggr_grp_cache);
}

uint_t
aggr_grp_count(void)
{
	uint_t	count;

	rw_enter(&aggr_grp_lock, RW_READER);
	count = aggr_grp_cnt;
	rw_exit(&aggr_grp_lock);
	return (count);
}

/*
 * Since both aggr_port_notify_cb() and aggr_port_timer_thread() functions
 * requires the mac perimeter, this function holds a reference of the aggr
 * and aggr won't call mac_unregister() until this reference drops to 0.
 */
void
aggr_grp_port_hold(aggr_port_t *port)
{
	aggr_grp_t	*grp = port->lp_grp;

	AGGR_PORT_REFHOLD(port);
	mutex_enter(&grp->lg_port_lock);
	grp->lg_port_ref++;
	mutex_exit(&grp->lg_port_lock);
}

/*
 * Release the reference of the grp and inform aggr_grp_delete() calling
 * mac_unregister() is now safe.
 */
void
aggr_grp_port_rele(aggr_port_t *port)
{
	aggr_grp_t	*grp = port->lp_grp;

	mutex_enter(&grp->lg_port_lock);
	if (--grp->lg_port_ref == 0)
		cv_signal(&grp->lg_port_cv);
	mutex_exit(&grp->lg_port_lock);
	AGGR_PORT_REFRELE(port);
}

/*
 * Wait for the port's lacp timer thread and the port's notification callback
 * to exit.
 */
void
aggr_grp_port_wait(aggr_grp_t *grp)
{
	mutex_enter(&grp->lg_port_lock);
	if (grp->lg_port_ref != 0)
		cv_wait(&grp->lg_port_cv, &grp->lg_port_lock);
	mutex_exit(&grp->lg_port_lock);
}

/*
 * Attach a port to a link aggregation group.
 *
 * A port is attached to a link aggregation group once its speed
 * and link state have been verified.
 *
 * Returns B_TRUE if the group link state or speed has changed. If
 * it's the case, the caller must notify the MAC layer via a call
 * to mac_link().
 */
boolean_t
aggr_grp_attach_port(aggr_grp_t *grp, aggr_port_t *port)
{
	boolean_t link_state_changed = B_FALSE;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	if (port->lp_state == AGGR_PORT_STATE_ATTACHED)
		return (B_FALSE);

	/*
	 * Validate the MAC port link speed and update the group
	 * link speed if needed.
	 */
	if (port->lp_ifspeed == 0 ||
	    port->lp_link_state != LINK_STATE_UP ||
	    port->lp_link_duplex != LINK_DUPLEX_FULL) {
		/*
		 * Can't attach a MAC port with unknown link speed,
		 * down link, or not in full duplex mode.
		 */
		return (B_FALSE);
	}

	if (grp->lg_ifspeed == 0) {
		/*
		 * The group inherits the speed of the first link being
		 * attached.
		 */
		grp->lg_ifspeed = port->lp_ifspeed;
		link_state_changed = B_TRUE;
	} else if (grp->lg_ifspeed != port->lp_ifspeed) {
		/*
		 * The link speed of the MAC port must be the same as
		 * the group link speed, as per 802.3ad. Since it is
		 * not, the attach is cancelled.
		 */
		return (B_FALSE);
	}

	grp->lg_nattached_ports++;

	/*
	 * Update the group link state.
	 */
	if (grp->lg_link_state != LINK_STATE_UP) {
		grp->lg_link_state = LINK_STATE_UP;
		grp->lg_link_duplex = LINK_DUPLEX_FULL;
		link_state_changed = B_TRUE;
	}

	/*
	 * Update port's state.
	 */
	port->lp_state = AGGR_PORT_STATE_ATTACHED;

	aggr_grp_multicst_port(port, B_TRUE);

	/*
	 * Set port's receive callback
	 */
	mac_rx_set(port->lp_mch, aggr_recv_cb, port);

	/*
	 * If LACP is OFF, the port can be used to send data as soon
	 * as its link is up and verified to be compatible with the
	 * aggregation.
	 *
	 * If LACP is active or passive, notify the LACP subsystem, which
	 * will enable sending on the port following the LACP protocol.
	 */
	if (grp->lg_lacp_mode == AGGR_LACP_OFF)
		aggr_send_port_enable(port);
	else
		aggr_lacp_port_attached(port);

	return (link_state_changed);
}

boolean_t
aggr_grp_detach_port(aggr_grp_t *grp, aggr_port_t *port)
{
	boolean_t link_state_changed = B_FALSE;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	/* update state */
	if (port->lp_state != AGGR_PORT_STATE_ATTACHED)
		return (B_FALSE);

	mac_rx_clear(port->lp_mch);

	aggr_grp_multicst_port(port, B_FALSE);

	if (grp->lg_lacp_mode == AGGR_LACP_OFF)
		aggr_send_port_disable(port);
	else
		aggr_lacp_port_detached(port);

	port->lp_state = AGGR_PORT_STATE_STANDBY;

	grp->lg_nattached_ports--;
	if (grp->lg_nattached_ports == 0) {
		/* the last attached MAC port of the group is being detached */
		grp->lg_ifspeed = 0;
		grp->lg_link_state = LINK_STATE_DOWN;
		grp->lg_link_duplex = LINK_DUPLEX_UNKNOWN;
		link_state_changed = B_TRUE;
	}

	return (link_state_changed);
}

/*
 * Update the MAC addresses of the constituent ports of the specified
 * group. This function is invoked:
 * - after creating a new aggregation group.
 * - after adding new ports to an aggregation group.
 * - after removing a port from a group when the MAC address of
 *   that port was used for the MAC address of the group.
 * - after the MAC address of a port changed when the MAC address
 *   of that port was used for the MAC address of the group.
 *
 * Return true if the link state of the aggregation changed, for example
 * as a result of a failure changing the MAC address of one of the
 * constituent ports.
 */
boolean_t
aggr_grp_update_ports_mac(aggr_grp_t *grp)
{
	aggr_port_t *cport;
	boolean_t link_state_changed = B_FALSE;
	mac_perim_handle_t mph;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	for (cport = grp->lg_ports; cport != NULL;
	    cport = cport->lp_next) {
		mac_perim_enter_by_mh(cport->lp_mh, &mph);
		if (aggr_port_unicst(cport) != 0) {
			if (aggr_grp_detach_port(grp, cport))
				link_state_changed = B_TRUE;
		} else {
			/*
			 * If a port was detached because of a previous
			 * failure changing the MAC address, the port is
			 * reattached when it successfully changes the MAC
			 * address now, and this might cause the link state
			 * of the aggregation to change.
			 */
			if (aggr_grp_attach_port(grp, cport))
				link_state_changed = B_TRUE;
		}
		mac_perim_exit(mph);
	}
	return (link_state_changed);
}

/*
 * Invoked when the MAC address of a port has changed. If the port's
 * MAC address was used for the group MAC address, set mac_addr_changedp
 * to B_TRUE to indicate to the caller that it should send a MAC_NOTE_UNICST
 * notification. If the link state changes due to detach/attach of
 * the constituent port, set link_state_changedp to B_TRUE to indicate
 * to the caller that it should send a MAC_NOTE_LINK notification. In both
 * cases, it is the responsibility of the caller to invoke notification
 * functions after releasing the the port lock.
 */
void
aggr_grp_port_mac_changed(aggr_grp_t *grp, aggr_port_t *port,
    boolean_t *mac_addr_changedp, boolean_t *link_state_changedp)
{
	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(MAC_PERIM_HELD(port->lp_mh));
	ASSERT(mac_addr_changedp != NULL);
	ASSERT(link_state_changedp != NULL);

	*mac_addr_changedp = B_FALSE;
	*link_state_changedp = B_FALSE;

	if (grp->lg_addr_fixed) {
		/*
		 * The group is using a fixed MAC address or an automatic
		 * MAC address has not been set.
		 */
		return;
	}

	if (grp->lg_mac_addr_port == port) {
		/*
		 * The MAC address of the port was assigned to the group
		 * MAC address. Update the group MAC address.
		 */
		bcopy(port->lp_addr, grp->lg_addr, ETHERADDRL);
		*mac_addr_changedp = B_TRUE;
	} else {
		/*
		 * Update the actual port MAC address to the MAC address
		 * of the group.
		 */
		if (aggr_port_unicst(port) != 0) {
			*link_state_changedp = aggr_grp_detach_port(grp, port);
		} else {
			/*
			 * If a port was detached because of a previous
			 * failure changing the MAC address, the port is
			 * reattached when it successfully changes the MAC
			 * address now, and this might cause the link state
			 * of the aggregation to change.
			 */
			*link_state_changedp = aggr_grp_attach_port(grp, port);
		}
	}
}

/*
 * Add a port to a link aggregation group.
 */
static int
aggr_grp_add_port(aggr_grp_t *grp, datalink_id_t port_linkid, boolean_t force,
    aggr_port_t **pp)
{
	aggr_port_t *port, **cport;
	mac_perim_handle_t mph;
	zoneid_t port_zoneid = ALL_ZONES;
	int err;

	/* The port must be int the same zone as the aggregation. */
	if (zone_check_datalink(&port_zoneid, port_linkid) != 0)
		port_zoneid = GLOBAL_ZONEID;
	if (grp->lg_zoneid != port_zoneid)
		return (EBUSY);

	/*
	 * lg_mh could be NULL when the function is called during the creation
	 * of the aggregation.
	 */
	ASSERT(grp->lg_mh == NULL || MAC_PERIM_HELD(grp->lg_mh));

	/* create new port */
	err = aggr_port_create(grp, port_linkid, force, &port);
	if (err != 0)
		return (err);

	mac_perim_enter_by_mh(port->lp_mh, &mph);

	/* add port to list of group constituent ports */
	cport = &grp->lg_ports;
	while (*cport != NULL)
		cport = &((*cport)->lp_next);
	*cport = port;

	/*
	 * Back reference to the group it is member of. A port always
	 * holds a reference to its group to ensure that the back
	 * reference is always valid.
	 */
	port->lp_grp = grp;
	AGGR_GRP_REFHOLD(grp);
	grp->lg_nports++;

	aggr_lacp_init_port(port);
	mac_perim_exit(mph);

	if (pp != NULL)
		*pp = port;

	return (0);
}

/*
 * This is called in response to either our LACP state machine or a MAC
 * notification that the link has gone down via aggr_send_port_disable(). At
 * this point, we may need to update our default ring. To that end, we go
 * through the set of ports (underlying datalinks in an aggregation) that are
 * currently enabled to transmit data. If all our links have been disabled for
 * transmit, then we don't do anything.
 *
 * Note, because we only have a single TX group, we don't have to worry about
 * the rings moving between groups and the chance that mac will reassign it
 * unless someone removes a port, at which point, we play it safe and call this
 * again.
 */
void
aggr_grp_update_default(aggr_grp_t *grp)
{
	aggr_port_t *port;
	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	rw_enter(&grp->lg_tx_lock, RW_WRITER);

	if (grp->lg_ntx_ports == 0) {
		rw_exit(&grp->lg_tx_lock);
		return;
	}

	port = grp->lg_tx_ports[0];
	ASSERT(port->lp_tx_ring_cnt > 0);
	mac_hwring_set_default(grp->lg_mh, port->lp_pseudo_tx_rings[0]);
	rw_exit(&grp->lg_tx_lock);
}

/*
 * Add a pseudo RX ring for the given HW ring handle.
 */
static int
aggr_add_pseudo_rx_ring(aggr_port_t *port,
    aggr_pseudo_rx_group_t *rx_grp, mac_ring_handle_t hw_rh)
{
	aggr_pseudo_rx_ring_t	*ring;
	int			err;
	int			j;

	for (j = 0; j < MAX_RINGS_PER_GROUP; j++) {
		ring = rx_grp->arg_rings + j;
		if (!(ring->arr_flags & MAC_PSEUDO_RING_INUSE))
			break;
	}

	/*
	 * No slot for this new RX ring.
	 */
	if (j == MAX_RINGS_PER_GROUP)
		return (EIO);

	ring->arr_flags |= MAC_PSEUDO_RING_INUSE;
	ring->arr_hw_rh = hw_rh;
	ring->arr_port = port;
	rx_grp->arg_ring_cnt++;

	/*
	 * The group is already registered, dynamically add a new ring to the
	 * mac group.
	 */
	if ((err = mac_group_add_ring(rx_grp->arg_gh, j)) != 0) {
		ring->arr_flags &= ~MAC_PSEUDO_RING_INUSE;
		ring->arr_hw_rh = NULL;
		ring->arr_port = NULL;
		rx_grp->arg_ring_cnt--;
	} else {
		mac_hwring_setup(hw_rh, (mac_resource_handle_t)ring,
		    mac_find_ring(rx_grp->arg_gh, j));
	}
	return (err);
}

/*
 * Remove the pseudo RX ring of the given HW ring handle.
 */
static void
aggr_rem_pseudo_rx_ring(aggr_pseudo_rx_group_t *rx_grp, mac_ring_handle_t hw_rh)
{
	aggr_pseudo_rx_ring_t	*ring;
	int			j;

	for (j = 0; j < MAX_RINGS_PER_GROUP; j++) {
		ring = rx_grp->arg_rings + j;
		if (!(ring->arr_flags & MAC_PSEUDO_RING_INUSE) ||
		    ring->arr_hw_rh != hw_rh) {
			continue;
		}

		mac_group_rem_ring(rx_grp->arg_gh, ring->arr_rh);

		ring->arr_flags &= ~MAC_PSEUDO_RING_INUSE;
		ring->arr_hw_rh = NULL;
		ring->arr_port = NULL;
		rx_grp->arg_ring_cnt--;
		mac_hwring_teardown(hw_rh);
		break;
	}
}

/*
 * This function is called to create pseudo rings over the hardware rings of
 * the underlying device. Note that there is a 1:1 mapping between the pseudo
 * RX rings of the aggr and the hardware rings of the underlying port.
 */
static int
aggr_add_pseudo_rx_group(aggr_port_t *port, aggr_pseudo_rx_group_t *rx_grp)
{
	aggr_grp_t		*grp = port->lp_grp;
	mac_ring_handle_t	hw_rh[MAX_RINGS_PER_GROUP];
	aggr_unicst_addr_t	*addr, *a;
	mac_perim_handle_t	pmph;
	int			hw_rh_cnt, i = 0, j;
	int			err = 0;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &pmph);

	/*
	 * This function must be called after the aggr registers its mac
	 * and its RX group has been initialized.
	 */
	ASSERT(rx_grp->arg_gh != NULL);

	/*
	 * Get the list the the underlying HW rings.
	 */
	hw_rh_cnt = mac_hwrings_get(port->lp_mch,
	    &port->lp_hwgh, hw_rh, MAC_RING_TYPE_RX);

	if (port->lp_hwgh != NULL) {
		/*
		 * Quiesce the HW ring and the mac srs on the ring. Note
		 * that the HW ring will be restarted when the pseudo ring
		 * is started. At that time all the packets will be
		 * directly passed up to the pseudo RX ring and handled
		 * by mac srs created over the pseudo RX ring.
		 */
		mac_rx_client_quiesce(port->lp_mch);
		mac_srs_perm_quiesce(port->lp_mch, B_TRUE);
	}

	/*
	 * Add all the unicast addresses to the newly added port.
	 */
	for (addr = rx_grp->arg_macaddr; addr != NULL; addr = addr->aua_next) {
		if ((err = aggr_port_addmac(port, addr->aua_addr)) != 0)
			break;
	}

	for (i = 0; err == 0 && i < hw_rh_cnt; i++)
		err = aggr_add_pseudo_rx_ring(port, rx_grp, hw_rh[i]);

	if (err != 0) {
		for (j = 0; j < i; j++)
			aggr_rem_pseudo_rx_ring(rx_grp, hw_rh[j]);

		for (a = rx_grp->arg_macaddr; a != addr; a = a->aua_next)
			aggr_port_remmac(port, a->aua_addr);

		if (port->lp_hwgh != NULL) {
			mac_srs_perm_quiesce(port->lp_mch, B_FALSE);
			mac_rx_client_restart(port->lp_mch);
			port->lp_hwgh = NULL;
		}
	} else {
		port->lp_rx_grp_added = B_TRUE;
	}
done:
	mac_perim_exit(pmph);
	return (err);
}

/*
 * This function is called by aggr to remove pseudo RX rings over the
 * HW rings of the underlying port.
 */
static void
aggr_rem_pseudo_rx_group(aggr_port_t *port, aggr_pseudo_rx_group_t *rx_grp)
{
	aggr_grp_t		*grp = port->lp_grp;
	mac_ring_handle_t	hw_rh[MAX_RINGS_PER_GROUP];
	aggr_unicst_addr_t	*addr;
	mac_group_handle_t	hwgh;
	mac_perim_handle_t	pmph;
	int			hw_rh_cnt, i;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &pmph);

	if (!port->lp_rx_grp_added)
		goto done;

	ASSERT(rx_grp->arg_gh != NULL);
	hw_rh_cnt = mac_hwrings_get(port->lp_mch,
	    &hwgh, hw_rh, MAC_RING_TYPE_RX);

	/*
	 * If hw_rh_cnt is 0, it means that the underlying port does not
	 * support RX rings. Directly return in this case.
	 */
	for (i = 0; i < hw_rh_cnt; i++)
		aggr_rem_pseudo_rx_ring(rx_grp, hw_rh[i]);

	for (addr = rx_grp->arg_macaddr; addr != NULL; addr = addr->aua_next)
		aggr_port_remmac(port, addr->aua_addr);

	if (port->lp_hwgh != NULL) {
		port->lp_hwgh = NULL;

		/*
		 * First clear the permanent-quiesced flag of the RX srs then
		 * restart the HW ring and the mac srs on the ring. Note that
		 * the HW ring and associated SRS will soon been removed when
		 * the port is removed from the aggr.
		 */
		mac_srs_perm_quiesce(port->lp_mch, B_FALSE);
		mac_rx_client_restart(port->lp_mch);
	}

	port->lp_rx_grp_added = B_FALSE;
done:
	mac_perim_exit(pmph);
}

/*
 * Add a pseudo TX ring for the given HW ring handle.
 */
static int
aggr_add_pseudo_tx_ring(aggr_port_t *port,
    aggr_pseudo_tx_group_t *tx_grp, mac_ring_handle_t hw_rh,
    mac_ring_handle_t *pseudo_rh)
{
	aggr_pseudo_tx_ring_t	*ring;
	int			err;
	int			i;

	ASSERT(MAC_PERIM_HELD(port->lp_mh));
	for (i = 0; i < MAX_RINGS_PER_GROUP; i++) {
		ring = tx_grp->atg_rings + i;
		if (!(ring->atr_flags & MAC_PSEUDO_RING_INUSE))
			break;
	}
	/*
	 * No slot for this new TX ring.
	 */
	if (i == MAX_RINGS_PER_GROUP)
		return (EIO);
	/*
	 * The following 4 statements needs to be done before
	 * calling mac_group_add_ring(). Otherwise it will
	 * result in an assertion failure in mac_init_ring().
	 */
	ring->atr_flags |= MAC_PSEUDO_RING_INUSE;
	ring->atr_hw_rh = hw_rh;
	ring->atr_port = port;
	tx_grp->atg_ring_cnt++;

	/*
	 * The TX side has no concept of ring groups unlike RX groups.
	 * There is just a single group which stores all the TX rings.
	 * This group will be used to store aggr's pseudo TX rings.
	 */
	if ((err = mac_group_add_ring(tx_grp->atg_gh, i)) != 0) {
		ring->atr_flags &= ~MAC_PSEUDO_RING_INUSE;
		ring->atr_hw_rh = NULL;
		ring->atr_port = NULL;
		tx_grp->atg_ring_cnt--;
	} else {
		*pseudo_rh = mac_find_ring(tx_grp->atg_gh, i);
		if (hw_rh != NULL) {
			mac_hwring_setup(hw_rh, (mac_resource_handle_t)ring,
			    mac_find_ring(tx_grp->atg_gh, i));
		}
	}

	return (err);
}

/*
 * Remove the pseudo TX ring of the given HW ring handle.
 */
static void
aggr_rem_pseudo_tx_ring(aggr_pseudo_tx_group_t *tx_grp,
    mac_ring_handle_t pseudo_hw_rh)
{
	aggr_pseudo_tx_ring_t	*ring;
	int			i;

	for (i = 0; i < MAX_RINGS_PER_GROUP; i++) {
		ring = tx_grp->atg_rings + i;
		if (ring->atr_rh != pseudo_hw_rh)
			continue;

		ASSERT(ring->atr_flags & MAC_PSEUDO_RING_INUSE);
		mac_group_rem_ring(tx_grp->atg_gh, pseudo_hw_rh);
		ring->atr_flags &= ~MAC_PSEUDO_RING_INUSE;
		mac_hwring_teardown(ring->atr_hw_rh);
		ring->atr_hw_rh = NULL;
		ring->atr_port = NULL;
		tx_grp->atg_ring_cnt--;
		break;
	}
}

/*
 * This function is called to create pseudo rings over hardware rings of
 * the underlying device. There is a 1:1 mapping between the pseudo TX
 * rings of the aggr and the hardware rings of the underlying port.
 */
static int
aggr_add_pseudo_tx_group(aggr_port_t *port, aggr_pseudo_tx_group_t *tx_grp)
{
	aggr_grp_t		*grp = port->lp_grp;
	mac_ring_handle_t	hw_rh[MAX_RINGS_PER_GROUP], pseudo_rh;
	mac_perim_handle_t	pmph;
	int			hw_rh_cnt, i = 0, j;
	int			err = 0;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &pmph);

	/*
	 * Get the list the the underlying HW rings.
	 */
	hw_rh_cnt = mac_hwrings_get(port->lp_mch,
	    NULL, hw_rh, MAC_RING_TYPE_TX);

	/*
	 * Even if the underlying NIC does not have TX rings, we
	 * still make a psuedo TX ring for that NIC with NULL as
	 * the ring handle.
	 */
	if (hw_rh_cnt == 0)
		port->lp_tx_ring_cnt = 1;
	else
		port->lp_tx_ring_cnt = hw_rh_cnt;

	port->lp_tx_rings = kmem_zalloc((sizeof (mac_ring_handle_t *) *
	    port->lp_tx_ring_cnt), KM_SLEEP);
	port->lp_pseudo_tx_rings = kmem_zalloc((sizeof (mac_ring_handle_t *) *
	    port->lp_tx_ring_cnt), KM_SLEEP);

	if (hw_rh_cnt == 0) {
		if ((err = aggr_add_pseudo_tx_ring(port, tx_grp,
		    NULL, &pseudo_rh)) == 0) {
			port->lp_tx_rings[0] = NULL;
			port->lp_pseudo_tx_rings[0] = pseudo_rh;
		}
	} else {
		for (i = 0; err == 0 && i < hw_rh_cnt; i++) {
			err = aggr_add_pseudo_tx_ring(port,
			    tx_grp, hw_rh[i], &pseudo_rh);
			if (err != 0)
				break;
			port->lp_tx_rings[i] = hw_rh[i];
			port->lp_pseudo_tx_rings[i] = pseudo_rh;
		}
	}

	if (err != 0) {
		if (hw_rh_cnt != 0) {
			for (j = 0; j < i; j++) {
				aggr_rem_pseudo_tx_ring(tx_grp,
				    port->lp_pseudo_tx_rings[j]);
			}
		}
		kmem_free(port->lp_tx_rings,
		    (sizeof (mac_ring_handle_t *) * port->lp_tx_ring_cnt));
		kmem_free(port->lp_pseudo_tx_rings,
		    (sizeof (mac_ring_handle_t *) * port->lp_tx_ring_cnt));
		port->lp_tx_ring_cnt = 0;
	} else {
		port->lp_tx_grp_added = B_TRUE;
		port->lp_tx_notify_mh = mac_client_tx_notify(port->lp_mch,
		    aggr_tx_ring_update, port);
	}
	mac_perim_exit(pmph);
	aggr_grp_update_default(grp);
	return (err);
}

/*
 * This function is called by aggr to remove pseudo TX rings over the
 * HW rings of the underlying port.
 */
static void
aggr_rem_pseudo_tx_group(aggr_port_t *port, aggr_pseudo_tx_group_t *tx_grp)
{
	aggr_grp_t		*grp = port->lp_grp;
	mac_perim_handle_t	pmph;
	int			i;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &pmph);

	if (!port->lp_tx_grp_added)
		goto done;

	ASSERT(tx_grp->atg_gh != NULL);

	for (i = 0; i < port->lp_tx_ring_cnt; i++)
		aggr_rem_pseudo_tx_ring(tx_grp, port->lp_pseudo_tx_rings[i]);

	kmem_free(port->lp_tx_rings,
	    (sizeof (mac_ring_handle_t *) * port->lp_tx_ring_cnt));
	kmem_free(port->lp_pseudo_tx_rings,
	    (sizeof (mac_ring_handle_t *) * port->lp_tx_ring_cnt));

	port->lp_tx_ring_cnt = 0;
	(void) mac_client_tx_notify(port->lp_mch, NULL, port->lp_tx_notify_mh);
	port->lp_tx_grp_added = B_FALSE;
	aggr_grp_update_default(grp);
done:
	mac_perim_exit(pmph);
}

static int
aggr_pseudo_disable_intr(mac_intr_handle_t ih)
{
	aggr_pseudo_rx_ring_t *rr_ring = (aggr_pseudo_rx_ring_t *)ih;
	return (mac_hwring_disable_intr(rr_ring->arr_hw_rh));
}

static int
aggr_pseudo_enable_intr(mac_intr_handle_t ih)
{
	aggr_pseudo_rx_ring_t *rr_ring = (aggr_pseudo_rx_ring_t *)ih;
	return (mac_hwring_enable_intr(rr_ring->arr_hw_rh));
}

static int
aggr_pseudo_start_ring(mac_ring_driver_t arg, uint64_t mr_gen)
{
	aggr_pseudo_rx_ring_t *rr_ring = (aggr_pseudo_rx_ring_t *)arg;
	int err;

	err = mac_hwring_start(rr_ring->arr_hw_rh);
	if (err == 0)
		rr_ring->arr_gen = mr_gen;
	return (err);
}

static void
aggr_pseudo_stop_ring(mac_ring_driver_t arg)
{
	aggr_pseudo_rx_ring_t *rr_ring = (aggr_pseudo_rx_ring_t *)arg;
	mac_hwring_stop(rr_ring->arr_hw_rh);
}

/*
 * Add one or more ports to an existing link aggregation group.
 */
int
aggr_grp_add_ports(datalink_id_t linkid, uint_t nports, boolean_t force,
    laioc_port_t *ports)
{
	int rc, i, nadded = 0;
	aggr_grp_t *grp = NULL;
	aggr_port_t *port;
	boolean_t link_state_changed = B_FALSE;
	mac_perim_handle_t mph, pmph;

	/* get group corresponding to linkid */
	rw_enter(&aggr_grp_lock, RW_READER);
	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}
	AGGR_GRP_REFHOLD(grp);

	/*
	 * Hold the perimeter so that the aggregation won't be destroyed.
	 */
	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	rw_exit(&aggr_grp_lock);

	/* add the specified ports to group */
	for (i = 0; i < nports; i++) {
		/* add port to group */
		if ((rc = aggr_grp_add_port(grp, ports[i].lp_linkid,
		    force, &port)) != 0) {
			goto bail;
		}
		ASSERT(port != NULL);
		nadded++;

		/* check capabilities */
		if (!aggr_grp_capab_check(grp, port) ||
		    !aggr_grp_sdu_check(grp, port) ||
		    !aggr_grp_margin_check(grp, port)) {
			rc = ENOTSUP;
			goto bail;
		}

		/*
		 * Create the pseudo ring for each HW ring of the underlying
		 * port.
		 */
		rc = aggr_add_pseudo_tx_group(port, &grp->lg_tx_group);
		if (rc != 0)
			goto bail;
		rc = aggr_add_pseudo_rx_group(port, &grp->lg_rx_group);
		if (rc != 0)
			goto bail;

		mac_perim_enter_by_mh(port->lp_mh, &pmph);

		/* set LACP mode */
		aggr_port_lacp_set_mode(grp, port);

		/* start port if group has already been started */
		if (grp->lg_started) {
			rc = aggr_port_start(port);
			if (rc != 0) {
				mac_perim_exit(pmph);
				goto bail;
			}

			/*
			 * Turn on the promiscuous mode over the port when it
			 * is requested to be turned on to receive the
			 * non-primary address over a port, or the promiscous
			 * mode is enabled over the aggr.
			 */
			if (grp->lg_promisc || port->lp_prom_addr != NULL) {
				rc = aggr_port_promisc(port, B_TRUE);
				if (rc != 0) {
					mac_perim_exit(pmph);
					goto bail;
				}
			}
		}
		mac_perim_exit(pmph);

		/*
		 * Attach each port if necessary.
		 */
		if (aggr_port_notify_link(grp, port))
			link_state_changed = B_TRUE;

		/*
		 * Initialize the callback functions for this port.
		 */
		aggr_port_init_callbacks(port);
	}

	/* update the MAC address of the constituent ports */
	if (aggr_grp_update_ports_mac(grp))
		link_state_changed = B_TRUE;

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

bail:
	if (rc != 0) {
		/* stop and remove ports that have been added */
		for (i = 0; i < nadded; i++) {
			port = aggr_grp_port_lookup(grp, ports[i].lp_linkid);
			ASSERT(port != NULL);
			if (grp->lg_started) {
				mac_perim_enter_by_mh(port->lp_mh, &pmph);
				(void) aggr_port_promisc(port, B_FALSE);
				aggr_port_stop(port);
				mac_perim_exit(pmph);
			}
			aggr_rem_pseudo_tx_group(port, &grp->lg_tx_group);
			aggr_rem_pseudo_rx_group(port, &grp->lg_rx_group);
			(void) aggr_grp_rem_port(grp, port, NULL, NULL);
		}
	}

	mac_perim_exit(mph);
	AGGR_GRP_REFRELE(grp);
	return (rc);
}

static int
aggr_grp_modify_common(aggr_grp_t *grp, uint8_t update_mask, uint32_t policy,
    boolean_t mac_fixed, const uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode,
    aggr_lacp_timer_t lacp_timer)
{
	boolean_t mac_addr_changed = B_FALSE;
	boolean_t link_state_changed = B_FALSE;
	mac_perim_handle_t pmph;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	/* validate fixed address if specified */
	if ((update_mask & AGGR_MODIFY_MAC) && mac_fixed &&
	    ((bcmp(aggr_zero_mac, mac_addr, ETHERADDRL) == 0) ||
	    (mac_addr[0] & 0x01))) {
		return (EINVAL);
	}

	/* update policy if requested */
	if (update_mask & AGGR_MODIFY_POLICY)
		aggr_send_update_policy(grp, policy);

	/* update unicast MAC address if requested */
	if (update_mask & AGGR_MODIFY_MAC) {
		if (mac_fixed) {
			/* user-supplied MAC address */
			grp->lg_mac_addr_port = NULL;
			if (bcmp(mac_addr, grp->lg_addr, ETHERADDRL) != 0) {
				bcopy(mac_addr, grp->lg_addr, ETHERADDRL);
				mac_addr_changed = B_TRUE;
			}
		} else if (grp->lg_addr_fixed) {
			/* switch from user-supplied to automatic */
			aggr_port_t *port = grp->lg_ports;

			mac_perim_enter_by_mh(port->lp_mh, &pmph);
			bcopy(port->lp_addr, grp->lg_addr, ETHERADDRL);
			grp->lg_mac_addr_port = port;
			mac_addr_changed = B_TRUE;
			mac_perim_exit(pmph);
		}
		grp->lg_addr_fixed = mac_fixed;
	}

	if (mac_addr_changed)
		link_state_changed = aggr_grp_update_ports_mac(grp);

	if (update_mask & AGGR_MODIFY_LACP_MODE)
		aggr_lacp_update_mode(grp, lacp_mode);

	if (update_mask & AGGR_MODIFY_LACP_TIMER)
		aggr_lacp_update_timer(grp, lacp_timer);

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

	if (mac_addr_changed)
		mac_unicst_update(grp->lg_mh, grp->lg_addr);

	return (0);
}

/*
 * Update properties of an existing link aggregation group.
 */
int
aggr_grp_modify(datalink_id_t linkid, uint8_t update_mask, uint32_t policy,
    boolean_t mac_fixed, const uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode,
    aggr_lacp_timer_t lacp_timer)
{
	aggr_grp_t *grp = NULL;
	mac_perim_handle_t mph;
	int err;

	/* get group corresponding to linkid */
	rw_enter(&aggr_grp_lock, RW_READER);
	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}
	AGGR_GRP_REFHOLD(grp);

	/*
	 * Hold the perimeter so that the aggregation won't be destroyed.
	 */
	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	rw_exit(&aggr_grp_lock);

	err = aggr_grp_modify_common(grp, update_mask, policy, mac_fixed,
	    mac_addr, lacp_mode, lacp_timer);

	mac_perim_exit(mph);
	AGGR_GRP_REFRELE(grp);
	return (err);
}

/*
 * Create a new link aggregation group upon request from administrator.
 * Returns 0 on success, an errno on failure.
 */
int
aggr_grp_create(datalink_id_t linkid, uint32_t key, uint_t nports,
    laioc_port_t *ports, uint32_t policy, boolean_t mac_fixed, boolean_t force,
    uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer,
    cred_t *credp)
{
	aggr_grp_t *grp = NULL;
	aggr_port_t *port;
	mac_register_t *mac;
	boolean_t link_state_changed;
	mac_perim_handle_t mph;
	int err;
	int i;
	kt_did_t tid = 0;

	/* need at least one port */
	if (nports == 0)
		return (EINVAL);

	rw_enter(&aggr_grp_lock, RW_WRITER);

	/* does a group with the same linkid already exist? */
	err = mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp);
	if (err == 0) {
		rw_exit(&aggr_grp_lock);
		return (EEXIST);
	}

	grp = kmem_cache_alloc(aggr_grp_cache, KM_SLEEP);

	grp->lg_refs = 1;
	grp->lg_closing = B_FALSE;
	grp->lg_force = force;
	grp->lg_linkid = linkid;
	grp->lg_zoneid = crgetzoneid(credp);
	grp->lg_ifspeed = 0;
	grp->lg_link_state = LINK_STATE_UNKNOWN;
	grp->lg_link_duplex = LINK_DUPLEX_UNKNOWN;
	grp->lg_started = B_FALSE;
	grp->lg_promisc = B_FALSE;
	grp->lg_lacp_done = B_FALSE;
	grp->lg_tx_notify_done = B_FALSE;
	grp->lg_lacp_head = grp->lg_lacp_tail = NULL;
	grp->lg_lacp_rx_thread = thread_create(NULL, 0,
	    aggr_lacp_rx_thread, grp, 0, &p0, TS_RUN, minclsyspri);
	grp->lg_tx_notify_thread = thread_create(NULL, 0,
	    aggr_tx_notify_thread, grp, 0, &p0, TS_RUN, minclsyspri);
	grp->lg_tx_blocked_rings = kmem_zalloc((sizeof (mac_ring_handle_t *) *
	    MAX_RINGS_PER_GROUP), KM_SLEEP);
	grp->lg_tx_blocked_cnt = 0;
	bzero(&grp->lg_rx_group, sizeof (aggr_pseudo_rx_group_t));
	bzero(&grp->lg_tx_group, sizeof (aggr_pseudo_tx_group_t));
	aggr_lacp_init_grp(grp);

	/* add MAC ports to group */
	grp->lg_ports = NULL;
	grp->lg_nports = 0;
	grp->lg_nattached_ports = 0;
	grp->lg_ntx_ports = 0;

	/*
	 * If key is not specified by the user, allocate the key.
	 */
	if ((key == 0) && ((key = (uint32_t)id_alloc(key_ids)) == 0)) {
		err = ENOMEM;
		goto bail;
	}
	grp->lg_key = key;

	for (i = 0; i < nports; i++) {
		err = aggr_grp_add_port(grp, ports[i].lp_linkid, force, NULL);
		if (err != 0)
			goto bail;
	}

	/*
	 * If no explicit MAC address was specified by the administrator,
	 * set it to the MAC address of the first port.
	 */
	grp->lg_addr_fixed = mac_fixed;
	if (grp->lg_addr_fixed) {
		/* validate specified address */
		if (bcmp(aggr_zero_mac, mac_addr, ETHERADDRL) == 0) {
			err = EINVAL;
			goto bail;
		}
		bcopy(mac_addr, grp->lg_addr, ETHERADDRL);
	} else {
		bcopy(grp->lg_ports->lp_addr, grp->lg_addr, ETHERADDRL);
		grp->lg_mac_addr_port = grp->lg_ports;
	}

	/* set the initial group capabilities */
	aggr_grp_capab_set(grp);

	if ((mac = mac_alloc(MAC_VERSION)) == NULL) {
		err = ENOMEM;
		goto bail;
	}
	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = grp;
	mac->m_dip = aggr_dip;
	mac->m_instance = grp->lg_key > AGGR_MAX_KEY ? (uint_t)-1 : grp->lg_key;
	mac->m_src_addr = grp->lg_addr;
	mac->m_callbacks = &aggr_m_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = grp->lg_max_sdu = aggr_grp_max_sdu(grp);
	mac->m_margin = aggr_grp_max_margin(grp);
	mac->m_v12n = MAC_VIRT_LEVEL1;
	err = mac_register(mac, &grp->lg_mh);
	mac_free(mac);
	if (err != 0)
		goto bail;

	err = dls_devnet_create(grp->lg_mh, grp->lg_linkid, crgetzoneid(credp));
	if (err != 0) {
		(void) mac_unregister(grp->lg_mh);
		grp->lg_mh = NULL;
		goto bail;
	}

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	/*
	 * Update the MAC address of the constituent ports.
	 * None of the port is attached at this time, the link state of the
	 * aggregation will not change.
	 */
	link_state_changed = aggr_grp_update_ports_mac(grp);
	ASSERT(!link_state_changed);

	/* update outbound load balancing policy */
	aggr_send_update_policy(grp, policy);

	/* set LACP mode */
	aggr_lacp_set_mode(grp, lacp_mode, lacp_timer);

	/*
	 * Attach each port if necessary.
	 */
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		/*
		 * Create the pseudo ring for each HW ring of the underlying
		 * port. Note that this is done after the aggr registers the
		 * mac.
		 */
		VERIFY(aggr_add_pseudo_tx_group(port, &grp->lg_tx_group) == 0);
		VERIFY(aggr_add_pseudo_rx_group(port, &grp->lg_rx_group) == 0);
		if (aggr_port_notify_link(grp, port))
			link_state_changed = B_TRUE;

		/*
		 * Initialize the callback functions for this port.
		 */
		aggr_port_init_callbacks(port);
	}

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

	/* add new group to hash table */
	err = mod_hash_insert(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t)grp);
	ASSERT(err == 0);
	aggr_grp_cnt++;

	mac_perim_exit(mph);
	rw_exit(&aggr_grp_lock);
	return (0);

bail:

	grp->lg_closing = B_TRUE;

	port = grp->lg_ports;
	while (port != NULL) {
		aggr_port_t *cport;

		cport = port->lp_next;
		aggr_port_delete(port);
		port = cport;
	}

	/*
	 * Inform the lacp_rx thread to exit.
	 */
	mutex_enter(&grp->lg_lacp_lock);
	grp->lg_lacp_done = B_TRUE;
	cv_signal(&grp->lg_lacp_cv);
	while (grp->lg_lacp_rx_thread != NULL)
		cv_wait(&grp->lg_lacp_cv, &grp->lg_lacp_lock);
	mutex_exit(&grp->lg_lacp_lock);
	/*
	 * Inform the tx_notify thread to exit.
	 */
	mutex_enter(&grp->lg_tx_flowctl_lock);
	if (grp->lg_tx_notify_thread != NULL) {
		tid = grp->lg_tx_notify_thread->t_did;
		grp->lg_tx_notify_done = B_TRUE;
		cv_signal(&grp->lg_tx_flowctl_cv);
	}
	mutex_exit(&grp->lg_tx_flowctl_lock);
	if (tid != 0)
		thread_join(tid);

	kmem_free(grp->lg_tx_blocked_rings,
	    (sizeof (mac_ring_handle_t *) * MAX_RINGS_PER_GROUP));
	rw_exit(&aggr_grp_lock);
	AGGR_GRP_REFRELE(grp);
	return (err);
}

/*
 * Return a pointer to the member of a group with specified linkid.
 */
static aggr_port_t *
aggr_grp_port_lookup(aggr_grp_t *grp, datalink_id_t linkid)
{
	aggr_port_t *port;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (port->lp_linkid == linkid)
			break;
	}

	return (port);
}

/*
 * Stop, detach and remove a port from a link aggregation group.
 */
static int
aggr_grp_rem_port(aggr_grp_t *grp, aggr_port_t *port,
    boolean_t *mac_addr_changedp, boolean_t *link_state_changedp)
{
	int rc = 0;
	aggr_port_t **pport;
	boolean_t mac_addr_changed = B_FALSE;
	boolean_t link_state_changed = B_FALSE;
	mac_perim_handle_t mph;
	uint64_t val;
	uint_t i;
	uint_t stat;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(grp->lg_nports > 1);
	ASSERT(!grp->lg_closing);

	/* unlink port */
	for (pport = &grp->lg_ports; *pport != port;
	    pport = &(*pport)->lp_next) {
		if (*pport == NULL) {
			rc = ENOENT;
			goto done;
		}
	}
	*pport = port->lp_next;

	mac_perim_enter_by_mh(port->lp_mh, &mph);

	/*
	 * If the MAC address of the port being removed was assigned
	 * to the group, update the group MAC address
	 * using the MAC address of a different port.
	 */
	if (!grp->lg_addr_fixed && grp->lg_mac_addr_port == port) {
		/*
		 * Set the MAC address of the group to the
		 * MAC address of its first port.
		 */
		bcopy(grp->lg_ports->lp_addr, grp->lg_addr, ETHERADDRL);
		grp->lg_mac_addr_port = grp->lg_ports;
		mac_addr_changed = B_TRUE;
	}

	link_state_changed = aggr_grp_detach_port(grp, port);

	/*
	 * Add the counter statistics of the ports while it was aggregated
	 * to the group's residual statistics.  This is done by obtaining
	 * the current counter from the underlying MAC then subtracting the
	 * value of the counter at the moment it was added to the
	 * aggregation.
	 */
	for (i = 0; i < MAC_NSTAT; i++) {
		stat = i + MAC_STAT_MIN;
		if (!MAC_STAT_ISACOUNTER(stat))
			continue;
		val = aggr_port_stat(port, stat);
		val -= port->lp_stat[i];
		grp->lg_stat[i] += val;
	}
	for (i = 0; i < ETHER_NSTAT; i++) {
		stat = i + MACTYPE_STAT_MIN;
		if (!ETHER_STAT_ISACOUNTER(stat))
			continue;
		val = aggr_port_stat(port, stat);
		val -= port->lp_ether_stat[i];
		grp->lg_ether_stat[i] += val;
	}

	grp->lg_nports--;
	mac_perim_exit(mph);

	aggr_rem_pseudo_tx_group(port, &grp->lg_tx_group);
	aggr_port_delete(port);

	/*
	 * If the group MAC address has changed, update the MAC address of
	 * the remaining constituent ports according to the new MAC
	 * address of the group.
	 */
	if (mac_addr_changed && aggr_grp_update_ports_mac(grp))
		link_state_changed = B_TRUE;

done:
	if (mac_addr_changedp != NULL)
		*mac_addr_changedp = mac_addr_changed;
	if (link_state_changedp != NULL)
		*link_state_changedp = link_state_changed;

	return (rc);
}

/*
 * Remove one or more ports from an existing link aggregation group.
 */
int
aggr_grp_rem_ports(datalink_id_t linkid, uint_t nports, laioc_port_t *ports)
{
	int rc = 0, i;
	aggr_grp_t *grp = NULL;
	aggr_port_t *port;
	boolean_t mac_addr_update = B_FALSE, mac_addr_changed;
	boolean_t link_state_update = B_FALSE, link_state_changed;
	mac_perim_handle_t mph, pmph;

	/* get group corresponding to linkid */
	rw_enter(&aggr_grp_lock, RW_READER);
	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}
	AGGR_GRP_REFHOLD(grp);

	/*
	 * Hold the perimeter so that the aggregation won't be destroyed.
	 */
	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	rw_exit(&aggr_grp_lock);

	/* we need to keep at least one port per group */
	if (nports >= grp->lg_nports) {
		rc = EINVAL;
		goto bail;
	}

	/* first verify that all the groups are valid */
	for (i = 0; i < nports; i++) {
		if (aggr_grp_port_lookup(grp, ports[i].lp_linkid) == NULL) {
			/* port not found */
			rc = ENOENT;
			goto bail;
		}
	}

	/* clear the promiscous mode for the specified ports */
	for (i = 0; i < nports && rc == 0; i++) {
		/* lookup port */
		port = aggr_grp_port_lookup(grp, ports[i].lp_linkid);
		ASSERT(port != NULL);

		mac_perim_enter_by_mh(port->lp_mh, &pmph);
		rc = aggr_port_promisc(port, B_FALSE);
		mac_perim_exit(pmph);
	}
	if (rc != 0) {
		for (i = 0; i < nports; i++) {
			port = aggr_grp_port_lookup(grp,
			    ports[i].lp_linkid);
			ASSERT(port != NULL);

			/*
			 * Turn the promiscuous mode back on if it is required
			 * to receive the non-primary address over a port, or
			 * the promiscous mode is enabled over the aggr.
			 */
			mac_perim_enter_by_mh(port->lp_mh, &pmph);
			if (port->lp_started && (grp->lg_promisc ||
			    port->lp_prom_addr != NULL)) {
				(void) aggr_port_promisc(port, B_TRUE);
			}
			mac_perim_exit(pmph);
		}
		goto bail;
	}

	/* remove the specified ports from group */
	for (i = 0; i < nports; i++) {
		/* lookup port */
		port = aggr_grp_port_lookup(grp, ports[i].lp_linkid);
		ASSERT(port != NULL);

		/* stop port if group has already been started */
		if (grp->lg_started) {
			mac_perim_enter_by_mh(port->lp_mh, &pmph);
			aggr_port_stop(port);
			mac_perim_exit(pmph);
		}

		/*
		 * aggr_rem_pseudo_tx_group() is not called here. Instead
		 * it is called from inside aggr_grp_rem_port() after the
		 * port has been detached. The reason is that
		 * aggr_rem_pseudo_tx_group() removes one ring at a time
		 * and if there is still traffic going on, then there
		 * is the possibility of aggr_find_tx_ring() returning a
		 * removed ring for transmission. Once the port has been
		 * detached, that port will not be used and
		 * aggr_find_tx_ring() will not return any rings
		 * belonging to it.
		 */
		aggr_rem_pseudo_rx_group(port, &grp->lg_rx_group);

		/* remove port from group */
		rc = aggr_grp_rem_port(grp, port, &mac_addr_changed,
		    &link_state_changed);
		ASSERT(rc == 0);
		mac_addr_update = mac_addr_update || mac_addr_changed;
		link_state_update = link_state_update || link_state_changed;
	}

bail:
	if (mac_addr_update)
		mac_unicst_update(grp->lg_mh, grp->lg_addr);
	if (link_state_update)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

	mac_perim_exit(mph);
	AGGR_GRP_REFRELE(grp);

	return (rc);
}

int
aggr_grp_delete(datalink_id_t linkid, cred_t *cred)
{
	aggr_grp_t *grp = NULL;
	aggr_port_t *port, *cport;
	datalink_id_t tmpid;
	mod_hash_val_t val;
	mac_perim_handle_t mph, pmph;
	int err;
	kt_did_t tid = 0;

	rw_enter(&aggr_grp_lock, RW_WRITER);

	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}

	/*
	 * Note that dls_devnet_destroy() must be called before lg_lock is
	 * held. Otherwise, it will deadlock if another thread is in
	 * aggr_m_stat() and thus has a kstat_hold() on the kstats that
	 * dls_devnet_destroy() needs to delete.
	 */
	if ((err = dls_devnet_destroy(grp->lg_mh, &tmpid, B_TRUE)) != 0) {
		rw_exit(&aggr_grp_lock);
		return (err);
	}
	ASSERT(linkid == tmpid);

	/*
	 * Unregister from the MAC service module. Since this can
	 * fail if a client hasn't closed the MAC port, we gracefully
	 * fail the operation.
	 */
	if ((err = mac_disable(grp->lg_mh)) != 0) {
		(void) dls_devnet_create(grp->lg_mh, linkid, crgetzoneid(cred));
		rw_exit(&aggr_grp_lock);
		return (err);
	}
	(void) mod_hash_remove(aggr_grp_hash, GRP_HASH_KEY(linkid), &val);
	ASSERT(grp == (aggr_grp_t *)val);

	ASSERT(aggr_grp_cnt > 0);
	aggr_grp_cnt--;
	rw_exit(&aggr_grp_lock);

	/*
	 * Inform the lacp_rx thread to exit.
	 */
	mutex_enter(&grp->lg_lacp_lock);
	grp->lg_lacp_done = B_TRUE;
	cv_signal(&grp->lg_lacp_cv);
	while (grp->lg_lacp_rx_thread != NULL)
		cv_wait(&grp->lg_lacp_cv, &grp->lg_lacp_lock);
	mutex_exit(&grp->lg_lacp_lock);
	/*
	 * Inform the tx_notify_thread to exit.
	 */
	mutex_enter(&grp->lg_tx_flowctl_lock);
	if (grp->lg_tx_notify_thread != NULL) {
		tid = grp->lg_tx_notify_thread->t_did;
		grp->lg_tx_notify_done = B_TRUE;
		cv_signal(&grp->lg_tx_flowctl_cv);
	}
	mutex_exit(&grp->lg_tx_flowctl_lock);
	if (tid != 0)
		thread_join(tid);

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	grp->lg_closing = B_TRUE;
	/* detach and free MAC ports associated with group */
	port = grp->lg_ports;
	while (port != NULL) {
		cport = port->lp_next;
		mac_perim_enter_by_mh(port->lp_mh, &pmph);
		if (grp->lg_started)
			aggr_port_stop(port);
		(void) aggr_grp_detach_port(grp, port);
		mac_perim_exit(pmph);
		aggr_rem_pseudo_tx_group(port, &grp->lg_tx_group);
		aggr_rem_pseudo_rx_group(port, &grp->lg_rx_group);
		aggr_port_delete(port);
		port = cport;
	}

	mac_perim_exit(mph);

	kmem_free(grp->lg_tx_blocked_rings,
	    (sizeof (mac_ring_handle_t *) * MAX_RINGS_PER_GROUP));
	/*
	 * Wait for the port's lacp timer thread and its notification callback
	 * to exit before calling mac_unregister() since both needs to access
	 * the mac perimeter of the grp.
	 */
	aggr_grp_port_wait(grp);

	VERIFY(mac_unregister(grp->lg_mh) == 0);
	grp->lg_mh = NULL;

	AGGR_GRP_REFRELE(grp);
	return (0);
}

void
aggr_grp_free(aggr_grp_t *grp)
{
	ASSERT(grp->lg_refs == 0);
	ASSERT(grp->lg_port_ref == 0);
	if (grp->lg_key > AGGR_MAX_KEY) {
		id_free(key_ids, grp->lg_key);
		grp->lg_key = 0;
	}
	kmem_cache_free(aggr_grp_cache, grp);
}

int
aggr_grp_info(datalink_id_t linkid, void *fn_arg,
    aggr_grp_info_new_grp_fn_t new_grp_fn,
    aggr_grp_info_new_port_fn_t new_port_fn, cred_t *cred)
{
	aggr_grp_t	*grp;
	aggr_port_t	*port;
	mac_perim_handle_t mph, pmph;
	int		rc = 0;

	/*
	 * Make sure that the aggregation link is visible from the caller's
	 * zone.
	 */
	if (!dls_devnet_islinkvisible(linkid, crgetzoneid(cred)))
		return (ENOENT);

	rw_enter(&aggr_grp_lock, RW_READER);

	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}
	AGGR_GRP_REFHOLD(grp);

	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	rw_exit(&aggr_grp_lock);

	rc = new_grp_fn(fn_arg, grp->lg_linkid,
	    (grp->lg_key > AGGR_MAX_KEY) ? 0 : grp->lg_key, grp->lg_addr,
	    grp->lg_addr_fixed, grp->lg_force, grp->lg_tx_policy,
	    grp->lg_nports, grp->lg_lacp_mode, grp->aggr.PeriodicTimer);

	if (rc != 0)
		goto bail;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		mac_perim_enter_by_mh(port->lp_mh, &pmph);
		rc = new_port_fn(fn_arg, port->lp_linkid, port->lp_addr,
		    port->lp_state, &port->lp_lacp.ActorOperPortState);
		mac_perim_exit(pmph);

		if (rc != 0)
			goto bail;
	}

bail:
	mac_perim_exit(mph);
	AGGR_GRP_REFRELE(grp);
	return (rc);
}

/*ARGSUSED*/
static void
aggr_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	miocnak(q, mp, 0, ENOTSUP);
}

static int
aggr_grp_stat(aggr_grp_t *grp, uint_t stat, uint64_t *val)
{
	aggr_port_t	*port;
	uint_t		stat_index;

	/* We only aggregate counter statistics. */
	if (IS_MAC_STAT(stat) && !MAC_STAT_ISACOUNTER(stat) ||
	    IS_MACTYPE_STAT(stat) && !ETHER_STAT_ISACOUNTER(stat)) {
		return (ENOTSUP);
	}

	/*
	 * Counter statistics for a group are computed by aggregating the
	 * counters of the members MACs while they were aggregated, plus
	 * the residual counter of the group itself, which is updated each
	 * time a MAC is removed from the group.
	 */
	*val = 0;
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		/* actual port statistic */
		*val += aggr_port_stat(port, stat);
		/*
		 * minus the port stat when it was added, plus any residual
		 * amount for the group.
		 */
		if (IS_MAC_STAT(stat)) {
			stat_index = stat - MAC_STAT_MIN;
			*val -= port->lp_stat[stat_index];
			*val += grp->lg_stat[stat_index];
		} else if (IS_MACTYPE_STAT(stat)) {
			stat_index = stat - MACTYPE_STAT_MIN;
			*val -= port->lp_ether_stat[stat_index];
			*val += grp->lg_ether_stat[stat_index];
		}
	}
	return (0);
}

int
aggr_rx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	aggr_pseudo_rx_ring_t   *rx_ring = (aggr_pseudo_rx_ring_t *)rdriver;

	if (rx_ring->arr_hw_rh != NULL) {
		*val = mac_pseudo_rx_ring_stat_get(rx_ring->arr_hw_rh, stat);
	} else {
		aggr_port_t	*port = rx_ring->arr_port;

		*val = mac_stat_get(port->lp_mh, stat);

	}
	return (0);
}

int
aggr_tx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	aggr_pseudo_tx_ring_t   *tx_ring = (aggr_pseudo_tx_ring_t *)rdriver;

	if (tx_ring->atr_hw_rh != NULL) {
		*val = mac_pseudo_tx_ring_stat_get(tx_ring->atr_hw_rh, stat);
	} else {
		aggr_port_t	*port = tx_ring->atr_port;

		*val = mac_stat_get(port->lp_mh, stat);
	}
	return (0);
}

static int
aggr_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	aggr_grp_t		*grp = arg;
	mac_perim_handle_t	mph;
	int			rval = 0;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = grp->lg_ifspeed;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = grp->lg_link_duplex;
		break;

	default:
		/*
		 * For all other statistics, we return the aggregated stat
		 * from the underlying ports.  aggr_grp_stat() will set
		 * rval appropriately if the statistic isn't a counter.
		 */
		rval = aggr_grp_stat(grp, stat, val);
	}

	mac_perim_exit(mph);
	return (rval);
}

static int
aggr_m_start(void *arg)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	mac_perim_handle_t mph, pmph;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	/*
	 * Attempts to start all configured members of the group.
	 * Group members will be attached when their link-up notification
	 * is received.
	 */
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		mac_perim_enter_by_mh(port->lp_mh, &pmph);
		if (aggr_port_start(port) != 0) {
			mac_perim_exit(pmph);
			continue;
		}

		/*
		 * Turn on the promiscuous mode if it is required to receive
		 * the non-primary address over a port, or the promiscous
		 * mode is enabled over the aggr.
		 */
		if (grp->lg_promisc || port->lp_prom_addr != NULL) {
			if (aggr_port_promisc(port, B_TRUE) != 0)
				aggr_port_stop(port);
		}
		mac_perim_exit(pmph);
	}

	grp->lg_started = B_TRUE;

	mac_perim_exit(mph);
	return (0);
}

static void
aggr_m_stop(void *arg)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	mac_perim_handle_t mph, pmph;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		mac_perim_enter_by_mh(port->lp_mh, &pmph);

		/* reset port promiscuous mode */
		(void) aggr_port_promisc(port, B_FALSE);

		aggr_port_stop(port);
		mac_perim_exit(pmph);
	}

	grp->lg_started = B_FALSE;
	mac_perim_exit(mph);
}

static int
aggr_m_promisc(void *arg, boolean_t on)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	boolean_t link_state_changed = B_FALSE;
	mac_perim_handle_t mph, pmph;

	AGGR_GRP_REFHOLD(grp);
	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	ASSERT(!grp->lg_closing);

	if (on == grp->lg_promisc)
		goto bail;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		int	err = 0;

		mac_perim_enter_by_mh(port->lp_mh, &pmph);
		AGGR_PORT_REFHOLD(port);
		if (!on && (port->lp_prom_addr == NULL))
			err = aggr_port_promisc(port, B_FALSE);
		else if (on && port->lp_started)
			err = aggr_port_promisc(port, B_TRUE);

		if (err != 0) {
			if (aggr_grp_detach_port(grp, port))
				link_state_changed = B_TRUE;
		} else {
			/*
			 * If a port was detached because of a previous
			 * failure changing the promiscuity, the port
			 * is reattached when it successfully changes
			 * the promiscuity now, and this might cause
			 * the link state of the aggregation to change.
			 */
			if (aggr_grp_attach_port(grp, port))
				link_state_changed = B_TRUE;
		}
		mac_perim_exit(pmph);
		AGGR_PORT_REFRELE(port);
	}

	grp->lg_promisc = on;

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

bail:
	mac_perim_exit(mph);
	AGGR_GRP_REFRELE(grp);

	return (0);
}

static void
aggr_grp_port_rename(const char *new_name, void *arg)
{
	/*
	 * aggr port's mac client name is the format of "aggr link name" plus
	 * AGGR_PORT_NAME_DELIMIT plus "underneath link name".
	 */
	int aggr_len, link_len, clnt_name_len, i;
	char *str_end, *str_st, *str_del;
	char aggr_name[MAXNAMELEN];
	char link_name[MAXNAMELEN];
	char *clnt_name;
	aggr_grp_t *aggr_grp = arg;
	aggr_port_t *aggr_port = aggr_grp->lg_ports;

	for (i = 0; i < aggr_grp->lg_nports; i++) {
		clnt_name = mac_client_name(aggr_port->lp_mch);
		clnt_name_len = strlen(clnt_name);
		str_st = clnt_name;
		str_end = &(clnt_name[clnt_name_len]);
		str_del = strchr(str_st, AGGR_PORT_NAME_DELIMIT);
		ASSERT(str_del != NULL);
		aggr_len = (intptr_t)((uintptr_t)str_del - (uintptr_t)str_st);
		link_len = (intptr_t)((uintptr_t)str_end - (uintptr_t)str_del);
		bzero(aggr_name, MAXNAMELEN);
		bzero(link_name, MAXNAMELEN);
		bcopy(clnt_name, aggr_name, aggr_len);
		bcopy(str_del, link_name, link_len + 1);
		bzero(clnt_name, MAXNAMELEN);
		(void) snprintf(clnt_name, MAXNAMELEN, "%s%s", new_name,
		    link_name);

		(void) mac_rename_primary(aggr_port->lp_mh, NULL);
		aggr_port = aggr_port->lp_next;
	}
}

/*
 * Initialize the capabilities that are advertised for the group
 * according to the capabilities of the constituent ports.
 */
static boolean_t
aggr_m_capab_get(void *arg, mac_capab_t cap, void *cap_data)
{
	aggr_grp_t *grp = arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksum_txflags = cap_data;
		*hcksum_txflags = grp->lg_hcksum_txflags;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (grp->lg_lso) {
			*cap_lso = grp->lg_cap_lso;
			break;
		} else {
			return (B_FALSE);
		}
	}
	case MAC_CAPAB_NO_NATIVEVLAN:
		return (!grp->lg_vlan);
	case MAC_CAPAB_NO_ZCOPY:
		return (!grp->lg_zcopy);
	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = cap_data;

		if (cap_rings->mr_type == MAC_RING_TYPE_RX) {
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = grp->lg_rx_group.arg_ring_cnt;

			/*
			 * An aggregation advertises only one (pseudo) RX
			 * group, which virtualizes the main/primary group of
			 * the underlying devices.
			 */
			cap_rings->mr_gnum = 1;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
		} else {
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = grp->lg_tx_group.atg_ring_cnt;
			cap_rings->mr_gnum = 0;
		}
		cap_rings->mr_rget = aggr_fill_ring;
		cap_rings->mr_gget = aggr_fill_group;
		break;
	}
	case MAC_CAPAB_AGGR:
	{
		mac_capab_aggr_t *aggr_cap;

		if (cap_data != NULL) {
			aggr_cap = cap_data;
			aggr_cap->mca_rename_fn = aggr_grp_port_rename;
			aggr_cap->mca_unicst = aggr_m_unicst;
			aggr_cap->mca_find_tx_ring_fn = aggr_find_tx_ring;
			aggr_cap->mca_arg = arg;
		}
		return (B_TRUE);
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Callback funtion for MAC layer to register groups.
 */
static void
aggr_fill_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	aggr_grp_t *grp = arg;
	aggr_pseudo_rx_group_t *rx_group;
	aggr_pseudo_tx_group_t *tx_group;

	ASSERT(index == 0);
	if (rtype == MAC_RING_TYPE_RX) {
		rx_group = &grp->lg_rx_group;
		rx_group->arg_gh = gh;
		rx_group->arg_grp = grp;

		infop->mgi_driver = (mac_group_driver_t)rx_group;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = aggr_addmac;
		infop->mgi_remmac = aggr_remmac;
		infop->mgi_count = rx_group->arg_ring_cnt;
	} else {
		tx_group = &grp->lg_tx_group;
		tx_group->atg_gh = gh;
	}
}

/*
 * Callback funtion for MAC layer to register all rings.
 */
static void
aggr_fill_ring(void *arg, mac_ring_type_t rtype, const int rg_index,
    const int index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	aggr_grp_t	*grp = arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		aggr_pseudo_rx_group_t	*rx_group = &grp->lg_rx_group;
		aggr_pseudo_rx_ring_t	*rx_ring;
		mac_intr_t		aggr_mac_intr;

		ASSERT(rg_index == 0);

		ASSERT((index >= 0) && (index < rx_group->arg_ring_cnt));
		rx_ring = rx_group->arg_rings + index;
		rx_ring->arr_rh = rh;

		/*
		 * Entrypoint to enable interrupt (disable poll) and
		 * disable interrupt (enable poll).
		 */
		aggr_mac_intr.mi_handle = (mac_intr_handle_t)rx_ring;
		aggr_mac_intr.mi_enable = aggr_pseudo_enable_intr;
		aggr_mac_intr.mi_disable = aggr_pseudo_disable_intr;
		aggr_mac_intr.mi_ddi_handle = NULL;

		infop->mri_driver = (mac_ring_driver_t)rx_ring;
		infop->mri_start = aggr_pseudo_start_ring;
		infop->mri_stop = aggr_pseudo_stop_ring;

		infop->mri_intr = aggr_mac_intr;
		infop->mri_poll = aggr_rx_poll;

		infop->mri_stat = aggr_rx_ring_stat;
		break;
	}
	case MAC_RING_TYPE_TX: {
		aggr_pseudo_tx_group_t	*tx_group = &grp->lg_tx_group;
		aggr_pseudo_tx_ring_t	*tx_ring;

		ASSERT(rg_index == -1);
		ASSERT(index < tx_group->atg_ring_cnt);

		tx_ring = &tx_group->atg_rings[index];
		tx_ring->atr_rh = rh;

		infop->mri_driver = (mac_ring_driver_t)tx_ring;
		infop->mri_start = NULL;
		infop->mri_stop = NULL;
		infop->mri_tx = aggr_ring_tx;
		infop->mri_stat = aggr_tx_ring_stat;
		/*
		 * Use the hw TX ring handle to find if the ring needs
		 * serialization or not. For NICs that do not expose
		 * Tx rings, atr_hw_rh will be NULL.
		 */
		if (tx_ring->atr_hw_rh != NULL) {
			infop->mri_flags =
			    mac_hwring_getinfo(tx_ring->atr_hw_rh);
		}
		break;
	}
	default:
		break;
	}
}

static mblk_t *
aggr_rx_poll(void *arg, int bytes_to_pickup)
{
	aggr_pseudo_rx_ring_t *rr_ring = arg;
	aggr_port_t *port = rr_ring->arr_port;
	aggr_grp_t *grp = port->lp_grp;
	mblk_t *mp_chain, *mp, **mpp;

	mp_chain = mac_hwring_poll(rr_ring->arr_hw_rh, bytes_to_pickup);

	if (grp->lg_lacp_mode == AGGR_LACP_OFF)
		return (mp_chain);

	mpp = &mp_chain;
	while ((mp = *mpp) != NULL) {
		if (MBLKL(mp) >= sizeof (struct ether_header)) {
			struct ether_header *ehp;

			ehp = (struct ether_header *)mp->b_rptr;
			if (ntohs(ehp->ether_type) == ETHERTYPE_SLOW) {
				*mpp = mp->b_next;
				mp->b_next = NULL;
				aggr_recv_lacp(port,
				    (mac_resource_handle_t)rr_ring, mp);
				continue;
			}
		}

		if (!port->lp_collector_enabled) {
			*mpp = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			continue;
		}
		mpp = &mp->b_next;
	}
	return (mp_chain);
}

static int
aggr_addmac(void *arg, const uint8_t *mac_addr)
{
	aggr_pseudo_rx_group_t	*rx_group = (aggr_pseudo_rx_group_t *)arg;
	aggr_unicst_addr_t	*addr, **pprev;
	aggr_grp_t		*grp = rx_group->arg_grp;
	aggr_port_t		*port, *p;
	mac_perim_handle_t	mph;
	int			err = 0;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	if (bcmp(mac_addr, grp->lg_addr, ETHERADDRL) == 0) {
		mac_perim_exit(mph);
		return (0);
	}

	/*
	 * Insert this mac address into the list of mac addresses owned by
	 * the aggregation pseudo group.
	 */
	pprev = &rx_group->arg_macaddr;
	while ((addr = *pprev) != NULL) {
		if (bcmp(mac_addr, addr->aua_addr, ETHERADDRL) == 0) {
			mac_perim_exit(mph);
			return (EEXIST);
		}
		pprev = &addr->aua_next;
	}
	addr = kmem_alloc(sizeof (aggr_unicst_addr_t), KM_SLEEP);
	bcopy(mac_addr, addr->aua_addr, ETHERADDRL);
	addr->aua_next = NULL;
	*pprev = addr;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next)
		if ((err = aggr_port_addmac(port, mac_addr)) != 0)
			break;

	if (err != 0) {
		for (p = grp->lg_ports; p != port; p = p->lp_next)
			aggr_port_remmac(p, mac_addr);

		*pprev = NULL;
		kmem_free(addr, sizeof (aggr_unicst_addr_t));
	}

	mac_perim_exit(mph);
	return (err);
}

static int
aggr_remmac(void *arg, const uint8_t *mac_addr)
{
	aggr_pseudo_rx_group_t	*rx_group = (aggr_pseudo_rx_group_t *)arg;
	aggr_unicst_addr_t	*addr, **pprev;
	aggr_grp_t		*grp = rx_group->arg_grp;
	aggr_port_t		*port;
	mac_perim_handle_t	mph;
	int			err = 0;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);

	if (bcmp(mac_addr, grp->lg_addr, ETHERADDRL) == 0) {
		mac_perim_exit(mph);
		return (0);
	}

	/*
	 * Insert this mac address into the list of mac addresses owned by
	 * the aggregation pseudo group.
	 */
	pprev = &rx_group->arg_macaddr;
	while ((addr = *pprev) != NULL) {
		if (bcmp(mac_addr, addr->aua_addr, ETHERADDRL) != 0) {
			pprev = &addr->aua_next;
			continue;
		}
		break;
	}
	if (addr == NULL) {
		mac_perim_exit(mph);
		return (EINVAL);
	}

	for (port = grp->lg_ports; port != NULL; port = port->lp_next)
		aggr_port_remmac(port, mac_addr);

	*pprev = addr->aua_next;
	kmem_free(addr, sizeof (aggr_unicst_addr_t));

	mac_perim_exit(mph);
	return (err);
}

/*
 * Add or remove the multicast addresses that are defined for the group
 * to or from the specified port.
 *
 * Note that aggr_grp_multicst_port(..., B_TRUE) is called when the port
 * is started and attached, and aggr_grp_multicst_port(..., B_FALSE) is
 * called when the port is either stopped or detached.
 */
void
aggr_grp_multicst_port(aggr_port_t *port, boolean_t add)
{
	aggr_grp_t *grp = port->lp_grp;

	ASSERT(MAC_PERIM_HELD(port->lp_mh));
	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	if (!port->lp_started || port->lp_state != AGGR_PORT_STATE_ATTACHED)
		return;

	mac_multicast_refresh(grp->lg_mh, aggr_port_multicst, port, add);
}

static int
aggr_m_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port = NULL, *errport = NULL;
	mac_perim_handle_t mph;
	int err = 0;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (port->lp_state != AGGR_PORT_STATE_ATTACHED ||
		    !port->lp_started) {
			continue;
		}
		err = aggr_port_multicst(port, add, addrp);
		if (err != 0) {
			errport = port;
			break;
		}
	}

	/*
	 * At least one port caused error return and this error is returned to
	 * mac, eventually a NAK would be sent upwards.
	 * Some ports have this multicast address listed now, and some don't.
	 * Treat this error as a whole aggr failure not individual port failure.
	 * Therefore remove this multicast address from other ports.
	 */
	if ((err != 0) && add) {
		for (port = grp->lg_ports; port != errport;
		    port = port->lp_next) {
			if (port->lp_state != AGGR_PORT_STATE_ATTACHED ||
			    !port->lp_started) {
				continue;
			}
			(void) aggr_port_multicst(port, B_FALSE, addrp);
		}
	}
	mac_perim_exit(mph);
	return (err);
}

static int
aggr_m_unicst(void *arg, const uint8_t *macaddr)
{
	aggr_grp_t *grp = arg;
	mac_perim_handle_t mph;
	int err;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	err = aggr_grp_modify_common(grp, AGGR_MODIFY_MAC, 0, B_TRUE, macaddr,
	    0, 0);
	mac_perim_exit(mph);
	return (err);
}

/*
 * Initialize the capabilities that are advertised for the group
 * according to the capabilities of the constituent ports.
 */
static void
aggr_grp_capab_set(aggr_grp_t *grp)
{
	uint32_t cksum;
	aggr_port_t *port;
	mac_capab_lso_t cap_lso;

	ASSERT(grp->lg_mh == NULL);
	ASSERT(grp->lg_ports != NULL);

	grp->lg_hcksum_txflags = (uint32_t)-1;
	grp->lg_zcopy = B_TRUE;
	grp->lg_vlan = B_TRUE;

	grp->lg_lso = B_TRUE;
	grp->lg_cap_lso.lso_flags = (t_uscalar_t)-1;
	grp->lg_cap_lso.lso_basic_tcp_ipv4.lso_max = (t_uscalar_t)-1;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (!mac_capab_get(port->lp_mh, MAC_CAPAB_HCKSUM, &cksum))
			cksum = 0;
		grp->lg_hcksum_txflags &= cksum;

		grp->lg_vlan &=
		    !mac_capab_get(port->lp_mh, MAC_CAPAB_NO_NATIVEVLAN, NULL);

		grp->lg_zcopy &=
		    !mac_capab_get(port->lp_mh, MAC_CAPAB_NO_ZCOPY, NULL);

		grp->lg_lso &=
		    mac_capab_get(port->lp_mh, MAC_CAPAB_LSO, &cap_lso);
		if (grp->lg_lso) {
			grp->lg_cap_lso.lso_flags &= cap_lso.lso_flags;
			if (grp->lg_cap_lso.lso_basic_tcp_ipv4.lso_max >
			    cap_lso.lso_basic_tcp_ipv4.lso_max)
				grp->lg_cap_lso.lso_basic_tcp_ipv4.lso_max =
				    cap_lso.lso_basic_tcp_ipv4.lso_max;
		}
	}
}

/*
 * Checks whether the capabilities of the port being added are compatible
 * with the current capabilities of the aggregation.
 */
static boolean_t
aggr_grp_capab_check(aggr_grp_t *grp, aggr_port_t *port)
{
	uint32_t hcksum_txflags;

	ASSERT(grp->lg_ports != NULL);

	if (((!mac_capab_get(port->lp_mh, MAC_CAPAB_NO_NATIVEVLAN, NULL)) &
	    grp->lg_vlan) != grp->lg_vlan) {
		return (B_FALSE);
	}

	if (((!mac_capab_get(port->lp_mh, MAC_CAPAB_NO_ZCOPY, NULL)) &
	    grp->lg_zcopy) != grp->lg_zcopy) {
		return (B_FALSE);
	}

	if (!mac_capab_get(port->lp_mh, MAC_CAPAB_HCKSUM, &hcksum_txflags)) {
		if (grp->lg_hcksum_txflags != 0)
			return (B_FALSE);
	} else if ((hcksum_txflags & grp->lg_hcksum_txflags) !=
	    grp->lg_hcksum_txflags) {
		return (B_FALSE);
	}

	if (grp->lg_lso) {
		mac_capab_lso_t cap_lso;

		if (mac_capab_get(port->lp_mh, MAC_CAPAB_LSO, &cap_lso)) {
			if ((grp->lg_cap_lso.lso_flags & cap_lso.lso_flags) !=
			    grp->lg_cap_lso.lso_flags)
				return (B_FALSE);
			if (grp->lg_cap_lso.lso_basic_tcp_ipv4.lso_max >
			    cap_lso.lso_basic_tcp_ipv4.lso_max)
				return (B_FALSE);
		} else {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Returns the maximum SDU according to the SDU of the constituent ports.
 */
static uint_t
aggr_grp_max_sdu(aggr_grp_t *grp)
{
	uint_t max_sdu = (uint_t)-1;
	aggr_port_t *port;

	ASSERT(grp->lg_ports != NULL);

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		uint_t port_sdu_max;

		mac_sdu_get(port->lp_mh, NULL, &port_sdu_max);
		if (max_sdu > port_sdu_max)
			max_sdu = port_sdu_max;
	}

	return (max_sdu);
}

/*
 * Checks if the maximum SDU of the specified port is compatible
 * with the maximum SDU of the specified aggregation group, returns
 * B_TRUE if it is, B_FALSE otherwise.
 */
static boolean_t
aggr_grp_sdu_check(aggr_grp_t *grp, aggr_port_t *port)
{
	uint_t port_sdu_max;

	mac_sdu_get(port->lp_mh, NULL, &port_sdu_max);
	return (port_sdu_max >= grp->lg_max_sdu);
}

/*
 * Returns the maximum margin according to the margin of the constituent ports.
 */
static uint32_t
aggr_grp_max_margin(aggr_grp_t *grp)
{
	uint32_t margin = UINT32_MAX;
	aggr_port_t *port;

	ASSERT(grp->lg_mh == NULL);
	ASSERT(grp->lg_ports != NULL);

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (margin > port->lp_margin)
			margin = port->lp_margin;
	}

	grp->lg_margin = margin;
	return (margin);
}

/*
 * Checks if the maximum margin of the specified port is compatible
 * with the maximum margin of the specified aggregation group, returns
 * B_TRUE if it is, B_FALSE otherwise.
 */
static boolean_t
aggr_grp_margin_check(aggr_grp_t *grp, aggr_port_t *port)
{
	if (port->lp_margin >= grp->lg_margin)
		return (B_TRUE);

	/*
	 * See whether the current margin value is allowed to be changed to
	 * the new value.
	 */
	if (!mac_margin_update(grp->lg_mh, port->lp_margin))
		return (B_FALSE);

	grp->lg_margin = port->lp_margin;
	return (B_TRUE);
}

/*
 * Set MTU on individual ports of an aggregation group
 */
static int
aggr_set_port_sdu(aggr_grp_t *grp, aggr_port_t *port, uint32_t sdu,
    uint32_t *old_mtu)
{
	boolean_t 		removed = B_FALSE;
	mac_perim_handle_t	mph;
	mac_diag_t		diag;
	int			err, rv, retry = 0;

	if (port->lp_mah != NULL) {
		(void) mac_unicast_remove(port->lp_mch, port->lp_mah);
		port->lp_mah = NULL;
		removed = B_TRUE;
	}
	err = mac_set_mtu(port->lp_mh, sdu, old_mtu);
try_again:
	if (removed && (rv = mac_unicast_add(port->lp_mch, NULL,
	    MAC_UNICAST_PRIMARY | MAC_UNICAST_DISABLE_TX_VID_CHECK,
	    &port->lp_mah, 0, &diag)) != 0) {
		/*
		 * following is a workaround for a bug in 'bge' driver.
		 * See CR 6794654 for more information and this work around
		 * will be removed once the CR is fixed.
		 */
		if (rv == EIO && retry++ < 3) {
			delay(2 * hz);
			goto try_again;
		}
		/*
		 * if mac_unicast_add() failed while setting the MTU,
		 * detach the port from the group.
		 */
		mac_perim_enter_by_mh(port->lp_mh, &mph);
		(void) aggr_grp_detach_port(grp, port);
		mac_perim_exit(mph);
		cmn_err(CE_WARN, "Unable to restart the port %s while "
		    "setting MTU. Detaching the port from the aggregation.",
		    mac_client_name(port->lp_mch));
	}
	return (err);
}

static int
aggr_sdu_update(aggr_grp_t *grp, uint32_t sdu)
{
	int			err = 0, i, rv;
	aggr_port_t		*port;
	uint32_t		*mtu;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	/*
	 * If the MTU being set is equal to aggr group's maximum
	 * allowable value, then there is nothing to change
	 */
	if (sdu == grp->lg_max_sdu)
		return (0);

	/* 0 is aggr group's min sdu */
	if (sdu == 0)
		return (EINVAL);

	mtu = kmem_alloc(sizeof (uint32_t) * grp->lg_nports, KM_SLEEP);
	for (port = grp->lg_ports, i = 0; port != NULL && err == 0;
	    port = port->lp_next, i++) {
		err = aggr_set_port_sdu(grp, port, sdu, mtu + i);
	}
	if (err != 0) {
		/* recover from error: reset the mtus of the ports */
		aggr_port_t *tmp;

		for (tmp = grp->lg_ports, i = 0; tmp != port;
		    tmp = tmp->lp_next, i++) {
			(void) aggr_set_port_sdu(grp, tmp, *(mtu + i), NULL);
		}
		goto bail;
	}
	grp->lg_max_sdu = aggr_grp_max_sdu(grp);
	rv = mac_maxsdu_update(grp->lg_mh, grp->lg_max_sdu);
	ASSERT(rv == 0);
bail:
	kmem_free(mtu, sizeof (uint32_t) * grp->lg_nports);
	return (err);
}

/*
 * Callback functions for set/get of properties
 */
/*ARGSUSED*/
static int
aggr_m_setprop(void *m_driver, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	int 		err = ENOTSUP;
	aggr_grp_t 	*grp = m_driver;

	switch (pr_num) {
	case MAC_PROP_MTU: {
		uint32_t 	mtu;

		if (pr_valsize < sizeof (mtu)) {
			err = EINVAL;
			break;
		}
		bcopy(pr_val, &mtu, sizeof (mtu));
		err = aggr_sdu_update(grp, mtu);
		break;
	}
	default:
		break;
	}
	return (err);
}

typedef struct rboundary {
	uint32_t	bval;
	int		btype;
} rboundary_t;

/*
 * This function finds the intersection of mtu ranges stored in arrays -
 * mrange[0] ... mrange[mcount -1]. It returns the intersection in rval.
 * Individual arrays are assumed to contain non-overlapping ranges.
 * Algorithm:
 *   A range has two boundaries - min and max. We scan all arrays and store
 * each boundary as a separate element in a temporary array. We also store
 * the boundary types, min or max, as +1 or -1 respectively in the temporary
 * array. Then we sort the temporary array in ascending order. We scan the
 * sorted array from lower to higher values and keep a cumulative sum of
 * boundary types. Element in the temporary array for which the sum reaches
 * mcount is a min boundary of a range in the result and next element will be
 * max boundary.
 *
 * Example for mcount = 3,
 *
 *  ----|_________|-------|_______|----|__|------ mrange[0]
 *
 *  -------|________|--|____________|-----|___|-- mrange[1]
 *
 *  --------|________________|-------|____|------ mrange[2]
 *
 *                                      3 2 1
 *                                       \|/
 *      1  23     2 1  2  3  2    1 01 2  V   0  <- the sum
 *  ----|--||-----|-|--|--|--|----|-||-|--|---|-- sorted array
 *
 *                                 same min and max
 *                                        V
 *  --------|_____|-------|__|------------|------ intersecting ranges
 */
void
aggr_mtu_range_intersection(mac_propval_range_t **mrange, int mcount,
    mac_propval_uint32_range_t **prval, int *prmaxcnt, int *prcount)
{
	mac_propval_uint32_range_t	*rval, *ur;
	int				rmaxcnt, rcount;
	size_t				sz_range32;
	rboundary_t			*ta; /* temporary array */
	rboundary_t			temp;
	boolean_t			range_started = B_FALSE;
	int				i, j, m, sum;

	sz_range32 = sizeof (mac_propval_uint32_range_t);

	for (i = 0, rmaxcnt = 0; i < mcount; i++)
		rmaxcnt += mrange[i]->mpr_count;

	/* Allocate enough space to store the results */
	rval = kmem_alloc(rmaxcnt * sz_range32, KM_SLEEP);

	/* Number of boundaries are twice as many as ranges */
	ta = kmem_alloc(2 * rmaxcnt * sizeof (rboundary_t), KM_SLEEP);

	for (i = 0, m = 0; i < mcount; i++) {
		ur = &(mrange[i]->mpr_range_uint32[0]);
		for (j = 0; j < mrange[i]->mpr_count; j++) {
			ta[m].bval = ur[j].mpur_min;
			ta[m++].btype = 1;
			ta[m].bval = ur[j].mpur_max;
			ta[m++].btype = -1;
		}
	}

	/*
	 * Sort the temporary array in ascending order of bval;
	 * if boundary values are same then sort on btype.
	 */
	for (i = 0; i < m-1; i++) {
		for (j = i+1; j < m; j++) {
			if ((ta[i].bval > ta[j].bval) ||
			    ((ta[i].bval == ta[j].bval) &&
			    (ta[i].btype < ta[j].btype))) {
				temp = ta[i];
				ta[i] = ta[j];
				ta[j] = temp;
			}
		}
	}

	/* Walk through temporary array to find all ranges in the results */
	for (i = 0, sum = 0, rcount = 0; i < m; i++) {
		sum += ta[i].btype;
		if (sum == mcount) {
			rval[rcount].mpur_min = ta[i].bval;
			range_started = B_TRUE;
		} else if (sum < mcount && range_started) {
			rval[rcount++].mpur_max = ta[i].bval;
			range_started = B_FALSE;
		}
	}

	*prval = rval;
	*prmaxcnt = rmaxcnt;
	*prcount = rcount;

	kmem_free(ta, 2 * rmaxcnt * sizeof (rboundary_t));
}

/*
 * Returns the mtu ranges which could be supported by aggr group.
 * prmaxcnt returns the size of the buffer prval, prcount returns
 * the number of valid entries in prval. Caller is responsible
 * for freeing up prval.
 */
int
aggr_grp_possible_mtu_range(aggr_grp_t *grp, mac_propval_uint32_range_t **prval,
    int *prmaxcnt, int *prcount)
{
	mac_propval_range_t		**vals;
	aggr_port_t			*port;
	mac_perim_handle_t		mph;
	uint_t 				i, numr;
	int 				err = 0;
	size_t				sz_propval, sz_range32;
	size_t				size;

	sz_propval = sizeof (mac_propval_range_t);
	sz_range32 = sizeof (mac_propval_uint32_range_t);

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	vals = kmem_zalloc(sizeof (mac_propval_range_t *) * grp->lg_nports,
	    KM_SLEEP);

	for (port = grp->lg_ports, i = 0; port != NULL;
	    port = port->lp_next, i++) {

		size = sz_propval;
		vals[i] = kmem_alloc(size, KM_SLEEP);
		vals[i]->mpr_count = 1;

		mac_perim_enter_by_mh(port->lp_mh, &mph);

		err = mac_prop_info(port->lp_mh, MAC_PROP_MTU, NULL,
		    NULL, 0, vals[i], NULL);
		if (err == ENOSPC) {
			/*
			 * Not enough space to hold all ranges.
			 * Allocate extra space as indicated and retry.
			 */
			numr = vals[i]->mpr_count;
			kmem_free(vals[i], sz_propval);
			size = sz_propval + (numr - 1) * sz_range32;
			vals[i] = kmem_alloc(size, KM_SLEEP);
			vals[i]->mpr_count = numr;
			err = mac_prop_info(port->lp_mh, MAC_PROP_MTU, NULL,
			    NULL, 0, vals[i], NULL);
			ASSERT(err != ENOSPC);
		}
		mac_perim_exit(mph);
		if (err != 0) {
			kmem_free(vals[i], size);
			vals[i] = NULL;
			break;
		}
	}

	/*
	 * if any of the underlying ports does not support changing MTU then
	 * just return ENOTSUP
	 */
	if (port != NULL) {
		ASSERT(err != 0);
		goto done;
	}

	aggr_mtu_range_intersection(vals, grp->lg_nports, prval, prmaxcnt,
	    prcount);

done:
	for (i = 0; i < grp->lg_nports; i++) {
		if (vals[i] != NULL) {
			numr = vals[i]->mpr_count;
			size = sz_propval + (numr - 1) * sz_range32;
			kmem_free(vals[i], size);
		}
	}

	kmem_free(vals, sizeof (mac_propval_range_t *) * grp->lg_nports);
	return (err);
}

static void
aggr_m_propinfo(void *m_driver, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	aggr_grp_t			*grp = m_driver;
	mac_propval_uint32_range_t	*rval = NULL;
	int				i, rcount, rmaxcnt;
	int				err = 0;

	_NOTE(ARGUNUSED(pr_name));

	switch (pr_num) {
	case MAC_PROP_MTU:

		err = aggr_grp_possible_mtu_range(grp, &rval, &rmaxcnt,
		    &rcount);
		if (err != 0) {
			ASSERT(rval == NULL);
			return;
		}
		for (i = 0; i < rcount; i++) {
			mac_prop_info_set_range_uint32(prh,
			    rval[i].mpur_min, rval[i].mpur_max);
		}
		kmem_free(rval, sizeof (mac_propval_uint32_range_t) * rmaxcnt);
		break;
	}
}
