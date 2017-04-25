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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 OmniTI Computer Consulting, Inc  All rights reserved.
 * Copyright (c) 2017 Joyent, Inc.
 */

/*
 * IEEE 802.3ad Link Aggregation - Link Aggregation MAC ports.
 *
 * Implements the functions needed to manage the MAC ports that are
 * part of Link Aggregation groups.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/id_space.h>
#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/stat.h>
#include <sys/sdt.h>
#include <sys/dlpi.h>
#include <sys/dls.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>

static kmem_cache_t *aggr_port_cache;
static id_space_t *aggr_portids;

static void aggr_port_notify_cb(void *, mac_notify_type_t);

/*ARGSUSED*/
static int
aggr_port_constructor(void *buf, void *arg, int kmflag)
{
	bzero(buf, sizeof (aggr_port_t));
	return (0);
}

/*ARGSUSED*/
static void
aggr_port_destructor(void *buf, void *arg)
{
	aggr_port_t *port = buf;

	ASSERT(port->lp_mnh == NULL);
	ASSERT(port->lp_mphp == NULL);
	ASSERT(!port->lp_rx_grp_added && !port->lp_tx_grp_added);
	ASSERT(port->lp_hwgh == NULL);
}

void
aggr_port_init(void)
{
	aggr_port_cache = kmem_cache_create("aggr_port_cache",
	    sizeof (aggr_port_t), 0, aggr_port_constructor,
	    aggr_port_destructor, NULL, NULL, NULL, 0);

	/*
	 * Allocate a id space to manage port identification. The range of
	 * the arena will be from 1 to UINT16_MAX, because the LACP protocol
	 * specifies 16-bit unique identification.
	 */
	aggr_portids = id_space_create("aggr_portids", 1, UINT16_MAX);
	ASSERT(aggr_portids != NULL);
}

void
aggr_port_fini(void)
{
	/*
	 * This function is called only after all groups have been
	 * freed. This ensures that there are no remaining allocated
	 * ports when this function is invoked.
	 */
	kmem_cache_destroy(aggr_port_cache);
	id_space_destroy(aggr_portids);
}

/* ARGSUSED */
void
aggr_port_init_callbacks(aggr_port_t *port)
{
	/* add the port's receive callback */
	port->lp_mnh = mac_notify_add(port->lp_mh, aggr_port_notify_cb, port);
	/*
	 * Hold a reference of the grp and the port and this reference will
	 * be released when the thread exits.
	 *
	 * The reference on the port is used for aggr_port_delete() to
	 * continue without waiting for the thread to exit; the reference
	 * on the grp is used for aggr_grp_delete() to wait for the thread
	 * to exit before calling mac_unregister().
	 *
	 * Note that these references will be released either in
	 * aggr_port_delete() when mac_notify_remove() succeeds, or in
	 * the aggr_port_notify_cb() callback when the port is deleted
	 * (lp_closing is set).
	 */
	aggr_grp_port_hold(port);
}

/* ARGSUSED */
int
aggr_port_create(aggr_grp_t *grp, const datalink_id_t linkid, boolean_t force,
    aggr_port_t **pp)
{
	int err;
	mac_handle_t mh;
	mac_client_handle_t mch = NULL;
	aggr_port_t *port;
	uint16_t portid;
	uint_t i;
	boolean_t no_link_update = B_FALSE;
	const mac_info_t *mip;
	uint32_t note;
	uint32_t margin;
	char client_name[MAXNAMELEN];
	char aggr_name[MAXNAMELEN];
	char port_name[MAXNAMELEN];
	mac_diag_t diag;
	mac_unicast_handle_t mah;

	*pp = NULL;

	if ((err = mac_open_by_linkid(linkid, &mh)) != 0)
		return (err);

	mip = mac_info(mh);
	if (mip->mi_media != DL_ETHER || mip->mi_nativemedia != DL_ETHER) {
		err = EINVAL;
		goto fail;
	}

	/*
	 * If the underlying MAC does not support link update notification, it
	 * can only be aggregated if `force' is set.  This is because aggr
	 * depends on link notifications to attach ports whose link is up.
	 */
	note = mac_no_notification(mh);
	if ((note & (DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN)) != 0) {
		no_link_update = B_TRUE;
		if (!force) {
			/*
			 * We borrow this error code to indicate that link
			 * notification is not supported.
			 */
			err = ENETDOWN;
			goto fail;
		}
	}

	if (((err = dls_mgmt_get_linkinfo(grp->lg_linkid,
	    aggr_name, NULL, NULL, NULL)) != 0) ||
	    ((err = dls_mgmt_get_linkinfo(linkid, port_name,
	    NULL, NULL, NULL)) != 0)) {
		goto fail;
	}

	(void) snprintf(client_name, MAXNAMELEN, "%s-%s", aggr_name, port_name);
	if ((err = mac_client_open(mh, &mch, client_name,
	    MAC_OPEN_FLAGS_IS_AGGR_PORT | MAC_OPEN_FLAGS_EXCLUSIVE)) != 0) {
		goto fail;
	}

	if ((portid = (uint16_t)id_alloc(aggr_portids)) == 0) {
		err = ENOMEM;
		goto fail;
	}

	/*
	 * As the underlying mac's current margin size is used to determine
	 * the margin size of the aggregation itself, request the underlying
	 * mac not to change to a smaller size.
	 */
	if ((err = mac_margin_add(mh, &margin, B_TRUE)) != 0) {
		id_free(aggr_portids, portid);
		goto fail;
	}

	if ((err = mac_unicast_add(mch, NULL, MAC_UNICAST_PRIMARY |
	    MAC_UNICAST_DISABLE_TX_VID_CHECK, &mah, 0, &diag)) != 0) {
		VERIFY(mac_margin_remove(mh, margin) == 0);
		id_free(aggr_portids, portid);
		goto fail;
	}

	port = kmem_cache_alloc(aggr_port_cache, KM_SLEEP);

	port->lp_refs = 1;
	port->lp_next = NULL;
	port->lp_mh = mh;
	port->lp_mch = mch;
	port->lp_mip = mip;
	port->lp_linkid = linkid;
	port->lp_closing = B_FALSE;
	port->lp_mah = mah;

	/* get the port's original MAC address */
	mac_unicast_primary_get(port->lp_mh, port->lp_addr);

	/* initialize state */
	port->lp_state = AGGR_PORT_STATE_STANDBY;
	port->lp_link_state = LINK_STATE_UNKNOWN;
	port->lp_ifspeed = 0;
	port->lp_link_duplex = LINK_DUPLEX_UNKNOWN;
	port->lp_started = B_FALSE;
	port->lp_tx_enabled = B_FALSE;
	port->lp_promisc_on = B_FALSE;
	port->lp_no_link_update = no_link_update;
	port->lp_portid = portid;
	port->lp_margin = margin;
	port->lp_prom_addr = NULL;

	/*
	 * Save the current statistics of the port. They will be used
	 * later by aggr_m_stats() when aggregating the statistics of
	 * the constituent ports.
	 */
	for (i = 0; i < MAC_NSTAT; i++) {
		port->lp_stat[i] =
		    aggr_port_stat(port, i + MAC_STAT_MIN);
	}
	for (i = 0; i < ETHER_NSTAT; i++) {
		port->lp_ether_stat[i] =
		    aggr_port_stat(port, i + MACTYPE_STAT_MIN);
	}

	/* LACP related state */
	port->lp_collector_enabled = B_FALSE;

	*pp = port;
	return (0);

fail:
	if (mch != NULL)
		mac_client_close(mch, MAC_CLOSE_FLAGS_EXCLUSIVE);
	mac_close(mh);
	return (err);
}

void
aggr_port_delete(aggr_port_t *port)
{
	aggr_lacp_port_t *pl = &port->lp_lacp;

	ASSERT(port->lp_mphp == NULL);
	ASSERT(!port->lp_promisc_on);

	port->lp_closing = B_TRUE;

	VERIFY(mac_margin_remove(port->lp_mh, port->lp_margin) == 0);
	mac_rx_clear(port->lp_mch);
	/*
	 * If the notification callback is already in process and waiting for
	 * the aggr grp's mac perimeter, don't wait (otherwise there would be
	 * deadlock). Otherwise, if mac_notify_remove() succeeds, we can
	 * release the reference held when mac_notify_add() is called.
	 */
	if ((port->lp_mnh != NULL) &&
	    (mac_notify_remove(port->lp_mnh, B_FALSE) == 0)) {
		aggr_grp_port_rele(port);
	}
	port->lp_mnh = NULL;

	/*
	 * Inform the the port lacp timer thread to exit. Note that waiting
	 * for the thread to exit may cause deadlock since that thread may
	 * need to enter into the mac perimeter which we are currently in.
	 * It is fine to continue without waiting though since that thread
	 * is holding a reference of the port.
	 */
	mutex_enter(&pl->lacp_timer_lock);
	pl->lacp_timer_bits |= LACP_THREAD_EXIT;
	cv_broadcast(&pl->lacp_timer_cv);
	mutex_exit(&pl->lacp_timer_lock);

	/*
	 * Restore the port MAC address. Note it is called after the
	 * port's notification callback being removed. This prevent
	 * port's MAC_NOTE_UNICST notify callback function being called.
	 */
	(void) mac_unicast_primary_set(port->lp_mh, port->lp_addr);
	if (port->lp_mah != NULL)
		(void) mac_unicast_remove(port->lp_mch, port->lp_mah);
	mac_client_close(port->lp_mch, MAC_CLOSE_FLAGS_EXCLUSIVE);
	mac_close(port->lp_mh);
	AGGR_PORT_REFRELE(port);
}

void
aggr_port_free(aggr_port_t *port)
{
	ASSERT(port->lp_refs == 0);
	if (port->lp_grp != NULL)
		AGGR_GRP_REFRELE(port->lp_grp);
	port->lp_grp = NULL;
	id_free(aggr_portids, port->lp_portid);
	port->lp_portid = 0;
	mutex_destroy(&port->lp_lacp.lacp_timer_lock);
	cv_destroy(&port->lp_lacp.lacp_timer_cv);
	kmem_cache_free(aggr_port_cache, port);
}

/*
 * Invoked upon receiving a MAC_NOTE_LINK notification for
 * one of the constituent ports.
 */
boolean_t
aggr_port_notify_link(aggr_grp_t *grp, aggr_port_t *port)
{
	boolean_t do_attach = B_FALSE;
	boolean_t do_detach = B_FALSE;
	boolean_t link_state_changed = B_TRUE;
	uint64_t ifspeed;
	link_state_t link_state;
	link_duplex_t link_duplex;
	mac_perim_handle_t mph;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &mph);

	/*
	 * link state change?  For links that do not support link state
	 * notification, always assume the link is up.
	 */
	link_state = port->lp_no_link_update ? LINK_STATE_UP :
	    mac_link_get(port->lp_mh);
	if (port->lp_link_state != link_state) {
		if (link_state == LINK_STATE_UP)
			do_attach = (port->lp_link_state != LINK_STATE_UP);
		else
			do_detach = (port->lp_link_state == LINK_STATE_UP);
	}
	port->lp_link_state = link_state;

	/* link duplex change? */
	link_duplex = aggr_port_stat(port, ETHER_STAT_LINK_DUPLEX);
	if (port->lp_link_duplex != link_duplex) {
		if (link_duplex == LINK_DUPLEX_FULL)
			do_attach |= (port->lp_link_duplex != LINK_DUPLEX_FULL);
		else
			do_detach |= (port->lp_link_duplex == LINK_DUPLEX_FULL);
	}
	port->lp_link_duplex = link_duplex;

	/* link speed changes? */
	ifspeed = aggr_port_stat(port, MAC_STAT_IFSPEED);
	if (port->lp_ifspeed != ifspeed) {
		mutex_enter(&grp->lg_stat_lock);

		if (port->lp_state == AGGR_PORT_STATE_ATTACHED)
			do_detach |= (ifspeed != grp->lg_ifspeed);
		else
			do_attach |= (ifspeed == grp->lg_ifspeed);

		mutex_exit(&grp->lg_stat_lock);
	}
	port->lp_ifspeed = ifspeed;

	if (do_attach) {
		/* attempt to attach the port to the aggregation */
		link_state_changed = aggr_grp_attach_port(grp, port);
	} else if (do_detach) {
		/* detach the port from the aggregation */
		link_state_changed = aggr_grp_detach_port(grp, port);
	}

	mac_perim_exit(mph);
	return (link_state_changed);
}

/*
 * Invoked upon receiving a MAC_NOTE_UNICST for one of the constituent
 * ports of a group.
 */
static void
aggr_port_notify_unicst(aggr_grp_t *grp, aggr_port_t *port,
    boolean_t *mac_addr_changedp, boolean_t *link_state_changedp)
{
	boolean_t mac_addr_changed = B_FALSE;
	boolean_t link_state_changed = B_FALSE;
	uint8_t mac_addr[ETHERADDRL];
	mac_perim_handle_t mph;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(mac_addr_changedp != NULL);
	ASSERT(link_state_changedp != NULL);
	mac_perim_enter_by_mh(port->lp_mh, &mph);

	/*
	 * If it is called when setting the MAC address to the
	 * aggregation group MAC address, do nothing.
	 */
	mac_unicast_primary_get(port->lp_mh, mac_addr);
	if (bcmp(mac_addr, grp->lg_addr, ETHERADDRL) == 0) {
		mac_perim_exit(mph);
		goto done;
	}

	/* save the new port MAC address */
	bcopy(mac_addr, port->lp_addr, ETHERADDRL);

	aggr_grp_port_mac_changed(grp, port, &mac_addr_changed,
	    &link_state_changed);

	mac_perim_exit(mph);

	/*
	 * If this port was used to determine the MAC address of
	 * the group, update the MAC address of the constituent
	 * ports.
	 */
	if (mac_addr_changed && aggr_grp_update_ports_mac(grp))
		link_state_changed = B_TRUE;

done:
	*mac_addr_changedp = mac_addr_changed;
	*link_state_changedp = link_state_changed;
}

/*
 * Notification callback invoked by the MAC service module for
 * a particular MAC port.
 */
static void
aggr_port_notify_cb(void *arg, mac_notify_type_t type)
{
	aggr_port_t *port = arg;
	aggr_grp_t *grp = port->lp_grp;
	boolean_t mac_addr_changed, link_state_changed;
	mac_perim_handle_t mph;

	mac_perim_enter_by_mh(grp->lg_mh, &mph);
	if (port->lp_closing) {
		mac_perim_exit(mph);

		/*
		 * Release the reference so it is safe for aggr to call
		 * mac_unregister() now.
		 */
		aggr_grp_port_rele(port);
		return;
	}

	switch (type) {
	case MAC_NOTE_TX:
		mac_tx_update(grp->lg_mh);
		break;
	case MAC_NOTE_LINK:
		if (aggr_port_notify_link(grp, port))
			mac_link_update(grp->lg_mh, grp->lg_link_state);
		break;
	case MAC_NOTE_UNICST:
		aggr_port_notify_unicst(grp, port, &mac_addr_changed,
		    &link_state_changed);
		if (mac_addr_changed)
			mac_unicst_update(grp->lg_mh, grp->lg_addr);
		if (link_state_changed)
			mac_link_update(grp->lg_mh, grp->lg_link_state);
		break;
	default:
		break;
	}

	mac_perim_exit(mph);
}

int
aggr_port_start(aggr_port_t *port)
{
	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	if (port->lp_started)
		return (0);

	port->lp_started = B_TRUE;
	aggr_grp_multicst_port(port, B_TRUE);
	return (0);
}

void
aggr_port_stop(aggr_port_t *port)
{
	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	if (!port->lp_started)
		return;

	aggr_grp_multicst_port(port, B_FALSE);

	/* update the port state */
	port->lp_started = B_FALSE;
}

int
aggr_port_promisc(aggr_port_t *port, boolean_t on)
{
	int rc;

	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	if (on == port->lp_promisc_on)
		/* already in desired promiscous mode */
		return (0);

	if (on) {
		mac_rx_clear(port->lp_mch);

		/*
		 * We use the promisc callback because without hardware
		 * rings, we deliver through flows that will cause duplicate
		 * delivery of packets when we've flipped into this mode
		 * to compensate for the lack of hardware MAC matching
		 */
		rc = mac_promisc_add(port->lp_mch, MAC_CLIENT_PROMISC_ALL,
		    aggr_recv_promisc_cb, port, &port->lp_mphp,
		    MAC_PROMISC_FLAGS_NO_TX_LOOP);
		if (rc != 0) {
			mac_rx_set(port->lp_mch, aggr_recv_cb, port);
			return (rc);
		}
	} else {
		mac_promisc_remove(port->lp_mphp);
		port->lp_mphp = NULL;
		mac_rx_set(port->lp_mch, aggr_recv_cb, port);
	}

	port->lp_promisc_on = on;

	return (0);
}

/*
 * Set the MAC address of a port.
 */
int
aggr_port_unicst(aggr_port_t *port)
{
	aggr_grp_t		*grp = port->lp_grp;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	return (mac_unicast_primary_set(port->lp_mh, grp->lg_addr));
}

/*
 * Add or remove a multicast address to/from a port.
 */
int
aggr_port_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	aggr_port_t *port = arg;

	if (add) {
		return (mac_multicast_add(port->lp_mch, addrp));
	} else {
		mac_multicast_remove(port->lp_mch, addrp);
		return (0);
	}
}

uint64_t
aggr_port_stat(aggr_port_t *port, uint_t stat)
{
	return (mac_stat_get(port->lp_mh, stat));
}

/*
 * Add a non-primary unicast address to the underlying port. If the port
 * supports HW Rx group, try to add the address into the HW Rx group of
 * the port first. If that fails, or if the port does not support HW Rx
 * group, enable the port's promiscous mode.
 */
int
aggr_port_addmac(aggr_port_t *port, const uint8_t *mac_addr)
{
	aggr_unicst_addr_t	*addr, **pprev;
	mac_perim_handle_t	pmph;
	int			err;

	ASSERT(MAC_PERIM_HELD(port->lp_grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &pmph);

	/*
	 * If the underlying port support HW Rx group, add the mac to its
	 * RX group directly.
	 */
	if ((port->lp_hwgh != NULL) &&
	    ((mac_hwgroup_addmac(port->lp_hwgh, mac_addr)) == 0)) {
		mac_perim_exit(pmph);
		return (0);
	}

	/*
	 * If that fails, or if the port does not support HW Rx group, enable
	 * the port's promiscous mode. (Note that we turn on the promiscous
	 * mode only if the port is already started.
	 */
	if (port->lp_started &&
	    ((err = aggr_port_promisc(port, B_TRUE)) != 0)) {
		mac_perim_exit(pmph);
		return (err);
	}

	/*
	 * Walk through the unicast addresses that requires promiscous mode
	 * enabled on this port, and add this address to the end of the list.
	 */
	pprev = &port->lp_prom_addr;
	while ((addr = *pprev) != NULL) {
		ASSERT(bcmp(mac_addr, addr->aua_addr, ETHERADDRL) != 0);
		pprev = &addr->aua_next;
	}
	addr = kmem_alloc(sizeof (aggr_unicst_addr_t), KM_SLEEP);
	bcopy(mac_addr, addr->aua_addr, ETHERADDRL);
	addr->aua_next = NULL;
	*pprev = addr;
	mac_perim_exit(pmph);
	return (0);
}

/*
 * Remove a non-primary unicast address from the underlying port. This address
 * must has been added by aggr_port_addmac(). As a result, we probably need to
 * remove the address from the port's HW Rx group, or to disable the port's
 * promiscous mode.
 */
void
aggr_port_remmac(aggr_port_t *port, const uint8_t *mac_addr)
{
	aggr_grp_t		*grp = port->lp_grp;
	aggr_unicst_addr_t	*addr, **pprev;
	mac_perim_handle_t	pmph;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	mac_perim_enter_by_mh(port->lp_mh, &pmph);

	/*
	 * See whether this address is in the list of addresses that requires
	 * the port being promiscous mode.
	 */
	pprev = &port->lp_prom_addr;
	while ((addr = *pprev) != NULL) {
		if (bcmp(mac_addr, addr->aua_addr, ETHERADDRL) == 0)
			break;
		pprev = &addr->aua_next;
	}
	if (addr != NULL) {
		/*
		 * This unicast address put the port into the promiscous mode,
		 * delete this address from the lp_prom_addr list. If this is
		 * the last address in that list, disable the promiscous mode
		 * if the aggregation is not in promiscous mode.
		 */
		*pprev = addr->aua_next;
		kmem_free(addr, sizeof (aggr_unicst_addr_t));
		if (port->lp_prom_addr == NULL && !grp->lg_promisc)
			(void) aggr_port_promisc(port, B_FALSE);
	} else {
		ASSERT(port->lp_hwgh != NULL);
		(void) mac_hwgroup_remmac(port->lp_hwgh, mac_addr);
	}
	mac_perim_exit(pmph);
}
