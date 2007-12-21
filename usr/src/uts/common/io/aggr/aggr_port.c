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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <sys/aggr.h>
#include <sys/aggr_impl.h>

static kmem_cache_t *aggr_port_cache;
static id_space_t *aggr_portids;

static void aggr_port_notify_cb(void *, mac_notify_type_t);

/*ARGSUSED*/
static int
aggr_port_constructor(void *buf, void *arg, int kmflag)
{
	aggr_port_t *port = buf;

	bzero(buf, sizeof (aggr_port_t));
	rw_init(&port->lp_lock, NULL, RW_DRIVER, NULL);

	return (0);
}

/*ARGSUSED*/
static void
aggr_port_destructor(void *buf, void *arg)
{
	aggr_port_t *port = buf;

	rw_destroy(&port->lp_lock);
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
	 * uses it to be a 16 bits unique identfication.
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

mac_resource_handle_t
aggr_port_resource_add(void *arg, mac_resource_t *mrp)
{
	aggr_port_t *port = (aggr_port_t *)arg;
	aggr_grp_t *grp = port->lp_grp;

	return (mac_resource_add(grp->lg_mh, mrp));
}

void
aggr_port_init_callbacks(aggr_port_t *port)
{
	/* add the port's receive callback */
	port->lp_mnh = mac_notify_add(port->lp_mh, aggr_port_notify_cb,
	    (void *)port);

	/* set port's resource_add callback */
	mac_resource_set(port->lp_mh, aggr_port_resource_add, (void *)port);
}

int
aggr_port_create(const char *name, aggr_port_t **pp)
{
	int err;
	mac_handle_t mh;
	aggr_port_t *port;
	uint16_t portid;
	uint_t i;
	const mac_info_t *mip;

	*pp = NULL;

	if ((err = mac_open(name, &mh)) != 0)
		return (err);

	mip = mac_info(mh);
	if (mip->mi_media != DL_ETHER || mip->mi_nativemedia != DL_ETHER) {
		mac_close(mh);
		return (EINVAL);
	}

	if ((portid = (uint16_t)id_alloc(aggr_portids)) == 0) {
		mac_close(mh);
		return (ENOMEM);
	}

	if (!mac_active_set(mh)) {
		id_free(aggr_portids, portid);
		mac_close(mh);
		return (EBUSY);
	}

	port = kmem_cache_alloc(aggr_port_cache, KM_SLEEP);

	port->lp_refs = 1;
	port->lp_next = NULL;
	port->lp_mh = mh;
	port->lp_mip = mip;
	(void) strlcpy(port->lp_devname, name, sizeof (port->lp_devname));
	port->lp_closing = 0;

	/* get the port's original MAC address */
	mac_unicst_get(port->lp_mh, port->lp_addr);

	/* set port's transmit information */
	port->lp_txinfo = mac_tx_get(port->lp_mh);

	/* initialize state */
	port->lp_state = AGGR_PORT_STATE_STANDBY;
	port->lp_link_state = LINK_STATE_UNKNOWN;
	port->lp_ifspeed = 0;
	port->lp_link_duplex = LINK_DUPLEX_UNKNOWN;
	port->lp_started = B_FALSE;
	port->lp_tx_enabled = B_FALSE;
	port->lp_promisc_on = B_FALSE;
	port->lp_portid = portid;

	/*
	 * Save the current statistics of the port. They will be used
	 * later by aggr_m_stats() when aggregating the stastics of
	 * the consistituent ports.
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
}

void
aggr_port_delete(aggr_port_t *port)
{
	mac_rx_remove_wait(port->lp_mh);
	mac_resource_set(port->lp_mh, NULL, NULL);
	mac_notify_remove(port->lp_mh, port->lp_mnh);
	mac_active_clear(port->lp_mh);

	/*
	 * Restore the port MAC address. Note it is called after the
	 * port's notification callback being removed. This prevent
	 * port's MAC_NOTE_UNICST notify callback function being called.
	 */
	(void) mac_unicst_set(port->lp_mh, port->lp_addr);

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
	kmem_cache_free(aggr_port_cache, port);
}

/*
 * Invoked upon receiving a MAC_NOTE_LINK notification for
 * one of the consistuent ports.
 */
boolean_t
aggr_port_notify_link(aggr_grp_t *grp, aggr_port_t *port, boolean_t dolock)
{
	boolean_t do_attach = B_FALSE;
	boolean_t do_detach = B_FALSE;
	boolean_t link_state_changed = B_TRUE;
	uint64_t ifspeed;
	link_state_t link_state;
	link_duplex_t link_duplex;

	if (dolock) {
		AGGR_LACP_LOCK(grp);
		rw_enter(&grp->lg_lock, RW_WRITER);
	} else {
		ASSERT(AGGR_LACP_LOCK_HELD(grp));
		ASSERT(RW_WRITE_HELD(&grp->lg_lock));
	}

	rw_enter(&port->lp_lock, RW_WRITER);

	/* link state change? */
	link_state = mac_link_get(port->lp_mh);
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
		if (port->lp_state == AGGR_PORT_STATE_ATTACHED)
			do_detach |= (ifspeed != grp->lg_ifspeed);
		else
			do_attach |= (ifspeed == grp->lg_ifspeed);
	}
	port->lp_ifspeed = ifspeed;

	if (do_attach) {
		/* attempt to attach the port to the aggregation */
		link_state_changed = aggr_grp_attach_port(grp, port);
	} else if (do_detach) {
		/* detach the port from the aggregation */
		link_state_changed = aggr_grp_detach_port(grp, port);
	}

	rw_exit(&port->lp_lock);

	if (dolock) {
		rw_exit(&grp->lg_lock);
		AGGR_LACP_UNLOCK(grp);
	}

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

	ASSERT(mac_addr_changedp != NULL);
	ASSERT(link_state_changedp != NULL);

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);

	rw_enter(&port->lp_lock, RW_WRITER);

	/*
	 * If it is called when setting the MAC address to the
	 * aggregation group MAC address, do nothing.
	 */
	mac_unicst_get(port->lp_mh, mac_addr);
	if (bcmp(mac_addr, grp->lg_addr, ETHERADDRL) == 0) {
		rw_exit(&port->lp_lock);
		goto done;
	}

	/* save the new port MAC address */
	bcopy(mac_addr, port->lp_addr, ETHERADDRL);

	aggr_grp_port_mac_changed(grp, port, &mac_addr_changed,
	    &link_state_changed);

	rw_exit(&port->lp_lock);

	if (grp->lg_closing)
		goto done;

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
	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);
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

	/*
	 * Do nothing if the aggregation or the port is in the deletion
	 * process. Note that this is necessary to avoid deadlock.
	 */
	if ((grp->lg_closing) || (port->lp_closing))
		return;

	AGGR_PORT_REFHOLD(port);

	switch (type) {
	case MAC_NOTE_TX:
		mac_tx_update(grp->lg_mh);
		break;
	case MAC_NOTE_LINK:
		if (aggr_port_notify_link(grp, port, B_TRUE))
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
	case MAC_NOTE_PROMISC:
		port->lp_txinfo = mac_tx_get(port->lp_mh);
		break;
	default:
		break;
	}

	AGGR_PORT_REFRELE(port);
}

int
aggr_port_start(aggr_port_t *port)
{
	int rc;

	ASSERT(RW_WRITE_HELD(&port->lp_lock));

	if (port->lp_started)
		return (0);

	if ((rc = mac_start(port->lp_mh)) != 0)
		return (rc);

	/* update the port state */
	port->lp_started = B_TRUE;

	return (rc);
}

void
aggr_port_stop(aggr_port_t *port)
{
	ASSERT(RW_WRITE_HELD(&port->lp_lock));

	if (!port->lp_started)
		return;

	aggr_grp_multicst_port(port, B_FALSE);

	mac_stop(port->lp_mh);

	/* update the port state */
	port->lp_started = B_FALSE;
}

int
aggr_port_promisc(aggr_port_t *port, boolean_t on)
{
	int rc;

	ASSERT(RW_WRITE_HELD(&port->lp_lock));

	if (on == port->lp_promisc_on)
		/* already in desired promiscous mode */
		return (0);

	rc = mac_promisc_set(port->lp_mh, on, MAC_DEVPROMISC);

	if (rc == 0)
		port->lp_promisc_on = on;

	return (rc);
}

/*
 * Set the MAC address of a port.
 */
int
aggr_port_unicst(aggr_port_t *port, uint8_t *macaddr)
{
	int rc;

	ASSERT(RW_WRITE_HELD(&port->lp_lock));

	rc = mac_unicst_set(port->lp_mh, macaddr);

	return (rc);
}

/*
 * Add or remove a multicast address to/from a port.
 */
int
aggr_port_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	aggr_port_t *port = arg;

	return (add ? mac_multicst_add(port->lp_mh, addrp) :
	    mac_multicst_remove(port->lp_mh, addrp));
}

uint64_t
aggr_port_stat(aggr_port_t *port, uint_t stat)
{
	return (mac_stat_get(port->lp_mh, stat));
}
