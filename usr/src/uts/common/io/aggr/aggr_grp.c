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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
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
#include <sys/dlpi.h>
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
static void aggr_m_resources(void *);
static void aggr_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t aggr_m_capab_get(void *, mac_capab_t, void *);
static aggr_port_t *aggr_grp_port_lookup(aggr_grp_t *, datalink_id_t);
static int aggr_grp_rem_port(aggr_grp_t *, aggr_port_t *, boolean_t *,
    boolean_t *);

static void aggr_grp_capab_set(aggr_grp_t *);
static boolean_t aggr_grp_capab_check(aggr_grp_t *, aggr_port_t *);
static uint_t aggr_grp_max_sdu(aggr_grp_t *);
static uint32_t aggr_grp_max_margin(aggr_grp_t *);
static boolean_t aggr_grp_sdu_check(aggr_grp_t *, aggr_port_t *);
static boolean_t aggr_grp_margin_check(aggr_grp_t *, aggr_port_t *);

static kmem_cache_t	*aggr_grp_cache;
static mod_hash_t	*aggr_grp_hash;
static krwlock_t	aggr_grp_lock;
static uint_t		aggr_grp_cnt;
static id_space_t	*key_ids;

#define	GRP_HASHSZ		64
#define	GRP_HASH_KEY(linkid)	((mod_hash_key_t)(uintptr_t)linkid)

static uchar_t aggr_zero_mac[] = {0, 0, 0, 0, 0, 0};

#define	AGGR_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t aggr_m_callbacks = {
	AGGR_M_CALLBACK_FLAGS,
	aggr_m_stat,
	aggr_m_start,
	aggr_m_stop,
	aggr_m_promisc,
	aggr_m_multicst,
	aggr_m_unicst,
	aggr_m_tx,
	aggr_m_resources,
	aggr_m_ioctl,
	aggr_m_capab_get
};

/*ARGSUSED*/
static int
aggr_grp_constructor(void *buf, void *arg, int kmflag)
{
	aggr_grp_t *grp = buf;

	bzero(grp, sizeof (*grp));
	rw_init(&grp->lg_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&grp->aggr.gl_lock, NULL, MUTEX_DEFAULT, NULL);

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

	mutex_destroy(&grp->aggr.gl_lock);
	rw_destroy(&grp->lg_lock);
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

	ASSERT(AGGR_LACP_LOCK_HELD(grp));
	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
	ASSERT(RW_WRITE_HELD(&port->lp_lock));

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

	aggr_grp_multicst_port(port, B_TRUE);

	/*
	 * Update port's state.
	 */
	port->lp_state = AGGR_PORT_STATE_ATTACHED;

	/*
	 * Set port's receive callback
	 */
	port->lp_mrh = mac_rx_add(port->lp_mh, aggr_recv_cb, (void *)port);

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

	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
	ASSERT(RW_WRITE_HELD(&port->lp_lock));
	ASSERT(AGGR_LACP_LOCK_HELD(grp));

	/* update state */
	if (port->lp_state != AGGR_PORT_STATE_ATTACHED)
		return (B_FALSE);

	mac_rx_remove(port->lp_mh, port->lp_mrh, B_FALSE);
	port->lp_state = AGGR_PORT_STATE_STANDBY;

	aggr_grp_multicst_port(port, B_FALSE);

	if (grp->lg_lacp_mode == AGGR_LACP_OFF)
		aggr_send_port_disable(port);
	else
		aggr_lacp_port_detached(port);

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

	ASSERT(RW_WRITE_HELD(&grp->lg_lock));

	if (grp->lg_closing)
		return (link_state_changed);

	for (cport = grp->lg_ports; cport != NULL;
	    cport = cport->lp_next) {
		rw_enter(&cport->lp_lock, RW_WRITER);
		if (aggr_port_unicst(cport, grp->lg_addr) != 0) {
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
		rw_exit(&cport->lp_lock);
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
	ASSERT(AGGR_LACP_LOCK_HELD(grp));
	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
	ASSERT(RW_WRITE_HELD(&port->lp_lock));
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
		if (aggr_port_unicst(port, grp->lg_addr) != 0) {
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
aggr_grp_add_port(aggr_grp_t *grp, datalink_id_t linkid, boolean_t force,
    aggr_port_t **pp)
{
	aggr_port_t *port, **cport;
	int err;

	ASSERT(AGGR_LACP_LOCK_HELD(grp));
	ASSERT(RW_WRITE_HELD(&grp->lg_lock));

	/* create new port */
	err = aggr_port_create(linkid, force, &port);
	if (err != 0)
		return (err);

	rw_enter(&port->lp_lock, RW_WRITER);

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

	/*
	 * Initialize the callback functions for this port. Note that this
	 * can only be done after the lp_grp field is set.
	 */
	aggr_port_init_callbacks(port);

	rw_exit(&port->lp_lock);

	if (pp != NULL)
		*pp = port;

	return (0);
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

	/* get group corresponding to linkid */
	rw_enter(&aggr_grp_lock, RW_READER);
	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}
	AGGR_GRP_REFHOLD(grp);
	rw_exit(&aggr_grp_lock);

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);

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

		/* start port if group has already been started */
		if (grp->lg_started) {
			rw_enter(&port->lp_lock, RW_WRITER);
			rc = aggr_port_start(port);
			if (rc != 0) {
				rw_exit(&port->lp_lock);
				goto bail;
			}

			/* set port promiscuous mode */
			rc = aggr_port_promisc(port, grp->lg_promisc);
			if (rc != 0) {
				rw_exit(&port->lp_lock);
				goto bail;
			}
			rw_exit(&port->lp_lock);
		}

		/*
		 * Attach each port if necessary.
		 */
		if (aggr_port_notify_link(grp, port, B_FALSE))
			link_state_changed = B_TRUE;
	}

	/* update the MAC address of the constituent ports */
	if (aggr_grp_update_ports_mac(grp))
		link_state_changed = B_TRUE;

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

bail:
	if (rc != 0) {
		/* stop and remove ports that have been added */
		for (i = 0; i < nadded && !grp->lg_closing; i++) {
			port = aggr_grp_port_lookup(grp, ports[i].lp_linkid);
			ASSERT(port != NULL);
			if (grp->lg_started) {
				rw_enter(&port->lp_lock, RW_WRITER);
				aggr_port_stop(port);
				rw_exit(&port->lp_lock);
			}
			(void) aggr_grp_rem_port(grp, port, NULL, NULL);
		}
	}

	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);
	if (rc == 0 && !grp->lg_closing)
		mac_resource_update(grp->lg_mh);
	AGGR_GRP_REFRELE(grp);
	return (rc);
}

/*
 * Update properties of an existing link aggregation group.
 */
int
aggr_grp_modify(datalink_id_t linkid, aggr_grp_t *grp_arg, uint8_t update_mask,
    uint32_t policy, boolean_t mac_fixed, const uchar_t *mac_addr,
    aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer)
{
	int rc = 0;
	aggr_grp_t *grp = NULL;
	boolean_t mac_addr_changed = B_FALSE;
	boolean_t link_state_changed = B_FALSE;

	if (grp_arg == NULL) {
		/* get group corresponding to linkid */
		rw_enter(&aggr_grp_lock, RW_READER);
		if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
		    (mod_hash_val_t *)&grp) != 0) {
			rc = ENOENT;
			goto bail;
		}
		AGGR_LACP_LOCK(grp);
		rw_enter(&grp->lg_lock, RW_WRITER);
	} else {
		grp = grp_arg;
		ASSERT(AGGR_LACP_LOCK_HELD(grp));
		ASSERT(RW_WRITE_HELD(&grp->lg_lock));
	}

	ASSERT(RW_WRITE_HELD(&grp->lg_lock) || RW_READ_HELD(&grp->lg_lock));
	AGGR_GRP_REFHOLD(grp);

	/* validate fixed address if specified */
	if ((update_mask & AGGR_MODIFY_MAC) && mac_fixed &&
	    ((bcmp(aggr_zero_mac, mac_addr, ETHERADDRL) == 0) ||
	    (mac_addr[0] & 0x01))) {
		rc = EINVAL;
		goto bail;
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

			rw_enter(&port->lp_lock, RW_WRITER);
			bcopy(port->lp_addr, grp->lg_addr, ETHERADDRL);
			grp->lg_mac_addr_port = port;
			mac_addr_changed = B_TRUE;
			rw_exit(&port->lp_lock);
		}
		grp->lg_addr_fixed = mac_fixed;
	}

	if (mac_addr_changed)
		link_state_changed = aggr_grp_update_ports_mac(grp);

	if (update_mask & AGGR_MODIFY_LACP_MODE)
		aggr_lacp_update_mode(grp, lacp_mode);

	if ((update_mask & AGGR_MODIFY_LACP_TIMER) && !grp->lg_closing)
		aggr_lacp_update_timer(grp, lacp_timer);

bail:
	if (grp != NULL && !grp->lg_closing) {
		/*
		 * If grp_arg is non-NULL, this function is called from
		 * mac_unicst_set(), and the MAC_NOTE_UNICST notification
		 * will be sent there.
		 */
		if ((grp_arg == NULL) && mac_addr_changed)
			mac_unicst_update(grp->lg_mh, grp->lg_addr);

		if (link_state_changed)
			mac_link_update(grp->lg_mh, grp->lg_link_state);

	}

	if (grp_arg == NULL) {
		if (grp != NULL) {
			rw_exit(&grp->lg_lock);
			AGGR_LACP_UNLOCK(grp);
		}
		rw_exit(&aggr_grp_lock);
	}

	if (grp != NULL)
		AGGR_GRP_REFRELE(grp);

	return (rc);
}

/*
 * Create a new link aggregation group upon request from administrator.
 * Returns 0 on success, an errno on failure.
 */
int
aggr_grp_create(datalink_id_t linkid, uint32_t key, uint_t nports,
    laioc_port_t *ports, uint32_t policy, boolean_t mac_fixed, boolean_t force,
    uchar_t *mac_addr, aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer)
{
	aggr_grp_t *grp = NULL;
	aggr_port_t *port;
	mac_register_t *mac;
	boolean_t link_state_changed;
	int err;
	int i;

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

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);

	grp->lg_refs = 1;
	grp->lg_closing = B_FALSE;
	grp->lg_force = force;
	grp->lg_linkid = linkid;
	grp->lg_ifspeed = 0;
	grp->lg_link_state = LINK_STATE_UNKNOWN;
	grp->lg_link_duplex = LINK_DUPLEX_UNKNOWN;
	grp->lg_started = B_FALSE;
	grp->lg_promisc = B_FALSE;
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

	/*
	 * Update the MAC address of the constituent ports.
	 * None of the port is attached at this time, the link state of the
	 * aggregation will not change.
	 */
	link_state_changed = aggr_grp_update_ports_mac(grp);
	ASSERT(!link_state_changed);

	/* update outbound load balancing policy */
	aggr_send_update_policy(grp, policy);

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
	err = mac_register(mac, &grp->lg_mh);
	mac_free(mac);
	if (err != 0)
		goto bail;

	if ((err = dls_devnet_create(grp->lg_mh, grp->lg_linkid)) != 0) {
		(void) mac_unregister(grp->lg_mh);
		goto bail;
	}

	/* set LACP mode */
	aggr_lacp_set_mode(grp, lacp_mode, lacp_timer);

	/*
	 * Attach each port if necessary.
	 */
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (aggr_port_notify_link(grp, port, B_FALSE))
			link_state_changed = B_TRUE;
	}

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

	/* add new group to hash table */
	err = mod_hash_insert(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t)grp);
	ASSERT(err == 0);
	aggr_grp_cnt++;

	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);
	rw_exit(&aggr_grp_lock);
	return (0);

bail:
	if (grp != NULL) {
		aggr_port_t *cport;

		grp->lg_closing = B_TRUE;

		port = grp->lg_ports;
		while (port != NULL) {
			cport = port->lp_next;
			aggr_port_delete(port);
			port = cport;
		}

		rw_exit(&grp->lg_lock);
		AGGR_LACP_UNLOCK(grp);

		AGGR_GRP_REFRELE(grp);
	}

	rw_exit(&aggr_grp_lock);
	return (err);
}

/*
 * Return a pointer to the member of a group with specified linkid.
 */
static aggr_port_t *
aggr_grp_port_lookup(aggr_grp_t *grp, datalink_id_t linkid)
{
	aggr_port_t *port;

	ASSERT(RW_WRITE_HELD(&grp->lg_lock) || RW_READ_HELD(&grp->lg_lock));

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
	uint64_t val;
	uint_t i;
	uint_t stat;

	ASSERT(AGGR_LACP_LOCK_HELD(grp));
	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
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

	atomic_add_32(&port->lp_closing, 1);

	rw_enter(&port->lp_lock, RW_WRITER);

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
	for (i = 0; i < MAC_NSTAT && !grp->lg_closing; i++) {
		stat = i + MAC_STAT_MIN;
		if (!MAC_STAT_ISACOUNTER(stat))
			continue;
		val = aggr_port_stat(port, stat);
		val -= port->lp_stat[i];
		grp->lg_stat[i] += val;
	}
	for (i = 0; i < ETHER_NSTAT && !grp->lg_closing; i++) {
		stat = i + MACTYPE_STAT_MIN;
		if (!ETHER_STAT_ISACOUNTER(stat))
			continue;
		val = aggr_port_stat(port, stat);
		val -= port->lp_ether_stat[i];
		grp->lg_ether_stat[i] += val;
	}

	grp->lg_nports--;

	rw_exit(&port->lp_lock);

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

	/* get group corresponding to linkid */
	rw_enter(&aggr_grp_lock, RW_READER);
	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}
	AGGR_GRP_REFHOLD(grp);
	rw_exit(&aggr_grp_lock);

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);

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

	/* remove the specified ports from group */
	for (i = 0; i < nports && !grp->lg_closing; i++) {
		/* lookup port */
		port = aggr_grp_port_lookup(grp, ports[i].lp_linkid);
		ASSERT(port != NULL);

		/* stop port if group has already been started */
		if (grp->lg_started) {
			rw_enter(&port->lp_lock, RW_WRITER);
			aggr_port_stop(port);
			rw_exit(&port->lp_lock);
		}

		/* remove port from group */
		rc = aggr_grp_rem_port(grp, port, &mac_addr_changed,
		    &link_state_changed);
		ASSERT(rc == 0);
		mac_addr_update = mac_addr_update || mac_addr_changed;
		link_state_update = link_state_update || link_state_changed;
	}

bail:
	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);
	if (!grp->lg_closing) {
		if (mac_addr_update)
			mac_unicst_update(grp->lg_mh, grp->lg_addr);
		if (link_state_update)
			mac_link_update(grp->lg_mh, grp->lg_link_state);
		if (rc == 0)
			mac_resource_update(grp->lg_mh);
	}
	AGGR_GRP_REFRELE(grp);

	return (rc);
}

int
aggr_grp_delete(datalink_id_t linkid)
{
	aggr_grp_t *grp = NULL;
	aggr_port_t *port, *cport;
	datalink_id_t tmpid;
	mod_hash_val_t val;
	int err;

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
	if ((err = dls_devnet_destroy(grp->lg_mh, &tmpid)) != 0) {
		rw_exit(&aggr_grp_lock);
		return (err);
	}
	ASSERT(linkid == tmpid);

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);

	/*
	 * Unregister from the MAC service module. Since this can
	 * fail if a client hasn't closed the MAC port, we gracefully
	 * fail the operation.
	 */
	grp->lg_closing = B_TRUE;
	if ((err = mac_disable(grp->lg_mh)) != 0) {
		grp->lg_closing = B_FALSE;
		rw_exit(&grp->lg_lock);
		AGGR_LACP_UNLOCK(grp);

		(void) dls_devnet_create(grp->lg_mh, linkid);
		rw_exit(&aggr_grp_lock);
		return (err);
	}

	/* detach and free MAC ports associated with group */
	port = grp->lg_ports;
	while (port != NULL) {
		cport = port->lp_next;
		rw_enter(&port->lp_lock, RW_WRITER);
		if (grp->lg_started)
			aggr_port_stop(port);
		(void) aggr_grp_detach_port(grp, port);
		rw_exit(&port->lp_lock);
		aggr_port_delete(port);
		port = cport;
	}

	VERIFY(mac_unregister(grp->lg_mh) == 0);

	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);

	(void) mod_hash_remove(aggr_grp_hash, GRP_HASH_KEY(linkid), &val);
	ASSERT(grp == (aggr_grp_t *)val);

	ASSERT(aggr_grp_cnt > 0);
	aggr_grp_cnt--;

	rw_exit(&aggr_grp_lock);
	AGGR_GRP_REFRELE(grp);

	return (0);
}

void
aggr_grp_free(aggr_grp_t *grp)
{
	ASSERT(grp->lg_refs == 0);
	if (grp->lg_key > AGGR_MAX_KEY) {
		id_free(key_ids, grp->lg_key);
		grp->lg_key = 0;
	}
	kmem_cache_free(aggr_grp_cache, grp);
}

int
aggr_grp_info(datalink_id_t linkid, void *fn_arg,
    aggr_grp_info_new_grp_fn_t new_grp_fn,
    aggr_grp_info_new_port_fn_t new_port_fn)
{
	aggr_grp_t	*grp;
	aggr_port_t	*port;
	int		rc = 0;

	rw_enter(&aggr_grp_lock, RW_READER);

	if (mod_hash_find(aggr_grp_hash, GRP_HASH_KEY(linkid),
	    (mod_hash_val_t *)&grp) != 0) {
		rw_exit(&aggr_grp_lock);
		return (ENOENT);
	}

	rw_enter(&grp->lg_lock, RW_READER);

	rc = new_grp_fn(fn_arg, grp->lg_linkid,
	    (grp->lg_key > AGGR_MAX_KEY) ? 0 : grp->lg_key, grp->lg_addr,
	    grp->lg_addr_fixed, grp->lg_force, grp->lg_tx_policy,
	    grp->lg_nports, grp->lg_lacp_mode, grp->aggr.PeriodicTimer);

	if (rc != 0)
		goto bail;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		rw_enter(&port->lp_lock, RW_READER);
		rc = new_port_fn(fn_arg, port->lp_linkid, port->lp_addr,
		    port->lp_state, &port->lp_lacp.ActorOperPortState);
		rw_exit(&port->lp_lock);

		if (rc != 0)
			goto bail;
	}

bail:
	rw_exit(&grp->lg_lock);
	rw_exit(&aggr_grp_lock);
	return (rc);
}

static void
aggr_m_resources(void *arg)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;

	/* Call each port's m_resources function */
	for (port = grp->lg_ports; port != NULL; port = port->lp_next)
		mac_resources(port->lp_mh);
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

static int
aggr_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	aggr_grp_t	*grp = arg;
	int		rval = 0;

	rw_enter(&grp->lg_lock, RW_READER);

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

	rw_exit(&grp->lg_lock);
	return (rval);
}

static int
aggr_m_start(void *arg)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);

	/*
	 * Attempts to start all configured members of the group.
	 * Group members will be attached when their link-up notification
	 * is received.
	 */
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		rw_enter(&port->lp_lock, RW_WRITER);
		if (aggr_port_start(port) != 0) {
			rw_exit(&port->lp_lock);
			continue;
		}

		/* set port promiscuous mode */
		if (aggr_port_promisc(port, grp->lg_promisc) != 0)
			aggr_port_stop(port);
		rw_exit(&port->lp_lock);
	}

	grp->lg_started = B_TRUE;

	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);

	return (0);
}

static void
aggr_m_stop(void *arg)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;

	rw_enter(&grp->lg_lock, RW_WRITER);

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		rw_enter(&port->lp_lock, RW_WRITER);
		aggr_port_stop(port);
		rw_exit(&port->lp_lock);
	}

	grp->lg_started = B_FALSE;

	rw_exit(&grp->lg_lock);
}

static int
aggr_m_promisc(void *arg, boolean_t on)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	boolean_t link_state_changed = B_FALSE;

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);
	AGGR_GRP_REFHOLD(grp);

	ASSERT(!grp->lg_closing);

	if (on == grp->lg_promisc)
		goto bail;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		rw_enter(&port->lp_lock, RW_WRITER);
		AGGR_PORT_REFHOLD(port);
		if (port->lp_started) {
			if (aggr_port_promisc(port, on) != 0) {
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
		}
		rw_exit(&port->lp_lock);
		AGGR_PORT_REFRELE(port);
	}

	grp->lg_promisc = on;

	if (link_state_changed)
		mac_link_update(grp->lg_mh, grp->lg_link_state);

bail:
	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);
	AGGR_GRP_REFRELE(grp);

	return (0);
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
	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, we simply return
		 * B_TRUE or B_FALSE to represent the group's support
		 * status for this capability.
		 */
		return (grp->lg_gldv3_polling);
	case MAC_CAPAB_NO_NATIVEVLAN:
		return (!grp->lg_vlan);
	case MAC_CAPAB_NO_ZCOPY:
		return (!grp->lg_zcopy);
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Add or remove the multicast addresses that are defined for the group
 * to or from the specified port.
 * This function is called before stopping a port, before a port
 * is detached from a group, and when attaching a port to a group.
 */
void
aggr_grp_multicst_port(aggr_port_t *port, boolean_t add)
{
	aggr_grp_t *grp = port->lp_grp;

	ASSERT(RW_WRITE_HELD(&port->lp_lock));
	ASSERT(RW_WRITE_HELD(&grp->lg_lock) || RW_READ_HELD(&grp->lg_lock));

	if (!port->lp_started)
		return;

	mac_multicst_refresh(grp->lg_mh, aggr_port_multicst, port, add);
}

static int
aggr_m_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port = NULL;
	int err = 0, cerr;

	rw_enter(&grp->lg_lock, RW_WRITER);
	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (port->lp_state != AGGR_PORT_STATE_ATTACHED)
			continue;
		cerr = aggr_port_multicst(port, add, addrp);
		if (cerr != 0 && err == 0)
			err = cerr;
	}
	rw_exit(&grp->lg_lock);
	return (err);
}

static int
aggr_m_unicst(void *arg, const uint8_t *macaddr)
{
	aggr_grp_t *grp = arg;
	int rc;

	AGGR_LACP_LOCK(grp);
	rw_enter(&grp->lg_lock, RW_WRITER);
	rc = aggr_grp_modify(0, grp, AGGR_MODIFY_MAC, 0, B_TRUE, macaddr,
	    0, 0);
	rw_exit(&grp->lg_lock);
	AGGR_LACP_UNLOCK(grp);

	return (rc);
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

	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
	ASSERT(grp->lg_ports != NULL);

	grp->lg_hcksum_txflags = (uint32_t)-1;
	grp->lg_gldv3_polling = B_TRUE;
	grp->lg_zcopy = B_TRUE;
	grp->lg_vlan = B_TRUE;

	for (port = grp->lg_ports; port != NULL; port = port->lp_next) {
		if (!mac_capab_get(port->lp_mh, MAC_CAPAB_HCKSUM, &cksum))
			cksum = 0;
		grp->lg_hcksum_txflags &= cksum;

		grp->lg_vlan &=
		    !mac_capab_get(port->lp_mh, MAC_CAPAB_NO_NATIVEVLAN, NULL);

		grp->lg_zcopy &=
		    !mac_capab_get(port->lp_mh, MAC_CAPAB_NO_ZCOPY, NULL);

		grp->lg_gldv3_polling &=
		    mac_capab_get(port->lp_mh, MAC_CAPAB_POLL, NULL);
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

	if (mac_capab_get(port->lp_mh, MAC_CAPAB_POLL, NULL) !=
	    grp->lg_gldv3_polling) {
		return (B_FALSE);
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

	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
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

	ASSERT(RW_WRITE_HELD(&grp->lg_lock));
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
