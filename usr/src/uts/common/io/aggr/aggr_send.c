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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * IEEE 802.3ad Link Aggregation - Send code.
 *
 * Implements the Distributor function.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/vlan.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>

#include <inet/common.h>
#include <inet/led.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <netinet/udp.h>

#include <sys/aggr.h>
#include <sys/aggr_impl.h>

/*
 * Update the TX load balancing policy of the specified group.
 */
void
aggr_send_update_policy(aggr_grp_t *grp, uint32_t policy)
{
	uint8_t mac_policy = 0;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	if ((policy & AGGR_POLICY_L2) != 0)
		mac_policy |= MAC_PKT_HASH_L2;
	if ((policy & AGGR_POLICY_L3) != 0)
		mac_policy |= MAC_PKT_HASH_L3;
	if ((policy & AGGR_POLICY_L4) != 0)
		mac_policy |= MAC_PKT_HASH_L4;

	grp->lg_tx_policy = policy;
	grp->lg_mac_tx_policy = mac_policy;
}

/*
 * Send function invoked by the MAC service module.
 */
mblk_t *
aggr_m_tx(void *arg, mblk_t *mp)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	mblk_t *nextp;
	mac_tx_cookie_t	cookie;
	uint64_t hash;
	void	*mytx_handle;

	for (;;) {
		rw_enter(&grp->lg_tx_lock, RW_READER);
		if (grp->lg_ntx_ports == 0) {
			/*
			 * We could have returned from aggr_m_start() before
			 * the ports were actually attached. Drop the chain.
			 */
			rw_exit(&grp->lg_tx_lock);
			freemsgchain(mp);
			return (NULL);
		}

		nextp = mp->b_next;
		mp->b_next = NULL;

		hash = mac_pkt_hash(DL_ETHER, mp, grp->lg_mac_tx_policy,
		    B_TRUE);
		port = grp->lg_tx_ports[hash % grp->lg_ntx_ports];

		/*
		 * Bump the active Tx ref count so that the port won't
		 * be deleted. The reference count will be dropped in mac_tx().
		 */
		mytx_handle = mac_tx_hold(port->lp_mch);
		rw_exit(&grp->lg_tx_lock);

		if (mytx_handle == NULL) {
			/*
			 * The port is quiesced.
			 */
			freemsg(mp);
		} else {
			mblk_t	*ret_mp = NULL;

			/*
			 * It is fine that the port state changes now.
			 * Set MAC_TX_NO_HOLD to inform mac_tx() not to bump
			 * the active Tx ref again. Use hash as the hint so
			 * to direct traffic to different TX rings. Note below
			 * bit operation is needed to get the most benefit
			 * from the mac_tx() hash algorithm.
			 */
			hash = (hash << 24 | hash << 16 | hash);
			hash = (hash << 32 | hash);
			cookie = mac_tx(port->lp_mch, mp, (uintptr_t)hash,
			    MAC_TX_NO_ENQUEUE | MAC_TX_NO_HOLD, &ret_mp);

			mac_tx_rele(port->lp_mch, mytx_handle);

			if (cookie != NULL) {
				ret_mp->b_next = nextp;
				mp = ret_mp;
				break;
			}
		}

		if ((mp = nextp) == NULL)
			break;
	}
	return (mp);
}

/*
 * Enable sending on the specified port.
 */
void
aggr_send_port_enable(aggr_port_t *port)
{
	aggr_grp_t *grp = port->lp_grp;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));

	if (port->lp_tx_enabled || (port->lp_state !=
	    AGGR_PORT_STATE_ATTACHED)) {
		/* already enabled or port not yet attached */
		return;
	}

	/*
	 * Add to group's array of tx ports.
	 */
	rw_enter(&grp->lg_tx_lock, RW_WRITER);
	if (grp->lg_tx_ports_size < grp->lg_ntx_ports+1) {
		/* current array too small */
		aggr_port_t **new_ports;
		uint_t new_size;

		new_size = grp->lg_ntx_ports+1;
		new_ports = kmem_zalloc(new_size * sizeof (aggr_port_t *),
		    KM_SLEEP);

		if (grp->lg_tx_ports_size > 0) {
			ASSERT(grp->lg_tx_ports != NULL);
			bcopy(grp->lg_tx_ports, new_ports,
			    grp->lg_ntx_ports * sizeof (aggr_port_t *));
			kmem_free(grp->lg_tx_ports,
			    grp->lg_tx_ports_size * sizeof (aggr_port_t *));
		}

		grp->lg_tx_ports = new_ports;
		grp->lg_tx_ports_size = new_size;
	}

	grp->lg_tx_ports[grp->lg_ntx_ports++] = port;
	port->lp_tx_idx = grp->lg_ntx_ports-1;
	rw_exit(&grp->lg_tx_lock);

	port->lp_tx_enabled = B_TRUE;
}

/*
 * Disable sending from the specified port.
 */
void
aggr_send_port_disable(aggr_port_t *port)
{
	uint_t idx, ntx;
	aggr_grp_t *grp = port->lp_grp;

	ASSERT(MAC_PERIM_HELD(grp->lg_mh));
	ASSERT(MAC_PERIM_HELD(port->lp_mh));

	if (!port->lp_tx_enabled) {
		/* not yet enabled */
		return;
	}

	rw_enter(&grp->lg_tx_lock, RW_WRITER);
	idx = port->lp_tx_idx;
	ntx = grp->lg_ntx_ports;
	ASSERT(idx < ntx);

	/* remove from array of attached ports */
	if (idx == (ntx - 1)) {
		grp->lg_tx_ports[idx] = NULL;
	} else {
		/* not the last entry, replace with last one */
		aggr_port_t *victim;

		victim = grp->lg_tx_ports[ntx - 1];
		grp->lg_tx_ports[ntx - 1] = NULL;
		victim->lp_tx_idx = idx;
		grp->lg_tx_ports[idx] = victim;
	}

	port->lp_tx_idx = 0;
	grp->lg_ntx_ports--;
	rw_exit(&grp->lg_tx_lock);

	port->lp_tx_enabled = B_FALSE;
}
