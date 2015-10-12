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
 */

/*
 * IEEE 802.3ad Link Aggregation - Send code.
 *
 * Implements the Distributor function.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
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

#define	HASH_HINT(hint)	\
	((hint) ^ ((hint) >> 24) ^ ((hint) >> 16) ^ ((hint) >> 8))

/*
 * Function invoked by mac layer to find a specific TX ring on a port
 * to send data.
 */
mblk_t *
aggr_find_tx_ring(void *arg, mblk_t *mp, uintptr_t hint, mac_ring_handle_t *rh)
{
	aggr_grp_t *grp = arg;
	aggr_port_t *port;
	uint64_t hash;

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
	hash = mac_pkt_hash(DL_ETHER, mp, grp->lg_mac_tx_policy, B_TRUE);
	port = grp->lg_tx_ports[hash % grp->lg_ntx_ports];

	/*
	 * Use hash as the hint so to direct traffic to
	 * different TX rings. Note below bit operation
	 * is needed in case hint is 0 to get the most
	 * benefit from HASH_HINT() algorithm.
	 */
	if (port->lp_tx_ring_cnt > 1) {
		if (hint == 0) {
			hash = (hash << 24 | hash << 16 | hash);
			hash = (hash << 32 | hash);
		} else {
			hash = hint;
		}
		hash = HASH_HINT(hash);
		*rh = port->lp_pseudo_tx_rings[hash % port->lp_tx_ring_cnt];
	} else {
		*rh = port->lp_pseudo_tx_rings[0];
	}
	rw_exit(&grp->lg_tx_lock);

	return (mp);
}

/*
 * aggr_tx_notify_thread:
 *
 * aggr_tx_ring_update() callback function wakes up this thread when
 * it gets called. This thread will call mac_tx_ring_update() to
 * notify upper mac of flow control getting relieved. Note that
 * aggr_tx_ring_update() cannot call mac_tx_ring_update() directly
 * because aggr_tx_ring_update() is called from lower mac with
 * mi_rw_lock held.
 */
void
aggr_tx_notify_thread(void *arg)
{
	callb_cpr_t	cprinfo;
	aggr_grp_t	*grp = (aggr_grp_t *)arg;
	mac_ring_handle_t	pseudo_mrh;

	CALLB_CPR_INIT(&cprinfo, &grp->lg_tx_flowctl_lock, callb_generic_cpr,
	    "aggr_tx_notify_thread");

	mutex_enter(&grp->lg_tx_flowctl_lock);
	while (!grp->lg_tx_notify_done) {
		if ((grp->lg_tx_blocked_cnt) == 0) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&grp->lg_tx_flowctl_cv,
			    &grp->lg_tx_flowctl_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &grp->lg_tx_flowctl_lock);
			continue;
		}
		while (grp->lg_tx_blocked_cnt != 0) {
			grp->lg_tx_blocked_cnt--;
			pseudo_mrh =
			    grp->lg_tx_blocked_rings[grp->lg_tx_blocked_cnt];
			mutex_exit(&grp->lg_tx_flowctl_lock);
			mac_tx_ring_update(grp->lg_mh, pseudo_mrh);
			mutex_enter(&grp->lg_tx_flowctl_lock);
		}
	}
	/*
	 * The grp is being destroyed, exit the thread.
	 */
	grp->lg_tx_notify_thread = NULL;
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * Callback function registered with lower mac to receive wakeups from
 * drivers when flow control is relieved (i.e. Tx descriptors are
 * available).
 */
void
aggr_tx_ring_update(void *arg1, uintptr_t arg2)
{
	aggr_port_t *port = (aggr_port_t *)arg1;
	mac_ring_handle_t mrh = (mac_ring_handle_t)arg2;
	mac_ring_handle_t pseudo_mrh;
	aggr_grp_t *grp = port->lp_grp;
	int i = 0;

	if (mrh == NULL) {
		/*
		 * If the underlying NIC does not expose TX rings,
		 * still as pseudo TX ring is presented to the
		 * aggr mac.
		 */
		pseudo_mrh = port->lp_pseudo_tx_rings[0];
	} else {
		for (i = 0; i < port->lp_tx_ring_cnt; i++) {
			if (port->lp_tx_rings[i] == mrh)
				break;
		}
		ASSERT(i < port->lp_tx_ring_cnt);
		pseudo_mrh = port->lp_pseudo_tx_rings[i];
	}
	mutex_enter(&grp->lg_tx_flowctl_lock);
	/*
	 * It could be possible that some (broken?) device driver
	 * could send more than one wakeup on the same ring. In
	 * such a case, multiple instances of the same pseudo TX
	 * ring should not be saved in lg_tx_blocked_rings[]
	 * array. So first check if woken up ring (pseudo_mrh) is
	 * already in the lg_tx_blocked_rings[] array.
	 */
	for (i = 0; i < grp->lg_tx_blocked_cnt; i++) {
		if (grp->lg_tx_blocked_rings[i] == pseudo_mrh) {
			mutex_exit(&grp->lg_tx_flowctl_lock);
			return;
		}
	}
	/* A distinct mac_ring_handle. Save and increment count */
	grp->lg_tx_blocked_rings[grp->lg_tx_blocked_cnt] = pseudo_mrh;
	grp->lg_tx_blocked_cnt++;
	cv_signal(&grp->lg_tx_flowctl_cv);
	mutex_exit(&grp->lg_tx_flowctl_lock);
}

/*
 * Send function invoked by the MAC service module.
 */
mblk_t *
aggr_ring_tx(void *arg, mblk_t *mp)
{
	aggr_pseudo_tx_ring_t *pseudo_ring = (aggr_pseudo_tx_ring_t *)arg;
	aggr_port_t *port = pseudo_ring->atr_port;

	return (mac_hwring_send_priv(port->lp_mch, pseudo_ring->atr_hw_rh, mp));
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

	aggr_grp_update_default(grp);
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

	aggr_grp_update_default(grp);
}
