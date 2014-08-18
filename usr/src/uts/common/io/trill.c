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
 *  This module supports AF_TRILL sockets and TRILL layer-2 forwarding.
 */

#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/tihdr.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <net/trill.h>
#include <net/if_dl.h>
#include <sys/mac.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/sdt.h>
#include <sys/dls.h>
#include <sys/sunddi.h>

#include "trill_impl.h"

static void trill_del_all(trill_inst_t *, boolean_t);
static int trill_del_nick(trill_inst_t *, uint16_t, boolean_t);
static void trill_stop_recv(trill_sock_t *);
static void trill_ctrl_input(trill_sock_t *, mblk_t *, const uint8_t *,
    uint16_t);
static trill_node_t *trill_node_lookup(trill_inst_t *, uint16_t);
static void trill_node_unref(trill_inst_t *, trill_node_t *);
static void trill_sock_unref(trill_sock_t *);
static void trill_kstats_init(trill_sock_t *, const char *);

static list_t trill_inst_list;
static krwlock_t trill_inst_rwlock;

static sock_lower_handle_t trill_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);

static smod_reg_t sinfo = {
	SOCKMOD_VERSION,
	"trill",
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	trill_create,
	NULL,
};

/* modldrv structure */
static struct modlsockmod sockmod = {
	&mod_sockmodops, "AF_TRILL socket module", &sinfo
};

/* modlinkage structure */
static struct modlinkage ml = {
	MODREV_1,
	&sockmod,
	NULL
};

#define	VALID_NICK(n)	((n) != RBRIDGE_NICKNAME_NONE && \
			(n) != RBRIDGE_NICKNAME_UNUSED)

static mblk_t *
create_trill_header(trill_sock_t *tsock, mblk_t *mp, const uint8_t *daddr,
    boolean_t trill_hdr_ok, boolean_t multidest, uint16_t tci,
    size_t msglen)
{
	int extra_hdr_len;
	struct ether_vlan_header *ethvlanhdr;
	mblk_t *hdr_mp;
	uint16_t etype;

	etype = msglen > 0 ? (uint16_t)msglen : ETHERTYPE_TRILL;

	/* When sending on the PVID, we must not give a VLAN ID */
	if (tci == tsock->ts_link->bl_pvid)
		tci = TRILL_NO_TCI;

	/*
	 * Create new Ethernet header and include additional space
	 * for writing TRILL header and/or VLAN tag.
	 */
	extra_hdr_len = (trill_hdr_ok ? 0 : sizeof (trill_header_t)) +
	    (tci != TRILL_NO_TCI ? sizeof (struct ether_vlan_extinfo) : 0);
	hdr_mp = mac_header(tsock->ts_link->bl_mh, daddr,
	    tci != TRILL_NO_TCI ? ETHERTYPE_VLAN : etype, mp, extra_hdr_len);
	if (hdr_mp == NULL) {
		freemsg(mp);
		return (NULL);
	}

	if (tci != TRILL_NO_TCI) {
		/* LINTED: alignment */
		ethvlanhdr = (struct ether_vlan_header *)hdr_mp->b_rptr;
		ethvlanhdr->ether_tci = htons(tci);
		ethvlanhdr->ether_type = htons(etype);
		hdr_mp->b_wptr += sizeof (struct ether_vlan_extinfo);
	}

	if (!trill_hdr_ok) {
		trill_header_t *thp;
		/* LINTED: alignment */
		thp = (trill_header_t *)hdr_mp->b_wptr;
		(void) memset(thp, 0, sizeof (trill_header_t));
		thp->th_hopcount = TRILL_DEFAULT_HOPS;
		thp->th_multidest = (multidest ? 1:0);
		hdr_mp->b_wptr += sizeof (trill_header_t);
	}

	hdr_mp->b_cont = mp;
	return (hdr_mp);
}

/*
 * TRILL local recv function. TRILL data frames that should be received
 * by the local system are decapsulated here and passed to bridging for
 * learning and local system receive. Only called when we are the forwarder
 * on the link (multi-dest frames) or the frame was destined for us.
 */
static void
trill_recv_local(trill_sock_t *tsock, mblk_t *mp, uint16_t ingressnick)
{
	struct ether_header *inner_ethhdr;

	/* LINTED: alignment */
	inner_ethhdr = (struct ether_header *)mp->b_rptr;
	DTRACE_PROBE1(trill__recv__local, struct ether_header *, inner_ethhdr);

	DB_CKSUMFLAGS(mp) = 0;
	/*
	 * Transmit the decapsulated frame on the link via Bridging.
	 * Bridging does source address learning and appropriate forwarding.
	 */
	bridge_trill_decaps(tsock->ts_link, mp, ingressnick);
	KSPINCR(tks_decap);
}

/*
 * Determines the outgoing link to reach a RBridge having the given nick
 * Assumes caller has acquired the trill instance rwlock.
 */
static trill_sock_t *
find_trill_link(trill_inst_t *tip, datalink_id_t linkid)
{
	trill_sock_t *tsp = NULL;

	ASSERT(RW_LOCK_HELD(&tip->ti_rwlock));
	for (tsp = list_head(&tip->ti_socklist); tsp != NULL;
	    tsp = list_next(&tip->ti_socklist, tsp)) {
		if (tsp->ts_link != NULL && tsp->ts_link->bl_linkid == linkid) {
			ASSERT(tsp->ts_link->bl_mh != NULL);
			ASSERT(!(tsp->ts_flags & TSF_SHUTDOWN));
			atomic_inc_uint(&tsp->ts_refs);
			break;
		}
	}
	return (tsp);
}

/*
 * TRILL destination forwarding function. Transmits the TRILL data packet
 * to the next-hop, adjacent RBridge.  Consumes passed mblk_t.
 */
static void
trill_dest_fwd(trill_inst_t *tip, mblk_t *fwd_mp, uint16_t adj_nick,
    boolean_t has_trill_hdr, boolean_t multidest, uint16_t dtnick)
{
	trill_node_t *adj;
	trill_sock_t *tsock = NULL;
	trill_header_t *trillhdr;
	struct ether_header *ethhdr;
	int ethtype;
	int ethhdrlen;

	adj = trill_node_lookup(tip, adj_nick);
	if (adj == NULL || ((tsock = adj->tn_tsp) == NULL))
		goto dest_fwd_fail;

	ASSERT(tsock->ts_link != NULL);
	ASSERT(!(tsock->ts_flags & TSF_SHUTDOWN));
	ASSERT(adj->tn_ni != NULL);

	DTRACE_PROBE3(trill__dest__fwd, uint16_t, adj_nick, trill_node_t,
	    adj, trill_sock_t, tsock);

	/*
	 * For broadcast links by using the dest address of
	 * the RBridge to forward the frame should result in
	 * savings. When the link is a bridged LAN or there are
	 * many end stations the frame will not always be flooded.
	 */
	fwd_mp = create_trill_header(tsock, fwd_mp, adj->tn_ni->tni_adjsnpa,
	    has_trill_hdr, multidest, tsock->ts_desigvlan, 0);
	if (fwd_mp == NULL)
		goto dest_fwd_fail;

	/* LINTED: alignment */
	ethhdr = (struct ether_header *)fwd_mp->b_rptr;
	ethtype = ntohs(ethhdr->ether_type);
	ASSERT(ethtype == ETHERTYPE_VLAN || ethtype == ETHERTYPE_TRILL);

	/* Pullup Ethernet and TRILL header (w/o TRILL options) */
	ethhdrlen = sizeof (struct ether_header) +
	    (ethtype == ETHERTYPE_VLAN ? sizeof (struct ether_vlan_extinfo):0);
	if (!pullupmsg(fwd_mp, ethhdrlen + sizeof (trill_header_t)))
		goto dest_fwd_fail;
	/* LINTED: alignment */
	trillhdr = (struct trill_header *)(fwd_mp->b_rptr + ethhdrlen);

	/* Update TRILL header with ingress and egress nicks for new frames */
	if (!has_trill_hdr) {
		/* We are creating a new TRILL frame */
		trillhdr->th_egressnick = (multidest ? dtnick:adj_nick);
		rw_enter(&tip->ti_rwlock, RW_READER);
		trillhdr->th_ingressnick = tip->ti_nick;
		rw_exit(&tip->ti_rwlock);
		if (!VALID_NICK(trillhdr->th_ingressnick))
			goto dest_fwd_fail;
	}

	/* Set hop count and update header in packet */
	ASSERT(trillhdr->th_hopcount != 0);
	trillhdr->th_hopcount--;

	/* Clear checksum flag and transmit frame on the link */
	DB_CKSUMFLAGS(fwd_mp) = 0;
	DTRACE_PROBE1(trill__dest__fwd__tx, trill_header_t *, &trillhdr);
	fwd_mp = bridge_trill_output(tsock->ts_link, fwd_mp);
	if (fwd_mp == NULL) {
		KSPINCR(tks_sent);
		KSPINCR(tks_forward);
	} else {
		freemsg(fwd_mp);
		KSPINCR(tks_drops);
	}
	trill_node_unref(tip, adj);
	return;

dest_fwd_fail:
	if (adj != NULL)
		trill_node_unref(tip, adj);
	if (tsock != NULL)
		KSPINCR(tks_drops);
	freemsg(fwd_mp);
}

/*
 * TRILL multi-destination forwarding. Transmits the packet to the adjacencies
 * on the distribution tree determined by the egress nick. Source addr (saddr)
 * is NULL for new TRILL packets originating from us.
 */
static void
trill_multidest_fwd(trill_inst_t *tip, mblk_t *mp, uint16_t egressnick,
    uint16_t ingressnick, boolean_t is_trill_pkt, const uint8_t *saddr,
    int inner_vlan, boolean_t free_mblk)
{
	int idx;
	uint16_t adjnick;
	trill_node_t *dest;
	trill_node_t *adj;
	mblk_t *fwd_mp;
	boolean_t nicksaved = B_FALSE;
	uint16_t adjnicksaved;

	/* Lookup the egress nick info, this is the DT root */
	if ((dest = trill_node_lookup(tip, egressnick)) == NULL)
		goto fail_multidest_fwd;

	/* Send a copy to all our adjacencies on the DT root  */
	ASSERT(dest->tn_ni);
	for (idx = 0; idx < dest->tn_ni->tni_adjcount; idx++) {

		/* Check for a valid adjacency node */
		adjnick = TNI_ADJNICK(dest->tn_ni, idx);
		if (!VALID_NICK(adjnick) || ingressnick == adjnick ||
		    ((adj = trill_node_lookup(tip, adjnick)) == NULL))
			continue;

		/* Do not forward back to adjacency that sent the pkt to us */
		ASSERT(adj->tn_ni != NULL);
		if ((saddr != NULL) &&
		    (memcmp(adj->tn_ni->tni_adjsnpa, saddr,
		    ETHERADDRL) == 0)) {
			trill_node_unref(tip, adj);
			continue;
		}

		/* Check if adj is marked as reaching inner VLAN downstream */
		if ((inner_vlan != VLAN_ID_NONE) &&
		    !TRILL_VLANISSET(TNI_VLANFILTERMAP(dest->tn_ni, idx),
		    inner_vlan)) {
			trill_node_unref(tip, adj);
			DTRACE_PROBE4(trill__multi__dest__fwd__vlanfiltered,
			    uint16_t, adjnick, uint16_t, ingressnick,
			    uint16_t, egressnick, int, inner_vlan);
			continue;
		}

		trill_node_unref(tip, adj);

		/*
		 * Save the nick and look ahead to see if we should forward the
		 * frame to more adjacencies. We avoid doing a copy for this
		 * nick and use the passed mblk when we can consume the passed
		 * mblk.
		 */
		if (free_mblk && !nicksaved) {
			adjnicksaved = adjnick;
			nicksaved = B_TRUE;
			continue;
		}

		fwd_mp = copymsg(mp);
		if (fwd_mp == NULL)
			break;
		DTRACE_PROBE2(trill__multi__dest__fwd, uint16_t,
		    adjnick, uint16_t, ingressnick);
		trill_dest_fwd(tip, fwd_mp, adjnick, is_trill_pkt,
		    B_TRUE, egressnick);
	}
	trill_node_unref(tip, dest);

	if (nicksaved) {
		ASSERT(free_mblk);
		DTRACE_PROBE2(trill__multi__dest__fwd, uint16_t,
		    adjnicksaved, uint16_t, ingressnick);
		trill_dest_fwd(tip, mp, adjnicksaved, is_trill_pkt,
		    B_TRUE, egressnick);
		return;
	}

fail_multidest_fwd:
	DTRACE_PROBE2(trill__multi__dest__fwd__fail, uint16_t,
	    egressnick, uint16_t, ingressnick);
	if (free_mblk) {
		freemsg(mp);
	}
}

/*
 * TRILL data receive function. Forwards the received frame if necessary
 * and also determines if the received frame should be consumed locally.
 * Consumes passed mblk.
 */
static void
trill_recv(trill_sock_t *tsock, mblk_t *mp, const uint8_t *mpsaddr)
{
	trill_header_t *trillhdr;
	trill_node_t *dest = NULL;
	trill_node_t *source = NULL;
	trill_node_t *adj;
	uint16_t ournick, adjnick, treeroot;
	struct ether_header *ethhdr;
	trill_inst_t *tip = tsock->ts_tip;
	uint8_t srcaddr[ETHERADDRL];
	size_t trillhdrlen;
	int inner_vlan = VLAN_ID_NONE;
	int tci;
	int idx;
	size_t min_size;

	/* Copy Ethernet source address before modifying packet */
	(void) memcpy(srcaddr, mpsaddr, ETHERADDRL);

	/* Pull up TRILL header if necessary. */
	min_size = sizeof (trill_header_t);
	if ((MBLKL(mp) < min_size ||
	    !IS_P2ALIGNED(mp->b_rptr, TRILL_HDR_ALIGN)) &&
	    !pullupmsg(mp, min_size))
		goto fail;

	/* LINTED: alignment */
	trillhdr = (trill_header_t *)mp->b_rptr;
	if (trillhdr->th_version != TRILL_PROTOCOL_VERS) {
		DTRACE_PROBE1(trill__recv__wrongversion,
		    trill_header_t *, trillhdr);
		goto fail;
	}

	/* Drop if unknown or invalid nickname */
	if (!VALID_NICK(trillhdr->th_egressnick) ||
	    !VALID_NICK(trillhdr->th_ingressnick)) {
		DTRACE_PROBE1(trill__recv__invalidnick,
		    trill_header_t *, trillhdr);
		goto fail;
	}

	rw_enter(&tip->ti_rwlock, RW_READER);
	ournick = tip->ti_nick;
	treeroot = tip->ti_treeroot;
	rw_exit(&tip->ti_rwlock);
	/* Drop if we received a packet with our nick as ingress */
	if (trillhdr->th_ingressnick == ournick)
		goto fail;

	/* Re-pull any TRILL options and inner Ethernet header */
	min_size += GET_TRILL_OPTS_LEN(trillhdr) * sizeof (uint32_t) +
	    sizeof (struct ether_header);
	if (MBLKL(mp) < min_size) {
		if (!pullupmsg(mp, min_size))
			goto fail;
		/* LINTED: alignment */
		trillhdr = (trill_header_t *)mp->b_rptr;
	}
	trillhdrlen = sizeof (trill_header_t) +
	    (GET_TRILL_OPTS_LEN(trillhdr) * sizeof (uint32_t));

	/*
	 * Get the inner Ethernet header, plus the inner VLAN header if there
	 * is one.
	 */
	/* LINTED: alignment */
	ethhdr = (struct ether_header *)(mp->b_rptr + trillhdrlen);
	if (ethhdr->ether_type == htons(ETHERTYPE_VLAN)) {
		min_size += sizeof (struct ether_vlan_extinfo);
		if (MBLKL(mp) < min_size) {
			if (!pullupmsg(mp, min_size))
				goto fail;
			/* LINTED: alignment */
			trillhdr = (trill_header_t *)mp->b_rptr;
			/* LINTED: alignment */
			ethhdr = (struct ether_header *)(mp->b_rptr +
			    trillhdrlen);
		}

		tci = ntohs(((struct ether_vlan_header *)ethhdr)->ether_tci);
		inner_vlan = VLAN_ID(tci);
	}

	/* Known/single destination forwarding. */
	if (!trillhdr->th_multidest) {

		/* Inner MacDA must be unicast */
		if (ethhdr->ether_dhost.ether_addr_octet[0] & 1)
			goto fail;

		/* Ingress and Egress nicks must be different */
		if (trillhdr->th_egressnick == trillhdr->th_ingressnick)
			goto fail;

		DTRACE_PROBE1(trill__recv__singledest,
		    trill_header_t *, trillhdr);
		if (trillhdr->th_egressnick == ournick) {
			mp->b_rptr += trillhdrlen;
			trill_recv_local(tsock, mp, trillhdr->th_ingressnick);
		} else if (trillhdr->th_hopcount > 0) {
			trill_dest_fwd(tip, mp, trillhdr->th_egressnick,
			    B_TRUE, B_FALSE, RBRIDGE_NICKNAME_NONE);
		} else {
			goto fail;
		}
		return;
	}

	/*
	 * Multi-destination frame: perform checks verifying we have
	 * received a valid multi-destination frame before receiving the
	 * frame locally and forwarding the frame to other RBridges.
	 *
	 * Check if we received this multi-destination frame on a
	 * adjacency in the distribution tree indicated by the frame's
	 * egress nickname.
	 */
	if ((dest = trill_node_lookup(tip, trillhdr->th_egressnick)) == NULL)
		goto fail;
	for (idx = 0; idx < dest->tn_ni->tni_adjcount; idx++) {
		adjnick = TNI_ADJNICK(dest->tn_ni, idx);
		if ((adj = trill_node_lookup(tip, adjnick)) == NULL)
			continue;
		if (memcmp(adj->tn_ni->tni_adjsnpa, srcaddr, ETHERADDRL) == 0) {
			trill_node_unref(tip, adj);
			break;
		}
		trill_node_unref(tip, adj);
	}

	if (idx >= dest->tn_ni->tni_adjcount) {
		DTRACE_PROBE2(trill__recv__multidest__adjcheckfail,
		    trill_header_t *, trillhdr, trill_node_t *, dest);
		goto fail;
	}

	/*
	 * Reverse path forwarding check. Check if the ingress RBridge
	 * that has forwarded the frame advertised the use of the
	 * distribution tree specified in the egress nick.
	 */
	if ((source = trill_node_lookup(tip, trillhdr->th_ingressnick)) == NULL)
		goto fail;
	for (idx = 0; idx < source->tn_ni->tni_dtrootcount; idx++) {
		if (TNI_DTROOTNICK(source->tn_ni, idx) ==
		    trillhdr->th_egressnick)
			break;
	}

	if (idx >= source->tn_ni->tni_dtrootcount) {
		/*
		 * Allow receipt of forwarded frame with the highest
		 * tree root RBridge as the egress RBridge when the
		 * ingress RBridge has not advertised the use of any
		 * distribution trees.
		 */
		if (source->tn_ni->tni_dtrootcount != 0 ||
		    trillhdr->th_egressnick != treeroot) {
			DTRACE_PROBE3(
			    trill__recv__multidest__rpfcheckfail,
			    trill_header_t *, trillhdr, trill_node_t *,
			    source, trill_inst_t *, tip);
			goto fail;
		}
	}

	/* Check hop count before doing any forwarding */
	if (trillhdr->th_hopcount == 0)
		goto fail;

	/* Forward frame using the distribution tree specified by egress nick */
	DTRACE_PROBE2(trill__recv__multidest, trill_header_t *,
	    trillhdr, trill_node_t *, source);
	trill_node_unref(tip, source);
	trill_node_unref(tip, dest);

	/* Tell forwarding not to free if we're the link forwarder. */
	trill_multidest_fwd(tip, mp, trillhdr->th_egressnick,
	    trillhdr->th_ingressnick, B_TRUE, srcaddr, inner_vlan,
	    B_FALSE);

	/*
	 * Send de-capsulated frame locally if we are the link forwarder (also
	 * does bridge learning).
	 */
	mp->b_rptr += trillhdrlen;
	trill_recv_local(tsock, mp, trillhdr->th_ingressnick);
	KSPINCR(tks_recv);
	return;

fail:
	DTRACE_PROBE2(trill__recv__multidest__fail, mblk_t *, mp,
	    trill_sock_t *, tsock);
	if (dest != NULL)
		trill_node_unref(tip, dest);
	if (source != NULL)
		trill_node_unref(tip, source);
	freemsg(mp);
	KSPINCR(tks_drops);
}

static void
trill_stop_recv(trill_sock_t *tsock)
{
	mutex_enter(&tsock->ts_socklock);
stop_retry:
	if (tsock->ts_state == TS_UNBND || tsock->ts_link == NULL) {
		mutex_exit(&tsock->ts_socklock);
		return;
	}

	/*
	 * If another thread is closing the socket then wait. Our callers
	 * expect us to return only after the socket is closed.
	 */
	if (tsock->ts_flags & TSF_CLOSEWAIT) {
		cv_wait(&tsock->ts_sockclosewait, &tsock->ts_socklock);
		goto stop_retry;
	}

	/*
	 * Set state and flags to block new bind or close calls
	 * while we close the socket.
	 */
	tsock->ts_flags |= TSF_CLOSEWAIT;

	/* Wait until all AF_TRILL socket transmit operations are done */
	while (tsock->ts_sockthreadcount > 0)
		cv_wait(&tsock->ts_sockthreadwait, &tsock->ts_socklock);

	/*
	 * We are guaranteed to be the only thread closing on the
	 * socket while the TSF_CLOSEWAIT flag is set, all others cv_wait
	 * for us to finish.
	 */
	ASSERT(tsock->ts_link != NULL);
	if (tsock->ts_ksp != NULL)
		kstat_delete(tsock->ts_ksp);

	/*
	 * Release lock before bridge_trill_lnunref to prevent deadlock
	 * between trill_ctrl_input thread waiting to acquire ts_socklock
	 * and bridge_trill_lnunref waiting for the trill thread to finish.
	 */
	mutex_exit(&tsock->ts_socklock);

	/*
	 * Release TRILL link reference from Bridging. On return from
	 * bridge_trill_lnunref we can be sure there are no active TRILL data
	 * threads for this link.
	 */
	bridge_trill_lnunref(tsock->ts_link);

	/* Set socket as unbound & wakeup threads waiting for socket to close */
	mutex_enter(&tsock->ts_socklock);
	ASSERT(tsock->ts_link != NULL);
	tsock->ts_link = NULL;
	tsock->ts_state = TS_UNBND;
	tsock->ts_flags &= ~TSF_CLOSEWAIT;
	cv_broadcast(&tsock->ts_sockclosewait);
	mutex_exit(&tsock->ts_socklock);
}

static int
trill_start_recv(trill_sock_t *tsock, const struct sockaddr *sa, socklen_t len)
{
	struct sockaddr_dl *lladdr = (struct sockaddr_dl *)sa;
	datalink_id_t linkid;
	int err = 0;

	if (len != sizeof (*lladdr))
		return (EINVAL);

	mutex_enter(&tsock->ts_socklock);
	if (tsock->ts_tip == NULL || tsock->ts_state != TS_UNBND) {
		err = EINVAL;
		goto bind_error;
	}

	if (tsock->ts_flags & TSF_CLOSEWAIT || tsock->ts_link != NULL) {
		err = EBUSY;
		goto bind_error;
	}

	(void) memcpy(&(tsock->ts_lladdr), lladdr,
	    sizeof (struct sockaddr_dl));
	(void) memcpy(&linkid, tsock->ts_lladdr.sdl_data,
	    sizeof (datalink_id_t));

	tsock->ts_link = bridge_trill_lnref(tsock->ts_tip->ti_binst,
	    linkid, tsock);
	if (tsock->ts_link == NULL) {
		err = EINVAL;
		goto bind_error;
	}

	trill_kstats_init(tsock, tsock->ts_tip->ti_bridgename);
	tsock->ts_state = TS_IDLE;

bind_error:
	mutex_exit(&tsock->ts_socklock);
	return (err);
}

static int
trill_do_unbind(trill_sock_t *tsock)
{
	/* If a bind has not been done, we can't unbind. */
	if (tsock->ts_state != TS_IDLE)
		return (EINVAL);

	trill_stop_recv(tsock);
	return (0);
}

static void
trill_instance_unref(trill_inst_t *tip)
{
	rw_enter(&trill_inst_rwlock, RW_WRITER);
	rw_enter(&tip->ti_rwlock, RW_WRITER);
	if (atomic_dec_uint_nv(&tip->ti_refs) == 0) {
		list_remove(&trill_inst_list, tip);
		rw_exit(&tip->ti_rwlock);
		rw_exit(&trill_inst_rwlock);
		if (tip->ti_binst != NULL)
			bridge_trill_brunref(tip->ti_binst);
		list_destroy(&tip->ti_socklist);
		rw_destroy(&tip->ti_rwlock);
		kmem_free(tip, sizeof (*tip));
	} else {
		rw_exit(&tip->ti_rwlock);
		rw_exit(&trill_inst_rwlock);
	}
}

/*
 * This is called when the bridge module receives a TRILL-encapsulated packet
 * on a given link or a packet identified as "TRILL control."  We must verify
 * that it's for us (it almost certainly will be), and then either decapsulate
 * (if it's to our nickname), forward (if it's to someone else), or send up one
 * of the sockets (if it's control traffic).
 *
 * Sadly, on Ethernet, the control traffic is identified by Outer.MacDA, and
 * not by TRILL header information.
 */
static void
trill_recv_pkt_cb(void *lptr, bridge_link_t *blp, mac_resource_handle_t rsrc,
    mblk_t *mp, mac_header_info_t *hdr_info)
{
	trill_sock_t *tsock = lptr;

	_NOTE(ARGUNUSED(rsrc));

	ASSERT(tsock->ts_tip != NULL);
	ASSERT(tsock->ts_link != NULL);
	ASSERT(!(tsock->ts_flags & TSF_SHUTDOWN));

	/*
	 * Only receive packet if the source address is not multicast (which is
	 * bogus).
	 */
	if (hdr_info->mhi_saddr[0] & 1)
		goto discard;

	/*
	 * Check if this is our own packet reflected back.  It should not be.
	 */
	if (bcmp(hdr_info->mhi_saddr, blp->bl_local_mac, ETHERADDRL) == 0)
		goto discard;

	/* Only receive unicast packet if addressed to us */
	if (hdr_info->mhi_dsttype == MAC_ADDRTYPE_UNICAST &&
	    bcmp(hdr_info->mhi_daddr, blp->bl_local_mac, ETHERADDRL) != 0)
		goto discard;

	if (hdr_info->mhi_bindsap == ETHERTYPE_TRILL) {
		/* TRILL data packets */
		trill_recv(tsock, mp, hdr_info->mhi_saddr);
	} else {
		/* Design constraint for cheap IS-IS/BPDU comparison */
		ASSERT(all_isis_rbridges[4] != bridge_group_address[4]);
		/* Send received control packet upstream */
		trill_ctrl_input(tsock, mp, hdr_info->mhi_saddr,
		    hdr_info->mhi_daddr[4] == all_isis_rbridges[4] ?
		    hdr_info->mhi_tci : TRILL_TCI_BPDU);
	}

	return;

discard:
	freemsg(mp);
	KSPINCR(tks_drops);
}

/*
 * This is called when the bridge module discovers that the destination address
 * for a packet is not local -- it's through some remote node.  We must verify
 * that the remote node isn't our nickname (it shouldn't be), add a TRILL
 * header, and then use the IS-IS data to determine which link and which
 * next-hop RBridge should be used for output.  We then transmit on that link.
 *
 * The egress_nick is RBRIDGE_NICKNAME_NONE for the "unknown destination" case.
 */
static void
trill_encap_pkt_cb(void *lptr, bridge_link_t *blp, mac_header_info_t *hdr_info,
    mblk_t *mp, uint16_t egress_nick)
{
	uint16_t ournick;
	uint16_t dtnick;
	trill_node_t *self = NULL;
	trill_sock_t *tsock = lptr;
	trill_inst_t *tip = tsock->ts_tip;
	int vlan = VLAN_ID_NONE;

	_NOTE(ARGUNUSED(blp));
	ASSERT(hdr_info->mhi_bindsap != ETHERTYPE_TRILL);

	/* egress_nick = RBRIDGE_NICKNAME_NONE is valid */
	if (egress_nick != RBRIDGE_NICKNAME_NONE && !VALID_NICK(egress_nick))
		goto discard;

	/* Check if our own nick is valid before we do any forwarding */
	rw_enter(&tip->ti_rwlock, RW_READER);
	ournick = tip->ti_nick;
	dtnick = tip->ti_treeroot;
	rw_exit(&tip->ti_rwlock);
	if (!VALID_NICK(ournick))
		goto discard;

	/*
	 * For Multi-Destination forwarding determine our choice of
	 * root distribution tree. If we didn't choose a distribution
	 * tree (dtroots_count=0) then we use the highest priority tree
	 * root (t_treeroot) else we drop the packet without forwarding.
	 */
	if (egress_nick == RBRIDGE_NICKNAME_NONE) {
		if ((self = trill_node_lookup(tip, ournick)) == NULL)
			goto discard;

		/*
		 * Use the first DT configured for now. In future we
		 * should have DT selection code here.
		 */
		if (self->tn_ni->tni_dtrootcount > 0) {
			dtnick = TNI_DTROOTNICK(self->tn_ni, 0);
		}

		trill_node_unref(tip, self);
		if (!VALID_NICK(dtnick)) {
			DTRACE_PROBE(trill__fwd__packet__nodtroot);
			goto discard;
		}
	}

	/*
	 * Retrieve VLAN ID of the native frame used for VLAN
	 * pruning of multi-destination frames.
	 */
	if (hdr_info->mhi_istagged) {
		vlan = VLAN_ID(hdr_info->mhi_tci);
	}

	DTRACE_PROBE2(trill__fwd__packet, mac_header_info_t *, hdr_info,
	    uint16_t, egress_nick);
	if (egress_nick == RBRIDGE_NICKNAME_NONE) {
		trill_multidest_fwd(tip, mp, dtnick,
		    ournick, B_FALSE, NULL, vlan, B_TRUE);
	} else {
		trill_dest_fwd(tip, mp, egress_nick, B_FALSE, B_FALSE,
		    RBRIDGE_NICKNAME_NONE);
	}
	KSPINCR(tks_encap);
	return;

discard:
	freemsg(mp);
}

/*
 * This is called when the bridge module has completely torn down a bridge
 * instance and all of the attached links.  We need to make the TRILL instance
 * go away at this point.
 */
static void
trill_br_dstr_cb(void *bptr, bridge_inst_t *bip)
{
	trill_inst_t *tip = bptr;

	_NOTE(ARGUNUSED(bip));
	rw_enter(&tip->ti_rwlock, RW_WRITER);
	if (tip->ti_binst != NULL)
		bridge_trill_brunref(tip->ti_binst);
	tip->ti_binst = NULL;
	rw_exit(&tip->ti_rwlock);
}

/*
 * This is called when the bridge module is tearing down a link, but before the
 * actual tear-down starts.  When this function returns, we must make sure that
 * we will not initiate any new transmits on this link.
 */
static void
trill_ln_dstr_cb(void *lptr, bridge_link_t *blp)
{
	trill_sock_t *tsock = lptr;

	_NOTE(ARGUNUSED(blp));
	trill_stop_recv(tsock);
}

static void
trill_init(void)
{
	list_create(&trill_inst_list, sizeof (trill_inst_t),
	    offsetof(trill_inst_t, ti_instnode));
	rw_init(&trill_inst_rwlock, NULL, RW_DRIVER, NULL);
	bridge_trill_register_cb(trill_recv_pkt_cb, trill_encap_pkt_cb,
	    trill_br_dstr_cb, trill_ln_dstr_cb);
}

static void
trill_fini(void)
{
	bridge_trill_register_cb(NULL, NULL, NULL, NULL);
	rw_destroy(&trill_inst_rwlock);
	list_destroy(&trill_inst_list);
}

/* Loadable module configuration entry points */
int
_init(void)
{
	int rc;

	trill_init();
	if ((rc = mod_install(&ml)) != 0)
		trill_fini();
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int rc;

	rw_enter(&trill_inst_rwlock, RW_READER);
	rc = list_is_empty(&trill_inst_list) ? 0 : EBUSY;
	rw_exit(&trill_inst_rwlock);
	if (rc == 0 && ((rc = mod_remove(&ml)) == 0))
		trill_fini();
	return (rc);
}

static void
trill_kstats_init(trill_sock_t *tsock, const char *bname)
{
	int i;
	char kstatname[KSTAT_STRLEN];
	kstat_named_t  *knt;
	static const char *sock_kstats_list[] = { TRILL_KSSOCK_NAMES };
	char link_name[MAXNAMELEN];
	int num;
	int err;

	bzero(link_name, sizeof (link_name));
	if ((err = dls_mgmt_get_linkinfo(tsock->ts_link->bl_linkid, link_name,
	    NULL, NULL, NULL)) != 0) {
		cmn_err(CE_WARN, "%s: trill_kstats_init: error %d retrieving"
		    " linkinfo for linkid:%d", "trill", err,
		    tsock->ts_link->bl_linkid);
		return;
	}

	bzero(kstatname, sizeof (kstatname));
	(void) snprintf(kstatname, sizeof (kstatname), "%s-%s",
	    bname, link_name);

	num = sizeof (sock_kstats_list) / sizeof (*sock_kstats_list);
	for (i = 0; i < num; i++) {
		knt = (kstat_named_t *)&(tsock->ts_kstats);
		kstat_named_init(&knt[i], sock_kstats_list[i],
		    KSTAT_DATA_UINT64);
	}

	tsock->ts_ksp = kstat_create_zone("trill", 0, kstatname, "sock",
	    KSTAT_TYPE_NAMED, num, KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID);
	if (tsock->ts_ksp != NULL) {
		tsock->ts_ksp->ks_data = &tsock->ts_kstats;
		kstat_install(tsock->ts_ksp);
	}
}

static trill_sock_t *
trill_do_open(int flags)
{
	trill_sock_t *tsock;
	int kmflag = ((flags & SOCKET_NOSLEEP)) ? KM_NOSLEEP:KM_SLEEP;

	tsock = kmem_zalloc(sizeof (trill_sock_t), kmflag);
	if (tsock != NULL) {
		tsock->ts_state = TS_UNBND;
		tsock->ts_refs++;
		mutex_init(&tsock->ts_socklock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&tsock->ts_sockthreadwait, NULL, CV_DRIVER, NULL);
		cv_init(&tsock->ts_sockclosewait, NULL, CV_DRIVER, NULL);
	}
	return (tsock);
}

static int
trill_find_bridge(trill_sock_t *tsock, const char *bname, boolean_t can_create)
{
	trill_inst_t *tip, *newtip = NULL;

	/* Allocate some memory (speculatively) before taking locks */
	if (can_create)
		newtip = kmem_zalloc(sizeof (*tip), KM_NOSLEEP);

	rw_enter(&trill_inst_rwlock, RW_WRITER);
	for (tip = list_head(&trill_inst_list); tip != NULL;
	    tip = list_next(&trill_inst_list, tip)) {
		if (strcmp(tip->ti_bridgename, bname) == 0)
			break;
	}
	if (tip == NULL) {
		if (!can_create || newtip == NULL) {
			rw_exit(&trill_inst_rwlock);
			return (can_create ? ENOMEM : ENOENT);
		}

		tip = newtip;
		newtip = NULL;
		(void) strcpy(tip->ti_bridgename, bname);

		/* Register TRILL instance with bridging */
		tip->ti_binst = bridge_trill_brref(bname, tip);
		if (tip->ti_binst == NULL) {
			rw_exit(&trill_inst_rwlock);
			kmem_free(tip, sizeof (*tip));
			return (ENOENT);
		}

		rw_init(&tip->ti_rwlock, NULL, RW_DRIVER, NULL);
		list_create(&tip->ti_socklist, sizeof (trill_sock_t),
		    offsetof(trill_sock_t, ts_socklistnode));
		list_insert_tail(&trill_inst_list, tip);
	}
	atomic_inc_uint(&tip->ti_refs);
	rw_exit(&trill_inst_rwlock);

	/* If we didn't need the preallocated memory, then discard now. */
	if (newtip != NULL)
		kmem_free(newtip, sizeof (*newtip));

	rw_enter(&tip->ti_rwlock, RW_WRITER);
	list_insert_tail(&(tip->ti_socklist), tsock);
	tsock->ts_tip = tip;
	rw_exit(&tip->ti_rwlock);
	return (0);
}

static void
trill_clear_bridge(trill_sock_t *tsock)
{
	trill_inst_t *tip;

	if ((tip = tsock->ts_tip) == NULL)
		return;
	rw_enter(&tip->ti_rwlock, RW_WRITER);
	list_remove(&tip->ti_socklist, tsock);
	if (list_is_empty(&tip->ti_socklist))
		trill_del_all(tip, B_TRUE);
	rw_exit(&tip->ti_rwlock);
}

static void
trill_sock_unref(trill_sock_t *tsock)
{
	if (atomic_dec_uint_nv(&tsock->ts_refs) == 0) {
		mutex_destroy(&tsock->ts_socklock);
		cv_destroy(&tsock->ts_sockthreadwait);
		cv_destroy(&tsock->ts_sockclosewait);
		kmem_free(tsock, sizeof (trill_sock_t));
	}
}

static void
trill_do_close(trill_sock_t *tsock)
{
	trill_inst_t *tip;

	tip = tsock->ts_tip;
	trill_stop_recv(tsock);
	/* Remove socket from TRILL instance socket list */
	trill_clear_bridge(tsock);
	tsock->ts_flags |= TSF_SHUTDOWN;
	trill_sock_unref(tsock);
	if (tip != NULL)
		trill_instance_unref(tip);
}

static void
trill_del_all(trill_inst_t *tip, boolean_t lockheld)
{
	int i;

	if (!lockheld)
		rw_enter(&tip->ti_rwlock, RW_WRITER);
	for (i = RBRIDGE_NICKNAME_MIN; i < RBRIDGE_NICKNAME_MAX; i++) {
		if (tip->ti_nodes[i] != NULL)
			(void) trill_del_nick(tip, i, B_TRUE);
	}
	if (!lockheld)
		rw_exit(&tip->ti_rwlock);
}

static void
trill_node_free(trill_node_t *nick_entry)
{
	trill_nickinfo_t *tni;

	tni = nick_entry->tn_ni;
	kmem_free(tni, TNI_TOTALSIZE(tni));
	kmem_free(nick_entry, sizeof (trill_node_t));
}

static void
trill_node_unref(trill_inst_t *tip, trill_node_t *tnp)
{
	if (atomic_dec_uint_nv(&tnp->tn_refs) == 0) {
		if (tnp->tn_tsp != NULL)
			trill_sock_unref(tnp->tn_tsp);
		trill_node_free(tnp);
		atomic_dec_uint(&tip->ti_nodecount);
	}
}

static trill_node_t *
trill_node_lookup(trill_inst_t *tip, uint16_t nick)
{
	trill_node_t *nick_entry;

	if (!VALID_NICK(nick))
		return (NULL);
	rw_enter(&tip->ti_rwlock, RW_READER);
	nick_entry = tip->ti_nodes[nick];
	if (nick_entry != NULL) {
		atomic_inc_uint(&nick_entry->tn_refs);
	}
	rw_exit(&tip->ti_rwlock);
	return (nick_entry);
}

static int
trill_del_nick(trill_inst_t *tip, uint16_t nick, boolean_t lockheld)
{
	trill_node_t *nick_entry;
	int rc = ENOENT;

	if (!lockheld)
		rw_enter(&tip->ti_rwlock, RW_WRITER);
	if (VALID_NICK(nick)) {
		nick_entry = tip->ti_nodes[nick];
		if (nick_entry != NULL) {
			trill_node_unref(tip, nick_entry);
			tip->ti_nodes[nick] = NULL;
			rc = 0;
		}
	}
	if (!lockheld)
		rw_exit(&tip->ti_rwlock);
	return (rc);
}

static int
trill_add_nick(trill_inst_t *tip, void *arg, boolean_t self, int mode)
{
	uint16_t nick;
	int size;
	trill_node_t *tnode;
	trill_nickinfo_t tnihdr;

	/* First make sure we have at least the header available */
	if (ddi_copyin(arg, &tnihdr, sizeof (trill_nickinfo_t), mode) != 0)
		return (EFAULT);

	nick = tnihdr.tni_nick;
	if (!VALID_NICK(nick)) {
		DTRACE_PROBE1(trill__add__nick__bad, trill_nickinfo_t *,
		    &tnihdr);
		return (EINVAL);
	}

	size = TNI_TOTALSIZE(&tnihdr);
	if (size > TNI_MAXSIZE)
		return (EINVAL);
	tnode = kmem_zalloc(sizeof (trill_node_t), KM_SLEEP);
	tnode->tn_ni = kmem_zalloc(size, KM_SLEEP);
	if (ddi_copyin(arg, tnode->tn_ni, size, mode) != 0) {
		kmem_free(tnode->tn_ni, size);
		kmem_free(tnode, sizeof (trill_node_t));
		return (EFAULT);
	}

	tnode->tn_refs++;
	rw_enter(&tip->ti_rwlock, RW_WRITER);
	if (tip->ti_nodes[nick] != NULL)
		(void) trill_del_nick(tip, nick, B_TRUE);

	if (self) {
		tip->ti_nick = nick;
	} else {
		tnode->tn_tsp = find_trill_link(tip,
		    tnode->tn_ni->tni_linkid);
	}
	DTRACE_PROBE2(trill__add__nick, trill_node_t *, tnode,
	    uint16_t, nick);
	tip->ti_nodes[nick] = tnode;
	tip->ti_nodecount++;
	rw_exit(&tip->ti_rwlock);
	return (0);
}

static int
trill_do_ioctl(trill_sock_t *tsock, int cmd, void *arg, int mode)
{
	int error = 0;
	trill_inst_t *tip = tsock->ts_tip;

	switch (cmd) {
	case TRILL_DESIGVLAN: {
		uint16_t desigvlan;

		if (ddi_copyin(arg, &desigvlan, sizeof (desigvlan), mode) != 0)
			return (EFAULT);
		tsock->ts_desigvlan = desigvlan;
		break;
	}
	case TRILL_VLANFWDER: {
		uint8_t vlans[TRILL_VLANS_ARRSIZE];

		if (tsock->ts_link == NULL)
			return (EINVAL);
		if ((ddi_copyin(arg, vlans, sizeof (vlans), mode)) != 0)
			return (EFAULT);
		bridge_trill_setvlans(tsock->ts_link, vlans);
		break;
	}
	case TRILL_SETNICK:
		if (tip == NULL)
			return (EINVAL);
		error = trill_add_nick(tip, arg, B_TRUE, mode);
		break;

	case TRILL_GETNICK:
		if (tip == NULL)
			return (EINVAL);
		rw_enter(&tip->ti_rwlock, RW_READER);
		if (ddi_copyout(&tip->ti_nick, arg, sizeof (tip->ti_nick),
		    mode) != 0)
			error = EFAULT;
		rw_exit(&tip->ti_rwlock);
		break;

	case TRILL_ADDNICK:
		if (tip == NULL)
			break;
		error = trill_add_nick(tip, arg, B_FALSE, mode);
		break;

	case TRILL_DELNICK: {
		uint16_t delnick;

		if (tip == NULL)
			break;
		if (ddi_copyin(arg, &delnick, sizeof (delnick), mode) != 0)
			return (EFAULT);
		error = trill_del_nick(tip, delnick, B_FALSE);
		break;
	}
	case TRILL_DELALL:
		if (tip == NULL)
			break;
		trill_del_all(tip, B_FALSE);
		break;

	case TRILL_TREEROOT: {
		uint16_t treeroot;

		if (tip == NULL)
			break;
		if (ddi_copyin(arg, &treeroot, sizeof (treeroot), mode) != 0)
			return (EFAULT);
		if (!VALID_NICK(treeroot))
			return (EINVAL);
		rw_enter(&tip->ti_rwlock, RW_WRITER);
		tip->ti_treeroot = treeroot;
		rw_exit(&tip->ti_rwlock);
		break;
	}
	case TRILL_HWADDR:
		if (tsock->ts_link == NULL)
			break;
		if (ddi_copyout(tsock->ts_link->bl_local_mac, arg, ETHERADDRL,
		    mode) != 0)
			return (EFAULT);
		break;

	case TRILL_NEWBRIDGE: {
		char bname[MAXLINKNAMELEN];

		if (tsock->ts_state != TS_UNBND)
			return (ENOTSUP);
		/* ts_tip can only be set once */
		if (tip != NULL)
			return (EEXIST);
		if (ddi_copyin(arg, bname, sizeof (bname), mode) != 0)
			return (EFAULT);
		bname[MAXLINKNAMELEN-1] = '\0';
		error = trill_find_bridge(tsock, bname, B_TRUE);
		break;
	}

	case TRILL_GETBRIDGE: {
		char bname[MAXLINKNAMELEN];

		/* ts_tip can only be set once */
		if (tip != NULL)
			return (EEXIST);
		if (ddi_copyin(arg, bname, sizeof (bname), mode) != 0)
			return (EFAULT);
		bname[MAXLINKNAMELEN - 1] = '\0';
		error = trill_find_bridge(tsock, bname, B_FALSE);
		break;
	}

	case TRILL_LISTNICK: {
		trill_listnick_t tln;
		trill_node_t *tnp;
		trill_nickinfo_t *tnip;
		uint16_t nick;

		if (tip == NULL)
			return (EINVAL);
		if (ddi_copyin(arg, &tln, sizeof (tln), mode) != 0)
			return (EFAULT);
		nick = tln.tln_nick;
		if (nick >= RBRIDGE_NICKNAME_MAX) {
			error = EINVAL;
			break;
		}
		rw_enter(&tip->ti_rwlock, RW_READER);
		while (++nick < RBRIDGE_NICKNAME_MAX) {
			if ((tnp = tip->ti_nodes[nick]) != NULL) {
				tnip = tnp->tn_ni;
				ASSERT(nick == tnip->tni_nick);
				tln.tln_nick = nick;
				bcopy(tnip->tni_adjsnpa, tln.tln_nexthop,
				    ETHERADDRL);
				tln.tln_ours = nick == tip->ti_nick;
				if (tln.tln_ours || tnp->tn_tsp == NULL) {
					tln.tln_linkid =
					    DATALINK_INVALID_LINKID;
				} else {
					tln.tln_linkid =
					    tnp->tn_tsp->ts_link->bl_linkid;
				}
				break;
			}
		}
		rw_exit(&tip->ti_rwlock);
		if (nick >= RBRIDGE_NICKNAME_MAX)
			bzero(&tln, sizeof (tln));
		if (ddi_copyout(&tln, arg, sizeof (tln), mode) != 0)
			return (EFAULT);
		break;
	}

	/*
	 * Port flush: this is used when we lose AF on a port.  We must discard
	 * all regular bridge forwarding entries on this port with the
	 * indicated VLAN.
	 */
	case TRILL_PORTFLUSH: {
		uint16_t vlan = (uint16_t)(uintptr_t)arg;

		if (tsock->ts_link == NULL)
			return (EINVAL);
		bridge_trill_flush(tsock->ts_link, vlan, B_FALSE);
		break;
	}

	/*
	 * Nick flush: this is used when we lose AF on a port.  We must discard
	 * all bridge TRILL forwarding entries on this port with the indicated
	 * VLAN.
	 */
	case TRILL_NICKFLUSH: {
		uint16_t vlan = (uint16_t)(uintptr_t)arg;

		if (tsock->ts_link == NULL)
			return (EINVAL);
		bridge_trill_flush(tsock->ts_link, vlan, B_TRUE);
		break;
	}

	case TRILL_GETMTU:
		if (tsock->ts_link == NULL)
			break;
		if (ddi_copyout(&tsock->ts_link->bl_maxsdu, arg,
		    sizeof (uint_t), mode) != 0)
			return (EFAULT);
		break;

	default:
		error = ENOTSUP;
		break;
	}

	return (error);
}

/*
 * Sends received packet back upstream on the TRILL socket.
 * Consumes passed mblk_t.
 */
static void
trill_ctrl_input(trill_sock_t *tsock, mblk_t *mp, const uint8_t *saddr,
    uint16_t tci)
{
	int udi_size;
	mblk_t *mp1;
	struct T_unitdata_ind *tudi;
	struct sockaddr_dl *sdl;
	char *lladdr;
	int error;

	ASSERT(!(tsock->ts_flags & TSF_SHUTDOWN));
	if (tsock->ts_flow_ctrld) {
		freemsg(mp);
		KSPINCR(tks_drops);
		return;
	}

	udi_size =  sizeof (struct T_unitdata_ind) +
	    sizeof (struct sockaddr_dl);
	mp1 = allocb(udi_size, BPRI_MED);
	if (mp1 == NULL) {
		freemsg(mp);
		KSPINCR(tks_drops);
		return;
	}

	mp1->b_cont = mp;
	mp = mp1;
	mp->b_datap->db_type = M_PROTO;
	/* LINTED: alignment */
	tudi = (struct T_unitdata_ind *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)tudi + udi_size;

	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_length = sizeof (struct sockaddr_dl);
	tudi->SRC_offset = sizeof (struct T_unitdata_ind);
	tudi->OPT_length = 0;
	tudi->OPT_offset = sizeof (struct T_unitdata_ind) +
	    sizeof (struct sockaddr_dl);

	/* Information of the link on which packet was received. */
	sdl = (struct sockaddr_dl *)&tudi[1];
	(void) memset(sdl, 0, sizeof (struct sockaddr_dl));
	sdl->sdl_family = AF_TRILL;

	/* LINTED: alignment */
	*(datalink_id_t *)sdl->sdl_data = tsock->ts_link->bl_linkid;
	sdl->sdl_nlen = sizeof (tsock->ts_link->bl_linkid);

	lladdr = LLADDR(sdl);
	(void) memcpy(lladdr, saddr, ETHERADDRL);
	lladdr += ETHERADDRL;
	sdl->sdl_alen = ETHERADDRL;

	/* LINTED: alignment */
	*(uint16_t *)lladdr = tci;
	sdl->sdl_slen = sizeof (uint16_t);

	DTRACE_PROBE2(trill__ctrl__input, trill_sock_t *, tsock, mblk_t *, mp);
	(*tsock->ts_conn_upcalls->su_recv)(tsock->ts_conn_upper_handle,
	    mp, msgdsize(mp), 0, &error, NULL);

	if (error == ENOSPC) {
		mutex_enter(&tsock->ts_socklock);
		(*tsock->ts_conn_upcalls->su_recv)(tsock->ts_conn_upper_handle,
		    NULL, 0, 0, &error, NULL);
		if (error == ENOSPC)
			tsock->ts_flow_ctrld = B_TRUE;
		mutex_exit(&tsock->ts_socklock);
		KSPINCR(tks_drops);
	} else if (error != 0) {
		KSPINCR(tks_drops);
	} else {
		KSPINCR(tks_recv);
	}

	DTRACE_PROBE2(trill__ctrl__input__done, trill_sock_t *,
	    tsock, int, error);
}

/* ARGSUSED */
static void
trill_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls,
    int flags, cred_t *cr)
{
	trill_sock_t *tsock = (trill_sock_t *)proto_handle;
	struct sock_proto_props sopp;

	tsock->ts_conn_upcalls = sock_upcalls;
	tsock->ts_conn_upper_handle = sock_handle;

	sopp.sopp_flags = SOCKOPT_WROFF | SOCKOPT_RCVHIWAT |
	    SOCKOPT_RCVLOWAT | SOCKOPT_MAXADDRLEN | SOCKOPT_MAXPSZ |
	    SOCKOPT_MAXBLK | SOCKOPT_MINPSZ;
	sopp.sopp_wroff = 0;
	sopp.sopp_rxhiwat = SOCKET_RECVHIWATER;
	sopp.sopp_rxlowat = SOCKET_RECVLOWATER;
	sopp.sopp_maxaddrlen = sizeof (struct sockaddr_dl);
	sopp.sopp_maxpsz = INFPSZ;
	sopp.sopp_maxblk = INFPSZ;
	sopp.sopp_minpsz = 0;
	(*tsock->ts_conn_upcalls->su_set_proto_props)(
	    tsock->ts_conn_upper_handle, &sopp);
}

/* ARGSUSED */
static int
trill_close(sock_lower_handle_t proto_handle, int flags, cred_t *cr)
{
	trill_sock_t *tsock = (trill_sock_t *)proto_handle;

	trill_do_close(tsock);
	return (0);
}

/* ARGSUSED */
static int
trill_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	int error;
	trill_sock_t *tsock = (trill_sock_t *)proto_handle;

	if (sa == NULL)
		error = trill_do_unbind(tsock);
	else
		error = trill_start_recv(tsock, sa, len);

	return (error);
}

/* ARGSUSED */
static int
trill_send(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	trill_sock_t *tsock = (trill_sock_t *)proto_handle;
	struct sockaddr_dl *laddr;
	uint16_t tci;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(!(tsock->ts_flags & TSF_SHUTDOWN));

	if (msg->msg_name == NULL || msg->msg_namelen != sizeof (*laddr))
		goto eproto;

	/*
	 * The name is a datalink_id_t, the address is an Ethernet address, and
	 * the selector value is the VLAN ID.
	 */
	laddr = (struct sockaddr_dl *)msg->msg_name;
	if (laddr->sdl_nlen != sizeof (datalink_id_t) ||
	    laddr->sdl_alen != ETHERADDRL ||
	    (laddr->sdl_slen != sizeof (tci) && laddr->sdl_slen != 0))
		goto eproto;

	mutex_enter(&tsock->ts_socklock);
	if (tsock->ts_state != TS_IDLE || tsock->ts_link == NULL) {
		mutex_exit(&tsock->ts_socklock);
		goto eproto;
	}
	atomic_inc_uint(&tsock->ts_sockthreadcount);
	mutex_exit(&tsock->ts_socklock);

	/*
	 * Safe to dereference VLAN now, as we've checked the user's specified
	 * values, and alignment is now guaranteed.
	 */
	if (laddr->sdl_slen == 0) {
		tci = TRILL_NO_TCI;
	} else {
		/* LINTED: alignment */
		tci = *(uint16_t *)(LLADDR(laddr) + ETHERADDRL);
	}

	mp = create_trill_header(tsock, mp, (const uchar_t *)LLADDR(laddr),
	    B_TRUE, B_FALSE, tci, msgdsize(mp));
	if (mp != NULL) {
		mp = bridge_trill_output(tsock->ts_link, mp);
		if (mp == NULL) {
			KSPINCR(tks_sent);
		} else {
			freemsg(mp);
			KSPINCR(tks_drops);
		}
	}

	/* Wake up any threads blocking on us */
	if (atomic_dec_uint_nv(&tsock->ts_sockthreadcount) == 0)
		cv_broadcast(&tsock->ts_sockthreadwait);
	return (0);

eproto:
	freemsg(mp);
	KSPINCR(tks_drops);
	return (EPROTO);
}

/* ARGSUSED */
static int
trill_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
    int mode, int32_t *rvalp, cred_t *cr)
{
	trill_sock_t *tsock = (trill_sock_t *)proto_handle;
	int rc;

	switch (cmd) {
	/* List of unprivileged TRILL ioctls */
	case TRILL_GETNICK:
	case TRILL_GETBRIDGE:
	case TRILL_LISTNICK:
		break;
	default:
		if (secpolicy_dl_config(cr) != 0)
			return (EPERM);
		break;
	}

	/* Lock ensures socket state is unchanged during ioctl handling */
	mutex_enter(&tsock->ts_socklock);
	rc = trill_do_ioctl(tsock, cmd, (void *)arg, mode);
	mutex_exit(&tsock->ts_socklock);
	return (rc);
}

static void
trill_clr_flowctrl(sock_lower_handle_t proto_handle)
{
	trill_sock_t *tsock = (trill_sock_t *)proto_handle;

	mutex_enter(&tsock->ts_socklock);
	tsock->ts_flow_ctrld = B_FALSE;
	mutex_exit(&tsock->ts_socklock);
}

static sock_downcalls_t sock_trill_downcalls = {
	trill_activate,			/* sd_activate */
	sock_accept_notsupp,		/* sd_accept */
	trill_bind,			/* sd_bind */
	sock_listen_notsupp,		/* sd_listen */
	sock_connect_notsupp,		/* sd_connect */
	sock_getpeername_notsupp,	/* sd_getpeername */
	sock_getsockname_notsupp,	/* sd_getsockname */
	sock_getsockopt_notsupp,	/* sd_getsockopt */
	sock_setsockopt_notsupp,	/* sd_setsockopt */
	trill_send,			/* sd_send */
	NULL,				/* sd_send_uio */
	NULL,				/* sd_recv_uio */
	NULL,				/* sd_poll */
	sock_shutdown_notsupp,		/* sd_shutdown */
	trill_clr_flowctrl,		/* sd_setflowctrl */
	trill_ioctl,			/* sd_ioctl */
	trill_close			/* sd_close */
};

/* ARGSUSED */
static sock_lower_handle_t
trill_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	trill_sock_t *tsock;

	if (family != AF_TRILL || type != SOCK_DGRAM || proto != 0) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	*sock_downcalls = &sock_trill_downcalls;
	*smodep = SM_ATOMIC;
	tsock = trill_do_open(flags);
	*errorp = (tsock != NULL) ? 0:ENOMEM;
	return ((sock_lower_handle_t)tsock);
}
