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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <inet/ip_arp.h>
#include <inet/ip_ndp.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <sys/strsubr.h>
#include <inet/ip6.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <sys/dlpi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/sdt.h>
#include <inet/mi.h>
#include <inet/arp.h>
#include <inet/ipdrop.h>
#include <sys/sockio.h>
#include <inet/ip_impl.h>
#include <sys/policy.h>

#define	ARL_LL_ADDR_OFFSET(arl)	(((arl)->arl_sap_length) < 0 ? \
	(sizeof (dl_unitdata_req_t)) : \
	((sizeof (dl_unitdata_req_t)) + (ABS((arl)->arl_sap_length))))

/*
 * MAC-specific intelligence.  Shouldn't be needed, but the DL_INFO_ACK
 * doesn't quite do it for us.
 */
typedef struct arp_m_s {
	t_uscalar_t	arp_mac_type;
	uint32_t	arp_mac_arp_hw_type;
	t_scalar_t	arp_mac_sap_length;
	uint32_t	arp_mac_hw_addr_length;
} arp_m_t;

static int arp_close(queue_t *, int);
static void arp_rput(queue_t *, mblk_t *);
static void arp_wput(queue_t *, mblk_t *);
static arp_m_t	*arp_m_lookup(t_uscalar_t mac_type);
static void arp_notify(ipaddr_t, mblk_t *, uint32_t, ip_recv_attr_t *,
	ncec_t *);
static int arp_output(ill_t *, uint32_t, const uchar_t *, const uchar_t *,
	const uchar_t *, const uchar_t *, uchar_t *);
static int  arp_modclose(arl_t *);
static void  arp_mod_close_tail(arl_t *);
static mblk_t *arl_unbind(arl_t *);
static void arp_process_packet(ill_t *, mblk_t *);
static void arp_excl(ipsq_t *, queue_t *, mblk_t *, void *);
static void arp_drop_packet(const char *str, mblk_t *, ill_t *);
static int arp_open(queue_t *, dev_t *, int, int, cred_t *);
static int ip_sioctl_ifunitsel_arp(queue_t *, int *);
static int ip_sioctl_slifname_arp(queue_t *, void *);
static void arp_dlpi_send(arl_t *, mblk_t *);
static void arl_defaults_common(arl_t *, mblk_t *);
static int arp_modopen(queue_t *, dev_t *, int, int, cred_t *);
static void arp_ifname_notify(arl_t *);
static void arp_rput_dlpi_writer(ipsq_t *, queue_t *, mblk_t *, void *);
static arl_t *ill_to_arl(ill_t *);

#define	DL_PRIM(mp)	(((union DL_primitives *)(mp)->b_rptr)->dl_primitive)
#define	IS_DLPI_DATA(mp)						\
	((DB_TYPE(mp) == M_PROTO) &&					\
	MBLKL(mp) >= sizeof (dl_unitdata_ind_t) &&			\
	(DL_PRIM(mp) == DL_UNITDATA_IND))

#define	AR_NOTFOUND	1	/* No matching ace found in cache */
#define	AR_MERGED	2	/* Matching ace updated (RFC 826 Merge_flag) */
#define	AR_LOOPBACK	3	/* Our own arp packet was received */
#define	AR_BOGON	4	/* Another host has our IP addr. */
#define	AR_FAILED	5	/* Duplicate Address Detection has failed */
#define	AR_CHANGED	6	/* Address has changed; tell IP (and merged) */

boolean_t arp_no_defense;

struct module_info arp_mod_info = {
	IP_MOD_ID, "arp", 1, INFPSZ, 65536, 1024
};
static struct qinit rinit_arp = {
	(pfi_t)arp_rput, NULL, arp_open, arp_close, NULL, &arp_mod_info
};
static struct qinit winit_arp = {
	(pfi_t)arp_wput, NULL, arp_open, arp_close, NULL,
	&arp_mod_info
};
struct streamtab arpinfo = {
	&rinit_arp, &winit_arp
};
#define	ARH_FIXED_LEN	8
#define	AR_LL_HDR_SLACK	32

/*
 * pfhooks for ARP.
 */
#define	ARP_HOOK_IN(_hook, _event, _ilp, _hdr, _fm, _m, ipst)		\
									\
	if ((_hook).he_interested) {                       		\
		hook_pkt_event_t info;                          	\
									\
		info.hpe_protocol = ipst->ips_arp_net_data;		\
		info.hpe_ifp = _ilp;                       		\
		info.hpe_ofp = 0;                       		\
		info.hpe_hdr = _hdr;                            	\
		info.hpe_mp = &(_fm);                           	\
		info.hpe_mb = _m;                               	\
		if (hook_run(ipst->ips_arp_net_data->netd_hooks,	\
		    _event, (hook_data_t)&info) != 0) {			\
			if (_fm != NULL) {                      	\
				freemsg(_fm);                   	\
				_fm = NULL;                     	\
			}                                       	\
			_hdr = NULL;                            	\
			_m = NULL;                              	\
		} else {                                        	\
			_hdr = info.hpe_hdr;                    	\
			_m = info.hpe_mb;                       	\
		}                                               	\
	}

#define	ARP_HOOK_OUT(_hook, _event, _olp, _hdr, _fm, _m, ipst)		\
									\
	if ((_hook).he_interested) {                       		\
		hook_pkt_event_t info;                          	\
									\
		info.hpe_protocol = ipst->ips_arp_net_data;		\
		info.hpe_ifp = 0;                       		\
		info.hpe_ofp = _olp;                       		\
		info.hpe_hdr = _hdr;                            	\
		info.hpe_mp = &(_fm);                           	\
		info.hpe_mb = _m;                               	\
		if (hook_run(ipst->ips_arp_net_data->netd_hooks,	\
		    _event, (hook_data_t)&info) != 0) {			\
			if (_fm != NULL) {                      	\
				freemsg(_fm);                   	\
				_fm = NULL;                     	\
			}                                       	\
			_hdr = NULL;                            	\
			_m = NULL;                              	\
		} else {                                        	\
			_hdr = info.hpe_hdr;                    	\
			_m = info.hpe_mb;                       	\
		}                                               	\
	}

static arp_m_t	arp_m_tbl[] = {
	{ DL_CSMACD,	ARPHRD_ETHER,	-2,	6},	/* 802.3 */
	{ DL_TPB,	ARPHRD_IEEE802,	-2,	6},	/* 802.4 */
	{ DL_TPR,	ARPHRD_IEEE802,	-2,	6},	/* 802.5 */
	{ DL_METRO,	ARPHRD_IEEE802,	-2,	6},	/* 802.6 */
	{ DL_ETHER,	ARPHRD_ETHER,	-2,	6},	/* Ethernet */
	{ DL_FDDI,	ARPHRD_ETHER,	-2,	6},	/* FDDI */
	{ DL_IB,	ARPHRD_IB,	-2,	20},	/* Infiniband */
	{ DL_OTHER,	ARPHRD_ETHER,	-2,	6}	/* unknown */
};

static void
arl_refhold_locked(arl_t *arl)
{
	ASSERT(MUTEX_HELD(&arl->arl_lock));
	arl->arl_refcnt++;
	ASSERT(arl->arl_refcnt != 0);
}

static void
arl_refrele(arl_t *arl)
{
	mutex_enter(&arl->arl_lock);
	ASSERT(arl->arl_refcnt != 0);
	arl->arl_refcnt--;
	if (arl->arl_refcnt > 1) {
		mutex_exit(&arl->arl_lock);
		return;
	}

	/* ill_close or arp_unbind_complete may be waiting */
	cv_broadcast(&arl->arl_cv);
	mutex_exit(&arl->arl_lock);
}

/*
 * wake up any pending ip ioctls.
 */
static void
arp_cmd_done(ill_t *ill, int err, t_uscalar_t lastprim)
{
	if (lastprim == DL_UNBIND_REQ && ill->ill_replumbing)
		arp_replumb_done(ill, 0);
	else
		arp_bringup_done(ill, err);
}

static int
ip_nce_resolve_all(ill_t *ill, uchar_t *src_haddr, uint32_t hlen,
    const in_addr_t *src_paddr, ncec_t **sncec, int op)
{
	int retv;
	ncec_t *ncec;
	boolean_t ll_changed;
	uchar_t *lladdr = NULL;
	int new_state;

	ASSERT(ill != NULL);

	ncec = ncec_lookup_illgrp_v4(ill, src_paddr);
	*sncec = ncec;

	if (ncec == NULL) {
		retv = AR_NOTFOUND;
		goto done;
	}

	mutex_enter(&ncec->ncec_lock);
	/*
	 * IP addr and hardware address match what we already
	 * have, then this is a broadcast packet emitted by one of our
	 * interfaces, reflected by the switch and received on another
	 * interface.  We return AR_LOOPBACK.
	 */
	lladdr = ncec->ncec_lladdr;
	if (NCE_MYADDR(ncec) && hlen == ncec->ncec_ill->ill_phys_addr_length &&
	    bcmp(lladdr, src_haddr, hlen) == 0) {
		mutex_exit(&ncec->ncec_lock);
		retv = AR_LOOPBACK;
		goto done;
	}
	/*
	 * If the entry is unverified, then we've just verified that
	 * someone else already owns this address, because this is a
	 * message with the same protocol address but different
	 * hardware address.
	 */
	if (ncec->ncec_flags & NCE_F_UNVERIFIED) {
		mutex_exit(&ncec->ncec_lock);
		ncec_delete(ncec);
		ncec_refrele(ncec);
		*sncec = NULL;
		retv = AR_FAILED;
		goto done;
	}

	/*
	 * If the IP address matches ours and we're authoritative for
	 * this entry, then some other node is using our IP addr, so
	 * return AR_BOGON.  Also reset the transmit count to zero so
	 * that, if we're currently in initial announcement mode, we
	 * switch back to the lazier defense mode.  Knowing that
	 * there's at least one duplicate out there, we ought not
	 * blindly announce.
	 *
	 * NCE_F_AUTHORITY is set in one of two ways:
	 * 1. /sbin/arp told us so, via the "permanent" flag.
	 * 2. This is one of my addresses.
	 */
	if (ncec->ncec_flags & NCE_F_AUTHORITY) {
		ncec->ncec_unsolicit_count = 0;
		mutex_exit(&ncec->ncec_lock);
		retv = AR_BOGON;
		goto done;
	}

	/*
	 * No address conflict was detected, and we are getting
	 * ready to update the ncec's hwaddr. The nce MUST NOT be on an
	 * under interface, because all dynamic nce's are created on the
	 * native interface (in the non-IPMP case) or on the IPMP
	 * meta-interface (in the IPMP case)
	 */
	ASSERT(!IS_UNDER_IPMP(ncec->ncec_ill));

	/*
	 * update ncec with src_haddr, hlen.
	 *
	 * We are trying to resolve this ncec_addr/src_paddr and we
	 * got a REQUEST/RESPONSE from the ncec_addr/src_paddr.
	 * So the new_state is at least "STALE". If, in addition,
	 * this a solicited, unicast ARP_RESPONSE, we can transition
	 * to REACHABLE.
	 */
	new_state = ND_STALE;
	ip1dbg(("got info for ncec %p from addr %x\n",
	    (void *)ncec, *src_paddr));
	retv = AR_MERGED;
	if (ncec->ncec_state == ND_INCOMPLETE ||
	    ncec->ncec_state == ND_INITIAL) {
		ll_changed = B_TRUE;
	} else {
		ll_changed = nce_cmp_ll_addr(ncec, src_haddr, hlen);
		if (!ll_changed)
			new_state = ND_UNCHANGED;
		else
			retv = AR_CHANGED;
	}
	/*
	 * We don't have the equivalent of the IPv6 'S' flag indicating
	 * a solicited response, so we assume that if we are in
	 * INCOMPLETE, or got back an unchanged lladdr in PROBE state,
	 * and this is an ARP_RESPONSE, it must be a
	 * solicited response allowing us to transtion to REACHABLE.
	 */
	if (op == ARP_RESPONSE) {
		switch (ncec->ncec_state) {
		case ND_PROBE:
			new_state = (ll_changed ? ND_STALE : ND_REACHABLE);
			break;
		case ND_INCOMPLETE:
			new_state = ND_REACHABLE;
			break;
		}
	}
	/*
	 * Call nce_update() to refresh fastpath information on any
	 * dependent nce_t entries.
	 */
	nce_update(ncec, new_state, (ll_changed ? src_haddr : NULL));
	mutex_exit(&ncec->ncec_lock);
	nce_resolv_ok(ncec);
done:
	return (retv);
}

/* Find an entry for a particular MAC type in the arp_m_tbl. */
static arp_m_t	*
arp_m_lookup(t_uscalar_t mac_type)
{
	arp_m_t	*arm;

	for (arm = arp_m_tbl; arm < A_END(arp_m_tbl); arm++) {
		if (arm->arp_mac_type == mac_type)
			return (arm);
	}
	return (NULL);
}

uint32_t
arp_hw_type(t_uscalar_t mactype)
{
	arp_m_t *arm;

	if ((arm = arp_m_lookup(mactype)) == NULL)
		arm = arp_m_lookup(DL_OTHER);
	return (arm->arp_mac_arp_hw_type);
}

/*
 * Called when an DLPI control message has been acked; send down the next
 * queued message (if any).
 * The DLPI messages of interest being bind, attach and unbind since
 * these are the only ones sent by ARP via arp_dlpi_send.
 */
static void
arp_dlpi_done(arl_t *arl, ill_t *ill)
{
	mblk_t *mp;
	int err;
	t_uscalar_t prim;

	mutex_enter(&arl->arl_lock);
	prim = arl->arl_dlpi_pending;

	if ((mp = arl->arl_dlpi_deferred) == NULL) {
		arl->arl_dlpi_pending = DL_PRIM_INVAL;
		if (arl->arl_state_flags & ARL_LL_DOWN)
			err = ENETDOWN;
		else
			err = 0;
		mutex_exit(&arl->arl_lock);

		mutex_enter(&ill->ill_lock);
		ill->ill_arl_dlpi_pending = 0;
		mutex_exit(&ill->ill_lock);
		arp_cmd_done(ill, err, prim);
		return;
	}

	arl->arl_dlpi_deferred = mp->b_next;
	mp->b_next = NULL;

	ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);

	arl->arl_dlpi_pending = DL_PRIM(mp);
	mutex_exit(&arl->arl_lock);

	mutex_enter(&ill->ill_lock);
	ill->ill_arl_dlpi_pending = 1;
	mutex_exit(&ill->ill_lock);

	putnext(arl->arl_wq, mp);
}

/*
 * This routine is called during module initialization when the DL_INFO_ACK
 * comes back from the device.	We set up defaults for all the device dependent
 * doo-dads we are going to need.  This will leave us ready to roll if we are
 * attempting auto-configuration.  Alternatively, these defaults can be
 * overridden by initialization procedures possessing higher intelligence.
 *
 * Caller will free the mp.
 */
static void
arp_ll_set_defaults(arl_t *arl, mblk_t *mp)
{
	arp_m_t		*arm;
	dl_info_ack_t	*dlia = (dl_info_ack_t *)mp->b_rptr;

	if ((arm = arp_m_lookup(dlia->dl_mac_type)) == NULL)
		arm = arp_m_lookup(DL_OTHER);
	ASSERT(arm != NULL);

	/*
	 * We initialize based on parameters in the (currently) not too
	 * exhaustive arp_m_tbl.
	 */
	if (dlia->dl_version == DL_VERSION_2) {
		arl->arl_sap_length = dlia->dl_sap_length;
		arl->arl_phys_addr_length = dlia->dl_brdcst_addr_length;
		if (dlia->dl_provider_style == DL_STYLE2)
			arl->arl_needs_attach = 1;
	} else {
		arl->arl_sap_length = arm->arp_mac_sap_length;
		arl->arl_phys_addr_length = arm->arp_mac_hw_addr_length;
	}
	/*
	 * Note: the arp_hw_type in the arp header may be derived from
	 * the ill_mac_type and arp_m_lookup().
	 */
	arl->arl_sap = ETHERTYPE_ARP;
	arl_defaults_common(arl, mp);
}

static void
arp_wput(queue_t *q, mblk_t *mp)
{
	int err = EINVAL;
	struct iocblk *ioc;
	mblk_t *mp1;

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		ASSERT(q->q_next != NULL);
		ioc = (struct iocblk *)mp->b_rptr;
		if (ioc->ioc_cmd != SIOCSLIFNAME &&
		    ioc->ioc_cmd != IF_UNITSEL) {
			DTRACE_PROBE4(arl__dlpi, char *, "arp_wput",
			    char *, "<some ioctl>", char *, "-",
			    arl_t *, (arl_t *)q->q_ptr);
			putnext(q, mp);
			return;
		}
		if ((mp1 = mp->b_cont) == 0)
			err = EINVAL;
		else if (ioc->ioc_cmd == SIOCSLIFNAME)
			err = ip_sioctl_slifname_arp(q, mp1->b_rptr);
		else if (ioc->ioc_cmd == IF_UNITSEL)
			err = ip_sioctl_ifunitsel_arp(q, (int *)mp1->b_rptr);
		if (err == 0)
			miocack(q, mp, 0, 0);
		else
			miocnak(q, mp, 0, err);
		return;
	default:
		DTRACE_PROBE4(arl__dlpi, char *, "arp_wput default",
		    char *, "default mblk", char *, "-",
		    arl_t *, (arl_t *)q->q_ptr);
		putnext(q, mp);
		return;
	}
}

/*
 * similar to ill_dlpi_pending(): verify that the received DLPI response
 * matches the one that is pending for the arl.
 */
static boolean_t
arl_dlpi_pending(arl_t *arl, t_uscalar_t prim)
{
	t_uscalar_t pending;

	mutex_enter(&arl->arl_lock);
	if (arl->arl_dlpi_pending == prim) {
		mutex_exit(&arl->arl_lock);
		return (B_TRUE);
	}

	if (arl->arl_state_flags & ARL_CONDEMNED) {
		mutex_exit(&arl->arl_lock);
		return (B_FALSE);
	}
	pending = arl->arl_dlpi_pending;
	mutex_exit(&arl->arl_lock);

	if (pending == DL_PRIM_INVAL) {
		ip0dbg(("arl_dlpi_pending unsolicited ack for %s on %s",
		    dl_primstr(prim), arl->arl_name));
	} else {
		ip0dbg(("arl_dlpi_pending ack for %s on %s expect %s",
		    dl_primstr(prim), arl->arl_name, dl_primstr(pending)));
	}
	return (B_FALSE);
}

/* DLPI messages, other than DL_UNITDATA_IND are handled here. */
static void
arp_rput_dlpi(queue_t *q, mblk_t *mp)
{
	arl_t		*arl = (arl_t *)q->q_ptr;
	union DL_primitives *dlp;
	t_uscalar_t	prim;
	t_uscalar_t	reqprim = DL_PRIM_INVAL;
	ill_t		*ill;

	if ((mp->b_wptr - mp->b_rptr) < sizeof (dlp->dl_primitive)) {
		putnext(q, mp);
		return;
	}
	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;

	/*
	 * If we received an ACK but didn't send a request for it, then it
	 * can't be part of any pending operation; discard up-front.
	 */
	switch (prim) {
	case DL_ERROR_ACK:
		/*
		 * ce is confused about how DLPI works, so we have to interpret
		 * an "error" on DL_NOTIFY_ACK (which we never could have sent)
		 * as really meaning an error on DL_NOTIFY_REQ.
		 *
		 * Note that supporting DL_NOTIFY_REQ is optional, so printing
		 * out an error message on the console isn't warranted except
		 * for debug.
		 */
		if (dlp->error_ack.dl_error_primitive == DL_NOTIFY_ACK ||
		    dlp->error_ack.dl_error_primitive == DL_NOTIFY_REQ) {
			reqprim = DL_NOTIFY_REQ;
		} else {
			reqprim = dlp->error_ack.dl_error_primitive;
		}
		break;
	case DL_INFO_ACK:
		reqprim = DL_INFO_REQ;
		break;
	case DL_OK_ACK:
		reqprim = dlp->ok_ack.dl_correct_primitive;
		break;
	case DL_BIND_ACK:
		reqprim = DL_BIND_REQ;
		break;
	default:
		DTRACE_PROBE2(rput_dl_badprim, arl_t *, arl,
		    union DL_primitives *, dlp);
		putnext(q, mp);
		return;
	}
	if (reqprim == DL_PRIM_INVAL || !arl_dlpi_pending(arl, reqprim)) {
		freemsg(mp);
		return;
	}
	DTRACE_PROBE4(arl__dlpi, char *, "arp_rput_dlpi received",
	    char *, dl_primstr(prim), char *, dl_primstr(reqprim),
	    arl_t *, arl);

	ASSERT(prim != DL_NOTIFY_IND);

	ill = arl_to_ill(arl);

	switch (reqprim) {
	case DL_INFO_REQ:
		/*
		 * ill has not been set up yet for this case. This is the
		 * DL_INFO_ACK for the first DL_INFO_REQ sent from
		 * arp_modopen(). There should be no other arl_dlpi_deferred
		 * messages pending. We initialize the arl here.
		 */
		ASSERT(!arl->arl_dlpi_style_set);
		ASSERT(arl->arl_dlpi_pending == DL_INFO_REQ);
		ASSERT(arl->arl_dlpi_deferred == NULL);
		arl->arl_dlpi_pending = DL_PRIM_INVAL;
		arp_ll_set_defaults(arl, mp);
		freemsg(mp);
		return;
	case DL_UNBIND_REQ:
		mutex_enter(&arl->arl_lock);
		arl->arl_state_flags &= ~ARL_DL_UNBIND_IN_PROGRESS;
		/*
		 * This is not an error, so we don't set ARL_LL_DOWN
		 */
		arl->arl_state_flags &= ~ARL_LL_UP;
		arl->arl_state_flags |= ARL_LL_UNBOUND;
		if (arl->arl_state_flags & ARL_CONDEMNED) {
			/*
			 * if this is part of the unplumb the arl may
			 * vaporize any moment after we cv_signal the
			 * arl_cv so we reset arl_dlpi_pending here.
			 * All other cases (including replumb) will
			 * have the arl_dlpi_pending reset in
			 * arp_dlpi_done.
			 */
			arl->arl_dlpi_pending = DL_PRIM_INVAL;
		}
		cv_signal(&arl->arl_cv);
		mutex_exit(&arl->arl_lock);
		break;
	}
	if (ill != NULL) {
		/*
		 * ill ref obtained by arl_to_ill()  will be released
		 * by qwriter_ip()
		 */
		qwriter_ip(ill, ill->ill_wq, mp, arp_rput_dlpi_writer,
		    CUR_OP, B_TRUE);
		return;
	}
	freemsg(mp);
}

/*
 * Handling of DLPI messages that require exclusive access to the ipsq.
 */
/* ARGSUSED */
static void
arp_rput_dlpi_writer(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	union DL_primitives *dlp = (union DL_primitives *)mp->b_rptr;
	ill_t		*ill = (ill_t *)q->q_ptr;
	arl_t		*arl = ill_to_arl(ill);

	if (arl == NULL) {
		/*
		 * happens as a result arp_modclose triggering unbind.
		 * arp_rput_dlpi will cv_signal the arl_cv and the modclose
		 * will complete, but when it does ipsq_exit, the waiting
		 * qwriter_ip gets into the ipsq but will find the arl null.
		 * There should be no deferred messages in this case, so
		 * just complete and exit.
		 */
		arp_cmd_done(ill, 0, DL_UNBIND_REQ);
		freemsg(mp);
		return;
	}
	switch (dlp->dl_primitive) {
	case DL_ERROR_ACK:
		switch (dlp->error_ack.dl_error_primitive) {
		case DL_UNBIND_REQ:
			mutex_enter(&arl->arl_lock);
			arl->arl_state_flags &= ~ARL_DL_UNBIND_IN_PROGRESS;
			arl->arl_state_flags &= ~ARL_LL_UP;
			arl->arl_state_flags |= ARL_LL_UNBOUND;
			arl->arl_state_flags |= ARL_LL_DOWN;
			cv_signal(&arl->arl_cv);
			mutex_exit(&arl->arl_lock);
			break;
		case DL_BIND_REQ:
			mutex_enter(&arl->arl_lock);
			arl->arl_state_flags &= ~ARL_LL_UP;
			arl->arl_state_flags |= ARL_LL_DOWN;
			arl->arl_state_flags |= ARL_LL_UNBOUND;
			cv_signal(&arl->arl_cv);
			mutex_exit(&arl->arl_lock);
			break;
		case DL_ATTACH_REQ:
			break;
		default:
			/* If it's anything else, we didn't send it. */
			arl_refrele(arl);
			putnext(q, mp);
			return;
		}
		break;
	case DL_OK_ACK:
		DTRACE_PROBE4(arl__dlpi, char *, "arp_rput_dlpi_writer ok",
		    char *, dl_primstr(dlp->ok_ack.dl_correct_primitive),
		    char *, dl_primstr(dlp->ok_ack.dl_correct_primitive),
		    arl_t *, arl);
		mutex_enter(&arl->arl_lock);
		switch (dlp->ok_ack.dl_correct_primitive) {
		case DL_UNBIND_REQ:
		case DL_ATTACH_REQ:
			break;
		default:
			ip0dbg(("Dropping unrecognized DL_OK_ACK for %s",
			    dl_primstr(dlp->ok_ack.dl_correct_primitive)));
			mutex_exit(&arl->arl_lock);
			arl_refrele(arl);
			freemsg(mp);
			return;
		}
		mutex_exit(&arl->arl_lock);
		break;
	case DL_BIND_ACK:
		DTRACE_PROBE2(rput_dl_bind, arl_t *, arl,
		    dl_bind_ack_t *, &dlp->bind_ack);

		mutex_enter(&arl->arl_lock);
		ASSERT(arl->arl_state_flags & ARL_LL_BIND_PENDING);
		arl->arl_state_flags &=
		    ~(ARL_LL_BIND_PENDING|ARL_LL_DOWN|ARL_LL_UNBOUND);
		arl->arl_state_flags |= ARL_LL_UP;
		mutex_exit(&arl->arl_lock);
		break;
	case DL_UDERROR_IND:
		DTRACE_PROBE2(rput_dl_uderror, arl_t *, arl,
		    dl_uderror_ind_t *, &dlp->uderror_ind);
		arl_refrele(arl);
		putnext(q, mp);
		return;
	default:
		DTRACE_PROBE2(rput_dl_badprim, arl_t *, arl,
		    union DL_primitives *, dlp);
		arl_refrele(arl);
		putnext(q, mp);
		return;
	}
	arp_dlpi_done(arl, ill);
	arl_refrele(arl);
	freemsg(mp);
}

void
arp_rput(queue_t *q, mblk_t *mp)
{
	arl_t		*arl = q->q_ptr;
	boolean_t	need_refrele = B_FALSE;

	mutex_enter(&arl->arl_lock);
	if (((arl->arl_state_flags &
	    (ARL_CONDEMNED | ARL_LL_REPLUMBING)) != 0)) {
		/*
		 * Only allow high priority DLPI messages during unplumb or
		 * replumb, and we don't take an arl_refcnt for that case.
		 */
		if (DB_TYPE(mp) != M_PCPROTO) {
			mutex_exit(&arl->arl_lock);
			freemsg(mp);
			return;
		}
	} else {
		arl_refhold_locked(arl);
		need_refrele = B_TRUE;
	}
	mutex_exit(&arl->arl_lock);

	switch (DB_TYPE(mp)) {
	case M_PCPROTO:
	case M_PROTO: {
		ill_t *ill;

		/*
		 * could be one of
		 * (i)   real message from the wire, (DLPI_DATA)
		 * (ii)  DLPI message
		 * Take a ref on the ill associated with this arl to
		 * prevent the ill from being unplumbed until this thread
		 * is done.
		 */
		if (IS_DLPI_DATA(mp)) {
			ill = arl_to_ill(arl);
			if (ill == NULL) {
				arp_drop_packet("No ill", mp, ill);
				break;
			}
			arp_process_packet(ill, mp);
			ill_refrele(ill);
			break;
		}
		/* Miscellaneous DLPI messages get shuffled off. */
		arp_rput_dlpi(q, mp);
		break;
	}
	case M_ERROR:
	case M_HANGUP:
		if (mp->b_rptr < mp->b_wptr)
			arl->arl_error = (int)(*mp->b_rptr & 0xFF);
		if (arl->arl_error == 0)
			arl->arl_error = ENXIO;
		freemsg(mp);
		break;
	default:
		ip1dbg(("arp_rput other db type %x\n", DB_TYPE(mp)));
		putnext(q, mp);
		break;
	}
	if (need_refrele)
		arl_refrele(arl);
}

static void
arp_process_packet(ill_t *ill, mblk_t *mp)
{
	mblk_t 		*mp1;
	arh_t		*arh;
	in_addr_t	src_paddr, dst_paddr;
	uint32_t	hlen, plen;
	boolean_t	is_probe;
	int		op;
	ncec_t		*dst_ncec, *src_ncec = NULL;
	uchar_t		*src_haddr, *arhp, *dst_haddr, *dp, *sp;
	int		err;
	ip_stack_t	*ipst;
	boolean_t	need_ill_refrele = B_FALSE;
	nce_t		*nce;
	uchar_t		*src_lladdr;
	dl_unitdata_ind_t *dlui;
	ip_recv_attr_t	iras;

	ASSERT(ill != NULL);
	if (ill->ill_flags & ILLF_NOARP) {
		arp_drop_packet("Interface does not support ARP", mp, ill);
		return;
	}
	ipst = ill->ill_ipst;
	/*
	 * What we should have at this point is a DL_UNITDATA_IND message
	 * followed by an ARP packet.  We do some initial checks and then
	 * get to work.
	 */
	dlui = (dl_unitdata_ind_t *)mp->b_rptr;
	if (dlui->dl_group_address == 1) {
		/*
		 * multicast or broadcast  packet. Only accept on the ipmp
		 * nominated interface for multicasts ('cast_ill').
		 * If we have no cast_ill we are liberal and accept everything.
		 */
		if (IS_UNDER_IPMP(ill)) {
			/* For an under ill_grp can change under lock */
			rw_enter(&ipst->ips_ill_g_lock, RW_READER);
			if (!ill->ill_nom_cast && ill->ill_grp != NULL &&
			    ill->ill_grp->ig_cast_ill != NULL) {
				rw_exit(&ipst->ips_ill_g_lock);
				arp_drop_packet("Interface is not nominated "
				    "for multicast sends and receives",
				    mp, ill);
				return;
			}
			rw_exit(&ipst->ips_ill_g_lock);
		}
	}
	mp1 = mp->b_cont;
	if (mp1 == NULL) {
		arp_drop_packet("Missing ARP packet", mp, ill);
		return;
	}
	if (mp1->b_cont != NULL) {
		/* No fooling around with funny messages. */
		if (!pullupmsg(mp1, -1)) {
			arp_drop_packet("Funny message: pullup failed",
			    mp, ill);
			return;
		}
	}
	arh = (arh_t *)mp1->b_rptr;
	hlen = arh->arh_hlen;
	plen = arh->arh_plen;
	if (MBLKL(mp1) < ARH_FIXED_LEN + 2 * hlen + 2 * plen) {
		arp_drop_packet("mblk len too small", mp, ill);
		return;
	}
	/*
	 * hlen 0 is used for RFC 1868 UnARP.
	 *
	 * Note that the rest of the code checks that hlen is what we expect
	 * for this hardware address type, so might as well discard packets
	 * here that don't match.
	 */
	if ((hlen > 0 && hlen != ill->ill_phys_addr_length) || plen == 0) {
		DTRACE_PROBE2(rput_bogus, ill_t *, ill, mblk_t *, mp1);
		arp_drop_packet("Bogus hlen or plen", mp, ill);
		return;
	}
	/*
	 * Historically, Solaris has been lenient about hardware type numbers.
	 * We should check here, but don't.
	 */
	DTRACE_PROBE3(arp__physical__in__start, ill_t *, ill, arh_t *, arh,
	    mblk_t *, mp);
	/*
	 * If ill is in an ipmp group, it will be the under ill. If we want
	 * to report the packet as coming up the IPMP interface, we should
	 * convert it to the ipmp ill.
	 */
	ARP_HOOK_IN(ipst->ips_arp_physical_in_event, ipst->ips_arp_physical_in,
	    ill->ill_phyint->phyint_ifindex, arh, mp, mp1, ipst);
	DTRACE_PROBE1(arp__physical__in__end, mblk_t *, mp);
	if (mp == NULL)
		return;
	arhp = (uchar_t *)arh + ARH_FIXED_LEN;
	src_haddr = arhp;			/* ar$sha */
	arhp += hlen;
	bcopy(arhp, &src_paddr, IP_ADDR_LEN);	/* ar$spa */
	sp = arhp;
	arhp += IP_ADDR_LEN;
	dst_haddr = arhp;			/* ar$dha */
	arhp += hlen;
	bcopy(arhp, &dst_paddr, IP_ADDR_LEN);	/* ar$tpa */
	dp = arhp;
	op = BE16_TO_U16(arh->arh_operation);

	DTRACE_PROBE2(ip__arp__input, (in_addr_t), src_paddr,
	    (in_addr_t), dst_paddr);

	/* Determine if this is just a probe */
	is_probe = (src_paddr == INADDR_ANY);

	/*
	 * The following test for loopback is faster than
	 * IP_LOOPBACK_ADDR(), because it avoids any bitwise
	 * operations.
	 * Note that these addresses are always in network byte order
	 */
	if ((*(uint8_t *)&src_paddr) == IN_LOOPBACKNET ||
	    (*(uint8_t *)&dst_paddr) == IN_LOOPBACKNET ||
	    CLASSD(src_paddr) || CLASSD(dst_paddr)) {
		arp_drop_packet("Martian IP addr", mp, ill);
		return;
	}

	/*
	 * ira_ill is the only field used down the arp_notify path.
	 */
	bzero(&iras, sizeof (iras));
	iras.ira_ill = iras.ira_rill = ill;
	/*
	 * RFC 826: first check if the <protocol, sender protocol address> is
	 * in the cache, if there is a sender protocol address.  Note that this
	 * step also handles resolutions based on source.
	 */
	/* Note: after here we need to freeb(mp) and freemsg(mp1) separately */
	mp->b_cont = NULL;
	if (is_probe) {
		err = AR_NOTFOUND;
	} else {
		if (plen != 4) {
			arp_drop_packet("bad protocol len", mp, ill);
			return;
		}
		err = ip_nce_resolve_all(ill, src_haddr, hlen, &src_paddr,
		    &src_ncec, op);
		switch (err) {
		case AR_BOGON:
			ASSERT(src_ncec != NULL);
			arp_notify(src_paddr, mp1, AR_CN_BOGON,
			    &iras, src_ncec);
			break;
		case AR_FAILED:
			arp_notify(src_paddr, mp1, AR_CN_FAILED, &iras,
			    src_ncec);
			break;
		case AR_LOOPBACK:
			DTRACE_PROBE2(rput_loopback, ill_t *, ill, arh_t *,
			    arh);
			freemsg(mp1);
			break;
		default:
			goto update;
		}
		freemsg(mp);
		if (src_ncec != NULL)
			ncec_refrele(src_ncec);
		return;
	}
update:
	/*
	 * Now look up the destination address.  By RFC 826, we ignore the
	 * packet at this step if the target isn't one of our addresses (i.e.,
	 * one we have been asked to PUBLISH).  This is true even if the
	 * target is something we're trying to resolve and the packet
	 * is a response.
	 */
	dst_ncec = ncec_lookup_illgrp_v4(ill, &dst_paddr);
	if (dst_ncec == NULL || !NCE_PUBLISH(dst_ncec)) {
		/*
		 * Let the client know if the source mapping has changed, even
		 * if the destination provides no useful information for the
		 * client.
		 */
		if (err == AR_CHANGED) {
			arp_notify(src_paddr, mp1, AR_CN_ANNOUNCE, &iras,
			    NULL);
			freemsg(mp);
		} else {
			freemsg(mp);
			arp_drop_packet("Target is not interesting", mp1, ill);
		}
		if (dst_ncec != NULL)
			ncec_refrele(dst_ncec);
		if (src_ncec != NULL)
			ncec_refrele(src_ncec);
		return;
	}

	if (dst_ncec->ncec_flags & NCE_F_UNVERIFIED) {
		/*
		 * Check for a reflection.  Some misbehaving bridges will
		 * reflect our own transmitted packets back to us.
		 */
		ASSERT(NCE_PUBLISH(dst_ncec));
		if (hlen != dst_ncec->ncec_ill->ill_phys_addr_length) {
			ncec_refrele(dst_ncec);
			if (src_ncec != NULL)
				ncec_refrele(src_ncec);
			freemsg(mp);
			arp_drop_packet("bad arh_len", mp1, ill);
			return;
		}
		if (!nce_cmp_ll_addr(dst_ncec, src_haddr, hlen)) {
			DTRACE_PROBE3(rput_probe_reflected, ill_t *, ill,
			    arh_t *, arh, ncec_t *, dst_ncec);
			ncec_refrele(dst_ncec);
			if (src_ncec != NULL)
				ncec_refrele(src_ncec);
			freemsg(mp);
			arp_drop_packet("Reflected probe", mp1, ill);
			return;
		}
		/*
		 * Responses targeting our HW address that are not responses to
		 * our DAD probe must be ignored as they are related to requests
		 * sent before DAD was restarted.
		 */
		if (op == ARP_RESPONSE &&
		    (nce_cmp_ll_addr(dst_ncec, dst_haddr, hlen) == 0)) {
			ncec_refrele(dst_ncec);
			if (src_ncec != NULL)
				ncec_refrele(src_ncec);
			freemsg(mp);
			arp_drop_packet(
			    "Response to request that was sent before DAD",
			    mp1, ill);
			return;
		}
		/*
		 * Responses targeted to HW addresses which are not ours but
		 * sent to our unverified proto address are also conflicts.
		 * These may be reported by a proxy rather than the interface
		 * with the conflicting address, dst_paddr is in conflict
		 * rather than src_paddr. To ensure IP can locate the correct
		 * ipif to take down, it is necessary to copy dst_paddr to
		 * the src_paddr field before sending it to IP. The same is
		 * required for probes, where src_paddr will be INADDR_ANY.
		 */
		if (is_probe || op == ARP_RESPONSE) {
			bcopy(dp, sp, plen);
			arp_notify(src_paddr, mp1, AR_CN_FAILED, &iras,
			    NULL);
			ncec_delete(dst_ncec);
		} else if (err == AR_CHANGED) {
			arp_notify(src_paddr, mp1, AR_CN_ANNOUNCE, &iras,
			    NULL);
		} else {
			DTRACE_PROBE3(rput_request_unverified,
			    ill_t *, ill, arh_t *, arh, ncec_t *, dst_ncec);
			arp_drop_packet("Unverified request", mp1, ill);
		}
		freemsg(mp);
		ncec_refrele(dst_ncec);
		if (src_ncec != NULL)
			ncec_refrele(src_ncec);
		return;
	}
	/*
	 * If it's a request, then we reply to this, and if we think the
	 * sender's unknown, then we create an entry to avoid unnecessary ARPs.
	 * The design assumption is that someone ARPing us is likely to send us
	 * a packet soon, and that we'll want to reply to it.
	 */
	if (op == ARP_REQUEST) {
		const uchar_t *nce_hwaddr;
		struct in_addr nce_paddr;
		clock_t now;
		ill_t *under_ill = ill;
		boolean_t send_unicast = B_TRUE;

		ASSERT(NCE_PUBLISH(dst_ncec));

		if ((dst_ncec->ncec_flags & (NCE_F_BCAST|NCE_F_MCAST)) != 0) {
			/*
			 * Ignore senders who are deliberately or accidentally
			 * confused.
			 */
			goto bail;
		}

		if (!is_probe && err == AR_NOTFOUND) {
			ASSERT(src_ncec == NULL);

			if (IS_UNDER_IPMP(under_ill)) {
				/*
				 * create the ncec for the sender on ipmp_ill.
				 * We pass in the ipmp_ill itself to avoid
				 * creating an nce_t on the under_ill.
				 */
				ill = ipmp_ill_hold_ipmp_ill(under_ill);
				if (ill == NULL)
					ill = under_ill;
				else
					need_ill_refrele = B_TRUE;
			}

			err = nce_lookup_then_add_v4(ill, src_haddr, hlen,
			    &src_paddr, 0, ND_STALE, &nce);

			switch (err) {
			case 0:
			case EEXIST:
				ip1dbg(("added ncec %p in state %d ill %s\n",
				    (void *)src_ncec, src_ncec->ncec_state,
				    ill->ill_name));
				src_ncec = nce->nce_common;
				break;
			default:
				/*
				 * Either no memory, or the outgoing interface
				 * is in the process of down/unplumb. In the
				 * latter case, we will fail the send anyway,
				 * and in the former case, we should try to send
				 * the ARP response.
				 */
				src_lladdr = src_haddr;
				goto send_response;
			}
			ncec_refhold(src_ncec);
			nce_refrele(nce);
			/* set up cleanup interval on ncec */
		}

		/*
		 * This implements periodic address defense based on a modified
		 * version of the RFC 3927 requirements.  Instead of sending a
		 * broadcasted reply every time, as demanded by the RFC, we
		 * send at most one broadcast reply per arp_broadcast_interval.
		 */
		now = ddi_get_lbolt();
		if ((now - dst_ncec->ncec_last_time_defended) >
		    MSEC_TO_TICK(ipst->ips_ipv4_dad_announce_interval)) {
			dst_ncec->ncec_last_time_defended = now;
			/*
			 * If this is one of the long-suffering entries,
			 * pull it out now.  It no longer needs separate
			 * defense, because we're now doing that with this
			 * broadcasted reply.
			 */
			dst_ncec->ncec_flags &= ~NCE_F_DELAYED;
			send_unicast = B_FALSE;
		}
		if (src_ncec != NULL && send_unicast) {
			src_lladdr = src_ncec->ncec_lladdr;
		} else {
			src_lladdr = under_ill->ill_bcast_mp->b_rptr +
			    NCE_LL_ADDR_OFFSET(under_ill);
		}
send_response:
		nce_hwaddr = dst_ncec->ncec_lladdr;
		IN6_V4MAPPED_TO_INADDR(&dst_ncec->ncec_addr, &nce_paddr);

		(void) arp_output(under_ill, ARP_RESPONSE,
		    nce_hwaddr, (uchar_t *)&nce_paddr, src_haddr,
		    (uchar_t *)&src_paddr, src_lladdr);
	}
bail:
	if (dst_ncec != NULL) {
		ncec_refrele(dst_ncec);
	}
	if (src_ncec != NULL) {
		ncec_refrele(src_ncec);
	}
	if (err == AR_CHANGED) {
		mp->b_cont = NULL;
		arp_notify(src_paddr, mp1, AR_CN_ANNOUNCE, &iras, NULL);
		mp1 = NULL;
	}
	if (need_ill_refrele)
		ill_refrele(ill);
done:
	freemsg(mp);
	freemsg(mp1);
}

/*
 * Basic initialization of the arl_t and the arl_common structure shared with
 * the ill_t that is done after SLIFNAME/IF_UNITSEL.
 */
static int
arl_ill_init(arl_t *arl, char *ill_name)
{
	ill_t *ill;
	arl_ill_common_t *ai;

	ill = ill_lookup_on_name(ill_name, B_FALSE, B_FALSE, B_FALSE,
	    arl->arl_ipst);

	if (ill == NULL)
		return (ENXIO);

	/*
	 * By the time we set up the arl, we expect the ETHERTYPE_IP
	 * stream to be fully bound and attached. So we copy/verify
	 * relevant information as possible from/against the ill.
	 *
	 * The following should have been set up in arp_ll_set_defaults()
	 * after the first DL_INFO_ACK was received.
	 */
	ASSERT(arl->arl_phys_addr_length == ill->ill_phys_addr_length);
	ASSERT(arl->arl_sap == ETHERTYPE_ARP);
	ASSERT(arl->arl_mactype == ill->ill_mactype);
	ASSERT(arl->arl_sap_length == ill->ill_sap_length);

	ai =  kmem_zalloc(sizeof (*ai), KM_SLEEP);
	mutex_enter(&ill->ill_lock);
	/* First ensure that the ill is not CONDEMNED.  */
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		ill_refrele(ill);
		kmem_free(ai, sizeof (*ai));
		return (ENXIO);
	}
	if (ill->ill_common != NULL || arl->arl_common != NULL) {
		mutex_exit(&ill->ill_lock);
		ip0dbg(("%s: PPA already exists", ill->ill_name));
		ill_refrele(ill);
		kmem_free(ai, sizeof (*ai));
		return (EEXIST);
	}
	mutex_init(&ai->ai_lock, NULL, MUTEX_DEFAULT, NULL);
	ai->ai_arl = arl;
	ai->ai_ill = ill;
	ill->ill_common = ai;
	arl->arl_common = ai;
	mutex_exit(&ill->ill_lock);
	(void) strlcpy(arl->arl_name, ill->ill_name, LIFNAMSIZ);
	arl->arl_name_length = ill->ill_name_length;
	ill_refrele(ill);
	arp_ifname_notify(arl);
	return (0);
}

/* Allocate and do common initializations for DLPI messages. */
static mblk_t *
ip_ar_dlpi_comm(t_uscalar_t prim, size_t size)
{
	mblk_t  *mp;

	if ((mp = allocb(size, BPRI_HI)) == NULL)
		return (NULL);

	/*
	 * DLPIv2 says that DL_INFO_REQ and DL_TOKEN_REQ (the latter
	 * of which we don't seem to use) are sent with M_PCPROTO, and
	 * that other DLPI are M_PROTO.
	 */
	DB_TYPE(mp) = (prim == DL_INFO_REQ) ? M_PCPROTO : M_PROTO;

	mp->b_wptr = mp->b_rptr + size;
	bzero(mp->b_rptr, size);
	DL_PRIM(mp) = prim;
	return (mp);
}


int
ip_sioctl_ifunitsel_arp(queue_t *q, int *ppa)
{
	arl_t *arl;
	char *cp, ill_name[LIFNAMSIZ];

	if (q->q_next == NULL)
		return (EINVAL);

	do {
		q = q->q_next;
	} while (q->q_next != NULL);
	cp = q->q_qinfo->qi_minfo->mi_idname;

	arl = (arl_t *)q->q_ptr;
	(void) snprintf(ill_name, sizeof (ill_name), "%s%d", cp, *ppa);
	arl->arl_ppa = *ppa;
	return (arl_ill_init(arl, ill_name));
}

int
ip_sioctl_slifname_arp(queue_t *q, void *lifreq)
{
	arl_t *arl;
	struct lifreq *lifr = lifreq;

	/* ioctl not valid when IP opened as a device */
	if (q->q_next == NULL)
		return (EINVAL);

	arl = (arl_t *)q->q_ptr;
	arl->arl_ppa = lifr->lifr_ppa;
	return (arl_ill_init(arl, lifr->lifr_name));
}

arl_t *
ill_to_arl(ill_t *ill)
{
	arl_ill_common_t *ai = ill->ill_common;
	arl_t *arl = NULL;

	if (ai == NULL)
		return (NULL);
	/*
	 * Find the arl_t that corresponds to this ill_t from the shared
	 * ill_common structure. We can safely access the ai here as it
	 * will only be freed in arp_modclose() after we have become
	 * single-threaded.
	 */
	mutex_enter(&ai->ai_lock);
	if ((arl = ai->ai_arl) != NULL) {
		mutex_enter(&arl->arl_lock);
		if (!(arl->arl_state_flags & ARL_CONDEMNED)) {
			arl_refhold_locked(arl);
			mutex_exit(&arl->arl_lock);
		} else {
			mutex_exit(&arl->arl_lock);
			arl = NULL;
		}
	}
	mutex_exit(&ai->ai_lock);
	return (arl);
}

ill_t *
arl_to_ill(arl_t *arl)
{
	arl_ill_common_t *ai = arl->arl_common;
	ill_t *ill = NULL;

	if (ai == NULL) {
		/*
		 * happens when the arp stream is just being opened, and
		 * arl_ill_init has not been executed yet.
		 */
		return (NULL);
	}
	/*
	 * Find the ill_t that corresponds to this arl_t from the shared
	 * arl_common structure. We can safely access the ai here as it
	 * will only be freed in arp_modclose() after we have become
	 * single-threaded.
	 */
	mutex_enter(&ai->ai_lock);
	if ((ill = ai->ai_ill) != NULL) {
		mutex_enter(&ill->ill_lock);
		if (!ILL_IS_CONDEMNED(ill)) {
			ill_refhold_locked(ill);
			mutex_exit(&ill->ill_lock);
		} else {
			mutex_exit(&ill->ill_lock);
			ill = NULL;
		}
	}
	mutex_exit(&ai->ai_lock);
	return (ill);
}

int
arp_ll_up(ill_t *ill)
{
	mblk_t	*attach_mp = NULL;
	mblk_t	*bind_mp = NULL;
	mblk_t	*unbind_mp = NULL;
	arl_t 	*arl;

	ASSERT(IAM_WRITER_ILL(ill));
	arl = ill_to_arl(ill);

	DTRACE_PROBE2(ill__downup, char *, "arp_ll_up", ill_t *, ill);
	if (arl == NULL)
		return (ENXIO);
	DTRACE_PROBE2(arl__downup, char *, "arp_ll_up", arl_t *, arl);
	if ((arl->arl_state_flags & ARL_LL_UP) != 0) {
		arl_refrele(arl);
		return (0);
	}
	if (arl->arl_needs_attach) { /* DL_STYLE2 */
		attach_mp =
		    ip_ar_dlpi_comm(DL_ATTACH_REQ, sizeof (dl_attach_req_t));
		if (attach_mp == NULL)
			goto bad;
		((dl_attach_req_t *)attach_mp->b_rptr)->dl_ppa = arl->arl_ppa;
	}

	/* Allocate and initialize a bind message. */
	bind_mp = ip_ar_dlpi_comm(DL_BIND_REQ, sizeof (dl_bind_req_t));
	if (bind_mp == NULL)
		goto bad;
	((dl_bind_req_t *)bind_mp->b_rptr)->dl_sap = ETHERTYPE_ARP;
	((dl_bind_req_t *)bind_mp->b_rptr)->dl_service_mode = DL_CLDLS;

	unbind_mp = ip_ar_dlpi_comm(DL_UNBIND_REQ, sizeof (dl_unbind_req_t));
	if (unbind_mp == NULL)
		goto bad;
	if (arl->arl_needs_attach) {
		arp_dlpi_send(arl, attach_mp);
	}
	arl->arl_unbind_mp = unbind_mp;

	arl->arl_state_flags |= ARL_LL_BIND_PENDING;
	arp_dlpi_send(arl, bind_mp);
	arl_refrele(arl);
	return (EINPROGRESS);

bad:
	freemsg(attach_mp);
	freemsg(bind_mp);
	freemsg(unbind_mp);
	arl_refrele(arl);
	return (ENOMEM);
}

/*
 * consumes/frees mp
 */
static void
arp_notify(in_addr_t src, mblk_t *mp, uint32_t arcn_code,
    ip_recv_attr_t *ira, ncec_t *ncec)
{
	char		hbuf[MAC_STR_LEN];
	char		sbuf[INET_ADDRSTRLEN];
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	arh_t		*arh = (arh_t *)mp->b_rptr;

	switch (arcn_code) {
	case AR_CN_BOGON:
		/*
		 * Someone is sending ARP packets with a source protocol
		 * address that we have published and for which we believe our
		 * entry is authoritative and verified to be unique on
		 * the network.
		 *
		 * arp_process_packet() sends AR_CN_FAILED for the case when
		 * a DAD probe is received and the hardware address of a
		 * non-authoritative entry has changed. Thus, AR_CN_BOGON
		 * indicates a real conflict, and we have to do resolution.
		 *
		 * We back away quickly from the address if it's from DHCP or
		 * otherwise temporary and hasn't been used recently (or at
		 * all).  We'd like to include "deprecated" addresses here as
		 * well (as there's no real reason to defend something we're
		 * discarding), but IPMP "reuses" this flag to mean something
		 * other than the standard meaning.
		 */
		if (ip_nce_conflict(mp, ira, ncec)) {
			(void) mac_colon_addr((uint8_t *)(arh + 1),
			    arh->arh_hlen, hbuf, sizeof (hbuf));
			(void) ip_dot_addr(src, sbuf);
			cmn_err(CE_WARN,
			    "proxy ARP problem?  Node '%s' is using %s on %s",
			    hbuf, sbuf, ill->ill_name);
			if (!arp_no_defense)
				(void) arp_announce(ncec);
			/*
			 * ncec_last_time_defended has been adjusted in
			 * ip_nce_conflict.
			 */
		} else {
			ncec_delete(ncec);
		}
		freemsg(mp);
		break;
	case AR_CN_ANNOUNCE: {
		nce_hw_map_t hwm;
		/*
		 * ARP gives us a copy of any packet where it thinks
		 * the address has changed, so that we can update our
		 * caches.  We're responsible for caching known answers
		 * in the current design.  We check whether the
		 * hardware address really has changed in all of our
		 * entries that have cached this mapping, and if so, we
		 * blow them away.  This way we will immediately pick
		 * up the rare case of a host changing hardware
		 * address.
		 */
		if (src == 0) {
			freemsg(mp);
			break;
		}
		hwm.hwm_addr = src;
		hwm.hwm_hwlen = arh->arh_hlen;
		hwm.hwm_hwaddr = (uchar_t *)(arh + 1);
		hwm.hwm_flags = 0;
		ncec_walk_common(ipst->ips_ndp4, NULL,
		    (pfi_t)nce_update_hw_changed, &hwm, B_TRUE);
		freemsg(mp);
		break;
	}
	case AR_CN_FAILED:
		if (arp_no_defense) {
			(void) mac_colon_addr((uint8_t *)(arh + 1),
			    arh->arh_hlen, hbuf, sizeof (hbuf));
			(void) ip_dot_addr(src, sbuf);

			cmn_err(CE_WARN,
			    "node %s is using our IP address %s on %s",
			    hbuf, sbuf, ill->ill_name);
			freemsg(mp);
			break;
		}
		/*
		 * mp will be freed by arp_excl.
		 */
		ill_refhold(ill);
		qwriter_ip(ill, ill->ill_rq, mp, arp_excl, NEW_OP, B_FALSE);
		return;
	default:
		ASSERT(0);
		freemsg(mp);
		break;
	}
}

/*
 * arp_output is called to transmit an ARP Request or Response. The mapping
 * to RFC 826 variables is:
 *   haddr1 == ar$sha
 *   paddr1 == ar$spa
 *   haddr2 == ar$tha
 *   paddr2 == ar$tpa
 * The ARP frame is sent to the ether_dst in dst_lladdr.
 */
static int
arp_output(ill_t *ill, uint32_t operation,
    const uchar_t *haddr1, const uchar_t *paddr1, const uchar_t *haddr2,
    const uchar_t *paddr2, uchar_t *dst_lladdr)
{
	arh_t	*arh;
	uint8_t	*cp;
	uint_t	hlen;
	uint32_t plen = IPV4_ADDR_LEN; /* ar$pln from RFC 826 */
	uint32_t proto = IP_ARP_PROTO_TYPE;
	mblk_t *mp;
	arl_t *arl;

	ASSERT(dst_lladdr != NULL);
	hlen = ill->ill_phys_addr_length; /* ar$hln from RFC 826 */
	mp = ill_dlur_gen(dst_lladdr, hlen, ETHERTYPE_ARP, ill->ill_sap_length);

	if (mp == NULL)
		return (ENOMEM);

	/* IFF_NOARP flag is set or link down: do not send arp messages */
	if ((ill->ill_flags & ILLF_NOARP) || !ill->ill_dl_up) {
		freemsg(mp);
		return (ENXIO);
	}

	mp->b_cont = allocb(AR_LL_HDR_SLACK + ARH_FIXED_LEN + (hlen * 4) +
	    plen + plen, BPRI_MED);
	if (mp->b_cont == NULL) {
		freeb(mp);
		return (ENOMEM);
	}

	/* Fill in the ARP header. */
	cp = mp->b_cont->b_rptr + (AR_LL_HDR_SLACK + hlen + hlen);
	mp->b_cont->b_rptr = cp;
	arh = (arh_t *)cp;
	U16_TO_BE16(arp_hw_type(ill->ill_mactype), arh->arh_hardware);
	U16_TO_BE16(proto, arh->arh_proto);
	arh->arh_hlen = (uint8_t)hlen;
	arh->arh_plen = (uint8_t)plen;
	U16_TO_BE16(operation, arh->arh_operation);
	cp += ARH_FIXED_LEN;
	bcopy(haddr1, cp, hlen);
	cp += hlen;
	if (paddr1 == NULL)
		bzero(cp, plen);
	else
		bcopy(paddr1, cp, plen);
	cp += plen;
	if (haddr2 == NULL)
		bzero(cp, hlen);
	else
		bcopy(haddr2, cp, hlen);
	cp += hlen;
	bcopy(paddr2, cp, plen);
	cp += plen;
	mp->b_cont->b_wptr = cp;

	DTRACE_PROBE3(arp__physical__out__start,
	    ill_t *, ill, arh_t *, arh, mblk_t *, mp);
	ARP_HOOK_OUT(ill->ill_ipst->ips_arp_physical_out_event,
	    ill->ill_ipst->ips_arp_physical_out,
	    ill->ill_phyint->phyint_ifindex, arh, mp, mp->b_cont,
	    ill->ill_ipst);
	DTRACE_PROBE1(arp__physical__out__end, mblk_t *, mp);
	if (mp == NULL)
		return (0);

	/* Ship it out. */
	arl = ill_to_arl(ill);
	if (arl == NULL) {
		freemsg(mp);
		return (0);
	}
	if (canputnext(arl->arl_wq))
		putnext(arl->arl_wq, mp);
	else
		freemsg(mp);
	arl_refrele(arl);
	return (0);
}

/*
 * Process resolve requests.
 * If we are not yet reachable then we check and decrease ncec_rcnt; otherwise
 * we leave it alone (the caller will check and manage ncec_pcnt in those
 * cases.)
 */
int
arp_request(ncec_t *ncec, in_addr_t sender, ill_t *ill)
{
	int err;
	const uchar_t *target_hwaddr;
	struct in_addr nce_paddr;
	uchar_t *dst_lladdr;
	boolean_t use_rcnt = !NCE_ISREACHABLE(ncec);

	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	ASSERT(!IS_IPMP(ill));

	if (use_rcnt && ncec->ncec_rcnt == 0) {
		/* not allowed any more retransmits. */
		return (0);
	}

	if ((ill->ill_flags & ILLF_NOARP) != 0)
		return (0);

	IN6_V4MAPPED_TO_INADDR(&ncec->ncec_addr, &nce_paddr);

	target_hwaddr =
	    ill->ill_bcast_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill);

	if (NCE_ISREACHABLE(ncec)) {
		dst_lladdr =  ncec->ncec_lladdr;
	} else {
		dst_lladdr =  ill->ill_bcast_mp->b_rptr +
		    NCE_LL_ADDR_OFFSET(ill);
	}

	mutex_exit(&ncec->ncec_lock);
	err = arp_output(ill, ARP_REQUEST,
	    ill->ill_phys_addr, (uchar_t *)&sender, target_hwaddr,
	    (uchar_t *)&nce_paddr, dst_lladdr);
	mutex_enter(&ncec->ncec_lock);

	if (err != 0) {
		/*
		 * Some transient error such as ENOMEM or a down link was
		 * encountered. If the link has been taken down permanently,
		 * the ncec will eventually be cleaned up (ipif_down_tail()
		 * will call ipif_nce_down() and flush the ncec), to terminate
		 * recurring attempts to send ARP requests. In all other cases,
		 * allow the caller another chance at success next time.
		 */
		return (ncec->ncec_ill->ill_reachable_retrans_time);
	}

	if (use_rcnt)
		ncec->ncec_rcnt--;

	return (ncec->ncec_ill->ill_reachable_retrans_time);
}

/* return B_TRUE if dropped */
boolean_t
arp_announce(ncec_t *ncec)
{
	ill_t *ill;
	int err;
	uchar_t *sphys_addr, *bcast_addr;
	struct in_addr ncec_addr;
	boolean_t need_refrele = B_FALSE;

	ASSERT((ncec->ncec_flags & NCE_F_BCAST) == 0);
	ASSERT((ncec->ncec_flags & NCE_F_MCAST) == 0);

	if (IS_IPMP(ncec->ncec_ill)) {
		/* sent on the cast_ill */
		ill = ipmp_ill_hold_xmit_ill(ncec->ncec_ill, B_FALSE);
		if (ill == NULL)
			return (B_TRUE);
		need_refrele = B_TRUE;
	} else {
		ill = ncec->ncec_ill;
	}

	/*
	 * broadcast an announce to ill_bcast address.
	 */
	IN6_V4MAPPED_TO_INADDR(&ncec->ncec_addr, &ncec_addr);

	sphys_addr = ncec->ncec_lladdr;
	bcast_addr = ill->ill_bcast_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill);

	err = arp_output(ill, ARP_REQUEST,
	    sphys_addr, (uchar_t *)&ncec_addr, bcast_addr,
	    (uchar_t *)&ncec_addr, bcast_addr);

	if (need_refrele)
		ill_refrele(ill);
	return (err != 0);
}

/* return B_TRUE if dropped */
boolean_t
arp_probe(ncec_t *ncec)
{
	ill_t *ill;
	int err;
	struct in_addr ncec_addr;
	uchar_t *sphys_addr, *dst_lladdr;

	if (IS_IPMP(ncec->ncec_ill)) {
		ill = ipmp_ill_hold_xmit_ill(ncec->ncec_ill, B_FALSE);
		if (ill == NULL)
			return (B_TRUE);
	} else {
		ill = ncec->ncec_ill;
	}

	IN6_V4MAPPED_TO_INADDR(&ncec->ncec_addr, &ncec_addr);

	sphys_addr = ncec->ncec_lladdr;
	dst_lladdr = ill->ill_bcast_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill);
	err = arp_output(ill, ARP_REQUEST,
	    sphys_addr, NULL, NULL, (uchar_t *)&ncec_addr, dst_lladdr);

	if (IS_IPMP(ncec->ncec_ill))
		ill_refrele(ill);
	return (err != 0);
}

static mblk_t *
arl_unbind(arl_t *arl)
{
	mblk_t *mp;

	if ((mp = arl->arl_unbind_mp) != NULL) {
		arl->arl_unbind_mp = NULL;
		arl->arl_state_flags |= ARL_DL_UNBIND_IN_PROGRESS;
	}
	return (mp);
}

int
arp_ll_down(ill_t *ill)
{
	arl_t 	*arl;
	mblk_t *unbind_mp;
	int err = 0;
	boolean_t replumb = (ill->ill_replumbing == 1);

	DTRACE_PROBE2(ill__downup, char *, "arp_ll_down", ill_t *, ill);
	if ((arl = ill_to_arl(ill)) == NULL)
		return (ENXIO);
	DTRACE_PROBE2(arl__downup, char *, "arp_ll_down", arl_t *, arl);
	mutex_enter(&arl->arl_lock);
	unbind_mp = arl_unbind(arl);
	if (unbind_mp != NULL) {
		ASSERT(arl->arl_state_flags & ARL_DL_UNBIND_IN_PROGRESS);
		DTRACE_PROBE2(arp__unbinding, mblk_t *, unbind_mp,
		    arl_t *, arl);
		err = EINPROGRESS;
		if (replumb)
			arl->arl_state_flags |= ARL_LL_REPLUMBING;
	}
	mutex_exit(&arl->arl_lock);
	if (unbind_mp != NULL)
		arp_dlpi_send(arl, unbind_mp);
	arl_refrele(arl);
	return (err);
}

/* ARGSUSED */
int
arp_close(queue_t *q, int flags)
{
	if (WR(q)->q_next != NULL) {
		/* This is a module close */
		return (arp_modclose(q->q_ptr));
	}
	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

static int
arp_modclose(arl_t *arl)
{
	arl_ill_common_t *ai = arl->arl_common;
	ill_t		*ill;
	queue_t		*q = arl->arl_rq;
	mblk_t		*mp, *nextmp;
	ipsq_t		*ipsq = NULL;

	ill = arl_to_ill(arl);
	if (ill != NULL) {
		if (!ill_waiter_inc(ill)) {
			ill_refrele(ill);
		} else {
			ill_refrele(ill);
			if (ipsq_enter(ill, B_FALSE, NEW_OP))
				ipsq = ill->ill_phyint->phyint_ipsq;
			ill_waiter_dcr(ill);
		}
		if (ipsq == NULL) {
			/*
			 * could not enter the ipsq because ill is already
			 * marked CONDEMNED.
			 */
			ill = NULL;
		}
	}
	if (ai != NULL && ipsq == NULL) {
		/*
		 * Either we did not get an ill because it was marked CONDEMNED
		 * or we could not enter the ipsq because it was unplumbing.
		 * In both cases, wait for the ill to complete ip_modclose().
		 *
		 * If the arp_modclose happened even before SLIFNAME, the ai
		 * itself would be NULL, in which case we can complete the close
		 * without waiting.
		 */
		mutex_enter(&ai->ai_lock);
		while (ai->ai_ill != NULL)
			cv_wait(&ai->ai_ill_unplumb_done, &ai->ai_lock);
		mutex_exit(&ai->ai_lock);
	}
	ASSERT(ill == NULL || IAM_WRITER_ILL(ill));

	mutex_enter(&arl->arl_lock);
	/*
	 * If the ill had completed unplumbing before arp_modclose(), there
	 * would be no ill (and therefore, no ipsq) to serialize arp_modclose()
	 * so that we need to explicitly check for ARL_CONDEMNED and back off
	 * if it is set.
	 */
	if ((arl->arl_state_flags & ARL_CONDEMNED) != 0) {
		mutex_exit(&arl->arl_lock);
		ASSERT(ipsq == NULL);
		return (0);
	}
	arl->arl_state_flags |= ARL_CONDEMNED;

	/*
	 * send out all pending dlpi messages, don't wait for the ack (which
	 * will be ignored in arp_rput when CONDEMNED is set)
	 *
	 * We have to check for pending DL_UNBIND_REQ because, in the case
	 * that ip_modclose() executed before arp_modclose(), the call to
	 * ill_delete_tail->ipif_arp_down() would have triggered a
	 * DL_UNBIND_REQ. When arp_modclose() executes ipsq_enter() will fail
	 * (since ip_modclose() is in the ipsq) but the DL_UNBIND_ACK may not
	 * have been processed yet. In this scenario, we cannot reset
	 * arl_dlpi_pending, because the setting/clearing of arl_state_flags
	 * related to unbind, and the associated cv_waits must be allowed to
	 * continue.
	 */
	if (arl->arl_dlpi_pending != DL_UNBIND_REQ)
		arl->arl_dlpi_pending = DL_PRIM_INVAL;
	mp = arl->arl_dlpi_deferred;
	arl->arl_dlpi_deferred = NULL;
	mutex_exit(&arl->arl_lock);

	for (; mp != NULL; mp = nextmp) {
		nextmp = mp->b_next;
		mp->b_next = NULL;
		putnext(arl->arl_wq, mp);
	}

	/* Wait for data paths to quiesce */
	mutex_enter(&arl->arl_lock);
	while (arl->arl_refcnt != 0)
		cv_wait(&arl->arl_cv, &arl->arl_lock);

	/*
	 * unbind, so that nothing else can come up from driver.
	 */
	mp = arl_unbind(arl);
	mutex_exit(&arl->arl_lock);
	if (mp != NULL)
		arp_dlpi_send(arl, mp);
	mutex_enter(&arl->arl_lock);

	/* wait for unbind ack  */
	while (arl->arl_state_flags & ARL_DL_UNBIND_IN_PROGRESS)
		cv_wait(&arl->arl_cv, &arl->arl_lock);
	mutex_exit(&arl->arl_lock);

	qprocsoff(q);

	if (ill != NULL) {
		mutex_enter(&ill->ill_lock);
		ill->ill_arl_dlpi_pending = 0;
		mutex_exit(&ill->ill_lock);
	}

	if (ai != NULL) {
		mutex_enter(&ai->ai_lock);
		ai->ai_arl = NULL;
		if (ai->ai_ill == NULL) {
			mutex_destroy(&ai->ai_lock);
			kmem_free(ai, sizeof (*ai));
		} else {
			mutex_exit(&ai->ai_lock);
		}
	}

	/* free up the rest */
	arp_mod_close_tail(arl);

	q->q_ptr = WR(q)->q_ptr = NULL;

	if (ipsq != NULL)
		ipsq_exit(ipsq);

	return (0);
}

static void
arp_mod_close_tail(arl_t *arl)
{
	ip_stack_t	*ipst = arl->arl_ipst;
	mblk_t		**mpp;

	mutex_enter(&ipst->ips_ip_mi_lock);
	mi_close_unlink(&ipst->ips_arp_g_head, (IDP)arl);
	mutex_exit(&ipst->ips_ip_mi_lock);

	/*
	 * credp could be null if the open didn't succeed and ip_modopen
	 * itself calls ip_close.
	 */
	if (arl->arl_credp != NULL)
		crfree(arl->arl_credp);

	/* Free all retained control messages. */
	mpp = &arl->arl_first_mp_to_free;
	do {
		while (mpp[0]) {
			mblk_t  *mp;
			mblk_t  *mp1;

			mp = mpp[0];
			mpp[0] = mp->b_next;
			for (mp1 = mp; mp1 != NULL; mp1 = mp1->b_cont) {
				mp1->b_next = NULL;
				mp1->b_prev = NULL;
			}
			freemsg(mp);
		}
	} while (mpp++ != &arl->arl_last_mp_to_free);

	netstack_rele(ipst->ips_netstack);
	mi_free(arl->arl_name);
	mi_close_free((IDP)arl);
}

/*
 * DAD failed. Tear down ipifs with the specified srce address. Note that
 * tearing down the ipif also meas deleting the ncec through ipif_down,
 * so it is not possible to use nce_timer for recovery. Instead we start
 * a timer on the ipif. Caller has to free the mp.
 */
void
arp_failure(mblk_t *mp, ip_recv_attr_t *ira)
{
	ill_t *ill = ira->ira_ill;

	if ((mp = copymsg(mp)) != NULL) {
		ill_refhold(ill);
		qwriter_ip(ill, ill->ill_rq, mp, arp_excl, NEW_OP, B_FALSE);
	}
}

/*
 * This is for exclusive changes due to ARP.  Tear down an interface due
 * to AR_CN_FAILED and AR_CN_BOGON.
 */
/* ARGSUSED */
static void
arp_excl(ipsq_t *ipsq, queue_t *rq, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = rq->q_ptr;
	arh_t *arh;
	ipaddr_t src;
	ipif_t	*ipif;
	ip_stack_t *ipst = ill->ill_ipst;
	uchar_t	*haddr;
	uint_t	haddrlen;

	/* first try src = ar$spa */
	arh = (arh_t *)mp->b_rptr;
	bcopy((char *)&arh[1] + arh->arh_hlen, &src, IP_ADDR_LEN);

	haddrlen = arh->arh_hlen;
	haddr = (uint8_t *)(arh + 1);

	if (haddrlen == ill->ill_phys_addr_length) {
		/*
		 * Ignore conflicts generated by misbehaving switches that
		 * just reflect our own messages back to us.  For IPMP, we may
		 * see reflections across any ill in the illgrp.
		 */
		/* For an under ill_grp can change under lock */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (bcmp(haddr, ill->ill_phys_addr, haddrlen) == 0 ||
		    IS_UNDER_IPMP(ill) && ill->ill_grp != NULL &&
		    ipmp_illgrp_find_ill(ill->ill_grp, haddr,
		    haddrlen) != NULL) {
			rw_exit(&ipst->ips_ill_g_lock);
			goto ignore_conflict;
		}
		rw_exit(&ipst->ips_ill_g_lock);
	}

	/*
	 * Look up the appropriate ipif.
	 */
	ipif = ipif_lookup_addr(src, ill, ALL_ZONES, ipst);
	if (ipif == NULL)
		goto ignore_conflict;

	/* Reload the ill to match the ipif */
	ill = ipif->ipif_ill;

	/* If it's already duplicate or ineligible, then don't do anything. */
	if (ipif->ipif_flags & (IPIF_POINTOPOINT|IPIF_DUPLICATE)) {
		ipif_refrele(ipif);
		goto ignore_conflict;
	}

	/*
	 * If we failed on a recovery probe, then restart the timer to
	 * try again later.
	 */
	if (!ipif->ipif_was_dup) {
		char hbuf[MAC_STR_LEN];
		char sbuf[INET_ADDRSTRLEN];
		char ibuf[LIFNAMSIZ];

		(void) mac_colon_addr(haddr, haddrlen, hbuf, sizeof (hbuf));
		(void) ip_dot_addr(src, sbuf);
		ipif_get_name(ipif, ibuf, sizeof (ibuf));

		cmn_err(CE_WARN, "%s has duplicate address %s (in use by %s);"
		    " disabled", ibuf, sbuf, hbuf);
	}
	mutex_enter(&ill->ill_lock);
	ASSERT(!(ipif->ipif_flags & IPIF_DUPLICATE));
	ipif->ipif_flags |= IPIF_DUPLICATE;
	ill->ill_ipif_dup_count++;
	mutex_exit(&ill->ill_lock);
	(void) ipif_down(ipif, NULL, NULL);
	(void) ipif_down_tail(ipif);
	mutex_enter(&ill->ill_lock);
	if (!(ipif->ipif_flags & (IPIF_DHCPRUNNING|IPIF_TEMPORARY)) &&
	    ill->ill_net_type == IRE_IF_RESOLVER &&
	    !(ipif->ipif_state_flags & IPIF_CONDEMNED) &&
	    ipst->ips_ip_dup_recovery > 0) {
		ASSERT(ipif->ipif_recovery_id == 0);
		ipif->ipif_recovery_id = timeout(ipif_dup_recovery,
		    ipif, MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
	}
	mutex_exit(&ill->ill_lock);
	ipif_refrele(ipif);

ignore_conflict:
	freemsg(mp);
}

/*
 * This is a place for a dtrace hook.
 * Note that mp can be either the DL_UNITDATA_IND with a b_cont payload,
 * or just the ARP packet payload as an M_DATA.
 */
/* ARGSUSED */
static void
arp_drop_packet(const char *str, mblk_t *mp, ill_t *ill)
{
	freemsg(mp);
}

static boolean_t
arp_over_driver(queue_t *q)
{
	queue_t *qnext = STREAM(q)->sd_wrq->q_next;

	/*
	 * check if first module below stream head is IP or UDP.
	 */
	ASSERT(qnext != NULL);
	if (strcmp(Q2NAME(qnext), "ip") != 0 &&
	    strcmp(Q2NAME(qnext), "udp") != 0) {
		/*
		 * module below is not ip or udp, so arp has been pushed
		 * on the driver.
		 */
		return (B_TRUE);
	}
	return (B_FALSE);
}

static int
arp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int err;

	ASSERT(sflag & MODOPEN);
	if (!arp_over_driver(q)) {
		q->q_qinfo = dummymodinfo.st_rdinit;
		WR(q)->q_qinfo = dummymodinfo.st_wrinit;
		return ((*dummymodinfo.st_rdinit->qi_qopen)(q, devp, flag,
		    sflag, credp));
	}
	err = arp_modopen(q, devp, flag, sflag, credp);
	return (err);
}

/*
 * In most cases we must be a writer on the IP stream before coming to
 * arp_dlpi_send(), to serialize DLPI sends to the driver. The exceptions
 * when we are not a writer are very early duing initialization (in
 * arl_init, before the arl has done a SLIFNAME, so that we don't yet know
 * the associated ill) or during arp_mod_close, when we could not enter the
 * ipsq because the ill has already unplumbed.
 */
static void
arp_dlpi_send(arl_t *arl, mblk_t *mp)
{
	mblk_t **mpp;
	t_uscalar_t prim;
	arl_ill_common_t *ai;

	ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);

#ifdef DEBUG
	ai = arl->arl_common;
	if (ai != NULL) {
		mutex_enter(&ai->ai_lock);
		if (ai->ai_ill != NULL)
			ASSERT(IAM_WRITER_ILL(ai->ai_ill));
		mutex_exit(&ai->ai_lock);
	}
#endif /* DEBUG */

	mutex_enter(&arl->arl_lock);
	if (arl->arl_dlpi_pending != DL_PRIM_INVAL) {
		/* Must queue message. Tail insertion */
		mpp = &arl->arl_dlpi_deferred;
		while (*mpp != NULL)
			mpp = &((*mpp)->b_next);

		*mpp = mp;
		mutex_exit(&arl->arl_lock);
		return;
	}
	mutex_exit(&arl->arl_lock);
	if ((prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive)
	    == DL_BIND_REQ) {
		ASSERT((arl->arl_state_flags & ARL_DL_UNBIND_IN_PROGRESS) == 0);
	}
	/*
	 * No need to take the arl_lock to examine ARL_CONDEMNED at this point
	 * because the only thread that can see ARL_CONDEMNED here is the
	 * closing arp_modclose() thread which sets the flag after becoming a
	 * writer on the ipsq. Threads from IP must have finished and
	 * cannot be active now.
	 */
	if (!(arl->arl_state_flags & ARL_CONDEMNED) ||
	    (prim == DL_UNBIND_REQ)) {
		if (prim != DL_NOTIFY_CONF) {
			ill_t *ill = arl_to_ill(arl);

			arl->arl_dlpi_pending = prim;
			if (ill != NULL) {
				mutex_enter(&ill->ill_lock);
				ill->ill_arl_dlpi_pending = 1;
				mutex_exit(&ill->ill_lock);
				ill_refrele(ill);
			}
		}
	}
	DTRACE_PROBE4(arl__dlpi, char *, "arp_dlpi_send",
	    char *, dl_primstr(prim), char *, "-",  arl_t *, arl);
	putnext(arl->arl_wq, mp);
}

static void
arl_defaults_common(arl_t *arl, mblk_t *mp)
{
	dl_info_ack_t	*dlia = (dl_info_ack_t *)mp->b_rptr;
	/*
	 * Till the ill is fully up  the ill is not globally visible.
	 * So no need for a lock.
	 */
	arl->arl_mactype = dlia->dl_mac_type;
	arl->arl_sap_length = dlia->dl_sap_length;

	if (!arl->arl_dlpi_style_set) {
		if (dlia->dl_provider_style == DL_STYLE2)
			arl->arl_needs_attach = 1;
		mutex_enter(&arl->arl_lock);
		ASSERT(arl->arl_dlpi_style_set == 0);
		arl->arl_dlpi_style_set = 1;
		arl->arl_state_flags &= ~ARL_LL_SUBNET_PENDING;
		cv_broadcast(&arl->arl_cv);
		mutex_exit(&arl->arl_lock);
	}
}

int
arl_init(queue_t *q, arl_t *arl)
{
	mblk_t *info_mp;
	dl_info_req_t   *dlir;

	/* subset of ill_init */
	mutex_init(&arl->arl_lock, NULL, MUTEX_DEFAULT, 0);

	arl->arl_rq = q;
	arl->arl_wq = WR(q);

	info_mp = allocb(MAX(sizeof (dl_info_req_t), sizeof (dl_info_ack_t)),
	    BPRI_HI);
	if (info_mp == NULL)
		return (ENOMEM);
	/*
	 * allocate sufficient space to contain device name.
	 */
	arl->arl_name = (char *)(mi_zalloc(2 * LIFNAMSIZ));
	arl->arl_ppa = UINT_MAX;
	arl->arl_state_flags |= (ARL_LL_SUBNET_PENDING | ARL_LL_UNBOUND);

	/* Send down the Info Request to the driver. */
	info_mp->b_datap->db_type = M_PCPROTO;
	dlir = (dl_info_req_t *)info_mp->b_rptr;
	info_mp->b_wptr = (uchar_t *)&dlir[1];
	dlir->dl_primitive = DL_INFO_REQ;
	arl->arl_dlpi_pending = DL_PRIM_INVAL;
	qprocson(q);

	arp_dlpi_send(arl, info_mp);
	return (0);
}

int
arl_wait_for_info_ack(arl_t *arl)
{
	int err;

	mutex_enter(&arl->arl_lock);
	while (arl->arl_state_flags & ARL_LL_SUBNET_PENDING) {
		/*
		 * Return value of 0 indicates a pending signal.
		 */
		err = cv_wait_sig(&arl->arl_cv, &arl->arl_lock);
		if (err == 0) {
			mutex_exit(&arl->arl_lock);
			return (EINTR);
		}
	}
	mutex_exit(&arl->arl_lock);
	/*
	 * ip_rput_other could have set an error  in ill_error on
	 * receipt of M_ERROR.
	 */
	return (arl->arl_error);
}

void
arl_set_muxid(ill_t *ill, int muxid)
{
	arl_t *arl;

	arl = ill_to_arl(ill);
	if (arl != NULL) {
		arl->arl_muxid = muxid;
		arl_refrele(arl);
	}
}

int
arl_get_muxid(ill_t *ill)
{
	arl_t *arl;
	int muxid = 0;

	arl = ill_to_arl(ill);
	if (arl != NULL) {
		muxid = arl->arl_muxid;
		arl_refrele(arl);
	}
	return (muxid);
}

static int
arp_modopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int	err;
	zoneid_t zoneid;
	netstack_t *ns;
	ip_stack_t *ipst;
	arl_t	*arl = NULL;

	/*
	 * Prevent unprivileged processes from pushing IP so that
	 * they can't send raw IP.
	 */
	if (secpolicy_net_rawaccess(credp) != 0)
		return (EPERM);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	ipst = ns->netstack_ip;
	ASSERT(ipst != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make IP operate as if in the global zone.
	 */
	if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	arl = (arl_t *)mi_open_alloc_sleep(sizeof (arl_t));
	q->q_ptr = WR(q)->q_ptr = arl;
	arl->arl_ipst = ipst;
	arl->arl_zoneid = zoneid;
	err = arl_init(q, arl);

	if (err != 0) {
		mi_free(arl->arl_name);
		mi_free(arl);
		netstack_rele(ipst->ips_netstack);
		q->q_ptr = NULL;
		WR(q)->q_ptr = NULL;
		return (err);
	}

	/*
	 * Wait for the DL_INFO_ACK if a DL_INFO_REQ was sent.
	 */
	err = arl_wait_for_info_ack(arl);
	if (err == 0)
		arl->arl_credp = credp;
	else
		goto fail;

	crhold(credp);

	mutex_enter(&ipst->ips_ip_mi_lock);
	err = mi_open_link(&ipst->ips_arp_g_head, (IDP)q->q_ptr, devp, flag,
	    sflag, credp);
	mutex_exit(&ipst->ips_ip_mi_lock);
fail:
	if (err) {
		(void) arp_close(q, 0);
		return (err);
	}
	return (0);
}

/*
 * Notify any downstream modules (esp softmac and hitbox) of the name
 * of this interface using an M_CTL.
 */
static void
arp_ifname_notify(arl_t *arl)
{
	mblk_t *mp1, *mp2;
	struct iocblk *iocp;
	struct lifreq *lifr;

	if ((mp1 = mkiocb(SIOCSLIFNAME)) == NULL)
		return;
	if ((mp2 = allocb(sizeof (struct lifreq), BPRI_HI)) == NULL) {
		freemsg(mp1);
		return;
	}

	lifr = (struct lifreq *)mp2->b_rptr;
	mp2->b_wptr += sizeof (struct lifreq);
	bzero(lifr, sizeof (struct lifreq));

	(void) strncpy(lifr->lifr_name, arl->arl_name, LIFNAMSIZ);
	lifr->lifr_ppa = arl->arl_ppa;
	lifr->lifr_flags = ILLF_IPV4;

	/* Use M_CTL to avoid confusing anyone else who might be listening. */
	DB_TYPE(mp1) = M_CTL;
	mp1->b_cont = mp2;
	iocp = (struct iocblk *)mp1->b_rptr;
	iocp->ioc_count = msgsize(mp1->b_cont);
	DTRACE_PROBE4(arl__dlpi, char *, "arp_ifname_notify",
	    char *, "SIOCSLIFNAME", char *, "-",  arl_t *, arl);
	putnext(arl->arl_wq, mp1);
}

void
arp_send_replumb_conf(ill_t *ill)
{
	mblk_t *mp;
	arl_t *arl = ill_to_arl(ill);

	if (arl == NULL)
		return;
	/*
	 * arl_got_replumb and arl_got_unbind to be cleared after we complete
	 * arp_cmd_done.
	 */
	mp = mexchange(NULL, NULL, sizeof (dl_notify_conf_t), M_PROTO,
	    DL_NOTIFY_CONF);
	((dl_notify_conf_t *)(mp->b_rptr))->dl_notification =
	    DL_NOTE_REPLUMB_DONE;
	arp_dlpi_send(arl, mp);
	mutex_enter(&arl->arl_lock);
	arl->arl_state_flags &= ~ARL_LL_REPLUMBING;
	mutex_exit(&arl->arl_lock);
	arl_refrele(arl);
}

/*
 * The unplumb code paths call arp_unbind_complete() to make sure that it is
 * safe to tear down the ill. We wait for DL_UNBIND_ACK to complete, and also
 * for the arl_refcnt to fall to one so that, when we return from
 * arp_unbind_complete(), we know for certain that there are no threads in
 * arp_rput() that might access the arl_ill.
 */
void
arp_unbind_complete(ill_t *ill)
{
	arl_t *arl = ill_to_arl(ill);

	if (arl == NULL)
		return;
	mutex_enter(&arl->arl_lock);
	/*
	 * wait for unbind ack and arl_refcnt to drop to 1. Note that the
	 * quiescent arl_refcnt for this function is 1 (and not 0) because
	 * ill_to_arl() will itself return after taking a ref on the arl_t.
	 */
	while (arl->arl_state_flags & ARL_DL_UNBIND_IN_PROGRESS)
		cv_wait(&arl->arl_cv, &arl->arl_lock);
	while (arl->arl_refcnt != 1)
		cv_wait(&arl->arl_cv, &arl->arl_lock);
	mutex_exit(&arl->arl_lock);
	arl_refrele(arl);
}
