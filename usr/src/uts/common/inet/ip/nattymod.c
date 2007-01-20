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
 * Required include files.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/tihdr.h>
#include <sys/zone.h>
#include <sys/tpicommon.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <net/pfkeyv2.h>
#include <inet/sadb.h>
#include <inet/ip_ire.h>
#include <sys/cmn_err.h>
#include <inet/udp_impl.h>
#include <inet/ipsec_impl.h>
#include <inet/ipdrop.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>

/*
 * Design notes:
 *
 * - We assume that we're pushed on to a UDP instance that's bound to
 *   <addr>/4500.  (This is done in in.iked.)
 * - We assume that <addr> will not change on this instance.
 * - With those two assumptions, we can make the following assertions:
 *   + We can cache not only the IRE, but also the address that we look
 *     up for the IRE.
 * - We otherwise cache the ire in a manner similar to the conn_t structure
 *   in the main portions of TCP and IP.
 */

/* Structures. */
typedef struct nattyinfo
{
	struct nattyinfo **ni_ptpn; /* These two protected by nattyhlock. */
	struct nattyinfo *ni_next;
	kmutex_t ni_lock;	/* Lock for this instance. */
	ire_t *ni_ire;		/* Cached ire for looping back packets. */
	queue_t *ni_fbqueue;	/* Ire receive-from queue for feedback. */
	ipaddr_t ni_addr;	/* Addr for ire re-lookups. */
	boolean_t ni_setup_done; /* done with setup */
	boolean_t ni_rh_wait;	/* Seen UDP_RCVHDR request go by */
	boolean_t ni_rh_set;	/* Have we set UDP_RCVHDR? */
	boolean_t ni_addr_wait;	/* Seen T_ADDR_REQ go by */
	netstack_t *ni_netstack;
} nattyinfo_t;

kmutex_t nattyhlock;	/* List lock. */
nattyinfo_t *nattyhead;	/* List of instances. */


/*
 * Function prototypes.
 */

static int nattymodopen(queue_t *, dev_t *, int, int, cred_t *);
static int	nattymodclose(queue_t *);
static void natty_ka_timeout_callback(void *v_sa);
static void natty_rput(queue_t *q, mblk_t *mp);
static void natty_rput_other(queue_t *q, mblk_t *mp);
static void natty_rput_pkt(queue_t *q, mblk_t *mp);
static void natty_wput(queue_t *q, mblk_t *mp);

/*
 * Module linkage data
 */
static struct module_info	nattymod_minfo = {
	1970,		/* mi_idnum */
	"nattymod",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	0,		/* mi_hiwat */
	0		/* mi_lowat */
};

static struct qinit	nattymod_rinit = {
	(int (*)())natty_rput,	/* qi_putp */
	NULL,		/* qi_srvp  */
	nattymodopen,	/* qi_qopen */
	nattymodclose,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&nattymod_minfo,	/* qi_minfo */
};

/*
 * We don't worry much about the write-side here (except for the qtimeouts
 * that send keepalives.  Just putnext() and life is good.  We only care about
 * inbound packets.
 */
static struct qinit	nattymod_winit = {
	(int (*)())natty_wput,	/* qi_putp */
	NULL,		/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&nattymod_minfo,	/* qi_minfo */
};

static struct streamtab	nattymod_info = {
	&nattymod_rinit,	/* st_rdinit */
	&nattymod_winit,	/* st_wrinit */
};

static struct fmodsw fsw = {
	"nattymod",
	&nattymod_info,
	D_MP | D_MTQPAIR | D_MTPUTSHARED
};

/*
 * Module linkage information for the kernel.
 */
struct mod_ops mod_strmodops;

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "Nat-t module ver %I%", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlstrmod, NULL
};


clock_t natty_ka_timeout = 0;

/*
 * Standard module entry points.
 */
int
_init(void)
{
	int error;

	natty_ka_timeout = drv_usectohz(20 * 1000000);
	mutex_init(&nattyhlock, NULL, MUTEX_DEFAULT, NULL);
	error = mod_install(&modlinkage);
	if (error != 0)
		mutex_destroy(&nattyhlock);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);

	if (error == 0)
		mutex_destroy(&nattyhlock);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/* ARGSUSED */
static int
nattymodopen(queue_t *rq, dev_t *dev, int oflag, int sflag, cred_t *credp)
{
	nattyinfo_t *ni;
	netstack_t *ns;

	if (sflag != MODOPEN)
		return (EINVAL);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);

	/* Use kmem_zalloc() to avoid initializing ni->* fields. */
	ni = kmem_zalloc(sizeof (nattyinfo_t), KM_SLEEP);
	mutex_init(&ni->ni_lock, NULL, MUTEX_DEFAULT, NULL);

	rq->q_ptr = ni;
	WR(rq)->q_ptr = ni;

	/* Insert into list before packets are allowed to flow. */
	mutex_enter(&nattyhlock);
	ni->ni_ptpn = &nattyhead;
	if (nattyhead != NULL)
		nattyhead->ni_ptpn = &ni->ni_next;
	ni->ni_next = nattyhead;
	nattyhead = ni;
	ni->ni_netstack = ns;
	mutex_exit(&nattyhlock);

	qprocson(rq);

	return (0);
}

static int
nattymodclose(queue_t *rq)
{
	nattyinfo_t *ni = (nattyinfo_t *)rq->q_ptr;

	/* Unlink from list. */
	mutex_enter(&nattyhlock);
	*(ni->ni_ptpn) = ni->ni_next;
	if (ni->ni_next != NULL)
		ni->ni_next->ni_ptpn = ni->ni_ptpn;
	mutex_exit(&nattyhlock);

	sadb_clear_timeouts(WR(rq), ni->ni_netstack);

	netstack_rele(ni->ni_netstack);
	qprocsoff(rq);

	/* Unlinked from list means ==> no need to mutex. */
	if (ni->ni_ire != NULL) {
		IRE_REFRELE_NOTR(ni->ni_ire);
	}

	mutex_destroy(&ni->ni_lock);
	kmem_free(ni, sizeof (*ni));
	rq->q_ptr = NULL;
	WR(rq)->q_ptr = NULL;


	return (0);
}

static ipaddr_t
addr_from_mblk(mblk_t *mp)
{
	struct T_addr_ack *taa;
	sin_t *sin;
	sin6_t *sin6;
	ipaddr_t addr = (ipaddr_t)-1;

	taa = (struct T_addr_ack *)mp->b_rptr;

	if (MBLKL(mp) >= sizeof (*taa) &&
	    mp->b_wptr >= (mp->b_rptr + taa->LOCADDR_offset + sizeof (*sin))) {
		sin = (sin_t *)(mp->b_rptr + taa->LOCADDR_offset);
		if (IS_P2ALIGNED(sin, sizeof (uint32_t))) {
			if (sin->sin_family == AF_INET) {
				addr = sin->sin_addr.s_addr;
			} else if (sin->sin_family == AF_INET6 &&
			    mp->b_wptr >= (mp->b_rptr +
				taa->LOCADDR_offset + sizeof (*sin))) {
				sin6 = (sin6_t *)sin;
				ASSERT(sin6->sin6_family == AF_INET6);
				if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
					IN6_V4MAPPED_TO_IPADDR(
					    &sin6->sin6_addr, addr);
			}
		}
	}

	return (addr);
}

static void
get_my_ire(nattyinfo_t *ni, ipaddr_t addr)
{
	ire_t *ire;
	uint8_t *bytes;
	boolean_t cached;

	mutex_enter(&ni->ni_lock);
	if (ni->ni_ire != NULL) {
		/* I lost the race. */
		mutex_exit(&ni->ni_lock);
		return;
	}

	if (addr == (ipaddr_t)0 || addr == (ipaddr_t)-1)
		goto bail;

	ni->ni_addr = addr;

	ire = ire_ctable_lookup(addr, 0, IRE_LOCAL, NULL, ALL_ZONES, NULL,
	    MATCH_IRE_TYPE, ni->ni_netstack->netstack_ip);
	if (ire == NULL)
		goto bail;

	rw_enter(&ire->ire_bucket->irb_lock, RW_READER);
	if (!(ire->ire_marks & IRE_MARK_CONDEMNED)) {
		ni->ni_ire = ire;
		ni->ni_fbqueue = ire->ire_rfq;
		cached = B_TRUE;
	} else {
		cached = B_FALSE;
	}
	rw_exit(&ire->ire_bucket->irb_lock);

	if (!cached) {
		ASSERT(ni->ni_ire == NULL);
		ASSERT(ni->ni_fbqueue == NULL);
		IRE_REFRELE(ire);
	} else {
		IRE_UNTRACE_REF(ire);
	}

	mutex_exit(&ni->ni_lock);
	return;
bail:
	/* Error getting address or ire.  Make nattyinfo null and void. */
	bytes = (uint8_t *)&addr;
	cmn_err(CE_WARN, "Missing local IP address %u.%u.%u.%u",
	    bytes[0], bytes[1], bytes[2], bytes[3]);
	ni->ni_fbqueue = NULL;
	ni->ni_ire = NULL;
	mutex_exit(&ni->ni_lock);
}

/* rput */
void
natty_rput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_DATA:
		/* Shouldn't see M_DATA.  UDP converts these to M_PROTO. */
		freemsg(mp);
		break;
	case M_PROTO:
	case M_PCPROTO:
		/* strip ip header, process, pass up */
		natty_rput_other(q, mp);
		return;
	default:
		putnext(q, mp);
		return;
	}

}

void
natty_rput_other(queue_t *q, mblk_t *mp)
{
	nattyinfo_t *ni = (nattyinfo_t *)q->q_ptr;
	t_scalar_t t;

	/* proto or pcproto from UDP */

	ASSERT(mp != NULL);
	ASSERT(mp->b_datap->db_type == M_PROTO ||
	    mp->b_datap->db_type == M_PCPROTO);

	t = *(t_scalar_t *)(mp->b_rptr);

	if (t == T_UNITDATA_IND) {
		natty_rput_pkt(q, mp);
		return;
	}

	if (ni->ni_setup_done) {
		putnext(q, mp);
		return;
	}

	switch (t) {
	case T_OPTMGMT_ACK:
		if (ni->ni_rh_wait &&
		    (MBLKL(mp) >= sizeof (struct T_optmgmt_ack))) {
			ni->ni_rh_set = B_TRUE;
			ni->ni_rh_wait = B_FALSE;
		}
		break;
	case T_ADDR_ACK:
		if (ni->ni_addr_wait && ni->ni_ire == NULL) {
			get_my_ire(ni, addr_from_mblk(mp));
			ni->ni_addr_wait = B_FALSE;
		}
		break;
	}
	if (ni->ni_rh_set && (ni->ni_ire != NULL))
		ni->ni_setup_done = B_TRUE;
	putnext(q, mp);
}

void
natty_rput_pkt(queue_t *q, mblk_t *mp)
{
	mblk_t *data_mp;
	mblk_t *iph_mp;
	mblk_t *tdi_mp;
	uchar_t *rptr;
	uchar_t *new_rptr;
	ipha_t *iph;
	int32_t pkt_len;
	ipsa_t *ipsa;
	int32_t hdr_length;
	uint16_t tmp_len;
	int ntries = 0;
	nattyinfo_t *ni = q->q_ptr;
	sadb_t *sp;
	netstack_t	*ns = ni->ni_netstack;
	ipsecesp_stack_t *espstack = ns->netstack_ipsecesp;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (!ni->ni_rh_set) {
#ifdef DEBUG
		cmn_err(CE_WARN, "natty_rput_pkt: not set up");
#endif
		/* not fully set up */
		freemsg(mp);
		return;
	}

	/* remember mp, may need it later */
	tdi_mp = mp;
	data_mp = mp->b_cont;
	if (data_mp == NULL) {
		putnext(q, mp);
		return;
	}

	if (data_mp->b_cont != NULL) {
		data_mp = msgpullup(data_mp, -1);
		freemsg(mp->b_cont);
	}
	tdi_mp->b_cont = NULL;

	if (data_mp == NULL ||
	    data_mp->b_wptr - data_mp->b_rptr <
	    sizeof (ipha_t) + sizeof (udpha_t) + 1) {
		cmn_err(CE_WARN, (data_mp == NULL) ? "msgpullup() failure" :
		    "Short packet");
		freemsg(data_mp);
		freemsg(tdi_mp);
		return;
	};

	iph_mp = copyb(data_mp);
	if (iph_mp == NULL) {
		cmn_err(CE_WARN, "Low memory: copyb() failed.");
		freemsg(data_mp);
		freemsg(tdi_mp);
		return;
	}

	/* IP headers */
	rptr = iph_mp->b_rptr;
	hdr_length = IPH_HDR_LENGTH(rptr) + UDPH_SIZE;
	iph = (ipha_t *)rptr;
	data_mp->b_rptr += hdr_length;
	iph_mp->b_wptr = iph_mp->b_rptr + hdr_length;

	iph_mp->b_cont = data_mp;
	new_rptr = data_mp->b_rptr;

	pkt_len = data_mp->b_wptr - data_mp->b_rptr;
	if (pkt_len == 1) {
		/* keep alive */
		freemsg(tdi_mp);
		freemsg(iph_mp);
		return;
	}

	if (pkt_len > 3) {
		isaf_t *bucket;
		uint32_t spi;

		if (IS_P2ALIGNED(new_rptr, 4)) {
			spi = *((uint32_t *)new_rptr);
		} else {
			spi = new_rptr[0] + (new_rptr[1] << 8) +
			    (new_rptr[2] << 16) + (new_rptr[3] << 24);
		}

		if (spi == 0) {
			/*
			 * it's ike over 4500
			 * strip off marker and pass up
			 */
			data_mp->b_rptr += 4;

			iph_mp->b_cont = NULL;
			freemsg(iph_mp);

			tdi_mp->b_cont = data_mp;
			putnext(q, tdi_mp);
			return;
		}

		freemsg(tdi_mp);

		/*
		 * build new packet
		 *
		 * packet should be one mblk
		 * looks like [IP][UDP][ESP]
		 * via clever manipulation of mblk, becomes
		 * [IP][ESP]
		 */


		/* change fields */
		/* len, protocol, cksum */

		tmp_len = ntohs(iph->ipha_length);
		tmp_len -= UDPH_SIZE;
		iph->ipha_length = htons(tmp_len);

		iph->ipha_protocol = IPPROTO_ESP;

		iph->ipha_hdr_checksum = 0;
		iph->ipha_hdr_checksum = ip_csum_hdr(iph);

		iph_mp->b_wptr -= UDPH_SIZE;

		/* we are v4 only */
		sp = &espstack->esp_sadb.s_v4;
		bucket = INBOUND_BUCKET(sp, spi);

		mutex_enter(&bucket->isaf_lock);
		ipsa = ipsec_getassocbyspi(bucket, spi,
		    (uint32_t *)&(iph->ipha_src), (uint32_t *)&(iph->ipha_dst),
		    AF_INET);
		mutex_exit(&bucket->isaf_lock);

		if (ipsa == NULL || ipsa->ipsa_state == IPSA_STATE_DEAD ||
		    (!(ipsa->ipsa_flags & IPSA_F_NATT) &&
			ipsa->ipsa_state != IPSA_STATE_LARVAL)) {
			/* no associated sa error */

			if (ipsa != NULL) {
				/*
				 * While we give LARVALs the benefit of the
				 * doubt, full SAs that aren't NAT-T shouldn't
				 * be dealing with inbound NAT-T traffic.
				 */
				if (!(ipsa->ipsa_flags & IPSA_F_NATT)) {
					cmn_err(CE_WARN, "UDP-ESP arrived for "
					    "non-NAT SA, spi 0x%x",
					    htonl(ipsa->ipsa_spi));
				}
				IPSA_REFRELE(ipsa);
			}

			/* Handle the kstat_create in ip_drop_init() failing */
			ip_drop_packet(iph_mp, B_TRUE, NULL, NULL,
			    DROPPER(ipss, ipds_esp_no_sa),
			    &ipss->ipsec_dropper);
			return;
		}

		mutex_enter(&ipsa->ipsa_lock);
		if (ipsa->ipsa_natt_ka_timer == 0) {
			ASSERT(ipsa->ipsa_natt_q == NULL ||
			    ipsa->ipsa_natt_q == WR(q));
			ipsa->ipsa_natt_q = WR(q);

			ipsa->ipsa_natt_ka_timer = qtimeout(ipsa->ipsa_natt_q,
			    natty_ka_timeout_callback, ipsa, natty_ka_timeout);
		}
		mutex_exit(&ipsa->ipsa_lock);

		IPSA_REFRELE(ipsa);

		iph_mp->b_datap->db_type = M_DATA;

		/*
		 * If the cached ire is useless, try up to IRE_RETRIES number
		 * of times to get a new one.
		 */
#define	IRE_RETRIES 2
		do {
			mutex_enter(&ni->ni_lock);
			ASSERT(ni->ni_ire == NULL ||
			    ni->ni_ire->ire_rfq == ni->ni_fbqueue);
			if (ni->ni_ire != NULL &&
			    !(ni->ni_ire->ire_marks & IRE_MARK_CONDEMNED)) {
				IRE_REFHOLD(ni->ni_ire);
				mutex_exit(&ni->ni_lock);
				put(ni->ni_fbqueue, iph_mp);
				IRE_REFRELE(ni->ni_ire);
				return;
			} else if (ntries < IRE_RETRIES) {
				ire_t *ire;

				ntries++;
				ire = ni->ni_ire;
				ni->ni_ire = NULL;
				ni->ni_fbqueue = NULL;
				mutex_exit(&ni->ni_lock);
				if (ire != NULL)
					IRE_REFRELE_NOTR(ire);
				get_my_ire(ni, ni->ni_addr);
			} else {
				mutex_exit(&ni->ni_lock);
			}
		} while (ntries < IRE_RETRIES);
	} else {
		freemsg(tdi_mp);
	}

	/* bad pkt */
	freemsg(iph_mp);
}

static void
natty_wput(queue_t *q, mblk_t *mp)
{
	nattyinfo_t *ni = q->q_ptr;
	struct T_optmgmt_req *rp;
	struct opthdr *ohp;

	if (ni->ni_setup_done) {
		putnext(q, mp);
		return;
	}

	if (mp->b_datap->db_type != M_PROTO &&
	    mp->b_datap->db_type != M_PCPROTO) {
		putnext(q, mp);
		return;
	}

	if (MBLKL(mp) < sizeof (int)) {
		putnext(q, mp);
		return;
	}

	switch (*(t_scalar_t *)(mp->b_rptr)) {
	case T_SVR4_OPTMGMT_REQ:
		/*
		 * Expect a T_optmgmt_req followed by an opthdr
		 * followed by an int (with the option value of interest).
		 * If the one request we're snooping for wouldn't fit,
		 * don't bother looking further.
		 */
		if (MBLKL(mp) < (sizeof (*rp) + sizeof (*ohp) + sizeof (int))) {
			putnext(q, mp);
			return;
		}

		rp = (struct T_optmgmt_req *)mp->b_rptr;

		if ((rp->OPT_length >= sizeof (struct opthdr) + sizeof (int)) &&
		    (rp->OPT_offset == sizeof (struct T_optmgmt_req)) &&
		    (rp->MGMT_flags == T_NEGOTIATE)) {
			ohp = (struct opthdr *)(rp + 1);
			if ((ohp->level == IPPROTO_UDP) &&
			    (ohp->name == UDP_RCVHDR) &&
			    (ohp->len == sizeof (int))) {
				if (((int *)(ohp + 1)) != 0) {
					ni->ni_rh_wait = B_TRUE;
				}
			}
		}
		break;

	case T_ADDR_REQ:
		ni->ni_addr_wait = B_TRUE;
		break;
	}

	putnext(q, mp);
}

static void
natty_ka_timeout_callback(void *v_sa)
{
	ipsa_t *ipsa = (ipsa_t *)v_sa;
	mblk_t *mp;
	struct T_unitdata_req *tudr;
	sin_t *sin;
	boolean_t set_new_timeout = B_FALSE;
	queue_t *q;

	ASSERT(ipsa != NULL);

	if (ipsa->ipsa_state == IPSA_STATE_DEAD) {
		/* clear out timer and return */
		goto ntbail;
	}

	/*
	 * build packet
	 *
	 * [tudr][addr] + [1 byte of data (0xff)]
	 */

	mp = allocb(sizeof (*tudr) + sizeof (*sin), BPRI_HI);

	if (mp == NULL) {
		/* natt timeouts are the least of our worries */
		goto ntbail;
	}

	set_new_timeout = B_TRUE;

	mp->b_datap->db_type = M_PROTO;
	mp->b_wptr = mp->b_rptr + sizeof (*tudr) + sizeof (*sin);

	tudr = (struct T_unitdata_req *)mp->b_rptr;

	tudr->PRIM_type = T_UNITDATA_REQ;
	tudr->DEST_length = sizeof (*sin);
	tudr->DEST_offset = sizeof (*tudr);
	tudr->OPT_length = 0;
	tudr->OPT_offset = 0;
	sin = (sin_t *)(mp->b_rptr + sizeof (*tudr));
	if (ipsa->ipsa_remote_port != 0)
		sin->sin_port = ipsa->ipsa_remote_port;
	else
		sin->sin_port = htons(IPPORT_IKE_NATT);
	sin->sin_family = AF_INET;

	if (ipsa->ipsa_addrfam == AF_INET6)
		sin->sin_addr.s_addr = ipsa->ipsa_srcaddr[3];
	else
		sin->sin_addr.s_addr = ipsa->ipsa_srcaddr[0];

	mp->b_cont = allocb(1, BPRI_HI);

	if (mp->b_cont == NULL) {
		set_new_timeout = B_FALSE;
		freeb(mp);
		goto ntbail;
	}

	*(mp->b_cont->b_rptr) = 0xFF;
	mp->b_cont->b_wptr = mp->b_cont->b_rptr + 1;

ntbail:
	mutex_enter(&ipsa->ipsa_lock);
	if (set_new_timeout && ipsa->ipsa_natt_ka_timer != 0) {
		ipsa->ipsa_natt_ka_timer = qtimeout(ipsa->ipsa_natt_q,
		    natty_ka_timeout_callback, ipsa, natty_ka_timeout);
	} else {
		ipsa->ipsa_natt_ka_timer = 0;
		ipsa->ipsa_natt_q = NULL;
	}
	q = ipsa->ipsa_natt_q;
	mutex_exit(&ipsa->ipsa_lock);

	if (q != NULL)
		putnext(q, mp);
}

/*
 * Called from ipif_down(), if this module's loaded (or it hits a modstub if
 * not).  Check all nattyinfos for the ipif pointer.
 */
void
nattymod_clean_ipif(ipif_t *ipif)
{
	nattyinfo_t *walker;
	ire_t *ire;

	ASSERT(ipif != NULL);

	mutex_enter(&nattyhlock);
	for (walker = nattyhead; walker != NULL; walker = walker->ni_next) {
		mutex_enter(&walker->ni_lock);
		ire = walker->ni_ire;
		if (ire != NULL && (ipif == NULL || ire->ire_ipif == ipif)) {
			walker->ni_ire = NULL;
			walker->ni_fbqueue = NULL;
			mutex_exit(&walker->ni_lock);
			IRE_REFRELE_NOTR(ire);
			continue;
		}
		mutex_exit(&walker->ni_lock);
	}
	mutex_exit(&nattyhlock);
}
