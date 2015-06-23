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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

/*
 * Solaris Multithreaded STREAMS Chelsio PCI Ethernet Driver.
 * Interface code
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/ethernet.h>
#if PE_PROFILING_ENABLED
#include <sys/time.h>
#endif
#include <sys/gld.h>
#include "ostypes.h"
#include "common.h"
#include "oschtoe.h"
#ifdef CONFIG_CHELSIO_T1_1G
#include "fpga_defs.h"
#endif
#include "regs.h"
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#include "mc3.h"
#include "mc4.h"
#endif
#include "sge.h"
#include "tp.h"
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#include "ulp.h"
#endif
#include "espi.h"
#include "elmer0.h"
#include "gmac.h"
#include "cphy.h"
#include "suni1x10gexp_regs.h"
#include "ch.h"

#define	MLEN(mp) ((mp)->b_wptr - (mp)->b_rptr)

extern uint32_t buffers_in_use[];
extern kmutex_t in_use_l;
extern uint32_t in_use_index;

static void link_start(ch_t *sa, struct pe_port_t *pp);
static ch_esb_t *ch_alloc_small_esbbuf(ch_t *sa, uint32_t i);
static ch_esb_t *ch_alloc_big_esbbuf(ch_t *sa, uint32_t i);
void ch_big_rbuf_recycle(ch_esb_t *rbp);
void ch_small_rbuf_recycle(ch_esb_t *rbp);
static const struct board_info *pe_sa_init(ch_t *sa);
static int ch_set_config_data(ch_t *chp);
void pe_rbuf_pool_free(ch_t *chp);
static void pe_free_driver_resources(ch_t *sa);
static void update_mtu_tab(ch_t *adapter);
static int pe_change_mtu(ch_t *chp);

/*
 * CPL5 Defines (from netinet/cpl5_commands.h)
 */
#define	FLITSTOBYTES	8

#define	CPL_FORMAT_0_SIZE 8
#define	CPL_FORMAT_1_SIZE 16
#define	CPL_FORMAT_2_SIZE 24
#define	CPL_FORMAT_3_SIZE 32
#define	CPL_FORMAT_4_SIZE 40
#define	CPL_FORMAT_5_SIZE 48

#define	TID_MASK 0xffffff

#define	PE_LINK_SPEED_AUTONEG	5

static int pe_small_rbuf_pool_init(ch_t *sa);
static int pe_big_rbuf_pool_init(ch_t *sa);
static int pe_make_fake_arp(ch_t *chp, unsigned char *arpp);
static uint32_t pe_get_ip(unsigned char *arpp);

/*
 * May be set in /etc/system to 0 to use default latency timer for 10G.
 * See PCI register 0xc definition.
 */
int enable_latency_timer = 1;

/*
 * May be set in /etc/system to 0 to disable hardware checksum for
 * TCP and UDP.
 */
int enable_checksum_offload = 1;

/*
 * Multiplier for freelist pool.
 */
int fl_sz_multiplier = 6;

uint_t
pe_intr(ch_t *sa)
{
	mutex_enter(&sa->ch_intr);

	if (sge_data_in(sa->sge)) {
		sa->isr_intr++;
		mutex_exit(&sa->ch_intr);
		return (DDI_INTR_CLAIMED);
	}

	mutex_exit(&sa->ch_intr);

	return (DDI_INTR_UNCLAIMED);
}

/*
 * Each setup struct will call this function to
 * initialize.
 */
void
pe_init(void* xsa)
{
	ch_t *sa = NULL;
	int i = 0;

	sa = (ch_t *)xsa;

	/*
	 * Need to count the number of times this routine is called
	 * because we only want the resources to be allocated once.
	 * The 7500 has four ports and so this routine can be called
	 * once for each port.
	 */
	if (sa->init_counter == 0) {
		for_each_port(sa, i) {

			/*
			 * We only want to initialize the line if it is down.
			 */
			if (sa->port[i].line_up == 0) {
				link_start(sa, &sa->port[i]);
				sa->port[i].line_up = 1;
			}
		}

		(void) t1_init_hw_modules(sa);

		/*
		 * Enable/Disable checksum offloading.
		 */
		if (sa->ch_config.cksum_enabled) {
			if (sa->config_data.offload_ip_cksum) {
				/* Notify that HW will do the checksum. */
				t1_tp_set_ip_checksum_offload(sa->tp, 1);
			}

			if (sa->config_data.offload_tcp_cksum) {
				/* Notify that HW will do the checksum. */
				t1_tp_set_tcp_checksum_offload(sa->tp, 1);
			}

			if (sa->config_data.offload_udp_cksum) {
				/* Notify that HW will do the checksum. */
				t1_tp_set_udp_checksum_offload(sa->tp, 1);
			}
		}

		sa->ch_flags |= PEINITDONE;

		sa->init_counter++;
	}

	/*
	 * Enable interrupts after starting the SGE so
	 * that the SGE is ready to handle interrupts.
	 */
	(void) sge_start(sa->sge);
	t1_interrupts_enable(sa);

	/*
	 * set mtu (either 1500 or bigger)
	 */
	(void) pe_change_mtu(sa);
#ifdef HOST_PAUSE
	/*
	 * get the configured value of the MAC.
	 */
	(void) t1_tpi_read(sa, SUNI1x10GEXP_REG_TXXG_CONFIG_1 << 2,
	    &sa->txxg_cfg1);
#endif
}

/* ARGSUSED */
static void
link_start(ch_t *sa, struct pe_port_t *p)
{
	struct cmac *mac = p->mac;

	mac->ops->reset(mac);
	if (mac->ops->macaddress_set)
		mac->ops->macaddress_set(mac, p->enaddr);
	(void) t1_link_start(p->phy, mac, &p->link_config);
	mac->ops->enable(mac, MAC_DIRECTION_RX | MAC_DIRECTION_TX);
}

/*
 * turn off interrupts...
 */
void
pe_stop(ch_t *sa)
{
	t1_interrupts_disable(sa);
	(void) sge_stop(sa->sge);

	/*
	 * we can still be running an interrupt thread in sge_data_in().
	 * If we are, we'll block on the ch_intr lock
	 */
	mutex_enter(&sa->ch_intr);
	mutex_exit(&sa->ch_intr);
}

/*
 * output mblk to SGE level and out to the wire.
 */

int
pe_start(ch_t *sa, mblk_t *mp, uint32_t flg)
{
	mblk_t *m0 = mp;
	cmdQ_ce_t cm[16];
	cmdQ_ce_t *cmp;
	cmdQ_ce_t *hmp = &cm[0]; /* head of cm table (may be kmem_alloed) */
	int cm_flg = 0;		/* flag (1 - if kmem-alloced) */
	int nseg = 0;		/* number cmdQ_ce entries created */
	int mseg = 16;		/* maximum entries in hmp arrary */
	int freeme = 0;		/* we have an mblk to free in case of error */
	uint32_t ch_bind_dma_handle(ch_t *, int, caddr_t, cmdQ_ce_t *,
	    uint32_t);
#if defined(__sparc)
	uint32_t ch_bind_dvma_handle(ch_t *, int, caddr_t, cmdQ_ce_t *,
	    uint32_t);
#endif
	int rv;			/* return value on error */

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (flg & CH_OFFLOAD) {
		hmp->ce_pa = ((tbuf_t *)mp)->tb_pa;
		hmp->ce_dh = NULL;
		hmp->ce_flg = DH_TOE;
		hmp->ce_len = ((tbuf_t *)mp)->tb_len;
		hmp->ce_mp = mp;

		/* make sure data is flushed to physical memory */
		(void) ddi_dma_sync((ddi_dma_handle_t)((tbuf_t *)mp)->tb_dh,
		    (off_t)0, hmp->ce_len, DDI_DMA_SYNC_FORDEV);

		if (sge_data_out(sa->sge, 0, mp, hmp, 1, flg) == 0) {
			return (0);
		}

		/*
		 * set a flag so we'll restart upper layer when
		 * resources become available.
		 */
		sa->ch_blked = 1;
		return (1);
	}
#endif	/* CONFIG_CHELSIO_T1_OFFLOAD */

	/* writes from toe will always have CPL header in place */
	if (flg & CH_NO_CPL) {
		struct cpl_tx_pkt *cpl;

		/* PR2928 & PR3309 */
		if (sa->ch_ip == NULL) {
			ushort_t ethertype = ntohs(*(short *)&mp->b_rptr[12]);
			if (ethertype == ETHERTYPE_ARP) {
				if (is_T2(sa)) {
					/*
					 * We assume here that the arp will be
					 * contained in one mblk.
					 */
					if (pe_make_fake_arp(sa, mp->b_rptr)) {
						freemsg(mp);
						sa->oerr++;
						return (0);
					}
				} else {
					sa->ch_ip = pe_get_ip(mp->b_rptr);
				}
			}
		}

		/*
		 * if space in front of packet big enough for CPL
		 * header, then use it. We'll allocate an mblk
		 * otherwise.
		 */
		if ((mp->b_rptr - mp->b_datap->db_base) >= SZ_CPL_TX_PKT) {

			mp->b_rptr -= SZ_CPL_TX_PKT;

		} else {

#ifdef SUN_KSTATS
			sa->sge->intr_cnt.tx_need_cpl_space++;
#endif
			m0 = allocb(SZ_CPL_TX_PKT, BPRI_HI);
			if (m0 == NULL) {
				freemsg(mp);
				sa->oerr++;
				return (0);
			}

			m0->b_wptr = m0->b_rptr + SZ_CPL_TX_PKT;
			m0->b_cont = mp;
			freeme = 1;

			mp = m0;
		}

		/* fill in cpl header */
		cpl = (struct cpl_tx_pkt *)mp->b_rptr;
		cpl->opcode = CPL_TX_PKT;
		cpl->iff = 0;		/* XXX port 0 needs fixing with NEMO */
		cpl->ip_csum_dis = 1;	/* no IP header cksum */
		cpl->l4_csum_dis =
		    flg & CH_NO_HWCKSUM;	/* CH_NO_HWCKSUM == 1 */
		cpl->vlan_valid = 0;		/* no vlan */
	}

	if (m0->b_cont) {

#ifdef SUN_KSTATS
			sa->sge->intr_cnt.tx_multi_mblks++;
#endif

		while (mp) {
			int lseg;	/* added by ch_bind_dma_handle() */
			int len;

			len = MLEN(mp);
			/* skip mlks with no data */
			if (len == 0) {
				mp = mp->b_cont;
				continue;
			}

			/*
			 * if we've run out of space on stack, then we
			 * allocate a temporary buffer to hold the
			 * information. This will kill the the performance,
			 * but since it shouldn't really occur, we can live
			 * with it. Since jumbo frames may map multiple
			 * descriptors, we reallocate the hmp[] array before
			 * we reach the end.
			 */
			if (nseg >= (mseg-4)) {
				cmdQ_ce_t *buf;
				int j;

				buf = kmem_alloc(sizeof (cmdQ_ce_t) * 2 * mseg,
				    KM_SLEEP);

				for (j = 0; j < nseg; j++)
					buf[j] = hmp[j];

				if (cm_flg) {
					kmem_free(hmp,
					    mseg * sizeof (cmdQ_ce_t));
				} else
					cm_flg = 1;

				hmp = buf;
				mseg = 2*mseg;

				/*
				 * We've used up ch table on stack
				 */
			}

#if defined(__sparc)
			if (sa->ch_config.enable_dvma) {
				lseg = ch_bind_dvma_handle(sa, len,
				    (void *)mp->b_rptr,
				    &hmp[nseg], mseg - nseg);
				if (lseg == NULL) {
					sa->sge->intr_cnt.tx_no_dvma1++;
					if ((lseg = ch_bind_dma_handle(sa, len,
					    (void *)mp->b_rptr,
					    &hmp[nseg],
					    mseg - nseg)) == NULL) {
						sa->sge->intr_cnt.tx_no_dma1++;

						/*
						 * ran out of space. Gonna bale
						 */
						rv = 0;

						/*
						 * we may have processed
						 * previous mblks and have
						 * descriptors. If so, we need
						 * to free the meta struct
						 * entries before freeing
						 * the mblk.
						 */
						if (nseg)
							goto error;
						goto error1;
					}
				}
			} else {
				lseg = ch_bind_dma_handle(sa, len,
				    (void *)mp->b_rptr, &hmp[nseg],
				    mseg - nseg);
				if (lseg == NULL) {
					sa->sge->intr_cnt.tx_no_dma1++;

					/*
					 * ran out of space. Gona bale
					 */
					rv = 0;

					/*
					 * we may have processed previous
					 * mblks and have descriptors. If so,
					 * we need to free the meta struct
					 * entries before freeing the mblk.
					 */
					if (nseg)
						goto error;
					goto error1;
				}
			}
#else	/* defined(__sparc) */
			lseg = ch_bind_dma_handle(sa, len,
			    (void *)mp->b_rptr, &hmp[nseg],
			    mseg - nseg);
			if (lseg == NULL) {
				sa->sge->intr_cnt.tx_no_dma1++;

				/*
				 * ran out of space. Gona bale
				 */
				rv = 0;

				/*
				 * we may have processed previous mblks and
				 * have descriptors. If so, we need to free
				 * the meta struct entries before freeing
				 * the mblk.
				 */
				if (nseg)
					goto error;
				goto error1;
			}
#endif	/* defined(__sparc) */
			nseg += lseg;
			mp = mp->b_cont;
		}

		/*
		 * SHOULD NEVER OCCUR, BUT...
		 * no data if nseg 0 or
		 * nseg 1 and a CPL mblk (CPL mblk only with offload mode)
		 * and no data
		 */
		if ((nseg == 0) || (freeme && (nseg == 1))) {
			rv = 0;
			goto error1;
		}

	} else {
		int len;

		/* we assume that we always have data with one packet */
		len = MLEN(mp);

#if defined(__sparc)
		if (sa->ch_config.enable_dvma) {
			nseg = ch_bind_dvma_handle(sa, len,
			    (void *)mp->b_rptr,
			    &hmp[0], 16);
			if (nseg == NULL) {
				sa->sge->intr_cnt.tx_no_dvma2++;
				nseg = ch_bind_dma_handle(sa, len,
				    (void *)mp->b_rptr,
				    &hmp[0], 16);
				if (nseg == NULL) {
					sa->sge->intr_cnt.tx_no_dma2++;

					/*
					 * ran out of space. Gona bale
					 */
					rv = 0;
					goto error1;
				}
			}
		} else {
			nseg = ch_bind_dma_handle(sa, len,
			    (void *)mp->b_rptr, &hmp[0], 16);
			if (nseg == NULL) {
				sa->sge->intr_cnt.tx_no_dma2++;

				/*
				 * ran out of space. Gona bale
				 */
				rv = 0;
				goto error1;
			}
		}
#else	/* defined(__sparc) */
		nseg = ch_bind_dma_handle(sa, len,
		    (void *)mp->b_rptr, &hmp[0], 16);
		if (nseg == NULL) {
			sa->sge->intr_cnt.tx_no_dma2++;

			/*
			 * ran out of space. Gona bale
			 */
			rv = 0;
			goto error1;
		}
#endif	/* defined(__sparc) */

		/*
		 * dummy arp message to handle PR3309 & PR2928
		 */
		if (flg & CH_ARP)
			hmp->ce_flg |= DH_ARP;
	}

	if (sge_data_out(sa->sge, 0, m0, hmp, nseg, flg) == 0) {
		if (cm_flg)
			kmem_free(hmp, mseg * sizeof (cmdQ_ce_t));
		return (0);
	}

	/*
	 * set a flag so we'll restart upper layer when
	 * resources become available.
	 */
	if ((flg & CH_ARP) == 0)
		sa->ch_blked = 1;
	rv = 1;

error:
	/*
	 * unmap the physical addresses allocated earlier.
	 */
	cmp = hmp;
	for (--nseg; nseg >= 0; nseg--) {
		if (cmp->ce_dh) {
			if (cmp->ce_flg == DH_DMA)
				ch_unbind_dma_handle(sa, cmp->ce_dh);
#if defined(__sparc)
			else
				ch_unbind_dvma_handle(sa, cmp->ce_dh);
#endif
		}
		cmp++;
	}

error1:

	/* free the temporary array */
	if (cm_flg)
		kmem_free(hmp, mseg * sizeof (cmdQ_ce_t));

	/*
	 * if we've allocated an mblk above, then we need to free it
	 * before returning. This is safe since we haven't done anything to
	 * the original message. The caller, gld, will still have a pointer
	 * to the original mblk.
	 */
	if (rv == 1) {
		if (freeme) {
			/* we had to allocate an mblk. Free it. */
			freeb(m0);
		} else {
			/* adjust the mblk back to original start */
			if (flg & CH_NO_CPL)
				m0->b_rptr += SZ_CPL_TX_PKT;
		}
	} else {
		freemsg(m0);
		sa->oerr++;
	}

	return (rv);
}

/* KLUDGE ALERT. HARD WIRED TO PORT ZERO */
void
pe_set_mac(ch_t *sa, unsigned char *ac_enaddr)
{
	sa->port[0].mac->ops->macaddress_set(sa->port[0].mac, ac_enaddr);
}

/* KLUDGE ALERT. HARD WIRED TO PORT ZERO */
unsigned char *
pe_get_mac(ch_t *sa)
{
	return (sa->port[0].enaddr);
}

/* KLUDGE ALERT. HARD WIRED TO ONE PORT */
void
pe_set_promiscuous(ch_t *sa, int flag)
{
	struct cmac *mac = sa->port[0].mac;
	struct t1_rx_mode rm;

	switch (flag) {
	case 0:		/* turn off promiscuous mode */
		sa->ch_flags &= ~(PEPROMISC|PEALLMULTI);
		break;

	case 1:		/* turn on promiscuous mode */
		sa->ch_flags |= PEPROMISC;
		break;

	case 2:		/* turn on multicast reception */
		sa->ch_flags |= PEALLMULTI;
		break;
	}

	mutex_enter(&sa->ch_mc_lck);
	rm.chp = sa;
	rm.mc = sa->ch_mc;

	mac->ops->set_rx_mode(mac, &rm);
	mutex_exit(&sa->ch_mc_lck);
}

int
pe_set_mc(ch_t *sa, uint8_t *ep, int flg)
{
	struct cmac *mac = sa->port[0].mac;
	struct t1_rx_mode rm;

	if (flg == GLD_MULTI_ENABLE) {
		ch_mc_t *mcp;

		mcp = (ch_mc_t *)kmem_zalloc(sizeof (struct ch_mc),
		    KM_NOSLEEP);
		if (mcp == NULL)
			return (GLD_NORESOURCES);

		bcopy(ep, &mcp->cmc_mca, 6);

		mutex_enter(&sa->ch_mc_lck);
		mcp->cmc_next = sa->ch_mc;
		sa->ch_mc = mcp;
		sa->ch_mc_cnt++;
		mutex_exit(&sa->ch_mc_lck);

	} else if (flg == GLD_MULTI_DISABLE) {
		ch_mc_t **p = &sa->ch_mc;
		ch_mc_t *q = NULL;

		mutex_enter(&sa->ch_mc_lck);
		p = &sa->ch_mc;
		while (*p) {
			if (bcmp(ep, (*p)->cmc_mca, 6) == 0) {
				q = *p;
				*p = (*p)->cmc_next;
				kmem_free(q, sizeof (*q));
				sa->ch_mc_cnt--;
				break;
			}

			p = &(*p)->cmc_next;
		}
		mutex_exit(&sa->ch_mc_lck);

		if (q == NULL)
			return (GLD_BADARG);
	} else
		return (GLD_BADARG);

	mutex_enter(&sa->ch_mc_lck);
	rm.chp = sa;
	rm.mc = sa->ch_mc;

	mac->ops->set_rx_mode(mac, &rm);
	mutex_exit(&sa->ch_mc_lck);

	return (GLD_SUCCESS);
}

/*
 * return: speed       - bandwidth of interface
 * return: intrcnt     - # interrupts
 * return: norcvbuf    - # recedived packets dropped by driver
 * return: oerrors     - # bad send packets
 * return: ierrors     - # bad receive packets
 * return: underrun    - # bad underrun xmit packets
 * return: overrun     - # bad overrun recv packets
 * return: framing     - # bad aligned recv packets
 * return: crc         - # bad FCS (crc) recv packets
 * return: carrier     - times carrier was lost
 * return: collisions  - # xmit collisions
 * return: xcollisions - # xmit pkts dropped due to collisions
 * return: late        - # late xmit collisions
 * return: defer       - # deferred xmit packets
 * return: xerrs       - # xmit dropped packets
 * return: rerrs       - # recv dropped packets
 * return: toolong     - # recv pkts too long
 * return: runt        - # recv runt pkts
 * return: multixmt    - # multicast pkts xmitted
 * return: multircv    - # multicast pkts recved
 * return: brdcstxmt   - # broadcast pkts xmitted
 * return: brdcstrcv   - # broadcast pkts rcv
 */

int
pe_get_stats(ch_t *sa, uint64_t *speed, uint32_t *intrcnt, uint32_t *norcvbuf,
    uint32_t *oerrors, uint32_t *ierrors, uint32_t *underrun,
    uint32_t *overrun, uint32_t *framing, uint32_t *crc,
    uint32_t *carrier, uint32_t *collisions, uint32_t *xcollisions,
    uint32_t *late, uint32_t *defer, uint32_t *xerrs, uint32_t *rerrs,
    uint32_t *toolong, uint32_t *runt, ulong_t  *multixmt, ulong_t  *multircv,
    ulong_t  *brdcstxmt, ulong_t  *brdcstrcv)
{
	struct pe_port_t *pt;
	int line_speed;
	int line_duplex;
	int line_is_active;
	uint64_t v;
	const struct cmac_statistics *sp;

	pt = &(sa->port[0]);
	(void) pt->phy->ops->get_link_status(pt->phy,
	    &line_is_active, &line_speed, &line_duplex, NULL);

	switch (line_speed) {
	case SPEED_10:
		*speed = 10000000;
		break;
	case SPEED_100:
		*speed = 100000000;
		break;
	case SPEED_1000:
		*speed = 1000000000;
		break;
	case SPEED_10000:
		/*
		 * kludge to get 10,000,000,000 constant (and keep
		 * compiler happy).
		 */
		v = 10000000;
		v *= 1000;
		*speed = v;
		break;
	default:
		goto error;
	}

	*intrcnt = sa->isr_intr;
	*norcvbuf = sa->norcvbuf;

	sp = sa->port[0].mac->ops->statistics_update(sa->port[0].mac,
	    MAC_STATS_UPDATE_FULL);

	*ierrors = sp->RxOctetsBad;

	/*
	 * not sure this is correct. # aborted at driver level +
	 * # at hardware level
	 */
	*oerrors = sa->oerr + sp->TxFramesAbortedDueToXSCollisions +
	    sp->TxUnderrun + sp->TxLengthErrors +
	    sp->TxInternalMACXmitError +
	    sp->TxFramesWithExcessiveDeferral +
	    sp->TxFCSErrors;

	*underrun = sp->TxUnderrun;
	*overrun = sp->RxFrameTooLongErrors;
	*framing = sp->RxAlignErrors;
	*crc = sp->RxFCSErrors;
	*carrier = 0;		/* need to find this */
	*collisions = sp->TxTotalCollisions;
	*xcollisions = sp->TxFramesAbortedDueToXSCollisions;
	*late = sp->TxLateCollisions;
	*defer = sp->TxFramesWithDeferredXmissions;
	*xerrs = sp->TxUnderrun + sp->TxLengthErrors +
	    sp->TxInternalMACXmitError + sp->TxFCSErrors;
	*rerrs = sp->RxSymbolErrors + sp->RxSequenceErrors + sp->RxRuntErrors +
	    sp->RxJabberErrors + sp->RxInternalMACRcvError +
	    sp->RxInRangeLengthErrors + sp->RxOutOfRangeLengthField;
	*toolong = sp->RxFrameTooLongErrors;
	*runt = sp->RxRuntErrors;

	*multixmt = sp->TxMulticastFramesOK;
	*multircv = sp->RxMulticastFramesOK;
	*brdcstxmt = sp->TxBroadcastFramesOK;
	*brdcstrcv = sp->RxBroadcastFramesOK;

	return (0);

error:
	*speed = 0;
	*intrcnt = 0;
	*norcvbuf = 0;
	*norcvbuf = 0;
	*oerrors = 0;
	*ierrors = 0;
	*underrun = 0;
	*overrun = 0;
	*framing = 0;
	*crc = 0;
	*carrier = 0;
	*collisions = 0;
	*xcollisions = 0;
	*late = 0;
	*defer = 0;
	*xerrs = 0;
	*rerrs = 0;
	*toolong = 0;
	*runt = 0;
	*multixmt = 0;
	*multircv = 0;
	*brdcstxmt = 0;
	*brdcstrcv = 0;

	return (1);
}

uint32_t ch_gtm = 0;		/* Default: Global Tunnel Mode off */
uint32_t ch_global_config = 0x07000000;	/* Default: errors, warnings, status */
uint32_t ch_is_asic = 0;	/* Default: non-ASIC */
uint32_t ch_link_speed = PE_LINK_SPEED_AUTONEG;	/* Default: auto-negoiate */
uint32_t ch_num_of_ports = 1;	/* Default: 1 port */
uint32_t ch_tp_reset_cm = 1;	/* Default: reset CM memory map */
uint32_t ch_phy_tx_fifo = 0;	/* Default: 0 phy tx fifo depth */
uint32_t ch_phy_rx_fifo = 0;	/* Default: 0 phy rx fifo depth */
uint32_t ch_phy_force_master = 1;	/* Default: link always master mode */
uint32_t ch_mc5_rtbl_size = 2048;	/* Default: TCAM routing table size */
uint32_t ch_mc5_dbsvr_size = 128;	/* Default: TCAM server size */
uint32_t ch_mc5_parity = 1;	/* Default: parity error checking */
uint32_t ch_mc5_issue_syn = 0;	/* Default: Allow transaction overlap */
uint32_t ch_packet_tracing = 0;		/* Default: no packet tracing */
uint32_t ch_server_region_len =
	DEFAULT_SERVER_REGION_LEN;
uint32_t ch_rt_region_len =
	DEFAULT_RT_REGION_LEN;
uint32_t ch_offload_ip_cksum = 0;	/* Default: no checksum offloading */
uint32_t ch_offload_udp_cksum = 1;	/* Default: offload UDP ckecksum */
uint32_t ch_offload_tcp_cksum = 1;	/* Default: offload TCP checksum */
uint32_t ch_sge_cmdq_threshold = 0;	/* Default: threshold 0 */
uint32_t ch_sge_flq_threshold = 0;	/* Default: SGE flq threshold */
uint32_t ch_sge_cmdq0_cnt =	/* Default: cmd queue 0 size */
	SGE_CMDQ0_CNT;
uint32_t ch_sge_cmdq1_cnt =	/* Default: cmd queue 1 size */
	SGE_CMDQ0_CNT;
uint32_t ch_sge_flq0_cnt =	/* Default: free list queue-0 length */
	SGE_FLQ0_CNT;
uint32_t ch_sge_flq1_cnt =	/* Default: free list queue-1 length */
	SGE_FLQ0_CNT;
uint32_t ch_sge_respq_cnt =	/* Default: reqsponse queue size */
	SGE_RESPQ_CNT;
uint32_t ch_stats = 1;		/* Default: Automatic Update MAC stats */
uint32_t ch_tx_delay_us = 0;	/* Default: No Msec delay to Tx pkts */
int32_t ch_chip = -1;		/* Default: use hardware lookup tbl */
uint32_t ch_exit_early = 0;	/* Default: complete initialization */
uint32_t ch_rb_num_of_entries = 1000; /* Default: number ring buffer entries */
uint32_t ch_rb_size_of_entries = 64;	/* Default: ring buffer entry size */
uint32_t ch_rb_flag = 1;	/* Default: ring buffer flag */
uint32_t ch_type;
uint64_t ch_cat_opt0 = 0;
uint64_t ch_cat_opt1 = 0;
uint32_t ch_timer_delay = 0;	/* Default: use value from board entry */

int
pe_attach(ch_t *chp)
{
	int return_val = 1;
	const struct board_info *bi;
	uint32_t pcix_cmd;

	(void) ch_set_config_data(chp);

	bi = pe_sa_init(chp);
	if (bi == 0)
		return (1);

	if (t1_init_sw_modules(chp, bi) < 0)
		return (1);

	if (pe_small_rbuf_pool_init(chp) == NULL)
		return (1);

	if (pe_big_rbuf_pool_init(chp) == NULL)
		return (1);

	/*
	 * We gain significaint performance improvements when we
	 * increase the PCI's maximum memory read byte count to
	 * 2K(HW doesn't support 4K at this time) and set the PCI's
	 * maximum outstanding split transactions to 4. We want to do
	 * this for 10G. Done by software utility.
	 */

	if (board_info(chp)->caps & SUPPORTED_10000baseT_Full) {
		(void) t1_os_pci_read_config_4(chp, A_PCICFG_PCIX_CMD,
		    &pcix_cmd);
		/*
		 * if the burstsize is set, then use it instead of default
		 */
		if (chp->ch_config.burstsize_set) {
			pcix_cmd &= ~0xc0000;
			pcix_cmd |= (chp->ch_config.burstsize << 18);
		}
		/*
		 * if the split transaction count is set, then use it.
		 */
		if (chp->ch_config.transaction_cnt_set) {
			pcix_cmd &= ~ 0x700000;
			pcix_cmd |= (chp->ch_config.transaction_cnt << 20);
		}

		/*
		 * set ralaxed ordering flag as configured in chxge.conf
		 */
		pcix_cmd |= (chp->ch_config.relaxed_ordering << 17);

		(void) t1_os_pci_write_config_4(chp, A_PCICFG_PCIX_CMD,
		    pcix_cmd);
	}

	/*
	 * set the latency time to F8 for 10G cards.
	 * Done by software utiltiy.
	 */
	if (enable_latency_timer) {
		if (board_info(chp)->caps & SUPPORTED_10000baseT_Full) {
			(void) t1_os_pci_write_config_4(chp, 0xc, 0xf800);
		}
	}

	/*
	 * update mtu table (regs: 0x404 - 0x420) with bigger values than
	 * default.
	 */
	update_mtu_tab(chp);

	/*
	 * Clear all interrupts now.  Don't enable
	 * them until later.
	 */
	t1_interrupts_clear(chp);

	/*
	 * Function succeeded.
	 */
	return_val = 0;

	return (return_val);
}

/*
 * DESC: Read variables set in /boot/loader.conf and save
 *       them internally. These internal values are then
 *       used to make decisions at run-time on behavior thus
 *       allowing a certain level of customization.
 * OUT:  p_config - pointer to config structure that
 *                  contains all of the new values.
 * RTN:  0 - Success;
 */
static int
ch_set_config_data(ch_t *chp)
{
	pe_config_data_t *p_config = (pe_config_data_t *)&chp->config_data;

	bzero(p_config, sizeof (pe_config_data_t));

	/*
	 * Global Tunnel Mode configuration
	 */
	p_config->gtm = ch_gtm;

	p_config->global_config = ch_global_config;

	if (p_config->gtm)
		p_config->global_config |= CFGMD_TUNNEL;

	p_config->tp_reset_cm = ch_tp_reset_cm;
	p_config->is_asic = ch_is_asic;

	/*
	 * MC5 configuration.
	 */
	p_config->mc5_rtbl_size = ch_mc5_rtbl_size;
	p_config->mc5_dbsvr_size = ch_mc5_dbsvr_size;
	p_config->mc5_parity = ch_mc5_parity;
	p_config->mc5_issue_syn = ch_mc5_issue_syn;

	p_config->offload_ip_cksum = ch_offload_ip_cksum;
	p_config->offload_udp_cksum = ch_offload_udp_cksum;
	p_config->offload_tcp_cksum = ch_offload_tcp_cksum;

	p_config->packet_tracing = ch_packet_tracing;

	p_config->server_region_len = ch_server_region_len;
	p_config->rt_region_len = ch_rt_region_len;

	/*
	 * Link configuration.
	 *
	 * 5-auto-neg 2-1000Gbps; 1-100Gbps; 0-10Gbps
	 */
	p_config->link_speed = ch_link_speed;
	p_config->num_of_ports = ch_num_of_ports;

	/*
	 * Catp options
	 */
	p_config->cat_opt0 = ch_cat_opt0;
	p_config->cat_opt1 = ch_cat_opt1;

	/*
	 * SGE configuration.
	 */
	p_config->sge_cmdq0_cnt = ch_sge_cmdq0_cnt;
	p_config->sge_cmdq1_cnt = ch_sge_cmdq1_cnt;
	p_config->sge_flq0_cnt = ch_sge_flq0_cnt;
	p_config->sge_flq1_cnt = ch_sge_flq1_cnt;
	p_config->sge_respq_cnt = ch_sge_respq_cnt;

	p_config->phy_rx_fifo = ch_phy_rx_fifo;
	p_config->phy_tx_fifo = ch_phy_tx_fifo;

	p_config->sge_cmdq_threshold = ch_sge_cmdq_threshold;

	p_config->sge_flq_threshold = ch_sge_flq_threshold;

	p_config->phy_force_master = ch_phy_force_master;

	p_config->rb_num_of_entries = ch_rb_num_of_entries;

	p_config->rb_size_of_entries = ch_rb_size_of_entries;

	p_config->rb_flag = ch_rb_flag;

	p_config->exit_early = ch_exit_early;

	p_config->chip = ch_chip;

	p_config->stats = ch_stats;

	p_config->tx_delay_us = ch_tx_delay_us;

	return (0);
}

static const struct board_info *
pe_sa_init(ch_t *sa)
{
	uint16_t device_id;
	uint16_t device_subid;
	const struct board_info *bi;

	sa->config = sa->config_data.global_config;
	device_id = pci_config_get16(sa->ch_hpci, 2);
	device_subid = pci_config_get16(sa->ch_hpci, 0x2e);

	bi = t1_get_board_info_from_ids(device_id, device_subid);
	if (bi == NULL) {
		cmn_err(CE_NOTE,
		    "The adapter with device_id %d %d is not supported.\n",
		    device_id, device_subid);
		return (NULL);
	}

	if (t1_get_board_rev(sa, bi, &sa->params)) {
		cmn_err(CE_NOTE, "unknown device_id %d %d\n",
		    device_id, device_subid);
		return ((const struct board_info *)NULL);
	}

	return (bi);
}

/*
 * allocate pool of small receive buffers (with vaddr & paddr) and
 * receiver buffer control structure (ch_esb_t *rbp).
 * XXX we should allow better tuning of the # of preallocated
 * free buffers against the # of freelist entries.
 */
static int
pe_small_rbuf_pool_init(ch_t *sa)
{
	int i;
	ch_esb_t *rbp;
	extern uint32_t sge_flq0_cnt;
	extern uint32_t sge_flq1_cnt;
	int size;
	uint32_t j;

	if (is_T2(sa))
		size = sge_flq1_cnt * fl_sz_multiplier;
	else
		size = sge_flq0_cnt * fl_sz_multiplier;

	mutex_init(&sa->ch_small_esbl, NULL, MUTEX_DRIVER, sa->ch_icookp);

	mutex_enter(&in_use_l);
	j = in_use_index++;
	if (in_use_index >= SZ_INUSE)
		in_use_index = 0;
	mutex_exit(&in_use_l);

	sa->ch_small_owner = NULL;
	sa->ch_sm_index = j;
	sa->ch_small_esb_free = NULL;
	for (i = 0; i < size; i++) {
		rbp = ch_alloc_small_esbbuf(sa, j);
		if (rbp == NULL)
			goto error;
		/*
		 * add entry to free list
		 */
		rbp->cs_next = sa->ch_small_esb_free;
		sa->ch_small_esb_free = rbp;

		/*
		 * add entry to owned list
		 */
		rbp->cs_owner = sa->ch_small_owner;
		sa->ch_small_owner = rbp;
	}
	return (1);

error:
	sa->ch_small_owner = NULL;

	/* free whatever we've already allocated */
	pe_rbuf_pool_free(sa);

	return (0);
}

/*
 * allocate pool of receive buffers (with vaddr & paddr) and
 * receiver buffer control structure (ch_esb_t *rbp).
 * XXX we should allow better tuning of the # of preallocated
 * free buffers against the # of freelist entries.
 */
static int
pe_big_rbuf_pool_init(ch_t *sa)
{
	int i;
	ch_esb_t *rbp;
	extern uint32_t sge_flq0_cnt;
	extern uint32_t sge_flq1_cnt;
	int size;
	uint32_t j;

	if (is_T2(sa))
		size = sge_flq0_cnt * fl_sz_multiplier;
	else
		size = sge_flq1_cnt * fl_sz_multiplier;

	mutex_init(&sa->ch_big_esbl, NULL, MUTEX_DRIVER, sa->ch_icookp);

	mutex_enter(&in_use_l);
	j = in_use_index++;
	if (in_use_index >= SZ_INUSE)
		in_use_index = 0;
	mutex_exit(&in_use_l);

	sa->ch_big_owner = NULL;
	sa->ch_big_index = j;
	sa->ch_big_esb_free = NULL;
	for (i = 0; i < size; i++) {
		rbp = ch_alloc_big_esbbuf(sa, j);
		if (rbp == NULL)
			goto error;
		rbp->cs_next = sa->ch_big_esb_free;
		sa->ch_big_esb_free = rbp;

		/*
		 * add entry to owned list
		 */
		rbp->cs_owner = sa->ch_big_owner;
		sa->ch_big_owner = rbp;
	}
	return (1);

error:
	sa->ch_big_owner = NULL;

	/* free whatever we've already allocated */
	pe_rbuf_pool_free(sa);

	return (0);
}

/*
 * allocate receive buffer structure and dma mapped buffer (SGE_SM_BUF_SZ bytes)
 * note that we will DMA at a 2 byte offset for Solaris when checksum offload
 * is enabled.
 */
static ch_esb_t *
ch_alloc_small_esbbuf(ch_t *sa, uint32_t i)
{
	ch_esb_t *rbp;

	rbp = (ch_esb_t *)kmem_zalloc(sizeof (ch_esb_t), KM_SLEEP);
	if (rbp == NULL) {
		return ((ch_esb_t *)0);
	}

#if BYTE_ORDER == BIG_ENDIAN
	rbp->cs_buf = (caddr_t)ch_alloc_dma_mem(sa, 1, DMA_STREAM|DMA_SMALN,
	    SGE_SM_BUF_SZ(sa), &rbp->cs_pa, &rbp->cs_dh, &rbp->cs_ah);
#else
	rbp->cs_buf = (caddr_t)ch_alloc_dma_mem(sa, 0, DMA_STREAM|DMA_SMALN,
	    SGE_SM_BUF_SZ(sa), &rbp->cs_pa, &rbp->cs_dh, &rbp->cs_ah);
#endif

	if (rbp->cs_buf == NULL) {
		kmem_free(rbp, sizeof (ch_esb_t));
		return ((ch_esb_t *)0);
	}

	rbp->cs_sa = sa;
	rbp->cs_index = i;

	rbp->cs_frtn.free_func = (void (*)())&ch_small_rbuf_recycle;
	rbp->cs_frtn.free_arg  = (caddr_t)rbp;

	return (rbp);
}

/*
 * allocate receive buffer structure and dma mapped buffer (SGE_BG_BUF_SZ bytes)
 * note that we will DMA at a 2 byte offset for Solaris when checksum offload
 * is enabled.
 */
static ch_esb_t *
ch_alloc_big_esbbuf(ch_t *sa, uint32_t i)
{
	ch_esb_t *rbp;

	rbp = (ch_esb_t *)kmem_zalloc(sizeof (ch_esb_t), KM_SLEEP);
	if (rbp == NULL) {
		return ((ch_esb_t *)0);
	}

#if BYTE_ORDER == BIG_ENDIAN
	rbp->cs_buf = (caddr_t)ch_alloc_dma_mem(sa, 1, DMA_STREAM|DMA_BGALN,
	    SGE_BG_BUF_SZ(sa), &rbp->cs_pa, &rbp->cs_dh, &rbp->cs_ah);
#else
	rbp->cs_buf = (caddr_t)ch_alloc_dma_mem(sa, 0, DMA_STREAM|DMA_BGALN,
	    SGE_BG_BUF_SZ(sa), &rbp->cs_pa, &rbp->cs_dh, &rbp->cs_ah);
#endif

	if (rbp->cs_buf == NULL) {
		kmem_free(rbp, sizeof (ch_esb_t));
		return ((ch_esb_t *)0);
	}

	rbp->cs_sa = sa;
	rbp->cs_index = i;

	rbp->cs_frtn.free_func = (void (*)())&ch_big_rbuf_recycle;
	rbp->cs_frtn.free_arg  = (caddr_t)rbp;

	return (rbp);
}

/*
 * free entries on the receive buffer list.
 */
void
pe_rbuf_pool_free(ch_t *sa)
{
	ch_esb_t *rbp;

	mutex_enter(&sa->ch_small_esbl);

	/*
	 * Now set-up the rest to commit suicide.
	 */
	while (sa->ch_small_owner) {
		rbp = sa->ch_small_owner;
		sa->ch_small_owner = rbp->cs_owner;
		rbp->cs_owner = NULL;
		rbp->cs_flag = 1;
	}

	while ((rbp = sa->ch_small_esb_free) != NULL) {
		/* advance head ptr to next entry */
		sa->ch_small_esb_free = rbp->cs_next;
		/* free private buffer allocated in ch_alloc_esbbuf() */
		ch_free_dma_mem(rbp->cs_dh, rbp->cs_ah);
		/* free descripter buffer */
		kmem_free(rbp, sizeof (ch_esb_t));
	}

	mutex_exit(&sa->ch_small_esbl);

	/* destroy ch_esbl lock */
	mutex_destroy(&sa->ch_small_esbl);


	mutex_enter(&sa->ch_big_esbl);

	/*
	 * Now set-up the rest to commit suicide.
	 */
	while (sa->ch_big_owner) {
		rbp = sa->ch_big_owner;
		sa->ch_big_owner = rbp->cs_owner;
		rbp->cs_owner = NULL;
		rbp->cs_flag = 1;
	}

	while ((rbp = sa->ch_big_esb_free) != NULL) {
		/* advance head ptr to next entry */
		sa->ch_big_esb_free = rbp->cs_next;
		/* free private buffer allocated in ch_alloc_esbbuf() */
		ch_free_dma_mem(rbp->cs_dh, rbp->cs_ah);
		/* free descripter buffer */
		kmem_free(rbp, sizeof (ch_esb_t));
	}

	mutex_exit(&sa->ch_big_esbl);

	/* destroy ch_esbl lock */
	mutex_destroy(&sa->ch_big_esbl);
}

void
ch_small_rbuf_recycle(ch_esb_t *rbp)
{
	ch_t *sa = rbp->cs_sa;

	if (rbp->cs_flag) {
		uint32_t i;
		/*
		 * free private buffer allocated in ch_alloc_esbbuf()
		 */
		ch_free_dma_mem(rbp->cs_dh, rbp->cs_ah);

		i = rbp->cs_index;

		/*
		 * free descripter buffer
		 */
		kmem_free(rbp, sizeof (ch_esb_t));

		/*
		 * decrement count of receive buffers freed by callback
		 * We decrement here so anyone trying to do fini will
		 * only remove the driver once the counts go to 0.
		 */
		atomic_dec_32(&buffers_in_use[i]);

		return;
	}

	mutex_enter(&sa->ch_small_esbl);
	rbp->cs_next = sa->ch_small_esb_free;
	sa->ch_small_esb_free = rbp;
	mutex_exit(&sa->ch_small_esbl);

	/*
	 * decrement count of receive buffers freed by callback
	 */
	atomic_dec_32(&buffers_in_use[rbp->cs_index]);
}

/*
 * callback function from freeb() when esballoced mblk freed.
 */
void
ch_big_rbuf_recycle(ch_esb_t *rbp)
{
	ch_t *sa = rbp->cs_sa;

	if (rbp->cs_flag) {
		uint32_t i;
		/*
		 * free private buffer allocated in ch_alloc_esbbuf()
		 */
		ch_free_dma_mem(rbp->cs_dh, rbp->cs_ah);

		i = rbp->cs_index;

		/*
		 * free descripter buffer
		 */
		kmem_free(rbp, sizeof (ch_esb_t));

		/*
		 * decrement count of receive buffers freed by callback
		 * We decrement here so anyone trying to do fini will
		 * only remove the driver once the counts go to 0.
		 */
		atomic_dec_32(&buffers_in_use[i]);

		return;
	}

	mutex_enter(&sa->ch_big_esbl);
	rbp->cs_next = sa->ch_big_esb_free;
	sa->ch_big_esb_free = rbp;
	mutex_exit(&sa->ch_big_esbl);

	/*
	 * decrement count of receive buffers freed by callback
	 */
	atomic_dec_32(&buffers_in_use[rbp->cs_index]);
}

/*
 * get a pre-allocated, pre-mapped receive buffer from free list.
 * (used sge.c)
 */
ch_esb_t *
ch_get_small_rbuf(ch_t *sa)
{
	ch_esb_t *rbp;

	mutex_enter(&sa->ch_small_esbl);
	rbp = sa->ch_small_esb_free;
	if (rbp) {
		sa->ch_small_esb_free = rbp->cs_next;
	}
	mutex_exit(&sa->ch_small_esbl);

	return (rbp);
}

/*
 * get a pre-allocated, pre-mapped receive buffer from free list.
 * (used sge.c)
 */

ch_esb_t *
ch_get_big_rbuf(ch_t *sa)
{
	ch_esb_t *rbp;

	mutex_enter(&sa->ch_big_esbl);
	rbp = sa->ch_big_esb_free;
	if (rbp) {
		sa->ch_big_esb_free = rbp->cs_next;
	}
	mutex_exit(&sa->ch_big_esbl);

	return (rbp);
}

void
pe_detach(ch_t *sa)
{
	(void) sge_stop(sa->sge);

	pe_free_driver_resources(sa);
}

static void
pe_free_driver_resources(ch_t *sa)
{
	if (sa) {
		t1_free_sw_modules(sa);

		/* free pool of receive buffers */
		pe_rbuf_pool_free(sa);
	}
}

/*
 * Processes elmer0 external interrupts in process context.
 */
static void
ext_intr_task(ch_t *adapter)
{
	u32 enable;

	(void) elmer0_ext_intr_handler(adapter);

	/* Now reenable external interrupts */
	t1_write_reg_4(adapter, A_PL_CAUSE, F_PL_INTR_EXT);
	enable = t1_read_reg_4(adapter, A_PL_ENABLE);
	t1_write_reg_4(adapter, A_PL_ENABLE, enable | F_PL_INTR_EXT);
	adapter->slow_intr_mask |= F_PL_INTR_EXT;
}

/*
 * Interrupt-context handler for elmer0 external interrupts.
 */
void
t1_os_elmer0_ext_intr(ch_t *adapter)
{
	u32 enable = t1_read_reg_4(adapter, A_PL_ENABLE);

	adapter->slow_intr_mask &= ~F_PL_INTR_EXT;
	t1_write_reg_4(adapter, A_PL_ENABLE, enable & ~F_PL_INTR_EXT);
#ifdef NOTYET
	schedule_work(&adapter->ext_intr_handler_task);
#else
	ext_intr_task(adapter);
#endif
}

uint8_t *
t1_get_next_mcaddr(struct t1_rx_mode *rmp)
{
	uint8_t *addr = 0;
	if (rmp->mc) {
		addr = rmp->mc->cmc_mca;
		rmp->mc = rmp->mc->cmc_next;
	}
	return (addr);
}

void
pe_dma_handle_init(ch_t *chp, int cnt)
{
	free_dh_t *dhe;
#if defined(__sparc)
	int tcnt = cnt/2;

	for (; cnt; cnt--) {
		dhe = ch_get_dvma_handle(chp);
		if (dhe == NULL)
			break;
		mutex_enter(&chp->ch_dh_lck);
		dhe->dhe_next = chp->ch_vdh;
		chp->ch_vdh = dhe;
		mutex_exit(&chp->ch_dh_lck);
	}

	cnt += tcnt;
#endif
	while (cnt--) {
		dhe = ch_get_dma_handle(chp);
		if (dhe == NULL)
			return;
		mutex_enter(&chp->ch_dh_lck);
		dhe->dhe_next = chp->ch_dh;
		chp->ch_dh = dhe;
		mutex_exit(&chp->ch_dh_lck);
	}
}

/*
 * Write new values to the MTU table.  Caller must validate that the new MTUs
 * are in ascending order. params.mtus[] is initialized by init_mtus()
 * called in t1_init_sw_modules().
 */
#define	MTUREG(idx) (A_TP_MTU_REG0 + (idx) * 4)

static void
update_mtu_tab(ch_t *adapter)
{
	int i;

	for (i = 0; i < NMTUS; ++i) {
		int mtu = (unsigned int)adapter->params.mtus[i];

		t1_write_reg_4(adapter, MTUREG(i), mtu);
	}
}

static int
pe_change_mtu(ch_t *chp)
{
	struct cmac *mac = chp->port[0].mac;
	int ret;

	if (!mac->ops->set_mtu) {
		return (EOPNOTSUPP);
	}
	if (chp->ch_mtu < 68) {
		return (EINVAL);
	}
	if (ret = mac->ops->set_mtu(mac, chp->ch_mtu)) {
		return (ret);
	}

	return (0);
}

typedef struct fake_arp {
	char fa_dst[6];		/* ethernet header */
	char fa_src[6];		/* ethernet header */
	ushort_t fa_typ;		/* ethernet header */

	ushort_t fa_hrd;		/* arp */
	ushort_t fa_pro;
	char fa_hln;
	char fa_pln;
	ushort_t fa_op;
	char fa_src_mac[6];
	uint_t fa_src_ip;
	char fa_dst_mac[6];
	char fa_dst_ip[4];
} fake_arp_t;

/*
 * PR2928 & PR3309
 * construct packet in mblk and attach it to sge structure.
 */
static int
pe_make_fake_arp(ch_t *chp, unsigned char *arpp)
{
	pesge *sge = chp->sge;
	mblk_t *bp;
	fake_arp_t *fap;
	static char buf[6] = {0, 7, 0x43, 0, 0, 0};
	struct cpl_tx_pkt *cpl;

	bp = allocb(sizeof (struct fake_arp) + SZ_CPL_TX_PKT, BPRI_HI);
	if (bp == NULL) {
		return (1);
	}
	bzero(bp->b_rptr, sizeof (struct fake_arp) + SZ_CPL_TX_PKT);

	/* fill in cpl header */
	cpl = (struct cpl_tx_pkt *)bp->b_rptr;
	cpl->opcode = CPL_TX_PKT;
	cpl->iff = 0;			/* XXX port 0 needs fixing with NEMO */
	cpl->ip_csum_dis = 1;		/* no IP header cksum */
	cpl->l4_csum_dis = 1;		/* no tcp/udp cksum */
	cpl->vlan_valid = 0;		/* no vlan */

	fap = (fake_arp_t *)&bp->b_rptr[SZ_CPL_TX_PKT];

	bcopy(arpp, fap, sizeof (*fap));	/* copy first arp to mblk */

	bcopy(buf, fap->fa_dst, 6);		/* overwrite dst mac */
	chp->ch_ip = fap->fa_src_ip;		/* not used yet */
	bcopy(buf, fap->fa_dst_mac, 6);		/* overwrite dst mac */

	bp->b_wptr = bp->b_rptr + sizeof (struct fake_arp)+SZ_CPL_TX_PKT;

	sge_add_fake_arp(sge, (void *)bp);

	return (0);
}

/*
 * PR2928 & PR3309
 * free the fake arp's mblk on sge structure.
 */
void
pe_free_fake_arp(void *arp)
{
	mblk_t *bp = (mblk_t *)(arp);

	freemsg(bp);
}

/*
 * extract ip address of nic from first outgoing arp.
 */
static uint32_t
pe_get_ip(unsigned char *arpp)
{
	fake_arp_t fap;

	/*
	 * first copy packet to buffer so we know
	 * it will be properly aligned.
	 */
	bcopy(arpp, &fap, sizeof (fap));	/* copy first arp to buffer */
	return (fap.fa_src_ip);
}

/* ARGSUSED */
void
t1_os_link_changed(ch_t *obj, int port_id, int link_status,
    int speed, int duplex, int fc)
{
	gld_mac_info_t *macinfo = obj->ch_macp;
	if (link_status) {
		gld_linkstate(macinfo, GLD_LINKSTATE_UP);
		/*
		 * Link states should be reported to user
		 * whenever it changes
		 */
		cmn_err(CE_NOTE, "%s: link is up", adapter_name(obj));
	} else {
		gld_linkstate(macinfo, GLD_LINKSTATE_DOWN);
		/*
		 * Link states should be reported to user
		 * whenever it changes
		 */
		cmn_err(CE_NOTE, "%s: link is down", adapter_name(obj));
	}
}
