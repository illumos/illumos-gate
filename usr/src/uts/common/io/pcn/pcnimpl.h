/*
 * Copyright (c) 2011 Jason King.
 * Copyright (c) 2000 Berkeley Software Design, Inc.
 * Copyright (c) 1997, 1998, 1999, 2000
 *      Bill Paul <wpaul@ee.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifndef	_PCNIMPL_H
#define	_PCNIMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	PCN_VENDORID		0x1022
#define	PCN_DEVICEID_PCNET	0x2000
#define	PCN_DEVICEID_HOME	0x2001

typedef struct pcn_type {
	uint16_t	pcn_vid;
	uint16_t	pcn_did;
	char		*pcn_name;	/* ddi_set_prop takes char * */
} pcn_type_t;

#define	PCN_TXRECLAIM		8
#define	PCN_HEADROOM		34
#define	PCN_TXRESCHED		120

#define	PCN_RXSTAT_BAM		0x0008	/* broadcast address match */
#define	PCN_RXSTAT_LAFM		0x0010	/* logical address filter match */
#define	PCN_RXSTAT_PAM		0x0020	/* physical address match */
#define	PCN_RXSTAT_BPE		0x0080  /* bus parity error */
#define	PCN_RXSTAT_ENP		0x0100  /* end of packet */
#define	PCN_RXSTAT_STP		0x0200  /* start of packet */
#define	PCN_RXSTAT_BUFF		0x0400  /* buffer error */
#define	PCN_RXSTAT_CRC		0x0800  /* CRC error */
#define	PCN_RXSTAT_OFLOW	0x1000  /* rx overrun */
#define	PCN_RXSTAT_FRAM		0x2000  /* framing error */
#define	PCN_RXSTAT_ERR		0x4000  /* error summary */
#define	PCN_RXSTAT_OWN		0x8000
#define	PCN_RXSTAT_STR \
	"\020" \
	"\004BAM" \
	"\005LAFM" \
	"\006PAM" \
	"\010BPE" \
	"\011ENP" \
	"\012STP" \
	"\013BUFF" \
	"\014CRC" \
	"\015OFLOW" \
	"\016FRAM" \
	"\017ERR" \
	"\020OWN"

#define	PCN_RXLEN_MBO		0xF000
#define	PCN_RXLEN_BUFSZ		0x0FFF

typedef struct pcn_rx_desc {
	uint16_t	pcn_rxlen;
	uint16_t	pcn_rsvd0;
	uint16_t	pcn_bufsz;
	uint16_t	pcn_rxstat;
	uint32_t	pcn_rbaddr;
	uint32_t	pcn_uspace;
} pcn_rx_desc_t;

typedef struct pcn_tx_desc {
	uint32_t	pcn_txstat;
	uint32_t	pcn_txctl;
	uint32_t	pcn_tbaddr;
	uint32_t	pcn_uspace;
} pcn_tx_desc_t;

#define	PCN_TXCTL_OWN		0x80000000
#define	PCN_TXCTL_ERR		0x40000000	/* error summary */
#define	PCN_TXCTL_ADD_FCS	0x20000000	/* add FCS to pkt */
#define	PCN_TXCTL_MORE_LTINT	0x10000000
#define	PCN_TXCTL_ONE		0x08000000
#define	PCN_TXCTL_DEF		0x04000000
#define	PCN_TXCTL_STP		0x02000000
#define	PCN_TXCTL_ENP		0x01000000
#define	PCN_TXCTL_BPE		0x00800000
#define	PCN_TXCTL_MBO		0x0000F000
#define	PCN_TXCTL_BUFSZ		0x00000FFF
#define	PCN_TXCTL_STR \
	"\020" \
	"\040OWN" \
	"\037ERR" \
	"\036ADD_FCS" \
	"\035MORE_LTINT" \
	"\034ONE" \
	"\033DEF" \
	"\032STP" \
	"\031ENP" \
	"\030BPE"

typedef struct pcn_buf {
	caddr_t			pb_buf;
	ddi_dma_handle_t	pb_dmah;
	ddi_acc_handle_t	pb_acch;
	uint32_t		pb_paddr;
} pcn_buf_t;

/* Constants, do not change */
#define	PCN_BUFSZ	(1664)
#define	PCN_MCHASH	(64)

/* Number of descriptor entries */
#define	PCN_RXRING	64
#define	PCN_TXRING	256

typedef struct pcn {
	dev_info_t		*pcn_dip;
	mac_handle_t		pcn_mh;
	mii_handle_t		pcn_mii;
	uint16_t		pcn_cachesize;
	int			pcn_flags;
	int			pcn_instance;
	kmutex_t		pcn_xmtlock;
	kmutex_t		pcn_intrlock;
	kmutex_t		pcn_reglock;
	ddi_iblock_cookie_t	pcn_icookie;
	uint_t			pcn_int_pri;
	int			pcn_type;
	int8_t			pcn_extphyaddr;

	/*
	 * Register and DMA access
	 */
	uintptr_t		pcn_regs;
	ddi_acc_handle_t	pcn_regshandle;

	/*
	 * Receive descriptors.
	 */
	int			pcn_rxhead;
	pcn_rx_desc_t		*pcn_rxdescp;
	ddi_dma_handle_t	pcn_rxdesc_dmah;
	ddi_acc_handle_t	pcn_rxdesc_acch;
	uint32_t		pcn_rxdesc_paddr;
	pcn_buf_t		**pcn_rxbufs;

	/*
	 * Transmit descriptors.
	 */
	int			pcn_txreclaim;
	int			pcn_txsend;
	int			pcn_txavail;
	pcn_tx_desc_t		*pcn_txdescp;
	ddi_dma_handle_t	pcn_txdesc_dmah;
	ddi_acc_handle_t	pcn_txdesc_acch;
	uint32_t		pcn_txdesc_paddr;
	pcn_buf_t		**pcn_txbufs;
	hrtime_t		pcn_txstall_time;
	boolean_t		pcn_wantw;

	/*
	 * Address management.
	 */
	uchar_t			pcn_addr[ETHERADDRL];
	boolean_t		pcn_promisc;
	uint16_t		pcn_mccount[PCN_MCHASH];
	uint16_t		pcn_mctab[PCN_MCHASH / 16];

	/*
	 * stats
	 */
	uint64_t		pcn_ipackets;
	uint64_t		pcn_opackets;
	uint64_t		pcn_rbytes;
	uint64_t		pcn_obytes;
	uint64_t		pcn_brdcstxmt;
	uint64_t		pcn_multixmt;
	uint64_t		pcn_brdcstrcv;
	uint64_t		pcn_multircv;
	uint64_t		pcn_norcvbuf;
	uint64_t		pcn_errrcv;
	uint64_t		pcn_errxmt;
	uint64_t		pcn_missed;
	uint64_t		pcn_underflow;
	uint64_t		pcn_overflow;
	uint64_t		pcn_align_errors;
	uint64_t		pcn_fcs_errors;
	uint64_t		pcn_carrier_errors;
	uint64_t		pcn_collisions;
	uint64_t		pcn_ex_collisions;
	uint64_t		pcn_tx_late_collisions;
	uint64_t		pcn_defer_xmts;
	uint64_t		pcn_first_collisions;
	uint64_t		pcn_multi_collisions;
	uint64_t		pcn_sqe_errors;
	uint64_t		pcn_macxmt_errors;
	uint64_t		pcn_macrcv_errors;
	uint64_t		pcn_toolong_errors;
	uint64_t		pcn_runt;
	uint64_t		pcn_jabber;
} pcn_t;

/* Flags */
#define	PCN_RUNNING		(1L << 0)
#define	PCN_SUSPENDED		(1L << 1)
#define	PCN_INTR_ENABLED	(1L << 2)
#define	PCN_FLAGSTR \
	"\020" \
	"\001RUNNING" \
	"\002SUSPENDED" \
	"\003INTR_ENABLED"
#define	IS_RUNNING(p)	((p)->pcn_flags & PCN_RUNNING)
#define	IS_SUSPENDED(p)	((p)->pcn_flags & PCN_SUSPENDED)

#define	SYNCTXDESC(pcnp, index, who) \
	(void) ddi_dma_sync(pcnp->pcn_txdesc_dmah, \
	    (index * sizeof (pcn_tx_desc_t)), sizeof (pcn_tx_desc_t), who)

#define	SYNCRXDESC(pcnp, index, who) \
	(void) ddi_dma_sync(pcnp->pcn_rxdesc_dmah, \
	    (index * sizeof (pcn_rx_desc_t)), sizeof (pcn_rx_desc_t), who)

#define	SYNCBUF(pb, len, who) \
	(void) ddi_dma_sync(pb->pb_dmah, 0, len, who)

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _PCNIMPL_H */
