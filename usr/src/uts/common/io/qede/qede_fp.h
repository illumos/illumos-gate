/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef _QEDE_FP_H
#define _QEDE_FP_H

#define	RX_INDICATE_UPSTREAM(rx_ring, mp) \
	mac_rx_ring(rx_ring->qede->mac_handle, \
	    rx_ring->mac_ring_handle, mp, \
	    rx_ring->mr_gen_num)

#define	MAX_TX_RING_SIZE		8192

#define	RESUME_TX(tx_ring)  mac_tx_ring_update(tx_ring->qede->mac_handle, \
			    tx_ring->mac_ring_handle)

#define CQE_FLAGS_ERR   (PARSING_AND_ERR_FLAGS_IPHDRERROR_MASK <<   \
			PARSING_AND_ERR_FLAGS_IPHDRERROR_SHIFT |   \
			PARSING_AND_ERR_FLAGS_L4CHKSMERROR_MASK << \
			PARSING_AND_ERR_FLAGS_L4CHKSMERROR_SHIFT | \
			PARSING_AND_ERR_FLAGS_TUNNELIPHDRERROR_MASK << \
			PARSING_AND_ERR_FLAGS_TUNNELIPHDRERROR_SHIFT | \
			PARSING_AND_ERR_FLAGS_TUNNELL4CHKSMERROR_MASK << \
			PARSING_AND_ERR_FLAGS_TUNNELL4CHKSMERROR_SHIFT)

/*
 * VB: Keeping such perf. tuning macros as ifndefs so that
 * they can be collectively tuned from Makefile when exp.
 * are to be done
 */
#ifndef	QEDE_POLL_ALL
#define	QEDE_POLL_ALL			INT_MAX
#endif
#ifndef	QEDE_MAX_RX_PKTS_PER_INTR
#define	QEDE_MAX_RX_PKTS_PER_INTR	128
#endif

#ifndef	QEDE_TX_MAP_PATH_PAUSE_THRESHOLD
#define	QEDE_TX_MAP_PATH_PAUSE_THRESHOLD	128	
#endif

#ifndef	QEDE_TX_COPY_PATH_PAUSE_THRESHOLD
#define	QEDE_TX_COPY_PATH_PAUSE_THRESHOLD	8
#endif

#define ETHER_VLAN_HEADER_LEN		sizeof (struct ether_vlan_header)
#define ETHER_HEADER_LEN                sizeof (struct ether_header)
#define IP_HEADER_LEN                   sizeof (ipha_t)

#ifndef	MBLKL
#define	MBLKL(_mp_)	((uintptr_t)(_mp_)->b_wptr - (uintptr_t)(_mp_)->b_rptr)
#endif

#define	UPDATE_RX_PROD(_ptr, data) \
	internal_ram_wr(&(_ptr)->qede->edev.hwfns[0], \
	    (_ptr)->hw_rxq_prod_addr, sizeof (data), \
	    (u32 *)&data);

#define	BD_SET_ADDR_LEN(_bd, _addr, _len) \
       do { \
       	(_bd)->addr.hi = HOST_TO_LE_32(U64_HI(_addr)); \
	(_bd)->addr.lo = HOST_TO_LE_32(U64_LO(_addr)); \
	(_bd)->nbytes = HOST_TO_LE_32(_len); \
       } while (0)

enum qede_xmit_mode {
	XMIT_MODE_UNUSED,
	USE_DMA_BIND,
	USE_BCOPY,
	USE_PULLUP
};

enum qede_xmit_status {
	XMIT_FAILED,
	XMIT_DONE,
	XMIT_FALLBACK_BCOPY,
	XMIT_FALLBACK_PULLUP,
	XMIT_PAUSE_QUEUE,
	XMIT_TOO_MANY_COOKIES
};

/*
 * Maintain the metadata of the
 * tx packet in one place
 */
typedef struct qede_tx_pktinfo_s {
	u32		total_len;
	u32		mblk_no;
	u32		cksum_flags;

	/* tso releated */
	bool		use_lso;
	u16		mss;

	bool 	pulled_up;

	/* hdr parse data */
	u16		ether_type;
	u16		mac_hlen;
	u16		ip_hlen;
	u16		l4_hlen;
	u16		total_hlen;
	u16		l4_proto;
	u16		vlan_tag;
} qede_tx_pktinfo_t;

typedef struct qede_tx_bcopy_pkt_s {
	mblk_t *mp;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	u32			ncookies;
	u32			offset;
	u64			phys_addr;
	void *virt_addr;
	u32			padding;
} qede_tx_bcopy_pkt_t;

typedef	struct qede_tx_bcopy_list_s {
	qede_tx_bcopy_pkt_t *bcopy_pool;
	qede_tx_bcopy_pkt_t *free_list[MAX_TX_RING_SIZE];
	u16		head;
	u16		tail;
	kmutex_t	lock;
	size_t		size;
} qede_tx_bcopy_list_t;

typedef	struct qede_dma_handle_entry_s {
	mblk_t *mp;
	ddi_dma_handle_t	dma_handle;
	struct qede_dma_handle_entry_s *next;
} qede_dma_handle_entry_t;

typedef	struct qede_dma_handles_list_s {
	qede_dma_handle_entry_t	*dmah_pool;
	qede_dma_handle_entry_t *free_list[MAX_TX_RING_SIZE];
	u16		head;
	u16		tail;
	kmutex_t	lock;
	size_t		size;
} qede_dma_handles_list_t;

typedef struct qede_tx_recycle_list_s {
	qede_tx_bcopy_pkt_t *bcopy_pkt;
	qede_dma_handle_entry_t	*dmah_entry;
} qede_tx_recycle_list_t;

mblk_t *qede_ring_tx(void *arg, mblk_t *mp);

#endif  /* !_QEDE_FP_H */
