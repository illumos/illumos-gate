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

#ifndef _SYS_IB_CLIENTS_IBD_H
#define	_SYS_IB_CLIENTS_IBD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IETF defined IPoIB encapsulation header, with 2b of ethertype
 * followed by 2 reserved bytes. This is at the start of the
 * datagram sent to and received over the wire by the driver.
 */
typedef struct ipoib_header {
	ushort_t	ipoib_type;
	ushort_t	ipoib_mbz;
} ipoib_hdr_t;

#define	IPOIB_HDRSIZE	sizeof (struct ipoib_header)

/*
 * IETF defined IPoIB link address; IBA QPN, followed by GID,
 * which has a prefix and suffix, as reported via ARP.
 */
typedef struct ipoib_mac {
	uint32_t	ipoib_qpn;
	uint32_t	ipoib_gidpref[2];
	uint32_t	ipoib_gidsuff[2];
} ipoib_mac_t;

#define	IPOIB_ADDRL	sizeof (struct ipoib_mac)

/*
 * Pseudo header prepended to datagram in DLIOCRAW transmit path
 * and when GLD hands the datagram to the gldm_send entry point.
 */
typedef struct ipoib_ptxhdr {
	ipoib_mac_t	ipoib_dest;
	ipoib_hdr_t	ipoib_rhdr;
} ipoib_ptxhdr_t;

#define	IPOIBDLSAP(p, offset)	((ipoib_ptxhdr_t *)((caddr_t)(p)+offset))

/*
 * The pseudo-GRH structure that sits before the data in the
 * receive buffer, and is overlaid on top of the real GRH.
 * The driver sets the ipoib_vertcflow to 0 if the pseudo-GRH
 * does not hold valid information. If it is indicated valid,
 * the driver must additionally provide the sender's qpn in
 * network byte order in ipoib_sqpn, and not touch the
 * remaining parts which were DMA'ed in by the IBA hardware.
 */
typedef struct ipoib_pgrh {
	uint32_t	ipoib_vertcflow;
	uint32_t	ipoib_sqpn;
	uint32_t	ipoib_sgid_pref[2];
	uint32_t	ipoib_sgid_suff[2];
	uint32_t	ipoib_dgid_pref[2];
	uint32_t	ipoib_dgid_suff[2];
} ipoib_pgrh_t;

/*
 * The GRH is also dma'ed into recv buffers, thus space needs
 * to be allocated for them.
 */
#define	IPOIB_GRH_SIZE	sizeof (ipoib_pgrh_t)

#if defined(_KERNEL) && !defined(_BOOT)

#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ib_pkt_hdrs.h>
#include <sys/list.h>
#include <sys/mac.h>
#include <sys/mac_ib.h>
#include <sys/modhash.h>

#define	IBD_HIWAT	(64*1024)	/* drv flow control high water */
#define	IBD_LOWAT	(1024)		/* drv flow control low water */
#define	IBD_IDNUM	0		/* ibd module ID; zero works */

#define	IBD_MAX_SQSEG	3
#define	IBD_MAX_RQSEG	1

typedef struct ibd_copybuf_s {
	ibt_mr_hdl_t		ic_mr_hdl;
	ibt_wr_ds_t		ic_sgl;
	ibt_mr_desc_t		ic_mr_desc;
	uint8_t			*ic_bufaddr;
} ibd_copybuf_t;

typedef struct ibd_mblkbuf_s {
	ibt_mr_hdl_t		im_mr_hdl;
	ibt_mr_desc_t		im_mr_desc;
} ibd_mblkbuf_t;

/*
 * Structure to encapsulate various types of async requests.
 */
typedef struct ibd_acache_rq {
	struct list_node 	rq_list; 	/* list of pending work */
	int			rq_op;		/* what operation */
	ipoib_mac_t		rq_mac;
	ib_gid_t		rq_gid;
	void			*rq_ptr;
} ibd_req_t;


typedef struct ibd_mcache {
	struct list_node	mc_list;	/* full/non list */
	uint8_t			mc_jstate;
	boolean_t		mc_fullreap;
	ibt_mcg_info_t		mc_info;
	ibd_req_t		mc_req;		/* to queue LEAVE req */
} ibd_mce_t;

typedef struct ibd_acache_s {
	struct list_node	ac_list;	/* free/active list */
	ibt_ud_dest_hdl_t	ac_dest;
	ipoib_mac_t		ac_mac;
	uint32_t		ac_ref;
	ibd_mce_t		*ac_mce;	/* for MCG AHs */
} ibd_ace_t;

typedef enum {IBD_WQE_SEND, IBD_WQE_RECV} ibd_wqe_type_t;

typedef struct ibd_wqe_s {
	struct ibd_wqe_s	*w_next;
	struct ibd_wqe_s	*w_prev;
	ibd_wqe_type_t		w_type;
	ibd_copybuf_t		w_copybuf;
	mblk_t			*im_mblk;
} ibd_wqe_t;

typedef struct ibd_swqe_s {
	ibd_wqe_t		w_ibd_swqe;
	ibt_send_wr_t		w_swr;
	ibt_wr_ds_t		w_smblk_sgl[IBD_MAX_SQSEG];
	ibd_mblkbuf_t		w_smblkbuf[IBD_MAX_SQSEG];
	ibd_ace_t		*w_ahandle;
} ibd_swqe_t;

#define	swqe_next		w_ibd_swqe.w_next
#define	swqe_prev		w_ibd_swqe.w_prev
#define	swqe_type		w_ibd_swqe.w_type
#define	swqe_copybuf		w_ibd_swqe.w_copybuf
#define	swqe_im_mblk		w_ibd_swqe.im_mblk
#define	SWQE_TO_WQE(swqe)	(ibd_wqe_t *)&((swqe)->w_ibd_swqe)
#define	WQE_TO_SWQE(wqe)	(ibd_swqe_t *)wqe

typedef struct ibd_rwqe_s {
	ibd_wqe_t		w_ibd_rwqe;
	struct ibd_state_s	*w_state;
	ibt_recv_wr_t		w_rwr;
	boolean_t		w_freeing_wqe;
	frtn_t			w_freemsg_cb;
} ibd_rwqe_t;

#define	rwqe_next		w_ibd_rwqe.w_next
#define	rwqe_prev		w_ibd_rwqe.w_prev
#define	rwqe_type		w_ibd_rwqe.w_type
#define	rwqe_copybuf		w_ibd_rwqe.w_copybuf
#define	rwqe_im_mblk		w_ibd_rwqe.im_mblk
#define	RWQE_TO_WQE(rwqe)	(ibd_wqe_t *)&((rwqe)->w_ibd_rwqe)
#define	WQE_TO_RWQE(wqe)	(ibd_rwqe_t *)wqe


typedef struct ibd_list_s {
	ibd_wqe_t		*dl_head;
	ibd_wqe_t		*dl_tail;
	union {
		boolean_t	pending_sends;
		uint32_t	bufs_outstanding;
	} ustat;
	uint32_t		dl_cnt;
	kmutex_t		dl_mutex;
} ibd_list_t;

#define	dl_pending_sends	ustat.pending_sends
#define	dl_bufs_outstanding	ustat.bufs_outstanding

/*
 * This structure maintains information per port per HCA
 * (per network interface).
 */
typedef struct ibd_state_s {
	dev_info_t		*id_dip;
	ibt_clnt_hdl_t		id_ibt_hdl;
	ibt_hca_hdl_t		id_hca_hdl;
	ibt_pd_hdl_t		id_pd_hdl;
	kmem_cache_t		*id_req_kmc;

	uint32_t		id_max_sqseg;
	ibd_list_t		id_tx_list;
	ddi_softintr_t		id_tx;
	uint32_t		id_tx_sends;
	kmutex_t		id_txcomp_lock;
	ibt_cq_hdl_t		id_scq_hdl;
	ibt_wc_t		*id_txwcs;
	uint32_t		id_txwcs_size;

	uint32_t		id_num_rwqe;
	ibd_list_t		id_rx_list;
	ddi_softintr_t		id_rx;
	ibt_cq_hdl_t		id_rcq_hdl;
	void			*id_fifos;
	int			id_nfifos;
	ibt_wc_t		*id_rxwcs;
	uint32_t		id_rxwcs_size;
	kmutex_t		id_rx_mutex;

	ibt_channel_hdl_t	id_chnl_hdl;
	ib_pkey_t		id_pkey;
	uint16_t		id_pkix;
	uint8_t			id_port;
	ibt_mcg_info_t		*id_mcinfo;

	mac_handle_t		id_mh;
	ib_gid_t		id_sgid;
	ib_qpn_t		id_qpnum;
	ipoib_mac_t		id_macaddr;
	ib_gid_t		id_mgid;
	ipoib_mac_t		id_bcaddr;

	int			id_mtu;
	uchar_t			id_scope;

	struct list		id_req_list;

	kmutex_t		id_acache_req_lock;
	kcondvar_t		id_acache_req_cv;
	kt_did_t		id_async_thrid;

	kmutex_t		id_ac_mutex;
	mod_hash_t		*id_ah_active_hash;
	struct list		id_ah_free;
	struct list		id_ah_active;
	ipoib_mac_t		id_ah_addr;
	ibd_req_t		id_ah_req;
	char			id_ah_op;
	ibd_ace_t		*id_ac_list;

	kmutex_t		id_mc_mutex;
	struct list		id_mc_full;
	struct list		id_mc_non;

	kmutex_t		id_trap_lock;
	kcondvar_t		id_trap_cv;
	boolean_t		id_trap_stop;
	uint32_t		id_trap_inprog;

	char			id_prom_op;

	kmutex_t		id_sched_lock;
	boolean_t		id_sched_needed;

	kmutex_t		id_link_mutex;
	link_state_t		id_link_state;
	uint64_t		id_link_speed;

	uint64_t		id_ah_error;
	uint64_t		id_rx_short;
	uint64_t		id_num_intrs;
	uint64_t		id_tx_short;
	uint32_t		id_num_swqe;

	uint64_t		id_xmt_bytes;
	uint64_t		id_recv_bytes;
	uint64_t		id_multi_xmt;
	uint64_t		id_brd_xmt;
	uint64_t		id_multi_rcv;
	uint64_t		id_brd_rcv;
	uint64_t		id_xmt_pkt;
	uint64_t		id_rcv_pkt;
} ibd_state_t;

#endif /* _KERNEL && !_BOOT */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_CLIENTS_IBD_H */
