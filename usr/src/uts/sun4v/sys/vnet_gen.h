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

#ifndef _VNET_GEN_H
#define	_VNET_GEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vgen_stats.h>

#define	VGEN_SUCCESS		(0)	/* successful return */
#define	VGEN_FAILURE		(-1)	/* unsuccessful return */

#define	VGEN_NUM_VER		1	/* max # of vgen versions */

#define	VGEN_LOCAL	1	/* local ldc end-point */
#define	VGEN_PEER	2	/* peer ldc end-point */

/* vgen_t flags */
#define	VGEN_STOPPED		0x0
#define	VGEN_STARTED		0x1

#define	KMEM_FREE(_p)		kmem_free((_p), sizeof (*(_p)))

#define	VGEN_INIT_MCTAB_SIZE	16	/* initial size of multicast table */

#define	READ_ENTER(x)	rw_enter(x, RW_READER)
#define	WRITE_ENTER(x)	rw_enter(x, RW_WRITER)
#define	RW_EXIT(x)	rw_exit(x)

/* channel flags */
#define	CHANNEL_ATTACHED	0x1
#define	CHANNEL_STARTED		0x2

/* transmit return values */
#define	VGEN_TX_SUCCESS		0	/* transmit success */
#define	VGEN_TX_FAILURE		1	/* transmit failure */
#define	VGEN_TX_NORESOURCES	2	/* out of tbufs/txds */

/* private descriptor flags */
#define	VGEN_PRIV_DESC_FREE	0x0	/* desc is available */
#define	VGEN_PRIV_DESC_BUSY	0x1	/* desc in use */

#define	LDC_TO_VNET(ldcp)  ((ldcp)->portp->vgenp->vnetp)
#define	LDC_TO_VGEN(ldcp)  ((ldcp)->portp->vgenp)

/* receive thread flags */
#define	VGEN_WTHR_DATARCVD 		0x01 /* data received */
#define	VGEN_WTHR_STOP 			0x02 /* stop worker thr request */
#define	VGEN_WTHR_PROCESSING		0x04 /* worker thr awake & processing */

#define	VGEN_LDC_MTU		64	/* ldc pkt transfer mtu */
#define	VGEN_LDC_UP_DELAY	100	/* usec delay between ldc_up retries */
#define	VGEN_LDC_CLOSE_DELAY	100	/* usec delay between ldc_cl retries */
#define	VGEN_LDC_UNINIT_DELAY	100	/* usec delay between uninit retries */
#define	VGEN_TXWD_INTERVAL	1000	/* tx watchdog freq in msec */
#define	VGEN_TXWD_TIMEOUT	1000	/* tx watchdog timeout in msec */

#define	VGEN_NUM_VMPOOLS	3	/* number of vio mblk pools */

#define	VGEN_DBLK_SZ_128	128	/* data buffer size 128 bytes */
#define	VGEN_DBLK_SZ_256	256	/* data buffer size 256 bytes */
#define	VGEN_DBLK_SZ_2048	2048	/* data buffer size 2K bytes */
#define	VGEN_NRBUFS		512	/* number of receive bufs */

#define	VGEN_TXDBLK_SZ		2048	/* Tx data buffer size */

#define	VGEN_NUM_DESCRIPTORS_MIN	128	/* min # of descriptors */

static struct ether_addr etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
/*
 * MIB II broadcast/multicast packets
 */
#define	IS_BROADCAST(ehp) \
		(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)

/*
 * The handshake process consists of 5 phases defined below, with VH_PHASE0
 * being the pre-handshake phase and VH_DONE is the phase to indicate
 * successful completion of all phases. Each phase may have one to several
 * handshake states which are required to complete successfully to move to the
 * next phase. See functions vgen_handshake() and vgen_handshake_done() for
 * more details.
 */
/* Handshake phases */
enum {	VH_PHASE0, VH_PHASE1, VH_PHASE2, VH_PHASE3, VH_PHASE4, VH_DONE = 0x80 };

/* Handshake states */
enum {

	VER_INFO_SENT	=	0x1,
	VER_ACK_RCVD	=	0x2,
	VER_INFO_RCVD	=	0x4,
	VER_ACK_SENT	=	0x8,
	VER_NEGOTIATED	=	(VER_ACK_RCVD | VER_ACK_SENT),

	ATTR_INFO_SENT	=	0x10,
	ATTR_ACK_RCVD	=	0x20,
	ATTR_INFO_RCVD	=	0x40,
	ATTR_ACK_SENT	=	0x80,
	ATTR_INFO_EXCHANGED	=	(ATTR_ACK_RCVD | ATTR_ACK_SENT),

	DRING_INFO_SENT	=	0x100,
	DRING_ACK_RCVD	=	0x200,
	DRING_INFO_RCVD	=	0x400,
	DRING_ACK_SENT	=	0x800,
	DRING_INFO_EXCHANGED	=	(DRING_ACK_RCVD | DRING_ACK_SENT),

	RDX_INFO_SENT	=	0x1000,
	RDX_ACK_RCVD	=	0x2000,
	RDX_INFO_RCVD	=	0x4000,
	RDX_ACK_SENT	=	0x8000,
	RDX_EXCHANGED	=	(RDX_ACK_RCVD | RDX_ACK_SENT)

};

/* reset flags */
typedef enum {
	VGEN_FLAG_EVT_RESET = 0x1,	/* channel reset event */
	VGEN_FLAG_NEED_LDCRESET = 0x2,	/* need channel reset */
	VGEN_FLAG_UNINIT = 0x4		/* channel tear down */
} vgen_reset_flags_t;

/* caller information needed in some code paths */
typedef enum {
	VGEN_LDC_CB = 0x1,	/* ldc callback handler */
	VGEN_MSG_THR = 0x2,	/* vio message worker thread */
	VGEN_OTHER = 0x4	/* other threads - tx etc */
} vgen_caller_t;

/* get the address of next tbuf */
#define	NEXTTBUF(ldcp, tbufp)	(((tbufp) + 1) == (ldcp)->tbufendp    \
		? (ldcp)->tbufp : ((tbufp) + 1))

/* increment recv index */
#define	INCR_RXI(i, ldcp)	\
		((i) = (((i) + 1) & ((ldcp)->num_rxds - 1)))

/* decrement recv index */
#define	DECR_RXI(i, ldcp)	\
		((i) = (((i) - 1) & ((ldcp)->num_rxds - 1)))

/* increment tx index */
#define	INCR_TXI(i, ldcp)	\
		((i) = (((i) + 1) & ((ldcp)->num_txds - 1)))

/* decrement tx index */
#define	DECR_TXI(i, ldcp)	\
		((i) = (((i) - 1) & ((ldcp)->num_txds - 1)))

/* bounds check rx index */
#define	CHECK_RXI(i, ldcp)	\
		(((i) >= 0) && ((i) < (ldcp)->num_rxds))

/* bounds check tx index */
#define	CHECK_TXI(i, ldcp)	\
		(((i) >= 0) && ((i) < (ldcp)->num_txds))

#ifdef DEBUG

/* Error injection codes */
#define	VGEN_ERR_HVER		0x1	/* handshake version */
#define	VGEN_ERR_HTIMEOUT	0x2	/* handshake timeout */
#define	VGEN_ERR_HSID		0x4	/* handshake session id */
#define	VGEN_ERR_HSTATE		0x8	/* handshake state */
#define	VGEN_ERR_TXTIMEOUT	0x10	/* tx timeout */
#define	VGEN_ERR_RXLOST		0x20	/* rx lost pkts */

#endif
/* private descriptor */
typedef struct vgen_priv_desc {
	uint64_t		flags;		/* flag bits */
	vnet_public_desc_t	*descp;		/* associated public desc */
	ldc_mem_handle_t	memhandle;	/* mem handle for data */
	caddr_t			datap;		/* prealloc'd tx data buffer */
	uint64_t		datalen;	/* total actual datalen */
	uint64_t		ncookies;	/* num ldc_mem_cookies */
	ldc_mem_cookie_t	memcookie[MAX_COOKIES];	/* data cookies */
} vgen_private_desc_t;

/*
 * Handshake parameters (per vio_mailbox.h) of each ldc end point, used
 * during handshake negotiation.
 */
typedef struct vgen_handshake_params {
	/* version specific params */
	uint16_t	ver_major;		/* major version number */
	uint16_t	ver_minor;		/* minor version number */
	uint8_t		dev_class;		/* device class */

	/* attributes specific params */
	uint64_t		mtu;		/* max transfer unit size */
	uint64_t		addr;		/* address of the device */
	uint8_t			addr_type;	/* type of address */
	uint8_t			xfer_mode;	/* SHM or PKT */
	uint16_t		ack_freq;	/* dring data ack freq */
	uint32_t		physlink_update; /* physlink updates */
	uint8_t			dring_mode;	/* Descriptor ring mode */

	/* descriptor ring params */
	uint32_t		num_desc;	/* # of descriptors in ring */
	uint32_t		desc_size;	/* size of descriptor */
	ldc_mem_cookie_t	dring_cookie;	/* desc ring cookie */
	uint32_t		dring_ncookies;	/* # of dring cookies */
	uint64_t		dring_ident;	/* ident=0 for INFO msg */
	boolean_t		dring_ready;	/* dring ready flag */
} vgen_hparams_t;

/* version info */
typedef struct vgen_ver {
	uint16_t	ver_major;		/* major version number */
	uint16_t	ver_minor;		/* minor version number */
} vgen_ver_t;

/*
 * vnet-protocol-version dependent function prototypes.
 */
typedef int	(*vgen_ldctx_t) (void *, mblk_t *);
typedef void	(*vgen_ldcrx_pktdata_t) (void *, void *, uint32_t);
typedef int	(*vgen_ldcrx_dringdata_t) (void *, void *);

/*
 * LDC end point abstraction in vnet. This structure holds all the information
 * that is required to configure and use the Channel for data transfers with
 * the peer LDC end point (vnet or vswitch), using VIO Protocol.
 */
typedef struct vgen_ldc {

	struct vgen_port	*portp;		/* associated port */

	/*
	 * Locks:
	 * locking hierarchy when more than one lock is held concurrently:
	 * cblock > rxlock > txlock > tclock.
	 */
	kmutex_t		cblock;		/* sync callback processing */
	kmutex_t		txlock;		/* protect txd alloc */
	kmutex_t		tclock;		/* tx reclaim lock */
	kmutex_t		wrlock;		/* sync transmits */
	kmutex_t		rxlock;		/* sync reception */
	kmutex_t		pollq_lock;	/* sync polling and rxworker */

	/*
	 * Channel and Handshake Info
	 */
	uint64_t		ldc_id;		/* channel number */
	uint64_t		ldc_handle;	/* channel handle */
	ldc_status_t		ldc_status;	/* channel status */
	vgen_ver_t		vgen_versions[VGEN_NUM_VER]; /* versions */
	int			hphase;		/* handshake phase */
	int			hstate;		/* handshake state bits */
	link_state_t		link_state;	/* channel link state */
#ifdef	VNET_IOC_DEBUG
	boolean_t		link_down_forced; /* forced link down */
#endif
	uint32_t		local_sid;	/* local session id */
	uint32_t		peer_sid;	/* session id of peer */
	vgen_hparams_t		local_hparams;	/* local handshake params */
	vgen_hparams_t		peer_hparams;	/* peer's handshake params */
	timeout_id_t		htid;		/* handshake wd timeout id */
	timeout_id_t		cancel_htid;	/* cancel handshake watchdog */
	uint8_t			dring_mtype;	/* dring mem map type */
	uint64_t		*ldcmsg;	/* msg buffer for ldc_read() */
	uint64_t		msglen;		/* size of ldcmsg */
	uint32_t		flags;		/* flags */
	uint_t			reset_in_progress; /* channel being reset */
	uint32_t		hretries;	/* handshake retry count */
	uint32_t		ldc_reset_count; /* # of channel resets */

	/*
	 * Transmit Specific Fields
	 */
	/* TX-Common (Used in both TxDring and RxDringData modes) */
	uint32_t		num_txds;	   /* # of descriptors */
	uint32_t		tx_dring_ncookies; /* # of dring cookies */
	ldc_dring_handle_t	tx_dring_handle;   /* dring handle */
	ldc_mem_cookie_t	tx_dring_cookie;   /* dring cookie */
	uint32_t		next_txi;	   /* free descriptor index */
	caddr_t			tx_datap;	   /* tx data area */
	size_t			tx_data_sz;	   /* size of data area */
	size_t			tx_dblk_sz;	   /* size of data blk */
	timeout_id_t		wd_tid;		   /* watchdog timeout id */
	boolean_t		tx_blocked;	   /* flow controlled */
	clock_t			tx_blocked_lbolt;  /* flow controlled time */
	boolean_t		resched_peer;	   /* restart peer needed */
	uint32_t		resched_peer_txi;  /* index to resched peer */
	vgen_ldctx_t		tx;		   /* transmit function */
	vgen_ldctx_t		tx_dringdata;	   /* dring transmit function */

	/* TX-TxDring mode */
	vnet_public_desc_t	*txdp;		/* exported dring */
	vgen_private_desc_t	*tbufp;		/* dring associated resources */
	vgen_private_desc_t	*tbufendp;	/* tbuf ring end */
	vgen_private_desc_t	*next_tbufp;	/* free tbuf */
	vgen_private_desc_t	*cur_tbufp;	/* reclaim tbuf */
	uint32_t		cur_txi;	/* reclaim descrptor index */
	uint64_t		next_txseq;	/* msg seqnum */
	clock_t			reclaim_lbolt;	/* time of last reclaim */

	/* TX-RxDringData mode */
	uint32_t		tx_data_ncookies; /* # of data cookies */
	ldc_mem_handle_t	tx_data_handle;	  /* mapped data handle */
	ldc_mem_cookie_t	*tx_data_cookie;  /* mapped data cookies */
	vnet_rx_dringdata_desc_t *mtxdp;	  /* mapped dring */
	uint32_t		dringdata_msgid;  /* msg id */

	/*
	 * Receive Specific Fields
	 */
	/* RX-Common (Used in both TxDring and RxDringData modes) */
	uint32_t		num_rxds;	   /* # of descriptors */
	uint32_t		rx_dring_ncookies; /* # of dring cookies */
	ldc_dring_handle_t	rx_dring_handle;   /* dring handle */
	ldc_mem_cookie_t	rx_dring_cookie;   /* dring cookie */
	uint32_t		next_rxi;	   /* free descriptor index */
	vgen_ldcrx_dringdata_t	rx_dringdata;	   /* dring rcv function */
	vgen_ldcrx_pktdata_t	rx_pktdata;	   /* raw data rcv function */
	boolean_t		polling_on;	   /* polling enabled ? */

	/* RX-TxDring mode */
	vnet_public_desc_t	*mrxdp;		 /* mapped dring */
	uint64_t		next_rxseq;	 /* msg seqnum */
	vio_multi_pool_t	vmp;		 /* mblk pools */
	uint32_t		max_rxpool_size; /* max size of rxpool in use */
	mblk_t			*pollq_headp;	 /* head of pkts in pollq */
	mblk_t			*pollq_tailp;	 /* tail of pkts in pollq */
	kthread_t		*msg_thread;	 /* message thread */
	uint32_t		msg_thr_flags;	 /* message thread flags */
	kmutex_t		msg_thr_lock;	 /* lock for message thread */
	kcondvar_t		msg_thr_cv;	 /* cond.var for msg thread */

	/* RX-RxDringData mode */
	uint32_t		num_rbufs;	  /* # of data bufs */
	uint32_t		rx_data_ncookies; /* # of data cookies */
	ldc_mem_handle_t	rx_data_handle;	  /* exported data handle */
	ldc_mem_cookie_t	*rx_data_cookie;  /* exported data cookies */
	vnet_rx_dringdata_desc_t *rxdp;		  /* exported dring */
	vio_mblk_pool_t		*rx_vmp;	  /* mblk pool */
	vio_mblk_t		**rxdp_to_vmp;	  /* descr to buf map tbl */
	caddr_t			rx_datap;	  /* mapped rx data area */
	size_t			rx_data_sz;	  /* size of mapped rx data */
	size_t			rx_dblk_sz;	  /* size of each rx data blk */
	mblk_t			*rx_pri_head;	  /* priority pkts head */
	mblk_t			*rx_pri_tail;	  /* priority pkts tail */

	/* Channel Statistics */
	vgen_stats_t		stats;		/* channel statistics */
	kstat_t			*ksp;		/* channel kstats */
} vgen_ldc_t;

/* port information  structure */
typedef struct vgen_port {
	struct vgen_port	*nextp;		/* next port in the list */
	struct vgen		*vgenp;		/* associated vgen_t */
	int			port_num;	/* port number */
	boolean_t		is_vsw_port;	/* connected to vswitch ? */
	int			num_ldcs;	/* # of channels in this port */
	uint64_t		*ldc_ids;	/* channel ids */
	vgen_ldc_t		*ldcp;		/* list of ldcs for this port */
	ether_addr_t		macaddr;	/* mac address of peer */
	uint16_t		pvid;		/* port vlan id (untagged) */
	uint16_t		*vids;		/* vlan ids (tagged) */
	uint16_t		nvids;		/* # of vids */
	mod_hash_t		*vlan_hashp;	/* vlan hash table */
	uint32_t		vlan_nchains;	/* # of vlan hash chains */
	uint32_t		use_vsw_port;	/* Use vsw_port or not */
	uint32_t		flags;		/* status of this port */
	vio_net_callbacks_t	vcb;		/* vnet callbacks */
	vio_net_handle_t	vhp;		/* handle from vnet */
	kmutex_t		lock;		/* synchornize ops */
} vgen_port_t;

/* port list structure */
typedef struct vgen_portlist {
	vgen_port_t	*headp;		/* head of ports */
	vgen_port_t	*tailp;		/* tail */
	krwlock_t	rwlock;		/* sync access to the port list */
} vgen_portlist_t;

/* vgen instance information  */
typedef struct vgen {
	vnet_t			*vnetp;		/* associated vnet instance */
	int			instance;	/* vnet instance */
	dev_info_t		*vnetdip;	/* dip of vnet */
	uint64_t		regprop;	/* "reg" property */
	ether_addr_t		macaddr;	/* mac addr of vnet */
	kmutex_t		lock;		/* synchornize ops */
	int			flags;		/* flags */
	vgen_portlist_t		vgenports;	/* Port List */
	mdeg_node_spec_t	*mdeg_parentp;
	mdeg_handle_t		mdeg_dev_hdl;	/* mdeg cb handle for device */
	mdeg_handle_t		mdeg_port_hdl;	/* mdeg cb handle for port */
	vgen_port_t		*vsw_portp;	/* port connected to vsw */
	struct ether_addr	*mctab;		/* multicast addr table */
	uint32_t		mcsize;		/* allocated size of mctab */
	uint32_t		mccount;	/* # of valid addrs in mctab */
	ddi_taskq_t		*rxp_taskq;	/* VIO rx pool taskq */
	uint32_t		pri_num_types;	/* # of priority eth types */
	uint16_t		*pri_types;	/* priority eth types */
	vio_mblk_pool_t		*pri_tx_vmp;	/* tx priority mblk pool */
	uint32_t		max_frame_size;	/* max frame size supported */

	uint32_t		vsw_port_refcnt; /* refcnt for vsw_port */
	boolean_t		pls_negotiated;	/* phys link state update ? */
	link_state_t		phys_link_state; /* physical link state */
} vgen_t;

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_GEN_H */
