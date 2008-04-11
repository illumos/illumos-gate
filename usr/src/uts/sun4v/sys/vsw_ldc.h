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

/*
 * This header file contains the basic data structures which the
 * virtual switch (vsw) uses to communicate with vnet clients.
 *
 * The virtual switch reads the machine description (MD) to
 * determine how many port_t structures to create (each port_t
 * can support communications to a single network device). The
 * port_t's are maintained in a linked list.
 *
 * Each port in turn contains a number of logical domain channels
 * (ldc's) which are inter domain communications channels which
 * are used for passing small messages between the domains. Their
 * may be an unlimited number of channels associated with each port,
 * though most devices only use a single channel.
 *
 * The ldc is a bi-directional channel, which is divided up into
 * two directional 'lanes', one outbound from the switch to the
 * virtual network device, the other inbound to the switch.
 * Depending on the type of device each lane may have seperate
 * communication paramaters (such as mtu etc).
 *
 * For those network clients which use descriptor rings the
 * rings are associated with the appropriate lane. I.e. rings
 * which the switch exports are associated with the outbound lanes
 * while those which the network clients are exporting to the switch
 * are associated with the inbound lane.
 *
 * In diagram form the data structures look as follows:
 *
 * vsw instance
 *     |
 *     +----->port_t----->port_t----->port_t----->
 *		|
 *		+--->ldc_t--->ldc_t--->ldc_t--->
 *		       |
 *		       +--->lane_t (inbound)
 *		       |       |
 *		       |       +--->dring--->dring--->
 *		       |
 *		       +--->lane_t (outbound)
 *			       |
 *			       +--->dring--->dring--->
 *
 */

#ifndef	_VSW_LDC_H
#define	_VSW_LDC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Default message type.
 */
typedef struct def_msg {
	uint64_t	data[8];
} def_msg_t;

/*
 * Currently only support one major/minor pair.
 */
#define	VSW_NUM_VER	1

typedef struct ver_sup {
	uint16_t	ver_major;	/* major version number */
	uint16_t	ver_minor;	/* minor version number */
} ver_sup_t;

/*
 * Lane states.
 */
#define	VSW_LANE_INACTIV	0x0	/* No params set for lane */

#define	VSW_VER_INFO_SENT	0x1	/* Version # sent to peer */
#define	VSW_VER_INFO_RECV	0x2	/* Version # recv from peer */
#define	VSW_VER_ACK_RECV	0x4
#define	VSW_VER_ACK_SENT	0x8
#define	VSW_VER_NACK_RECV	0x10
#define	VSW_VER_NACK_SENT	0x20

#define	VSW_ATTR_INFO_SENT	0x40	/* Attributes sent to peer */
#define	VSW_ATTR_INFO_RECV	0x80	/* Peer attributes received */
#define	VSW_ATTR_ACK_SENT	0x100
#define	VSW_ATTR_ACK_RECV	0x200
#define	VSW_ATTR_NACK_SENT	0x400
#define	VSW_ATTR_NACK_RECV	0x800

#define	VSW_DRING_INFO_SENT	0x1000	/* Dring info sent to peer */
#define	VSW_DRING_INFO_RECV	0x2000	/* Dring info received */
#define	VSW_DRING_ACK_SENT	0x4000
#define	VSW_DRING_ACK_RECV	0x8000
#define	VSW_DRING_NACK_SENT	0x10000
#define	VSW_DRING_NACK_RECV	0x20000

#define	VSW_RDX_INFO_SENT	0x40000	/* RDX sent to peer */
#define	VSW_RDX_INFO_RECV	0x80000	/* RDX received from peer */
#define	VSW_RDX_ACK_SENT	0x100000
#define	VSW_RDX_ACK_RECV	0x200000
#define	VSW_RDX_NACK_SENT	0x400000
#define	VSW_RDX_NACK_RECV	0x800000

#define	VSW_MCST_INFO_SENT	0x1000000
#define	VSW_MCST_INFO_RECV	0x2000000
#define	VSW_MCST_ACK_SENT	0x4000000
#define	VSW_MCST_ACK_RECV	0x8000000
#define	VSW_MCST_NACK_SENT	0x10000000
#define	VSW_MCST_NACK_RECV	0x20000000

#define	VSW_LANE_ACTIVE		0x40000000	/* Lane open to xmit data */

/* Handshake milestones */
#define	VSW_MILESTONE0		0x1	/* ver info exchanged */
#define	VSW_MILESTONE1		0x2	/* attribute exchanged */
#define	VSW_MILESTONE2		0x4	/* dring info exchanged */
#define	VSW_MILESTONE3		0x8	/* rdx exchanged */
#define	VSW_MILESTONE4		0x10	/* handshake complete */

/*
 * Lane direction (relative to ourselves).
 */
#define	INBOUND			0x1
#define	OUTBOUND		0x2

/* Peer session id received */
#define	VSW_PEER_SESSION	0x1

/*
 * Maximum number of consecutive reads of data from channel
 */
#define	VSW_MAX_CHAN_READ	50

/*
 * Currently only support one ldc per port.
 */
#define	VSW_PORT_MAX_LDCS	1	/* max # of ldcs per port */

/*
 * Used for port add/deletion.
 */
#define	VSW_PORT_UPDATED	0x1

#define	LDC_TX_SUCCESS		0	/* ldc transmit success */
#define	LDC_TX_FAILURE		1	/* ldc transmit failure */
#define	LDC_TX_NORESOURCES	2	/* out of descriptors */

/*
 * Descriptor ring info
 *
 * Each descriptor element has a pre-allocated data buffer
 * associated with it, into which data being transmitted is
 * copied. By pre-allocating we speed up the copying process.
 * The buffer is re-used once the peer has indicated that it is
 * finished with the descriptor.
 */
#define	VSW_RING_EL_DATA_SZ	2048	/* Size of data section (bytes) */
#define	VSW_PRIV_SIZE	sizeof (vnet_private_desc_t)
#define	VSW_PUB_SIZE	sizeof (vnet_public_desc_t)

#define	VSW_MAX_COOKIES		((ETHERMTU >> MMU_PAGESHIFT) + 2)

/*
 * LDC pkt tranfer MTU
 */
#define	VSW_LDC_MTU	sizeof (def_msg_t)

/*
 * Size of the mblk in each mblk pool.
 */
#define	VSW_MBLK_SZ_128		128
#define	VSW_MBLK_SZ_256		256
#define	VSW_MBLK_SZ_2048	2048

/*
 * Number of mblks in each mblk pool.
 */
#define	VSW_NUM_MBLKS	1024

/*
 * Private descriptor
 */
typedef struct vsw_private_desc {
	/*
	 * Below lock must be held when accessing the state of
	 * a descriptor on either the private or public sections
	 * of the ring.
	 */
	kmutex_t		dstate_lock;
	uint64_t		dstate;
	vnet_public_desc_t	*descp;
	ldc_mem_handle_t	memhandle;
	void			*datap;
	uint64_t		datalen;
	uint64_t		ncookies;
	ldc_mem_cookie_t	memcookie[VSW_MAX_COOKIES];
	int			bound;
} vsw_private_desc_t;

/*
 * Descriptor ring structure
 */
typedef struct dring_info {
	struct	dring_info	*next;	/* next ring in chain */
	kmutex_t		dlock;
	uint32_t		num_descriptors;
	uint32_t		descriptor_size;
	uint32_t		options;
	uint32_t		ncookies;
	ldc_mem_cookie_t	cookie[1];

	ldc_dring_handle_t	handle;
	uint64_t		ident;	/* identifier sent to peer */
	uint64_t		end_idx;	/* last idx processed */
	int64_t			last_ack_recv;

	kmutex_t		restart_lock;
	boolean_t		restart_reqd;	/* send restart msg */

	/*
	 * base address of private and public portions of the
	 * ring (where appropriate), and data block.
	 */
	void			*pub_addr;	/* base of public section */
	void			*priv_addr;	/* base of private section */
	void			*data_addr;	/* base of data section */
	size_t			data_sz;	/* size of data section */
	size_t			desc_data_sz;	/* size of descr data blk */
} dring_info_t;

/*
 * Each ldc connection is comprised of two lanes, incoming
 * from a peer, and outgoing to that peer. Each lane shares
 * common ldc parameters and also has private lane-specific
 * parameters.
 */
typedef struct lane {
	uint64_t	lstate;		/* Lane state */
	uint16_t	ver_major;	/* Version major number */
	uint16_t	ver_minor;	/* Version minor number */
	uint64_t	seq_num;	/* Sequence number */
	uint64_t	mtu;		/* ETHERMTU */
	uint64_t	addr;		/* Unique physical address */
	uint8_t		addr_type;	/* Only MAC address at moment */
	uint8_t		xfer_mode;	/* Dring or Pkt based */
	uint8_t		ack_freq;	/* Only non zero for Pkt based xfer */
	krwlock_t	dlistrw;	/* Lock for dring list */
	dring_info_t	*dringp;	/* List of drings for this lane */
} lane_t;

/* channel drain states */
#define	VSW_LDC_INIT		0x1	/* Initial non-drain state */
#define	VSW_LDC_DRAINING	0x2	/* Channel draining */

/*
 * vnet-protocol-version dependent function prototypes.
 */
typedef int	(*vsw_ldctx_t) (void *, mblk_t *, mblk_t *, uint32_t);
typedef void	(*vsw_ldcrx_pktdata_t) (void *, void *, uint32_t);

/* ldc information associated with a vsw-port */
typedef struct vsw_ldc {
	struct vsw_ldc		*ldc_next;	/* next ldc in the list */
	struct vsw_port		*ldc_port;	/* associated port */
	struct vsw		*ldc_vswp;	/* associated vsw */
	kmutex_t		ldc_cblock;	/* sync callback processing */
	kmutex_t		ldc_txlock;	/* sync transmits */
	kmutex_t		ldc_rxlock;	/* sync rx */
	uint64_t		ldc_id;		/* channel number */
	ldc_handle_t		ldc_handle;	/* channel handle */
	kmutex_t		drain_cv_lock;
	kcondvar_t		drain_cv;	/* channel draining */
	int			drain_state;
	uint32_t		hphase;		/* handshake phase */
	int			hcnt;		/* # handshake attempts */
	kmutex_t		status_lock;
	ldc_status_t		ldc_status;	/* channel status */
	uint8_t			reset_active;	/* reset flag */
	uint64_t		local_session;	/* Our session id */
	uint64_t		peer_session;	/* Our peers session id */
	uint8_t			session_status;	/* Session recv'd, sent */
	uint32_t		hss_id;		/* Handshake session id */
	uint64_t		next_ident;	/* Next dring ident # to use */
	lane_t			lane_in;	/* Inbound lane */
	lane_t			lane_out;	/* Outbound lane */
	uint8_t			dev_class;	/* Peer device class */
	vio_multi_pool_t	vmp;		/* Receive mblk pools */
	uint64_t		*ldcmsg;	/* msg buffer for ldc_read() */
	uint64_t		msglen;		/* size of ldcmsg */

	/* tx thread fields */
	kthread_t		*tx_thread;	/* tx thread */
	uint32_t		tx_thr_flags;	/* tx thread flags */
	kmutex_t		tx_thr_lock;	/* lock for tx thread */
	kcondvar_t		tx_thr_cv;	/* cond.var for tx thread */
	mblk_t			*tx_mhead;	/* tx mblks head */
	mblk_t			*tx_mtail;	/* tx mblks tail */
	uint32_t		tx_cnt;		/* # of pkts queued for tx */

	/* receive thread fields */
	kthread_t		*rx_thread;	/* receive thread */
	uint32_t		rx_thr_flags;	/* receive thread flags */
	kmutex_t		rx_thr_lock;	/* lock for receive thread */
	kcondvar_t		rx_thr_cv;	/* cond.var for recv thread */

	vsw_ldctx_t		tx;		/* transmit function */
	vsw_ldcrx_pktdata_t	rx_pktdata;	/* process rx raw data msg */

	/* channel statistics */
	vgen_stats_t		ldc_stats;	/* channel statistics */
	kstat_t			*ksp;		/* channel kstats */
} vsw_ldc_t;

/* worker thread flags */
#define	VSW_WTHR_RUNNING 	0x01	/* worker thread running */
#define	VSW_WTHR_DATARCVD 	0x02	/* data received */
#define	VSW_WTHR_STOP 		0x04	/* stop worker thread request */

/* list of ldcs per port */
typedef struct vsw_ldc_list {
	vsw_ldc_t	*head;		/* head of the list */
	krwlock_t	lockrw;		/* sync access(rw) to the list */
} vsw_ldc_list_t;

/* multicast addresses port is interested in */
typedef struct mcst_addr {
	struct mcst_addr	*nextp;
	struct ether_addr	mca;	/* multicast address */
	uint64_t		addr;	/* mcast addr converted to hash key */
	boolean_t		mac_added; /* added into physical device */
} mcst_addr_t;

/* Port detach states */
#define	VSW_PORT_INIT		0x1	/* Initial non-detach state */
#define	VSW_PORT_DETACHING	0x2	/* In process of being detached */
#define	VSW_PORT_DETACHABLE	0x4	/* Safe to detach */

#define	VSW_ADDR_UNSET		0x0	/* Addr not set */
#define	VSW_ADDR_HW		0x1	/* Addr programmed in HW */
#define	VSW_ADDR_PROMISC	0x2	/* Card in promisc to see addr */

/* port information associated with a vsw */
typedef struct vsw_port {
	int			p_instance;	/* port instance */
	struct vsw_port		*p_next;	/* next port in the list */
	struct vsw		*p_vswp;	/* associated vsw */
	int			num_ldcs;	/* # of ldcs in the port */
	uint64_t		*ldc_ids;	/* ldc ids */
	vsw_ldc_list_t		p_ldclist;	/* list of ldcs for this port */

	kmutex_t		tx_lock;	/* transmit lock */
	int			(*transmit)(vsw_ldc_t *, mblk_t *);

	int			state;		/* port state */
	kmutex_t		state_lock;
	kcondvar_t		state_cv;

	kmutex_t		mca_lock;	/* multicast lock */
	mcst_addr_t		*mcap;		/* list of multicast addrs */

	mac_addr_slot_t		addr_slot;	/* Unicast address slot */
	int			addr_set;	/* Addr set where */

	/*
	 * mac address of the port & connected device
	 */
	struct ether_addr	p_macaddr;
	uint16_t		pvid;	/* port vlan id (untagged) */
	uint16_t		*vids;	/* vlan ids (tagged) */
	uint16_t		nvids;	/* # of vids */
	uint32_t		vids_size; /* size alloc'd for vids list */
	mod_hash_t		*vlan_hashp;	/* vlan hash table */
	uint32_t		vlan_nchains;	/* # of vlan hash chains */
} vsw_port_t;

/* list of ports per vsw */
typedef struct vsw_port_list {
	vsw_port_t	*head;		/* head of the list */
	krwlock_t	lockrw;		/* sync access(rw) to the list */
	int		num_ports;	/* number of ports in the list */
} vsw_port_list_t;

/*
 * Taskq control message
 */
typedef struct vsw_ctrl_task {
	vsw_ldc_t	*ldcp;
	def_msg_t	pktp;
	uint32_t	hss_id;
} vsw_ctrl_task_t;

/*
 * State of connection to peer. Some of these states
 * can be mapped to LDC events as follows:
 *
 * VSW_CONN_RESET -> LDC_RESET_EVT
 * VSW_CONN_UP    -> LDC_UP_EVT
 */
#define	VSW_CONN_UP		0x1	/* Connection come up */
#define	VSW_CONN_RESET		0x2	/* Connection reset */
#define	VSW_CONN_RESTART	0x4	/* Restarting handshake on connection */

typedef struct vsw_conn_evt {
	uint16_t	evt;		/* Connection event */
	vsw_ldc_t	*ldcp;
} vsw_conn_evt_t;

/*
 * Ethernet broadcast address definition.
 */
static	struct	ether_addr	etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define	IS_BROADCAST(ehp) \
	(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
	((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)

#define	READ_ENTER(x)	rw_enter(x, RW_READER)
#define	WRITE_ENTER(x)	rw_enter(x, RW_WRITER)
#define	RW_EXIT(x)	rw_exit(x)

#define	VSW_PORT_REFHOLD(portp)	atomic_inc_32(&((portp)->ref_cnt))
#define	VSW_PORT_REFRELE(portp)	atomic_dec_32(&((portp)->ref_cnt))

#ifdef	__cplusplus
}
#endif

#endif	/* _VSW_LDC_H */
