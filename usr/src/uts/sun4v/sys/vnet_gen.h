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

#ifndef _VNET_GEN_H
#define	_VNET_GEN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#define	VGEN_WTHR_RUNNING 	0x01	/* worker thread running */
#define	VGEN_WTHR_DATARCVD 	0x02	/* data received */
#define	VGEN_WTHR_STOP 		0x04	/* stop worker thread request */

#define	VGEN_LDC_UP_DELAY	100	/* usec delay between ldc_up retries */

#define	VGEN_NUM_VMPOOLS	3	/* number of vio mblk pools */

#define	VGEN_DBLK_SZ_128	128	/* data buffer size 128 bytes */
#define	VGEN_DBLK_SZ_256	256	/* data buffer size 256 bytes */
#define	VGEN_DBLK_SZ_2048	2048	/* data buffer size 2K bytes */
#define	VGEN_NRBUFS		512	/* number of receive bufs */

#define	VGEN_TXDBLK_SZ		2048	/* Tx data buffer size */

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

	/* descriptor ring params */
	uint32_t		num_desc;	/* # of descriptors in ring */
	uint32_t		desc_size;	/* size of descriptor */
	ldc_mem_cookie_t	dring_cookie;	/* desc ring cookie */
	uint32_t		num_dcookies;	/* # of dring cookies */
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

/* Channel information associated with a vgen-port */
typedef struct vgen_ldc {

	struct vgen_ldc		*nextp;		/* next ldc in the list */
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

	/* channel info from ldc layer */
	uint64_t		ldc_id;		/* channel number */
	uint64_t		ldc_handle;	/* channel handle */
	ldc_status_t		ldc_status;	/* channel status */

	/* handshake info */
	vgen_ver_t		vgen_versions[VGEN_NUM_VER]; /* versions */
	int			hphase;		/* handshake phase */
	int			hstate;		/* handshake state bits */
	uint32_t		local_sid;	/* local session id */
	uint32_t		peer_sid;	/* session id of peer */
	vgen_hparams_t		local_hparams;	/* local handshake params */
	vgen_hparams_t		peer_hparams;	/* peer's handshake params */
	timeout_id_t		htid;		/* handshake wd timeout id */
	timeout_id_t		cancel_htid;	/* cancel handshake watchdog */

	/* transmit and receive descriptor ring info */
	ldc_dring_handle_t	tx_dhandle;	/* tx descriptor ring handle */
	ldc_mem_cookie_t	tx_dcookie;	/* tx descriptor ring cookie */
	ldc_dring_handle_t	rx_dhandle;	/* mapped rx dhandle */
	ldc_mem_cookie_t	rx_dcookie;	/* rx descriptor ring cookie */
	vnet_public_desc_t	*txdp;		/* transmit frame descriptors */
	vnet_public_desc_t	*txdendp;	/* txd ring end */
	vgen_private_desc_t	*tbufp;		/* associated tx resources */
	vgen_private_desc_t	*tbufendp;	/* tbuf ring end */
	vgen_private_desc_t	*next_tbufp;	/* next free tbuf */
	vgen_private_desc_t	*cur_tbufp;	/* next reclaim tbuf */
	uint64_t		next_txseq;	/* next tx sequence number */
	uint32_t		num_txdcookies;	/* # of tx dring cookies */
	uint32_t		num_rxdcookies;	/* # of rx dring cookies */
	uint32_t		next_txi;	/* next tx descriptor index */
	uint32_t		num_txds;	/* number of tx descriptors */
	clock_t			reclaim_lbolt;	/* time of last tx reclaim */
	timeout_id_t		wd_tid;		/* tx watchdog timeout id */
	vnet_public_desc_t	*rxdp;		/* receive frame descriptors */
	uint64_t		next_rxseq;	/* next expected recv seqnum */
	uint32_t		next_rxi;	/* next expected recv index */
	uint32_t		num_rxds;	/* number of rx descriptors */
	caddr_t			tx_datap;	/* prealloc'd tx data area */
	size_t			tx_data_sz;	/* alloc'd size of tx databuf */
	vio_multi_pool_t	vmp;		/* rx mblk pools */
	uint64_t		*ldcmsg;	/* msg buffer for ldc_read() */
	uint64_t		msglen;		/* size of ldcmsg */

	/* misc */
	uint32_t		flags;		/* flags */
	boolean_t		need_resched;	/* reschedule tx */
	boolean_t		need_ldc_reset; /* ldc_reset needed */
	uint32_t		hretries;	/* handshake retry count */
	boolean_t		resched_peer;	/* send tx msg to peer */
	uint32_t		resched_peer_txi; /* tx index to resched peer */

	vgen_ldctx_t		tx;		/* transmit function */
	vgen_ldcrx_pktdata_t	rx_pktdata;	/* process rx raw data msg */

	/* receive thread field */
	kthread_t		*rcv_thread;	/* receive thread */
	uint32_t		rcv_thr_flags;	/* receive thread flags */
	kmutex_t		rcv_thr_lock;	/* lock for receive thread */
	kcondvar_t		rcv_thr_cv;	/* cond.var for recv thread */

	/* channel statistics */
	vgen_stats_t		stats;		/* channel statistics */
	kstat_t			*ksp;		/* channel kstats */

} vgen_ldc_t;

/* Channel list structure */
typedef struct vgen_ldclist_s {
	vgen_ldc_t	*headp;		/* head of the list */
	krwlock_t	rwlock;		/* sync access to the list */
} vgen_ldclist_t;

/* port information  structure */
typedef struct vgen_port {
	struct vgen_port	*nextp;		/* next port in the list */
	struct vgen		*vgenp;		/* associated vgen_t */
	int			port_num;	/* port number */
	int			num_ldcs;	/* # of channels in this port */
	uint64_t		*ldc_ids;	/* channel ids */
	vgen_ldclist_t		ldclist;	/* list of ldcs for this port */
	struct ether_addr	macaddr;	/* mac address of peer */
	uint16_t		pvid;		/* port vlan id (untagged) */
	uint16_t		*vids;		/* vlan ids (tagged) */
	uint16_t		nvids;		/* # of vids */
	mod_hash_t		*vlan_hashp;	/* vlan hash table */
	uint32_t		vlan_nchains;	/* # of vlan hash chains */
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
	dev_info_t		*vnetdip;	/* dip of vnet */
	uint64_t		regprop;	/* "reg" property */
	uint8_t			macaddr[ETHERADDRL];	/* mac addr of vnet */
	kmutex_t		lock;		/* synchornize ops */
	int			flags;		/* flags */
	vgen_portlist_t		vgenports;	/* Port List */
	mdeg_node_spec_t	*mdeg_parentp;
	mdeg_handle_t		mdeg_dev_hdl;	/* mdeg cb handle for device */
	mdeg_handle_t		mdeg_port_hdl;	/* mdeg cb handle for port */
	vgen_port_t		*vsw_portp;	/* port connected to vsw */
	mac_register_t		*macp;		/* vgen mac ops */
	struct ether_addr	*mctab;		/* multicast addr table */
	uint32_t		mcsize;		/* allocated size of mctab */
	uint32_t		mccount;	/* # of valid addrs in mctab */
	vio_mblk_pool_t		*rmp;		/* rx mblk pools to be freed */
	uint32_t		pri_num_types;	/* # of priority eth types */
	uint16_t		*pri_types;	/* priority eth types */
	vio_mblk_pool_t		*pri_tx_vmp;	/* tx priority mblk pool */
	uint32_t		max_frame_size;	/* max frame size supported */
} vgen_t;

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_GEN_H */
