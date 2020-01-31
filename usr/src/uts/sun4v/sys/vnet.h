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

#ifndef _VNET_H
#define	_VNET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vnet_res.h>
#include <sys/vnet_mailbox.h>
#include <sys/modhash.h>
#include <net/if.h>
#include <sys/mac_client.h>

#define	VNET_SUCCESS		(0)	/* successful return */
#define	VNET_FAILURE		(-1)	/* unsuccessful return */

#define	KMEM_FREE(_p)		kmem_free((_p), sizeof (*(_p)))

#define	VNET_NUM_DESCRIPTORS	512		/* power of 2 descriptors */

#define	IS_BROADCAST(ehp) \
		(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)

#define	VNET_MATCH_RES(vresp, vnetp)	\
	(ether_cmp(vresp->local_macaddr, vnetp->curr_macaddr) == 0)

/*
 * Flags used to indicate the state of the vnet device and its associated
 * resources.
 */
typedef enum vnet_flags {
	VNET_STOPPED = 0x0,
	VNET_STARTED = 0x1,
	VNET_STOPPING = 0x2
} vnet_flags_t;

typedef struct vnet_hio_stats {
	/* Link Input/Output stats */
	uint64_t	ipackets;	/* # rx packets */
	uint64_t	ierrors;	/* # rx error */
	uint64_t	opackets;	/* # tx packets */
	uint64_t	oerrors;	/* # tx error */

	/* MIB II variables */
	uint64_t	rbytes;		/* # bytes received */
	uint64_t	obytes;		/* # bytes transmitted */
	uint32_t	multircv;	/* # multicast packets received */
	uint32_t	multixmt;	/* # multicast packets for xmit */
	uint32_t	brdcstrcv;	/* # broadcast packets received */
	uint32_t	brdcstxmt;	/* # broadcast packets for xmit */
	uint32_t	norcvbuf;	/* # rcv packets discarded */
	uint32_t	noxmtbuf;	/* # xmit packets discarded */
} vnet_hio_stats_t;

typedef struct vnet_hio_kstats {
	/* Link Input/Output stats */
	kstat_named_t	ipackets;
	kstat_named_t	ipackets64;
	kstat_named_t	ierrors;
	kstat_named_t	opackets;
	kstat_named_t	opackets64;
	kstat_named_t	oerrors;

	/* required by kstat for MIB II objects(RFC 1213) */
	kstat_named_t	rbytes;		/* MIB - ifInOctets */
	kstat_named_t	rbytes64;
	kstat_named_t	obytes;		/* MIB - ifOutOctets */
	kstat_named_t	obytes64;
	kstat_named_t	multircv;	/* MIB - ifInNUcastPkts */
	kstat_named_t	multixmt;	/* MIB - ifOutNUcastPkts */
	kstat_named_t	brdcstrcv;	/* MIB - ifInNUcastPkts */
	kstat_named_t	brdcstxmt;	/* MIB - ifOutNUcastPkts */
	kstat_named_t	norcvbuf;	/* MIB - ifInDiscards */
	kstat_named_t	noxmtbuf;	/* MIB - ifOutDiscards */
} vnet_hio_kstats_t;

typedef struct vnet_tx_ring_stats {
	uint64_t	opackets;	/* # tx packets */
	uint64_t	obytes;		/* # bytes transmitted */
} vnet_tx_ring_stats_t;

/*
 * A vnet resource structure.
 */
typedef struct vnet_res {
	struct vnet_res		*nextp;		/* next resource in the list */
	mac_register_t		macreg;		/* resource's mac_reg */
	vio_net_res_type_t	type;		/* resource type */
	ether_addr_t		local_macaddr;	/* resource's macaddr */
	ether_addr_t		rem_macaddr;	/* resource's remote macaddr */
	vnet_flags_t		flags;		/* resource flags */
	uint32_t		refcnt;		/* reference count */
	struct	vnet		*vnetp;		/* back pointer to vnet */
	kstat_t			*ksp;		/* hio kstats */
	void			*rx_ringp;	/* assoc pseudo rx ring */
} vnet_res_t;

#define	VNET_DDS_TASK_ADD_SHARE		0x01
#define	VNET_DDS_TASK_DEL_SHARE		0x02
#define	VNET_DDS_TASK_REL_SHARE		0x04

/* An instance specific DDS structure */
typedef struct vnet_dds_info {
	kmutex_t	lock;		/* lock for this structure */
	uint8_t		task_flags;	/* flags for taskq */
	uint8_t		dds_req_id;	/* DDS message request id */
	vio_dds_msg_t	dmsg;		/* Pending DDS message */
	dev_info_t	*hio_dip;	/* Hybrid device's dip */
	uint64_t	hio_cookie;	/* Hybrid device's cookie */
	char		hio_ifname[LIFNAMSIZ];  /* Hybrid interface name */
	ddi_taskq_t	*dds_taskqp;	/* Taskq's used for DDS */
	struct vnet	*vnetp;		/* Back pointer to vnetp */
} vnet_dds_info_t;

#define	VNET_NFDB_HASH	64

#define	KEY_HASH(key, addr) \
	(key = (((uint64_t)(addr[0])) << 40) | \
	(((uint64_t)(addr[1])) << 32) | \
	(((uint64_t)(addr[2])) << 24) | \
	(((uint64_t)(addr[3])) << 16) | \
	(((uint64_t)(addr[4])) << 8) | \
	((uint64_t)(addr[5])));


/* rwlock macros */
#define	READ_ENTER(x)	rw_enter(x, RW_READER)
#define	WRITE_ENTER(x)	rw_enter(x, RW_WRITER)
#define	RW_EXIT(x)	rw_exit(x)

#define	VLAN_ID_KEY(key)	((mod_hash_key_t)(uintptr_t)(key))

typedef enum {
		AST_init = 0x0, AST_vnet_alloc = 0x1,
		AST_ring_init = 0x2, AST_vdds_init = 0x4,
		AST_read_macaddr = 0x8, AST_fdbh_alloc = 0x10,
		AST_taskq_create = 0x20, AST_vnet_list = 0x40,
		AST_vgen_init = 0x80, AST_macreg = 0x100,
		AST_init_mdeg = 0x200
} vnet_attach_progress_t;

#define	VNET_NUM_PSEUDO_GROUPS		1	/* # of pseudo ring grps */
#define	VNET_NUM_HYBRID_RINGS		2	/* # of Hybrid tx/rx rings */
#define	VNET_HYBRID_RXRING_INDEX	1	/* Hybrid rx ring start index */

/*
 * # of Pseudo TX Rings is defined based on the possible
 * # of TX Hardware Rings from a Hybrid resource.
 */
#define	VNET_NUM_PSEUDO_TXRINGS		VNET_NUM_HYBRID_RINGS

/*
 * # of Pseudo RX Rings that are reserved and exposed by default.
 * 1 for LDC resource to vsw + 2 for RX rings of Hybrid resource.
 */
#define	VNET_NUM_PSEUDO_RXRINGS_DEFAULT	(VNET_NUM_HYBRID_RINGS + 1)

/* Pseudo RX Ring States */
typedef enum {
	VNET_RXRING_FREE = 0x0,		/* Free */
	VNET_RXRING_INUSE = 0x1,	/* In use */
	VNET_RXRING_LDC_SERVICE = 0x2,	/* Mapped to vswitch */
	VNET_RXRING_LDC_GUEST = 0x4,	/* Mapped to a peer vnet */
	VNET_RXRING_HYBRID = 0x8,	/* Mapped to Hybrid resource */
	VNET_RXRING_STARTED = 0x10	/* Started */
} vnet_rxring_state_t;

/* Pseudo TX Ring States */
typedef enum {
	VNET_TXRING_FREE = 0x0,		/* Free */
	VNET_TXRING_INUSE = 0x1,	/* In use */
	VNET_TXRING_SHARED = 0x2,	/* Shared among LDCs */
	VNET_TXRING_HYBRID = 0x4,	/* Shared among LDCs, Hybrid resource */
	VNET_TXRING_STARTED = 0x8	/* Started */
} vnet_txring_state_t;

/*
 * Psuedo TX Ring
 */
typedef struct vnet_pseudo_tx_ring {
	uint_t			index;		/* ring index */
	vnet_txring_state_t	state;		/* ring state */
	void			*grp;		/* grp associated */
	void			*vnetp;		/* vnet associated */
	mac_ring_handle_t	handle;		/* ring handle in mac layer */
	mac_ring_handle_t	hw_rh;	/* Resource type dependent, internal */
					/* ring handle. Hybrid res: ring hdl */
					/* of hardware rx ring; LDC res: hdl */
					/* to the res itself (vnet_res_t)    */
	boolean_t		woken_up;
	vnet_tx_ring_stats_t	tx_ring_stats;	/* ring statistics */
} vnet_pseudo_tx_ring_t;

/*
 * Psuedo RX Ring
 */
typedef struct vnet_pseudo_rx_ring {
	uint_t			index;		/* ring index */
	vnet_rxring_state_t	state;		/* ring state */
	void			*grp;		/* grp associated */
	void			*vnetp;		/* vnet associated */
	mac_ring_handle_t	handle;		/* ring handle in mac layer */
	mac_ring_handle_t	hw_rh;	/* Resource type dependent, internal */
					/* ring handle. Hybrid res: ring hdl */
					/* of hardware tx ring; otherwise    */
					/* NULL */
	uint64_t		gen_num;	/* Mac layer gen_num */
} vnet_pseudo_rx_ring_t;

/*
 * Psuedo TX Ring Group
 */
typedef struct vnet_pseudo_tx_group {
	uint_t			index;		/* group index */
	void			*vnetp;		/* vnet associated */
	mac_group_handle_t	handle;		/* grp handle in mac layer */
	uint_t			ring_cnt;	/* total # of rings in grp */
	vnet_pseudo_tx_ring_t	*rings;		/* array of rings */
	kmutex_t		flowctl_lock;	/* flow control lock */
	kcondvar_t		flowctl_cv;
	kthread_t		*flowctl_thread;
	boolean_t		flowctl_done;
	void			*tx_notify_handle; /* Tx ring notification */
} vnet_pseudo_tx_group_t;

/*
 * Psuedo RX Ring Group
 */
typedef struct vnet_pseudo_rx_group {
	krwlock_t		lock;		/* sync rings access in grp */
	int			index;		/* group index */
	void			*vnetp;		/* vnet this grp belongs to */
	mac_group_handle_t	handle;		/* grp handle in mac layer */
	uint_t			max_ring_cnt;	/* total # of rings in grp */
	uint_t			ring_cnt;	/* # of rings in use */
	vnet_pseudo_rx_ring_t	*rings;		/* array of rings */
} vnet_pseudo_rx_group_t;

/*
 * vnet instance state information
 */
typedef struct vnet {
	int			instance;	/* instance # */
	dev_info_t		*dip;		/* dev_info */
	uint64_t		reg;		/* reg prop value */
	vnet_attach_progress_t	attach_progress; /* attach progress flags */
	struct vnet		*nextp;		/* next in list */
	mac_handle_t		mh;		/* handle to GLDv3 mac module */
	uchar_t			vendor_addr[ETHERADDRL]; /* orig macadr */
	uchar_t			curr_macaddr[ETHERADDRL]; /* current macadr */
	void			*vgenhdl;	/* Handle for vgen */

	uint32_t		fdb_nchains;	/* # of hash chains in fdbtbl */
	mod_hash_t		*fdb_hashp;	/* forwarding database */
	vnet_res_t		*vsw_fp;	/* cached fdb entry of vsw */
	krwlock_t		vsw_fp_rw;	/* lock to protect vsw_fp */
	uint32_t		mtu;		/* mtu of the device */

	uint16_t		default_vlan_id; /* default vlan id */
	uint16_t		pvid;		/* port vlan id (untagged) */
	uint16_t		*vids;		/* vlan ids (tagged) */
	uint16_t		nvids;		/* # of vids */

	link_state_t		link_state;	/* link status */
	boolean_t		pls_update;	/* phys link state update ? */
	vnet_flags_t		flags;		/* interface flags */
	vnet_res_t		*hio_fp;	/* Hybrid IO resource */
	vnet_res_t		*vres_list;	/* Resource list */
	vnet_dds_info_t		vdds_info;	/* DDS related info */
	krwlock_t		vrwlock;	/* Resource list lock */
	ddi_taskq_t		*taskqp;	/* Resource taskq */

	/* pseudo ring groups */
	vnet_pseudo_rx_group_t	rx_grp[VNET_NUM_PSEUDO_GROUPS];
	vnet_pseudo_tx_group_t	tx_grp[VNET_NUM_PSEUDO_GROUPS];

	vio_net_handle_t	hio_vhp;	/* HIO resource hdl */
	mac_handle_t		hio_mh;		/* HIO mac hdl */
	mac_client_handle_t	hio_mch;	/* HIO mac client hdl */
	mac_unicast_handle_t	hio_muh;	/* HIO mac unicst hdl */
	mac_group_handle_t	rx_hwgh;	/* HIO rx ring-group hdl */
	mac_group_handle_t	tx_hwgh;	/* HIO tx ring-group hdl */
} vnet_t;

#ifdef DEBUG
/*
 * debug levels:
 * DBG_LEVEL1:	Function entry/exit tracing
 * DBG_LEVEL2:	Info messages
 * DBG_LEVEL3:	Warning messages
 * DBG_LEVEL4:	Error messages
 */

enum	{ DBG_LEVEL1 = 0x01, DBG_LEVEL2 = 0x02, DBG_WARN = 0x04,
	    DBG_ERR = 0x08 };

#define	DBG1(...)	do {						\
			    if ((vnet_dbglevel & DBG_LEVEL1) != 0) {	\
				DEBUG_PRINTF(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DBG2(...)	do {						\
			    if ((vnet_dbglevel & DBG_LEVEL2) != 0) {	\
				DEBUG_PRINTF(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DWARN(...)	do {						\
			    if ((vnet_dbglevel & DBG_WARN) != 0) {	\
				DEBUG_PRINTF(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DERR(...)	do {						\
			    if ((vnet_dbglevel & DBG_ERR) != 0) {	\
				DEBUG_PRINTF(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#else

#define	DBG1(...)
#define	DBG2(...)
#define	DWARN(...)
#define	DERR(...)

#endif

#ifdef	VNET_IOC_DEBUG	/* Debug ioctls */

#define	VNET_FORCE_LINK_DOWN	0x1
#define	VNET_FORCE_LINK_UP	0x2

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_H */
