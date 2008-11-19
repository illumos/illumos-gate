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

#ifndef _VNET_H
#define	_VNET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vnet_res.h>
#include <sys/vnet_mailbox.h>
#include <sys/modhash.h>

#define	VNET_SUCCESS		(0)	/* successful return */
#define	VNET_FAILURE		(-1)	/* unsuccessful return */

#define	KMEM_FREE(_p)		kmem_free((_p), sizeof (*(_p)))

#define	VNET_NTXDS		512		/* power of 2 tx descriptors */
#define	VNET_LDCWD_INTERVAL	1000		/* watchdog freq in msec */
#define	VNET_LDCWD_TXTIMEOUT	1000		/* tx timeout in msec */
#define	VNET_LDC_MTU		64		/* ldc mtu */


#define	IS_BROADCAST(ehp) \
		(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)

#define	VNET_MATCH_RES(vresp, vnetp)	\
	(ether_cmp(vresp->local_macaddr, vnetp->curr_macaddr) == 0)

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
	kstat_named_t	rbytes; 	/* MIB - ifInOctets */
	kstat_named_t	rbytes64;
	kstat_named_t	obytes; 	/* MIB - ifOutOctets */
	kstat_named_t	obytes64;
	kstat_named_t	multircv; 	/* MIB - ifInNUcastPkts */
	kstat_named_t	multixmt; 	/* MIB - ifOutNUcastPkts */
	kstat_named_t	brdcstrcv;	/* MIB - ifInNUcastPkts */
	kstat_named_t	brdcstxmt;	/* MIB - ifOutNUcastPkts */
	kstat_named_t	norcvbuf; 	/* MIB - ifInDiscards */
	kstat_named_t	noxmtbuf; 	/* MIB - ifOutDiscards */
} vnet_hio_kstats_t;

/*
 * A vnet resource structure.
 */
typedef struct vnet_res {
	struct vnet_res		*nextp;		/* next resource in the list */
	mac_register_t		macreg;		/* resource's mac_reg */
	vio_net_res_type_t	type;		/* resource type */
	ether_addr_t		local_macaddr;	/* resource's macaddr */
	ether_addr_t		rem_macaddr;	/* resource's remote macaddr */
	uint32_t		flags;		/* resource flags */
	uint32_t		refcnt;		/* reference count */
	struct	vnet		*vnetp;		/* back pointer to vnet */
	kstat_t			*ksp;		/* hio kstats */
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

/*
 * vnet instance state information
 */
typedef struct vnet {
	int			instance;	/* instance # */
	dev_info_t		*dip;		/* dev_info */
	uint64_t		reg;		/* reg prop value */
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

	uint32_t		flags;		/* interface flags */
	vnet_res_t		*hio_fp;	/* Hybrid IO resource */
	vnet_res_t		*vres_list;	/* Resource list */
	vnet_dds_info_t		vdds_info;	/* DDS related info */
	krwlock_t		vrwlock;	/* Resource list lock */
	ddi_taskq_t		*taskqp;	/* Resource taskq */
} vnet_t;

#define	VNET_STARTED	0x01

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
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DBG2(...)	do {						\
			    if ((vnet_dbglevel & DBG_LEVEL2) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DWARN(...)	do {						\
			    if ((vnet_dbglevel & DBG_WARN) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DERR(...)	do {						\
			    if ((vnet_dbglevel & DBG_ERR) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#else

#define	DBG1(...)	if (0)	do { } while (0)
#define	DBG2(...)	if (0)	do { } while (0)
#define	DWARN(...)	if (0)	do { } while (0)
#define	DERR(...)	if (0)	do { } while (0)

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_H */
