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
 * gld - Generic LAN Driver support system for DLPI drivers.
 */

#ifndef	_SYS_GLD_H
#define	_SYS_GLD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ethernet.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Media specific MIB-II counters/statistics
 *
 * This only includes those that aren't in the legacy counters.
 */

typedef union media_stats {
	struct dot3stat {
		/* Ethernet: RFC1643 Dot3Stats (subset) */
		uint32_t	first_coll;	/* SingleCollisionFrames */
		uint32_t	multi_coll;	/* MultipleCollisionFrames */
		uint32_t	sqe_error;	/* SQETestErrors */
		uint32_t	mac_xmt_error;	/* InternalMacTransmitErrors */
		uint32_t	frame_too_long;	/* FrameTooLongs */
		uint32_t	mac_rcv_error;	/* InternalMacReceiveErrors */
	} dot3;
	struct dot5stat {
		/* Token Ring: RFC1748 Dot5Stats (subset) */
		uint32_t	ace_error;
		uint32_t	internal_error;
		uint32_t	lost_frame_error;
		uint32_t	frame_copied_error;
		uint32_t	token_error;
		uint32_t	freq_error;
	} dot5;
	struct fddistat {
		/* FDDI: RFC1512 (subset) */
		uint32_t	mac_error;
		uint32_t	mac_lost;
		uint32_t	mac_token;
		uint32_t	mac_tvx_expired;
		uint32_t	mac_late;
		uint32_t	mac_ring_op;
	} fddi;
	uint32_t		pad[16];
} media_stats_t;

#define	glds_dot3_first_coll		glds_media_specific.dot3.first_coll
#define	glds_dot3_multi_coll		glds_media_specific.dot3.multi_coll
#define	glds_dot3_sqe_error		glds_media_specific.dot3.sqe_error
#define	glds_dot3_mac_xmt_error		glds_media_specific.dot3.mac_xmt_error
#define	glds_dot3_mac_rcv_error		glds_media_specific.dot3.mac_rcv_error
#define	glds_dot3_frame_too_long	glds_media_specific.dot3.frame_too_long

#define	glds_dot5_line_error		glds_crc
#define	glds_dot5_burst_error		glds_frame
#define	glds_dot5_ace_error		glds_media_specific.dot5.ace_error
#define	glds_dot5_internal_error	glds_media_specific.dot5.internal_error
#define	glds_dot5_lost_frame_error   glds_media_specific.dot5.lost_frame_error
#define	glds_dot5_frame_copied_error glds_media_specific.dot5.frame_copied_error
#define	glds_dot5_token_error		glds_media_specific.dot5.token_error
#define	glds_dot5_signal_loss		glds_nocarrier
#define	glds_dot5_freq_error		glds_media_specific.dot5.freq_error

#define	glds_fddi_mac_error		glds_media_specific.fddi.mac_error
#define	glds_fddi_mac_lost		glds_media_specific.fddi.mac_lost
#define	glds_fddi_mac_token		glds_media_specific.fddi.mac_token
#define	glds_fddi_mac_tvx_expired	glds_media_specific.fddi.mac_tvx_expired
#define	glds_fddi_mac_late		glds_media_specific.fddi.mac_late
#define	glds_fddi_mac_ring_op		glds_media_specific.fddi.mac_ring_op

/*
 * structure for driver statistics
 */
struct gld_stats {
	ulong_t		glds_multixmt;	/* (G) ifOutMulticastPkts */
	ulong_t		glds_multircv;	/* (G) ifInMulticastPkts */
	ulong_t		glds_brdcstxmt;	/* (G) ifOutBroadcastPkts */
	ulong_t		glds_brdcstrcv;	/* (G) ifInBroadcastPkts */
	uint32_t	glds_blocked;	/* (G) discard: upstream flow cntrl */
	uint32_t	glds_reserved1;
	uint32_t	glds_reserved2;
	uint32_t	glds_reserved3;
	uint32_t	glds_reserved4;
	uint32_t	glds_errxmt;	/* (D) ifOutErrors */
	uint32_t	glds_errrcv;	/* (D) ifInErrors */
	uint32_t	glds_collisions; /* (e) Sun MIB's rsIfCollisions */
	uint32_t	glds_excoll;	/* (e) dot3StatsExcessiveCollisions */
	uint32_t	glds_defer;	/* (e) dot3StatsDeferredTransmissions */
	uint32_t	glds_frame;	/* (e) dot3StatsAlignErrors */
	uint32_t	glds_crc;	/* (e) dot3StatsFCSErrors */
	uint32_t	glds_overflow;	/* (D) */
	uint32_t	glds_underflow;	/* (D) */
	uint32_t	glds_short;	/* (e) */
	uint32_t	glds_missed;	/* (D) */
	uint32_t	glds_xmtlatecoll; /* (e) dot3StatsLateCollisions */
	uint32_t	glds_nocarrier; /* (e) dot3StatsCarrierSenseErrors */
	uint32_t	glds_noxmtbuf;	/* (G) ifOutDiscards */
	uint32_t	glds_norcvbuf;	/* (D) ifInDiscards */
	uint32_t	glds_intr;	/* (D) */
	uint32_t	glds_xmtretry;	/* (G) */
	uint64_t	glds_pktxmt64;	/* (G) 64-bit rsIfOutPackets */
	uint64_t	glds_pktrcv64;	/* (G) 64-bit rsIfInPackets */
	uint64_t	glds_bytexmt64;	/* (G) ifHCOutOctets */
	uint64_t	glds_bytercv64;	/* (G) ifHCInOctets */
	uint64_t	glds_speed;	/* (D) ifSpeed */
	uint32_t	glds_duplex;	/* (e) Invented for GLD */
	uint32_t	glds_media;	/* (D) Invented for GLD */
	uint32_t	glds_unknowns;	/* (G) ifInUnknownProtos */
	uint32_t	reserved[19];
	media_stats_t	glds_media_specific;
	uint32_t	glds_xmtbadinterp; /* (G) bad packet len/format */
	uint32_t	glds_rcvbadinterp; /* (G) bad packet len/format */
	uint32_t	glds_gldnorcvbuf;  /* (G) norcvbuf from inside GLD */
};

/*
 * gld_mac_info structure.  Used to define the per-board data for all
 * drivers.
 *
 * The below definition of gld_mac_info contains GLD PRIVATE entries that must
 * not be used by the device driver. Only entries marked SET BY DRIVER should
 * be modified.
 */

#define	GLD_STATS_SIZE_ORIG	(sizeof (uint32_t) * 26) /* don't change */
#define	GLD_KSTAT_SIZE_ORIG (sizeof (kstat_named_t) * 26) /* don't change */
#define	GLD_PAD  ((int)GLD_KSTAT_SIZE_ORIG + (int)GLD_STATS_SIZE_ORIG)

typedef union gld_lock {
	kmutex_t	reserved;
	krwlock_t	gldl_rw_lock;
} gld_lock_t;

typedef struct gld_mac_info {
	struct gld_mac_info *gldm_next;			/* GLD PRIVATE */
	struct gld_mac_info *gldm_prev;			/* GLD PRIVATE */
	caddr_t		reserved1;			/* GLD PRIVATE */
	caddr_t		reserved2;			/* GLD PRIVATE */
	uint16_t	gldm_driver_version;		/* GLD PRIVATE */
	uint16_t	gldm_GLD_version;		/* GLD PRIVATE */
	uint16_t	gldm_GLD_flags;			/* GLD PRIVATE */
	uint16_t	gldm_options;			/* GLD_PRIVATE */
	dev_info_t	*gldm_devinfo;			/* SET BY DRIVER */
	uchar_t		*gldm_vendor_addr;		/* SET BY DRIVER */
	uchar_t		*gldm_broadcast_addr;		/* SET BY DRIVER */
	gld_lock_t	gldm_lock;			/* GLD PRIVATE */
	ddi_iblock_cookie_t gldm_cookie;		/* SET BY DRIVER */
	uint32_t	gldm_margin;			/* SET BY DRIVER */
	uint32_t	reserved4;			/* GLD PRIVATE */
	uint32_t	gldm_maxpkt;			/* SET BY DRIVER */
	uint32_t	gldm_minpkt;			/* SET BY DRIVER */
	char		*gldm_ident;			/* SET BY DRIVER */
	uint32_t	gldm_type;			/* SET BY DRIVER */
	uint32_t	reserved5;			/* GLD PRIVATE */
	uint32_t	gldm_addrlen;			/* SET BY DRIVER */
	int32_t		gldm_saplen;			/* SET BY DRIVER */
							/* NOTE: MUST BE -2 */
	unsigned char	reserved7[ETHERADDRL];		/* GLD PRIVATE */
	unsigned char	reserved8[ETHERADDRL];		/* GLD PRIVATE */
	unsigned char	reserved9[ETHERADDRL];		/* GLD PRIVATE */
	t_uscalar_t	gldm_ppa;			/* SET BY DRIVER */
	int32_t		reserved10;			/* GLD PRIVATE */
	uint32_t	gldm_capabilities; 		/* SET BY DRIVER */
	int32_t		gldm_linkstate;			/* GLD PRIVATE */
	uint32_t	reserved11;			/* GLD PRIVATE */
	caddr_t		reserved12;			/* GLD PRIVATE */
	int32_t		reserved13;			/* GLD PRIVATE */
	uint32_t	reserved14;			/* GLD PRIVATE */
	int32_t		reserved15;			/* GLD PRIVATE */
	caddr_t		gldm_mac_pvt;			/* GLD PRIVATE */
	caddr_t		reserved16;			/* GLD PRIVATE */
	char		reserved17[GLD_PAD];		/* GLD PRIVATE */
	caddr_t		reserved18;			/* GLD PRIVATE */
	caddr_t		gldm_private;			/* GLD PRIVATE */
	int		(*gldm_reset)();		/* SET BY DRIVER */
	int		(*gldm_start)();		/* SET BY DRIVER */
	int		(*gldm_stop)();			/* SET BY DRIVER */
	int		(*gldm_set_mac_addr)();		/* SET BY DRIVER */
	int		(*gldm_send)();			/* SET BY DRIVER */
	int		(*gldm_set_promiscuous)();	/* SET BY DRIVER */
	int		(*gldm_get_stats)();		/* SET BY DRIVER */
	int		(*gldm_ioctl)();		/* SET BY DRIVER */
	int		(*gldm_set_multicast)(); 	/* SET BY DRIVER */
	uint_t		(*gldm_intr)();			/* SET BY DRIVER */
	int		(*gldm_mctl)();			/* SET BY DRIVER */
	int		(*gldm_send_tagged)();		/* SET BY DRIVER */
	/*
	 * The following MDT related entry points are Sun private,
	 * meant only for use by Sun's IPoIB (ibd) driver.
	 */
	int		(*gldm_mdt_pre)();		/* SET BY DRIVER */
	void		(*gldm_mdt_send)();		/* SET BY DRIVER */
	void		(*gldm_mdt_post)();		/* SET BY DRIVER */
	int		gldm_mdt_sgl;			/* SET BY DRIVER */
	int		gldm_mdt_segs;			/* SET BY DRIVER */
} gld_mac_info_t;

/* flags for physical promiscuous state */
#define	GLD_MAC_PROMISC_NOOP	-1	/* leave mode unchanged		 */
#define	GLD_MAC_PROMISC_NONE	0	/* promiscuous mode(s) OFF	 */
#define	GLD_MAC_PROMISC_PHYS	1	/* receive all packets		 */
#define	GLD_MAC_PROMISC_MULTI	2	/* receive all multicast packets */

#define	GLD_MULTI_ENABLE	1
#define	GLD_MULTI_DISABLE	0

/* flags for gldm_capabilities */
#define	GLD_CAP_LINKSTATE	0x00000001 /* will call gld_linkstate() */
#define	GLD_CAP_CKSUM_IPHDR	0x00000008 /* IP checksum offload	*/
#define	GLD_CAP_CKSUM_PARTIAL	0x00000010 /* TCP/UDP partial		*/
#define	GLD_CAP_CKSUM_FULL_V4	0x00000020 /* TCP/UDP full for IPv4	*/
#define	GLD_CAP_ZEROCOPY	0x00000040 /* zerocopy */
#define	GLD_CAP_CKSUM_FULL_V6	0x00000080 /* TCP/UDP full for IPv6	*/
#define	GLD_CAP_CKSUM_ANY				\
	(GLD_CAP_CKSUM_IPHDR|GLD_CAP_CKSUM_PARTIAL|	\
	GLD_CAP_CKSUM_FULL_V4|GLD_CAP_CKSUM_FULL_V6)

/* values of gldm_linkstate, as passed to gld_linkstate() */
#define	GLD_LINKSTATE_DOWN	-1
#define	GLD_LINKSTATE_UNKNOWN	0
#define	GLD_LINKSTATE_UP	1

/*
 * media type: this identifies the media/connector currently used by the
 * driver.  Possible types will be defined for each DLPI type defined in
 * gldm_type.  The below definitions should be used by the device dependent
 * drivers to set glds_media.
 */

/* if driver cannot determine media/connector type  */
#define	GLDM_UNKNOWN	0

#define	GLDM_AUI	1
#define	GLDM_BNC	2
#define	GLDM_TP		3
#define	GLDM_FIBER	4
#define	GLDM_100BT	5
#define	GLDM_VGANYLAN	6
#define	GLDM_10BT	7
#define	GLDM_RING4	8
#define	GLDM_RING16	9
#define	GLDM_PHYMII	10
#define	GLDM_100BTX	11
#define	GLDM_100BT4	12
#define	GLDM_IB		14

/* defines for possible duplex states (glds_duplex) */
#define	GLD_DUPLEX_UNKNOWN	0
#define	GLD_DUPLEX_HALF		1
#define	GLD_DUPLEX_FULL		2

/* Values returned from driver entry points */
#define	GLD_SUCCESS		0
#define	GLD_NORESOURCES		1
#define	GLD_NOTSUPPORTED	2
#define	GLD_BADARG		3
#define	GLD_NOLINK		4
#define	GLD_RETRY		5
#define	GLD_FAILURE		(-1)

#if defined(_KERNEL)
/* Functions exported to drivers */
extern gld_mac_info_t *gld_mac_alloc(dev_info_t *);
extern void gld_mac_free(gld_mac_info_t *);
extern int gld_register(dev_info_t *, char *, gld_mac_info_t *);
extern int gld_unregister(gld_mac_info_t *);
extern void gld_recv(gld_mac_info_t *, mblk_t *);
extern void gld_recv_tagged(gld_mac_info_t *, mblk_t *, uint32_t);
extern void gld_linkstate(gld_mac_info_t *, int32_t);
extern void gld_sched(gld_mac_info_t *);
extern uint_t gld_intr();

extern int gld_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
extern int gld_open(queue_t *, dev_t *, int, int, cred_t *);
extern int gld_close(queue_t *, int, cred_t *);
extern int gld_wput(queue_t *, mblk_t *);
extern int gld_wsrv(queue_t *);
extern int gld_rsrv(queue_t *);
#endif

/*
 * VLAN tag macros
 *
 * Per IEEE802.1Q, a VLAN tag is made up of a 2-byte Tagged Protocol
 * Identifier (TPID) and two bytes of Tag/Control information (TCI).
 * All fields should be treated as unsigned, and so a VTAG is held as
 * a 'uint32_t'
 */
#define	VTAG_SIZE	4		/* bytes (octets)		*/

#define	VLAN_TPID_MASK	0xffff0000u
#define	VLAN_TPID_SHIFT	16
#define	VLAN_TCI_MASK	0x0000ffffu
#define	VLAN_TCI_SHIFT	0

#define	VLAN_PRI_MASK	0x0000e000u
#define	VLAN_PRI_SHIFT	13
#define	VLAN_CFI_MASK	0x00001000u
#define	VLAN_CFI_SHIFT	12
#define	VLAN_VID_MASK	0x00000fffu
#define	VLAN_VID_SHIFT	0

#define	VLAN_TPID	0x8100u		/* Per IEEE 802.1Q standard	*/
#define	VLAN_CFI_ETHER	0		/* CFI on Ethernet must be 0	*/
#define	VLAN_PRI_DFLT	0
#define	VLAN_PRI_MAX	7
#define	VLAN_VID_NONE	0		/* Not a valid VID		*/
#define	VLAN_VID_MIN	1
#define	VLAN_VID_MAX	4094		/* IEEE std; 4095 is reserved	*/

#define	VLAN_VTAG_NONE	0		/* Special case: "untagged"	*/

/*
 * Macros to construct a TCI or VTAG.  The user must ensure values are in
 * range.  Note that in the special case of priority tag, VLAN_VID_NONE
 * is also a valid argument to these constructor macros.
 */
#define	GLD_MAKE_TCI(pri, cfi, vid)    (((pri) << VLAN_PRI_SHIFT) |	\
					((cfi) << VLAN_CFI_SHIFT) |	\
					((vid) << VLAN_VID_SHIFT))

#define	GLD_MAKE_VTAG(pri, cfi, vid)				\
	(((uint32_t)ETHERTYPE_VLAN << VLAN_TPID_SHIFT) |	\
	((pri) << VLAN_PRI_SHIFT) |				\
	((cfi) << VLAN_CFI_SHIFT) |				\
	((vid) << VLAN_VID_SHIFT))

#define	GLD_TCI2VTAG(tci)	\
	(((uint32_t)ETHERTYPE_VLAN << VLAN_TPID_SHIFT) | (tci))

/*
 * Macros to construct a prototype TCI/VTAG and then convert it to a real one
 */
#define	GLD_MK_PTCI(cfi, vid)	GLD_MAKE_TCI(VLAN_PRI_MAX, cfi, vid)
#define	GLD_MK_PTAG(cfi, vid)	GLD_MAKE_VTAG(VLAN_PRI_MAX, cfi, vid)
#define	GLD_MK_PMSK(pri)	(((pri) << VLAN_PRI_SHIFT) | ~VLAN_PRI_MASK)
#define	GLD_MK_VTAG(ptag, pri)	((ptag) & GLD_MK_PMSK(pri))

/*
 * Deconstruct a VTAG ...
 */
#define	GLD_VTAG_TPID(vtag)	(((vtag) & VLAN_TPID_MASK) >> VLAN_TPID_SHIFT)
#define	GLD_VTAG_TCI(vtag)	(((vtag) & VLAN_TCI_MASK) >> VLAN_TCI_SHIFT)

#define	GLD_VTAG_PRI(vtag)	(((vtag) & VLAN_PRI_MASK) >> VLAN_PRI_SHIFT)
#define	GLD_VTAG_CFI(vtag)	(((vtag) & VLAN_CFI_MASK) >> VLAN_CFI_SHIFT)
#define	GLD_VTAG_VID(vtag)	(((vtag) & VLAN_VID_MASK) >> VLAN_VID_SHIFT)

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_GLD_H */
