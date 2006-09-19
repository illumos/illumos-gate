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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * gldpriv.h - Private interfaces/structures needed by gld.c
 *
 * The definitions in this file are private to GLD and may change at any time.
 * They must not be used by any driver.
 */

#ifndef	_SYS_GLDPRIV_H
#define	_SYS_GLDPRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	DEBUG
#define	GLD_DEBUG 1
#endif

/*
 * The version number should not be changed.
 */
#define	GLD_VERSION_200		0x200			/* version 2.0 */
#define	GLD_VERSION		GLD_VERSION_200		/* current version */
#define	GLD_VERSION_STRING	"v2"			/* in modinfo string */

/* gld_global_options bits */
#define	GLD_OPT_NO_IPQ		0x00000001	/* don't use IP shortcut */
#define	GLD_OPT_NO_FASTPATH	0x00000002	/* don't implement fastpath */
#define	GLD_OPT_NO_ETHRXSNAP	0x00000008	/* don't interp SNAP on ether */

/* gld per instance options */
#define	GLDOPT_FAST_RECV	0x40
#define	GLDOPT_CANONICAL_ADDR	0x08
#define	GLDOPT_MDT		0x100

/*
 * This version of GLD allows a "Virtual-LAN-PPA" to be specified in
 * the same manner as Cassini: the virtual PPA number is composed of
 * the VLAN tag number (1-4094), multiplied by 1000(!), plus the real
 * (hardware) PPA.  Thus "bge23001" refers to the "device" which
 * transports packets with tag VLAN "23" over the hardware of "bge1".
 *
 * This scheme limits the number of physical devices of a single type to
 * 1000 e.g. bge0 .. bge999 (since bge1000 would instead be interpreted
 * as VLAN1 over bge0).
 */
#define	GLD_VLAN_SCALE		1000
#define	GLD_MAX_PPA		(GLD_VLAN_SCALE-1)

/*
 * Minor numbers:
 *
 * For each device type, GLD creates a single "style 2" node with minor 0.
 * For each instance of that device type, GLD also creates a "style 1"
 * node with minor number one greater than the PPA.  Thus, nodes with
 * minor numbers 0..1000 may exist in the /dev* filesystem.
 *
 * So, on open:
 *
 * Minor 0 implies DLPI "style 2": the STREAM is not intrinsically
 * associated with any particular device/PPA.  The association is set
 * (and may be changed) dynamically, by DLPI_ATTACH/DETACH messages.
 *
 * Minors 1..1000 are "style 1", where the PPA is entirely defined by
 * the minor; GLD defines the mapping as PPA=minor-1 (minor=PPA+1).
 * Note that the upper bound of 1000 is (now) limited by the VLAN
 * mapping scheme set out above.
 *
 * GLD devices are "self-cloning": each new open will cause a new minor
 * number to be allocated; these are selected from the range 1001..0x3ffff.
 * This minor number is only associated with the open stream and doesn't
 * appear in the /dev* filesystem; manually created nodes with minors in
 * this range will be rejected by gld_open().
 */
#define	GLD_USE_STYLE2		0

#define	GLD_MIN_STYLE1_MINOR	1
#define	GLD_MAX_STYLE1_MINOR	(GLD_MAX_PPA+1)

#define	GLD_STYLE1_MINOR_TO_PPA(minor)	(minor - 1)
#define	GLD_STYLE1_PPA_TO_MINOR(ppa)	(ppa + 1)

#define	GLD_MIN_CLONE_MINOR	(GLD_MAX_STYLE1_MINOR+1)
#define	GLD_MAX_CLONE_MINOR	0x3ffff

/* gldm_GLD_flags */
#define	GLD_MAC_READY 0x0001	/* this mac has succeeded gld_register */
#define	GLD_INTR_READY 0x0001	/* v0 compat name */
#define	GLD_INTR_WAIT 0x0002	/* v1: waiting for interrupt to do scheduling */
#define	GLD_LOCK_INITED 0x0004	/* maclock is currently initialized */
#define	GLD_UNREGISTERED 0x0008	/* this mac has succeeded gld_unregister */

/* This is the largest macaddr currently supported by GLD */
#define	GLD_MAX_ADDRLEN		32	/* Largest mac addr in all media  */

#define	GLD_MAX_MULTICAST	64	/* default multicast table size */

/* multicast structures */
typedef struct gld_multicast_addr {
	int		gldm_refcnt;	/* number of streams referring */
					/* to this per-mac entry */
	unsigned char	gldm_addr[GLD_MAX_ADDRLEN];
} gld_mcast_t;

/* gld_flag bits -- GLD PRIVATE */
#define	GLD_RAW		0x0001	/* lower stream is in RAW mode */
#define	GLD_FAST	0x0002	/* use "fast" path */
#define	GLD_PROM_PHYS	0x0004	/* stream is in physical promiscuous mode */
#define	GLD_PROM_SAP	0x0008
#define	GLD_PROM_MULT	0x0010
#define	GLD_STR_CLOSING	0x0020	/* stream is closing; don't putnext */

/*
 * gld structure.  Used to define the per-stream information required to
 * implement DLPI.
 */
typedef struct gld {
	struct gld	*gld_next, *gld_prev;
	caddr_t		gld_dummy1;
	int32_t		gld_state;	/* DL_UNATTACHED, DL_UNBOUND, DL_IDLE */
	int32_t		gld_style;	/* open style 1 or style 2 */
	int32_t		gld_minor;	/* cloned minor number */
	int32_t		gld_type;	/* DL_ETHER, DL_TPR, DL_FDDI, etc */
	int32_t		gld_sap;	/* Bound SAP */
	int32_t		gld_flags;	/* flags defined in gldpriv.h */
	int32_t		gld_multicnt;	/* # of stream multicast addresses */
	gld_mcast_t	**gld_mcast;	/* multicast table or NULL */
	queue_t		*gld_qptr;	/* pointer to streams queue */
	caddr_t		gld_dummy2;
	caddr_t		gld_dummy3;
	struct gld_mac_info *gld_mac_info;	/* if not DL_UNATTACHED */
	caddr_t		gld_dummy4;
	struct glddevice *gld_device;	/* per-major structure */

	volatile boolean_t gld_xwait;		/* want an xmit qenable */
	volatile boolean_t gld_sched_ran;	/* gld_sched examined this Q */
	volatile boolean_t gld_in_unbind;	/* DL_UNBIND in progress */
	volatile uint32_t gld_wput_count; /* number of threads in wput=>start */
	volatile boolean_t gld_in_wsrv;	/* Q thread currently running in wsrv */

	boolean_t	gld_ethertype;	/* ethertype/LLC stream */
	uint32_t	gld_notifications;
	uint32_t	gld_upri;	/* user priority */
	void		*gld_vlan;
	int (*gld_send)();
} gld_t;

/*
 * definitions for the per driver class structure
 */
typedef struct glddevice {
	struct glddevice *gld_next, *gld_prev;
	int		gld_ndevice;	/* number of mac devices linked */
	gld_mac_info_t	*gld_mac_next, *gld_mac_prev;	/* the various macs */
	gld_t		*gld_str_next, *gld_str_prev;	/* open, unattached, */
							/* style 2 streams */
	char		gld_name[16];	/* name of device */
	kmutex_t	gld_devlock;	/* used to serialize read/write locks */
	int		gld_nextminor;	/* next unused minor number for clone */
	int		gld_major;	/* device's major number */
	int		gld_multisize;	/* # of multicast entries to alloc */
	int		gld_type;	/* for use before attach */
	int		gld_minsdu;
	int		gld_maxsdu;
	int		gld_addrlen;	/* physical address length */
	int		gld_saplen;	/* sap length, neg appends */
	unsigned char	*gld_broadcast;	/* pointer to broadcast address */
	int		gld_styles;	/* provider styles */
} glddev_t;

typedef struct pktinfo {
	uint_t		isBroadcast:1;
	uint_t		isMulticast:1;
	uint_t		isLooped:1;
	uint_t		isForMe:1;
	uint_t		isLLC:1;
	uint_t		user_pri:3;
	uint_t		cfi:1;
	uint_t		vid:12;
	uint_t		wasAccepted:1;
	uint_t		nosource:1;
	uint_t		isTagged:1;
	uint_t		macLen;
	uint_t		hdrLen;
	uint_t		pktLen;
	uchar_t		dhost[GLD_MAX_ADDRLEN];
	uchar_t		shost[GLD_MAX_ADDRLEN];
	uint_t		ethertype;
} pktinfo_t;

/*
 * Flags input to the gld_interpret_*() interpreter routines.
 */
typedef enum packet_flag {
	GLD_RXQUICK,
	GLD_RXLOOP,
	GLD_RX,
	GLD_TX
} packet_flag_t;

/*
 * Flags input to the gld_interpret_mdt_*() interpreter routines.
 */
typedef enum mdt_packet_flag {
	GLD_MDT_TX,
	GLD_MDT_TXPKT,
	GLD_MDT_RXLOOP
} mdt_packet_flag_t;

/*
 * Describes characteristics of the Media Access Layer.
 * The mac_type is one of the supported DLPI media types (see <sys/dlpi.h>).
 * The mtu_size is the size of the largest frame.
 * The interpreter is the function that "knows" how to interpret the frame.
 * The interpreter_mdt routine knows how to interpret/format MDT packets.
 * Other routines create and/or add headers to packets.
 */
typedef struct {
	uint_t	mac_type;
	uint_t	mtu_size;
	int	hdr_size;
	int	(*interpreter)(gld_mac_info_t *, mblk_t *, pktinfo_t *,
		    packet_flag_t);
	void	(*interpreter_mdt)(gld_mac_info_t *, mblk_t *,
		    struct pdescinfo_s *, pktinfo_t *, mdt_packet_flag_t);
	mblk_t	*(*mkfastpath)(gld_t *, mblk_t *);
	mblk_t	*(*mkunitdata)(gld_t *, mblk_t *);
	void	(*init)(gld_mac_info_t *);
	void	(*uninit)(gld_mac_info_t *);
	char	*mac_string;
} gld_interface_t;

/*
 * structure for names stat structure usage as required by "netstat"
 */
typedef union media_kstats {
	struct dot3kstat {
		kstat_named_t	first_coll;
		kstat_named_t	multi_coll;
		kstat_named_t	sqe_error;
		kstat_named_t	mac_xmt_error;
		kstat_named_t	frame_too_long;
		kstat_named_t	mac_rcv_error;
	} dot3;
	struct dot5kstat {
		kstat_named_t	ace_error;
		kstat_named_t	internal_error;
		kstat_named_t	lost_frame_error;
		kstat_named_t	frame_copied_error;
		kstat_named_t	token_error;
		kstat_named_t	freq_error;
	} dot5;
	struct fddikstat {
		kstat_named_t	mac_error;
		kstat_named_t	mac_lost;
		kstat_named_t	mac_token;
		kstat_named_t	mac_tvx_expired;
		kstat_named_t	mac_late;
		kstat_named_t	mac_ring_op;
	} fddi;
} media_kstats_t;

struct gldkstats {
	kstat_named_t	glds_pktxmt;
	kstat_named_t	glds_pktrcv;
	kstat_named_t	glds_errxmt;
	kstat_named_t	glds_errrcv;
	kstat_named_t	glds_collisions;
	kstat_named_t	glds_bytexmt;
	kstat_named_t	glds_bytercv;
	kstat_named_t	glds_multixmt;
	kstat_named_t	glds_multircv;	/* multicast but not broadcast */
	kstat_named_t	glds_brdcstxmt;
	kstat_named_t	glds_brdcstrcv;
	kstat_named_t	glds_unknowns;
	kstat_named_t	glds_blocked;	/* discard due to upstream flow */
					/* control */
	kstat_named_t	glds_excoll;
	kstat_named_t	glds_defer;
	kstat_named_t	glds_frame;
	kstat_named_t	glds_crc;
	kstat_named_t	glds_overflow;
	kstat_named_t	glds_underflow;
	kstat_named_t	glds_short;
	kstat_named_t	glds_missed;
	kstat_named_t	glds_xmtlatecoll;
	kstat_named_t	glds_nocarrier;
	kstat_named_t	glds_noxmtbuf;
	kstat_named_t	glds_norcvbuf;
	kstat_named_t	glds_xmtbadinterp;
	kstat_named_t	glds_rcvbadinterp;
	kstat_named_t	glds_intr;
	kstat_named_t	glds_xmtretry;
	kstat_named_t	glds_pktxmt64;
	kstat_named_t	glds_pktrcv64;
	kstat_named_t	glds_bytexmt64;
	kstat_named_t	glds_bytercv64;
	kstat_named_t	glds_speed;
	kstat_named_t	glds_duplex;
	kstat_named_t	glds_media;
	kstat_named_t	glds_prom;
	media_kstats_t	glds_media_specific;
};

typedef struct gld_mac_pvt gld_mac_pvt_t;

typedef struct gld_vlan {
	struct gld_vlan *gldv_next, *gldv_prev;
	uint32_t		gldv_id;
	uint32_t		gldv_ptag;
	int			gldv_nstreams;
	gld_mac_info_t		*gldv_mac;
	queue_t			*gldv_ipq;
	queue_t			*gldv_ipv6q;
	struct gld		*gldv_str_next;	/* list of attached streams */
	struct gld		*gldv_str_prev;
	kstat_t			*gldv_kstatp;
	struct gld_stats	*gldv_stats;
	/* The number of streams that are in promiscous mode */
	uint_t			gldv_nprom;
	/* The number of streams that are interested in VLAN tagged packets. */
	uint_t			gldv_nvlan_sap;
} gld_vlan_t;

#define	VLAN_HASHSZ	23

/* Per-mac info used by GLD */
struct gld_mac_pvt {
	gld_interface_t	*interfacep;
	kmutex_t	datalock;	/* data lock for "data" */
	caddr_t		data;		/* media specific private data */
	gld_vlan_t	*vlan_hash[VLAN_HASHSZ];
	struct gld	*last_sched;	/* last scheduled stream */
	struct glddevice *major_dev;	/* per-major device struct */
	int		nvlan;		/* VLANs in use on this mac */
	int		nprom;		/* num streams in promiscuous mode */
	int		nprom_multi;	/* streams in promiscuous multicast */
	gld_mcast_t	*mcast_table;	/* per device multicast table */
	unsigned char	*curr_macaddr;	/* Currently programmed mac address */
	kstat_t		*kstatp;
	struct gld_stats *statistics;	/* The ones the driver updates */
	int		rde_enabled;	/* RDE (Source Routing) Enabled */
	int		rde_str_indicator_ste;	/* use STE when no SR info */
	int		rde_timeout;	/* route link inactivity timeout */
	uint32_t	notifications;	/* DL_NOTE options supported */
	boolean_t	started;	/* Has the MAC been started? */
};

/* return values from gld_cmds */
#define	GLDE_OK		(-1)	/* internal procedure status is OK */
#define	GLDE_RETRY	0x1002	/* want to retry later */

/* caller argument to gld_start */
#define	GLD_WPUT	0
#define	GLD_WSRV	1

#define	GLD_MAX_802_SAP	0xff

/*
 * definitions for debug tracing
 */
#define	GLDTRACE	0x0001	/* basic procedure level tracing */
#define	GLDERRS		0x0002	/* trace errors */
#define	GLDRECV		0x0004	/* trace receive path */
#define	GLDSEND		0x0008	/* trace send path */
#define	GLDPROT		0x0010	/* trace DLPI protocol */
#define	GLDNOBR		0x0020	/* do not show broadcast messages */
#define	GLDETRACE	0x0040	/* trace "normal case" errors */
#define	GLDRDE		0x0080	/* netstat -k dump routing table */

/*
 * Lock manipulation macros for GLDM_LOCK. Conceptually, the
 * GLD layer treats the lock as a rw lock; for v0 binary and
 * semantic compatibility, the underlying implementation still
 * uses a mutex, whereas for v2 drivers, the more scalable rwlock
 * is used instead. See notes in gld.h.
 */
#define	GLDM_LOCK_INIT(macinfo)						\
	rw_init(&(macinfo)->gldm_lock.gldl_rw_lock, NULL,		\
	    RW_DRIVER, (macinfo)->gldm_cookie);				\
	(macinfo)->gldm_GLD_flags |= GLD_LOCK_INITED

#define	GLDM_LOCK_INITED(macinfo)					\
	((macinfo)->gldm_GLD_flags & GLD_LOCK_INITED)

#define	GLDM_LOCK_DESTROY(macinfo)					\
	if ((macinfo)->gldm_GLD_flags & GLD_LOCK_INITED) {		\
		rw_destroy(&(macinfo)->gldm_lock.gldl_rw_lock);		\
		(macinfo)->gldm_GLD_flags &= ~GLD_LOCK_INITED;		\
	}

#define	GLDM_LOCK(macinfo, rw)						\
	rw_enter(&(macinfo)->gldm_lock.gldl_rw_lock, (rw))

#define	GLDM_UNLOCK(macinfo)						\
	rw_exit(&(macinfo)->gldm_lock.gldl_rw_lock)

#define	GLDM_TRYLOCK(macinfo, rw)					\
	rw_tryenter(&(macinfo)->gldm_lock.gldl_rw_lock, (rw))

/* lock held in read or write mode? */
#define	GLDM_LOCK_HELD(macinfo)						\
	rw_lock_held(&(macinfo)->gldm_lock.gldl_rw_lock)

/* lock held in write mode? */
#define	GLDM_LOCK_HELD_WRITE(macinfo)					\
	rw_write_held(&(macinfo)->gldm_lock.gldl_rw_lock)

/*
 * Compare/copy two MAC addresses.
 * Note that unlike bcmp, we return zero if they are different.
 */
#define	mac_eq(a, b, l) (bcmp((caddr_t)(a), (caddr_t)(b), (l)) == 0)
#define	mac_copy(a, b, l) (bcopy((caddr_t)(a), (caddr_t)(b), (l)))
/* copy a mac address to/from canonical form */
#define	cmac_copy(a, b, l, macinfo) {					\
	    if ((macinfo)->gldm_options & GLDOPT_CANONICAL_ADDR)	\
		gld_bitrevcopy((caddr_t)(a), (caddr_t)(b), (l));	\
	    else							\
		mac_copy((a), (b), (l));				\
	}

/*
 * Macros to access possibly-unaligned variables
 */

#if	(_ALIGNMENT_REQUIRED == 0)

#define	REF_HOST_USHORT(lvalue) (lvalue)
#define	REF_NET_USHORT(lvalue) (ntohs(lvalue))
#define	SET_NET_USHORT(lvalue, val) ((lvalue) = htons(val))

#else	/* ALIGNMENT_REQUIRED */

#define	REF_NET_USHORT(lvalue) \
	((ushort_t)((((uchar_t *)(&(lvalue)))[0]<<8) | \
	((uchar_t *)(&(lvalue)))[1]))

#define	SET_NET_USHORT(lvalue, val) { \
	((uchar_t *)(&(lvalue)))[0] = (uchar_t)((val)>>8); \
	((uchar_t *)(&(lvalue)))[1] = (uchar_t)(val); \
}

#if defined(_LITTLE_ENDIAN)

#define	REF_HOST_USHORT(lvalue) \
	((ushort_t)((((uchar_t *)(&(lvalue)))[1]<<8) | \
	((uchar_t *)(&(lvalue)))[0]))

#elif defined(_BIG_ENDIAN)

#define	REF_HOST_USHORT(lvalue) \
	((ushort_t)((((uchar_t *)(&(lvalue)))[0]<<8) | \
	((uchar_t *)(&(lvalue)))[1]))

#else	/* unknown endian */
#error	"what endian is this machine?"
#endif	/* endian */

#endif	/* ALIGNMENT_REQUIRED */

/* ================================================================ */
/* Route Determination Entity definitions (IEEE 802.2 1994 edition) */
/* ================================================================ */

struct rde_pdu {
	uchar_t	rde_ver;
	uchar_t	rde_ptype;
	uchar_t	rde_target_mac[6];
	uchar_t	rde_orig_mac[6];
	uchar_t	rde_target_sap;
	uchar_t	rde_orig_sap;
};

#define	LSAP_RDE	0xa6	/* IEEE 802.2 section 3.3.1.2 */
#define	RDE_RQC		0x01	/* Route Query Command */
#define	RDE_RQR		0x02	/* Route Query Response */
#define	RDE_RS		0x03	/* Route Selected */

/* ============================================================= */
/* Source Routing fields and definitions (IEEE 802.2 and 802.1D) */
/* ============================================================= */

#define	MAX_RDFLDS	14	/* changed to 14 from 8 as per IEEE */

/*
 * Source Routing Route Information field.
 */
struct gld_ri {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t len:5;			/* length */
	uchar_t rt:3;			/* routing type */
	uchar_t res:4;			/* reserved */
	uchar_t mtu:3;			/* largest frame */
	uchar_t dir:1;			/* direction bit */
	struct tr_rd {			/* route designator fields */
		ushort_t bridge:4;	/* Note: assumes network order... */
		ushort_t ring:12;	/* ...(Big Endian) -- needs ntohs() */
	} rd[MAX_RDFLDS];
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t rt:3;			/* routing type */
	uchar_t len:5;			/* length */
	uchar_t dir:1;			/* direction bit */
	uchar_t mtu:3;			/* largest frame */
	uchar_t res:4;			/* reserved */
	struct tr_rd {			/* route designator fields */
		ushort_t ring:12;
		ushort_t bridge:4;
	} rd[MAX_RDFLDS];
#else
#error	"which way do bit fields get allocated?"
#endif
};

#define	RT_SRF		0x0		/* 0xx: specifically routed frame */
#define	RT_ARE		0x4		/* 10x: all routes explorer frame */
#define	RT_STE		0x6		/* 11x: spanning tree explorer frame */

#define	RT_MTU_MAX	0x7		/* Max MTU field (base only) */

/*
 * Source route table info
 */
struct srtab {
	struct srtab	*sr_next;		/* next in linked list */
	uchar_t		sr_mac[6];		/* MAC address */
	struct		gld_ri sr_ri;		/* routing information */
	clock_t		sr_timer;
};

#define	SR_HASH_SIZE	256		/* Number of bins */

/* ================================================================= */
/* Media dependent defines for media dependent routines in gldutil.c */
/* ================================================================= */

/*
 * Some "semi-generic" defines used by ether, token, and fddi,
 * and probably anything else with addrlen == 6 && saplen == -2.
 */

struct gld_dlsap {
	unsigned char   glda_addr[ETHERADDRL];
	unsigned short  glda_sap;
};

#define	DLSAP(p, offset) ((struct gld_dlsap *)((caddr_t)(p)+offset))

typedef uchar_t mac_addr_t[ETHERADDRL];

struct llc_snap_hdr {
	uchar_t  d_lsap;		/* destination service access point */
	uchar_t  s_lsap;		/* source link service access point */
	uchar_t  control;		/* short control field */
	uchar_t  org[3];		/* Ethernet style organization field */
	ushort_t type;			/* Ethernet style type field */
};

#define	LLC_HDR1_LEN		3	/* Length of the LLC1 header */
#define	LLC_SNAP_HDR_LEN	8	/* Full length of SNAP header */
#define	LSAP_SNAP		0xaa	/* SAP for SubNet Access Protocol */
#define	CNTL_LLC_UI		0x03	/* un-numbered information packet */

/* ======================== */
/* FDDI related definitions */
/* ======================== */

struct	fddi_mac_frm {
	uchar_t		fddi_fc;
	mac_addr_t	fddi_dhost;
	mac_addr_t	fddi_shost;
};

/* ============================== */
/* Token Ring related definitions */
/* ============================== */

struct tr_mac_frm_nori {
	uchar_t		tr_ac;
	uchar_t		tr_fc;
	mac_addr_t	tr_dhost;
	mac_addr_t	tr_shost;
};

struct tr_mac_frm {
	uchar_t		tr_ac;
	uchar_t		tr_fc;
	mac_addr_t	tr_dhost;
	mac_addr_t	tr_shost;
	struct gld_ri	tr_ri;		/* Routing Information Field */
};

/*
 * Note that the pad field is used to save the value of tci.
 */
#define	GLD_SAVE_MBLK_VTAG(mp, vtag)	(DB_TCI(mp) = GLD_VTAG_TCI(vtag))
#define	GLD_CLEAR_MBLK_VTAG(mp)		GLD_SAVE_MBLK_VTAG(mp, 0)
#define	GLD_GET_MBLK_VTAG(mp)		GLD_TCI2VTAG(DB_TCI(mp))

int gld_interpret_ether(gld_mac_info_t *, mblk_t *, pktinfo_t *, packet_flag_t);
int gld_interpret_fddi(gld_mac_info_t *, mblk_t *, pktinfo_t *, packet_flag_t);
int gld_interpret_tr(gld_mac_info_t *, mblk_t *, pktinfo_t *, packet_flag_t);
int gld_interpret_ib(gld_mac_info_t *, mblk_t *, pktinfo_t *, packet_flag_t);
void gld_interpret_mdt_ib(gld_mac_info_t *, mblk_t *, pdescinfo_t *,
    pktinfo_t *, mdt_packet_flag_t);

mblk_t *gld_fastpath_ether(gld_t *, mblk_t *);
mblk_t *gld_fastpath_fddi(gld_t *, mblk_t *);
mblk_t *gld_fastpath_tr(gld_t *, mblk_t *);
mblk_t *gld_fastpath_ib(gld_t *, mblk_t *);

mblk_t *gld_insert_vtag_ether(mblk_t *, uint32_t);

mblk_t *gld_unitdata_ether(gld_t *, mblk_t *);
mblk_t *gld_unitdata_fddi(gld_t *, mblk_t *);
mblk_t *gld_unitdata_tr(gld_t *, mblk_t *);
mblk_t *gld_unitdata_ib(gld_t *, mblk_t *);

void gld_init_ether(gld_mac_info_t *);
void gld_init_fddi(gld_mac_info_t *);
void gld_init_tr(gld_mac_info_t *);
void gld_init_ib(gld_mac_info_t *);

void gld_uninit_ether(gld_mac_info_t *);
void gld_uninit_fddi(gld_mac_info_t *);
void gld_uninit_tr(gld_mac_info_t *);
void gld_uninit_ib(gld_mac_info_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_GLDPRIV_H */
