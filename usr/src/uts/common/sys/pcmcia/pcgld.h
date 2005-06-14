/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Warning - This file is not an approved Public Interface.
 *           It may change or disappear at any time.
 */

/*
 * gld - a generic LAN driver support system for drivers using the DLPI
 * interface.
 *
 * Copyrighted as an unpublished work. (c) Copyright 1992 Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PCMCIA_PCGLD_H
#define	_SYS_PCMCIA_PCGLD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * structure for driver statistics
 */
struct gld_stats {
	uint32_t	glds_multixmt;
	uint32_t	glds_multircv;	/* multicast but not broadcast */
	uint32_t	glds_brdcstxmt;
	uint32_t	glds_brdcstrcv;
	uint32_t	glds_blocked;	/* discard due to upstream being flow */
				/* controlled */
	uint32_t	glds_pktxmt;
	uint32_t	glds_pktrcv;
	uint32_t	glds_bytexmt;
	uint32_t	glds_bytercv;
	uint32_t	glds_errxmt;
	uint32_t	glds_errrcv;
	uint32_t	glds_collisions;
	uint32_t	glds_excoll;
	uint32_t	glds_defer;
	uint32_t	glds_frame;
	uint32_t	glds_crc;
	uint32_t	glds_overflow;
	uint32_t	glds_underflow;
	uint32_t	glds_short;
	uint32_t	glds_missed;
	uint32_t	glds_xmtlatecoll;
	uint32_t	glds_nocarrier;
	uint32_t	glds_noxmtbuf;
	uint32_t	glds_norcvbuf;
	uint32_t	glds_intr;
	uint32_t	glds_xmtretry;
};

/*
 * structure for names stat structure usage as required by "netstat"
 */
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
	kstat_named_t	glds_intr;
	kstat_named_t	glds_xmtretry;
};

/* multicast structures */
typedef struct gld_multicast_addr {
	int		gldm_refcnt;	/* number of streams referring */
					/* to entry */
	unsigned char	gldm_addr[ETHERADDRL];
} gld_mcast_t;
#define	GLD_MAX_MULTICAST	16	/* default max multicast table size */

/*
 * gld_mac_info structure.  Used to define the per-board data for all
 * drivers.
 */
typedef
struct gld_mac_info {
	struct gld_mac_info *gldm_next, *gldm_prev;	/* GLD PRIVATE */
	struct gld	*gldm_last;	/* last scheduled stream -- GLD */
					/* PRIVATE */
	struct glddevice *gldm_dev;	/* pointer to device base -- GLD */
					/* PRIVATE */
	int32_t		gldm_version;	/* Currently UNUSED, must be zero */
	int32_t		gldm_GLD_flags;	/* GLD PRIVATE */
	dev_info_t	*gldm_devinfo;	/* SET BY GLD, DRIVER MAY USE */
	mblk_t		*gldm_rcvq;
					/* UNUSED */
	kmutex_t	gldm_intrlock;
	kmutex_t	gldm_maclock;	/* SET BY GLD, DRIVER MAY USE */
	ddi_iblock_cookie_t gldm_cookie;	/* SET BY GLD, DRIVER MAY USE */
	int32_t		gldm_flags;	/* PRIVATE TO DRIVER */
	int32_t		gldm_state;	/* PRIVATE TO DRIVER */
	int32_t		gldm_maxpkt;
	int32_t		gldm_minpkt;
	char		*gldm_ident;
	int32_t		gldm_type;
	uint32_t	gldm_media;
	int32_t		gldm_addrlen;	/* usually 6 but could be 2 */
	int32_t		gldm_saplen;
	unsigned char	gldm_macaddr[ETHERADDRL];
	unsigned char	gldm_vendor[ETHERADDRL];
	unsigned char	gldm_broadcast[ETHERADDRL];
	int		gldm_ppa;	/* PPA number -- GLD PRIVATE */
	off_t		gldm_reg_offset;	/* used to find base of real */
						/* shared ram */
	int32_t		gldm_nstreams;	/* GLD PRIVATE */
	int32_t		gldm_nprom;	/* num streams in promiscuous */
					/* mode--GLD PRIVATE */
	acc_handle_t	gldm_port;	/* I/O port address -- PRIVATE TO */
					/* DRIVER */
	acc_handle_t	gldm_portdata;	/* I/O port address -- PRIVATE TO */
	caddr_t		gldm_memp;	/* SET BY GLD, DRIVER MAY USE */
	int32_t		gldm_reg_index;	/* SET BY DRIVER FOR GLD TO USE */
	off_t		gldm_reg_len;	/* used to specify length of RAM */
	int32_t		gldm_irq_index;	/* SET BY DRIVER FOR GLD TO USE */
	uint32_t	gldm_options;	/* Identify features to use */
	gld_mcast_t	*gldm_mcast;	/* per device multicast table -- GLD */
					/* PRIVATE */
	struct gld_stats gldm_stats;

	struct gldkstats gldm_kstats;	/* GLD PRIVATE */
	kstat_t		*gldm_kstatp;	/* GLD PRIVATE */
	caddr_t		gldm_private;	/* board private data -- PRIVATE TO */
					/* DRIVER */
	int		(*gldm_reset)();	/* reset procedure */
	int		(*gldm_start)();	/* start board */
	int		(*gldm_stop)();		/* stop board completely */
	int		(*gldm_saddr)();	/* set physical address */
	int		(*gldm_send)();		/* transmit procedure */
	int		(*gldm_prom)();		/* set promiscuous mode */
	int		(*gldm_gstat)();	/* get board statistics */
	int		(*gldm_ioctl)();	/* Driver specific ioctls */
	int		(*gldm_sdmulti)();	/* set/delete multicast */
						/* address */
	uint32_t	(*gldm_intr)();		/* interrupt handler */
	uint32_t	(*gldm_intr_hi)();	/* inform driver of event */
	ddi_softintr_t	  gldm_softid;		/* soft intr trigger */
} gld_mac_info_t;

/* gldm_GLD_flags */
#define	GLD_INTR_READY 0x0001	/* safe to call interrupt routine */
#define	GLD_INTR_HI    0x0002	/* using above lock level handler */
#define	GLD_DEV_PRESENT	0x0004	/* removable device is present */
#define	GLD_INTR_SOFT	0x0008	/* soft handler installed */

/* flags for mac info (hardware) status */
#define	GLD_PROMISC	0x0010	/* hardware is in promiscous mode */
#define	GLD_IN_INTR	0x0020	/* in the interrupt mutex area */

/* PPA number mask */
#define	GLD_PPA_MASK	0x3f
#define	GLD_PPA_INIT	0x40
#define	GLD_USE_STYLE2	0

/* GLD Options */
#define	GLDOPT_PCMCIA		0x0001	/* PCMCIA details */
#define	GLDOPT_DRIVER_PPA	0x0002 /* driver defines PPA */

/*
 * gld structure.  Used to define the per-stream information required to
 * implement DLPI.
 */
typedef struct gld {
	struct gld	*gld_next, *gld_prev;
	mblk_t		*gld_mb;
	int32_t		gld_state;
	int32_t		gld_style;
	int32_t		gld_minor;
	int32_t		gld_type;
	int32_t		gld_sap;
	int32_t		gld_flags;	/* flags used for controlling things */
	int32_t		gld_multicnt;	/* number of multicast addresses for */
					/* stream */
	gld_mcast_t	**gld_mcast;	/* multicast table if multicast is */
					/* enabled */
	queue_t		*gld_qptr;
	kmutex_t	gld_lock;
	struct gld_mac_info *gld_mac_info;
	struct gld_stats *gld_stats;
	struct glddevice *gld_device;
} gld_t;

/* gld_flag bits */
#define	GLD_RAW		0x0001	/* lower stream is in RAW mode */
#define	GLD_FAST	0x0002	/* use "fast" path */
#define	GLD_PROM_PHYS	0x0004	/* stream is in physical promiscuous mode */
#define	GLD_PROM_SAP	0x0008
#define	GLD_PROM_MULT	0x0010
#define	GLD_XWAIT	0x0020	/* waiting for transmitter */
#define	GLD_LOCKED	0x0040	/* queue is locked (mutex) */

/* special case SAP values */
#define	GLD_802_SAP	1500
#define	GLDMAXETHERSAP	0xFFFF
#define	GLD_MAX_802_SAP 0xFF

/*
 * media type This identifies the media/connector used by the LAN type of the
 * driver.  Possible types will be defined per the DLPI type defined in
 * gldm_type
 */
/* if driver cannot determine media/connector type  */
#define	GLDM_UNKNOWN	0

/* DL_ETHER/DL_CSMACD */
#define	GLDM_AUI	1
#define	GLDM_BNC	2
#define	GLDM_TP		3
#define	GLDM_FIBER	4

/*
 * definitions for the per driver class structure
 */
typedef struct glddevice {
	struct glddevice *gld_next, *gld_prev;
	char		gld_name[16];	/* name of device */
	int		gld_status;
	krwlock_t	gld_rwlock;	/* used to serialize read/write locks */
	int		gld_minors;
	int		gld_major;
	int		gld_multisize;
	int		gld_type;	/* for use before attach */
	int		gld_minsdu;
	int		gld_maxsdu;
	gld_mac_info_t	*gld_mac_next, *gld_mac_prev;	/* the various mac */
							/* layers */
	int		gld_ndevice;	/* number of devices linked */
	int		gld_nextppa;	/* number to use for next PPA default */
	gld_t		*gld_str_next, *gld_str_prev;	/* open streams */
} glddev_t;

#define	GLD_ATTACHED	0x0001	/* board is attached so mutexes are */
				/* initialized */


/*
 * definitions for debug tracing
 */
#ifdef DEBUG
#define	GLD_DEBUG 1
#endif
#define	GLDTRACE	0x0001	/* basic procedure level tracing */
#define	GLDERRS		0x0002	/* trace errors */
#define	GLDRECV		0x0004	/* trace receive path */
#define	GLDSEND		0x0008	/* trace send path */
#define	GLDPROT		0x0010	/* trace DLPI protocol */

/*
 * other definitions
 */
#define	GLDE_OK		-1	/* internal procedure status is OK */
#define	GLDE_NOBUFFER	0x1001	/* couldn't allocate a buffer */
#define	GLDE_RETRY	0x1002	/* want to retry later */


/*
 * definitions for module_info
 */
#define	GLDIDNUM	0x8020

#define	ismulticast(cp) ((*(caddr_t)(cp)) & 0x01)

/* define structure for DLSAP value parsing */
struct gld_dlsap {
	unsigned char   glda_addr[ETHERADDRL];
	unsigned short  glda_sap;
};

#define	DLSAP(p, offset) ((struct gld_dlsap *)((caddr_t)(p)+offset))

/* union used in calculating hash values */
union gldhash {
	uint32_t   value;
	struct {
		unsigned	a0:1;
		unsigned	a1:1;
		unsigned	a2:1;
		unsigned	a3:1;
		unsigned	a4:1;
		unsigned	a5:1;
		unsigned	a6:1;
		unsigned	a7:1;
		unsigned	a8:1;
		unsigned	a9:1;
		unsigned	a10:1;
		unsigned	a11:1;
		unsigned	a12:1;
		unsigned	a13:1;
		unsigned	a14:1;
		unsigned	a15:1;
		unsigned	a16:1;
		unsigned	a17:1;
		unsigned	a18:1;
		unsigned	a19:1;
		unsigned	a20:1;
		unsigned	a21:1;
		unsigned	a22:1;
		unsigned	a23:1;
		unsigned	a24:1;
		unsigned	a25:1;
		unsigned	a26:1;
		unsigned	a27:1;
		unsigned	a28:1;
		unsigned	a29:1;
		unsigned	a30:1;
		unsigned	a31:1;
	} bits;
};

/*
 * new interface to allow informing of status changes with hardware
 * via the gld_status_change() function
 */
#define	GLDSTAT_INSERT		1 /* device just inserted */
#define	GLDSTAT_REMOVE		2 /* device just removed */

/*
 * miscellaneous linkage glue
 */
#define	DEPENDS_ON_GLD	char _depends_on[] = "misc/gld"

/*
 * defines to make porting older ISC LLC drivers to GLD easier
 */
#define	llcp_int gldm_irq
#define	LLC_ADDR_LEN ETHERADDRL
#define	GLD_EHDR_SIZE sizeof (struct ether_header)
#define	LOW(x) ((x)&0xFF)
#define	HIGH(x) (((x)>>8)&0xFF)

#if defined(_KERNEL)
extern int pcgld_open(queue_t *q, dev_t *dev, int flag, int sflag,
		cred_t *cred);
extern int pcgld_close(queue_t *q, int flag, cred_t *cred);
extern int pcgld_wput(queue_t *q, mblk_t *mp);
extern int pcgld_wsrv(queue_t *q);
extern int pcgld_rsrv(queue_t *q);
extern int pcgld_ioctl(queue_t *q, mblk_t *mp);
extern int pcgld_recv(gld_mac_info_t *macinfo, mblk_t *mp);
extern int pcgld_register(dev_info_t *, char *, gld_mac_info_t *);
extern int pcgld_unregister(gld_mac_info_t *);
extern uchar_t  pcgldbroadcastaddr[];
extern uint32_t  pcgldcrc32(uchar_t *);
#endif

/*
 * EISA support functions
 */

#define	gldnvm(ptr) ((NVM_SLOTINFO *)ptr)
#define	gld_boardid(nvm) (*(ushort_t *)(gldnvm(nvm)->boardid))
#define	gld_check_boardid(nvm, id) (gld_boardid(nvm) == id)

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PCMCIA_PCGLD_H */
