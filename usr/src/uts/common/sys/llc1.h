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
 * llc1 - an LLC Class 1 MUX compatible with SunConnect LLC2 uses DLPI
 * interface.
 *
 * Copyrighted as an unpublished work.
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LLC1_H
#define	_SYS_LLC1_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct llc_stats {
	long	llcs_nobuffer;
	long	llcs_multixmt;
	long	llcs_multircv;	/* multicast but note broadcast */
	long	llcs_brdcstxmt;
	long	llcs_brdcstrcv;
	long	llcs_blocked;	/* discard due to upstream being flow */
				/* controlled */
	long	llcs_pktxmt;
	long	llcs_pktrcv;
	long	llcs_bytexmt;
	long	llcs_bytercv;
	long	llcs_xidxmt;
	long	llcs_xidrcv;
	long	llcs_testxmt;
	long	llcs_testrcv;
	long	llcs_ierrors;
	long	llcs_oerrors;
};

#define	LLCS_NOBUFFER	0
#define	LLCS_MULTIXMT	1
#define	LLCS_MULTIRCV	2
#define	LLCS_BRDCSTXMT	3
#define	LLCS_BRDCSTRCV	4
#define	LLCS_BLOCKED	5
#define	LLCS_PKTXMT	6
#define	LLCS_PKTRCV	7
#define	LLCS_BYTEXMT	8
#define	LLCS_BYTERCV	9
#define	LLCS_XIDXMT	10
#define	LLCS_XIDRCV	11
#define	LLCS_TESTXMT	12
#define	LLCS_TESTRCV	13
#define	LLCS_IERRORS	14
#define	LLCS_OERRORS	15

/* multicast structures */
typedef struct llc1_multicast_addr {
	int		llcm_refcnt;	/* number of streams referring to */
					/* entry */
	unsigned char	llcm_addr[ETHERADDRL];
} llc_mcast_t;
#define	LLC1_MAX_MULTICAST	16	/* default max multicast table size */

typedef
struct llc_mac_info {
	struct llc_mac_info *llcp_next, *llcp_prev;
	long		llcp_flags;
	long		llcp_maxpkt;
	long		llcp_minpkt;
	long		llcp_type;
	long		llcp_addrlen;	/* usually 6 but could be 2 */
	unsigned char	llcp_macaddr[ETHERADDRL];
	unsigned char	llcp_broadcast[ETHERADDRL];
	queue_t		*llcp_queue;	/* queue to MAC device */
	long		llcp_lindex;	/* link index for unlink */
	long		llcp_ppa;	/* the PPA number */
	long		llcp_sap;	/* when doing auto bind on lower */
					/* stream */
	mblk_t		*llcp_data;	/* temporarily hold data */
	queue_t		*llcp_lqtop;	/* queue for ioctls */
	mblk_t		*llcp_mb;
	long		llcp_nstreams;
	llc_mcast_t	*llcp_mcast;	/* per device multicast table */
	struct llc_stats llcp_stats;
	kstat_t		*llcp_kstatp;
	uint_t		llcp_iocid;	/* outstanding ioc_id */
} llc_mac_info_t;

/* flags for mac info (link) status */
#define	LLC1_LINKED	0x0001	/* there is a stream linked but not ready */
#define	LLC1_AVAILABLE	0x0002	/* linked stream is now ready */
#define	LLC1_INFO_WAIT	0x0004	/* waiting on info_ack */
#define	LLC1_DEF_PPA	0x0008	/* default (system assigned PPA) */
#define	LLC1_RAW_WAIT	0x0010	/* waiting for DLIOCRAW to happen */
#define	LLC1_USING_RAW	0x0020	/* lower driver is using DLIOCRAW mode */
#define	LLC1_AUTO_XID	0x0040	/* automatically respond to XID */
#define	LLC1_AUTO_TEST	0x0080	/* automatically respond to TEST */
#define	LLC1_BINDING	0x0100	/* autmatically binding the lower stream */

typedef struct llc1 {
	struct llc1	*llc_next, *llc_prev;
	mblk_t		*llc_mb;
	long		llc_state;
	long		llc_style;
	long		llc_minor;
	long		llc_type;
	long		llc_sap;
	uchar_t		llc_snap[5];	/* SNAP header */
	long		llc_waiting_for;	/* DL request to lower layer */
	long		llc_flags;	/* flags used for controlling things */
	long		llc_multicnt;	/* number of multicast addresses for */
					/* stream */
	llc_mcast_t	**llc_mcast;	/* multicast table if multicast is */
					/* enabled */
	queue_t		*llc_qptr;
	kmutex_t	llc_lock;
	struct llc_mac_info *llc_mac_info;
	struct llc_stats *llc_stats;
} llc1_t;

/* llc_flag bits */
#define	LLC_RAW		0x0001	/* lower stream is in RAW mode */
#define	LLC_FAST	0x0002	/* use "fast" path */
#define	LLC_PROM	0x0004	/* stream is in physical promiscuous mode */
#define	LLC_SNAP	0x0008	/* stream is using SNAP header */
#define	LLC_SNAP_OID	0x0010	/* stream is SNAP, OID is defined */


typedef struct llc1device {
	long		llc1_status;
	krwlock_t	llc1_rwlock;	/* used to serialize read/write locks */
	int		llc1_minors;
	int		llc1_multisize;
	llc_mac_info_t	*llc1_mac_next, *llc1_mac_prev;	/* the various mac */
							/* layers */
	int		llc1_ndevice;	/* number of devices linked */
	int		llc1_nextppa;	/* number to use for next PPA default */
	llc1_t		*llc1_str_next, *llc1_str_prev;	/* open streams */
} llc1dev_t;

#define	LLC1_ATTACHED	0x0001	/* board is attached so mutexes are */
				/* initialized */


/*
 * definitions for debug tracing
 */
#define	LLCTRACE	0x0001	/* basic procedure level tracing */
#define	LLCERRS		0x0002	/* trace errors */
#define	LLCRECV		0x0004	/* trace receive path */
#define	LLCSEND		0x0008	/* trace send path */
#define	LLCPROT		0x0010	/* trace DLPI protocol */

/*
 * other definitions
 */
#define	LLCE_OK		-1	/* internal procedure status is OK */
#define	LLCE_NOBUFFER	0x1001	/* couldn't allocate a buffer */


/*
 * definitions for module_info
 */
#define	LLC1IDNUM	0x8022
#define	LLC1_HIWATER	32000	/* high water mark for flow control */
#define	LLC1_LOWATER	4096	/* low water mark for flow control */
#define	LLC1_DEFMAX	4096	/* default max packet size */

/* address format for unitdata */

struct llcaddr {
	unsigned char   llca_addr[ETHERADDRL];
	unsigned char   llca_sap;
};
#define	LLCADDR(p, offset) ((struct llcaddr *)(((caddr_t)(p))+(offset)))

struct llcsaddr {
	unsigned char   llca_saddr[ETHERADDRL];
	unsigned short  llca_ssap;
};
#define	LLCSADDR(p, offset) ((struct llcsaddr *)(((caddr_t)(p))+(offset)))

/*
 * 802.2 specific declarations
 */
struct llchdr {
	unsigned char   llc_dsap;
	unsigned char   llc_ssap;
	unsigned char   llc_ctl;
};
struct llchdr_xid {
	unsigned char   llcx_format;
	unsigned char   llcx_class;
	unsigned char   llcx_window;
};
struct snaphdr {
	uchar_t		snap_oid[3];
	uchar_t		snap_type[2];
};

#define	LLC_UI		0x3
#define	LLC_XID 	0xAF
#define	LLC_TEST	0xE3
#define	LLC_P		0x10	/* P bit for use with XID/TEST */
#define	LLC_XID_FMTID	0x81	/* XID format identifier */
#define	LLC_SERVICES	0x01	/* Services supported */
#define	LLC_GLOBAL_SAP	0XFF	/* Global SAP address */
#define	LLC_NULL_SAP	0x00
#define	LLC_SNAP_SAP	0xAA	/* SNAP SAP */
#define	LLC_GROUP_ADDR	0x01	/* indication in DSAP of a group address */
#define	LLC_RESPONSE	0x01	/* indication in SSAP of a response */
#define	LLC_NOVELL_SAP	-1	/* indicator that Novell 802.3 mode is used */

#define	LLC_XID_INFO_SIZE	3	/* length of the INFO field */
#define	LLC_XID_CLASS_I		(0x01)	/* Class I */
#define	LLC_XID_CLASS_II	(0x03)	/* Class II */
#define	LLC_XID_CLASS_III	(0x05)	/* Class III */
#define	LLC_XID_CLASS_IV	(0x07)	/* Class IV */

/* Types can be or'd together */
#define	LLC_XID_TYPE_1		(0x01)	/* Type 1 */
#define	LLC_XID_TYPE_2		(0x02)	/* Type 2 */
#define	LLC_XID_TYPE_3		(0x04)	/* Type 3 */

#define	LLC1_CSMACD_HDR_SIZE	(2*ETHERADDRL+2)

#define	ismulticast(cp) ((*(caddr_t)(cp)) & 0x01)

/*
 * special ioctl calls for SunSelect LLC2 conformance
 */
#define	L_GETPPA	(('L'<<8)|1)
#define	L_SETPPA	(('L'<<8)|2)
#define	L_GETSTATS	(('L'<<8)|5)
#define	L_ZEROSTATS	(('L'<<8)|6)

#define	LI_SPPA		0x02	/* type of snioc structure */

struct ll_snioc {
	uchar_t		lli_type;
	uchar_t		lli_spare[3];
	int		lli_ppa;
	int		lli_index;
};

/*
 * version of insque/remque for use by this driver
 */
struct qelem {
	struct qelem   *q_forw;
	struct qelem   *q_back;
	/* rest of structure */
};

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_LLC1_H */
