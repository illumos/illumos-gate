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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ****** NOTICE **** This header file is maintained in the SMS gate,
 * ****** NOTICE **** the ON gate, and the ssc driver gate. Any changes
 * ****** NOTICE **** to it must also be made to in all gates.
 */

#ifndef	_DMAN_H
#define	_DMAN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Ethernet stuff
 */

#define	ETHERHEADER_SIZE (sizeof (struct ether_header))
typedef struct ether_header ehdr_t;
typedef struct ether_addr eaddr_t;
#define	IS_BROADCAST(eap) \
		(ether_cmp(eap, &etherbroadcast) == 0)
#define	IS_MULTICAST(eap) \
		((eap->ether_addr_octet[0] & 01) == 1)
#define	IS_UNICAST(eap) \
		(!IS_BROADCAST(eap) && !IS_MULTICAST(eap))

#define	MAN_IS_DATA(mp)		((DB_TYPE(mp) == M_DATA) ||		\
				    ((DB_TYPE(mp) == M_PROTO) &&	\
				    (DL_PRIM(mp) == DL_UNITDATA_IND)))

#define	MAN_ADDRL (sizeof (uint16_t) + ETHERADDRL)

/*
 * Private	DLPI full dlsap address format - stolen from eri.h
 */
typedef struct  man_dladdr_s {
	struct  ether_addr	dl_phys;
	uint16_t		dl_sap;
} man_dladdr_t;

#define	put_ether_type(ptr, value) {\
	((uint8_t *)(&((ehdr_t *)ptr)->ether_type))[0] = \
	    ((uint16_t)value & 0xff00) >> 8; \
	((uint8_t *)(&((ehdr_t *)ptr)->ether_type))[1] = (value & 0xff); }
#define	ether_bcopy(a, b) (bcopy((caddr_t)a, (caddr_t)b, 6))

#define	MAN_MAX_EXPANDERS		18
#define	MAN_MAX_DESTS			38 /* (MAN_NUM_EXPANDERS * 2) + 2 */
#define	MAN_DEST_ARRAY_SIZE		(MAN_MAX_DESTS * sizeof (man_dest_t))
#define	TRUE		1
#define	FALSE		0

/*
 * Caller IDs for man_sendit processing decision on canput failure.
 */
#define	MAN_UPPER	0x1
#define	MAN_LOWER	0x2

/*
 * MAN device information structure, one per man instance
 *
 * global list pointed to by MAN_XX_head
 */
typedef struct man_s {
	struct man_s	*man_next;		/* next in list of devices */
	dev_info_t	*man_dip;		/* devinfo for this device */
	int		man_meta_ppa;		/* mxx device minor */
	major_t		man_meta_major;		/* mxx device major # */
	struct man_pg_s	*man_pg;		/* Pathgroups for this inst */
	int		man_refcnt;		/* DL_ATTACHes to us */
	int		man_suspended;		/* DDI_SUSPEND on device */
	kstat_t		*man_ksp;		/* meta interface statistics */
	int		man_eaddr_v;		/* ether addr valid */
	eaddr_t		man_eaddr;		/* active ether addr */
	/*
	 * Failover timers, used by man_dest_t.
	 */
	int32_t		man_init_time;		/* init time in usecs */
	int32_t		man_linkcheck_time;	/* linkcheck time in usecs */
	int32_t		man_linkstale_time;	/* linkstale time in usecs */
	int32_t		man_linkstale_retries;	/* linkstale retries/probes */
	int32_t		man_dr_delay;		/* DR retry delay in usecs */
	int32_t		man_dr_retries;		/* DR retries on EAGAIN errs */
	int32_t		man_kstat_waittime;	/* kstat_wait time in usecs */
	int32_t		man_dlpireset_time;	/* dlpireset time in usecs */
} man_t;

/*
 * MAN link state definitions
 */
#define	MAN_LINKUNKNOWN		0x0
#define	MAN_LINKINIT		0x1
#define	MAN_LINKGOOD		0x2
#define	MAN_LINKSTALE		0x3
#define	MAN_LINKFAIL		0x4

/*
 * MAN timer types and times.
 */
#define	MAN_TIMER_INIT		0x1
#define	MAN_TIMER_LINKCHECK	0x2
#define	MAN_TIMER_DLPIRESET	0x4
#define	MAN_INIT_TIME		1000000		/* 1 sec in usecs */
#define	MAN_LINKCHECK_TIME	30000000	/* 30 secs in usecs */
#define	MAN_LINKSTALE_TIME	1000000		/* 1 secs in usecs */
#define	MAN_LINKSTALE_RETRIES	10		/* send 10 probes */
#define	MAN_KSTAT_WAITTIME	300000		/* 0.3 secs in usecs */
#define	MAN_DLPIRESET_TIME	5000000		/* 5 secs in usecs */
#define	MAN_MAX_DLPIERRORS	10		/* 10 dlpi errors */

/*
 * MAN DR variables
 */
#define	MAN_DR_DELAY		200000		/* 1/5th sec in usecs */
#define	MAN_DR_RETRIES		150		/* DR retries on EAGAIN errs */

/*
 * Device info - this must stay 64 bit aligned.
 */
typedef struct md_s {
	major_t		mdev_major;	/* Driver major */
	uint32_t	mdev_ppa;	/* Driver instance */
	uint32_t	mdev_exp_id;	/* Containing expander in domain */
	uint32_t	mdev_state;	/* Device state */
} man_dev_t;

/*
 * mdev_state definitions
 */
#define	MDEV_UNASSIGNED		0x0	/* Path assigned to a destination */
#define	MDEV_ASSIGNED		0x1	/* Path assigned to a destination */
#define	MDEV_ACTIVE		0x2	/* Path actively in use for dest */
#define	MDEV_FAILED		0x4	/* Failure detected in past. */

/*
 * MAN lower multiplexor data structure
 */
typedef struct man_dest_s {
	uint_t		md_state;	/* state of this destination */
	struct manstr_s	*md_msp;	/* containing upper STREAM structure */
	queue_t		*md_rq;		/* upper read queue */
	queue_t		*md_wq;		/* lower write queue  for active path */
	man_dev_t	md_device;	/* Device from active path. */
	int		md_pg_id;	/* pathgroup for destination */
	eaddr_t		md_dst_eaddr;	/* Destinations ether address */
	eaddr_t		md_src_eaddr;	/* Our ether address */
	int		md_dlpistate;	/* DLPI State of netdev below us */
	int		md_muxid;	/* muxid of netdev linked below us */
	void *		md_switch_id;	/* ID of switch request */
	kmutex_t	md_lock;	/* Lock for md_dmp_* */
	mblk_t		*md_dmp_head;	/* deferred mblk list head */
	mblk_t		*md_dmp_tail;	/* deferred mblk list tail */
	size_t		 md_dmp_count;	/* bytes in deferred mblk list */
	ulong_t		md_switches;	/* # of failover switches */
	time_t		md_lastswitch;	/* time of last switch */
	timeout_id_t	md_bc_id;	/* qbufcall timeout id */
	/*
	 * Failover variables, only valid for active path.
	 */
	timeout_id_t	md_lc_timer_id;		/* qtimeout ID */
	int		md_linkstate;		/* link state */
	ulong_t		md_lastrcvcnt;		/* snapshot of packet count */
	ulong_t		md_rcvcnt;		/* current packet count */
	ulong_t		md_linkfails;		/* # of AP link failures */
	ulong_t		md_linkstales;		/* # of AP link stales */
	int32_t		md_linkstale_retries;	/* # of probes to send */
	ulong_t		md_icmpv4probes;	/* # of ICMPv4 probes sent */
	ulong_t		md_icmpv6probes;	/* # of ICMPv6 probes sent */
	int		md_link_updown_msg;	/* Last up/down message */
	int		md_dlpierrors;		/* # of DLPI errors */
} man_dest_t;

/*
 * md_state values
 */
#define	MAN_DSTATE_NOTPRESENT	0x0	/* Destination doesnt exist */
#define	MAN_DSTATE_INITIALIZING	0x1	/* Initialize lower stream for dest */
#define	MAN_DSTATE_READY	0x2	/* Destination lower stream exists */
#define	MAN_DSTATE_PLUMBING	0x4	/* lower stream being switched */
#define	MAN_DSTATE_CLOSING	0x8	/* lower stream closing */
#define	MAN_DSTATE_BUSY		(MAN_DSTATE_PLUMBING|MAN_DSTATE_CLOSING)

/*
 * md_link_updwon_msg states.
 */
#define	MAN_LINK_UP_MSG		0x0	/* Last msg emitted was "Link up" */
#define	MAN_LINK_DOWN_MSG	0x1	/* Last msg emitted was "Link down" */

/*
 * Upper per-stream instance state information.
 *
 * Each instance is dynamically allocated at open() and free'd at close().
 * Each per-stream instance points to at most one per-device structure
 * using the ms_manp field.  All instances are threaded together into one
 * list of active instances ordered on sequence of opens.
 */
typedef struct manstr_s {
	struct manstr_s	*ms_next;	/* next in list of streams */
	man_t		*ms_manp;	/* MAN device info pointer */
	man_dest_t	*ms_destp;	/* Optimization if only one ms_dests */
	man_dest_t	*ms_dests;	/* lower streams */
	int		ms_flags;	/* State for this MAN upper stream */
	queue_t		*ms_rq;		/* MAN upper read queue */
	int		ms_minor;	/* minor number of this stream */
	t_uscalar_t	ms_sap;		/* SAP bound to (if DL_BOUND) */
	int		ms_dlpistate;	/* DLPI State of this MAN instance */
	major_t		ms_meta_maj;	/* mxx device major # */
	int		ms_meta_ppa;	/* mxx device minor # */
	mblk_t		*ms_dl_mp;	/* list of DLPI ATTACH/BIND rqsts */
	mblk_t		*ms_dlioc_mp;	/* list of DL_IOC rqsts */
	uint_t		ms_dp;		/* # of pending DL_DETACH_REQs */
	ulong_t		ms_switches;	/* number of switches so far	*/
} manstr_t;

/*
 * ms_flags values.
 */
#define	MAN_SFLAG_FAST		0x1	/* M_DATA fastpath mode */
#define	MAN_SFLAG_RAW		0x2	/* M_DATA plain raw mode */
#define	MAN_SFLAG_ALLPHYS	0x4	/* promiscuous mode */
#define	MAN_SFLAG_ALLMULTI	0x8	/* enable all multicast addresses */
#define	MAN_SFLAG_ALLSAP	0x10	/* enable all ether type values */
#define	MAN_SFLAG_CKSUM		0x20	/* enable hardware tcp checksumming */
#define	MAN_SFLAG_MULTI		0x40	/* enable multicast addresses */
#define	MAN_SFLAG_SERLPBK	0x80	/* enable SERDES looopback (DIAG) */
#define	MAN_SFLAG_MACLPBK	0x100	/* enable MAC int loopback (DIAG) */

#define	MAN_SFLAG_PROMISC	(MAN_SFLAG_ALLPHYS|MAN_SFLAG_ALLMULTI| \
					MAN_SFLAG_ALLSAP)
#define	MAN_SFLAG_CLOSING	0x200	/* Stream in process of closing */
#define	MAN_SFLAG_CLOSE_DONE	0x400	/* Stream in process of closing */
#define	MAN_SFLAG_CONTROL	0x800	/* Stream is control stream */

/*
 * Paths in pathgroup lists.
 */
typedef struct mpa_s {
	struct mpa_s	*mp_next;	/* Next in linked list */
	man_dev_t	mp_device;	/* Device for this path */
	kstat_named_t	*mp_last_knp;	/* last named kstats from mp_phys_ksp */
	time_t		mp_lru;		/* Last time used */
} man_path_t;

/*
 * Pathgroup list, one per destination ID. Each pathgroup connects
 * to one destination. Hence we put that destination ethernet address
 * here. It is read from here and stored in man_dest_t.md_dst_eaddr
 * each time a new path is switched to.
 */
typedef struct man_pg_s {
	struct man_pg_s		*mpg_next;
	int			mpg_flags;
	uint_t			mpg_pg_id;
	uint_t			mpg_man_ppa;	/* MAN instance for pathgroup */
	eaddr_t			mpg_dst_eaddr;
	man_path_t		*mpg_pathp;
} man_pg_t;
/*
 *  mpg_pg_flags fields.
 */
#define	MAN_PG_IDLE		0x0
#define	MAN_PG_SWITCHING	0x1

/*
 * MAN IOCTL Definitions.
 */
#define	MIOC			('M'<< 16)
#define	MAN_SETPATH		(MIOC|0x1)
#define	MAN_GETEADDR		(MIOC|0x2)
#define	MAN_SET_LINKCHECK_TIME	(MIOC|0x3)
#define	MAN_SET_SC_IPADDRS	(MIOC|0x4)
#define	MAN_SET_SC_IP6ADDRS	(MIOC|0x8)

/*
 * Pathgroup assignment data structure - this must stay 64 bit aligned.
 */
typedef struct mi_path_t {
	uchar_t		mip_cmd;	/* Cmd for this pathgroup */
	uchar_t		pad1[3];
	uint32_t	mip_man_ppa;	/* Man instance to apply cmd to */
	uint32_t	mip_pg_id;	/* pathgroup ID this path is for */
	eaddr_t		mip_eaddr;	/* Eaddr for this destination */
	uchar_t		pad2[2];
	man_dev_t	mip_devs[MAN_MAX_DESTS]; /* Array of devices */
	uint32_t	mip_ndevs;	/* #devs at mip_devs */
} mi_path_t;

#define	MI_PATH_READ		0x0	/* Fill in devs for destID */
#define	MI_PATH_ASSIGN		0x1	/* Assign devs for destID */
#define	MI_PATH_ACTIVATE	0x2	/* Mark a dev as active for destID */
#define	MI_PATH_DEACTIVATE	0x3	/* Deactivate active dev for destID */
#define	MI_PATH_UNASSIGN	0x4	/* Unassign assigned dev for destID */
#define	MI_PATH_ADD		0x5	/* Just Add devs for destID */

/*
 * Linkcheck time assignment data structure - this must stay 64 bit aligned.
 */
typedef struct mi_time_t {
	int32_t		mtp_man_ppa;	/* Man instance to apply cmd to */
	int32_t		mtp_time;	/* Time in usecs to */
} mi_time_t;

/*
 * SC IP address assignment data structure. See man_pinger().
 */
typedef struct man_sc_ipaddrs_s {
	in_addr_t	ip_other_sc_ipaddr;
	in_addr_t	ip_my_sc_ipaddr;
} man_sc_ipaddrs_t;

/*
 * SC IPv6 address assignment data structure. See man_pinger().
 */
typedef struct man_sc_ip6addrs_s {
	in6_addr_t	ip6_other_sc_ipaddr;
	in6_addr_t	ip6_my_sc_ipaddr;
} man_sc_ip6addrs_t;

/*
 * Array of dests to apply operation to.
 */
typedef struct man_adest_s {
	int		a_man_ppa;	/* man instance */
	int		a_pg_id;	/* pg_id of dests */
	uint32_t	a_exp_id;	/* Used for DR requests */
	man_dev_t	a_sf_dev;	/* Switch from device */
	man_dev_t	a_st_dev;	/* Switch to device */
	man_dest_t	*a_mdp;		/* array of dests for mw_type */
	uint_t		a_ndests;	/* size of array */
} man_adest_t;

/*
 * work structure for MAN background thread.
 */
typedef struct man_work_s {
	struct	man_work_s	*mw_next;	/* next request on q */
	queue_t			*mw_q;		/* For qwait-ers */
	int			mw_type;	/* work request type */
	int			mw_flags;	/* asycn/sync flags */
	int			mw_status;	/* Status of work request */
	man_adest_t		mw_arg;		/* work argument */
	kcondvar_t		mw_cv;		/* sender sleeps here */
} man_work_t;

/*
 * Values for mw_flags
 */
#define	MAN_WFLAGS_NOWAITER	0x0
#define	MAN_WFLAGS_CVWAITER	0x1
#define	MAN_WFLAGS_QWAITER	0x2
#define	MAN_WFLAGS_DONE		0x4

/*
 * Values for mw_type.
 */
#define	MAN_WORK_OPEN_CTL	0x0	/* Open the control stream */
#define	MAN_WORK_CLOSE_CTL	0x1	/* Open the control stream */
#define	MAN_WORK_SWITCH		0x2	/* Dest requests switch to new path */
#define	MAN_WORK_PATH_UPDATE	0x3	/* pathgrp info changed, update dests */
#define	MAN_WORK_CLOSE		0x4	/* Close destinations */
#define	MAN_WORK_CLOSE_STREAM	0x5	/* man_close()-ing upper stream */
#define	MAN_WORK_DRATTACH	0x6	/* DR attached new IO board */
#define	MAN_WORK_DRDETACH	0x7	/* DR detached an IO board */
#define	MAN_WORK_STOP		0x8	/* Stop and exit */
#define	MAN_WORK_DRSWITCH	0x9	/* Switch path prior to DRDETACH */
#define	MAN_WORK_KSTAT_UPDATE	0xA	/* Take kstat snapshot */

#define	MAN_IDNUM	(13138)		/* module ID number */
#define	MAN_MINPSZ	(0)		/* min packet size */
#define	MAN_MAXPSZ	(INFPSZ)	/* max packet size */
#define	MAN_HIWAT	(64 * 1024)	/* hi-water mark */
#define	MAN_LOWAT	(1)		/* lo-water mark */
#define	MAN_MEDIA	"Ethernet"	/* media type */

/*
 * State definitions for man_config_state
 */
#define	MAN_UNCONFIGURED	0x0		/* Attached but never opened */
#define	MAN_CONFIGURING		0x1		/* First open */
#define	MAN_CONFIGURED		0x2		/* Done configuring */
#define	MAN_FINI		0x3		/* cv_waiting in _fini() */

/*
 * IOSRAM definitions
 */
#define	MANC_VERSION		0x1
#define	IOSRAM_KEY_MANC		(('M'<<24)|('A'<<16)|('N'<<8)|'C')
#define	IOSRAM_KEY_SCMD		(('S'<<24)|('C'<<16)|('M'<<8)|'D')
#define	IOSRAM_KEY_MDSC		(('M'<<24)|('D'<<16)|('S'<<8)|'C')
#define	MAN_IOSRAM_TIMEOUT	10000		/* 10 secs in ms */

typedef struct manc_s {
	uint32_t	manc_magic;		/* MANC_MAGIC */
	uint32_t	manc_version;		/* MANC_VERSION */
	uint32_t	manc_csum;		/* TBD */
	int		manc_ip_type;		/* AF_INET or AF_INET6 */
	in_addr_t	manc_dom_ipaddr;	/* Domains IP address */
	in_addr_t	manc_dom_ip_netmask;	/* Domains IP netmask */
	in_addr_t	manc_sc_ipaddr;		/* SC's IP address */
	in6_addr_t	manc_dom_ipv6addr;	/* Domain's IPv6 address */
	in6_addr_t	manc_dom_ipv6_netmask;	/* Domain's IPv6 netmask */
	in6_addr_t	manc_sc_ipv6addr;	/* SC's IPv6 address */
	eaddr_t		manc_dom_eaddr;		/* 48 bit ethernet address */
	eaddr_t		manc_sc_eaddr;		/* 48 bit ethernet address */
	uint32_t	manc_iob_bitmap;	/* initial ioboard list */
	uchar_t		manc_golden_iob;	/* post selected ioboard */
} manc_t;


typedef struct man_mb_s {
	uint32_t		mb_status;
	uint32_t		mb_exp_id;
} man_mbox_msg_t;

typedef struct ml_s {
	struct ml_s	*l_next;
	int		l_muxid;
	queue_t		*l_rq;
	queue_t		*l_wq;
} man_linkrec_t;

typedef struct man_workq_s {
	man_work_t	*q_work;
	kcondvar_t	q_cv;
	bufcall_id_t	*q_id;
} man_workq_t;

/*
 * PCI stuff.
 */

/*
 * Misc defines
 */
#define	MAN_DDI_BUFLEN		128
#define	MAN_DEVTYPE_PROP	"device_type"
#define	MAN_REG_PROP		"reg"
#define	MAN_PORTID_PROP		"portid"
#define	MAN_DEVTYPE_PCI		"pci"
#define	MAN_PCI_B_CSR_BASE	0x00700000
#define	MAN_SCHIZO_MASK		0xF
#define	MAN_SCHIZO_0_ID		0xC

/* ------------------------------------------------------------------------- */
/*
 * Patchable debug flag.
 * Set this to nonzero to enable error messages.
 */

/*
 * The following parameters may be configured by the user. If they are not
 * configured by the user, the values will be based on the capabilities of
 * the transceiver.
 * The value "MAN_NOTUSR" is ORed with the parameter value to indicate values
 * which are NOT configured by the user.
 */

/* command */

#define	MAN_ND_GET	ND_GET
#define	MAN_ND_SET	ND_SET
#define	MAN_NOTUSR	0x0f000000
#define	MAN_MASK_1BIT	0x1
#define	MAN_MASK_2BIT	0x3
#define	MAN_MASK_8BIT	0xff

typedef struct param_s {
	uint32_t param_min;
	uint32_t param_max;
	uint32_t param_val;
	char   *param_name;
} param_t;

#if defined(DEBUG)
#define	MAN_DBG(flag, msg)	{ if (man_debug&flag) (void) printf msg; }
#define	MAN_DBGCALL(flag, func)	{ if (man_debug&flag) (void) func; }

#define	MAN_INIT	0x00000001
#define	MAN_OCLOSE	0x00000002
#define	MAN_CONFIG	0x00000004
#define	MAN_SWITCH	0x00000008
#define	MAN_IOSRAM	0x00000010
#define	MAN_LINK	0x00000020
#define	MAN_PATH	0x00000040
#define	MAN_DEST	0x00000080
#define	MAN_KSTAT	0x00000100
#define	MAN_KSTAT2	0x00000200
#define	MAN_DDI		0x000001FF

#define	MAN_UWPUT	0x00000400
#define	MAN_LWPUT	0x00000800
#define	MAN_LRPUT	0x00001000
#define	MAN_LRPUT2	0x00002000
#define	MAN_PUT		(MAN_UWPUT | MAN_LWPUT | MAN_LRPUT)
#define	MAN_UWSRV	0x00004000
#define	MAN_LWSRV	0x00008000
#define	MAN_LRSRV	0x00010000
#define	MAN_DATA	0x00020000
#define	MAN_DLPI	0x00040000
#define	MAN_SRV		(MAN_UWSRV | MAN_LWSRV | MAN_LRSRV)
#define	MAN_STREAMS	(MAN_PUT | MAN_SRV | MAN_OCLOSE)

#define	MAN_CALLS	(MAN_DDI | MAN_STREAMS)

#define	MAN_STATE	0x00080000
#define	MAN_WARN	0x00100000
#define	MAN_DEBUG	(MAN_CALLS | MAN_WARN | MAN_STATE)
#define	MAN_KMEM	0x00200000
#define	MAN_DR		0x00400000
#define	MAN_ALL		0xFFFFFFFF

#else

#define	MAN_DBG(flag, msg)
#define	MAN_DBGCALL(flag, func)

#endif  /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif /* _DMAN_H */
