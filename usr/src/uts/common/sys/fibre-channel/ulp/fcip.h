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

#ifndef	_SYS_FIBRE_CHANNEL_ULP_FCIP_H
#define	_SYS_FIBRE_CHANNEL_ULP_FCIP_H



/*
 * Header file for FCIP: IP/ARP ULP over FibreChannel
 */

#include <sys/kstat.h>
#include <sys/socket.h>
#include <netinet/arp.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for module_info.
 */
#define		FCIPIDNUM	(77)		/* module ID number */
#define		FCIPNAME	"fcip"		/* module name */
#define		FCIPMINPSZ	(0)		/* min packet size */
#define		FCIPMAXPSZ	1514		/* max packet size */
#define		FCIPHIWAT	(32 * 1024)	/* hi-water mark */
#define		FCIPLOWAT	(1)		/* lo-water mark */
#define		FCIPMTU		65280		/* Max permissible MTU */
#define		FCIPMIN		(ETHERMIN + sizeof (llc_snap_hdr_t) + \
				sizeof (fcph_network_hdr_t))

/*
 * Per-Stream instance state information.
 *
 * Each instance is dynamically allocated at open() and free'd
 * at close().  Each per-Stream instance points to at most one
 * per-device structure using the sl_fcip field.  All instances
 * are threaded together into one list of active instances
 * ordered on minor device number.
 */

#define	NMCHASH			64	/* no. of multicast hash buckets */
#define	INIT_BUCKET_SIZE	16	/* Initial hash bucket size */

struct	fcipstr {
	struct fcipstr	*sl_nextp;	/* next in list */
	queue_t		*sl_rq;		/* pointer to our rq */
	struct fcip 	*sl_fcip;	/* attached device */
	t_uscalar_t	sl_state;	/* current DL state */
	t_uscalar_t	sl_sap;		/* bound sap */
	uint32_t	sl_flags;	/* misc. flags */
	uint32_t	sl_minor;	/* minor device number */
	la_wwn_t	*sl_mctab[NMCHASH]; /* multicast addr table */
	uint_t		sl_mccount[NMCHASH]; /* # valid addr in mctab[i] */
	uint_t		sl_mcsize[NMCHASH]; /* size of mctab[i] */
	ushort_t	sl_ladrf[4];	/* Multicast filter bits */
	ushort_t	sl_ladrf_refcnt[64]; /* ref. count for filter bits */
	kmutex_t	sl_lock;	/* protect this structure */
};

/* per-stream flags */
#define	FCIP_SLFAST	0x01	/* "M_DATA fastpath" mode */
#define	FCIP_SLRAW	0x02	/* M_DATA plain raw mode */
#define	FCIP_SLALLPHYS	0x04	/* "promiscuous mode" */
#define	FCIP_SLALLMULTI	0x08	/* enable all multicast addresses */
#define	FCIP_SLALLSAP	0x10	/* enable all ether type values */

/*
 * Maximum # of multicast addresses per Stream.
 */
#define	FCIPMAXMC	64
#define	FCIPMCALLOC	(FCIPMAXMC * sizeof (la_wwn_t))

/*
 * Full DLSAP address length (in struct dladdr format).
 */
#define	FCIPADDRL	(sizeof (ushort_t) + sizeof (struct ether_addr))


typedef struct fcip_port_info {
	struct fcip_port_info	*fcipp_next;	/* next port in list */
	opaque_t		*fcipp_handle;
	struct modlinkage	fcipp_linkage;
	dev_info_t		*fcipp_dip;
	uint32_t		fcipp_topology;
	uint32_t		fcipp_pstate;
	la_wwn_t		fcipp_pwwn;
	la_wwn_t		fcipp_nwwn;
	uchar_t			fcipp_naa;	/* This port's NAA */
	int			fcipp_fca_pkt_size;
	ddi_dma_attr_t		fcipp_cmd_dma_attr;
	ddi_dma_attr_t		fcipp_resp_dma_attr;
	ddi_device_acc_attr_t	fcipp_fca_acc_attr;
	fc_portid_t		fcipp_sid;	/* this port's S_ID */
	struct fcip		*fcipp_fcip;	/* this port's fcip struct */
} fcip_port_info_t;

#define	FCIP_SUCCESS		(0)
#define	FCIP_FAILURE		(1)
#define	FCIP_FARP_TIMEOUT	10	/* seconds */
#define	FCIP_WAIT_CMDS		5	/* 5 retries at 1 sec between retries */

/*
 * Num ports supported for soft_state_init
 */
#define	FCIP_NUM_INSTANCES	5

#define	FCIP_UB_NBUFS		60
#define	FCIP_UB_SIZE		65535
#define	FCIP_UB_DECREMENT	4
#define	FCIP_UB_MINBUFS		8
#define	FCIP_INIT_DELAY		10000000	/* 10 seconds */
#define	FCIP_PKT_TTL		120		/* 120 secs */
#define	FCIP_TIMEOUT_INTERVAL	10		/* 10 seconds */
#define	FCIP_OFFLINE_TIMEOUT	60		/* 60 seconds */
#define	FCIP_MAX_PORTS		127		/* for private loop/pt_pt */
#define	FCIP_RTE_TIMEOUT	60		/* 60 seconds */

#define	ETHERSTRL		((2 * ETHERADDRL) + 1)
/*
 * Hash lists
 */
#define	FCIP_RT_HASH_ELEMS	32
#define	FCIP_DEST_HASH_ELEMS	16


#define	FCIP_RT_HASH(x)		((x[2] + x[3] + x[4] + x[5] + x[6] + x[7]) \
				& (FCIP_RT_HASH_ELEMS - 1))

#define	FCIP_DEST_HASH(x)	((x[2] + x[3] + x[4] + x[5] + x[6] + x[7]) \
				& (FCIP_DEST_HASH_ELEMS - 1))

#define	FCIP_HDR_SIZE		8
#define	FCIP_RT_INVALID		(-1)
#define	FCIP_RT_RETIRED		(-2)
#define	FCIP_RT_SUSPENDED	(-3)
#define	FCIP_RT_LOGIN_PROGRESS	(-4)

#define	FCIP_RTE_UNAVAIL(state)	(((state) == FCIP_RT_INVALID) || \
					((state) == FCIP_RT_RETIRED) || \
					((state) == FCIP_RT_SUSPENDED)) ? 1 : 0

/*
 * Taskq related
 */
#define	FCIP_NUM_THREADS	4
#define	FCIP_MIN_TASKS		12
#define	FCIP_MAX_TASKS		32


/*
 * Per-Device instance state information.
 *
 * Each instance is dynamically allocated on first attach.
 */
struct fcip {
	dev_info_t		*fcip_dip;	/* parent's dev_info */
	int			fcip_instance;	/* parent's instance */
	struct fcip		*fcip_sibling;	/* The other FCA port */
	uint32_t		fcip_flags;	/* misc. flags */
	uint32_t		fcip_port_state; /* Link State */
	fcip_port_info_t	*fcip_port_info; /* info about port */
	struct fcip		*fcip_next;

	kcondvar_t		fcip_farp_cv;	/* For perport serialization */
	int			fcip_farp_rsp_flag; /* FARP response flag */
	kmutex_t		fcip_mutex;	/* protect this structure */
	kmutex_t		fcip_ub_mutex;	/* protect the unsol bufs */

	uint32_t		fcip_ub_nbufs;	/* no. of Unsol. Buffers */
	uint32_t		fcip_ub_upstream; /* no ubufs in use */
	kcondvar_t		fcip_ub_cv;
	timeout_id_t		fcip_timeout_id; /* for timeout routine */
	uint32_t		fcip_timeout_ticks;
	uint32_t		fcip_mark_offline;

	uint64_t		*fcip_ub_tokens; /* unsol buf tokens */
	kmutex_t		fcip_dest_mutex; /* dest table lock */
	struct fcip_dest	*fcip_dest[FCIP_DEST_HASH_ELEMS];
					/* hash table of remote dest. ports */
	kmutex_t		fcip_rt_mutex;	/* routing table lock */
	struct fcip_routing_table *fcip_rtable[FCIP_RT_HASH_ELEMS];
					/* hash table of WWN to D_ID maps */

	int			fcip_intr_flag;	/* init. flag for fcipintr() */
	uint32_t		fcip_addrflags;	/* type of MAC address */
	struct ether_addr	fcip_factmacaddr; /* local mac address */
	struct ether_addr	fcip_macaddr;	/* MAC addr */
	la_wwn_t		fcip_ouraddr;	/* individual address */
	uchar_t			fcip_ouripaddr[16]; /* Our IP address */
	struct kmem_cache	*fcip_xmit_cache; /* cache of xmit pkts */
	uint32_t		fcip_wantw;	/* out of xmit resources */
	queue_t			*fcip_ipq;	/* ip read queue */
	taskq_t			*fcip_tq;	/* Taskq pointer */
	int			fcip_sendup_thr_initted; /* sendup tq thread */
	kmutex_t		fcip_sendup_mutex; /* for upstream data */
	kcondvar_t		fcip_sendup_cv;	/* for upstream unsol data */
	struct fcip_sendup_elem	*fcip_sendup_head; /* head of mblk elems */
	struct fcip_sendup_elem	*fcip_sendup_tail; /* tail of elem list */
	struct kmem_cache	*fcip_sendup_cache; /* for sendup elems */
	uint32_t		fcip_sendup_cnt; /* Num msgs queued */
	uint32_t		fcip_broadcast_did; /* broadcast D_ID */

	kstat_t			*fcip_intrstats; /* interrupt statistics */
	kstat_t			*fcip_kstatp;	/* kstat pointer */

	callb_cpr_t		fcip_cpr_info;	/* for the sendup thread */

	ulong_t			fcip_ipackets;  /* # packets received */
	ulong_t			fcip_ierrors;	/* # total input errors */
	ulong_t			fcip_opackets;  /* # packets sent */
	ulong_t			fcip_oerrors;	/* # total output errors */
	ulong_t			fcip_collisions;  /* # collisions */
	ulong_t			fcip_defer;	/* # defers */
	ulong_t			fcip_fram;	/* # receive framing errors */
	ulong_t			fcip_crc;	/* # receive crc errors */
	ulong_t			fcip_oflo;	/* # receiver overflows */
	ulong_t			fcip_uflo;	/* # transmit underflows */
	ulong_t			fcip_missed;	/* # receive missed */
	ulong_t			fcip_tlcol;	/* # xmit late collisions */
	ulong_t			fcip_trtry;	/* # transmit retry failures */
	ulong_t			fcip_tnocar;	/* # loss of carrier errors */
	ulong_t			fcip_inits;	/* # driver inits */
	ulong_t			fcip_notbufs;	/* # out of pkts for xmit */
	ulong_t			fcip_norbufs;	/* # out of buffers for rcv */
	ulong_t			fcip_nocanput;  /* # input canputret.false */
	ulong_t			fcip_allocbfail;  /* # allocb failed */
	int 			fcip_tx_lbolt;  /* time of last tx interrupt */
	int 			fcip_rx_lbolt; 	/* time of last rx interrupt */

	/*
	 * MIB II variables
	 */
	ulong_t			fcip_rcvbytes; /* # bytes received */
	ulong_t			fcip_xmtbytes; /* # bytes transmitted */
	ulong_t			fcip_multircv; /* # multicast pkts received */
	ulong_t			fcip_multixmt; /* # multicast pkts for xmit */
	ulong_t			fcip_brdcstrcv; /* # broadcast pkts received */
	ulong_t			fcip_brdcstxmt; /* # broadcast pkts for xmit */
	ulong_t			fcip_norcvbuf; /* # rcv pkts discarded */
	ulong_t			fcip_noxmtbuf; /* # xmit pkts discarded */

	ulong_t			fcip_num_ipkts_pending;
						/* #ipkts pending call back */
};

#define	FCIP_FACTADDR_PRESENT		0x01
#define	FCIP_FACTADDR_USE		0x02

/* flags */
#define	FCIP_RUNNING			0x01
#define	FCIP_INITED			0x02
#define	FCIP_PROMISC			0x04
#define	FCIP_SUSPENDED			0x08
#define	FCIP_NOTIMEOUTS			0x10
#define	FCIP_DETACHING			0x20
#define	FCIP_DETACHED			0x40
#define	FCIP_ATTACHING			0x80
#define	FCIP_LINK_DOWN			0x100
#define	FCIP_IN_SC_CB			0x200
#define	FCIP_IN_DATA_CB			0x400
#define	FCIP_IN_ELS_CB			0x800
#define	FCIP_IN_TIMEOUT			0x1000
#define	FCIP_POWER_DOWN			0x2000
#define	FCIP_RTE_REMOVING		0x4000
#define	FCIP_REG_INPROGRESS		0x8000
/* macro for checking any callback */
#define	FCIP_IN_CALLBACK		(FCIP_IN_SC_CB | FCIP_IN_DATA_CB | \
					FCIP_IN_ELS_CB)
/* macro for checking if a port is busy */
#define	FCIP_PORT_BUSY			(FCIP_ATTACHING | \
					FCIP_REG_INPROGRESS | FCIP_DETACHING)


/*
 * FCIP routing table maintains the FC Layer and the ARP layer
 * mapping for a destination port.
 */
struct fcip_routing_table {
	struct fcip_routing_table *fcipr_next;	/* next elem */
	la_wwn_t	fcipr_pwwn;	/* Destination Port's Port WWN */
	la_wwn_t	fcipr_nwwn;	/* Destination Port's Node WWN */
	fc_portid_t	fcipr_d_id;	/* Destination Port's D_ID */
	void		*fcipr_pd;	/* pointer to port device struct */
	uchar_t		fcipr_ipaddr[16]; /* Port's IP address */
	int		fcipr_state;	/* login state etc */
	clock_t		fcipr_invalid_timeout;	/* wait after marked inval */
	opaque_t	fcipr_fca_dev;	/* FCA device pointer */
};

#define	FCIP_COMPARE_NWWN		0x001
#define	FCIP_COMPARE_PWWN		0x010
#define	FCIP_COMPARE_BROADCAST		0x100

#define	IS_BROADCAST_ADDR(wwn)	(((wwn)->raw_wwn[2] == 0xff) && \
				((wwn)->raw_wwn[3] == 0xff) && \
				((wwn)->w.wwn_lo == 0xffffffff))

/*
 * Define a fcip_pkt structure. We can stuff information about
 * the message block and queue for which the packet was built. We can
 * then free up the message once the transport layer has confirmed
 * that the packet has been successfully transported.
 */
typedef struct fcip_pkt {
	mblk_t			*fcip_pkt_mp;	/* message blk pointer */
	queue_t			*fcip_pkt_wq;	/* queue pointer if needed */
	uint32_t		fcip_pkt_ttl;	/* time to live */
	uint32_t		fcip_pkt_retries; /* retries if needed */
	fc_packet_t		*fcip_pkt_fcpktp; /* the actual fc packet */
	struct fcip_dest	*fcip_pkt_dest;	/* destination of pkt */
	struct fcip		*fcip_pkt_fptr;	/* fcip structure */
	struct fcip_pkt		*fcip_pkt_next;	/* next pkt */
	struct fcip_pkt		*fcip_pkt_prev;	/* prev pkt */
	uint32_t		fcip_pkt_state;	/* pkt state */
	uint32_t		fcip_pkt_reason;	/* pkt reason */
	uint32_t		fcip_pkt_flags;	/* pkt flags */
	uint32_t		fcip_pkt_dma_flags; /* DMA flags */
	fc_packet_t		fcip_pkt_fcpkt;	/* the actual fc packet */
	struct fcip_routing_table *fcip_pkt_frp;	/* routing table */
} fcip_pkt_t;

/* fcipp_dma_flags */
#define	FCIP_CMD_DMA_MEM	0x01
#define	FCIP_CMD_DMA_BOUND	0x02
#define	FCIP_RESP_DMA_MEM	0x04
#define	FCIP_RESP_DMA_BOUND	0x08

/* fcipp_flags */
#define	FCIP_PKT_INTERNAL	0x01
#define	FCIP_PKT_IN_TIMEOUT	0x02
#define	FCIP_PKT_RETURNED	0x04
#define	FCIP_PKT_IN_LIST	0x08
#define	FCIP_PKT_IN_ABORT	0x10

#define	FCIP_PKT_TO_FC_PKT(fcip_pkt)	&(fcip_pkt)->fcip_pkt_fcpkt
/*
 * For each remote port we have a active session with (logged in and
 * having active exchanges) setup a Destination Port structure. Maintain
 * a Hash list of destination structures in the fcip structure. Before
 * starting a new session with the destination port, lookup the hash
 * table to see if we are already having active exchanges with a remote
 * port and if yes bump the reference count and continue use the same
 * destination port. Hash on Port WWNs.
 */
struct fcip_dest {
	struct fcip_dest	*fcipd_next;	/* next element of hashtable */
	fcip_pkt_t		*fcipd_head;	/* packet head for this port */
	kmutex_t		fcipd_mutex;	/* packet list mutex */
	uint32_t		fcipd_refcnt;	/* no.of active sessions */
	struct fcip_routing_table *fcipd_rtable;

#define	fcipd_nwwn	fcipd_rtable->fcipr_nwwn
#define	fcipd_pwwn	fcipd_rtable->fcipr_pwwn
#define	fcipd_did	fcipd_rtable->fcipr_d_id
#define	fcipd_pd	fcipd_rtable->fcipr_pd
#define	fcipd_state	fcipd_rtable->fcipr_state
#define	fcipd_fca_dev	fcipd_rtable->fcipr_fca_dev;

	uint32_t		fcipd_retries;	/* retries if needed ?? */
	uint32_t		fcipd_flags;	/* flags ?? */
	ulong_t			fcipd_ncmds;	/* no. of transport cmds */
};


#define	FCIP_PORT_OFFLINE	0
#define	FCIP_PORT_ONLINE	1
#define	FCIP_PORT_NOTLOGGED	2

#define	FCIP_INVALID_WWN	-1

#define	SLFAST			0x01	/* MDATA fastpath mode */
#define	SLRAW			0x02	/* M_DATA plain raw mode */
#define	SLALLPHYS		0x04	/* promiscuous mode */
#define	SLALLMULTI		0x05	/* enable all multicast addr */
#define	SLALLSAP		0x10	/* enable all ethertype values */



/*
 * Private DLPI full dlsap address format.
 */
struct	fcipdladdr {
	struct	ether_addr	dl_phys;
	uint16_t		dl_sap;
};


typedef struct llc_snap_hdr {
	uchar_t		dsap;
	uchar_t		ssap;
	uchar_t		ctrl;
	uchar_t		oui[3];
	ushort_t	pid;
} llc_snap_hdr_t;

/*
 * "Export" a few of the error counters via the kstats mechanism.
 */
struct	fcipstat {
	struct	kstat_named	fcips_ipackets;
	struct	kstat_named	fcips_ierrors;
	struct	kstat_named	fcips_opackets;
	struct	kstat_named	fcips_oerrors;
	struct	kstat_named	fcips_collisions;
	struct	kstat_named	fcips_defer;
	struct	kstat_named	fcips_fram;
	struct	kstat_named	fcips_crc;
	struct	kstat_named	fcips_oflo;
	struct	kstat_named	fcips_uflo;
	struct	kstat_named	fcips_missed;
	struct	kstat_named	fcips_tlcol;
	struct	kstat_named	fcips_trtry;
	struct	kstat_named	fcips_tnocar;
	struct	kstat_named	fcips_inits;
	struct	kstat_named	fcips_notmds;
	struct	kstat_named	fcips_notbufs;
	struct	kstat_named	fcips_norbufs;
	struct	kstat_named	fcips_nocanput;
	struct	kstat_named	fcips_allocbfail;

	/*
	 * required by kstat for MIB II objects(RFC 1213)
	 */
	struct  kstat_named	fcips_rcvbytes;	/* # octets received */
						/* MIB - ifInOctets */
	struct  kstat_named	fcips_xmtbytes; /* # octets xmitted */
						/* MIB - ifOutOctets */
	struct  kstat_named	fcips_multircv;	/* # multicast packets */
						/* delivered to upper layer */
						/* MIB - ifInNUcastPkts */
	struct  kstat_named	fcips_multixmt;	/* # multicast packets */
						/* requested to be sent */
						/* MIB - ifOutNUcastPkts */
	struct  kstat_named	fcips_brdcstrcv; /* # broadcast packets */
						/* delivered to upper layer */
						/* MIB - ifInNUcastPkts */
	struct  kstat_named	fcips_brdcstxmt; /* # broadcast packets */
						/* requested to be sent */
						/* MIB - ifOutNUcastPkts */
	struct  kstat_named	fcips_norcvbuf;	/* # rcv packets discarded */
						/* MIB - ifInDiscards */
	struct  kstat_named	fcips_noxmtbuf;	/* # xmt packets discarded */
						/* MIB - ifOutDiscards */
};


#define	FC_OFF		0x00
#define	DA_OFF		0x01
#define	SA_OFF		0x07
#define	DLSAP_OFF	0x0D
#define	SLSAP_OFF	0x0E
#define	ORG_OFF		0x0F
#define	TYPE_OFF	0x13

#define	FCIP_IPV4_LEN	0x04;

#define	FCIP_CP_IN(s, d, handle, len)	(ddi_rep_get8((handle), \
					(uint8_t *)(d), (uint8_t *)(s), \
					(len), DDI_DEV_AUTOINCR))

#define	FCIP_CP_OUT(s, d, handle, len)	(ddi_rep_put8((handle), \
					(uint8_t *)(s), (uint8_t *)(d), \
					(len), DDI_DEV_AUTOINCR))

#define	LA_ELS_FARP_REQ			0x54
#define	LA_ELS_FARP_REPLY		0x55

/* Match address code points */
#define	FARP_MATCH_RSVD			0x00
#define	FARP_MATCH_WW_PN		0x01
#define	FARP_MATCH_WW_NN		0x02
#define	FARP_MATCH_WW_PN_NN		0x03
#define	FARP_MATCH_IPv4			0x04
#define	FARP_MATCH_WW_PN_IPv4		0x05
#define	FARP_MATCH_WW_NN_IPv4		0x06
#define	FARP_MATCH_WW_PN_NN_IPv4	0x07

/* Responder flags */
#define	FARP_INIT_P_LOGI		0x0
#define	FARP_INIT_REPLY			0x1


/*
 * Structure for FARP ELS request and Response
 */
typedef struct la_els_farp {
	ls_code_t	ls_code;  /* FARP ELS code - 0x54/0x55 */
	uchar_t		match_addr; /* match addr. code points */
	fc_portid_t	req_id; /* Requester Port_ID */
	uchar_t		resp_flags; /* Responder flags */
	fc_portid_t	dest_id; /* Responder Port_ID */
	la_wwn_t	req_pwwn; /* Port WWN of Requester */
	la_wwn_t	req_nwwn; /* Node WWN of Requester */
	la_wwn_t	resp_pwwn; /* Port WWN of Responder */
	la_wwn_t	resp_nwwn; /* Node WWN of Responder */
	uchar_t		req_ip[16]; /* IP address or Requester */
	uchar_t		resp_ip[16]; /* IP address or Responder */
} la_els_farp_t;

/*
 * Linked list of farp responses
 */
struct farp_resp_list {
	struct farp_resp_list *farpl_next;
	struct farp_resp_list *farpl_prev;
	la_els_farp_t *farpl_resp;
};

/*
 * FCPH Optional network Header
 */
typedef struct network_header {
	la_wwn_t	net_dest_addr;
	la_wwn_t	net_src_addr;
} fcph_network_hdr_t;

/*
 * InArp request structure
 */
typedef struct fcip_inarp {
	fcph_network_hdr_t	fcip_inarp_nh;
	llc_snap_hdr_t		fcip_inarp_snap;
	struct ether_arp	fcip_inarp_data;
} fcip_inarp_t;

/*
 * InArp Response list
 */
struct inarp_resp_list {
	struct inarp_resp_list *inarpl_next;
	struct inarp_resp_list *inarpl_prev;
	fcip_inarp_t *inarpl_resp;
};

/*
 * Structure to define args for esballoc frtn function
 */
struct fcip_esballoc_arg {
	fc_unsol_buf_t	*buf;
	opaque_t	phandle;
	frtn_t		*frtnp;
};

struct fcip_sendup_elem {
	struct fcip_sendup_elem *fcipsu_next;
	mblk_t			*fcipsu_mp;
	struct fcipstr		*(*fcipsu_func)();
};

/*
 * FC4 type setttings for Name Server registration.
 */
#define	FC4_TYPE_WORD_POS(x)	((uchar_t)(x) >> 5)
#define	FC4_TYPE_BIT_POS(x)	((uchar_t)(x) & 0x1F)

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_FIBRE_CHANNEL_ULP_FCIP_H */
