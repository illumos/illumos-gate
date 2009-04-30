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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DAPL_IF_H_
#define	_DAPL_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

/* change this "version" everytime the interface changes */
#define	DAPL_IF_VERSION			(0x05302007)

#define	DAPL_IOC			(0x0da9 << 16)
#define	DAPL_TYPE_IA			(DAPL_IOC | 0x11 << 8)
#define	DAPL_TYPE_EVD			(DAPL_IOC | 0x12 << 8)
#define	DAPL_TYPE_EP			(DAPL_IOC | 0x13 << 8)
#define	DAPL_TYPE_MR			(DAPL_IOC | 0x14 << 8)
#define	DAPL_TYPE_PD			(DAPL_IOC | 0x15 << 8)
#define	DAPL_TYPE_SP			(DAPL_IOC | 0x16 << 8)
#define	DAPL_TYPE_CNO			(DAPL_IOC | 0x17 << 8)
#define	DAPL_TYPE_MW			(DAPL_IOC | 0x18 << 8)
#define	DAPL_TYPE_MISC			(DAPL_IOC | 0x19 << 8)
#define	DAPL_TYPE_SRQ			(DAPL_IOC | 0x1a << 8)
#define	DAPL_TYPE_NONE			(DAPL_IOC | 0x1f << 8)
#define	DAPL_TYPE_MASK			(0xffffff00)

/* NONE */
#define	DAPL_IA_CREATE			(DAPL_TYPE_NONE | 0x01)

/* MISC */
#define	DAPL_CR_ACCEPT			(DAPL_TYPE_MISC | 0x01)
#define	DAPL_CR_REJECT			(DAPL_TYPE_MISC | 0x02)
#define	DAPL_IA_QUERY			(DAPL_TYPE_MISC | 0x03)
#define	DAPL_CR_HANDOFF			(DAPL_TYPE_MISC | 0x04)

/* EP */
#define	DAPL_EP_CREATE			(DAPL_TYPE_EP | 0x01)
#define	DAPL_EP_FREE			(DAPL_TYPE_EP | 0x02)
#define	DAPL_EP_CONNECT			(DAPL_TYPE_EP | 0x03)
#define	DAPL_EP_MODIFY			(DAPL_TYPE_EP | 0x04)
#define	DAPL_EP_DISCONNECT		(DAPL_TYPE_EP | 0x05)
#define	DAPL_EP_REINIT			(DAPL_TYPE_EP | 0x06)

/* EVD */
#define	DAPL_EVD_CREATE			(DAPL_TYPE_EVD | 0x01)
#define	DAPL_CQ_RESIZE			(DAPL_TYPE_EVD | 0x02)
#define	DAPL_EVD_FREE			(DAPL_TYPE_EVD | 0x03)
#define	DAPL_EVENT_POLL			(DAPL_TYPE_EVD | 0x04)
#define	DAPL_EVENT_WAKEUP		(DAPL_TYPE_EVD | 0x05)
#define	DAPL_EVD_MODIFY_CNO		(DAPL_TYPE_EVD | 0x06)

/* MR */
#define	DAPL_MR_REGISTER		(DAPL_TYPE_MR | 0x01)
#define	DAPL_MR_REGISTER_LMR		(DAPL_TYPE_MR | 0x02)
#define	DAPL_MR_REGISTER_SHARED		(DAPL_TYPE_MR | 0x03)
#define	DAPL_MR_DEREGISTER		(DAPL_TYPE_MR | 0x04)
#define	DAPL_MR_SYNC			(DAPL_TYPE_MR | 0x05)

/* MW */
#define	DAPL_MW_ALLOC			(DAPL_TYPE_MW | 0x01)
#define	DAPL_MW_FREE			(DAPL_TYPE_MW | 0x02)

/* CNO */
#define	DAPL_CNO_ALLOC			(DAPL_TYPE_CNO | 0x01)
#define	DAPL_CNO_FREE			(DAPL_TYPE_CNO | 0x02)
#define	DAPL_CNO_WAIT			(DAPL_TYPE_CNO | 0x03)

/* PD */
#define	DAPL_PD_ALLOC			(DAPL_TYPE_PD | 0x01)
#define	DAPL_PD_FREE			(DAPL_TYPE_PD | 0x02)

/* SP */
#define	DAPL_SERVICE_REGISTER		(DAPL_TYPE_SP | 0x01)
#define	DAPL_SERVICE_DEREGISTER		(DAPL_TYPE_SP | 0x02)

/* SRQ */
#define	DAPL_SRQ_CREATE			(DAPL_TYPE_SRQ	| 0x01)
#define	DAPL_SRQ_FREE			(DAPL_TYPE_SRQ	| 0x02)
#define	DAPL_SRQ_RESIZE			(DAPL_TYPE_SRQ	| 0x03)

/*
 * Drivers name and minor name.
 */
#define	DAPLKA_DRV_NAME		"daplt"
#define	DAPLKA_MINOR_NAME	"daplt"
#define	DAPLKA_DEFAULT_PATH	"/devices/ib/daplt@0:daplt"
#define	DAPLKA_DRIVER_MINOR	0

/*
 * Upper limit on number of events that can be polled per event_poll ioctl
 * Since we allocate memory in kernel there needs to be an upper bound.
 */
#define	DAPL_EVD_MAX_EVENTS	16384
/*
 * Number of events that we generally poll for in event_poll.
 */
#define	NUM_EVENTS_PER_POLL	16

/* duplicated from dat.h */
#ifndef _DAT_H_
typedef enum dat_evd_flags {
	DAT_EVD_SOFTWARE_FLAG	= 0x01,
	DAT_EVD_CR_FLAG		= 0x10,
	DAT_EVD_DTO_FLAG	= 0x20,
	DAT_EVD_CONNECTION_FLAG	= 0x40,
	DAT_EVD_RMR_BIND_FLAG	= 0x80,
	DAT_EVD_ASYNC_FLAG	= 0x100,
	/* DAT events only, no software events */
	DAT_EVD_DEFAULT_FLAG	= 0x1F0
} DAT_EVD_FLAGS;
#endif /* _DAT_H_ */

#define	DAPL_MAX_PRIVATE_DATA_SIZE	IBT_MAX_PRIV_DATA_SZ
#define	DAPL_ATS_NBYTES			16	/* SA record data length */

/*
 * All structures defined herein are used for ioctls. On amd64,
 * use pack(4) to make structures match the x86 alignment rules.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 *				      Byte     Offset
 * uDAPL client's private data		64	00
 * Base Sockets Direct Header (BSDH)	 4	64
 * Extended Header				68
 *  Hello Message (HH)			24
 *
 *   bits	32-24		23-16		15-8	7-0
 * bytes
 * 00-63	uDAPL client's private data
 * 64-67	MID             client_msg_len	checksum
 * 68-72	MajV MinV       IPV 		rsvd1
 * 73-75	rsvd2				LocalPort
 * 76-79	SrcIP(127-96)
 * 80-83	SrcIP(95-64)
 * 84-87	SrcIP(63-32)
 * 88-92	SrcIP(31-00)
 *
 */
typedef union dapl_ia_addr_s {
	struct {
		uint32_t	iad_pad[3];
		struct in_addr	iad_v4data;
	} iad_v4_s;			/* IPv4 format */
	in6_addr_t	iad_v6data;	/* IPv6 format */
	uint8_t		iad_sadata[DAPL_ATS_NBYTES]; /* SA format */
	uint32_t	iad_src;	/* alignment */
} dapl_ia_addr_t;
#define	iad_v4		iad_v4_s.iad_v4data
#define	iad_v4pad	iad_v4_s.iad_pad
#define	iad_v6		iad_v6data
#define	iad_sa		iad_sadata

typedef struct dapl_hello_msg {
	uint16_t	hi_checksum;	/* checksum */
	uint8_t		hi_clen;	/* client private data len */
	uint8_t		hi_mid;		/* command - not use */
	uint16_t	hi_rsvd1;
	uint8_t		hi_ipv;		/* IP family ipv4 or ipv6 */
	uint8_t		hi_vers;	/* hello message version number */
	in_port_t	hi_port;	/* IP port number */
	uint16_t	hi_rsvd2;
	dapl_ia_addr_t	_hi_ipaddr;	/* IP address */
} DAPL_HELLO_MSG;
/* different views of the address field */
#define	hi_v4ipaddr	_hi_ipaddr.iad_v4	/* IPv4 */
#define	hi_v4pad	_hi_ipaddr.iad_v4pad
#define	hi_v6ipaddr	_hi_ipaddr.iad_v6	/* IPv6 */
#define	hi_saaddr	_hi_ipaddr.iad_sa	/* 16 bytes SA record */

#define	DAPL_CHECKSUM		0xbeef		/* use as magic number */
#define	DAPL_HELLO_MSG_VERS	0x10		/* major 1 minor 0 */
/* DAPL_PRIVATE used to pass private data in a connection */
#define	DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE	64
typedef struct dapl_private {
	unsigned char private_data[DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE];
	DAPL_HELLO_MSG hello_msg;
} DAPL_PRIVATE;

/* EP ioctl interfaces */

/*
 * Definitions used by DAPL for HCA specific "data out" information.  This
 * data is opaque to daplt, and is consumed by HCA specific code in the
 * userland library.
 *
 * The sizes (in units of uint64_t) need to be big enough for all HCAs
 * supported.  Although 16 is large enough, since we never want to have
 * to change our interface version just because we undersized this, we
 * have chosen 24.
 */
#define	DAPL_CQ_DATA_OUT_SIZE	24
#define	DAPL_QP_DATA_OUT_SIZE	24
#define	DAPL_SRQ_DATA_OUT_SIZE	24

typedef uint64_t dapl_cq_data_out_t[DAPL_QP_DATA_OUT_SIZE];
typedef uint64_t dapl_qp_data_out_t[DAPL_CQ_DATA_OUT_SIZE];
typedef uint64_t dapl_srq_data_out_t[DAPL_SRQ_DATA_OUT_SIZE];

/*
 * Channel sizes struct, copy of ibt_chan_sizes_t so that it can work
 * fine for both 32/64 bit library
 */
typedef struct dapl_chan_sizes_s {
	uint_t	dcs_sq;		/* SendQ size. */
	uint_t	dcs_rq;		/* ReceiveQ size. */
	uint_t	dcs_sq_sgl;	/* Max SGL elements in a SQ WR. */
	uint_t	dcs_rq_sgl;	/* Max SGL elements in a RQ Wr. */
} dapl_chan_sizes_t;

/*
 * EP create ioctl message structure
 */
typedef struct dapl_ep_create_s {
	uint64_t		ep_hkey;	  /* hash key of the EP */
	uint64_t		ep_pd_hkey;	  /* PD hash key */
	uint64_t		ep_rcv_evd_hkey;  /* Recv evd hash key */
	uint64_t		ep_snd_evd_hkey;  /* Send evd hash key */
	uint64_t		ep_conn_evd_hkey; /* Conn evd hash key */
	uint64_t		ep_srq_hkey;	  /* SRQ hash key	*/
	uint32_t		ep_srq_attached;  /* EP with SRQ - 1 or 0 */
	uint64_t		ep_cookie;	  /* Userland EP pointer */
	dapl_chan_sizes_t	ep_ch_sizes;	  /* Requested RC params */
	dapl_chan_sizes_t	ep_ch_real_sizes; /* Allocated RC params */
	dapl_qp_data_out_t	ep_qp_data_out;
} dapl_ep_create_t;

/*
 * Modify is not yet completely implemented
 */
typedef struct dapl_ep_modify_s {
	uint64_t		epm_hkey;
	ibt_cep_modify_flags_t	epm_flags;
	uint8_t			epm_rdma_ra_out;
	uint8_t			epm_rdma_ra_in;
} dapl_ep_modify_t;

/*
 * EP Connect ioctl message
 */
typedef struct dapl_ep_connect_s {
	uint64_t		epc_hkey;	/* EP hash key		*/
	ib_gid_t		epc_dgid;	/* destination gid	*/
	uint64_t		epc_sid;	/* service id		*/
	uint64_t		epc_timeout;	/* timeout		*/
	uint32_t		epc_priv_sz;	/* private data size	*/
	dapl_ia_addr_t		epc_raddr_sadata; /* remote addr in SA format */
	uchar_t			epc_priv[DAPL_MAX_PRIVATE_DATA_SIZE];
} dapl_ep_connect_t;

typedef struct dapl_ep_disconnect_s {
	uint64_t		epd_hkey;	/* EP hash key */
} dapl_ep_disconnect_t;

/*
 * EP reinit ioctl called to recycle the RC
 */
typedef struct dapl_ep_reinit_s {
	uint64_t		epri_hkey;	 /* EP hash key */
	uint64_t		epri_map_offset; /* Mapping offset of new QP */
	uint64_t		epri_map_len;	 /* Map len of new QP	*/
	uint32_t		epri_qpnum;	 /* QPnum of the new QP */
	uint32_t		epri_rq_offset;  /* New RecvQ offset in buf */
	uint32_t		epri_rq_desc_addr; /* New RecvQ kernel addr */
	uint32_t		epri_rq_numwqe;
	uint32_t		epri_rq_wqesz;
	uint32_t		epri_sq_offset;  /* New SendQ offset in buf */
	uint32_t		epri_sq_desc_addr; /* New SendQ kernel addr */
	uint32_t		epri_sq_numwqe;
	uint32_t		epri_sq_wqesz;
} dapl_ep_reinit_t;

typedef struct dapl_ep_free_s {
	uint64_t		epf_hkey;	/* EP hash key */
} dapl_ep_free_t;

/* EVD ioctl interfaces */

/*
 * EVD create ioctl
 */
typedef struct dapl_evd_create_s {
	uint64_t		evd_hkey;	/* EVD hash key */
	DAT_EVD_FLAGS		evd_flags;	/* EVD streams flag */
	uint64_t		evd_cookie;	/* userland EVD pointer */
	uint64_t		evd_cno_hkey;	/* CNO hash key */
	uint32_t		evd_cq_size;	/* Requested CQ Size */
	uint32_t		evd_cq_real_size;  /* Allocated CQ size */
	dapl_cq_data_out_t	evd_cq_data_out;
} dapl_evd_create_t;

/*
 * If an EVD has a CQ this ioctl message is used to resize the CQ
 */
typedef struct dapl_cq_resize_s {
	uint64_t		cqr_evd_hkey;	  /* EVD hash key */
	uint32_t		cqr_cq_new_size;  /* New requested CQ size */
	uint32_t		cqr_cq_real_size; /* Allocated CQ size */
	dapl_cq_data_out_t	cqr_cq_data_out;
} dapl_cq_resize_t;

/*
 * Event type used while returning events from the kernel
 */
typedef enum {
	/* event family for the Async events */
	DAPL_ASYNC_EVENTS = 0x01,
	/* event family for events posted by the PASSIVE side cm_handler */
	DAPL_CR_EVENTS = 0x02,
	/* event family for events posted by the PASSIVE side cm_handler */
	DAPL_PASSIVE_CONNECTION_EVENTS = 0x04,
	/* event family for events posted by the ACTIVE side cm_handler */
	DAPL_ACTIVE_CONNECTION_EVENTS = 0x08
} dapl_event_family_t;

/*
 * Async event structure
 */
typedef struct dapl_ib_async_event_s {
	ibt_async_code_t	ibae_type;
	ib_guid_t		ibae_hca_guid; /* HCA node GUID */
	uint64_t		ibae_cookie; /* ep or cq pointer */
	uint8_t			ibae_port; /* HCA Port num unaffiliated evnt */
} dapl_ib_async_event_t;

/*
 * CM events definitions used to translate IBTF CM events to DAPL CM events
 */
typedef enum {
	/* IBT_CM_EVENT_CONN_EST */
	DAPL_IB_CME_CONNECTED = 1,
	/* IBT_CM_EVENT_CONN_CLOSED */
	DAPL_IB_CME_DISCONNECTED,
	/* IBT_CM_EVENT_REQ_RCV */
	DAPL_IB_CME_CONNECTION_REQUEST_PENDING,
	DAPL_IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA,
	/* IBT_CM_EVENT_FAILURE */
	DAPL_IB_CME_DESTINATION_REJECT,
	DAPL_IB_CME_DESTINATION_REJECT_PRIVATE_DATA,
	/* Currently not mapped to IBTF CM events */
	DAPL_IB_CME_DESTINATION_UNREACHABLE,
	DAPL_IB_CME_TOO_MANY_CONNECTION_REQUESTS,
	DAPL_IB_CME_LOCAL_FAILURE,
	DAPL_IB_CME_TIMED_OUT,
	DAPL_IB_CME_DISCONNECTED_ON_LINK_DOWN,
	/*
	 * Not really a CM event but library uses CM events as reject reasons
	 * so to avoid any overlaps, make it part of this enum
	 */
	DAPL_IB_CM_REJ_REASON_CONSUMER_REJ
} dapl_ib_cm_event_type_t;

/*
 * CM event structure
 */
typedef struct dapl_ib_cm_event_s {
	dapl_ib_cm_event_type_t	ibce_event;
	/* Userland PSP ptr for CR, EP ptr for CONNECTION */
	uint64_t		ibce_cookie;
	/* Unique CR cookie: tmstamp + Index in the connection pending table */
	uint64_t		ibce_psep_cookie;
	uint32_t		ibce_priv_data_size;
	uchar_t			ibce_priv_data_ptr[DAPL_MAX_PRIVATE_DATA_SIZE];
} dapl_ib_cm_event_t;

/*
 * Kernel Events structure used for returning CM or Async events
 */
typedef struct dapl_ib_event_s {
	dapl_event_family_t	ibe_ev_family;
	union {
		dapl_ib_async_event_t	ibe_async; /* Async event */
		dapl_ib_cm_event_t	ibe_ce;	   /* CM event    */
	} ev_data;
#define	ibe_async	ev_data.ibe_async
#define	ibe_ce		ev_data.ibe_ce
} dapl_ib_event_t;

/*
 * Event poll ioctl message
 */
typedef struct dapl_event_poll_s {
	uint64_t		evp_evd_hkey;  /* EVD hash key		*/
	uint64_t		evp_timeout;   /* Timeout value		*/
	uint_t			evp_threshold; /* Threshold passed in	*/
	dapl_ib_event_t		*evp_ep;    /* array of events to be filled */
	uint_t			evp_num_ev; /* array sz, possbly > threshold */
	uint_t			evp_num_polled; /* number of elements filled */
} dapl_event_poll_t;

/*
 * Event poll ioctl message
 */
typedef struct dapl_event_poll32_s {
	uint64_t		evp_evd_hkey;  /* EVD hash key		*/
	uint64_t		evp_timeout;   /* Timeout value		*/
	uint_t			evp_threshold; /* Threshold passed in	*/
	caddr32_t		evp_ep;    /* array of events to be filled */
	uint_t			evp_num_ev; /* array sz, possbly > threshold */
	uint_t			evp_num_polled; /* number of elements filled */
} dapl_event_poll32_t;

/*
 * EVD hash key to wakeup
 */
typedef struct dapl_event_wakeup_s {
	uint64_t		evw_hkey;	/* EVD hash key */
} dapl_event_wakeup_t;

/*
 * modify EVD to CNO association
 */
typedef struct dapl_evd_modify_cno_s {
	uint64_t		evmc_hkey;	/* EVD hash key */
	uint64_t		evmc_cno_hkey;	/* new CNO hash key */
} dapl_evd_modify_cno_t;


/*
 * EVD hash key to free
 */
typedef struct dapl_evd_free_s {
	uint64_t		evf_hkey;	/* EVD hash key */
} dapl_evd_free_t;

/* MR ioctl interfaces */

/*
 * MR register ioctl message
 */
typedef struct dapl_mr_register_s {
	uint64_t		mr_hkey;    /* MR hash key		 */
	uint64_t		mr_pd_hkey; /* PD hash key		 */
	ib_vaddr_t		mr_vaddr; /* Virtual address to register */
	ib_memlen_t		mr_len;	  /* Length of region to register */
	ibt_mr_flags_t		mr_flags;
	ibt_lkey_t		mr_lkey;  /* Lkey returned from mr_register */
	ibt_rkey_t		mr_rkey;  /* Rkey returned from mr_register */
} dapl_mr_register_t;

/*
 * Shared MR cookie
 */
typedef union dapl_mr_cookie_u {
	uint64_t		mc_uint_arr[5];
	uchar_t			mc_byte_arr[40];
} dapl_mr_cookie_t;

/*
 * Shared MR register ioctl message
 */
typedef struct dapl_mr_register_shared_s {
	uint64_t		mrs_hkey;    /* MR hash key		 */
	uint64_t		mrs_pd_hkey; /* PD hash key		 */
	ib_vaddr_t		mrs_vaddr; /* Virtual address to register */
	ib_memlen_t		mrs_len;   /* Length of region to register */
	ibt_mr_flags_t		mrs_flags;
	ibt_lkey_t		mrs_lkey;  /* Lkey returned from mr_register */
	ibt_rkey_t		mrs_rkey;  /* Rkey returned from mr_register */
	dapl_mr_cookie_t	mrs_shm_cookie; /* shared mem cookie */
} dapl_mr_register_shared_t;

/*
 * MR based MR register ioctl message
 */
typedef struct dapl_mr_register_lmr_s {
	uint64_t		mrl_hkey; /* MR hash key */
	uint64_t		mrl_orig_hkey; /* hash key of Original MR */
	ibt_mr_flags_t		mrl_flags;
	ibt_lkey_t		mrl_lkey; /* Lkey returned from mr_register */
	ibt_rkey_t		mrl_rkey; /* Rkey returned from mr_register */
} dapl_mr_register_lmr_t;

/*
 * MR deregister ioctl message
 */
typedef struct dapl_mr_deregister_s {
	uint64_t		mrd_hkey; /* MR hash key */
} dapl_mr_deregister_t;

/*
 * MR RDMA sync ioctl message
 */

#define	DAPL_MR_PER_SYNC 16
#define	DAPL_MR_SYNC_RDMA_RD 0
#define	DAPL_MR_SYNC_RDMA_WR 1

typedef struct dapl_mr_sync_vec_s {
	uint64_t	mrsv_hkey;	/* MR hash key */
	uint64_t	mrsv_va;	/* MR sync virtual addr */
	uint64_t	mrsv_len;	/* MR sync length */
} dapl_mr_sync_vec_t;

typedef struct dapl_mr_sync_s {
	uint32_t		mrs_flags;	/* MR sync direction */
	uint64_t		mrs_numseg;	/* number of MR's */
	dapl_mr_sync_vec_t 	mrs_vec[DAPL_MR_PER_SYNC]; /* sync elements */
} dapl_mr_sync_t;

/* IA ioctl interfaces */

/*
 * IA create ioctl message
 */
typedef struct dapl_ia_create_s {
	uint32_t		ia_version; /* ioctl interface version	*/
	ib_guid_t		ia_guid;    /* HCA guid			*/
	uint32_t		ia_port;    /* port number		*/
	uint32_t		ia_pkey;    /* pkey of the ibd instance */
	uint32_t		ia_resnum;  /* resource num in resrc table */
	uint8_t			ia_sadata[DAPL_ATS_NBYTES]; /* SA data record */
} dapl_ia_create_t;

/*
 * This structure is pretty much a copy of ibt_hca_attr_t but only
 * relevant fields are present and the data types are such that
 * its safe to use it in both in 32 and 64 bit libraries
 * For detailed description refer to ibt_hca_attr_t in ibtl_types.h
 */
typedef struct dapl_hca_attr_s {
	uint32_t	dhca_vendor_id:24;
	uint16_t	dhca_device_id;
	uint32_t	dhca_version_id;
	uint_t		dhca_max_chans;
	uint_t		dhca_max_chan_sz;
	uint_t		dhca_max_sgl;
	uint_t		dhca_max_cq;
	uint_t		dhca_max_cq_sz;
	uint_t		dhca_max_memr;
	ib_memlen_t	dhca_max_memr_len;
	uint_t		dhca_max_mem_win;
	uint8_t		dhca_max_rdma_in_chan;
	uint8_t		dhca_max_rdma_out_chan;
	uint16_t	dhca_max_partitions;
	uint8_t		dhca_nports;
	ib_guid_t	dhca_node_guid;
	uint_t		dhca_max_pd;
	uint_t		dhca_max_srqs;
	uint_t		dhca_max_srqs_sz;
	uint_t		dhca_max_srq_sgl;
} dapl_hca_attr_t;

/*
 * IA query ioctl message
 */
typedef struct dapl_ia_query_s {
	dapl_hca_attr_t		hca_attr;
} dapl_ia_query_t;

#define	DAPL_MAX_IA	64
/*
 * IA enum ioctl message
 */
typedef struct dapl_ia_enum_s {
	uint32_t		ia_count;	/* number of IAs */
	uint16_t		ia_devnum[DAPL_MAX_IA]; /* devnum of IAs */
} dapl_ia_enum_t;

/* PD ioctl interfaces */

typedef struct dapl_pd_alloc_s {
	uint64_t		pda_hkey;
} dapl_pd_alloc_t;

typedef struct dapl_pd_free_s {
	uint64_t		pdf_hkey;
} dapl_pd_free_t;

/* MW ioctl interfaces */

typedef struct dapl_mw_alloc_s {
	uint64_t		mw_pd_hkey;
	uint64_t		mw_hkey;
	ibt_rkey_t		mw_rkey;
} dapl_mw_alloc_t;

typedef struct dapl_mw_free_s {
	uint64_t		mw_hkey;
} dapl_mw_free_t;

/* Passive Side ioctl interfaces */

/*
 * Service register ioctl message
 */
typedef struct dapl_service_register_s {
	ib_svc_id_t		sr_sid;		/* Requested service id */
	uint64_t		sr_evd_hkey;	/* CR EVD hash key	*/
	uint64_t		sr_sp_hkey;	/* SP hash key		*/
	uint64_t		sr_sp_cookie;	/* Userland xSP ptr	*/
	ib_svc_id_t		sr_retsid;	/* Returned service id  */
} dapl_service_register_t;

/*
 * Service deregister ioctl message
 */
typedef struct dapl_service_deregister_s {
	uint64_t		sdr_sp_hkey;
} dapl_service_deregister_t;

/*
 * Connection request accept ioctl message
 */
typedef struct dapl_cr_accept_s {
	uint64_t	cra_sp_hkey;	/* xSP hash key */
	uint64_t	cra_ep_hkey;	/* EP hash key */
	uint64_t	cra_bkl_cookie;	/* CR timestamp + SP backlog index */
	uint32_t	cra_priv_sz;	/* private data and size */
	uchar_t		cra_priv[DAPL_MAX_PRIVATE_DATA_SIZE];
} dapl_cr_accept_t;

/*
 * Connection request reject ioctl message
 */
typedef struct dapl_cr_reject_s {
	uint64_t	crr_sp_hkey;	/* xSP hash key */
	uint64_t	crr_bkl_cookie;  /* CR timestamp + SP backlog index */
	int		crr_reason;	/* Reason for rejecting the CR */
} dapl_cr_reject_t;

/*
 * Connection request handoff ioctl message
 */
typedef struct dapl_cr_handoff_s {
	uint64_t	crh_sp_hkey;	/* xSP hash key */
	uint64_t	crh_bkl_cookie;  /* CR timestamp + SP backlog index */
	ib_svc_id_t	crh_conn_qual;  /* Service id of destination SP */
} dapl_cr_handoff_t;

/* CNO ioctl interfaces */

/*
 * CNO alloc ioctl message
 */
typedef struct dapl_cno_alloc_s {
	uint64_t	cno_hkey;	/* CNO hash key */
} dapl_cno_alloc_t;

/*
 * CNO free ioctl message
 */
typedef struct dapl_cno_free_s {
	uint64_t	cnf_hkey;	/* CNO hash key */
} dapl_cno_free_t;

/*
 * CNO wait ioctl message
 */
typedef struct dapl_cno_wait_s {
	uint64_t	cnw_hkey;	/* CNO hash key */
	uint64_t	cnw_timeout;	/* CNO timeout */
	uint64_t	cnw_evd_cookie;
} dapl_cno_wait_t;

/*
 * SRQ related structures
 */
typedef struct dapl_srq_sizes_s {
	uint_t	srqs_sz;
	uint_t	srqs_sgl;
} dapl_srq_sizes_t;

/*
 * SRQ create ioctl message
 */
typedef struct dapl_srq_create_s {
	uint64_t		srqc_pd_hkey;	/* hash key of the assoc PD */
	dapl_srq_sizes_t	srqc_sizes;	/* Requested SRQ params	*/
	uint64_t		srqc_hkey;	/* hash key of allocated SRQ */
	dapl_srq_sizes_t	srqc_real_sizes; /* Allocated SRQ params */
	dapl_srq_data_out_t	srqc_data_out;
} dapl_srq_create_t;

/*
 * SRQ resize ioctl message
 */
typedef struct dapl_srq_resize_s {
	uint64_t		srqr_hkey;	/* hash key of the SRQ */
	uint32_t		srqr_new_size;	/* New SRQ size		*/
	uint32_t		srqr_real_size; /* Actual SRQ size	*/
	dapl_srq_data_out_t	srqr_data_out;
} dapl_srq_resize_t;

/*
 * SRQ free ioctl message
 */
typedef struct dapl_srq_free_s {
	uint64_t	srqf_hkey; /* hash key of the SRQ being freed */
} dapl_srq_free_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _DAPL_IF_H_ */
