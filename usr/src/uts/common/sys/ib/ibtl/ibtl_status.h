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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_IBTL_IBTL_STATUS_H
#define	_SYS_IB_IBTL_IBTL_STATUS_H

/*
 * ibtl_status.h
 *
 * Define global IBTL return codes.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mnemonics
 *   APM   - Automatic Path Migration
 *   APR   - Alternate Path Response
 *   AH    - Address Handle
 *   CI    - Channel Interface (HCA)
 *   CQ    - Completion Queue
 *   DLID  - Destination Local Id
 *   DS    - Data Segment.
 *   GSI   - General Service Interface
 *   GUID  - Globally Unique Identifier
 *   HCA   - Host Channel Adapter.
 *   L_KEY - Local Key
 *   LAP   - Load Alternative Path
 *   MC    - Multicast
 *   MCG   - Multicast Group
 *   MR    - Memory Region
 *   MW    - Memory Window
 *   MTU   - Maximum Transfer Unit
 *   NAK   - Negative Acknowledge
 *   P_KEY - Partition Key
 *   PD    - Protection Domain
 *   PSN   - Packet Serial Number
 *   QP    - Queue Pair
 *   QPN   - Queue Pair Number
 *   R_KEY - Remote Key
 *   RC    - Reliable Connected
 *   RDMA  - Remote DMA
 *   RNR   - Receiver Not Ready
 *   RQ    - Receive Work Queue
 *   SGL   - Scatter/Gather List
 *   SL    - Service Level
 *   SMI   - Subnet Management Interface
 *   SQ    - Send Work Queue
 *   UC    - Unreliable Connected
 *   UD    - Unreliable Datagram
 *   VA    - Virtual Address
 *   WR    - Work Request
 *   WC    - Work Completion
 *   WRC   - Work Request Completion
 */

/*
 * IBTF Immediate status codes.
 */
typedef enum ibt_status_e {
	/*
	 * Generic Status codes.
	 */
	IBT_SUCCESS			= 0,	/* Operation Successful */
	IBT_FAILURE			= 1,	/* Undefined IBTF Failure */
	IBT_NOT_SUPPORTED		= 2,	/* Feature not supported */
	IBT_ILLEGAL_OP			= 3,	/* Operation not supported */
	IBT_INVALID_PARAM		= 4,	/* Invalid argument specified */
	IBT_INSUFF_KERNEL_RESOURCE	= 5,	/* Not enough Kernel Resource */
	IBT_CM_FAILURE			= 6,	/* A call to CM returned */
						/* look into detailed error */
						/* code for actual failure */
	IBT_CM_SERVICE_EXISTS		= 7,	/* For the given parameters */
						/* serviceId already exists */
	IBT_APM_NOT_SUPPORTED		= 8,	/* Can not satisfy a request */
						/* for APM */
	IBT_IBMF_TIMEOUT		= 10,	/* IBMF call returned with */
						/* TIMEOUT error code. */
	IBT_INSUFF_DATA			= 11,	/* Requested number of */
						/* paths/records are not */
						/* available. */
	IBT_NO_HCAS_AVAILABLE		= 12,	/* No HCAs have attached. */
	IBT_PATH_RECORDS_NOT_FOUND	= 13,	/* Path records not found. */
	IBT_SERVICE_RECORDS_NOT_FOUND	= 14,	/* Service records not found. */
	IBT_MCG_RECORDS_NOT_FOUND	= 15,	/* MCG records not found. */
	IBT_PATH_PKT_LT_TOO_HIGH	= 16,	/* Path's packet life time */
						/* is too high. */
	IBT_CM_SERVICE_BUSY		= 17,	/* Service still has bindings */
	IBT_STATIC_RATE_INVALID		= 18,	/* Invalid Static Rate */
	IBT_SGID_INVALID		= 19,	/* Invalid SGID or SGID index */
	IBT_NODE_RECORDS_NOT_FOUND	= 20,	/* NODEInfo records not found */
	IBT_GIDS_NOT_FOUND		= 21,	/* Companion GIDs not found */
	IBT_INCONSISTENT_AR		= 22,	/* Address Record contradicts */
						/* an existing Address Record */
	IBT_AR_NOT_REGISTERED		= 23,	/* Address Record is not */
						/* currently registered */
	IBT_MULTIPLE_AR			= 24,	/* Multiple records exist for */
						/* what should be a unique */
						/* query result. One of the */
						/* records was returned. */
	IBT_DEST_IP_GID_NOT_FOUND	= 25,	/* No IP to GID Mapping */
	IBT_SRC_IP_NOT_FOUND		= 26,	/* SRC IP Endpoint not found */
	IBT_NO_SUCH_OBJECT		= 27,	/* No such object */

	/*
	 * Resource Errors
	 */
	IBT_INSUFF_RESOURCE		= 100,	/* Not enough resources */
	IBT_HCA_CQ_EXCEEDED		= 101,	/* CQ capacity requested */
						/* exceeds HCA capability */
	IBT_HCA_WR_EXCEEDED		= 102,	/* Requested WRs exceed limit */
	IBT_HCA_SGL_EXCEEDED		= 103,	/* Requested SGL entries */
						/* exceed HCA max limit */
	IBT_ERR_OPAQUE1			= 104,
	IBT_HCA_MCG_CHAN_EXCEEDED	= 105,	/* Requested Channel exceeds */
						/* HCA multicast groups */
						/* channel limit */
	IBT_HCA_IN_USE			= 106,	/* HCA already open (in use) */
	IBT_HCA_RESOURCES_NOT_FREED	= 107,	/* HCA resources still in use */
	IBT_HCA_BUSY_DETACHING		= 108,	/* HCA detach in progress */
	IBT_HCA_BUSY_CLOSING		= 109,	/* This client is in the */
						/* process of closing this */
						/* HCA */

	/*
	 * Host Channel Adapter (HCA) Attribute Errors.
	 */
	IBT_HCA_INVALID			= 200,	/* Invalid HCA GUID */
	IBT_HCA_HDL_INVALID		= 201,	/* Invalid HCA Handle */
	IBT_HCA_PORT_MTU_EXCEEDED	= 202,	/* MTU of HCA port exceeded */
	IBT_HCA_PORT_INVALID		= 203,	/* Invalid HCA physical port */
	IBT_HCA_CNTR_INVALID		= 204,	/* Invalid Counter Specified */
	IBT_HCA_CNTR_VAL_INVALID	= 205,	/* Invalid Counter value */
	IBT_HCA_PORT_NOT_ACTIVE		= 206,	/* Port is down */
	IBT_HCA_SRQ_NOT_SUPPORTED	= 207,	/* Shared Receive Queue */
						/* not supported */
	IBT_HCA_RESIZE_SRQ_NOT_SUPPORTED = 208,	/* SRQ Resize not supported */
	IBT_HCA_PAGE_MODE		= 209,	/* Not opened in page mode */
	IBT_HCA_BLOCK_MODE		= 210,	/* HCA does not support Block */
						/* mode or Not opened in */
						/* Block mode */
	IBT_HCA_BMM_NOT_SUPPORTED	= 211,	/* Base Memory Management */
						/* Extensions not supported */
	IBT_HCA_BQM_NOT_SUPPORTED	= 212,	/* Base Queue Management */
						/* Extensions not supported */
	IBT_HCA_ZBVA_NOT_SUPPORTED	= 213,	/* Zero Based Virtual */
						/* Addresses not supported */
	IBT_HCA_MR_MPB_SZ_NOT_SUPPORTED	= 214,	/* Multiple physical buffer */
						/* sizes per MR not supported */
	IBT_HCA_TYPE_2_MW_NOT_SUPPORTED	= 215,

	IBT_HCA_LIF_NOT_SUPPORTED	= 216,	/* Local Invalidate Fencing */
						/* not supported */
	IBT_HCA_FMR_NOT_SUPPORTED	= 217,	/* Fast Memory Registration */
						/* not supported */
	/*
	 * Address errors
	 */
	IBT_UD_DEST_HDL_INVALID		= 300,	/* Invalid Address Handle */

	/*
	 * Channel Errors
	 */
	IBT_CHAN_HDL_INVALID		= 400,	/* Invalid channel Handle */
	IBT_CHAN_ATTR_RO		= 401,	/* Cannot Change channel */
						/* Attribute */
	IBT_CHAN_STATE_INVALID		= 402,	/* Invalid channel State */
	IBT_CHAN_SRV_TYPE_INVALID	= 403,	/* Invalid channel Service */
						/* Type */
	IBT_CHAN_IN_USE			= 404,	/* SMI/GSI channel in use */
	IBT_CHAN_ATOMICS_NOT_SUPPORTED	= 405,	/* Atomics not supported */
	IBT_ERR_OPAQUE2			= 406,
	IBT_ERR_OPAQUE3			= 407,
	IBT_CHAN_OP_TYPE_INVALID 	= 408,	/* Invalid Operation Type */
	IBT_CHAN_SGL_FORMAT_INVALID	= 409,	/* Invalid SG List format */
	IBT_CHAN_SGL_LEN_INVALID 	= 410,	/* Invalid SG List length */
	IBT_CHAN_APM_STATE_INVALID	= 411,	/* Invalid Path Migration */
						/* State */
	IBT_CHAN_SPECIAL_TYPE_INVALID	= 412,	/* Invalid Special channel */
	IBT_CHAN_SZ_INSUFFICIENT	= 413,	/* The Size of the WQ is too */
						/* small, there are more */
						/* outstanding entries than */
						/* than the requested size. */
	IBT_CHAN_FULL			= 414,	/* Too many WRs posted */
	IBT_CHAN_SRQ			= 415,	/* Handle used on a channel */
						/* that is associated with an */
						/* SRQ */
	IBT_CHAN_TYPE_2A_MW_BOUND	= 416,	/* Channel still has a type */
						/* 2A memory window bound */
	IBT_CHAN_WQE_SZ_INSUFF		= 417,	/* inline-data/LSO too large */

	/*
	 * Completion Queue (CQ) errors
	 */
	IBT_CQ_HDL_INVALID		= 500,	/* Invalid CQ Handle */
	IBT_CQ_SZ_INSUFFICIENT		= 501,  /* The Size of the CQ is too */
						/* small, there are more */
						/* outstanding completions */
						/* than the requested size. */
	IBT_CQ_BUSY			= 502,	/* WQ(s) Still Reference CQ */
	IBT_CQ_EMPTY			= 503,	/* Completion Queue Empty */
	IBT_CQ_NOTIFY_TYPE_INVALID	= 504,	/* Invalid notification type */
	IBT_CQ_INVALID_PRIORITY		= 505,	/* Invalid CQ Priority */
	IBT_CQ_SCHED_INVALID		= 550,	/* Invalid CQ Sched Handle */
	IBT_CQ_NO_SCHED_GROUP		= 551,	/* Schedule group not found */
	IBT_CQ_HID_INVALID		= 552,	/* CQ Handler ID invalid */

	/*
	 * Reserved for future use.
	 */
	IBT_ERR_OPAQUE4			= 600,
	IBT_ERR_OPAQUE5			= 601,
	IBT_ERR_OPAQUE6			= 602,
	IBT_ERR_OPAQUE7			= 700,
	IBT_ERR_OPAQUE8			= 701,
	IBT_ERR_OPAQUE9 		= 702,
	IBT_ERR_OPAQUE10		= 703,

	/*
	 * Memory operation errors
	 */
	IBT_MR_VA_INVALID		= 800,	/* Invalid Virtual Address */
	IBT_MR_LEN_INVALID		= 801,	/* Invalid Memory Length */
	IBT_MR_PHYSBUF_INVALID 		= 802,	/* Invalid Physical Buffer */
						/* List */
	IBT_MR_OFFSET_INVALID		= 803,	/* Invalid Memory Offset */
	IBT_MR_LKEY_INVALID		= 804,	/* Invalid Memory L_KEY */
	IBT_MR_RKEY_INVALID		= 805,	/* Invalid Memory R_KEY */
	IBT_MR_HDL_INVALID 		= 806,	/* Invalid Memory Region */
						/* Handle */
	IBT_MR_ACCESS_REQ_INVALID 	= 807,	/* Invalid Access Control */
						/* Specifier */
	IBT_MR_IN_USE			= 808,	/* Mem region in Use */
	IBT_MW_HDL_INVALID 		= 809,	/* Invalid Memory Window */
						/* Handle */
	IBT_MW_TYPE_INVALID		= 810,
	IBT_MA_HDL_INVALID		= 811,  /* Invalid Memory Area Hdl */
	IBT_SGL_TOO_SMALL		= 812,
	IBT_MI_HDL_INVALID		= 813,

	/*
	 * Multicast errors
	 */
	IBT_MC_OPAQUE			= 900,	/* Invalid MLID */
	IBT_MC_MGID_INVALID		= 901,	/* Invalid MGID */
	IBT_MC_GROUP_INVALID		= 902,	/* Invalid MC Group */

	/*
	 * Partition table errors.
	 */
	IBT_PKEY_IX_ILLEGAL		= 1000,	/* P_Key index Out of range */
	IBT_PKEY_IX_INVALID		= 1001,	/* P_Key index specifies */
						/* invalid entry in table */
	/*
	 * Protection Domain errors
	 */
	IBT_PD_HDL_INVALID		= 1100,	/* Invalid protection domain */
	IBT_PD_IN_USE			= 1101,	/* Protection Domain in Use */
	IBT_MEM_ALLOC_HDL_INVALID	= 1102,	/* Invalid MEM handle */

	/*
	 * Shared Receive Queue errors
	 */
	IBT_SRQ_HDL_INVALID		= 1200,	/* Invalid SRQ Handle */
	IBT_SRQ_ERROR_STATE		= 1201, /* SRQ in Error State */
	IBT_SRQ_LIMIT_EXCEEDED		= 1202, /* SRQ Limit exceeds max SRQ */
						/* size */
	IBT_SRQ_SZ_INSUFFICIENT		= 1203,	/* The Size of the WQ is too */
						/* small, there are more */
						/* outstanding entries than */
	IBT_SRQ_IN_USE			= 1204,	/* SRQ Still has QPs */
						/* associated with it */
	/*
	 * FMR Errors
	 */
	IBT_FMR_POOL_HDL_INVALID	= 1300,	/* Invalid FMR Pool handle */
	IBT_FMR_POOL_IN_USE		= 1301,	/* FMR Pool in use. */
	IBT_PBL_TOO_SMALL		= 1302
} ibt_status_t;

/*
 * Work Request Completion Return Status.
 *
 * Refer InfiniBand Architecture Release Volume 1:
 * Section 11.6.2 Completion Return Status.
 *
 * NOTE: this was converted from an enum to a uint8_t to save space.
 */
typedef uint8_t ibt_wc_status_t;
#define	IBT_WC_SUCCESS			0	/* WR Completed Successfully */
#define	IBT_WC_LOCAL_LEN_ERR		10	/* Data in WR posted to local */
						/* queue too big */
#define	IBT_WC_LOCAL_CHAN_OP_ERR	11	/* Internal consistency error */
#define	IBT_WC_LOCAL_PROTECT_ERR	13	/* Memory Region violation */
						/* for posted WR */
#define	IBT_WC_WR_FLUSHED_ERR		14	/* WR was in process when the */
						/* chan went to error state */
#define	IBT_WC_MEM_MGT_OP_ERR		15	/* bind plus 1.2 mem ext */
#define	IBT_WC_MEM_WIN_BIND_ERR		IBT_WC_MEM_MGT_OP_ERR

	/*
	 * Errors that are only reported for Reliable Queue Pairs.
	 */
#define	IBT_WC_BAD_RESPONSE_ERR		20	/* An unexpected transport */
						/* layer opcode was returned */
						/* by the responder */
#define	IBT_WC_LOCAL_ACCESS_ERR		21	/* A protection error */
						/* occurred on a local data */
						/* buffer during the */
						/* processing of a RDMA Write */
						/* with Immediate Data */
						/* operation sent from the */
						/* remote node */
						/* data buffer */
#define	IBT_WC_REMOTE_INVALID_REQ_ERR	22	/* Responder detected invalid */
						/* message on the channel */
#define	IBT_WC_REMOTE_ACCESS_ERR	23	/* Protection Error on remote */
						/* data buffer */
#define	IBT_WC_REMOTE_OP_ERR		24	/* Operation could not be */
						/* completed by the responder */
#define	IBT_WC_TRANS_TIMEOUT_ERR	25	/* Local transport retry */
						/* counter exceeded */
#define	IBT_WC_RNR_NAK_TIMEOUT_ERR	26	/* RNR NAK retry counter */
						/* exceeded */
#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBTL_STATUS_H */
