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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBDM_IBDM_IMPL_H
#define	_SYS_IB_MGT_IBDM_IBDM_IMPL_H

/*
 * ibdm_impl.h
 *
 *	This file contains definitions of the data structures, macros etc
 *	related to the IBDM module.
 */

#include <sys/ib/mgt/ibdm/ibdm_ibnex.h>
#include <sys/ib/ibtl/impl/ibtl_util.h>

#ifdef __cplusplus
extern "C" {
#endif

/* values for "cb_req_type" */
#define	IBDM_REQ_TYPE_INVALID		0x0
#define	IBDM_REQ_TYPE_CLASSPORTINFO	0x1
#define	IBDM_REQ_TYPE_IOUINFO		0x2
#define	IBDM_REQ_TYPE_IOCINFO		0x4
#define	IBDM_REQ_TYPE_SRVENTS		0x8
#define	IBDM_REQ_TYPE_IOU_DIAGCODE	0x10
#define	IBDM_REQ_TYPE_IOC_DIAGCODE	0x20

typedef struct ibdm_taskq_args_s {
	ibmf_handle_t		tq_ibmf_handle;
	ibmf_msg_t		*tq_ibmf_msg;
	void			*tq_args;
} ibdm_taskq_args_t;
_NOTE(SCHEME_PROTECTS_DATA("unique per call", ibdm_taskq_args_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", ib_mad_hdr_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", ibmf_msg_t))

#define	IBDM_GID_PRESENT		0x1
#define	IBDM_GID_NOT_PRESENT		0x0

#define	IBDM_IBMF_PKT_DUP_RESP		0x1
#define	IBDM_IBMF_PKT_REUSED		0x2
#define	IBDM_IBMF_PKT_UNEXP_RESP	0x4

#define	IBDM_MAX_SERV_ENTRIES_PER_REQ	4

typedef struct ibdm_gid_s {
	uint64_t		gid_dgid_hi;
	uint64_t		gid_dgid_lo;
	struct ibdm_gid_s	*gid_next;
} ibdm_gid_t;

#define	IBDM_GID_PROBE_NOT_DONE		0x00
#define	IBDM_GET_CLASSPORTINFO		0x01
#define	IBDM_GET_IOUNITINFO		0x02
#define	IBDM_GET_IOC_DETAILS		0x04
#define	IBDM_GID_PROBING_COMPLETE	0x08
#define	IBDM_GID_PROBING_SKIPPED	0x10
#define	IBDM_GID_PROBING_FAILED		0x20
#define	IBDM_SET_CLASSPORTINFO		0x40

/*
 * Identifiers to distinguish a Cisco FC GW from others.
 * Used to filter a setclassportinfo request.
 */
#define	IBDM_CISCO_COMPANY_ID		(0x5ad)
#define	IBDM_CISCO_DEVICE_ID		(0xa87c)

/*
 * the bit-shift value for OUI in GUID
 * A 64 bit globally unique identifier (GUID) composed of a 24 bit company id
 * and an 48 bit extension identifier, and this value is used to extract
 * the company id from the GUID.
 */
#define	IBDM_OUI_GUID_SHIFT		(40)

/*
 * The state diagram for the gl_state
 *
 *                          (in case of Cisco FC GW)
 * IBDM_GID_PROBE_NOT_DONE  ---------- 40 -> IBDM_SET_CLASSPORTINFO
 *                          ----.	        |
 *    |      |			| (others)      |
 *    |      |			1		|
 *    |      |			|               1
 *    |      |			`-------------.	|
 *    |      |                                v v
 *    |	     |				     IBDM_GET_CLASSPORTINFO
 *    |      |
 *    |      |                                  |
 *    |      2                                  3
 *    |      |                                  |
 *    |      v                                  v
 *    |     IBDM_GID_PROBING_FAILED          IBDM_GET_IOUNITINFO
 *    |                                         |
 *    6                                         4
 *    |                                         |
 *    v                                         v
 *  IBDM_GID_PROBING_SKIPPLED                IBDM_GET_IOC_DETAILS
 *                                              |
 *                                              5
 *                                              |
 *                                              v
 *                                           IBDM_GID_PROBE_COMPLETE
 *
 * Initial state : IBDM_GID_PROBE_NOT_DONE
 *     40 = Port sends setClassPortInfo to activate Cisco FC GW
 *	1 = Port supports DM MAD's and a request to ClassportInfo is sent
 *	3 = Received ClassPortInfo and sent IOUnitInfo
 *	4 = Recevied IOUunitInfo and sent IOC profile, diagcodes, and
 *		service entries requests
 *	5 = Received all the IOC information
 *	2 = Failed to probe the GID
 *		Port does not support DM MAD's
 *		Port did not respond property
 *	6 = A different GID for the same port, skip the probe
 *
 * Reprobe state transition :
 *
 * IBDM_GID_PROBE_COMPLETE
 *	|
 *	7
 *	|
 *	v
 * IBDM_GET_IOC_DETAILS
 *	|
 *	8
 *	|
 *	v
 * IBDM_GID_PROBE_COMPLETE
 *
 *	7 = Reprobe request for one or more IOCs initiated.
 *	8 = Reprobe done(IOC COntroller Profile & Service entries)
 */

typedef struct ibdm_dp_gidinfo_s {
	kmutex_t		gl_mutex;
	uint_t			gl_state;
	int			gl_reprobe_flag;	/* pass this to taskq */
	struct ibdm_dp_gidinfo_s *gl_next;
	struct ibdm_dp_gidinfo_s *gl_prev;
	ibdm_iou_info_t		*gl_iou;
	int			gl_pending_cmds;
	ibmf_qp_handle_t	gl_qp_hdl;
	uint64_t		gl_transactionID;
	ibdm_timeout_cb_args_t	gl_iou_cb_args;
	ib_lid_t		gl_dlid;
	ib_lid_t		gl_slid;
	uint64_t		gl_dgid_hi;
	uint64_t		gl_dgid_lo;
	uint64_t		gl_sgid_hi;
	uint64_t		gl_sgid_lo;
	ib_guid_t		gl_nodeguid;
	ib_guid_t		gl_portguid;
	ib_pkey_t		gl_p_key;
	boolean_t		gl_is_dm_capable;
	boolean_t		gl_redirected;
	uint32_t		gl_redirect_dlid;
	uint32_t		gl_redirect_QP;
	ib_pkey_t		gl_redirect_pkey;
	ib_qkey_t		gl_redirect_qkey;
	uint64_t		gl_redirectGID_hi;
	uint64_t		gl_redirectGID_lo;
	ibmf_handle_t		gl_ibmf_hdl;
	ibmf_saa_handle_t	gl_sa_hdl;
	timeout_id_t		gl_timeout_id;
	ibdm_timeout_cb_args_t	gl_cpi_cb_args;
	uint32_t		gl_ngids;
	ibdm_gid_t		*gl_gid;
	uint32_t		gl_resp_timeout;
	int			gl_num_iocs;
	ibdm_hca_list_t		*gl_hca_list;
	int			gl_disconnected;
	uint64_t		gl_min_transactionID;
	uint64_t		gl_max_transactionID;
	ibdm_iou_info_t		*gl_prev_iou;
	uint16_t		gl_devid;	/* device ID info */
	kcondvar_t		gl_probe_cv;	/* sync for Cisco FC GW */
	uint32_t		gl_flag;
	uint8_t			gl_SL:4; 	/* SL from path_record */
	uint8_t			gl_redirectSL:4; /* SL from redirection */
} ibdm_dp_gidinfo_t;
_NOTE(MUTEX_PROTECTS_DATA(ibdm_dp_gidinfo_s::gl_mutex,
	ibdm_dp_gidinfo_s::{gl_state gl_timeout_id gl_pending_cmds}))
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv", ibdm_dp_gidinfo_s))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibdm_dp_gidinfo_s::{gl_ibmf_hdl gl_sa_hdl}))
_NOTE(MUTEX_PROTECTS_DATA(ibdm_dp_gidinfo_s::gl_mutex,
	ibdm_ioc_info_s::{ioc_timeout_id ioc_dc_timeout_id}))
_NOTE(MUTEX_PROTECTS_DATA(ibdm_dp_gidinfo_s::gl_mutex,
	ibdm_srvents_info_s::se_timeout_id))

/*
 * The transaction ID for the GID contains of two parts :
 *	1. Upper 32 bits which is unique for each GID.
 *	2. Lower 32 bits which is unique for each MAD.
 * The assumptions are :
 *	1. At most 2 power 32 DM capable GIDs on the IB fabric
 *	2. IBDM sends maximum of 2 power 32 MADs to the same DM GID
 * The limits are sufficient for practical configurations.
 */
#define	IBDM_GID_TRANSACTIONID_SHIFT	((ulong_t)32)
#define	IBDM_GID_TRANSACTIONID_MASK	0xFFFFFFFF00000000ULL

typedef struct ibdm_s {
	/* Protects IBDM's critical data */
	kmutex_t		ibdm_mutex;
	uint32_t		ibdm_hca_count;
	kmutex_t		ibdm_hl_mutex;
	kmutex_t		ibdm_ibnex_mutex;
	ibdm_hca_list_t		*ibdm_hca_list_head;
	ibdm_hca_list_t		*ibdm_hca_list_tail;

	ibdm_dp_gidinfo_t	*ibdm_dp_gidlist_head;
	ibdm_dp_gidinfo_t	*ibdm_dp_gidlist_tail;

	kcondvar_t		ibdm_probe_cv;
	kcondvar_t		ibdm_busy_cv;
	kcondvar_t		ibdm_port_settle_cv;
	uint32_t		ibdm_ngid_probes_in_progress;
	uint64_t		ibdm_transactionID;
	uint32_t		ibdm_ngids;
	uint32_t		ibdm_busy;
	int			ibdm_state;
	ibt_clnt_hdl_t		ibdm_ibt_clnt_hdl;

	/*
	 * These are callback routines registered by the IB nexus driver.
	 * These callbacks are used to inform the IB nexus driver about
	 * the arrival/removal of HCA and IOC's
	 */
	ibdm_callback_t		ibdm_ibnex_callback;

	/* Flag indicating - prev_iou during sweep */
	int			ibdm_prev_iou;
} ibdm_t;
_NOTE(MUTEX_PROTECTS_DATA(ibdm_s::ibdm_mutex, ibdm_s::{ibdm_ibt_clnt_hdl
	ibdm_busy ibdm_state}))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibdm_s::ibdm_ibt_clnt_hdl))
_NOTE(MUTEX_PROTECTS_DATA(ibdm_s::ibdm_hl_mutex,
	ibdm_s::{ibdm_hca_list_head ibdm_hca_list_tail}))
_NOTE(MUTEX_PROTECTS_DATA(ibdm_s::ibdm_ibnex_mutex,
	ibdm_s::ibdm_ibnex_callback))
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv", ibdm_s))
_NOTE(LOCK_ORDER(ibdm_s::ibdm_mutex ibdm_dp_gidinfo_s::gl_mutex))

/* valid values for ibdm_state */
#define	IBDM_LOCKS_ALLOCED	0x01		/* global locks alloced */
#define	IBDM_CVS_ALLOCED	0x02		/* global "cv"s alloced */
#define	IBDM_IBT_ATTACHED	0x04		/* ibt_attach() called */
#define	IBDM_HCA_ATTACHED	0x08		/* ibdm_handle_hca() called */

#define	IBDM_8_BIT_MASK		0x00FF
#define	IBDM_16_BIT_MASK	0xFFFF
#define	IBDM_RETRY_COUNT	0x2

#define	IBDM_BUSY		0x1
#define	IBDM_PROBE_IN_PROGRESS	0x2
#define	IBDM_CISCO_PROBE	0x4
#define	IBDM_CISCO_PROBE_DONE	0x8

/*
 * Device Management MAD packet format
 * +--------+------------+------------+------------+------------+
 * | offset |   byte 0   |   byte 1   |   byte 2   |   byte 3   |
 * +--------+------------+------------+------------+------------+ --
 * |   0    |                                                   |  ^
 * +--------+                                                   | sizeof(
 * |   ...  |              Common MAD Header                    | ib_mad_hdr_t)
 * +--------+                                                   |  | (A)
 * |   20   |                                                   |  v
 * +--------+------------+------------+------------+------------+ --
 * |   24   |                                                   |  ^
 * +--------+                                                   |  |
 * |   ...  |              RMPP Header                          |  |
 * +--------+                                                   |  |
 * |   32   |                                                   |  |
 * +--------+------------+------------+------------+------------+  |
 * |   36   |                                                   |  |
 * +--------+              Access_Key                           |
 * |   40   |                                                   | IBDM_DM_MAD_
 * +--------+------------+------------+------------+------------+ HDR_SZ
 * |   44   |  KeyType   |              reserved                |    (B)
 * +--------+------------+------------+------------+------------+  |
 * |   48   |                                                   |  |
 * +--------+                                                   |  |
 * |   52   |              Reserved                             |  |
 * +--------+                                                   |  |
 * |   56   |                                                   |  |
 * +--------+------------+------------+------------+------------+  |
 * |   60   |       Change_ID         |     ComponentMask       |  v
 * +--------+------------+------------+------------+------------+ --
 * |   64   |                                                   |  ^
 * +--------+                                                   | IBDM_MAD_SIZE
 * |   ...  |              Device Management Data               | - (A) - (B)
 * +--------+                                                   |  |
 * |  252   |                                                   |  v
 * +--------+------------+------------+------------+------------+ --
 */
#define	IBDM_MAD_SIZE		256
#define	IBDM_DM_MAD_HDR_SZ	40

#define	IBDM_DFT_TIMEOUT	4
#define	IBDM_DFT_NRETRIES	3

#define	IBDM_ENABLE_TASKQ_HANDLING	1
#define	IBDM_DISABLE_TASKQ_HANLDING	0

typedef struct ibdm_saa_event_arg_s {
	ibmf_saa_handle_t ibmf_saa_handle;
	ibmf_saa_subnet_event_t ibmf_saa_event;
	ibmf_saa_event_details_t event_details;
	void *callback_arg;
} ibdm_saa_event_arg_t;

#define	IBDM_TIMEOUT_VALUE(t)	(drv_usectohz(t * 1000000))

#define	IBDM_OUT_IBMFMSG_MADHDR(msg)\
		(msg->im_msgbufs_send.im_bufs_mad_hdr)

#define	IBDM_IN_IBMFMSG_MADHDR(msg)\
		(msg->im_msgbufs_recv.im_bufs_mad_hdr)

#define	IBDM_IN_IBMFMSG_STATUS(msg)\
		b2h16(msg->im_msgbufs_recv.im_bufs_mad_hdr->Status)

#define	IBDM_IN_IBMFMSG_ATTR(msg)\
		b2h16(msg->im_msgbufs_recv.im_bufs_mad_hdr->AttributeID)

#define	IBDM_IN_IBMFMSG_ATTRMOD(msg)\
		b2h32(msg->im_msgbufs_recv.im_bufs_mad_hdr->AttributeModifier)

#define	IBDM_IN_IBMFMSG2IOU(msg)	(ib_dm_io_unitinfo_t *)\
		(msg->im_msgbufs_recv.im_bufs_cl_data)

#define	IBDM_IN_IBMFMSG2IOC(msg)	(ib_dm_ioc_ctrl_profile_t *)\
		(msg->im_msgbufs_recv.im_bufs_cl_data)

#define	IBDM_IN_IBMFMSG2SRVENT(msg)	(ib_dm_srv_t *)\
		(msg->im_msgbufs_recv.im_bufs_cl_data)

#define	IBDM_IN_IBMFMSG2DIAGCODE(msg)	(uint32_t *)\
		(msg->im_msgbufs_recv.im_bufs_cl_data)

#define	IBDM_GIDINFO2IOCINFO(gid_info, idx) \
		(ibdm_ioc_info_t *)&gid_info->gl_iou->iou_ioc_info[idx];

#define	IBDM_IS_IOC_NUM_INVALID(ioc_no, gid_info)\
		((ioc_no < 1) || (ioc_no >\
			gid_info->gl_iou->iou_info.iou_num_ctrl_slots))

#define	IBDM_INVALID_PKEY(pkey)	\
		(((pkey) == IB_PKEY_INVALID_FULL) || \
		((pkey) == IB_PKEY_INVALID_LIMITED))

#ifdef DEBUG

void	ibdm_dump_mad_hdr(ib_mad_hdr_t *);
void	ibdm_dump_ibmf_msg(ibmf_msg_t *, int);
void	ibdm_dump_path_info(sa_path_record_t *);
void	ibdm_dump_classportinfo(ib_mad_classportinfo_t *);
void	ibdm_dump_iounitinfo(ib_dm_io_unitinfo_t *);
void	ibdm_dump_ioc_profile(ib_dm_ioc_ctrl_profile_t *);
void	ibdm_dump_service_entries(ib_dm_srv_t *);
void	ibdm_dump_sweep_fabric_timestamp(int);

#define	ibdm_dump_mad_hdr(a)		ibdm_dump_mad_hdr(a)
#define	ibdm_dump_ibmf_msg(a, b)	ibdm_dump_ibmf_msg(a, b)
#define	ibdm_dump_path_info(a)		ibdm_dump_path_info(a)
#define	ibdm_dump_classportinfo(a)	ibdm_dump_classportinfo(a)
#define	ibdm_dump_iounitinfo(a)		ibdm_dump_iounitinfo(a)
#define	ibdm_dump_ioc_profile(a)	ibdm_dump_ioc_profile(a)
#define	ibdm_dump_service_entries(a)	ibdm_dump_service_entries(a)

#else

#define	ibdm_dump_mad_hdr(a)
#define	ibdm_dump_ibmf_msg(a, b)
#define	ibdm_dump_path_info(a)
#define	ibdm_dump_classportinfo(a)
#define	ibdm_dump_iounitinfo(a)
#define	ibdm_dump_ioc_profile(a)
#define	ibdm_dump_service_entries(a)
#define	ibdm_dump_sweep_fabric_timestamp(a)

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_MGT_IBDM_IBDM_IMPL_H */
