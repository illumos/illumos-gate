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

#ifndef _ISER_H
#define	_ISER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sunddi.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibtl_types.h>

#include <sys/idm/idm.h>
#include <sys/ib/clients/iser/iser_ib.h>
#include <sys/ib/clients/iser/iser_resource.h>
#include <sys/ib/clients/iser/iser_cm.h>
#include <sys/ib/clients/iser/iser_xfer.h>

/*
 * iser.h
 *	Definitions and macros related to iSER core functionality,
 * 	softstate and DDI routines.
 */
extern boolean_t iser_logging;
#define	ISER_LOG if (iser_logging) cmn_err

#define	ISER_TASKQ_NTHREADS	4

#define	ISER_HEADER_LENGTH	28

#define	ISER_DELAY_HALF_SECOND	500000 /* for use with drv_usectohz() */

/* iSER Operational Parameters */
#define	ISER_TARGET_RECV_DATA_SEGMENT_LENGTH_MIN		0x200
#define	ISER_TARGET_RECV_DATA_SEGMENT_LENGTH_MAX		0xFFFFFF
#define	ISER_TARGET_RECV_DATA_SEGMENT_LENGTH_IMPL_MAX		0xFFFFFF
#define	ISER_TARGET_RECV_DATA_SEGMENT_LENGTH_DEFAULT		\
	ISCSI_DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH
#define	ISER_INITIATOR_RECV_DATA_SEGMENT_LENGTH_MIN		0x200
#define	ISER_INITIATOR_RECV_DATA_SEGMENT_LENGTH_MAX		0xFFFFFF
#define	ISER_INITIATOR_RECV_DATA_SEGMENT_LENGTH_IMPL_MAX	0xFFFFFF
#define	ISER_INITIATOR_RECV_DATA_SEGMENT_LENGTH_DEFAULT		\
	ISCSI_DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH
#define	ISER_MAX_OUTSTANDING_UNEXPECTED_PDUS_MIN		0x0
#define	ISER_MAX_OUTSTANDING_UNEXPECTED_PDUS_MAX		0xFFFFFFFF
#define	ISER_MAX_OUTSTANDING_UNEXPECTED_PDUS_IMPL_MAX		0xFFFFFFFF
#define	ISER_MAX_OUTSTANDING_UNEXPECTED_PDUS_DEFAULT		0x0

/* iSCSI key names that iSER is interested in */
#define	ISER_KV_KEY_NAME_RDMA_EXTENSIONS	"RDMAExtensions"
#define	ISER_KV_KEY_NAME_OF_MARKER		"OFMarker"
#define	ISER_KV_KEY_NAME_IF_MARKER		"IFMarker"
#define	ISER_KV_KEY_NAME_TGT_RECV_SEGLEN	"TargetRecvDataSegmentLength"
#define	ISER_KV_KEY_NAME_INI_RECV_SEGLEN	"InitiatorRecvDataSegmentLength"
#define	ISER_KV_KEY_NAME_MAX_OUTSTANDING_PDU	"MaxOutstandingUnexpectedPDUs"

typedef struct iser_sbind_s {
	list_node_t		is_list_node;
	ibt_sbind_hdl_t		is_sbindhdl;
	ib_gid_t		is_gid;
	ib_guid_t		is_guid;
} iser_sbind_t;

/* iSER-specific portion of idm_svc_t */
typedef struct iser_svc_s {
	idm_refcnt_t		is_refcnt;
	ib_svc_id_t		is_svcid;
	ibt_srv_hdl_t		is_srvhdl;
	/* list of service bind handles - one per HCA port */
	list_t			is_sbindlist;
} iser_svc_t;

/*
 * iSER endpoint connection type
 */
typedef enum {
	ISER_CONN_TYPE_INI = 1,
	ISER_CONN_TYPE_TGT
} iser_conn_type_t;

/*
 * iSER Connection States to keep track of the connection going into
 * iSER-assisted mode
 */
typedef enum {
	ISER_CONN_STAGE_UNDEFINED,
	ISER_CONN_STAGE_ALLOCATED,	/* conn handle allocated */
	ISER_CONN_STAGE_IC_CONNECTED,	/* conn established */
	ISER_CONN_STAGE_HELLO_SENT,	/* hello exchange stages */
	ISER_CONN_STAGE_HELLO_SENT_FAIL,
	ISER_CONN_STAGE_HELLO_WAIT,
	ISER_CONN_STAGE_HELLO_RCV,
	ISER_CONN_STAGE_HELLO_RCV_FAIL,
	ISER_CONN_STAGE_HELLOREPLY_SENT,
	ISER_CONN_STAGE_HELLOREPLY_SENT_FAIL,
	ISER_CONN_STAGE_HELLOREPLY_RCV,
	ISER_CONN_STAGE_HELLOREPLY_RCV_FAIL,
	ISER_CONN_STAGE_LOGGED_IN,
	ISER_CONN_STAGE_IC_DISCONNECTED, /* conn disconnected */
	ISER_CONN_STAGE_IC_FREED,	/* conn handle allocated */
	ISER_CONN_STAGE_CLOSING,	/* channel closing */
	ISER_CONN_STAGE_CLOSED		/* channel closed */
} iser_conn_stage_t;

/*
 * iSER operations parameters negotiated for a given connection
 */
typedef struct iser_op_params_s {
	uint32_t	op_header_digest:1,
			op_data_digest:1,
			op_rdma_extensions:1,
			op_ofmarker:1,
			op_ifmarker:1;
	uint64_t	op_target_recv_data_segment_length;
	uint64_t	op_initiator_recv_data_segment_length;
	uint64_t	op_max_outstanding_unexpected_pdus;
} iser_op_params_t;

/*
 * iSER connection information
 */
typedef struct iser_conn_s {
	kmutex_t		ic_lock;
	kcondvar_t		ic_stage_cv;
	iser_conn_type_t	ic_type;
	iser_chan_t		*ic_chan;
	iser_conn_stage_t	ic_stage; /* for iSER-assisted mode */
	iser_op_params_t	ic_op_params;
	idm_conn_t		*ic_idmc;
	idm_svc_t		*ic_idms;
} iser_conn_t;

/*
 * iser_state_t is the iser driver's state structure, encoding all of
 * the state information.
 */
typedef struct iser_state_s {
	dev_info_t	*is_dip;
	int		is_instance;

	/* IDM open ref counter and lock */
	kmutex_t	is_refcnt_lock;
	int		is_open_refcnt;

	ibt_clnt_hdl_t	is_ibhdl;	/* IBT handle */

	/* list of HCAs */
	kmutex_t	is_hcalist_lock; /* locked by is_hcalist_lock */
	list_t		is_hcalist;
	uint_t		is_num_hcas;

	/* Connection list */
	iser_conn_t	*is_connlist;

	/* Global work request handle cache */
	kmem_cache_t		*iser_wr_cache;
} iser_state_t;

typedef enum {
	ISER_STATUS_SUCCESS = 0,
	ISER_STATUS_FAIL
} iser_status_t;

int iser_idm_register();

iser_status_t iser_register_service(idm_svc_t *idm_svc);

iser_status_t iser_bind_service(idm_svc_t *idm_svc);

void iser_unbind_service(idm_svc_t *idm_svc);

void iser_deregister_service(idm_svc_t *idm_svc);

boolean_t iser_path_exists(idm_sockaddr_t *laddr, idm_sockaddr_t *raddr);

iser_chan_t *iser_channel_alloc(idm_sockaddr_t *laddr, idm_sockaddr_t *raddr);

iser_status_t iser_channel_open(iser_chan_t *chan);

void iser_channel_close(iser_chan_t *chan);

void iser_channel_free(iser_chan_t *chan);

void iser_internal_conn_destroy(iser_conn_t *ic);

/* IDM refcnt utilities for the iSER tgt svc handle */
void iser_tgt_svc_hold(iser_svc_t *is);
void iser_tgt_svc_rele(iser_svc_t *is);


#ifdef	__cplusplus
}
#endif

#endif /* _ISER_H */
