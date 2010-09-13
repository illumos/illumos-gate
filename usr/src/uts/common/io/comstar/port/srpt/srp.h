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

#ifndef _SRP_H
#define	_SRP_H

/*
 * General SCSI RDMA Protocol generic defines
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following defines and structures are based on revision 16A of
 * the T10 Project 1415-D SRP Protocol specification.
 */

/* Protocol revsion information */
enum {
	SRP_PROTOCOL		= 0x0108,
	SRP_PROTOCOL_VERSION	= 0x0001,
	SRP_REV_16A_IO_CLASS	= 0x0100,
	SRP_REV_10_IO_CLASS	= 0xFF00,	/* Old targets */
	SRP_IO_SUBCLASS		= 0x690E
};

/* SRP memory descriptors; direct and indirect formats */
typedef struct srp_direct_desc_s {
	uint64_t	dd_vaddr;
	uint32_t	dd_hdl;
	uint32_t	dd_len;
} srp_direct_desc_t;

#pragma pack(1)
typedef struct srp_indirect_desc_s {
	srp_direct_desc_t	id_table;
	uint32_t		id_len;
	srp_direct_desc_t	id_desc[1];
} srp_indirect_desc_t;
#pragma pack()
enum {
	SRP_DIRECT_BUFR_DESC	= 1 << 1,
	SRP_INDIRECT_BUFR_DESC	= 1 << 2
};

/* General constants */
enum {
	SRP_CDB_SIZE		= 16,
	SRP_LUN_SIZE		= 8,
	SRP_PORT_ID_LEN		= 16,
	SRP_MIN_IU_SIZE		= 64
};

/* SRP IU types */
enum {
	SRP_IU_LOGIN_REQ	= 0x00,
	SRP_IU_TASK_MGMT	= 0x01,
	SRP_IU_CMD		= 0x02,
	SRP_IU_I_LOGOUT		= 0x03,
	SRP_IU_LOGIN_RSP	= 0xC0,
	SRP_IU_RSP		= 0xC1,
	SRP_IU_LOGIN_REJ	= 0xC2,
	SRP_IU_T_LOGOUT		= 0x80,
	SRP_IU_CRED_REQ		= 0x81,
	SRP_IU_AER_REQ		= 0x82,
	SRP_IU_CRED_RSP		= 0x41,
	SRP_IU_AER_RSP		= 0x42
};

/* SRP Initiator Login IU, 64 bytes */
enum {
	SRP_LOGIN_MULTI_CH_SINGLE		= 0,
	SRP_LOGIN_MULTI_CH_MULTIPLE		= 1,
	SRP_LOGIN_MULTI_CH_MASK			= 0x03,
	SRP_LOGIN_AESOL_NOTIFICATION		= 1 << 6,
	SRP_LOGIN_CRSOL_NOTIFICATION		= 1 << 5,
	SRP_LOGIN_LOSOL_NOTIFICATION		= 1 << 4
};

typedef struct srp_login_req_s {
	uint8_t		lreq_type;
	uint8_t		lreq_rsvd[7];
	uint64_t	lreq_tag;
	uint32_t	lreq_req_it_iu_len;
	uint8_t		lreq_rsvd2[4];
	uint16_t	lreq_buf_format;
	uint8_t		lreq_req_flags;
	uint8_t		lreq_rsvd3[5];
	uint8_t		lreq_initiator_port_id[SRP_PORT_ID_LEN];
	uint8_t		lreq_target_port_id[SRP_PORT_ID_LEN];
} srp_login_req_t;

/* SRP Task Management IU, 64 bytes. */
enum {
	SRP_TSK_MGMT_SUCCESSFUL_COMP_SOLNT	= 1 << 1,
	SRP_TSK_MGMT_UNSUCCESSFUL_COMP_SOLNT	= 1 << 2
};

enum {
	SRP_TSK_ATTR_QTYPE_SIMPLE	= 0,
	SRP_TSK_ATTR_QTYPE_HEAD_OF_Q	= 1,
	SRP_TSK_ATTR_QTYPE_ORDERED	= 2,
	SRP_TSK_ATTR_QTYPE_ACA_Q_TAG	= 4
};

enum {
	SRP_TSK_MGMT_ABORT_TASK		= 1,
	SRP_TSK_MGMT_ABORT_TASK_SET	= 2,
	SRP_TSK_MGMT_CLEAR_TASK_SET	= 4,
	SRP_TSK_MGMT_LUN_RESET		= 8,
	SRP_TSK_MGMT_CLEAR_ACA		= 0x40
};

typedef struct srp_tsk_mgmt_s {
	uint8_t		tm_type;
	uint8_t		tm_not_flags;
	uint8_t		tm_rsvd[6];
	uint64_t	tm_tag;
	uint8_t		tm_rsvd2[4];
	uint8_t		tm_lun[8];
	uint8_t		tm_rsvd3[2];
	uint8_t		tm_function;
	uint8_t		tm_rsvd4;
	uint64_t	tm_task_tag;
	uint8_t		tm_rsvd5[8];
} srp_tsk_mgmt_t;

/* SRP Command Request IU, 48 bytes minimum */
enum {
	SRP_DATA_DESC_NONE		= 0,
	SRP_DATA_DESC_DIRECT		= 1,
	SRP_DATA_DESC_INDIRECT		= 2
};

#pragma pack(1)
typedef struct srp_cmd_req_s {
	uint8_t		cr_type;
	uint8_t		cr_not_flags;
	uint8_t		cr_rsvd[3];
	uint8_t		cr_buf_fmt;
	uint8_t		cr_docnt;
	uint8_t		cr_dicnt;
	uint64_t	cr_tag;
	uint8_t		cr_rsvd2[4];
	uint8_t		cr_lun[8];
	uint8_t		cr_rsvd3;
	uint8_t		cr_task_attr;
	uint8_t		cr_rsvd4;
	uint8_t		cr_add_cdb_len;
	uint8_t		cr_cdb[SRP_CDB_SIZE];
	uint8_t		cr_add_data;
} srp_cmd_req_t;
#pragma pack()

/* SRP Initiator Logout IU, 16 bytes */
typedef struct srp_i_logout_s {
	uint8_t		il_type;
	uint8_t		il_rsvd[7];
	uint64_t	il_tag;
} srp_i_logout_t;

/* SRP Login Response IU, 52 bytes */
enum {
	SRP_MULTI_CH_RESULT_NO_EXISTING		= 0,
	SRP_MULTI_CH_RESULT_TERM_EXISTING	= 1,
	SRP_MULTI_CH_RESULT_EXISTING_EXISTS  	= 1 << 1,
	SRP_SOLNT_SUPPORTED			= 1 << 4
};

#define	SRP_LOGIN_RSP_SIZE	52

typedef struct srp_login_rsp_s {
	uint8_t		lrsp_type;
	uint8_t		lrsp_rsvd[3];
	uint32_t	lrsp_req_limit_delta;
	uint64_t	lrsp_tag;
	uint32_t	lrsp_max_it_iu_len;
	uint32_t	lrsp_max_ti_iu_len;
	uint16_t	lrsp_sup_buf_format;
	uint8_t		lrsp_rsp_flags;
	uint8_t		lrsp_rsvd2[25];
} srp_login_rsp_t;

/* SRP Response IU, 36 byte minimum */
enum {
	SRP_RSP_SOLICITED_NOTIFICATION = 1
};

enum {
	SRP_RSP_VALID		= 1,
	SRP_RSP_SNS_VALID	= 1 << 1,
	SRP_RSP_DO_OVER		= 1 << 2,
	SRP_RSP_DO_UNDER	= 1 << 3,
	SRP_RSP_DI_OVER		= 1 << 4,
	SRP_RSP_DI_UNDER	= 1 << 5
};

/* Additional response data used for task mgmt responses */
enum {
	SRP_TM_SUCCESS		= 0,
	SRP_TM_REQ_INVALID	= 2,
	SRP_TM_NOT_SUPPORTED	= 4,
	SRP_TM_FAILED		= 5
};

typedef struct srp_rsp_data_s {
	uint8_t		rd_rsvd[3];
	uint8_t		rd_rsp_status;
} srp_rsp_data_t;

#define	SRP_RSP_SIZE		36

typedef struct srp_rsp_s {
	uint8_t		rsp_type;
	uint8_t		rsp_sol_not;
	uint8_t		rsp_rsvd[2];
	uint32_t	rsp_req_limit_delta;
	uint64_t	rsp_tag;
	uint8_t		rsp_rsvd2[2];
	uint8_t		rsp_flags;
	uint8_t		rsp_status;
	uint32_t	rsp_do_resid_cnt;
	uint32_t	rsp_di_resid_cnt;
	uint32_t	rsp_sense_data_len;
	uint32_t	rsp_data_len;
} srp_rsp_t;

/* SRP Login Reject IU, 32 bytes */
enum {
	SRP_LOGIN_REJ_NO_REASON				= 0x00010000,
	SRP_LOGIN_REJ_INSUFFICIENT_CH_RESOURCES		= 0x00010001,
	SRP_LOGIN_REJ_REQ_IT_IU_LENGTH_TOO_LARGE	= 0x00010002,
	SRP_LOGIN_REJ_UNABLE_TO_ASSOCIATE_I_T_NEXUS	= 0x00010003,
	SRP_LOGIN_REJ_REQ_BUF_FORMAT_NOT_SUPPORTED	= 0x00010004,
	SRP_LOGIN_REJ_MULTI_CH_NOT_SUPPORTED		= 0x00010005,
	SRP_LOGIN_REJ_INIT_CH_LIMIT			= 0x00010006
};

typedef struct srp_login_rej_s {
	uint8_t		lrej_type;
	uint8_t		lrej_rsvd[3];
	uint32_t	lrej_reason;
	uint64_t	lrej_tag;
	uint8_t		lrej_rsvd2[8];
	uint16_t	lrej_sup_buf_format;
	uint8_t		lrej_rsvd3[6];
} srp_login_rej_t;

/* SRP Target Logout IU, 16 bytes */
enum {
	SRP_T_LOGOUT_NO_REASON			= 0,
	SRP_T_LOGOUT_INACTIVE			= 1,
	SRP_T_LOGOUT_INVALID_IU_TYPE		= 2,
	SRP_T_LOGOUT_UNEXPECTED_INITIATOR_RSP	= 3,
	SRP_T_LOGOUT_MULTI_CHANNEL_ACTION	= 4,
	SRP_T_LOGOUT_UNSUPPORTED_DO_FORMAT	= 6,
	SRP_T_LOGOUT_UNSUPPORTED_DI_FORMAT	= 7,
	SRP_T_LOGOUT_INVALID_IU_LENGTH		= 8
};

typedef struct srp_t_logout_s {
	uint8_t		tl_type;
	uint8_t		tl_sol_not;
	uint8_t		tl_rsvd[2];
	uint32_t	tl_reason;
	uint64_t	tl_tag;
} srp_t_logout_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SRP_H */
