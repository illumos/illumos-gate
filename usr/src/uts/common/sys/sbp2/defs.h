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

#ifndef	_SYS_SBP2_DEFS_H
#define	_SYS_SBP2_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Serial Bus Protocol 2 (SBP-2) definitions
 *
 * References are to ANSI NCITS 325-1998 unless specified otherwise
 */

#include <sys/sbp2/common.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Operation request blocks (ORB's)
 * Note that the targets specify the minimum ORB size (ref: 7.8.4)
 *
 * dummy ORB (ref: 5.1.1)
 */
typedef struct sbp2_dummy_orb {
	sbp2_orbp_t	do_next_orb;	/* next ORB pointer */
	uint32_t	do_ignored1[2];	/* ignored */
	uint16_t	do_params;	/* parameters */
	uint16_t	do_ignored2;	/* ignored */
} sbp2_dummy_orb_t;

/* parameters */
#define	SBP2_ORB_NOTIFY			0x8000	/* notify bit */
#define	SBP2_ORB_RQ_FMT			0x6000	/* ORB format */

/* ORB formats */
#define	SBP2_ORB_RQ_FMT_SBP2		0x0000	/* SBP2 ORB */
#define	SBP2_ORB_RQ_FMT_DUMMY		0x6000	/* dummy (NOP) ORB */

/* command block ORB (ref: 5.1.2) */
typedef struct sbp2_cmd_orb {
	sbp2_orbp_t	co_next_orb;	/* next ORB pointer */
	uint32_t	co_data_descr[2]; /* data descriptor */
	uint16_t	co_params;	/* parameters */
	uint16_t	co_data_size;	/* data size */
} sbp2_cmd_orb_t;

/* request */
#define	SBP2_ORB_CMD_DIR		0x0800
#define	SBP2_ORB_CMD_SPD		0x0700
#define	SBP2_ORB_CMD_SPD_SHIFT		8
#define	SBP2_ORB_CMD_MAX_PAYLOAD 	0x00F0
#define	SBP2_ORB_CMD_MAX_PAYLOAD_SHIFT 	4
#define	SBP2_ORB_CMD_PT			0x0008
#define	SBP2_ORB_CMD_PSZ		0x0007

/* speeds */
#define	SBP2_ORB_CMD_SPD_S100		0x0000
#define	SBP2_ORB_CMD_SPD_S200		0x0100
#define	SBP2_ORB_CMD_SPD_S400		0x0200
#define	SBP2_ORB_CMD_SPD_S800		0x0300
#define	SBP2_ORB_CMD_SPD_S1600		0x0400
#define	SBP2_ORB_CMD_SPD_S3200		0x0500

/* management ORB (ref: 5.1.3) */
typedef struct sbp2_mgt_orb {
	uint32_t	mo_fdep1[4];	/* function-dependent */
	uint16_t	mo_params;	/* parameters */
	uint16_t	mo_fdep2;	/* function-dependent */
	uint32_t	mo_fdep3;	/* function-dependent */
	sbp2_addr_t	mo_status_fifo;	/* status FIFO address */
} sbp2_mgt_orb_t;

/* parameters */
#define	SBP2_ORB_MGT_FUNC 		0x000F	/* mgt function */

/* mgt functions */
#define	SBP2_ORB_MGT_FUNC_LOGIN 	0x0000
#define	SBP2_ORB_MGT_FUNC_QUERY_LOGINS	0x0001
#define	SBP2_ORB_MGT_FUNC_RECONNECT 	0x0003
#define	SBP2_ORB_MGT_FUNC_SET_PASSWORD	0x0004
#define	SBP2_ORB_MGT_FUNC_LOGOUT 	0x0007
#define	SBP2_ORB_MGT_FUNC_ABORT_TASK 	0x000B
#define	SBP2_ORB_MGT_FUNC_ABORT_TASK_SET 0x000C
#define	SBP2_ORB_MGT_FUNC_LUN_RESET 	0x000E
#define	SBP2_ORB_MGT_FUNC_TARGET_RESET	0x000F

/* login ORB (ref: 5.1.3.1) */
typedef struct sbp2_login_orb {
	sbp2_addr_t	lo_passwd;	/* password */
	sbp2_addr_t	lo_resp;	/* response */
	uint16_t	lo_params;	/* parameters */
	uint16_t	lo_lun;		/* lun */
	uint16_t	lo_passwd_len;	/* password length */
	uint16_t	lo_resp_len;	/* response length */
	sbp2_addr_t	lo_status_fifo;	/* status FIFO address */
} sbp2_login_orb_t;

/* parameters */
#define	SBP2_ORB_LOGIN_EXCL		0x1000
#define	SBP2_ORB_LOGIN_RECONNECT	0x00F0
#define	SBP2_ORB_LOGIN_RECONNECT_SHIFT	4

/* login response */
typedef struct sbp2_login_resp {
	uint16_t	lr_len;		/* login length */
	uint16_t	lr_login_id;	/* login ID */
	sbp2_addr_t	lr_cmd_agent;	/* command block agent address */
	uint16_t	lr_reserved;	/* reserved */
	uint16_t	lr_reconnect_hold; /* reconnect hold */
} sbp2_login_resp_t;

/* query logins ORB (ref: 5.1.3.2) */
typedef struct sbp2_qlogins_orb {
	uint32_t	qo_reserved1[2]; /* reserved */
	sbp2_addr_t	qo_resp;	/* query response address */
	uint16_t	qo_params;	/* parameters */
	uint16_t	qo_lun;		/* LUN */
	uint16_t	qo_reserved2;	/* reserved */
	uint16_t	qo_len;		/* lengths */
	sbp2_addr_t	qo_status_fifo; /* status FIFO address */
} sbp2_qlogins_orb_t;

/* reconnect ORB (ref: 5.1.3.3) */
typedef struct sbp2_reconnect_orb {
	uint32_t	ro_reserved1[4]; /* reserved */
	uint16_t	ro_params;	/* parameters */
	uint16_t	ro_login_id;	/* login ID */
	uint32_t	ro_reserved2;	/* reserved */
	sbp2_addr_t	ro_status_fifo; /* status FIFO address */
} sbp2_reconnect_orb_t;

/* logout ORB (ref: 5.1.3.4) */
typedef struct sbp2_logout_orb {
	uint32_t	lo_reserved1[4]; /* reserved */
	uint16_t	lo_params;	/* parameters */
	uint16_t	lo_login_id;	/* login ID */
	uint32_t	lo_reserved2;	/* reserved */
	sbp2_addr_t	lo_status_fifo; /* status FIFO address */
} sbp2_logout_orb_t;

/* task management ORB (ref: 5.1.3.5) */
typedef struct sbp2_task_mgt_orb {
	sbp2_orbp_t	to_orb;		/* task pointer */
	uint32_t	to_reserved1[2]; /* reserved */
	uint16_t	to_params;	/* parameters */
	uint16_t	to_login_id;	/* login ID */
	uint32_t	to_reserved;	/* reserved */
	sbp2_addr_t	to_status_fifo; /* status FIFO address */
} sbp2_task_mgt_orb_t;

/* status block (ref: 5.3) */
typedef struct sbp2_status {
	uint8_t		st_param;	/* parameters */
	uint8_t		st_sbp_status;	/* SBP status */
	uint16_t	st_orb_offset_hi; /* ORB offset hi */
	uint32_t	st_orb_offset_lo; /* ORB offset lo */
	uint32_t	st_data[6];	/* command set-dependent data */
} sbp2_status_t;

/* parameters */
#define	SBP2_ST_SRC		0xC0
#define	SBP2_ST_SRC_SHIFT	6
#define	SBP2_ST_RESP		0x30
#define	SBP2_ST_RESP_SHIFT	4
#define	SBP2_ST_DEAD		0x08
#define	SBP2_ST_LEN		0x07

/* status origins */
#define	SBP2_ST_SRC_ORB		0x00
#define	SBP2_ST_SRC_ORB_NULL	0x40
#define	SBP2_ST_SRC_UNSOLICITED	0x80

/* response status */
#define	SBP2_ST_RESP_COMPLETE	0x00	/* REQUEST COMPLETE */
#define	SBP2_ST_RESP_TRANFAIL	0x10	/* TRANSPORT FAILURE */
#define	SBP2_ST_RESP_ILLREQ	0x20	/* ILLEGAL REQUEST */
#define	SBP2_ST_RESP_VENDOR	0x30	/* VENDOR DEPENDENT */

/* SBP status, when response status is REQUEST COMPLETE */
#define	SBP2_ST_SBP_NOINFO	0x00	/* no additional info */
#define	SBP2_ST_SBP_REQ_TYPE	0x01	/* req type not supported */
#define	SBP2_ST_SBP_SPD		0x02	/* speed not supported */
#define	SBP2_ST_SBP_PSZ		0x03	/* page size not supported */
#define	SBP2_ST_SBP_ACCESS	0x04	/* access denied */
#define	SBP2_ST_SBP_LUN		0x05	/* LUN not supported */
#define	SBP2_ST_SBP_PAYLOAD	0x06	/* max payload too small */
#define	SBP2_ST_SBP_RSRC	0x08	/* resources unavailable */
#define	SBP2_ST_SBP_FUNC	0x09	/* function rejected */
#define	SBP2_ST_SBP_LOGIN_ID	0x0A	/* login ID not recognized */
#define	SBP2_ST_SBP_DUMMY_ORB	0x0B	/* dummy ORB completed */
#define	SBP2_ST_SBP_REQ_ABORT	0x0C	/* request aborted */
#define	SBP2_ST_SBP_UNSPEC	0xFF	/* unspecified error */

/* SBP status, when response status is TRANSPORT FAILURE */
#define	SBP2_ST_SBP_OBJ		0xC0	/* failed object */
#define	SBP2_ST_SBP_ERR		0x0F	/* serial bus error */

/* objects */
#define	SBP2_ST_SBP_OBJ_ORB	0x00	/* ORB */
#define	SBP2_ST_SBP_OBJ_DATA	0x40	/* data buffer */
#define	SBP2_ST_SBP_OBJ_PT	0x80	/* page table */
#define	SBP2_ST_SBP_OBJ_UNSPEC	0xC0	/* unable to specify */

/* serial bus errors */
#define	SBP2_ST_SBP_ERR_ACK		0x00	/* missing ackknowledge */
#define	SBP2_ST_SBP_ERR_TIMEOUT		0x02	/* time-out error */
#define	SBP2_ST_SBP_ERR_ACK_BUSY_X	0x04	/* ack_busy_X */
#define	SBP2_ST_SBP_ERR_ACK_BUSY_A	0x05	/* ack_busy_A */
#define	SBP2_ST_SBP_ERR_ACK_BUSY_B	0x06	/* ack_busy_B */
#define	SBP2_ST_SBP_ERR_TARDY		0x0B	/* tardy limit exceeded */
#define	SBP2_ST_SBP_ERR_CONFLICT	0x0C	/* conflict error */
#define	SBP2_ST_SBP_ERR_DATA		0x0D	/* data error */
#define	SBP2_ST_SBP_ERR_TYPE		0x0E	/* type error */
#define	SBP2_ST_SBP_ERR_ADDR		0x0F	/* address error */


/* command block agent registers (ref: 6.4) */
#define	SBP2_AGENT_STATE_OFFSET		0x00
#define	SBP2_AGENT_RESET_OFFSET		0x04
#define	SBP2_ORB_POINTER_OFFSET		0x08
#define	SBP2_DOORBELL_OFFSET		0x10
#define	SBP2_UNSOLICITED_STATUS_ENABLE_OFFSET 0x14

/* agent states */
#define	SBP2_AGENT_STATE_RESET		0
#define	SBP2_AGENT_STATE_ACTIVE		1
#define	SBP2_AGENT_STATE_SUSPENDED	2
#define	SBP2_AGENT_STATE_DEAD		3

/* page table parameters */
#define	SBP2_PT_ENT_SIZE		8		/* table entry size */
#define	SBP2_PT_SEGSIZE_MAX		(65536 - 8)	/* max segment size */

/* page table element for unrestricted page table (ref: 5.2.1) */
typedef struct sbp2_pt_unrestricted {
	uint16_t	pt_seg_len;	/* segment length */
	uint16_t	pt_seg_base_hi;	/* segment base hi */
	uint32_t	pt_seg_base_lo;	/* segment base lo */
} sbp2_pt_unrestricted_t;

/*
 * Configuration ROM
 *
 * key types & values
 */
#define	SBP2_KT_MGT_AGENT		1
#define	SBP2_KV_MGT_AGENT		0x14
#define	SBP2_KT_LUN			0
#define	SBP2_KV_LUN			0x14
#define	SBP2_KT_UNCHAR			0
#define	SBP2_KV_UNCHAR			0x3A

/* Logical_Unit_Number */
#define	SBP2_LUN_TYPE			0x001F0000	/* device_type */
#define	SBP2_LUN_TYPE_SHIFT		16
#define	SBP2_LUN_NUM			0x0000FFFF	/* lun */

/* Unit_Characteristics */
#define	SBP2_UNCHAR_MOT			0x0000FF00	/* mgt_ORB_timeout */
#define	SBP2_UNCHAR_MOT_SHIFT		8
#define	SBP2_UNCHAR_ORB_SIZE		0x000000FF	/* ORB_size */


_NOTE(SCHEME_PROTECTS_DATA("unique per ORB", { sbp2_dummy_orb sbp2_cmd_orb
    sbp2_mgt_orb sbp2_login_orb sbp2_login_resp sbp2_qlogins_orb
    sbp2_reconnect_orb sbp2_logout_orb sbp2_task_mgt_orb sbp2_status
    sbp2_pt_unrestricted }))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBP2_DEFS_H */
