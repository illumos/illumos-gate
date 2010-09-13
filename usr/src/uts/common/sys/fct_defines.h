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
#ifndef	_FCT_DEFINES_H
#define	_FCT_DEFINES_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef	stmf_status_t	fct_status_t;
/*
 * Error codes
 */
#define	FCT_SUCCESS		STMF_SUCCESS
#define	FCT_FAILURE		STMF_TARGET_FAILURE
#define	FCT_FCA_FAILURE		(FCT_FAILURE | (uint64_t)0x0100000000000000)
#define	FCT_BUSY		STMF_BUSY
#define	FCT_ABORT_SUCCESS	STMF_ABORT_SUCCESS
#define	FCT_ABORTED		STMF_ABORTED
#define	FCT_NOT_FOUND		STMF_NOT_FOUND
#define	FCT_TIMEOUT		STMF_TIMEOUT

#define	FCT_WORKER_STUCK	(FCT_FAILURE | STMF_FSC(1))
#define	FCT_ALLOC_FAILURE	(FCT_FAILURE | STMF_FSC(2))
#define	FCT_LOCAL_PORT_OFFLINE	(FCT_FAILURE | STMF_FSC(3))
#define	FCT_NO_XCHG_RESOURCE	(FCT_FAILURE | STMF_FSC(4))
#define	FCT_NOT_LOGGED_IN	(FCT_FAILURE | STMF_FSC(5))
#define	FCT_ABTS_RECEIVED	(FCT_FAILURE | STMF_FSC(6))
#define	FCT_RPORT_SENT_REJECT	(FCT_FAILURE | STMF_FSC(7))

#define	FCT_REJECT_STATUS(reason, expln)	\
	(FCT_RPORT_SENT_REJECT | (((uint64_t)(reason)) << 8) | \
	    ((uint64_t)(expln)))

/*
 * Event codes
 */
#define	FCT_EVENT_LINK_UP	0x01
#define	FCT_EVENT_LINK_DOWN	0x02
#define	FCT_EVENT_LINK_RESET	0x03
#define	FCT_EVENT_ADAPTER_FATAL	0x04

/*
 * ELS OP codes
 */
#define	ELS_OP_LSRJT		0x01
#define	ELS_OP_ACC		0x02
#define	ELS_OP_PLOGI		0x03
#define	ELS_OP_FLOGI		0x04
#define	ELS_OP_LOGO		0x05
#define	ELS_OP_ABTX		0x06
#define	ELS_OP_RLS		0x0f
#define	ELS_OP_ECHO		0x10
#define	ELS_OP_REC		0x13
#define	ELS_OP_SRR		0x14
#define	ELS_OP_PRLI		0x20
#define	ELS_OP_PRLO		0x21
#define	ELS_OP_SCN		0x22
#define	ELS_OP_TPRLO		0x24
#define	ELS_OP_PDISC		0x50
#define	ELS_OP_ADISC		0x52
#define	ELS_OP_RSCN		0x61
#define	ELS_OP_SCR		0x62
#define	ELS_OP_RNID		0x78

/*
 * BLS replies
 */
#define	BLS_OP_BA_ACC		0x84
#define	BLS_OP_BA_RJT		0x85

/*
 * Name Service Command Codes
 */
#define	NS_GA_NXT		0x0100	/* Get All next */
#define	NS_GPN_ID		0x0112	/* Get Port Name */
#define	NS_GNN_ID		0x0113	/* Get Node Name */
#define	NS_GCS_ID		0x0114	/* Get Class Of service */
#define	NS_GFT_ID		0x0117	/* Get FC-4 Types */
#define	NS_GSPN_ID		0x0118	/* Get Sym Port name */
#define	NS_GPT_ID		0x011A	/* Get Port Type */
#define	NS_GID_PN		0x0121	/* Get port id for PN */
#define	NS_GID_NN		0x0131	/* Get port id for NN */
#define	NS_GIP_NN		0x0135	/* Get IP address */
#define	NS_GIPA_NN		0x0136	/* Get I.P.A */
#define	NS_GSNN_NN		0x0139	/* Get Sym Node name */
#define	NS_GNN_IP		0x0153	/* Get Node name for IP */
#define	NS_GIPA_IP		0x0156	/* Get I.P.A for IP */
#define	NS_GID_FT		0x0171	/* Get port Id for FC-4 type */
#define	NS_GID_PT		0x01A1	/* Get port Id for type */
#define	NS_RPN_ID		0x0212	/* Reg port name */
#define	NS_RNN_ID		0x0213	/* Reg node name */
#define	NS_RCS_ID		0x0214	/* Reg C.O.S */
#define	NS_RFT_ID		0x0217	/* Reg FC-4 Types */
#define	NS_RSPN_ID		0x0218	/* Reg Sym Port name */
#define	NS_RPT_ID		0x021A	/* Reg Port Type */
#define	NS_RIP_NN		0x0235	/* Reg I.P address */
#define	NS_RIPA_NN		0x0236	/* Reg I.P.A */
#define	NS_RSNN_NN		0x0239	/* Reg Sym Node name */
#define	NS_DA_ID		0x0300	/* De-Register all */

#define	CT_OP_RJT		0x8001
#define	CT_OP_ACC		0x8002

/*
 * PRLI bits
 */
#define	PRLI_BIT_WRITE_XRDY_DISABLED		0x00000001
#define	PRLI_BIT_READ_XRDY_DISABLED		0x00000002
#define	PRLI_BIT_TARGET_FUNCTION		0x00000010
#define	PRLI_BIT_INITIATOR_FUNCTION		0x00000020
#define	PRLI_BIT_DATA_OVERLAY_ALLOWED		0x00000040
#define	PRLI_BIT_FCP_CONF_ALLOWED		0x00000080
#define	PRLI_BIT_RETRY				0x00000100
#define	PRLI_BIT_TASK_RETRY_IDENT_REQUESTED	0x00000200
#define	PRLI_BIT_REC_SUPPORT			0x00000400

#define	FC_NS_CLASSF		0x01
#define	FC_NS_CLASS1		0x02
#define	FC_NS_CLASS2		0x04
#define	FC_NS_CLASS3		0x08
#define	FC_NS_CLASS4		0x10
#define	FC_NS_CLASS5		0x20
#define	FC_NS_CLASS6		0x40

/*
 * SCR function code
 */
#define	FC_SCR_FABRIC_REGISTRATION	0x01
#define	FC_SCR_NPORT_REGISTRATION	0x02
#define	FC_SCR_FULL_REGISTRATION	0x03
#define	FC_SCR_CLEAR_REGISTRATION	0xFF

/*
 * FCP_CNTL bits
 */
#define	FCP_CNTL_TASK_ATTR(fcp_cntl)	((((uint32_t)(fcp_cntl)) >> 16) & 7)
#define	TASK_ATTR_SIMPLE_Q		0
#define	TASK_ATTR_HEAD_OF_Q		1
#define	TASK_ATTR_ORDERED_Q		2
#define	TASK_ATTR_ACA_Q			4
#define	TASK_ATTR_UNTAGGED		5
#define	FCP_CNTL_IS_TASK_MGMT(fcp_cntl)	(((uint32_t)(fcp_cntl)) & 0xff00)
#define	FCP_CNTL_TERMINATE_TASK		0x8000
#define	FCP_CNTL_CLEAR_ACA		0x4000
#define	FCP_CNTL_TARGET_RESET		0x2000
#define	FCP_CNTL_LUN_RESET		0x1000
#define	FCP_CNTL_CLEAR_TASK_SET		0x0400
#define	FCP_CNTL_ABORT_TASK_SET		0x0200
#define	FCP_CNTL_READ_DATA		0x2
#define	FCP_CNTL_WRITE_DATA		0x1

/*
 * SCSI STATUS BITS
 */
#define	FCP_BIDI_RESP		0x8000
#define	FCP_BIDI_UNDER		0x4000
#define	FCP_BIDI_OVER		0x2000
#define	FCP_CONF_REQ		0x1000
#define	FCP_RESID_UNDER		0x0800
#define	FCP_RESID_OVER		0x0400
#define	FCP_SNS_LEN_VALID	0x0200
#define	FCP_RESP_LEN_VALID	0x0100

/*
 * Well known addresses ...
 */
#define	NPORT_ID_DOM_CTLR_START	0xFFFC01
#define	NPORT_ID_DOM_CTLR_END	0xFFFCFE

#define	FS_GENERAL_MULTICAST	0xFFFFF7
#define	FS_WELL_KNOWN_MULTICAST	0xFFFFF8
#define	FS_HUNT_GROUP		0xFFFFF9
#define	FS_MANAGEMENT_SERVER	0xFFFFFA
#define	FS_TIME_SERVER		0xFFFFFB
#define	FS_NAME_SERVER		0xFFFFFC
#define	FS_FABRIC_CONTROLLER	0xFFFFFD
#define	FS_FABRIC_F_PORT	0xFFFFFE
#define	FS_BROADCAST		0xFFFFFF

#define	FC_WELL_KNOWN_START	0xFFFFF0
#define	FC_WELL_KNOWN_END	0xFFFFFF
#define	FC_WELL_KNOWN_ADDR(x)	\
	((((x) >= FC_WELL_KNOWN_START) && ((x) <= FC_WELL_KNOWN_END)) ||\
	(((x) >= NPORT_ID_DOM_CTLR_START) && ((x) <= NPORT_ID_DOM_CTLR_END)))

#define	FC_WWN_LEN		8
/*
 * NB: FC_WWN_BUFLEN should be 64-bit aligned (divisible by 8).
 */
#define	FC_WWN_BUFLEN		(FC_WWN_LEN * 3)
#define	FC_WWN_STRLEN		(FC_WWN_BUFLEN - 1)	/* add trailing null */

struct fct_cmd;
struct fct_local_port;
struct fct_els;
struct fct_link_info;
struct fct_flogi_xchg;
struct fct_dbuf_store;

#ifdef	__cplusplus
}
#endif

#endif /* _FCT_DEFINES_H */
