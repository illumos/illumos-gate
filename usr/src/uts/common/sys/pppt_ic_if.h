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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _SYS_PPPT_IC_IF_H
#define	_SYS_PPPT_IC_IF_H

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ALUA messaging and interconnect API.
 */

/*
 * Message type.
 */
typedef enum {
	STMF_ICM_REGISTER_PROXY_PORT = 0,
	STMF_ICM_DEREGISTER_PROXY_PORT,
	STMF_ICM_REGISTER_LUN,
	STMF_ICM_DEREGISTER_LUN,
	STMF_ICM_SCSI_CMD,
	STMF_ICM_SCSI_DATA,
	STMF_ICM_SCSI_DATA_XFER_DONE,
	STMF_ICM_SCSI_STATUS,
	STMF_ICM_R2T,
	STMF_ICM_STATUS,
	STMF_ICM_SESSION_CREATE,
	STMF_ICM_SESSION_DESTROY,
	STMF_ICM_ECHO_REQUEST,
	STMF_ICM_ECHO_REPLY,
	STMF_ICM_LUN_ACTIVE,
	STMF_ICM_MAX_MSG_TYPE
} stmf_ic_msg_type_t;

/*
 * Message id: uniquely identifies a message.
 * This need not be a sequence number since we don't depend on
 * messages being delivered in sequence.
 */
typedef uint64_t stmf_ic_msgid_t;

/*
 * IC message.  This is a container for the various specific message types.
 *
 * Note that the message contains a pointer to an nvlist.  This pointer
 * is valid only in the case of messages which are unmarshaled from
 * nvlists.  In that case, it's important to retain a pointer to the nvlist,
 * since the message and the nvlist share data in the case of strings
 * and array elements, and data in the message may be invalid if used
 * after the nvlist is freed.
 */
typedef struct stmf_ic_msg {
	stmf_ic_msg_type_t icm_msg_type;
	stmf_ic_msgid_t icm_msgid;
	nvlist_t *icm_nvlist;		/* nvlist associated with the msg */
	void *icm_msg;			/* ptr to the specific msg */
} stmf_ic_msg_t;

/*
 * Register port message.
 */
typedef struct {
	scsi_devid_desc_t 	*icrp_port_id;
	uint16_t 		icrp_relative_port_id;
	/* opaque callback data */
	uint16_t		icrp_cb_arg_len;
	uint8_t			*icrp_cb_arg;
} stmf_ic_reg_port_msg_t;

/*
 * Deregister port message.
 */
typedef struct {
	scsi_devid_desc_t 	*icdp_port_id;
	/* opaque callback data */
	uint16_t		icdp_cb_arg_len;
	uint8_t			*icdp_cb_arg;
} stmf_ic_dereg_port_msg_t;

/*
 * Register/deregister lun message.
 */
typedef struct {
	uint8_t 		icrl_lun_id[16];
	char			*icrl_lu_provider_name;
	/* opaque callback data */
	uint16_t		icrl_cb_arg_len;
	uint8_t			*icrl_cb_arg;
} stmf_ic_reg_dereg_lun_msg_t;

/*
 * SCSI cmd msg.
 */
typedef struct {
	stmf_ic_msgid_t		icsc_task_msgid;
	scsi_devid_desc_t	*icsc_ini_devid;
	scsi_devid_desc_t	*icsc_tgt_devid;
	stmf_remote_port_t	*icsc_rport;
	uint8_t 		icsc_lun_id[16];
	/*
	 * fields from scsi_task_t
	 */
	uint64_t	icsc_session_id;
	uint8_t		icsc_task_lun_no[8];
	uint32_t	icsc_task_expected_xfer_length;
	uint16_t	icsc_task_cdb_length;
	uint8_t 	*icsc_task_cdb;
	uint8_t		icsc_task_flags;	/* See def. for task flags */
	uint8_t		icsc_task_priority;	/* As per SAM-3 */
	uint8_t		icsc_task_mgmt_function;	/* if is a TM req */
	uint32_t	icsc_immed_data_len;
	uint8_t		*icsc_immed_data;
} stmf_ic_scsi_cmd_msg_t;

/*
 * SCSI data message.
 */
typedef struct {
	stmf_ic_msgid_t icsd_task_msgid;	/* matches msgid of cmd */
	uint64_t icsd_session_id;
	uint8_t icsd_lun_id[16];
	uint64_t icsd_data_len;
	uint8_t *icsd_data;
} stmf_ic_scsi_data_msg_t;

/*
 * SCSI data xfer done msg
 */
typedef struct {
	stmf_ic_msgid_t icsx_task_msgid;	/* matches msgid of cmd */
	uint64_t icsx_session_id;
	stmf_status_t	icsx_status;
} stmf_ic_scsi_data_xfer_done_msg_t;

/*
 * SCSI status msg.
 */
typedef struct {
	stmf_ic_msgid_t icss_task_msgid;	/* matches msgid of cmd */
	uint64_t icss_session_id;
	uint8_t icss_lun_id[16];
	uint8_t icss_response;		/* was command processed? */
	uint8_t icss_status;
	uint8_t	icss_flags;		/* TASK_SCTRL_OVER, TASK_SCTRL_UNDER */
	uint32_t icss_resid;
	uint8_t	icss_sense_len;
	uint8_t	*icss_sense;
} stmf_ic_scsi_status_msg_t;

/*
 * Ready to transfer (r2t) msg.
 */
typedef struct {
	stmf_ic_msgid_t icrt_task_msgid;	/* matches msgid of cmd */
	uint64_t icrt_session_id;
	uint32_t icrt_offset;
	uint32_t icrt_length;
} stmf_ic_r2t_msg_t;

/*
 * Status message: sent in response to messages other than SCSI messages.
 */
typedef struct {
	stmf_ic_msg_type_t ics_msg_type;	/* msg type rpting status on */
	stmf_ic_msgid_t ics_msgid;		/* msgid reporting status on */
	stmf_status_t ics_status;
} stmf_ic_status_msg_t;

/*
 * Session create/destroy message.
 */
typedef struct {
	uint64_t		icscd_session_id;
	scsi_devid_desc_t	*icscd_ini_devid;
	scsi_devid_desc_t	*icscd_tgt_devid;
	stmf_remote_port_t	*icscd_rport;
} stmf_ic_session_create_destroy_msg_t;

/*
 * Echo request/reply message
 */
typedef struct {
	uint8_t			*icerr_data;
	uint32_t		icerr_datalen;
} stmf_ic_echo_request_reply_msg_t;

typedef enum {
	STMF_IC_MSG_SUCCESS = 0,
	STMF_IC_MSG_IC_DOWN,
	STMF_IC_MSG_TIMED_OUT,
	STMF_IC_MSG_INTERNAL_ERROR
} stmf_ic_msg_status_t;

/*
 * Function prototypes.
 *
 * Note: Functions which are exported to other modules must have a function
 * typedef and a prototype; the function type definition is used by
 * the other module to import the symbol using ddi_modsym().
 */

void stmf_ic_ioctl_cmd(void *ibuf, uint32_t ibuf_size);

/* Allocate a register port message */
typedef
stmf_ic_msg_t *(*stmf_ic_reg_port_msg_alloc_func_t)(
    scsi_devid_desc_t *port_id,
    uint16_t relative_port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_reg_port_msg_alloc(
    scsi_devid_desc_t *port_id,
    uint16_t relative_port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

/* Allocate a deregister port message */
typedef
stmf_ic_msg_t *(*stmf_ic_dereg_port_msg_alloc_func_t)(
    scsi_devid_desc_t *port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_dereg_port_msg_alloc(
    scsi_devid_desc_t *port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);


/* Allocate a register lun message */
typedef
stmf_ic_msg_t *(*stmf_ic_reg_lun_msg_alloc_func_t)(
    uint8_t *icrl_lun_id,	/* should be 16 bytes */
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_reg_lun_msg_alloc(
    uint8_t *icrl_lun_id,	/* should be 16 bytes */
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

/* Allocate a lun active message */
typedef
stmf_ic_msg_t *(*stmf_ic_lun_active_msg_alloc_func_t)(
    uint8_t *icrl_lun_id,	/* should be 16 bytes */
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_lun_active_msg_alloc(
    uint8_t *icrl_lun_id,	/* should be 16 bytes */
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

/* Allocate a deregister lun message */
typedef
stmf_ic_msg_t *(*stmf_ic_dereg_lun_msg_alloc_func_t)(
    uint8_t *icrl_lun_id,	/* should be 16 bytes */
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_dereg_lun_msg_alloc(
    uint8_t *icrl_lun_id,	/* should be 16 bytes */
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid);

/* Allocate a scsi cmd message */
typedef
stmf_ic_msg_t *(*stmf_ic_scsi_cmd_msg_alloc_func_t)(
    stmf_ic_msgid_t 	task_msgid,
    scsi_task_t 	*scsi_task,
    uint32_t		immed_data_len,
    uint8_t		*immed_data,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_scsi_cmd_msg_alloc(
    stmf_ic_msgid_t 	task_msgid,
    scsi_task_t 	*scsi_task,
    uint32_t		immed_data_len,
    uint8_t		*immed_data,
    stmf_ic_msgid_t msgid);

/* Allocate a scsi data message */
typedef
stmf_ic_msg_t *(*stmf_ic_scsi_data_msg_alloc_func_t)(
    stmf_ic_msgid_t 	task_msgid,
    uint64_t		session_id,
    uint8_t		*lun_id,
    uint64_t		data_len,
    uint8_t		*data,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_scsi_data_msg_alloc(
    stmf_ic_msgid_t 	task_msgid,
    uint64_t		session_id,
    uint8_t		*lun_id,
    uint64_t		data_len,
    uint8_t		*data,
    stmf_ic_msgid_t msgid);

/* Allocate a scsi transfer done message */
typedef
stmf_ic_msg_t *(*stmf_ic_scsi_data_xfer_done_msg_alloc_func_t)(
    stmf_ic_msgid_t 	task_msgid,
    uint64_t		session_id,
    stmf_status_t	status,
    stmf_ic_msgid_t	msgid);

stmf_ic_msg_t *stmf_ic_scsi_data_xfer_done_msg_alloc(
    stmf_ic_msgid_t 	task_msgid,
    uint64_t		session_id,
    stmf_status_t	status,
    stmf_ic_msgid_t	msgid);


/* Allocate a scsi status message */
stmf_ic_msg_t *stmf_ic_scsi_status_msg_alloc(
    stmf_ic_msgid_t 	task_msgid,
    uint64_t		session_id,
    uint8_t		*lun_id,
    uint8_t		response,		/* was command processed? */
    uint8_t		status,
    uint8_t		flags,
    uint32_t 		resid,
    uint8_t		sense_len,
    uint8_t		*sense,
    stmf_ic_msgid_t msgid);	/* must match corresponding scsi cmd msgid */


/* Allocate a scsi ready to transfer (r2t) message */
stmf_ic_msg_t *stmf_ic_r2t_msg_alloc(
    stmf_ic_msgid_t 	task_msgid,
    uint64_t		session_id,
    uint32_t		offset,
    uint32_t		length,
    stmf_ic_msgid_t msgid);	/* must match corresponding scsi cmd msgid */

/* Allocate a status message */
stmf_ic_msg_t *stmf_ic_status_msg_alloc(
    stmf_status_t	status,
    stmf_ic_msg_type_t	msg_type,	/* msg type reporting status on */
    stmf_ic_msgid_t 	msgid);		/* id of msg reporting status on */

/* Allocate a session create message */
typedef
stmf_ic_msg_t *(*stmf_ic_session_create_msg_alloc_func_t)(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_session_create_msg_alloc(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid);

/* Allocate a session destroy message */
typedef
stmf_ic_msg_t *(*stmf_ic_session_destroy_msg_alloc_func_t)(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid);

stmf_ic_msg_t *stmf_ic_session_destroy_msg_alloc(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid);

/* Allocate an echo request message */
stmf_ic_msg_t *stmf_ic_echo_request_msg_alloc(
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid);

/* Allocate an echo reply message */
stmf_ic_msg_t *stmf_ic_echo_reply_msg_alloc(
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid);

/*
 * Free a msg.
 */
typedef void (*stmf_ic_msg_free_func_t)(stmf_ic_msg_t *msg);
void stmf_ic_msg_free(stmf_ic_msg_t *msg);

/*
 * Send a message out over the interconnect, in the process marshalling
 * the arguments.
 *
 * After being sent, the message is freed by tx_msg().
 */
typedef stmf_ic_msg_status_t (*stmf_ic_tx_msg_func_t)(stmf_ic_msg_t *msg);
stmf_ic_msg_status_t stmf_ic_tx_msg(stmf_ic_msg_t *msg);

/*
 * This is a low-level upcall which is called when a message has
 * been received on the interconnect.
 */
void stmf_ic_rx_msg(char *buf, size_t len);

stmf_status_t stmf_msg_rx(stmf_ic_msg_t *msg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PPPT_IC_IF_H */
