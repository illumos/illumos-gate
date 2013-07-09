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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */
#ifndef	_STMF_H
#define	_STMF_H

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum stmf_struct_id {
	STMF_STRUCT_LU_PROVIDER = 1,
	STMF_STRUCT_PORT_PROVIDER,
	STMF_STRUCT_STMF_LOCAL_PORT,
	STMF_STRUCT_STMF_LU,
	STMF_STRUCT_SCSI_SESSION,
	STMF_STRUCT_SCSI_TASK,
	STMF_STRUCT_DATA_BUF,
	STMF_STRUCT_DBUF_STORE,
	STMF_MAX_STRUCT_IDS
} stmf_struct_id_t;

/*
 * Provider callback commands
 */
#define	STMF_PROVIDER_DATA_UPDATED	0x01

/*
 * Provider callback flags
 */
#define	STMF_PCB_STMF_ONLINING		0x0001
#define	STMF_PCB_PREG_COMPLETE		0x0002

typedef void *data_seg_handle_t;
#define	STMF_MAX_LU_CACHE_NTASKS 16

#define	STMF_NO_HANDLE	0xffffffff

#define	COMPANY_ID_NONE			0xFFFFFFFF
#define	COMPANY_ID_SUN			0x00144F

/*
 * The scatter/gather list buffer format is used in 2 different
 * contexts within stmf:
 * 1) supplied by the port provider that the LU provider uses to exchange
 *    data with the backing store.
 * 2) supplied by the LU provider that the port provider uses exchange
 *    data with the host initiator.
 * The second format is optionally supported by the port provided as
 * indicated by the command task flags.
 */

typedef struct stmf_sglist_ent {
	uint32_t	seg_length;
	uint8_t		*seg_addr;
} stmf_sglist_ent_t;

typedef struct stmf_data_buf {
	void		*db_stmf_private;
	void		*db_port_private;
	void		*db_lu_private;
	uint32_t	db_buf_size;	/* Total size of this buffer */
	uint32_t	db_data_size;	/* Intended xfer size of this buffer */
	uint32_t	db_relative_offset;
	uint16_t	db_sglist_length;
	uint16_t	db_flags;	/* Direction, auto status etc */
	stmf_status_t	db_xfer_status;
	uint8_t		db_handle;	/* To track parallel buffers */
	hrtime_t	db_xfer_start_timestamp;
	stmf_sglist_ent_t db_sglist[1];	/* PP scatter/gather list */
} stmf_data_buf_t;

/*
 * db_flags
 */
#define	DB_DIRECTION_TO_RPORT		0x0001
#define	DB_DIRECTION_FROM_RPORT		0x0002
#define	DB_SEND_STATUS_GOOD		0x0004
#define	DB_STATUS_GOOD_SENT		0x0008
#define	DB_DONT_CACHE			0x0010
#define	DB_DONT_REUSE			0x0020
#define	DB_LU_DATA_BUF			0x0040
#define	DB_LPORT_XFER_ACTIVE		0x8000

typedef struct scsi_task {
	void		*task_stmf_private;
	void		*task_port_private;

	void		*task_lu_private;
	struct stmf_scsi_session *task_session;
	struct stmf_local_port *task_lport;
	struct stmf_lu	*task_lu;
	void		*task_lu_itl_handle;	/* Assigned by LU */

	/* CMD information from initiator */
	uint8_t		task_lun_no[8];
	uint8_t		task_flags;		/* See def. for task flags */
	uint8_t		task_priority;		/* As per SAM-3 */
	uint8_t		task_mgmt_function;	/* If this is a TM request */
	uint8_t		task_max_nbufs;
	uint8_t		task_cur_nbufs;
	uint8_t		task_csn_size;		/* cmd seq no size in bits */
	uint16_t	task_additional_flags;
	uint32_t	task_cmd_seq_no;
	uint32_t	task_expected_xfer_length;
	uint32_t	task_timeout;		/* In seconds */
	uint16_t	task_ext_id;
	uint16_t	task_cdb_length;
	uint8_t		*task_cdb;

	/* Fields to manage data phase */
	uint32_t	task_cmd_xfer_length;	/* xfer len based on CDB */
	uint32_t	task_nbytes_transferred;
	uint32_t	task_max_xfer_len;	/* largest xfer allowed */
	uint32_t	task_1st_xfer_len;	/* 1st xfer hint */
	uint32_t	task_copy_threshold;	/* copy reduction threshold */


	/* Status Phase */
	stmf_status_t	task_completion_status;
	uint32_t	task_resid;
	uint8_t		task_status_ctrl;	/* See def. for status ctrl */
	uint8_t		task_scsi_status;
	uint16_t	task_sense_length;
	uint8_t		*task_sense_data;

	/* Misc. task data */
	void		*task_extended_cmd;

} scsi_task_t;

/*
 * Maximum expected transfer length.   Can also be used when the transfer
 * length is unknown when the task is allocated (e.g. SAS)
 */

#define	TASK_MAX_XFER_LENGTH	0xFFFFFFFF

/*
 * task_flags definitions.
 */
/*
 * If TF_INITIAL_BURST is set, the dbuf passed with new_task() contains
 * data from initial burst. Otherwise its just a buffer which the port
 * passed to the LU.
 */
#define	TF_INITIAL_BURST	0x80
/* Both READ_DATA and WRITE_DATA can be set for bidirectional xfers */
#define	TF_READ_DATA		0x40
#define	TF_WRITE_DATA		0x20
#define	TF_ATTR_MASK		0x07
#define	TF_ATTR_UNTAGGED	0x0
#define	TF_ATTR_SIMPLE_QUEUE	0x1
#define	TF_ATTR_ORDERED_QUEUE	0x2
#define	TF_ATTR_HEAD_OF_QUEUE	0x3
#define	TF_ATTR_ACA		0x4

/*
 * Task Management flags.
 */
#define	TM_NONE			0x00
#define	TM_ABORT_TASK		0x01
#define	TM_ABORT_TASK_SET	0x02
#define	TM_CLEAR_ACA		0x03
#define	TM_CLEAR_TASK_SET	0x04
#define	TM_LUN_RESET		0x05
#define	TM_TARGET_WARM_RESET	0x06
#define	TM_TARGET_COLD_RESET	0x07
#define	TM_TASK_REASSIGN	0x08
#define	TM_TARGET_RESET		0x09
#define	TM_QUERY_TASK		0x0A

/*
 * additional flags
 */
#define	TASK_AF_ENABLE_COMP_CONF	0x01
#define	TASK_AF_PORT_LOAD_HIGH		0x02
#define	TASK_AF_NO_EXPECTED_XFER_LENGTH	0x04
/*
 * PP sets this flag if it can process dbufs created by the LU.
 */
#define	TASK_AF_ACCEPT_LU_DBUF		0x08

/*
 * scsi_task_t extension identifiers
 */
#define	STMF_TASK_EXT_NONE		0

/*
 * max_nbufs
 */
#define	STMF_BUFS_MAX		255

/*
 * Task status ctrl
 */
#define	TASK_SCTRL_OVER		1
#define	TASK_SCTRL_UNDER	2

/*
 * The flags used by I/O flow.
 */
#define	STMF_IOF_LU_DONE		0x0001
#define	STMF_IOF_LPORT_DONE		0x0002
#define	STMF_IOF_STATS_ONLY		0x0004

/*
 * struct allocation flags
 */
#define	AF_FORCE_NOSLEEP	0x0001
#define	AF_DONTZERO		0x0002

typedef struct stmf_state_change_info {
	uint64_t	st_rflags;	/* Reason behind this change */
	char		*st_additional_info;
} stmf_state_change_info_t;

typedef struct stmf_change_status {
	stmf_status_t	st_completion_status;
	char		*st_additional_info;
} stmf_change_status_t;

/*
 * conditions causing or affecting the change.
 */
#define	STMF_RFLAG_USER_REQUEST		0x0001
#define	STMF_RFLAG_FATAL_ERROR		0x0002
#define	STMF_RFLAG_STAY_OFFLINED	0x0004
#define	STMF_RFLAG_RESET		0x0008
#define	STMF_RFLAG_COLLECT_DEBUG_DUMP	0x0010
#define	STMF_RFLAG_LU_ABORT		0x0020
#define	STMF_RFLAG_LPORT_ABORT		0x0040

#define	STMF_CHANGE_INFO_LEN		160

/*
 * cmds to stmf_abort entry point
 */
#define	STMF_QUEUE_TASK_ABORT		1
#define	STMF_REQUEUE_TASK_ABORT_LPORT	2
#define	STMF_REQUEUE_TASK_ABORT_LU	3
#define	STMF_QUEUE_ABORT_LU		4

/*
 * cmds to be used by stmf ctl
 */
#define	STMF_CMD_LU_OP			0x0100
#define	STMF_CMD_LPORT_OP		0x0200
#define	STMF_CMD_MASK			0x00ff
#define	STMF_CMD_ONLINE			0x0001
#define	STMF_CMD_OFFLINE		0x0002
#define	STMF_CMD_GET_STATUS		0x0003
#define	STMF_CMD_ONLINE_COMPLETE	0x0004
#define	STMF_CMD_OFFLINE_COMPLETE	0x0005
#define	STMF_ACK_ONLINE_COMPLETE	0x0006
#define	STMF_ACK_OFFLINE_COMPLETE	0x0007

#define	STMF_CMD_LU_ONLINE		(STMF_CMD_LU_OP | STMF_CMD_ONLINE)
#define	STMF_CMD_LU_OFFLINE		(STMF_CMD_LU_OP | STMF_CMD_OFFLINE)
#define	STMF_CMD_LPORT_ONLINE		(STMF_CMD_LPORT_OP | STMF_CMD_ONLINE)
#define	STMF_CMD_LPORT_OFFLINE		(STMF_CMD_LPORT_OP | STMF_CMD_OFFLINE)
#define	STMF_CMD_GET_LU_STATUS		(STMF_CMD_LU_OP | STMF_CMD_GET_STATUS)
#define	STMF_CMD_GET_LPORT_STATUS	\
			(STMF_CMD_LPORT_OP | STMF_CMD_GET_STATUS)
#define	STMF_CMD_LU_ONLINE_COMPLETE	\
			(STMF_CMD_LU_OP | STMF_CMD_ONLINE_COMPLETE)
#define	STMF_CMD_LPORT_ONLINE_COMPLETE	\
			(STMF_CMD_LPORT_OP | STMF_CMD_ONLINE_COMPLETE)
#define	STMF_ACK_LU_ONLINE_COMPLETE	\
			(STMF_CMD_LU_OP | STMF_ACK_ONLINE_COMPLETE)
#define	STMF_ACK_LPORT_ONLINE_COMPLETE	\
			(STMF_CMD_LPORT_OP | STMF_ACK_ONLINE_COMPLETE)
#define	STMF_CMD_LU_OFFLINE_COMPLETE	\
			(STMF_CMD_LU_OP | STMF_CMD_OFFLINE_COMPLETE)
#define	STMF_CMD_LPORT_OFFLINE_COMPLETE	\
			(STMF_CMD_LPORT_OP | STMF_CMD_OFFLINE_COMPLETE)
#define	STMF_ACK_LU_OFFLINE_COMPLETE	\
			(STMF_CMD_LU_OP | STMF_ACK_OFFLINE_COMPLETE)
#define	STMF_ACK_LPORT_OFFLINE_COMPLETE	\
			(STMF_CMD_LPORT_OP | STMF_ACK_OFFLINE_COMPLETE)
/*
 * For LPORTs and LUs to create their own ctl cmds which dont
 * conflict with stmf ctl cmds.
 */
#define	STMF_LPORT_CTL_CMDS		0x1000
#define	STMF_LU_CTL_CMDS		0x2000

/*
 * Commands for various info routines.
 */
/* Command classifiers */
#define	SI_LPORT		0x1000000
#define	SI_STMF			0x2000000
#define	SI_LU			0x4000000
#define	SI_LPORT_FC		0x0000000
#define	SI_LPORT_ISCSI		0x0010000
#define	SI_LPORT_SAS		0x0020000
#define	SI_STMF_LU		0x0010000
#define	SI_STMF_LPORT		0x0020000

#define	SI_GET_CLASS(v)		((v) & 0xFF000000)
#define	SI_GET_SUBCLASS(v)	((v) & 0x00FF0000)

/* Commands for LPORT info routines */
/* XXX - Implement these. */
#if 0
#define	SI_LPORT_FC_PORTINFO		(SI_LPORT | SI_LPORT_FC | 1)
#define	SI_RPORT_FC_PORTINFO		(SI_LPORT | SI_LPORT_FC | 2)
#endif

/*
 * Events
 */
#define	STMF_EVENT_ALL			((int)-1)
#define	LPORT_EVENT_INITIAL_LUN_MAPPED	0

/*
 * This needs to go into common/ddi/sunddi.h
 */
#define	DDI_NT_STMF		"ddi_scsi_target:framework"
#define	DDI_NT_STMF_LP		"ddi_scsi_target:lu_provider"
#define	DDI_NT_STMF_PP		"ddi_scsi_target:port_provider"

/*
 * VPD page bits.
 */
#define	STMF_VPD_LU_ID		0x01
#define	STMF_VPD_TARGET_ID	0x02
#define	STMF_VPD_TP_GROUP	0x04
#define	STMF_VPD_RELATIVE_TP_ID	0x08

/*
 * Common macros to simplify coding
 */
#define	STMF_SEC2TICK(x_sec)	(drv_usectohz((x_sec) * 1000000))

void stmf_trace(caddr_t ident, const char *fmt, ...);
void *stmf_alloc(stmf_struct_id_t sid, int additional_size, int alloc_flags);
void stmf_free(void *struct_ptr);
struct scsi_task *stmf_task_alloc(struct stmf_local_port *lport,
    struct stmf_scsi_session *ss, uint8_t *lun, uint16_t cdb_length,
    uint16_t ext_id);
void stmf_post_task(scsi_task_t *task, stmf_data_buf_t *dbuf);
stmf_data_buf_t *stmf_alloc_dbuf(scsi_task_t *task, uint32_t size,
    uint32_t *pminsize, uint32_t flags);
void stmf_free_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf);
stmf_status_t stmf_setup_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t flags);
void stmf_teardown_dbuf(scsi_task_t *task, stmf_data_buf_t *dbuf);
stmf_status_t stmf_xfer_data(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t ioflags);
stmf_status_t stmf_send_scsi_status(scsi_task_t *task, uint32_t ioflags);
void stmf_data_xfer_done(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t iof);
void stmf_send_status_done(scsi_task_t *task, stmf_status_t s, uint32_t iof);
void stmf_task_lu_done(scsi_task_t *task);
void stmf_abort(int abort_cmd, scsi_task_t *task, stmf_status_t s, void *arg);
void stmf_task_lu_aborted(scsi_task_t *task, stmf_status_t s, uint32_t iof);
void stmf_task_lport_aborted(scsi_task_t *task, stmf_status_t s, uint32_t iof);
stmf_status_t stmf_task_poll_lu(scsi_task_t *task, uint32_t timeout);
stmf_status_t stmf_task_poll_lport(scsi_task_t *task, uint32_t timeout);
stmf_status_t stmf_ctl(int cmd, void *obj, void *arg);
stmf_status_t stmf_register_itl_handle(struct stmf_lu *lu, uint8_t *lun,
    struct stmf_scsi_session *ss, uint64_t session_id, void *itl_handle);
stmf_status_t stmf_deregister_all_lu_itl_handles(struct stmf_lu *lu);
stmf_status_t stmf_get_itl_handle(struct stmf_lu *lu, uint8_t *lun,
    struct stmf_scsi_session *ss, uint64_t session_id, void **itl_handle_retp);
stmf_data_buf_t *stmf_handle_to_buf(scsi_task_t *task, uint8_t h);
stmf_status_t stmf_lu_add_event(struct stmf_lu *lu, int eventid);
stmf_status_t stmf_lu_remove_event(struct stmf_lu *lu, int eventid);
stmf_status_t stmf_lport_add_event(struct stmf_local_port *lport, int eventid);
stmf_status_t stmf_lport_remove_event(struct stmf_local_port *lport,
    int eventid);
void stmf_wwn_to_devid_desc(struct scsi_devid_desc *sdid, uint8_t *wwn,
    uint8_t protocol_id);
stmf_status_t stmf_scsilib_uniq_lu_id(uint32_t company_id,
    struct scsi_devid_desc *lu_id);
stmf_status_t stmf_scsilib_uniq_lu_id2(uint32_t company_id, uint32_t host_id,
    struct scsi_devid_desc *lu_id);
void stmf_scsilib_send_status(scsi_task_t *task, uint8_t st, uint32_t saa);
uint32_t stmf_scsilib_prepare_vpd_page83(scsi_task_t *task, uint8_t *page,
		uint32_t page_len, uint8_t byte0, uint32_t vpd_mask);
uint16_t stmf_scsilib_get_lport_rtid(struct scsi_devid_desc *devid);
struct scsi_devid_desc *stmf_scsilib_get_devid_desc(uint16_t rtpid);
void stmf_scsilib_handle_report_tpgs(scsi_task_t *task, stmf_data_buf_t *dbuf);
void stmf_scsilib_handle_task_mgmt(scsi_task_t *task);

struct stmf_remote_port *stmf_scsilib_devid_to_remote_port(
    struct scsi_devid_desc *);
boolean_t stmf_scsilib_tptid_validate(struct scsi_transport_id *,
    uint32_t, uint16_t *);
boolean_t stmf_scsilib_tptid_compare(struct scsi_transport_id *,
    struct scsi_transport_id *);
struct stmf_remote_port *stmf_remote_port_alloc(uint16_t);
void stmf_remote_port_free(struct stmf_remote_port *);
#ifdef	__cplusplus
}
#endif

#endif	/* _STMF_H */
