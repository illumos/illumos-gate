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
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */
#ifndef	_FCT_H
#define	_FCT_H

/*
 * Definitions for common FC Target.
 */
#include <sys/note.h>
#include <sys/stmf_defines.h>
#include <sys/fct_defines.h>
#include <sys/portif.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum fct_struct_id {
	FCT_STRUCT_LOCAL_PORT = 1,
	FCT_STRUCT_REMOTE_PORT,
	FCT_STRUCT_CMD_RCVD_ELS,
	FCT_STRUCT_CMD_SOL_ELS,
	FCT_STRUCT_CMD_SOL_CT,
	FCT_STRUCT_CMD_RCVD_ABTS,
	FCT_STRUCT_CMD_FCP_XCHG,
	FCT_STRUCT_DBUF_STORE,

	FCT_MAX_STRUCT_IDS
} fct_struct_id_t;

typedef struct fct_remote_port {
	void		*rp_fct_private;
	void		*rp_fca_private;

	struct fct_local_port *rp_port;
	char		rp_nwwn_str[FC_WWN_BUFLEN];
	char		rp_pwwn_str[FC_WWN_BUFLEN];
	uint8_t		rp_nwwn[FC_WWN_LEN];
	uint8_t		rp_pwwn[FC_WWN_LEN];
	uint32_t	rp_id;		/* 8 or 24 bit */
	uint32_t	rp_hard_address;
	uint16_t	rp_handle;
} fct_remote_port_t;

#define	FCT_HANDLE_NONE	0xffff

typedef struct fct_cmd {
	void		*cmd_fct_private;
	void		*cmd_fca_private;
	void		*cmd_specific;

	struct fct_local_port	*cmd_port;

	/* During cmd porting this can be set to NULL */
	struct fct_remote_port	*cmd_rp;

	/* To link cmds together for handling things like ABTS. */
	struct fct_cmd	*cmd_link;
	uint8_t		cmd_type;
	uint8_t		cmd_rsvd1;

	/* During cmd posting this can be set to FCT_HANDLE_NONE */
	uint16_t	cmd_rp_handle;
	uint32_t	cmd_handle;
	uint32_t	cmd_rportid;
	uint32_t	cmd_lportid;
	uint32_t	cmd_rsvd2;
	uint16_t	cmd_oxid;
	uint16_t	cmd_rxid;
	fct_status_t	cmd_comp_status;
} fct_cmd_t;

/*
 * fcmd_cmd_handle: Bit definitions.
 *   31		  23	       15	    7	       0
 *  +--------------+------------+------------+------------+
 *  | V |uniq_cntr |fca specific|   cmd slot index	  |
 *  +--------------+------------+------------+------------+
 * V = handle valid.
 */
#define	CMD_HANDLE_SLOT_INDEX(x)	((x) & 0xffff)
#define	CMD_HANDLE_VALID(x)		((x) & 0x80000000)

enum fct_cmd_types {
	FCT_CMD_FCP_XCHG =	0x0001,
	FCT_CMD_RCVD_ELS =	0x0002,
	FCT_CMD_SOL_ELS =	0x0004,
	FCT_CMD_RCVD_ABTS =	0x0008,
	FCT_CMD_SOL_CT =	0x0010,

	FCT_CMD_TYPE_ALL =	0xffff
};

typedef struct fct_els {
	uint16_t	els_req_size;
	uint16_t	els_resp_size;
	uint16_t	els_req_alloc_size;
	uint16_t	els_resp_alloc_size;
	uint8_t		*els_req_payload;
	uint8_t		*els_resp_payload;
} fct_els_t;

typedef struct fct_sol_ct {
	uint16_t	ct_req_size;
	uint16_t	ct_resp_size;
	uint16_t	ct_req_alloc_size;
	uint16_t	ct_resp_alloc_size;
	uint8_t		*ct_req_payload;
	uint8_t		*ct_resp_payload;
} fct_sol_ct_t;

typedef struct fct_rcvd_abts {
	uint8_t		abts_resp_rctl;	/* Can be BA_ACC or BA_RJT */
	uint8_t		abts_state;
	uint16_t	rsvd;
	uint8_t		abts_resp_payload[12];
} fct_rcvd_abts_t;

/*
 * abts state
 */
#define	ABTS_STATE_RECEIVED		0
#define	ABTS_STATE_RESPONDED		1
#define	ABTS_STATE_COMPLETED		2
#define	ABTS_STATE_ABORT_REQUESTED	3
#define	ABTS_STATE_ABORT_COMPLETED	4

#define	FCHBA_MANUFACTURER_LEN		64
#define	FCHBA_SERIAL_NUMBER_LEN		64
#define	FCHBA_MODEL_LEN			256
#define	FCHBA_MODEL_DESCRIPTION_LEN	256
#define	FCHBA_HARDWARE_VERSION_LEN	256
#define	FCHBA_DRIVER_VERSION_LEN	256
#define	FCHBA_OPTION_ROM_VERSION_LEN	256
#define	FCHBA_FIRMWARE_VERSION_LEN	256
#define	FCHBA_DRIVER_NAME_LEN		256
#define	FCHBA_SYMB_NAME_LEN		255

#define	FCT_INFO_LEN			160
#define	FCT_TASKQ_NAME_LEN		24

#define	FC_TGT_PORT_INFO_CMD		(((uint32_t)'I') << 24)
#define	FC_TGT_PORT_RLS			FC_TGT_PORT_INFO_CMD + 0x1

typedef struct fct_port_attrs {
	char		manufacturer[FCHBA_MANUFACTURER_LEN];
	char		serial_number[FCHBA_SERIAL_NUMBER_LEN];
	char		model[FCHBA_MODEL_LEN];
	char		model_description[FCHBA_MODEL_DESCRIPTION_LEN];
	char		hardware_version[FCHBA_HARDWARE_VERSION_LEN];
	char		driver_version[FCHBA_DRIVER_VERSION_LEN];
	char		option_rom_version[FCHBA_OPTION_ROM_VERSION_LEN];
	char		firmware_version[FCHBA_FIRMWARE_VERSION_LEN];
	char		driver_name[FCHBA_DRIVER_NAME_LEN];
	uint32_t	vendor_specific_id;
	uint32_t	supported_cos;
	uint32_t	supported_speed;
	uint32_t	max_frame_size;
} fct_port_attrs_t;

typedef struct fct_port_link_status {
	uint32_t	LinkFailureCount;
	uint32_t	LossOfSyncCount;
	uint32_t	LossOfSignalsCount;
	uint32_t	PrimitiveSeqProtocolErrorCount;
	uint32_t	InvalidTransmissionWordCount;
	uint32_t	InvalidCRCCount;
} fct_port_link_status_t;

typedef struct fct_dbuf_store {
	void			*fds_fct_private;
	void			*fds_fca_private;
	struct stmf_dbuf_store	*fds_ds;

	stmf_data_buf_t *(*fds_alloc_data_buf)(struct fct_local_port *port,
			    uint32_t size, uint32_t *pminsize, uint32_t flags);
	void		(*fds_free_data_buf)(struct fct_dbuf_store *fds,
			    stmf_data_buf_t *dbuf);
	stmf_status_t	(*fds_setup_dbuf)(struct fct_local_port *port,
			    stmf_data_buf_t *dbuf, uint32_t flags);
	void		(*fds_teardown_dbuf)(struct fct_dbuf_store *fds,
			    stmf_data_buf_t *dbuf);

	uint32_t		fds_max_sgl_xfer_len;
	uint32_t		fds_copy_threshold;
} fct_dbuf_store_t;

#define	FCT_FCA_MODREV_1	1

typedef struct fct_local_port {
	void			*port_fct_private;
	void			*port_fca_private;
	stmf_local_port_t	*port_lport;

	char			port_nwwn_str[FC_WWN_BUFLEN];
	char			port_pwwn_str[FC_WWN_BUFLEN];
	uint8_t			port_nwwn[FC_WWN_LEN];
	uint8_t			port_pwwn[FC_WWN_LEN];
	char			*port_default_alias;
	char			*port_sym_node_name;
	char			*port_sym_port_name;

	stmf_port_provider_t	*port_pp;

	uint32_t		port_hard_address;
	uint16_t		port_max_logins;
	uint16_t		port_max_xchges;
	uint32_t		port_fca_fcp_cmd_size;
	uint32_t		port_fca_rp_private_size;
	uint32_t		port_fca_sol_els_private_size;
	uint32_t		port_fca_sol_ct_private_size;

	/* in milliseconds */
	uint32_t		port_fca_abort_timeout;

	fct_dbuf_store_t	*port_fds;
	fct_status_t		(*port_get_link_info)(
		struct fct_local_port *port, struct fct_link_info *li);
	fct_status_t		(*port_register_remote_port)(
		struct fct_local_port *port, struct fct_remote_port *rp,
		struct fct_cmd *login_els);
	fct_status_t		(*port_deregister_remote_port)(
		struct fct_local_port *port, struct fct_remote_port *rp);
	fct_status_t		(*port_send_cmd)(fct_cmd_t *cmd);
	fct_status_t		(*port_xfer_scsi_data)(fct_cmd_t *cmd,
			stmf_data_buf_t *dbuf, uint32_t flags);
	fct_status_t		(*port_send_cmd_response)(fct_cmd_t *cmd,
					uint32_t ioflags);
	fct_status_t		(*port_abort_cmd)(struct fct_local_port *port,
			fct_cmd_t *cmd, uint32_t flags);
	void			(*port_ctl)(struct fct_local_port *port,
						int cmd, void *arg);
	fct_status_t		(*port_flogi_xchg)(struct fct_local_port *port,
			struct fct_flogi_xchg *fx);
	void			(*port_populate_hba_details)(
		struct fct_local_port *port, struct fct_port_attrs *port_attrs);
	fct_status_t		(*port_info)(uint32_t cmd,
		struct fct_local_port *port, void *arg, uint8_t *buf,
		uint32_t *bufsizep);
	int		port_fca_version;
} fct_local_port_t;

/*
 * Common struct used during FLOGI exchange.
 */
typedef struct fct_flogi_xchg {
	uint8_t		fx_op;		/* ELS_OP_FLOGI or ELS_OP_ACC/RJT */
	uint8_t		fx_rjt_reason;
	uint8_t		fx_rjt_expl;
	uint8_t		fx_sec_timeout;	/* Timeout in seconds */
	uint32_t	fx_fport:1,	/* 0=N_port, 1=F_port */
			rsvd2:31;
	uint32_t	fx_sid;		/* 24 bit SID to use */
	uint32_t	fx_did;		/* 24 bit DID to use */
	uint8_t		fx_pwwn[8];
	uint8_t		fx_nwwn[8];
} fct_flogi_xchg_t;

typedef struct fct_link_info {
	uint32_t		portid;
	uint8_t			port_topology;
	uint8_t			port_speed;

	uint8_t			rsvd:5,

	/*
	 * FCA sets this bit to indicate that fct does not need to do FLOGI
	 * because either FCA did the FLOGI or it determined that its a private
	 * loop. Setting this bit by FCA is optional.
	 */
				port_no_fct_flogi:1,

	/* FCA sets this bit to indicate that it did FLOGI */
				port_fca_flogi_done:1,

	/* FCT sets this bit to indicate that it did FLOGI */
				port_fct_flogi_done:1;

	uint8_t			rsvd1;

	/* The fields below are only valid if someone did a successful flogi */
	uint8_t			port_rnwwn[8];
	uint8_t			port_rpwwn[8];
} fct_link_info_t;

typedef struct fct_port_stat {
	kstat_named_t	link_failure_cnt;
	kstat_named_t	loss_of_sync_cnt;
	kstat_named_t	loss_of_signals_cnt;
	kstat_named_t	prim_seq_protocol_err_cnt;
	kstat_named_t	invalid_tx_word_cnt;
	kstat_named_t	invalid_crc_cnt;
} fct_port_stat_t;

/*
 * port topology
 */
#define	PORT_TOPOLOGY_UNKNOWN		0
#define	PORT_TOPOLOGY_PT_TO_PT		1
#define	PORT_TOPOLOGY_PRIVATE_LOOP	2
#define	PORT_TOPOLOGY_PUBLIC_LOOP	6
#define	PORT_TOPOLOGY_FABRIC_PT_TO_PT	5
#define	PORT_TOPOLOGY_FABRIC_BIT	4

#define	PORT_FLOGI_DONE(li)	(((li)->port_fca_flogi_done) || \
					((li)->port_fct_flogi_done))

/*
 * port speed
 */
#define	PORT_SPEED_UNKNOWN		0
#define	PORT_SPEED_1G			1
#define	PORT_SPEED_2G			2
#define	PORT_SPEED_4G			4
#define	PORT_SPEED_8G			8
#define	PORT_SPEED_10G			16
#define	PORT_SPEED_16G			32

/*
 * Abort commands
 */
#define	FCT_TERMINATE_CMD		1

/*
 * FCT port states.
 */
#define	FCT_STATE_OFFLINE	0
#define	FCT_STATE_ONLINING	1
#define	FCT_STATE_ONLINE	2
#define	FCT_STATE_OFFLINING	3

/*
 * fct ctl commands. These should not conflict with stmf ctl commands
 */
#define	FCT_CMD_PORT_ONLINE		(STMF_LPORT_CTL_CMDS | 0x01)
#define	FCT_CMD_PORT_ONLINE_COMPLETE	(STMF_LPORT_CTL_CMDS | 0x02)
#define	FCT_CMD_PORT_OFFLINE		(STMF_LPORT_CTL_CMDS | 0x03)
#define	FCT_CMD_PORT_OFFLINE_COMPLETE	(STMF_LPORT_CTL_CMDS | 0x04)
#define	FCT_ACK_PORT_ONLINE_COMPLETE	(STMF_LPORT_CTL_CMDS | 0x05)
#define	FCT_ACK_PORT_OFFLINE_COMPLETE	(STMF_LPORT_CTL_CMDS | 0x06)
#define	FCT_CMD_FORCE_LIP		(STMF_LPORT_CTL_CMDS | 0x07)

/*
 * IO flags for cmd flow.
 */
#define	FCT_IOF_FCA_DONE		0x10000
#define	FCT_IOF_FORCE_FCA_DONE		0x20000

/*
 * Fill CTIU preamble
 */
#ifdef	lint
#define	FCT_FILL_CTIU_PREAMBLE(x_payload, x_ctop)	_NOTE(EMPTY)
#else
#define	FCT_FILL_CTIU_PREAMBLE(x_payload, x_ctop)	\
	do {						\
		x_payload[0] = 0x01;			\
		x_payload[4] = 0xFC;			\
		x_payload[5] = 0x02;			\
		x_payload[8] = 0xFF & (x_ctop >> 8);	\
		x_payload[9] = 0xFF & (x_ctop);		\
	} while (0)
#endif

uint64_t fct_netbuf_to_value(uint8_t *buf, uint8_t nbytes);
void fct_value_to_netbuf(uint64_t value, uint8_t *buf, uint8_t nbytes);
void *fct_alloc(fct_struct_id_t struct_id, int additional_size, int flags);
void fct_free(void *ptr);
fct_cmd_t *fct_scsi_task_alloc(struct fct_local_port *port,
    uint16_t rp_handle, uint32_t rportid, uint8_t *lun,
    uint16_t cdb_length, uint16_t task_ext);
fct_status_t fct_register_local_port(fct_local_port_t *port);
fct_status_t fct_deregister_local_port(fct_local_port_t *port);
void fct_handle_event(fct_local_port_t *port, int event_id,
    uint32_t event_flags, caddr_t arg);
void fct_post_rcvd_cmd(fct_cmd_t *cmd, stmf_data_buf_t *dbuf);
void fct_queue_cmd_for_termination(fct_cmd_t *cmd, fct_status_t s);
void fct_queue_scsi_task_for_termination(fct_cmd_t *cmd, fct_status_t s);
fct_cmd_t *fct_handle_to_cmd(fct_local_port_t *port, uint32_t fct_handle);
void fct_ctl(struct stmf_local_port *lport, int cmd, void *arg);
void fct_cmd_fca_aborted(fct_cmd_t *cmd, fct_status_t s, uint32_t ioflags);
uint16_t fct_get_rp_handle(fct_local_port_t *port, uint32_t rportid);
void fct_send_response_done(fct_cmd_t *cmd, fct_status_t s, uint32_t ioflags);
void fct_send_cmd_done(fct_cmd_t *cmd, fct_status_t s, uint32_t ioflags);
void fct_scsi_data_xfer_done(fct_cmd_t *cmd, stmf_data_buf_t *dbuf,
    uint32_t ioflags);
fct_status_t fct_port_initialize(fct_local_port_t *port, uint32_t rflags,
    char *additional_info);
fct_status_t fct_port_shutdown(fct_local_port_t *port, uint32_t rflags,
    char *additional_info);
fct_status_t fct_handle_rcvd_flogi(fct_local_port_t *port,
    fct_flogi_xchg_t *fx);
void fct_log_local_port_event(fct_local_port_t *port, char *subclass);
void fct_log_remote_port_event(fct_local_port_t *port, char *subclass,
    uint8_t *rp_pwwn, uint32_t rp_id);
void fct_wwn_to_str(char *to_ptr, const uint8_t *from_ptr);

#ifdef	__cplusplus
}
#endif

#endif /* _FCT_H */
