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
#ifndef	_FCT_IMPL_H
#define	_FCT_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	RSCN_OPTION_VERIFY	0x0001

typedef enum fct_li_state {
	LI_STATE_DO_FLOGI = 0,	/* FLOGI handled by FCA */
	LI_STATE_FINI_TOPOLOGY,	/* Finalize topology */
	LI_STATE_N2N_PLOGI,	/* In case of a N2N connection */

	LI_STATE_DO_FCLOGIN,	/* Login into 0xFFFFFD */
	LI_STATE_DO_SCR,	/* State change registration */

	LI_STATE_DO_NSLOGIN,	/* Login into 0xFFFFFC */
	LI_STATE_DO_RNN,	/* Register node name */
	LI_STATE_DO_RCS,	/* Register classes of service */
	LI_STATE_DO_RFT,	/* Register FC-4 types */
	LI_STATE_DO_RSPN,	/* Register symbolic port name */
	LI_STATE_DO_RSNN,	/* Register symbolic node name */

	LI_STATE_MAX		/* Not a real state */
} fct_li_state_t;

#define	LI_STATE_START			0
#define	LI_STATE_MASK			0x3F
/* Next state depends on the return value */
#define	LI_STATE_FLAG_CMD_RETCHECK	0x40
/* Link init cmd is still outstanding */
#define	LI_STATE_FLAG_CMD_WAITING	0x80
/* Flag to indicate that link info is not available yet */
#define	LI_STATE_FLAG_NO_LI_YET		0x100

#define	FCT_MAX_CACHED_CMDS	256
#define	USEC_ELS_TIMEOUT	(10 * 1000 * 1000)
#define	USEC_SOL_TIMEOUT	(10 * 1000 * 1000)
#define	USEC_DEREG_RP_TIMEOUT	(25 * 1000 * 1000)
#define	USEC_DEREG_RP_INTERVAL	(2 * 1000 * 1000)

struct fct_i_cmd;
typedef void (* fct_icmd_cb_t)(struct fct_i_cmd *icmd);
typedef struct fct_i_cmd {
	fct_cmd_t		*icmd_cmd;
	uint32_t		 icmd_alloc_size;
	fct_struct_id_t		 icmd_struct_id;
	uint32_t		 icmd_flags;
	clock_t			 icmd_start_time;
	struct fct_i_cmd	*icmd_next;	/* iport_abort_queue and irp */
	struct fct_i_cmd	*icmd_solcmd_next;	/* iport_solcmd_queue */
	fct_icmd_cb_t		 icmd_cb;
	void			*icmd_cb_private;
} fct_i_cmd_t;

/*
 * icmd_flags
 */
#define	ICMD_SESSION_AFFECTING		0x0002
#define	ICMD_IN_IRP_QUEUE		0x0004
#define	ICMD_BEING_ABORTED		0x0008
#define	ICMD_KNOWN_TO_FCA		0x0020
#define	ICMD_FCA_ABORT_CALLED		0x0040
#define	ICMD_CMD_COMPLETE		0x0080
#define	ICMD_IN_TRANSITION		0x0100
#define	ICMD_ABTS_RECEIVED		0x0200
#define	ICMD_IMPLICIT			0x0400
#define	ICMD_IMPLICIT_CMD_HAS_RESOURCE	0x0800
/* High order are debug flags */
#define	ICMD_ELS_PROCESSING_STARTED	0x80000000

/*
 * For solicited commands, there's only 3 states:
 * 1) it's new. We need send it to FCA. ICMD_SOLCMD_NEW is set
 * 2) it's running. We are waiting for completion.
 * 3) it's completed. We need free it. ICMD_CMD_COMPLETE is set
 * ICMD_SOLCMD_NEW and ICMD_CMD_COMPLETE should not be set in the same time
 */
#define	ICMD_IN_SOLCMD_QUEUE		0x010000
#define	ICMD_SOLCMD_NEW			0x020000

typedef struct fct_i_remote_port {
	fct_remote_port_t		*irp_rp;
	uint32_t			irp_alloc_size;
	fct_struct_id_t			irp_struct_id;
	krwlock_t			irp_lock;

	/* For queueing to local port */
	struct fct_i_remote_port	*irp_next;

	/* For queueing to handle elses */
	struct fct_i_remote_port	*irp_discovery_next;

	fct_i_cmd_t			*irp_els_list;

	/*
	 * sa stands for session affecting, nsa is non session affecting.
	 * The els counts only represent elses under progress not the ones
	 * that are terminated. active_xchg_count covers everything including
	 * the ones waiting to be terminated.
	 */
	uint16_t			irp_sa_elses_count;
	uint16_t			irp_nsa_elses_count;
	uint16_t			irp_fcp_xchg_count;
	uint16_t			irp_nonfcp_xchg_count;

	uint32_t			irp_flags;
	clock_t				irp_deregister_timer;
	uint32_t			irp_dereg_count;

	uint32_t			irp_portid;
	uint8_t				irp_id[24];
	uint32_t			irp_rcvd_prli_params;
	uint32_t			irp_sent_prli_params;

	/*
	 * Most HBAs will only register symbolic node name instead of port name,
	 * so we use SNN as session alias.
	 */
	stmf_scsi_session_t		*irp_session;
	char				*irp_snn;

	/* items will be filled in ns cmd */
	uint8_t				irp_fc4types[32]; /* FC-4 types */
	char				*irp_spn;	/* port symbolic name */
	uint32_t			irp_cos;	/* class of service */

	uint32_t			irp_rscn_counter;
} fct_i_remote_port_t;

/*
 * structure used for fct_rls_cb() callback private data
 */
typedef struct fct_rls_cb_data {
	struct fct_port_link_status	*fct_link_status;
	fct_status_t			fct_els_res;
} fct_rls_cb_data_t;

/*
 * irp flags
 */
#define	IRP_PLOGI_DONE			0x0001
#define	IRP_PRLI_DONE			0x0002
#define	IRP_IN_DISCOVERY_QUEUE		0x0004
#define	IRP_FCP_CLEANUP			0x0008
#define	IRP_SESSION_CLEANUP		(IRP_FCP_CLEANUP | 0x0010)
#define	IRP_HANDLE_OPENED		0x0020
#define	IRP_SCSI_SESSION_STARTED	0x0040
#define	IRP_RSCN_QUEUED			0x0080
#define	IRP_SOL_PLOGI_IN_PROGRESS	0x0100

typedef struct fct_cmd_slot {
	fct_i_cmd_t		*slot_cmd;
	uint16_t		slot_no;
	uint16_t		slot_next;
	uint8_t			slot_uniq_cntr;
} fct_cmd_slot_t;
#define	FCT_SLOT_EOL		0xffff

#define	FCT_HASH_TABLE_SIZE		256
#define	FCT_LOOP_HASH(portid)		(portid & 0xff)
#define	FCT_FABRIC_HASH(portid)		(((portid & 0x1f00) | \
	((portid & 0x70000)>>3)) >> 8)
#define	FCT_PORTID_HASH_FUNC(portid) \
	((portid & 0xFFFF00)?FCT_FABRIC_HASH(portid):FCT_LOOP_HASH(portid))

typedef struct fct_i_local_port {
	fct_local_port_t	*iport_port;
	uint32_t		iport_alloc_size;
	fct_struct_id_t		iport_struct_id;

	struct fct_i_local_port	*iport_next;
	struct fct_i_local_port	*iport_prev;

	char			*iport_alias;
	char			iport_alias_mem[16];
	uint8_t			iport_id[24];	/* scsi_devid_desc_t */
	krwlock_t		iport_lock;
	uint32_t		iport_flags;
	uint16_t		iport_link_state;
	uint8_t			iport_state:7,
	    iport_state_not_acked:1;
	uint8_t			iport_offline_prstate;
	struct fct_link_info	iport_link_info;

	fct_i_remote_port_t	**iport_rp_slots;
	fct_i_remote_port_t	**iport_rp_tb;
	uint32_t		iport_nrps_login; /* currently logged in */
	uint32_t		iport_nrps;	/* items in hash table */
	uint64_t		iport_last_change;

	/*
	 * These variables are used to manage fct_cmd_t cache for SCSI traffic
	 */
	/*
	 * Total # of cmds allocated by the driver. Some of which are free
	 * and sitting on iport_cached_cmdlist. And some are executing.
	 */
	uint32_t		iport_total_alloced_ncmds;

	/*
	 * Max active cmds in last interval (10 or 30 seconds)
	 */
	uint32_t		iport_max_active_ncmds;

	/*
	 * # of free cmds sitting on the iport_cached_cmdlist
	 */
	uint32_t		iport_cached_ncmds;
	struct fct_i_cmd	*iport_cached_cmdlist;
	kmutex_t		iport_cached_cmd_lock;

	/*
	 * To release free cmds periodically
	 */
	clock_t			iport_cmdcheck_clock;

	uint16_t		iport_task_green_limit;
	uint16_t		iport_task_yellow_limit;
	uint16_t		iport_task_red_limit;
	/* cmd slots */
	uint16_t		iport_nslots_free;

	/* upper 16 bits is just a counter to avoid ABA issues */
	uint32_t		iport_next_free_slot;

	uint8_t			iport_login_retry; /* for flogi and N2N plogi */
	uint8_t			iport_link_old_topology;
	uint8_t			iport_link_cleanup_retry;
	clock_t			iport_li_cmd_timeout; /* for li state m/c */
	fct_cmd_slot_t		*iport_cmd_slots;

	/* worker thread data */
	ddi_taskq_t		*iport_worker_taskq;
	kmutex_t		iport_worker_lock;
	kcondvar_t		iport_worker_cv;
	struct fct_i_event	*iport_event_head;
	struct fct_i_event	*iport_event_tail;
	struct fct_i_cmd	*iport_abort_queue;
	struct fct_i_cmd	**iport_ppicmd_term;

	/* link initialization */
	fct_status_t		iport_li_comp_status;
	enum fct_li_state	iport_li_state;

	/* solicited cmd link */
	struct fct_i_cmd	*iport_solcmd_queue;

	/* rpwe = remote port with pending els(es) */
	fct_i_remote_port_t	*iport_rpwe_head;
	fct_i_remote_port_t	*iport_rpwe_tail;
	kstat_t			*iport_kstat_portstat;
	ksema_t			iport_rls_sema;
	fct_rls_cb_data_t	iport_rls_cb_data;
} fct_i_local_port_t;

#define	IPORT_FLOGI_DONE(iport)	PORT_FLOGI_DONE(&(iport)->iport_link_info)

/*
 * iport flags
 */
#define	IPORT_WORKER_RUNNING		0x0001
#define	IPORT_TERMINATE_WORKER		0x0002
#define	IPORT_WORKER_DOING_TIMEDWAIT	0x0004
#define	IPORT_WORKER_DOING_WAIT		0x0008
#define	IPORT_FLAG_PORT_OFFLINED	0x0010
#define	IPORT_ALLOW_UNSOL_FLOGI		0x0020

#define	IS_WORKER_SLEEPING(iport)	((iport)->iport_flags & \
	(IPORT_WORKER_DOING_TIMEDWAIT | IPORT_WORKER_DOING_WAIT))

/* Limits for scsi task load of local port */
#define	FCT_TASK_GREEN_LIMIT		80
#define	FCT_TASK_YELLOW_LIMIT		90
#define	FCT_TASK_RED_LIMIT		95

typedef struct fct_i_event {
	struct fct_i_event	*event_next;
	int			event_type;
} fct_i_event_t;

typedef enum { /* Seggested action values for discovery thread */
    DISC_ACTION_NO_WORK = 0,
    DISC_ACTION_RESCAN = 1,
    DISC_ACTION_DELAY_RESCAN = 2,
    DISC_ACTION_USE_SHORT_DELAY = 4
} disc_action_t;

/*
 * Local port state definitions
 * NOTE that every time there is a state change, the newly set bit suggests
 * the action. So far there are 3 actions S_PORT_CLEANUP, S_ADAPTER_FATAL
 * and S_INIT_LINK.
 */
#define	S_RCVD_LINK_DOWN	0x01
#define	S_RCVD_LINK_UP		0x02
#define	S_LINK_ONLINE		0x04
#define	S_INIT_LINK		0x08
#define	S_PORT_CLEANUP		0x10

#define	PORT_STATE_LINK_DOWN		0x00
#define	PORT_STATE_LINK_INIT_START	(S_RCVD_LINK_UP | S_LINK_ONLINE |\
    S_INIT_LINK)
#define	PORT_STATE_LINK_INIT_DONE	(S_LINK_ONLINE)
#define	PORT_STATE_LINK_UP_CLEANING	(S_RCVD_LINK_UP | S_PORT_CLEANUP)
#define	PORT_STATE_LINK_DOWN_CLEANING	(S_RCVD_LINK_DOWN | S_PORT_CLEANUP)

/*
 * Internal events
 */
#define	FCT_I_EVENT_LINK_INIT_DONE	0x80
#define	FCT_I_EVENT_CLEANUP_POLL	0x81

/*
 * Offline processing states, used by worker thread.
 */
#define	FCT_OPR_DONE			0
#define	FCT_OPR_START			1
#define	FCT_OPR_CMD_CLEANUP_WAIT	2
#define	FCT_OPR_INT_CLEANUP_WAIT	3

/*
 * Check time
 */
#define	FCT_CMDLIST_CHECK_SECONDS	10

/*
 * Define frequently used macros
 */
#define	ICMD_TO_CT(x_icmd)	\
	((fct_sol_ct_t *)(x_icmd)->icmd_cmd->cmd_specific)

#define	ICMD_TO_ELS(x_icmd)	\
	((fct_els_t *)(x_icmd)->icmd_cmd->cmd_specific)

#define	ICMD_TO_IPORT(x_icmd)	\
	((fct_i_local_port_t *)(x_icmd)->icmd_cmd->cmd_port->port_fct_private)

#define	ICMD_TO_PORT(x_icmd)	\
	((x_icmd)->icmd_cmd->cmd_port)

#define	ICMD_TO_IRP(x_icmd)	\
	((fct_i_remote_port_t *)(x_icmd)->icmd_cmd->cmd_rp->rp_fct_private)

#define	CMD_TO_ICMD(x_cmd)	((fct_i_cmd_t *)(x_cmd)->cmd_fct_private)

#define	RP_TO_IRP(x_rp)		((fct_i_remote_port_t *)(x_rp)->rp_fct_private)

#define	PORT_TO_IPORT(x_port)	\
	((fct_i_local_port_t *)(x_port)->port_fct_private)

#define	FCT_IS_ELS_ACC(x_icmd)	\
	(((x_icmd)->icmd_cmd->cmd_comp_status == FCT_SUCCESS) &&	\
	(ICMD_TO_ELS(x_icmd)->els_resp_payload[0] == ELS_OP_ACC))

#define	FCT_IS_CT_ACC(x_icmd)	\
	(((x_icmd)->icmd_cmd->cmd_comp_status == FCT_SUCCESS) &&	\
	(ICMD_TO_CT(x_icmd)->ct_resp_payload[8] == 0x80) &&\
	(ICMD_TO_CT(x_icmd)->ct_resp_payload[9] == 0x02))

#define	IPORT_IN_NS_TOPO(x_iport)	\
	((x_iport)->iport_link_info.port_topology & PORT_TOPOLOGY_FABRIC_BIT)

#define	IS_LOGO_ELS(icmd)	\
	(ICMD_TO_ELS(icmd)->els_req_payload[0] == ELS_OP_LOGO)

stmf_status_t fct_xfer_scsi_data(scsi_task_t *task,
    stmf_data_buf_t *dbuf, uint32_t ioflags);
stmf_status_t fct_send_scsi_status(scsi_task_t *task, uint32_t ioflags);
fct_i_remote_port_t *fct_portid_to_portptr(fct_i_local_port_t *iport,
    uint32_t portid);
fct_i_remote_port_t *fct_lookup_irp_by_nodewwn(fct_i_local_port_t *iport,
    uint8_t *nodewwn);
fct_i_remote_port_t *fct_lookup_irp_by_portwwn(fct_i_local_port_t *iport,
    uint8_t *portwwn);
void fct_queue_rp(fct_i_local_port_t *iport, fct_i_remote_port_t *irp);
void fct_deque_rp(fct_i_local_port_t *iport, fct_i_remote_port_t *irp);
int fct_implicitly_logo_all(fct_i_local_port_t *iport, int force_implicit);
void fct_post_implicit_logo(fct_cmd_t *cmd);
void fct_rehash(fct_i_local_port_t *iport);
uint8_t fct_local_port_cleanup_done(fct_i_local_port_t *iport);
void fct_handle_rcvd_abts(fct_cmd_t *cmd);
void fct_fill_abts_acc(fct_cmd_t *cmd);
void fct_q_for_termination_lock_held(fct_i_local_port_t *iport,
    fct_i_cmd_t *icmd, fct_status_t s);
disc_action_t fct_handle_port_offline(fct_i_local_port_t *iport);
disc_action_t fct_cmd_terminator(fct_i_local_port_t *iport);
void fct_cmd_free(fct_cmd_t *cmd);
void fct_scsi_task_free(scsi_task_t *task);
stmf_status_t fct_scsi_abort(stmf_local_port_t *lport, int abort_cmd,
    void *arg, uint32_t flags);
stmf_status_t fct_info(uint32_t cmd, stmf_local_port_t *lport,
    void *arg, uint8_t *buf, uint32_t *bufsizep);
void fct_event_handler(stmf_local_port_t *lport, int eventid,
    void *arg, uint32_t flags);
uint16_t fct_alloc_cmd_slot(fct_i_local_port_t *iport, fct_cmd_t *cmd);
void fct_post_to_discovery_queue(fct_i_local_port_t *iport,
    fct_i_remote_port_t *irp, fct_i_cmd_t *icmd);
fct_cmd_t *fct_create_solct(fct_local_port_t *port, fct_remote_port_t *rp,
    uint16_t ctop, fct_icmd_cb_t icmdcb);
fct_cmd_t *fct_create_solels(fct_local_port_t *port, fct_remote_port_t *rp,
    int implicit, uchar_t elsop, uint32_t wkdid, fct_icmd_cb_t icmdcb);
void fct_handle_solct(fct_cmd_t *cmd);
void fct_post_to_solcmd_queue(fct_local_port_t *port, fct_cmd_t *cmd);
void fct_logo_cb(fct_i_cmd_t *icmd);
void fct_link_init_cb(fct_i_cmd_t *icmd);
void fct_gsnn_cb(fct_i_cmd_t *icmd);
void fct_gcs_cb(fct_i_cmd_t *icmd);
void fct_gft_cb(fct_i_cmd_t *icmd);
void fct_gspn_cb(fct_i_cmd_t *icmd);
void fct_rls_cb(fct_i_cmd_t *icmd);
disc_action_t fct_process_link_init(fct_i_local_port_t *iport);

#ifdef	__cplusplus
}
#endif

#endif /* _FCT_IMPL_H */
