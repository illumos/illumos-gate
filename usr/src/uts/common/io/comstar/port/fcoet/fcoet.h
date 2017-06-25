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
#ifndef	_FCOET_H
#define	_FCOET_H

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	FCOET_VERSION	"v20091123-1.02"
#define	FCOET_NAME	"COMSTAR FCoET "
#define	FCOET_MOD_NAME	FCOET_NAME FCOET_VERSION

#define	FCOET_TASKQ_NAME_LEN	32

/*
 * FCOET logging
 */
extern int fcoet_use_ext_log;

/*
 * Caution: 1) LOG will be available in debug/non-debug mode
 *	    2) Anything which can potentially flood the log should be under
 *	       extended logging, and use FCOET_EXT_LOG.
 *	    3) Don't use FCOET_EXT_LOG in performance-critical code path, such
 *	       as normal SCSI I/O code path. It could hurt system performance.
 *	    4) Use kmdb to change focet_use_ext_log in the fly to adjust
 *	       tracing
 */
#define	FCOET_EXT_LOG(log_ident, ...)	\
	{	\
		if (fcoet_use_ext_log) {	\
			fcoe_trace(log_ident, __VA_ARGS__);	\
		}	\
	}

#define	FCOET_LOG(log_ident, ...)	\
	fcoe_trace(log_ident, __VA_ARGS__)

/*
 * define common-used constants
 */
#define	FCOET_MAX_LOGINS	2048
#define	FCOET_MAX_XCHGES	2048
#define	FCOET_SOL_HASH_SIZE	128
#define	FCOET_UNSOL_HASH_SIZE	2048

typedef enum fcoet_sol_flogi_state {
	SFS_WAIT_LINKUP = 0,
	SFS_FLOGI_INIT,
	SFS_FLOGI_CHECK_TIMEOUT,
	SFS_ABTS_INIT,
	SFS_CLEAR_FLOGI,
	SFS_FLOGI_ACC,
	SFS_FLOGI_DONE
} fcoet_sol_flogi_state_t;

/*
 * define data structures
 */
struct fcoet_exchange;
typedef struct fcoet_soft_state {
	/*
	 * basic information
	 */
	dev_info_t		*ss_dip;
	int			 ss_instance;
	uint32_t		 ss_flags;
	fct_local_port_t	*ss_port;
	fcoe_port_t		*ss_eport;
	char			 ss_alias[32];
	uint32_t		 ss_fcp_data_payload_size;

	/*
	 * support degregister remote port
	 */
	uint32_t		 ss_rportid_in_dereg;
	uint32_t		 ss_rport_dereg_state;

	/*
	 * oxid/rxid
	 */
	mod_hash_t		*ss_sol_oxid_hash;
	mod_hash_t		*ss_unsol_rxid_hash;
	uint16_t		 ss_next_sol_oxid;
	uint16_t		 ss_next_unsol_rxid;
	int			 ss_sol_oxid_hash_empty;
	int			 ss_unsol_rxid_hash_empty;

	/*
	 * watch thread related stuff
	 */
	ddi_taskq_t		*ss_watchdog_taskq;
	kcondvar_t		 ss_watch_cv;
	kmutex_t		 ss_watch_mutex;
	uint64_t		 ss_watch_count;
	list_t			 ss_abort_xchg_list;

	/*
	 * topology discovery
	 */
	struct fcoet_exchange	*ss_sol_flogi;
	fcoet_sol_flogi_state_t	 ss_sol_flogi_state;
	fct_link_info_t		 ss_link_info;

	/*
	 * ioctl related stuff
	 */
	uint32_t		 ss_ioctl_flags;
	kmutex_t		 ss_ioctl_mutex;

	/*
	 * special stuff
	 */
	uint32_t		 ss_change_state_flags;
	uint8_t			 ss_state:7,
	    ss_state_not_acked:1;
} fcoet_soft_state_t;

#define	SS_FLAG_UNSOL_FLOGI_DONE	0x0001
#define	SS_FLAG_REPORT_TO_FCT		0x0002
#define	SS_FLAG_PORT_DISABLED		0x0004
#define	SS_FLAG_STOP_WATCH		0x0008
#define	SS_FLAG_TERMINATE_WATCHDOG	0x0010
#define	SS_FLAG_WATCHDOG_RUNNING	0x0020
#define	SS_FLAG_DOG_WAITING		0x0040
#define	SS_FLAG_DELAY_PLOGI		0x0080

/*
 * Sequence and frame are transient objects, so their definition is simple.
 */

/*
 * Sequence.
 * we will not use sequence in current implementation
 */
typedef struct fcoet_sequence {
	list_t			 seq_frame_list;
	struct fcoet_exchange	*seq_exchange;
} fcoet_sequence_t;

/*
 * Frame
 */
typedef struct fcoet_frame {
	list_node_t		 tfm_seq_node;
	fcoe_frame_t		*tfm_fcoe_frame;

	struct fcoet_exchange	*tfm_xch;
	struct fcoet_sequence	*tfm_seq;
	uint8_t			 tfm_rctl;
	uint8_t			 tfm_buf_idx;
} fcoet_frame_t;

/*
 * FCOET_MAX_DBUF_LEN should better be consistent with sbd_scsi.c. Since
 * sbd_scsi.c use 128k as the max dbuf size, we'd better define this between
 * 32k - 128k.
 */
#define	FCOET_MAX_DBUF_LEN	0x20000 /* 128 * 1024 */
/*
 * exchange - cmd alias
 */
typedef struct fcoet_exchange {
	/*
	 * it is only used for ss_abort_xchg_list
	 */
	list_node_t		 xch_abort_node;

	/*
	 * We don't believe oxid/rxid in fct_cmd_t
	 */
	uint16_t		 xch_oxid;
	uint16_t		 xch_rxid;

	uint32_t		 xch_flags;
	fcoet_soft_state_t	*xch_ss;
	fct_cmd_t		*xch_cmd;

	fcoet_sequence_t	*xch_current_seq;
	clock_t			 xch_start_time;

	stmf_data_buf_t		**xch_dbufs;
	uint8_t			xch_dbuf_num;
	uint8_t			xch_sequence_no;
	uint8_t			xch_ref;

	int			 xch_left_data_size;
} fcoet_exchange_t;
/*
 * Add the reference to avoid such situation:
 * 1, Frame received, then abort happen (maybe because local port offline, or
 * remote port abort the cmd), cmd is aborted and then freed right after we
 * get the exchange from hash table in fcoet_rx_frame.
 * 2, Frame sent out, then queued in fcoe for release. then abort happen, cmd
 * is aborted and then freed before fcoe_watchdog() call up to release the
 * frame.
 * These two situation should seldom happen. But just invoke this seems won't
 * downgrade the performance too much, so we keep it.
 */
#define	FCOET_BUSY_XCHG(xch)	atomic_inc_8(&(xch)->xch_ref)
#define	FCOET_RELE_XCHG(xch)	atomic_dec_8(&(xch)->xch_ref)

#define	XCH_FLAG_NONFCP_REQ_SENT	0x0001
#define	XCH_FLAG_NONFCP_RESP_SENT	0x0002
#define	XCH_FLAG_FCP_CMD_RCVD		0x0004
#define	XCH_FLAG_INI_ASKED_ABORT	0x0008
#define	XCH_FLAG_FCT_CALLED_ABORT	0x0010
#define	XCH_FLAG_IN_HASH_TABLE		0x0020

/*
 * IOCTL supporting stuff
 */
#define	FCOET_IOCTL_FLAG_MASK		0xFF
#define	FCOET_IOCTL_FLAG_IDLE		0x00
#define	FCOET_IOCTL_FLAG_OPEN		0x01
#define	FCOET_IOCTL_FLAG_EXCL		0x02

/*
 * define common-used conversion and calculation macros
 */
#define	FRM2SS(x_frm)							\
	((fcoet_soft_state_t *)(x_frm)->frm_eport->eport_client_private)
#define	FRM2TFM(x_frm)	((fcoet_frame_t *)(x_frm)->frm_client_private)

#define	PORT2SS(x_port)	((fcoet_soft_state_t *)(x_port)->port_fca_private)
#define	EPORT2SS(x_port) ((fcoet_soft_state_t *)(x_port)->eport_client_private)

#define	XCH2ELS(x_xch)	((fct_els_t *)x_xch->xch_cmd->cmd_specific)
#define	XCH2CT(x_xch)	((fct_ct_t *)x_xch->xch_cmd->cmd_specific)
#define	XCH2TASK(x_xch)	((scsi_task_t *)x_xch->xch_cmd->cmd_specific)

#define	CMD2ELS(x_cmd)	((fct_els_t *)x_cmd->cmd_specific)
#define	CMD2CT(x_cmd)	((fct_sol_ct_t *)x_cmd->cmd_specific)
#define	CMD2TASK(x_cmd)	((scsi_task_t *)x_cmd->cmd_specific)
#define	CMD2XCH(x_cmd)	((fcoet_exchange_t *)x_cmd->cmd_fca_private)
#define	CMD2SS(x_cmd)							\
	((fcoet_soft_state_t *)(x_cmd)->cmd_port->port_fca_private)

void fcoet_init_tfm(fcoe_frame_t *frm, fcoet_exchange_t *xch);
fct_status_t fcoet_send_status(fct_cmd_t *cmd);
void fcoet_modhash_find_cb(mod_hash_key_t, mod_hash_val_t);

/*
 * DBUF stuff
 */
#define	FCOET_DB_SEG_NUM(x_db) (x_db->db_port_private)
#define	FCOET_DB_NETB(x_db)						\
	(((uintptr_t)FCOET_DB_SEG_NUM(x_db)) *			\
	sizeof (struct stmf_sglist_ent) + (uintptr_t)(x_db)->db_sglist)

#define	FCOET_SET_SEG_NUM(x_db, x_num)			\
	{						\
		FCOET_DB_SEG_NUM(x_db) = (void *)(unsigned long)x_num;	\
	}

#define	FCOET_GET_SEG_NUM(x_db)	((int)(unsigned long)FCOET_DB_SEG_NUM(x_db))


#define	FCOET_SET_NETB(x_db, x_idx, x_netb)				\
	{								\
		((void **)FCOET_DB_NETB(x_db))[x_idx] = x_netb;	\
	}

#define	FCOET_GET_NETB(x_db, x_idx)		\
	(((void **)FCOET_DB_NETB(x_db))[x_idx])

#define	PRT_FRM_HDR(x_p, x_f)						\
	{								\
		FCOET_LOG(x_p, "rctl/%x, type/%x, fctl/%x, oxid/%x",	\
		    FRM_R_CTL(x_f),		\
		    FRM_TYPE(x_f),		\
		    FRM_F_CTL(x_f),		\
		    FRM_OXID(x_f));		\
	}

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _FCOET_H */
