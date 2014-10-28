/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>

#ifdef SFCT_SUPPORT


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_FCT_C);

static void emlxs_fct_memseg_init(emlxs_hba_t *hba);

static fct_status_t emlxs_fct_cmd_acquire(emlxs_port_t *port,
	fct_cmd_t *fct_cmd, uint16_t fct_state);
static fct_status_t emlxs_fct_cmd_accept(emlxs_port_t *port,
	fct_cmd_t *fct_cmd, uint16_t fct_state);
static void emlxs_fct_cmd_release(emlxs_port_t *port, fct_cmd_t *fct_cmd,
	uint16_t fct_state);

static emlxs_buf_t *emlxs_fct_cmd_init(emlxs_port_t *port,
    fct_cmd_t *fct_cmd, uint16_t fct_state);
static void emlxs_fct_cmd_done(emlxs_port_t *port, fct_cmd_t *fct_cmd,
	uint16_t fct_state);
static void emlxs_fct_cmd_post(emlxs_port_t *port, fct_cmd_t *fct_cmd,
	uint16_t fct_state);

static fct_status_t emlxs_fct_flogi_xchg(struct fct_local_port *fct_port,
    struct fct_flogi_xchg *fx);
static fct_status_t emlxs_fct_get_link_info(fct_local_port_t *fct_port,
    fct_link_info_t *link);
static fct_status_t emlxs_fct_deregister_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *port_handle);
static fct_status_t emlxs_fct_send_cmd(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_fcp_data(fct_cmd_t *fct_cmd,
    stmf_data_buf_t *dbuf, uint32_t ioflags);
static fct_status_t emlxs_fct_send_cmd_rsp(fct_cmd_t *fct_cmd, uint32_t flags);
static fct_status_t emlxs_fct_abort(fct_local_port_t *fct_port,
    fct_cmd_t *cmd, uint32_t flags);
static void emlxs_fct_ctl(fct_local_port_t *fct_port, int cmd, void *arg);
static fct_status_t emlxs_fct_register_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *port_handle, fct_cmd_t *plogi);
static fct_status_t emlxs_fct_send_els_cmd(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_ct_cmd(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_fcp_status(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_els_rsp(fct_cmd_t *fct_cmd);
static void emlxs_fct_pkt_comp(fc_packet_t *pkt);
static void emlxs_fct_populate_hba_details(fct_local_port_t *fct_port,
    fct_port_attrs_t *port_attrs);
static fct_status_t emlxs_fct_port_info(uint32_t cmd,
    fct_local_port_t *fct_port, void *arg, uint8_t *buffer, uint32_t *size);

static fct_status_t emlxs_fct_dmem_init(emlxs_port_t *port);
static void emlxs_fct_dmem_fini(emlxs_port_t *port);

static stmf_data_buf_t *emlxs_fct_dbuf_alloc(fct_local_port_t *fct_port,
    uint32_t size, uint32_t *pminsize, uint32_t flags);
static void emlxs_fct_dbuf_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf);

static int emlxs_fct_dbuf_dma_sync(emlxs_hba_t *hba, stmf_data_buf_t *dbuf,
    uint_t sync_type);
static emlxs_buf_t *emlxs_fct_pkt_init(emlxs_port_t *port,
    fct_cmd_t *fct_cmd, fc_packet_t *pkt);

static void emlxs_fct_unsol_flush_thread(emlxs_hba_t *hba, void *arg1,
    void *arg2);
static void emlxs_fct_unsol_flush(emlxs_port_t *port);
static uint32_t emlxs_fct_process_unsol_flogi(emlxs_port_t *port,
    CHANNEL *cp, IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static uint32_t emlxs_fct_process_unsol_plogi(emlxs_port_t *port,
    CHANNEL *cp, IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static uint32_t emlxs_fct_pkt_abort_txq(emlxs_port_t *port,
    emlxs_buf_t *cmd_sbp);
static fct_status_t emlxs_fct_send_qfull_reply(emlxs_port_t *port,
    emlxs_node_t *ndlp, uint16_t xid, uint32_t class, emlxs_fcp_cmd_t *fcp_cmd);

#ifdef FCT_IO_TRACE
uint8_t *emlxs_iotrace = 0;	/* global for mdb */
int emlxs_iotrace_cnt = 0;

/*
 *
 * FCT_CMD  (cmd_sbp->fct_state)
 *
 * STATE				LOCK STATUS			OWNER
 * -----------------------------------------------------------------------------
 * EMLXS_FCT_ABORT_DONE			Lock Destroyed			COMSTAR
 * EMLXS_FCT_IO_DONE			Lock Destroyed			COMSTAR
 *
 * EMLXS_FCT_CMD_POSTED			Lock Released			COMSTAR
 * EMLXS_FCT_OWNED			Lock Released			COMSTAR
 *
 * EMLXS_FCT_CMD_WAITQ			Lock Released			DRIVER
 * EMLXS_FCT_RSP_PENDING		Lock Released			DRIVER
 * EMLXS_FCT_REQ_PENDING		Lock Released			DRIVER
 * EMLXS_FCT_REG_PENDING		Lock Released			DRIVER
 * EMLXS_FCT_DATA_PENDING		Lock Released			DRIVER
 * EMLXS_FCT_STATUS_PENDING		Lock Released			DRIVER
 * EMLXS_FCT_CLOSE_PENDING		Lock Released			DRIVER
 * EMLXS_FCT_ABORT_PENDING		Lock Released			DRIVER
 *
 * EMLXS_FCT_FCP_CMD_RECEIVED		Transistional, lock held	DRIVER
 * EMLXS_FCT_ELS_CMD_RECEIVED		Transistional, lock held	DRIVER
 * EMLXS_FCT_SEND_CMD_RSP		Transistional, lock held	DRIVER
 * EMLXS_FCT_SEND_ELS_RSP		Transistional, lock held	DRIVER
 * EMLXS_FCT_SEND_ELS_REQ		Transistional, lock held	DRIVER
 * EMLXS_FCT_SEND_CT_REQ		Transistional, lock held	DRIVER
 * EMLXS_FCT_REG_COMPLETE		Transistional, lock held	DRIVER
 * EMLXS_FCT_SEND_FCP_DATA		Transistional, lock held	DRIVER
 * EMLXS_FCT_SEND_FCP_STATUS		Transistional, lock held	DRIVER
 * EMLXS_FCT_PKT_COMPLETE		Transistional, lock held	DRIVER
 * EMLXS_FCT_PKT_FCPRSP_COMPLETE	Transistional, lock held	DRIVER
 * EMLXS_FCT_PKT_ELSRSP_COMPLETE	Transistional, lock held	DRIVER
 * EMLXS_FCT_PKT_ELSCMD_COMPLETE	Transistional, lock held	DRIVER
 * EMLXS_FCT_PKT_CTCMD_COMPLETE		Transistional, lock held	DRIVER
 * EMLXS_FCT_REQ_COMPLETE		Transistional, lock held	DRIVER
 *
 *
 * 	COMSTAR OWNED	DRIVER OWNED
 * 	-------------	---------------------------------------------------
 * 	------- >	@	   Accept---- >Release  @   Acquire--- >+
 *									|
 *	< -------	@	Post/Done< ----Acquire  @   Release< ---+
 *
 * 	@  :Indicates COMSTAR use of emlxs_fct_abort()
 *	    Abort requests set the EMLXS_FCT_ABORT_INP flag.
 *
 * 	Accept		:Indicates use of emlxs_fct_cmd_accept()
 * 	Acquire		:Indicates use of emlxs_fct_cmd_acquire()
 * 	Post		:Indicates use of emlxs_fct_cmd_post()
 * 	Done		:Indicates use of emlxs_fct_cmd_done()
 */

void
emlxs_fct_io_trace(emlxs_port_t *port, fct_cmd_t *fct_cmd, uint32_t data)
{
	emlxs_iotrace_t *iop = port->iotrace;
	uint16_t iotrace_cnt;
	uint16_t iotrace_index;
	int i;

	if (!iop) {
		return;
	}

	mutex_enter(&port->iotrace_mtx);
	iotrace_cnt = port->iotrace_cnt;
	iotrace_index = port->iotrace_index;

	switch (data) {

		/* New entry */
	case EMLXS_FCT_ELS_CMD_RECEIVED:
	case EMLXS_FCT_FCP_CMD_RECEIVED:
	case EMLXS_FCT_SEND_ELS_REQ:
	case EMLXS_FCT_SEND_CT_REQ:
		for (i = 0; i < iotrace_cnt; i++) {
			if ((iop->fct_cmd == fct_cmd) &&
			    (iop->trc[0] != (uint8_t)(0)))
				break;
			iop++;
		}
		if (i < iotrace_cnt) {
			/* New entry already exists */
			mutex_exit(&port->iotrace_mtx);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "IOTRACE: New entry already exists: fct_cmd: %p",
			    fct_cmd);
			return;
		}
		iop = port->iotrace + iotrace_index;
		for (i = 0; i < iotrace_cnt; i++) {
			if (iop->trc[0] == (uint8_t)(0))
				break;

			iop++;
			if (iop == (port->iotrace + iotrace_cnt))
				iop = port->iotrace;
		}
		if (i >= iotrace_cnt) {
			/* No new slots available */
			mutex_exit(&port->iotrace_mtx);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "IOTRACE: No new slots: fct_cmd: %p data: %d",
			    fct_cmd, data);
			return;
		}
		port->iotrace_index++;
		if (port->iotrace_index >= iotrace_cnt)
			port->iotrace_index = 0;

		bzero((uint8_t *)iop, sizeof (emlxs_iotrace_t));
		iop->fct_cmd = fct_cmd;
		iop->xri = fct_cmd->cmd_rxid;
		iop->marker = 0xff;
		iop->trc[0] = 2;
		iop->trc[1] = data;
		mutex_exit(&port->iotrace_mtx);
		return;
	}

	for (i = 0; i < iotrace_cnt; i++) {
		if ((iop->fct_cmd == fct_cmd) &&
		    (iop->trc[0] != (uint8_t)(0)))
			break;
		iop++;
	}
	if (i >= iotrace_cnt) {
		/* Cannot find existing slot for fct_cmd */
		mutex_exit(&port->iotrace_mtx);

		if ((data != EMLXS_FCT_REG_PENDING) &&
		    (data != EMLXS_FCT_REG_COMPLETE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "IOTRACE: Missing slot: fct_cmd: %p data: %d",
			    fct_cmd, data);
		}
		return;
	}

	if (iop->trc[0] >= MAX_IO_TRACE) {
		/* trc overrun for fct_cmd */
		mutex_exit(&port->iotrace_mtx);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "IOTRACE: trc overrun slot: fct_cmd: %p data: %d",
		    fct_cmd, data);
		return;
	}

	if (iop->xri != fct_cmd->cmd_rxid) {
		/* xri mismatch for fct_cmd */
		mutex_exit(&port->iotrace_mtx);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "IOTRACE: xri mismatch %x != %x: fct_cmd: %p data: %d",
		    iop->xri, fct_cmd->cmd_rxid, fct_cmd, data);
		return;
	}

	iop->trc[iop->trc[0]] = data;
	if ((data == EMLXS_FCT_IO_DONE) || (data == EMLXS_FCT_ABORT_DONE)) {
		/* IOCB ULPCOMMAND is saved after EMLXS_FCT_IOCB_ISSUED */
		if (iop->trc[iop->trc[0]-1] == EMLXS_FCT_IOCB_ISSUED) {
			iop->trc[0]++;
		} else {
			iop->trc[0] = 0;
	} else {
		iop->trc[0]++;
	}
	mutex_exit(&port->iotrace_mtx);

	return;

} /* emlxs_fct_io_trace() */
#endif /* FCT_IO_TRACE */

#ifdef MODSYM_SUPPORT

extern int
emlxs_fct_modopen()
{
	int err;

	mutex_enter(&emlxs_device.lock);

	if (emlxs_modsym.fct_modopen) {
		mutex_exit(&emlxs_device.lock);
		return (0);
	}

	emlxs_modsym.fct_modopen++;

	/* Comstar (fct) */
	err = 0;
	emlxs_modsym.mod_fct = ddi_modopen("drv/fct", KRTLD_MODE_FIRST, &err);
	if (!emlxs_modsym.mod_fct) {

		cmn_err(CE_WARN, "?%s: ddi_modopen drv/fct failed: err %d",
		    DRIVER_NAME, err);
		goto failed;
	}

	/* Comstar (stmf) */
	err = 0;
	emlxs_modsym.mod_stmf =
	    ddi_modopen("drv/stmf", KRTLD_MODE_FIRST, &err);
	if (!emlxs_modsym.mod_stmf) {

		cmn_err(CE_WARN, "?%s: ddi_modopen drv/stmf failed: err %d",
		    DRIVER_NAME, err);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_alloc is present */
	emlxs_modsym.fct_alloc = (void *(*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_alloc", &err);
	if ((void *)emlxs_modsym.fct_alloc == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_alloc not present", DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_free is present */
	emlxs_modsym.fct_free = (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_free", &err);
	if ((void *)emlxs_modsym.fct_free == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_free not present", DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_scsi_task_alloc is present */
	emlxs_modsym.fct_scsi_task_alloc =
	    (void *(*)(void *, uint16_t, uint32_t, uint8_t *,
	    uint16_t, uint16_t))ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_scsi_task_alloc", &err);
	if ((void *)emlxs_modsym.fct_scsi_task_alloc == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_scsi_task_alloc not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_register_local_port is present */
	emlxs_modsym.fct_register_local_port =
	    (int (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_register_local_port", &err);
	if ((void *)emlxs_modsym.fct_register_local_port == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_register_local_port not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_deregister_local_port is present */
	emlxs_modsym.fct_deregister_local_port =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_deregister_local_port", &err);
	if ((void *)emlxs_modsym.fct_deregister_local_port == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_deregister_local_port not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_handle_event is present */
	emlxs_modsym.fct_handle_event =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct, "fct_handle_event",
	    &err);
	if ((void *)emlxs_modsym.fct_handle_event == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_handle_event not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_post_rcvd_cmd is present */
	emlxs_modsym.fct_post_rcvd_cmd =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct, "fct_post_rcvd_cmd",
	    &err);
	if ((void *)emlxs_modsym.fct_post_rcvd_cmd == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_post_rcvd_cmd not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_alloc is present */
	emlxs_modsym.fct_ctl = (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_ctl", &err);
	if ((void *)emlxs_modsym.fct_ctl == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_ctl not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_queue_cmd_for_termination is present */
	emlxs_modsym.fct_queue_cmd_for_termination =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_queue_cmd_for_termination", &err);
	if ((void *)emlxs_modsym.fct_queue_cmd_for_termination == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_queue_cmd_for_termination not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_send_response_done is present */
	emlxs_modsym.fct_send_response_done =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_send_response_done", &err);
	if ((void *)emlxs_modsym.fct_send_response_done == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_send_response_done not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_send_cmd_done is present */
	emlxs_modsym.fct_send_cmd_done =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct, "fct_send_cmd_done",
	    &err);
	if ((void *)emlxs_modsym.fct_send_cmd_done == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_send_cmd_done not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_scsi_xfer_data_done is present */
	emlxs_modsym.fct_scsi_data_xfer_done =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_scsi_data_xfer_done", &err);
	if ((void *)emlxs_modsym.fct_scsi_data_xfer_done == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_scsi_data_xfer_done not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_port_shutdown is present */
	emlxs_modsym.fct_port_shutdown =
	    (fct_status_t(*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_port_shutdown", &err);
	if ((void *)emlxs_modsym.fct_port_shutdown == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_port_shutdown not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_port_initialize is present */
	emlxs_modsym.fct_port_initialize =
	    (fct_status_t(*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_port_initialize", &err);
	if ((void *)emlxs_modsym.fct_port_initialize == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_port_initialize not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_cmd_fca_aborted is present */
	emlxs_modsym.fct_cmd_fca_aborted =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_cmd_fca_aborted", &err);
	if ((void *)emlxs_modsym.fct_cmd_fca_aborted == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_cmd_fca_aborted not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the fct fct_handle_rcvd_flogi is present */
	emlxs_modsym.fct_handle_rcvd_flogi =
	    (fct_status_t(*)())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_handle_rcvd_flogi", &err);
	if ((void *)emlxs_modsym.fct_handle_rcvd_flogi == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_handle_rcvd_flogi not present",
		    DRIVER_NAME);
		goto failed;
	}

	/* Comstar (stmf) */
	err = 0;
	/* Check if the stmf stmf_alloc is present */
	emlxs_modsym.stmf_alloc =
	    (void *(*)())ddi_modsym(emlxs_modsym.mod_stmf, "stmf_alloc",
	    &err);
	if ((void *)emlxs_modsym.stmf_alloc == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_alloc not present", DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the stmf stmf_free is present */
	emlxs_modsym.stmf_free = (void (*)())ddi_modsym(emlxs_modsym.mod_stmf,
	    "stmf_free", &err);
	if ((void *)emlxs_modsym.stmf_free == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_free not present", DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the stmf stmf_deregister_port_provider is present */
	emlxs_modsym.stmf_deregister_port_provider =
	    (void (*)())ddi_modsym(emlxs_modsym.mod_stmf,
	    "stmf_deregister_port_provider", &err);
	if ((void *)emlxs_modsym.stmf_deregister_port_provider == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_deregister_port_provider not present",
		    DRIVER_NAME);
		goto failed;
	}

	err = 0;
	/* Check if the stmf stmf_register_port_provider is present */
	emlxs_modsym.stmf_register_port_provider =
	    (int (*)())ddi_modsym(emlxs_modsym.mod_stmf,
	    "stmf_register_port_provider", &err);
	if ((void *)emlxs_modsym.stmf_register_port_provider == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_register_port_provider not present",
		    DRIVER_NAME);
		goto failed;
	}

	mutex_exit(&emlxs_device.lock);
	return (0);

failed:

	mutex_exit(&emlxs_device.lock);
	emlxs_fct_modclose();
	return (1);

} /* emlxs_fct_modopen() */


extern void
emlxs_fct_modclose()
{
	mutex_enter(&emlxs_device.lock);

	if (emlxs_modsym.fct_modopen == 0) {
		mutex_exit(&emlxs_device.lock);
		return;
	}

	emlxs_modsym.fct_modopen--;

	if (emlxs_modsym.fct_modopen) {
		mutex_exit(&emlxs_device.lock);
		return;
	}

	if (emlxs_modsym.mod_fct) {
		(void) ddi_modclose(emlxs_modsym.mod_fct);
		emlxs_modsym.mod_fct = 0;
	}

	if (emlxs_modsym.mod_stmf) {
		(void) ddi_modclose(emlxs_modsym.mod_stmf);
		emlxs_modsym.mod_stmf = 0;
	}

	emlxs_modsym.fct_alloc = NULL;
	emlxs_modsym.fct_free = NULL;
	emlxs_modsym.fct_scsi_task_alloc = NULL;
	emlxs_modsym.fct_register_local_port = NULL;
	emlxs_modsym.fct_deregister_local_port = NULL;
	emlxs_modsym.fct_handle_event = NULL;
	emlxs_modsym.fct_ctl = NULL;
	emlxs_modsym.fct_queue_cmd_for_termination = NULL;
	emlxs_modsym.fct_send_response_done = NULL;
	emlxs_modsym.fct_send_cmd_done = NULL;
	emlxs_modsym.fct_scsi_data_xfer_done = NULL;
	emlxs_modsym.fct_port_shutdown = NULL;
	emlxs_modsym.fct_port_initialize = NULL;
	emlxs_modsym.fct_cmd_fca_aborted = NULL;
	emlxs_modsym.fct_handle_rcvd_flogi = NULL;

	emlxs_modsym.stmf_alloc = NULL;
	emlxs_modsym.stmf_free = NULL;
	emlxs_modsym.stmf_deregister_port_provider = NULL;
	emlxs_modsym.stmf_register_port_provider = NULL;

	mutex_exit(&emlxs_device.lock);

} /* emlxs_fct_modclose() */

#endif /* MODSYM_SUPPORT */

/*
 * This routine is called to handle an unsol FLOGI exchange
 *	fx	save
 *	0	1	Process or save port->fx
 *	0	0	Process or reject port->fx
 *	1	1	Process port->fx, Process or save fx
 *	1	0	Process or reject port->fx, Process or reject fx
 */
static void
emlxs_fct_handle_unsol_flogi(emlxs_port_t *port, fct_flogi_xchg_t *fx,
    uint32_t save)
{
	emlxs_hba_t *hba = HBA;
	fct_status_t status;
	IOCBQ iocbq;
	fct_flogi_xchg_t fxchg;

begin:
	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check if there is an old saved FLOGI */
	if (port->fx.fx_op) {
		/* Get it now */
		bcopy(&port->fx, &fxchg, sizeof (fct_flogi_xchg_t));

		if (fx) {
			/* Save new FLOGI */
			bcopy(fx, &port->fx, sizeof (fct_flogi_xchg_t));

			/* Reject old stale FLOGI */
			fx = &fxchg;
			goto reject_it;

		} else {
			bzero(&port->fx, sizeof (fct_flogi_xchg_t));
			fx = &fxchg;
		}

	} else if (!fx) {
		/* Nothing to do, just return */
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* We have a valid FLOGI here */
	/* There is no saved FLOGI at this point either */

	/* Check if COMSTAR is ready to accept it */
	if (port->fct_flags & FCT_STATE_LINK_UP_ACKED) {
		mutex_exit(&EMLXS_PORT_LOCK);

		bzero((uint8_t *)&iocbq, sizeof (IOCBQ));
		iocbq.iocb.un.elsreq.remoteID = fx->fx_sid;
		iocbq.iocb.un.elsreq.myID = fx->fx_did;
		iocbq.iocb.ULPCONTEXT = (uint16_t)fx->rsvd2;
		fx->rsvd2 = 0; /* Clear the reserved field now */

		status = MODSYM(fct_handle_rcvd_flogi) (port->fct_port, fx);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_handle_rcvd_flogi %p: status=%x",
		    port->fct_port, status);
#endif /* FCT_API_TRACE */

		if (status == FCT_SUCCESS) {
			if (fx->fx_op == ELS_OP_ACC) {
				(void) emlxs_els_reply(port, &iocbq,
				    ELS_CMD_ACC, ELS_CMD_FLOGI, 0, 0);

			} else {	/* ELS_OP_LSRJT */
				(void) emlxs_els_reply(port, &iocbq,
				    ELS_CMD_LS_RJT, ELS_CMD_FLOGI,
				    fx->fx_rjt_reason, fx->fx_rjt_expl);
			}
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
			    "FLOGI: sid=%x xid=%x. "
			    "fct_handle_rcvd_flogi failed. Rejecting.",
			    fx->fx_sid, iocbq.iocb.ULPCONTEXT);

			(void) emlxs_els_reply(port, &iocbq,
			    ELS_CMD_LS_RJT, ELS_CMD_FLOGI,
			    LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);
		}

		return;
	}

	if (save) {
		/* Save FLOGI for later */
		bcopy(fx, &port->fx, sizeof (fct_flogi_xchg_t));
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

reject_it:

	mutex_exit(&EMLXS_PORT_LOCK);

	if (port->fct_flags & FCT_STATE_LINK_UP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "FLOGI: sid=%x xid=%x. Stale. Rejecting.",
		    fx->fx_sid, fx->rsvd2);

		bzero((uint8_t *)&iocbq, sizeof (IOCBQ));
		iocbq.iocb.un.elsreq.remoteID = fx->fx_sid;
		iocbq.iocb.un.elsreq.myID = fx->fx_did;
		iocbq.iocb.ULPCONTEXT = fx->rsvd2;

		(void) emlxs_els_reply(port, &iocbq,
		    ELS_CMD_LS_RJT, ELS_CMD_FLOGI,
		    LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

		/* If we have an FLOGI saved, try sending it now */
		if (port->fx.fx_op) {
			fx = NULL;
			goto begin;
		}

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "FLOGI: sid=%x xid=%x. Link down. "
		    "Dropping.",
		    fx->fx_sid, fx->rsvd2);
	}

	return;

} /* emlxs_fct_handle_unsol_flogi() */


/* ARGSUSED */
static void
emlxs_fct_unsol_flush_thread(emlxs_hba_t *hba, void *arg1, void *arg2)
{
	emlxs_port_t *port = (emlxs_port_t *)arg1;

	emlxs_fct_unsol_flush(port);
	return;

} /* emlxs_fct_unsol_flush_thread() */


/* This is called at port online and offline */
static void
emlxs_fct_unsol_flush(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	emlxs_buf_t *next;
	fct_cmd_t *fct_cmd;
	fct_status_t rval;
	uint32_t cmd_code;

	if (!port->fct_port) {
		return;
	}

	/* First handle any pending FLOGI */
	emlxs_fct_handle_unsol_flogi(port, NULL, 0);

	if ((port->fct_flags & FCT_STATE_LINK_UP_ACKED) &&
	    !(port->fct_flags & FCT_STATE_FLOGI_CMPL)) {
		return;
	}

	/* Wait queue */
	mutex_enter(&EMLXS_PORT_LOCK);
	cmd_sbp = port->fct_wait_head;
	port->fct_wait_head = NULL;
	port->fct_wait_tail = NULL;
	mutex_exit(&EMLXS_PORT_LOCK);

	/*
	 * Next process any outstanding ELS commands. It doesn't
	 * matter if the Link is up or not, always post them to FCT.
	 */
	while (cmd_sbp) {
		next = cmd_sbp->next;
		fct_cmd = cmd_sbp->fct_cmd;

		cmd_code = (fct_cmd->cmd_oxid << ELS_CMD_SHIFT);

		/* Reacquire ownership of the fct_cmd */
		rval = emlxs_fct_cmd_acquire(port, fct_cmd, 0);
		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_unsol_flush: %s: sid=%x xid=%x "
			    "Unable to reacquire fct_cmd.",
			    emlxs_elscmd_xlate(cmd_code),
			    fct_cmd->cmd_rxid, fct_cmd->cmd_rportid);

			cmd_sbp = next;
			continue;
		}
		/* mutex_enter(&cmd_sbp->fct_mtx); */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Posting %s: sid=%x xid=%x %p",
		    emlxs_elscmd_xlate(cmd_code),
		    fct_cmd->cmd_rportid, fct_cmd->cmd_rxid,
		    fct_cmd);

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_post_rcvd_cmd:2 %p:%p portid x%x", fct_cmd, cmd_sbp,
		    fct_cmd->cmd_lportid);
#endif /* FCT_API_TRACE */

		MODSYM(fct_post_rcvd_cmd) (fct_cmd, 0);

		cmd_sbp = next;

	}	/* while () */

	return;

} /* emlxs_fct_unsol_flush() */


int
emlxs_is_digit(uint8_t chr)
{
	if ((chr >= '0') && (chr <= '9')) {
		return (1);
	}

	return (0);

} /* emlxs_is_digit */


/*
 *   Convert an ASCII decimal numeric string to integer.
 *   Negation character '-' is not handled.
 */
static uint32_t
emlxs_str_atoi(uint8_t *string)
{
	uint32_t num = 0;
	int i = 0;

	while (string[i]) {
		if (!emlxs_is_digit(string[i])) {
			return (num);
		}

		num = num * 10 + (string[i++] - '0');
	}

	return (num);

} /* emlxs_str_atoi() */


extern uint32_t
emlxs_fct_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;

	/* Check if COMSTAR is present */
	if (((void *)MODSYM(stmf_alloc) == NULL) ||
	    ((void *)MODSYM(fct_alloc) == NULL)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Comstar not present.");
		return (1);
	}

	return (0);

} /* emlxs_fct_init() */


extern void
emlxs_fct_attach(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t vpi;

	if (!(port->flag & EMLXS_TGT_ENABLED)) {
		return;
	}

	/* Bind the physical port */
	emlxs_fct_bind_port(port);

	/* Bind virtual ports */
	if (hba->flag & FC_NPIV_ENABLED) {
		for (vpi = 1; vpi <= hba->vpi_high; vpi++) {
			port = &VPORT(vpi);

			if (!(port->flag & EMLXS_PORT_ENABLED)) {
				continue;
			}

			emlxs_fct_bind_port(port);
		}
	}

	return;

} /* emlxs_fct_attach() */


extern void
emlxs_fct_detach(emlxs_hba_t *hba)
{
	uint32_t i;
	emlxs_port_t *vport;

	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		if (!(vport->flag & EMLXS_PORT_ENABLED)) {
			continue;
		}

		emlxs_fct_unbind_port(vport);
	}

#ifdef FCT_IO_TRACE
{
	emlxs_port_t *port = &PPORT;

	mutex_destroy(&port->iotrace_mtx);
	if (port->iotrace) {
		kmem_free(port->iotrace,
		    (port->iotrace_cnt * sizeof (emlxs_iotrace_t)));
	}
	port->iotrace = NULL;
}
#endif /* FCT_IO_TRACE */

	return;

} /* emlxs_fct_detach() */


extern void
emlxs_fct_unbind_port(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	char node_name[32];

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->flag & EMLXS_TGT_BOUND)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "fct_unbind_port: port=%d", port->vpi);

	/* Destroy & flush all port nodes, if they exist */
	if (port->node_count) {
		(void) EMLXS_SLI_UNREG_NODE(port, NULL, NULL, NULL, NULL);
	}

	port->flag &= ~EMLXS_TGT_BOUND;
	port->flag &= ~EMLXS_TGT_ENABLED;
	hba->num_of_ports--;
	mutex_exit(&EMLXS_PORT_LOCK);

	if (port->fct_port) {
		emlxs_fct_link_down(port);
		emlxs_fct_unsol_flush(port);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_deregister_local_port %p", port->fct_port);
#endif /* FCT_API_TRACE */
		MODSYM(fct_deregister_local_port) (port->fct_port);

		if (port->fct_port->port_fds) {
#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_free:3 %p", port->fct_port->port_fds);
#endif /* FCT_API_TRACE */
			MODSYM(fct_free) (port->fct_port->port_fds);
			port->fct_port->port_fds = NULL;
		}
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_free:4 %p", port->fct_port);
#endif /* FCT_API_TRACE */
		MODSYM(fct_free) (port->fct_port);
		port->fct_port = NULL;
		port->fct_flags = 0;
	}

	if (port->port_provider) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_deregister_port_provider:1 %p",
		    port->port_provider);
#endif /* FCT_API_TRACE */
		MODSYM(stmf_deregister_port_provider) (port->port_provider);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_free:1 %p", port->port_provider);
#endif /* FCT_API_TRACE */
		MODSYM(stmf_free) (port->port_provider);
		port->port_provider = NULL;
	}

	if (port->fct_memseg) {
		emlxs_fct_dmem_fini(port);
	}

	(void) snprintf(node_name, sizeof (node_name), "%d,%d:SFCT",
	    hba->ddiinst, port->vpi);
	(void) ddi_remove_minor_node(hba->dip, node_name);

	return;

} /* emlxs_fct_unbind_port() */


extern void
emlxs_fct_bind_port(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	fct_local_port_t *fct_port;
	uint32_t flag = 0;
	emlxs_config_t *cfg = &CFG;
	fct_dbuf_store_t *fds;
	char node_name[32];
	uint8_t *bptr;

	if (!(port->flag & EMLXS_TGT_ENABLED)) {
		return;
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	if (port->flag & EMLXS_TGT_BOUND) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "fct_bind_port: port=%d", port->vpi);

	/* Perform generic port initialization */
	emlxs_port_init(port);

	if (port->vpi == 0) {
		(void) snprintf(port->cfd_name, sizeof (port->cfd_name),
		    "%s%d", DRIVER_NAME, hba->ddiinst);
	} else {
		(void) snprintf(port->cfd_name, sizeof (port->cfd_name),
		    "%s%d.%d", DRIVER_NAME, hba->ddiinst, port->vpi);
	}

	if (emlxs_fct_dmem_init(port) != FCT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_bind_port: Unable to allocate fct memory.");
		goto failed;
	}
	flag |= 0x00000001;

	port->port_provider =
	    (stmf_port_provider_t *)
	    MODSYM(stmf_alloc) (STMF_STRUCT_PORT_PROVIDER, 0, 0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "stmf_alloc port_provider %p", port->port_provider);
#endif /* FCT_API_TRACE */

	if (port->port_provider == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_bind_port: Unable to allocate port provider.");
		goto failed;
	}
	flag |= 0x00000002;

	port->port_provider->pp_portif_rev = PORTIF_REV_1;
	port->port_provider->pp_name = port->cfd_name;
	port->port_provider->pp_provider_private = port;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "stmf_register_port_provider %p", port->port_provider);
#endif /* FCT_API_TRACE */
	/* register port provider with framework */
	if (MODSYM(stmf_register_port_provider) (port->port_provider) !=
	    STMF_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_bind_port: Unable to register port provider.");
		goto failed;
	}
	flag |= 0x00000004;

	port->fct_port =
	    (fct_local_port_t *)MODSYM(fct_alloc) (FCT_STRUCT_LOCAL_PORT, 0,
	    0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_alloc fct_port %p", port->fct_port);
#endif /* FCT_API_TRACE */

	if (port->fct_port == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_bind_port: Unable to allocate fct port.");
		goto failed;
	}
	flag |= 0x00000008;

	port->fct_port->port_fds =
	    (fct_dbuf_store_t *)MODSYM(fct_alloc) (FCT_STRUCT_DBUF_STORE, 0,
	    0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_alloc port_fds %p", port->fct_port->port_fds);
#endif /* FCT_API_TRACE */

	if (port->fct_port->port_fds == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_bind_port: Unable to allocate dbuf store.");
		goto failed;
	}
	flag |= 0x00000010;

	(void) snprintf(node_name, sizeof (node_name), "%d,%d:SFCT",
	    hba->ddiinst, port->vpi);
	if (ddi_create_minor_node(hba->dip, node_name, S_IFCHR, hba->ddiinst,
	    NULL, 0) == DDI_FAILURE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "Unable to create SFCT device node.");
		goto failed;
	}
	flag |= 0x00000020;

	/* Intialize */
	fct_port = port->fct_port;
	fct_port->port_fca_version = FCT_FCA_MODREV_1;
	fct_port->port_fca_private = port;
	fct_port->port_fca_abort_timeout = 30 * 1000;	/* 30 seconds */

	bcopy((uint8_t *)&port->wwpn, (uint8_t *)fct_port->port_pwwn, 8);
	bcopy((uint8_t *)&port->wwnn, (uint8_t *)fct_port->port_nwwn, 8);

	bptr = (uint8_t *)&port->wwnn;
	(void) snprintf(fct_port->port_nwwn_str, FC_WWN_BUFLEN,
	    "%02x%02x%02x%02x%02x%02x%02x%02x",
	    bptr[0], bptr[1], bptr[2], bptr[3],
	    bptr[4], bptr[5], bptr[6], bptr[7]);

	bptr = (uint8_t *)&port->wwpn;
	(void) snprintf(fct_port->port_pwwn_str, FC_WWN_BUFLEN,
	    "%02x%02x%02x%02x%02x%02x%02x%02x",
	    bptr[0], bptr[1], bptr[2], bptr[3],
	    bptr[4], bptr[5], bptr[6], bptr[7]);

	fct_port->port_sym_node_name = port->snn;
	fct_port->port_sym_port_name = port->spn;
	fct_port->port_hard_address = cfg[CFG_ASSIGN_ALPA].current;
	fct_port->port_default_alias = port->cfd_name;
	fct_port->port_pp = port->port_provider;
	fct_port->port_max_logins = hba->max_nodes + EMLXS_FCT_NUM_ELS_ONLY;

	if (cfg[CFG_FCT_QDEPTH].current &&
	    (cfg[CFG_FCT_QDEPTH].current < hba->io_throttle)) {
		fct_port->port_max_xchges = cfg[CFG_FCT_QDEPTH].current;
	} else {
		fct_port->port_max_xchges = hba->io_throttle;
	}

	fct_port->port_fca_fcp_cmd_size = sizeof (emlxs_buf_t);
	fct_port->port_fca_rp_private_size = sizeof (uintptr_t);
	fct_port->port_fca_sol_els_private_size = sizeof (emlxs_buf_t);
	fct_port->port_fca_sol_ct_private_size = sizeof (emlxs_buf_t);
	fct_port->port_get_link_info = emlxs_fct_get_link_info;
	fct_port->port_register_remote_port = emlxs_fct_register_remote_port;
	fct_port->port_deregister_remote_port =
	    emlxs_fct_deregister_remote_port;
	fct_port->port_send_cmd = emlxs_fct_send_cmd;
	fct_port->port_xfer_scsi_data = emlxs_fct_send_fcp_data;
	fct_port->port_send_cmd_response = emlxs_fct_send_cmd_rsp;
	fct_port->port_abort_cmd = emlxs_fct_abort;
	fct_port->port_ctl = emlxs_fct_ctl;
	fct_port->port_flogi_xchg = emlxs_fct_flogi_xchg;
	fct_port->port_populate_hba_details = emlxs_fct_populate_hba_details;
	fct_port->port_info = emlxs_fct_port_info;

	fds = port->fct_port->port_fds;
	fds->fds_fca_private = port;
	fds->fds_alloc_data_buf = emlxs_fct_dbuf_alloc;
	fds->fds_free_data_buf = emlxs_fct_dbuf_free;

	/* Scatter gather list support */
/*	fds->fds_setup_dbuf = ; */
/*	fds->fds_teardown_dbuf = ; */
/*	fds->fds_max_sgl_xfer_len = ; */
/*	fds->fds_copy_threshold = ; */

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_register_local_port %p", fct_port);
#endif /* FCT_API_TRACE */
	/* register this local port with the fct module */
	if (MODSYM(fct_register_local_port) (fct_port) != FCT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_bind_port: Unable to register fct port.");
		goto failed;
	}

	/* Set the bound flag */
	port->flag |= EMLXS_TGT_BOUND;
	hba->num_of_ports++;

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

failed:

	if (flag & 0x20) {
		(void) ddi_remove_minor_node(hba->dip, node_name);
	}

	if (flag & 0x10) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_free:5 %p", port->fct_port->port_fds);
#endif /* FCT_API_TRACE */
		MODSYM(fct_free) (port->fct_port->port_fds);
		port->fct_port->port_fds = NULL;
	}

	if (flag & 0x8) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_free:6 %p", port->fct_port);
#endif /* FCT_API_TRACE */
		MODSYM(fct_free) (port->fct_port);
		port->fct_port = NULL;
		port->fct_flags = 0;
	}

	if (flag & 0x4) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_deregister_port_provider:2 %p",
		    port->port_provider);
#endif /* FCT_API_TRACE */
		MODSYM(stmf_deregister_port_provider) (port->port_provider);
	}

	if (flag & 0x2) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_free:2 %p", port->port_provider);
#endif /* FCT_API_TRACE */
		MODSYM(stmf_free) (port->port_provider);
		port->port_provider = NULL;
	}

	if (flag & 0x1) {
		emlxs_fct_dmem_fini(port);
	}

	port->flag &= ~EMLXS_TGT_ENABLED;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "Target mode disabled.");

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_fct_bind_port() */


/* COMSTAR ENTER POINT */
/*ARGSUSED*/
static fct_status_t
emlxs_fct_port_info(uint32_t cmd, fct_local_port_t *fct_port, void *arg,
    uint8_t *buffer, uint32_t *size)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	fct_status_t rval = FCT_SUCCESS;
	fct_port_link_status_t *link_status;
	MAILBOX *mb;
	MAILBOXQ *mbq;

	switch (cmd) {
	case FC_TGT_PORT_RLS:
		bzero(buffer, *size);

		if ((*size) < sizeof (fct_port_link_status_t)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
			    "FC_TGT_PORT_RLS: Buffer too small. %d < %d",
			    *size, sizeof (fct_port_link_status_t));

			rval = FCT_FAILURE;
			break;
		}

		if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX)) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
			    "FC_TGT_PORT_RLS: Unable to allocate mailbox.");

			rval = FCT_ALLOC_FAILURE;
			break;
		}
		mb = (MAILBOX *)mbq;

		emlxs_mb_read_lnk_stat(hba, mbq);
		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0)
		    != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
			    "FC_TGT_PORT_RLS: Unable to send request.");

			rval = FCT_BUSY;
		} else {
			link_status = (fct_port_link_status_t *)buffer;
			link_status->LinkFailureCount =
			    mb->un.varRdLnk.linkFailureCnt;
			link_status->LossOfSyncCount =
			    mb->un.varRdLnk.lossSyncCnt;
			link_status->LossOfSignalsCount =
			    mb->un.varRdLnk.lossSignalCnt;
			link_status->PrimitiveSeqProtocolErrorCount =
			    mb->un.varRdLnk.primSeqErrCnt;
			link_status->InvalidTransmissionWordCount =
			    mb->un.varRdLnk.invalidXmitWord;
			link_status->InvalidCRCCount =
			    mb->un.varRdLnk.crcCnt;
		}

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "fct_port_info: Invalid request. cmd=%x",
		    cmd);

		rval = FCT_FAILURE;
		break;

	}

	return (rval);

} /* emlxs_fct_port_info() */


/* COMSTAR ENTER POINT */
static void
emlxs_fct_populate_hba_details(fct_local_port_t *fct_port,
    fct_port_attrs_t *port_attrs)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_vpd_t *vpd = &VPD;

	(void) strncpy(port_attrs->manufacturer, "Emulex",
	    (sizeof (port_attrs->manufacturer)-1));
	(void) strncpy(port_attrs->serial_number, vpd->serial_num,
	    (sizeof (port_attrs->serial_number)-1));
	(void) strncpy(port_attrs->model, hba->model_info.model,
	    (sizeof (port_attrs->model)-1));
	(void) strncpy(port_attrs->model_description,
	    hba->model_info.model_desc,
	    (sizeof (port_attrs->model_description)-1));
	(void) snprintf(port_attrs->hardware_version,
	    (sizeof (port_attrs->hardware_version)-1),
	    "%x", vpd->biuRev);
	(void) snprintf(port_attrs->driver_version,
	    (sizeof (port_attrs->driver_version)-1),
	    "%s (%s)", emlxs_version,
	    emlxs_revision);
	(void) strncpy(port_attrs->option_rom_version, vpd->fcode_version,
	    (sizeof (port_attrs->option_rom_version)-1));
	(void) snprintf(port_attrs->firmware_version,
	    (sizeof (port_attrs->firmware_version)-1),
	    "%s (%s)", vpd->fw_version,
	    vpd->fw_label);
	(void) strncpy(port_attrs->driver_name, DRIVER_NAME,
	    (sizeof (port_attrs->driver_name)-1));
	port_attrs->vendor_specific_id =
	    ((hba->model_info.device_id << 16) | PCI_VENDOR_ID_EMULEX);
	port_attrs->supported_cos = LE_SWAP32(FC_NS_CLASS3);

	port_attrs->max_frame_size = FF_FRAME_SIZE;

	if (vpd->link_speed & LMT_16GB_CAPABLE) {
		port_attrs->supported_speed |= PORT_SPEED_16G;
	}
	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		port_attrs->supported_speed |= PORT_SPEED_10G;
	}
	if (vpd->link_speed & LMT_8GB_CAPABLE) {
		port_attrs->supported_speed |= PORT_SPEED_8G;
	}
	if (vpd->link_speed & LMT_4GB_CAPABLE) {
		port_attrs->supported_speed |= PORT_SPEED_4G;
	}
	if (vpd->link_speed & LMT_2GB_CAPABLE) {
		port_attrs->supported_speed |= PORT_SPEED_2G;
	}
	if (vpd->link_speed & LMT_1GB_CAPABLE) {
		port_attrs->supported_speed |= PORT_SPEED_1G;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: manufacturer       = %s", port_attrs->manufacturer);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: serial_num         = %s", port_attrs->serial_number);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: model              = %s", port_attrs->model);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: model_description  = %s",
	    port_attrs->model_description);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: hardware_version   = %s",
	    port_attrs->hardware_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: driver_version     = %s", port_attrs->driver_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: option_rom_version = %s",
	    port_attrs->option_rom_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: firmware_version   = %s",
	    port_attrs->firmware_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: driver_name        = %s", port_attrs->driver_name);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: vendor_specific_id = 0x%x",
	    port_attrs->vendor_specific_id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: supported_cos      = 0x%x",
	    port_attrs->supported_cos);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: supported_speed    = 0x%x",
	    port_attrs->supported_speed);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: max_frame_size     = 0x%x",
	    port_attrs->max_frame_size);

	return;

} /* emlxs_fct_populate_hba_details() */


/* COMSTAR ENTER POINT */
/* ARGSUSED */
static void
emlxs_fct_ctl(fct_local_port_t *fct_port, int cmd, void *arg)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	stmf_change_status_t st;

	st.st_completion_status = FCT_SUCCESS;
	st.st_additional_info = NULL;

	switch (cmd) {
	case FCT_CMD_PORT_ONLINE:
		/* If the HBA is offline, we cannot bring the tgtport online */
		if (hba->flag & (FC_OFFLINE_MODE | FC_OFFLINING_MODE)) {
			st.st_completion_status = FCT_FAILURE;
			MODSYM(fct_ctl) (fct_port->port_lport,
			    FCT_CMD_PORT_ONLINE_COMPLETE, &st);
			break;
		}

		if (port->fct_flags & FCT_STATE_PORT_ONLINE) {
			st.st_completion_status = STMF_ALREADY;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "STATE: ONLINE chk");
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "STATE: OFFLINE --> ONLINE");

			port->fct_flags |= FCT_STATE_NOT_ACKED;
			port->fct_flags |= FCT_STATE_PORT_ONLINE;

			if ((port->vpi == 0) &&
			    (port->mode == MODE_TARGET) &&
			    (hba->state <= FC_LINK_DOWN)) {
				/* Try to bring the link up */
				(void) emlxs_reset_link(hba, 1, 1);
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "STATE: ONLINE");
		}

		MODSYM(fct_ctl) (fct_port->port_lport,
		    FCT_CMD_PORT_ONLINE_COMPLETE, &st);
		break;

	case FCT_CMD_PORT_OFFLINE:
		if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
			st.st_completion_status = STMF_ALREADY;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "STATE: OFFLINE chk");

		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "STATE: ONLINE --> OFFLINE");

			/* Take link down and flush */
			emlxs_fct_link_down(port);
			emlxs_fct_unsol_flush(port);

			/* Declare this port offline now */
			port->fct_flags |= FCT_STATE_NOT_ACKED;
			port->fct_flags &= ~FCT_STATE_PORT_ONLINE;

			if ((port->vpi == 0) &&
			    (port->mode == MODE_TARGET) &&
			    !(port->flag & EMLXS_INI_ENABLED)) {
				/* Take link down and hold it down */
				(void) emlxs_reset_link(hba, 0, 1);
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "STATE: OFFLINE");
		}

		MODSYM(fct_ctl) (fct_port->port_lport,
		    FCT_CMD_PORT_OFFLINE_COMPLETE, &st);

		break;

	case FCT_ACK_PORT_OFFLINE_COMPLETE:
		port->fct_flags &= ~FCT_STATE_NOT_ACKED;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "STATE: OFFLINE ack");
		break;

	case FCT_ACK_PORT_ONLINE_COMPLETE:
		port->fct_flags &= ~FCT_STATE_NOT_ACKED;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "STATE: ONLINE ack");
		break;

	case FCT_CMD_FORCE_LIP:
		if (port->mode == MODE_INITIATOR) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_ctl: FCT_CMD_FORCE_LIP.");
			break;
		}

		if (hba->fw_flag & FW_UPDATE_NEEDED) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_ctl: FCT_CMD_FORCE_LIP -> "
			    "FCT_CMD_RESET");

			hba->fw_flag |= FW_UPDATE_KERNEL;

			/* Reset the adapter */
			(void) emlxs_reset(port, FC_FCA_RESET);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_ctl: FCT_CMD_FORCE_LIP");

			/* Reset the link */
			(void) emlxs_reset(port, FC_FCA_LINK_RESET);
		}
		break;
	}

	return;

} /* emlxs_fct_ctl() */


extern int
emlxs_fct_port_shutdown(emlxs_port_t *port)
{
	fct_local_port_t *fct_port;
	int i;

	fct_port = port->fct_port;
	if (!fct_port) {
		return (0);
	}

	port->fct_flags |= FCT_STATE_NOT_ACKED;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg, "fct_port_shutdown");
	MODSYM(fct_port_shutdown) (fct_port, STMF_RFLAG_STAY_OFFLINED,
	    DRIVER_NAME" shutdown");

	i = 0;
	while (port->fct_flags & FCT_STATE_NOT_ACKED) {
		i++;
		if (i > 300) {	/* 30 seconds */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_port_shutdown failed to ACK");
			break;
		}
		delay(drv_usectohz(100000));	/* 100 msec */
	}
	return (1);
}


extern int
emlxs_fct_port_initialize(emlxs_port_t *port)
{
	fct_local_port_t *fct_port;
	int i;

	fct_port = port->fct_port;
	if (!fct_port) {
		return (0);
	}

	port->fct_flags |= FCT_STATE_NOT_ACKED;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_port_initialize");
	MODSYM(fct_port_initialize) (fct_port, STMF_RFLAG_STAY_OFFLINED,
	    DRIVER_NAME" initialize");

	i = 0;
	while (port->fct_flags & FCT_STATE_NOT_ACKED) {
		i++;
		if (i > 300) {	/* 30 seconds */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_port_initialize failed to ACK");
			break;
		}
		delay(drv_usectohz(100000));	/* 100 msec */
	}
	return (1);
}


/* COMSTAR ENTER POINT */
static fct_status_t
emlxs_fct_send_cmd(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port;

	port = (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_send_cmd %p:%p  x%x", fct_cmd,
	    fct_cmd->cmd_fca_private, fct_cmd->cmd_type);
#endif /* FCT_API_TRACE */

	switch (fct_cmd->cmd_type) {
	case FCT_CMD_SOL_ELS:

		return (emlxs_fct_send_els_cmd(fct_cmd));

	case FCT_CMD_SOL_CT:

		return (emlxs_fct_send_ct_cmd(fct_cmd));

	default:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_send_cmd: Invalid cmd type found. type=%x",
		    fct_cmd->cmd_type);

		return (FCT_FAILURE);
	}

} /* emlxs_fct_send_cmd() */


/* COMSTAR ENTER POINT */
static fct_status_t
emlxs_fct_send_cmd_rsp(fct_cmd_t *fct_cmd, uint32_t ioflags)
{
	emlxs_port_t *port;
	emlxs_buf_t *cmd_sbp;
	fct_status_t rval;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint32_t status;

	port = (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;

	rval = emlxs_fct_cmd_accept(port, fct_cmd, EMLXS_FCT_SEND_CMD_RSP);
	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_send_cmd_rsp: "
		    "Unable to accept fct_cmd. type=%x",
		    fct_cmd->cmd_type);

		return (rval);
	}
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	iocbq = &cmd_sbp->iocbq;
	iocbq->sbp = cmd_sbp;
	iocb = &iocbq->iocb;
	status = iocb->ULPSTATUS;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_send_cmd_rsp %p:%p x%x, %x, %x",
	    fct_cmd, cmd_sbp, fct_cmd->cmd_type, iocb->ULPCT, status);
#endif /* FCT_API_TRACE */

	switch (fct_cmd->cmd_type) {
	case FCT_CMD_FCP_XCHG:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			goto failure;
		}

		if ((iocb->ULPCT == 0x1) && (status == 0)) {

			/* Firmware already sent out resp */
			cmd_sbp->fct_flags |= EMLXS_FCT_SEND_STATUS;

			TGTPORTSTAT.FctOutstandingIO--;

			emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
			/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_send_response_done:4 %p: x%x",
			    fct_cmd, fct_cmd->cmd_comp_status);

#endif /* FCT_API_TRACE */

			MODSYM(fct_send_response_done) (fct_cmd,
			    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);

			return (FCT_SUCCESS);
		}

		rval =  emlxs_fct_send_fcp_status(fct_cmd);
		if (rval == FCT_NOT_FOUND) {
			goto failure;
		}
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (rval);

	case FCT_CMD_RCVD_ELS:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			goto failure;
		}

		rval =  emlxs_fct_send_els_rsp(fct_cmd);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (rval);

	default:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			fct_cmd->cmd_handle = 0;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_send_cmd_rsp: Invalid cmd type found. type=%x",
		    fct_cmd->cmd_type);

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_FAILURE);
	}

failure:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_send_cmd_rsp: "
	    "Unable to handle FCT_IOF_FORCE_FCA_DONE. type=%x",
	    fct_cmd->cmd_type);

	emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	return (FCT_FAILURE);

} /* emlxs_fct_send_cmd_rsp() */


/* COMSTAR ENTER POINT */
static fct_status_t
emlxs_fct_flogi_xchg(struct fct_local_port *fct_port, struct fct_flogi_xchg *fx)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t size;
	fc_packet_t *pkt = NULL;
	ELS_PKT *els;
	fct_status_t rval = FCT_SUCCESS;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_flogi_xchg: Sending FLOGI: %p", fct_port);
#else
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_flogi_xchg: Sending FLOGI.");
#endif /* FCT_API_TRACE */

	if (hba->state <= FC_LINK_DOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_flogi_xchg: FLOGI failed. Link down.");
		rval = FCT_FAILURE;
		goto done;
	}

	/* Use this entry point as the link up acknowledgment */
	mutex_enter(&EMLXS_PORT_LOCK);
	port->fct_flags |= FCT_STATE_LINK_UP_ACKED;
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_link_up acked.");
	mutex_exit(&EMLXS_PORT_LOCK);

	/* First handle any pending FLOGI's */
	emlxs_fct_handle_unsol_flogi(port, NULL, 0);

	size = sizeof (SERV_PARM) + 4;

	if (!(pkt = emlxs_pkt_alloc(port, size, size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_flogi_xchg: FLOGI failed. "
		    "Unable allocate packet.");
		rval = FCT_FAILURE;
		goto done;
	}

	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = fx->fx_sec_timeout;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(fx->fx_did);
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(fx->fx_sid);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_FIRST_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	/* Service paramters will be added automatically later by the driver */
	els = (ELS_PKT *)pkt->pkt_cmd;
	els->elsCode = 0x04;	/* FLOGI */

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_flogi_xchg: FLOGI failed. "
		    "Unable to send packet.");

		rval = FCT_FAILURE;
		goto done;
	}

	if ((pkt->pkt_state != FC_PKT_SUCCESS) &&
	    (pkt->pkt_state != FC_PKT_LS_RJT)) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			rval = FCT_TIMEOUT;
		} else if ((pkt->pkt_state == FC_PKT_LOCAL_RJT) &&
		    (pkt->pkt_reason == FC_REASON_FCAL_OPN_FAIL)) {
			rval = FCT_NOT_FOUND;
		} else {
			rval = FCT_FAILURE;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_flogi_xchg: FLOGI failed. state=%x reason=%x "
		    "rval=%llx", pkt->pkt_state, pkt->pkt_reason, rval);

		goto done;
	}

	if (pkt->pkt_state == FC_PKT_LS_RJT) {
		fx->fx_op = ELS_OP_LSRJT;
		fx->fx_rjt_reason = pkt->pkt_reason;
		fx->fx_rjt_expl = pkt->pkt_expln;
	} else {	/* FC_PKT_SUCCESS */

		fx->fx_op = ELS_OP_ACC;
		fx->fx_sid = FABRIC_DID;
		fx->fx_did = port->did;

		els = (ELS_PKT *)pkt->pkt_resp;
		bcopy((caddr_t)&els->un.logi.nodeName,
		    (caddr_t)fx->fx_nwwn, 8);
		bcopy((caddr_t)&els->un.logi.portName,
		    (caddr_t)fx->fx_pwwn, 8);
		fx->fx_fport = els->un.logi.cmn.fPort;
	}

done:
	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	if ((rval == FCT_SUCCESS) || (rval == FCT_NOT_FOUND)) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_flogi_xchg: FCT_STATE_FLOGI_CMPL.  rval=%s",
		    ((rval == FCT_SUCCESS)? "FCT_SUCCESS":"FCT_NOT_FOUND"));

		mutex_enter(&EMLXS_PORT_LOCK);
		port->fct_flags |= FCT_STATE_FLOGI_CMPL;
		mutex_exit(&EMLXS_PORT_LOCK);

		/*
		 * Flush all unsolicited commands
		 * Must use separate thread since
		 * this thread must complete first
		 */
		emlxs_thread_spawn(hba, emlxs_fct_unsol_flush_thread,
		    (void *)port, 0);
	}

	return (rval);

} /* emlxs_fct_flogi_xchg() */


/* COMSTAR ENTER POINT */
/* This is called right after we report that link has come online */
static fct_status_t
emlxs_fct_get_link_info(fct_local_port_t *fct_port, fct_link_info_t *link)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_get_link_info %p: FCT: flg x%x  HBA: ste x%x flg x%x topo x%x",
	    fct_port, port->fct_flags, hba->state, hba->flag, hba->topology);

	mutex_enter(&EMLXS_PORT_LOCK);

	if (port->mode == MODE_INITIATOR) {
		link->port_topology = PORT_TOPOLOGY_UNKNOWN;
		link->port_speed = PORT_SPEED_UNKNOWN;
		link->portid = 0;

		mutex_exit(&EMLXS_PORT_LOCK);

		return (FCT_SUCCESS);
	}

	if (!(port->fct_flags & FCT_STATE_LINK_UP) ||
	    (hba->state < FC_LINK_UP) || (hba->flag & FC_LOOPBACK_MODE)) {
		link->port_topology = PORT_TOPOLOGY_UNKNOWN;
		link->port_speed = PORT_SPEED_UNKNOWN;
		link->portid = 0;

		mutex_exit(&EMLXS_PORT_LOCK);

		return (FCT_SUCCESS);
	}

	if (hba->topology == TOPOLOGY_LOOP) {
		link->port_topology = PORT_TOPOLOGY_PRIVATE_LOOP;
	} else {
		link->port_topology = PORT_TOPOLOGY_PT_TO_PT;
	}

	switch (hba->linkspeed) {
	case LA_1GHZ_LINK:
		link->port_speed = PORT_SPEED_1G;
		break;
	case LA_2GHZ_LINK:
		link->port_speed = PORT_SPEED_2G;
		break;
	case LA_4GHZ_LINK:
		link->port_speed = PORT_SPEED_4G;
		break;
	case LA_8GHZ_LINK:
		link->port_speed = PORT_SPEED_8G;
		break;
	case LA_10GHZ_LINK:
		link->port_speed = PORT_SPEED_10G;
		break;
	case LA_16GHZ_LINK:
		link->port_speed = PORT_SPEED_16G;
		break;
	default:
		link->port_speed = PORT_SPEED_UNKNOWN;
		break;
	}

	link->portid = port->did;
	link->port_no_fct_flogi = 0;
	link->port_fca_flogi_done = 0;
	link->port_fct_flogi_done = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	return (FCT_SUCCESS);

} /* emlxs_fct_get_link_info() */


/* COMSTAR ENTER POINT */
static fct_status_t
emlxs_fct_register_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *remote_port, fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	clock_t timeout;
	int32_t pkt_ret;
	fct_els_t *els;
	SERV_PARM *sp;
	emlxs_node_t *ndlp;
	SERV_PARM sparam;
	uint32_t *iptr;
	uint16_t hdl;
	uint64_t addr;
	fct_status_t rval;
	fct_status_t rval2;
	uint32_t i;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_register_remote_port %p", fct_port);
#endif /* FCT_API_TRACE */

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {

		cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd,
		    EMLXS_FCT_REG_PENDING);
		/* mutex_enter(&cmd_sbp->fct_mtx); */

		cmd_sbp->channel = &hba->chan[hba->channel_els];
		cmd_sbp->fct_type = EMLXS_FCT_ELS_CMD;

	} else {

		rval = emlxs_fct_cmd_accept(port, fct_cmd,
		    EMLXS_FCT_REG_PENDING);
		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_register_remote_port: "
			    "Unable to accept fct_cmd. lid=%x rid=%x",
			    fct_cmd->cmd_lportid, fct_cmd->cmd_rportid);

			return (rval);
		}
		/* mutex_enter(&cmd_sbp->fct_mtx); */
	}

	cmd_sbp->fct_flags &= ~EMLXS_FCT_REGISTERED;
	cmd_sbp->node = emlxs_node_find_did(port, fct_cmd->cmd_rportid, 1);

	/* Check for unsolicited PLOGI */
	if (cmd_sbp->fct_flags & EMLXS_FCT_PLOGI_RECEIVED) {
		els = (fct_els_t *)fct_cmd->cmd_specific;
		sp = (SERV_PARM *)((caddr_t)els->els_req_payload +
		    sizeof (uint32_t));

	} else {	/* Solicited PLOGI */

		sp = &sparam;
		bcopy((caddr_t)&port->sparam, (caddr_t)sp,
		    sizeof (SERV_PARM));

		/*
		 * Create temporary WWN's from fct_cmd address
		 * This simply allows us to get an RPI from the
		 * adapter until we get real service params.
		 * The PLOGI ACC reply will trigger a REG_LOGIN
		 * update later
		 */
		addr = (uint64_t)((unsigned long)fct_cmd);

		iptr = (uint32_t *)&sp->portName;
		iptr[0] = PADDR_HI(addr);
		iptr[1] = PADDR_LO(addr);

		iptr = (uint32_t *)&sp->nodeName;
		iptr[0] = PADDR_HI(addr);
		iptr[1] = PADDR_LO(addr);
	}

	if (hba->flag & FC_PT_TO_PT) {
		mutex_enter(&EMLXS_PORT_LOCK);
		port->did = fct_cmd->cmd_lportid;
		port->rdid = fct_cmd->cmd_rportid;
		mutex_exit(&EMLXS_PORT_LOCK);

		/*
		 * We already received the remote port's
		 * parameters in the FLOGI exchange
		 */
		if (!(cmd_sbp->fct_flags & EMLXS_FCT_PLOGI_RECEIVED)) {
			sp = &sparam;
			bcopy((caddr_t)&port->fabric_sparam, (caddr_t)sp,
			    sizeof (SERV_PARM));

			/*
			 * Since this is a PLOGI, not a FLOGI, we need
			 * to fix up word2 of the CSP accordingly.
			 */
			sp->cmn.w2.r_a_tov = port->sparam.cmn.w2.r_a_tov;
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "fct_register_remote_port: Register lid=%x rid=%x. (%x,%x,%p)",
	    fct_cmd->cmd_lportid, fct_cmd->cmd_rportid, cmd_sbp->fct_state,
	    hba->flag, fct_cmd);

	emlxs_fct_cmd_release(port, fct_cmd, 0);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	/* Create a new node */
	if (EMLXS_SLI_REG_DID(port, fct_cmd->cmd_rportid, sp, cmd_sbp,
	    NULL, NULL) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_register_remote_port: "
		    "Reg login failed. lid=%x rid=%x",
		    fct_cmd->cmd_lportid, fct_cmd->cmd_rportid);
	} else {

		/* Wait for completion */
		mutex_enter(&EMLXS_PKT_LOCK);
		timeout = emlxs_timeout(hba, 30);
		pkt_ret = 0;
		while ((pkt_ret != -1) &&
		    (cmd_sbp->fct_state == EMLXS_FCT_REG_PENDING) &&
		    !(cmd_sbp->fct_flags & EMLXS_FCT_REGISTERED)) {
			pkt_ret = cv_timedwait(&EMLXS_PKT_CV,
			    &EMLXS_PKT_LOCK, timeout);
		}
		mutex_exit(&EMLXS_PKT_LOCK);
	}

	/* Reacquire ownership of the fct_cmd */
	rval2 = emlxs_fct_cmd_acquire(port, fct_cmd,
	    EMLXS_FCT_REG_COMPLETE);
	if (rval2) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_register_remote_port: "
		    "Unable to reacquire fct_cmd. lid=%x rid=%x",
		    fct_cmd->cmd_lportid, fct_cmd->cmd_rportid);

		return (rval2);
	}
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	/* Prepare response */

	ndlp = (emlxs_node_t *)cmd_sbp->node;

	if (ndlp) {
		cmd_sbp->fct_flags |= EMLXS_FCT_REGISTERED;

		*((emlxs_node_t **)remote_port->rp_fca_private) =
		    cmd_sbp->node;

		hdl = ndlp->nlp_Rpi;
		if (hdl == FABRIC_RPI) {
			if (fct_cmd->cmd_rportid == SCR_DID) {
				/* The SCR handle is hardcoded */
				remote_port->rp_handle = hba->max_nodes;
				port->fct_els_only_bmap |= 1;

			} else {
				for (i = 1; i < EMLXS_FCT_NUM_ELS_ONLY; i++) {
					if (port->fct_els_only_bmap & (1 << i))
						continue;
					/*
					 * Bit is not set, so use this
					 * for the handle
					 */
					remote_port->rp_handle =
					    hba->max_nodes + i;
					port->fct_els_only_bmap |= (1 << i);
					break;
				}
				if (i >= EMLXS_FCT_NUM_ELS_ONLY) {
					remote_port->rp_handle =
					    FCT_HANDLE_NONE;
				}
			}
		} else {
			if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
				hdl = emlxs_sli4_rpi_to_index(hba, hdl);
			}
			remote_port->rp_handle = hdl;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_register_remote_port: lid=%x rid=%x hdl=%x",
		    fct_cmd->cmd_lportid, fct_cmd->cmd_rportid,
		    remote_port->rp_handle);

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		TGTPORTSTAT.FctPortRegister++;
		return (FCT_SUCCESS);
	} else {
		*((emlxs_node_t **)remote_port->rp_fca_private) = NULL;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_register_remote_port: failed. lid=%x rid=%x hdl=%x",
		    fct_cmd->cmd_lportid, fct_cmd->cmd_rportid,
		    remote_port->rp_handle);

		remote_port->rp_handle = FCT_HANDLE_NONE;

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		TGTPORTSTAT.FctFailedPortRegister++;
		return (FCT_FAILURE);
	}

} /* emlxs_fct_register_remote_port() */


/* COMSTAR ENTER POINT */
static fct_status_t
emlxs_fct_deregister_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *remote_port)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_node_t *ndlp;
	uint32_t i;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_deregister_remote_port: did=%x hdl=%x",
	    remote_port->rp_id, remote_port->rp_handle);
#else
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_deregister_remote_port: did=%x hdl=%x",
	    remote_port->rp_id, remote_port->rp_handle);
#endif /* FCT_API_TRACE */

	if (remote_port->rp_handle >= hba->max_nodes) {
		i = remote_port->rp_handle - hba->max_nodes;
		if ((i < EMLXS_FCT_NUM_ELS_ONLY) &&
		    (port->fct_els_only_bmap & (1 << i))) {
			port->fct_els_only_bmap &= ~(1 << i);
		}
	}

	ndlp = *((emlxs_node_t **)remote_port->rp_fca_private);
	*((emlxs_node_t **)remote_port->rp_fca_private) = NULL;

	if (ndlp) {
		(void) EMLXS_SLI_UNREG_NODE(port, ndlp, NULL,
		    NULL, NULL);
	}

	TGTPORTSTAT.FctPortDeregister++;
	return (FCT_SUCCESS);

} /* emlxs_fct_deregister_remote_port() */


/* ARGSUSED */
extern int
emlxs_fct_handle_unsol_req(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	IOCB *iocb;
	fct_cmd_t *fct_cmd;
	emlxs_buf_t *cmd_sbp;
	emlxs_fcp_cmd_t *fcp_cmd;
	emlxs_node_t *ndlp;
	uint32_t cnt;
	uint32_t tm;
	uint16_t hdl;
	scsi_task_t *fct_task;
	uint8_t lun[8];
	uint32_t sid = 0;

	iocb = &iocbq->iocb;
	ndlp = emlxs_node_find_rpi(port, iocb->ULPIOTAG);
	if (!ndlp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: Unknown RPI. rpi=%d rxid=%x. Dropping...",
		    iocb->ULPIOTAG, iocb->ULPCONTEXT);

		goto dropped;
	}
	sid = ndlp->nlp_DID;

	fcp_cmd = (emlxs_fcp_cmd_t *)mp->virt;

	if (!port->fct_port) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: Target unbound. rpi=%d rxid=%x. Dropping...",
		    iocb->ULPIOTAG, iocb->ULPCONTEXT);

		emlxs_send_logo(port, sid);

		goto dropped;
	}

	if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: Target offline. rpi=%d rxid=%x. Dropping...",
		    iocb->ULPIOTAG, iocb->ULPCONTEXT);

		emlxs_send_logo(port, sid);

		goto dropped;
	}

	/* Get lun id */
	bcopy((void *)&fcp_cmd->fcpLunMsl, lun, 8);

	if (TGTPORTSTAT.FctOutstandingIO >= port->fct_port->port_max_xchges) {
		TGTPORTSTAT.FctOverQDepth++;
	}

	hdl = ndlp->nlp_Rpi;
	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		hdl = emlxs_sli4_rpi_to_index(hba, hdl);
	}
	fct_cmd =
	    MODSYM(fct_scsi_task_alloc) (port->fct_port, hdl, sid, lun, 16, 0);

	if (fct_cmd == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: sid=%x xid=%x. "
		    "Unable to allocate scsi task. Returning QFULL.",
		    sid, iocb->ULPCONTEXT);

		(void) emlxs_fct_send_qfull_reply(port, ndlp, iocb->ULPCONTEXT,
		    iocb->ULPCLASS, fcp_cmd);

		goto dropped;
	}

	/* Initialize fct_cmd */
	fct_cmd->cmd_rportid = sid;
	fct_cmd->cmd_lportid = port->did;
	fct_cmd->cmd_rp_handle = hdl;
	fct_cmd->cmd_port = port->fct_port;

	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd, EMLXS_FCT_FCP_CMD_RECEIVED);
	/* mutex_enter(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_scsi_task_alloc %p:%p FCP rcvd: "
	    "cmd=%x sid=%x rxid=%x oxid=%x lun=%02x%02x dl=%d",
	    fct_cmd, cmd_sbp, fcp_cmd->fcpCdb[0], sid, iocb->ULPCONTEXT,
	    iocb->unsli3.ext_rcv.oxid, lun[0], lun[1],
	    LE_SWAP32(fcp_cmd->fcpDl));
#endif /* FCT_API_TRACE */

	/* Initialize cmd_sbp */
	cmd_sbp->channel = cp;
	cmd_sbp->class = iocb->ULPCLASS;
	cmd_sbp->lun = (lun[0] << 8) | lun[1];
	cmd_sbp->fct_type = EMLXS_FCT_FCP_CMD;
	cmd_sbp->ticks = hba->timer_tics + (2 * hba->fc_ratov);

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		/* xrip was setup / passed in from the SLI layer */
		cmd_sbp->xrip = iocbq->sbp;
		cmd_sbp->node = iocbq->node;
		iocbq->sbp = 0;

		fct_cmd->cmd_oxid = cmd_sbp->xrip->rx_id;
		fct_cmd->cmd_rxid = cmd_sbp->xrip->XRI;

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: oxid=%x rxid=%x iotag=%d %p ",
		    fct_cmd->cmd_oxid, fct_cmd->cmd_rxid, cmd_sbp->xrip->iotag,
		    hba->fc_table[cmd_sbp->xrip->iotag]);
#endif /* FCT_API_TRACE */

	} else {
		fct_cmd->cmd_oxid = iocb->unsli3.ext_rcv.oxid;
		if (!fct_cmd->cmd_oxid) {
			fct_cmd->cmd_oxid = 0xFFFF;
		}
		fct_cmd->cmd_rxid = iocb->ULPCONTEXT;
	}


	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;

	/* Set task_flags */
	switch (fcp_cmd->fcpCntl1) {
	case SIMPLE_Q:
		fct_task->task_flags = TF_ATTR_SIMPLE_QUEUE;
		break;

	case HEAD_OF_Q:
		fct_task->task_flags = TF_ATTR_HEAD_OF_QUEUE;
		break;

	case ORDERED_Q:
		fct_task->task_flags = TF_ATTR_ORDERED_QUEUE;
		break;

	case ACA_Q:
		fct_task->task_flags = TF_ATTR_ACA;
		break;

	case UNTAGGED:
		fct_task->task_flags = TF_ATTR_UNTAGGED;
		break;
	}

	cnt = LE_SWAP32(fcp_cmd->fcpDl);
	switch (fcp_cmd->fcpCntl3) {
	case 0:
		TGTPORTSTAT.FctIOCmdCnt++;
		break;
	case 1:
		EMLXS_BUMP_WRIOCTR(port, cnt);
		TGTPORTSTAT.FctWriteBytes += cnt;
		fct_task->task_flags |= TF_WRITE_DATA;
		break;

	case 2:
		EMLXS_BUMP_RDIOCTR(port, cnt);
		TGTPORTSTAT.FctReadBytes += cnt;
		fct_task->task_flags |= TF_READ_DATA;
		break;
	}

	fct_task->task_priority = 0;

	/* task_mgmt_function */
	tm = fcp_cmd->fcpCntl2;
	if (tm) {
		if (tm & BIT_1) {
			fct_task->task_mgmt_function = TM_ABORT_TASK_SET;
		} else if (tm & BIT_2) {
			fct_task->task_mgmt_function = TM_CLEAR_TASK_SET;
		} else if (tm & BIT_4) {
			fct_task->task_mgmt_function = TM_LUN_RESET;
		} else if (tm & BIT_5) {
			fct_task->task_mgmt_function = TM_TARGET_COLD_RESET;
		} else if (tm & BIT_6) {
			fct_task->task_mgmt_function = TM_CLEAR_ACA;
		} else {
			fct_task->task_mgmt_function = TM_ABORT_TASK;
		}
	}

	/* Parallel buffers support - future */
	fct_task->task_max_nbufs = 1;

	fct_task->task_additional_flags = 0;
	fct_task->task_cur_nbufs = 0;
	fct_task->task_csn_size = 8;
	fct_task->task_cmd_seq_no = 0;
	fct_task->task_expected_xfer_length = cnt;
	bcopy((void *)&fcp_cmd->fcpCdb, fct_task->task_cdb, 16);

	TGTPORTSTAT.FctCmdReceived++;
	TGTPORTSTAT.FctOutstandingIO++;

	emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_post_rcvd_cmd:3 %p:%p portid x%x, %d outio %d",
	    fct_cmd, cmd_sbp, fct_cmd->cmd_lportid,
	    fct_task->task_expected_xfer_length,
	    TGTPORTSTAT.FctOutstandingIO);
#endif /* FCT_API_TRACE */

	MODSYM(fct_post_rcvd_cmd) (fct_cmd, 0);

	return (0);

dropped:

	TGTPORTSTAT.FctRcvDropped++;
	return (1);

} /* emlxs_fct_handle_unsol_req() */


/* COMSTAR ENTER POINT */
/* ARGSUSED */
static fct_status_t
emlxs_fct_send_fcp_data(fct_cmd_t *fct_cmd, stmf_data_buf_t *dbuf,
    uint32_t ioflags)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
#ifdef FCT_API_TRACE
	scsi_task_t *fct_task;
#endif /* FCT_API_TRACE */
	IOCBQ *iocbq;
	emlxs_node_t *ndlp;

	int	channel;
	int	channelno;
	fct_status_t rval = 0;

	rval = emlxs_fct_cmd_accept(port, fct_cmd, EMLXS_FCT_SEND_FCP_DATA);
	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_send_fcp_data: "
		    "Unable to accept fct_cmd. did=%x",
		    fct_cmd->cmd_rportid);

		return (rval);
	}
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
#ifdef FCT_API_TRACE
	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
#endif /* FCT_API_TRACE */
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;

	cmd_sbp->node = ndlp;
	cmd_sbp->fct_buf = dbuf;

	channelno = ((CHANNEL *)cmd_sbp->channel)->channelno;

	channel = channelno;



	iocbq = &cmd_sbp->iocbq;
	iocbq->sbp = cmd_sbp;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_send_fcp_data %p:%p flgs=%x ioflags=%x dl=%d,%d,%d,%d",
	    fct_cmd, cmd_sbp, dbuf->db_flags, ioflags,
	    fct_task->task_cmd_xfer_length,
	    fct_task->task_nbytes_transferred, dbuf->db_data_size,
	    fct_task->task_expected_xfer_length);
#endif /* FCT_API_TRACE */

	/* Setup for I/O prep routine */
	iocbq->iocb.ULPCOMMAND = 0;

	if (EMLXS_SLI_PREP_FCT_IOCB(port, cmd_sbp, channel) != IOERR_SUCCESS) {

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_BUSY);
	}

	cmd_sbp->fct_type = EMLXS_FCT_FCP_DATA;

	if (dbuf->db_flags & DB_SEND_STATUS_GOOD) {
		cmd_sbp->fct_flags |= EMLXS_FCT_SEND_STATUS;
	}

	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {
		if (emlxs_fct_dbuf_dma_sync(hba, dbuf, DDI_DMA_SYNC_FORDEV)) {
			emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
			/* mutex_exit(&cmd_sbp->fct_mtx); */

			if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
				emlxs_sli4_free_xri(port, cmd_sbp, 0, 0);
			}
			return (FCT_BUSY);
		}
	}

	cmd_sbp->fct_flags |= EMLXS_FCT_IO_INP;
	emlxs_fct_cmd_release(port, fct_cmd, EMLXS_FCT_DATA_PENDING);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	EMLXS_SLI_ISSUE_IOCB_CMD(hba, cmd_sbp->channel, iocbq);

	return (FCT_SUCCESS);

} /* emlxs_fct_send_fcp_data() */


/* cmd_sbp->fct_mtx must be held to enter */
/* cmd_sbp->fct_mtx must be released before exiting */
static fct_status_t
emlxs_fct_send_fcp_status(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	scsi_task_t *fct_task;
	fc_packet_t *pkt;
	emlxs_buf_t *sbp = NULL;
	emlxs_fcp_rsp *fcp_rsp;
	emlxs_node_t *ndlp;
	fct_status_t rval;
	uint32_t did;
	uint32_t size;

	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;
	did = fct_cmd->cmd_rportid;

	/* Initialize cmd_sbp */
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, EMLXS_FCT_SEND_FCP_STATUS);

	cmd_sbp->node = ndlp;

	size = 24;
	if (fct_task->task_sense_length) {
		size += fct_task->task_sense_length;
	}
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_send_fcp_status %p:%p stat=%d resid=%d size=%d rx=%x ox=%x",
	    fct_cmd, cmd_sbp, fct_task->task_scsi_status,
	    fct_task->task_resid, size, fct_cmd->cmd_rxid, fct_cmd->cmd_oxid);
#endif /* FCT_API_TRACE */

	if (!(pkt = emlxs_pkt_alloc(port, size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_fcp_status: Unable to allocate packet.");

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_BUSY);
	}

	cmd_sbp->fct_type = EMLXS_FCT_FCP_STATUS;

	sbp =  emlxs_fct_pkt_init(port, fct_cmd, pkt);
	cmd_sbp->fct_pkt = pkt;

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_timeout = (pkt->pkt_timeout > 60)? 60: pkt->pkt_timeout;
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_STATUS;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_SCSI_FCP;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = fct_cmd->cmd_oxid;
	pkt->pkt_cmd_fhdr.rx_id = fct_cmd->cmd_rxid;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the status payload */
	fcp_rsp = (emlxs_fcp_rsp *)pkt->pkt_cmd;

	if (fct_task->task_resid) {
		if (fct_task->task_status_ctrl & TASK_SCTRL_OVER) {
			TGTPORTSTAT.FctScsiResidOver++;
			fcp_rsp->rspStatus2 |= RESID_OVER;
			fcp_rsp->rspResId = LE_SWAP32(fct_task->task_resid);

		} else if (fct_task->task_status_ctrl & TASK_SCTRL_UNDER) {
			TGTPORTSTAT.FctScsiResidUnder++;
			fcp_rsp->rspStatus2 |= RESID_UNDER;
			fcp_rsp->rspResId = LE_SWAP32(fct_task->task_resid);

		}
	}

	if (fct_task->task_scsi_status) {
		if (fct_task->task_scsi_status == SCSI_STAT_QUE_FULL) {
			TGTPORTSTAT.FctScsiQfullErr++;
		} else {
			TGTPORTSTAT.FctScsiStatusErr++;
		}

		/* Make sure residual reported on non-SCSI_GOOD READ status */
		if ((fct_task->task_flags & TF_READ_DATA) &&
		    (fcp_rsp->rspResId == 0)) {
			fcp_rsp->rspStatus2 |= RESID_UNDER;
			fcp_rsp->rspResId =
			    fct_task->task_expected_xfer_length;
		}
	}


	if (fct_task->task_sense_length) {
		TGTPORTSTAT.FctScsiSenseErr++;
		fcp_rsp->rspStatus2 |= SNS_LEN_VALID;
		fcp_rsp->rspSnsLen = LE_SWAP32(fct_task->task_sense_length);

		bcopy((uint8_t *)fct_task->task_sense_data,
		    (uint8_t *)&fcp_rsp->rspInfo0,
		    fct_task->task_sense_length);
	}

	fcp_rsp->rspStatus3 = fct_task->task_scsi_status;
	fcp_rsp->rspRspLen = 0;

#ifdef FCT_API_TRACE
	emlxs_data_dump(port, "RESP", (uint32_t *)fcp_rsp, 36, 0);
#endif /* FCT_API_TRACE */

	cmd_sbp->fct_flags |= EMLXS_FCT_IO_INP;
	emlxs_fct_cmd_release(port, fct_cmd, EMLXS_FCT_STATUS_PENDING);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_fcp_status: Unable to send packet.");

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			emlxs_sli4_free_xri(port, sbp, 0, 0);
		}

		/* Reacquire ownership of the fct_cmd */
		rval = emlxs_fct_cmd_acquire(port, fct_cmd, 0);
		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_send_fcp_status: "
			    "Unable to acquire fct_cmd.");
			return (rval);
		}
		/* mutex_enter(&cmd_sbp->fct_mtx); */

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_BUSY);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_send_fcp_status() */


static fct_status_t
emlxs_fct_send_qfull_reply(emlxs_port_t *port, emlxs_node_t *ndlp,
    uint16_t xid, uint32_t class, emlxs_fcp_cmd_t *fcp_cmd)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;
	emlxs_fcp_rsp *fcp_rsp;
	uint32_t size;
	CHANNEL *cp = &hba->chan[hba->CHANNEL_FCT];
	uint8_t lun[8];

	bcopy((void *)&fcp_cmd->fcpLunMsl, lun, 8);
	size = 24;

	if (!(pkt = emlxs_pkt_alloc(port, size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_qfull_reply: Unable to allocate packet.");
		return (FCT_FAILURE);
	}

	sbp = PKT2PRIV(pkt);
	sbp->node = ndlp;
	sbp->channel = cp;
	sbp->did = ndlp->nlp_DID;
	sbp->lun = (lun[0] << 8) | lun[1];
	sbp->class = class;

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(ndlp->nlp_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_STATUS;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_SCSI_FCP;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = xid;
	pkt->pkt_cmd_fhdr.ro = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
	    "fct_send_qfull_reply: Sending QFULL: x%x lun x%x: %d %d",
	    xid, sbp->lun, TGTPORTSTAT.FctOutstandingIO,
	    port->fct_port->port_max_xchges);

	/* Build the status payload */
	fcp_rsp = (emlxs_fcp_rsp *)pkt->pkt_cmd;

	TGTPORTSTAT.FctScsiQfullErr++;
	fcp_rsp->rspStatus3 = SCSI_STAT_QUE_FULL;
	fcp_rsp->rspStatus2 |= RESID_UNDER;
	fcp_rsp->rspResId = LE_SWAP32(fcp_cmd->fcpDl);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			emlxs_sli4_free_xri(port, sbp, 0, 0);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_qfull_reply: Unable to send packet.");
		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_send_qfull_reply() */


/* ARGSUSED */
extern int
emlxs_fct_handle_fcp_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	emlxs_buf_t *cmd_sbp;
	uint32_t status;
	fct_cmd_t *fct_cmd;
	stmf_data_buf_t *dbuf;
	scsi_task_t *fct_task;
	fc_packet_t *pkt;
	uint32_t fct_flags;
	stmf_data_buf_t *fct_buf;
	fct_status_t rval;

	iocb = &iocbq->iocb;
	sbp = (emlxs_buf_t *)iocbq->sbp;

	TGTPORTSTAT.FctEvent++;

	if (!sbp) {
		/* completion with missing xmit command */
		TGTPORTSTAT.FctStray++;

		/* emlxs_stray_fcp_completion_msg */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP event cmd=%x status=%x error=%x iotag=%d",
		    iocb->ULPCOMMAND, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, iocb->ULPIOTAG);

		return (1);
	}

	TGTPORTSTAT.FctCompleted++;

	port = sbp->iocbq.port;
	fct_cmd = sbp->fct_cmd;
	status = iocb->ULPSTATUS;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_handle_fcp_event: %p:%p cmd=%x status=%x, %x",
	    fct_cmd, sbp, iocb->ULPCOMMAND, status, iocb->ULPCT);
#endif /* FCT_API_TRACE */

	if (fct_cmd == NULL) {
		/* For driver generated QFULL response */
		if (((iocb->ULPCOMMAND == CMD_FCP_TRSP_CX) ||
		    (iocb->ULPCOMMAND == CMD_FCP_TRSP64_CX)) && sbp->pkt) {
			emlxs_pkt_free(sbp->pkt);
		}
		return (0);
	}

	rval = emlxs_fct_cmd_acquire(port, fct_cmd, EMLXS_FCT_REQ_COMPLETE);
	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_handle_fcp_event: "
		    "Unable to reacquire fct_cmd. type=%x",
		    fct_cmd->cmd_type);

		return (1);
	}
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	cmd_sbp->fct_flags &= ~EMLXS_FCT_IO_INP;

	pkt = cmd_sbp->fct_pkt;
	cmd_sbp->fct_pkt = NULL;

	dbuf = sbp->fct_buf;

	fct_cmd->cmd_comp_status = FCT_SUCCESS;

	if (status) {
emlxs_dma_error:
		/*
		 * The error indicates this IO should be terminated
		 * immediately.
		 */
		cmd_sbp->fct_flags &= ~EMLXS_FCT_SEND_STATUS;
		fct_cmd->cmd_comp_status = FCT_FAILURE;

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_OWNED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_queue_cmd_for_termination:1 %p: x%x",
		    fct_cmd, fct_cmd->cmd_comp_status);
#endif /* FCT_API_TRACE */

		MODSYM(fct_queue_cmd_for_termination) (fct_cmd,
		    FCT_ABTS_RECEIVED);

		goto done;
	}

	switch (iocb->ULPCOMMAND) {

	/*
	 *  FCP Data completion
	 */
	case CMD_FCP_TSEND_CX:
	case CMD_FCP_TSEND64_CX:
	case CMD_FCP_TRECEIVE_CX:
	case CMD_FCP_TRECEIVE64_CX:

		if (dbuf->db_flags & DB_DIRECTION_FROM_RPORT) {
			if (emlxs_fct_dbuf_dma_sync(hba, dbuf,
			    DDI_DMA_SYNC_FORCPU)) {
				goto emlxs_dma_error;
			}
		}

		if ((cmd_sbp->fct_flags & EMLXS_FCT_SEND_STATUS) &&
		    (iocb->ULPCT != 1)) {

			dbuf->db_flags |= DB_STATUS_GOOD_SENT;

			fct_task =
			    (scsi_task_t *)fct_cmd->cmd_specific;
			fct_task->task_scsi_status = 0;

			(void) emlxs_fct_send_fcp_status(fct_cmd);
			/* mutex_exit(&cmd_sbp->fct_mtx); */

			break;

		} else if ((cmd_sbp->fct_flags &
		    EMLXS_FCT_SEND_STATUS) &&
		    (iocb->ULPCT == 1)) {
			/* Auto-resp has been sent out by firmware */
			/* We can assume this is really a FC_TRSP_CX */

			dbuf->db_flags |= DB_STATUS_GOOD_SENT;
			fct_task =
			    (scsi_task_t *)fct_cmd->cmd_specific;
			fct_task->task_scsi_status = 0;

			cmd_sbp->fct_flags |= EMLXS_FCT_SEND_STATUS;

			goto auto_resp;
		}

		cmd_sbp->fct_flags &= ~EMLXS_FCT_SEND_STATUS;

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_scsi_data_xfer_done:1 %p %p", fct_cmd, dbuf);
#endif /* FCT_API_TRACE */

		MODSYM(fct_scsi_data_xfer_done) (fct_cmd, dbuf, 0);

		break;

		/* FCP Status completion */
	case CMD_FCP_TRSP_CX:
	case CMD_FCP_TRSP64_CX:

auto_resp:
		/* Copy these before calling emlxs_fct_cmd_done */
		fct_flags = cmd_sbp->fct_flags;
		fct_buf = cmd_sbp->fct_buf;

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		TGTPORTSTAT.FctOutstandingIO--;

		if (fct_flags & EMLXS_FCT_SEND_STATUS) {
#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_scsi_data_xfer_done:2 %p %p outio %d",
			    fct_cmd, fct_buf, TGTPORTSTAT.FctOutstandingIO);
#endif /* FCT_API_TRACE */

			MODSYM(fct_scsi_data_xfer_done) (fct_cmd,
			    fct_buf, FCT_IOF_FCA_DONE);
		} else {
#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_send_response_done:1 %p: x%x outio %d",
			    fct_cmd, fct_cmd->cmd_comp_status,
			    TGTPORTSTAT.FctOutstandingIO);
#endif /* FCT_API_TRACE */

			MODSYM(fct_send_response_done) (fct_cmd,
			    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);
		}
		break;

	default:
		emlxs_fct_cmd_release(port, fct_cmd, 0);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		TGTPORTSTAT.FctStray++;
		TGTPORTSTAT.FctCompleted--;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Invalid iocb: cmd=0x%x", iocb->ULPCOMMAND);

		if (pkt) {
			emlxs_pkt_complete(sbp, status,
			    iocb->un.grsp.perr.statLocalError, 1);
		}

	}	/* switch(iocb->ULPCOMMAND) */


done:
	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	if (status == IOSTAT_SUCCESS) {
		TGTPORTSTAT.FctCmplGood++;
	} else {
		TGTPORTSTAT.FctCmplError++;
	}

	return (0);

} /* emlxs_fct_handle_fcp_event() */


/* ARGSUSED */
extern int
emlxs_fct_handle_abort(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;

	iocb = &iocbq->iocb;
	sbp = (emlxs_buf_t *)iocbq->sbp;

	TGTPORTSTAT.FctEvent++;

	if (!sbp) {
		/* completion with missing xmit command */
		TGTPORTSTAT.FctStray++;

		/* emlxs_stray_fcp_completion_msg */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "ABORT event cmd=%x status=%x error=%x iotag=%d",
		    iocb->ULPCOMMAND, iocb->ULPSTATUS,
		    iocb->un.grsp.perr.statLocalError, iocb->ULPIOTAG);

		return (1);
	}

	pkt = PRIV2PKT(sbp);

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_handle_abort: %p:%p xri=%d cmd=%x status=%x",
	    sbp->fct_cmd, sbp,
	    iocb->ULPCONTEXT, iocb->ULPCOMMAND, iocb->ULPSTATUS);
#endif /* FCT_API_TRACE */

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		XRIobj_t	*xrip;

		emlxs_sli4_free_xri(port, NULL, sbp->xrip, 1);
		xrip = emlxs_sli4_find_xri(port, iocb->ULPCONTEXT);
		if (!xrip || xrip->state == XRI_STATE_FREE) {
			goto exit;
		}

		if ((hba->fc_table[xrip->iotag]) &&
		    (hba->fc_table[xrip->iotag] != STALE_PACKET)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
			    "Cmd not aborted, retrying: xri=%d iotag=%d sbp=%p",
			    xrip->XRI, xrip->iotag, hba->fc_table[xrip->iotag]);

			/* Abort retry */
			if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
				    "Abort retry failed xri=%x", xrip->XRI);
			} else {
				return (0);
			}
		}
	}

exit:
	if (pkt) {
		emlxs_pkt_free(pkt);
	}
	return (0);

} /* emlxs_fct_handle_abort() */


extern int
emlxs_fct_handle_unsol_els(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	emlxs_hba_t *hba = HBA;
	IOCB *iocb;
	uint32_t cmd_code;
	fct_cmd_t *fct_cmd;
	fct_els_t *els;
	uint32_t sid;
	uint32_t padding;
	uint8_t *bp;
	emlxs_buf_t *cmd_sbp;
	uint32_t rval;

	HBASTATS.ElsCmdReceived++;

	bp = mp->virt;
	cmd_code = (*(uint32_t *)bp) & ELS_CMD_MASK;
	iocb = &iocbq->iocb;
	sid = iocb->un.elsreq.remoteID;

	if (!port->fct_port) {
		if (!(hba->flag & FC_ONLINE_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
			    "%s: sid=%x. Adapter offline. Dropping...",
			    emlxs_elscmd_xlate(cmd_code), sid);
			goto done;
		}

		switch (cmd_code) {
		case ELS_CMD_LOGO:
		case ELS_CMD_PRLO:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
			    "%s: sid=%x. Target unbound. Accepting...",
			    emlxs_elscmd_xlate(cmd_code), sid);
			(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC,
			    ELS_CMD_LOGO, 0, 0);
			break;
		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
			    "%s: sid=%x. Target unbound. Rejecting...",
			    emlxs_elscmd_xlate(cmd_code), sid);
			(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT,
			    cmd_code, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);
			break;
		}
		goto done;
	}

	if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Target offline. Rejecting...",
		    emlxs_elscmd_xlate(cmd_code), sid);
		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT, cmd_code,
		    LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

		goto done;
	}

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "%s: sid=%x cnt=%d. Target rcv. ",
	    emlxs_elscmd_xlate(cmd_code), sid, size);
#endif /* FCT_API_TRACE */

	/* Process the request */
	switch (cmd_code) {
	case ELS_CMD_FLOGI:
		rval = emlxs_fct_process_unsol_flogi(port, cp, iocbq, mp, size);

		if (!rval) {
			ELS_PKT *els_pkt = (ELS_PKT *)bp;
			fct_flogi_xchg_t fx;

			bzero((uint8_t *)&fx, sizeof (fct_flogi_xchg_t));

			/* Save the FLOGI exchange information */
			fx.rsvd2 = iocb->ULPCONTEXT;
			bcopy((caddr_t)&els_pkt->un.logi.nodeName,
			    (caddr_t)fx.fx_nwwn, 8);
			bcopy((caddr_t)&els_pkt->un.logi.portName,
			    (caddr_t)fx.fx_pwwn, 8);
			fx.fx_sid = sid;
			fx.fx_did = iocb->un.elsreq.myID;
			fx.fx_fport = els_pkt->un.logi.cmn.fPort;
			fx.fx_op = ELS_OP_FLOGI;

			emlxs_fct_handle_unsol_flogi(port, &fx, 1);
		}

		goto done;

	case ELS_CMD_PLOGI:
		rval =
		    emlxs_fct_process_unsol_plogi(port, cp, iocbq, mp, size);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=0x%x", emlxs_elscmd_xlate(cmd_code), sid);
		rval = 0;
		break;
	}

	if (rval) {
		goto done;
	}

	padding = (8 - (size & 7)) & 7;

	fct_cmd = (fct_cmd_t *)MODSYM(fct_alloc) (FCT_STRUCT_CMD_RCVD_ELS,
	    (size + padding + GET_STRUCT_SIZE(emlxs_buf_t)),
	    AF_FORCE_NOSLEEP);

#ifdef FCT_API_TRACE
	{
		uint32_t *ptr = (uint32_t *)bp;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_alloc %p: ELS rcvd: rxid=%x payload: x%x x%x",
		    fct_cmd, iocb->ULPCONTEXT, *ptr, *(ptr + 1));
	}
#endif /* FCT_API_TRACE */

	if (fct_cmd == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Out of memory. Rejecting...",
		    emlxs_elscmd_xlate(cmd_code), sid);

		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT, cmd_code,
		    LSRJT_LOGICAL_BSY, LSEXP_OUT_OF_RESOURCE);
		goto done;
	}

	/* Initialize fct_cmd */
	fct_cmd->cmd_oxid = (cmd_code >> ELS_CMD_SHIFT) & 0xff;
	fct_cmd->cmd_rxid = iocb->ULPCONTEXT;
	fct_cmd->cmd_rportid = sid;
	fct_cmd->cmd_lportid = port->did;
	fct_cmd->cmd_rp_handle = FCT_HANDLE_NONE;
	fct_cmd->cmd_port = port->fct_port;

	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd, EMLXS_FCT_ELS_CMD_RECEIVED);
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	/* Initialize cmd_sbp */
	cmd_sbp->channel = cp;
	cmd_sbp->class = iocb->ULPCLASS;
	cmd_sbp->fct_type = EMLXS_FCT_ELS_CMD;
	cmd_sbp->fct_flags |= EMLXS_FCT_PLOGI_RECEIVED;

	bcopy((uint8_t *)iocb, (uint8_t *)&cmd_sbp->iocbq,
	    sizeof (emlxs_iocb_t));

	els = (fct_els_t *)fct_cmd->cmd_specific;
	els->els_req_size = (uint16_t)size;
	els->els_req_payload =
	    GET_BYTE_OFFSET(fct_cmd->cmd_fca_private,
	    GET_STRUCT_SIZE(emlxs_buf_t));
	bcopy(bp, els->els_req_payload, size);


	/* Check if Offline */
	if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_post_rcvd_cmd:4 %p: portid x%x", fct_cmd,
		    fct_cmd->cmd_lportid);
#endif /* FCT_API_TRACE */

		MODSYM(fct_post_rcvd_cmd) (fct_cmd, 0);

		goto done;
	}

	/* Online */

	/* Check if Link up is acked */
	if (!(port->fct_flags & FCT_STATE_LINK_UP_ACKED)) {
		goto defer;
	}

	if ((cmd_code != ELS_CMD_FLOGI) &&
	    !(port->fct_flags & FCT_STATE_FLOGI_CMPL)) {
		goto defer;
	}

	/* Post it to COMSTAR */
	emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_post_rcvd_cmd:1 %p: portid x%x", fct_cmd,
	    fct_cmd->cmd_lportid);
#endif /* FCT_API_TRACE */

	MODSYM(fct_post_rcvd_cmd) (fct_cmd, 0);

	goto done;

defer:
	/* Defer processing of fct_cmd till later (after link up ack). */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "%s: sid=%x. Defer Processing x%x.",
	    emlxs_elscmd_xlate(cmd_code), sid, port->fct_flags);

	emlxs_fct_cmd_release(port, fct_cmd, EMLXS_FCT_CMD_WAITQ);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	/* Add cmd_sbp to queue tail */
	mutex_enter(&EMLXS_PORT_LOCK);

	if (port->fct_wait_tail) {
		port->fct_wait_tail->next = cmd_sbp;
	}
	port->fct_wait_tail = cmd_sbp;

	if (!port->fct_wait_head) {
		port->fct_wait_head = cmd_sbp;
	}

	mutex_exit(&EMLXS_PORT_LOCK);

done:

	return (0);

} /* emlxs_fct_handle_unsol_els() */


/* ARGSUSED */
static uint32_t
emlxs_fct_process_unsol_flogi(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB *iocb;
	char buffer[64];

	buffer[0] = 0;

	iocb = &iocbq->iocb;

	/* Perform processing of FLOGI payload */
	if (emlxs_process_unsol_flogi(port, iocbq, mp, size, buffer,
	    sizeof (buffer))) {
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "FLOGI: sid=0x%x xid=%x %s",
	    iocb->un.elsreq.remoteID, iocb->ULPIOTAG, buffer);

	return (0);

} /* emlxs_fct_process_unsol_flogi() */


/* ARGSUSED */
static uint32_t
emlxs_fct_process_unsol_plogi(emlxs_port_t *port, CHANNEL *cp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB *iocb;
	char buffer[64];

	buffer[0] = 0;

	iocb = &iocbq->iocb;

	/* Perform processing of PLOGI payload */
	if (emlxs_process_unsol_plogi(port, iocbq, mp, size, buffer,
	    sizeof (buffer))) {
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
	    "PLOGI: sid=0x%x xid=%x %s",
	    iocb->un.elsreq.remoteID, iocb->ULPIOTAG, buffer);

	return (0);

} /* emlxs_fct_process_unsol_plogi() */


/* ARGSUSED */
static emlxs_buf_t *
emlxs_fct_pkt_init(emlxs_port_t *port, fct_cmd_t *fct_cmd,
    fc_packet_t *pkt)
{
	emlxs_buf_t *cmd_sbp;
	emlxs_buf_t *sbp;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	sbp = PKT2PRIV(pkt);
	sbp->fct_cmd = cmd_sbp->fct_cmd;
	sbp->node = cmd_sbp->node;
	sbp->channel = cmd_sbp->channel;
	sbp->did = cmd_sbp->did;
	sbp->lun = cmd_sbp->lun;
	sbp->class = cmd_sbp->class;
	sbp->fct_type = cmd_sbp->fct_type;
	sbp->fct_state = cmd_sbp->fct_state;
	sbp->xrip = cmd_sbp->xrip;
	sbp->iotag = cmd_sbp->iotag;

	return (sbp);

} /* emlxs_fct_pkt_init() */


/* Mutex will be acquired */
static emlxs_buf_t *
emlxs_fct_cmd_init(emlxs_port_t *port, fct_cmd_t *fct_cmd, uint16_t fct_state)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	bzero((void *)cmd_sbp, sizeof (emlxs_buf_t));
	mutex_init(&cmd_sbp->fct_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));
	mutex_init(&cmd_sbp->mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_enter(&cmd_sbp->fct_mtx);
	cmd_sbp->pkt_flags = PACKET_VALID;
	cmd_sbp->port = port;
	cmd_sbp->fct_cmd = fct_cmd;
	cmd_sbp->node = (fct_cmd->cmd_rp) ?
	    *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private : NULL;
	cmd_sbp->iocbq.sbp = cmd_sbp;
	cmd_sbp->iocbq.port = port;
	cmd_sbp->did = fct_cmd->cmd_rportid;

	/* Flags fct_cmd as inuse */
	if ((fct_cmd->cmd_oxid == 0) && (fct_cmd->cmd_rxid == 0)) {
		fct_cmd->cmd_oxid = 0xffff;
		fct_cmd->cmd_rxid = 0xffff;
	}

	if (fct_state) {
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, fct_state);
	}

	return (cmd_sbp);

} /* emlxs_fct_cmd_init() */


/* Called after receiving fct_cmd from COMSTAR */
static fct_status_t
emlxs_fct_cmd_accept(emlxs_port_t *port, fct_cmd_t *fct_cmd, uint16_t fct_state)
{
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_accept: "
		    "Invalid fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	mutex_enter(&cmd_sbp->fct_mtx);

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		mutex_exit(&cmd_sbp->fct_mtx);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_accept:2 "
		    "Invalid fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	if (cmd_sbp->fct_flags & EMLXS_FCT_ABORT_INP) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_accept: "
		    "Aborted fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_ABORT_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		MODSYM(fct_cmd_fca_aborted) (fct_cmd,
		    FCT_ABORT_SUCCESS, FCT_IOF_FCA_DONE);

		return (FCT_NOT_FOUND);
	}

	mutex_enter(&cmd_sbp->mtx);
	if (!(cmd_sbp->pkt_flags & PACKET_ULP_OWNED)) {
		mutex_exit(&cmd_sbp->mtx);
		mutex_exit(&cmd_sbp->fct_mtx);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_accept: "
		    "Busy fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_BUSY);
	}
	cmd_sbp->pkt_flags &= ~PACKET_ULP_OWNED;
	mutex_exit(&cmd_sbp->mtx);

	if (fct_state) {
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, fct_state);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_cmd_accept() */


/* Called after receiving fct_cmd from driver */
static fct_status_t
emlxs_fct_cmd_acquire(emlxs_port_t *port, fct_cmd_t *fct_cmd,
    uint16_t fct_state)
{
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if ((fct_cmd->cmd_oxid == 0) && (fct_cmd->cmd_rxid == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire: "
		    "Bad fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire: "
		    "Invalid fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	if ((cmd_sbp->pkt_flags & PACKET_ULP_OWNED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire: "
		    "Returned fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	mutex_enter(&cmd_sbp->fct_mtx);

	if ((fct_cmd->cmd_oxid == 0) && (fct_cmd->cmd_rxid == 0)) {
		mutex_exit(&cmd_sbp->fct_mtx);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire:2 "
		    "Bad fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		mutex_exit(&cmd_sbp->fct_mtx);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire:2 "
		    "Invalid fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	if ((cmd_sbp->pkt_flags & PACKET_ULP_OWNED)) {
		mutex_exit(&cmd_sbp->fct_mtx);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire:2 "
		    "Returned fct_cmd found! fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		return (FCT_NOT_FOUND);
	}

	if (cmd_sbp->fct_flags & EMLXS_FCT_ABORT_INP) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_cmd_acquire: "
		    "Aborting cmd. fct_cmd=%p state=%x",
		    fct_cmd, fct_state);

		if (fct_cmd->cmd_type == FCT_CMD_FCP_XCHG) {
			TGTPORTSTAT.FctOutstandingIO--;
		}

		fct_cmd->cmd_comp_status = FCT_FAILURE;

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_ABORT_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		MODSYM(fct_cmd_fca_aborted) (fct_cmd,
		    FCT_ABORT_SUCCESS, FCT_IOF_FCA_DONE);

		return (FCT_NOT_FOUND);
	}

	if (fct_state) {
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, fct_state);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_cmd_acquire() */


/* cmd_sbp->fct_mtx must be held to enter */
/* cmd_sbp->fct_mtx must be released before exiting */
/* Called before transitionally sending fct_cmd to driver */
/*ARGSUSED*/
static void
emlxs_fct_cmd_release(emlxs_port_t *port, fct_cmd_t *fct_cmd,
    uint16_t fct_state)
{
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if (fct_state) {
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, fct_state);
	}

	mutex_exit(&cmd_sbp->fct_mtx);

	return;

} /* emlxs_fct_cmd_release() */


/* cmd_sbp->fct_mtx must be held to enter */
/* cmd_sbp->fct_mtx must be released before exiting */
/* Called before posting fct_cmd back to COMSTAR */
/*ARGSUSED*/
static void
emlxs_fct_cmd_post(emlxs_port_t *port, fct_cmd_t *fct_cmd,
    uint16_t fct_state)
{
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	fc_packet_t *pkt;

	pkt = cmd_sbp->fct_pkt;
	cmd_sbp->fct_pkt = NULL;
	cmd_sbp->fct_flags &= ~EMLXS_FCT_IO_INP;

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags |= PACKET_ULP_OWNED;
	mutex_exit(&cmd_sbp->mtx);

	if (fct_state) {
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, fct_state);
	}

	mutex_exit(&cmd_sbp->fct_mtx);

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return;

} /* emlxs_fct_cmd_post() */


/* cmd_sbp->fct_mtx must be held to enter */
/* Called before completing fct_cmd back to COMSTAR */
static void
emlxs_fct_cmd_done(emlxs_port_t *port, fct_cmd_t *fct_cmd, uint16_t fct_state)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	fc_packet_t *pkt;

	/* Flags fct_cmd is no longer used */
	fct_cmd->cmd_oxid = 0;
	fct_cmd->cmd_rxid = 0;

	if (cmd_sbp->iotag != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Pkt still registered! channel=%p iotag=%d sbp=%p",
		    cmd_sbp->channel, cmd_sbp->iotag, cmd_sbp);

		if (cmd_sbp->channel) {
			if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
				emlxs_sli4_free_xri(port, cmd_sbp,
				    cmd_sbp->xrip, 1);
			} else {
				(void) emlxs_unregister_pkt(cmd_sbp->channel,
				    cmd_sbp->iotag, 0);
			}

		}
	}

	pkt = cmd_sbp->fct_pkt;
	cmd_sbp->fct_pkt = NULL;
	cmd_sbp->fct_flags &= ~EMLXS_FCT_IO_INP;

	if (fct_state) {
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, fct_state);
	}

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags |= PACKET_ULP_OWNED;
	cmd_sbp->pkt_flags &= ~PACKET_VALID;
	mutex_exit(&cmd_sbp->mtx);
	mutex_exit(&cmd_sbp->fct_mtx);


	mutex_destroy(&cmd_sbp->fct_mtx);
	mutex_destroy(&cmd_sbp->mtx);

	if (pkt) {
		emlxs_pkt_free(pkt);
	}

	return;

} /* emlxs_fct_cmd_done() */


static void
emlxs_fct_pkt_comp(fc_packet_t *pkt)
{
	emlxs_port_t *port;
#ifdef FMA_SUPPORT
	emlxs_hba_t *hba;
#endif	/* FMA_SUPPORT */
	emlxs_buf_t *sbp;
	emlxs_buf_t *cmd_sbp;
	fct_cmd_t *fct_cmd;
	fct_els_t *fct_els;
	fct_sol_ct_t *fct_ct;
	fct_status_t rval;

	sbp = PKT2PRIV(pkt);
	port = sbp->port;
#ifdef FMA_SUPPORT
	hba = HBA;
#endif	/* FMA_SUPPORT */
	fct_cmd = sbp->fct_cmd;

	rval = emlxs_fct_cmd_acquire(port, fct_cmd, EMLXS_FCT_PKT_COMPLETE);
	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_pkt_comp: "
		    "Unable to reacquire fct_cmd.");
		return;
	}
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	cmd_sbp->fct_flags &= ~EMLXS_FCT_IO_INP;
	cmd_sbp->fct_pkt = NULL;

	switch (fct_cmd->cmd_type) {
	case FCT_CMD_FCP_XCHG:
		if ((pkt->pkt_reason == FC_REASON_ABORTED) ||
		    (pkt->pkt_reason == FC_REASON_XCHG_DROPPED) ||
		    (pkt->pkt_reason == FC_REASON_OFFLINE)) {
			/*
			 * The error indicates this IO should be terminated
			 * immediately.
			 */
			cmd_sbp->fct_flags &= ~EMLXS_FCT_SEND_STATUS;

			emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_OWNED);
			/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_queue_cmd_for_termination:2 %p:%p x%x",
			    fct_cmd, cmd_sbp, fct_cmd->cmd_comp_status);
#endif /* FCT_API_TRACE */

			MODSYM(fct_queue_cmd_for_termination) (fct_cmd,
			    FCT_ABTS_RECEIVED);

			break;
		}

		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp,
		    EMLXS_FCT_PKT_FCPRSP_COMPLETE);

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_response_done:2 %p:%p x%x outio %d",
		    fct_cmd, cmd_sbp, fct_cmd->cmd_comp_status,
		    TGTPORTSTAT.FctOutstandingIO);
#else
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_pkt_comp: fct_send_response_done. dbuf=%p",
		    sbp->fct_buf);
#endif /* FCT_API_TRACE */

		TGTPORTSTAT.FctOutstandingIO--;

		MODSYM(fct_send_response_done) (fct_cmd,
		    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);

		break;

	case FCT_CMD_RCVD_ELS:

		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp,
		    EMLXS_FCT_PKT_ELSRSP_COMPLETE);

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_response_done:3 %p:%p x%x",
		    fct_cmd, cmd_sbp, fct_cmd->cmd_comp_status);
#endif /* FCT_API_TRACE */

		MODSYM(fct_send_response_done) (fct_cmd,
		    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);

		break;

	case FCT_CMD_SOL_ELS:

		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp,
		    EMLXS_FCT_PKT_ELSCMD_COMPLETE);

		fct_els = (fct_els_t *)fct_cmd->cmd_specific;

		if (fct_els->els_resp_payload) {
			EMLXS_MPDATA_SYNC(pkt->pkt_resp_dma, 0,
			    pkt->pkt_rsplen, DDI_DMA_SYNC_FORKERNEL);

			bcopy((uint8_t *)pkt->pkt_resp,
			    (uint8_t *)fct_els->els_resp_payload,
			    fct_els->els_resp_size);
		}

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_cmd_done:1 %p:%p x%x",
		    fct_cmd, cmd_sbp, fct_cmd->cmd_comp_status);
#endif /* FCT_API_TRACE */

#ifdef FMA_SUPPORT
		if (emlxs_fm_check_dma_handle(hba, pkt->pkt_resp_dma)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "fct_pkt_comp: hdl=%p",
			    pkt->pkt_resp_dma);
			MODSYM(fct_send_cmd_done) (fct_cmd, FCT_FAILURE,
			    FCT_IOF_FCA_DONE);

			break;
		}
#endif /* FMA_SUPPORT */

		MODSYM(fct_send_cmd_done) (fct_cmd, FCT_SUCCESS,
		    FCT_IOF_FCA_DONE);

		break;

	case FCT_CMD_SOL_CT:

		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp,
		    EMLXS_FCT_PKT_CTCMD_COMPLETE);

		fct_ct = (fct_sol_ct_t *)fct_cmd->cmd_specific;

		if (fct_ct->ct_resp_payload) {
			EMLXS_MPDATA_SYNC(pkt->pkt_resp_dma, 0,
			    pkt->pkt_rsplen, DDI_DMA_SYNC_FORKERNEL);

			bcopy((uint8_t *)pkt->pkt_resp,
			    (uint8_t *)fct_ct->ct_resp_payload,
			    fct_ct->ct_resp_size);
		}

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_cmd_done:2 %p:%p x%x",
		    fct_cmd, cmd_sbp, fct_cmd->cmd_comp_status);
#endif /* FCT_API_TRACE */

#ifdef FMA_SUPPORT
		if (emlxs_fm_check_dma_handle(hba, pkt->pkt_resp_dma)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "fct_pkt_comp: hdl=%p",
			    pkt->pkt_resp_dma);
			MODSYM(fct_send_cmd_done) (fct_cmd, FCT_FAILURE,
			    FCT_IOF_FCA_DONE);

			break;
		}
#endif /* FMA_SUPPORT */
		MODSYM(fct_send_cmd_done) (fct_cmd, FCT_SUCCESS,
		    FCT_IOF_FCA_DONE);

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_pkt_comp: Invalid cmd type found. type=%x",
		    fct_cmd->cmd_type);

		emlxs_fct_cmd_done(port, fct_cmd, EMLXS_FCT_IO_DONE);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		break;
	}

	emlxs_pkt_free(pkt);
	return;

} /* emlxs_fct_pkt_comp() */


static void
emlxs_fct_abort_pkt_comp(fc_packet_t *pkt)
{
#ifdef FCT_API_TRACE
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_port_t *port;

	sbp = PKT2PRIV(pkt);
	port = sbp->port;
	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_abort_pkt_comp: %p: xri=%d cmd=%x status=%x",
	    sbp->fct_cmd, sbp,
	    iocb->ULPCONTEXT, iocb->ULPCOMMAND, iocb->ULPSTATUS);
#endif /* FCT_API_TRACE */

	emlxs_pkt_free(pkt);
	return;

} /* emlxs_fct_abort_pkt_comp() */


/* COMSTAR ENTER POINT (INDIRECT) */
static fct_status_t
emlxs_fct_send_els_cmd(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t did;
	uint32_t sid;
	fct_els_t *fct_els;
	fc_packet_t *pkt;
	emlxs_buf_t *cmd_sbp;
	fct_status_t rval;

	did = fct_cmd->cmd_rportid;
	sid = fct_cmd->cmd_lportid;
	fct_els = (fct_els_t *)fct_cmd->cmd_specific;

	if (!(pkt = emlxs_pkt_alloc(port, fct_els->els_req_size,
	    fct_els->els_resp_size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_els_cmd: Unable to allocate packet.");

		return (FCT_BUSY);
	}

	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd, EMLXS_FCT_SEND_ELS_REQ);
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	cmd_sbp->channel = &hba->chan[hba->channel_els];
	cmd_sbp->fct_type = EMLXS_FCT_ELS_REQ;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);
	cmd_sbp->fct_pkt = pkt;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_timeout = (pkt->pkt_timeout > 60)? 60: pkt->pkt_timeout;
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_send_els_cmd: pkt_timeout=%d ratov=%d",
	    pkt->pkt_timeout, hba->fc_ratov);

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(sid);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Copy the cmd payload */
	bcopy((uint8_t *)fct_els->els_req_payload, (uint8_t *)pkt->pkt_cmd,
	    fct_els->els_req_size);

	cmd_sbp->fct_flags |= EMLXS_FCT_IO_INP;
	emlxs_fct_cmd_release(port, fct_cmd, EMLXS_FCT_REQ_PENDING);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_els_cmd: Unable to send packet.");

		/* Reacquire ownership of the fct_cmd */
		rval = emlxs_fct_cmd_acquire(port, fct_cmd, 0);
		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_send_els_cmd: "
			    "Unable to reacquire fct_cmd.");
			return (rval);
		}
		/* mutex_enter(&cmd_sbp->fct_mtx); */

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_OWNED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_BUSY);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_send_els_cmd() */


/* cmd_sbp->fct_mtx must be held to enter */
/* cmd_sbp->fct_mtx must be released before exiting */
static fct_status_t
emlxs_fct_send_els_rsp(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t did;
	uint32_t sid;
	fct_els_t *fct_els;
	fc_packet_t *pkt;
	emlxs_buf_t *cmd_sbp;
	fct_status_t rval;

	fct_els = (fct_els_t *)fct_cmd->cmd_specific;
	did = fct_cmd->cmd_rportid;
	sid = fct_cmd->cmd_lportid;
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if (!(pkt = emlxs_pkt_alloc(port, fct_els->els_resp_size, 0, 0,
	    KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_els_rsp: Unable to allocate packet.");

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_FAILURE);
	}

	EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, EMLXS_FCT_SEND_ELS_RSP);

	cmd_sbp->fct_type = EMLXS_FCT_ELS_RSP;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);
	cmd_sbp->fct_pkt = pkt;

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_timeout = (pkt->pkt_timeout > 60)? 60: pkt->pkt_timeout;
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_RSP;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(sid);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = fct_cmd->cmd_oxid;
	pkt->pkt_cmd_fhdr.rx_id = fct_cmd->cmd_rxid;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Copy the resp payload to pkt_cmd buffer */
	bcopy((uint8_t *)fct_els->els_resp_payload, (uint8_t *)pkt->pkt_cmd,
	    fct_els->els_resp_size);

	cmd_sbp->fct_flags |= EMLXS_FCT_IO_INP;
	emlxs_fct_cmd_release(port, fct_cmd, EMLXS_FCT_RSP_PENDING);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_els_rsp: Unable to send packet.");

		/* Reacquire ownership of the fct_cmd */
		rval = emlxs_fct_cmd_acquire(port, fct_cmd, 0);
		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_send_els_rsp: "
			    "Unable to reacquire fct_cmd.");
			return (rval);
		}
		/* mutex_enter(&cmd_sbp->fct_mtx); */

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_CMD_POSTED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_FAILURE);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_send_els_rsp() */


/* COMSTAR ENTER POINT (INDIRECT) */
static fct_status_t
emlxs_fct_send_ct_cmd(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t did;
	fct_sol_ct_t *fct_ct;
	fc_packet_t *pkt;
	emlxs_buf_t *cmd_sbp;
	fct_status_t rval;

	did = fct_cmd->cmd_rportid;
	fct_ct = (fct_sol_ct_t *)fct_cmd->cmd_specific;

	if (!(pkt = emlxs_pkt_alloc(port, fct_ct->ct_req_size,
	    fct_ct->ct_resp_size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_ct_cmd: Unable to allocate packet.");
		return (FCT_BUSY);
	}

	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd, EMLXS_FCT_SEND_CT_REQ);
	/* mutex_enter(&cmd_sbp->fct_mtx); */

	cmd_sbp->channel = &hba->chan[hba->channel_ct];
	cmd_sbp->fct_type = EMLXS_FCT_CT_REQ;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);
	cmd_sbp->fct_pkt = pkt;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_timeout = (pkt->pkt_timeout > 60)? 60: pkt->pkt_timeout;
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_FC_SERVICES;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Copy the cmd payload */
	bcopy((uint8_t *)fct_ct->ct_req_payload, (uint8_t *)pkt->pkt_cmd,
	    fct_ct->ct_req_size);

	cmd_sbp->fct_flags |= EMLXS_FCT_IO_INP;
	emlxs_fct_cmd_release(port, fct_cmd, EMLXS_FCT_REQ_PENDING);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_send_ct_cmd: Unable to send packet.");

		/* Reacquire ownership of the fct_cmd */
		rval = emlxs_fct_cmd_acquire(port, fct_cmd, 0);
		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_send_ct_cmd: "
			    "Unable to reacquire fct_cmd.");

			return (rval);
		}
		/* mutex_enter(&cmd_sbp->fct_mtx); */

		emlxs_fct_cmd_post(port, fct_cmd, EMLXS_FCT_OWNED);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		return (FCT_BUSY);
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_send_ct_cmd() */


/* cmd_sbp->fct_mtx must be held to enter */
static uint32_t
emlxs_fct_pkt_abort_txq(emlxs_port_t *port, emlxs_buf_t *cmd_sbp)
{
	emlxs_hba_t *hba = HBA;
	NODELIST *nlp;
	fc_packet_t *pkt;
	emlxs_buf_t *sbp;
	emlxs_buf_t *iocb_sbp;
	uint8_t channelno;
	CHANNEL *cp;
	IOCBQ *iocbq;
	IOCBQ *next;
	IOCBQ *prev;
	uint32_t found;
	uint32_t pkt_flags;

	/* Check the transmit queue */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	/* The IOCB could point to a cmd_sbp (no packet) or a sbp (packet) */
	pkt = cmd_sbp->fct_pkt;
	if (pkt) {
		sbp = PKT2PRIV(pkt);
		if (sbp == NULL) {
			goto done;
		}
		iocb_sbp = sbp;
		iocbq = &sbp->iocbq;
		pkt_flags = sbp->pkt_flags;
	} else {
		sbp = NULL;
		iocb_sbp = cmd_sbp;
		iocbq = &cmd_sbp->iocbq;
		pkt_flags = cmd_sbp->pkt_flags;
	}

	nlp = (NODELIST *)cmd_sbp->node;
	cp = (CHANNEL *)cmd_sbp->channel;
	channelno = (cp) ? cp->channelno : 0;

	if (pkt_flags & PACKET_IN_TXQ) {
		/* Find it on the queue */
		found = 0;
		if (iocbq->flag & IOCB_PRIORITY) {
			/* Search the priority queue */
			prev = NULL;
			next = (IOCBQ *)nlp->nlp_ptx[channelno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}

					if (nlp->nlp_ptx[channelno].q_last ==
					    (void *)iocbq) {
						nlp->nlp_ptx[channelno].q_last =
						    (void *)prev;
					}

					if (nlp->nlp_ptx[channelno].q_first ==
					    (void *)iocbq) {
						nlp->nlp_ptx[channelno].
						    q_first =
						    (void *)iocbq->next;
					}

					nlp->nlp_ptx[channelno].q_cnt--;
					iocbq->next = NULL;
					found = 1;
					break;
				}

				prev = next;
				next = next->next;
			}
		} else {
			/* Search the normal queue */
			prev = NULL;
			next = (IOCBQ *)nlp->nlp_tx[channelno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}

					if (nlp->nlp_tx[channelno].q_last ==
					    (void *)iocbq) {
						nlp->nlp_tx[channelno].q_last =
						    (void *)prev;
					}

					if (nlp->nlp_tx[channelno].q_first ==
					    (void *)iocbq) {
						nlp->nlp_tx[channelno].q_first =
						    (void *)iocbq->next;
					}

					nlp->nlp_tx[channelno].q_cnt--;
					iocbq->next = NULL;
					found = 1;
					break;
				}

				prev = next;
				next = (IOCBQ *)next->next;
			}
		}

		if (!found) {
			goto done;
		}

		/* Check if node still needs servicing */
		if ((nlp->nlp_ptx[channelno].q_first) ||
		    (nlp->nlp_tx[channelno].q_first &&
		    !(nlp->nlp_flag[channelno] & NLP_CLOSED))) {

			/*
			 * If this is the base node, don't shift the pointers
			 */
			/* We want to drain the base node before moving on */
			if (!nlp->nlp_base) {
				/* Shift channel queue pointers to next node */
				cp->nodeq.q_last = (void *)nlp;
				cp->nodeq.q_first = nlp->nlp_next[channelno];
			}
		} else {
			/* Remove node from channel queue */

			/* If this is the last node on list */
			if (cp->nodeq.q_last == (void *)nlp) {
				cp->nodeq.q_last = NULL;
				cp->nodeq.q_first = NULL;
				cp->nodeq.q_cnt = 0;
			} else {
				/* Remove node from head */
				cp->nodeq.q_first = nlp->nlp_next[channelno];
				((NODELIST *)cp->nodeq.q_last)->
				    nlp_next[channelno] = cp->nodeq.q_first;
				cp->nodeq.q_cnt--;
			}

			/* Clear node */
			nlp->nlp_next[channelno] = NULL;
		}

		/* The IOCB points to iocb_sbp (no packet) or a sbp (packet) */
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			emlxs_sli4_free_xri(port, iocb_sbp, iocb_sbp->xrip, 1);
		} else {
			(void) emlxs_unregister_pkt(cp, iocb_sbp->iotag, 0);
		}

		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		if (pkt) {
			emlxs_pkt_free(pkt);
			cmd_sbp->fct_pkt = NULL;
		}
		return (1);
	}
done:
	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
	return (0);

} /* emlxs_fct_pkt_abort_txq() */


/* COMSTAR ENTER POINT */
/* FCT_NOT_FOUND & FCT_ABORT_SUCCESS indicates IO is done */
/* FCT_SUCCESS indicates abort will occur asyncronously */
static fct_status_t
emlxs_fct_abort(fct_local_port_t *fct_port, fct_cmd_t *fct_cmd,
    uint32_t flags)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	emlxs_buf_t *cmd_sbp2;
	emlxs_buf_t *prev;
	fc_packet_t *pkt;
	emlxs_buf_t *sbp = NULL;
	kmutex_t *fct_mtx;
	uint32_t fct_state;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	fct_mtx = &cmd_sbp->fct_mtx;

top:

	/* Sanity check */
	if ((fct_cmd->cmd_oxid == 0) && (fct_cmd->cmd_rxid == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_abort: Bad fct_cmd=%p.", fct_cmd);

		return (FCT_NOT_FOUND);
	}

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_abort: Pkt invalid. cmd_sbp=%p",
		    cmd_sbp);

		return (FCT_NOT_FOUND);
	}

	if (mutex_tryenter(fct_mtx) == 0) {
		/*
		 * This code path handles a race condition if
		 * an IO completes, in emlxs_fct_handle_fcp_event(),
		 * and we get an abort at the same time.
		 */
		delay(drv_usectohz(100000));	/* 100 msec */
		goto top;
	}
	/* At this point, we have entered the mutex */

	/* Sanity check */
	if ((fct_cmd->cmd_oxid == 0) && (fct_cmd->cmd_rxid == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_abort: Bad fct_cmd=%p.", fct_cmd);

		mutex_exit(fct_mtx);
		return (FCT_NOT_FOUND);
	}

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_abort: Pkt invalid. cmd_sbp=%p",
		    cmd_sbp);

		mutex_exit(fct_mtx);
		return (FCT_NOT_FOUND);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_abort: hbastate=%x. "
	    "xid=%x,%x cmd_sbp=%p fctstate=%d flags=%x,%x,%x",
	    hba->state, fct_cmd->cmd_oxid, fct_cmd->cmd_rxid, cmd_sbp,
	    cmd_sbp->fct_state, flags, cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

	if (cmd_sbp->fct_flags & EMLXS_FCT_ABORT_INP) {
		EMLXS_SLI_ISSUE_IOCB_CMD(hba, cmd_sbp->channel, 0);

		/* If Abort is already in progress */
		mutex_exit(fct_mtx);
		return (FCT_SUCCESS);
	}
	cmd_sbp->fct_flags |= EMLXS_FCT_ABORT_INP;

	if (flags & FCT_IOF_FORCE_FCA_DONE) {
		fct_cmd->cmd_handle = 0;
	}

	TGTPORTSTAT.FctAbortSent++;

	switch (cmd_sbp->fct_state) {
	/* These are currently owned by COMSTAR. */
	/* They were last processed by emlxs_fct_cmd_post() */
	/* We have NO exchange resources associated with this IO. */
	case EMLXS_FCT_OWNED:
		goto abort_done;

	/* These are on the unsol waitQ in the driver */
	case EMLXS_FCT_CMD_WAITQ:
		/* Find and remove it */
		mutex_enter(&EMLXS_PORT_LOCK);
		cmd_sbp2 = port->fct_wait_head;
		prev = NULL;
		while (cmd_sbp2) {
			if (cmd_sbp2 == cmd_sbp) {
				/* Remove it */
				if (prev) {
					prev->next = cmd_sbp2->next;
				}

				if (port->fct_wait_head == cmd_sbp2) {
					port->fct_wait_head = cmd_sbp2->next;
				}

				if (port->fct_wait_tail == cmd_sbp2) {
					port->fct_wait_tail = prev;
				}

				cmd_sbp2->next = NULL;
				break;
			}
			prev = cmd_sbp2;
			cmd_sbp2 = cmd_sbp2->next;
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		/*FALLTHROUGH*/

	/* These are currently owned by COMSTAR. */
	/* They were last processed by emlxs_fct_cmd_post() */
	/* We have residual exchange resources associated with this IO */
	case EMLXS_FCT_CMD_POSTED:
		switch (fct_cmd->cmd_type) {
		case FCT_CMD_FCP_XCHG: /* Unsol */
			TGTPORTSTAT.FctOutstandingIO--;
			emlxs_abort_fct_exchange(hba, port, fct_cmd->cmd_rxid);
			break;

		case FCT_CMD_RCVD_ELS: /* Unsol */
			emlxs_abort_els_exchange(hba, port, fct_cmd->cmd_rxid);
			break;
		}

		goto abort_done;

	/* These are active in the driver */
	/* They were last processed by emlxs_fct_cmd_release() */
	case EMLXS_FCT_RSP_PENDING:
	case EMLXS_FCT_REQ_PENDING:
	case EMLXS_FCT_REG_PENDING:
	case EMLXS_FCT_DATA_PENDING:
	case EMLXS_FCT_STATUS_PENDING:

		/* Abort anything pending */
		if (emlxs_fct_pkt_abort_txq(port, cmd_sbp)) {

			if (fct_cmd->cmd_type == FCT_CMD_FCP_XCHG) {
				TGTPORTSTAT.FctOutstandingIO--;
			}

			goto abort_done;
		}

		/* If we're not online, then all IO will be flushed anyway */
		if (!(hba->flag & FC_ONLINE_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_abort: Not online. fct_cmd=%p.",
			    fct_cmd);

			emlxs_fct_cmd_release(port, fct_cmd, 0);
			/* mutex_exit(&cmd_sbp->fct_mtx); */

			/* The cmd will be aborted on the */
			/* next emlxs_fct_cmd_acquire */
			/* because EMLXS_FCT_ABORT_INP is set. */
			break;
		}

		/* Try to send abort request */
		if (!(pkt = emlxs_pkt_alloc(port, 0, 0, 0, KM_NOSLEEP))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
			    "fct_abort: Unable to allocate packet. "
			    "fct_cmd=%p",
			    fct_cmd);

			emlxs_fct_cmd_release(port, fct_cmd, 0);
			/* mutex_exit(&cmd_sbp->fct_mtx); */

			/* The cmd will be aborted on the */
			/* next emlxs_fct_cmd_acquire anyway */
			/* because EMLXS_FCT_ABORT_INP is set. */
			break;
		}

		sbp = emlxs_fct_pkt_init(port, fct_cmd, pkt);

		pkt->pkt_tran_type = FC_PKT_OUTBOUND;
		pkt->pkt_timeout =
		    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
		pkt->pkt_comp = emlxs_fct_abort_pkt_comp;

		/* Build the fc header */
		pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(fct_cmd->cmd_rportid);
		pkt->pkt_cmd_fhdr.r_ctl = R_CTL_STATUS;
		pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
		pkt->pkt_cmd_fhdr.type = FC_TYPE_BASIC_LS;
		pkt->pkt_cmd_fhdr.f_ctl =
		    (F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ | F_CTL_END_SEQ);
		pkt->pkt_cmd_fhdr.seq_id = 0;
		pkt->pkt_cmd_fhdr.df_ctl = 0;
		pkt->pkt_cmd_fhdr.seq_cnt = 0;
		pkt->pkt_cmd_fhdr.ox_id = fct_cmd->cmd_oxid;
		pkt->pkt_cmd_fhdr.rx_id = fct_cmd->cmd_rxid;
		pkt->pkt_cmd_fhdr.ro = 0;

		/* Make sure xrip is setup */
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			if (!sbp->xrip || sbp->xrip->state == XRI_STATE_FREE) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
				    "fct_abort: "
				    "Unable to acquire xri. (xid:%x,%x)",
				    fct_cmd->cmd_oxid, fct_cmd->cmd_rxid);

				emlxs_pkt_free(pkt);
				return (FCT_NOT_FOUND);
			}
		}

		cmd_sbp->fct_cmd = fct_cmd;
		cmd_sbp->abort_attempts++;

		/* Now disassociate the sbp / pkt from the fct_cmd */
		sbp->fct_cmd = NULL;

		if (hba->state >= FC_LINK_UP) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_abort: ABORT: %p xid:%x,%x",
			    fct_cmd, fct_cmd->cmd_oxid, fct_cmd->cmd_rxid);

			fct_state = EMLXS_FCT_ABORT_PENDING;

		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_abort: CLOSE: %p xid:%x,%x",
			    fct_cmd, fct_cmd->cmd_oxid, fct_cmd->cmd_rxid);

			fct_state = EMLXS_FCT_CLOSE_PENDING;
		}

		emlxs_fct_cmd_release(port, fct_cmd, fct_state);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
			    "fct_abort: Unable to send abort packet.");

			emlxs_pkt_free(pkt);

			/* The cmd will be aborted on the */
			/* next emlxs_fct_cmd_acquire anyway */
			/* because EMLXS_FCT_ABORT_INP is set. */
		}

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_abort: Unexpected fct_state. "
		    "fct_cmd=%p state=%d",
		    fct_cmd, cmd_sbp->fct_state);

		emlxs_fct_cmd_release(port, fct_cmd, 0);
		/* mutex_exit(&cmd_sbp->fct_mtx); */

		/* The cmd will be aborted on the */
		/* next emlxs_fct_cmd_acquire anyway */
		/* because EMLXS_FCT_ABORT_INP is set. */

	}	/* switch */

	return (FCT_SUCCESS);

abort_done:

	emlxs_fct_cmd_done(port, fct_cmd,
	    EMLXS_FCT_ABORT_DONE);
	/* mutex_exit(&cmd_sbp->fct_mtx); */

	return (FCT_ABORT_SUCCESS);

} /* emlxs_fct_abort() */


extern void
emlxs_fct_link_up(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;

	mutex_enter(&EMLXS_PORT_LOCK);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_link_up port %p fct flags x%x",
	    port->fct_port, port->fct_flags);
#endif /* FCT_API_TRACE */

	if (port->fct_port &&
	    (port->fct_flags & FCT_STATE_PORT_ONLINE) &&
	    !(port->fct_flags & FCT_STATE_LINK_UP)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_link_up event.");

		port->fct_flags &= ~FCT_STATE_LINK_UP_ACKED;
		port->fct_flags &= ~FCT_STATE_FLOGI_CMPL;
		port->fct_flags |= FCT_STATE_LINK_UP;
		mutex_exit(&EMLXS_PORT_LOCK);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_handle_event LINK_UP");
#endif /* FCT_API_TRACE */
		MODSYM(fct_handle_event) (port->fct_port, FCT_EVENT_LINK_UP,
		    0, 0);
	} else if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
		mutex_exit(&EMLXS_PORT_LOCK);

		if (port->vpi == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_link_up event. FCT port offline (%x). "
			    "Disable link.",
			    port->fct_flags);

			/* Take link down and hold it down */
			(void) emlxs_reset_link(hba, 0, 1);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct_link_up event. FCT port offline (%x).",
			    port->fct_flags);
		}
	} else {
		mutex_exit(&EMLXS_PORT_LOCK);
	}

	return;

} /* emlxs_fct_link_up() */


extern void
emlxs_fct_link_down(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;

	mutex_enter(&EMLXS_PORT_LOCK);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_link_down port %p fct flags x%x",
	    port->fct_port, port->fct_flags);
#endif /* FCT_API_TRACE */

	if (port->fct_port &&
	    (port->fct_flags & FCT_STATE_PORT_ONLINE) &&
	    (port->fct_flags & FCT_STATE_LINK_UP)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_link_down event.");

		port->fct_flags &= ~FCT_STATE_LINK_UP_ACKED;
		port->fct_flags &= ~FCT_STATE_FLOGI_CMPL;
		port->fct_flags &= ~FCT_STATE_LINK_UP;
		mutex_exit(&EMLXS_PORT_LOCK);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_handle_event LINK_DOWN");
#endif /* FCT_API_TRACE */

		MODSYM(fct_handle_event) (port->fct_port, FCT_EVENT_LINK_DOWN,
		    0, 0);
	} else {
		mutex_exit(&EMLXS_PORT_LOCK);
	}

	return;

} /* emlxs_fct_link_down() */


void
emlxs_abort_fct_exchange(emlxs_hba_t *hba, emlxs_port_t *port, uint32_t rxid)
{
	CHANNEL *cp;
	IOCBQ *iocbq;
	IOCB *iocb;

	if (rxid == 0 || rxid == 0xFFFF) {
		return;
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Aborting FCT exchange: xid=%x", rxid);

		if (emlxs_sli4_unreserve_xri(port, rxid, 1) == 0) {
			/* We have no way to abort unsolicited exchanges */
			/* that we have not responded to at this time */
			/* So we will return for now */
			return;
		}
	}

	cp = &hba->chan[hba->channel_fcp];

	mutex_enter(&EMLXS_FCTAB_LOCK);

	/* Create the abort IOCB */
	if (hba->state >= FC_LINK_UP) {
		iocbq = emlxs_create_abort_xri_cx(port, NULL, rxid, cp,
		    CLASS3, ABORT_TYPE_ABTS);
	} else {
		iocbq = emlxs_create_close_xri_cx(port, NULL, rxid, cp);
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

	if (iocbq) {
		iocb = &iocbq->iocb;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Aborting FCT exchange: xid=%x iotag=%d", rxid,
		    iocb->ULPIOTAG);

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);
	}

} /* emlxs_abort_fct_exchange() */


extern uint32_t
emlxs_fct_stmf_alloc(emlxs_hba_t *hba, MATCHMAP *mp)
{
	emlxs_port_t *port = &PPORT;
	stmf_data_buf_t *db;

	if (mp->tag < MEM_FCTSEG) {
		return (0);
	}

	db = MODSYM(stmf_alloc) (STMF_STRUCT_DATA_BUF, 0, 0);

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "stmf_alloc:%p iotag=%d phys %p virt %p sz %d",
	    db, mp->tag, mp->phys, mp->virt, mp->size);
#endif /* FCT_API_TRACE */

	if (db == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_stmf_alloc: alloc failed.");
		return (1);
	}

	db->db_port_private = (void*)mp;
	db->db_sglist[0].seg_addr = mp->virt;
	db->db_sglist[0].seg_length = mp->size;
	db->db_buf_size = mp->size;
	db->db_sglist_length = 1;

	mp->fct_private = (void*)db;

	return (0);

} /* emlxs_fct_stmf_alloc() */


/* ARGSUSED */
extern void
emlxs_fct_stmf_free(emlxs_hba_t *hba, MATCHMAP *mp)
{
#ifdef FCT_API_TRACE
	emlxs_port_t *port = &PPORT;
#endif /* FCT_API_TRACE */
	stmf_data_buf_t *db;

	if (mp->tag < MEM_FCTSEG) {
		return;
	}

	db = (stmf_data_buf_t *)mp->fct_private;
	mp->fct_private = NULL;

	if (db == NULL) {
		return;
	}

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "stmf_free:%p iotag=%d",
	    db, mp->tag);
#endif /* FCT_API_TRACE */

	MODSYM(stmf_free) (db);

	return;

} /* emlxs_fct_stmf_free() */


static void
emlxs_fct_memseg_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	char **arrayp = NULL;
	uint32_t cnt = 0;
	char buf[32];
	uint32_t rval;
	uint8_t *datap;
	int i;
	int j;
	int fct_memseg_cnt = 0;
	int numblks;
	int memsize;
	emlxs_memseg_t *fct_memseg = NULL;
	uint32_t fct_memseg_size = 0;
	emlxs_memseg_t *current;
	emlxs_memseg_t *next;
	emlxs_memseg_t *seg;

	port->fct_memseg = NULL;
	port->fct_memseg_cnt = 0;

	/* Check for the per adapter setting */
	(void) snprintf(buf, sizeof (buf), "%s%d-fct-bufpool", DRIVER_NAME,
	    hba->ddiinst);
	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS), buf, &arrayp, &cnt);

	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		/* Check for the global setting */
		cnt = 0;
		arrayp = NULL;
		rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
		    (DDI_PROP_DONTPASS), "fct-bufpool", &arrayp, &cnt);
	}

	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		goto default_config;
	}

	fct_memseg_size = cnt * sizeof (emlxs_memseg_t);
	fct_memseg = kmem_zalloc(fct_memseg_size, KM_SLEEP);

	if (!fct_memseg) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Unable to alloc fct_memseg. cnt=%d. "
		    "Trying default config.",
		    cnt);
		goto default_config;
	}

	for (i = 0; i < cnt; i++) {
		datap = (uint8_t *)arrayp[i];
		if (datap == 0) {
			break;
		}

		while (*datap == ' ') {	/* Skip spaces */
			datap++;
		}

		memsize = emlxs_str_atoi(datap);

		while ((*datap != ':') && (*datap != 0)) {
			datap++;
		}
		if (*datap == ':') { /* Skip past delimeter */
			datap++;
		}
		while (*datap == ' ') { /* Skip spaces */
			datap++;
		}

		numblks = emlxs_str_atoi(datap);

		/* Check for a bad entry */
		if (!memsize || !numblks) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "fct-bufpool: Entry %d:%d. Invalid.",
			    memsize, numblks);
			continue;
		}

		fct_memseg[fct_memseg_cnt].fc_memsize = memsize;
		fct_memseg[fct_memseg_cnt].fc_numblks = numblks;
		fct_memseg_cnt++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct-bufpool: Entry:%d  %d:%d",
		    fct_memseg_cnt, memsize, numblks);
	}

	if (!fct_memseg_cnt) {
		kmem_free(fct_memseg, fct_memseg_size);
		fct_memseg_size = 0;
		fct_memseg = NULL;
	}

default_config:
	/* If buffer list is empty, setup defaults */
	if (!fct_memseg) {

		fct_memseg_size = 8 * sizeof (emlxs_memseg_t);
		fct_memseg = kmem_zalloc(fct_memseg_size, KM_SLEEP);

		if (!fct_memseg) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "Unable to alloc default port buffer pool. "
			    "fct_memseg_cnt=%d",
			    cnt);
			return;
		}

		i = 0;
		numblks = FCT_BUF_COUNT_2K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 2 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_2K;
		}
		numblks = FCT_BUF_COUNT_4K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 4 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_4K;
		}
		numblks = FCT_BUF_COUNT_8K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 8 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_8K;
		}
		numblks = FCT_BUF_COUNT_16K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 16 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_16K;
		}
		numblks = FCT_BUF_COUNT_32K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 32 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_32K;
		}
		numblks = FCT_BUF_COUNT_64K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 64 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_64K;
		}
		numblks = FCT_BUF_COUNT_128K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 128 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_128K;
		}
		numblks = FCT_BUF_COUNT_256K;
		if (numblks) {
			fct_memseg[i].fc_memsize = 256 * 1024;
			fct_memseg[i++].fc_numblks = FCT_BUF_COUNT_256K;
		}
		fct_memseg_cnt = i;
	}

	port->fct_memseg = kmem_zalloc((fct_memseg_cnt *
	    sizeof (emlxs_memseg_t)), KM_SLEEP);

	if (!port->fct_memseg) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Unable to alloc port buffer pool. fct_memseg_cnt=%d",
		    fct_memseg_cnt);
		kmem_free(fct_memseg, fct_memseg_size);
		return;
	}

	/* Initalize port bucket list */
	port->fct_memseg_cnt = fct_memseg_cnt;

	/* Sort the entries smallest to largest */
	seg = port->fct_memseg;
	for (i = 0; i < fct_memseg_cnt; i++, seg++) {

		/* Find next smallest buffer */
		current = fct_memseg;
		next = NULL;
		for (j = 0; j < fct_memseg_cnt; j++, current++) {
			if (current->fc_memsize == 0) {
				continue;
			}

			if (next == NULL) {
				next = current;
				continue;
			}

			if (current->fc_memsize < next->fc_memsize) {
				next = current;
			}
		}

		/* Save next entry */
		seg->fc_memsize = next->fc_memsize;
		seg->fc_numblks = next->fc_numblks;
		next->fc_memsize = 0;
		next->fc_numblks = 0;
	}

	kmem_free(fct_memseg, fct_memseg_size);

	/* Complete the initialization */
	seg = port->fct_memseg;
	for (i = 0; i < port->fct_memseg_cnt; i++, seg++) {
/*		seg->fc_memsize = ; Already setup */
/*		seg->fc_numblks = ; Already setup */

		(void) snprintf(seg->fc_label, sizeof (seg->fc_label),
		    "FCT_DMEM_%d", seg->fc_memsize);

		seg->fc_memtag   = MEM_FCTSEG + i;
		seg->fc_memflag  = FC_MBUF_DMA | FC_MBUF_SNGLSG;
		seg->fc_memalign = 32;
		seg->fc_hi_water = 0xFFFF;
		seg->fc_lo_water = seg->fc_numblks;
		seg->fc_numblks  = 0;
		seg->fc_step = 1;
	}

	return;

} /* emlxs_fct_memseg_init() */


fct_status_t
emlxs_fct_dmem_init(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_memseg_t *seg;
	int32_t i;

	/* Initialize the fct memseg list */
	emlxs_fct_memseg_init(hba);

	if (!port->fct_memseg || !port->fct_memseg_cnt) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_dmem_init: fct_memseg list is empty.");
		return (FCT_FAILURE);
	}

	/* Create the DMA buffer pools */
	seg = port->fct_memseg;
	for (i = 0; i < port->fct_memseg_cnt; i++, seg++) {

		(void) emlxs_mem_pool_create(hba, seg);

		if (seg->fc_numblks < seg->fc_lo_water) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "%s: count=%d size=%d flags=%x lo=%d hi=%d",
			    seg->fc_label, seg->fc_numblks,
			    seg->fc_memsize, seg->fc_memflag, seg->fc_lo_water,
			    seg->fc_hi_water);
		}
	}

	return (FCT_SUCCESS);

} /* emlxs_fct_dmem_init */


void
emlxs_fct_dmem_fini(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_memseg_t *seg;
	int32_t i;

	if (!port->fct_memseg || !port->fct_memseg_cnt) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "fct_dmem_fini: fct_memseg list is empty.");
		return;
	}

	/* Destroy the dmem buffer pools */
	seg = port->fct_memseg;
	for (i = 0; i < port->fct_memseg_cnt; i++, seg++) {
		(void) emlxs_mem_pool_destroy(hba, seg);
	}

	/* Clear the segment space */
	kmem_free(port->fct_memseg,
	    (port->fct_memseg_cnt * sizeof (emlxs_memseg_t)));

	port->fct_memseg = 0;
	port->fct_memseg_cnt = 0;

	return;

} /* emlxs_fct_dmem_fini */


/* COMSTAR ENTER POINT */
/*ARGSUSED*/
static stmf_data_buf_t *
emlxs_fct_dbuf_alloc(fct_local_port_t *fct_port, uint32_t size,
    uint32_t *pminsize, uint32_t flags)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_memseg_t *seg;
	stmf_data_buf_t *db;
	MATCHMAP *mp;
	int i;
	uint32_t minsize = 0;

	if (!port->fct_memseg || !port->fct_memseg_cnt) {
		goto failed;
	}

	/* Check if our largest buffer is too small */
	seg = &port->fct_memseg[port->fct_memseg_cnt-1];
	if (size > seg->fc_memsize) {
		goto partial_alloc;
	}

	/* Find smallest available buffer >= size */
	seg = port->fct_memseg;
	for (i = 0; i < port->fct_memseg_cnt; i++, seg++) {
		if (seg->fc_memsize < size) {
			continue;
		}

		mp = (MATCHMAP*)emlxs_mem_pool_get(hba, seg);

		if (mp) {
			goto success;
		}
	}

	seg = &port->fct_memseg[port->fct_memseg_cnt-1];

partial_alloc:
	/* Find largest available buffer >= *pminsize */
	for (i = port->fct_memseg_cnt-1; i >= 0; i--, seg--) {
		if (seg->fc_memsize < *pminsize) {
			minsize = seg->fc_memsize;
			goto failed;
		}

		mp = (MATCHMAP*)emlxs_mem_pool_get(hba, seg);

		if (mp) {
			goto success;
		}
	}

failed:
	*pminsize = minsize;
	TGTPORTSTAT.FctNoBuffer++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_dbuf_alloc:Failed. size=%d minsize=%d",
	    size, *pminsize);

	return (NULL);

success:
	/* Setup the data buffer */
	db = (stmf_data_buf_t *)mp->fct_private;
	db->db_data_size = min(size, mp->size);

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_dbuf_alloc:%p iotag=%d size=%d,%d",
	    db, mp->tag, size,  mp->size);
#endif /* FCT_API_TRACE */

	return (db);

} /* emlxs_fct_dbuf_alloc() */


/* COMSTAR ENTER POINT */
/*ARGSUSED*/
static void
emlxs_fct_dbuf_free(fct_dbuf_store_t *fds, stmf_data_buf_t *db)
{
	emlxs_port_t *port = (emlxs_port_t *)fds->fds_fca_private;
	emlxs_hba_t *hba = HBA;
	MATCHMAP *mp = (MATCHMAP *)db->db_port_private;

	if (!mp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_dbuf_free:%p  NULL mp found!",
		    db);
		return;
	}

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_dbuf_free:%p iotag=%d",
	    db, mp->tag);
#endif /* FCT_API_TRACE */

	emlxs_mem_pool_put(hba, mp->segment, (void *)mp);

} /* emlxs_fct_dbuf_free() */


static int
emlxs_fct_dbuf_dma_sync(emlxs_hba_t *hba, stmf_data_buf_t *db,
    uint_t sync_type)
{
	emlxs_port_t *port = &PPORT;
	MATCHMAP *mp = (MATCHMAP *)db->db_port_private;

	if (!mp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_dbuf_dma_sync:%p  NULL mp found!",
		    db);
		return (0);
	}

#ifdef FCT_API_TRACE
{
	char buf[16];

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_dbuf_dma_sync:%p iotag=%d size=%d",
	    db, mp->tag, db->db_data_size);

	(void) snprintf(buf, sizeof (buf), "TAG%d:", mp->tag);
	emlxs_data_dump(port, buf, (uint32_t *)db->db_sglist[0].seg_addr,
	    36, 0);
}
#endif /* FCT_API_TRACE */

	EMLXS_MPDATA_SYNC(mp->dma_handle, 0, db->db_data_size, sync_type);

#ifdef FMA_SUPPORT
	if (emlxs_fm_check_dma_handle(hba, mp->dma_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_dma_handle_msg,
		    "fct_dbuf_dma_sync:%p iotag=%d",
		    db, mp->tag);
		return (1);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_fct_dbuf_dma_sync() */

#endif /* SFCT_SUPPORT */
