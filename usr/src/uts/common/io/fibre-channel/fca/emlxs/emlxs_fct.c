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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#include "emlxs.h"

#ifdef SFCT_SUPPORT

/* #define	FCT_API_TRACE		Extra debug */

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_FCT_C);

#ifndef PORT_SPEED_10G
#define	PORT_SPEED_10G			0x10
#endif	/* PORT_SPEED_10G */

static uint32_t emlxs_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
static uint32_t emlxs_fct_sli2_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
static uint32_t emlxs_fct_sli3_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
static void emlxs_fct_handle_acc(emlxs_port_t *port, emlxs_buf_t *sbp,
    IOCBQ *iocbq);
static void emlxs_fct_handle_reject(emlxs_port_t *port, emlxs_buf_t *sbp,
    IOCBQ *iocbq);
static emlxs_buf_t *emlxs_fct_cmd_init(emlxs_port_t *port, fct_cmd_t *fct_cmd);
static int emlxs_fct_cmd_uninit(emlxs_port_t *port, fct_cmd_t *fct_cmd);

static fct_status_t emlxs_flogi_xchg(struct fct_local_port *fct_port,
    struct fct_flogi_xchg *fx);
static fct_status_t emlxs_fct_get_link_info(fct_local_port_t *fct_port,
    fct_link_info_t *link);
static fct_status_t emlxs_fct_deregister_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *port_handle);
static fct_status_t emlxs_fct_send_cmd(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_fcp_data(fct_cmd_t *fct_cmd,
    stmf_data_buf_t *dbuf, uint32_t ioflags);
static fct_status_t emlxs_fct_send_cmd_rsp(fct_cmd_t *fct_cmd,
    uint32_t ioflags);
static fct_status_t emlxs_fct_abort(fct_local_port_t *fct_port, fct_cmd_t *cmd,
    uint32_t flags);
static void emlxs_fct_ctl(fct_local_port_t *fct_port, int cmd, void *arg);
static fct_status_t emlxs_fct_register_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *port_handle, fct_cmd_t *plogi);
static fct_status_t emlxs_fct_send_els_cmd(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_ct_cmd(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_fcp_status(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_els_rsp(fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_send_abts_rsp(fct_cmd_t *fct_cmd);
static void emlxs_fct_pkt_comp(fc_packet_t *pkt);
static void emlxs_populate_hba_details(fct_local_port_t *fct_port,
    fct_port_attrs_t *port_attrs);

static fct_status_t emlxs_fct_dmem_init(emlxs_port_t *port);
static void emlxs_fct_dmem_fini(emlxs_port_t *port);

static stmf_data_buf_t *emlxs_fct_dbuf_alloc(fct_local_port_t *fct_port,
    uint32_t size, uint32_t *pminsize, uint32_t flags);
static void emlxs_fct_dbuf_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf);

static void emlxs_fct_dbuf_dma_sync(stmf_data_buf_t *dbuf, uint_t sync_type);
static emlxs_buf_t *emlxs_fct_pkt_init(emlxs_port_t *port, fct_cmd_t *fct_cmd,
    fc_packet_t *pkt);

static void emlxs_fct_unsol_flush(emlxs_port_t *port);
static uint32_t emlxs_fct_process_unsol_flogi(emlxs_port_t *port, RING *rp,
    IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static uint32_t emlxs_fct_process_unsol_plogi(emlxs_port_t *port, RING *rp,
    IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
static void emlxs_fct_handle_rcvd_flogi(emlxs_port_t *port, fct_cmd_t *fct_cmd);
static fct_status_t emlxs_fct_pkt_abort(emlxs_port_t *port, emlxs_buf_t *sbp);
static fct_status_t emlxs_fct_send_qfull_reply(emlxs_port_t *port,
    emlxs_node_t *ndlp, uint16_t xid, uint32_t class, emlxs_fcp_cmd_t *fcp_cmd);

#ifdef MODSYM_SUPPORT

static int
emlxs_fct_modopen()
{
	int err;

	if (emlxs_modsym.mod_fct) {
		return (1);
	}
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
	emlxs_modsym.mod_stmf = ddi_modopen("drv/stmf", KRTLD_MODE_FIRST, &err);
	if (!emlxs_modsym.mod_stmf) {

		cmn_err(CE_WARN, "?%s: ddi_modopen drv/stmf failed: err %d",
		    DRIVER_NAME, err);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_alloc is present */
	emlxs_modsym.fct_alloc = (void *(*) ()) ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_alloc", &err);
	if ((void *)emlxs_modsym.fct_alloc == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_alloc not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_free is present */
	emlxs_modsym.fct_free = (void (*) ())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_free", &err);
	if ((void *)emlxs_modsym.fct_free == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_free not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_scsi_task_alloc is present */
	emlxs_modsym.fct_scsi_task_alloc = (void *(*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_scsi_task_alloc", &err);
	if ((void *)emlxs_modsym.fct_scsi_task_alloc == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_scsi_task_alloc not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_register_local_port is present */
	emlxs_modsym.fct_register_local_port = (int (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_register_local_port", &err);
	if ((void *)emlxs_modsym.fct_register_local_port == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_register_local_port not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_deregister_local_port is present */
	emlxs_modsym.fct_deregister_local_port = (void (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_deregister_local_port", &err);
	if ((void *)emlxs_modsym.fct_deregister_local_port == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_deregister_local_port not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_handle_event is present */
	emlxs_modsym.fct_handle_event = (void (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_handle_event", &err);
	if ((void *)emlxs_modsym.fct_handle_event == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_handle_event not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_post_rcvd_cmd is present */
	emlxs_modsym.fct_post_rcvd_cmd = (void (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_post_rcvd_cmd", &err);
	if ((void *)emlxs_modsym.fct_post_rcvd_cmd == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_post_rcvd_cmd not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_alloc is present */
	emlxs_modsym.fct_ctl = (void (*) ())ddi_modsym(emlxs_modsym.mod_fct,
	    "fct_ctl", &err);
	if ((void *)emlxs_modsym.fct_ctl == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_ctl not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_send_response_done is present */
	emlxs_modsym.fct_send_response_done = (void (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_send_response_done", &err);
	if ((void *)emlxs_modsym.fct_send_response_done == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_send_response_done not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_send_cmd_done is present */
	emlxs_modsym.fct_send_cmd_done = (void (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_send_cmd_done", &err);
	if ((void *)emlxs_modsym.fct_send_cmd_done == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_send_cmd_done not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_scsi_xfer_data_done is present */
	emlxs_modsym.fct_scsi_data_xfer_done = (void (*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_scsi_data_xfer_done", &err);
	if ((void *)emlxs_modsym.fct_scsi_data_xfer_done == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_scsi_data_xfer_done not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_port_shutdown is present */
	emlxs_modsym.fct_port_shutdown = (fct_status_t(*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_port_shutdown", &err);
	if ((void *)emlxs_modsym.fct_port_shutdown == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_port_shutdown not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_port_initialize is present */
	emlxs_modsym.fct_port_initialize = (fct_status_t(*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_port_initialize", &err);
	if ((void *)emlxs_modsym.fct_port_initialize == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_port_initialize not present",
		    DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the fct fct_handle_rcvd_flogi is present */
	emlxs_modsym.fct_handle_rcvd_flogi = (fct_status_t(*) ())
	    ddi_modsym(emlxs_modsym.mod_fct, "fct_handle_rcvd_flogi", &err);
	if ((void *)emlxs_modsym.fct_handle_rcvd_flogi == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/fct: fct_handle_rcvd_flogi not present",
		    DRIVER_NAME);
		goto failed;
	}
	/* Comstar (stmf) */
	err = 0;
	/* Check if the stmf stmf_alloc is present */
	emlxs_modsym.stmf_alloc = (void *(*) ())
	    ddi_modsym(emlxs_modsym.mod_stmf, "stmf_alloc", &err);
	if ((void *)emlxs_modsym.stmf_alloc == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_alloc not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the stmf stmf_free is present */
	emlxs_modsym.stmf_free = (void (*) ())ddi_modsym(emlxs_modsym.mod_stmf,
	    "stmf_free", &err);
	if ((void *)emlxs_modsym.stmf_free == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_free not present", DRIVER_NAME);
		goto failed;
	}
	err = 0;
	/* Check if the stmf stmf_deregister_port_provider is present */
	emlxs_modsym.stmf_deregister_port_provider =
	    (void (*) ())ddi_modsym(emlxs_modsym.mod_stmf,
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
	    (int (*) ())ddi_modsym(emlxs_modsym.mod_stmf,
	    "stmf_register_port_provider", &err);
	if ((void *)emlxs_modsym.stmf_register_port_provider == NULL) {
		cmn_err(CE_WARN,
		    "?%s: drv/stmf: stmf_register_port_provider not present",
		    DRIVER_NAME);
		goto failed;
	}
	return (1);

failed:

	emlxs_fct_modclose();

	return (0);

} /* emlxs_fct_modopen() */


extern void
emlxs_fct_modclose()
{

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
	emlxs_modsym.fct_send_response_done = NULL;
	emlxs_modsym.fct_send_cmd_done = NULL;
	emlxs_modsym.fct_scsi_data_xfer_done = NULL;
	emlxs_modsym.fct_port_shutdown = NULL;
	emlxs_modsym.fct_port_initialize = NULL;
	emlxs_modsym.fct_handle_rcvd_flogi = NULL;

	emlxs_modsym.stmf_alloc = NULL;
	emlxs_modsym.stmf_free = NULL;
	emlxs_modsym.stmf_deregister_port_provider = NULL;
	emlxs_modsym.stmf_register_port_provider = NULL;

} /* emlxs_fct_modclose() */

#endif	/* MODSYM_SUPPORT */



extern void
emlxs_fct_unsol_callback(emlxs_port_t *port, fct_cmd_t *fct_cmd)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
		mutex_enter(&cmd_sbp->mtx);
		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_free:1 %p", cmd_sbp->fct_cmd);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_free) (cmd_sbp->fct_cmd);
	}
	/* Online & Link up */
	else if (port->fct_flags & FCT_STATE_LINK_UP) {
		if (cmd_sbp->fct_flags & EMLXS_FCT_FLOGI) {

			emlxs_fct_handle_rcvd_flogi(port, fct_cmd);
		} else {
			mutex_enter(&cmd_sbp->mtx);
			cmd_sbp->pkt_flags |= PACKET_RETURNED;
			mutex_exit(&cmd_sbp->mtx);

#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_post_rcvd_cmd:1 %p: portid x%x",
			    fct_cmd, fct_cmd->cmd_lportid);
#endif	/* FCT_API_TRACE */
			MODSYM(fct_post_rcvd_cmd) (fct_cmd, 0);
		}
	} else {	/* Online & Link down */
		/* Add buffer to queue tail */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (port->fct_wait_tail) {
			port->fct_wait_tail->next = cmd_sbp;
		}
		port->fct_wait_tail = cmd_sbp;

		if (!port->fct_wait_head) {
			port->fct_wait_head = cmd_sbp;
		}
		mutex_exit(&EMLXS_PORT_LOCK);
	}

	return;

} /* emlxs_fct_unsol_callback() */


/* This is called at port online and offline */
static void
emlxs_fct_unsol_flush(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	emlxs_buf_t *next;
	fct_cmd_t *fct_cmd;

	if (!port->fct_port) {
		return;
	}
	/* Return if nothing to do */
	if (!port->fct_wait_head) {
		return;
	}
	mutex_enter(&EMLXS_PORT_LOCK);
	cmd_sbp = port->fct_wait_head;
	port->fct_wait_head = NULL;
	port->fct_wait_tail = NULL;
	mutex_exit(&EMLXS_PORT_LOCK);

	while (cmd_sbp) {
		next = cmd_sbp->next;
		fct_cmd = cmd_sbp->fct_cmd;

		if (port->fct_flags & FCT_STATE_LINK_UP) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "Completing fct_cmd: %p", fct_cmd);

			if (cmd_sbp->fct_flags & EMLXS_FCT_FLOGI) {
				emlxs_fct_handle_rcvd_flogi(port, fct_cmd);
			} else {
				mutex_enter(&cmd_sbp->mtx);
				cmd_sbp->pkt_flags |= PACKET_RETURNED;
				mutex_exit(&cmd_sbp->mtx);

#ifdef FCT_API_TRACE
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
				    "fct_post_rcvd_cmd:2 %p: portid x%x",
				    fct_cmd, fct_cmd->cmd_lportid);
#endif	/* FCT_API_TRACE */
				MODSYM(fct_post_rcvd_cmd) (fct_cmd, 0);
			}
		} else {	/* Drop the cmd */
			mutex_enter(&cmd_sbp->mtx);
			/* mutex_exit(&cmd_sbp->mtx); */
			(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_free:2 %p", fct_cmd);
#endif	/* FCT_API_TRACE */
			MODSYM(fct_free) (fct_cmd);
		}

		cmd_sbp = next;

	}	/* while() */

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
uint32_t
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


static void
emlxs_init_fct_bufpool(emlxs_hba_t *hba, char **arrayp, uint32_t cnt)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *datap;
	int i;

	bzero((uint8_t *)port->dmem_bucket, sizeof (port->dmem_bucket));
	for (i = 0; i < cnt; i++) {
		datap = (uint8_t *)arrayp[i];
		if (datap == 0)
			break;

		while (*datap == ' ')	/* Skip spaces */
			datap++;

		port->dmem_bucket[i].dmem_buf_size = emlxs_str_atoi(datap);

		while ((*datap != ':') && (*datap != 0))
			datap++;
		if (*datap == ':')	/* Skip past delimeter */
			datap++;
		while (*datap == ' ')	/* Skip spaces */
			datap++;

		port->dmem_bucket[i].dmem_nbufs = emlxs_str_atoi(datap);

		/* Check for a bad entry */
		if (!port->dmem_bucket[i].dmem_buf_size ||
		    !port->dmem_bucket[i].dmem_nbufs) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "Bad fct-bufpool entry %d %d",
			    port->dmem_bucket[i].dmem_buf_size,
			    port->dmem_bucket[i].dmem_nbufs);

			port->dmem_bucket[i].dmem_buf_size = 0;
			port->dmem_bucket[i].dmem_nbufs = 0;
		}
		if (i >= FCT_MAX_BUCKETS)
			break;
	}
}


static void
emlxs_fct_cfg_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	char **arrayp;
	uint32_t cnt;
	char buf[32];
	int status;

	bzero((void *) buf, 32);
	cnt = 0;
	arrayp = NULL;

	(void) sprintf(buf, "emlxs%d-fct-bufpool", ddi_get_instance(hba->dip));
	status = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS), buf, &arrayp, &cnt);

	if ((status == DDI_PROP_SUCCESS) && cnt && arrayp) {
		emlxs_init_fct_bufpool(hba, arrayp, cnt);
	} else {
		status = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
		    (DDI_PROP_DONTPASS), "fct-bufpool", &arrayp, &cnt);

		if ((status == DDI_PROP_SUCCESS) && cnt && arrayp) {
			emlxs_init_fct_bufpool(hba, arrayp, cnt);
		} else {
			bzero((uint8_t *)port->dmem_bucket,
			    sizeof (port->dmem_bucket));
			port->dmem_bucket[0].dmem_buf_size = 512;
			port->dmem_bucket[0].dmem_nbufs = FCT_BUF_COUNT_512;
			port->dmem_bucket[1].dmem_buf_size = 8192;
			port->dmem_bucket[1].dmem_nbufs = FCT_BUF_COUNT_8K;
			port->dmem_bucket[2].dmem_buf_size = 65536;
			port->dmem_bucket[2].dmem_nbufs = FCT_BUF_COUNT_64K;
			port->dmem_bucket[3].dmem_buf_size = (2 * 65536);
			port->dmem_bucket[3].dmem_nbufs = FCT_BUF_COUNT_128K;
		}
	}

	bzero((void *)buf, 32);
	cnt = 0;

	(void) sprintf(buf, "emlxs%d-fct-queue-depth",
	    ddi_get_instance(hba->dip));
	cnt = ddi_prop_get_int(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS), buf, 0);

	if ((cnt == DDI_PROP_NOT_FOUND) || (cnt == 0)) {
		cnt = ddi_prop_get_int(DDI_DEV_T_ANY, hba->dip,
		    (DDI_PROP_DONTPASS), "fct-queue-depth", 0);

		if (cnt == DDI_PROP_NOT_FOUND) {
			cnt = 64;
		}
	}
	port->fct_queue_depth = cnt;
	return;

} /* emlxs_fct_cfg_init() */


extern void
emlxs_fct_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	emlxs_port_t *vport;
	uint32_t i;

	if (!hba->tgt_mode) {
		return;
	}
#ifdef MODSYM_SUPPORT
	/* Open COMSTAR */
	(void) emlxs_fct_modopen();
#endif	/* MODSYM_SUPPORT */

	/* Check if COMSTAR is present */
	if (((void *)MODSYM(stmf_alloc) == NULL) ||
	    ((void *) MODSYM(fct_alloc) == NULL)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
		    "Comstar not present. Target mode disabled.");
		goto failed;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_debug_msg,
	    "Comstar present. Target mode enabled.");

#ifdef NPIV_SUPPORT
	if (cfg[CFG_NPIV_ENABLE].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
		    "enable-npiv: Not supported in target mode. Disabling.");

		/* Temporary patch to disable npiv */
		cfg[CFG_NPIV_ENABLE].current = 0;
	}
#endif	/* NPIV_SUPPORT */

#ifdef DHCHAP_SUPPORT
	if (cfg[CFG_AUTH_ENABLE].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
		    "enable-auth: Not supported in target mode. Disabling.");

		/* Temporary patch to disable auth */
		cfg[CFG_AUTH_ENABLE].current = 0;
	}
#endif	/* DHCHAP_SUPPORT */

	emlxs_fct_cfg_init(hba);
	return;

failed:

	hba->tgt_mode = 0;
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->tgt_mode = 0;
		vport->fct_flags = 0;
	}
} /* emlxs_fct_init() */


extern void
emlxs_fct_attach(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t vpi;

	if (!hba->tgt_mode) {
		return;
	}
	/* Bind the physical port */
	emlxs_fct_bind_port(port);

	/* Bind virtual ports */
	if (hba->flag & FC_NPIV_ENABLED) {
		for (vpi = 1; vpi < hba->vpi_high; vpi++) {
			port = &VPORT(vpi);

			if (!(port->flag & EMLXS_PORT_ENABLE)) {
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

	if (hba->tgt_mode) {
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (!vport->tgt_mode) {
				continue;
			}
			emlxs_fct_unbind_port(vport);
			vport->tgt_mode = 0;
		}


		hba->tgt_mode = 0;
	}
	return;

} /* emlxs_fct_detach() */


extern void
emlxs_fct_unbind_port(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	char node_name[32];

	if (!port->tgt_mode) {
		return;
	}
	mutex_enter(&EMLXS_PORT_LOCK);
	if (!(port->flag & EMLXS_PORT_BOUND)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "emlxs_fct_unbind_port: port=%d", port->vpi);

	/* Destroy & flush all port nodes, if they exist */
	if (port->node_count) {
		(void) emlxs_mb_unreg_rpi(port, 0xffff, 0, 0, 0);
	}
	port->flag &= ~EMLXS_PORT_BOUND;
	hba->num_of_ports--;
	mutex_exit(&EMLXS_PORT_LOCK);

	if (port->fct_port) {
		emlxs_fct_link_down(port);
		emlxs_fct_unsol_flush(port);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_deregister_local_port %p", port->fct_port);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_deregister_local_port) (port->fct_port);

		if (port->fct_port->port_fds) {
#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_free:3 %p", port->fct_port->port_fds);
#endif	/* FCT_API_TRACE */
			MODSYM(fct_free) (port->fct_port->port_fds);
			port->fct_port->port_fds = NULL;
		}
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_free:4 %p", port->fct_port);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_free) (port->fct_port);
		port->fct_port = NULL;
		port->fct_flags = 0;
	}
	if (port->port_provider) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_deregister_port_provider:1 %p", port->port_provider);
#endif	/* FCT_API_TRACE */
		MODSYM(stmf_deregister_port_provider) (port->port_provider);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_free:1 %p", port->port_provider);
#endif	/* FCT_API_TRACE */
		MODSYM(stmf_free) (port->port_provider);
		port->port_provider = NULL;
	}
	if (port->dmem_bucket) {
		emlxs_fct_dmem_fini(port);
	}
	(void) sprintf(node_name, "%d,%d:SFCT", hba->ddiinst, port->vpi);
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

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!hba->tgt_mode || !port->tgt_mode) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	if (port->flag & EMLXS_PORT_BOUND) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "emlxs_fct_bind_port: port=%d", port->vpi);

	/* Perform generic port initialization */
	emlxs_port_init(port);

	if (port->vpi == 0) {
		(void) sprintf(port->cfd_name, "%s%d", DRIVER_NAME,
		    hba->ddiinst);
	} else {
		(void) sprintf(port->cfd_name, "%s%d.%d", DRIVER_NAME,
		    hba->ddiinst, port->vpi);
	}

	if (emlxs_fct_dmem_init(port) != FCT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_bind_port: Unable to allocate fct memory.");
		goto failed;
	}
	flag |= 0x00000001;

	port->port_provider = (stmf_port_provider_t *)
	    MODSYM(stmf_alloc) (STMF_STRUCT_PORT_PROVIDER, 0, 0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "stmf_alloc port_provider %p", port->port_provider);
#endif	/* FCT_API_TRACE */

	if (port->port_provider == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_bind_port: Unable to allocate "
		    "fct port provider.");
		goto failed;
	}
	flag |= 0x00000002;

	port->port_provider->pp_portif_rev = PORTIF_REV_1;
	port->port_provider->pp_name = port->cfd_name;
	port->port_provider->pp_provider_private = port;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "stmf_register_port_provider %p", port->port_provider);
#endif	/* FCT_API_TRACE */
	/* register port provider with framework */
	if (MODSYM(stmf_register_port_provider) (port->port_provider)
	    != STMF_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_bind_port: Unable to register "
		    "fct port provider.");
		goto failed;
	}
	flag |= 0x00000004;

	port->fct_port = (fct_local_port_t *)
	    MODSYM(fct_alloc) (FCT_STRUCT_LOCAL_PORT, 0, 0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_alloc fct_port %p", port->fct_port);
#endif	/* FCT_API_TRACE */

	if (port->fct_port == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_bind_port: Unable to allocate fct port.");
		goto failed;
	}
	flag |= 0x00000008;

	port->fct_port->port_fds = (fct_dbuf_store_t *)
	    MODSYM(fct_alloc) (FCT_STRUCT_DBUF_STORE, 0, 0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_alloc port_fds %p", port->fct_port->port_fds);
#endif	/* FCT_API_TRACE */

	if (port->fct_port->port_fds == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_bind_port: Unable to allocate dbuf store.");
		goto failed;
	}
	flag |= 0x00000010;

	(void) sprintf(node_name, "%d,%d:SFCT", hba->ddiinst, port->vpi);
	if (ddi_create_minor_node(hba->dip, node_name, S_IFCHR,
	    hba->ddiinst, NULL, 0) == DDI_FAILURE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "Unable to create SFCT device node.");
		goto failed;
	}
	flag |= 0x00000020;

	/* Intialize */
	fct_port = port->fct_port;
	fct_port->port_fca_private = port;
	fct_port->port_fca_abort_timeout = 30 * 1000;	/* 30 seconds */

	bcopy((uint8_t *)&port->wwpn, (uint8_t *)fct_port->port_pwwn, 8);
	bcopy((uint8_t *)&port->wwnn, (uint8_t *)fct_port->port_nwwn, 8);

	fct_port->port_sym_node_name = port->snn;
	fct_port->port_sym_port_name = port->spn;
	fct_port->port_hard_address = cfg[CFG_ASSIGN_ALPA].current;
	fct_port->port_default_alias = port->cfd_name;
	fct_port->port_pp = port->port_provider;
	fct_port->port_max_logins = hba->max_nodes;

	if ((port->fct_queue_depth) && (port->fct_queue_depth
	    < hba->io_throttle)) {
		fct_port->port_max_xchges = port->fct_queue_depth;
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
	fct_port->port_flogi_xchg = emlxs_flogi_xchg;
	fct_port->port_populate_hba_details = emlxs_populate_hba_details;

	fds = port->fct_port->port_fds;
	fds->fds_fca_private = port;
	fds->fds_alloc_data_buf = emlxs_fct_dbuf_alloc;
	fds->fds_free_data_buf = emlxs_fct_dbuf_free;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_register_local_port %p", fct_port);
#endif	/* FCT_API_TRACE */
	/* register this local port with the fct module */
	if (MODSYM(fct_register_local_port) (fct_port) != FCT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_bind_port: Unable to register fct port.");
		goto failed;
	}
	/* Set the bound flag */
	port->flag |= EMLXS_PORT_BOUND;
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
#endif	/* FCT_API_TRACE */
		MODSYM(fct_free) (port->fct_port->port_fds);
		port->fct_port->port_fds = NULL;
	}
	if (flag & 0x8) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_free:6 %p", port->fct_port);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_free) (port->fct_port);
		port->fct_port = NULL;
		port->fct_flags = 0;
	}
	if (flag & 0x4) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_deregister_port_provider:2 %p", port->port_provider);
#endif	/* FCT_API_TRACE */
		MODSYM(stmf_deregister_port_provider) (port->port_provider);
	}
	if (flag & 0x2) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_free:2 %p", port->port_provider);
#endif	/* FCT_API_TRACE */
		MODSYM(stmf_free) (port->port_provider);
		port->port_provider = NULL;
	}
	if (flag & 0x1) {
		emlxs_fct_dmem_fini(port);
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
	    "Target mode disabled.");

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_fct_bind_port() */


static void
emlxs_populate_hba_details(fct_local_port_t *fct_port,
    fct_port_attrs_t *port_attrs)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_vpd_t *vpd = &VPD;

	(void) strcpy(port_attrs->manufacturer, "Emulex");
	(void) strcpy(port_attrs->serial_number, vpd->serial_num);
	(void) strcpy(port_attrs->model, hba->model_info.model);
	(void) strcpy(port_attrs->model_description,
	    hba->model_info.model_desc);
	(void) sprintf(port_attrs->hardware_version, "%x", vpd->biuRev);
	(void) sprintf(port_attrs->driver_version, "%s (%s)", emlxs_version,
	    emlxs_revision);
	(void) strcpy(port_attrs->option_rom_version, vpd->fcode_version);
	(void) sprintf(port_attrs->firmware_version, "%s (%s)", vpd->fw_version,
	    vpd->fw_label);
	(void) strcpy(port_attrs->driver_name, DRIVER_NAME);
	port_attrs->vendor_specific_id =
	    ((hba->model_info.device_id << 16) | PCI_VENDOR_ID_EMULEX);
	port_attrs->supported_cos = SWAP_DATA32(FC_NS_CLASS3);

	port_attrs->max_frame_size = FF_FRAME_SIZE;

	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		port_attrs->supported_speed |= FC_HBA_PORTSPEED_10GBIT;
	}
	if (vpd->link_speed & LMT_8GB_CAPABLE) {
		port_attrs->supported_speed |= FC_HBA_PORTSPEED_8GBIT;
	}
	if (vpd->link_speed & LMT_4GB_CAPABLE) {
		port_attrs->supported_speed |= FC_HBA_PORTSPEED_4GBIT;
	}
	if (vpd->link_speed & LMT_2GB_CAPABLE) {
		port_attrs->supported_speed |= FC_HBA_PORTSPEED_2GBIT;
	}
	if (vpd->link_speed & LMT_1GB_CAPABLE) {
		port_attrs->supported_speed |= FC_HBA_PORTSPEED_1GBIT;
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
	    "Port attr: hardware_version   = %s", port_attrs->hardware_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: driver_version     = %s", port_attrs->driver_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: option_rom_version = %s",
	    port_attrs->option_rom_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: firmware_version   = %s", port_attrs->firmware_version);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: driver_name        = %s", port_attrs->driver_name);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: vendor_specific_id = 0x%x",
	    port_attrs->vendor_specific_id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: supported_cos      = 0x%x", port_attrs->supported_cos);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: supported_speed    = 0x%x",
	    port_attrs->supported_speed);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "Port attr: max_frame_size     = 0x%x", port_attrs->max_frame_size);

	return;

} /* emlxs_populate_hba_details() */


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

			if (hba->state <= FC_LINK_DOWN) {
				/* Try to bring the link up */
				(void) emlxs_reset_link(hba, 1);
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

			/* Take link down and hold it down */
			(void) emlxs_reset_link(hba, 0);

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
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_port_shutdown");
	MODSYM(fct_port_shutdown) (fct_port, STMF_RFLAG_STAY_OFFLINED,
	    "emlxs shutdown");

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
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "fct_port_initialize");
	MODSYM(fct_port_initialize) (fct_port, STMF_RFLAG_STAY_OFFLINED,
	    "emlxs initialize");

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

static fct_status_t
emlxs_fct_send_cmd(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port;

	port = (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_send_cmd %p: x%x", fct_cmd, fct_cmd->cmd_type);
#endif	/* FCT_API_TRACE */

	switch (fct_cmd->cmd_type) {
	case FCT_CMD_SOL_ELS:

		return (emlxs_fct_send_els_cmd(fct_cmd));

	case FCT_CMD_SOL_CT:

		return (emlxs_fct_send_ct_cmd(fct_cmd));

	default:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_send_cmd: Invalid cmd type found. type=%x",
		    fct_cmd->cmd_type);

		return (FCT_FAILURE);
	}

} /* emlxs_fct_send_cmd() */



static fct_status_t
emlxs_fct_send_cmd_rsp(fct_cmd_t *fct_cmd, uint32_t ioflags)
{
	emlxs_port_t *port;

	port = (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_send_cmd_rsp %p: x%x", fct_cmd, fct_cmd->cmd_type);
#endif	/* FCT_API_TRACE */

	switch (fct_cmd->cmd_type) {
	case FCT_CMD_FCP_XCHG:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			goto failure;
		}
		return (emlxs_fct_send_fcp_status(fct_cmd));

	case FCT_CMD_RCVD_ELS:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			goto failure;
		}
		return (emlxs_fct_send_els_rsp(fct_cmd));

	case FCT_CMD_RCVD_ABTS:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			fct_cmd->cmd_handle = 0;
		}
		return (emlxs_fct_send_abts_rsp(fct_cmd));

	default:

		if (ioflags & FCT_IOF_FORCE_FCA_DONE) {
			fct_cmd->cmd_handle = 0;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_send_cmd_rsp: Invalid cmd type found. type=%x",
		    fct_cmd->cmd_type);

		return (FCT_FAILURE);
	}

failure:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_send_cmd_rsp: Unable to handle FCT_IOF_FORCE_FCA_DONE. "
	    "type=%x", fct_cmd->cmd_type);

	return (FCT_FAILURE);

} /* emlxs_fct_send_cmd_rsp() */



static fct_status_t
emlxs_flogi_xchg(struct fct_local_port *fct_port, struct fct_flogi_xchg *fx)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t size;
	fc_packet_t *pkt;
	ELS_PKT *els;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_flogi_xchg: Sending FLOGI: %p", fct_port);
#else
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_flogi_xchg: Sending FLOGI.");
#endif	/* FCT_API_TRACE */

	if (hba->state <= FC_LINK_DOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_flogi_xchg: FLOGI failed. Link down.");
		return (FCT_FAILURE);
	}
	size = sizeof (SERV_PARM) + 4;

	if (!(pkt = emlxs_pkt_alloc(port, size, size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_flogi_xchg: FLOGI failed. Unable allocate packet.");
		return (FCT_FAILURE);
	}
	/* Make this a polled IO */
	pkt->pkt_tran_flags &= ~FC_TRAN_INTR;
	pkt->pkt_tran_flags |= FC_TRAN_NO_INTR;
	pkt->pkt_comp = NULL;

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = fx->fx_sec_timeout;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = SWAP_DATA24_LO(fx->fx_did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(fx->fx_sid);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_FIRST_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	/*
	 * Service paramters will be added automatically later by the driver
	 * (See emlxs_send_els())
	 */
	els = (ELS_PKT *)pkt->pkt_cmd;
	els->elsCode = 0x04;	/* FLOGI */

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_flogi_xchg: FLOGI failed. Unable to send packet.");

		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}
	if ((pkt->pkt_state != FC_PKT_SUCCESS) &&
	    (pkt->pkt_state != FC_PKT_LS_RJT)) {
		if (pkt->pkt_state == FC_PKT_TIMEOUT) {
			return (FCT_TIMEOUT);
		} else if ((pkt->pkt_state == FC_PKT_LOCAL_RJT) &&
		    (pkt->pkt_reason == FC_REASON_FCAL_OPN_FAIL)) {
			return (FCT_NOT_FOUND);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_flogi_xchg: FLOGI failed. state=%x reason=%x",
		    pkt->pkt_state, pkt->pkt_reason);

		return (FCT_FAILURE);
	}
	if (pkt->pkt_state == FC_PKT_LS_RJT) {
		fx->fx_op = ELS_OP_LSRJT;
		fx->fx_rjt_reason = pkt->pkt_reason;
		fx->fx_rjt_expl = pkt->pkt_expln;
	} else {	/* FC_PKT_SUCCESS */
		fx->fx_op = ELS_OP_ACC;
		fx->fx_sid = Fabric_DID;
		fx->fx_did = port->did;

		els = (ELS_PKT *) pkt->pkt_resp;
		bcopy((caddr_t)&els->un.logi.nodeName,
		    (caddr_t)fx->fx_nwwn, 8);
		bcopy((caddr_t)&els->un.logi.portName,
		    (caddr_t)fx->fx_pwwn, 8);
		fx->fx_fport = els->un.logi.cmn.fPort;
	}

	return (FCT_SUCCESS);

} /* emlxs_flogi_xchg() */



/* This is called right after we report that link has come online */
static fct_status_t
emlxs_fct_get_link_info(fct_local_port_t *fct_port, fct_link_info_t *link)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_get_link_info %p", fct_port);

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->fct_flags & FCT_STATE_LINK_UP) ||
	    (hba->state < FC_LINK_UP) ||
	    (hba->flag & FC_LOOPBACK_MODE)) {
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

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_register_remote_port %p", fct_port);
#endif	/* FCT_API_TRACE */

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		(void) emlxs_fct_cmd_init(port, fct_cmd);
		/* mutex_enter(&cmd_sbp->mtx); */

		cmd_sbp->ring = &hba->ring[FC_ELS_RING];
		cmd_sbp->fct_type = EMLXS_FCT_ELS_CMD;
		cmd_sbp->fct_state = EMLXS_FCT_REQ_CREATED;
	} else {
		mutex_enter(&cmd_sbp->mtx);
	}

	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;

	if (!cmd_sbp->node) {
		cmd_sbp->node = emlxs_node_find_did(port, fct_cmd->cmd_rportid);
	}
	if (!cmd_sbp->node) {
		els = (fct_els_t *)fct_cmd->cmd_specific;

		/* Check for unsolicited PLOGI */
		if (cmd_sbp->fct_state == EMLXS_FCT_CMD_RECEIVED) {
			sp = (SERV_PARM *)
			    ((caddr_t)els->els_req_payload + sizeof (uint32_t));
		} else {	/* Solicited PLOGI */
			sp = &sparam;
			bcopy((caddr_t)&port->sparam, (caddr_t)sp,
			    sizeof (SERV_PARM));

			/* Create temporary WWN's from fct_cmd address */
			/*
			 * This simply allows us to get an RPI from the
			 * adapter until we get real service params
			 */
			/*
			 * The PLOGI ACC reply will trigger a REG_LOGIN
			 * update later
			 */
			iptr = (uint32_t *)&sp->portName;
			iptr[0] =
			    (uint32_t)putPaddrHigh((unsigned long)fct_cmd);
			iptr[1] =
			    (uint32_t)putPaddrLow((unsigned long)fct_cmd);
			iptr = (uint32_t *)&sp->nodeName;
			iptr[0] =
			    (uint32_t)putPaddrHigh((unsigned long)fct_cmd);
			iptr[1] =
			    (uint32_t)putPaddrLow((unsigned long)fct_cmd);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_debug_msg,
		    "emlxs_fct_register_remote_port: Registering did=%x. "
		    "(%x,%p)", fct_cmd->cmd_rportid, cmd_sbp->fct_state,
		    fct_cmd);

		cmd_sbp->fct_state = EMLXS_FCT_REG_PENDING;

		/* Create a new node */
		if (emlxs_mb_reg_did(port, fct_cmd->cmd_rportid, sp, cmd_sbp,
		    NULL, NULL) != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
			    "emlxs_fct_register_remote_port: Reg login failed. "
			    "did=%x", fct_cmd->cmd_rportid);
			goto done;
		}
		mutex_exit(&cmd_sbp->mtx);

		/* Wait for completion */
		mutex_enter(&EMLXS_PKT_LOCK);
		timeout = emlxs_timeout(hba, 30);
		pkt_ret = 0;
		while ((pkt_ret != -1) &&
		    (cmd_sbp->fct_state == EMLXS_FCT_REG_PENDING)) {
			pkt_ret = cv_timedwait(&EMLXS_PKT_CV,
			    &EMLXS_PKT_LOCK, timeout);
		}
		mutex_exit(&EMLXS_PKT_LOCK);

		mutex_enter(&cmd_sbp->mtx);
	}
done:

	ndlp = (emlxs_node_t *)cmd_sbp->node;

	if (ndlp) {
		*((emlxs_node_t **)remote_port->rp_fca_private) = cmd_sbp->node;
		remote_port->rp_handle = ndlp->nlp_Rpi;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_register_remote_port: did=%x hdl=%x",
		    fct_cmd->cmd_rportid, remote_port->rp_handle);

		remote_port->rp_handle = ndlp->nlp_Rpi;

		cmd_sbp->pkt_flags |= PACKET_RETURNED;
		mutex_exit(&cmd_sbp->mtx);

		TGTPORTSTAT.FctPortRegister++;
		return (FCT_SUCCESS);
	} else {
		*((emlxs_node_t **)remote_port->rp_fca_private) = NULL;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_register_remote_port: failed. did=%x hdl=%x",
		    fct_cmd->cmd_rportid, remote_port->rp_handle);

		remote_port->rp_handle = FCT_HANDLE_NONE;

		cmd_sbp->pkt_flags |= PACKET_RETURNED;
		cmd_sbp->fct_state = EMLXS_FCT_REQ_CREATED;

		mutex_exit(&cmd_sbp->mtx);

		TGTPORTSTAT.FctFailedPortRegister++;
		return (FCT_FAILURE);
	}


} /* emlxs_fct_register_remote_port() */


static fct_status_t
emlxs_fct_deregister_remote_port(fct_local_port_t *fct_port,
    fct_remote_port_t *remote_port)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_deregister_remote_port: did=%x hdl=%x",
	    remote_port->rp_id, remote_port->rp_handle);
#else
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_deregister_remote_port: did=%x hdl=%x",
	    remote_port->rp_id, remote_port->rp_handle);
#endif	/* FCT_API_TRACE */

	*((emlxs_node_t **)remote_port->rp_fca_private) = NULL;
	(void) emlxs_mb_unreg_did(port, remote_port->rp_id, NULL, NULL, NULL);

	TGTPORTSTAT.FctPortDeregister++;
	return (FCT_SUCCESS);

} /* emlxs_fct_deregister_remote_port() */


/* ARGSUSED */
extern int
emlxs_fct_handle_unsol_req(emlxs_port_t *port, RING *rp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB *iocb;
	fct_cmd_t *fct_cmd;
	emlxs_buf_t *cmd_sbp;
	emlxs_fcp_cmd_t *fcp_cmd;
	emlxs_node_t *ndlp;
	uint32_t cnt;
	uint32_t tm;
	scsi_task_t *fct_task;
	uint8_t lun[8];
	uint32_t sid = 0;

	iocb = &iocbq->iocb;
	ndlp = emlxs_node_find_rpi(port, iocb->ulpIoTag);
	if (!ndlp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: Unknown RPI. rpi=%x rxid=%x. Dropping...",
		    iocb->ulpIoTag, iocb->ulpContext);

		goto dropped;
	}
	sid = ndlp->nlp_DID;

	fcp_cmd = (emlxs_fcp_cmd_t *)mp->virt;

	if (!port->fct_port) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: Target unbound. rpi=%x rxid=%x. Dropping...",
		    iocb->ulpIoTag, iocb->ulpContext);

		emlxs_send_logo(port, sid);

		goto dropped;
	}
	if (!(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: Target offline. rpi=%x rxid=%x. Dropping...",
		    iocb->ulpIoTag, iocb->ulpContext);

		emlxs_send_logo(port, sid);

		goto dropped;
	}
	/* Get lun id */
	bcopy((void *)&fcp_cmd->fcpLunMsl, lun, 8);

	if (TGTPORTSTAT.FctOutstandingIO >= port->fct_port->port_max_xchges) {
		TGTPORTSTAT.FctOverQDepth++;
	}
	fct_cmd = MODSYM(fct_scsi_task_alloc)
	    (port->fct_port, iocb->ulpIoTag, sid, lun, 16, 0);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_scsi_task_alloc %p: FCP rcvd: cmd=%x sid=%x rxid=%x "
	    "lun=%02x%02x dl=%d", fct_cmd, fcp_cmd->fcpCdb[0], sid,
	    iocb->ulpContext, lun[0], lun[1], SWAP_DATA32(fcp_cmd->fcpDl));
#endif	/* FCT_API_TRACE */

	if (fct_cmd == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCP rcvd: sid=%x xid=%x. Unable to allocate scsi task. "
		    "Returning QFULL.", sid, iocb->ulpContext);

		(void) emlxs_fct_send_qfull_reply(port, ndlp, iocb->ulpContext,
		    iocb->ulpClass, fcp_cmd);

		goto dropped;
	}
	/* Initialize fct_cmd */
	fct_cmd->cmd_oxid = 0xFFFF;
	fct_cmd->cmd_rxid = iocb->ulpContext;
	fct_cmd->cmd_rportid = sid;
	fct_cmd->cmd_lportid = port->did;
	fct_cmd->cmd_rp_handle = iocb->ulpIoTag;	/* RPI */
	fct_cmd->cmd_port = port->fct_port;

	/* Initialize cmd_sbp */
	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd);
	/* mutex_enter(&cmd_sbp->mtx); */

	cmd_sbp->ring = rp;
	cmd_sbp->class = iocb->ulpClass;
	cmd_sbp->lun = (lun[0] << 8) | lun[1];
	cmd_sbp->fct_type = EMLXS_FCT_FCP_CMD;
	cmd_sbp->fct_state = EMLXS_FCT_CMD_RECEIVED;
	/*
	 * bcopy((uint8_t*)iocb, (uint8_t*)&cmd_sbp->iocbq,
	 * sizeof(emlxs_iocb_t));
	 */

	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;

	/* Set task_flags */
	switch (fcp_cmd->fcpCntl2) {
	case 0:
		fct_task->task_flags = TF_ATTR_SIMPLE_QUEUE;
		break;

	case 1:
		fct_task->task_flags = TF_ATTR_HEAD_OF_QUEUE;
		break;

	case 2:
		fct_task->task_flags = TF_ATTR_ORDERED_QUEUE;
		break;

	case 4:
		fct_task->task_flags = TF_ATTR_ACA;
		break;

	case 5:
		fct_task->task_flags = TF_ATTR_UNTAGGED;
		break;
	}

	cnt = SWAP_DATA32(fcp_cmd->fcpDl);
	switch (fcp_cmd->fcpCntl3) {
	case 0:
		TGTPORTSTAT.FctIOCmdCnt++;
		break;
	case 1:
		emlxs_bump_wrioctr(port, cnt);
		TGTPORTSTAT.FctWriteBytes += cnt;
		fct_task->task_flags |= TF_WRITE_DATA;
		break;

	case 2:
		emlxs_bump_rdioctr(port, cnt);
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

	cmd_sbp->pkt_flags |= PACKET_RETURNED;
	mutex_exit(&cmd_sbp->mtx);

	emlxs_fct_unsol_callback(port, fct_cmd);

	return (0);

dropped:

	TGTPORTSTAT.FctRcvDropped++;
	return (1);

} /* emlxs_fct_handle_unsol_req() */


/* ARGSUSED */
static fct_status_t
emlxs_fct_send_fcp_data(fct_cmd_t *fct_cmd, stmf_data_buf_t *dbuf,
    uint32_t ioflags)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	emlxs_buf_t *cmd_sbp;
	scsi_task_t *fct_task;
	uint32_t did;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint32_t timeout;
	uint32_t iotag;
	emlxs_node_t *ndlp;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;
	did = fct_cmd->cmd_rportid;

	/* Initialize cmd_sbp */
	mutex_enter(&cmd_sbp->mtx);

	/*
	 * This check is here because task_max_nbufs is set to 1. This
	 * ensures we will only have 1 outstanding call to this routine.
	 */
	if (!(cmd_sbp->pkt_flags & PACKET_RETURNED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Processing IO. did=0x%x", did);
		mutex_exit(&cmd_sbp->mtx);
		return (FCT_BUSY);
	}
	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;
	cmd_sbp->node = ndlp;
	cmd_sbp->fct_buf = dbuf;

	iocbq = &cmd_sbp->iocbq;
	iocb = &iocbq->iocb;

	if (cfg[CFG_TIMEOUT_ENABLE].current) {
		timeout = ((2 * hba->fc_ratov) < 60) ? 60 : (2 * hba->fc_ratov);
	} else {
		timeout = 0x80000000;
	}

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_send_fcp_data %p: flgs=%x ioflags=%x dl=%d,%d,%d",
	    fct_cmd, dbuf->db_flags, ioflags, fct_task->task_cmd_xfer_length,
	    fct_task->task_nbytes_transferred, dbuf->db_data_size);
#endif	/* FCT_API_TRACE */

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cmd_sbp->ring, cmd_sbp);

	if (!iotag) {
		/* No more command slots available, retry later */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		cmd_sbp->pkt_flags |= PACKET_RETURNED;
		mutex_exit(&cmd_sbp->mtx);
		return (FCT_BUSY);
	}
	if (emlxs_fct_bde_setup(port, cmd_sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(cmd_sbp->ring, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		cmd_sbp->pkt_flags |= PACKET_RETURNED;
		mutex_exit(&cmd_sbp->mtx);
		return (FCT_BUSY);
	}
	/* Point of no return */
	cmd_sbp->fct_type = EMLXS_FCT_FCP_DATA;
	cmd_sbp->fct_state = EMLXS_FCT_DATA_PENDING;

	if (dbuf->db_flags & DB_SEND_STATUS_GOOD) {
		cmd_sbp->fct_flags |= EMLXS_FCT_SEND_STATUS;
	}
	cmd_sbp->ticks = hba->timer_tics + timeout +
	    ((timeout > 0xff) ? 0 : 10);

	/* Initalize iocbq */
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->ring = (void *)cmd_sbp->ring;

	/* Initalize iocb */
	iocb->ulpContext = (uint16_t)fct_cmd->cmd_rxid;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((timeout > 0xff) ? 0 : timeout);
	iocb->ulpOwner = OWN_CHIP;
	iocb->ulpClass = cmd_sbp->class;

	iocb->ulpPU = 1;	/* Wd4 is relative offset */
	iocb->un.fcpt64.fcpt_Offset = dbuf->db_relative_offset;

	if (fct_task->task_flags & TF_WRITE_DATA) {
		iocb->ulpCommand = CMD_FCP_TRECEIVE64_CX;
	} else {	/* TF_READ_DATA */
		iocb->ulpCommand = CMD_FCP_TSEND64_CX;
	}

#if 0
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "FCT reply: icmd=%x did=%x oxid=%x rxid=%x sbp=%p",
	    iocb->ulpCommand, did, fct_cmd->cmd_oxid, fct_cmd->cmd_rxid,
	    cmd_sbp);
#endif

	if (dbuf->db_flags & DB_DIRECTION_TO_RPORT) {
		emlxs_fct_dbuf_dma_sync(dbuf, DDI_DMA_SYNC_FORDEV);
	}
	mutex_exit(&cmd_sbp->mtx);
	emlxs_issue_iocb_cmd(hba, cmd_sbp->ring, iocbq);

	return (FCT_SUCCESS);

} /* emlxs_fct_send_fcp_data() */


static fct_status_t
emlxs_fct_send_fcp_status(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	scsi_task_t *fct_task;
	fc_packet_t *pkt;
	uint32_t did;
	emlxs_fcp_rsp *fcp_rsp;
	uint32_t size;
	emlxs_node_t *ndlp;

	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;
	did = fct_cmd->cmd_rportid;

	/* Initialize cmd_sbp */
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;
	cmd_sbp->node = ndlp;

	size = 24;
	if (fct_task->task_sense_length) {
		size += fct_task->task_sense_length;
	}
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_send_fcp_status %p: stat=%d resid=%d size=%d rx=%x",
	    fct_cmd, fct_task->task_scsi_status,
	    fct_task->task_resid, size, fct_cmd->cmd_rxid);
#endif	/* FCT_API_TRACE */

	if (!(pkt = emlxs_pkt_alloc(port, size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_fcp_status: Unable to allocate packet.");

		cmd_sbp->pkt_flags |= PACKET_RETURNED;
		mutex_exit(&cmd_sbp->mtx);

		return (FCT_FAILURE);
	}
	cmd_sbp->fct_type = EMLXS_FCT_FCP_STATUS;
	cmd_sbp->fct_state = EMLXS_FCT_STATUS_PENDING;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = SWAP_DATA24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_STATUS;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(port->did);
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
			fcp_rsp->rspResId = SWAP_DATA32(fct_task->task_resid);

		} else if (fct_task->task_status_ctrl & TASK_SCTRL_UNDER) {
			TGTPORTSTAT.FctScsiResidUnder++;
			fcp_rsp->rspStatus2 |= RESID_UNDER;
			fcp_rsp->rspResId = SWAP_DATA32(fct_task->task_resid);

		}
	}
	if (fct_task->task_scsi_status) {
		if (fct_task->task_scsi_status == SCSI_STAT_QUE_FULL) {
			TGTPORTSTAT.FctScsiQfullErr++;
		} else {
			TGTPORTSTAT.FctScsiStatusErr++;
		}

		/*
		 * Make sure a residual is reported on non-SCSI_GOOD READ
		 * status
		 */
		if ((fct_task->task_flags & TF_READ_DATA) &&
		    (fcp_rsp->rspResId == 0)) {
			fcp_rsp->rspStatus2 |= RESID_UNDER;
			fcp_rsp->rspResId = fct_task->task_expected_xfer_length;
		}
	}
	if (fct_task->task_sense_length) {
		TGTPORTSTAT.FctScsiSenseErr++;
		fcp_rsp->rspStatus2 |= SNS_LEN_VALID;
		fcp_rsp->rspSnsLen = SWAP_DATA32(fct_task->task_sense_length);

		bcopy((uint8_t *)fct_task->task_sense_data,
		    (uint8_t *)&fcp_rsp->rspInfo0, fct_task->task_sense_length);
	}
	fcp_rsp->rspStatus3 = fct_task->task_scsi_status;
	fcp_rsp->rspRspLen = 0;

	mutex_exit(&cmd_sbp->mtx);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_fcp_status: Unable to send packet.");

		if (cmd_sbp->pkt_flags & PACKET_VALID) {
			mutex_enter(&cmd_sbp->mtx);
			cmd_sbp->fct_pkt = NULL;
			cmd_sbp->fct_state = EMLXS_FCT_STATUS_COMPLETE;
			cmd_sbp->pkt_flags |= PACKET_RETURNED;
			mutex_exit(&cmd_sbp->mtx);
		}
		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}
	return (FCT_SUCCESS);

} /* emlxs_fct_send_fcp_status() */


static fct_status_t
emlxs_fct_send_qfull_reply(emlxs_port_t *port, emlxs_node_t *ndlp, uint16_t xid,
    uint32_t class, emlxs_fcp_cmd_t *fcp_cmd)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt;
	emlxs_fcp_rsp *fcp_rsp;
	uint32_t size;
	RING *rp = &hba->ring[FC_FCP_RING];
	uint8_t lun[8];

	bcopy((void *)&fcp_cmd->fcpLunMsl, lun, 8);
	size = 24;

	if (!(pkt = emlxs_pkt_alloc(port, size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_qfull_reply: Unable to allocate packet.");
		return (FCT_FAILURE);
	}
	sbp = PKT2PRIV(pkt);
	sbp->node = ndlp;
	sbp->ring = rp;
	sbp->did = ndlp->nlp_DID;
	sbp->lun = (lun[0] << 8) | lun[1];
	sbp->class = class;

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = SWAP_DATA24_LO(ndlp->nlp_DID);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_STATUS;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(port->did);
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
	    "emlxs_fct_send_qfull_reply: Sending QFULL: x%x lun x%x: %d %d",
	    xid, sbp->lun, TGTPORTSTAT.FctOutstandingIO,
	    port->fct_port->port_max_xchges);

	/* Build the status payload */
	fcp_rsp = (emlxs_fcp_rsp *)pkt->pkt_cmd;

	TGTPORTSTAT.FctScsiQfullErr++;
	fcp_rsp->rspStatus3 = SCSI_STAT_QUE_FULL;
	fcp_rsp->rspStatus2 |= RESID_UNDER;
	fcp_rsp->rspResId = SWAP_DATA32(fcp_cmd->fcpDl);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_qfull_reply: Unable to send packet.");
		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}
	return (FCT_SUCCESS);

} /* emlxs_fct_send_qfull_reply() */




/* ARGSUSED */
extern int
emlxs_fct_handle_fcp_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	emlxs_buf_t *cmd_sbp;
	uint32_t status;
	fct_cmd_t *fct_cmd;
	stmf_data_buf_t *dbuf;
	scsi_task_t *fct_task;

	iocb = &iocbq->iocb;
	sbp = (emlxs_buf_t *)iocbq->sbp;


	TGTPORTSTAT.FctEvent++;

	if (!sbp) {
		/* completion with missing xmit command */
		TGTPORTSTAT.FctStray++;

		/* emlxs_stray_fcp_completion_msg */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "cmd=%x status=%x error=%x iotag=%x", iocb->ulpCommand,
		    iocb->ulpStatus, iocb->un.grsp.perr.statLocalError,
		    iocb->ulpIoTag);

		return (1);
	}
	TGTPORTSTAT.FctCompleted++;

	port = sbp->iocbq.port;
	fct_cmd = sbp->fct_cmd;
	status = iocb->ulpStatus;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_handle_fcp_event: %p: cmd=%x status=%x",
	    fct_cmd, iocb->ulpCommand, status);
#endif	/* FCT_API_TRACE */

	if (fct_cmd == NULL) {
		if ((iocb->ulpCommand == CMD_FCP_TRSP_CX) ||
		    (iocb->ulpCommand == CMD_FCP_TRSP64_CX)) {
			emlxs_pkt_free(sbp->pkt);
		}
		return (0);
	}
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	dbuf = sbp->fct_buf;
	fct_cmd->cmd_comp_status = (status) ? FCT_FAILURE : FCT_SUCCESS;


	switch (iocb->ulpCommand) {

		/*
		 * FCP Data completion
		 */
	case CMD_FCP_TSEND_CX:
	case CMD_FCP_TSEND64_CX:
	case CMD_FCP_TRECEIVE_CX:
	case CMD_FCP_TRECEIVE64_CX:

		mutex_enter(&cmd_sbp->mtx);
		cmd_sbp->pkt_flags &= ~PACKET_RETURNED;
		cmd_sbp->fct_state = EMLXS_FCT_DATA_COMPLETE;

		if (cmd_sbp->fct_flags & EMLXS_FCT_ABORT) {
			cmd_sbp->fct_flags |= EMLXS_FCT_ABORT_COMPLETE;
			mutex_exit(&cmd_sbp->mtx);

			/* Wake up sleeping thread */
			mutex_enter(&EMLXS_PKT_LOCK);
			cv_broadcast(&EMLXS_PKT_CV);
			mutex_exit(&EMLXS_PKT_LOCK);

			break;
		}
		if (status == 0) {
			if (dbuf->db_flags & DB_DIRECTION_FROM_RPORT) {
				emlxs_fct_dbuf_dma_sync(dbuf,
				    DDI_DMA_SYNC_FORCPU);
			}
			if (cmd_sbp->fct_flags & EMLXS_FCT_SEND_STATUS) {
				dbuf->db_flags |= DB_STATUS_GOOD_SENT;

				fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
				fct_task->task_scsi_status = 0;

				mutex_exit(&cmd_sbp->mtx);
				(void) emlxs_fct_send_fcp_status(fct_cmd);

				break;
			}
		}
		cmd_sbp->fct_flags &= ~EMLXS_FCT_SEND_STATUS;
		cmd_sbp->pkt_flags |= PACKET_RETURNED;
		mutex_exit(&cmd_sbp->mtx);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_scsi_data_xfer_done:1 %p %p", fct_cmd, dbuf);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_scsi_data_xfer_done) (fct_cmd, dbuf, 0);

		break;

		/* FCP Status completion */
	case CMD_FCP_TRSP_CX:
	case CMD_FCP_TRSP64_CX:

		mutex_enter(&cmd_sbp->mtx);
		cmd_sbp->pkt_flags &= ~PACKET_RETURNED;
		cmd_sbp->fct_state = EMLXS_FCT_STATUS_COMPLETE;

		if (cmd_sbp->fct_flags & EMLXS_FCT_ABORT) {
			cmd_sbp->fct_flags |= EMLXS_FCT_ABORT_COMPLETE;
			mutex_exit(&cmd_sbp->mtx);

			/* Wake up sleeping thread */
			mutex_enter(&EMLXS_PKT_LOCK);
			cv_broadcast(&EMLXS_PKT_CV);
			mutex_exit(&EMLXS_PKT_LOCK);
		} else if (cmd_sbp->fct_flags & EMLXS_FCT_SEND_STATUS) {

			/* mutex_exit(&cmd_sbp->mtx); */
			(void) emlxs_fct_cmd_uninit(port, fct_cmd);
			TGTPORTSTAT.FctOutstandingIO--;

#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_scsi_data_xfer_done:2 %p %p",
			    fct_cmd, cmd_sbp->fct_buf);
#endif	/* FCT_API_TRACE */
			MODSYM(fct_scsi_data_xfer_done) (fct_cmd,
			    cmd_sbp->fct_buf, FCT_IOF_FCA_DONE);
		} else {
			/* mutex_exit(&cmd_sbp->mtx); */
			(void) emlxs_fct_cmd_uninit(port, fct_cmd);
			TGTPORTSTAT.FctOutstandingIO--;

#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "fct_send_response_done:1 %p: x%x",
			    fct_cmd, fct_cmd->cmd_comp_status);
#endif	/* FCT_API_TRACE */
			MODSYM(fct_send_response_done) (fct_cmd,
			    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);
		}

		emlxs_pkt_free(sbp->pkt);

		break;

	default:

		TGTPORTSTAT.FctStray++;

		TGTPORTSTAT.FctCompleted--;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Invalid iocb: cmd=0x%x", iocb->ulpCommand);

		emlxs_pkt_complete(sbp, status,
		    iocb->un.grsp.perr.statLocalError, 1);

		return (1);
	}	/* switch(iocb->ulpCommand) */


	if (status == IOSTAT_SUCCESS) {
		TGTPORTSTAT.FctCmplGood++;
	} else {
		TGTPORTSTAT.FctCmplError++;
	}

	return (0);


} /* emlxs_fct_handle_fcp_event() */


extern int
emlxs_fct_handle_unsol_els(emlxs_port_t *port, RING *rp, IOCBQ *iocbq,
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
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "%s: sid=%x. Target unbound. Rejecting...",
		    emlxs_elscmd_xlate(cmd_code), sid);
		(void) emlxs_els_reply(port, iocbq, ELS_CMD_LS_RJT, cmd_code,
		    LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);

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
	/* Process the request */
	switch (cmd_code) {
	case ELS_CMD_FLOGI:
		rval = emlxs_fct_process_unsol_flogi(port, rp, iocbq, mp, size);
		break;

	case ELS_CMD_PLOGI:
		rval = emlxs_fct_process_unsol_plogi(port, rp, iocbq, mp, size);
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
	    (size + padding + GET_STRUCT_SIZE(emlxs_buf_t)), AF_FORCE_NOSLEEP);

#ifdef FCT_API_TRACE
	{
		uint32_t *ptr = (uint32_t *)bp;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_alloc %p: ELS rcvd: rxid=%x payload: x%x x%x",
		    fct_cmd, iocb->ulpContext, *ptr, *(ptr + 1));
	}
#endif	/* FCT_API_TRACE */

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
	fct_cmd->cmd_rxid = iocb->ulpContext;
	fct_cmd->cmd_rportid = sid;
	fct_cmd->cmd_lportid = port->did;
	fct_cmd->cmd_rp_handle = iocb->ulpIoTag;	/* RPI */
	fct_cmd->cmd_port = port->fct_port;

	/* Initialize cmd_sbp */
	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd);
	/* mutex_enter(&cmd_sbp->mtx); */

	cmd_sbp->ring = rp;
	cmd_sbp->class = iocb->ulpClass;
	cmd_sbp->fct_type = EMLXS_FCT_ELS_CMD;
	cmd_sbp->fct_state = EMLXS_FCT_CMD_RECEIVED;
	bcopy((uint8_t *)iocb, (uint8_t *)&cmd_sbp->iocbq,
	    sizeof (emlxs_iocb_t));

	if (cmd_code == ELS_CMD_FLOGI) {
		cmd_sbp->fct_flags |= EMLXS_FCT_FLOGI;
	}
	els = (fct_els_t *)fct_cmd->cmd_specific;
	els->els_req_size = size;
	els->els_req_payload = GET_BYTE_OFFSET(fct_cmd->cmd_fca_private,
	    GET_STRUCT_SIZE(emlxs_buf_t));
	bcopy(bp, els->els_req_payload, size);

	cmd_sbp->pkt_flags |= PACKET_RETURNED;
	mutex_exit(&cmd_sbp->mtx);

	emlxs_fct_unsol_callback(port, fct_cmd);

done:

	return (0);

} /* emlxs_fct_handle_unsol_els() */


static void
emlxs_fct_handle_rcvd_flogi(emlxs_port_t *port, fct_cmd_t *fct_cmd)
{
	fct_els_t *fct_els;
	ELS_PKT *els;
	fct_flogi_xchg_t fx;
	fct_status_t status;
	emlxs_buf_t *cmd_sbp;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;

	fct_els = (fct_els_t *)fct_cmd->cmd_specific;
	els = (ELS_PKT *)fct_els->els_req_payload;

	/* Init the xchg object */
	bzero((uint8_t *)&fx, sizeof (fct_flogi_xchg_t));
	bcopy((caddr_t)&els->un.logi.nodeName, (caddr_t)fx.fx_nwwn, 8);
	bcopy((caddr_t)&els->un.logi.portName, (caddr_t)fx.fx_pwwn, 8);
	fx.fx_sid = fct_cmd->cmd_rportid;
	fx.fx_did = fct_cmd->cmd_lportid;
	fx.fx_fport = els->un.logi.cmn.fPort;
	fx.fx_op = ELS_OP_FLOGI;

	status = MODSYM(fct_handle_rcvd_flogi) (port->fct_port, &fx);
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_handle_rcvd_flogi %p: x%x", port->fct_port, status);
#endif	/* FCT_API_TRACE */

	if (status == FCT_SUCCESS) {
		if (fx.fx_op == ELS_OP_ACC) {
			(void) emlxs_els_reply(port, &cmd_sbp->iocbq,
			    ELS_CMD_ACC, ELS_CMD_FLOGI, 0, 0);
		} else {	/* ELS_OP_LSRJT */
			(void) emlxs_els_reply(port, &cmd_sbp->iocbq,
			    ELS_CMD_LS_RJT, ELS_CMD_FLOGI, fx.fx_rjt_reason,
			    fx.fx_rjt_expl);
		}
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "FLOGI: sid=%x. fct_handle_rcvd_flogi failed. Rejecting.",
		    fct_cmd->cmd_rportid);

		(void) emlxs_els_reply(port, &cmd_sbp->iocbq, ELS_CMD_LS_RJT,
		    ELS_CMD_FLOGI, LSRJT_UNABLE_TPC, LSEXP_NOTHING_MORE);
	}

	/* mutex_exit(&cmd_sbp->mtx); */
	(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_free:7 %p", fct_cmd);
#endif	/* FCT_API_TRACE */
	MODSYM(fct_free) (fct_cmd);

	return;

} /* emlxs_fct_handle_rcvd_flogi() */


/* ARGSUSED */
static uint32_t
emlxs_fct_process_unsol_flogi(emlxs_port_t *port, RING *rp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB *iocb;
	char buffer[64];

	buffer[0] = 0;

	iocb = &iocbq->iocb;

	/* Perform processing of FLOGI payload */
	if (emlxs_process_unsol_flogi(port, iocbq, mp, size, buffer)) {
		return (1);
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg, "FLOGI: sid=0x%x %s",
	    iocb->un.elsreq.remoteID, buffer);

	return (0);

} /* emlxs_fct_process_unsol_flogi() */


/* ARGSUSED */
static uint32_t
emlxs_fct_process_unsol_plogi(emlxs_port_t *port, RING *rp, IOCBQ *iocbq,
    MATCHMAP *mp, uint32_t size)
{
	IOCB *iocb;
	char buffer[64];

	buffer[0] = 0;

	iocb = &iocbq->iocb;

	/* Perform processing of PLOGI payload */
	if (emlxs_process_unsol_plogi(port, iocbq, mp, size, buffer)) {
		return (1);
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg, "PLOGI: sid=0x%x %s",
	    iocb->un.elsreq.remoteID, buffer);

	return (0);

} /* emlxs_fct_process_unsol_plogi() */


/* ARGSUSED */
static emlxs_buf_t *
emlxs_fct_pkt_init(emlxs_port_t *port, fct_cmd_t *fct_cmd, fc_packet_t *pkt)
{
	emlxs_buf_t *cmd_sbp;
	emlxs_buf_t *sbp;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
	cmd_sbp->fct_pkt = pkt;

	sbp = PKT2PRIV(pkt);
	sbp->fct_cmd = cmd_sbp->fct_cmd;
	sbp->node = cmd_sbp->node;
	sbp->ring = cmd_sbp->ring;
	sbp->did = cmd_sbp->did;
	sbp->lun = cmd_sbp->lun;
	sbp->class = cmd_sbp->class;
	sbp->fct_type = cmd_sbp->fct_type;
	sbp->fct_state = cmd_sbp->fct_state;

	return (sbp);

} /* emlxs_fct_pkt_init() */


/* Mutex will be acquired */
static emlxs_buf_t *
emlxs_fct_cmd_init(emlxs_port_t *port, fct_cmd_t *fct_cmd)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	bzero((void *)cmd_sbp, sizeof (emlxs_buf_t));

	mutex_init(&cmd_sbp->mtx, NULL, MUTEX_DRIVER, (void *)hba->intr_arg);

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags = PACKET_VALID;
	cmd_sbp->port = port;
	cmd_sbp->fct_cmd = fct_cmd;
	cmd_sbp->node = (fct_cmd->cmd_rp) ?
	    *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private : NULL;
	cmd_sbp->did = fct_cmd->cmd_rportid;
	cmd_sbp->iocbq.sbp = cmd_sbp;

	return (cmd_sbp);

} /* emlxs_fct_cmd_init() */


/* Mutex must be held */
static int
emlxs_fct_cmd_uninit(emlxs_port_t *port, fct_cmd_t *fct_cmd)
{
	emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		return (FC_FAILURE);
	}
	if (cmd_sbp->iotag != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "Pkt still registered! ringo=%d iotag=%d sbp=%p",
		    cmd_sbp->ring, cmd_sbp->iotag, cmd_sbp);

		if (cmd_sbp->ring) {
			(void) emlxs_unregister_pkt(cmd_sbp->ring,
			    cmd_sbp->iotag, 1);
		}
	}
	cmd_sbp->pkt_flags |= PACKET_RETURNED;
	cmd_sbp->pkt_flags &= ~PACKET_VALID;

	mutex_exit(&cmd_sbp->mtx);
	mutex_destroy(&cmd_sbp->mtx);

	return (FC_SUCCESS);

} /* emlxs_fct_cmd_uninit() */


static void
emlxs_fct_pkt_comp(fc_packet_t *pkt)
{
	emlxs_port_t *port;
	emlxs_buf_t *sbp;
	emlxs_buf_t *cmd_sbp;
	fct_cmd_t *fct_cmd;
	fct_els_t *fct_els;
	fct_sol_ct_t *fct_ct;

	sbp = PKT2PRIV(pkt);
	port = sbp->port;
	fct_cmd = sbp->fct_cmd;
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;
	cmd_sbp->fct_pkt = NULL;

	if (cmd_sbp->fct_flags & EMLXS_FCT_ABORT) {
		cmd_sbp->fct_flags |= EMLXS_FCT_ABORT_COMPLETE;
		mutex_exit(&cmd_sbp->mtx);

		/* Wake up sleeping thread */
		mutex_enter(&EMLXS_PKT_LOCK);
		cv_broadcast(&EMLXS_PKT_CV);
		mutex_exit(&EMLXS_PKT_LOCK);

		goto done;
	}
	fct_cmd->cmd_comp_status = (pkt->pkt_state) ? FCT_FAILURE : FCT_SUCCESS;

	switch (fct_cmd->cmd_type) {
	case FCT_CMD_FCP_XCHG:
		cmd_sbp->fct_state = EMLXS_FCT_STATUS_COMPLETE;

		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_response_done:2 %p: x%x",
		    fct_cmd, fct_cmd->cmd_comp_status);
#else
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_pkt_comp: fct_send_response_done. dbuf=%p",
		    sbp->fct_buf);
#endif	/* FCT_API_TRACE */

		MODSYM(fct_send_response_done) (fct_cmd,
		    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);

		break;

	case FCT_CMD_RCVD_ELS:
		cmd_sbp->fct_state = EMLXS_FCT_RSP_COMPLETE;

		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_response_done:3 %p: x%x",
		    fct_cmd, fct_cmd->cmd_comp_status);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_send_response_done) (fct_cmd,
		    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);

		break;

	case FCT_CMD_SOL_ELS:
		cmd_sbp->fct_state = EMLXS_FCT_REQ_COMPLETE;

		fct_els = (fct_els_t *)fct_cmd->cmd_specific;

		if (fct_els->els_resp_payload) {
			emlxs_mpdata_sync(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
			    DDI_DMA_SYNC_FORKERNEL);

			bcopy((uint8_t *)pkt->pkt_resp,
			    (uint8_t *)fct_els->els_resp_payload,
			    fct_els->els_resp_size);
		}
		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_cmd_done:1 %p: x%x",
		    fct_cmd, fct_cmd->cmd_comp_status);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_send_cmd_done) (fct_cmd,
		    FCT_SUCCESS, FCT_IOF_FCA_DONE);

		break;

	case FCT_CMD_SOL_CT:
		cmd_sbp->fct_state = EMLXS_FCT_REQ_COMPLETE;

		fct_ct = (fct_sol_ct_t *)fct_cmd->cmd_specific;

		if (fct_ct->ct_resp_payload) {
			emlxs_mpdata_sync(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
			    DDI_DMA_SYNC_FORKERNEL);

			bcopy((uint8_t *)pkt->pkt_resp,
			    (uint8_t *)fct_ct->ct_resp_payload,
			    fct_ct->ct_resp_size);
		}
		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_send_cmd_done:2 %p: x%x",
		    fct_cmd, fct_cmd->cmd_comp_status);
#endif	/* FCT_API_TRACE */
		MODSYM(fct_send_cmd_done) (fct_cmd,
		    FCT_SUCCESS, FCT_IOF_FCA_DONE);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_pkt_comp: Invalid cmd type found. type=%x",
		    fct_cmd->cmd_type);

		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);
	}

done:

	emlxs_pkt_free(pkt);

	return;

} /* emlxs_fct_pkt_comp() */



static fct_status_t
emlxs_fct_send_els_cmd(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t did;
	fct_els_t *fct_els;
	fc_packet_t *pkt;
	emlxs_buf_t *cmd_sbp;

#if 0
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_send_els_cmd() called.");
#endif

	did = fct_cmd->cmd_rportid;
	fct_els = (fct_els_t *)fct_cmd->cmd_specific;

	if (!(pkt = emlxs_pkt_alloc(port, fct_els->els_req_size,
	    fct_els->els_resp_size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_els_cmd: Unable to allocate packet.");
		return (FCT_FAILURE);
	}
	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd);
	/* mutex_enter(&cmd_sbp->mtx); */

	cmd_sbp->ring = &hba->ring[FC_ELS_RING];
	cmd_sbp->fct_type = EMLXS_FCT_ELS_REQ;
	cmd_sbp->fct_state = EMLXS_FCT_REQ_PENDING;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_send_els_cmd: pkt_timeout=%d ratov=%d",
	    pkt->pkt_timeout, hba->fc_ratov);


	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = SWAP_DATA24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(port->did);
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

	mutex_exit(&cmd_sbp->mtx);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_els_cmd: Unable to send packet.");

		if (cmd_sbp->pkt_flags & PACKET_VALID) {
			mutex_enter(&cmd_sbp->mtx);
			cmd_sbp->fct_pkt = NULL;
			cmd_sbp->fct_state = EMLXS_FCT_REQ_COMPLETE;
			cmd_sbp->pkt_flags |= PACKET_RETURNED;
			mutex_exit(&cmd_sbp->mtx);
		}
		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}
	return (FCT_SUCCESS);

} /* emlxs_fct_send_els_cmd() */


static fct_status_t
emlxs_fct_send_abts_rsp(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	IOCBQ *iocbq;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_send_abts_rsp: cmd=%p", fct_cmd);

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;

	cmd_sbp->fct_flags |= (EMLXS_FCT_ABORT | EMLXS_FCT_ABORT_COMPLETE);

	/* Create the abort IOCB */
	if (hba->state >= FC_LINK_UP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_send_abts_rsp: Aborting xid=%x. sbp=%p "
		    "state=%d flags=%x,%x", fct_cmd->cmd_rxid, cmd_sbp,
		    cmd_sbp->fct_state, cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

		iocbq = emlxs_create_abort_xri_cx(port, cmd_sbp->node,
		    fct_cmd->cmd_rxid, cmd_sbp->ring, cmd_sbp->class,
		    ABORT_TYPE_ABTS);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_send_abts_rsp: Closing xid=%x. sbp=%p state=%d "
		    "flags=%x,%x", fct_cmd->cmd_rxid, cmd_sbp,
		    cmd_sbp->fct_state, cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

		iocbq = emlxs_create_close_xri_cx(port, cmd_sbp->node,
		    fct_cmd->cmd_rxid, cmd_sbp->ring);
	}

	cmd_sbp->abort_attempts++;
	emlxs_issue_iocb_cmd(hba, cmd_sbp->ring, iocbq);

	/* mutex_exit(&cmd_sbp->mtx); */
	(void) emlxs_fct_cmd_uninit(port, fct_cmd);

	fct_cmd->cmd_comp_status = FCT_SUCCESS;
#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "fct_send_response_done:4 %p: x%x",
	    fct_cmd, fct_cmd->cmd_comp_status);
#endif	/* FCT_API_TRACE */
	MODSYM(fct_send_response_done) (fct_cmd,
	    fct_cmd->cmd_comp_status, FCT_IOF_FCA_DONE);

	return (FCT_SUCCESS);

} /* emlxs_fct_send_abts_rsp() */


static fct_status_t
emlxs_fct_send_els_rsp(fct_cmd_t *fct_cmd)
{
	emlxs_port_t *port =
	    (emlxs_port_t *)fct_cmd->cmd_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	uint32_t did;
	fct_els_t *fct_els;
	fc_packet_t *pkt;
	emlxs_buf_t *cmd_sbp;

#if 0
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_send_els_rsp: cmd=%p", fct_cmd);
#endif

	fct_els = (fct_els_t *)fct_cmd->cmd_specific;
	did = fct_cmd->cmd_rportid;

	if (!(pkt =
	    emlxs_pkt_alloc(port, fct_els->els_resp_size, 0, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_els_rsp: Unable to allocate packet.");
		return (FCT_FAILURE);
	}
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	mutex_enter(&cmd_sbp->mtx);
	cmd_sbp->pkt_flags &= ~PACKET_RETURNED;

	cmd_sbp->fct_type = EMLXS_FCT_ELS_RSP;
	cmd_sbp->fct_state = EMLXS_FCT_RSP_PENDING;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);

	pkt->pkt_tran_type = FC_PKT_OUTBOUND;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = SWAP_DATA24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_RSP;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(port->did);
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

	mutex_exit(&cmd_sbp->mtx);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_els_rsp: Unable to send packet.");

		if (cmd_sbp->pkt_flags & PACKET_VALID) {
			mutex_enter(&cmd_sbp->mtx);
			cmd_sbp->fct_pkt = NULL;
			cmd_sbp->fct_state = EMLXS_FCT_RSP_COMPLETE;
			cmd_sbp->pkt_flags |= PACKET_RETURNED;
			mutex_exit(&cmd_sbp->mtx);
		}
		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}
	return (FCT_SUCCESS);

} /* emlxs_fct_send_els_rsp() */



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

#if 0
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	    "emlxs_fct_send_ct_cmd() called.");
#endif

	did = fct_cmd->cmd_rportid;
	fct_ct = (fct_sol_ct_t *)fct_cmd->cmd_specific;

	if (!(pkt = emlxs_pkt_alloc(port, fct_ct->ct_req_size,
	    fct_ct->ct_resp_size, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_ct_cmd: Unable to allocate packet.");
		return (FCT_FAILURE);
	}
	cmd_sbp = emlxs_fct_cmd_init(port, fct_cmd);
	/* mutex_enter(&cmd_sbp->mtx); */

	cmd_sbp->ring = &hba->ring[FC_CT_RING];
	cmd_sbp->fct_type = EMLXS_FCT_CT_REQ;
	cmd_sbp->fct_state = EMLXS_FCT_REQ_PENDING;

	(void) emlxs_fct_pkt_init(port, fct_cmd, pkt);

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout =
	    ((2 * hba->fc_ratov) < 30) ? 30 : (2 * hba->fc_ratov);
	pkt->pkt_comp = emlxs_fct_pkt_comp;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = SWAP_DATA24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = SWAP_DATA24_LO(port->did);
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

	mutex_exit(&cmd_sbp->mtx);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_send_ct_cmd: Unable to send packet.");

		if (cmd_sbp->pkt_flags & PACKET_VALID) {
			mutex_enter(&cmd_sbp->mtx);
			cmd_sbp->fct_pkt = NULL;
			cmd_sbp->fct_state = EMLXS_FCT_REQ_COMPLETE;
			cmd_sbp->pkt_flags |= PACKET_RETURNED;
			mutex_exit(&cmd_sbp->mtx);
		}
		emlxs_pkt_free(pkt);
		return (FCT_FAILURE);
	}
	return (FCT_SUCCESS);

} /* emlxs_fct_send_ct_cmd() */


/* FCT_NOT_FOUND & FCT_ABORT_SUCCESS indicates IO is done */
/* FCT_SUCCESS indicates abort will occur asyncronously */
static fct_status_t
emlxs_fct_abort(fct_local_port_t *fct_port, fct_cmd_t *fct_cmd, uint32_t flags)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *cmd_sbp;
	uint32_t pkt_flags = 0;
	emlxs_buf_t *sbp = NULL;
	IOCBQ *iocbq;
	fct_status_t rval;

	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_abort: Invalid cmd_sbp=%p.", cmd_sbp);

		return (FCT_NOT_FOUND);
	}
	mutex_enter(&cmd_sbp->mtx);

	if (!(cmd_sbp->pkt_flags & PACKET_VALID)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_abort: Invalid cmd_sbp=%p.", cmd_sbp);

		mutex_exit(&cmd_sbp->mtx);
		return (FCT_NOT_FOUND);
	}
	if (flags & FCT_IOF_FORCE_FCA_DONE) {
		fct_cmd->cmd_handle = 0;
	}
	TGTPORTSTAT.FctAbortSent++;
	TGTPORTSTAT.FctOutstandingIO--;

	switch (cmd_sbp->fct_state) {
	case 0:
	case EMLXS_FCT_REQ_CREATED:
	case EMLXS_FCT_REG_PENDING:

	case EMLXS_FCT_REG_COMPLETE:
	case EMLXS_FCT_REQ_COMPLETE:
	case EMLXS_FCT_DATA_COMPLETE:
	case EMLXS_FCT_STATUS_COMPLETE:
	case EMLXS_FCT_RSP_COMPLETE:

		cmd_sbp->fct_flags |=
		    (EMLXS_FCT_ABORT | EMLXS_FCT_ABORT_COMPLETE);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_abort: Aborted. cmd_sbp=%p state=%d "
		    "flags=%x,%x,%x,%x", cmd_sbp, cmd_sbp->fct_state,
		    flags, cmd_sbp->fct_flags, cmd_sbp->pkt_flags, pkt_flags);

		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

		fct_cmd->cmd_comp_status = FCT_ABORT_SUCCESS;
		return (FCT_ABORT_SUCCESS);


	case EMLXS_FCT_CMD_RECEIVED:

		cmd_sbp->fct_flags |=
		    (EMLXS_FCT_ABORT | EMLXS_FCT_ABORT_COMPLETE);

		/* Create the abort IOCB */
		if (hba->state >= FC_LINK_UP) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_abort: Aborted. xid=%x. cmd_sbp=%p "
			    "state=%d flags=%x,%x,%x", fct_cmd->cmd_rxid,
			    cmd_sbp, cmd_sbp->fct_state, flags,
			    cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

			iocbq = emlxs_create_abort_xri_cx(port, cmd_sbp->node,
			    fct_cmd->cmd_rxid, cmd_sbp->ring, cmd_sbp->class,
			    ABORT_TYPE_ABTS);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_abort: Closed. xid=%x. cmd_sbp=%p "
			    "state=%d flags=%x,%x,%x", fct_cmd->cmd_rxid,
			    cmd_sbp, cmd_sbp->fct_state, flags,
			    cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

			iocbq = emlxs_create_close_xri_cx(port, cmd_sbp->node,
			    fct_cmd->cmd_rxid, cmd_sbp->ring);
		}

		cmd_sbp->abort_attempts++;
		emlxs_issue_iocb_cmd(hba, cmd_sbp->ring, iocbq);

		/* mutex_exit(&cmd_sbp->mtx); */
		(void) emlxs_fct_cmd_uninit(port, fct_cmd);

		fct_cmd->cmd_comp_status = FCT_ABORT_SUCCESS;
		return (FCT_ABORT_SUCCESS);


	case EMLXS_FCT_REQ_PENDING:
	case EMLXS_FCT_STATUS_PENDING:
	case EMLXS_FCT_RSP_PENDING:

		sbp = (emlxs_buf_t *)cmd_sbp->fct_pkt->pkt_fca_private;
		cmd_sbp->fct_flags |= EMLXS_FCT_ABORT;
		mutex_exit(&cmd_sbp->mtx);

		(void) emlxs_fct_pkt_abort(port, sbp);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_abort: Aborted. cmd_sbp=%p state=%d "
		    "flags=%x,%x,%x", cmd_sbp, cmd_sbp->fct_state, flags,
		    cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

		if (cmd_sbp->pkt_flags & PACKET_VALID) {
			mutex_enter(&cmd_sbp->mtx);
			/* mutex_exit(&cmd_sbp->mtx); */
			(void) emlxs_fct_cmd_uninit(port, fct_cmd);
		}
		fct_cmd->cmd_comp_status = FCT_ABORT_SUCCESS;
		return (FCT_ABORT_SUCCESS);

	case EMLXS_FCT_DATA_PENDING:

		if ((cmd_sbp->pkt_flags & (PACKET_IN_COMPLETION |
		    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_abort: Completing. cmd_sbp=%p state=%d "
			    "flags=%x,%x,%x", cmd_sbp, cmd_sbp->fct_state,
			    flags, cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

			mutex_exit(&cmd_sbp->mtx);
			return (FCT_NOT_FOUND);
		}
		cmd_sbp->fct_flags |= EMLXS_FCT_ABORT;
		mutex_exit(&cmd_sbp->mtx);

		rval = emlxs_fct_pkt_abort(port, cmd_sbp);

		if (rval == FCT_ABORT_SUCCESS) {
			fct_cmd->cmd_comp_status = FCT_ABORT_SUCCESS;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_abort: Aborted. cmd_sbp=%p state=%d "
			    "flags=%x,%x,%x", cmd_sbp, cmd_sbp->fct_state,
			    flags, cmd_sbp->fct_flags, cmd_sbp->pkt_flags);

			if (cmd_sbp->pkt_flags & PACKET_VALID) {
				mutex_enter(&cmd_sbp->mtx);
				/* mutex_exit(&cmd_sbp->mtx); */
				(void) emlxs_fct_cmd_uninit(port, fct_cmd);
			}
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_abort: Not found. cmd_sbp=%p state=%d "
			    "flags=%x,%x,%x", cmd_sbp, cmd_sbp->fct_state,
			    flags, cmd_sbp->fct_flags, cmd_sbp->pkt_flags);
		}

		return (rval);

	}	/* switch */

	return (FCT_SUCCESS);

} /* emlxs_fct_abort() */


/* Returns FCT_ABORT_SUCCESS or FCT_NOT_FOUND */
static fct_status_t
emlxs_fct_pkt_abort(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;

	NODELIST *nlp;
	uint8_t ringno;
	RING *rp;
	clock_t timeout;
	clock_t time;
	int32_t pkt_ret;
	IOCBQ *iocbq;
	IOCBQ *next;
	IOCBQ *prev;
	uint32_t found;
	uint32_t att_bit;
	uint32_t pass = 0;
	fct_cmd_t *fct_cmd;
	emlxs_buf_t *cmd_sbp;

	fct_cmd = sbp->fct_cmd;
	cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

	iocbq = &sbp->iocbq;
	nlp = (NODELIST *)sbp->node;
	rp = (RING *)sbp->ring;
	ringno = (rp) ? rp->ringno : 0;

	/* Check packet */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & PACKET_RETURNED)) {
		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		 * "emlxs_fct_pkt_abort: 1. sbp=%p flags=%x,%x", sbp,
		 * cmd_sbp->fct_flags, sbp->pkt_flags);
		 */

		return (FCT_NOT_FOUND);
	}
	mutex_enter(&sbp->mtx);

	/* Check again if we still own this */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & PACKET_RETURNED)) {
		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		 * "emlxs_fct_pkt_abort: 2. sbp=%p flags=%x,%x", sbp,
		 * cmd_sbp->fct_flags, sbp->pkt_flags);
		 */

		mutex_exit(&sbp->mtx);
		return (FCT_NOT_FOUND);
	}
	sbp->pkt_flags |= PACKET_IN_ABORT;

	/* Check again if we still own this */
	if (sbp->pkt_flags &
	    (PACKET_IN_COMPLETION | PACKET_IN_FLUSH | PACKET_IN_TIMEOUT)) {
		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		 * "emlxs_fct_pkt_abort: 3. sbp=%p flags=%x,%x", sbp,
		 * cmd_sbp->fct_flags, sbp->pkt_flags);
		 */

		mutex_exit(&sbp->mtx);
		goto done;
	}
	mutex_exit(&sbp->mtx);

begin:
	pass++;

	/* Check the transmit queue */
	mutex_enter(&EMLXS_RINGTX_LOCK);

	if (sbp->pkt_flags & PACKET_IN_TXQ) {
		/* Find it on the queue */
		found = 0;
		if (iocbq->flag & IOCB_PRIORITY) {
			/* Search the priority queue */
			prev = NULL;
			next = (IOCBQ *)nlp->nlp_ptx[ringno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}
					if (nlp->nlp_ptx[ringno].q_last ==
					    (void *)iocbq) {
						nlp->nlp_ptx[ringno].q_last =
						    (void *)prev;
					}
					if (nlp->nlp_ptx[ringno].q_first ==
					    (void *)iocbq) {
						nlp->nlp_ptx[ringno].q_first =
						    (void *)iocbq->next;
					}
					nlp->nlp_ptx[ringno].q_cnt--;
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
			next = (IOCBQ *)nlp->nlp_tx[ringno].q_first;

			while (next) {
				if (next == iocbq) {
					/* Remove it */
					if (prev) {
						prev->next = iocbq->next;
					}
					if (nlp->nlp_tx[ringno].q_last ==
					    (void *)iocbq) {
						nlp->nlp_tx[ringno].q_last =
						    (void *)prev;
					}
					if (nlp->nlp_tx[ringno].q_first ==
					    (void *)iocbq) {
						nlp->nlp_tx[ringno].q_first =
						    (void *)iocbq->next;
					}
					nlp->nlp_tx[ringno].q_cnt--;
					iocbq->next = NULL;
					found = 1;
					break;
				}
				prev = next;
				next = (IOCBQ *)next->next;
			}
		}

		if (!found) {
			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			 * "emlxs_fct_pkt_abort: 4. sbp=%p flags=%x,%x", sbp,
			 * cmd_sbp->fct_flags, sbp->pkt_flags);
			 */

			goto done;
		}
		/* Check if node still needs servicing */
		if ((nlp->nlp_ptx[ringno].q_first) ||
		    (nlp->nlp_tx[ringno].q_first &&
		    !(nlp->nlp_flag[ringno] & NLP_CLOSED))) {

			/*
			 * If this is the base node, then don't shift the
			 * pointers
			 */
			/* We want to drain the base node before moving on */
			if (!nlp->nlp_base) {
				/*
				 * Just shift ring queue pointers to next
				 * node
				 */
				rp->nodeq.q_last = (void *)nlp;
				rp->nodeq.q_first = nlp->nlp_next[ringno];
			}
		} else {
			/* Remove node from ring queue */

			/* If this is the last node on list */
			if (rp->nodeq.q_last == (void *)nlp) {
				rp->nodeq.q_last = NULL;
				rp->nodeq.q_first = NULL;
				rp->nodeq.q_cnt = 0;
			} else {
				/* Remove node from head */
				rp->nodeq.q_first = nlp->nlp_next[ringno];
				((NODELIST *)rp->nodeq.q_last)->
				    nlp_next[ringno] = rp->nodeq.q_first;
				rp->nodeq.q_cnt--;
			}

			/* Clear node */
			nlp->nlp_next[ringno] = NULL;
		}

		mutex_enter(&sbp->mtx);

		if (sbp->pkt_flags & PACKET_IN_TXQ) {
			sbp->pkt_flags &= ~PACKET_IN_TXQ;
			hba->ring_tx_count[ringno]--;
		}
		mutex_exit(&sbp->mtx);

		(void) emlxs_unregister_pkt(rp, sbp->iotag, 0);

		mutex_exit(&EMLXS_RINGTX_LOCK);

		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		 * "emlxs_fct_pkt_abort: 5. sbp=%p flags=%x,%x", sbp,
		 * cmd_sbp->fct_flags, sbp->pkt_flags);
		 */

		/* Now complete it */
		if (sbp->pkt) {
			emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_ABORT_REQUESTED, 1);
		}
		goto done;
	}
	mutex_exit(&EMLXS_RINGTX_LOCK);


	/* Check the chip queue */
	mutex_enter(&EMLXS_FCTAB_LOCK(ringno));

	if ((sbp->pkt_flags & PACKET_IN_CHIPQ) &&
	    !(sbp->pkt_flags & PACKET_XRI_CLOSED) &&
	    (sbp == rp->fc_table[sbp->iotag])) {
		/* Create the abort IOCB */
		if (hba->state >= FC_LINK_UP) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_pkt_abort: Aborting. sbp=%p "
			    "flags=%x,%x", sbp, cmd_sbp->fct_flags,
			    sbp->pkt_flags);

			iocbq = emlxs_create_abort_xri_cn(port, sbp->node,
			    sbp->iotag, rp, sbp->class, ABORT_TYPE_ABTS);

			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_XRI_CLOSED;
			sbp->ticks = hba->timer_tics + (4 * hba->fc_ratov) + 10;
			sbp->abort_attempts++;
			mutex_exit(&sbp->mtx);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_pkt_abort: Closing. sbp=%p flags=%x,%x",
			    sbp, cmd_sbp->fct_flags, sbp->pkt_flags);

			iocbq = emlxs_create_close_xri_cn(port, sbp->node,
			    sbp->iotag, rp);

			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_XRI_CLOSED;
			sbp->ticks = hba->timer_tics + 30;
			sbp->abort_attempts++;
			mutex_exit(&sbp->mtx);
		}

		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

		/* Send this iocbq */
		if (iocbq) {
			emlxs_issue_iocb_cmd(hba, rp, iocbq);
			iocbq = NULL;
		}
		goto done;
	}
	mutex_exit(&EMLXS_FCTAB_LOCK(ringno));


	/* Pkt was not on any queues */

	/* Check again if we still own this */
	if (!(sbp->pkt_flags & PACKET_VALID) ||
	    (sbp->pkt_flags & (PACKET_RETURNED | PACKET_IN_COMPLETION |
	    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {
		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		 * "emlxs_fct_pkt_abort: 9. sbp=%p flags=%x,%x", sbp,
		 * cmd_sbp->fct_flags, sbp->pkt_flags);
		 */

		goto done;
	}
	/* Apparently the pkt was not found.  Let's delay and try again */
	if (pass < 5) {
		delay(drv_usectohz(5000000));	/* 5 seconds */

		/* Check packet */
		if (!(sbp->pkt_flags & PACKET_VALID) ||
		    (sbp->pkt_flags & (PACKET_RETURNED | PACKET_IN_COMPLETION |
		    PACKET_IN_FLUSH | PACKET_IN_TIMEOUT))) {

			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			 * "emlxs_fct_pkt_abort: 10. sbp=%p flags=%x,%x",
			 * sbp, cmd_sbp->fct_flags, sbp->pkt_flags);
			 */

			goto done;
		}
		goto begin;
	}
force_it:

	/* Force the completion now */
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	 * "emlxs_fct_pkt_abort: 11. sbp=%p flags=%x,%x", sbp,
	 * cmd_sbp->fct_flags, sbp->pkt_flags);
	 */

	/* Unregister the pkt */
	(void) emlxs_unregister_pkt(rp, sbp->iotag, 1);

	/* Now complete it */
	if (sbp->pkt) {
		emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_ABORT_REQUESTED, 1);
	}
done:

	/* Now wait for the pkt to complete */
	if (!(cmd_sbp->fct_flags & EMLXS_FCT_ABORT_COMPLETE)) {
		/* Set thread timeout */
		timeout = emlxs_timeout(hba, 30);

		/* Check for panic situation */
		if (ddi_in_panic()) {
			/*
			 * In panic situations there will be one thread with
			 * no interrrupts (hard or soft) and no timers
			 */

			/*
			 * We must manually poll everything in this thread to
			 * keep the driver going.
			 */

			rp = (emlxs_ring_t *)sbp->ring;
			switch (rp->ringno) {
			case FC_FCP_RING:
				att_bit = HA_R0ATT;
				break;

			case FC_IP_RING:
				att_bit = HA_R1ATT;
				break;

			case FC_ELS_RING:
				att_bit = HA_R2ATT;
				break;

			case FC_CT_RING:
				att_bit = HA_R3ATT;
				break;
			}

			/* Keep polling the chip until our IO is completed */
			(void) drv_getparm(LBOLT, &time);
			while ((time < timeout) &&
			    !(cmd_sbp->fct_flags & EMLXS_FCT_ABORT_COMPLETE)) {
				emlxs_poll_intr(hba, att_bit);
				(void) drv_getparm(LBOLT, &time);
			}
		} else {
			/* Wait for IO completion or timeout */
			mutex_enter(&EMLXS_PKT_LOCK);
			pkt_ret = 0;
			while ((pkt_ret != -1) &&
			    !(cmd_sbp->fct_flags & EMLXS_FCT_ABORT_COMPLETE)) {
				pkt_ret = cv_timedwait(&EMLXS_PKT_CV,
				    &EMLXS_PKT_LOCK, timeout);
			}
			mutex_exit(&EMLXS_PKT_LOCK);
		}

		/*
		 * Check if timeout occured.  This is not good.  Something
		 * happened to our IO.
		 */
		if (!(cmd_sbp->fct_flags & EMLXS_FCT_ABORT_COMPLETE)) {
			/* Force the completion now */
			goto force_it;
		}
	}
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
	 * "emlxs_fct_pkt_abort: 12. sbp=%p flags=%x,%x", sbp,
	 * cmd_sbp->fct_flags, sbp->pkt_flags);
	 */

	return (FCT_ABORT_SUCCESS);

} /* emlxs_fct_pkt_abort() */



static uint32_t
emlxs_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	uint32_t sgllen = 1;
	uint32_t rval;
	uint32_t size;
	uint32_t count;
	uint32_t resid;
	struct stmf_sglist_ent *sgl;

	size = sbp->fct_buf->db_data_size;
	count = sbp->fct_buf->db_sglist_length;
	sgl = sbp->fct_buf->db_sglist;
	resid = size;

	for (sgllen = 0; sgllen < count && resid > 0; sgllen++) {
		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	if (resid > 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_bde_setup: Not enough scatter gather buffers "
		    "provided. size=%d resid=%d count=%d", size, resid, count);
		return (1);
	}
#ifdef SLI3_SUPPORT
	if ((hba->sli_mode < 3) || (sgllen > SLI3_MAX_BDE)) {
		rval = emlxs_fct_sli2_bde_setup(port, sbp);
	} else {
		rval = emlxs_fct_sli3_bde_setup(port, sbp);
	}
#else	/* !SLI3_SUPPORT */
	rval = emlxs_fct_sli2_bde_setup(port, sbp);
#endif	/* SLI3_SUPPORT */

	return (rval);

} /* emlxs_fct_bde_setup() */



/* Only used for FCP Data xfers */
static uint32_t
emlxs_fct_sli2_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	scsi_task_t *fct_task;
	MATCHMAP *bmp;
	ULP_BDE64 *bpl;
	uint64_t bp;
	uint8_t bdeFlags;
	IOCB *iocb;
	uint32_t resid;
	uint32_t count;
	uint32_t size;
	uint32_t sgllen;
	struct stmf_sglist_ent *sgl;
	emlxs_fct_dmem_bctl_t *bctl;

	iocb = (IOCB *)&sbp->iocbq;
	sbp->bmp = NULL;

	if (!sbp->fct_buf) {
		iocb->un.fcpt64.bdl.addrHigh = 0;
		iocb->un.fcpt64.bdl.addrLow = 0;
		iocb->un.fcpt64.bdl.bdeSize = 0;
		iocb->un.fcpt64.bdl.bdeFlags = 0;
		iocb->un.fcpt64.fcpt_Offset = 0;
		iocb->un.fcpt64.fcpt_Length = 0;
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 1;
		return (0);
	}
#ifdef EMLXS_SPARC
	/* Use FCP MEM_BPL table to get BPL buffer */
	bmp = &hba->fcp_bpl_table[sbp->iotag];
#else
	/* Use MEM_BPL pool to get BPL buffer */
	bmp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BPL);
#endif	/* EMLXS_SPARC */

	if (!bmp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_sli2_bde_setup: Unable to BPL buffer. iotag=%x",
		    sbp->iotag);

		iocb->un.fcpt64.bdl.addrHigh = 0;
		iocb->un.fcpt64.bdl.addrLow = 0;
		iocb->un.fcpt64.bdl.bdeSize = 0;
		iocb->un.fcpt64.bdl.bdeFlags = 0;
		iocb->un.fcpt64.fcpt_Offset = 0;
		iocb->un.fcpt64.fcpt_Length = 0;
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 1;
		return (1);
	}
	bpl = (ULP_BDE64 *) bmp->virt;
	bp = bmp->phys;

	fct_task = (scsi_task_t *)sbp->fct_cmd->cmd_specific;

	/* size = fct_task->task_cmd_xfer_length; */
	size = sbp->fct_buf->db_data_size;
	count = sbp->fct_buf->db_sglist_length;
	bctl = (emlxs_fct_dmem_bctl_t *)sbp->fct_buf->db_port_private;

	bdeFlags = (fct_task->task_flags & TF_WRITE_DATA) ? BUFF_USE_RCV : 0;
	sgl = sbp->fct_buf->db_sglist;
	resid = size;

	/* Init the buffer list */
	for (sgllen = 0; sgllen < count && resid > 0; sgllen++) {
		bpl->addrHigh =
		    PCIMEM_LONG((uint32_t)putPaddrHigh(bctl->bctl_dev_addr));
		bpl->addrLow =
		    PCIMEM_LONG((uint32_t)putPaddrLow(bctl->bctl_dev_addr));
		bpl->tus.f.bdeSize = MIN(resid, sgl->seg_length);
		bpl->tus.f.bdeFlags = bdeFlags;
		bpl->tus.w = PCIMEM_LONG(bpl->tus.w);
		bpl++;

		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	/* Init the IOCB */
	iocb->un.fcpt64.bdl.addrHigh = (uint32_t)putPaddrHigh(bp);
	iocb->un.fcpt64.bdl.addrLow = (uint32_t)putPaddrLow(bp);
	iocb->un.fcpt64.bdl.bdeSize = sgllen * sizeof (ULP_BDE64);
	iocb->un.fcpt64.bdl.bdeFlags = BUFF_TYPE_BDL;

	iocb->un.fcpt64.fcpt_Length =
	    (fct_task->task_flags & TF_WRITE_DATA) ? size : 0;
	iocb->un.fcpt64.fcpt_Offset = 0;

	iocb->ulpBdeCount = 1;
	iocb->ulpLe = 1;
	sbp->bmp = bmp;

	return (0);

} /* emlxs_fct_sli2_bde_setup */



#ifdef SLI3_SUPPORT

/* ARGSUSED */
static uint32_t
emlxs_fct_sli3_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	scsi_task_t *fct_task;
	ULP_BDE64 *bde;
	IOCB *iocb;
	uint32_t size;
	uint32_t count;
	uint32_t sgllen;
	int32_t resid;
	struct stmf_sglist_ent *sgl;
	uint32_t bdeFlags;
	emlxs_fct_dmem_bctl_t *bctl;

	iocb = (IOCB *)&sbp->iocbq;

	if (!sbp->fct_buf) {
		iocb->un.fcpt64.bdl.addrHigh = 0;
		iocb->un.fcpt64.bdl.addrLow = 0;
		iocb->un.fcpt64.bdl.bdeSize = 0;
		iocb->un.fcpt64.bdl.bdeFlags = 0;
		iocb->un.fcpt64.fcpt_Offset = 0;
		iocb->un.fcpt64.fcpt_Length = 0;
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 0;
		iocb->unsli3.ext_iocb.ebde_count = 0;
		return (0);
	}
	fct_task = (scsi_task_t *)sbp->fct_cmd->cmd_specific;

	size = sbp->fct_buf->db_data_size;
	count = sbp->fct_buf->db_sglist_length;
	bctl = (emlxs_fct_dmem_bctl_t *)sbp->fct_buf->db_port_private;

	bdeFlags = (fct_task->task_flags & TF_WRITE_DATA) ? BUFF_USE_RCV : 0;
	sgl = sbp->fct_buf->db_sglist;
	resid = size;

	/* Init first BDE */
	iocb->un.fcpt64.bdl.addrHigh = putPaddrHigh(bctl->bctl_dev_addr);
	iocb->un.fcpt64.bdl.addrLow = putPaddrLow(bctl->bctl_dev_addr);
	iocb->un.fcpt64.bdl.bdeSize = MIN(resid, sgl->seg_length);
	iocb->un.fcpt64.bdl.bdeFlags = bdeFlags;
	resid -= MIN(resid, sgl->seg_length);
	sgl++;

	/* Init remaining BDE's */
	bde = (ULP_BDE64 *) & iocb->unsli3.ext_iocb.ebde1;
	for (sgllen = 1; sgllen < count && resid > 0; sgllen++) {
		bde->addrHigh = putPaddrHigh(bctl->bctl_dev_addr);
		bde->addrLow = putPaddrLow(bctl->bctl_dev_addr);
		bde->tus.f.bdeSize = MIN(resid, sgl->seg_length);
		bde->tus.f.bdeFlags = bdeFlags;
		bde++;

		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	iocb->unsli3.ext_iocb.ebde_count = sgllen - 1;
	iocb->un.fcpt64.fcpt_Length =
	    (fct_task->task_flags & TF_WRITE_DATA) ? size : 0;
	iocb->un.fcpt64.fcpt_Offset = 0;

	iocb->ulpBdeCount = 0;
	iocb->ulpLe = 0;

	return (0);

} /* emlxs_fct_sli3_bde_setup */

#endif	/* SLI3_SUPPORT */


extern void
emlxs_fct_link_up(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (port->fct_port &&
	    (port->fct_flags & FCT_STATE_PORT_ONLINE) &&
	    !(port->fct_flags & FCT_STATE_LINK_UP)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_link_up event.");

		port->fct_flags |= FCT_STATE_LINK_UP;

		mutex_exit(&EMLXS_PORT_LOCK);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_handle_event LINK_UP");
#endif	/* FCT_API_TRACE */
		MODSYM(fct_handle_event) (port->fct_port,
		    FCT_EVENT_LINK_UP, 0, 0);

		emlxs_fct_unsol_flush(port);
	} else {
		if (!hba->ini_mode &&
		    !(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
			mutex_exit(&EMLXS_PORT_LOCK);

			/* Take link down and hold it down */
			(void) emlxs_reset_link(hba, 0);
		} else {
			mutex_exit(&EMLXS_PORT_LOCK);
		}
	}

	return;

} /* emlxs_fct_link_up() */

extern void
emlxs_fct_link_down(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (port->fct_port &&
	    (port->fct_flags & FCT_STATE_PORT_ONLINE) &&
	    (port->fct_flags & FCT_STATE_LINK_UP)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "emlxs_fct_link_down event.");

		port->fct_flags &= ~FCT_STATE_LINK_UP;

		mutex_exit(&EMLXS_PORT_LOCK);

#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "fct_handle_event LINK_DOWN");
#endif	/* FCT_API_TRACE */
		MODSYM(fct_handle_event) (port->fct_port,
		    FCT_EVENT_LINK_DOWN, 0, 0);
	} else {
		mutex_exit(&EMLXS_PORT_LOCK);
	}

	return;

} /* emlxs_fct_link_down() */



/*
 * DMA FUNCTIONS
 */


fct_status_t
emlxs_fct_dmem_init(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_fct_dmem_bucket_t *p;
	emlxs_fct_dmem_bctl_t *bctl;
	emlxs_fct_dmem_bctl_t *bc;
	emlxs_fct_dmem_bctl_t *prev;
	int32_t j;
	int32_t i;
	uint32_t total_mem;
	uint8_t *addr;
	uint8_t *host_addr;
	uint64_t dev_addr;
	ddi_dma_cookie_t cookie;
	uint32_t ncookie;
	uint32_t bsize;
	size_t len;
	char buf[64];
	ddi_device_acc_attr_t acc;

	bzero(&acc, sizeof (acc));
	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	p = port->dmem_bucket;
	for (i = 0; i < FCT_MAX_BUCKETS; i++, p++) {
		if (!p->dmem_nbufs) {
			continue;
		}
		bctl = (emlxs_fct_dmem_bctl_t *)kmem_zalloc(p->dmem_nbufs *
		    sizeof (emlxs_fct_dmem_bctl_t), KM_NOSLEEP);

		if (bctl == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_dmem_init: Unable to allocate bctl.");
			goto alloc_bctl_failed;
		}
		p->dmem_bctls_mem = bctl;

		if (ddi_dma_alloc_handle(hba->dip, &emlxs_dma_attr_1sg,
		    DDI_DMA_SLEEP, 0, &p->dmem_dma_handle) != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_dmem_init: Unable to allocate handle.");
			goto alloc_handle_failed;
		}

		total_mem = p->dmem_buf_size * p->dmem_nbufs;

		if (ddi_dma_mem_alloc(p->dmem_dma_handle, total_mem, &acc,
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0, (caddr_t *)&addr,
		    &len, &p->dmem_acc_handle) != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_dmem_init: Unable to allocate memory.");
			goto mem_alloc_failed;
		}

		if (ddi_dma_addr_bind_handle(p->dmem_dma_handle, NULL,
		    (caddr_t)addr, total_mem, DDI_DMA_RDWR | DDI_DMA_STREAMING,
		    DDI_DMA_DONTWAIT, 0, &cookie, &ncookie) != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_dmem_init: Unable to bind handle.");
			goto addr_bind_handle_failed;
		}

		if (ncookie != 1) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlxs_fct_dmem_init: DMEM init failed.");
			goto dmem_init_failed;
		}
		(void) sprintf(buf, "%s%d_bucket%d mutex", DRIVER_NAME,
		    hba->ddiinst, i);
		mutex_init(&p->dmem_lock, buf, MUTEX_DRIVER,
		    (void *)hba->intr_arg);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "bufsize=%d cnt=%d", p->dmem_buf_size, p->dmem_nbufs);

		host_addr = addr;
		dev_addr = (uint64_t)cookie.dmac_laddress;

		p->dmem_host_addr = addr;
		p->dmem_dev_addr = dev_addr;
		p->dmem_bctl_free_list = bctl;
		p->dmem_nbufs_free = p->dmem_nbufs;
		bsize = p->dmem_buf_size;

		for (j = 0; j < p->dmem_nbufs; j++) {
			stmf_data_buf_t *db;

			db = MODSYM(stmf_alloc) (STMF_STRUCT_DATA_BUF, 0, 0);
#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "stmf_alloc data_buf %p", db);
#endif	/* FCT_API_TRACE */
			if (db == NULL) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
				    "emlxs_fct_dmem_init: DMEM init: "
				    "alloc failed.");
				goto dmem_init_failed;
			}
			db->db_port_private = bctl;
			db->db_sglist[0].seg_addr = host_addr;
			db->db_sglist[0].seg_length = bsize;
			db->db_buf_size = bsize;
			db->db_sglist_length = 1;

			bctl->bctl_bucket = p;
			bctl->bctl_buf = db;
			bctl->bctl_dev_addr = dev_addr;

			host_addr += bsize;
			dev_addr += bsize;

			prev = bctl;
			bctl++;
			prev->bctl_next = bctl;
		}

		prev->bctl_next = NULL;
	}

	return (FCT_SUCCESS);

dmem_failure_loop:
	mutex_destroy(&p->dmem_lock);
	bc = bctl;
	while (bc) {
#ifdef FCT_API_TRACE
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
		    "stmf_free:3 %p", bctl->bctl_buf);
#endif	/* FCT_API_TRACE */
		MODSYM(stmf_free) (bc->bctl_buf);
		bc = bc->bctl_next;
	}

dmem_init_failed:
	(void) ddi_dma_unbind_handle(p->dmem_dma_handle);

addr_bind_handle_failed:
	(void) ddi_dma_mem_free(&p->dmem_acc_handle);

mem_alloc_failed:
	(void) ddi_dma_free_handle(&p->dmem_dma_handle);

alloc_handle_failed:
	kmem_free(p->dmem_bctls_mem,
	    p->dmem_nbufs * sizeof (emlxs_fct_dmem_bctl_t));

alloc_bctl_failed:
	if (--i >= 0) {
		p = &port->dmem_bucket[i];
		bctl = p->dmem_bctl_free_list;
		goto dmem_failure_loop;
	}
	return (FCT_FAILURE);

} /* emlxs_fct_dmem_init() */



void
emlxs_fct_dmem_fini(emlxs_port_t *port)
{
	emlxs_fct_dmem_bucket_t *p;
	emlxs_fct_dmem_bctl_t *bctl;
	uint32_t i;

	p = port->dmem_bucket;
	for (i = 0; i < FCT_MAX_BUCKETS; i++, p++) {
		if (!p->dmem_nbufs) {
			continue;
		}
		bctl = p->dmem_bctl_free_list;

		while (bctl) {
#ifdef FCT_API_TRACE
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
			    "stmf_free:4 %p", bctl->bctl_buf);
#endif	/* FCT_API_TRACE */
			MODSYM(stmf_free) (bctl->bctl_buf);
			bctl = bctl->bctl_next;
		}

		bctl = p->dmem_bctl_free_list;

		(void) ddi_dma_unbind_handle(p->dmem_dma_handle);
		(void) ddi_dma_mem_free(&p->dmem_acc_handle);
		(void) ddi_dma_free_handle(&p->dmem_dma_handle);

		kmem_free(p->dmem_bctls_mem,
		    (p->dmem_nbufs * sizeof (emlxs_fct_dmem_bctl_t)));
		mutex_destroy(&p->dmem_lock);
	}

	bzero((uint8_t *)port->dmem_bucket, sizeof (port->dmem_bucket));

	return;

} /* emlxs_fct_dmem_fini() */


/* ARGSUSED */
static stmf_data_buf_t *
emlxs_fct_dbuf_alloc(fct_local_port_t *fct_port, uint32_t size,
    uint32_t *pminsize, uint32_t flags)
{
	emlxs_port_t *port = (emlxs_port_t *)fct_port->port_fca_private;
	emlxs_fct_dmem_bucket_t *p;
	emlxs_fct_dmem_bctl_t *bctl;
	uint32_t i;

/*
 *	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
 *	    "emlxs_fct_dbuf_alloc: size=%d min=%d", size, *pminsize);
 */

	if (size > FCT_DMEM_MAX_BUF_SIZE) {
		size = FCT_DMEM_MAX_BUF_SIZE;
	}
	p = port->dmem_bucket;
	for (i = 0; i < FCT_MAX_BUCKETS; i++, p++) {
		if (!p->dmem_nbufs) {
			continue;
		}
		if (p->dmem_buf_size >= size) {
			mutex_enter(&p->dmem_lock);
			if (p->dmem_nbufs_free) {
				if (p->dmem_buf_size < *pminsize) {
					*pminsize = p->dmem_buf_size;
					TGTPORTSTAT.FctNoBuffer++;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_fct_api_msg,
					    "emlxs_fct_dbuf_alloc: Failed(1).");
					mutex_exit(&p->dmem_lock);
					return (NULL);
				}
				bctl = p->dmem_bctl_free_list;
				if (bctl == NULL) {
					mutex_exit(&p->dmem_lock);
					continue;
				}
				p->dmem_bctl_free_list = bctl->bctl_next;
				p->dmem_nbufs_free--;
				bctl->bctl_buf->db_data_size = size;
				mutex_exit(&p->dmem_lock);

#ifdef FCT_API_TRACE
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
				    "emlx_fct_buf_alloc size %p: %d",
				    bctl->bctl_buf, size);
#endif	/* FCT_API_TRACE */

				return (bctl->bctl_buf);
			}
			mutex_exit(&p->dmem_lock);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
			    "emlx_fct_buf_alloc size %d Nothing free bck %d",
			    size, i);
		}
	}

	*pminsize = 0;
	TGTPORTSTAT.FctNoBuffer++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_dbuf_alloc: Failed(2).");

	return (NULL);

} /* emlxs_fct_dbuf_alloc() */


/* ARGSUSED */
static void
emlxs_fct_dbuf_free(fct_dbuf_store_t *fds, stmf_data_buf_t *dbuf)
{
	emlxs_fct_dmem_bctl_t *bctl =
	    (emlxs_fct_dmem_bctl_t *)dbuf->db_port_private;
	emlxs_fct_dmem_bucket_t *p = bctl->bctl_bucket;

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlx_fct_buf_free %p", dbuf);
#endif	/* FCT_API_TRACE */

	mutex_enter(&p->dmem_lock);
	bctl->bctl_next = p->dmem_bctl_free_list;
	p->dmem_bctl_free_list = bctl;
	p->dmem_nbufs_free++;
	mutex_exit(&p->dmem_lock);

} /* emlxs_fct_dbuf_free() */


void
emlxs_fct_dbuf_dma_sync(stmf_data_buf_t *dbuf, uint_t sync_type)
{
	emlxs_fct_dmem_bctl_t *bctl =
	    (emlxs_fct_dmem_bctl_t *)dbuf->db_port_private;
	emlxs_fct_dmem_bucket_t *p = bctl->bctl_bucket;

	(void) ddi_dma_sync(p->dmem_dma_handle,
	    (unsigned long)(bctl->bctl_dev_addr - p->dmem_dev_addr),
	    dbuf->db_data_size, sync_type);

} /* emlxs_fct_dbuf_dma_sync() */


#endif	/* SFCT_SUPPORT */
