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

/*
 * SCSI Target Port I/F for Solaris SCSI RDMA Protocol Target (SRP)
 * port provider module for the COMSTAR framework.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>
#include <sys/taskq.h>
#include <sys/atomic.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>

#include <sys/scsi/generic/persist.h>
#include <sys/ib/mgt/ibdma/ibdma.h>

#include "srp.h"
#include "srpt_impl.h"
#include "srpt_cm.h"
#include "srpt_ioc.h"
#include "srpt_ch.h"
#include "srpt_stp.h"

extern srpt_ctxt_t	*srpt_ctxt;
extern uint32_t		srpt_iu_size;

/*
 * STMF LPort Interface Prototypes
 */
static stmf_status_t srpt_stp_xfer_data(struct scsi_task *task,
	struct stmf_data_buf *dbuf, uint32_t ioflags);
stmf_status_t srpt_stp_send_status(struct scsi_task *task,
	uint32_t ioflags);
static void srpt_stp_task_free(struct scsi_task *task);
static stmf_status_t srpt_stp_abort(struct stmf_local_port *lport,
	int abort_cmd, void *arg, uint32_t flags);
static void srpt_stp_task_poll(struct scsi_task *task);
static void srpt_stp_ctl(struct stmf_local_port *lport,
	int cmd, void *arg);
static stmf_status_t srpt_stp_info(uint32_t cmd,
	struct stmf_local_port *lport, void *arg, uint8_t *buf,
	uint32_t *bufsizep);
static void srpt_stp_event_handler(struct stmf_local_port *lport,
	int eventid, void *arg, uint32_t flags);

static void srpt_format_login_rsp(srp_login_req_t *req,
	srp_login_rsp_t *rsp, uint8_t flags);
static void srpt_format_login_rej(srp_login_req_t *req,
	srp_login_rej_t *rej, uint32_t reason);

static scsi_devid_desc_t *srpt_stp_alloc_scsi_devid_desc(uint64_t guid);
static void srpt_stp_free_scsi_devid_desc(scsi_devid_desc_t *sdd);

extern uint16_t srpt_send_msg_depth;

/*
 * srpt_stp_start_srp() - Start SRP service
 *
 * Enable the SRP service for the specified SCSI Target Port.
 */
int
srpt_stp_start_srp(srpt_target_port_t *tgt)
{
	ibt_status_t		status;
	ibdma_status_t		dma_status;
	int			port;
	srpt_ioc_t		*ioc;

	if (tgt == NULL) {
		SRPT_DPRINTF_L1("stp_start_srp, NULL SCSI target port");
		return (IBT_FAILURE);
	}

	if (tgt->tp_ioc == NULL) {
		SRPT_DPRINTF_L1("stp_start_srp, SCSI target port NULL"
		    " IOC pointer");
		return (IBT_FAILURE);
	}
	ioc = tgt->tp_ioc;

	SRPT_DPRINTF_L2("stp_start_srp, register SRP service for"
	    " svc_id (%016llx)", (u_longlong_t)tgt->tp_ibt_svc_id);
	status = ibt_register_service(srpt_ctxt->sc_ibt_hdl,
	    &tgt->tp_ibt_svc_desc, tgt->tp_ibt_svc_id, 1,
	    &tgt->tp_ibt_svc_hdl, NULL);
	if (status != IBT_SUCCESS) {
		tgt->tp_ibt_svc_hdl = NULL;
		SRPT_DPRINTF_L1("stp_start_srp, SRP service creation err (%d)",
		    status);
		return (status);
	}

	/*
	 * Bind the service associated with the SCSI target port to
	 * each active port of the I/O Controller.
	 */
	for (port = 0; port < ioc->ioc_attr.hca_nports; port++) {
		status = srpt_ioc_svc_bind(tgt, port+1);
		if (status != IBT_SUCCESS &&
		    status != IBT_HCA_PORT_NOT_ACTIVE) {
			SRPT_DPRINTF_L1("start_srp, Unable to bind"
			    " service (%d)", status);
			goto srp_start_err;
		}
	}

	/* don't online if we have no active ports */
	if (tgt->tp_num_active_ports == 0) {
		SRPT_DPRINTF_L2("start_srp, no ports active for svc_id %016llx",
		    (u_longlong_t)tgt->tp_ibt_svc_id);
		status = IBT_HCA_PORT_NOT_ACTIVE;
		goto srp_start_err;
	}

	tgt->tp_srp_enabled = 1;

	/*
	 * Calculate the new I/O Controller profile and either update the
	 * profile if previously registered or register it with the IB
	 * Device Management Agent.
	 */
	SRPT_DPRINTF_L3("start_srp, update I/O Controller profile (%016llx)",
	    (u_longlong_t)ioc->ioc_guid);

	srpt_ioc_init_profile(ioc);
	if (ioc->ioc_ibdma_hdl == NULL) {
		ioc->ioc_ibdma_hdl =
		    srpt_ctxt->sc_ibdma_ops.ibdma_register(ioc->ioc_guid,
		    &ioc->ioc_profile, &ioc->ioc_svc);
		if (ioc->ioc_ibdma_hdl == NULL) {
			SRPT_DPRINTF_L1("start_srp, Unable to register"
			    " I/O Profile for svc_id %016llx",
			    (u_longlong_t)tgt->tp_ibt_svc_id);
			status = IBT_FAILURE;
			goto srp_start_err;
		}
	} else {
		dma_status =
		    srpt_ctxt->sc_ibdma_ops.ibdma_update(ioc->ioc_ibdma_hdl,
		    &ioc->ioc_profile, &ioc->ioc_svc);
		if (dma_status != IBDMA_SUCCESS) {
			SRPT_DPRINTF_L1("start_srp, Unable to update I/O"
			    " Profile for svc_id %016llxi (%d)",
			    (u_longlong_t)tgt->tp_ibt_svc_id, dma_status);
			status = IBT_FAILURE;
			goto srp_start_err;
		}
	}

	return (IBT_SUCCESS);

srp_start_err:
	tgt->tp_srp_enabled = 0;
	srpt_ioc_svc_unbind_all(tgt);
	tgt->tp_num_active_ports = 0;
	if (tgt->tp_ibt_svc_hdl != NULL) {
		(void) ibt_deregister_service(srpt_ctxt->sc_ibt_hdl,
		    tgt->tp_ibt_svc_hdl);
		tgt->tp_ibt_svc_hdl = NULL;
	}
	return (status);
}

/*
 * srpt_stp_stop_srp() - Stop SRP service.
 *
 * Disable the SRP service on the specified SCSI Target Port.
 */
void
srpt_stp_stop_srp(srpt_target_port_t *tgt)
{
	ibt_status_t		status;
	ibdma_status_t		dma_status;
	srpt_ioc_t		*ioc;
	srpt_channel_t		*ch;

	if (tgt == NULL) {
		SRPT_DPRINTF_L2("stp_stop_srp, NULL SCSI Target Port"
		    " specified");
		return;
	}

	if (tgt->tp_ioc == NULL) {
		SRPT_DPRINTF_L2("stp_stop_srp, bad Target, IOC NULL");
		return;
	}
	ioc = tgt->tp_ioc;

	/*
	 * Update the I/O Controller profile to remove the SRP service
	 * for this SCSI target port.
	 */
	tgt->tp_srp_enabled = 0;

	if (ioc->ioc_ibdma_hdl != NULL) {
		SRPT_DPRINTF_L3("stp_stop_srp, update I/O Controller"
		    " profile (%016llx)", (u_longlong_t)ioc->ioc_guid);
		srpt_ioc_init_profile(ioc);

		if (ioc->ioc_profile.ioc_service_entries == 0) {
			SRPT_DPRINTF_L3("stp_stop_srp, no services active"
			    " unregister IOC profile");
			srpt_ctxt->sc_ibdma_ops.ibdma_unregister(
			    ioc->ioc_ibdma_hdl);
			ioc->ioc_ibdma_hdl = NULL;
		} else {
			dma_status = srpt_ctxt->sc_ibdma_ops.ibdma_update(
			    ioc->ioc_ibdma_hdl, &ioc->ioc_profile,
			    &ioc->ioc_svc);
			if (dma_status != IBDMA_SUCCESS) {
				SRPT_DPRINTF_L1("stp_stop_srp, Unable to"
				    " update I/O Profile (%d)", dma_status);
				return;
			}
		}
	}

	/*
	 * Unbind the SRP service associated with the SCSI target port
	 * from all of the I/O Controller physical ports.
	 */
	SRPT_DPRINTF_L2("stp_stop_srp, unbind and de-register service"
	    "(%016llx)", (u_longlong_t)tgt->tp_ibt_svc_id);
	if (tgt->tp_ibt_svc_hdl != NULL) {
		srpt_ioc_svc_unbind_all(tgt);
	}

	if (tgt->tp_ibt_svc_hdl != NULL) {
		status = ibt_deregister_service(srpt_ctxt->sc_ibt_hdl,
		    tgt->tp_ibt_svc_hdl);
		if (status != IBT_SUCCESS) {
			SRPT_DPRINTF_L1("stp_stop_srp, de-register service"
			    " error(%d)", status);
		}
		tgt->tp_ibt_svc_hdl = NULL;
	}

	/*
	 * SRP service is now off-line for this SCSI Target Port.
	 * We force a disconnect (i.e. SRP Target Logout) for any
	 * active SRP logins.
	 */
	mutex_enter(&tgt->tp_ch_list_lock);
	ch = list_head(&tgt->tp_ch_list);
	while (ch != NULL) {
		SRPT_DPRINTF_L3("stp_stop_srp, disconnect ch(%p)",
		    (void *)ch);
		srpt_ch_disconnect(ch);
		ch = list_next(&tgt->tp_ch_list, ch);
	}
	mutex_exit(&tgt->tp_ch_list_lock);

	/*
	 * wait for all sessions to terminate before returning
	 */
	mutex_enter(&tgt->tp_sess_list_lock);
	while (!list_is_empty(&tgt->tp_sess_list)) {
		cv_wait(&tgt->tp_sess_complete, &tgt->tp_sess_list_lock);
	}
	mutex_exit(&tgt->tp_sess_list_lock);
}

/*
 * srpt_stp_alloc_port() - Allocate SCSI Target Port
 */
srpt_target_port_t *
srpt_stp_alloc_port(srpt_ioc_t *ioc, ib_guid_t guid)
{
	stmf_status_t		status;
	srpt_target_port_t	*tgt;
	stmf_local_port_t	*lport;
	uint64_t		temp;

	if (ioc == NULL) {
		SRPT_DPRINTF_L1("stp_alloc_port, NULL I/O Controller");
		return (NULL);
	}

	SRPT_DPRINTF_L3("stp_alloc_port, allocate STMF local port");
	lport = stmf_alloc(STMF_STRUCT_STMF_LOCAL_PORT, sizeof (*tgt), 0);
	if (lport == NULL) {
		SRPT_DPRINTF_L1("tgt_alloc_port, stmf_alloc failed");
		return (NULL);
	}

	tgt = lport->lport_port_private;
	ASSERT(tgt != NULL);

	mutex_init(&tgt->tp_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&tgt->tp_ch_list_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tgt->tp_offline_complete, NULL, CV_DRIVER, NULL);
	list_create(&tgt->tp_ch_list, sizeof (srpt_channel_t),
	    offsetof(srpt_channel_t, ch_stp_node));

	mutex_init(&tgt->tp_sess_list_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tgt->tp_sess_complete, NULL, CV_DRIVER, NULL);
	list_create(&tgt->tp_sess_list, sizeof (srpt_session_t),
	    offsetof(srpt_session_t, ss_node));

	tgt->tp_state	 = SRPT_TGT_STATE_OFFLINE;
	tgt->tp_drv_disabled  = 0;
	tgt->tp_srp_enabled   = 0;
	tgt->tp_lport	 = lport;
	tgt->tp_ioc	   = ioc;
	tgt->tp_ibt_svc_id = guid;
	tgt->tp_ibt_svc_desc.sd_handler = srpt_cm_hdlr;
	tgt->tp_ibt_svc_desc.sd_flags   = IBT_SRV_NO_FLAGS;
	temp = h2b64(tgt->tp_ibt_svc_id);
	bcopy(&temp, &tgt->tp_srp_port_id[0], 8);
	temp = h2b64(tgt->tp_ioc->ioc_guid);
	bcopy(&temp, &tgt->tp_srp_port_id[8], 8);

	tgt->tp_nports  = ioc->ioc_attr.hca_nports;
	tgt->tp_hw_port =
	    kmem_zalloc(sizeof (srpt_hw_port_t) * tgt->tp_nports, KM_SLEEP);
	tgt->tp_num_active_ports = 0;
	tgt->tp_requested_state = SRPT_TGT_STATE_OFFLINE;

	tgt->tp_scsi_devid = srpt_stp_alloc_scsi_devid_desc(tgt->tp_ibt_svc_id);

	lport->lport_id = tgt->tp_scsi_devid;
	lport->lport_pp = srpt_ctxt->sc_pp;
	lport->lport_ds	= ioc->ioc_stmf_ds;
	lport->lport_xfer_data	= &srpt_stp_xfer_data;
	lport->lport_send_status = &srpt_stp_send_status;
	lport->lport_task_free	= &srpt_stp_task_free;
	lport->lport_abort	= &srpt_stp_abort;
	lport->lport_abort_timeout = 300;	/* 5 minutes */
	lport->lport_task_poll	= &srpt_stp_task_poll;
	lport->lport_ctl	= &srpt_stp_ctl;
	lport->lport_info	= &srpt_stp_info;
	lport->lport_event_handler = &srpt_stp_event_handler;

	/* set up as alua participating port */
	stmf_set_port_alua(lport);

	SRPT_DPRINTF_L3("stp_alloc_port, register STMF LPORT");

retry_registration:
	status = stmf_register_local_port(lport);
	if (status == STMF_SUCCESS) {
		SRPT_DPRINTF_L3("stp_alloc_port, LPORT successfully"
		    " registered");
		return (tgt);
	}

	if (status == STMF_BUSY) {
		/*
		 * This is only done on an administrative thread of
		 * execution so it is ok to take a while.
		 */
		SRPT_DPRINTF_L3("stp_alloc_port, delaying");
		delay(2 * drv_usectohz(1000000));
		goto retry_registration;
	}
	SRPT_DPRINTF_L1("stp_alloc_port, STMF register local port err(0x%llx)",
	    (u_longlong_t)status);

	SRPT_DPRINTF_L3("stp_alloc_port, free STMF local port");
	cv_destroy(&tgt->tp_offline_complete);
	mutex_destroy(&tgt->tp_ch_list_lock);
	mutex_destroy(&tgt->tp_lock);
	if (tgt->tp_hw_port) {
		kmem_free(tgt->tp_hw_port,
		    sizeof (srpt_hw_port_t) * tgt->tp_nports);
	}
	if (tgt->tp_scsi_devid) {
		srpt_stp_free_scsi_devid_desc(tgt->tp_scsi_devid);
	}

	stmf_free(lport);

	return (NULL);
}

/*
 * srpt_stp_free_port() - Free SCSI Target Port
 */
stmf_status_t
srpt_stp_free_port(srpt_target_port_t *tgt)
{
	ASSERT(tgt != NULL);
	ASSERT(list_is_empty(&tgt->tp_sess_list));
	ASSERT(list_is_empty(&tgt->tp_ch_list));

	list_destroy(&tgt->tp_ch_list);
	list_destroy(&tgt->tp_sess_list);

	cv_destroy(&tgt->tp_sess_complete);
	cv_destroy(&tgt->tp_offline_complete);

	mutex_destroy(&tgt->tp_sess_list_lock);
	mutex_destroy(&tgt->tp_ch_list_lock);
	mutex_destroy(&tgt->tp_lock);


	SRPT_DPRINTF_L3("stp_free_port, free STMF local port");
	if (tgt->tp_hw_port) {
		kmem_free(tgt->tp_hw_port,
		    sizeof (srpt_hw_port_t) * tgt->tp_nports);
	}

	if (tgt->tp_scsi_devid) {
		srpt_stp_free_scsi_devid_desc(tgt->tp_scsi_devid);
	}

	stmf_free(tgt->tp_lport);

	return (STMF_SUCCESS);
}

/*
 * srpt_stp_destroy_port()
 */
stmf_status_t
srpt_stp_destroy_port(srpt_target_port_t *tgt)
{
	stmf_status_t		status;
	stmf_change_status_t	cstatus;
	uint64_t		guid;

	ASSERT(tgt != NULL);
	ASSERT(tgt->tp_lport != NULL);

	SRPT_DPRINTF_L3("stp_destroy_port, de-register STMF LPORT");

	mutex_enter(&tgt->tp_lock);
	if (tgt->tp_drv_disabled != 0) {
		/* already being destroyed, get out now - should not happen */
		mutex_exit(&tgt->tp_lock);
		return (STMF_ALREADY);
	}

	tgt->tp_drv_disabled = 1;
	guid = tgt->tp_ioc->ioc_guid;
	mutex_exit(&tgt->tp_lock);

	SRPT_DPRINTF_L2("stp_destroy_port: unbind and de-register"
	    " services for GUID(%016llx)", (u_longlong_t)guid);

	cstatus.st_completion_status = STMF_SUCCESS;
	cstatus.st_additional_info = NULL;

	status = stmf_ctl(STMF_CMD_LPORT_OFFLINE, tgt->tp_lport, &cstatus);

	/*
	 * Wait for asynchronous target off-line operation
	 * to complete and then deregister the target
	 * port.
	 */
	mutex_enter(&tgt->tp_lock);
	while (tgt->tp_state != SRPT_TGT_STATE_OFFLINE) {
		cv_wait(&tgt->tp_offline_complete, &tgt->tp_lock);
	}
	mutex_exit(&tgt->tp_lock);

	SRPT_DPRINTF_L3("stp_destroy_port: IOC (0x%016llx) Target"
	    " SRP off-line complete", (u_longlong_t)guid);

	/* loop waiting for all I/O to drain */
	for (;;) {
		status = stmf_deregister_local_port(tgt->tp_lport);
		if (status == STMF_BUSY) {
			delay(drv_usectohz(1000000));
		} else {
			break;
		}
	}

	if (status == STMF_SUCCESS) {
		SRPT_DPRINTF_L3("stp_destroy_port, LPORT de-register"
		    " complete");
	} else {
		/*
		 * Something other than a BUSY error, this should not happen.
		 */
		SRPT_DPRINTF_L1(
		    "stp_destroy_port, de-register STMF error(0x%llx)",
		    (u_longlong_t)status);
	}

	return (status);
}

/*
 * srpt_stp_xfer_data()
 */
/* ARGSUSED */
static stmf_status_t
srpt_stp_xfer_data(struct scsi_task *task, struct stmf_data_buf *dbuf,
	uint32_t ioflags)
{
	srpt_iu_t		*iu;
	srpt_channel_t		*ch;
	srpt_ds_dbuf_t		*db;
	ibt_send_wr_t		wr;
	ibt_wr_ds_t		ds;
	ibt_status_t		status;
	uint32_t		xfer_len;
	uint32_t		xferred_len;
	uint32_t		rdma_len;
	uint32_t		base_offset;
	uint32_t		desc_offset;
	srp_direct_desc_t	*desc;

	SRPT_DPRINTF_L3("stp_xfer_data, invoked task (%p), dbuf (%p)",
	    (void *)task, (void *)dbuf);
	iu = task->task_port_private;
	ASSERT(iu != NULL);
	ASSERT(iu->iu_ch != NULL);
	/*
	 * We should use iu->iu_ch->ch_swqe_posted to throttle
	 * send wqe posting. This is very unlikely because we limit
	 * the maximum number of initiator descriptors per IU (impact
	 * of fragmentation of intiator buffer space) but it could occur
	 * if the back-end (STMF) were to use too many small buffers. In
	 * that case we would want to return STMF_BUSY.
	 */

	SRPT_DPRINTF_L4("stp_xfer_data, dbuf->db_flags (0x%x)",
	    dbuf->db_flags);
	SRPT_DPRINTF_L4("stp_xfer_data, dbuf->db_data_size (%d)",
	    dbuf->db_data_size);
	SRPT_DPRINTF_L4("stp_xfer_data, dbuf->db_relative_offset (%d)",
	    dbuf->db_relative_offset);

	ASSERT((dbuf->db_flags & (DB_DIRECTION_TO_RPORT |
	    DB_DIRECTION_FROM_RPORT)) != (DB_DIRECTION_TO_RPORT |
	    DB_DIRECTION_FROM_RPORT));

	db = dbuf->db_port_private;

	/*
	 * Check to see if request will overflow the remote buffer; if so
	 * return a bad status and let STMF abort the task.
	 */
	if ((dbuf->db_relative_offset + dbuf->db_data_size) >
	    iu->iu_tot_xfer_len) {
		SRPT_DPRINTF_L2("stp_xfer_data, overflow of remote buffer");
		return (STMF_FAILURE);
	}

	db->db_iu	= iu;
	wr.wr_trans  = IBT_RC_SRV;
	wr.wr_opcode = (dbuf->db_flags & DB_DIRECTION_TO_RPORT) ?
	    IBT_WRC_RDMAW : IBT_WRC_RDMAR;
	wr.wr_nds    = 1;
	wr.wr_sgl    = &ds;

	/*
	 * We know that the data transfer is within the bounds described
	 * by our list of remote buffer descriptors.  Find the starting
	 * point based on the offset for the transfer, then perform the
	 * RDMA operations required of this transfer.
	 */
	base_offset = 0;
	desc = iu->iu_rdescs;

	while ((base_offset + desc->dd_len) < dbuf->db_relative_offset) {
		base_offset += desc->dd_len;
		desc++;
	}

	xfer_len    = dbuf->db_data_size;
	xferred_len = 0;
	desc_offset = dbuf->db_relative_offset - base_offset;

	ch = iu->iu_ch;

	/*
	 * If the channel is no longer connected then return an
	 * error and do not initiate I/O.  STMF should abort the
	 * task.
	 */
	rw_enter(&ch->ch_rwlock, RW_READER);

	if (iu->iu_ch->ch_state == SRPT_CHANNEL_DISCONNECTING) {
		rw_exit(&iu->iu_ch->ch_rwlock);
		return (STMF_FAILURE);
	}

	while (xfer_len > 0) {
		rdma_len = desc->dd_len - desc_offset;

		/*
		 * We only generate completion entries on the last IB
		 * operation associated with any STMF buffer.
		 */
		if (rdma_len >= xfer_len) {
			rdma_len = xfer_len;
			wr.wr_flags  = IBT_WR_SEND_SIGNAL;
		} else {
			wr.wr_flags  = IBT_WR_NO_FLAGS;
		}

		wr.wr.rc.rcwr.rdma.rdma_raddr = desc->dd_vaddr + desc_offset;
		wr.wr.rc.rcwr.rdma.rdma_rkey  = desc->dd_hdl;
		ds.ds_va  = db->db_sge.ds_va + xferred_len;
		ds.ds_key = db->db_sge.ds_key;
		ds.ds_len = rdma_len;

		SRPT_DPRINTF_L4("stp_xfer_data, post RDMA operation");

		/*
		 * If this task is being aborted or has been aborted,
		 * do not post additional I/O.
		 */
		DTRACE_SRP_8(xfer__start, srpt_channel_t, ch,
		    ibt_wr_ds_t, &(db->db_sge), srpt_iu_t, iu,
		    ibt_send_wr_t, &wr, uint32_t, rdma_len,
		    uint32_t, xferred_len, uint32_t, desc_offset,
		    uint32_t, wr.wr_opcode == IBT_WRC_RDMAR ? 0 : 1);
		mutex_enter(&iu->iu_lock);
		if ((iu->iu_flags & (SRPT_IU_SRP_ABORTING |
		    SRPT_IU_STMF_ABORTING | SRPT_IU_ABORTED)) != 0) {
			mutex_exit(&iu->iu_lock);
			rw_exit(&iu->iu_ch->ch_rwlock);
			return (STMF_SUCCESS);
		}

		/*
		 * If a non-error CQE will be requested, add a reference to
		 * the IU and initialize the work request appropriately.
		 */
		if ((wr.wr_flags & IBT_WR_SEND_SIGNAL) != 0) {
			wr.wr_id = srpt_ch_alloc_swqe_wrid(ch,
			    SRPT_SWQE_TYPE_DATA, (void *)dbuf);
			if (wr.wr_id == 0) {
				rw_exit(&iu->iu_ch->ch_rwlock);
				mutex_exit(&iu->iu_lock);
				return (STMF_BUSY);
			}
			atomic_inc_32(&iu->iu_sq_posted_cnt);
		} else {
			wr.wr_id = 0;
		}

		status = ibt_post_send(iu->iu_ch->ch_chan_hdl, &wr, 1, NULL);
		mutex_exit(&iu->iu_lock);

		if (status != IBT_SUCCESS) {
			/*
			 * Could not post to IB transport, report to STMF and
			 * and let it initiate an abort of the task.
			 */
			SRPT_DPRINTF_L2("stp_xfer_data, post RDMA"
			    " error (%d)", status);

			if ((wr.wr_flags & IBT_WR_SEND_SIGNAL) != 0) {
				srpt_ch_free_swqe_wrid(ch, wr.wr_id);
				atomic_dec_32(&iu->iu_sq_posted_cnt);
			}
			rw_exit(&iu->iu_ch->ch_rwlock);
			return (STMF_FAILURE);
		}
		xferred_len += rdma_len;
		xfer_len    -= rdma_len;
		desc_offset  = 0;
		desc++;
	}

	rw_exit(&ch->ch_rwlock);
	return (STMF_SUCCESS);
}

/*
 * srpt_stp_send_mgmt_response() - Return SRP task managment response IU
 */
ibt_status_t
srpt_stp_send_mgmt_response(srpt_iu_t *iu, uint8_t srp_rsp,
	uint_t fence)
{
	srp_rsp_t	*rsp;
	srp_rsp_data_t	*data;
	uint32_t	rsp_length;
	ibt_status_t	status;
	uint8_t		*bufp;

	ASSERT(mutex_owned(&iu->iu_lock));
	rsp = iu->iu_buf;
	bufp = (uint8_t *)iu->iu_buf + SRP_RSP_SIZE;
	bzero(rsp, SRP_RSP_SIZE + sizeof (srp_rsp_data_t));
	rsp->rsp_type = SRP_IU_RSP;

	/*
	 * Report ULP credits we have added since last response sent
	 * over this channel.
	 */
	rsp->rsp_req_limit_delta =
	    h2b32(atomic_swap_32(&iu->iu_ch->ch_req_lim_delta, 0));
	rsp->rsp_tag = iu->iu_tag;

	/* srp_rsp_t is padded out, so use explicit size here */
	rsp_length = SRP_RSP_SIZE;
	if (srp_rsp != SRP_TM_SUCCESS) {
		rsp->rsp_flags |= SRP_RSP_VALID;
		data = (srp_rsp_data_t *)bufp;
		data->rd_rsp_status = srp_rsp;
		rsp->rsp_data_len = h2b32(sizeof (srp_rsp_data_t));
		rsp_length += sizeof (srp_rsp_data_t);
	}

	SRPT_DPRINTF_L4("stp_send_mgmt_response, sending on ch(%p),"
	    " iu(%p), mgmt status(%d)", (void *)iu->iu_ch,
	    (void *)iu, srp_rsp);

	DTRACE_SRP_4(task__response, srpt_channel_t, iu->iu_ch,
	    srp_rsp_t, iu->iu_buf, scsi_task_t, iu->iu_stmf_task,
	    int8_t, srp_rsp);

	status = srpt_ch_post_send(iu->iu_ch, iu, rsp_length, fence);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("stp_send_mgmt_response, post "
		    "response err(%d)", status);
	}
	return (status);
}

/*
 * srpt_stp_send_response() - Send SRP command response IU
 */
ibt_status_t
srpt_stp_send_response(srpt_iu_t *iu, uint8_t scsi_status,
	uint8_t flags, uint32_t resid, uint16_t sense_length,
	uint8_t *sense_data, uint_t fence)
{
	srp_rsp_t	*rsp;
	uint32_t	rsp_length;
	uint8_t		*bufp;
	ibt_status_t	status;

	ASSERT(mutex_owned(&iu->iu_lock));
	rsp = iu->iu_buf;
	bufp = (uint8_t *)iu->iu_buf + SRP_RSP_SIZE;
	bzero(rsp, SRP_RSP_SIZE);
	rsp->rsp_type = SRP_IU_RSP;

	/*
	 * Report ULP credits we have added since last response sent
	 * over this channel.
	 */
	rsp->rsp_req_limit_delta =
	    h2b32(atomic_swap_32(&iu->iu_ch->ch_req_lim_delta, 0));
	rsp->rsp_tag = iu->iu_tag;
	rsp->rsp_status = scsi_status;

	rsp_length = SRP_RSP_SIZE;

	if (resid != 0) {
		rsp->rsp_flags |= flags;

		if ((flags & SRP_RSP_DO_OVER) ||
		    (flags & SRP_RSP_DO_UNDER)) {
			rsp->rsp_do_resid_cnt = h2b32(resid);
		} else if ((flags & SRP_RSP_DI_OVER) ||
		    (flags & SRP_RSP_DI_UNDER)) {
			rsp->rsp_di_resid_cnt = h2b32(resid);
		}
	}

	if (sense_length != 0) {
		rsp->rsp_flags |= SRP_RSP_SNS_VALID;
		if (SRP_RSP_SIZE + sense_length >
		    iu->iu_ch->ch_ti_iu_len) {
			sense_length = iu->iu_ch->ch_ti_iu_len -
			    SRP_RSP_SIZE;
		}
		bcopy(sense_data, bufp, sense_length);
		rsp->rsp_sense_data_len = h2b32(sense_length);
		rsp_length += sense_length;
	}

	SRPT_DPRINTF_L4("stp_send_reponse, sending on ch(%p),"
	    " iu(%p), length(%d)", (void *)iu->iu_ch,
	    (void *)iu, rsp_length);

	DTRACE_SRP_4(task__response, srpt_channel_t, iu->iu_ch,
	    srp_rsp_t, iu->iu_buf, scsi_task_t, iu->iu_stmf_task,
	    uint8_t, scsi_status);

	status = srpt_ch_post_send(iu->iu_ch, iu, rsp_length, fence);
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("stp_send_response, post response err(%d)",
		    status);
	}
	return (status);
}

/*
 * srpt_stp_send_status()
 */
/* ARGSUSED */
stmf_status_t
srpt_stp_send_status(struct scsi_task *task, uint32_t ioflags)
{
	srpt_iu_t	*iu;
	ibt_status_t	status;

	ASSERT(task != NULL);
	iu = task->task_port_private;

	ASSERT(iu != NULL);

	mutex_enter(&iu->iu_lock);

	ASSERT(iu->iu_ch != NULL);

	SRPT_DPRINTF_L3("stp_send_status, invoked task (%p)"
	    ", task_completion_status (%d)"
	    ", task_resid (%d)"
	    ", task_status_ctrl (%d)"
	    ", task_scsi_status (%d)"
	    ", task_sense_length (%d)"
	    ", task_sense_data (%p)",
	    (void *)task,
	    (int)task->task_completion_status,
	    task->task_resid,
	    task->task_status_ctrl,
	    task->task_scsi_status,
	    task->task_sense_length,
	    (void *)task->task_sense_data);

	DTRACE_SRP_4(scsi__response, srpt_channel_t, iu->iu_ch,
	    srp_rsp_t, iu->iu_buf, scsi_task_t, task,
	    int8_t, task->task_scsi_status);

	if ((iu->iu_flags & (SRPT_IU_STMF_ABORTING |
	    SRPT_IU_SRP_ABORTING | SRPT_IU_ABORTED)) != 0) {
		mutex_exit(&iu->iu_lock);
		return (STMF_FAILURE);
	}

	/*
	 * Indicate future aborts can not be initiated (although
	 * we will handle any that have been requested since the
	 * last I/O completed and before we are sending status).
	 */
	iu->iu_flags |= SRPT_IU_RESP_SENT;

	/*
	 * Send SRP command response or SRP task mgmt response.
	 */
	if (task->task_mgmt_function == 0) {
		uint8_t		rsp_flags = 0;
		uint32_t	resbytes = 0;

		if (task->task_status_ctrl == TASK_SCTRL_OVER) {
			resbytes = task->task_resid;

			if (task->task_flags & TF_READ_DATA) {
				SRPT_DPRINTF_L3(
				    "stp_send_status, data out overrun");
				rsp_flags |= SRP_RSP_DO_OVER;
			} else if (task->task_flags & TF_WRITE_DATA) {
				SRPT_DPRINTF_L3(
				    "stp_send_status, data in overrun");
				rsp_flags |= SRP_RSP_DI_OVER;
			}
		} else if (task->task_status_ctrl == TASK_SCTRL_UNDER) {
			resbytes = task->task_resid;

			if (task->task_flags & TF_READ_DATA) {
				SRPT_DPRINTF_L3(
				    "stp_send_status, data out underrun");
				rsp_flags |= SRP_RSP_DO_UNDER;
			} else if (task->task_flags & TF_WRITE_DATA) {
				SRPT_DPRINTF_L3(
				    "stp_send_status, data in underrun");
				rsp_flags |= SRP_RSP_DI_UNDER;
			}
		}

		status = srpt_stp_send_response(iu,
		    task->task_scsi_status, rsp_flags, resbytes,
		    task->task_sense_length, task->task_sense_data, 0);
	} else {
		status = srpt_stp_send_mgmt_response(iu,
		    (task->task_scsi_status ?
		    SRP_TM_FAILED : SRP_TM_SUCCESS),
		    SRPT_FENCE_SEND);
	}

	/*
	 * If we have an error posting the response return bad status
	 * to STMF and let it initiate an abort for the task.
	 */
	if (status != IBT_SUCCESS) {
		SRPT_DPRINTF_L2("stp_send_status, post response err(%d)",
		    status);

		/* clear the response sent flag since it never went out */
		iu->iu_flags &= ~SRPT_IU_RESP_SENT;

		mutex_exit(&iu->iu_lock);
		return (STMF_FAILURE);
	}
	mutex_exit(&iu->iu_lock);
	return (STMF_SUCCESS);
}

/*
 * srpt_stp_task_free() - STMF call-back.
 */
static void
srpt_stp_task_free(struct scsi_task *task)
{
	srpt_iu_t	*iu;
	srpt_channel_t	*ch;

	SRPT_DPRINTF_L3("stp_task_free, invoked task (%p)",
	    (void *)task);

	iu = task->task_port_private;
	ASSERT(iu != NULL);

	mutex_enter(&iu->iu_lock);
	ch = iu->iu_ch;
	mutex_exit(&iu->iu_lock);

	ASSERT(ch != NULL);
	ASSERT(ch->ch_session != NULL);

	/*
	 * Do not hold IU lock while task is being removed from
	 * the session list - possible deadlock if cleaning up
	 * channel when this is called.
	 */
	srpt_stp_remove_task(ch->ch_session, iu);

	mutex_enter(&iu->iu_lock);
	iu->iu_stmf_task = NULL;

	srpt_ioc_repost_recv_iu(iu->iu_ioc, iu);

	mutex_exit(&iu->iu_lock);

	srpt_ch_release_ref(ch, 0);
}

/*
 * srpt_stp_abort() - STMF call-back.
 */
/* ARGSUSED */
static stmf_status_t
srpt_stp_abort(struct stmf_local_port *lport, int abort_cmd,
	void *arg, uint32_t flags)
{
	struct scsi_task	*task;
	srpt_iu_t		*iu;
	stmf_status_t		status;

	SRPT_DPRINTF_L3("stp_abort, invoked lport (%p), arg (%p)",
	    (void *)lport, (void *)arg);

	task = (struct scsi_task *)arg;
	ASSERT(task != NULL);

	iu = (srpt_iu_t *)task->task_port_private;
	ASSERT(iu != NULL);

	mutex_enter(&iu->iu_lock);

	/*
	 * If no I/O is outstanding then immediately transition to
	 * aborted state.  If any I/O is in progress OR we've sent the
	 * completion response, then indicate that an STMF abort has been
	 * requested and ask STMF to call us back later to complete the abort.
	 */
	if ((iu->iu_flags & SRPT_IU_RESP_SENT) ||
	    (iu->iu_sq_posted_cnt > 0)) {
		SRPT_DPRINTF_L3("stp_abort, deferring abort request. "
		    "%d outstanding I/O for IU %p",
		    iu->iu_sq_posted_cnt, (void *)iu);
		iu->iu_flags |= SRPT_IU_STMF_ABORTING;
		status = STMF_BUSY;
	} else {
		SRPT_DPRINTF_L3("stp_abort, no outstanding I/O for %p",
		    (void *)iu);
		iu->iu_flags |= SRPT_IU_ABORTED;
		/* Synchronous abort - STMF will call task_free */
		status = STMF_ABORT_SUCCESS;
	}

	mutex_exit(&iu->iu_lock);
	return (status);
}

/*
 * srpt_stp_task_poll() - STMF call-back
 */
static void
srpt_stp_task_poll(struct scsi_task *task)
{
	SRPT_DPRINTF_L3("stp_task_poll, invoked, task (%p)",
	    (void *)task);
}

/*
 * srpt_stp_ctl() - STMF call-back
 */
static void
srpt_stp_ctl(struct stmf_local_port *lport, int cmd, void *arg)
{
	stmf_state_change_info_t	*sc_info = arg;
	stmf_change_status_t		cstatus;
	stmf_status_t			status;
	srpt_target_port_t		*tgt;
	char				*why;

	ASSERT(sc_info != NULL);
	ASSERT(lport != NULL);

	tgt = lport->lport_port_private;
	ASSERT(tgt->tp_ioc != NULL);

	why = sc_info->st_additional_info;
	if (why == NULL) {
		why = "<null>";
	}

	SRPT_DPRINTF_L2("stp_ctl, invoked for LPORT (0x%016llx), cmd (%d), "
	    "info (%s)", (u_longlong_t)tgt->tp_ibt_svc_id, cmd, why);

	cstatus.st_completion_status = STMF_SUCCESS;
	cstatus.st_additional_info = NULL;

	switch (cmd) {
	case STMF_CMD_LPORT_ONLINE:
		SRPT_DPRINTF_L2("stp_ctl, LPORT_ONLINE command,"
		    " st_rflags(0x%llx)", (u_longlong_t)sc_info->st_rflags);
		/*
		 * If the SCSI Target Port is not enabled by the driver,
		 * don't start and instead return busy.  This is a
		 * creation/destruction transitional state and the will
		 * either go away or become enabled.
		 */
		mutex_enter(&tgt->tp_lock);

		tgt->tp_requested_state = SRPT_TGT_STATE_ONLINE;

		if (tgt->tp_drv_disabled != 0) {
			SRPT_DPRINTF_L1("stp_ctl, set LPORT_ONLINE failed - "
			    "LPORT (0x%016llx) BUSY",
			    (u_longlong_t)tgt->tp_ibt_svc_id);
			cstatus.st_completion_status = STMF_BUSY;
		} else if ((tgt->tp_state == SRPT_TGT_STATE_ONLINE) ||
		    (tgt->tp_state == SRPT_TGT_STATE_ONLINING)) {
			cstatus.st_completion_status = STMF_ALREADY;
		} else if (tgt->tp_state != SRPT_TGT_STATE_OFFLINE) {
			cstatus.st_completion_status = STMF_INVALID_ARG;
		} else {
			tgt->tp_state = SRPT_TGT_STATE_ONLINING;
			status = srpt_stp_start_srp(tgt);
			if (status != IBT_SUCCESS) {
				tgt->tp_state = SRPT_TGT_STATE_OFFLINE;
				cstatus.st_completion_status = STMF_INVALID_ARG;
				if (tgt->tp_num_active_ports == 0) {
					SRPT_DPRINTF_L1(
					    "stp_ctl, no ports active "
					    "for HCA 0x%016llx. Target will "
					    "not be placed online.",
					    (u_longlong_t)tgt->tp_ibt_svc_id);
				}
			}
		}
		mutex_exit(&tgt->tp_lock);
		SRPT_DPRINTF_L3("stp_ctl, (0x%016llx) LPORT_ONLINE command"
		    " status (0x%llx)", (u_longlong_t)tgt->tp_ibt_svc_id,
		    (u_longlong_t)cstatus.st_completion_status);
		status = stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE, lport,
		    &cstatus);
		if (status != STMF_SUCCESS) {
			SRPT_DPRINTF_L1("stp_ctl, ONLINE_COMPLETE returned"
			    " error(0x%llx)", (u_longlong_t)status);
		}
		break;

	case STMF_CMD_LPORT_OFFLINE:
		SRPT_DPRINTF_L2("stp_ctl, LPORT_OFFLINE command,"
		    " st_rflags(0x%llx)", (u_longlong_t)sc_info->st_rflags);
		mutex_enter(&tgt->tp_lock);

		/*
		 * Only keep persistent state if explicitly requested by user
		 * action, such as stmfadm offline-target or
		 * svcadm disable stmf.
		 * If not requested by the user, this was likely triggered by
		 * not having any HCA ports active.
		 */
		if (sc_info->st_rflags & STMF_RFLAG_USER_REQUEST) {
			tgt->tp_requested_state = SRPT_TGT_STATE_OFFLINE;
		}

		if ((tgt->tp_state == SRPT_TGT_STATE_OFFLINE) ||
		    (tgt->tp_state == SRPT_TGT_STATE_OFFLINING)) {
			cstatus.st_completion_status = STMF_ALREADY;
		} else if (tgt->tp_state != SRPT_TGT_STATE_ONLINE) {
			cstatus.st_completion_status = STMF_INVALID_ARG;
		} else {
			tgt->tp_state = SRPT_TGT_STATE_OFFLINING;
			srpt_stp_stop_srp(tgt);
		}
		mutex_exit(&tgt->tp_lock);
		SRPT_DPRINTF_L3("stp_ctl, notify STMF OFFLINE complete"
		    " (0x%016llx)", (u_longlong_t)tgt->tp_ibt_svc_id);
		status = stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    lport, &cstatus);
		if (status != STMF_SUCCESS) {
			SRPT_DPRINTF_L1("stp_ctl, OFFLINE_COMPLETE returned"
			    " error(0x%llx)", (u_longlong_t)status);
		}
		break;

	case STMF_ACK_LPORT_ONLINE_COMPLETE:
		SRPT_DPRINTF_L2("stp_ctl, LPORT_ONLINE_COMPLETE ACK from"
		    " STMF");
		mutex_enter(&tgt->tp_lock);
		if (tgt->tp_state == SRPT_TGT_STATE_ONLINING) {
			SRPT_DPRINTF_L2("stp_ctl, LPORT is ONLINE");
			tgt->tp_state = SRPT_TGT_STATE_ONLINE;
		} else {
			SRPT_DPRINTF_L2("stp_ctl, LPORT not on-lining");
		}
		mutex_exit(&tgt->tp_lock);
		break;

	case STMF_ACK_LPORT_OFFLINE_COMPLETE:
		SRPT_DPRINTF_L2("stp_ctl, LPORT_OFFLINE_COMPLETE ACK from"
		    " STMF");
		mutex_enter(&tgt->tp_lock);
		if (tgt->tp_state == SRPT_TGT_STATE_OFFLINING) {
			SRPT_DPRINTF_L2("stp_ctl, LPORT is OFFLINE");
			tgt->tp_state = SRPT_TGT_STATE_OFFLINE;
			cv_broadcast(&tgt->tp_offline_complete);
		} else {
			SRPT_DPRINTF_L2("stp_ctl, LPORT not off-lining");
		}
		mutex_exit(&tgt->tp_lock);
		break;

	default:
		SRPT_DPRINTF_L2("stp_ctl, cmd (%d) not handled",
		    cmd);
		break;
	}
}

/*
 * srpt_stp_info() - STMF call-back
 */
/* ARGSUSED */
static stmf_status_t
srpt_stp_info(uint32_t cmd, struct stmf_local_port *lport,
	void *arg, uint8_t *buf, uint32_t *bufsizep)
{
	SRPT_DPRINTF_L3("stp_info, invoked");
	return (STMF_SUCCESS);
}

/*
 * srpt_stp_event_handler() - STMF call-back
 */
/* ARGSUSED */
static void
srpt_stp_event_handler(struct stmf_local_port *lport, int eventid,
	void *arg, uint32_t flags)
{
	SRPT_DPRINTF_L3("stp_event_handler, invoked");
}

/*
 * srpt_stp_alloc_scsi_devid_desc()
 *
 * Allocate and initialize a SCSI device ID descriptor for
 * the SRP protocol.  Names are eui.GUID format.
 *
 * Both extension and guid are passed in host order.
 */
static scsi_devid_desc_t *
srpt_stp_alloc_scsi_devid_desc(uint64_t guid)
{
	scsi_devid_desc_t	*sdd;

	sdd = kmem_zalloc(sizeof (*sdd) + SRPT_EUI_ID_LEN + 1, KM_SLEEP);
	sdd->protocol_id = PROTOCOL_SRP;
	sdd->piv = 1;
	sdd->code_set = CODE_SET_ASCII;
	sdd->association = ID_IS_TARGET_PORT;
	sdd->ident_length = SRPT_EUI_ID_LEN;
	(void) sprintf((char *)sdd->ident, "eui.%016llX", (u_longlong_t)guid);
	return (sdd);
}

/*
 * srpt_stp_free_scsi_devid_desc()
 *
 * Free a SRPT SCSI device ID descriptor previously allocated via
 * srpt_stp_alloc_scsi_devid_desc().
 */
static void
srpt_stp_free_scsi_devid_desc(scsi_devid_desc_t *sdd)
{
	kmem_free(sdd, sizeof (*sdd) + SRPT_EUI_ID_LEN + 1);
}

/*
 * srpt_stp_alloc_session()
 */
srpt_session_t *
srpt_stp_alloc_session(srpt_target_port_t *tgt,
	uint8_t *i_id, uint8_t *t_id, uint8_t port,
	char *local_gid, char *remote_gid)
{
	stmf_status_t		status;
	srpt_session_t		*ss;
	stmf_scsi_session_t	*stmf_ss;
	uint64_t		i_guid;
	scsi_srp_transport_id_t *srptpd;

	ASSERT(tgt != NULL);
	SRPT_DPRINTF_L3("stp_alloc_session, invoked");

	mutex_enter(&tgt->tp_sess_list_lock);

	i_guid = BE_IN64(&i_id[8]);

	stmf_ss = stmf_alloc(STMF_STRUCT_SCSI_SESSION,
	    sizeof (srpt_session_t), 0);
	if (stmf_ss == NULL) {
		SRPT_DPRINTF_L2("stp_alloc_session, stmf_alloc"
		    " returned NULL");
		mutex_exit(&tgt->tp_sess_list_lock);
		return (NULL);
	}
	ss = stmf_ss->ss_port_private;
	ASSERT(ss != NULL);

	rw_init(&ss->ss_rwlock, NULL, RW_DRIVER, NULL);
	list_create(&ss->ss_task_list, sizeof (srpt_iu_t),
	    offsetof(srpt_iu_t, iu_ss_task_node));

	stmf_ss->ss_rport_id = srpt_stp_alloc_scsi_devid_desc(i_guid);
	/* Setup remote port transport id */
	stmf_ss->ss_rport = stmf_remote_port_alloc(
	    sizeof (scsi_srp_transport_id_t));
	stmf_ss->ss_rport->rport_tptid->protocol_id = PROTOCOL_SRP;
	stmf_ss->ss_rport->rport_tptid->format_code = 0;
	srptpd = (scsi_srp_transport_id_t *)stmf_ss->ss_rport->rport_tptid;
	bcopy(i_id, srptpd->srp_name, SRP_PORT_ID_LEN);

	stmf_ss->ss_lport    = tgt->tp_lport;

	ss->ss_ss	= stmf_ss;
	ss->ss_hw_port	= port;
	ss->ss_tgt	= tgt;
	bcopy(i_id, ss->ss_i_id, SRP_PORT_ID_LEN);
	bcopy(t_id, ss->ss_t_id, SRP_PORT_ID_LEN);

	/*
	 * Set the alias to include the initiator extension, this will enable
	 * the administrator to identify multiple unique sessions originating
	 * from the same initiator.
	 */
	(void) strlcpy(ss->ss_i_gid, remote_gid, SRPT_ALIAS_LEN);
	(void) strlcpy(ss->ss_t_gid, local_gid, SRPT_ALIAS_LEN);
	EUI_STR(ss->ss_i_name, BE_IN64(&ss->ss_i_id[8]));
	EUI_STR(ss->ss_t_name, BE_IN64(&ss->ss_t_id[0]));
	ALIAS_STR(ss->ss_i_alias, BE_IN64(&ss->ss_i_id[0]),
	    BE_IN64(&ss->ss_i_id[8]));
	ALIAS_STR(ss->ss_t_alias, BE_IN64(&ss->ss_t_id[0]),
	    BE_IN64(&ss->ss_t_id[8]));
	stmf_ss->ss_rport_alias = ss->ss_i_alias;

	status = stmf_register_scsi_session(tgt->tp_lport, stmf_ss);
	if (status != STMF_SUCCESS) {
		SRPT_DPRINTF_L1("stp_alloc_session, STMF register session"
		    " err(0x%llx)", (u_longlong_t)status);
		list_destroy(&ss->ss_task_list);
		rw_destroy(&ss->ss_rwlock);
		srpt_stp_free_scsi_devid_desc(stmf_ss->ss_rport_id);
		stmf_remote_port_free(stmf_ss->ss_rport);
		stmf_free(stmf_ss);
		mutex_exit(&tgt->tp_sess_list_lock);
		return (NULL);
	}

	list_insert_tail(&tgt->tp_sess_list, ss);
	mutex_exit(&tgt->tp_sess_list_lock);
	return (ss);
}

/*
 * srpt_stp_free_session()
 */
void
srpt_stp_free_session(srpt_session_t *session)
{
	stmf_scsi_session_t	*stmf_ss;
	srpt_target_port_t	*tgt;

	ASSERT(session != NULL);

	tgt = session->ss_tgt;

	ASSERT(tgt != NULL);

	SRPT_DPRINTF_L3("stp_free_session, invoked");

	mutex_enter(&tgt->tp_sess_list_lock);

	stmf_ss = session->ss_ss;

	list_destroy(&session->ss_task_list);
	rw_destroy(&session->ss_rwlock);

	stmf_deregister_scsi_session(tgt->tp_lport, stmf_ss);
	srpt_stp_free_scsi_devid_desc(stmf_ss->ss_rport_id);
	stmf_remote_port_free(stmf_ss->ss_rport);
	list_remove(&tgt->tp_sess_list, session);
	cv_signal(&tgt->tp_sess_complete);
	mutex_exit(&tgt->tp_sess_list_lock);
	stmf_free(stmf_ss);
}

/*
 * srpt_stp_login() - SRP SCSI Target port login
 */
srpt_channel_t *
srpt_stp_login(srpt_target_port_t *tgt, srp_login_req_t *login,
	srp_login_rsp_t *login_rsp, srp_login_rej_t *login_rej,
	uint8_t login_port, char *local_gid, char *remote_gid)
{
	uint32_t	reason;
	uint32_t	req_it_ui_len;
	uint8_t		rsp_flags;
	srpt_ioc_t	*ioc;
	srpt_channel_t	*ch = NULL;
	srpt_channel_t	*next_ch = NULL;
	srpt_session_t	*session = NULL;
	srpt_session_t	sess;

	ASSERT(tgt != NULL);
	ASSERT(login != NULL);
	ASSERT(login_rsp != NULL);
	ASSERT(login_rej != NULL);

	/* Store the string representation of connection info */
	/* for Dtrace probes */
	bzero(&sess, sizeof (srpt_session_t));
	(void) strlcpy(sess.ss_i_gid, remote_gid, SRPT_ALIAS_LEN);
	(void) strlcpy(sess.ss_t_gid, local_gid, SRPT_ALIAS_LEN);
	EUI_STR(sess.ss_i_name,
	    BE_IN64(&login->lreq_initiator_port_id[8]));
	EUI_STR(sess.ss_t_name,
	    BE_IN64(&login->lreq_target_port_id[0]));
	ALIAS_STR(sess.ss_i_alias,
	    BE_IN64(&login->lreq_initiator_port_id[0]),
	    BE_IN64(&login->lreq_initiator_port_id[8]));
	ALIAS_STR(sess.ss_t_alias,
	    BE_IN64(&login->lreq_target_port_id[0]),
	    BE_IN64(&login->lreq_target_port_id[8]));

	DTRACE_SRP_2(login__command, srpt_session_t, &sess,
	    srp_login_req_t, login);

	/*
	 * The target lock taken here serializes logins to this target
	 * and prevents an STMF target port from starting a control
	 * operation to transition the target state while a login is
	 * being processed.
	 */
	bzero(login_rsp, sizeof (srp_login_rsp_t));
	bzero(login_rej, sizeof (srp_login_rej_t));
	mutex_enter(&tgt->tp_lock);
	ioc = tgt->tp_ioc;
	if (ioc == NULL) {
		SRPT_DPRINTF_L1("stp_login, NULL I/O Controller");
		reason = SRP_LOGIN_REJ_UNABLE_TO_ASSOCIATE_I_T_NEXUS;
		goto reject_login;
	}

	/*
	 * Validate that the SRP Target ID in the login request specifies
	 * this I/O Controller SCSI Target Port.
	 */
	if (memcmp(login->lreq_target_port_id, tgt->tp_srp_port_id,
	    SRP_PORT_ID_LEN) != 0) {
		SRPT_DPRINTF_L2("stp_login, SRP CM SVC target ID mismatch."
		    " Incoming TgtID 0x%016llx:0x%016llx",
		    (u_longlong_t)BE_IN64(&login->lreq_target_port_id[0]),
		    (u_longlong_t)BE_IN64(&login->lreq_target_port_id[8]));

		reason = SRP_LOGIN_REJ_UNABLE_TO_ASSOCIATE_I_T_NEXUS;
		goto reject_login;
	}

	if (tgt->tp_state != SRPT_TGT_STATE_ONLINE) {
		SRPT_DPRINTF_L2("stp_login, SRP Login target not on-line");
		reason = SRP_LOGIN_REJ_UNABLE_TO_ASSOCIATE_I_T_NEXUS;
		goto reject_login;
	}

	/*
	 * Initiator requested IU size must be as large as the specification
	 * minimum and no greater than what we chose to support.
	 */
	req_it_ui_len = b2h32(login->lreq_req_it_iu_len);
	SRPT_DPRINTF_L2("stp_login, requested iu size = %d", req_it_ui_len);
	if (req_it_ui_len > srpt_iu_size) {
		SRPT_DPRINTF_L2("stp_login, SRP Login IU size (%d) too large",
		    req_it_ui_len);
		reason = SRP_LOGIN_REJ_REQ_IT_IU_LENGTH_TOO_LARGE;
		goto reject_login;
	}
	if (req_it_ui_len < SRP_MIN_IU_SIZE) {
		SRPT_DPRINTF_L2("stp_login, SRP Login IU size (%d) too small",
		    req_it_ui_len);
		reason = SRP_LOGIN_REJ_NO_REASON;
		goto reject_login;
	}

	SRPT_DPRINTF_L2("stp_login, login req InitID 0x%016llx:0x%016llx",
	    (u_longlong_t)BE_IN64(&login->lreq_initiator_port_id[0]),
	    (u_longlong_t)BE_IN64(&login->lreq_initiator_port_id[8]));
	SRPT_DPRINTF_L2("stp_login, login req TgtID 0x%016llx:0x%016llx",
	    (u_longlong_t)BE_IN64(&login->lreq_target_port_id[0]),
	    (u_longlong_t)BE_IN64(&login->lreq_target_port_id[8]));

	/*
	 * Processing is based on either single channel or multi-channel
	 * operation.  In single channel, all current logins for this
	 * same I_T_Nexus should be logged out.  In multi-channel
	 * mode we would add an additional channel to an existing
	 * I_T_Nexus if one currently exists (i.e. reference the
	 * same SCSI session).
	 */
	rsp_flags = SRP_MULTI_CH_RESULT_NO_EXISTING;

	switch (login->lreq_req_flags & SRP_LOGIN_MULTI_CH_MASK) {

	case SRP_LOGIN_MULTI_CH_SINGLE:
		/*
		 * Only a single channel may be associated with a I_T_Nexus.
		 * Disconnect any channel with the same SRP Initiator and
		 * SRP target IDs.
		 */
		mutex_enter(&tgt->tp_ch_list_lock);
		ch = list_head(&tgt->tp_ch_list);
		while (ch != NULL) {
			SRPT_DPRINTF_L3("stp_login, compare session,"
			    " ch_state(%d)", ch->ch_state);
			next_ch = list_next(&tgt->tp_ch_list, ch);

			if (ch->ch_state != SRPT_CHANNEL_CONNECTING &&
			    ch->ch_state != SRPT_CHANNEL_CONNECTED) {
				SRPT_DPRINTF_L3("stp_login, compare session,"
				    " channel not active");
				ch = next_ch;
				continue;
			}

			ASSERT(ch->ch_session != NULL);
			SRPT_DPRINTF_L3("stp_login, compare session"
			    " I_ID 0x%016llx:0x%016llx",
			    (u_longlong_t)b2h64(*((uint64_t *)(void *)
			    &ch->ch_session->ss_i_id[0])),
			    (u_longlong_t)b2h64(*((uint64_t *)(void *)
			    &ch->ch_session->ss_i_id[8])));
			SRPT_DPRINTF_L3("stp_login, compare session"
			    " T_ID 0x%016llx:0x%016llx",
			    (u_longlong_t)b2h64(*((uint64_t *)(void *)
			    &ch->ch_session->ss_t_id[0])),
			    (u_longlong_t)b2h64(*((uint64_t *)(void *)
			    &ch->ch_session->ss_t_id[8])));
			if ((bcmp(login->lreq_initiator_port_id,
			    ch->ch_session->ss_i_id,
			    SRP_PORT_ID_LEN) == 0) &&
			    (bcmp(login->lreq_target_port_id,
			    ch->ch_session->ss_t_id,
			    SRP_PORT_ID_LEN) == 0)) {
				/*
				 * if a session is in the process of connecting,
				 * reject subsequent equivalent requests.
				 */
				if (ch->ch_state == SRPT_CHANNEL_CONNECTING) {
					reason = SRP_LOGIN_REJ_INIT_CH_LIMIT;
					mutex_exit(&tgt->tp_ch_list_lock);
					goto reject_login;
				}

				SRPT_DPRINTF_L2("stp_login, terminate"
				    " existing login");
				rsp_flags =
				    SRP_MULTI_CH_RESULT_TERM_EXISTING;
				srpt_ch_disconnect(ch);
			}

			ch = next_ch;
		}
		mutex_exit(&tgt->tp_ch_list_lock);

		/* Create the new session for this SRP login */
		session = srpt_stp_alloc_session(tgt,
		    login->lreq_initiator_port_id,
		    login->lreq_target_port_id, login_port,
		    local_gid, remote_gid);
		if (session == NULL) {
			SRPT_DPRINTF_L2("stp_login, session allocation"
			    " failed");
			reason = SRP_LOGIN_REJ_UNABLE_TO_ASSOCIATE_I_T_NEXUS;
			goto reject_login;
		}
		break;

	case SRP_LOGIN_MULTI_CH_MULTIPLE:
		SRPT_DPRINTF_L2("stp_login, multichannel not supported yet");
		reason = SRP_LOGIN_REJ_MULTI_CH_NOT_SUPPORTED;
		goto reject_login;
		/* break via goto */

	default:
		SRPT_DPRINTF_L2("stp_login, invalid multichannel field (%d)",
		    login->lreq_req_flags & SRP_LOGIN_MULTI_CH_MASK);
		reason = SRP_LOGIN_REJ_NO_REASON;
		goto reject_login;
		/* break via goto */
	}

	/*
	 * Create new RDMA channel for this SRP login request.
	 * The channel is returned with a single reference which
	 * represents the reference held by the CM.
	 */
	ch = srpt_ch_alloc(tgt, login_port);
	if (ch == NULL) {
		SRPT_DPRINTF_L2("stp_login, unable to alloc RDMA channel");
		reason = SRP_LOGIN_REJ_INSUFFICIENT_CH_RESOURCES;
		srpt_stp_free_session(session);
		goto reject_login;
	}
	ch->ch_session = session;
	ch->ch_ti_iu_len = b2h32(login->lreq_req_it_iu_len);

	/*
	 * Add another reference to the channel which represents
	 * a reference placed by the target port and add it to
	 * the store of channels logged in for this target port.
	 */
	srpt_ch_add_ref(ch);
	mutex_enter(&tgt->tp_ch_list_lock);
	list_insert_tail(&tgt->tp_ch_list, ch);
	mutex_exit(&tgt->tp_ch_list_lock);

	srpt_format_login_rsp(login, login_rsp, rsp_flags);
	mutex_exit(&tgt->tp_lock);
	SRPT_DPRINTF_L2("stp_login, login successful");

	DTRACE_SRP_3(login__response, srpt_session_t, &sess,
	    srp_login_rsp_t, login_rsp, srp_login_rej_t, login_rej)

	return (ch);

reject_login:
	srpt_format_login_rej(login, login_rej, reason);
	mutex_exit(&tgt->tp_lock);

	DTRACE_SRP_3(login__response, srpt_session_t, &sess,
	    srp_login_rsp_t, login_rsp, srp_login_rej_t, login_rej);

	return (NULL);
}

/*
 * srpt_stp_logout() - SRP logout
 *
 * Logout is not normally initiated in-band, but is so, just
 * initiate a disconnect.
 */
void
srpt_stp_logout(srpt_channel_t *ch)
{
	DTRACE_SRP_1(logout__command, srpt_channel_t, ch);
	SRPT_DPRINTF_L2("stp_logout, invoked for ch (%p)", (void *)ch);
	srpt_ch_disconnect(ch);
}

/*
 * srpt_format_login_rej() - Format login reject IU
 */
static void
srpt_format_login_rej(srp_login_req_t *req, srp_login_rej_t *rej,
	uint32_t reason)
{
	rej->lrej_type   = SRP_IU_LOGIN_REJ;
	rej->lrej_reason = h2b32(reason);
	rej->lrej_tag    = req->lreq_tag;
	rej->lrej_sup_buf_format =
	    h2b16(SRP_DIRECT_BUFR_DESC | SRP_INDIRECT_BUFR_DESC);
}

/*
 * srpt_format_login_rsp() - Format login response IU
 */
static void
srpt_format_login_rsp(srp_login_req_t *req, srp_login_rsp_t *rsp,
	uint8_t flags)
{
	rsp->lrsp_type   = SRP_IU_LOGIN_RSP;
	rsp->lrsp_req_limit_delta = h2b32((uint32_t)srpt_send_msg_depth);
	rsp->lrsp_tag    = req->lreq_tag;

	rsp->lrsp_max_it_iu_len = req->lreq_req_it_iu_len;
	/* by def. > min T_IU_LEN */
	rsp->lrsp_max_ti_iu_len = req->lreq_req_it_iu_len;

	rsp->lrsp_sup_buf_format =
	    h2b16(SRP_DIRECT_BUFR_DESC | SRP_INDIRECT_BUFR_DESC);
	rsp->lrsp_rsp_flags = flags;
}

/*
 * srpt_stp_add_task()
 */
void
srpt_stp_add_task(srpt_session_t *session, srpt_iu_t *iu)
{
	rw_enter(&session->ss_rwlock, RW_WRITER);
	list_insert_tail(&session->ss_task_list, iu);
	rw_exit(&session->ss_rwlock);
}

/*
 * srpt_stp_remove_task()
 */
void
srpt_stp_remove_task(srpt_session_t *session, srpt_iu_t *iu)
{
	rw_enter(&session->ss_rwlock, RW_WRITER);

	ASSERT(!list_is_empty(&session->ss_task_list));

	list_remove(&session->ss_task_list, iu);
	rw_exit(&session->ss_rwlock);
}
