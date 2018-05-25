/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * This file sets up the interrupts with the system and also processes
 * interrupts from the hardware.
 */

/* ---- Driver specific header ---- */
#include <smartpqi.h>

/* ---- Forward declarations of private methods ---- */
static int add_intrs(pqi_state_t *s, int type);
static uint_t intr_handler(caddr_t arg1, caddr_t arg2);
static void sync_error(pqi_state_t *s, pqi_io_request_t *io,
    pqi_io_response_t *rsp);
static void process_raid_io_error(pqi_io_request_t *io);
static void process_aio_io_error(pqi_io_request_t *io);
static void disable_aio_path(pqi_io_request_t *io);

/*
 * smartpqi_register_intrs -- Figure out which type of interrupts and register
 *			      them with the framework.
 */
int
smartpqi_register_intrs(pqi_state_t *s)
{
	int	intr_types;

	/* ---- Get supported interrupt types ---- */
	if (ddi_intr_get_supported_types(s->s_dip, &intr_types) !=
	    DDI_SUCCESS) {
		dev_err(s->s_dip, CE_NOTE,
		    "failed to get supported intr types");
		return (FALSE);
	}

	if (intr_types & DDI_INTR_TYPE_MSIX) {
		if (add_intrs(s, DDI_INTR_TYPE_MSIX) == TRUE) {
			s->s_intr_type = DDI_INTR_TYPE_MSIX;
			return (TRUE);
		}
	} else if (intr_types & DDI_INTR_TYPE_MSI) {
		if (add_intrs(s, DDI_INTR_TYPE_MSI) == TRUE) {
			s->s_intr_type = DDI_INTR_TYPE_MSI;
			return (TRUE);
		}
	} else if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (add_intrs(s, DDI_INTR_TYPE_FIXED) == TRUE) {
			s->s_intr_type = DDI_INTR_TYPE_FIXED;
			return (TRUE);
		}
	} else {
		/* ---- Warning since it's a DDI framework error ---- */
		dev_err(s->s_dip, CE_WARN,
		    "ddi_intr_get_supported_types returned bogus type of 0x%x",
		    intr_types);
	}

	return (FALSE);
}

/*
 * smartqpi_unregister_intrs -- Disable and remove interrupt handlers
 */
void
smartpqi_unregister_intrs(pqi_state_t *s)
{
	int	i;

	/* --- First disable the interrupts ---- */
	if (s->s_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(s->s_itable, s->s_intr_cnt);
	} else {
		for (i = 0; i < s->s_intr_cnt; i++) {
			(void) ddi_intr_disable(s->s_itable[i]);
		}
	}

	/* ---- Next remove the interrupt handlers ---- */
	for (i = 0; i < s->s_intr_cnt; i++) {
		(void) ddi_intr_remove_handler(s->s_itable[i]);
		(void) ddi_intr_free(s->s_itable[i]);
	}

	kmem_free(s->s_itable, s->s_intr_size);
	/* ---- Just in case ---- */
	s->s_itable = NULL;
	s->s_intr_size = 0;
}

void
pqi_process_io_intr(pqi_state_t *s, pqi_queue_group_t *qg)
{
	pqi_index_t		oq_pi;
	pqi_index_t		oq_ci;
	pqi_io_request_t	*io;
	pqi_io_response_t	*rsp;
	uint16_t		rqst_ix;
	uint8_t			rqst_gen;
	int			response_cnt = 0;
	int			qnotify;

	oq_ci = qg->oq_ci_copy;
	atomic_inc_32(&s->s_intr_count);

	mutex_enter(&s->s_intr_mutex);
	for (;;) {
		(void) ddi_dma_sync(s->s_queue_dma->handle,
		    (uintptr_t)qg->oq_pi -
		    (uintptr_t)s->s_queue_dma->alloc_memory,
		    sizeof (oq_pi), DDI_DMA_SYNC_FORCPU);

		oq_pi = *qg->oq_pi;
		if (oq_pi == oq_ci)
			break;

		rsp = (pqi_io_response_t *)(qg->oq_element_array +
		    (oq_ci * PQI_OPERATIONAL_OQ_ELEMENT_LENGTH));
		(void) ddi_dma_sync(s->s_queue_dma->handle,
		    (uintptr_t)rsp - (uintptr_t)s->s_queue_dma->alloc_memory,
		    sizeof (*rsp), DDI_DMA_SYNC_FORCPU);
		rqst_ix = PQI_REQID_INDEX(rsp->request_id);
		ASSERT(rqst_ix < s->s_max_io_slots);
		rqst_gen = PQI_REQID_GEN(rsp->request_id);
		io = &s->s_io_rqst_pool[rqst_ix];

		if (!pqi_service_io(io, rqst_gen)) {
			/*
			 * Generation does not match, this response must be
			 * a stale response for a previous (timed out) i/o req.
			 */
			goto skipto;
		}
		ASSERT(io->io_refcount == 1);

		if (io->io_cmd != NULL) {
			pqi_cmd_t	*cmd = io->io_cmd;

			if ((cmd->pc_flags & PQI_FLAG_TIMED_OUT) != 0)
				goto skipto;
		}

		io->io_iu_type = rsp->header.iu_type;
		switch (rsp->header.iu_type) {
		case PQI_RESPONSE_IU_RAID_PATH_IO_SUCCESS:
		case PQI_RESPONSE_IU_AIO_PATH_IO_SUCCESS:
		case PQI_RESPONSE_IU_GENERAL_MANAGEMENT:
		case PQI_RESPONSE_IU_TASK_MANAGEMENT:
			io->io_status = PQI_DATA_IN_OUT_GOOD;
			break;
		case PQI_RESPONSE_IU_RAID_PATH_IO_ERROR:
			io->io_status = PQI_DATA_IN_OUT_ERROR;
			sync_error(s, io, rsp);
			process_raid_io_error(io);
			break;
		case PQI_RESPONSE_IU_AIO_PATH_IO_ERROR:
			io->io_status = PQI_DATA_IN_OUT_ERROR;
			sync_error(s, io, rsp);
			process_aio_io_error(io);
			break;
		case PQI_RESPONSE_IU_AIO_PATH_DISABLED:
			io->io_status = PQI_DATA_IN_OUT_PROTOCOL_ERROR;
			disable_aio_path(io);
			break;

		default:
			ASSERT(0);
			break;
		}
		io->io_cb(io, io->io_context);
skipto:
		response_cnt++;
		oq_ci = (oq_ci + 1) % s->s_num_elements_per_oq;
	}

	if (response_cnt) {
		qg->cmplt_count += response_cnt;
		qg->oq_ci_copy = oq_ci;
		ddi_put32(s->s_datap, qg->oq_ci, oq_ci);
	}
	mutex_exit(&s->s_intr_mutex);

	mutex_enter(&s->s_mutex);
	qnotify = HBA_QUIESCED_PENDING(s);
	mutex_exit(&s->s_mutex);

	if (qnotify)
		pqi_quiesced_notify(s);

}

static int
add_intrs(pqi_state_t *s, int type)
{
	dev_info_t	*dip	= s->s_dip;
	int		avail;
	int		actual;
	int		count	= 0;
	int		i;
	int		ret;

	/* ---- Get number of interrupts ---- */
	ret = ddi_intr_get_nintrs(dip, type, &count);
	if (ret != DDI_SUCCESS || count <= 0) {
		dev_err(s->s_dip, CE_NOTE, "ddi_intr_get_nintrs failed, "
		    "ret=%d, count=%d", ret, count);
		return (FALSE);
	}

	/* ---- Get number of available interrupts ---- */
	ret = ddi_intr_get_navail(dip, type, &avail);
	if (ret != DDI_SUCCESS || avail == 0) {
		dev_err(s->s_dip, CE_NOTE, "ddi_intr_get_navail failed, "
		    "ret=%d, avail=%d", ret, avail);
		return (FALSE);
	}

	if (type != DDI_INTR_TYPE_FIXED)
		count = 1;

	s->s_intr_size = count * sizeof (ddi_intr_handle_t);
	s->s_itable = kmem_zalloc(s->s_intr_size, KM_SLEEP);
	ret = ddi_intr_alloc(dip, s->s_itable, type, 0, count, &actual,
	    DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS || actual == 0) {
		dev_err(s->s_dip, CE_NOTE, "ddi_intr_alloc failed, ret=%d",
		    ret);
		return (FALSE);
	}

	/* ---- Use count return or abort? Make note of at least---- */
	if (actual < count) {
		dev_err(s->s_dip, CE_NOTE,
		    "interrupts: requested=%d, received=%d",
		    count, actual);
	}
	s->s_intr_cnt = actual;

	/* ---- Get priority for first intr, assume rest are the same ---- */
	if ((ret = ddi_intr_get_pri(s->s_itable[0], &s->s_intr_pri)) !=
	    DDI_SUCCESS) {
		dev_err(s->s_dip, CE_NOTE, "ddi_intr_get_pri failed, ret=%d",
		    ret);
		goto failure;
	}

	/* ---- Test for high level mutex ---- */
	if (s->s_intr_pri >= ddi_intr_get_hilevel_pri()) {
		dev_err(s->s_dip, CE_NOTE, "Hi level interrupts not supported");
		goto failure;
	}

	/* ---- Install interrupt handler ---- */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(s->s_itable[i], intr_handler,
		    (caddr_t)s, (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			dev_err(s->s_dip, CE_NOTE,
			    "ddi_intr_add_handler failed, index=%d, ret=%d",
			    i, ret);
			goto failure;
		}
	}

	if ((ret = ddi_intr_get_cap(s->s_itable[0], &s->s_intr_cap))
	    != DDI_SUCCESS) {
		dev_err(s->s_dip, CE_NOTE, "ddi_intr_get_cap failed, ret=%d",
		    ret);
		goto failure;
	}

	/* ---- Enable interrupts ---- */
	if (s->s_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(s->s_itable, s->s_intr_cnt);
	} else {
		/* --- Enable interrupts for either MSI or FIXED ---- */
		for (i = 0; i < actual; i++)
			(void) ddi_intr_enable(s->s_itable[i]);
	}

	return (TRUE);

failure:
	/* ---- Free allocated interrupts pointers ---- */
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(s->s_itable[i]);
	kmem_free(s->s_itable, s->s_intr_size);
	s->s_itable = NULL;
	s->s_intr_size = 0;
	return (FALSE);
}

static void
disable_aio_path(pqi_io_request_t *io)
{
	pqi_device_t	*devp;

	devp = io->io_cmd->pc_device;
	devp->pd_aio_enabled = 0;
}

static void
process_raid_io_error(pqi_io_request_t *io)
{
	pqi_raid_error_info_t	ei;
	pqi_cmd_t		*cmd;
	int			sense_len;
	int			statusbuf_len;
	int			sense_len_to_copy;
	struct scsi_arq_status	*arq;
	struct scsi_pkt		*pkt;

	if ((ei = io->io_error_info) != NULL) {
		io->io_status = ei->data_out_result;
		if ((cmd = io->io_cmd) == NULL || cmd->pc_pkt == NULL)
			return;

		pkt = cmd->pc_pkt;
		pkt->pkt_resid -= ei->data_out_transferred;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		arq = (struct scsi_arq_status *)pkt->pkt_scbp;
		*((uchar_t *)&arq->sts_status) = ei->status;
		*((uchar_t *)&arq->sts_rqpkt_status) = STATUS_GOOD;
		arq->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS |
		    STATE_ARQ_DONE;

		sense_len = ei->sense_data_length;
		if (sense_len == 0)
			sense_len = ei->response_data_length;

		if (sense_len == 0) {
			/* ---- auto request sense failed ---- */
			arq->sts_rqpkt_status.sts_chk = 1;
			arq->sts_rqpkt_resid = cmd->pc_statuslen;
			return;
		} else if (sense_len < cmd->pc_statuslen) {
			/* ---- auto request sense short ---- */
			arq->sts_rqpkt_resid = cmd->pc_statuslen -
			    sense_len;
		} else {
			/* ---- auto request sense complete ---- */
			arq->sts_rqpkt_resid = 0;
		}
		arq->sts_rqpkt_statistics = 0;
		pkt->pkt_state |= STATE_ARQ_DONE;
		if (cmd->pc_statuslen > PQI_ARQ_STATUS_NOSENSE_LEN) {
			statusbuf_len = cmd->pc_statuslen -
			    PQI_ARQ_STATUS_NOSENSE_LEN;
		} else {
			statusbuf_len = 0;
		}

		if (sense_len > sizeof (ei->data))
			sense_len = sizeof (ei->data);
		sense_len_to_copy = min(sense_len, statusbuf_len);

		if (sense_len_to_copy) {
			(void) memcpy(&arq->sts_sensedata, ei->data,
			    sense_len_to_copy);
		}
	} else {
		/*
		 * sync_error is called before this and sets io_error_info
		 * which means the value must be non-zero
		 */
		ASSERT(0);
	}
}

static void
process_aio_io_error(pqi_io_request_t *io __unused)
{
}

static void
sync_error(pqi_state_t *s, pqi_io_request_t *io, pqi_io_response_t *rsp)
{
	(void) ddi_dma_sync(s->s_error_dma->handle,
	    rsp->error_index * PQI_ERROR_BUFFER_ELEMENT_LENGTH,
	    PQI_ERROR_BUFFER_ELEMENT_LENGTH, DDI_DMA_SYNC_FORCPU);

	io->io_error_info = s->s_error_dma->alloc_memory +
	    (rsp->error_index * PQI_ERROR_BUFFER_ELEMENT_LENGTH);
}

static void
process_event_intr(pqi_state_t *s)
{
	pqi_event_queue_t	*q = &s->s_event_queue;
	pqi_event_response_t	*rsp;
	int			idx;
	int			num_events	= 0;
	pqi_event_t		*e;
	pqi_index_t		oq_ci;
	pqi_index_t		oq_pi;

	oq_ci = q->oq_ci_copy;

	mutex_enter(&s->s_intr_mutex);
	for (;;) {
		(void) ddi_dma_sync(s->s_queue_dma->handle,
		    (uintptr_t)q->oq_pi -
		    (uintptr_t)s->s_queue_dma->alloc_memory,
		    sizeof (oq_pi), DDI_DMA_SYNC_FORCPU);
		oq_pi = *q->oq_pi;

		if (oq_pi == oq_ci)
			break;

		num_events++;
		(void) ddi_dma_sync(s->s_queue_dma->handle,
		    (uintptr_t)q->oq_element_array +
		    (oq_ci * PQI_EVENT_OQ_ELEMENT_LENGTH) -
		    (uintptr_t)s->s_queue_dma->alloc_memory,
		    sizeof (*rsp),
		    DDI_DMA_SYNC_FORCPU);
		rsp = (pqi_event_response_t *)((uintptr_t)q->oq_element_array +
		    (oq_ci * PQI_EVENT_OQ_ELEMENT_LENGTH));
		idx = pqi_map_event(rsp->event_type);

		if (idx != -1 && rsp->request_acknowlege) {
			e = &s->s_events[idx];
			e->ev_pending = B_TRUE;
			e->ev_type = rsp->event_type;
			e->ev_id = rsp->event_id;
			e->ev_additional = rsp->additional_event_id;
		}
		oq_ci = (oq_ci + 1) % PQI_NUM_EVENT_QUEUE_ELEMENTS;
	}

	if (num_events != 0) {
		q->oq_ci_copy = oq_ci;
		ddi_put32(s->s_datap, q->oq_ci, oq_ci);
		(void) ddi_taskq_dispatch(s->s_events_taskq, pqi_event_worker,
		    s, 0);
	}
	mutex_exit(&s->s_intr_mutex);
}

static uint_t
intr_handler(caddr_t arg1, caddr_t arg2)
{
	pqi_state_t		*s = (pqi_state_t *)arg1;
	int			queue_group_idx = (int)(intptr_t)arg2;
	pqi_queue_group_t	*qg;

	if (!s->s_intr_ready)
		return (DDI_INTR_CLAIMED);

	qg = &s->s_queue_groups[queue_group_idx];
	pqi_process_io_intr(s, qg);
	if (queue_group_idx == s->s_event_queue.int_msg_num)
		process_event_intr(s);

	pqi_start_io(s, qg, RAID_PATH, NULL);
	pqi_start_io(s, qg, AIO_PATH, NULL);

	return (DDI_INTR_CLAIMED);
}
