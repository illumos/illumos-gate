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
 * This file contains code necessary to send SCSI commands to HBA.
 */
#include <smartpqi.h>

/*
 * []------------------------------------------------------------------[]
 * | Forward declarations for support/utility functions			|
 * []------------------------------------------------------------------[]
 */
static void aio_io_complete(pqi_io_request_t *io, void *context);
static void raid_io_complete(pqi_io_request_t *io, void *context);
static void build_aio_sg_list(pqi_state_t *s,
	pqi_aio_path_request_t *rqst, pqi_cmd_t *cmd, pqi_io_request_t *);
static void build_raid_sg_list(pqi_state_t *s,
	pqi_raid_path_request_t *rqst, pqi_cmd_t *cmd, pqi_io_request_t *);
static pqi_io_request_t *setup_aio_request(pqi_state_t *s, pqi_cmd_t *cmd);
static pqi_io_request_t *setup_raid_request(pqi_state_t *s, pqi_cmd_t *cmd);
static uint32_t read_heartbeat_counter(pqi_state_t *s);
static void take_ctlr_offline(pqi_state_t *s);
static uint32_t free_elem_count(pqi_index_t pi, pqi_index_t ci,
	uint32_t per_iq);
static void ack_event(pqi_state_t *s, pqi_event_t *e);
static boolean_t is_aio_enabled(pqi_device_t *d);
static void lun_reset_worker(void *v);
static void lun_reset_complete(pqi_io_request_t *io, void *ctx);

#define	DIV_UP(n, d) ((n + (d - 1)) / d)

/*
 * []------------------------------------------------------------------[]
 * | Main entry points in file.						|
 * []------------------------------------------------------------------[]
 */

int pqi_do_reset_lun = -1;
int pqi_do_reset_ctlr = -1;
/*
 * pqi_watchdog -- interrupt count and/or heartbeat must increase over time.
 */
void
pqi_watchdog(void *v)
{
	pqi_state_t	*s = v;
	uint32_t	hb;

	if (pqi_is_offline(s))
		return;

	hb = read_heartbeat_counter(s);
	if ((s->s_last_intr_count == s->s_intr_count) &&
	    (s->s_last_heartbeat_count == hb)) {
		dev_err(s->s_dip, CE_NOTE, "No heartbeat");
		pqi_show_dev_state(s);
		take_ctlr_offline(s);
	} else {
		if (pqi_do_reset_ctlr == s->s_instance) {
			pqi_do_reset_ctlr = -1;
			take_ctlr_offline(s);
		} else {
			s->s_last_intr_count = s->s_intr_count;
			s->s_last_heartbeat_count = hb;
			s->s_watchdog = timeout(pqi_watchdog, s,
			    drv_usectohz(WATCHDOG));
		}
	}
}

/*
 * pqi_start_io -- queues command to HBA.
 *
 * This method can be called either from the upper layer with a non-zero
 * io argument or called during an interrupt to load the outgoing queue
 * with more commands.
 */
void
pqi_start_io(pqi_state_t *s, pqi_queue_group_t *qg, pqi_path_t path,
    pqi_io_request_t *io)
{
	pqi_iu_header_t	*rqst;
	size_t		iu_len;
	size_t		copy_to_end;
	pqi_index_t	iq_pi;
	pqi_index_t	iq_ci;
	uint32_t	elem_needed;
	uint32_t	elem_to_end;
	caddr_t		next_elem;
	int		sending		= 0;

	mutex_enter(&qg->submit_lock[path]);
	if (io != NULL) {
		io->io_queue_group = qg;
		io->io_queue_path = path;
		list_insert_tail(&qg->request_list[path], io);
	}


	iq_pi = qg->iq_pi_copy[path];
	while ((io = list_remove_head(&qg->request_list[path])) != NULL) {

		/* ---- Primary cause for !active is controller failure ---- */
		if (qg->qg_active == B_FALSE) {
			pqi_cmd_t	*c = io->io_cmd;

			mutex_enter(&c->pc_device->pd_mutex);
			/*
			 * When a command is failed it will be removed from
			 * the queue group if pc_io_rqst is not NULL. Since
			 * we have already removed the command from the list
			 * would shouldn't attempt to do so a second time.
			 */
			c->pc_io_rqst = NULL;
			(void) pqi_fail_cmd(io->io_cmd, CMD_DEV_GONE,
			    STAT_TERMINATED);
			mutex_exit(&c->pc_device->pd_mutex);
			continue;
		}

		rqst = io->io_iu;
		iu_len = rqst->iu_length + PQI_REQUEST_HEADER_LENGTH;
		elem_needed = DIV_UP(iu_len, PQI_OPERATIONAL_IQ_ELEMENT_LENGTH);
		(void) ddi_dma_sync(s->s_queue_dma->handle,
		    (uintptr_t)qg->iq_ci[path] -
		    (uintptr_t)s->s_queue_dma->alloc_memory, sizeof (iq_ci),
		    DDI_DMA_SYNC_FORCPU);
		iq_ci = *qg->iq_ci[path];

		if (elem_needed > free_elem_count(iq_pi, iq_ci,
		    s->s_num_elements_per_iq)) {
			list_insert_head(&qg->request_list[path], io);
			break;
		}

		if (pqi_cmd_action(io->io_cmd, PQI_CMD_START) == PQI_CMD_FAIL)
			continue;

		io->io_pi = iq_pi;
		rqst->iu_id = qg->oq_id;
		next_elem = qg->iq_element_array[path] +
		    (iq_pi * PQI_OPERATIONAL_IQ_ELEMENT_LENGTH);
		elem_to_end = s->s_num_elements_per_iq - iq_pi;
		if (elem_needed <= elem_to_end) {
			(void) memcpy(next_elem, rqst, iu_len);
			(void) ddi_dma_sync(s->s_queue_dma->handle,
			    (uintptr_t)next_elem -
			    (uintptr_t)s->s_queue_dma->alloc_memory, iu_len,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			copy_to_end = elem_to_end *
			    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH;
			(void) memcpy(next_elem, rqst, copy_to_end);
			(void) ddi_dma_sync(s->s_queue_dma->handle,
			    (uintptr_t)next_elem -
			    (uintptr_t)s->s_queue_dma->alloc_memory,
			    copy_to_end, DDI_DMA_SYNC_FORDEV);
			(void) memcpy(qg->iq_element_array[path],
			    (caddr_t)rqst + copy_to_end,
			    iu_len - copy_to_end);
			(void) ddi_dma_sync(s->s_queue_dma->handle,
			    0, iu_len - copy_to_end, DDI_DMA_SYNC_FORDEV);
		}
		sending += elem_needed;

		iq_pi = (iq_pi + elem_needed) % s->s_num_elements_per_iq;
	}

	qg->submit_count += sending;
	if (iq_pi != qg->iq_pi_copy[path]) {
		qg->iq_pi_copy[path] = iq_pi;
		ddi_put32(s->s_datap, qg->iq_pi[path], iq_pi);
	} else {
		ASSERT0(sending);
	}
	mutex_exit(&qg->submit_lock[path]);
}

int
pqi_transport_command(pqi_state_t *s, pqi_cmd_t *cmd)
{
	pqi_device_t		*devp = cmd->pc_device;
	int			path;
	pqi_io_request_t	*io;

	if (is_aio_enabled(devp) == B_TRUE) {
		path = AIO_PATH;
		io = setup_aio_request(s, cmd);
	} else {
		path = RAID_PATH;
		io = setup_raid_request(s, cmd);
	}

	if (io == NULL)
		return (TRAN_BUSY);

	cmd->pc_io_rqst = io;
	(void) pqi_cmd_action(cmd, PQI_CMD_QUEUE);

	pqi_start_io(s, &s->s_queue_groups[PQI_DEFAULT_QUEUE_GROUP],
	    path, io);

	return (TRAN_ACCEPT);
}

void
pqi_do_rescan(void *v)
{
	pqi_state_t	*s	= v;

	ndi_devi_enter(scsi_vhci_dip);
	ndi_devi_enter(s->s_dip);
	pqi_rescan_devices(s);
	(void) pqi_config_all(s->s_dip, s);
	ndi_devi_exit(s->s_dip);
	ndi_devi_exit(scsi_vhci_dip);
}

void
pqi_event_worker(void *v)
{
	pqi_state_t	*s		= v;
	int		i;
	pqi_event_t	*e;
	boolean_t	non_heartbeat	= B_FALSE;

	if (pqi_is_offline(s))
		return;

	e = s->s_events;
	for (i = 0; i < PQI_NUM_SUPPORTED_EVENTS; i++) {
		if (e->ev_pending == B_TRUE) {
			e->ev_pending = B_FALSE;
			ack_event(s, e);
			if (pqi_map_event(PQI_EVENT_TYPE_HEARTBEAT) != i)
				non_heartbeat = B_TRUE;
		}
		e++;
	}

	if (non_heartbeat == B_TRUE)
		pqi_do_rescan(s);
}

/*
 * pqi_fail_cmd -- given a reason and stats the command is failed.
 */
pqi_cmd_action_t
pqi_fail_cmd(pqi_cmd_t *cmd, uchar_t reason, uint_t stats)
{
	struct scsi_pkt		*pkt	= CMD2PKT(cmd);

	pkt->pkt_reason = reason;
	pkt->pkt_statistics = stats;

	return (pqi_cmd_action_nolock(cmd, PQI_CMD_FAIL));
}

void
pqi_fail_drive_cmds(pqi_device_t *d, uchar_t reason)
{
	pqi_cmd_t	*c, *next_c;

	mutex_enter(&d->pd_mutex);

	c = list_head(&d->pd_cmd_list);
	while (c != NULL) {
		next_c = list_next(&d->pd_cmd_list, c);
		if (pqi_fail_cmd(c, reason, STAT_BUS_RESET) !=
		    PQI_CMD_START) {
			/*
			 * The command can't be terminated in the driver because
			 * it was already handed off to the HBA and the driver
			 * will have to wait for completion. The reason is
			 * that the HBA indicates slots are complete, not a
			 * pointer to a command. If the code were to cancel
			 * an outstanding command that slot could be reused
			 * by another command and when the completion interrupt
			 * arrives the driver would signal that a command had
			 * completed when in fact it was a prior command that
			 * had been canceled.
			 *
			 * Should the command fail to complete due to an HBA
			 * error the command will be forced through to
			 * completion during a timeout scan that occurs on
			 * another thread.
			 */
			d->pd_killed++;
		} else {
			d->pd_posted++;
		}
		c = next_c;
	}

	mutex_exit(&d->pd_mutex);
}

uint32_t
pqi_disable_intr(pqi_state_t *s)
{
	uint32_t	db;
	uint32_t	rval;

	rval = db = G32(s, sis_host_to_ctrl_doorbell);
	db &= ~(SIS_ENABLE_MSIX | SIS_ENABLE_INTX);
	S32(s, sis_host_to_ctrl_doorbell, db);
	return (rval);
}

void
pqi_enable_intr(pqi_state_t *s, uint32_t old_state)
{
	S32(s, sis_host_to_ctrl_doorbell, old_state);
}

typedef struct reset_closure {
	pqi_state_t	*rc_s;
	pqi_device_t	*rc_d;
} *reset_closure_t;

/*
 * pqi_lun_reset -- set up callback to reset the device
 *
 * Dispatch queue is used here because the call tree can come from the interrupt
 * routine. (pqi_process_io_intr -> aio_io_complete -> SCSA -> tran_reset ->
 * pqi_lun_reset). If pqi_lun_reset were to actually do the reset work it would
 * then wait for an interrupt which would never arrive since the current thread
 * would be the interrupt thread. So, start a task to reset the device and
 * wait for completion.
 */
void
pqi_lun_reset(pqi_state_t *s, pqi_device_t *d)
{
	reset_closure_t	r = kmem_alloc(sizeof (struct reset_closure), KM_SLEEP);

	r->rc_s = s;
	r->rc_d = d;
	(void) ddi_taskq_dispatch(s->s_events_taskq, lun_reset_worker, r, 0);
}

/*
 * []------------------------------------------------------------------[]
 * | Support/utility functions for main entry points			|
 * []------------------------------------------------------------------[]
 */

static uint32_t
count_drive_cmds(pqi_device_t *d)
{
	pqi_cmd_t	*c;
	uint32_t	count = 0;

	mutex_enter(&d->pd_mutex);
	c = list_head(&d->pd_cmd_list);
	while (c != NULL) {
		c = list_next(&d->pd_cmd_list, c);
		count++;
	}
	mutex_exit(&d->pd_mutex);

	return (count);
}

static uint32_t
count_oustanding_cmds(pqi_state_t *s)
{
	uint32_t	count = 0;
	pqi_device_t	*d;

	mutex_enter(&s->s_mutex);
	d = list_head(&s->s_devnodes);
	while (d != NULL) {
		count += count_drive_cmds(d);
		d = list_next(&s->s_devnodes, d);
	}
	mutex_exit(&s->s_mutex);

	return (count);
}

static void
lun_reset_worker(void *v)
{
	reset_closure_t			r = v;
	pqi_state_t			*s;
	pqi_device_t			*d;
	pqi_io_request_t		*io;
	ksema_t				sema;
	pqi_task_management_rqst_t	*rqst;
	struct pqi_cmd			cmd;

	s = r->rc_s;
	d = r->rc_d;

	pqi_fail_drive_cmds(d, CMD_RESET);
	sema_init(&sema, 0, NULL, SEMA_DRIVER, NULL);

	bzero(&cmd, sizeof (cmd));
	mutex_init(&cmd.pc_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((io = pqi_alloc_io(s)) == NULL) {
		mutex_destroy(&cmd.pc_mutex);
		kmem_free(r, sizeof (*r));
		return;
	}
	io->io_cb = lun_reset_complete;
	io->io_context = &sema;
	io->io_cmd = &cmd;
	cmd.pc_io_rqst = io;
	cmd.pc_softc = s;
	cmd.pc_device = &s->s_special_device;

	(void) pqi_cmd_action(&cmd, PQI_CMD_QUEUE);

	rqst = io->io_iu;
	(void) memset(rqst, 0, sizeof (*rqst));

	rqst->header.iu_type = PQI_REQUEST_IU_TASK_MANAGEMENT;
	rqst->header.iu_length = sizeof (*rqst) - PQI_REQUEST_HEADER_LENGTH;
	rqst->request_id = PQI_MAKE_REQID(io->io_index, io->io_gen);
	(void) memcpy(rqst->lun_number, d->pd_scsi3addr,
	    sizeof (rqst->lun_number));
	rqst->task_management_function = SOP_TASK_MANAGEMENT_LUN_RESET;

	pqi_start_io(s, &s->s_queue_groups[PQI_DEFAULT_QUEUE_GROUP], RAID_PATH,
	    io);

	sema_p(&sema);

	(void) pqi_cmd_action(&cmd, PQI_CMD_CMPLT);
	mutex_destroy(&cmd.pc_mutex);
	kmem_free(r, sizeof (*r));
}

static void
lun_reset_complete(pqi_io_request_t *io __unused, void *ctx)
{
	sema_v((ksema_t *)ctx);
}

static void
send_event_ack(pqi_state_t *s, pqi_event_acknowledge_request_t *rqst)
{
	pqi_queue_group_t	*qg;
	caddr_t			next_element;
	pqi_index_t		iq_ci;
	pqi_index_t		iq_pi;
	int			ms_timeo = 1000 * 10;

	qg = &s->s_queue_groups[PQI_DEFAULT_QUEUE_GROUP];
	rqst->header.iu_id = qg->oq_id;

	for (;;) {
		mutex_enter(&qg->submit_lock[RAID_PATH]);
		iq_pi = qg->iq_pi_copy[RAID_PATH];
		iq_ci = ddi_get32(s->s_queue_dma->acc, qg->iq_ci[RAID_PATH]);

		if (free_elem_count(iq_pi, iq_ci, s->s_num_elements_per_iq))
			break;

		mutex_exit(&qg->submit_lock[RAID_PATH]);
		if (pqi_is_offline(s))
			return;
	}
	next_element = qg->iq_element_array[RAID_PATH] +
	    (iq_pi * PQI_OPERATIONAL_IQ_ELEMENT_LENGTH);

	(void) memcpy(next_element, rqst, sizeof (*rqst));
	(void) ddi_dma_sync(s->s_queue_dma->handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	iq_pi = (iq_pi + 1) % s->s_num_elements_per_iq;
	qg->iq_pi_copy[RAID_PATH] = iq_pi;

	ddi_put32(s->s_datap, qg->iq_pi[RAID_PATH], iq_pi);

	/*
	 * Special case processing for events required. The driver must
	 * wait until the acknowledgement is processed before proceeding.
	 * Unfortunately, the HBA doesn't provide an interrupt which means
	 * the code must busy wait.
	 * Code will wait up to 10 seconds.
	 */
	while (ms_timeo--) {
		drv_usecwait(1000);
		iq_ci = ddi_get32(s->s_queue_dma->acc, qg->iq_ci[RAID_PATH]);
		if (iq_pi == iq_ci)
			break;
	}

	mutex_exit(&qg->submit_lock[RAID_PATH]);
}

static void
ack_event(pqi_state_t *s, pqi_event_t *e)
{
	pqi_event_acknowledge_request_t	rqst;

	(void) memset(&rqst, 0, sizeof (rqst));
	rqst.header.iu_type = PQI_REQUEST_IU_ACKNOWLEDGE_VENDOR_EVENT;
	rqst.header.iu_length = sizeof (rqst) - PQI_REQUEST_HEADER_LENGTH;
	rqst.event_type = e->ev_type;
	rqst.event_id = e->ev_id;
	rqst.additional_event_id = e->ev_additional;

	send_event_ack(s, &rqst);
}

static pqi_io_request_t *
setup_aio_request(pqi_state_t *s, pqi_cmd_t *cmd)
{
	pqi_io_request_t	*io;
	pqi_aio_path_request_t	*rqst;
	pqi_device_t		*devp = cmd->pc_device;

	/* ---- Most likely received a signal during a cv_wait ---- */
	if ((io = pqi_alloc_io(s)) == NULL)
		return (NULL);

	io->io_cb = aio_io_complete;
	io->io_cmd = cmd;
	io->io_raid_bypass = 0;

	rqst = io->io_iu;
	(void) memset(rqst, 0, sizeof (*rqst));

	rqst->header.iu_type = PQI_REQUEST_IU_AIO_PATH_IO;
	rqst->nexus_id = devp->pd_aio_handle;
	rqst->buffer_length = cmd->pc_dma_count;
	rqst->task_attribute = SOP_TASK_ATTRIBUTE_SIMPLE;
	rqst->request_id = PQI_MAKE_REQID(io->io_index, io->io_gen);
	rqst->error_index = io->io_index;
	rqst->cdb_length = cmd->pc_cmdlen;
	(void) memcpy(rqst->cdb, cmd->pc_cdb, cmd->pc_cmdlen);
	(void) memcpy(rqst->lun_number, devp->pd_scsi3addr,
	    sizeof (rqst->lun_number));

	if (cmd->pc_flags & PQI_FLAG_DMA_VALID) {
		if (cmd->pc_flags & PQI_FLAG_IO_READ)
			rqst->data_direction = SOP_READ_FLAG;
		else
			rqst->data_direction = SOP_WRITE_FLAG;
	} else {
		rqst->data_direction = SOP_NO_DIRECTION_FLAG;
	}

	build_aio_sg_list(s, rqst, cmd, io);
	return (io);
}

static pqi_io_request_t *
setup_raid_request(pqi_state_t *s, pqi_cmd_t *cmd)
{
	pqi_io_request_t	*io;
	pqi_raid_path_request_t	*rqst;
	pqi_device_t		*devp = cmd->pc_device;

	/* ---- Most likely received a signal during a cv_wait ---- */
	if ((io = pqi_alloc_io(s)) == NULL)
		return (NULL);

	io->io_cb = raid_io_complete;
	io->io_cmd = cmd;
	io->io_raid_bypass = 0;

	rqst = io->io_iu;
	(void) memset(rqst, 0, sizeof (*rqst));
	rqst->header.iu_type = PQI_REQUEST_IU_RAID_PATH_IO;
	rqst->rp_data_len = cmd->pc_dma_count;
	rqst->rp_task_attr = SOP_TASK_ATTRIBUTE_SIMPLE;
	rqst->rp_id = PQI_MAKE_REQID(io->io_index, io->io_gen);
	rqst->rp_error_index = io->io_index;
	(void) memcpy(rqst->rp_lun, devp->pd_scsi3addr, sizeof (rqst->rp_lun));
	(void) memcpy(rqst->rp_cdb, cmd->pc_cdb, cmd->pc_cmdlen);

	ASSERT(cmd->pc_cmdlen <= 16);
	rqst->rp_additional_cdb = SOP_ADDITIONAL_CDB_BYTES_0;

	if (cmd->pc_flags & PQI_FLAG_DMA_VALID) {
		if (cmd->pc_flags & PQI_FLAG_IO_READ)
			rqst->rp_data_dir = SOP_READ_FLAG;
		else
			rqst->rp_data_dir = SOP_WRITE_FLAG;
	} else {
		rqst->rp_data_dir = SOP_NO_DIRECTION_FLAG;
	}

	build_raid_sg_list(s, rqst, cmd, io);
	return (io);
}

pqi_cmd_t *
pqi_process_comp_ring(pqi_state_t *s __unused)
{
	return (NULL);
}

static void
raid_io_complete(pqi_io_request_t *io, void *context)
{
	/*
	 * ---- XXX Not sure if this complete function will be the same
	 * or different in the end. If it's the same this will be removed
	 * and aio_io_complete will have it's named changed to something
	 * more generic.
	 */
	aio_io_complete(io, context);
}

/*
 * special_error_check -- See if sense buffer matches "offline" status.
 *
 * spc3r23 section 4.5.6 -- Sense key and sense code definitions.
 * Sense key == 5 (KEY_ILLEGAL_REQUEST) indicates one of several conditions
 * a) Command addressed to incorrect logical unit.
 * b) Command had an invalid task attribute.
 * ...
 * Table 28 also shows that ASC 0x26 and ASCQ of 0x00 is an INVALID FIELD
 * IN PARAMETER LIST.
 * At no other time does this combination of KEY/ASC/ASCQ occur except when
 * a device or cable is pulled from the system along with a Hotplug event.
 * Without documentation it's only a guess, but it's the best that's available.
 * So, if the conditions are true the command packet pkt_reason will be changed
 * to CMD_DEV_GONE which causes MPxIO to switch to the other path and the
 * Hotplug event will cause a scan to occur which removes other inactive
 * devices in case of a cable pull.
 */
boolean_t
special_error_check(pqi_cmd_t *cmd)
{
	struct scsi_arq_status *arq;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	arq = (struct scsi_arq_status *)cmd->pc_pkt->pkt_scbp;

	if (((*cmd->pc_pkt->pkt_scbp & STATUS_MASK) == STATUS_CHECK) &&
	    (arq->sts_sensedata.es_key == KEY_ILLEGAL_REQUEST) &&
	    (arq->sts_sensedata.es_add_code == 0x26) &&
	    (arq->sts_sensedata.es_qual_code == 0)) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

static void
aio_io_complete(pqi_io_request_t *io, void *context __unused)
{
	pqi_cmd_t	*cmd = io->io_cmd;
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	boolean_t	pkt_ok = B_FALSE;

	if (cmd->pc_flags & (PQI_FLAG_IO_READ | PQI_FLAG_IO_IOPB))
		(void) ddi_dma_sync(cmd->pc_dmahdl, 0, 0, DDI_DMA_SYNC_FORCPU);

	switch (io->io_status) {
	case PQI_DATA_IN_OUT_UNDERFLOW:
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;
		if (pkt->pkt_resid == cmd->pc_dma_count) {
			pkt->pkt_reason = CMD_INCOMPLETE;
		} else {
			pkt->pkt_state |= STATE_XFERRED_DATA;
			pkt->pkt_reason = CMD_CMPLT;
		}
		break;

	case PQI_DATA_IN_OUT_GOOD:
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;
		if (cmd->pc_flags & PQI_FLAG_DMA_VALID)
			pkt->pkt_state |= STATE_XFERRED_DATA;
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_resid = 0;
		pkt->pkt_statistics = 0;
		pkt_ok = B_TRUE;
		break;

	case PQI_DATA_IN_OUT_ERROR:
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD;
		if (pkt->pkt_resid != cmd->pc_dma_count) {
			pkt->pkt_state |= STATE_XFERRED_DATA;
			pkt->pkt_reason = CMD_CMPLT;
		} else {
			pkt->pkt_reason = CMD_CMPLT;
		}
		break;

	case PQI_DATA_IN_OUT_PROTOCOL_ERROR:
		pkt->pkt_reason = CMD_TERMINATED;
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET;
		break;

	case PQI_DATA_IN_OUT_HARDWARE_ERROR:
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_GOT_BUS;
		break;

	default:
		pkt->pkt_reason = CMD_INCOMPLETE;
		break;
	}

	if (pkt_ok == B_FALSE)
		atomic_inc_32(&cmd->pc_device->pd_sense_errors);

	if (special_error_check(cmd) == B_TRUE) {
		pkt->pkt_reason = CMD_DEV_GONE;
		pkt->pkt_statistics = STAT_TERMINATED;
	}
	(void) pqi_cmd_action(cmd, PQI_CMD_CMPLT);
}

static void
fail_outstanding_cmds(pqi_state_t *s)
{
	pqi_device_t		*devp;

	ASSERT(MUTEX_HELD(&s->s_mutex));

	pqi_fail_drive_cmds(&s->s_special_device, CMD_TRAN_ERR);
	for (devp = list_head(&s->s_devnodes); devp != NULL;
	    devp = list_next(&s->s_devnodes, devp)) {
		pqi_fail_drive_cmds(devp, CMD_TRAN_ERR);
	}
}

static void
set_sg_descriptor(pqi_sg_entry_t *sg, ddi_dma_cookie_t *cookie)
{
	sg->sg_addr = cookie->dmac_laddress;
	sg->sg_len = cookie->dmac_size;
	sg->sg_flags = 0;
}

static void
build_aio_sg_list(pqi_state_t *s, pqi_aio_path_request_t *rqst,
    pqi_cmd_t *cmd, pqi_io_request_t *io)
{
	int			i;
	int			max_sg_per_iu;
	uint16_t		iu_length;
	uint8_t			chained;
	uint8_t			num_sg_in_iu	= 0;
	ddi_dma_cookie_t	*cookies;
	pqi_sg_entry_t		*sg;

	iu_length = offsetof(struct pqi_aio_path_request, ap_sglist) -
	    PQI_REQUEST_HEADER_LENGTH;

	if (cmd->pc_dmaccount == 0)
		goto out;
	sg = rqst->ap_sglist;
	cookies = cmd->pc_cached_cookies;
	max_sg_per_iu = s->s_max_sg_per_iu - 1;
	i = 0;
	chained = 0;

	for (;;) {
		set_sg_descriptor(sg, cookies);
		if (!chained)
			num_sg_in_iu++;
		i++;
		if (i == cmd->pc_dmaccount)
			break;
		sg++;
		cookies++;
		if (i == max_sg_per_iu) {
			sg->sg_addr = io->io_sg_chain_dma->dma_addr;
			sg->sg_len = (cmd->pc_dmaccount - num_sg_in_iu) *
			    sizeof (*sg);
			sg->sg_flags = CISS_SG_CHAIN;
			chained = 1;
			num_sg_in_iu++;
			sg = (pqi_sg_entry_t *)
			    io->io_sg_chain_dma->alloc_memory;
		}
	}
	sg->sg_flags = CISS_SG_LAST;
	rqst->partial = chained;
	if (chained) {
		(void) ddi_dma_sync(io->io_sg_chain_dma->handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
	}
	iu_length += num_sg_in_iu * sizeof (*sg);

out:
	rqst->header.iu_length = iu_length;
	rqst->num_sg_descriptors = num_sg_in_iu;
}

static void
build_raid_sg_list(pqi_state_t *s, pqi_raid_path_request_t *rqst,
    pqi_cmd_t *cmd, pqi_io_request_t *io)
{
	int			i		= 0;
	int			max_sg_per_iu;
	int			num_sg_in_iu	= 0;
	uint16_t		iu_length;
	uint8_t			chained		= 0;
	ddi_dma_cookie_t	*cookies;
	pqi_sg_entry_t		*sg;

	iu_length = offsetof(struct pqi_raid_path_request, rp_sglist) -
	    PQI_REQUEST_HEADER_LENGTH;

	if (cmd->pc_dmaccount == 0)
		goto out;

	sg = rqst->rp_sglist;
	cookies = cmd->pc_cached_cookies;
	max_sg_per_iu = s->s_max_sg_per_iu - 1;

	for (;;) {
		set_sg_descriptor(sg, cookies);
		if (!chained)
			num_sg_in_iu++;
		i++;
		if (i == cmd->pc_dmaccount)
			break;
		sg++;
		cookies++;
		if (i == max_sg_per_iu) {
			ASSERT(io->io_sg_chain_dma != NULL);
			sg->sg_addr = io->io_sg_chain_dma->dma_addr;
			sg->sg_len = (cmd->pc_dmaccount - num_sg_in_iu) *
			    sizeof (*sg);
			sg->sg_flags = CISS_SG_CHAIN;
			chained = 1;
			num_sg_in_iu++;
			sg = (pqi_sg_entry_t *)
			    io->io_sg_chain_dma->alloc_memory;
		}
	}
	sg->sg_flags = CISS_SG_LAST;
	rqst->rp_partial = chained;
	if (chained) {
		(void) ddi_dma_sync(io->io_sg_chain_dma->handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
	}
	iu_length += num_sg_in_iu * sizeof (*sg);

out:
	rqst->header.iu_length = iu_length;
}

static uint32_t
read_heartbeat_counter(pqi_state_t *s)
{
	return (ddi_get32(s->s_datap, s->s_heartbeat_counter));
}

static void
take_ctlr_offline(pqi_state_t *s)
{
	int			num_passes = 5;
	int			i;
	pqi_device_t		*d;
	pqi_cmd_t		*c, *nc;
	pqi_io_request_t	*io;
	uint32_t		active_count;

	/*
	 * 1) Why always panic here?
	 * Firmware resets don't work on the Microsemi HBA when the firmware
	 * is hung. The code as written fails outstanding commands and tries
	 * to reset the HBA. Since the reset don't work the HBA is left in an
	 * offline state and further commands sent (retries and new commands)
	 * are also failed. Eventually ZFS will panic with a deadman timer,
	 * but before that COMSTAR will see I/O requests error out and send
	 * I/O errors back to the client which causes corruption since these
	 * errors are no different than a device that starts to fail. So,
	 * instead of trying to play nice the driver now panics which will
	 * allow HA to fail fast to the other node.
	 *
	 * 2) Why not just remove this routine can call panic from the heartbeat
	 * routine?
	 * I'm hoping this is a temporary work around. We have been asking
	 * for more documentation on the product and we've been told there isn't
	 * any available.  It has been implied that some HBA's do support
	 * firmware resets. Therefore documentation would enable the driver
	 * to determine model number and adjust parameters such as panic on
	 * firmware hang or try a reset.
	 */
	if (1)
		panic("Firmware hung");

	d = &s->s_special_device;
	mutex_enter(&d->pd_mutex);
	while ((c = list_remove_head(&d->pd_cmd_list)) != NULL) {
		io = c->pc_io_rqst;
		io->io_status = PQI_DATA_IN_OUT_ERROR;

		mutex_exit(&d->pd_mutex);
		(io->io_cb)(io, io->io_context);
		mutex_enter(&d->pd_mutex);
	}
	mutex_exit(&d->pd_mutex);

	/*
	 * If pqi_reset_ctl() completes successfully the queues will be marked
	 * B_TRUE and the controller will be marked online again.
	 */
	mutex_enter(&s->s_mutex);
	for (i = 0; i < s->s_num_queue_groups; i++)
		s->s_queue_groups[i].qg_active = B_FALSE;
	s->s_offline = B_TRUE;
	fail_outstanding_cmds(s);
	mutex_exit(&s->s_mutex);

	/*
	 * Commands have been canceled that can be. It's possible there are
	 * commands currently running that are about to complete. Give them
	 * up to 5 seconds to finish. If those haven't completed by then they
	 * are most likely hung in the firmware of the HBA so go ahead and
	 * reset the firmware.
	 */
	while (num_passes-- > 0) {
		active_count = count_oustanding_cmds(s);
		if (active_count == 0)
			break;
		drv_usecwait(MICROSEC);
	}

	/*
	 * Any commands remaining are hung in the controller firmware so
	 * go ahead time them out so that the upper layers know what's
	 * happening.
	 */
	mutex_enter(&s->s_mutex);
	for (d = list_head(&s->s_devnodes); d != NULL;
	    d = list_next(&s->s_devnodes, d)) {
		mutex_enter(&d->pd_mutex);
		while ((c = list_head(&d->pd_cmd_list)) != NULL) {
			struct scsi_pkt *pkt = CMD2PKT(c);

			nc = list_next(&d->pd_cmd_list, c);
			ASSERT(pkt);
			if (pkt != NULL) {
				pkt->pkt_reason = CMD_TIMEOUT;
				pkt->pkt_statistics = STAT_TIMEOUT;
			}
			(void) pqi_cmd_action_nolock(c, PQI_CMD_TIMEOUT);
			c = nc;
		}
		mutex_exit(&d->pd_mutex);
	}
	mutex_exit(&s->s_mutex);

	cmn_err(CE_WARN, "Firmware Status: 0x%x", G32(s, sis_firmware_status));

	if (pqi_reset_ctl(s) == B_FALSE) {
		cmn_err(CE_WARN, "Failed to reset controller");
		return;
	}

	/*
	 * This will have the effect of releasing the device's dip
	 * structure from the NDI layer do to s_offline == B_TRUE.
	 */
	ndi_devi_enter(scsi_vhci_dip);
	ndi_devi_enter(s->s_dip);
	(void) pqi_config_all(s->s_dip, s);
	ndi_devi_exit(s->s_dip);
	ndi_devi_exit(scsi_vhci_dip);
}

static uint32_t
free_elem_count(pqi_index_t pi, pqi_index_t ci, uint32_t per_iq)
{
	pqi_index_t	used;
	if (pi >= ci) {
		used = pi - ci;
	} else {
		used = per_iq - ci + pi;
	}
	return (per_iq - used - 1);
}

static boolean_t
is_aio_enabled(pqi_device_t *d)
{
	return (d->pd_aio_enabled ? B_TRUE : B_FALSE);
}
