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
 * Copyright 2019 RackTop Systems, Inc.
 */

/*
 * Utility routines that have common usage throughout the driver.
 */
#include <smartpqi.h>

/* ---- Forward declarations for support/utility functions ---- */
static void reinit_io(pqi_io_request_t *io);
static void dump_raid(pqi_state_t *s, void *v, pqi_index_t idx);
static void dump_aio(void *v);
static void show_error_detail(pqi_state_t *s);
static void cmd_start_time(pqi_cmd_t *c);
static void cmd_finish_task(void *v);


/*
 * Entry points for this file
 */

#ifdef DEBUG
int	pqi_shuffle_delay = 0;
#endif	/* DEBUG */

static void
cmd_remove_group(pqi_cmd_t *c)
{
	pqi_io_request_t	*io = c->pc_io_rqst;
	pqi_device_t		*d = c->pc_device;

	/*
	 * This would be a good place to send a SCSI TASK MANAGEMENT
	 * command to cancel an individual command, but we don't
	 * have any documentation on the HBA to describe how that
	 * might be done.
	 */
	if (io != NULL) {
		pqi_queue_group_t	*qg = io->io_queue_group;
		int			path = io->io_queue_path;

		/*
		 * The lock ordering is such that the driver must drop
		 * the device lock in order to grab the queue lock.
		 * We must also drop the cmd mutex to prevent possible deadlock.
		 */
		mutex_exit(&c->pc_mutex);
		mutex_exit(&d->pd_mutex);
		mutex_enter(&qg->submit_lock[path]);
		if (list_link_active(&io->io_list_node)) {
			list_remove(&qg->request_list[path], io);
		}
		mutex_exit(&qg->submit_lock[path]);
#ifdef DEBUG
		if (pqi_shuffle_delay != 0) { /* try to force deadlock error */
			pqi_state_t	*s = c->pc_softc;
			pqi_lun_reset(s, d);
			delay(pqi_shuffle_delay * drv_usectohz(1000000));
		}
#endif	/* DEBUG */
		mutex_enter(&d->pd_mutex);
		mutex_enter(&c->pc_mutex);
	}
}

pqi_cmd_action_t
pqi_cmd_action_nolock(pqi_cmd_t *c, pqi_cmd_action_t a)
{
	pqi_device_t	*d = c->pc_device;
	pqi_state_t	*s = c->pc_softc;
	struct scsi_pkt	*pkt;

	mutex_enter(&c->pc_mutex);
	/*
	 * Don't change cmd if we are in middle of a timeout.
	 */
	if ((c->pc_flags & PQI_FLAG_TIMED_OUT) != 0) {
		a = PQI_CMD_FAIL;
		goto skipto;
	}
	c->pc_last_action = c->pc_cur_action;
	c->pc_cur_action = a;
	switch (a) {
	case PQI_CMD_QUEUE:
		list_insert_tail(&d->pd_cmd_list, c);

		/*
		 * Set the start time now in case the HBA hangs. That will
		 * allow the timeout processing to handle these commands, which
		 * in theory have been started but not really started, without
		 * the need for special handling logic in the timeout scan.
		 */
		cmd_start_time(c);
		break;

	case PQI_CMD_START:
		if (c->pc_last_action == PQI_CMD_FAIL) {
			list_remove(&d->pd_cmd_list, c);

			pkt = CMD2PKT(c);
			if (pkt == NULL) {
				pqi_io_request_t	*io = c->pc_io_rqst;

				io->io_status = PQI_DATA_IN_OUT_TIMEOUT;
				(*io->io_cb)(io, io->io_context);
				pqi_free_io(io);
				c->pc_io_rqst = NULL;
			} else {
				pqi_free_io(c->pc_io_rqst);
				c->pc_io_rqst = NULL;
				(void) ddi_taskq_dispatch(s->s_complete_taskq,
				    cmd_finish_task, c, 0);
			}
			a = PQI_CMD_FAIL;
		} else {
			/*
			 * Now that the command is actually being sent to the
			 * HBA reset the start so that a timeout will occur
			 * only after the HBA has had the command for some
			 * amount of time as defined by the SCSI packet.
			 */
			cmd_start_time(c);
		}
		break;

	case PQI_CMD_FAIL:
		if (c->pc_last_action == PQI_CMD_START) {
			/*
			 * There's no means to cancel a command that has
			 * been passed to the HBA, at least none without more
			 * documentation. So, if the command has been passed
			 * to the HBA the queue slot must remain active until
			 * the command completes. If it fails to complete
			 * then it will be freed by cmd_timeout_scan() when
			 * the action is PQI_CMD_TIMEOUT. So, for now keep
			 * the action as being PQI_CMD_START.
			 */
			a = PQI_CMD_START;
		} else {
			/*
			 * Don't do any actual processing here to cancel and
			 * free the command. By leaving the pc_cur_action
			 * set to PQI_CMD_FAIL the command will be freed
			 * when pqi_start_io() calls pqi_cmd_action(). The need
			 * for handling the error case in this manner is due
			 * to a small window in pqi_start_io() where the command
			 * has been removed from the group queue and before
			 * pqi_cmd_action() is called. It would be possible
			 * to fix by adding an additional lock to
			 * pqi_io_request_t or handle the issue in this manner.
			 * Less locks == good.
			 */
			/*
			 * We could have come in here during a cmd timeout
			 * lock shuffle so last action might be timeout here.
			 */
			ASSERT(c->pc_last_action == PQI_CMD_TIMEOUT ||
			    c->pc_last_action == PQI_CMD_QUEUE);
		}
		break;

	case PQI_CMD_TIMEOUT:
		list_remove(&d->pd_cmd_list, c);
		/*
		 * Set a flag to prevent this command from changing while we
		 * shuffle locks below.
		 */
		c->pc_flags |= PQI_FLAG_TIMED_OUT;
		cmd_remove_group(c);

		/*
		 * When a timeout has occurred it means something has gone
		 * wrong with the HBA or drive.  Timed out io requests are
		 * marked and the cmd was marked and removed from the chain
		 * above so it should not have changed state when we dropped
		 * and re-grabbed the locks.
		 */
		ASSERT3U(c->pc_cur_action, ==, PQI_CMD_TIMEOUT);

		c->pc_flags &= ~PQI_FLAG_TIMED_OUT;
		/*
		 * Internal commands to the driver will not have a SCSI packet
		 * associated.
		 */
		pkt = CMD2PKT(c);
		if (pkt == NULL) {
			pqi_io_request_t	*io = c->pc_io_rqst;

			io->io_status = PQI_DATA_IN_OUT_TIMEOUT;
			(*io->io_cb)(io, io->io_context);
			pqi_free_io(c->pc_io_rqst);
			c->pc_io_rqst = NULL;
		} else {
			pqi_free_io(c->pc_io_rqst);
			c->pc_io_rqst = NULL;
			mutex_exit(&c->pc_mutex);
			(void) ddi_taskq_dispatch(s->s_complete_taskq,
			    cmd_finish_task, c, 0);
			return (a);
		}
		break;

	case PQI_CMD_CMPLT:
		if (c->pc_last_action == PQI_CMD_TIMEOUT)
			break;

		list_remove(&d->pd_cmd_list, c);

		pqi_free_io(c->pc_io_rqst);
		c->pc_io_rqst = NULL;
		if (CMD2PKT(c) != NULL) {
			/*
			 * ddi_taskq_dispatch doesn't always start a separate
			 * thread. Under some conditions this will turn into
			 * a direct call to cmd_finish_task(). That in turn
			 * calls into the SCSA layer which can call
			 * tran_ini_pkt which will eventually try to call
			 * pqi_cmd_action(). So, need to drop the mutex before
			 * making the call to ddi_taskq_dispatch and then
			 * return.
			 */
			mutex_exit(&c->pc_mutex);
			(void) ddi_taskq_dispatch(s->s_complete_taskq,
			    cmd_finish_task, c, 0);
			return (a);
		}
		break;

	default:
		cmn_err(CE_PANIC,
		    "%s: Unknown action request: %d", __func__, a);
	}
skipto:
	mutex_exit(&c->pc_mutex);
	return (a);
}

pqi_cmd_action_t
pqi_cmd_action(pqi_cmd_t *c, pqi_cmd_action_t a)
{
	pqi_device_t		*d = c->pc_device;
	pqi_cmd_action_t	rval;

	mutex_enter(&d->pd_mutex);
	rval = pqi_cmd_action_nolock(c, a);
	mutex_exit(&d->pd_mutex);

	return (rval);
}

boolean_t
pqi_is_offline(pqi_state_t *s)
{
	return (s->s_offline);
}

/*
 * pqi_alloc_io -- return next available slot.
 */
pqi_io_request_t *
pqi_alloc_io(pqi_state_t *s)
{
	pqi_io_request_t	*io	= NULL;
	uint16_t		loop;
	uint16_t		i;

	mutex_enter(&s->s_io_mutex);
	i = s->s_next_io_slot; /* just a hint */
	s->s_io_need++;
	for (;;) {
		for (loop = 0; loop < s->s_max_io_slots; loop++) {
			/*
			 * Controller offline can only occur if the HBA is going
			 * through reset due to firmware hang.
			 */
			if (pqi_is_offline(s)) {
				mutex_exit(&s->s_io_mutex);
				return (NULL);
			}
			io = &s->s_io_rqst_pool[i];
			i = (i + 1) % s->s_max_io_slots;
			if (io->io_refcount == 0) {
				io->io_refcount = 1;
				break;
			}
		}
		if (loop != s->s_max_io_slots)
			break;

		s->s_io_had2wait++;
		s->s_io_wait_cnt++;
		if (cv_wait_sig(&s->s_io_condvar, &s->s_io_mutex) == 0) {
			s->s_io_sig++;
			io = NULL;
			break;
		}
		i = s->s_next_io_slot; /* just a hint */
	}
	s->s_next_io_slot = i;
	mutex_exit(&s->s_io_mutex);

	if (io != NULL)
		reinit_io(io);
	return (io);
}

void
pqi_free_io(pqi_io_request_t *io)
{
	pqi_state_t	*s = io->io_softc;

	mutex_enter(&s->s_io_mutex);
	ASSERT(io->io_refcount == 1);
	io->io_refcount = 0;
	reinit_io(io);
	if (s->s_io_wait_cnt != 0) {
		s->s_io_wait_cnt--;
		cv_signal(&s->s_io_condvar);
	}
	mutex_exit(&s->s_io_mutex);
}


/*
 * Time out an in progress i/o.
 * If the i/o has been serviced then return false (can't timeout),
 * otherwise increment the generation counter and return true.
 */
boolean_t
pqi_timeout_io(pqi_io_request_t *io)
{
	mutex_enter(&io->io_lock);
	if (io->io_serviced) {
		/*
		 * Can't timeout this io, it's already been serviced.
		 */
		mutex_exit(&io->io_lock);
		return (B_FALSE);
	}
	io->io_gen = (io->io_gen + 1) % PQI_NGENS;
	mutex_exit(&io->io_lock);
	return (B_TRUE);
}

/*
 * Check if an i/o is serviceable (generation counter matches).
 * If so, mark it as serviced and return true.
 * Otherwise, return false.
 */
boolean_t
pqi_service_io(pqi_io_request_t *io, uint8_t generation)
{
	mutex_enter(&io->io_lock);
	if (io->io_gen != generation) {
		/*
		 * Can't service this io, it's already been timed out.
		 */
		mutex_exit(&io->io_lock);
		return (B_FALSE);
	}
	io->io_serviced = B_TRUE;
	mutex_exit(&io->io_lock);
	return (B_TRUE);
}

void
pqi_dump_io(pqi_io_request_t *io)
{
	pqi_iu_header_t	*hdr = io->io_iu;
	pqi_state_t	*s;

	if (io->io_cmd != NULL) {
		s = io->io_cmd->pc_softc;
	} else {
		/*
		 * Early on, during driver attach, commands are run without
		 * a pqi_cmd_t structure associated. These io requests are
		 * low level operations direct to the HBA. So, grab a
		 * reference to the first and only instance through the
		 * DDI interface. Even though there might be multiple HBA's
		 * grabbing the first is okay since dump_raid() only references
		 * the debug level which will be the same for all the
		 * controllers.
		 */
		s = ddi_get_soft_state(pqi_state, 0);
	}

	if (hdr->iu_type == PQI_REQUEST_IU_AIO_PATH_IO) {
		dump_aio(io->io_iu);
	} else if (hdr->iu_type == PQI_REQUEST_IU_RAID_PATH_IO) {
		dump_raid(s, io->io_iu, io->io_pi);
	}
}

static uint_t supported_event_types[] = {
	PQI_EVENT_TYPE_HOTPLUG,
	PQI_EVENT_TYPE_HARDWARE,
	PQI_EVENT_TYPE_PHYSICAL_DEVICE,
	PQI_EVENT_TYPE_LOGICAL_DEVICE,
	PQI_EVENT_TYPE_AIO_STATE_CHANGE,
	PQI_EVENT_TYPE_AIO_CONFIG_CHANGE,
	PQI_EVENT_TYPE_HEARTBEAT
};

int
pqi_map_event(uint8_t event)
{
	int i;

	for (i = 0; i < sizeof (supported_event_types) / sizeof (uint_t); i++)
		if (supported_event_types[i] == event)
			return (i);
	return (-1);
}

boolean_t
pqi_supported_event(uint8_t event)
{
	return (pqi_map_event(event) == -1 ? B_FALSE : B_TRUE);
}

char *
pqi_event_to_str(uint8_t event)
{
	switch (event) {
	case PQI_EVENT_TYPE_HOTPLUG: return ("Hotplug");
	case PQI_EVENT_TYPE_HARDWARE: return ("Hardware");
	case PQI_EVENT_TYPE_PHYSICAL_DEVICE:
		return ("Physical Device");
	case PQI_EVENT_TYPE_LOGICAL_DEVICE: return ("logical Device");
	case PQI_EVENT_TYPE_AIO_STATE_CHANGE:
		return ("AIO State Change");
	case PQI_EVENT_TYPE_AIO_CONFIG_CHANGE:
		return ("AIO Config Change");
	case PQI_EVENT_TYPE_HEARTBEAT: return ("Heartbeat");
	default: return ("Unsupported Event Type");
	}
}

char *
bool_to_str(int v)
{
	return (v ? "T" : "f");
}

char *
dtype_to_str(int t)
{
	switch (t) {
	case DTYPE_DIRECT: return ("Direct");
	case DTYPE_SEQUENTIAL: return ("Sequential");
	case DTYPE_ESI: return ("ESI");
	case DTYPE_ARRAY_CTRL: return ("RAID");
	default: return ("Ughknown");
	}
}

static ddi_dma_attr_t single_dma_attrs = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0ull,
	.dma_attr_addr_hi =	0xffffffffffffffffull,
	.dma_attr_count_max =	0x7ffffull,
	.dma_attr_align =	4096,
	.dma_attr_burstsizes =	0x78,
	.dma_attr_minxfer =	1,
	.dma_attr_maxxfer =	0x007ffffull,
	.dma_attr_seg =		0xffffffffull,
	.dma_attr_sgllen =	1,
	.dma_attr_granular =	512,
	.dma_attr_flags =	0,
};

pqi_dma_overhead_t *
pqi_alloc_single(pqi_state_t *s, size_t len)
{
	pqi_dma_overhead_t	*d;
	ddi_dma_cookie_t	cookie;

	d = kmem_zalloc(sizeof (*d), KM_SLEEP);
	d->len_to_alloc = len;

	if (ddi_dma_alloc_handle(s->s_dip, &single_dma_attrs,
	    DDI_DMA_SLEEP, 0, &d->handle) != DDI_SUCCESS)
		goto error_out;

	if (ddi_dma_mem_alloc(d->handle, len, &s->s_reg_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    &d->alloc_memory, &len, &d->acc) != DDI_SUCCESS)
		goto error_out;

	bzero(d->alloc_memory, len);
	if (ddi_dma_addr_bind_handle(d->handle, NULL, d->alloc_memory, len,
	    DDI_DMA_RDWR, DDI_DMA_SLEEP, 0, &cookie, &d->cookie_count) !=
	    DDI_SUCCESS)
		goto error_out;

	d->dma_addr = cookie.dmac_laddress;
	if (d->cookie_count != 1)
		ddi_dma_nextcookie(d->handle, &d->second);

	return (d);

error_out:
	pqi_free_single(s, d);
	return (NULL);
}

void
pqi_free_single(pqi_state_t *s __unused, pqi_dma_overhead_t *d)
{
	(void) ddi_dma_unbind_handle(d->handle);
	if (d->alloc_memory != NULL)
		ddi_dma_mem_free(&d->acc);
	if (d->handle != NULL)
		ddi_dma_free_handle(&d->handle);
	kmem_free(d, sizeof (*d));
}

void
pqi_show_dev_state(pqi_state_t *s)
{
	uint32_t dev_status = G32(s, pqi_registers.device_status);

	switch (dev_status & 0xf) {
	case 0:
		cmn_err(CE_NOTE, "Power_On_And_Reset");
		break;

	case 1:
		cmn_err(CE_NOTE, "PQI_Status_Available");
		break;

	case 2:
		cmn_err(CE_NOTE, "All_Registers_Ready");
		break;

	case 3:
		cmn_err(CE_NOTE,
		    "Adminstrator_Queue_Pair_Ready");
		break;

	case 4:
		cmn_err(CE_NOTE, "Error: %s %s",
		    dev_status & 0x100 ? "(OP OQ Error)" : "",
		    dev_status & 0x200 ? "(OP IQ Error)" : "");
		show_error_detail(s);
		break;

	default:
		cmn_err(CE_WARN, "Unknown HBA status: 0x%x", dev_status);
		break;
	}
}

char *
cdb_to_str(uint8_t scsi_cmd)
{
	switch (scsi_cmd) {
	case SCMD_INQUIRY: return ("Inquiry");
	case SCMD_TEST_UNIT_READY: return ("TestUnitReady");
	case SCMD_READ: return ("Read");
	case SCMD_READ_G1: return ("Read G1");
	case SCMD_RESERVE: return ("Reserve");
	case SCMD_RELEASE: return ("Release");
	case SCMD_WRITE: return ("Write");
	case SCMD_WRITE_G1: return ("Write G1");
	case SCMD_START_STOP: return ("StartStop");
	case SCMD_READ_CAPACITY: return ("ReadCap");
	case SCMD_MODE_SENSE: return ("ModeSense");
	case SCMD_MODE_SELECT: return ("ModeSelect");
	case SCMD_SVC_ACTION_IN_G4: return ("ActionInG4");
	case SCMD_MAINTENANCE_IN: return ("MaintenanceIn");
	case SCMD_GDIAG: return ("ReceiveDiag");
	case SCMD_SDIAG: return ("SendDiag");
	case SCMD_LOG_SENSE_G1: return ("LogSenseG1");
	case SCMD_PERSISTENT_RESERVE_IN: return ("PgrReserveIn");
	case SCMD_PERSISTENT_RESERVE_OUT: return ("PgrReserveOut");
	case BMIC_READ: return ("BMIC Read");
	case BMIC_WRITE: return ("BMIC Write");
	case CISS_REPORT_LOG: return ("CISS Report Logical");
	case CISS_REPORT_PHYS: return ("CISS Report Physical");
	default: return ("unmapped");
	}
}

char *
io_status_to_str(int val)
{
	switch (val) {
	case PQI_DATA_IN_OUT_GOOD: return ("Good");
	case PQI_DATA_IN_OUT_UNDERFLOW: return ("Underflow");
	case PQI_DATA_IN_OUT_ERROR: return ("ERROR");
	case PQI_DATA_IN_OUT_PROTOCOL_ERROR: return ("Protocol Error");
	case PQI_DATA_IN_OUT_HARDWARE_ERROR: return ("Hardware Error");
	default: return ("UNHANDLED");
	}
}

char *
scsi_status_to_str(uint8_t val)
{
	switch (val) {
	case STATUS_GOOD: return ("Good");
	case STATUS_CHECK: return ("Check");
	case STATUS_MET: return ("Met");
	case STATUS_BUSY: return ("Busy");
	case STATUS_INTERMEDIATE: return ("Intermediate");
	case STATUS_RESERVATION_CONFLICT: return ("Reservation Conflict");
	case STATUS_TERMINATED: return ("Terminated");
	case STATUS_QFULL: return ("QFull");
	case STATUS_ACA_ACTIVE: return ("ACA Active");
	case STATUS_TASK_ABORT: return ("Task Abort");
	default: return ("Illegal Status");
	}
}

char *
iu_type_to_str(int val)
{
	switch (val) {
	case PQI_RESPONSE_IU_RAID_PATH_IO_SUCCESS: return ("Success");
	case PQI_RESPONSE_IU_AIO_PATH_IO_SUCCESS: return ("AIO Success");
	case PQI_RESPONSE_IU_GENERAL_MANAGEMENT: return ("General");
	case PQI_RESPONSE_IU_RAID_PATH_IO_ERROR: return ("IO Error");
	case PQI_RESPONSE_IU_AIO_PATH_IO_ERROR: return ("AIO IO Error");
	case PQI_RESPONSE_IU_AIO_PATH_DISABLED: return ("AIO Path Disabled");
	default: return ("UNHANDLED");
	}
}

void
pqi_free_mem_len(mem_len_pair_t *m)
{
	kmem_free(m->mem, m->len);
}

mem_len_pair_t
pqi_alloc_mem_len(int len)
{
	mem_len_pair_t m;
	m.len = len;
	m.mem = kmem_alloc(m.len, KM_SLEEP);
	*m.mem = '\0';
	return (m);
}

/*
 * []------------------------------------------------------------------[]
 * | Support/utility functions for main functions above			|
 * []------------------------------------------------------------------[]
 */

typedef struct qual {
	int	q_val;
	char	*q_str;
} qual_t;

typedef struct code_qual {
	int	cq_code;
	qual_t	*cq_list;
} code_qual_t;

/*
 * These messages come from pqi2r01 spec section 5.6 table 18.
 */
static qual_t pair0[] = { {0, "No error"}, {0, NULL} };
static qual_t pair1[] = { {0, "Error detected during initialization"},
	{ 0, NULL } };
static qual_t pair2[] = { {1, "Invalid PD Function"},
	{2, "Invalid paramter for PD function"},
	{0, NULL } };
static qual_t pair3[] = { {0, "Error creating admin queue pair"},
	{ 1, "Error deleting admin queue pair"},
	{ 0, NULL} };
static qual_t pair4[] = { {1, "Invalid IU type in general" },
	{2, "Invalid IU length in general admin request"},
	{0, NULL} };
static qual_t pair5[] = { {1, "Internal error" },
	{2, "OQ spanning conflict"},
	{0, NULL} };
static qual_t pair6[] = { {1, "Error completing PQI soft reset"},
	{2, "Error completing PQI firmware reset"},
	{3, "Error completing PQI hardware reset"},
	{0, NULL} };
static code_qual_t cq_table[] = {
	{ 0, pair0 },
	{ 1, pair1 },
	{ 2, pair2 },
	{ 3, pair3 },
	{ 4, pair4 },
	{ 5, pair5 },
	{ 6, pair6 },
	{ 0, NULL },
};

/*
 * cmd_finish_task -- taskq to complete command processing
 *
 * Under high load the driver will run out of IO slots which causes command
 * requests to pause until a slot is free. Calls to pkt_comp below can circle
 * through the SCSI layer and back into the driver to start another command
 * request and therefore possibly pause. If cmd_finish_task() was called on
 * the interrupt thread a hang condition could occur because IO slots wouldn't
 * be processed and then freed. So, this portion of the command completion
 * is run on a taskq.
 */
static void
cmd_finish_task(void *v)
{
	pqi_cmd_t	*c = v;
	struct scsi_pkt	*pkt = CMD2PKT(c);

	if (c->pc_poll)
		sema_v(c->pc_poll);

	if (pkt != NULL && (pkt->pkt_flags & FLAG_NOINTR) == 0 &&
	    (pkt->pkt_comp != NULL))
		(*pkt->pkt_comp)(pkt);
}

static void
cmd_start_time(pqi_cmd_t *c)
{
	c->pc_start_time = gethrtime();
	if (CMD2PKT(c) != NULL) {
		c->pc_expiration = c->pc_start_time +
		    ((hrtime_t)c->pc_pkt->pkt_time * NANOSEC);
	} else {
		c->pc_expiration = c->pc_start_time + 5 * NANOSEC;
	}
}

static void
show_error_detail(pqi_state_t *s)
{
	uint32_t error_reg = G32(s, pqi_registers.device_error);
	uint8_t		code, qualifier;
	qual_t		*p;
	code_qual_t	*cq;

	code = error_reg & 0xff;
	qualifier = (error_reg >> 8) & 0xff;

	for (cq = cq_table; cq->cq_list != NULL; cq++) {
		if (cq->cq_code == code) {
			for (p = cq->cq_list; p->q_str != NULL; p++) {
				if (p->q_val == qualifier) {
					cmn_err(CE_NOTE,
					    "[code=%x,qual=%x]: %s",
					    code, qualifier, p->q_str);
					return;
				}
			}
		}
	}
	cmn_err(CE_NOTE, "Undefined code(%x)/qualifier(%x)",
	    code, qualifier);
}

static void
pqi_catch_release(pqi_io_request_t *io __unused, void *v __unused)
{
	/*
	 * This call can occur if the software times out a command because
	 * the HBA hasn't responded in the default amount of time, 10 seconds,
	 * and then the HBA responds. It's occurred a few times during testing
	 * so catch and ignore.
	 */
	cmn_err(CE_NOTE, "%s: caught", __func__);
}

static void
reinit_io(pqi_io_request_t *io)
{
	io->io_cb = pqi_catch_release;
	io->io_status = 0;
	io->io_serviced = B_FALSE;
	io->io_error_info = NULL;
	io->io_raid_bypass = B_FALSE;
	io->io_context = NULL;
	io->io_cmd = NULL;
}

mem_len_pair_t
build_cdb_str(uint8_t *cdb)
{
	mem_len_pair_t m = pqi_alloc_mem_len(64);

	m.mem[0] = '\0';

	switch (cdb[0]) {
	case SCMD_INQUIRY:
		MEMP("%s", cdb_to_str(cdb[0]));
		if ((cdb[1] & 0x1) != 0)
			MEMP(".vpd=%x", cdb[2]);
		else if (cdb[2])
			MEMP("Illegal CDB");
		MEMP(".len=%x", cdb[3] << 8 | cdb[4]);
		break;

	case SCMD_READ:
		MEMP("%s.lba=%x.len=%x", cdb_to_str(cdb[0]),
		    (cdb[1] & 0x1f) << 16 | cdb[2] << 8 | cdb[3],
		    cdb[4]);
		break;

	case SCMD_MODE_SENSE:
		MEMP("%s.dbd=%s.pc=%x.page_code=%x.subpage=%x."
		    "len=%x", cdb_to_str(cdb[0]),
		    bool_to_str(cdb[1] & 8), cdb[2] >> 6 & 0x3,
		    cdb[2] & 0x3f, cdb[3], cdb[4]);
		break;

	case SCMD_START_STOP:
		MEMP("%s.immed=%s.power=%x.start=%s",
		    cdb_to_str(cdb[0]), bool_to_str(cdb[1] & 1),
		    (cdb[4] >> 4) & 0xf, bool_to_str(cdb[4] & 1));
		break;

	case SCMD_SVC_ACTION_IN_G4:
	case SCMD_READ_CAPACITY:
	case SCMD_TEST_UNIT_READY:
	default:
		MEMP("%s (%x)", cdb_to_str(cdb[0]), cdb[0]);
		break;
	}
	return (m);
}

mem_len_pair_t
mem_to_arraystr(uint8_t *ptr, size_t len)
{
	mem_len_pair_t	m	= pqi_alloc_mem_len(len * 3 + 20);
	int		i;

	m.mem[0] = '\0';
	MEMP("{ ");
	for (i = 0; i < len; i++) {
		MEMP("%02x ", *ptr++ & 0xff);
	}
	MEMP(" }");

	return (m);
}

static char lun_str[64];
static char *
lun_to_str(uint8_t *lun)
{
	int	i;
	lun_str[0] = '\0';
	for (i = 0; i < 8; i++)
		(void) snprintf(lun_str + strlen(lun_str),
		    sizeof (lun_str) - strlen(lun_str), "%02x.", *lun++);
	return (lun_str);
}

static char *
dir_to_str(int dir)
{
	switch (dir) {
	case SOP_NO_DIRECTION_FLAG: return ("NoDir");
	case SOP_WRITE_FLAG: return ("Write");
	case SOP_READ_FLAG: return ("Read");
	case SOP_BIDIRECTIONAL: return ("RW");
	default: return ("Oops");
	}
}

static char *
flags_to_str(uint32_t flag)
{
	switch (flag) {
	case CISS_SG_LAST: return ("Last");
	case CISS_SG_CHAIN: return ("Chain");
	case CISS_SG_NORMAL: return ("Norm");
	default: return ("Ooops");
	}
}

/* ---- Only for use in dump_raid and dump_aio ---- */
#define	SCRATCH_PRINT(args...) (void)snprintf(scratch + strlen(scratch), \
    len - strlen(scratch), args)

static void
dump_raid(pqi_state_t *s, void *v, pqi_index_t idx)
{
	int			i;
	int			len	= 512;
	caddr_t			scratch;
	pqi_raid_path_request_t	*rqst = v;
	mem_len_pair_t		cdb_data;
	caddr_t			raw = v;

	scratch = kmem_alloc(len, KM_SLEEP);
	scratch[0] = '\0';

	if (s->s_debug_level & DBG_LVL_RAW_RQST) {
		SCRATCH_PRINT("RAW RQST: ");
		for (i = 0; i < sizeof (*rqst); i++)
			SCRATCH_PRINT("%02x:", *raw++ & 0xff);
		cmn_err(CE_NOTE, "%s", scratch);
		scratch[0] = '\0';
	}

	if (s->s_debug_level & DBG_LVL_CDB) {
		cdb_data = build_cdb_str(rqst->rp_cdb);
		SCRATCH_PRINT("cdb(%s),", cdb_data.mem);
		pqi_free_mem_len(&cdb_data);
	}

	ASSERT0(rqst->header.reserved);
	ASSERT0(rqst->reserved1);
	ASSERT0(rqst->reserved2);
	ASSERT0(rqst->reserved3);
	ASSERT0(rqst->reserved4);
	ASSERT0(rqst->reserved5);

	if (s->s_debug_level & DBG_LVL_RQST) {
		SCRATCH_PRINT("pi=%x,h(type=%x,len=%x,id=%x)", idx,
		    rqst->header.iu_type, rqst->header.iu_length,
		    rqst->header.iu_id);
		SCRATCH_PRINT("rqst_id=%x,nexus_id=%x,len=%x,lun=(%s),"
		    "proto=%x,dir=%s,partial=%s,",
		    rqst->rp_id, rqst->rp_nexus_id, rqst->rp_data_len,
		    lun_to_str(rqst->rp_lun), rqst->protocol_specific,
		    dir_to_str(rqst->rp_data_dir),
		    bool_to_str(rqst->rp_partial));
		SCRATCH_PRINT("fence=%s,error_idx=%x,task_attr=%x,"
		    "priority=%x,additional=%x,sg=(",
		    bool_to_str(rqst->rp_fence), rqst->rp_error_index,
		    rqst->rp_task_attr,
		    rqst->rp_pri, rqst->rp_additional_cdb);
		for (i = 0; i < PQI_MAX_EMBEDDED_SG_DESCRIPTORS; i++) {
			SCRATCH_PRINT("%lx:%x:%s,",
			    (long unsigned int)rqst->rp_sglist[i].sg_addr,
			    rqst->rp_sglist[i].sg_len,
			    flags_to_str(rqst->rp_sglist[i].sg_flags));
		}
		SCRATCH_PRINT(")");
	}

	cmn_err(CE_NOTE, "%s", scratch);
	kmem_free(scratch, len);
}

static void
dump_aio(void *v)
{
	pqi_aio_path_request_t	*rqst	= v;
	int			i;
	int			len	= 512;
	caddr_t			scratch;
	mem_len_pair_t		cdb_data;

	scratch = kmem_alloc(len, KM_SLEEP);
	scratch[0] = '\0';

	cdb_data = build_cdb_str(rqst->cdb);
	SCRATCH_PRINT("cdb(%s)", cdb_data.mem);
	pqi_free_mem_len(&cdb_data);

	SCRATCH_PRINT("h(type=%x,len=%x,id=%x)",
	    rqst->header.iu_type, rqst->header.iu_length,
	    rqst->header.iu_id);
	SCRATCH_PRINT("rqst_id=%x,nexus_id=%x,len=%x,lun=(%s),dir=%s,"
	    "partial=%s,",
	    rqst->request_id, rqst->nexus_id, rqst->buffer_length,
	    lun_to_str(rqst->lun_number),
	    dir_to_str(rqst->data_direction), bool_to_str(rqst->partial));
	SCRATCH_PRINT("fence=%s,error_idx=%x,task_attr=%x,priority=%x,"
	    "num_sg=%x,cdb_len=%x,sg=(",
	    bool_to_str(rqst->fence), rqst->error_index, rqst->task_attribute,
	    rqst->command_priority, rqst->num_sg_descriptors, rqst->cdb_length);
	for (i = 0; i < PQI_MAX_EMBEDDED_SG_DESCRIPTORS; i++) {
		SCRATCH_PRINT("%lx:%x:%s,",
		    (long unsigned int)rqst->ap_sglist[i].sg_addr,
		    rqst->ap_sglist[i].sg_len,
		    flags_to_str(rqst->ap_sglist[i].sg_flags));
	}
	SCRATCH_PRINT(")");

	cmn_err(CE_NOTE, "%s", scratch);
	kmem_free(scratch, len);
}
