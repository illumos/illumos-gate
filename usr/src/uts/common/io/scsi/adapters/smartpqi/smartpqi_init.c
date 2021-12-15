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
 * Copyright 2021 Racktop Systems.
 */

/*
 * This file contains the start up code to initialize the HBA for use
 * with the PQI interface.
 */
#include <smartpqi.h>

#define	PQI_DEVICE_SIGNATURE			"PQI DREG"
#define	PQI_STATUS_IDLE				0x0
#define	PQI_DEVICE_STATE_ALL_REGISTERS_READY	0x2

typedef struct _func_list_ {
	char		*func_name;
	boolean_t	(*func)(pqi_state_t *);
} func_list_t;

static boolean_t pqi_reset_prep(pqi_state_t *);
static boolean_t pqi_ctlr_ready(pqi_state_t *);
static boolean_t revert_to_sis(pqi_state_t *);
static boolean_t pqi_calculate_io_resources(pqi_state_t *);
static boolean_t pqi_check_alloc(pqi_state_t *);
static boolean_t pqi_wait_for_mode_ready(pqi_state_t *);
static boolean_t save_ctrl_mode_pqi(pqi_state_t *);
static boolean_t pqi_process_config_table(pqi_state_t *);
static boolean_t pqi_alloc_admin_queue(pqi_state_t *);
static boolean_t pqi_create_admin_queues(pqi_state_t *);
static boolean_t pqi_report_device_capability(pqi_state_t *);
static boolean_t pqi_valid_device_capability(pqi_state_t *);
static boolean_t pqi_calculate_queue_resources(pqi_state_t *);
static boolean_t pqi_alloc_io_resource(pqi_state_t *);
static boolean_t pqi_alloc_operation_queues(pqi_state_t *);
static boolean_t pqi_init_operational_queues(pqi_state_t *);
static boolean_t pqi_init_operational_locks(pqi_state_t *);
static boolean_t pqi_create_queues(pqi_state_t *);
static boolean_t pqi_change_irq_mode(pqi_state_t *);
static boolean_t pqi_start_heartbeat_timer(pqi_state_t *);
static boolean_t pqi_enable_events(pqi_state_t *);
static boolean_t pqi_get_hba_version(pqi_state_t *);
static boolean_t pqi_version_to_hba(pqi_state_t *);
static boolean_t pqi_schedule_update_time_worker(pqi_state_t *);
static boolean_t pqi_scan_scsi_devices(pqi_state_t *);

func_list_t startup_funcs[] =
{
	{ "sis_wait_for_ctrl_ready", sis_wait_for_ctrl_ready },
	{ "sis_get_ctrl_props", sis_get_ctrl_props },
	{ "sis_get_pqi_capabilities", sis_get_pqi_capabilities },
	{ "pqi_calculate_io_resources", pqi_calculate_io_resources },
	{ "pqi_check_alloc", pqi_check_alloc },
	{ "sis_init_base_struct_addr", sis_init_base_struct_addr },
	{ "pqi_wait_for_mode_ready", pqi_wait_for_mode_ready },
	{ "save_ctrl_mode_pqi", save_ctrl_mode_pqi },
	{ "pqi_process_config_table", pqi_process_config_table },
	{ "pqi_alloc_admin_queue", pqi_alloc_admin_queue },
	{ "pqi_create_admin_queues", pqi_create_admin_queues },
	{ "pqi_report_device_capability", pqi_report_device_capability },
	{ "pqi_valid_device_capability", pqi_valid_device_capability },
	{ "pqi_calculate_queue_resources", pqi_calculate_queue_resources },
	{ "pqi_alloc_io_resource", pqi_alloc_io_resource },
	{ "pqi_alloc_operation_queues", pqi_alloc_operation_queues },
	{ "pqi_init_operational_queues", pqi_init_operational_queues },
	{ "pqi_init_operational_locks", pqi_init_operational_locks },
	{ "pqi_create_queues", pqi_create_queues },
	{ "pqi_change_irq_mode", pqi_change_irq_mode },
	{ "pqi_start_heartbeat_timer", pqi_start_heartbeat_timer },
	{ "pqi_enable_events", pqi_enable_events },
	{ "pqi_get_hba_version", pqi_get_hba_version },
	{ "pqi_version_to_hba", pqi_version_to_hba },
	{ "pqi_schedule_update_time_worker", pqi_schedule_update_time_worker },
	{ "pqi_scan_scsi_devices", pqi_scan_scsi_devices },
	{ NULL, NULL }
};

func_list_t reset_funcs[] =
{
	{ "pqi_reset_prep", pqi_reset_prep },
	{ "revert_to_sis", revert_to_sis },
	{ "pqi_check_firmware", pqi_check_firmware },
	{ "sis_wait_for_ctrl_ready", sis_wait_for_ctrl_ready },
	{ "sis_get_ctrl_props", sis_get_ctrl_props },
	{ "sis_get_pqi_capabilities", sis_get_pqi_capabilities },
	{ "pqi_calculate_io_resources", pqi_calculate_io_resources },
	{ "pqi_check_alloc", pqi_check_alloc },
	{ "sis_init_base_struct_addr", sis_init_base_struct_addr },
	{ "pqi_wait_for_mode_ready", pqi_wait_for_mode_ready },
	{ "save_ctrl_mode_pqi", save_ctrl_mode_pqi },
	{ "pqi_process_config_table", pqi_process_config_table },
	{ "pqi_alloc_admin_queue", pqi_alloc_admin_queue },
	{ "pqi_create_admin_queues", pqi_create_admin_queues },
	{ "pqi_report_device_capability", pqi_report_device_capability },
	{ "pqi_valid_device_capability", pqi_valid_device_capability },
	{ "pqi_calculate_queue_resources", pqi_calculate_queue_resources },
	{ "pqi_alloc_io_resource", pqi_alloc_io_resource },
	{ "pqi_alloc_operation_queues", pqi_alloc_operation_queues },
	{ "pqi_init_operational_queues", pqi_init_operational_queues },
	{ "pqi_create_queues", pqi_create_queues },
	{ "pqi_change_irq_mode", pqi_change_irq_mode },
	{ "pqi_ctlr_ready", pqi_ctlr_ready },
	{ "pqi_start_heartbeat_timer", pqi_start_heartbeat_timer },
	{ "pqi_enable_events", pqi_enable_events },
	{ "pqi_get_hba_version", pqi_get_hba_version },
	{ "pqi_version_to_hba", pqi_version_to_hba },
	{ "pqi_schedule_update_time_worker", pqi_schedule_update_time_worker },
	{ NULL, NULL }
};

/* ---- Forward declarations for utility functions ---- */
static void bcopy_fromregs(pqi_state_t *s, uint8_t *iomem, uint8_t *dst,
    uint32_t len);
static boolean_t submit_admin_rqst_sync(pqi_state_t *s,
    pqi_general_admin_request_t *rqst, pqi_general_admin_response_t *rsp);
static boolean_t create_event_queue(pqi_state_t *s);
static boolean_t create_queue_group(pqi_state_t *s, int idx);
static boolean_t submit_raid_rqst_sync(pqi_state_t *s, pqi_iu_header_t *rqst,
    pqi_raid_error_info_t e_info);
static boolean_t identify_controller(pqi_state_t *s,
    bmic_identify_controller_t *ident);
static boolean_t write_host_wellness(pqi_state_t *s, void *buf, size_t len);
static boolean_t get_device_list(pqi_state_t *s,
    report_phys_lun_extended_t **pl, size_t *plen,
    report_log_lun_extended_t **ll, size_t *llen);
static boolean_t build_raid_path_request(pqi_raid_path_request_t *rqst, int cmd,
    caddr_t lun, uint32_t len, int vpd_page);
static boolean_t identify_physical_device(pqi_state_t *s, pqi_device_t *devp,
    bmic_identify_physical_device_t *buf);
static pqi_device_t *create_phys_dev(pqi_state_t *s,
    report_phys_lun_extended_entry_t *e);
static pqi_device_t *create_logical_dev(pqi_state_t *s,
    report_log_lun_extended_entry_t *e);
static boolean_t is_new_dev(pqi_state_t *s, pqi_device_t *new_dev);
static boolean_t revert_to_sis(pqi_state_t *s);
static void save_ctrl_mode(pqi_state_t *s, int mode);
static boolean_t scsi_common(pqi_state_t *s, pqi_raid_path_request_t *rqst,
    caddr_t buf, int len);
static void update_time(void *v);

static int reset_devices = 1;

int pqi_max_io_slots = PQI_MAX_IO_SLOTS;

static boolean_t
pqi_reset_prep(pqi_state_t *s)
{
	s->s_intr_ready = B_FALSE;
	(void) untimeout(s->s_time_of_day);
	(void) untimeout(s->s_watchdog);
	pqi_free_single(s, s->s_error_dma);
	s->s_error_dma = NULL;

	pqi_free_single(s, s->s_adminq_dma);
	s->s_adminq_dma = NULL;

	mutex_enter(&s->s_io_mutex);
	pqi_free_io_resource(s);
	mutex_exit(&s->s_io_mutex);
	return (B_TRUE);
}

static boolean_t
pqi_ctlr_ready(pqi_state_t *s)
{
	s->s_offline = B_FALSE;
	return (B_TRUE);
}

boolean_t
pqi_check_firmware(pqi_state_t *s)
{
	uint32_t	status;

	status = G32(s, sis_firmware_status);
	if (status & SIS_CTRL_KERNEL_PANIC)
		return (B_FALSE);

	if (sis_read_scratch(s) == SIS_MODE)
		return (B_TRUE);

	if (status & SIS_CTRL_KERNEL_UP) {
		sis_write_scratch(s, SIS_MODE);
		return (B_TRUE);
	} else {
		return (revert_to_sis(s));
	}
}

boolean_t
pqi_prep_full(pqi_state_t *s)
{
	func_list_t	*f;

	for (f = startup_funcs; f->func_name != NULL; f++)
		if (f->func(s) == B_FALSE) {
			cmn_err(CE_WARN, "Init failed on %s", f->func_name);
			return (B_FALSE);
		}

	return (B_TRUE);
}

boolean_t
pqi_reset_ctl(pqi_state_t *s)
{
	func_list_t	*f;

	for (f = reset_funcs; f->func_name != NULL; f++)
		if (f->func(s) == B_FALSE) {
			cmn_err(CE_WARN, "Reset failed on %s", f->func_name);
			return (B_FALSE);
		}

	return (B_TRUE);
}
/*
 * []----------------------------------------------------------[]
 * | Startup functions called in sequence to initialize HBA.	|
 * []----------------------------------------------------------[]
 */

static boolean_t
pqi_calculate_io_resources(pqi_state_t *s)
{
	uint32_t	max_xfer_size;
	uint32_t	max_sg_entries;

	s->s_max_io_slots = s->s_max_outstanding_requests;

	max_xfer_size = min(s->s_max_xfer_size, PQI_MAX_TRANSFER_SIZE);

	/* ---- add 1 when buf is not page aligned ---- */
	max_sg_entries = max_xfer_size / PAGESIZE + 1;
	max_sg_entries = min(max_sg_entries, s->s_max_sg_entries);
	max_xfer_size = (max_sg_entries - 1) * PAGESIZE;

	s->s_sg_chain_buf_length = (max_sg_entries * sizeof (pqi_sg_entry_t)) +
	    PQI_EXTRA_SGL_MEMORY;

	s->s_max_sectors = max_xfer_size / 512;

	return (B_TRUE);
}

static boolean_t
pqi_check_alloc(pqi_state_t *s)
{
	/*
	 * Note that we need to pass a generation cnt as part of a i/o
	 * request id.  The id is limited to 16 bits and we reserve 4 bits
	 * for a generation no.  This means we must limit s_max_io_slots
	 * to max 12 bits worth of slot indexes.
	 */
	if (pqi_max_io_slots != 0 && pqi_max_io_slots < s->s_max_io_slots) {
		s->s_max_io_slots = pqi_max_io_slots;
	}

	s->s_error_dma = pqi_alloc_single(s, (s->s_max_io_slots *
	    PQI_ERROR_BUFFER_ELEMENT_LENGTH) + SIS_BASE_STRUCT_ALIGNMENT);
	if (s->s_error_dma == NULL)
		return (B_FALSE);

	return (B_TRUE);
}

#define	WAIT_FOR_FIRMWARE_IN_MSECS (5 * MILLISEC)

static boolean_t
pqi_wait_for_mode_ready(pqi_state_t *s)
{
	uint64_t	signature;
	int32_t		count = WAIT_FOR_FIRMWARE_IN_MSECS;

	for (;;) {
		signature = G64(s, pqi_registers.signature);
		if (memcmp(&signature, PQI_DEVICE_SIGNATURE,
		    sizeof (signature)) == 0)
			break;
		if (count-- == 0)
			return (B_FALSE);
		drv_usecwait(MICROSEC / MILLISEC);
	}

	count = WAIT_FOR_FIRMWARE_IN_MSECS;
	for (;;) {
		if (G64(s, pqi_registers.function_and_status_code) ==
		    PQI_STATUS_IDLE)
			break;
		if (count-- == 0)
			return (B_FALSE);
		drv_usecwait(MICROSEC / MILLISEC);
	}

	count = WAIT_FOR_FIRMWARE_IN_MSECS;
	for (;;) {
		if (G32(s, pqi_registers.device_status) ==
		    PQI_DEVICE_STATE_ALL_REGISTERS_READY)
			break;
		if (count-- == 0)
			return (B_FALSE);
		drv_usecwait(MICROSEC / MILLISEC);
	}

	return (B_TRUE);
}

static boolean_t
save_ctrl_mode_pqi(pqi_state_t *s)
{
	save_ctrl_mode(s, PQI_MODE);
	return (B_TRUE);
}

static boolean_t
pqi_process_config_table(pqi_state_t *s)
{
	pqi_config_table_t			*c_table;
	pqi_config_table_section_header_t	*section;
	uint32_t				section_offset;

	c_table = kmem_zalloc(s->s_config_table_len, KM_SLEEP);
	bcopy_fromregs(s, (uint8_t *)s->s_reg + s->s_config_table_offset,
	    (uint8_t *)c_table, s->s_config_table_len);

	section_offset = c_table->first_section_offset;
	while (section_offset) {
		section = (pqi_config_table_section_header_t *)
		    ((caddr_t)c_table + section_offset);
		switch (section->section_id) {
		case PQI_CONFIG_TABLE_SECTION_HEARTBEAT:
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			s->s_heartbeat_counter = (uint32_t *)
			    ((caddr_t)s->s_reg +
			    s->s_config_table_offset + section_offset +
			    offsetof(struct pqi_config_table_heartbeat,
			    heartbeat_counter));
			break;
		}
		section_offset = section->next_section_offset;
	}
	kmem_free(c_table, s->s_config_table_len);
	return (B_TRUE);
}

static boolean_t
pqi_alloc_admin_queue(pqi_state_t *s)
{
	pqi_admin_queues_t		*aq;
	pqi_admin_queues_aligned_t	*aq_aligned;
	int				len;

	len = sizeof (*aq_aligned) + PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT;
	if ((s->s_adminq_dma = pqi_alloc_single(s, len)) == NULL)
		return (B_FALSE);
	(void) memset(s->s_adminq_dma->alloc_memory, 0,
	    s->s_adminq_dma->len_to_alloc);
	(void) ddi_dma_sync(s->s_adminq_dma->handle, 0,
	    s->s_adminq_dma->len_to_alloc, DDI_DMA_SYNC_FORDEV);

	aq = &s->s_admin_queues;
	aq_aligned = PQIALIGN_TYPED(s->s_adminq_dma->alloc_memory,
	    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, pqi_admin_queues_aligned_t *);
	aq->iq_element_array = (caddr_t)&aq_aligned->iq_element_array;
	aq->oq_element_array = (caddr_t)&aq_aligned->oq_element_array;
	aq->iq_ci = &aq_aligned->iq_ci;
	aq->oq_pi = &aq_aligned->oq_pi;

	aq->iq_element_array_bus_addr = s->s_adminq_dma->dma_addr +
	    ((uintptr_t)aq->iq_element_array -
	    (uintptr_t)s->s_adminq_dma->alloc_memory);
	aq->oq_element_array_bus_addr = s->s_adminq_dma->dma_addr +
	    ((uintptr_t)aq->oq_element_array -
	    (uintptr_t)s->s_adminq_dma->alloc_memory);

	aq->iq_ci_bus_addr = s->s_adminq_dma->dma_addr +
	    ((uintptr_t)aq->iq_ci - (uintptr_t)s->s_adminq_dma->alloc_memory);
	aq->oq_pi_bus_addr = s->s_adminq_dma->dma_addr +
	    ((uintptr_t)aq->oq_pi - (uintptr_t)s->s_adminq_dma->alloc_memory);
	return (B_TRUE);
}

static boolean_t
pqi_create_admin_queues(pqi_state_t *s)
{
	pqi_admin_queues_t *aq = &s->s_admin_queues;
	int			val;
	int			status;
	int			countdown = 1000;


	aq->iq_pi_copy = 0;
	aq->oq_ci_copy = 0;

	S64(s, pqi_registers.admin_iq_element_array_addr,
	    aq->iq_element_array_bus_addr);
	S64(s, pqi_registers.admin_oq_element_array_addr,
	    aq->oq_element_array_bus_addr);
	S64(s, pqi_registers.admin_iq_ci_addr,
	    aq->iq_ci_bus_addr);
	S64(s, pqi_registers.admin_oq_pi_addr,
	    aq->oq_pi_bus_addr);

	val = PQI_ADMIN_IQ_NUM_ELEMENTS | PQI_ADMIN_OQ_NUM_ELEMENTS << 8 |
	    aq->int_msg_num << 16;
	S32(s, pqi_registers.admin_queue_params, val);
	S64(s, pqi_registers.function_and_status_code,
	    PQI_CREATE_ADMIN_QUEUE_PAIR);

	while (countdown-- > 0) {
		status = G64(s, pqi_registers.function_and_status_code);
		if (status == PQI_STATUS_IDLE)
			break;
		drv_usecwait(1000);	/* ---- Wait 1ms ---- */
	}
	if (countdown == 0)
		return (B_FALSE);

	/*
	 * The offset registers are not initialized to the correct
	 * offsets until *after* the create admin queue pair command
	 * completes successfully.
	 */
	aq->iq_pi = (void *)(intptr_t)((intptr_t)s->s_reg +
	    PQI_DEVICE_REGISTERS_OFFSET +
	    G64(s, pqi_registers.admin_iq_pi_offset));
	ASSERT((G64(s, pqi_registers.admin_iq_pi_offset) +
	    PQI_DEVICE_REGISTERS_OFFSET) < 0x8000);

	aq->oq_ci = (void *)(intptr_t)((intptr_t)s->s_reg +
	    PQI_DEVICE_REGISTERS_OFFSET +
	    G64(s, pqi_registers.admin_oq_ci_offset));
	ASSERT((G64(s, pqi_registers.admin_oq_ci_offset) +
	    PQI_DEVICE_REGISTERS_OFFSET) < 0x8000);

	return (B_TRUE);
}

static boolean_t
pqi_report_device_capability(pqi_state_t *s)
{
	pqi_general_admin_request_t	rqst;
	pqi_general_admin_response_t	rsp;
	pqi_device_capability_t		*cap;
	pqi_iu_layer_descriptor_t	*iu_layer;
	pqi_dma_overhead_t		*dma;
	boolean_t			rval;
	pqi_sg_entry_t			*sg;

	(void) memset(&rqst, 0, sizeof (rqst));

	rqst.header.iu_type = PQI_REQUEST_IU_GENERAL_ADMIN;
	rqst.header.iu_length = PQI_GENERAL_ADMIN_IU_LENGTH;
	rqst.function_code =
	    PQI_GENERAL_ADMIN_FUNCTION_REPORT_DEVICE_CAPABILITY;
	rqst.data.report_device_capability.buffer_length =
	    sizeof (*cap);

	if ((dma = pqi_alloc_single(s, sizeof (*cap))) == NULL)
		return (B_FALSE);

	sg = &rqst.data.report_device_capability.sg_descriptor;
	sg->sg_addr = dma->dma_addr;
	sg->sg_len = dma->len_to_alloc;
	sg->sg_flags = CISS_SG_LAST;

	rval = submit_admin_rqst_sync(s, &rqst, &rsp);
	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORCPU);
	cap = (pqi_device_capability_t *)dma->alloc_memory;

	s->s_max_inbound_queues = cap->max_inbound_queues;
	s->s_max_elements_per_iq = cap->max_elements_per_iq;
	s->s_max_iq_element_length = cap->max_iq_element_length * 16;
	s->s_max_outbound_queues = cap->max_outbound_queues;
	s->s_max_elements_per_oq = cap->max_elements_per_oq;
	s->s_max_oq_element_length = cap->max_oq_element_length * 16;

	iu_layer = &cap->iu_layer_descriptors[PQI_PROTOCOL_SOP];
	s->s_max_inbound_iu_length_per_firmware =
	    iu_layer->max_inbound_iu_length;
	s->s_inbound_spanning_supported = iu_layer->inbound_spanning_supported;
	s->s_outbound_spanning_supported =
	    iu_layer->outbound_spanning_supported;

	pqi_free_single(s, dma);
	return (rval);
}

static boolean_t
pqi_valid_device_capability(pqi_state_t *s)
{
	if (s->s_max_iq_element_length < PQI_OPERATIONAL_IQ_ELEMENT_LENGTH)
		return (B_FALSE);
	if (s->s_max_oq_element_length < PQI_OPERATIONAL_OQ_ELEMENT_LENGTH)
		return (B_FALSE);
	if (s->s_max_inbound_iu_length_per_firmware <
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH)
		return (B_FALSE);
	/* ---- Controller doesn't support spanning but we need it ---- */
	if (!s->s_inbound_spanning_supported)
		return (B_FALSE);
	/* ---- Controller wants outbound spanning, the driver doesn't ---- */
	if (s->s_outbound_spanning_supported)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
pqi_calculate_queue_resources(pqi_state_t *s)
{
	int	max_queue_groups;
	int	num_queue_groups;
	int	num_elements_per_iq;
	int	num_elements_per_oq;

	if (reset_devices) {
		num_queue_groups = 1;
	} else {
		max_queue_groups = min(s->s_max_inbound_queues / 2,
		    s->s_max_outbound_queues - 1);
		max_queue_groups = min(max_queue_groups, PQI_MAX_QUEUE_GROUPS);

		num_queue_groups = min(ncpus, s->s_intr_cnt);
		num_queue_groups = min(num_queue_groups, max_queue_groups);
	}
	s->s_num_queue_groups = num_queue_groups;

	s->s_max_inbound_iu_length =
	    (s->s_max_inbound_iu_length_per_firmware /
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH) *
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH;

	num_elements_per_iq = s->s_max_inbound_iu_length /
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH;
	/* ---- add one because one element in each queue is unusable ---- */
	num_elements_per_iq++;

	num_elements_per_iq = min(num_elements_per_iq,
	    s->s_max_elements_per_iq);

	num_elements_per_oq = ((num_elements_per_iq - 1) * 2) + 1;
	num_elements_per_oq = min(num_elements_per_oq,
	    s->s_max_elements_per_oq);

	s->s_num_elements_per_iq = num_elements_per_iq;
	s->s_num_elements_per_oq = num_elements_per_oq;

	s->s_max_sg_per_iu = ((s->s_max_inbound_iu_length -
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH) /
	    sizeof (struct pqi_sg_entry)) +
	    PQI_MAX_EMBEDDED_SG_DESCRIPTORS;
	return (B_TRUE);
}

static boolean_t
pqi_alloc_io_resource(pqi_state_t *s)
{
	pqi_io_request_t	*io;
	size_t			sg_chain_len;
	int			i;

	s->s_io_rqst_pool = kmem_zalloc(s->s_max_io_slots * sizeof (*io),
	    KM_SLEEP);

	sg_chain_len = s->s_sg_chain_buf_length;
	io = s->s_io_rqst_pool;
	for (i = 0; i < s->s_max_io_slots; i++) {
		io->io_iu = kmem_zalloc(s->s_max_inbound_iu_length, KM_SLEEP);

		/*
		 * TODO: Don't allocate dma space here. Move this to
		 * init_pkt when it's clear the data being transferred
		 * will not fit in the four SG slots provided by each
		 * command.
		 */
		io->io_sg_chain_dma = pqi_alloc_single(s, sg_chain_len);
		if (io->io_sg_chain_dma == NULL)
			goto error_out;

		mutex_init(&io->io_lock, NULL, MUTEX_DRIVER, NULL);
		io->io_gen = 1;
		list_link_init(&io->io_list_node);
		io->io_index = (uint16_t)i;

		io->io_softc = s;
		io++;
	}

	return (B_TRUE);

error_out:
	for (i = 0; i < s->s_max_io_slots; i++) {
		if (io->io_iu != NULL) {
			kmem_free(io->io_iu, s->s_max_inbound_iu_length);
			io->io_iu = NULL;
		}
		if (io->io_sg_chain_dma != NULL) {
			pqi_free_single(s, io->io_sg_chain_dma);
			io->io_sg_chain_dma = NULL;
		}
	}
	kmem_free(s->s_io_rqst_pool, s->s_max_io_slots * sizeof (*io));
	s->s_io_rqst_pool = NULL;

	return (B_FALSE);
}

static boolean_t
pqi_alloc_operation_queues(pqi_state_t *s)
{
	uint32_t	niq = s->s_num_queue_groups * 2;
	uint32_t	noq = s->s_num_queue_groups;
	uint32_t	queue_idx = (s->s_num_queue_groups * 3) + 1;
	uint32_t	i;
	size_t		array_len_iq;
	size_t		array_len_oq;
	size_t		alloc_len;
	caddr_t		aligned_pointer = NULL;
	pqi_queue_group_t	*qg;

	array_len_iq = PQI_OPERATIONAL_IQ_ELEMENT_LENGTH *
	    s->s_num_elements_per_iq;
	array_len_oq = PQI_OPERATIONAL_OQ_ELEMENT_LENGTH *
	    s->s_num_elements_per_oq;

	for (i = 0; i < niq; i++) {
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);
		aligned_pointer += array_len_iq;
	}

	for (i = 0; i < noq; i++) {
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);
		aligned_pointer += array_len_oq;
	}

	aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
	    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);
	aligned_pointer += PQI_NUM_EVENT_QUEUE_ELEMENTS *
	    PQI_EVENT_OQ_ELEMENT_LENGTH;

	for (i = 0; i < queue_idx; i++) {
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_OPERATIONAL_INDEX_ALIGNMENT, caddr_t);
		aligned_pointer += sizeof (pqi_index_t);
	}

	alloc_len = (size_t)aligned_pointer +
	    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT + PQI_EXTRA_SGL_MEMORY;
	if ((s->s_queue_dma = pqi_alloc_single(s, alloc_len)) == NULL)
		return (B_FALSE);

	aligned_pointer = PQIALIGN_TYPED(s->s_queue_dma->alloc_memory,
	    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);
	for (i = 0; i < s->s_num_queue_groups; i++) {
		qg = &s->s_queue_groups[i];

		qg->iq_pi_copy[0] = 0;
		qg->iq_pi_copy[1] = 0;
		qg->oq_ci_copy = 0;
		qg->iq_element_array[RAID_PATH] = aligned_pointer;
		qg->iq_element_array_bus_addr[RAID_PATH] =
		    s->s_queue_dma->dma_addr +
		    ((uintptr_t)aligned_pointer -
		    (uintptr_t)s->s_queue_dma->alloc_memory);

		aligned_pointer += array_len_iq;
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);

		qg->iq_element_array[AIO_PATH] = aligned_pointer;
		qg->iq_element_array_bus_addr[AIO_PATH] =
		    s->s_queue_dma->dma_addr +
		    ((uintptr_t)aligned_pointer -
		    (uintptr_t)s->s_queue_dma->alloc_memory);

		aligned_pointer += array_len_iq;
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);
	}
	for (i = 0; i < s->s_num_queue_groups; i++) {
		qg = &s->s_queue_groups[i];

		qg->oq_element_array = aligned_pointer;
		qg->oq_element_array_bus_addr =
		    s->s_queue_dma->dma_addr +
		    ((uintptr_t)aligned_pointer -
		    (uintptr_t)s->s_queue_dma->alloc_memory);

		aligned_pointer += array_len_oq;
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT, caddr_t);
	}

	s->s_event_queue.oq_element_array = aligned_pointer;
	s->s_event_queue.oq_element_array_bus_addr =
	    s->s_queue_dma->dma_addr +
	    ((uintptr_t)aligned_pointer -
	    (uintptr_t)s->s_queue_dma->alloc_memory);
	aligned_pointer += PQI_NUM_EVENT_QUEUE_ELEMENTS *
	    PQI_EVENT_OQ_ELEMENT_LENGTH;

	aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
	    PQI_OPERATIONAL_INDEX_ALIGNMENT, caddr_t);

	for (i = 0; i < s->s_num_queue_groups; i++) {
		qg = &s->s_queue_groups[i];

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		qg->iq_ci[RAID_PATH] = (pqi_index_t *)aligned_pointer;
		qg->iq_ci_bus_addr[RAID_PATH] =
		    s->s_queue_dma->dma_addr +
		    ((uintptr_t)aligned_pointer -
		    (uintptr_t)s->s_queue_dma->alloc_memory);

		aligned_pointer += sizeof (pqi_index_t);
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_OPERATIONAL_INDEX_ALIGNMENT, caddr_t);

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		qg->iq_ci[AIO_PATH] = (pqi_index_t *)aligned_pointer;
		qg->iq_ci_bus_addr[AIO_PATH] =
		    s->s_queue_dma->dma_addr +
		    ((uintptr_t)aligned_pointer -
		    (uintptr_t)s->s_queue_dma->alloc_memory);

		aligned_pointer += sizeof (pqi_index_t);
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_OPERATIONAL_INDEX_ALIGNMENT, caddr_t);

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		qg->oq_pi = (pqi_index_t *)aligned_pointer;
		qg->oq_pi_bus_addr =
		    s->s_queue_dma->dma_addr +
		    ((uintptr_t)aligned_pointer -
		    (uintptr_t)s->s_queue_dma->alloc_memory);

		aligned_pointer += sizeof (pqi_index_t);
		aligned_pointer = PQIALIGN_TYPED(aligned_pointer,
		    PQI_OPERATIONAL_INDEX_ALIGNMENT, caddr_t);
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	s->s_event_queue.oq_pi = (pqi_index_t *)aligned_pointer;
	s->s_event_queue.oq_pi_bus_addr =
	    s->s_queue_dma->dma_addr +
	    ((uintptr_t)aligned_pointer -
	    (uintptr_t)s->s_queue_dma->alloc_memory);
	ASSERT((uintptr_t)aligned_pointer -
	    (uintptr_t)s->s_queue_dma->alloc_memory +
	    sizeof (pqi_index_t) <= s->s_queue_dma->len_to_alloc);

	return (B_TRUE);
}

static boolean_t
pqi_init_operational_queues(pqi_state_t *s)
{
	int		i;
	uint16_t	iq_id = PQI_MIN_OPERATIONAL_QUEUE_ID;
	uint16_t	oq_id = PQI_MIN_OPERATIONAL_QUEUE_ID;

	for (i = 0; i < s->s_num_queue_groups; i++) {
		s->s_queue_groups[i].qg_softc = s;
	}
	s->s_event_queue.oq_id = oq_id++;
	for (i = 0; i < s->s_num_queue_groups; i++) {
		s->s_queue_groups[i].iq_id[RAID_PATH] = iq_id++;
		s->s_queue_groups[i].iq_id[AIO_PATH] = iq_id++;
		s->s_queue_groups[i].oq_id = oq_id++;
		s->s_queue_groups[i].qg_active = B_TRUE;
	}
	s->s_event_queue.int_msg_num = 0;
	for (i = 0; i < s->s_num_queue_groups; i++)
		s->s_queue_groups[i].int_msg_num = (uint16_t)i;

	return (B_TRUE);
}

static boolean_t
pqi_init_operational_locks(pqi_state_t *s)
{
	int	i;

	for (i = 0; i < s->s_num_queue_groups; i++) {
		mutex_init(&s->s_queue_groups[i].submit_lock[0], NULL,
		    MUTEX_DRIVER, NULL);
		mutex_init(&s->s_queue_groups[i].submit_lock[1], NULL,
		    MUTEX_DRIVER, NULL);
		list_create(&s->s_queue_groups[i].request_list[RAID_PATH],
		    sizeof (pqi_io_request_t),
		    offsetof(struct pqi_io_request, io_list_node));
		list_create(&s->s_queue_groups[i].request_list[AIO_PATH],
		    sizeof (pqi_io_request_t),
		    offsetof(struct pqi_io_request, io_list_node));
	}
	return (B_TRUE);
}

static boolean_t
pqi_create_queues(pqi_state_t *s)
{
	int	i;

	if (create_event_queue(s) == B_FALSE)
		return (B_FALSE);

	for (i = 0; i < s->s_num_queue_groups; i++) {
		if (create_queue_group(s, i) == B_FALSE) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
pqi_change_irq_mode(pqi_state_t *s)
{
	/* ---- Device already is in MSIX mode ---- */
	s->s_intr_ready = B_TRUE;
	return (B_TRUE);
}

static boolean_t
pqi_start_heartbeat_timer(pqi_state_t *s)
{
	s->s_last_heartbeat_count = 0;
	s->s_last_intr_count = 0;

	s->s_watchdog = timeout(pqi_watchdog, s, drv_usectohz(WATCHDOG));
	return (B_TRUE);
}

#define	PQI_REPORT_EVENT_CONFIG_BUFFER_LENGTH \
	(offsetof(struct pqi_event_config, descriptors) + \
	(PQI_MAX_EVENT_DESCRIPTORS * sizeof (pqi_event_descriptor_t)))

static boolean_t
pqi_enable_events(pqi_state_t *s)
{
	int			i;
	pqi_event_config_t	*ec;
	pqi_event_descriptor_t	*desc;
	pqi_general_mgmt_rqst_t	rqst;
	pqi_dma_overhead_t	*dma;
	pqi_sg_entry_t		*sg;
	boolean_t		rval = B_FALSE;

	(void) memset(&rqst, 0, sizeof (rqst));
	dma = pqi_alloc_single(s, PQI_REPORT_EVENT_CONFIG_BUFFER_LENGTH);
	if (dma == NULL)
		return (B_FALSE);

	rqst.header.iu_type = PQI_REQUEST_IU_REPORT_VENDOR_EVENT_CONFIG;
	rqst.header.iu_length = offsetof(struct pqi_general_management_request,
	    data.report_event_configuration.sg_descriptors[1]) -
	    PQI_REQUEST_HEADER_LENGTH;
	rqst.data.report_event_configuration.buffer_length =
	    PQI_REPORT_EVENT_CONFIG_BUFFER_LENGTH;
	sg = &rqst.data.report_event_configuration.sg_descriptors[0];
	sg->sg_addr = dma->dma_addr;
	sg->sg_len = dma->len_to_alloc;
	sg->sg_flags = CISS_SG_LAST;

	if (submit_raid_rqst_sync(s, &rqst.header, NULL) == B_FALSE)
		goto error_out;

	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORCPU);
	ec = (pqi_event_config_t *)dma->alloc_memory;
	for (i = 0; i < ec->num_event_descriptors; i++) {
		desc = &ec->descriptors[i];
		if (pqi_supported_event(desc->event_type) == B_TRUE)
			desc->oq_id = s->s_event_queue.oq_id;
		else
			desc->oq_id = 0;
	}

	rqst.header.iu_type = PQI_REQUEST_IU_SET_VENDOR_EVENT_CONFIG;
	rqst.header.iu_length = offsetof(struct pqi_general_management_request,
	    data.report_event_configuration.sg_descriptors[1]) -
	    PQI_REQUEST_HEADER_LENGTH;
	rqst.data.report_event_configuration.buffer_length =
	    PQI_REPORT_EVENT_CONFIG_BUFFER_LENGTH;
	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	rval = submit_raid_rqst_sync(s, &rqst.header, NULL);

error_out:
	pqi_free_single(s, dma);
	return (rval);
}

/*
 * pqi_get_hba_version -- find HBA's version number
 */
static boolean_t
pqi_get_hba_version(pqi_state_t *s)
{
	bmic_identify_controller_t	*ident;
	boolean_t			rval = B_FALSE;

	ident = kmem_zalloc(sizeof (*ident), KM_SLEEP);
	if (identify_controller(s, ident) == B_FALSE)
		goto out;
	(void) memcpy(s->s_firmware_version, ident->firmware_version,
	    sizeof (ident->firmware_version));
	s->s_firmware_version[sizeof (ident->firmware_version)] = '\0';
	(void) snprintf(s->s_firmware_version + strlen(s->s_firmware_version),
	    sizeof (s->s_firmware_version) - strlen(s->s_firmware_version),
	    "-%u", ident->firmware_build_number);
	rval = B_TRUE;
	cmn_err(CE_NOTE, "!smartpqi%d - firmware version: %s",
	    s->s_instance, s->s_firmware_version);
out:
	kmem_free(ident, sizeof (*ident));
	return (rval);
}

/*
 * pqi_version_to_hba -- send driver version to HBA
 */
static boolean_t
pqi_version_to_hba(pqi_state_t *s)
{
	bmic_host_wellness_driver_version_t	*b;
	boolean_t				rval = B_FALSE;

	b = kmem_zalloc(sizeof (*b), KM_SLEEP);
	b->start_tag[0] = '<';
	b->start_tag[1] = 'H';
	b->start_tag[2] = 'W';
	b->start_tag[3] = '>';
	b->drv_tag[0] = 'D';
	b->drv_tag[1] = 'V';
	b->driver_version_length = sizeof (b->driver_version);
	(void) snprintf(b->driver_version, sizeof (b->driver_version),
	    "Illumos 1.0");
	b->end_tag[0] = 'Z';
	b->end_tag[1] = 'Z';

	rval = write_host_wellness(s, b, sizeof (*b));
	kmem_free(b, sizeof (*b));

	return (rval);
}


static boolean_t
pqi_schedule_update_time_worker(pqi_state_t *s)
{
	update_time(s);
	return (B_TRUE);
}

static boolean_t
pqi_scan_scsi_devices(pqi_state_t *s)
{
	report_phys_lun_extended_t	*phys_list	= NULL;
	report_log_lun_extended_t	*logical_list	= NULL;
	size_t plen;
	size_t llen;
	boolean_t			rval		= B_FALSE;
	int				num_phys	= 0;
	int				num_logical	= 0;
	int				i;
	pqi_device_t			*dev;

	if (get_device_list(s, &phys_list, &plen,
	    &logical_list, &llen) == B_FALSE)
		goto error_out;

	if (phys_list) {
		num_phys = ntohl(phys_list->header.list_length) /
		    sizeof (phys_list->lun_entries[0]);
	}

	if (logical_list) {
		num_logical = ntohl(logical_list->header.list_length) /
		    sizeof (logical_list->lun_entries[0]);
	}

	/*
	 * Need to look for devices that are no longer available. The call
	 * below to is_new_dev() will mark either the new device just created
	 * as having been scanned or if is_new_dev() finds an existing
	 * device in the list that one will be marked as scanned.
	 */
	mutex_enter(&s->s_mutex);
	for (dev = list_head(&s->s_devnodes); dev != NULL;
	    dev = list_next(&s->s_devnodes, dev)) {
		dev->pd_scanned = 0;
	}
	mutex_exit(&s->s_mutex);

	for (i = 0; i < (num_phys + num_logical); i++) {
		if (i < num_phys) {
			dev = create_phys_dev(s, &phys_list->lun_entries[i]);
		} else {
			dev = create_logical_dev(s,
			    &logical_list->lun_entries[i - num_phys]);
		}
		if (dev != NULL) {
			if (is_new_dev(s, dev) == B_TRUE) {
				list_create(&dev->pd_cmd_list,
				    sizeof (struct pqi_cmd),
				    offsetof(struct pqi_cmd, pc_list));
				mutex_init(&dev->pd_mutex, NULL, MUTEX_DRIVER,
				    NULL);

				mutex_enter(&s->s_mutex);
				list_insert_tail(&s->s_devnodes, dev);
				mutex_exit(&s->s_mutex);
			} else {
				ddi_devid_free_guid(dev->pd_guid);
				kmem_free(dev, sizeof (*dev));
			}
		}
	}

	/*
	 * Now look through the list for devices which have disappeared.
	 * Mark them as being offline. During the call to config_one, which
	 * will come next during a hotplug event, those devices will be
	 * offlined to the SCSI subsystem.
	 */
	mutex_enter(&s->s_mutex);
	for (dev = list_head(&s->s_devnodes); dev != NULL;
	    dev = list_next(&s->s_devnodes, dev)) {
		if (dev->pd_scanned)
			dev->pd_online = 1;
		else
			dev->pd_online = 0;
	}

	mutex_exit(&s->s_mutex);

	rval = B_TRUE;

error_out:
	if (phys_list != NULL)
		kmem_free(phys_list, plen);
	if (logical_list != NULL)
		kmem_free(logical_list, llen);
	return (rval);
}

/*
 * []----------------------------------------------------------[]
 * | Entry points used by other funtions found in other files	|
 * []----------------------------------------------------------[]
 */
void
pqi_rescan_devices(pqi_state_t *s)
{
	(void) pqi_scan_scsi_devices(s);
}

boolean_t
pqi_scsi_inquiry(pqi_state_t *s, pqi_device_t *dev, int vpd,
    struct scsi_inquiry *inq, int len)
{
	pqi_raid_path_request_t rqst;

	if (build_raid_path_request(&rqst, SCMD_INQUIRY,
	    dev->pd_scsi3addr, len, vpd) == B_FALSE)
		return (B_FALSE);

	return (scsi_common(s, &rqst, (caddr_t)inq, len));
}

void
pqi_free_io_resource(pqi_state_t *s)
{
	pqi_io_request_t	*io = s->s_io_rqst_pool;
	int			i;

	if (io == NULL)
		return;

	for (i = 0; i < s->s_max_io_slots; i++) {
		if (io->io_iu == NULL)
			break;
		kmem_free(io->io_iu, s->s_max_inbound_iu_length);
		io->io_iu = NULL;
		pqi_free_single(s, io->io_sg_chain_dma);
		io->io_sg_chain_dma = NULL;
	}

	kmem_free(s->s_io_rqst_pool, s->s_max_io_slots * sizeof (*io));
	s->s_io_rqst_pool = NULL;
}

/*
 * []----------------------------------------------------------[]
 * | Utility functions for startup code.			|
 * []----------------------------------------------------------[]
 */

static boolean_t
scsi_common(pqi_state_t *s, pqi_raid_path_request_t *rqst, caddr_t buf, int len)
{
	pqi_dma_overhead_t	*dma;
	pqi_sg_entry_t		*sg;
	boolean_t		rval = B_FALSE;

	if ((dma = pqi_alloc_single(s, len)) == NULL)
		return (B_FALSE);

	sg = &rqst->rp_sglist[0];
	sg->sg_addr = dma->dma_addr;
	sg->sg_len = dma->len_to_alloc;
	sg->sg_flags = CISS_SG_LAST;

	if (submit_raid_rqst_sync(s, &rqst->header, NULL) == B_FALSE)
		goto out;

	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORCPU);
	(void) memcpy(buf, dma->alloc_memory, len);
	rval = B_TRUE;
out:
	pqi_free_single(s, dma);
	return (rval);
}

static void
bcopy_fromregs(pqi_state_t *s, uint8_t *iomem, uint8_t *dst, uint32_t len)
{
	int	i;

	for (i = 0; i < len; i++) {
		*dst++ = ddi_get8(s->s_datap, iomem + i);
	}
}

static void
submit_admin_request(pqi_state_t *s, pqi_general_admin_request_t *r)
{
	pqi_admin_queues_t	*aq;
	pqi_index_t		iq_pi;
	caddr_t			next_element;

	aq = &s->s_admin_queues;
	iq_pi = aq->iq_pi_copy;
	next_element = aq->iq_element_array + (iq_pi *
	    PQI_ADMIN_IQ_ELEMENT_LENGTH);
	(void) memcpy(next_element, r, sizeof (*r));
	(void) ddi_dma_sync(s->s_adminq_dma->handle,
	    iq_pi * PQI_ADMIN_IQ_ELEMENT_LENGTH, sizeof (*r),
	    DDI_DMA_SYNC_FORDEV);
	iq_pi = (iq_pi + 1) % PQI_ADMIN_IQ_NUM_ELEMENTS;
	aq->iq_pi_copy = iq_pi;

	ddi_put32(s->s_datap, aq->iq_pi, iq_pi);
}

static boolean_t
poll_for_admin_response(pqi_state_t *s, pqi_general_admin_response_t *r)
{
	pqi_admin_queues_t	*aq;
	pqi_index_t		oq_pi;
	pqi_index_t		oq_ci;
	int			countdown = 10 * MICROSEC;	/* 10 seconds */
	int			pause_time = 10 * MILLISEC;	/* 10ms */

	countdown /= pause_time;
	aq = &s->s_admin_queues;
	oq_ci = aq->oq_ci_copy;

	while (--countdown) {
		oq_pi = ddi_get32(s->s_adminq_dma->acc, aq->oq_pi);
		if (oq_pi != oq_ci)
			break;
		drv_usecwait(pause_time);
	}
	if (countdown == 0)
		return (B_FALSE);

	(void) ddi_dma_sync(s->s_adminq_dma->handle,
	    oq_ci * PQI_ADMIN_OQ_ELEMENT_LENGTH, sizeof (*r),
	    DDI_DMA_SYNC_FORCPU);
	(void) memcpy(r, aq->oq_element_array +
	    (oq_ci * PQI_ADMIN_OQ_ELEMENT_LENGTH), sizeof (*r));

	aq->oq_ci_copy = (oq_ci + 1) % PQI_ADMIN_OQ_NUM_ELEMENTS;
	ddi_put32(s->s_datap, aq->oq_ci, aq->oq_ci_copy);

	return (B_TRUE);
}

static boolean_t
validate_admin_response(pqi_general_admin_response_t *r, uint8_t code)
{
	if (r->header.iu_type != PQI_RESPONSE_IU_GENERAL_ADMIN)
		return (B_FALSE);

	if (r->header.iu_length != PQI_GENERAL_ADMIN_IU_LENGTH)
		return (B_FALSE);

	if (r->function_code != code)
		return (B_FALSE);

	if (r->status != PQI_GENERAL_ADMIN_STATUS_SUCCESS)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
submit_admin_rqst_sync(pqi_state_t *s,
    pqi_general_admin_request_t *rqst, pqi_general_admin_response_t *rsp)
{
	boolean_t	rval;

	submit_admin_request(s, rqst);
	rval = poll_for_admin_response(s, rsp);
	if (rval == B_TRUE) {
		rval = validate_admin_response(rsp, rqst->function_code);
		if (rval == B_FALSE) {
			pqi_show_dev_state(s);
		}
	}
	return (rval);
}

static boolean_t
create_event_queue(pqi_state_t *s)
{
	pqi_event_queue_t		*eq;
	pqi_general_admin_request_t	request;
	pqi_general_admin_response_t	response;

	eq = &s->s_event_queue;

	/*
	 * Create OQ (Outbound Queue - device to host queue) to dedicate
	 * to events.
	 */
	(void) memset(&request, 0, sizeof (request));
	request.header.iu_type = PQI_REQUEST_IU_GENERAL_ADMIN;
	request.header.iu_length = PQI_GENERAL_ADMIN_IU_LENGTH;
	request.function_code = PQI_GENERAL_ADMIN_FUNCTION_CREATE_OQ;
	request.data.create_operational_oq.queue_id = eq->oq_id;
	request.data.create_operational_oq.element_array_addr =
	    eq->oq_element_array_bus_addr;
	request.data.create_operational_oq.pi_addr = eq->oq_pi_bus_addr;
	request.data.create_operational_oq.num_elements =
	    PQI_NUM_EVENT_QUEUE_ELEMENTS;
	request.data.create_operational_oq.element_length =
	    PQI_EVENT_OQ_ELEMENT_LENGTH / 16;
	request.data.create_operational_oq.queue_protocol = PQI_PROTOCOL_SOP;
	request.data.create_operational_oq.int_msg_num = eq->int_msg_num;

	if (submit_admin_rqst_sync(s, &request, &response) == B_FALSE)
		return (B_FALSE);

	eq->oq_ci = (uint32_t *)(intptr_t)((uint64_t)(intptr_t)s->s_reg +
	    PQI_DEVICE_REGISTERS_OFFSET +
	    response.data.create_operational_oq.oq_ci_offset);

	return (B_TRUE);
}

static boolean_t
create_queue_group(pqi_state_t *s, int idx)
{
	pqi_queue_group_t		*qg;
	pqi_general_admin_request_t	rqst;
	pqi_general_admin_response_t	rsp;

	qg = &s->s_queue_groups[idx];

	/* ---- Create inbound queue for RAID path (host to device) ---- */
	(void) memset(&rqst, 0, sizeof (rqst));
	rqst.header.iu_type = PQI_REQUEST_IU_GENERAL_ADMIN;
	rqst.header.iu_length = PQI_GENERAL_ADMIN_IU_LENGTH;
	rqst.function_code = PQI_GENERAL_ADMIN_FUNCTION_CREATE_IQ;
	rqst.data.create_operational_iq.queue_id = qg->iq_id[RAID_PATH];
	rqst.data.create_operational_iq.element_array_addr =
	    qg->iq_element_array_bus_addr[RAID_PATH];
	rqst.data.create_operational_iq.ci_addr =
	    qg->iq_ci_bus_addr[RAID_PATH];
	rqst.data.create_operational_iq.num_elements =
	    s->s_num_elements_per_iq;
	rqst.data.create_operational_iq.element_length =
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH / 16;
	rqst.data.create_operational_iq.queue_protocol = PQI_PROTOCOL_SOP;

	if (submit_admin_rqst_sync(s, &rqst, &rsp) == B_FALSE)
		return (B_FALSE);
	qg->iq_pi[RAID_PATH] =
	    (uint32_t *)(intptr_t)((uint64_t)(intptr_t)s->s_reg +
	    PQI_DEVICE_REGISTERS_OFFSET +
	    rsp.data.create_operational_iq.iq_pi_offset);

	/* ---- Create inbound queue for Advanced I/O path. ---- */
	(void) memset(&rqst, 0, sizeof (rqst));
	rqst.header.iu_type = PQI_REQUEST_IU_GENERAL_ADMIN;
	rqst.header.iu_length = PQI_GENERAL_ADMIN_IU_LENGTH;
	rqst.function_code = PQI_GENERAL_ADMIN_FUNCTION_CREATE_IQ;
	rqst.data.create_operational_iq.queue_id =
	    qg->iq_id[AIO_PATH];
	rqst.data.create_operational_iq.element_array_addr =
	    qg->iq_element_array_bus_addr[AIO_PATH];
	rqst.data.create_operational_iq.ci_addr =
	    qg->iq_ci_bus_addr[AIO_PATH];
	rqst.data.create_operational_iq.num_elements =
	    s->s_num_elements_per_iq;
	rqst.data.create_operational_iq.element_length =
	    PQI_OPERATIONAL_IQ_ELEMENT_LENGTH / 16;
	rqst.data.create_operational_iq.queue_protocol = PQI_PROTOCOL_SOP;

	if (submit_admin_rqst_sync(s, &rqst, &rsp) == B_FALSE)
		return (B_FALSE);

	qg->iq_pi[AIO_PATH] =
	    (uint32_t *)(intptr_t)((uint64_t)(intptr_t)s->s_reg +
	    PQI_DEVICE_REGISTERS_OFFSET +
	    rsp.data.create_operational_iq.iq_pi_offset);

	/* ---- Change second queue to be AIO ---- */
	(void) memset(&rqst, 0, sizeof (rqst));
	rqst.header.iu_type = PQI_REQUEST_IU_GENERAL_ADMIN;
	rqst.header.iu_length =	PQI_GENERAL_ADMIN_IU_LENGTH;
	rqst.function_code = PQI_GENERAL_ADMIN_FUNCTION_CHANGE_IQ_PROPERTY;
	rqst.data.change_operational_iq_properties.queue_id =
	    qg->iq_id[AIO_PATH];
	rqst.data.change_operational_iq_properties.queue_id =
	    PQI_IQ_PROPERTY_IS_AIO_QUEUE;

	if (submit_admin_rqst_sync(s, &rqst, &rsp) == B_FALSE)
		return (B_FALSE);

	/* ---- Create outbound queue (device to host) ---- */
	(void) memset(&rqst, 0, sizeof (rqst));
	rqst.header.iu_type = PQI_REQUEST_IU_GENERAL_ADMIN;
	rqst.header.iu_length = PQI_GENERAL_ADMIN_IU_LENGTH;
	rqst.function_code = PQI_GENERAL_ADMIN_FUNCTION_CREATE_OQ;
	rqst.data.create_operational_oq.queue_id = qg->oq_id;
	rqst.data.create_operational_oq.element_array_addr =
	    qg->oq_element_array_bus_addr;
	rqst.data.create_operational_oq.pi_addr = qg->oq_pi_bus_addr;
	rqst.data.create_operational_oq.num_elements =
	    s->s_num_elements_per_oq;
	rqst.data.create_operational_oq.element_length =
	    PQI_OPERATIONAL_OQ_ELEMENT_LENGTH / 16;
	rqst.data.create_operational_oq.queue_protocol = PQI_PROTOCOL_SOP;
	rqst.data.create_operational_oq.int_msg_num = qg->int_msg_num;

	if (submit_admin_rqst_sync(s, &rqst, &rsp) == B_FALSE)
		return (B_FALSE);
	qg->oq_ci = (uint32_t *)(intptr_t)((uint64_t)(intptr_t)s->s_reg +
	    PQI_DEVICE_REGISTERS_OFFSET +
	    rsp.data.create_operational_oq.oq_ci_offset);

	return (B_TRUE);
}

static void
raid_sync_complete(pqi_io_request_t *io __unused, void *ctx)
{
	ksema_t *s = (ksema_t *)ctx;

	sema_v(s);
}

static boolean_t
submit_raid_sync_with_io(pqi_state_t *s, pqi_io_request_t *io)
{
	ksema_t	sema;

	sema_init(&sema, 0, NULL, SEMA_DRIVER, NULL);

	io->io_cb = raid_sync_complete;
	io->io_context = &sema;

	pqi_start_io(s, &s->s_queue_groups[PQI_DEFAULT_QUEUE_GROUP],
	    RAID_PATH, io);
	sema_p(&sema);

	switch (io->io_status) {
		case PQI_DATA_IN_OUT_GOOD:
		case PQI_DATA_IN_OUT_UNDERFLOW:
			return (B_TRUE);
		default:
			return (B_FALSE);
	}
}

static boolean_t
submit_raid_rqst_sync(pqi_state_t *s, pqi_iu_header_t *rqst,
    pqi_raid_error_info_t e_info __unused)
{
	pqi_io_request_t	*io;
	size_t			len;
	boolean_t		rval = B_FALSE; // default to error case
	struct pqi_cmd		*c;

	if ((io = pqi_alloc_io(s)) == NULL)
		return (B_FALSE);

	c = kmem_zalloc(sizeof (*c), KM_SLEEP);

	mutex_init(&c->pc_mutex, NULL, MUTEX_DRIVER, NULL);
	c->pc_io_rqst = io;
	c->pc_device = &s->s_special_device;
	c->pc_softc = s;
	io->io_cmd = c;
	(void) pqi_cmd_action(c, PQI_CMD_QUEUE);

	((pqi_raid_path_request_t *)rqst)->rp_id = PQI_MAKE_REQID(io->io_index,
	    io->io_gen);
	if (rqst->iu_type == PQI_REQUEST_IU_RAID_PATH_IO)
		((pqi_raid_path_request_t *)rqst)->rp_error_index =
		    io->io_index;
	len = rqst->iu_length + PQI_REQUEST_HEADER_LENGTH;
	(void) memcpy(io->io_iu, rqst, len);

	if (submit_raid_sync_with_io(s, io) == B_TRUE)
		rval = B_TRUE;

	(void) pqi_cmd_action(c, PQI_CMD_CMPLT);
	mutex_destroy(&c->pc_mutex);
	kmem_free(c, sizeof (*c));

	return (rval);
}

static boolean_t
build_raid_path_request(pqi_raid_path_request_t *rqst,
    int cmd, caddr_t lun, uint32_t len, int vpd_page)
{
	uint8_t		*cdb;

	(void) memset(rqst, 0, sizeof (*rqst));
	rqst->header.iu_type = PQI_REQUEST_IU_RAID_PATH_IO;
	rqst->header.iu_length = offsetof(struct pqi_raid_path_request,
	    rp_sglist[1]) - PQI_REQUEST_HEADER_LENGTH;
	rqst->rp_data_len = len;
	(void) memcpy(rqst->rp_lun, lun, sizeof (rqst->rp_lun));
	rqst->rp_task_attr = SOP_TASK_ATTRIBUTE_SIMPLE;
	rqst->rp_additional_cdb = SOP_ADDITIONAL_CDB_BYTES_0;

	cdb = rqst->rp_cdb;
	switch (cmd) {
	case SCMD_READ_CAPACITY:
		rqst->rp_data_dir = (uint8_t)SOP_READ_FLAG;
		cdb[0] = (uint8_t)cmd;
		break;

	case SCMD_READ:
		rqst->rp_data_dir = (uint8_t)SOP_READ_FLAG;
		cdb[0] = (uint8_t)cmd;
		cdb[2] = (uint8_t)(vpd_page >> 8);
		cdb[3] = (uint8_t)vpd_page;
		cdb[4] = len >> 9;
		break;

	case SCMD_MODE_SENSE:
		rqst->rp_data_dir = (uint8_t)SOP_READ_FLAG;
		cdb[0] = (uint8_t)cmd;
		cdb[1] = 0;
		cdb[2] = (uint8_t)vpd_page;
		cdb[4] = (uint8_t)len;
		break;

	case SCMD_INQUIRY:
		rqst->rp_data_dir = SOP_READ_FLAG;
		cdb[0] = (uint8_t)cmd;
		if (vpd_page & VPD_PAGE) {
			cdb[1] = 0x1;
			cdb[2] = (uint8_t)vpd_page;
		}
		cdb[4] = (uint8_t)len;
		break;

	case BMIC_IDENTIFY_PHYSICAL_DEVICE:
	case BMIC_IDENTIFY_CONTROLLER:
		rqst->rp_data_dir = SOP_READ_FLAG;
		cdb[0] = BMIC_READ;
		cdb[6] = (uint8_t)cmd;
		cdb[7] = (uint8_t)(len >> 8);
		cdb[8] = (uint8_t)len;
		break;

	case BMIC_WRITE_HOST_WELLNESS:
		rqst->rp_data_dir = SOP_WRITE_FLAG;
		cdb[0] = BMIC_WRITE;
		cdb[6] = (uint8_t)cmd;
		cdb[7] = (uint8_t)(len >> 8);
		cdb[8] = (uint8_t)len;
		break;

	case CISS_REPORT_LOG:
	case CISS_REPORT_PHYS:
		rqst->rp_data_dir = SOP_READ_FLAG;
		cdb[0] = (uint8_t)cmd;
		if (cmd == CISS_REPORT_PHYS)
			cdb[1] = CISS_REPORT_PHYS_EXTENDED;
		else
			cdb[1] = CISS_REPORT_LOG_EXTENDED;
		cdb[6] = (uint8_t)(len >> 24);
		cdb[7] = (uint8_t)(len >> 16);
		cdb[8] = (uint8_t)(len >> 8);
		cdb[9] = (uint8_t)len;
		break;

	default:
		ASSERT(0);
		break;
	}

	return (B_TRUE);
}

static boolean_t
identify_physical_device(pqi_state_t *s, pqi_device_t *devp,
    bmic_identify_physical_device_t *buf)
{
	pqi_dma_overhead_t	*dma;
	pqi_raid_path_request_t	rqst;
	boolean_t		rval = B_FALSE;
	uint16_t		idx;

	if ((dma = pqi_alloc_single(s, sizeof (*buf))) == NULL)
		return (B_FALSE);

	if (build_raid_path_request(&rqst, BMIC_IDENTIFY_PHYSICAL_DEVICE,
	    RAID_CTLR_LUNID, sizeof (*buf), 0) == B_FALSE)
		goto out;

	idx = CISS_GET_DRIVE_NUMBER(devp->pd_scsi3addr);
	rqst.rp_cdb[2] = (uint8_t)idx;
	rqst.rp_cdb[9] = (uint8_t)(idx >> 8);

	rqst.rp_sglist[0].sg_addr = dma->dma_addr;
	rqst.rp_sglist[0].sg_len = dma->len_to_alloc;
	rqst.rp_sglist[0].sg_flags = CISS_SG_LAST;

	if (submit_raid_rqst_sync(s, &rqst.header, NULL) == B_FALSE)
		goto out;

	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORCPU);
	(void) memcpy(buf, dma->alloc_memory, sizeof (*buf));
	rval = B_TRUE;
out:
	pqi_free_single(s, dma);
	return (rval);
}

static boolean_t
identify_controller(pqi_state_t *s, bmic_identify_controller_t *ident)
{
	pqi_raid_path_request_t	rqst;
	pqi_dma_overhead_t	*dma;
	boolean_t		rval = B_FALSE;

	if ((dma = pqi_alloc_single(s, sizeof (*ident))) == NULL)
		return (B_FALSE);

	if (build_raid_path_request(&rqst, BMIC_IDENTIFY_CONTROLLER,
	    RAID_CTLR_LUNID, sizeof (*ident), 0) == B_FALSE)
		goto out;

	rqst.rp_sglist[0].sg_addr = dma->dma_addr;
	rqst.rp_sglist[0].sg_len = dma->len_to_alloc;
	rqst.rp_sglist[0].sg_flags = CISS_SG_LAST;

	if (submit_raid_rqst_sync(s, &rqst.header, NULL) == B_FALSE)
		goto out;

	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORCPU);
	(void) memcpy(ident, dma->alloc_memory, sizeof (*ident));
	rval = B_TRUE;
out:
	pqi_free_single(s, dma);
	return (rval);
}

static boolean_t
write_host_wellness(pqi_state_t *s, void *buf, size_t len)
{
	pqi_dma_overhead_t	*dma;
	boolean_t		rval = B_FALSE;
	pqi_raid_path_request_t	rqst;

	if ((dma = pqi_alloc_single(s, len)) == NULL)
		return (B_FALSE);
	if (build_raid_path_request(&rqst, BMIC_WRITE_HOST_WELLNESS,
	    RAID_CTLR_LUNID, len, 0) == B_FALSE)
		goto out;

	(void) memcpy(dma->alloc_memory, buf, dma->len_to_alloc);
	rqst.rp_sglist[0].sg_addr = dma->dma_addr;
	rqst.rp_sglist[0].sg_len = dma->len_to_alloc;
	rqst.rp_sglist[0].sg_flags = CISS_SG_LAST;

	rval = submit_raid_rqst_sync(s, &rqst.header, NULL);
out:
	pqi_free_single(s, dma);
	return (rval);
}

static boolean_t
report_luns(pqi_state_t *s, int cmd, void *data, size_t len)
{
	pqi_dma_overhead_t	*dma;
	boolean_t		rval = B_FALSE;
	pqi_raid_path_request_t	rqst;

	if ((dma = pqi_alloc_single(s, len)) == NULL)
		return (B_FALSE);
	if (build_raid_path_request(&rqst, cmd, RAID_CTLR_LUNID,
	    len, 0) == B_FALSE)
		goto error_out;

	rqst.rp_sglist[0].sg_addr = dma->dma_addr;
	rqst.rp_sglist[0].sg_len = dma->len_to_alloc;
	rqst.rp_sglist[0].sg_flags = CISS_SG_LAST;

	if (submit_raid_rqst_sync(s, &rqst.header, NULL) == B_FALSE)
		goto error_out;

	(void) ddi_dma_sync(dma->handle, 0, 0, DDI_DMA_SYNC_FORCPU);
	(void) memcpy(data, dma->alloc_memory, len);
	rval = B_TRUE;

error_out:
	pqi_free_single(s, dma);
	return (rval);
}

static boolean_t
report_luns_by_cmd(pqi_state_t *s, int cmd, void **buf, size_t *buflen)
{
	void		*data		= NULL;
	size_t		data_len	= 0;
	size_t		new_data_len;
	uint32_t	new_list_len	= 0;
	uint32_t	list_len	= 0;
	boolean_t	rval		= B_FALSE;

	new_data_len = sizeof (report_lun_header_t);
	do {
		if (data != NULL) {
			kmem_free(data, data_len);
		}
		data_len = new_data_len;
		data = kmem_zalloc(data_len, KM_SLEEP);
		list_len = new_list_len;
		if (report_luns(s, cmd, data, data_len) == B_FALSE)
			goto error_out;
		new_list_len =
		    ntohl(((report_lun_header_t *)data)->list_length);
		new_data_len = sizeof (report_lun_header_t) +
		    new_list_len;
	} while (new_list_len > list_len);
	rval = B_TRUE;

error_out:
	if (rval == B_FALSE) {
		kmem_free(data, data_len);
		data = NULL;
		data_len = 0;
	}
	*buf = data;
	*buflen = data_len;
	return (rval);
}

static inline boolean_t
report_phys_luns(pqi_state_t *s, void **v, size_t *vlen)
{
	return (report_luns_by_cmd(s, CISS_REPORT_PHYS, v, vlen));
}

static inline boolean_t
report_logical_luns(pqi_state_t *s, void **v, size_t *vlen)
{
	return (report_luns_by_cmd(s, CISS_REPORT_LOG, v, vlen));
}

static boolean_t
get_device_list(pqi_state_t *s, report_phys_lun_extended_t **pl, size_t *plen,
    report_log_lun_extended_t **ll, size_t *llen)
{
	report_log_lun_extended_t	*log_data;
	report_log_lun_extended_t	*internal_log;
	size_t				list_len;
	size_t				data_len;
	report_lun_header_t		header;

	if (report_phys_luns(s, (void **)pl, plen) == B_FALSE)
		return (B_FALSE);

	if (report_logical_luns(s, (void **)ll, llen) == B_FALSE)
		return (B_FALSE);

	log_data = *ll;
	if (log_data != NULL) {
		list_len = ntohl(log_data->header.list_length);
	} else {
		(void) memset(&header, 0, sizeof (header));
		log_data = (report_log_lun_extended_t *)&header;
		list_len = 0;
	}

	data_len = sizeof (header) + list_len;
	/*
	 * Add the controller to the logical luns which is a empty device
	 */
	internal_log = kmem_zalloc(data_len +
	    sizeof (report_log_lun_extended_entry_t), KM_SLEEP);
	(void) memcpy(internal_log, log_data, data_len);
	internal_log->header.list_length = htonl(list_len +
	    sizeof (report_log_lun_extended_entry_t));

	if (*ll != NULL)
		kmem_free(*ll, *llen);
	*ll = internal_log;
	*llen = data_len + sizeof (report_log_lun_extended_entry_t);
	return (B_TRUE);
}

static boolean_t
get_device_info(pqi_state_t *s, pqi_device_t *dev)
{
	boolean_t		rval = B_FALSE;
	struct scsi_inquiry	*inq;

	inq = kmem_zalloc(sizeof (*inq), KM_SLEEP);
	if (pqi_scsi_inquiry(s, dev, 0, inq, sizeof (*inq)) == B_FALSE)
		goto out;

	dev->pd_devtype = inq->inq_dtype & 0x1f;
	(void) memcpy(dev->pd_vendor, inq->inq_vid, sizeof (dev->pd_vendor));
	(void) memcpy(dev->pd_model, inq->inq_pid, sizeof (dev->pd_model));

	rval = B_TRUE;
out:
	kmem_free(inq, sizeof (*inq));
	return (rval);
}

static boolean_t
is_supported_dev(pqi_state_t *s, pqi_device_t *dev)
{
	boolean_t	rval = B_FALSE;

	switch (dev->pd_devtype) {
	case DTYPE_DIRECT:
	case TYPE_ZBC:
	case DTYPE_SEQUENTIAL:
	case DTYPE_ESI:
		rval = B_TRUE;
		break;
	case DTYPE_ARRAY_CTRL:
		if (strncmp(dev->pd_scsi3addr, RAID_CTLR_LUNID,
		    sizeof (dev->pd_scsi3addr)) == 0)
			rval = B_TRUE;
		break;
	default:
		dev_err(s->s_dip, CE_WARN, "%s is not a supported device",
		    scsi_dname(dev->pd_devtype));
		break;
	}
	return (rval);
}

static void
get_phys_disk_info(pqi_state_t *s __unused, pqi_device_t *dev,
    bmic_identify_physical_device_t *id)
{
	dev->pd_lun = id->scsi_lun;
	(void) snprintf(dev->pd_unit_address, sizeof (dev->pd_unit_address),
	    "w%016lx,%d", dev->pd_wwid, id->scsi_lun);
}

static int
is_external_raid_addr(char *addr)
{
	return (addr[2] != 0);
}

static void
build_guid(pqi_state_t *s, pqi_device_t *d)
{
	int			len	= 0xff;
	struct scsi_inquiry	*inq	= NULL;
	uchar_t			*inq83	= NULL;
	ddi_devid_t		devid;

	ddi_devid_free_guid(d->pd_guid);
	d->pd_guid = NULL;

	inq = kmem_alloc(sizeof (struct scsi_inquiry), KM_SLEEP);
	if (pqi_scsi_inquiry(s, d, 0, inq, sizeof (struct scsi_inquiry)) ==
	    B_FALSE) {
		goto out;
	}

	inq83 = kmem_zalloc(len, KM_SLEEP);
	if (pqi_scsi_inquiry(s, d, VPD_PAGE | 0x83,
	    (struct scsi_inquiry *)inq83, len) == B_FALSE) {
		goto out;
	}

	if (ddi_devid_scsi_encode(DEVID_SCSI_ENCODE_VERSION_LATEST, NULL,
	    (uchar_t *)inq, sizeof (struct scsi_inquiry), NULL, 0, inq83,
	    (size_t)len, &devid) == DDI_SUCCESS) {
		d->pd_guid = ddi_devid_to_guid(devid);
		ddi_devid_free(devid);
	}
out:
	if (inq != NULL)
		kmem_free(inq, sizeof (struct scsi_inquiry));
	if (inq83 != NULL)
		kmem_free(inq83, len);
}

static pqi_device_t *
create_phys_dev(pqi_state_t *s, report_phys_lun_extended_entry_t *e)
{
	pqi_device_t			*dev;
	bmic_identify_physical_device_t	*id_phys	= NULL;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->pd_phys_dev = 1;
	dev->pd_wwid = htonll(e->wwid);
	(void) memcpy(dev->pd_scsi3addr, e->lunid, sizeof (dev->pd_scsi3addr));

	/* Skip masked physical devices */
	if (MASKED_DEVICE(dev->pd_scsi3addr))
		goto out;

	if (get_device_info(s, dev) == B_FALSE)
		goto out;

	if (!is_supported_dev(s, dev))
		goto out;

	switch (dev->pd_devtype) {
	case DTYPE_ESI:
		build_guid(s, dev);
		/* hopefully only LUN 0... which seems to match */
		(void) snprintf(dev->pd_unit_address, 20, "w%016lx,0",
		    dev->pd_wwid);
		break;

	case DTYPE_DIRECT:
	case TYPE_ZBC:
		build_guid(s, dev);
		id_phys = kmem_zalloc(sizeof (*id_phys), KM_SLEEP);
		if ((e->device_flags &
		    REPORT_PHYS_LUN_DEV_FLAG_AIO_ENABLED) &&
		    e->aio_handle) {

			/*
			 * XXX Until I figure out what's wrong with
			 * using AIO I'll disable this for now.
			 */
			dev->pd_aio_enabled = 0;
			dev->pd_aio_handle = e->aio_handle;
			if (identify_physical_device(s, dev,
			    id_phys) == B_FALSE)
				goto out;
		}
		get_phys_disk_info(s, dev, id_phys);
		kmem_free(id_phys, sizeof (*id_phys));
		break;
	}

	return (dev);
out:
	kmem_free(dev, sizeof (*dev));
	return (NULL);
}

static pqi_device_t *
create_logical_dev(pqi_state_t *s, report_log_lun_extended_entry_t *e)
{
	pqi_device_t	*dev;
	uint16_t	target;
	uint16_t	lun;

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->pd_phys_dev = 0;
	(void) memcpy(dev->pd_scsi3addr, e->lunid, sizeof (dev->pd_scsi3addr));
	dev->pd_external_raid = is_external_raid_addr(dev->pd_scsi3addr);

	if (get_device_info(s, dev) == B_FALSE)
		goto out;

	if (!is_supported_dev(s, dev))
		goto out;

	if (memcmp(dev->pd_scsi3addr, RAID_CTLR_LUNID, 8) == 0) {
		target = 0;
		lun = 0;
	} else if (dev->pd_external_raid) {
		target = (LE_IN16(&dev->pd_scsi3addr[2]) & 0x3FFF) + 2;
		lun = dev->pd_scsi3addr[0];
	} else {
		target = 1;
		lun = LE_IN16(dev->pd_scsi3addr);
	}
	dev->pd_target = target;
	dev->pd_lun = lun;
	(void) snprintf(dev->pd_unit_address, sizeof (dev->pd_unit_address),
	    "%d,%d", target, lun);

	(void) memcpy(dev->pd_volume_id, e->volume_id,
	    sizeof (dev->pd_volume_id));
	return (dev);

out:
	kmem_free(dev, sizeof (*dev));
	return (NULL);
}

/*
 * is_new_dev -- look to see if new_dev is indeed new.
 *
 * NOTE: This function has two outcomes. One is to determine if the new_dev
 * is truly new. The other is to mark a new_dev as being scanned if it's
 * truly new or marking the existing device as having been scanned.
 */
static boolean_t
is_new_dev(pqi_state_t *s, pqi_device_t *new_dev)
{
	pqi_device_t	*dev;

	for (dev = list_head(&s->s_devnodes); dev != NULL;
	    dev = list_next(&s->s_devnodes, dev)) {
		if (new_dev->pd_phys_dev != dev->pd_phys_dev) {
			continue;
		}
		if (dev->pd_phys_dev) {
			if (dev->pd_wwid == new_dev->pd_wwid) {
				dev->pd_scanned = 1;
				return (B_FALSE);
			}
		} else {
			if (memcmp(dev->pd_volume_id, new_dev->pd_volume_id,
			    16) == 0) {
				dev->pd_scanned = 1;
				return (B_FALSE);
			}
		}
	}

	new_dev->pd_scanned = 1;
	return (B_TRUE);
}

enum pqi_reset_action {
	PQI_RESET_ACTION_RESET = 0x1,
	PQI_RESET_ACTION_COMPLETE = 0x2
};

enum pqi_reset_type {
	PQI_RESET_TYPE_NO_RESET =	0x0,
	PQI_RESET_TYPE_SOFT_RESET =	0x1,
	PQI_RESET_TYPE_FIRM_RESET =	0x2,
	PQI_RESET_TYPE_HARD_RESET =	0x3
};

boolean_t
pqi_hba_reset(pqi_state_t *s)
{
	uint32_t	val;
	int		max_count = 1000;

	val = (PQI_RESET_ACTION_RESET << 5) | PQI_RESET_TYPE_HARD_RESET;
	S32(s, pqi_registers.device_reset, val);

	while (1) {
		drv_usecwait(100 * (MICROSEC / MILLISEC));
		val = G32(s, pqi_registers.device_reset);
		if ((val >> 5) == PQI_RESET_ACTION_COMPLETE)
			break;
		if (max_count-- == 0)
			break;
	}

#ifdef DEBUG
	cmn_err(CE_WARN, "pqi_hba_reset: reset reg=0x%x, count=%d", val,
	    max_count);
#endif
	return (pqi_wait_for_mode_ready(s));
}

static void
save_ctrl_mode(pqi_state_t *s, int mode)
{
	sis_write_scratch(s, mode);
}

static boolean_t
revert_to_sis(pqi_state_t *s)
{
	if (!pqi_hba_reset(s))
		return (B_FALSE);
	if (sis_reenable_mode(s) == B_FALSE)
		return (B_FALSE);
	sis_write_scratch(s, SIS_MODE);
	return (B_TRUE);
}


#define	BIN2BCD(x)	((((x) / 10) << 4) + (x) % 10)

static void
update_time(void *v)
{
	pqi_state_t			*s = v;
	bmic_host_wellness_time_t	*ht;
	struct timeval			curtime;
	todinfo_t			tod;

	ht = kmem_zalloc(sizeof (*ht), KM_SLEEP);
	ht->start_tag[0] = '<';
	ht->start_tag[1] = 'H';
	ht->start_tag[2] = 'W';
	ht->start_tag[3] = '>';
	ht->time_tag[0] = 'T';
	ht->time_tag[1] = 'D';
	ht->time_length = sizeof (ht->time);

	uniqtime(&curtime);
	mutex_enter(&tod_lock);
	tod = utc_to_tod(curtime.tv_sec);
	mutex_exit(&tod_lock);

	ht->time[0] = BIN2BCD(tod.tod_hour);		/* Hour */
	ht->time[1] = BIN2BCD(tod.tod_min);		/* Minute */
	ht->time[2] = BIN2BCD(tod.tod_sec);		/* Second */
	ht->time[3] = 0;
	ht->time[4] = BIN2BCD(tod.tod_month);		/* Month */
	ht->time[5] = BIN2BCD(tod.tod_day);		/* Day */
	ht->time[6] = BIN2BCD(20);			/* Century */
	ht->time[7] = BIN2BCD(tod.tod_year - 70);	/* Year w/in century */

	ht->dont_write_tag[0] = 'D';
	ht->dont_write_tag[1] = 'W';
	ht->end_tag[0] = 'Z';
	ht->end_tag[1] = 'Z';

	(void) write_host_wellness(s, ht, sizeof (*ht));
	kmem_free(ht, sizeof (*ht));
	s->s_time_of_day = timeout(update_time, s,
	    DAY * drv_usectohz(MICROSEC));
}
