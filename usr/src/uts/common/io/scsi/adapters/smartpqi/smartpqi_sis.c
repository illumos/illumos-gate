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
 * Copyright 2018 Nexenta Systems, Inc.
 */

/*
 * A few simple method to access controller when it's in the base mode.
 */
#include <smartpqi.h>

/* ---- legacy SIS interface commands ---- */
#define	SIS_CMD_GET_ADAPTER_PROPERTIES	0x19
#define	SIS_CMD_INIT_BASE_STRUCT_ADDRESS	0x1b
#define	SIS_CMD_GET_PQI_CAPABILITIES		0x3000

/* ---- used with SIS_CMD_GET_ADAPTER_PROPERTIES command ---- */
#define	SIS_EXTENDED_PROPERTIES_SUPPORTED	0x800000
#define	SIS_SMARTARRAY_FEATURES_SUPPORTED	0x2
#define	SIS_PQI_MODE_SUPPORTED			0x4
#define	SIS_REQUIRED_EXTENDED_PROPERTIES	\
	(SIS_SMARTARRAY_FEATURES_SUPPORTED | SIS_PQI_MODE_SUPPORTED)

/* used for passing command parameters/results when issuing SIS commands */
typedef struct sis_sync_cmd_params {
	uint32_t	mailbox[6];	/* mailboxes 0-5 */
} __packed sis_sync_cmd_params_t;

#define	SIS_BASE_STRUCT_REVISION	9

typedef struct sis_base_struct {
	uint32_t	sb_revision;
	uint32_t	sb_flags;
	uint32_t	sb_error_buffer_paddr_low;
	uint32_t	sb_error_buffer_paddr_high;
	uint32_t	sb_error_elements_len;
	uint32_t	sb_error_elements_num;
} __packed sis_base_struct_t;

/* ---- Forward declaration for support functions ---- */
static boolean_t sis_send_sync_cmd(pqi_state_t *s, uint32_t cmd,
    sis_sync_cmd_params_t *params);

uint32_t
sis_read_scratch(pqi_state_t *s)
{
	return (G32(s, sis_driver_scratch));
}

void
sis_write_scratch(pqi_state_t *s, int mode)
{
	S32(s, sis_driver_scratch, mode);
}

boolean_t
sis_reenable_mode(pqi_state_t *s)
{
	int		loop_count;
	uint32_t	doorbell;

	S32(s, sis_host_to_ctrl_doorbell, SIS_REENABLE_SIS_MODE);

	for (loop_count = 0; loop_count < 1000; loop_count++) {
		doorbell = G32(s, sis_ctrl_to_host_doorbell);
		if ((doorbell & SIS_REENABLE_SIS_MODE) == 0) {
			return (B_TRUE);
		}
		drv_usecwait(MICROSEC / MILLISEC); /* ---- Wait 1ms ---- */
	}
	return (B_FALSE);
}

boolean_t
sis_wait_for_ctrl_ready(pqi_state_t *s)
{
	int		loop_count;
	uint32_t	status;

	for (loop_count = 0; loop_count < 1000; loop_count++) {
		status = G32(s, sis_firmware_status);
		if (status & SIS_CTRL_KERNEL_PANIC)
			return (B_FALSE);
		if (status & SIS_CTRL_KERNEL_UP)
			return (B_TRUE);
		drv_usecwait(MICROSEC / MILLISEC); /* ---- Wait 1ms ---- */
	}
	return (B_FALSE);
}

/*
 * sis_get_ctrl_props -- Verify we're talking to controller that speaks PQI
 */
boolean_t
sis_get_ctrl_props(pqi_state_t *s)
{
	sis_sync_cmd_params_t	p;
	uint32_t		property;
	uint32_t		extended_property;

	(void) memset(&p, 0, sizeof (p));
	if (sis_send_sync_cmd(s, SIS_CMD_GET_ADAPTER_PROPERTIES, &p) == B_FALSE)
		return (B_FALSE);

	property = p.mailbox[1];
	if (!(property & SIS_EXTENDED_PROPERTIES_SUPPORTED))
		return (B_FALSE);

	extended_property = p.mailbox[4];
	if ((extended_property & SIS_REQUIRED_EXTENDED_PROPERTIES) !=
	    SIS_REQUIRED_EXTENDED_PROPERTIES)
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
sis_get_pqi_capabilities(pqi_state_t *s)
{
	sis_sync_cmd_params_t	p;

	(void) memset(&p, 0, sizeof (p));
	if (sis_send_sync_cmd(s, SIS_CMD_GET_PQI_CAPABILITIES, &p) == B_FALSE)
		return (B_FALSE);

	s->s_max_sg_entries = p.mailbox[1];
	s->s_max_xfer_size = p.mailbox[2];
	s->s_max_outstanding_requests = p.mailbox[3];
	s->s_config_table_offset = p.mailbox[4];
	s->s_config_table_len = p.mailbox[5];
	return (B_TRUE);
}

boolean_t
sis_init_base_struct_addr(pqi_state_t *s)
{
	sis_base_struct_t	*base;
	pqi_dma_overhead_t	*o;
	sis_sync_cmd_params_t	params;
	boolean_t		rc;
	void			*dma_addr;

	o = pqi_alloc_single(s, sizeof (*base) + SIS_BASE_STRUCT_ALIGNMENT);
	if (o == NULL)
		return (B_FALSE);

	base = PQIALIGN_TYPED(o->alloc_memory, SIS_BASE_STRUCT_ALIGNMENT,
	    sis_base_struct_t *);
	base->sb_revision = SIS_BASE_STRUCT_REVISION;
	base->sb_error_buffer_paddr_low = (uint32_t)s->s_error_dma->dma_addr;
	base->sb_error_buffer_paddr_high =
	    (uint32_t)(s->s_error_dma->dma_addr >> 32);
	base->sb_error_elements_len = PQI_ERROR_BUFFER_ELEMENT_LENGTH;
	base->sb_error_elements_num = s->s_max_outstanding_requests;

	dma_addr = PQIALIGN_TYPED(o->dma_addr, SIS_BASE_STRUCT_ALIGNMENT,
	    void *);
	(void) memset(&params, 0, sizeof (params));
	params.mailbox[1] = (uint32_t)(uintptr_t)dma_addr;
	params.mailbox[2] = (uint32_t)((uint64_t)((uintptr_t)dma_addr) >> 32);
	params.mailbox[3] = sizeof (*base);
	(void) ddi_dma_sync(o->handle, 0, 0, DDI_DMA_SYNC_FORDEV);
	rc = sis_send_sync_cmd(s, SIS_CMD_INIT_BASE_STRUCT_ADDRESS, &params);

	pqi_free_single(s, o);

	return (rc);
}

/*
 * Support functions for the visible legacy functions
 */
static boolean_t
sis_send_sync_cmd(pqi_state_t *s, uint32_t cmd,
    sis_sync_cmd_params_t *params)
{
	uint32_t	i;
	uint32_t	doorbell;
	uint32_t	cmd_status;

	/* Write the command to mailbox 0. */
	S32(s, sis_mailbox[0], cmd);

	/*
	 * Write the command parameters to mailboxes 1-4 (mailbox 5 is not used
	 * when sending a command to the controller).
	 */
	for (i = 1; i <= 4; i++)
		S32(s, sis_mailbox[i], params->mailbox[i]);

	/* Clear the command doorbell. */
	S32(s, sis_ctrl_to_host_doorbell_clear,
	    SIS_CLEAR_CTRL_TO_HOST_DOORBELL);

	/* Disable doorbell interrupts by masking all interrupts. */
	S32(s, sis_interrupt_mask, ~0);

	/*
	 * Force the completion of the interrupt mask register write before
	 * submitting the command.
	 */
	(void) G32(s, sis_interrupt_mask);

	/* Submit the command to the controller. */
	S32(s, sis_host_to_ctrl_doorbell, SIS_CMD_READY);

	/*
	 * Poll for command completion.  Note that the call to msleep() is at
	 * the top of the loop in order to give the controller time to start
	 * processing the command before we start polling.
	 */
	for (i = 0; i < 10000; i++) {
		drv_usecwait(MICROSEC / MILLISEC);
		doorbell = G32(s, sis_ctrl_to_host_doorbell);
		if (doorbell & SIS_CMD_COMPLETE)
			break;
	}
	if (i == 10000)
		return (B_FALSE);

	/* Read the command status from mailbox 0. */
	cmd_status = G32(s, sis_mailbox[0]);
	if (cmd_status != SIS_CMD_STATUS_SUCCESS)
		return (B_FALSE);

	/*
	 * The command completed successfully, so save the command status and
	 * read the values returned in mailboxes 1-5.
	 */
	params->mailbox[0] = cmd_status;
	for (i = 1; i < ARRAY_SIZE(params->mailbox); i++)
		params->mailbox[i] = G32(s, sis_mailbox[i]);

	return (B_TRUE);
}
