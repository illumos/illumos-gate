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

/* Copyright 2010 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"Copyright 2010 QLogic Corporation; ql_api.c"

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>
#include <ql_init.h>
#include <ql_iocb.h>
#include <ql_ioctl.h>
#include <ql_isr.h>
#include <ql_mbx.h>
#include <ql_nx.h>
#include <ql_xioctl.h>

/*
 * Solaris external defines.
 */
extern pri_t minclsyspri;
extern pri_t maxclsyspri;

/*
 * dev_ops functions prototypes
 */
static int ql_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ql_attach(dev_info_t *, ddi_attach_cmd_t);
static int ql_detach(dev_info_t *, ddi_detach_cmd_t);
static int ql_power(dev_info_t *, int, int);
static int ql_quiesce(dev_info_t *);

/*
 * FCA functions prototypes exported by means of the transport table
 */
static opaque_t ql_bind_port(dev_info_t *, fc_fca_port_info_t *,
    fc_fca_bind_info_t *);
static void ql_unbind_port(opaque_t);
static int ql_init_pkt(opaque_t, fc_packet_t *, int);
static int ql_un_init_pkt(opaque_t, fc_packet_t *);
static int ql_els_send(opaque_t, fc_packet_t *);
static int ql_get_cap(opaque_t, char *, void *);
static int ql_set_cap(opaque_t, char *, void *);
static int ql_getmap(opaque_t, fc_lilpmap_t *);
static int ql_transport(opaque_t, fc_packet_t *);
static int ql_ub_alloc(opaque_t, uint64_t *, uint32_t, uint32_t *, uint32_t);
static int ql_ub_free(opaque_t, uint32_t, uint64_t *);
static int ql_ub_release(opaque_t, uint32_t, uint64_t *);
static int ql_abort(opaque_t, fc_packet_t *, int);
static int ql_reset(opaque_t, uint32_t);
static int ql_port_manage(opaque_t, fc_fca_pm_t *);
static opaque_t ql_get_device(opaque_t, fc_portid_t);

/*
 * FCA Driver Support Function Prototypes.
 */
static uint16_t	ql_wait_outstanding(ql_adapter_state_t *);
static void ql_task_mgmt(ql_adapter_state_t *, ql_tgt_t *, fc_packet_t *,
    ql_srb_t *);
static void ql_task_daemon(void *);
static void ql_task_thread(ql_adapter_state_t *);
static void ql_unsol_callback(ql_srb_t *);
static void ql_free_unsolicited_buffer(ql_adapter_state_t *,
    fc_unsol_buf_t *);
static void ql_timer(void *);
static void ql_watchdog(ql_adapter_state_t *, uint32_t *, uint32_t *);
static void ql_cmd_timeout(ql_adapter_state_t *, ql_tgt_t *q, ql_srb_t *,
    uint32_t *, uint32_t *);
static void ql_halt(ql_adapter_state_t *, int);
static int ql_els_plogi(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_flogi(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_logo(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_prli(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_prlo(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_adisc(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_linit(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_lpc(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_lsts(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_scr(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_rscn(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_farp_req(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_farp_reply(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_rls(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_rnid(ql_adapter_state_t *, fc_packet_t *);
static int ql_login_port(ql_adapter_state_t *, port_id_t);
static int ql_login_fabric_port(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
static int ql_logout_port(ql_adapter_state_t *, port_id_t);
static ql_lun_t *ql_lun_queue(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
static int ql_fcp_scsi_cmd(ql_adapter_state_t *, fc_packet_t *, ql_srb_t *);
static int ql_fcp_ip_cmd(ql_adapter_state_t *, fc_packet_t *, ql_srb_t *);
static int ql_fc_services(ql_adapter_state_t *, fc_packet_t *);
static int ql_poll_cmd(ql_adapter_state_t *, ql_srb_t *, time_t);
static int ql_start_cmd(ql_adapter_state_t *, ql_tgt_t *, fc_packet_t *,
    ql_srb_t *);
static int ql_kstat_update(kstat_t *, int);
static ql_adapter_state_t *ql_fca_handle_to_state(opaque_t);
static ql_adapter_state_t *ql_cmd_setup(opaque_t, fc_packet_t *, int *);
static int ql_program_flash_address(ql_adapter_state_t *, uint32_t, uint8_t);
static void ql_rst_aen(ql_adapter_state_t *);
static void ql_restart_queues(ql_adapter_state_t *);
static void ql_abort_queues(ql_adapter_state_t *);
static void ql_abort_device_queues(ql_adapter_state_t *ha, ql_tgt_t *tq);
static void ql_idle_check(ql_adapter_state_t *);
static int ql_loop_resync(ql_adapter_state_t *);
static size_t ql_24xx_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static size_t ql_2581_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static int ql_save_config_regs(dev_info_t *);
static int ql_restore_config_regs(dev_info_t *);
static int ql_process_rscn(ql_adapter_state_t *, fc_affected_id_t *);
static int ql_handle_rscn_update(ql_adapter_state_t *);
static int ql_send_plogi(ql_adapter_state_t *, ql_tgt_t *, ql_head_t *);
static int ql_process_rscn_for_device(ql_adapter_state_t *, ql_tgt_t *);
static int ql_dump_firmware(ql_adapter_state_t *);
static int ql_process_logo_for_device(ql_adapter_state_t *, ql_tgt_t *);
static int ql_2200_binary_fw_dump(ql_adapter_state_t *, ql_fw_dump_t *);
static int ql_2300_binary_fw_dump(ql_adapter_state_t *, ql_fw_dump_t *);
static int ql_24xx_binary_fw_dump(ql_adapter_state_t *, ql_24xx_fw_dump_t *);
static int ql_25xx_binary_fw_dump(ql_adapter_state_t *, ql_25xx_fw_dump_t *);
static int ql_81xx_binary_fw_dump(ql_adapter_state_t *, ql_81xx_fw_dump_t *);
static int ql_read_risc_ram(ql_adapter_state_t *, uint32_t, uint32_t,
    void *);
static void *ql_read_regs(ql_adapter_state_t *, void *, void *, uint32_t,
    uint8_t);
static int ql_busy_plogi(ql_adapter_state_t *, fc_packet_t *, ql_tgt_t *);
static int ql_suspend_adapter(ql_adapter_state_t *);
static int ql_bstr_to_dec(char *, uint32_t *, uint32_t);
static void ql_update_rscn(ql_adapter_state_t *, fc_affected_id_t *);
int ql_alloc_dma_resouce(ql_adapter_state_t *, dma_mem_t *, int);
static int ql_bind_dma_buffer(ql_adapter_state_t *, dma_mem_t *, int);
static void ql_unbind_dma_buffer(ql_adapter_state_t *, dma_mem_t *);
static void ql_timeout_insert(ql_adapter_state_t *, ql_tgt_t *, ql_srb_t *);
static int ql_setup_interrupts(ql_adapter_state_t *);
static int ql_setup_msi(ql_adapter_state_t *);
static int ql_setup_msix(ql_adapter_state_t *);
static int ql_setup_fixed(ql_adapter_state_t *);
static void ql_release_intr(ql_adapter_state_t *);
static void ql_disable_intr(ql_adapter_state_t *);
static int ql_legacy_intr(ql_adapter_state_t *);
static int ql_init_mutex(ql_adapter_state_t *);
static void ql_destroy_mutex(ql_adapter_state_t *);
static void ql_iidma(ql_adapter_state_t *);

static int ql_n_port_plogi(ql_adapter_state_t *);
static void ql_fca_isp_els_request(ql_adapter_state_t *, fc_packet_t *,
    els_descriptor_t *);
static void ql_isp_els_request_ctor(els_descriptor_t *,
    els_passthru_entry_t *);
static int ql_p2p_plogi(ql_adapter_state_t *, fc_packet_t *);
static int ql_wait_for_td_stop(ql_adapter_state_t *);
static void ql_process_idc_event(ql_adapter_state_t *);

/*
 * Global data
 */
static uint8_t	ql_enable_pm = 1;
static int	ql_flash_sbus_fpga = 0;
uint32_t	ql_os_release_level;
uint32_t	ql_disable_aif = 0;
uint32_t	ql_disable_msi = 0;
uint32_t	ql_disable_msix = 0;
uint32_t	ql_enable_ets = 0;
uint16_t	ql_osc_wait_count = 1000;

/* Timer routine variables. */
static timeout_id_t	ql_timer_timeout_id = NULL;
static clock_t		ql_timer_ticks;

/* Soft state head pointer. */
void *ql_state = NULL;

/* Head adapter link. */
ql_head_t ql_hba = {
	NULL,
	NULL
};

/* Global hba index */
uint32_t ql_gfru_hba_index = 1;

/*
 * Some IP defines and globals
 */
uint32_t	ql_ip_buffer_count = 128;
uint32_t	ql_ip_low_water = 10;
uint8_t		ql_ip_fast_post_count = 5;
static int	ql_ip_mtu = 65280;		/* equivalent to FCIPMTU */

/* Device AL_PA to Device Head Queue index array. */
uint8_t ql_alpa_to_index[] = {
	0x7e, 0x7d, 0x7c, 0x00, 0x7b, 0x01, 0x02, 0x03, 0x7a, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x79, 0x78, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x77, 0x76, 0x10, 0x11, 0x75, 0x12, 0x74,
	0x73, 0x72, 0x13, 0x14, 0x15, 0x71, 0x16, 0x70, 0x6f, 0x6e,
	0x17, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x18, 0x19, 0x67,
	0x66, 0x65, 0x64, 0x63, 0x62, 0x20, 0x21, 0x61, 0x60, 0x23,
	0x5f, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x5e, 0x2a, 0x5d,
	0x5c, 0x5b, 0x2b, 0x5a, 0x59, 0x58, 0x57, 0x56, 0x55, 0x2c,
	0x2d, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4f, 0x2e, 0x2f, 0x4e,
	0x4d, 0x30, 0x4c, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x4b,
	0x37, 0x4a, 0x49, 0x48, 0x38, 0x47, 0x46, 0x45, 0x44, 0x43,
	0x42, 0x39, 0x3a, 0x41, 0x40, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b,
	0x3c, 0x3b, 0x3a, 0x3d, 0x39, 0x3e, 0x3f, 0x40, 0x38, 0x37,
	0x36, 0x41, 0x35, 0x42, 0x43, 0x44, 0x34, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x33, 0x32, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x31, 0x30, 0x51, 0x52, 0x2f, 0x53, 0x2e, 0x2d, 0x2c,
	0x54, 0x55, 0x56, 0x2b, 0x57, 0x2a, 0x29, 0x28, 0x58, 0x27,
	0x26, 0x25, 0x24, 0x23, 0x22, 0x59, 0x5a, 0x21, 0x20, 0x1f,
	0x1e, 0x1d, 0x1c, 0x5b, 0x5c, 0x1b, 0x1a, 0x5d, 0x19, 0x5e,
	0x5f, 0x60, 0x61, 0x62, 0x63, 0x18, 0x64, 0x17, 0x16, 0x15,
	0x65, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x66, 0x67, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x68, 0x69, 0x08, 0x07, 0x6a,
	0x06, 0x6b, 0x6c, 0x6d, 0x05, 0x04, 0x03, 0x6e, 0x02, 0x6f,
	0x70, 0x71, 0x01, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x00,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7f, 0x80, 0x00, 0x01,
	0x02, 0x03, 0x80, 0x7f, 0x7e, 0x04
};

/* Device loop_id to ALPA array. */
static uint8_t ql_index_to_alpa[] = {
	0xef, 0xe8, 0xe4, 0xe2, 0xe1, 0xe0, 0xdc, 0xda, 0xd9, 0xd6,
	0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xce, 0xcd, 0xcc, 0xcb, 0xca,
	0xc9, 0xc7, 0xc6, 0xc5, 0xc3, 0xbc, 0xba, 0xb9, 0xb6, 0xb5,
	0xb4, 0xb3, 0xb2, 0xb1, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9,
	0xa7, 0xa6, 0xa5, 0xa3, 0x9f, 0x9e, 0x9d, 0x9b, 0x98, 0x97,
	0x90, 0x8f, 0x88, 0x84, 0x82, 0x81, 0x80, 0x7c, 0x7a, 0x79,
	0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x6e, 0x6d, 0x6c, 0x6b,
	0x6a, 0x69, 0x67, 0x66, 0x65, 0x63, 0x5c, 0x5a, 0x59, 0x56,
	0x55, 0x54, 0x53, 0x52, 0x51, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a,
	0x49, 0x47, 0x46, 0x45, 0x43, 0x3c, 0x3a, 0x39, 0x36, 0x35,
	0x34, 0x33, 0x32, 0x31, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29,
	0x27, 0x26, 0x25, 0x23, 0x1f, 0x1e, 0x1d, 0x1b, 0x18, 0x17,
	0x10, 0x0f, 0x08, 0x04, 0x02, 0x01
};

/* 2200 register offsets */
static reg_off_t reg_off_2200 = {
	0x00,	/* flash_address */
	0x02,	/* flash_data */
	0x06,	/* ctrl_status */
	0x08,	/* ictrl */
	0x0a,	/* istatus */
	0x0c,	/* semaphore */
	0x0e,	/* nvram */
	0x18,	/* req_in */
	0x18,	/* req_out */
	0x1a,	/* resp_in */
	0x1a,	/* resp_out */
	0xff,	/* risc2host - n/a */
	24,	/* Number of mailboxes */

	/* Mailbox in register offsets 0 - 23 */
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
	0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	/* 2200 does not have mailbox 24-31 - n/a */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

	/* Mailbox out register offsets 0 - 23 */
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
	0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	/* 2200 does not have mailbox 24-31 - n/a */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

	0x96,	/* fpm_diag_config */
	0xa4,	/* pcr */
	0xb0,	/* mctr */
	0xb8,	/* fb_cmd */
	0xc0,	/* hccr */
	0xcc,	/* gpiod */
	0xce,	/* gpioe */
	0xff,	/* host_to_host_sema - n/a */
	0xff,	/* pri_req_in - n/a */
	0xff,	/* pri_req_out - n/a */
	0xff,	/* atio_req_in - n/a */
	0xff,	/* atio_req_out - n/a */
	0xff,	/* io_base_addr - n/a */
	0xff,	/* nx_host_int - n/a */
	0xff	/* nx_risc_int - n/a */
};

/* 2300 register offsets */
static reg_off_t reg_off_2300 = {
	0x00,	/* flash_address */
	0x02,	/* flash_data */
	0x06,	/* ctrl_status */
	0x08,	/* ictrl */
	0x0a,	/* istatus */
	0x0c,	/* semaphore */
	0x0e,	/* nvram */
	0x10,	/* req_in */
	0x12,	/* req_out */
	0x14,	/* resp_in */
	0x16,	/* resp_out */
	0x18,	/* risc2host */
	32,	/* Number of mailboxes */

	/* Mailbox in register offsets 0 - 31 */
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,

	/* Mailbox out register offsets 0 - 31 */
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,

	0x96,	/* fpm_diag_config */
	0xa4,	/* pcr */
	0xb0,	/* mctr */
	0x80,	/* fb_cmd */
	0xc0,	/* hccr */
	0xcc,	/* gpiod */
	0xce,	/* gpioe */
	0x1c,	/* host_to_host_sema */
	0xff,	/* pri_req_in - n/a */
	0xff,	/* pri_req_out - n/a */
	0xff,	/* atio_req_in - n/a */
	0xff,	/* atio_req_out - n/a */
	0xff,	/* io_base_addr - n/a */
	0xff,	/* nx_host_int - n/a */
	0xff	/* nx_risc_int - n/a */
};

/* 2400/2500 register offsets */
reg_off_t reg_off_2400_2500 = {
	0x00,	/* flash_address */
	0x04,	/* flash_data */
	0x08,	/* ctrl_status */
	0x0c,	/* ictrl */
	0x10,	/* istatus */
	0xff,	/* semaphore - n/a */
	0xff,	/* nvram - n/a */
	0x1c,	/* req_in */
	0x20,	/* req_out */
	0x24,	/* resp_in */
	0x28,	/* resp_out */
	0x44,	/* risc2host */
	32,	/* Number of mailboxes */

	/* Mailbox in register offsets 0 - 31 */
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
	0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,

	/* Mailbox out register offsets 0 - 31 */
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
	0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,

	0xff,	/* fpm_diag_config  - n/a */
	0xff,	/* pcr - n/a */
	0xff,	/* mctr - n/a */
	0xff,	/* fb_cmd - n/a */
	0x48,	/* hccr */
	0x4c,	/* gpiod */
	0x50,	/* gpioe */
	0xff,	/* host_to_host_sema - n/a */
	0x2c,	/* pri_req_in */
	0x30,	/* pri_req_out */
	0x3c,	/* atio_req_in */
	0x40,	/* atio_req_out */
	0x54,	/* io_base_addr */
	0xff,	/* nx_host_int - n/a */
	0xff	/* nx_risc_int - n/a */
};

/* P3 register offsets */
static reg_off_t reg_off_8021 = {
	0x00,	/* flash_address */
	0x04,	/* flash_data */
	0x08,	/* ctrl_status */
	0x0c,	/* ictrl */
	0x10,	/* istatus */
	0xff,	/* semaphore - n/a */
	0xff,	/* nvram - n/a */
	0xff,	/* req_in - n/a */
	0x0,	/* req_out */
	0x100,	/* resp_in */
	0x200,	/* resp_out */
	0x500,	/* risc2host */
	32,	/* Number of mailboxes */

	/* Mailbox in register offsets 0 - 31 */
	0x300, 0x302, 0x304, 0x306, 0x308, 0x30a, 0x30c, 0x30e,
	0x310, 0x312, 0x314, 0x316, 0x318, 0x31a, 0x31c, 0x31e,
	0x320, 0x322, 0x324, 0x326, 0x328, 0x32a, 0x32c, 0x32e,
	0x330, 0x332, 0x334, 0x336, 0x338, 0x33a, 0x33c, 0x33e,

	/* Mailbox out register offsets 0 - 31 */
	0x400, 0x402, 0x404, 0x406, 0x408, 0x40a, 0x40c, 0x40e,
	0x410, 0x412, 0x414, 0x416, 0x418, 0x41a, 0x41c, 0x41e,
	0x420, 0x422, 0x424, 0x426, 0x428, 0x42a, 0x42c, 0x42e,
	0x430, 0x432, 0x434, 0x436, 0x438, 0x43a, 0x43c, 0x43e,

	0xff,	/* fpm_diag_config  - n/a */
	0xff,	/* pcr - n/a */
	0xff,	/* mctr - n/a */
	0xff,	/* fb_cmd - n/a */
	0x48,	/* hccr */
	0x4c,	/* gpiod */
	0x50,	/* gpioe */
	0xff,	/* host_to_host_sema - n/a */
	0x2c,	/* pri_req_in */
	0x30,	/* pri_req_out */
	0x3c,	/* atio_req_in */
	0x40,	/* atio_req_out */
	0x54,	/* io_base_addr */
	0x380,	/* nx_host_int */
	0x504	/* nx_risc_int */
};

/* mutex for protecting variables shared by all instances of the driver */
kmutex_t ql_global_mutex;
kmutex_t ql_global_hw_mutex;
kmutex_t ql_global_el_mutex;

/* DMA access attribute structure. */
static ddi_device_acc_attr_t ql_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* I/O DMA attributes structures. */
static ddi_dma_attr_t ql_64bit_io_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	QL_DMA_LOW_ADDRESS,		/* low DMA address range */
	QL_DMA_HIGH_64BIT_ADDRESS,	/* high DMA address range */
	QL_DMA_XFER_COUNTER,		/* DMA counter register */
	QL_DMA_ADDRESS_ALIGNMENT,	/* DMA address alignment */
	QL_DMA_BURSTSIZES,		/* DMA burstsizes */
	QL_DMA_MIN_XFER_SIZE,		/* min effective DMA size */
	QL_DMA_MAX_XFER_SIZE,		/* max DMA xfer size */
	QL_DMA_SEGMENT_BOUNDARY,	/* segment boundary */
	QL_DMA_SG_LIST_LENGTH,		/* s/g list length */
	QL_DMA_GRANULARITY,		/* granularity of device */
	QL_DMA_XFER_FLAGS		/* DMA transfer flags */
};

static ddi_dma_attr_t ql_32bit_io_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	QL_DMA_LOW_ADDRESS,		/* low DMA address range */
	QL_DMA_HIGH_32BIT_ADDRESS,	/* high DMA address range */
	QL_DMA_XFER_COUNTER,		/* DMA counter register */
	QL_DMA_ADDRESS_ALIGNMENT,	/* DMA address alignment */
	QL_DMA_BURSTSIZES,		/* DMA burstsizes */
	QL_DMA_MIN_XFER_SIZE,		/* min effective DMA size */
	QL_DMA_MAX_XFER_SIZE,		/* max DMA xfer size */
	QL_DMA_SEGMENT_BOUNDARY,	/* segment boundary */
	QL_DMA_SG_LIST_LENGTH,		/* s/g list length */
	QL_DMA_GRANULARITY,		/* granularity of device */
	QL_DMA_XFER_FLAGS		/* DMA transfer flags */
};

/* Load the default dma attributes */
static	ddi_dma_attr_t	ql_32fcsm_cmd_dma_attr;
static	ddi_dma_attr_t	ql_64fcsm_cmd_dma_attr;
static	ddi_dma_attr_t	ql_32fcsm_rsp_dma_attr;
static	ddi_dma_attr_t	ql_64fcsm_rsp_dma_attr;
static	ddi_dma_attr_t	ql_32fcip_cmd_dma_attr;
static	ddi_dma_attr_t	ql_64fcip_cmd_dma_attr;
static	ddi_dma_attr_t	ql_32fcip_rsp_dma_attr;
static	ddi_dma_attr_t	ql_64fcip_rsp_dma_attr;
static	ddi_dma_attr_t	ql_32fcp_cmd_dma_attr;
static	ddi_dma_attr_t	ql_64fcp_cmd_dma_attr;
static	ddi_dma_attr_t	ql_32fcp_rsp_dma_attr;
static	ddi_dma_attr_t	ql_64fcp_rsp_dma_attr;
static	ddi_dma_attr_t	ql_32fcp_data_dma_attr;
static	ddi_dma_attr_t	ql_64fcp_data_dma_attr;

/* Static declarations of cb_ops entry point functions... */
static struct cb_ops ql_cb_ops = {
	ql_open,			/* b/c open */
	ql_close,			/* b/c close */
	nodev,				/* b strategy */
	nodev,				/* b print */
	nodev,				/* b dump */
	nodev,				/* c read */
	nodev,				/* c write */
	ql_ioctl,			/* c ioctl */
	nodev,				/* c devmap */
	nodev,				/* c mmap */
	nodev,				/* c segmap */
	nochpoll,			/* c poll */
	nodev,				/* cb_prop_op */
	NULL,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* cb_ops revision */
	nodev,				/* c aread */
	nodev				/* c awrite */
};

/* Static declarations of dev_ops entry point functions... */
static struct dev_ops ql_devops = {
	DEVO_REV,			/* devo_rev */
	0,				/* refcnt */
	ql_getinfo,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	ql_attach,			/* attach */
	ql_detach,			/* detach */
	nodev,				/* reset */
	&ql_cb_ops,			/* char/block ops */
	NULL,				/* bus operations */
	ql_power,			/* power management */
	ql_quiesce			/* quiesce device */
};

/* ELS command code to text converter */
cmd_table_t els_cmd_tbl[] = ELS_CMD_TABLE();
/* Mailbox command code to text converter */
cmd_table_t mbox_cmd_tbl[] = MBOX_CMD_TABLE();

char qlc_driver_version[] = QL_VERSION;

/*
 * Loadable Driver Interface Structures.
 * Declare and initialize the module configuration section...
 */
static struct modldrv modldrv = {
	&mod_driverops,				/* type of module: driver */
	"SunFC Qlogic FCA v" QL_VERSION,	/* name of module */
	&ql_devops				/* driver dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* ************************************************************************ */
/*				Loadable Module Routines.		    */
/* ************************************************************************ */

/*
 * _init
 *	Initializes a loadable module. It is called before any other
 *	routine in a loadable module.
 *
 * Returns:
 *	0 = success
 *
 * Context:
 *	Kernel context.
 */
int
_init(void)
{
	uint16_t	w16;
	int		rval = 0;

	/* Get OS major release level. */
	for (w16 = 0; w16 < sizeof (utsname.release); w16++) {
		if (utsname.release[w16] == '.') {
			w16++;
			break;
		}
	}
	if (w16 < sizeof (utsname.release)) {
		(void) ql_bstr_to_dec(&utsname.release[w16],
		    &ql_os_release_level, 0);
	} else {
		ql_os_release_level = 0;
	}
	if (ql_os_release_level < 6) {
		cmn_err(CE_WARN, "%s Unsupported OS release level = %d",
		    QL_NAME, ql_os_release_level);
		rval = EINVAL;
	}
	if (ql_os_release_level == 6) {
		ql_32bit_io_dma_attr.dma_attr_count_max = 0x00ffffff;
		ql_64bit_io_dma_attr.dma_attr_count_max = 0x00ffffff;
	}

	if (rval == 0) {
		rval = ddi_soft_state_init(&ql_state,
		    sizeof (ql_adapter_state_t), 0);
	}
	if (rval == 0) {
		/* allow the FC Transport to tweak the dev_ops */
		fc_fca_init(&ql_devops);

		mutex_init(&ql_global_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&ql_global_hw_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&ql_global_el_mutex, NULL, MUTEX_DRIVER, NULL);
		rval = mod_install(&modlinkage);
		if (rval != 0) {
			mutex_destroy(&ql_global_hw_mutex);
			mutex_destroy(&ql_global_mutex);
			mutex_destroy(&ql_global_el_mutex);
			ddi_soft_state_fini(&ql_state);
		} else {
			/*EMPTY*/
			ql_32fcsm_cmd_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcsm_cmd_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcsm_rsp_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcsm_rsp_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcip_cmd_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcip_cmd_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcip_rsp_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcip_rsp_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcp_cmd_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcp_cmd_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcp_rsp_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcp_rsp_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcp_data_dma_attr = ql_32bit_io_dma_attr;
			ql_64fcp_data_dma_attr = ql_64bit_io_dma_attr;
			ql_32fcsm_cmd_dma_attr.dma_attr_sgllen =
			    ql_64fcsm_cmd_dma_attr.dma_attr_sgllen =
			    QL_FCSM_CMD_SGLLEN;
			ql_32fcsm_rsp_dma_attr.dma_attr_sgllen =
			    ql_64fcsm_rsp_dma_attr.dma_attr_sgllen =
			    QL_FCSM_RSP_SGLLEN;
			ql_32fcip_cmd_dma_attr.dma_attr_sgllen =
			    ql_64fcip_cmd_dma_attr.dma_attr_sgllen =
			    QL_FCIP_CMD_SGLLEN;
			ql_32fcip_rsp_dma_attr.dma_attr_sgllen =
			    ql_64fcip_rsp_dma_attr.dma_attr_sgllen =
			    QL_FCIP_RSP_SGLLEN;
			ql_32fcp_cmd_dma_attr.dma_attr_sgllen =
			    ql_64fcp_cmd_dma_attr.dma_attr_sgllen =
			    QL_FCP_CMD_SGLLEN;
			ql_32fcp_rsp_dma_attr.dma_attr_sgllen =
			    ql_64fcp_rsp_dma_attr.dma_attr_sgllen =
			    QL_FCP_RSP_SGLLEN;
		}
	}

	if (rval != 0) {
		cmn_err(CE_CONT, "?Unable to install/attach driver '%s'",
		    QL_NAME);
	}

	return (rval);
}

/*
 * _fini
 *	Prepares a module for unloading. It is called when the system
 *	wants to unload a module. If the module determines that it can
 *	be unloaded, then _fini() returns the value returned by
 *	mod_remove(). Upon successful return from _fini() no other
 *	routine in the module will be called before _init() is called.
 *
 * Returns:
 *	0 = success
 *
 * Context:
 *	Kernel context.
 */
int
_fini(void)
{
	int	rval;

	rval = mod_remove(&modlinkage);
	if (rval == 0) {
		mutex_destroy(&ql_global_hw_mutex);
		mutex_destroy(&ql_global_mutex);
		mutex_destroy(&ql_global_el_mutex);
		ddi_soft_state_fini(&ql_state);
	}

	return (rval);
}

/*
 * _info
 *	Returns information about loadable module.
 *
 * Input:
 *	modinfo = pointer to module information structure.
 *
 * Returns:
 *	Value returned by mod_info().
 *
 * Context:
 *	Kernel context.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ************************************************************************ */
/*			dev_ops functions				    */
/* ************************************************************************ */

/*
 * ql_getinfo
 *	Returns the pointer associated with arg when cmd is
 *	set to DDI_INFO_DEVT2DEVINFO, or it should return the
 *	instance number associated with arg when cmd is set
 *	to DDI_INFO_DEV2INSTANCE.
 *
 * Input:
 *	dip = Do not use.
 *	cmd = command argument.
 *	arg = command specific argument.
 *	resultp = pointer to where request information is stored.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	ql_adapter_state_t	*ha;
	int			minor;
	int			rval = DDI_FAILURE;

	minor = (int)(getminor((dev_t)arg));
	ha = ddi_get_soft_state(ql_state, minor);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, unknown minor=%d\n",
		    getminor((dev_t)arg));
		*resultp = NULL;
		return (rval);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = ha->dip;
		rval = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)(ha->instance);
		rval = DDI_SUCCESS;
		break;
	default:
		EL(ha, "failed, unsupported cmd=%d\n", cmd);
		rval = DDI_FAILURE;
		break;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_attach
 *	Configure and attach an instance of the driver
 *	for a port.
 *
 * Input:
 *	dip = pointer to device information structure.
 *	cmd = attach type.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	off_t			regsize;
	uint32_t		size;
	int			rval, *ptr;
	int			instance;
	uint_t			progress = 0;
	char			*buf;
	ushort_t		caps_ptr, cap;
	fc_fca_tran_t		*tran;
	ql_adapter_state_t	*ha = NULL;

	static char *pmcomps[] = {
		NULL,
		PM_LEVEL_D3_STR,		/* Device OFF */
		PM_LEVEL_D0_STR,		/* Device ON */
	};

	QL_PRINT_3(CE_CONT, "(%d): started, cmd=%xh\n",
	    ddi_get_instance(dip), cmd);

	buf = (char *)(kmem_zalloc(MAXPATHLEN, KM_SLEEP));

	switch (cmd) {
	case DDI_ATTACH:
		/* first get the instance */
		instance = ddi_get_instance(dip);

		cmn_err(CE_CONT, "!Qlogic %s(%d) FCA Driver v%s\n",
		    QL_NAME, instance, QL_VERSION);

		/* Correct OS version? */
		if (ql_os_release_level != 11) {
			cmn_err(CE_WARN, "%s(%d): This driver is for Solaris "
			    "11", QL_NAME, instance);
			goto attach_failed;
		}

		/* Hardware is installed in a DMA-capable slot? */
		if (ddi_slaveonly(dip) == DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): slave only", QL_NAME,
			    instance);
			goto attach_failed;
		}

		/* No support for high-level interrupts */
		if (ddi_intr_hilevel(dip, 0) != 0) {
			cmn_err(CE_WARN, "%s(%d): High level interrupt"
			    " not supported", QL_NAME, instance);
			goto attach_failed;
		}

		/* Allocate our per-device-instance structure */
		if (ddi_soft_state_zalloc(ql_state,
		    instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): soft state alloc failed",
			    QL_NAME, instance);
			goto attach_failed;
		}
		progress |= QL_SOFT_STATE_ALLOCED;

		ha = ddi_get_soft_state(ql_state, instance);
		if (ha == NULL) {
			cmn_err(CE_WARN, "%s(%d): can't get soft state",
			    QL_NAME, instance);
			goto attach_failed;
		}
		ha->dip = dip;
		ha->instance = instance;
		ha->hba.base_address = ha;
		ha->pha = ha;

		if (ql_el_trace_desc_ctor(ha) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): can't setup el tracing",
			    QL_NAME, instance);
			goto attach_failed;
		}

		/* Get extended logging and dump flags. */
		ql_common_properties(ha);

		if (strcmp(ddi_driver_name(ddi_get_parent(dip)),
		    "sbus") == 0) {
			EL(ha, "%s SBUS card detected", QL_NAME);
			ha->cfg_flags |= CFG_SBUS_CARD;
		}

		ha->dev = kmem_zalloc(sizeof (*ha->dev) *
		    DEVICE_HEAD_LIST_SIZE, KM_SLEEP);

		ha->outstanding_cmds = kmem_zalloc(
		    sizeof (*ha->outstanding_cmds) * MAX_OUTSTANDING_COMMANDS,
		    KM_SLEEP);

		ha->ub_array = kmem_zalloc(sizeof (*ha->ub_array) *
		    QL_UB_LIMIT, KM_SLEEP);

		ha->adapter_stats = kmem_zalloc(sizeof (*ha->adapter_stats),
		    KM_SLEEP);

		(void) ddi_pathname(dip, buf);
		ha->devpath = kmem_zalloc(strlen(buf)+1, KM_SLEEP);
		if (ha->devpath == NULL) {
			EL(ha, "devpath mem alloc failed\n");
		} else {
			(void) strcpy(ha->devpath, buf);
			EL(ha, "devpath is: %s\n", ha->devpath);
		}

		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			/*
			 * For cards where PCI is mapped to sbus e.g. Ivory.
			 *
			 * 0x00	: 0x000 - 0x0FF PCI Config Space for 2200
			 *	: 0x100 - 0x3FF PCI IO space for 2200
			 * 0x01	: 0x000 - 0x0FF PCI Config Space for fpga
			 *	: 0x100 - 0x3FF PCI IO Space for fpga
			 */
			if (ddi_regs_map_setup(dip, 0, (caddr_t *)&ha->iobase,
			    0x100, 0x300, &ql_dev_acc_attr, &ha->dev_handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): Unable to map device"
				    " registers", QL_NAME, instance);
				goto attach_failed;
			}
			if (ddi_regs_map_setup(dip, 1,
			    (caddr_t *)&ha->sbus_fpga_iobase, 0, 0x400,
			    &ql_dev_acc_attr, &ha->sbus_fpga_dev_handle) !=
			    DDI_SUCCESS) {
				/* We should not fail attach here */
				cmn_err(CE_WARN, "%s(%d): Unable to map FPGA",
				    QL_NAME, instance);
				ha->sbus_fpga_iobase = NULL;
			}
			progress |= QL_REGS_MAPPED;

			/*
			 * We should map config space before adding interrupt
			 * So that the chip type (2200 or 2300) can be
			 * determined before the interrupt routine gets a
			 * chance to execute.
			 */
			if (ddi_regs_map_setup(dip, 0,
			    (caddr_t *)&ha->sbus_config_base, 0, 0x100,
			    &ql_dev_acc_attr, &ha->sbus_config_handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): Unable to map sbus "
				    "config registers", QL_NAME, instance);
				goto attach_failed;
			}
			progress |= QL_CONFIG_SPACE_SETUP;
		} else {
			/*LINTED [Solaris DDI_DEV_T_ANY Lint error]*/
			rval = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "reg", &ptr, &size);
			if (rval != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): Unable to get PCI "
				    "address registers", QL_NAME, instance);
				goto attach_failed;
			} else {
				ha->pci_bus_addr = ptr[0];
				ha->function_number = (uint8_t)
				    (ha->pci_bus_addr >> 8 & 7);
				ddi_prop_free(ptr);
			}

			/*
			 * We should map config space before adding interrupt
			 * So that the chip type (2200 or 2300) can be
			 * determined before the interrupt routine gets a
			 * chance to execute.
			 */
			if (pci_config_setup(ha->dip, &ha->pci_handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): can't setup PCI "
				    "config space", QL_NAME, instance);
				goto attach_failed;
			}
			progress |= QL_CONFIG_SPACE_SETUP;

			/*
			 * Setup the ISP2200 registers address mapping to be
			 * accessed by this particular driver.
			 * 0x0   Configuration Space
			 * 0x1   I/O Space
			 * 0x2   32-bit Memory Space address
			 * 0x3   64-bit Memory Space address
			 */
			size = ql_pci_config_get32(ha, PCI_CONF_BASE0) & BIT_0 ?
			    2 : 1;
			if (ddi_dev_regsize(dip, size, &regsize) !=
			    DDI_SUCCESS ||
			    ddi_regs_map_setup(dip, size, &ha->iobase,
			    0, regsize, &ql_dev_acc_attr, &ha->dev_handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): regs_map_setup(mem) "
				    "failed", QL_NAME, instance);
				goto attach_failed;
			}
			progress |= QL_REGS_MAPPED;

			/*
			 * We need I/O space mappings for 23xx HBAs for
			 * loading flash (FCode). The chip has a bug due to
			 * which loading flash fails through mem space
			 * mappings in PCI-X mode.
			 */
			if (size == 1) {
				ha->iomap_iobase = ha->iobase;
				ha->iomap_dev_handle = ha->dev_handle;
			} else {
				if (ddi_dev_regsize(dip, 1, &regsize) !=
				    DDI_SUCCESS ||
				    ddi_regs_map_setup(dip, 1,
				    &ha->iomap_iobase, 0, regsize,
				    &ql_dev_acc_attr, &ha->iomap_dev_handle) !=
				    DDI_SUCCESS) {
					cmn_err(CE_WARN, "%s(%d): regs_map_"
					    "setup(I/O) failed", QL_NAME,
					    instance);
					goto attach_failed;
				}
				progress |= QL_IOMAP_IOBASE_MAPPED;
			}
		}

		ha->subsys_id = (uint16_t)ql_pci_config_get16(ha,
		    PCI_CONF_SUBSYSID);
		ha->subven_id = (uint16_t)ql_pci_config_get16(ha,
		    PCI_CONF_SUBVENID);
		ha->ven_id = (uint16_t)ql_pci_config_get16(ha,
		    PCI_CONF_VENID);
		ha->device_id = (uint16_t)ql_pci_config_get16(ha,
		    PCI_CONF_DEVID);
		ha->rev_id = (uint8_t)ql_pci_config_get8(ha,
		    PCI_CONF_REVID);

		EL(ha, "ISP%x chip detected (RevID=%x, VenID=%x, SVenID=%x, "
		    "SSysID=%x)\n", ha->device_id, ha->rev_id, ha->ven_id,
		    ha->subven_id, ha->subsys_id);

		switch (ha->device_id) {
		case 0x2300:
		case 0x2312:
		case 0x2322:
		case 0x6312:
		case 0x6322:
			if (ql_pci_config_get8(ha, PCI_CONF_IPIN) == 2) {
				ha->flags |= FUNCTION_1;
			}
			if ((ha->device_id == 0x6322) ||
			    (ha->device_id == 0x2322)) {
				ha->cfg_flags |= CFG_CTRL_6322;
				ha->fw_class = 0x6322;
				ha->risc_dump_size = QL_6322_FW_DUMP_SIZE;
			} else {
				ha->cfg_flags |= CFG_CTRL_2300;
				ha->fw_class = 0x2300;
				ha->risc_dump_size = QL_2300_FW_DUMP_SIZE;
			}
			ha->reg_off = &reg_off_2300;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->fcp_cmd = ql_command_iocb;
			ha->ip_cmd = ql_ip_iocb;
			ha->ms_cmd = ql_ms_iocb;
			if (CFG_IST(ha, CFG_SBUS_CARD)) {
				ha->cmd_segs = CMD_TYPE_2_DATA_SEGMENTS;
				ha->cmd_cont_segs = CONT_TYPE_0_DATA_SEGMENTS;
			} else {
				ha->cmd_segs = CMD_TYPE_3_DATA_SEGMENTS;
				ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			}
			break;

		case 0x2200:
			ha->cfg_flags |= CFG_CTRL_2200;
			ha->reg_off = &reg_off_2200;
			ha->fw_class = 0x2200;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_2200_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_iocb;
			ha->ip_cmd = ql_ip_iocb;
			ha->ms_cmd = ql_ms_iocb;
			if (CFG_IST(ha, CFG_SBUS_CARD)) {
				ha->cmd_segs = CMD_TYPE_2_DATA_SEGMENTS;
				ha->cmd_cont_segs = CONT_TYPE_0_DATA_SEGMENTS;
			} else {
				ha->cmd_segs = CMD_TYPE_3_DATA_SEGMENTS;
				ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			}
			break;

		case 0x2422:
		case 0x2432:
		case 0x5422:
		case 0x5432:
		case 0x8432:
			if (ql_pci_config_get8(ha, PCI_CONF_IPIN) == 2) {
				ha->flags |= FUNCTION_1;
			}
			ha->cfg_flags |= CFG_CTRL_2422;
			if (ha->device_id == 0x8432) {
				ha->cfg_flags |= CFG_CTRL_MENLO;
			} else {
				ha->flags |= VP_ENABLED;
			}

			ha->reg_off = &reg_off_2400_2500;
			ha->fw_class = 0x2400;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_24XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ip_cmd = ql_ip_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->els_cmd = ql_els_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			break;

		case 0x2522:
		case 0x2532:
			if (ql_pci_config_get8(ha, PCI_CONF_IPIN) == 2) {
				ha->flags |= FUNCTION_1;
			}
			ha->cfg_flags |= CFG_CTRL_25XX;
			ha->flags |= VP_ENABLED;
			ha->fw_class = 0x2500;
			ha->reg_off = &reg_off_2400_2500;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_25XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ip_cmd = ql_ip_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->els_cmd = ql_els_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			break;

		case 0x8001:
			if (ql_pci_config_get8(ha, PCI_CONF_IPIN) == 4) {
				ha->flags |= FUNCTION_1;
			}
			ha->cfg_flags |= CFG_CTRL_81XX;
			ha->flags |= VP_ENABLED;
			ha->fw_class = 0x8100;
			ha->reg_off = &reg_off_2400_2500;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_25XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ip_cmd = ql_ip_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			break;

		case 0x8021:
			if (ha->function_number & BIT_0) {
				ha->flags |= FUNCTION_1;
			}
			ha->cfg_flags |= CFG_CTRL_8021;
			ha->reg_off = &reg_off_8021;
			ha->risc_dump_size = QL_25XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;

			ha->nx_pcibase = ha->iobase;
			ha->iobase += 0xBC000 + (ha->function_number << 11);
			ha->iomap_iobase += 0xBC000 +
			    (ha->function_number << 11);

			/* map doorbell */
			if (ddi_dev_regsize(dip, 2, &regsize) != DDI_SUCCESS ||
			    ddi_regs_map_setup(dip, 2, &ha->db_iobase,
			    0, regsize, &ql_dev_acc_attr, &ha->db_dev_handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): regs_map_setup"
				    "(doorbell) failed", QL_NAME, instance);
				goto attach_failed;
			}
			progress |= QL_DB_IOBASE_MAPPED;

			ha->nx_req_in = (uint32_t *)(ha->db_iobase +
			    (ha->function_number << 12));
			ha->db_read = ha->nx_pcibase + (512 * 1024) +
			    (ha->function_number * 8);

			ql_8021_update_crb_int_ptr(ha);
			ql_8021_set_drv_active(ha);
			break;

		default:
			cmn_err(CE_WARN, "%s(%d): Unsupported device id: %x",
			    QL_NAME, instance, ha->device_id);
			goto attach_failed;
		}

		/* Setup hba buffer. */

		size = CFG_IST(ha, CFG_CTRL_24258081) ?
		    (REQUEST_QUEUE_SIZE + RESPONSE_QUEUE_SIZE) :
		    (REQUEST_QUEUE_SIZE + RESPONSE_QUEUE_SIZE +
		    RCVBUF_QUEUE_SIZE);

		if (ql_get_dma_mem(ha, &ha->hba_buf, size, LITTLE_ENDIAN_DMA,
		    QL_DMA_RING_ALIGN) != QL_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): request queue DMA memory "
			    "alloc failed", QL_NAME, instance);
			goto attach_failed;
		}
		progress |= QL_HBA_BUFFER_SETUP;

		/* Setup buffer pointers. */
		ha->request_dvma = ha->hba_buf.cookie.dmac_laddress +
		    REQUEST_Q_BUFFER_OFFSET;
		ha->request_ring_bp = (struct cmd_entry *)
		    ((caddr_t)ha->hba_buf.bp + REQUEST_Q_BUFFER_OFFSET);

		ha->response_dvma = ha->hba_buf.cookie.dmac_laddress +
		    RESPONSE_Q_BUFFER_OFFSET;
		ha->response_ring_bp = (struct sts_entry *)
		    ((caddr_t)ha->hba_buf.bp + RESPONSE_Q_BUFFER_OFFSET);

		ha->rcvbuf_dvma = ha->hba_buf.cookie.dmac_laddress +
		    RCVBUF_Q_BUFFER_OFFSET;
		ha->rcvbuf_ring_bp = (struct rcvbuf *)
		    ((caddr_t)ha->hba_buf.bp + RCVBUF_Q_BUFFER_OFFSET);

		/* Allocate resource for QLogic IOCTL */
		(void) ql_alloc_xioctl_resource(ha);

		/* Setup interrupts */
		if ((rval = ql_setup_interrupts(ha)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): Failed to add interrupt, "
			    "rval=%xh", QL_NAME, instance, rval);
			goto attach_failed;
		}

		progress |= (QL_INTR_ADDED | QL_MUTEX_CV_INITED);

		if (ql_nvram_cache_desc_ctor(ha) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): can't setup nvram cache",
			    QL_NAME, instance);
			goto attach_failed;
		}

		/*
		 * Allocate an N Port information structure
		 * for use when in P2P topology.
		 */
		ha->n_port = (ql_n_port_info_t *)
		    kmem_zalloc(sizeof (ql_n_port_info_t), KM_SLEEP);
		if (ha->n_port == NULL) {
			cmn_err(CE_WARN, "%s(%d): Failed to create N Port info",
			    QL_NAME, instance);
			goto attach_failed;
		}

		progress |= QL_N_PORT_INFO_CREATED;

		/*
		 * Determine support for Power Management
		 */
		caps_ptr = (uint8_t)ql_pci_config_get8(ha, PCI_CONF_CAP_PTR);

		while (caps_ptr != PCI_CAP_NEXT_PTR_NULL) {
			cap = (uint8_t)ql_pci_config_get8(ha, caps_ptr);
			if (cap == PCI_CAP_ID_PM) {
				ha->pm_capable = 1;
				break;
			}
			caps_ptr = (uint8_t)ql_pci_config_get8(ha, caps_ptr +
			    PCI_CAP_NEXT_PTR);
		}

		if (ha->pm_capable) {
			/*
			 * Enable PM for 2200 based HBAs only.
			 */
			if (ha->device_id != 0x2200) {
				ha->pm_capable = 0;
			}
		}

		if (ha->pm_capable) {
			ha->pm_capable = ql_enable_pm;
		}

		if (ha->pm_capable) {
			/*
			 * Initialize power management bookkeeping;
			 * components are created idle.
			 */
			(void) sprintf(buf, "NAME=%s(%d)", QL_NAME, instance);
			pmcomps[0] = buf;

			/*LINTED [Solaris DDI_DEV_T_NONE Lint warning]*/
			if (ddi_prop_update_string_array(DDI_DEV_T_NONE,
			    dip, "pm-components", pmcomps,
			    sizeof (pmcomps) / sizeof (pmcomps[0])) !=
			    DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): failed to create"
				    " pm-components property", QL_NAME,
				    instance);

				/* Initialize adapter. */
				ha->power_level = PM_LEVEL_D0;
				if (ql_initialize_adapter(ha) != QL_SUCCESS) {
					cmn_err(CE_WARN, "%s(%d): failed to"
					    " initialize adapter", QL_NAME,
					    instance);
					goto attach_failed;
				}
			} else {
				ha->power_level = PM_LEVEL_D3;
				if (pm_raise_power(dip, QL_POWER_COMPONENT,
				    PM_LEVEL_D0) != DDI_SUCCESS) {
					cmn_err(CE_WARN, "%s(%d): failed to"
					    " raise power or initialize"
					    " adapter", QL_NAME, instance);
				}
			}
		} else {
			/* Initialize adapter. */
			ha->power_level = PM_LEVEL_D0;
			if (ql_initialize_adapter(ha) != QL_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): failed to initialize"
				    " adapter", QL_NAME, instance);
			}
		}

		if (ha->fw_major_version == 0 && ha->fw_minor_version == 0 &&
		    ha->fw_subminor_version == 0) {
			cmn_err(CE_NOTE, "!%s(%d): Firmware not loaded",
			    QL_NAME, ha->instance);
		} else {
			int	rval;
			char	ver_fmt[256];

			rval = (int)snprintf(ver_fmt, (size_t)sizeof (ver_fmt),
			    "Firmware version %d.%d.%d", ha->fw_major_version,
			    ha->fw_minor_version, ha->fw_subminor_version);

			if (CFG_IST(ha, CFG_CTRL_81XX)) {
				rval = (int)snprintf(ver_fmt + rval,
				    (size_t)sizeof (ver_fmt),
				    ", MPI fw version %d.%d.%d",
				    ha->mpi_fw_major_version,
				    ha->mpi_fw_minor_version,
				    ha->mpi_fw_subminor_version);

				if (ha->subsys_id == 0x17B ||
				    ha->subsys_id == 0x17D) {
					(void) snprintf(ver_fmt + rval,
					    (size_t)sizeof (ver_fmt),
					    ", PHY fw version %d.%d.%d",
					    ha->phy_fw_major_version,
					    ha->phy_fw_minor_version,
					    ha->phy_fw_subminor_version);
				}
			}
			cmn_err(CE_NOTE, "!%s(%d): %s",
			    QL_NAME, ha->instance, ver_fmt);
		}

		ha->k_stats = kstat_create(QL_NAME, instance, "statistics",
		    "controller", KSTAT_TYPE_RAW,
		    (uint32_t)sizeof (ql_adapter_stat_t), KSTAT_FLAG_VIRTUAL);
		if (ha->k_stats == NULL) {
			cmn_err(CE_WARN, "%s(%d): Failed to create kstat",
			    QL_NAME, instance);
			goto attach_failed;
		}
		progress |= QL_KSTAT_CREATED;

		ha->adapter_stats->version = 1;
		ha->k_stats->ks_data = (void *)ha->adapter_stats;
		ha->k_stats->ks_private = ha;
		ha->k_stats->ks_update = ql_kstat_update;
		ha->k_stats->ks_ndata = 1;
		ha->k_stats->ks_data_size = sizeof (ql_adapter_stat_t);
		kstat_install(ha->k_stats);

		if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
		    instance, DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): failed to create minor node",
			    QL_NAME, instance);
			goto attach_failed;
		}
		progress |= QL_MINOR_NODE_CREATED;

		/* Allocate a transport structure for this instance */
		tran = kmem_zalloc(sizeof (fc_fca_tran_t), KM_SLEEP);
		if (tran == NULL) {
			cmn_err(CE_WARN, "%s(%d): failed to allocate transport",
			    QL_NAME, instance);
			goto attach_failed;
		}

		progress |= QL_FCA_TRAN_ALLOCED;

		/* fill in the structure */
		tran->fca_numports = 1;
		tran->fca_version = FCTL_FCA_MODREV_5;
		if (CFG_IST(ha, CFG_CTRL_2422)) {
			tran->fca_num_npivports = MAX_24_VIRTUAL_PORTS;
		} else if (CFG_IST(ha, CFG_CTRL_2581)) {
			tran->fca_num_npivports = MAX_25_VIRTUAL_PORTS;
		}
		bcopy(ha->loginparams.node_ww_name.raw_wwn,
		    tran->fca_perm_pwwn.raw_wwn, 8);

		EL(ha, "FCA version %d\n", tran->fca_version);

		/* Specify the amount of space needed in each packet */
		tran->fca_pkt_size = sizeof (ql_srb_t);

		/* command limits are usually dictated by hardware */
		tran->fca_cmd_max = MAX_OUTSTANDING_COMMANDS;

		/* dmaattr are static, set elsewhere. */
		if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			tran->fca_dma_attr = &ql_64bit_io_dma_attr;
			tran->fca_dma_fcp_cmd_attr = &ql_64fcp_cmd_dma_attr;
			tran->fca_dma_fcp_rsp_attr = &ql_64fcp_rsp_dma_attr;
			tran->fca_dma_fcp_data_attr = &ql_64fcp_data_dma_attr;
			tran->fca_dma_fcsm_cmd_attr = &ql_64fcsm_cmd_dma_attr;
			tran->fca_dma_fcsm_rsp_attr = &ql_64fcsm_rsp_dma_attr;
			tran->fca_dma_fcip_cmd_attr = &ql_64fcip_cmd_dma_attr;
			tran->fca_dma_fcip_rsp_attr = &ql_64fcip_rsp_dma_attr;
		} else {
			tran->fca_dma_attr = &ql_32bit_io_dma_attr;
			tran->fca_dma_fcp_cmd_attr = &ql_32fcp_cmd_dma_attr;
			tran->fca_dma_fcp_rsp_attr = &ql_32fcp_rsp_dma_attr;
			tran->fca_dma_fcp_data_attr = &ql_32fcp_data_dma_attr;
			tran->fca_dma_fcsm_cmd_attr = &ql_32fcsm_cmd_dma_attr;
			tran->fca_dma_fcsm_rsp_attr = &ql_32fcsm_rsp_dma_attr;
			tran->fca_dma_fcip_cmd_attr = &ql_32fcip_cmd_dma_attr;
			tran->fca_dma_fcip_rsp_attr = &ql_32fcip_rsp_dma_attr;
		}

		tran->fca_acc_attr = &ql_dev_acc_attr;
		tran->fca_iblock = &(ha->iblock_cookie);

		/* the remaining values are simply function vectors */
		tran->fca_bind_port = ql_bind_port;
		tran->fca_unbind_port = ql_unbind_port;
		tran->fca_init_pkt = ql_init_pkt;
		tran->fca_un_init_pkt = ql_un_init_pkt;
		tran->fca_els_send = ql_els_send;
		tran->fca_get_cap = ql_get_cap;
		tran->fca_set_cap = ql_set_cap;
		tran->fca_getmap = ql_getmap;
		tran->fca_transport = ql_transport;
		tran->fca_ub_alloc = ql_ub_alloc;
		tran->fca_ub_free = ql_ub_free;
		tran->fca_ub_release = ql_ub_release;
		tran->fca_abort = ql_abort;
		tran->fca_reset = ql_reset;
		tran->fca_port_manage = ql_port_manage;
		tran->fca_get_device = ql_get_device;

		/* give it to the FC transport */
		if (fc_fca_attach(dip, tran) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): FCA attach failed", QL_NAME,
			    instance);
			goto attach_failed;
		}
		progress |= QL_FCA_ATTACH_DONE;

		/* Stash the structure so it can be freed at detach */
		ha->tran = tran;

		/* Acquire global state lock. */
		GLOBAL_STATE_LOCK();

		/* Add adapter structure to link list. */
		ql_add_link_b(&ql_hba, &ha->hba);

		/* Start one second driver timer. */
		if (ql_timer_timeout_id == NULL) {
			ql_timer_ticks = drv_usectohz(1000000);
			ql_timer_timeout_id = timeout(ql_timer, (void *)0,
			    ql_timer_ticks);
		}

		/* Release global state lock. */
		GLOBAL_STATE_UNLOCK();

		/* Determine and populate HBA fru info */
		ql_setup_fruinfo(ha);

		/* Setup task_daemon thread. */
		(void) thread_create(NULL, 0, (void (*)())ql_task_daemon, ha,
		    0, &p0, TS_RUN, minclsyspri);

		progress |= QL_TASK_DAEMON_STARTED;

		ddi_report_dev(dip);

		/* Disable link reset in panic path */
		ha->lip_on_panic = 1;

		rval = DDI_SUCCESS;
		break;

attach_failed:
		if (progress & QL_FCA_ATTACH_DONE) {
			(void) fc_fca_detach(dip);
			progress &= ~QL_FCA_ATTACH_DONE;
		}

		if (progress & QL_FCA_TRAN_ALLOCED) {
			kmem_free(tran, sizeof (fc_fca_tran_t));
			progress &= ~QL_FCA_TRAN_ALLOCED;
		}

		if (progress & QL_MINOR_NODE_CREATED) {
			ddi_remove_minor_node(dip, "devctl");
			progress &= ~QL_MINOR_NODE_CREATED;
		}

		if (progress & QL_KSTAT_CREATED) {
			kstat_delete(ha->k_stats);
			progress &= ~QL_KSTAT_CREATED;
		}

		if (progress & QL_N_PORT_INFO_CREATED) {
			kmem_free(ha->n_port, sizeof (ql_n_port_info_t));
			progress &= ~QL_N_PORT_INFO_CREATED;
		}

		if (progress & QL_TASK_DAEMON_STARTED) {
			TASK_DAEMON_LOCK(ha);

			ha->task_daemon_flags |= TASK_DAEMON_STOP_FLG;

			cv_signal(&ha->cv_task_daemon);

			/* Release task daemon lock. */
			TASK_DAEMON_UNLOCK(ha);

			/* Wait for for task daemon to stop running. */
			while (ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) {
				ql_delay(ha, 10000);
			}
			progress &= ~QL_TASK_DAEMON_STARTED;
		}

		if (progress & QL_DB_IOBASE_MAPPED) {
			ql_8021_clr_drv_active(ha);
			ddi_regs_map_free(&ha->db_dev_handle);
			progress &= ~QL_DB_IOBASE_MAPPED;
		}
		if (progress & QL_IOMAP_IOBASE_MAPPED) {
			ddi_regs_map_free(&ha->iomap_dev_handle);
			progress &= ~QL_IOMAP_IOBASE_MAPPED;
		}

		if (progress & QL_CONFIG_SPACE_SETUP) {
			if (CFG_IST(ha, CFG_SBUS_CARD)) {
				ddi_regs_map_free(&ha->sbus_config_handle);
			} else {
				pci_config_teardown(&ha->pci_handle);
			}
			progress &= ~QL_CONFIG_SPACE_SETUP;
		}

		if (progress & QL_INTR_ADDED) {
			ql_disable_intr(ha);
			ql_release_intr(ha);
			progress &= ~QL_INTR_ADDED;
		}

		if (progress & QL_MUTEX_CV_INITED) {
			ql_destroy_mutex(ha);
			progress &= ~QL_MUTEX_CV_INITED;
		}

		if (progress & QL_HBA_BUFFER_SETUP) {
			ql_free_phys(ha, &ha->hba_buf);
			progress &= ~QL_HBA_BUFFER_SETUP;
		}

		if (progress & QL_REGS_MAPPED) {
			ddi_regs_map_free(&ha->dev_handle);
			if (ha->sbus_fpga_iobase != NULL) {
				ddi_regs_map_free(&ha->sbus_fpga_dev_handle);
			}
			progress &= ~QL_REGS_MAPPED;
		}

		if (progress & QL_SOFT_STATE_ALLOCED) {

			ql_fcache_rel(ha->fcache);

			kmem_free(ha->adapter_stats,
			    sizeof (*ha->adapter_stats));

			kmem_free(ha->ub_array, sizeof (*ha->ub_array) *
			    QL_UB_LIMIT);

			kmem_free(ha->outstanding_cmds,
			    sizeof (*ha->outstanding_cmds) *
			    MAX_OUTSTANDING_COMMANDS);

			if (ha->devpath != NULL) {
				kmem_free(ha->devpath,
				    strlen(ha->devpath) + 1);
			}

			kmem_free(ha->dev, sizeof (*ha->dev) *
			    DEVICE_HEAD_LIST_SIZE);

			if (ha->xioctl != NULL) {
				ql_free_xioctl_resource(ha);
			}

			if (ha->fw_module != NULL) {
				(void) ddi_modclose(ha->fw_module);
			}
			(void) ql_el_trace_desc_dtor(ha);
			(void) ql_nvram_cache_desc_dtor(ha);

			ddi_soft_state_free(ql_state, instance);
			progress &= ~QL_SOFT_STATE_ALLOCED;
		}

		ddi_prop_remove_all(dip);
		rval = DDI_FAILURE;
		break;

	case DDI_RESUME:
		rval = DDI_FAILURE;

		ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
		if (ha == NULL) {
			cmn_err(CE_WARN, "%s(%d): can't get soft state",
			    QL_NAME, instance);
			break;
		}

		ha->power_level = PM_LEVEL_D3;
		if (ha->pm_capable) {
			/*
			 * Get ql_power to do power on initialization
			 */
			if (pm_raise_power(dip, QL_POWER_COMPONENT,
			    PM_LEVEL_D0) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): can't raise adapter"
				    " power", QL_NAME, instance);
			}
		}

		/*
		 * There is a bug in DR that prevents PM framework
		 * from calling ql_power.
		 */
		if (ha->power_level == PM_LEVEL_D3) {
			ha->power_level = PM_LEVEL_D0;

			if (ql_initialize_adapter(ha) != QL_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): can't initialize the"
				    " adapter", QL_NAME, instance);
			}

			/* Wake up task_daemon. */
			ql_awaken_task_daemon(ha, NULL, TASK_DAEMON_ALIVE_FLG,
			    0);
		}

		/* Acquire global state lock. */
		GLOBAL_STATE_LOCK();

		/* Restart driver timer. */
		if (ql_timer_timeout_id == NULL) {
			ql_timer_timeout_id = timeout(ql_timer, (void *)0,
			    ql_timer_ticks);
		}

		/* Release global state lock. */
		GLOBAL_STATE_UNLOCK();

		/* Wake up command start routine. */
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~ADAPTER_SUSPENDED;
		ADAPTER_STATE_UNLOCK(ha);

		/*
		 * Transport doesn't make FC discovery in polled
		 * mode; So we need the daemon thread's services
		 * right here.
		 */
		(void) callb_generic_cpr(&ha->cprinfo, CB_CODE_CPR_RESUME);

		rval = DDI_SUCCESS;

		/* Restart IP if it was running. */
		if (ha->flags & IP_ENABLED && !(ha->flags & IP_INITIALIZED)) {
			(void) ql_initialize_ip(ha);
			ql_isp_rcvbuf(ha);
		}
		break;

	default:
		cmn_err(CE_WARN, "%s(%d): attach, unknown code:"
		    " %x", QL_NAME, ddi_get_instance(dip), cmd);
		rval = DDI_FAILURE;
		break;
	}

	kmem_free(buf, MAXPATHLEN);

	if (rval != DDI_SUCCESS) {
		/*EMPTY*/
		QL_PRINT_2(CE_CONT, "(%d): failed, rval = %xh\n",
		    ddi_get_instance(dip), rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ddi_get_instance(dip));
	}

	return (rval);
}

/*
 * ql_detach
 *	Used to remove all the states associated with a given
 *	instances of a device node prior to the removal of that
 *	instance from the system.
 *
 * Input:
 *	dip = pointer to device information structure.
 *	cmd = type of detach.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ql_adapter_state_t	*ha, *vha;
	ql_tgt_t		*tq;
	int			delay_cnt;
	uint16_t		index;
	ql_link_t		*link;
	char			*buf;
	timeout_id_t		timer_id = NULL;
	int			suspend, rval = DDI_SUCCESS;

	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "(%d): no adapter\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	QL_PRINT_3(CE_CONT, "(%d): started, cmd=%xh\n", ha->instance, cmd);

	buf = (char *)(kmem_zalloc(MAXPATHLEN, KM_SLEEP));

	switch (cmd) {
	case DDI_DETACH:
		ADAPTER_STATE_LOCK(ha);
		ha->flags |= (ADAPTER_SUSPENDED | ABORT_CMDS_LOOP_DOWN_TMO);
		ADAPTER_STATE_UNLOCK(ha);

		TASK_DAEMON_LOCK(ha);

		if (ha->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) {
			ha->task_daemon_flags |= TASK_DAEMON_STOP_FLG;
			cv_signal(&ha->cv_task_daemon);

			TASK_DAEMON_UNLOCK(ha);

			(void) ql_wait_for_td_stop(ha);

			TASK_DAEMON_LOCK(ha);
			if (ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) {
				ha->task_daemon_flags &= ~TASK_DAEMON_STOP_FLG;
				EL(ha, "failed, could not stop task daemon\n");
			}
		}
		TASK_DAEMON_UNLOCK(ha);

		GLOBAL_STATE_LOCK();

		/* Disable driver timer if no adapters. */
		if (ql_timer_timeout_id && ql_hba.first == &ha->hba &&
		    ql_hba.last == &ha->hba) {
			timer_id = ql_timer_timeout_id;
			ql_timer_timeout_id = NULL;
		}
		ql_remove_link(&ql_hba, &ha->hba);

		GLOBAL_STATE_UNLOCK();

		if (timer_id) {
			(void) untimeout(timer_id);
		}

		if (ha->pm_capable) {
			if (pm_lower_power(dip, QL_POWER_COMPONENT,
			    PM_LEVEL_D3) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): failed to lower the"
				    " power", QL_NAME, ha->instance);
			}
		}

		/*
		 * If pm_lower_power shutdown the adapter, there
		 * isn't much else to do
		 */
		if (ha->power_level != PM_LEVEL_D3) {
			ql_halt(ha, PM_LEVEL_D3);
		}

		/* Remove virtual ports. */
		while ((vha = ha->vp_next) != NULL) {
			ql_vport_destroy(vha);
		}

		/* Free target queues. */
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			link = ha->dev[index].first;
			while (link != NULL) {
				tq = link->base_address;
				link = link->next;
				ql_dev_free(ha, tq);
			}
		}

		/*
		 * Free unsolicited buffers.
		 * If we are here then there are no ULPs still
		 * alive that wish to talk to ql so free up
		 * any SRB_IP_UB_UNUSED buffers that are
		 * lingering around
		 */
		QL_UB_LOCK(ha);
		for (index = 0; index < QL_UB_LIMIT; index++) {
			fc_unsol_buf_t *ubp = ha->ub_array[index];

			if (ubp != NULL) {
				ql_srb_t *sp = ubp->ub_fca_private;

				sp->flags |= SRB_UB_FREE_REQUESTED;

				while (!(sp->flags & SRB_UB_IN_FCA) ||
				    (sp->flags & (SRB_UB_CALLBACK |
				    SRB_UB_ACQUIRED))) {
					QL_UB_UNLOCK(ha);
					delay(drv_usectohz(100000));
					QL_UB_LOCK(ha);
				}
				ha->ub_array[index] = NULL;

				QL_UB_UNLOCK(ha);
				ql_free_unsolicited_buffer(ha, ubp);
				QL_UB_LOCK(ha);
			}
		}
		QL_UB_UNLOCK(ha);

		/* Free any saved RISC code. */
		if (ha->risc_code != NULL) {
			kmem_free(ha->risc_code, ha->risc_code_size);
			ha->risc_code = NULL;
			ha->risc_code_size = 0;
		}

		if (ha->fw_module != NULL) {
			(void) ddi_modclose(ha->fw_module);
			ha->fw_module = NULL;
		}

		/* Free resources. */
		ddi_prop_remove_all(dip);
		(void) fc_fca_detach(dip);
		kmem_free(ha->tran, sizeof (fc_fca_tran_t));
		ddi_remove_minor_node(dip, "devctl");
		if (ha->k_stats != NULL) {
			kstat_delete(ha->k_stats);
		}

		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			ddi_regs_map_free(&ha->sbus_config_handle);
		} else {
			if (CFG_IST(ha, CFG_CTRL_8021)) {
				ql_8021_clr_drv_active(ha);
				ddi_regs_map_free(&ha->db_dev_handle);
			}
			if (ha->iomap_dev_handle != ha->dev_handle) {
				ddi_regs_map_free(&ha->iomap_dev_handle);
			}
			pci_config_teardown(&ha->pci_handle);
		}

		ql_disable_intr(ha);
		ql_release_intr(ha);

		ql_free_xioctl_resource(ha);

		ql_destroy_mutex(ha);

		ql_free_phys(ha, &ha->hba_buf);
		ql_free_phys(ha, &ha->fwexttracebuf);
		ql_free_phys(ha, &ha->fwfcetracebuf);

		ddi_regs_map_free(&ha->dev_handle);
		if (ha->sbus_fpga_iobase != NULL) {
			ddi_regs_map_free(&ha->sbus_fpga_dev_handle);
		}

		ql_fcache_rel(ha->fcache);
		if (ha->vcache != NULL) {
			kmem_free(ha->vcache, QL_24XX_VPD_SIZE);
		}

		if (ha->pi_attrs != NULL) {
			kmem_free(ha->pi_attrs, sizeof (fca_port_attrs_t));
		}

		kmem_free(ha->adapter_stats, sizeof (*ha->adapter_stats));

		kmem_free(ha->ub_array, sizeof (*ha->ub_array) * QL_UB_LIMIT);

		kmem_free(ha->outstanding_cmds,
		    sizeof (*ha->outstanding_cmds) * MAX_OUTSTANDING_COMMANDS);

		if (ha->n_port != NULL) {
			kmem_free(ha->n_port, sizeof (ql_n_port_info_t));
		}

		if (ha->devpath != NULL) {
			kmem_free(ha->devpath, strlen(ha->devpath) + 1);
		}

		kmem_free(ha->dev, sizeof (*ha->dev) * DEVICE_HEAD_LIST_SIZE);

		EL(ha, "detached\n");

		ddi_soft_state_free(ql_state, (int)ha->instance);

		break;

	case DDI_SUSPEND:
		ADAPTER_STATE_LOCK(ha);

		delay_cnt = 0;
		ha->flags |= ADAPTER_SUSPENDED;
		while (ha->flags & ADAPTER_TIMER_BUSY && delay_cnt++ < 10) {
			ADAPTER_STATE_UNLOCK(ha);
			delay(drv_usectohz(1000000));
			ADAPTER_STATE_LOCK(ha);
		}
		if (ha->busy || ha->flags & ADAPTER_TIMER_BUSY) {
			ha->flags &= ~ADAPTER_SUSPENDED;
			ADAPTER_STATE_UNLOCK(ha);
			rval = DDI_FAILURE;
			cmn_err(CE_WARN, "!%s(%d): Fail suspend"
			    " busy %xh flags %xh", QL_NAME, ha->instance,
			    ha->busy, ha->flags);
			break;
		}

		ADAPTER_STATE_UNLOCK(ha);

		if (ha->flags & IP_INITIALIZED) {
			(void) ql_shutdown_ip(ha);
		}

		if ((suspend = ql_suspend_adapter(ha)) != QL_SUCCESS) {
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~ADAPTER_SUSPENDED;
			ADAPTER_STATE_UNLOCK(ha);
			cmn_err(CE_WARN, "%s(%d): Fail suspend rval %xh",
			    QL_NAME, ha->instance, suspend);

			/* Restart IP if it was running. */
			if (ha->flags & IP_ENABLED &&
			    !(ha->flags & IP_INITIALIZED)) {
				(void) ql_initialize_ip(ha);
				ql_isp_rcvbuf(ha);
			}
			rval = DDI_FAILURE;
			break;
		}

		/* Acquire global state lock. */
		GLOBAL_STATE_LOCK();

		/* Disable driver timer if last adapter. */
		if (ql_timer_timeout_id && ql_hba.first == &ha->hba &&
		    ql_hba.last == &ha->hba) {
			timer_id = ql_timer_timeout_id;
			ql_timer_timeout_id = NULL;
		}
		GLOBAL_STATE_UNLOCK();

		if (timer_id) {
			(void) untimeout(timer_id);
		}

		EL(ha, "suspended\n");

		break;

	default:
		rval = DDI_FAILURE;
		break;
	}

	kmem_free(buf, MAXPATHLEN);

	if (rval != DDI_SUCCESS) {
		if (ha != NULL) {
			EL(ha, "failed, rval = %xh\n", rval);
		} else {
			/*EMPTY*/
			QL_PRINT_2(CE_CONT, "(%d): failed, rval = %xh\n",
			    ddi_get_instance(dip), rval);
		}
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ddi_get_instance(dip));
	}

	return (rval);
}


/*
 * ql_power
 *	Power a device attached to the system.
 *
 * Input:
 *	dip = pointer to device information structure.
 *	component = device.
 *	level = power level.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_power(dev_info_t *dip, int component, int level)
{
	int			rval = DDI_FAILURE;
	off_t			csr;
	uint8_t			saved_pm_val;
	ql_adapter_state_t	*ha;
	char			*buf;
	char			*path;

	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL || ha->pm_capable == 0) {
		QL_PRINT_2(CE_CONT, "(%d): no hba or PM not supported\n",
		    ddi_get_instance(dip));
		return (rval);
	}

	QL_PRINT_10(CE_CONT, "(%d,%d): started\n", ha->instance, ha->vp_index);

	buf = (char *)(kmem_zalloc(MAXPATHLEN, KM_SLEEP));
	path = (char *)(kmem_zalloc(MAXPATHLEN, KM_SLEEP));

	if (component != QL_POWER_COMPONENT || (level != PM_LEVEL_D0 &&
	    level != PM_LEVEL_D3)) {
		EL(ha, "invalid, component=%xh or level=%xh\n",
		    component, level);
		return (rval);
	}

	GLOBAL_HW_LOCK();
	csr = (uint8_t)ql_pci_config_get8(ha, PCI_CONF_CAP_PTR) + PCI_PMCSR;
	GLOBAL_HW_UNLOCK();

	(void) snprintf(buf, sizeof (buf),
	    "Qlogic %s(%d): %s\n\t", QL_NAME, ddi_get_instance(dip),
	    ddi_pathname(dip, path));

	switch (level) {
	case PM_LEVEL_D0:	/* power up to D0 state - fully on */

		QL_PM_LOCK(ha);
		if (ha->power_level == PM_LEVEL_D0) {
			QL_PM_UNLOCK(ha);
			rval = DDI_SUCCESS;
			break;
		}

		/*
		 * Enable interrupts now
		 */
		saved_pm_val = ha->power_level;
		ha->power_level = PM_LEVEL_D0;
		QL_PM_UNLOCK(ha);

		GLOBAL_HW_LOCK();

		ql_pci_config_put16(ha, csr, PCI_PMCSR_D0);

		/*
		 * Delay after reset, for chip to recover.
		 * Otherwise causes system PANIC
		 */
		drv_usecwait(200000);

		GLOBAL_HW_UNLOCK();

		if (ha->config_saved) {
			ha->config_saved = 0;
			if (QL_RESTORE_CONFIG_REGS(dip) != DDI_SUCCESS) {
				QL_PM_LOCK(ha);
				ha->power_level = saved_pm_val;
				QL_PM_UNLOCK(ha);
				cmn_err(CE_WARN, "%s failed to restore "
				    "config regs", buf);
				break;
			}
		}

		if (ql_initialize_adapter(ha) != QL_SUCCESS) {
			cmn_err(CE_WARN, "%s adapter initialization failed",
			    buf);
		}

		/* Wake up task_daemon. */
		ql_awaken_task_daemon(ha, NULL, TASK_DAEMON_ALIVE_FLG |
		    TASK_DAEMON_SLEEPING_FLG, 0);

		/* Restart IP if it was running. */
		if (ha->flags & IP_ENABLED && !(ha->flags & IP_INITIALIZED)) {
			(void) ql_initialize_ip(ha);
			ql_isp_rcvbuf(ha);
		}

		cmn_err(CE_NOTE, QL_BANG "ql_power(%d): %s is powered ON\n",
		    ha->instance, QL_NAME);

		rval = DDI_SUCCESS;
		break;

	case PM_LEVEL_D3:	/* power down to D3 state - off */

		QL_PM_LOCK(ha);

		if (ha->busy || ((ha->task_daemon_flags &
		    TASK_DAEMON_SLEEPING_FLG) == 0)) {
			QL_PM_UNLOCK(ha);
			break;
		}

		if (ha->power_level == PM_LEVEL_D3) {
			rval = DDI_SUCCESS;
			QL_PM_UNLOCK(ha);
			break;
		}
		QL_PM_UNLOCK(ha);

		if (QL_SAVE_CONFIG_REGS(dip) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!Qlogic %s(%d): %s failed to save"
			    " config regs", QL_NAME, ha->instance, buf);
			break;
		}
		ha->config_saved = 1;

		/*
		 * Don't enable interrupts. Running mailbox commands with
		 * interrupts enabled could cause hangs since pm_run_scan()
		 * runs out of a callout thread and on single cpu systems
		 * cv_reltimedwait_sig(), called from ql_mailbox_command(),
		 * would not get to run.
		 */
		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags |= TASK_DAEMON_POWERING_DOWN;
		TASK_DAEMON_UNLOCK(ha);

		ql_halt(ha, PM_LEVEL_D3);

		/*
		 * Setup ql_intr to ignore interrupts from here on.
		 */
		QL_PM_LOCK(ha);
		ha->power_level = PM_LEVEL_D3;
		QL_PM_UNLOCK(ha);

		/*
		 * Wait for ISR to complete.
		 */
		INTR_LOCK(ha);
		ql_pci_config_put16(ha, csr, PCI_PMCSR_D3HOT);
		INTR_UNLOCK(ha);

		cmn_err(CE_NOTE, QL_BANG "ql_power(%d): %s is powered OFF\n",
		    ha->instance, QL_NAME);

		rval = DDI_SUCCESS;
		break;
	}

	kmem_free(buf, MAXPATHLEN);
	kmem_free(path, MAXPATHLEN);

	QL_PRINT_10(CE_CONT, "(%d,%d): done\n", ha->instance, ha->vp_index);

	return (rval);
}

/*
 * ql_quiesce
 *	quiesce a device attached to the system.
 *
 * Input:
 *	dip = pointer to device information structure.
 *
 * Returns:
 *	DDI_SUCCESS
 *
 * Context:
 *	Kernel context.
 */
static int
ql_quiesce(dev_info_t *dip)
{
	ql_adapter_state_t	*ha;
	uint32_t		timer;
	uint32_t		stat;

	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL) {
		/* Oh well.... */
		QL_PRINT_2(CE_CONT, "(%d): no adapter\n",
		    ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_8021)) {
		(void) ql_stop_firmware(ha);
	} else if (CFG_IST(ha, CFG_CTRL_242581)) {
		WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
		WRT16_IO_REG(ha, mailbox_in[0], MBC_STOP_FIRMWARE);
		WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
		for (timer = 0; timer < 30000; timer++) {
			stat = RD32_IO_REG(ha, risc2host);
			if (stat & BIT_15) {
				if ((stat & 0xff) < 0x12) {
					WRT32_IO_REG(ha, hccr,
					    HC24_CLR_RISC_INT);
					break;
				}
				WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
			}
			drv_usecwait(100);
		}
		/* Reset the chip. */
		WRT32_IO_REG(ha, ctrl_status, ISP_RESET | DMA_SHUTDOWN |
		    MWB_4096_BYTES);
		drv_usecwait(100);

	} else {
		/* Disable ISP interrupts. */
		WRT16_IO_REG(ha, ictrl, 0);
		/* Select RISC module registers. */
		WRT16_IO_REG(ha, ctrl_status, 0);
		/* Reset ISP semaphore. */
		WRT16_IO_REG(ha, semaphore, 0);
		/* Reset RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RESET_RISC);
		/* Release RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);
	}

	ql_disable_intr(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

/* ************************************************************************ */
/*		Fibre Channel Adapter (FCA) Transport Functions.	    */
/* ************************************************************************ */

/*
 * ql_bind_port
 *	Handling port binding. The FC Transport attempts to bind an FCA port
 *	when it is ready to start transactions on the port. The FC Transport
 *	will call the fca_bind_port() function specified in the fca_transport
 *	structure it receives. The FCA must fill in the port_info structure
 *	passed in the call and also stash the information for future calls.
 *
 * Input:
 *	dip = pointer to FCA information structure.
 *	port_info = pointer to port information structure.
 *	bind_info = pointer to bind information structure.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
static opaque_t
ql_bind_port(dev_info_t *dip, fc_fca_port_info_t *port_info,
    fc_fca_bind_info_t *bind_info)
{
	ql_adapter_state_t	*ha, *vha;
	opaque_t		fca_handle = NULL;
	port_id_t		d_id;
	int			port_npiv = bind_info->port_npiv;
	uchar_t			*port_nwwn = bind_info->port_nwwn.raw_wwn;
	uchar_t			*port_pwwn = bind_info->port_pwwn.raw_wwn;

	/* get state info based on the dip */
	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "(%d): no adapter\n",
		    ddi_get_instance(dip));
		return (NULL);
	}
	QL_PRINT_10(CE_CONT, "(%d,%d): started\n", ha->instance, ha->vp_index);

	/* Verify port number is supported. */
	if (port_npiv != 0) {
		if (!(ha->flags & VP_ENABLED)) {
			QL_PRINT_2(CE_CONT, "(%d): FC_NPIV_NOT_SUPPORTED\n",
			    ha->instance);
			port_info->pi_error = FC_NPIV_NOT_SUPPORTED;
			return (NULL);
		}
		if (!(ha->flags & POINT_TO_POINT)) {
			QL_PRINT_2(CE_CONT, "(%d): FC_NPIV_WRONG_TOPOLOGY\n",
			    ha->instance);
			port_info->pi_error = FC_NPIV_WRONG_TOPOLOGY;
			return (NULL);
		}
		if (!(ha->flags & FDISC_ENABLED)) {
			QL_PRINT_2(CE_CONT, "(%d): switch does not support "
			    "FDISC\n", ha->instance);
			port_info->pi_error = FC_NPIV_FDISC_FAILED;
			return (NULL);
		}
		if (bind_info->port_num > (CFG_IST(ha, CFG_CTRL_2422) ?
		    MAX_24_VIRTUAL_PORTS : MAX_25_VIRTUAL_PORTS)) {
			QL_PRINT_2(CE_CONT, "(%d): port number=%d "
			    "FC_OUTOFBOUNDS\n", ha->instance);
			port_info->pi_error = FC_OUTOFBOUNDS;
			return (NULL);
		}
	} else if (bind_info->port_num != 0) {
		QL_PRINT_2(CE_CONT, "(%d): failed, port number=%d is not "
		    "supported\n", ha->instance, bind_info->port_num);
		port_info->pi_error = FC_OUTOFBOUNDS;
		return (NULL);
	}

	/* Locate port context. */
	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		if (vha->vp_index == bind_info->port_num) {
			break;
		}
	}

	/* If virtual port does not exist. */
	if (vha == NULL) {
		vha = ql_vport_create(ha, (uint8_t)bind_info->port_num);
	}

	/* make sure this port isn't already bound */
	if (vha->flags & FCA_BOUND) {
		port_info->pi_error = FC_ALREADY;
	} else {
		if (vha->vp_index != 0) {
			bcopy(port_nwwn,
			    vha->loginparams.node_ww_name.raw_wwn, 8);
			bcopy(port_pwwn,
			    vha->loginparams.nport_ww_name.raw_wwn, 8);
		}
		if (vha->vp_index != 0 && !(vha->flags & VP_ENABLED)) {
			if (ql_vport_enable(vha) != QL_SUCCESS) {
				QL_PRINT_2(CE_CONT, "(%d): failed to enable "
				    "virtual port=%d\n", ha->instance,
				    vha->vp_index);
				port_info->pi_error = FC_NPIV_FDISC_FAILED;
				return (NULL);
			}
			cmn_err(CE_CONT, "!Qlogic %s(%d) NPIV(%d) "
			    "WWPN=%02x%02x%02x%02x%02x%02x%02x%02x : "
			    "WWNN=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    QL_NAME, ha->instance, vha->vp_index,
			    port_pwwn[0], port_pwwn[1], port_pwwn[2],
			    port_pwwn[3], port_pwwn[4], port_pwwn[5],
			    port_pwwn[6], port_pwwn[7],
			    port_nwwn[0], port_nwwn[1], port_nwwn[2],
			    port_nwwn[3], port_nwwn[4], port_nwwn[5],
			    port_nwwn[6], port_nwwn[7]);
		}

		/* stash the bind_info supplied by the FC Transport */
		vha->bind_info.port_handle = bind_info->port_handle;
		vha->bind_info.port_statec_cb =
		    bind_info->port_statec_cb;
		vha->bind_info.port_unsol_cb = bind_info->port_unsol_cb;

		/* Set port's source ID. */
		port_info->pi_s_id.port_id = vha->d_id.b24;

		/* copy out the default login parameters */
		bcopy((void *)&vha->loginparams,
		    (void *)&port_info->pi_login_params,
		    sizeof (la_els_logi_t));

		/* Set port's hard address if enabled. */
		port_info->pi_hard_addr.hard_addr = 0;
		if (bind_info->port_num == 0) {
			d_id.b24 = ha->d_id.b24;
			if (CFG_IST(ha, CFG_CTRL_24258081)) {
				if (ha->init_ctrl_blk.cb24.
				    firmware_options_1[0] & BIT_0) {
					d_id.b.al_pa = ql_index_to_alpa[ha->
					    init_ctrl_blk.cb24.
					    hard_address[0]];
					port_info->pi_hard_addr.hard_addr =
					    d_id.b24;
				}
			} else if (ha->init_ctrl_blk.cb.firmware_options[0] &
			    BIT_0) {
				d_id.b.al_pa = ql_index_to_alpa[ha->
				    init_ctrl_blk.cb.hard_address[0]];
				port_info->pi_hard_addr.hard_addr = d_id.b24;
			}

			/* Set the node id data */
			if (ql_get_rnid_params(ha,
			    sizeof (port_info->pi_rnid_params.params),
			    (caddr_t)&port_info->pi_rnid_params.params) ==
			    QL_SUCCESS) {
				port_info->pi_rnid_params.status = FC_SUCCESS;
			} else {
				port_info->pi_rnid_params.status = FC_FAILURE;
			}

			/* Populate T11 FC-HBA details */
			ql_populate_hba_fru_details(ha, port_info);
			ha->pi_attrs = kmem_zalloc(sizeof (fca_port_attrs_t),
			    KM_SLEEP);
			if (ha->pi_attrs != NULL) {
				bcopy(&port_info->pi_attrs, ha->pi_attrs,
				    sizeof (fca_port_attrs_t));
			}
		} else {
			port_info->pi_rnid_params.status = FC_FAILURE;
			if (ha->pi_attrs != NULL) {
				bcopy(ha->pi_attrs, &port_info->pi_attrs,
				    sizeof (fca_port_attrs_t));
			}
		}

		/* Generate handle for this FCA. */
		fca_handle = (opaque_t)vha;

		ADAPTER_STATE_LOCK(ha);
		vha->flags |= FCA_BOUND;
		ADAPTER_STATE_UNLOCK(ha);
		/* Set port's current state. */
		port_info->pi_port_state = vha->state;
	}

	QL_PRINT_10(CE_CONT, "(%d,%d): done, pi_port_state=%xh, "
	    "pi_s_id.port_id=%xh\n", ha->instance, ha->vp_index,
	    port_info->pi_port_state, port_info->pi_s_id.port_id);

	return (fca_handle);
}

/*
 * ql_unbind_port
 *	To unbind a Fibre Channel Adapter from an FC Port driver.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *
 * Context:
 *	Kernel context.
 */
static void
ql_unbind_port(opaque_t fca_handle)
{
	ql_adapter_state_t	*ha;
	ql_tgt_t		*tq;
	uint32_t		flgs;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		/*EMPTY*/
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
	} else {
		QL_PRINT_10(CE_CONT, "(%d,%d): started\n", ha->instance,
		    ha->vp_index);

		if (!(ha->flags & FCA_BOUND)) {
			/*EMPTY*/
			QL_PRINT_2(CE_CONT, "(%d): port=%d already unbound\n",
			    ha->instance, ha->vp_index);
		} else {
			if (ha->vp_index != 0 && ha->flags & VP_ENABLED) {
				if ((tq = ql_loop_id_to_queue(ha,
				    FL_PORT_24XX_HDL)) != NULL) {
					(void) ql_logout_fabric_port(ha, tq);
				}
				(void) ql_vport_control(ha, (uint8_t)
				    (CFG_IST(ha, CFG_CTRL_2425) ?
				    VPC_DISABLE_INIT : VPC_DISABLE_LOGOUT));
				flgs = FCA_BOUND | VP_ENABLED;
			} else {
				flgs = FCA_BOUND;
			}
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~flgs;
			ADAPTER_STATE_UNLOCK(ha);
		}

		QL_PRINT_10(CE_CONT, "(%d,%d): done\n", ha->instance,
		    ha->vp_index);
	}
}

/*
 * ql_init_pkt
 *	Initialize FCA portion of packet.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet has successfully been initialized.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_NOMEM - the FCA failed initialization due to an allocation error.
 *	FC_FAILURE - the FCA failed initialization for undisclosed reasons
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_init_pkt(opaque_t fca_handle, fc_packet_t *pkt, int sleep)
{
	ql_adapter_state_t	*ha;
	ql_srb_t		*sp;
	int			rval = FC_SUCCESS;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	sp = (ql_srb_t *)pkt->pkt_fca_private;
	sp->flags = 0;

	/* init cmd links */
	sp->cmd.base_address = sp;
	sp->cmd.prev = NULL;
	sp->cmd.next = NULL;
	sp->cmd.head = NULL;

	/* init watchdog links */
	sp->wdg.base_address = sp;
	sp->wdg.prev = NULL;
	sp->wdg.next = NULL;
	sp->wdg.head = NULL;
	sp->pkt = pkt;
	sp->ha = ha;
	sp->magic_number = QL_FCA_BRAND;
	sp->sg_dma.dma_handle = NULL;
#ifndef __sparc
	if (CFG_IST(ha, CFG_CTRL_8021)) {
		/* Setup DMA for scatter gather list. */
		sp->sg_dma.size = sizeof (cmd6_2400_dma_t);
		sp->sg_dma.type = LITTLE_ENDIAN_DMA;
		sp->sg_dma.cookie_count = 1;
		sp->sg_dma.alignment = 64;
		if (ql_alloc_phys(ha, &sp->sg_dma, KM_SLEEP) != QL_SUCCESS) {
			rval = FC_NOMEM;
		}
	}
#endif	/* __sparc */

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_un_init_pkt
 *	Release all local resources bound to packet.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet has successfully been invalidated.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_BADPACKET - the packet has not been initialized or has
 *			already been freed by this FCA.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_un_init_pkt(opaque_t fca_handle, fc_packet_t *pkt)
{
	ql_adapter_state_t *ha;
	int rval;
	ql_srb_t *sp;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	sp = (ql_srb_t *)pkt->pkt_fca_private;

	if (sp->magic_number != QL_FCA_BRAND) {
		EL(ha, "failed, FC_BADPACKET\n");
		rval = FC_BADPACKET;
	} else {
		sp->magic_number = NULL;
		ql_free_phys(ha, &sp->sg_dma);
		rval = FC_SUCCESS;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_els_send
 *	Issue a extended link service request.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the command was successful.
 *	FC_ELS_FREJECT - the command was rejected by a Fabric.
 *	FC_ELS_PREJECT - the command was rejected by an N-port.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_ELS_BAD - the FCA can not issue the requested ELS.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_send(opaque_t fca_handle, fc_packet_t *pkt)
{
	ql_adapter_state_t	*ha;
	int			rval;
	clock_t			timer = drv_usectohz(30000000);
	ls_code_t		els;
	la_els_rjt_t		rjt;
	ql_srb_t		*sp = (ql_srb_t *)pkt->pkt_fca_private;

	/* Verify proper command. */
	ha = ql_cmd_setup(fca_handle, pkt, &rval);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, ql_cmd_setup=%xh, fcah=%ph\n",
		    rval, fca_handle);
		return (FC_INVALID_REQUEST);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Wait for suspension to end. */
	TASK_DAEMON_LOCK(ha);
	while (ha->task_daemon_flags & QL_SUSPENDED) {
		ha->task_daemon_flags |= SUSPENDED_WAKEUP_FLG;

		/* 30 seconds from now */
		if (cv_reltimedwait(&ha->pha->cv_dr_suspended,
		    &ha->pha->task_daemon_mutex, timer, TR_CLOCK_TICK) == -1) {
			/*
			 * The timeout time 'timer' was
			 * reached without the condition
			 * being signaled.
			 */
			pkt->pkt_state = FC_PKT_TRAN_BSY;
			pkt->pkt_reason = FC_REASON_XCHG_BSY;

			/* Release task daemon lock. */
			TASK_DAEMON_UNLOCK(ha);

			EL(ha, "QL_SUSPENDED failed=%xh\n",
			    QL_FUNCTION_TIMEOUT);
			return (FC_TRAN_BUSY);
		}
	}
	/* Release task daemon lock. */
	TASK_DAEMON_UNLOCK(ha);

	/* Setup response header. */
	bcopy((void *)&pkt->pkt_cmd_fhdr, (void *)&pkt->pkt_resp_fhdr,
	    sizeof (fc_frame_hdr_t));

	if (pkt->pkt_rsplen) {
		bzero((void *)pkt->pkt_resp, pkt->pkt_rsplen);
	}

	pkt->pkt_resp_fhdr.d_id = ha->d_id.b24;
	pkt->pkt_resp_fhdr.s_id = pkt->pkt_cmd_fhdr.d_id;
	pkt->pkt_resp_fhdr.r_ctl = R_CTL_EXTENDED_SVC |
	    R_CTL_SOLICITED_CONTROL;
	pkt->pkt_resp_fhdr.f_ctl = F_CTL_XCHG_CONTEXT | F_CTL_LAST_SEQ |
	    F_CTL_END_SEQ;

	sp->flags &= ~(SRB_UB_CALLBACK | SRB_UB_RSCN | SRB_UB_FCP |
	    SRB_FCP_CMD_PKT | SRB_FCP_DATA_PKT | SRB_FCP_RSP_PKT |
	    SRB_IP_PKT | SRB_COMMAND_TIMEOUT | SRB_UB_ACQUIRED | SRB_MS_PKT);

	sp->flags |= SRB_ELS_PKT;

	/* map the type of ELS to a function */
	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
	    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

#if 0
	QL_PRINT_3(CE_CONT, "(%d): command fhdr:\n", ha->instance);
	QL_DUMP_3((uint8_t *)&pkt->pkt_cmd_fhdr, 32,
	    sizeof (fc_frame_hdr_t) / 4);
	QL_PRINT_3(CE_CONT, "(%d): command:\n", ha->instance);
	QL_DUMP_3((uint8_t *)&els, 32, sizeof (els) / 4);
#endif

	sp->iocb = ha->els_cmd;
	sp->req_cnt = 1;

	switch (els.ls_code) {
	case LA_ELS_RJT:
	case LA_ELS_ACC:
		EL(ha, "LA_ELS_RJT\n");
		pkt->pkt_state = FC_PKT_SUCCESS;
		rval = FC_SUCCESS;
		break;
	case LA_ELS_PLOGI:
	case LA_ELS_PDISC:
		rval = ql_els_plogi(ha, pkt);
		break;
	case LA_ELS_FLOGI:
	case LA_ELS_FDISC:
		rval = ql_els_flogi(ha, pkt);
		break;
	case LA_ELS_LOGO:
		rval = ql_els_logo(ha, pkt);
		break;
	case LA_ELS_PRLI:
		rval = ql_els_prli(ha, pkt);
		break;
	case LA_ELS_PRLO:
		rval = ql_els_prlo(ha, pkt);
		break;
	case LA_ELS_ADISC:
		rval = ql_els_adisc(ha, pkt);
		break;
	case LA_ELS_LINIT:
		rval = ql_els_linit(ha, pkt);
		break;
	case LA_ELS_LPC:
		rval = ql_els_lpc(ha, pkt);
		break;
	case LA_ELS_LSTS:
		rval = ql_els_lsts(ha, pkt);
		break;
	case LA_ELS_SCR:
		rval = ql_els_scr(ha, pkt);
		break;
	case LA_ELS_RSCN:
		rval = ql_els_rscn(ha, pkt);
		break;
	case LA_ELS_FARP_REQ:
		rval = ql_els_farp_req(ha, pkt);
		break;
	case LA_ELS_FARP_REPLY:
		rval = ql_els_farp_reply(ha, pkt);
		break;
	case LA_ELS_RLS:
		rval = ql_els_rls(ha, pkt);
		break;
	case LA_ELS_RNID:
		rval = ql_els_rnid(ha, pkt);
		break;
	default:
		EL(ha, "LA_ELS_RJT, FC_REASON_CMD_UNSUPPORTED=%xh\n",
		    els.ls_code);
		/* Build RJT. */
		bzero(&rjt, sizeof (rjt));
		rjt.ls_code.ls_code = LA_ELS_RJT;
		rjt.reason = FC_REASON_CMD_UNSUPPORTED;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
		    (uint8_t *)pkt->pkt_resp, sizeof (rjt), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_UNSUPPORTED;
		rval = FC_SUCCESS;
		break;
	}

#if 0
	QL_PRINT_3(CE_CONT, "(%d): response fhdr:\n", ha->instance);
	QL_DUMP_3((uint8_t *)&pkt->pkt_resp_fhdr, 32,
	    sizeof (fc_frame_hdr_t) / 4);
#endif
	/*
	 * Return success if the srb was consumed by an iocb. The packet
	 * completion callback will be invoked by the response handler.
	 */
	if (rval == QL_CONSUMED) {
		rval = FC_SUCCESS;
	} else if (rval == FC_SUCCESS &&
	    !(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
		/* Do command callback only if no error */
		ql_awaken_task_daemon(ha, sp, 0, 0);
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_get_cap
 *	Export FCA hardware and software capabilities.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	cap = pointer to the capabilities string.
 *	ptr = buffer pointer for return capability.
 *
 * Returns:
 *	FC_CAP_ERROR - no such capability
 *	FC_CAP_FOUND - the capability was returned and cannot be set
 *	FC_CAP_SETTABLE - the capability was returned and can be set
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_get_cap(opaque_t fca_handle, char *cap, void *ptr)
{
	ql_adapter_state_t	*ha;
	int			rval;
	uint32_t		*rptr = (uint32_t *)ptr;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (strcmp(cap, FC_NODE_WWN) == 0) {
		bcopy((void *)&ha->loginparams.node_ww_name.raw_wwn[0],
		    ptr, 8);
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_LOGIN_PARAMS) == 0) {
		bcopy((void *)&ha->loginparams, ptr,
		    sizeof (la_els_logi_t));
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_UNSOL_BUF) == 0) {
		*rptr = (uint32_t)QL_UB_LIMIT;
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_NOSTREAM_ON_UNALIGN_BUF) == 0) {

		dev_info_t	*psydip = NULL;
#ifdef __sparc
		/*
		 * Disable streaming for certain 2 chip adapters
		 * below Psycho to handle Psycho byte hole issue.
		 */
		if ((CFG_IST(ha, CFG_MULTI_CHIP_ADAPTER)) &&
		    (!CFG_IST(ha, CFG_SBUS_CARD))) {
			for (psydip = ddi_get_parent(ha->dip); psydip;
			    psydip = ddi_get_parent(psydip)) {
				if (strcmp(ddi_driver_name(psydip),
				    "pcipsy") == 0) {
					break;
				}
			}
		}
#endif	/* __sparc */

		if (psydip) {
			*rptr = (uint32_t)FC_NO_STREAMING;
			EL(ha, "No Streaming\n");
		} else {
			*rptr = (uint32_t)FC_ALLOW_STREAMING;
			EL(ha, "Allow Streaming\n");
		}
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_PAYLOAD_SIZE) == 0) {
		if (CFG_IST(ha, CFG_CTRL_24258081)) {
			*rptr = (uint32_t)CHAR_TO_SHORT(
			    ha->init_ctrl_blk.cb24.max_frame_length[0],
			    ha->init_ctrl_blk.cb24.max_frame_length[1]);
		} else {
			*rptr = (uint32_t)CHAR_TO_SHORT(
			    ha->init_ctrl_blk.cb.max_frame_length[0],
			    ha->init_ctrl_blk.cb.max_frame_length[1]);
		}
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_POST_RESET_BEHAVIOR) == 0) {
		*rptr = FC_RESET_RETURN_ALL;
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_FCP_DMA) == 0) {
		*rptr = FC_NO_DVMA_SPACE;
		rval = FC_CAP_FOUND;
	} else {
		EL(ha, "unknown=%s, FC_CAP_ERROR\n", cap);
		rval = FC_CAP_ERROR;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_set_cap
 *	Allow the FC Transport to set FCA capabilities if possible.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	cap = pointer to the capabilities string.
 *	ptr = buffer pointer for capability.
 *
 * Returns:
 *	FC_CAP_ERROR - no such capability
 *	FC_CAP_FOUND - the capability cannot be set by the FC Transport.
 *	FC_CAP_SETTABLE - the capability was successfully set.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_set_cap(opaque_t fca_handle, char *cap, void *ptr)
{
	ql_adapter_state_t	*ha;
	int			rval;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (strcmp(cap, FC_NODE_WWN) == 0) {
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_LOGIN_PARAMS) == 0) {
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_UNSOL_BUF) == 0) {
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_PAYLOAD_SIZE) == 0) {
		rval = FC_CAP_FOUND;
	} else if (strcmp(cap, FC_CAP_POST_RESET_BEHAVIOR) == 0) {
		rval = FC_CAP_FOUND;
	} else {
		EL(ha, "unknown=%s, FC_CAP_ERROR\n", cap);
		rval = FC_CAP_ERROR;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_getmap
 *	Request of Arbitrated Loop (AL-PA) map.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	mapbuf= buffer pointer for map.
 *
 * Returns:
 *	FC_OLDPORT - the specified port is not operating in loop mode.
 *	FC_OFFLINE - the specified port is not online.
 *	FC_NOMAP - there is no loop map available for this port.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_SUCCESS - a valid map has been placed in mapbuf.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_getmap(opaque_t fca_handle, fc_lilpmap_t *mapbuf)
{
	ql_adapter_state_t	*ha;
	clock_t			timer = drv_usectohz(30000000);
	int			rval = FC_SUCCESS;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mapbuf->lilp_magic = (uint16_t)MAGIC_LIRP;
	mapbuf->lilp_myalpa = ha->d_id.b.al_pa;

	/* Wait for suspension to end. */
	TASK_DAEMON_LOCK(ha);
	while (ha->task_daemon_flags & QL_SUSPENDED) {
		ha->task_daemon_flags |= SUSPENDED_WAKEUP_FLG;

		/* 30 seconds from now */
		if (cv_reltimedwait(&ha->pha->cv_dr_suspended,
		    &ha->pha->task_daemon_mutex, timer, TR_CLOCK_TICK) == -1) {
			/*
			 * The timeout time 'timer' was
			 * reached without the condition
			 * being signaled.
			 */

			/* Release task daemon lock. */
			TASK_DAEMON_UNLOCK(ha);

			EL(ha, "QL_SUSPENDED failed, FC_TRAN_BUSY\n");
			return (FC_TRAN_BUSY);
		}
	}
	/* Release task daemon lock. */
	TASK_DAEMON_UNLOCK(ha);

	if (ql_get_loop_position_map(ha, LOOP_POSITION_MAP_SIZE,
	    (caddr_t)&mapbuf->lilp_length) != QL_SUCCESS) {
		/*
		 * Now, since transport drivers cosider this as an
		 * offline condition, let's wait for few seconds
		 * for any loop transitions before we reset the.
		 * chip and restart all over again.
		 */
		ql_delay(ha, 2000000);
		EL(ha, "failed, FC_NOMAP\n");
		rval = FC_NOMAP;
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): my_alpa %xh len %xh "
		    "data %xh %xh %xh %xh\n", ha->instance,
		    mapbuf->lilp_myalpa, mapbuf->lilp_length,
		    mapbuf->lilp_alpalist[0], mapbuf->lilp_alpalist[1],
		    mapbuf->lilp_alpalist[2], mapbuf->lilp_alpalist[3]);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
#if 0
	QL_DUMP_3((uint8_t *)mapbuf, 8, sizeof (fc_lilpmap_t));
#endif
	return (rval);
}

/*
 * ql_transport
 *	Issue an I/O request. Handles all regular requests.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *	FC_BADPACKET - the packet to be transported had not been
 *			initialized by this FCA.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_transport(opaque_t fca_handle, fc_packet_t *pkt)
{
	ql_adapter_state_t	*ha;
	int			rval = FC_TRANSPORT_ERROR;
	ql_srb_t		*sp = (ql_srb_t *)pkt->pkt_fca_private;

	/* Verify proper command. */
	ha = ql_cmd_setup(fca_handle, pkt, &rval);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, ql_cmd_setup=%xh, fcah=%ph\n",
		    rval, fca_handle);
		return (rval);
	}
	QL_PRINT_3(CE_CONT, "(%d): started command:\n", ha->instance);
#if 0
	QL_DUMP_3((uint8_t *)&pkt->pkt_cmd_fhdr, 32,
	    sizeof (fc_frame_hdr_t) / 4);
	QL_PRINT_3(CE_CONT, "(%d): command:\n", ha->instance);
	QL_DUMP_3((uint8_t *)pkt->pkt_cmd, 8, pkt->pkt_cmdlen);
#endif

	/* Reset SRB flags. */
	sp->flags &= ~(SRB_ISP_STARTED | SRB_ISP_COMPLETED | SRB_RETRY |
	    SRB_POLL | SRB_WATCHDOG_ENABLED | SRB_ABORT | SRB_UB_CALLBACK |
	    SRB_UB_RSCN | SRB_UB_FCP | SRB_FCP_CMD_PKT | SRB_FCP_DATA_PKT |
	    SRB_FCP_RSP_PKT | SRB_IP_PKT | SRB_GENERIC_SERVICES_PKT |
	    SRB_COMMAND_TIMEOUT | SRB_ABORTING | SRB_IN_DEVICE_QUEUE |
	    SRB_IN_TOKEN_ARRAY | SRB_UB_FREE_REQUESTED | SRB_UB_ACQUIRED |
	    SRB_MS_PKT | SRB_ELS_PKT);

	pkt->pkt_resp_fhdr.d_id = ha->d_id.b24;
	pkt->pkt_resp_fhdr.r_ctl = R_CTL_STATUS;
	pkt->pkt_resp_fhdr.s_id = pkt->pkt_cmd_fhdr.d_id;
	pkt->pkt_resp_fhdr.f_ctl = pkt->pkt_cmd_fhdr.f_ctl;
	pkt->pkt_resp_fhdr.type = pkt->pkt_cmd_fhdr.type;

	switch (pkt->pkt_cmd_fhdr.r_ctl) {
	case R_CTL_COMMAND:
		if (pkt->pkt_cmd_fhdr.type == FC_TYPE_SCSI_FCP) {
			sp->flags |= SRB_FCP_CMD_PKT;
			rval = ql_fcp_scsi_cmd(ha, pkt, sp);
		}
		break;

	default:
		/* Setup response header and buffer. */
		if (pkt->pkt_rsplen) {
			bzero((void *)pkt->pkt_resp, pkt->pkt_rsplen);
		}

		switch (pkt->pkt_cmd_fhdr.r_ctl) {
		case R_CTL_UNSOL_DATA:
			if (pkt->pkt_cmd_fhdr.type == FC_TYPE_IS8802_SNAP) {
				sp->flags |= SRB_IP_PKT;
				rval = ql_fcp_ip_cmd(ha, pkt, sp);
			}
			break;

		case R_CTL_UNSOL_CONTROL:
			if (pkt->pkt_cmd_fhdr.type == FC_TYPE_FC_SERVICES) {
				sp->flags |= SRB_GENERIC_SERVICES_PKT;
				rval = ql_fc_services(ha, pkt);
			}
			break;

		case R_CTL_SOLICITED_DATA:
		case R_CTL_STATUS:
		default:
			pkt->pkt_state = FC_PKT_LOCAL_RJT;
			pkt->pkt_reason = FC_REASON_UNSUPPORTED;
			rval = FC_TRANSPORT_ERROR;
			EL(ha, "unknown, r_ctl=%xh\n",
			    pkt->pkt_cmd_fhdr.r_ctl);
			break;
		}
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_ub_alloc
 *	Allocate buffers for unsolicited exchanges.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	tokens = token array for each buffer.
 *	size = size of each buffer.
 *	count = pointer to number of buffers.
 *	type = the FC-4 type the buffers are reserved for.
 *		1 = Extended Link Services, 5 = LLC/SNAP
 *
 * Returns:
 *	FC_FAILURE - buffers could not be allocated.
 *	FC_TOOMANY - the FCA could not allocate the requested
 *			number of buffers.
 *	FC_SUCCESS - unsolicited buffers were allocated.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_ub_alloc(opaque_t fca_handle, uint64_t tokens[], uint32_t size,
    uint32_t *count, uint32_t type)
{
	ql_adapter_state_t	*ha;
	caddr_t			bufp = NULL;
	fc_unsol_buf_t		*ubp;
	ql_srb_t		*sp;
	uint32_t		index;
	uint32_t		cnt;
	uint32_t		ub_array_index = 0;
	int			rval = FC_SUCCESS;
	int			ub_updated = FALSE;

	/* Check handle. */
	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d,%d): started, count = %xh\n",
	    ha->instance, ha->vp_index, *count);

	QL_PM_LOCK(ha);
	if (ha->power_level != PM_LEVEL_D0) {
		QL_PM_UNLOCK(ha);
		QL_PRINT_3(CE_CONT, "(%d,%d): down done\n", ha->instance,
		    ha->vp_index);
		return (FC_FAILURE);
	}
	QL_PM_UNLOCK(ha);

	/* Acquire adapter state lock. */
	ADAPTER_STATE_LOCK(ha);

	/* Check the count. */
	if ((*count + ha->ub_allocated) > QL_UB_LIMIT) {
		*count = 0;
		EL(ha, "failed, FC_TOOMANY\n");
		rval = FC_TOOMANY;
	}

	/*
	 * reset ub_array_index
	 */
	ub_array_index = 0;

	/*
	 * Now proceed to allocate any buffers required
	 */
	for (index = 0; index < *count && rval == FC_SUCCESS; index++) {
		/* Allocate all memory needed. */
		ubp = (fc_unsol_buf_t *)kmem_zalloc(sizeof (fc_unsol_buf_t),
		    KM_SLEEP);
		if (ubp == NULL) {
			EL(ha, "failed, FC_FAILURE\n");
			rval = FC_FAILURE;
		} else {
			sp = kmem_zalloc(sizeof (ql_srb_t), KM_SLEEP);
			if (sp == NULL) {
				kmem_free(ubp, sizeof (fc_unsol_buf_t));
				rval = FC_FAILURE;
			} else {
				if (type == FC_TYPE_IS8802_SNAP) {
#ifdef	__sparc
					if (ql_get_dma_mem(ha,
					    &sp->ub_buffer, size,
					    BIG_ENDIAN_DMA,
					    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
						rval = FC_FAILURE;
						kmem_free(ubp,
						    sizeof (fc_unsol_buf_t));
						kmem_free(sp,
						    sizeof (ql_srb_t));
					} else {
						bufp = sp->ub_buffer.bp;
						sp->ub_size = size;
					}
#else
					if (ql_get_dma_mem(ha,
					    &sp->ub_buffer, size,
					    LITTLE_ENDIAN_DMA,
					    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
						rval = FC_FAILURE;
						kmem_free(ubp,
						    sizeof (fc_unsol_buf_t));
						kmem_free(sp,
						    sizeof (ql_srb_t));
					} else {
						bufp = sp->ub_buffer.bp;
						sp->ub_size = size;
					}
#endif
				} else {
					bufp = kmem_zalloc(size, KM_SLEEP);
					if (bufp == NULL) {
						rval = FC_FAILURE;
						kmem_free(ubp,
						    sizeof (fc_unsol_buf_t));
						kmem_free(sp,
						    sizeof (ql_srb_t));
					} else {
						sp->ub_size = size;
					}
				}
			}
		}

		if (rval == FC_SUCCESS) {
			/* Find next available slot. */
			QL_UB_LOCK(ha);
			while (ha->ub_array[ub_array_index] != NULL) {
				ub_array_index++;
			}

			ubp->ub_fca_private = (void *)sp;

			/* init cmd links */
			sp->cmd.base_address = sp;
			sp->cmd.prev = NULL;
			sp->cmd.next = NULL;
			sp->cmd.head = NULL;

			/* init wdg links */
			sp->wdg.base_address = sp;
			sp->wdg.prev = NULL;
			sp->wdg.next = NULL;
			sp->wdg.head = NULL;
			sp->ha = ha;

			ubp->ub_buffer = bufp;
			ubp->ub_bufsize = size;
			ubp->ub_port_handle = fca_handle;
			ubp->ub_token = ub_array_index;

			/* Save the token. */
			tokens[index] = ub_array_index;

			/* Setup FCA private information. */
			sp->ub_type = type;
			sp->handle = ub_array_index;
			sp->flags |= SRB_UB_IN_FCA;

			ha->ub_array[ub_array_index] = ubp;
			ha->ub_allocated++;
			ub_updated = TRUE;
			QL_UB_UNLOCK(ha);
		}
	}

	/* Release adapter state lock. */
	ADAPTER_STATE_UNLOCK(ha);

	/* IP buffer. */
	if (ub_updated) {
		if ((type == FC_TYPE_IS8802_SNAP) &&
		    (!(CFG_IST(ha, (CFG_CTRL_6322 | CFG_CTRL_2581))))) {

			ADAPTER_STATE_LOCK(ha);
			ha->flags |= IP_ENABLED;
			ADAPTER_STATE_UNLOCK(ha);

			if (!(ha->flags & IP_INITIALIZED)) {
				if (CFG_IST(ha, CFG_CTRL_2422)) {
					ha->ip_init_ctrl_blk.cb24.mtu_size[0] =
					    LSB(ql_ip_mtu);
					ha->ip_init_ctrl_blk.cb24.mtu_size[1] =
					    MSB(ql_ip_mtu);
					ha->ip_init_ctrl_blk.cb24.buf_size[0] =
					    LSB(size);
					ha->ip_init_ctrl_blk.cb24.buf_size[1] =
					    MSB(size);

					cnt = CHAR_TO_SHORT(
					    ha->ip_init_ctrl_blk.cb24.cc[0],
					    ha->ip_init_ctrl_blk.cb24.cc[1]);

					if (cnt < *count) {
						ha->ip_init_ctrl_blk.cb24.cc[0]
						    = LSB(*count);
						ha->ip_init_ctrl_blk.cb24.cc[1]
						    = MSB(*count);
					}
				} else {
					ha->ip_init_ctrl_blk.cb.mtu_size[0] =
					    LSB(ql_ip_mtu);
					ha->ip_init_ctrl_blk.cb.mtu_size[1] =
					    MSB(ql_ip_mtu);
					ha->ip_init_ctrl_blk.cb.buf_size[0] =
					    LSB(size);
					ha->ip_init_ctrl_blk.cb.buf_size[1] =
					    MSB(size);

					cnt = CHAR_TO_SHORT(
					    ha->ip_init_ctrl_blk.cb.cc[0],
					    ha->ip_init_ctrl_blk.cb.cc[1]);

					if (cnt < *count) {
						ha->ip_init_ctrl_blk.cb.cc[0] =
						    LSB(*count);
						ha->ip_init_ctrl_blk.cb.cc[1] =
						    MSB(*count);
					}
				}

				(void) ql_initialize_ip(ha);
			}
			ql_isp_rcvbuf(ha);
		}
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d,%d): done\n", ha->instance,
		    ha->vp_index);
	}
	return (rval);
}

/*
 * ql_ub_free
 *	Free unsolicited buffers.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	count = number of buffers.
 *	tokens = token array for each buffer.
 *
 * Returns:
 *	FC_SUCCESS - the requested buffers have been freed.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_UB_BADTOKEN - an invalid token was encountered.
 *			 No buffers have been released.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_ub_free(opaque_t fca_handle, uint32_t count, uint64_t tokens[])
{
	ql_adapter_state_t	*ha;
	ql_srb_t		*sp;
	uint32_t		index;
	uint64_t		ub_array_index;
	int			rval = FC_SUCCESS;

	/* Check handle. */
	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Acquire adapter state lock. */
	ADAPTER_STATE_LOCK(ha);

	/* Check all returned tokens. */
	for (index = 0; index < count; index++) {
		fc_unsol_buf_t	*ubp;

		/* Check the token range. */
		if ((ub_array_index = tokens[index]) >= QL_UB_LIMIT) {
			EL(ha, "failed, FC_UB_BADTOKEN\n");
			rval = FC_UB_BADTOKEN;
			break;
		}

		/* Check the unsolicited buffer array. */
		QL_UB_LOCK(ha);
		ubp = ha->ub_array[ub_array_index];

		if (ubp == NULL) {
			EL(ha, "failed, FC_UB_BADTOKEN-2\n");
			rval = FC_UB_BADTOKEN;
			QL_UB_UNLOCK(ha);
			break;
		}

		/* Check the state of the unsolicited buffer. */
		sp = ha->ub_array[ub_array_index]->ub_fca_private;
		sp->flags |= SRB_UB_FREE_REQUESTED;

		while (!(sp->flags & SRB_UB_IN_FCA) ||
		    (sp->flags & (SRB_UB_CALLBACK | SRB_UB_ACQUIRED))) {
			QL_UB_UNLOCK(ha);
			ADAPTER_STATE_UNLOCK(ha);
			delay(drv_usectohz(100000));
			ADAPTER_STATE_LOCK(ha);
			QL_UB_LOCK(ha);
		}
		ha->ub_array[ub_array_index] = NULL;
		QL_UB_UNLOCK(ha);
		ql_free_unsolicited_buffer(ha, ubp);
	}

	if (rval == FC_SUCCESS) {
		/*
		 * Signal any pending hardware reset when there are
		 * no more unsolicited buffers in use.
		 */
		if (ha->ub_allocated == 0) {
			cv_broadcast(&ha->pha->cv_ub);
		}
	}

	/* Release adapter state lock. */
	ADAPTER_STATE_UNLOCK(ha);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_ub_release
 *	Release unsolicited buffers from FC Transport
 *	to FCA for future use.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	count = number of buffers.
 *	tokens = token array for each buffer.
 *
 * Returns:
 *	FC_SUCCESS - the requested buffers have been released.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_UB_BADTOKEN - an invalid token was encountered.
 *		No buffers have been released.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_ub_release(opaque_t fca_handle, uint32_t count, uint64_t tokens[])
{
	ql_adapter_state_t	*ha;
	ql_srb_t		*sp;
	uint32_t		index;
	uint64_t		ub_array_index;
	int			rval = FC_SUCCESS;
	int			ub_ip_updated = FALSE;

	/* Check handle. */
	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, ": failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Acquire adapter state lock. */
	ADAPTER_STATE_LOCK(ha);
	QL_UB_LOCK(ha);

	/* Check all returned tokens. */
	for (index = 0; index < count; index++) {
		/* Check the token range. */
		if ((ub_array_index = tokens[index]) >= QL_UB_LIMIT) {
			EL(ha, "failed, FC_UB_BADTOKEN\n");
			rval = FC_UB_BADTOKEN;
			break;
		}

		/* Check the unsolicited buffer array. */
		if (ha->ub_array[ub_array_index] == NULL) {
			EL(ha, "failed, FC_UB_BADTOKEN-2\n");
			rval = FC_UB_BADTOKEN;
			break;
		}

		/* Check the state of the unsolicited buffer. */
		sp = ha->ub_array[ub_array_index]->ub_fca_private;
		if (sp->flags & SRB_UB_IN_FCA) {
			EL(ha, "failed, FC_UB_BADTOKEN-3\n");
			rval = FC_UB_BADTOKEN;
			break;
		}
	}

	/* If all tokens checkout, release the buffers. */
	if (rval == FC_SUCCESS) {
		/* Check all returned tokens. */
		for (index = 0; index < count; index++) {
			fc_unsol_buf_t	*ubp;

			ub_array_index = tokens[index];
			ubp = ha->ub_array[ub_array_index];
			sp = ubp->ub_fca_private;

			ubp->ub_resp_flags = 0;
			sp->flags &= ~(SRB_UB_ACQUIRED | SRB_UB_CALLBACK);
			sp->flags |= SRB_UB_IN_FCA;

			/* IP buffer. */
			if (sp->ub_type == FC_TYPE_IS8802_SNAP) {
				ub_ip_updated = TRUE;
			}
		}
	}

	QL_UB_UNLOCK(ha);
	/* Release adapter state lock. */
	ADAPTER_STATE_UNLOCK(ha);

	/*
	 * XXX: We should call ql_isp_rcvbuf() to return a
	 * buffer to ISP only if the number of buffers fall below
	 * the low water mark.
	 */
	if (ub_ip_updated) {
		ql_isp_rcvbuf(ha);
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_abort
 *	Abort a packet.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	pkt = pointer to fc_packet.
 *	flags = KM_SLEEP flag.
 *
 * Returns:
 *	FC_SUCCESS - the packet has successfully aborted.
 *	FC_ABORTED - the packet has successfully aborted.
 *	FC_ABORTING - the packet is being aborted.
 *	FC_ABORT_FAILED - the packet could not be aborted.
 *	FC_TRANSPORT_ERROR - a transport error occurred while attempting
 *		to abort the packet.
 *	FC_BADEXCHANGE - no packet found.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_abort(opaque_t fca_handle, fc_packet_t *pkt, int flags)
{
	port_id_t		d_id;
	ql_link_t		*link;
	ql_adapter_state_t	*ha, *pha;
	ql_srb_t		*sp;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	int			rval = FC_ABORTED;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}

	pha = ha->pha;

	QL_PRINT_3(CE_CONT, "(%d,%d): started\n", ha->instance, ha->vp_index);

	/* Get target queue pointer. */
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	tq = ql_d_id_to_queue(ha, d_id);

	if ((tq == NULL) || (pha->task_daemon_flags & LOOP_DOWN)) {
		if (tq == NULL) {
			EL(ha, "failed, FC_TRANSPORT_ERROR\n");
			rval = FC_TRANSPORT_ERROR;
		} else {
			EL(ha, "failed, FC_OFFLINE\n");
			rval = FC_OFFLINE;
		}
		return (rval);
	}

	sp = (ql_srb_t *)pkt->pkt_fca_private;
	lq = sp->lun_queue;

	/* Set poll flag if sleep wanted. */
	if (flags == KM_SLEEP) {
		sp->flags |= SRB_POLL;
	}

	/* Acquire target queue lock. */
	DEVICE_QUEUE_LOCK(tq);
	REQUEST_RING_LOCK(ha);

	/* If command not already started. */
	if (!(sp->flags & SRB_ISP_STARTED)) {
		/* Check pending queue for command. */
		sp = NULL;
		for (link = pha->pending_cmds.first; link != NULL;
		    link = link->next) {
			sp = link->base_address;
			if (sp == (ql_srb_t *)pkt->pkt_fca_private) {
				/* Remove srb from q. */
				ql_remove_link(&pha->pending_cmds, &sp->cmd);
				break;
			} else {
				sp = NULL;
			}
		}
		REQUEST_RING_UNLOCK(ha);

		if (sp == NULL) {
			/* Check for cmd on device queue. */
			for (link = lq->cmd.first; link != NULL;
			    link = link->next) {
				sp = link->base_address;
				if (sp == (ql_srb_t *)pkt->pkt_fca_private) {
					/* Remove srb from q. */
					ql_remove_link(&lq->cmd, &sp->cmd);
					break;
				} else {
					sp = NULL;
				}
			}
		}
		/* Release device lock */
		DEVICE_QUEUE_UNLOCK(tq);

		/* If command on target queue. */
		if (sp != NULL) {
			sp->flags &= ~SRB_IN_DEVICE_QUEUE;

			/* Set return status */
			pkt->pkt_reason = CS_ABORTED;

			sp->cmd.next = NULL;
			ql_done(&sp->cmd);
			rval = FC_ABORTED;
		} else {
			EL(ha, "failed, FC_BADEXCHANGE\n");
			rval = FC_BADEXCHANGE;
		}
	} else if (sp->flags & SRB_ISP_COMPLETED) {
		/* Release device queue lock. */
		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);
		EL(ha, "failed, already done, FC_FAILURE\n");
		rval = FC_FAILURE;
	} else if ((sp->pkt->pkt_cmd_fhdr.r_ctl == R_CTL_SOLICITED_DATA) ||
	    (sp->pkt->pkt_cmd_fhdr.r_ctl == R_CTL_STATUS)) {
		/*
		 * If here, target data/resp ctio is with Fw.
		 * Since firmware is supposed to terminate such I/Os
		 * with an error, we need not do any thing. If FW
		 * decides not to terminate those IOs and simply keep
		 * quite then we need to initiate cleanup here by
		 * calling ql_done.
		 */
		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);
		rval = FC_ABORTED;
	} else {
		request_t	*ep = pha->request_ring_bp;
		uint16_t	cnt;

		if (sp->handle != 0) {
			for (cnt = 0; cnt < REQUEST_ENTRY_CNT; cnt++) {
				if (sp->handle == ddi_get32(
				    pha->hba_buf.acc_handle, &ep->handle)) {
					ep->entry_type = INVALID_ENTRY_TYPE;
					break;
				}
				ep++;
			}
		}

		/* Release device queue lock. */
		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);

		sp->flags |= SRB_ABORTING;
		(void) ql_abort_command(ha, sp);
		pkt->pkt_reason = CS_ABORTED;
		rval = FC_ABORTED;
	}

	QL_PRINT_3(CE_CONT, "(%d,%d): done\n", ha->instance, ha->vp_index);

	return (rval);
}

/*
 * ql_reset
 *	Reset link or hardware.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	cmd = reset type command.
 *
 * Returns:
 *	FC_SUCCESS - reset has successfully finished.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *	FC_FAILURE - reset failed.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_reset(opaque_t fca_handle, uint32_t cmd)
{
	ql_adapter_state_t	*ha;
	int			rval = FC_SUCCESS, rval2;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}

	QL_PRINT_3(CE_CONT, "(%d,%d): started, cmd=%d\n", ha->instance,
	    ha->vp_index, cmd);

	switch (cmd) {
	case FC_FCA_CORE:
		/* dump firmware core if specified. */
		if (ha->vp_index == 0) {
			if (ql_dump_firmware(ha) != QL_SUCCESS) {
				EL(ha, "failed, FC_FAILURE\n");
				rval = FC_FAILURE;
			}
		}
		break;
	case FC_FCA_LINK_RESET:
		if (!(ha->pha->task_daemon_flags & LOOP_DOWN)) {
			if (ql_loop_reset(ha) != QL_SUCCESS) {
				EL(ha, "failed, FC_FAILURE-2\n");
				rval = FC_FAILURE;
			}
		}
		break;
	case FC_FCA_RESET_CORE:
	case FC_FCA_RESET:
		/* if dump firmware core if specified. */
		if (cmd == FC_FCA_RESET_CORE) {
			if (ha->vp_index != 0) {
				rval2 = ha->pha->task_daemon_flags & LOOP_DOWN
				    ? QL_SUCCESS : ql_loop_reset(ha);
			} else {
				rval2 = ql_dump_firmware(ha);
			}
			if (rval2 != QL_SUCCESS) {
				EL(ha, "failed, FC_FAILURE-3\n");
				rval = FC_FAILURE;
			}
		}

		/* Free up all unsolicited buffers. */
		if (ha->ub_allocated != 0) {
			/* Inform to release buffers. */
			ha->state = FC_PORT_SPEED_MASK(ha->state);
			ha->state |= FC_STATE_RESET_REQUESTED;
			if (ha->flags & FCA_BOUND) {
				(ha->bind_info.port_statec_cb)
				    (ha->bind_info.port_handle,
				    ha->state);
			}
		}

		ha->state = FC_PORT_SPEED_MASK(ha->state);

		/* All buffers freed */
		if (ha->ub_allocated == 0) {
			/* Hardware reset. */
			if (cmd == FC_FCA_RESET) {
				if (ha->vp_index == 0) {
					(void) ql_abort_isp(ha);
				} else if (!(ha->pha->task_daemon_flags &
				    LOOP_DOWN)) {
					(void) ql_loop_reset(ha);
				}
			}

			/* Inform that the hardware has been reset */
			ha->state |= FC_STATE_RESET;
		} else {
			/*
			 * the port driver expects an online if
			 * buffers are not freed.
			 */
			if (ha->topology & QL_LOOP_CONNECTION) {
				ha->state |= FC_STATE_LOOP;
			} else {
				ha->state |= FC_STATE_ONLINE;
			}
		}

		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags |= FC_STATE_CHANGE;
		TASK_DAEMON_UNLOCK(ha);

		ql_awaken_task_daemon(ha, NULL, FC_STATE_CHANGE, 0);

		break;
	default:
		EL(ha, "unknown cmd=%xh\n", cmd);
		break;
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "cmd=%xh, failed=%xh\n", cmd, rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d,%d): done\n", ha->instance,
		    ha->vp_index);
	}

	return (rval);
}

/*
 * ql_port_manage
 *	Perform port management or diagnostics.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	cmd = pointer to command structure.
 *
 * Returns:
 *	FC_SUCCESS - the request completed successfully.
 *	FC_FAILURE - the request did not complete successfully.
 *	FC_UNBOUND - the fca_handle specified is not bound.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_port_manage(opaque_t fca_handle, fc_fca_pm_t *cmd)
{
	clock_t			timer;
	uint16_t		index;
	uint32_t		*bp;
	port_id_t		d_id;
	ql_link_t		*link;
	ql_adapter_state_t	*ha, *pha;
	ql_tgt_t		*tq;
	dma_mem_t		buffer_xmt, buffer_rcv;
	size_t			length;
	uint32_t		cnt;
	char			buf[80];
	lbp_t			*lb;
	ql_mbx_data_t		mr;
	app_mbx_cmd_t		*mcp;
	int			i0;
	uint8_t			*bptr;
	int			rval2, rval = FC_SUCCESS;
	uint32_t		opcode;
	uint32_t		set_flags = 0;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, ": failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	pha = ha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started=%xh\n", ha->instance,
	    cmd->pm_cmd_code);

	ql_awaken_task_daemon(ha, NULL, DRIVER_STALL, 0);

	/*
	 * Wait for all outstanding commands to complete
	 */
	index = (uint16_t)ql_wait_outstanding(ha);

	if (index != MAX_OUTSTANDING_COMMANDS) {
		ql_awaken_task_daemon(ha, NULL, 0, DRIVER_STALL);
		ql_restart_queues(ha);
		EL(ha, "failed, FC_TRAN_BUSY\n");
		return (FC_TRAN_BUSY);
	}

	switch (cmd->pm_cmd_code) {
	case FC_PORT_BYPASS:
		d_id.b24 = *cmd->pm_cmd_buf;
		tq = ql_d_id_to_queue(ha, d_id);
		if (tq == NULL || ql_loop_port_bypass(ha, tq) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_BYPASS FC_FAILURE\n");
			rval = FC_FAILURE;
		}
		break;
	case FC_PORT_UNBYPASS:
		d_id.b24 = *cmd->pm_cmd_buf;
		tq = ql_d_id_to_queue(ha, d_id);
		if (tq == NULL || ql_loop_port_enable(ha, tq) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_UNBYPASS FC_FAILURE\n");
			rval = FC_FAILURE;
		}
		break;
	case FC_PORT_GET_FW_REV:
		(void) sprintf(buf, "%d.%d.%d", pha->fw_major_version,
		    pha->fw_minor_version, pha->fw_subminor_version);
		length = strlen(buf) + 1;
		if (cmd->pm_data_len < length) {
			cmd->pm_data_len = length;
			EL(ha, "failed, FC_PORT_GET_FW_REV FC_FAILURE\n");
			rval = FC_FAILURE;
		} else {
			(void) strcpy(cmd->pm_data_buf, buf);
		}
		break;

	case FC_PORT_GET_FCODE_REV: {
		caddr_t		fcode_ver_buf = NULL;

		i0 = 0;
		/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
		rval2 = ddi_getlongprop(DDI_DEV_T_ANY, ha->dip,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "version",
		    (caddr_t)&fcode_ver_buf, &i0);
		length = (uint_t)i0;

		if (rval2 != DDI_PROP_SUCCESS) {
			EL(ha, "failed, getting version = %xh\n", rval2);
			length = 20;
			fcode_ver_buf = kmem_alloc(length, KM_SLEEP);
			if (fcode_ver_buf != NULL) {
				(void) sprintf(fcode_ver_buf,
				    "NO FCODE FOUND");
			}
		}

		if (cmd->pm_data_len < length) {
			EL(ha, "length error, FC_PORT_GET_FCODE_REV "
			    "dst=%ld, src=%ld\n", cmd->pm_data_len, length);
			cmd->pm_data_len = length;
			rval = FC_FAILURE;
		} else if (fcode_ver_buf != NULL) {
			bcopy((void *)fcode_ver_buf, (void *)cmd->pm_data_buf,
			    length);
		}

		if (fcode_ver_buf != NULL) {
			kmem_free(fcode_ver_buf, length);
		}
		break;
	}

	case FC_PORT_GET_DUMP:
		QL_DUMP_LOCK(pha);
		if (cmd->pm_data_len < (size_t)pha->risc_dump_size) {
			EL(ha, "failed, FC_PORT_GET_DUMP incorrect "
			    "length=%lxh\n", cmd->pm_data_len);
			cmd->pm_data_len = pha->risc_dump_size;
			rval = FC_FAILURE;
		} else if (pha->ql_dump_state & QL_DUMPING) {
			EL(ha, "failed, FC_PORT_GET_DUMP FC_TRAN_BUSY\n");
			rval = FC_TRAN_BUSY;
		} else if (pha->ql_dump_state & QL_DUMP_VALID) {
			(void) ql_ascii_fw_dump(ha, cmd->pm_data_buf);
			pha->ql_dump_state |= QL_DUMP_UPLOADED;
		} else {
			EL(ha, "failed, FC_PORT_GET_DUMP no dump file\n");
			rval = FC_FAILURE;
		}
		QL_DUMP_UNLOCK(pha);
		break;
	case FC_PORT_FORCE_DUMP:
		PORTMANAGE_LOCK(ha);
		if (ql_dump_firmware(ha) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_FORCE_DUMP FC_FAILURE\n");
			rval = FC_FAILURE;
		}
		PORTMANAGE_UNLOCK(ha);
		break;
	case FC_PORT_DOWNLOAD_FW:
		PORTMANAGE_LOCK(ha);
		if (CFG_IST(ha, CFG_CTRL_24258081)) {
			if (ql_24xx_load_flash(ha, (uint8_t *)cmd->pm_data_buf,
			    (uint32_t)cmd->pm_data_len,
			    ha->flash_fw_addr << 2) != QL_SUCCESS) {
				EL(ha, "failed, FC_PORT_DOWNLOAD_FW\n");
				rval = FC_FAILURE;
			}
			ql_reset_chip(ha);
			set_flags |= ISP_ABORT_NEEDED;
		} else {
			/* Save copy of the firmware. */
			if (pha->risc_code != NULL) {
				kmem_free(pha->risc_code, pha->risc_code_size);
				pha->risc_code = NULL;
				pha->risc_code_size = 0;
			}

			pha->risc_code = kmem_alloc(cmd->pm_data_len,
			    KM_SLEEP);
			if (pha->risc_code != NULL) {
				pha->risc_code_size =
				    (uint32_t)cmd->pm_data_len;
				bcopy(cmd->pm_data_buf, pha->risc_code,
				    cmd->pm_data_len);

				/* Do abort to force reload. */
				ql_reset_chip(ha);
				if (ql_abort_isp(ha) != QL_SUCCESS) {
					kmem_free(pha->risc_code,
					    pha->risc_code_size);
					pha->risc_code = NULL;
					pha->risc_code_size = 0;
					ql_reset_chip(ha);
					(void) ql_abort_isp(ha);
					EL(ha, "failed, FC_PORT_DOWNLOAD_FW"
					    " FC_FAILURE\n");
					rval = FC_FAILURE;
				}
			}
		}
		PORTMANAGE_UNLOCK(ha);
		break;
	case FC_PORT_GET_DUMP_SIZE:
		bp = (uint32_t *)cmd->pm_data_buf;
		*bp = pha->risc_dump_size;
		break;
	case FC_PORT_DIAG:
		/*
		 * Prevents concurrent diags
		 */
		PORTMANAGE_LOCK(ha);

		/* Wait for suspension to end. */
		for (timer = 0; timer < 3000 &&
		    pha->task_daemon_flags & QL_LOOP_TRANSITION; timer++) {
			ql_delay(ha, 10000);
		}

		if (pha->task_daemon_flags & QL_LOOP_TRANSITION) {
			EL(ha, "failed, FC_TRAN_BUSY-2\n");
			rval = FC_TRAN_BUSY;
			PORTMANAGE_UNLOCK(ha);
			break;
		}

		switch (cmd->pm_cmd_flags) {
		case QL_DIAG_EXEFMW:
			if (ql_start_firmware(ha) != QL_SUCCESS) {
				EL(ha, "failed, QL_DIAG_EXEFMW FC_FAILURE\n");
				rval = FC_FAILURE;
			}
			break;
		case QL_DIAG_CHKCMDQUE:
			for (i0 = 1, cnt = 0; i0 < MAX_OUTSTANDING_COMMANDS;
			    i0++) {
				cnt += (pha->outstanding_cmds[i0] != NULL);
			}
			if (cnt != 0) {
				EL(ha, "failed, QL_DIAG_CHKCMDQUE "
				    "FC_FAILURE\n");
				rval = FC_FAILURE;
			}
			break;
		case QL_DIAG_FMWCHKSUM:
			if (ql_verify_checksum(ha) != QL_SUCCESS) {
				EL(ha, "failed, QL_DIAG_FMWCHKSUM "
				    "FC_FAILURE\n");
				rval = FC_FAILURE;
			}
			break;
		case QL_DIAG_SLFTST:
			if (ql_online_selftest(ha) != QL_SUCCESS) {
				EL(ha, "failed, QL_DIAG_SLFTST FC_FAILURE\n");
				rval = FC_FAILURE;
			}
			ql_reset_chip(ha);
			set_flags |= ISP_ABORT_NEEDED;
			break;
		case QL_DIAG_REVLVL:
			if (cmd->pm_stat_len <
			    sizeof (ql_adapter_revlvl_t)) {
				EL(ha, "failed, QL_DIAG_REVLVL FC_NOMEM, "
				    "slen=%lxh, rlvllen=%lxh\n",
				    cmd->pm_stat_len,
				    sizeof (ql_adapter_revlvl_t));
				rval = FC_NOMEM;
			} else {
				bcopy((void *)&(pha->adapter_stats->revlvl),
				    cmd->pm_stat_buf,
				    (size_t)cmd->pm_stat_len);
				cmd->pm_stat_len =
				    sizeof (ql_adapter_revlvl_t);
			}
			break;
		case QL_DIAG_LPBMBX:

			if (cmd->pm_data_len != sizeof (struct app_mbx_cmd)) {
				EL(ha, "failed, QL_DIAG_LPBMBX "
				    "FC_INVALID_REQUEST, pmlen=%lxh, "
				    "reqd=%lxh\n", cmd->pm_data_len,
				    sizeof (struct app_mbx_cmd));
				rval = FC_INVALID_REQUEST;
				break;
			}
			/*
			 * Don't do the wrap test on a 2200 when the
			 * firmware is running.
			 */
			if (!CFG_IST(ha, CFG_CTRL_2200)) {
				mcp = (app_mbx_cmd_t *)cmd->pm_data_buf;
				mr.mb[1] = mcp->mb[1];
				mr.mb[2] = mcp->mb[2];
				mr.mb[3] = mcp->mb[3];
				mr.mb[4] = mcp->mb[4];
				mr.mb[5] = mcp->mb[5];
				mr.mb[6] = mcp->mb[6];
				mr.mb[7] = mcp->mb[7];

				bcopy(&mr.mb[0], &mr.mb[10],
				    sizeof (uint16_t) * 8);

				if (ql_mbx_wrap_test(ha, &mr) != QL_SUCCESS) {
					EL(ha, "failed, QL_DIAG_LPBMBX "
					    "FC_FAILURE\n");
					rval = FC_FAILURE;
					break;
				} else {
					for (i0 = 1; i0 < 8; i0++) {
						if (mr.mb[i0] !=
						    mr.mb[i0 + 10]) {
							EL(ha, "failed, "
							    "QL_DIAG_LPBMBX "
							    "FC_FAILURE-2\n");
							rval = FC_FAILURE;
							break;
						}
					}
				}

				if (rval == FC_FAILURE) {
					(void) ql_flash_errlog(ha,
					    FLASH_ERRLOG_ISP_ERR, 0,
					    RD16_IO_REG(ha, hccr),
					    RD16_IO_REG(ha, istatus));
					set_flags |= ISP_ABORT_NEEDED;
				}
			}
			break;
		case QL_DIAG_LPBDTA:
			/*
			 * For loopback data, we receive the
			 * data back in pm_stat_buf. This provides
			 * the user an opportunity to compare the
			 * transmitted and received data.
			 *
			 * NB: lb->options are:
			 *	0 --> Ten bit loopback
			 *	1 --> One bit loopback
			 *	2 --> External loopback
			 */
			if (cmd->pm_data_len > 65536) {
				rval = FC_TOOMANY;
				EL(ha, "failed, QL_DIAG_LPBDTA "
				    "FC_TOOMANY=%lxh\n", cmd->pm_data_len);
				break;
			}
			if (ql_get_dma_mem(ha, &buffer_xmt,
			    (uint32_t)cmd->pm_data_len, LITTLE_ENDIAN_DMA,
			    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
				EL(ha, "failed, QL_DIAG_LPBDTA FC_NOMEM\n");
				rval = FC_NOMEM;
				break;
			}
			if (ql_get_dma_mem(ha, &buffer_rcv,
			    (uint32_t)cmd->pm_data_len, LITTLE_ENDIAN_DMA,
			    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
				EL(ha, "failed, QL_DIAG_LPBDTA FC_NOMEM-2\n");
				rval = FC_NOMEM;
				break;
			}
			ddi_rep_put8(buffer_xmt.acc_handle,
			    (uint8_t *)cmd->pm_data_buf,
			    (uint8_t *)buffer_xmt.bp,
			    cmd->pm_data_len, DDI_DEV_AUTOINCR);

			/* 22xx's adapter must be in loop mode for test. */
			if (CFG_IST(ha, CFG_CTRL_2200)) {
				bptr = &ha->init_ctrl_blk.cb.add_fw_opt[0];
				if (ha->flags & POINT_TO_POINT ||
				    (ha->task_daemon_flags & LOOP_DOWN &&
				    *bptr & (BIT_6 | BIT_5 | BIT_4))) {
					cnt = *bptr;
					*bptr = (uint8_t)
					    (*bptr & ~(BIT_6|BIT_5|BIT_4));
					(void) ql_abort_isp(ha);
					*bptr = (uint8_t)cnt;
				}
			}

			/* Shutdown IP. */
			if (pha->flags & IP_INITIALIZED) {
				(void) ql_shutdown_ip(pha);
			}

			lb = (lbp_t *)cmd->pm_cmd_buf;
			lb->transfer_count =
			    (uint32_t)cmd->pm_data_len;
			lb->transfer_segment_count = 0;
			lb->receive_segment_count = 0;
			lb->transfer_data_address =
			    buffer_xmt.cookie.dmac_address;
			lb->receive_data_address =
			    buffer_rcv.cookie.dmac_address;

			if (ql_loop_back(ha, 0, lb,
			    buffer_xmt.cookie.dmac_notused,
			    buffer_rcv.cookie.dmac_notused) == QL_SUCCESS) {
				bzero((void *)cmd->pm_stat_buf,
				    cmd->pm_stat_len);
				ddi_rep_get8(buffer_rcv.acc_handle,
				    (uint8_t *)cmd->pm_stat_buf,
				    (uint8_t *)buffer_rcv.bp,
				    cmd->pm_stat_len, DDI_DEV_AUTOINCR);
				rval = FC_SUCCESS;
			} else {
				EL(ha, "failed, QL_DIAG_LPBDTA FC_FAILURE\n");
				rval = FC_FAILURE;
			}

			ql_free_phys(ha, &buffer_xmt);
			ql_free_phys(ha, &buffer_rcv);

			/* Needed to recover the f/w */
			set_flags |= ISP_ABORT_NEEDED;

			/* Restart IP if it was shutdown. */
			if (pha->flags & IP_ENABLED &&
			    !(pha->flags & IP_INITIALIZED)) {
				(void) ql_initialize_ip(pha);
				ql_isp_rcvbuf(pha);
			}

			break;
		case QL_DIAG_ECHO: {
			/*
			 * issue an echo command with a user supplied
			 * data pattern and destination address
			 */
			echo_t		echo;		/* temp echo struct */

			/* Setup echo cmd & adjust for platform */
			opcode = QL_ECHO_CMD;
			BIG_ENDIAN_32(&opcode);

			/*
			 * due to limitations in the ql
			 * firmaware the echo data field is
			 * limited to 220
			 */
			if ((cmd->pm_cmd_len > QL_ECHO_CMD_LENGTH) ||
			    (cmd->pm_stat_len > QL_ECHO_CMD_LENGTH)) {
				EL(ha, "failed, QL_DIAG_ECHO FC_TOOMANY, "
				    "cmdl1=%lxh, statl2=%lxh\n",
				    cmd->pm_cmd_len, cmd->pm_stat_len);
				rval = FC_TOOMANY;
				break;
			}

			/*
			 * the input data buffer has the user
			 * supplied data pattern.  The "echoed"
			 * data will be DMAed into the output
			 * data buffer.  Therefore the length
			 * of the output buffer must be equal
			 * to or greater then the input buffer
			 * length
			 */
			if (cmd->pm_cmd_len > cmd->pm_stat_len) {
				EL(ha, "failed, QL_DIAG_ECHO FC_TOOMANY-2,"
				    " cmdl1=%lxh, statl2=%lxh\n",
				    cmd->pm_cmd_len, cmd->pm_stat_len);
				rval = FC_TOOMANY;
				break;
			}
			/* add four bytes for the opcode */
			echo.transfer_count = (uint32_t)(cmd->pm_cmd_len + 4);

			/*
			 * are we 32 or 64 bit addressed???
			 * We need to get the appropriate
			 * DMA and set the command options;
			 * 64 bit (bit 6) or 32 bit
			 * (no bit 6) addressing.
			 * while we are at it lets ask for
			 * real echo (bit 15)
			 */
			echo.options = BIT_15;
			if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING) &&
			    !(CFG_IST(ha, CFG_CTRL_8081))) {
				echo.options = (uint16_t)
				    (echo.options | BIT_6);
			}

			/*
			 * Set up the DMA mappings for the
			 * output and input data buffers.
			 * First the output buffer
			 */
			if (ql_get_dma_mem(ha, &buffer_xmt,
			    (uint32_t)(cmd->pm_data_len + 4),
			    LITTLE_ENDIAN_DMA,
			    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
				EL(ha, "failed, QL_DIAG_ECHO FC_NOMEM\n");
				rval = FC_NOMEM;
				break;
			}
			echo.transfer_data_address = buffer_xmt.cookie;

			/* Next the input buffer */
			if (ql_get_dma_mem(ha, &buffer_rcv,
			    (uint32_t)(cmd->pm_data_len + 4),
			    LITTLE_ENDIAN_DMA,
			    QL_DMA_DATA_ALIGN) != QL_SUCCESS) {
				/*
				 * since we could not allocate
				 * DMA space for the input
				 * buffer we need to clean up
				 * by freeing the DMA space
				 * we allocated for the output
				 * buffer
				 */
				ql_free_phys(ha, &buffer_xmt);
				EL(ha, "failed, QL_DIAG_ECHO FC_NOMEM-2\n");
				rval = FC_NOMEM;
				break;
			}
			echo.receive_data_address = buffer_rcv.cookie;

			/*
			 * copy the 4 byte ECHO op code to the
			 * allocated DMA space
			 */
			ddi_rep_put8(buffer_xmt.acc_handle, (uint8_t *)&opcode,
			    (uint8_t *)buffer_xmt.bp, 4, DDI_DEV_AUTOINCR);

			/*
			 * copy the user supplied data to the
			 * allocated DMA space
			 */
			ddi_rep_put8(buffer_xmt.acc_handle,
			    (uint8_t *)cmd->pm_cmd_buf,
			    (uint8_t *)buffer_xmt.bp + 4, cmd->pm_cmd_len,
			    DDI_DEV_AUTOINCR);

			/* Shutdown IP. */
			if (pha->flags & IP_INITIALIZED) {
				(void) ql_shutdown_ip(pha);
			}

			/* send the echo */
			if (ql_echo(ha, 0, &echo) == QL_SUCCESS) {
				ddi_rep_put8(buffer_rcv.acc_handle,
				    (uint8_t *)buffer_rcv.bp + 4,
				    (uint8_t *)cmd->pm_stat_buf,
				    cmd->pm_stat_len, DDI_DEV_AUTOINCR);
			} else {
				EL(ha, "failed, QL_DIAG_ECHO FC_FAILURE\n");
				rval = FC_FAILURE;
			}

			/* Restart IP if it was shutdown. */
			if (pha->flags & IP_ENABLED &&
			    !(pha->flags & IP_INITIALIZED)) {
				(void) ql_initialize_ip(pha);
				ql_isp_rcvbuf(pha);
			}
			/* free up our DMA buffers */
			ql_free_phys(ha, &buffer_xmt);
			ql_free_phys(ha, &buffer_rcv);
			break;
		}
		default:
			EL(ha, "unknown=%xh, FC_PORT_DIAG "
			    "FC_INVALID_REQUEST\n", cmd->pm_cmd_flags);
			rval = FC_INVALID_REQUEST;
			break;
		}
		PORTMANAGE_UNLOCK(ha);
		break;
	case FC_PORT_LINK_STATE:
		/* Check for name equal to null. */
		for (index = 0; index < 8 && index < cmd->pm_cmd_len;
		    index++) {
			if (cmd->pm_cmd_buf[index] != 0) {
				break;
			}
		}

		/* If name not null. */
		if (index < 8 && cmd->pm_cmd_len >= 8) {
			/* Locate device queue. */
			tq = NULL;
			for (index = 0; index < DEVICE_HEAD_LIST_SIZE &&
			    tq == NULL; index++) {
				for (link = ha->dev[index].first; link != NULL;
				    link = link->next) {
					tq = link->base_address;

					if (bcmp((void *)&tq->port_name[0],
					    (void *)cmd->pm_cmd_buf, 8) == 0) {
						break;
					} else {
						tq = NULL;
					}
				}
			}

			if (tq != NULL && VALID_DEVICE_ID(ha, tq->loop_id)) {
				cmd->pm_stat_buf[0] = (int8_t)LSB(ha->state);
				cmd->pm_stat_buf[1] = (int8_t)MSB(ha->state);
			} else {
				cnt = FC_PORT_SPEED_MASK(ha->state) |
				    FC_STATE_OFFLINE;
				cmd->pm_stat_buf[0] = (int8_t)LSB(cnt);
				cmd->pm_stat_buf[1] = (int8_t)MSB(cnt);
			}
		} else {
			cmd->pm_stat_buf[0] = (int8_t)LSB(ha->state);
			cmd->pm_stat_buf[1] = (int8_t)MSB(ha->state);
		}
		break;
	case FC_PORT_INITIALIZE:
		if (cmd->pm_cmd_len >= 8) {
			tq = NULL;
			for (index = 0; index < DEVICE_HEAD_LIST_SIZE &&
			    tq == NULL; index++) {
				for (link = ha->dev[index].first; link != NULL;
				    link = link->next) {
					tq = link->base_address;

					if (bcmp((void *)&tq->port_name[0],
					    (void *)cmd->pm_cmd_buf, 8) == 0) {
						if (!VALID_DEVICE_ID(ha,
						    tq->loop_id)) {
							tq = NULL;
						}
						break;
					} else {
						tq = NULL;
					}
				}
			}

			if (tq == NULL || ql_target_reset(ha, tq,
			    ha->loop_reset_delay) != QL_SUCCESS) {
				EL(ha, "failed, FC_PORT_INITIALIZE "
				    "FC_FAILURE\n");
				rval = FC_FAILURE;
			}
		} else {
			EL(ha, "failed, FC_PORT_INITIALIZE FC_FAILURE-2, "
			    "clen=%lxh\n", cmd->pm_cmd_len);

			rval = FC_FAILURE;
		}
		break;
	case FC_PORT_RLS:
		if (cmd->pm_data_len < sizeof (fc_rls_acc_t)) {
			EL(ha, "failed, buffer size passed: %lxh, "
			    "req: %lxh\n", cmd->pm_data_len,
			    (sizeof (fc_rls_acc_t)));
			rval = FC_FAILURE;
		} else if (LOOP_NOT_READY(pha)) {
			EL(ha, "loop NOT ready\n");
			bzero(cmd->pm_data_buf, cmd->pm_data_len);
		} else if (ql_get_link_status(ha, ha->loop_id,
		    cmd->pm_data_len, cmd->pm_data_buf, 0) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_RLS FC_FAILURE\n");
			rval = FC_FAILURE;
#ifdef _BIG_ENDIAN
		} else {
			fc_rls_acc_t		*rls;

			rls = (fc_rls_acc_t *)cmd->pm_data_buf;
			LITTLE_ENDIAN_32(&rls->rls_link_fail);
			LITTLE_ENDIAN_32(&rls->rls_sync_loss);
			LITTLE_ENDIAN_32(&rls->rls_sig_loss);
			LITTLE_ENDIAN_32(&rls->rls_invalid_crc);
#endif /* _BIG_ENDIAN */
		}
		break;
	case FC_PORT_GET_NODE_ID:
		if (ql_get_rnid_params(ha, cmd->pm_data_len,
		    cmd->pm_data_buf) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_GET_NODE_ID FC_FAILURE\n");
			rval = FC_FAILURE;
		}
		break;
	case FC_PORT_SET_NODE_ID:
		if (ql_set_rnid_params(ha, cmd->pm_data_len,
		    cmd->pm_data_buf) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_SET_NODE_ID FC_FAILURE\n");
			rval = FC_FAILURE;
		}
		break;
	case FC_PORT_DOWNLOAD_FCODE:
		PORTMANAGE_LOCK(ha);
		if ((CFG_IST(ha, CFG_CTRL_24258081)) == 0) {
			rval = ql_load_flash(ha, (uint8_t *)cmd->pm_data_buf,
			    (uint32_t)cmd->pm_data_len);
		} else {
			if (cmd->pm_data_buf[0] == 4 &&
			    cmd->pm_data_buf[8] == 0 &&
			    cmd->pm_data_buf[9] == 0x10 &&
			    cmd->pm_data_buf[10] == 0 &&
			    cmd->pm_data_buf[11] == 0) {
				rval = ql_24xx_load_flash(ha,
				    (uint8_t *)cmd->pm_data_buf,
				    (uint32_t)cmd->pm_data_len,
				    ha->flash_fw_addr << 2);
			} else {
				rval = ql_24xx_load_flash(ha,
				    (uint8_t *)cmd->pm_data_buf,
				    (uint32_t)cmd->pm_data_len, 0);
			}
		}

		if (rval != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_DOWNLOAD_FCODE FC_FAILURE\n");
			rval = FC_FAILURE;
		} else {
			rval = FC_SUCCESS;
		}
		ql_reset_chip(ha);
		set_flags |= ISP_ABORT_NEEDED;
		PORTMANAGE_UNLOCK(ha);
		break;
	default:
		EL(ha, "unknown=%xh, FC_BADCMD\n", cmd->pm_cmd_code);
		rval = FC_BADCMD;
		break;
	}

	/* Wait for suspension to end. */
	ql_awaken_task_daemon(ha, NULL, set_flags, DRIVER_STALL);
	timer = 0;

	while (timer++ < 3000 &&
	    ha->task_daemon_flags & (QL_LOOP_TRANSITION | DRIVER_STALL)) {
		ql_delay(ha, 10000);
	}

	ql_restart_queues(ha);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

static opaque_t
ql_get_device(opaque_t fca_handle, fc_portid_t d_id)
{
	port_id_t		id;
	ql_adapter_state_t	*ha;
	ql_tgt_t		*tq;

	id.r.rsvd_1 = 0;
	id.b24 = d_id.port_id;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (NULL);
	}
	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance, id.b24);

	tq = ql_d_id_to_queue(ha, id);

	if (tq == NULL) {
		EL(ha, "failed, tq=NULL\n");
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (tq);
}

/* ************************************************************************ */
/*			FCA Driver Local Support Functions.		    */
/* ************************************************************************ */

/*
 * ql_cmd_setup
 *	Verifies proper command.
 *
 * Input:
 *	fca_handle = handle setup by ql_bind_port().
 *	pkt = pointer to fc_packet.
 *	rval = pointer for return value.
 *
 * Returns:
 *	Adapter state pointer, NULL = failure.
 *
 * Context:
 *	Kernel context.
 */
static ql_adapter_state_t *
ql_cmd_setup(opaque_t fca_handle, fc_packet_t *pkt, int *rval)
{
	ql_adapter_state_t	*ha, *pha;
	ql_srb_t		*sp = (ql_srb_t *)pkt->pkt_fca_private;
	ql_tgt_t		*tq;
	port_id_t		d_id;

	pkt->pkt_resp_resid = 0;
	pkt->pkt_data_resid = 0;

	/* check that the handle is assigned by this FCA */
	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		*rval = FC_UNBOUND;
		QL_PRINT_2(CE_CONT, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (NULL);
	}
	pha = ha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ddi_in_panic() || pkt->pkt_tran_flags & FC_TRAN_DUMPING) {
		return (ha);
	}

	if (!(pha->flags & ONLINE)) {
		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_HW_ERROR;
		*rval = FC_TRANSPORT_ERROR;
		EL(ha, "failed, not online hf=%xh\n", pha->flags);
		return (NULL);
	}

	/* Exit on loop down. */
	if (CFG_IST(ha, CFG_ENABLE_LINK_DOWN_REPORTING) &&
	    pha->task_daemon_flags & LOOP_DOWN &&
	    pha->loop_down_timer <= pha->loop_down_abort_time) {
		pkt->pkt_state = FC_PKT_PORT_OFFLINE;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		*rval = FC_OFFLINE;
		EL(ha, "failed, loop down tdf=%xh\n", pha->task_daemon_flags);
		return (NULL);
	}

	if (pkt->pkt_cmd_fhdr.r_ctl == R_CTL_COMMAND &&
	    pkt->pkt_cmd_fhdr.type == FC_TYPE_SCSI_FCP) {
		tq = (ql_tgt_t *)pkt->pkt_fca_device;
		if ((tq == NULL) || (!VALID_DEVICE_ID(ha, tq->loop_id))) {
			d_id.r.rsvd_1 = 0;
			d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
			tq = ql_d_id_to_queue(ha, d_id);

			pkt->pkt_fca_device = (opaque_t)tq;
		}

		if (tq != NULL) {
			DEVICE_QUEUE_LOCK(tq);
			if (tq->flags & (TQF_RSCN_RCVD |
			    TQF_NEED_AUTHENTICATION)) {
				*rval = FC_DEVICE_BUSY;
				DEVICE_QUEUE_UNLOCK(tq);
				EL(ha, "failed, busy qf=%xh, d_id=%xh\n",
				    tq->flags, tq->d_id.b24);
				return (NULL);
			}
			DEVICE_QUEUE_UNLOCK(tq);
		}
	}

	/*
	 * Check DMA pointers.
	 */
	*rval = DDI_SUCCESS;
	if (pkt->pkt_cmd_acc != NULL && pkt->pkt_cmdlen) {
		QL_CLEAR_DMA_HANDLE(pkt->pkt_cmd_dma);
		*rval = ddi_check_dma_handle(pkt->pkt_cmd_dma);
		if (*rval == DDI_SUCCESS) {
			*rval = ddi_check_acc_handle(pkt->pkt_cmd_acc);
		}
	}

	if (pkt->pkt_resp_acc != NULL && *rval == DDI_SUCCESS &&
	    pkt->pkt_rsplen != 0) {
		QL_CLEAR_DMA_HANDLE(pkt->pkt_resp_dma);
		*rval = ddi_check_dma_handle(pkt->pkt_resp_dma);
		if (*rval == DDI_SUCCESS) {
			*rval = ddi_check_acc_handle(pkt->pkt_resp_acc);
		}
	}

	/*
	 * Minimum branch conditional; Change it with care.
	 */
	if (((pkt->pkt_data_acc != NULL) & (*rval == DDI_SUCCESS) &
	    (pkt->pkt_datalen != 0)) != 0) {
		QL_CLEAR_DMA_HANDLE(pkt->pkt_data_dma);
		*rval = ddi_check_dma_handle(pkt->pkt_data_dma);
		if (*rval == DDI_SUCCESS) {
			*rval = ddi_check_acc_handle(pkt->pkt_data_acc);
		}
	}

	if (*rval != DDI_SUCCESS) {
		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_DMA_ERROR;

		/* Do command callback. */
		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
			ql_awaken_task_daemon(ha, sp, 0, 0);
		}
		*rval = FC_BADPACKET;
		EL(ha, "failed, bad DMA pointers\n");
		return (NULL);
	}

	if (sp->magic_number != QL_FCA_BRAND) {
		*rval = FC_BADPACKET;
		EL(ha, "failed, magic number=%xh\n", sp->magic_number);
		return (NULL);
	}
	*rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (ha);
}

/*
 * ql_els_plogi
 *	Issue a extended link service port login request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_plogi(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_tgt_t		*tq = NULL;
	port_id_t		d_id;
	la_els_logi_t		acc;
	class_svc_param_t	*class3_param;
	int			ret;
	int			rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    pkt->pkt_cmd_fhdr.d_id);

	TASK_DAEMON_LOCK(ha);
	if (!(ha->task_daemon_flags & STATE_ONLINE)) {
		TASK_DAEMON_UNLOCK(ha);
		QL_PRINT_3(CE_CONT, "(%d): offline done\n", ha->instance);
		return (FC_OFFLINE);
	}
	TASK_DAEMON_UNLOCK(ha);

	bzero(&acc, sizeof (acc));
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	ret = QL_SUCCESS;

	if (CFG_IST(ha, CFG_CTRL_2425) && ha->topology & QL_N_PORT) {
		/*
		 * In p2p topology it sends a PLOGI after determining
		 * it has the N_Port login initiative.
		 */
		ret = ql_p2p_plogi(ha, pkt);
	}
	if (ret == QL_CONSUMED) {
		return (ret);
	}

	switch (ret = ql_login_port(ha, d_id)) {
	case QL_SUCCESS:
		tq = ql_d_id_to_queue(ha, d_id);
		break;

	case QL_LOOP_ID_USED:
		if ((ret = ql_login_port(ha, d_id)) == QL_SUCCESS) {
			tq = ql_d_id_to_queue(ha, d_id);
		}
		break;

	default:
		break;
	}

	if (ret != QL_SUCCESS) {
		/*
		 * Invalidate this entry so as to seek a fresh loop ID
		 * in case firmware reassigns it to something else
		 */
		tq = ql_d_id_to_queue(ha, d_id);
		if (tq && (ret != QL_MEMORY_ALLOC_FAILED)) {
			tq->loop_id = PORT_NO_LOOP_ID;
		}
	} else if (tq) {
		(void) ql_get_port_database(ha, tq, PDF_ADISC);
	}

	if (tq != NULL && VALID_DEVICE_ID(ha, tq->loop_id) &&
	    (ret != QL_MEMORY_ALLOC_FAILED) && PD_PORT_LOGIN(tq)) {

		/* Build ACC. */
		acc.ls_code.ls_code = LA_ELS_ACC;
		acc.common_service.fcph_version = 0x2006;
		acc.common_service.cmn_features = 0x8800;
		acc.common_service.rx_bufsize = QL_MAX_FRAME_SIZE(ha);
		acc.common_service.conc_sequences = 0xff;
		acc.common_service.relative_offset = 0x03;
		acc.common_service.e_d_tov = 0x7d0;

		bcopy((void *)&tq->port_name[0],
		    (void *)&acc.nport_ww_name.raw_wwn[0], 8);
		bcopy((void *)&tq->node_name[0],
		    (void *)&acc.node_ww_name.raw_wwn[0], 8);

		class3_param = (class_svc_param_t *)&acc.class_3;
		class3_param->class_valid_svc_opt = 0x8000;
		class3_param->recipient_ctl = tq->class3_recipient_ctl;
		class3_param->rcv_data_size = tq->class3_rcv_data_size;
		class3_param->conc_sequences = tq->class3_conc_sequences;
		class3_param->open_sequences_per_exch =
		    tq->class3_open_sequences_per_exch;

		if ((ql_busy_plogi(ha, pkt, tq) == FC_TRAN_BUSY)) {
			acc.ls_code.ls_code = LA_ELS_RJT;
			pkt->pkt_state = FC_PKT_TRAN_BSY;
			pkt->pkt_reason = FC_REASON_XCHG_BSY;
			EL(ha, "LA_ELS_RJT, FC_REASON_XCHG_BSY\n");
			rval = FC_TRAN_BUSY;
		} else {
			DEVICE_QUEUE_LOCK(tq);
			tq->logout_sent = 0;
			tq->flags &= ~TQF_NEED_AUTHENTICATION;
			if (CFG_IST(ha, CFG_CTRL_242581)) {
				tq->flags |= TQF_IIDMA_NEEDED;
			}
			DEVICE_QUEUE_UNLOCK(tq);

			if (CFG_IST(ha, CFG_CTRL_242581)) {
				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |= TD_IIDMA_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
			}

			pkt->pkt_state = FC_PKT_SUCCESS;
		}
	} else {
		/* Build RJT. */
		acc.ls_code.ls_code = LA_ELS_RJT;

		switch (ret) {
		case QL_FUNCTION_TIMEOUT:
			pkt->pkt_state = FC_PKT_TIMEOUT;
			pkt->pkt_reason = FC_REASON_HW_ERROR;
			break;

		case QL_MEMORY_ALLOC_FAILED:
			pkt->pkt_state = FC_PKT_LOCAL_BSY;
			pkt->pkt_reason = FC_REASON_NOMEM;
			rval = FC_TRAN_BUSY;
			break;

		case QL_FABRIC_NOT_INITIALIZED:
			pkt->pkt_state = FC_PKT_FABRIC_BSY;
			pkt->pkt_reason = FC_REASON_NO_CONNECTION;
			rval = FC_TRAN_BUSY;
			break;

		default:
			pkt->pkt_state = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_NO_CONNECTION;
			break;
		}

		EL(ha, "Plogi unsuccess for %xh state %xh reason %xh "
		    "ret %xh rval %xh\n", d_id.b24, pkt->pkt_state,
		    pkt->pkt_reason, ret, rval);
	}

	if (tq != NULL) {
		DEVICE_QUEUE_LOCK(tq);
		tq->flags &= ~(TQF_PLOGI_PROGRS | TQF_QUEUE_SUSPENDED);
		if (rval == FC_TRAN_BUSY) {
			if (tq->d_id.b24 != BROADCAST_ADDR) {
				tq->flags |= TQF_NEED_AUTHENTICATION;
			}
		}
		DEVICE_QUEUE_UNLOCK(tq);
	}

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_p2p_plogi
 *	Start an extended link service port login request using
 *	an ELS Passthru iocb.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	QL_CONSUMMED - the iocb was queued for transport.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_p2p_plogi(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	uint16_t	id;
	ql_tgt_t	tmp;
	ql_tgt_t	*tq = &tmp;
	int		rval;
	port_id_t	d_id;
	ql_srb_t	*sp = (ql_srb_t *)pkt->pkt_fca_private;

	tq->d_id.b.al_pa = 0;
	tq->d_id.b.area = 0;
	tq->d_id.b.domain = 0;

	/*
	 * Verify that the port database hasn't moved beneath our feet by
	 * switching to the appropriate n_port_handle if necessary.  This is
	 * less unplesant than the error recovery if the wrong one is used.
	 */
	for (id = 0; id <= LAST_LOCAL_LOOP_ID; id++) {
		tq->loop_id = id;
		rval = ql_get_port_database(ha, tq, PDF_NONE);
		EL(ha, "rval=%xh\n", rval);
		/* check all the ones not logged in for possible use */
		if (rval == QL_NOT_LOGGED_IN) {
			if (tq->master_state == PD_STATE_PLOGI_PENDING) {
				ha->n_port->n_port_handle = tq->loop_id;
				EL(ha, "n_port_handle =%xh, master state=%x\n",
				    tq->loop_id, tq->master_state);
				break;
			}
			/*
			 * Use a 'port unavailable' entry only
			 * if we used it before.
			 */
			if (tq->master_state == PD_STATE_PORT_UNAVAILABLE) {
				/* if the port_id matches, reuse it */
				if (pkt->pkt_cmd_fhdr.d_id == tq->d_id.b24) {
					EL(ha, "n_port_handle =%xh,"
					    "master state=%xh\n",
					    tq->loop_id, tq->master_state);
					break;
				} else if (tq->loop_id ==
				    ha->n_port->n_port_handle) {
				    // avoid a lint error
					uint16_t *hndl;
					uint16_t val;

					hndl = &ha->n_port->n_port_handle;
					val = *hndl;
					val++;
					val++;
					*hndl = val;
				}
			EL(ha, "rval=%xh, id=%d, n_port_handle =%xh, "
			    "master state=%x\n", rval, id, tq->loop_id,
			    tq->master_state);
			}

		}
		if (rval == QL_SUCCESS) {
			if ((tq->flags & TQF_INITIATOR_DEVICE) == 0) {
				ha->n_port->n_port_handle = tq->loop_id;
				EL(ha, "n_port_handle =%xh, master state=%x\n",
				    tq->loop_id, tq->master_state);
				break;
			}
			EL(ha, "rval=%xh, id=%d, n_port_handle =%xh, "
			    "master state=%x\n", rval, id, tq->loop_id,
			    tq->master_state);
		}
	}
	(void) ddi_dma_sync(pkt->pkt_cmd_dma, 0, 0, DDI_DMA_SYNC_FORDEV);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	tq = ql_d_id_to_queue(ha, d_id);
	ql_timeout_insert(ha, tq, sp);
	ql_start_iocb(ha, sp);

	return (QL_CONSUMED);
}


/*
 * ql_els_flogi
 *	Issue a extended link service fabric login request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_flogi(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_tgt_t		*tq = NULL;
	port_id_t		d_id;
	la_els_logi_t		acc;
	class_svc_param_t	*class3_param;
	int			rval = FC_SUCCESS;
	int			accept = 0;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    pkt->pkt_cmd_fhdr.d_id);

	bzero(&acc, sizeof (acc));
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	if (CFG_IST(ha, CFG_CTRL_2425) && ha->topology & QL_N_PORT) {
		/*
		 * d_id of zero in a FLOGI accept response in a point to point
		 * topology triggers evaluation of N Port login initiative.
		 */
		pkt->pkt_resp_fhdr.d_id = 0;
		/*
		 * An N_Port already logged in with the firmware
		 * will have the only database entry.
		 */
		if (LOCAL_LOOP_ID(ha->n_port->n_port_handle)) {
			tq = ql_loop_id_to_queue(ha, ha->n_port->n_port_handle);
		}

		if (tq != NULL) {
			/*
			 * If the target port has initiative send
			 * up a PLOGI about the new device.
			 */
			if ((ql_wwn_cmp(ha, (la_wwn_t *)&tq->port_name[0],
			    (la_wwn_t *)(CFG_IST(ha, CFG_CTRL_2425) ?
			    &ha->init_ctrl_blk.cb24.port_name[0] :
			    &ha->init_ctrl_blk.cb.port_name[0])) == 1)) {
				ha->send_plogi_timer = 3;
			} else {
				ha->send_plogi_timer = 0;
			}
			pkt->pkt_resp_fhdr.s_id = tq->d_id.b24;
		} else {
			/*
			 * An N_Port not logged in with the firmware will not
			 * have a database entry.  We accept anyway and rely
			 * on a PLOGI from the upper layers to set the d_id
			 * and s_id.
			 */
			accept = 1;
		}
	} else {
		tq = ql_d_id_to_queue(ha, d_id);
	}
	if ((tq != NULL) || (accept != NULL)) {
		/* Build ACC. */
		pkt->pkt_state = FC_PKT_SUCCESS;
		class3_param = (class_svc_param_t *)&acc.class_3;

		acc.ls_code.ls_code = LA_ELS_ACC;
		acc.common_service.fcph_version = 0x2006;
		if (ha->topology & QL_N_PORT) {
			/* clear F_Port indicator */
			acc.common_service.cmn_features = 0x0800;
		} else {
			acc.common_service.cmn_features = 0x1b00;
		}
		CFG_IST(ha, CFG_CTRL_24258081) ?
		    (acc.common_service.rx_bufsize = CHAR_TO_SHORT(
		    ha->init_ctrl_blk.cb24.max_frame_length[0],
		    ha->init_ctrl_blk.cb24.max_frame_length[1])) :
		    (acc.common_service.rx_bufsize = CHAR_TO_SHORT(
		    ha->init_ctrl_blk.cb.max_frame_length[0],
		    ha->init_ctrl_blk.cb.max_frame_length[1]));
		acc.common_service.conc_sequences = 0xff;
		acc.common_service.relative_offset = 0x03;
		acc.common_service.e_d_tov = 0x7d0;
		if (accept) {
			/* Use the saved N_Port WWNN and WWPN */
			if (ha->n_port != NULL) {
				bcopy((void *)&ha->n_port->port_name[0],
				    (void *)&acc.nport_ww_name.raw_wwn[0], 8);
				bcopy((void *)&ha->n_port->node_name[0],
				    (void *)&acc.node_ww_name.raw_wwn[0], 8);
				/* mark service options invalid */
				class3_param->class_valid_svc_opt = 0x0800;
			} else {
				EL(ha, "ha->n_port is NULL\n");
				/* Build RJT. */
				acc.ls_code.ls_code = LA_ELS_RJT;

				pkt->pkt_state = FC_PKT_TRAN_ERROR;
				pkt->pkt_reason = FC_REASON_NO_CONNECTION;
			}
		} else {
			bcopy((void *)&tq->port_name[0],
			    (void *)&acc.nport_ww_name.raw_wwn[0], 8);
			bcopy((void *)&tq->node_name[0],
			    (void *)&acc.node_ww_name.raw_wwn[0], 8);

			class3_param = (class_svc_param_t *)&acc.class_3;
			class3_param->class_valid_svc_opt = 0x8800;
			class3_param->recipient_ctl = tq->class3_recipient_ctl;
			class3_param->rcv_data_size = tq->class3_rcv_data_size;
			class3_param->conc_sequences =
			    tq->class3_conc_sequences;
			class3_param->open_sequences_per_exch =
			    tq->class3_open_sequences_per_exch;
		}
	} else {
		/* Build RJT. */
		acc.ls_code.ls_code = LA_ELS_RJT;

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_logo
 *	Issue a extended link service logout request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_logo(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	port_id_t	d_id;
	ql_tgt_t	*tq;
	la_els_logo_t	acc;
	int		rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    pkt->pkt_cmd_fhdr.d_id);

	bzero(&acc, sizeof (acc));
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	tq = ql_d_id_to_queue(ha, d_id);
	if (tq) {
		DEVICE_QUEUE_LOCK(tq);
		if (tq->d_id.b24 == BROADCAST_ADDR) {
			DEVICE_QUEUE_UNLOCK(tq);
			return (FC_SUCCESS);
		}

		tq->flags |= TQF_NEED_AUTHENTICATION;

		do {
			DEVICE_QUEUE_UNLOCK(tq);
			(void) ql_abort_device(ha, tq, 1);

			/*
			 * Wait for commands to drain in F/W (doesn't
			 * take more than a few milliseconds)
			 */
			ql_delay(ha, 10000);

			DEVICE_QUEUE_LOCK(tq);
		} while (tq->outcnt);

		DEVICE_QUEUE_UNLOCK(tq);
	}

	if (ql_logout_port(ha, d_id) == QL_SUCCESS) {
		/* Build ACC. */
		acc.ls_code.ls_code = LA_ELS_ACC;

		pkt->pkt_state = FC_PKT_SUCCESS;
	} else {
		/* Build RJT. */
		acc.ls_code.ls_code = LA_ELS_RJT;

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_prli
 *	Issue a extended link service process login request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_prli(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_tgt_t		*tq;
	port_id_t		d_id;
	la_els_prli_t		acc;
	prli_svc_param_t	*param;
	ql_srb_t		*sp = (ql_srb_t *)pkt->pkt_fca_private;
	int			rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    pkt->pkt_cmd_fhdr.d_id);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	tq = ql_d_id_to_queue(ha, d_id);
	if (tq != NULL) {
		(void) ql_get_port_database(ha, tq, PDF_NONE);

		if ((ha->topology & QL_N_PORT) &&
		    (tq->master_state == PD_STATE_PLOGI_COMPLETED)) {
			ql_timeout_insert(ha, tq, sp);
			ql_start_iocb(ha, sp);
			rval = QL_CONSUMED;
		} else {
			/* Build ACC. */
			bzero(&acc, sizeof (acc));
			acc.ls_code = LA_ELS_ACC;
			acc.page_length = 0x10;
			acc.payload_length = tq->prli_payload_length;

			param = (prli_svc_param_t *)&acc.service_params[0];
			param->type = 0x08;
			param->rsvd = 0x00;
			param->process_assoc_flags = tq->prli_svc_param_word_0;
			param->process_flags = tq->prli_svc_param_word_3;

			ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
			    (uint8_t *)pkt->pkt_resp, sizeof (acc),
			    DDI_DEV_AUTOINCR);

			pkt->pkt_state = FC_PKT_SUCCESS;
		}
	} else {
		la_els_rjt_t rjt;

		/* Build RJT. */
		bzero(&rjt, sizeof (rjt));
		rjt.ls_code.ls_code = LA_ELS_RJT;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
		    (uint8_t *)pkt->pkt_resp, sizeof (rjt), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	if ((rval != FC_SUCCESS) && (rval != QL_CONSUMED)) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_prlo
 *	Issue a extended link service process logout request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_els_prlo(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	la_els_prli_t	acc;
	int		rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    pkt->pkt_cmd_fhdr.d_id);

	/* Build ACC. */
	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_cmd, sizeof (acc), DDI_DEV_AUTOINCR);

	acc.ls_code = LA_ELS_ACC;
	acc.service_params[2] = 1;

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	pkt->pkt_state = FC_PKT_SUCCESS;

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_adisc
 *	Issue a extended link service address discovery request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_adisc(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_dev_id_list_t	*list;
	uint32_t		list_size;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	port_id_t		d_id;
	la_els_adisc_t		acc;
	uint16_t		index, loop_id;
	ql_mbx_data_t		mr;
	int			rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	bzero(&acc, sizeof (acc));
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	/*
	 * MBC_GET_PORT_DATABASE causes ADISC to go out to
	 * the device from the firmware
	 */
	index = ql_alpa_to_index[d_id.b.al_pa];
	tq = NULL;
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			break;
		} else {
			tq = NULL;
		}
	}

	if ((tq != NULL) && (!VALID_DEVICE_ID(ha, tq->loop_id))) {
		list_size = sizeof (ql_dev_id_list_t) * DEVICE_LIST_ENTRIES;
		list = (ql_dev_id_list_t *)kmem_zalloc(list_size, KM_SLEEP);

		if (list != NULL &&
		    ql_get_id_list(ha, (caddr_t)list, list_size, &mr) ==
		    QL_SUCCESS) {

			for (index = 0; index < mr.mb[1]; index++) {
				ql_dev_list(ha, list, index, &d_id, &loop_id);

				if (tq->d_id.b24 == d_id.b24) {
					tq->loop_id = loop_id;
					break;
				}
			}
		} else {
			cmn_err(CE_WARN, "!%s(%d) didn't get list for %xh",
			    QL_NAME, ha->instance, d_id.b24);
			tq = NULL;
		}
		if ((tq != NULL) && (!VALID_DEVICE_ID(ha, tq->loop_id))) {
			cmn_err(CE_WARN, "!%s(%d) no loop_id for adisc %xh",
			    QL_NAME, ha->instance, tq->d_id.b24);
			tq = NULL;
		}

		if (list != NULL) {
			kmem_free(list, list_size);
		}
	}

	if ((tq != NULL) && (VALID_DEVICE_ID(ha, tq->loop_id)) &&
	    ql_get_port_database(ha, tq, PDF_ADISC) == QL_SUCCESS) {

		/* Build ACC. */

		DEVICE_QUEUE_LOCK(tq);
		tq->flags &= ~TQF_NEED_AUTHENTICATION;
		if (tq->prli_svc_param_word_3 & PRLI_W3_RETRY) {
			for (link = tq->lun_queues.first; link != NULL;
			    link = link->next) {
				lq = link->base_address;

				if (lq->cmd.first != NULL) {
					ql_next(ha, lq);
					DEVICE_QUEUE_LOCK(tq);
				}
			}
		}
		DEVICE_QUEUE_UNLOCK(tq);

		acc.ls_code.ls_code = LA_ELS_ACC;
		acc.hard_addr.hard_addr = tq->hard_addr.b24;

		bcopy((void *)&tq->port_name[0],
		    (void *)&acc.port_wwn.raw_wwn[0], 8);
		bcopy((void *)&tq->node_name[0],
		    (void *)&acc.node_wwn.raw_wwn[0], 8);

		acc.nport_id.port_id = tq->d_id.b24;

		pkt->pkt_state = FC_PKT_SUCCESS;
	} else {
		/* Build RJT. */
		acc.ls_code.ls_code = LA_ELS_RJT;

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_linit
 *	Issue a extended link service loop initialize request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_linit(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;
	conv_num_t		n;
	port_id_t		d_id;
	int			rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	if (ha->topology & QL_SNS_CONNECTION) {
		fc_linit_req_t els;
		lfa_cmd_t lfa;

		ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
		    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

		/* Setup LFA mailbox command data. */
		bzero((void *)&lfa, sizeof (lfa_cmd_t));

		lfa.resp_buffer_length[0] = 4;

		cp = pkt->pkt_resp_cookie;
		if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			n.size64 = (uint64_t)cp->dmac_laddress;
			LITTLE_ENDIAN_64(&n.size64);
		} else {
			n.size32[0] = LSD(cp->dmac_laddress);
			LITTLE_ENDIAN_32(&n.size32[0]);
			n.size32[1] = MSD(cp->dmac_laddress);
			LITTLE_ENDIAN_32(&n.size32[1]);
		}

		/* Set buffer address. */
		for (cnt = 0; cnt < 8; cnt++) {
			lfa.resp_buffer_address[cnt] = n.size8[cnt];
		}

		lfa.subcommand_length[0] = 4;
		n.size32[0] = d_id.b24;
		LITTLE_ENDIAN_32(&n.size32[0]);
		lfa.addr[0] = n.size8[0];
		lfa.addr[1] = n.size8[1];
		lfa.addr[2] = n.size8[2];
		lfa.subcommand[1] = 0x70;
		lfa.payload[2] = els.func;
		lfa.payload[4] = els.lip_b3;
		lfa.payload[5] = els.lip_b4;

		if (ql_send_lfa(ha, &lfa) != QL_SUCCESS) {
			pkt->pkt_state = FC_PKT_TRAN_ERROR;
		} else {
			pkt->pkt_state = FC_PKT_SUCCESS;
		}
	} else {
		fc_linit_resp_t rjt;

		/* Build RJT. */
		bzero(&rjt, sizeof (rjt));
		rjt.ls_code.ls_code = LA_ELS_RJT;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
		    (uint8_t *)pkt->pkt_resp, sizeof (rjt), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_lpc
 *	Issue a extended link service loop control request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_lpc(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;
	conv_num_t		n;
	port_id_t		d_id;
	int			rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	if (ha->topology & QL_SNS_CONNECTION) {
		ql_lpc_t els;
		lfa_cmd_t lfa;

		ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
		    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

		/* Setup LFA mailbox command data. */
		bzero((void *)&lfa, sizeof (lfa_cmd_t));

		lfa.resp_buffer_length[0] = 4;

		cp = pkt->pkt_resp_cookie;
		if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			n.size64 = (uint64_t)(cp->dmac_laddress);
			LITTLE_ENDIAN_64(&n.size64);
		} else {
			n.size32[0] = cp->dmac_address;
			LITTLE_ENDIAN_32(&n.size32[0]);
			n.size32[1] = 0;
		}

		/* Set buffer address. */
		for (cnt = 0; cnt < 8; cnt++) {
			lfa.resp_buffer_address[cnt] = n.size8[cnt];
		}

		lfa.subcommand_length[0] = 20;
		n.size32[0] = d_id.b24;
		LITTLE_ENDIAN_32(&n.size32[0]);
		lfa.addr[0] = n.size8[0];
		lfa.addr[1] = n.size8[1];
		lfa.addr[2] = n.size8[2];
		lfa.subcommand[1] = 0x71;
		lfa.payload[4] = els.port_control;
		bcopy((void *)&els.lpb[0], (void *)&lfa.payload[6], 32);

		if (ql_send_lfa(ha, &lfa) != QL_SUCCESS) {
			pkt->pkt_state = FC_PKT_TRAN_ERROR;
		} else {
			pkt->pkt_state = FC_PKT_SUCCESS;
		}
	} else {
		ql_lpc_resp_t rjt;

		/* Build RJT. */
		bzero(&rjt, sizeof (rjt));
		rjt.ls_code.ls_code = LA_ELS_RJT;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
		    (uint8_t *)pkt->pkt_resp, sizeof (rjt), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_lsts
 *	Issue a extended link service loop status request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_lsts(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;
	conv_num_t		n;
	port_id_t		d_id;
	int			rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	if (ha->topology & QL_SNS_CONNECTION) {
		fc_lsts_req_t els;
		lfa_cmd_t lfa;

		ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
		    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

		/* Setup LFA mailbox command data. */
		bzero((void *)&lfa, sizeof (lfa_cmd_t));

		lfa.resp_buffer_length[0] = 84;

		cp = pkt->pkt_resp_cookie;
		if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			n.size64 = cp->dmac_laddress;
			LITTLE_ENDIAN_64(&n.size64);
		} else {
			n.size32[0] = cp->dmac_address;
			LITTLE_ENDIAN_32(&n.size32[0]);
			n.size32[1] = 0;
		}

		/* Set buffer address. */
		for (cnt = 0; cnt < 8; cnt++) {
			lfa.resp_buffer_address[cnt] = n.size8[cnt];
		}

		lfa.subcommand_length[0] = 2;
		n.size32[0] = d_id.b24;
		LITTLE_ENDIAN_32(&n.size32[0]);
		lfa.addr[0] = n.size8[0];
		lfa.addr[1] = n.size8[1];
		lfa.addr[2] = n.size8[2];
		lfa.subcommand[1] = 0x72;

		if (ql_send_lfa(ha, &lfa) != QL_SUCCESS) {
			pkt->pkt_state = FC_PKT_TRAN_ERROR;
		} else {
			pkt->pkt_state = FC_PKT_SUCCESS;
		}
	} else {
		fc_lsts_resp_t rjt;

		/* Build RJT. */
		bzero(&rjt, sizeof (rjt));
		rjt.lsts_ls_code.ls_code = LA_ELS_RJT;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
		    (uint8_t *)pkt->pkt_resp, sizeof (rjt), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_scr
 *	Issue a extended link service state change registration request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_scr(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	fc_scr_resp_t	acc;
	int		rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	bzero(&acc, sizeof (acc));
	if (ha->topology & QL_SNS_CONNECTION) {
		fc_scr_req_t els;

		ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
		    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

		if (ql_send_change_request(ha, els.scr_func) ==
		    QL_SUCCESS) {
			/* Build ACC. */
			acc.scr_acc = LA_ELS_ACC;

			pkt->pkt_state = FC_PKT_SUCCESS;
		} else {
			/* Build RJT. */
			acc.scr_acc = LA_ELS_RJT;

			pkt->pkt_state = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_HW_ERROR;
			EL(ha, "LA_ELS_RJT, FC_REASON_HW_ERROR\n");
		}
	} else {
		/* Build RJT. */
		acc.scr_acc = LA_ELS_RJT;

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_rscn
 *	Issue a extended link service register state
 *	change notification request.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_rscn(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_rscn_resp_t	acc;
	int		rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	bzero(&acc, sizeof (acc));
	if (ha->topology & QL_SNS_CONNECTION) {
		/* Build ACC. */
		acc.scr_acc = LA_ELS_ACC;

		pkt->pkt_state = FC_PKT_SUCCESS;
	} else {
		/* Build RJT. */
		acc.scr_acc = LA_ELS_RJT;

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
	}

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_farp_req
 *	Issue FC Address Resolution Protocol (FARP)
 *	extended link service request.
 *
 *	Note: not supported.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_els_farp_req(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_acc_rjt_t	acc;
	int		rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	bzero(&acc, sizeof (acc));

	/* Build ACC. */
	acc.ls_code.ls_code = LA_ELS_ACC;

	pkt->pkt_state = FC_PKT_SUCCESS;

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_els_farp_reply
 *	Issue FC Address Resolution Protocol (FARP)
 *	extended link service reply.
 *
 *	Note: not supported.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_els_farp_reply(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_acc_rjt_t	acc;
	int		rval = FC_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	bzero(&acc, sizeof (acc));

	/* Build ACC. */
	acc.ls_code.ls_code = LA_ELS_ACC;

	pkt->pkt_state = FC_PKT_SUCCESS;

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

static int
ql_els_rnid(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	uchar_t			*rnid_acc;
	port_id_t		d_id;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	uint16_t		index;
	la_els_rnid_acc_t	acc;
	la_els_rnid_t		*req;
	size_t			req_len;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	req_len =  FCIO_RNID_MAX_DATA_LEN + sizeof (fc_rnid_hdr_t);
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	index = ql_alpa_to_index[d_id.b.al_pa];

	tq = NULL;
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			break;
		} else {
			tq = NULL;
		}
	}

	/* Allocate memory for rnid status block */
	rnid_acc = kmem_zalloc(req_len, KM_SLEEP);

	bzero(&acc, sizeof (acc));

	req = (la_els_rnid_t *)pkt->pkt_cmd;
	if ((tq == NULL) || (!VALID_DEVICE_ID(ha, tq->loop_id)) ||
	    (ql_send_rnid_els(ha, tq->loop_id, req->data_format, req_len,
	    (caddr_t)rnid_acc) != QL_SUCCESS)) {

		kmem_free(rnid_acc, req_len);
		acc.ls_code.ls_code = LA_ELS_RJT;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
		    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");

		return (FC_FAILURE);
	}

	acc.ls_code.ls_code = LA_ELS_ACC;
	bcopy(rnid_acc, &acc.hdr, req_len);
	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	kmem_free(rnid_acc, req_len);
	pkt->pkt_state = FC_PKT_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

static int
ql_els_rls(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	fc_rls_acc_t		*rls_acc;
	port_id_t		d_id;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	uint16_t		index;
	la_els_rls_acc_t	acc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	index = ql_alpa_to_index[d_id.b.al_pa];

	tq = NULL;
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			break;
		} else {
			tq = NULL;
		}
	}

	/* Allocate memory for link error status block */
	rls_acc = kmem_zalloc(sizeof (*rls_acc), KM_SLEEP);

	bzero(&acc, sizeof (la_els_rls_acc_t));

	if ((tq == NULL) || (!VALID_DEVICE_ID(ha, tq->loop_id)) ||
	    (ql_get_link_status(ha, tq->loop_id, sizeof (*rls_acc),
	    (caddr_t)rls_acc, 0) != QL_SUCCESS)) {

		kmem_free(rls_acc, sizeof (*rls_acc));
		acc.ls_code.ls_code = LA_ELS_RJT;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
		    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;
		EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");

		return (FC_FAILURE);
	}

	LITTLE_ENDIAN_32(&rls_acc->rls_link_fail);
	LITTLE_ENDIAN_32(&rls_acc->rls_sync_loss);
	LITTLE_ENDIAN_32(&rls_acc->rls_sig_loss);
	LITTLE_ENDIAN_32(&rls_acc->rls_invalid_word);
	LITTLE_ENDIAN_32(&rls_acc->rls_invalid_crc);

	acc.ls_code.ls_code = LA_ELS_ACC;
	acc.rls_link_params.rls_link_fail = rls_acc->rls_link_fail;
	acc.rls_link_params.rls_sync_loss = rls_acc->rls_sync_loss;
	acc.rls_link_params.rls_sig_loss  = rls_acc->rls_sig_loss;
	acc.rls_link_params.rls_invalid_word = rls_acc->rls_invalid_word;
	acc.rls_link_params.rls_invalid_crc = rls_acc->rls_invalid_crc;
	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	kmem_free(rls_acc, sizeof (*rls_acc));
	pkt->pkt_state = FC_PKT_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

static int
ql_busy_plogi(ql_adapter_state_t *ha, fc_packet_t *pkt, ql_tgt_t *tq)
{
	port_id_t	d_id;
	ql_srb_t	*sp;
	fc_unsol_buf_t  *ubp;
	ql_link_t	*link, *next_link;
	int		rval = FC_SUCCESS;
	int		cnt = 5;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/*
	 * we need to ensure that q->outcnt == 0, otherwise
	 * any cmd completed with PKT_PORT_OFFLINE after PLOGI
	 * will confuse ulps.
	 */

	DEVICE_QUEUE_LOCK(tq);
	do {
		/*
		 * wait for the cmds to get drained. If they
		 * don't get drained then the transport will
		 * retry PLOGI after few secs.
		 */
		if (tq->outcnt != 0) {
			rval = FC_TRAN_BUSY;
			DEVICE_QUEUE_UNLOCK(tq);
			ql_delay(ha, 10000);
			DEVICE_QUEUE_LOCK(tq);
			cnt--;
			if (!cnt) {
				cmn_err(CE_NOTE, "!%s(%d) Plogi busy"
				    " for %xh outcount %xh", QL_NAME,
				    ha->instance, tq->d_id.b24, tq->outcnt);
			}
		} else {
			rval = FC_SUCCESS;
			break;
		}
	} while (cnt > 0);
	DEVICE_QUEUE_UNLOCK(tq);

	/*
	 * return, if busy or if the plogi was asynchronous.
	 */
	if ((rval != FC_SUCCESS) ||
	    (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) &&
	    pkt->pkt_comp)) {
		QL_PRINT_3(CE_CONT, "(%d): done, busy or async\n",
		    ha->instance);
		return (rval);
	}

	/*
	 * Let us give daemon sufficient time and hopefully
	 * when transport retries PLOGI, it would have flushed
	 * callback queue.
	 */
	TASK_DAEMON_LOCK(ha);
	for (link = ha->callback_queue.first; link != NULL;
	    link = next_link) {
		next_link = link->next;
		sp = link->base_address;
		if (sp->flags & SRB_UB_CALLBACK) {
			ubp = ha->ub_array[sp->handle];
			d_id.b24 = ubp->ub_frame.s_id;
		} else {
			d_id.b24 = sp->pkt->pkt_cmd_fhdr.d_id;
		}
		if (tq->d_id.b24 == d_id.b24) {
			cmn_err(CE_NOTE, "!%s(%d) Plogi busy for %xh", QL_NAME,
			    ha->instance, tq->d_id.b24);
			rval = FC_TRAN_BUSY;
			break;
		}
	}
	TASK_DAEMON_UNLOCK(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_login_port
 *	Logs in a device if not already logged in.
 *
 * Input:
 *	ha = adapter state pointer.
 *	d_id = 24 bit port ID.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Returns:
 *	QL local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_login_port(ql_adapter_state_t *ha, port_id_t d_id)
{
	ql_adapter_state_t	*vha;
	ql_link_t		*link;
	uint16_t		index;
	ql_tgt_t		*tq, *tq2;
	uint16_t		loop_id, first_loop_id, last_loop_id;
	int			rval = QL_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    d_id.b24);

	/* Get head queue index. */
	index = ql_alpa_to_index[d_id.b.al_pa];

	/* Check for device already has a queue. */
	tq = NULL;
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			loop_id = tq->loop_id;
			break;
		} else {
			tq = NULL;
		}
	}

	/* Let's stop issuing any IO and unsolicited logo */
	if ((tq != NULL) && (!(ddi_in_panic()))) {
		DEVICE_QUEUE_LOCK(tq);
		tq->flags |= (TQF_QUEUE_SUSPENDED | TQF_PLOGI_PROGRS);
		tq->flags &= ~TQF_RSCN_RCVD;
		DEVICE_QUEUE_UNLOCK(tq);
	}
	if ((tq != NULL) && (tq->loop_id & PORT_LOST_ID) &&
	    !(tq->flags & TQF_FABRIC_DEVICE)) {
		loop_id = (uint16_t)(tq->loop_id & ~PORT_LOST_ID);
	}

	/* Special case for Nameserver */
	if (d_id.b24 == 0xFFFFFC) {
		loop_id = (uint16_t)(CFG_IST(ha, CFG_CTRL_24258081) ?
		    SNS_24XX_HDL : SIMPLE_NAME_SERVER_LOOP_ID);
		if (tq == NULL) {
			ADAPTER_STATE_LOCK(ha);
			tq = ql_dev_init(ha, d_id, loop_id);
			ADAPTER_STATE_UNLOCK(ha);
			if (tq == NULL) {
				EL(ha, "failed=%xh, d_id=%xh\n",
				    QL_FUNCTION_FAILED, d_id.b24);
				return (QL_FUNCTION_FAILED);
			}
		}
		if (!(CFG_IST(ha, CFG_CTRL_8021))) {
			rval = ql_login_fabric_port(ha, tq, loop_id);
			if (rval == QL_SUCCESS) {
				tq->loop_id = loop_id;
				tq->flags |= TQF_FABRIC_DEVICE;
				(void) ql_get_port_database(ha, tq, PDF_NONE);
			}
		} else {
			ha->topology = (uint8_t)
			    (ha->topology | QL_SNS_CONNECTION);
		}
	/* Check for device already logged in. */
	} else if (tq != NULL && VALID_DEVICE_ID(ha, loop_id)) {
		if (tq->flags & TQF_FABRIC_DEVICE) {
			rval = ql_login_fabric_port(ha, tq, loop_id);
			if (rval == QL_PORT_ID_USED) {
				rval = QL_SUCCESS;
			}
		} else if (LOCAL_LOOP_ID(loop_id)) {
			rval = ql_login_lport(ha, tq, loop_id, (uint16_t)
			    (tq->flags & TQF_INITIATOR_DEVICE ?
			    LLF_NONE : LLF_PLOGI));
			if (rval == QL_SUCCESS) {
				DEVICE_QUEUE_LOCK(tq);
				tq->loop_id = loop_id;
				DEVICE_QUEUE_UNLOCK(tq);
			}
		}
	} else if (ha->topology & QL_SNS_CONNECTION) {
		/* Locate unused loop ID. */
		if (CFG_IST(ha, CFG_CTRL_24258081)) {
			first_loop_id = 0;
			last_loop_id = LAST_N_PORT_HDL;
		} else if (ha->topology & QL_F_PORT) {
			first_loop_id = 0;
			last_loop_id = SNS_LAST_LOOP_ID;
		} else {
			first_loop_id = SNS_FIRST_LOOP_ID;
			last_loop_id = SNS_LAST_LOOP_ID;
		}

		/* Acquire adapter state lock. */
		ADAPTER_STATE_LOCK(ha);

		tq = ql_dev_init(ha, d_id, PORT_NO_LOOP_ID);
		if (tq == NULL) {
			EL(ha, "failed=%xh, d_id=%xh\n", QL_FUNCTION_FAILED,
			    d_id.b24);

			ADAPTER_STATE_UNLOCK(ha);

			return (QL_FUNCTION_FAILED);
		}

		rval = QL_FUNCTION_FAILED;
		loop_id = ha->pha->free_loop_id++;
		for (index = (uint16_t)(last_loop_id - first_loop_id); index;
		    index--) {
			if (loop_id < first_loop_id ||
			    loop_id > last_loop_id) {
				loop_id = first_loop_id;
				ha->pha->free_loop_id = (uint16_t)
				    (loop_id + 1);
			}

			/* Bypass if loop ID used. */
			for (vha = ha->pha; vha != NULL; vha = vha->vp_next) {
				tq2 = ql_loop_id_to_queue(vha, loop_id);
				if (tq2 != NULL && tq2 != tq) {
					break;
				}
			}
			if (vha != NULL || RESERVED_LOOP_ID(ha, loop_id) ||
			    loop_id == ha->loop_id) {
				loop_id = ha->pha->free_loop_id++;
				continue;
			}

			ADAPTER_STATE_UNLOCK(ha);
			rval = ql_login_fabric_port(ha, tq, loop_id);

			/*
			 * If PORT_ID_USED is returned
			 * the login_fabric_port() updates
			 * with the correct loop ID
			 */
			switch (rval) {
			case QL_PORT_ID_USED:
				/*
				 * use f/w handle and try to
				 * login again.
				 */
				ADAPTER_STATE_LOCK(ha);
				ha->pha->free_loop_id--;
				ADAPTER_STATE_UNLOCK(ha);
				loop_id = tq->loop_id;
				break;

			case QL_SUCCESS:
				tq->flags |= TQF_FABRIC_DEVICE;
				(void) ql_get_port_database(ha,
				    tq, PDF_NONE);
				index = 1;
				break;

			case QL_LOOP_ID_USED:
				tq->loop_id = PORT_NO_LOOP_ID;
				loop_id = ha->pha->free_loop_id++;
				break;

			case QL_ALL_IDS_IN_USE:
				tq->loop_id = PORT_NO_LOOP_ID;
				index = 1;
				break;

			default:
				tq->loop_id = PORT_NO_LOOP_ID;
				index = 1;
				break;
			}

			ADAPTER_STATE_LOCK(ha);
		}

		ADAPTER_STATE_UNLOCK(ha);
	} else {
		rval = QL_FUNCTION_FAILED;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, d_id.b24);
	} else {
		EL(ha, "d_id=%xh, loop_id=%xh, "
		    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02xh\n", tq->d_id.b24,
		    tq->loop_id, tq->port_name[0], tq->port_name[1],
		    tq->port_name[2], tq->port_name[3], tq->port_name[4],
		    tq->port_name[5], tq->port_name[6], tq->port_name[7]);
	}
	return (rval);
}

/*
 * ql_login_fabric_port
 *	Issue login fabric port mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	loop_id:	FC Loop ID.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_login_fabric_port(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t loop_id)
{
	int		rval;
	int		index;
	int		retry = 0;
	port_id_t	d_id;
	ql_tgt_t	*newq;
	ql_mbx_data_t	mr;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    tq->d_id.b24);

	/*
	 * QL_PARAMETER_ERROR also means the firmware is
	 * not able to allocate PCB entry due to resource
	 * issues, or collision.
	 */
	do {
		rval = ql_login_fport(ha, tq, loop_id, LFF_NONE, &mr);
		if ((rval == QL_PARAMETER_ERROR) ||
		    ((rval == QL_COMMAND_ERROR) && (mr.mb[1] == 2 ||
		    mr.mb[1] == 3 || mr.mb[1] == 7 || mr.mb[1] == 0xd))) {
			retry++;
			drv_usecwait(10 * MILLISEC);
		} else {
			break;
		}
	} while (retry < 5);

	switch (rval) {
	case QL_SUCCESS:
		tq->loop_id = loop_id;
		break;

	case QL_PORT_ID_USED:
		/*
		 * This Loop ID should NOT be in use in drivers
		 */
		newq = ql_loop_id_to_queue(ha, mr.mb[1]);

		if (newq != NULL && newq != tq && tq->logout_sent == 0) {
			cmn_err(CE_WARN, "ql_login_fabric_port(%d): logout of "
			    "dup loop_id=%xh, d_id=%xh", ha->instance,
			    newq->loop_id, newq->d_id.b24);
			ql_send_logo(ha, newq, NULL);
		}

		tq->loop_id = mr.mb[1];
		break;

	case QL_LOOP_ID_USED:
		d_id.b.al_pa = LSB(mr.mb[2]);
		d_id.b.area = MSB(mr.mb[2]);
		d_id.b.domain = LSB(mr.mb[1]);

		newq = ql_d_id_to_queue(ha, d_id);
		if (newq && (newq->loop_id != loop_id)) {
			/*
			 * This should NEVER ever happen; but this
			 * code is needed to bail out when the worst
			 * case happens - or as used to happen before
			 */
			QL_PRINT_2(CE_CONT, "(%d,%d): Loop ID is now "
			    "reassigned; old pairs: [%xh, %xh] and [%xh, %xh];"
			    "new pairs: [%xh, unknown] and [%xh, %xh]\n",
			    ha->instance, ha->vp_index, tq->d_id.b24, loop_id,
			    newq->d_id.b24, newq->loop_id, tq->d_id.b24,
			    newq->d_id.b24, loop_id);

			if ((newq->d_id.b24 & 0xff) != (d_id.b24 & 0xff)) {
				ADAPTER_STATE_LOCK(ha);

				index = ql_alpa_to_index[newq->d_id.b.al_pa];
				ql_add_link_b(&ha->dev[index], &newq->device);

				newq->d_id.b24 = d_id.b24;

				index = ql_alpa_to_index[d_id.b.al_pa];
				ql_add_link_b(&ha->dev[index], &newq->device);

				ADAPTER_STATE_UNLOCK(ha);
			}

			(void) ql_get_port_database(ha, newq, PDF_NONE);

		}

		/*
		 * Invalidate the loop ID for the
		 * us to obtain a new one.
		 */
		tq->loop_id = PORT_NO_LOOP_ID;
		break;

	case QL_ALL_IDS_IN_USE:
		rval = QL_FUNCTION_FAILED;
		EL(ha, "no loop id's available\n");
		break;

	default:
		if (rval == QL_COMMAND_ERROR) {
			switch (mr.mb[1]) {
			case 2:
			case 3:
				rval = QL_MEMORY_ALLOC_FAILED;
				break;

			case 4:
				rval = QL_FUNCTION_TIMEOUT;
				break;
			case 7:
				rval = QL_FABRIC_NOT_INITIALIZED;
				break;
			default:
				EL(ha, "cmd rtn; mb1=%xh\n", mr.mb[1]);
				break;
			}
		} else {
			cmn_err(CE_WARN, "%s(%d): login fabric port failed"
			    " D_ID=%xh, rval=%xh, mb1=%xh", QL_NAME,
			    ha->instance, tq->d_id.b24, rval, mr.mb[1]);
		}
		break;
	}

	if (rval != QL_SUCCESS && rval != QL_PORT_ID_USED &&
	    rval != QL_LOOP_ID_USED) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_logout_port
 *	Logs out a device if possible.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	d_id:	24 bit port ID.
 *
 * Returns:
 *	QL local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_logout_port(ql_adapter_state_t *ha, port_id_t d_id)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	uint16_t	index;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get head queue index. */
	index = ql_alpa_to_index[d_id.b.al_pa];

	/* Get device queue. */
	tq = NULL;
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			break;
		} else {
			tq = NULL;
		}
	}

	if (tq != NULL && tq->flags & TQF_FABRIC_DEVICE) {
		(void) ql_logout_fabric_port(ha, tq);
		tq->loop_id = PORT_NO_LOOP_ID;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (QL_SUCCESS);
}

/*
 * ql_dev_init
 *	Initialize/allocate device queue.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	d_id:		device destination ID
 *	loop_id:	device loop ID
 *	ADAPTER_STATE_LOCK must be already obtained.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
ql_tgt_t *
ql_dev_init(ql_adapter_state_t *ha, port_id_t d_id, uint16_t loop_id)
{
	ql_link_t	*link;
	uint16_t	index;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh, loop_id=%xh\n",
	    ha->instance, d_id.b24, loop_id);

	index = ql_alpa_to_index[d_id.b.al_pa];

	/* If device queue exists, set proper loop ID. */
	tq = NULL;
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			tq->loop_id = loop_id;

			/* Reset port down retry count. */
			tq->port_down_retry_count = ha->port_down_retry_count;
			tq->qfull_retry_count = ha->qfull_retry_count;

			break;
		} else {
			tq = NULL;
		}
	}

	/* If device does not have queue. */
	if (tq == NULL) {
		tq = (ql_tgt_t *)kmem_zalloc(sizeof (ql_tgt_t), KM_SLEEP);
		if (tq != NULL) {
			/*
			 * mutex to protect the device queue,
			 * does not block interrupts.
			 */
			mutex_init(&tq->mutex, NULL, MUTEX_DRIVER,
			    (ha->iflags & IFLG_INTR_AIF) ?
			    (void *)(uintptr_t)ha->intr_pri :
			    (void *)(uintptr_t)ha->iblock_cookie);

			tq->d_id.b24 = d_id.b24;
			tq->loop_id = loop_id;
			tq->device.base_address = tq;
			tq->iidma_rate = IIDMA_RATE_INIT;

			/* Reset port down retry count. */
			tq->port_down_retry_count = ha->port_down_retry_count;
			tq->qfull_retry_count = ha->qfull_retry_count;

			/* Add device to device queue. */
			ql_add_link_b(&ha->dev[index], &tq->device);
		}
	}

	if (tq == NULL) {
		EL(ha, "failed, d_id=%xh, loop_id=%xh\n", d_id.b24, loop_id);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (tq);
}

/*
 * ql_dev_free
 *	Remove queue from device list and frees resources used by queue.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	ADAPTER_STATE_LOCK must be already obtained.
 *
 * Context:
 *	Kernel context.
 */
void
ql_dev_free(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	ql_link_t	*link;
	uint16_t	index;
	ql_lun_t	*lq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	for (link = tq->lun_queues.first; link != NULL; link = link->next) {
		lq = link->base_address;
		if (lq->cmd.first != NULL) {
			return;
		}
	}

	if (tq->outcnt == 0) {
		/* Get head queue index. */
		index = ql_alpa_to_index[tq->d_id.b.al_pa];
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			if (link->base_address == tq) {
				ql_remove_link(&ha->dev[index], link);

				link = tq->lun_queues.first;
				while (link != NULL) {
					lq = link->base_address;
					link = link->next;

					ql_remove_link(&tq->lun_queues,
					    &lq->link);
					kmem_free(lq, sizeof (ql_lun_t));
				}

				mutex_destroy(&tq->mutex);
				kmem_free(tq, sizeof (ql_tgt_t));
				break;
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_lun_queue
 *	Allocate LUN queue if does not exists.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue.
 *	lun:	LUN number.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
static ql_lun_t *
ql_lun_queue(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t lun)
{
	ql_lun_t	*lq;
	ql_link_t	*link;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Fast path. */
	if (tq->last_lun_queue != NULL && tq->last_lun_queue->lun_no == lun) {
		QL_PRINT_3(CE_CONT, "(%d): fast done\n", ha->instance);
		return (tq->last_lun_queue);
	}

	if (lun >= MAX_LUNS) {
		EL(ha, "Exceeded MAX_LUN=%d, lun=%d\n", MAX_LUNS, lun);
		return (NULL);
	}
	/* If device queue exists, set proper loop ID. */
	lq = NULL;
	for (link = tq->lun_queues.first; link != NULL; link = link->next) {
		lq = link->base_address;
		if (lq->lun_no == lun) {
			QL_PRINT_3(CE_CONT, "(%d): found done\n", ha->instance);
			tq->last_lun_queue = lq;
			return (lq);
		}
	}

	/* If queue does exist. */
	lq = (ql_lun_t *)kmem_zalloc(sizeof (ql_lun_t), KM_SLEEP);

	/* Initialize LUN queue. */
	if (lq != NULL) {
		lq->link.base_address = lq;

		lq->lun_no = lun;
		lq->target_queue = tq;

		DEVICE_QUEUE_LOCK(tq);
		ql_add_link_b(&tq->lun_queues, &lq->link);
		DEVICE_QUEUE_UNLOCK(tq);
		tq->last_lun_queue = lq;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (lq);
}

/*
 * ql_fcp_scsi_cmd
 *	Process fibre channel (FCP) SCSI protocol commands.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = pointer to fc_packet.
 *	sp = srb pointer.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_fcp_scsi_cmd(ql_adapter_state_t *ha, fc_packet_t *pkt, ql_srb_t *sp)
{
	port_id_t	d_id;
	ql_tgt_t	*tq;
	uint64_t	*ptr;
	uint16_t	lun;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	tq = (ql_tgt_t *)pkt->pkt_fca_device;
	if (tq == NULL) {
		d_id.r.rsvd_1 = 0;
		d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
		tq = ql_d_id_to_queue(ha, d_id);
	}

	sp->fcp = (struct fcp_cmd *)pkt->pkt_cmd;
	lun = CHAR_TO_SHORT(lobyte(sp->fcp->fcp_ent_addr.ent_addr_0),
	    hibyte(sp->fcp->fcp_ent_addr.ent_addr_0));

	if (tq != NULL &&
	    (sp->lun_queue = ql_lun_queue(ha, tq, lun)) != NULL) {

		/*
		 * zero out FCP response; 24 Bytes
		 */
		ptr = (uint64_t *)pkt->pkt_resp;
		*ptr++ = 0; *ptr++ = 0; *ptr++ = 0;

		/* Handle task management function. */
		if ((sp->fcp->fcp_cntl.cntl_kill_tsk |
		    sp->fcp->fcp_cntl.cntl_clr_aca |
		    sp->fcp->fcp_cntl.cntl_reset_tgt |
		    sp->fcp->fcp_cntl.cntl_reset_lun |
		    sp->fcp->fcp_cntl.cntl_clr_tsk |
		    sp->fcp->fcp_cntl.cntl_abort_tsk) != 0) {
			ql_task_mgmt(ha, tq, pkt, sp);
		} else {
			ha->pha->xioctl->IosRequested++;
			ha->pha->xioctl->BytesRequested += (uint32_t)
			    sp->fcp->fcp_data_len;

			/*
			 * Setup for commands with data transfer
			 */
			sp->iocb = ha->fcp_cmd;
			sp->req_cnt = 1;
			if (sp->fcp->fcp_data_len != 0) {
				/*
				 * FCP data is bound to pkt_data_dma
				 */
				if (sp->fcp->fcp_cntl.cntl_write_data) {
					(void) ddi_dma_sync(pkt->pkt_data_dma,
					    0, 0, DDI_DMA_SYNC_FORDEV);
				}

				/* Setup IOCB count. */
				if (pkt->pkt_data_cookie_cnt > ha->cmd_segs &&
				    (!CFG_IST(ha, CFG_CTRL_8021) ||
				    sp->sg_dma.dma_handle == NULL)) {
					uint32_t	cnt;

					cnt = pkt->pkt_data_cookie_cnt -
					    ha->cmd_segs;
					sp->req_cnt = (uint16_t)
					    (cnt / ha->cmd_cont_segs);
					if (cnt % ha->cmd_cont_segs) {
						sp->req_cnt = (uint16_t)
						    (sp->req_cnt + 2);
					} else {
						sp->req_cnt++;
					}
				}
			}
			QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

			return (ql_start_cmd(ha, tq, pkt, sp));
		}
	} else {
		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;

		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp)
			ql_awaken_task_daemon(ha, sp, 0, 0);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

/*
 * ql_task_mgmt
 *	Task management function processor.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	pkt:	pointer to fc_packet.
 *	sp:	SRB pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_task_mgmt(ql_adapter_state_t *ha, ql_tgt_t *tq, fc_packet_t *pkt,
    ql_srb_t *sp)
{
	fcp_rsp_t		*fcpr;
	struct fcp_rsp_info	*rsp;
	uint16_t		lun;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	fcpr = (fcp_rsp_t *)pkt->pkt_resp;
	rsp = (struct fcp_rsp_info *)pkt->pkt_resp + sizeof (fcp_rsp_t);

	bzero(fcpr, pkt->pkt_rsplen);

	fcpr->fcp_u.fcp_status.rsp_len_set = 1;
	fcpr->fcp_response_len = 8;
	lun = CHAR_TO_SHORT(lobyte(sp->fcp->fcp_ent_addr.ent_addr_0),
	    hibyte(sp->fcp->fcp_ent_addr.ent_addr_0));

	if (sp->fcp->fcp_cntl.cntl_clr_aca) {
		if (ql_clear_aca(ha, tq, lun) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_reset_lun) {
		if (ql_lun_reset(ha, tq, lun) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_reset_tgt) {
		if (ql_target_reset(ha, tq, ha->loop_reset_delay) !=
		    QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_clr_tsk) {
		if (ql_clear_task_set(ha, tq, lun) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_abort_tsk) {
		if (ql_abort_task_set(ha, tq, lun) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else {
		rsp->rsp_code = FCP_TASK_MGMT_NOT_SUPPTD;
	}

	pkt->pkt_state = FC_PKT_SUCCESS;

	/* Do command callback. */
	if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
		ql_awaken_task_daemon(ha, sp, 0, 0);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_fcp_ip_cmd
 *	Process fibre channel (FCP) Internet (IP) protocols commands.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	pkt:	pointer to fc_packet.
 *	sp:	SRB pointer.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_fcp_ip_cmd(ql_adapter_state_t *ha, fc_packet_t *pkt, ql_srb_t *sp)
{
	port_id_t	d_id;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	tq = (ql_tgt_t *)pkt->pkt_fca_device;
	if (tq == NULL) {
		d_id.r.rsvd_1 = 0;
		d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
		tq = ql_d_id_to_queue(ha, d_id);
	}

	if (tq != NULL && (sp->lun_queue = ql_lun_queue(ha, tq, 0)) != NULL) {
		/*
		 * IP data is bound to pkt_cmd_dma
		 */
		(void) ddi_dma_sync(pkt->pkt_cmd_dma,
		    0, 0, DDI_DMA_SYNC_FORDEV);

		/* Setup IOCB count. */
		sp->iocb = ha->ip_cmd;
		if (pkt->pkt_cmd_cookie_cnt > ha->cmd_segs) {
			uint32_t	cnt;

			cnt = pkt->pkt_cmd_cookie_cnt - ha->cmd_segs;
			sp->req_cnt = (uint16_t)(cnt / ha->cmd_cont_segs);
			if (cnt % ha->cmd_cont_segs) {
				sp->req_cnt = (uint16_t)(sp->req_cnt + 2);
			} else {
				sp->req_cnt++;
			}
		} else {
			sp->req_cnt = 1;
		}
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

		return (ql_start_cmd(ha, tq, pkt, sp));
	} else {
		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;

		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp)
			ql_awaken_task_daemon(ha, sp, 0, 0);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

/*
 * ql_fc_services
 *	Process fibre channel services (name server).
 *
 * Input:
 *	ha:	adapter state pointer.
 *	pkt:	pointer to fc_packet.
 *
 * Returns:
 *	FC_SUCCESS - the packet was accepted for transport.
 *	FC_TRANSPORT_ERROR - a transport error occurred.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_fc_services(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	uint32_t	cnt;
	fc_ct_header_t	hdr;
	la_els_rjt_t	rjt;
	port_id_t	d_id;
	ql_tgt_t	*tq;
	ql_srb_t	*sp;
	int		rval;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&hdr,
	    (uint8_t *)pkt->pkt_cmd, sizeof (hdr), DDI_DEV_AUTOINCR);

	bzero(&rjt, sizeof (rjt));

	/* Do some sanity checks */
	cnt = (uint32_t)((uint32_t)(hdr.ct_aiusize * 4) +
	    sizeof (fc_ct_header_t));
	if (cnt > (uint32_t)pkt->pkt_rsplen) {
		EL(ha, "FC_ELS_MALFORMED, cnt=%xh, size=%xh\n", cnt,
		    pkt->pkt_rsplen);
		return (FC_ELS_MALFORMED);
	}

	switch (hdr.ct_fcstype) {
	case FCSTYPE_DIRECTORY:
	case FCSTYPE_MGMTSERVICE:
		/* An FCA must make sure that the header is in big endian */
		ql_cthdr_endian(pkt->pkt_cmd_acc, pkt->pkt_cmd, B_FALSE);

		d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
		tq = ql_d_id_to_queue(ha, d_id);
		sp = (ql_srb_t *)pkt->pkt_fca_private;
		if (tq == NULL ||
		    (sp->lun_queue = ql_lun_queue(ha, tq, 0)) == NULL) {
			pkt->pkt_state = FC_PKT_LOCAL_RJT;
			pkt->pkt_reason = FC_REASON_NO_CONNECTION;
			rval = QL_SUCCESS;
			break;
		}

		/*
		 * Services data is bound to pkt_cmd_dma
		 */
		(void) ddi_dma_sync(pkt->pkt_cmd_dma, 0, 0,
		    DDI_DMA_SYNC_FORDEV);

		sp->flags |= SRB_MS_PKT;
		sp->retry_count = 32;

		/* Setup IOCB count. */
		sp->iocb = ha->ms_cmd;
		if (pkt->pkt_resp_cookie_cnt > MS_DATA_SEGMENTS) {
			cnt = pkt->pkt_resp_cookie_cnt - MS_DATA_SEGMENTS;
			sp->req_cnt =
			    (uint16_t)(cnt / CONT_TYPE_1_DATA_SEGMENTS);
			if (cnt % CONT_TYPE_1_DATA_SEGMENTS) {
				sp->req_cnt = (uint16_t)(sp->req_cnt + 2);
			} else {
				sp->req_cnt++;
			}
		} else {
			sp->req_cnt = 1;
		}
		rval = ql_start_cmd(ha, tq, pkt, sp);

		QL_PRINT_3(CE_CONT, "(%d): done, ql_start_cmd=%xh\n",
		    ha->instance, rval);

		return (rval);

	default:
		EL(ha, "unknown fcstype=%xh\n", hdr.ct_fcstype);
		rval = QL_FUNCTION_PARAMETER_ERROR;
		break;
	}

	if (rval != QL_SUCCESS) {
		/* Build RJT. */
		rjt.ls_code.ls_code = LA_ELS_RJT;
		rjt.reason = FC_REASON_CMD_UNSUPPORTED;

		ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
		    (uint8_t *)pkt->pkt_resp, sizeof (rjt), DDI_DEV_AUTOINCR);

		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_UNSUPPORTED;
		EL(ha, "LA_ELS_RJT, FC_REASON_UNSUPPORTED\n");
	}

	/* Do command callback. */
	if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
		ql_awaken_task_daemon(ha, (ql_srb_t *)pkt->pkt_fca_private,
		    0, 0);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (FC_SUCCESS);
}

/*
 * ql_cthdr_endian
 *	Change endianess of ct passthrough header and payload.
 *
 * Input:
 *	acc_handle:	DMA buffer access handle.
 *	ct_hdr:		Pointer to header.
 *	restore:	Restore first flag.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_cthdr_endian(ddi_acc_handle_t acc_handle, caddr_t ct_hdr,
    boolean_t restore)
{
	uint8_t		i, *bp;
	fc_ct_header_t	hdr;
	uint32_t	*hdrp = (uint32_t *)&hdr;

	ddi_rep_get8(acc_handle, (uint8_t *)&hdr,
	    (uint8_t *)ct_hdr, sizeof (hdr), DDI_DEV_AUTOINCR);

	if (restore) {
		for (i = 0; i < ((sizeof (hdr)) / (sizeof (uint32_t))); i++) {
			*hdrp = BE_32(*hdrp);
			hdrp++;
		}
	}

	if (hdr.ct_fcstype == FCSTYPE_DIRECTORY) {
		bp = (uint8_t *)ct_hdr + sizeof (fc_ct_header_t);

		switch (hdr.ct_cmdrsp) {
		case NS_GA_NXT:
		case NS_GPN_ID:
		case NS_GNN_ID:
		case NS_GCS_ID:
		case NS_GFT_ID:
		case NS_GSPN_ID:
		case NS_GPT_ID:
		case NS_GID_FT:
		case NS_GID_PT:
		case NS_RPN_ID:
		case NS_RNN_ID:
		case NS_RSPN_ID:
		case NS_DA_ID:
			BIG_ENDIAN_32(bp);
			break;
		case NS_RFT_ID:
		case NS_RCS_ID:
		case NS_RPT_ID:
			BIG_ENDIAN_32(bp);
			bp += 4;
			BIG_ENDIAN_32(bp);
			break;
		case NS_GNN_IP:
		case NS_GIPA_IP:
			BIG_ENDIAN(bp, 16);
			break;
		case NS_RIP_NN:
			bp += 8;
			BIG_ENDIAN(bp, 16);
			break;
		case NS_RIPA_NN:
			bp += 8;
			BIG_ENDIAN_64(bp);
			break;
		default:
			break;
		}
	}

	if (restore == B_FALSE) {
		for (i = 0; i < ((sizeof (hdr)) / (sizeof (uint32_t))); i++) {
			*hdrp = BE_32(*hdrp);
			hdrp++;
		}
	}

	ddi_rep_put8(acc_handle, (uint8_t *)&hdr,
	    (uint8_t *)ct_hdr, sizeof (hdr), DDI_DEV_AUTOINCR);
}

/*
 * ql_start_cmd
 *	Finishes starting fibre channel protocol (FCP) command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	pkt:	pointer to fc_packet.
 *	sp:	SRB pointer.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_start_cmd(ql_adapter_state_t *ha, ql_tgt_t *tq, fc_packet_t *pkt,
    ql_srb_t *sp)
{
	int		rval = FC_SUCCESS;
	time_t		poll_wait = 0;
	ql_lun_t	*lq = sp->lun_queue;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	sp->handle = 0;

	/* Set poll for finish. */
	if (pkt->pkt_tran_flags & FC_TRAN_NO_INTR) {
		sp->flags |= SRB_POLL;
		if (pkt->pkt_timeout == 0) {
			pkt->pkt_timeout = SCSI_POLL_TIMEOUT;
		}
	}

	/* Acquire device queue lock. */
	DEVICE_QUEUE_LOCK(tq);

	/*
	 * If we need authentication, report device busy to
	 * upper layers to retry later
	 */
	if (tq->flags & (TQF_RSCN_RCVD | TQF_NEED_AUTHENTICATION)) {
		DEVICE_QUEUE_UNLOCK(tq);
		EL(ha, "failed, FC_DEVICE_BUSY=%xh, d_id=%xh\n", tq->flags,
		    tq->d_id.b24);
		return (FC_DEVICE_BUSY);
	}

	/* Insert command onto watchdog queue. */
	if (!(pkt->pkt_tran_flags & FC_TRAN_DUMPING)) {
		ql_timeout_insert(ha, tq, sp);
	} else {
		/*
		 * Run dump requests in polled mode as kernel threads
		 * and interrupts may have been disabled.
		 */
		sp->flags |= SRB_POLL;
		sp->init_wdg_q_time = 0;
		sp->isp_timeout = 0;
	}

	/* If a polling command setup wait time. */
	if (sp->flags & SRB_POLL) {
		if (sp->flags & SRB_WATCHDOG_ENABLED) {
			poll_wait = (sp->wdg_q_time + 2) * WATCHDOG_TIME;
		} else {
			poll_wait = pkt->pkt_timeout;
		}
	}

	if (ha->pha->flags & ABORT_CMDS_LOOP_DOWN_TMO &&
	    (CFG_IST(ha, CFG_ENABLE_LINK_DOWN_REPORTING))) {
		/* Set ending status. */
		sp->pkt->pkt_reason = CS_PORT_UNAVAILABLE;

		/* Call done routine to handle completions. */
		sp->cmd.next = NULL;
		DEVICE_QUEUE_UNLOCK(tq);
		ql_done(&sp->cmd);
	} else {
		if (ddi_in_panic() && (sp->flags & SRB_POLL)) {
			int do_lip = 0;

			DEVICE_QUEUE_UNLOCK(tq);

			ADAPTER_STATE_LOCK(ha);
			if ((do_lip = ha->pha->lip_on_panic) == 0) {
				ha->pha->lip_on_panic++;
			}
			ADAPTER_STATE_UNLOCK(ha);

			if (!do_lip) {

				/*
				 * That Qlogic F/W performs PLOGI, PRLI, etc
				 * is helpful here. If a PLOGI fails for some
				 * reason, you would get CS_PORT_LOGGED_OUT
				 * or some such error; and we should get a
				 * careful polled mode login kicked off inside
				 * of this driver itself. You don't have FC
				 * transport's services as all threads are
				 * suspended, interrupts disabled, and so
				 * on. Right now we do re-login if the packet
				 * state isn't FC_PKT_SUCCESS.
				 */
				(void) ql_abort_isp(ha);
			}

			ql_start_iocb(ha, sp);
		} else {
			/* Add the command to the device queue */
			if (pkt->pkt_tran_flags & FC_TRAN_HI_PRIORITY) {
				ql_add_link_t(&lq->cmd, &sp->cmd);
			} else {
				ql_add_link_b(&lq->cmd, &sp->cmd);
			}

			sp->flags |= SRB_IN_DEVICE_QUEUE;

			/* Check whether next message can be processed */
			ql_next(ha, lq);
		}
	}

	/* If polling, wait for finish. */
	if (poll_wait) {
		if (ql_poll_cmd(ha, sp, poll_wait) != QL_SUCCESS) {
			int	res;

			res = ql_abort((opaque_t)ha, pkt, 0);
			if (res != FC_SUCCESS && res != FC_ABORTED) {
				DEVICE_QUEUE_LOCK(tq);
				ql_remove_link(&lq->cmd, &sp->cmd);
				sp->flags &= ~SRB_IN_DEVICE_QUEUE;
				DEVICE_QUEUE_UNLOCK(tq);
			}
		}

		if (pkt->pkt_state != FC_PKT_SUCCESS) {
			EL(ha, "failed, FC_TRANSPORT_ERROR\n");
			rval = FC_TRANSPORT_ERROR;
		}

		if (ddi_in_panic()) {
			if (pkt->pkt_state != FC_PKT_SUCCESS) {
				port_id_t d_id;

				/*
				 * successful LOGIN implies by design
				 * that PRLI also succeeded for disks
				 * Note also that there is no special
				 * mailbox command to send PRLI.
				 */
				d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
				(void) ql_login_port(ha, d_id);
			}
		}

		/*
		 * This should only happen during CPR dumping
		 */
		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) &&
		    pkt->pkt_comp) {
			sp->flags &= ~SRB_POLL;
			(*pkt->pkt_comp)(pkt);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_poll_cmd
 *	Polls commands for completion.
 *
 * Input:
 *	ha = adapter state pointer.
 *	sp = SRB command pointer.
 *	poll_wait = poll wait time in seconds.
 *
 * Returns:
 *	QL local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_poll_cmd(ql_adapter_state_t *vha, ql_srb_t *sp, time_t poll_wait)
{
	int			rval = QL_SUCCESS;
	time_t			msecs_left = poll_wait * 100;	/* 10ms inc */
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	while (sp->flags & SRB_POLL) {

		if ((ha->flags & INTERRUPTS_ENABLED) == 0 ||
		    ha->idle_timer >= 15 || ddi_in_panic()) {

			/* If waiting for restart, do it now. */
			if (ha->port_retry_timer != 0) {
				ADAPTER_STATE_LOCK(ha);
				ha->port_retry_timer = 0;
				ADAPTER_STATE_UNLOCK(ha);

				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |= PORT_RETRY_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
			}

			if (INTERRUPT_PENDING(ha)) {
				(void) ql_isr((caddr_t)ha);
				INTR_LOCK(ha);
				ha->intr_claimed = TRUE;
				INTR_UNLOCK(ha);
			}

			/*
			 * Call task thread function in case the
			 * daemon is not running.
			 */
			TASK_DAEMON_LOCK(ha);

			if (!ddi_in_panic() && QL_DAEMON_NOT_ACTIVE(ha) &&
			    QL_TASK_PENDING(ha)) {
				ha->task_daemon_flags |= TASK_THREAD_CALLED;
				ql_task_thread(ha);
				ha->task_daemon_flags &= ~TASK_THREAD_CALLED;
			}

			TASK_DAEMON_UNLOCK(ha);
		}

		if (msecs_left < 10) {
			rval = QL_FUNCTION_TIMEOUT;
			break;
		}

		/*
		 * Polling interval is 10 milli seconds; Increasing
		 * the polling interval to seconds since disk IO
		 * timeout values are ~60 seconds is tempting enough,
		 * but CPR dump time increases, and so will the crash
		 * dump time; Don't toy with the settings without due
		 * consideration for all the scenarios that will be
		 * impacted.
		 */
		ql_delay(ha, 10000);
		msecs_left -= 10;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_next
 *	Retrieve and process next job in the device queue.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	lq:	LUN queue pointer.
 *	DEVICE_QUEUE_LOCK must be already obtained.
 *
 * Output:
 *	Releases DEVICE_QUEUE_LOCK upon exit.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_next(ql_adapter_state_t *vha, ql_lun_t *lq)
{
	ql_srb_t		*sp;
	ql_link_t		*link;
	ql_tgt_t		*tq = lq->target_queue;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ddi_in_panic()) {
		DEVICE_QUEUE_UNLOCK(tq);
		QL_PRINT_3(CE_CONT, "(%d): panic/active exit\n",
		    ha->instance);
		return;
	}

	while ((link = lq->cmd.first) != NULL) {
		sp = link->base_address;

		/* Exit if can not start commands. */
		if (DRIVER_SUSPENDED(ha) ||
		    (ha->flags & ONLINE) == 0 ||
		    !VALID_DEVICE_ID(ha, tq->loop_id) ||
		    sp->flags & SRB_ABORT ||
		    tq->flags & (TQF_RSCN_RCVD | TQF_NEED_AUTHENTICATION |
		    TQF_QUEUE_SUSPENDED)) {
			EL(vha, "break, d_id=%xh, tdf=%xh, tqf=%xh, spf=%xh, "
			    "haf=%xh, loop_id=%xh\n", tq->d_id.b24,
			    ha->task_daemon_flags, tq->flags, sp->flags,
			    ha->flags, tq->loop_id);
			break;
		}

		/*
		 * Find out the LUN number for untagged command use.
		 * If there is an untagged command pending for the LUN,
		 * we would not submit another untagged command
		 * or if reached LUN execution throttle.
		 */
		if (sp->flags & SRB_FCP_CMD_PKT) {
			if (lq->flags & LQF_UNTAGGED_PENDING ||
			    lq->lun_outcnt >= ha->execution_throttle) {
				QL_PRINT_8(CE_CONT, "(%d): break, d_id=%xh, "
				    "lf=%xh, lun_outcnt=%xh\n", ha->instance,
				    tq->d_id.b24, lq->flags, lq->lun_outcnt);
				break;
			}
			if (sp->fcp->fcp_cntl.cntl_qtype ==
			    FCP_QTYPE_UNTAGGED) {
				/*
				 * Set the untagged-flag for the LUN
				 * so that no more untagged commands
				 * can be submitted for this LUN.
				 */
				lq->flags |= LQF_UNTAGGED_PENDING;
			}

			/* Count command as sent. */
			lq->lun_outcnt++;
		}

		/* Remove srb from device queue. */
		ql_remove_link(&lq->cmd, &sp->cmd);
		sp->flags &= ~SRB_IN_DEVICE_QUEUE;

		tq->outcnt++;

		ql_start_iocb(vha, sp);
	}

	/* Release device queue lock. */
	DEVICE_QUEUE_UNLOCK(tq);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_done
 *	Process completed commands.
 *
 * Input:
 *	link:	first command link in chain.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_done(ql_link_t *link)
{
	ql_adapter_state_t	*ha;
	ql_link_t		*next_link;
	ql_srb_t		*sp;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;

	QL_PRINT_3(CE_CONT, "started\n");

	for (; link != NULL; link = next_link) {
		next_link = link->next;
		sp = link->base_address;
		ha = sp->ha;

		if (sp->flags & SRB_UB_CALLBACK) {
			QL_UB_LOCK(ha);
			if (sp->flags & SRB_UB_IN_ISP) {
				if (ha->ub_outcnt != 0) {
					ha->ub_outcnt--;
				}
				QL_UB_UNLOCK(ha);
				ql_isp_rcvbuf(ha);
				QL_UB_LOCK(ha);
			}
			QL_UB_UNLOCK(ha);
			ql_awaken_task_daemon(ha, sp, 0, 0);
		} else {
			/* Free outstanding command slot. */
			if (sp->handle != 0) {
				ha->outstanding_cmds[
				    sp->handle & OSC_INDEX_MASK] = NULL;
				sp->handle = 0;
				sp->flags &= ~SRB_IN_TOKEN_ARRAY;
			}

			/* Acquire device queue lock. */
			lq = sp->lun_queue;
			tq = lq->target_queue;
			DEVICE_QUEUE_LOCK(tq);

			/* Decrement outstanding commands on device. */
			if (tq->outcnt != 0) {
				tq->outcnt--;
			}

			if (sp->flags & SRB_FCP_CMD_PKT) {
				if (sp->fcp->fcp_cntl.cntl_qtype ==
				    FCP_QTYPE_UNTAGGED) {
					/*
					 * Clear the flag for this LUN so that
					 * untagged commands can be submitted
					 * for it.
					 */
					lq->flags &= ~LQF_UNTAGGED_PENDING;
				}

				if (lq->lun_outcnt != 0) {
					lq->lun_outcnt--;
				}
			}

			/* Reset port down retry count on good completion. */
			if (sp->pkt->pkt_reason == CS_COMPLETE) {
				tq->port_down_retry_count =
				    ha->port_down_retry_count;
				tq->qfull_retry_count = ha->qfull_retry_count;
			}


			/* Alter aborted status for fast timeout feature */
			if (CFG_IST(ha, CFG_FAST_TIMEOUT) &&
			    (sp->flags & (SRB_MS_PKT | SRB_ELS_PKT) ||
			    !(tq->flags & TQF_NEED_AUTHENTICATION)) &&
			    sp->flags & SRB_RETRY &&
			    (sp->flags & SRB_WATCHDOG_ENABLED &&
			    sp->wdg_q_time > 1)) {
				EL(ha, "fast abort modify change\n");
				sp->flags &= ~(SRB_RETRY);
				sp->pkt->pkt_reason = CS_TIMEOUT;
			}

			/* Place request back on top of target command queue */
			if ((sp->flags & (SRB_MS_PKT | SRB_ELS_PKT) ||
			    !(tq->flags & TQF_NEED_AUTHENTICATION)) &&
			    sp->flags & SRB_RETRY &&
			    (sp->flags & SRB_WATCHDOG_ENABLED &&
			    sp->wdg_q_time > 1)) {
				sp->flags &= ~(SRB_ISP_STARTED |
				    SRB_ISP_COMPLETED | SRB_RETRY);

				/* Reset watchdog timer */
				sp->wdg_q_time = sp->init_wdg_q_time;

				/* Issue marker command on reset status. */
				if (!(ha->task_daemon_flags & LOOP_DOWN) &&
				    (sp->pkt->pkt_reason == CS_RESET ||
				    (CFG_IST(ha, CFG_CTRL_24258081) &&
				    sp->pkt->pkt_reason == CS_ABORTED))) {
					(void) ql_marker(ha, tq->loop_id, 0,
					    MK_SYNC_ID);
				}

				ql_add_link_t(&lq->cmd, &sp->cmd);
				sp->flags |= SRB_IN_DEVICE_QUEUE;
				ql_next(ha, lq);
			} else {
				/* Remove command from watchdog queue. */
				if (sp->flags & SRB_WATCHDOG_ENABLED) {
					ql_remove_link(&tq->wdg, &sp->wdg);
					sp->flags &= ~SRB_WATCHDOG_ENABLED;
				}

				if (lq->cmd.first != NULL) {
					ql_next(ha, lq);
				} else {
					/* Release LU queue specific lock. */
					DEVICE_QUEUE_UNLOCK(tq);
					if (ha->pha->pending_cmds.first !=
					    NULL) {
						ql_start_iocb(ha, NULL);
					}
				}

				/* Sync buffers if required.  */
				if (sp->flags & (SRB_MS_PKT | SRB_ELS_PKT)) {
					(void) ddi_dma_sync(
					    sp->pkt->pkt_resp_dma,
					    0, 0, DDI_DMA_SYNC_FORCPU);
				}

				/* Map ISP completion codes. */
				sp->pkt->pkt_expln = FC_EXPLN_NONE;
				sp->pkt->pkt_action = FC_ACTION_RETRYABLE;
				switch (sp->pkt->pkt_reason) {
				case CS_COMPLETE:
					sp->pkt->pkt_state = FC_PKT_SUCCESS;
					break;
				case CS_RESET:
					/* Issue marker command. */
					if (!(ha->task_daemon_flags &
					    LOOP_DOWN)) {
						(void) ql_marker(ha,
						    tq->loop_id, 0,
						    MK_SYNC_ID);
					}
					sp->pkt->pkt_state =
					    FC_PKT_PORT_OFFLINE;
					sp->pkt->pkt_reason =
					    FC_REASON_ABORTED;
					break;
				case CS_RESOUCE_UNAVAILABLE:
					sp->pkt->pkt_state = FC_PKT_LOCAL_BSY;
					sp->pkt->pkt_reason =
					    FC_REASON_PKT_BUSY;
					break;

				case CS_TIMEOUT:
					sp->pkt->pkt_state = FC_PKT_TIMEOUT;
					sp->pkt->pkt_reason =
					    FC_REASON_HW_ERROR;
					break;
				case CS_DATA_OVERRUN:
					sp->pkt->pkt_state = FC_PKT_LOCAL_RJT;
					sp->pkt->pkt_reason =
					    FC_REASON_OVERRUN;
					break;
				case CS_PORT_UNAVAILABLE:
				case CS_PORT_LOGGED_OUT:
					sp->pkt->pkt_state =
					    FC_PKT_PORT_OFFLINE;
					sp->pkt->pkt_reason =
					    FC_REASON_LOGIN_REQUIRED;
					ql_send_logo(ha, tq, NULL);
					break;
				case CS_PORT_CONFIG_CHG:
					sp->pkt->pkt_state =
					    FC_PKT_PORT_OFFLINE;
					sp->pkt->pkt_reason =
					    FC_REASON_OFFLINE;
					break;
				case CS_QUEUE_FULL:
					sp->pkt->pkt_state = FC_PKT_LOCAL_RJT;
					sp->pkt->pkt_reason = FC_REASON_QFULL;
					break;

				case CS_ABORTED:
					DEVICE_QUEUE_LOCK(tq);
					if (tq->flags & (TQF_RSCN_RCVD |
					    TQF_NEED_AUTHENTICATION)) {
						sp->pkt->pkt_state =
						    FC_PKT_PORT_OFFLINE;
						sp->pkt->pkt_reason =
						    FC_REASON_LOGIN_REQUIRED;
					} else {
						sp->pkt->pkt_state =
						    FC_PKT_LOCAL_RJT;
						sp->pkt->pkt_reason =
						    FC_REASON_ABORTED;
					}
					DEVICE_QUEUE_UNLOCK(tq);
					break;

				case CS_TRANSPORT:
					sp->pkt->pkt_state = FC_PKT_LOCAL_RJT;
					sp->pkt->pkt_reason =
					    FC_PKT_TRAN_ERROR;
					break;

				case CS_DATA_UNDERRUN:
					sp->pkt->pkt_state = FC_PKT_LOCAL_RJT;
					sp->pkt->pkt_reason =
					    FC_REASON_UNDERRUN;
					break;
				case CS_DMA_ERROR:
				case CS_BAD_PAYLOAD:
				case CS_UNKNOWN:
				case CS_CMD_FAILED:
				default:
					sp->pkt->pkt_state = FC_PKT_LOCAL_RJT;
					sp->pkt->pkt_reason =
					    FC_REASON_HW_ERROR;
					break;
				}

				/* Now call the pkt completion callback */
				if (sp->flags & SRB_POLL) {
					sp->flags &= ~SRB_POLL;
				} else if (sp->pkt->pkt_comp) {
					if (sp->pkt->pkt_tran_flags &
					    FC_TRAN_IMMEDIATE_CB) {
						(*sp->pkt->pkt_comp)(sp->pkt);
					} else {
						ql_awaken_task_daemon(ha, sp,
						    0, 0);
					}
				}
			}
		}
	}

	QL_PRINT_3(CE_CONT, "done\n");
}

/*
 * ql_awaken_task_daemon
 *	Adds command completion callback to callback queue and/or
 *	awakens task daemon thread.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	sp:		srb pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_awaken_task_daemon(ql_adapter_state_t *vha, ql_srb_t *sp,
    uint32_t set_flags, uint32_t reset_flags)
{
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Acquire task daemon lock. */
	TASK_DAEMON_LOCK(ha);

	if (set_flags & ISP_ABORT_NEEDED) {
		if (ha->task_daemon_flags & ABORT_ISP_ACTIVE) {
			set_flags &= ~ISP_ABORT_NEEDED;
		}
	}

	ha->task_daemon_flags |= set_flags;
	ha->task_daemon_flags &= ~reset_flags;

	if (QL_DAEMON_SUSPENDED(ha)) {
		if (sp != NULL) {
			TASK_DAEMON_UNLOCK(ha);

			/* Do callback. */
			if (sp->flags & SRB_UB_CALLBACK) {
				ql_unsol_callback(sp);
			} else {
				(*sp->pkt->pkt_comp)(sp->pkt);
			}
		} else {
			if (!(curthread->t_flag & T_INTR_THREAD) &&
			    !(ha->task_daemon_flags & TASK_THREAD_CALLED)) {
				ha->task_daemon_flags |= TASK_THREAD_CALLED;
				ql_task_thread(ha);
				ha->task_daemon_flags &= ~TASK_THREAD_CALLED;
			}

			TASK_DAEMON_UNLOCK(ha);
		}
	} else {
		if (sp != NULL) {
			ql_add_link_b(&ha->callback_queue, &sp->cmd);
		}

		if (ha->task_daemon_flags & TASK_DAEMON_SLEEPING_FLG) {
			cv_broadcast(&ha->cv_task_daemon);
		}
		TASK_DAEMON_UNLOCK(ha);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_task_daemon
 *	Thread that is awaken by the driver when a
 *	background needs to be done.
 *
 * Input:
 *	arg = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_task_daemon(void *arg)
{
	ql_adapter_state_t	*ha = (void *)arg;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	CALLB_CPR_INIT(&ha->cprinfo, &ha->task_daemon_mutex, callb_generic_cpr,
	    "ql_task_daemon");

	/* Acquire task daemon lock. */
	TASK_DAEMON_LOCK(ha);

	ha->task_daemon_flags |= TASK_DAEMON_ALIVE_FLG;

	while ((ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) == 0) {
		ql_task_thread(ha);

		QL_PRINT_3(CE_CONT, "(%d): Going to sleep\n", ha->instance);

		/*
		 * Before we wait on the conditional variable, we
		 * need to check if STOP_FLG is set for us to terminate
		 */
		if (ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) {
			break;
		}

		/*LINTED [Solaris CALLB_CPR_SAFE_BEGIN Lint error]*/
		CALLB_CPR_SAFE_BEGIN(&ha->cprinfo);

		ha->task_daemon_flags |= TASK_DAEMON_SLEEPING_FLG;

		/* If killed, stop task daemon */
		if (cv_wait_sig(&ha->cv_task_daemon,
		    &ha->task_daemon_mutex) == 0) {
			ha->task_daemon_flags |= TASK_DAEMON_STOP_FLG;
		}

		ha->task_daemon_flags &= ~TASK_DAEMON_SLEEPING_FLG;

		/*LINTED [Solaris CALLB_CPR_SAFE_END Lint error]*/
		CALLB_CPR_SAFE_END(&ha->cprinfo, &ha->task_daemon_mutex);

		QL_PRINT_3(CE_CONT, "(%d): Awakened\n", ha->instance);
	}

	ha->task_daemon_flags &= ~(TASK_DAEMON_STOP_FLG |
	    TASK_DAEMON_ALIVE_FLG);

	/*LINTED [Solaris CALLB_CPR_EXIT Lint error]*/
	CALLB_CPR_EXIT(&ha->cprinfo);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	thread_exit();
}

/*
 * ql_task_thread
 *	Thread run by daemon.
 *
 * Input:
 *	ha = adapter state pointer.
 *	TASK_DAEMON_LOCK must be acquired prior to call.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_task_thread(ql_adapter_state_t *ha)
{
	int			loop_again;
	ql_srb_t		*sp;
	ql_head_t		*head;
	ql_link_t		*link;
	caddr_t			msg;
	ql_adapter_state_t	*vha;

	do {
		QL_PRINT_3(CE_CONT, "(%d): task_daemon_flags=%xh\n",
		    ha->instance, ha->task_daemon_flags);

		loop_again = FALSE;

		QL_PM_LOCK(ha);
		if (ha->power_level != PM_LEVEL_D0) {
			QL_PM_UNLOCK(ha);
			ha->task_daemon_flags |= TASK_DAEMON_STALLED_FLG;
			break;
		}
		QL_PM_UNLOCK(ha);

		/* IDC event. */
		if (ha->task_daemon_flags & IDC_EVENT) {
			ha->task_daemon_flags &= ~IDC_EVENT;
			TASK_DAEMON_UNLOCK(ha);
			ql_process_idc_event(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = TRUE;
		}

		if (ha->flags & ADAPTER_SUSPENDED || ha->task_daemon_flags &
		    (TASK_DAEMON_STOP_FLG | DRIVER_STALL) ||
		    (ha->flags & ONLINE) == 0) {
			ha->task_daemon_flags |= TASK_DAEMON_STALLED_FLG;
			break;
		}
		ha->task_daemon_flags &= ~TASK_DAEMON_STALLED_FLG;

		if (ha->task_daemon_flags & ISP_ABORT_NEEDED) {
			TASK_DAEMON_UNLOCK(ha);
			if (ha->log_parity_pause == B_TRUE) {
				(void) ql_flash_errlog(ha,
				    FLASH_ERRLOG_PARITY_ERR, 0,
				    MSW(ha->parity_stat_err),
				    LSW(ha->parity_stat_err));
				ha->log_parity_pause = B_FALSE;
			}
			ql_port_state(ha, FC_STATE_OFFLINE, FC_STATE_CHANGE);
			TASK_DAEMON_LOCK(ha);
			loop_again = TRUE;
		}

		/* Idle Check. */
		if (ha->task_daemon_flags & TASK_DAEMON_IDLE_CHK_FLG) {
			ha->task_daemon_flags &= ~TASK_DAEMON_IDLE_CHK_FLG;
			if (!(ha->task_daemon_flags & QL_SUSPENDED)) {
				TASK_DAEMON_UNLOCK(ha);
				ql_idle_check(ha);
				TASK_DAEMON_LOCK(ha);
				loop_again = TRUE;
			}
		}

		/* Crystal+ port#0 bypass transition */
		if (ha->task_daemon_flags & HANDLE_PORT_BYPASS_CHANGE) {
			ha->task_daemon_flags &= ~HANDLE_PORT_BYPASS_CHANGE;
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_initiate_lip(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = TRUE;
		}

		/* Abort queues needed. */
		if (ha->task_daemon_flags & ABORT_QUEUES_NEEDED) {
			ha->task_daemon_flags &= ~ABORT_QUEUES_NEEDED;
			TASK_DAEMON_UNLOCK(ha);
			ql_abort_queues(ha);
			TASK_DAEMON_LOCK(ha);
		}

		/* Not suspended, awaken waiting routines. */
		if (!(ha->task_daemon_flags & QL_SUSPENDED) &&
		    ha->task_daemon_flags & SUSPENDED_WAKEUP_FLG) {
			ha->task_daemon_flags &= ~SUSPENDED_WAKEUP_FLG;
			cv_broadcast(&ha->cv_dr_suspended);
			loop_again = TRUE;
		}

		/* Handle RSCN changes. */
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			if (vha->task_daemon_flags & RSCN_UPDATE_NEEDED) {
				vha->task_daemon_flags &= ~RSCN_UPDATE_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
				(void) ql_handle_rscn_update(vha);
				TASK_DAEMON_LOCK(ha);
				loop_again = TRUE;
			}
		}

		/* Handle state changes. */
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			if (vha->task_daemon_flags & FC_STATE_CHANGE &&
			    !(ha->task_daemon_flags &
			    TASK_DAEMON_POWERING_DOWN)) {
				/* Report state change. */
				EL(vha, "state change = %xh\n", vha->state);
				vha->task_daemon_flags &= ~FC_STATE_CHANGE;

				if (vha->task_daemon_flags &
				    COMMAND_WAIT_NEEDED) {
					vha->task_daemon_flags &=
					    ~COMMAND_WAIT_NEEDED;
					if (!(ha->task_daemon_flags &
					    COMMAND_WAIT_ACTIVE)) {
						ha->task_daemon_flags |=
						    COMMAND_WAIT_ACTIVE;
						TASK_DAEMON_UNLOCK(ha);
						ql_cmd_wait(ha);
						TASK_DAEMON_LOCK(ha);
						ha->task_daemon_flags &=
						    ~COMMAND_WAIT_ACTIVE;
					}
				}

				msg = NULL;
				if (FC_PORT_STATE_MASK(vha->state) ==
				    FC_STATE_OFFLINE) {
					if (vha->task_daemon_flags &
					    STATE_ONLINE) {
						if (ha->topology &
						    QL_LOOP_CONNECTION) {
							msg = "Loop OFFLINE";
						} else {
							msg = "Link OFFLINE";
						}
					}
					vha->task_daemon_flags &=
					    ~STATE_ONLINE;
				} else if (FC_PORT_STATE_MASK(vha->state) ==
				    FC_STATE_LOOP) {
					if (!(vha->task_daemon_flags &
					    STATE_ONLINE)) {
						msg = "Loop ONLINE";
					}
					vha->task_daemon_flags |= STATE_ONLINE;
				} else if (FC_PORT_STATE_MASK(vha->state) ==
				    FC_STATE_ONLINE) {
					if (!(vha->task_daemon_flags &
					    STATE_ONLINE)) {
						msg = "Link ONLINE";
					}
					vha->task_daemon_flags |= STATE_ONLINE;
				} else {
					msg = "Unknown Link state";
				}

				if (msg != NULL) {
					cmn_err(CE_NOTE, "!Qlogic %s(%d,%d): "
					    "%s", QL_NAME, ha->instance,
					    vha->vp_index, msg);
				}

				if (vha->flags & FCA_BOUND) {
					QL_PRINT_10(CE_CONT, "(%d,%d): statec_"
					    "cb state=%xh\n", ha->instance,
					    vha->vp_index, vha->state);
					TASK_DAEMON_UNLOCK(ha);
					(vha->bind_info.port_statec_cb)
					    (vha->bind_info.port_handle,
					    vha->state);
					TASK_DAEMON_LOCK(ha);
				}
				loop_again = TRUE;
			}
		}

		if (ha->task_daemon_flags & LIP_RESET_PENDING &&
		    !(ha->task_daemon_flags & TASK_DAEMON_POWERING_DOWN)) {
			EL(ha, "processing LIP reset\n");
			ha->task_daemon_flags &= ~LIP_RESET_PENDING;
			TASK_DAEMON_UNLOCK(ha);
			for (vha = ha; vha != NULL; vha = vha->vp_next) {
				if (vha->flags & FCA_BOUND) {
					QL_PRINT_10(CE_CONT, "(%d,%d): statec_"
					    "cb reset\n", ha->instance,
					    vha->vp_index);
					(vha->bind_info.port_statec_cb)
					    (vha->bind_info.port_handle,
					    FC_STATE_TARGET_PORT_RESET);
				}
			}
			TASK_DAEMON_LOCK(ha);
			loop_again = TRUE;
		}

		if (QL_IS_SET(ha->task_daemon_flags, NEED_UNSOLICITED_BUFFERS |
		    FIRMWARE_UP)) {
			/*
			 * The firmware needs more unsolicited
			 * buffers. We cannot allocate any new
			 * buffers unless the ULP module requests
			 * for new buffers. All we can do here is
			 * to give received buffers from the pool
			 * that is already allocated
			 */
			ha->task_daemon_flags &= ~NEED_UNSOLICITED_BUFFERS;
			TASK_DAEMON_UNLOCK(ha);
			ql_isp_rcvbuf(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = TRUE;
		}

		if (ha->task_daemon_flags & ISP_ABORT_NEEDED) {
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_abort_isp(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = TRUE;
		}

		if (!(ha->task_daemon_flags & (LOOP_DOWN | DRIVER_STALL |
		    COMMAND_WAIT_NEEDED))) {
			if (QL_IS_SET(ha->task_daemon_flags,
			    RESET_MARKER_NEEDED | FIRMWARE_UP)) {
				ha->task_daemon_flags &= ~RESET_MARKER_NEEDED;
				if (!(ha->task_daemon_flags & RESET_ACTIVE)) {
					ha->task_daemon_flags |= RESET_ACTIVE;
					TASK_DAEMON_UNLOCK(ha);
					for (vha = ha; vha != NULL;
					    vha = vha->vp_next) {
						ql_rst_aen(vha);
					}
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags &= ~RESET_ACTIVE;
					loop_again = TRUE;
				}
			}

			if (QL_IS_SET(ha->task_daemon_flags,
			    LOOP_RESYNC_NEEDED | FIRMWARE_UP)) {
				if (!(ha->task_daemon_flags &
				    LOOP_RESYNC_ACTIVE)) {
					ha->task_daemon_flags |=
					    LOOP_RESYNC_ACTIVE;
					TASK_DAEMON_UNLOCK(ha);
					(void) ql_loop_resync(ha);
					TASK_DAEMON_LOCK(ha);
					loop_again = TRUE;
				}
			}
		}

		/* Port retry needed. */
		if (ha->task_daemon_flags & PORT_RETRY_NEEDED) {
			ha->task_daemon_flags &= ~PORT_RETRY_NEEDED;
			ADAPTER_STATE_LOCK(ha);
			ha->port_retry_timer = 0;
			ADAPTER_STATE_UNLOCK(ha);

			TASK_DAEMON_UNLOCK(ha);
			ql_restart_queues(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		/* iiDMA setting needed? */
		if (ha->task_daemon_flags & TD_IIDMA_NEEDED) {
			ha->task_daemon_flags &= ~TD_IIDMA_NEEDED;

			TASK_DAEMON_UNLOCK(ha);
			ql_iidma(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		if (ha->task_daemon_flags & SEND_PLOGI) {
			ha->task_daemon_flags &= ~SEND_PLOGI;
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_n_port_plogi(ha);
			TASK_DAEMON_LOCK(ha);
		}

		head = &ha->callback_queue;
		if (head->first != NULL) {
			sp = head->first->base_address;
			link = &sp->cmd;

			/* Dequeue command. */
			ql_remove_link(head, link);

			/* Release task daemon lock. */
			TASK_DAEMON_UNLOCK(ha);

			/* Do callback. */
			if (sp->flags & SRB_UB_CALLBACK) {
				ql_unsol_callback(sp);
			} else {
				(*sp->pkt->pkt_comp)(sp->pkt);
			}

			/* Acquire task daemon lock. */
			TASK_DAEMON_LOCK(ha);

			loop_again = TRUE;
		}

	} while (loop_again);
}

/*
 * ql_idle_check
 *	Test for adapter is alive and well.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_idle_check(ql_adapter_state_t *ha)
{
	ddi_devstate_t	state;
	int		rval;
	ql_mbx_data_t	mr;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Firmware Ready Test. */
	rval = ql_get_firmware_state(ha, &mr);
	if (!(ha->task_daemon_flags & QL_SUSPENDED) &&
	    (rval != QL_SUCCESS || mr.mb[1] != FSTATE_READY)) {
		EL(ha, "failed, Firmware Ready Test = %xh\n", rval);
		state = ddi_get_devstate(ha->dip);
		if (state == DDI_DEVSTATE_UP) {
			/*EMPTY*/
			ddi_dev_report_fault(ha->dip, DDI_SERVICE_DEGRADED,
			    DDI_DEVICE_FAULT, "Firmware Ready Test failed");
		}
		TASK_DAEMON_LOCK(ha);
		if (!(ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
			EL(ha, "fstate_ready, isp_abort_needed\n");
			ha->task_daemon_flags |= ISP_ABORT_NEEDED;
		}
		TASK_DAEMON_UNLOCK(ha);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_unsol_callback
 *	Handle unsolicited buffer callbacks.
 *
 * Input:
 *	ha = adapter state pointer.
 *	sp = srb pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_unsol_callback(ql_srb_t *sp)
{
	fc_affected_id_t	*af;
	fc_unsol_buf_t		*ubp;
	uchar_t			r_ctl;
	uchar_t			ls_code;
	ql_tgt_t		*tq;
	ql_adapter_state_t	*ha = sp->ha, *pha = sp->ha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	ubp = ha->ub_array[sp->handle];
	r_ctl = ubp->ub_frame.r_ctl;
	ls_code = ubp->ub_buffer[0];

	if (sp->lun_queue == NULL) {
		tq = NULL;
	} else {
		tq = sp->lun_queue->target_queue;
	}

	QL_UB_LOCK(ha);
	if (sp->flags & SRB_UB_FREE_REQUESTED ||
	    pha->task_daemon_flags & TASK_DAEMON_POWERING_DOWN) {
		sp->flags &= ~(SRB_UB_IN_ISP | SRB_UB_CALLBACK |
		    SRB_UB_RSCN | SRB_UB_FCP | SRB_UB_ACQUIRED);
		sp->flags |= SRB_UB_IN_FCA;
		QL_UB_UNLOCK(ha);
		return;
	}

	/* Process RSCN */
	if (sp->flags & SRB_UB_RSCN) {
		int sendup = 1;

		/*
		 * Defer RSCN posting until commands return
		 */
		QL_UB_UNLOCK(ha);

		af = (fc_affected_id_t *)((caddr_t)ubp->ub_buffer + 4);

		/* Abort outstanding commands */
		sendup = ql_process_rscn(ha, af);
		if (sendup == 0) {

			TASK_DAEMON_LOCK(ha);
			ql_add_link_b(&pha->callback_queue, &sp->cmd);
			TASK_DAEMON_UNLOCK(ha);

			/*
			 * Wait for commands to drain in F/W (doesn't take
			 * more than a few milliseconds)
			 */
			ql_delay(ha, 10000);

			QL_PRINT_2(CE_CONT, "(%d,%d): done rscn_sendup=0, "
			    "fmt=%xh, d_id=%xh\n", ha->instance, ha->vp_index,
			    af->aff_format, af->aff_d_id);
			return;
		}

		QL_UB_LOCK(ha);

		EL(ha, "sending unsol rscn, fmt=%xh, d_id=%xh to transport\n",
		    af->aff_format, af->aff_d_id);
	}

	/* Process UNSOL LOGO */
	if ((r_ctl == R_CTL_ELS_REQ) && (ls_code == LA_ELS_LOGO)) {
		QL_UB_UNLOCK(ha);

		if (tq && (ql_process_logo_for_device(ha, tq) == 0)) {
			TASK_DAEMON_LOCK(ha);
			ql_add_link_b(&pha->callback_queue, &sp->cmd);
			TASK_DAEMON_UNLOCK(ha);
			QL_PRINT_2(CE_CONT, "(%d,%d): logo_sendup=0, d_id=%xh"
			    "\n", ha->instance, ha->vp_index, tq->d_id.b24);
			return;
		}

		QL_UB_LOCK(ha);
		EL(ha, "sending unsol logout for %xh to transport\n",
		    ubp->ub_frame.s_id);
	}

	sp->flags &= ~(SRB_UB_IN_FCA | SRB_UB_IN_ISP | SRB_UB_RSCN |
	    SRB_UB_FCP);

	if (sp->ub_type == FC_TYPE_IS8802_SNAP) {
		(void) ddi_dma_sync(sp->ub_buffer.dma_handle, 0,
		    ubp->ub_bufsize, DDI_DMA_SYNC_FORCPU);
	}
	QL_UB_UNLOCK(ha);

	(ha->bind_info.port_unsol_cb)(ha->bind_info.port_handle,
	    ubp, sp->ub_type);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_send_logo
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	done_q:	done queue pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_send_logo(ql_adapter_state_t *vha, ql_tgt_t *tq, ql_head_t *done_q)
{
	fc_unsol_buf_t		*ubp;
	ql_srb_t		*sp;
	la_els_logo_t		*payload;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh\n", ha->instance,
	    tq->d_id.b24);

	if ((tq->d_id.b24 == 0) || (tq->d_id.b24 == 0xffffff)) {
		EL(ha, "no device, d_id=%xh\n", tq->d_id.b24);
		return;
	}

	if ((tq->flags & (TQF_RSCN_RCVD | TQF_PLOGI_PROGRS)) == 0 &&
	    tq->logout_sent == 0 && (ha->task_daemon_flags & LOOP_DOWN) == 0) {

		/* Locate a buffer to use. */
		ubp = ql_get_unsolicited_buffer(vha, FC_TYPE_EXTENDED_LS);
		if (ubp == NULL) {
			EL(vha, "Failed, get_unsolicited_buffer\n");
			return;
		}

		DEVICE_QUEUE_LOCK(tq);
		tq->flags |= TQF_NEED_AUTHENTICATION;
		tq->logout_sent++;
		DEVICE_QUEUE_UNLOCK(tq);

		EL(vha, "Received LOGO from = %xh\n", tq->d_id.b24);

		sp = ubp->ub_fca_private;

		/* Set header. */
		ubp->ub_frame.d_id = vha->d_id.b24;
		ubp->ub_frame.r_ctl = R_CTL_ELS_REQ;
		ubp->ub_frame.s_id = tq->d_id.b24;
		ubp->ub_frame.rsvd = 0;
		ubp->ub_frame.f_ctl = F_CTL_FIRST_SEQ | F_CTL_END_SEQ |
		    F_CTL_SEQ_INITIATIVE;
		ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
		ubp->ub_frame.seq_cnt = 0;
		ubp->ub_frame.df_ctl = 0;
		ubp->ub_frame.seq_id = 0;
		ubp->ub_frame.rx_id = 0xffff;
		ubp->ub_frame.ox_id = 0xffff;

		/* set payload. */
		payload = (la_els_logo_t *)ubp->ub_buffer;
		bzero(payload, sizeof (la_els_logo_t));
		/* Make sure ls_code in payload is always big endian */
		ubp->ub_buffer[0] = LA_ELS_LOGO;
		ubp->ub_buffer[1] = 0;
		ubp->ub_buffer[2] = 0;
		ubp->ub_buffer[3] = 0;
		bcopy(&vha->loginparams.node_ww_name.raw_wwn[0],
		    &payload->nport_ww_name.raw_wwn[0], 8);
		payload->nport_id.port_id = tq->d_id.b24;

		QL_UB_LOCK(ha);
		sp->flags |= SRB_UB_CALLBACK;
		QL_UB_UNLOCK(ha);
		if (tq->lun_queues.first != NULL) {
			sp->lun_queue = (tq->lun_queues.first)->base_address;
		} else {
			sp->lun_queue = ql_lun_queue(vha, tq, 0);
		}
		if (done_q) {
			ql_add_link_b(done_q, &sp->cmd);
		} else {
			ql_awaken_task_daemon(ha, sp, 0, 0);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

static int
ql_process_logo_for_device(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	port_id_t	d_id;
	ql_srb_t	*sp;
	ql_link_t	*link;
	int		sendup = 1;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	DEVICE_QUEUE_LOCK(tq);
	if (tq->outcnt) {
		DEVICE_QUEUE_UNLOCK(tq);
		sendup = 0;
		(void) ql_abort_device(ha, tq, 1);
		ql_delay(ha, 10000);
	} else {
		DEVICE_QUEUE_UNLOCK(tq);
		TASK_DAEMON_LOCK(ha);

		for (link = ha->pha->callback_queue.first; link != NULL;
		    link = link->next) {
			sp = link->base_address;
			if (sp->flags & SRB_UB_CALLBACK) {
				continue;
			}
			d_id.b24 = sp->pkt->pkt_cmd_fhdr.d_id;

			if (tq->d_id.b24 == d_id.b24) {
				sendup = 0;
				break;
			}
		}

		TASK_DAEMON_UNLOCK(ha);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (sendup);
}

static int
ql_send_plogi(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_head_t *done_q)
{
	fc_unsol_buf_t		*ubp;
	ql_srb_t		*sp;
	la_els_logi_t		*payload;
	class_svc_param_t	*class3_param;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((tq->flags & TQF_RSCN_RCVD) || (ha->task_daemon_flags &
	    LOOP_DOWN)) {
		EL(ha, "Failed, tqf=%xh\n", tq->flags);
		return (QL_FUNCTION_FAILED);
	}

	/* Locate a buffer to use. */
	ubp = ql_get_unsolicited_buffer(ha, FC_TYPE_EXTENDED_LS);
	if (ubp == NULL) {
		EL(ha, "Failed\n");
		return (QL_FUNCTION_FAILED);
	}

	QL_PRINT_3(CE_CONT, "(%d): Received LOGO from = %xh\n",
	    ha->instance, tq->d_id.b24);

	EL(ha, "Emulate PLOGI from = %xh tq = %x\n", tq->d_id.b24, tq);

	sp = ubp->ub_fca_private;

	/* Set header. */
	ubp->ub_frame.d_id = ha->d_id.b24;
	ubp->ub_frame.r_ctl = R_CTL_ELS_REQ;
	ubp->ub_frame.s_id = tq->d_id.b24;
	ubp->ub_frame.rsvd = 0;
	ubp->ub_frame.f_ctl = F_CTL_FIRST_SEQ | F_CTL_END_SEQ |
	    F_CTL_SEQ_INITIATIVE;
	ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
	ubp->ub_frame.seq_cnt = 0;
	ubp->ub_frame.df_ctl = 0;
	ubp->ub_frame.seq_id = 0;
	ubp->ub_frame.rx_id = 0xffff;
	ubp->ub_frame.ox_id = 0xffff;

	/* set payload. */
	payload = (la_els_logi_t *)ubp->ub_buffer;
	bzero(payload, sizeof (payload));

	payload->ls_code.ls_code = LA_ELS_PLOGI;
	payload->common_service.fcph_version = 0x2006;
	payload->common_service.cmn_features = 0x8800;

	CFG_IST(ha, CFG_CTRL_24258081) ?
	    (payload->common_service.rx_bufsize = CHAR_TO_SHORT(
	    ha->init_ctrl_blk.cb24.max_frame_length[0],
	    ha->init_ctrl_blk.cb24.max_frame_length[1])) :
	    (payload->common_service.rx_bufsize = CHAR_TO_SHORT(
	    ha->init_ctrl_blk.cb.max_frame_length[0],
	    ha->init_ctrl_blk.cb.max_frame_length[1]));

	payload->common_service.conc_sequences = 0xff;
	payload->common_service.relative_offset = 0x03;
	payload->common_service.e_d_tov = 0x7d0;

	bcopy((void *)&tq->port_name[0],
	    (void *)&payload->nport_ww_name.raw_wwn[0], 8);

	bcopy((void *)&tq->node_name[0],
	    (void *)&payload->node_ww_name.raw_wwn[0], 8);

	class3_param = (class_svc_param_t *)&payload->class_3;
	class3_param->class_valid_svc_opt = 0x8000;
	class3_param->recipient_ctl = tq->class3_recipient_ctl;
	class3_param->rcv_data_size = tq->class3_rcv_data_size;
	class3_param->conc_sequences = tq->class3_conc_sequences;
	class3_param->open_sequences_per_exch =
	    tq->class3_open_sequences_per_exch;

	QL_UB_LOCK(ha);
	sp->flags |= SRB_UB_CALLBACK;
	QL_UB_UNLOCK(ha);

	ql_isp_els_handle_endian(ha, (uint8_t *)payload, LA_ELS_PLOGI);

	if (done_q) {
		ql_add_link_b(done_q, &sp->cmd);
	} else {
		ql_awaken_task_daemon(ha, sp, 0, 0);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (QL_SUCCESS);
}

/*
 * Abort outstanding commands in the Firmware, clear internally
 * queued commands in the driver, Synchronize the target with
 * the Firmware
 */
int
ql_abort_device(ql_adapter_state_t *ha, ql_tgt_t *tq, int drain)
{
	ql_link_t	*link, *link2;
	ql_lun_t	*lq;
	int		rval = QL_SUCCESS;
	ql_srb_t	*sp;
	ql_head_t	done_q = { NULL, NULL };

	QL_PRINT_10(CE_CONT, "(%d,%d): started\n", ha->instance, ha->vp_index);

	/*
	 * First clear, internally queued commands
	 */
	DEVICE_QUEUE_LOCK(tq);
	for (link = tq->lun_queues.first; link != NULL; link = link->next) {
		lq = link->base_address;

		link2 = lq->cmd.first;
		while (link2 != NULL) {
			sp = link2->base_address;
			link2 = link2->next;

			if (sp->flags & SRB_ABORT) {
				continue;
			}

			/* Remove srb from device command queue. */
			ql_remove_link(&lq->cmd, &sp->cmd);
			sp->flags &= ~SRB_IN_DEVICE_QUEUE;

			/* Set ending status. */
			sp->pkt->pkt_reason = CS_ABORTED;

			/* Call done routine to handle completions. */
			ql_add_link_b(&done_q, &sp->cmd);
		}
	}
	DEVICE_QUEUE_UNLOCK(tq);

	if (done_q.first != NULL) {
		ql_done(done_q.first);
	}

	if (drain && VALID_TARGET_ID(ha, tq->loop_id) && PD_PORT_LOGIN(tq)) {
		rval = ql_abort_target(ha, tq, 0);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_10(CE_CONT, "(%d,%d): done\n", ha->instance,
		    ha->vp_index);
	}

	return (rval);
}

/*
 * ql_rcv_rscn_els
 *	Processes received RSCN extended link service.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mb:	array containing input mailbox registers.
 *	done_q:	done queue pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_rcv_rscn_els(ql_adapter_state_t *ha, uint16_t *mb, ql_head_t *done_q)
{
	fc_unsol_buf_t		*ubp;
	ql_srb_t		*sp;
	fc_rscn_t		*rn;
	fc_affected_id_t	*af;
	port_id_t		d_id;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Locate a buffer to use. */
	ubp = ql_get_unsolicited_buffer(ha, FC_TYPE_EXTENDED_LS);
	if (ubp != NULL) {
		sp = ubp->ub_fca_private;

		/* Set header. */
		ubp->ub_frame.d_id = ha->d_id.b24;
		ubp->ub_frame.r_ctl = R_CTL_ELS_REQ;
		ubp->ub_frame.s_id = FS_FABRIC_CONTROLLER;
		ubp->ub_frame.rsvd = 0;
		ubp->ub_frame.f_ctl = F_CTL_FIRST_SEQ | F_CTL_END_SEQ |
		    F_CTL_SEQ_INITIATIVE;
		ubp->ub_frame.type = FC_TYPE_EXTENDED_LS;
		ubp->ub_frame.seq_cnt = 0;
		ubp->ub_frame.df_ctl = 0;
		ubp->ub_frame.seq_id = 0;
		ubp->ub_frame.rx_id = 0xffff;
		ubp->ub_frame.ox_id = 0xffff;

		/* set payload. */
		rn = (fc_rscn_t *)ubp->ub_buffer;
		af = (fc_affected_id_t *)((caddr_t)ubp->ub_buffer + 4);

		rn->rscn_code = LA_ELS_RSCN;
		rn->rscn_len = 4;
		rn->rscn_payload_len = 8;
		d_id.b.al_pa = LSB(mb[2]);
		d_id.b.area = MSB(mb[2]);
		d_id.b.domain =	LSB(mb[1]);
		af->aff_d_id = d_id.b24;
		af->aff_format = MSB(mb[1]);

		EL(ha, "LA_ELS_RSCN fmt=%xh, d_id=%xh\n", af->aff_format,
		    af->aff_d_id);

		ql_update_rscn(ha, af);

		QL_UB_LOCK(ha);
		sp->flags |= SRB_UB_CALLBACK | SRB_UB_RSCN;
		QL_UB_UNLOCK(ha);
		ql_add_link_b(done_q, &sp->cmd);
	}

	if (ubp == NULL) {
		EL(ha, "Failed, get_unsolicited_buffer\n");
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
}

/*
 * ql_update_rscn
 *	Update devices from received RSCN.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	af:	pointer to RSCN data.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_update_rscn(ql_adapter_state_t *ha, fc_affected_id_t *af)
{
	ql_link_t	*link;
	uint16_t	index;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (af->aff_format == FC_RSCN_PORT_ADDRESS) {
		port_id_t d_id;

		d_id.r.rsvd_1 = 0;
		d_id.b24 = af->aff_d_id;

		tq = ql_d_id_to_queue(ha, d_id);
		if (tq) {
			EL(ha, "SD_RSCN_RCVD %xh RPA\n", d_id.b24);
			DEVICE_QUEUE_LOCK(tq);
			tq->flags |= TQF_RSCN_RCVD;
			DEVICE_QUEUE_UNLOCK(tq);
		}
		QL_PRINT_3(CE_CONT, "(%d): FC_RSCN_PORT_ADDRESS done\n",
		    ha->instance);

		return;
	}

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			switch (af->aff_format) {
			case FC_RSCN_FABRIC_ADDRESS:
				if (!RESERVED_LOOP_ID(ha, tq->loop_id)) {
					EL(ha, "SD_RSCN_RCVD %xh RFA\n",
					    tq->d_id.b24);
					DEVICE_QUEUE_LOCK(tq);
					tq->flags |= TQF_RSCN_RCVD;
					DEVICE_QUEUE_UNLOCK(tq);
				}
				break;

			case FC_RSCN_AREA_ADDRESS:
				if ((tq->d_id.b24 & 0xffff00) == af->aff_d_id) {
					EL(ha, "SD_RSCN_RCVD %xh RAA\n",
					    tq->d_id.b24);
					DEVICE_QUEUE_LOCK(tq);
					tq->flags |= TQF_RSCN_RCVD;
					DEVICE_QUEUE_UNLOCK(tq);
				}
				break;

			case FC_RSCN_DOMAIN_ADDRESS:
				if ((tq->d_id.b24 & 0xff0000) == af->aff_d_id) {
					EL(ha, "SD_RSCN_RCVD %xh RDA\n",
					    tq->d_id.b24);
					DEVICE_QUEUE_LOCK(tq);
					tq->flags |= TQF_RSCN_RCVD;
					DEVICE_QUEUE_UNLOCK(tq);
				}
				break;

			default:
				break;
			}
		}
	}
	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_process_rscn
 *
 * Input:
 *	ha:	adapter state pointer.
 *	af:	RSCN payload pointer.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_process_rscn(ql_adapter_state_t *ha, fc_affected_id_t *af)
{
	int		sendit;
	int		sendup = 1;
	ql_link_t	*link;
	uint16_t	index;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (af->aff_format == FC_RSCN_PORT_ADDRESS) {
		port_id_t d_id;

		d_id.r.rsvd_1 = 0;
		d_id.b24 = af->aff_d_id;

		tq = ql_d_id_to_queue(ha, d_id);
		if (tq) {
			sendup = ql_process_rscn_for_device(ha, tq);
		}

		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

		return (sendup);
	}

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {

			tq = link->base_address;
			if (tq == NULL) {
				continue;
			}

			switch (af->aff_format) {
			case FC_RSCN_FABRIC_ADDRESS:
				if (!RESERVED_LOOP_ID(ha, tq->loop_id)) {
					sendit = ql_process_rscn_for_device(
					    ha, tq);
					if (sendup) {
						sendup = sendit;
					}
				}
				break;

			case FC_RSCN_AREA_ADDRESS:
				if ((tq->d_id.b24 & 0xffff00) ==
				    af->aff_d_id) {
					sendit = ql_process_rscn_for_device(
					    ha, tq);

					if (sendup) {
						sendup = sendit;
					}
				}
				break;

			case FC_RSCN_DOMAIN_ADDRESS:
				if ((tq->d_id.b24 & 0xff0000) ==
				    af->aff_d_id) {
					sendit = ql_process_rscn_for_device(
					    ha, tq);

					if (sendup) {
						sendup = sendit;
					}
				}
				break;

			default:
				break;
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (sendup);
}

/*
 * ql_process_rscn_for_device
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_process_rscn_for_device(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	int sendup = 1;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	DEVICE_QUEUE_LOCK(tq);

	/*
	 * Let FCP-2 compliant devices continue I/Os
	 * with their low level recoveries.
	 */
	if (((tq->flags & TQF_INITIATOR_DEVICE) == 0) &&
	    (tq->prli_svc_param_word_3 & PRLI_W3_RETRY)) {
		/*
		 * Cause ADISC to go out
		 */
		DEVICE_QUEUE_UNLOCK(tq);

		(void) ql_get_port_database(ha, tq, PDF_NONE);

		DEVICE_QUEUE_LOCK(tq);
		tq->flags &= ~TQF_RSCN_RCVD;

	} else if (tq->loop_id != PORT_NO_LOOP_ID) {
		if (tq->d_id.b24 != BROADCAST_ADDR) {
			tq->flags |= TQF_NEED_AUTHENTICATION;
		}

		DEVICE_QUEUE_UNLOCK(tq);

		(void) ql_abort_device(ha, tq, 1);

		DEVICE_QUEUE_LOCK(tq);

		if (tq->outcnt) {
			sendup = 0;
		} else {
			tq->flags &= ~TQF_RSCN_RCVD;
		}
	} else {
		tq->flags &= ~TQF_RSCN_RCVD;
	}

	if (sendup) {
		if (tq->d_id.b24 != BROADCAST_ADDR) {
			tq->flags |= TQF_NEED_AUTHENTICATION;
		}
	}

	DEVICE_QUEUE_UNLOCK(tq);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (sendup);
}

static int
ql_handle_rscn_update(ql_adapter_state_t *ha)
{
	int			rval;
	ql_tgt_t		*tq;
	uint16_t		index, loop_id;
	ql_dev_id_list_t	*list;
	uint32_t		list_size;
	port_id_t		d_id;
	ql_mbx_data_t		mr;
	ql_head_t		done_q = { NULL, NULL };

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	list_size = sizeof (ql_dev_id_list_t) * DEVICE_LIST_ENTRIES;
	list = kmem_zalloc(list_size, KM_SLEEP);
	if (list == NULL) {
		rval = QL_MEMORY_ALLOC_FAILED;
		EL(ha, "kmem_zalloc failed=%xh\n", rval);
		return (rval);
	}

	/*
	 * Get data from RISC code d_id list to init each device queue.
	 */
	rval = ql_get_id_list(ha, (caddr_t)list, list_size, &mr);
	if (rval != QL_SUCCESS) {
		kmem_free(list, list_size);
		EL(ha, "get_id_list failed=%xh\n", rval);
		return (rval);
	}

	/* Acquire adapter state lock. */
	ADAPTER_STATE_LOCK(ha);

	/* Check for new devices */
	for (index = 0; index < mr.mb[1]; index++) {
		ql_dev_list(ha, list, index, &d_id, &loop_id);

		if (VALID_DEVICE_ID(ha, loop_id)) {
			d_id.r.rsvd_1 = 0;

			tq = ql_d_id_to_queue(ha, d_id);
			if (tq != NULL) {
				continue;
			}

			tq = ql_dev_init(ha, d_id, loop_id);

			/* Test for fabric device. */
			if (d_id.b.domain != ha->d_id.b.domain ||
			    d_id.b.area != ha->d_id.b.area) {
				tq->flags |= TQF_FABRIC_DEVICE;
			}

			ADAPTER_STATE_UNLOCK(ha);
			if (ql_get_port_database(ha, tq, PDF_NONE) !=
			    QL_SUCCESS) {
				tq->loop_id = PORT_NO_LOOP_ID;
			}
			ADAPTER_STATE_LOCK(ha);

			/*
			 * Send up a PLOGI about the new device
			 */
			if (VALID_DEVICE_ID(ha, tq->loop_id)) {
				(void) ql_send_plogi(ha, tq, &done_q);
			}
		}
	}

	/* Release adapter state lock. */
	ADAPTER_STATE_UNLOCK(ha);

	if (done_q.first != NULL) {
		ql_done(done_q.first);
	}

	kmem_free(list, list_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_free_unsolicited_buffer
 *	Frees allocated buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	index = buffer array index.
 *	ADAPTER_STATE_LOCK must be already obtained.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_free_unsolicited_buffer(ql_adapter_state_t *ha, fc_unsol_buf_t *ubp)
{
	ql_srb_t	*sp;
	int		status;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	sp = ubp->ub_fca_private;
	if (sp->ub_type == FC_TYPE_IS8802_SNAP) {
		/* Disconnect IP from system buffers. */
		if (ha->flags & IP_INITIALIZED) {
			ADAPTER_STATE_UNLOCK(ha);
			status = ql_shutdown_ip(ha);
			ADAPTER_STATE_LOCK(ha);
			if (status != QL_SUCCESS) {
				cmn_err(CE_WARN,
				    "!Qlogic %s(%d): Failed to shutdown IP",
				    QL_NAME, ha->instance);
				return;
			}

			ha->flags &= ~IP_ENABLED;
		}

		ql_free_phys(ha, &sp->ub_buffer);
	} else {
		kmem_free(ubp->ub_buffer, ubp->ub_bufsize);
	}

	kmem_free(sp, sizeof (ql_srb_t));
	kmem_free(ubp, sizeof (fc_unsol_buf_t));

	if (ha->ub_allocated != 0) {
		ha->ub_allocated--;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_get_unsolicited_buffer
 *	Locates a free unsolicited buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	type = buffer type.
 *
 * Returns:
 *	Unsolicited buffer pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
fc_unsol_buf_t *
ql_get_unsolicited_buffer(ql_adapter_state_t *ha, uint32_t type)
{
	fc_unsol_buf_t	*ubp;
	ql_srb_t	*sp;
	uint16_t	index;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Locate a buffer to use. */
	ubp = NULL;

	QL_UB_LOCK(ha);
	for (index = 0; index < QL_UB_LIMIT; index++) {
		ubp = ha->ub_array[index];
		if (ubp != NULL) {
			sp = ubp->ub_fca_private;
			if ((sp->ub_type == type) &&
			    (sp->flags & SRB_UB_IN_FCA) &&
			    (!(sp->flags & (SRB_UB_CALLBACK |
			    SRB_UB_FREE_REQUESTED | SRB_UB_ACQUIRED)))) {
				sp->flags |= SRB_UB_ACQUIRED;
				ubp->ub_resp_flags = 0;
				break;
			}
			ubp = NULL;
		}
	}
	QL_UB_UNLOCK(ha);

	if (ubp) {
		ubp->ub_resp_token = NULL;
		ubp->ub_class = FC_TRAN_CLASS3;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (ubp);
}

/*
 * ql_ub_frame_hdr
 *	Processes received unsolicited buffers from ISP.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	index:	unsolicited buffer array index.
 *	done_q:	done queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
int
ql_ub_frame_hdr(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t index,
    ql_head_t *done_q)
{
	fc_unsol_buf_t	*ubp;
	ql_srb_t	*sp;
	uint16_t	loop_id;
	int		rval = QL_FUNCTION_FAILED;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	QL_UB_LOCK(ha);
	if (index >= QL_UB_LIMIT || (ubp = ha->ub_array[index]) == NULL) {
		EL(ha, "Invalid buffer index=%xh\n", index);
		QL_UB_UNLOCK(ha);
		return (rval);
	}

	sp = ubp->ub_fca_private;
	if (sp->flags & SRB_UB_FREE_REQUESTED) {
		EL(ha, "buffer freed index=%xh\n", index);
		sp->flags &= ~(SRB_UB_IN_ISP | SRB_UB_CALLBACK |
		    SRB_UB_RSCN | SRB_UB_FCP | SRB_UB_ACQUIRED);

		sp->flags |= SRB_UB_IN_FCA;

		QL_UB_UNLOCK(ha);
		return (rval);
	}

	if ((sp->handle == index) &&
	    (sp->flags & SRB_UB_IN_ISP) &&
	    (sp->ub_type == FC_TYPE_IS8802_SNAP) &&
	    (!(sp->flags & SRB_UB_ACQUIRED))) {
		/* set broadcast D_ID */
		loop_id = (uint16_t)(CFG_IST(ha, CFG_CTRL_24258081) ?
		    BROADCAST_24XX_HDL : IP_BROADCAST_LOOP_ID);
		if (tq->ub_loop_id == loop_id) {
			if (ha->topology & QL_FL_PORT) {
				ubp->ub_frame.d_id = 0x000000;
			} else {
				ubp->ub_frame.d_id = 0xffffff;
			}
		} else {
			ubp->ub_frame.d_id = ha->d_id.b24;
		}
		ubp->ub_frame.r_ctl = R_CTL_UNSOL_DATA;
		ubp->ub_frame.rsvd = 0;
		ubp->ub_frame.s_id = tq->d_id.b24;
		ubp->ub_frame.type = FC_TYPE_IS8802_SNAP;
		ubp->ub_frame.seq_cnt = tq->ub_seq_cnt;
		ubp->ub_frame.df_ctl = 0;
		ubp->ub_frame.seq_id = tq->ub_seq_id;
		ubp->ub_frame.rx_id = 0xffff;
		ubp->ub_frame.ox_id = 0xffff;
		ubp->ub_bufsize = sp->ub_size < tq->ub_sequence_length ?
		    sp->ub_size : tq->ub_sequence_length;
		ubp->ub_frame.ro = tq->ub_frame_ro;

		tq->ub_sequence_length = (uint16_t)
		    (tq->ub_sequence_length - ubp->ub_bufsize);
		tq->ub_frame_ro += ubp->ub_bufsize;
		tq->ub_seq_cnt++;

		if (tq->ub_seq_cnt == tq->ub_total_seg_cnt) {
			if (tq->ub_seq_cnt == 1) {
				ubp->ub_frame.f_ctl = F_CTL_RO_PRESENT |
				    F_CTL_FIRST_SEQ | F_CTL_END_SEQ;
			} else {
				ubp->ub_frame.f_ctl = F_CTL_RO_PRESENT |
				    F_CTL_END_SEQ;
			}
			tq->ub_total_seg_cnt = 0;
		} else if (tq->ub_seq_cnt == 1) {
			ubp->ub_frame.f_ctl = F_CTL_RO_PRESENT |
			    F_CTL_FIRST_SEQ;
			ubp->ub_frame.df_ctl = 0x20;
		}

		QL_PRINT_3(CE_CONT, "(%d): ub_frame.d_id=%xh\n",
		    ha->instance, ubp->ub_frame.d_id);
		QL_PRINT_3(CE_CONT, "(%d): ub_frame.s_id=%xh\n",
		    ha->instance, ubp->ub_frame.s_id);
		QL_PRINT_3(CE_CONT, "(%d): ub_frame.seq_cnt=%xh\n",
		    ha->instance, ubp->ub_frame.seq_cnt);
		QL_PRINT_3(CE_CONT, "(%d): ub_frame.seq_id=%xh\n",
		    ha->instance, ubp->ub_frame.seq_id);
		QL_PRINT_3(CE_CONT, "(%d): ub_frame.ro=%xh\n",
		    ha->instance, ubp->ub_frame.ro);
		QL_PRINT_3(CE_CONT, "(%d): ub_frame.f_ctl=%xh\n",
		    ha->instance, ubp->ub_frame.f_ctl);
		QL_PRINT_3(CE_CONT, "(%d): ub_bufsize=%xh\n",
		    ha->instance, ubp->ub_bufsize);
		QL_DUMP_3(ubp->ub_buffer, 8,
		    ubp->ub_bufsize < 64 ? ubp->ub_bufsize : 64);

		sp->flags |= SRB_UB_CALLBACK | SRB_UB_ACQUIRED;
		ql_add_link_b(done_q, &sp->cmd);
		rval = QL_SUCCESS;
	} else {
		if (sp->handle != index) {
			EL(ha, "Bad index=%xh, expect=%xh\n", index,
			    sp->handle);
		}
		if ((sp->flags & SRB_UB_IN_ISP) == 0) {
			EL(ha, "buffer was already in driver, index=%xh\n",
			    index);
		}
		if ((sp->ub_type == FC_TYPE_IS8802_SNAP) == 0) {
			EL(ha, "buffer was not an IP buffer, index=%xh\n",
			    index);
		}
		if (sp->flags & SRB_UB_ACQUIRED) {
			EL(ha, "buffer was being used by driver, index=%xh\n",
			    index);
		}
	}
	QL_UB_UNLOCK(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_timer
 *	One second timer function.
 *
 * Input:
 *	ql_hba.first = first link in adapter list.
 *
 * Context:
 *	Interrupt context, no mailbox commands allowed.
 */
static void
ql_timer(void *arg)
{
	ql_link_t		*link;
	uint32_t		set_flags;
	uint32_t		reset_flags;
	ql_adapter_state_t	*ha = NULL, *vha;

	QL_PRINT_6(CE_CONT, "started\n");

	/* Acquire global state lock. */
	GLOBAL_STATE_LOCK();
	if (ql_timer_timeout_id == NULL) {
		/* Release global state lock. */
		GLOBAL_STATE_UNLOCK();
		return;
	}

	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha = link->base_address;

		/* Skip adapter if suspended of stalled. */
		ADAPTER_STATE_LOCK(ha);
		if (ha->flags & ADAPTER_SUSPENDED ||
		    ha->task_daemon_flags & DRIVER_STALL) {
			ADAPTER_STATE_UNLOCK(ha);
			continue;
		}
		ha->flags |= ADAPTER_TIMER_BUSY;
		ADAPTER_STATE_UNLOCK(ha);

		QL_PM_LOCK(ha);
		if (ha->power_level != PM_LEVEL_D0) {
			QL_PM_UNLOCK(ha);

			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~ADAPTER_TIMER_BUSY;
			ADAPTER_STATE_UNLOCK(ha);
			continue;
		}
		ha->busy++;
		QL_PM_UNLOCK(ha);

		set_flags = 0;
		reset_flags = 0;

		/* Port retry timer handler. */
		if (LOOP_READY(ha)) {
			ADAPTER_STATE_LOCK(ha);
			if (ha->port_retry_timer != 0) {
				ha->port_retry_timer--;
				if (ha->port_retry_timer == 0) {
					set_flags |= PORT_RETRY_NEEDED;
				}
			}
			ADAPTER_STATE_UNLOCK(ha);
		}

		/* Loop down timer handler. */
		if (LOOP_RECONFIGURE(ha) == 0) {
			if (ha->loop_down_timer > LOOP_DOWN_TIMER_END) {
				ha->loop_down_timer--;
				/*
				 * give the firmware loop down dump flag
				 * a chance to work.
				 */
				if (ha->loop_down_timer == LOOP_DOWN_RESET) {
					if (CFG_IST(ha,
					    CFG_DUMP_LOOP_OFFLINE_TIMEOUT)) {
						(void) ql_binary_fw_dump(ha,
						    TRUE);
					}
					EL(ha, "loop_down_reset, "
					    "isp_abort_needed\n");
					set_flags |= ISP_ABORT_NEEDED;
				}
			}
			if (CFG_IST(ha, CFG_ENABLE_LINK_DOWN_REPORTING)) {
				/* Command abort time handler. */
				if (ha->loop_down_timer ==
				    ha->loop_down_abort_time) {
					ADAPTER_STATE_LOCK(ha);
					ha->flags |= ABORT_CMDS_LOOP_DOWN_TMO;
					ADAPTER_STATE_UNLOCK(ha);
					set_flags |= ABORT_QUEUES_NEEDED;
					EL(ha, "loop_down_abort_time, "
					    "abort_queues_needed\n");
				}

				/* Watchdog timer handler. */
				if (ha->watchdog_timer == 0) {
					ha->watchdog_timer = WATCHDOG_TIME;
				} else if (LOOP_READY(ha)) {
					ha->watchdog_timer--;
					if (ha->watchdog_timer == 0) {
						for (vha = ha; vha != NULL;
						    vha = vha->vp_next) {
							ql_watchdog(vha,
							    &set_flags,
							    &reset_flags);
						}
						ha->watchdog_timer =
						    WATCHDOG_TIME;
					}
				}
			}
		}

		/* Idle timer handler. */
		if (!DRIVER_SUSPENDED(ha)) {
			if (++ha->idle_timer >= IDLE_CHECK_TIMER) {
#if defined(QL_DEBUG_LEVEL_6) || !defined(QL_DEBUG_LEVEL_3)
				set_flags |= TASK_DAEMON_IDLE_CHK_FLG;
#endif
				ha->idle_timer = 0;
			}
			if (ha->send_plogi_timer != NULL) {
				ha->send_plogi_timer--;
				if (ha->send_plogi_timer == NULL) {
					set_flags |= SEND_PLOGI;
				}
			}
		}
		ADAPTER_STATE_LOCK(ha);
		if (ha->idc_restart_timer != 0) {
			ha->idc_restart_timer--;
			if (ha->idc_restart_timer == 0) {
				ha->idc_restart_cnt = 0;
				reset_flags |= DRIVER_STALL;
			}
		}
		if (ha->idc_flash_acc_timer != 0) {
			ha->idc_flash_acc_timer--;
			if (ha->idc_flash_acc_timer == 0 &&
			    ha->idc_flash_acc != 0) {
				ha->idc_flash_acc = 1;
				ha->idc_mb[0] = MBA_IDC_NOTIFICATION;
				ha->idc_mb[1] = 0;
				ha->idc_mb[2] = IDC_OPC_DRV_START;
				set_flags |= IDC_EVENT;
			}
		}
		ADAPTER_STATE_UNLOCK(ha);

		if (set_flags != 0 || reset_flags != 0) {
			ql_awaken_task_daemon(ha, NULL, set_flags,
			    reset_flags);
		}

		if (ha->xioctl->ledstate.BeaconState == BEACON_ON) {
			ql_blink_led(ha);
		}

		/* Update the IO stats */
		if (ha->xioctl->IOInputByteCnt >= 0x100000) {
			ha->xioctl->IOInputMByteCnt +=
			    (ha->xioctl->IOInputByteCnt / 0x100000);
			ha->xioctl->IOInputByteCnt %= 0x100000;
		}

		if (ha->xioctl->IOOutputByteCnt >= 0x100000) {
			ha->xioctl->IOOutputMByteCnt +=
			    (ha->xioctl->IOOutputByteCnt / 0x100000);
			ha->xioctl->IOOutputByteCnt %= 0x100000;
		}

		if (CFG_IST(ha, CFG_CTRL_8021)) {
			(void) ql_8021_idc_handler(ha);
		}

		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~ADAPTER_TIMER_BUSY;
		ADAPTER_STATE_UNLOCK(ha);

		QL_PM_LOCK(ha);
		ha->busy--;
		QL_PM_UNLOCK(ha);
	}

	/* Restart timer, if not being stopped. */
	if (ql_timer_timeout_id != NULL) {
		ql_timer_timeout_id = timeout(ql_timer, arg, ql_timer_ticks);
	}

	/* Release global state lock. */
	GLOBAL_STATE_UNLOCK();

	QL_PRINT_6(CE_CONT, "done\n");
}

/*
 * ql_timeout_insert
 *	Function used to insert a command block onto the
 *	watchdog timer queue.
 *
 *	Note: Must insure that pkt_time is not zero
 *			before calling ql_timeout_insert.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	sp:	SRB pointer.
 *	DEVICE_QUEUE_LOCK must be already obtained.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static void
ql_timeout_insert(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_srb_t *sp)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (sp->pkt->pkt_timeout != 0 && sp->pkt->pkt_timeout < 0x10000) {
		sp->isp_timeout = (uint16_t)(sp->pkt->pkt_timeout);
		/*
		 * The WATCHDOG_TIME must be rounded up + 1.  As an example,
		 * consider a 1 second timeout. If the WATCHDOG_TIME is 1, it
		 * will expire in the next watchdog call, which could be in
		 * 1 microsecond.
		 *
		 */
		sp->wdg_q_time = (sp->isp_timeout + WATCHDOG_TIME - 1) /
		    WATCHDOG_TIME;
		/*
		 * Added an additional 10 to account for the
		 * firmware timer drift which can occur with
		 * very long timeout values.
		 */
		sp->wdg_q_time += 10;

		/*
		 * Add 6 more to insure watchdog does not timeout at the same
		 * time as ISP RISC code timeout.
		 */
		sp->wdg_q_time += 6;

		/* Save initial time for resetting watchdog time. */
		sp->init_wdg_q_time = sp->wdg_q_time;

		/* Insert command onto watchdog queue. */
		ql_add_link_b(&tq->wdg, &sp->wdg);

		sp->flags |= SRB_WATCHDOG_ENABLED;
	} else {
		sp->isp_timeout = 0;
		sp->wdg_q_time = 0;
		sp->init_wdg_q_time = 0;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_watchdog
 *	Timeout handler that runs in interrupt context. The
 *	ql_adapter_state_t * argument is the parameter set up when the
 *	timeout was initialized (state structure pointer).
 *	Function used to update timeout values and if timeout
 *	has occurred command will be aborted.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt context, no mailbox commands allowed.
 */
static void
ql_watchdog(ql_adapter_state_t *ha, uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t	*sp;
	ql_link_t	*link;
	ql_link_t	*next_cmd;
	ql_link_t	*next_device;
	ql_tgt_t	*tq;
	ql_lun_t	*lq;
	uint16_t	index;
	int		q_sane;

	QL_PRINT_6(CE_CONT, "(%d): started\n", ha->instance);

	/* Loop through all targets. */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = next_device) {
			tq = link->base_address;

			/* Try to acquire device queue lock. */
			if (TRY_DEVICE_QUEUE_LOCK(tq) == 0) {
				next_device = NULL;
				continue;
			}

			next_device = link->next;

			if (!(CFG_IST(ha, CFG_ENABLE_LINK_DOWN_REPORTING)) &&
			    (tq->port_down_retry_count == 0)) {
				/* Release device queue lock. */
				DEVICE_QUEUE_UNLOCK(tq);
				continue;
			}

			/* Find out if this device is in a sane state. */
			if (tq->flags & (TQF_RSCN_RCVD |
			    TQF_NEED_AUTHENTICATION | TQF_QUEUE_SUSPENDED)) {
				q_sane = 0;
			} else {
				q_sane = 1;
			}
			/* Loop through commands on watchdog queue. */
			for (link = tq->wdg.first; link != NULL;
			    link = next_cmd) {
				next_cmd = link->next;
				sp = link->base_address;
				lq = sp->lun_queue;

				/*
				 * For SCSI commands, if everything seems to
				 * be going fine and this packet is stuck
				 * because of throttling at LUN or target
				 * level then do not decrement the
				 * sp->wdg_q_time
				 */
				if (ha->task_daemon_flags & STATE_ONLINE &&
				    (sp->flags & SRB_ISP_STARTED) == 0 &&
				    q_sane && sp->flags & SRB_FCP_CMD_PKT &&
				    lq->lun_outcnt >= ha->execution_throttle) {
					continue;
				}

				if (sp->wdg_q_time != 0) {
					sp->wdg_q_time--;

					/* Timeout? */
					if (sp->wdg_q_time != 0) {
						continue;
					}

					ql_remove_link(&tq->wdg, &sp->wdg);
					sp->flags &= ~SRB_WATCHDOG_ENABLED;

					if (sp->flags & SRB_ISP_STARTED) {
						ql_cmd_timeout(ha, tq, sp,
						    set_flags, reset_flags);

						DEVICE_QUEUE_UNLOCK(tq);
						tq = NULL;
						next_cmd = NULL;
						next_device = NULL;
						index = DEVICE_HEAD_LIST_SIZE;
					} else {
						ql_cmd_timeout(ha, tq, sp,
						    set_flags, reset_flags);
					}
				}
			}

			/* Release device queue lock. */
			if (tq != NULL) {
				DEVICE_QUEUE_UNLOCK(tq);
			}
		}
	}

	QL_PRINT_6(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_cmd_timeout
 *	Command timeout handler.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	sp:		SRB pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_cmd_timeout(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_srb_t *sp,
    uint32_t *set_flags, uint32_t *reset_flags)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (!(sp->flags & SRB_ISP_STARTED)) {

		EL(ha, "command timed out in driver = %ph\n", (void *)sp);

		REQUEST_RING_LOCK(ha);

		/* if it's on a queue */
		if (sp->cmd.head) {
			/*
			 * The pending_cmds que needs to be
			 * protected by the ring lock
			 */
			ql_remove_link(sp->cmd.head, &sp->cmd);
		}
		sp->flags &= ~SRB_IN_DEVICE_QUEUE;

		/* Release device queue lock. */
		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);

		/* Set timeout status */
		sp->pkt->pkt_reason = CS_TIMEOUT;

		/* Ensure no retry */
		sp->flags &= ~SRB_RETRY;

		/* Call done routine to handle completion. */
		ql_done(&sp->cmd);

		DEVICE_QUEUE_LOCK(tq);
	} else if (CFG_IST(ha, CFG_CTRL_8021)) {
		int		rval;
		uint32_t	index;

		EL(ha, "command timed out in isp=%ph, osc=%ph, index=%xh, "
		    "spf=%xh\n", (void *)sp,
		    (void *)ha->outstanding_cmds[sp->handle & OSC_INDEX_MASK],
		    sp->handle & OSC_INDEX_MASK, sp->flags);

		DEVICE_QUEUE_UNLOCK(tq);

		INTR_LOCK(ha);
		ha->pha->xioctl->ControllerErrorCount++;
		if (sp->handle) {
			ha->pha->timeout_cnt++;
			index = sp->handle & OSC_INDEX_MASK;
			if (ha->pha->outstanding_cmds[index] == sp) {
				sp->request_ring_ptr->entry_type =
				    INVALID_ENTRY_TYPE;
				sp->request_ring_ptr->entry_count = 0;
				ha->pha->outstanding_cmds[index] = 0;
			}
			INTR_UNLOCK(ha);

			rval = ql_abort_command(ha, sp);
			if (rval == QL_FUNCTION_TIMEOUT ||
			    rval == QL_LOCK_TIMEOUT ||
			    rval == QL_FUNCTION_PARAMETER_ERROR ||
			    ha->pha->timeout_cnt > TIMEOUT_THRESHOLD) {
				*set_flags |= ISP_ABORT_NEEDED;
				EL(ha, "abort status=%xh, tc=%xh, isp_abort_"
				    "needed\n", rval, ha->pha->timeout_cnt);
			}

			sp->handle = 0;
			sp->flags &= ~SRB_IN_TOKEN_ARRAY;
		} else {
			INTR_UNLOCK(ha);
		}

		/* Set timeout status */
		sp->pkt->pkt_reason = CS_TIMEOUT;

		/* Ensure no retry */
		sp->flags &= ~SRB_RETRY;

		/* Call done routine to handle completion. */
		ql_done(&sp->cmd);

		DEVICE_QUEUE_LOCK(tq);

	} else {
		EL(ha, "command timed out in isp=%ph, osc=%ph, index=%xh, "
		    "spf=%xh, isp_abort_needed\n", (void *)sp,
		    (void *)ha->outstanding_cmds[sp->handle & OSC_INDEX_MASK],
		    sp->handle & OSC_INDEX_MASK, sp->flags);

		/* Release device queue lock. */
		DEVICE_QUEUE_UNLOCK(tq);

		INTR_LOCK(ha);
		ha->pha->xioctl->ControllerErrorCount++;
		INTR_UNLOCK(ha);

		/* Set ISP needs to be reset */
		sp->flags |= SRB_COMMAND_TIMEOUT;

		if (CFG_IST(ha, CFG_DUMP_DRIVER_COMMAND_TIMEOUT)) {
			(void) ql_binary_fw_dump(ha, TRUE);
		}

		*set_flags |= ISP_ABORT_NEEDED;

		DEVICE_QUEUE_LOCK(tq);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_rst_aen
 *	Processes asynchronous reset.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_rst_aen(ql_adapter_state_t *ha)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Issue marker command. */
	(void) ql_marker(ha, 0, 0, MK_SYNC_ALL);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_cmd_wait
 *	Stall driver until all outstanding commands are returned.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_cmd_wait(ql_adapter_state_t *ha)
{
	uint16_t		index;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	ql_adapter_state_t	*vha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Wait for all outstanding commands to be returned. */
	(void) ql_wait_outstanding(ha);

	/*
	 * clear out internally queued commands
	 */
	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			for (link = vha->dev[index].first; link != NULL;
			    link = link->next) {
				tq = link->base_address;
				if (tq &&
				    (!(tq->prli_svc_param_word_3 &
				    PRLI_W3_RETRY))) {
					(void) ql_abort_device(vha, tq, 0);
				}
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_wait_outstanding
 *	Wait for all outstanding commands to complete.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	index - the index for ql_srb into outstanding_cmds.
 *
 * Context:
 *	Kernel context.
 */
static uint16_t
ql_wait_outstanding(ql_adapter_state_t *ha)
{
	ql_srb_t	*sp;
	uint16_t	index, count;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	count = ql_osc_wait_count;
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		if (ha->pha->pending_cmds.first != NULL) {
			ql_start_iocb(ha, NULL);
			index = 1;
		}
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    (sp->flags & SRB_COMMAND_TIMEOUT) == 0) {
			if (count-- != 0) {
				ql_delay(ha, 10000);
				index = 0;
			} else {
				EL(ha, "failed, sp=%ph, oci=%d, hdl=%xh\n",
				    (void *)sp, index, sp->handle);
				break;
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (index);
}

/*
 * ql_restart_queues
 *	Restart device queues.
 *
 * Input:
 *	ha = adapter state pointer.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_restart_queues(ql_adapter_state_t *ha)
{
	ql_link_t		*link, *link2;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	uint16_t		index;
	ql_adapter_state_t	*vha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	for (vha = ha->pha; vha != NULL; vha = vha->vp_next) {
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			for (link = vha->dev[index].first; link != NULL;
			    link = link->next) {
				tq = link->base_address;

				/* Acquire device queue lock. */
				DEVICE_QUEUE_LOCK(tq);

				tq->flags &= ~TQF_QUEUE_SUSPENDED;

				for (link2 = tq->lun_queues.first;
				    link2 != NULL; link2 = link2->next) {
					lq = link2->base_address;

					if (lq->cmd.first != NULL) {
						ql_next(vha, lq);
						DEVICE_QUEUE_LOCK(tq);
					}
				}

				/* Release device queue lock. */
				DEVICE_QUEUE_UNLOCK(tq);
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_iidma
 *	Setup iiDMA parameters to firmware
 *
 * Input:
 *	ha = adapter state pointer.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_iidma(ql_adapter_state_t *ha)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	uint16_t	index;
	char		buf[256];
	uint32_t	data;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_CTRL_242581)) == 0) {
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
		return;
	}

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			/* Acquire device queue lock. */
			DEVICE_QUEUE_LOCK(tq);

			if ((tq->flags & TQF_IIDMA_NEEDED) == 0) {
				DEVICE_QUEUE_UNLOCK(tq);
				continue;
			}

			tq->flags &= ~TQF_IIDMA_NEEDED;

			if ((tq->loop_id > LAST_N_PORT_HDL) ||
			    (tq->iidma_rate == IIDMA_RATE_NDEF)) {
				DEVICE_QUEUE_UNLOCK(tq);
				continue;
			}

			/* Get the iiDMA persistent data */
			if (tq->iidma_rate == IIDMA_RATE_INIT) {
				(void) sprintf(buf,
				    "iidma-rate-%02x%02x%02x%02x%02x"
				    "%02x%02x%02x", tq->port_name[0],
				    tq->port_name[1], tq->port_name[2],
				    tq->port_name[3], tq->port_name[4],
				    tq->port_name[5], tq->port_name[6],
				    tq->port_name[7]);

				if ((data = ql_get_prop(ha, buf)) ==
				    0xffffffff) {
					tq->iidma_rate = IIDMA_RATE_NDEF;
				} else {
					switch (data) {
					case IIDMA_RATE_1GB:
					case IIDMA_RATE_2GB:
					case IIDMA_RATE_4GB:
					case IIDMA_RATE_10GB:
						tq->iidma_rate = data;
						break;
					case IIDMA_RATE_8GB:
						if (CFG_IST(ha,
						    CFG_CTRL_25XX)) {
							tq->iidma_rate = data;
						} else {
							tq->iidma_rate =
							    IIDMA_RATE_4GB;
						}
						break;
					default:
						EL(ha, "invalid data for "
						    "parameter: %s: %xh\n",
						    buf, data);
						tq->iidma_rate =
						    IIDMA_RATE_NDEF;
						break;
					}
				}
			}

			/* Set the firmware's iiDMA rate */
			if (tq->iidma_rate <= IIDMA_RATE_MAX &&
			    !(CFG_IST(ha, CFG_CTRL_8081))) {
				data = ql_iidma_rate(ha, tq->loop_id,
				    &tq->iidma_rate, EXT_IIDMA_MODE_SET);
				if (data != QL_SUCCESS) {
					EL(ha, "mbx failed: %xh\n", data);
				}
			}

			/* Release device queue lock. */
			DEVICE_QUEUE_UNLOCK(tq);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_abort_queues
 *	Abort all commands on device queues.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_abort_queues(ql_adapter_state_t *ha)
{
	ql_link_t		*link;
	ql_tgt_t		*tq;
	ql_srb_t		*sp;
	uint16_t		index;
	ql_adapter_state_t	*vha;

	QL_PRINT_10(CE_CONT, "(%d): started\n", ha->instance);

	/* Return all commands in outstanding command list. */
	INTR_LOCK(ha);

	/* Place all commands in outstanding cmd list on device queue. */
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		if (ha->pending_cmds.first != NULL) {
			INTR_UNLOCK(ha);
			ql_start_iocb(ha, NULL);
			/* Delay for system */
			ql_delay(ha, 10000);
			INTR_LOCK(ha);
			index = 1;
		}
		sp = ha->outstanding_cmds[index];

		/* skip devices capable of FCP2 retrys */
		if ((sp != NULL) &&
		    ((tq = sp->lun_queue->target_queue) != NULL) &&
		    (!(tq->prli_svc_param_word_3 & PRLI_W3_RETRY))) {
			ha->outstanding_cmds[index] = NULL;
			sp->handle = 0;
			sp->flags &= ~SRB_IN_TOKEN_ARRAY;

			INTR_UNLOCK(ha);

			/* Set ending status. */
			sp->pkt->pkt_reason = CS_PORT_UNAVAILABLE;
			sp->flags |= SRB_ISP_COMPLETED;

			/* Call done routine to handle completions. */
			sp->cmd.next = NULL;
			ql_done(&sp->cmd);

			INTR_LOCK(ha);
		}
	}
	INTR_UNLOCK(ha);

	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		QL_PRINT_10(CE_CONT, "(%d,%d): abort instance\n",
		    vha->instance, vha->vp_index);
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			for (link = vha->dev[index].first; link != NULL;
			    link = link->next) {
				tq = link->base_address;
				/* skip devices capable of FCP2 retrys */
				if (!(tq->prli_svc_param_word_3 &
				    PRLI_W3_RETRY)) {
					/*
					 * Set port unavailable status and
					 * return all commands on a devices
					 * queues.
					 */
					ql_abort_device_queues(ha, tq);
				}
			}
		}
	}
	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_abort_device_queues
 *	Abort all commands on device queues.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_abort_device_queues(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	ql_link_t	*lun_link, *cmd_link;
	ql_srb_t	*sp;
	ql_lun_t	*lq;

	QL_PRINT_10(CE_CONT, "(%d): started\n", ha->instance);

	DEVICE_QUEUE_LOCK(tq);

	for (lun_link = tq->lun_queues.first; lun_link != NULL;
	    lun_link = lun_link->next) {
		lq = lun_link->base_address;

		cmd_link = lq->cmd.first;
		while (cmd_link != NULL) {
			sp = cmd_link->base_address;

			if (sp->flags & SRB_ABORT) {
				cmd_link = cmd_link->next;
				continue;
			}

			/* Remove srb from device cmd queue. */
			ql_remove_link(&lq->cmd, &sp->cmd);

			sp->flags &= ~SRB_IN_DEVICE_QUEUE;

			DEVICE_QUEUE_UNLOCK(tq);

			/* Set ending status. */
			sp->pkt->pkt_reason = CS_PORT_UNAVAILABLE;

			/* Call done routine to handle completion. */
			ql_done(&sp->cmd);

			/* Delay for system */
			ql_delay(ha, 10000);

			DEVICE_QUEUE_LOCK(tq);
			cmd_link = lq->cmd.first;
		}
	}
	DEVICE_QUEUE_UNLOCK(tq);

	QL_PRINT_10(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_loop_resync
 *	Resync with fibre channel devices.
 *
 * Input:
 *	ha = adapter state pointer.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_loop_resync(ql_adapter_state_t *ha)
{
	int rval;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->flags & IP_INITIALIZED) {
		(void) ql_shutdown_ip(ha);
	}

	rval = ql_fw_ready(ha, 10);

	TASK_DAEMON_LOCK(ha);
	ha->task_daemon_flags &= ~LOOP_RESYNC_ACTIVE;
	TASK_DAEMON_UNLOCK(ha);

	/* Set loop online, if it really is. */
	if (rval == QL_SUCCESS) {
		ql_loop_online(ha);
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	} else {
		EL(ha, "failed, rval = %xh\n", rval);
	}

	return (rval);
}

/*
 * ql_loop_online
 *	Set loop online status if it really is online.
 *
 * Input:
 *	ha = adapter state pointer.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Context:
 *	Kernel context.
 */
void
ql_loop_online(ql_adapter_state_t *ha)
{
	ql_adapter_state_t	*vha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Inform the FC Transport that the hardware is online. */
	for (vha = ha->pha; vha != NULL; vha = vha->vp_next) {
		if (!(vha->task_daemon_flags &
		    (LOOP_RESYNC_NEEDED | LOOP_DOWN))) {
			/* Restart IP if it was shutdown. */
			if (vha->vp_index == 0 && vha->flags & IP_ENABLED &&
			    !(vha->flags & IP_INITIALIZED)) {
				(void) ql_initialize_ip(vha);
				ql_isp_rcvbuf(vha);
			}

			if (FC_PORT_STATE_MASK(vha->state) != FC_STATE_LOOP &&
			    FC_PORT_STATE_MASK(vha->state) !=
			    FC_STATE_ONLINE) {
				vha->state = FC_PORT_SPEED_MASK(vha->state);
				if (vha->topology & QL_LOOP_CONNECTION) {
					vha->state |= FC_STATE_LOOP;
				} else {
					vha->state |= FC_STATE_ONLINE;
				}
				TASK_DAEMON_LOCK(ha);
				vha->task_daemon_flags |= FC_STATE_CHANGE;
				TASK_DAEMON_UNLOCK(ha);
			}
		}
	}

	ql_awaken_task_daemon(ha, NULL, 0, 0);

	/* Restart device queues that may have been stopped. */
	ql_restart_queues(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_fca_handle_to_state
 *	Verifies handle to be correct.
 *
 * Input:
 *	fca_handle = pointer to state structure.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
static ql_adapter_state_t *
ql_fca_handle_to_state(opaque_t fca_handle)
{
#ifdef	QL_DEBUG_ROUTINES
	ql_link_t		*link;
	ql_adapter_state_t	*ha = NULL;
	ql_adapter_state_t	*vha = NULL;

	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha = link->base_address;
		for (vha = ha->vp_next; vha != NULL; vha = vha->vp_next) {
			if ((opaque_t)vha == fca_handle) {
				ha = vha;
				break;
			}
		}
		if ((opaque_t)ha == fca_handle) {
			break;
		} else {
			ha = NULL;
		}
	}

	if (ha == NULL) {
		/*EMPTY*/
		QL_PRINT_2(CE_CONT, "failed\n");
	}

#endif /* QL_DEBUG_ROUTINES */

	return ((ql_adapter_state_t *)fca_handle);
}

/*
 * ql_d_id_to_queue
 *	Locate device queue that matches destination ID.
 *
 * Input:
 *	ha = adapter state pointer.
 *	d_id = destination ID
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
ql_tgt_t *
ql_d_id_to_queue(ql_adapter_state_t *ha, port_id_t d_id)
{
	uint16_t	index;
	ql_tgt_t	*tq;
	ql_link_t	*link;

	/* Get head queue index. */
	index = ql_alpa_to_index[d_id.b.al_pa];

	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24 &&
		    VALID_DEVICE_ID(ha, tq->loop_id)) {
			return (tq);
		}
	}

	return (NULL);
}

/*
 * ql_loop_id_to_queue
 *	Locate device queue that matches loop ID.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	destination ID
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
ql_tgt_t *
ql_loop_id_to_queue(ql_adapter_state_t *ha, uint16_t loop_id)
{
	uint16_t	index;
	ql_tgt_t	*tq;
	ql_link_t	*link;

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;
			if (tq->loop_id == loop_id) {
				return (tq);
			}
		}
	}

	return (NULL);
}

/*
 * ql_kstat_update
 *	Updates kernel statistics.
 *
 * Input:
 *	ksp - driver kernel statistics structure pointer.
 *	rw - function to perform
 *
 * Returns:
 *	0 or EACCES
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
ql_kstat_update(kstat_t *ksp, int rw)
{
	int			rval;

	QL_PRINT_3(CE_CONT, "started\n");

	if (rw == KSTAT_WRITE) {
		rval = EACCES;
	} else {
		rval = 0;
	}

	if (rval != 0) {
		/*EMPTY*/
		QL_PRINT_2(CE_CONT, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "done\n");
	}
	return (rval);
}

/*
 * ql_load_flash
 *	Loads flash.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dp:	data pointer.
 *	size:	data length.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_load_flash(ql_adapter_state_t *ha, uint8_t *dp, uint32_t size)
{
	uint32_t	cnt;
	int		rval;
	uint32_t	size_to_offset;
	uint32_t	size_to_compare;
	int		erase_all;

	if (CFG_IST(ha, CFG_CTRL_24258081)) {
		return (ql_24xx_load_flash(ha, dp, size, 0));
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	size_to_compare = 0x20000;
	size_to_offset = 0;
	erase_all = 0;
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		if (size == 0x80000) {
			/* Request to flash the entire chip. */
			size_to_compare = 0x80000;
			erase_all = 1;
		} else {
			size_to_compare = 0x40000;
			if (ql_flash_sbus_fpga) {
				size_to_offset = 0x40000;
			}
		}
	}
	if (size > size_to_compare) {
		rval = QL_FUNCTION_PARAMETER_ERROR;
		EL(ha, "failed=%xh\n", rval);
		return (rval);
	}

	GLOBAL_HW_LOCK();

	/* Enable Flash Read/Write. */
	ql_flash_enable(ha);

	/* Erase flash prior to write. */
	rval = ql_erase_flash(ha, erase_all);

	if (rval == QL_SUCCESS) {
		/* Write data to flash. */
		for (cnt = 0; cnt < size; cnt++) {
			/* Allow other system activity. */
			if (cnt % 0x1000 == 0) {
				ql_delay(ha, 10000);
			}
			rval = ql_program_flash_address(ha,
			    cnt + size_to_offset, *dp++);
			if (rval != QL_SUCCESS) {
				break;
			}
		}
	}

	ql_flash_disable(ha);

	GLOBAL_HW_UNLOCK();

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_program_flash_address
 *	Program flash address.
 *
 * Input:
 *	ha = adapter state pointer.
 *	addr = flash byte address.
 *	data = data to be written to flash.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_program_flash_address(ql_adapter_state_t *ha, uint32_t addr, uint8_t data)
{
	int rval;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ql_write_flash_byte(ha, 0x5555, 0xa0);
		ql_write_flash_byte(ha, addr, data);
	} else {
		/* Write Program Command Sequence */
		ql_write_flash_byte(ha, 0x5555, 0xaa);
		ql_write_flash_byte(ha, 0x2aaa, 0x55);
		ql_write_flash_byte(ha, 0x5555, 0xa0);
		ql_write_flash_byte(ha, addr, data);
	}

	/* Wait for write to complete. */
	rval = ql_poll_flash(ha, addr, data);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_erase_flash
 *	Erases entire flash.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_erase_flash(ql_adapter_state_t *ha, int erase_all)
{
	int		rval;
	uint32_t	erase_delay = 2000000;
	uint32_t	sStartAddr;
	uint32_t	ssize;
	uint32_t	cnt;
	uint8_t		*bfp;
	uint8_t		*tmp;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((CFG_IST(ha, CFG_SBUS_CARD)) && !erase_all) {

		if (ql_flash_sbus_fpga == 1) {
			ssize = QL_SBUS_FCODE_SIZE;
			sStartAddr = QL_FCODE_OFFSET;
		} else {
			ssize = QL_FPGA_SIZE;
			sStartAddr = QL_FPGA_OFFSET;
		}

		erase_delay = 20000000;

		bfp = (uint8_t *)kmem_zalloc(ssize, KM_SLEEP);

		/* Save the section of flash we're not updating to buffer */
		tmp = bfp;
		for (cnt = sStartAddr; cnt < ssize+sStartAddr; cnt++) {
			/* Allow other system activity. */
			if (cnt % 0x1000 == 0) {
				ql_delay(ha, 10000);
			}
			*tmp++ = (uint8_t)ql_read_flash_byte(ha, cnt);
		}
	}

	/* Chip Erase Command Sequence */
	ql_write_flash_byte(ha, 0x5555, 0xaa);
	ql_write_flash_byte(ha, 0x2aaa, 0x55);
	ql_write_flash_byte(ha, 0x5555, 0x80);
	ql_write_flash_byte(ha, 0x5555, 0xaa);
	ql_write_flash_byte(ha, 0x2aaa, 0x55);
	ql_write_flash_byte(ha, 0x5555, 0x10);

	ql_delay(ha, erase_delay);

	/* Wait for erase to complete. */
	rval = ql_poll_flash(ha, 0, 0x80);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			kmem_free(bfp, ssize);
		}
		return (rval);
	}

	/* restore the section we saved in the buffer */
	if ((CFG_IST(ha, CFG_SBUS_CARD)) && !erase_all) {
		/* Restore the section we saved off */
		tmp = bfp;
		for (cnt = sStartAddr; cnt < ssize+sStartAddr; cnt++) {
			/* Allow other system activity. */
			if (cnt % 0x1000 == 0) {
				ql_delay(ha, 10000);
			}
			rval = ql_program_flash_address(ha, cnt, *tmp++);
			if (rval != QL_SUCCESS) {
				break;
			}
		}

		kmem_free(bfp, ssize);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_poll_flash
 *	Polls flash for completion.
 *
 * Input:
 *	ha = adapter state pointer.
 *	addr = flash byte address.
 *	data = data to be polled.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_poll_flash(ql_adapter_state_t *ha, uint32_t addr, uint8_t poll_data)
{
	uint8_t		flash_data;
	uint32_t	cnt;
	int		rval = QL_FUNCTION_FAILED;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	poll_data = (uint8_t)(poll_data & BIT_7);

	/* Wait for 30 seconds for command to finish. */
	for (cnt = 30000000; cnt; cnt--) {
		flash_data = (uint8_t)ql_read_flash_byte(ha, addr);

		if ((flash_data & BIT_7) == poll_data) {
			rval = QL_SUCCESS;
			break;
		}
		if (flash_data & BIT_5 && cnt > 2) {
			cnt = 2;
		}
		drv_usecwait(1);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_flash_enable
 *	Setup flash for reading/writing.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_flash_enable(ql_adapter_state_t *ha)
{
	uint16_t	data;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Enable Flash Read/Write. */
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		data = (uint16_t)ddi_get16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_CONF));
		data = (uint16_t)(data | SBUS_FLASH_WRITE_ENABLE);
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_CONF), data);
		/* Read reset command sequence */
		ql_write_flash_byte(ha, 0xaaa, 0xaa);
		ql_write_flash_byte(ha, 0x555, 0x55);
		ql_write_flash_byte(ha, 0xaaa, 0x20);
		ql_write_flash_byte(ha, 0x555, 0xf0);
	} else {
		data = (uint16_t)(RD16_IO_REG(ha, ctrl_status) |
		    ISP_FLASH_ENABLE);
		WRT16_IO_REG(ha, ctrl_status, data);

		/* Read/Reset Command Sequence */
		ql_write_flash_byte(ha, 0x5555, 0xaa);
		ql_write_flash_byte(ha, 0x2aaa, 0x55);
		ql_write_flash_byte(ha, 0x5555, 0xf0);
	}
	(void) ql_read_flash_byte(ha, 0);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_flash_disable
 *	Disable flash and allow RISC to run.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_flash_disable(ql_adapter_state_t *ha)
{
	uint16_t	data;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		/*
		 * Lock the flash back up.
		 */
		ql_write_flash_byte(ha, 0x555, 0x90);
		ql_write_flash_byte(ha, 0x555, 0x0);

		data = (uint16_t)ddi_get16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_CONF));
		data = (uint16_t)(data & ~SBUS_FLASH_WRITE_ENABLE);
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_CONF), data);
	} else {
		data = (uint16_t)(RD16_IO_REG(ha, ctrl_status) &
		    ~ISP_FLASH_ENABLE);
		WRT16_IO_REG(ha, ctrl_status, data);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_write_flash_byte
 *	Write byte to flash.
 *
 * Input:
 *	ha = adapter state pointer.
 *	addr = flash byte address.
 *	data = data to be written.
 *
 * Context:
 *	Kernel context.
 */
void
ql_write_flash_byte(ql_adapter_state_t *ha, uint32_t addr, uint8_t data)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_EEPROM_LOADDR),
		    LSW(addr));
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_EEPROM_HIADDR),
		    MSW(addr));
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_EEPROM_DATA),
		    (uint16_t)data);
	} else {
		uint16_t bank_select;

		/* Setup bit 16 of flash address. */
		bank_select = (uint16_t)RD16_IO_REG(ha, ctrl_status);

		if (CFG_IST(ha, CFG_CTRL_6322)) {
			bank_select = (uint16_t)(bank_select & ~0xf0);
			bank_select = (uint16_t)(bank_select |
			    ((addr >> 12 & 0xf0) | ISP_FLASH_64K_BANK));
			WRT16_IO_REG(ha, ctrl_status, bank_select);
		} else {
			if (addr & BIT_16 && !(bank_select &
			    ISP_FLASH_64K_BANK)) {
				bank_select = (uint16_t)(bank_select |
				    ISP_FLASH_64K_BANK);
				WRT16_IO_REG(ha, ctrl_status, bank_select);
			} else if (!(addr & BIT_16) && bank_select &
			    ISP_FLASH_64K_BANK) {
				bank_select = (uint16_t)(bank_select &
				    ~ISP_FLASH_64K_BANK);
				WRT16_IO_REG(ha, ctrl_status, bank_select);
			}
		}

		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			WRT16_IO_REG(ha, flash_address, (uint16_t)addr);
			WRT16_IO_REG(ha, flash_data, (uint16_t)data);
		} else {
			WRT16_IOMAP_REG(ha, flash_address, addr);
			WRT16_IOMAP_REG(ha, flash_data, data);
		}
	}
}

/*
 * ql_read_flash_byte
 *	Reads byte from flash, but must read a word from chip.
 *
 * Input:
 *	ha = adapter state pointer.
 *	addr = flash byte address.
 *
 * Returns:
 *	byte from flash.
 *
 * Context:
 *	Kernel context.
 */
uint8_t
ql_read_flash_byte(ql_adapter_state_t *ha, uint32_t addr)
{
	uint8_t	data;

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_EEPROM_LOADDR),
		    LSW(addr));
		ddi_put16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_EEPROM_HIADDR),
		    MSW(addr));
		data = (uint8_t)ddi_get16(ha->sbus_fpga_dev_handle,
		    (uint16_t *)(ha->sbus_fpga_iobase + FPGA_EEPROM_DATA));
	} else {
		uint16_t	bank_select;

		/* Setup bit 16 of flash address. */
		bank_select = RD16_IO_REG(ha, ctrl_status);
		if (CFG_IST(ha, CFG_CTRL_6322)) {
			bank_select = (uint16_t)(bank_select & ~0xf0);
			bank_select = (uint16_t)(bank_select |
			    ((addr >> 12 & 0xf0) | ISP_FLASH_64K_BANK));
			WRT16_IO_REG(ha, ctrl_status, bank_select);
		} else {
			if (addr & BIT_16 &&
			    !(bank_select & ISP_FLASH_64K_BANK)) {
				bank_select = (uint16_t)(bank_select |
				    ISP_FLASH_64K_BANK);
				WRT16_IO_REG(ha, ctrl_status, bank_select);
			} else if (!(addr & BIT_16) &&
			    bank_select & ISP_FLASH_64K_BANK) {
				bank_select = (uint16_t)(bank_select &
				    ~ISP_FLASH_64K_BANK);
				WRT16_IO_REG(ha, ctrl_status, bank_select);
			}
		}

		if (CFG_IST(ha, CFG_SBUS_CARD)) {
			WRT16_IO_REG(ha, flash_address, addr);
			data = (uint8_t)RD16_IO_REG(ha, flash_data);
		} else {
			WRT16_IOMAP_REG(ha, flash_address, addr);
			data = (uint8_t)RD16_IOMAP_REG(ha, flash_data);
		}
	}

	return (data);
}

/*
 * ql_24xx_flash_id
 *	Get flash IDs.
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_24xx_flash_id(ql_adapter_state_t *vha)
{
	int			rval;
	uint32_t		fdata = 0;
	ql_adapter_state_t	*ha = vha->pha;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	rval = ql_24xx_read_flash(ha, FLASH_CONF_ADDR | 0x3AB, &fdata);

	if (rval != QL_SUCCESS || fdata == 0 || CFG_IST(ha, CFG_CTRL_2581)) {
		fdata = 0;
		rval = ql_24xx_read_flash(ha, FLASH_CONF_ADDR |
		    (CFG_IST(ha, CFG_CTRL_2422) ? 0x39F : 0x49F), &fdata);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "24xx read_flash failed=%xh\n", rval);
	} else if (fdata != 0) {
		xp->fdesc.flash_manuf = LSB(LSW(fdata));
		xp->fdesc.flash_id = MSB(LSW(fdata));
		xp->fdesc.flash_len = LSB(MSW(fdata));
	} else {
		xp->fdesc.flash_manuf = ATMEL_FLASH;
		xp->fdesc.flash_id = ATMEL_FLASHID_1024K;
		xp->fdesc.flash_len = 0;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_24xx_load_flash
 *	Loads flash.
 *
 * Input:
 *	ha = adapter state pointer.
 *	dp = data pointer.
 *	size = data length in bytes.
 *	faddr = 32bit word flash byte address.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_24xx_load_flash(ql_adapter_state_t *vha, uint8_t *dp, uint32_t size,
    uint32_t faddr)
{
	int			rval;
	uint32_t		cnt, rest_addr, fdata, wc;
	dma_mem_t		dmabuf = {0};
	ql_adapter_state_t	*ha = vha->pha;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_3(CE_CONT, "(%d): started, faddr=%xh, size=%xh\n",
	    ha->instance, faddr, size);

	/* start address must be 32 bit word aligned */
	if ((faddr & 0x3) != 0) {
		EL(ha, "incorrect buffer size alignment\n");
		return (QL_FUNCTION_PARAMETER_ERROR);
	}

	/* Allocate DMA buffer */
	if (CFG_IST(ha, CFG_CTRL_2581)) {
		if ((rval = ql_get_dma_mem(ha, &dmabuf, 0xffff,
		    LITTLE_ENDIAN_DMA, QL_DMA_DATA_ALIGN)) !=
		    QL_SUCCESS) {
			EL(ha, "dma alloc failed, rval=%xh\n", rval);
			return (rval);
		}
	}

	GLOBAL_HW_LOCK();

	/* Enable flash write */
	if ((rval = ql_24xx_unprotect_flash(ha)) != QL_SUCCESS) {
		GLOBAL_HW_UNLOCK();
		EL(ha, "unprotect_flash failed, rval=%xh\n", rval);
		ql_free_phys(ha, &dmabuf);
		return (rval);
	}

	/* setup mask of address range within a sector */
	rest_addr = (xp->fdesc.block_size - 1) >> 2;

	faddr = faddr >> 2;	/* flash gets 32 bit words */

	/*
	 * Write data to flash.
	 */
	cnt = 0;
	size = (size + 3) >> 2;	/* Round up & convert to dwords */

	while (cnt < size) {
		/* Beginning of a sector? */
		if ((faddr & rest_addr) == 0) {
			if (CFG_IST(ha, CFG_CTRL_8021)) {
				fdata = ha->flash_data_addr | faddr;
				rval = ql_8021_rom_erase(ha, fdata);
				if (rval != QL_SUCCESS) {
					EL(ha, "8021 erase sector status="
					    "%xh, start=%xh, end=%xh"
					    "\n", rval, fdata,
					    fdata + rest_addr);
					break;
				}
			} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
				fdata = ha->flash_data_addr | faddr;
				rval = ql_flash_access(ha,
				    FAC_ERASE_SECTOR, fdata, fdata +
				    rest_addr, 0);
				if (rval != QL_SUCCESS) {
					EL(ha, "erase sector status="
					    "%xh, start=%xh, end=%xh"
					    "\n", rval, fdata,
					    fdata + rest_addr);
					break;
				}
			} else {
				fdata = (faddr & ~rest_addr) << 2;
				fdata = (fdata & 0xff00) |
				    (fdata << 16 & 0xff0000) |
				    (fdata >> 16 & 0xff);

				if (rest_addr == 0x1fff) {
					/* 32kb sector block erase */
					rval = ql_24xx_write_flash(ha,
					    FLASH_CONF_ADDR | 0x0352,
					    fdata);
				} else {
					/* 64kb sector block erase */
					rval = ql_24xx_write_flash(ha,
					    FLASH_CONF_ADDR | 0x03d8,
					    fdata);
				}
				if (rval != QL_SUCCESS) {
					EL(ha, "Unable to flash sector"
					    ": address=%xh\n", faddr);
					break;
				}
			}
		}

		/* Write data */
		if (CFG_IST(ha, CFG_CTRL_2581) &&
		    ((faddr & 0x3f) == 0)) {
			/*
			 * Limit write up to sector boundary.
			 */
			wc = ((~faddr & (rest_addr>>1)) + 1);

			if (size - cnt < wc) {
				wc = size - cnt;
			}

			ddi_rep_put8(dmabuf.acc_handle, (uint8_t *)dp,
			    (uint8_t *)dmabuf.bp, wc<<2,
			    DDI_DEV_AUTOINCR);

			rval = ql_wrt_risc_ram(ha, ha->flash_data_addr |
			    faddr, dmabuf.cookie.dmac_laddress, wc);
			if (rval != QL_SUCCESS) {
				EL(ha, "unable to dma to flash "
				    "address=%xh\n", faddr << 2);
				break;
			}

			cnt += wc;
			faddr += wc;
			dp += wc << 2;
		} else {
			fdata = *dp++;
			fdata |= *dp++ << 8;
			fdata |= *dp++ << 16;
			fdata |= *dp++ << 24;
			rval = ql_24xx_write_flash(ha,
			    ha->flash_data_addr | faddr, fdata);
			if (rval != QL_SUCCESS) {
				EL(ha, "Unable to program flash "
				    "address=%xh data=%xh\n", faddr,
				    *dp);
				break;
			}
			cnt++;
			faddr++;

			/* Allow other system activity. */
			if (cnt % 0x1000 == 0) {
				ql_delay(ha, 10000);
			}
		}
	}

	ql_24xx_protect_flash(ha);

	ql_free_phys(ha, &dmabuf);

	GLOBAL_HW_UNLOCK();

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_24xx_read_flash
 *	Reads a 32bit word from ISP24xx NVRAM/FLASH.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	faddr:	NVRAM/FLASH address.
 *	bp:	data pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_24xx_read_flash(ql_adapter_state_t *vha, uint32_t faddr, uint32_t *bp)
{
	uint32_t		timer;
	int			rval = QL_SUCCESS;
	ql_adapter_state_t	*ha = vha->pha;

	if (CFG_IST(ha, CFG_CTRL_8021)) {
		if ((rval = ql_8021_rom_read(ha, faddr, bp)) != QL_SUCCESS) {
			EL(ha, "8021 access error\n");
		}
		return (rval);
	}

	/* Clear access error flag */
	WRT32_IO_REG(ha, ctrl_status,
	    RD32_IO_REG(ha, ctrl_status) | FLASH_NVRAM_ACCESS_ERROR);

	WRT32_IO_REG(ha, flash_address, faddr & ~FLASH_DATA_FLAG);

	/* Wait for READ cycle to complete. */
	for (timer = 300000; timer; timer--) {
		if (RD32_IO_REG(ha, flash_address) & FLASH_DATA_FLAG) {
			break;
		}
		drv_usecwait(10);
	}

	if (timer == 0) {
		EL(ha, "failed, timeout\n");
		rval = QL_FUNCTION_TIMEOUT;
	} else if (RD32_IO_REG(ha, ctrl_status) & FLASH_NVRAM_ACCESS_ERROR) {
		EL(ha, "failed, access error\n");
		rval = QL_FUNCTION_FAILED;
	}

	*bp = RD32_IO_REG(ha, flash_data);

	return (rval);
}

/*
 * ql_24xx_write_flash
 *	Writes a 32bit word to ISP24xx NVRAM/FLASH.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	addr:	NVRAM/FLASH address.
 *	value:	data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_24xx_write_flash(ql_adapter_state_t *vha, uint32_t addr, uint32_t data)
{
	uint32_t		timer, fdata;
	int			rval = QL_SUCCESS;
	ql_adapter_state_t	*ha = vha->pha;

	if (CFG_IST(ha, CFG_CTRL_8021)) {
		if ((rval = ql_8021_rom_write(ha, addr, data)) != QL_SUCCESS) {
			EL(ha, "8021 access error\n");
		}
		return (rval);
	}
	/* Clear access error flag */
	WRT32_IO_REG(ha, ctrl_status,
	    RD32_IO_REG(ha, ctrl_status) | FLASH_NVRAM_ACCESS_ERROR);

	WRT32_IO_REG(ha, flash_data, data);
	RD32_IO_REG(ha, flash_data);		/* PCI Posting. */
	WRT32_IO_REG(ha, flash_address, addr | FLASH_DATA_FLAG);

	/* Wait for Write cycle to complete. */
	for (timer = 3000000; timer; timer--) {
		if ((RD32_IO_REG(ha, flash_address) & FLASH_DATA_FLAG) == 0) {
			/* Check flash write in progress. */
			if ((addr & FLASH_ADDR_MASK) == FLASH_CONF_ADDR) {
				(void) ql_24xx_read_flash(ha,
				    FLASH_CONF_ADDR | 0x005, &fdata);
				if (!(fdata & BIT_0)) {
					break;
				}
			} else {
				break;
			}
		}
		drv_usecwait(10);
	}
	if (timer == 0) {
		EL(ha, "failed, timeout\n");
		rval = QL_FUNCTION_TIMEOUT;
	} else if (RD32_IO_REG(ha, ctrl_status) & FLASH_NVRAM_ACCESS_ERROR) {
		EL(ha, "access error\n");
		rval = QL_FUNCTION_FAILED;
	}

	return (rval);
}
/*
 * ql_24xx_unprotect_flash
 *	Enable writes
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_24xx_unprotect_flash(ql_adapter_state_t *vha)
{
	int			rval;
	uint32_t		fdata;
	ql_adapter_state_t	*ha = vha->pha;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_8021)) {
		(void) ql_8021_rom_wrsr(ha, xp->fdesc.write_enable_bits);
		rval = ql_8021_rom_wrsr(ha, xp->fdesc.write_enable_bits);
		if (rval != QL_SUCCESS) {
			EL(ha, "8021 access error\n");
		}
		return (rval);
	}
	if (CFG_IST(ha, CFG_CTRL_81XX)) {
		if (ha->task_daemon_flags & FIRMWARE_UP) {
			if ((rval = ql_flash_access(ha, FAC_WRT_ENABLE, 0, 0,
			    0)) != QL_SUCCESS) {
				EL(ha, "status=%xh\n", rval);
			}
			QL_PRINT_3(CE_CONT, "(%d): 8100 done\n",
			    ha->instance);
			return (rval);
		}
	} else {
		/* Enable flash write. */
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) | ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	/*
	 * Remove block write protection (SST and ST) and
	 * Sector/Block Protection Register Lock (SST, ST, ATMEL).
	 * Unprotect sectors.
	 */
	(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x100 |
	    xp->fdesc.write_statusreg_cmd, xp->fdesc.write_enable_bits);

	if (xp->fdesc.unprotect_sector_cmd != 0) {
		for (fdata = 0; fdata < 0x10; fdata++) {
			(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR |
			    0x300 | xp->fdesc.unprotect_sector_cmd, fdata);
		}

		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x300 |
		    xp->fdesc.unprotect_sector_cmd, 0x00400f);
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x300 |
		    xp->fdesc.unprotect_sector_cmd, 0x00600f);
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x300 |
		    xp->fdesc.unprotect_sector_cmd, 0x00800f);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (QL_SUCCESS);
}

/*
 * ql_24xx_protect_flash
 *	Disable writes
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_24xx_protect_flash(ql_adapter_state_t *vha)
{
	int			rval;
	uint32_t		fdata;
	ql_adapter_state_t	*ha = vha->pha;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_8021)) {
		(void) ql_8021_rom_wrsr(ha, xp->fdesc.write_enable_bits);
		rval = ql_8021_rom_wrsr(ha, xp->fdesc.write_disable_bits);
		if (rval != QL_SUCCESS) {
			EL(ha, "8021 access error\n");
		}
		return;
	}
	if (CFG_IST(ha, CFG_CTRL_81XX)) {
		if (ha->task_daemon_flags & FIRMWARE_UP) {
			if ((rval = ql_flash_access(ha, FAC_WRT_PROTECT, 0, 0,
			    0)) != QL_SUCCESS) {
				EL(ha, "status=%xh\n", rval);
			}
			QL_PRINT_3(CE_CONT, "(%d): 8100 done\n",
			    ha->instance);
			return;
		}
	} else {
		/* Enable flash write. */
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) | ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	/*
	 * Protect sectors.
	 * Set block write protection (SST and ST) and
	 * Sector/Block Protection Register Lock (SST, ST, ATMEL).
	 */
	if (xp->fdesc.protect_sector_cmd != 0) {
		for (fdata = 0; fdata < 0x10; fdata++) {
			(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR |
			    0x330 | xp->fdesc.protect_sector_cmd, fdata);
		}
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x330 |
		    xp->fdesc.protect_sector_cmd, 0x00400f);
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x330 |
		    xp->fdesc.protect_sector_cmd, 0x00600f);
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x330 |
		    xp->fdesc.protect_sector_cmd, 0x00800f);

		/* TODO: ??? */
		(void) ql_24xx_write_flash(ha,
		    FLASH_CONF_ADDR | 0x101, 0x80);
	} else {
		(void) ql_24xx_write_flash(ha,
		    FLASH_CONF_ADDR | 0x101, 0x9c);
	}

	/* Disable flash write. */
	if (!(CFG_IST(ha, CFG_CTRL_81XX))) {
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) & ~ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_dump_firmware
 *	Save RISC code state information.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	QL local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_dump_firmware(ql_adapter_state_t *vha)
{
	int			rval;
	clock_t			timer = drv_usectohz(30000000);
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	QL_DUMP_LOCK(ha);

	if (ha->ql_dump_state & QL_DUMPING ||
	    (ha->ql_dump_state & QL_DUMP_VALID &&
	    !(ha->ql_dump_state & QL_DUMP_UPLOADED))) {
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
		QL_DUMP_UNLOCK(ha);
		return (QL_SUCCESS);
	}

	QL_DUMP_UNLOCK(ha);

	ql_awaken_task_daemon(ha, NULL, DRIVER_STALL, 0);

	/*
	 * Wait for all outstanding commands to complete
	 */
	(void) ql_wait_outstanding(ha);

	/* Dump firmware. */
	rval = ql_binary_fw_dump(ha, TRUE);

	/* Do abort to force restart. */
	ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED, DRIVER_STALL);
	EL(ha, "restarting, isp_abort_needed\n");

	/* Acquire task daemon lock. */
	TASK_DAEMON_LOCK(ha);

	/* Wait for suspension to end. */
	while (ha->task_daemon_flags & QL_SUSPENDED) {
		ha->task_daemon_flags |= SUSPENDED_WAKEUP_FLG;

		/* 30 seconds from now */
		if (cv_reltimedwait(&ha->cv_dr_suspended,
		    &ha->task_daemon_mutex, timer, TR_CLOCK_TICK) == -1) {
			/*
			 * The timeout time 'timer' was
			 * reached without the condition
			 * being signaled.
			 */
			break;
		}
	}

	/* Release task daemon lock. */
	TASK_DAEMON_UNLOCK(ha);

	if (rval == QL_SUCCESS || rval == QL_DATA_EXISTS) {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	} else {
		EL(ha, "failed, rval = %xh\n", rval);
	}
	return (rval);
}

/*
 * ql_binary_fw_dump
 *	Dumps binary data from firmware.
 *
 * Input:
 *	ha = adapter state pointer.
 *	lock_needed = mailbox lock needed.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
int
ql_binary_fw_dump(ql_adapter_state_t *vha, int lock_needed)
{
	clock_t			timer;
	mbx_cmd_t		mc;
	mbx_cmd_t		*mcp = &mc;
	int			rval = QL_SUCCESS;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_8021)) {
		EL(ha, "8021 not supported\n");
		return (QL_NOT_SUPPORTED);
	}

	QL_DUMP_LOCK(ha);

	if (ha->ql_dump_state & QL_DUMPING ||
	    (ha->ql_dump_state & QL_DUMP_VALID &&
	    !(ha->ql_dump_state & QL_DUMP_UPLOADED))) {
		EL(ha, "dump already done, qds=%x\n", ha->ql_dump_state);
		QL_DUMP_UNLOCK(ha);
		return (QL_DATA_EXISTS);
	}

	ha->ql_dump_state &= ~(QL_DUMP_VALID | QL_DUMP_UPLOADED);
	ha->ql_dump_state |= QL_DUMPING;

	QL_DUMP_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE)) {

		/* Insert Time Stamp */
		rval = ql_fw_etrace(ha, &ha->fwexttracebuf,
		    FTO_INSERT_TIME_STAMP);
		if (rval != QL_SUCCESS) {
			EL(ha, "f/w extended trace insert"
			    "time stamp failed: %xh\n", rval);
		}
	}

	if (lock_needed == TRUE) {
		/* Acquire mailbox register lock. */
		MBX_REGISTER_LOCK(ha);
		timer = (ha->mcp->timeout + 2) * drv_usectohz(1000000);

		/* Check for mailbox available, if not wait for signal. */
		while (ha->mailbox_flags & MBX_BUSY_FLG) {
			ha->mailbox_flags = (uint8_t)
			    (ha->mailbox_flags | MBX_WANT_FLG);

			/* 30 seconds from now */
			if (cv_reltimedwait(&ha->cv_mbx_wait, &ha->mbx_mutex,
			    timer, TR_CLOCK_TICK) == -1) {
				/*
				 * The timeout time 'timer' was
				 * reached without the condition
				 * being signaled.
				 */

				/* Release mailbox register lock. */
				MBX_REGISTER_UNLOCK(ha);

				EL(ha, "failed, rval = %xh\n",
				    QL_FUNCTION_TIMEOUT);
				return (QL_FUNCTION_TIMEOUT);
			}
		}

		/* Set busy flag. */
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags | MBX_BUSY_FLG);
		mcp->timeout = 120;
		ha->mcp = mcp;

		/* Release mailbox register lock. */
		MBX_REGISTER_UNLOCK(ha);
	}

	/* Free previous dump buffer. */
	if (ha->ql_dump_ptr != NULL) {
		kmem_free(ha->ql_dump_ptr, ha->ql_dump_size);
		ha->ql_dump_ptr = NULL;
	}

	if (CFG_IST(ha, CFG_CTRL_2422)) {
		ha->ql_dump_size = (uint32_t)(sizeof (ql_24xx_fw_dump_t) +
		    ha->fw_ext_memory_size);
	} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
		ha->ql_dump_size = (uint32_t)(sizeof (ql_25xx_fw_dump_t) +
		    ha->fw_ext_memory_size);
	} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
		ha->ql_dump_size = (uint32_t)(sizeof (ql_81xx_fw_dump_t) +
		    ha->fw_ext_memory_size);
	} else {
		ha->ql_dump_size = sizeof (ql_fw_dump_t);
	}

	if ((ha->ql_dump_ptr = kmem_zalloc(ha->ql_dump_size, KM_NOSLEEP)) ==
	    NULL) {
		rval = QL_MEMORY_ALLOC_FAILED;
	} else {
		if (CFG_IST(ha, (CFG_CTRL_2300 | CFG_CTRL_6322))) {
			rval = ql_2300_binary_fw_dump(ha, ha->ql_dump_ptr);
		} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
			rval = ql_81xx_binary_fw_dump(ha, ha->ql_dump_ptr);
		} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
			rval = ql_25xx_binary_fw_dump(ha, ha->ql_dump_ptr);
		} else if (CFG_IST(ha, CFG_CTRL_2422)) {
			rval = ql_24xx_binary_fw_dump(ha, ha->ql_dump_ptr);
		} else {
			rval = ql_2200_binary_fw_dump(ha, ha->ql_dump_ptr);
		}
	}

	/* Reset ISP chip. */
	ql_reset_chip(ha);

	QL_DUMP_LOCK(ha);

	if (rval != QL_SUCCESS) {
		if (ha->ql_dump_ptr != NULL) {
			kmem_free(ha->ql_dump_ptr, ha->ql_dump_size);
			ha->ql_dump_ptr = NULL;
		}
		ha->ql_dump_state &= ~(QL_DUMPING | QL_DUMP_VALID |
		    QL_DUMP_UPLOADED);
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		ha->ql_dump_state &= ~(QL_DUMPING | QL_DUMP_UPLOADED);
		ha->ql_dump_state |= QL_DUMP_VALID;
		EL(ha, "done\n");
	}

	QL_DUMP_UNLOCK(ha);

	return (rval);
}

/*
 * ql_ascii_fw_dump
 *	Converts firmware binary dump to ascii.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bptr = buffer pointer.
 *
 * Returns:
 *	Amount of data buffer used.
 *
 * Context:
 *	Kernel context.
 */
size_t
ql_ascii_fw_dump(ql_adapter_state_t *vha, caddr_t bufp)
{
	uint32_t		cnt;
	caddr_t			bp;
	int			mbox_cnt;
	ql_adapter_state_t	*ha = vha->pha;
	ql_fw_dump_t		*fw = ha->ql_dump_ptr;

	if (CFG_IST(ha, CFG_CTRL_2422)) {
		return (ql_24xx_ascii_fw_dump(ha, bufp));
	} else if (CFG_IST(ha, CFG_CTRL_2581)) {
		return (ql_2581_ascii_fw_dump(ha, bufp));
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2300)) {
		(void) sprintf(bufp, "\nISP 2300IP ");
	} else if (CFG_IST(ha, CFG_CTRL_6322)) {
		(void) sprintf(bufp, "\nISP 6322FLX ");
	} else {
		(void) sprintf(bufp, "\nISP 2200IP ");
	}

	bp = bufp + strlen(bufp);
	(void) sprintf(bp, "Firmware Version %d.%d.%d\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version);

	(void) strcat(bufp, "\nPBIU Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->pbiu_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->pbiu_reg[cnt]);
		bp = bp + 6;
	}

	if (CFG_IST(ha, (CFG_CTRL_2300 | CFG_CTRL_6322))) {
		(void) strcat(bufp, "\n\nReqQ-RspQ-Risc2Host Status "
		    "registers:");
		bp = bufp + strlen(bufp);
		for (cnt = 0; cnt < sizeof (fw->risc_host_reg) / 2; cnt++) {
			if (cnt % 8 == 0) {
				*bp++ = '\n';
			}
			(void) sprintf(bp, "%04x  ", fw->risc_host_reg[cnt]);
			bp = bp + 6;
		}
	}

	(void) strcat(bp, "\n\nMailbox Registers:");
	bp = bufp + strlen(bufp);
	mbox_cnt = (CFG_IST(ha, (CFG_CTRL_2300 | CFG_CTRL_6322))) ? 16 : 8;
	for (cnt = 0; cnt < mbox_cnt; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->mailbox_reg[cnt]);
		bp = bp + 6;
	}

	if (CFG_IST(ha, (CFG_CTRL_2300 | CFG_CTRL_6322))) {
		(void) strcat(bp, "\n\nAuto Request Response DMA Registers:");
		bp = bufp + strlen(bufp);
		for (cnt = 0; cnt < sizeof (fw->resp_dma_reg) / 2; cnt++) {
			if (cnt % 8 == 0) {
				*bp++ = '\n';
			}
			(void) sprintf(bp, "%04x  ", fw->resp_dma_reg[cnt]);
			bp = bp + 6;
		}
	}

	(void) strcat(bp, "\n\nDMA Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->dma_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->dma_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC Hardware Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_hdw_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_hdw_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP0 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp0_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp0_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP1 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp1_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp1_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP2 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp2_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp2_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP3 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp3_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp3_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP4 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp4_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp4_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP5 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp5_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp5_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP6 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp6_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp6_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nRISC GP7 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp7_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->risc_gp7_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nFrame Buffer Hardware Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->frame_buf_hdw_reg) / 2; cnt++) {
		if ((cnt == 16) && ((CFG_IST(ha, (CFG_CTRL_2300 |
		    CFG_CTRL_6322)) == 0))) {
			break;
		}
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->frame_buf_hdw_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nFPM B0 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->fpm_b0_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->fpm_b0_reg[cnt]);
		bp = bp + 6;
	}

	(void) strcat(bp, "\n\nFPM B1 Registers:");
	bp = bufp + strlen(bufp);
	for (cnt = 0; cnt < sizeof (fw->fpm_b1_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->fpm_b1_reg[cnt]);
		bp = bp + 6;
	}

	if (CFG_IST(ha, (CFG_CTRL_2300 | CFG_CTRL_6322))) {
		(void) strcat(bp, "\n\nCode RAM Dump:");
		bp = bufp + strlen(bufp);
		for (cnt = 0; cnt < sizeof (fw->risc_ram) / 2; cnt++) {
			if (cnt % 8 == 0) {
				(void) sprintf(bp, "\n%05x: ", cnt + 0x0800);
				bp = bp + 8;
			}
			(void) sprintf(bp, "%04x  ", fw->risc_ram[cnt]);
			bp = bp + 6;
		}

		(void) strcat(bp, "\n\nStack RAM Dump:");
		bp = bufp + strlen(bufp);
		for (cnt = 0; cnt < sizeof (fw->stack_ram) / 2; cnt++) {
			if (cnt % 8 == 0) {
				(void) sprintf(bp, "\n%05x: ", cnt + 0x010000);
				bp = bp + 8;
			}
			(void) sprintf(bp, "%04x  ", fw->stack_ram[cnt]);
			bp = bp + 6;
		}

		(void) strcat(bp, "\n\nData RAM Dump:");
		bp = bufp + strlen(bufp);
		for (cnt = 0; cnt < sizeof (fw->data_ram) / 2; cnt++) {
			if (cnt % 8 == 0) {
				(void) sprintf(bp, "\n%05x: ", cnt + 0x010800);
				bp = bp + 8;
			}
			(void) sprintf(bp, "%04x  ", fw->data_ram[cnt]);
			bp = bp + 6;
		}
	} else {
		(void) strcat(bp, "\n\nRISC SRAM:");
		bp = bufp + strlen(bufp);
		for (cnt = 0; cnt < 0xf000; cnt++) {
			if (cnt % 8 == 0) {
				(void) sprintf(bp, "\n%04x: ", cnt + 0x1000);
				bp = bp + 7;
			}
			(void) sprintf(bp, "%04x  ", fw->risc_ram[cnt]);
			bp = bp + 6;
		}
	}

	(void) strcat(bp, "\n\n[<==END] ISP Debug Dump.");
	bp += strlen(bp);

	(void) sprintf(bp, "\n\nRequest Queue");
	bp += strlen(bp);
	for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt);
			bp += strlen(bp);
		}
		(void) sprintf(bp, "%08x ", fw->req_q[cnt]);
		bp += strlen(bp);
	}

	(void) sprintf(bp, "\n\nResponse Queue");
	bp += strlen(bp);
	for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt);
			bp += strlen(bp);
		}
		(void) sprintf(bp, "%08x ", fw->rsp_q[cnt]);
		bp += strlen(bp);
	}

	(void) sprintf(bp, "\n");

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (strlen(bufp));
}

/*
 * ql_24xx_ascii_fw_dump
 *	Converts ISP24xx firmware binary dump to ascii.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bptr = buffer pointer.
 *
 * Returns:
 *	Amount of data buffer used.
 *
 * Context:
 *	Kernel context.
 */
static size_t
ql_24xx_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t		cnt;
	caddr_t			bp = bufp;
	ql_24xx_fw_dump_t	*fw = ha->ql_dump_ptr;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	(void) sprintf(bp, "ISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);
	bp += strlen(bp);

	(void) sprintf(bp, "\nHCCR Register\n%08x\n", fw->hccr);

	(void) strcat(bp, "\nHost Interface Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->host_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->host_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nMailbox Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->mailbox_reg) / 2; cnt++) {
		if (cnt % 16 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%04x ", fw->mailbox_reg[cnt]);
		bp += 5;
	}

	(void) sprintf(bp, "\n\nXSEQ GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xseq_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXSEQ-0 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xseq_0_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXSEQ-1 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xseq_1_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->rseq_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ-0 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->rseq_0_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ-1 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->rseq_1_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ-2 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->rseq_2_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nCommand DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->cmd_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->cmd_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRequest0 Queue DMA Channel Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->req0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->req0_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nResponse0 Queue DMA Channel Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->resp0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->resp0_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRequest1 Queue DMA Channel Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->req1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->req1_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT0 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xmt0_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT1 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xmt1_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT2 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt2_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xmt2_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT3 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt3_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xmt3_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT4 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt4_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xmt4_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT Data DMA Common Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->xmt_data_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRCV Thread 0 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rcvt0_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->rcvt0_data_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRCV Thread 1 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rcvt1_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->rcvt1_data_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRISC GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->risc_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bufp + strlen(bufp), "\n\nShadow Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->shadow_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->shadow_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nLMC Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->lmc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->lmc_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nFPM Hardware Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->fpm_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->fpm_hdw_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nFB Hardware Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->fb_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}

		(void) sprintf(bp, "%08x ", fw->fb_hdw_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nCode RAM");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->code_ram) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt + 0x20000);
			bp += 11;
		}

		(void) sprintf(bp, "%08x ", fw->code_ram[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nExternal Memory");
	bp += strlen(bp);
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt + 0x100000);
			bp += 11;
		}
		(void) sprintf(bp, "%08x ", fw->ext_mem[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n[<==END] ISP Debug Dump");
	bp += strlen(bp);

	(void) sprintf(bp, "\n\nRequest Queue");
	bp += strlen(bp);
	for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt);
			bp += strlen(bp);
		}
		(void) sprintf(bp, "%08x ", fw->req_q[cnt]);
		bp += strlen(bp);
	}

	(void) sprintf(bp, "\n\nResponse Queue");
	bp += strlen(bp);
	for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt);
			bp += strlen(bp);
		}
		(void) sprintf(bp, "%08x ", fw->rsp_q[cnt]);
		bp += strlen(bp);
	}

	if (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE) &&
	    (ha->fwexttracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint64_t w64 = (uintptr_t)ha->fwexttracebuf.bp;

		(void) sprintf(bp, "\n\nExtended Trace Buffer Memory");
		bp += strlen(bp);
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				(void) sprintf(bp, "\n%08x: ",
				    (int)(w64 + cnt_b));
				bp += 11;
			}
			(void) sprintf(bp, "%08x ", fw->ext_trace_buf[cnt]);
			bp += 9;
		}
	}

	if (CFG_IST(ha, CFG_ENABLE_FWFCETRACE) &&
	    (ha->fwfcetracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint64_t w64 = (uintptr_t)ha->fwfcetracebuf.bp;

		(void) sprintf(bp, "\n\nFC Event Trace Buffer Memory");
		bp += strlen(bp);
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				(void) sprintf(bp, "\n%08x: ",
				    (int)(w64 + cnt_b));
				bp += 11;
			}
			(void) sprintf(bp, "%08x ", fw->fce_trace_buf[cnt]);
			bp += 9;
		}
	}

	(void) sprintf(bp, "\n\n");
	bp += strlen(bp);

	cnt = (uint32_t)((uintptr_t)bp - (uintptr_t)bufp);

	QL_PRINT_3(CE_CONT, "(%d): done=%xh\n", ha->instance, cnt);

	return (cnt);
}

/*
 * ql_2581_ascii_fw_dump
 *	Converts ISP25xx or ISP81xx firmware binary dump to ascii.
 *
 * Input:
 *	ha = adapter state pointer.
 *	bptr = buffer pointer.
 *
 * Returns:
 *	Amount of data buffer used.
 *
 * Context:
 *	Kernel context.
 */
static size_t
ql_2581_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t		cnt;
	uint32_t		cnt1;
	caddr_t			bp = bufp;
	ql_25xx_fw_dump_t	*fw = ha->ql_dump_ptr;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	(void) sprintf(bp, "\nISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);
	bp += strlen(bp);

	(void) sprintf(bp, "\nR2H Status Register\n%08x\n", fw->r2h_status);
	bp += strlen(bp);

	(void) sprintf(bp, "\nHostRisc Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->hostrisc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->hostrisc_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nPCIe Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->pcie_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->pcie_reg[cnt]);
		bp += 9;
	}

	(void) strcat(bp, "\n\nHost Interface Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->host_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->host_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bufp + strlen(bufp), "\n\nShadow Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->shadow_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->shadow_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bufp + strlen(bufp), "\n\nRISC IO Register\n%08x",
	    fw->risc_io);
	bp += strlen(bp);

	(void) sprintf(bp, "\n\nMailbox Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->mailbox_reg) / 2; cnt++) {
		if (cnt % 16 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%04x ", fw->mailbox_reg[cnt]);
		bp += 5;
	}

	(void) sprintf(bp, "\n\nXSEQ GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xseq_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXSEQ-0 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xseq_0_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXSEQ-1 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xseq_1_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->rseq_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ-0 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->rseq_0_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ-1 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->rseq_1_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRSEQ-2 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->rseq_2_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nASEQ GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->aseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->aseq_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nASEQ-0 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->aseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->aseq_0_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nASEQ-1 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->aseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->aseq_1_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nASEQ-2 Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->aseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->aseq_2_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nCommand DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->cmd_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void)  sprintf(bp, "%08x ", fw->cmd_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRequest0 Queue DMA Channel Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->req0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->req0_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nResponse0 Queue DMA Channel Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->resp0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->resp0_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRequest1 Queue DMA Channel Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->req1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->req1_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT0 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xmt0_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT1 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xmt1_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT2 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt2_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xmt2_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT3 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt3_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xmt3_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT4 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt4_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xmt4_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nXMT Data DMA Common Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->xmt_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->xmt_data_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRCV Thread 0 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rcvt0_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->rcvt0_data_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRCV Thread 1 Data DMA Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->rcvt1_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->rcvt1_data_dma_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nRISC GP Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->risc_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->risc_gp_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nLMC Registers");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->lmc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->lmc_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nFPM Hardware Registers");
	bp += strlen(bp);
	cnt1 = CFG_IST(ha, CFG_CTRL_81XX) ?
	    (uint32_t)(sizeof (((ql_81xx_fw_dump_t *)(fw))->fpm_hdw_reg)) :
	    (uint32_t)(sizeof (fw->fpm_hdw_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->fpm_hdw_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nFB Hardware Registers");
	bp += strlen(bp);
	cnt1 = CFG_IST(ha, CFG_CTRL_81XX) ?
	    (uint32_t)(sizeof (((ql_81xx_fw_dump_t *)(fw))->fb_hdw_reg)) :
	    (uint32_t)(sizeof (fw->fb_hdw_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->fb_hdw_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nCode RAM");
	bp += strlen(bp);
	for (cnt = 0; cnt < sizeof (fw->code_ram) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt + 0x20000);
			bp += 11;
		}
		(void) sprintf(bp, "%08x ", fw->code_ram[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nExternal Memory");
	bp += strlen(bp);
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt + 0x100000);
			bp += 11;
		}
		(void) sprintf(bp, "%08x ", fw->ext_mem[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n[<==END] ISP Debug Dump");
	bp += strlen(bp);

	(void) sprintf(bp, "\n\nRequest Queue");
	bp += strlen(bp);
	for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt);
			bp += strlen(bp);
		}
		(void) sprintf(bp, "%08x ", fw->req_q[cnt]);
		bp += strlen(bp);
	}

	(void) sprintf(bp, "\n\nResponse Queue");
	bp += strlen(bp);
	for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt);
			bp += strlen(bp);
		}
		(void) sprintf(bp, "%08x ", fw->rsp_q[cnt]);
		bp += strlen(bp);
	}

	if (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE) &&
	    (ha->fwexttracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint64_t w64 = (uintptr_t)ha->fwexttracebuf.bp;

		(void) sprintf(bp, "\n\nExtended Trace Buffer Memory");
		bp += strlen(bp);
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				(void) sprintf(bp, "\n%08x: ",
				    (int)(w64 + cnt_b));
				bp += 11;
			}
			(void) sprintf(bp, "%08x ", fw->ext_trace_buf[cnt]);
			bp += 9;
		}
	}

	if (CFG_IST(ha, CFG_ENABLE_FWFCETRACE) &&
	    (ha->fwfcetracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint64_t w64 = (uintptr_t)ha->fwfcetracebuf.bp;

		(void) sprintf(bp, "\n\nFC Event Trace Buffer Memory");
		bp += strlen(bp);
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				(void) sprintf(bp, "\n%08x: ",
				    (int)(w64 + cnt_b));
				bp += 11;
			}
			(void) sprintf(bp, "%08x ", fw->fce_trace_buf[cnt]);
			bp += 9;
		}
	}

	(void) sprintf(bp, "\n\n");
	bp += strlen(bp);

	cnt = (uint32_t)((uintptr_t)bp - (uintptr_t)bufp);

	QL_PRINT_3(CE_CONT, "(%d): done=%xh\n", ha->instance, cnt);

	return (cnt);
}

/*
 * ql_2200_binary_fw_dump
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fw:	firmware dump context pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_2200_binary_fw_dump(ql_adapter_state_t *ha, ql_fw_dump_t *fw)
{
	uint32_t	cnt;
	uint16_t	risc_address;
	clock_t		timer;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Disable ISP interrupts. */
	WRT16_IO_REG(ha, ictrl, 0);
	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~INTERRUPTS_ENABLED;
	ADAPTER_STATE_UNLOCK(ha);

	/* Release mailbox registers. */
	WRT16_IO_REG(ha, semaphore, 0);

	/* Pause RISC. */
	WRT16_IO_REG(ha, hccr, HC_PAUSE_RISC);
	timer = 30000;
	while ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) == 0) {
		if (timer-- != 0) {
			drv_usecwait(MILLISEC);
		} else {
			rval = QL_FUNCTION_TIMEOUT;
			break;
		}
	}

	if (rval == QL_SUCCESS) {
		(void) ql_read_regs(ha, fw->pbiu_reg, ha->iobase,
		    sizeof (fw->pbiu_reg) / 2, 16);

		/* In 2200 we only read 8 mailboxes */
		(void) ql_read_regs(ha, fw->mailbox_reg, ha->iobase + 0x10,
		    8, 16);

		(void) ql_read_regs(ha, fw->dma_reg, ha->iobase + 0x20,
		    sizeof (fw->dma_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0);
		(void) ql_read_regs(ha, fw->risc_hdw_reg, ha->iobase + 0xA0,
		    sizeof (fw->risc_hdw_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2000);
		(void) ql_read_regs(ha, fw->risc_gp0_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp0_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2100);
		(void) ql_read_regs(ha, fw->risc_gp1_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp1_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2200);
		(void) ql_read_regs(ha, fw->risc_gp2_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp2_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2300);
		(void) ql_read_regs(ha, fw->risc_gp3_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp3_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2400);
		(void) ql_read_regs(ha, fw->risc_gp4_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp4_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2500);
		(void) ql_read_regs(ha, fw->risc_gp5_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp5_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2600);
		(void) ql_read_regs(ha, fw->risc_gp6_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp6_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2700);
		(void) ql_read_regs(ha, fw->risc_gp7_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp7_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x10);
		/* 2200 has only 16 registers */
		(void) ql_read_regs(ha, fw->frame_buf_hdw_reg,
		    ha->iobase + 0x80, 16, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x20);
		(void) ql_read_regs(ha, fw->fpm_b0_reg, ha->iobase + 0x80,
		    sizeof (fw->fpm_b0_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x30);
		(void) ql_read_regs(ha, fw->fpm_b1_reg, ha->iobase + 0x80,
		    sizeof (fw->fpm_b1_reg) / 2, 16);

		/* Select FPM registers. */
		WRT16_IO_REG(ha, ctrl_status, 0x20);

		/* FPM Soft Reset. */
		WRT16_IO_REG(ha, fpm_diag_config, 0x100);

		/* Select frame buffer registers. */
		WRT16_IO_REG(ha, ctrl_status, 0x10);

		/* Reset frame buffer FIFOs. */
		WRT16_IO_REG(ha, fb_cmd, 0xa000);

		/* Select RISC module registers. */
		WRT16_IO_REG(ha, ctrl_status, 0);

		/* Reset RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RESET_RISC);

		/* Reset ISP semaphore. */
		WRT16_IO_REG(ha, semaphore, 0);

		/* Release RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);

		/* Wait for RISC to recover from reset. */
		timer = 30000;
		while (RD16_IO_REG(ha, mailbox_out[0]) == MBS_BUSY) {
			if (timer-- != 0) {
				drv_usecwait(MILLISEC);
			} else {
				rval = QL_FUNCTION_TIMEOUT;
				break;
			}
		}

		/* Disable RISC pause on FPM parity error. */
		WRT16_IO_REG(ha, hccr, HC_DISABLE_PARITY_PAUSE);
	}

	if (rval == QL_SUCCESS) {
		/* Pause RISC. */
		WRT16_IO_REG(ha, hccr, HC_PAUSE_RISC);
		timer = 30000;
		while ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) == 0) {
			if (timer-- != 0) {
				drv_usecwait(MILLISEC);
			} else {
				rval = QL_FUNCTION_TIMEOUT;
				break;
			}
		}
	}

	if (rval == QL_SUCCESS) {
		/* Set memory configuration and timing. */
		WRT16_IO_REG(ha, mctr, 0xf2);

		/* Release RISC. */
		WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);

		/* Get RISC SRAM. */
		risc_address = 0x1000;
		WRT16_IO_REG(ha, mailbox_in[0], MBC_READ_RAM_WORD);
		for (cnt = 0; cnt < 0xf000; cnt++) {
			WRT16_IO_REG(ha, mailbox_in[1], risc_address++);
			WRT16_IO_REG(ha, hccr, HC_SET_HOST_INT);
			for (timer = 6000000; timer != 0; timer--) {
				/* Check for pending interrupts. */
				if (INTERRUPT_PENDING(ha)) {
					if (RD16_IO_REG(ha, semaphore) &
					    BIT_0) {
						WRT16_IO_REG(ha, hccr,
						    HC_CLR_RISC_INT);
						mcp->mb[0] = RD16_IO_REG(ha,
						    mailbox_out[0]);
						fw->risc_ram[cnt] =
						    RD16_IO_REG(ha,
						    mailbox_out[2]);
						WRT16_IO_REG(ha,
						    semaphore, 0);
						break;
					}
					WRT16_IO_REG(ha, hccr,
					    HC_CLR_RISC_INT);
				}
				drv_usecwait(5);
			}

			if (timer == 0) {
				rval = QL_FUNCTION_TIMEOUT;
			} else {
				rval = mcp->mb[0];
			}

			if (rval != QL_SUCCESS) {
				break;
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_2300_binary_fw_dump
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fw:	firmware dump context pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_2300_binary_fw_dump(ql_adapter_state_t *ha, ql_fw_dump_t *fw)
{
	clock_t	timer;
	int	rval = QL_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Disable ISP interrupts. */
	WRT16_IO_REG(ha, ictrl, 0);
	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~INTERRUPTS_ENABLED;
	ADAPTER_STATE_UNLOCK(ha);

	/* Release mailbox registers. */
	WRT16_IO_REG(ha, semaphore, 0);

	/* Pause RISC. */
	WRT16_IO_REG(ha, hccr, HC_PAUSE_RISC);
	timer = 30000;
	while ((RD16_IO_REG(ha, hccr) & HC_RISC_PAUSE) == 0) {
		if (timer-- != 0) {
			drv_usecwait(MILLISEC);
		} else {
			rval = QL_FUNCTION_TIMEOUT;
			break;
		}
	}

	if (rval == QL_SUCCESS) {
		(void) ql_read_regs(ha, fw->pbiu_reg, ha->iobase,
		    sizeof (fw->pbiu_reg) / 2, 16);

		(void) ql_read_regs(ha, fw->risc_host_reg, ha->iobase + 0x10,
		    sizeof (fw->risc_host_reg) / 2, 16);

		(void) ql_read_regs(ha, fw->mailbox_reg, ha->iobase + 0x40,
		    sizeof (fw->mailbox_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x40);
		(void) ql_read_regs(ha, fw->resp_dma_reg, ha->iobase + 0x80,
		    sizeof (fw->resp_dma_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x50);
		(void) ql_read_regs(ha, fw->dma_reg, ha->iobase + 0x80,
		    sizeof (fw->dma_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0);
		(void) ql_read_regs(ha, fw->risc_hdw_reg, ha->iobase + 0xA0,
		    sizeof (fw->risc_hdw_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2000);
		(void) ql_read_regs(ha, fw->risc_gp0_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp0_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2200);
		(void) ql_read_regs(ha, fw->risc_gp1_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp1_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2400);
		(void) ql_read_regs(ha, fw->risc_gp2_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp2_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2600);
		(void) ql_read_regs(ha, fw->risc_gp3_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp3_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2800);
		(void) ql_read_regs(ha, fw->risc_gp4_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp4_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2A00);
		(void) ql_read_regs(ha, fw->risc_gp5_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp5_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2C00);
		(void) ql_read_regs(ha, fw->risc_gp6_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp6_reg) / 2, 16);

		WRT16_IO_REG(ha, pcr, 0x2E00);
		(void) ql_read_regs(ha, fw->risc_gp7_reg, ha->iobase + 0x80,
		    sizeof (fw->risc_gp7_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x10);
		(void) ql_read_regs(ha, fw->frame_buf_hdw_reg,
		    ha->iobase + 0x80, sizeof (fw->frame_buf_hdw_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x20);
		(void) ql_read_regs(ha, fw->fpm_b0_reg, ha->iobase + 0x80,
		    sizeof (fw->fpm_b0_reg) / 2, 16);

		WRT16_IO_REG(ha, ctrl_status, 0x30);
		(void) ql_read_regs(ha, fw->fpm_b1_reg, ha->iobase + 0x80,
		    sizeof (fw->fpm_b1_reg) / 2, 16);

		/* Select FPM registers. */
		WRT16_IO_REG(ha, ctrl_status, 0x20);

		/* FPM Soft Reset. */
		WRT16_IO_REG(ha, fpm_diag_config, 0x100);

		/* Select frame buffer registers. */
		WRT16_IO_REG(ha, ctrl_status, 0x10);

		/* Reset frame buffer FIFOs. */
		WRT16_IO_REG(ha, fb_cmd, 0xa000);

		/* Select RISC module registers. */
		WRT16_IO_REG(ha, ctrl_status, 0);

		/* Reset RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RESET_RISC);

		/* Reset ISP semaphore. */
		WRT16_IO_REG(ha, semaphore, 0);

		/* Release RISC module. */
		WRT16_IO_REG(ha, hccr, HC_RELEASE_RISC);

		/* Wait for RISC to recover from reset. */
		timer = 30000;
		while (RD16_IO_REG(ha, mailbox_out[0]) == MBS_BUSY) {
			if (timer-- != 0) {
				drv_usecwait(MILLISEC);
			} else {
				rval = QL_FUNCTION_TIMEOUT;
				break;
			}
		}

		/* Disable RISC pause on FPM parity error. */
		WRT16_IO_REG(ha, hccr, HC_DISABLE_PARITY_PAUSE);
	}

	/* Get RISC SRAM. */
	if (rval == QL_SUCCESS) {
		rval = ql_read_risc_ram(ha, 0x800, 0xf800, fw->risc_ram);
	}
	/* Get STACK SRAM. */
	if (rval == QL_SUCCESS) {
		rval = ql_read_risc_ram(ha, 0x10000, 0x800, fw->stack_ram);
	}
	/* Get DATA SRAM. */
	if (rval == QL_SUCCESS) {
		rval = ql_read_risc_ram(ha, 0x10800, 0xf800, fw->data_ram);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_24xx_binary_fw_dump
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fw:	firmware dump context pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_24xx_binary_fw_dump(ql_adapter_state_t *ha, ql_24xx_fw_dump_t *fw)
{
	uint32_t	*reg32;
	void		*bp;
	clock_t		timer;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	fw->hccr = RD32_IO_REG(ha, hccr);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		/* Disable ISP interrupts. */
		WRT16_IO_REG(ha, ictrl, 0);

		WRT32_IO_REG(ha, hccr, HC24_PAUSE_RISC);
		for (timer = 30000;
		    (RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0 &&
		    rval == QL_SUCCESS; timer--) {
			if (timer) {
				drv_usecwait(100);
			} else {
				rval = QL_FUNCTION_TIMEOUT;
			}
		}
	}

	if (rval == QL_SUCCESS) {
		/* Host interface registers. */
		(void) ql_read_regs(ha, fw->host_reg, ha->iobase,
		    sizeof (fw->host_reg) / 4, 32);

		/* Disable ISP interrupts. */
		WRT32_IO_REG(ha, ictrl, 0);
		RD32_IO_REG(ha, ictrl);
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~INTERRUPTS_ENABLED;
		ADAPTER_STATE_UNLOCK(ha);

		/* Shadow registers. */

		WRT32_IO_REG(ha, io_base_addr, 0x0F70);
		RD32_IO_REG(ha, io_base_addr);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0000000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[0] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0100000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[1] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0200000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[2] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0300000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[3] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0400000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[4] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0500000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[5] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0600000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[6] = RD_REG_DWORD(ha, reg32);

		/* Mailbox registers. */
		(void) ql_read_regs(ha, fw->mailbox_reg, ha->iobase + 0x80,
		    sizeof (fw->mailbox_reg) / 2, 16);

		/* Transfer sequence registers. */

		/* XSEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xBF00);
		bp = ql_read_regs(ha, fw->xseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XSEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xBFE0);
		(void) ql_read_regs(ha, fw->xseq_0_reg, ha->iobase + 0xC0,
		    sizeof (fw->xseq_0_reg) / 4, 32);

		/* XSEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xBFF0);
		(void) ql_read_regs(ha, fw->xseq_1_reg, ha->iobase + 0xC0,
		    sizeof (fw->xseq_1_reg) / 4, 32);

		/* Receive sequence registers. */

		/* RSEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xFF00);
		bp = ql_read_regs(ha, fw->rseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RSEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFD0);
		(void) ql_read_regs(ha, fw->rseq_0_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_0_reg) / 4, 32);

		/* RSEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFE0);
		(void) ql_read_regs(ha, fw->rseq_1_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_1_reg) / 4, 32);

		/* RSEQ-2 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFF0);
		(void) ql_read_regs(ha, fw->rseq_2_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_2_reg) / 4, 32);

		/* Command DMA registers. */

		WRT32_IO_REG(ha, io_base_addr, 0x7100);
		(void) ql_read_regs(ha, fw->cmd_dma_reg, ha->iobase + 0xC0,
		    sizeof (fw->cmd_dma_reg) / 4, 32);

		/* Queues. */

		/* RequestQ0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7200);
		bp = ql_read_regs(ha, fw->req0_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* ResponseQ0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7300);
		bp = ql_read_regs(ha, fw->resp0_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* RequestQ1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7400);
		bp = ql_read_regs(ha, fw->req1_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* Transmit DMA registers. */

		/* XMT0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7600);
		bp = ql_read_regs(ha, fw->xmt0_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7610);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7620);
		bp = ql_read_regs(ha, fw->xmt1_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7630);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT2 */
		WRT32_IO_REG(ha, io_base_addr, 0x7640);
		bp = ql_read_regs(ha, fw->xmt2_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7650);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT3 */
		WRT32_IO_REG(ha, io_base_addr, 0x7660);
		bp = ql_read_regs(ha, fw->xmt3_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7670);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT4 */
		WRT32_IO_REG(ha, io_base_addr, 0x7680);
		bp = ql_read_regs(ha, fw->xmt4_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7690);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT Common */
		WRT32_IO_REG(ha, io_base_addr, 0x76A0);
		(void) ql_read_regs(ha, fw->xmt_data_dma_reg,
		    ha->iobase + 0xC0, sizeof (fw->xmt_data_dma_reg) / 4, 32);

		/* Receive DMA registers. */

		/* RCVThread0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7700);
		bp = ql_read_regs(ha, fw->rcvt0_data_dma_reg,
		    ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7710);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RCVThread1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7720);
		bp = ql_read_regs(ha, fw->rcvt1_data_dma_reg,
		    ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7730);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RISC registers. */

		/* RISC GP */
		WRT32_IO_REG(ha, io_base_addr, 0x0F00);
		bp = ql_read_regs(ha, fw->risc_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Local memory controller registers. */

		/* LMC */
		WRT32_IO_REG(ha, io_base_addr, 0x3000);
		bp = ql_read_regs(ha, fw->lmc_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3060);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Fibre Protocol Module registers. */

		/* FPM hardware */
		WRT32_IO_REG(ha, io_base_addr, 0x4000);
		bp = ql_read_regs(ha, fw->fpm_hdw_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4070);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4080);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4090);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40A0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40B0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Frame Buffer registers. */

		/* FB hardware */
		WRT32_IO_REG(ha, io_base_addr, 0x6000);
		bp = ql_read_regs(ha, fw->fb_hdw_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6100);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6130);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6150);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6170);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6190);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x61B0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	}

	/* Get the request queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 = (uint32_t *)ha->request_ring_bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    REQUEST_Q_BUFFER_OFFSET, sizeof (fw->req_q),
		    DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->req_q) / 4; cnt++) {
			fw->req_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->req_q[cnt]);
		}
	}

	/* Get the response queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 = (uint32_t *)ha->response_ring_bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    RESPONSE_Q_BUFFER_OFFSET, sizeof (fw->rsp_q),
		    DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->rsp_q) / 4; cnt++) {
			fw->rsp_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->rsp_q[cnt]);
		}
	}

	/* Reset RISC. */
	ql_reset_chip(ha);

	/* Memory. */
	if (rval == QL_SUCCESS) {
		/* Code RAM. */
		rval = ql_read_risc_ram(ha, 0x20000,
		    sizeof (fw->code_ram) / 4, fw->code_ram);
	}
	if (rval == QL_SUCCESS) {
		/* External Memory. */
		rval = ql_read_risc_ram(ha, 0x100000,
		    ha->fw_ext_memory_size / 4, fw->ext_mem);
	}

	/* Get the extended trace buffer */
	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE) &&
		    (ha->fwexttracebuf.bp != NULL)) {
			uint32_t	cnt;
			uint32_t	*w32 = ha->fwexttracebuf.bp;

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(ha->fwexttracebuf.dma_handle, 0,
			    FWEXTSIZE, DDI_DMA_SYNC_FORKERNEL);

			for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
				fw->ext_trace_buf[cnt] = *w32++;
			}
		}
	}

	/* Get the FC event trace buffer */
	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ENABLE_FWFCETRACE) &&
		    (ha->fwfcetracebuf.bp != NULL)) {
			uint32_t	cnt;
			uint32_t	*w32 = ha->fwfcetracebuf.bp;

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(ha->fwfcetracebuf.dma_handle, 0,
			    FWFCESIZE, DDI_DMA_SYNC_FORKERNEL);

			for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
				fw->fce_trace_buf[cnt] = *w32++;
			}
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_25xx_binary_fw_dump
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fw:	firmware dump context pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_25xx_binary_fw_dump(ql_adapter_state_t *ha, ql_25xx_fw_dump_t *fw)
{
	uint32_t	*reg32;
	void		*bp;
	clock_t		timer;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	fw->r2h_status = RD32_IO_REG(ha, risc2host);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		/* Disable ISP interrupts. */
		WRT16_IO_REG(ha, ictrl, 0);

		WRT32_IO_REG(ha, hccr, HC24_PAUSE_RISC);
		for (timer = 30000;
		    (RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0 &&
		    rval == QL_SUCCESS; timer--) {
			if (timer) {
				drv_usecwait(100);
				if (timer % 10000 == 0) {
					EL(ha, "risc pause %d\n", timer);
				}
			} else {
				EL(ha, "risc pause timeout\n");
				rval = QL_FUNCTION_TIMEOUT;
			}
		}
	}

	if (rval == QL_SUCCESS) {

		/* Host Interface registers */

		/* HostRisc registers. */
		WRT32_IO_REG(ha, io_base_addr, 0x7000);
		bp = ql_read_regs(ha, fw->hostrisc_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* PCIe registers. */
		WRT32_IO_REG(ha, io_base_addr, 0x7c00);
		WRT_REG_DWORD(ha, ha->iobase + 0xc0, 0x1);
		bp = ql_read_regs(ha, fw->pcie_reg, ha->iobase + 0xC4,
		    3, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 1, 32);
		WRT_REG_DWORD(ha, ha->iobase + 0xc0, 0x0);

		/* Host interface registers. */
		(void) ql_read_regs(ha, fw->host_reg, ha->iobase,
		    sizeof (fw->host_reg) / 4, 32);

		/* Disable ISP interrupts. */

		WRT32_IO_REG(ha, ictrl, 0);
		RD32_IO_REG(ha, ictrl);
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~INTERRUPTS_ENABLED;
		ADAPTER_STATE_UNLOCK(ha);

		/* Shadow registers. */

		WRT32_IO_REG(ha, io_base_addr, 0x0F70);
		RD32_IO_REG(ha, io_base_addr);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0000000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[0] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0100000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[1] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0200000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[2] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0300000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[3] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0400000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[4] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0500000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[5] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0600000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[6] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0700000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[7] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0800000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[8] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0900000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[9] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0A00000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[0xa] = RD_REG_DWORD(ha, reg32);

		/* RISC I/O register. */

		WRT32_IO_REG(ha, io_base_addr, 0x0010);
		(void) ql_read_regs(ha, &fw->risc_io, ha->iobase + 0xC0,
		    1, 32);

		/* Mailbox registers. */

		(void) ql_read_regs(ha, fw->mailbox_reg, ha->iobase + 0x80,
		    sizeof (fw->mailbox_reg) / 2, 16);

		/* Transfer sequence registers. */

		/* XSEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xBF00);
		bp = ql_read_regs(ha, fw->xseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XSEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xBFC0);
		bp = ql_read_regs(ha, fw->xseq_0_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBFD0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBFE0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XSEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xBFF0);
		(void) ql_read_regs(ha, fw->xseq_1_reg, ha->iobase + 0xC0,
		    16, 32);

		/* Receive sequence registers. */

		/* RSEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xFF00);
		bp = ql_read_regs(ha, fw->rseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RSEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFC0);
		bp = ql_read_regs(ha, fw->rseq_0_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFFD0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RSEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFE0);
		(void) ql_read_regs(ha, fw->rseq_1_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_1_reg) / 4, 32);

		/* RSEQ-2 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFF0);
		(void) ql_read_regs(ha, fw->rseq_2_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_2_reg) / 4, 32);

		/* Auxiliary sequencer registers. */

		/* ASEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xB000);
		bp = ql_read_regs(ha, fw->aseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB070);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* ASEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xB0C0);
		bp = ql_read_regs(ha, fw->aseq_0_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB0D0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* ASEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xB0E0);
		(void) ql_read_regs(ha, fw->aseq_1_reg, ha->iobase + 0xC0,
		    16, 32);

		/* ASEQ-2 */
		WRT32_IO_REG(ha, io_base_addr, 0xB0F0);
		(void) ql_read_regs(ha, fw->aseq_2_reg, ha->iobase + 0xC0,
		    16, 32);

		/* Command DMA registers. */

		WRT32_IO_REG(ha, io_base_addr, 0x7100);
		(void) ql_read_regs(ha, fw->cmd_dma_reg, ha->iobase + 0xC0,
		    sizeof (fw->cmd_dma_reg) / 4, 32);

		/* Queues. */

		/* RequestQ0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7200);
		bp = ql_read_regs(ha, fw->req0_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* ResponseQ0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7300);
		bp = ql_read_regs(ha, fw->resp0_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* RequestQ1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7400);
		bp = ql_read_regs(ha, fw->req1_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* Transmit DMA registers. */

		/* XMT0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7600);
		bp = ql_read_regs(ha, fw->xmt0_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7610);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7620);
		bp = ql_read_regs(ha, fw->xmt1_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7630);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT2 */
		WRT32_IO_REG(ha, io_base_addr, 0x7640);
		bp = ql_read_regs(ha, fw->xmt2_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7650);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT3 */
		WRT32_IO_REG(ha, io_base_addr, 0x7660);
		bp = ql_read_regs(ha, fw->xmt3_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7670);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT4 */
		WRT32_IO_REG(ha, io_base_addr, 0x7680);
		bp = ql_read_regs(ha, fw->xmt4_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7690);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT Common */
		WRT32_IO_REG(ha, io_base_addr, 0x76A0);
		(void) ql_read_regs(ha, fw->xmt_data_dma_reg,
		    ha->iobase + 0xC0, sizeof (fw->xmt_data_dma_reg) / 4, 32);

		/* Receive DMA registers. */

		/* RCVThread0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7700);
		bp = ql_read_regs(ha, fw->rcvt0_data_dma_reg,
		    ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7710);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RCVThread1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7720);
		bp = ql_read_regs(ha, fw->rcvt1_data_dma_reg,
		    ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7730);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RISC registers. */

		/* RISC GP */
		WRT32_IO_REG(ha, io_base_addr, 0x0F00);
		bp = ql_read_regs(ha, fw->risc_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Local memory controller (LMC) registers. */

		/* LMC */
		WRT32_IO_REG(ha, io_base_addr, 0x3000);
		bp = ql_read_regs(ha, fw->lmc_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3070);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Fibre Protocol Module registers. */

		/* FPM hardware */
		WRT32_IO_REG(ha, io_base_addr, 0x4000);
		bp = ql_read_regs(ha, fw->fpm_hdw_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4070);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4080);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4090);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40A0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40B0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Frame Buffer registers. */

		/* FB hardware */
		WRT32_IO_REG(ha, io_base_addr, 0x6000);
		bp = ql_read_regs(ha, fw->fb_hdw_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6100);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6130);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6150);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6170);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6190);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x61B0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6F00);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	}

	/* Get the request queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 = (uint32_t *)ha->request_ring_bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    REQUEST_Q_BUFFER_OFFSET, sizeof (fw->req_q),
		    DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->req_q) / 4; cnt++) {
			fw->req_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->req_q[cnt]);
		}
	}

	/* Get the respons queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 = (uint32_t *)ha->response_ring_bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    RESPONSE_Q_BUFFER_OFFSET, sizeof (fw->rsp_q),
		    DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->rsp_q) / 4; cnt++) {
			fw->rsp_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->rsp_q[cnt]);
		}
	}

	/* Reset RISC. */

	ql_reset_chip(ha);

	/* Memory. */

	if (rval == QL_SUCCESS) {
		/* Code RAM. */
		rval = ql_read_risc_ram(ha, 0x20000,
		    sizeof (fw->code_ram) / 4, fw->code_ram);
	}
	if (rval == QL_SUCCESS) {
		/* External Memory. */
		rval = ql_read_risc_ram(ha, 0x100000,
		    ha->fw_ext_memory_size / 4, fw->ext_mem);
	}

	/* Get the FC event trace buffer */
	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ENABLE_FWFCETRACE) &&
		    (ha->fwfcetracebuf.bp != NULL)) {
			uint32_t	cnt;
			uint32_t	*w32 = ha->fwfcetracebuf.bp;

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(ha->fwfcetracebuf.dma_handle, 0,
			    FWFCESIZE, DDI_DMA_SYNC_FORKERNEL);

			for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
				fw->fce_trace_buf[cnt] = *w32++;
			}
		}
	}

	/* Get the extended trace buffer */
	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE) &&
		    (ha->fwexttracebuf.bp != NULL)) {
			uint32_t	cnt;
			uint32_t	*w32 = ha->fwexttracebuf.bp;

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(ha->fwexttracebuf.dma_handle, 0,
			    FWEXTSIZE, DDI_DMA_SYNC_FORKERNEL);

			for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
				fw->ext_trace_buf[cnt] = *w32++;
			}
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_81xx_binary_fw_dump
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fw:	firmware dump context pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_81xx_binary_fw_dump(ql_adapter_state_t *ha, ql_81xx_fw_dump_t *fw)
{
	uint32_t	*reg32;
	void		*bp;
	clock_t		timer;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	fw->r2h_status = RD32_IO_REG(ha, risc2host);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		/* Disable ISP interrupts. */
		WRT16_IO_REG(ha, ictrl, 0);

		WRT32_IO_REG(ha, hccr, HC24_PAUSE_RISC);
		for (timer = 30000;
		    (RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0 &&
		    rval == QL_SUCCESS; timer--) {
			if (timer) {
				drv_usecwait(100);
				if (timer % 10000 == 0) {
					EL(ha, "risc pause %d\n", timer);
				}
			} else {
				EL(ha, "risc pause timeout\n");
				rval = QL_FUNCTION_TIMEOUT;
			}
		}
	}

	if (rval == QL_SUCCESS) {

		/* Host Interface registers */

		/* HostRisc registers. */
		WRT32_IO_REG(ha, io_base_addr, 0x7000);
		bp = ql_read_regs(ha, fw->hostrisc_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* PCIe registers. */
		WRT32_IO_REG(ha, io_base_addr, 0x7c00);
		WRT_REG_DWORD(ha, ha->iobase + 0xc0, 0x1);
		bp = ql_read_regs(ha, fw->pcie_reg, ha->iobase + 0xC4,
		    3, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 1, 32);
		WRT_REG_DWORD(ha, ha->iobase + 0xc0, 0x0);

		/* Host interface registers. */
		(void) ql_read_regs(ha, fw->host_reg, ha->iobase,
		    sizeof (fw->host_reg) / 4, 32);

		/* Disable ISP interrupts. */

		WRT32_IO_REG(ha, ictrl, 0);
		RD32_IO_REG(ha, ictrl);
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~INTERRUPTS_ENABLED;
		ADAPTER_STATE_UNLOCK(ha);

		/* Shadow registers. */

		WRT32_IO_REG(ha, io_base_addr, 0x0F70);
		RD32_IO_REG(ha, io_base_addr);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0000000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[0] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0100000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[1] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0200000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[2] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0300000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[3] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0400000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[4] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0500000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[5] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0600000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[6] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0700000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[7] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0800000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[8] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0900000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[9] = RD_REG_DWORD(ha, reg32);

		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xF0);
		WRT_REG_DWORD(ha, reg32, 0xB0A00000);
		reg32 = (uint32_t *)((caddr_t)ha->iobase + 0xFC);
		fw->shadow_reg[0xa] = RD_REG_DWORD(ha, reg32);

		/* RISC I/O register. */

		WRT32_IO_REG(ha, io_base_addr, 0x0010);
		(void) ql_read_regs(ha, &fw->risc_io, ha->iobase + 0xC0,
		    1, 32);

		/* Mailbox registers. */

		(void) ql_read_regs(ha, fw->mailbox_reg, ha->iobase + 0x80,
		    sizeof (fw->mailbox_reg) / 2, 16);

		/* Transfer sequence registers. */

		/* XSEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xBF00);
		bp = ql_read_regs(ha, fw->xseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBF70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XSEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xBFC0);
		bp = ql_read_regs(ha, fw->xseq_0_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBFD0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xBFE0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XSEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xBFF0);
		(void) ql_read_regs(ha, fw->xseq_1_reg, ha->iobase + 0xC0,
		    16, 32);

		/* Receive sequence registers. */

		/* RSEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xFF00);
		bp = ql_read_regs(ha, fw->rseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFF70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RSEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFC0);
		bp = ql_read_regs(ha, fw->rseq_0_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xFFD0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RSEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFE0);
		(void) ql_read_regs(ha, fw->rseq_1_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_1_reg) / 4, 32);

		/* RSEQ-2 */
		WRT32_IO_REG(ha, io_base_addr, 0xFFF0);
		(void) ql_read_regs(ha, fw->rseq_2_reg, ha->iobase + 0xC0,
		    sizeof (fw->rseq_2_reg) / 4, 32);

		/* Auxiliary sequencer registers. */

		/* ASEQ GP */
		WRT32_IO_REG(ha, io_base_addr, 0xB000);
		bp = ql_read_regs(ha, fw->aseq_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB070);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* ASEQ-0 */
		WRT32_IO_REG(ha, io_base_addr, 0xB0C0);
		bp = ql_read_regs(ha, fw->aseq_0_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0xB0D0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* ASEQ-1 */
		WRT32_IO_REG(ha, io_base_addr, 0xB0E0);
		(void) ql_read_regs(ha, fw->aseq_1_reg, ha->iobase + 0xC0,
		    16, 32);

		/* ASEQ-2 */
		WRT32_IO_REG(ha, io_base_addr, 0xB0F0);
		(void) ql_read_regs(ha, fw->aseq_2_reg, ha->iobase + 0xC0,
		    16, 32);

		/* Command DMA registers. */

		WRT32_IO_REG(ha, io_base_addr, 0x7100);
		(void) ql_read_regs(ha, fw->cmd_dma_reg, ha->iobase + 0xC0,
		    sizeof (fw->cmd_dma_reg) / 4, 32);

		/* Queues. */

		/* RequestQ0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7200);
		bp = ql_read_regs(ha, fw->req0_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* ResponseQ0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7300);
		bp = ql_read_regs(ha, fw->resp0_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* RequestQ1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7400);
		bp = ql_read_regs(ha, fw->req1_dma_reg, ha->iobase + 0xC0,
		    8, 32);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xE4, 7, 32);

		/* Transmit DMA registers. */

		/* XMT0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7600);
		bp = ql_read_regs(ha, fw->xmt0_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7610);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7620);
		bp = ql_read_regs(ha, fw->xmt1_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7630);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT2 */
		WRT32_IO_REG(ha, io_base_addr, 0x7640);
		bp = ql_read_regs(ha, fw->xmt2_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7650);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT3 */
		WRT32_IO_REG(ha, io_base_addr, 0x7660);
		bp = ql_read_regs(ha, fw->xmt3_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7670);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT4 */
		WRT32_IO_REG(ha, io_base_addr, 0x7680);
		bp = ql_read_regs(ha, fw->xmt4_dma_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7690);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* XMT Common */
		WRT32_IO_REG(ha, io_base_addr, 0x76A0);
		(void) ql_read_regs(ha, fw->xmt_data_dma_reg,
		    ha->iobase + 0xC0, sizeof (fw->xmt_data_dma_reg) / 4, 32);

		/* Receive DMA registers. */

		/* RCVThread0 */
		WRT32_IO_REG(ha, io_base_addr, 0x7700);
		bp = ql_read_regs(ha, fw->rcvt0_data_dma_reg,
		    ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7710);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RCVThread1 */
		WRT32_IO_REG(ha, io_base_addr, 0x7720);
		bp = ql_read_regs(ha, fw->rcvt1_data_dma_reg,
		    ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x7730);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* RISC registers. */

		/* RISC GP */
		WRT32_IO_REG(ha, io_base_addr, 0x0F00);
		bp = ql_read_regs(ha, fw->risc_gp_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F10);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F20);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F30);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F40);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F50);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F60);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x0F70);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Local memory controller (LMC) registers. */

		/* LMC */
		WRT32_IO_REG(ha, io_base_addr, 0x3000);
		bp = ql_read_regs(ha, fw->lmc_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x3070);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Fibre Protocol Module registers. */

		/* FPM hardware */
		WRT32_IO_REG(ha, io_base_addr, 0x4000);
		bp = ql_read_regs(ha, fw->fpm_hdw_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4050);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4060);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4070);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4080);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x4090);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40A0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40B0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40C0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x40D0);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

		/* Frame Buffer registers. */

		/* FB hardware */
		WRT32_IO_REG(ha, io_base_addr, 0x6000);
		bp = ql_read_regs(ha, fw->fb_hdw_reg, ha->iobase + 0xC0,
		    16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6010);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6020);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6030);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6040);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6100);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6130);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6150);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6170);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6190);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x61B0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x61C0);
		bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
		WRT32_IO_REG(ha, io_base_addr, 0x6F00);
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	}

	/* Get the request queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 = (uint32_t *)ha->request_ring_bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    REQUEST_Q_BUFFER_OFFSET, sizeof (fw->req_q),
		    DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->req_q) / 4; cnt++) {
			fw->req_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->req_q[cnt]);
		}
	}

	/* Get the response queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 = (uint32_t *)ha->response_ring_bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    RESPONSE_Q_BUFFER_OFFSET, sizeof (fw->rsp_q),
		    DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->rsp_q) / 4; cnt++) {
			fw->rsp_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->rsp_q[cnt]);
		}
	}

	/* Reset RISC. */

	ql_reset_chip(ha);

	/* Memory. */

	if (rval == QL_SUCCESS) {
		/* Code RAM. */
		rval = ql_read_risc_ram(ha, 0x20000,
		    sizeof (fw->code_ram) / 4, fw->code_ram);
	}
	if (rval == QL_SUCCESS) {
		/* External Memory. */
		rval = ql_read_risc_ram(ha, 0x100000,
		    ha->fw_ext_memory_size / 4, fw->ext_mem);
	}

	/* Get the FC event trace buffer */
	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ENABLE_FWFCETRACE) &&
		    (ha->fwfcetracebuf.bp != NULL)) {
			uint32_t	cnt;
			uint32_t	*w32 = ha->fwfcetracebuf.bp;

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(ha->fwfcetracebuf.dma_handle, 0,
			    FWFCESIZE, DDI_DMA_SYNC_FORKERNEL);

			for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
				fw->fce_trace_buf[cnt] = *w32++;
			}
		}
	}

	/* Get the extended trace buffer */
	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ENABLE_FWEXTTRACE) &&
		    (ha->fwexttracebuf.bp != NULL)) {
			uint32_t	cnt;
			uint32_t	*w32 = ha->fwexttracebuf.bp;

			/* Sync DMA buffer. */
			(void) ddi_dma_sync(ha->fwexttracebuf.dma_handle, 0,
			    FWEXTSIZE, DDI_DMA_SYNC_FORKERNEL);

			for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
				fw->ext_trace_buf[cnt] = *w32++;
			}
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_read_risc_ram
 *	Reads RISC RAM one word at a time.
 *	Risc interrupts must be disabled when this routine is called.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	risc_address:	RISC code start address.
 *	len:		Number of words.
 *	buf:		buffer pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_read_risc_ram(ql_adapter_state_t *ha, uint32_t risc_address, uint32_t len,
    void *buf)
{
	uint32_t	cnt;
	uint16_t	stat;
	clock_t		timer;
	uint16_t	*buf16 = (uint16_t *)buf;
	uint32_t	*buf32 = (uint32_t *)buf;
	int		rval = QL_SUCCESS;

	for (cnt = 0; cnt < len; cnt++, risc_address++) {
		WRT16_IO_REG(ha, mailbox_in[0], MBC_READ_RAM_EXTENDED);
		WRT16_IO_REG(ha, mailbox_in[1], LSW(risc_address));
		WRT16_IO_REG(ha, mailbox_in[8], MSW(risc_address));
		if (CFG_IST(ha, CFG_CTRL_8021)) {
			WRT32_IO_REG(ha, nx_host_int, NX_MBX_CMD);
		} else if (CFG_IST(ha, CFG_CTRL_242581)) {
			WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
		} else {
			WRT16_IO_REG(ha, hccr, HC_SET_HOST_INT);
		}
		for (timer = 6000000; timer && rval == QL_SUCCESS; timer--) {
			if (INTERRUPT_PENDING(ha)) {
				stat = (uint16_t)
				    (RD16_IO_REG(ha, risc2host) & 0xff);
				if ((stat == 1) || (stat == 0x10)) {
					if (CFG_IST(ha, CFG_CTRL_24258081)) {
						buf32[cnt] = SHORT_TO_LONG(
						    RD16_IO_REG(ha,
						    mailbox_out[2]),
						    RD16_IO_REG(ha,
						    mailbox_out[3]));
					} else {
						buf16[cnt] =
						    RD16_IO_REG(ha,
						    mailbox_out[2]);
					}

					break;
				} else if ((stat == 2) || (stat == 0x11)) {
					rval = RD16_IO_REG(ha, mailbox_out[0]);
					break;
				}
				if (CFG_IST(ha, CFG_CTRL_8021)) {
					ql_8021_clr_hw_intr(ha);
					ql_8021_clr_fw_intr(ha);
				} else if (CFG_IST(ha, CFG_CTRL_242581)) {
					WRT32_IO_REG(ha, hccr,
					    HC24_CLR_RISC_INT);
					RD32_IO_REG(ha, hccr);
				} else {
					WRT16_IO_REG(ha, hccr,
					    HC_CLR_RISC_INT);
				}
			}
			drv_usecwait(5);
		}
		if (CFG_IST(ha, CFG_CTRL_8021)) {
			ql_8021_clr_hw_intr(ha);
			ql_8021_clr_fw_intr(ha);
		} else if (CFG_IST(ha, CFG_CTRL_242581)) {
			WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
			RD32_IO_REG(ha, hccr);
		} else {
			WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
			WRT16_IO_REG(ha, semaphore, 0);
		}

		if (timer == 0) {
			rval = QL_FUNCTION_TIMEOUT;
		}
	}

	return (rval);
}

/*
 * ql_read_regs
 *	Reads adapter registers to buffer.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	buf:	buffer pointer.
 *	reg:	start address.
 *	count:	number of registers.
 *	wds:	register size.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void *
ql_read_regs(ql_adapter_state_t *ha, void *buf, void *reg, uint32_t count,
    uint8_t wds)
{
	uint32_t	*bp32, *reg32;
	uint16_t	*bp16, *reg16;
	uint8_t		*bp8, *reg8;

	switch (wds) {
	case 32:
		bp32 = buf;
		reg32 = reg;
		while (count--) {
			*bp32++ = RD_REG_DWORD(ha, reg32++);
		}
		return (bp32);
	case 16:
		bp16 = buf;
		reg16 = reg;
		while (count--) {
			*bp16++ = RD_REG_WORD(ha, reg16++);
		}
		return (bp16);
	case 8:
		bp8 = buf;
		reg8 = reg;
		while (count--) {
			*bp8++ = RD_REG_BYTE(ha, reg8++);
		}
		return (bp8);
	default:
		EL(ha, "Unknown word size=%d\n", wds);
		return (buf);
	}
}

static int
ql_save_config_regs(dev_info_t *dip)
{
	ql_adapter_state_t	*ha;
	int			ret;
	ql_config_space_t	chs;
	caddr_t			prop = "ql-config-space";

	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "(%d): no adapter\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, prop) ==
	    1) {
		QL_PRINT_2(CE_CONT, "(%d): no prop exit\n", ha->instance);
		return (DDI_SUCCESS);
	}

	chs.chs_command = (uint16_t)ql_pci_config_get16(ha, PCI_CONF_COMM);
	chs.chs_header_type = (uint8_t)ql_pci_config_get8(ha,
	    PCI_CONF_HEADER);
	if ((chs.chs_header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		chs.chs_bridge_control = (uint8_t)ql_pci_config_get8(ha,
		    PCI_BCNF_BCNTRL);
	}

	chs.chs_cache_line_size = (uint8_t)ql_pci_config_get8(ha,
	    PCI_CONF_CACHE_LINESZ);

	chs.chs_latency_timer = (uint8_t)ql_pci_config_get8(ha,
	    PCI_CONF_LATENCY_TIMER);

	if ((chs.chs_header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		chs.chs_sec_latency_timer = (uint8_t)ql_pci_config_get8(ha,
		    PCI_BCNF_LATENCY_TIMER);
	}

	chs.chs_base0 = ql_pci_config_get32(ha, PCI_CONF_BASE0);
	chs.chs_base1 = ql_pci_config_get32(ha, PCI_CONF_BASE1);
	chs.chs_base2 = ql_pci_config_get32(ha, PCI_CONF_BASE2);
	chs.chs_base3 = ql_pci_config_get32(ha, PCI_CONF_BASE3);
	chs.chs_base4 = ql_pci_config_get32(ha, PCI_CONF_BASE4);
	chs.chs_base5 = ql_pci_config_get32(ha, PCI_CONF_BASE5);

	/*LINTED [Solaris DDI_DEV_T_NONE Lint warning]*/
	ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip, prop,
	    (uchar_t *)&chs, sizeof (ql_config_space_t));

	if (ret != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "!Qlogic %s(%d) can't update prop %s",
		    QL_NAME, ddi_get_instance(dip), prop);
		return (DDI_FAILURE);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

static int
ql_restore_config_regs(dev_info_t *dip)
{
	ql_adapter_state_t	*ha;
	uint_t			elements;
	ql_config_space_t	*chs_p;
	caddr_t			prop = "ql-config-space";

	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL) {
		QL_PRINT_2(CE_CONT, "(%d): no adapter\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, prop,
	    (uchar_t **)&chs_p, &elements) != DDI_PROP_SUCCESS) {
		QL_PRINT_2(CE_CONT, "(%d): no prop exit\n", ha->instance);
		return (DDI_FAILURE);
	}

	ql_pci_config_put16(ha, PCI_CONF_COMM, chs_p->chs_command);

	if ((chs_p->chs_header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		ql_pci_config_put16(ha, PCI_BCNF_BCNTRL,
		    chs_p->chs_bridge_control);
	}

	ql_pci_config_put8(ha, PCI_CONF_CACHE_LINESZ,
	    chs_p->chs_cache_line_size);

	ql_pci_config_put8(ha, PCI_CONF_LATENCY_TIMER,
	    chs_p->chs_latency_timer);

	if ((chs_p->chs_header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		ql_pci_config_put8(ha, PCI_BCNF_LATENCY_TIMER,
		    chs_p->chs_sec_latency_timer);
	}

	ql_pci_config_put32(ha, PCI_CONF_BASE0, chs_p->chs_base0);
	ql_pci_config_put32(ha, PCI_CONF_BASE1, chs_p->chs_base1);
	ql_pci_config_put32(ha, PCI_CONF_BASE2, chs_p->chs_base2);
	ql_pci_config_put32(ha, PCI_CONF_BASE3, chs_p->chs_base3);
	ql_pci_config_put32(ha, PCI_CONF_BASE4, chs_p->chs_base4);
	ql_pci_config_put32(ha, PCI_CONF_BASE5, chs_p->chs_base5);

	ddi_prop_free(chs_p);

	/*LINTED [Solaris DDI_DEV_T_NONE Lint warning]*/
	if (ndi_prop_remove(DDI_DEV_T_NONE, dip, prop) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "!Qlogic %s(%d): can't remove prop %s",
		    QL_NAME, ddi_get_instance(dip), prop);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

uint8_t
ql_pci_config_get8(ql_adapter_state_t *ha, off_t off)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		return (ddi_get8(ha->sbus_config_handle,
		    (uint8_t *)(ha->sbus_config_base + off)));
	}

#ifdef KERNEL_32
	return (pci_config_getb(ha->pci_handle, off));
#else
	return (pci_config_get8(ha->pci_handle, off));
#endif
}

uint16_t
ql_pci_config_get16(ql_adapter_state_t *ha, off_t off)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		return (ddi_get16(ha->sbus_config_handle,
		    (uint16_t *)(ha->sbus_config_base + off)));
	}

#ifdef KERNEL_32
	return (pci_config_getw(ha->pci_handle, off));
#else
	return (pci_config_get16(ha->pci_handle, off));
#endif
}

uint32_t
ql_pci_config_get32(ql_adapter_state_t *ha, off_t off)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		return (ddi_get32(ha->sbus_config_handle,
		    (uint32_t *)(ha->sbus_config_base + off)));
	}

#ifdef KERNEL_32
	return (pci_config_getl(ha->pci_handle, off));
#else
	return (pci_config_get32(ha->pci_handle, off));
#endif
}

void
ql_pci_config_put8(ql_adapter_state_t *ha, off_t off, uint8_t val)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put8(ha->sbus_config_handle,
		    (uint8_t *)(ha->sbus_config_base + off), val);
	} else {
#ifdef KERNEL_32
		pci_config_putb(ha->pci_handle, off, val);
#else
		pci_config_put8(ha->pci_handle, off, val);
#endif
	}
}

void
ql_pci_config_put16(ql_adapter_state_t *ha, off_t off, uint16_t val)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put16(ha->sbus_config_handle,
		    (uint16_t *)(ha->sbus_config_base + off), val);
	} else {
#ifdef KERNEL_32
		pci_config_putw(ha->pci_handle, off, val);
#else
		pci_config_put16(ha->pci_handle, off, val);
#endif
	}
}

void
ql_pci_config_put32(ql_adapter_state_t *ha, off_t off, uint32_t val)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put32(ha->sbus_config_handle,
		    (uint32_t *)(ha->sbus_config_base + off), val);
	} else {
#ifdef KERNEL_32
		pci_config_putl(ha->pci_handle, off, val);
#else
		pci_config_put32(ha->pci_handle, off, val);
#endif
	}
}

/*
 * ql_halt
 *	Waits for commands that are running to finish and
 *	if they do not, commands are aborted.
 *	Finally the adapter is reset.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	pwr:	power state.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_halt(ql_adapter_state_t *ha, int pwr)
{
	uint32_t	cnt;
	ql_tgt_t	*tq;
	ql_srb_t	*sp;
	uint16_t	index;
	ql_link_t	*link;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Wait for all commands running to finish. */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;
			(void) ql_abort_device(ha, tq, 0);

			/* Wait for 30 seconds for commands to finish. */
			for (cnt = 3000; cnt != 0; cnt--) {
				/* Acquire device queue lock. */
				DEVICE_QUEUE_LOCK(tq);
				if (tq->outcnt == 0) {
					/* Release device queue lock. */
					DEVICE_QUEUE_UNLOCK(tq);
					break;
				} else {
					/* Release device queue lock. */
					DEVICE_QUEUE_UNLOCK(tq);
					ql_delay(ha, 10000);
				}
			}

			/* Finish any commands waiting for more status. */
			if (ha->status_srb != NULL) {
				sp = ha->status_srb;
				ha->status_srb = NULL;
				sp->cmd.next = NULL;
				ql_done(&sp->cmd);
			}

			/* Abort commands that did not finish. */
			if (cnt == 0) {
				for (cnt = 1; cnt < MAX_OUTSTANDING_COMMANDS;
				    cnt++) {
					if (ha->pending_cmds.first != NULL) {
						ql_start_iocb(ha, NULL);
						cnt = 1;
					}
					sp = ha->outstanding_cmds[cnt];
					if (sp != NULL &&
					    sp->lun_queue->target_queue ==
					    tq) {
						(void) ql_abort((opaque_t)ha,
						    sp->pkt, 0);
					}
				}
			}
		}
	}

	/* Shutdown IP. */
	if (ha->flags & IP_INITIALIZED) {
		(void) ql_shutdown_ip(ha);
	}

	/* Stop all timers. */
	ADAPTER_STATE_LOCK(ha);
	ha->port_retry_timer = 0;
	ha->loop_down_timer = LOOP_DOWN_TIMER_OFF;
	ha->watchdog_timer = 0;
	ADAPTER_STATE_UNLOCK(ha);

	if (pwr == PM_LEVEL_D3) {
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~ONLINE;
		ADAPTER_STATE_UNLOCK(ha);

		/* Reset ISP chip. */
		ql_reset_chip(ha);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_get_dma_mem
 *	Function used to allocate dma memory.
 *
 * Input:
 *	ha:			adapter state pointer.
 *	mem:			pointer to dma memory object.
 *	size:			size of the request in bytes
 *
 * Returns:
 *	qn local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_dma_mem(ql_adapter_state_t *ha, dma_mem_t *mem, uint32_t size,
    mem_alloc_type_t allocation_type, mem_alignment_t alignment)
{
	int	rval;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mem->size = size;
	mem->type = allocation_type;
	mem->cookie_count = 1;

	switch (alignment) {
	case QL_DMA_DATA_ALIGN:
		mem->alignment = QL_DMA_ALIGN_8_BYTE_BOUNDARY;
		break;
	case QL_DMA_RING_ALIGN:
		mem->alignment = QL_DMA_ALIGN_64_BYTE_BOUNDARY;
		break;
	default:
		EL(ha, "failed, unknown alignment type %x\n", alignment);
		break;
	}

	if ((rval = ql_alloc_phys(ha, mem, KM_SLEEP)) != QL_SUCCESS) {
		ql_free_phys(ha, mem);
		EL(ha, "failed, alloc_phys=%xh\n", rval);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_alloc_phys
 *	Function used to allocate memory and zero it.
 *	Memory is below 4 GB.
 *
 * Input:
 *	ha:			adapter state pointer.
 *	mem:			pointer to dma memory object.
 *	sleep:			KM_SLEEP/KM_NOSLEEP flag.
 *	mem->cookie_count	number of segments allowed.
 *	mem->type		memory allocation type.
 *	mem->size		memory size.
 *	mem->alignment		memory alignment.
 *
 * Returns:
 *	qn local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_alloc_phys(ql_adapter_state_t *ha, dma_mem_t *mem, int sleep)
{
	size_t			rlen;
	ddi_dma_attr_t		dma_attr;
	ddi_device_acc_attr_t	acc_attr = ql_dev_acc_attr;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	dma_attr = CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING) ?
	    ql_64bit_io_dma_attr : ql_32bit_io_dma_attr;

	dma_attr.dma_attr_align = mem->alignment; /* DMA address alignment */
	dma_attr.dma_attr_sgllen = (int)mem->cookie_count;

	/*
	 * Workaround for SUN XMITS buffer must end and start on 8 byte
	 * boundary. Else, hardware will overrun the buffer. Simple fix is
	 * to make sure buffer has enough room for overrun.
	 */
	if (mem->size & 7) {
		mem->size += 8 - (mem->size & 7);
	}

	mem->flags = DDI_DMA_CONSISTENT;

	/*
	 * Allocate DMA memory for command.
	 */
	if (ddi_dma_alloc_handle(ha->dip, &dma_attr, (sleep == KM_SLEEP) ?
	    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT, NULL, &mem->dma_handle) !=
	    DDI_SUCCESS) {
		EL(ha, "failed, ddi_dma_alloc_handle\n");
		mem->dma_handle = NULL;
		return (QL_MEMORY_ALLOC_FAILED);
	}

	switch (mem->type) {
	case KERNEL_MEM:
		mem->bp = kmem_zalloc(mem->size, sleep);
		break;
	case BIG_ENDIAN_DMA:
	case LITTLE_ENDIAN_DMA:
	case NO_SWAP_DMA:
		if (mem->type == BIG_ENDIAN_DMA) {
			acc_attr.devacc_attr_endian_flags =
			    DDI_STRUCTURE_BE_ACC;
		} else if (mem->type == NO_SWAP_DMA) {
			acc_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
		}
		if (ddi_dma_mem_alloc(mem->dma_handle, mem->size, &acc_attr,
		    mem->flags, (sleep == KM_SLEEP) ? DDI_DMA_SLEEP :
		    DDI_DMA_DONTWAIT, NULL, (caddr_t *)&mem->bp, &rlen,
		    &mem->acc_handle) == DDI_SUCCESS) {
			bzero(mem->bp, mem->size);
			/* ensure we got what we asked for (32bit) */
			if (dma_attr.dma_attr_addr_hi == NULL) {
				if (mem->cookie.dmac_notused != NULL) {
					EL(ha, "failed, ddi_dma_mem_alloc "
					    "returned 64 bit DMA address\n");
					ql_free_phys(ha, mem);
					return (QL_MEMORY_ALLOC_FAILED);
				}
			}
		} else {
			mem->acc_handle = NULL;
			mem->bp = NULL;
		}
		break;
	default:
		EL(ha, "failed, unknown type=%xh\n", mem->type);
		mem->acc_handle = NULL;
		mem->bp = NULL;
		break;
	}

	if (mem->bp == NULL) {
		EL(ha, "failed, ddi_dma_mem_alloc\n");
		ddi_dma_free_handle(&mem->dma_handle);
		mem->dma_handle = NULL;
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mem->flags |= DDI_DMA_RDWR;

	if (ql_bind_dma_buffer(ha, mem, sleep) != DDI_DMA_MAPPED) {
		EL(ha, "failed, ddi_dma_addr_bind_handle\n");
		ql_free_phys(ha, mem);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (QL_SUCCESS);
}

/*
 * ql_free_phys
 *	Function used to free physical memory.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mem:	pointer to dma memory object.
 *
 * Context:
 *	Kernel context.
 */
void
ql_free_phys(ql_adapter_state_t *ha, dma_mem_t *mem)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (mem != NULL && mem->dma_handle != NULL) {
		ql_unbind_dma_buffer(ha, mem);
		switch (mem->type) {
		case KERNEL_MEM:
			if (mem->bp != NULL) {
				kmem_free(mem->bp, mem->size);
			}
			break;
		case LITTLE_ENDIAN_DMA:
		case BIG_ENDIAN_DMA:
		case NO_SWAP_DMA:
			if (mem->acc_handle != NULL) {
				ddi_dma_mem_free(&mem->acc_handle);
				mem->acc_handle = NULL;
			}
			break;
		default:
			break;
		}
		mem->bp = NULL;
		ddi_dma_free_handle(&mem->dma_handle);
		mem->dma_handle = NULL;
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_alloc_dma_resouce.
 *	Allocates DMA resource for buffer.
 *
 * Input:
 *	ha:			adapter state pointer.
 *	mem:			pointer to dma memory object.
 *	sleep:			KM_SLEEP/KM_NOSLEEP flag.
 *	mem->cookie_count	number of segments allowed.
 *	mem->type		memory allocation type.
 *	mem->size		memory size.
 *	mem->bp			pointer to memory or struct buf
 *
 * Returns:
 *	qn local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_alloc_dma_resouce(ql_adapter_state_t *ha, dma_mem_t *mem, int sleep)
{
	ddi_dma_attr_t	dma_attr;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	dma_attr = CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING) ?
	    ql_64bit_io_dma_attr : ql_32bit_io_dma_attr;
	dma_attr.dma_attr_sgllen = (int)mem->cookie_count;

	/*
	 * Allocate DMA handle for command.
	 */
	if (ddi_dma_alloc_handle(ha->dip, &dma_attr, (sleep == KM_SLEEP) ?
	    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT, NULL, &mem->dma_handle) !=
	    DDI_SUCCESS) {
		EL(ha, "failed, ddi_dma_alloc_handle\n");
		mem->dma_handle = NULL;
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mem->flags = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;

	if (ql_bind_dma_buffer(ha, mem, sleep) != DDI_DMA_MAPPED) {
		EL(ha, "failed, bind_dma_buffer\n");
		ddi_dma_free_handle(&mem->dma_handle);
		mem->dma_handle = NULL;
		return (QL_MEMORY_ALLOC_FAILED);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (QL_SUCCESS);
}

/*
 * ql_free_dma_resource
 *	Frees DMA resources.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	mem:		pointer to dma memory object.
 *	mem->dma_handle	DMA memory handle.
 *
 * Context:
 *	Kernel context.
 */
void
ql_free_dma_resource(ql_adapter_state_t *ha, dma_mem_t *mem)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	ql_free_phys(ha, mem);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_bind_dma_buffer
 *	Binds DMA buffer.
 *
 * Input:
 *	ha:			adapter state pointer.
 *	mem:			pointer to dma memory object.
 *	sleep:			KM_SLEEP or KM_NOSLEEP.
 *	mem->dma_handle		DMA memory handle.
 *	mem->cookie_count	number of segments allowed.
 *	mem->type		memory allocation type.
 *	mem->size		memory size.
 *	mem->bp			pointer to memory or struct buf
 *
 * Returns:
 *	mem->cookies		pointer to list of cookies.
 *	mem->cookie_count	number of cookies.
 *	status			success = DDI_DMA_MAPPED
 *				DDI_DMA_PARTIAL_MAP, DDI_DMA_INUSE,
 *				DDI_DMA_NORESOURCES, DDI_DMA_NOMAPPING or
 *				DDI_DMA_TOOBIG
 *
 * Context:
 *	Kernel context.
 */
static int
ql_bind_dma_buffer(ql_adapter_state_t *ha, dma_mem_t *mem, int sleep)
{
	int			rval;
	ddi_dma_cookie_t	*cookiep;
	uint32_t		cnt = mem->cookie_count;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (mem->type == STRUCT_BUF_MEMORY) {
		rval = ddi_dma_buf_bind_handle(mem->dma_handle, mem->bp,
		    mem->flags, (sleep == KM_SLEEP) ? DDI_DMA_SLEEP :
		    DDI_DMA_DONTWAIT, NULL, &mem->cookie, &mem->cookie_count);
	} else {
		rval = ddi_dma_addr_bind_handle(mem->dma_handle, NULL, mem->bp,
		    mem->size, mem->flags, (sleep == KM_SLEEP) ?
		    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT, NULL, &mem->cookie,
		    &mem->cookie_count);
	}

	if (rval == DDI_DMA_MAPPED) {
		if (mem->cookie_count > cnt) {
			(void) ddi_dma_unbind_handle(mem->dma_handle);
			EL(ha, "failed, cookie_count %d > %d\n",
			    mem->cookie_count, cnt);
			rval = DDI_DMA_TOOBIG;
		} else {
			if (mem->cookie_count > 1) {
				if (mem->cookies = kmem_zalloc(
				    sizeof (ddi_dma_cookie_t) *
				    mem->cookie_count, sleep)) {
					*mem->cookies = mem->cookie;
					cookiep = mem->cookies;
					for (cnt = 1; cnt < mem->cookie_count;
					    cnt++) {
						ddi_dma_nextcookie(
						    mem->dma_handle,
						    ++cookiep);
					}
				} else {
					(void) ddi_dma_unbind_handle(
					    mem->dma_handle);
					EL(ha, "failed, kmem_zalloc\n");
					rval = DDI_DMA_NORESOURCES;
				}
			} else {
				/*
				 * It has been reported that dmac_size at times
				 * may be incorrect on sparc machines so for
				 * sparc machines that only have one segment
				 * use the buffer size instead.
				 */
				mem->cookies = &mem->cookie;
				mem->cookies->dmac_size = mem->size;
			}
		}
	}

	if (rval != DDI_DMA_MAPPED) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_unbind_dma_buffer
 *	Unbinds DMA buffer.
 *
 * Input:
 *	ha:			adapter state pointer.
 *	mem:			pointer to dma memory object.
 *	mem->dma_handle		DMA memory handle.
 *	mem->cookies		pointer to cookie list.
 *	mem->cookie_count	number of cookies.
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static void
ql_unbind_dma_buffer(ql_adapter_state_t *ha, dma_mem_t *mem)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	(void) ddi_dma_unbind_handle(mem->dma_handle);
	if (mem->cookie_count > 1) {
		kmem_free(mem->cookies, sizeof (ddi_dma_cookie_t) *
		    mem->cookie_count);
		mem->cookies = NULL;
	}
	mem->cookie_count = 0;

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

static int
ql_suspend_adapter(ql_adapter_state_t *ha)
{
	clock_t timer = 32 * drv_usectohz(1000000);

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/*
	 * First we will claim mbox ownership so that no
	 * thread using mbox hangs when we disable the
	 * interrupt in the middle of it.
	 */
	MBX_REGISTER_LOCK(ha);

	/* Check for mailbox available, if not wait for signal. */
	while (ha->mailbox_flags & MBX_BUSY_FLG) {
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags | MBX_WANT_FLG);

		/* 30 seconds from now */
		if (cv_reltimedwait(&ha->cv_mbx_wait, &ha->mbx_mutex,
		    timer, TR_CLOCK_TICK) == -1) {

			/* Release mailbox register lock. */
			MBX_REGISTER_UNLOCK(ha);
			EL(ha, "failed, Suspend mbox");
			return (QL_FUNCTION_TIMEOUT);
		}
	}

	/* Set busy flag. */
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags | MBX_BUSY_FLG);
	MBX_REGISTER_UNLOCK(ha);

	(void) ql_wait_outstanding(ha);

	/*
	 * here we are sure that there will not be any mbox interrupt.
	 * So, let's make sure that we return back all the outstanding
	 * cmds as well as internally queued commands.
	 */
	ql_halt(ha, PM_LEVEL_D0);

	if (ha->power_level != PM_LEVEL_D3) {
		/* Disable ISP interrupts. */
		WRT16_IO_REG(ha, ictrl, 0);
	}

	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~INTERRUPTS_ENABLED;
	ADAPTER_STATE_UNLOCK(ha);

	MBX_REGISTER_LOCK(ha);
	/* Reset busy status. */
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags & ~MBX_BUSY_FLG);

	/* If thread is waiting for mailbox go signal it to start. */
	if (ha->mailbox_flags & MBX_WANT_FLG) {
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags & ~MBX_WANT_FLG);
		cv_broadcast(&ha->cv_mbx_wait);
	}
	/* Release mailbox register lock. */
	MBX_REGISTER_UNLOCK(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (QL_SUCCESS);
}

/*
 * ql_add_link_b
 *	Add link to the end of the chain.
 *
 * Input:
 *	head = Head of link list.
 *	link = link to be added.
 *	LOCK must be already obtained.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_add_link_b(ql_head_t *head, ql_link_t *link)
{
	/* at the end there isn't a next */
	link->next = NULL;

	if ((link->prev = head->last) == NULL) {
		head->first = link;
	} else {
		head->last->next = link;
	}

	head->last = link;
	link->head = head;	/* the queue we're on */
}

/*
 * ql_add_link_t
 *	Add link to the beginning of the chain.
 *
 * Input:
 *	head = Head of link list.
 *	link = link to be added.
 *	LOCK must be already obtained.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_add_link_t(ql_head_t *head, ql_link_t *link)
{
	link->prev = NULL;

	if ((link->next = head->first) == NULL)	{
		head->last = link;
	} else {
		head->first->prev = link;
	}

	head->first = link;
	link->head = head;	/* the queue we're on */
}

/*
 * ql_remove_link
 *	Remove a link from the chain.
 *
 * Input:
 *	head = Head of link list.
 *	link = link to be removed.
 *	LOCK must be already obtained.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_remove_link(ql_head_t *head, ql_link_t *link)
{
	if (link->prev != NULL) {
		if ((link->prev->next = link->next) == NULL) {
			head->last = link->prev;
		} else {
			link->next->prev = link->prev;
		}
	} else if ((head->first = link->next) == NULL) {
		head->last = NULL;
	} else {
		head->first->prev = NULL;
	}

	/* not on a queue any more */
	link->prev = link->next = NULL;
	link->head = NULL;
}

/*
 * ql_chg_endian
 *	Change endianess of byte array.
 *
 * Input:
 *	buf = array pointer.
 *	size = size of array in bytes.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_chg_endian(uint8_t buf[], size_t size)
{
	uint8_t byte;
	size_t  cnt1;
	size_t  cnt;

	cnt1 = size - 1;
	for (cnt = 0; cnt < size / 2; cnt++) {
		byte = buf[cnt1];
		buf[cnt1] = buf[cnt];
		buf[cnt] = byte;
		cnt1--;
	}
}

/*
 * ql_bstr_to_dec
 *	Convert decimal byte string to number.
 *
 * Input:
 *	s:	byte string pointer.
 *	ans:	interger pointer for number.
 *	size:	number of ascii bytes.
 *
 * Returns:
 *	success = number of ascii bytes processed.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
static int
ql_bstr_to_dec(char *s, uint32_t *ans, uint32_t size)
{
	int			mul, num, cnt, pos;
	char			*str;

	/* Calculate size of number. */
	if (size == 0) {
		for (str = s; *str >= '0' && *str <= '9'; str++) {
			size++;
		}
	}

	*ans = 0;
	for (cnt = 0; *s != '\0' && size; size--, cnt++) {
		if (*s >= '0' && *s <= '9') {
			num = *s++ - '0';
		} else {
			break;
		}

		for (mul = 1, pos = 1; pos < size; pos++) {
			mul *= 10;
		}
		*ans += num * mul;
	}

	return (cnt);
}

/*
 * ql_delay
 *	Calls delay routine if threads are not suspended, otherwise, busy waits
 *	Minimum = 1 tick = 10ms
 *
 * Input:
 *	dly = delay time in microseconds.
 *
 * Context:
 *	Kernel or Interrupt context, no mailbox commands allowed.
 */
void
ql_delay(ql_adapter_state_t *ha, clock_t usecs)
{
	if (QL_DAEMON_SUSPENDED(ha) || ddi_in_panic()) {
		drv_usecwait(usecs);
	} else {
		delay(drv_usectohz(usecs));
	}
}

/*
 * ql_stall_drv
 *	Stalls one or all driver instances, waits for 30 seconds.
 *
 * Input:
 *	ha:		adapter state pointer or NULL for all.
 *	options:	BIT_0 --> leave driver stalled on exit if
 *				  failed.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_stall_driver(ql_adapter_state_t *ha, uint32_t options)
{
	ql_link_t		*link;
	ql_adapter_state_t	*ha2;
	uint32_t		timer;

	QL_PRINT_3(CE_CONT, "started\n");

	/* Wait for 30 seconds for daemons unstall. */
	timer = 3000;
	link = ha == NULL ? ql_hba.first : &ha->hba;
	while (link != NULL && timer) {
		ha2 = link->base_address;

		ql_awaken_task_daemon(ha2, NULL, DRIVER_STALL, 0);

		if ((ha2->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) == 0 ||
		    (ha2->task_daemon_flags & TASK_DAEMON_STOP_FLG) != 0 ||
		    (ha2->task_daemon_flags & TASK_DAEMON_STALLED_FLG &&
		    ql_wait_outstanding(ha2) == MAX_OUTSTANDING_COMMANDS)) {
			link = ha == NULL ? link->next : NULL;
			continue;
		}

		ql_delay(ha2, 10000);
		timer--;
		link = ha == NULL ? ql_hba.first : &ha->hba;
	}

	if (ha2 != NULL && timer == 0) {
		EL(ha2, "failed, tdf=%xh, exiting state is: %s\n",
		    ha2->task_daemon_flags, (options & BIT_0 ? "stalled" :
		    "unstalled"));
		if (options & BIT_0) {
			ql_awaken_task_daemon(ha2, NULL, 0, DRIVER_STALL);
		}
		return (QL_FUNCTION_TIMEOUT);
	}

	QL_PRINT_3(CE_CONT, "done\n");

	return (QL_SUCCESS);
}

/*
 * ql_restart_driver
 *	Restarts one or all driver instances.
 *
 * Input:
 *	ha:	adapter state pointer or NULL for all.
 *
 * Context:
 *	Kernel context.
 */
void
ql_restart_driver(ql_adapter_state_t *ha)
{
	ql_link_t		*link;
	ql_adapter_state_t	*ha2;
	uint32_t		timer;

	QL_PRINT_3(CE_CONT, "started\n");

	/* Tell all daemons to unstall. */
	link = ha == NULL ? ql_hba.first : &ha->hba;
	while (link != NULL) {
		ha2 = link->base_address;

		ql_awaken_task_daemon(ha2, NULL, 0, DRIVER_STALL);

		link = ha == NULL ? link->next : NULL;
	}

	/* Wait for 30 seconds for all daemons unstall. */
	timer = 3000;
	link = ha == NULL ? ql_hba.first : &ha->hba;
	while (link != NULL && timer) {
		ha2 = link->base_address;

		if ((ha2->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) == 0 ||
		    (ha2->task_daemon_flags & TASK_DAEMON_STOP_FLG) != 0 ||
		    (ha2->task_daemon_flags & TASK_DAEMON_STALLED_FLG) == 0) {
			QL_PRINT_2(CE_CONT, "(%d,%d): restarted\n",
			    ha2->instance, ha2->vp_index);
			ql_restart_queues(ha2);
			link = ha == NULL ? link->next : NULL;
			continue;
		}

		QL_PRINT_2(CE_CONT, "(%d,%d): failed, tdf=%xh\n",
		    ha2->instance, ha2->vp_index, ha2->task_daemon_flags);

		ql_delay(ha2, 10000);
		timer--;
		link = ha == NULL ? ql_hba.first : &ha->hba;
	}

	QL_PRINT_3(CE_CONT, "done\n");
}

/*
 * ql_setup_interrupts
 *	Sets up interrupts based on the HBA's and platform's
 *	capabilities (e.g., legacy / MSI / FIXED).
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_interrupts(ql_adapter_state_t *ha)
{
	int32_t		rval = DDI_FAILURE;
	int32_t		i;
	int32_t		itypes = 0;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/*
	 * The Solaris Advanced Interrupt Functions (aif) are only
	 * supported on s10U1 or greater.
	 */
	if (ql_os_release_level < 10 || ql_disable_aif != 0) {
		EL(ha, "interrupt framework is not supported or is "
		    "disabled, using legacy\n");
		return (ql_legacy_intr(ha));
	} else if (ql_os_release_level == 10) {
		/*
		 * See if the advanced interrupt functions (aif) are
		 * in the kernel
		 */
		void	*fptr = (void *)&ddi_intr_get_supported_types;

		if (fptr == NULL) {
			EL(ha, "aif is not supported, using legacy "
			    "interrupts (rev)\n");
			return (ql_legacy_intr(ha));
		}
	}

	/* See what types of interrupts this HBA and platform support */
	if ((i = ddi_intr_get_supported_types(ha->dip, &itypes)) !=
	    DDI_SUCCESS) {
		EL(ha, "get supported types failed, rval=%xh, "
		    "assuming FIXED\n", i);
		itypes = DDI_INTR_TYPE_FIXED;
	}

	EL(ha, "supported types are: %xh\n", itypes);

	if ((itypes & DDI_INTR_TYPE_MSIX) &&
	    (rval = ql_setup_msix(ha)) == DDI_SUCCESS) {
		EL(ha, "successful MSI-X setup\n");
	} else if ((itypes & DDI_INTR_TYPE_MSI) &&
	    (rval = ql_setup_msi(ha)) == DDI_SUCCESS) {
		EL(ha, "successful MSI setup\n");
	} else {
		rval = ql_setup_fixed(ha);
	}

	if (rval != DDI_SUCCESS) {
		EL(ha, "failed, aif, rval=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n");
	}

	return (rval);
}

/*
 * ql_setup_msi
 *	Set up aif MSI interrupts
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_msi(ql_adapter_state_t *ha)
{
	int32_t		count = 0;
	int32_t		avail = 0;
	int32_t		actual = 0;
	int32_t		msitype = DDI_INTR_TYPE_MSI;
	int32_t		ret;
	ql_ifunc_t	itrfun[10] = {0};

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ql_disable_msi != 0) {
		EL(ha, "MSI is disabled by user\n");
		return (DDI_FAILURE);
	}

	/* MSI support is only suported on 24xx HBA's. */
	if (!(CFG_IST(ha, CFG_CTRL_24258081))) {
		EL(ha, "HBA does not support MSI\n");
		return (DDI_FAILURE);
	}

	/* Get number of MSI interrupts the system supports */
	if (((ret = ddi_intr_get_nintrs(ha->dip, msitype, &count)) !=
	    DDI_SUCCESS) || count == 0) {
		EL(ha, "failed, nintrs ret=%xh, cnt=%xh\n", ret, count);
		return (DDI_FAILURE);
	}

	/* Get number of available MSI interrupts */
	if (((ret = ddi_intr_get_navail(ha->dip, msitype, &avail)) !=
	    DDI_SUCCESS) || avail == 0) {
		EL(ha, "failed, navail ret=%xh, avail=%xh\n", ret, avail);
		return (DDI_FAILURE);
	}

	/* MSI requires only 1.  */
	count = 1;
	itrfun[0].ifunc = &ql_isr_aif;

	/* Allocate space for interrupt handles */
	ha->hsize = ((uint32_t)(sizeof (ddi_intr_handle_t)) * count);
	ha->htable = kmem_zalloc(ha->hsize, KM_SLEEP);

	ha->iflags |= IFLG_INTR_MSI;

	/* Allocate the interrupts */
	if ((ret = ddi_intr_alloc(ha->dip, ha->htable, msitype, 0, count,
	    &actual, 0)) != DDI_SUCCESS || actual < count) {
		EL(ha, "failed, intr_alloc ret=%xh, count = %xh, "
		    "actual=%xh\n", ret, count, actual);
		ql_release_intr(ha);
		return (DDI_FAILURE);
	}

	ha->intr_cnt = actual;

	/* Get interrupt priority */
	if ((ret = ddi_intr_get_pri(ha->htable[0], &ha->intr_pri)) !=
	    DDI_SUCCESS) {
		EL(ha, "failed, get_pri ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Add the interrupt handler */
	if ((ret = ddi_intr_add_handler(ha->htable[0], itrfun[0].ifunc,
	    (caddr_t)ha, (caddr_t)0)) != DDI_SUCCESS) {
		EL(ha, "failed, intr_add ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Setup mutexes */
	if ((ret = ql_init_mutex(ha)) != DDI_SUCCESS) {
		EL(ha, "failed, mutex init ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Get the capabilities */
	(void) ddi_intr_get_cap(ha->htable[0], &ha->intr_cap);

	/* Enable interrupts */
	if (ha->intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(ha->htable, ha->intr_cnt)) !=
		    DDI_SUCCESS) {
			EL(ha, "failed, block enable, ret=%xh\n", ret);
			ql_destroy_mutex(ha);
			ql_release_intr(ha);
			return (ret);
		}
	} else {
		if ((ret = ddi_intr_enable(ha->htable[0])) != DDI_SUCCESS) {
			EL(ha, "failed, intr enable, ret=%xh\n", ret);
			ql_destroy_mutex(ha);
			ql_release_intr(ha);
			return (ret);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

/*
 * ql_setup_msix
 *	Set up aif MSI-X interrupts
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_msix(ql_adapter_state_t *ha)
{
	uint16_t	hwvect;
	int32_t		count = 0;
	int32_t		avail = 0;
	int32_t		actual = 0;
	int32_t		msitype = DDI_INTR_TYPE_MSIX;
	int32_t		ret;
	uint32_t	i;
	ql_ifunc_t	itrfun[QL_MSIX_MAXAIF] = {0};

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ql_disable_msix != 0) {
		EL(ha, "MSI-X is disabled by user\n");
		return (DDI_FAILURE);
	}

	/*
	 * MSI-X support is only available on 24xx HBA's that have
	 * rev A2 parts (revid = 3) or greater.
	 */
	if (!((ha->device_id == 0x2532) || (ha->device_id == 0x2432) ||
	    (ha->device_id == 0x8432) || (ha->device_id == 0x8001) ||
	    (ha->device_id == 0x8021))) {
		EL(ha, "HBA does not support MSI-X\n");
		return (DDI_FAILURE);
	}

	if (CFG_IST(ha, CFG_CTRL_2422) && (ha->rev_id < 3)) {
		EL(ha, "HBA does not support MSI-X (revid)\n");
		return (DDI_FAILURE);
	}

	/* Per HP, these HP branded HBA's are not supported with MSI-X */
	if (ha->ven_id == 0x103C && (ha->subsys_id == 0x7041 ||
	    ha->subsys_id == 0x7040 || ha->subsys_id == 0x1705)) {
		EL(ha, "HBA does not support MSI-X (subdevid)\n");
		return (DDI_FAILURE);
	}

	/* Get the number of 24xx/25xx MSI-X h/w vectors */
	hwvect = (uint16_t)(((CFG_IST(ha, CFG_CTRL_2422) ?
	    ql_pci_config_get16(ha, 0x7e) :
	    ql_pci_config_get16(ha, 0xa2)) & 0x3ff) + 1);

	EL(ha, "pcie config space hwvect = %d\n", hwvect);

	if (hwvect < QL_MSIX_MAXAIF) {
		EL(ha, "failed, min h/w vectors req'd: %d, avail: %d\n",
		    QL_MSIX_MAXAIF, hwvect);
		return (DDI_FAILURE);
	}

	/* Get number of MSI-X interrupts the platform h/w supports */
	if (((ret = ddi_intr_get_nintrs(ha->dip, msitype, &count)) !=
	    DDI_SUCCESS) || count == 0) {
		EL(ha, "failed, nintrs ret=%xh, cnt=%xh\n", ret, count);
		return (DDI_FAILURE);
	}

	/* Get number of available system interrupts */
	if (((ret = ddi_intr_get_navail(ha->dip, msitype, &avail)) !=
	    DDI_SUCCESS) || avail == 0) {
		EL(ha, "failed, navail ret=%xh, avail=%xh\n", ret, avail);
		return (DDI_FAILURE);
	}

	/* Fill out the intr table */
	count = QL_MSIX_MAXAIF;
	itrfun[QL_MSIX_AIF].ifunc = &ql_isr_aif;
	itrfun[QL_MSIX_RSPQ].ifunc = &ql_isr_aif;

	/* Allocate space for interrupt handles */
	ha->hsize = ((uint32_t)(sizeof (ddi_intr_handle_t)) * hwvect);
	if ((ha->htable = kmem_zalloc(ha->hsize, KM_SLEEP)) == NULL) {
		ha->hsize = 0;
		EL(ha, "failed, unable to allocate htable space\n");
		return (DDI_FAILURE);
	}

	ha->iflags |= IFLG_INTR_MSIX;

	/* Allocate the interrupts */
	if (((ret = ddi_intr_alloc(ha->dip, ha->htable, msitype,
	    DDI_INTR_ALLOC_NORMAL, count, &actual, 0)) != DDI_SUCCESS) ||
	    actual < QL_MSIX_MAXAIF) {
		EL(ha, "failed, intr_alloc ret=%xh, count = %xh, "
		    "actual=%xh\n", ret, count, actual);
		ql_release_intr(ha);
		return (DDI_FAILURE);
	}

	ha->intr_cnt = actual;

	/* Get interrupt priority */
	if ((ret = ddi_intr_get_pri(ha->htable[0], &ha->intr_pri)) !=
	    DDI_SUCCESS) {
		EL(ha, "failed, get_pri ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Add the interrupt handlers */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(ha->htable[i], itrfun[i].ifunc,
		    (void *)ha, (void *)((ulong_t)i))) != DDI_SUCCESS) {
			EL(ha, "failed, addh#=%xh, act=%xh, ret=%xh\n", i,
			    actual, ret);
			ql_release_intr(ha);
			return (ret);
		}
	}

	/*
	 * duplicate the rest of the intr's
	 * ddi_intr_dup_handler() isn't working on x86 just yet...
	 */
#ifdef __sparc
	for (i = actual; i < hwvect; i++) {
		if ((ret = ddi_intr_dup_handler(ha->htable[0], (int)i,
		    &ha->htable[i])) != DDI_SUCCESS) {
			EL(ha, "failed, intr_dup#=%xh, act=%xh, ret=%xh\n",
			    i, actual, ret);
			ql_release_intr(ha);
			return (ret);
		}
	}
#endif

	/* Setup mutexes */
	if ((ret = ql_init_mutex(ha)) != DDI_SUCCESS) {
		EL(ha, "failed, mutex init ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Get the capabilities */
	(void) ddi_intr_get_cap(ha->htable[0], &ha->intr_cap);

	/* Enable interrupts */
	if (ha->intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(ha->htable, ha->intr_cnt)) !=
		    DDI_SUCCESS) {
			EL(ha, "failed, block enable, ret=%xh\n", ret);
			ql_destroy_mutex(ha);
			ql_release_intr(ha);
			return (ret);
		}
	} else {
		for (i = 0; i < ha->intr_cnt; i++) {
			if ((ret = ddi_intr_enable(ha->htable[i])) !=
			    DDI_SUCCESS) {
				EL(ha, "failed, intr enable, ret=%xh\n", ret);
				ql_destroy_mutex(ha);
				ql_release_intr(ha);
				return (ret);
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

/*
 * ql_setup_fixed
 *	Sets up aif FIXED interrupts
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_fixed(ql_adapter_state_t *ha)
{
	int32_t		count = 0;
	int32_t		actual = 0;
	int32_t		ret;
	uint32_t	i;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get number of fixed interrupts the system supports */
	if (((ret = ddi_intr_get_nintrs(ha->dip, DDI_INTR_TYPE_FIXED,
	    &count)) != DDI_SUCCESS) || count == 0) {
		EL(ha, "failed, nintrs ret=%xh, cnt=%xh\n", ret, count);
		return (DDI_FAILURE);
	}

	ha->iflags |= IFLG_INTR_FIXED;

	/* Allocate space for interrupt handles */
	ha->hsize = ((uint32_t)(sizeof (ddi_intr_handle_t)) * count);
	ha->htable = kmem_zalloc(ha->hsize, KM_SLEEP);

	/* Allocate the interrupts */
	if (((ret = ddi_intr_alloc(ha->dip, ha->htable, DDI_INTR_TYPE_FIXED,
	    0, count, &actual, DDI_INTR_ALLOC_STRICT)) != DDI_SUCCESS) ||
	    actual < count) {
		EL(ha, "failed, intr_alloc ret=%xh, count=%xh, "
		    "actual=%xh\n", ret, count, actual);
		ql_release_intr(ha);
		return (DDI_FAILURE);
	}

	ha->intr_cnt = actual;

	/* Get interrupt priority */
	if ((ret = ddi_intr_get_pri(ha->htable[0], &ha->intr_pri)) !=
	    DDI_SUCCESS) {
		EL(ha, "failed, get_pri ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Add the interrupt handlers */
	for (i = 0; i < ha->intr_cnt; i++) {
		if ((ret = ddi_intr_add_handler(ha->htable[i], &ql_isr_aif,
		    (void *)ha, (void *)((ulong_t)(i)))) != DDI_SUCCESS) {
			EL(ha, "failed, intr_add ret=%xh\n", ret);
			ql_release_intr(ha);
			return (ret);
		}
	}

	/* Setup mutexes */
	if ((ret = ql_init_mutex(ha)) != DDI_SUCCESS) {
		EL(ha, "failed, mutex init ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}

	/* Enable interrupts */
	for (i = 0; i < ha->intr_cnt; i++) {
		if ((ret = ddi_intr_enable(ha->htable[i])) != DDI_SUCCESS) {
			EL(ha, "failed, intr enable, ret=%xh\n", ret);
			ql_destroy_mutex(ha);
			ql_release_intr(ha);
			return (ret);
		}
	}

	EL(ha, "using FIXED interupts\n");

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

/*
 * ql_disable_intr
 *	Disables interrupts
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_disable_intr(ql_adapter_state_t *ha)
{
	uint32_t	i, rval;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (!(ha->iflags & IFLG_INTR_AIF)) {

		/* Disable legacy interrupts */
		(void) ddi_remove_intr(ha->dip, 0, ha->iblock_cookie);

	} else if ((ha->intr_cap & DDI_INTR_FLAG_BLOCK) &&
	    (ha->iflags & (IFLG_INTR_MSI | IFLG_INTR_MSIX))) {

		/* Remove AIF block interrupts (MSI) */
		if ((rval = ddi_intr_block_disable(ha->htable, ha->intr_cnt))
		    != DDI_SUCCESS) {
			EL(ha, "failed intr block disable, rval=%x\n", rval);
		}

	} else {

		/* Remove AIF non-block interrupts (fixed).  */
		for (i = 0; i < ha->intr_cnt; i++) {
			if ((rval = ddi_intr_disable(ha->htable[i])) !=
			    DDI_SUCCESS) {
				EL(ha, "failed intr disable, intr#=%xh, "
				    "rval=%xh\n", i, rval);
			}
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_release_intr
 *	Releases aif legacy interrupt resources
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_release_intr(ql_adapter_state_t *ha)
{
	int32_t 	i;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (!(ha->iflags & IFLG_INTR_AIF)) {
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
		return;
	}

	ha->iflags &= ~(IFLG_INTR_AIF);
	if (ha->htable != NULL && ha->hsize > 0) {
		i = (int32_t)ha->hsize / (int32_t)sizeof (ddi_intr_handle_t);
		while (i-- > 0) {
			if (ha->htable[i] == 0) {
				EL(ha, "htable[%x]=0h\n", i);
				continue;
			}

			(void) ddi_intr_disable(ha->htable[i]);

			if (i < ha->intr_cnt) {
				(void) ddi_intr_remove_handler(ha->htable[i]);
			}

			(void) ddi_intr_free(ha->htable[i]);
		}

		kmem_free(ha->htable, ha->hsize);
		ha->htable = NULL;
	}

	ha->hsize = 0;
	ha->intr_cnt = 0;
	ha->intr_pri = 0;
	ha->intr_cap = 0;

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_legacy_intr
 *	Sets up legacy interrupts.
 *
 *	NB: Only to be used if AIF (Advanced Interupt Framework)
 *	    if NOT in the kernel.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_legacy_intr(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Setup mutexes */
	if (ql_init_mutex(ha) != DDI_SUCCESS) {
		EL(ha, "failed, mutex init\n");
		return (DDI_FAILURE);
	}

	/* Setup standard/legacy interrupt handler */
	if (ddi_add_intr(ha->dip, (uint_t)0, &ha->iblock_cookie,
	    (ddi_idevice_cookie_t *)0, ql_isr, (caddr_t)ha) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d): Failed to add legacy interrupt",
		    QL_NAME, ha->instance);
		ql_destroy_mutex(ha);
		rval = DDI_FAILURE;
	}

	if (rval == DDI_SUCCESS) {
		ha->iflags |= IFLG_INTR_LEGACY;
		EL(ha, "using legacy interrupts\n");
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_init_mutex
 *	Initializes mutex's
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_init_mutex(ql_adapter_state_t *ha)
{
	int	ret;
	void	*intr;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->iflags & IFLG_INTR_AIF) {
		intr = (void *)(uintptr_t)ha->intr_pri;
	} else {
		/* Get iblock cookies to initialize mutexes */
		if ((ret = ddi_get_iblock_cookie(ha->dip, 0,
		    &ha->iblock_cookie)) != DDI_SUCCESS) {
			EL(ha, "failed, get_iblock: %xh\n", ret);
			return (DDI_FAILURE);
		}
		intr = (void *)ha->iblock_cookie;
	}

	/* mutexes to protect the adapter state structure. */
	mutex_init(&ha->mutex, NULL, MUTEX_DRIVER, intr);

	/* mutex to protect the ISP response ring. */
	mutex_init(&ha->intr_mutex, NULL, MUTEX_DRIVER, intr);

	/* mutex to protect the mailbox registers. */
	mutex_init(&ha->mbx_mutex, NULL, MUTEX_DRIVER, intr);

	/* power management protection */
	mutex_init(&ha->pm_mutex, NULL, MUTEX_DRIVER, intr);

	/* Mailbox wait and interrupt conditional variable. */
	cv_init(&ha->cv_mbx_wait, NULL, CV_DRIVER, NULL);
	cv_init(&ha->cv_mbx_intr, NULL, CV_DRIVER, NULL);

	/* mutex to protect the ISP request ring. */
	mutex_init(&ha->req_ring_mutex, NULL, MUTEX_DRIVER, intr);

	/* Unsolicited buffer conditional variable. */
	cv_init(&ha->cv_ub, NULL, CV_DRIVER, NULL);

	mutex_init(&ha->ub_mutex, NULL, MUTEX_DRIVER, intr);
	mutex_init(&ha->cache_mutex, NULL, MUTEX_DRIVER, intr);

	/* Suspended conditional variable. */
	cv_init(&ha->cv_dr_suspended, NULL, CV_DRIVER, NULL);

	/* mutex to protect task daemon context. */
	mutex_init(&ha->task_daemon_mutex, NULL, MUTEX_DRIVER, intr);

	/* Task_daemon thread conditional variable. */
	cv_init(&ha->cv_task_daemon, NULL, CV_DRIVER, NULL);

	/* mutex to protect diag port manage interface */
	mutex_init(&ha->portmutex, NULL, MUTEX_DRIVER, intr);

	/* mutex to protect per instance f/w dump flags and buffer */
	mutex_init(&ha->dump_mutex, NULL, MUTEX_DRIVER, intr);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (DDI_SUCCESS);
}

/*
 * ql_destroy_mutex
 *	Destroys mutex's
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_destroy_mutex(ql_adapter_state_t *ha)
{
	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mutex_destroy(&ha->dump_mutex);
	mutex_destroy(&ha->portmutex);
	cv_destroy(&ha->cv_task_daemon);
	mutex_destroy(&ha->task_daemon_mutex);
	cv_destroy(&ha->cv_dr_suspended);
	mutex_destroy(&ha->cache_mutex);
	mutex_destroy(&ha->ub_mutex);
	cv_destroy(&ha->cv_ub);
	mutex_destroy(&ha->req_ring_mutex);
	cv_destroy(&ha->cv_mbx_intr);
	cv_destroy(&ha->cv_mbx_wait);
	mutex_destroy(&ha->pm_mutex);
	mutex_destroy(&ha->mbx_mutex);
	mutex_destroy(&ha->intr_mutex);
	mutex_destroy(&ha->mutex);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_fwmodule_resolve
 *	Loads and resolves external firmware module and symbols
 *
 * Input:
 *	ha:		adapter state pointer.
 *
 * Returns:
 *	ql local function return status code:
 *		QL_SUCCESS - external f/w module module and symbols resolved
 *		QL_FW_NOT_SUPPORTED - Driver does not support ISP type
 *		QL_FWMODLOAD_FAILED - Could not load f/w module (ddi failed)
 *		QL_FWSYM_NOT_FOUND - Unable to resolve internal f/w symbol
 * Context:
 *	Kernel context.
 *
 * NOTE: We currently ddi_modopen/ddi_modclose at attach/detach time.  We
 * could switch to a tighter scope around acutal download (and add an extra
 * ddi_modopen for module opens that occur before root is mounted).
 *
 */
uint32_t
ql_fwmodule_resolve(ql_adapter_state_t *ha)
{
	int8_t			module[128];
	int8_t			fw_version[128];
	uint32_t		rval = QL_SUCCESS;
	caddr_t			code, code02;
	uint8_t			*p_ucfw;
	uint16_t		*p_usaddr, *p_uslen;
	uint32_t		*p_uiaddr, *p_uilen, *p_uifw;
	uint32_t		*p_uiaddr02, *p_uilen02;
	struct fw_table		*fwt;
	extern struct fw_table	fw_table[];

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->fw_module != NULL) {
		EL(ha, "%x f/w module %d.%02d.%02d is already loaded\n",
		    ha->fw_class, ha->fw_major_version, ha->fw_minor_version,
		    ha->fw_subminor_version);
		return (rval);
	}

	/* make sure the fw_class is in the fw_table of supported classes */
	for (fwt = &fw_table[0]; fwt->fw_version; fwt++) {
		if (fwt->fw_class == ha->fw_class)
			break;			/* match */
	}
	if (fwt->fw_version == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't find f/w class %x "
		    "in driver's fw_table", QL_NAME, ha->instance,
		    ha->fw_class);
		return (QL_FW_NOT_SUPPORTED);
	}

	/*
	 * open the module related to the fw_class
	 */
	(void) snprintf(module, sizeof (module), "misc/qlc/qlc_fw_%x",
	    ha->fw_class);

	ha->fw_module = ddi_modopen(module, KRTLD_MODE_FIRST, NULL);
	if (ha->fw_module == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't load firmware file %s",
		    QL_NAME, ha->instance, module);
		return (QL_FWMODLOAD_FAILED);
	}

	/*
	 * resolve the fw module symbols, data types depend on fw_class
	 */

	switch (ha->fw_class) {
	case 0x2200:
	case 0x2300:
	case 0x6322:

		if ((code = ddi_modsym(ha->fw_module, "risc_code01",
		    NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rc01 symbol\n", module);
		} else if ((p_usaddr = ddi_modsym(ha->fw_module,
		    "risc_code_addr01", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rca01 symbol\n", module);
		} else if ((p_uslen = ddi_modsym(ha->fw_module,
		    "risc_code_length01", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rcl01 symbol\n", module);
		} else if ((p_ucfw = ddi_modsym(ha->fw_module,
		    "firmware_version", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d fwver symbol\n", module);
		}

		if (rval == QL_SUCCESS) {
			ha->risc_fw[0].code = code;
			ha->risc_fw[0].addr = *p_usaddr;
			ha->risc_fw[0].length = *p_uslen;

			(void) snprintf(fw_version, sizeof (fw_version),
			    "%d.%02d.%02d", p_ucfw[0], p_ucfw[1], p_ucfw[2]);
		}
		break;

	case 0x2400:
	case 0x2500:
	case 0x8100:

		if ((code = ddi_modsym(ha->fw_module, "risc_code01",
		    NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rc01 symbol\n", module);
		} else if ((p_uiaddr = ddi_modsym(ha->fw_module,
		    "risc_code_addr01", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rca01 symbol\n", module);
		} else if ((p_uilen = ddi_modsym(ha->fw_module,
		    "risc_code_length01", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rcl01 symbol\n", module);
		} else if ((p_uifw = ddi_modsym(ha->fw_module,
		    "firmware_version", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d fwver symbol\n", module);
		}

		if ((code02 = ddi_modsym(ha->fw_module, "risc_code02",
		    NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rc02 symbol\n", module);
		} else if ((p_uiaddr02 = ddi_modsym(ha->fw_module,
		    "risc_code_addr02", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rca02 symbol\n", module);
		} else if ((p_uilen02 = ddi_modsym(ha->fw_module,
		    "risc_code_length02", NULL)) == NULL) {
			rval = QL_FWSYM_NOT_FOUND;
			EL(ha, "failed, f/w module %d rcl02 symbol\n", module);
		}

		if (rval == QL_SUCCESS) {
			ha->risc_fw[0].code = code;
			ha->risc_fw[0].addr = *p_uiaddr;
			ha->risc_fw[0].length = *p_uilen;
			ha->risc_fw[1].code = code02;
			ha->risc_fw[1].addr = *p_uiaddr02;
			ha->risc_fw[1].length = *p_uilen02;

			(void) snprintf(fw_version, sizeof (fw_version),
			    "%d.%02d.%02d", p_uifw[0], p_uifw[1], p_uifw[2]);
		}
		break;

	default:
		EL(ha, "fw_class: '%x' is not supported\n", ha->fw_class);
		rval = QL_FW_NOT_SUPPORTED;
	}

	if (rval != QL_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d): can't resolve firmware "
		    "module %s (%x)", QL_NAME, ha->instance, module, rval);
		if (ha->fw_module != NULL) {
			(void) ddi_modclose(ha->fw_module);
			ha->fw_module = NULL;
		}
	} else {
		/*
		 * check for firmware version mismatch between module and
		 * compiled in fw_table version.
		 */

		if (strcmp(fwt->fw_version, fw_version) != 0) {

			/*
			 * If f/w / driver version mismatches then
			 * return a successful status -- however warn
			 * the user that this is NOT recommended.
			 */

			cmn_err(CE_WARN, "%s(%d): driver / f/w version "
			    "mismatch for %x: driver-%s module-%s", QL_NAME,
			    ha->instance, ha->fw_class, fwt->fw_version,
			    fw_version);

			ha->cfg_flags |= CFG_FW_MISMATCH;
		} else {
			ha->cfg_flags &= ~CFG_FW_MISMATCH;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_port_state
 *	Set the state on all adapter ports.
 *
 * Input:
 *	ha:	parent adapter state pointer.
 *	state:	port state.
 *	flags:	task daemon flags to set.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_port_state(ql_adapter_state_t *ha, uint32_t state, uint32_t flags)
{
	ql_adapter_state_t	*vha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	TASK_DAEMON_LOCK(ha);
	for (vha = ha->pha; vha != NULL; vha = vha->vp_next) {
		if (FC_PORT_STATE_MASK(vha->state) != state) {
			vha->state = state != FC_STATE_OFFLINE ?
			    (FC_PORT_SPEED_MASK(vha->state) | state) : state;
			vha->task_daemon_flags |= flags;
		}
	}
	ha->pha->task_daemon_flags |= flags & LOOP_DOWN;
	TASK_DAEMON_UNLOCK(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_el_trace_desc_ctor - Construct an extended logging trace descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
int
ql_el_trace_desc_ctor(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	ha->el_trace_desc =
	    (el_trace_desc_t *)kmem_zalloc(sizeof (el_trace_desc_t), KM_SLEEP);

	if (ha->el_trace_desc == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't construct trace descriptor",
		    QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		ha->el_trace_desc->next		= 0;
		ha->el_trace_desc->trace_buffer =
		    (char *)kmem_zalloc(EL_TRACE_BUF_SIZE, KM_SLEEP);

		if (ha->el_trace_desc->trace_buffer == NULL) {
			cmn_err(CE_WARN, "%s(%d): can't get trace buffer",
			    QL_NAME, ha->instance);
			kmem_free(ha->el_trace_desc, sizeof (el_trace_desc_t));
			rval = DDI_FAILURE;
		} else {
			ha->el_trace_desc->trace_buffer_size =
			    EL_TRACE_BUF_SIZE;
			mutex_init(&ha->el_trace_desc->mutex, NULL,
			    MUTEX_DRIVER, NULL);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_el_trace_desc_dtor - Destroy an extended logging trace descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
int
ql_el_trace_desc_dtor(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->el_trace_desc == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't destroy el trace descriptor",
		    QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		if (ha->el_trace_desc->trace_buffer != NULL) {
			kmem_free(ha->el_trace_desc->trace_buffer,
			    ha->el_trace_desc->trace_buffer_size);
		}
		mutex_destroy(&ha->el_trace_desc->mutex);
		kmem_free(ha->el_trace_desc, sizeof (el_trace_desc_t));
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * els_cmd_text	- Return a pointer to a string describing the command
 *
 * Input:	els_cmd = the els command opcode.
 * Returns:	pointer to a string.
 * Context:	Kernel context.
 */
char *
els_cmd_text(int els_cmd)
{
	cmd_table_t *entry = &els_cmd_tbl[0];

	return (cmd_text(entry, els_cmd));
}

/*
 * mbx_cmd_text - Return a pointer to a string describing the command
 *
 * Input:	mbx_cmd = the mailbox command opcode.
 * Returns:	pointer to a string.
 * Context:	Kernel context.
 */
char *
mbx_cmd_text(int mbx_cmd)
{
	cmd_table_t *entry = &mbox_cmd_tbl[0];

	return (cmd_text(entry, mbx_cmd));
}

/*
 * cmd_text	Return a pointer to a string describing the command
 *
 * Input:	entry = the command table
 *		cmd = the command.
 * Returns:	pointer to a string.
 * Context:	Kernel context.
 */
char *
cmd_text(cmd_table_t *entry, int cmd)
{
	for (; entry->cmd != 0; entry++) {
		if (entry->cmd == cmd) {
			break;
		}
	}
	return (entry->string);
}

/*
 * ql_els_24xx_mbox_cmd_iocb - els request indication.
 *
 * Input:	ha = adapter state pointer.
 *		srb = scsi request block pointer.
 *		arg = els passthru entry iocb pointer.
 * Returns:
 * Context:	Kernel context.
 */
void
ql_els_24xx_iocb(ql_adapter_state_t *ha, ql_srb_t *srb, void *arg)
{
	els_descriptor_t	els_desc;

	/* Extract the ELS information */
	ql_fca_isp_els_request(ha, (fc_packet_t *)srb->pkt, &els_desc);

	/* Construct the passthru entry */
	ql_isp_els_request_ctor(&els_desc, (els_passthru_entry_t *)arg);

	/* Ensure correct endianness */
	ql_isp_els_handle_cmd_endian(ha, srb);
}

/*
 * ql_fca_isp_els_request - Extract into an els descriptor the info required
 *			    to build an els_passthru iocb from an fc packet.
 *
 * Input:	ha = adapter state pointer.
 *		pkt = fc packet pointer
 *		els_desc = els descriptor pointer
 * Returns:
 * Context:	Kernel context.
 */
static void
ql_fca_isp_els_request(ql_adapter_state_t *ha, fc_packet_t *pkt,
    els_descriptor_t *els_desc)
{
	ls_code_t	els;

	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
	    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

	els_desc->els = els.ls_code;

	els_desc->els_handle = ha->hba_buf.acc_handle;
	els_desc->d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	els_desc->s_id.b24 = pkt->pkt_cmd_fhdr.s_id;
	/* if n_port_handle is not < 0x7d use 0 */
	if (LOCAL_LOOP_ID(ha->n_port->n_port_handle)) {
		els_desc->n_port_handle = ha->n_port->n_port_handle;
	} else {
		els_desc->n_port_handle = 0;
	}
	els_desc->control_flags = 0;
	els_desc->cmd_byte_count = pkt->pkt_cmdlen;
	/*
	 * Transmit DSD. This field defines the Fibre Channel Frame payload
	 * (without the frame header) in system memory.
	 */
	els_desc->tx_dsd.addr[0] = LSD(pkt->pkt_cmd_cookie->dmac_laddress);
	els_desc->tx_dsd.addr[1] = MSD(pkt->pkt_cmd_cookie->dmac_laddress);
	els_desc->tx_dsd.length = (uint32_t)pkt->pkt_cmd_cookie->dmac_size;

	els_desc->rsp_byte_count = pkt->pkt_rsplen;
	/*
	 * Receive DSD. This field defines the ELS response payload buffer
	 * for the ISP24xx firmware transferring the received ELS
	 * response frame to a location in host memory.
	 */
	els_desc->rx_dsd.addr[0] = LSD(pkt->pkt_resp_cookie->dmac_laddress);
	els_desc->rx_dsd.addr[1] = MSD(pkt->pkt_resp_cookie->dmac_laddress);
	els_desc->rx_dsd.length = (uint32_t)pkt->pkt_resp_cookie->dmac_size;
}

/*
 * ql_isp_els_request_ctor - Construct an els_passthru_entry iocb
 * using the els descriptor.
 *
 * Input:	ha = adapter state pointer.
 *		els_desc = els descriptor pointer.
 *		els_entry = els passthru entry iocb pointer.
 * Returns:
 * Context:	Kernel context.
 */
static void
ql_isp_els_request_ctor(els_descriptor_t *els_desc,
    els_passthru_entry_t *els_entry)
{
	uint32_t	*ptr32;

	/*
	 * Construct command packet.
	 */
	ddi_put8(els_desc->els_handle, &els_entry->entry_type,
	    (uint8_t)ELS_PASSTHRU_TYPE);
	ddi_put16(els_desc->els_handle, &els_entry->n_port_hdl,
	    els_desc->n_port_handle);
	ddi_put8(els_desc->els_handle, &els_entry->sof_type, (uint8_t)BIT_4);
	ddi_put32(els_desc->els_handle, &els_entry->rcv_exch_address,
	    (uint32_t)0);
	ddi_put8(els_desc->els_handle, &els_entry->els_cmd_opcode,
	    els_desc->els);
	ddi_put8(els_desc->els_handle, &els_entry->d_id_7_0,
	    els_desc->d_id.b.al_pa);
	ddi_put8(els_desc->els_handle, &els_entry->d_id_15_8,
	    els_desc->d_id.b.area);
	ddi_put8(els_desc->els_handle, &els_entry->d_id_23_16,
	    els_desc->d_id.b.domain);
	ddi_put8(els_desc->els_handle, &els_entry->s_id_7_0,
	    els_desc->s_id.b.al_pa);
	ddi_put8(els_desc->els_handle, &els_entry->s_id_15_8,
	    els_desc->s_id.b.area);
	ddi_put8(els_desc->els_handle, &els_entry->s_id_23_16,
	    els_desc->s_id.b.domain);
	ddi_put16(els_desc->els_handle, &els_entry->control_flags,
	    els_desc->control_flags);
	ddi_put32(els_desc->els_handle, &els_entry->rcv_payld_data_bcnt,
	    els_desc->rsp_byte_count);
	ddi_put32(els_desc->els_handle, &els_entry->xmt_payld_data_bcnt,
	    els_desc->cmd_byte_count);
	/* Load transmit data segments and count. */
	ptr32 = (uint32_t *)&els_entry->xmt_dseg_0_address;
	ddi_put16(els_desc->els_handle, &els_entry->xmt_dseg_count, 1);
	ddi_put32(els_desc->els_handle, ptr32++, els_desc->tx_dsd.addr[0]);
	ddi_put32(els_desc->els_handle, ptr32++, els_desc->tx_dsd.addr[1]);
	ddi_put32(els_desc->els_handle, ptr32++, els_desc->tx_dsd.length);
	ddi_put16(els_desc->els_handle, &els_entry->rcv_dseg_count, 1);
	ddi_put32(els_desc->els_handle, ptr32++, els_desc->rx_dsd.addr[0]);
	ddi_put32(els_desc->els_handle, ptr32++, els_desc->rx_dsd.addr[1]);
	ddi_put32(els_desc->els_handle, ptr32++, els_desc->rx_dsd.length);
}

/*
 * ql_isp_els_handle_cmd_endian - els requests must be in big endian
 *				  in host memory.
 *
 * Input:	ha = adapter state pointer.
 *		srb = scsi request block
 * Returns:
 * Context:	Kernel context.
 */
void
ql_isp_els_handle_cmd_endian(ql_adapter_state_t *ha, ql_srb_t *srb)
{
	ls_code_t	els;
	fc_packet_t	*pkt;
	uint8_t		*ptr;

	pkt = srb->pkt;

	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
	    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

	ptr = (uint8_t *)pkt->pkt_cmd;

	ql_isp_els_handle_endian(ha, ptr, els.ls_code);
}

/*
 * ql_isp_els_handle_rsp_endian - els responses must be in big endian
 *				  in host memory.
 * Input:	ha = adapter state pointer.
 *		srb = scsi request block
 * Returns:
 * Context:	Kernel context.
 */
void
ql_isp_els_handle_rsp_endian(ql_adapter_state_t *ha, ql_srb_t *srb)
{
	ls_code_t	els;
	fc_packet_t	*pkt;
	uint8_t		*ptr;

	pkt = srb->pkt;

	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
	    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

	ptr = (uint8_t *)pkt->pkt_resp;
	BIG_ENDIAN_32(&els);
	ql_isp_els_handle_endian(ha, ptr, els.ls_code);
}

/*
 * ql_isp_els_handle_endian - els requests/responses must be in big endian
 *			      in host memory.
 * Input:	ha = adapter state pointer.
 *		ptr = els request/response buffer pointer.
 *		ls_code = els command code.
 * Returns:
 * Context:	Kernel context.
 */
void
ql_isp_els_handle_endian(ql_adapter_state_t *ha, uint8_t *ptr, uint8_t ls_code)
{
	switch (ls_code) {
	case LA_ELS_PLOGI: {
		BIG_ENDIAN_32(ptr);	/* Command Code */
		ptr += 4;
		BIG_ENDIAN_16(ptr);	/* FC-PH version */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* b2b credit */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Cmn Feature flags */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Rcv data size */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Concurrent Seq */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Rel offset */
		ptr += 2;
		BIG_ENDIAN_32(ptr);	/* E_D_TOV */
		ptr += 4;		/* Port Name */
		ptr += 8;		/* Node Name */
		ptr += 8;		/* Class 1 */
		ptr += 16;		/* Class 2 */
		ptr += 16;		/* Class 3 */
		BIG_ENDIAN_16(ptr);	/* Service options */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Initiator control */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Recipient Control */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Rcv size */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Concurrent Seq */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* N_Port e2e credit */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Open Seq/Exch */
		break;
	}
	case LA_ELS_PRLI: {
		BIG_ENDIAN_32(ptr);	/* Command Code/Page length */
		ptr += 4;		/* Type */
		ptr += 2;
		BIG_ENDIAN_16(ptr);	/* Flags */
		ptr += 2;
		BIG_ENDIAN_32(ptr);	/* Originator Process associator  */
		ptr += 4;
		BIG_ENDIAN_32(ptr);	/* Responder Process associator */
		ptr += 4;
		BIG_ENDIAN_32(ptr);	/* Flags */
		break;
	}
	default:
		EL(ha, "can't handle els code %x\n", ls_code);
		break;
	}
}

/*
 * ql_n_port_plogi
 *	In N port 2 N port topology where an N Port has logged in with the
 *	firmware because it has the N_Port login initiative, we send up
 *	a plogi by proxy which stimulates the login procedure to continue.
 *
 * Input:
 *	ha = adapter state pointer.
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static int
ql_n_port_plogi(ql_adapter_state_t *ha)
{
	int		rval;
	ql_tgt_t	*tq;
	ql_head_t done_q = { NULL, NULL };

	rval = QL_SUCCESS;

	if (ha->topology & QL_N_PORT) {
		/* if we're doing this the n_port_handle must be good */
		if (LOCAL_LOOP_ID(ha->n_port->n_port_handle)) {
			tq = ql_loop_id_to_queue(ha,
			    ha->n_port->n_port_handle);
			if (tq != NULL) {
				(void) ql_send_plogi(ha, tq, &done_q);
			} else {
				EL(ha, "n_port_handle = %x, tq = %x\n",
				    ha->n_port->n_port_handle, tq);
			}
		} else {
			EL(ha, "n_port_handle = %x, tq = %x\n",
			    ha->n_port->n_port_handle, tq);
		}
		if (done_q.first != NULL) {
			ql_done(done_q.first);
		}
	}
	return (rval);
}

/*
 * Compare two WWNs. The NAA is omitted for comparison.
 *
 * Note particularly that the indentation used in this
 * function  isn't according to Sun recommendations. It
 * is indented to make reading a bit easy.
 *
 * Return Values:
 *   if first == second return  0
 *   if first > second  return  1
 *   if first < second  return -1
 */
int
ql_wwn_cmp(ql_adapter_state_t *ha, la_wwn_t *first, la_wwn_t *second)
{
	la_wwn_t t1, t2;
	int rval;

	EL(ha, "WWPN=%08x%08x\n",
	    BE_32(first->i_wwn[0]), BE_32(first->i_wwn[1]));
	EL(ha, "WWPN=%08x%08x\n",
	    BE_32(second->i_wwn[0]), BE_32(second->i_wwn[1]));
	/*
	 * Fibre Channel protocol is big endian, so compare
	 * as big endian values
	 */
	t1.i_wwn[0] = BE_32(first->i_wwn[0]);
	t1.i_wwn[1] = BE_32(first->i_wwn[1]);

	t2.i_wwn[0] = BE_32(second->i_wwn[0]);
	t2.i_wwn[1] = BE_32(second->i_wwn[1]);

	if (t1.i_wwn[0] == t2.i_wwn[0]) {
		if (t1.i_wwn[1] == t2.i_wwn[1]) {
			rval = 0;
		} else if (t1.i_wwn[1] > t2.i_wwn[1]) {
			rval = 1;
		} else {
			rval = -1;
		}
	} else {
		if (t1.i_wwn[0] > t2.i_wwn[0]) {
			rval = 1;
		} else {
			rval = -1;
		}
	}
	return (rval);
}

/*
 * ql_wait_for_td_stop
 *	Wait for task daemon to stop running.  Internal command timeout
 *	is approximately 30 seconds, so it may help in some corner
 *	cases to wait that long
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */

static int
ql_wait_for_td_stop(ql_adapter_state_t *ha)
{
	int	rval = DDI_FAILURE;
	UINT16	wait_cnt;

	for (wait_cnt = 0; wait_cnt < 3000; wait_cnt++) {
		/* The task daemon clears the stop flag on exit. */
		if (ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) {
			if (ha->cprinfo.cc_events & CALLB_CPR_START ||
			    ddi_in_panic()) {
				drv_usecwait(10000);
			} else {
				delay(drv_usectohz(10000));
			}
		} else {
			rval = DDI_SUCCESS;
			break;
		}
	}
	return (rval);
}

/*
 * ql_nvram_cache_desc_ctor - Construct an nvram cache descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
int
ql_nvram_cache_desc_ctor(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	ha->nvram_cache =
	    (nvram_cache_desc_t *)kmem_zalloc(sizeof (nvram_cache_desc_t),
	    KM_SLEEP);

	if (ha->nvram_cache == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't construct nvram cache"
		    " descriptor", QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		if (CFG_IST(ha, CFG_CTRL_24258081)) {
			ha->nvram_cache->size = sizeof (nvram_24xx_t);
		} else {
			ha->nvram_cache->size = sizeof (nvram_t);
		}
		ha->nvram_cache->cache =
		    (void *)kmem_zalloc(ha->nvram_cache->size, KM_SLEEP);
		if (ha->nvram_cache->cache == NULL) {
			cmn_err(CE_WARN, "%s(%d): can't get nvram cache buffer",
			    QL_NAME, ha->instance);
			kmem_free(ha->nvram_cache,
			    sizeof (nvram_cache_desc_t));
			ha->nvram_cache = 0;
			rval = DDI_FAILURE;
		} else {
			mutex_init(&ha->nvram_cache->mutex, NULL,
			    MUTEX_DRIVER, NULL);
			ha->nvram_cache->valid = 0;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_nvram_cache_desc_dtor - Destroy an nvram cache descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
int
ql_nvram_cache_desc_dtor(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (ha->nvram_cache == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't destroy nvram descriptor",
		    QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		if (ha->nvram_cache->cache != NULL) {
			kmem_free(ha->nvram_cache->cache,
			    ha->nvram_cache->size);
		}
		mutex_destroy(&ha->nvram_cache->mutex);
		kmem_free(ha->nvram_cache, sizeof (nvram_cache_desc_t));
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_process_idc_event - Handle an Inter-Driver Communication async event.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	void
 * Context:	Kernel context.
 */
static void
ql_process_idc_event(ql_adapter_state_t *ha)
{
	int	rval;

	switch (ha->idc_mb[0]) {
	case MBA_IDC_NOTIFICATION:
		/*
		 * The informational opcode (idc_mb[2]) can be a
		 * defined value or the mailbox command being executed
		 * on another function which stimulated this IDC message.
		 */
		ADAPTER_STATE_LOCK(ha);
		switch (ha->idc_mb[2]) {
		case IDC_OPC_DRV_START:
			if (ha->idc_flash_acc != 0) {
				ha->idc_flash_acc--;
				if (ha->idc_flash_acc == 0) {
					ha->idc_flash_acc_timer = 0;
					GLOBAL_HW_UNLOCK();
				}
			}
			if (ha->idc_restart_cnt != 0) {
				ha->idc_restart_cnt--;
				if (ha->idc_restart_cnt == 0) {
					ha->idc_restart_timer = 0;
					ADAPTER_STATE_UNLOCK(ha);
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags &= ~DRIVER_STALL;
					TASK_DAEMON_UNLOCK(ha);
					ql_restart_queues(ha);
				} else {
					ADAPTER_STATE_UNLOCK(ha);
				}
			} else {
				ADAPTER_STATE_UNLOCK(ha);
			}
			break;
		case IDC_OPC_FLASH_ACC:
			ha->idc_flash_acc_timer = 30;
			if (ha->idc_flash_acc == 0) {
				GLOBAL_HW_LOCK();
			}
			ha->idc_flash_acc++;
			ADAPTER_STATE_UNLOCK(ha);
			break;
		case IDC_OPC_RESTART_MPI:
			ha->idc_restart_timer = 30;
			ha->idc_restart_cnt++;
			ADAPTER_STATE_UNLOCK(ha);
			TASK_DAEMON_LOCK(ha);
			ha->task_daemon_flags |= DRIVER_STALL;
			TASK_DAEMON_UNLOCK(ha);
			break;
		case IDC_OPC_PORT_RESET_MBC:
		case IDC_OPC_SET_PORT_CONFIG_MBC:
			ha->idc_restart_timer = 30;
			ha->idc_restart_cnt++;
			ADAPTER_STATE_UNLOCK(ha);
			TASK_DAEMON_LOCK(ha);
			ha->task_daemon_flags |= DRIVER_STALL;
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_wait_outstanding(ha);
			break;
		default:
			ADAPTER_STATE_UNLOCK(ha);
			EL(ha, "Unknown IDC opcode=%xh %xh\n", ha->idc_mb[0],
			    ha->idc_mb[2]);
			break;
		}
		/*
		 * If there is a timeout value associated with this IDC
		 * notification then there is an implied requirement
		 * that we return an ACK.
		 */
		if (ha->idc_mb[1] & IDC_TIMEOUT_MASK) {
			rval = ql_idc_ack(ha);
			if (rval != QL_SUCCESS) {
				EL(ha, "idc_ack status=%xh %xh\n", rval,
				    ha->idc_mb[2]);
			}
		}
		break;
	case MBA_IDC_COMPLETE:
		/*
		 * We don't ACK completions, only these require action.
		 */
		switch (ha->idc_mb[2]) {
		case IDC_OPC_PORT_RESET_MBC:
		case IDC_OPC_SET_PORT_CONFIG_MBC:
			ADAPTER_STATE_LOCK(ha);
			if (ha->idc_restart_cnt != 0) {
				ha->idc_restart_cnt--;
				if (ha->idc_restart_cnt == 0) {
					ha->idc_restart_timer = 0;
					ADAPTER_STATE_UNLOCK(ha);
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags &= ~DRIVER_STALL;
					TASK_DAEMON_UNLOCK(ha);
					ql_restart_queues(ha);
				} else {
					ADAPTER_STATE_UNLOCK(ha);
				}
			} else {
				ADAPTER_STATE_UNLOCK(ha);
			}
			break;
		default:
			break; /* Don't care... */
		}
		break;
	case MBA_IDC_TIME_EXTENDED:
		QL_PRINT_10(CE_CONT, "(%d): MBA_IDC_TIME_EXTENDED="
		    "%xh\n", ha->instance, ha->idc_mb[2]);
		break;
	default:
		EL(ha, "Inconsistent IDC event =%xh %xh\n", ha->idc_mb[0],
		    ha->idc_mb[2]);
		ADAPTER_STATE_UNLOCK(ha);
		break;
	}
}
