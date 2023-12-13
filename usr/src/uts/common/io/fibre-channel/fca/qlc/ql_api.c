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

/* Copyright 2015 QLogic Corporation */

/*
 * Copyright (c) 2008, 2011, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
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
#include <ql_fm.h>

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
static ql_adapter_state_t *ql_cmd_setup(opaque_t, fc_packet_t *, int *);
static int ql_els_plogi(ql_adapter_state_t *, fc_packet_t *);
static int ql_p2p_plogi(ql_adapter_state_t *, fc_packet_t *);
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
static int ql_els_rnid(ql_adapter_state_t *, fc_packet_t *);
static int ql_els_rls(ql_adapter_state_t *, fc_packet_t *);
static int ql_busy_plogi(ql_adapter_state_t *, fc_packet_t *, ql_tgt_t *);
static int ql_login_port(ql_adapter_state_t *, port_id_t);
static int ql_login_fabric_port(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
static int ql_logout_port(ql_adapter_state_t *, port_id_t);
static ql_lun_t *ql_lun_queue(ql_adapter_state_t *, ql_tgt_t *, uint64_t);
static int ql_fcp_scsi_cmd(ql_adapter_state_t *, fc_packet_t *, ql_srb_t *);
static void ql_task_mgmt(ql_adapter_state_t *, ql_tgt_t *, fc_packet_t *,
    ql_srb_t *);
static int ql_fcp_ip_cmd(ql_adapter_state_t *, fc_packet_t *, ql_srb_t *);
static int ql_fc_services(ql_adapter_state_t *, fc_packet_t *);
static int ql_start_cmd(ql_adapter_state_t *, ql_tgt_t *, fc_packet_t *,
    ql_srb_t *);
static int ql_poll_cmd(ql_adapter_state_t *, ql_srb_t *, time_t);
static void ql_task_daemon(void *);
static void ql_task_thread(ql_adapter_state_t *);
static void ql_idle_check(ql_adapter_state_t *);
static void ql_unsol_callback(ql_srb_t *);
static int ql_process_logo_for_device(ql_adapter_state_t *, ql_tgt_t *);
static int ql_send_plogi(ql_adapter_state_t *, ql_tgt_t *, ql_head_t *);
static void ql_update_rscn(ql_adapter_state_t *, fc_affected_id_t *);
static int ql_process_rscn(ql_adapter_state_t *, fc_affected_id_t *);
static int ql_process_rscn_for_device(ql_adapter_state_t *, ql_tgt_t *);
static int ql_handle_rscn_update(ql_adapter_state_t *);
static void ql_free_unsolicited_buffer(ql_adapter_state_t *,
    fc_unsol_buf_t *);
static void ql_timer(void *);
static void ql_timeout_insert(ql_adapter_state_t *, ql_tgt_t *, ql_srb_t *);
static void ql_watchdog(ql_adapter_state_t *);
static void ql_wdg_tq_list(ql_adapter_state_t *, ql_tgt_t *);
static void ql_cmd_timeout(ql_adapter_state_t *, ql_tgt_t *q, ql_srb_t *);
static uint16_t	ql_wait_outstanding(ql_adapter_state_t *);
static void ql_iidma(ql_adapter_state_t *);
static void ql_abort_device_queues(ql_adapter_state_t *ha, ql_tgt_t *tq);
static void ql_loop_resync(ql_adapter_state_t *);
static ql_adapter_state_t *ql_fca_handle_to_state(opaque_t);
static int ql_kstat_update(kstat_t *, int);
static int ql_program_flash_address(ql_adapter_state_t *, uint32_t, uint8_t);
static size_t ql_24xx_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static size_t ql_25xx_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static size_t ql_81xx_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static size_t ql_8021_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static int ql_2200_binary_fw_dump(ql_adapter_state_t *, ql_fw_dump_t *);
static int ql_2300_binary_fw_dump(ql_adapter_state_t *, ql_fw_dump_t *);
static int ql_24xx_binary_fw_dump(ql_adapter_state_t *, ql_24xx_fw_dump_t *);
static int ql_25xx_binary_fw_dump(ql_adapter_state_t *, ql_25xx_fw_dump_t *);
static int ql_81xx_binary_fw_dump(ql_adapter_state_t *, ql_81xx_fw_dump_t *);
static int ql_read_risc_ram(ql_adapter_state_t *, uint32_t, uint32_t,
    void *);
static void *ql_read_regs(ql_adapter_state_t *, void *, void *, uint32_t,
    uint8_t);
static int ql_save_config_regs(dev_info_t *);
static int ql_restore_config_regs(dev_info_t *);
static void ql_halt(ql_adapter_state_t *, int);
static int ql_bind_dma_buffer(ql_adapter_state_t *, dma_mem_t *, int);
static void ql_unbind_dma_buffer(ql_adapter_state_t *, dma_mem_t *);
static int ql_suspend_adapter(ql_adapter_state_t *);
static int ql_bstr_to_dec(char *, uint32_t *, uint32_t);
static int ql_setup_interrupts(ql_adapter_state_t *);
static int ql_setup_msi(ql_adapter_state_t *);
static int ql_setup_msix(ql_adapter_state_t *);
static int ql_setup_fixed(ql_adapter_state_t *);
static void ql_release_intr(ql_adapter_state_t *);
static int ql_legacy_intr(ql_adapter_state_t *);
static int ql_init_mutex(ql_adapter_state_t *);
static void ql_destroy_mutex(ql_adapter_state_t *);
static void ql_fca_isp_els_request(ql_adapter_state_t *, ql_request_q_t *,
    fc_packet_t *, els_descriptor_t *);
static void ql_isp_els_request_ctor(els_descriptor_t *,
    els_passthru_entry_t *);
static int ql_n_port_plogi(ql_adapter_state_t *);
static int ql_create_queues(ql_adapter_state_t *);
static int ql_create_rsp_queue(ql_adapter_state_t *, uint16_t);
static void ql_delete_queues(ql_adapter_state_t *);
static int ql_multi_queue_support(ql_adapter_state_t *);
static int ql_map_mem_bar(ql_adapter_state_t *, ddi_acc_handle_t *, caddr_t *,
    uint32_t, uint32_t);
static void ql_completion_thread(void *);
static void ql_process_comp_queue(void *);
static int ql_abort_io(ql_adapter_state_t *vha, ql_srb_t *);
static void ql_idc(ql_adapter_state_t *);
static int ql_83xx_binary_fw_dump(ql_adapter_state_t *, ql_83xx_fw_dump_t *);
static size_t ql_83xx_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static caddr_t ql_str_ptr(ql_adapter_state_t *, caddr_t, uint32_t *);
static int ql_27xx_binary_fw_dump(ql_adapter_state_t *);
static size_t ql_27xx_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
static uint32_t ql_2700_dmp_parse_template(ql_adapter_state_t *, ql_dt_hdr_t *,
    uint8_t *, uint32_t);
static int ql_2700_dt_riob1(ql_adapter_state_t *, ql_dt_riob1_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_wiob1(ql_adapter_state_t *, ql_dt_wiob1_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_riob2(ql_adapter_state_t *, ql_dt_riob2_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_wiob2(ql_adapter_state_t *, ql_dt_wiob2_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_rpci(ql_adapter_state_t *, ql_dt_rpci_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_wpci(ql_adapter_state_t *, ql_dt_wpci_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_rram(ql_adapter_state_t *, ql_dt_rram_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_gque(ql_adapter_state_t *, ql_dt_gque_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_gfce(ql_adapter_state_t *, ql_dt_gfce_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_prisc(ql_adapter_state_t *, ql_dt_prisc_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_rrisc(ql_adapter_state_t *, ql_dt_rrisc_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_dint(ql_adapter_state_t *, ql_dt_dint_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_ghbd(ql_adapter_state_t *, ql_dt_ghbd_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_scra(ql_adapter_state_t *, ql_dt_scra_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_rrreg(ql_adapter_state_t *, ql_dt_rrreg_t *, uint8_t *,
    uint8_t *);
static void ql_2700_dt_wrreg(ql_adapter_state_t *, ql_dt_wrreg_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_rrram(ql_adapter_state_t *, ql_dt_rrram_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_rpcic(ql_adapter_state_t *, ql_dt_rpcic_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_gques(ql_adapter_state_t *, ql_dt_gques_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dt_wdmp(ql_adapter_state_t *, ql_dt_wdmp_t *, uint8_t *,
    uint8_t *);
static int ql_2700_dump_ram(ql_adapter_state_t *, uint16_t, uint32_t, uint32_t,
    uint8_t *);

/*
 * Global data
 */
static uint8_t	ql_enable_pm = 1;
static int	ql_flash_sbus_fpga = 0;
uint32_t	ql_os_release_level;
uint32_t	ql_disable_aif = 0;
uint32_t	ql_disable_intx = 0;
uint32_t	ql_disable_msi = 0;
uint32_t	ql_disable_msix = 0;
uint32_t	ql_enable_ets = 0;
uint16_t	ql_osc_wait_count = 1000;
uint32_t	ql_task_cb_dly = 64;
uint32_t	qlc_disable_load = 0;

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

/* 2700/8300 register offsets */
static reg_off_t reg_off_2700_8300 = {
	0x00,	/* flash_address */
	0x04,	/* flash_data */
	0x08,	/* ctrl_status */
	0x0c,	/* ictrl */
	0x10,	/* istatus */
	0xff,	/* semaphore - n/a */
	0xff,	/* nvram - n/a */
	0xff,	/* req_in - n/a */
	0xff,	/* req_out - n/a */
	0xff,	/* resp_in - n/a */
	0xff,	/* resp_out - n/a */
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

	0xff,	/* fpm_diag_config - n/a */
	0xff,	/* pcr - n/a */
	0xff,	/* mctr - n/a */
	0xff,	/* fb_cmd - n/a */
	0x48,	/* hccr */
	0x4c,	/* gpiod */
	0x50,	/* gpioe */
	0x58,	/* host_to_host_sema - n/a */
	0xff,	/* pri_req_in - n/a */
	0xff,	/* pri_req_out - n/a */
	0xff,	/* atio_req_in - n/a */
	0xff,	/* atio_req_out - n/a */
	0x54,	/* io_base_addr */
	0xff,	/* nx_host_int - n/a */
	0xff	/* nx_risc_int - n/a */
};

/* mutex for protecting variables shared by all instances of the driver */
kmutex_t ql_global_mutex;
kmutex_t ql_global_hw_mutex;
kmutex_t ql_global_el_mutex;
kmutex_t ql_global_timer_mutex;

/* DMA access attribute structure. */
ddi_device_acc_attr_t ql_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* I/O DMA attributes structures. */
ddi_dma_attr_t ql_64bit_io_dma_attr = {
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

ddi_dma_attr_t ql_32bit_io_dma_attr = {
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

char ql_driver_version[] = QL_VERSION;

uint32_t ql_log_entries = QL_LOG_ENTRIES;

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

	if (qlc_disable_load) {
		cmn_err(CE_WARN, "%s load disabled", QL_NAME);
		return (EINVAL);
	}

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
		mutex_init(&ql_global_timer_mutex, NULL, MUTEX_DRIVER, NULL);
		rval = mod_install(&modlinkage);
		if (rval != 0) {
			mutex_destroy(&ql_global_timer_mutex);
			mutex_destroy(&ql_global_el_mutex);
			mutex_destroy(&ql_global_hw_mutex);
			mutex_destroy(&ql_global_mutex);
			ddi_soft_state_fini(&ql_state);
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
		mutex_destroy(&ql_global_timer_mutex);
		mutex_destroy(&ql_global_el_mutex);
		mutex_destroy(&ql_global_hw_mutex);
		mutex_destroy(&ql_global_mutex);
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
		QL_PRINT_2(ha, "failed, unknown minor=%d\n",
		    getminor((dev_t)arg));
		*resultp = NULL;
		return (rval);
	}

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");

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
	uint_t			progress = 0;
	char			*buf, taskq_name[32];
	ushort_t		caps_ptr, cap;
	fc_fca_tran_t		*tran;
	ql_adapter_state_t	*ha = NULL;
	int			instance = ddi_get_instance(dip);

	static char *pmcomps[] = {
		NULL,
		PM_LEVEL_D3_STR,		/* Device OFF */
		PM_LEVEL_D0_STR,		/* Device ON */
	};

	QL_PRINT_3(NULL, "started, instance=%d, cmd=%xh\n",
	    ddi_get_instance(dip), cmd);

	buf = (char *)(kmem_zalloc(MAXPATHLEN, KM_SLEEP));

	switch (cmd) {
	case DDI_ATTACH:
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

		/* Allocate our per-device-instance structure */
		if (ddi_soft_state_zalloc(ql_state,
		    instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): soft state alloc failed",
			    QL_NAME, instance);
			goto attach_failed;
		}

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

		ha->bit32_io_dma_attr = ql_32bit_io_dma_attr;
		ha->bit64_io_dma_attr = ql_64bit_io_dma_attr;

		(void) ql_el_trace_alloc(ha);

		progress |= QL_SOFT_STATE_ALLOCED;

		/* Get extended logging and dump flags. */
		ql_common_properties(ha);

		qlc_fm_init(ha);
		progress |= QL_FCA_INIT_FM;

		ha->io_dma_attr = ha->bit32_io_dma_attr;

		if (strcmp(ddi_driver_name(ddi_get_parent(dip)),
		    "sbus") == 0) {
			EL(ha, "%s SBUS card detected\n", QL_NAME);
			ha->cfg_flags |= CFG_SBUS_CARD;
		}

		ha->dev = kmem_zalloc(sizeof (*ha->dev) *
		    DEVICE_HEAD_LIST_SIZE, KM_SLEEP);

		ha->ub_array = kmem_zalloc(sizeof (*ha->ub_array) *
		    QL_UB_LIMIT, KM_SLEEP);

		ha->adapter_stats = kmem_zalloc(sizeof (*ha->adapter_stats),
		    KM_SLEEP);

		(void) ddi_pathname(dip, buf);
		ha->devpath = kmem_zalloc(strlen(buf) + 1, KM_SLEEP);
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
				ha->pci_function_number = (uint8_t)
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

			if (qlc_fm_check_acc_handle(ha, ha->pci_handle)
			    != DDI_FM_OK) {
				qlc_fm_report_err_impact(ha,
				    QL_FM_EREPORT_ACC_HANDLE_CHECK);
				goto attach_failed;
			}

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

			if (qlc_fm_check_acc_handle(ha, ha->dev_handle)
			    != DDI_FM_OK) {
				qlc_fm_report_err_impact(ha,
				    QL_FM_EREPORT_ACC_HANDLE_CHECK);
				goto attach_failed;
			}

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

				if (qlc_fm_check_acc_handle(ha,
				    ha->iomap_dev_handle) != DDI_FM_OK) {
					qlc_fm_report_err_impact(ha,
					    QL_FM_EREPORT_ACC_HANDLE_CHECK);
					goto attach_failed;
				}
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
				ha->function_number = 1;
			}
			if (ha->device_id == 0x2322 ||
			    ha->device_id == 0x6322) {
				ha->cfg_flags |= CFG_CTRL_63XX;
				ha->fw_class = 0x6322;
				ha->risc_dump_size = QL_6322_FW_DUMP_SIZE;
			} else {
				ha->cfg_flags |= CFG_CTRL_23XX;
				ha->fw_class = 0x2300;
				ha->risc_dump_size = QL_2300_FW_DUMP_SIZE;
			}
			ha->reg_off = &reg_off_2300;
			ha->interrupt_count = 1;
			ha->osc_max_cnt = 1024;
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
			ha->cfg_flags |= CFG_CTRL_22XX;
			ha->reg_off = &reg_off_2200;
			ha->interrupt_count = 1;
			ha->osc_max_cnt = 1024;
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
				ha->function_number = 1;
			}
			ha->cfg_flags |= CFG_CTRL_24XX;
			if (ha->device_id == 0x8432) {
				ha->cfg_flags |= CFG_CTRL_MENLO;
			} else {
				ha->flags |= VP_ENABLED;
				ha->max_vports = MAX_24_VIRTUAL_PORTS;
			}

			ha->reg_off = &reg_off_2400_2500;
			ha->interrupt_count = 2;
			ha->osc_max_cnt = 2048;
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
				ha->function_number = 1;
			}
			ha->cfg_flags |= CFG_CTRL_25XX;
			ha->flags |= VP_ENABLED;
			ha->max_vports = MAX_25_VIRTUAL_PORTS;
			ha->reg_off = &reg_off_2400_2500;
			ha->mbar_queue_offset = MBAR2_REG_OFFSET;
			ha->interrupt_count = 2;
			ha->osc_max_cnt = 2048;
			ha->fw_class = 0x2500;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_25XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->els_cmd = ql_els_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			if (ql_multi_queue_support(ha) == QL_SUCCESS) {
				ha->flags |= MULTI_QUEUE;
			}
			break;

		case 0x2031:
			/* Get queue pointer memory mapped registers */
			if (ddi_dev_regsize(dip, 3, &regsize) != DDI_SUCCESS ||
			    ddi_regs_map_setup(dip, 3, &ha->mbar,
			    0, regsize, &ql_dev_acc_attr,
			    &ha->mbar_dev_handle) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): regs_map_setup"
				    "(mbar) failed", QL_NAME, instance);
				goto attach_failed;
			}
			ha->mbar_size = (uint32_t)regsize;

			if (ha->pci_function_number != 0 &&
			    ha->pci_function_number != 2) {
				ha->function_number = 1;
			}
			ha->cfg_flags |= CFG_CTRL_83XX;
			ha->flags |= VP_ENABLED | MULTI_QUEUE;
			ha->max_vports = MAX_83_VIRTUAL_PORTS;
			ha->reg_off = &reg_off_2700_8300;
			ha->mbar_queue_offset = MBAR2_REG_OFFSET;
			ha->interrupt_count = 2;
			ha->osc_max_cnt = 2048;
			ha->fw_class = 0x8301fc;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_83XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->els_cmd = ql_els_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			break;

		case 0x2071:
		case 0x2261:
		case 0x2271:
			/* Get queue pointer memory mapped registers */
			if (ddi_dev_regsize(dip, 3, &regsize) != DDI_SUCCESS ||
			    ddi_regs_map_setup(dip, 3, &ha->mbar,
			    0, regsize, &ql_dev_acc_attr,
			    &ha->mbar_dev_handle) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): regs_map_setup"
				    "(mbar) failed", QL_NAME, instance);
				goto attach_failed;
			}
			ha->mbar_size = (uint32_t)regsize;

			ha->function_number = ha->pci_function_number;
			ha->cfg_flags |= CFG_CTRL_27XX;
			ha->flags |= VP_ENABLED | MULTI_QUEUE |
			    QUEUE_SHADOW_PTRS;
			ha->max_vports = MAX_27_VIRTUAL_PORTS;
			ha->reg_off = &reg_off_2700_8300;
			ha->mbar_queue_offset = MBAR2_REG_OFFSET;
			ha->interrupt_count = 2;
			ha->osc_max_cnt = 2048;
			ha->fw_class = 0x2700;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_27XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->els_cmd = ql_els_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			break;

		case 0x8001:
			if (ql_pci_config_get8(ha, PCI_CONF_IPIN) == 4) {
				ha->function_number = 1;
			}
			ha->cfg_flags |= CFG_CTRL_81XX;
			ha->flags |= VP_ENABLED;
			ha->max_vports = MAX_81XX_VIRTUAL_PORTS;
			ha->reg_off = &reg_off_2400_2500;
			ha->mbar_queue_offset = MBAR2_REG_OFFSET;
			ha->interrupt_count = 2;
			ha->osc_max_cnt = 2048;
			ha->fw_class = 0x8100;
			if (ql_fwmodule_resolve(ha) != QL_SUCCESS) {
				goto attach_failed;
			}
			ha->risc_dump_size = QL_81XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			if (ql_multi_queue_support(ha) == QL_SUCCESS) {
				ha->flags |= MULTI_QUEUE;
			}
			break;

		case 0x8021:
			if (ha->pci_function_number & BIT_0) {
				ha->function_number = 1;
			}
			ha->cfg_flags |= CFG_CTRL_82XX;
			ha->flags |= VP_ENABLED;
			ha->max_vports = MAX_8021_VIRTUAL_PORTS;
			ha->reg_off = &reg_off_8021;
			ha->interrupt_count = 2;
			ha->osc_max_cnt = 2048;
			ha->risc_dump_size = QL_25XX_FW_DUMP_SIZE;
			ha->fcp_cmd = ql_command_24xx_iocb;
			ha->ms_cmd = ql_ms_24xx_iocb;
			ha->cmd_segs = CMD_TYPE_7_DATA_SEGMENTS;
			ha->cmd_cont_segs = CONT_TYPE_1_DATA_SEGMENTS;
			ha->io_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;

			ha->nx_pcibase = ha->iobase;
			ha->iobase += 0xBC000 + (ha->pci_function_number << 11);
			ha->iomap_iobase += 0xBC000 +
			    (ha->pci_function_number << 11);

			/* map doorbell */
			if (ddi_dev_regsize(dip, 2, &regsize) != DDI_SUCCESS ||
			    ddi_regs_map_setup(dip, 2, &ha->db_iobase,
			    0, regsize, &ql_dev_acc_attr,
			    &ha->db_dev_handle) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s(%d): regs_map_setup"
				    "(doorbell) failed", QL_NAME, instance);
				goto attach_failed;
			}
			progress |= QL_DB_IOBASE_MAPPED;

			if (qlc_fm_check_acc_handle(ha, ha->db_dev_handle)
			    != DDI_FM_OK) {
				qlc_fm_report_err_impact(ha,
				    QL_FM_EREPORT_ACC_HANDLE_CHECK);
				goto attach_failed;
			}

			ha->nx_req_in = (uint32_t *)(ha->db_iobase +
			    (ha->pci_function_number << 12));
			ha->db_read = ha->nx_pcibase + (512 * 1024) +
			    (ha->pci_function_number * 8);

			ql_8021_update_crb_int_ptr(ha);
			ql_8021_set_drv_active(ha);
			break;

		default:
			cmn_err(CE_WARN, "%s(%d): Unsupported device id: %x",
			    QL_NAME, instance, ha->device_id);
			goto attach_failed;
		}

		ha->outstanding_cmds = kmem_zalloc(
		    sizeof (*ha->outstanding_cmds) * ha->osc_max_cnt,
		    KM_SLEEP);

		/* Setup interrupts */
		if ((rval = ql_setup_interrupts(ha)) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): Failed to add interrupt, "
			    "rval=%xh", QL_NAME, instance, rval);
			goto attach_failed;
		}

		progress |= (QL_INTR_ADDED | QL_MUTEX_CV_INITED);

		/* Setup hba buffer. */
		if (ql_create_queues(ha) != QL_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): request queue DMA memory "
			    "alloc failed", QL_NAME, instance);
			goto attach_failed;
		}
		progress |= QL_HBA_BUFFER_SETUP;

		/* Allocate resource for QLogic IOCTL */
		(void) ql_alloc_xioctl_resource(ha);


		if (ql_nvram_cache_desc_ctor(ha) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): can't setup nvram cache",
			    QL_NAME, instance);
			goto attach_failed;
		}

		progress |= QL_NVRAM_CACHE_CREATED;

		if (ql_plogi_params_desc_ctor(ha) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): can't setup plogi params",
			    QL_NAME, instance);
			goto attach_failed;
		}

		progress |= QL_PLOGI_PARAMS_CREATED;

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
			int	rval, rval1;
			char	ver_fmt[256];

			rval1 = (int)snprintf(ver_fmt, (size_t)sizeof (ver_fmt),
			    "Firmware version %d.%d.%d", ha->fw_major_version,
			    ha->fw_minor_version, ha->fw_subminor_version);

			if (CFG_IST(ha, CFG_CTRL_81XX)) {
				rval = (int)snprintf(ver_fmt + rval1,
				    (size_t)sizeof (ver_fmt),
				    ", MPI fw version %d.%d.%d",
				    ha->mpi_fw_major_version,
				    ha->mpi_fw_minor_version,
				    ha->mpi_fw_subminor_version);

				if (ha->subsys_id == 0x17B ||
				    ha->subsys_id == 0x17D) {
					(void) snprintf(ver_fmt + rval1 + rval,
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
		tran->fca_num_npivports = ha->max_vports ?
		    ha->max_vports - 1 : 0;
		bcopy(ha->loginparams.node_ww_name.raw_wwn,
		    tran->fca_perm_pwwn.raw_wwn, 8);

		if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
			ha->io_dma_attr = ha->bit64_io_dma_attr;
			ha->fcsm_cmd_dma_attr = ha->bit64_io_dma_attr;
			ha->fcsm_rsp_dma_attr = ha->bit64_io_dma_attr;
			ha->fcip_cmd_dma_attr = ha->bit64_io_dma_attr;
			ha->fcip_rsp_dma_attr = ha->bit64_io_dma_attr;
			ha->fcp_cmd_dma_attr = ha->bit64_io_dma_attr;
			ha->fcp_rsp_dma_attr = ha->bit64_io_dma_attr;
			ha->fcp_data_dma_attr = ha->bit64_io_dma_attr;
		} else {
			ha->io_dma_attr = ha->bit32_io_dma_attr;
			ha->fcsm_cmd_dma_attr = ha->bit32_io_dma_attr;
			ha->fcsm_rsp_dma_attr = ha->bit32_io_dma_attr;
			ha->fcip_cmd_dma_attr = ha->bit32_io_dma_attr;
			ha->fcip_rsp_dma_attr = ha->bit32_io_dma_attr;
			ha->fcp_cmd_dma_attr = ha->bit32_io_dma_attr;
			ha->fcp_rsp_dma_attr = ha->bit32_io_dma_attr;
			ha->fcp_data_dma_attr = ha->bit32_io_dma_attr;
		}
		ha->fcsm_cmd_dma_attr.dma_attr_sgllen = QL_FCSM_CMD_SGLLEN;
		ha->fcsm_rsp_dma_attr.dma_attr_sgllen = QL_FCSM_RSP_SGLLEN;
		ha->fcip_cmd_dma_attr.dma_attr_sgllen = QL_FCIP_CMD_SGLLEN;
		ha->fcip_rsp_dma_attr.dma_attr_sgllen = QL_FCIP_RSP_SGLLEN;
		ha->fcp_cmd_dma_attr.dma_attr_sgllen = QL_FCP_CMD_SGLLEN;
		ha->fcp_rsp_dma_attr.dma_attr_sgllen = QL_FCP_RSP_SGLLEN;
		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ha->io_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcsm_cmd_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcsm_rsp_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcip_cmd_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcip_rsp_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcp_cmd_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcp_rsp_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
			ha->fcp_data_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;
		}

		/* Specify the amount of space needed in each packet */
		tran->fca_pkt_size = sizeof (ql_srb_t);

		/* command limits are usually dictated by hardware */
		tran->fca_cmd_max = ha->osc_max_cnt;

		/* dmaattr are static, set elsewhere. */
		tran->fca_dma_attr = &ha->io_dma_attr;
		tran->fca_dma_fcp_cmd_attr = &ha->fcp_cmd_dma_attr;
		tran->fca_dma_fcp_rsp_attr = &ha->fcp_rsp_dma_attr;
		tran->fca_dma_fcp_data_attr = &ha->fcp_data_dma_attr;
		tran->fca_dma_fcsm_cmd_attr = &ha->fcsm_cmd_dma_attr;
		tran->fca_dma_fcsm_rsp_attr = &ha->fcsm_rsp_dma_attr;
		tran->fca_dma_fcip_cmd_attr = &ha->fcip_cmd_dma_attr;
		tran->fca_dma_fcip_rsp_attr = &ha->fcip_rsp_dma_attr;
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

		EL(ha, "Transport interface setup. FCA version %d\n",
		    tran->fca_version);

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

		/* Determine and populate HBA fru info */
		ql_setup_fruinfo(ha);

		/* Release global state lock. */
		GLOBAL_STATE_UNLOCK();

		/* Start one second driver timer. */
		GLOBAL_TIMER_LOCK();
		if (ql_timer_timeout_id == NULL) {
			ql_timer_ticks = drv_usectohz(1000000);
			ql_timer_timeout_id = timeout(ql_timer, (void *)0,
			    ql_timer_ticks);
		}
		GLOBAL_TIMER_UNLOCK();

		/* Setup task_daemon thread. */
		(void) snprintf(taskq_name, sizeof (taskq_name),
		    "qlc_%d_driver_thread", instance);
		ha->driver_thread_taskq = ddi_taskq_create(NULL, taskq_name, 1,
		    TASKQ_DEFAULTPRI, 0);
		(void) ddi_taskq_dispatch(ha->driver_thread_taskq,
		    ql_task_daemon, ha, DDI_SLEEP);
		ha->task_daemon_flags |= TASK_DAEMON_ALIVE_FLG;

		(void) snprintf(taskq_name, sizeof (taskq_name),
		    "qlc_%d_comp_thd", instance);
		ha->completion_taskq = ddi_taskq_create(0, taskq_name,
		    ha->completion_thds, maxclsyspri, 0);
		for (size = 0; size < ha->completion_thds; size++) {
			(void) ddi_taskq_dispatch(ha->completion_taskq,
			    ql_completion_thread, ha, DDI_SLEEP);
		}

		progress |= QL_TASK_DAEMON_STARTED;

		ddi_report_dev(dip);

		/* Disable link reset in panic path */
		ha->lip_on_panic = 1;

		rval = DDI_SUCCESS;
		break;

attach_failed:
		if (progress & QL_FCA_INIT_FM) {
			qlc_fm_fini(ha);
			progress &= ~QL_FCA_INIT_FM;
		}

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

		if (progress & QL_PLOGI_PARAMS_CREATED) {
			(void) ql_plogi_params_desc_dtor(ha);
			progress &= ~QL_PLOGI_PARAMS_CREATED;
		}

		if (progress & QL_NVRAM_CACHE_CREATED) {
			(void) ql_nvram_cache_desc_dtor(ha);
			progress &= ~QL_NVRAM_CACHE_CREATED;
		}

		if (progress & QL_TASK_DAEMON_STARTED) {
			if (ha->driver_thread_taskq) {
				while (ha->task_daemon_flags &
				    TASK_DAEMON_ALIVE_FLG) {
					/* Delay for 1 tick (10 ms). */
					ql_awaken_task_daemon(ha, NULL,
					    TASK_DAEMON_STOP_FLG, 0);
					delay(1);
				}
				ha->task_daemon_flags &= ~TASK_DAEMON_STOP_FLG;

				ddi_taskq_destroy(ha->driver_thread_taskq);
				ha->driver_thread_taskq = NULL;
			}
			if (ha->completion_taskq) {
				ADAPTER_STATE_LOCK(ha);
				ha->flags |= COMP_THD_TERMINATE;
				ADAPTER_STATE_UNLOCK(ha);

				do {
					COMP_Q_LOCK(ha);
					cv_broadcast(&ha->cv_comp_thread);
					COMP_Q_UNLOCK(ha);
					ql_delay(ha, 10000);
				} while (ha->comp_thds_active != 0);

				ddi_taskq_destroy(ha->completion_taskq);
				ha->completion_taskq = NULL;
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
		if (progress & QL_REGS_MAPPED) {
			if (ha->mbar_dev_handle) {
				ddi_regs_map_free(&ha->mbar_dev_handle);
				ha->mbar_dev_handle = 0;
			}
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
			ql_delete_queues(ha);
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

			if (ha->outstanding_cmds != NULL) {
				kmem_free(ha->outstanding_cmds,
				    sizeof (*ha->outstanding_cmds) *
				    ha->osc_max_cnt);
			}

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
			(void) ql_el_trace_dealloc(ha);

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

		/* Restart driver timer. */
		GLOBAL_TIMER_LOCK();
		if (ql_timer_timeout_id == NULL) {
			ql_timer_timeout_id = timeout(ql_timer, (void *)0,
			    ql_timer_ticks);
		}
		GLOBAL_TIMER_LOCK();

		/* Wake up command start routine. */
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~ADAPTER_SUSPENDED;
		ADAPTER_STATE_UNLOCK(ha);

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
		QL_PRINT_2(ha, "failed instance=%d, rval = %xh\n",
		    ddi_get_instance(dip), rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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
	uint16_t		index;
	ql_link_t		*link;
	char			*buf;
	timeout_id_t		timer_id = NULL;
	int			suspend, rval = DDI_SUCCESS;

	ha = ddi_get_soft_state(ql_state, ddi_get_instance(dip));
	if (ha == NULL) {
		QL_PRINT_2(NULL, "no adapter, instance=%d\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	QL_PRINT_3(ha, "started, cmd=%xh\n", cmd);

	buf = (char *)(kmem_zalloc(MAXPATHLEN, KM_SLEEP));

	switch (cmd) {
	case DDI_DETACH:
		ADAPTER_STATE_LOCK(ha);
		ha->flags |= (ADAPTER_SUSPENDED | ABORT_CMDS_LOOP_DOWN_TMO);
		ADAPTER_STATE_UNLOCK(ha);

		/* Wait for task thread to see suspend flag. */
		while (!(ha->task_daemon_flags & TASK_DAEMON_STALLED_FLG) &&
		    ha->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) {
			ql_awaken_task_daemon(ha, NULL, 0, 0);
			/* Delay for 1 tick (10 milliseconds). */
			delay(1);
		}

		if (ha->driver_thread_taskq) {
			while (ha->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) {
				/* Delay for 1 tick (10 milliseconds). */
				ql_awaken_task_daemon(ha, NULL,
				    TASK_DAEMON_STOP_FLG, 0);
				delay(1);
			}
			ha->task_daemon_flags &= ~TASK_DAEMON_STOP_FLG;

			ddi_taskq_destroy(ha->driver_thread_taskq);
			ha->driver_thread_taskq = NULL;
		}

		if (ha->completion_taskq) {
			ADAPTER_STATE_LOCK(ha);
			ha->flags |= COMP_THD_TERMINATE;
			ADAPTER_STATE_UNLOCK(ha);

			do {
				COMP_Q_LOCK(ha);
				cv_broadcast(&ha->cv_comp_thread);
				COMP_Q_UNLOCK(ha);
				ql_delay(ha, 10000);
			} while (ha->comp_thds_active != 0);

			ddi_taskq_destroy(ha->completion_taskq);
			ha->completion_taskq = NULL;
		}

		/* Disable driver timer if no adapters. */
		GLOBAL_TIMER_LOCK();
		if (ql_timer_timeout_id && ql_hba.first == &ha->hba &&
		    ql_hba.last == &ha->hba) {
			timer_id = ql_timer_timeout_id;
			ql_timer_timeout_id = NULL;
		}
		GLOBAL_TIMER_UNLOCK();

		if (timer_id) {
			(void) untimeout(timer_id);
		}

		GLOBAL_STATE_LOCK();
		ql_remove_link(&ql_hba, &ha->hba);
		GLOBAL_STATE_UNLOCK();

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
			if (CFG_IST(ha, CFG_CTRL_82XX)) {
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

		ql_delete_queues(ha);
		ql_free_phys(ha, &ha->fwexttracebuf);
		ql_free_phys(ha, &ha->fwfcetracebuf);

		ddi_regs_map_free(&ha->dev_handle);
		if (ha->sbus_fpga_iobase != NULL) {
			ddi_regs_map_free(&ha->sbus_fpga_dev_handle);
		}
		if (ha->mbar_dev_handle != NULL) {
			ddi_regs_map_free(&ha->mbar_dev_handle);
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
		    sizeof (*ha->outstanding_cmds) * ha->osc_max_cnt);

		if (ha->n_port != NULL) {
			kmem_free(ha->n_port, sizeof (ql_n_port_info_t));
		}

		if (ha->devpath != NULL) {
			kmem_free(ha->devpath, strlen(ha->devpath) + 1);
		}

		kmem_free(ha->dev, sizeof (*ha->dev) * DEVICE_HEAD_LIST_SIZE);

		(void) ql_plogi_params_desc_dtor(ha);

		(void) ql_nvram_cache_desc_dtor(ha);

		(void) qlc_fm_fini(ha);

		EL(ha, "detached\n");

		(void) ql_el_trace_dealloc(ha);

		ddi_soft_state_free(ql_state, (int)ha->instance);

		rval = DDI_SUCCESS;

		break;

	case DDI_SUSPEND:
		ADAPTER_STATE_LOCK(ha);
		ha->flags |= ADAPTER_SUSPENDED;
		ADAPTER_STATE_UNLOCK(ha);

		/* Disable driver timer if last adapter. */
		GLOBAL_TIMER_LOCK();
		if (ql_timer_timeout_id && ql_hba.first == &ha->hba &&
		    ql_hba.last == &ha->hba) {
			timer_id = ql_timer_timeout_id;
			ql_timer_timeout_id = NULL;
		}
		GLOBAL_TIMER_UNLOCK();

		if (timer_id) {
			(void) untimeout(timer_id);
		}

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

		EL(ha, "suspended\n");

		break;

	default:
		rval = DDI_FAILURE;
		break;
	}

	kmem_free(buf, MAXPATHLEN);

	if (rval != DDI_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(ha, "no hba or PM not supported\n");
		return (rval);
	}

	QL_PRINT_10(ha, "started\n");

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

	(void) snprintf(buf, MAXPATHLEN,
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

		if (ha->pm_busy || ((ha->task_daemon_flags &
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

	QL_PRINT_10(ha, "done\n");

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
		QL_PRINT_2(NULL, "no adapter, instance=%d\n",
		    ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		ql_8021_clr_hw_intr(ha);
		ql_8021_clr_fw_intr(ha);
		WRT16_IO_REG(ha, mailbox_in[0], MBC_TOGGLE_INTERRUPT);
		WRT16_IO_REG(ha, mailbox_in[1], 0);
		WRT32_IO_REG(ha, nx_host_int, NX_MBX_CMD);
		for (timer = 0; timer < 20000; timer++) {
			stat = RD32_IO_REG(ha, risc2host);
			if (stat & BIT_15) {
				ql_8021_clr_hw_intr(ha);
				if ((stat & 0xff) < 0x12) {
					ql_8021_clr_fw_intr(ha);
					break;
				}
				ql_8021_clr_fw_intr(ha);
			}
			drv_usecwait(100);
		}
		ql_8021_wr_32(ha, ha->nx_legacy_intr.tgt_mask_reg, 0x0400);
		WRT16_IO_REG(ha, mailbox_in[0], MBC_STOP_FIRMWARE);
		WRT16_IO_REG(ha, mailbox_in[1], 0);
		WRT32_IO_REG(ha, nx_host_int, NX_MBX_CMD);
		for (timer = 0; timer < 20000; timer++) {
			stat = RD32_IO_REG(ha, risc2host);
			if (stat & BIT_15) {
				ql_8021_clr_hw_intr(ha);
				if ((stat & 0xff) < 0x12) {
					ql_8021_clr_fw_intr(ha);
					break;
				}
				ql_8021_clr_fw_intr(ha);
			}
			drv_usecwait(100);
		}
	} else if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
		WRT16_IO_REG(ha, mailbox_in[0], MBC_STOP_FIRMWARE);
		WRT16_IO_REG(ha, mailbox_in[1], 0);
		WRT16_IO_REG(ha, mailbox_in[2], 0);
		WRT16_IO_REG(ha, mailbox_in[3], 0);
		WRT16_IO_REG(ha, mailbox_in[4], 0);
		WRT16_IO_REG(ha, mailbox_in[5], 0);
		WRT16_IO_REG(ha, mailbox_in[6], 0);
		WRT16_IO_REG(ha, mailbox_in[7], 0);
		WRT16_IO_REG(ha, mailbox_in[8], 0);
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
		if (CFG_IST(ha, CFG_MWB_4096_SUPPORT)) {
			WRT32_IO_REG(ha, ctrl_status, ISP_RESET | DMA_SHUTDOWN |
			    MWB_4096_BYTES);
		} else {
			WRT32_IO_REG(ha, ctrl_status, ISP_RESET | DMA_SHUTDOWN);
		}
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

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(ha, "no adapter, instance=%d\n",
		    ddi_get_instance(dip));
		return (NULL);
	}
	QL_PRINT_10(ha, "started\n");

	/* Verify port number is supported. */
	if (port_npiv != 0) {
		if (!(ha->flags & VP_ENABLED)) {
			QL_PRINT_2(ha, "FC_NPIV_NOT_SUPPORTED\n");
			port_info->pi_error = FC_NPIV_NOT_SUPPORTED;
			return (NULL);
		}
		if (!(ha->flags & POINT_TO_POINT)) {
			QL_PRINT_2(ha, "FC_NPIV_WRONG_TOPOLOGY\n");
			port_info->pi_error = FC_NPIV_WRONG_TOPOLOGY;
			return (NULL);
		}
		if (!(ha->flags & FDISC_ENABLED)) {
			QL_PRINT_2(ha, "switch does not support "
			    "FDISC\n");
			port_info->pi_error = FC_NPIV_FDISC_FAILED;
			return (NULL);
		}
		if (bind_info->port_num >= ha->max_vports) {
			QL_PRINT_2(ha, "port number=%d "
			    "FC_OUTOFBOUNDS\n", bind_info->port_num);
			port_info->pi_error = FC_OUTOFBOUNDS;
			return (NULL);
		}
	} else if (bind_info->port_num != 0) {
		QL_PRINT_2(ha, "failed, port number=%d is not "
		    "supported\n", bind_info->port_num);
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
				QL_PRINT_2(ha, "failed to enable "
				    "virtual port=%d\n",
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
		vha->bind_info.port_statec_cb = bind_info->port_statec_cb;
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
			if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
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

	QL_PRINT_10(ha, "done, pi_port_state=%xh, "
	    "pi_s_id.port_id=%xh\n",
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
	} else {
		QL_PRINT_10(ha, "started\n");

		if (!(ha->flags & FCA_BOUND)) {
			/*EMPTY*/
			QL_PRINT_2(ha, "port already unbound\n");
		} else {
			if (ha->vp_index != 0 && ha->flags & VP_ENABLED) {
				(void) ql_vport_control(ha, (uint8_t)
				    (CFG_IST(ha, CFG_FC_TYPE) ?
				    VPC_DISABLE_INIT : VPC_DISABLE_LOGOUT));
				if ((tq = ql_loop_id_to_queue(ha,
				    FL_PORT_24XX_HDL)) != NULL) {
					(void) ql_logout_fabric_port(ha, tq);
				}
				flgs = FCA_BOUND | VP_ENABLED;
			} else {
				flgs = FCA_BOUND;
			}
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~flgs;
			ADAPTER_STATE_UNLOCK(ha);
		}

		QL_PRINT_10(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

	sp = (ql_srb_t *)pkt->pkt_fca_private;
	sp->flags = 0;
	sp->handle = 0;

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
	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		/* Setup DMA for scatter gather list. */
		sp->sg_dma.size = sizeof (cmd6_2400_dma_t);
		sp->sg_dma.type = LITTLE_ENDIAN_DMA;
		sp->sg_dma.max_cookie_count = 1;
		sp->sg_dma.alignment = 64;
		if (ql_alloc_phys(ha, &sp->sg_dma, KM_SLEEP) != QL_SUCCESS) {
			rval = FC_NOMEM;
		}
	}
#endif	/* __sparc */

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

	sp = (ql_srb_t *)pkt->pkt_fca_private;

	if (sp->magic_number != QL_FCA_BRAND) {
		EL(ha, "failed, FC_BADPACKET\n");
		rval = FC_BADPACKET;
	} else {
		sp->magic_number = 0;
		ql_free_phys(ha, &sp->sg_dma);
		rval = FC_SUCCESS;
	}

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(NULL, "failed, ql_cmd_setup=%xh, fcah=%ph\n",
		    rval, fca_handle);
		return (FC_INVALID_REQUEST);
	}
	QL_PRINT_3(ha, "started\n");

	/* Wait for suspension to end. */
	TASK_DAEMON_LOCK(ha);
	while (DRIVER_SUSPENDED(ha)) {
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

	QL_PRINT_10(ha, "els.ls_code=%xh, d_id=%xh\n", els.ls_code,
	    pkt->pkt_cmd_fhdr.d_id);

	sp->iocb = ha->els_cmd;
	sp->req_cnt = 1;

	switch (els.ls_code) {
	case LA_ELS_RJT:
	case LA_ELS_ACC:
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

	/*
	 * Return success if the srb was consumed by an iocb. The packet
	 * completion callback will be invoked by the response handler.
	 */
	if (rval == QL_CONSUMED) {
		rval = FC_SUCCESS;
	} else if (rval == FC_SUCCESS &&
	    !(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
		/* Do command callback only if no error */
		ql_io_comp(sp);
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "rval=%x, ls_code=%xh sent to d_id=%xh, sp=%ph\n",
		    rval, els.ls_code, pkt->pkt_cmd_fhdr.d_id, sp);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

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
		if (ha->flags & MULTI_CHIP_ADAPTER &&
		    !CFG_IST(ha, CFG_SBUS_CARD)) {
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
		*rptr = ha->loginparams.common_service.rx_bufsize;
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

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

	mapbuf->lilp_magic = (uint16_t)MAGIC_LIRP;
	mapbuf->lilp_myalpa = ha->d_id.b.al_pa;

	/* Wait for suspension to end. */
	TASK_DAEMON_LOCK(ha);
	while (DRIVER_SUSPENDED(ha)) {
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
		EL(ha, "failed, FC_NO_MAP\n");
		rval = FC_NO_MAP;
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "my_alpa %xh len %xh "
		    "data %xh %xh %xh %xh\n",
		    mapbuf->lilp_myalpa, mapbuf->lilp_length,
		    mapbuf->lilp_alpalist[0], mapbuf->lilp_alpalist[1],
		    mapbuf->lilp_alpalist[2], mapbuf->lilp_alpalist[3]);
	}

	QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, ql_cmd_setup=%xh, fcah=%ph\n",
		    rval, fca_handle);
		return (rval);
	}
	QL_PRINT_3(ha, "started, d_id=%xh\n", pkt->pkt_cmd_fhdr.d_id);

	/* Reset SRB flags. */
	sp->flags &= ~(SRB_ISP_STARTED | SRB_ISP_COMPLETED | SRB_RETRY |
	    SRB_POLL | SRB_WATCHDOG_ENABLED | SRB_UB_CALLBACK |
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
		} else {
			pkt->pkt_state = FC_PKT_LOCAL_RJT;
			pkt->pkt_reason = FC_REASON_UNSUPPORTED;
			rval = FC_TRANSPORT_ERROR;
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
				if (CFG_IST(ha, CFG_FCIP_SUPPORT) &&
				    ha->vp_index == 0) {
					sp->flags |= SRB_IP_PKT;
					rval = ql_fcp_ip_cmd(ha, pkt, sp);
				} else {
					cmn_err(CE_NOTE, "%s(%d) FC-IP is not "
					    "supported on this adapter\n",
					    QL_NAME, ha->instance);
					pkt->pkt_state = FC_PKT_LOCAL_RJT;
					pkt->pkt_reason = FC_REASON_UNSUPPORTED;
					rval = FC_TRANSPORT_ERROR;
				}
			}
			break;

		case R_CTL_UNSOL_CONTROL:
			if (pkt->pkt_cmd_fhdr.type == FC_TYPE_FC_SERVICES) {
				sp->flags |= SRB_GENERIC_SERVICES_PKT;
				rval = ql_fc_services(ha, pkt);
			} else {
				pkt->pkt_state = FC_PKT_LOCAL_RJT;
				pkt->pkt_reason = FC_REASON_UNSUPPORTED;
				rval = FC_TRANSPORT_ERROR;
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
		QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started, count = %xh\n", *count);

	QL_PM_LOCK(ha);
	if (ha->power_level != PM_LEVEL_D0) {
		QL_PM_UNLOCK(ha);
		QL_PRINT_3(ha, "down done\n");
		return (FC_FAILURE);
	}
	QL_PM_UNLOCK(ha);

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

	/* IP buffer. */
	if (ub_updated) {
		if (type == FC_TYPE_IS8802_SNAP &&
		    CFG_IST(ha, CFG_FCIP_SUPPORT) &&
		    ha->vp_index == 0) {

			ADAPTER_STATE_LOCK(ha);
			ha->flags |= IP_ENABLED;
			ADAPTER_STATE_UNLOCK(ha);

			if (!(ha->flags & IP_INITIALIZED)) {
				if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
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
		QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

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
			delay(drv_usectohz(100000));
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
			QL_UB_LOCK(ha);
			cv_broadcast(&ha->pha->cv_ub);
			QL_UB_UNLOCK(ha);
		}
	}

	if (rval != FC_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(NULL, ": failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	QL_PRINT_3(ha, "started\n");

	/* Acquire adapter state lock. */
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
		QL_PRINT_3(ha, "done\n");
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
/*ARGSUSED*/
static int
ql_abort(opaque_t fca_handle, fc_packet_t *pkt, int flags)
{
	port_id_t		d_id;
	ql_link_t		*link;
	ql_adapter_state_t	*ha, *pha;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	int			rval = FC_ABORTED;
	ql_srb_t		*sp = (ql_srb_t *)pkt->pkt_fca_private;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}

	pha = ha->pha;

	QL_PRINT_3(ha, "started\n");

	/* Get target queue pointer. */
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	tq = ql_d_id_to_queue(ha, d_id);

	if ((tq == NULL) || (lq = sp->lun_queue) == NULL ||
	    (pha->task_daemon_flags & LOOP_DOWN)) {
		if (tq == NULL || lq == NULL) {
			EL(ha, "failed, FC_TRANSPORT_ERROR\n");
			rval = FC_TRANSPORT_ERROR;
		} else {
			EL(ha, "failed, FC_OFFLINE\n");
			rval = FC_OFFLINE;
		}
		return (rval);
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
			ql_done(&sp->cmd, B_TRUE);
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
		ql_request_q_t	*req_q;
		request_t	*pio;
		uint32_t	index;

		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);

		INTR_LOCK(ha);
		sp->flags |= SRB_ABORTING;
		if (sp->handle != 0) {
			index = sp->handle & OSC_INDEX_MASK;
			if (ha->outstanding_cmds[index] == sp) {
				ha->outstanding_cmds[index] =
				    QL_ABORTED_SRB(ha);
			}
			if (ha->req_q[1] != NULL && sp->rsp_q_number != 0) {
				req_q = ha->req_q[1];
			} else {
				req_q = ha->req_q[0];
			}
			pio = sp->request_ring_ptr;
			if (sp->handle ==
			    ddi_get32(req_q->req_ring.acc_handle,
			    &pio->handle)) {
				EL(ha, "inflight sp=%ph, handle=%xh, "
				    "invalidated\n", (void *)sp, sp->handle);
				for (index = 0; index < sp->req_cnt; index++) {
					ddi_put8(req_q->req_ring.acc_handle,
					    &pio->entry_type,
					    ABORTED_ENTRY_TYPE);
					pio++;
					if (pio == (request_t *)
					    ((uintptr_t)req_q->req_ring.bp +
					    req_q->req_ring.size)) {
						pio = req_q->req_ring.bp;
					}
				}
			}
			/* Decrement outstanding commands on device. */
			if (tq->outcnt != 0) {
				tq->outcnt--;
			}
			if (sp->flags & SRB_FCP_CMD_PKT &&
			    lq->lun_outcnt != 0) {
				lq->lun_outcnt--;
			}
			/* Remove command from watchdog queue. */
			if (sp->flags & SRB_WATCHDOG_ENABLED) {
				ql_remove_link(&tq->wdg, &sp->wdg);
				sp->flags &= ~SRB_WATCHDOG_ENABLED;
			}
			/* Release device queue lock. */
			INTR_UNLOCK(ha);

			(void) ql_abort_command(ha, sp);
			sp->handle = 0;
		} else {
			/* Release device queue lock. */
			INTR_UNLOCK(ha);
		}

		sp->flags &= ~SRB_IN_TOKEN_ARRAY;
		sp->flags |= SRB_ISP_COMPLETED;
		pkt->pkt_reason = CS_ABORTED;
		rval = FC_ABORTED;
	}

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}

	QL_PRINT_3(ha, "started, cmd=%d\n", cmd);

	if (ha->task_daemon_flags & (ABORT_ISP_ACTIVE | LOOP_RESYNC_ACTIVE |
	    DRIVER_STALL | ISP_ABORT_NEEDED | LOOP_RESYNC_NEEDED)) {
		EL(ha, "driver stalled, FC_TRAN_BUSY, dtf=%xh\n",
		    ha->task_daemon_flags);
		return (FC_TRAN_BUSY);
	}

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
		QL_PRINT_3(ha, "done\n");
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
	fc_fca_p2p_info_t	*p2p_info;

	ha = ql_fca_handle_to_state(fca_handle);
	if (ha == NULL) {
		QL_PRINT_2(NULL, ": failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (FC_UNBOUND);
	}
	pha = ha->pha;

#ifdef	QL_DEBUG_LEVEL_10
	if (cmd->pm_cmd_code != FC_PORT_GET_FW_REV) {
		QL_PRINT_10(ha, "started=%xh\n", cmd->pm_cmd_code);
	}
#endif

	if (ha->task_daemon_flags & (ABORT_ISP_ACTIVE | LOOP_RESYNC_ACTIVE |
	    DRIVER_STALL | ISP_ABORT_NEEDED | LOOP_RESYNC_NEEDED)) {
		EL(ha, "driver stalled, FC_TRAN_BUSY, dtf=%xh\n",
		    ha->task_daemon_flags);
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
		if (ql_dump_firmware(ha) != QL_SUCCESS) {
			EL(ha, "failed, FC_PORT_FORCE_DUMP FC_FAILURE\n");
			rval = FC_FAILURE;
		}
		break;
	case FC_PORT_GET_DUMP_SIZE:
		bp = (uint32_t *)cmd->pm_data_buf;
		*bp = pha->risc_dump_size;
		break;
	case FC_PORT_DIAG:
		EL(ha, "diag cmd=%xh\n", cmd->pm_cmd_flags);

		/* Wait for suspension to end. */
		for (timer = 0; timer < 3000 &&
		    pha->task_daemon_flags & QL_LOOP_TRANSITION; timer++) {
			ql_delay(ha, 10000);
		}

		if (pha->task_daemon_flags & QL_LOOP_TRANSITION) {
			EL(ha, "failed, FC_TRAN_BUSY-2\n");
			rval = FC_TRAN_BUSY;
			break;
		}

		if ((rval2 = ql_stall_driver(ha, 0)) != QL_SUCCESS) {
			EL(ha, "stall_driver status=%xh, FC_TRAN_BUSY\n",
			    rval2);
			ql_restart_driver(ha);
			rval = FC_TRAN_BUSY;
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
			for (i0 = 1, cnt = 0; i0 < pha->osc_max_cnt;
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
			if (!CFG_IST(ha, CFG_CTRL_22XX)) {
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
			if (CFG_IST(ha, CFG_CTRL_22XX)) {
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

			if (CFG_IST(ha, CFG_LOOP_POINT_SUPPORT)) {
				(void) ql_set_loop_point(ha, lb->options);
			}

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

			if (CFG_IST(ha, CFG_LOOP_POINT_SUPPORT)) {
				(void) ql_set_loop_point(ha, 0);
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
			    !(CFG_IST(ha, CFG_FCOE_SUPPORT))) {
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
		ql_restart_driver(ha);
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
		if ((rval2 = ql_stall_driver(ha, 0)) != QL_SUCCESS) {
			EL(ha, "stall_driver status=%xh, FC_TRAN_BUSY\n",
			    rval2);
			ql_restart_driver(ha);
			rval = FC_TRAN_BUSY;
			break;
		}
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
		ql_restart_driver(ha);
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
			LITTLE_ENDIAN_32(&rls->rls_prim_seq_err);
			LITTLE_ENDIAN_32(&rls->rls_invalid_word);
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
		if ((rval2 = ql_stall_driver(ha, 0)) != QL_SUCCESS) {
			EL(ha, "stall_driver status=%xh, FC_TRAN_BUSY\n",
			    rval2);
			ql_restart_driver(ha);
			rval = FC_TRAN_BUSY;
			break;
		}
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_1)) {
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
		ql_restart_driver(ha);
		break;

	case FC_PORT_GET_P2P_INFO:

		bzero(cmd->pm_data_buf, cmd->pm_data_len);
		if (cmd->pm_data_len < sizeof (fc_fca_p2p_info_t)) {
			EL(ha, "inadequate data length")
			rval = FC_NOMEM;
			break;
		}

		p2p_info = (fc_fca_p2p_info_t *)cmd->pm_data_buf;

		if ((ha->topology & QL_N_PORT) &&
		    (ha->flags & POINT_TO_POINT)) {
			p2p_info->fca_d_id = ha->d_id.b24;
			p2p_info->d_id = ha->n_port->d_id.b24;

			bcopy((void *) &ha->n_port->port_name[0],
			    (caddr_t)&p2p_info->pwwn, 8);
			bcopy((void *) &ha->n_port->node_name[0],
			    (caddr_t)&p2p_info->nwwn, 8);
			rval = FC_SUCCESS;

			EL(ha, "P2P HID=%xh, d_id=%xh, WWPN=%02x%02x%02x%02x"
			    "%02x%02x%02x%02x : "
			    "WWNN=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    p2p_info->fca_d_id, p2p_info->d_id,
			    ha->n_port->port_name[0],
			    ha->n_port->port_name[1], ha->n_port->port_name[2],
			    ha->n_port->port_name[3], ha->n_port->port_name[4],
			    ha->n_port->port_name[5], ha->n_port->port_name[6],
			    ha->n_port->port_name[7], ha->n_port->node_name[0],
			    ha->n_port->node_name[1], ha->n_port->node_name[2],
			    ha->n_port->node_name[3], ha->n_port->node_name[4],
			    ha->n_port->node_name[5], ha->n_port->node_name[6],
			    ha->n_port->node_name[7]);
			break;
		} else {
			EL(ha, "No p2p info reported in non n2n topology\n");
			rval = FC_BADCMD;
		}
		break;

	case FC_PORT_DOWNLOAD_FW:
		EL(ha, "unsupported=%xh, FC_BADCMD\n", cmd->pm_cmd_code);
		rval = FC_BADCMD;
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

	if (rval != FC_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (NULL);
	}
	QL_PRINT_3(ha, "started, d_id=%xh\n", id.b24);

	tq = ql_d_id_to_queue(ha, id);

	if (tq == NULL && id.b24 != 0 && id.b24 != FS_BROADCAST) {
		EL(ha, "failed, no tq available for d_id: %xh\n", id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(NULL, "failed, no adapter=%ph\n",
		    (void *)fca_handle);
		return (NULL);
	}
	pha = ha->pha;

	QL_PRINT_3(ha, "started\n");

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

	/* Check for packet already running. */
	if (sp->handle != 0) {
		*rval = FC_DEVICE_BUSY;
		cmn_err(CE_WARN, "%s(%d) already running pkt=%p, sp=%p, "
		    "sp->pkt=%p, sp->hdl=%x, spf=%x, cq=%p\n", QL_NAME,
		    ha->instance, (void *)pkt, (void *)sp, (void *)sp->pkt,
		    sp->handle, sp->flags, (void *)sp->cmd.head);
		return (NULL);
	}
	if (ha->rsp_queues_cnt > 1) {
		ADAPTER_STATE_LOCK(ha);
		sp->rsp_q_number = ha->rsp_q_number++;
		if (ha->rsp_q_number == ha->rsp_queues_cnt) {
			ha->rsp_q_number = 0;
		}
		ADAPTER_STATE_UNLOCK(ha);
	} else {
		sp->rsp_q_number = 0;
	}

	/*
	 * Check DMA pointers.
	 */
	*rval = DDI_SUCCESS;
	if (pkt->pkt_cmd_acc != NULL && pkt->pkt_cmdlen) {
		QL_CLEAR_DMA_HANDLE(pkt->pkt_cmd_dma);

		*rval = qlc_fm_check_dma_handle(ha, pkt->pkt_cmd_dma);
		if (*rval == DDI_FM_OK) {
			*rval = qlc_fm_check_acc_handle(ha,
			    pkt->pkt_cmd_acc);
		}
	}

	if (pkt->pkt_resp_acc != NULL && *rval == DDI_SUCCESS &&
	    pkt->pkt_rsplen != 0) {
		QL_CLEAR_DMA_HANDLE(pkt->pkt_resp_dma);

		*rval = qlc_fm_check_dma_handle(ha, pkt->pkt_resp_dma);
		if (*rval == DDI_FM_OK) {
			*rval = qlc_fm_check_acc_handle(ha,
			    pkt->pkt_resp_acc);
		}
	}

	/*
	 * Minimum branch conditional; Change it with care.
	 */
	if (((pkt->pkt_data_acc != NULL) & (*rval == DDI_SUCCESS) &
	    (pkt->pkt_datalen != 0)) != 0) {
		QL_CLEAR_DMA_HANDLE(pkt->pkt_data_dma);

		*rval = qlc_fm_check_dma_handle(ha, pkt->pkt_data_dma);
		if (*rval == DDI_FM_OK) {
			*rval = qlc_fm_check_acc_handle(ha,
			    pkt->pkt_data_acc);
		}
	}

	if (*rval != DDI_FM_OK) {
		pkt->pkt_state = FC_PKT_TRAN_ERROR;
		pkt->pkt_reason = FC_REASON_DMA_ERROR;
		pkt->pkt_expln = FC_EXPLN_NONE;
		pkt->pkt_action = FC_ACTION_RETRYABLE;

		/* Do command callback. */
		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
			ql_io_comp(sp);
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started, d_id=%xh\n", pkt->pkt_cmd_fhdr.d_id);

	TASK_DAEMON_LOCK(ha);
	if (!(ha->task_daemon_flags & STATE_ONLINE)) {
		TASK_DAEMON_UNLOCK(ha);
		QL_PRINT_3(ha, "offline done\n");
		return (FC_OFFLINE);
	}
	TASK_DAEMON_UNLOCK(ha);

	bzero(&acc, sizeof (acc));
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	ret = QL_SUCCESS;

	if (CFG_IST(ha, CFG_N2N_SUPPORT) && ha->topology & QL_N_PORT) {
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
		acc.common_service.rx_bufsize =
		    ha->loginparams.common_service.rx_bufsize;
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
			if (CFG_IST(ha, CFG_IIDMA_SUPPORT)) {
				tq->flags |= TQF_IIDMA_NEEDED;
			}
			DEVICE_QUEUE_UNLOCK(tq);

			if (CFG_IST(ha, CFG_IIDMA_SUPPORT)) {
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
		QL_PRINT_3(ha, "done\n");
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
	uint16_t	loop_id;

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
		EL(ha, "rval=%xh, id=%x\n", rval, id);
		/* check all the ones not logged in for possible use */
		if (rval == QL_NOT_LOGGED_IN) {
			if (tq->master_state == PD_STATE_PLOGI_PENDING) {
				ha->n_port->n_port_handle = tq->loop_id;
				EL(ha, "loop_id=%xh, master state=%x\n",
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
					EL(ha, "n_port_handle loop_id=%xh, "
					    "master state=%xh\n",
					    tq->loop_id, tq->master_state);
					break;
				} else if (tq->loop_id ==
				    ha->n_port->n_port_handle) {
				    /* avoid a lint error */
					uint16_t *hndl;
					uint16_t val;

					hndl = &ha->n_port->n_port_handle;
					val = *hndl;
					val++;
					val++;
					*hndl = val;
				}
			EL(ha, "rval=%xh, id=%d, n_port_handle loop_id=%xh, "
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
			EL(ha, "rval=%xh, id=%d, n_port_handle loop_id=%xh, "
			    "master state=%x\n", rval, id, tq->loop_id,
			    tq->master_state);
		}
	}
	(void) ddi_dma_sync(pkt->pkt_cmd_dma, 0, 0, DDI_DMA_SYNC_FORDEV);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	/*
	 * In case fw does not have the loop id ready, driver assume 0 is
	 * used since this is p2p and there is only one remote port.
	 */
	if (id == LAST_LOCAL_LOOP_ID + 1) {
		EL(ha, "out of range loop id; rval=%xh, id=%xh, d_id=%xh\n",
		    rval, id, d_id.b24);
	} else {
		EL(ha, "remote port loop_id '%x' has been logged in, d_id=%x\n",
		    id, d_id.b24);
	}

	tq = ql_d_id_to_queue(ha, d_id);

	/*
	 * LV could use any d_id it likes.
	 * tq may not be available yet.
	 */
	if (tq == NULL) {
		if (id != LAST_LOCAL_LOOP_ID + 1) {
			loop_id = id;
		} else {
			loop_id = 0;
		}
		/* Acquire adapter state lock. */
		ADAPTER_STATE_LOCK(ha);

		tq = ql_dev_init(ha, d_id, loop_id);

		ADAPTER_STATE_UNLOCK(ha);
	}

	/*
	 * Lun0 should always allocated since tq is
	 * derived from lun queue in ql_els_passthru_entry
	 * in the interrupt handler.
	 */
	sp->lun_queue = ql_lun_queue(ha, tq, 0);

	DEVICE_QUEUE_LOCK(tq);
	ql_timeout_insert(ha, tq, sp);
	DEVICE_QUEUE_UNLOCK(tq);

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

	QL_PRINT_3(ha, "started, d_id=%xh\n", pkt->pkt_cmd_fhdr.d_id);

	bzero(&acc, sizeof (acc));
	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	if (CFG_IST(ha, CFG_N2N_SUPPORT) && ha->topology & QL_N_PORT) {
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
			if (ql_wwn_cmp(ha, (la_wwn_t *)tq->port_name,
			    (la_wwn_t *)ha->loginparams.nport_ww_name.raw_wwn)
			    == 1) {
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
	if ((tq != NULL) || (accept != 0)) {
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
		acc.common_service.rx_bufsize =
		    ha->loginparams.common_service.rx_bufsize;
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
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started, d_id=%xh\n", pkt->pkt_cmd_fhdr.d_id);

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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started, d_id=%xh\n", pkt->pkt_cmd_fhdr.d_id);

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;

	tq = ql_d_id_to_queue(ha, d_id);
	if (tq != NULL) {
		(void) ql_get_port_database(ha, tq, PDF_NONE);

		if ((ha->topology & QL_N_PORT) &&
		    (tq->master_state == PD_STATE_PLOGI_COMPLETED)) {

			/* always set lun_queue */
			sp->lun_queue = ql_lun_queue(ha, tq, 0);

			DEVICE_QUEUE_LOCK(tq);
			ql_timeout_insert(ha, tq, sp);
			DEVICE_QUEUE_UNLOCK(tq);
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
		/* in case of P2P, tq might not have been created yet */
		if (ha->topology & QL_N_PORT) {

			/* Acquire adapter state lock. */
			ADAPTER_STATE_LOCK(ha);
			tq = ql_dev_init(ha, d_id, ha->n_port->n_port_handle);
			ADAPTER_STATE_UNLOCK(ha);

			/* always alloc lun #0 */
			sp->lun_queue = ql_lun_queue(ha, tq, 0);
			bcopy((void *)&ha->n_port->port_name[0],
			    (void *) &tq->port_name[0], 8);
			bcopy((void *)&ha->n_port->node_name[0],
			    (void *) &tq->node_name[0], 8);

			DEVICE_QUEUE_LOCK(tq);
			ql_timeout_insert(ha, tq, sp);
			DEVICE_QUEUE_UNLOCK(tq);

			ql_start_iocb(ha, sp);
			rval = QL_CONSUMED;

		} else {

			la_els_rjt_t rjt;

			/* Build RJT. */
			bzero(&rjt, sizeof (rjt));
			rjt.ls_code.ls_code = LA_ELS_RJT;

			ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&rjt,
			    (uint8_t *)pkt->pkt_resp, sizeof (rjt),
			    DDI_DEV_AUTOINCR);

			pkt->pkt_state = FC_PKT_TRAN_ERROR;
			pkt->pkt_reason = FC_REASON_NO_CONNECTION;
			EL(ha, "LA_ELS_RJT, FC_REASON_NO_CONNECTION\n");
		}
	}

	if ((rval != FC_SUCCESS) && (rval != QL_CONSUMED)) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started, d_id=%xh\n", pkt->pkt_cmd_fhdr.d_id);

	/* Build ACC. */
	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_cmd, sizeof (acc), DDI_DEV_AUTOINCR);

	acc.ls_code = LA_ELS_ACC;
	acc.service_params[2] = 1;

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	pkt->pkt_state = FC_PKT_SUCCESS;

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	if (ha->topology & QL_FABRIC_CONNECTION) {
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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	if (ha->topology & QL_FABRIC_CONNECTION) {
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
		bcopy((void *)&els.lpb[0], (void *)&lfa.payload[6], 16);

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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
	if (ha->topology & QL_FABRIC_CONNECTION) {
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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	bzero(&acc, sizeof (acc));
	if (ha->topology & QL_FABRIC_CONNECTION) {
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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	bzero(&acc, sizeof (acc));
	if (ha->topology & QL_FABRIC_CONNECTION) {
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

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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
/* ARGSUSED */
static int
ql_els_farp_req(ql_adapter_state_t *ha, fc_packet_t *pkt)
{
	ql_acc_rjt_t	acc;

	QL_PRINT_3(ha, "started\n");

	bzero(&acc, sizeof (acc));

	/* Build ACC. */
	acc.ls_code.ls_code = LA_ELS_ACC;

	pkt->pkt_state = FC_PKT_SUCCESS;

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	bzero(&acc, sizeof (acc));

	/* Build ACC. */
	acc.ls_code.ls_code = LA_ELS_ACC;

	pkt->pkt_state = FC_PKT_SUCCESS;

	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
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

	QL_PRINT_3(ha, "started\n");

	req_len = FCIO_RNID_MAX_DATA_LEN + sizeof (fc_rnid_hdr_t);
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
	bcopy(rnid_acc, &acc.hdr, sizeof (fc_rnid_hdr_t));
	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	kmem_free(rnid_acc, req_len);
	pkt->pkt_state = FC_PKT_SUCCESS;

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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
	acc.rls_link_params.rls_sig_loss = rls_acc->rls_sig_loss;
	acc.rls_link_params.rls_invalid_word = rls_acc->rls_invalid_word;
	acc.rls_link_params.rls_invalid_crc = rls_acc->rls_invalid_crc;
	ddi_rep_put8(pkt->pkt_resp_acc, (uint8_t *)&acc,
	    (uint8_t *)pkt->pkt_resp, sizeof (acc), DDI_DEV_AUTOINCR);

	kmem_free(rls_acc, sizeof (*rls_acc));
	pkt->pkt_state = FC_PKT_SUCCESS;

	QL_PRINT_3(ha, "done\n");

	return (FC_SUCCESS);
}

static int
ql_busy_plogi(ql_adapter_state_t *ha, fc_packet_t *pkt, ql_tgt_t *tq)
{
	port_id_t	d_id;
	ql_srb_t	*sp;
	fc_unsol_buf_t	*ubp;
	ql_link_t	*link, *next_link;
	int		rval = FC_SUCCESS;
	int		cnt = 5;

	QL_PRINT_3(ha, "started\n");

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
		QL_PRINT_3(ha, "done, busy or async\n");
		return (rval);
	}

	/*
	 * Let us give daemon sufficient time and hopefully
	 * when transport retries PLOGI, it would have flushed
	 * callback queue.
	 */
	TASK_DAEMON_LOCK(ha);
	for (link = ha->unsol_callback_queue.first; link != NULL;
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started, d_id=%xh\n", d_id.b24);

	/* Do not login vports */
	for (vha = ha->pha; vha != NULL; vha = vha->vp_next) {
		if (vha->d_id.b24 == d_id.b24) {
			EL(ha, "failed=%xh, d_id=%xh vp_index=%xh\n",
			    QL_FUNCTION_FAILED, d_id.b24, vha->vp_index);
			return (QL_FUNCTION_FAILED);
		}
	}

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
	if (d_id.b24 == FS_NAME_SERVER) {
		if (!(ha->topology & QL_FABRIC_CONNECTION)) {
			EL(ha, "failed=%xh, d_id=%xh no fabric\n",
			    QL_FUNCTION_FAILED, d_id.b24);
			return (QL_FUNCTION_FAILED);
		}

		loop_id = (uint16_t)(CFG_IST(ha, CFG_ISP_FW_TYPE_2) ?
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
		if (!(CFG_IST(ha, CFG_CTRL_82XX))) {
			rval = ql_login_fabric_port(ha, tq, loop_id);
			if (rval == QL_SUCCESS) {
				tq->loop_id = loop_id;
				tq->flags |= TQF_FABRIC_DEVICE;
				(void) ql_get_port_database(ha, tq, PDF_NONE);
			}
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
	} else if (ha->topology & QL_FABRIC_CONNECTION) {
		/* Locate unused loop ID. */
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
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
				ADAPTER_STATE_LOCK(ha);
				loop_id = ha->pha->free_loop_id++;
				ADAPTER_STATE_UNLOCK(ha);
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
		EL(ha, "failed, rval=%xh, d_id=%xh\n",
		    rval, d_id.b24);
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

	QL_PRINT_3(ha, "started, d_id=%xh\n", tq->d_id.b24);

	/*
	 * QL_PARAMETER_ERROR also means the firmware is not able to allocate
	 * PCB entry due to resource issues, or collision.
	 */
	do {
		rval = ql_login_fport(ha, tq, loop_id, LFF_NONE, &mr);
		if ((rval == QL_PARAMETER_ERROR) ||
		    ((rval == QL_COMMAND_ERROR) && (mr.mb[1] == 2 ||
		    mr.mb[1] == 3 || mr.mb[1] == 7 || mr.mb[1] == 0xd))) {
			retry++;
			drv_usecwait(ha->plogi_params->retry_dly_usec);
		} else {
			break;
		}
	} while (retry < ha->plogi_params->retry_cnt);

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
			QL_PRINT_2(ha, "Loop ID is now "
			    "reassigned; old pairs: [%xh, %xh] and [%xh, %xh];"
			    "new pairs: [%xh, unknown] and [%xh, %xh]\n",
			    tq->d_id.b24, loop_id,
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

			case 0xd:
			case 4:
				rval = QL_FUNCTION_TIMEOUT;
				break;
			case 1:
			case 5:
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
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started, d_id=%xh, loop_id=%xh\n", d_id.b24, loop_id);

	index = ql_alpa_to_index[d_id.b.al_pa];

	/* If device queue exists, set proper loop ID. */
	for (link = ha->dev[index].first; link != NULL; link = link->next) {
		tq = link->base_address;
		if (tq->d_id.b24 == d_id.b24) {
			tq->loop_id = loop_id;

			/* Reset port down retry count. */
			tq->port_down_retry_count = ha->port_down_retry_count;
			tq->qfull_retry_count = ha->qfull_retry_count;

			break;
		}
	}

	/* If device does not have queue. */
	if (link == NULL) {
		tq = (ql_tgt_t *)kmem_zalloc(sizeof (ql_tgt_t), KM_SLEEP);
		if (tq != NULL) {
			/*
			 * mutex to protect the device queue,
			 * does not block interrupts.
			 */
			mutex_init(&tq->mutex, NULL, MUTEX_DRIVER,
			    ha->intr_pri);

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
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	for (link = tq->lun_queues.first; link != NULL; link = link->next) {
		lq = link->base_address;
		if (lq->cmd.first != NULL) {
			EL(ha, "cmd %ph pending in lq=%ph, lun=%xh\n",
			    lq->cmd.first, lq, lq->lun_no);
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

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_lun_queue
 *	Allocate LUN queue if does not exists.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:		target queue.
 *	lun_addr:	LUN number.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
static ql_lun_t *
ql_lun_queue(ql_adapter_state_t *ha, ql_tgt_t *tq, uint64_t lun_addr)
{
	ql_lun_t	*lq;
	ql_link_t	*link;
	uint16_t	lun_no, lun_no_tmp;
	fcp_ent_addr_t	*fcp_ent_addr = (fcp_ent_addr_t *)&lun_addr;

	QL_PRINT_3(ha, "started\n");

	/* Fast path. */
	if (tq->last_lun_queue != NULL && tq->last_lun_queue->lun_addr ==
	    lun_addr) {
		QL_PRINT_3(ha, "fast done\n");
		return (tq->last_lun_queue);
	}

	/* If device queue exists, set proper loop ID. */
	for (link = tq->lun_queues.first; link != NULL; link = link->next) {
		lq = link->base_address;
		if (lq->lun_addr == lun_addr) {
			QL_PRINT_3(ha, "found done\n");
			tq->last_lun_queue = lq;
			return (lq);
		}
	}

	/* Check the LUN addressing levels. */
	if (fcp_ent_addr->ent_addr_1 != 0 || fcp_ent_addr->ent_addr_2 != 0 ||
	    fcp_ent_addr->ent_addr_3 != 0) {
		EL(ha, "Unsupported LUN Addressing level=0x%llxh", lun_addr);
	}

	lun_no_tmp = CHAR_TO_SHORT(lobyte(fcp_ent_addr->ent_addr_0),
	    hibyte(fcp_ent_addr->ent_addr_0));

	lun_no = lun_no_tmp & ~(QL_LUN_AM_MASK << 8);

	if (lun_no_tmp & (QL_LUN_AM_LUN << 8)) {
		EL(ha, "Unsupported first level LUN Addressing method=%xh, "
		    "lun=%d(%xh)\n", lun_no_tmp & (QL_LUN_AM_MASK << 8),
		    lun_no, lun_no_tmp);
	}

	/* Create and initialize LUN queue. */
	lq = (ql_lun_t *)kmem_zalloc(sizeof (ql_lun_t), KM_SLEEP);
	if (lq != NULL) {
		lq->link.base_address = lq;
		lq->target_queue = tq;
		lq->lun_addr = lun_addr;
		lq->lun_no = lun_no;

		DEVICE_QUEUE_LOCK(tq);
		ql_add_link_b(&tq->lun_queues, &lq->link);
		DEVICE_QUEUE_UNLOCK(tq);
		tq->last_lun_queue = lq;
	}

	QL_PRINT_3(ha, "done\n");

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
	uint64_t	fcp_ent_addr = 0;

	QL_PRINT_3(ha, "started\n");

	tq = (ql_tgt_t *)pkt->pkt_fca_device;
	if (tq == NULL) {
		d_id.r.rsvd_1 = 0;
		d_id.b24 = pkt->pkt_cmd_fhdr.d_id;
		tq = ql_d_id_to_queue(ha, d_id);
	}

	sp->fcp = (struct fcp_cmd *)pkt->pkt_cmd;
	fcp_ent_addr = *(uint64_t *)(&sp->fcp->fcp_ent_addr);
	if (tq != NULL &&
	    (sp->lun_queue = ql_lun_queue(ha, tq, fcp_ent_addr)) != NULL) {

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
				    (!CFG_IST(ha, CFG_CTRL_82XX) ||
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
			QL_PRINT_3(ha, "done\n");

			return (ql_start_cmd(ha, tq, pkt, sp));
		}
	} else {
		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;

		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
			ql_io_comp(sp);
		}
	}

	QL_PRINT_3(ha, "done\n");

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
	ql_lun_t		*lq = sp->lun_queue;

	QL_PRINT_3(ha, "started\n");

	fcpr = (fcp_rsp_t *)pkt->pkt_resp;
	rsp = (struct fcp_rsp_info *)(pkt->pkt_resp + sizeof (fcp_rsp_t));

	bzero(fcpr, pkt->pkt_rsplen);

	fcpr->fcp_u.fcp_status.rsp_len_set = 1;
	fcpr->fcp_response_len = 8;

	if (sp->fcp->fcp_cntl.cntl_clr_aca) {
		if (ql_clear_aca(ha, tq, lq) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_reset_lun) {
		if (ql_lun_reset(ha, tq, lq) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_reset_tgt) {
		if (ql_target_reset(ha, tq, ha->loop_reset_delay) !=
		    QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_clr_tsk) {
		if (ql_clear_task_set(ha, tq, lq) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else if (sp->fcp->fcp_cntl.cntl_abort_tsk) {
		if (ql_abort_task_set(ha, tq, lq) != QL_SUCCESS) {
			rsp->rsp_code = FCP_TASK_MGMT_FAILED;
		}
	} else {
		rsp->rsp_code = FCP_TASK_MGMT_NOT_SUPPTD;
	}

	pkt->pkt_state = FC_PKT_SUCCESS;

	/* Do command callback. */
	if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp) {
		ql_io_comp(sp);
	}

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		QL_PRINT_3(ha, "done\n");

		return (ql_start_cmd(ha, tq, pkt, sp));
	} else {
		pkt->pkt_state = FC_PKT_LOCAL_RJT;
		pkt->pkt_reason = FC_REASON_NO_CONNECTION;

		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) && pkt->pkt_comp)
			ql_io_comp(sp);
	}

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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

		if (tq->flags & TQF_LOGIN_NEEDED) {
			DEVICE_QUEUE_LOCK(tq);
			tq->flags &= ~TQF_LOGIN_NEEDED;
			DEVICE_QUEUE_UNLOCK(tq);
			(void) ql_login_fport(ha, tq, tq->loop_id, LFF_NONE,
			    NULL);
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
			    (uint16_t)(cnt / ha->cmd_cont_segs);
			if (cnt % ha->cmd_cont_segs) {
				sp->req_cnt = (uint16_t)(sp->req_cnt + 2);
			} else {
				sp->req_cnt++;
			}
		} else {
			sp->req_cnt = 1;
		}
		rval = ql_start_cmd(ha, tq, pkt, sp);

		QL_PRINT_3(ha, "done, ql_start_cmd=%xh\n", rval);

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
		ql_io_comp((ql_srb_t *)pkt->pkt_fca_private);
	}

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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
		ql_done(&sp->cmd, B_FALSE);
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
		if (ql_poll_cmd(ha, sp, poll_wait) != QL_SUCCESS &&
		    pkt->pkt_state == FC_PKT_SUCCESS) {
			pkt->pkt_state = FC_PKT_TIMEOUT;
			pkt->pkt_reason = FC_REASON_HW_ERROR;
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

		(void) qlc_fm_check_pkt_dma_handle(ha, sp);
		/*
		 * This should only happen during CPR dumping
		 */
		if (!(pkt->pkt_tran_flags & FC_TRAN_NO_INTR) &&
		    pkt->pkt_comp) {
			sp->flags &= ~SRB_POLL;
			(*pkt->pkt_comp)(pkt);
		}
	}

	QL_PRINT_3(ha, "done\n");

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
	uint32_t		index;
	int			rval = QL_SUCCESS;
	time_t			msecs_left = poll_wait * 100;	/* 10ms inc */
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	while (sp->flags & SRB_POLL) {

		if ((ha->flags & INTERRUPTS_ENABLED) == 0 ||
		    ha->idle_timer >= 15 || ddi_in_panic() ||
		    curthread->t_flag & T_INTR_THREAD) {

			/* If waiting for restart, do it now. */
			if (ha->port_retry_timer != 0) {
				ADAPTER_STATE_LOCK(ha);
				ha->port_retry_timer = 0;
				ADAPTER_STATE_UNLOCK(ha);

				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |= PORT_RETRY_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
			}

			ADAPTER_STATE_LOCK(ha);
			ha->flags |= POLL_INTR;
			ADAPTER_STATE_UNLOCK(ha);

			if (INTERRUPT_PENDING(ha)) {
				(void) ql_isr_aif((caddr_t)ha, 0);
				INTR_LOCK(ha);
				ha->intr_claimed = TRUE;
				INTR_UNLOCK(ha);
			}
			if (ha->flags & NO_INTR_HANDSHAKE) {
				for (index = 0; index < ha->rsp_queues_cnt;
				    index++) {
					(void) ql_isr_aif((caddr_t)ha,
					    (caddr_t)((uintptr_t)(index + 1)));
				}
			}

			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~POLL_INTR;
			ADAPTER_STATE_UNLOCK(ha);

			/*
			 * Call task thread function in case the
			 * daemon is not running.
			 */
			TASK_DAEMON_LOCK(ha);

			if (!ddi_in_panic() && QL_DAEMON_NOT_ACTIVE(ha) &&
			    QL_TASK_PENDING(ha)) {
				ql_task_thread(ha);
			}

			TASK_DAEMON_UNLOCK(ha);
		}

		if (msecs_left == 0) {
			if (rval == QL_SUCCESS) {
				EL(ha, "timeout\n");
				rval = QL_FUNCTION_TIMEOUT;
				if (ql_abort_io(ha, sp) == QL_SUCCESS) {
					sp->pkt->pkt_reason = CS_ABORTED;
					sp->cmd.next = NULL;
					ql_done(&sp->cmd, B_FALSE);
					break;
				}
				sp->flags |= SRB_COMMAND_TIMEOUT;
				EL(ha, "abort failed, isp_abort_needed\n");
				ql_awaken_task_daemon(ha, NULL,
				    ISP_ABORT_NEEDED, 0);
				msecs_left = 30 * 100;
			} else {
				break;
			}
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

	if (ddi_in_panic()) {
		DEVICE_QUEUE_UNLOCK(tq);
		QL_PRINT_3(ha, "panic/active exit\n");
		return;
	}

	while ((link = lq->cmd.first) != NULL) {
		sp = link->base_address;

		/* Exit if can not start commands. */
		if (DRIVER_SUSPENDED(ha) ||
		    (ha->flags & ONLINE) == 0 ||
		    !VALID_DEVICE_ID(ha, tq->loop_id) ||
		    tq->flags & (TQF_RSCN_RCVD | TQF_NEED_AUTHENTICATION |
		    TQF_QUEUE_SUSPENDED)) {
			EL(vha, "break, d_id=%xh, tdf=%xh, tqf=%xh, spf=%xh, "
			    "haf=%xh, loop_id=%xh sp=%ph\n", tq->d_id.b24,
			    ha->task_daemon_flags, tq->flags, sp->flags,
			    ha->flags, tq->loop_id, sp);
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
				QL_PRINT_8(ha, "break, d_id=%xh, "
				    "lf=%xh, lun_outcnt=%xh\n",
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

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_done
 *	Process completed commands.
 *
 * Input:
 *	link:	first command link in chain.
 *	cmplt:	do command complete call back.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_done(ql_link_t *link, boolean_t cmplt)
{
	ql_adapter_state_t	*ha;
	ql_link_t		*next_link;
	ql_srb_t		*sp;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	uint64_t		set_flags;

	QL_PRINT_3(NULL, "started\n");

	for (; link != NULL; link = next_link) {
		next_link = link->next;
		sp = link->base_address;
		link->prev = link->next = NULL;
		link->head = NULL;
		ha = sp->ha;
		set_flags = 0;

		if (sp->flags & SRB_UB_CALLBACK) {
			QL_UB_LOCK(ha);
			if (sp->flags & SRB_UB_IN_ISP) {
				if (ha->ub_outcnt != 0) {
					ha->ub_outcnt--;
				}
				if (ha->flags & IP_ENABLED) {
					set_flags |= NEED_UNSOLICITED_BUFFERS;
				}
			}
			QL_UB_UNLOCK(ha);
			ql_awaken_task_daemon(ha, sp, set_flags, 0);
		} else {
			/* Free outstanding command slot. */
			INTR_LOCK(ha);
			if (sp->handle != 0) {
				EL(ha, "free sp=%ph, sp->hdl=%xh\n",
				    (void *)sp, sp->handle);
				ha->pha->outstanding_cmds[
				    sp->handle & OSC_INDEX_MASK] = NULL;
				sp->handle = 0;
				sp->flags &= ~SRB_IN_TOKEN_ARRAY;
			}
			INTR_UNLOCK(ha);

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
				    (CFG_IST(ha, CFG_ISP_FW_TYPE_2) &&
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
				case CS_DEV_NOT_READY:
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

				(void) qlc_fm_check_pkt_dma_handle(ha, sp);

				/* Now call the pkt completion callback */
				if (sp->flags & SRB_POLL) {
					sp->flags &= ~SRB_POLL;
				} else if (cmplt == B_TRUE &&
				    sp->pkt->pkt_comp) {
					(sp->pkt->pkt_comp)(sp->pkt);
				} else {
					ql_io_comp(sp);
				}
			}
		}
	}

	QL_PRINT_3(ha, "done\n");
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
    uint64_t set_flags, uint64_t reset_flags)
{
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started, sp=%p set_flags=%llx reset_flags=%llx\n",
	    sp, set_flags, reset_flags);

	/* Acquire task daemon lock. */
	TASK_DAEMON_LOCK(ha);

	if (set_flags) {
		ha->task_daemon_flags |= set_flags;
	}
	if (reset_flags) {
		ha->task_daemon_flags &= ~reset_flags;
	}

	if (!(ha->task_daemon_flags & TASK_DAEMON_ALIVE_FLG)) {
		EL(ha, "done, not alive dtf=%xh\n", ha->task_daemon_flags);
		TASK_DAEMON_UNLOCK(ha);
		return;
	}

	if (sp != NULL) {
		if (sp->flags & SRB_UB_CALLBACK) {
			ql_add_link_b(&ha->unsol_callback_queue, &sp->cmd);
		} else {
			EL(ha, "sp=%p, spf=%xh is not SRB_UB_CALLBACK",
			    sp->flags);
		}
	}

	if (!ha->driver_thread_awake) {
		QL_PRINT_3(ha, "driver_thread_awake\n");
		cv_broadcast(&ha->cv_task_daemon);
	}

	TASK_DAEMON_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	/* Acquire task daemon lock. */
	TASK_DAEMON_LOCK(ha);

	while ((ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) == 0) {
		ql_task_thread(ha);

		/*
		 * Before we wait on the conditional variable, we
		 * need to check if STOP_FLG is set for us to terminate
		 */
		if (ha->task_daemon_flags & TASK_DAEMON_STOP_FLG) {
			break;
		}

		QL_PRINT_3(ha, "Going to sleep\n");
		ha->task_daemon_flags |= TASK_DAEMON_SLEEPING_FLG;

		/* If killed, stop task daemon */
		if (cv_wait_sig(&ha->cv_task_daemon,
		    &ha->task_daemon_mutex) == 0) {
			QL_PRINT_10(ha, "killed\n");
			break;
		}

		QL_PRINT_3(ha, "Awakened\n");
		ha->task_daemon_flags &= ~TASK_DAEMON_SLEEPING_FLG;
	}

	ha->task_daemon_flags &= ~(TASK_DAEMON_SLEEPING_FLG |
	    TASK_DAEMON_ALIVE_FLG);

	TASK_DAEMON_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
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
	boolean_t		loop_again;
	ql_srb_t		*sp;
	ql_link_t		*link;
	caddr_t			msg;
	ql_adapter_state_t	*vha;

	ha->driver_thread_awake++;
	do {
		loop_again = B_FALSE;

		if (ha->sf != ha->flags ||
		    (ha->task_daemon_flags & ~DTF_EL_MSG_SKIP_FLGS) != ha->df ||
		    ha->cf != ha->cfg_flags) {
			ha->sf = ha->flags;
			ha->df = ha->task_daemon_flags & ~DTF_EL_MSG_SKIP_FLGS;
			ha->cf = ha->cfg_flags;
			EL(ha, "df=%xh, sf=%xh, cf=%xh\n",
			    ha->df, ha->sf, ha->cf);
		}

		QL_PM_LOCK(ha);
		if (ha->power_level != PM_LEVEL_D0) {
			QL_PM_UNLOCK(ha);
			ha->task_daemon_flags |= DRIVER_STALL |
			    TASK_DAEMON_STALLED_FLG;
			break;
		}
		QL_PM_UNLOCK(ha);

		if (ha->flags & ADAPTER_SUSPENDED) {
			ha->task_daemon_flags |= TASK_DAEMON_STALLED_FLG;
			break;
		}

		/* Handle FW IDC events. */
		while (ha->flags & (IDC_STALL_NEEDED | IDC_RESTART_NEEDED |
		    IDC_ACK_NEEDED)) {
			TASK_DAEMON_UNLOCK(ha);
			ql_idc(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		if (ha->task_daemon_flags &
		    (TASK_DAEMON_STOP_FLG | DRIVER_STALL) ||
		    !(ha->flags & ONLINE)) {
			ha->task_daemon_flags |= TASK_DAEMON_STALLED_FLG;
			break;
		}
		ha->task_daemon_flags &= ~TASK_DAEMON_STALLED_FLG;

		/* Store error log. */
		if (ha->errlog[0] != 0 &&
		    !(ha->task_daemon_flags & ISP_ABORT_NEEDED)) {
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_flash_errlog(ha, ha->errlog[0],
			    ha->errlog[1], ha->errlog[2], ha->errlog[3]);
			ha->errlog[0] = 0;
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		/* Idle Check. */
		if (ha->task_daemon_flags & TASK_DAEMON_IDLE_CHK_FLG) {
			ha->task_daemon_flags &= ~TASK_DAEMON_IDLE_CHK_FLG;
			if (!DRIVER_SUSPENDED(ha)) {
				TASK_DAEMON_UNLOCK(ha);
				ql_idle_check(ha);
				TASK_DAEMON_LOCK(ha);
				loop_again = B_TRUE;
			}
		}

		/* Crystal+ port#0 bypass transition */
		if (ha->task_daemon_flags & HANDLE_PORT_BYPASS_CHANGE) {
			ha->task_daemon_flags &= ~HANDLE_PORT_BYPASS_CHANGE;
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_initiate_lip(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		/* Abort queues needed. */
		if (ha->task_daemon_flags & ABORT_QUEUES_NEEDED) {
			ha->task_daemon_flags &= ~ABORT_QUEUES_NEEDED;
			if (ha->flags & ABORT_CMDS_LOOP_DOWN_TMO) {
				TASK_DAEMON_UNLOCK(ha);
				ql_abort_queues(ha);
				TASK_DAEMON_LOCK(ha);
				loop_again = B_TRUE;
			}
		}

		/* Not suspended, awaken waiting routines. */
		if (!DRIVER_SUSPENDED(ha) &&
		    ha->task_daemon_flags & SUSPENDED_WAKEUP_FLG) {
			ha->task_daemon_flags &= ~SUSPENDED_WAKEUP_FLG;
			cv_broadcast(&ha->cv_dr_suspended);
			loop_again = B_TRUE;
		}

		/* Handle RSCN changes. */
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			if (vha->task_daemon_flags & RSCN_UPDATE_NEEDED) {
				vha->task_daemon_flags &= ~RSCN_UPDATE_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
				(void) ql_handle_rscn_update(vha);
				TASK_DAEMON_LOCK(ha);
				loop_again = B_TRUE;
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
						loop_again = B_TRUE;
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
					QL_PRINT_10(vha, "statec_"
					    "cb state=%xh\n",
					    vha->state);
					TASK_DAEMON_UNLOCK(ha);
					(vha->bind_info.port_statec_cb)
					    (vha->bind_info.port_handle,
					    vha->state);
					TASK_DAEMON_LOCK(ha);
					loop_again = B_TRUE;
				}
			}
		}

		if (ha->task_daemon_flags & NEED_UNSOLICITED_BUFFERS &&
		    ha->task_daemon_flags & FIRMWARE_UP) {
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
			loop_again = B_TRUE;
		}

		if (ha->task_daemon_flags & WATCHDOG_NEEDED) {
			ha->task_daemon_flags &= ~WATCHDOG_NEEDED;
			TASK_DAEMON_UNLOCK(ha);
			ql_watchdog(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		if (ha->task_daemon_flags & ISP_ABORT_NEEDED) {
			TASK_DAEMON_UNLOCK(ha);
			(void) ql_abort_isp(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		if (!(ha->task_daemon_flags & (COMMAND_WAIT_NEEDED |
		    ABORT_QUEUES_NEEDED | ISP_ABORT_NEEDED | LOOP_DOWN)) &&
		    ha->task_daemon_flags & FIRMWARE_UP) {
			if (ha->task_daemon_flags & MARKER_NEEDED) {
				if (!(ha->task_daemon_flags & MARKER_ACTIVE)) {
					ha->task_daemon_flags |= MARKER_ACTIVE;
					ha->task_daemon_flags &= ~MARKER_NEEDED;
					TASK_DAEMON_UNLOCK(ha);
					for (vha = ha; vha != NULL;
					    vha = vha->vp_next) {
						(void) ql_marker(vha, 0, 0,
						    MK_SYNC_ALL);
					}
					TASK_DAEMON_LOCK(ha);
					ha->task_daemon_flags &= ~MARKER_ACTIVE;
					TASK_DAEMON_UNLOCK(ha);
					ql_restart_queues(ha);
					TASK_DAEMON_LOCK(ha);
					loop_again = B_TRUE;
				} else {
					ha->task_daemon_flags &= ~MARKER_NEEDED;
				}
			}

			if (ha->task_daemon_flags & LOOP_RESYNC_NEEDED) {
				if (!(ha->task_daemon_flags &
				    LOOP_RESYNC_ACTIVE)) {
					ha->task_daemon_flags |=
					    LOOP_RESYNC_ACTIVE;
					TASK_DAEMON_UNLOCK(ha);
					ql_loop_resync(ha);
					TASK_DAEMON_LOCK(ha);
					loop_again = B_TRUE;
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
			loop_again = B_TRUE;
		}

		if (ha->unsol_callback_queue.first != NULL) {
			sp = (ha->unsol_callback_queue.first)->base_address;
			link = &sp->cmd;
			ql_remove_link(&ha->unsol_callback_queue, link);
			TASK_DAEMON_UNLOCK(ha);
			ql_unsol_callback(sp);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		if (ha->task_daemon_flags & IDC_POLL_NEEDED) {
			ha->task_daemon_flags &= ~IDC_POLL_NEEDED;
			TASK_DAEMON_UNLOCK(ha);
			ql_8021_idc_poll(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

		if (ha->task_daemon_flags & LED_BLINK) {
			ha->task_daemon_flags &= ~LED_BLINK;
			TASK_DAEMON_UNLOCK(ha);
			ql_blink_led(ha);
			TASK_DAEMON_LOCK(ha);
			loop_again = B_TRUE;
		}

	} while (loop_again == B_TRUE);

	if (ha->driver_thread_awake) {
		ha->driver_thread_awake--;
	}
	QL_PRINT_3(ha, "done\n");
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
	int		rval;
	ql_mbx_data_t	mr;

	QL_PRINT_3(ha, "started\n");

	/* Firmware Ready Test. */
	rval = ql_get_firmware_state(ha, &mr);
	if (!DRIVER_SUSPENDED(ha) &&
	    (rval != QL_SUCCESS || mr.mb[1] != FSTATE_READY)) {
		EL(ha, "failed, Firmware Ready Test = %xh\n", rval);
		TASK_DAEMON_LOCK(ha);
		if (!(ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
			EL(ha, "fstate_ready, isp_abort_needed\n");
			ha->task_daemon_flags |= ISP_ABORT_NEEDED;
		}
		TASK_DAEMON_UNLOCK(ha);
	}

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		int sendup;

		/*
		 * Defer RSCN posting until commands return
		 */
		QL_UB_UNLOCK(ha);

		af = (fc_affected_id_t *)((caddr_t)ubp->ub_buffer + 4);

		/* Abort outstanding commands */
		sendup = ql_process_rscn(ha, af);
		if (sendup == 0) {

			TASK_DAEMON_LOCK(ha);
			ql_add_link_b(&pha->unsol_callback_queue, &sp->cmd);
			TASK_DAEMON_UNLOCK(ha);

			/*
			 * Wait for commands to drain in F/W (doesn't take
			 * more than a few milliseconds)
			 */
			ql_delay(ha, 10000);

			QL_PRINT_2(ha, "done rscn_sendup=0, "
			    "fmt=%xh, d_id=%xh\n",
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
			ql_add_link_b(&pha->unsol_callback_queue, &sp->cmd);
			TASK_DAEMON_UNLOCK(ha);
			QL_PRINT_2(ha, "logo_sendup=0, d_id=%xh"
			    "\n", tq->d_id.b24);
			return;
		}

		QL_UB_LOCK(ha);
		EL(ha, "sending unsol logout for %xh to transport\n",
		    ubp->ub_frame.s_id);
	}

	if ((r_ctl == R_CTL_ELS_REQ) && (ls_code == LA_ELS_PLOGI)) {
		EL(ha, "sending unsol plogi for %xh to transport\n",
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

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started, d_id=%xh\n", tq->d_id.b24);

	if ((tq->d_id.b24 == 0) || (tq->d_id.b24 == FS_BROADCAST)) {
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

	QL_PRINT_3(ha, "done\n");
}

static int
ql_process_logo_for_device(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	port_id_t	d_id;
	ql_srb_t	*sp;
	ql_link_t	*link;
	int		sendup = 1;

	QL_PRINT_3(ha, "started\n");

	DEVICE_QUEUE_LOCK(tq);
	if (tq->outcnt) {
		DEVICE_QUEUE_UNLOCK(tq);
		sendup = 0;
		(void) ql_abort_device(ha, tq, 1);
		ql_delay(ha, 10000);
	} else {
		DEVICE_QUEUE_UNLOCK(tq);
		TASK_DAEMON_LOCK(ha);

		for (link = ha->pha->unsol_callback_queue.first; link != NULL;
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

	QL_PRINT_3(ha, "done\n");

	return (sendup);
}

static int
ql_send_plogi(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_head_t *done_q)
{
	fc_unsol_buf_t		*ubp;
	ql_srb_t		*sp;
	la_els_logi_t		*payload;
	class_svc_param_t	*class3_param;

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "Received LOGO from = %xh\n", tq->d_id.b24);

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
	bzero(payload, sizeof (la_els_logi_t));

	payload->ls_code.ls_code = LA_ELS_PLOGI;
	payload->common_service.fcph_version = 0x2006;
	payload->common_service.cmn_features =
	    ha->topology & QL_N_PORT ? 0x8000 : 0x8800;
	payload->common_service.rx_bufsize =
	    ha->loginparams.common_service.rx_bufsize;
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

	if (done_q) {
		ql_add_link_b(done_q, &sp->cmd);
	} else {
		ql_awaken_task_daemon(ha, sp, 0, 0);
	}

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_10(ha, "started\n");

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
		ql_done(done_q.first, B_FALSE);
	}

	if (drain && VALID_TARGET_ID(ha, tq->loop_id) && PD_PORT_LOGIN(tq)) {
		rval = ql_abort_target(ha, tq, 0);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	if (af->aff_format == FC_RSCN_PORT_ADDRESS) {
		port_id_t d_id;

		d_id.r.rsvd_1 = 0;
		d_id.b24 = af->aff_d_id;

		tq = ql_d_id_to_queue(ha, d_id);
		if (tq) {
			EL(ha, "SD_RSCN_RCVD %xh RPA\n", d_id.b24);
			DEVICE_QUEUE_LOCK(tq);
			tq->flags |= TQF_RSCN_RCVD;
			ql_requeue_pending_cmds(ha, tq);
			DEVICE_QUEUE_UNLOCK(tq);
		}
		QL_PRINT_3(ha, "FC_RSCN_PORT_ADDRESS done\n");

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
					ql_requeue_pending_cmds(ha, tq);
					DEVICE_QUEUE_UNLOCK(tq);
				}
				break;

			case FC_RSCN_AREA_ADDRESS:
				if ((tq->d_id.b24 & 0xffff00) == af->aff_d_id) {
					EL(ha, "SD_RSCN_RCVD %xh RAA\n",
					    tq->d_id.b24);
					DEVICE_QUEUE_LOCK(tq);
					tq->flags |= TQF_RSCN_RCVD;
					ql_requeue_pending_cmds(ha, tq);
					DEVICE_QUEUE_UNLOCK(tq);
				}
				break;

			case FC_RSCN_DOMAIN_ADDRESS:
				if ((tq->d_id.b24 & 0xff0000) == af->aff_d_id) {
					EL(ha, "SD_RSCN_RCVD %xh RDA\n",
					    tq->d_id.b24);
					DEVICE_QUEUE_LOCK(tq);
					tq->flags |= TQF_RSCN_RCVD;
					ql_requeue_pending_cmds(ha, tq);
					DEVICE_QUEUE_UNLOCK(tq);
				}
				break;

			default:
				break;
			}
		}
	}
	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_requeue_pending_cmds
 *	Requeue target commands from pending queue to LUN queue
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	DEVICE_QUEUE_LOCK must be already obtained.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_requeue_pending_cmds(ql_adapter_state_t *vha, ql_tgt_t *tq)
{
	ql_link_t		*link;
	ql_srb_t		*sp;
	ql_lun_t		*lq;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	REQUEST_RING_LOCK(ha);
	for (link = ha->pending_cmds.first; link != NULL; link = link->next) {
		sp = link->base_address;
		if ((lq = sp->lun_queue) == NULL || lq->target_queue != tq) {
			continue;
		}
		ql_remove_link(&ha->pending_cmds, &sp->cmd);

		if (tq->outcnt) {
			tq->outcnt--;
		}
		if (sp->flags & SRB_FCP_CMD_PKT) {
			if (sp->fcp->fcp_cntl.cntl_qtype ==
			    FCP_QTYPE_UNTAGGED) {
				lq->flags &= ~LQF_UNTAGGED_PENDING;
			}
			if (lq->lun_outcnt != 0) {
				lq->lun_outcnt--;
			}
		}
		ql_add_link_t(&lq->cmd, &sp->cmd);
		sp->flags |= SRB_IN_DEVICE_QUEUE;
	}
	REQUEST_RING_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	if (af->aff_format == FC_RSCN_PORT_ADDRESS) {
		port_id_t d_id;

		d_id.r.rsvd_1 = 0;
		d_id.b24 = af->aff_d_id;

		tq = ql_d_id_to_queue(ha, d_id);
		if (tq) {
			sendup = ql_process_rscn_for_device(ha, tq);
		}

		QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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
			EL(ha, "busy tq->outcnt=%d\n", tq->outcnt);
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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
			if (ha->topology & QL_F_PORT ||
			    d_id.b.domain != ha->d_id.b.domain ||
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
		ql_done(done_q.first, B_FALSE);
	}

	kmem_free(list, list_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	sp = ubp->ub_fca_private;
	if (sp->ub_type == FC_TYPE_IS8802_SNAP) {
		/* Disconnect IP from system buffers. */
		if (ha->flags & IP_INITIALIZED) {
			status = ql_shutdown_ip(ha);
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

	QL_UB_LOCK(ha);
	if (ha->ub_allocated != 0) {
		ha->ub_allocated--;
	}
	QL_UB_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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
		loop_id = (uint16_t)(CFG_IST(ha, CFG_ISP_FW_TYPE_2) ?
		    BROADCAST_24XX_HDL : IP_BROADCAST_LOOP_ID);
		if (tq->ub_loop_id == loop_id) {
			if (ha->topology & QL_FL_PORT) {
				ubp->ub_frame.d_id = 0x000000;
			} else {
				ubp->ub_frame.d_id = FS_BROADCAST;
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

		QL_PRINT_3(ha, "ub_frame.d_id=%xh\n", ubp->ub_frame.d_id);
		QL_PRINT_3(ha, "ub_frame.s_id=%xh\n", ubp->ub_frame.s_id);
		QL_PRINT_3(ha, "ub_frame.seq_cnt=%xh\n", ubp->ub_frame.seq_cnt);
		QL_PRINT_3(ha, "ub_frame.seq_id=%xh\n", ubp->ub_frame.seq_id);
		QL_PRINT_3(ha, "ub_frame.ro=%xh\n", ubp->ub_frame.ro);
		QL_PRINT_3(ha, "ub_frame.f_ctl=%xh\n", ubp->ub_frame.f_ctl);
		QL_PRINT_3(ha, "ub_bufsize=%xh\n", ubp->ub_bufsize);
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

	QL_PRINT_3(ha, "done\n");

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
	uint64_t		set_flags;
	ql_adapter_state_t	*ha;
	static uint32_t		sec_cnt = 0;

	QL_PRINT_6(NULL, "started\n");

	/* Acquire global state lock. */
	GLOBAL_TIMER_LOCK();
	if (ql_timer_timeout_id == NULL) {
		/* Release global state lock. */
		GLOBAL_TIMER_UNLOCK();
		return;
	}

	sec_cnt++;
	for (link = ql_hba.first; link != NULL; link = link->next) {
		ha = link->base_address;

		/* Skip adapter if suspended or stalled. */
		if (ha->flags & ADAPTER_SUSPENDED ||
		    ha->task_daemon_flags & DRIVER_STALL ||
		    !(ha->task_daemon_flags & FIRMWARE_UP)) {
			continue;
		}

		QL_PM_LOCK(ha);
		if (ha->power_level != PM_LEVEL_D0) {
			QL_PM_UNLOCK(ha);
			continue;
		}
		ha->pm_busy++;
		QL_PM_UNLOCK(ha);

		set_flags = 0;

		/* All completion treads busy, wake up a helper thread. */
		if (ha->comp_thds_awake == ha->comp_thds_active &&
		    ha->comp_q.first != NULL) {
			QL_PRINT_10(ha, "comp queue helper thrd started\n");
			(void) timeout(ql_process_comp_queue, (void *)ha, 1);
		}

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
						ADAPTER_STATE_LOCK(ha);
						ha->flags |= FW_DUMP_NEEDED;
						ADAPTER_STATE_UNLOCK(ha);
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
						set_flags |= WATCHDOG_NEEDED;
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
			if (ha->send_plogi_timer != 0) {
				ha->send_plogi_timer--;
				if (ha->send_plogi_timer == 0) {
					set_flags |= SEND_PLOGI;
				}
			}
		}

		if (CFG_IST(ha, CFG_CTRL_82XX) && ha->flags & ONLINE &&
		    !(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE)) &&
		    !(sec_cnt % 2)) {
			set_flags |= IDC_POLL_NEEDED;
		}

		if (ha->ledstate.BeaconState == BEACON_ON) {
			set_flags |= LED_BLINK;
		}

		if (set_flags != 0) {
			ql_awaken_task_daemon(ha, NULL, set_flags, 0);
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

		QL_PM_LOCK(ha);
		if (ha->pm_busy) {
			ha->pm_busy--;
		}
		QL_PM_UNLOCK(ha);
	}

	/* Restart timer, if not being stopped. */
	if (ql_timer_timeout_id != NULL) {
		ql_timer_timeout_id = timeout(ql_timer, arg, ql_timer_ticks);
	}

	/* Release global state lock. */
	GLOBAL_TIMER_UNLOCK();

	QL_PRINT_6(ha, "done\n");
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
	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");
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
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_watchdog(ql_adapter_state_t *ha)
{
	ql_link_t		*link;
	ql_tgt_t		*tq;
	uint16_t		index;
	ql_adapter_state_t	*vha;

	QL_PRINT_6(ha, "started\n");

	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		/* Loop through all targets. */
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			for (link = vha->dev[index].first; link != NULL;
			    link = link->next) {
				tq = link->base_address;

				/* Try to acquire device queue lock. */
				if (TRY_DEVICE_QUEUE_LOCK(tq) == 0) {
					break;
				}

				if (!(CFG_IST(ha,
				    CFG_ENABLE_LINK_DOWN_REPORTING)) &&
				    (tq->port_down_retry_count == 0)) {
					/* Release device queue lock. */
					DEVICE_QUEUE_UNLOCK(tq);
					continue;
				}
				ql_wdg_tq_list(vha, tq);
			}
		}
	}
	ha->watchdog_timer = WATCHDOG_TIME;

	QL_PRINT_6(ha, "done\n");
}

/*
 * ql_wdg_tq_list
 *	Timeout handler that runs in interrupt context. The
 *	ql_adapter_state_t * argument is the parameter set up when the
 *	timeout was initialized (state structure pointer).
 *	Function used to update timeout values and if timeout
 *	has occurred command will be aborted.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	DEVICE_QUEUE_LOCK must be already obtained.
 *
 * Output:
 *	Releases DEVICE_QUEUE_LOCK upon exit.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_wdg_tq_list(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	ql_srb_t	*sp;
	ql_link_t	*link, *next_cmd;
	ql_lun_t	*lq;
	boolean_t	q_sane, timeout = B_FALSE;

	QL_PRINT_6(ha, "started\n");

	/* Find out if this device is in a sane state */
	if (tq->flags & (TQF_RSCN_RCVD | TQF_NEED_AUTHENTICATION |
	    TQF_QUEUE_SUSPENDED)) {
		q_sane = B_FALSE;
	} else {
		q_sane = B_TRUE;
	}
	/* Loop through commands on watchdog queue. */
	for (link = tq->wdg.first; link != NULL; link = next_cmd) {
		next_cmd = link->next;
		sp = link->base_address;
		lq = sp->lun_queue;

		/*
		 * For SCSI commands, if everything
		 * seems to * be going fine and this
		 * packet is stuck
		 * because of throttling at LUN or
		 * target level then do not decrement
		 * the sp->wdg_q_time
		 */
		if (ha->task_daemon_flags & STATE_ONLINE &&
		    !(sp->flags & SRB_ISP_STARTED) &&
		    q_sane == B_TRUE &&
		    sp->flags & SRB_FCP_CMD_PKT &&
		    lq->lun_outcnt >= ha->execution_throttle) {
			continue;
		}

		if (sp->wdg_q_time != 0) {
			sp->wdg_q_time--;

			/* Timeout? */
			if (sp->wdg_q_time != 0) {
				continue;
			}

			sp->flags |= SRB_COMMAND_TIMEOUT;
			timeout = B_TRUE;
		}
	}

	/*
	 * Loop through commands on watchdog queue and
	 * abort timed out commands.
	 */
	if (timeout == B_TRUE) {
		for (link = tq->wdg.first; link != NULL; link = next_cmd) {
			sp = link->base_address;
			next_cmd = link->next;

			if (sp->flags & SRB_COMMAND_TIMEOUT) {
				ql_remove_link(&tq->wdg, &sp->wdg);
				sp->flags &= ~(SRB_WATCHDOG_ENABLED |
				    SRB_COMMAND_TIMEOUT);
				ql_cmd_timeout(ha, tq, sp);
				next_cmd = tq->wdg.first;
			}
		}
	}

	/* Release device queue lock. */
	DEVICE_QUEUE_UNLOCK(tq);

	QL_PRINT_6(ha, "done\n");
}

/*
 * ql_cmd_timeout
 *	Command timeout handler.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	sp:		SRB pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_cmd_timeout(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_srb_t *sp)
{
	int	rval = 0;

	QL_PRINT_3(ha, "started\n");

	REQUEST_RING_LOCK(ha);
	if (!(sp->flags & SRB_ISP_STARTED)) {
		EL(ha, "command timed out in driver, sp=%ph spf=%xh\n",
		    (void *)sp, sp->flags);

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
		ql_done(&sp->cmd, B_FALSE);
	} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);

		EL(ha, "command timed out in isp=%ph, osc=%ph, index=%xh, "
		    "spf=%xh\n", (void *)sp,
		    (void *)ha->outstanding_cmds[sp->handle & OSC_INDEX_MASK],
		    sp->handle & OSC_INDEX_MASK, sp->flags);

		if (ha->pha->timeout_cnt++ > TIMEOUT_THRESHOLD ||
		    (rval = ql_abort_io(ha, sp)) != QL_SUCCESS) {
			sp->flags |= SRB_COMMAND_TIMEOUT;
			TASK_DAEMON_LOCK(ha);
			ha->task_daemon_flags |= ISP_ABORT_NEEDED;
			TASK_DAEMON_UNLOCK(ha);
			EL(ha, "abort status=%xh, tc=%xh, isp_abort_"
			    "needed\n", rval, ha->pha->timeout_cnt);
		}
	} else {
		REQUEST_RING_UNLOCK(ha);
		DEVICE_QUEUE_UNLOCK(tq);

		EL(ha, "command timed out in isp=%ph, osc=%ph, index=%xh, "
		    "spf=%xh, isp_abort_needed\n", (void *)sp,
		    (void *)ha->outstanding_cmds[sp->handle & OSC_INDEX_MASK],
		    sp->handle & OSC_INDEX_MASK, sp->flags);

		INTR_LOCK(ha);
		ha->pha->xioctl->ControllerErrorCount++;
		INTR_UNLOCK(ha);

		/* Set ISP needs to be reset */
		sp->flags |= SRB_COMMAND_TIMEOUT;

		if (CFG_IST(ha, CFG_DUMP_DRIVER_COMMAND_TIMEOUT)) {
			ADAPTER_STATE_LOCK(ha);
			ha->flags |= FW_DUMP_NEEDED;
			ADAPTER_STATE_UNLOCK(ha);
		}

		TASK_DAEMON_LOCK(ha);
		ha->task_daemon_flags |= ISP_ABORT_NEEDED;
		TASK_DAEMON_UNLOCK(ha);
	}
	DEVICE_QUEUE_LOCK(tq);

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
				    PRLI_W3_RETRY) ||
				    ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
					(void) ql_abort_device(vha, tq, 0);
				}
			}
		}
	}

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	count = ql_osc_wait_count;
	for (index = 1; index < ha->pha->osc_max_cnt; index++) {
		if (ha->pha->pending_cmds.first != NULL) {
			ql_start_iocb(ha, NULL);
			index = 1;
		}
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    sp != QL_ABORTED_SRB(ha) &&
		    (sp->flags & SRB_COMMAND_TIMEOUT) == 0) {
			if (count-- != 0) {
				ql_delay(ha, 10000);
				index = 0;
			} else {
				EL(ha, "still in OSC,sp=%ph,oci=%d,sph=%xh,"
				    "spf=%xh\n", (void *) sp, index, sp->handle,
				    sp->flags);
				break;
			}
		}
	}

	QL_PRINT_3(ha, "done\n");

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
void
ql_restart_queues(ql_adapter_state_t *ha)
{
	ql_link_t		*link, *link2;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	uint16_t		index;
	ql_adapter_state_t	*vha;

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	if (!CFG_IST(ha, CFG_IIDMA_SUPPORT)) {
		QL_PRINT_3(ha, "done\n");
		return;
	}

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;

			if ((tq->flags & TQF_IIDMA_NEEDED) == 0) {
				continue;
			}

			/* Acquire device queue lock. */
			DEVICE_QUEUE_LOCK(tq);

			tq->flags &= ~TQF_IIDMA_NEEDED;

			/* Release device queue lock. */
			DEVICE_QUEUE_UNLOCK(tq);

			if ((tq->loop_id > LAST_N_PORT_HDL) ||
			    (tq->d_id.b24 == FS_MANAGEMENT_SERVER) ||
			    (tq->flags & TQF_INITIATOR_DEVICE) ||
			    (tq->iidma_rate == IIDMA_RATE_NDEF)) {
				continue;
			}

			/* Get the iiDMA persistent data */
			(void) snprintf(buf, sizeof (buf),
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
				case IIDMA_RATE_4GB:
				case IIDMA_RATE_8GB:
				case IIDMA_RATE_10GB:
				case IIDMA_RATE_16GB:
				case IIDMA_RATE_32GB:
					tq->iidma_rate = data;
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

			EL(ha, "d_id = %xh iidma_rate = %xh\n",
			    tq->d_id.b24, tq->iidma_rate);

			/* Set the firmware's iiDMA rate */
			if (!CFG_IST(ha, CFG_FCOE_SUPPORT)) {
				if (tq->iidma_rate <= IIDMA_RATE_MAX) {
					data = ql_iidma_rate(ha, tq->loop_id,
					    &tq->iidma_rate,
					    EXT_IIDMA_MODE_SET);
					if (data != QL_SUCCESS) {
						EL(ha, "mbx failed: %xh\n",
						    data);
					}
				}
			}
		}
	}

	QL_PRINT_3(ha, "done\n");
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
void
ql_abort_queues(ql_adapter_state_t *ha)
{
	ql_link_t		*link;
	ql_tgt_t		*tq;
	ql_srb_t		*sp;
	uint16_t		index;
	ql_adapter_state_t	*vha;

	QL_PRINT_10(ha, "started\n");

	/* Return all commands in outstanding command list. */
	INTR_LOCK(ha);

	/* Place all commands in outstanding cmd list on device queue. */
	for (index = 1; index < ha->osc_max_cnt; index++) {
		if (ha->pending_cmds.first != NULL) {
			INTR_UNLOCK(ha);
			ql_start_iocb(ha, NULL);
			/* Delay for system */
			ql_delay(ha, 10000);
			INTR_LOCK(ha);
			index = 1;
		}
		sp = ha->outstanding_cmds[index];

		if (sp && (sp == QL_ABORTED_SRB(ha) || sp->ha != ha)) {
			continue;
		}

		/* skip devices capable of FCP2 retrys */
		if (sp != NULL &&
		    (sp->lun_queue == NULL ||
		    (tq = sp->lun_queue->target_queue) == NULL ||
		    !(tq->prli_svc_param_word_3 & PRLI_W3_RETRY) ||
		    ha->task_daemon_flags & ABORT_ISP_ACTIVE)) {
			ha->outstanding_cmds[index] = NULL;
			sp->handle = 0;
			sp->flags &= ~SRB_IN_TOKEN_ARRAY;

			INTR_UNLOCK(ha);

			/* Set ending status. */
			sp->pkt->pkt_reason = CS_PORT_UNAVAILABLE;
			sp->flags |= SRB_ISP_COMPLETED;

			/* Call done routine to handle completions. */
			sp->cmd.next = NULL;
			ql_done(&sp->cmd, B_FALSE);

			INTR_LOCK(ha);
		}
	}
	INTR_UNLOCK(ha);

	for (vha = ha; vha != NULL; vha = vha->vp_next) {
		QL_PRINT_10(vha, "abort instance\n");
		for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
			for (link = vha->dev[index].first; link != NULL;
			    link = link->next) {
				tq = link->base_address;
				/* skip devices capable of FCP2 retrys */
				if (!(tq->prli_svc_param_word_3 &
				    PRLI_W3_RETRY) ||
				    ha->task_daemon_flags & ABORT_ISP_ACTIVE) {
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
	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_10(ha, "started\n");

	DEVICE_QUEUE_LOCK(tq);
	ql_requeue_pending_cmds(ha, tq);

	for (lun_link = tq->lun_queues.first; lun_link != NULL;
	    lun_link = lun_link->next) {
		lq = lun_link->base_address;

		cmd_link = lq->cmd.first;
		while (cmd_link != NULL) {
			sp = cmd_link->base_address;

			/* Remove srb from device cmd queue. */
			ql_remove_link(&lq->cmd, &sp->cmd);

			sp->flags &= ~SRB_IN_DEVICE_QUEUE;

			DEVICE_QUEUE_UNLOCK(tq);

			/* Set ending status. */
			sp->pkt->pkt_reason = CS_PORT_UNAVAILABLE;

			/* Call done routine to handle completion. */
			ql_done(&sp->cmd, B_FALSE);

			/* Delay for system */
			ql_delay(ha, 10000);

			DEVICE_QUEUE_LOCK(tq);
			cmd_link = lq->cmd.first;
		}
	}
	DEVICE_QUEUE_UNLOCK(tq);

	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_loop_resync
 *	Resync with fibre channel devices.
 *
 * Input:
 *	ha = adapter state pointer.
 *	DEVICE_QUEUE_LOCK must be released.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_loop_resync(ql_adapter_state_t *ha)
{
	int rval;

	QL_PRINT_3(ha, "started\n");

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
		QL_PRINT_3(ha, "done\n");
	} else {
		EL(ha, "failed, rval = %xh\n", rval);
	}
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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");
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
		QL_PRINT_2(ha, "failed\n");
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
	int	rval;

	QL_PRINT_3(ksp->ks_private, "started\n");

	if (rw == KSTAT_WRITE) {
		rval = EACCES;
	} else {
		rval = 0;
	}

	if (rval != 0) {
		/*EMPTY*/
		QL_PRINT_2(ksp->ks_private, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ksp->ks_private, "done\n");
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

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		return (ql_24xx_load_flash(ha, dp, size, 0));
	}

	QL_PRINT_3(ha, "started\n");

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

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		for (cnt = sStartAddr; cnt < ssize + sStartAddr; cnt++) {
			/* Allow other system activity. */
			if (cnt % 0x1000 == 0) {
				ql_delay(ha, 10000);
			}
			*tmp++ = (uint8_t)ql_read_flash_byte(ha, cnt);
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

		if (rval == QL_SUCCESS) {
			/* Restore the section we saved off */
			tmp = bfp;
			for (cnt = sStartAddr; cnt < ssize + sStartAddr;
			    cnt++) {
				/* Allow other system activity. */
				if (cnt % 0x1000 == 0) {
					ql_delay(ha, 10000);
				}
				rval = ql_program_flash_address(ha, cnt,
				    *tmp++);
				if (rval != QL_SUCCESS) {
					break;
				}
			}
		}
		kmem_free(bfp, ssize);
	} else {
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
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");
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

		if (ha->device_id == 0x2322 || ha->device_id == 0x6322) {
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
		if (ha->device_id == 0x2322 || ha->device_id == 0x6322) {
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

	QL_PRINT_3(ha, "started\n");

	rval = ql_24xx_read_flash(ha, FLASH_CONF_ADDR | 0x3AB, &fdata);
	if (CFG_IST(ha, CFG_CTRL_24XX)) {
		if (rval != QL_SUCCESS || fdata == 0) {
			fdata = 0;
			rval = ql_24xx_read_flash(ha, FLASH_CONF_ADDR | 0x39F,
			    &fdata);
		}
	} else {
		fdata = 0;
		rval = ql_24xx_read_flash(ha, FLASH_CONF_ADDR |
		    (CFG_IST(ha, CFG_CTRL_25XX) ? 0x49F : 0x39F), &fdata);
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started, faddr=%xh, size=%xh\n",
	    ha->instance, faddr, size);

	/* start address must be 32 bit word aligned */
	if ((faddr & 0x3) != 0) {
		EL(ha, "incorrect buffer size alignment\n");
		return (QL_FUNCTION_PARAMETER_ERROR);
	}

	/* Allocate DMA buffer */
	if (CFG_IST(ha, CFG_FLASH_DMA_SUPPORT)) {
		if ((rval = ql_get_dma_mem(ha, &dmabuf, 0xffff,
		    LITTLE_ENDIAN_DMA, QL_DMA_DATA_ALIGN)) !=
		    QL_SUCCESS) {
			EL(ha, "dma alloc failed, rval=%xh\n", rval);
			return (rval);
		}
	}

	/* Enable flash write */
	if ((rval = ql_24xx_unprotect_flash(ha)) != QL_SUCCESS) {
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
			if (CFG_IST(ha, CFG_CTRL_82XX)) {
				fdata = ha->flash_data_addr | faddr;
				rval = ql_8021_rom_erase(ha, fdata);
				if (rval != QL_SUCCESS) {
					EL(ha, "8021 erase sector status="
					    "%xh, start=%xh, end=%xh"
					    "\n", rval, fdata,
					    fdata + rest_addr);
					break;
				}
			} else if (CFG_IST(ha, CFG_FLASH_ACC_SUPPORT)) {
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
		if (CFG_IST(ha, CFG_FLASH_DMA_SUPPORT) &&
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

	if (CFG_IST(ha, CFG_FLASH_DMA_SUPPORT)) {
		ql_free_phys(ha, &dmabuf);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
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

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
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

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
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
				    FLASH_CONF_ADDR | 0x105, &fdata);
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
	uint32_t		fdata, timer;
	ql_adapter_state_t	*ha = vha->pha;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		(void) ql_8021_rom_wrsr(ha, xp->fdesc.write_enable_bits);
		rval = ql_8021_rom_wrsr(ha, xp->fdesc.write_enable_bits);
		if (rval != QL_SUCCESS) {
			EL(ha, "8021 access error\n");
		}
		return (rval);
	}
	if (CFG_IST(ha, CFG_FLASH_ACC_SUPPORT)) {
		if (ha->task_daemon_flags & FIRMWARE_UP) {
			for (timer = 3000; timer; timer--) {
				if (ha->task_daemon_flags & ISP_ABORT_NEEDED) {
					EL(ha, "ISP_ABORT_NEEDED done\n");
					return (QL_ABORTED);
				}
				rval = ql_flash_access(ha, FAC_SEMA_LOCK,
				    0, 0, NULL);
				if (rval == QL_SUCCESS ||
				    rval == QL_FUNCTION_TIMEOUT) {
					EL(ha, "lock status=%xh\n", rval);
					break;
				}
				delay(1);
			}

			if (rval == QL_SUCCESS &&
			    (rval = ql_flash_access(ha, FAC_WRT_ENABLE, 0,
			    0, NULL)) != QL_SUCCESS) {
				EL(ha, "WRT_ENABLE status=%xh\n", rval);
				(void) ql_flash_access(ha, FAC_SEMA_UNLOCK,
				    0, 0, NULL);
			}
		} else {
			rval = QL_SUCCESS;
		}
		QL_PRINT_3(ha, "CFG_FLASH_ACC_SUPPORT done\n");
		return (rval);
	} else {
		/* Enable flash write. */
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) | ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	/* Sector/Block Protection Register Lock (SST, ST, ATMEL). */
	(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x100 |
	    xp->fdesc.write_statusreg_cmd, xp->fdesc.write_enable_bits);

	/*
	 * Remove block write protection (SST and ST)
	 * Global unprotect sectors (ATMEL).
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

	QL_PRINT_3(ha, "done\n");

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
	uint32_t		fdata, timer;
	ql_adapter_state_t	*ha = vha->pha;
	ql_xioctl_t		*xp = ha->xioctl;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		(void) ql_8021_rom_wrsr(ha, xp->fdesc.write_enable_bits);
		rval = ql_8021_rom_wrsr(ha, xp->fdesc.write_disable_bits);
		if (rval != QL_SUCCESS) {
			EL(ha, "8021 access error\n");
		}
		return;
	}
	if (CFG_IST(ha, CFG_FLASH_ACC_SUPPORT)) {
		if (ha->task_daemon_flags & FIRMWARE_UP) {
			for (timer = 3000; timer; timer--) {
				if (ha->task_daemon_flags & ISP_ABORT_NEEDED) {
					EL(ha, "ISP_ABORT_NEEDED done\n");
					return;
				}
				rval = ql_flash_access(ha, FAC_SEMA_LOCK,
				    0, 0, NULL);
				if (rval == QL_SUCCESS ||
				    rval == QL_FUNCTION_TIMEOUT) {
					if (rval != QL_SUCCESS) {
						EL(ha, "lock status=%xh\n",
						    rval);
					}
					break;
				}
				delay(1);
			}

			if (rval == QL_SUCCESS &&
			    (rval = ql_flash_access(ha, FAC_WRT_PROTECT, 0,
			    0, NULL)) != QL_SUCCESS) {
				EL(ha, "protect status=%xh\n", rval);
				(void) ql_flash_access(ha, FAC_SEMA_UNLOCK, 0,
				    0, NULL);
			}
			QL_PRINT_3(ha, "CFG_FLASH_ACC_SUPPORT done\n");
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
			    0x300 | xp->fdesc.protect_sector_cmd, fdata);
		}
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x300 |
		    xp->fdesc.protect_sector_cmd, 0x00400f);
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x300 |
		    xp->fdesc.protect_sector_cmd, 0x00600f);
		(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x300 |
		    xp->fdesc.protect_sector_cmd, 0x00800f);
	}

	/* Remove Sector Protection Registers Locked (SPRL) bit. */
	(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x100 |
	    xp->fdesc.write_statusreg_cmd, xp->fdesc.write_enable_bits);

	(void) ql_24xx_write_flash(ha, FLASH_CONF_ADDR | 0x100 |
	    xp->fdesc.write_statusreg_cmd, xp->fdesc.write_disable_bits);

	/* Disable flash write. */
	if (!CFG_IST(ha, CFG_FLASH_ACC_SUPPORT)) {
		WRT32_IO_REG(ha, ctrl_status,
		    RD32_IO_REG(ha, ctrl_status) & ~ISP_FLASH_ENABLE);
		RD32_IO_REG(ha, ctrl_status);	/* PCI Posting. */
	}

	QL_PRINT_3(ha, "done\n");
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
int
ql_dump_firmware(ql_adapter_state_t *vha)
{
	int			rval;
	clock_t			timer = drv_usectohz(30000000);
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	QL_DUMP_LOCK(ha);

	if (ha->ql_dump_state & QL_DUMPING ||
	    (ha->ql_dump_state & QL_DUMP_VALID &&
	    !(ha->ql_dump_state & QL_DUMP_UPLOADED))) {
		QL_PRINT_3(ha, "done\n");
		QL_DUMP_UNLOCK(ha);
		return (QL_SUCCESS);
	}

	QL_DUMP_UNLOCK(ha);

	(void) ql_stall_driver(ha, 0);

	/* Dump firmware. */
	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		rval = ql_binary_fw_dump(ha, FALSE);
	} else {
		rval = ql_binary_fw_dump(ha, TRUE);
	}

	/* Do abort to force restart. */
	ql_restart_driver(ha);
	ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED, 0);
	EL(ha, "restarting, isp_abort_needed\n");

	/* Acquire task daemon lock. */
	TASK_DAEMON_LOCK(ha);

	/* Wait for suspension to end. */
	while (DRIVER_SUSPENDED(ha)) {
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
		QL_PRINT_3(ha, "done\n");
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
	uint32_t		cnt, index;
	clock_t			timer;
	int			rval = QL_SUCCESS;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~FW_DUMP_NEEDED;
	ADAPTER_STATE_UNLOCK(ha);

	if (CFG_IST(ha, CFG_CTRL_82XX) && ha->md_capture_size == 0) {
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
		    FTO_INSERT_TIME_STAMP, NULL);
		if (rval != QL_SUCCESS) {
			EL(ha, "f/w extended trace insert"
			    "time stamp failed: %xh\n", rval);
		}
	}

	if (lock_needed == TRUE) {
		/* Acquire mailbox register lock. */
		MBX_REGISTER_LOCK(ha);
		timer = ((MAILBOX_TOV + 6) * drv_usectohz(1000000));

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

		/* Release mailbox register lock. */
		MBX_REGISTER_UNLOCK(ha);
	}

	/* Free previous dump buffer. */
	if (ha->ql_dump_ptr != NULL) {
		kmem_free(ha->ql_dump_ptr, ha->ql_dump_size);
		ha->ql_dump_ptr = NULL;
	}

	if (CFG_IST(ha, CFG_CTRL_24XX)) {
		ha->ql_dump_size = (uint32_t)(sizeof (ql_24xx_fw_dump_t) +
		    ha->fw_ext_memory_size);
	} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
		cnt = ha->rsp_queues_cnt > 1 ? ha->req_q[0]->req_ring.size +
		    ha->req_q[1]->req_ring.size : ha->req_q[0]->req_ring.size;
		index = ha->rsp_queues[0]->rsp_ring.size * ha->rsp_queues_cnt;

		ha->ql_dump_size = (uint32_t)(sizeof (ql_25xx_fw_dump_t) +
		    cnt + index + ha->fw_ext_memory_size +
		    (ha->rsp_queues_cnt * 16));

	} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
		cnt = ha->rsp_queues_cnt > 1 ? ha->req_q[0]->req_ring.size +
		    ha->req_q[1]->req_ring.size : ha->req_q[0]->req_ring.size;
		index = ha->rsp_queues[0]->rsp_ring.size * ha->rsp_queues_cnt;

		ha->ql_dump_size = (uint32_t)(sizeof (ql_81xx_fw_dump_t) +
		    cnt + index + ha->fw_ext_memory_size +
		    (ha->rsp_queues_cnt * 16));

	} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
		cnt = ha->rsp_queues_cnt > 1 ? ha->req_q[0]->req_ring.size +
		    ha->req_q[1]->req_ring.size : ha->req_q[0]->req_ring.size;
		index = ha->rsp_queues[0]->rsp_ring.size * ha->rsp_queues_cnt;

		ha->ql_dump_size = (uint32_t)(sizeof (ql_83xx_fw_dump_t) +
		    cnt + index + ha->fw_ext_memory_size +
		    (ha->rsp_queues_cnt * 16));
	} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
		ha->ql_dump_size = ha->md_capture_size;
	} else {
		ha->ql_dump_size = sizeof (ql_fw_dump_t);
	}

	if (CFG_IST(ha, CFG_CTRL_27XX)) {
		rval = ql_27xx_binary_fw_dump(ha);
	} else {
		if ((ha->ql_dump_ptr =
		    kmem_zalloc(ha->ql_dump_size, KM_NOSLEEP)) == NULL) {
			rval = QL_MEMORY_ALLOC_FAILED;
		} else {
			if (CFG_IST(ha, CFG_CTRL_2363)) {
				rval = ql_2300_binary_fw_dump(ha,
				    ha->ql_dump_ptr);
			} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
				rval = ql_81xx_binary_fw_dump(ha,
				    ha->ql_dump_ptr);
			} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
				rval = ql_83xx_binary_fw_dump(ha,
				    ha->ql_dump_ptr);
			} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
				rval = ql_25xx_binary_fw_dump(ha,
				    ha->ql_dump_ptr);
			} else if (CFG_IST(ha, CFG_CTRL_24XX)) {
				rval = ql_24xx_binary_fw_dump(ha,
				    ha->ql_dump_ptr);
			} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
				(void) ql_8021_reset_fw(ha);
				rval = QL_SUCCESS;
			} else {
				rval = ql_2200_binary_fw_dump(ha,
				    ha->ql_dump_ptr);
			}
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

	if (CFG_IST(ha, CFG_CTRL_24XX)) {
		return (ql_24xx_ascii_fw_dump(ha, bufp));
	} else if (CFG_IST(ha, CFG_CTRL_25XX)) {
		return (ql_25xx_ascii_fw_dump(ha, bufp));
	} else if (CFG_IST(ha, CFG_CTRL_81XX)) {
		return (ql_81xx_ascii_fw_dump(ha, bufp));
	} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
		return (ql_8021_ascii_fw_dump(ha, bufp));
	} else if (CFG_IST(ha, CFG_CTRL_83XX)) {
		return (ql_83xx_ascii_fw_dump(ha, bufp));
	} else if (CFG_IST(ha, CFG_CTRL_27XX)) {
		return (ql_27xx_ascii_fw_dump(ha, bufp));
	}

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_23XX)) {
		(void) sprintf(bufp, "\nISP 2300IP ");
	} else if (CFG_IST(ha, CFG_CTRL_63XX)) {
		(void) sprintf(bufp, "\nISP 2322/6322FLX ");
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

	if (CFG_IST(ha, CFG_CTRL_2363)) {
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
	mbox_cnt = CFG_IST(ha, CFG_CTRL_2363) ? 16 : 8;
	for (cnt = 0; cnt < mbox_cnt; cnt++) {
		if (cnt % 8 == 0) {
			*bp++ = '\n';
		}
		(void) sprintf(bp, "%04x  ", fw->mailbox_reg[cnt]);
		bp = bp + 6;
	}

	if (CFG_IST(ha, CFG_CTRL_2363)) {
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
		if (cnt == 16 && !CFG_IST(ha, CFG_CTRL_2363)) {
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

	if (CFG_IST(ha, CFG_CTRL_2363)) {
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

	QL_PRINT_10(ha, "done, size=0x%x\n", strlen(bufp));

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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_10(ha, "done=%xh\n", cnt);

	return (cnt);
}

/*
 * ql_25xx_ascii_fw_dump
 *	Converts ISP25xx firmware binary dump to ascii.
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
ql_25xx_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t		cnt, cnt1, *dp, *dp2;
	caddr_t			bp = bufp;
	ql_25xx_fw_dump_t	*fw = ha->ql_dump_ptr;

	QL_PRINT_3(ha, "started\n");

	(void) sprintf(bp, "\nISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);
	bp += strlen(bp);

	(void) sprintf(bp, "\nHCCR Register\n%08x\n", fw->hccr);
	bp += strlen(bp);

	(void) sprintf(bp, "\nR2H Status Register\n%08x\n", fw->r2h_status);
	bp += strlen(bp);

	(void) sprintf(bp, "\nAER Uncorrectable Error Status Register\n%08x\n",
	    fw->aer_ues);
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
	cnt1 = sizeof (fw->fpm_hdw_reg);
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->fpm_hdw_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nFB Hardware Registers");
	bp += strlen(bp);
	cnt1 = sizeof (fw->fb_hdw_reg);
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
	dp = (uint32_t *)((caddr_t)fw->req_rsp_ext_mem + fw->req_q_size[0] +
	    fw->req_q_size[1] + fw->rsp_q_size + (ha->rsp_queues_cnt * 16));
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt + 0x100000);
			bp += 11;
		}
		(void) sprintf(bp, "%08x ", *dp++);
		bp += 9;
	}

	(void) sprintf(bp, "\n[<==END] ISP Debug Dump");
	bp += strlen(bp);

	dp = fw->req_rsp_ext_mem + (ha->rsp_queues_cnt * 4);
	for (cnt = 0; cnt < 2 && fw->req_q_size[cnt]; cnt++) {
		dp2 = dp;
		for (cnt1 = 0; cnt1 < fw->req_q_size[cnt] / 4; cnt1++) {
			if (*dp2++) {
				break;
			}
		}
		if (cnt1 == fw->req_q_size[cnt] / 4) {
			dp = dp2;
			continue;
		}
		(void) sprintf(bp, "\n\nRequest Queue\nQueue %d:", cnt);
		bp += strlen(bp);
		for (cnt1 = 0; cnt1 < fw->req_q_size[cnt] / 4; cnt1++) {
			if (cnt1 % 8 == 0) {
				(void) sprintf(bp, "\n%08x: ", cnt1);
				bp += strlen(bp);
			}
			(void) sprintf(bp, "%08x ", *dp++);
			bp += strlen(bp);
		}
	}

	for (cnt = 0; cnt < ha->rsp_queues_cnt && cnt < 16; cnt++) {
		dp2 = dp;
		for (cnt1 = 0; cnt1 < ha->rsp_queues[cnt]->rsp_ring.size / 4;
		    cnt1++) {
			if (*dp2++) {
				break;
			}
		}
		if (cnt1 == ha->rsp_queues[cnt]->rsp_ring.size / 4) {
			dp = dp2;
			continue;
		}
		(void) sprintf(bp, "\n\nResponse Queue\nQueue %d:", cnt);
		bp += strlen(bp);
		for (cnt1 = 0; cnt1 < ha->rsp_queues[cnt]->rsp_ring.size / 4;
		    cnt1++) {
			if (cnt1 % 8 == 0) {
				(void) sprintf(bp, "\n%08x: ", cnt1);
				bp += strlen(bp);
			}
			(void) sprintf(bp, "%08x ", *dp++);
			bp += strlen(bp);
		}
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

	QL_PRINT_10(ha, "done=%xh\n", cnt);

	return (cnt);
}

/*
 * ql_81xx_ascii_fw_dump
 *	Converts ISP81xx firmware binary dump to ascii.
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
ql_81xx_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t		cnt, cnt1, *dp, *dp2;
	caddr_t			bp = bufp;
	ql_81xx_fw_dump_t	*fw = ha->ql_dump_ptr;

	QL_PRINT_3(ha, "started\n");

	(void) sprintf(bp, "\nISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);
	bp += strlen(bp);

	(void) sprintf(bp, "\nHCCR Register\n%08x\n", fw->hccr);
	bp += strlen(bp);

	(void) sprintf(bp, "\nR2H Status Register\n%08x\n", fw->r2h_status);
	bp += strlen(bp);

	(void) sprintf(bp, "\nAER Uncorrectable Error Status Register\n%08x\n",
	    fw->aer_ues);
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
	cnt1 = sizeof (fw->fpm_hdw_reg);
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp++, "\n");
		}
		(void) sprintf(bp, "%08x ", fw->fpm_hdw_reg[cnt]);
		bp += 9;
	}

	(void) sprintf(bp, "\n\nFB Hardware Registers");
	bp += strlen(bp);
	cnt1 = sizeof (fw->fb_hdw_reg);
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
	dp = (uint32_t *)((caddr_t)fw->req_rsp_ext_mem + fw->req_q_size[0] +
	    fw->req_q_size[1] + fw->rsp_q_size + (ha->rsp_queues_cnt * 16));
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) sprintf(bp, "\n%08x: ", cnt + 0x100000);
			bp += 11;
		}
		(void) sprintf(bp, "%08x ", *dp++);
		bp += 9;
	}

	(void) sprintf(bp, "\n[<==END] ISP Debug Dump");
	bp += strlen(bp);

	dp = fw->req_rsp_ext_mem + (ha->rsp_queues_cnt * 4);
	for (cnt = 0; cnt < 2 && fw->req_q_size[cnt]; cnt++) {
		dp2 = dp;
		for (cnt1 = 0; cnt1 < fw->req_q_size[cnt] / 4; cnt1++) {
			if (*dp2++) {
				break;
			}
		}
		if (cnt1 == fw->req_q_size[cnt] / 4) {
			dp = dp2;
			continue;
		}
		(void) sprintf(bp, "\n\nRequest Queue\nQueue %d:", cnt);
		bp += strlen(bp);
		for (cnt1 = 0; cnt1 < fw->req_q_size[cnt] / 4; cnt1++) {
			if (cnt1 % 8 == 0) {
				(void) sprintf(bp, "\n%08x: ", cnt1);
				bp += strlen(bp);
			}
			(void) sprintf(bp, "%08x ", *dp++);
			bp += strlen(bp);
		}
	}

	for (cnt = 0; cnt < ha->rsp_queues_cnt && cnt < 16; cnt++) {
		dp2 = dp;
		for (cnt1 = 0; cnt1 < ha->rsp_queues[cnt]->rsp_ring.size / 4;
		    cnt1++) {
			if (*dp2++) {
				break;
			}
		}
		if (cnt1 == ha->rsp_queues[cnt]->rsp_ring.size / 4) {
			dp = dp2;
			continue;
		}
		(void) sprintf(bp, "\n\nResponse Queue\nQueue %d:", cnt);
		bp += strlen(bp);
		for (cnt1 = 0; cnt1 < ha->rsp_queues[cnt]->rsp_ring.size / 4;
		    cnt1++) {
			if (cnt1 % 8 == 0) {
				(void) sprintf(bp, "\n%08x: ", cnt1);
				bp += strlen(bp);
			}
			(void) sprintf(bp, "%08x ", *dp++);
			bp += strlen(bp);
		}
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

	QL_PRINT_10(ha, "done=%xh\n", cnt);

	return (cnt);
}

/*
 * ql_8021_ascii_fw_dump
 *	Converts ISP8021 firmware binary dump to ascii.
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
ql_8021_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t	cnt;
	caddr_t		bp = bufp;
	uint8_t		*fw = ha->ql_dump_ptr;

	/*
	 * 2 ascii bytes per binary byte + a space and
	 * a newline every 16 binary bytes
	 */
	cnt = 0;
	while (cnt < ha->ql_dump_size) {
		(void) sprintf(bp, "%02x ", *fw++);
		bp += strlen(bp);
		if (++cnt % 16 == 0) {
			(void) sprintf(bp, "\n");
			bp += strlen(bp);
		}
	}
	if (cnt % 16 != 0) {
		(void) sprintf(bp, "\n");
		bp += strlen(bp);
	}
	cnt = (uint32_t)((uintptr_t)bp - (uintptr_t)bufp);
	QL_PRINT_10(ha, "done=%xh\n", cnt);
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

	QL_PRINT_3(ha, "started\n");

	/* Disable ISP interrupts. */
	ql_disable_intr(ha);

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
		while (RD16_IO_REG(ha, mailbox_out[0]) == MBS_ROM_BUSY) {
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

	/* Disable ISP interrupts. */
	ql_disable_intr(ha);

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
		while (RD16_IO_REG(ha, mailbox_out[0]) == MBS_ROM_BUSY) {
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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

	fw->hccr = RD32_IO_REG(ha, hccr);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		/* Disable ISP interrupts. */
		ql_disable_intr(ha);

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
		ql_disable_intr(ha);

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
		uint32_t	*w32 = (uint32_t *)ha->req_q[0]->req_ring.bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->req_q[0]->req_ring.dma_handle,
		    0, sizeof (fw->req_q), DDI_DMA_SYNC_FORKERNEL);

		for (cnt = 0; cnt < sizeof (fw->req_q) / 4; cnt++) {
			fw->req_q[cnt] = *w32++;
			LITTLE_ENDIAN_32(&fw->req_q[cnt]);
		}
	}

	/* Get the response queue */
	if (rval == QL_SUCCESS) {
		uint32_t	cnt;
		uint32_t	*w32 =
		    (uint32_t *)ha->rsp_queues[0]->rsp_ring.bp;

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->rsp_queues[0]->rsp_ring.dma_handle,
		    0, sizeof (fw->rsp_q), DDI_DMA_SYNC_FORKERNEL);

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
		QL_PRINT_3(ha, "done\n");
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
	uint32_t	*reg32,	cnt, *w32ptr, index, *dp;
	void		*bp;
	clock_t		timer;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	fw->req_q_size[0] = ha->req_q[0]->req_ring.size;
	if (ha->req_q[1] != NULL) {
		fw->req_q_size[1] = ha->req_q[1]->req_ring.size;
	}
	fw->rsp_q_size = ha->rsp_queues[0]->rsp_ring.size * ha->rsp_queues_cnt;

	fw->hccr = RD32_IO_REG(ha, hccr);
	fw->r2h_status = RD32_IO_REG(ha, risc2host);
	fw->aer_ues = ql_pci_config_get32(ha, 0x104);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		/* Disable ISP interrupts. */
		ql_disable_intr(ha);

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
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

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
		ql_disable_intr(ha);

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

	if (rval == QL_SUCCESS) {
		/* Get the Queue Pointers */
		dp = fw->req_rsp_ext_mem;
		for (index = 0; index < ha->rsp_queues_cnt; index++) {
			if (index == 0 && ha->flags & MULTI_QUEUE) {
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[0]->mbar_req_in);
				LITTLE_ENDIAN_32(dp);
				dp++;
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[0]->mbar_req_out);
				LITTLE_ENDIAN_32(dp);
				dp++;
			} else if (index == 1 && ha->flags & MULTI_QUEUE) {
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[1]->mbar_req_in);
				LITTLE_ENDIAN_32(dp);
				dp++;
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[1]->mbar_req_out);
				LITTLE_ENDIAN_32(dp);
				dp++;
			} else {
				*dp++ = 0;
				*dp++ = 0;
			}
			if (ha->flags & MULTI_QUEUE) {
				*dp = RD32_MBAR_REG(ha,
				    ha->rsp_queues[index]->mbar_rsp_in);
				LITTLE_ENDIAN_32(dp);
				dp++;
				*dp = RD32_MBAR_REG(ha,
				    ha->rsp_queues[index]->mbar_rsp_out);
				LITTLE_ENDIAN_32(dp);
				dp++;
			} else {
				*dp++ = 0;
				*dp++ = 0;
			}
		}
		/* Get the request queue */
		(void) ddi_dma_sync(ha->req_q[0]->req_ring.dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		w32ptr = (uint32_t *)ha->req_q[0]->req_ring.bp;
		for (cnt = 0; cnt < fw->req_q_size[0] / 4; cnt++) {
			*dp = *w32ptr++;
			LITTLE_ENDIAN_32(dp);
			dp++;
		}
		if (ha->req_q[1] != NULL) {
			(void) ddi_dma_sync(ha->req_q[1]->req_ring.dma_handle,
			    0, 0, DDI_DMA_SYNC_FORCPU);
			w32ptr = (uint32_t *)ha->req_q[1]->req_ring.bp;
			for (cnt = 0; cnt < fw->req_q_size[1] / 4; cnt++) {
				*dp = *w32ptr++;
				LITTLE_ENDIAN_32(dp);
				dp++;
			}
		}

		/* Get the response queues */
		for (index = 0; index < ha->rsp_queues_cnt; index++) {
			(void) ddi_dma_sync(
			    ha->rsp_queues[index]->rsp_ring.dma_handle,
			    0, 0, DDI_DMA_SYNC_FORCPU);
			w32ptr = (uint32_t *)
			    ha->rsp_queues[index]->rsp_ring.bp;
			for (cnt = 0;
			    cnt < ha->rsp_queues[index]->rsp_ring.size / 4;
			    cnt++) {
				*dp = *w32ptr++;
				LITTLE_ENDIAN_32(dp);
				dp++;
			}
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
		    ha->fw_ext_memory_size / 4, dp);
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
		QL_PRINT_3(ha, "done\n");
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
	uint32_t	*reg32, cnt, *w32ptr, index, *dp;
	void		*bp;
	clock_t		timer;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	fw->req_q_size[0] = ha->req_q[0]->req_ring.size;
	if (ha->req_q[1] != NULL) {
		fw->req_q_size[1] = ha->req_q[1]->req_ring.size;
	}
	fw->rsp_q_size = ha->rsp_queues[0]->rsp_ring.size * ha->rsp_queues_cnt;

	fw->hccr = RD32_IO_REG(ha, hccr);
	fw->r2h_status = RD32_IO_REG(ha, risc2host);
	fw->aer_ues = ql_pci_config_get32(ha, 0x104);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		/* Disable ISP interrupts. */
		ql_disable_intr(ha);

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
		(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

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
		ql_disable_intr(ha);

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

	if (rval == QL_SUCCESS) {
		/* Get the Queue Pointers */
		dp = fw->req_rsp_ext_mem;
		for (index = 0; index < ha->rsp_queues_cnt; index++) {
			if (index == 0 && ha->flags & MULTI_QUEUE) {
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[0]->mbar_req_in);
				LITTLE_ENDIAN_32(dp);
				dp++;
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[0]->mbar_req_out);
				LITTLE_ENDIAN_32(dp);
				dp++;
			} else if (index == 1 && ha->flags & MULTI_QUEUE) {
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[1]->mbar_req_in);
				LITTLE_ENDIAN_32(dp);
				dp++;
				*dp = RD32_MBAR_REG(ha,
				    ha->req_q[1]->mbar_req_out);
				LITTLE_ENDIAN_32(dp);
				dp++;
			} else {
				*dp++ = 0;
				*dp++ = 0;
			}
			if (ha->flags & MULTI_QUEUE) {
				*dp = RD32_MBAR_REG(ha,
				    ha->rsp_queues[index]->mbar_rsp_in);
				LITTLE_ENDIAN_32(dp);
				dp++;
				*dp = RD32_MBAR_REG(ha,
				    ha->rsp_queues[index]->mbar_rsp_out);
				LITTLE_ENDIAN_32(dp);
				dp++;
			} else {
				*dp++ = 0;
				*dp++ = 0;
			}
		}
		/* Get the request queue */
		(void) ddi_dma_sync(ha->req_q[0]->req_ring.dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		w32ptr = (uint32_t *)ha->req_q[0]->req_ring.bp;
		for (cnt = 0; cnt < fw->req_q_size[0] / 4; cnt++) {
			*dp = *w32ptr++;
			LITTLE_ENDIAN_32(dp);
			dp++;
		}
		if (ha->req_q[1] != NULL) {
			(void) ddi_dma_sync(ha->req_q[1]->req_ring.dma_handle,
			    0, 0, DDI_DMA_SYNC_FORCPU);
			w32ptr = (uint32_t *)ha->req_q[1]->req_ring.bp;
			for (cnt = 0; cnt < fw->req_q_size[1] / 4; cnt++) {
				*dp = *w32ptr++;
				LITTLE_ENDIAN_32(dp);
				dp++;
			}
		}

		/* Get the response queues */
		for (index = 0; index < ha->rsp_queues_cnt; index++) {
			(void) ddi_dma_sync(
			    ha->rsp_queues[index]->rsp_ring.dma_handle,
			    0, 0, DDI_DMA_SYNC_FORCPU);
			w32ptr = (uint32_t *)
			    ha->rsp_queues[index]->rsp_ring.bp;
			for (cnt = 0;
			    cnt < ha->rsp_queues[index]->rsp_ring.size / 4;
			    cnt++) {
				*dp = *w32ptr++;
				LITTLE_ENDIAN_32(dp);
				dp++;
			}
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
		    ha->fw_ext_memory_size / 4, dp);
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
		QL_PRINT_3(ha, "done\n");
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
		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			WRT32_IO_REG(ha, nx_host_int, NX_MBX_CMD);
		} else if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
		} else {
			WRT16_IO_REG(ha, hccr, HC_SET_HOST_INT);
		}
		for (timer = 6000000; timer && rval == QL_SUCCESS; timer--) {
			if (INTERRUPT_PENDING(ha)) {
				stat = (uint16_t)
				    (RD16_IO_REG(ha, risc2host) & 0xff);
				if ((stat == 1) || (stat == 0x10)) {
					if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
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
				if (CFG_IST(ha, CFG_CTRL_82XX)) {
					ql_8021_clr_hw_intr(ha);
					ql_8021_clr_fw_intr(ha);
				} else if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
					WRT32_IO_REG(ha, hccr,
					    HC24_CLR_RISC_INT);
					RD32_IO_REG(ha, hccr);
				} else {
					WRT16_IO_REG(ha, semaphore, 0);
					WRT16_IO_REG(ha, hccr,
					    HC_CLR_RISC_INT);
					RD16_IO_REG(ha, hccr);
				}
			}
			drv_usecwait(5);
		}
		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ql_8021_clr_hw_intr(ha);
			ql_8021_clr_fw_intr(ha);
		} else if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
			RD32_IO_REG(ha, hccr);
		} else {
			WRT16_IO_REG(ha, semaphore, 0);
			WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
			RD16_IO_REG(ha, hccr);
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
		QL_PRINT_2(NULL, "no adapter instance=%d\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	QL_PRINT_3(ha, "started\n");

	/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, prop) ==
	    1) {
		QL_PRINT_2(ha, "no prop exit\n");
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

	QL_PRINT_3(ha, "done\n");

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
		QL_PRINT_2(NULL, "no adapter instance=%d\n",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	QL_PRINT_3(ha, "started\n");

	/*LINTED [Solaris DDI_DEV_T_ANY Lint warning]*/
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, prop,
	    (uchar_t **)&chs_p, &elements) != DDI_PROP_SUCCESS) {
		QL_PRINT_2(ha, "no prop exit\n");
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

	QL_PRINT_3(ha, "done\n");

	return (DDI_SUCCESS);
}

uint8_t
ql_pci_config_get8(ql_adapter_state_t *ha, off_t off)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		return (ddi_get8(ha->sbus_config_handle,
		    (uint8_t *)(ha->sbus_config_base + off)));
	}

	return (pci_config_get8(ha->pci_handle, off));
}

uint16_t
ql_pci_config_get16(ql_adapter_state_t *ha, off_t off)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		return (ddi_get16(ha->sbus_config_handle,
		    (uint16_t *)(ha->sbus_config_base + off)));
	}

	return (pci_config_get16(ha->pci_handle, off));
}

uint32_t
ql_pci_config_get32(ql_adapter_state_t *ha, off_t off)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		return (ddi_get32(ha->sbus_config_handle,
		    (uint32_t *)(ha->sbus_config_base + off)));
	}

	return (pci_config_get32(ha->pci_handle, off));
}

void
ql_pci_config_put8(ql_adapter_state_t *ha, off_t off, uint8_t val)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put8(ha->sbus_config_handle,
		    (uint8_t *)(ha->sbus_config_base + off), val);
	} else {
		pci_config_put8(ha->pci_handle, off, val);
	}
}

void
ql_pci_config_put16(ql_adapter_state_t *ha, off_t off, uint16_t val)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put16(ha->sbus_config_handle,
		    (uint16_t *)(ha->sbus_config_base + off), val);
	} else {
		pci_config_put16(ha->pci_handle, off, val);
	}
}

void
ql_pci_config_put32(ql_adapter_state_t *ha, off_t off, uint32_t val)
{
	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		ddi_put32(ha->sbus_config_handle,
		    (uint32_t *)(ha->sbus_config_base + off), val);
	} else {
		pci_config_put32(ha->pci_handle, off, val);
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
	ql_link_t	*link;
	ql_response_q_t	*rsp_q;
	ql_tgt_t	*tq;
	ql_srb_t	*sp;
	uint32_t	cnt, i;
	uint16_t	index;

	QL_PRINT_3(ha, "started\n");

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
			for (i = 0; i < ha->rsp_queues_cnt; i++) {
				if ((rsp_q = ha->rsp_queues[i]) != NULL &&
				    (sp = rsp_q->status_srb) != NULL) {
					rsp_q->status_srb = NULL;
					sp->cmd.next = NULL;
					ql_done(&sp->cmd, B_FALSE);
				}
			}

			/* Abort commands that did not finish. */
			if (cnt == 0) {
				for (cnt = 1; cnt < ha->osc_max_cnt;
				    cnt++) {
					if (ha->pending_cmds.first != NULL) {
						ql_start_iocb(ha, NULL);
						cnt = 1;
					}
					sp = ha->outstanding_cmds[cnt];
					if (sp != NULL &&
					    sp != QL_ABORTED_SRB(ha) &&
					    sp->lun_queue->target_queue ==
					    tq) {
						(void) ql_abort_io(ha, sp);
						sp->pkt->pkt_reason =
						    CS_ABORTED;
						sp->cmd.next = NULL;
						ql_done(&sp->cmd, B_FALSE);
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

	if (pwr == PM_LEVEL_D3 && ha->flags & ONLINE) {
		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~ONLINE;
		ADAPTER_STATE_UNLOCK(ha);

		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ql_8021_clr_drv_active(ha);
		}

		/* Reset ISP chip. */
		ql_reset_chip(ha);
	}

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

	mem->size = size;
	mem->type = allocation_type;
	mem->max_cookie_count = 1;

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

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_free_dma_resource
 *	Function used to free dma memory.
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
	QL_PRINT_3(ha, "started\n");

	ql_free_phys(ha, mem);

	QL_PRINT_3(ha, "done\n");
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
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_alloc_phys(ql_adapter_state_t *ha, dma_mem_t *mem, int sleep)
{
	size_t			rlen;
	ddi_dma_attr_t		dma_attr = ha->io_dma_attr;
	ddi_device_acc_attr_t	acc_attr = ql_dev_acc_attr;

	QL_PRINT_3(ha, "started\n");

	dma_attr.dma_attr_align = mem->alignment; /* DMA address alignment */
	dma_attr.dma_attr_sgllen = (int)mem->max_cookie_count;

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
			if (dma_attr.dma_attr_addr_hi == 0) {
				if (mem->cookie.dmac_notused != 0) {
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

	if (qlc_fm_check_dma_handle(ha, mem->dma_handle)
	    != DDI_FM_OK) {
		EL(ha, "failed, ddi_dma_addr_bind_handle\n");
		ql_free_phys(ha, mem);
		qlc_fm_report_err_impact(ha,
		    QL_FM_EREPORT_DMA_HANDLE_CHECK);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	if (ql_bind_dma_buffer(ha, mem, sleep) != DDI_DMA_MAPPED) {
		EL(ha, "failed, ddi_dma_addr_bind_handle\n");
		ql_free_phys(ha, mem);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	QL_PRINT_3(ha, "done\n");

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
	QL_PRINT_3(ha, "started\n");

	if (mem != NULL) {
		if (mem->memflags == DDI_DMA_MAPPED) {
			ql_unbind_dma_buffer(ha, mem);
		}

		switch (mem->type) {
		case KERNEL_MEM:
			if (mem->bp != NULL) {
				kmem_free(mem->bp, mem->size);
				mem->bp = NULL;
			}
			break;
		case LITTLE_ENDIAN_DMA:
		case BIG_ENDIAN_DMA:
		case NO_SWAP_DMA:
			if (mem->acc_handle != NULL) {
				ddi_dma_mem_free(&mem->acc_handle);
				mem->acc_handle = NULL;
				mem->bp = NULL;
			}
			break;
		default:
			break;
		}
		if (mem->dma_handle != NULL) {
			ddi_dma_free_handle(&mem->dma_handle);
			mem->dma_handle = NULL;
		}
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_bind_dma_buffer
 *	Binds DMA buffer.
 *
 * Input:
 *	ha:			adapter state pointer.
 *	mem:			pointer to dma memory object.
 *	kmflags:		KM_SLEEP or KM_NOSLEEP.
 *	mem->dma_handle		DMA memory handle.
 *	mem->max_cookie_count	number of segments allowed.
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
ql_bind_dma_buffer(ql_adapter_state_t *ha, dma_mem_t *mem, int kmflags)
{
	ddi_dma_cookie_t	*cookiep;
	uint32_t		cnt;

	QL_PRINT_3(ha, "started\n");

	mem->memflags = ddi_dma_addr_bind_handle(mem->dma_handle, NULL,
	    mem->bp, mem->size, mem->flags, (kmflags == KM_SLEEP) ?
	    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT, NULL, &mem->cookie,
	    &mem->cookie_count);

	if (mem->memflags == DDI_DMA_MAPPED) {
		if (mem->cookie_count > mem->max_cookie_count) {
			(void) ddi_dma_unbind_handle(mem->dma_handle);
			EL(ha, "failed, cookie_count %d > %d\n",
			    mem->cookie_count, mem->max_cookie_count);
			mem->memflags = (uint32_t)DDI_DMA_TOOBIG;
		} else {
			if (mem->cookie_count > 1) {
				if (mem->cookies = kmem_zalloc(
				    sizeof (ddi_dma_cookie_t) *
				    mem->cookie_count, kmflags)) {
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
					mem->memflags = (uint32_t)
					    DDI_DMA_NORESOURCES;
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

	if (mem->memflags != DDI_DMA_MAPPED) {
		EL(ha, "failed=%xh\n", mem->memflags);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (mem->memflags);
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
	QL_PRINT_3(ha, "started\n");

	if (mem->dma_handle != NULL && mem->memflags == DDI_DMA_MAPPED) {
		(void) ddi_dma_unbind_handle(mem->dma_handle);
	}
	if (mem->cookie_count > 1) {
		kmem_free(mem->cookies, sizeof (ddi_dma_cookie_t) *
		    mem->cookie_count);
		mem->cookies = NULL;
	}
	mem->cookie_count = 0;
	mem->memflags = (uint32_t)DDI_DMA_NORESOURCES;

	QL_PRINT_3(ha, "done\n");
}

static int
ql_suspend_adapter(ql_adapter_state_t *ha)
{
	clock_t timer = (clock_t)(32 * drv_usectohz(1000000));

	QL_PRINT_3(ha, "started\n");

	(void) ql_wait_outstanding(ha);

	/*
	 * here we are sure that there will not be any mbox interrupt.
	 * So, let's make sure that we return back all the outstanding
	 * cmds as well as internally queued commands.
	 */
	ql_halt(ha, PM_LEVEL_D0);

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

	if (ha->power_level != PM_LEVEL_D3) {
		/* Disable ISP interrupts. */
		ql_disable_intr(ha);
	}

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

	QL_PRINT_3(ha, "done\n");

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
	if (link->head != NULL) {
		EL(NULL, "link in use by list=%ph\n", link->head);
	}

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
	if (link->head != NULL) {
		EL(NULL, "link in use by list=%ph\n", link->head);
	}
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
 *	associated proper LOCK must be already obtained.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_remove_link(ql_head_t *head, ql_link_t *link)
{
	if (head != NULL) {
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
	size_t	cnt1;
	size_t	cnt;

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
	if (ha->flags & ADAPTER_SUSPENDED || ddi_in_panic() ||
	    curthread->t_flag & T_INTR_THREAD) {
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
	ql_adapter_state_t	*ha2 = NULL;
	uint32_t		timer;

	QL_PRINT_3(ha, "started\n");

	/* Tell all daemons to stall. */
	link = ha == NULL ? ql_hba.first : &ha->hba;
	while (link != NULL) {
		ha2 = link->base_address;

		ql_awaken_task_daemon(ha2, NULL, DRIVER_STALL, 0);

		link = ha == NULL ? link->next : NULL;
	}

	/* Wait for 30 seconds for daemons stall. */
	timer = 3000;
	link = ha == NULL ? ql_hba.first : &ha->hba;
	while (link != NULL && timer) {
		ha2 = link->base_address;

		if ((ha2->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) == 0 ||
		    (ha2->task_daemon_flags & TASK_DAEMON_STOP_FLG) != 0 ||
		    (ha2->task_daemon_flags & FIRMWARE_UP) == 0 ||
		    (ha2->task_daemon_flags & TASK_DAEMON_STALLED_FLG &&
		    ql_wait_outstanding(ha2) == ha2->pha->osc_max_cnt)) {
			link = ha == NULL ? link->next : NULL;
			continue;
		}

		QL_PRINT_2(ha2, "status, dtf=%xh, stf=%xh\n",
		    ha2->task_daemon_flags, ha2->flags);

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

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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
			QL_PRINT_2(ha2, "restarted\n");
			ql_restart_queues(ha2);
			link = ha == NULL ? link->next : NULL;
			continue;
		}

		QL_PRINT_2(ha2, "status, tdf=%xh\n", ha2->task_daemon_flags);

		ql_delay(ha2, 10000);
		timer--;
		link = ha == NULL ? ql_hba.first : &ha->hba;
	}

	QL_PRINT_3(ha, "done\n");
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

	QL_PRINT_3(ha, "started\n");

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
		/* Setup mutexes */
		if ((rval = ql_init_mutex(ha)) != DDI_SUCCESS) {
			EL(ha, "failed, mutex init ret=%xh\n", rval);
			ql_release_intr(ha);
		}
		QL_PRINT_3(ha, "done\n");
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
	uint_t		i;
	int32_t		count = 0;
	int32_t		avail = 0;
	int32_t		actual = 0;
	int32_t		msitype = DDI_INTR_TYPE_MSI;
	int32_t		ret;

	QL_PRINT_3(ha, "started\n");

	if (ql_disable_msi != 0) {
		EL(ha, "MSI is disabled by user\n");
		return (DDI_FAILURE);
	}

	/* MSI support is only suported on 24xx HBA's. */
	if (!CFG_IST(ha, CFG_MSI_SUPPORT)) {
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
	if ((ret = ddi_intr_get_pri(ha->htable[0], &i)) != DDI_SUCCESS) {
		EL(ha, "failed, get_pri ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}
	ha->intr_pri = DDI_INTR_PRI(i);

	/* Add the interrupt handler */
	if ((ret = ddi_intr_add_handler(ha->htable[0], ql_isr_aif,
	    (caddr_t)ha, (caddr_t)0)) != DDI_SUCCESS) {
		EL(ha, "failed, intr_add ret=%xh\n", ret);
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
			ql_release_intr(ha);
			return (ret);
		}
	} else {
		for (i = 0; i < actual; i++) {
			if ((ret = ddi_intr_enable(ha->htable[i])) !=
			    DDI_SUCCESS) {
				EL(ha, "failed, intr enable, ret=%xh\n", ret);
				ql_release_intr(ha);
				return (ret);
			}
		}
	}

	QL_PRINT_3(ha, "done\n");

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
	int		hwvect;
	int32_t		count = 0;
	int32_t		avail = 0;
	int32_t		actual = 0;
	int32_t		msitype = DDI_INTR_TYPE_MSIX;
	int32_t		ret;
	uint_t		i;

	QL_PRINT_3(ha, "started\n");

	if (ql_disable_msix != 0) {
		EL(ha, "MSI-X is disabled by user\n");
		return (DDI_FAILURE);
	}

	/*
	 * MSI-X support is only available on 24xx HBA's that have
	 * rev A2 parts (revid = 3) or greater.
	 */
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_1) ||
	    (CFG_IST(ha, CFG_CTRL_24XX) && ha->rev_id < 3)) {
		EL(ha, "HBA does not support MSI-X\n");
		return (DDI_FAILURE);
	}

	/* Per HP, these HP branded HBA's are not supported with MSI-X */
	if (ha->ven_id == 0x103C && (ha->subsys_id == 0x7041 ||
	    ha->subsys_id == 0x7040 || ha->subsys_id == 0x1705)) {
		EL(ha, "HBA does not support MSI-X (subdevid)\n");
		return (DDI_FAILURE);
	}

	/* Get number of MSI-X interrupts the platform h/w supports */
	if (((ret = ddi_intr_get_nintrs(ha->dip, msitype, &hwvect)) !=
	    DDI_SUCCESS) || hwvect == 0) {
		EL(ha, "failed, nintrs ret=%xh, cnt=%xh\n", ret, hwvect);
		return (DDI_FAILURE);
	}
	QL_PRINT_10(ha, "ddi_intr_get_nintrs, hwvect=%d\n", hwvect);

	/* Get number of available system interrupts */
	if (((ret = ddi_intr_get_navail(ha->dip, msitype, &avail)) !=
	    DDI_SUCCESS) || avail == 0) {
		EL(ha, "failed, navail ret=%xh, avail=%xh\n", ret, avail);
		return (DDI_FAILURE);
	}
	QL_PRINT_10(ha, "ddi_intr_get_navail, avail=%d\n", avail);

	/* Fill out the intr table */
	count = ha->interrupt_count;
	if (ha->flags & MULTI_QUEUE && count < ha->mq_msix_vectors) {
		count = ha->mq_msix_vectors;
		/* don't exceed the h/w capability */
		if (count > hwvect) {
			count = hwvect;
		}
	}

	/* Allocate space for interrupt handles */
	ha->hsize = ((uint32_t)(sizeof (ddi_intr_handle_t)) * hwvect);
	ha->htable = kmem_zalloc(ha->hsize, KM_SLEEP);

	ha->iflags |= IFLG_INTR_MSIX;

	/* Allocate the interrupts */
	if (((ret = ddi_intr_alloc(ha->dip, ha->htable, msitype,
	    DDI_INTR_ALLOC_NORMAL, count, &actual, 0)) != DDI_SUCCESS) ||
	    actual < ha->interrupt_count) {
		EL(ha, "failed, intr_alloc ret=%xh, count = %xh, "
		    "actual=%xh\n", ret, count, actual);
		ql_release_intr(ha);
		return (DDI_FAILURE);
	}
	ha->intr_cnt = actual;
	EL(ha, "min=%d, multi-q=%d, req=%d, rcv=%d\n",
	    ha->interrupt_count, ha->mq_msix_vectors, count,
	    ha->intr_cnt);

	/* Get interrupt priority */
	if ((ret = ddi_intr_get_pri(ha->htable[0], &i)) != DDI_SUCCESS) {
		EL(ha, "failed, get_pri ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}
	ha->intr_pri = DDI_INTR_PRI(i);

	/* Add the interrupt handlers */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(ha->htable[i], ql_isr_aif,
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
		if ((ret = ddi_intr_enable(ha->htable[i])) != DDI_SUCCESS) {
			EL(ha, "failed, intr enable, ret=%xh\n", ret);
			ql_release_intr(ha);
			return (ret);
		}
	}
#endif

	/* Get the capabilities */
	(void) ddi_intr_get_cap(ha->htable[0], &ha->intr_cap);

	/* Enable interrupts */
	if (ha->intr_cap & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(ha->htable, actual)) !=
		    DDI_SUCCESS) {
			EL(ha, "failed, block enable, ret=%xh\n", ret);
			ql_release_intr(ha);
			return (ret);
		}
		QL_PRINT_10(ha, "intr_block_enable %d\n", actual);
	} else {
		for (i = 0; i < actual; i++) {
			if ((ret = ddi_intr_enable(ha->htable[i])) !=
			    DDI_SUCCESS) {
				EL(ha, "failed, intr enable, ret=%xh\n", ret);
				ql_release_intr(ha);
				return (ret);
			}
			QL_PRINT_10(ha, "intr_enable %d\n", i);
		}
	}

	QL_PRINT_3(ha, "done\n");

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
	uint_t		i;

	QL_PRINT_3(ha, "started\n");

	if (ql_disable_intx != 0) {
		EL(ha, "INT-X is disabled by user\n");
		return (DDI_FAILURE);
	}

	/* Get number of fixed interrupts the system supports */
	if (((ret = ddi_intr_get_nintrs(ha->dip, DDI_INTR_TYPE_FIXED,
	    &count)) != DDI_SUCCESS) || count == 0) {
		EL(ha, "failed, nintrs ret=%xh, cnt=%xh\n", ret, count);
		return (DDI_FAILURE);
	}

	/* Allocate space for interrupt handles */
	ha->hsize = ((uint32_t)(sizeof (ddi_intr_handle_t)) * count);
	ha->htable = kmem_zalloc(ha->hsize, KM_SLEEP);

	ha->iflags |= IFLG_INTR_FIXED;

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
	if ((ret = ddi_intr_get_pri(ha->htable[0], &i)) != DDI_SUCCESS) {
		EL(ha, "failed, get_pri ret=%xh\n", ret);
		ql_release_intr(ha);
		return (ret);
	}
	ha->intr_pri = DDI_INTR_PRI(i);

	/* Add the interrupt handlers */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(ha->htable[i], ql_isr_aif,
		    (void *)ha, (void *)((ulong_t)(i)))) != DDI_SUCCESS) {
			EL(ha, "failed, intr_add ret=%xh\n", ret);
			ql_release_intr(ha);
			return (ret);
		}
	}

	/* Enable interrupts */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_enable(ha->htable[i])) != DDI_SUCCESS) {
			EL(ha, "failed, intr enable, ret=%xh\n", ret);
			ql_release_intr(ha);
			return (ret);
		}
	}

	EL(ha, "using FIXED interupts\n");

	QL_PRINT_3(ha, "done\n");

	return (DDI_SUCCESS);
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
	int32_t	i, x;

	QL_PRINT_3(ha, "started\n");

	if (!(ha->iflags & IFLG_INTR_AIF)) {
		ddi_remove_intr(ha->dip, 0, ha->iblock_cookie);
	} else {
		ha->iflags &= ~(IFLG_INTR_AIF);
		if (ha->htable != NULL && ha->hsize > 0) {
			i = x = (int32_t)ha->hsize /
			    (int32_t)sizeof (ddi_intr_handle_t);
			if (ha->intr_cap & DDI_INTR_FLAG_BLOCK) {
				(void) ddi_intr_block_disable(ha->htable,
				    ha->intr_cnt);
			} else {
				while (i-- > 0) {
					if (ha->htable[i] == 0) {
						EL(ha, "htable[%x]=0h\n", i);
						continue;
					}

					(void) ddi_intr_disable(ha->htable[i]);
				}
			}

			i = x;
			while (i-- > 0) {
				if (i < ha->intr_cnt) {
					(void) ddi_intr_remove_handler(
					    ha->htable[i]);
				}
				(void) ddi_intr_free(ha->htable[i]);
			}

			ha->intr_cnt = 0;
			ha->intr_cap = 0;

			kmem_free(ha->htable, ha->hsize);
			ha->htable = NULL;
			ha->hsize = 0;
		}
	}

	ha->intr_pri = NULL;

	QL_PRINT_3(ha, "done\n");
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
	int	rval;

	QL_PRINT_3(ha, "started\n");

	/* Get iblock cookies to initialize mutexes */
	if ((rval = ddi_get_iblock_cookie(ha->dip, 0, &ha->iblock_cookie)) !=
	    DDI_SUCCESS) {
		EL(ha, "failed, get_iblock: %xh\n", rval);
		return (rval);
	}
	ha->intr_pri = (void *)ha->iblock_cookie;

	/* Setup standard/legacy interrupt handler */
	if (ddi_add_intr(ha->dip, (uint_t)0, &ha->iblock_cookie,
	    (ddi_idevice_cookie_t *)0, ql_isr, (caddr_t)ha) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d): Failed to add legacy interrupt",
		    QL_NAME, ha->instance);
		return (rval);
	}
	ha->iflags |= IFLG_INTR_LEGACY;

	/* Setup mutexes */
	if ((rval = ql_init_mutex(ha)) != DDI_SUCCESS) {
		EL(ha, "failed, mutex init ret=%xh\n", rval);
		ql_release_intr(ha);
	} else {
		EL(ha, "using legacy interrupts\n");
	}
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
	QL_PRINT_3(ha, "started\n");

	/* mutexes to protect the adapter state structure. */
	mutex_init(&ha->mutex, NULL, MUTEX_DRIVER, ha->intr_pri);

	/* mutex to protect the ISP request ring. */
	mutex_init(&ha->req_ring_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);

	/* I/O completion queue protection. */
	mutex_init(&ha->comp_q_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);
	cv_init(&ha->cv_comp_thread, NULL, CV_DRIVER, NULL);

	/* mutex to protect the mailbox registers. */
	mutex_init(&ha->mbx_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);

	/* Mailbox wait and interrupt conditional variable. */
	cv_init(&ha->cv_mbx_wait, NULL, CV_DRIVER, NULL);
	cv_init(&ha->cv_mbx_intr, NULL, CV_DRIVER, NULL);

	/* power management protection */
	mutex_init(&ha->pm_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);

	/* Unsolicited buffer conditional variable. */
	mutex_init(&ha->ub_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);
	cv_init(&ha->cv_ub, NULL, CV_DRIVER, NULL);

	/* mutex to protect task daemon context. */
	mutex_init(&ha->task_daemon_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);
	cv_init(&ha->cv_task_daemon, NULL, CV_DRIVER, NULL);

	/* Suspended conditional variable. */
	cv_init(&ha->cv_dr_suspended, NULL, CV_DRIVER, NULL);

	/* mutex to protect per instance f/w dump flags and buffer */
	mutex_init(&ha->dump_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);

	QL_PRINT_3(ha, "done\n");

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
	QL_PRINT_3(ha, "started\n");

	mutex_destroy(&ha->dump_mutex);
	cv_destroy(&ha->cv_dr_suspended);
	cv_destroy(&ha->cv_task_daemon);
	mutex_destroy(&ha->task_daemon_mutex);
	cv_destroy(&ha->cv_ub);
	mutex_destroy(&ha->ub_mutex);
	mutex_destroy(&ha->pm_mutex);
	cv_destroy(&ha->cv_mbx_intr);
	cv_destroy(&ha->cv_mbx_wait);
	mutex_destroy(&ha->mbx_mutex);
	cv_destroy(&ha->cv_comp_thread);
	mutex_destroy(&ha->comp_q_mutex);
	mutex_destroy(&ha->req_ring_mutex);
	mutex_destroy(&ha->mutex);

	QL_PRINT_3(ha, "done\n");
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
	caddr_t			code, code02, code03;
	uint8_t			*p_ucfw;
	uint16_t		*p_usaddr, *p_uslen;
	uint32_t		*p_uiaddr, *p_uilen, *p_uifw;
	uint32_t		*p_uiaddr02, *p_uilen02, *p_uilen03;
	struct fw_table		*fwt;
	extern struct fw_table	fw_table[];

	QL_PRINT_3(ha, "started\n");

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
	case 0x2700:
	case 0x8100:
	case 0x8301fc:

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
			if (ha->fw_class == 0x2700) {
				if ((code03 = ddi_modsym(ha->fw_module,
				    "tmplt_code01", NULL)) == NULL) {
					EL(ha, "failed, f/w module %d "
					    "tmplt_code01 symbol\n", module);
				} else if ((p_uilen03 = ddi_modsym(
				    ha->fw_module, "tmplt_code_length01",
				    NULL)) == NULL) {
					code03 = NULL;
					EL(ha, "failed, f/w module %d "
					    "tmplt_code_length01 symbol\n",
					    module);
				}
				ha->risc_fw[2].code = code03;
				if ((ha->risc_fw[2].code = code03) != NULL) {
					ha->risc_fw[2].length = *p_uilen03;
				}
			}
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
		}
	}

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

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

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_el_trace_alloc - Construct an extended logging trace descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Context:	Kernel context.
 */
void
ql_el_trace_alloc(ql_adapter_state_t *ha)
{
	ql_trace_entry_t	*entry;
	size_t			maxsize;

	ha->ql_trace_desc =
	    (ql_trace_desc_t *)kmem_zalloc(
	    sizeof (ql_trace_desc_t), KM_SLEEP);

	/* ql_log_entries could be adjusted in /etc/system */
	maxsize = ql_log_entries * sizeof (ql_trace_entry_t);
	entry = kmem_zalloc(maxsize, KM_SLEEP);

	mutex_init(&ha->ql_trace_desc->mutex, NULL,
	    MUTEX_DRIVER, NULL);

	ha->ql_trace_desc->trace_buffer = entry;
	ha->ql_trace_desc->trace_buffer_size = maxsize;
	ha->ql_trace_desc->nindex = 0;

	ha->ql_trace_desc->nentries = ql_log_entries;
	ha->ql_trace_desc->start = ha->ql_trace_desc->end = 0;
	ha->ql_trace_desc->csize = 0;
	ha->ql_trace_desc->count = 0;
}

/*
 * ql_el_trace_dealloc - Destroy an extended logging trace descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Context:	Kernel context.
 */
void
ql_el_trace_dealloc(ql_adapter_state_t *ha)
{
	if (ha->ql_trace_desc != NULL) {
		if (ha->ql_trace_desc->trace_buffer != NULL) {
			kmem_free(ha->ql_trace_desc->trace_buffer,
			    ha->ql_trace_desc->trace_buffer_size);
		}
		mutex_destroy(&ha->ql_trace_desc->mutex);
		kmem_free(ha->ql_trace_desc,
		    sizeof (ql_trace_desc_t));
	}
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
 * ql_els_24xx_iocb
 * 	els request indication.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	srb:	scsi request block pointer.
 *      arg:	els passthru entry iocb pointer.
 *
 * Returns:
 *
 * Context:	Kernel context.
 */
void
ql_els_24xx_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q, ql_srb_t *srb,
    void *arg)
{
	els_descriptor_t	els_desc;

	/* Extract the ELS information */
	ql_fca_isp_els_request(ha, req_q, (fc_packet_t *)srb->pkt,
	    &els_desc);

	/* Construct the passthru entry */
	ql_isp_els_request_ctor(&els_desc, (els_passthru_entry_t *)arg);

	/* Ensure correct endianness */
	ql_isp_els_handle_cmd_endian(ha, srb);
}

/*
 * ql_fca_isp_els_request
 *	Extract into an els descriptor the info required
 *	to build an els_passthru iocb from an fc packet.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	req_q:		request queue structure pointer.
 *	pkt:		fc packet pointer
 *	els_desc:	els descriptor pointer
 *
 * Context:
 *	Kernel context.
 */
static void
ql_fca_isp_els_request(ql_adapter_state_t *ha, ql_request_q_t *req_q,
    fc_packet_t *pkt, els_descriptor_t *els_desc)
{
	ls_code_t	els;

	ddi_rep_get8(pkt->pkt_cmd_acc, (uint8_t *)&els,
	    (uint8_t *)pkt->pkt_cmd, sizeof (els), DDI_DEV_AUTOINCR);

	els_desc->els = els.ls_code;

	els_desc->els_handle = req_q->req_ring.acc_handle;
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
	ptr32 = (uint32_t *)&els_entry->dseg;
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
	ql_tgt_t	*tq = NULL;
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
			ql_done(done_q.first, B_FALSE);
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
/* ARGSUSED */
int
ql_wwn_cmp(ql_adapter_state_t *ha, la_wwn_t *first, la_wwn_t *second)
{
	la_wwn_t t1, t2;
	int rval;

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

	QL_PRINT_3(ha, "started\n");

	ha->nvram_cache =
	    (nvram_cache_desc_t *)kmem_zalloc(sizeof (nvram_cache_desc_t),
	    KM_SLEEP);

	if (ha->nvram_cache == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't construct nvram cache"
		    " descriptor", QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
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
			ha->nvram_cache->valid = 0;
		}
	}

	QL_PRINT_3(ha, "done\n");

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

	QL_PRINT_3(ha, "started\n");

	if (ha->nvram_cache == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't destroy nvram descriptor",
		    QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		if (ha->nvram_cache->cache != NULL) {
			kmem_free(ha->nvram_cache->cache,
			    ha->nvram_cache->size);
		}
		kmem_free(ha->nvram_cache, sizeof (nvram_cache_desc_t));
	}

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_plogi_params_desc_ctor - Construct an plogi retry params descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
int
ql_plogi_params_desc_ctor(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	ha->plogi_params =
	    (plogi_params_desc_t *)kmem_zalloc(sizeof (plogi_params_desc_t),
	    KM_SLEEP);

	if (ha->plogi_params == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't construct plogi params"
		    " descriptor", QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		/* default initializers. */
		ha->plogi_params->retry_cnt = QL_PLOGI_RETRY_CNT;
		ha->plogi_params->retry_dly_usec = QL_PLOGI_RETRY_DLY_USEC;
	}

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_plogi_params_desc_dtor - Destroy an plogi retry params descriptor.
 *
 * Input:	Pointer to the adapter state structure.
 * Returns:	Success or Failure.
 * Context:	Kernel context.
 */
int
ql_plogi_params_desc_dtor(ql_adapter_state_t *ha)
{
	int	rval = DDI_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	if (ha->plogi_params == NULL) {
		cmn_err(CE_WARN, "%s(%d): can't destroy plogi params"
		    " descriptor", QL_NAME, ha->instance);
		rval = DDI_FAILURE;
	} else {
		kmem_free(ha->plogi_params, sizeof (plogi_params_desc_t));
	}

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_toggle_loop_state
 *	Changes looop state to offline and then online.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
ql_toggle_loop_state(ql_adapter_state_t *ha)
{
	uint32_t	timer;

	if (LOOP_READY(ha)) {
		ql_port_state(ha, FC_STATE_OFFLINE, FC_STATE_CHANGE);
		ql_awaken_task_daemon(ha, NULL, FC_STATE_CHANGE, 0);
		for (timer = 30; timer; timer--) {
			if (!(ha->task_daemon_flags & FC_STATE_CHANGE)) {
				break;
			}
			delay(100);
		}
		ql_loop_online(ha);
	}
}

/*
 * ql_create_queues
 *	Allocate request/response queues.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql driver local function return status codes
 *
 * Context:
 *	Kernel context.
 */
static int
ql_create_queues(ql_adapter_state_t *ha)
{
	int		rval;
	uint16_t	cnt;

	QL_PRINT_10(ha, "started\n");

	if (ha->req_q[0] != NULL) {
		QL_PRINT_10(ha, "done, queues already exist\n");
		return (QL_SUCCESS);
	}
	if (ha->vp_index != 0) {
		QL_PRINT_10(ha, "done, no multi-req-q \n");
		ha->req_q[0] = ha->pha->req_q[0];
		ha->req_q[1] = ha->pha->req_q[1];
		ha->rsp_queues = ha->pha->rsp_queues;
		return (QL_SUCCESS);
	}

	/* Setup request queue buffer pointers. */
	ha->req_q[0] = kmem_zalloc(sizeof (ql_request_q_t), KM_SLEEP);

	/* Allocate request queue. */
	ha->req_q[0]->req_entry_cnt = REQUEST_ENTRY_CNT;
	ha->req_q[0]->req_ring.size = ha->req_q[0]->req_entry_cnt *
	    REQUEST_ENTRY_SIZE;
	if (ha->flags & QUEUE_SHADOW_PTRS) {
		ha->req_q[0]->req_ring.size += SHADOW_ENTRY_SIZE;
	}
	ha->req_q[0]->req_ring.type = LITTLE_ENDIAN_DMA;
	ha->req_q[0]->req_ring.max_cookie_count = 1;
	ha->req_q[0]->req_ring.alignment = 64;
	if ((rval = ql_alloc_phys(ha, &ha->req_q[0]->req_ring, KM_SLEEP)) !=
	    QL_SUCCESS) {
		EL(ha, "request queue status=%xh", rval);
		ql_delete_queues(ha);
		return (rval);
	}
	if (ha->flags & QUEUE_SHADOW_PTRS) {
		ha->req_q[0]->req_out_shadow_ofst =
		    ha->req_q[0]->req_entry_cnt * REQUEST_ENTRY_SIZE;
		ha->req_q[0]->req_out_shadow_ptr = (uint32_t *)
		    ((caddr_t)ha->req_q[0]->req_ring.bp +
		    ha->req_q[0]->req_out_shadow_ofst);
	}
	ha->fw_transfer_size = ha->req_q[0]->req_ring.size;
	if (ha->flags & MULTI_QUEUE) {
		ha->req_q[0]->mbar_req_in = MBAR2_REQ_IN;
		ha->req_q[0]->mbar_req_out = MBAR2_REQ_OUT;
		if (ha->req_q[0]->mbar_req_in >= ha->mbar_size) {
			EL(ha, "req_q index=0 exceeds mbar size=%xh",
			    ha->mbar_size);
			ql_delete_queues(ha);
			return (QL_FUNCTION_PARAMETER_ERROR);
		}
	}

	/* Allocate response queues. */
	if (ha->rsp_queues == NULL) {
		if (ha->intr_cnt > 1) {
			ha->rsp_queues_cnt = (uint8_t)(ha->intr_cnt - 1);
		} else {
			ha->rsp_queues_cnt = 1;
		}
		ha->io_min_rsp_q_number = 0;
		if (ha->rsp_queues_cnt > 1) {
			/* Setup request queue buffer pointers. */
			ha->req_q[1] = kmem_zalloc(sizeof (ql_request_q_t),
			    KM_SLEEP);

			/* Allocate request queue. */
			ha->req_q[1]->req_entry_cnt = REQUEST_ENTRY_CNT;
			ha->req_q[1]->req_ring.size =
			    ha->req_q[1]->req_entry_cnt * REQUEST_ENTRY_SIZE;
			if (ha->flags & QUEUE_SHADOW_PTRS) {
				ha->req_q[1]->req_ring.size +=
				    SHADOW_ENTRY_SIZE;
			}
			ha->req_q[1]->req_ring.type = LITTLE_ENDIAN_DMA;
			ha->req_q[1]->req_ring.max_cookie_count = 1;
			ha->req_q[1]->req_ring.alignment = 64;
			if ((rval = ql_alloc_phys(ha, &ha->req_q[1]->req_ring,
			    KM_SLEEP)) != QL_SUCCESS) {
				EL(ha, "ha request queue status=%xh", rval);
				ql_delete_queues(ha);
				return (rval);
			}
			if (ha->flags & QUEUE_SHADOW_PTRS) {
				ha->req_q[1]->req_out_shadow_ofst =
				    ha->req_q[1]->req_entry_cnt *
				    REQUEST_ENTRY_SIZE;
				ha->req_q[1]->req_out_shadow_ptr = (uint32_t *)
				    ((caddr_t)ha->req_q[1]->req_ring.bp +
				    ha->req_q[1]->req_out_shadow_ofst);
			}
			ha->req_q[1]->req_q_number = 1;
			if (ha->flags & MULTI_QUEUE) {
				ha->req_q[1]->mbar_req_in =
				    ha->mbar_queue_offset + MBAR2_REQ_IN;
				ha->req_q[1]->mbar_req_out =
				    ha->mbar_queue_offset + MBAR2_REQ_OUT;
				if (ha->req_q[1]->mbar_req_in >=
				    ha->mbar_size) {
					EL(ha, "ha req_q index=1 exceeds mbar "
					    "size=%xh", ha->mbar_size);
					ql_delete_queues(ha);
					return (QL_FUNCTION_PARAMETER_ERROR);
				}
			}
		}

		/* Allocate enough rsp_queue descriptors for IRM */
		ha->rsp_queues_size = (ha->hsize / sizeof (ddi_intr_handle_t)) *
		    sizeof (ql_response_q_t *);
		ha->rsp_queues = kmem_zalloc(ha->rsp_queues_size, KM_SLEEP);

		/* Create rsp_queues for the current rsp_queue_cnt */
		for (cnt = 0; cnt < ha->rsp_queues_cnt; cnt++) {
			rval = ql_create_rsp_queue(ha, cnt);
			if (rval != QL_SUCCESS) {
				ql_delete_queues(ha);
				return (rval);
			}
		}
	}

	if (CFG_IST(ha, CFG_FCIP_TYPE_1)) {
		/* Allocate IP receive queue. */
		ha->rcv_ring.size = RCVBUF_QUEUE_SIZE;
		ha->rcv_ring.type = LITTLE_ENDIAN_DMA;
		ha->rcv_ring.max_cookie_count = 1;
		ha->rcv_ring.alignment = 64;
		if ((rval = ql_alloc_phys(ha, &ha->rcv_ring, KM_SLEEP)) !=
		    QL_SUCCESS) {
			EL(ha, "receive queue status=%xh", rval);
			ql_delete_queues(ha);
			return (rval);
		}
	}

	QL_PRINT_10(ha, "done\n");

	return (rval);
}

/*
 * ql_create_rsp_queue
 *	Allocate a response queues.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql driver local function return status codes
 *
 * Context:
 *	Kernel context.
 */
static int
ql_create_rsp_queue(ql_adapter_state_t *ha, uint16_t rsp_q_indx)
{
	ql_response_q_t	*rsp_q;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	ha->rsp_queues[rsp_q_indx] = rsp_q =
	    kmem_zalloc(sizeof (ql_response_q_t), KM_SLEEP);
	/* ISP response ring and interrupt protection. */
	mutex_init(&rsp_q->intr_mutex, NULL, MUTEX_DRIVER, ha->intr_pri);
	rsp_q->rsp_q_number = rsp_q_indx;
	rsp_q->msi_x_vector = (uint16_t)(rsp_q_indx + 1);
	if (ha->flags & MULTI_QUEUE) {
		rsp_q->mbar_rsp_in = rsp_q->rsp_q_number *
		    ha->mbar_queue_offset + MBAR2_RESP_IN;
		rsp_q->mbar_rsp_out = rsp_q->rsp_q_number *
		    ha->mbar_queue_offset + MBAR2_RESP_OUT;
		if (rsp_q->mbar_rsp_in >= ha->mbar_size) {
			EL(ha, "rsp_q index=%xh exceeds mbar size=%xh",
			    rsp_q_indx, ha->mbar_size);
			return (QL_FUNCTION_PARAMETER_ERROR);
		}
	}

	rsp_q->rsp_entry_cnt = RESPONSE_ENTRY_CNT;
	rsp_q->rsp_ring.size = rsp_q->rsp_entry_cnt * RESPONSE_ENTRY_SIZE;
	if (ha->flags & QUEUE_SHADOW_PTRS) {
		rsp_q->rsp_ring.size += SHADOW_ENTRY_SIZE;
	}
	rsp_q->rsp_ring.type = LITTLE_ENDIAN_DMA;
	rsp_q->rsp_ring.max_cookie_count = 1;
	rsp_q->rsp_ring.alignment = 64;
	rval = ql_alloc_phys(ha, &rsp_q->rsp_ring, KM_SLEEP);
	if (rval != QL_SUCCESS) {
		EL(ha, "response queue status=%xh", rval);
	}
	if (ha->flags & QUEUE_SHADOW_PTRS) {
		rsp_q->rsp_in_shadow_ofst =
		    rsp_q->rsp_entry_cnt * RESPONSE_ENTRY_SIZE;
		rsp_q->rsp_in_shadow_ptr = (uint32_t *)
		    ((caddr_t)rsp_q->rsp_ring.bp +
		    rsp_q->rsp_in_shadow_ofst);
	}

	QL_PRINT_3(ha, "done\n");
	return (rval);
}

/*
 * ql_delete_queues
 *	Deletes request/response queues.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_delete_queues(ql_adapter_state_t *ha)
{
	uint32_t	cnt;

	QL_PRINT_10(ha, "started\n");

	if (ha->vp_index != 0) {
		QL_PRINT_10(ha, "done, no multi-req-q \n");
		ha->req_q[0] = ha->req_q[1] = NULL;
		return;
	}
	if (ha->req_q[0] != NULL) {
		ql_free_phys(ha, &ha->req_q[0]->req_ring);
		kmem_free(ha->req_q[0], sizeof (ql_request_q_t));
		ha->req_q[0] = NULL;
	}
	if (ha->req_q[1] != NULL) {
		ql_free_phys(ha, &ha->req_q[1]->req_ring);
		kmem_free(ha->req_q[1], sizeof (ql_request_q_t));
		ha->req_q[1] = NULL;
	}

	if (ha->rsp_queues != NULL) {
		ql_response_q_t	*rsp_q;

		for (cnt = 0; cnt < ha->rsp_queues_cnt; cnt++) {
			if ((rsp_q = ha->rsp_queues[cnt]) == NULL) {
				continue;
			}

			mutex_destroy(&rsp_q->intr_mutex);
			ql_free_phys(ha, &rsp_q->rsp_ring);
			kmem_free(rsp_q, sizeof (ql_response_q_t));
			ha->rsp_queues[cnt] = NULL;
		}
		kmem_free(ha->rsp_queues, ha->rsp_queues_size);
		ha->rsp_queues = NULL;
	}

	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_multi_queue_support
 *      Test 2500 or 8100 adapters for support of multi-queue
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *      ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_multi_queue_support(ql_adapter_state_t *ha)
{
	uint32_t	data;
	int		rval;

	data = ql_get_cap_ofst(ha, PCI_CAP_ID_MSI_X);
	if ((ql_pci_config_get16(ha, data + PCI_MSIX_CTRL) &
	    PCI_MSIX_TBL_SIZE_MASK) > 2) {
		ha->mbar_size = MBAR2_MULTI_Q_MAX * MBAR2_REG_OFFSET;

		if (ql_map_mem_bar(ha, &ha->mbar_dev_handle, &ha->mbar,
		    PCI_CONF_BASE3, ha->mbar_size) != DDI_SUCCESS) {
			return (QL_FUNCTION_FAILED);
		}
		if ((rval = qlc_fm_check_acc_handle(ha,
		    ha->mbar_dev_handle)) != DDI_FM_OK) {
			qlc_fm_report_err_impact(ha,
			    QL_FM_EREPORT_ACC_HANDLE_CHECK);
			EL(ha, "fm_check_acc_handle mbar_dev_handle "
			    "status=%xh\n", rval);
			return (QL_FUNCTION_FAILED);
		}
		return (QL_SUCCESS);
	}
	return (QL_FUNCTION_FAILED);
}

/*
 * ql_get_cap_ofst
 *	Locates PCI configuration space capability pointer
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cap_id:	Capability ID.
 *
 * Returns:
 *	capability offset
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_cap_ofst(ql_adapter_state_t *ha, uint8_t cap_id)
{
	int	cptr = PCI_CAP_NEXT_PTR_NULL;

	QL_PRINT_3(ha, "started\n");

	if (ql_pci_config_get16(ha, PCI_CONF_STAT) & PCI_STAT_CAP) {
		cptr = ql_pci_config_get8(ha, PCI_CONF_CAP_PTR);

		while (cptr != PCI_CAP_NEXT_PTR_NULL) {
			if (ql_pci_config_get8(ha, cptr) == cap_id) {
				break;
			}
			cptr = ql_pci_config_get8(ha, cptr + PCI_CAP_NEXT_PTR);
		}
	}

	QL_PRINT_3(ha, "done\n");
	return (cptr);
}

/*
 * ql_map_mem_bar
 *	Map Mem BAR
 *
 * Input:
 *	ha:		 adapter state pointer.
 *	handlep:	access handle pointer.
 *	addrp:		address structure pointer.
 *	ofst:		BAR offset.
 *	len:		address space length.
 *
 * Returns:
 *	DDI_SUCCESS or DDI_FAILURE.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_map_mem_bar(ql_adapter_state_t *ha, ddi_acc_handle_t *handlep,
    caddr_t *addrp, uint32_t ofst, uint32_t len)
{
	caddr_t		nreg;
	pci_regspec_t	*reg, *reg2;
	int		rval;
	uint_t		rlen;
	uint32_t	rcnt, w32, nreg_size;

	QL_PRINT_10(ha, "started\n");

	/* Check for Mem BAR */
	w32 = ql_pci_config_get32(ha, ofst);
	if (w32 == 0) {
		EL(ha, "no Mem BAR %xh\n", ofst);
		return (DDI_FAILURE);
	}

	/*LINTED [Solaris DDI_DEV_T_ANY Lint error]*/
	if ((rval = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ha->dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&reg, &rlen)) !=
	    DDI_PROP_SUCCESS) {
		EL(ha, "ddi_prop_lookup_int_array status=%xh\n", rval);
		return (DDI_FAILURE);
	}
	rlen = (uint_t)(rlen * sizeof (int));	/* in bytes */
	rcnt = (uint32_t)(rlen / sizeof (pci_regspec_t));

	/* Check if register already added. */
	reg2 = reg;
	for (w32 = 0; w32 < rcnt; w32++) {
		if ((reg2->pci_phys_hi & PCI_REG_REG_M) == ofst) {
			EL(ha, "already mapped\n");
			break;
		}
		reg2++;
	}
	if (w32 == rcnt) {
		/*
		 * Allocate memory for the existing reg(s) plus one and then
		 * build it.
		 */
		nreg_size = (uint32_t)(rlen + sizeof (pci_regspec_t));
		nreg = kmem_zalloc(nreg_size, KM_SLEEP);

		/*
		 * Find a current map memory reg to copy.
		 */
		reg2 = reg;
		while ((reg2->pci_phys_hi & PCI_REG_ADDR_M) !=
		    PCI_ADDR_MEM32 && (reg2->pci_phys_hi & PCI_REG_ADDR_M) !=
		    PCI_ADDR_MEM64) {
			reg2++;
			if ((caddr_t)reg2 >= (caddr_t)reg + rlen) {
				reg2 = reg;
				break;
			}
		}
		w32 = (reg2->pci_phys_hi & ~PCI_REG_REG_M) | ofst;

		bcopy(reg, nreg, rlen);
		reg2 = (pci_regspec_t *)(nreg + rlen);

		reg2->pci_phys_hi = w32;
		reg2->pci_phys_mid = 0;
		reg2->pci_phys_low = 0;
		reg2->pci_size_hi = 0;
		reg2->pci_size_low = len;

		/*
		 * Write out the new "reg" property
		 */
		/*LINTED [Solaris DDI_DEV_T_NONE Lint error]*/
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, ha->dip,
		    "reg", (int *)nreg, (uint_t)(nreg_size / sizeof (int)));

		w32 = (uint_t)(nreg_size / sizeof (pci_regspec_t) - 1);
		kmem_free((caddr_t)nreg, nreg_size);
	}

	ddi_prop_free(reg);

	/* Map register */
	rval = ddi_regs_map_setup(ha->dip, w32, addrp, 0, len,
	    &ql_dev_acc_attr, handlep);
	if (rval != DDI_SUCCESS || *addrp == NULL || *handlep == NULL) {
		EL(ha, "regs_map status=%xh, base=%xh, handle=%xh\n",
		    rval, *addrp, *handlep);
		if (*handlep != NULL) {
			ddi_regs_map_free(handlep);
			*handlep = NULL;
		}
	}

	QL_PRINT_10(ha, "done\n");

	return (rval);
}

/*
 * ql_intr_lock
 *	Acquires all interrupt locks.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
void
ql_intr_lock(ql_adapter_state_t *ha)
{
	uint16_t	cnt;

	QL_PRINT_3(ha, "started\n");

	if (ha->rsp_queues != NULL) {
		for (cnt = 0; cnt < ha->rsp_queues_cnt; cnt++) {
			if (ha->rsp_queues[cnt] != NULL) {
				INDX_INTR_LOCK(ha, cnt);
			}
		}
	}
	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_intr_unlock
 *	Releases all interrupt locks.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Context:
 *	Kernel/Interrupt context.
 */
void
ql_intr_unlock(ql_adapter_state_t *ha)
{
	uint16_t	cnt;

	QL_PRINT_3(ha, "started\n");

	if (ha->rsp_queues != NULL) {
		for (cnt = 0; cnt < ha->rsp_queues_cnt; cnt++) {
			if (ha->rsp_queues[cnt] != NULL) {
				INDX_INTR_UNLOCK(ha, cnt);
			}
		}
	}
	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_completion_thread
 *	I/O completion thread.
 *
 * Input:
 *	arg:	port info pointer.
 *	COMP_Q_LOCK must be acquired prior to call.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_completion_thread(void *arg)
{
	ql_srb_t		*sp;
	ql_adapter_state_t	*ha = arg;

	QL_PRINT_3(ha, "started, hsp=%p\n", (void *)&sp);

	COMP_Q_LOCK(ha);
	ha->comp_thds_active++;
	ha->comp_thds_awake++;
	while (!(ha->flags & COMP_THD_TERMINATE)) {
		/* process completion queue items */
		while (ha->comp_q.first != NULL) {
			sp = (ha->comp_q.first)->base_address;
			/* Remove command from completion queue */
			ql_remove_link(&ha->comp_q, &sp->cmd);
			COMP_Q_UNLOCK(ha);
			QL_PRINT_3(ha, "pkt_comp, sp=%p, pkt_state=%xh, "
			    "hsp=%p\n", (void*)sp, sp->pkt->pkt_state,
			    (void *)&sp);
			(sp->pkt->pkt_comp)(sp->pkt);
			COMP_Q_LOCK(ha);
		}
		ha->comp_thds_awake--;
		QL_PRINT_3(ha, "sleep, hsp=%p\n", (void *)&sp);
		cv_wait(&ha->cv_comp_thread, &ha->comp_q_mutex);
		QL_PRINT_3(ha, "awoke, hsp=%p\n", (void *)&sp);
	}
	ha->comp_thds_awake--;
	ha->comp_thds_active--;
	COMP_Q_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_io_comp
 *	Transport I/O completion
 *
 * Input:
 *	sp:	SRB structure pointer
 *
 * Context:
 *	Kernel context.
 */
void
ql_io_comp(ql_srb_t *sp)
{
	ql_adapter_state_t	*ha = sp->ha->pha;

	QL_PRINT_3(ha, "started, sp=%ph, d_id=%xh\n", (void*)sp,
	    sp->pkt->pkt_cmd_fhdr.d_id);

	if (sp->pkt->pkt_comp && !ddi_in_panic()) {
		QL_PRINT_3(ha, "added to comp_q\n");
		COMP_Q_LOCK(ha);
		ql_add_link_b(&ha->comp_q, &sp->cmd);
		if (ha->comp_thds_awake < ha->comp_thds_active) {
			ha->comp_thds_awake++;
			QL_PRINT_3(ha, "signal\n");
			cv_signal(&ha->cv_comp_thread);
		}
		COMP_Q_UNLOCK(ha);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_process_comp_queue
 *	Process completion queue entries.
 *
 * Input:
 *	arg:	adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_process_comp_queue(void *arg)
{
	ql_srb_t		*sp;
	ql_adapter_state_t	*ha = arg;

	QL_PRINT_3(ha, "started\n");

	COMP_Q_LOCK(ha);

	/* process completion queue items */
	while (ha->comp_q.first != NULL) {
		sp = (ha->comp_q.first)->base_address;
		QL_PRINT_3(ha, "sending comp=0x%p\n", (void *)sp);
		/* Remove command from completion queue */
		ql_remove_link(&ha->comp_q, &sp->cmd);
		COMP_Q_UNLOCK(ha);
		(sp->pkt->pkt_comp)(sp->pkt);
		COMP_Q_LOCK(ha);
	}

	COMP_Q_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_abort_io
 *	Abort I/O.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	sp:	SRB pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_abort_io(ql_adapter_state_t *vha, ql_srb_t *sp)
{
	ql_link_t		*link;
	ql_srb_t		*sp2;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	int			rval = QL_FUNCTION_FAILED;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_10(ha, "started, sp=%ph, handle=%xh\n", (void *)sp,
	    sp->handle);

	if ((lq = sp->lun_queue) != NULL) {
		tq = lq->target_queue;
	} else {
		tq = NULL;
	}

	/* Acquire target queue lock. */
	if (tq) {
		DEVICE_QUEUE_LOCK(tq);
	}
	REQUEST_RING_LOCK(ha);

	/* If command not already started. */
	if (!(sp->flags & SRB_ISP_STARTED)) {
		rval = QL_FUNCTION_PARAMETER_ERROR;

		/* Check pending queue for command. */
		for (link = ha->pending_cmds.first; link != NULL;
		    link = link->next) {
			sp2 = link->base_address;
			if (sp2 == sp) {
				rval = QL_SUCCESS;
				/* Remove srb from pending command queue */
				ql_remove_link(&ha->pending_cmds, &sp->cmd);
				break;
			}
		}

		if (link == NULL && lq) {
			/* Check for cmd on device queue. */
			for (link = lq->cmd.first; link != NULL;
			    link = link->next) {
				sp2 = link->base_address;
				if (sp2 == sp) {
					rval = QL_SUCCESS;
					/* Remove srb from device queue. */
					ql_remove_link(&lq->cmd, &sp->cmd);
					sp->flags &= ~SRB_IN_DEVICE_QUEUE;
					break;
				}
			}
		}
	}

	REQUEST_RING_UNLOCK(ha);
	if (tq) {
		DEVICE_QUEUE_UNLOCK(tq);
	}

	if (sp->flags & SRB_ISP_COMPLETED || rval == QL_SUCCESS) {
		rval = QL_SUCCESS;
	} else {
		uint32_t	index;

		INTR_LOCK(ha);
		sp->flags |= SRB_ABORTING;
		if (sp->handle != 0) {
			index = sp->handle & OSC_INDEX_MASK;
			if (ha->outstanding_cmds[index] == sp) {
				ha->outstanding_cmds[index] =
				    QL_ABORTED_SRB(ha);
			}
			/* Decrement outstanding commands on device. */
			if (tq != NULL && tq->outcnt != 0) {
				tq->outcnt--;
			}
			if (lq != NULL && sp->flags & SRB_FCP_CMD_PKT &&
			    lq->lun_outcnt != 0) {
				lq->lun_outcnt--;
			}
			/* Remove command from watchdog queue. */
			if (sp->flags & SRB_WATCHDOG_ENABLED) {
				if (tq != NULL) {
					ql_remove_link(&tq->wdg, &sp->wdg);
				}
				sp->flags &= ~SRB_WATCHDOG_ENABLED;
			}
			INTR_UNLOCK(ha);
			(void) ql_abort_command(ha, sp);
			sp->handle = 0;
		} else {
			INTR_UNLOCK(ha);
		}
		rval = QL_SUCCESS;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "sp=%p not aborted=%xh\n", (void *)sp, rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 *  ql_idc
 *	Inter driver communication thread.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
ql_idc(ql_adapter_state_t *ha)
{
	int		rval;
	uint32_t	timer = 300;

	QL_PRINT_10(ha, "started\n");

	for (;;) {
		/* IDC Stall needed. */
		if (ha->flags & IDC_STALL_NEEDED) {
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~IDC_STALL_NEEDED;
			ADAPTER_STATE_UNLOCK(ha);
			TASK_DAEMON_LOCK(ha);
			ha->task_daemon_flags |= DRIVER_STALL;
			TASK_DAEMON_UNLOCK(ha);
			if (LOOP_READY(ha)) {
				if ((ha->idc_mb[1] & IDC_TIMEOUT_MASK) <
				    IDC_TIMEOUT_MASK) {
					ha->idc_mb[1] = (uint16_t)
					    (ha->idc_mb[1] | IDC_TIMEOUT_MASK);
					rval = ql_idc_time_extend(ha);
					if (rval != QL_SUCCESS) {
						EL(ha, "idc_time_extend status"
						    "=%xh\n", rval);
					}
				}
				(void) ql_wait_outstanding(ha);
			}
		}

		/* IDC ACK needed. */
		if (ha->flags & IDC_ACK_NEEDED) {
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~IDC_ACK_NEEDED;
			ADAPTER_STATE_UNLOCK(ha);
			rval = ql_idc_ack(ha);
			if (rval != QL_SUCCESS) {
				EL(ha, "idc_ack status=%xh\n", rval);
				ADAPTER_STATE_LOCK(ha);
				ha->flags |= IDC_RESTART_NEEDED;
				ADAPTER_STATE_UNLOCK(ha);
			}
		}

		/* IDC Restart needed. */
		if (timer-- == 0 || ha->flags & ADAPTER_SUSPENDED ||
		    (ha->flags & IDC_RESTART_NEEDED &&
		    !(ha->flags & LOOPBACK_ACTIVE))) {
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~(IDC_RESTART_NEEDED | IDC_STALL_NEEDED |
			    IDC_ACK_NEEDED);
			ADAPTER_STATE_UNLOCK(ha);
			TASK_DAEMON_LOCK(ha);
			ha->task_daemon_flags &= ~DRIVER_STALL;
			TASK_DAEMON_UNLOCK(ha);
			if (LOOP_READY(ha)) {
				ql_restart_queues(ha);
			}
			break;
		}
		delay(10);
	}

	QL_PRINT_10(ha, "done\n");
}

/*
 * ql_get_lun_addr
 *	get the lunslun address.
 *
 * Input:
 *	tq:	target queue pointer.
 *	lun:	the lun number.
 *
 * Returns:
 *	the lun address.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
uint64_t
ql_get_lun_addr(ql_tgt_t *tq, uint16_t lun)
{
	ql_lun_t		*lq;
	ql_link_t		*link = NULL;
	uint64_t		lun_addr = 0;
	fcp_ent_addr_t		*fcp_ent_addr = (fcp_ent_addr_t *)&lun_addr;

	/* If the lun queue exists */
	if (tq) {
		for (link = tq->lun_queues.first; link != NULL;
		    link = link->next) {
			lq = link->base_address;
			if (lq->lun_no == lun) {
				break;
			}
		}
	}
	if (link == NULL) {
		/* create an fcp_ent_addr from the lun number */
		if (MSB(lun)) {
			fcp_ent_addr->ent_addr_0 = CHAR_TO_SHORT(lobyte(lun),
			    (hibyte(lun) | QL_LUN_AM_FLAT));
		} else {
			fcp_ent_addr->ent_addr_0 = CHAR_TO_SHORT(lobyte(lun),
			    hibyte(lun));
		}
	} else {
		lun_addr = lq->lun_addr;
	}

	return (lun_addr);
}


/*
 * ql_83xx_binary_fw_dump
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
ql_83xx_binary_fw_dump(ql_adapter_state_t *ha, ql_83xx_fw_dump_t *fw)
{
	uint32_t	*reg32, cnt, *w32ptr, index, *dp;
	void		*bp;
	clock_t		timer;
	int		rv, rval = QL_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	fw->req_q_size[0] = ha->req_q[0]->req_ring.size;
	if (ha->req_q[1] != NULL) {
		fw->req_q_size[1] = ha->req_q[1]->req_ring.size;
	}
	fw->rsp_q_size = ha->rsp_queues[0]->rsp_ring.size * ha->rsp_queues_cnt;

	fw->hccr = RD32_IO_REG(ha, hccr);
	fw->r2h_status = RD32_IO_REG(ha, risc2host);
	fw->aer_ues = ql_pci_config_get32(ha, 0x104);

	/* Disable ISP interrupts. */
	ql_disable_intr(ha);

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
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

	WRT32_IO_REG(ha, io_base_addr, 0x6000);
	WRT_REG_DWORD(ha, ha->iobase + 0xc0, 0);
	WRT_REG_DWORD(ha, ha->iobase + 0xcc, 0);

	WRT32_IO_REG(ha, io_base_addr, 0x6010);
	WRT_REG_DWORD(ha, ha->iobase + 0xd4, 0);

	WRT32_IO_REG(ha, io_base_addr, 0x0F70);
	WRT_REG_DWORD(ha, ha->iobase + 0xf0, 0x60000000);

	/* Host Interface registers */

	/* HostRisc registers. */
	WRT32_IO_REG(ha, io_base_addr, 0x7000);
	bp = ql_read_regs(ha, fw->hostrisc_reg, ha->iobase + 0xC0,
	    16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x7010);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x7040);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

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
	WRT32_IO_REG(ha, io_base_addr, 0xBE00);
	bp = ql_read_regs(ha, fw->xseq_gp_reg, ha->iobase + 0xC0,
	    16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE10);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE20);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE30);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE40);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE50);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE60);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBE70);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBF00);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
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
	bp = ql_read_regs(ha, fw->xseq_0_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBFD0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xBFE0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* XSEQ-1 */
	WRT32_IO_REG(ha, io_base_addr, 0xBFF0);
	(void) ql_read_regs(ha, fw->xseq_1_reg, ha->iobase + 0xC0,
	    16, 32);

	/* XSEQ-2 */
	WRT32_IO_REG(ha, io_base_addr, 0xBEF0);
	(void) ql_read_regs(ha, fw->xseq_2_reg, ha->iobase + 0xC0,
	    16, 32);

	/* Receive sequence registers. */

	/* RSEQ GP */
	WRT32_IO_REG(ha, io_base_addr, 0xFE00);
	bp = ql_read_regs(ha, fw->rseq_gp_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE10);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE20);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE30);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE40);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE50);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE60);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFE70);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xFF00);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
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

	/* RSEQ-3 */
	WRT32_IO_REG(ha, io_base_addr, 0xFEF0);
	(void) ql_read_regs(ha, fw->rseq_3_reg, ha->iobase + 0xC0,
	    sizeof (fw->rseq_3_reg) / 4, 32);

	/* Auxiliary sequencer registers. */

	/* ASEQ GP */
	WRT32_IO_REG(ha, io_base_addr, 0xB000);
	bp = ql_read_regs(ha, fw->aseq_gp_reg, ha->iobase + 0xC0, 16, 32);
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
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB100);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB110);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB120);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB130);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB140);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB150);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB160);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0xB170);
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

	/* ASEQ-3 */
	WRT32_IO_REG(ha, io_base_addr, 0xB1F0);
	(void) ql_read_regs(ha, fw->aseq_3_reg, ha->iobase + 0xC0,
	    16, 32);

	/* Command DMA registers. */

	WRT32_IO_REG(ha, io_base_addr, 0x7100);
	bp = ql_read_regs(ha, fw->cmd_dma_reg, ha->iobase + 0xC0,
	    16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x7120);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x7130);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x71f0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

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
	bp = ql_read_regs(ha, fw->risc_gp_reg, ha->iobase + 0xC0, 16, 32);
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
	bp = ql_read_regs(ha, fw->lmc_reg, ha->iobase + 0xC0, 16, 32);
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
	bp = ql_read_regs(ha, fw->fpm_hdw_reg, ha->iobase + 0xC0, 16, 32);
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
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x40E0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x40F0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* Pointer arrays registers */

	/* RQ0 Array registers. */
	WRT32_IO_REG(ha, io_base_addr, 0x5C00);
	bp = ql_read_regs(ha, fw->rq0_array_reg, ha->iobase + 0xC0,
	    16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C10);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C20);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C30);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C40);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C50);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C60);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C70);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C80);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5C90);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5CA0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5CB0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5CC0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5CD0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5CE0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5CF0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* RQ1 Array registers. */
	WRT32_IO_REG(ha, io_base_addr, 0x5D00);
	bp = ql_read_regs(ha, fw->rq1_array_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D10);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D20);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D30);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D40);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D50);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D60);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D70);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D80);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5D90);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5DA0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5DB0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5DC0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5DD0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5DE0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5DF0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* RP0 Array registers. */
	WRT32_IO_REG(ha, io_base_addr, 0x5E00);
	bp = ql_read_regs(ha, fw->rp0_array_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E10);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E20);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E30);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E40);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E50);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E60);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E70);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E80);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5E90);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5EA0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5EB0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5EC0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5ED0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5EE0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5EF0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* RP1 Array registers. */
	WRT32_IO_REG(ha, io_base_addr, 0x5F00);
	bp = ql_read_regs(ha, fw->rp1_array_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F10);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F20);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F30);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F40);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F50);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F60);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F70);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F80);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5F90);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5FA0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5FB0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5FC0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5FD0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5FE0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x5FF0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* AT0 Array Registers */
	WRT32_IO_REG(ha, io_base_addr, 0x7080);
	bp = ql_read_regs(ha, fw->ato_array_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x7090);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x70A0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x70B0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x70C0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x70D0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x70E0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x70F0);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* I/O queue control registers */

	/* Queue Control Registers. */
	WRT32_IO_REG(ha, io_base_addr, 0x7800);
	(void) ql_read_regs(ha, fw->queue_control_reg, ha->iobase + 0xC0,
	    16, 32);

	/* Frame Buffer registers. */

	/* FB hardware */
	WRT32_IO_REG(ha, io_base_addr, 0x6000);
	bp = ql_read_regs(ha, fw->fb_hdw_reg, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6010);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6020);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6030);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6040);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6060);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6070);
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
	WRT32_IO_REG(ha, io_base_addr, 0x6530);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6540);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6550);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6560);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6570);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6580);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6590);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x65A0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x65B0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x65C0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x65D0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x65E0);
	bp = ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);
	WRT32_IO_REG(ha, io_base_addr, 0x6F00);
	(void) ql_read_regs(ha, bp, ha->iobase + 0xC0, 16, 32);

	/* Get the Queue Pointers */
	dp = fw->req_rsp_ext_mem;
	for (index = 0; index < ha->rsp_queues_cnt; index++) {
		if (index == 0) {
			*dp = RD32_MBAR_REG(ha, ha->req_q[0]->mbar_req_in);
			LITTLE_ENDIAN_32(dp);
			dp++;
			*dp = RD32_MBAR_REG(ha, ha->req_q[0]->mbar_req_out);
			LITTLE_ENDIAN_32(dp);
			dp++;
		} else if (index == 1) {
			*dp = RD32_MBAR_REG(ha, ha->req_q[1]->mbar_req_in);
			LITTLE_ENDIAN_32(dp);
			dp++;
			*dp = RD32_MBAR_REG(ha, ha->req_q[1]->mbar_req_out);
			LITTLE_ENDIAN_32(dp);
			dp++;
		} else {
			*dp++ = 0;
			*dp++ = 0;
		}
		*dp = RD32_MBAR_REG(ha, ha->rsp_queues[index]->mbar_rsp_in);
		LITTLE_ENDIAN_32(dp);
		dp++;
		*dp = RD32_MBAR_REG(ha, ha->rsp_queues[index]->mbar_rsp_out);
		LITTLE_ENDIAN_32(dp);
		dp++;
	}

	/* Get the request queue */
	(void) ddi_dma_sync(ha->req_q[0]->req_ring.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORCPU);
	w32ptr = (uint32_t *)ha->req_q[0]->req_ring.bp;
	for (cnt = 0; cnt < fw->req_q_size[0] / 4; cnt++) {
		*dp = *w32ptr++;
		LITTLE_ENDIAN_32(dp);
		dp++;
	}
	if (ha->req_q[1] != NULL) {
		(void) ddi_dma_sync(ha->req_q[1]->req_ring.dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		w32ptr = (uint32_t *)ha->req_q[1]->req_ring.bp;
		for (cnt = 0; cnt < fw->req_q_size[1] / 4; cnt++) {
			*dp = *w32ptr++;
			LITTLE_ENDIAN_32(dp);
			dp++;
		}
	}

	/* Get the response queues */
	for (index = 0; index < ha->rsp_queues_cnt; index++) {
		(void) ddi_dma_sync(ha->rsp_queues[index]->rsp_ring.dma_handle,
		    0, 0, DDI_DMA_SYNC_FORCPU);
		w32ptr = (uint32_t *)ha->rsp_queues[index]->rsp_ring.bp;
		for (cnt = 0; cnt < ha->rsp_queues[index]->rsp_ring.size / 4;
		    cnt++) {
			*dp = *w32ptr++;
			LITTLE_ENDIAN_32(dp);
			dp++;
		}
	}

	/* Reset RISC. */
	ql_reset_chip(ha);

	/* Code RAM. */
	rv = ql_read_risc_ram(ha, 0x20000, sizeof (fw->code_ram) / 4,
	    fw->code_ram);
	if (rval == QL_SUCCESS) {
		rval = rv;
	}
	rv = ql_read_risc_ram(ha, 0x100000,
	    ha->fw_ext_memory_size / 4, dp);
	if (rval == QL_SUCCESS) {
		rval = rv;
	}

	/* Get the extended trace buffer */
	if (ha->fwexttracebuf.dma_handle != NULL) {
		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->fwexttracebuf.dma_handle, 0,
		    FWEXTSIZE, DDI_DMA_SYNC_FORCPU);

		w32ptr = ha->fwexttracebuf.bp;
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			fw->ext_trace_buf[cnt] = *w32ptr++;
		}
	}

	/* Get the FC event trace buffer */
	if (ha->fwfcetracebuf.dma_handle != NULL) {
		/* Sync DMA buffer. */
		(void) ddi_dma_sync(ha->fwfcetracebuf.dma_handle, 0,
		    FWFCESIZE, DDI_DMA_SYNC_FORCPU);

		w32ptr = ha->fwfcetracebuf.bp;
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			fw->fce_trace_buf[cnt] = *w32ptr++;
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (QL_SUCCESS);
}

/*
 * ql_83xx_ascii_fw_dump
 *	Converts ISP83xx firmware binary dump to ascii.
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
ql_83xx_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t		cnt, cnt1, len, *dp, *dp2;
	caddr_t			bp = bufp;
	ql_83xx_fw_dump_t	*fw = ha->ql_dump_ptr;

	QL_PRINT_3(ha, "started\n");

	if ((len = ha->risc_dump_size) == 0) {
		QL_PRINT_10(ha, "no buffer\n");
		return (0);
	}
	(void) snprintf(bp, len, "\nISP FW Version %d.%02d.%02d Attributes "
	    "%X\n", ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}

	(void) snprintf(bp, len, "\nHCCR Register\n%08x\n", fw->hccr);
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}

	(void) snprintf(bp, len, "\nR2H Status Register\n%08x\n",
	    fw->r2h_status);
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}

	(void) snprintf(bp, len,
	    "\nAER Uncorrectable Error Status Register\n%08x\n", fw->aer_ues);
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}

	(void) snprintf(bp, len, "\nHostRisc Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->hostrisc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->hostrisc_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nPCIe Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->pcie_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->pcie_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	dp = fw->req_rsp_ext_mem;
	for (cnt = 0; cnt < ha->rsp_queues_cnt; cnt++) {
		(void) snprintf(bp, len, "\n\nQueue Pointers #%d:\n", cnt);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
		for (cnt1 = 0; cnt1 < 4; cnt1++) {
			(void) snprintf(bp, len, "%08x ", *dp++);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
	}

	(void) snprintf(bp, len, "\n\nHost Interface Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->host_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->host_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nShadow Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->shadow_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->shadow_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRISC IO Register\n%08x", fw->risc_io);
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}

	(void) snprintf(bp, len, "\n\nMailbox Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->mailbox_reg) / 2; cnt++) {
		if (cnt % 16 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%04x ", fw->mailbox_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXSEQ GP Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xseq_gp_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXSEQ-0 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xseq_0_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXSEQ-1 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xseq_1_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXSEQ-2 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xseq_2_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRSEQ GP Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rseq_gp_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRSEQ-0 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rseq_0_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRSEQ-1 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rseq_1_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRSEQ-2 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rseq_2_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRSEQ-3 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rseq_3_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rseq_3_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nASEQ GP Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->aseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->aseq_gp_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nASEQ-0 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->aseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->aseq_0_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nASEQ-1 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->aseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->aseq_1_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nASEQ-2 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->aseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->aseq_2_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nASEQ-3 Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->aseq_3_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->aseq_3_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nCommand DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->cmd_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->cmd_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRequest0 Queue DMA Channel Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->req0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->req0_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nResponse0 Queue DMA Channel Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->resp0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->resp0_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRequest1 Queue DMA Channel Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->req1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->req1_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXMT0 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xmt0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xmt0_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXMT1 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xmt1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xmt1_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXMT2 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xmt2_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xmt2_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXMT3 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xmt3_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xmt3_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXMT4 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xmt4_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xmt4_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nXMT Data DMA Common Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->xmt_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->xmt_data_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRCV Thread 0 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rcvt0_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rcvt0_data_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRCV Thread 1 Data DMA Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->rcvt1_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rcvt1_data_dma_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRISC GP Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->risc_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->risc_gp_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nLMC Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->lmc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->lmc_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nFPM Hardware Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->fpm_hdw_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->fpm_hdw_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRQ0 Array Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->rq0_array_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rq0_array_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRQ1 Array Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->rq1_array_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rq1_array_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRP0 Array Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->rp0_array_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rp0_array_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nRP1 Array Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->rp1_array_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->rp1_array_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nAT0 Array Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->ato_array_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->ato_array_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nQueue Control Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->queue_control_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->queue_control_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nFB Hardware Registers");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	cnt1 = (uint32_t)(sizeof (fw->fb_hdw_reg));
	for (cnt = 0; cnt < cnt1 / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->fb_hdw_reg[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nCode RAM");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	for (cnt = 0; cnt < sizeof (fw->code_ram) / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n%08x: ", cnt + 0x20000);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", fw->code_ram[cnt]);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\nExternal Memory");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}
	dp = (uint32_t *)((caddr_t)fw->req_rsp_ext_mem + fw->req_q_size[0] +
	    fw->req_q_size[1] + fw->rsp_q_size + (ha->rsp_queues_cnt * 16));
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			(void) snprintf(bp, len, "\n%08x: ", cnt + 0x100000);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
		(void) snprintf(bp, len, "%08x ", *dp++);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
	}

	(void) snprintf(bp, len, "\n\n[<==END] ISP Debug Dump");
	if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
		return (strlen(bufp));
	}

	dp = fw->req_rsp_ext_mem + (ha->rsp_queues_cnt * 4);
	for (cnt = 0; cnt < 2 && fw->req_q_size[cnt]; cnt++) {
		dp2 = dp;
		for (cnt1 = 0; cnt1 < fw->req_q_size[cnt] / 4; cnt1++) {
			if (*dp2++) {
				break;
			}
		}
		if (cnt1 == fw->req_q_size[cnt] / 4) {
			dp = dp2;
			continue;
		}
		(void) snprintf(bp, len, "\n\nRequest Queue\nQueue %d:", cnt);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
		for (cnt1 = 0; cnt1 < fw->req_q_size[cnt] / 4; cnt1++) {
			if (cnt1 % 8 == 0) {
				(void) snprintf(bp, len, "\n%08x: ", cnt1);
				if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
					return (strlen(bufp));
				}
			}
			(void) snprintf(bp, len, "%08x ", *dp++);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
	}

	for (cnt = 0; cnt < ha->rsp_queues_cnt; cnt++) {
		dp2 = dp;
		for (cnt1 = 0; cnt1 < ha->rsp_queues[cnt]->rsp_ring.size / 4;
		    cnt1++) {
			if (*dp2++) {
				break;
			}
		}
		if (cnt1 == ha->rsp_queues[cnt]->rsp_ring.size / 4) {
			dp = dp2;
			continue;
		}
		(void) snprintf(bp, len, "\n\nResponse Queue\nQueue %d:", cnt);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
		for (cnt1 = 0; cnt1 < ha->rsp_queues[cnt]->rsp_ring.size / 4;
		    cnt1++) {
			if (cnt1 % 8 == 0) {
				(void) snprintf(bp, len, "\n%08x: ", cnt1);
				if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
					return (strlen(bufp));
				}
			}
			(void) snprintf(bp, len, "%08x ", *dp++);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
	}

	if (ha->fwexttracebuf.dma_handle != NULL) {
		uint32_t	cnt_b;
		uint64_t	w64 = (uintptr_t)ha->fwexttracebuf.bp;

		(void) snprintf(bp, len, "\n\nExtended Trace Buffer Memory");
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				(void) snprintf(bp, len, "\n%08x: ",
				    (int)(w64 + cnt_b));
				if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
					return (strlen(bufp));
				}
			}
			(void) snprintf(bp, len, "%08x ",
			    fw->ext_trace_buf[cnt]);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
	}

	if (ha->fwfcetracebuf.dma_handle != NULL) {
		uint32_t	cnt_b;
		uint64_t	w64 = (uintptr_t)ha->fwfcetracebuf.bp;

		(void) snprintf(bp, len, "\n\nFC Event Trace Buffer Memory");
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				(void) snprintf(bp, len, "\n%08x: ",
				    (int)(w64 + cnt_b));
				if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
					return (strlen(bufp));
				}
			}
			(void) snprintf(bp, len, "%08x ",
			    fw->fce_trace_buf[cnt]);
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
	}

	QL_PRINT_10(ha, "done=%xh\n", strlen(bufp));

	return (strlen(bufp));
}


/*
 * ql_str_ptr
 *	Verifies buffer is not full
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	string buffer pointer
 *	len:	buffer length
 *
 * Returns:
 *	NULL = buffer full else adjusted buffer pointer
 *
 * Context:
 *	Kernel context.
 */
/*ARGSUSED*/
static caddr_t
ql_str_ptr(ql_adapter_state_t *ha, caddr_t bp, uint32_t *len)
{
	uint32_t	i;

	i = strlen(bp);
	if (i > *len || !(*len -= i)) {
		QL_PRINT_10(ha, "full buffer\n");
		return (NULL);
	}
	return (bp += i);
}

/*
 * ql_27xx_binary_fw_dump
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dmp:	firmware dump pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_27xx_binary_fw_dump(ql_adapter_state_t *ha)
{
	ql_dmp_template_t	*template_buff;
	int			rval;
	uint32_t		cnt, *dp, *bp, tsize;

	QL_PRINT_10(ha, "started\n");

	if (ha->dmp_template.dma_handle == NULL) {
		rval = CFG_IST(ha, CFG_LOAD_FLASH_FW) ?
		    ql_2700_get_flash_dmp_template(ha) :
		    ql_2700_get_module_dmp_template(ha);
		if (rval != QL_SUCCESS) {
			EL(ha, "no dump template, status=%xh\n", rval);
			return (QL_FUNCTION_PARAMETER_ERROR);
		}
	}
	template_buff = ha->dmp_template.bp;
	tsize = template_buff->hdr.size_of_template;

	if (ha->md_capture_size == 0) {
		ha->ql_dump_ptr = kmem_zalloc(tsize, KM_NOSLEEP);
		if (ha->ql_dump_ptr == NULL) {
			QL_PRINT_10(ha, "done, failed alloc\n");
			return (QL_MEMORY_ALLOC_FAILED);
		}
		cnt = (uint32_t)(tsize / sizeof (uint32_t));
		dp = (uint32_t *)ha->ql_dump_ptr;
		bp = (uint32_t *)&template_buff->hdr;
		while (cnt--) {
			*dp++ = ddi_get32(ha->dmp_template.acc_handle, bp++);
		}
		ha->md_capture_size = ql_2700_dmp_parse_template(ha,
		    (ql_dt_hdr_t *)ha->ql_dump_ptr, NULL, 0);
		kmem_free(ha->ql_dump_ptr, tsize);
		ha->ql_dump_ptr = NULL;

		if (ha->md_capture_size == 0) {
			return (QL_MEMORY_ALLOC_FAILED);
		}

		/*
		 * Determine ascii dump file size
		 * 2 ascii bytes per binary byte + a space and
		 * a newline every 16 binary bytes
		 */
		ha->risc_dump_size = ha->md_capture_size << 1;
		ha->risc_dump_size += ha->md_capture_size;
		ha->risc_dump_size += ha->md_capture_size / 16 + 1;
		QL_PRINT_10(ha, "md_capture_size=%xh, "
		    "risc_dump_size=%xh\n", ha->md_capture_size,
		    ha->risc_dump_size);
	}

	ha->ql_dump_ptr = kmem_zalloc(ha->md_capture_size, KM_NOSLEEP);
	if (ha->ql_dump_ptr == NULL) {
		QL_PRINT_10(ha, "done, failed alloc\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}
	ha->ql_dump_size = ha->md_capture_size;

	/* Disable ISP interrupts. */
	ql_disable_intr(ha);

	cnt = (uint32_t)(tsize / sizeof (uint32_t));
	dp = (uint32_t *)ha->ql_dump_ptr;
	bp = (uint32_t *)&template_buff->hdr;
	while (cnt--) {
		*dp++ = ddi_get32(ha->dmp_template.acc_handle, bp++);
	}

	(void) ql_2700_dmp_parse_template(ha,
	    (ql_dt_hdr_t *)ha->ql_dump_ptr,
	    (uint8_t *)dp, ha->ql_dump_size);

#ifdef _BIG_ENDIAN
	cnt = (uint32_t)(tsize / sizeof (uint32_t));
	dp = (uint32_t *)ha->ql_dump_ptr;
	while (cnt--) {
		ql_chg_endian((uint8_t *)dp, 4);
		dp++;
	}
#endif
	QL_PRINT_10(ha, "done\n");
	return (QL_SUCCESS);
}

/*
 * ql_27xx_ascii_fw_dump
 *	Converts ISP27xx firmware binary dump to ascii.
 *
 * Input:
 *	ha:	port info pointer.
 *	bptr:	buffer pointer.
 *
 * Returns:
 *	Amount of data buffer used.
 *
 * Context:
 *	Kernel context.
 */
static size_t
ql_27xx_ascii_fw_dump(ql_adapter_state_t *ha, caddr_t bufp)
{
	uint32_t	cnt, len, dsize;
	uint8_t		*fw;
	caddr_t		bp;

	QL_PRINT_10(ha, "started\n");

	if ((len = ha->risc_dump_size) == 0) {
		QL_PRINT_10(ha, "no buffer\n");
		return (0);
	}

	dsize = ha->ql_dump_size;
	fw = (uint8_t *)ha->ql_dump_ptr;
	bp = bufp;

	QL_PRINT_10(ha, "fw_dump_buffer=%ph, fw_bin_dump_size=%xh\n",
	    (void *)ha->ql_dump_ptr, ha->ql_dump_size);

	/*
	 * 2 ascii bytes per binary byte + a space and
	 * a newline every 16 binary bytes
	 */
	cnt = 0;
	while (cnt < dsize) {
		(void) snprintf(bp, len, "%02x ", *fw++);
		if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
			return (strlen(bufp));
		}
		if (++cnt % 16 == 0) {
			(void) snprintf(bp, len, "\n");
			if ((bp = ql_str_ptr(ha, bp, &len)) == NULL) {
				return (strlen(bufp));
			}
		}
	}
	if (cnt % 16 != 0) {
		(void) snprintf(bp, len, "\n");
		bp = ql_str_ptr(ha, bp, &len);
		if (bp == NULL) {
			return (strlen(bufp));
		}
	}

	QL_PRINT_10(ha, "done=%xh\n", strlen(bufp));

	return (strlen(bufp));
}

/* ******************************************************************* */
/* ********************* Dump Template Functions ********************* */
/* ******************************************************************* */

/*
 * ql_2700_get_module_dmp_template
 *	Get dump template from firmware module
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
ql_2700_get_module_dmp_template(ql_adapter_state_t *ha)
{
	int		rval;
	uint32_t	word_count, cnt, *bp, *dp;

	QL_PRINT_10(ha, "started\n");

	if (ha->dmp_template.dma_handle != NULL) {
		return (QL_SUCCESS);
	}

	if ((word_count = ha->risc_fw[2].length) == 0) {
		EL(ha, "no dump template, length=0\n");
		return (QL_FUNCTION_PARAMETER_ERROR);
	}

	/* Allocate template buffer. */
	ha->dmp_template.size = word_count << 2;
	ha->dmp_template.type = LITTLE_ENDIAN_DMA;
	ha->dmp_template.max_cookie_count = 1;
	ha->dmp_template.alignment = 8;
	rval = ql_alloc_phys(ha, &ha->dmp_template, KM_SLEEP);
	if (rval != QL_SUCCESS) {
		EL(ha, "unable to allocate template buffer, "
		    "status=%xh\n", rval);
		return (rval);
	}

	/* Get big endian template. */
	bp = ha->dmp_template.bp;
	dp = (uint32_t *)ha->risc_fw[2].code;
	for (cnt = 0; cnt < word_count; cnt++) {
		ddi_put32(ha->dmp_template.acc_handle, bp, *dp++);
		if (cnt > 6) {
			ql_chg_endian((uint8_t *)bp, 4);
		}
		bp++;
	}

	QL_PRINT_10(ha, "done\n");
	return (rval);
}

/*
 * ql_2700_get_flash_dmp_template
 *	Get dump template from flash
 *
 * Input:
 *	pi:	port info pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_2700_get_flash_dmp_template(ql_adapter_state_t *ha)
{
	int		rval;
	uint32_t	word_count, cnt, *bp;
	uint32_t	faddr = ha->flash_data_addr | ha->flash_fw_addr;
	uint32_t	fdata = 0;

	QL_PRINT_10(ha, "started, fw_addr=%xh\n", ha->flash_fw_addr);

	if (ha->dmp_template.dma_handle != NULL) {
		ql_free_phys(ha, &ha->dmp_template);
	}

	/* First array length */
	rval = ql_24xx_read_flash(ha, faddr + 3, &fdata);
	QL_PRINT_7(ha, "read_flash, fw_addr=0x%x, data=0x%x\n",
	    faddr + 3, fdata);
	if (rval != QL_SUCCESS) {
		EL(ha, "2700_read_flash status=%xh\n", rval);
		return (rval);
	}
	if (fdata == 0 || fdata == 0xffffffff) {
		EL(ha, "Invalid first array length = %xh\n", fdata);
		return (QL_FUNCTION_PARAMETER_ERROR);
	}
	ql_chg_endian((uint8_t *)&fdata, 4);
	QL_PRINT_7(ha, "First array length = %xh\n", fdata);
	faddr += fdata;

	/* Second array length */
	rval = ql_24xx_read_flash(ha, faddr + 3, &fdata);
	QL_PRINT_7(ha, "read_flash, fw_addr=0x%x, data=0x%x\n",
	    faddr + 3, fdata);
	if (rval != QL_SUCCESS) {
		EL(ha, "2700_read_flash status=%xh\n", rval);
		return (rval);
	}
	if (fdata == 0 || fdata == 0xffffffff) {
		EL(ha, "Invalid second array length = %xh\n", fdata);
		return (QL_FUNCTION_PARAMETER_ERROR);
	}
	ql_chg_endian((uint8_t *)&fdata, 4);
	QL_PRINT_7(ha, "Second array length = %xh\n", fdata);
	faddr += fdata;

	/* Third array length (dump template) */
	rval = ql_24xx_read_flash(ha, faddr + 2, &fdata);
	QL_PRINT_7(ha, "read_flash, fw_addr=0x%x, data=0x%x\n",
	    faddr + 2, fdata);
	if (rval != QL_SUCCESS) {
		EL(ha, "2700_read_flash status=%xh\n", rval);
		return (rval);
	}
	if (fdata == 0 || fdata == 0xffffffff) {
		EL(ha, "Invalid third array length = %xh\n", fdata);
		return (QL_FUNCTION_PARAMETER_ERROR);
	}
	ql_chg_endian((uint8_t *)&fdata, 4);
	QL_PRINT_7(ha, "Third array length = %xh\n", fdata);
	word_count = fdata;

	/* Allocate template buffer. */
	ha->dmp_template.size = word_count << 2;
	ha->dmp_template.type = LITTLE_ENDIAN_DMA;
	ha->dmp_template.max_cookie_count = 1;
	ha->dmp_template.alignment = 8;
	rval = ql_alloc_phys(ha, &ha->dmp_template, KM_SLEEP);
	if (rval != QL_SUCCESS) {
		EL(ha, "unable to allocate template buffer, "
		    "status=%xh\n", rval);
		return (rval);
	}

	/* Get big endian template. */
	bp = ha->dmp_template.bp;
	for (cnt = 0; cnt < word_count; cnt++) {
		rval = ql_24xx_read_flash(ha, faddr++, &fdata);
		if (rval != QL_SUCCESS) {
			EL(ha, "2700_read_flash status=%xh\n", rval);
			ql_free_phys(ha, &ha->dmp_template);
			return (rval);
		}
		ddi_put32(ha->dmp_template.acc_handle, bp, fdata);
		bp++;
	}

	QL_PRINT_10(ha, "done\n");
	return (rval);
}

static uint32_t
ql_2700_dmp_parse_template(ql_adapter_state_t *ha, ql_dt_hdr_t *template_hdr,
    uint8_t *dump_buff, uint32_t buff_size)
{
	int		e_cnt, esize, num_of_entries;
	uint32_t	bsize;
	time_t		time;
	uint8_t		*dbuff, *dbuff_end;
	ql_dt_entry_t	*entry;
	int		sane_end = 0;

	dbuff = dump_buff;	/* dbuff = NULL	size determination. */
	dbuff_end = dump_buff + buff_size;

	template_hdr->ver_attr[0] = ha->fw_major_version;
	template_hdr->ver_attr[1] = ha->fw_minor_version;
	template_hdr->ver_attr[2] = ha->fw_subminor_version;
	template_hdr->ver_attr[3] = ha->fw_attributes;
	template_hdr->ver_attr[4] = ha->fw_ext_attributes;

	QL_PRINT_7(ha, "started, template_hdr=%ph, dump_buff=%ph, "
	    "buff_size=%xh, buff_end=%ph\n", (void *)template_hdr,
	    (void *)dbuff, buff_size, (void *)dbuff_end);

	/* Setup parameters */
	QL_PRINT_7(ha, "type=%d, first_entry_offset=%xh, "
	    "num_of_entries=%xh ver_attr=%xh,%xh,%xh,%xh,%xh\n",
	    template_hdr->type, template_hdr->first_entry_offset,
	    template_hdr->num_of_entries, template_hdr->ver_attr[0],
	    template_hdr->ver_attr[1], template_hdr->ver_attr[2],
	    template_hdr->ver_attr[3], template_hdr->ver_attr[4]);

	if (template_hdr->type != DT_THDR) {
		EL(ha, "Template header not found\n");
		return (0);
	}
	if (dbuff != NULL) {
		(void) drv_getparm(TIME, &time);
		template_hdr->driver_timestamp = LSD(time);
	}

	num_of_entries = template_hdr->num_of_entries;
	entry = (ql_dt_entry_t *)((caddr_t)template_hdr +
	    template_hdr->first_entry_offset);

	bsize = template_hdr->size_of_template;
	for (e_cnt = 0; e_cnt < num_of_entries; e_cnt++) {
		QL_PRINT_7(ha, "e_cnt=%xh, entry=%ph, type=%d, size=%xh, "
		    "capture_flags=%xh, driver_flags=%xh, bofst=%xh\n",
		    e_cnt, (void *)entry, entry->h.type, entry->h.size,
		    entry->h.capture_flags, entry->h.driver_flags,
		    dbuff != NULL ? (uintptr_t)dbuff - (uintptr_t)template_hdr :
		    bsize);
		/*
		 * Decode the entry type and process it accordingly
		 */
		esize = 0;
		switch (entry->h.type) {
		case DT_NOP:
			if (dbuff != NULL) {
				entry->h.driver_flags = (uint8_t)
				    (entry->h.driver_flags | SKIPPED_FLAG);
			}
			QL_PRINT_3(ha, "Skipping Entry ID=%d, type=%d\n",
			    e_cnt, entry->h.type);
			break;
		case DT_TEND:
			if (dbuff != NULL) {
				entry->h.driver_flags = (uint8_t)
				    (entry->h.driver_flags | SKIPPED_FLAG);
			}
			QL_PRINT_3(ha, "Skipping Entry ID=%d, type=%d\n",
			    e_cnt, entry->h.type);
			sane_end++;
			break;
		case DT_RIOB1:
			esize = ql_2700_dt_riob1(ha, (ql_dt_riob1_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WIOB1:
			ql_2700_dt_wiob1(ha, (ql_dt_wiob1_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RIOB2:
			esize = ql_2700_dt_riob2(ha, (ql_dt_riob2_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WIOB2:
			ql_2700_dt_wiob2(ha, (ql_dt_wiob2_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RPCI:
			esize = ql_2700_dt_rpci(ha, (ql_dt_rpci_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WPCI:
			ql_2700_dt_wpci(ha, (ql_dt_wpci_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRAM:
			esize = ql_2700_dt_rram(ha, (ql_dt_rram_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GQUE:
			esize = ql_2700_dt_gque(ha, (ql_dt_gque_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GFCE:
			esize = ql_2700_dt_gfce(ha, (ql_dt_gfce_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_PRISC:
			ql_2700_dt_prisc(ha, (ql_dt_prisc_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRISC:
			ql_2700_dt_rrisc(ha, (ql_dt_rrisc_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_DINT:
			ql_2700_dt_dint(ha, (ql_dt_dint_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GHBD:
			esize = ql_2700_dt_ghbd(ha, (ql_dt_ghbd_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_SCRA:
			esize = ql_2700_dt_scra(ha, (ql_dt_scra_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRREG:
			esize = ql_2700_dt_rrreg(ha, (ql_dt_rrreg_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WRREG:
			ql_2700_dt_wrreg(ha, (ql_dt_wrreg_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RRRAM:
			esize = ql_2700_dt_rrram(ha, (ql_dt_rrram_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_RPCIC:
			esize = ql_2700_dt_rpcic(ha, (ql_dt_rpcic_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_GQUES:
			esize = ql_2700_dt_gques(ha, (ql_dt_gques_t *)entry,
			    dbuff, dbuff_end);
			break;
		case DT_WDMP:
			esize = ql_2700_dt_wdmp(ha, (ql_dt_wdmp_t *)entry,
			    dbuff, dbuff_end);
			break;
		default:
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			EL(ha, "Entry ID=%d, type=%d unknown\n", e_cnt,
			    entry->h.type);
			break;
		}
		if (dbuff != NULL && esize) {
			QL_PRINT_7(ha, "entry=%d, esize=%xh, capture data\n",
			    entry->h.type, esize);
			QL_DUMP_3(dbuff, 8, esize);
			dbuff += esize;
		}
		bsize += esize;
		/* next entry in the template */
		entry = (ql_dt_entry_t *)((caddr_t)entry + entry->h.size);
	}
	if (sane_end > 1) {
		EL(ha, "Template configuration error. Check Template\n");
	}

	QL_PRINT_7(ha, "done, num of entries=%xh, size=%xh\n",
	    template_hdr->num_of_entries, bsize);
	return (bsize);
}

static int
ql_2700_dt_riob1(ql_adapter_state_t *ha, ql_dt_riob1_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	i, cnt;
	uint8_t		*bp = dbuff;
	uint32_t	addr = entry->addr;
	uint8_t		*reg = (uint8_t *)ha->iobase + entry->pci_offset;

	QL_PRINT_7(ha, "started, buf=%ph, addr=%xh, reg_size=%xh, "
	    "reg_count=%x%02xh, pci_offset=%xh\n", (void *)dbuff, entry->addr,
	    entry->reg_size, entry->reg_count_h, entry->reg_count_l,
	    entry->pci_offset);

	cnt = CHAR_TO_SHORT(entry->reg_count_l, entry->reg_count_h);
	esize = cnt * 4;		/* addr */
	esize += cnt * entry->reg_size;	/* data */

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	WRT32_IO_REG(ha, io_base_addr, addr);
	while (cnt--) {
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < entry->reg_size; i++) {
			*bp++ = RD_REG_BYTE(ha, reg++);
		}
		addr++;
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static void
ql_2700_dt_wiob1(ql_adapter_state_t *ha, ql_dt_wiob1_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	uint8_t	*reg = (uint8_t *)ha->iobase + entry->pci_offset;

	QL_PRINT_7(ha, "started, addr=%xh, data=%xh, pci_offset=%xh\n",
	    entry->addr, entry->data, entry->pci_offset);

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	WRT32_IO_REG(ha, io_base_addr, entry->addr);
	WRT_REG_DWORD(ha, reg, entry->data);

	QL_PRINT_7(ha, "done\n");
}

static int
ql_2700_dt_riob2(ql_adapter_state_t *ha, ql_dt_riob2_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	i, cnt;
	uint8_t		*bp = dbuff;
	uint8_t		*reg = (uint8_t *)ha->iobase + entry->pci_offset;
	uint32_t	addr = entry->addr;

	QL_PRINT_7(ha, "started, buf=%ph, addr=%xh, reg_size=%xh, "
	    "reg_count=%x%02xh, pci_offset=%xh, bank_sel_offset=%xh, "
	    "reg_bank=%xh\n", (void *)dbuff, entry->addr,
	    entry->reg_size, entry->reg_count_h, entry->reg_count_l,
	    entry->pci_offset, entry->bank_sel_offset, entry->reg_bank);

	cnt = CHAR_TO_SHORT(entry->reg_count_l, entry->reg_count_h);
	esize = cnt * 4;		/* addr */
	esize += cnt * entry->reg_size;	/* data */

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	WRT32_IO_REG(ha, io_base_addr, addr);
	WRT_REG_DWORD(ha, ha->iobase + entry->bank_sel_offset, entry->reg_bank);
	while (cnt--) {
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < entry->reg_size; i++) {
			*bp++ = RD_REG_BYTE(ha, reg++);
		}
		addr++;
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static void
ql_2700_dt_wiob2(ql_adapter_state_t *ha, ql_dt_wiob2_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	uint16_t	data;
	uint8_t		*reg = (uint8_t *)ha->iobase + entry->pci_offset;

	QL_PRINT_7(ha, "started, addr=%xh, data=%x%02xh, pci_offset=%xhh, "
	    "bank_sel_offset=%xh, reg_bank=%xh\n", entry->addr, entry->data_h,
	    entry->data_l, entry->pci_offset, entry->bank_sel_offset,
	    entry->reg_bank);

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	data = CHAR_TO_SHORT(entry->data_l, entry->data_h);

	WRT32_IO_REG(ha, io_base_addr, entry->addr);
	WRT_REG_DWORD(ha, ha->iobase + entry->bank_sel_offset, entry->reg_bank);
	WRT_REG_WORD(ha, reg, data);

	QL_PRINT_7(ha, "done\n");
}

static int
ql_2700_dt_rpci(ql_adapter_state_t *ha, ql_dt_rpci_t *entry, uint8_t *dbuff,
    uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	i;
	uint8_t		*bp = dbuff;
	uint8_t		*reg = (uint8_t *)ha->iobase + entry->addr;

	QL_PRINT_7(ha, "started, addr=%xh, reg=%ph\n", entry->addr,
	    (void *)reg);

	esize = 4;	/* addr */
	esize += 4;	/* data */

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	*bp++ = LSB(LSW(entry->addr));
	*bp++ = MSB(LSW(entry->addr));
	*bp++ = LSB(MSW(entry->addr));
	*bp++ = MSB(MSW(entry->addr));
	for (i = 0; i < 4; i++) {
		*bp++ = RD_REG_BYTE(ha, reg++);
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static void
ql_2700_dt_wpci(ql_adapter_state_t *ha, ql_dt_wpci_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	uint8_t	*reg = (uint8_t *)ha->iobase + entry->addr;

	QL_PRINT_7(ha, "started, addr=%xh, data=%xh, reg=%ph\n",
	    entry->addr, entry->data, (void *)reg);

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	WRT_REG_DWORD(ha, reg, entry->data);

	QL_PRINT_7(ha, "done\n");
}

static int
ql_2700_dt_rram(ql_adapter_state_t *ha, ql_dt_rram_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize, rval;
	uint32_t	start = entry->start_addr;
	uint32_t	end = entry->end_addr;

	QL_PRINT_7(ha, "started, buf=%ph, ram_area=%xh, start_addr=%xh, "
	    "end_addr=%xh\n", (void *)dbuff, entry->ram_area,
	    entry->start_addr, entry->end_addr);

	if (entry->ram_area == 2) {
		end = ha->fw_ext_memory_end;
	} else if (entry->ram_area == 3) {
		start = ha->fw_shared_ram_start;
		end = ha->fw_shared_ram_end;
	} else if (entry->ram_area == 4) {
		start = ha->fw_ddr_ram_start;
		end = ha->fw_ddr_ram_end;
	} else if (entry->ram_area != 1) {
		EL(ha, "skipped, unknown RAM_AREA %d\n", entry->ram_area);
		start = 0;
		end = 0;
	}
	esize = end > start ? end - start : 0;
	if (esize) {
		esize = (esize + 1) * 4;
	}

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize == 0 || esize + dbuff >= dbuff_end) {
		if (esize != 0) {
			EL(ha, "skipped, no buffer space, needed=%xh\n",
			    esize);
		} else {
			/*EMPTY*/
			QL_PRINT_7(ha, "skipped, no ram_area=%xh, start=%xh, "
			    "end=%xh\n", entry->ram_area, start, end);
		}
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}
	entry->end_addr = end;
	entry->start_addr = start;

	if ((rval = ql_2700_dump_ram(ha, MBC_DUMP_RAM_EXTENDED,
	    start, esize / 4, dbuff)) != QL_SUCCESS) {
		EL(ha, "dump_ram failed, rval=%xh, addr=%xh, len=%xh, "
		    "esize=0\n", rval, start, esize / 4);
		return (0);
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static int
ql_2700_dt_gque(ql_adapter_state_t *ha, ql_dt_gque_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	cnt, q_cnt, e_cnt, i;
	uint8_t		*bp = dbuff, *dp;

	QL_PRINT_7(ha, "started, buf=%ph, num_queues=%xh, queue_type=%xh\n",
	    (void *)dbuff, entry->num_queues, entry->queue_type);

	if (entry->queue_type == 1) {
		ql_request_q_t	*req_q;

		e_cnt = ha->rsp_queues_cnt > 1 ? 2 : 1;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* queue entries */

		/* queue size */
		esize += ha->req_q[0]->req_entry_cnt * REQUEST_ENTRY_SIZE;
		if (e_cnt > 1) {
			esize += ha->req_q[1]->req_entry_cnt *
			    REQUEST_ENTRY_SIZE;
		}

		if (dbuff == NULL) {
			QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			req_q = q_cnt == 0 ? ha->req_q[0] : ha->req_q[1];
			e_cnt = req_q->req_entry_cnt;
			dp = req_q->req_ring.bp;
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			for (cnt = 0; cnt < e_cnt; cnt++) {
				for (i = 0; i < REQUEST_ENTRY_SIZE; i++) {
					*bp++ = *dp++;
				}
			}
		}
	} else if (entry->queue_type == 2) {
		ql_response_q_t	*rsp_q;

		e_cnt = ha->rsp_queues_cnt;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* queue entries */

		/* queue size */
		for (q_cnt = 0; q_cnt < ha->rsp_queues_cnt; q_cnt++) {
			rsp_q = ha->rsp_queues[q_cnt];
			esize += rsp_q->rsp_entry_cnt * RESPONSE_ENTRY_SIZE;
		}

		if (dbuff == NULL) {
			QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(ha, "skipped2, no buffer space, needed=%xh\n",
			    esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			rsp_q = ha->rsp_queues[q_cnt];
			e_cnt = rsp_q->rsp_entry_cnt;
			dp = rsp_q->rsp_ring.bp;
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			for (cnt = 0; cnt < e_cnt; cnt++) {
				for (i = 0; i < RESPONSE_ENTRY_SIZE; i++) {
					*bp++ = *dp++;
				}
			}
		}
	} else if (entry->queue_type == 3) {
		QL_PRINT_7(ha, "skipped, no ATIO queue, esize=0\n");
		if (dbuff != NULL) {
			entry->num_queues = 0;
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	} else {
		EL(ha, "skipped, unknown queue_type %d, esize=0\n",
		    entry->queue_type);
		if (dbuff != NULL) {
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

/*ARGSUSED*/
static int
ql_2700_dt_gfce(ql_adapter_state_t *ha, ql_dt_gfce_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	QL_PRINT_7(ha, "started\n");

	QL_PRINT_7(ha, "skipped, not supported, esize=0\n");
	if (dbuff != NULL) {
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
	}

	return (0);
}

static void
ql_2700_dt_prisc(ql_adapter_state_t *ha, ql_dt_prisc_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	clock_t	timer;

	QL_PRINT_7(ha, "started\n");

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	/* Pause RISC. */
	if ((RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0) {
		WRT32_IO_REG(ha, hccr, HC24_PAUSE_RISC);
		for (timer = 30000;
		    (RD32_IO_REG(ha, risc2host) & RH_RISC_PAUSED) == 0;
		    timer--) {
			if (timer) {
				drv_usecwait(100);
				if (timer % 10000 == 0) {
					EL(ha, "risc pause %d\n", timer);
				}
			} else {
				EL(ha, "risc pause timeout\n");
				break;
			}
		}
	}

	QL_PRINT_7(ha, "done\n");
}

static void
ql_2700_dt_rrisc(ql_adapter_state_t *ha, ql_dt_rrisc_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	clock_t	timer;

	QL_PRINT_7(ha, "started\n");

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	/* Shutdown DMA. */
	WRT32_IO_REG(ha, ctrl_status, DMA_SHUTDOWN);

	/* Wait for DMA to stop. */
	for (timer = 0; timer < 30000; timer++) {
		if (!(RD32_IO_REG(ha, ctrl_status) & DMA_ACTIVE)) {
			break;
		}
		drv_usecwait(100);
	}

	/* Reset the chip. */
	WRT32_IO_REG(ha, ctrl_status, ISP_RESET);
	drv_usecwait(200);

	/* Wait for RISC to recover from reset. */
	for (timer = 30000; timer; timer--) {
		ha->rom_status = RD16_IO_REG(ha, mailbox_out[0]);
		if ((ha->rom_status & MBS_ROM_STATUS_MASK) != MBS_ROM_BUSY) {
			break;
		}
		drv_usecwait(100);
	}

	/* Wait for reset to finish. */
	for (timer = 30000; timer; timer--) {
		if (!(RD32_IO_REG(ha, ctrl_status) & ISP_RESET)) {
			break;
		}
		drv_usecwait(100);
	}

	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~FIRMWARE_UP;
	ADAPTER_STATE_UNLOCK(ha);

	QL_PRINT_7(ha, "done\n");
}

static void
ql_2700_dt_dint(ql_adapter_state_t *ha, ql_dt_dint_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	QL_PRINT_7(ha, "started, pci_offset=%xh, data=%xh\n",
	    entry->pci_offset, entry->data);

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	ql_pci_config_put32(ha, entry->pci_offset, entry->data);

	QL_PRINT_7(ha, "done\n");
}

/*ARGSUSED*/
static int
ql_2700_dt_ghbd(ql_adapter_state_t *ha, ql_dt_ghbd_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	QL_PRINT_7(ha, "started\n");

	QL_PRINT_7(ha, "skipped, not supported\n");
	if (dbuff != NULL) {
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
	}

	return (0);
}

/*ARGSUSED*/
static int
ql_2700_dt_scra(ql_adapter_state_t *ha, ql_dt_scra_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	QL_PRINT_7(ha, "started\n");

	QL_PRINT_7(ha, "skipped, not supported, esize=0\n");
	if (dbuff != NULL) {
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
	}

	return (0);
}

static int
ql_2700_dt_rrreg(ql_adapter_state_t *ha, ql_dt_rrreg_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	i;
	uint8_t		*bp = dbuff;
	uint8_t		*reg = (uint8_t *)ha->iobase + 0xc4;
	uint32_t	addr = entry->addr;
	uint32_t	cnt = entry->count;

	QL_PRINT_7(ha, "started, buf=%ph, addr=%xh, count=%xh\n",
	    (void *)dbuff, entry->addr, entry->count);

	esize = cnt * 4;	/* addr */
	esize += cnt * 4;	/* data */

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	WRT32_IO_REG(ha, io_base_addr, 0x40);
	while (cnt--) {
		WRT_REG_DWORD(ha, ha->iobase + 0xc0, addr | 0x80000000);
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < 4; i++) {
			*bp++ = RD_REG_BYTE(ha, reg + i);
		}
		addr += 4;
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static void
ql_2700_dt_wrreg(ql_adapter_state_t *ha, ql_dt_wrreg_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	QL_PRINT_7(ha, "started, addr=%xh, data=%xh\n", entry->addr,
	    entry->data);

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done\n");
		return;
	}
	if (dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=0\n");
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return;
	}

	WRT32_IO_REG(ha, io_base_addr, 0x40);
	WRT_REG_DWORD(ha, ha->iobase + 0xc4, entry->data);
	WRT_REG_DWORD(ha, ha->iobase + 0xc0, entry->addr);

	QL_PRINT_7(ha, "done\n");
}

static int
ql_2700_dt_rrram(ql_adapter_state_t *ha, ql_dt_rrram_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int	rval, esize;

	QL_PRINT_7(ha, "started, buf=%ph, addr=%xh, count=%xh\n",
	    (void *)dbuff, entry->addr, entry->count);

	esize = entry->count * 4;	/* data */

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	if ((rval = ql_2700_dump_ram(ha, MBC_MPI_RAM, entry->addr,
	    entry->count, dbuff)) != QL_SUCCESS) {
		EL(ha, "dump_ram failed, rval=%xh, addr=%xh, len=%xh, "
		    "esize=0\n", rval, entry->addr, entry->count);
		return (0);
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static int
ql_2700_dt_rpcic(ql_adapter_state_t *ha, ql_dt_rpcic_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	i;
	uint8_t		*bp = dbuff;
	uint32_t	addr = entry->addr;
	uint32_t	cnt = entry->count;

	QL_PRINT_7(ha, "started, buf=%ph, addr=%xh, count=%xh\n",
	    (void *)dbuff, entry->addr, entry->count);

	esize = cnt * 4;	/* addr */
	esize += cnt * 4;	/* data */

	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	while (cnt--) {
		*bp++ = LSB(LSW(addr));
		*bp++ = MSB(LSW(addr));
		*bp++ = LSB(MSW(addr));
		*bp++ = MSB(MSW(addr));
		for (i = 0; i < 4; i++) {
			*bp++ = ql_pci_config_get8(ha, addr++);
		}
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static int
ql_2700_dt_gques(ql_adapter_state_t *ha, ql_dt_gques_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint32_t	q_cnt, e_cnt, data;
	uint8_t		*bp = dbuff;

	QL_PRINT_7(ha, "started, buf=%ph, num_queues=%xh, queue_type=%xh\n",
	    (void *)dbuff, entry->num_queues, entry->queue_type);

	if (entry->queue_type == 1) {
		ql_request_q_t	*req_q;

		e_cnt = ha->rsp_queues_cnt > 1 ? 2 : 1;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* shadow entries */

		/* shadow size */
		esize += SHADOW_ENTRY_SIZE;
		if (e_cnt > 1) {
			esize += SHADOW_ENTRY_SIZE;
		}
		if (dbuff == NULL) {
			QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			req_q = q_cnt == 0 ? ha->req_q[0] : ha->req_q[1];
			e_cnt = 1;
			data = ddi_get32(req_q->req_ring.acc_handle,
			    req_q->req_out_shadow_ptr);
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			*bp++ = LSB(LSW(data));
			*bp++ = MSB(LSW(data));
			*bp++ = LSB(MSW(data));
			*bp++ = MSB(MSW(data));
		}
	} else if (entry->queue_type == 2) {
		ql_response_q_t	*rsp_q;

		e_cnt = ha->rsp_queues_cnt;
		esize = e_cnt * 2;	/* queue number */
		esize += e_cnt * 2;	/* shadow entries */

		/* shadow size */
		for (q_cnt = 0; q_cnt < ha->rsp_queues_cnt; q_cnt++) {
			esize += SHADOW_ENTRY_SIZE;
		}

		if (dbuff == NULL) {
			QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
			return (esize);
		}
		if (esize + dbuff >= dbuff_end) {
			EL(ha, "skipped2, no buffer space, needed=%xh\n",
			    esize);
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
			return (0);
		}
		entry->num_queues = e_cnt;

		for (q_cnt = 0; q_cnt < entry->num_queues; q_cnt++) {
			rsp_q = ha->rsp_queues[q_cnt];
			e_cnt = 1;
			data = ddi_get32(rsp_q->rsp_ring.acc_handle,
			    rsp_q->rsp_in_shadow_ptr);
			*bp++ = LSB(q_cnt);
			*bp++ = MSB(q_cnt);
			*bp++ = LSB(e_cnt);
			*bp++ = MSB(e_cnt);
			*bp++ = LSB(LSW(data));
			*bp++ = MSB(LSW(data));
			*bp++ = LSB(MSW(data));
			*bp++ = MSB(MSW(data));
		}
	} else if (entry->queue_type == 3) {
		EL(ha, "skipped, no ATIO queue, esize=0\n");
		if (dbuff != NULL) {
			entry->num_queues = 0;
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	} else {
		EL(ha, "skipped, unknown queue_type %d, esize=0\n",
		    entry->queue_type);
		if (dbuff != NULL) {
			entry->h.driver_flags = (uint8_t)
			    (entry->h.driver_flags | SKIPPED_FLAG);
		}
		return (0);
	}

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

static int
ql_2700_dt_wdmp(ql_adapter_state_t *ha, ql_dt_wdmp_t *entry,
    uint8_t *dbuff, uint8_t *dbuff_end)
{
	int		esize;
	uint8_t		*bp = dbuff;
	uint32_t	data, cnt = entry->length, *dp = entry->data;

	QL_PRINT_7(ha, "started, buf=%ph, length=%xh\n",
	    (void *)dbuff, entry->length);

	esize = cnt;
	if (dbuff == NULL) {
		QL_PRINT_7(ha, "null buf done, esize=%xh\n", esize);
		return (esize);
	}
	if (esize + dbuff >= dbuff_end) {
		EL(ha, "skipped, no buffer space, needed=%xh\n", esize);
		entry->h.driver_flags = (uint8_t)
		    (entry->h.driver_flags | SKIPPED_FLAG);
		return (0);
	}

	while (cnt--) {
		data = *dp++;
		*bp++ = LSB(LSW(data));
		*bp++ = MSB(LSW(data));
		*bp++ = LSB(MSW(data));
		*bp++ = MSB(MSW(data));
	}
	QL_PRINT_7(ha, "%s\n", dbuff);

	QL_PRINT_7(ha, "done, esize=%xh\n", esize);
	return (esize);
}

/*
 * ql_2700_dump_ram
 *	Dumps RAM.
 *	Risc interrupts must be disabled when this routine is called.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	cmd:		MBC_DUMP_RAM_EXTENDED/MBC_MPI_RAM.
 *	risc_address:	RISC code start address.
 *	len:		Number of words.
 *	bp:		buffer pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_2700_dump_ram(ql_adapter_state_t *ha, uint16_t cmd, uint32_t risc_address,
    uint32_t len, uint8_t *bp)
{
	dma_mem_t	mem;
	uint32_t	i, stat, timer;
	uint8_t		*dp;
	int		rval = QL_SUCCESS;

	QL_PRINT_7(ha, "started, cmd=%xh, risc_address=%xh, len=%xh, "
	    "bp=%ph\n", cmd, risc_address, len, (void *)bp);

	mem.size = len * 4;
	mem.type = LITTLE_ENDIAN_DMA;
	mem.max_cookie_count = 1;
	mem.alignment = 8;
	if ((rval = ql_alloc_phys(ha, &mem, KM_SLEEP)) != QL_SUCCESS) {
		EL(ha, "alloc status=%xh\n", rval);
		return (rval);
	}

	WRT16_IO_REG(ha, mailbox_in[0], cmd);
	WRT16_IO_REG(ha, mailbox_in[1], LSW(risc_address));
	WRT16_IO_REG(ha, mailbox_in[2], MSW(LSD(mem.cookie.dmac_laddress)));
	WRT16_IO_REG(ha, mailbox_in[3], LSW(LSD(mem.cookie.dmac_laddress)));
	WRT16_IO_REG(ha, mailbox_in[4], MSW(len));
	WRT16_IO_REG(ha, mailbox_in[5], LSW(len));
	WRT16_IO_REG(ha, mailbox_in[6], MSW(MSD(mem.cookie.dmac_laddress)));
	WRT16_IO_REG(ha, mailbox_in[7], LSW(MSD(mem.cookie.dmac_laddress)));
	WRT16_IO_REG(ha, mailbox_in[8], MSW(risc_address));
	if (cmd == MBC_MPI_RAM) {
		WRT16_IO_REG(ha, mailbox_in[9], BIT_0);
	}

	WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
	for (timer = 6000000; timer && rval == QL_SUCCESS; timer--) {
		stat = RD32_IO_REG(ha, risc2host);
		if (stat & RH_RISC_INT) {
			stat &= 0xff;
			if ((stat == 1) || (stat == 0x10)) {
				break;
			} else if ((stat == 2) || (stat == 0x11)) {
				rval = RD16_IO_REG(ha, mailbox_out[0]);
				break;
			}
			WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);
		}
		drv_usecwait(5);
	}
	WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT);

	if (timer == 0) {
		QL_PRINT_7(ha, "timeout addr=%xh\n", risc_address);
		rval = QL_FUNCTION_TIMEOUT;
	} else {
		(void) ddi_dma_sync(mem.dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);
		dp = mem.bp;
		for (i = 0; i < mem.size; i++) {
			*bp++ = *dp++;
		}
	}

	ql_free_phys(ha, &mem);

	QL_PRINT_7(ha, "done\n");
	return (rval);
}
