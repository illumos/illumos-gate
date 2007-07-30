/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2001,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_WCI_REGS_H
#define	_SYS_WCI_REGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_KERNEL) && !defined(_ASM)

/*
 * wci_sram_array
 */
typedef union {
	struct wci_sram_array {
		uint64_t error				: 1;	/* 63 */
		uint64_t data				: 63;	/* 62:0 */
	} bit;
	uint64_t val;
} wci_sram_array_u;

#define	wci_sram_array_error	\
	bit.error
#define	wci_sram_array_data	\
	bit.data


/*
 * wci_shadow_addr
 */
typedef union {
	struct wci_shadow_addr {
		uint64_t set_agent_reset		: 1;	/* 63 */
		uint64_t pull_stop			: 1;	/* 62 */
		uint64_t data_stop			: 1;	/* 61 */
		uint64_t shadow_rsvd			: 1;	/* 60 */
		uint64_t rsvd_z				: 10;	/* 59:50 */
		uint64_t shadow_valid			: 1;	/* 49 */
		uint64_t shadow_timeout			: 1;	/* 48 */
		uint64_t shadow_addr_not_vld		: 1;	/* 47 */
		uint64_t shadow_sram_error		: 1;	/* 46 */
		uint64_t shadow_sram			: 1;	/* 45 */
		uint64_t shadow_write			: 1;	/* 44 */
		uint64_t rsvd_y				: 15;	/* 43:29 */
		uint64_t shadow_addr			: 24;	/* 28:5 */
		uint64_t rsvd_x				: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_shadow_addr_u;

#define	wci_shadow_addr_set_agent_reset	\
	bit.set_agent_reset
#define	wci_shadow_addr_pull_stop	\
	bit.pull_stop
#define	wci_shadow_addr_data_stop	\
	bit.data_stop
#define	wci_shadow_addr_shadow_rsvd	\
	bit.shadow_rsvd
#define	wci_shadow_addr_shadow_valid	\
	bit.shadow_valid
#define	wci_shadow_addr_shadow_timeout	\
	bit.shadow_timeout
#define	wci_shadow_addr_shadow_addr_not_vld	\
	bit.shadow_addr_not_vld
#define	wci_shadow_addr_shadow_sram_error	\
	bit.shadow_sram_error
#define	wci_shadow_addr_shadow_sram	\
	bit.shadow_sram
#define	wci_shadow_addr_shadow_write	\
	bit.shadow_write
#define	wci_shadow_addr_shadow_addr	\
	bit.shadow_addr


/*
 * wci_shadow_data
 */
typedef union {
	struct wci_shadow_data {
		uint64_t shadow_data			: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_shadow_data_u;

#define	wci_shadow_data_shadow_data	\
	bit.shadow_data


/*
 * wci_config
 */
typedef union {
	struct wci_config {
		uint64_t rsvd_z				: 19;	/* 63:45 */
		uint64_t wr_dir_on_rinv_miss		: 1;	/* 44 */
		uint64_t wr_dir_on_rws_miss		: 1;	/* 43 */
		uint64_t safari_compliant_targid	: 1;	/* 42 */
		uint64_t rsvd_y				: 3;	/* 41:39 */
		uint64_t cluster_early_reuse_en		: 1;	/* 38 */
		uint64_t reserved_default_0		: 1;	/* 37 */
		uint64_t ra_numa_bypass_en		: 1;	/* 36 */
		uint64_t ha_disable_unexp_snid		: 1;	/* 35 */
		uint64_t ra_disable_unexp_snid		: 1;	/* 34 */
		uint64_t dc_cpi_snid_disable		: 1;	/* 33 */
		uint64_t dbg_bytemask_en		: 1;	/* 32 */
		uint64_t partner_node_id		: 4;	/* 31:28 */
		uint64_t cluster_mode			: 1;	/* 27 */
		uint64_t rsvd_x				: 1;	/* 26 */
		uint64_t nc_stripe_by_addr		: 1;	/* 25 */
		uint64_t enable_inid			: 1;	/* 24 */
		uint64_t stripe_bits			: 4;	/* 23:20 */
		uint64_t dev_config_node_id		: 5;	/* 19:15 */
		uint64_t box_id				: 6;	/* 14:9 */
		uint64_t device_id			: 5;	/* 8:4 */
		uint64_t node_id			: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_config_u;

#define	wci_config_wr_dir_on_rinv_miss	\
	bit.wr_dir_on_rinv_miss
#define	wci_config_wr_dir_on_rws_miss	\
	bit.wr_dir_on_rws_miss
#define	wci_config_safari_compliant_targid	\
	bit.safari_compliant_targid
#define	wci_config_cluster_early_reuse_en	\
	bit.cluster_early_reuse_en
#define	wci_config_reserved_default_0	\
	bit.reserved_default_0
#define	wci_config_ra_numa_bypass_en	\
	bit.ra_numa_bypass_en
#define	wci_config_ha_disable_unexp_snid	\
	bit.ha_disable_unexp_snid
#define	wci_config_ra_disable_unexp_snid	\
	bit.ra_disable_unexp_snid
#define	wci_config_dc_cpi_snid_disable	\
	bit.dc_cpi_snid_disable
#define	wci_config_dbg_bytemask_en	\
	bit.dbg_bytemask_en
#define	wci_config_partner_node_id	\
	bit.partner_node_id
#define	wci_config_cluster_mode	\
	bit.cluster_mode
#define	wci_config_nc_stripe_by_addr	\
	bit.nc_stripe_by_addr
#define	wci_config_enable_inid	\
	bit.enable_inid
#define	wci_config_stripe_bits	\
	bit.stripe_bits
#define	wci_config_dev_config_node_id	\
	bit.dev_config_node_id
#define	wci_config_box_id	\
	bit.box_id
#define	wci_config_device_id	\
	bit.device_id
#define	wci_config_node_id	\
	bit.node_id


/*
 * wci_domain_config
 */
typedef union {
	struct wci_domain_config {
		uint64_t rsvd_z				: 48;	/* 63:16 */
		uint64_t domain_mask			: 16;	/* 15:0 */
	} bit;
	uint64_t val;
} wci_domain_config_u;

#define	wci_domain_config_domain_mask	\
	bit.domain_mask


/*
 * wci_local_device_id
 */
typedef union {
	struct wci_local_device_id {
		uint64_t skip_rs_vec			: 32;	/* 63:32 */
		uint64_t ssm_mask			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_local_device_id_u;

#define	wci_local_device_id_skip_rs_vec	\
	bit.skip_rs_vec
#define	wci_local_device_id_ssm_mask	\
	bit.ssm_mask


/*
 * wci_reset_config
 */
typedef union {
	struct wci_reset_config {
		uint64_t rsvd_z				: 63;	/* 63:1 */
		uint64_t agent_reset_e			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_reset_config_u;

#define	wci_reset_config_agent_reset_e	\
	bit.agent_reset_e


/*
 * wci_reset_status
 */
typedef union {
	struct wci_reset_status {
		uint64_t rsvd_z				: 61;	/* 63:3 */
		uint64_t por				: 1;	/* 2 */
		uint64_t node_reset			: 1;	/* 1 */
		uint64_t agent_reset			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_reset_status_u;

#define	wci_reset_status_por	\
	bit.por
#define	wci_reset_status_node_reset	\
	bit.node_reset
#define	wci_reset_status_agent_reset	\
	bit.agent_reset


/*
 * wci_id
 */
typedef union {
	struct wci_id {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t version			: 4;	/* 31:28 */
		uint64_t parid				: 16;	/* 27:12 */
		uint64_t manfid				: 11;	/* 11:1 */
		uint64_t one				: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_id_u;

#define	wci_id_version	\
	bit.version
#define	wci_id_parid	\
	bit.parid
#define	wci_id_manfid	\
	bit.manfid
#define	wci_id_one	\
	bit.one


/*
 * wci_board2cnid_control
 */
typedef union {
	struct wci_board2cnid_control {
		uint64_t rsvd_z				: 63;	/* 63:1 */
		uint64_t board2cnid_enable		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_board2cnid_control_u;

#define	wci_board2cnid_control_board2cnid_enable	\
	bit.board2cnid_enable


/*
 * wci_csr_control
 */
typedef union {
	struct wci_csr_control {
		uint64_t rsvd_z				: 63;	/* 63:1 */
		uint64_t jtag_wr_only			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_csr_control_u;

#define	wci_csr_control_jtag_wr_only	\
	bit.jtag_wr_only


/*
 * wci_error_summary
 */
typedef union {
	struct wci_error_summary {
		uint64_t rsvd_z				: 53;	/* 63:11 */
		uint64_t cci_error			: 1;	/* 10 */
		uint64_t request_agent_error		: 1;	/* 9 */
		uint64_t home_agent_error		: 1;	/* 8 */
		uint64_t slave_agent_error		: 1;	/* 7 */
		uint64_t cluster_agent_error		: 1;	/* 6 */
		uint64_t csr_agent_error		: 1;	/* 5 */
		uint64_t lc_error			: 1;	/* 4 */
		uint64_t sfi_error			: 1;	/* 3 */
		uint64_t sfq_error			: 1;	/* 2 */
		uint64_t dc_error			: 1;	/* 1 */
		uint64_t hli_error			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_error_summary_u;

#define	wci_error_summary_cci_error	\
	bit.cci_error
#define	wci_error_summary_request_agent_error	\
	bit.request_agent_error
#define	wci_error_summary_home_agent_error	\
	bit.home_agent_error
#define	wci_error_summary_slave_agent_error	\
	bit.slave_agent_error
#define	wci_error_summary_cluster_agent_error	\
	bit.cluster_agent_error
#define	wci_error_summary_csr_agent_error	\
	bit.csr_agent_error
#define	wci_error_summary_lc_error	\
	bit.lc_error
#define	wci_error_summary_sfi_error	\
	bit.sfi_error
#define	wci_error_summary_sfq_error	\
	bit.sfq_error
#define	wci_error_summary_dc_error	\
	bit.dc_error
#define	wci_error_summary_hli_error	\
	bit.hli_error


/*
 * wci_error_pause_timer_hold
 */
typedef union {
	struct wci_error_pause_timer_hold {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t ca_aphase			: 1;	/* 7 */
		uint64_t ca_dphase			: 1;	/* 6 */
		uint64_t ca_reuse			: 1;	/* 5 */
		uint64_t reserved			: 1;	/* 4 */
		uint64_t ra_cluster_primary		: 1;	/* 3 */
		uint64_t ra_ssm_primary			: 1;	/* 2 */
		uint64_t ha_primary			: 1;	/* 1 */
		uint64_t sa_primary			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_error_pause_timer_hold_u;

#define	wci_error_pause_timer_hold_ca_aphase	\
	bit.ca_aphase
#define	wci_error_pause_timer_hold_ca_dphase	\
	bit.ca_dphase
#define	wci_error_pause_timer_hold_ca_reuse	\
	bit.ca_reuse
#define	wci_error_pause_timer_hold_reserved	\
	bit.reserved
#define	wci_error_pause_timer_hold_ra_cluster_primary	\
	bit.ra_cluster_primary
#define	wci_error_pause_timer_hold_ra_ssm_primary	\
	bit.ra_ssm_primary
#define	wci_error_pause_timer_hold_ha_primary	\
	bit.ha_primary
#define	wci_error_pause_timer_hold_sa_primary	\
	bit.sa_primary


/*
 * wci_first_error_time
 */
typedef union {
	struct wci_first_error_time {
		uint64_t stick_time			: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_first_error_time_u;

#define	wci_first_error_time_stick_time	\
	bit.stick_time


/*
 * wci_csra_esr
 */
typedef union {
	struct wci_csra_esr {
		uint64_t rsvd_z				: 37;	/* 63:27 */
		uint64_t acc_timeout			: 1;	/* 26 */
		uint64_t acc_pull_targid_timeout	: 1;	/* 25 */
		uint64_t acc_pull_timeout		: 1;	/* 24 */
		uint64_t acc_sram_error			: 1;	/* 23 */
		uint64_t acc_protection_error		: 1;	/* 22 */
		uint64_t acc_uncorrectable_mtag_error	: 1;	/* 21 */
		uint64_t acc_uncorrectable_data_error	: 1;	/* 20 */
		uint64_t acc_correctable_mtag_error	: 1;	/* 19 */
		uint64_t acc_correctable_data_error	: 1;	/* 18 */
		uint64_t acc_mtag_not_gm		: 1;	/* 17 */
		uint64_t acc_mtag_mismatch		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 4;	/* 14:11 */
		uint64_t timeout			: 1;	/* 10 */
		uint64_t pull_targid_timeout		: 1;	/* 9 */
		uint64_t pull_timeout			: 1;	/* 8 */
		uint64_t sram_error			: 1;	/* 7 */
		uint64_t protection_error		: 1;	/* 6 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 5 */
		uint64_t uncorrectable_data_error	: 1;	/* 4 */
		uint64_t correctable_mtag_error		: 1;	/* 3 */
		uint64_t correctable_data_error		: 1;	/* 2 */
		uint64_t mtag_not_gm			: 1;	/* 1 */
		uint64_t mtag_mismatch			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_csra_esr_u;

#define	wci_csra_esr_acc_timeout	\
	bit.acc_timeout
#define	wci_csra_esr_acc_pull_targid_timeout	\
	bit.acc_pull_targid_timeout
#define	wci_csra_esr_acc_pull_timeout	\
	bit.acc_pull_timeout
#define	wci_csra_esr_acc_sram_error	\
	bit.acc_sram_error
#define	wci_csra_esr_acc_protection_error	\
	bit.acc_protection_error
#define	wci_csra_esr_acc_uncorrectable_mtag_error	\
	bit.acc_uncorrectable_mtag_error
#define	wci_csra_esr_acc_uncorrectable_data_error	\
	bit.acc_uncorrectable_data_error
#define	wci_csra_esr_acc_correctable_mtag_error	\
	bit.acc_correctable_mtag_error
#define	wci_csra_esr_acc_correctable_data_error	\
	bit.acc_correctable_data_error
#define	wci_csra_esr_acc_mtag_not_gm	\
	bit.acc_mtag_not_gm
#define	wci_csra_esr_acc_mtag_mismatch	\
	bit.acc_mtag_mismatch
#define	wci_csra_esr_first_error	\
	bit.first_error
#define	wci_csra_esr_timeout	\
	bit.timeout
#define	wci_csra_esr_pull_targid_timeout	\
	bit.pull_targid_timeout
#define	wci_csra_esr_pull_timeout	\
	bit.pull_timeout
#define	wci_csra_esr_sram_error	\
	bit.sram_error
#define	wci_csra_esr_protection_error	\
	bit.protection_error
#define	wci_csra_esr_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_csra_esr_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_csra_esr_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_csra_esr_correctable_data_error	\
	bit.correctable_data_error
#define	wci_csra_esr_mtag_not_gm	\
	bit.mtag_not_gm
#define	wci_csra_esr_mtag_mismatch	\
	bit.mtag_mismatch


/*
 * wci_csra_esr_mask
 */
typedef union {
	struct wci_csra_esr_mask {
		uint64_t rsvd_z				: 53;	/* 63:11 */
		uint64_t timeout			: 1;	/* 10 */
		uint64_t pull_targid_timeout		: 1;	/* 9 */
		uint64_t pull_timeout			: 1;	/* 8 */
		uint64_t sram_error			: 1;	/* 7 */
		uint64_t protection_error		: 1;	/* 6 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 5 */
		uint64_t uncorrectable_data_error	: 1;	/* 4 */
		uint64_t correctable_mtag_error		: 1;	/* 3 */
		uint64_t correctable_data_error		: 1;	/* 2 */
		uint64_t mtag_not_gm			: 1;	/* 1 */
		uint64_t mtag_mismatch			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_csra_esr_mask_u;

#define	wci_csra_esr_mask_timeout	\
	bit.timeout
#define	wci_csra_esr_mask_pull_targid_timeout	\
	bit.pull_targid_timeout
#define	wci_csra_esr_mask_pull_timeout	\
	bit.pull_timeout
#define	wci_csra_esr_mask_sram_error	\
	bit.sram_error
#define	wci_csra_esr_mask_protection_error	\
	bit.protection_error
#define	wci_csra_esr_mask_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_csra_esr_mask_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_csra_esr_mask_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_csra_esr_mask_correctable_data_error	\
	bit.correctable_data_error
#define	wci_csra_esr_mask_mtag_not_gm	\
	bit.mtag_not_gm
#define	wci_csra_esr_mask_mtag_mismatch	\
	bit.mtag_mismatch


/*
 * wci_csra_status
 */
typedef union {
	struct wci_csra_status {
		uint64_t rsvd_z				: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t scar				: 1;	/* 58 */
		uint64_t atransid			: 9;	/* 57:49 */
		uint64_t targid_3_to_0			: 3;	/* 48:46 */
		uint64_t cesr_number			: 8;	/* 45:38 */
		uint64_t rw				: 1;	/* 37 */
		uint64_t nc_slice			: 8;	/* 36:29 */
		uint64_t sf_addr_28_to_5		: 24;	/* 28:5 */
		uint64_t fsm_state			: 3;	/* 4:2 */
		uint64_t type				: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_csra_status_u;

#define	wci_csra_status_esr_index	\
	bit.esr_index
#define	wci_csra_status_scar	\
	bit.scar
#define	wci_csra_status_atransid	\
	bit.atransid
#define	wci_csra_status_targid_3_to_0	\
	bit.targid_3_to_0
#define	wci_csra_status_cesr_number	\
	bit.cesr_number
#define	wci_csra_status_rw	\
	bit.rw
#define	wci_csra_status_nc_slice	\
	bit.nc_slice
#define	wci_csra_status_sf_addr_28_to_5	\
	bit.sf_addr_28_to_5
#define	wci_csra_status_fsm_state	\
	bit.fsm_state
#define	wci_csra_status_type	\
	bit.type


/*
 * wci_csra_timeout_config
 */
typedef union {
	struct wci_csra_timeout_config {
		uint64_t rsvd_z				: 43;	/* 63:21 */
		uint64_t pull_targid_fail_fast_enable	: 1;	/* 20 */
		uint64_t pull_fail_fast_enable		: 1;	/* 19 */
		uint64_t disable			: 1;	/* 18 */
		uint64_t freeze				: 1;	/* 17 */
		uint64_t magnitude			: 1;	/* 16 */
		uint64_t rd_timeout			: 8;	/* 15:8 */
		uint64_t wr_timeout			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_csra_timeout_config_u;

#define	wci_csra_timeout_config_pull_targid_fail_fast_enable	\
	bit.pull_targid_fail_fast_enable
#define	wci_csra_timeout_config_pull_fail_fast_enable	\
	bit.pull_fail_fast_enable
#define	wci_csra_timeout_config_disable	\
	bit.disable
#define	wci_csra_timeout_config_freeze	\
	bit.freeze
#define	wci_csra_timeout_config_magnitude	\
	bit.magnitude
#define	wci_csra_timeout_config_rd_timeout	\
	bit.rd_timeout
#define	wci_csra_timeout_config_wr_timeout	\
	bit.wr_timeout


/*
 * wci_dc_esr
 */
typedef union {
	struct wci_dc_esr {
		uint64_t rsvd_z				: 38;	/* 63:26 */
		uint64_t acc_dif_timeout		: 1;	/* 25 */
		uint64_t acc_dci_d_err_dstat		: 1;	/* 24 */
		uint64_t acc_dco_ce			: 1;	/* 23 */
		uint64_t acc_dc_dif_overflow		: 1;	/* 22 */
		uint64_t acc_dc_launch_queue_overflow	: 1;	/* 21 */
		uint64_t acc_dco_map_error		: 1;	/* 20 */
		uint64_t acc_dco_data_parity_error	: 1;	/* 19 */
		uint64_t acc_dci_d_err			: 1;	/* 18 */
		uint64_t acc_dci_cpi_invalid		: 1;	/* 17 */
		uint64_t acc_dci_cpi_snid_mismatch	: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 5;	/* 14:10 */
		uint64_t dif_timeout			: 1;	/* 9 */
		uint64_t dci_d_err_dstat		: 1;	/* 8 */
		uint64_t dco_ce				: 1;	/* 7 */
		uint64_t dc_dif_overflow		: 1;	/* 6 */
		uint64_t dc_launch_queue_overflow	: 1;	/* 5 */
		uint64_t dco_map_error			: 1;	/* 4 */
		uint64_t dco_data_parity_error		: 1;	/* 3 */
		uint64_t dci_d_err			: 1;	/* 2 */
		uint64_t dci_cpi_invalid		: 1;	/* 1 */
		uint64_t dci_cpi_snid_mismatch		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_dc_esr_u;

#define	wci_dc_esr_acc_dif_timeout	\
	bit.acc_dif_timeout
#define	wci_dc_esr_acc_dci_d_err_dstat	\
	bit.acc_dci_d_err_dstat
#define	wci_dc_esr_acc_dco_ce	\
	bit.acc_dco_ce
#define	wci_dc_esr_acc_dc_dif_overflow	\
	bit.acc_dc_dif_overflow
#define	wci_dc_esr_acc_dc_launch_queue_overflow	\
	bit.acc_dc_launch_queue_overflow
#define	wci_dc_esr_acc_dco_map_error	\
	bit.acc_dco_map_error
#define	wci_dc_esr_acc_dco_data_parity_error	\
	bit.acc_dco_data_parity_error
#define	wci_dc_esr_acc_dci_d_err	\
	bit.acc_dci_d_err
#define	wci_dc_esr_acc_dci_cpi_invalid	\
	bit.acc_dci_cpi_invalid
#define	wci_dc_esr_acc_dci_cpi_snid_mismatch	\
	bit.acc_dci_cpi_snid_mismatch
#define	wci_dc_esr_first_error	\
	bit.first_error
#define	wci_dc_esr_dif_timeout	\
	bit.dif_timeout
#define	wci_dc_esr_dci_d_err_dstat	\
	bit.dci_d_err_dstat
#define	wci_dc_esr_dco_ce	\
	bit.dco_ce
#define	wci_dc_esr_dc_dif_overflow	\
	bit.dc_dif_overflow
#define	wci_dc_esr_dc_launch_queue_overflow	\
	bit.dc_launch_queue_overflow
#define	wci_dc_esr_dco_map_error	\
	bit.dco_map_error
#define	wci_dc_esr_dco_data_parity_error	\
	bit.dco_data_parity_error
#define	wci_dc_esr_dci_d_err	\
	bit.dci_d_err
#define	wci_dc_esr_dci_cpi_invalid	\
	bit.dci_cpi_invalid
#define	wci_dc_esr_dci_cpi_snid_mismatch	\
	bit.dci_cpi_snid_mismatch


/*
 * wci_dc_esr_mask
 */
typedef union {
	struct wci_dc_esr_mask {
		uint64_t rsvd_z				: 54;	/* 63:10 */
		uint64_t dif_timeout			: 1;	/* 9 */
		uint64_t dci_d_err_dstat		: 1;	/* 8 */
		uint64_t dco_ce				: 1;	/* 7 */
		uint64_t dc_dif_overflow		: 1;	/* 6 */
		uint64_t dc_launch_queue_overflow	: 1;	/* 5 */
		uint64_t dco_map_error			: 1;	/* 4 */
		uint64_t dco_data_parity_error		: 1;	/* 3 */
		uint64_t dci_d_err			: 1;	/* 2 */
		uint64_t dci_cpi_invalid		: 1;	/* 1 */
		uint64_t dci_cpi_snid_mismatch		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_dc_esr_mask_u;

#define	wci_dc_esr_mask_dif_timeout	\
	bit.dif_timeout
#define	wci_dc_esr_mask_dci_d_err_dstat	\
	bit.dci_d_err_dstat
#define	wci_dc_esr_mask_dco_ce	\
	bit.dco_ce
#define	wci_dc_esr_mask_dc_dif_overflow	\
	bit.dc_dif_overflow
#define	wci_dc_esr_mask_dc_launch_queue_overflow	\
	bit.dc_launch_queue_overflow
#define	wci_dc_esr_mask_dco_map_error	\
	bit.dco_map_error
#define	wci_dc_esr_mask_dco_data_parity_error	\
	bit.dco_data_parity_error
#define	wci_dc_esr_mask_dci_d_err	\
	bit.dci_d_err
#define	wci_dc_esr_mask_dci_cpi_invalid	\
	bit.dci_cpi_invalid
#define	wci_dc_esr_mask_dci_cpi_snid_mismatch	\
	bit.dci_cpi_snid_mismatch


/*
 * wci_dco_state
 */
typedef union {
	struct wci_dco_state {
		uint64_t link_0_lq_overflow		: 1;	/* 63 */
		uint64_t link_1_lq_overflow		: 1;	/* 62 */
		uint64_t link_2_lq_overflow		: 1;	/* 61 */
		uint64_t rsvd_z				: 2;	/* 60:59 */
		uint64_t lpbk_lq_overflow		: 1;	/* 58 */
		uint64_t csr_lq_overflow		: 1;	/* 57 */
		uint64_t rsvd_y				: 5;	/* 56:52 */
		uint64_t dco_map_error_dtarg		: 1;	/* 51 */
		uint64_t dco_map_error_dtransid		: 9;	/* 50:42 */
		uint64_t mtag_ecc_error_aid		: 7;	/* 41:35 */
		uint64_t data_ecc_error_aid		: 7;	/* 34:28 */
		uint64_t data_ecc_ue			: 1;	/* 27 */
		uint64_t mtag_ecc_ue			: 1;	/* 26 */
		uint64_t mtag_syndrome_0		: 4;	/* 25:22 */
		uint64_t mtag_syndrome_1		: 4;	/* 21:18 */
		uint64_t data_syndrome_0		: 9;	/* 17:9 */
		uint64_t data_syndrome_1		: 9;	/* 8:0 */
	} bit;
	uint64_t val;
} wci_dco_state_u;

#define	wci_dco_state_link_0_lq_overflow	\
	bit.link_0_lq_overflow
#define	wci_dco_state_link_1_lq_overflow	\
	bit.link_1_lq_overflow
#define	wci_dco_state_link_2_lq_overflow	\
	bit.link_2_lq_overflow
#define	wci_dco_state_lpbk_lq_overflow	\
	bit.lpbk_lq_overflow
#define	wci_dco_state_csr_lq_overflow	\
	bit.csr_lq_overflow
#define	wci_dco_state_dco_map_error_dtarg	\
	bit.dco_map_error_dtarg
#define	wci_dco_state_dco_map_error_dtransid	\
	bit.dco_map_error_dtransid
#define	wci_dco_state_mtag_ecc_error_aid	\
	bit.mtag_ecc_error_aid
#define	wci_dco_state_data_ecc_error_aid	\
	bit.data_ecc_error_aid
#define	wci_dco_state_data_ecc_ue	\
	bit.data_ecc_ue
#define	wci_dco_state_mtag_ecc_ue	\
	bit.mtag_ecc_ue
#define	wci_dco_state_mtag_syndrome_0	\
	bit.mtag_syndrome_0
#define	wci_dco_state_mtag_syndrome_1	\
	bit.mtag_syndrome_1
#define	wci_dco_state_data_syndrome_0	\
	bit.data_syndrome_0
#define	wci_dco_state_data_syndrome_1	\
	bit.data_syndrome_1


/*
 * wci_dco_ce_count
 */
typedef union {
	struct wci_dco_ce_count {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t ce_count			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_dco_ce_count_u;

#define	wci_dco_ce_count_ce_count	\
	bit.ce_count


/*
 * wci_dci_state
 */
typedef union {
	struct wci_dci_state {
		uint64_t rsvd_z				: 40;	/* 63:24 */
		uint64_t dci_d_err_dtarg		: 1;	/* 23 */
		uint64_t dci_d_err_dtransid		: 9;	/* 22:14 */
		uint64_t dci_cpi_err_dtarg		: 1;	/* 13 */
		uint64_t dci_cpi_err_dtransid		: 9;	/* 12:4 */
		uint64_t dci_cpi_err_source_nid		: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_dci_state_u;

#define	wci_dci_state_dci_d_err_dtarg	\
	bit.dci_d_err_dtarg
#define	wci_dci_state_dci_d_err_dtransid	\
	bit.dci_d_err_dtransid
#define	wci_dci_state_dci_cpi_err_dtarg	\
	bit.dci_cpi_err_dtarg
#define	wci_dci_state_dci_cpi_err_dtransid	\
	bit.dci_cpi_err_dtransid
#define	wci_dci_state_dci_cpi_err_source_nid	\
	bit.dci_cpi_err_source_nid


/*
 * wci_hli_strange_pkt_1
 */
typedef union {
	struct wci_hli_strange_pkt_1 {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t hi				: 31;	/* 30:0 */
	} bit;
	uint64_t val;
} wci_hli_strange_pkt_1_u;

#define	wci_hli_strange_pkt_1_hi	\
	bit.hi


/*
 * wci_hli_strange_pkt_0
 */
typedef union {
	struct wci_hli_strange_pkt_0 {
		uint64_t lo				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_hli_strange_pkt_0_u;

#define	wci_hli_strange_pkt_0_lo	\
	bit.lo


/*
 * wci_hli_esr
 */
typedef union {
	struct wci_hli_esr {
		uint64_t rsvd_z				: 41;	/* 63:23 */
		uint64_t acc_slq_perr			: 1;	/* 22 */
		uint64_t acc_hmq_perr			: 1;	/* 21 */
		uint64_t acc_strange_pkt		: 1;	/* 20 */
		uint64_t acc_bq_unfl			: 1;	/* 19 */
		uint64_t acc_hmq_unfl			: 1;	/* 18 */
		uint64_t acc_hmq_ovfl			: 1;	/* 17 */
		uint64_t acc_slq_ovfl			: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 8;	/* 14:7 */
		uint64_t slq_perr			: 1;	/* 6 */
		uint64_t hmq_perr			: 1;	/* 5 */
		uint64_t strange_pkt			: 1;	/* 4 */
		uint64_t bq_unfl			: 1;	/* 3 */
		uint64_t hmq_unfl			: 1;	/* 2 */
		uint64_t hmq_ovfl			: 1;	/* 1 */
		uint64_t slq_ovfl			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_hli_esr_u;

#define	wci_hli_esr_acc_slq_perr	\
	bit.acc_slq_perr
#define	wci_hli_esr_acc_hmq_perr	\
	bit.acc_hmq_perr
#define	wci_hli_esr_acc_strange_pkt	\
	bit.acc_strange_pkt
#define	wci_hli_esr_acc_bq_unfl	\
	bit.acc_bq_unfl
#define	wci_hli_esr_acc_hmq_unfl	\
	bit.acc_hmq_unfl
#define	wci_hli_esr_acc_hmq_ovfl	\
	bit.acc_hmq_ovfl
#define	wci_hli_esr_acc_slq_ovfl	\
	bit.acc_slq_ovfl
#define	wci_hli_esr_first_error	\
	bit.first_error
#define	wci_hli_esr_slq_perr	\
	bit.slq_perr
#define	wci_hli_esr_hmq_perr	\
	bit.hmq_perr
#define	wci_hli_esr_strange_pkt	\
	bit.strange_pkt
#define	wci_hli_esr_bq_unfl	\
	bit.bq_unfl
#define	wci_hli_esr_hmq_unfl	\
	bit.hmq_unfl
#define	wci_hli_esr_hmq_ovfl	\
	bit.hmq_ovfl
#define	wci_hli_esr_slq_ovfl	\
	bit.slq_ovfl


/*
 * wci_hli_esr_mask
 */
typedef union {
	struct wci_hli_esr_mask {
		uint64_t rsvd_z				: 57;	/* 63:7 */
		uint64_t slq_perr			: 1;	/* 6 */
		uint64_t hmq_perr			: 1;	/* 5 */
		uint64_t strange_pkt			: 1;	/* 4 */
		uint64_t bq_unfl			: 1;	/* 3 */
		uint64_t hmq_unfl			: 1;	/* 2 */
		uint64_t hmq_ovfl			: 1;	/* 1 */
		uint64_t slq_ovfl			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_hli_esr_mask_u;

#define	wci_hli_esr_mask_slq_perr	\
	bit.slq_perr
#define	wci_hli_esr_mask_hmq_perr	\
	bit.hmq_perr
#define	wci_hli_esr_mask_strange_pkt	\
	bit.strange_pkt
#define	wci_hli_esr_mask_bq_unfl	\
	bit.bq_unfl
#define	wci_hli_esr_mask_hmq_unfl	\
	bit.hmq_unfl
#define	wci_hli_esr_mask_hmq_ovfl	\
	bit.hmq_ovfl
#define	wci_hli_esr_mask_slq_ovfl	\
	bit.slq_ovfl


/*
 * wci_hli_state
 */
typedef union {
	struct wci_hli_state {
		uint64_t rsvd_z				: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_y				: 34;	/* 58:25 */
		uint64_t queue				: 17;	/* 24:8 */
		uint64_t index				: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_hli_state_u;

#define	wci_hli_state_esr_index	\
	bit.esr_index
#define	wci_hli_state_queue	\
	bit.queue
#define	wci_hli_state_index	\
	bit.index


/*
 * wci_sfq_esr
 */
typedef union {
	struct wci_sfq_esr {
		uint64_t rsvd_z				: 46;	/* 63:18 */
		uint64_t acc_sfq_perr			: 1;	/* 17 */
		uint64_t acc_sfq_ovfl			: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 13;	/* 14:2 */
		uint64_t sfq_perr			: 1;	/* 1 */
		uint64_t sfq_ovfl			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfq_esr_u;

#define	wci_sfq_esr_acc_sfq_perr	\
	bit.acc_sfq_perr
#define	wci_sfq_esr_acc_sfq_ovfl	\
	bit.acc_sfq_ovfl
#define	wci_sfq_esr_first_error	\
	bit.first_error
#define	wci_sfq_esr_sfq_perr	\
	bit.sfq_perr
#define	wci_sfq_esr_sfq_ovfl	\
	bit.sfq_ovfl


/*
 * wci_sfq_esr_mask
 */
typedef union {
	struct wci_sfq_esr_mask {
		uint64_t rsvd_z				: 62;	/* 63:2 */
		uint64_t sfq_perr			: 1;	/* 1 */
		uint64_t sfq_ovfl			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfq_esr_mask_u;

#define	wci_sfq_esr_mask_sfq_perr	\
	bit.sfq_perr
#define	wci_sfq_esr_mask_sfq_ovfl	\
	bit.sfq_ovfl


/*
 * wci_sfq_state
 */
typedef union {
	struct wci_sfq_state {
		uint64_t rsvd_z				: 55;	/* 63:9 */
		uint64_t index				: 9;	/* 8:0 */
	} bit;
	uint64_t val;
} wci_sfq_state_u;

#define	wci_sfq_state_index	\
	bit.index


/*
 * wci_error_inducement
 */
typedef union {
	struct wci_error_inducement {
		uint64_t rsvd_z				: 8;	/* 63:56 */
		uint64_t internal_sram_vector		: 7;	/* 55:49 */
		uint64_t hmq_p				: 1;	/* 48 */
		uint64_t slq_p				: 1;	/* 47 */
		uint64_t sfq_p				: 1;	/* 46 */
		uint64_t sram_ecc_xor_2_select		: 6;	/* 45:40 */
		uint64_t sram_ecc_xor_1_select		: 6;	/* 39:34 */
		uint64_t sram_p				: 2;	/* 33:32 */
		uint64_t mtag_ecc0_xor			: 4;	/* 31:28 */
		uint64_t mtag_ecc1_xor			: 4;	/* 27:24 */
		uint64_t mtag0_xor			: 3;	/* 23:21 */
		uint64_t mtag1_xor			: 3;	/* 20:18 */
		uint64_t ecc0_xor			: 9;	/* 17:9 */
		uint64_t ecc1_xor			: 9;	/* 8:0 */
	} bit;
	uint64_t val;
} wci_error_inducement_u;

#define	wci_error_inducement_internal_sram_vector	\
	bit.internal_sram_vector
#define	wci_error_inducement_hmq_p	\
	bit.hmq_p
#define	wci_error_inducement_slq_p	\
	bit.slq_p
#define	wci_error_inducement_sfq_p	\
	bit.sfq_p
#define	wci_error_inducement_sram_ecc_xor_2_select	\
	bit.sram_ecc_xor_2_select
#define	wci_error_inducement_sram_ecc_xor_1_select	\
	bit.sram_ecc_xor_1_select
#define	wci_error_inducement_sram_p	\
	bit.sram_p
#define	wci_error_inducement_mtag_ecc0_xor	\
	bit.mtag_ecc0_xor
#define	wci_error_inducement_mtag_ecc1_xor	\
	bit.mtag_ecc1_xor
#define	wci_error_inducement_mtag0_xor	\
	bit.mtag0_xor
#define	wci_error_inducement_mtag1_xor	\
	bit.mtag1_xor
#define	wci_error_inducement_ecc0_xor	\
	bit.ecc0_xor
#define	wci_error_inducement_ecc1_xor	\
	bit.ecc1_xor


/*
 * wci_ue_direction
 */
typedef union {
	struct wci_ue_direction {
		uint64_t rsvd_z				: 25;	/* 63:39 */
		uint64_t outbound_error_detected	: 1;	/* 38 */
		uint64_t ue_inbound			: 1;	/* 37 */
		uint64_t ue_outbound			: 1;	/* 36 */
		uint64_t ue_agent			: 4;	/* 35:32 */
		uint64_t ue_stick			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_ue_direction_u;

#define	wci_ue_direction_outbound_error_detected	\
	bit.outbound_error_detected
#define	wci_ue_direction_ue_inbound	\
	bit.ue_inbound
#define	wci_ue_direction_ue_outbound	\
	bit.ue_outbound
#define	wci_ue_direction_ue_agent	\
	bit.ue_agent
#define	wci_ue_direction_ue_stick	\
	bit.ue_stick


/*
 * wci_generates_cesr_number
 */
typedef union {
	struct wci_generates_cesr_number {
		uint64_t rsvd_z				: 31;	/* 63:33 */
		uint64_t enable				: 1;	/* 32 */
		uint64_t device_vector			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_generates_cesr_number_u;

#define	wci_generates_cesr_number_enable	\
	bit.enable
#define	wci_generates_cesr_number_device_vector	\
	bit.device_vector


/*
 * wci_dif_timeout_cntl
 */
typedef union {
	struct wci_dif_timeout_cntl {
		uint64_t rsvd_z				: 52;	/* 63:12 */
		uint64_t timeout_disable		: 1;	/* 11 */
		uint64_t timeout_freeze			: 1;	/* 10 */
		uint64_t timeout_mag			: 2;	/* 9:8 */
		uint64_t timeout_val			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_dif_timeout_cntl_u;

#define	wci_dif_timeout_cntl_timeout_disable	\
	bit.timeout_disable
#define	wci_dif_timeout_cntl_timeout_freeze	\
	bit.timeout_freeze
#define	wci_dif_timeout_cntl_timeout_mag	\
	bit.timeout_mag
#define	wci_dif_timeout_cntl_timeout_val	\
	bit.timeout_val


/*
 * wci_dif_timeout_count
 */
typedef union {
	struct wci_dif_timeout_count {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t count				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_dif_timeout_count_u;

#define	wci_dif_timeout_count_count	\
	bit.count


/*
 * wci_max
 */
typedef union {
	struct wci_max {
		uint64_t rsvd_z				: 29;	/* 63:35 */
		uint64_t sel				: 3;	/* 34:32 */
		uint64_t value				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_max_u;

#define	wci_max_sel	\
	bit.sel
#define	wci_max_value	\
	bit.value


/*
 * wci_jnk_route_map0
 */
typedef union {
	struct wci_jnk_route_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_jnk_route_map0_u;

#define	wci_jnk_route_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_jnk_route_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_jnk_route_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_jnk_route_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_jnk_route_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_jnk_route_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_jnk_route_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_jnk_route_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_jnk_route_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_jnk_route_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_jnk_route_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_jnk_route_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_jnk_route_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_jnk_route_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_jnk_route_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_jnk_route_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_jnk_route_map1
 */
typedef union {
	struct wci_jnk_route_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_jnk_route_map1_u;

#define	wci_jnk_route_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_jnk_route_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_jnk_route_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_jnk_route_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_jnk_route_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_jnk_route_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_jnk_route_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_jnk_route_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_jnk_route_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_jnk_route_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_jnk_route_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_jnk_route_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_jnk_route_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_jnk_route_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_jnk_route_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_jnk_route_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_stick_rate
 */
typedef union {
	struct wci_stick_rate {
		uint64_t reset				: 1;	/* 63 */
		uint64_t cycle_limit_integer		: 15;	/* 62:48 */
		uint64_t cycle_limit_fraction		: 48;	/* 47:0 */
	} bit;
	uint64_t val;
} wci_stick_rate_u;

#define	wci_stick_rate_reset	\
	bit.reset
#define	wci_stick_rate_cycle_limit_integer	\
	bit.cycle_limit_integer
#define	wci_stick_rate_cycle_limit_fraction	\
	bit.cycle_limit_fraction


/*
 * wci_stick
 */
typedef union {
	struct wci_stick {
		uint64_t count				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_stick_u;

#define	wci_stick_count	\
	bit.count


/*
 * wci_misc_ctr
 */
typedef union {
	struct wci_misc_ctr {
		uint64_t count1				: 32;	/* 63:32 */
		uint64_t count0				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_misc_ctr_u;

#define	wci_misc_ctr_count1	\
	bit.count1
#define	wci_misc_ctr_count0	\
	bit.count0


/*
 * wci_misc_ctr_ctl
 */
typedef union {
	struct wci_misc_ctr_ctl {
		uint64_t rsvd_z				: 43;	/* 63:21 */
		uint64_t duration_mode			: 1;	/* 20 */
		uint64_t cnt1_agent_select		: 4;	/* 19:16 */
		uint64_t cnt1_event_select		: 6;	/* 15:10 */
		uint64_t cnt0_agent_select		: 4;	/* 9:6 */
		uint64_t cnt0_event_select		: 6;	/* 5:0 */
	} bit;
	uint64_t val;
} wci_misc_ctr_ctl_u;

#define	wci_misc_ctr_ctl_duration_mode	\
	bit.duration_mode
#define	wci_misc_ctr_ctl_cnt1_agent_select	\
	bit.cnt1_agent_select
#define	wci_misc_ctr_ctl_cnt1_event_select	\
	bit.cnt1_event_select
#define	wci_misc_ctr_ctl_cnt0_agent_select	\
	bit.cnt0_agent_select
#define	wci_misc_ctr_ctl_cnt0_event_select	\
	bit.cnt0_event_select


/*
 * wci_monitor_pins
 */
typedef union {
	struct wci_monitor_pins {
		uint64_t rsvd_z				: 16;	/* 63:48 */
		uint64_t monitor_pins			: 16;	/* 47:32 */
		uint64_t rsvd_y				: 23;	/* 31:9 */
		uint64_t signal_sel			: 5;	/* 8:4 */
		uint64_t module_sel			: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_monitor_pins_u;

#define	wci_monitor_pins_monitor_pins	\
	bit.monitor_pins
#define	wci_monitor_pins_signal_sel	\
	bit.signal_sel
#define	wci_monitor_pins_module_sel	\
	bit.module_sel


/*
 * wci_sram_config
 */
typedef union {
	struct wci_sram_config {
		uint64_t rsvd_z				: 45;	/* 63:19 */
		uint64_t error_threshold		: 5;	/* 18:14 */
		uint64_t ecc_writeback_disable		: 1;	/* 13 */
		uint64_t ecc_disable			: 1;	/* 12 */
		uint64_t parity_disable			: 1;	/* 11 */
		uint64_t use_ga2lpa			: 1;	/* 10 */
		uint64_t use_directory			: 1;	/* 9 */
		uint64_t dir_stripe			: 2;	/* 8:7 */
		uint64_t rsvd_y				: 2;	/* 6:5 */
		uint64_t sram_size			: 3;	/* 4:2 */
		uint64_t sram_size_pins			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sram_config_u;

#define	wci_sram_config_error_threshold	\
	bit.error_threshold
#define	wci_sram_config_ecc_writeback_disable	\
	bit.ecc_writeback_disable
#define	wci_sram_config_ecc_disable	\
	bit.ecc_disable
#define	wci_sram_config_parity_disable	\
	bit.parity_disable
#define	wci_sram_config_use_ga2lpa	\
	bit.use_ga2lpa
#define	wci_sram_config_use_directory	\
	bit.use_directory
#define	wci_sram_config_dir_stripe	\
	bit.dir_stripe
#define	wci_sram_config_sram_size	\
	bit.sram_size
#define	wci_sram_config_sram_size_pins	\
	bit.sram_size_pins


/*
 * wci_cluster_members_bits
 */
typedef union {
	struct wci_cluster_members_bits {
		uint64_t mask				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_cluster_members_bits_u;

#define	wci_cluster_members_bits_mask	\
	bit.mask


/*
 * wci_nc_slice_config_array
 */
typedef union {
	struct wci_nc_slice_config_array {
		uint64_t config				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_nc_slice_config_array_u;

#define	wci_nc_slice_config_array_config	\
	bit.config


/*
 * wci_cluster_ctr_ctl
 */
typedef union {
	struct wci_cluster_ctr_ctl {
		uint64_t rsvd_z				: 55;	/* 63:9 */
		uint64_t enable_all			: 1;	/* 8 */
		uint64_t cnt1_received_interrupt	: 1;	/* 7 */
		uint64_t cnt1_received_atomic		: 1;	/* 6 */
		uint64_t cnt1_received_cacheable_read	: 1;	/* 5 */
		uint64_t cnt1_received_cacheable_write	: 1;	/* 4 */
		uint64_t cnt0_received_interrupt	: 1;	/* 3 */
		uint64_t cnt0_received_atomic		: 1;	/* 2 */
		uint64_t cnt0_received_cacheable_read	: 1;	/* 1 */
		uint64_t cnt0_received_cacheable_write	: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_cluster_ctr_ctl_u;

#define	wci_cluster_ctr_ctl_enable_all	\
	bit.enable_all
#define	wci_cluster_ctr_ctl_cnt1_received_interrupt	\
	bit.cnt1_received_interrupt
#define	wci_cluster_ctr_ctl_cnt1_received_atomic	\
	bit.cnt1_received_atomic
#define	wci_cluster_ctr_ctl_cnt1_received_cacheable_read	\
	bit.cnt1_received_cacheable_read
#define	wci_cluster_ctr_ctl_cnt1_received_cacheable_write	\
	bit.cnt1_received_cacheable_write
#define	wci_cluster_ctr_ctl_cnt0_received_interrupt	\
	bit.cnt0_received_interrupt
#define	wci_cluster_ctr_ctl_cnt0_received_atomic	\
	bit.cnt0_received_atomic
#define	wci_cluster_ctr_ctl_cnt0_received_cacheable_read	\
	bit.cnt0_received_cacheable_read
#define	wci_cluster_ctr_ctl_cnt0_received_cacheable_write	\
	bit.cnt0_received_cacheable_write


/*
 * wci_sram_status
 */
typedef union {
	struct wci_sram_status {
		uint64_t rsvd_z				: 44;	/* 63:20 */
		uint64_t sticky_error_19		: 1;	/* 19 */
		uint64_t sticky_error_18		: 1;	/* 18 */
		uint64_t sticky_error_17		: 1;	/* 17 */
		uint64_t sticky_error_16		: 1;	/* 16 */
		uint64_t sticky_error_15		: 1;	/* 15 */
		uint64_t sticky_error_14		: 1;	/* 14 */
		uint64_t sticky_error_13		: 1;	/* 13 */
		uint64_t sticky_error_12		: 1;	/* 12 */
		uint64_t sticky_error_11		: 1;	/* 11 */
		uint64_t sticky_error_10		: 1;	/* 10 */
		uint64_t sticky_error_9			: 1;	/* 9 */
		uint64_t sticky_error_8			: 1;	/* 8 */
		uint64_t sticky_error_7			: 1;	/* 7 */
		uint64_t sticky_error_6			: 1;	/* 6 */
		uint64_t sticky_error_5			: 1;	/* 5 */
		uint64_t sticky_error_4			: 1;	/* 4 */
		uint64_t sticky_error_3			: 1;	/* 3 */
		uint64_t sticky_error_2			: 1;	/* 2 */
		uint64_t sticky_error_1			: 1;	/* 1 */
		uint64_t sticky_error_0			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sram_status_u;

#define	wci_sram_status_sticky_error_19	\
	bit.sticky_error_19
#define	wci_sram_status_sticky_error_18	\
	bit.sticky_error_18
#define	wci_sram_status_sticky_error_17	\
	bit.sticky_error_17
#define	wci_sram_status_sticky_error_16	\
	bit.sticky_error_16
#define	wci_sram_status_sticky_error_15	\
	bit.sticky_error_15
#define	wci_sram_status_sticky_error_14	\
	bit.sticky_error_14
#define	wci_sram_status_sticky_error_13	\
	bit.sticky_error_13
#define	wci_sram_status_sticky_error_12	\
	bit.sticky_error_12
#define	wci_sram_status_sticky_error_11	\
	bit.sticky_error_11
#define	wci_sram_status_sticky_error_10	\
	bit.sticky_error_10
#define	wci_sram_status_sticky_error_9	\
	bit.sticky_error_9
#define	wci_sram_status_sticky_error_8	\
	bit.sticky_error_8
#define	wci_sram_status_sticky_error_7	\
	bit.sticky_error_7
#define	wci_sram_status_sticky_error_6	\
	bit.sticky_error_6
#define	wci_sram_status_sticky_error_5	\
	bit.sticky_error_5
#define	wci_sram_status_sticky_error_4	\
	bit.sticky_error_4
#define	wci_sram_status_sticky_error_3	\
	bit.sticky_error_3
#define	wci_sram_status_sticky_error_2	\
	bit.sticky_error_2
#define	wci_sram_status_sticky_error_1	\
	bit.sticky_error_1
#define	wci_sram_status_sticky_error_0	\
	bit.sticky_error_0


/*
 * wci_sram_ce_count
 */
typedef union {
	struct wci_sram_ce_count {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t ce_count			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_sram_ce_count_u;

#define	wci_sram_ce_count_ce_count	\
	bit.ce_count


/*
 * wci_sram_ecc_address
 */
typedef union {
	struct wci_sram_ecc_address {
		uint64_t rsvd_z				: 31;	/* 63:33 */
		uint64_t ce				: 1;	/* 32 */
		uint64_t addr_error			: 1;	/* 31 */
		uint64_t syndrome			: 7;	/* 30:24 */
		uint64_t address			: 24;	/* 23:0 */
	} bit;
	uint64_t val;
} wci_sram_ecc_address_u;

#define	wci_sram_ecc_address_ce	\
	bit.ce
#define	wci_sram_ecc_address_addr_error	\
	bit.addr_error
#define	wci_sram_ecc_address_syndrome	\
	bit.syndrome
#define	wci_sram_ecc_address_address	\
	bit.address


/*
 * wci_cci_esr
 */
typedef union {
	struct wci_cci_esr {
		uint64_t rsvd_z				: 42;	/* 63:22 */
		uint64_t acc_parity			: 1;	/* 21 */
		uint64_t acc_threshold			: 1;	/* 20 */
		uint64_t acc_sram_ae			: 1;	/* 19 */
		uint64_t acc_sram_ue			: 1;	/* 18 */
		uint64_t acc_sram_ce			: 1;	/* 17 */
		uint64_t acc_ce_count_zero		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 9;	/* 14:6 */
		uint64_t parity				: 1;	/* 5 */
		uint64_t threshold			: 1;	/* 4 */
		uint64_t sram_ae			: 1;	/* 3 */
		uint64_t sram_ue			: 1;	/* 2 */
		uint64_t sram_ce			: 1;	/* 1 */
		uint64_t ce_count_zero			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_cci_esr_u;

#define	wci_cci_esr_acc_parity	\
	bit.acc_parity
#define	wci_cci_esr_acc_threshold	\
	bit.acc_threshold
#define	wci_cci_esr_acc_sram_ae	\
	bit.acc_sram_ae
#define	wci_cci_esr_acc_sram_ue	\
	bit.acc_sram_ue
#define	wci_cci_esr_acc_sram_ce	\
	bit.acc_sram_ce
#define	wci_cci_esr_acc_ce_count_zero	\
	bit.acc_ce_count_zero
#define	wci_cci_esr_first_error	\
	bit.first_error
#define	wci_cci_esr_parity	\
	bit.parity
#define	wci_cci_esr_threshold	\
	bit.threshold
#define	wci_cci_esr_sram_ae	\
	bit.sram_ae
#define	wci_cci_esr_sram_ue	\
	bit.sram_ue
#define	wci_cci_esr_sram_ce	\
	bit.sram_ce
#define	wci_cci_esr_ce_count_zero	\
	bit.ce_count_zero


/*
 * wci_cci_esr_mask
 */
typedef union {
	struct wci_cci_esr_mask {
		uint64_t rsvd_z				: 58;	/* 63:6 */
		uint64_t parity				: 1;	/* 5 */
		uint64_t threshold			: 1;	/* 4 */
		uint64_t sram_ae			: 1;	/* 3 */
		uint64_t sram_ue			: 1;	/* 2 */
		uint64_t sram_ce			: 1;	/* 1 */
		uint64_t ce_count_zero			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_cci_esr_mask_u;

#define	wci_cci_esr_mask_parity	\
	bit.parity
#define	wci_cci_esr_mask_threshold	\
	bit.threshold
#define	wci_cci_esr_mask_sram_ae	\
	bit.sram_ae
#define	wci_cci_esr_mask_sram_ue	\
	bit.sram_ue
#define	wci_cci_esr_mask_sram_ce	\
	bit.sram_ce
#define	wci_cci_esr_mask_ce_count_zero	\
	bit.ce_count_zero


/*
 * wci_cci_route_map0
 */
typedef union {
	struct wci_cci_route_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_cci_route_map0_u;

#define	wci_cci_route_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_cci_route_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_cci_route_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_cci_route_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_cci_route_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_cci_route_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_cci_route_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_cci_route_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_cci_route_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_cci_route_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_cci_route_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_cci_route_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_cci_route_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_cci_route_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_cci_route_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_cci_route_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_cci_route_map1
 */
typedef union {
	struct wci_cci_route_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_cci_route_map1_u;

#define	wci_cci_route_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_cci_route_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_cci_route_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_cci_route_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_cci_route_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_cci_route_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_cci_route_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_cci_route_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_cci_route_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_cci_route_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_cci_route_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_cci_route_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_cci_route_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_cci_route_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_cci_route_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_cci_route_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_cluster_write_lockout
 */
typedef union {
	struct wci_cluster_write_lockout {
		uint64_t mask				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_cluster_write_lockout_u;

#define	wci_cluster_write_lockout_mask	\
	bit.mask


/*
 * wci_cluster_config
 */
typedef union {
	struct wci_cluster_config {
		uint64_t rsvd_z				: 61;	/* 63:3 */
		uint64_t in_an_ssm			: 1;	/* 2 */
		uint64_t bad_ecc_on_write_error		: 1;	/* 1 */
		uint64_t allow_multiple_hops		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_cluster_config_u;

#define	wci_cluster_config_in_an_ssm	\
	bit.in_an_ssm
#define	wci_cluster_config_bad_ecc_on_write_error	\
	bit.bad_ecc_on_write_error
#define	wci_cluster_config_allow_multiple_hops	\
	bit.allow_multiple_hops


/*
 * wci_ca_freeze
 */
typedef union {
	struct wci_ca_freeze {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t vector				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_ca_freeze_u;

#define	wci_ca_freeze_vector	\
	bit.vector


/*
 * wci_ca_busy
 */
typedef union {
	struct wci_ca_busy {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t vector				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_ca_busy_u;

#define	wci_ca_busy_vector	\
	bit.vector


/*
 * wci_ca_first_packet_0
 */
typedef union {
	struct wci_ca_first_packet_0 {
		uint64_t addr				: 6;	/* 63:58 */
		uint64_t rsvd_z				: 13;	/* 57:45 */
		uint64_t rtransid			: 9;	/* 44:36 */
		uint64_t scnid				: 8;	/* 35:28 */
		uint64_t rsvd_y				: 8;	/* 27:20 */
		uint64_t rtid				: 5;	/* 19:15 */
		uint64_t snid				: 4;	/* 14:11 */
		uint64_t opcode				: 6;	/* 10:5 */
		uint64_t stripe				: 1;	/* 4 */
		uint64_t dnid				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ca_first_packet_0_u;

#define	wci_ca_first_packet_0_addr	\
	bit.addr
#define	wci_ca_first_packet_0_rtransid	\
	bit.rtransid
#define	wci_ca_first_packet_0_scnid	\
	bit.scnid
#define	wci_ca_first_packet_0_rtid	\
	bit.rtid
#define	wci_ca_first_packet_0_snid	\
	bit.snid
#define	wci_ca_first_packet_0_opcode	\
	bit.opcode
#define	wci_ca_first_packet_0_stripe	\
	bit.stripe
#define	wci_ca_first_packet_0_dnid	\
	bit.dnid


/*
 * wci_ca_first_packet_1
 */
typedef union {
	struct wci_ca_first_packet_1 {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t addr				: 31;	/* 30:0 */
	} bit;
	uint64_t val;
} wci_ca_first_packet_1_u;

#define	wci_ca_first_packet_1_addr	\
	bit.addr


/*
 * wci_ca_ecc_address
 */
typedef union {
	struct wci_ca_ecc_address {
		uint64_t data				: 1;	/* 63 */
		uint64_t ue				: 1;	/* 62 */
		uint64_t passthru			: 1;	/* 61 */
		uint64_t rsvd_z				: 24;	/* 60:37 */
		uint64_t addr				: 37;	/* 36:0 */
	} bit;
	uint64_t val;
} wci_ca_ecc_address_u;

#define	wci_ca_ecc_address_data	\
	bit.data
#define	wci_ca_ecc_address_ue	\
	bit.ue
#define	wci_ca_ecc_address_passthru	\
	bit.passthru
#define	wci_ca_ecc_address_addr	\
	bit.addr


/*
 * wci_ca_error_transaction
 */
typedef union {
	struct wci_ca_error_transaction {
		uint64_t status				: 4;	/* 63:60 */
		uint64_t esr_reg			: 1;	/* 59 */
		uint64_t esr_index			: 4;	/* 58:55 */
		uint64_t ctid				: 5;	/* 54:50 */
		uint64_t targid				: 9;	/* 49:41 */
		uint64_t second_atransid		: 4;	/* 40:37 */
		uint64_t first_atransid			: 4;	/* 36:33 */
		uint64_t cmd_grant_1			: 1;	/* 32 */
		uint64_t cmd_grant_2			: 1;	/* 31 */
		uint64_t reissue_pending_1		: 1;	/* 30 */
		uint64_t reissue_pending_2		: 1;	/* 29 */
		uint64_t transid_released		: 1;	/* 28 */
		uint64_t const_grant			: 1;	/* 27 */
		uint64_t map_grant			: 1;	/* 26 */
		uint64_t map_queued			: 1;	/* 25 */
		uint64_t reuse_timeout			: 1;	/* 24 */
		uint64_t data_timeout			: 1;	/* 23 */
		uint64_t aphase_timeout			: 1;	/* 22 */
		uint64_t pkt_sent			: 1;	/* 21 */
		uint64_t pkt_queued			: 1;	/* 20 */
		uint64_t cpi_inval			: 1;	/* 19 */
		uint64_t cpi_queued			: 1;	/* 18 */
		uint64_t cpi_err			: 1;	/* 17 */
		uint64_t cpi_rcv2			: 1;	/* 16 */
		uint64_t cpi_rcv1			: 1;	/* 15 */
		uint64_t dc_atom_err			: 1;	/* 14 */
		uint64_t dc_snd2			: 1;	/* 13 */
		uint64_t dc_rcv2			: 1;	/* 12 */
		uint64_t dc_err1			: 1;	/* 11 */
		uint64_t pull_late			: 1;	/* 10 */
		uint64_t pull_timeout			: 1;	/* 9 */
		uint64_t pull_cleared			: 1;	/* 8 */
		uint64_t pull_err			: 1;	/* 7 */
		uint64_t pull_ok			: 1;	/* 6 */
		uint64_t snoop_late			: 1;	/* 5 */
		uint64_t snoop2				: 2;	/* 4:3 */
		uint64_t snoop1				: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_ca_error_transaction_u;

#define	wci_ca_error_transaction_status	\
	bit.status
#define	wci_ca_error_transaction_esr_reg	\
	bit.esr_reg
#define	wci_ca_error_transaction_esr_index	\
	bit.esr_index
#define	wci_ca_error_transaction_ctid	\
	bit.ctid
#define	wci_ca_error_transaction_targid	\
	bit.targid
#define	wci_ca_error_transaction_second_atransid	\
	bit.second_atransid
#define	wci_ca_error_transaction_first_atransid	\
	bit.first_atransid
#define	wci_ca_error_transaction_cmd_grant_1	\
	bit.cmd_grant_1
#define	wci_ca_error_transaction_cmd_grant_2	\
	bit.cmd_grant_2
#define	wci_ca_error_transaction_reissue_pending_1	\
	bit.reissue_pending_1
#define	wci_ca_error_transaction_reissue_pending_2	\
	bit.reissue_pending_2
#define	wci_ca_error_transaction_transid_released	\
	bit.transid_released
#define	wci_ca_error_transaction_const_grant	\
	bit.const_grant
#define	wci_ca_error_transaction_map_grant	\
	bit.map_grant
#define	wci_ca_error_transaction_map_queued	\
	bit.map_queued
#define	wci_ca_error_transaction_reuse_timeout	\
	bit.reuse_timeout
#define	wci_ca_error_transaction_data_timeout	\
	bit.data_timeout
#define	wci_ca_error_transaction_aphase_timeout	\
	bit.aphase_timeout
#define	wci_ca_error_transaction_pkt_sent	\
	bit.pkt_sent
#define	wci_ca_error_transaction_pkt_queued	\
	bit.pkt_queued
#define	wci_ca_error_transaction_cpi_inval	\
	bit.cpi_inval
#define	wci_ca_error_transaction_cpi_queued	\
	bit.cpi_queued
#define	wci_ca_error_transaction_cpi_err	\
	bit.cpi_err
#define	wci_ca_error_transaction_cpi_rcv2	\
	bit.cpi_rcv2
#define	wci_ca_error_transaction_cpi_rcv1	\
	bit.cpi_rcv1
#define	wci_ca_error_transaction_dc_atom_err	\
	bit.dc_atom_err
#define	wci_ca_error_transaction_dc_snd2	\
	bit.dc_snd2
#define	wci_ca_error_transaction_dc_rcv2	\
	bit.dc_rcv2
#define	wci_ca_error_transaction_dc_err1	\
	bit.dc_err1
#define	wci_ca_error_transaction_pull_late	\
	bit.pull_late
#define	wci_ca_error_transaction_pull_timeout	\
	bit.pull_timeout
#define	wci_ca_error_transaction_pull_cleared	\
	bit.pull_cleared
#define	wci_ca_error_transaction_pull_err	\
	bit.pull_err
#define	wci_ca_error_transaction_pull_ok	\
	bit.pull_ok
#define	wci_ca_error_transaction_snoop_late	\
	bit.snoop_late
#define	wci_ca_error_transaction_snoop2	\
	bit.snoop2
#define	wci_ca_error_transaction_snoop1	\
	bit.snoop1


/*
 * wci_ca_timeout_config
 */
typedef union {
	struct wci_ca_timeout_config {
		uint64_t rsvd_z				: 6;	/* 63:58 */
		uint64_t dphase_disable			: 1;	/* 57 */
		uint64_t dphase_freeze			: 1;	/* 56 */
		uint64_t rsvd_y				: 2;	/* 55:54 */
		uint64_t dphase_dest_mag		: 2;	/* 53:52 */
		uint64_t dphase_dest_val		: 8;	/* 51:44 */
		uint64_t rsvd_x				: 2;	/* 43:42 */
		uint64_t dphase_pass_mag		: 2;	/* 41:40 */
		uint64_t dphase_pass_val		: 8;	/* 39:32 */
		uint64_t rsvd_w				: 2;	/* 31:30 */
		uint64_t aphase_disable			: 1;	/* 29 */
		uint64_t aphase_freeze			: 1;	/* 28 */
		uint64_t rsvd_v				: 2;	/* 27:26 */
		uint64_t aphase_mag			: 2;	/* 25:24 */
		uint64_t aphase_val			: 8;	/* 23:16 */
		uint64_t rsvd_u				: 1;	/* 15 */
		uint64_t reuse_disable			: 1;	/* 14 */
		uint64_t reuse_freeze			: 1;	/* 13 */
		uint64_t reuse_mag			: 2;	/* 12:11 */
		uint64_t reuse_val			: 11;	/* 10:0 */
	} bit;
	uint64_t val;
} wci_ca_timeout_config_u;

#define	wci_ca_timeout_config_dphase_disable	\
	bit.dphase_disable
#define	wci_ca_timeout_config_dphase_freeze	\
	bit.dphase_freeze
#define	wci_ca_timeout_config_dphase_dest_mag	\
	bit.dphase_dest_mag
#define	wci_ca_timeout_config_dphase_dest_val	\
	bit.dphase_dest_val
#define	wci_ca_timeout_config_dphase_pass_mag	\
	bit.dphase_pass_mag
#define	wci_ca_timeout_config_dphase_pass_val	\
	bit.dphase_pass_val
#define	wci_ca_timeout_config_aphase_disable	\
	bit.aphase_disable
#define	wci_ca_timeout_config_aphase_freeze	\
	bit.aphase_freeze
#define	wci_ca_timeout_config_aphase_mag	\
	bit.aphase_mag
#define	wci_ca_timeout_config_aphase_val	\
	bit.aphase_val
#define	wci_ca_timeout_config_reuse_disable	\
	bit.reuse_disable
#define	wci_ca_timeout_config_reuse_freeze	\
	bit.reuse_freeze
#define	wci_ca_timeout_config_reuse_mag	\
	bit.reuse_mag
#define	wci_ca_timeout_config_reuse_val	\
	bit.reuse_val


/*
 * wci_ca_config
 */
typedef union {
	struct wci_ca_config {
		uint64_t rsvd_z				: 58;	/* 63:6 */
		uint64_t cluster_disable		: 1;	/* 5 */
		uint64_t reuse_timeout_limit		: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_ca_config_u;

#define	wci_ca_config_cluster_disable	\
	bit.cluster_disable
#define	wci_ca_config_reuse_timeout_limit	\
	bit.reuse_timeout_limit


/*
 * wci_ca_esr_0
 */
typedef union {
	struct wci_ca_esr_0 {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t acc_unexpect_cpi_ack		: 1;	/* 30 */
		uint64_t acc_unexpect_dc_ack		: 1;	/* 29 */
		uint64_t acc_unexpect_pull		: 1;	/* 28 */
		uint64_t acc_unexpect_reissue		: 1;	/* 27 */
		uint64_t acc_atomic_map_mismatch	: 1;	/* 26 */
		uint64_t acc_unmapped			: 1;	/* 25 */
		uint64_t acc_uncorrectable_mtag_error	: 1;	/* 24 */
		uint64_t acc_uncorrectable_data_error	: 1;	/* 23 */
		uint64_t acc_correctable_mtag_error	: 1;	/* 22 */
		uint64_t acc_correctable_data_error	: 1;	/* 21 */
		uint64_t acc_dstat_inconsistent		: 1;	/* 20 */
		uint64_t acc_mtag_mismatch_within_hcl	: 1;	/* 19 */
		uint64_t acc_mtag_mismatch_between_hcls	: 1;	/* 18 */
		uint64_t acc_remote_timeout		: 1;	/* 17 */
		uint64_t acc_local_timeout		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t unexpect_cpi_ack		: 1;	/* 14 */
		uint64_t unexpect_dc_ack		: 1;	/* 13 */
		uint64_t unexpect_pull			: 1;	/* 12 */
		uint64_t unexpect_reissue		: 1;	/* 11 */
		uint64_t atomic_map_mismatch		: 1;	/* 10 */
		uint64_t unmapped			: 1;	/* 9 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 8 */
		uint64_t uncorrectable_data_error	: 1;	/* 7 */
		uint64_t correctable_mtag_error		: 1;	/* 6 */
		uint64_t correctable_data_error		: 1;	/* 5 */
		uint64_t dstat_inconsistent		: 1;	/* 4 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 3 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 2 */
		uint64_t remote_timeout			: 1;	/* 1 */
		uint64_t local_timeout			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ca_esr_0_u;

#define	wci_ca_esr_0_acc_unexpect_cpi_ack	\
	bit.acc_unexpect_cpi_ack
#define	wci_ca_esr_0_acc_unexpect_dc_ack	\
	bit.acc_unexpect_dc_ack
#define	wci_ca_esr_0_acc_unexpect_pull	\
	bit.acc_unexpect_pull
#define	wci_ca_esr_0_acc_unexpect_reissue	\
	bit.acc_unexpect_reissue
#define	wci_ca_esr_0_acc_atomic_map_mismatch	\
	bit.acc_atomic_map_mismatch
#define	wci_ca_esr_0_acc_unmapped	\
	bit.acc_unmapped
#define	wci_ca_esr_0_acc_uncorrectable_mtag_error	\
	bit.acc_uncorrectable_mtag_error
#define	wci_ca_esr_0_acc_uncorrectable_data_error	\
	bit.acc_uncorrectable_data_error
#define	wci_ca_esr_0_acc_correctable_mtag_error	\
	bit.acc_correctable_mtag_error
#define	wci_ca_esr_0_acc_correctable_data_error	\
	bit.acc_correctable_data_error
#define	wci_ca_esr_0_acc_dstat_inconsistent	\
	bit.acc_dstat_inconsistent
#define	wci_ca_esr_0_acc_mtag_mismatch_within_hcl	\
	bit.acc_mtag_mismatch_within_hcl
#define	wci_ca_esr_0_acc_mtag_mismatch_between_hcls	\
	bit.acc_mtag_mismatch_between_hcls
#define	wci_ca_esr_0_acc_remote_timeout	\
	bit.acc_remote_timeout
#define	wci_ca_esr_0_acc_local_timeout	\
	bit.acc_local_timeout
#define	wci_ca_esr_0_first_error	\
	bit.first_error
#define	wci_ca_esr_0_unexpect_cpi_ack	\
	bit.unexpect_cpi_ack
#define	wci_ca_esr_0_unexpect_dc_ack	\
	bit.unexpect_dc_ack
#define	wci_ca_esr_0_unexpect_pull	\
	bit.unexpect_pull
#define	wci_ca_esr_0_unexpect_reissue	\
	bit.unexpect_reissue
#define	wci_ca_esr_0_atomic_map_mismatch	\
	bit.atomic_map_mismatch
#define	wci_ca_esr_0_unmapped	\
	bit.unmapped
#define	wci_ca_esr_0_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_ca_esr_0_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_ca_esr_0_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_ca_esr_0_correctable_data_error	\
	bit.correctable_data_error
#define	wci_ca_esr_0_dstat_inconsistent	\
	bit.dstat_inconsistent
#define	wci_ca_esr_0_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_ca_esr_0_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_ca_esr_0_remote_timeout	\
	bit.remote_timeout
#define	wci_ca_esr_0_local_timeout	\
	bit.local_timeout


/*
 * wci_ca_esr_1
 */
typedef union {
	struct wci_ca_esr_1 {
		uint64_t rsvd_z				: 43;	/* 63:21 */
		uint64_t acc_qlimit_timeout		: 1;	/* 20 */
		uint64_t acc_internal_error		: 1;	/* 19 */
		uint64_t acc_cmmu_ecc_error		: 1;	/* 18 */
		uint64_t acc_wrong_cmd			: 1;	/* 17 */
		uint64_t acc_data_phase_timeout		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 10;	/* 14:5 */
		uint64_t qlimit_timeout			: 1;	/* 4 */
		uint64_t internal_error			: 1;	/* 3 */
		uint64_t cmmu_ecc_error			: 1;	/* 2 */
		uint64_t wrong_cmd			: 1;	/* 1 */
		uint64_t data_phase_timeout		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ca_esr_1_u;

#define	wci_ca_esr_1_acc_qlimit_timeout	\
	bit.acc_qlimit_timeout
#define	wci_ca_esr_1_acc_internal_error	\
	bit.acc_internal_error
#define	wci_ca_esr_1_acc_cmmu_ecc_error	\
	bit.acc_cmmu_ecc_error
#define	wci_ca_esr_1_acc_wrong_cmd	\
	bit.acc_wrong_cmd
#define	wci_ca_esr_1_acc_data_phase_timeout	\
	bit.acc_data_phase_timeout
#define	wci_ca_esr_1_first_error	\
	bit.first_error
#define	wci_ca_esr_1_qlimit_timeout	\
	bit.qlimit_timeout
#define	wci_ca_esr_1_internal_error	\
	bit.internal_error
#define	wci_ca_esr_1_cmmu_ecc_error	\
	bit.cmmu_ecc_error
#define	wci_ca_esr_1_wrong_cmd	\
	bit.wrong_cmd
#define	wci_ca_esr_1_data_phase_timeout	\
	bit.data_phase_timeout


/*
 * wci_ca_esr_mask
 */
typedef union {
	struct wci_ca_esr_mask {
		uint64_t rsvd_z				: 43;	/* 63:21 */
		uint64_t qlimit_timeout			: 1;	/* 20 */
		uint64_t internal_error			: 1;	/* 19 */
		uint64_t cmmu_ecc_error			: 1;	/* 18 */
		uint64_t wrong_cmd			: 1;	/* 17 */
		uint64_t data_phase_timeout		: 1;	/* 16 */
		uint64_t rsvd_y				: 1;	/* 15 */
		uint64_t unexpect_cpi_ack		: 1;	/* 14 */
		uint64_t unexpect_dc_ack		: 1;	/* 13 */
		uint64_t unexpect_pull			: 1;	/* 12 */
		uint64_t unexpect_reissue		: 1;	/* 11 */
		uint64_t atomic_map_mismatch		: 1;	/* 10 */
		uint64_t unmapped			: 1;	/* 9 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 8 */
		uint64_t uncorrectable_data_error	: 1;	/* 7 */
		uint64_t correctable_mtag_error		: 1;	/* 6 */
		uint64_t correctable_data_error		: 1;	/* 5 */
		uint64_t dstat_inconsistent		: 1;	/* 4 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 3 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 2 */
		uint64_t remote_timeout			: 1;	/* 1 */
		uint64_t local_timeout			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ca_esr_mask_u;

#define	wci_ca_esr_mask_qlimit_timeout	\
	bit.qlimit_timeout
#define	wci_ca_esr_mask_internal_error	\
	bit.internal_error
#define	wci_ca_esr_mask_cmmu_ecc_error	\
	bit.cmmu_ecc_error
#define	wci_ca_esr_mask_wrong_cmd	\
	bit.wrong_cmd
#define	wci_ca_esr_mask_data_phase_timeout	\
	bit.data_phase_timeout
#define	wci_ca_esr_mask_unexpect_cpi_ack	\
	bit.unexpect_cpi_ack
#define	wci_ca_esr_mask_unexpect_dc_ack	\
	bit.unexpect_dc_ack
#define	wci_ca_esr_mask_unexpect_pull	\
	bit.unexpect_pull
#define	wci_ca_esr_mask_unexpect_reissue	\
	bit.unexpect_reissue
#define	wci_ca_esr_mask_atomic_map_mismatch	\
	bit.atomic_map_mismatch
#define	wci_ca_esr_mask_unmapped	\
	bit.unmapped
#define	wci_ca_esr_mask_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_ca_esr_mask_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_ca_esr_mask_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_ca_esr_mask_correctable_data_error	\
	bit.correctable_data_error
#define	wci_ca_esr_mask_dstat_inconsistent	\
	bit.dstat_inconsistent
#define	wci_ca_esr_mask_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_ca_esr_mask_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_ca_esr_mask_remote_timeout	\
	bit.remote_timeout
#define	wci_ca_esr_mask_local_timeout	\
	bit.local_timeout


/*
 * wci_cluster_sync
 */
typedef union {
	struct wci_cluster_sync {
		uint64_t sync_in_progress		: 1;	/* 63 */
		uint64_t rsvd_z				: 31;	/* 62:32 */
		uint64_t cag_busy			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_cluster_sync_u;

#define	wci_cluster_sync_sync_in_progress	\
	bit.sync_in_progress
#define	wci_cluster_sync_cag_busy	\
	bit.cag_busy


/*
 * wci_ca_timeout_config_2
 */
typedef union {
	struct wci_ca_timeout_config_2 {
		uint64_t rsvd_z				: 39;	/* 63:25 */
		uint64_t sfi_targid_timeout_disable	: 1;	/* 24 */
		uint64_t rsvd_y				: 1;	/* 23 */
		uint64_t sfi_targid_timeout_sel		: 3;	/* 22:20 */
		uint64_t rsvd_x				: 6;	/* 19:14 */
		uint64_t loc_reuse_mag			: 2;	/* 13:12 */
		uint64_t rsvd_w				: 1;	/* 11 */
		uint64_t loc_reuse_val			: 11;	/* 10:0 */
	} bit;
	uint64_t val;
} wci_ca_timeout_config_2_u;

#define	wci_ca_timeout_config_2_sfi_targid_timeout_disable	\
	bit.sfi_targid_timeout_disable
#define	wci_ca_timeout_config_2_sfi_targid_timeout_sel	\
	bit.sfi_targid_timeout_sel
#define	wci_ca_timeout_config_2_loc_reuse_mag	\
	bit.loc_reuse_mag
#define	wci_ca_timeout_config_2_loc_reuse_val	\
	bit.loc_reuse_val


/*
 * wci_ca_error_transaction_2
 */
typedef union {
	struct wci_ca_error_transaction_2 {
		uint64_t rsvd_z				: 60;	/* 63:4 */
		uint64_t snoop2_late_reissue		: 1;	/* 3 */
		uint64_t dc_rcv2_barrier		: 1;	/* 2 */
		uint64_t cpi_barrier			: 1;	/* 1 */
		uint64_t cpi_rcv2_barrier		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ca_error_transaction_2_u;

#define	wci_ca_error_transaction_2_snoop2_late_reissue	\
	bit.snoop2_late_reissue
#define	wci_ca_error_transaction_2_dc_rcv2_barrier	\
	bit.dc_rcv2_barrier
#define	wci_ca_error_transaction_2_cpi_barrier	\
	bit.cpi_barrier
#define	wci_ca_error_transaction_2_cpi_rcv2_barrier	\
	bit.cpi_rcv2_barrier


/*
 * wci_qlim_config_cag
 */
typedef union {
	struct wci_qlim_config_cag {
		uint64_t freeze				: 1;	/* 63 */
		uint64_t disable			: 1;	/* 62 */
		uint64_t rsvd_z				: 9;	/* 61:53 */
		uint64_t max_discard			: 13;	/* 52:40 */
		uint64_t rsvd_y				: 2;	/* 39:38 */
		uint64_t num2discard			: 10;	/* 37:28 */
		uint64_t rsvd_x				: 11;	/* 27:17 */
		uint64_t tmin_mag			: 13;	/* 16:4 */
		uint64_t rsvd_w				: 1;	/* 3 */
		uint64_t hwmark_exp			: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_qlim_config_cag_u;

#define	wci_qlim_config_cag_freeze	\
	bit.freeze
#define	wci_qlim_config_cag_disable	\
	bit.disable
#define	wci_qlim_config_cag_max_discard	\
	bit.max_discard
#define	wci_qlim_config_cag_num2discard	\
	bit.num2discard
#define	wci_qlim_config_cag_tmin_mag	\
	bit.tmin_mag
#define	wci_qlim_config_cag_hwmark_exp	\
	bit.hwmark_exp


/*
 * wci_qlim_cag_timer
 */
typedef union {
	struct wci_qlim_cag_timer {
		uint64_t rsvd_z				: 35;	/* 63:29 */
		uint64_t value				: 29;	/* 28:0 */
	} bit;
	uint64_t val;
} wci_qlim_cag_timer_u;

#define	wci_qlim_cag_timer_value	\
	bit.value


/*
 * wci_board2cnid_array
 */
typedef union {
	struct wci_board2cnid_array {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t data				: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_board2cnid_array_u;

#define	wci_board2cnid_array_data	\
	bit.data


/*
 * wci_inid2dnid_array
 */
typedef union {
	struct wci_inid2dnid_array {
		uint64_t rsvd_z				: 60;	/* 63:4 */
		uint64_t dnid				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_inid2dnid_array_u;

#define	wci_inid2dnid_array_dnid	\
	bit.dnid


/*
 * wci_ra_freeze
 */
typedef union {
	struct wci_ra_freeze {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t vector				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_ra_freeze_u;

#define	wci_ra_freeze_vector	\
	bit.vector


/*
 * wci_ra_busy
 */
typedef union {
	struct wci_ra_busy {
		uint64_t request_synch			: 32;	/* 63:32 */
		uint64_t vector				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_ra_busy_u;

#define	wci_ra_busy_request_synch	\
	bit.request_synch
#define	wci_ra_busy_vector	\
	bit.vector


/*
 * wci_ra_first_error_agent
 */
typedef union {
	struct wci_ra_first_error_agent {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_z				: 54;	/* 58:5 */
		uint64_t instance			: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_ra_first_error_agent_u;

#define	wci_ra_first_error_agent_esr_reg	\
	bit.esr_reg
#define	wci_ra_first_error_agent_esr_index	\
	bit.esr_index
#define	wci_ra_first_error_agent_instance	\
	bit.instance


/*
 * wci_ra_first_packet_0
 */
typedef union {
	struct wci_ra_first_packet_0 {
		uint64_t lo				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_ra_first_packet_0_u;

#define	wci_ra_first_packet_0_lo	\
	bit.lo


/*
 * wci_ra_first_packet_1
 */
typedef union {
	struct wci_ra_first_packet_1 {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t sfq_input			: 2;	/* 58:57 */
		uint64_t transaction_type		: 6;	/* 56:51 */
		uint64_t rsvd_z				: 20;	/* 50:31 */
		uint64_t hi				: 31;	/* 30:0 */
	} bit;
	uint64_t val;
} wci_ra_first_packet_1_u;

#define	wci_ra_first_packet_1_esr_reg	\
	bit.esr_reg
#define	wci_ra_first_packet_1_esr_index	\
	bit.esr_index
#define	wci_ra_first_packet_1_sfq_input	\
	bit.sfq_input
#define	wci_ra_first_packet_1_transaction_type	\
	bit.transaction_type
#define	wci_ra_first_packet_1_hi	\
	bit.hi


/*
 * wci_ra_ecc_address
 */
typedef union {
	struct wci_ra_ecc_address {
		uint64_t data				: 1;	/* 63 */
		uint64_t ue				: 1;	/* 62 */
		uint64_t atransid			: 9;	/* 61:53 */
		uint64_t transaction_type		: 6;	/* 52:47 */
		uint64_t rsvd_z				: 4;	/* 46:43 */
		uint64_t addr				: 39;	/* 42:4 */
		uint64_t rsvd_y				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ra_ecc_address_u;

#define	wci_ra_ecc_address_data	\
	bit.data
#define	wci_ra_ecc_address_ue	\
	bit.ue
#define	wci_ra_ecc_address_atransid	\
	bit.atransid
#define	wci_ra_ecc_address_transaction_type	\
	bit.transaction_type
#define	wci_ra_ecc_address_addr	\
	bit.addr


/*
 * wci_ra_error_transaction_0
 */
typedef union {
	struct wci_ra_error_transaction_0 {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_z				: 3;	/* 58:56 */
		uint64_t cesr_index			: 8;	/* 55:48 */
		uint64_t atransid			: 9;	/* 47:39 */
		uint64_t addr				: 39;	/* 38:0 */
	} bit;
	uint64_t val;
} wci_ra_error_transaction_0_u;

#define	wci_ra_error_transaction_0_esr_reg	\
	bit.esr_reg
#define	wci_ra_error_transaction_0_esr_index	\
	bit.esr_index
#define	wci_ra_error_transaction_0_cesr_index	\
	bit.cesr_index
#define	wci_ra_error_transaction_0_atransid	\
	bit.atransid
#define	wci_ra_error_transaction_0_addr	\
	bit.addr


/*
 * wci_ra_error_transaction_1
 */
typedef union {
	struct wci_ra_error_transaction_1 {
		uint64_t fsm_state			: 7;	/* 63:57 */
		uint64_t rsvd_z				: 25;	/* 56:32 */
		uint64_t rtid				: 4;	/* 31:28 */
		uint64_t rsvd_y				: 1;	/* 27 */
		uint64_t dh_errors			: 7;	/* 26:20 */
		uint64_t error_code			: 4;	/* 19:16 */
		uint64_t rcv_cntr			: 2;	/* 15:14 */
		uint64_t snd_cntr			: 2;	/* 13:12 */
		uint64_t tmot_err			: 1;	/* 11 */
		uint64_t rh_err				: 1;	/* 10 */
		uint64_t transaction_type		: 6;	/* 9:4 */
		uint64_t rsvd_x				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ra_error_transaction_1_u;

#define	wci_ra_error_transaction_1_fsm_state	\
	bit.fsm_state
#define	wci_ra_error_transaction_1_rtid	\
	bit.rtid
#define	wci_ra_error_transaction_1_dh_errors	\
	bit.dh_errors
#define	wci_ra_error_transaction_1_error_code	\
	bit.error_code
#define	wci_ra_error_transaction_1_rcv_cntr	\
	bit.rcv_cntr
#define	wci_ra_error_transaction_1_snd_cntr	\
	bit.snd_cntr
#define	wci_ra_error_transaction_1_tmot_err	\
	bit.tmot_err
#define	wci_ra_error_transaction_1_rh_err	\
	bit.rh_err
#define	wci_ra_error_transaction_1_transaction_type	\
	bit.transaction_type


/*
 * wci_ra_timeout_config
 */
typedef union {
	struct wci_ra_timeout_config {
		uint64_t rsvd_z				: 22;	/* 63:42 */
		uint64_t clus_disable			: 1;	/* 41 */
		uint64_t clus_freeze			: 1;	/* 40 */
		uint64_t rsvd_y				: 2;	/* 39:38 */
		uint64_t clus_aphase_mag		: 2;	/* 37:36 */
		uint64_t rsvd_x				: 2;	/* 35:34 */
		uint64_t clus_aphase_val		: 8;	/* 33:26 */
		uint64_t clus_dphase_mag		: 2;	/* 25:24 */
		uint64_t clus_dphase_val		: 8;	/* 23:16 */
		uint64_t rsvd_w				: 2;	/* 15:14 */
		uint64_t ssm_disable			: 1;	/* 13 */
		uint64_t ssm_freeze			: 1;	/* 12 */
		uint64_t rsvd_v				: 2;	/* 11:10 */
		uint64_t ssm_mag			: 2;	/* 9:8 */
		uint64_t ssm_val			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_ra_timeout_config_u;

#define	wci_ra_timeout_config_clus_disable	\
	bit.clus_disable
#define	wci_ra_timeout_config_clus_freeze	\
	bit.clus_freeze
#define	wci_ra_timeout_config_clus_aphase_mag	\
	bit.clus_aphase_mag
#define	wci_ra_timeout_config_clus_aphase_val	\
	bit.clus_aphase_val
#define	wci_ra_timeout_config_clus_dphase_mag	\
	bit.clus_dphase_mag
#define	wci_ra_timeout_config_clus_dphase_val	\
	bit.clus_dphase_val
#define	wci_ra_timeout_config_ssm_disable	\
	bit.ssm_disable
#define	wci_ra_timeout_config_ssm_freeze	\
	bit.ssm_freeze
#define	wci_ra_timeout_config_ssm_mag	\
	bit.ssm_mag
#define	wci_ra_timeout_config_ssm_val	\
	bit.ssm_val


/*
 * wci_ra_esr_0
 */
typedef union {
	struct wci_ra_esr_0 {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t acc_ssm_timeout		: 1;	/* 30 */
		uint64_t acc_wrong_reply		: 1;	/* 29 */
		uint64_t acc_illegal_sender		: 1;	/* 28 */
		uint64_t acc_not_expected_reply		: 1;	/* 27 */
		uint64_t acc_qlimit_timeout		: 1;	/* 26 */
		uint64_t acc_unexpected_snid		: 1;	/* 25 */
		uint64_t acc_wrong_safari_command	: 1;	/* 24 */
		uint64_t acc_non_block_trans		: 1;	/* 23 */
		uint64_t acc_cesr_error_wrong		: 1;	/* 22 */
		uint64_t acc_cluster_local_timeout	: 1;	/* 21 */
		uint64_t acc_cluster_remote_timeout	: 1;	/* 20 */
		uint64_t acc_mtag_mismatch_between_hcls	: 1;	/* 19 */
		uint64_t acc_mtag_mismatch_within_hcl	: 1;	/* 18 */
		uint64_t acc_dstat_inconsistent		: 1;	/* 17 */
		uint64_t acc_mtag_not_gm		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t ssm_timeout			: 1;	/* 14 */
		uint64_t wrong_reply			: 1;	/* 13 */
		uint64_t illegal_sender			: 1;	/* 12 */
		uint64_t not_expected_reply		: 1;	/* 11 */
		uint64_t qlimit_timeout			: 1;	/* 10 */
		uint64_t unexpected_snid		: 1;	/* 9 */
		uint64_t wrong_safari_command		: 1;	/* 8 */
		uint64_t non_block_trans		: 1;	/* 7 */
		uint64_t cesr_error_wrong		: 1;	/* 6 */
		uint64_t cluster_local_timeout		: 1;	/* 5 */
		uint64_t cluster_remote_timeout		: 1;	/* 4 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 3 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 2 */
		uint64_t dstat_inconsistent		: 1;	/* 1 */
		uint64_t mtag_not_gm			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ra_esr_0_u;

#define	wci_ra_esr_0_acc_ssm_timeout	\
	bit.acc_ssm_timeout
#define	wci_ra_esr_0_acc_wrong_reply	\
	bit.acc_wrong_reply
#define	wci_ra_esr_0_acc_illegal_sender	\
	bit.acc_illegal_sender
#define	wci_ra_esr_0_acc_not_expected_reply	\
	bit.acc_not_expected_reply
#define	wci_ra_esr_0_acc_qlimit_timeout	\
	bit.acc_qlimit_timeout
#define	wci_ra_esr_0_acc_unexpected_snid	\
	bit.acc_unexpected_snid
#define	wci_ra_esr_0_acc_wrong_safari_command	\
	bit.acc_wrong_safari_command
#define	wci_ra_esr_0_acc_non_block_trans	\
	bit.acc_non_block_trans
#define	wci_ra_esr_0_acc_cesr_error_wrong	\
	bit.acc_cesr_error_wrong
#define	wci_ra_esr_0_acc_cluster_local_timeout	\
	bit.acc_cluster_local_timeout
#define	wci_ra_esr_0_acc_cluster_remote_timeout	\
	bit.acc_cluster_remote_timeout
#define	wci_ra_esr_0_acc_mtag_mismatch_between_hcls	\
	bit.acc_mtag_mismatch_between_hcls
#define	wci_ra_esr_0_acc_mtag_mismatch_within_hcl	\
	bit.acc_mtag_mismatch_within_hcl
#define	wci_ra_esr_0_acc_dstat_inconsistent	\
	bit.acc_dstat_inconsistent
#define	wci_ra_esr_0_acc_mtag_not_gm	\
	bit.acc_mtag_not_gm
#define	wci_ra_esr_0_first_error	\
	bit.first_error
#define	wci_ra_esr_0_ssm_timeout	\
	bit.ssm_timeout
#define	wci_ra_esr_0_wrong_reply	\
	bit.wrong_reply
#define	wci_ra_esr_0_illegal_sender	\
	bit.illegal_sender
#define	wci_ra_esr_0_not_expected_reply	\
	bit.not_expected_reply
#define	wci_ra_esr_0_qlimit_timeout	\
	bit.qlimit_timeout
#define	wci_ra_esr_0_unexpected_snid	\
	bit.unexpected_snid
#define	wci_ra_esr_0_wrong_safari_command	\
	bit.wrong_safari_command
#define	wci_ra_esr_0_non_block_trans	\
	bit.non_block_trans
#define	wci_ra_esr_0_cesr_error_wrong	\
	bit.cesr_error_wrong
#define	wci_ra_esr_0_cluster_local_timeout	\
	bit.cluster_local_timeout
#define	wci_ra_esr_0_cluster_remote_timeout	\
	bit.cluster_remote_timeout
#define	wci_ra_esr_0_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_ra_esr_0_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_ra_esr_0_dstat_inconsistent	\
	bit.dstat_inconsistent
#define	wci_ra_esr_0_mtag_not_gm	\
	bit.mtag_not_gm


/*
 * wci_ra_esr_1
 */
typedef union {
	struct wci_ra_esr_1 {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t acc_write_lockout		: 1;	/* 30 */
		uint64_t acc_unexpected_mtag		: 1;	/* 29 */
		uint64_t acc_address_not_mapped		: 1;	/* 28 */
		uint64_t acc_illegal_home_node		: 1;	/* 27 */
		uint64_t acc_lpa2ga_ecc_error		: 1;	/* 26 */
		uint64_t acc_lpa2ga_violation		: 1;	/* 25 */
		uint64_t acc_unexpected_send_ack	: 1;	/* 24 */
		uint64_t acc_unexpected_receive_ack	: 1;	/* 23 */
		uint64_t acc_invalid_reply_pattern	: 1;	/* 22 */
		uint64_t acc_hw_protocol_error		: 1;	/* 21 */
		uint64_t acc_hw_fifo_ovfl_unfl		: 1;	/* 20 */
		uint64_t acc_correctable_mtag_error	: 1;	/* 19 */
		uint64_t acc_correctable_data_error	: 1;	/* 18 */
		uint64_t acc_uncorrectable_mtag_error	: 1;	/* 17 */
		uint64_t acc_uncorrectable_data_error	: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t write_lockout			: 1;	/* 14 */
		uint64_t unexpected_mtag		: 1;	/* 13 */
		uint64_t address_not_mapped		: 1;	/* 12 */
		uint64_t illegal_home_node		: 1;	/* 11 */
		uint64_t lpa2ga_ecc_error		: 1;	/* 10 */
		uint64_t lpa2ga_violation		: 1;	/* 9 */
		uint64_t unexpected_send_ack		: 1;	/* 8 */
		uint64_t unexpected_receive_ack		: 1;	/* 7 */
		uint64_t invalid_reply_pattern		: 1;	/* 6 */
		uint64_t hw_protocol_error		: 1;	/* 5 */
		uint64_t hw_fifo_ovfl_unfl		: 1;	/* 4 */
		uint64_t correctable_mtag_error		: 1;	/* 3 */
		uint64_t correctable_data_error		: 1;	/* 2 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 1 */
		uint64_t uncorrectable_data_error	: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ra_esr_1_u;

#define	wci_ra_esr_1_acc_write_lockout	\
	bit.acc_write_lockout
#define	wci_ra_esr_1_acc_unexpected_mtag	\
	bit.acc_unexpected_mtag
#define	wci_ra_esr_1_acc_address_not_mapped	\
	bit.acc_address_not_mapped
#define	wci_ra_esr_1_acc_illegal_home_node	\
	bit.acc_illegal_home_node
#define	wci_ra_esr_1_acc_lpa2ga_ecc_error	\
	bit.acc_lpa2ga_ecc_error
#define	wci_ra_esr_1_acc_lpa2ga_violation	\
	bit.acc_lpa2ga_violation
#define	wci_ra_esr_1_acc_unexpected_send_ack	\
	bit.acc_unexpected_send_ack
#define	wci_ra_esr_1_acc_unexpected_receive_ack	\
	bit.acc_unexpected_receive_ack
#define	wci_ra_esr_1_acc_invalid_reply_pattern	\
	bit.acc_invalid_reply_pattern
#define	wci_ra_esr_1_acc_hw_protocol_error	\
	bit.acc_hw_protocol_error
#define	wci_ra_esr_1_acc_hw_fifo_ovfl_unfl	\
	bit.acc_hw_fifo_ovfl_unfl
#define	wci_ra_esr_1_acc_correctable_mtag_error	\
	bit.acc_correctable_mtag_error
#define	wci_ra_esr_1_acc_correctable_data_error	\
	bit.acc_correctable_data_error
#define	wci_ra_esr_1_acc_uncorrectable_mtag_error	\
	bit.acc_uncorrectable_mtag_error
#define	wci_ra_esr_1_acc_uncorrectable_data_error	\
	bit.acc_uncorrectable_data_error
#define	wci_ra_esr_1_first_error	\
	bit.first_error
#define	wci_ra_esr_1_write_lockout	\
	bit.write_lockout
#define	wci_ra_esr_1_unexpected_mtag	\
	bit.unexpected_mtag
#define	wci_ra_esr_1_address_not_mapped	\
	bit.address_not_mapped
#define	wci_ra_esr_1_illegal_home_node	\
	bit.illegal_home_node
#define	wci_ra_esr_1_lpa2ga_ecc_error	\
	bit.lpa2ga_ecc_error
#define	wci_ra_esr_1_lpa2ga_violation	\
	bit.lpa2ga_violation
#define	wci_ra_esr_1_unexpected_send_ack	\
	bit.unexpected_send_ack
#define	wci_ra_esr_1_unexpected_receive_ack	\
	bit.unexpected_receive_ack
#define	wci_ra_esr_1_invalid_reply_pattern	\
	bit.invalid_reply_pattern
#define	wci_ra_esr_1_hw_protocol_error	\
	bit.hw_protocol_error
#define	wci_ra_esr_1_hw_fifo_ovfl_unfl	\
	bit.hw_fifo_ovfl_unfl
#define	wci_ra_esr_1_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_ra_esr_1_correctable_data_error	\
	bit.correctable_data_error
#define	wci_ra_esr_1_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_ra_esr_1_uncorrectable_data_error	\
	bit.uncorrectable_data_error


/*
 * wci_ra_esr_mask
 */
typedef union {
	struct wci_ra_esr_mask {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t write_lockout			: 1;	/* 30 */
		uint64_t unexpected_mtag		: 1;	/* 29 */
		uint64_t address_not_mapped		: 1;	/* 28 */
		uint64_t illegal_home_node		: 1;	/* 27 */
		uint64_t lpa2ga_ecc_error		: 1;	/* 26 */
		uint64_t lpa2ga_violation		: 1;	/* 25 */
		uint64_t unexpected_send_ack		: 1;	/* 24 */
		uint64_t unexpected_receive_ack		: 1;	/* 23 */
		uint64_t invalid_reply_pattern		: 1;	/* 22 */
		uint64_t hw_protocol_error		: 1;	/* 21 */
		uint64_t hw_fifo_ovfl_unfl		: 1;	/* 20 */
		uint64_t correctable_mtag_error		: 1;	/* 19 */
		uint64_t correctable_data_error		: 1;	/* 18 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 17 */
		uint64_t uncorrectable_data_error	: 1;	/* 16 */
		uint64_t rsvd_y				: 1;	/* 15 */
		uint64_t ssm_timeout			: 1;	/* 14 */
		uint64_t wrong_reply			: 1;	/* 13 */
		uint64_t illegal_sender			: 1;	/* 12 */
		uint64_t not_expected_reply		: 1;	/* 11 */
		uint64_t qlimit_timeout			: 1;	/* 10 */
		uint64_t unexpected_snid		: 1;	/* 9 */
		uint64_t wrong_safari_command		: 1;	/* 8 */
		uint64_t non_block_trans		: 1;	/* 7 */
		uint64_t cesr_error_wrong		: 1;	/* 6 */
		uint64_t cluster_local_timeout		: 1;	/* 5 */
		uint64_t cluster_remote_timeout		: 1;	/* 4 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 3 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 2 */
		uint64_t dstat_inconsistent		: 1;	/* 1 */
		uint64_t mtag_not_gm			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ra_esr_mask_u;

#define	wci_ra_esr_mask_write_lockout	\
	bit.write_lockout
#define	wci_ra_esr_mask_unexpected_mtag	\
	bit.unexpected_mtag
#define	wci_ra_esr_mask_address_not_mapped	\
	bit.address_not_mapped
#define	wci_ra_esr_mask_illegal_home_node	\
	bit.illegal_home_node
#define	wci_ra_esr_mask_lpa2ga_ecc_error	\
	bit.lpa2ga_ecc_error
#define	wci_ra_esr_mask_lpa2ga_violation	\
	bit.lpa2ga_violation
#define	wci_ra_esr_mask_unexpected_send_ack	\
	bit.unexpected_send_ack
#define	wci_ra_esr_mask_unexpected_receive_ack	\
	bit.unexpected_receive_ack
#define	wci_ra_esr_mask_invalid_reply_pattern	\
	bit.invalid_reply_pattern
#define	wci_ra_esr_mask_hw_protocol_error	\
	bit.hw_protocol_error
#define	wci_ra_esr_mask_hw_fifo_ovfl_unfl	\
	bit.hw_fifo_ovfl_unfl
#define	wci_ra_esr_mask_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_ra_esr_mask_correctable_data_error	\
	bit.correctable_data_error
#define	wci_ra_esr_mask_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_ra_esr_mask_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_ra_esr_mask_ssm_timeout	\
	bit.ssm_timeout
#define	wci_ra_esr_mask_wrong_reply	\
	bit.wrong_reply
#define	wci_ra_esr_mask_illegal_sender	\
	bit.illegal_sender
#define	wci_ra_esr_mask_not_expected_reply	\
	bit.not_expected_reply
#define	wci_ra_esr_mask_qlimit_timeout	\
	bit.qlimit_timeout
#define	wci_ra_esr_mask_unexpected_snid	\
	bit.unexpected_snid
#define	wci_ra_esr_mask_wrong_safari_command	\
	bit.wrong_safari_command
#define	wci_ra_esr_mask_non_block_trans	\
	bit.non_block_trans
#define	wci_ra_esr_mask_cesr_error_wrong	\
	bit.cesr_error_wrong
#define	wci_ra_esr_mask_cluster_local_timeout	\
	bit.cluster_local_timeout
#define	wci_ra_esr_mask_cluster_remote_timeout	\
	bit.cluster_remote_timeout
#define	wci_ra_esr_mask_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_ra_esr_mask_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_ra_esr_mask_dstat_inconsistent	\
	bit.dstat_inconsistent
#define	wci_ra_esr_mask_mtag_not_gm	\
	bit.mtag_not_gm


/*
 * wci_ra_status_array
 */
typedef union {
	struct wci_ra_status_array {
		uint64_t fsm_state			: 7;	/* 63:57 */
		uint64_t dtargid			: 9;	/* 56:48 */
		uint64_t atransid			: 9;	/* 47:39 */
		uint64_t addr				: 39;	/* 38:0 */
	} bit;
	uint64_t val;
} wci_ra_status_array_u;

#define	wci_ra_status_array_fsm_state	\
	bit.fsm_state
#define	wci_ra_status_array_dtargid	\
	bit.dtargid
#define	wci_ra_status_array_atransid	\
	bit.atransid
#define	wci_ra_status_array_addr	\
	bit.addr


/*
 * wci_ra_status_2_array
 */
typedef union {
	struct wci_ra_status_2_array {
		uint64_t tflg_ecc			: 1;	/* 63 */
		uint64_t replies_rcvd_vld		: 1;	/* 62 */
		uint64_t stripe				: 1;	/* 61 */
		uint64_t rh_sm				: 2;	/* 60:59 */
		uint64_t rcvd_mtag			: 3;	/* 58:56 */
		uint64_t cesr_index			: 8;	/* 55:48 */
		uint64_t ntransid			: 9;	/* 47:39 */
		uint64_t dtarg				: 1;	/* 38 */
		uint64_t saw_s_ack			: 1;	/* 37 */
		uint64_t saw_h_d			: 1;	/* 36 */
		uint64_t saw_s_d			: 1;	/* 35 */
		uint64_t saw_h_pull			: 1;	/* 34 */
		uint64_t saw_h_pull_m			: 1;	/* 33 */
		uint64_t saw_h_pull_i			: 1;	/* 32 */
		uint64_t replies_rcvd			: 16;	/* 31:16 */
		uint64_t rcv_cntr			: 2;	/* 15:14 */
		uint64_t snd_cntr			: 2;	/* 13:12 */
		uint64_t saw_h_nack			: 1;	/* 11 */
		uint64_t saw_h_err			: 1;	/* 10 */
		uint64_t transaction_type		: 6;	/* 9:4 */
		uint64_t hnid				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ra_status_2_array_u;

#define	wci_ra_status_2_array_tflg_ecc	\
	bit.tflg_ecc
#define	wci_ra_status_2_array_replies_rcvd_vld	\
	bit.replies_rcvd_vld
#define	wci_ra_status_2_array_stripe	\
	bit.stripe
#define	wci_ra_status_2_array_rh_sm	\
	bit.rh_sm
#define	wci_ra_status_2_array_rcvd_mtag	\
	bit.rcvd_mtag
#define	wci_ra_status_2_array_cesr_index	\
	bit.cesr_index
#define	wci_ra_status_2_array_ntransid	\
	bit.ntransid
#define	wci_ra_status_2_array_dtarg	\
	bit.dtarg
#define	wci_ra_status_2_array_saw_s_ack	\
	bit.saw_s_ack
#define	wci_ra_status_2_array_saw_h_d	\
	bit.saw_h_d
#define	wci_ra_status_2_array_saw_s_d	\
	bit.saw_s_d
#define	wci_ra_status_2_array_saw_h_pull	\
	bit.saw_h_pull
#define	wci_ra_status_2_array_saw_h_pull_m	\
	bit.saw_h_pull_m
#define	wci_ra_status_2_array_saw_h_pull_i	\
	bit.saw_h_pull_i
#define	wci_ra_status_2_array_replies_rcvd	\
	bit.replies_rcvd
#define	wci_ra_status_2_array_rcv_cntr	\
	bit.rcv_cntr
#define	wci_ra_status_2_array_snd_cntr	\
	bit.snd_cntr
#define	wci_ra_status_2_array_saw_h_nack	\
	bit.saw_h_nack
#define	wci_ra_status_2_array_saw_h_err	\
	bit.saw_h_err
#define	wci_ra_status_2_array_transaction_type	\
	bit.transaction_type
#define	wci_ra_status_2_array_hnid	\
	bit.hnid


/*
 * wci_ra_write_lockout_status
 */
typedef union {
	struct wci_ra_write_lockout_status {
		uint64_t rsvd_z				: 54;	/* 63:10 */
		uint64_t link_stripe			: 2;	/* 9:8 */
		uint64_t nc_slice			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_ra_write_lockout_status_u;

#define	wci_ra_write_lockout_status_link_stripe	\
	bit.link_stripe
#define	wci_ra_write_lockout_status_nc_slice	\
	bit.nc_slice


/*
 * wci_rag_route_map0
 */
typedef union {
	struct wci_rag_route_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_rag_route_map0_u;

#define	wci_rag_route_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_rag_route_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_rag_route_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_rag_route_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_rag_route_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_rag_route_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_rag_route_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_rag_route_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_rag_route_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_rag_route_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_rag_route_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_rag_route_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_rag_route_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_rag_route_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_rag_route_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_rag_route_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_rag_route_map1
 */
typedef union {
	struct wci_rag_route_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_rag_route_map1_u;

#define	wci_rag_route_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_rag_route_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_rag_route_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_rag_route_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_rag_route_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_rag_route_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_rag_route_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_rag_route_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_rag_route_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_rag_route_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_rag_route_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_rag_route_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_rag_route_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_rag_route_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_rag_route_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_rag_route_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_cluster_error_status_array
 */
typedef union {
	struct wci_cluster_error_status_array {
		uint64_t rsvd_z				: 58;	/* 63:6 */
		uint64_t disable_fail_fast		: 1;	/* 5 */
		uint64_t not_valid			: 1;	/* 4 */
		uint64_t value				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_cluster_error_status_array_u;

#define	wci_cluster_error_status_array_disable_fail_fast	\
	bit.disable_fail_fast
#define	wci_cluster_error_status_array_not_valid	\
	bit.not_valid
#define	wci_cluster_error_status_array_value	\
	bit.value


/*
 * wci_cluster_error_count
 */
typedef union {
	struct wci_cluster_error_count {
		uint64_t value				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_cluster_error_count_u;

#define	wci_cluster_error_count_value	\
	bit.value


/*
 * wci_int_dest_busy_count
 */
typedef union {
	struct wci_int_dest_busy_count {
		uint64_t value				: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_int_dest_busy_count_u;

#define	wci_int_dest_busy_count_value	\
	bit.value


/*
 * wci_qlim_3req_priority
 */
typedef union {
	struct wci_qlim_3req_priority {
		uint64_t rsvd_z				: 28;	/* 63:36 */
		uint64_t num_slots			: 4;	/* 35:32 */
		uint64_t arb_slots			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_qlim_3req_priority_u;

#define	wci_qlim_3req_priority_num_slots	\
	bit.num_slots
#define	wci_qlim_3req_priority_arb_slots	\
	bit.arb_slots


/*
 * wci_qlim_2req_priority
 */
typedef union {
	struct wci_qlim_2req_priority {
		uint64_t rsvd_z				: 4;	/* 63:60 */
		uint64_t ciq_niq_num_slots		: 4;	/* 59:56 */
		uint64_t piq_ciq_num_slots		: 4;	/* 55:52 */
		uint64_t niq_piq_num_slots		: 4;	/* 51:48 */
		uint64_t ciq_niq_arb_slots		: 16;	/* 47:32 */
		uint64_t piq_ciq_arb_slots		: 16;	/* 31:16 */
		uint64_t niq_piq_arb_slots		: 16;	/* 15:0 */
	} bit;
	uint64_t val;
} wci_qlim_2req_priority_u;

#define	wci_qlim_2req_priority_ciq_niq_num_slots	\
	bit.ciq_niq_num_slots
#define	wci_qlim_2req_priority_piq_ciq_num_slots	\
	bit.piq_ciq_num_slots
#define	wci_qlim_2req_priority_niq_piq_num_slots	\
	bit.niq_piq_num_slots
#define	wci_qlim_2req_priority_ciq_niq_arb_slots	\
	bit.ciq_niq_arb_slots
#define	wci_qlim_2req_priority_piq_ciq_arb_slots	\
	bit.piq_ciq_arb_slots
#define	wci_qlim_2req_priority_niq_piq_arb_slots	\
	bit.niq_piq_arb_slots


/*
 * wci_qlim_config_piq
 */
typedef union {
	struct wci_qlim_config_piq {
		uint64_t freeze				: 1;	/* 63 */
		uint64_t disable			: 1;	/* 62 */
		uint64_t rsvd_z				: 2;	/* 61:60 */
		uint64_t discard_cnt_timer_en		: 1;	/* 59 */
		uint64_t discard_cnt_timer_mag		: 3;	/* 58:56 */
		uint64_t discard_cnt_timer_val		: 3;	/* 55:53 */
		uint64_t max_discard			: 13;	/* 52:40 */
		uint64_t rsvd_y				: 2;	/* 39:38 */
		uint64_t num2discard			: 10;	/* 37:28 */
		uint64_t rsvd_x				: 4;	/* 27:24 */
		uint64_t decay				: 4;	/* 23:20 */
		uint64_t rsvd_w				: 3;	/* 19:17 */
		uint64_t tmin_mag			: 13;	/* 16:4 */
		uint64_t rsvd_v				: 1;	/* 3 */
		uint64_t hwmark_exp			: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_qlim_config_piq_u;

#define	wci_qlim_config_piq_freeze	\
	bit.freeze
#define	wci_qlim_config_piq_disable	\
	bit.disable
#define	wci_qlim_config_piq_discard_cnt_timer_en	\
	bit.discard_cnt_timer_en
#define	wci_qlim_config_piq_discard_cnt_timer_mag	\
	bit.discard_cnt_timer_mag
#define	wci_qlim_config_piq_discard_cnt_timer_val	\
	bit.discard_cnt_timer_val
#define	wci_qlim_config_piq_max_discard	\
	bit.max_discard
#define	wci_qlim_config_piq_num2discard	\
	bit.num2discard
#define	wci_qlim_config_piq_decay	\
	bit.decay
#define	wci_qlim_config_piq_tmin_mag	\
	bit.tmin_mag
#define	wci_qlim_config_piq_hwmark_exp	\
	bit.hwmark_exp


/*
 * wci_qlim_config_niq
 */
typedef union {
	struct wci_qlim_config_niq {
		uint64_t freeze				: 1;	/* 63 */
		uint64_t disable			: 1;	/* 62 */
		uint64_t rsvd_z				: 2;	/* 61:60 */
		uint64_t discard_cnt_timer_en		: 1;	/* 59 */
		uint64_t discard_cnt_timer_mag		: 3;	/* 58:56 */
		uint64_t discard_cnt_timer_val		: 3;	/* 55:53 */
		uint64_t max_discard			: 13;	/* 52:40 */
		uint64_t rsvd_y				: 2;	/* 39:38 */
		uint64_t num2discard			: 10;	/* 37:28 */
		uint64_t rsvd_x				: 4;	/* 27:24 */
		uint64_t decay				: 4;	/* 23:20 */
		uint64_t rsvd_w				: 3;	/* 19:17 */
		uint64_t tmin_mag			: 13;	/* 16:4 */
		uint64_t rsvd_v				: 1;	/* 3 */
		uint64_t hwmark_exp			: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_qlim_config_niq_u;

#define	wci_qlim_config_niq_freeze	\
	bit.freeze
#define	wci_qlim_config_niq_disable	\
	bit.disable
#define	wci_qlim_config_niq_discard_cnt_timer_en	\
	bit.discard_cnt_timer_en
#define	wci_qlim_config_niq_discard_cnt_timer_mag	\
	bit.discard_cnt_timer_mag
#define	wci_qlim_config_niq_discard_cnt_timer_val	\
	bit.discard_cnt_timer_val
#define	wci_qlim_config_niq_max_discard	\
	bit.max_discard
#define	wci_qlim_config_niq_num2discard	\
	bit.num2discard
#define	wci_qlim_config_niq_decay	\
	bit.decay
#define	wci_qlim_config_niq_tmin_mag	\
	bit.tmin_mag
#define	wci_qlim_config_niq_hwmark_exp	\
	bit.hwmark_exp


/*
 * wci_qlim_config_ciq
 */
typedef union {
	struct wci_qlim_config_ciq {
		uint64_t freeze				: 1;	/* 63 */
		uint64_t disable			: 1;	/* 62 */
		uint64_t rsvd_z				: 2;	/* 61:60 */
		uint64_t discard_cnt_timer_en		: 1;	/* 59 */
		uint64_t discard_cnt_timer_mag		: 3;	/* 58:56 */
		uint64_t discard_cnt_timer_val		: 3;	/* 55:53 */
		uint64_t max_discard			: 13;	/* 52:40 */
		uint64_t rsvd_y				: 2;	/* 39:38 */
		uint64_t num2discard			: 10;	/* 37:28 */
		uint64_t rsvd_x				: 4;	/* 27:24 */
		uint64_t decay				: 4;	/* 23:20 */
		uint64_t rsvd_w				: 3;	/* 19:17 */
		uint64_t tmin_mag			: 13;	/* 16:4 */
		uint64_t rsvd_v				: 1;	/* 3 */
		uint64_t hwmark_exp			: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_qlim_config_ciq_u;

#define	wci_qlim_config_ciq_freeze	\
	bit.freeze
#define	wci_qlim_config_ciq_disable	\
	bit.disable
#define	wci_qlim_config_ciq_discard_cnt_timer_en	\
	bit.discard_cnt_timer_en
#define	wci_qlim_config_ciq_discard_cnt_timer_mag	\
	bit.discard_cnt_timer_mag
#define	wci_qlim_config_ciq_discard_cnt_timer_val	\
	bit.discard_cnt_timer_val
#define	wci_qlim_config_ciq_max_discard	\
	bit.max_discard
#define	wci_qlim_config_ciq_num2discard	\
	bit.num2discard
#define	wci_qlim_config_ciq_decay	\
	bit.decay
#define	wci_qlim_config_ciq_tmin_mag	\
	bit.tmin_mag
#define	wci_qlim_config_ciq_hwmark_exp	\
	bit.hwmark_exp


/*
 * wci_qlim_piq_timer
 */
typedef union {
	struct wci_qlim_piq_timer {
		uint64_t rsvd_z				: 35;	/* 63:29 */
		uint64_t value				: 29;	/* 28:0 */
	} bit;
	uint64_t val;
} wci_qlim_piq_timer_u;

#define	wci_qlim_piq_timer_value	\
	bit.value


/*
 * wci_qlim_niq_timer
 */
typedef union {
	struct wci_qlim_niq_timer {
		uint64_t rsvd_z				: 35;	/* 63:29 */
		uint64_t value				: 29;	/* 28:0 */
	} bit;
	uint64_t val;
} wci_qlim_niq_timer_u;

#define	wci_qlim_niq_timer_value	\
	bit.value


/*
 * wci_qlim_ciq_timer
 */
typedef union {
	struct wci_qlim_ciq_timer {
		uint64_t rsvd_z				: 35;	/* 63:29 */
		uint64_t value				: 29;	/* 28:0 */
	} bit;
	uint64_t val;
} wci_qlim_ciq_timer_u;

#define	wci_qlim_ciq_timer_value	\
	bit.value


/*
 * wci_os_cluster_disable
 */
typedef union {
	struct wci_os_cluster_disable {
		uint64_t rsvd_z				: 60;	/* 63:4 */
		uint64_t ca_cluster_disable		: 1;	/* 3 */
		uint64_t ra_piq_disable			: 1;	/* 2 */
		uint64_t ra_niq_disable			: 1;	/* 1 */
		uint64_t ra_ciq_disable			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_os_cluster_disable_u;

#define	wci_os_cluster_disable_ca_cluster_disable	\
	bit.ca_cluster_disable
#define	wci_os_cluster_disable_ra_piq_disable	\
	bit.ra_piq_disable
#define	wci_os_cluster_disable_ra_niq_disable	\
	bit.ra_niq_disable
#define	wci_os_cluster_disable_ra_ciq_disable	\
	bit.ra_ciq_disable


/*
 * wci_sc_cluster_disable
 */
typedef union {
	struct wci_sc_cluster_disable {
		uint64_t rsvd_z				: 60;	/* 63:4 */
		uint64_t ca_cluster_disable		: 1;	/* 3 */
		uint64_t ra_piq_disable			: 1;	/* 2 */
		uint64_t ra_niq_disable			: 1;	/* 1 */
		uint64_t ra_ciq_disable			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sc_cluster_disable_u;

#define	wci_sc_cluster_disable_ca_cluster_disable	\
	bit.ca_cluster_disable
#define	wci_sc_cluster_disable_ra_piq_disable	\
	bit.ra_piq_disable
#define	wci_sc_cluster_disable_ra_niq_disable	\
	bit.ra_niq_disable
#define	wci_sc_cluster_disable_ra_ciq_disable	\
	bit.ra_ciq_disable


/*
 * wci_ha_freeze
 */
typedef union {
	struct wci_ha_freeze {
		uint64_t rsvd_z				: 48;	/* 63:16 */
		uint64_t vector				: 16;	/* 15:0 */
	} bit;
	uint64_t val;
} wci_ha_freeze_u;

#define	wci_ha_freeze_vector	\
	bit.vector


/*
 * wci_ha_busy
 */
typedef union {
	struct wci_ha_busy {
		uint64_t rsvd_z				: 48;	/* 63:16 */
		uint64_t vector				: 16;	/* 15:0 */
	} bit;
	uint64_t val;
} wci_ha_busy_u;

#define	wci_ha_busy_vector	\
	bit.vector


/*
 * wci_ha_first_error_agent
 */
typedef union {
	struct wci_ha_first_error_agent {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_z				: 54;	/* 58:5 */
		uint64_t instance			: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_ha_first_error_agent_u;

#define	wci_ha_first_error_agent_esr_reg	\
	bit.esr_reg
#define	wci_ha_first_error_agent_esr_index	\
	bit.esr_index
#define	wci_ha_first_error_agent_instance	\
	bit.instance


/*
 * wci_ha_first_packet_0
 */
typedef union {
	struct wci_ha_first_packet_0 {
		uint64_t lo_a				: 28;	/* 63:36 */
		uint64_t rsvd_z				: 8;	/* 35:28 */
		uint64_t lo_b				: 28;	/* 27:0 */
	} bit;
	uint64_t val;
} wci_ha_first_packet_0_u;

#define	wci_ha_first_packet_0_lo_a	\
	bit.lo_a
#define	wci_ha_first_packet_0_lo_b	\
	bit.lo_b


/*
 * wci_ha_first_packet_1
 */
typedef union {
	struct wci_ha_first_packet_1 {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_z				: 28;	/* 58:31 */
		uint64_t hi				: 31;	/* 30:0 */
	} bit;
	uint64_t val;
} wci_ha_first_packet_1_u;

#define	wci_ha_first_packet_1_esr_reg	\
	bit.esr_reg
#define	wci_ha_first_packet_1_esr_index	\
	bit.esr_index
#define	wci_ha_first_packet_1_hi	\
	bit.hi


/*
 * wci_ha_ecc_address
 */
typedef union {
	struct wci_ha_ecc_address {
		uint64_t data				: 1;	/* 63 */
		uint64_t ue				: 1;	/* 62 */
		uint64_t rsvd_z				: 19;	/* 61:43 */
		uint64_t addr				: 39;	/* 42:4 */
		uint64_t rsvd_y				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ha_ecc_address_u;

#define	wci_ha_ecc_address_data	\
	bit.data
#define	wci_ha_ecc_address_ue	\
	bit.ue
#define	wci_ha_ecc_address_addr	\
	bit.addr


/*
 * wci_ha_error_address
 */
typedef union {
	struct wci_ha_error_address {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_z				: 16;	/* 58:43 */
		uint64_t addr				: 39;	/* 42:4 */
		uint64_t rsvd_y				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ha_error_address_u;

#define	wci_ha_error_address_esr_reg	\
	bit.esr_reg
#define	wci_ha_error_address_esr_index	\
	bit.esr_index
#define	wci_ha_error_address_addr	\
	bit.addr


/*
 * wci_ha_timeout_config
 */
typedef union {
	struct wci_ha_timeout_config {
		uint64_t rsvd_z				: 50;	/* 63:14 */
		uint64_t ssm_disable			: 1;	/* 13 */
		uint64_t ssm_freeze			: 1;	/* 12 */
		uint64_t rsvd_y				: 2;	/* 11:10 */
		uint64_t ssm_mag			: 2;	/* 9:8 */
		uint64_t ssm_val			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_ha_timeout_config_u;

#define	wci_ha_timeout_config_ssm_disable	\
	bit.ssm_disable
#define	wci_ha_timeout_config_ssm_freeze	\
	bit.ssm_freeze
#define	wci_ha_timeout_config_ssm_mag	\
	bit.ssm_mag
#define	wci_ha_timeout_config_ssm_val	\
	bit.ssm_val


/*
 * wci_ha_esr_0
 */
typedef union {
	struct wci_ha_esr_0 {
		uint64_t rsvd_z				: 35;	/* 63:29 */
		uint64_t acc_unexpected_snid		: 1;	/* 28 */
		uint64_t acc_address_not_mapped_io	: 1;	/* 27 */
		uint64_t acc_dir_parity_error		: 1;	/* 26 */
		uint64_t acc_not_expected_compl		: 1;	/* 25 */
		uint64_t acc_illegal_sender		: 1;	/* 24 */
		uint64_t acc_wrong_cmd			: 1;	/* 23 */
		uint64_t acc_uncorrectable_mtag_error	: 1;	/* 22 */
		uint64_t acc_uncorrectable_data_error	: 1;	/* 21 */
		uint64_t acc_correctable_mtag_error	: 1;	/* 20 */
		uint64_t acc_correctable_data_error	: 1;	/* 19 */
		uint64_t acc_mtag_mismatch_within_hcl	: 1;	/* 18 */
		uint64_t acc_mtag_mismatch_between_hcls	: 1;	/* 17 */
		uint64_t acc_timeout			: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 2;	/* 14:13 */
		uint64_t unexpected_snid		: 1;	/* 12 */
		uint64_t address_not_mapped_io		: 1;	/* 11 */
		uint64_t dir_parity_error		: 1;	/* 10 */
		uint64_t not_expected_compl		: 1;	/* 9 */
		uint64_t illegal_sender			: 1;	/* 8 */
		uint64_t wrong_cmd			: 1;	/* 7 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 6 */
		uint64_t uncorrectable_data_error	: 1;	/* 5 */
		uint64_t correctable_mtag_error		: 1;	/* 4 */
		uint64_t correctable_data_error		: 1;	/* 3 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 2 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 1 */
		uint64_t timeout			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ha_esr_0_u;

#define	wci_ha_esr_0_acc_unexpected_snid	\
	bit.acc_unexpected_snid
#define	wci_ha_esr_0_acc_address_not_mapped_io	\
	bit.acc_address_not_mapped_io
#define	wci_ha_esr_0_acc_dir_parity_error	\
	bit.acc_dir_parity_error
#define	wci_ha_esr_0_acc_not_expected_compl	\
	bit.acc_not_expected_compl
#define	wci_ha_esr_0_acc_illegal_sender	\
	bit.acc_illegal_sender
#define	wci_ha_esr_0_acc_wrong_cmd	\
	bit.acc_wrong_cmd
#define	wci_ha_esr_0_acc_uncorrectable_mtag_error	\
	bit.acc_uncorrectable_mtag_error
#define	wci_ha_esr_0_acc_uncorrectable_data_error	\
	bit.acc_uncorrectable_data_error
#define	wci_ha_esr_0_acc_correctable_mtag_error	\
	bit.acc_correctable_mtag_error
#define	wci_ha_esr_0_acc_correctable_data_error	\
	bit.acc_correctable_data_error
#define	wci_ha_esr_0_acc_mtag_mismatch_within_hcl	\
	bit.acc_mtag_mismatch_within_hcl
#define	wci_ha_esr_0_acc_mtag_mismatch_between_hcls	\
	bit.acc_mtag_mismatch_between_hcls
#define	wci_ha_esr_0_acc_timeout	\
	bit.acc_timeout
#define	wci_ha_esr_0_first_error	\
	bit.first_error
#define	wci_ha_esr_0_unexpected_snid	\
	bit.unexpected_snid
#define	wci_ha_esr_0_address_not_mapped_io	\
	bit.address_not_mapped_io
#define	wci_ha_esr_0_dir_parity_error	\
	bit.dir_parity_error
#define	wci_ha_esr_0_not_expected_compl	\
	bit.not_expected_compl
#define	wci_ha_esr_0_illegal_sender	\
	bit.illegal_sender
#define	wci_ha_esr_0_wrong_cmd	\
	bit.wrong_cmd
#define	wci_ha_esr_0_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_ha_esr_0_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_ha_esr_0_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_ha_esr_0_correctable_data_error	\
	bit.correctable_data_error
#define	wci_ha_esr_0_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_ha_esr_0_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_ha_esr_0_timeout	\
	bit.timeout


/*
 * wci_ha_esr_1
 */
typedef union {
	struct wci_ha_esr_1 {
		uint64_t rsvd_z				: 42;	/* 63:22 */
		uint64_t acc_gnr_err			: 1;	/* 21 */
		uint64_t acc_hw_err			: 1;	/* 20 */
		uint64_t acc_address_not_mapped		: 1;	/* 19 */
		uint64_t acc_dstat_inconsistent		: 1;	/* 18 */
		uint64_t acc_mtag_not_gm		: 1;	/* 17 */
		uint64_t acc_unexpected_mtag		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 9;	/* 14:6 */
		uint64_t gnr_err			: 1;	/* 5 */
		uint64_t hw_err				: 1;	/* 4 */
		uint64_t address_not_mapped		: 1;	/* 3 */
		uint64_t dstat_inconsistent		: 1;	/* 2 */
		uint64_t mtag_not_gm			: 1;	/* 1 */
		uint64_t unexpected_mtag		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ha_esr_1_u;

#define	wci_ha_esr_1_acc_gnr_err	\
	bit.acc_gnr_err
#define	wci_ha_esr_1_acc_hw_err	\
	bit.acc_hw_err
#define	wci_ha_esr_1_acc_address_not_mapped	\
	bit.acc_address_not_mapped
#define	wci_ha_esr_1_acc_dstat_inconsistent	\
	bit.acc_dstat_inconsistent
#define	wci_ha_esr_1_acc_mtag_not_gm	\
	bit.acc_mtag_not_gm
#define	wci_ha_esr_1_acc_unexpected_mtag	\
	bit.acc_unexpected_mtag
#define	wci_ha_esr_1_first_error	\
	bit.first_error
#define	wci_ha_esr_1_gnr_err	\
	bit.gnr_err
#define	wci_ha_esr_1_hw_err	\
	bit.hw_err
#define	wci_ha_esr_1_address_not_mapped	\
	bit.address_not_mapped
#define	wci_ha_esr_1_dstat_inconsistent	\
	bit.dstat_inconsistent
#define	wci_ha_esr_1_mtag_not_gm	\
	bit.mtag_not_gm
#define	wci_ha_esr_1_unexpected_mtag	\
	bit.unexpected_mtag


/*
 * wci_ha_hw_err_status
 */
typedef union {
	struct wci_ha_hw_err_status {
		uint64_t rsvd_z				: 45;	/* 63:19 */
		uint64_t oh_error_case_fall_through	: 1;	/* 18 */
		uint64_t dir_fetchq_ovfl		: 1;	/* 17 */
		uint64_t dir_fetchq_unfl		: 1;	/* 16 */
		uint64_t srq4_errors_ovfl		: 1;	/* 15 */
		uint64_t srq4_errors_unfl		: 1;	/* 14 */
		uint64_t srq3_errors_ovfl		: 1;	/* 13 */
		uint64_t srq3_errors_unfl		: 1;	/* 12 */
		uint64_t srq2_errors_ovfl		: 1;	/* 11 */
		uint64_t srq2_errors_unfl		: 1;	/* 10 */
		uint64_t srq1_errors_ovfl		: 1;	/* 9 */
		uint64_t srq1_errors_unfl		: 1;	/* 8 */
		uint64_t kmapq_errors_ovfl		: 1;	/* 7 */
		uint64_t kmapq_errors_unfl		: 1;	/* 6 */
		uint64_t ohq_errors_ovfl		: 1;	/* 5 */
		uint64_t ohq_errors_unfl		: 1;	/* 4 */
		uint64_t shq_errors_ovfl		: 1;	/* 3 */
		uint64_t shq_errors_unfl		: 1;	/* 2 */
		uint64_t dhc_all_uexp_rcv_error		: 1;	/* 1 */
		uint64_t dhc_all_uexp_snd_error		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ha_hw_err_status_u;

#define	wci_ha_hw_err_status_oh_error_case_fall_through	\
	bit.oh_error_case_fall_through
#define	wci_ha_hw_err_status_dir_fetchq_ovfl	\
	bit.dir_fetchq_ovfl
#define	wci_ha_hw_err_status_dir_fetchq_unfl	\
	bit.dir_fetchq_unfl
#define	wci_ha_hw_err_status_srq4_errors_ovfl	\
	bit.srq4_errors_ovfl
#define	wci_ha_hw_err_status_srq4_errors_unfl	\
	bit.srq4_errors_unfl
#define	wci_ha_hw_err_status_srq3_errors_ovfl	\
	bit.srq3_errors_ovfl
#define	wci_ha_hw_err_status_srq3_errors_unfl	\
	bit.srq3_errors_unfl
#define	wci_ha_hw_err_status_srq2_errors_ovfl	\
	bit.srq2_errors_ovfl
#define	wci_ha_hw_err_status_srq2_errors_unfl	\
	bit.srq2_errors_unfl
#define	wci_ha_hw_err_status_srq1_errors_ovfl	\
	bit.srq1_errors_ovfl
#define	wci_ha_hw_err_status_srq1_errors_unfl	\
	bit.srq1_errors_unfl
#define	wci_ha_hw_err_status_kmapq_errors_ovfl	\
	bit.kmapq_errors_ovfl
#define	wci_ha_hw_err_status_kmapq_errors_unfl	\
	bit.kmapq_errors_unfl
#define	wci_ha_hw_err_status_ohq_errors_ovfl	\
	bit.ohq_errors_ovfl
#define	wci_ha_hw_err_status_ohq_errors_unfl	\
	bit.ohq_errors_unfl
#define	wci_ha_hw_err_status_shq_errors_ovfl	\
	bit.shq_errors_ovfl
#define	wci_ha_hw_err_status_shq_errors_unfl	\
	bit.shq_errors_unfl
#define	wci_ha_hw_err_status_dhc_all_uexp_rcv_error	\
	bit.dhc_all_uexp_rcv_error
#define	wci_ha_hw_err_status_dhc_all_uexp_snd_error	\
	bit.dhc_all_uexp_snd_error


/*
 * wci_ha_esr_mask
 */
typedef union {
	struct wci_ha_esr_mask {
		uint64_t rsvd_z				: 42;	/* 63:22 */
		uint64_t gnr_err			: 1;	/* 21 */
		uint64_t hw_err				: 1;	/* 20 */
		uint64_t address_not_mapped		: 1;	/* 19 */
		uint64_t dstat_inconsistent		: 1;	/* 18 */
		uint64_t mtag_not_gm			: 1;	/* 17 */
		uint64_t unexpected_mtag		: 1;	/* 16 */
		uint64_t rsvd_y				: 3;	/* 15:13 */
		uint64_t unexpected_snid		: 1;	/* 12 */
		uint64_t address_not_mapped_io		: 1;	/* 11 */
		uint64_t dir_parity_error		: 1;	/* 10 */
		uint64_t not_expected_compl		: 1;	/* 9 */
		uint64_t illegal_sender			: 1;	/* 8 */
		uint64_t wrong_cmd			: 1;	/* 7 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 6 */
		uint64_t uncorrectable_data_error	: 1;	/* 5 */
		uint64_t correctable_mtag_error		: 1;	/* 4 */
		uint64_t correctable_data_error		: 1;	/* 3 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 2 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 1 */
		uint64_t timeout			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ha_esr_mask_u;

#define	wci_ha_esr_mask_gnr_err	\
	bit.gnr_err
#define	wci_ha_esr_mask_hw_err	\
	bit.hw_err
#define	wci_ha_esr_mask_address_not_mapped	\
	bit.address_not_mapped
#define	wci_ha_esr_mask_dstat_inconsistent	\
	bit.dstat_inconsistent
#define	wci_ha_esr_mask_mtag_not_gm	\
	bit.mtag_not_gm
#define	wci_ha_esr_mask_unexpected_mtag	\
	bit.unexpected_mtag
#define	wci_ha_esr_mask_unexpected_snid	\
	bit.unexpected_snid
#define	wci_ha_esr_mask_address_not_mapped_io	\
	bit.address_not_mapped_io
#define	wci_ha_esr_mask_dir_parity_error	\
	bit.dir_parity_error
#define	wci_ha_esr_mask_not_expected_compl	\
	bit.not_expected_compl
#define	wci_ha_esr_mask_illegal_sender	\
	bit.illegal_sender
#define	wci_ha_esr_mask_wrong_cmd	\
	bit.wrong_cmd
#define	wci_ha_esr_mask_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_ha_esr_mask_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_ha_esr_mask_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_ha_esr_mask_correctable_data_error	\
	bit.correctable_data_error
#define	wci_ha_esr_mask_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_ha_esr_mask_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_ha_esr_mask_timeout	\
	bit.timeout


/*
 * wci_probe_memory
 */
typedef union {
	struct wci_probe_memory {
		uint64_t done				: 1;	/* 63 */
		uint64_t in_progress			: 1;	/* 62 */
		uint64_t rsvd_z				: 15;	/* 61:47 */
		uint64_t mtag				: 3;	/* 46:44 */
		uint64_t rsvd_y				: 1;	/* 43 */
		uint64_t address			: 39;	/* 42:4 */
		uint64_t rsvd_x				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_probe_memory_u;

#define	wci_probe_memory_done	\
	bit.done
#define	wci_probe_memory_in_progress	\
	bit.in_progress
#define	wci_probe_memory_mtag	\
	bit.mtag
#define	wci_probe_memory_address	\
	bit.address


/*
 * wci_ha_status_array
 */
typedef union {
	struct wci_ha_status_array {
		uint64_t orig_atransid			: 9;	/* 63:55 */
		uint64_t orig_rtid			: 5;	/* 54:50 */
		uint64_t dispatched_op			: 6;	/* 49:44 */
		uint64_t rsvd_z				: 1;	/* 43 */
		uint64_t orig_addr			: 39;	/* 42:4 */
		uint64_t orig_snid			: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_ha_status_array_u;

#define	wci_ha_status_array_orig_atransid	\
	bit.orig_atransid
#define	wci_ha_status_array_orig_rtid	\
	bit.orig_rtid
#define	wci_ha_status_array_dispatched_op	\
	bit.dispatched_op
#define	wci_ha_status_array_orig_addr	\
	bit.orig_addr
#define	wci_ha_status_array_orig_snid	\
	bit.orig_snid


/*
 * wci_ha_status_2_array
 */
typedef union {
	struct wci_ha_status_2_array {
		uint64_t rsvd_z				: 30;	/* 63:34 */
		uint64_t dir_vld			: 1;	/* 33 */
		uint64_t dir_hit			: 1;	/* 32 */
		uint64_t old_dir_entry			: 12;	/* 31:20 */
		uint64_t rsvd_y				: 1;	/* 19 */
		uint64_t old_mtag			: 3;	/* 18:16 */
		uint64_t dir_copt			: 2;	/* 15:14 */
		uint64_t data_copt			: 2;	/* 13:12 */
		uint64_t rsvd_x				: 3;	/* 11:9 */
		uint64_t safari_thread			: 1;	/* 8 */
		uint64_t auxid_thread			: 1;	/* 7 */
		uint64_t cmpl_thread			: 1;	/* 6 */
		uint64_t data_sent_thread		: 1;	/* 5 */
		uint64_t data_rcvd_thread		: 1;	/* 4 */
		uint64_t dob_clrd_thread		: 1;	/* 3 */
		uint64_t hdr_sent_thread		: 1;	/* 2 */
		uint64_t constmap_thread		: 1;	/* 1 */
		uint64_t pull_seen_thread		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_ha_status_2_array_u;

#define	wci_ha_status_2_array_dir_vld	\
	bit.dir_vld
#define	wci_ha_status_2_array_dir_hit	\
	bit.dir_hit
#define	wci_ha_status_2_array_old_dir_entry	\
	bit.old_dir_entry
#define	wci_ha_status_2_array_old_mtag	\
	bit.old_mtag
#define	wci_ha_status_2_array_dir_copt	\
	bit.dir_copt
#define	wci_ha_status_2_array_data_copt	\
	bit.data_copt
#define	wci_ha_status_2_array_safari_thread	\
	bit.safari_thread
#define	wci_ha_status_2_array_auxid_thread	\
	bit.auxid_thread
#define	wci_ha_status_2_array_cmpl_thread	\
	bit.cmpl_thread
#define	wci_ha_status_2_array_data_sent_thread	\
	bit.data_sent_thread
#define	wci_ha_status_2_array_data_rcvd_thread	\
	bit.data_rcvd_thread
#define	wci_ha_status_2_array_dob_clrd_thread	\
	bit.dob_clrd_thread
#define	wci_ha_status_2_array_hdr_sent_thread	\
	bit.hdr_sent_thread
#define	wci_ha_status_2_array_constmap_thread	\
	bit.constmap_thread
#define	wci_ha_status_2_array_pull_seen_thread	\
	bit.pull_seen_thread


/*
 * wci_ha_config
 */
typedef union {
	struct wci_ha_config {
		uint64_t rsvd_z				: 55;	/* 63:9 */
		uint64_t snid_in_mask			: 1;	/* 8 */
		uint64_t disable_same_box_opt		: 1;	/* 7 */
		uint64_t migratory_sharing_ctrl		: 7;	/* 6:0 */
	} bit;
	uint64_t val;
} wci_ha_config_u;

#define	wci_ha_config_snid_in_mask	\
	bit.snid_in_mask
#define	wci_ha_config_disable_same_box_opt	\
	bit.disable_same_box_opt
#define	wci_ha_config_migratory_sharing_ctrl	\
	bit.migratory_sharing_ctrl


/*
 * wci_hag_route_map0
 */
typedef union {
	struct wci_hag_route_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_hag_route_map0_u;

#define	wci_hag_route_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_hag_route_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_hag_route_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_hag_route_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_hag_route_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_hag_route_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_hag_route_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_hag_route_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_hag_route_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_hag_route_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_hag_route_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_hag_route_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_hag_route_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_hag_route_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_hag_route_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_hag_route_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_hag_route_map1
 */
typedef union {
	struct wci_hag_route_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_hag_route_map1_u;

#define	wci_hag_route_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_hag_route_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_hag_route_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_hag_route_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_hag_route_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_hag_route_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_hag_route_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_hag_route_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_hag_route_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_hag_route_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_hag_route_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_hag_route_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_hag_route_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_hag_route_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_hag_route_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_hag_route_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_emiss_cntl_array
 */
typedef union {
	struct wci_emiss_cntl_array {
		uint64_t rsvd_z				: 13;	/* 63:51 */
		uint64_t auto_reset_active		: 1;	/* 50 */
		uint64_t enabled			: 1;	/* 49 */
		uint64_t address			: 37;	/* 48:12 */
		uint64_t nid				: 4;	/* 11:8 */
		uint64_t length				: 2;	/* 7:6 */
		uint64_t event0				: 3;	/* 5:3 */
		uint64_t event1				: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_emiss_cntl_array_u;

#define	wci_emiss_cntl_array_auto_reset_active	\
	bit.auto_reset_active
#define	wci_emiss_cntl_array_enabled	\
	bit.enabled
#define	wci_emiss_cntl_array_address	\
	bit.address
#define	wci_emiss_cntl_array_nid	\
	bit.nid
#define	wci_emiss_cntl_array_length	\
	bit.length
#define	wci_emiss_cntl_array_event0	\
	bit.event0
#define	wci_emiss_cntl_array_event1	\
	bit.event1


/*
 * wci_emiss_data_array
 */
typedef union {
	struct wci_emiss_data_array {
		uint64_t rsvd_z				: 20;	/* 63:44 */
		uint64_t event0_count			: 10;	/* 43:34 */
		uint64_t event1_count			: 10;	/* 33:24 */
		uint64_t event0_count_all		: 12;	/* 23:12 */
		uint64_t event1_count_all		: 12;	/* 11:0 */
	} bit;
	uint64_t val;
} wci_emiss_data_array_u;

#define	wci_emiss_data_array_event0_count	\
	bit.event0_count
#define	wci_emiss_data_array_event1_count	\
	bit.event1_count
#define	wci_emiss_data_array_event0_count_all	\
	bit.event0_count_all
#define	wci_emiss_data_array_event1_count_all	\
	bit.event1_count_all


/*
 * wci_emiss_reset_ctl
 */
typedef union {
	struct wci_emiss_reset_ctl {
		uint64_t rsvd_z				: 42;	/* 63:22 */
		uint64_t auto_reset_mask		: 10;	/* 21:12 */
		uint64_t count				: 12;	/* 11:0 */
	} bit;
	uint64_t val;
} wci_emiss_reset_ctl_u;

#define	wci_emiss_reset_ctl_auto_reset_mask	\
	bit.auto_reset_mask
#define	wci_emiss_reset_ctl_count	\
	bit.count


/*
 * wci_global_emiss_counter
 */
typedef union {
	struct wci_global_emiss_counter {
		uint64_t rsvd_z				: 40;	/* 63:24 */
		uint64_t count				: 24;	/* 23:0 */
	} bit;
	uint64_t val;
} wci_global_emiss_counter_u;

#define	wci_global_emiss_counter_count	\
	bit.count


/*
 * wci_sa_freeze
 */
typedef union {
	struct wci_sa_freeze {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t vector				: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_sa_freeze_u;

#define	wci_sa_freeze_vector	\
	bit.vector


/*
 * wci_sa_busy
 */
typedef union {
	struct wci_sa_busy {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t vector				: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_sa_busy_u;

#define	wci_sa_busy_vector	\
	bit.vector


/*
 * wci_sa_first_error_agent
 */
typedef union {
	struct wci_sa_first_error_agent {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_z				: 56;	/* 58:3 */
		uint64_t instance			: 3;	/* 2:0 */
	} bit;
	uint64_t val;
} wci_sa_first_error_agent_u;

#define	wci_sa_first_error_agent_esr_reg	\
	bit.esr_reg
#define	wci_sa_first_error_agent_esr_index	\
	bit.esr_index
#define	wci_sa_first_error_agent_instance	\
	bit.instance


/*
 * wci_sa_first_packet_0
 */
typedef union {
	struct wci_sa_first_packet_0 {
		uint64_t rsvd_z				: 7;	/* 63:57 */
		uint64_t ntransid			: 9;	/* 56:48 */
		uint64_t rsvd_y				: 2;	/* 47:46 */
		uint64_t cmr				: 1;	/* 45 */
		uint64_t otransid			: 9;	/* 44:36 */
		uint64_t rsvd_x				: 2;	/* 35:34 */
		uint64_t rnid				: 4;	/* 33:30 */
		uint64_t r2e				: 4;	/* 29:26 */
		uint64_t emiss				: 1;	/* 25 */
		uint64_t rsvd_w				: 1;	/* 24 */
		uint64_t htid				: 4;	/* 23:20 */
		uint64_t rtid				: 5;	/* 19:15 */
		uint64_t snid				: 4;	/* 14:11 */
		uint64_t msgop				: 4;	/* 10:7 */
		uint64_t htyp				: 2;	/* 6:5 */
		uint64_t stripe				: 1;	/* 4 */
		uint64_t dnid				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_sa_first_packet_0_u;

#define	wci_sa_first_packet_0_ntransid	\
	bit.ntransid
#define	wci_sa_first_packet_0_cmr	\
	bit.cmr
#define	wci_sa_first_packet_0_otransid	\
	bit.otransid
#define	wci_sa_first_packet_0_rnid	\
	bit.rnid
#define	wci_sa_first_packet_0_r2e	\
	bit.r2e
#define	wci_sa_first_packet_0_emiss	\
	bit.emiss
#define	wci_sa_first_packet_0_htid	\
	bit.htid
#define	wci_sa_first_packet_0_rtid	\
	bit.rtid
#define	wci_sa_first_packet_0_snid	\
	bit.snid
#define	wci_sa_first_packet_0_msgop	\
	bit.msgop
#define	wci_sa_first_packet_0_htyp	\
	bit.htyp
#define	wci_sa_first_packet_0_stripe	\
	bit.stripe
#define	wci_sa_first_packet_0_dnid	\
	bit.dnid


/*
 * wci_sa_first_packet_1
 */
typedef union {
	struct wci_sa_first_packet_1 {
		uint64_t esr_reg			: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t a_entry			: 1;	/* 58 */
		uint64_t s_entry			: 1;	/* 57 */
		uint64_t rsvd_z				: 14;	/* 56:43 */
		uint64_t ga				: 38;	/* 42:5 */
		uint64_t rsvd_y				: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_sa_first_packet_1_u;

#define	wci_sa_first_packet_1_esr_reg	\
	bit.esr_reg
#define	wci_sa_first_packet_1_esr_index	\
	bit.esr_index
#define	wci_sa_first_packet_1_a_entry	\
	bit.a_entry
#define	wci_sa_first_packet_1_s_entry	\
	bit.s_entry
#define	wci_sa_first_packet_1_ga	\
	bit.ga


/*
 * wci_sa_ecc_address
 */
typedef union {
	struct wci_sa_ecc_address {
		uint64_t data				: 1;	/* 63 */
		uint64_t ue				: 1;	/* 62 */
		uint64_t rsvd_z				: 19;	/* 61:43 */
		uint64_t addr				: 38;	/* 42:5 */
		uint64_t rsvd_y				: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_sa_ecc_address_u;

#define	wci_sa_ecc_address_data	\
	bit.data
#define	wci_sa_ecc_address_ue	\
	bit.ue
#define	wci_sa_ecc_address_addr	\
	bit.addr


/*
 * wci_sa_timeout_config
 */
typedef union {
	struct wci_sa_timeout_config {
		uint64_t rsvd_z				: 50;	/* 63:14 */
		uint64_t ssm_disable			: 1;	/* 13 */
		uint64_t ssm_freeze			: 1;	/* 12 */
		uint64_t rsvd_y				: 2;	/* 11:10 */
		uint64_t ssm_mag			: 2;	/* 9:8 */
		uint64_t ssm_val			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_sa_timeout_config_u;

#define	wci_sa_timeout_config_ssm_disable	\
	bit.ssm_disable
#define	wci_sa_timeout_config_ssm_freeze	\
	bit.ssm_freeze
#define	wci_sa_timeout_config_ssm_mag	\
	bit.ssm_mag
#define	wci_sa_timeout_config_ssm_val	\
	bit.ssm_val


/*
 * wci_sa_esr_0
 */
typedef union {
	struct wci_sa_esr_0 {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t acc_hw_err			: 1;	/* 30 */
		uint64_t acc_address_not_owned		: 1;	/* 29 */
		uint64_t acc_address_not_mapped		: 1;	/* 28 */
		uint64_t acc_ga2lpa_ecc_error		: 1;	/* 27 */
		uint64_t acc_rip_multi_hit		: 1;	/* 26 */
		uint64_t acc_illegal_sender		: 1;	/* 25 */
		uint64_t acc_wrong_demand		: 1;	/* 24 */
		uint64_t acc_uncorrectable_mtag_error	: 1;	/* 23 */
		uint64_t acc_uncorrectable_data_error	: 1;	/* 22 */
		uint64_t acc_correctable_mtag_error	: 1;	/* 21 */
		uint64_t acc_correctable_data_error	: 1;	/* 20 */
		uint64_t acc_mtag_mismatch_within_hcl	: 1;	/* 19 */
		uint64_t acc_mtag_mismatch_between_hcls	: 1;	/* 18 */
		uint64_t acc_unexpected_mtag		: 1;	/* 17 */
		uint64_t acc_timeout			: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t hw_err				: 1;	/* 14 */
		uint64_t address_not_owned		: 1;	/* 13 */
		uint64_t address_not_mapped		: 1;	/* 12 */
		uint64_t ga2lpa_ecc_error		: 1;	/* 11 */
		uint64_t rip_multi_hit			: 1;	/* 10 */
		uint64_t illegal_sender			: 1;	/* 9 */
		uint64_t wrong_demand			: 1;	/* 8 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 7 */
		uint64_t uncorrectable_data_error	: 1;	/* 6 */
		uint64_t correctable_mtag_error		: 1;	/* 5 */
		uint64_t correctable_data_error		: 1;	/* 4 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 3 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 2 */
		uint64_t unexpected_mtag		: 1;	/* 1 */
		uint64_t timeout			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sa_esr_0_u;

#define	wci_sa_esr_0_acc_hw_err	\
	bit.acc_hw_err
#define	wci_sa_esr_0_acc_address_not_owned	\
	bit.acc_address_not_owned
#define	wci_sa_esr_0_acc_address_not_mapped	\
	bit.acc_address_not_mapped
#define	wci_sa_esr_0_acc_ga2lpa_ecc_error	\
	bit.acc_ga2lpa_ecc_error
#define	wci_sa_esr_0_acc_rip_multi_hit	\
	bit.acc_rip_multi_hit
#define	wci_sa_esr_0_acc_illegal_sender	\
	bit.acc_illegal_sender
#define	wci_sa_esr_0_acc_wrong_demand	\
	bit.acc_wrong_demand
#define	wci_sa_esr_0_acc_uncorrectable_mtag_error	\
	bit.acc_uncorrectable_mtag_error
#define	wci_sa_esr_0_acc_uncorrectable_data_error	\
	bit.acc_uncorrectable_data_error
#define	wci_sa_esr_0_acc_correctable_mtag_error	\
	bit.acc_correctable_mtag_error
#define	wci_sa_esr_0_acc_correctable_data_error	\
	bit.acc_correctable_data_error
#define	wci_sa_esr_0_acc_mtag_mismatch_within_hcl	\
	bit.acc_mtag_mismatch_within_hcl
#define	wci_sa_esr_0_acc_mtag_mismatch_between_hcls	\
	bit.acc_mtag_mismatch_between_hcls
#define	wci_sa_esr_0_acc_unexpected_mtag	\
	bit.acc_unexpected_mtag
#define	wci_sa_esr_0_acc_timeout	\
	bit.acc_timeout
#define	wci_sa_esr_0_first_error	\
	bit.first_error
#define	wci_sa_esr_0_hw_err	\
	bit.hw_err
#define	wci_sa_esr_0_address_not_owned	\
	bit.address_not_owned
#define	wci_sa_esr_0_address_not_mapped	\
	bit.address_not_mapped
#define	wci_sa_esr_0_ga2lpa_ecc_error	\
	bit.ga2lpa_ecc_error
#define	wci_sa_esr_0_rip_multi_hit	\
	bit.rip_multi_hit
#define	wci_sa_esr_0_illegal_sender	\
	bit.illegal_sender
#define	wci_sa_esr_0_wrong_demand	\
	bit.wrong_demand
#define	wci_sa_esr_0_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_sa_esr_0_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_sa_esr_0_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_sa_esr_0_correctable_data_error	\
	bit.correctable_data_error
#define	wci_sa_esr_0_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_sa_esr_0_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_sa_esr_0_unexpected_mtag	\
	bit.unexpected_mtag
#define	wci_sa_esr_0_timeout	\
	bit.timeout


/*
 * wci_sa_hw_err_state
 */
typedef union {
	struct wci_sa_hw_err_state {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t sh_queue_overflow		: 1;	/* 7 */
		uint64_t sh_wrong_stid			: 1;	/* 6 */
		uint64_t sh_unexpected_snoop		: 1;	/* 5 */
		uint64_t oh_queue_overflow		: 1;	/* 4 */
		uint64_t oh_wrong_stid			: 1;	/* 3 */
		uint64_t oh_unexpected_ordered		: 1;	/* 2 */
		uint64_t unexpected_send_ack		: 1;	/* 1 */
		uint64_t unexpected_receive_ack		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sa_hw_err_state_u;

#define	wci_sa_hw_err_state_sh_queue_overflow	\
	bit.sh_queue_overflow
#define	wci_sa_hw_err_state_sh_wrong_stid	\
	bit.sh_wrong_stid
#define	wci_sa_hw_err_state_sh_unexpected_snoop	\
	bit.sh_unexpected_snoop
#define	wci_sa_hw_err_state_oh_queue_overflow	\
	bit.oh_queue_overflow
#define	wci_sa_hw_err_state_oh_wrong_stid	\
	bit.oh_wrong_stid
#define	wci_sa_hw_err_state_oh_unexpected_ordered	\
	bit.oh_unexpected_ordered
#define	wci_sa_hw_err_state_unexpected_send_ack	\
	bit.unexpected_send_ack
#define	wci_sa_hw_err_state_unexpected_receive_ack	\
	bit.unexpected_receive_ack


/*
 * wci_sa_esr_mask
 */
typedef union {
	struct wci_sa_esr_mask {
		uint64_t rsvd_z				: 49;	/* 63:15 */
		uint64_t hw_err				: 1;	/* 14 */
		uint64_t address_not_owned		: 1;	/* 13 */
		uint64_t address_not_mapped		: 1;	/* 12 */
		uint64_t ga2lpa_ecc_error		: 1;	/* 11 */
		uint64_t rip_multi_hit			: 1;	/* 10 */
		uint64_t illegal_sender			: 1;	/* 9 */
		uint64_t wrong_demand			: 1;	/* 8 */
		uint64_t uncorrectable_mtag_error	: 1;	/* 7 */
		uint64_t uncorrectable_data_error	: 1;	/* 6 */
		uint64_t correctable_mtag_error		: 1;	/* 5 */
		uint64_t correctable_data_error		: 1;	/* 4 */
		uint64_t mtag_mismatch_within_hcl	: 1;	/* 3 */
		uint64_t mtag_mismatch_between_hcls	: 1;	/* 2 */
		uint64_t unexpected_mtag		: 1;	/* 1 */
		uint64_t timeout			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sa_esr_mask_u;

#define	wci_sa_esr_mask_hw_err	\
	bit.hw_err
#define	wci_sa_esr_mask_address_not_owned	\
	bit.address_not_owned
#define	wci_sa_esr_mask_address_not_mapped	\
	bit.address_not_mapped
#define	wci_sa_esr_mask_ga2lpa_ecc_error	\
	bit.ga2lpa_ecc_error
#define	wci_sa_esr_mask_rip_multi_hit	\
	bit.rip_multi_hit
#define	wci_sa_esr_mask_illegal_sender	\
	bit.illegal_sender
#define	wci_sa_esr_mask_wrong_demand	\
	bit.wrong_demand
#define	wci_sa_esr_mask_uncorrectable_mtag_error	\
	bit.uncorrectable_mtag_error
#define	wci_sa_esr_mask_uncorrectable_data_error	\
	bit.uncorrectable_data_error
#define	wci_sa_esr_mask_correctable_mtag_error	\
	bit.correctable_mtag_error
#define	wci_sa_esr_mask_correctable_data_error	\
	bit.correctable_data_error
#define	wci_sa_esr_mask_mtag_mismatch_within_hcl	\
	bit.mtag_mismatch_within_hcl
#define	wci_sa_esr_mask_mtag_mismatch_between_hcls	\
	bit.mtag_mismatch_between_hcls
#define	wci_sa_esr_mask_unexpected_mtag	\
	bit.unexpected_mtag
#define	wci_sa_esr_mask_timeout	\
	bit.timeout


/*
 * wci_sa_status_array
 */
typedef union {
	struct wci_sa_status_array {
		uint64_t rsvd_z				: 43;	/* 63:21 */
		uint64_t receive_count			: 2;	/* 20:19 */
		uint64_t send_count			: 3;	/* 18:16 */
		uint64_t owned				: 1;	/* 15 */
		uint64_t first_mtag			: 3;	/* 14:12 */
		uint64_t atransid_3_0			: 4;	/* 11:8 */
		uint64_t rsvd_y				: 2;	/* 7:6 */
		uint64_t ga2lpa_status			: 2;	/* 5:4 */
		uint64_t msgop				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_sa_status_array_u;

#define	wci_sa_status_array_receive_count	\
	bit.receive_count
#define	wci_sa_status_array_send_count	\
	bit.send_count
#define	wci_sa_status_array_owned	\
	bit.owned
#define	wci_sa_status_array_first_mtag	\
	bit.first_mtag
#define	wci_sa_status_array_atransid_3_0	\
	bit.atransid_3_0
#define	wci_sa_status_array_ga2lpa_status	\
	bit.ga2lpa_status
#define	wci_sa_status_array_msgop	\
	bit.msgop


/*
 * wci_sa_status_2_array
 */
typedef union {
	struct wci_sa_status_2_array {
		uint64_t rsvd_z				: 53;	/* 63:11 */
		uint64_t send_done			: 1;	/* 10 */
		uint64_t ph_done			: 1;	/* 9 */
		uint64_t got_2nd_snoop			: 1;	/* 8 */
		uint64_t got_1st_snoop			: 1;	/* 7 */
		uint64_t got_2nd_ord			: 1;	/* 6 */
		uint64_t got_1st_ord			: 1;	/* 5 */
		uint64_t sf_3_done			: 1;	/* 4 */
		uint64_t sf_2_done			: 1;	/* 3 */
		uint64_t dsh_done			: 1;	/* 2 */
		uint64_t drh_done			: 1;	/* 1 */
		uint64_t req_done			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sa_status_2_array_u;

#define	wci_sa_status_2_array_send_done	\
	bit.send_done
#define	wci_sa_status_2_array_ph_done	\
	bit.ph_done
#define	wci_sa_status_2_array_got_2nd_snoop	\
	bit.got_2nd_snoop
#define	wci_sa_status_2_array_got_1st_snoop	\
	bit.got_1st_snoop
#define	wci_sa_status_2_array_got_2nd_ord	\
	bit.got_2nd_ord
#define	wci_sa_status_2_array_got_1st_ord	\
	bit.got_1st_ord
#define	wci_sa_status_2_array_sf_3_done	\
	bit.sf_3_done
#define	wci_sa_status_2_array_sf_2_done	\
	bit.sf_2_done
#define	wci_sa_status_2_array_dsh_done	\
	bit.dsh_done
#define	wci_sa_status_2_array_drh_done	\
	bit.drh_done
#define	wci_sa_status_2_array_req_done	\
	bit.req_done


/*
 * wci_sa_status_3_array
 */
typedef union {
	struct wci_sa_status_3_array {
		uint64_t rsvd_z				: 51;	/* 63:13 */
		uint64_t ntransid			: 9;	/* 12:4 */
		uint64_t snid				: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_sa_status_3_array_u;

#define	wci_sa_status_3_array_ntransid	\
	bit.ntransid
#define	wci_sa_status_3_array_snid	\
	bit.snid


/*
 * wci_sa_status_4_array
 */
typedef union {
	struct wci_sa_status_4_array {
		uint64_t rsvd_z				: 31;	/* 63:33 */
		uint64_t otransid			: 9;	/* 32:24 */
		uint64_t rnid				: 4;	/* 23:20 */
		uint64_t replies_2_exp			: 4;	/* 19:16 */
		uint64_t htid				: 4;	/* 15:12 */
		uint64_t rsvd_y				: 3;	/* 11:9 */
		uint64_t rtid				: 5;	/* 8:4 */
		uint64_t rsvd_x				: 2;	/* 3:2 */
		uint64_t emiss				: 1;	/* 1 */
		uint64_t stripe				: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sa_status_4_array_u;

#define	wci_sa_status_4_array_otransid	\
	bit.otransid
#define	wci_sa_status_4_array_rnid	\
	bit.rnid
#define	wci_sa_status_4_array_replies_2_exp	\
	bit.replies_2_exp
#define	wci_sa_status_4_array_htid	\
	bit.htid
#define	wci_sa_status_4_array_rtid	\
	bit.rtid
#define	wci_sa_status_4_array_emiss	\
	bit.emiss
#define	wci_sa_status_4_array_stripe	\
	bit.stripe


/*
 * wci_sa_status_5_array
 */
typedef union {
	struct wci_sa_status_5_array {
		uint64_t rsvd_z				: 21;	/* 63:43 */
		uint64_t original_ga			: 30;	/* 42:13 */
		uint64_t rsvd_y				: 12;	/* 12:1 */
		uint64_t cmr				: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sa_status_5_array_u;

#define	wci_sa_status_5_array_original_ga	\
	bit.original_ga
#define	wci_sa_status_5_array_cmr	\
	bit.cmr


/*
 * wci_sa_status_6_array
 */
typedef union {
	struct wci_sa_status_6_array {
		uint64_t rsvd_z				: 21;	/* 63:43 */
		uint64_t safari_addr_42			: 1;	/* 42 */
		uint64_t safari_addr_41_38		: 4;	/* 41:38 */
		uint64_t safari_addr_37			: 1;	/* 37 */
		uint64_t safari_addr_36_5		: 32;	/* 36:5 */
		uint64_t rsvd_y				: 5;	/* 4:0 */
	} bit;
	uint64_t val;
} wci_sa_status_6_array_u;

#define	wci_sa_status_6_array_safari_addr_42	\
	bit.safari_addr_42
#define	wci_sa_status_6_array_safari_addr_41_38	\
	bit.safari_addr_41_38
#define	wci_sa_status_6_array_safari_addr_37	\
	bit.safari_addr_37
#define	wci_sa_status_6_array_safari_addr_36_5	\
	bit.safari_addr_36_5


/*
 * wci_sag_route_map0
 */
typedef union {
	struct wci_sag_route_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sag_route_map0_u;

#define	wci_sag_route_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_sag_route_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_sag_route_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_sag_route_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_sag_route_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_sag_route_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_sag_route_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_sag_route_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_sag_route_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_sag_route_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_sag_route_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_sag_route_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_sag_route_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_sag_route_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_sag_route_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_sag_route_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_sag_route_map1
 */
typedef union {
	struct wci_sag_route_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sag_route_map1_u;

#define	wci_sag_route_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_sag_route_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_sag_route_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_sag_route_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_sag_route_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_sag_route_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_sag_route_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_sag_route_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_sag_route_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_sag_route_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_sag_route_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_sag_route_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_sag_route_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_sag_route_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_sag_route_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_sag_route_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_nc2nid_array
 */
typedef union {
	struct wci_nc2nid_array {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t no_stripe			: 1;	/* 7 */
		uint64_t encode_cluster_origin_tag	: 1;	/* 6 */
		uint64_t launch_remote			: 1;	/* 5 */
		uint64_t launch_local_sram		: 1;	/* 4 */
		uint64_t dest_node_id			: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_nc2nid_array_u;

#define	wci_nc2nid_array_no_stripe	\
	bit.no_stripe
#define	wci_nc2nid_array_encode_cluster_origin_tag	\
	bit.encode_cluster_origin_tag
#define	wci_nc2nid_array_launch_remote	\
	bit.launch_remote
#define	wci_nc2nid_array_launch_local_sram	\
	bit.launch_local_sram
#define	wci_nc2nid_array_dest_node_id	\
	bit.dest_node_id


/*
 * wci_sfi_transid_alloc
 */
typedef union {
	struct wci_sfi_transid_alloc {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t targid_available		: 15;	/* 30:16 */
		uint64_t atransid_available		: 15;	/* 15:1 */
		uint64_t rsvd_y				: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfi_transid_alloc_u;

#define	wci_sfi_transid_alloc_targid_available	\
	bit.targid_available
#define	wci_sfi_transid_alloc_atransid_available	\
	bit.atransid_available


/*
 * wci_sfi_esr
 */
typedef union {
	struct wci_sfi_esr {
		uint64_t rsvd_z				: 38;	/* 63:26 */
		uint64_t acc_targid_timeout		: 1;	/* 25 */
		uint64_t acc_nc2nid_misconfig		: 1;	/* 24 */
		uint64_t acc_addr_pty			: 1;	/* 23 */
		uint64_t acc_incoming_prereq_conflict	: 1;	/* 22 */
		uint64_t acc_modcam_clr_set_conflict	: 1;	/* 21 */
		uint64_t acc_modcam_multi_hit		: 1;	/* 20 */
		uint64_t acc_modcam_set_set		: 1;	/* 19 */
		uint64_t acc_unexpected_incoming	: 1;	/* 18 */
		uint64_t acc_unexpected_targarbgnt	: 1;	/* 17 */
		uint64_t acc_transid_unalloc_released	: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 5;	/* 14:10 */
		uint64_t targid_timeout			: 1;	/* 9 */
		uint64_t nc2nid_misconfig		: 1;	/* 8 */
		uint64_t addr_pty			: 1;	/* 7 */
		uint64_t incoming_prereq_conflict	: 1;	/* 6 */
		uint64_t modcam_clr_set_conflict	: 1;	/* 5 */
		uint64_t modcam_multi_hit		: 1;	/* 4 */
		uint64_t modcam_set_set			: 1;	/* 3 */
		uint64_t unexpected_incoming		: 1;	/* 2 */
		uint64_t unexpected_targarbgnt		: 1;	/* 1 */
		uint64_t transid_unalloc_released	: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfi_esr_u;

#define	wci_sfi_esr_acc_targid_timeout	\
	bit.acc_targid_timeout
#define	wci_sfi_esr_acc_nc2nid_misconfig	\
	bit.acc_nc2nid_misconfig
#define	wci_sfi_esr_acc_addr_pty	\
	bit.acc_addr_pty
#define	wci_sfi_esr_acc_incoming_prereq_conflict	\
	bit.acc_incoming_prereq_conflict
#define	wci_sfi_esr_acc_modcam_clr_set_conflict	\
	bit.acc_modcam_clr_set_conflict
#define	wci_sfi_esr_acc_modcam_multi_hit	\
	bit.acc_modcam_multi_hit
#define	wci_sfi_esr_acc_modcam_set_set	\
	bit.acc_modcam_set_set
#define	wci_sfi_esr_acc_unexpected_incoming	\
	bit.acc_unexpected_incoming
#define	wci_sfi_esr_acc_unexpected_targarbgnt	\
	bit.acc_unexpected_targarbgnt
#define	wci_sfi_esr_acc_transid_unalloc_released	\
	bit.acc_transid_unalloc_released
#define	wci_sfi_esr_first_error	\
	bit.first_error
#define	wci_sfi_esr_targid_timeout	\
	bit.targid_timeout
#define	wci_sfi_esr_nc2nid_misconfig	\
	bit.nc2nid_misconfig
#define	wci_sfi_esr_addr_pty	\
	bit.addr_pty
#define	wci_sfi_esr_incoming_prereq_conflict	\
	bit.incoming_prereq_conflict
#define	wci_sfi_esr_modcam_clr_set_conflict	\
	bit.modcam_clr_set_conflict
#define	wci_sfi_esr_modcam_multi_hit	\
	bit.modcam_multi_hit
#define	wci_sfi_esr_modcam_set_set	\
	bit.modcam_set_set
#define	wci_sfi_esr_unexpected_incoming	\
	bit.unexpected_incoming
#define	wci_sfi_esr_unexpected_targarbgnt	\
	bit.unexpected_targarbgnt
#define	wci_sfi_esr_transid_unalloc_released	\
	bit.transid_unalloc_released


/*
 * wci_sfi_esr_mask
 */
typedef union {
	struct wci_sfi_esr_mask {
		uint64_t rsvd_z				: 54;	/* 63:10 */
		uint64_t targid_timeout			: 1;	/* 9 */
		uint64_t nc2nid_misconfig		: 1;	/* 8 */
		uint64_t addr_pty			: 1;	/* 7 */
		uint64_t incoming_prereq_conflict	: 1;	/* 6 */
		uint64_t modcam_clr_set_conflict	: 1;	/* 5 */
		uint64_t modcam_multi_hit		: 1;	/* 4 */
		uint64_t modcam_set_set			: 1;	/* 3 */
		uint64_t unexpected_incoming		: 1;	/* 2 */
		uint64_t unexpected_targarbgnt		: 1;	/* 1 */
		uint64_t transid_unalloc_released	: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfi_esr_mask_u;

#define	wci_sfi_esr_mask_targid_timeout	\
	bit.targid_timeout
#define	wci_sfi_esr_mask_nc2nid_misconfig	\
	bit.nc2nid_misconfig
#define	wci_sfi_esr_mask_addr_pty	\
	bit.addr_pty
#define	wci_sfi_esr_mask_incoming_prereq_conflict	\
	bit.incoming_prereq_conflict
#define	wci_sfi_esr_mask_modcam_clr_set_conflict	\
	bit.modcam_clr_set_conflict
#define	wci_sfi_esr_mask_modcam_multi_hit	\
	bit.modcam_multi_hit
#define	wci_sfi_esr_mask_modcam_set_set	\
	bit.modcam_set_set
#define	wci_sfi_esr_mask_unexpected_incoming	\
	bit.unexpected_incoming
#define	wci_sfi_esr_mask_unexpected_targarbgnt	\
	bit.unexpected_targarbgnt
#define	wci_sfi_esr_mask_transid_unalloc_released	\
	bit.transid_unalloc_released


/*
 * wci_sfi_state
 */
typedef union {
	struct wci_sfi_state {
		uint64_t rsvd_z				: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_y				: 10;	/* 58:49 */
		uint64_t wci_issued			: 1;	/* 48 */
		uint64_t agent_id			: 7;	/* 47:41 */
		uint64_t modcam_index			: 4;	/* 40:37 */
		uint64_t modcam_addr			: 31;	/* 36:6 */
		uint64_t sf_cmd				: 2;	/* 5:4 */
		uint64_t sf_mask_3_to_0			: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_sfi_state_u;

#define	wci_sfi_state_esr_index	\
	bit.esr_index
#define	wci_sfi_state_wci_issued	\
	bit.wci_issued
#define	wci_sfi_state_agent_id	\
	bit.agent_id
#define	wci_sfi_state_modcam_index	\
	bit.modcam_index
#define	wci_sfi_state_modcam_addr	\
	bit.modcam_addr
#define	wci_sfi_state_sf_cmd	\
	bit.sf_cmd
#define	wci_sfi_state_sf_mask_3_to_0	\
	bit.sf_mask_3_to_0


/*
 * wci_sfi_state1
 */
typedef union {
	struct wci_sfi_state1 {
		uint64_t rsvd_z				: 1;	/* 63 */
		uint64_t esr_index			: 4;	/* 62:59 */
		uint64_t rsvd_y				: 8;	/* 58:51 */
		uint64_t unalloc_release_agents		: 5;	/* 50:46 */
		uint64_t unalloc_targids_released	: 15;	/* 45:31 */
		uint64_t unalloc_atransids_released	: 15;	/* 30:16 */
		uint64_t nc2nid_index			: 8;	/* 15:8 */
		uint64_t nc2nid_data			: 8;	/* 7:0 */
	} bit;
	uint64_t val;
} wci_sfi_state1_u;

#define	wci_sfi_state1_esr_index	\
	bit.esr_index
#define	wci_sfi_state1_unalloc_release_agents	\
	bit.unalloc_release_agents
#define	wci_sfi_state1_unalloc_targids_released	\
	bit.unalloc_targids_released
#define	wci_sfi_state1_unalloc_atransids_released	\
	bit.unalloc_atransids_released
#define	wci_sfi_state1_nc2nid_index	\
	bit.nc2nid_index
#define	wci_sfi_state1_nc2nid_data	\
	bit.nc2nid_data


/*
 * wci_sfi_ctr1_mask
 */
typedef union {
	struct wci_sfi_ctr1_mask {
		uint64_t rsvd_z				: 6;	/* 63:58 */
		uint64_t mask				: 10;	/* 57:48 */
		uint64_t atransid			: 9;	/* 47:39 */
		uint64_t address			: 39;	/* 38:0 */
	} bit;
	uint64_t val;
} wci_sfi_ctr1_mask_u;

#define	wci_sfi_ctr1_mask_mask	\
	bit.mask
#define	wci_sfi_ctr1_mask_atransid	\
	bit.atransid
#define	wci_sfi_ctr1_mask_address	\
	bit.address


/*
 * wci_sfi_ctr1_match_transaction
 */
typedef union {
	struct wci_sfi_ctr1_match_transaction {
		uint64_t rsvd_z				: 45;	/* 63:19 */
		uint64_t rts				: 1;	/* 18 */
		uint64_t rto				: 1;	/* 17 */
		uint64_t rs				: 1;	/* 16 */
		uint64_t ws				: 1;	/* 15 */
		uint64_t rtsr				: 1;	/* 14 */
		uint64_t rtor				: 1;	/* 13 */
		uint64_t rsr				: 1;	/* 12 */
		uint64_t wb				: 1;	/* 11 */
		uint64_t rtsm				: 1;	/* 10 */
		uint64_t interrupt			: 1;	/* 9 */
		uint64_t r_rts				: 1;	/* 8 */
		uint64_t r_rto				: 1;	/* 7 */
		uint64_t r_rs				: 1;	/* 6 */
		uint64_t r_ws				: 1;	/* 5 */
		uint64_t r_wb				: 1;	/* 4 */
		uint64_t rbio				: 1;	/* 3 */
		uint64_t rio				: 1;	/* 2 */
		uint64_t wbio				: 1;	/* 1 */
		uint64_t wio				: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfi_ctr1_match_transaction_u;

#define	wci_sfi_ctr1_match_transaction_rts	\
	bit.rts
#define	wci_sfi_ctr1_match_transaction_rto	\
	bit.rto
#define	wci_sfi_ctr1_match_transaction_rs	\
	bit.rs
#define	wci_sfi_ctr1_match_transaction_ws	\
	bit.ws
#define	wci_sfi_ctr1_match_transaction_rtsr	\
	bit.rtsr
#define	wci_sfi_ctr1_match_transaction_rtor	\
	bit.rtor
#define	wci_sfi_ctr1_match_transaction_rsr	\
	bit.rsr
#define	wci_sfi_ctr1_match_transaction_wb	\
	bit.wb
#define	wci_sfi_ctr1_match_transaction_rtsm	\
	bit.rtsm
#define	wci_sfi_ctr1_match_transaction_interrupt	\
	bit.interrupt
#define	wci_sfi_ctr1_match_transaction_r_rts	\
	bit.r_rts
#define	wci_sfi_ctr1_match_transaction_r_rto	\
	bit.r_rto
#define	wci_sfi_ctr1_match_transaction_r_rs	\
	bit.r_rs
#define	wci_sfi_ctr1_match_transaction_r_ws	\
	bit.r_ws
#define	wci_sfi_ctr1_match_transaction_r_wb	\
	bit.r_wb
#define	wci_sfi_ctr1_match_transaction_rbio	\
	bit.rbio
#define	wci_sfi_ctr1_match_transaction_rio	\
	bit.rio
#define	wci_sfi_ctr1_match_transaction_wbio	\
	bit.wbio
#define	wci_sfi_ctr1_match_transaction_wio	\
	bit.wio


/*
 * wci_sfi_ctr1_match
 */
typedef union {
	struct wci_sfi_ctr1_match {
		uint64_t rsvd_z				: 6;	/* 63:58 */
		uint64_t mask				: 10;	/* 57:48 */
		uint64_t atransid			: 9;	/* 47:39 */
		uint64_t address			: 39;	/* 38:0 */
	} bit;
	uint64_t val;
} wci_sfi_ctr1_match_u;

#define	wci_sfi_ctr1_match_mask	\
	bit.mask
#define	wci_sfi_ctr1_match_atransid	\
	bit.atransid
#define	wci_sfi_ctr1_match_address	\
	bit.address


/*
 * wci_sfi_ctr0_mask
 */
typedef union {
	struct wci_sfi_ctr0_mask {
		uint64_t rsvd_z				: 6;	/* 63:58 */
		uint64_t mask				: 10;	/* 57:48 */
		uint64_t atransid			: 9;	/* 47:39 */
		uint64_t address			: 39;	/* 38:0 */
	} bit;
	uint64_t val;
} wci_sfi_ctr0_mask_u;

#define	wci_sfi_ctr0_mask_mask	\
	bit.mask
#define	wci_sfi_ctr0_mask_atransid	\
	bit.atransid
#define	wci_sfi_ctr0_mask_address	\
	bit.address


/*
 * wci_sfi_ctr0_match_transaction
 */
typedef union {
	struct wci_sfi_ctr0_match_transaction {
		uint64_t rsvd_z				: 45;	/* 63:19 */
		uint64_t rts				: 1;	/* 18 */
		uint64_t rto				: 1;	/* 17 */
		uint64_t rs				: 1;	/* 16 */
		uint64_t ws				: 1;	/* 15 */
		uint64_t rtsr				: 1;	/* 14 */
		uint64_t rtor				: 1;	/* 13 */
		uint64_t rsr				: 1;	/* 12 */
		uint64_t wb				: 1;	/* 11 */
		uint64_t rtsm				: 1;	/* 10 */
		uint64_t interrupt			: 1;	/* 9 */
		uint64_t r_rts				: 1;	/* 8 */
		uint64_t r_rto				: 1;	/* 7 */
		uint64_t r_rs				: 1;	/* 6 */
		uint64_t r_ws				: 1;	/* 5 */
		uint64_t r_wb				: 1;	/* 4 */
		uint64_t rbio				: 1;	/* 3 */
		uint64_t rio				: 1;	/* 2 */
		uint64_t wbio				: 1;	/* 1 */
		uint64_t wio				: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sfi_ctr0_match_transaction_u;

#define	wci_sfi_ctr0_match_transaction_rts	\
	bit.rts
#define	wci_sfi_ctr0_match_transaction_rto	\
	bit.rto
#define	wci_sfi_ctr0_match_transaction_rs	\
	bit.rs
#define	wci_sfi_ctr0_match_transaction_ws	\
	bit.ws
#define	wci_sfi_ctr0_match_transaction_rtsr	\
	bit.rtsr
#define	wci_sfi_ctr0_match_transaction_rtor	\
	bit.rtor
#define	wci_sfi_ctr0_match_transaction_rsr	\
	bit.rsr
#define	wci_sfi_ctr0_match_transaction_wb	\
	bit.wb
#define	wci_sfi_ctr0_match_transaction_rtsm	\
	bit.rtsm
#define	wci_sfi_ctr0_match_transaction_interrupt	\
	bit.interrupt
#define	wci_sfi_ctr0_match_transaction_r_rts	\
	bit.r_rts
#define	wci_sfi_ctr0_match_transaction_r_rto	\
	bit.r_rto
#define	wci_sfi_ctr0_match_transaction_r_rs	\
	bit.r_rs
#define	wci_sfi_ctr0_match_transaction_r_ws	\
	bit.r_ws
#define	wci_sfi_ctr0_match_transaction_r_wb	\
	bit.r_wb
#define	wci_sfi_ctr0_match_transaction_rbio	\
	bit.rbio
#define	wci_sfi_ctr0_match_transaction_rio	\
	bit.rio
#define	wci_sfi_ctr0_match_transaction_wbio	\
	bit.wbio
#define	wci_sfi_ctr0_match_transaction_wio	\
	bit.wio


/*
 * wci_sfi_ctr0_match
 */
typedef union {
	struct wci_sfi_ctr0_match {
		uint64_t rsvd_z				: 6;	/* 63:58 */
		uint64_t mask				: 10;	/* 57:48 */
		uint64_t atransid			: 9;	/* 47:39 */
		uint64_t address			: 39;	/* 38:0 */
	} bit;
	uint64_t val;
} wci_sfi_ctr0_match_u;

#define	wci_sfi_ctr0_match_mask	\
	bit.mask
#define	wci_sfi_ctr0_match_atransid	\
	bit.atransid
#define	wci_sfi_ctr0_match_address	\
	bit.address


/*
 * wci_sfi_analyzer
 */
typedef union {
	struct wci_sfi_analyzer {
		uint64_t valid				: 1;	/* 63 */
		uint64_t in_use				: 1;	/* 62 */
		uint64_t shared				: 1;	/* 61 */
		uint64_t owned				: 1;	/* 60 */
		uint64_t mapped				: 1;	/* 59 */
		uint64_t overflow			: 6;	/* 58:53 */
		uint64_t address			: 39;	/* 52:14 */
		uint64_t mask				: 4;	/* 13:10 */
		uint64_t command			: 1;	/* 9 */
		uint64_t atransid			: 9;	/* 8:0 */
	} bit;
	uint64_t val;
} wci_sfi_analyzer_u;

#define	wci_sfi_analyzer_valid	\
	bit.valid
#define	wci_sfi_analyzer_in_use	\
	bit.in_use
#define	wci_sfi_analyzer_shared	\
	bit.shared
#define	wci_sfi_analyzer_owned	\
	bit.owned
#define	wci_sfi_analyzer_mapped	\
	bit.mapped
#define	wci_sfi_analyzer_overflow	\
	bit.overflow
#define	wci_sfi_analyzer_address	\
	bit.address
#define	wci_sfi_analyzer_mask	\
	bit.mask
#define	wci_sfi_analyzer_command	\
	bit.command
#define	wci_sfi_analyzer_atransid	\
	bit.atransid


/*
 * wci_sfi_route_map0
 */
typedef union {
	struct wci_sfi_route_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sfi_route_map0_u;

#define	wci_sfi_route_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_sfi_route_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_sfi_route_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_sfi_route_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_sfi_route_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_sfi_route_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_sfi_route_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_sfi_route_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_sfi_route_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_sfi_route_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_sfi_route_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_sfi_route_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_sfi_route_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_sfi_route_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_sfi_route_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_sfi_route_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_sfi_route_map1
 */
typedef union {
	struct wci_sfi_route_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sfi_route_map1_u;

#define	wci_sfi_route_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_sfi_route_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_sfi_route_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_sfi_route_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_sfi_route_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_sfi_route_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_sfi_route_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_sfi_route_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_sfi_route_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_sfi_route_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_sfi_route_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_sfi_route_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_sfi_route_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_sfi_route_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_sfi_route_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_sfi_route_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_qlim_sort_piq
 */
typedef union {
	struct wci_qlim_sort_piq {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t dev_id_vec			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_qlim_sort_piq_u;

#define	wci_qlim_sort_piq_dev_id_vec	\
	bit.dev_id_vec


/*
 * wci_qlim_sort_niq
 */
typedef union {
	struct wci_qlim_sort_niq {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t dev_id_vec			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_qlim_sort_niq_u;

#define	wci_qlim_sort_niq_dev_id_vec	\
	bit.dev_id_vec


/*
 * wci_qlim_sort_ciq
 */
typedef union {
	struct wci_qlim_sort_ciq {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t dev_id_vec			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_qlim_sort_ciq_u;

#define	wci_qlim_sort_ciq_dev_id_vec	\
	bit.dev_id_vec


/*
 * wci_link_esr
 */
typedef union {
	struct wci_link_esr {
		uint64_t rsvd_z				: 40;	/* 63:24 */
		uint64_t acc_link_2_illegal_gnid	: 1;	/* 23 */
		uint64_t acc_link_2_illegal_link	: 1;	/* 22 */
		uint64_t rsvd_y				: 1;	/* 21 */
		uint64_t acc_link_1_illegal_gnid	: 1;	/* 20 */
		uint64_t acc_link_1_illegal_link	: 1;	/* 19 */
		uint64_t rsvd_x				: 1;	/* 18 */
		uint64_t acc_link_0_illegal_gnid	: 1;	/* 17 */
		uint64_t acc_link_0_illegal_link	: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_w				: 7;	/* 14:8 */
		uint64_t link_2_illegal_gnid		: 1;	/* 7 */
		uint64_t link_2_illegal_link		: 1;	/* 6 */
		uint64_t rsvd_v				: 1;	/* 5 */
		uint64_t link_1_illegal_gnid		: 1;	/* 4 */
		uint64_t link_1_illegal_link		: 1;	/* 3 */
		uint64_t rsvd_u				: 1;	/* 2 */
		uint64_t link_0_illegal_gnid		: 1;	/* 1 */
		uint64_t link_0_illegal_link		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_link_esr_u;

#define	wci_link_esr_acc_link_2_illegal_gnid	\
	bit.acc_link_2_illegal_gnid
#define	wci_link_esr_acc_link_2_illegal_link	\
	bit.acc_link_2_illegal_link
#define	wci_link_esr_acc_link_1_illegal_gnid	\
	bit.acc_link_1_illegal_gnid
#define	wci_link_esr_acc_link_1_illegal_link	\
	bit.acc_link_1_illegal_link
#define	wci_link_esr_acc_link_0_illegal_gnid	\
	bit.acc_link_0_illegal_gnid
#define	wci_link_esr_acc_link_0_illegal_link	\
	bit.acc_link_0_illegal_link
#define	wci_link_esr_first_error	\
	bit.first_error
#define	wci_link_esr_link_2_illegal_gnid	\
	bit.link_2_illegal_gnid
#define	wci_link_esr_link_2_illegal_link	\
	bit.link_2_illegal_link
#define	wci_link_esr_link_1_illegal_gnid	\
	bit.link_1_illegal_gnid
#define	wci_link_esr_link_1_illegal_link	\
	bit.link_1_illegal_link
#define	wci_link_esr_link_0_illegal_gnid	\
	bit.link_0_illegal_gnid
#define	wci_link_esr_link_0_illegal_link	\
	bit.link_0_illegal_link


/*
 * wci_link_esr_mask
 */
typedef union {
	struct wci_link_esr_mask {
		uint64_t rsvd_z				: 56;	/* 63:8 */
		uint64_t link_2_illegal_gnid		: 1;	/* 7 */
		uint64_t link_2_illegal_link		: 1;	/* 6 */
		uint64_t rsvd_y				: 1;	/* 5 */
		uint64_t link_1_illegal_gnid		: 1;	/* 4 */
		uint64_t link_1_illegal_link		: 1;	/* 3 */
		uint64_t rsvd_x				: 1;	/* 2 */
		uint64_t link_0_illegal_gnid		: 1;	/* 1 */
		uint64_t link_0_illegal_link		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_link_esr_mask_u;

#define	wci_link_esr_mask_link_2_illegal_gnid	\
	bit.link_2_illegal_gnid
#define	wci_link_esr_mask_link_2_illegal_link	\
	bit.link_2_illegal_link
#define	wci_link_esr_mask_link_1_illegal_gnid	\
	bit.link_1_illegal_gnid
#define	wci_link_esr_mask_link_1_illegal_link	\
	bit.link_1_illegal_link
#define	wci_link_esr_mask_link_0_illegal_gnid	\
	bit.link_0_illegal_gnid
#define	wci_link_esr_mask_link_0_illegal_link	\
	bit.link_0_illegal_link


/*
 * wci_sw_esr
 */
typedef union {
	struct wci_sw_esr {
		uint64_t rsvd_z				: 36;	/* 63:28 */
		uint64_t acc_link_2_failover		: 1;	/* 27 */
		uint64_t acc_link_1_failover		: 1;	/* 26 */
		uint64_t acc_link_0_failover		: 1;	/* 25 */
		uint64_t rsvd_y				: 2;	/* 24:23 */
		uint64_t acc_link_2_auto_shut		: 1;	/* 22 */
		uint64_t acc_link_1_auto_shut		: 1;	/* 21 */
		uint64_t acc_link_0_auto_shut		: 1;	/* 20 */
		uint64_t acc_addr_lpbk_illegal_gnid	: 1;	/* 19 */
		uint64_t acc_error_pause_broadcast	: 1;	/* 18 */
		uint64_t acc_addr_lpbk_fifo_ovf		: 1;	/* 17 */
		uint64_t acc_data_lpbk_fifo_ovf		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_x				: 3;	/* 14:12 */
		uint64_t link_2_failover		: 1;	/* 11 */
		uint64_t link_1_failover		: 1;	/* 10 */
		uint64_t link_0_failover		: 1;	/* 9 */
		uint64_t rsvd_w				: 2;	/* 8:7 */
		uint64_t link_2_auto_shut		: 1;	/* 6 */
		uint64_t link_1_auto_shut		: 1;	/* 5 */
		uint64_t link_0_auto_shut		: 1;	/* 4 */
		uint64_t addr_lpbk_illegal_gnid		: 1;	/* 3 */
		uint64_t error_pause_broadcast		: 1;	/* 2 */
		uint64_t addr_lpbk_fifo_ovf		: 1;	/* 1 */
		uint64_t data_lpbk_fifo_ovf		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_esr_u;

#define	wci_sw_esr_acc_link_2_failover	\
	bit.acc_link_2_failover
#define	wci_sw_esr_acc_link_1_failover	\
	bit.acc_link_1_failover
#define	wci_sw_esr_acc_link_0_failover	\
	bit.acc_link_0_failover
#define	wci_sw_esr_acc_link_2_auto_shut	\
	bit.acc_link_2_auto_shut
#define	wci_sw_esr_acc_link_1_auto_shut	\
	bit.acc_link_1_auto_shut
#define	wci_sw_esr_acc_link_0_auto_shut	\
	bit.acc_link_0_auto_shut
#define	wci_sw_esr_acc_addr_lpbk_illegal_gnid	\
	bit.acc_addr_lpbk_illegal_gnid
#define	wci_sw_esr_acc_error_pause_broadcast	\
	bit.acc_error_pause_broadcast
#define	wci_sw_esr_acc_addr_lpbk_fifo_ovf	\
	bit.acc_addr_lpbk_fifo_ovf
#define	wci_sw_esr_acc_data_lpbk_fifo_ovf	\
	bit.acc_data_lpbk_fifo_ovf
#define	wci_sw_esr_first_error	\
	bit.first_error
#define	wci_sw_esr_link_2_failover	\
	bit.link_2_failover
#define	wci_sw_esr_link_1_failover	\
	bit.link_1_failover
#define	wci_sw_esr_link_0_failover	\
	bit.link_0_failover
#define	wci_sw_esr_link_2_auto_shut	\
	bit.link_2_auto_shut
#define	wci_sw_esr_link_1_auto_shut	\
	bit.link_1_auto_shut
#define	wci_sw_esr_link_0_auto_shut	\
	bit.link_0_auto_shut
#define	wci_sw_esr_addr_lpbk_illegal_gnid	\
	bit.addr_lpbk_illegal_gnid
#define	wci_sw_esr_error_pause_broadcast	\
	bit.error_pause_broadcast
#define	wci_sw_esr_addr_lpbk_fifo_ovf	\
	bit.addr_lpbk_fifo_ovf
#define	wci_sw_esr_data_lpbk_fifo_ovf	\
	bit.data_lpbk_fifo_ovf


/*
 * wci_sw_esr_mask
 */
typedef union {
	struct wci_sw_esr_mask {
		uint64_t rsvd_z				: 52;	/* 63:12 */
		uint64_t link_2_failover		: 1;	/* 11 */
		uint64_t link_1_failover		: 1;	/* 10 */
		uint64_t link_0_failover		: 1;	/* 9 */
		uint64_t rsvd_y				: 2;	/* 8:7 */
		uint64_t link_2_auto_shut		: 1;	/* 6 */
		uint64_t link_1_auto_shut		: 1;	/* 5 */
		uint64_t link_0_auto_shut		: 1;	/* 4 */
		uint64_t addr_lpbk_illegal_gnid		: 1;	/* 3 */
		uint64_t error_pause_broadcast		: 1;	/* 2 */
		uint64_t addr_lpbk_fifo_ovf		: 1;	/* 1 */
		uint64_t data_lpbk_fifo_ovf		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_esr_mask_u;

#define	wci_sw_esr_mask_link_2_failover	\
	bit.link_2_failover
#define	wci_sw_esr_mask_link_1_failover	\
	bit.link_1_failover
#define	wci_sw_esr_mask_link_0_failover	\
	bit.link_0_failover
#define	wci_sw_esr_mask_link_2_auto_shut	\
	bit.link_2_auto_shut
#define	wci_sw_esr_mask_link_1_auto_shut	\
	bit.link_1_auto_shut
#define	wci_sw_esr_mask_link_0_auto_shut	\
	bit.link_0_auto_shut
#define	wci_sw_esr_mask_addr_lpbk_illegal_gnid	\
	bit.addr_lpbk_illegal_gnid
#define	wci_sw_esr_mask_error_pause_broadcast	\
	bit.error_pause_broadcast
#define	wci_sw_esr_mask_addr_lpbk_fifo_ovf	\
	bit.addr_lpbk_fifo_ovf
#define	wci_sw_esr_mask_data_lpbk_fifo_ovf	\
	bit.data_lpbk_fifo_ovf


/*
 * wci_sw_link_control
 */
typedef union {
	struct wci_sw_link_control {
		uint64_t rsvd_z				: 9;	/* 63:55 */
		uint64_t rexmit_freeze			: 1;	/* 54 */
		uint64_t rexmit_mag			: 2;	/* 53:52 */
		uint64_t rexmit_val			: 8;	/* 51:44 */
		uint64_t error_inducement		: 2;	/* 43:42 */
		uint64_t xmit_timeout			: 8;	/* 41:34 */
		uint64_t usr_data_2			: 2;	/* 33:32 */
		uint64_t usr_data_1			: 16;	/* 31:16 */
		uint64_t rsvd_y				: 3;	/* 15:13 */
		uint64_t xmit_enable			: 1;	/* 12 */
		uint64_t ustat_src			: 2;	/* 11:10 */
		uint64_t in_domain			: 1;	/* 9 */
		uint64_t paroli_tck_enable		: 1;	/* 8 */
		uint64_t laser_enable			: 1;	/* 7 */
		uint64_t rsvd_x				: 1;	/* 6 */
		uint64_t rexmit_shutdown_en		: 1;	/* 5 */
		uint64_t near_end_shutdown_lock		: 1;	/* 4 */
		uint64_t failover_en			: 1;	/* 3 */
		uint64_t auto_shut_en			: 1;	/* 2 */
		uint64_t link_state			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sw_link_control_u;

#define	wci_sw_link_control_rexmit_freeze	\
	bit.rexmit_freeze
#define	wci_sw_link_control_rexmit_mag	\
	bit.rexmit_mag
#define	wci_sw_link_control_rexmit_val	\
	bit.rexmit_val
#define	wci_sw_link_control_error_inducement	\
	bit.error_inducement
#define	wci_sw_link_control_xmit_timeout	\
	bit.xmit_timeout
#define	wci_sw_link_control_usr_data_2	\
	bit.usr_data_2
#define	wci_sw_link_control_usr_data_1	\
	bit.usr_data_1
#define	wci_sw_link_control_xmit_enable	\
	bit.xmit_enable
#define	wci_sw_link_control_ustat_src	\
	bit.ustat_src
#define	wci_sw_link_control_in_domain	\
	bit.in_domain
#define	wci_sw_link_control_paroli_tck_enable	\
	bit.paroli_tck_enable
#define	wci_sw_link_control_laser_enable	\
	bit.laser_enable
#define	wci_sw_link_control_rexmit_shutdown_en	\
	bit.rexmit_shutdown_en
#define	wci_sw_link_control_near_end_shutdown_lock	\
	bit.near_end_shutdown_lock
#define	wci_sw_link_control_failover_en	\
	bit.failover_en
#define	wci_sw_link_control_auto_shut_en	\
	bit.auto_shut_en
#define	wci_sw_link_control_link_state	\
	bit.link_state


/*
 * wci_sw_link_error_count
 */
typedef union {
	struct wci_sw_link_error_count {
		uint64_t error_count			: 24;	/* 63:40 */
		uint64_t rsvd_z				: 40;	/* 39:0 */
	} bit;
	uint64_t val;
} wci_sw_link_error_count_u;

#define	wci_sw_link_error_count_error_count	\
	bit.error_count


/*
 * wci_sw_link_status
 */
typedef union {
	struct wci_sw_link_status {
		uint64_t rsvd_z				: 9;	/* 63:55 */
		uint64_t paroli_present			: 1;	/* 54 */
		uint64_t bad_gnid			: 4;	/* 53:50 */
		uint64_t farend_ustat_2			: 2;	/* 49:48 */
		uint64_t farend_ustat_1			: 16;	/* 47:32 */
		uint64_t ustat_1			: 16;	/* 31:16 */
		uint64_t shutdown_cause			: 2;	/* 15:14 */
		uint64_t got_fo_pkt			: 1;	/* 13 */
		uint64_t multiple_link_failover		: 1;	/* 12 */
		uint64_t failover_cause			: 1;	/* 11 */
		uint64_t link_idle			: 1;	/* 10 */
		uint64_t sync_locked			: 1;	/* 9 */
		uint64_t optical_signal_detect		: 1;	/* 8 */
		uint64_t reset_pending			: 1;	/* 7 */
		uint64_t framing_error			: 1;	/* 6 */
		uint64_t clocking_error			: 1;	/* 5 */
		uint64_t end_status			: 2;	/* 4:3 */
		uint64_t crc_error			: 1;	/* 2 */
		uint64_t rsvd_y				: 1;	/* 1 */
		uint64_t packets_discarded		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_link_status_u;

#define	wci_sw_link_status_paroli_present	\
	bit.paroli_present
#define	wci_sw_link_status_bad_gnid	\
	bit.bad_gnid
#define	wci_sw_link_status_farend_ustat_2	\
	bit.farend_ustat_2
#define	wci_sw_link_status_farend_ustat_1	\
	bit.farend_ustat_1
#define	wci_sw_link_status_ustat_1	\
	bit.ustat_1
#define	wci_sw_link_status_shutdown_cause	\
	bit.shutdown_cause
#define	wci_sw_link_status_got_fo_pkt	\
	bit.got_fo_pkt
#define	wci_sw_link_status_multiple_link_failover	\
	bit.multiple_link_failover
#define	wci_sw_link_status_failover_cause	\
	bit.failover_cause
#define	wci_sw_link_status_link_idle	\
	bit.link_idle
#define	wci_sw_link_status_sync_locked	\
	bit.sync_locked
#define	wci_sw_link_status_optical_signal_detect	\
	bit.optical_signal_detect
#define	wci_sw_link_status_reset_pending	\
	bit.reset_pending
#define	wci_sw_link_status_framing_error	\
	bit.framing_error
#define	wci_sw_link_status_clocking_error	\
	bit.clocking_error
#define	wci_sw_link_status_end_status	\
	bit.end_status
#define	wci_sw_link_status_crc_error	\
	bit.crc_error
#define	wci_sw_link_status_packets_discarded	\
	bit.packets_discarded


/*
 * wci_sw_config
 */
typedef union {
	struct wci_sw_config {
		uint64_t max_errors			: 24;	/* 63:40 */
		uint64_t rsvd_z				: 23;	/* 39:17 */
		uint64_t error_pause_shutdown_en	: 1;	/* 16 */
		uint64_t partner_gnid			: 4;	/* 15:12 */
		uint64_t gnid				: 4;	/* 11:8 */
		uint64_t failover_en			: 1;	/* 7 */
		uint64_t drop_illegal_gnid		: 1;	/* 6 */
		uint64_t sync_buffer_safety_level	: 2;	/* 5:4 */
		uint64_t mask_originate_broadcast	: 1;	/* 3 */
		uint64_t xmit_arb_policy		: 2;	/* 2:1 */
		uint64_t enable_dx_shortcut		: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_config_u;

#define	wci_sw_config_max_errors	\
	bit.max_errors
#define	wci_sw_config_error_pause_shutdown_en	\
	bit.error_pause_shutdown_en
#define	wci_sw_config_partner_gnid	\
	bit.partner_gnid
#define	wci_sw_config_gnid	\
	bit.gnid
#define	wci_sw_config_failover_en	\
	bit.failover_en
#define	wci_sw_config_drop_illegal_gnid	\
	bit.drop_illegal_gnid
#define	wci_sw_config_sync_buffer_safety_level	\
	bit.sync_buffer_safety_level
#define	wci_sw_config_mask_originate_broadcast	\
	bit.mask_originate_broadcast
#define	wci_sw_config_xmit_arb_policy	\
	bit.xmit_arb_policy
#define	wci_sw_config_enable_dx_shortcut	\
	bit.enable_dx_shortcut


/*
 * wci_sw_status
 */
typedef union {
	struct wci_sw_status {
		uint64_t rsvd_z				: 55;	/* 63:9 */
		uint64_t addr_lpbk_illegal_gnid		: 4;	/* 8:5 */
		uint64_t error_pause_broadcast_status	: 3;	/* 4:2 */
		uint64_t originate			: 1;	/* 1 */
		uint64_t local_source			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_status_u;

#define	wci_sw_status_addr_lpbk_illegal_gnid	\
	bit.addr_lpbk_illegal_gnid
#define	wci_sw_status_error_pause_broadcast_status	\
	bit.error_pause_broadcast_status
#define	wci_sw_status_originate	\
	bit.originate
#define	wci_sw_status_local_source	\
	bit.local_source


/*
 * wci_link_ctr_ctl
 */
typedef union {
	struct wci_link_ctr_ctl {
		uint64_t rsvd_z				: 33;	/* 63:31 */
		uint64_t cnt1_source_select		: 2;	/* 30:29 */
		uint64_t cnt1_gnid_target		: 4;	/* 28:25 */
		uint64_t cnt1_snid_target		: 4;	/* 24:21 */
		uint64_t cnt1_rcvd_admin_packet		: 1;	/* 20 */
		uint64_t cnt1_rejected_normal_flit	: 1;	/* 19 */
		uint64_t cnt1_data_rcvd_data_packet	: 1;	/* 18 */
		uint64_t cnt1_mhop_rcvd_data_packet	: 1;	/* 17 */
		uint64_t cnt1_xmitting_admin_packet	: 1;	/* 16 */
		uint64_t rsvd_y				: 1;	/* 15 */
		uint64_t cnt0_source_select		: 2;	/* 14:13 */
		uint64_t cnt0_gnid_target		: 4;	/* 12:9 */
		uint64_t cnt0_snid_target		: 4;	/* 8:5 */
		uint64_t cnt0_rcvd_admin_packet		: 1;	/* 4 */
		uint64_t cnt0_rejected_normal_flit	: 1;	/* 3 */
		uint64_t cnt0_data_rcvd_data_packet	: 1;	/* 2 */
		uint64_t cnt0_mhop_rcvd_data_packet	: 1;	/* 1 */
		uint64_t cnt0_xmitting_admin_packet	: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_link_ctr_ctl_u;

#define	wci_link_ctr_ctl_cnt1_source_select	\
	bit.cnt1_source_select
#define	wci_link_ctr_ctl_cnt1_gnid_target	\
	bit.cnt1_gnid_target
#define	wci_link_ctr_ctl_cnt1_snid_target	\
	bit.cnt1_snid_target
#define	wci_link_ctr_ctl_cnt1_rcvd_admin_packet	\
	bit.cnt1_rcvd_admin_packet
#define	wci_link_ctr_ctl_cnt1_rejected_normal_flit	\
	bit.cnt1_rejected_normal_flit
#define	wci_link_ctr_ctl_cnt1_data_rcvd_data_packet	\
	bit.cnt1_data_rcvd_data_packet
#define	wci_link_ctr_ctl_cnt1_mhop_rcvd_data_packet	\
	bit.cnt1_mhop_rcvd_data_packet
#define	wci_link_ctr_ctl_cnt1_xmitting_admin_packet	\
	bit.cnt1_xmitting_admin_packet
#define	wci_link_ctr_ctl_cnt0_source_select	\
	bit.cnt0_source_select
#define	wci_link_ctr_ctl_cnt0_gnid_target	\
	bit.cnt0_gnid_target
#define	wci_link_ctr_ctl_cnt0_snid_target	\
	bit.cnt0_snid_target
#define	wci_link_ctr_ctl_cnt0_rcvd_admin_packet	\
	bit.cnt0_rcvd_admin_packet
#define	wci_link_ctr_ctl_cnt0_rejected_normal_flit	\
	bit.cnt0_rejected_normal_flit
#define	wci_link_ctr_ctl_cnt0_data_rcvd_data_packet	\
	bit.cnt0_data_rcvd_data_packet
#define	wci_link_ctr_ctl_cnt0_mhop_rcvd_data_packet	\
	bit.cnt0_mhop_rcvd_data_packet
#define	wci_link_ctr_ctl_cnt0_xmitting_admin_packet	\
	bit.cnt0_xmitting_admin_packet


/*
 * wci_lpbk_ctr_ctl
 */
typedef union {
	struct wci_lpbk_ctr_ctl {
		uint64_t rsvd_z				: 38;	/* 63:26 */
		uint64_t cnt1_data_gnid_source_select	: 1;	/* 25 */
		uint64_t cnt1_data_gnid_target		: 4;	/* 24:21 */
		uint64_t cnt1_addr_lpbk_full		: 1;	/* 20 */
		uint64_t cnt1_data_lpbk_full		: 1;	/* 19 */
		uint64_t cnt1_addr_lpbk_rcvd_addr_1_packet	: 1;	/* 18 */
		uint64_t cnt1_addr_lpbk_rcvd_addr_2_packet	: 1;	/* 17 */
		uint64_t cnt1_data_lpbk_rcvd_data_packet	: 1;	/* 16 */
		uint64_t rsvd_y				: 6;	/* 15:10 */
		uint64_t cnt0_data_gnid_source_select	: 1;	/* 9 */
		uint64_t cnt0_data_gnid_target		: 4;	/* 8:5 */
		uint64_t cnt0_addr_lpbk_full		: 1;	/* 4 */
		uint64_t cnt0_data_lpbk_full		: 1;	/* 3 */
		uint64_t cnt0_addr_lpbk_rcvd_addr_1_packet	: 1;	/* 2 */
		uint64_t cnt0_addr_lpbk_rcvd_addr_2_packet	: 1;	/* 1 */
		uint64_t cnt0_data_lpbk_rcvd_data_packet	: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_lpbk_ctr_ctl_u;

#define	wci_lpbk_ctr_ctl_cnt1_data_gnid_source_select	\
	bit.cnt1_data_gnid_source_select
#define	wci_lpbk_ctr_ctl_cnt1_data_gnid_target	\
	bit.cnt1_data_gnid_target
#define	wci_lpbk_ctr_ctl_cnt1_addr_lpbk_full	\
	bit.cnt1_addr_lpbk_full
#define	wci_lpbk_ctr_ctl_cnt1_data_lpbk_full	\
	bit.cnt1_data_lpbk_full
#define	wci_lpbk_ctr_ctl_cnt1_addr_lpbk_rcvd_addr_1_packet	\
	bit.cnt1_addr_lpbk_rcvd_addr_1_packet
#define	wci_lpbk_ctr_ctl_cnt1_addr_lpbk_rcvd_addr_2_packet	\
	bit.cnt1_addr_lpbk_rcvd_addr_2_packet
#define	wci_lpbk_ctr_ctl_cnt1_data_lpbk_rcvd_data_packet	\
	bit.cnt1_data_lpbk_rcvd_data_packet
#define	wci_lpbk_ctr_ctl_cnt0_data_gnid_source_select	\
	bit.cnt0_data_gnid_source_select
#define	wci_lpbk_ctr_ctl_cnt0_data_gnid_target	\
	bit.cnt0_data_gnid_target
#define	wci_lpbk_ctr_ctl_cnt0_addr_lpbk_full	\
	bit.cnt0_addr_lpbk_full
#define	wci_lpbk_ctr_ctl_cnt0_data_lpbk_full	\
	bit.cnt0_data_lpbk_full
#define	wci_lpbk_ctr_ctl_cnt0_addr_lpbk_rcvd_addr_1_packet	\
	bit.cnt0_addr_lpbk_rcvd_addr_1_packet
#define	wci_lpbk_ctr_ctl_cnt0_addr_lpbk_rcvd_addr_2_packet	\
	bit.cnt0_addr_lpbk_rcvd_addr_2_packet
#define	wci_lpbk_ctr_ctl_cnt0_data_lpbk_rcvd_data_packet	\
	bit.cnt0_data_lpbk_rcvd_data_packet


/*
 * wci_link_ctr
 */
typedef union {
	struct wci_link_ctr {
		uint64_t cnt1				: 32;	/* 63:32 */
		uint64_t cnt0				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_link_ctr_u;

#define	wci_link_ctr_cnt1	\
	bit.cnt1
#define	wci_link_ctr_cnt0	\
	bit.cnt0


/*
 * wci_lpbk_ctr
 */
typedef union {
	struct wci_lpbk_ctr {
		uint64_t cnt1				: 32;	/* 63:32 */
		uint64_t cnt0				: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_lpbk_ctr_u;

#define	wci_lpbk_ctr_cnt1	\
	bit.cnt1
#define	wci_lpbk_ctr_cnt0	\
	bit.cnt0


/*
 * wci_sw_esr_a
 */
typedef union {
	struct wci_sw_esr_a {
		uint64_t rsvd_z				: 46;	/* 63:18 */
		uint64_t acc_fo_b_fifo_ovf		: 1;	/* 17 */
		uint64_t acc_fo_a_fifo_ovf		: 1;	/* 16 */
		uint64_t first_error			: 1;	/* 15 */
		uint64_t rsvd_y				: 13;	/* 14:2 */
		uint64_t fo_b_fifo_ovf			: 1;	/* 1 */
		uint64_t fo_a_fifo_ovf			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_esr_a_u;

#define	wci_sw_esr_a_acc_fo_b_fifo_ovf	\
	bit.acc_fo_b_fifo_ovf
#define	wci_sw_esr_a_acc_fo_a_fifo_ovf	\
	bit.acc_fo_a_fifo_ovf
#define	wci_sw_esr_a_first_error	\
	bit.first_error
#define	wci_sw_esr_a_fo_b_fifo_ovf	\
	bit.fo_b_fifo_ovf
#define	wci_sw_esr_a_fo_a_fifo_ovf	\
	bit.fo_a_fifo_ovf


/*
 * wci_sw_esr_a_mask
 */
typedef union {
	struct wci_sw_esr_a_mask {
		uint64_t rsvd_z				: 62;	/* 63:2 */
		uint64_t fo_b_fifo_ovf			: 1;	/* 1 */
		uint64_t fo_a_fifo_ovf			: 1;	/* 0 */
	} bit;
	uint64_t val;
} wci_sw_esr_a_mask_u;

#define	wci_sw_esr_a_mask_fo_b_fifo_ovf	\
	bit.fo_b_fifo_ovf
#define	wci_sw_esr_a_mask_fo_a_fifo_ovf	\
	bit.fo_a_fifo_ovf


/*
 * wci_gnid_map0
 */
typedef union {
	struct wci_gnid_map0 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_gnid_map0_u;

#define	wci_gnid_map0_node15_tlink	\
	bit.node15_tlink
#define	wci_gnid_map0_node14_tlink	\
	bit.node14_tlink
#define	wci_gnid_map0_node13_tlink	\
	bit.node13_tlink
#define	wci_gnid_map0_node12_tlink	\
	bit.node12_tlink
#define	wci_gnid_map0_node11_tlink	\
	bit.node11_tlink
#define	wci_gnid_map0_node10_tlink	\
	bit.node10_tlink
#define	wci_gnid_map0_node9_tlink	\
	bit.node9_tlink
#define	wci_gnid_map0_node8_tlink	\
	bit.node8_tlink
#define	wci_gnid_map0_node7_tlink	\
	bit.node7_tlink
#define	wci_gnid_map0_node6_tlink	\
	bit.node6_tlink
#define	wci_gnid_map0_node5_tlink	\
	bit.node5_tlink
#define	wci_gnid_map0_node4_tlink	\
	bit.node4_tlink
#define	wci_gnid_map0_node3_tlink	\
	bit.node3_tlink
#define	wci_gnid_map0_node2_tlink	\
	bit.node2_tlink
#define	wci_gnid_map0_node1_tlink	\
	bit.node1_tlink
#define	wci_gnid_map0_node0_tlink	\
	bit.node0_tlink


/*
 * wci_gnid_map1
 */
typedef union {
	struct wci_gnid_map1 {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_gnid_map1_u;

#define	wci_gnid_map1_node15_tlink	\
	bit.node15_tlink
#define	wci_gnid_map1_node14_tlink	\
	bit.node14_tlink
#define	wci_gnid_map1_node13_tlink	\
	bit.node13_tlink
#define	wci_gnid_map1_node12_tlink	\
	bit.node12_tlink
#define	wci_gnid_map1_node11_tlink	\
	bit.node11_tlink
#define	wci_gnid_map1_node10_tlink	\
	bit.node10_tlink
#define	wci_gnid_map1_node9_tlink	\
	bit.node9_tlink
#define	wci_gnid_map1_node8_tlink	\
	bit.node8_tlink
#define	wci_gnid_map1_node7_tlink	\
	bit.node7_tlink
#define	wci_gnid_map1_node6_tlink	\
	bit.node6_tlink
#define	wci_gnid_map1_node5_tlink	\
	bit.node5_tlink
#define	wci_gnid_map1_node4_tlink	\
	bit.node4_tlink
#define	wci_gnid_map1_node3_tlink	\
	bit.node3_tlink
#define	wci_gnid_map1_node2_tlink	\
	bit.node2_tlink
#define	wci_gnid_map1_node1_tlink	\
	bit.node1_tlink
#define	wci_gnid_map1_node0_tlink	\
	bit.node0_tlink


/*
 * wci_fo_route_map
 */
typedef union {
	struct wci_fo_route_map {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_fo_route_map_u;

#define	wci_fo_route_map_node15_tlink	\
	bit.node15_tlink
#define	wci_fo_route_map_node14_tlink	\
	bit.node14_tlink
#define	wci_fo_route_map_node13_tlink	\
	bit.node13_tlink
#define	wci_fo_route_map_node12_tlink	\
	bit.node12_tlink
#define	wci_fo_route_map_node11_tlink	\
	bit.node11_tlink
#define	wci_fo_route_map_node10_tlink	\
	bit.node10_tlink
#define	wci_fo_route_map_node9_tlink	\
	bit.node9_tlink
#define	wci_fo_route_map_node8_tlink	\
	bit.node8_tlink
#define	wci_fo_route_map_node7_tlink	\
	bit.node7_tlink
#define	wci_fo_route_map_node6_tlink	\
	bit.node6_tlink
#define	wci_fo_route_map_node5_tlink	\
	bit.node5_tlink
#define	wci_fo_route_map_node4_tlink	\
	bit.node4_tlink
#define	wci_fo_route_map_node3_tlink	\
	bit.node3_tlink
#define	wci_fo_route_map_node2_tlink	\
	bit.node2_tlink
#define	wci_fo_route_map_node1_tlink	\
	bit.node1_tlink
#define	wci_fo_route_map_node0_tlink	\
	bit.node0_tlink


/*
 * wci_sec_fo_route_map
 */
typedef union {
	struct wci_sec_fo_route_map {
		uint64_t rsvd_z				: 17;	/* 63:47 */
		uint64_t node15_tlink			: 2;	/* 46:45 */
		uint64_t rsvd_y				: 1;	/* 44 */
		uint64_t node14_tlink			: 2;	/* 43:42 */
		uint64_t rsvd_x				: 1;	/* 41 */
		uint64_t node13_tlink			: 2;	/* 40:39 */
		uint64_t rsvd_w				: 1;	/* 38 */
		uint64_t node12_tlink			: 2;	/* 37:36 */
		uint64_t rsvd_v				: 1;	/* 35 */
		uint64_t node11_tlink			: 2;	/* 34:33 */
		uint64_t rsvd_u				: 1;	/* 32 */
		uint64_t node10_tlink			: 2;	/* 31:30 */
		uint64_t rsvd_t				: 1;	/* 29 */
		uint64_t node9_tlink			: 2;	/* 28:27 */
		uint64_t rsvd_s				: 1;	/* 26 */
		uint64_t node8_tlink			: 2;	/* 25:24 */
		uint64_t rsvd_r				: 1;	/* 23 */
		uint64_t node7_tlink			: 2;	/* 22:21 */
		uint64_t rsvd_q				: 1;	/* 20 */
		uint64_t node6_tlink			: 2;	/* 19:18 */
		uint64_t rsvd_p				: 1;	/* 17 */
		uint64_t node5_tlink			: 2;	/* 16:15 */
		uint64_t rsvd_o				: 1;	/* 14 */
		uint64_t node4_tlink			: 2;	/* 13:12 */
		uint64_t rsvd_n				: 1;	/* 11 */
		uint64_t node3_tlink			: 2;	/* 10:9 */
		uint64_t rsvd_m				: 1;	/* 8 */
		uint64_t node2_tlink			: 2;	/* 7:6 */
		uint64_t rsvd_l				: 1;	/* 5 */
		uint64_t node1_tlink			: 2;	/* 4:3 */
		uint64_t rsvd_k				: 1;	/* 2 */
		uint64_t node0_tlink			: 2;	/* 1:0 */
	} bit;
	uint64_t val;
} wci_sec_fo_route_map_u;

#define	wci_sec_fo_route_map_node15_tlink	\
	bit.node15_tlink
#define	wci_sec_fo_route_map_node14_tlink	\
	bit.node14_tlink
#define	wci_sec_fo_route_map_node13_tlink	\
	bit.node13_tlink
#define	wci_sec_fo_route_map_node12_tlink	\
	bit.node12_tlink
#define	wci_sec_fo_route_map_node11_tlink	\
	bit.node11_tlink
#define	wci_sec_fo_route_map_node10_tlink	\
	bit.node10_tlink
#define	wci_sec_fo_route_map_node9_tlink	\
	bit.node9_tlink
#define	wci_sec_fo_route_map_node8_tlink	\
	bit.node8_tlink
#define	wci_sec_fo_route_map_node7_tlink	\
	bit.node7_tlink
#define	wci_sec_fo_route_map_node6_tlink	\
	bit.node6_tlink
#define	wci_sec_fo_route_map_node5_tlink	\
	bit.node5_tlink
#define	wci_sec_fo_route_map_node4_tlink	\
	bit.node4_tlink
#define	wci_sec_fo_route_map_node3_tlink	\
	bit.node3_tlink
#define	wci_sec_fo_route_map_node2_tlink	\
	bit.node2_tlink
#define	wci_sec_fo_route_map_node1_tlink	\
	bit.node1_tlink
#define	wci_sec_fo_route_map_node0_tlink	\
	bit.node0_tlink


/*
 * wci_fo_tnid_map
 */
typedef union {
	struct wci_fo_tnid_map {
		uint64_t rsvd_z				: 52;	/* 63:12 */
		uint64_t link2_tnid			: 4;	/* 11:8 */
		uint64_t link1_tnid			: 4;	/* 7:4 */
		uint64_t link0_tnid			: 4;	/* 3:0 */
	} bit;
	uint64_t val;
} wci_fo_tnid_map_u;

#define	wci_fo_tnid_map_link2_tnid	\
	bit.link2_tnid
#define	wci_fo_tnid_map_link1_tnid	\
	bit.link1_tnid
#define	wci_fo_tnid_map_link0_tnid	\
	bit.link0_tnid

/*
 * wci_sw_link_rexmit
 */
typedef union {
	struct wci_sw_link_rexmit {
		uint64_t rsvd_z				: 32;	/* 63:32 */
		uint64_t rexmit_count			: 32;	/* 31:0 */
	} bit;
	uint64_t val;
} wci_sw_link_rexmit_u;

#define	wci_sw_link_rexmit_rexmit_count	\
	bit.rexmit_count


/*
 * wci_dnid2gnid
 */
typedef union {
	struct wci_dnid2gnid {
		uint64_t dnid2gnid			: 64;	/* 63:0 */
	} bit;
	uint64_t val;
} wci_dnid2gnid_u;

#define	wci_dnid2gnid_dnid2gnid	\
	bit.dnid2gnid


/* For compatibility with WCI-1 */
#define	ADDR_WCI_ROUTE_MAP0 ADDR_WCI_JNK_ROUTE_MAP0
#define	ADDR_WCI_ROUTE_MAP1 ADDR_WCI_JNK_ROUTE_MAP1
typedef wci_jnk_route_map0_u wci_route_map0_u;
typedef wci_jnk_route_map1_u wci_route_map1_u;

#endif /* _KERNEL && !_ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_WCI_REGS_H */
