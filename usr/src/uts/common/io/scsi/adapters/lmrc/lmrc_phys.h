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
 * Copyright 2023 Racktop Systems, Inc.
 */

#ifndef _LMRC_PHYS_H
#define	_LMRC_PHYS_H

#include <sys/types.h>
#include <sys/debug.h>

typedef struct lmrc_pd_info			lmrc_pd_info_t;
typedef struct lmrc_pd_cfg			lmrc_pd_cfg_t;
typedef struct lmrc_pd_map			lmrc_pd_map_t;
typedef struct lmrc_pd_addr			lmrc_pd_addr_t;
typedef struct lmrc_pd_list			lmrc_pd_list_t;

#include "lmrc.h"
#include "lmrc_raid.h"

#pragma pack(1)

/*
 * PD info
 */
struct lmrc_pd_info {
	uint16_t	pd_dev_id;
	uint16_t	pd_seqnum;
	uint8_t		pd_inq[96];
	uint8_t		pd_vpd83[64];
	uint8_t		pd_notsup;
	uint8_t		pd_scsi_dev_type;

	union {
		uint8_t	pd_conn_port_bitmap;
		uint8_t	pd_conn_port_num;
	};

	uint8_t		pd_dev_speed;
	uint32_t	pd_media_err_cnt;
	uint32_t	pd_other_err_cnt;
	uint32_t	pd_pred_fail_cnt;
	uint32_t	pd_last_pred_fail_evt_seqnum;

	uint16_t	pd_fw_state;
	uint8_t		pd_disabled_for_removal;
	uint8_t		pd_link_speed;

	struct {
		uint32_t	pd_forced_pd_guid:1;
		uint32_t	pd_in_vd:1;
		uint32_t	pd_is_global_spare:1;
		uint32_t	pd_is_spare:1;
		uint32_t	pd_is_foreign:1;
		uint32_t	pd_rsvd:7;
		uint32_t	pd_intf:4;
		uint32_t	pd_rsvd2:16;
	} pd_ddf_type;

	struct {
		uint8_t		pi_count;
		uint8_t		pi_path_broken:4;
		uint8_t		pi_rsvd:3;
		uint8_t		pi_wide_port_cap:1;
		uint8_t		pi_conn_idx[2];
		uint8_t		pi_rsvd2[4];
		uint64_t	pi_sas_addr[2];
		uint8_t		pi_rsvd3[16];
	} pd_pathinfo;

	uint64_t	pd_raw_size;
	uint64_t	pd_non_coerced_size;
	uint64_t	pd_coerced_size;

	uint16_t	pd_encl_dev_id;
	uint8_t		pd_encl_idx;

	union {
		uint8_t	pd_slot_num;
		uint8_t	pd_encl_conn_idx;
	};

	struct {
		uint32_t	pp_active_rbld:1;
		uint32_t	pp_active_patrol:1;
		uint32_t	pp_active_clear:1;
		uint32_t	pp_active_copyback:1;
		uint32_t	pp_active_erase:1;
		uint32_t	pp_active_locate:1;
		uint32_t	pp_active_rsvd:26;

		uint16_t	pp_rbld_progress;
		uint16_t	pp_rbld_elapsed;
		uint16_t	pp_patrol_progress;
		uint16_t	pp_patrol_elapsed;
		uint16_t	pp_erase_progress;
		uint16_t	pp_erase_elapsed;

		uint32_t	pp_pause_rbld:1;
		uint32_t	pp_pause_patrol:1;
		uint32_t	pp_pause_clear:1;
		uint32_t	pp_pause_copyback:1;
		uint32_t	pp_pause_erase:1;
		uint32_t	pp_pause_rsvd:27;

		uint32_t	pp_rsvd[3];
	} pd_progress;

	uint8_t		pd_bad_block_table_full;
	uint8_t		pd_unusable_in_current_config;
	uint8_t		pd_vpd83ext[64];
	uint8_t		pd_powerstate;
	uint8_t		pd_encl_pos;
	uint32_t	pd_allowed_ops;
	uint16_t	pd_copyback_partner_id;
	uint16_t	pd_encl_partner_dev_id;

	struct {
		uint16_t	ps_fde_capable:1;
		uint16_t	ps_fde_enabled:1;
		uint16_t	ps_secured:1;
		uint16_t	ps_locked:1;
		uint16_t	ps_foreign:1;
		uint16_t	ps_needs_EKM:1;
		uint16_t	ps_rsvd:10;
	} pd_security;

	uint8_t		pd_mediatype;
	uint8_t		pd_not_certified;
	uint8_t		pd_bridge_vendor[8];
	uint8_t		pd_bridge_product_id[16];
	uint8_t		pd_bridge_product_rev[4];
	uint8_t		pd_sat_bridge_exists;

	uint8_t		pd_interface_type;
	uint8_t		pd_temperature;
	uint8_t		pd_emulated_blocksize;
	uint16_t	pd_userdata_blocksize;
	uint16_t	pd_rsvd;

	struct {
		uint32_t	pp_pi_type:3;
		uint32_t	pp_pi_formatted:1;
		uint32_t	pp_pi_eligible:1;
		uint32_t	pp_ncq:1;
		uint32_t	pp_wce:1;
		uint32_t	pp_comm_spare:1;
		uint32_t	pp_emerg_spare:1;
		uint32_t	pp_ineligible_for_sscd:1;
		uint32_t	pp_ineligible_for_ld:1;
		uint32_t	pp_use_ss_erase_type:1;
		uint32_t	pp_wce_unchanged:1;
		uint32_t	pp_support_scsi_unmap:1;
		uint32_t	pp_rsvd:18;
	} pd_prop;

	uint64_t	pd_shield_diag_compl_time;
	uint8_t		pd_shield_counter;

	uint8_t		pd_link_speed_other;
	uint8_t		pd_rsvd2[2];

	struct {
		uint32_t bbm_err_count_supported:1;
		uint32_t bbm_err_count:31;
	} pd_bbm_err;

	uint8_t		pd_rsvd3[512 - 428];
};

/*
 * PD config map
 */
struct lmrc_pd_cfg {
	uint16_t	pd_seqnum;
	uint16_t	pd_devhdl;
	struct {
		uint8_t pd_tm_capable:1;
		uint8_t	pd_rsvd:7;
	};
	uint8_t		pd_rsvd2;
	uint16_t	pd_tgtid;
};

struct lmrc_pd_map {
	uint32_t	pm_size;
	uint32_t	pm_count;
	lmrc_pd_cfg_t	pm_pdcfg[0];
};

/*
 * PD address list
 */
struct lmrc_pd_addr {
	uint16_t	pa_dev_id;
	uint16_t	pa_enc_id;

	union {
		struct {
			uint8_t	pa_enc_idx;
			uint8_t	pa_slot_num;
		};
		struct {
			uint8_t	pa_enc_pos;
			uint8_t	pa_enc_conn_idx;
		};
	};
	uint8_t		pa_scsi_dev_type;
	union {
		uint8_t	pa_conn_port_bitmap;
		uint8_t	pa_conn_port_numbers;
	};
	uint64_t	pa_sas_addr[2];
};

#define	LMRC_PD_STATE_UNCONFIGURED_GOOD	0x00
#define	LMRC_PD_STATE_UNCONFIGURED_BAD	0x01
#define	LMRC_PD_STATE_HOT_SPARE		0x02
#define	LMRC_PD_STATE_OFFLINE		0x10
#define	LMRC_PD_STATE_FAILED		0x11
#define	LMRC_PD_STATE_REBUILD		0x14
#define	LMRC_PD_STATE_ONLINE		0x18
#define	LMRC_PD_STATE_COPYBACK		0x20
#define	LMRC_PD_STATE_SYSTEM		0x40

struct lmrc_pd_list {
	uint32_t	pl_size;
	uint32_t	pl_count;
	lmrc_pd_addr_t	pl_addr[0];
};
#pragma pack(0)

int lmrc_setup_pdmap(lmrc_t *);
void lmrc_free_pdmap(lmrc_t *);

boolean_t lmrc_pd_tm_capable(lmrc_t *, uint16_t);

int lmrc_get_pd_list(lmrc_t *);

int lmrc_phys_attach(dev_info_t *);
int lmrc_phys_detach(dev_info_t *);

int lmrc_phys_aen_handler(lmrc_t *, lmrc_evt_t *);

#endif /* _LMRC_PHYS_H */
