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
 * Copyright 2024 Racktop Systems, Inc.
 */

#ifndef	_MFI_LD_H
#define	_MFI_LD_H

#include <sys/debug.h>
#include <sys/types.h>

#include <sys/scsi/adapters/mfi/mfi.h>
#include <sys/scsi/adapters/mfi/mfi_pd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MFI_SPARE_DEDICATED		1
#define	MFI_SPARE_REVERTIBLE		2
#define	MFI_SPARE_ENCL_AFFINITY		4

#define	MFI_LD_STATE_OFFLINE		0
#define	MFI_LD_STATE_PARTIALLY_DEGRADED	1
#define	MFI_LD_STATE_DEGRADED		2
#define	MFI_LD_STATE_OPTIMAL		3

#define	MFI_LD_PARAMS_INIT_NO		0
#define	MFI_LD_PARAMS_INIT_QUICK	1
#define	MFI_LD_PARAMS_INIT_FULL		2

#define	MFI_LD_ACCESS_RW		0
#define	MFI_LD_ACCESS_RO		2
#define	MFI_LD_ACCESS_BLOCKED		3

#define	MFI_LD_CACHE_WRITE_BACK			0x01
#define	MFI_LD_CACHE_WRITE_ADAPTIVE		0x02
#define	MFI_LD_CACHE_READ_AHEAD			0x04
#define	MFI_LD_CACHE_READ_ADAPTIVE		0x08
#define	MFI_LD_CACHE_WRITE_CACHE_BAD_BBU	0x10
#define	MFI_LD_CACHE_ALLOW_WRITE_CACHE		0x20
#define	MFI_LD_CACHE_ALLOW_READ_CACHE		0x40

#define	MFI_MAX_ARRAYS			16
#define	MFI_MAX_ROW_SIZE		32
#define	MFI_MAX_SPAN_DEPTH		8

#pragma pack(1)

/*
 * Array configuration
 */
struct mfi_array {
	uint64_t	ar_size;
	uint8_t		ar_ndrive;
	uint8_t		ar_rsvd;
	uint16_t	ar_ref;
	uint8_t		ar_pad[20];
	struct {
		mfi_pd_ref_t	pd_ref;
		uint16_t	pd_fw_state;
		struct {
			uint8_t	e_idx;
			uint8_t	e_slot;
		} pd_encl;
	} ar_pd[MFI_MAX_ROW_SIZE];
};
CTASSERT(sizeof (mfi_array_t) == 288);

/*
 * Spare
 */
struct mfi_spare {
	mfi_pd_ref_t	s_pd_ref;
	uint8_t		s_type;
	uint8_t		s_rsvd[2];
	uint8_t		s_array_cnt;
	uint16_t	s_array_ref[MFI_MAX_ARRAYS];
};
CTASSERT(sizeof (mfi_spare_t) == 40);

/*
 * LD reference
 */
struct mfi_ld_ref {
	uint8_t		lr_tgtid;
	uint8_t		lr_rsvd;
	uint16_t	lr_seqnum;
};
CTASSERT(sizeof (mfi_ld_ref_t) == 4);

/*
 * LD list
 */
struct mfi_ld_list {
	uint32_t	ll_ld_count;
	uint32_t	ll_rsvd;
	struct {
		mfi_ld_ref_t	ld_ref;
		uint8_t		ld_state;
		uint8_t		ld_rsvd[3];
		uint64_t	ld_size;
	} ll_ld[MFI_MAX_LOGICAL_DRIVES];
};
CTASSERT(sizeof (mfi_ld_list_t) == 1032);

/*
 * LD parameters
 */
struct mfi_ld_parameters {
	uint8_t		lp_primary_raid_lvl;
	uint8_t		lp_raid_lvl_qual;
	uint8_t		lp_secondary_raid_lvl;
	uint8_t		lp_stripe_size;
	uint8_t		lp_ndrive;
	uint8_t		lp_span_depth;
	uint8_t		lp_state;
	uint8_t		lp_init_state;
	uint8_t		lp_is_consistent;
	uint8_t		lp_rsvd1[6];
	uint8_t		lp_is_sscd;
	uint8_t		lp_rsvd2[16];
};
CTASSERT(sizeof (mfi_ld_parameters_t) == 32);

/*
 * LD properties
 */
struct mfi_ld_properties {
	mfi_ld_ref_t	lp_ld;
	char		lp_name[16];
	uint8_t		lp_def_cache_policy;
	uint8_t		lp_access_policy;
	uint8_t		lp_disk_cache_policy;
	uint8_t		lp_cur_cache_policy;
	uint8_t		lp_no_bgi;
	uint8_t		lp_rsvd[7];
};
CTASSERT(sizeof (mfi_ld_properties_t) == 32);

/*
 * LD span
 */
struct mfi_span {
	uint64_t	s_start_block;
	uint64_t	s_num_blocks;
	uint16_t	s_array_ref;
	uint8_t		s_rsvd[6];
};
CTASSERT(sizeof (mfi_span_t) == 24);

/*
 * LD configuration
 */
struct mfi_ld_config {
	mfi_ld_properties_t	lc_props;
	mfi_ld_parameters_t	lc_params;
	mfi_span_t		lc_span[MFI_MAX_SPAN_DEPTH];
};
CTASSERT(sizeof (mfi_ld_config_t) == 256);

/*
 * LD progress
 */
struct mfi_ld_progress {
	struct {
		uint32_t	lp_active_cc:1;
		uint32_t	lp_active_bgi:1;
		uint32_t	lp_active_fgi:1;
		uint32_t	lp_active_recon:1;
		uint32_t	lp_active_rsvd:28;
	};
	mfi_progress_t		lp_cc;
	mfi_progress_t		lp_bgi;
	mfi_progress_t		lp_fgi;
	mfi_progress_t		lp_recon;
	mfi_progress_t		lp_rsvd[4];
};
CTASSERT(sizeof (mfi_ld_progress_t) == 36);

/*
 * LD information
 */
struct mfi_ld_info {
	mfi_ld_config_t		li_config;
	uint64_t		li_size;
	mfi_ld_progress_t	li_progress;
	uint16_t		li_cluster_owner;
	uint8_t			li_recon_active;
	uint8_t			li_resvd1;
	uint8_t			li_vpd_page83[64];
	uint8_t			li_resvd2[16];
};
CTASSERT(sizeof (mfi_ld_info_t) == 384);

/*
 * LD target ID list
 */
struct mfi_ld_tgtid_list {
	uint32_t	ltl_size;
	uint32_t	ltl_count;
	uint8_t		ltl_rsvd[3];
	uint8_t		ltl_tgtid[0];
};

/*
 * RAID configuration
 */
struct mfi_config_data {
	uint32_t	cd_size;
	uint16_t	cd_array_cnt;
	uint16_t	cd_array_size;
	uint16_t	cd_ld_cnt;
	uint16_t	cd_ld_size;
	uint16_t	cd_spare_cnt;
	uint16_t	cd_spare_size;
	uint8_t		cd_rsvd[16];
	mfi_array_t	cd_array[0];
	mfi_ld_config_t	cd_ld[0];
	mfi_spare_t	cd_spare[0];
};

#pragma pack(0)
#ifdef __cplusplus
}
#endif

#endif	/* _MFI_LD_H */
