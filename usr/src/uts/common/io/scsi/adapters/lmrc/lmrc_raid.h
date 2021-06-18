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

#ifndef _LMRC_RAID_H
#define	_LMRC_RAID_H

#include <sys/types.h>
#include <sys/debug.h>

#include <sys/scsi/adapters/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpi/mpi2.h>
#include <sys/scsi/adapters/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpi/mpi2_ioc.h>

typedef struct lmrc_raidctx_g35		lmrc_raidctx_g35_t;
typedef struct lmrc_devhdl_info		lmrc_devhdl_info_t;
typedef struct lmrc_array_info		lmrc_array_info_t;
typedef struct lmrc_quad_element	lmrc_quad_element_t;
typedef struct lmrc_span_info		lmrc_span_info_t;
typedef struct lmrc_ld_span		lmrc_ld_span_t;
typedef struct lmrc_span_block_info	lmrc_span_block_info_t;
typedef struct lmrc_ld_raid		lmrc_ld_raid_t;
typedef struct lmrc_ld_span_map		lmrc_ld_span_map_t;

typedef struct lmrc_fw_raid_map		lmrc_fw_raid_map_t;
typedef struct lmrc_raid_map_desc	lmrc_raid_map_desc_t;

typedef struct lmrc_ld_tgt		lmrc_ld_tgt_t;
typedef struct lmrc_ld_ref		lmrc_ld_ref_t;
typedef	struct lmrc_ld_cfg		lmrc_ld_cfg_t;
typedef struct lmrc_ld_list		lmrc_ld_list_t;
typedef struct lmrc_ld_tgtid_list	lmrc_ld_tgtid_list_t;

#include "lmrc.h"

#pragma pack(1)

struct lmrc_raidctx_g35 {
	uint8_t		rc_type:4;
	uint8_t		rc_nseg:4;
	uint8_t		rc_rsvd0;
	uint16_t	rc_timeout;

	struct {
		uint16_t	rf_rsvd:1;
		uint16_t	rf_sld:1;
		uint16_t	rf_c2f:1;
		uint16_t	rf_fwn:1;
		uint16_t	rf_sqn:1;
		uint16_t	rf_sbs:1;
		uint16_t	rf_rw:1;
		uint16_t	rf_log:1;
		uint16_t	rf_cpu_sel:4;
		uint16_t	rf_set_divert:4;
	} rc_routing_flags;

	uint16_t	rc_ld_tgtid;
	uint64_t	rc_reg_lock_rowlba;
	uint32_t	rc_reg_lock_len;

	union {
		uint16_t	rc_next_lmid;
		uint16_t	rc_peer_smid;
	} rc_smid;

	uint8_t		rc_exstatus;
	uint8_t		rc_status;

	struct {
		uint8_t	rf_pref_cpu:1;
		uint8_t	rf_rsvd1:3;
		uint8_t	rf_io_subtype:3;
		uint8_t	rf_rsvd2:1;
	} rc_raid_flags;

	uint8_t		rc_span_arm;
	uint16_t	rc_cfg_seqnum;
	struct {
		uint16_t	rc_num_sge:12;
		uint16_t	rc_rsvd1:3;
		uint16_t	rc_stream_detected:1;
	};
	uint8_t		rc_rsvd2[2];
};
CTASSERT(sizeof (lmrc_raidctx_g35_t) == 0x20);

/*
 * rc_raid_flags values
 */
#define	LMRC_RF_IO_SUBTYPE_NONE			0
#define	LMRC_RF_IO_SUBTYPE_SYSTEM_PD		1
#define	LMRC_RF_IO_SUBTYPE_RMW_DATA		2
#define	LMRC_RF_IO_SUBTYPE_RMW_P		3
#define	LMRC_RF_IO_SUBTYPE_RMW_Q		4
#define	LMRC_RF_IO_SUBTYPE_CACHE_BYPASS		6
#define	LMRC_RF_IO_SUBTYPE_LDIO_BW_LIMIT	7

/*
 * RAID map related structures
 */
#define	LMRC_MIN_MAP_SIZE			0x10000

#define	LMRC_MAX_SPAN_DEPTH		8
#define	LMRC_MAX_QUAD_DEPTH		LMRC_SPAN_DEPTH
#define	LMRC_MAX_ROW_SIZE		32
#define	LMRC_MAX_LOGICAL_DRIVES		64
#define	LMRC_MAX_LOGICAL_DRIVES_EXT	256
#define	LMRC_MAX_LOGICAL_DRIVES_DYN	512
#define	LMRC_MAX_ARRAYS			128
#define	LMRC_MAX_ARRAYS_EXT		256
#define	LMRC_MAX_API_ARRAYS_EXT		(LMRC_MAX_ARRAYS_EXT)
#define	LMRC_MAX_API_ARRAYS_DYN		512
#define	LMRC_MAX_PHYS_DEV		256

#define	LMRC_RAIDMAP_MAX_SPAN_DEPTH	(LMRC_MAX_SPAN_DEPTH)
#define	LMRC_RAIDMAP_MAX_ROW_SIZE	(LMRC_MAX_ROW_SIZE)
#define	LMRC_RAIDMAP_ARRAYS		(LMRC_MAX_ARRAYS)
#define	LMRC_RAIDMAP_MAX_PHYS_DEV_DYN	512

#define	LMRC_DEVHDL_IFTYPE_UNKNOWN		0
#define	LMRC_DEVHDL_IFTYPE_PARALLEL_SCSI	1
#define	LMRC_DEVHDL_IFTYPE_SAS_PD		2
#define	LMRC_DEVHDL_IFTYPE_SATA_PD		3
#define	LMRC_DEVHDL_IFTYPE_FC_PD		4
#define	LMRC_DEVHDL_IFTYPE_NVME_PD		5

#define	LMRC_DEVHDL_INVALID			0xFFFF

struct lmrc_devhdl_info {
	uint16_t	di_cur_devhdl;
	uint8_t		di_valid_handles;
	uint8_t		di_iftype;
	uint16_t	di_devhdl[2];
};

struct lmrc_array_info {
	uint16_t	ai_pd[LMRC_RAIDMAP_MAX_ROW_SIZE];
};

struct lmrc_quad_element {
	uint64_t	qe_logstart;
	uint64_t	qe_logend;
	uint64_t	qe_offset_in_span;
	uint32_t	qe_diff;
	uint32_t	qe_reserved;
};

struct lmrc_span_info {
	uint32_t		si_nelem;
	uint32_t		si_reserved;
	lmrc_quad_element_t	si_quad[LMRC_RAIDMAP_MAX_SPAN_DEPTH];
};

struct lmrc_ld_span {
	uint64_t	ls_start_blk;
	uint64_t	ls_nblk;
	uint16_t	ls_arrayref;
	uint8_t		ls_span_rowsz;
	uint8_t		ls_span_row_datasz;
	uint8_t		ls_reserved[4];
};

struct lmrc_span_block_info {
	uint64_t	sbi_num_rows;
	lmrc_ld_span_t	sbi_span;
	lmrc_span_info_t	sbi_block_span_info;
};

struct lmrc_ld_raid {
	struct {
		uint32_t lc_fp_cap:1;
		uint32_t lc_ra_cap:1;
		uint32_t lc_reserved5:2;
		uint32_t lc_ld_pi_mode:4;
		uint32_t lc_pd_pi_mode:4;
		uint32_t lc_encryption_type:8;
		uint32_t lc_fp_write_cap:1;
		uint32_t lc_fp_read_cap:1;
		uint32_t lc_fp_write_across_stripe:1;
		uint32_t lc_fp_read_across_stripe:1;
		uint32_t lc_fp_non_rw_cap:1;
		uint32_t lc_tm_cap:1;
		uint32_t lc_fp_cache_bypass_cap:1;
		uint32_t lc_reserved4:5;
	} lr_cap;

	uint32_t lr_reserved6;
	uint64_t lr_size;

	uint8_t lr_span_depth;
	uint8_t lr_level;
	uint8_t lr_stripe_shift;
	uint8_t lr_row_size;

	uint8_t lr_row_data_size;
	uint8_t lr_write_mode;
	uint8_t lr_prl;
	uint8_t lr_srl;

	uint16_t lr_target_id;
	uint8_t lr_ld_state;
	uint8_t lr_reg_type_req_on_write;
	uint8_t lr_mod_factor;
	uint8_t lr_reg_type_req_on_read;
	uint16_t lr_seq_num;

	struct {
		uint32_t lf_reserved:30;
		uint32_t lf_reg_type_req_on_read_ls_valid:1;
		uint32_t lf_ld_sync_required:1;
	} lr_flags;

	uint8_t lr_lun[8];
	uint8_t lr_fp_io_timeout_for_ld;
	uint8_t lr_reserved2[3];
	uint32_t lr_logical_block_length;

	struct {
		uint32_t le_reserved1:24;
		uint32_t le_ld_logical_block_exp:4;
		uint32_t le_ld_pi_exp:4;
	} lr_exponent;
	uint8_t lr_reserved3[0x80 - 0x38];
};

struct lmrc_ld_span_map {
	lmrc_ld_raid_t sm_ld_raid;
	uint8_t sm_data_arm_map[LMRC_RAIDMAP_MAX_ROW_SIZE];
	lmrc_span_block_info_t sm_span_block[LMRC_RAIDMAP_MAX_SPAN_DEPTH];
};

/*
 * RAID map descriptor
 */
struct lmrc_raid_map_desc {
	uint32_t	rmd_type;	/* descriptor type */
	uint32_t	rmd_off;	/* offset in RAID map buffer */
	uint32_t	rmd_bufsz;	/* size of buffer */
	uint32_t	rmd_desc_nelem;	/* number of elements in buffer */
};

#define	LMRC_RAID_MAP_DESC_TYPE_DEVHDL	0
#define	LMRC_RAID_MAP_DESC_TYPE_LD_ID	1
#define	LMRC_RAID_MAP_DESC_TYPE_ARRAY	2
#define	LMRC_RAID_MAP_DESC_TYPE_SPAN	3
#define	LMRC_RAID_MAP_DESC_TYPES_COUNT	(LMRC_RAID_MAP_DESC_TYPE_SPAN + 1)

/*
 * Dynamic RAID Map
 */
struct lmrc_fw_raid_map {
	uint32_t	rm_raidmap_sz;
	uint32_t	rm_desc_table_off;
	uint32_t	rm_desc_table_sz;
	uint32_t	rm_desc_table_nelem;
	uint64_t	rm_pci_thres_bandw;
	uint32_t	rm_rsvd[3];

	uint8_t		rm_fp_pd_io_timeout;
	uint8_t		rm_rsvd2[3];
	uint32_t	rm_rmw_fp_seqnum;
	uint16_t	rm_ld_count;
	uint16_t	rm_ar_count;
	uint16_t	rm_span_count;
	uint16_t	rm_rsvd3[3];

	/*
	 * FreeBSD uses this for driver purposes and claims FW doesn't
	 * modify this.
	 */
	union {
		struct {
			lmrc_devhdl_info_t	*rm_devhdl;
			uint16_t		*rm_ld_id;
			lmrc_array_info_t	*rm_array;
			lmrc_ld_span_map_t	*rm_span;
		};
		void		*rm_desc_ptrs[LMRC_RAID_MAP_DESC_TYPES_COUNT];
	};

	/* Variable size descriptor table. */
	lmrc_raid_map_desc_t	rm_desc_table[LMRC_RAID_MAP_DESC_TYPES_COUNT];

	/* Variable size buffer containing all data */
	uint32_t	rm_desc_data[0];
};

/*
 * LD target list
 */
struct lmrc_ld_tgt {
	uint8_t		lt_tgtid;
	uint8_t		lt_rsvd;
	uint16_t	lt_seqnum;
};

struct lmrc_ld_tgtid_list {
	uint32_t	ltl_size;
	uint32_t	ltl_count;
	uint8_t		ltl_rsvd[3];
	uint8_t		ltl_tgtid[0];
};

#pragma pack(0)

/* RAID map accessor functions */
static inline lmrc_ld_raid_t *
lmrc_ld_raid_get(uint16_t ld_id, lmrc_fw_raid_map_t *rm)
{
	if (ld_id >= rm->rm_ld_count)
		return (NULL);

	return (&rm->rm_span[ld_id].sm_ld_raid);
}

static inline uint16_t
lmrc_ld_id_get(uint16_t tgtid, lmrc_fw_raid_map_t *rm)
{
	ASSERT3U(tgtid, <,
	    rm->rm_desc_table[LMRC_RAID_MAP_DESC_TYPE_LD_ID].rmd_desc_nelem);

	uint32_t nelem =
	    rm->rm_desc_table[LMRC_RAID_MAP_DESC_TYPE_LD_ID].rmd_desc_nelem;

	if (tgtid >= nelem)
		return (LMRC_DEVHDL_INVALID);

	return (rm->rm_ld_id[tgtid]);
}

static inline uint16_t
lmrc_tgtid_get(uint16_t ld_id, lmrc_fw_raid_map_t *rm)
{
	lmrc_ld_raid_t *raid;

	if (ld_id >= rm->rm_ld_count)
		return (LMRC_DEVHDL_INVALID);

	raid = lmrc_ld_raid_get(ld_id, rm);
	if (raid == NULL)
		return (LMRC_DEVHDL_INVALID);

	return (raid->lr_target_id);
}

/* other helper functions */
static inline boolean_t
lmrc_cmd_is_rw(uint8_t cdb0)
{
	switch (cdb0) {
	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

typedef lmrc_raidctx_g35_t			MPI25_SCSI_IO_VENDOR_UNIQUE;
#define	MPI25_SCSI_IO_VENDOR_UNIQUE_REGION
#include <sys/scsi/adapters/mpi/mpi2_init.h>

int lmrc_setup_raidmap(lmrc_t *);
void lmrc_free_raidmap(lmrc_t *);

boolean_t lmrc_ld_tm_capable(lmrc_t *, uint16_t);

int lmrc_get_ld_list(lmrc_t *);

int lmrc_raid_attach(dev_info_t *);
int lmrc_raid_detach(dev_info_t *);

int lmrc_raid_aen_handler(lmrc_t *, lmrc_evt_t *);

#endif /* _LMRC_RAID_H */
