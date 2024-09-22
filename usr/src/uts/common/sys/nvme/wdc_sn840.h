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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_NVME_WDC_SN840_H
#define	_SYS_NVME_WDC_SN840_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * Vendor-specific definitions for the WDC SN840 NVMe device.
 */

#include <sys/debug.h>
#include <sys/stdint.h>
#include <sys/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	WDC_SN840_DID	0x2500

typedef enum {
	/*
	 * This log is the fixed wdc_vul_sn840_eol_t structure.
	 */
	WDC_SN840_LOG_EOL		= 0xc0,
	/*
	 * This log uses the wdc_log_vsd_t with a series of different entry
	 * types.
	 */
	WDC_SN840_LOG_DEV_MANAGE	= 0xc2,
	/*
	 * While this log exists, we do not know the data format of it.
	 */
	WDC_SN840_LOG_PCIE_SI		= 0xc4,
	/*
	 * This uses the common wdc_vul_power_t structure.
	 */
	WDC_SN840_LOG_POWER		= 0xc5,
	/*
	 * This uses the common wdc_vul_temp_t structure. The specific
	 * measurements are recorded in the wdc_log_sn840_temp_t.
	 */
	WDC_SN840_LOG_TEMP		= 0xc6,
	/*
	 * The firmware activation log uses the wdc_sn840_fw_act_hdr_t stucture
	 * as a header and then is followed by one or more
	 * wdc_vul_sn840_fw_act_ent_t structures that have entry information.
	 */
	WDC_SN840_LOG_FW_ACT		= 0xcb,
	/*
	 * This log uses the wdc_vul_sn840_ccds_info_t structure.
	 */
	WDC_SN840_LOG_CCDS		= 0xfa
} wdc_sn840_vul_t;

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * Device EOL Log Page
 */
typedef struct {
	uint8_t		eol_rsvd0[76];
	uint32_t	eol_rbc;
	uint8_t		eol_rsvd1[4];
	uint32_t	eol_waf;
	uint32_t	eol_plr;
	uint8_t		eol_rsvd2[4];
	uint32_t	eol_pfc;
	uint32_t	eol_efc;
	uint8_t		eol_rss3[4];
	uint32_t	eol_vendor;
	uint16_t	eol_cust_sts;
	uint16_t	eol_sys_sts;
	uint8_t		eol_cust_state;
	uint8_t		eol_sys_state;
} wdc_vul_sn840_eol_t;

/*
 * Smatch can't handle packed structure sizeof calculations correctly,
 * unfortunately.
 */
#ifndef __CHECKER__
CTASSERT(sizeof (wdc_vul_sn840_eol_t) == 118);
#endif

typedef enum {
	WDC_SN840_VSD_ID		= 0x01,		/* uint32_t */
	WDC_SN840_VSD_UEFI_VER		= 0x02,		/* CBS */
	WDC_SN840_VSD_SBL_VER		= 0x03,		/* CBS */
	WDC_SN840_VSD_DEF_USER_CAP	= 0x04,		/* uint64_t */
	WDC_SN840_VSD_MAX_USER_CAP	= 0x05,		/* uint64_t */
	WDC_SN840_VSD_MIN_USER_CAP	= 0x06,		/* uint64_t */
	WDC_SN840_VSD_NAME		= 0x07,		/* CBS */
	WDC_SN840_VSD_LOG_SUP		= 0x08,		/* CBS */
	WDC_SN840_VSD_FEAT_SUP		= 0x09,		/* CBS */
	WDC_SN840_VSD_FORM_FACTOR	= 0x0a,		/* uint32_t */
	WDC_SN840_VSD_RESIZE_GRAN	= 0x0b,		/* uint64_t */
	WDC_SN840_VSD_NS_ALLOC_SIZE	= 0x0c,		/* uint64_t */
	WDC_SN840_VSD_NS_REG_AVAIL	= 0x0d,		/* uint64_t */
	WDC_SN840_VSD_RAW_NVM		= 0x0e,		/* uint64_t */
	WDC_SN840_VSD_PORT_CFG_STS	= 0x0f,		/* uint32_t */
	WDC_SN840_VSD_MPN		= 0x10,		/* CBS */
	WDC_SN840_VSD_SN		= 0x11,		/* CBS */
	WDC_SN840_VSD_DEF_NS_ATTRS	= 0x12,		/* uint32_t */
	WDC_SN840_VSD_GIT_DESCR		= 0x13,		/* CBS */
	WDC_SN840_VSD_SMB_BL		= 0x14,		/* CBS */
	WDC_SN840_VSD_CUST_ID		= 0x15,		/* uint32_t */
	WDC_SN840_VSD_PROD_DESC		= 0x16,		/* CBS */
	WDC_SN840_VSD_TMM_VER		= 0x17,		/* CBS */
	WDC_SN840_VSD_THERM_THROT_STS	= 0x18,		/* uint32_t */
	WDC_SN840_VSD_ASSERT_DUMP	= 0x19,		/* uint32_t */
	WDC_SN840_VSD_CUST_EOL_STS	= 0x1a,		/* uint32_t */
	WDC_SN840_VSD_IFS_EOL_STS	= 0x1b,		/* uint32_t */
	WDC_SN840_VSD_CUST_EOL_STATE	= 0x1c,		/* uint32_t */
	WDC_SN840_VSD_IFS_EOL_STATE	= 0x1d,		/* uint32_t */
	WDC_SN840_VSD_FCR		= 0x1e,		/* uint32_t */
	WDC_SN840_VSD_VCA_BPC_REV	= 0x1f,		/* uint32_t */
	WDC_SN840_VSD_VCA_BPC_MIN_REV	= 0x20,		/* uint32_t */
	WDC_SN840_VSD_VCA_BPC_RST_SEQ	= 0x21,		/* uint32_t */
	WDC_SN840_VSD_VCA_TPC_RST_SEQ	= 0x22,		/* uint32_t */
	WDC_SN840_VSD_VCA_TPC_FSS_SEQ	= 0x23		/* uint32_t */
} wdc_sn840_vsd_id_t;

typedef enum {
	WDC_SN840_VSD_NS_LIDS		= 0x08,		/* CBS */
	WDC_SN840_VSD_NS_FIDS		= 0x09		/* CBS */
} wdc_sn840_vsd_ns_id_t;

typedef enum {
	WDC_SN840_TEMP_NAND	= 0,
	WDC_SN840_TEMP_BOARD,
	WDC_SN840_TEMP_FE,
	WDC_SN840_TEMP_FM0,
	WDC_SN840_TEMP_FM1,
	WDC_SN840_TEMP_AVG_NAND,
	WDC_SN840_TEMP_AVG_FE,
	WDC_SN840_TEMP_MAX_ASIC,
	WDC_SN840_TEMP_TOUCH,
	WDC_SN840_TEMP_COMP,
	WDC_SN840_TEMP_NSMAPLES
} wdc_sn840_temp_sample_t;

/*
 * These are structures for the firmware activation log. The first structure is
 * an individual entry. The second is the header which points to these. The data
 * is versioned and the entries have a specific size, but right now we only know
 * of the one.
 */
typedef struct {
	uint32_t	fah_ent_no;
	uint32_t	fah_pow_cyc;
	uint64_t	fah_pow_sec;
	uint64_t	fah_cur_fw_ver;
	uint64_t	fah_new_fw_ver;
	uint8_t		fah_slot_no;
	uint8_t		fah_commit_type;
	uint16_t	fah_result;
	uint8_t		fah_rsvd[12];
} wdc_vul_sn840_fw_act_ent_t;

CTASSERT(sizeof (wdc_vul_sn840_fw_act_ent_t) == 48);

typedef struct {
	uint8_t		fah_hdr[4];
	uint8_t		fah_vers;
	uint8_t		fah_rsvd0;
	uint8_t		fah_nent;
	uint8_t		fah_rsvd1;
	uint32_t	fah_entlen;
	uint32_t	fah_rsvd;
} wdc_vul_sn840_fw_act_hdr_t;

CTASSERT(sizeof (wdc_vul_sn840_fw_act_hdr_t) == 16);

typedef struct {
	uint8_t		cbi_hdr[8];
	uint32_t	cbi_cust_id;
	uint16_t	cbi_vers_id;
	uint16_t	cbi_rev_id;
	uint32_t	cbi_build_id;
	uint8_t		cbi_nand_head[8];
	uint32_t	cbi_cust_nand_id;
	uint16_t	cbi_nand_vers_id;
	uint16_t	cbi_nand_rev_id;
} wdc_vul_sn840_ccds_info_t;

CTASSERT(sizeof (wdc_vul_sn840_ccds_info_t) == 36);

#pragma	pack()	/* pack(1) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_WDC_SN840_H */
