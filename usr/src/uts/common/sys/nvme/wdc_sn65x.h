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

#ifndef _SYS_NVME_WDC_SN65X_H
#define	_SYS_NVME_WDC_SN65X_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * Vendor-specific definitions for the WDC SN650 and SN655 NVMe devices.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	WDC_SN650_DID	0x2720
#define	WDC_SN655_DID	0x2722

typedef enum {
	WDC_SN65X_LOG_OCP_SMART		= 0xc0,
	/*
	 * This uses the common wdc_vul_power_t structure.
	 */
	WDC_SN65X_LOG_POWER		= 0xc5,
	/*
	 * This uses the common wdc_vul_temp_t structure. The specific
	 * measurements are recorded in the wdc_log_sn65x_temp_t.
	 */
	WDC_SN65X_LOG_TEMP		= 0xc6,
	WDC_SN65X_LOG_UNIQUE_SMART	= 0xca
} wdc_sn65x_vul_t;

typedef enum {
	WDC_SN65X_TEMP_BOARD1	= 0,
	WDC_SN65X_TEMP_BOARD2,
	WDC_SN65X_TEMP_BOARD3,
	WDC_SN65X_TEMP_INLET_LED,
	WDC_SN65X_TEMP_OUTLET_HOST,
	WDC_SN65X_TEMP_NAND,
	WDC_SN65X_TEMP_FE,
	WDC_SN65X_TEMP_FM0,
	WDC_SN65X_TEMP_FM1,
	WDC_SN65X_TEMP_THERMR,
	WDC_SN65X_TEMP_AVG_THERMR,
	WDC_SN65X_TEMP_AVG_NAND,
	WDC_SN65X_TEMP_AVG_FE,
	WDC_SN65X_TEMP_NSAMPLES
} wdc_sn65x_temp_sample_t;

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * This structure represents an individual entry in the WDC Customer Unique
 * SMART log page.
 */
typedef struct {
	uint8_t vulp_id;
	uint8_t vulp_rsvd0[2];
	uint8_t vulp_norm;
	uint8_t vulp_rsvd1[1];
	uint8_t vulp_data[4];
	uint8_t vulp_pad[3];
} wdc_vul_sn65x_smart_ent_t;

/*
 * This structure represents the layout of the 0xca log page. Each entry has an
 * id that corresponds to it and should be validated when reading this.
 */
typedef struct {
	wdc_vul_sn65x_smart_ent_t sm_prog_fail;
	wdc_vul_sn65x_smart_ent_t sm_erase_fail;
	wdc_vul_sn65x_smart_ent_t sm_wear_level;
	wdc_vul_sn65x_smart_ent_t sm_etoe_edet;
	wdc_vul_sn65x_smart_ent_t sm_crc_err;
	wdc_vul_sn65x_smart_ent_t sm_timed_wear;
	wdc_vul_sn65x_smart_ent_t sm_timed_read;
	wdc_vul_sn65x_smart_ent_t sm_timed_timer;
	wdc_vul_sn65x_smart_ent_t sm_therm_throt;
	wdc_vul_sn65x_smart_ent_t sm_retry_buf_over;
	wdc_vul_sn65x_smart_ent_t sm_pll_lock_loss;
	wdc_vul_sn65x_smart_ent_t sm_nand_write;
	wdc_vul_sn65x_smart_ent_t sm_host_write;
} wdc_vul_sn65x_smart_t;

typedef enum {
	WDC_SN65X_SMART_ENT_ID_PROG_FAIL	= 0,
	WDC_SN65X_SMART_END_ID_ERASE_FAIL,
	WDC_SN65X_SMART_ENT_ID_WEAR_LEVEL,
	WDC_SN65X_SMART_ENT_ID_ETOE_ERROR_DET,
	WDC_SN65X_SMART_ENT_ID_CRC_ERROR,
	WDC_SN65X_SMART_ENT_ID_TIMED_MEDIA_WEAR,
	WDC_SN65X_SMART_ENT_ID_TIMED_READS,
	WDC_SN65X_SMART_ENT_ID_TIMED_TIMER,
	WDC_SN65X_SMART_ENT_ID_THERMAL_THROTLE,
	WDC_SN65X_SMART_ENT_ID_RETRY_BUF_OVERFLOW,
	WDC_SN65X_SMART_ENT_ID_PLL_LOCK_LOSS,
	WDC_SN65X_SMART_ENT_ID_NAND_WRITTEN,
	WDC_SN65X_SMART_ENT_ID_HOST_WRITTEN
} wdc_sn65x_smart_ent_id_t;

#pragma	pack()	/* pack(1) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_WDC_SN65X_H */
