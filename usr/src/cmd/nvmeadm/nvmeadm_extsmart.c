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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Many vendors have followed the same layout for their Extended SMART data
 * which usually is a 1 byte id, 1 byte normalized value, and 6ish bytes of
 * data. This file contains the field data for printing those and the
 * corresponding logs.
 */

#include <sys/stddef.h>
#include <sys/sysmacros.h>
#include <sys/nvme/kioxia.h>
#include <sys/nvme/solidigm.h>
#include <sys/nvme/wdc.h>

#include "nvmeadm.h"

#define	EXTSMART_F(f)	\
	.nf_off = offsetof(solidigm_smart_ent_t, sse_##f), \
	.nf_len = sizeof (((solidigm_smart_ent_t *)NULL)->sse_##f)

static const nvmeadm_field_t extsmart_percent_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_PERCENT
}, {
	EXTSMART_F(raw),
	.nf_short = "raw",
	.nf_desc = "Raw",
	.nf_type = NVMEADM_FT_HEX
} };

/*
 * All fields are just printed in hex.
 */
static const nvmeadm_field_t extsmart_hex_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(raw),
	.nf_short = "raw",
	.nf_desc = "Raw",
	.nf_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_t extsmart_wl_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_PERCENT
}, {
	.nf_off = offsetof(solidigm_smart_ent_t, sse_raw[0]),
	.nf_len = 2,
	.nf_short = "min",
	.nf_desc = "Minimum Erase Cycles",
	.nf_type = NVMEADM_FT_HEX
}, {
	.nf_off = offsetof(solidigm_smart_ent_t, sse_raw[2]),
	.nf_len = 2,
	.nf_short = "max",
	.nf_desc = "Maximum Erase Cycles",
	.nf_type = NVMEADM_FT_HEX
}, {
	.nf_off = offsetof(solidigm_smart_ent_t, sse_raw[4]),
	.nf_len = 2,
	.nf_short = "avg",
	.nf_desc = "Average Erase Cycles",
	.nf_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_t extsmart_32mio_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(raw),
	.nf_short = "raw",
	.nf_desc = "Raw",
	.nf_type = NVMEADM_FT_BYTES,
	.nf_addend = { .nfa_shift = 25 }
} };

static const nvmeadm_field_t extsmart_rawpct_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(raw),
	.nf_short = "raw",
	.nf_desc = "Raw",
	.nf_type = NVMEADM_FT_PERCENT,
} };

static const nvmeadm_field_t extsmart_rawmin_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(raw),
	.nf_short = "raw",
	.nf_desc = "Raw",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "min" }
} };

static const nvmeadm_field_t extsmart_rawhour_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(raw),
	.nf_short = "raw",
	.nf_desc = "Raw",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "hours" }
} };

static const nvmeadm_field_t extsmart_therm_fields[] = { {
	EXTSMART_F(type),
	.nf_short = "id",
	.nf_desc = "Identifier",
	.nf_type = NVMEADM_FT_HEX
}, {
	EXTSMART_F(norm),
	.nf_short = "norm",
	.nf_desc = "Normalized",
	.nf_type = NVMEADM_FT_HEX
}, {
	.nf_off = offsetof(solidigm_smart_ent_t, sse_raw[0]),
	.nf_len = 1,
	.nf_short = "status",
	.nf_desc = "Throttle Status",
	.nf_type = NVMEADM_FT_PERCENT
}, {
	.nf_off = offsetof(solidigm_smart_ent_t, sse_raw[1]),
	.nf_len = 4,
	.nf_short = "count",
	.nf_desc = "Throttle Count",
	.nf_type = NVMEADM_FT_HEX
} };

#define	WDC_F_SMART(f)	\
	.nf_off = offsetof(wdc_vul_sn65x_smart_t, sm_##f), \
	.nf_len = sizeof (((wdc_vul_sn65x_smart_t *)NULL)->sm_##f)

static const nvmeadm_field_t wdc_vul_cusmart_fields[] = { {
	WDC_F_SMART(prog_fail),
	.nf_short = "pfc",
	.nf_desc = "Program Fail Count",
	NVMEADM_F_FIELDS(extsmart_percent_fields)
}, {
	WDC_F_SMART(erase_fail),
	.nf_short = "efc",
	.nf_desc = "Erase Fail Count",
	NVMEADM_F_FIELDS(extsmart_percent_fields)
}, {
	WDC_F_SMART(wear_level),
	.nf_short = "wl",
	.nf_desc = "Wear Leveling",
	NVMEADM_F_FIELDS(extsmart_wl_fields)
}, {
	WDC_F_SMART(e2e_edet),
	.nf_short = "e2e",
	.nf_desc = "End-to-End Error Detection Count",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	WDC_F_SMART(crc_err),
	.nf_short = "crc",
	.nf_desc = "CRC Error Count",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	WDC_F_SMART(timed_wear),
	.nf_short = "twmw",
	.nf_desc = "Timed Workload Media Wear",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	WDC_F_SMART(timed_read),
	.nf_short = "twhr",
	.nf_desc = "Timed Workload Host Reads",
	NVMEADM_F_FIELDS(extsmart_rawpct_fields)
}, {
	WDC_F_SMART(timed_timer),
	.nf_short = "twt",
	.nf_desc = "Timed Workload Timer",
	NVMEADM_F_FIELDS(extsmart_rawmin_fields)
}, {
	WDC_F_SMART(therm_throt),
	.nf_short = "tthrot",
	.nf_desc = "Thermal Throttle",
	NVMEADM_F_FIELDS(extsmart_therm_fields)
}, {
	WDC_F_SMART(retry_buf_over),
	.nf_short = "rboc",
	.nf_desc = "Retry Buffer Overflow Count",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	WDC_F_SMART(pll_lock_loss),
	.nf_short = "pllll",
	.nf_desc = "PLL Lock Loss Count",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	WDC_F_SMART(nand_write),
	.nf_short = "nbw",
	.nf_desc = "NAND Bytes Written",
	NVMEADM_F_FIELDS(extsmart_32mio_fields)
}, {
	WDC_F_SMART(host_write),
	.nf_short = "hbw",
	.nf_desc = "Host Bytes Written",
	NVMEADM_F_FIELDS(extsmart_32mio_fields)
} };

const nvmeadm_log_field_info_t wdc_vul_cusmart_field_info = {
	.nlfi_log = "wdc/cusmart",
	.nlfi_fields = wdc_vul_cusmart_fields,
	.nlfi_nfields = ARRAY_SIZE(wdc_vul_cusmart_fields),
	.nlfi_min = sizeof (wdc_vul_sn65x_smart_t)
};


#define	KIOXIA_F_SMART(f)	\
	.nf_off = offsetof(kioxia_vul_cd8_smart_t, cds_##f), \
	.nf_len = sizeof (((kioxia_vul_cd8_smart_t *)NULL)->cds_##f)

static const nvmeadm_field_t kioxia_vul_extsmart_fields[] = { {
	KIOXIA_F_SMART(prog_fail),
	.nf_short = "pfc",
	.nf_desc = "Program Fail Count",
	NVMEADM_F_FIELDS(extsmart_percent_fields)
}, {
	KIOXIA_F_SMART(erase_fail),
	.nf_short = "efc",
	.nf_desc = "Erase Fail Count",
	NVMEADM_F_FIELDS(extsmart_percent_fields)
}, {
	KIOXIA_F_SMART(wear_level),
	.nf_short = "wl",
	.nf_desc = "Wear Leveling",
	NVMEADM_F_FIELDS(extsmart_wl_fields)
}, {
	KIOXIA_F_SMART(e2e_det),
	.nf_short = "e2e",
	.nf_desc = "End-to-End Error Detection Count",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	KIOXIA_F_SMART(crc_error),
	.nf_short = "crc",
	.nf_desc = "CRC Error Count",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	KIOXIA_F_SMART(nand_write),
	.nf_short = "nbw",
	.nf_desc = "NAND Bytes Written",
	NVMEADM_F_FIELDS(extsmart_32mio_fields)
}, {
	KIOXIA_F_SMART(host_write),
	.nf_short = "hbw",
	.nf_desc = "Host Bytes Written",
	NVMEADM_F_FIELDS(extsmart_32mio_fields)
}, {
	/*
	 * The remaining fields (other than host bytes read) are duplicates from
	 * the normal NVMe Health log so we use the standard's name and short
	 * values.
	 */
	KIOXIA_F_SMART(crit_warn),
	.nf_short = "cw",
	.nf_desc = "Device Critical Warning",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	KIOXIA_F_SMART(host_read),
	.nf_short = "hbr",
	.nf_desc = "Host Bytes Read",
	NVMEADM_F_FIELDS(extsmart_32mio_fields)
}, {
	KIOXIA_F_SMART(comp_temp),
	.nf_short = "ctemp",
	.nf_desc = "Composite Temperature",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	KIOXIA_F_SMART(life_used),
	.nf_short = "pused",
	.nf_desc = "Percentage Used",
	NVMEADM_F_FIELDS(extsmart_percent_fields)
}, {
	KIOXIA_F_SMART(power_cycles),
	.nf_short = "pwrc",
	.nf_desc = "Power Cycles",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
}, {
	KIOXIA_F_SMART(power_hours),
	.nf_short = "poh",
	.nf_desc = "Power On Hours",
	NVMEADM_F_FIELDS(extsmart_rawhour_fields)
}, {
	KIOXIA_F_SMART(unsafe_shut),
	.nf_short = "upl",
	.nf_desc = "Unexpected Power Losses",
	NVMEADM_F_FIELDS(extsmart_hex_fields)
} };

const nvmeadm_log_field_info_t kioxia_vul_extsmart_field_info = {
	.nlfi_log = "kioxia/extsmart",
	.nlfi_fields = kioxia_vul_extsmart_fields,
	.nlfi_nfields = ARRAY_SIZE(kioxia_vul_extsmart_fields),
	.nlfi_min = sizeof (kioxia_vul_cd8_smart_t)
};
