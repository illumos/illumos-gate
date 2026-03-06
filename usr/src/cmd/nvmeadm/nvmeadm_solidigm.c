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
 * Deal with Solidigm-specific logs.
 */

#include <sys/stddef.h>
#include <sys/sysmacros.h>
#include <sys/nvme/solidigm.h>

#include "nvmeadm.h"

#define	SOLIDIGM_F_POWER(f)	\
	.nf_off = offsetof(solidigm_vul_p5x2x_power_t, pow_##f), \
	.nf_len = sizeof (((solidigm_vul_p5x2x_power_t *)NULL)->pow_##f)

static const nvmeadm_field_t solidigm_vul_power_fields[] = { {
	SOLIDIGM_F_POWER(vin1),
	.nf_short = "pin1",
	.nf_desc = "Voltage Rail 1 Power",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "uW" }
}, {
	SOLIDIGM_F_POWER(vin2),
	.nf_short = "pin2",
	.nf_desc = "Voltage Rail 2 Power",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "uW" }
} };

const nvmeadm_log_field_info_t solidigm_vul_power_field_info = {
	.nlfi_log = "solidigm/power",
	.nlfi_fields = solidigm_vul_power_fields,
	.nlfi_nfields = ARRAY_SIZE(solidigm_vul_power_fields),
	.nlfi_min = sizeof (solidigm_vul_p5x2x_power_t)
};

#define	SOLIDIGM_F_TEMP(f)	\
	.nf_off = offsetof(solidigm_vul_temp_t, temp_##f), \
	.nf_len = sizeof (((solidigm_vul_temp_t *)NULL)->temp_##f)

static const nvmeadm_field_t solidigm_vul_temp_fields[] = { {
	SOLIDIGM_F_TEMP(cur),
	.nf_short = "cur",
	.nf_desc = "Current Internal Temperature",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "C" }
}, {
	SOLIDIGM_F_TEMP(over_last),
	.nf_short = "otlpow",
	.nf_desc = "SSD Overtemp Shutdown flag for Last Power On",
	.nf_type = NVMEADM_FT_HEX
}, {
	SOLIDIGM_F_TEMP(over_life),
	.nf_short = "otlife",
	.nf_desc = "SSD Overtemp Shutdown flag for Lifetime",
	.nf_type = NVMEADM_FT_HEX
}, {
	SOLIDIGM_F_TEMP(comp_life_high),
	.nf_short = "lifehigh",
	.nf_desc = "Highest (Lifetime) Composite Temperature",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "C" }
}, {
	SOLIDIGM_F_TEMP(comp_life_low),
	.nf_short = "lifelow",
	.nf_desc = "Lowest (Lifetime) Composite Temperature",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "C" }
}, {
	SOLIDIGM_F_TEMP(norm_max_warn),
	.nf_short = "maxnorm",
	.nf_desc = "Max Warning Normalized Threshold",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "C" }
}, {
	SOLIDIGM_F_TEMP(spec_min_op),
	.nf_short = "minorm",
	.nf_desc = "Specified Minimum Operating Temp",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "C" }
}, {
	SOLIDIGM_F_TEMP(est_off),
	.nf_short = "estoff",
	.nf_desc = "Estimated Offset",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "C" }
} };

const nvmeadm_log_field_info_t solidigm_vul_temp_field_info = {
	.nlfi_log = "solidigm/temp",
	.nlfi_fields = solidigm_vul_temp_fields,
	.nlfi_nfields = ARRAY_SIZE(solidigm_vul_temp_fields),
	.nlfi_min = sizeof (solidigm_vul_temp_t)
};
