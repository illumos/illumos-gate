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

/*
 * MFI battery backup unit (BBU) definitions
 */

#ifndef	_MFI_BBU_H
#define	_MFI_BBU_H

#include <sys/types.h>
#include <sys/debug.h>

#include <sys/scsi/adapters/mfi/mfi.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)

struct mfi_bbu_capacity {
	uint16_t	bbu_rel_charge;
	uint16_t	bbu_abs_charge;
	uint16_t	bbu_rem_cap;
	uint16_t	bbu_full_charge_cap;
	uint16_t	bbu_run_time_to_empty;
	uint16_t	bbu_avg_time_to_empty;
	uint16_t	bbu_avg_time_to_full;
	uint16_t	bbu_cycle_count;
	uint16_t	bbu_max_error;
	uint16_t	bbu_rem_cap_alarm;
	uint16_t	bbu_rem_time_alarm;
	uint8_t		bbu_rsvd[26];
};
CTASSERT(sizeof (mfi_bbu_capacity_t) == 48);

struct mfi_bbu_design_info {
	uint32_t	bbu_mfg_date;
	uint16_t	bbu_design_cap;
	uint16_t	bbu_design_voltage;
	uint16_t	bbu_spec_info;
	uint16_t	bbu_serial_number;
	uint16_t	bbu_pack_stat_config;
	uint8_t		bbu_mfg_name[12];
	uint8_t		bbu_dev_name[8];
	uint8_t		bbu_dev_chemistry[8];
	uint8_t		bbu_mfg_data[8];
	uint8_t		bbu_rsvd[17];
};
CTASSERT(sizeof (mfi_bbu_design_info_t) == 67);

struct mfi_ibbu_state {
	uint16_t	ibbu_gas_gauge;
	uint16_t	ibbu_rel_charge;
	uint16_t	ibbu_charger_system_state;
	uint16_t	ibbu_charger_system_ctrl;
	uint16_t	ibbu_charging_current;
	uint16_t	ibbu_absolute_charge;
	uint16_t	ibbu_max_error;
	uint8_t		ibbu_rsvd[18];
};
CTASSERT(sizeof (mfi_ibbu_state_t) == 32);

struct mfi_bbu_state {
	uint16_t	bbu_gas_gauge;
	uint16_t	bbu_rel_charge;
	uint16_t	bbu_charge_state;
	uint16_t	bbu_rem_cap;
	uint16_t	bbu_full_cap;
	uint8_t		bbu_healthy;
	uint8_t		bbu_rsvd[21];
};
CTASSERT(sizeof (mfi_bbu_state_t) == 32);

struct mfi_bbu_status {
	uint8_t		bbu_type;
	uint8_t		bbu_rsvd;
	uint16_t	bbu_voltage;
	int16_t		bbu_current;
	uint16_t	bbu_temp;
	struct {
		uint32_t	bbu_state_pack_missing:1;
		uint32_t	bbu_state_voltage_low:1;
		uint32_t	bbu_state_temperature_high:1;
		uint32_t	bbu_state_charging:1;
		uint32_t	bbu_state_discharging:1;
		uint32_t	bbu_state_learn_cyc_req:1;
		uint32_t	bbu_state_learn_cyc_active:1;
		uint32_t	bbu_state_learn_cyc_fail:1;
		uint32_t	bbu_state_learn_cyc_timeout:1;
		uint32_t	bbu_state_i2c_err_detect:1;
		uint32_t	bbu_state_rsvd:22;
	};
	uint8_t		bbu_pad[20];
	union {
		mfi_bbu_state_t		bbu_state;
		mfi_ibbu_state_t	ibbu_state;
	};
};
CTASSERT(sizeof (mfi_bbu_status_t) == 64);

struct mfi_bbu_properties {
	uint32_t	bbu_auto_learn_period;
	uint32_t	bbu_next_learn_time;
	uint8_t		bbu_learn_delay_interval;
	uint8_t		bbu_auto_learn_mode;
	uint8_t		bbu_mode;
	uint8_t		bbu_rsvd[21];
};
CTASSERT(sizeof (mfi_bbu_properties_t) == 32);

#pragma pack(0)

#ifdef __cplusplus
}
#endif

#endif	/* _MFI_BBU_H */
