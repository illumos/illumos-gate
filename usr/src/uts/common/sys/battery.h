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

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BATTERY_H
#define	_BATTERY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/param.h>

#define	_BATT_DRV		(('B' << 24) + ('A' << 16) + ('T' << 8))

#define	BATT_IOC_BAY		(_BATT_DRV | 0)
#define	BATT_IOC_INFO		(_BATT_DRV | 1)
#define	BATT_IOC_STATUS		(_BATT_DRV | 2)
#define	BATT_IOC_AC_COUNT	(_BATT_DRV | 3)
#define	BATT_IOC_POWER_STATUS	(_BATT_DRV | 4)
#define	BATT_IOC_SET_WARNING	(_BATT_DRV | 5)
#define	BATT_IOC_GET_WARNING	(_BATT_DRV | 6)

#define	BATT_BST_CHARGING	2
#define	BATT_BST_DISCHARGING	1

typedef struct batt_bay {
	/* Total number of bays in the system */
	int bay_number;

	/*
	 * Bitmap for each bay and its battery.
	 * battery_map bit i:
	 *    1 -- battery inserted to bay i
	 *    0 -- bay i empty
	 */
	uint64_t battery_map;
} batt_bay_t;

typedef	struct acpi_bif {
	uint32_t	bif_unit;

	/*
	 * 0x00000000 - 0x7fffffff
	 * 0xffffffff - Unknown design capacity in [mWh] or [mAh]
	 */
	uint32_t	bif_design_cap;

	/*
	 * 0x00000000 - 0x7fffffff
	 * 0xffffffff - Unknown last full charge capacity in [mWh] or [mAh]
	 */
	uint32_t	bif_last_cap;

	uint32_t	bif_tech;

	/*
	 * 0x00000000 - 0x7fffffff
	 * 0xffffffff - Unknown design voltage in [mV]
	 */
	uint32_t	bif_voltage;

	/*
	 * 0x00000000 - 0x7fffffff in [mWh] or [mAh]
	 */
	uint32_t	bif_warn_cap;

	/*
	 * 0x00000000 - 0x7fffffff in [mWh] or [mAh]
	 */
	uint32_t	bif_low_cap;

	uint32_t	bif_gran1_cap;
	uint32_t	bif_gran2_cap;
	char		bif_model[MAXNAMELEN];
	char		bif_serial[MAXNAMELEN];
	char		bif_type[MAXNAMELEN];
	char		bif_oem_info[MAXNAMELEN];
} acpi_bif_t;

typedef	struct acpi_bst {
	uint32_t	bst_state;

	/*
	 * 0x00000000 - 0x7fffffff in [mW] or [mA]
	 * 0xffffffff - Unknown rate
	 */
	uint32_t	bst_rate;

	/*
	 * 0x00000000 - 0x7fffffff in [mWh] or [mAh]
	 * 0xffffffff - Unknown capacity
	 */
	uint32_t	bst_rem_cap;

	/*
	 * 0x00000000 - 0x7fffffff in [mV]
	 * 0xffffffff - Unknown voltage
	 */
	uint32_t	bst_voltage;
} acpi_bst_t;

/* Battery warnning levels in percentage */
typedef struct batt_warn {
	uint32_t	bw_enabled;	/* Enabled */
	uint32_t	bw_charge_warn;	/* charge warn threshold */
	uint32_t	bw_charge_low;	/* charge low threshold */
} batt_warn_t;

#define	BATT_DRV_NAME		"battery"
#define	BATT_POWER_KSTAT_NAME	"power"
#define	BATT_BTWARN_KSTAT_NAME	"battery warning"
#define	BATT_BIF_KSTAT_NAME	"battery BIF"
#define	BATT_BST_KSTAT_NAME	"battery BST"

#define	AC			"AC"
#define	BATTERY			"battery"
#define	SYSTEM_POWER		"system power"
#define	SUPPORTED_BATTERY_COUNT	"supported_battery_count"

#define	BW_ENABLED		"enabled"
#define	BW_POWEROFF_THRESHOLD	"warn capacity threshold"
#define	BW_SHUTDOWN_THRESHOLD	"low capacity threshold"

#define	BIF_UNIT		"bif_unit"
#define	BIF_DESIGN_CAP		"bif_design_cap"
#define	BIF_LAST_CAP		"bif_last_cap"
#define	BIF_TECH		"bif_tech"
#define	BIF_VOLTAGE		"bif_voltage"
#define	BIF_WARN_CAP		"bif_warn_cap"
#define	BIF_LOW_CAP		"bif_low_cap"
#define	BIF_GRAN1_CAP		"bif_gran1_cap"
#define	BIF_GRAN2_CAP		"bif_gran2_cap"
#define	BIF_MODEL		"bif_model"
#define	BIF_SERIAL		"bif_serial"
#define	BIF_TYPE		"bif_type"
#define	BIF_OEM_INFO		"bif_oem_info"

#define	BST_STATE		"bst_state"
#define	BST_RATE		"bst_rate"
#define	BST_REM_CAP		"bst_rem_cap"
#define	BST_VOLTAGE		"bst_voltage"

#define	PSR_AC_PRESENT		"psr_ac_present"

typedef struct batt_power_kstat_s {
	struct kstat_named	batt_power;
	struct kstat_named	batt_supported_battery_count;
} batt_power_kstat_t;

typedef struct batt_warn_kstat_s {
	struct kstat_named	batt_bw_enabled;
	struct kstat_named	batt_bw_charge_warn;
	struct kstat_named	batt_bw_charge_low;
} batt_warn_kstat_t;

/* BIF kstat */
typedef struct batt_bif_kstat_s {
	struct kstat_named	batt_bif_unit;
	struct kstat_named	batt_bif_design_cap;
	struct kstat_named	batt_bif_last_cap;
	struct kstat_named	batt_bif_tech;
	struct kstat_named	batt_bif_voltage;
	struct kstat_named	batt_bif_warn_cap;
	struct kstat_named	batt_bif_low_cap;
	struct kstat_named	batt_bif_gran1_cap;
	struct kstat_named	batt_bif_gran2_cap;
	struct kstat_named	batt_bif_model;
	struct kstat_named	batt_bif_serial;
	struct kstat_named	batt_bif_type;
	struct kstat_named	batt_bif_oem_info;
} batt_bif_kstat_t;

/* BST kstat */
typedef struct batt_bst_kstat_s {
	struct kstat_named	batt_bst_state;
	struct kstat_named	batt_bst_rate;
	struct kstat_named	batt_bst_rem_cap;
	struct kstat_named	batt_bst_voltage;
} batt_bst_kstat_t;

#ifdef	__cplusplus
}
#endif

#endif /* _BATTERY_H */
