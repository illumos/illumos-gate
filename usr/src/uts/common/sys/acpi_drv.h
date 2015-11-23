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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

#ifndef _ACPI_DRV_H
#define	_ACPI_DRV_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <sys/kstat.h>

enum acpi_drv_ioctl {
	ACPI_DRV_IOC_BAY,
	ACPI_DRV_IOC_INFO,
	ACPI_DRV_IOC_STATUS,
	ACPI_DRV_IOC_AC_COUNT,
	ACPI_DRV_IOC_POWER_STATUS,
	ACPI_DRV_IOC_SET_WARNING,
	ACPI_DRV_IOC_GET_WARNING,
	ACPI_DRV_IOC_LID_STATUS,
	ACPI_DRV_IOC_LID_UPDATE,
	ACPI_DRV_IOC_LEVELS,
	ACPI_DRV_IOC_SET_BRIGHTNESS
};

#define	ACPI_DRV_BST_CHARGING		2
#define	ACPI_DRV_BST_DISCHARGING	1

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
typedef struct acpi_drv_warn {
	uint32_t	bw_enabled;	/* Enabled */
	uint32_t	bw_charge_warn;	/* charge warn threshold */
	uint32_t	bw_charge_low;	/* charge low threshold */
} acpi_drv_warn_t;

#define	ACPI_DRV_NAME		"acpi_drv"
#define	ACPI_DRV_POWER_KSTAT_NAME	"power"
#define	ACPI_DRV_BTWARN_KSTAT_NAME	"battery warning"
#define	ACPI_DRV_BIF_KSTAT_NAME		"battery BIF"
#define	ACPI_DRV_BST_KSTAT_NAME		"battery BST"

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

typedef struct acpi_drv_power_kstat_s {
	struct kstat_named	acpi_drv_power;
	struct kstat_named	acpi_drv_supported_battery_count;
} acpi_drv_power_kstat_t;

typedef struct acpi_drv_warn_kstat_s {
	struct kstat_named	acpi_drv_bw_enabled;
	struct kstat_named	acpi_drv_bw_charge_warn;
	struct kstat_named	acpi_drv_bw_charge_low;
} acpi_drv_warn_kstat_t;

/* BIF kstat */
typedef struct acpi_drv_bif_kstat_s {
	struct kstat_named	acpi_drv_bif_unit;
	struct kstat_named	acpi_drv_bif_design_cap;
	struct kstat_named	acpi_drv_bif_last_cap;
	struct kstat_named	acpi_drv_bif_tech;
	struct kstat_named	acpi_drv_bif_voltage;
	struct kstat_named	acpi_drv_bif_warn_cap;
	struct kstat_named	acpi_drv_bif_low_cap;
	struct kstat_named	acpi_drv_bif_gran1_cap;
	struct kstat_named	acpi_drv_bif_gran2_cap;
	struct kstat_named	acpi_drv_bif_model;
	struct kstat_named	acpi_drv_bif_serial;
	struct kstat_named	acpi_drv_bif_type;
	struct kstat_named	acpi_drv_bif_oem_info;
} acpi_drv_bif_kstat_t;

/* BST kstat */
typedef struct acpi_drv_bst_kstat_s {
	struct kstat_named	acpi_drv_bst_state;
	struct kstat_named	acpi_drv_bst_rate;
	struct kstat_named	acpi_drv_bst_rem_cap;
	struct kstat_named	acpi_drv_bst_voltage;
} acpi_drv_bst_kstat_t;

/* acpi device types */
enum acpi_drv_type {
	ACPI_DRV_TYPE_UNKNOWN,
	ACPI_DRV_TYPE_CBAT,
	ACPI_DRV_TYPE_AC,
	ACPI_DRV_TYPE_LID,
	ACPI_DRV_TYPE_DISPLAY,
	ACPI_DRV_TYPE_HOTKEY
};

struct acpi_drv_output_info {
	uint32_t adr; /* unique ID for this output device */
	int nlev; /* number of brightness levels */
};

struct acpi_drv_output_status {
	int state;
	int num_levels;
	int cur_level;
	int cur_level_index;
};

#define	ACPI_DRV_OK			0
#define	ACPI_DRV_ERR			-1

#ifdef _KERNEL

#define	MINOR_SHIFT			8
#define	IDX_MASK			((1 << MINOR_SHIFT) - 1)
#define	MINOR_BATT(idx)			(ACPI_DRV_TYPE_CBAT << MINOR_SHIFT | \
					(idx))
#define	MINOR_AC(idx)			(ACPI_DRV_TYPE_AC << MINOR_SHIFT | \
					(idx))
#define	MINOR_LID(idx)			(ACPI_DRV_TYPE_LID << MINOR_SHIFT | \
					(idx))
#define	MINOR_HOTKEY(idx)		(ACPI_DRV_TYPE_HOTKEY << MINOR_SHIFT \
					| (idx))
#define	MINOR2IDX(minor)		((minor) & IDX_MASK)
#define	MINOR2TYPE(minor)		((minor) >> MINOR_SHIFT)

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _ACPI_DRV_H */
