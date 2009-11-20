/*
 * Copyright 2009, Intel Corporation
 * Copyright 2009, Sun Microsystems, Inc
 *
 * This file is part of PowerTOP
 *
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA
 *
 * Authors:
 *	Arjan van de Ven <arjan@linux.intel.com>
 *	Eric C Saxe <eric.saxe@sun.com>
 *	Aubrey Li <aubrey.li@intel.com>
 */

/*
 * GPL Disclaimer
 *
 * For the avoidance of doubt, except that if any license choice other
 * than GPL or LGPL is available it will apply instead, Sun elects to
 * use only the General Public License version 2 (GPLv2) at this time
 * for any software where a choice of GPL license versions is made
 * available with the language indicating that GPLv2 or any later
 * version may be used, or where a choice of which version of the GPL
 * is applied is otherwise unspecified.
 */

#include <string.h>
#include <kstat.h>
#include <errno.h>
#include "powertop.h"

#define	mW2W(value)	((value) / 1000)

typedef struct battery_state {
	uint32_t exist;
	uint32_t power_unit;
	uint32_t bst_state;
	double present_rate;
	double remain_cap;
	double last_cap;
} battery_state_t;

static char		*kstat_batt_mod[3] = {NULL, "battery", "acpi_drv"};
static uint_t		kstat_batt_idx;
static battery_state_t	battery_state;

static int		pt_battery_stat_snapshot(void);

/*
 * Checks if the kstat module for battery information is present and
 * whether it's called 'battery' or 'acpi_drv'
 */
void
pt_battery_mod_lookup(void)
{
	kstat_ctl_t *kc = kstat_open();

	if (kstat_lookup(kc, kstat_batt_mod[1], 0, NULL))
		kstat_batt_idx = 1;
	else
		if (kstat_lookup(kc, kstat_batt_mod[2], 0, NULL))
			kstat_batt_idx = 2;
		else
			kstat_batt_idx = 0;

	(void) kstat_close(kc);
}

void
pt_battery_print(void)
{
	int err;

	(void) memset(&battery_state, 0, sizeof (battery_state_t));

	/*
	 * The return value of pt_battery_stat_snapshot() can be used for
	 * debug or to show/hide the acpi power line. We currently don't
	 * make the distinction of a system that runs only on AC and one
	 * that runs on battery but has no kstat battery info.
	 *
	 * We still display the estimate power usage for systems
	 * running on AC with a fully charged battery because some
	 * batteries may still consume power.
	 *
	 * If pt_battery_mod_lookup() didn't find a kstat battery module, don't
	 * bother trying to take the snapshot
	 */
	if (kstat_batt_idx > 0) {
		if ((err = pt_battery_stat_snapshot()) < 0)
			pt_error("battery kstat not found (%d)\n", err);
	}

	pt_display_acpi_power(battery_state.exist, battery_state.present_rate,
	    battery_state.remain_cap, battery_state.last_cap,
	    battery_state.bst_state);
}

static int
pt_battery_stat_snapshot(void)
{
	kstat_ctl_t	*kc;
	kstat_t		*ksp;
	kstat_named_t	*knp;

	kc = kstat_open();

	/*
	 * power unit:
	 * 	0 - Capacity information is reported in [mWh] and
	 *	    charge/discharge rate information in [mW]
	 *	1 - Capacity information is reported in [mAh] and
	 *	    charge/discharge rate information in [mA].
	 */
	ksp = kstat_lookup(kc, kstat_batt_mod[kstat_batt_idx], 0,
	    "battery BIF0");

	if (ksp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	(void) kstat_read(kc, ksp, NULL);
	knp = kstat_data_lookup(ksp, "bif_unit");

	if (knp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	battery_state.power_unit = knp->value.ui32;

	/*
	 * Present rate:
	 *	the power or current being supplied or accepted
	 *	through the battery's terminal
	 */
	ksp = kstat_lookup(kc, kstat_batt_mod[kstat_batt_idx], 0,
	    "battery BST0");

	if (ksp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	(void) kstat_read(kc, ksp, NULL);
	knp = kstat_data_lookup(ksp, "bst_rate");

	if (knp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	if (knp->value.ui32 == 0xFFFFFFFF)
		battery_state.present_rate = 0;
	else {
		battery_state.exist = 1;
		battery_state.present_rate = mW2W((double)(knp->value.ui32));
	}

	/*
	 * Last Full charge capacity:
	 *	Predicted battery capacity when fully charged.
	 */
	ksp = kstat_lookup(kc, kstat_batt_mod[kstat_batt_idx], 0,
	    "battery BIF0");

	if (ksp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	(void) kstat_read(kc, ksp, NULL);
	knp = kstat_data_lookup(ksp, "bif_last_cap");

	if (knp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	battery_state.last_cap = mW2W((double)(knp->value.ui32));

	/*
	 * Remaining capacity:
	 *	the estimated remaining battery capacity
	 */
	ksp = kstat_lookup(kc, kstat_batt_mod[kstat_batt_idx], 0,
	    "battery BST0");

	if (ksp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	(void) kstat_read(kc, ksp, NULL);
	knp = kstat_data_lookup(ksp, "bst_rem_cap");

	if (knp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	battery_state.remain_cap = mW2W((double)(knp->value.ui32));

	/*
	 * Battery State:
	 *	Bit0 - 1 : discharging
	 *	Bit1 - 1 : charging
	 *	Bit2 - 1 : critical energy state
	 */
	ksp = kstat_lookup(kc, kstat_batt_mod[kstat_batt_idx], 0,
	    "battery BST0");

	if (ksp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	(void) kstat_read(kc, ksp, NULL);
	knp = kstat_data_lookup(ksp, "bst_state");

	if (knp == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	battery_state.bst_state = knp->value.ui32;

	(void) kstat_close(kc);

	return (0);
}
