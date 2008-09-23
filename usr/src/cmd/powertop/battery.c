/*
 * Copyright 2008, Intel Corporation
 * Copyright 2008, Sun Microsystems, Inc
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

typedef struct battery_state {
	uint32_t exist;
	uint32_t power_unit;
	uint32_t bst_state;
	double present_rate;
	double remain_cap;
	double last_cap;
} battery_state_t;

battery_state_t battery;

static	int	battery_stat_snapshot(void);

#define	mW2W(value)	((value) / 1000)

void
print_battery(void)
{
	int err;

	(void) memset(&battery, 0, sizeof (battery_state_t));

	/*
	 * The return value of battery_stat_snapsho() can be used for
	 * debug or to show/hide the acpi power line. We currently don't
	 * make the distinction of a system that runs only on AC and one
	 * that runs on battery but has no kstat battery info.
	 *
	 * We still display the estimate power usage for systems
	 * running on AC with a fully charged battery because some
	 * batteries may still consume power.
	 *
	 * If battery_mod_lookup() didn't find a kstat battery module, don't
	 * bother trying to take the snapshot
	 */
	if (kstat_batt_idx > 0) {
		if ((err = battery_stat_snapshot()) < 0)
			pt_error("%s : battery kstat not found %d\n", __FILE__,
			    err);
	}

	show_acpi_power_line(battery.exist, battery.present_rate,
	    battery.remain_cap, battery.last_cap, battery.bst_state);
}

static int
battery_stat_snapshot(void)
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

	battery.power_unit = knp->value.ui32;

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
		battery.present_rate = 0;
	else {
		battery.exist = 1;
		battery.present_rate = mW2W((double)(knp->value.ui32));
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

	battery.last_cap = mW2W((double)(knp->value.ui32));

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

	battery.remain_cap = mW2W((double)(knp->value.ui32));

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

	battery.bst_state = knp->value.ui32;

	(void) kstat_close(kc);

	return (0);
}
