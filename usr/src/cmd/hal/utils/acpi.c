/***************************************************************************
 *
 * acpi.c : Main routines for setting battery, AC adapter, and lid properties
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <kstat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/acpi_drv.h>

#include <libhal.h>
#include "../hald/device_info.h"
#include "../hald/hald_dbus.h"
#include "../hald/logger.h"
#include "../hald/util_pm.h"
#include "acpi.h"


static void
my_dbus_error_free(DBusError *error)
{
	if (dbus_error_is_set(error)) {
		dbus_error_free(error);
	}
}

gboolean
laptop_panel_update(LibHalContext *ctx, const char *udi, int fd)
{
	LibHalChangeSet *cs;
	DBusError error;
	struct acpi_drv_output_info inf;

	HAL_DEBUG(("laptop_panel_update() enter"));

	dbus_error_init(&error);
	if (!libhal_device_query_capability(ctx, udi, "laptop_panel", &error)) {
		bzero(&inf, sizeof (inf));
		if ((ioctl(fd, ACPI_DRV_IOC_INFO, &inf) < 0) ||
		    (inf.nlev == 0)) {
			return (FALSE);
		}

		my_dbus_error_free(&error);
		libhal_device_add_capability(ctx, udi, "laptop_panel", &error);
		if ((cs = libhal_device_new_changeset(udi)) == NULL) {
			my_dbus_error_free(&error);
			return (FALSE);
		}
		libhal_changeset_set_property_string(cs, "info.product",
		    "Generic Backlight Device");
		libhal_changeset_set_property_string(cs, "info.category",
		    "laptop_panel");
		libhal_changeset_set_property_int(cs, "laptop_panel.num_levels",
		    inf.nlev);
		my_dbus_error_free(&error);
		libhal_device_commit_changeset(ctx, cs, &error);
		libhal_device_free_changeset(cs);
	}
	my_dbus_error_free(&error);
	HAL_DEBUG(("ac_adapter_present() exit"));
	return (TRUE);
}

gboolean
lid_update(LibHalContext *ctx, const char *udi, int fd)
{
	LibHalChangeSet *cs;
	DBusError error;

	HAL_DEBUG(("lid_update() enter"));

	dbus_error_init(&error);
	if (!libhal_device_query_capability(ctx, udi, "button", &error)) {
		my_dbus_error_free(&error);
		libhal_device_add_capability(ctx, udi, "button", &error);
		if ((cs = libhal_device_new_changeset(udi)) == NULL) {
			my_dbus_error_free(&error);
			return (FALSE);
		}
		libhal_changeset_set_property_bool(cs, "button.has_state",
		    TRUE);
		libhal_changeset_set_property_bool(cs, "button.state.value",
		    FALSE);
		libhal_changeset_set_property_string(cs, "button.type",
		    "lid");
		libhal_changeset_set_property_string(cs, "info.product",
		    "Lid Switch");
		libhal_changeset_set_property_string(cs, "info.category",
		    "button");
		my_dbus_error_free(&error);
		libhal_device_commit_changeset(ctx, cs, &error);
		libhal_device_free_changeset(cs);
	}
	my_dbus_error_free(&error);
	HAL_DEBUG(("update_lid() exit"));
	return (TRUE);
}

static void
ac_adapter_present(LibHalContext *ctx, const char *udi, int fd)
{
	int pow;
	LibHalChangeSet *cs;
	DBusError error;

	HAL_DEBUG(("ac_adapter_present() enter"));
	if (ioctl(fd, ACPI_DRV_IOC_POWER_STATUS, &pow) < 0) {
		return;
	}
	if ((cs = libhal_device_new_changeset(udi)) == NULL) {
		return;
	}
	if (pow > 0) {
		libhal_changeset_set_property_bool(cs, "ac_adapter.present",
		    TRUE);
	} else {
		libhal_changeset_set_property_bool(cs, "ac_adapter.present",
		    FALSE);
	}

	dbus_error_init(&error);
	libhal_device_commit_changeset(ctx, cs, &error);
	libhal_device_free_changeset(cs);
	my_dbus_error_free(&error);
	HAL_DEBUG(("ac_adapter_present() exit"));
}

static void
battery_remove(LibHalContext *ctx, const char *udi)
{
	DBusError error;

	HAL_DEBUG(("battery_remove() enter"));
	dbus_error_init(&error);
	libhal_device_remove_property(ctx, udi, "battery.remaining_time",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.charge_level.percentage", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.charge_level.rate",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.charge_level.last_full", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.charge_level.current", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.voltage.present",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.rate",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.current",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.rechargeable.is_discharging", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.rechargeable.is_charging", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.is_rechargeable",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.charge_level.unit",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.charge_level.granularity_2", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.charge_level.granularity_1", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.charge_level.low",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.charge_level.warning",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.charge_level.design",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.voltage.design",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.reporting.granularity_2", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi,
	    "battery.reporting.granularity_1", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.low",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.warning",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.design",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.last_full",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.unit",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.technology", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.reporting.technology",
	    &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.serial", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.model", &error);
	my_dbus_error_free(&error);
	libhal_device_remove_property(ctx, udi, "battery.vendor", &error);
	my_dbus_error_free(&error);
	HAL_DEBUG(("battery_remove() exit"));
}

static void
battery_last_full(LibHalChangeSet *cs, int fd)
{
	acpi_bif_t bif;

	bzero(&bif, sizeof (bif));
	if (ioctl(fd, ACPI_DRV_IOC_INFO, &bif) < 0) {
		return;
	}
	libhal_changeset_set_property_int(cs, "battery.reporting_last_full",
	    bif.bif_last_cap);
}

static void
battery_dynamic_update(LibHalContext *ctx, const char *udi, int fd)
{
	int reporting_rate;
	int reporting_current;
	int reporting_lastfull;
	int design_voltage;
	int present_voltage;
	char *reporting_unit;
	int remaining_time;
	int remaining_percentage;
	gboolean charging;
	gboolean discharging;
	acpi_bst_t bst;
	LibHalChangeSet *cs;
	DBusError error;
	static int counter = 0;

	HAL_DEBUG(("battery_dynamic_update() enter"));
	bzero(&bst, sizeof (bst));
	if (ioctl(fd, ACPI_DRV_IOC_STATUS, &bst) < 0) {
		return;
	}

	charging = bst.bst_state & ACPI_DRV_BST_CHARGING ? TRUE : FALSE;
	discharging = bst.bst_state & ACPI_DRV_BST_DISCHARGING ? TRUE : FALSE;
	/* No need to continue if battery is essentially idle. */
	if (counter && !charging && !discharging) {
		return;
	}
	dbus_error_init(&error);
	libhal_device_set_property_bool(ctx, udi, "battery.is_rechargeable",
	    TRUE, &error);
	my_dbus_error_free(&error);
	if (libhal_device_property_exists(ctx, udi,
	    "battery.charge_level.percentage", &error)) {
		remaining_percentage = libhal_device_get_property_int(ctx, udi,
		    "battery.charge_level.percentage", &error);
		if ((remaining_percentage == 100) && charging) {
			charging = FALSE;
		}
	}
	libhal_device_set_property_bool(ctx, udi,
	    "battery.rechargeable.is_charging", charging, &error);
	my_dbus_error_free(&error);
	libhal_device_set_property_bool(ctx, udi,
	    "battery.rechargeable.is_discharging", discharging, &error);
	my_dbus_error_free(&error);
	reporting_current = bst.bst_rem_cap;
	libhal_device_set_property_int(ctx, udi, "battery.reporting.current",
	    bst.bst_rem_cap, &error);
	my_dbus_error_free(&error);
	reporting_rate = bst.bst_rate;
	libhal_device_set_property_int(ctx, udi, "battery.reporting.rate",
	    bst.bst_rate, &error);
	my_dbus_error_free(&error);
	present_voltage = bst.bst_voltage;
	libhal_device_set_property_int(ctx, udi, "battery.voltage.present",
	    bst.bst_voltage, &error);
	/* get all the data we know */
	my_dbus_error_free(&error);
	reporting_unit = libhal_device_get_property_string(ctx, udi,
	    "battery.reporting.unit", &error);
	my_dbus_error_free(&error);
	reporting_lastfull = libhal_device_get_property_int(ctx, udi,
	    "battery.reporting.last_full", &error);

	/*
	 * Convert mAh to mWh since util_compute_time_remaining() works
	 * for mWh.
	 */
	if (reporting_unit && strcmp(reporting_unit, "mAh") == 0) {
		my_dbus_error_free(&error);
		design_voltage = libhal_device_get_property_int(ctx, udi,
		    "battery.voltage.design", &error);
		/*
		 * If the present_voltage is inaccurate, set it to the
		 * design_voltage.
		 */
		if (((present_voltage * 10) < design_voltage) ||
		    (present_voltage <= 0) ||
		    (present_voltage > design_voltage)) {
			present_voltage = design_voltage;
		}
		reporting_rate = (reporting_rate * present_voltage) / 1000;
		reporting_lastfull = (reporting_lastfull * present_voltage) /
		    1000;
		reporting_current = (reporting_current * present_voltage) /
		    1000;
	}

	/* Make sure the current charge does not exceed the full charge */
	if (reporting_current > reporting_lastfull) {
		reporting_current = reporting_lastfull;
	}
	if (!charging && !discharging) {
		counter++;
		reporting_rate = 0;
	}

	if ((cs = libhal_device_new_changeset(udi)) == NULL) {
		HAL_DEBUG(("Cannot allocate changeset"));
		libhal_free_string(reporting_unit);
		my_dbus_error_free(&error);
		return;
	}

	libhal_changeset_set_property_int(cs, "battery.charge_level.rate",
	    reporting_rate);
	libhal_changeset_set_property_int(cs,
	    "battery.charge_level.last_full", reporting_lastfull);
	libhal_changeset_set_property_int(cs,
	    "battery.charge_level.current", reporting_current);

	remaining_percentage = util_compute_percentage_charge(udi,
	    reporting_current, reporting_lastfull);
	remaining_time = util_compute_time_remaining(udi, reporting_rate,
	    reporting_current, reporting_lastfull, discharging, charging, 0);
	/*
	 * Some batteries give bad remaining_time estimates relative to
	 * the charge level.
	 */
	if (charging && ((remaining_time < 30) || ((remaining_time < 300) &&
	    (remaining_percentage < 95)) || (remaining_percentage > 97))) {
		remaining_time = util_compute_time_remaining(udi,
		    reporting_rate, reporting_current, reporting_lastfull,
		    discharging, charging, 1);
	}

	if (remaining_percentage > 0) {
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.percentage", remaining_percentage);
	} else {
		my_dbus_error_free(&error);
		libhal_device_remove_property(ctx, udi,
		    "battery.charge_level.percentage", &error);
	}
	if ((remaining_percentage == 100) && charging) {
		battery_last_full(cs, fd);
	}
	/*
	 * remaining_percentage is more accurate so we handle cases
	 * where the remaining_time cannot be correct.
	 */
	if ((!charging && !discharging) || ((remaining_percentage == 100) &&
	    !discharging)) {
		remaining_time = 0;
	}
	if (remaining_time < 0) {
		my_dbus_error_free(&error);
		libhal_device_remove_property(ctx, udi,
		    "battery.remaining_time", &error);
	} else if (remaining_time >= 0) {
		libhal_changeset_set_property_int(cs,
		    "battery.remaining_time", remaining_time);
	}

	my_dbus_error_free(&error);
	libhal_device_commit_changeset(ctx, cs, &error);
	libhal_device_free_changeset(cs);
	libhal_free_string(reporting_unit);
	my_dbus_error_free(&error);
	HAL_DEBUG(("battery_dynamic_update() exit"));
}

static gboolean
battery_static_update(LibHalContext *ctx, const char *udi, int fd)
{
	const char *technology;
	int reporting_design;
	int reporting_warning;
	int reporting_low;
	int reporting_gran1;
	int reporting_gran2;
	int voltage_design;
	char reporting_unit[10];
	acpi_bif_t bif;
	LibHalChangeSet *cs;
	DBusError error;

	HAL_DEBUG(("battery_static_update() enter"));
	bzero(&bif, sizeof (bif));
	if (ioctl(fd, ACPI_DRV_IOC_INFO, &bif) < 0) {
		return (FALSE);
	}
	if ((cs = libhal_device_new_changeset(udi)) == NULL) {
		HAL_DEBUG(("Cannot allocate changeset"));
		return (FALSE);
	}

	libhal_changeset_set_property_string(cs, "battery.vendor",
	    bif.bif_oem_info);
	technology = bif.bif_type;
	if (technology != NULL) {
		libhal_changeset_set_property_string(cs,
		    "battery.reporting.technology", technology);
		libhal_changeset_set_property_string(cs, "battery.technology",
		    util_get_battery_technology(technology));
	}
	libhal_changeset_set_property_string(cs, "battery.serial",
	    bif.bif_serial);
	libhal_changeset_set_property_string(cs, "battery.model",
	    bif.bif_model);

	if (bif.bif_unit) {
		libhal_changeset_set_property_string(cs,
		    "battery.reporting.unit", "mAh");
		strlcpy(reporting_unit, "mAh", sizeof (reporting_unit));
	} else {
		libhal_changeset_set_property_string(cs,
		    "battery.reporting.unit", "mWh");
		strlcpy(reporting_unit, "mWh", sizeof (reporting_unit));
	}
	libhal_changeset_set_property_int(cs, "battery.reporting.last_full",
	    bif.bif_last_cap);
	libhal_changeset_set_property_int(cs, "battery.reporting.design",
	    bif.bif_design_cap);
	reporting_design = bif.bif_design_cap;
	libhal_changeset_set_property_int(cs, "battery.reporting.warning",
	    bif.bif_warn_cap);
	reporting_warning = bif.bif_warn_cap;
	libhal_changeset_set_property_int(cs, "battery.reporting.low",
	    bif.bif_low_cap);
	reporting_low = bif.bif_low_cap;
	libhal_changeset_set_property_int(cs,
	    "battery.reporting.granularity_1", bif.bif_gran1_cap);
	reporting_gran1 = bif.bif_gran1_cap;
	libhal_changeset_set_property_int(cs,
	    "battery.reporting.granularity_2", bif.bif_gran2_cap);
	reporting_gran2 = bif.bif_gran2_cap;
	libhal_changeset_set_property_int(cs, "battery.voltage.design",
	    bif.bif_voltage);
	voltage_design = bif.bif_voltage;

	if (reporting_unit && strcmp(reporting_unit, "mAh") == 0) {
		/* convert to mWh */
		libhal_changeset_set_property_string(cs,
		    "battery.charge_level.unit", "mWh");
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.design",
		    (reporting_design * voltage_design) / 1000);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.warning",
		    (reporting_warning * voltage_design) / 1000);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.low",
		    (reporting_low * voltage_design) / 1000);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.granularity_1",
		    (reporting_gran1 * voltage_design) / 1000);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.granularity_2",
		    (reporting_gran2 * voltage_design) / 1000);
	} else {
		if (reporting_unit && strcmp(reporting_unit, "mWh") == 0) {
			libhal_changeset_set_property_string(cs,
			    "battery.charge_level.unit", "mWh");
		}
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.design", reporting_design);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.warning", reporting_warning);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.low", reporting_low);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.granularity_1", reporting_gran1);
		libhal_changeset_set_property_int(cs,
		    "battery.charge_level.granularity_2", reporting_gran2);
	}


	dbus_error_init(&error);
	libhal_device_commit_changeset(ctx, cs, &error);
	libhal_device_free_changeset(cs);
	my_dbus_error_free(&error);
	HAL_DEBUG(("battery_static_update() exit"));
	return (TRUE);
}

gboolean
battery_update(LibHalContext *ctx, const char *udi, int fd)
{
	acpi_bst_t bst;
	DBusError error;

	HAL_DEBUG(("battery_update() enter"));
	dbus_error_init(&error);
	libhal_device_set_property_string(ctx, udi, "info.product",
	    "Battery Bay", &error);
	my_dbus_error_free(&error);
	libhal_device_set_property_string(ctx, udi, "info.category", "battery",
	    &error);

	bzero(&bst, sizeof (bst));
	if (ioctl(fd, ACPI_DRV_IOC_STATUS, &bst) < 0) {
		if (errno == ENXIO) {
			my_dbus_error_free(&error);
			libhal_device_set_property_bool(ctx, udi,
			    "battery.present", FALSE, &error);
		} else {
			my_dbus_error_free(&error);
			return (FALSE);
		}
	} else {
		my_dbus_error_free(&error);
		libhal_device_set_property_bool(ctx, udi, "battery.present",
		    TRUE, &error);
	}

	my_dbus_error_free(&error);
	if (!libhal_device_get_property_bool(ctx, udi, "battery.present",
	    &error)) {
		HAL_DEBUG(("battery_update(): battery is NOT present"));
		battery_remove(ctx, udi);
	} else {
		HAL_DEBUG(("battery_update(): battery is present"));
		my_dbus_error_free(&error);
		libhal_device_set_property_string(ctx, udi, "battery.type",
		    "primary", &error);
		my_dbus_error_free(&error);
		libhal_device_add_capability(ctx, udi, "battery", &error);
		my_dbus_error_free(&error);
		if (libhal_device_get_property_type(ctx, udi, "battery.vendor",
		    &error) == LIBHAL_PROPERTY_TYPE_INVALID) {
			battery_static_update(ctx, udi, fd);
		}
		battery_dynamic_update(ctx, udi, fd);
	}
	my_dbus_error_free(&error);
	HAL_DEBUG(("battery_update() exit"));
	return (TRUE);
}

static gboolean
battery_update_all(LibHalContext *ctx)
{
	int i;
	int num_devices;
	char **battery_devices;
	int fd;
	DBusError error;

	HAL_DEBUG(("battery_update_all() enter"));

	dbus_error_init(&error);
	if ((battery_devices = libhal_manager_find_device_string_match
	    (ctx, "info.category", "battery", &num_devices, &error)) !=
	    NULL) {
		for (i = 0; i < num_devices; i++) {
			my_dbus_error_free(&error);
			if (libhal_device_get_property_bool(ctx,
			    battery_devices[i], "battery.present", &error)) {
				if ((fd = open_device(ctx,
				    battery_devices[i])) == -1) {
					continue;
				}
				battery_dynamic_update(ctx, battery_devices[i],
				    fd);
				close(fd);
			}
		}
		libhal_free_string_array(battery_devices);
	}
	my_dbus_error_free(&error);
	HAL_DEBUG(("battery_update_all() exit"));
	return (TRUE);
}

gboolean
ac_adapter_update(LibHalContext *ctx, const char *udi, int fd)
{
	LibHalChangeSet *cs;
	DBusError error;

	HAL_DEBUG(("ac_adapter_update() enter"));
	dbus_error_init(&error);
	if (!libhal_device_query_capability(ctx, udi, "ac_adapter", &error)) {
		my_dbus_error_free(&error);
		libhal_device_add_capability(ctx, udi, "ac_adapter", &error);
		if ((cs = libhal_device_new_changeset(udi)) == NULL) {
			my_dbus_error_free(&error);
			return (FALSE);
		}
		libhal_changeset_set_property_string(cs, "info.product",
		    "AC Adapter");
		libhal_changeset_set_property_string(cs, "info.category",
		    "ac_adapter");
		my_dbus_error_free(&error);
		libhal_device_commit_changeset(ctx, cs, &error);
		libhal_device_free_changeset(cs);
	}
	ac_adapter_present(ctx, udi, fd);
	battery_update_all(ctx);

	my_dbus_error_free(&error);
	HAL_DEBUG(("ac_adapter_update() exit"));
	return (TRUE);
}

static gboolean
ac_adapter_update_all(LibHalContext *ctx)
{
	int i;
	int num_devices;
	char **ac_adapter_devices;
	int fd;
	DBusError error;

	HAL_DEBUG(("ac_adapter_update_all() enter"));
	dbus_error_init(&error);
	if ((ac_adapter_devices = libhal_manager_find_device_string_match(
	    ctx, "info.category", "ac_adapter", &num_devices, &error)) !=
	    NULL) {
		for (i = 0; i < num_devices; i++) {
			if ((fd = open_device(ctx, ac_adapter_devices[i]))
			    == -1) {
				continue;
			}
			ac_adapter_present(ctx, ac_adapter_devices[i], fd);
			close(fd);
		}
		libhal_free_string_array(ac_adapter_devices);
	}
	my_dbus_error_free(&error);
	HAL_DEBUG(("ac_adapter_update_all() exit"));
	return (TRUE);
}

gboolean
update_devices(gpointer data)
{
	LibHalContext *ctx = (LibHalContext *)data;

	HAL_DEBUG(("update_devices() enter"));
	ac_adapter_update_all(ctx);
	battery_update_all(ctx);
	HAL_DEBUG(("update_devices() exit"));
	return (TRUE);
}

int
open_device(LibHalContext *ctx, char *udi)
{
	char path[HAL_PATH_MAX] = "/devices";
	char *devfs_path;
	DBusError error;

	dbus_error_init(&error);
	devfs_path = libhal_device_get_property_string(ctx, udi,
	    "solaris.devfs_path", &error);
	my_dbus_error_free(&error);
	if (devfs_path == NULL) {
		return (-1);
	}
	strlcat(path, devfs_path, HAL_PATH_MAX);
	libhal_free_string(devfs_path);
	return (open(path, O_RDONLY | O_NONBLOCK));
}
