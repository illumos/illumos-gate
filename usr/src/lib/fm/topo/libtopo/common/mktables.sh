#!/bin/sh

#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Construct translation tables for defines in libtopo.h to translate to readable
# strings.
#

if [ $# -ne 1 ]; then
	echo >&2 "USAGE: $0 <path to libtopo.h>"
	exit 1
fi

if [ -r $1 ]; then
	libtopo_h=$1
else
	echo >&2 "USAGE: $0 <path to libtopo.h>"
	echo >&2 "Make sure libtopo.h exists and is readable"
	exit 1
fi

echo "\
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libtopo.h>
#include \"topo_mod.h\"
#include \"topo_subr.h\""

#
# Sensor types.
#
echo "\ntopo_name_trans_t topo_sensor_type_table[] = {"

pattern="#define	TOPO_SENSOR_TYPE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_TYPE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Units
#
echo "\ntopo_name_trans_t topo_units_type_table[] = {"

pattern="	TOPO_SENSOR_UNITS_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_UNITS_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Indicator (LED) types
#
echo "\ntopo_name_trans_t topo_led_type_table[] = {"

pattern="	TOPO_LED_TYPE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_LED_TYPE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Indicator (LED) states
#
echo "\ntopo_name_trans_t topo_led_states_table[] = {"

pattern="	TOPO_LED_STATE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_LED_STATE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Discrete sensor states
#
echo "\ntopo_name_trans_t topo_sensor_states_physical_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_PHYSICAL_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_PHYSICAL_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_platform_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_PLATFORM_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_PLATFORM_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_processor_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_PROCESSOR_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_PROCESSOR_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_power_supply_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_POWER_SUPPLY_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_POWER_SUPPLY_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_power_unit_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_POWER_UNIT_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_POWER_UNIT_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_memory_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_MEMORY_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_MEMORY_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_bay_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_BAY_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_BAY_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_firmware_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_FIRMWARE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_FIRMWARE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_event_log_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_EVENT_LOG_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_EVENT_LOG_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_watchdog1_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_WATCHDOG_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_WATCHDOG_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_system_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_SYSTEM_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_SYSTEM_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_critical_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_CRITICAL_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_CRITICAL_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_button_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_BUTTON_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_BUTTON_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_cable_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_CABLE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_CABLE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_boot_state_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_BOOT_STATE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_BOOT_STATE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_boot_error_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_BOOT_ERROR_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_BOOT_ERROR_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_boot_os_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_BOOT_OS_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_BOOT_OS_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_os_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_OS_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_OS_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_slot_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_SLOT_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_SLOT_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_acpi_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_ACPI_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_ACPI_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_watchdog2_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_WATCHDOG2_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_WATCHDOG2_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_alert_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_ALERT_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_ALERT_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_presence_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_PRESENCE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_PRESENCE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_lan_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_LAN_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_LAN_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_health_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_HEALTH_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_HEALTH_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_battery_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_BATTERY_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_BATTERY_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_audit_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_AUDIT_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_AUDIT_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_version_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_VERSION_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_VERSION_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_fru_state_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_FRU_STATE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_FRU_STATE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_thresh_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_THRESH_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_THRESH_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_usage_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_USAGE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_USAGE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_state_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_STATE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_STATE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"


echo "\ntopo_name_trans_t topo_sensor_states_generic_predfail_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_PREDFAIL_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_PREDFAIL_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_limit_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_LIMIT_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_LIMIT_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_perf_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_PERFORMANCE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_PERFORMANCE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_severity_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_SEVERITY_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_SEVERITY_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_presence_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_PRESENCE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_PRESENCE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_avail_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_AVAILABILITY_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_AVAILABILITY_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_status_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_STATUS_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_STATUS_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_acpi_pwr_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_ACPI_PWR_STATE_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_ACPI_PWR_STATE_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_failure_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_FAIL_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_FAIL_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

echo "\ntopo_name_trans_t topo_sensor_states_generic_ok_table[] = {"

pattern="#define	TOPO_SENSOR_STATE_GENERIC_OK_\([A-Z0-9_]*\).*\$"
replace="	{ TOPO_SENSOR_STATE_GENERIC_OK_\1, \"\1\" },"

cat $libtopo_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"
