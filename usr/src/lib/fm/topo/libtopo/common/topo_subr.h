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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _TOPO_SUBR_H
#define	_TOPO_SUBR_H

#include <fm/libtopo.h>
#include <topo_list.h>

#include <pthread.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct topo_debug_mode {
	char *tdm_name;		/* mode name */
	char *tdm_desc;		/* mode description */
	int tdm_mode;		/* mode: See below */
} topo_debug_mode_t;

#define	TOPO_DBOUT_STDERR	0	/* Debug messages to stderr */
#define	TOPO_DBOUT_SYSLOG	1	/* Debug messages to syslog */

#define	TOPO_DBG_ERR	0x0001	/* enable error handling debug messages */
#define	TOPO_DBG_MOD	0x0002	/* enable module debug messages */
#define	TOPO_DBG_MODSVC	0x0004	/* enable module services debug messages */
#define	TOPO_DBG_WALK	0x0008	/* enable walker debug messages */
#define	TOPO_DBG_XML	0x0010	/* enable xml parsing debug messages */
#define	TOPO_DBG_FORCE	0x0020	/* use DINFOFORCE snapshot for topology */
#define	TOPO_DBG_ALL	0xffff	/* enable all debug modes */

#define	TOPO_STABSTR_INTERNAL	"Internal"	/* private to libtopo */
#define	TOPO_STABSTR_PRIVATE	"Private"	/* private to Sun */
#define	TOPO_STABSTR_OBSOLETE	"Obsolete"	/* scheduled for removal */
#define	TOPO_STABSTR_EXTERNAL	"External"	/* not controlled by Sun */
#define	TOPO_STABSTR_UNSTABLE	"Unstable"	/* new or rapidly changing */
#define	TOPO_STABSTR_EVOLVING	"Evolving"	/* less rapidly changing */
#define	TOPO_STABSTR_STABLE	"Stable"	/* mature interface from Sun */
#define	TOPO_STABSTR_STANDARD	"Standard"	/* industry standard */
#define	TOPO_STABSTR_UNKNOWN	"Unknown"	/* stability unknown */

typedef struct topo_name_trans {
	uint32_t	int_value;
	const char	*int_name;
} topo_name_trans_t;

extern topo_name_trans_t topo_sensor_type_table[];
extern topo_name_trans_t topo_units_type_table[];
extern topo_name_trans_t topo_led_type_table[];
extern topo_name_trans_t topo_led_states_table[];
extern topo_name_trans_t topo_sensor_states_physical_table[];
extern topo_name_trans_t topo_sensor_states_platform_table[];
extern topo_name_trans_t topo_sensor_states_processor_table[];
extern topo_name_trans_t topo_sensor_states_power_supply_table[];
extern topo_name_trans_t topo_sensor_states_power_unit_table[];
extern topo_name_trans_t topo_sensor_states_memory_table[];
extern topo_name_trans_t topo_sensor_states_bay_table[];
extern topo_name_trans_t topo_sensor_states_firmware_table[];
extern topo_name_trans_t topo_sensor_states_event_log_table[];
extern topo_name_trans_t topo_sensor_states_watchdog1_table[];
extern topo_name_trans_t topo_sensor_states_system_table[];
extern topo_name_trans_t topo_sensor_states_critical_table[];
extern topo_name_trans_t topo_sensor_states_button_table[];
extern topo_name_trans_t topo_sensor_states_cable_table[];
extern topo_name_trans_t topo_sensor_states_boot_state_table[];
extern topo_name_trans_t topo_sensor_states_boot_error_table[];
extern topo_name_trans_t topo_sensor_states_boot_os_table[];
extern topo_name_trans_t topo_sensor_states_os_table[];
extern topo_name_trans_t topo_sensor_states_slot_table[];
extern topo_name_trans_t topo_sensor_states_acpi_table[];
extern topo_name_trans_t topo_sensor_states_watchdog2_table[];
extern topo_name_trans_t topo_sensor_states_alert_table[];
extern topo_name_trans_t topo_sensor_states_presence_table[];
extern topo_name_trans_t topo_sensor_states_lan_table[];
extern topo_name_trans_t topo_sensor_states_health_table[];
extern topo_name_trans_t topo_sensor_states_battery_table[];
extern topo_name_trans_t topo_sensor_states_audit_table[];
extern topo_name_trans_t topo_sensor_states_version_table[];
extern topo_name_trans_t topo_sensor_states_fru_state_table[];
extern topo_name_trans_t topo_sensor_states_thresh_table[];
extern topo_name_trans_t topo_sensor_states_generic_usage_table[];
extern topo_name_trans_t topo_sensor_states_generic_state_table[];
extern topo_name_trans_t topo_sensor_states_generic_predfail_table[];
extern topo_name_trans_t topo_sensor_states_generic_limit_table[];
extern topo_name_trans_t topo_sensor_states_generic_perf_table[];
extern topo_name_trans_t topo_sensor_states_generic_presence_table[];
extern topo_name_trans_t topo_sensor_states_severity_table[];
extern topo_name_trans_t topo_sensor_states_generic_avail_table[];
extern topo_name_trans_t topo_sensor_states_generic_status_table[];
extern topo_name_trans_t topo_sensor_states_generic_acpi_pwr_table[];
extern topo_name_trans_t topo_sensor_states_generic_failure_table[];
extern topo_name_trans_t topo_sensor_states_generic_ok_table[];

extern void topo_hdl_lock(topo_hdl_t *);
extern void topo_hdl_unlock(topo_hdl_t *);

extern const char *topo_stability_name(topo_stability_t);
extern char *topo_version_num2str(topo_version_t, char *, size_t);
extern int topo_version_str2num(const char *, topo_version_t);
extern int topo_version_defined(topo_version_t);

extern void topo_dprintf(topo_hdl_t *, int, const char *, ...);
extern void topo_vdprintf(topo_hdl_t *, const char *, const char *,
    va_list);

extern tnode_t *topo_hdl_root(topo_hdl_t *, const char *);
extern char *topo_search_path(topo_mod_t *, const char *, const char *);

extern void topo_fmristr_build(ssize_t *, char *, size_t, char *, char *,
    char *);

extern int topo_walk_byid(topo_walk_t *wp, const char *name, topo_instance_t);
extern int topo_walk_bysibling(topo_walk_t *wp, const char *name,
    topo_instance_t);

extern char *topo_cleanup_auth_str(topo_hdl_t *, const char *);
extern char *topo_cleanup_strn(topo_hdl_t *, const char *, size_t);

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_SUBR_H */
