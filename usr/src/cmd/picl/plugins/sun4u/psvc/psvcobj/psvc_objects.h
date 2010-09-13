/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PSVC_OBJECTS_H
#define	_PSVC_OBJECTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Platform Services Framework definitions
 */

#include <sys/types.h>
#include <pthread.h>

typedef struct psvc_opaque *psvc_opaque_t;

/* Return values */
#define	PSVC_SUCCESS 0
#define	PSVC_FAILURE -1
#define	PSVC_NOT_USED -1

/* Class definitions */
#define	PSVC_TEMPERATURE_SENSOR_CLASS 0
#define	PSVC_FAN_CLASS 1
#define	PSVC_LED_CLASS 2
#define	PSVC_SYSTEM_CLASS 3
#define	PSVC_DIGITAL_SENSOR_CLASS 4
#define	PSVC_DIGITAL_CONTROL_CLASS 5
#define	PSVC_BOOLEAN_GPIO_CLASS 6
#define	PSVC_FAN_TACHOMETER_CLASS 7
#define	PSVC_ON_OFF_SWITCH_CLASS 8
#define	PSVC_KEYSWITCH_CLASS 9
#define	PSVC_8BIT_GPIO_CLASS 10
#define	PSVC_PHYSICAL_DEVICE_CLASS 11

#define	PSVC_CHASSIS "SYSTEM"

/* Associations */
#define	PSVC_PRESENCE_SENSOR 0
#define	PSVC_FAN_ONOFF_SENSOR 1
#define	PSVC_FAN_SPEED_TACHOMETER 2
#define	PSVC_FAN_PRIM_SEC_SELECTOR 3
#define	PSVC_DEV_TEMP_SENSOR 4
#define	PSVC_FAN_DRIVE_CONTROL 5
#define	PSVC_KS_NORMAL_POS_SENSOR 6
#define	PSVC_KS_DIAG_POS_SENSOR 7
#define	PSVC_KS_LOCK_POS_SENSOR 8
#define	PSVC_KS_OFF_POS_SENSOR 9
#define	PSVC_SLOT_FAULT_LED 10
#define	PSVC_SLOT_REMOVE_LED 11
#define	PSVC_TS_OVERTEMP_LED 12
#define	PSVC_PS_I_SENSOR 13
#define	PSVC_DEV_FAULT_SENSOR 14
#define	PSVC_DEV_FAULT_LED 15
#define	PSVC_TABLE 16
#define	PSVC_PARENT 17
#define	PSVC_CPU 18
#define	PSVC_ALTERNATE 19
#define	PSVC_HOTPLUG_ENABLE_SWITCH 20
#define	PSVC_PS 21
#define	PSVC_FAN 22
#define	PSVC_TS 23
#define	PSVC_DISK 24
#define	PSVC_LED 25
#define	PSVC_FSP_LED 26
#define	PSVC_KEYSWITCH 27
#define	PSVC_PCI_CARD 28
#define	PSVC_PHYSICAL_DEVICE 29
#define	PSVC_DEV_TYPE_SENSOR 30
#define	PSVC_FAN_TRAY_FANS 31
#define	PSVC_FRU 32


/* Device "feature" definitions */
#define	PSVC_DEV_PERM		0x0000000000000001ULL /* Permanently in sys */
#define	PSVC_DEV_HOTPLUG	0x0000000000000002ULL /* Hot-pluggable device */
#define	PSVC_DEV_OPTION	0x0000000000000004ULL /* Option (not hot-pluggable) */
#define	PSVC_DEV_PRIMARY	0x0000000000000010ULL /* Primary device */
#define	PSVC_DEV_SECONDARY	0x0000000000000020ULL /* Secondary device */
#define	PSVC_DEV_RDONLY    	0x0000000000000100ULL /* Read only device */
#define	PSVC_DEV_RDWR		0x0000000000000400ULL /* read/write device */
#define	PSVC_DEV_FRU		0x0000000000000800ULL /* device is a FRU */
#define	PSVC_LOW_WARN		0x0000000000001000ULL
#define	PSVC_LOW_SHUT		0x0000000000002000ULL
#define	PSVC_HIGH_WARN		0x0000000000004000ULL
#define	PSVC_HIGH_SHUT		0x0000000000008000ULL
#define	PSVC_CONVERSION_TABLE	0x0000000000010000ULL /* Conversion table */
#define	PSVC_OPT_TEMP		0x0000000000020000ULL /* Optimal Temperature */
#define	PSVC_HW_LOW_SHUT	0x0000000000040000ULL
#define	PSVC_HW_HIGH_SHUT	0x0000000000080000ULL
#define	PSVC_FAN_DRIVE_PR	0x0001000000000000ULL
#define	PSVC_TEMP_DRIVEN	0x0002000000000000ULL /* Temperature driven */
#define	PSVC_SPEED_CTRL_PR	0x0004000000000000ULL /* Variable speed ctrl */
#define	PSVC_FAN_ON_OFF		0x0008000000000000ULL /* On/off fans */
#define	PSVC_CLOSED_LOOP_CTRL	0x0010000000000000ULL /* Closed loop control */
#define	PSVC_FAN_DRIVE_TABLE_PR 0x0010000000000000ULL /* oC to fan input tbl */
#define	PSVC_DIE_TEMP		0x0001000000000000ULL
#define	PSVC_AMB_TEMP		0x0002000000000000ULL
#define	PSVC_DIGI_SENSOR	0x0100000000000000ULL /* A to D converter */
#define	PSVC_BI_STATE		0x0001000000000000ULL
#define	PSVC_TRI_STATE		0x0002000000000000ULL
#define	PSVC_GREEN		0x0010000000000000ULL
#define	PSVC_AMBER		0x0020000000000000ULL
#define	PSVC_OUTPUT		0x0100000000000000ULL
#define	PSVC_INPUT		0x0200000000000000ULL
#define	PSVC_BIDIR		0x0400000000000000ULL
#define	PSVC_BIT_POS	0x0001000000000000ULL /* One bit per key positon */
#define	PSVC_VAL_POS	0x0002000000000000ULL /* One value per key position */
#define	PSVC_NORMAL_POS_AV	0x0010000000000000ULL
#define	PSVC_DIAG_POS_AV	0x0020000000000000ULL
#define	PSVC_LOCK_POS_AV	0x0040000000000000ULL
#define	PSVC_OFF_POS_AV		0x0080000000000000ULL
#define	PSVC_GPIO_PORT		0x0001000000000000ULL
#define	PSVC_GPIO_REG		0x0002000000000000ULL


/* LED colors */
#define	PSVC_LED_GREEN "GREEN"
#define	PSVC_LED_AMBER "AMBER"
#define	PSVC_LED_WHITE "WHITE"
#define	PSVC_LED_RED "RED"

/* States */
#define	PSVC_OK	"OK"
#define	PSVC_ERROR	"ERROR"
#define	PSVC_DEGRADED "DEGRADED"
#define	PSVC_STOPPED "STOPPED"
#define	PSVC_OVERHEATING "OVERHEATING"
#define	PSVC_OFF "OFF"
#define	PSVC_ON "ON"
#define	PSVC_HOTPLUGGED "HOTPLUGGED"	/* hotplugged, but not yet enabled */

/*
 * The Following States are for the Locking Object created by PSARC 2002/003
 */
#define	PSVC_LOCK_RUNNING "running"
#define	PSVC_LOCK_ENABLED "enabled"
#define	PSVC_LOCK_DISABLED "disabled"

/* LED states */
#define	PSVC_LED_OFF PSVC_OFF
#define	PSVC_LED_ON PSVC_ON
#define	PSVC_LED_SLOW_BLINK "SLOW_BLINK"
#define	PSVC_LED_FAST_BLINK "FAST_BLINK"

/* On/Off switch states */
#define	PSVC_SWITCH_OFF PSVC_OFF
#define	PSVC_SWITCH_ON PSVC_ON

/* Keyswitch positions */
#define	PSVC_OFF_POS PSVC_OFF
#define	PSVC_NORMAL_POS "NORMAL"
#define	PSVC_LOCKED_POS "LOCKED"
#define	PSVC_DIAG_POS "DIAG"

/* Fault strings */
#define	PSVC_NO_FAULT "NO_FAULT"
#define	PSVC_GEN_FAULT "DEVICE_FAULT"
#define	PSVC_PS_LLO_FLT "PS_LLO_FAULT"
#define	PSVC_PS_FAN_FLT "PS_FAN_FAULT"
#define	PSVC_PS_TEMP_FLT "PS_TEMP_FAULT"
#define	PSVC_PS_ISHARE_FLT "PS_ISHARE_FAULT"
#define	PSVC_PS_TYPE_FLT "PS_TYPE_FLT"
#define	PSVC_TEMP_LO_WARN "TEMP_LOW_WARNING"
#define	PSVC_TEMP_LO_SHUT "TEMP_LOW_SHUTDOWN"
#define	PSVC_TEMP_HI_WARN "TEMP_HIGH_WARNING"
#define	PSVC_TEMP_HI_SHUT "TEMP_HIGH_SHUTDOWN"

/*
 * When Adding Attributes be sure to add the string value of the
 * Attribute to attr_str_tab in psvc_objects_class.h
 */

/* Attribute names */
#define	PSVC_CLASS_ATTR				0	/* "_class" */
#define	PSVC_SUBCLASS_ATTR			1	/* "Subclass" */
#define	PSVC_PRESENCE_ATTR			2	/* "Presence" */
#define	PSVC_PREV_PRESENCE_ATTR			3	/* Previous-presence */
#define	PSVC_STATE_ATTR				4	/* "State" */
#define	PSVC_PREV_STATE_ATTR			5	/* "Previous-state" */
#define	PSVC_ENABLE_ATTR			6	/* "Enabled" */
#define	PSVC_FAULTID_ATTR			7	/* "FaultInformation" */
#define	PSVC_FEATURES_ATTR			8	/* "Features" */
#define	PSVC_LABEL_ATTR				9	/* "Label" */
#define	PSVC_FRUID_ATTR				10	/* "Fruid" */
#define	PSVC_INSTANCE_ATTR			11	/* "Instance" */
#define	PSVC_LED_COLOR_ATTR			12	/* "Led-color" */
#define	PSVC_LO_WARN_ATTR			13	/* "Lo-warn" */
#define	PSVC_LO_SHUT_ATTR			14	/* "Lo-shut" */
#define	PSVC_HI_WARN_ATTR			15	/* "Hi-warn" */
#define	PSVC_HI_SHUT_ATTR			16	/* "Hi-shut" */
#define	PSVC_OPTIMAL_TEMP_ATTR			17	/* "Opt-temp" */
#define	PSVC_HW_HI_SHUT_ATTR			18	/* "Hw-hi-shut" */
#define	PSVC_HW_LO_SHUT_ATTR			19	/* "Hw-lo-shut" */
#define	PSVC_SETPOINT_ATTR			20	/* "Setpoint" */
#define	PSVC_HYSTERESIS_ATTR			21	/* "Hysteresis" */
#define	PSVC_LOOPGAIN_ATTR			22	/* "Loopgain" */
#define	PSVC_LOOPBIAS_ATTR			23	/* "Loopbias" */
#define	PSVC_TEMP_DIFFERENTIAL_ATTR		24 /* "Temp_differential" */
#define	PSVC_TEMP_DIFFERENTIAL_INDEX_ATTR	25 /* Temp_differential_index */
#define	PSVC_SENSOR_VALUE_ATTR			26	/* "Sensor-value" */
#define	PSVC_GPIO_VALUE_ATTR			27	/* "Gpio-value" */
#define	PSVC_GPIO_BITS				28	/* "#Bits" */
#define	PSVC_CONTROL_VALUE_ATTR			29	/* "Control-value" */
#define	PSVC_LED_STATE_ATTR			30	/* "Led-state" */
#define	PSVC_SWITCH_STATE_ATTR			31	/* "Switch-state" */
#define	PSVC_PROBE_RESULT_ATTR			32	/* "Probe-result" */
#define	PSVC_TABLE_VALUE_ATTR			33	/* "Table_value" */
#define	PSVC_ASSOC_ID_ATTR			34	/* "Assoc_id" */
#define	PSVC_ASSOC_MATCHES_ATTR			35	/* "Assoc_matches" */
#define	PSVC_ADDR_SPEC_ATTR			36	/* "Addr-spec" */
#define	PSVC_OBJECT_ID_ATTR			37	/* "Object-id" */
#define	PSVC_LIT_COUNT_ATTR			38	/* "Led-lit-count" */
#define	PSVC_FRU_INFO_ATTR			39	/* "FRU-info" */

#define	PSVC_LED_IS_LOCATOR_ATTR		40	/* "IsLocator" */
#define	PSVC_LED_LOCATOR_NAME_ATTR		41	/* "LocatorName" */
#define	PSVC_LOCATOR_TRUE	"true"

/* PSVC_PRESENCE_ATTR values */
#define	PSVC_ABSENT 0
#define	PSVC_PRESENT 1

/* PSVC_ENABLE_ATTR values */
#define	PSVC_DISABLED 0
#define	PSVC_ENABLED 1

/* PSVC_PROBE_RESULT_ATTR values */
#define	PSVC_DEV_PROBE_SUCCESS PSVC_SUCCESS
#define	PSVC_DEV_PROBE_FAILED  PSVC_FAILURE

/* Size of fan temperature differential array */
#define	PSVC_MAXERRORS 2

/* Address specification macros */
#define	PSVC_VERSION 0		/* Current version */

#define	PSVC_VERSION_SHIFT 0
#define	PSVC_ACTIVE_LOW_SHIFT 7
#define	PSVC_BIT_NUM_SHIFT 4
#define	PSVC_INVERT_SHIFT 4
#define	PSVC_PORT_SHIFT 8
#define	PSVC_BITSHIFT_SHIFT 12
#define	PSVC_BYTEMASK_SHIFT 16
#define	PSVC_REG_SHIFT 24
#define	PSVC_TYPE_SHIFT 32
#define	PSVC_BUSADDR_SHIFT 40
#define	PSVC_BUSNUM_SHIFT 48
#define	PSVC_CNTLR_SHIFT 56

#define	PSVC_GET_VERSION(X) ((X >> PSVC_VERSION_SHIFT) & 0xF)
#define	PSVC_IS_ACTIVE_LOW(X) ((X >> PSVC_ACTIVE_LOW_SHIFT) & 0x1)
#define	PSVC_GET_BIT_NUM(X)  ((X >> PSVC_BIT_NUM_SHIFT) & 0x7)
#define	PSVC_HP_INVERT(X) (((X >> PSVC_INVERT_SHIFT) & 0x7) == 1)
#define	PSVC_GET_ASPEC_PORT(X) ((X >> PSVC_PORT_SHIFT) & 0xF)
#define	PSVC_GET_ASPEC_BITSHIFT(X) ((X >> PSVC_BITSHIFT_SHIFT) & 0xF)
#define	PSVC_GET_ASPEC_BYTEMASK(X) ((X >> PSVC_BYTEMASK_SHIFT) & 0xFF)
#define	PSVC_GET_ASPEC_REG(X) ((X >> PSVC_REG_SHIFT) & 0xFF)
#define	PSVC_GET_ASPEC_TYPE(X) ((X >> PSVC_TYPE_SHIFT) & 0xFF)
#define	PSVC_GET_ASPEC_BUSADDR(X) ((X >> PSVC_BUSADDR_SHIFT) & 0xFF)
#define	PSVC_GET_ASPEC_BUSNUM(X) ((X >> PSVC_BUSNUM_SHIFT) & 0xFF)
#define	PSVC_GET_ASPEC_CNTLR(X) ((X >> PSVC_CNTLR_SHIFT) & 0xFF)


/* Address spec device_types */
#define	PSVC_I2C_AT24		0
#define	PSVC_I2C_HPC3130	1
#define	PSVC_I2C_LM75		2
#define	PSVC_I2C_LTC1427	3
#define	PSVC_I2C_MAX1617	4
#define	PSVC_I2C_PCF8574	5
#define	PSVC_I2C_PCF8591	6
#define	PSVC_I2C_SSC050		7
#define	PSVC_I2C_TDA8444	8
#define	PSVC_I2C_SSC100		9

/* numbers of attempts for retrying requests over the I2C bus */
#define	PSVC_NUM_OF_RETRIES	5
#define	PSVC_THRESHOLD_COUNTER	5

/* Prototypes */
#ifndef LIBRARY_BUILD
int32_t psvc_init(psvc_opaque_t *);
int32_t psvc_fini(psvc_opaque_t);
int32_t psvc_get_attr(psvc_opaque_t, char *, int32_t, void *, ...);
int32_t psvc_set_attr(psvc_opaque_t, char *, int32_t, void *);
void psvcplugin_add_children(char *parent_path);
void psvcplugin_lookup(char *name, char *parent, picl_nodehdl_t *node);
#endif

/* FRU reading structure */
typedef struct {
	int32_t buf_start;
	char *buf;
	int32_t read_size;
}fru_info_t;

/* Mutex used for Daktari Fan speed reading */
extern pthread_mutex_t fan_mutex;

#ifdef	__cplusplus
}
#endif

#endif /* _PSVC_OBJECTS_H */
