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

#ifndef	_PICLOIDS_H
#define	_PICLOIDS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * IETF OIDs (not all are used by PICL)
 */
#define	OID_ISO				"1"
#define	OID_ORG				OID_ISO ".3"
#define	OID_DOD				OID_ORG ".6"
#define	OID_INTERNET			OID_DOD ".1"

#define	OID_PRIVATE			OID_INTERNET ".4"
#define	OID_ENTERPRISES			OID_PRIVATE ".1"
#define	OID_SUN				OID_ENTERPRISES ".42"

#define	OID_MGMT			OID_INTERNET ".2"
#define	OID_MIB2			OID_MGMT ".1"
#define	OID_entityMIB			OID_MIB2 ".47"
#define	OID_entityMIBObjects		OID_entityMIB ".1"

#define	OID_entityPhysical		OID_entityMIBObjects ".1"
#define	OID_entPhysicalTable		OID_entityPhysical ".1"
#define	OID_entPhysicalEntry		OID_entPhysicalTable ".1"

#define	OID_entPhysicalIndex		OID_entPhysicalEntry ".1"
#define	OID_entPhysicalDescr		OID_entPhysicalEntry ".2"
#define	OID_entPhysicalVendorType	OID_entPhysicalEntry ".3"
#define	OID_entPhysicalContainedIn	OID_entPhysicalEntry ".4"
#define	OID_entPhysicalClass		OID_entPhysicalEntry ".5"
#define	OID_entPhysicalParentRelPos	OID_entPhysicalEntry ".6"
#define	OID_entPhysicalName		OID_entPhysicalEntry ".7"
#define	OID_entPhysicalHardwareRev	OID_entPhysicalEntry ".8"
#define	OID_entPhysicalFirmwareRev	OID_entPhysicalEntry ".9"
#define	OID_entPhysicalSoftwareRev	OID_entPhysicalEntry ".10"
#define	OID_entPhysicalSerialNum	OID_entPhysicalEntry ".11"
#define	OID_entPhysicalMfgName		OID_entPhysicalEntry ".12"
#define	OID_entPhysicalModelName	OID_entPhysicalEntry ".13"
#define	OID_entPhysicalAlias		OID_entPhysicalEntry ".14"
#define	OID_entPhysicalAssetID		OID_entPhysicalEntry ".15"
#define	OID_entPhysicalIsFRU		OID_entPhysicalEntry ".16"

/*
 * Conceptual row change time for handling hotplug/hotswap events
 */
#define	OID_entityGeneral		OID_entityMIBObjects ".4"
#define	OID_entLastChangeTime		OID_entityGeneral ".1"

/*
 * Sun Platform MIB OIDs used by PICL
 */
#define	OID_products			OID_SUN ".2"
#define	OID_sunFire			OID_products ".70"
#define	OID_sunPlatMIB			OID_sunFire ".101"
#define	OID_sunPlatMIBObjects		OID_sunPlatMIB ".1"
#define	OID_sunPlatMIBPhysicalObjects	OID_sunPlatMIBObjects ".1"

/*
 * Equipment Table
 */
#define	OID_sunPlatEquipmentTable	OID_sunPlatMIBPhysicalObjects ".2"
#define	OID_sunPlatEquipmentEntry	OID_sunPlatEquipmentTable ".1"
#define	OID_sunPlatEquipmentOperationalState	\
					OID_sunPlatEquipmentEntry ".2"

/*
 * Equipment Holder Table
 */
#define	OID_sunPlatEquipmentHolderTable	OID_sunPlatMIBPhysicalObjects ".3"
#define	OID_sunPlatEquipmentHolderEntry	OID_sunPlatEquipmentHolderTable ".1"
#define	OID_sunPlatEquipmentHolderAcceptableTypes	\
					OID_sunPlatEquipmentHolderEntry ".2"

/*
 * Circuit Pack Table
 */
#define	OID_sunPlatCircuitPackTable	OID_sunPlatMIBPhysicalObjects ".4"
#define	OID_sunPlatCircuitPackEntry	OID_sunPlatCircuitPackTable ".1"
#define	OID_sunPlatCircuitPackReplaceable	\
					OID_sunPlatCircuitPackEntry ".3"
#define	OID_sunPlatCircuitPackHotSwappable	\
					OID_sunPlatCircuitPackEntry ".4"

/*
 * Physical Class Table
 */
#define	OID_sunPlatPhysicalTable	OID_sunPlatMIBPhysicalObjects ".5"
#define	OID_sunPlatPhysicalEntry	OID_sunPlatPhysicalTable ".1"
#define	OID_sunPlatPhysicalClass	OID_sunPlatPhysicalEntry ".1"

/*
 * Sensor Table
 */
#define	OID_sunPlatSensorTable		OID_sunPlatMIBPhysicalObjects ".6"
#define	OID_sunPlatSensorEntry		OID_sunPlatSensorTable ".1"
#define	OID_sunPlatSensorClass		OID_sunPlatSensorEntry ".1"
#define	OID_sunPlatSensorType		OID_sunPlatSensorEntry ".2"

/*
 * Binary Sensor Table
 */
#define	OID_sunPlatBinarySensorTable	OID_sunPlatMIBPhysicalObjects ".7"
#define	OID_sunPlatBinarySensorEntry	OID_sunPlatBinarySensorTable ".1"

#define	OID_sunPlatBinarySensorCurrent	OID_sunPlatBinarySensorEntry ".1"
#define	OID_sunPlatBinarySensorExpected	OID_sunPlatBinarySensorEntry ".2"
#define	OID_sunPlatBinarySensorInterpretTrue	\
					OID_sunPlatBinarySensorEntry ".3"
#define	OID_sunPlatBinarySensorInterpretFalse	\
					OID_sunPlatBinarySensorEntry ".4"

/*
 * Numeric Sensor Table
 */
#define	OID_sunPlatNumericSensorTable	OID_sunPlatMIBPhysicalObjects ".8"
#define	OID_sunPlatNumericSensorEntry	OID_sunPlatNumericSensorTable ".1"
#define	OID_sunPlatNumericSensorCurrent	OID_sunPlatNumericSensorEntry ".4"
#define	OID_sunPlatNumericSensorBaseUnits	\
					OID_sunPlatNumericSensorEntry ".1"
#define	OID_sunPlatNumericSensorExponent	\
					OID_sunPlatNumericSensorEntry ".2"
#define	OID_sunPlatNumericSensorRateUnits	\
					OID_sunPlatNumericSensorEntry ".3"
#define	OID_sunPlatNumericSensorLowerThresholdNonCritical	\
					OID_sunPlatNumericSensorEntry ".8"
#define	OID_sunPlatNumericSensorUpperThresholdNonCritical	\
					OID_sunPlatNumericSensorEntry ".9"
#define	OID_sunPlatNumericSensorLowerThresholdCritical	\
					OID_sunPlatNumericSensorEntry ".10"
#define	OID_sunPlatNumericSensorUpperThresholdCritical	\
					OID_sunPlatNumericSensorEntry ".11"
#define	OID_sunPlatNumericSensorLowerThresholdFatal	\
					OID_sunPlatNumericSensorEntry ".12"
#define	OID_sunPlatNumericSensorUpperThresholdFatal	\
					OID_sunPlatNumericSensorEntry ".13"
#define	OID_sunPlatNumericSensorEnabledThresholds	\
					OID_sunPlatNumericSensorEntry ".15"

/*
 * Alarm Table
 */
#define	OID_sunPlatAlarmTable		OID_sunPlatMIBPhysicalObjects ".12"
#define	OID_sunPlatAlarmEntry		OID_sunPlatAlarmTable ".1"
#define	OID_sunPlatAlarmType		OID_sunPlatAlarmEntry ".1"
#define	OID_sunPlatAlarmState		OID_sunPlatAlarmEntry ".2"

/*
 * Power Supply Table
 */
#define	OID_sunPlatPowerSupplyTable	OID_sunPlatMIBPhysicalObjects ".14"
#define	OID_sunPlatPowerSupplyEntry	OID_sunPlatPowerSupplyTable ".1"
#define	OID_sunPlatPowerSupplyClass	OID_sunPlatPowerSupplyEntry ".1"

/*
 * Battery Table
 */
#define	OID_sunPlatBatteryTable		OID_sunPlatMIBPhysicalObjects ".15"
#define	OID_sunPlatBatteryEntry		OID_sunPlatBatteryTable ".1"
#define	OID_sunPlatBatteryStatus	OID_sunPlatBatteryEntry ".1"

/*
 * Integer enumeration classes used by PICL
 */
typedef enum {
	ST_TRUE = 1,
	ST_FALSE = 2
} snmp_truthval_t;

/*
 * Note that the truth values could be much longer than the length
 * of the strings "true" or "false", since we actuallly interpret them
 * using InterpretTrue and InterpretFalse values in the MIB. Currently
 * we limit them to be 32 (see MAX_TRUTHVAL_LEN definition below)
 */
#define	STR_ST_TRUE	"true"
#define	STR_ST_FALSE	"false"

/* entPhysicalClass */
typedef enum {
	SPC_OTHER = 1,
	SPC_UNKNOWN = 2,
	SPC_CHASSIS = 3,
	SPC_BACKPLANE = 4,
	SPC_CONTAINER = 5,
	SPC_POWERSUPPLY = 6,
	SPC_FAN = 7,
	SPC_SENSOR = 8,
	SPC_MODULE = 9,
	SPC_PORT = 10,
	SPC_STACK = 11
} snmp_physical_class_t;

/* sunPlatEquipmentOperationalState */
typedef enum {
	SSOS_DISABLED = 1,
	SSOS_ENABLED = 2
} snmp_sunplat_op_state_t;

/*
 * Update MAX_OPSTATE_LEN below if these strings are changed
 */
#define	STR_SSOS_DISABLED	"disabled"
#define	STR_SSOS_ENABLED	"enabled"

/* sunPlatPhysicalClass */
typedef enum {
	SSPC_OTHER = 1,
	SSPC_ALARM = 2,
	SSPC_WATCHDOG = 3
} snmp_sunplat_phys_class_t;

/* sunPlatSensorClass */
typedef enum {
	SSSC_BINARY = 1,
	SSSC_NUMERIC = 2,
	SSSC_DISCRETE = 3
} snmp_sunplat_sensor_class_t;

/* sunPlatSensorType */
typedef enum {
	SSST_OTHER = 1,
	SSST_UNKNOWN = 2,
	SSST_TEMPERATURE = 3,
	SSST_VOLTAGE = 4,
	SSST_CURRENT = 5,
	SSST_TACHOMETER = 6,
	SSST_COUNTER = 7,
	SSST_SWITCH = 8,
	SSST_LOCK = 9,
	SSST_HUMIDITY = 10,
	SSST_SMOKE_DETECTION = 11,
	SSST_PRESENCE = 12,
	SSST_AIRFLOW = 13
} snmp_sunplat_sensor_type_t;

/* sunPlatAlarmType */
typedef enum {
	SSAT_OTHER = 1,
	SSAT_AUDIBLE = 2,
	SSAT_VISIBLE = 3,
	SSAT_MOTION = 4,
	SSAT_SWITCH = 5
} snmp_sunplat_alarm_type_t;

/* sunPlatAlarmState */
typedef enum {
	SSAS_UNKNOWN = 1,
	SSAS_OFF = 2,
	SSAS_STEADY = 3,
	SSAS_ALTERNATING = 4
} snmp_sunplat_alarm_state_t;

/*
 * Update MAX_ALARMSTATE_LEN below if these strings are changed
 */
#define	STR_SSAS_UNKNOWN	"unknown"
#define	STR_SSAS_OFF		"off"
#define	STR_SSAS_STEADY		"steady"
#define	STR_SSAS_ALTERNATING	"alternating"

/*
 * Bit masks for the sunPlatNumericSensorEnabledThresholds
 */
#define	LOWER_NON_CRITICAL	0x80
#define	UPPER_NON_CRITICAL	0x40
#define	LOWER_CRITICAL		0x20
#define	UPPER_CRITICAL		0x10
#define	LOWER_FATAL		0x08
#define	UPPER_FATAL		0x04

/*
 * sunPlatPowerSupplyClass
 */
typedef enum {
	SSPSC_OTHER = 1,
	SSPSC_POWERSUPPLY = 2,
	SSPSC_BATTERY = 3
} snmp_sunplat_power_supply_class_t;

/*
 * sunPlatBatteryStatus
 */
typedef enum {
	SSBS_OTHER = 1,
	SSBS_UNKNOWN = 2,
	SSBS_FULLYCHARGED = 3,
	SSBS_LOW = 4,
	SSBS_CRITICAL = 5,
	SSBS_CHARGING = 6,
	SSBS_CHARGING_AND_LOW = 7,
	SSBS_CHARGING_AND_HIGH = 8,
	SSBS_CHARGING_AND_CRITICAL = 9,
	SSBS_UNDEFINED = 10,
	SSBS_PARTIALLY_CHARGED = 11
} snmp_sunplat_battery_status_t;

/*
 * Update MAX_BATTERYSTATUS_LEN below if these strings are changed
 */
#define	STR_SSBS_OTHER			"Other"
#define	STR_SSBS_UNKNOWN		"Unknown"
#define	STR_SSBS_FULLYCHARGED		"Fully Charged"
#define	STR_SSBS_LOW			"Low"
#define	STR_SSBS_CRITICAL		"Critical"
#define	STR_SSBS_CHARGING		"Charging"
#define	STR_SSBS_CHARGING_AND_LOW	"Charging and Low"
#define	STR_SSBS_CHARGING_AND_HIGH	"Charging and High"
#define	STR_SSBS_CHARGING_AND_CRITICAL	"Charging and Critical"
#define	STR_SSBS_UNDEFINED		"Undefined"
#define	STR_SSBS_PARTIALLY_CHARGED	"Partially Charged"

/*
 * Max limits of all volatiles
 */
#define	MAX_OPSTATE_LEN			10
#define	MAX_ALARMSTATE_LEN		12
#define	MAX_TRUTHVAL_LEN		32
#define	MAX_BATTERYSTATUS_LEN		32

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLOIDS_H */
