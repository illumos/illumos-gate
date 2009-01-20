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

#ifndef	_PICLDEFS_H
#define	_PICLDEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PICL Tree paths
 */
#define	PLATFORM_PATH		"/platform"
#define	MEMORY_PATH		"/platform/memory"
#define	FRUTREE_PATH		"/frutree"
#define	PICL_FRUTREE_CHASSIS	"/frutree/chassis"

/*
 * PICL classes
 */
#define	PICL_CLASS_BYTE			"byte"
#define	PICL_CLASS_BLOCK		"block"
#define	PICL_CLASS_DISK			"disk"
#define	PICL_CLASS_CDROM		"cdrom"
#define	PICL_CLASS_FLOPPY		"floppy"
#define	PICL_CLASS_TAPE			"tape"
#define	PICL_CLASS_FABRIC		"fabric"
#define	PICL_CLASS_ATTACHMENT_POINT	"attachment-point"
#define	PICL_CLASS_DISPLAY		"display"
#define	PICL_CLASS_SERIAL		"serial"
#define	PICL_CLASS_PARALLEL		"parallel"
#define	PICL_CLASS_SEEPROM		"seeprom"
#define	PICL_CLASS_KEYBOARD		"keyboard"
#define	PICL_CLASS_MOUSE		"mouse"
#define	PICL_CLASS_MEMORY		"memory"
#define	PICL_CLASS_I2C			"i2c"
#define	PICL_CLASS_USB			"usb"
#define	PICL_CLASS_ISA			"isa"
#define	PICL_CLASS_DMA			"dma"
#define	PICL_CLASS_OBP_DEVICE		"obp-device"
#define	PICL_CLASS_TEMPERATURE_DEVICE	"temperature-device"
#define	PICL_CLASS_TEMPERATURE_SENSOR	"temperature-sensor"
#define	PICL_CLASS_TEMPERATURE_INDICATOR	"temperature-indicator"
#define	PICL_CLASS_VOLTAGE_INDICATOR	"voltage-indicator"
#define	PICL_CLASS_VOLTAGE_SENSOR	"voltage-sensor"
#define	PICL_CLASS_CURRENT_INDICATOR	"current-indicator"
#define	PICL_CLASS_CURRENT_SENSOR	"current-sensor"
#define	PICL_CLASS_LED			"led"
#define	PICL_CLASS_FAN			"fan"
#define	PICL_CLASS_FAN_CONTROL		"fan-control"
#define	PICL_CLASS_KEYSWITCH		"keyswitch"
#define	PICL_CLASS_EBUS			"ebus"
#define	PICL_CLASS_SYSTEM_CONTROLLER	"system-controller"
#define	PICL_CLASS_SERVICE_PROCESSOR	"service-processor"
#define	PICL_CLASS_HARDWARE_MONITOR	"hardware-monitor"
#define	PICL_CLASS_FLASHPROM		"flashprom"
#define	PICL_CLASS_SEEPROM		"seeprom"
#define	PICL_CLASS_FIREWIRE		"firewire"
#define	PICL_CLASS_I86CPUS		"cpus"
#define	PICL_CLASS_CPU			"cpu"
#define	PICL_CLASS_UPA			"upa"
#define	PICL_CLASS_PCI			"pci"
#define	PICL_CLASS_PCIEX		"pciex"
#define	PICL_CLASS_PMU			"pmu"
#define	PICL_CLASS_SOUND		"sound"
#define	PICL_CLASS_SBUS			"sbus"
#define	PICL_CLASS_SCSI			"scsi"
#define	PICL_CLASS_SCSI2		"scsi-2"
#define	PICL_CLASS_GPTWO		"gptwo"
#define	PICL_CLASS_JBUS			"jbus"
#define	PICL_CLASS_MEMORY		"memory"
#define	PICL_CLASS_MEMORY_SEGMENT	"memory-segment"
#define	PICL_CLASS_MEMORY_BANK		"memory-bank"
#define	PICL_CLASS_MEMORY_CONTROLLER	"memory-controller"
#define	PICL_CLASS_MEMORY_MODULE_GROUP	"memory-module-group"
#define	PICL_CLASS_MEMORY_MODULE	"memory-module"
#define	PICL_CLASS_FRU			"fru"
#define	PICL_CLASS_LOCATION		"location"
#define	PICL_CLASS_SECTION		"fru-section"
#define	PICL_CLASS_SEGMENT		"fru-segment"
#define	PICL_CLASS_PORT			"port"
#define	PICL_CLASS_WATCHDOG_CONTROLLER	"watchdog-controller"
#define	PICL_CLASS_WATCHDOG_TIMER	"watchdog-timer"
#define	PICL_CLASS_CHASSIS_SERIAL_NUM	"chassis-serial-number"
#define	PICL_CLASS_MULTIPATH		"multipath"

/*
 * Sun4v platforms do not create /frutree; instead they create
 * the /physical-platform subtree. The following is the list of
 * additional PICL classes that may be present in /physical-platform
 */
#define	PICL_CLASS_ALARM		"alarm"
#define	PICL_CLASS_BACKPLANE		"backplane"
#define	PICL_CLASS_BATTERY		"battery"
#define	PICL_CLASS_CHASSIS		"chassis"
#define	PICL_CLASS_CONTAINER		"container"
#define	PICL_CLASS_MODULE		"module"
#define	PICL_CLASS_OTHER		"other"
#define	PICL_CLASS_POWERSUPPLY		"power-supply"
#define	PICL_CLASS_RPM_INDICATOR	"rpm-indicator"
#define	PICL_CLASS_RPM_SENSOR		"rpm-sensor"
#define	PICL_CLASS_PRESENCE_INDICATOR	"presence-indicator"
#define	PICL_CLASS_INDICATOR		"indicator"
#define	PICL_CLASS_SENSOR		"sensor"
#define	PICL_CLASS_STACK		"stack"
#define	PICL_CLASS_UNKNOWN		"unknown"
#define	PICL_CLASS_HUMIDITY_SENSOR	"humidity-sensor"
#define	PICL_CLASS_HUMIDITY_INDICATOR	"humidity-indicator"

/*
 * Solaris driver property names
 */
#define	PICL_PROP_INSTANCE		"instance"
#define	PICL_PROP_BINDING_NAME		"binding-name"
#define	PICL_PROP_BUS_ADDR		"bus-addr"
#define	PICL_PROP_DRIVER_NAME		"driver-name"
#define	PICL_PROP_DEVFS_PATH		"devfs-path"
#define	PICL_PROP_STATUS		"status"

/*
 * PICL property names
 */
#define	PICL_PROP_PLATFORM_NAME			"PlatformName"
#define	PICL_PROP_SYSNAME			"OS-Name"
#define	PICL_PROP_NODENAME			"HostName"
#define	PICL_PROP_MACHINE			"PlatformGroup"
#define	PICL_PROP_RELEASE			"OS-Release"
#define	PICL_PROP_VERSION			"OS-Version"
#define	PICL_PROP_SIZE				"Size"
#define	PICL_PROP_ID				"ID"
#define	PICL_PROP_STATE				"State"
#define	PICL_PROP_PROCESSOR_TYPE		"ProcessorType"
#define	PICL_PROP_FPUTYPE			"FPUType"
#define	PICL_PROP_STATE_BEGIN			"StateBegin"
#define	PICL_PROP_FFB_BOARD_REV			"FFB-Board-Rev"
#define	PICL_PROP_FFB_FBRAM_VER			"FFB-FBRAM-Ver"
#define	PICL_PROP_FFB_DAC_VER			"FFB-DAC-Ver"
#define	PICL_PROP_UNIT_ADDRESS			"UnitAddress"
#define	PICL_PROP_SLOT				"Slot"
#define	PICL_PROP_DEVICE_ID			"DeviceID"
#define	PICL_PROP_TRANSFER_SIZE			"TransferSize"
#define	PICL_PROP_BASEADDRESS			"BaseAddress"
#define	PICL_PROP_INTERLEAVE_FACTOR		"InterleaveFactor"
#define	PICL_PROP_ADDRESSMASK			"AddressMask"
#define	PICL_PROP_ADDRESSMATCH			"AddressMatch"
#define	PICL_PROP_LABEL				"Label"
#define	PICL_PROP_CONTAINER			"Container"
#define	PICL_PROP_OFFSET			"Offset"
#define	PICL_PROP_LENGTH			"Length"
#define	PICL_PROP_PROTECTED			"Protected"
#define	PICL_PROP_NUM_SEGMENTS			"#Segments"
#define	PICL_PROP_DESCRIPTOR			"Descriptor"
#define	PICL_PROP_PACKET_TABLE			"PacketTable"
#define	PICL_PROP_NUM_TAGS			"#Packets"
#define	PICL_PROP_ADD_SEGMENT			"AddSegment"
#define	PICL_PROP_DELETE_PACKET			"DeletePacket"
#define	PICL_PROP_ADD_PACKET			"AddPacket"
#define	PICL_PROP_DELETE_SEGMENT		"DeleteSegment"
#define	PICL_PROP_TAG				"Tag"
#define	PICL_PROP_PAYLOAD			"Payload"
#define	PICL_PROP_FRUDATA_AVAIL			"FRUDataAvailable"
#define	PICL_PROP_DEVICEPATH			"FRUDevicePath"
#define	PICL_PROP_FAN_SPEED			"Speed"
#define	PICL_PROP_FAN_SPEED_UNIT		"SpeedUnit"
#define	PICL_PROP_TEMPERATURE			"Temperature"
#define	PICL_PROP_CPU_AMB_TEMP			"AmbientTemperature"
#define	PICL_PROP_CPU_DIE_TEMP			"Temperature"
#define	PICL_PROP_IS_LOCATOR			"IsLocator"
#define	PICL_PROP_LOCATOR_NAME			"LocatorName"
#define	PICL_PROP_DEVICES			"Devices"
#define	PICL_PROP_ENV				"Environment"
#define	PICL_PROP_COLOR				"Color"
#define	PICL_PROP_SC_HANDLE			"SC_handle"
#define	PICL_PROP_FRU_TYPE			"FRUType"
#define	PICL_PROP_SLOT_TYPE			"SlotType"
#define	PICL_PROP_OPERATIONAL_STATUS		"OperationalStatus"
#define	PICL_PROP_VOLTAGE			"Voltage"
#define	PICL_PROP_CURRENT			"Current"
#define	PICL_PROP_CLASS				"Class"
#define	PICL_PROP_CONDITION			"Condition"
#define	PICL_REFPROP_LOC_PARENT			"_location_parent"
#define	PICL_REFPROP_FRU_PARENT			"_fru_parent"
#define	PICL_REFPROP_PORT_PARENT		"_port_parent"
#define	PICL_REFPROP_MEMORY_MODULE_GROUP	"_memory-module-group_"
#define	PICL_REFPROP_MEMORY_MODULE		"_memory-module_"
#define	PICL_REFPROP_SEEPROM_SRC		"_seeprom_source"
#define	PICL_PROP_DEVICE_TYPE			"device_type"
#define	PICL_PROP_PROBE_PATH			"PdevProbePath"
#define	PICL_PROP_WATCHDOG_ACTION		"WdAction"
#define	PICL_PROP_WATCHDOG_TIMEOUT		"WdTimeout"
#define	PICL_PROP_WATCHDOG_OPERATION		"WdOp"
#define	PICL_PROP_STATUS_TIME			"StatusTime"
#define	PICL_PROP_CONDITION			"Condition"
#define	PICL_PROP_CONDITION_TIME		"ConditionTime"
#define	PICL_PROP_CHASSIS_TYPE			"ChassisType"
#define	PICL_PROP_GEO_ADDR			"GeoAddr"
#define	PICL_PROP_ADMIN_LOCK			"AdminLock"
#define	PICL_PROP_PORT_TYPE			"PortType"
#define	PICL_PROP_SERIAL_NUMBER			"SerialNumber"

#define	PICL_UNITADDR_LEN_MAX		256

/*
 * Additional PICL properties for Sun4v platforms
 */
#define	PICL_PROP_BATTERY_STATUS		"BatteryStatus"
#define	PICL_PROP_EXPECTED			"Expected"
#define	PICL_PROP_FW_REVISION			"FW-version"
#define	PICL_PROP_HW_REVISION			"HW-version"
#define	PICL_PROP_IS_REPLACEABLE		"Replaceable"
#define	PICL_PROP_IS_HOT_SWAPPABLE		"HotSwappable"
#define	PICL_PROP_IS_FRU			"FRU"
#define	PICL_PROP_PHYS_DESCRIPTION		"Description"
#define	PICL_PROP_SPEED				"Speed"
#define	PICL_PROP_MFG_NAME			"MfgName"
#define	PICL_PROP_MODEL_NAME			"ModelName"
#define	PICL_PROP_SENSOR_VALUE			"SensorValue"
#define	PICL_PROP_BASE_UNITS			"BaseUnits"
#define	PICL_PROP_EXPONENT			"Exponent"
#define	PICL_PROP_RATE_UNITS			"RateUnits"
#define	PICL_PROP_HUMIDITY			"Humidity"

/*
 * Various threshold property names
 */
#define	PICL_PROP_LOW_POWER_OFF			"LowPowerOffThreshold"
#define	PICL_PROP_LOW_SHUTDOWN			"LowShutdownThreshold"
#define	PICL_PROP_LOW_WARNING			"LowWarningThreshold"
#define	PICL_PROP_TARGET_TEMPERATURE		"TargetTemperature"
#define	PICL_PROP_HIGH_POWER_OFF		"HighPowerOffThreshold"
#define	PICL_PROP_HIGH_SHUTDOWN			"HighShutdownThreshold"
#define	PICL_PROP_HIGH_WARNING			"HighWarningThreshold"

/*
 * OBP property names
 */
#define	OBP_PROP_UPA_PORTID		"upa-portid"
#define	OBP_PROP_PORTID			"portid"
#define	OBP_PROP_CPUID			"cpuid"
#define	OBP_PROP_SIZE_CELLS		"#size-cells"
#define	OBP_PROP_ADDRESS_CELLS		"#address-cells"

/*
 * PICL Event names
 */
#define	PICLEVENT_SYSEVENT_DEVICE_ADDED		"sysevent-device-added"
#define	PICLEVENT_SYSEVENT_DEVICE_REMOVED	"sysevent-device-removed"
#define	PICLEVENT_DR_AP_STATE_CHANGE		"dr-ap-state-change"
#define	PICLEVENT_MC_ADDED			"picl-memory-controller-added"
#define	PICLEVENT_MC_REMOVED			"picl-memory-controller-removed"
#define	PICLEVENT_STATE_CHANGE			"picl-state-change"
#define	PICLEVENT_CONDITION_CHANGE		"picl-condition-change"
#define	PICLEVENT_CPU_STATE_CHANGE		"picl-cpu-node-state-change"
#define	PICLEVENT_DR_REQ			"dr-req"

/*
 * Contract Private
 */
#define	PICL_FRU_ADDED			"picl-fru-added" /* PSARC/2000/546 */
#define	PICL_FRU_REMOVED		"picl-fru-removed" /* PSARC/2000/546 */

/*
 * PICL Event Argument Names
 */
#define	PICLEVENTARG_DEVFS_PATH		"devfs-path"
#define	PICLEVENTARG_AP_ID		"ap-id"
#define	PICLEVENTARG_HINT		"hint"
#define	PICLEVENTARG_NODEHANDLE		"picl-nodehandle"
#define	PICLEVENTARG_DR_REQ_TYPE	"req-type"
#define	PICLEVENTARG_CPU_EV_TYPE	"cpu-ev-type"
#define	PICLEVENTARG_STATE		"State"
#define	PICLEVENTARG_LAST_STATE		"LastState"
#define	PICLEVENTARG_CONDITION		"Condition"

/*
 * PICL Label Names
 */
#define	PICL_PROPVAL_LABEL_DIE		"Die"
#define	PICL_PROPVAL_LABEL_AMBIENT	"Ambient"

/*
 * Contract Private
 */
#define	PICLEVENTARG_FRUHANDLE		"picl-fru-handle" /* PSARC/2000/546 */
#define	PICLEVENTARG_PARENTHANDLE	"picl-parent-handle" /* 2000/546 */

/*
 * The following are PICL PRIVATE event argument names
 */
#define	PICLEVENTARG_EVENT_NAME		"piclevent-name"
#define	PICLEVENTARG_DATA_TYPE		"piclevent-data-type"

/*
 * The following are values of piclevent-data-type (PRIVATE)
 */
#define	PICLEVENTARG_PICLEVENT_DATA	"piclevent-data"

/* These values are used for PICLEVENT_CPU_STATE_CHANGE event */
#define	PICLEVENTARGVAL_ONLINE		"Online"
#define	PICLEVENTARGVAL_OFFLINE		"Offline"

/*
 * These values are used for PICLEVENT_STATE_CHANGE,
 * PICLEVENT_CONDITION_CHANGE event
 */
#define	PICLEVENTARGVAL_UNKNOWN		"unknown"
#define	PICLEVENTARGVAL_OK		"ok"
#define	PICLEVENTARGVAL_FAILING		"failing"
#define	PICLEVENTARGVAL_FAILED		"failed"
#define	PICLEVENTARGVAL_TESTING		"testing"
#define	PICLEVENTARGVAL_UNUSABLE	"unusable"
#define	PICLEVENTARGVAL_CONNECTING	"connecting"
#define	PICLEVENTARGVAL_DISCONNECTING	"disconnecting"
#define	PICLEVENTARGVAL_CONNECTED	"connected"
#define	PICLEVENTARGVAL_DISCONNECTED	"disconnected"
#define	PICLEVENTARGVAL_EMPTY		"empty"
#define	PICLEVENTARGVAL_CONFIGURED	"configured"
#define	PICLEVENTARGVAL_UNCONFIGURED	"unconfigured"
#define	PICLEVENTARGVAL_CONFIGURING	"configuring"
#define	PICLEVENTARGVAL_UNCONFIGURING	"unconfiguring"
#define	PICLEVENTARGVAL_UP		"up"
#define	PICLEVENTARGVAL_DOWN		"down"

/* PSARC 2003/163 */
#define	PICLEVENTARGVAL_SENSOR_COND_WARNING	"warning"
#define	PICLEVENTARGVAL_SENSOR_COND_SHUTDOWN	"shutdown"

/* PSARC 2003/231 */
/* watchdog property values */
#define	PICL_PROPVAL_WD_OP_ARM		"arm"
#define	PICL_PROPVAL_WD_OP_DISARM	"disarm"
#define	PICL_PROPVAL_WD_ACTION_NONE	"none"
#define	PICL_PROPVAL_WD_ACTION_REBOOT	"reboot"
#define	PICL_PROPVAL_WD_ACTION_ALARM	"alarm"
#define	PICL_PROPVAL_WD_ACTION_RESET	"reset"
#define	PICL_PROPVAL_WD_STATE_ARMED	"armed"
#define	PICL_PROPVAL_WD_STATE_DISARMED	"disarmed"
#define	PICL_PROPVAL_WD_STATE_EXPIRED	"expired"

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLDEFS_H */
