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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FRAMEWORK_SES_H
#define	_FRAMEWORK_SES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Node properties
 */
#define	SES_PROP_ELEMENT_TYPE		"ses-element-type"
typedef enum ses2_element_type {
	SES_ET_UNSPECIFIED = 0,
	SES_ET_DEVICE = 0x1,
	SES_ET_POWER_SUPPLY = 0x2,
	SES_ET_COOLING = 0x3,
	SES_ET_TEMPERATURE_SENSOR = 0x4,
	SES_ET_DOOR_LOCK = 0x5,
	SES_ET_AUDIBLE_ALARM = 0x6,
	SES_ET_ESC_ELECTRONICS = 0x7,
	SES_ET_SCC_ELECTRONICS = 0x8,
	SES_ET_NONVOLATILE_CACHE = 0x9,
	SES_ET_INVALID_OPERATION_REASON = 0xa,
	SES_ET_UPS = 0xb,
	SES_ET_DISPLAY = 0xc,
	SES_ET_KEY_PAD_ENTRY = 0xd,
	SES_ET_ENCLOSURE = 0xe,
	SES_ET_SCSI_PORT_XCVR = 0xf,
	SES_ET_LANGUAGE = 0x10,
	SES_ET_COMMUNICATION_PORT = 0x11,
	SES_ET_VOLTAGE_SENSOR = 0x12,
	SES_ET_CURRENT_SENSOR = 0x13,
	SES_ET_SCSI_TARGET_PORT = 0x14,
	SES_ET_SCSI_INITIATOR_PORT = 0x15,
	SES_ET_SIMPLE_SUBENCLOSURE = 0x16,
	SES_ET_ARRAY_DEVICE = 0x17,
	SES_ET_SAS_EXPANDER = 0x18,
	SES_ET_SAS_CONNECTOR = 0x19
} ses2_element_type_t;

#define	SES_PROP_STATUS_CODE		"ses-status-code"
typedef enum ses_element_status_code {
	SES_ESC_UNSUPPORTED = 0,
	SES_ESC_OK = 1,
	SES_ESC_CRITICAL = 2,
	SES_ESC_NONCRITICAL = 3,
	SES_ESC_UNRECOVERABLE = 4,
	SES_ESC_NOT_INSTALLED = 5,
	SES_ESC_UNKNOWN = 6,
	SES_ESC_UNAVAIL = 7,
	SES_ESC_NO_ACCESS = 8
} ses_element_status_code_t;

#define	SES_PROP_ELEMENT_CLASS_INDEX	"ses-element-class-index" /* U64 */
#define	SES_PROP_ELEMENT_INDEX		"ses-element-index"	/* U64 */
#define	SES_PROP_BAY_NUMBER		"ses-bay-number"	/* U64 */
#define	SES_PROP_PRDFAIL		"ses-failure-predicted"
#define	SES_PROP_SWAP			"ses-swapped"
#define	SES_PROP_DISABLED		"ses-disabled"
#define	SES_PROP_IDENT			"ses-identify"
#define	SES_PROP_WARN			"ses-warning"
#define	SES_PROP_FAIL			"ses-failed"
#define	SES_PROP_WARN_REQ		"ses-warning-indicator-requested"
#define	SES_PROP_FAIL_REQ		"ses-failure-indicator-requested"
#define	SES_PROP_REPORT			"ses-reported-via"
#define	SES_PROP_RMV			"ses-ready-to-remove"
#define	SES_PROP_OFF			"ses-off"
#define	SES_PROP_REQUESTED_ON		"ses-requested-on"
#define	SES_PROP_CLASS_DESCRIPTION	"ses-class-description"	/* S */
#define	SES_PROP_DESCRIPTION		"ses-description"	/* S */
#define	SES_PROP_HOT_SWAP		"ses-hot-swappable"

#define	SES_PROP_CRIT_OVER		"ses-critical-over"
#define	SES_PROP_CRIT_UNDER		"ses-critical-under"
#define	SES_PROP_WARN_OVER		"ses-warning-over"
#define	SES_PROP_WARN_UNDER		"ses-warning-under"

#define	SES_FC_PROP_NODE_NAME		"ses-fc-node-name"	/* U64 */
#define	SES_FC_PROP_LOOP_POS		"ses-fc-loop-position"	/* U64 */
#define	SES_FC_PROP_REQ_HARDADDR	"ses-fc-requested-hard-address"
#define	SES_FC_PROP_N_PORT_ID		"ses-fc-n_port-identifier" /* U64 */
#define	SES_FC_PROP_N_PORT_NAME		"ses-fc-n_port-name"	/* U64 */
#define	SES_FC_PROP_PORTS		"ses-fc-ports"		/* NVA */

#define	SES_SAS_PROP_DEVICE_TYPE	"ses-sas-device-type"	/* U64 */
/*
 * SAS2r11 7.8.2 Table 123
 */
typedef enum sas_device_type {
	SAS_DT_END_DEVICE = 0x01,
	SAS_DT_EXPANDER = 0x02,
	SAS_DT_LEGACY_EXPANDER = 0x3
} sas_device_type_t;

#define	SES_SAS_PROP_SMPI_PORT		"ses-sas-smp-initiator-port"
#define	SES_SAS_PROP_STPI_PORT		"ses-sas-stp-initiator-port"
#define	SES_SAS_PROP_SSPI_PORT		"ses-sas-ssp-initiator-port"
#define	SES_SAS_PROP_SATA_DEVICE	"ses-sas-sata-device"
#define	SES_SAS_PROP_SMPT_PORT		"ses-sas-smp-target-port"
#define	SES_SAS_PROP_STPT_PORT		"ses-sas-stp-target-port"
#define	SES_SAS_PROP_SSPT_PORT		"ses-sas-ssp-target-port"
#define	SES_SAS_PROP_ATT_ADDR		"ses-sas-attached-address" /* U64 */
#define	SES_SAS_PROP_ADDR		"ses-sas-address"	/* U64 */
#define	SES_SAS_PROP_PHY_ID		"ses-sas-phy-identifier" /* U64 */
#define	SES_SAS_PROP_PHYS		"ses-sas-phys"		/* NVA */
#define	SES_PROP_CE_IDX			"ses-connector-element-index" /* U64 */
#define	SES_PROP_OE_IDX			"ses-other-element-index" /* U64 */

#define	SES_PROP_THRESH_CRIT_HI		"ses-high-critical-threshold" /* U64 */
#define	SES_PROP_THRESH_WARN_HI		"ses-high-warning-threshold" /* U64 */
#define	SES_PROP_THRESH_CRIT_LO		"ses-low-critical-threshold" /* U64 */
#define	SES_PROP_THRESH_WARN_LO		"ses-low-warning-threshold" /* U64 */

/*
 * Audible Alarm properties
 */
#define	SES_ALARM_PROP_UNRECOV		"ses-indicating-unrecoverable"
#define	SES_ALARM_PROP_CRIT		"ses-indicating-critical"
#define	SES_ALARM_PROP_NONCRIT		"ses-indicating-noncritical"
#define	SES_ALARM_PROP_INFO		"ses-indicating-informational"
#define	SES_ALARM_PROP_REMIND		"ses-reminder-mode"
#define	SES_ALARM_PROP_MUTED		"ses-muted"
#define	SES_ALARM_PROP_RQST_MUTE	"ses-mute-requested"

/*
 * Nonvolatile Cache properties
 */
#define	SES_CACHE_PROP_SIZE		"ses-cache-size"	/* U64 */

/*
 * Cooling Element properties
 */
#define	SES_COOLING_PROP_FAN_SPEED	"ses-fan-speed"		/* U64 */
#define	SES_COOLING_PROP_SPEED_CODE	"ses-fan-speed-code"	/* U64 */
typedef enum ses_cooling_fan_speed {
	SES_COOLING_FAN_SPEED_STOPPED = 0,
	SES_COOLING_FAN_SPEED_LOWEST = 1,
	SES_COOLING_FAN_SPEED_LOWER = 2,
	SES_COOLING_FAN_SPEED_LOW = 3,
	SES_COOLING_FAN_SPEED_INTERMEDIATE = 4,
	SES_COOLING_FAN_SPEED_HIGH = 5,
	SES_COOLING_FAN_SPEED_HIGHER = 6,
	SES_COOLING_FAN_SPEED_HIGHEST = 7
} ses_cooling_fan_speed_t;

/*
 * Device/Array Device properties
 */
#define	SES_DEV_PROP_SLOT_ADDR		"ses-slot-address"	/* U64 */
#define	SES_DEV_PROP_PRDFAIL		"ses-failure-predicted"
#define	SES_DEV_PROP_READY_TO_INSERT	"ses-ready-to-insert"
#define	SES_DEV_PROP_ENC_BYP_A		"ses-enclosure-bypassed-a"
#define	SES_DEV_PROP_ENC_BYP_B		"ses-enclosure-bypassed-b"
#define	SES_DEV_PROP_DO_NOT_REMOVE	"ses-do-not-remove"
#define	SES_DEV_PROP_APP_BYP_A		"ses-app-client-bypassed-a"
#define	SES_DEV_PROP_APP_BYP_B		"ses-app-client-bypassed-b"
#define	SES_DEV_PROP_DEV_BYP_A		"ses-device-bypassed-a"
#define	SES_DEV_PROP_DEV_BYP_B		"ses-device-bypassed-b"
#define	SES_DEV_PROP_BYP_A		"ses-bypassed-a"
#define	SES_DEV_PROP_BYP_B		"ses-bypassed-b"
#define	SES_DEV_PROP_FAULT_RQSTD	"ses-fault-requested"
#define	SES_DEV_PROP_FAULT_SENSED	"ses-fault-sensed"
#define	SES_DEV_PROP_SAS_NOT_ALL_PHYS	"ses-sas-not-all-phys"

/* Control only */
#define	SES_DEV_PROP_REQ_MISSING	"ses-request-missing"
#define	SES_DEV_PROP_REQ_ACTIVE		"ses-request-activity"

#define	SES_AD_PROP_RR_ABORT		"ses-remap-rebuild-abort"
#define	SES_AD_PROP_REBUILD		"ses-remap-rebuild"
#define	SES_AD_PROP_IN_FAILED_ARRAY	"ses-in-failed-array"
#define	SES_AD_PROP_IN_CRIT_ARRAY	"ses-in-critical-array"
#define	SES_AD_PROP_CONS_CHK		"ses-consistency-check"
#define	SES_AD_PROP_HOT_SPARE		"ses-hot-spare"
#define	SES_AD_PROP_RSVD_DEVICE		"ses-reserved-device"
#define	SES_AD_PROP_OK			"ses-ok"

/*
 * Display Element properties
 */
#define	SES_DPY_PROP_CHAR		"ses-displayed-character" /* U16 */
#define	SES_DPY_PROP_MODE		"ses-display-mode"	/* U64 */
/*
 * SES-2r17 Table 96, 7.3.14
 */
typedef enum ses_display_mode_ctl {
	SES_DISPLAY_MC_NOCHG = 0,
	SES_DISPLAY_MC_ESP = 1,
	SES_DISPLAY_MC_SET = 2
} ses_display_mode_ctl_t;

typedef enum ses2_display_mode_status {
	SES_DISPLAY_MS_NOTSUP = 0,
	SES_DISPLAY_MS_ESP = 1,
	SES_DISPLAY_MS_SET = 2
} ses_display_mode_status_t;

/*
 * Current Sensor properties
 */
#define	SES_CS_PROP_CURRENT_MA		"ses-current"		/* I64 */

/*
 * Door Lock properties
 */
#define	SES_LOCK_PROP_UNLOCKED		"ses-unlocked"

/*
 * SCSI Initiator or Target Port properties
 */
#define	SES_ITP_PROP_ENABLED		"ses-enabled"

/*
 * Language Module properties
 */
#define	SES_LANG_PROP_LANGCODE		"ses-language-code"	/* U64 */

/*
 * SCSI Port/Transceiver properties
 */
#define	SES_PX_PROP_XMIT_FAIL		"ses-transmitter-failure"
#define	SES_PX_PROP_LOL			"ses-loss-of-link"

/*
 * Power Supply properties
 */
#define	SES_PSU_PROP_DC_OVER_CURRENT	"ses-dc-over-current"
#define	SES_PSU_PROP_DC_UNDER_VOLTAGE	"ses-dc-under-voltage"
#define	SES_PSU_PROP_DC_OVER_VOLTAGE	"ses-dc-over-voltage"
#define	SES_PSU_PROP_DC_FAIL		"ses-dc-fail"
#define	SES_PSU_PROP_AC_FAIL		"ses-ac-fail"
#define	SES_PSU_PROP_TEMP_WARN		"ses-temperature-warning" /* I64 */
#define	SES_PSU_PROP_OVERTEMP_FAIL	"ses-overtemperature-failure"

/*
 * SAS Expander properties
 */
#define	SES_EXP_PROP_SAS_ADDR		"ses-expander-sas-address" /* U64 */

/*
 * SAS Connector properties
 */
#define	SES_SC_PROP_PHYSICAL_LINK	"ses-sas-physical-link"	/* U64 */
#define	SES_SC_PROP_CONNECTOR_TYPE	"ses-sas-connector-type" /* U64 */
/*
 * SES2r17 Table 122, 7.3.26
 */
typedef enum ses_sasconn_type {
	SES_SASCONN_T_UNKNOWN = 0,
	SES_SASCONN_T_SFF_8470 = 0x1,
	SES_SASCONN_T_SFF_8088 = 0x2,
	SES_SASCONN_T_VENDOR_EXT = 0xf,
	SES_SASCONN_T_SFF_8484 = 0x10,
	SES_SASCONN_T_SFF_8087 = 0x11,
	SES_SASCONN_T_SFF_8482_R = 0x20,
	SES_SASCONN_T_SATA_HOST = 0x21,
	SES_SASCONN_T_SFF_8482_P = 0x22,
	SES_SASCONN_T_SATA_DEV = 0x23,
	SES_SASCONN_T_VIRTUAL = 0x2f,
	SES_SASCONN_T_VENDOR_INT = 0x3f,
	SES_SASCONN_T_VENDOR_70 = 0x70,
	SES_SASCONN_T_VENDOR_71 = 0x71,
	SES_SASCONN_T_VENDOR_72 = 0x72,
	SES_SASCONN_T_VENDOR_73 = 0x73,
	SES_SASCONN_T_VENDOR_74 = 0x74,
	SES_SASCONN_T_VENDOR_75 = 0x75,
	SES_SASCONN_T_VENDOR_76 = 0x76,
	SES_SASCONN_T_VENDOR_77 = 0x77,
	SES_SASCONN_T_VENDOR_78 = 0x78,
	SES_SASCONN_T_VENDOR_79 = 0x79,
	SES_SASCONN_T_VENDOR_7A = 0x7a,
	SES_SASCONN_T_VENDOR_7B = 0x7b,
	SES_SASCONN_T_VENDOR_7C = 0x7c,
	SES_SASCONN_T_VENDOR_7D = 0x7d,
	SES_SASCONN_T_VENDOR_7E = 0x7e,
	SES_SASCONN_T_VENDOR_7F = 0x7f
} ses_sasconn_type_t;

/*
 * Simple Subenclosure properties
 */
#define	SES_SS_PROP_SHORT_STATUS	"ses-short-status"	/* U64 */

/*
 * Temperature Sensor properties
 */
#define	SES_TEMP_PROP_TEMP		"ses-temperature"	/* I64 */

/*
 * Uninterruptible Power Supply properties
 */
#define	SES_UPS_PROP_TIMELEFT		"ses-battery-time-remaining" /* U64 */
#define	SES_UPS_PROP_INTF_FAIL		"ses-interface-failure"
#define	SES_UPS_PROP_WARN		"ses-low-battery-warning"
#define	SES_UPS_PROP_UPS_FAIL		"ses-ups-failure"
#define	SES_UPS_PROP_DC_FAIL		"ses-dc-failure"
#define	SES_UPS_PROP_AC_FAIL		"ses-ac-failure"
#define	SES_UPS_PROP_AC_QUAL		"ses-ac-quality-exception"
#define	SES_UPS_PROP_AC_HI		"ses-ac-overvoltage-exception"
#define	SES_UPS_PROP_AC_LO		"ses-ac-undervoltage-exception"
#define	SES_UPS_PROP_BPF		"ses-battery-failure-predicted"
#define	SES_UPS_PROP_BATT_FAIL		"ses-battery-failure"

/*
 * Voltage Sensor properties
 */
#define	SES_VS_PROP_VOLTAGE_MV		"ses-voltage"		/* I64 */

/*
 * Enclosure Services Controller properties (Control only)
 */
#define	SES_ESC_PROP_SELECT		"ses-select-element"

/*
 * Primary/Subenclosure properties
 */
#define	SES_EN_PROP_EID			"ses-enclosure-id"	/* U64 */
#define	SES_EN_PROP_ESPID		"ses-enclosure-service-proc-id"
#define	SES_EN_PROP_NESP		"ses-enclosure-service-proc-count"
#define	SES_EN_PROP_LID			"ses-logical-id"		/* NV */
#define	SES_EN_PROP_VID			"ses-vendor-id"		/* S */
#define	SES_EN_PROP_PID			"ses-product-id"	/* S */
#define	SES_EN_PROP_REV			"ses-product-revision"	/* S */
#define	SES_EN_PROP_VS			"ses-product-vendor-specific" /* BA */

#define	SES_EN_PROP_UNRECOV		"ses-status-unrecoverable"
#define	SES_EN_PROP_CRIT		"ses-status-critical"
#define	SES_EN_PROP_NONCRIT		"ses-status-noncritical"
#define	SES_EN_PROP_INFO		"ses-status-informational"
#define	SES_EN_PROP_INVOP		"ses-status-invalid-operation"
#define	SES_EN_PROP_HELP		"ses-help-text"		/* S */
#define	SES_EN_PROP_STRING		"ses-string-in-data"	/* BA */
#define	SES_EN_PROP_SHORT		"ses-short-status"	/* U64 */
#define	SES_EN_PROP_UCODE		"ses-microcode-dl-status" /* U64 */
typedef enum ses2_dl_ucode_status {
	SES2_DLUCODE_S_NOP = 0,
	SES2_DLUCODE_S_INPROGRESS = 0x1,
	SES2_DLUCODE_S_SAVING = 0x2,
	SES2_DLUCODE_S_INTERIM_3 = 0x3,
	SES2_DLUCODE_S_INTERIM_4 = 0x4,
	SES2_DLUCODE_S_INTERIM_5 = 0x5,
	SES2_DLUCODE_S_INTERIM_6 = 0x6,
	SES2_DLUCODE_S_INTERIM_7 = 0x7,
	SES2_DLUCODE_S_INTERIM_8 = 0x8,
	SES2_DLUCODE_S_INTERIM_9 = 0x9,
	SES2_DLUCODE_S_INTERIM_A = 0xa,
	SES2_DLUCODE_S_INTERIM_B = 0xb,
	SES2_DLUCODE_S_INTERIM_C = 0xc,
	SES2_DLUCODE_S_INTERIM_D = 0xd,
	SES2_DLUCODE_S_INTERIM_E = 0xe,
	SES2_DLUCODE_S_INTERIM_F = 0xf,
	SES2_DLUCODE_S_COMPLETE_NOW = 0x10,
	SES2_DLUCODE_S_COMPLETE_AT_RESET = 0x11,
	SES2_DLUCODE_S_COMPLETE_AT_POWERON = 0x12,
	SES2_DLUCODE_S_VENDOR_70 = 0x70,
	SES2_DLUCODE_S_VENDOR_71 = 0x71,
	SES2_DLUCODE_S_VENDOR_72 = 0x72,
	SES2_DLUCODE_S_VENDOR_73 = 0x73,
	SES2_DLUCODE_S_VENDOR_74 = 0x74,
	SES2_DLUCODE_S_VENDOR_75 = 0x75,
	SES2_DLUCODE_S_VENDOR_76 = 0x76,
	SES2_DLUCODE_S_VENDOR_77 = 0x77,
	SES2_DLUCODE_S_VENDOR_78 = 0x78,
	SES2_DLUCODE_S_VENDOR_79 = 0x79,
	SES2_DLUCODE_S_VENDOR_7A = 0x7a,
	SES2_DLUCODE_S_VENDOR_7B = 0x7b,
	SES2_DLUCODE_S_VENDOR_7C = 0x7c,
	SES2_DLUCODE_S_VENDOR_7D = 0x7d,
	SES2_DLUCODE_S_VENDOR_7E = 0x7e,
	SES2_DLUCODE_S_VENDOR_7F = 0x7f,
	SES2_DLUCODE_S_PAGE_ERR = 0x80,
	SES2_DLUCODE_S_IMAGE_ERR = 0x81,
	SES2_DLUCODE_S_TIMEOUT = 0x82,
	SES2_DLUCODE_S_INTERNAL_NEEDIMAGE = 0x83,
	SES2_DLUCODE_S_INTERNAL_SAFE = 0x84,
	SES2_DLUCODE_S_VENDOR_ERR_F0 = 0xf0,
	SES2_DLUCODE_S_VENDOR_ERR_F1 = 0xf1,
	SES2_DLUCODE_S_VENDOR_ERR_F2 = 0xf2,
	SES2_DLUCODE_S_VENDOR_ERR_F3 = 0xf3,
	SES2_DLUCODE_S_VENDOR_ERR_F4 = 0xf4,
	SES2_DLUCODE_S_VENDOR_ERR_F5 = 0xf5,
	SES2_DLUCODE_S_VENDOR_ERR_F6 = 0xf6,
	SES2_DLUCODE_S_VENDOR_ERR_F7 = 0xf7,
	SES2_DLUCODE_S_VENDOR_ERR_F8 = 0xf8,
	SES2_DLUCODE_S_VENDOR_ERR_F9 = 0xf9,
	SES2_DLUCODE_S_VENDOR_ERR_FA = 0xfa,
	SES2_DLUCODE_S_VENDOR_ERR_FB = 0xfb,
	SES2_DLUCODE_S_VENDOR_ERR_FC = 0xfc,
	SES2_DLUCODE_S_VENDOR_ERR_FD = 0xfd,
	SES2_DLUCODE_S_VENDOR_ERR_FE = 0xfe,
	SES2_DLUCODE_S_VENDOR_ERR_FF = 0xff
} ses2_dl_ucode_status_t;

typedef enum ses_dl_ucode_mode {
	SES_DLUCODE_M_WITH_OFFS = 6,
	SES_DLUCODE_M_WITH_OFFS_SAVE = 7
} ses_dl_ucode_mode_t;

#define	SES_EN_PROP_UCODE_A		"ses-microcode-dl-addl-status" /* U64 */
#define	SES_EN_PROP_UCODE_SZ		"ses-microcode-maximum-size" /* U64 */
#define	SES_EN_PROP_UCODE_BUF		"ses-microcode-buffer-id" /* U64 */
#define	SES_EN_PROP_UCODE_OFF		"ses-microcode-buffer-offset" /* U64 */

#define	SES_EN_PROP_NICK		"ses-nickname"		/* S */
#define	SES_EN_PROP_NICK_STATUS		"ses-nickname-status"	/* U64 */
typedef enum ses_subnick_status {
	SES_SNS_NO_ERROR = 0x0,
	SES_SNS_ERR_PAGE = 0x80,
	SES_SNS_ERR_INT_NICKLOST = 0x81,
	SES_SNS_ERR_INT_PRESERVED = 0x82
} ses_subnick_status_t;

#define	SES_EN_PROP_NICK_ADDL_STATUS	"ses-nickname-additional-status"
#define	SES_EN_PROP_NICK_LANG		"ses-nickname-language"	/* U64 */

#define	SES_EN_PROP_POWER_DELAY		"ses-power-cycle-delay"	/* U64 */
#define	SES_EN_PROP_POWER_DURATION	"ses-power-cycle-duration" /* U64 */
#define	SES_EN_PROP_POWER_REQUEST	"ses-power-cycle-request" /* U64 */

typedef enum ses_power_delay {
	SES_PDL_NONE = 0x0,
	SES_PDL_IMMEDIATE = 0x3f
} ses_power_delay_t;

typedef enum ses_power_duration {
	SES_PDR_NONE = 0x0,
	SES_PDR_MANUAL = 0x3f
} ses_power_duration_t;

typedef enum ses_power_request {
	SES_PRQ_NONE = 0x0,
	SES_PRQ_SET = 0x1,
	SES_PRQ_CANCEL = 0x2
} ses_power_request_t;

/*
 * IEEE logical IDs (for SES_EN_PROP_LID)
 */
#define	SPC3_NAA_INT			"naa-id-integer"	/* U64 */
#define	SPC3_NAA_ID_TYPE		"naa-id-type"		/* U64 */
#define	SPC3_NAA_COMPANY_ID		"naa-company-id"	/* U64 */
#define	SPC3_NAA_VS_A			"naa-vendor-specific-a"	/* U64 */
#define	SPC3_NAA_VS_B			"naa-vendor-specific-b"	/* U64 */

/*
 * SES-2 Diagnostic page codes (Table 5, 6.1.1).  The set of exported pages
 * constitutes an inter-plugin interface and is therefore part of the public
 * header file.
 */
typedef enum ses2_diag_page {
	SES2_DIAGPAGE_SUPPORTED_PAGES = 0x00,
	SES2_DIAGPAGE_CONFIG = 0x01,
	SES2_DIAGPAGE_ENCLOSURE_CTL_STATUS = 0x02,
	SES2_DIAGPAGE_HELP_TEXT = 0x03,
	SES2_DIAGPAGE_STRING_IO = 0x04,
	SES2_DIAGPAGE_THRESHOLD_IO = 0x05,
	SES2_DIAGPAGE_ELEMENT_DESC = 0x07,
	SES2_DIAGPAGE_SHORT_STATUS = 0x08,
	SES2_DIAGPAGE_ENCLOSURE_BUSY = 0x09,
	SES2_DIAGPAGE_ADDL_ELEM_STATUS = 0x0a,
	SES2_DIAGPAGE_SUBENCLOSURE_HELP_TEXT = 0x0b,
	SES2_DIAGPAGE_SUBENCLOSURE_STRING_IO = 0x0c,
	SES2_DIAGPAGE_SUPPORTED_SES_PAGES = 0x0d,
	SES2_DIAGPAGE_DL_MICROCODE_CTL_STATUS = 0x0e,
	SES2_DIAGPAGE_SUBENCLOSURE_NICKNAME_CTL_STATUS = 0x0f,
	SES2_DIAGPAGE_VENDOR_0 = 0x10,
	SES2_DIAGPAGE_VENDOR_1 = 0x11,
	SES2_DIAGPAGE_VENDOR_2 = 0x12,
	SES2_DIAGPAGE_VENDOR_3 = 0x13,
	SES2_DIAGPAGE_VENDOR_4 = 0x14,
	SES2_DIAGPAGE_VENDOR_5 = 0x15,
	SES2_DIAGPAGE_VENDOR_6 = 0x16,
	SES2_DIAGPAGE_VENDOR_7 = 0x17,
	SES2_DIAGPAGE_VENDOR_8 = 0x18,
	SES2_DIAGPAGE_VENDOR_9 = 0x19,
	SES2_DIAGPAGE_VENDOR_A = 0x1a,
	SES2_DIAGPAGE_VENDOR_B = 0x1b,
	SES2_DIAGPAGE_VENDOR_C = 0x1c,
	SES2_DIAGPAGE_VENDOR_D = 0x1d,
	SES2_DIAGPAGE_VENDOR_E = 0x1e,
	SES2_DIAGPAGE_VENDOR_F = 0x1f
} ses2_diag_page_t;

#define	SES_CTL_OP_SETPROP		"ses-ctl-setprop"
#define	SES_CTL_OP_DL_UCODE		"ses-ctl-dl-ucode"

#define	SES_CTL_PROP_UCODE_DATA		"ses-ctl-ucode-data"
#define	SES_CTL_PROP_UCODE_BUFID	"ses-ctl-ucode-bufid"
#define	SES_CTL_PROP_UCODE_MODE		"ses-ctl-ucode-mode"

#ifdef	__cplusplus
}
#endif

#endif	/* _FRAMEWORK_SES_H */
