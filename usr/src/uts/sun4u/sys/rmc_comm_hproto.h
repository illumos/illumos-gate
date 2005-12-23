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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_RMC_COMM_HPROTO_H
#define	_SYS_RMC_COMM_HPROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * data types used in the data protocol fields
 */

typedef unsigned char rsci8;
typedef unsigned short rsci16;

typedef short rscis16;

#ifdef _LP64
typedef unsigned int rsci32;
typedef unsigned long rsci64;
#else
typedef unsigned long rsci32;
typedef unsigned long long rsci64;
#endif

/*
 * handle definition. Handles are used in the high-level data protocol
 * to identify FRU, sensors (temperature, voltage), and so on.
 */

typedef rsci16 dp_handle_t;

#define	DP_NULL_HANDLE		0xffff

#define	DP_MAX_HANDLE_NAME	32

#define	DP_NULL_MSG		0x00

/*
 * Supported message types and associated data types:
 */

#define	DP_RESET_RSC		0x7A

#define	DP_RESET_RSC_R		0x5A

#define	DP_UPDATE_FLASH		0x66

#define	DP_UPDATE_FLASH_R	0x46
typedef struct dp_update_flash_r {
	rsci32	status;		/* completion code */
} dp_update_flash_r_t;

#define	DP_RUN_TEST		0x74
typedef struct dp_run_test {
	rsci32	testno;		/* test number to run; see below. */
	rsci32	param_len;	/* # bytes in test parameter data. */
} dp_run_test_t;
/* followed by test parameters; see individual tests below. */

#define	DP_RUN_TEST_R		0x54
typedef struct dp_run_test_r {
	rsci32	status;		/* 0 = test passed, otherwise see failure */
				/* codes below. */
	rsci32	idatalen;	/* # items in input data array */
	rsci32	odatalen;	/* # items in output data array */
#define	DP_MAX_RUN_TEST_DATALEN (DP_MAX_MSGLEN-32)/2
	rsci8	idata[DP_MAX_RUN_TEST_DATALEN];	/* input data array */
	rsci8	odata[DP_MAX_RUN_TEST_DATALEN];	/* output data array */
} dp_run_test_r_t;

#define	RSC_TEST_PASSED		0
#define	RSC_TEST_SW_FAILURE	1
#define	RSC_TEST_BAD_DATA	2
#define	RSC_TEST_NO_RESPONSE	3
#define	RSC_TEST_BAD_CRC	4
#define	RSC_TEST_BAD_PARAMS	5
#define	RSC_TEST_NO_DEVICE	6
#define	RSC_TEST_DEV_SETUP_FAIL	7
#define	RSC_TEST_MEM_ALLOC_FAIL	8
#define	RSC_TEST_ENET_ADDR_FAIL	9
#define	RSC_TEST_DEV_INFO_FAIL	10
#define	RSC_TEST_NYI		255

#define	DP_RSC_STATUS		0x73

#define	DP_RSC_STATUS_R		0x53
typedef struct dp_rsc_status_r {
/* The first six fields here must not be changed to ensure that they  */
/* are the same in all versions of RSC, most notably when compared to */
/* 1.x. New fields must be added to the end of the structure. */
	rsci16	main_rev_major;
	rsci16	main_rev_minor;
	rsci16	bootmon_rev_major;
	rsci16	bootmon_rev_minor;
	rsci16	post_status;
	rsci16	nusers;		/* number of users currently logged in to */
				/* CLI.  */
/* Any new fields in the structure may be added after this point ONLY! */
	rsci16	release_rev_major;
	rsci16	release_rev_minor;
	rsci16	release_rev_micro;
	rsci16	main_rev_micro;
	rsci16	bootmon_rev_micro;
	rsci16	hardware_rev;

	rsci32 bm_cksum;
	rsci8  rsc_build;
	char creationDate[256];
	rsci32 fw_cksum;
	rsci32 sys_mem;
	rsci32 nvram_version;

} dp_rsc_status_r_t;

#define	DP_SET_CFGVAR		0x76
typedef struct dp_set_cfgvar {
	rsci32	hidden;		/* boolean */
} dp_set_cfgvar_t;

/* Data is variable name & new value as zero-terminated ascii strings. */

#define	DP_SET_CFGVAR_R		0x56
typedef struct dp_set_cfgvar_r {
	rsci32	status;		/* completion code */
} dp_set_cfgvar_r_t;

#define	DP_GET_CFGVAR		0x67
/* Data is variable name as zero-terminated ascii string. */

#define	DP_GET_CFGVAR_R		0x47
typedef struct dp_get_cfgvar_r {
	rsci32	status;		/* completion code */
} dp_get_cfgvar_r_t;
/* followed by value of variable as a zero-terminated ascii string. */

#define	DP_GET_CFGVAR_NAME	0x6E
/*
 * Data is variable name as zero-terminated ascii string.  A zero-length
 * string means 'return the name of the "first" variable.'
 */

#define	DP_GET_CFGVAR_NAME_R	0x4E
typedef struct dp_get_cfgvar_name_r {
	rsci32	status;		/* completion code */
} dp_get_cfgvar_name_r_t;
/* followed by name of "next" variable as a zero-terminated ascii string. */

#define	DP_SET_DATE_TIME		0x64
#define	DP_SET_DATE_TIME_IGNORE_FIELD	0xFFFF
typedef struct dp_set_date_time {
	rsci32	year;		/* Full year, IE 1997 */
	rsci32	month;		/* 1 = Jan, 2 = Feb, etc. */
	rsci32	day;		/* Day of the month, 1 to 31. */
	rsci32	hour;		/* 0 to 23 */
	rsci32	minute;		/* 0 to 59 */
	rsci32	second;		/* 0 to 59 */
} dp_set_date_time_t;

#define	DP_SET_DATE_TIME_R	0x44
typedef struct dp_set_date_time_r {
	rsci32	status;		/* 0 - succes, non-zero - fail. */
} dp_set_date_time_r_t;

#define	DP_GET_DATE_TIME	0x65
#define	DP_GET_DATE_TIME_R	0x45
typedef struct dp_get_date_time_r {
	rsci32	status;		/* completion code */
	rsci32	current_datetime; /* in Unix format */
} dp_get_date_time_r_t;
/* followed by the date represented as a zero-terminated ascii string. */


#define	DP_SEND_ALERT		0x61
typedef struct dp_send_alert {
	rsci32	critical; /* boolean */
} dp_send_alert_t;

#define	DP_SEND_ALERT_R		0x41
typedef struct dp_send_alert_r {
	rsci32	status;		/* completion code */
} dp_send_alert_r_t;

#define	DP_GET_TEMP		0x78

#define	DP_GET_TEMP_R		0x58
typedef struct dp_get_temp_r {
	rsci32	status;
	rsci32	current_temp;
} dp_get_temp_r_t;

/*
 * Implementations using this level of protocol or above,
 * will generate a response to any supplied command code.
 * This doesn't mean they will support a given command.
 * It only means that they will generate a response to that
 * command.
 */
#define	SDP_RESPONDS_TO_ALL_CMDS	3

#define	DP_GET_SDP_VERSION	0x7B

#define	DP_GET_SDP_VERSION_R	0x5B
typedef struct dp_get_sdp_version_r {
	rsci32	version;
} dp_get_sdp_version_r_t;

#define	DP_GET_TOD_CLOCK	0x7C

#define	DP_GET_TOD_CLOCK_R	0x5C
typedef struct dp_get_tod_clock_r {
	rsci32	current_tod;
} dp_get_tod_clock_r_t;

#define	DP_MAX_LOGSIZE		(DP_MAX_MSGLEN-24)

#define	DP_GET_EVENT_LOG	0x7D

/*
 * NOTE: changing this or the dp_event_log_entry structure will almost
 * certainly require changing the code that parses these structures
 * in scadm.  See src/cmd/scadm/sparcv9/mpxu/common/eventlog.c.
 */
#define	DP_GET_EVENT_LOG_R	0x5D
typedef struct dp_get_event_log_r {
	rsci32	entry_count;
	rsci8	data[DP_MAX_LOGSIZE];
} dp_get_event_log_r_t;

typedef struct dp_event_log_entry {
	rsci32	eventTime;
	rsci32	eventId;
	rsci32	paramLen;
	char	param[256];
} dp_event_log_entry_t;

#define	DP_GET_PCMCIA_INFO	0x7E

#define	DP_GET_PCMCIA_INFO_R	0x5E
typedef struct dp_get_pcmcia_info_r {
	rsci32	card_present;	/* true=present, false=no card */
	rsci32	idInfoLen;
	rsci8	idInfo[256];
} dp_get_pcmcia_info_r_t;


#define	DP_USER_MAX		16
#define	DP_USER_NAME_SIZE	16

/* User sub-commands */
#define	DP_USER_CMD_ADD		0x1
#define	DP_USER_CMD_DEL		0x2
#define	DP_USER_CMD_SHOW	0x3
#define	DP_USER_CMD_PASSWORD	0x4
#define	DP_USER_CMD_PERM	0x5

/*
 * The following fields are used to set the user permissions.
 * Each must be represented as a single bit in the parm field.
 */
#define	DP_USER_PERM_C		0x1
#define	DP_USER_PERM_U		0x2
#define	DP_USER_PERM_A		0x4
#define	DP_USER_PERM_R		0x8

/*
 * values for parm for CMD_SHOW.  Anything other than 0 will show
 * the user # up to and including DP_USER_MAX
 */
#define	DP_USER_SHOW_USERNAME	0x0

/* Error values for status */
#define	DP_ERR_USER_FULL	0x1  /* No free user slots */
#define	DP_ERR_USER_NONE	0x2  /* User does not exist */
#define	DP_ERR_USER_BAD		0x3  /* Malformed username */
#define	DP_ERR_USER_NACT	0x4  /* user # not activated */
#define	DP_ERR_USER_THERE	0x5  /* user already registered */
#define	DP_ERR_USER_PASSWD	0x6  /* invalid password */
#define	DP_ERR_USER_WARNING	0x7  /* Malformed username warning */
#define	DP_ERR_USER_NYI		0xFD /* Not yet implemented */
#define	DP_ERR_USER_UNDEF	0xFE /* Undefine error */
#define	DP_ERR_USER_CMD		0xFF /* Invalid Command */

#define	DP_USER_ADM		0x50
/*
 * The parm field is used by the permission command to set specific
 *  permissions.  The parm field is also used by the show command to
 * indicate if the user name is specified or not.
 */
typedef struct dp_user_adm {
	rsci32	command;
	rsci32	parm;
} dp_user_adm_t;
/*
 * followed by zero-terminated ascii strings.  All user commands
 * are followed by the username. The password command is also
 * followed by the password.
 */

#define	DP_USER_ADM_R		0x51
/*
 * the response field is used to return the user permissions
 * for the user permissions command. The response is also used
 * to echo back the user selection for the show command.
 */
typedef struct dp_user_adm_r {
	rsci32	status;		/* completion code */
	rsci32  command;	/* echo back adm command */
	rsci32	response;
} dp_user_adm_r_t;
/* followed by a zero-terminated ascii string for the show command.  */


#define	DP_MODEM_PASS		0
#define	DP_MODEM_FAIL		-1

/* Commands used for rscadm modem_setup */
#define	DP_MODEM_CONNECT	0x30
#define	DP_MODEM_CONNECT_R	0x31
typedef struct dp_modem_connect_r {
	rsci32	status;
} dp_modem_connect_r_t;

/* There is no reponse to a modem_data command */
/* The modem data command goes in both directions */
#define	DP_MODEM_DATA		0x32
/* followed by a zero-terminated ascii string */

#define	DP_MODEM_DISCONNECT	0x34
#define	DP_MODEM_DISCONNECT_R	0x35
typedef struct dp_modem_disconnect_r {
	rsci32	status;
} dp_modem_disconnect_r_t;


#define	DP_GET_TICKCNT		0x22
#define	DP_GET_TICKCNT_R	0x23
typedef struct dp_get_tickcnt_r {
	rsci32	upper;		/* MSW of 64 bit tick count */
	rsci32	lower;		/* LSW of 64 bit tick count */
} dp_get_tickcnt_r_t;


#define	DP_SET_DEFAULT_CFG	0x72

#define	DP_SET_DEFAULT_CFG_R	0x52
typedef struct dp_set_default_cfg_r {
	rsci32	status;
} dp_set_default_cfg_r_t;


#define	DP_GET_NETWORK_CFG	0x59

#define	DP_GET_NETWORK_CFG_R	0x79
typedef struct dp_get_network_cfg_r {
	rsci32	status;
	char	ipMode[7];
	char	ipAddr[16];
	char	ipMask[16];
	char	ipGateway[16];
	char	ethAddr[18];
	char	ipDHCPServer[16];
} dp_get_network_cfg_r_t;


/*
 * Parameters for DP_RUN_TEST message:
 */

/*
 * Test routines need to know what the low-level protocol sync
 * character is.
 */

#define	RSC_TEST_SERIAL		0
typedef struct rsc_serial_test {
	rsci32	testtype;
#define	RSC_SERIAL_TTYC_LB	0
#define	RSC_SERIAL_TTYC_LB_OFF	1
#define	RSC_SERIAL_TTYD_LB	2
#define	RSC_SERIAL_TTYD_LB_OFF	3
#define	RSC_SERIAL_TTYCD_LB	4
#define	RSC_SERIAL_TTYCD_LB_OFF	5
#define	RSC_SERIAL_TTYU_INT_LB	6
#define	RSC_SERIAL_TTYU_EXT_LB	7
	rsci32	baud;
	rsci32	passes;
	rsci32	datalen;
	rsci8	data[DP_MAX_MSGLEN-32];
} rsc_serial_test_t;

#define	RSC_TEST_ENET		1
typedef struct rsc_enet_test {
	rsci32	testtype;
#define	RSC_ENET_INT_LB		0
#define	RSC_ENET_EXT_LB		1
#define	RSC_ENET_PING		2
#define	RSC_ENET_INT_PHY_LB	3
	rsci8	ip_addr[4];
	rsci32	passes;
	rsci32	datalen;
	rsci8	data[DP_MAX_MSGLEN-32];
} rsc_enet_test_t;

#define	RSC_TEST_FLASH_CRC	2
typedef struct rsc_flash_crcs_r {
	rsci32	boot_crc;
	rsci32	main_crc;
} rsc_flash_crcs_r_t;

#define	RSC_TEST_SEEPROM_CRC	3
typedef struct rsc_seeprom_crcs_r {
	rsci32	hdr_crc;
	rsci32	main_crc;
} rsc_seeprom_crcs_r_t;

#define	RSC_TEST_FRU_SEEPROM_CRC 4
typedef struct rsc_fru_crcs_r {
	rsci32	ro_hdr_crc;
	rsci32	seg_sd_crc;
} rsc_fru_crcs_r_t;


/*
 * new commands definitions
 */

#define	DP_GET_SYSINFO		0x20

#define	DP_GET_SYSINFO_R	0x21
typedef struct dp_get_sysinfo_r {
	rsci8 maxTemp;		/* max number of temperature sensors */
	rsci8 maxFan;		/* max number of FANs */
	rsci8 maxPSU;		/* max number of PSUs slot */
	rsci8 maxLED;		/* max number of LEDs */
	rsci8 maxVolt;		/* max number of voltage sensors */
	rsci8 maxFRU;		/* max number of FRUs (field replac. unit)  */
	rsci8 maxCircuitBrks;	/* max number of circuit breakers */
	rsci8 keyswitch;	/* key switch setting value */
} dp_get_sysinfo_r_t;


#define	DP_GET_TEMPERATURES	0x24
typedef struct dp_get_temperatures {
	dp_handle_t handle;	/* handle of a temperature sensor */
				/* or <null handle> (0xffff) */
} dp_get_temperatures_t;

/* Data is variable name & new value as zero-terminated ascii strings. */

#define	DP_GET_TEMPERATURES_R	0x25
typedef rscis16		dp_tempr_t;

enum sensor_status {
	DP_SENSOR_DATA_AVAILABLE = 0,
	DP_SENSOR_DATA_UNAVAILABLE,
	DP_SENSOR_NOT_PRESENT
};

typedef struct dp_tempr_status {
	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	dp_tempr_t	value;	/* temperature value (celsius). */

	dp_tempr_t 	low_warning;
	dp_tempr_t 	low_soft_shutdown;
	dp_tempr_t 	low_hard_shutdown;
	dp_tempr_t 	high_warning;
	dp_tempr_t 	high_soft_shutdown;
	dp_tempr_t 	high_hard_shutdown;

} dp_tempr_status_t;

typedef struct dp_get_temperatures_r {
	rsci8			num_temps;
	dp_tempr_status_t	temp_status[1];

} dp_get_temperatures_r_t;


#define	DP_GET_FAN_STATUS	0x26
typedef struct dp_get_fan_status {
	dp_handle_t handle;	/* handle of a temperature sensor */
				/* or <null handle> (0xffff) */
} dp_get_fan_status_t;

#define	DP_GET_FAN_STATUS_R	0x27

typedef struct dp_fan_status {
	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	rsci8 		flag;

#define	DP_FAN_PRESENCE		0x01	/* FAN presence (bit set=FAN present) */
#define	DP_FAN_SPEED_VAL_UNIT	0x02	/* speed unit	(bit set=relative, */
					/*		bit clear=RPM) */
#define	DP_FAN_STATUS		0x04	/* FAN status (bit set=error) */

	rsci16		speed;	/* FAN speed. */
	rsci16		minspeed; /* minimum FAN speed warning threshold */

} dp_fan_status_t;

typedef struct dp_get_fan_status_r {
	rsci8		num_fans;
	dp_fan_status_t	fan_status[1];

} dp_get_fan_status_r_t;


#define	DP_GET_PSU_STATUS	0x28
typedef struct dp_get_psu_status {
	dp_handle_t handle;	/* handle of a temperature sensor */
				/* or <null handle> (0xffff) */
} dp_get_psu_status_t;

#define	DP_GET_PSU_STATUS_R	0x29
typedef struct dp_psu_status {
	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	rsci16 		mask;		/* flag bit mask (feature presence) */
	rsci16 		flag;		/* status bits */

#define	DP_PSU_PRESENCE			0x0001	/* PSU presence  */
#define	DP_PSU_OUTPUT_STATUS		0x0002	/* output status */
#define	DP_PSU_INPUT_STATUS		0x0004	/* input status */
#define	DP_PSU_SEC_INPUT_STATUS		0x0008	/* secondary input status */
#define	DP_PSU_OVERTEMP_FAULT		0x0010	/* over temperature fault */
#define	DP_PSU_FAN_FAULT    		0x0020	/* FAN fault */
#define	DP_PSU_FAIL_STATUS		0x0040	/* PSU generic fault */
#define	DP_PSU_OUTPUT_VLO_STATUS	0x0080	/* output under voltage */
#define	DP_PSU_OUTPUT_VHI_STATUS	0x0100	/* output over voltage */
#define	DP_PSU_OUTPUT_AHI_STATUS	0x0200	/* output over current */
#define	DP_PSU_ALERT_STATUS		0x0400	/* PSU alert indication */
#define	DP_PSU_PDCT_FAN			0x0800	/* predicted fan fail */
#define	DP_PSU_NR_WARNING		0x1000	/* non-redundancy condition */

			/* presence: 	bit clear=not present */
			/*		bit set=present */
			/* status:	bit clear=ok */
			/*		bit set=generic fault */
} dp_psu_status_t;

typedef struct dp_get_psu_status_r {

	rsci8		num_psus;
	dp_psu_status_t	psu_status[1];

} dp_get_psu_status_r_t;

#define	DP_GET_FRU_STATUS	0x2A
typedef struct dp_get_fru_status {
	dp_handle_t handle;	/* handle of a hot pluggable unit */
				/* or <null handle> (0xffff)	  */
} dp_get_fru_status_t;


#define	DP_GET_FRU_STATUS_R	0x2B
typedef struct dp_fru_status {

	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	rsci8		presence;	/* 1=FRU present */
	rsci8		status;

} dp_fru_status_t;

enum dp_fru_status_type {
	DP_FRU_STATUS_OK = 1,
	DP_FRU_STATUS_FAILED,
	DP_FRU_STATUS_BLACKLISTED,
	DP_FRU_STATUS_UNKNOWN
};

typedef struct dp_get_fru_status_r {
	rsci8		num_frus;
	dp_fru_status_t	fru_status[1];

} dp_get_fru_status_r_t;

/*
 * DP_GET_DEVICE(_R) command is used to discover I2C devices dynamically
 * (used by SunVTS)
 */
#define	DP_GET_DEVICE		0x2C

typedef struct dp_get_device {
	dp_handle_t	handle;	/* handle of a device or */
				/* <null handle>(0xffff) */
} dp_get_device_t;

#define	DP_GET_DEVICE_R		0x2D

#define	DP_MAX_DEVICE_TYPE_NAME	32

typedef struct dp_device {
	dp_handle_t	handle;
	rsci8		presence;	/* 0 is not present, 1 is present */
	char		device_type[DP_MAX_DEVICE_TYPE_NAME];
} dp_device_t;

typedef struct dp_get_device_r {
	rsci8		num_devices;
	dp_device_t	device[1];
} dp_get_device_r_t;


#define	DP_SET_CPU_SIGNATURE	0x33

typedef struct dp_set_cpu_signature {
	int		cpu_id;		/* see PSARC 2000/205 for more */
	ushort_t	sig; 		/* information on the value/meaning */
	uchar_t		states;		/* of these fields */
	uchar_t		sub_state;

} dp_cpu_signature_t;


#define	DP_SET_CPU_NODENAME	0x38

#define	DP_MAX_NODENAME		256

typedef struct dp_set_nodename {
	char		nodename[DP_MAX_NODENAME];
} dp_set_nodename_t;


#define	DP_GET_LED_STATE	0x3C

typedef struct dp_get_led_state {
	dp_handle_t handle;	/* handle of a hot pluggable unit */
				/* or <null handle> (0xffff) */
} dp_get_led_state_t;

#define	DP_GET_LED_STATE_R	0x3D

typedef struct dp_led_state {
	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	rsci8		state;
	rsci8		colour;
} dp_led_state_t;

typedef struct dp_get_led_state_r {
	rsci8		num_leds;
	dp_led_state_t	led_state[1];
} dp_get_led_state_r_t;

/* LED states */

enum dp_led_states {
	DP_LED_OFF = 0,
	DP_LED_ON,
	DP_LED_FLASHING,
	DP_LED_BLINKING
};

enum dp_led_colours {
	DP_LED_COLOUR_NONE = -1,
	DP_LED_COLOUR_ANY,
	DP_LED_COLOUR_WHITE,
	DP_LED_COLOUR_BLUE,
	DP_LED_COLOUR_GREEN,
	DP_LED_COLOUR_AMBER
};


#define	DP_SET_LED_STATE	0x3E

typedef struct dp_set_led_state {
	dp_handle_t	handle;		/* handle of a LED */
	rsci8		state;
} dp_set_led_state_t;

#define	DP_SET_LED_STATE_R	0x3F
typedef struct dp_set_led_state_r {
	rsci8		status;
} dp_set_led_state_r_t;

enum dp_set_led_status {
	DP_SET_LED_OK = 0,
	DP_SET_LED_INVALID_HANDLE,
	DP_SET_LED_ERROR
};


#define	DP_GET_ALARM_STATE	0x68

typedef struct dp_get_alarm_state {
	dp_handle_t handle;	/* handle of an alarm relay */
				/* or <null handle> (0xffff) */
} dp_get_alarm_state_t;

#define	DP_GET_ALARM_STATE_R	0x69

typedef struct dp_alarm_state {
	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	rsci8		state;
} dp_alarm_state_t;

typedef struct dp_get_alarm_state_r {
	rsci8		num_alarms;
	dp_alarm_state_t	alarm_state[1];
} dp_get_alarm_state_r_t;

/* ALARM states */

enum dp_alarm_states {
	DP_ALARM_OFF = 0,
	DP_ALARM_ON
};

#define	DP_SET_ALARM_STATE	0x6A

typedef struct dp_set_alarm_state {
	dp_handle_t	handle;		/* handle of a ALARM */
	rsci8		state;
} dp_set_alarm_state_t;

#define	DP_SET_ALARM_STATE_R	0x6B
typedef struct dp_set_alarm_state_r {
	rsci8		status;
} dp_set_alarm_state_r_t;

enum dp_set_alarm_status {
	DP_SET_ALARM_OK = 0,
	DP_SET_ALARM_INVALID_HANDLE,
	DP_SET_ALARM_ERROR
};


#define	DP_SET_USER_WATCHDOG	0x60
#define	DP_SET_USER_WATCHDOG_R	0x6F
#define	DP_GET_USER_WATCHDOG	0x70
#define	DP_GET_USER_WATCHDOG_R	0x71

#define	DP_USER_WATCHDOG_ENABLE		0x01
#define	DP_USER_WATCHDOG_DISABLE	0x00

enum dp_user_watchdog_status {
	DP_USER_WDT_OK = 0,
	DP_USER_WDT_ERROR
};

typedef struct dp_set_user_watchdog {
	rsci8 enable;	/* enable = 1 */
} dp_set_user_watchdog_t;

typedef struct dp_set_user_watchdog_r {
	rsci8 status;
} dp_set_user_watchdog_r_t;

typedef struct dp_get_user_watchdog_r {
	rsci8 enable;
} dp_get_user_watchdog_r_t;

#define	DP_GET_VOLTS		0x42

typedef struct dp_get_volts {
	dp_handle_t	handle;		/* handle of a voltage sensor */
} dp_get_volts_t;

#define	DP_GET_VOLTS_R		0x43

typedef rscis16		dp_volt_reading_t;	/* unit in mV */

typedef struct dp_volt_status {
	dp_handle_t		handle;
	rsci8			sensor_status; 	/* tells whether the reading */
						/* is available or not */
	rsci8			status;		/* 0=ok, 1=error */
	dp_volt_reading_t	reading;	/* value in mV. */
	dp_volt_reading_t	low_warning;
	dp_volt_reading_t	low_soft_shutdown;
	dp_volt_reading_t	low_hard_shutdown;
	dp_volt_reading_t	high_warning;
	dp_volt_reading_t	high_soft_shutdown;
	dp_volt_reading_t	high_hard_shutdown;

} dp_volt_status_t;

typedef struct dp_get_volts_r {
	rsci8			num_volts;
	dp_volt_status_t	volt_status[1];

} dp_get_volts_r_t;


#define	DP_GET_CIRCUIT_BRKS	0x62

typedef struct dp_get_circuit_brks {
	dp_handle_t handle;	/* handle of a circuit breaker */
				/* or <null handle> (0xffff) */
} dp_get_circuit_brks_t;

#define	DP_GET_CIRCUIT_BRKS_R	0x63

typedef struct dp_circuit_brk_status {
	dp_handle_t	handle;
	rsci8		sensor_status; 	/* tells whether the reading is */
					/* available or not */
	rsci8		status;		/* 0=ok, 1=error */

} dp_circuit_brk_status_t;

typedef struct dp_get_circuit_brks_r {
	rsci8			num_circuit_brks;
	dp_circuit_brk_status_t	circuit_brk_status[1];

} dp_get_circuit_brks_r_t;


#define	DP_SET_HOST_WATCHDOG	0x48

typedef struct dp_set_host_watchdog {
	rsci8	enable;		/* 0=enable watchdog, 1=disable watchdog */
} dp_set_host_watchdog_t;


#define	DP_GET_HANDLE_NAME	0x4A

typedef struct dp_get_handle_name {
	dp_handle_t	handle;
} dp_get_handle_name_t;

#define	DP_GET_HANDLE_NAME_R	0x4B

typedef struct dp_get_handle_name_r {
	dp_handle_t	handle;
	char 		name[DP_MAX_HANDLE_NAME];
} dp_get_handle_name_r_t;


#define	DP_GET_HANDLE		0x4C

typedef struct dp_get_handle {
	char 		name[DP_MAX_HANDLE_NAME];
} dp_get_handle_t;

#define	DP_GET_HANDLE_R		0x4D

typedef struct dp_get_handle_r {
	dp_handle_t 	handle;
} dp_get_handle_r_t;


#define	DP_RMC_EVENTS		0x57

typedef rsci16	dp_event_t;

/*
 * list of events
 */

enum rmc_events {
	RMC_INIT_EVENT	= 0x01,
	RMC_HPU_EVENT,
	RMC_ENV_EVENT,
	RMC_KEYSWITCH_EVENT,
	RMC_LOG_EVENT
};

/*
 * event data structures
 */
enum rmc_hpu_events {
	RMC_HPU_INSERT_EVENT	= 0x20,
	RMC_HPU_REMOVE_EVENT,
	RMC_HPU_HWERROR_EVENT
};

typedef struct dp_hpu_event {
	dp_handle_t	hpu_hdl;
	dp_event_t	sub_event;

} dp_hpu_event_t;


enum rmc_env_events {
	RMC_ENV_WARNING_THRESHOLD_EVENT = 0x31,
	RMC_ENV_SHUTDOWN_THRESHOLD_EVENT,
	RMC_ENV_FAULT_EVENT,
	RMC_ENV_OK_EVENT
};

typedef struct dp_env_event {
	dp_handle_t	env_hdl;
	dp_event_t	sub_event;

} dp_env_event_t;


enum rmc_keyswitch_pos {
	RMC_KEYSWITCH_POS_UNKNOWN	= 0x00,
	RMC_KEYSWITCH_POS_NORMAL,
	RMC_KEYSWITCH_POS_DIAG,
	RMC_KEYSWITCH_POS_LOCKED,
	RMC_KEYSWITCH_POS_OFF
};

typedef struct dp_keyswitch_event {
	rsci8	key_position;
} dp_keyswitch_event_t;


typedef struct dp_rmclog_event {
	int	log_record_size;
	rsci8	log_record[DP_MAX_LOGSIZE];
} dp_rmclog_event_t;

typedef union dp_event_info {
	dp_hpu_event_t		ev_hpunot;
	dp_env_event_t		ev_envnot;
	dp_keyswitch_event_t	ev_keysw;
	dp_rmclog_event_t	ev_rmclog;
} dp_event_info_t;

typedef struct dp_event_notification {
	dp_event_t	event;
	rsci32		event_seqno; 	/* event sequence number */
	rsci32		timestamp;	/* timestamp of the event */
	dp_event_info_t	event_info;	/* event information */
} dp_event_notification_t;

#define	DP_RMC_EVENTS_R		0x5F

typedef struct dp_event_notification_r {
	rsci32		event_seqno; 	/* event sequence number */
} dp_event_notification_r_t;

#define	DP_GET_CHASSIS_SERIALNUM	0x2E
#define	DP_GET_CHASSIS_SERIALNUM_R	0x2F
typedef struct dp_get_serialnum_r {
	rsci8		chassis_serial_number[32];
} dp_get_serialnum_r_t;

#define	DP_GET_CONSOLE_LOG	0x1A
typedef struct dp_get_console_log {
	rsci64		start_seq; 	/* sequence number of first log byte */
	rsci16		length;		/* expected size of retrieved data */
} dp_get_console_log_t;

#define	DP_GET_CONSOLE_LOG_R	0x1B
typedef struct dp_get_console_log_r {
	rsci64		next_seq;	/* sequence number of next log byte */
	rsci64		remaining_log_bytes;	/* bytes left to retrieve */
	rsci16		length;		/* size of retrieved data */
	char		buffer[DP_MAX_MSGLEN - (sizeof (rsci64) * 2 +
			    sizeof (rsci16))];
} dp_get_console_log_r_t;

#define	DP_GET_CONFIG_LOG	0x1C
typedef struct dp_get_config_log {
	rsci64		start_seq;	/* sequence number of first log byte */
	rsci16		length;		/* size of retrieved data */
} dp_get_config_log_t;

#define	DP_GET_CONFIG_LOG_R	0x1D
typedef struct dp_get_config_log_r {
	rsci64		next_seq;	/* sequence number of next log byte */
	rsci64		remaining_log_bytes;	/* bytes left to retrieve */
	rsci16		length;		/* size of retrieved data */
	char		buffer[DP_MAX_MSGLEN - (sizeof (rsci64) * 2 +
			    sizeof (rsci16))];
} dp_get_config_log_r_t;

#define	DP_GET_EVENT_LOG2	0x1E
typedef struct dp_get_event_log2 {
	rsci64		start_seq;	/* sequence number of first log event */
	rsci16		length;		/* size of retrieved data */
} dp_get_event_log2_t;

#define	DP_GET_EVENT_LOG2_R	0x1F
typedef struct dp_get_event_log2_r {
	rsci64		next_seq;	/* sequence number of next log event */
	rsci64		remaining_log_events;	/* events left to retrieve */
	rsci16		num_events;		/* size of retrieved data */
	char		buffer[DP_MAX_MSGLEN - (sizeof (rsci64) * 2 +
			    sizeof (rsci16))];
} dp_get_event_log2_r_t;

/*
 * This is ALOM's response to command codes it does not know.  It will
 * return the unknown command code in inv_type.  Note that this is
 * available starting with protocol version 3.  ALOM will not respond
 * to unknown commands in older versions of the protocol.
 */
#define	DP_INVCMD	0x7F
typedef struct dp_invcmd {
	uint8_t inv_type;
} dp_invcmd_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMC_COMM_HPROTO_H */
