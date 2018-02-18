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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 */

#ifndef	_LIBIPMI_H
#define	_LIBIPMI_H

#include <sys/byteorder.h>
#include <sys/nvpair.h>
#include <sys/sysmacros.h>

/*
 * Private interfaces for communicating with attached services over IPMI.  This
 * library is designed for system software communicating with Illumos-supported
 * service processors over /dev/ipmi0.  It is not a generic IPMI library.
 *
 * Documentation references refer to "Intelligent Platform Management Interface
 * Specification Second Generation v2.0", document revision 1.0 with Februrary
 * 15, 2006 Markup from "IPMI v2.0 Addenda, Errata, and Clarifications Revision
 * 3".
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ipmi_handle ipmi_handle_t;

#pragma pack(1)

/*
 * Basic netfn definitions.  See section 5.1.
 */
#define	IPMI_NETFN_CHASSIS		0x0
#define	IPMI_NETFN_BRIDGE		0x2
#define	IPMI_NETFN_SE			0x4
#define	IPMI_NETFN_APP			0x6
#define	IPMI_NETFN_FIRMWARE		0x8
#define	IPMI_NETFN_STORAGE		0xa
#define	IPMI_NETFN_TRANSPORT		0x0C
#define	IPMI_NETFN_OEM			0x2e

/*
 * Error definitions
 */
#define	EIPMI_BASE	2000

typedef enum {
	EIPMI_NOMEM = EIPMI_BASE,	/* memory allocation failure */
	EIPMI_BMC_OPEN_FAILED,		/* failed to open /dev/ipmi0 */
	EIPMI_BMC_PUTMSG,	/* failed to send message to /dev/ipmi0 */
	EIPMI_BMC_GETMSG,	/* failed to read response from /dev/ipmi0 */
	EIPMI_BMC_RESPONSE,		/* response from /dev/ipmi0 failed */
	EIPMI_INVALID_COMMAND,		/* invalid command */
	EIPMI_COMMAND_TIMEOUT,		/* command timeout */
	EIPMI_DATA_LENGTH_EXCEEDED,	/* maximum data length exceeded */
	EIPMI_SEND_FAILED,		/* failed to send BMC request */
	EIPMI_UNSPECIFIED,		/* unspecified BMC error */
	EIPMI_UNKNOWN,			/* unknown error */
	EIPMI_BAD_RESPONSE,		/* received unexpected response */
	EIPMI_BAD_RESPONSE_LENGTH,	/* unexpected response length */
	EIPMI_INVALID_RESERVATION,	/* invalid or cancelled reservation */
	EIPMI_NOT_PRESENT,		/* requested entity not present */
	EIPMI_INVALID_REQUEST,		/* malformed request data */
	EIPMI_BUSY,			/* service processor is busy */
	EIPMI_NOSPACE,			/* service processor is out of space */
	EIPMI_UNAVAILABLE,		/* service processor is unavailable */
	EIPMI_ACCESS,			/* insufficient privileges */
	EIPMI_BADPARAM,			/* parameter is not supported */
	EIPMI_READONLY,			/* attempt to write read-only param */
	EIPMI_WRITEONLY,		/* attempt to read write-only param */
	EIPMI_LAN_OPEN_FAILED,		/* failed to open socket */
	EIPMI_LAN_PING_FAILED,		/* RMCP Ping message failed */
	EIPMI_LAN_PASSWD_NOTSUP, /* password authentication not supported */
	EIPMI_LAN_CHALLENGE,		/* failure getting challenge */
	EIPMI_LAN_SESSION,		/* failure activating session */
	EIPMI_LAN_SETPRIV		/* failure setting session privs */
} ipmi_errno_t;

/*
 * Basic library functions.
 *
 * The ipmi_handle is the primary interface to the library.  The library itself
 * is not MT-safe, but it is safe within a single handle.  Multithreaded clients
 * should either open multiple handles, or otherwise synchronize access to the
 * same handle.
 *
 * There is a single command response buffer that is stored with the handle, to
 * simplify memory management in the caller.  The memory referenced by a command
 * response is only valid until the next command is issued.  The caller is
 * responsible for making a copy of the response if it is needed.
 */
extern ipmi_handle_t *ipmi_open(int *, char **, uint_t xport_type, nvlist_t *);

/*
 * Constants for nvpair names for the params nvlist that is passed to
 * ipmi_open().  If the IPMI_TRANSPORT_BMC is desired, then it is sufficient
 * to just specify NULL for the params nvlist.
 *
 * For IPMI_TRANSPORT_LAN, the params nvlist must contain the following
 * nvpairs:
 *
 * IPMI_LAN_HOST, IPMI_LAN_USER, IPMI_LAN_PASSWD
 *
 * IPMI_LAN_PORT is optional and will default to 623
 * IPMI_LAN_PRIVLVL is optional and will default to admin
 * IPMI_LAN_TIMEOUT is optional and will default to 3 seconds
 * IPMI_LAN_NUM_RETIES is optional and will default to 5
 */
#define	IPMI_TRANSPORT_TYPE	"transport-type"
#define	IPMI_TRANSPORT_BMC	0x01
#define	IPMI_TRANSPORT_LAN	0x02

#define	IPMI_LAN_HOST		"lan-host"
#define	IPMI_LAN_PORT		"lan-port"
#define	IPMI_LAN_USER		"lan-user"
#define	IPMI_LAN_PASSWD		"lan-passwd"
#define	IPMI_LAN_PRIVLVL	"lan-privlvl"
#define	IPMI_LAN_TIMEOUT	"lan-timeout"
#define	IPMI_LAN_NUM_RETRIES	"lan-num-retries"

extern void ipmi_close(ipmi_handle_t *);

extern int ipmi_errno(ipmi_handle_t *);
extern const char *ipmi_errmsg(ipmi_handle_t *);

/*
 * Raw requests.  See section 5.
 */
typedef struct ipmi_cmd {
	uint8_t		ic_netfn:6;
	uint8_t		ic_lun:2;
	uint8_t		ic_cmd;
	uint16_t	ic_dlen;
	void		*ic_data;
} ipmi_cmd_t;

extern ipmi_cmd_t *ipmi_send(ipmi_handle_t *, ipmi_cmd_t *);

/*
 * Retrieve basic information about the IPMI device.  See section 20.1 "Get
 * Device ID Command".
 */
#define	IPMI_CMD_GET_DEVICEID		0x01

typedef struct ipmi_deviceid {
	uint8_t		id_devid;
	DECL_BITFIELD3(
	    id_dev_rev		:4,
	    __reserved		:3,
	    id_dev_sdrs		:1);
	DECL_BITFIELD2(
	    id_firm_major	:7,
	    id_dev_available	:1);
	uint8_t		id_firm_minor;
	uint8_t		id_ipmi_rev;
	uint8_t		id_dev_support;
	uint8_t		id_manufacturer[3];
	uint8_t		id_product[2];
} ipmi_deviceid_t;

#define	IPMI_OEM_SUN		0x2a
#define	IPMI_PROD_SUN_ILOM	0x4701

ipmi_deviceid_t *ipmi_get_deviceid(ipmi_handle_t *);

#define	ipmi_devid_manufacturer(dp)		\
	((dp)->id_manufacturer[0] |		\
	((dp)->id_manufacturer[1] << 8) |	\
	((dp)->id_manufacturer[2] << 16))

#define	ipmi_devid_product(dp)		\
	((dp)->id_product[0] |		\
	((dp)->id_product[1] << 8))

const char *ipmi_firmware_version(ipmi_handle_t *);

/*
 * Get Channel Auth Caps.  See section 22.13.
 */
typedef struct ipmi_channel_auth_caps {
	uint8_t cap_channel;
	DECL_BITFIELD3(
	    cap_authtype	:6,
	    __reserved1		:1,
	    cap_ipmirev2	:1);
	DECL_BITFIELD5(
	    cap_anon		:3,
	    cap_peruser		:1,
	    cap_permesg		:1,
	    cap_kgstatus	:1,
	    __reserved2		:2);
	uint8_t cap_ext;
	uint8_t cap_oemid[3];
	uint8_t cap_oemaux;
} ipmi_channel_auth_caps_t;

#define	IPMI_CMD_GET_CHANNEL_AUTH_CAPS	0x38
extern ipmi_channel_auth_caps_t *ipmi_get_channel_auth_caps(ipmi_handle_t *,
    uint8_t, uint8_t);

/*
 * Get Channel Info.  See section 22.24.
 */
typedef struct ipmi_channel_info {
	DECL_BITFIELD2(
	    ici_number		:4,
	    __reserved1		:4);
	DECL_BITFIELD2(
	    ici_medium		:7,
	    __reserved2		:1);
	DECL_BITFIELD2(
	    ici_protocol	:5,
	    __reserved3		:3);
	DECL_BITFIELD3(
	    ici_session_count	:6,
	    ici_single_session	:1,
	    ici_multi_Session	:1);
	uint8_t		ici_vendor[3];
	uint8_t		ici_auxinfo[2];
} ipmi_channel_info_t;

#define	IPMI_CMD_GET_CHANNEL_INFO	0x42

/*
 * Channel Numbers.  See section 6.3.
 */
#define	IPMI_CHANNEL_PRIMARY		0x0
#define	IPMI_CHANNEL_MIN		0x1
#define	IPMI_CHANNEL_MAX		0xB
#define	IPMI_CHANNEL_CURRENT		0xE
#define	IPMI_CHANNEL_SYSTEM		0xF

extern ipmi_channel_info_t *ipmi_get_channel_info(ipmi_handle_t *, int);

/*
 * Channel Protocol Types.  See section 6.4.
 */
#define	IPMI_PROTOCOL_IPMB		0x1
#define	IPMI_PROTOCOL_ICMB		0x2
#define	IPMI_PROTOCOL_SMBUS		0x4
#define	IPMI_PROTOCOL_KCS		0x5
#define	IPMI_PROTOCOL_SMIC		0x6
#define	IPMI_PROTOCOL_BT10		0x7
#define	IPMI_PROTOCOL_BT15		0x8
#define	IPMI_PROTOCOL_TMODE		0x9
#define	IPMI_PROTOCOL_OEM1		0xC
#define	IPMI_PROTOCOL_OEM2		0xD
#define	IPMI_PROTOCOL_OEM3		0xE
#define	IPMI_PROTOCOL_OEM4		0xF

/*
 * Channel Medium Types.  See section 6.5.
 */
#define	IPMI_MEDIUM_IPMB		0x1
#define	IPMI_MEDIUM_ICMB10		0x2
#define	IPMI_MEDIUM_ICMB09		0x3
#define	IPMI_MEDIUM_8023LAN		0x4
#define	IPMI_MEDIUM_RS232		0x5
#define	IPMI_MEDIUM_OTHERLAN		0x6
#define	IPMI_MEDIUM_PCISMBUS		0x7
#define	IPMI_MEDIUM_SMBUS10		0x8
#define	IPMI_MEDIUM_SMBUS20		0x9
#define	IPMI_MEDIUM_USB1		0xA
#define	IPMI_MEDIUM_USB2		0xB
#define	IPMI_MEDIUM_SYSTEM		0xC

/*
 * LAN Configuration.  See section 23.  While the underlying mechanism is
 * implemented via a sequence of get/set parameter commands, we assume that
 * consumers prefer to get and set information in chunks, and therefore expose
 * the configuration as a structure, with some of the less useful fields
 * removed.  When making changes, the consumer specifies which fields to apply
 * along with the structure the library takes care of the rest of the work.
 *
 * This can be expanded in the future as needed.
 */

typedef struct ipmi_lan_config {
	boolean_t	ilc_set_in_progress;
	uint32_t	ilc_ipaddr;
	uint8_t		ilc_ipaddr_source;
	uint8_t		ilc_macaddr[6];
	uint32_t	ilc_subnet;
	uint32_t	ilc_gateway_addr;
} ipmi_lan_config_t;

#define	IPMI_LAN_SRC_UNSPECIFIED	0x0
#define	IPMI_LAN_SRC_STATIC		0x1
#define	IPMI_LAN_SRC_DHCP		0x2
#define	IPMI_LAN_SRC_BIOS		0x3
#define	IPMI_LAN_SRC_OTHER		0x4

#define	IPMI_LAN_SET_IPADDR		0x01
#define	IPMI_LAN_SET_IPADDR_SOURCE	0x02
#define	IPMI_LAN_SET_MACADDR		0x04
#define	IPMI_LAN_SET_SUBNET		0x08
#define	IPMI_LAN_SET_GATEWAY_ADDR	0x10

#define	IPMI_CMD_SET_LAN_CONFIG		0x01
#define	IPMI_CMD_GET_LAN_CONFIG		0x02

extern int ipmi_lan_get_config(ipmi_handle_t *, int,
    ipmi_lan_config_t *);
extern int ipmi_lan_set_config(ipmi_handle_t *, int, ipmi_lan_config_t *, int);

/*
 * SEL (System Event Log) commands.  Currently the library only provides
 * commands for reading the SEL.
 */

/*
 * 31.2 Get SEL Info Command
 */
#define	IPMI_CMD_GET_SEL_INFO		0x40

typedef struct ipmi_sel_info {
	uint8_t		isel_version;
	uint16_t	isel_entries;
	uint16_t	isel_free;
	uint32_t	isel_add_ts;
	uint32_t	isel_erase_ts;
	DECL_BITFIELD6(
	    isel_supp_allocation	:1,
	    isel_supp_reserve		:1,
	    isel_supp_partial		:1,
	    isel_supp_delete		:1,
	    __reserved			:3,
	    isel_overflow		:1);
} ipmi_sel_info_t;

extern ipmi_sel_info_t *ipmi_sel_get_info(ipmi_handle_t *);
extern boolean_t ipmi_sdr_changed(ipmi_handle_t *);
extern int ipmi_sdr_refresh(ipmi_handle_t *);

/*
 * 32.1 SEL Event Records
 */
typedef struct ipmi_sel_event {
	uint16_t	isel_ev_next;
	uint16_t	isel_ev_recid;
	uint8_t		isel_ev_rectype;
	uint32_t	isel_ev_ts;
	DECL_BITFIELD2(
	    isel_ev_software	:1,
	    isel_ev_addr_or_id	:7);
	DECL_BITFIELD3(
	    isel_ev_lun		:2,
	    __reserved		:2,
	    isel_ev_channel	:4);
	uint8_t		isel_ev_rev;
	uint8_t		isel_ev_sensor_type;
	uint8_t		isel_ev_sensor_number;
	DECL_BITFIELD2(
	    isel_ev_type	:7,
	    isel_ev_dir		:1);
	uint8_t		isel_ev_data[3];
} ipmi_sel_event_t;

#define	IPMI_EV_REV15		0x04
#define	IPMI_EV_REV1		0x03

#define	IPMI_SEL_SYSTEM		0x02
#define	IPMI_SEL_OEMTS_LO	0xC0
#define	IPMI_SEL_OEMTS_HI	0xDF
#define	IPMI_SEL_OEM_LO		0xE0
#define	IPMI_SEL_OEM_HI		0xFF

#define	IPMI_EV_ASSERT		0x0
#define	IPMI_EV_DEASSERT	0x1

/*
 * 32.2 OEM SEL Record (with timestamp)
 */
typedef struct ipmi_sel_oem_ts {
	uint16_t	isel_oem_next;
	uint16_t	isel_oem_id;
	uint8_t		isel_oem_type;
	uint32_t	isel_oem_ts;
	uint8_t		isel_oem_devid[3];
	uint8_t		isel_oem_data[6];
} ipmi_sel_oem_ts_t;

/*
 * 32.3 OEM SEL Record (no timestamp)
 */
typedef struct ipmi_sel_oem {
	uint16_t	isel_oem_next;
	uint16_t	isel_oem_id;
	uint8_t		isel_oem_type;
	uint8_t		isel_oem_data[13];
} ipmi_sel_oem_t;

/*
 * 29.3 Platform Event Message Command.
 */
typedef struct ipmi_platform_event_message {
	uint8_t		ipem_generator;
	uint8_t		ipem_rev;
	uint8_t		ipem_sensor_type;
	uint8_t		ipem_sensor_num;
	DECL_BITFIELD2(
	    ipem_event_type	:7,
	    ipem_event_dir	:1);
	uint8_t		ipem_event_data[3];
} ipmi_platform_event_message_t;

#define	IPMI_CMD_PLATFORM_EVENT_MESSAGE	0x02

extern int ipmi_event_platform_message(ipmi_handle_t *,
    ipmi_platform_event_message_t *);

/*
 * 29.7 Event Data Field Formats.  Consumers can cast the data field of the
 * event record to the appropriate type depending on the sensor class.
 */

typedef struct ipmi_event_threshold {
	DECL_BITFIELD3(
	    iev_offset		:4,
	    iev_desc_byte3	:2,
	    iev_desc_byte2	:2);
	uint8_t		iev_reading;
	uint8_t		iev_threshold;
} ipmi_event_threshold_t;

#define	IPMI_EV_DESC_UNSPECIFIED	0x00
#define	IPMI_EV_DESC_TRIGGER		0x01
#define	IPMI_EV_DESC_OEM		0x02
#define	IPMI_EV_DESC_SPECIFIC		0x03

typedef struct ipmi_event_discrete {
	DECL_BITFIELD3(
	    iev_offset		:4,
	    iev_desc_byte3	:2,
	    iev_desc_byte2	:2);
	DECL_BITFIELD2(
	    iev_offset_type	:4,
	    iev_offset_severity	:4);
	uint8_t		iev_oem_code;
} ipmi_event_discrete_t;

#define	IPMI_EV_DESC_PREVSTATE		0x01
#define	IPMI_EV_DESC_SPECIFIC		0x03

typedef struct ipmi_event_oem {
	DECL_BITFIELD3(
	    iev_offset		:4,
	    iev_desc_byte3	:2,
	    iev_desc_byte2	:2);
	DECL_BITFIELD2(
	    iev_offset_type	:4,
	    iev_offset_severity	:4);
	uint8_t		iev_oem_code;
} ipmi_event_oem_t;

/*
 * Get SEL Entry Command.  See section 31.5.  We don't support partial reads, so
 * this interface is quite a bit simpler than in the spec.  We default to
 * returning event records, though the consumer should check the type field and
 * cast it to the appropriate type if it is no IPMI_SEL_SYSTEM.
 */
#define	IPMI_CMD_GET_SEL_ENTRY		0x43

extern ipmi_sel_event_t *ipmi_sel_get_entry(ipmi_handle_t *, uint16_t);

#define	IPMI_SEL_FIRST_ENTRY		0x0000
#define	IPMI_SEL_LAST_ENTRY		0xFFFF

/*
 * SEL time management.  See sections 31.10 and 31.11.
 */
#define	IPMI_CMD_GET_SEL_TIME		0x48
#define	IPMI_CMD_SET_SEL_TIME		0x49
#define	IPMI_CMD_GET_SEL_UTC_OFFSET	0x5C
#define	IPMI_CMD_SET_SEL_UTC_OFFSET	0x5D

extern int ipmi_sel_get_time(ipmi_handle_t *, uint32_t *);
extern int ipmi_sel_set_time(ipmi_handle_t *, uint32_t);
extern int ipmi_sel_get_utc_offset(ipmi_handle_t *, int *);
extern int ipmi_sel_set_utc_offset(ipmi_handle_t *, int);

/*
 * SDR (Sensor Device Record) requests.  A cache of the current SDR repository
 * is kept as part of the IPMI handle and updated when necessary.  This does the
 * work of processing the SDR names and providing an easy way to lookup
 * individual records and iterate over all records.
 */

/*
 * Get SDR Repository Info Command.  See section 33.9.
 */
#define	IPMI_CMD_GET_SDR_INFO		0x20

typedef struct ipmi_sdr_info {
	uint8_t		isi_version;
	uint16_t	isi_record_count;
	uint16_t	isi_free_space;
	uint32_t	isi_add_ts;
	uint32_t	isi_erase_ts;
	DECL_BITFIELD7(
	    isi_supp_allocation		:1,
	    isi_supp_reserve		:1,
	    isi_supp_partial		:1,
	    isi_supp_delete		:1,
	    __reserved			:1,
	    isi_modal			:2,
	    isi_overflow		:1);
} ipmi_sdr_info_t;

extern ipmi_sdr_info_t *ipmi_sdr_get_info(ipmi_handle_t *);

/*
 * Reserve repository command.  See section 33.11.
 */
#define	IPMI_CMD_RESERVE_SDR_REPOSITORY	0x22

/*
 * Get SDR command.  See section 33.12.  This command accesses the raw SDR
 * repository.  Clients can also use the lookup functions to retrieve a
 * particular SDR record by name.
 *
 * The list of possible types is indicated in the sub-chapters of section 43.
 */
typedef struct ipmi_sdr {
	uint16_t	is_id;
	uint8_t		is_version;
	uint8_t		is_type;
	uint8_t		is_length;
	uint8_t		is_record[1];
} ipmi_sdr_t;
#define	IPMI_CMD_GET_SDR		0x23

#define	IPMI_SDR_FIRST			0x0000
#define	IPMI_SDR_LAST			0xFFFF

extern ipmi_sdr_t *ipmi_sdr_get(ipmi_handle_t *, uint16_t, uint16_t *);

/*
 * Full Sensor Record.  See 43.1
 */
#define	IPMI_SDR_TYPE_FULL_SENSOR		0x01

typedef struct ipmi_sdr_full_sensor {
	/* RECORD KEY BYTES */
	uint8_t		is_fs_owner;
	DECL_BITFIELD3(
	    is_fs_sensor_lun			:2,
	    __reserved1				:2,
	    is_fs_channel			:4);
	uint8_t		is_fs_number;
	/* RECORD BODY BYTES */
	uint8_t		is_fs_entity_id;
	DECL_BITFIELD2(
	    is_fs_entity_instance		:7,
	    is_fs_entity_logical		:1);
	DECL_BITFIELD8(
	    is_fs_sensor_scanning_enabled	:1,
	    is_fs_event_generation_enabled	:1,
	    is_fs_init_sensor_type		:1,
	    is_fs_init_hysteresis		:1,
	    is_fs_init_thresholds		:1,
	    is_fs_init_events			:1,
	    is_fs_init_scanning			:1,
	    is_fs_settable			:1);
	DECL_BITFIELD5(
	    is_fs_event_support			:2,
	    is_fs_threshold_support		:2,
	    is_fs_hysteresis_support		:2,
	    is_fs_rearm_support			:1,
	    is_fs_ignore			:1);
	uint8_t		is_fs_type;
	uint8_t		is_fs_reading_type;
	uint16_t	is_fs_assert_mask;
	uint16_t	is_fs_deassert_mask;
	uint16_t	is_fs_reading_mask;
	DECL_BITFIELD4(
	    is_fs_units_isprcnt			:1,
	    is_fs_mod_unit			:2,
	    is_fs_rate_unit			:3,
	    is_fs_analog_fmt			:2);
	uint8_t		is_fs_unit2;
	uint8_t		is_fs_unit3;
	/* Linearization */
	DECL_BITFIELD2(
	    is_fs_sensor_linear_type		:7,
	    __reserved2				:1);
	/* M, Tolerance */
	uint16_t	is_fs_mtol;
	/* B, Accuracy, R exp, B exp */
	uint32_t	is_fs_bacc;
	DECL_BITFIELD4(
	    is_fs_nominal_reading_spec		:1,
	    is_fs_normal_max_spec		:1,
	    is_fs_normal_min_spec		:1,
	    __reserved3				:5);
	uint8_t	is_fs_nominal_reading;
	uint8_t	is_fs_normal_maximum;
	uint8_t	is_fs_normal_minimum;
	uint8_t	is_fs_max;
	uint8_t	is_fs_min;
	uint8_t is_fs_upper_nonrecov;
	uint8_t	is_fs_upper_critical;
	uint8_t	is_fs_upper_noncrit;
	uint8_t	is_fs_lower_nonrecov;
	uint8_t	is_fs_lower_critical;
	uint8_t	is_fs_lower_noncrit;
	uint8_t		is_fs_hysteresis_positive;
	uint8_t		is_fs_hysteresis_negative;
	uint16_t	__reserved4;
	uint8_t		is_fs_oem;
	DECL_BITFIELD3(
	    is_fs_idlen				:5,
	    __reserved5				:1,
	    is_fs_idtype			:2);
	char		is_fs_idstring[1];
} ipmi_sdr_full_sensor_t;

#define	IPMI_SDR_TYPE_COMPACT_SENSOR		0x02

/*
 * Compact Sensor Record.  See section 43.2
 */
typedef struct ipmi_sdr_compact_sensor {
	/* RECORD KEY BYTES */
	uint8_t		is_cs_owner;
	DECL_BITFIELD3(
	    is_cs_sensor_lun			:2,
	    is_cs_fru_lun			:2,
	    is_cs_channel			:4);
	uint8_t		is_cs_number;
	/* RECORD BODY BYTES */
	uint8_t		is_cs_entity_id;
	DECL_BITFIELD2(
	    is_cs_entity_instance		:7,
	    is_cs_entity_logical		:1);
	DECL_BITFIELD8(
	    is_cs_sensor_scanning_enabled	:1,
	    is_cs_event_generation_enabled	:1,
	    is_cs_init_sensor_type		:1,
	    is_cs_init_hysteresis		:1,
	    __reserved1				:1,
	    is_cs_init_events			:1,
	    is_cs_init_scanning			:1,
	    is_cs_settable			:1);
	DECL_BITFIELD5(
	    is_cs_event_support			:2,
	    is_cs_threshold_support		:2,
	    is_cs_hysteresis_support		:2,
	    is_cs_rearm_support			:1,
	    is_cs_ignore			:1);
	uint8_t		is_cs_type;
	uint8_t		is_cs_reading_type;
	uint16_t	is_cs_assert_mask;
	uint16_t	is_cs_deassert_mask;
	uint16_t	is_cs_reading_mask;
	DECL_BITFIELD4(
	    is_cs_units_isprcnt			:1,
	    is_cs_mod_unit			:2,
	    is_cs_rate_unit			:3,
	    __reserved2				:2);
	uint8_t		is_cs_unit2;
	uint8_t		is_cs_unit3;
	DECL_BITFIELD3(
	    is_cs_share_count			:4,
	    is_cs_modifier_type			:2,
	    is_cs_direction			:2);
	DECL_BITFIELD2(
	    is_cs_modifier_offset		:7,
	    is_cs_sharing			:1);
	uint8_t		is_cs_hysteresis_positive;
	uint8_t		is_cs_hysteresis_negative;
	uint16_t	__reserved3;
	uint8_t		__reserved4;
	uint8_t		is_cs_oem;
	DECL_BITFIELD3(
	    is_cs_idlen				:5,
	    __reserved5				:1,
	    is_cs_idtype			:2);
	char		is_cs_idstring[1];
} ipmi_sdr_compact_sensor_t;

/*
 * Threshold sensor masks for is_cs_assert_mask and is_cs_deassert_mask.
 */
#define	IPMI_SENSOR_RETURN_NONRECOV	0x4000
#define	IPMI_SENSOR_RETURN_CRIT		0x2000
#define	IPMI_SENSOR_RETURN_NONCRIT	0x1000

#define	IPMI_SENSOR_MASK_UPPER_NONRECOV_HI	0x0800
#define	IPMI_SENSOR_MASK_UPPER_NONRECOV_LO	0x0400
#define	IPMI_SENSOR_MASK_UPPER_CRIT_HI		0x0200
#define	IPMI_SENSOR_MASK_UPPER_CRIT_LO		0x0100
#define	IPMI_SENSOR_MASK_UPPER_NONCRIT_HI	0x0080
#define	IPMI_SENSOR_MASK_UPPER_NONCRIT_LO	0x0040
#define	IPMI_SENSOR_MASK_LOWER_NONRECOV_HI	0x0020
#define	IPMI_SENSOR_MASK_LOWER_NONRECOV_LO	0x0010
#define	IPMI_SENSOR_MASK_LOWER_CRIT_HI		0x0008
#define	IPMI_SENSOR_MASK_LOWER_CRIT_LO		0x0004
#define	IPMI_SENSOR_MASK_LOWER_NONCRIT_HI	0x0002
#define	IPMI_SENSOR_MASK_LOWER_NONCRIT_LO	0x0001

/*
 * Threshold sensor masks for is_cs_reading_mask.
 */
#define	IPMI_SENSOR_SETTABLE_UPPER_NONRECOV	0x2000
#define	IPMI_SENSOR_SETTABLE_UPPER_CRIT		0x1000
#define	IPMI_SENSOR_SETTABLE_UPPER_NONCRIT	0x0800
#define	IPMI_SENSOR_SETTABLE_LOWER_NONRECOV	0x0400
#define	IPMI_SENSOR_SETTABLE_LOWER_CRIT		0x0200
#define	IPMI_SENSOR_SETTABLE_LOWER_NONCRIT	0x0100
#define	IPMI_SENSOR_READABLE_UPPER_NONRECOV	0x0020
#define	IPMI_SENSOR_READABLE_UPPER_CRIT		0x0010
#define	IPMI_SENSOR_READABLE_UPPER_NONCRIT	0x0008
#define	IPMI_SENSOR_READABLE_LOWER_NONRECOV	0x0004
#define	IPMI_SENSOR_READABLE_LOWER_CRIT		0x0002
#define	IPMI_SENSOR_READABLE_LOWER_NONCRIT	0x0001

/*
 * Values for is_cs_reading_type.  See table 42-2.
 */
#define	IPMI_RT_THRESHOLD			0x01
#define	IPMI_RT_USAGE				0x02
#define	IPMI_RT_STATE				0x03
#define	IPMI_RT_PREDFAIL			0x04
#define	IPMI_RT_LIMIT				0x05
#define	IPMI_RT_PERFORMANCE			0x06
#define	IPMI_RT_SEVERITY			0x07
#define	IPMI_RT_PRESENT				0x08
#define	IPMI_RT_ENABLED				0x09
#define	IPMI_RT_AVAILABILITY			0x0A
#define	IPMI_RT_REDUNDANCY			0x0B
#define	IPMI_RT_ACPI				0x0C
#define	IPMI_RT_SPECIFIC			0x6F

/*
 * Bitmasks based on above reading types.  See table 42-2
 */
#define	IPMI_SR_THRESHOLD_LOWER_NONCRIT_LOW	0x0001
#define	IPMI_SR_THRESHOLD_LOWER_NONCRIT_HIGH	0x0002
#define	IPMI_SR_THRESHOLD_LOWER_CRIT_LOW	0x0004
#define	IPMI_SR_THRESHOLD_LOWER_CRIT_HIGH	0x0008
#define	IPMI_SR_THRESHOLD_LOWER_NONRECOV_LOW	0x0010
#define	IPMI_SR_THRESHOLD_LOWER_NONRECOV_HIGH	0x0020
#define	IPMI_SR_THRESHOLD_UPPER_NONCRIT_LOW	0x0040
#define	IPMI_SR_THRESHOLD_UPPER_NONCRIT_HIGH	0x0080
#define	IPMI_SR_THRESHOLD_UPPER_CRIT_LOW	0x0100
#define	IPMI_SR_THRESHOLD_UPPER_CRIT_HIGH	0x0200
#define	IPMI_SR_THRESHOLD_UPPER_NONRECOV_LOW	0x0400
#define	IPMI_SR_THRESHOLD_UPPER_NONRECOV_HIGH	0x0800

#define	IPMI_SR_USAGE_IDLE			0x0001
#define	IPMI_SR_USAGE_ACTIVE			0x0002
#define	IPMI_SR_USAGE_BUSY			0x0004

#define	IPMI_SR_STATE_DEASSERT			0x0001
#define	IPMI_SR_STATE_ASSERT			0x0002

#define	IPMI_SR_PREDFAIL_DEASSERT		0x0001
#define	IPMI_SR_PREDFAIL_ASSERT			0x0002

#define	IPMI_SR_LIMIT_NOTEXCEEDED		0x0001
#define	IPMI_SR_LIMIT_EXCEEDED			0x0002

#define	IPMI_SR_PERFORMANCE_MET			0x0001
#define	IPMI_SR_PERFORMANCE_LAGS		0x0002

#define	IPMI_SR_SEVERITY_TO_OK			0x0001
#define	IPMI_SR_SEVERITY_OK_TO_NONCRIT		0x0002
#define	IPMI_SR_SEVERITY_LESS_TO_CRIT		0x0004
#define	IPMI_SR_SEVERITY_LESS_TO_NONRECOV	0x0008
#define	IPMI_SR_SEVERITY_MORE_TO_NONCRIT	0x0010
#define	IPMI_SR_SEVERITY_NONRECOV_TO_CRIT	0x0020
#define	IPMI_SR_SEVERITY_TO_NONRECOV		0x0040
#define	IPMI_SR_SEVERITY_MONITOR		0x0080
#define	IPMI_SR_SEVERITY_INFO			0x0100

#define	IPMI_SR_PRESENT_DEASSERT		0x0001
#define	IPMI_SR_PRESENT_ASSERT			0x0002

#define	IPMI_SR_ENABLED_DEASSERT		0x0001
#define	IPMI_SR_ENABLED_ASSERT			0x0002

#define	IPMI_SR_AVAILABILITY_RUNNING		0x0001
#define	IPMI_SR_AVAILABILITY_INTEST		0x0002
#define	IPMI_SR_AVAILABILITY_POWEROFF		0x0004
#define	IPMI_SR_AVAILABILITY_ONLINE		0x0008
#define	IPMI_SR_AVAILABILITY_OFFLINE		0x0010
#define	IPMI_SR_AVAILABILITY_OFFDUTY		0x0020
#define	IPMI_SR_AVAILABILITY_DEGRADED		0x0040
#define	IPMI_SR_AVAILABILITY_POWERSAVE		0x0080
#define	IPMI_SR_AVAILABILITY_INSTALLERR		0x0100

#define	IPMI_SR_REDUNDANCY_FULL			0x0001
#define	IPMI_SR_REDUNDANCY_LOST			0x0002
#define	IPMI_SR_REDUNDANCY_DEGRADED		0x0004
#define	IPMI_SR_REDUNDANCY_NONE_MINIMAL		0x0008
#define	IPMI_SR_REDUNDANCY_NONE_REGAINED	0x0010
#define	IPMI_SR_REDUNDANCY_NONE_INSUFFFICIENT	0x0020
#define	IPMI_SR_REDUNDANCY_DEG_FROM_FULL	0x0040
#define	IPMI_SR_REDUNDANCY_DEG_FROM_NON		0x0080

#define	IPMI_SR_ACPI_DO				0x0001
#define	IPMI_SR_ACPI_D1				0x0002
#define	IPMI_SR_ACPI_D2				0x0004
#define	IPMI_SR_ACPI_D3				0x0008

/*
 * Bitmasks for sensor-specific reading type (0x6F).  See section 42.2.
 */
#define	IPMI_ST_RESERVED			0x00
#define	IPMI_ST_TEMP				0x01
#define	IPMI_ST_VOLTAGE				0x02
#define	IPMI_ST_CURRENT				0x03
#define	IPMI_ST_FAN				0x04
#define	IPMI_ST_PHYSICAL			0x05

#define	IPMI_EV_PHYSICAL_GENERAL		0x0001
#define	IPMI_EV_PHYSICAL_BAY			0x0002
#define	IPMI_EV_PHYSICAL_CARD			0x0004
#define	IPMI_EV_PHYSICAL_PROCESSOR		0x0008
#define	IPMI_EV_PHYSICAL_LAN			0x0010
#define	IPMI_EV_PHYSICAL_DOCK			0x0020
#define	IPMI_EV_PHYSICAL_FAN			0x0040

#define	IPMI_ST_PLATFORM			0x06

#define	IPMI_EV_PLATFORM_SECURE			0x0001
#define	IPMI_EV_PLATFORM_USER_PASS		0x0002
#define	IPMI_EV_PLATFORM_SETUP_PASS		0x0004
#define	IPMI_EV_PLATFORM_NETWORK_PASS		0x0008
#define	IPMI_EV_PLATFORM_OTHER_PASS		0x0010
#define	IPMI_EV_PLATFORM_OUT_OF_BAND		0x0020

#define	IPMI_ST_PROCESSOR			0x07

#define	IPMI_EV_PROCESSOR_IERR			0x0001
#define	IPMI_EV_PROCESSOR_THERMAL		0x0002
#define	IPMI_EV_PROCESSOR_FRB1			0x0004
#define	IPMI_EV_PROCESSOR_FRB2			0x0008
#define	IPMI_EV_PROCESSOR_FRB3			0x0010
#define	IPMI_EV_PROCESSOR_CONFIG		0x0020
#define	IPMI_EV_PROCESSOR_SMBIOS		0x0040
#define	IPMI_EV_PROCESSOR_PRESENT		0x0080
#define	IPMI_EV_PROCESSOR_DISABLED		0x0100
#define	IPMI_EV_PROCESSOR_TERMINATOR		0x0200
#define	IPMI_EV_PROCESSOR_THROTTLED		0x0400

#define	IPMI_ST_POWER_SUPPLY			0x08

#define	IPMI_EV_POWER_SUPPLY_PRESENT		0x0001
#define	IPMI_EV_POWER_SUPPLY_FAILURE		0x0002
#define	IPMI_EV_POWER_SUPPLY_PREDFAIL		0x0004
#define	IPMI_EV_POWER_SUPPLY_INPUT_LOST		0x0008
#define	IPMI_EV_POWER_SUPPLY_INPUT_RANGE	0x0010
#define	IPMI_EV_POWER_SUPPLY_INPUT_RANGE_PRES	0x0020
#define	IPMI_EV_POWER_SUPPLY_CONFIG_ERR		0x0040

#define	IPMI_ST_POWER_UNIT			0x09

#define	IPMI_EV_POWER_UNIT_OFF			0x0001
#define	IPMI_EV_POWER_UNIT_CYCLE		0x0002
#define	IPMI_EV_POWER_UNIT_240_DOWN		0x0004
#define	IPMI_EV_POWER_UNIT_INTERLOCK_DOWN	0x0008
#define	IPMI_EV_POWER_UNIT_AC_LOST		0x0010
#define	IPMI_EV_POWER_UNIT_SOFT_FAILURE		0x0020
#define	IPMI_EV_POWER_UNIT_FAIL			0x0040
#define	IPMI_EV_POWER_UNIT_PREDFAIL		0x0080

#define	IPMI_ST_COOLING				0x0A
#define	IPMI_ST_OTHER				0x0B
#define	IPMI_ST_MEMORY				0x0C

#define	IPMI_EV_MEMORY_CE			0x0001
#define	IPMI_EV_MEMORY_UE			0x0002
#define	IPMI_EV_MEMORY_PARITY			0x0004
#define	IPMI_EV_MEMORY_SCRUB_FAIL		0x0008
#define	IPMI_EV_MEMORY_DISABLED			0x0010
#define	IPMI_EV_MEMORY_CE_LOG_LIMIT		0x0020
#define	IPMI_EV_MEMORY_PRESENT			0x0040
#define	IPMI_EV_MEMORY_CONFIG_ERR		0x0080
#define	IPMI_EV_MEMORY_SPARE			0x0100
#define	IPMI_EV_MEMORY_THROTTLED		0x0200
#define	IPMI_EV_MEMORY_OVERTEMP			0x0400

#define	IPMI_ST_BAY				0x0D

#define	IPMI_EV_BAY_PRESENT			0x0001
#define	IPMI_EV_BAY_FAULT			0x0002
#define	IPMI_EV_BAY_PREDFAIL			0x0004
#define	IPMI_EV_BAY_SPARE			0x0008
#define	IPMI_EV_BAY_CHECK			0x0010
#define	IPMI_EV_BAY_CRITICAL			0x0020
#define	IPMI_EV_BAY_FAILED			0x0040
#define	IPMI_EV_BAY_REBUILDING			0x0080
#define	IPMI_EV_BAY_ABORTED			0x0100

#define	IPMI_ST_POST_RESIZE			0x0E
#define	IPMI_ST_FIRMWARE			0x0F

#define	IPMI_EV_FIRMWARE_ERROR			0x0001
#define	IPMI_EV_FIRMWARE_HANG			0x0002
#define	IPMI_EV_FIRMWARE_PROGRESS		0x0004

#define	IPMI_ST_EVENT_LOG			0x10

#define	IPMI_EV_EVENT_LOG_CE			0x0001
#define	IPMI_EV_EVENT_LOG_TYPE			0x0002
#define	IPMI_EV_EVENT_LOG_RESET			0x0004
#define	IPMI_EV_EVENT_LOG_ALL			0x0008
#define	IPMI_EV_EVENT_LOG_FULL			0x0010
#define	IPMI_EV_EVENT_LOG_ALMOST_FULL		0x0020

#define	IPMI_ST_WATCHDOG1			0x11

#define	IPMI_EV_WATCHDOG_BIOS_RESET		0x0001
#define	IPMI_EV_WATCHDOG_OS_RESET		0x0002
#define	IPMI_EV_WATCHDOG_OS_SHUTDOWN		0x0004
#define	IPMI_EV_WATCHDOG_OS_PWR_DOWN		0x0008
#define	IPMI_EV_WATCHDOG_OS_PWR_CYCLE		0x0010
#define	IPMI_EV_WATCHDOG_OS_NMI_DIAG		0x0020
#define	IPMI_EV_WATCHDOG_EXPIRED		0x0040
#define	IPMI_EV_WATCHDOG_PRE_TIMEOUT_INT	0x0080

#define	IPMI_ST_SYSTEM				0x12

#define	IPMI_EV_STSTEM_RECONF			0x0001
#define	IPMI_EV_STSTEM_BOOT			0x0002
#define	IPMI_EV_STSTEM_UNKNOWN_HW_FAILURE	0x0004
#define	IPMI_EV_STSTEM_AUX_LOG_UPDATED		0x0008
#define	IPMI_EV_STSTEM_PEF_ACTION		0x0010
#define	IPMI_EV_SYSTEM_TIMETAMP_CLOCKSYNC	0x0020

#define	IPMI_ST_CRITICAL			0x13

#define	IPMI_EV_CRITICAL_EXT_NMI		0x0001
#define	IPMI_EV_CRITICAL_BUS_TIMOEOUT		0x0002
#define	IPMI_EV_CRITICAL_IO_NMI			0x0004
#define	IPMI_EV_CRITICAL_SW_NMI			0x0008
#define	IPMI_EV_CRITICAL_PCI_PERR		0x0010
#define	IPMI_EV_CRITICAL_PCI_SERR		0x0020
#define	IPMI_EV_CRITICAL_EISA_FAILSAFE		0x0040
#define	IPMI_EV_CRITICAL_BUS_CE			0x0080
#define	IPMI_EV_CRITICAL_BUS_UE			0x0100
#define	IPMI_EV_CRITICAL_FATAL_NMI		0x0200
#define	IPMI_EV_CRITICAL_BUS_FATAL_ERR		0x0400
#define	IPMI_EV_CRITICAL_BUS_DEGRADED		0x0800

#define	IPMI_ST_BUTTON				0x14

#define	IPMI_EV_BUTTON_PWR			0x0001
#define	IPMI_EV_BUTTON_SLEEP			0x0002
#define	IPMI_EV_BUTTON_RESET			0x0004
#define	IPMI_EV_BUTTON_FRU_LATCH		0x0008
#define	IPMI_EV_BUTTON_FRU_SERVICE		0x0010

#define	IPMI_ST_MODULE				0x15
#define	IPMI_ST_MICROCONTROLLER			0x16
#define	IPMI_ST_CARD				0x17
#define	IPMI_ST_CHASSIS				0x18

#define	IPMI_ST_CHIPSET				0x19

#define	IPMI_EV_CHIPSET_PWR_CTL_FAIL		0x0001

#define	IPMI_ST_FRU				0x1A
#define	IPMI_ST_CABLE				0x1B

#define	IPMI_EV_CABLE_CONNECTED			0x0001
#define	IPMI_EV_CABLE_CONFIG_ERR		0x0002

#define	IPMI_ST_TERMINATOR			0x1C

#define	IPMI_ST_BOOT				0x1D

#define	IPMI_EV_BOOT_BIOS_PWR_UP		0x0001
#define	IPMI_EV_BOOT_BIOS_HARD_RESET		0x0002
#define	IPMI_EV_BOOT_BIOS_WARM_RESET		0x0004
#define	IPMI_EV_BOOT_PXE_BOOT			0x0008
#define	IPMI_EV_BOOT_DIAG_BOOT			0x0010
#define	IPMI_EV_BOOT_OS_HARD_RESET		0x0020
#define	IPMI_EV_BOOT_OS_WARM_RESET		0x0040
#define	IPMI_EV_BOOT_SYS_RESTART		0x0080

#define	IPMI_ST_BOOT_ERROR			0x1E

#define	IPMI_EV_BOOT_ERROR_NOMEDIA		0x0001
#define	IPMI_EV_BOOT_ERROR_NON_BOOTABLE_DISK	0x0002
#define	IPMI_EV_BOOT_ERROR_NO_PXE_SERVER	0x0004
#define	IPMI_EV_BOOT_ERROR_INV_BOOT_SECT	0x0008
#define	IPMI_EV_BOOT_ERROR_USR_SELECT_TIMEOUT	0x0010

#define	IPMI_ST_BOOT_OS				0x1F

#define	IPMI_EV_BOOT_OS_A_DRV_BOOT_COMPLETE	0x0001
#define	IPMI_EV_BOOT_OS_C_DRV_BOOT_COMPLETE	0x0002
#define	IPMI_EV_BOOT_OS_PXE_BOOT_COMPLETE	0x0004
#define	IPMI_EV_BOOT_OS_DIAG_BOOT_COMPLETE	0x0008
#define	IPMI_EV_BOOT_OS_CDROM_BOOT_COMPLETE	0x0010
#define	IPMI_EV_BOOT_OS_ROM_BOOT_COMPLETE	0x0020
#define	IPMI_EV_BOOT_OS_UNSPEC_BOOT_COMPLETE	0x0040

#define	IPMI_ST_OS_SHUTDOWN			0x20

#define	IPMI_EV_OS_SHUTDOWN_LOADING		0x0001
#define	IPMI_EV_OS_SHUTDOWN_CRASH		0x0002
#define	IPMI_EV_OS_STOP_GRACEFUL		0x0004
#define	IPMI_EV_OS_SHUTDOWN_GRACEFUL		0x0008
#define	IPMI_EV_OS_SHUTDOWN_PEF			0x0010
#define	IPMI_EV_OS_SHUTDOWN_BMC			0x0020

#define	IPMI_ST_SLOT				0x21

#define	IPMI_EV_SLOT_FAULT_ASSERTED		0x0001
#define	IPMI_EV_SLOT_IDENTIFY_ASSERTED		0x0002
#define	IPMI_EV_SLOT_CONNECTED			0x0004
#define	IPMI_EV_SLOT_INSTALL_READY		0x0008
#define	IPMI_EV_SLOT_REMOVE_READY		0x0010
#define	IPMI_EV_SLOT_PWR_OFF			0x0020
#define	IPMI_EV_SLOT_REMOVED			0x0040
#define	IPMI_EV_SLOT_INTERLOCK_ASSERTED		0x0080
#define	IPMI_EV_SLOT_DISABLED			0x0100
#define	IPMI_EV_SLOT_SPARE_DEVICE		0x0200

#define	IPMI_ST_ACPI				0x22

#define	IPMI_EV_ACPI_PSTATE_S0_G0		0x0001
#define	IPMI_EV_ACPI_PSTATE_S1			0x0002
#define	IPMI_EV_ACPI_PSTATE_S2			0x0004
#define	IPMI_EV_ACPI_PSTATE_S3			0x0008
#define	IPMI_EV_ACPI_PSTATE_S4			0x0010
#define	IPMI_EV_ACPI_PSTATE_S5_G2_SOFT_OFF	0x0020
#define	IPMI_EV_ACPI_PSTATE_S4_S5_SOFT_OFF	0x0040
#define	IPMI_EV_ACPI_PSATTE_G3_MECH_OFF		0x0080
#define	IPMI_EV_ACPI_PSTATE_S1_S2_S3_SLEEP	0x0100
#define	IPMI_EV_ACPI_PSTATE_G1_SLEEP		0x0200
#define	IPMI_EV_ACPI_PSTATE_S5_OVERRIDE		0x0400
#define	IPMI_EV_ACPI_PSTATE_LEGACY_ON		0x0800
#define	IPMI_EV_ACPI_PSTATE_LEGACY_OFF		0x1000
#define	IPMI_EV_ACPI_PSTATE_UNKNOWN		0x2000

#define	IPMI_ST_WATCHDOG2			0x23

#define	IPMI_EV_WATCHDOG2_EXPIRED		0x0001
#define	IPMI_EV_WATCHDOG2_HARD_RESET		0x0002
#define	IPMI_EV_WATCHDOG2_PWR_DOWN		0x0004
#define	IPMI_EV_WATCHDOG2_PWR_CYCLE		0x0008
#define	IPMI_EV_WATCHDOG2_RESERVED1		0x0010
#define	IPMI_EV_WATCHDOG2_RESERVED2		0x0020
#define	IPMI_EV_WATCHDOG2_RESERVED3		0x0040
#define	IPMI_EV_WATCHDOG2_RESERVED4		0x0080
#define	IPMI_EV_WATCHDOG2_TIMEOUT_INT		0x0100

#define	IPMI_ST_ALERT				0x24

#define	IPMI_EV_ALERT_PLAT_PAGE			0x0001
#define	IPMI_EV_ALERT_PLAT_LAN_ALERT		0x0002
#define	IPMI_EV_ALERT_PLAT_EVT_TRAP		0x0004
#define	IPMI_EV_ALERT_PLAT_SNMP_TRAP		0x0008

#define	IPMI_ST_PRESENCE			0x25

#define	IPMI_EV_PRESENCE_PRESENT		0x0001
#define	IPMI_EV_PRESENCE_ABSENT			0x0002
#define	IPMI_EV_PRESENCE_DISABLED		0x0004

#define	IPMI_ST_ASIC				0x26

#define	IPMI_ST_LAN				0x27

#define	IPMI_EV_LAN_HEARTBEAT_LOST		0x0001
#define	IPMI_EV_LAN_HEARTBEAT			0x0002

#define	IPMI_ST_HEALTH				0x28

#define	IPMI_EV_HEALTH_SENSOR_ACC_DEGRADED	0x0001
#define	IPMI_EV_HEALTH_CNTLR_ACC_DEGRADED	0x0002
#define	IPMI_EV_HEALTH_CNTLR_OFFLINE		0x0004
#define	IPMI_EV_HEALTH_CNTLR_UNAVAIL		0x0008
#define	IPMI_EV_HEALTH_SENSOR_FAILURE		0x0010
#define	IPMI_EV_HEALTH_FRU_FAILURE		0x0020

#define	IPMI_ST_BATTERY				0x29

#define	IPMI_EV_BATTERY_LOW			0x0001
#define	IPMI_EV_BATTERY_FAILED			0x0002
#define	IPMI_EV_BATTERY_PRESENCE		0x0004

#define	IPMI_ST_AUDIT				0x2A

#define	IPMI_EV_AUDIT_SESSION_ACTIVATED		0x0001
#define	IPMI_EV_AUDIT_SESSION_DEACTIVATED	0x0002

#define	IPMI_ST_VERSION				0x2B

#define	IPMI_EV_VERSION_HW_CHANGE		0x0001
#define	IPMI_EV_VERSION_SW_CHANGE		0x0002
#define	IPMI_EV_VERSION_HW_INCOMPATIBLE		0x0004
#define	IPMI_EV_VERSION_SW_INCOMPATIBLE		0x0008
#define	IPMI_EV_VERSION_HW_INVAL		0x0010
#define	IPMI_EV_VERSION_SW_INVAL		0x0020
#define	IPMI_EV_VERSION_HW_CHANGE_SUCCESS	0x0040
#define	IPMI_EV_VERSION_SW_CHANGE_SUCCESS	0x0080

#define	IPMI_ST_FRU_STATE			0x2C

#define	IPMI_EV_FRU_STATE_NOT_INSTALLED		0x0001
#define	IPMI_EV_FRU_STATE_INACTIVE		0x0002
#define	IPMI_EV_FRU_STATE_ACT_REQ		0x0004
#define	IPMI_EV_FRU_STATE_ACT_INPROGRESS	0x0008
#define	IPMI_EV_FRU_STATE_ACTIVE		0x0010
#define	IPMI_EV_FRU_STATE_DEACT_REQ		0x0020
#define	IPMI_EV_FRU_STATE_DEACT_INPROGRESS	0x0040
#define	IPMI_EV_FRU_STATE_COMM_LOST		0x0080

/*
 * Constants for unit type codes.  See Table 43-15.
 */
#define	IPMI_UNITS_UNSPECIFIED			0x00
#define	IPMI_UNITS_DEGREES_C			0x01
#define	IPMI_UNITS_DEGREES_F			0x02
#define	IPMI_UNITS_DEGREES_K			0x03
#define	IPMI_UNITS_VOLTS			0x04
#define	IPMI_UNITS_AMPS				0x05
#define	IPMI_UNITS_WATTS			0x06
#define	IPMI_UNITS_JOULES			0x07
#define	IPMI_UNITS_COULOMBS			0x08
#define	IPMI_UNITS_VA				0x09
#define	IPMI_UNITS_NITS				0x0A
#define	IPMI_UNITS_LUMEN			0x0B
#define	IPMI_UNITS_LUX				0x0C
#define	IPMI_UNITS_CANDELA			0x0D
#define	IPMI_UNITS_KPA				0x0E
#define	IPMI_UNITS_PSI				0x0F

#define	IPMI_UNITS_NEWTON			0x10
#define	IPMI_UNITS_CFM				0x11
#define	IPMI_UNITS_RPM				0x12
#define	IPMI_UNITS_HZ				0x13
#define	IPMI_UNITS_MICROSEC			0x14
#define	IPMI_UNITS_MILLISEC			0x15
#define	IPMI_UNITS_SECS				0x16
#define	IPMI_UNITS_MIN				0x17
#define	IPMI_UNITS_HOUR				0x18
#define	IPMI_UNITS_DAY				0x19
#define	IPMI_UNITS_WEEK				0x1A
#define	IPMI_UNITS_MIL				0x1B
#define	IPMI_UNITS_INCHES			0x1C
#define	IPMI_UNITS_FEET				0x1D
#define	IPMI_UNITS_CUB_INCH			0x1E
#define	IPMI_UNITS_CUB_FEET			0x1F

#define	IPMI_UNITS_MM				0x20
#define	IPMI_UNITS_CM				0x21
#define	IPMI_UNITS_METERS			0x22
#define	IPMI_UNITS_CUB_CM			0x23
#define	IPMI_UNITS_CUB_METER			0x24
#define	IPMI_UNITS_LITERS			0x25
#define	IPMI_UNITS_FLUID_OUNCE			0x26
#define	IPMI_UNITS_RADIANS			0x27
#define	IPMI_UNITS_STERADIANS			0x28
#define	IPMI_UNITS_REVOLUTIONS			0x29
#define	IPMI_UNITS_CYCLES			0x2A
#define	IPMI_UNITS_GRAVITIES			0x2B
#define	IPMI_UNITS_OUNCE			0x2C
#define	IPMI_UNITS_POUND			0x2D
#define	IPMI_UNITS_FOOT_POUND			0x2E
#define	IPMI_UNITS_OZ_INCH			0x2F

#define	IPMI_UNITS_GAUSS			0x30
#define	IPMI_UNITS_GILBERTS			0x31
#define	IPMI_UNITS_HENRY			0x32
#define	IPMI_UNITS_MILHENRY			0x33
#define	IPMI_UNITS_FARAD			0x34
#define	IPMI_UNITS_MICROFARAD			0x35
#define	IPMI_UNITS_OHMS				0x36
#define	IPMI_UNITS_SIEMENS			0x37
#define	IPMI_UNITS_MOLE				0x38
#define	IPMI_UNITS_BECQUEREL			0x39
#define	IPMI_UNITS_PPM				0x3A
/* 0x3B is reserved */
#define	IPMI_UNITS_DECIBELS			0x3C
#define	IPMI_UNITS_DBA				0x3D
#define	IPMI_UNITS_DBC				0x3E
#define	IPMI_UNITS_GRAY				0x3F

#define	IPMI_UNITS_SIEVERT			0x40
#define	IPMI_UNITS_COLOR_TEMP_K			0x41
#define	IPMI_UNITS_BIT				0x42
#define	IPMI_UNITS_KILOBIT			0x43
#define	IPMI_UNITS_MEGABIT			0x44
#define	IPMI_UNITS_GIGABIT			0x45
#define	IPMI_UNITS_BYTE				0x46
#define	IPMI_UNITS_KILOBYTE			0x47
#define	IPMI_UNITS_MEGABYTE			0x48
#define	IPMI_UNITS_GIGABYTE			0x49
#define	IPMI_UNITS_WORD				0x4A
#define	IPMI_UNITS_DWORD			0x4B
#define	IPMI_UNITS_QWORD			0x4C
#define	IPMI_UNITS_MEMLINE			0x4D
#define	IPMI_UNITS_HIT				0x4E
#define	IPMI_UNITS_MISS				0x4F

#define	IPMI_UNITS_RETRY			0x50
#define	IPMI_UNITS_RESET			0x51
#define	IPMI_UNITS_OVERFLOW			0x52
#define	IPMI_UNITS_UNDERRUN			0x53
#define	IPMI_UNITS_COLLISION			0x54
#define	IPMI_UNITS_PACKETS			0x55
#define	IPMI_UNITS_MESSAGES			0x56
#define	IPMI_UNITS_CHARACTERS			0x57
#define	IPMI_UNITS_ERROR			0x58
#define	IPMI_UNITS_CE				0x59
#define	IPMI_UNITS_UE				0x5A
#define	IPMI_UNITS_FATAL_ERROR			0x5B
#define	IPMI_UNITS_GRAMS			0x5C

/*
 * Event-Only Record.  See section 43.3.
 */

#define	IPMI_SDR_TYPE_EVENT_ONLY		0x03

typedef struct ipmi_sdr_event_only {
	/* RECORD KEY BYTES */
	uint8_t		is_eo_owner;
	DECL_BITFIELD3(
	    is_eo_sensor_lun			:2,
	    is_eo_fru_lun			:2,
	    is_eo_channel			:4);
	uint8_t		is_eo_number;
	/* RECORD BODY BYTES */
	uint8_t		is_eo_entity_id;
	DECL_BITFIELD2(
	    is_eo_entity_instance		:7,
	    is_eo_entity_logical		:1);
	uint8_t		is_eo_sensor_type;
	uint8_t		is_eo_reading_type;
	DECL_BITFIELD3(
	    is_eo_share_count			:4,
	    is_eo_modifier_type			:2,
	    is_eo_direction			:2);
	DECL_BITFIELD2(
	    is_eo_modifier_offset		:7,
	    is_eo_sharing			:1);
	uint8_t		__reserved;
	uint8_t		is_eo_oem;
	DECL_BITFIELD3(
	    is_eo_idlen				:5,
	    __reserved1				:1,
	    is_eo_idtype			:2);
	char		is_eo_idstring[1];
} ipmi_sdr_event_only_t;

/*
 * Entity Association Record.  See section 43.4.
 */

#define	IPMI_SDR_TYPE_ENTITY_ASSOCIATION	0x08

typedef struct ipmi_sdr_entity_association {
	/* RECORD KEY BYTES */
	uint8_t		is_ea_entity_id;
	uint8_t		is_ea_entity_instance;
	DECL_BITFIELD4(
	    __reserved		:5,
	    is_ea_presence	:1,
	    is_ea_record_link	:1,
	    is_ea_range		:1);
	/* RECORD BODY BYTES */
	struct {
		uint8_t		is_ea_sub_id;
		uint8_t		is_ea_sub_instance;
	} is_ea_sub[4];
} ipmi_sdr_entity_association_t;

/*
 * Device-relative Entity Association Record.  See section 43.5.
 */

#define	IPMI_SDR_TYPE_DEVICE_RELATIVE		0x09

typedef struct ipmi_sdr_device_relative {
	/* RECORD KEY BYTES */
	uint8_t		is_dr_entity_id;
	uint8_t		is_dr_entity_instance;
	DECL_BITFIELD2(
	    __reserved1			:1,
	    is_dr_slaveaddr		:7);
	DECL_BITFIELD2(
	    __reserved2			:4,
	    is_dr_channel		:4);
	DECL_BITFIELD4(
	    __reserved			:5,
	    is_dr_presence		:1,
	    is_dr_record_link		:1,
	    is_dr_range			:1);
	/* RECORD BODY BYTES */
	struct {
		DECL_BITFIELD2(
		    __reserved3		:1,
		    is_dr_sub_slaveaddr	:7);
		DECL_BITFIELD2(
		    __reserved4		:4,
		    is_dr_sub_channel	:4);
		uint8_t		is_ea_sub_id;
		uint8_t		is_ea_sub_instance;
	} is_ea_sub[4];
} ipmi_sdr_device_relative_t;

/*
 * Generic Device Locator Record.  See section 43.7.
 */

#define	IPMI_SDR_TYPE_GENERIC_LOCATOR		0x10

typedef struct ipmi_sdr_generic_locator {
	/* RECORD KEY BYTES */
	DECL_BITFIELD2(
	    __reserved1		:1,
	    is_gl_accessaddr	:7);
	DECL_BITFIELD2(
	    is_gl_channel_msb	:1,
	    is_gl_slaveaddr	:7);
	DECL_BITFIELD3(
	    is_gl_bus		:3,
	    is_gl_lun		:2,
	    is_gl_channel	:3);
	/* RECORD BODY BYTES */
	DECL_BITFIELD2(
	    is_gl_span		:3,
	    __reserved2		:5);
	uint8_t		__reserved3;
	uint8_t		is_gl_type;
	uint8_t		is_gl_modifier;
	uint8_t		is_gl_entity;
	uint8_t		is_gl_instance;
	uint8_t		is_gl_oem;
	DECL_BITFIELD3(
	    is_gl_idlen		:5,
	    __reserved4		:1,
	    is_gl_idtype	:2);
	char		is_gl_idstring[1];
} ipmi_sdr_generic_locator_t;

/*
 * FRU Device Locator Record.  See section 43.8.
 */

#define	IPMI_SDR_TYPE_FRU_LOCATOR		0x11

typedef struct ipmi_sdr_fru_locator {
	/* RECORD KEY BYTES */
	DECL_BITFIELD2(
	    __reserved1		:1,
	    is_fl_accessaddr	:7);
	union {
		struct {
			uint8_t	_is_fl_devid;
		} _logical;
		struct {
			DECL_BITFIELD2(
			    __reserved		:1,
			    _is_fl_slaveaddr	:7);
		} _nonintelligent;
	} _devid_or_slaveaddr;
	DECL_BITFIELD4(
	    is_fl_bus		:3,
	    is_fl_lun		:2,
	    __reserved2		:2,
	    is_fl_logical	:1);
	DECL_BITFIELD2(
	    __reserved3		:4,
	    is_fl_channel	:4);
	/* RECORD BODY BYTES */
	uint8_t		__reserved4;
	uint8_t		is_fl_type;
	uint8_t		is_fl_modifier;
	uint8_t		is_fl_entity;
	uint8_t		is_fl_instance;
	uint8_t		is_fl_oem;
	DECL_BITFIELD3(
	    is_fl_idlen		:5,
	    __reserved5		:1,
	    is_fl_idtype	:2);
	char		is_fl_idstring[1];
} ipmi_sdr_fru_locator_t;

#define	is_fl_devid	_devid_or_slaveaddr._logical._is_fl_devid
#define	is_fl_slaveaddr	_devid_or_slaveaddr._nonintelligent._is_fl_slaveaddr

/*
 * Management Controller Device Locator Record.  See section 43.9
 */

#define	IPMI_SDR_TYPE_MANAGEMENT_LOCATOR	0x12

typedef struct ipmi_sdr_management_locator {
	/* RECORD KEY BYTES */
	DECL_BITFIELD2(
	    __reserved1			:1,
	    is_ml_devaddr		:7);
	DECL_BITFIELD2(
	    is_ml_channel		:4,
	    __reserved2			:4);
	/* RECORD BODY BYTES */
	DECL_BITFIELD7(
	    is_ml_init_message		:2,
	    is_ml_init_log		:1,
	    is_ml_init_controller_log	:1,
	    __reserved3			:1,
	    is_ml_static		:1,
	    is_ml_acpi_device		:1,
	    is_ml_acpi_system		:1);
	DECL_BITFIELD8(
	    is_ml_supp_sensor		:1,
	    is_ml_supp_sdr		:1,
	    is_ml_supp_sel		:1,
	    is_ml_supp_fru		:1,
	    is_ml_supp_event_receiver	:1,
	    is_ml_supp_event_generator	:1,
	    is_ml_supp_bridge		:1,
	    is_ml_supp_chassis		:1);
	uint8_t		__reserved4;
	uint16_t	__reserved5;
	uint8_t		is_ml_entity_id;
	uint8_t		is_ml_entity_instance;
	uint8_t		is_ml_oem;
	DECL_BITFIELD3(
	    is_ml_idlen		:5,
	    __reserved6		:1,
	    is_ml_idtype	:2);
	char		is_ml_idstring[1];
} ipmi_sdr_management_locator_t;

#define	IPMI_MESSAGE_INIT_ENABLE		0x0
#define	IPMI_MESSAGE_INIT_DISABLE		0x1
#define	IPMI_MESSAGE_INIT_NONE			0x2

/*
 *  Management Controller Confirmation Record.  See section 43.10
 */

#define	IPMI_SDR_TYPE_MANAGEMENT_CONFIRMATION	0x13

typedef struct ipmi_sdr_management_confirmation {
	/* RECORD KEY BYTES */
	DECL_BITFIELD2(
	    __reserved1		:1,
	    is_mc_slaveaddr	:7);
	uint8_t		is_mc_deviceid;
	DECL_BITFIELD2(
	    is_mc_dev_revision	:4,
	    is_mc_channel	:4);
	/* RECORD BODY BYTES */
	DECL_BITFIELD2(
	    is_mc_major_rev	:7,
	    __reserved2		:1);
	uint8_t		is_mc_minor_rev;
	uint8_t		is_mc_impi_ver;
	uint8_t		is_mc_manufacturer[3];
	uint16_t	is_mc_product;
	uint8_t		is_mc_guid[16];
} ipmi_sdr_management_confirmation_t;

/*
 * BMC Message Channel Info Record.  See esction 43.11.
 */

#define	IPMI_SDR_TYPE_BMC_MESSAGE_CHANNEL	0x14

typedef struct ipmi_sdr_bmc_channel {
	/* RECORD BODY BYTES */
	struct {
		DECL_BITFIELD3(
		    is_bc_protocol	:4,
		    is_bc_receive_lun	:3,
		    is_bc_transmit	:1);
	} is_bc_channel[8];
	uint8_t		is_bc_interrupt_type;
	uint8_t		is_bc_buffer_type;
	uint8_t		__reserved;
} ipmi_sdr_bmc_channel_t;

/*
 * OEM Record.  See ction 43.12.
 */

#define	IPMI_SDR_TYPE_OEM			0xC0

typedef struct ipmi_sdr_oem {
	uint8_t		is_oem_manufacturer[3];
	uint8_t		is_oem_data[1];
} ipmi_sdr_oem_t;

/*
 * Iterate over the SDR repository.  This function does the work of parsing the
 * name when available, and keeping the repository in a consistent state.
 */
extern int ipmi_sdr_iter(ipmi_handle_t *,
    int (*)(ipmi_handle_t *, const char *, ipmi_sdr_t *, void *), void *);

/*
 * Lookup the given sensor type by name.  These functions automatically read in
 * and cache the complete SDR repository.
 */
extern ipmi_sdr_t *ipmi_sdr_lookup(ipmi_handle_t *, const char *);
extern ipmi_sdr_fru_locator_t *ipmi_sdr_lookup_fru(ipmi_handle_t *,
    const char *);
extern ipmi_sdr_generic_locator_t *ipmi_sdr_lookup_generic(ipmi_handle_t *,
    const char *);
extern ipmi_sdr_compact_sensor_t *ipmi_sdr_lookup_compact_sensor(
    ipmi_handle_t *, const char *);
extern ipmi_sdr_full_sensor_t *ipmi_sdr_lookup_full_sensor(
    ipmi_handle_t *, const char *);

/*
 * Entity ID codes.  See table 43.13.
 */
#define	IPMI_ET_UNSPECIFIED		0x00
#define	IPMI_ET_OTHER			0x01
#define	IPMI_ET_UNKNOWN			0x02
#define	IPMI_ET_PROCESSOR		0x03
#define	IPMI_ET_DISK			0x04
#define	IPMI_ET_PERIPHERAL		0x05
#define	IPMI_ET_MANAGEMENT_MODULE	0x06
#define	IPMI_ET_MOTHERBOARD		0x07
#define	IPMI_ET_MEMORY_MODULE		0x08
#define	IPMI_ET_PROCESSOR_MODULE	0x09
#define	IPMI_ET_PSU			0x0A
#define	IPMI_ET_CARD			0x0B
#define	IPMI_ET_FRONT_PANEL		0x0C
#define	IPMI_ET_BACK_PANEL		0x0D
#define	IPMI_ET_POWER_BOARD		0x0E
#define	IPMI_ET_BACKPLANE		0x0F
#define	IPMI_ET_EXPANSION_BOARD		0x10
#define	IPMI_ET_OTHER_BOARD		0x11
#define	IPMI_ET_PROCESSOR_BOARD		0x12
#define	IPMI_ET_POWER_DOMAIN		0x13
#define	IPMI_ET_POWER_CONVERTER		0x14
#define	IPMI_ET_POWER_MANAGEMENT	0x15
#define	IPMI_ET_BACK_CHASSIS		0x16
#define	IPMI_ET_SYSTEM_CHASSIS		0x17
#define	IPMI_ET_SUB_CHASSIS		0x18
#define	IPMI_ET_OTHER_CHASSIS		0x19
#define	IPMI_ET_DISK_BAY		0x1A
#define	IPMI_ET_PERIPHERAL_BAY		0x1B
#define	IPMI_ET_DEVICE_BAY		0x1C
#define	IPMI_ET_FAN			0x1D
#define	IPMI_ET_COOLING_DOMAIN		0x1E
#define	IPMI_ET_CABLE			0x1F
#define	IPMI_ET_MEMORY_DEVICE		0x20
#define	IPMI_ET_MANAGEMENT_SOFTWARE	0x21
#define	IPMI_ET_SYSTEM_FIRMWARE		0x22
#define	IPMI_ET_OS			0x23
#define	IPMI_ET_SYSTEM_BUS		0x24
#define	IPMI_ET_GROUP			0x25
#define	IPMI_ET_REMOTE			0x26
#define	IPMI_ET_ENVIRONMENT		0x27
#define	IPMI_ET_BATTERY			0x28
#define	IPMI_ET_BLADE			0x29
#define	IPMI_ET_SWITCH			0x2A
#define	IPMI_ET_PROCMEM_MODULE		0x2B
#define	IPMI_ET_IO_MODULE		0x2C
#define	IPMI_ET_PROCIO_MODULE		0x2D
#define	IPMI_ET_CONTROLLER_FIRMWARE	0x2E
#define	IPMI_ET_CHANNEL			0x2F
#define	IPMI_ET_PCI			0x30
#define	IPMI_ET_PCIE			0x31
#define	IPMI_ET_SCSI			0x32
#define	IPMI_ET_SATA_SAS		0x33
#define	IPMI_ET_FSB			0x34
#define	IPMI_ET_RTC			0x35

/*
 * Get Sensor Reading.  See section 35.14.
 */

#define	IPMI_CMD_GET_SENSOR_READING	0x2d

typedef struct ipmi_sensor_reading {
	uint8_t		isr_reading;
	DECL_BITFIELD4(
	    __reserved1			:5,
	    isr_state_unavailable	:1,
	    isr_scanning_enabled	:1,
	    isr_event_enabled		:1);
	uint16_t	isr_state;
} ipmi_sensor_reading_t;

#define	IPMI_SENSOR_THRESHOLD_LOWER_NONCRIT		0x0001
#define	IPMI_SENSOR_THRESHOLD_LOWER_CRIT		0x0002
#define	IPMI_SENSOR_THRESHOLD_LOWER_NONRECOV		0x0004
#define	IPMI_SENSOR_THRESHOLD_UPPER_NONCRIT		0x0008
#define	IPMI_SENSOR_THRESHOLD_UPPER_CRIT		0x0010
#define	IPMI_SENSOR_THRESHOLD_UPPER_NONRECOV		0x0020

extern ipmi_sensor_reading_t *ipmi_get_sensor_reading(ipmi_handle_t *, uint8_t);
extern int ipmi_sdr_conv_reading(ipmi_sdr_full_sensor_t *, uint8_t,
    double *);
/*
 * Set Sensor Reading.  See section 35.14.
 */
#define	IPMI_CMD_SET_SENSOR_READING	0x30

#define	IPMI_SENSOR_OP_CLEAR	0x3	/* clear '0' bits */
#define	IPMI_SENSOR_OP_SET	0x2	/* set '1' bits */
#define	IPMI_SENSOR_OP_EXACT	0x1	/* set bits exactly */

typedef struct ipmi_set_sensor_reading {
	uint8_t		iss_id;
	DECL_BITFIELD5(
	    iss_set_reading		:1,
	    __reserved			:1,
	    iss_deassrt_op		:2,
	    iss_assert_op		:2,
	    iss_data_bytes		:2);
	uint8_t		iss_sensor_reading;
	uint16_t	iss_assert_state;	/* optional */
	uint16_t	iss_deassert_state;	/* optional */
	uint8_t		iss_event_data1;	/* optional */
	uint8_t		iss_event_data2;	/* optional */
	uint8_t		iss_event_data3;	/* optional */
} ipmi_set_sensor_reading_t;

extern int ipmi_set_sensor_reading(ipmi_handle_t *,
    ipmi_set_sensor_reading_t *);

/*
 * These IPMI message id/opcodes are documented in Appendix G in the IPMI spec.
 *
 * Payloads for these two commands are described in Sections 34.1 and 34.2 of
 * the spec, respectively.
 */
#define	IPMI_CMD_GET_FRU_INV_AREA	0x10
#define	IPMI_CMD_READ_FRU_DATA		0x11

/*
 * Structs to hold the FRU Common Header and the FRU Product Info Area, as
 * described in the IPMI Platform Management FRU Information Storage
 * Definition (v1.1).
 */
typedef struct ipmi_fru_hdr
{
	uint8_t		ifh_format;
	uint8_t		ifh_int_use_off;
	uint8_t		ifh_chassis_info_off;
	uint8_t		ifh_board_info_off;
	uint8_t		ifh_product_info_off;
	uint8_t		ifh_multi_rec_off;
	uint8_t		ifh_pad;
	uint8_t		ifh_chksum;
} ipmi_fru_hdr_t;

/*
 * Because only 6 bits are used to specify the length of each field in the FRU
 * product and board info areas, the biggest string we would ever need to hold
 * would be 63 chars plus a NULL.
 */
#define	FRU_INFO_MAXLEN	64

typedef struct ipmi_fru_brd_info
{
	char	ifbi_manuf_date[3];
	char	ifbi_manuf_name[FRU_INFO_MAXLEN];
	char	ifbi_board_name[FRU_INFO_MAXLEN];
	char	ifbi_product_serial[FRU_INFO_MAXLEN];
	char	ifbi_part_number[FRU_INFO_MAXLEN];
} ipmi_fru_brd_info_t;

typedef struct ipmi_fru_prod_info
{
	char	ifpi_manuf_name[FRU_INFO_MAXLEN];
	char	ifpi_product_name[FRU_INFO_MAXLEN];
	char	ifpi_part_number[FRU_INFO_MAXLEN];
	char	ifpi_product_version[FRU_INFO_MAXLEN];
	char	ifpi_product_serial[FRU_INFO_MAXLEN];
	char	ifpi_asset_tag[FRU_INFO_MAXLEN];
} ipmi_fru_prod_info_t;

extern int ipmi_fru_read(ipmi_handle_t *, ipmi_sdr_fru_locator_t *, char **);
extern int ipmi_fru_parse_board(ipmi_handle_t *, char *, ipmi_fru_brd_info_t *);
extern int ipmi_fru_parse_product(ipmi_handle_t *, char *,
    ipmi_fru_prod_info_t *);

/*
 * Routines to convert from entity and sensors defines into text strings.
 */
void ipmi_entity_name(uint8_t, char *, size_t);
void ipmi_sensor_type_name(uint8_t, char *, size_t);
void ipmi_sensor_units_name(uint8_t, char *, size_t);
void ipmi_sensor_reading_name(uint8_t, uint8_t, char *, size_t);

/*
 * Entity management.  IPMI has a notion of 'entities', but these are not
 * directly accessible from any commands.  Instead, their existence is inferred
 * from examining the SDR repository.  Since this is rather unwieldy, and
 * iterating over entities is a common operation, libipmi provides an entity
 * abstraction that hides the implementation details.  This handles entity
 * groupings as well as SDR associations.
 */
typedef struct ipmi_entity {
	uint8_t		ie_type;
	uint8_t		ie_instance;
	uint8_t		ie_children;
	boolean_t	ie_logical;
} ipmi_entity_t;

extern int ipmi_entity_iter(ipmi_handle_t *, int (*)(ipmi_handle_t *,
    ipmi_entity_t *, void *), void *);
extern int ipmi_entity_iter_sdr(ipmi_handle_t *, ipmi_entity_t *,
    int (*)(ipmi_handle_t *, ipmi_entity_t *, const char *, ipmi_sdr_t *,
    void *), void *);
extern int ipmi_entity_iter_children(ipmi_handle_t *, ipmi_entity_t *,
    int (*)(ipmi_handle_t *, ipmi_entity_t *, void *), void *);
extern ipmi_entity_t *ipmi_entity_lookup(ipmi_handle_t *, uint8_t,
    uint8_t);
extern ipmi_entity_t *ipmi_entity_lookup_sdr(ipmi_handle_t *, const char *);
extern ipmi_entity_t *ipmi_entity_parent(ipmi_handle_t *, ipmi_entity_t *);
extern int ipmi_entity_present(ipmi_handle_t *, ipmi_entity_t *, boolean_t *);
extern int ipmi_entity_present_sdr(ipmi_handle_t *, ipmi_sdr_t *, boolean_t *);

/*
 * User management.  The raw functions are private to libipmi, and only the
 * higher level abstraction (ipmi_user_t) is exported to consumers of the
 * library.
 */

#define	IPMI_USER_PRIV_CALLBACK		0x1
#define	IPMI_USER_PRIV_USER		0x2
#define	IPMI_USER_PRIV_OPERATOR		0x3
#define	IPMI_USER_PRIV_ADMIN		0x4
#define	IPMI_USER_PRIV_OEM		0x5
#define	IPMI_USER_PRIV_NONE		0xf

typedef struct ipmi_user {
	uint8_t		iu_uid;
	char		*iu_name;
	boolean_t	iu_enabled;
	boolean_t	iu_ipmi_msg_enable;
	boolean_t	iu_link_auth_enable;
	uint8_t		iu_priv;
} ipmi_user_t;

extern int ipmi_user_iter(ipmi_handle_t *,
    int (*)(ipmi_user_t *, void *), void *);
extern ipmi_user_t *ipmi_user_lookup_name(ipmi_handle_t *, const char *);
extern ipmi_user_t *ipmi_user_lookup_id(ipmi_handle_t *, uint8_t);
extern int ipmi_user_set_password(ipmi_handle_t *, uint8_t, const char *);

/*
 * The remaining functions are private to the implementation of the Sun ILOM
 * service processor.  These function first check the manufacturer from the IPMI
 * device ID, and will return EIPMI_NOT_SUPPORTED if attempted for non-Sun
 * devices.
 */
boolean_t ipmi_is_sun_ilom(ipmi_deviceid_t *);

/*
 * Sun OEM LED requests.
 */

#define	IPMI_SUNOEM_LED_MODE_OFF	0
#define	IPMI_SUNOEM_LED_MODE_ON		1
#define	IPMI_SUNOEM_LED_MODE_STANDBY	2
#define	IPMI_SUNOEM_LED_MODE_SLOW	3
#define	IPMI_SUNOEM_LED_MODE_FAST	4

/*
 * These functions take a SDR record and construct the appropriate form of the
 * above commands.
 */
extern int ipmi_sunoem_led_set(ipmi_handle_t *,
    ipmi_sdr_generic_locator_t *, uint8_t);
extern int ipmi_sunoem_led_get(ipmi_handle_t *,
    ipmi_sdr_generic_locator_t *, uint8_t *);

/*
 * Sun OEM uptime.  Note that the underlying command returns the uptime in big
 * endian form.  This wrapper automatically converts to the appropriate native
 * form.
 */

#define	IPMI_CMD_SUNOEM_UPTIME		0x08

extern int ipmi_sunoem_uptime(ipmi_handle_t *, uint32_t *, uint32_t *);

/*
 * Sun OEM FRU update.  The FRU information is managed through a generic
 * identifier, and then a type-specific data portion.  The wrapper function will
 * automatically fill in the data length field according to which type is
 * specified.
 */

#define	IPMI_CMD_SUNOEM_FRU_UPDATE	0x16

#define	IPMI_SUNOEM_FRU_DIMM	0x00
#define	IPMI_SUNOEM_FRU_CPU	0x01
#define	IPMI_SUNOEM_FRU_BIOS	0x02
#define	IPMI_SUNOEM_FRU_DISK	0x03

typedef struct ipmi_sunoem_fru {
	uint8_t				isf_type;
	uint8_t				isf_id;
	uint8_t				isf_datalen;
	union {
		struct {
			uint8_t		isf_data[128];
		} dimm;
		struct {
			uint32_t	isf_thermtrip;
			uint32_t	isf_eax;
			char		isf_product[48];
		} cpu;
		struct {
			char		isf_part[16];
			char		isf_version[16];
		} bios;
		struct {
			char		isf_manufacturer[16];
			char		isf_model[28];
			char		isf_serial[20];
			char		isf_version[8];
			char		isf_capacity[16];
		} disk;
	} isf_data;
} ipmi_sunoem_fru_t;

int ipmi_sunoem_update_fru(ipmi_handle_t *, ipmi_sunoem_fru_t *);

/*
 * See section 28.2
 */
#define	IPMI_CMD_GET_CHASSIS_STATUS		0x01

/*
 * flags for ichs_current_pwr_state field
 */
#define	IPMI_CURR_PWR_STATE_ON		0x01
#define	IPMI_CURR_PWR_STATE_OVERLOAD	0x02
#define	IPMI_CURR_PWR_STATE_INTERLOCK	0x04
#define	IPMI_CURR_PWR_STATE_FAULT	0x08
#define	IPMI_CURR_PWR_STATE_CNTL_FAULT	0x10

/*
 * flags for ichs_last_pwr_state field
 */
#define	IPMI_LAST_PWR_STATE_ACFAILED	0x01
#define	IPMI_LAST_PWR_STATE_OVERLOAD	0x02
#define	IPMI_LAST_PWR_STATE_INTERLOCK	0x04
#define	IPMI_LAST_PWR_STATE_FAULT	0x08
#define	IPMI_LAST_PWR_STATE_CMD_ON	0x10

/*
 * flags for the ichs_pwr_restore_policy field
 */
#define	IPMI_PWR_POLICY_REMAIN_OFF	0x0
#define	IPMI_PWR_POLICY_RESTORE		0x1
#define	IPMI_PWR_POLICY_POWER_ON	0x2
#define	IPMI_PWR_POLICY_UNKNOWN		0x3

typedef struct ipmi_chassis_status {
	DECL_BITFIELD3(
	    ichs_current_pwr_state	:5,
	    ichs_pwr_restore_policy	:2,
	    __reserved1			:1);
	DECL_BITFIELD2(
	    ichs_last_pwr_state		:5,
	    __reserved2			:3);
	DECL_BITFIELD7(
	    ichs_intrusion_asserted	:1,
	    ichs_front_panel_disabled	:1,
	    ichs_drive_fault_asserted	:1,
	    ichs_fan_fault_asserted	:1,
	    ichs_identify_state		:2,
	    ichs_identify_supported	:1,
	    __reserved3			:1);
} ipmi_chassis_status_t;

extern ipmi_chassis_status_t *ipmi_chassis_status(ipmi_handle_t *);

/*
 * See section 28.5
 */
#define	IPMI_CMD_CHASSIS_IDENTIFY	0x04
int ipmi_chassis_identify(ipmi_handle_t *, boolean_t);

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBIPMI_H */
