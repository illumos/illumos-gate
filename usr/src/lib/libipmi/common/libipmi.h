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

#ifndef	_LIBIPMI_H
#define	_LIBIPMI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/bmc_intf.h>
#include <sys/byteorder.h>

/*
 * Private interfaces for communicating with attached services over IPMI.  This
 * library is designed for system software communicating with Sun-supported
 * service processors over /dev/bmc.  It is not a generic IPMI library.
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

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

#pragma pack(1)

/*
 * Basic netfn definitions.  See section 5.1.
 */
#define	IPMI_NETFN_APP			BMC_NETFN_APP
#define	IPMI_NETFN_STORAGE		BMC_NETFN_STORAGE
#define	IPMI_NETFN_SE			BMC_NETFN_SE
#define	IPMI_NETFN_OEM			0x2e

/*
 * Error definitions
 */
#define	EIPMI_BASE	2000

enum {
	EIPMI_NOMEM = EIPMI_BASE,	/* memory allocation failure */
	EIPMI_BMC_OPEN_FAILED,		/* failed to open /dev/bmc */
	EIPMI_BMC_PUTMSG,		/* putmsg() failed */
	EIPMI_BMC_GETMSG,		/* getmsg() failed */
	EIPMI_BMC_RESPONSE,		/* response from /dev/bmc failed */
	EIPMI_INVALID_COMMAND,		/* invalid command */
	EIPMI_COMMAND_TIMEOUT,		/* command timeout */
	EIPMI_DATA_LENGTH_EXCEEDED,	/* maximum data length exceeded */
	EIPMI_SEND_FAILED,		/* failed to send BMC request */
	EIPMI_UNSPECIFIED,		/* unspecified error */
	EIPMI_UNKNOWN,			/* unknown error */
	EIPMI_BAD_RESPONSE,		/* received unexpected response */
	EIPMI_BAD_RESPONSE_LENGTH,	/* unexpected response length */
	EIPMI_INVALID_RESERVATION,	/* invalid reservation */
	EIPMI_NOT_PRESENT,		/* requested entity not present */
	EIPMI_INVALID_REQUEST,		/* malformed request */
	EIPMI_BUSY,			/* SP is busy */
	EIPMI_NOSPACE,			/* SP is out of space */
	EIPMI_UNAVAILABLE,		/* SP is present but unavailable */
	EIPMI_ACCESS			/* insufficient privileges */
};

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
extern ipmi_handle_t *ipmi_open(int *, char **);
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
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		id_dev_rev:4;
	uint8_t		__reserved:3;
	uint8_t		id_dev_sdrs:1;
#else
	uint8_t		id_dev_sdrs:1;
	uint8_t		__reserved:3;
	uint8_t		id_dev_rev:4;
#endif
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		id_firm_major:7;
	uint8_t		id_dev_available:1;
#else
	uint8_t		id_dev_available:1;
	uint8_t		id_firm_major:7;
#endif
	uint8_t		id_firm_minor;
	uint8_t		id_ipmi_rev;
	uint8_t		id_dev_support;
	uint8_t		id_manufacturer[3];
	uint16_t	id_product;
} ipmi_deviceid_t;

#define	IPMI_OEM_SUN	0x2a

ipmi_deviceid_t *ipmi_get_deviceid(ipmi_handle_t *);

#define	ipmi_devid_manufacturer(dp)		\
	((dp)->id_manufacturer[0] |		\
	((dp)->id_manufacturer[1] << 8) |	\
	((dp)->id_manufacturer[2] << 16))

/*
 * SDR (Sensor Device Record) requests.  A cache of the current SDR repository
 * is kept as part of the IPMI handle and updated when necessary.  Routines to
 * access the raw SDR repository are also provided.
 */

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
 * Generic Device Locator Record.  See section 43.7.
 */

#define	IPMI_SDR_TYPE_GENERIC_LOCATOR		0x10

typedef struct ipmi_sdr_generic_locator {
	/* RECORD KEY BYTES */
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		__reserved1:1;
	uint8_t		is_gl_accessaddr:7;
	uint8_t		is_gl_channel_msb:1;
	uint8_t		is_gl_slaveaddr:7;
	uint8_t		is_gl_bus:3;
	uint8_t		is_gl_lun:2;
	uint8_t		is_gl_channel:3;
#else
	uint8_t		is_gl_accessaddr:7;
	uint8_t		__reserved1:1;
	uint8_t		is_gl_slaveaddr:7;
	uint8_t		is_gl_channel_msb:1;
	uint8_t		is_gl_channel:3;
	uint8_t		is_gl_lun:2;
	uint8_t		is_gl_bus:3;
#endif
	/* RECORD BODY BYTES */
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		is_gl_span:3;
	uint8_t		__reserved2:5;
#else
	uint8_t		__reserved2:5;
	uint8_t		is_gl_span:3;
#endif
	uint8_t		__reserved3;
	uint8_t		is_gl_type;
	uint8_t		is_gl_modifier;
	uint8_t		is_gl_entity;
	uint8_t		is_gl_instance;
	uint8_t		is_gl_oem;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		is_gl_idlen:6;
	uint8_t		is_gl_idtype:2;
#else
	uint8_t		is_gl_idtype:2;
	uint8_t		is_gl_idlen:6;
#endif
	char		is_gl_idstring[1];
} ipmi_sdr_generic_locator_t;

/*
 * FRU Device Locator Record.  See section 43.8.
 */

#define	IPMI_SDR_TYPE_FRU_LOCATOR		0x11

typedef struct ipmi_sdr_fru_locator {
	/* RECORD KEY BYTES */
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		__reserved1:1;
	uint8_t		is_fl_accessaddr:7;
#else
	uint8_t		is_fl_accessaddr:7;
	uint8_t		__reserved1:1;
#endif
	union {
		struct {
			uint8_t	_is_fl_devid;
		} _logical;
		struct {
#if defined(_BIT_FIELDS_LTOH)
			uint8_t	__reserved:1;
			uint8_t	_is_fl_slaveaddr:7;
#else
			uint8_t	_is_fl_slaveaddr:7;
			uint8_t	__reserved:1;
#endif
		} _nonintelligent;
	} _devid_or_slaveaddr;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		is_fl_bus:3;
	uint8_t		is_fl_lun:2;
	uint8_t		__reserved2:2;
	uint8_t		is_fl_logical:1;
	uint8_t		__reserved3:4;
	uint8_t		is_fl_channel:4;
#else
	uint8_t		is_fl_logical:1;
	uint8_t		__reserved2:2;
	uint8_t		is_fl_lun:2;
	uint8_t		is_fl_bus:3;
	uint8_t		is_fl_channel:4;
	uint8_t		__reserved3:4;
#endif
	/* RECORD BODY BYTES */
	uint8_t		__reserved4;
	uint8_t		is_fl_type;
	uint8_t		is_fl_modifier;
	uint8_t		is_fl_entity;
	uint8_t		is_fl_instance;
	uint8_t		is_fl_oem;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		is_fl_idlen:6;
	uint8_t		is_fl_idtype:2;
#else
	uint8_t		is_fl_idtype:2;
	uint8_t		is_fl_idlen:6;
#endif
	char		is_fl_idstring[1];
} ipmi_sdr_fru_locator_t;

#define	is_fl_devid	_devid_or_slaveaddr._logical._is_fl_devid
#define	is_fl_slaveaddr	_devid_or_slaveaddr._nonintelligent._is_fl_slaveaddr

/*
 * The remaining SDR types do not have an associated structure, yet.
 */
#define	IPMI_SDR_TYPE_FULL_SENSOR		0x01
#define	IPMI_SDR_TYPE_COMPACT_SENSOR		0x02
#define	IPMI_SDR_TYPE_EVENT_ONLY		0x03
#define	IPMI_SDR_TYPE_ENTITY_ASSOCIATION	0x08
#define	IPMI_SDR_TYPE_DEVICE_RELATIVE		0x09
#define	IPMI_SDR_TYPE_MANAGEMENT_DEVICE		0x12
#define	IPMI_SDR_TYPE_MANAGEMENT_CONFIRMATION	0x13
#define	IPMI_SDR_TYPE_BMC_MESSAGE_CHANNEL	0x14
#define	IPMI_SDR_TYPE_OEM			0xC0

/*
 * Lookup the given sensor type by name.  These functions automatically read in
 * and cache the complete SDR repository.
 */
extern ipmi_sdr_fru_locator_t *ipmi_sdr_lookup_fru(ipmi_handle_t *,
    const char *);
extern ipmi_sdr_generic_locator_t *ipmi_sdr_lookup_generic(ipmi_handle_t *,
    const char *);

/*
 * Get Sensor Reading.  See section 35.14.
 */

#define	IPMI_CMD_GET_SENSOR_READING	0x2d

typedef struct ipmi_sensor_reading {
	uint8_t		isr_reading;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		__reserved1:5;
	uint8_t		isr_state_unavailable:1;
	uint8_t		isr_scanning_disabled:1;
	uint8_t		isr_event_disabled:1;
#else
	uint8_t		isr_event_disabled:1;
	uint8_t		isr_scanning_disabled:1;
	uint8_t		isr_state_unavailable:1;
	uint8_t		__reserved1:5;
#endif
	uint16_t	isr_state;
} ipmi_sensor_reading_t;

extern ipmi_sensor_reading_t *ipmi_get_sensor_reading(ipmi_handle_t *, uint8_t);

/*
 * Set Sensor Reading.  See section 35.14.
 */
#define	IPMI_CMD_SET_SENSOR_READING	0x30

#define	IPMI_SENSOR_OP_CLEAR	0x3	/* clear '0' bits */
#define	IPMI_SENSOR_OP_SET	0x2	/* set '1' bits */
#define	IPMI_SENSOR_OP_EXACT	0x1	/* set bits exactly */

typedef struct ipmi_set_sensor_reading {
	uint8_t		iss_id;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		iss_set_reading:1;
	uint8_t		__reserved:1;
	uint8_t		iss_deassrt_op:2;
	uint8_t		iss_assert_op:2;
	uint8_t		iss_data_bytes:2;
#else
	uint8_t		iss_data_bytes:2;
	uint8_t		iss_assert_op:2;
	uint8_t		iss_deassrt_op:2;
	uint8_t		__reserved:1;
	uint8_t		iss_set_reading:1;
#endif
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

int ipmi_fru_read(ipmi_handle_t *, ipmi_sdr_fru_locator_t *, char **);
int ipmi_fru_parse_board(ipmi_handle_t *, char *, ipmi_fru_brd_info_t *);
int ipmi_fru_parse_product(ipmi_handle_t *, char *, ipmi_fru_prod_info_t *);

/*
 * The remaining functions are private to the implementation of the Sun ILOM
 * service processor.  These function first check the manufacturer from the IPMI
 * device ID, and will return EIPMI_NOT_SUPPORTED if attempted for non-Sun
 * devices.
 */

/*
 * Sun OEM LED requests.
 */

#define	IPMI_CMD_SUNOEM_LED_GET		0x21
#define	IPMI_CMD_SUNOEM_LED_SET		0x22

typedef struct ipmi_cmd_sunoem_led_set {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		ic_sls_channel_msb:1;	/* device slave address */
	uint8_t		ic_sls_slaveaddr:7;	/* (from SDR record) */
#else
	uint8_t		ic_sls_slaveaddr:7;
	uint8_t		ic_sls_channel_msb:1;
#endif
	uint8_t		ic_sls_type;		/* led type */
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		__reserved:1;		/* device access address */
	uint8_t		ic_sls_accessaddr:7;	/* (from SDR record) */
#else
	uint8_t		ic_sls_accessaddr:7;
	uint8_t		__reserved:1;
#endif
	uint8_t		ic_sls_hwinfo;		/* OEM hardware info */
	uint8_t		ic_sls_mode;		/* LED mode */
	uint8_t		ic_sls_force;		/* force direct access */
	uint8_t		ic_sls_role;		/* BMC authorization */
} ipmi_cmd_sunoem_led_set_t;

typedef struct ipmi_cmd_sunoem_led_get {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		ic_slg_channel_msb:1;	/* device slave address */
	uint8_t		ic_slg_slaveaddr:7;	/* (from SDR record) */
#else
	uint8_t		ic_slg_slaveaddr:7;
	uint8_t		ic_slg_channel_msb:1;
#endif
	uint8_t		ic_slg_type;		/* led type */
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		__reserved:1;		/* device access address */
	uint8_t		ic_slg_accessaddr:7;	/* (from SDR record) */
#else
	uint8_t		ic_slg_accessaddr:7;
	uint8_t		__reserved:1;
#endif
	uint8_t		ic_slg_hwinfo;		/* OEM hardware info */
	uint8_t		ic_slg_force;		/* force direct access */
} ipmi_cmd_sunoem_led_get_t;

#define	IPMI_SUNOEM_LED_TYPE_OK2RM	0
#define	IPMI_SUNOEM_LED_TYPE_SERVICE	1
#define	IPMI_SUNOEM_LED_TYPE_ACT	2
#define	IPMI_SUNOEM_LED_TYPE_LOCATE	3
#define	IPMI_SUNOEM_LED_TYPE_ANY	0xFF

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

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBIPMI_H */
