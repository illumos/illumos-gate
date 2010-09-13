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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * These routines in this file are used to interact with SMC driver to
 * read and write FRUID data
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <synch.h>
#include <thread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <stropts.h>
#include <poll.h>
#include <smclib.h>
#include "fru_access_impl.h"

#define	POLL_TIMEOUT			10000
#define	FRUID_CHECK_POLL_TIMEOUT	5000
#define	SIZE_TO_READ_WRITE		20

/* IPMI fru spec Storage definition version 1.0, rev 1.1 */
#define	IPMI_COMMON_HEADER_SIZE		8
#define	IPMI_VERSION			1
#define	CMN_HDR_VERSION_MASK		0x0
#define	CMN_HDR_OFFSET			0x0
#define	BD_MFR_OFFSET			6
#define	BD_FIELDS_SIZE			6
#define	AREA_TERMINATION_INDICATOR	0xc1

/* type encoding */
#define	BINARY_TYPE			0x0
#define	BCDPLUS_TYPE			0x1
#define	SIX_BITASCII_TYPE		0x2
#define	UNICODE_TYPE			0x3

/* for ascii conversion */
#define	ASCII_MAP			0x20
#define	BIT_MASK1			0x3f
#define	BIT_MASK2			0x0f
#define	BIT_MASK3			0x03

#define	SUN_NAME			"SUN MICROSYSTEMS, INC."
#define	SUN_JEDEC_CODE			0x3e
#define	MANR_MAX_LENGTH	80
#define	FRU_DATA_MAX_SIZE		100

/* IPMI commands */
#define	IPMI_GET_DEVICE_ID		0x1
#define	FRU_DEVICE_ID			0x0
#define	READ_FRU_INVENTORY_INFO		0x10
#define	READ_FRU_INVENTORY_DATA		0x11
#define	WRITE_FRU_INVENTORY_DATA	0x12

#define	TMP_BUFFER_SIZE			10
#define	BYTE_TO_READ_SUN_CHK		5

typedef struct {
	uint8_t	internal;	/* internal use area */
	uint8_t chassis;	/* chassis info area */
	uint8_t board;		/* board area */
	uint8_t product;	/* product info area */
	uint8_t records;	/* multirecord area */
} fruid_offset_t;

extern void get_fru_data_info(int, int, format_t *);
static void convert_to_ascii(uint8_t [], uint8_t [], int, int);
static void bcdplus_to_ascii(uint8_t [], uint8_t [], int);
static time_t get_utc_time(uint8_t  []);
static uint8_t	cpu_no = 0;

/*
 * Routine to read FRUID information from BMC
 */
static int
get_alarm_fru_data(int offset, int size, void *buffer, format_t *format)
{
	uint8_t	datap[5];
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;

	if (buffer == NULL) {
		return (-1);
	}
	bzero(buffer, size);

	datap[0] = 0x7;			/* bus id */
	datap[1] = 0xa0;		/* slave address */
	datap[2] = size;		/* count */
	datap[3] = offset >> 8;		/* MSB */
	datap[4] = (uint8_t)offset;	/* LSB */

	(void) smc_init_ipmi_msg(&req_pkt, SMC_MASTER_WR_RD_I2C,
		FRUACCESS_MSG_ID, 5, datap, DEFAULT_SEQN, format->dest,
		SMC_NETFN_APP_REQ, SMC_BMC_LUN);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	/* check the completion code */
	if (res_pkt.data[7] != 0) {
		return (-1);
	}

	(void) memcpy(buffer, &(res_pkt.data[8]), size);
	return (0);
}

/*
 * Routine to read FRUID information from other boards
 */
static int
get_fru_data(int offset, int size, void *buffer, format_t *format)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;
	uint8_t datap[4];
	int ipmi = 0;

	if (buffer == NULL) {
		return (-1);
	}

	/* figure out if onboard access or ipmb access */
	if (format->src == format->dest) {
		ipmi = 0;
	} else {
		ipmi = 1;
	}

	switch (ipmi) {

	case 0: /* on board info (local i2c) */

	SC_MSG_CMD(&req_pkt) = SMC_EEPROM_READ;
	SC_MSG_LEN(&req_pkt) = 4;
	SC_MSG_ID(&req_pkt) = FRUACCESS_MSG_ID;

	/* data field for request */
	req_pkt.data[0] = format->sun_device_id;	/* device id */
	req_pkt.data[1] = (uint8_t)offset; /* (LSB) */
	req_pkt.data[3] = size;

	if (format->format == SUN_FORMAT) {
		req_pkt.data[2] = offset >> 8;
	} else {
		req_pkt.data[2] = 0x0;	/* (MSB) always 0x0 for IPMI */
	}

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}

	if (SC_MSG_LEN(&res_pkt) != size) {
		return (-1);
	}
	(void) memcpy(buffer, res_pkt.data, size);
	return (0);

	default:

	/* data for request packet */
	datap[0] = format->sun_device_id;	/* device id */
	datap[1] = (uint8_t)offset;		/* LSB */
	datap[3] = size;			/* bytes to read */
	if (format->format == SUN_FORMAT) {
		datap[2] = offset >> 8;
	} else {
		datap[2] = 0x0;			/* (MSB) always 0x0 for IPMI */
	}

	(void) smc_init_ipmi_msg(&req_pkt, READ_FRU_INVENTORY_DATA,
		FRUACCESS_MSG_ID, 4, datap, DEFAULT_SEQN,
		format->dest, SMC_NETFN_STORAGE_REQ, format->sun_lun);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	/* check the completion code */
	if (res_pkt.data[7] != 0) {
		return (-1);
	}

	/* check the size */
	if (res_pkt.data[8] != size) {
		return (-1);
	}

	(void) memcpy(buffer, &(res_pkt.data[9]), size);
	return (0);
	}
}

/*
 * routine to read the IPMI common header field
 */
static int
read_common_header(fruid_offset_t *offset, format_t *format)
{
	int ret = 0;
	uint8_t data[FRU_DATA_MAX_SIZE];

	ret = get_fru_data(CMN_HDR_OFFSET, IPMI_COMMON_HEADER_SIZE, data,
		format);
	if (ret < 0) {
		return (-1);
	}

	/* version check */
	if ((data[0] | CMN_HDR_VERSION_MASK) != 1) {
		return (-1);
	}

	offset->internal = data[1] * 8;
	offset->chassis  = data[2] * 8;
	offset->board    = data[3] * 8;
	offset->product  = data[4] * 8;
	offset->records  = data[5] * 8;

	return (0);
}

/*
 * Read the values of each field based on FORMAT
 */
/* ARGSUSED */
static int
read_bd_fields(uint8_t *field, int offset, format_t *format)
{

	int ret, encode_type = 0x0, len, length, extra_bytes, alloc_size;
	uint8_t *store;
	uint8_t data[FRU_DATA_MAX_SIZE];

	bzero(field, MANR_MAX_LENGTH);

	ret = get_fru_data(offset, BD_FIELDS_SIZE, data, format);
	if (ret < 0) {
		return (-1);
	}

	if (data[0] == AREA_TERMINATION_INDICATOR) {
		return (0);
	}

	encode_type = data[0] >> 6;
	len = data[0] & 0x3f;
	if (len <= 0) {
		return (0);
	}

	ret = get_fru_data(offset+1, len, data, format);
	if (ret < 0) {
		return (-1);
	}

	switch (encode_type) {

	case SIX_BITASCII_TYPE:

		length  = len - (len % 3);
		extra_bytes = len % 3;
		alloc_size = ((length/3) * 4) + extra_bytes;
		store = (uint8_t *)malloc(sizeof (uint8_t) * alloc_size);
		if (store == NULL) {
			return (-1);
		}
		convert_to_ascii(data, store, len, extra_bytes);
		break;

	case BCDPLUS_TYPE:

		alloc_size = len * 2;
		store = (uint8_t *)malloc(sizeof (uint8_t) * alloc_size);
		if (store == NULL) {
			return (-1);
		}

		bcdplus_to_ascii(data, store, len);
		break;

	case BINARY_TYPE:
	case UNICODE_TYPE:
	default:
		return (-1);
	}

	(void) memcpy(field, store, alloc_size);
	free(store);
	return (len);
}

static int
read_board_info(uint8_t board_offset, payload_t *manr, format_t *format)
{
	time_t time;
	uint8_t *buffer;
	uint8_t mfg_time[4];
	uint8_t data[FRU_DATA_MAX_SIZE];
	int ret = 0, current_offset = 0x0;
	int bd_area_len = 0;

	/* read version, length, lang code, mfg. time */
	ret = get_fru_data(board_offset, BD_FIELDS_SIZE, data, format);

	if (ret < 0) {
		return (-1);
	}

	/* version check */
	if ((data[0] | CMN_HDR_VERSION_MASK) != 1) {
		return (-1);
	}

	/* byte 2 is lang code */
	bd_area_len = data[1] * 8;
	mfg_time[3] = data[3];
	mfg_time[2] = data[4];
	mfg_time[1] = data[5];
	mfg_time[0] = 0x0;
	time = get_utc_time(mfg_time);

	/* fill the timestamp into manr */
	(void) memcpy(manr->timestamp, &time, MANR_TIME_LEN);

	if (bd_area_len < BD_MFR_OFFSET) {
		return (-1);
	}
	buffer = (uint8_t *)malloc(sizeof (uint8_t) * MANR_MAX_LENGTH);
	if (buffer == NULL) {
		return (-1);
	}

	/* read the  board info  */
	current_offset += board_offset + BD_MFR_OFFSET;
	current_offset += read_bd_fields(buffer, current_offset, format);

	if (strncmp(SUN_NAME, (char *)buffer, sizeof (SUN_NAME)) == 0) {
		manr->vendor_name[0] = 0x00;
		manr->vendor_name[1] = 0x3e;
	} else {
		manr->vendor_name[0] = 0x00;
		manr->vendor_name[1] = 0x00;
	}

	current_offset += 1;	/* for length/type field */

	current_offset += read_bd_fields(buffer, current_offset, format);
	current_offset += 1;	/* for length/type field */
	(void) memcpy(manr->fru_short_name, buffer, MANR_FRUNAME_LEN);

	current_offset += read_bd_fields(buffer, current_offset, format);
	current_offset += 1;	/* for length/type field */
	(void) memcpy(manr->sun_serial_no, buffer, MANR_SERIALNUM_LEN);

	current_offset += read_bd_fields(buffer, current_offset, format);
	current_offset += 1;	/* for length/type field */
	(void) memcpy(manr->sun_part_no, buffer, MANR_PARTNUM_LEN);

	/*
	 * We dont need the FRU FILE ID, so just skip the field
	 * and get the offset to read the custom MFG. info fields
	 */
	current_offset += read_bd_fields(buffer, current_offset, format);
	current_offset += 1;	/* for length/type field */

	current_offset += read_bd_fields(buffer, current_offset, format);
	current_offset += 1;	/* for length/type field */

	/* read the custom mfg. info fields */
	current_offset += read_bd_fields(buffer, current_offset, format);
	current_offset += 1;	/* for length/type field */
	(void) memcpy(manr->manufacture_loc, buffer, MANR_MFRLOC_LEN);

	current_offset += read_bd_fields(buffer, current_offset, format);
	(void) memcpy(manr->fru_descr, buffer, MANR_FRUDESCR_LEN);

	free(buffer);
	return (0);
}

/*
 * Read the IPMI information from hardware and translate it into
 * MANR(SUN format)
 */
int
get_manr(format_t *format, payload_t *manr)
{
	int ret = 0;
	fruid_offset_t *offset = NULL;

	offset = (fruid_offset_t *)malloc(sizeof (fruid_offset_t));
	if (offset == NULL) {
		return (-1);
	}

	ret  = read_common_header(offset, format);
	if (ret != 0) {
		free(offset);
		return (-1);
	}

	if (offset->board != 0) {
		ret  = read_board_info(offset->board, manr, format);
	}

	free(offset);
	return (ret);
}

static void
convert_to_ascii(uint8_t  data [], uint8_t store[],
				int length, int extra_bytes)
{
	uint8_t x, y;
	int index = 0;
	int i, idx = length - (length % 3);

	for (i = 0; ; i += 3) {

		x = 0x0;
		y = 0x0;

		if (i == idx && extra_bytes == 0) {
			break;
		}

		/* get the first six bits */
		x = (data[i] & BIT_MASK1);
		x +=  ASCII_MAP;
		store[index] = x;

		if (i == idx && extra_bytes == 1) {
			break;
		}

		/*
		 * get last 2 bits of first byte and first
		 * 4 bits of second byte
		 */

		x = (data[i] >> 6);
		y = (data[i + 1] & BIT_MASK2) << 2;
		x |= y  + ASCII_MAP;
		store[index+1] = x;

		if (i == idx) {
			break;
		}

		/* get last 4 bits of second byte and 2 bits of last byte */
		x = data[i + 1] >> 4;
		y = (data[i + 2] & BIT_MASK3) << 4;
		x |= y + ASCII_MAP;
		store[index+2] = x;

		/* get last six bits of third byte */
		store[index + 3] = (data[i + 2] >> 2) + ASCII_MAP;
		index += 4;
	}
}

static void
bcdplus_to_ascii(uint8_t data[], uint8_t store[], int len)
{
	int i, j, index = 0;
	uint8_t tmp = 0;

	struct {
		int a:4;
		int b:4;
	} val;

	for (i = 0; i < len; i++) {
		(void) memcpy(&val, &data[i], 1);
		for (j = 0; j < 2; j++) {
			if (j == 0) {
				tmp = val.a;
			} else
				tmp = val.b;

			if (tmp <= 9) {
				/* ascii conversion */
				store[index++] = tmp + 48;
				continue;
			}

			switch (tmp) {

			case 0xa:
				store[index++] = ' ';
				break;
			case 0xb:
				store[index++] = '-';
				break;
			case 0xc:
				store[index++] = '.';
				break;
			default:
				store[index++] = ' ';
			}
		}
	}
}

/* converts ipmi format time to UTC time (unix 32 bit timestamp) */
static time_t
get_utc_time(uint8_t data [])
{
	time_t time;
	struct tm tm1;
	uint32_t ipmi_time;

	(void) memcpy(&ipmi_time, data, 4);

	ipmi_time *= 60;	/* convert into seconds */

	/* get UTC time for 0:00 1/1/96 (ipmi epoch) */
	tm1.tm_sec 	= 0;
	tm1.tm_min 	= 0;
	tm1.tm_hour 	= 0;
	tm1.tm_mday 	= 1;
	tm1.tm_mon 	= 0;
	tm1.tm_year 	= 96;

	time = mktime(&tm1);
	time += ipmi_time;

	return (time);
}

/*
 * routine to write information to BMC
 */
static int
write_alarm_fru_data(const void  *buffer, size_t size,
		off_t offset, format_t *format)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;
	uint8_t	*datap = NULL;

	if (buffer == NULL) {
		return (-1);
	}
	datap = (uint8_t *)malloc(sizeof (uint8_t) * (size  + 5));
	if (datap == NULL) {
		return (-1);
	}

	datap[0] = 0x7;		/* bus id */
	datap[1] = 0xa0;	/* slave address */
	datap[2] = 0;		/* count */
	datap[3] = offset >> 8;	/* MSB */
	datap[4] = (uint8_t)offset;	/* LSB */
	(void) memcpy((void *)&(datap[5]), buffer, size);

	/* initialize ipmi request packet */
	(void) smc_init_ipmi_msg(&req_pkt, SMC_MASTER_WR_RD_I2C,
		FRUACCESS_MSG_ID, (5 + size), datap, DEFAULT_SEQN,
		format->dest, SMC_NETFN_APP_REQ, SMC_BMC_LUN);
	free(datap);

	/* send ipmi request packet */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	/* check the completion code */
	if (res_pkt.data[7] != 0) {
		return (-1);
	}
	return (0);
}

static int
write_fru_data(const void  *buffer, size_t size,
	off_t offset, format_t *format)
{
	int ipmi = 0;
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;
	uint8_t	*datap = NULL;

	if (buffer == NULL) {
		return (-1);
	}

	if (format->src == format->dest) {
		ipmi = 0;
	} else {
		ipmi = 1;
	}

	switch (ipmi) {

	case 0: /* on board info (local i2c) */

	SC_MSG_CMD(&req_pkt) = SMC_EEPROM_WRITE;
	SC_MSG_LEN(&req_pkt) = 4 + size;
	SC_MSG_ID(&req_pkt) = FRUACCESS_MSG_ID;

	/* data field for request */
	req_pkt.data[0] = format->sun_device_id;	/* device id */
	req_pkt.data[1] = offset; /* (LSB) */
	req_pkt.data[3] = size;
	if (format->format == SUN_FORMAT) {
		req_pkt.data[2] = offset >> 8;
	} else {
		req_pkt.data[2] = 0x0;  /* (MSB) always 0x0 for IPMI */
	}
	(void) memcpy((void *)&(req_pkt.data[4]), buffer, size);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	break;

	default: /* read data from remote device (ipmi) */
	datap = (uint8_t *)malloc(sizeof (uint8_t) * (size  + 4));
	if (datap == NULL) {
		return (-1);
	}

	datap[0] = format->sun_device_id;	/* device id */
	datap[1] = offset;			/* LSB */
	datap[3] = size;			/* nbytes */
	if (format->format == SUN_FORMAT) {
		datap[2] = offset >> 8;
	} else {
		datap[2] = 0x0;	/* (MSB) always 0x0 for IPMI */
	}
	(void) memcpy((void *)&(datap[4]), buffer, size);

	(void) smc_init_ipmi_msg(&req_pkt, WRITE_FRU_INVENTORY_DATA,
		FRUACCESS_MSG_ID, (4 + size), datap, DEFAULT_SEQN,
		format->dest, SMC_NETFN_STORAGE_REQ, format->sun_lun);
	free(datap);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	/* check the completion code */
	if (res_pkt.data[7] != 0) {
		return (-1);
	}
	break;
	} /* end of switch */
	return (0);
}

/*
 * This routine splits the data to write into smaller chunks and
 * write it to FRUID chip using SMC drv APIs
 */

/* ARGSUSED */
ssize_t
pwrite_new(int fd, const void  *buffer, size_t size,
		off_t offset, format_t *format)
{
	int ret;
	int index = 0;
	size_t bytes = 0;
	off_t next_offset = 0x0;
	off_t curr_offset = offset;
	size_t bytes_to_write = size;
	uint8_t *data;
	int retry = 3;
	int (* func_ptr)(const void  *, size_t, off_t, format_t *);

	if (format->dest == 0x20) {
		func_ptr = write_alarm_fru_data;
	} else {
		func_ptr = write_fru_data;
	}

	data = (uint8_t *)buffer;
	while (bytes_to_write != 0) {

		retry = 3;
		ret = 1;

		if (bytes_to_write > SIZE_TO_READ_WRITE) {
			bytes = SIZE_TO_READ_WRITE;
			next_offset = curr_offset + SIZE_TO_READ_WRITE;
		} else {
			bytes = bytes_to_write;
		}

		bytes_to_write = bytes_to_write - bytes;
		while ((ret != 0) && (retry != 0)) {
			ret = (*func_ptr)((void *)&data[index],
				bytes, curr_offset, format);
			retry--;
		}
		if (ret != 0) {
			return (ret);
		}
		index = index + bytes;
		curr_offset = next_offset;
	}
	return (size);
}

/*
 * This routine reads the data in smaller chunks and
 * sends it to upper layer(frudata plugin) in the sw stack
 */
/* ARGSUSED */
ssize_t
pread_new(int fd, void  *buffer, size_t size,
		off_t offset, format_t *format)
{
	int ret;
	int index = 0;
	size_t bytes = 0;
	off_t next_offset = 0x0;
	off_t curr_offset = offset;
	size_t bytes_to_read = size;
	uint8_t *data;
	int retry = 3;
	int (* func_ptr)(int, int, void *, format_t *);

	if (format->dest == 0x20) {
		func_ptr = get_alarm_fru_data;
	} else {
		func_ptr = get_fru_data;
	}

	data = (uint8_t *)buffer;

	while (bytes_to_read != 0) {

		retry = 3;
		ret = 1;

		if (bytes_to_read > SIZE_TO_READ_WRITE) {
			bytes = SIZE_TO_READ_WRITE;
			next_offset = curr_offset + SIZE_TO_READ_WRITE;
		} else {
			bytes = bytes_to_read;
		}

		bytes_to_read = bytes_to_read - bytes;

		while ((ret != 0) && (retry != 0)) {
			ret = (* func_ptr)(curr_offset, bytes,
				(void *) &data[index], format);
			retry--;
		}
		if (ret != 0) {
			return (ret);
		}
		index = index + bytes;
		curr_offset = next_offset;
	}
	return (size);
}

/*
 * routine to check if IPMI fruid info is available,
 * return 0: IPMI fruid not present
 * return 1: IPMI fruid present
 */
static int
is_ipmi_fru_data_available(int src, int dest)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;
	uint8_t datap[5];

	/* on board access */
	if (src == dest) {

		SC_MSG_CMD(&req_pkt) = SMC_EEPROM_READ;
		SC_MSG_LEN(&req_pkt) = 4;
		SC_MSG_ID(&req_pkt) = FRUACCESS_MSG_ID;

		/* data field for request */
		req_pkt.data[0] = 0x0;	/* eeprom number (ipmi format) */
		req_pkt.data[1] = CMN_HDR_OFFSET; /* (LSB) */
		req_pkt.data[2] = 0x0;	/* (MSB) always 0x0 for IPMI */
		req_pkt.data[3] = IPMI_COMMON_HEADER_SIZE;

		/* make a call to smc library to send cmd */
		if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
			POLL_TIMEOUT) != SMC_SUCCESS) {
			return (0);
		}

		/* version check */
		if (res_pkt.data[0] != IPMI_VERSION) {
			return (0);
		} else {
			return (1);
		}
	}

	/* ipmi access */
	datap[0] = FRU_DEVICE_ID;	/*  fru device id - always */
	datap[1] = 0x0;		/* LSB */
	datap[2] = 0x0;		/* MSB */
	datap[3] = 8;		/* bytes to read */

	(void) smc_init_ipmi_msg(&req_pkt, READ_FRU_INVENTORY_DATA,
		FRUACCESS_MSG_ID, 4, datap, DEFAULT_SEQN,
		IPMB_ADDR(dest), SMC_NETFN_STORAGE_REQ, SMC_BMC_LUN);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		FRUID_CHECK_POLL_TIMEOUT) != SMC_SUCCESS) {
		return (0);
	}

	if (res_pkt.data[9] == IPMI_VERSION) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * routine to check if fruid info is available on BMC,
 * return 0: fruid not present
 * return 1: fruid present
 */
static int
is_alarm_frudata_available(format_t *fru_format)
{
	int ret;
	char buffer[TMP_BUFFER_SIZE];
	int fd = -1;
	format_t format;

	bzero(buffer, sizeof (buffer));
	format.src = fru_format->src;
	format.dest = fru_format->dest;
	format.sun_device_id = 0x0;
	format.sun_lun = 0x0;
	format.format |= SUN_FORMAT;

	/* passing dummy fd */
	/* for now read the first 3 bytes and check the info */
	ret = pread_new(fd, (void *) buffer, 3, STATIC_OFFSET, &format);
	if (ret < 0) {
		return (0);
	}

	if (buffer[0] != SECTION_HDR_TAG) {
		fru_format->format  = NO_FRUDATA;
		return (0);
	}

	fru_format->format = SUN_FORMAT;
	fru_format->sun_device_id = 0x0;
	fru_format->sun_lun = 0x0;
	return (1);
}

/*
 * checks if the remote device intelligent device (IPMI capable) or not
 * return 0: not ipmi capable
 * return 1: ipmi capable
 */
static int
is_ipmi_capable(int src, int dest)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;

	if (src == dest) {
		return (1);
	}

	(void) smc_init_ipmi_msg(&req_pkt, IPMI_GET_DEVICE_ID,
		FRUACCESS_MSG_ID, 0, NULL, DEFAULT_SEQN,
		IPMB_ADDR(dest), SMC_NETFN_APP_REQ, SMC_BMC_LUN);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		FRUID_CHECK_POLL_TIMEOUT) != SMC_SUCCESS) {
		return (0);
	}
	return (1);	/* got response */
}

int
is_fru_data_available(int precedence, int slot_no, format_t *fru_format)
{
	int ret, fd = 0;
	uint8_t data[TMP_BUFFER_SIZE];

	fru_format->format  = NO_FRUDATA;
	if (fru_format->dest == 0x20) {	/* alarm card */
		ret = is_alarm_frudata_available(fru_format);
		return (ret);
	}

	if (cpu_no == 0) { /* get the geo_addr */
		sc_reqmsg_t req_pkt;
		sc_rspmsg_t rsp_pkt;
		uint8_t size = 0;

		/* initialize the request packet */
		(void) smc_init_smc_msg(&req_pkt,
			SMC_GET_GEOGRAPHICAL_ADDRESS, DEFAULT_SEQN, size);
		/* make a call to smc library to send cmd */
		if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
			POLL_TIMEOUT) != SMC_SUCCESS) {
			return (0);
		}
		if (SC_MSG_LEN(&rsp_pkt) == 0) {
			return (0);
		}
		cpu_no = rsp_pkt.data[0];
	}

	/* check if it is IPMI intelligent or not */
	if (slot_no != cpu_no) {
		ret = is_ipmi_capable(cpu_no, slot_no);
		if (ret == 0) { /* dumb I/O card */
			return (0);
		}
	}

	/* check if ipmi frudata is present or not */
	ret = is_ipmi_fru_data_available(cpu_no, slot_no);
	if (ret == 1) {
		fru_format->format  |= IPMI_FORMAT;
		fru_format->sun_device_id = 0x0;
		fru_format->sun_lun = 0x0;

		/* no need to look for sun format */
		if (precedence == IPMI_FORMAT) {
			return (fru_format->format);
		}
	}

	/* check if sun fruid is present */
	get_fru_data_info(cpu_no, slot_no, fru_format);
	/* check the hdr version */
	if (fru_format->format & SUN_FORMAT) {
		ret = pread_new(fd, &data, BYTE_TO_READ_SUN_CHK,
			STATIC_OFFSET, fru_format);
		if (ret != BYTE_TO_READ_SUN_CHK) {
			fru_format->format = fru_format->format &
				(~ (SUN_FORMAT));
			fru_format->sun_device_id = 0x0;
			fru_format->sun_lun = 0x0;
		}
		if (data[0] != SECTION_HDR_TAG) {
			fru_format->format = fru_format->format &
				(~ (SUN_FORMAT));
			fru_format->sun_device_id = 0x0;
			fru_format->sun_lun = 0x0;
		}
	}
	return (fru_format->format);
}
