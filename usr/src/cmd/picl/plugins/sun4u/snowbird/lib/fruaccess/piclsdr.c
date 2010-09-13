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
 * Read the SDR information on a board and get the device id to
 * read the FRUID information
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <stropts.h>
#include <stdarg.h>
#include <syslog.h>
#include <smclib.h>
#include "fru_access_impl.h"

#define	POLL_TIMEOUT	10000	/* 20 sec */
#define	SEQUENCE	10

#define	IPMI_GET_SDR_INFO	0x20
#define	IPMI_SENSOR_NETFN	0x4
#define	SDR_INFO_RESPONSE_SZ_MIN	10

#define	NUM_OF_LUN	4
#define	SUN_FRU	"SUN FRU SDR"
#define	FRU_DEVICE_SDR_TYPE	0x11
#define	IPMI_SDR_VERSION	0x51
#define	IPMI_DATA_OFFSET	7
#define	IPMI_GET_SDR_INFO_CMD	0x20
#define	SDR_BUFFER_LEN_MAX	100

typedef struct {
	uint8_t	src;
	uint8_t	dest;
	uint8_t	lun;
	uint8_t record_id_lsb;
	uint8_t record_id_msb;
	int 	offset;
	int 	length;
	char    *buffer;
} sdr_info_t;

static int get_sdr_info(int, int, uint8_t lun);
static int get_sdr(sdr_info_t *);
static int get_sun_sdr(int, uint8_t, uint8_t, uint8_t);

/*
 * bug in smc f/w
 *
 *  static int lun_mask[4] = { 0x01, 0x02, 0x04, 0x08 };
 */

/*
 * routine to read the onboard/remote device SDR information
 */
void
get_fru_data_info(int src, int dest, format_t *fru_format)
{
	int ret;

	src = IPMB_ADDR(src);
	dest = IPMB_ADDR(dest);

	if (src != dest) { /* ipmi */
		int i = 0;
		for (i = 0; i < NUM_OF_LUN; i++) { /* for each lun */
			ret = get_sdr_info(src, dest, i);
			if (ret > 0) {
				ret = get_sun_sdr(ret, src, dest, i);
				if (ret > 0) {
					fru_format->format |= SUN_FORMAT;
					fru_format->sun_device_id = ret;
					fru_format->sun_lun = i;
					break;
				}
			}
		}
	} else { /* on board */
		ret = get_sdr_info(src, dest, 0);
		if (ret > 0) {
			ret = get_sun_sdr(ret, src, dest, 0);
			if (ret > 0) {
				fru_format->format |= SUN_FORMAT;
				fru_format->sun_device_id = ret;
				fru_format->sun_lun = 0;
			}
		}
	}
}

/*
 * read the onboard sdr information
 */
static int
get_onboard_sdr(sdr_info_t *sdr)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;

	SC_MSG_CMD(&req_pkt) =  SMC_DEVICE_SDR_GET;
	SC_MSG_LEN(&req_pkt) = 6;
	SC_MSG_ID(&req_pkt) = SEQUENCE;

	/* data  for request packet */
	req_pkt.data[0] = 0x0;
	req_pkt.data[1] = 0x0;
	req_pkt.data[2] = sdr->record_id_lsb;
	req_pkt.data[3] = sdr->record_id_msb;
	req_pkt.data[4] = sdr->offset;
	req_pkt.data[5] = sdr->length;

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}

	bzero(sdr->buffer, SDR_BUFFER_LEN_MAX);
	(void) memcpy(sdr->buffer, res_pkt.data, res_pkt.hdr.len);
	return (0);
}

/*
 * get the sdr information
 */
static int
get_sdr_info(int src, int dest, uint8_t lun)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;

	if (lun >= NUM_OF_LUN) {
		return (-1);
	}

	if (src == dest) {	/* onboard */
		SC_MSG_CMD(&req_pkt) = SMC_DEVICE_SDR_INFO_GET;
		SC_MSG_LEN(&req_pkt) = 0;
		SC_MSG_ID(&req_pkt) = SEQUENCE;
		if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
			POLL_TIMEOUT) != SMC_SUCCESS) {
			return (-1);
		}
		return (res_pkt.data[0]);
	}

	/* ipmb access */
	(void) smc_init_ipmi_msg(&req_pkt, IPMI_GET_SDR_INFO_CMD,
		FRUACCESS_MSG_ID, 0, NULL, DEFAULT_SEQN, dest,
		SMC_NETFN_SENSOR_REQ, lun);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}

	/* completion code */
	if (res_pkt.data[IPMI_DATA_OFFSET] != 0) {
		return (-1);
	}

	/*
	 * Known bug in SMC f/w. take this out for next release
	 * if ((res_pkt.data[IPMI_DATA_OFFSET + 2] & lun_mask[lun]) != 1) {
	 *	return (0);
	 * }
	 */
	return (res_pkt.data[IPMI_DATA_OFFSET + 1]);
}

static int
get_sun_sdr(int num_records, uint8_t src, uint8_t dest, uint8_t lun)
{
	int i, ret;
	sdr_info_t sdr;
	char data[SDR_BUFFER_LEN_MAX];
	uint8_t next_record_lsb;
	uint8_t next_record_msb;

	sdr.src = src;
	sdr.dest = dest;
	sdr.lun = lun;
	sdr.buffer = data;

	/* get the first record info */
	next_record_lsb = 0x0;
	next_record_msb = 0x0;
	sdr.length = 4;
	sdr.offset = 0x0;

	if (src == dest) { /* onboard */
		for (i = 0; i < num_records; i++) {
			sdr.record_id_lsb = next_record_lsb;
			sdr.record_id_msb = next_record_msb;

			if ((ret = get_onboard_sdr(&sdr)) < 0) {
				return (ret);
			}

			next_record_lsb = data[0];
			next_record_msb = data[1];
			if (data[4] != IPMI_SDR_VERSION) {
				return (-1);
			}

			if (data[5] == FRU_DEVICE_SDR_TYPE) {
				sdr.offset = 0x10;
				sdr.length = strlen(SUN_FRU);
				if ((ret = get_onboard_sdr(&sdr)) < 0) {
					return (ret);
				}

				/* first two bytes of response is reserv. id */
				if (strncmp(SUN_FRU, &data[2],
					strlen(SUN_FRU)) == 0) {
					/* found sun sdr */
					sdr.offset = 0x0;
					sdr.length = 7;
					if ((ret = get_onboard_sdr(&sdr)) < 0) {
						return (ret);
					}
					return (data[8]);
				}
			}
		}
		return (-1);
	}

	/* ipmb access */
	/* traverse thru all the records until we find sun sdr */
	for (i = 0; i < num_records; i++) {

		sdr.record_id_lsb = next_record_lsb;
		sdr.record_id_msb = next_record_msb;

		if ((ret = get_sdr(&sdr)) < 0) {
			return (ret);
		}

		/* completion code */
		if (data[IPMI_DATA_OFFSET] != 0) {
			return (-1);
		}
		next_record_lsb = data[IPMI_DATA_OFFSET + 1];
		next_record_msb = data[IPMI_DATA_OFFSET + 2];

		if (data[IPMI_DATA_OFFSET + 5] != IPMI_SDR_VERSION) {
			return (-1);
		}

		if (data[IPMI_DATA_OFFSET + 6] == FRU_DEVICE_SDR_TYPE) {

			sdr.offset = 0x10;
			sdr.length = strlen(SUN_FRU);
			if ((ret = get_sdr(&sdr)) < 0) {
				return (ret);
			}

			/* completion code */
			if (data[IPMI_DATA_OFFSET] != 0) {
				return (-1);
			}

			if (strncmp(&data[IPMI_DATA_OFFSET+ 3],
				SUN_FRU, strlen(SUN_FRU)) == 0) {
				/* found sun sdr */
				sdr.offset = 0x0;
				sdr.length = 7;
				if ((ret = get_sdr(&sdr)) < 0) {
					return (ret);
				}

				/* completion code */
				if (data[IPMI_DATA_OFFSET] != 0) {
					return (-1);
				}
				return (data[IPMI_DATA_OFFSET +	9]);
			}
		}
	}
	return (-1);
}

static int
get_sdr(sdr_info_t *sdr)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t res_pkt;
	uint8_t datap[6];

	if (sdr->lun > 3) {
		return (-1);
	}

	/* data  for request packet */
	datap[0] = 0x0;		/* reserved */
	datap[1] = 0x0;		/* reserved */
	datap[2] = sdr->record_id_lsb;
	datap[3] = sdr->record_id_msb;
	datap[4] = sdr->offset;
	datap[5] = sdr->length;

	(void) smc_init_ipmi_msg(&req_pkt, SMC_GET_DEVICE_SDR,
		FRUACCESS_MSG_ID, 6, datap, DEFAULT_SEQN,
		sdr->dest, SMC_NETFN_SENSOR_REQ, sdr->lun);

	if (smc_send_msg(DEFAULT_FD, &req_pkt, &res_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	bzero(sdr->buffer, SDR_BUFFER_LEN_MAX);
	(void) memcpy(sdr->buffer, res_pkt.data, res_pkt.hdr.len);
	return (0);
}
