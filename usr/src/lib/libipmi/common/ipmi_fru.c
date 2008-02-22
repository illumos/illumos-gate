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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libipmi.h>
#include <string.h>

#include "ipmi_impl.h"

/*
 * Extracts bits between index h (high, inclusive) and l (low, exclusive) from
 * u, which must be an unsigned integer.
 */
#define	BITX(u, h, l)	(((u) >> (l)) & ((1LU << ((h) - (l) + 1LU)) - 1LU))

typedef struct ipmi_fru_read
{
	uint8_t		ifr_devid;
	uint8_t		ifr_offset_lsb;
	uint8_t		ifr_offset_msb;
	uint8_t		ifr_count;
} ipmi_fru_read_t;

/*
 * returns: size of FRU inventory data in bytes, on success
 *          -1, otherwise
 */
int
ipmi_fru_read(ipmi_handle_t *ihp, ipmi_sdr_fru_locator_t *fru_loc, char **buf)
{
	ipmi_cmd_t cmd, *resp;
	uint8_t count, devid;
	uint16_t sz, offset = 0;
	ipmi_fru_read_t cmd_data_in;

	devid = fru_loc->_devid_or_slaveaddr._logical._is_fl_devid;
	/*
	 * First we issue a command to retrieve the size of the specified FRU's
	 * inventory area
	 */
	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_cmd = IPMI_CMD_GET_FRU_INV_AREA;
	cmd.ic_data = &devid;
	cmd.ic_dlen = sizeof (uint8_t);
	cmd.ic_lun = 0;

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen != 3) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (-1);
	}

	(void) memcpy(&sz, resp->ic_data, sizeof (uint16_t));
	if ((*buf = malloc(sz)) == NULL) {
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);
		return (-1);
	}

	while (offset < sz) {
		cmd_data_in.ifr_devid = devid;
		cmd_data_in.ifr_offset_lsb = BITX(offset, 7, 0);
		cmd_data_in.ifr_offset_msb = BITX(offset, 15, 8);
		if ((sz - offset) < 128)
			cmd_data_in.ifr_count = sz - offset;
		else
			cmd_data_in.ifr_count = 128;

		cmd.ic_netfn = IPMI_NETFN_STORAGE;
		cmd.ic_cmd = IPMI_CMD_READ_FRU_DATA;
		cmd.ic_data = &cmd_data_in;
		cmd.ic_dlen = sizeof (ipmi_fru_read_t);
		cmd.ic_lun = 0;

		if ((resp = ipmi_send(ihp, &cmd)) == NULL)
			return (-1);

		(void) memcpy(&count, resp->ic_data, sizeof (uint8_t));
		if (count != cmd_data_in.ifr_count) {
			(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH,
			    NULL);
			return (-1);
		}
		(void) memcpy((*buf)+offset, (char *)(resp->ic_data)+1, count);
		offset += count;
	}
	return (sz);
}

int
ipmi_fru_parse_product(ipmi_handle_t *ihp, char *fru_area,
    ipmi_fru_prod_info_t *buf)
{
	ipmi_fru_hdr_t fru_hdr;
	char *tmp;
	uint8_t len, typelen;

	(void) memcpy(&fru_hdr, fru_area, sizeof (ipmi_fru_hdr_t));

	/*
	 * We get the offset to the product info area from the FRU common
	 * header which is at the start of the FRU inventory area.
	 *
	 * The product info area is optional, so if the offset is NULL,
	 * indicating that it doesn't exist, then we return an error.
	 */
	if (!fru_hdr.ifh_product_info_off) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
		return (-1);
	}

	tmp = fru_area + (fru_hdr.ifh_product_info_off * 8) + 3;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1, buf->ifpi_manuf_name);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1,
	    buf->ifpi_product_name);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1, buf->ifpi_part_number);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1,
	    buf->ifpi_product_version);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1,
	    buf->ifpi_product_serial);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1, buf->ifpi_asset_tag);

	return (0);
}


/*
 * The Board Info area is described in Sect 11 of the IPMI Platform Management
 * FRU Information Storage Definition (v1.1).
 */
int
ipmi_fru_parse_board(ipmi_handle_t *ihp, char *fru_area,
    ipmi_fru_brd_info_t *buf)
{
	ipmi_fru_hdr_t fru_hdr;
	char *tmp;
	uint8_t len, typelen;

	(void) memcpy(&fru_hdr, fru_area, sizeof (ipmi_fru_hdr_t));

	/*
	 * We get the offset to the board info area from the FRU common
	 * header which is at the start of the FRU inventory area.
	 *
	 * The board info area is optional, so if the offset is NULL,
	 * indicating that it doesn't exist, then we return an error.
	 */
	if (!fru_hdr.ifh_board_info_off) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
		return (-1);
	}
	tmp = fru_area + (fru_hdr.ifh_board_info_off * 8) + 3;

	(void) memcpy(buf->ifbi_manuf_date, tmp, 3);
	tmp += 3;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1, buf->ifbi_manuf_name);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1, buf->ifbi_board_name);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1,
	    buf->ifbi_product_serial);
	tmp += len + 1;

	(void) memcpy(&typelen, tmp, sizeof (uint8_t));
	len = BITX(typelen, 4, 0);
	ipmi_decode_string((typelen >> 6), len, tmp+1, buf->ifbi_part_number);

	return (0);
}
