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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "fru_access_impl.h"

static uchar_t			sp_sec_hdr[] = SP_SEC_HDR;
static uchar_t			sp_seg_hdr[] = SP_SEG_HDR;
static uchar_t			sp_seg_body[] = SP_DATA;

/*
 * function to return section header for simulated SPD fruid
 *
 * parameters:
 *	sec_hdr		buffer to receive section header
 *	sec_hdr_len	size of buffer sec_hdr
 * return value:
 *	size of returned data (0 if sec_hdr_len too small)
 */
size_t
get_sp_sec_hdr(void *sec_hdr, size_t sec_hdr_len)
{
	if (sec_hdr_len < sizeof (sp_sec_hdr))
		return (0);
	(void) memcpy(sec_hdr, sp_sec_hdr, sizeof (sp_sec_hdr));
	return (sizeof (sp_sec_hdr));
}

/*
 * function to return segment header for simulated SPD fruid
 *
 * parameters:
 *	seg_hdr		buffer to receive segment header
 *	seg_hdr_len	size of buffer seg_hdr
 * return value:
 *	size of returned data (0 if seg_hdr_len too small)
 */
size_t
get_sp_seg_hdr(void *seg_hdr, size_t seg_hdr_len)
{
	if (seg_hdr_len < sizeof (sp_seg_hdr))
		return (0);
	(void) memcpy(seg_hdr, sp_seg_hdr, sizeof (sp_seg_hdr));
	return (sizeof (sp_seg_hdr));
}

/*
 * Function to convert SPD data into SPD fruid segment.
 * The segment comprises two tagged records: DIMM_Capacity and SPD_R.
 *
 * DIMM_Capacity is a text string showing the total usable size of the
 * DIMM (i.e. not including error correction bits). This record is derived
 * from module row density and number of rows.
 *
 * SPD_R contains the entire SPD data area from the DIMM. It is slightly
 * massaged to make it easier to display:
 * bytes  0 -  63 are presented as is
 * bytes 64 -  71 (JEDEC code) are compressed into 2 bytes, matching the
 *		  format used in ManR
 * bytes 72 -  92 are copied as is (to bytes 66 - 86)
 * byte  93	  year of manufacture is expanded to a 2 byte (big endian)
 *		  field which includes the century (to bytes 87 - 88)
 * bytes 94 - 127 are copied as is (to bytes 89 - 122)
 *
 * parameters:
 *	spd_data	pointer to SPD data
 *	spd_data_len	length of supplied SPD data
 *	sp_seg_ptr	pointer to receive address of converted data
 *	sp_seg_len	pointer for size of converted data
 * return value:
 *	0	- success
 *	NZ	- error code
 */
int
cvrt_dim_data(const char *spd_data, size_t spd_data_len, uchar_t **sp_seg_ptr,
    size_t *sp_seg_len)
{
	int		c;
	ushort_t	year;
	int		capacity;
	spd_data_t	*spd;
	uint32_t	sum;

	if (spd_data_len < sizeof (spd_data_t))
		return (EINVAL);

	spd = (spd_data_t *)spd_data;
	*sp_seg_ptr = malloc(sizeof (sp_seg_body));

	if (*sp_seg_ptr == NULL)
		return (ENOMEM);

	/* set up template for SP seg */
	(void) memcpy(*sp_seg_ptr, sp_seg_body, sizeof (sp_seg_body));

	year = spd->manu_year;

	if (year < 80)
		year += 2000;
	else
		year += 1900;

	/*
	 * move first 64 bytes of SPD data into SPD-R record
	 */
	(void) memcpy(*sp_seg_ptr + SPD_R_OFF, spd_data, 64);

	/*
	 * re-write full data width as big endian
	 */
	(*sp_seg_ptr + SPD_R_OFF + DATA_WIDTH)[0] = spd->ms_data_width;
	(*sp_seg_ptr + SPD_R_OFF + DATA_WIDTH)[1] = spd->ls_data_width;

	/*
	 * construct Sun compressed encoding for JEDEC code
	 */
	for (c = 0; c < sizeof (spd->jedec) - 1; c++) {
		if (spd->jedec[c] != 0x7F)
			break;
	}

	(*sp_seg_ptr)[SPD_R_OFF + MANUF_ID] = (uchar_t)c;
	(*sp_seg_ptr)[SPD_R_OFF + MANUF_ID + 1] = (uchar_t)spd->jedec[c];

	/*
	 * move other fields in place
	 */
	(void) memcpy(*sp_seg_ptr + SPD_R_OFF + MANUF_LOC,
	    &spd->manu_loc, MANUF_YEAR - MANUF_LOC);

	(*sp_seg_ptr + SPD_R_OFF + MANUF_YEAR)[0] = (uchar_t)(year >> 8);
	(*sp_seg_ptr + SPD_R_OFF + MANUF_YEAR)[1] = (uchar_t)year;

	(void) memcpy(*sp_seg_ptr + SPD_R_OFF + MANUF_WEEK,
	    &spd->manu_week, SPD_R_LEN - MANUF_WEEK);

	/*
	 * calculate the capacity and insert into capacity record
	 */
	if ((spd->spd_rev >> 4) > 1) {
		(void) snprintf((char *)(*sp_seg_ptr + DIMM_CAP_OFF), 8,
		    "ver %x.%x", spd->spd_rev >> 4, spd->spd_rev & 0x0f);
	} else if ((spd->memory_type != SPDMEM_SDRAM) &&
	    (spd->memory_type != SPDMEM_SDRAM_DDR) &&
	    (spd->memory_type != SPDMEM_DDR2_SDRAM)) {
		/*
		 * can't handle this memory type
		 */
		((char *)(*sp_seg_ptr))[DIMM_CAP_OFF] = '\0';
	} else if ((((spd->ms_data_width << 8) | spd->ls_data_width) == 72) &&
	    ((spd->n_rows & 0xf0) == 0) && ((spd->n_cols & 0xf0) == 0)) {
		/*
		 * OK it's 72-bits wide with equal width banks
		 */
		char m_or_g = 'G';
		capacity = spd->mod_row_density;
		if (((spd->memory_type == SPDMEM_DDR2_SDRAM) &&
		    (capacity > 16)) ||
		    (capacity > 4)) {
			capacity *= 4;
			m_or_g = 'M';
		}
		c = spd->n_mod_rows;
		if (spd->memory_type == SPDMEM_DDR2_SDRAM) {
			c &= 7;
			c++;
		}
		capacity *= c;
		if ((m_or_g == 'M') && (capacity >= 1024)) {
			capacity /= 1024;
			m_or_g = 'G';
		}
		(void) snprintf((char *)(*sp_seg_ptr + DIMM_CAP_OFF), 8,
		    "%d %cB", capacity, m_or_g);
	} else {
		((char *)(*sp_seg_ptr))[DIMM_CAP_OFF] = '\0';
	}

	/*
	 * finally, set the checksum
	 */
	sum = compute_crc32(*sp_seg_ptr, sizeof (sp_seg_body) - 5);
	for (c = 0; c < 4; c++) {
		(*sp_seg_ptr + sizeof (sp_seg_body) - 4)[c] =
		    ((char *)(&sum))[c];
	}
	*sp_seg_len = sizeof (sp_seg_body);
	return (0);
}

/*
 * get_spd_data - reads raw data from container
 * parameters:
 *	fd		file descriptor for SPD device
 *	ctr_offset	container offset
 *	ctr_len		container size
 *	spd_data	buffer to receive SPD data (length ctr_len)
 * return value:
 *	0	- success
 *	NZ	- error code
 */
int
get_spd_data(int fd, char *spd_data, size_t ctr_len, off_t ctr_offset)
{
	if (ctr_len < sizeof (spd_data_t))
		return (EINVAL);

	(void) memset(spd_data, 0, ctr_len);

	if (pread(fd, spd_data, sizeof (spd_data_t), ctr_offset) !=
	    sizeof (spd_data_t))
		return (EIO);
	return (0);
}
