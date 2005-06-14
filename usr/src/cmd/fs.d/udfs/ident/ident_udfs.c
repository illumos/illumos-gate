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
 * Copyright 1999,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<rmmount.h>
#include	<rpc/types.h>
#include	<sys/types.h>
#include	<sys/cdio.h>
#include	<sys/dkio.h>
#include	<sys/fs/udf_volume.h>

static bool_t udfs_check_avds(int32_t, uint8_t *,
		int32_t, uint32_t *, uint32_t *, uint32_t);
static bool_t udfs_getsector(int32_t, uint8_t *, int32_t, int32_t);
static uint32_t ud_verify_tag_and_desc(struct tag *, uint16_t,
					uint32_t, int32_t);
static uint16_t ud_crc(uint8_t *, int32_t);

/*
 * We call it a udfs file system iff:
 *	The File system is a valid udfs
 *
 */

#ifdef STANDALONE
/*
 * Compile using cc -DSTANDALONE ident_udfs.c
 * if needed to run this standalone for testing
 */
int32_t
main(int32_t argc, char *argv[])
{
	int32_t			clean;
	int32_t			fd;
	int32_t			ret;

	if (argc != 2) {
		(void) printf("Usage : %s device_name\n", argv[0]);
		return (1);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[0]);
		return (1);
	}

	ret = ident_fs(fd, "", &clean, 0);
	(void) printf("return value of ident_fs is %s clean flag "
		"is set to %d\n", (ret == TRUE) ? "TRUE" : "FALSE", clean);

	(void) close(fd);
	return (0);
}
#endif

/*
 * As sun scsi cdrom drives return block size of different
 * values 512, 1024, 2048 so we still need to check the
 * different blocksizes on the device. But on the other
 * hand ATAPI cdrom and DVD-ROM
 * drives will return the blocksize as 2048 which is
 * the most probable block size of UDFS on a CD/DVD media
 * for this reason we issue the ioctl at the begining of
 * the code. The code also handles the situation when
 * a a image is created on a Hard Disk and copied to a CD-ROM.
 */
/* ARGSUSED */
int32_t
ident_fs(int32_t fd, char *rawpath, int32_t *clean, int32_t verbose)
{
	int32_t			ssize = 0;
	int32_t			count = 0;
	int32_t			index = 0;
	int32_t			ret = FALSE;
	int32_t			bsizes[] = {0, 512, 1024, 2048};
	uint32_t		loc = 0;
	uint32_t		len = 0;
	struct	log_vol_desc	*lvd = NULL;
	struct	log_vol_int_desc	*lvid = NULL;
	uint8_t			*read_buf = NULL;
	uint32_t		buf[2048/4];
				/* size match with the biggest bsizes */
	struct	dk_minfo	dkminfo;
	uint32_t		offset = 0;
	int32_t			desc_len;

	read_buf = (uint8_t *)buf;

	/*
	 * Try to get the physical
	 * block size of the device
	 */
	if (ioctl(fd, CDROMGBLKMODE, &bsizes[0]) < 0) {
		/*
		 * Not a CDROM so issue DKIOCGMEDIAINFO
		 */
		if (ioctl(fd, DKIOCGMEDIAINFO, &dkminfo) == 0) {
			bsizes[0] = dkminfo.dki_lbsize;
		} else {
			bsizes[0] = 512;
		}
	} else {
		if (ioctl(fd, CDROMREADOFFSET, &offset) == -1) {
			offset = 0;
		}
	}

	/* Read AVD */
	count = sizeof (bsizes) / sizeof (int32_t);
	for (index = 0; index < count; index++) {
		if ((index > 0) && (bsizes[index] == bsizes[0])) {
			continue;
		}
		ret = udfs_check_avds(fd, read_buf, bsizes[index],
				&loc, &len, offset);
		if (ret == TRUE) {
			break;
		}
	}
	/*
	 * Return FALSE if there is no Anchor Volume Descriptor
	 */
	if (ret == FALSE) {
		return (FALSE);
	}

	ssize = bsizes[index];

	/*
	 * read mvds and figure out the location
	 * of the lvid
	 */
	count = len / ssize;
	for (index = 0; index < count; index++) {
		if (udfs_getsector(fd, read_buf, loc + index, ssize) == FALSE) {
			return (FALSE);
		}
		desc_len = len - (index * ssize);
		/* LINTED */
		lvd = (struct log_vol_desc *)read_buf;
		if (ud_verify_tag_and_desc(&lvd->lvd_tag, UD_LOG_VOL_DESC,
		    loc + index, desc_len) == 0) {
			if (strncmp(lvd->lvd_dom_id.reg_id,
			    UDF_DOMAIN_NAME, 23) != 0) {
				return (FALSE);
			}
			loc = SWAP_32(lvd->lvd_int_seq_ext.ext_loc);
			len = SWAP_32(lvd->lvd_int_seq_ext.ext_len);
			break;
		}
	}
	if (index == count) {
		return (FALSE);
	}

	/*
	 * See if the lvid is closed
	 * or open integrity
	 */
	count = len / ssize;
	for (index = 0; index < count; index++) {
		if (udfs_getsector(fd, read_buf, loc + index, ssize) == FALSE) {
			return (FALSE);
		}
		desc_len = len - (index * ssize);
		/* LINTED */
		lvid = (struct log_vol_int_desc *)read_buf;
		if (ud_verify_tag_and_desc(&lvid->lvid_tag, UD_LOG_VOL_INT,
		    loc + index, desc_len) == 0) {
			if (SWAP_32(lvid->lvid_int_type) == LOG_VOL_OPEN_INT) {
				*clean = FALSE;
			} else {
				*clean = TRUE;
			}
			return (TRUE);
		}
	}
	return (FALSE);
}

static bool_t
udfs_check_avds(int32_t fd, uint8_t *read_buf, int32_t ssize,
		uint32_t *mvds_loc, uint32_t *mvds_size, uint32_t offset)
{
	struct	anch_vol_desc_ptr	*avd = NULL;
	uint32_t			loc = 0;

	if (ssize <= 2048) {
		loc = offset * 2048 / ssize + ANCHOR_VOL_DESC_LOC;
	} else {
		loc = offset / (ssize / 2048) + ANCHOR_VOL_DESC_LOC;
	}

	if (udfs_getsector(fd, read_buf, loc, ssize) == TRUE) {

		/* LINTED */
		avd = (struct anch_vol_desc_ptr *)read_buf;
		if (ud_verify_tag_and_desc(&avd->avd_tag, UD_ANCH_VOL_DESC,
		    loc, ANCHOR_VOL_DESC_LEN) == 0) {
			*mvds_loc = SWAP_32(avd->avd_main_vdse.ext_loc);
			*mvds_size = SWAP_32(avd->avd_main_vdse.ext_len);
			return (TRUE);
		}
	}
	return (FALSE);
}

static bool_t
udfs_getsector(int32_t fd, uint8_t *buf, int32_t secno, int32_t ssize)
{
	if (llseek(fd, (offset_t)(secno * ssize), SEEK_SET) < 0L) {
		return (FALSE);
	}

	if (read(fd, buf, ssize) != ssize) {
		return (FALSE);
	}

	/* all went well */
	return (TRUE);
}

static uint32_t
ud_verify_tag_and_desc(struct tag *tag, uint16_t id,
		uint32_t blockno, int32_t desc_len)
{
	int32_t i;
	uint8_t *addr, cksum = 0;
	uint16_t crc;

	/*
	 * Verify Tag Identifier
	 */
	if (tag->tag_id != SWAP_16(id)) {
		return (1);
	}

	/*
	 * Calculate Tag Checksum
	 */
	addr = (uint8_t *)tag;
	for (i = 0; i <= 15; i++) {
		if (i != 4) {
			cksum += addr[i];
		}
	}

	/*
	 * Verify Tag Checksum
	 */
	if (cksum != tag->tag_cksum) {
		return (1);
	}

	/*
	 * We are done verifying the tag. We proceed with verifying the
	 * the descriptor. desc_len indicates the size of the structure
	 * pointed to by argument tag. It includes the size of struct tag.
	 * We first check the tag_crc_len since we use this to compute the
	 * crc of the descriptor.
	 */
	if (SWAP_16(tag->tag_crc_len) > (desc_len - sizeof (struct tag))) {
		return (1);
	}
	if (tag->tag_crc_len) {

		/*
		 * Caliculate CRC for the descriptor
		 */
		crc = ud_crc(addr + 0x10, SWAP_16(tag->tag_crc_len));

		/*
		 * Verify CRC
		 */
		if (crc != SWAP_16(tag->tag_crc)) {
			return (1);
		}
	}

	/*
	 * Verify Tag Location
	 */
	if (SWAP_32(blockno) != tag->tag_loc) {
		return (1);
	}

	return (0);
}

static uint16_t ud_crc_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

static uint16_t
ud_crc(uint8_t *addr, int32_t len)
{
	uint16_t crc = 0;

	while (len-- > 0) {
		crc = ud_crc_table[(crc >> 8 ^ *addr++) & 0xff] ^ (crc<<8);
	}

	return (crc);
}
