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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <string.h>
#include <errno.h>
#include <mms_dmd.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_drive.h>
#include <mms_sym.h>

static	char *_SrcFile = __FILE__;

/*
 * Specify whether the persistent reserve out command is supported or not.
 * 0 - not supported
 * 1 - supported
 *
 * If the persistent reserve out command is supported, then it will be used
 * to reserve the drive.
 * If the persistent reserve out command is not supported, then the reserve
 * command will be used to reserve the drive.
 */
int	drv_prsv_supported = 1;		/* persistent reserve out supported */

/*
 * specify timeouts for this drive. Time is specified in seconds.
 */
drv_timeout_t	drv_timeout = {
	(151 *60),			/* For really long commands */
	(20 *60),			/* Normal commands */
	(1 *60),			/* short commands */
};

/*
 * Specify drive type of this drive
 * drv_drive_type must be a string.
 */
char	drv_drive_type[] = "dt_SDLT600";

/*
 * drv_density[]
 * - Specify density names with their density codes supported by this DM.
 * - Densities must be specified in the order of their selection priority.
 *   The ones at the beginning of the list will be selected before those
 *   at the end of the list.
 * - Density names must start with "den_" to avoid conflict with other names.
 */
mms_sym_t	drv_density[] = {
	"den_SDLT2", 0x4A,
	"den_SDLT1_220", 0x48,
	"den_SDLT1_320", 0x49,
	"den_VStape_160", 0x50,
	NULL				/* Must be last entry */
};

/*
 * drv_shape[]
 * - Specify shape names of cartridge types supported by this DM.
 * - Shape names must be specified in the order of their selection priority.
 *   The ones at the beginning of the list will be selected before those
 *   at the end of the list.
 * - Shape name must be a well known and published name.
 */
char	*drv_shape[] = {
	"SDLT2",
	"SDLT1",
	"VStape1",
	NULL				/* Must be last entry */
};

/*
 * drv_shape_den[]
 * Specify the shape of a cartridge and the density on it that can be
 * written over by a readwrite density.
 * All shape names and density names must have been specified in
 * drv_density[] and drv_shape[].
 * Each entry of the array consists of:
 * {shapename, density on cart, readwrite density}.
 * If the density on cartridge is the same as the readwrite density, then
 * the drive can read and write with that density.
 * If the density on cartridge is read only, then the readwrite density
 * is NULL.
 * If the readwrite density is not NULL and it is different from the density
 * on cartridge, then the drive is able to write over the existing data
 * starting from the beginning of medium.
 */

drv_shape_density_t	drv_shape_den[] = {
	/* shapename    existing den    readwrite density */
	/*
	 * Specify readwrite density
	 */
	"SDLT2", "den_SDLT2", "den_SDLT2",

	/*
	 * Specify readonly density
	 */
	"VStape1", "den_VStape_160", NULL,
	"SDLT1", "den_SDLT1_220", NULL,
	"SDLT1", "den_SDLT1_320", NULL,
	NULL				/* Must be last entry */
};

int
drv_get_capacity(mms_capacity_t *cap)
{
	uchar_t		buf[30];
	int		off;
	int		i;
	uint32_t	code;
	uint32_t	max = 0;
	uint32_t	avail = 0;

	if (DRV_CALL(drv_read_attribute,
	    (buf, sizeof (buf), 0x00, 0x00)) != 0) {
		return (EIO);
	}

	for (i = 0; i < 2; i++) {
		off = 4 + i * 13;
		char_to_uint32(buf + off, 2, &code);
		if (code == 0x0000) {	/* capacity left */
			char_to_uint32(buf + off + 5, 8, &avail);
			cap->mms_avail = avail;
			break;
		}
	}

	for (i = 0; i < 2; i++) {
		off = 4 + i * 13;
		char_to_uint32(buf + off, 2, &code);
		if (code == 0x0001) {	/* Max capacity */
			char_to_uint32(buf + off + 5, 8, &max);
			cap->mms_max = max;
			break;
		}
	}

	if (max > 0) {
		cap->mms_pc_avail = (avail * 100) / max;
		if (cap->mms_pc_avail > 100) {
			cap->mms_pc_avail = 100;
		}
	} else {
		cap->mms_pc_avail = 0;
	}

	TRACE((MMS_INFO, "Capacity: max %lld, avail %lld, avail %d%%",
	    cap->mms_max, cap->mms_avail, cap->mms_pc_avail));

	return (0);
}

int
drv_read_attribute(uchar_t *buf, int32_t len, int servact, int32_t attr)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x8C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00 };
	char		dumpbuf[1024];

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)buf;
	us.uscsi_buflen = len;

	cdb[1] = (servact & 0x1F);
	int32_to_char(len, cdb + 10, 4);
	int32_to_char(attr, cdb + 8, 2);

	TRACE((MMS_DEBUG, "Read attribute"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	(void) mms_trace_dump((char *)buf, len, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "read attribute data:\n%s", dumpbuf));

	return (0);
}
