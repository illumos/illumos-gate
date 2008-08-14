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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <errno.h>
#include <mms_dmd.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_drive.h>
#include <mms_sym.h>

static	char *_SrcFile = __FILE__;

int
drv_get_capacity(mms_capacity_t *cap)
{
	uchar_t		buf[40];
	int		off;
	int		i;
	uint32_t	code;
	uint32_t	max = 0;
	uint32_t	avail = 0;
	int		page_control = 1;	/* return current value */

	if (DRV_CALL(drv_log_sense,
	    (buf, sizeof (buf), page_control, 0x31)) != 0) {
		return (EIO);
	}

	for (i = 0; i < 4; i++) {
		off = 4 + i * 8;
		char_to_uint32(buf + off, 2, &code);
		if (code == 1) {	/* Max capacity */
			char_to_uint32(buf + off + 4, 4, &avail);
			cap->mms_avail = avail;
			break;
		}
	}

	for (i = 0; i < 4; i++) {
		off = 4 + i * 8;
		char_to_uint32(buf + off, 2, &code);
		if (code == 3) {	/* capacity left */
			char_to_uint32(buf + off + 4, 4, &max);
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
