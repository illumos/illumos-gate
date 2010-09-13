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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TRACKIO_H
#define	_TRACKIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "bstream.h"
#include "misc_scsi.h"

struct trackio_error {
	int	err_type;
/* File I/O errors */
	int	te_errno;
/* Transport Errors */
	uchar_t	status, key, asc, ascq;
};

/*
 * trackio error types
 */
#define	TRACKIO_ERR_SYSTEM	1
#define	TRACKIO_ERR_TRANSPORT	2
#define	TRACKIO_ERR_USER_ABORT	3

/*
 * iob state
 */
#define	IOBS_UNDER_FILE_IO	1
#define	IOBS_UNDER_DEVICE_IO	2
#define	IOBS_READY		3
#define	IOBS_EMPTY		4

struct iobuf {
	uchar_t *iob_buf;
	uint32_t iob_total_size; /* total size of the buf */
	uint32_t iob_data_size;	 /* size of the data in buf */
	uint32_t iob_start_blk;	 /* starting block address on the device */
	uint16_t iob_nblks;	 /* number of data blocks in this buf */
	int iob_state;		 /* state of buf */
};

/* Use small buffers. Some drives do not behave well with large buffers */
#define	NIOBS			8
#define	NBLKS_PER_BUF		24	/* < 64K in all cases */
#define	DATA_TRACK_BLKSIZE	2048
#define	AUDIO_TRACK_BLKSIZE	2352

int write_track(cd_device *dev, struct track_info *ti, bstreamhandle h,
		int (*cb)(int64_t, int64_t), int64_t arg, struct
		trackio_error *te);

#ifdef	__cplusplus
}
#endif

#endif /* _TRACKIO_H */
