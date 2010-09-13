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

#ifndef _SYS_SCSI_ADAPTERS_EMUL64_H
#define	_SYS_SCSI_ADAPTERS_EMUL64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the commands and structures for three emul64 ioctls,
 * that may be useful in speeding up tests involving large devices.  The
 * ioctls are documented at
 * http://lvm.central.sun.com/projects/lagavulin/emul64_design.html#ioctl.
 * Briefly, there are three ioctls:
 *
 *	EMUL64_WRITE_OFF - ignore all write operations to a specified block
 *		range.
 *	EMUL64_WRITE_ON - enable writes to a specified block range.
 *	EMUL64_ZERO_RANGE - zero all blocks in the specified range.
 *
 * The emul64_range structure is used to specify a block range for these
 * ioctls.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <sys/types.h>
#include <sys/scsi/scsi.h>

/*
 * emul64 ioctl commands:
 */

#define	EMUL64IOC	('e' << 8)

#define	EMUL64_WRITE_OFF	(EMUL64IOC|37)
#define	EMUL64_WRITE_ON		(EMUL64IOC|38)
#define	EMUL64_ZERO_RANGE	(EMUL64IOC|39)
#define	EMUL64_ERROR_INJECT	(EMUL64IOC|40)

struct emul64_range {
	diskaddr_t	emul64_sb;	/* starting block # of range */
	uint64_t	emul64_blkcnt;	/* # of blocks in range */
};

typedef struct emul64_range emul64_range_t;

/*
 * Structure to use when specifying an ioctl for a range of blocks on a
 * specific target.
 */
struct emul64_tgt_range {
	emul64_range_t	emul64_blkrange; /* blocks affected by ioctl */
	ushort_t	emul64_target;	/* target number of disk */
	ushort_t	emul64_lun;	/* lun of disk */
};

typedef struct emul64_tgt_range emul64_tgt_range_t;

/*
 * Structure to use for specifying error injection sense data
 */
#define	ERR_INJ_DISABLE		0
#define	ERR_INJ_ENABLE		1
#define	ERR_INJ_ENABLE_NODATA	2

struct emul64_error_inj_data {
	ushort_t	eccd_target;
	ushort_t	eccd_lun;
	ushort_t	eccd_inj_state; /* ERR_INJ_DISABLE, ... */
	ushort_t	eccd_sns_dlen; /* Number of bytes of sense data */
	struct scsi_status eccd_scsi_status;
	uchar_t		eccd_pkt_reason;
	uint_t		eccd_pkt_state;
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SCSI_ADAPTERS_EMUL64_H */
