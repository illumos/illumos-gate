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

#ifndef _SCSI_IMPL_USCSI_H
#define	_SCSI_IMPL_USCSI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Defines for user SCSI commands
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * definition for user-scsi command structure
 */
struct uscsi_cmd {
	caddr_t	uscsi_cdb;
	int	uscsi_cdblen;
	caddr_t	uscsi_bufaddr;
	int	uscsi_buflen;
	unsigned char	uscsi_status;
	int	uscsi_flags;
};

/*
 * flags for uscsi_flags field
 */
#define	USCSI_SILENT	0x01	/* no error messages */
#define	USCSI_DIAGNOSE	0x02	/* fail if any error occurs */
#define	USCSI_ISOLATE	0x04	/* isolate from normal commands */
#define	USCSI_READ	0x08	/* get data from device */
#define	USCSI_WRITE	0xFFF7	/* use to zero the READ bit in uscsi_flags */

/*
 * User SCSI io control command
 */
#define	USCSICMD	_IOWR('u', 1, struct uscsi_cmd) /* user scsi command */

/*
 * user scsi status bit masks
 */

#define	USCSI_STATUS_GOOD			0x00
#define	USCSI_STATUS_CHECK			0x02
#define	USCSI_STATUS_MET			0x04
#define	USCSI_STATUS_BUSY			0x08
#define	USCSI_STATUS_INTERMEDIATE		0x10
#define	USCSI_STATUS_RESERVATION_CONFLICT	\
	(USCSI_STATUS_INTERMEDIATE | USCSI_STATUS_BUSY)

#ifdef	__cplusplus
}
#endif

#endif	/* _SCSI_IMPL_USCSI_H */
