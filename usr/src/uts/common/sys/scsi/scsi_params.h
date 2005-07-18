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

#ifndef	_SYS_SCSI_SCSI_PARAMS_H
#define	_SYS_SCSI_SCSI_PARAMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	NUM_SENSE_KEYS		16	/* total number of Sense keys */

#define	NTAGS			256	/* number of tags per lun */

/*
 * General parallel SCSI parameters
 */
#define	NTARGETS		8	/* total # of targets per SCSI bus */
#define	NTARGETS_WIDE		16	/* #targets per wide SCSI bus */
#define	NLUNS_PER_TARGET	8	/* number of luns per target */

/*
 * the following defines are useful for setting max LUNs in
 * nexus/target drivers
 */
#define	SCSI_1LUN_PER_TARGET		1
#define	SCSI_8LUN_PER_TARGET		NLUNS_PER_TARGET
#define	SCSI_16LUNS_PER_TARGET		16
#define	SCSI_32LUNS_PER_TARGET		32

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_PARAMS_H */
