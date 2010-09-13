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

/*
 * PHOTON CONFIGURATION MANAGER
 * Error definitions
 */

#ifndef	_L_ERROR_H
#define	_L_ERROR_H



/*
 * Include any headers you depend on.
 */

/*
 * I18N message number ranges
 *  This file: 15000 - 15499
 *  Shared common messages: 1 - 1999
 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * This header file contains the error definitions
 * which are not exported but are used internally.
 */

/* Persistant Rservation: Invalid transfer length */
#define	L_PR_INVLD_TRNSFR_LEN		0x10001

/*
 * Error definitions
 * for Format Errors.
 */
/* box name conflicts with the SSA name */
#define	L_SSA_CONFLICT			0x20013


/*
 * Error definitions
 * for System Errors
 */
/* drvconfig fail */
#define	L_DRVCONFIG_ERROR		0x31001

/* disks program failed */
#define	L_DISKS_ERROR			0x31002

/* devlinks program failed */
#define	L_DEVLINKS_ERROR		0x31003

/* fail to read /dev/rdsk directory. */
#define	L_READ_DEV_DIR_ERROR		0x31004

/* Failed to open /dev/es/ directory. */
#define	L_OPEN_ES_DIR_FAILED		0x31005

/* fail to get status from /dev/es directory. */
#define	L_LSTAT_ES_DIR_ERROR		0x31006

/* disks program failed */
#define	L_TAPES_ERROR			0x31007

/* fail to get status from /dev/rmt/directory. */
#define	L_STAT_RMT_DIR_ERROR		0x31008

/* fail to get status from /dev/rmt/directory. */
#define	L_STAT_DEV_DIR_ERROR		0x31009


/*
 * Error definitions
 * specific to Back plane.
 */
/* Backplane: Busy or reserved disks found */
#define	L_BP_BUSY_RESERVED		0x50000

/* Backplane: one or more busy disks found */
#define	L_BP_BUSY			0x50001

/* Backplane: one or more reserved disks found */
#define	L_BP_RESERVED			0x50002

/* No BP element found in the enclosure */
#define	L_NO_BP_ELEM_FOUND		0x50003

/*
 * Thread errors.
 */
#define	L_TH_CREATE			0x60000
#define	L_TH_JOIN			0x60001


#ifdef	__cplusplus
}
#endif

#endif	/* _L_ERROR_H */
