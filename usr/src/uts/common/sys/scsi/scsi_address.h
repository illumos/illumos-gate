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

#ifndef	_SYS_SCSI_SCSI_ADDRESS_H
#define	_SYS_SCSI_SCSI_ADDRESS_H

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI address definition.
 *
 * A scsi_address structure stores the host routing and device unit-address
 * information necessary to reference a specific SCSI target device logical
 * unit function.
 *
 * The host routing information is stored in the scsi_hba_tran(9S) structure
 * pointed to by the a_hba_tran field.
 *
 * The device unit-address information is SCSA's representation of the
 * "@unit-address" portion of a SCSI target driver device node in the
 * /devices tree.  Separate components of the device unit-address information
 * define the target address and the logical unit address of a target.
 * In general, device unit-address information is used exclusively by the
 * host adapter driver (the exception being target drivers communicating
 * with SCSI Parallel Interconnect (SPI) SCSI-1 devices that embed SCSI
 * logical unit addressing in the CDB).
 *
 * Thus the a_target and a_lun fields are for compatibility purposes only.
 * They are not defined in SCSI-3.  SCSI-3 target drivers which need to
 * communicate with SPI SCSI-1 devices that embed logical unit addresses in
 * the CDB should obtain target and logical unit addresses from the device's
 * properties (SCSI_ADDR_PROP_TARGET and SCSI_ADDR_PROP_LUN).
 *
 * a_sublun is reserved for internal use only and is never part of DDI
 * (scsi_address(9S)).
 */
struct scsi_address {
	struct scsi_hba_tran	*a_hba_tran;	/* Transport vectors */
	ushort_t		a_target;	/* Target identifier */
	uchar_t			a_lun;		/* Lun on that Target */
	uchar_t			a_sublun;	/* Sublun on that Lun */
						/* Not used */
};

/* Device unit-address property names */
#define	SCSI_ADDR_PROP_TARGET		"target"
#define	SCSI_ADDR_PROP_LUN		"lun"

/*
 * Normalized representation of a scsi_lun (with SCSI-2 lun positioned
 * for compatibility).
 */
typedef uint64_t	scsi_lun64_t;
#define	PRIlun64	PRIx64
#ifdef	_LP64
#define	SCSI_LUN64_ILLEGAL	(-1L)
#else	/* _LP64 */
#define	SCSI_LUN64_ILLEGAL	(-1LL)
#endif	/* _LP64 */

/* Structure of a 64-bit SCSI LUN per SCSI standard */
typedef	struct scsi_lun {
	uchar_t	sl_lun1_msb;	/* format */
	uchar_t	sl_lun1_lsb;	/* first level */
	uchar_t	sl_lun2_msb;
	uchar_t	sl_lun2_lsb;	/* second level */
	uchar_t	sl_lun3_msb;
	uchar_t	sl_lun3_lsb;	/* third level */
	uchar_t	sl_lun4_msb;
	uchar_t	sl_lun4_lsb;	/* fourth level */
} scsi_lun_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_ADDRESS_H */
