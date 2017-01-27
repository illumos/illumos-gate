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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2017, Joyent, Inc.
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
 * A scsi_address(9S) structure stores the host adapter routing and
 * scsi_device(9S) unit-address routing information necessary to reference
 * a specific SCSI target device logical unit function.
 *
 * Host adapter routing information is stored in the scsi_hba_tran(9S)
 * structure, pointed to by the scsi_address(9S) 'a_hba_tran' field.
 *
 * The scsi_device(9S) unit-address routing information (i.e. SCSA's
 * representation of leaf disk/tape driver's "@unit-address" portion of
 * a /devices path) is maintained in three different forms:
 *
 * SCSI_HBA_ADDR_SPI: In SCSI_HBA_ADDR_SPI mode (default), the SCSA
 *	framework, during initialization, places unit-address property
 *	information, converted to numeric form, directly into the
 *	'a_target' and 'a_lun' fields of the scsi_address(9S) structure
 *	(embedded in the scsi_device(9S) structure). To maintain
 *	per-scsi_device(9S) state, host adapter drivers often use
 *	'a_target' and 'a_lun' to index into a large fixed array
 *	(limited by the drivers idea of maximum supported target and
 *	lun).
 *
 *	NOTE: a_sublun is reserved for internal use only and has never
 *	been part of DDI scsi_address(9S).
 *
 * SCSI_HBA_ADDR_COMPLEX: The host adapter driver will maintain
 *	per-unit-address/per-scsi_device(9S) HBA private state by using
 *	scsi_device_hba_private_set(9F) during tran_tgt_init(9E) (using
 *	property interfaces to obtain/convert unit-address information into
 *	a host adapter private form).  In SCSI_HBA_ADDR_COMPLEX mode, the SCSA
 *	framework, prior to tran_tgt_init(9E), places a pointer to the
 *	scsi_device(9S) in the 'a.a_sd' scsi_address(9S) field, and uses
 *	'sd_hba_private' to store per-scsi_device hba private data.
 *
 * SCSI_HBA_TRAN_CLONE: SCSI_HBA_TRAN_CLONE is an older method for
 *	supporting devices with non-SPI unit-address. It is still
 *	supported, but its use is discouraged. From a unit-address
 *	perspective, operation is similar to SCSI_HBA_ADDR_COMPLEX, but
 *	per-scsi_device(9S) state is supported via 'cloning' of the
 *	scsi_hba_tran(9S) structure (to provide a per-scsi_device(9S)
 *	version of 'tran_tgt_private'/'tran_sd' accessible via
 *	'a_hba_tran').
 *
 * NOTE: Compatible evolution of SCSA is constrained by the fact that the
 * scsi_address(9S) structure is embedded at the base of the scsi_device(9S)
 * structure, and is structure copied into the base of each allocated
 * scsi_pkt(9S) structure.
 *
 * In general, device unit-address information is used exclusively by
 * the host adapter driver (the exception being target drivers
 * communicating with SCSI Parallel Interconnect (SPI) SCSI-1 devices
 * that embed SCSI logical unit addressing in the CDB). Target drivers
 * which need to communicate with SPI SCSI-1 devices that embed logical
 * unit addresses in the CDB must obtain target and logical unit
 * addresses from the device's properties (SCSI_ADDR_PROP_TARGET and
 * SCSI_ADDR_PROP_LUN).
 */
struct scsi_address {
	struct scsi_hba_tran	*a_hba_tran;	/* Transport vector */
	union {
		struct {			/* SPI: */
			ushort_t a_target;	/* ua target */
			uchar_t	 a_lun;		/* ua lun on target */
			uchar_t	 _a_sublun;	/* (private) */
		} spi;
		struct scsi_device *a_sd;	/* COMPLEX: (private) */
	} a;					/* device unit-adddress info */
};
#define	a_target	a.spi.a_target
#define	a_lun		a.spi.a_lun
#define	a_sublun	a.spi._a_sublun

/* Device unit-address property names */
#define	SCSI_ADDR_PROP_TARGET		"target"	/* int */
#define	SCSI_ADDR_PROP_LUN		"lun"		/* int */

#define	SCSI_ADDR_PROP_TARGET_PORT	"target-port"	/* string */
#define	SCSI_ADDR_PROP_LUN64		"lun64"		/* int64 */
#define	SCSI_ADDR_PROP_SFUNC		"sfunc"		/* int */

#define	SCSI_ADDR_PROP_IPORTUA		"scsi-iport"	/* string */

#define	SCSI_ADDR_PROP_SATA_PHY		"sata-phy"	/* int */

/*
 * Addressing property names, values are in string form compatible
 * with the SCSI_ADDR_PROP_TARGET_PORT part of the related
 * IEEE-1275 OpenFirmware binding unit-address string.
 */
#define	SCSI_ADDR_PROP_INITIATOR_PORT	"initiator-port"
#define	SCSI_ADDR_PROP_ATTACHED_PORT	"attached-port"
#define	SCSI_ADDR_PROP_BRIDGE_PORT	"bridge-port"

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

/* SCSI standard defined lun addressing methods (in sl_lunX_msb) */
#define	SCSI_LUN_AM_MASK	0xC0		/* Address Method Mask */
#define	SCSI_LUN_AM_PDEV	0x00		/* Peripheral device AM */
#define	SCSI_LUN_AM_FLAT	0x40		/* Flat space AM */
#define	SCSI_LUN_AM_LUN		0x80		/* Logical unit AM */
#define	SCSI_LUN_AM_EFLAT	0xC0		/* Extended flat space AM */
#define	SCSI_LUN_AM_ELUN	0xC0		/* Extended logical unit AM */

#ifdef	_KERNEL
/* SCSI LUN conversion between SCSI_ADDR_PROP_LUN64 and SCSI standard forms */
scsi_lun64_t	scsi_lun_to_lun64(scsi_lun_t lun);
scsi_lun_t	scsi_lun64_to_lun(scsi_lun64_t lun64);

/* SCSI WWN conversion (property values should be in unit_address form) */
int		scsi_wwnstr_to_wwn(const char *wwnstr, uint64_t *wwnp);
char		*scsi_wwn_to_wwnstr(uint64_t wwn,
		    int unit_address_form, char *wwnstr);
void		scsi_wwnstr_hexcase(char *wwnstr, int lower_case);
const char	*scsi_wwnstr_skip_ua_prefix(const char *wwnstr);
void		scsi_free_wwnstr(char *wwnstr);

/*
 * Buffer lengths for SCSI strings. SCSI_WWN_STRLEN is the length of a WWN
 * that's not in unit-address form. SCSI_WWN_UA_STRLEN includes the
 * unit-address. SCSI_WWN_BUFLEN provides a buffer that's large enough for all
 * of these.
 */
#define	SCSI_WWN_STRLEN	16
#define	SCSI_WWN_UA_STRLEN	17
#define	SCSI_WWN_BUFLEN	SCSI_MAXNAMELEN

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_ADDRESS_H */
