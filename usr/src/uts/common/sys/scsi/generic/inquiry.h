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

#ifndef	_SYS_SCSI_GENERIC_INQUIRY_H
#define	_SYS_SCSI_GENERIC_INQUIRY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Inquiry Data
 *
 * Format of data returned as a result of an INQUIRY command.
 *
 */

#if defined(_BIT_FIELDS_LTOH)
struct scsi_inquiry {

	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
	 *
	 */

	uchar_t	inq_dtype;

	/* byte 1 */
	uchar_t	inq_qual	: 7,	/* device type qualifier	*/
		inq_rmb		: 1;	/* removable media		*/

	/* byte 2 */
	uchar_t	inq_ansi	: 3,	/* ANSI version 		*/
		inq_ecma	: 3,	/* ECMA version 		*/
		inq_iso		: 2;	/* ISO version 			*/

	/* byte 3 */
	uchar_t	inq_rdf		: 4,	/* response data format 	*/
		inq_hisup	: 1,	/* Hierarchial support		*/
		inq_normaca	: 1,	/* setting NACA bit supported */
		inq_trmiop	: 1,	/* TERMINATE I/O PROC msg 	*/
		inq_aenc	: 1;	/* async event notification cap. */

	/* bytes 4-7 */

	uchar_t	inq_len;		/* additional length 		*/

	uchar_t			: 4,	/* reserved 			*/
		inq_tpgs	: 1,	/* supports Target Port Group set */
				: 3;
	uchar_t	inq_addr16	: 1,	/* supports 16 bit wide SCSI addr */
		inq_addr32	: 1,	/* supports 32 bit wide SCSI addr */
		inq_ackqreqq	: 1,	/* data tranfer on Q cable */
		inq_mchngr	: 1,	/* embedded/attached to medium chngr */
		inq_dualp	: 1,	/* dual port device */
		inq_port	: 1,	/* port receiving inquiry cmd */
				: 1,	/* reserved */
		inq_bque	: 1;	/* combined with cmdque */

	uchar_t	inq_sftre	: 1,	/* supports Soft Reset option 	*/
		inq_cmdque	: 1,	/* supports command queueing 	*/
		inq_trandis	: 1,	/* supports transfer disable messages */
		inq_linked	: 1,	/* supports linked commands 	*/
		inq_sync	: 1,	/* supports synchronous data xfers */
		inq_wbus16	: 1,	/* supports 16 bit wide data xfers */
		inq_wbus32	: 1,	/* supports 32 bit wide data xfers */
		inq_reladdr	: 1;	/* supports relative addressing */

	/* bytes 8-35 */

	char	inq_vid[8];		/* vendor ID 			*/
	char	inq_pid[16];		/* product ID 			*/
	char	inq_revision[4];	/* revision level 		*/

	/*
	 * Bytes 36-47 are reserved:
	 *	For Sun qualified hard disk drives the inq_serial field contains
	 *		two bytes of mfg date year code (ascii)
	 *		two bytes of mfg date week code (ascii)
	 *		six bytes of mfg serial number (ascii)
	 *		two bytes unused
	 */
	char	inq_serial[12];

	/*
	 * Bytes 48-95 are reserved.
	 * 96 to 'n' are vendor-specific parameter bytes
	 */
};

#elif defined(_BIT_FIELDS_HTOL)

struct scsi_inquiry {

	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
	 *
	 */

	uchar_t	inq_dtype;

	/* byte 1 */
	uchar_t	inq_rmb		: 1,	/* removable media */
		inq_qual	: 7;	/* device type qualifier */

	/* byte 2 */
	uchar_t	inq_iso		: 2,	/* ISO version */
		inq_ecma	: 3,	/* ECMA version */
		inq_ansi	: 3;	/* ANSI version */

	/* byte 3 */
	uchar_t	inq_aenc	: 1,	/* async event notification cap. */
		inq_trmiop	: 1,	/* supports TERMINATE I/O PROC msg */
		inq_normaca	: 1,	/* setting NACA bit supported */
		inq_hisup	: 1,	/* hierachial support */
		inq_rdf		: 4;	/* response data format */

	/* bytes 4-7 */

	uchar_t	inq_len;		/* additional length */

	uchar_t			: 3,	/* reserved */
		inq_tpgs	: 1,	/* supports Target Port Group Set */
				: 4;

	uchar_t	inq_bque	: 1,	/* combined with cmdque */
				: 1,	/* reserved */
		inq_port	: 1,	/* port receiving inquiry cmd */
		inq_dualp	: 1,	/* dual port device */
		inq_mchngr	: 1,	/* embedded/attached to medium chngr */
		inq_ackqreqq	: 1,	/* data tranfer on Q cable */
		inq_addr32	: 1,	/* supports 32 bit wide SCSI addr */
		inq_addr16	: 1;	/* supports 16 bit wide SCSI addr */

	uchar_t	inq_reladdr	: 1,	/* supports relative addressing */
		inq_wbus32	: 1,	/* supports 32 bit wide data xfers */
		inq_wbus16	: 1,	/* supports 16 bit wide data xfers */
		inq_sync	: 1,	/* supports synchronous data xfers */
		inq_linked	: 1,	/* supports linked commands */
		inq_trandis	: 1,	/* supports transfer disable messages */
		inq_cmdque	: 1,	/* supports command queueing */
		inq_sftre	: 1;	/* supports Soft Reset option */

	/* bytes 8-35 */

	char	inq_vid[8];		/* vendor ID */

	char	inq_pid[16];		/* product ID */

	char	inq_revision[4];	/* revision level */

	/*
	 * Bytes 36-47 are reserved:
	 *	For Sun qualified hard disk drives the inq_serial field contains
	 *		two bytes of mfg date year code (ascii)
	 *		two bytes of mfg date week code (ascii)
	 *		six bytes of mfg serial number (ascii)
	 *		two bytes unused
	 */
	char	inq_serial[12];

	/*
	 * Bytes 48-95 are reserved.
	 * 96 to 'n' are vendor-specific parameter bytes
	 */
};
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

/*
 * Defined Peripheral Device Types
 */

#define	DTYPE_DIRECT		0x00
#define	DTYPE_SEQUENTIAL	0x01
#define	DTYPE_PRINTER		0x02
#define	DTYPE_PROCESSOR		0x03
#define	DTYPE_WORM		0x04
#define	DTYPE_RODIRECT		0x05
#define	DTYPE_SCANNER		0x06	/* obsolete */
#define	DTYPE_OPTICAL		0x07
#define	DTYPE_CHANGER		0x08
#define	DTYPE_COMM		0x09	/* obsolete */
#define	DTYPE_ARRAY_CTRL	0x0C
#define	DTYPE_ESI		0x0D
#define	DTYPE_RBC		0x0E
#define	DTYPE_OCRW		0x0F
#define	DTYPE_BCC		0x10
#define	DTYPE_OSD		0x11
#define	DTYPE_ADC		0x12
/*
 * Device types 0x13-0x1D are reserved in spc-3 (r23)
 */

#define	DTYPE_WELLKNOWN		0x1E
#define	DTYPE_UNKNOWN		0x1F

#define	DTYPE_MASK		0x1F

/*
 * The peripheral qualifier tells us more about a particular device.
 * (DPQ == DEVICE PERIPHERAL QUALIFIER).
 */

#define	DPQ_POSSIBLE	0x00
				/*
				 * The specified peripheral device type is
				 * currently connected to this logical unit.
				 * If the target cannot detrermine whether
				 * or not a physical device is currently
				 * connected, it shall also return this
				 * qualifier.
				 */

#define	DPQ_SUPPORTED	0x20
				/*
				 * The target is capable of supporting the
				 * specified peripheral device type on this
				 * logical unit, however the the physical
				 * device is not currently connected to this
				 * logical unit.
				 */

#define	DPQ_NEVER	0x60
				/*
				 * The target is not capable of supporting a
				 * physical device on this logical unit. For
				 * this peripheral qualifier, the peripheral
				 * device type will be set to DTYPE_UNKNOWN
				 * in order to provide compatibility with
				 * previous versions of SCSI.
				 */

#define	DPQ_VUNIQ	0x80
				/*
				 * If this bit is set, this is a vendor
				 * unique qualifier.
				 */
/*
 * To maintain compatibility with previous versions
 * of inquiry data formats, if a device peripheral
 * qualifier states that the target is not capable
 * of supporting a physical device on this logical unit,
 * then the qualifier DPQ_NEVER is set, *AND* the
 * actual device type must be set to DTYPE_UNKNOWN.
 *
 * This may make for some problems with older drivers
 * that blindly check the entire first byte, where they
 * should be checking for only the least 5 bits to see
 * whether the correct type is at the specified nexus.
 */

#define	DTYPE_NOTPRESENT	(DPQ_NEVER | DTYPE_UNKNOWN)

/*
 * Defined Response Data Formats
 *
 * RDF_LEVEL0 means that this structure complies with SCSI-1 spec.
 *
 * RDF_CCS means that this structure complies with CCS pseudo-spec.
 *
 * RDF_SCSI2 means that the structure complies with the SCSI-2/3 spec.
 */

#define	RDF_LEVEL0		0x00
#define	RDF_CCS			0x01
#define	RDF_SCSI2		0x02

/*
 * SPC-3 revision 21c, section 7.6.4.1
 * Table 289 -- Device Identification VPD page
 */
struct vpd_hdr {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	device_type	: 4,
		periph_qual	: 4;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	periph_qual	: 4,
		device_type	: 4;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	page_code,
		page_len[2];
};

/*
 * SPC-3 revision 21c, section 7.6.4.1
 * Table 290 -- Identification descriptor
 */
struct vpd_desc {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	code_set	: 4,
		proto_id	: 4;
	uchar_t id_type		: 4,
		association	: 2,
				: 1,
		piv		: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	proto_id	: 4,
		code_set	: 4;
	uchar_t piv		: 1,
				: 1,
		association	: 2,
		id_type		: 4;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	resrv1;
	uchar_t	len;
	/* ---- data follows ---- */
};

#ifdef	__cplusplus
}
#endif

/*
 * Include in implementation specifuc
 * (non-generic) inquiry definitions.
 */

#include <sys/scsi/impl/inquiry.h>

#endif	/* _SYS_SCSI_GENERIC_INQUIRY_H */
