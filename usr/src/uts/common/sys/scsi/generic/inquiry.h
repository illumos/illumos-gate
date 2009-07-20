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
 */

#ifndef	_SYS_SCSI_GENERIC_INQUIRY_H
#define	_SYS_SCSI_GENERIC_INQUIRY_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Standard Inquiry Data:
 *
 * Format of data returned as a result of an INQUIRY command.
 *
 * NOTE: Fields marked 'DEPRECATED' are defined in older versions of t10 "SCSI
 * Primary Command" spec, and are marked 'Obsolete' in newer versions.
 */
#if defined(_BIT_FIELDS_LTOH)
struct scsi_inquiry {
	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
	 */
	uchar_t	inq_dtype;

	/* byte 1 */
	uchar_t	inq_qual	: 7,	/* device type qualifier */
		inq_rmb		: 1;	/* removable media */

	/* byte 2 */
	uchar_t	inq_ansi	: 3,	/* ANSI version */
		inq_ecma	: 3,	/* ECMA version */
		inq_iso		: 2;	/* ISO version */

	/* byte 3 */
	uchar_t	inq_rdf		: 4,	/* response data format */
		inq_hisup	: 1,	/* hierarchical addressing model */
		inq_normaca	: 1,	/* setting NACA bit supported */
		inq_trmiop	: 1,	/* DEPRECATED: terminate I/O proc */
		inq_aenc	: 1;	/* DEPRECATED: async event notify */

	/* bytes 4-7 */
	uchar_t	inq_len;		/* additional length */

	uchar_t	inq_protect	: 1,	/* supports protection information */
		inq_5_1		: 1,
		inq_5_2		: 1,
		inq_3pc		: 1,	/* third-party copy */
		inq_tpgs	: 2,	/* impl/expl asymmetric lun access */
		inq_acc		: 1,	/* access controls coordinator */
		inq_sccs	: 1;	/* embedded storage array */

	uchar_t	inq_addr16	: 1,	/* SPI: 16-bit wide SCSI addr */
		inq_addr32	: 1,	/* DEPRECATED: 32 bit wide address */
		inq_ackqreqq	: 1,	/* DEPRECATED: data xfer on Q cable */
		inq_mchngr	: 1,	/* DEPRECATED: embeded medium changer */
		inq_dualp	: 1,	/* multi port device */
		inq_port	: 1,	/* DEPRECATED: port rcv inquiry cmd */
		inq_encserv	: 1,	/* embedded enclosure services */
		inq_bque	: 1;	/* DEPRECATED: combined with cmdque */

	uchar_t	inq_sftre	: 1,	/* DEPRECATED: Soft Reset option */
		inq_cmdque	: 1,	/* supports command queueing */
		inq_trandis	: 1,	/* DEPRECATED: transfer disable msgs */
		inq_linked	: 1,	/* DEPRECATED: linked commands */
		inq_sync	: 1,	/* SPI: synchronous data xfers */
		inq_wbus16	: 1,	/* SPI: 16-bit wide data xfers */
		inq_wbus32	: 1,	/* DEPRECATED: 32 bit wide data xfers */
		inq_reladdr	: 1;	/* DEPRECATED: relative addressing */

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
	 * Bytes 48-55 are reserved.
	 */
	uchar_t	__inq_48	: 8;
	uchar_t	__inq_49	: 8;
	uchar_t	__inq_50	: 8;
	uchar_t	__inq_51	: 8;
	uchar_t	__inq_52	: 8;
	uchar_t	__inq_53	: 8;
	uchar_t	__inq_54	: 8;
	uchar_t	__inq_55	: 8;

	/*
	 * The meanings of byte 56 is specific to SPI-3. For protocols older
	 * or other than this these fields are reserved.
	 */
	uchar_t	inq_ius		: 1,	/* SPI3: information units */
		inq_qas		: 1,	/* SPI3: quick arb sel */
		inq_clk		: 2,	/* SPI3: clocking */
		__inq_56_4	: 1,	/* reserved */
		__inq_56_5	: 1,	/* reserved */
		__inq_56_6	: 1,	/* reserved */
		__inq_56_7	: 1;	/* reserved */

	uchar_t	__inq_57	: 8;	/* reserved */

	/*
	 * byte pairs 58-73 are version descriptors
	 *  See: Table 51: dpANS SCSI Primary Commands - 2 (SPC-2) T10/1236
	 */
	struct	inq_vd {
		uchar_t		inq_vd_msb;
		uchar_t		inq_vd_lsb;
	}	inq_vd[8];

	/*
	 * Bytes 74-95 are reserved.
	 * 96 to 'n' are vendor-specific parameter bytes.
	 *
	 * Pad structure to 132 bytes so that access to some vendor-specific
	 * data is possible via scsi_device(9S) sd_inq (for mpxio).
	 */
	uchar_t	__inq_74_127[132 - 74];
};

#elif defined(_BIT_FIELDS_HTOL)

struct scsi_inquiry {
	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
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
	uchar_t	inq_aenc	: 1,	/* DEPRECATED: async event notify */
		inq_trmiop	: 1,	/* DEPRECATED: terminate I/O proc */
		inq_normaca	: 1,	/* setting NACA bit supported */
		inq_hisup	: 1,	/* hierarchical addressing model */
		inq_rdf		: 4;	/* response data format */

	/* bytes 4-7 */
	uchar_t	inq_len;		/* additional length */

	uchar_t	inq_sccs	: 1,	/* embedded storage array */
		inq_acc		: 1,	/* access controls coordinator */
		inq_tpgs	: 2,	/* impl/expl asymmetric lun access */
		inq_3pc		: 1,	/* third-party copy */
		inq_5_2		: 1,
		inq_5_1		: 1,
		inq_protect	: 1;	/* supports protection information */

	uchar_t	inq_bque	: 1,	/* DEPRECATED: combined with cmdque */
		inq_encserv	: 1,	/* embedded enclosure services */
		inq_port	: 1,	/* DEPRECATED: port rcv inquiry cmd */
		inq_dualp	: 1,	/* multi port device */
		inq_mchngr	: 1,	/* DEPRECATED: embeded medium changer */
		inq_ackqreqq	: 1,	/* DEPRECATED: data xfer on Q cable */
		inq_addr32	: 1,	/* DEPRECATED: 32 bit wide address */
		inq_addr16	: 1;	/* SPI: 16-bit wide SCSI addr */

	uchar_t	inq_reladdr	: 1,	/* DEPRECATED: relative addressing */
		inq_wbus32	: 1,	/* DEPRECATED: 32 bit wide data xfers */
		inq_wbus16	: 1,	/* SPI: 16-bit wide data xfers */
		inq_sync	: 1,	/* SPI: synchronous data xfers */
		inq_linked	: 1,	/* DEPRECATED: linked commands */
		inq_trandis	: 1,	/* DEPRECATED: transfer disable msgs */
		inq_cmdque	: 1,	/* supports command queueing */
		inq_sftre	: 1;	/* DEPRECATED: Soft Reset option */

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
	 * Bytes 48-55 are reserved.
	 */
	uchar_t	__inq_48	: 8;
	uchar_t	__inq_49	: 8;
	uchar_t	__inq_50	: 8;
	uchar_t	__inq_51	: 8;
	uchar_t	__inq_52	: 8;
	uchar_t	__inq_53	: 8;
	uchar_t	__inq_54	: 8;
	uchar_t	__inq_55	: 8;

	/*
	 * The meanings of byte 56 is specific to SPI-3. For protocols older
	 * or other than this these fields are reserved.
	 */
	uchar_t	__inq_56_7	: 1,	/* reserved */
		__inq_56_6	: 1,	/* reserved */
		__inq_56_5	: 1,	/* reserved */
		__inq_56_4	: 1,	/* reserved */
		inq_clk		: 2,	/* SPI3: clocking */
		inq_qas		: 1,	/* SPI3: quick arb sel */
		inq_ius		: 1;	/* SPI3: information units */

	uchar_t	__inq_57	: 8;		/* reserved */

	/*
	 * byte pairs 58-73 are version descriptors
	 *  See: Table 51: dpANS SCSI Primary Commands - 2 (SPC-2) T10/1236
	 */
	struct	inq_vd {
		uchar_t		inq_vd_msb;
		uchar_t		inq_vd_lsb;
	}	inq_vd[8];

	/*
	 * Bytes 74-95 are reserved.
	 * 96 to 'n' are vendor-specific parameter bytes.
	 *
	 * Pad structure to 132 bytes so that access to some vendor-specific
	 * data is possible via scsi_device(9S) sd_inq (for mpxio).
	 */
	uchar_t	__inq_74_127[132 - 74];
};
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

/*
 * Defined Peripheral Device Types
 */
#define	DTYPE_DIRECT		0x00	/* magnetic disk */
#define	DTYPE_SEQUENTIAL	0x01	/* magnetic tape */
#define	DTYPE_PRINTER		0x02
#define	DTYPE_PROCESSOR		0x03
#define	DTYPE_WORM		0x04	/* some optical disks */
#define	DTYPE_RODIRECT		0x05
#define	DTYPE_SCANNER		0x06	/* obsolete */
#define	DTYPE_OPTICAL		0x07
#define	DTYPE_CHANGER		0x08	/* jukeboxes */
#define	DTYPE_COMM		0x09	/* obsolete */
#define	DTYPE_ARRAY_CTRL	0x0C
#define	DTYPE_ESI		0x0D	/* Enclosure services device */
#define	DTYPE_RBC		0x0E	/* Simplified direct-access device */
#define	DTYPE_OCRW		0x0F	/* Optical card reader/writer device */
#define	DTYPE_BCC		0x10
#define	DTYPE_OSD		0x11	/* Object-based Storage Device */
#define	DTYPE_ADC		0x12
/*
 * Device types 0x13-0x1D are reserved in spc-3 (r23)
 */

#define	DTYPE_WELLKNOWN		0x1E
#define	DTYPE_UNKNOWN		0x1F
#define	DTYPE_MASK		0x1F

/* ASCII mapping used by scsi_dname(9F) */
#define	DTYPE_ASCII		{ \
		"Direct Access", "Sequential Access", "Printer", "Processor", \
		"Write-Once/Read-Many", "Read-Only Direct Access", "Scanner", \
		"Optical", "Changer", "Communications", "Unknown-0A", \
		"Unknown-0B", "Array Controller", "Enclosure-Services", \
		"Simplified-Direct-Access", "Optical-Card", "Bridge", \
		"Object-Storage", NULL}

/*
 * The peripheral qualifier tells us more about a particular device.
 * (DPQ == DEVICE PERIPHERAL QUALIFIER).
 */
#define	DPQ_MASK	0x60	/* DPQ bits */
#define	DPQ_POSSIBLE	0x00
				/*
				 * The specified peripheral device type is
				 * currently connected to this logical unit.
				 * If the target cannot determine whether
				 * or not a physical device is currently
				 * connected, it shall also return this
				 * qualifier.
				 */
#define	DPQ_SUPPORTED	0x20
				/*
				 * The target is capable of supporting the
				 * specified peripheral device type on this
				 * logical unit, however the physical device
				 * is not currently connected to this logical
				 * unit.
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
 * Defined Response Data Formats:
 */
#define	RDF_LEVEL0		0x00	/* no conformance claim (SCSI-1) */
#define	RDF_CCS			0x01	/* Obsolete (pseudo-spec) */
#define	RDF_SCSI2		0x02	/* Obsolete (SCSI-2/3 spec) */
#define	RDF_SCSI_SPC		0x03	/* ANSI INCITS 301-1997 (SPC) */
#define	RDF_SCSI_SPC2		0x04	/* ANSI INCITS 351-2001 (SPC-2) */
#define	RDF_SCSI_SPC3		0x05	/* ANSI INCITS 408-2005 (SPC-3) */
#define	RDF_SCSI_SPC4		0x06	/* t10 (SPC-4) */

/*
 * Defined Target Port Group Select values:
 */
#define	TPGS_FAILOVER_NONE	0x0
#define	TPGS_FAILOVER_IMPLICIT	0x1
#define	TPGS_FAILOVER_EXPLICIT	0x2
#define	TPGS_FAILOVER_BOTH	0x3

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
	uchar_t	id_type		: 4,
		association	: 2,
				: 1,
		piv		: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	proto_id	: 4,
		code_set	: 4;
	uchar_t	piv		: 1,
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

/*
 * "pm-capable" integer property bit mask definitions
 */
#define	PM_CAPABLE_PM_MASK	0x0000ffff	/* use lower 16 bits to */
						/* indicate PM mode */
#define	PM_CAPABLE_CCS		RDF_CCS
#define	PM_CAPABLE_SCSI2	RDF_SCSI2
#define	PM_CAPABLE_SPC		RDF_SCSI_SPC
#define	PM_CAPABLE_SPC2		RDF_SCSI_SPC2
#define	PM_CAPABLE_SPC3		RDF_SCSI_SPC3
#define	PM_CAPABLE_SPC4		RDF_SCSI_SPC4
#define	PM_CAPABLE_LOG_MASK	0xffff0000	/* use upper 16 bit to */
						/* indicate log specifics */
#define	PM_CAPABLE_LOG_SUPPORTED	0x10000	/* Log page 0xE might be */
						/* supported */
#define	PM_CAPABLE_SMART_LOG		0x20000 /* Log page 0xE reports SMART */
						/* attributes instead of the */
						/* default SCSI Log pages */
#ifdef	__cplusplus
}
#endif

/*
 * Include in implementation specifuc
 * (non-generic) inquiry definitions.
 */

#include <sys/scsi/impl/inquiry.h>

#endif	/* _SYS_SCSI_GENERIC_INQUIRY_H */
