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

#ifndef	_SYS_SCSI_GENERIC_SENSE_H
#define	_SYS_SCSI_GENERIC_SENSE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Standard (Non-Extended) SCSI Sense.
 *
 * For Error Classe 0-6. This is all
 * Vendor Unique sense information.
 *
 * Note: This is pre-SCSI-2.
 */

struct scsi_sense {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	ns_code		: 4,	/* Vendor Uniqe error code 	*/
		ns_class	: 3,	/* Error class 			*/
		ns_valid	: 1;	/* Logical Block Address is val */
	uchar_t	ns_lba_hi	: 5,	/* High Logical Block Address */
		ns_vu		: 3;	/* Vendor Unique value */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	ns_valid	: 1,	/* Logical Block Address is valid */
		ns_class	: 3,	/* Error class */
		ns_code		: 4;	/* Vendor Uniqe error code */
	uchar_t	ns_vu		: 3,	/* Vendor Unique value */
		ns_lba_hi	: 5;	/* High Logical Block Address */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t	ns_lba_mid;		/* Middle Logical Block Address */
	uchar_t	ns_lba_lo;		/* Low part of Logical Block Address */
};

/*
 * SCSI Extended Sense structure
 *
 * For Error Class 7, the Extended Sense Structure is applicable (now referred
 * to in SPC-3 as "fixed format sense data").  The es_code field is used
 * to determine whether the extended sense data is actually "fixed format" or
 * the newer "descriptor format" introduced in SPC-3.
 */

#define	CLASS_EXTENDED_SENSE	0x7	/* indicates extended sense */
#define	ADDL_SENSE_ADJUST	0x8	/* Add to es_add_length for total */
#define	MIN_FIXED_SENSE_LEN	0xE	/* Minimum allowed fixed buf len */

struct scsi_extended_sense {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	es_code		: 4,	/* Vendor Unique error code 	*/
		es_class	: 3,	/* Error Class- fixed at 0x7 	*/
		es_valid	: 1;	/* sense data is valid 		*/

	uchar_t	es_segnum;		/* segment number: for COPY cmd */

	uchar_t	es_key		: 4,	/* Sense key (see below) 	*/
				: 1,	/* reserved 			*/
		es_ili		: 1,	/* Incorrect Length Indicator 	*/
		es_eom		: 1,	/* End of Media 		*/
		es_filmk	: 1;	/* File Mark Detected 		*/
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	es_valid	: 1,	/* sense data is valid */
		es_class	: 3,	/* Error Class- fixed at 0x7 */
		es_code		: 4;	/* Vendor Unique error code */

	uchar_t	es_segnum;		/* segment number: for COPY cmd */

	uchar_t	es_filmk	: 1,	/* File Mark Detected */
		es_eom		: 1,	/* End of Media */
		es_ili		: 1,	/* Incorrect Length Indicator */
				: 1,	/* reserved */
		es_key		: 4;	/* Sense key (see below) */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

	uchar_t	es_info_1;		/* information byte 1 */
	uchar_t	es_info_2;		/* information byte 2 */
	uchar_t	es_info_3;		/* information byte 3 */
	uchar_t	es_info_4;		/* information byte 4 */
	uchar_t	es_add_len;		/* number of additional bytes */

	uchar_t	es_cmd_info[4];		/* command specific information */
	uchar_t	es_add_code;		/* Additional Sense Code */
	uchar_t	es_qual_code;		/* Additional Sense Code Qualifier */
	uchar_t	es_fru_code;		/* Field Replaceable Unit Code */
	uchar_t	es_skey_specific[3];	/* Sense Key Specific information */

	/*
	 * Additional bytes may be defined in each implementation.
	 * The actual amount of space allocated for Sense Information
	 * is also implementation dependent.
	 *
	 * Modulo that, the declaration of an array two bytes in size
	 * nicely rounds this entire structure to a size of 20 bytes.
	 */

	uchar_t	es_add_info[2];		/* additional information */

};

/*
 * Sense code values for Extended Sense
 */

#define	CODE_FMT_FIXED_CURRENT		0x0
#define	CODE_FMT_FIXED_DEFERRED		0x1
#define	CODE_FMT_DESCR_CURRENT		0x2
#define	CODE_FMT_DESCR_DEFERRED		0x3
#define	CODE_FMT_VENDOR_SPECIFIC	0xF

#define	SCSI_IS_DESCR_SENSE(sns_ptr) \
	(((((struct scsi_extended_sense *)(sns_ptr))->es_code) == \
	    CODE_FMT_DESCR_CURRENT) || \
	    ((((struct scsi_extended_sense *)(sns_ptr))->es_code) == \
		CODE_FMT_DESCR_DEFERRED))

/*
 * Sense Key values for Extended Sense.
 */

#define	KEY_NO_SENSE		0x00
#define	KEY_RECOVERABLE_ERROR	0x01
#define	KEY_NOT_READY		0x02
#define	KEY_MEDIUM_ERROR	0x03
#define	KEY_HARDWARE_ERROR	0x04
#define	KEY_ILLEGAL_REQUEST	0x05
#define	KEY_UNIT_ATTENTION	0x06
#define	KEY_WRITE_PROTECT	0x07
#define	KEY_DATA_PROTECT	KEY_WRITE_PROTECT
#define	KEY_BLANK_CHECK		0x08
#define	KEY_VENDOR_UNIQUE	0x09
#define	KEY_COPY_ABORTED	0x0A
#define	KEY_ABORTED_COMMAND	0x0B
#define	KEY_EQUAL		0x0C
#define	KEY_VOLUME_OVERFLOW	0x0D
#define	KEY_MISCOMPARE		0x0E
#define	KEY_RESERVED		0x0F

/*
 * Descriptor sense data header
 *
 * Descriptor format sense data is described in the SPC-3 standard.  Unlike
 * the fixed format sense data, descriptor format consists of a header
 * followed by a variable length list of sense data descriptors.
 */

struct scsi_descr_sense_hdr {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	ds_code		: 4,	/* Vendor Unique error code 	*/
		ds_class	: 3,	/* Error Class- fixed at 0x7 	*/
		ds_reserved	: 1;	/* sense data is valid 		*/

	uchar_t	ds_key		: 4,	/* Sense key 			*/
		ds_reserved2	: 4;	/* reserved 			*/
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	ds_reserved	: 1,	/* sense data is valid */
		ds_class	: 3,	/* Error Class- fixed at 0x7 */
		ds_code		: 4;	/* Vendor Unique error code */

	uchar_t	ds_reserved2	: 4,	/* reserved */
		ds_key		: 4;	/* Sense key (see below) */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */

	uchar_t	ds_add_code;		/* Additional Sense Code */
	uchar_t	ds_qual_code;		/* Additional Sense Code Qualifier */

	uchar_t ds_reserved3[3];	/* reserved */

	uchar_t ds_addl_sense_length;	/* Additional sense data length */
};

/*
 * SCSI sense descriptors
 */

struct scsi_information_sense_descr {
	uchar_t isd_descr_type;		/* Descriptor type (0x00)	*/
	uchar_t isd_addl_length;	/* Additional byte count (0x0A)	*/
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	isd_reserved1	: 7,	/* reserved 			*/
		isd_valid	: 1;	/* Always set to 1 		*/
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	isd_valid	: 1,	/* Always set to 1 		*/
		isd_reserved1	: 7;	/* reserved 			*/
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t isd_reserved2;		/* reserved */
	uchar_t isd_information[8];	/* Information bytes		*/
};

struct scsi_cmd_specific_sense_descr {
	uchar_t css_descr_type;		/* Descriptor type (0x01)	*/
	uchar_t css_addl_length;	/* Additional byte count (0x0A)	*/
	uchar_t css_reserved[2];	/* reserved 			*/
	uchar_t css_cmd_specific_info[8]; /* Command specific info	*/
};

union scsi_sk_specific_data {
	/*
	 * Field pointer (Sense key = Illegal Request)
	 */
	struct {
#if defined(_BIT_FIELDS_LTOH)
		uchar_t	bit_pointer	: 3,
			bpv		: 1,
			reserved	: 2,
			cd		: 1,
			sksv		: 1;
#elif defined(_BIT_FIELDS_HTOL)
		uchar_t	sksv		: 1,
			cd		: 1,
			reserved	: 2,
			bpv		: 1,
			bit_pointer	: 3;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		uchar_t field_pointer[2];
	} fp;
	/*
	 * Actual Retry Count (Sense key = Hardware error,
	 * Medium Error or Recovered Error)
	 */
	struct {
		uchar_t sksv;
		uchar_t actual_retry_count[2];
	} arc;
	/*
	 * Progress Indication (Sense key = No Sense or Not Ready
	 */
	struct {
		uchar_t sksv;
		uchar_t progress_indication[2];
	} pi;
	/*
	 * Segment Pointer (Sense key = Copy Aborted)
	 */
	struct {
#if defined(_BIT_FIELDS_LTOH)
		uchar_t	bit_pointer	: 3,
			bpv		: 1,
			reserved	: 1,
			sd		: 1,
			reserved2	: 1,
			sksv		: 1;
#elif defined(_BIT_FIELDS_HTOL)
		uchar_t	sksv		: 1,
			reserved2	: 1,
			sd		: 1,
			reserved	: 1,
			bpv		: 1,
			bit_pointer	: 3;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
		uchar_t field_pointer[2];
	} sp;
};

struct scsi_sk_specific_sense_descr {
	uchar_t sss_descr_type;		/* Descriptor type 		*/
	uchar_t sss_addl_length;	/* Additional byte count (0x06)	*/
	uchar_t sss_reserved[2];	/* reserved 			*/
	union	scsi_sk_specific_data sss_data;
	uchar_t sss_reserved2;
};

struct scsi_fru_sense_descr {
	uchar_t fs_descr_type;		/* Descriptor type (0x03)	*/
	uchar_t fs_addl_length;		/* Additional byte count (0x02)	*/
	uchar_t fs_reserved;		/* reserved 			*/
	uchar_t fs_fru_code; 		/* Field Replaceable Unit Code	*/
};

struct scsi_stream_cmd_data {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	scs_reserved2	: 5,
		scs_ili		: 1,
		scs_eom		: 1,
		scs_filemark	: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	scs_filemark	: 1,
		scs_eom		: 1,
		scs_ili		: 1,
		scs_reserved2	: 5;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
};

struct scsi_stream_cmd_sense_descr {
	uchar_t scs_descr_type;		/* Descriptor type (0x04)	*/
	uchar_t scs_addl_length;	/* Additional byte count (0x02)	*/
	uchar_t scs_reserved;		/* reserved 			*/
	struct scsi_stream_cmd_data scs_data;
};

struct scsi_block_cmd_sense_descr {
	uchar_t bcs_descr_type;		/* Descriptor type (0x05)	*/
	uchar_t bcs_addl_length;	/* Additional byte count (0x02)	*/
	uchar_t bcs_reserved;		/* reserved 			*/
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	bcs_reserved2	: 5,
		bcs_ili		: 1,
		bcs_reserved3	: 2;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	bcs_reserved3	: 2,
		bcs_ili		: 1,
		bcs_reserved2	: 5;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
};

struct scsi_ata_status_ret_sense_descr {
	uchar_t ars_descr_type;		/* Descriptor type (0x09)	*/
	uchar_t ars_addl_length;	/* Additional byte count (0x0c)	*/
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	ars_extend	: 1,
		ars_reserved1	: 7;	/* reserved 			*/
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	ars_reserved1	: 7,	/* reserved 			*/
		ars_extend	: 1;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t ars_error;
	uchar_t ars_sec_count_msb;
	uchar_t ars_sec_count_lsb;
	uchar_t ars_lba_low_msb;
	uchar_t ars_lba_low_lsb;
	uchar_t ars_lba_mid_msb;
	uchar_t ars_lba_mid_lsb;
	uchar_t ars_lba_high_msb;
	uchar_t ars_lba_high_lsb;
	uchar_t ars_device;
	uchar_t ars_status;
};

struct scsi_vendor_specific_sense_descr {
	uchar_t vss_descr_type;		/* Descriptor type (0x80-0xFF)	*/
	uchar_t vss_addl_length;	/* Additional byte count	*/
	/*
	 * Variable length vendor specific data
	 */
	uchar_t vss_vendor_specific_info[1];
};

/*
 * SCSI Descriptor Types
 */
#define	DESCR_INFORMATION		0x00
#define	DESCR_COMMAND_SPECIFIC		0x01
#define	DESCR_SENSE_KEY_SPECIFIC	0x02
#define	DESCR_FRU			0x03
#define	DESCR_STREAM_COMMANDS		0x04
#define	DESCR_BLOCK_COMMANDS		0x05
#define	DESCR_OSD_OID			0x06
#define	DESCR_OSD_RESP_INTEGRITY	0x07
#define	DESCR_OSD_ATTR_ID		0x08
#define	DESCR_ATA_STATUS_RETURN		0x09

#ifdef	__cplusplus
}
#endif

/*
 * Each implementation will have specific mappings to what
 * Sense Information means
 */

#include <sys/scsi/impl/sense.h>

#endif	/* _SYS_SCSI_GENERIC_SENSE_H */
