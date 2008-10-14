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
 * local SCSI definitions
 */

#ifndef	_G_SCSI_H
#define	_G_SCSI_H


/*
 * Include any headers you depend on.
 */

/*
 * I18N message number ranges
 *  This file: 18500 - 18999
 *  Shared common messages: 1 - 1999
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	MODEPAGE_GEOMETRY	0x04

/* NOTE: These command op codes are not defined in commands.h */
#define		SCMD_SYNC_CACHE			0x35
#define		SCMD_LOG_SENSE			0x4d
#define		SCMD_PERS_RESERV_IN		0x5e
#define		SCMD_PERS_RESERV_OUT		0x5f

#define	MAX_MODE_SENSE_LEN		0xffff

/*
 *  Structure for MODE SELECT/SENSE 10 byte page header
 *
 */
typedef struct mode_header_10_struct {
	ushort_t length;
	uchar_t medium_type; /* device specific */
	uchar_t device_specific; /* device specfic parameters */
	ushort_t	rsvdl;	/* reserved */
	ushort_t bdesc_length;	/* length of block descriptor(s), if any */
} Mode_header_10;

typedef	struct	mode_page_04_struct {
	struct	mode_page mode_page;	/* common mode page header */
	uchar_t	num_cylinders_hi;
	uchar_t	num_cylinders_mid;
	uchar_t	num_cylinders_lo;
	uchar_t	num_heads;
	uchar_t	write_precomp_hi;
	uchar_t	write_precomp_mid;
	uchar_t	write_precomp_lo;
	uchar_t	reduced_write_i_hi;
	uchar_t	reduced_write_i_mid;
	uchar_t	reduced_write_i_lo;
	ushort_t	step_rate;
	uchar_t	landing_zone_hi;
	uchar_t	landing_zone_mid;
	uchar_t	landing_zone_lo;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	rpl	: 2,	/* RPL */
			: 6;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		: 6,
		rpl	: 2;    /* disable correction */
#else
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */
	uchar_t	rot_offset;
	uchar_t	: 8;	/* reserved */
	ushort_t	rpm;
	uchar_t	: 8;	/* reserved */
	uchar_t	: 8;	/* reserved */
} Mp_04;


typedef	struct	mode_page_01_struct {
	struct	mode_page mode_page;	/* common mode page header */
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	dcr	: 1,	/* disable correction */
		dte	: 1,	/* disable transfer on error */
		per	: 1,	/* post error */
		eec	: 1,	/* enable early correction */
		rc	: 1,	/* read continuous */
		tb	: 1,	/* transfer block */
		arre	: 1,	/* auto read realloc enabled */
		awre	: 1;	/* auto write realloc enabled */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	awre	: 1,	/* auto write realloc enabled */
		arre	: 1,	/* auto read realloc enabled */
		tb	: 1,	/* transfer block */
		rc	: 1,	/* read continuous */
		eec	: 1,	/* enable early correction */
		per	: 1,	/* post error */
		dte	: 1,	/* disable transfer on error */
		dcr	: 1;    /* disable correction */
#else
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */
	uchar_t	read_retry_count;
	uchar_t	correction_span;
	uchar_t	head_offset_count;
	uchar_t	strobe_offset_count;
	uchar_t			: 8;	/* reserved */
	uchar_t	write_retry_count;
	uchar_t			: 8;	/* reserved */
	ushort_t	recovery_time_limit;
} Mp_01;

/*
 * I define here for backward compatability
 * with 2.5.1
 * For 2.6 & above you can use "mode_caching"
 */
struct my_mode_caching {
	struct	mode_page mode_page;	/* common mode page header */
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	rcd		: 1,	/* Read Cache Disable */
		mf		: 1,	/* Multiplication Factor */
		wce		: 1,	/* Write Cache Enable */
				: 5;	/* Reserved */
	uchar_t	write_ret_prio	: 4,	/* Write Retention Priority */
		dmd_rd_ret_prio	: 4;	/* Demand Read Retention Priority */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t			: 5,	/* Reserved */
		wce		: 1,	/* Write Cache Enable */
		mf		: 1,	/* Multiplication Factor */
		rcd		: 1;	/* Read Cache Disable */
	uchar_t	dmd_rd_ret_prio	: 4,	/* Demand Read Retention Priority */
		write_ret_prio	: 4;	/* Write Retention Priority */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	ushort_t	pf_dsbl_trans_len;	/* Disable prefetch Xfer len. */
	ushort_t	min_prefetch;	/* Minimum Prefetch */
	ushort_t	max_prefetch;	/* Maximum Prefetch */
	ushort_t	max_prefetch_ceiling;	/* Maximum Prefetch Ceiling */
};

/*
 *              SCSI CDB structures
 */
typedef	struct	my_cdb_g0 {
	unsigned	char	cmd;
	unsigned	char	lba_msb;
	unsigned	char	lba;
	unsigned	char	lba_lsb;
	unsigned	char	count;
	unsigned	char	control;
	}my_cdb_g0;

typedef	struct {
	unsigned	char	cmd;
	unsigned	char	byte1;
	unsigned	char	byte2;
	unsigned	char	byte3;
	unsigned	char	byte4;
	unsigned	char	byte5;
	unsigned	char	byte6;
	unsigned	char	byte7;
	unsigned	char	byte8;
	unsigned	char	byte9;
	}my_cdb_g1;

typedef struct l_inquiry80_struct {
	/*
	 * byte 0
	 *
	 * Bits 7-5 are the Peripheral Device Qualifier
	 * Bits 4-0 are the Peripheral Device Type
	 *
	 */
	uchar_t	inq_dtype;
	uchar_t	inq_page_code;
	uchar_t reserved;		/* reserved */
	uchar_t inq_page_len;
	uchar_t inq_serial[251];
} L_inquiry80;

typedef struct l_inquiry00_struct {
	uchar_t		qual    :3,
			dtype   :5;
	uchar_t		page_code;
	uchar_t		reserved;
	uchar_t		len;
	uchar_t		page_list[251];
} L_inquiry00;

#ifdef	__cplusplus
}
#endif

#endif	/* _G_SCSI_H */
