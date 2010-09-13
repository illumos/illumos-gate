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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SCSI_GENERIC_DAD_MODE_H
#define	_SYS_SCSI_GENERIC_DAD_MODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structures and defines for DIRECT ACCESS mode sense/select operations
 */

/*
 * Direct Access Device mode header device specific byte definitions.
 *
 * On MODE SELECT operations, the effect of the state of the WP bit is unknown,
 * else reflects the Write-Protect status of the device.
 *
 * On MODE SELECT operations, the the DPOFUA bit is reserved and must
 * be zero, else on MODE SENSE operations it reflects whether or not
 * DPO and FUA bits are supported.
 */

#define	MODE_DAD_WP	0x80
#define	MODE_DAD_DPOFUA	0x10

/*
 * Direct Access Device Medium Types (for non direct-access magentic tapes)
 */

#define	DAD_MTYP_DFLT	0x0 /* default (currently mounted) type */

#define	DAD_MTYP_FLXSS	0x1 /* flexible disk, single side, unspec. media */
#define	DAD_MTYP_FLXDS	0x2 /* flexible disk, double side, unspec. media */

#define	DAD_MTYP_FLX_8SSSD 0x05	/* 8", single side, single density, 48tpi */
#define	DAD_MTYP_FLX_8DSSD 0x06	/* 8", double side, single density, 48tpi */
#define	DAD_MTYP_FLX_8SSDD 0x09	/* 8", single side, double density, 48tpi */
#define	DAD_MTYP_FLX_8DSDD 0x0A	/* 8", double side, double density, 48tpi */
#define	DAD_MTYP_FLX_5SSLD 0x0D	/* 5.25", single side, single density, 48tpi */
#define	DAD_MTYP_FLX_5DSMD1 0x12 /* 5.25", double side, medium density, 48tpi */
#define	DAD_MTYP_FLX_5DSMD2 0x16 /* 5.25", double side, medium density, 96tpi */
#define	DAD_MTYP_FLX_5DSQD 0x1A	/* 5.25", double side, quad density, 96tpi */
#define	DAD_MTYP_FLX_3DSLD 0x1E	/* 3.5", double side, low density, 135tpi */


/*
 * Direct Access device Mode Sense/Mode Select Defined pages
 */

#define	DAD_MODE_ERR_RECOV	0x01
#define	DAD_MODE_FORMAT		0x03
#define	DAD_MODE_GEOMETRY	0x04
#define	DAD_MODE_FLEXDISK	0x05
#define	DAD_MODE_VRFY_ERR_RECOV	0x07
#define	DAD_MODE_CACHE		0x08
#define	DAD_MODE_MEDIA_TYPES	0x0B
#define	DAD_MODE_NOTCHPART	0x0C
#define	DAD_MODE_POWER_COND	0x0D

/*
 * Definitions of selected pages
 */

/*
 * Page 0x1 - Error Recovery Parameters
 *
 * Note:	This structure is incompatible with previous SCSI
 *		implementations. See <scsi/impl/mode.h> for an
 *		alternative form of this structure. They can be
 *		distinguished by the length of data returned
 *		from a MODE SENSE command.
 */

#define	PAGELENGTH_DAD_MODE_ERR_RECOV	0x0A

struct mode_err_recov {
	struct	mode_page mode_page;	/* common mode page header */
#if defined(_BIT_FIELDS_LTOH)
	uchar_t		dcr	: 1,	/* disable correction */
			dte	: 1,	/* disable transfer on error */
			per	: 1,	/* post error */
			eec	: 1,	/* enable early correction */
			rc	: 1,	/* read continuous */
			tb	: 1,	/* transfer block */
			arre	: 1,	/* auto read realloc enabled */
			awre	: 1;	/* auto write realloc enabled */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		awre	: 1,	/* auto write realloc enabled */
			arre	: 1,	/* auto read realloc enabled */
			tb	: 1,	/* transfer block */
			rc	: 1,	/* read continuous */
			eec	: 1,	/* enable early correction */
			per	: 1,	/* post error */
			dte	: 1,	/* disable transfer on error */
			dcr	: 1;	/* disable correction */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t	read_retry_count;
	uchar_t	correction_span;
	uchar_t	head_offset_count;
	uchar_t	strobe_offset_count;
	uchar_t	reserved;
	uchar_t	write_retry_count;
	uchar_t	reserved_2;
	ushort_t recovery_time_limit;
};

/*
 * Page 0x3 - Direct Access Device Format Parameters
 */

struct mode_format {
	struct	mode_page mode_page;	/* common mode page header */
	ushort_t tracks_per_zone;	/* Handling of Defects Fields */
	ushort_t alt_sect_zone;
	ushort_t alt_tracks_zone;
	ushort_t alt_tracks_vol;
	ushort_t sect_track;		/* Track Format Field */
	ushort_t data_bytes_sect;	/* Sector Format Fields */
	ushort_t interleave;
	ushort_t track_skew;
	ushort_t cylinder_skew;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t			: 3,
		_reserved_ins	: 1,	/* see <scsi/impl/mode.h> */
			surf	: 1,
			rmb	: 1,
			hsec	: 1,
			ssec	: 1;	/* Drive Type Field */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		ssec	: 1,	/* Drive Type Field */
			hsec	: 1,
			rmb	: 1,
			surf	: 1,
		_reserved_ins	: 1,	/* see <scsi/impl/mode.h> */
				: 3;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t	reserved[2];
};

/*
 * Page 0x4 - Rigid Disk Drive Geometry Parameters
 */

struct mode_geometry {
	struct	mode_page mode_page;	/* common mode page header */
	uchar_t	cyl_ub;			/* number of cylinders */
	uchar_t	cyl_mb;
	uchar_t	cyl_lb;
	uchar_t	heads;			/* number of heads */
	uchar_t	precomp_cyl_ub;		/* cylinder to start precomp */
	uchar_t	precomp_cyl_mb;
	uchar_t	precomp_cyl_lb;
	uchar_t	current_cyl_ub;		/* cyl to start reduced current */
	uchar_t	current_cyl_mb;
	uchar_t	current_cyl_lb;
	ushort_t step_rate;		/* drive step rate */
	uchar_t	landing_cyl_ub;		/* landing zone cylinder */
	uchar_t	landing_cyl_mb;
	uchar_t	landing_cyl_lb;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t		rpl	: 2,	/* rotational position locking */
				: 6;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t			: 6,
			rpl	: 2;	/* rotational position locking */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t	rotational_offset;	/* rotational offset */
	uchar_t	reserved;
	ushort_t rpm;			/* rotations per minute */
	uchar_t	reserved2[2];
};

#define	RPL_SPINDLE_SLAVE		1
#define	RPL_SPINDLE_MASTER		2
#define	RPL_SPINDLE_MASTER_CONTROL	3

/*
 * Page 0x8 - Caching Page
 *
 * Note:	This structure is incompatible with previous SCSI
 *		implementations. See <scsi/impl/mode.h> for an
 *		alternative form of this structure. They can be
 *		distinguished by the length of data returned
 *		from a MODE SENSE command.
 */

#define	PAGELENGTH_DAD_MODE_CACHE_SCSI3	0x12

struct mode_cache_scsi3 {
	struct	mode_page mode_page;	/* common mode page header */
#if defined(_BIT_FIELDS_LTOH)
	uchar_t		rcd	: 1,	/* Read Cache Disable */
			mf	: 1,	/* Multiplication Factor */
			wce	: 1,	/* Write Cache Enable */
			size	: 1,	/* Size Enable */
			disc	: 1,	/* Discontinuity */
			cap	: 1,	/* Caching Analysis Permitted */
			abpf	: 1,	/* Abort Pre-Fetch */
			ic	: 1;	/* Initiator Control */
	uchar_t	write_reten_pri	: 4,	/* Write Retention Priority */
		read_reten_pri	: 4;	/* Demand Read Retention Priority */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		ic	: 1,	/* Initiator Control */
			abpf	: 1,	/* Abort Pre-Fetch */
			cap	: 1,	/* Caching Analysis Permitted */
			disc	: 1,	/* Discontinuity */
			size	: 1,	/* Size Enable */
			wce	: 1,	/* Write Cache Enable */
			mf	: 1,	/* Multiplication Factor */
			rcd	: 1;	/* Read Cache Disable */
	uchar_t	read_reten_pri	: 4,	/* Demand Read Retention Priority */
		write_reten_pri	: 4;	/* Write Retention Priority */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	ushort_t dis_prefetch_len;	/* Disable prefetch xfer length */
	ushort_t min_prefetch;		/* minimum prefetch length */
	ushort_t max_prefetch;		/* maximum prefetch length */
	ushort_t prefetch_ceiling;	/* max prefetch ceiling */
#if defined(_BIT_FIELDS_LTOH)
	uchar_t			: 3,	/* reserved */
			vu_123	: 1,	/* Vendor Specific, byte 12 bit 3 */
			vu_124	: 1,	/* Vendor Specific, byte 12 bit 4 */
			dra	: 1,	/* Disable Read-Ahead */
			lbcss	: 1,	/* Logical Block Cache Segment Size */
			fsw	: 1;	/* Force Sequential Write */
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		fsw	: 1,	/* Force Sequential Write */
			lbcss	: 1,	/* Logical Block Cache Segment Size */
			dra	: 1,	/* Disable Read-Ahead */
			vu_124	: 1,	/* Vendor Specific, byte 12 bit 4 */
			vu_123	: 1,	/* Vendor Specific, byte 12 bit 3 */
				: 3;	/* reserved */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t	num_cache_seg;		/* Number of cache segments */
	ushort_t cache_seg_size;	/* Cache segment size */
	uchar_t	reserved;
	uchar_t	non_cache_seg_size_ub;	/* Non cache segment size */
	uchar_t	non_cache_seg_size_mb;
	uchar_t	non_cache_seg_size_lb;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_GENERIC_DAD_MODE_H */
