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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _T10_SSC_H
#define	_T10_SSC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation specific headers for SCSI Streaming Commands (Tapes)
 */

#ifdef __cplusplus
extern "C" {
#endif


#define	SSC_SPACE_CODE_BLOCKS		0x00 /* Mandatory support */
#define	SSC_SPACE_CODE_FILEMARKS	0x01 /* Mandatory support */
#define	SSC_SPACE_CODE_SEQ_FILEMARKS	0x02 /* Optional support */
#define	SSC_SPACE_CODE_END_OF_DATA	0x03 /* Optional support */

#define	SSC_READ_POS_SHORT_FORM	0x00
#define	SSC_READ_POS_LONG_FORM	0x06

#define	SSC_OBJ_SIG	0x22005454
#define	SSC_OBJ_TYPE_FM	1
#define	SSC_OBJ_TYPE_RM	2

#define	SSC_REWIND_IMMED	0x01

/*
 * SSC-3, revision 01c, section 7.2
 * LOAD/UNLOAD bits
 */
#define	SSC_LOAD_CMD_LOAD	0x01
#define	SSC_LOAD_CMD_RETEN	0x02
#define	SSC_LOAD_CMD_EOT	0x04
#define	SSC_LOAD_CMD_HOLD	0x08
/* ---- bit 0 of byte 1 ---- */
#define	SSC_LOAD_CMD_IMMED	0x01

/*
 * On disk file and record mark object structure.
 */
typedef struct ssc_obj_mark {
	uint32_t		som_sig;
	uint32_t		som_type;
	union {
		struct {
			Boolean_t	bom,
					eom;
			off_t		size;
			uint32_t	num,
					last_obj_id;
		} _fm_;
		struct {
			off_t		size;
			/*
			 * SSC-3 Revision 1c, Section 3.1.40
			 * Object Identifier relative to beginning of
			 * partition.
			 */
			uint32_t	obj_id;
		} _rm_;
		char _filler_[512 - (sizeof (uint32_t) * 2)];
	} _u_;
} ssc_obj_mark_t;

#define	o_fm _u_._fm_
#define	o_rm _u_._rm_

/*
 * In core structure which indicates current file-mark and record-mark
 */
typedef struct ssc_params {
	Boolean_t	s_fast_write_ack;
	off_t		s_size;
	off_t		s_cur_rec, /* starts at sizeof (ssc_obj_mark) */
			s_prev_rec,
			s_cur_fm; /* starts at 0 */
	t10_lu_state_t	s_state;
} ssc_params_t;

/*
 * During asynchronous I/O there are a few things needed to complete
 * the operation.
 */
typedef struct ssc_io {
	/*
	 * Look at SBC for the reason that this member must be first
	 */
	t10_aio_t	sio_aio;

	t10_cmd_t	*sio_cmd;

	char		*sio_data;
	size_t		sio_data_len;
	off_t		sio_offset; /* offset from s_cur_rec */
	size_t		sio_total;
} ssc_io_t;

/*
 * READ POSITION data format, short form
 */
typedef struct pos_short_form {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	rsvd2	: 1,
		perr	: 1,
		lolu	: 1,
		rsvd1	: 1,
		bycu	: 1,
		locu	: 1,
		eop	: 1,
		bop	: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	bop	: 1,
		eop	: 1,
		locu	: 1,
		bycu	: 1,
		rsvd1	: 1,
		lolu	: 1,
		perr	: 1,
		rsvd2	: 1;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	partition,
		rsvd3[2],
		first_obj[4],
		last_obj[4],
		rsvd4,
		objs_in_buf[3],
		bytes_in_buf[4];
} pos_short_form_t;

/*
 * REPORT DENSITY SUPPORT header
 */
typedef struct ssc_density_header {
	uint16_t	len,
			rsvd;
} ssc_density_header_t;

typedef struct ssc_density {
	ssc_density_header_t	d_hdr;
	uchar_t			d_prim_code,
				d_secondary_code;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t			d_dlv	: 1,
				d_rsvd	: 4,
				d_deflt	: 1,
				d_dup	: 1,
				d_wrtok	: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t			d_wrtok	: 1,
				d_dup	: 1,
				d_deflt	: 1,
				d_rsvd	: 4,
				d_dlv	: 1;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t			d_len[2],
				d_bpm[3],
				d_width[2],
				d_tracks[2],
				d_capacity[4],
				d_organization[8],
				d_name[8],
				d_description[20];
} ssc_density_t;

typedef struct ssc_density_media {
	ssc_density_header_t	d_hdr;
	uchar_t			d_type,
				d_resvd1,
				d_len[2],
				d_num_codes,
				d_codes[9],
				d_width[2],
				d_medium_len[2],
				d_rsvd2[2],
				d_organization[8],
				d_medium_name[8],
				d_description[20];
} ssc_density_media_t;

/*
 * MODE_SENSE/MODE_SELECT, Page Code 0xf
 * Data Compression
 */
typedef struct ssc_data_compression {
	struct mode_page	mode_page;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t c_rsvd1 : 6,
		c_dcc	: 1,
		c_dce	: 1;
	uchar_t c_rsdv2 : 5,
		c_red	: 2,
		c_dde	: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	c_dce	: 1,
		c_dcc	: 1,
		c_rsvd1	: 6;
	uchar_t c_dde	: 1,
		c_red	: 2,
		c_rsvd2 : 5;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	c_compression_algorithm[4],
		c_decompression_algorithm[4],
		c_rsvd3[4];
} ssc_data_compression_t;

/*
 * MODE_SENSE/MODE_SELECT, Page Code 0x10
 * Device Configuration
 */
typedef struct ssc_device_config {
	struct mode_page	mode_page;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t active_format	: 5,
		caf		: 1,
		obsolete1	: 1,
		rsvd		: 1;
	uchar_t active_partion,
		wo_buf_ratio,
		ro_buf_ratio,
		wr_delay_time[2];
	uchar_t rew		: 1,
		robo		: 1,
		socf		: 2,
		avc		: 1,
		obsolete2	: 1,
		lois		: 1,
		obr		: 1;
	uchar_t obsolete3;
	uchar_t bam		: 1,
		baml		: 1,
		swp		: 1,
		sew		: 1,
		eeg		: 1,
		eod_defined	: 3;
	uchar_t obj_size_ew[3],
		data_comp_algorithm;
	uchar_t prmwp		: 1,
		perswp		: 1,
		asocwp		: 1,
		rewind_on_reset : 2,
		oir		: 1,
		wtre		: 2;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	rsvd		: 1,
		obsolete1	: 1,
		caf		: 1,
		active_format	: 5;
	uchar_t active_partion,
		wo_buf_ratio,
		ro_buf_ratio,
		wr_delay_time[2];
	uchar_t	obr		: 1,
		lois		: 1,
		obsolete2	: 1,
		avc		: 1,
		socf		: 2,
		robo		: 1,
		rew		: 1;
	uchar_t obsolete3;
	uchar_t eod_defined	: 3,
		eeg		: 1,
		sew		: 1,
		swp		: 1,
		baml		: 1,
		bam		: 1;
	uchar_t obj_size_ew[3],
		data_comp_algorithm;
	uchar_t wtre		: 2,
		oir		: 1,
		rewind_on_reset : 2,
		asocwp		: 1,
		perswp		: 1,
		prmwp		: 1;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
} ssc_device_config_t;

#ifdef __cplusplus
}
#endif

#endif /* _T10_SSC_H */
