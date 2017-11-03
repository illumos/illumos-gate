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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_DS_SCSI_H
#define	_DS_SCSI_H

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/scsi/scsi.h>

#include "ds_impl.h"

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

/*
 * Log page structures
 */
#pragma pack(1)

typedef struct scsi_log_header {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		lh_code : 6,
			lh_spf : 1,
			lh_ds : 1;
#else
	uint8_t		lh_ds : 1,
			lh_spf : 1,
			lh_code : 6;
#endif
	uint8_t		lh_subpage;
	uint16_t	lh_length;
} scsi_log_header_t;

typedef struct scsi_log_parameter_header {
	uint16_t	lph_param;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		lph_lp	: 1,
			lph_lbin : 1,
			lph_tmc : 2,
			lph_etc	: 1,
			lph_tsd	: 1,
			lph_ds	: 1,
			lph_du	: 1;
#else
	uint8_t		lph_du	: 1,
			lph_ds	: 1,
			lph_tsd	: 1,
			lph_etc	: 1,
			lph_tmc	: 2,
			lph_lbin : 1,
			lph_lp	: 1;
#endif
	uint8_t		lph_length;
} scsi_log_parameter_header_t;

typedef struct scsi_supported_log_pages {
	scsi_log_header_t	slp_hdr;
	uchar_t			slp_pages[1];
} scsi_supported_log_pages_t;

typedef struct scsi_ie_log_param {
	scsi_log_parameter_header_t	ie_hdr;
	uchar_t				ie_asc;
	uchar_t				ie_ascq;
} scsi_ie_log_param_t;

/*
 * The SCSI-3 SPC document states that IE log page (0x2F) parameter 0
 * must have a length of at least 4 (including the length byte).
 */
#define	LOGPARAM_IE_MIN_LEN		2	/* the asc and ascq fields */

#define	INVALID_TEMPERATURE		0xff

#define	LOGPARAM_IE			0x0000

typedef struct scsi_temp_log_param {
	scsi_log_parameter_header_t	t_hdr;
	uchar_t				__reserved;
	uchar_t				t_temp;
} scsi_temp_log_param_t;

typedef struct scsi_selftest_log_param {
	scsi_log_parameter_header_t	st_hdr;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		st_results	: 4,
			__reserved1	: 1,
			st_testcode	: 3;
#else
	uint8_t		st_testcode	: 3,
			__reserved1	: 1,
			st_results	: 4;
#endif
	uint8_t		st_number;
	uint16_t	st_timestamp;
	uint64_t	st_lba;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		st_sensekey	: 4,
			__reserved2	: 4;
#else
	uint8_t		__reserved2	: 4,
			st_sensekey	: 4;
#endif
	uint8_t		st_asc;
	uint8_t		st_ascq;
	uint8_t		st_vendor;
} scsi_selftest_log_param_t;

/* The results field of the self-test log parameter */
#define	SELFTEST_OK			0x0
#define	SELFTEST_ABORT_REQUEST		0x1
#define	SELFTEST_ABORT_OTHER		0x2
#define	SELFTEST_FAILURE_INCOMPLETE	0x3
#define	SELFTEST_FAILURE_SEG_UNKNOWN	0x4
#define	SELFTEST_FAILURE_SEG_FIRST	0x5
#define	SELFTEST_FAILURE_SEG_SECOND	0x6
#define	SELFTEST_FAILURE_SEG_OTHER	0x7
#define	SELFTEST_INPROGRESS		0xf

#define	SELFTEST_COMPLETE(code)				\
	((code) == SELFTEST_OK ||			\
	((code) >= SELFTEST_FAILURE_INCOMPLETE &&	\
	((code) <= SELFTEST_FAILURE_SEG_OTHER)))

#define	LOGPARAM_TEMP_CURTEMP		0x0000
#define	LOGPARAM_TEMP_REFTEMP		0x0001

#define	LOGPARAM_TEMP_LEN	\
	(sizeof (scsi_temp_log_param_t) - \
	    sizeof (scsi_log_parameter_header_t))

/*
 * Described in SBC3
 */
typedef struct scsi_ssm_log_param {
	scsi_log_parameter_header_t ssm_hdr;
	uint16_t		__reserved2;
	uint8_t			__reserved1;
	uchar_t			ssm_prcnt_used;
} scsi_ssm_log_param_t;

#define	LOGPARAM_PRCNT_USED		0x0001
#define	LOGPARAM_PRCNT_USED_PARAM_LEN	0x04
#define	PRCNT_USED_FAULT_THRSH		90

/*
 * Mode sense/select page header information
 */
typedef struct scsi_ms_header {
	struct mode_header	ms_header;
	struct block_descriptor	ms_descriptor;
} scsi_ms_header_t;

typedef struct scsi_ms_header_g1 {
	struct mode_header_g1	ms_header;
	struct block_descriptor	ms_descriptor;
} scsi_ms_header_g1_t;

typedef struct scsi_ms_hdrs {
	int				ms_length;
	union {
		scsi_ms_header_t	g0;
		scsi_ms_header_g1_t	g1;
	} ms_hdr;
} scsi_ms_hdrs_t;

typedef struct scsi_ie_page {
	struct mode_page ie_mp;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		ie_logerr	: 1,	/* Errors should be logged */
			__reserved1	: 1,
			ie_test		: 1,	/* Enable test gen of IEs */
			ie_dexcpt	: 1,	/* Disable exceptions */
			ie_ewasc	: 1,	/* Enable warning generation */
			ie_ebf		: 1,	/* enable backgrnd functions */
			__reserved2	: 1,
			ie_perf		: 1;	/* No delays during excptns */
	uint8_t		ie_mrie		: 4,	/* Method/reporting excptons */
			__reserved3	: 4;
#else
	uint8_t		ie_perf		: 1,	/* No delays during excptons */
			__reserved2	: 1,
			ie_ebf		: 1,	/* enable background funcs */
			ie_ewasc	: 1,	/* Enable warning generation */
			ie_dexcpt	: 1,	/* Disable exceptions */
			ie_test		: 1,	/* Enable test gen of IEs */
			__reserved1	: 1,
			ie_logerr	: 1;	/* Errors should be logged */
	uint8_t		__reserved3	: 4,
			ie_mrie		: 4;	/* Method of report excptns */
#endif
	uint32_t	ie_interval_timer;	/* reporting interval for IEs */
	uint32_t	ie_report_count;	/* # of times to report an IE */
} scsi_ie_page_t;

#pragma pack()

#define	MODEPAGE_INFO_EXCPT_LEN	(sizeof (scsi_ie_page_t))

#define	IEC_IE_ENABLED(ies) ((ies).ie_dexcpt == 0)
#define	IEC_IE_CHANGEABLE(ies) ((ies).ie_dexcpt == 1)
#define	IEC_MRIE_CHANGEABLE(ies) ((ies).ie_mrie == 0xf)
#define	IEC_PERF_CHANGEABLE(ies) ((ies).ie_perf == 1)
#define	IEC_EWASC_CHANGEABLE(ies) ((ies).ie_ewasc == 1)
#define	IEC_TEST_CHANGEABLE(ies) ((ies).ie_test == 1)
#define	IEC_RPTCNT_CHANGEABLE(ies) ((ies).ie_report_count == BE_32(0xffffffff))
#define	IEC_LOGERR_CHANGEABLE(ies) ((ies).ie_logerr == 1)

/*
 * Values for the MRIE field of the informational exceptions control mode page
 */
#define	IE_REPORT_NONE			0
#define	IE_REPORT_ASYNCH		1
#define	IE_REPORT_UNIT_ATTN		2
#define	IE_REPORT_RECOV_ERR_COND	3
#define	IE_REPORT_RECOV_ERR_ALWAYS	4
#define	IE_REPORT_NO_SENSE		5
#define	IE_REPORT_ON_REQUEST		6

/*
 * Constants in support of the CONTROL MODE mode page (page 0xA)
 */
#define	MODEPAGE_CTRL_MODE_LEN	(sizeof (struct mode_control_scsi3))
#define	GLTSD_CHANGEABLE(chg)	((chg).gltsd == 1)

#define	LOGPAGE_SELFTEST_MIN_PARAM_CODE	0x0001
#define	LOGPAGE_SELFTEST_MAX_PARAM_CODE	0x0014

#define	LOGPAGE_SELFTEST_PARAM_LEN \
	((sizeof (scsi_selftest_log_param_t)) - \
	    (sizeof (scsi_log_parameter_header_t)))

/*
 * Macro to extract the length of a mode sense page
 * as returned by a target.
 */
#define	MODESENSE_PAGE_LEN(p)	(((int)((struct mode_page *)p)->length) + \
					sizeof (struct mode_page))

/*
 * Mode Select options
 */
#define	MODE_SELECT_SP			0x01
#define	MODE_SELECT_PF			0x10


/*
 * Mode Sense Page Control
 */
#define	PC_CURRENT		(0 << 6)
#define	PC_CHANGEABLE		(1 << 6)
#define	PC_DEFAULT		(2 << 6)
#define	PC_SAVED		(3 << 6)

/*
 * Log Sense Page Control
 */
#define	PC_CUMULATIVE		(1 << 6)

/*
 * LOG page codes
 */
#define	LOGPAGE_SUPP_LIST	0x00
#define	LOGPAGE_TEMP		0x0d
#define	LOGPAGE_SELFTEST	0x10
#define	LOGPAGE_IE		0x2f
/* Solid State Media log page code */
#define	LOGPAGE_SSM		0x11

/* ASC constants */
#define	ASC_INVALID_OPCODE				0x20
#define	ASC_INVALID_CDB_FIELD				0x24
#define	ASC_FAILURE_PREDICTION_THRESHOLD_EXCEEDED	0x5d

/* ASCQ constants */
#define	ASCQ_INVALID_OPCODE	0

/* Error tests */
#define	SCSI_INVALID_OPCODE(s, a, aq) \
	(((s) == KEY_ILLEGAL_REQUEST) && ((a) == ASC_INVALID_OPCODE) && \
	((aq) == ASCQ_INVALID_OPCODE))

#define	MODE_PAGE_UNSUPPORTED(s, a, aq) \
	(((s) == KEY_ILLEGAL_REQUEST) && ((a) == ASC_INVALID_CDB_FIELD))

/* command length to use */
#define	MODE_CMD_LEN_UNKNOWN		0
#define	MODE_CMD_LEN_6			1
#define	MODE_CMD_LEN_10			2

/* supported modepages bitmask */
#define	MODEPAGE_SUPP_IEC		0x1

/* supported logpages bitmask */
#define	LOGPAGE_SUPP_IE			0x1
#define	LOGPAGE_SUPP_TEMP		0x2
#define	LOGPAGE_SUPP_SELFTEST		0x4
#define	LOGPAGE_SUPP_SSM		0x8

#define	MSG_BUFLEN	256

/*
 * For SCSI commands which want to accept arbitrary length responses, we need to
 * allocate an appropriate sized buffer.  The maximum length is USHRT_MAX,
 * because some devices return nothing if the buffer length is too big.
 */
#define	MAX_BUFLEN(type)	(USHRT_MAX - sizeof (type))

extern ds_transport_t ds_scsi_uscsi_transport;
extern ds_transport_t ds_scsi_sim_transport;

#ifdef	__cplusplus
}
#endif

#endif	/* _DS_SCSI_H */
