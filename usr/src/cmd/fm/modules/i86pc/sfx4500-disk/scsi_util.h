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

#ifndef _SCSI_UTIL_H
#define	_SCSI_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for data structures used in the SCSI IE module
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/scsi/scsi.h>

/*
 * Log page structures
 */
#pragma pack(1)

struct log_header {

#if defined(_BIT_FIELDS_LTOH)

	uint8_t		code	: 6,
			rsrvd	: 2;

#elif defined(_BIT_FIELDS_HTOL)

	uint8_t		rsrvd	: 2,
			code	: 6;

#else
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */

	uint8_t		reserved;
	uint16_t	length;
};

struct log_parameter_header {

	uint16_t	param_code;

#if defined(_BIT_FIELDS_LTOH)

	uint8_t		lp	: 1,
			lbin	: 1,
			tmc	: 2,
			etc	: 1,
			tsd	: 1,
			ds	: 1,
			du	: 1;

#elif defined(_BIT_FIELDS_HTOL)

	uint8_t		du	: 1,
			ds	: 1,
			tsd	: 1,
			etc	: 1,
			tmc	: 2,
			lbin	: 1,
			lp	: 1;

#else
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */

	uint8_t		length;
};


struct supported_log_pages {
	struct log_header	hdr;
	uchar_t			pages[1];
};

/*
 * Specific log page parameters:
 */
struct info_excpt_log_param {
	struct log_parameter_header	hdr;
	uchar_t				ie_asc;
	uchar_t				ie_ascq;
	uchar_t				last_temp;

	/*
	 * The following fields may or may not exist -- depending on the
	 * length specified in the log parameter header.
	 */
	union {
		struct ie_ibm_extensions {
			uchar_t		ibm_temp_threshold;
		} ibm_e;
	} vnd;
#define	ex_temp_threshold	vnd.ibm_e.ibm_temp_threshold
};

/*
 * The SCSI-3 SPC document states that IE log page (0x2F) parameter 0
 * must have a length of at least 4 (including the length byte).
 * Drives that provide 5 bytes use the 5th byte as the temperature
 * threshold (reference) value.
 */
#define	LOGPARAM_IE_MIN_LEN		2	/* the asc and ascq fields */
#define	LOGPARAM_IE_WITH_TEMP_MIN_LEN	(LOGPARAM_IE_MIN_LEN + 1)

#define	INVALID_TEMPERATURE		0xff

#define	LOGPARAM_IE			0x0000


struct temperature_log_param_curtemp {
	struct log_parameter_header	hdr;
	uchar_t				rsrvd;
	uchar_t				current_temp;
};

struct temperature_log_param_reftemp {
	struct log_parameter_header	hdr;
	uchar_t				rsrvd2;
	uchar_t				reference_temp;

#define	REFTEMP_INVALID		0xff
};

struct selftest_log_parameter {
	struct log_parameter_header	hdr;

#if defined(_BIT_FIELDS_LTOH)

	uint8_t		results		: 4,
			rsrvd		: 1,
			testcode	: 3;

#elif defined(_BIT_FIELDS_HTOL)

	uint8_t		testcode	: 3,
			rsrvd		: 1,
			results		: 4;

#endif  /* _BIT_FIELDS_LTOH */

	uint8_t		test_number;
	uint16_t	timestamp;
	uint64_t	lba_of_first_failure;

#if defined(_BIT_FIELDS_LTOH)

	uint8_t		sense_key	: 4,
			rsrvd1		: 4;

#elif defined(_BIT_FIELDS_HTOL)

	uint8_t		rsrvd1		: 4,
			sense_key	: 4;

#endif  /* _BIT_FIELDS_LTOH */

	uint8_t		asc;
	uint8_t		ascq;
	uint8_t		vendor_specific;
};

/* The results field of the self-test log parameter */
#define	SELFTEST_FAILURE_INCOMPLETE	3
#define	SELFTEST_FAILURE_SEG_UNKNOWN	4
#define	SELFTEST_FAILURE_SEG_FIRST	5
#define	SELFTEST_FAILURE_SEG_SECOND	6
#define	SELFTEST_FAILURE_SEG_OTHER	7

#define	LOGPARAM_TEMP_CURTEMP		0x0000
#define	LOGPARAM_TEMP_REFTEMP		0x0001

#define	LOGPARAM_TEMP_CURTEMP_LEN	\
	(sizeof (struct temperature_log_param_curtemp) - \
	    sizeof (struct log_parameter_header))

#define	LOGPARAM_TEMP_REFTEMP_LEN	\
	(sizeof (struct temperature_log_param_reftemp) - \
	    sizeof (struct log_parameter_header))

/*
 * Mode sense/select page header information
 */
struct scsi_ms_header {
	struct mode_header	mode_header;
	struct block_descriptor	block_descriptor;
};

struct scsi_ms_header_g1 {
	struct mode_header_g1	mode_header;
	struct block_descriptor	block_descriptor;
};

struct info_except_page {
	struct mode_page	mp;

#if defined(_BIT_FIELDS_LTOH)

	uint8_t			logerr	: 1,	/* Errors should be logged */
				rsrvd1	: 1,
				test	: 1,	/* Enable test gen of IEs */
				dexcpt	: 1,	/* Disable exceptions */
				ewasc	: 1,	/* Enable warning generation */
				ebf	: 1,	/* enable backgrnd functions */
				rsrvd2	: 1,
				perf	: 1;	/* No delays during excptns */

	uint8_t			mrie	: 4,	/* Method/reporting excptons */
				rsrvd3	: 4;

#elif defined(_BIT_FIELDS_HTOL)

	uint8_t			perf	: 1;	/* No delays during excptons */
				rsrvd2	: 1,
				ebf	: 1,	/* enable background funcs */
				ewasc	: 1,	/* Enable warning generation */
				dexcpt	: 1,	/* Disable exceptions */
				test	: 1,	/* Enable test gen of IEs */
				rsrvd1	: 1,
				logerr	: 1,	/* Errors should be logged */

	uint8_t			rsrvd3	: 4;
				mrie	: 4,	/* Method of report excptns */


#else
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */

	uint32_t		interval_timer;	/* reporting grnulrty for IEs */
	uint32_t		report_count;	/* # of times to report an IE */
};

#pragma pack()

#define	MODEPAGE_INFO_EXCPT_LEN	(sizeof (struct info_except_page))

#define	IEC_IE_ENABLED(ies) ((ies).dexcpt == 0)
#define	IEC_IE_CHANGEABLE(ies) ((ies).dexcpt == 1)
#define	IEC_MRIE_CHANGEABLE(ies) ((ies).mrie == 0xf)
#define	IEC_PERF_CHANGEABLE(ies) ((ies).perf == 1)
#define	IEC_EWASC_CHANGEABLE(ies) ((ies).ewasc == 1)
#define	IEC_TEST_CHANGEABLE(ies) ((ies).test == 1)
#define	IEC_RPTCNT_CHANGEABLE(ies) ((ies).report_count == BE_32(0xffffffff))
#define	IEC_LOGERR_CHANGEABLE(ies) ((ies).logerr == 1)

/*
 * Values for the MSIE field of the informational exceptions control mode page
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
	((sizeof (struct selftest_log_parameter)) - \
	    (sizeof (struct log_parameter_header)))

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
 * These flags are used to control disk command execution.
 */
#define	F_NORMAL		0x00	/* normal operation */
#define	F_SILENT		0x01	/* no error msgs at all */
#define	F_ALLERRS		0x02	/* return any error, not just fatal */
#define	F_RQENABLE		0x04	/* no error msgs at all */

#define	INVALID_SENSE_KEY	0x10	/* An impossible sense key */

/*
 * LOG page codes
 */
#define	LOGPAGE_SUPP_LIST	0x00
#define	LOGPAGE_TEMP		0x0d
#define	LOGPAGE_SELFTEST	0x10
#define	LOGPAGE_IE		0x2f

/*
 * "impossible" status value
 */
#define	IMPOSSIBLE_SCSI_STATUS	0xff

/*
 * Minimum length of Request Sense data that we can accept
 */
#define	MIN_REQUEST_SENSE_LEN	18

/*
 * Rounded parameter, as returned in Extended Sense information
 */
#define	ROUNDED_PARAMETER	0x37


/* ASC constants */
#define	ASC_INVALID_OPCODE				0x20
#define	ASC_INVALID_CDB_FIELD				0x24
#define	ASC_FAILURE_PREDICTION_THRESHOLD_EXCEEDED	0x5d

/* ASCQ constants */
#define	ASCQ_INVALID_OPCODE	0

/* Error tests: */
#define	SCSI_INVALID_OPCODE(s, a, aq) \
	(((s) == KEY_ILLEGAL_REQUEST) && ((a) == ASC_INVALID_OPCODE) && \
	((aq) == ASCQ_INVALID_OPCODE))

#define	MODE_PAGE_UNSUPPORTED(s, a, aq) \
	(((s) == KEY_ILLEGAL_REQUEST) && ((a) == ASC_INVALID_CDB_FIELD))

int uscsi_mode_sense(int fd, int page_code, int page_control, caddr_t page_data,
    int page_size, struct scsi_ms_header *header, void *rqbuf, int *rqblen);
int uscsi_mode_sense_10(int fd, int page_code, int page_control,
    caddr_t page_data, int page_size, struct scsi_ms_header_g1 *header,
    void *rqbuf, int *rqblen);
int uscsi_mode_select(int fd, int page_code, int options, caddr_t page_data,
    int page_size, struct scsi_ms_header *header, void *rqbuf, int *rqblen);
int uscsi_mode_select_10(int fd, int page_code, int options,
    caddr_t page_data, int page_size, struct scsi_ms_header_g1 *header,
    void *rqbuf, int *rqblen);
int uscsi_log_sense(int fd, int page_code, int page_control, caddr_t page_data,
    int page_size, void *rqbuf, int *rqblen);
int uscsi_request_sense(int fd, caddr_t buf, int buflen, void *rqbuf,
    int *rqblen);
void scsi_translate_error(struct scsi_extended_sense *rq, uint_t *skeyp,
    uint_t *ascp, uint_t *ascqp);
const char *scsi_asc_ascq_string(uint_t asc, uint_t ascq);

#ifdef	__cplusplus
}
#endif

#endif /* _SCSI_UTIL_H */
