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

#ifndef _FAULT_ANALYZE_H
#define	_FAULT_ANALYZE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for data structures used in the SCSI IE module
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include "dm_types.h"

#define	MSG_BUFLEN			256	/* Message buffer length */

#define	IE_SUCCESS			0
#define	IE_NOT_SUPPORTED		1
#define	IE_CANNOT_BE_ENABLED		2
#define	IE_ENABLE_FAILED		3
#define	IE_ENABLE_DIDNT_STICK		4
#define	IE_OTHER_ERROR			10

#define	MODE_CMD_LEN_UNKNOWN		0
#define	MODE_CMD_LEN_6			1
#define	MODE_CMD_LEN_10			2

typedef enum {
	MODEPAGE_SUPP_IEC		= 0x00000001
} modepage_supp_e;

typedef enum {
	LOGPAGE_SUPP_IE			= 0x00000001,
	LOGPAGE_SUPP_TEMP		= 0x00000002,
	LOGPAGE_SUPP_SELFTEST		= 0x00000004
} logpage_supp_e;

typedef enum {
	EXTN_IE_TEMP_THRESHOLD		= 0x00000001,
	EXTN_TEMPLOG_TEMP_THRESHOLD	= 0x00000002
} disk_extension_e;

typedef enum {
	OPTION_PERF_MODE		= 0x00000001,
	OPTION_TEST_MODE		= 0x00000002,
	OPTION_SELFTEST_ERRS_ARE_FATAL	= 0x00000004,
	OPTION_OVERTEMP_ERRS_ARE_FATAL	= 0x00000008
} disk_option_e;

/* This MUST be a MASK: */
typedef enum {
	DISK_FAULT_SOURCE_NONE		= 0x00000000,
	DISK_FAULT_SOURCE_SELFTEST	= 0x00000001,
	DISK_FAULT_SOURCE_OVERTEMP	= 0x00000002,
	DISK_FAULT_SOURCE_INFO_EXCPT	= 0x00000004
} disk_flt_src_e;

#define	LOG_PAGE_SUPPORTED(di, supp)	((di)->log_pages_supported & (supp))
#define	MODE_PAGE_SUPPORTED(di, supp)	((di)->mode_pages_supported & (supp))
#define	EXTN_SUPPORTED(di, extn)	((di)->extensions & (extn))
#define	OPT_ENABLED(di, opt)		((di)->options & (opt))

struct scsi_ms_hdrs {
	int	length;
	union {
		struct scsi_ms_header		g0;
		struct scsi_ms_header_g1	g1;
	} h;
};

/* Yea, this can be a union... */
struct disk_fault {
	disk_flt_src_e		fault_src;
	char			*msg;

	/* Predictive failure information */
	boolean_t		sense_valid;
	uchar_t			sense_key;
	uchar_t			asc;
	uchar_t			ascq;

	/* Self-test failure information */
	uint16_t		selftest_code;

	/* Temperature information */
	int			cur_temp;
	int			thresh_temp;
	struct disk_fault	*next;
};

struct diskmon;
struct fault_monitor_info;

/*
 * Each of the following validation or analysis functions are called once
 * for each parameter type in the log page for which the function is
 * written.  If there's a problem with the parameter passed-in, the
 * function returns a negative number.
 */

typedef int (*logpage_validation_fn_t)(struct diskmon *,
    struct log_parameter_header *);

typedef int (*logpage_analyze_fn_t)(struct diskmon *,
    struct log_parameter_header *);

struct logpage_validation_entry {
	uchar_t			logpage_code;
	int			supp_bit;
	uchar_t			pc;
	const char		*descr;
	boolean_t		enabled;
	logpage_validation_fn_t	validate_fn;
	logpage_analyze_fn_t	analyze_fn;
};

extern int disk_fault_init(struct diskmon *diskp);
extern void disk_fault_uninit(struct diskmon *diskp);
extern int disk_fault_analyze(struct diskmon *diskp);
extern void free_disk_fault_list(struct fault_monitor_info *fmip);
extern void create_fake_faults(struct diskmon *diskp);

#ifdef	__cplusplus
}
#endif

#endif /* _FAULT_ANALYZE_H */
