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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */



#ifndef	_LIBSESLOG_H
#define	_LIBSESLOG_H

#include <libnvpair.h>
#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Error definitions
 */

enum {
	SES_LOG_FAILED_TO_OPEN_DEVICE = 1, /* Couldn't open dev path */
	SES_LOG_FAILED_TO_READ_DEVICE,	/* Couldn't read the log data */
	SES_LOG_FAILED_NULL_TARGET_PATH,	/* Empty target path */
	SES_LOG_FAILED_BAD_TARGET_PATH,	/* Couldn't find valid target path */
	SES_LOG_FAILED_MODE_SENSE,	/* Mode sense error returned */
	SES_LOG_FAILED_MODE_SENSE_OFFSET,	/* Offset not correct */
	SES_LOG_FAILED_BAD_DATA_LEN,	/* Data length not correct */
	SES_LOG_FAILED_BAD_CONTENT_LEN,	/* Content length not correct */
	SES_LOG_FAILED_FORMAT_PAGE_ERR,	/* Device doesn't support page */
	SES_LOG_FAILED_NV_UNIQUE,	/* Couldn't add unique to nvlist */
	SES_LOG_FAILED_NV_LOG,		/* Couldn't add log to nvlist */
	SES_LOG_FAILED_NV_CODE,		/* Couldn't add code to nvlist */
	SES_LOG_FAILED_NV_SEV,		/* Couldn't add sev to nvlist */
	SES_LOG_FAILED_NV_ENTRY,	/* Couldn't add entry to nvlist */
	SES_LOG_FAILED_MODE_SELECT,	/* Mode select failed */
	SES_LOG_FAILED_NVLIST_CREATE	/* Couldn't create a nvlist */
};

/*
 * define different levels of log entries that could be returned
 */
#define	SES_LOG_LEVEL_NOTICE 0
#define	SES_LOG_LEVEL_DEBUG 1
#define	SES_LOG_LEVEL_WARNING 2
#define	SES_LOG_LEVEL_NO_MASK 3
#define	SES_LOG_LEVEL_ERROR 4
#define	SES_LOG_LEVEL_FATAL 5

/* Valid size of log entry being returned by expander */
#define	SES_LOG_VALID_LOG_SIZE 71

/* The string log is made from 8 char entries */
#define	SES_LOG_SPECIFIC_ENTRY_SIZE 8

/* Index of where sequence number starts in returned string */
#define	SES_LOG_SEQ_NUM_START 27
/* Index of where log code starts */
#define	SES_LOG_CODE_START 36
/* Index of where log level starts in returned string */
#define	SES_LOG_LEVEL_START 40

/* Maximum size the each sub log entry can be */
#define	ENTRY_MAX_SIZE	10
/* Maximum save buffer log entry size */
#define	MAX_LOG_ENTRY_SZ	256

#define	MAX_ALLOC_LEN (0xfffc)
/*
 * Sense return buffer length
 * Arbitrary, could be larger
 */
#define	SENSE_BUFF_LEN	32
/*
 * 60 seconds for SCSI timeout
 */
#define	DEF_PT_TIMEOUT	60


/*
 * Defines for different SCSI cmd paramters
 */
#define	MODE_SELECT10_CMDLEN  10
#define	MODE10_RESP_HDR_LEN   8
#define	MODE_SENSE10_CMDLEN   10


/*
 * Defines for nvlist entries
 */
#define	ENTRY_PREFIX	"entry"
#define	ENTRY_SEVERITY	"severity"
#define	ENTRY_CODE	"code"
#define	ENTRY_LOG	"log"



/*
 * Genesis specific log clear control struct
 */
struct log_clear_control_struct {
	unsigned char pageControls;
	uint8_t subpage_code;
	uint8_t page_lengthUpper;
	uint8_t page_lengthLower;
	uint8_t host_id[16];
	uint8_t seq_clear[4];
	uint8_t timeout[2];
};



/*
 * Struct to contain information needed to read logs
 */
typedef struct ses_log_call_struct {
	char target_path[MAXPATHLEN]; /* Path to device, passed in */
	char product_id[MAXNAMELEN]; /* product id of expander, passed in */
	hrtime_t poll_time; /* nanosecond poll time, passed in */
	char last_log_entry[MAXNAMELEN]; /* Last entry read, passed in/out */
	int number_log_entries;  /* num of log entries read, passed back */
	int size_of_log_entries; /* Total size of all logs read passed back */
	nvlist_t *log_data;  /* Log data being returned, passed back */
} ses_log_call_t;

/*
 * Basic library functions
 */
extern int access_ses_log(struct ses_log_call_struct *);


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSESLOG_H */
