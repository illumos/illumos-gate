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
 *
 */

#ifndef	_IPP_H
#define	_IPP_H

/* $Id: ipp.h 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <sys/time.h>
#include <papi.h>
#include <inttypes.h>


typedef ssize_t (*ipp_reader_t)(void *fd, void *buffer, size_t buffer_size);
typedef ssize_t (*ipp_writer_t)(void *fd, void *buffer, size_t buffer_size);

enum {
	IPP_TYPE_UNKNOWN  = 0,
	IPP_TYPE_REQUEST  = 1,
	IPP_TYPE_RESPONSE = 2
};

/*
 * How closely do we conform to the spec when parsing?  Do we
 *   a) Stop parsing only when we encounter an error that prevents us from
 *      continuing parsing (a server error or ridiculously malformed request)?
 *   b) Stop parsing when we know the server wouldn't be able to act on the
 *      response correctly, even if we can make sense of some of the data?
 *   c) Jawohl, Mein IPP Spec!
 * The answer will usually be b, though a will be useful for debugging.
 */
enum {
	IPP_PARSE_CONFORMANCE_RASH = 0,
	IPP_PARSE_CONFORMANCE_LOOSE = 1,
	IPP_PARSE_CONFORMANCE_STRICT = 2
};


/* Operation IDs */
enum {
	OPID_MIN = 0x0000,			/* 0x0000 */
	OPID_RESERVED_0000 = 0x0000,		/* 0x0000 */
	OPID_RESERVED_0001,			/* 0x0001 */
	OPID_PRINT_JOB,				/* 0x0002 */
	OPID_PRINT_URI,				/* 0x0003 */
	OPID_VALIDATE_JOB,			/* 0x0004 */
	OPID_CREATE_JOB,			/* 0x0005 */
	OPID_SEND_DOCUMENT,			/* 0x0006 */
	OPID_SEND_URI,				/* 0x0007 */
	OPID_CANCEL_JOB,			/* 0x0008 */
	OPID_GET_JOB_ATTRIBUTES,		/* 0x0009 */
	OPID_GET_JOBS,				/* 0x000a */
	OPID_GET_PRINTER_ATTRIBUTES,		/* 0x000b */
	OPID_HOLD_JOB,				/* 0x000c */
	OPID_RELEASE_JOB,			/* 0x000d */
	OPID_RESTART_JOB,			/* 0x000e */
	OPID_RESERVED_000F,			/* 0x000f */
	OPID_PAUSE_PRINTER,			/* 0x0010 */
	OPID_RESUME_PRINTER,			/* 0x0011 */
	OPID_PURGE_JOBS,			/* 0x0012 */
	OPID_SET_PRINTER_ATTRIBUTES,		/* 0x0013 */
	OPID_SET_JOB_ATTRIBUTES,		/* 0x0014 */
	OPID_GET_PRINTER_SUPPORTED_VALUES,	/* 0x0015 */
	OPID_CREATE_PRINTER_SUBSCRIPTION,	/* 0x0016 */
	OPID_CREATE_JOB_SUBSCRIPTION,		/* 0x0017 */
	OPID_GET_SUBSCRIPTION_ATTRIBUTES,	/* 0x0018 */
	OPID_GET_SUBSCRIPTIONS,			/* 0x0019 */
	OPID_RENEW_SUBSCRIPTION,		/* 0x001a */
	OPID_CANCEL_SUBSCRIPTION,		/* 0x001b */
	OPID_GET_NOTIFICATIONS,			/* 0x001c */
	OPID_SEND_NOTIFICATIONS,		/* 0x001d */
	OPID_GET_RESOURCE_ATTRIBUTES,		/* 0x001e */
	OPID_GET_RESOURCE_DATA,			/* 0x001f */
	OPID_GET_RESOURCES,			/* 0x0020 */
	OPID_GET_PRINT_SUPPORT_FILES,		/* 0x0021 */
	OPID_ENABLE_PRINTER,			/* 0x0022 */
	OPID_DISABLE_PRINTER,			/* 0x0023 */
	OPID_PAUSE_PRINTER_AFTER_CURRENT_JOB,	/* 0x0024 */
	OPID_HOLD_NEW_JOBS,			/* 0x0025 */
	OPID_RELEASE_HELD_NEW_JOBS,		/* 0x0026 */
	OPID_DEACTIVATE_PRINTER,		/* 0x0027 */
	OPID_ACTIVATE_PRINTER,			/* 0x0028 */
	OPID_RESTART_PRINTER,			/* 0x0029 */
	OPID_SHUTDOWN_PRINTER,			/* 0x002a */
	OPID_STARTUP_PRINTER,			/* 0x002b */
	OPID_REPROCESS_JOB,			/* 0x002c */
	OPID_CANCEL_CURRENT_JOB,		/* 0x002d */
	OPID_SUSPEND_CURRENT_JOB,		/* 0x002e */
	OPID_RESUME_JOB,			/* 0x002f */
	OPID_PROMOTE_JOB,			/* 0x0030 */
	OPID_SCHEDULE_JOB_AFTER,		/* 0x0031 */
	OPID_RESERVED_MIN,			/* 0x0032 */
	OPID_RESERVED_0032 = 0x0032,		/* 0x0032 */
	/* ... */
	OPID_RESERVED_3FFF = 0x3fff,		/* 0x3fff */
	OPID_RESERVED_MAX = 0x3fff,		/* 0x3fff */
	OPID_RESERVED_VENDOR_MIN = 0x4000,	/* 0x4000 */
	OPID_RESERVED_VENDOR_4000 = 0x4000,	/* 0x4000 */
	/* ... */
	OPID_RESERVED_VENDOR_8FFF = 0x8fff,	/* 0x8fff */
	OPID_RESERVED_VENDOR_MAX = 0x8fff,	/* 0x8fff */
	OPID_MAX = 0x8fff			/* 0x8fff */
};

enum {
	/* Delimiter Tags */
	DTAG_MIN = 0x00,			/* 0x00 */
	DTAG_RESERVED_DELIMITER_00 = 0x00,	/* 0x00 */
	DTAG_OPERATION_ATTRIBUTES,		/* 0x01 */
	DTAG_JOB_ATTRIBUTES,			/* 0x02 */
	DTAG_END_OF_ATTRIBUTES,			/* 0x03 */
	DTAG_PRINTER_ATTRIBUTES,		/* 0x04 */
	DTAG_UNSUPPORTED_ATTRIBUTES,		/* 0x05 */
	DTAG_SUBSCRIPTION_ATTRIBUTES,		/* 0x06 */
	DTAG_EVENT_NOTIFICATION_ATTRIBUTES,	/* 0x07 */
	DTAG_RESERVED_DELIMITER_08,		/* 0x08 */
	DTAG_RESERVED_DELIMITER_09,		/* 0x09 */
	DTAG_RESERVED_DELIMITER_0A,		/* 0x0a */
	DTAG_RESERVED_DELIMITER_0B,		/* 0x0b */
	DTAG_RESERVED_DELIMITER_0C,		/* 0x0c */
	DTAG_RESERVED_DELIMITER_0D,		/* 0x0d */
	DTAG_RESERVED_DELIMITER_0E,		/* 0x0e */
	DTAG_RESERVED_DELIMITER_0F,		/* 0x0f */
	DTAG_MAX = 0x0f,			/* 0x0f */

	/* Value Tags */
	VTAG_MIN = 0x10,			/* 0x10 */
	VTAG_UNSUPPORTED = 0x10,		/* 0x10 */
	VTAG_RESERVED_DEFAULT,			/* 0x11 */
	VTAG_UNKNOWN,				/* 0x12 */
	VTAG_NOVALUE,				/* 0x13 */
	VTAG_RESERVED_OOB_14,			/* 0x14 */
	VTAG_NOT_SETTABLE,			/* 0x15 */
	VTAG_DELETE_ATTRIBUTE,			/* 0x16 */
	VTAG_ADMIN_DEFINE,			/* 0x17 */
	VTAG_RESERVED_OOB_18,			/* 0x18 */
	VTAG_RESERVED_OOB_19,			/* 0x19 */
	VTAG_RESERVED_OOB_1A,			/* 0x1a */
	VTAG_RESERVED_OOB_1B,			/* 0x1b */
	VTAG_RESERVED_OOB_1C,			/* 0x1c */
	VTAG_RESERVED_OOB_1D,			/* 0x1d */
	VTAG_RESERVED_OOB_1E,			/* 0x1e */
	VTAG_RESERVED_OOB_1F,			/* 0x1f */
	VTAG_RESERVED_INT_GEN,			/* 0x20 */
	VTAG_INTEGER,				/* 0x21 */
	VTAG_BOOLEAN,				/* 0x22 */
	VTAG_ENUM,				/* 0x23 */
	VTAG_RESERVED_INT_24,			/* 0x24 */
	VTAG_RESERVED_INT_25,			/* 0x25 */
	VTAG_RESERVED_INT_26,			/* 0x26 */
	VTAG_RESERVED_INT_27,			/* 0x27 */
	VTAG_RESERVED_INT_28,			/* 0x28 */
	VTAG_RESERVED_INT_29,			/* 0x29 */
	VTAG_RESERVED_INT_2A,			/* 0x2a */
	VTAG_RESERVED_INT_2B,			/* 0x2b */
	VTAG_RESERVED_INT_2C,			/* 0x2c */
	VTAG_RESERVED_INT_2D,			/* 0x2d */
	VTAG_RESERVED_INT_2E,			/* 0x2e */
	VTAG_RESERVED_INT_2F,			/* 0x2f */
	VTAG_OCTET_STRING,			/* 0x30 */
	VTAG_DATE_TIME,				/* 0x31 */
	VTAG_RESOLUTION,			/* 0x32 */
	VTAG_RANGE_OF_INTEGER,			/* 0x33 */
	VTAG_BEGIN_COLLECTION,			/* 0x34 */
	VTAG_TEXT_WITH_LANGUAGE,		/* 0x35 */
	VTAG_NAME_WITH_LANGUAGE,		/* 0x36 */
	VTAG_END_COLLECTION,			/* 0x37 */
	VTAG_RESERVED_STRING_38,		/* 0x38 */
	VTAG_RESERVED_STRING_39,		/* 0x39 */
	VTAG_RESERVED_STRING_3A,		/* 0x3a */
	VTAG_RESERVED_STRING_3B,		/* 0x3b */
	VTAG_RESERVED_STRING_3C,		/* 0x3c */
	VTAG_RESERVED_STRING_3D,		/* 0x3d */
	VTAG_RESERVED_STRING_3E,		/* 0x3e */
	VTAG_RESERVED_STRING_3F,		/* 0x3f */
	VTAG_RESERVED_CHAR_GEN,			/* 0x40 */
	VTAG_TEXT_WITHOUT_LANGUAGE,		/* 0x41 */
	VTAG_NAME_WITHOUT_LANGUAGE,		/* 0x42 */
	VTAG_RESERVED_43,			/* 0x43 */
	VTAG_KEYWORD,				/* 0x44 */
	VTAG_URI,				/* 0x45 */
	VTAG_URI_SCHEME,			/* 0x46 */
	VTAG_CHARSET,				/* 0x47 */
	VTAG_NATURAL_LANGUAGE,			/* 0x48 */
	VTAG_MIME_MEDIA_TYPE,			/* 0x49 */
	VTAG_MEMBER_ATTR_NAME,			/* 0x4a */
	VTAG_RESERVED_STRING_4B,		/* 0x4b */
	VTAG_RESERVED_STRING_4C,		/* 0x4c */
	VTAG_RESERVED_STRING_4D,		/* 0x4d */
	VTAG_RESERVED_STRING_4E,		/* 0x4e */
	VTAG_RESERVED_STRING_4F,		/* 0x4f */
	VTAG_RESERVED_STRING_50,		/* 0x50 */
	VTAG_RESERVED_STRING_51,		/* 0x51 */
	VTAG_RESERVED_STRING_52,		/* 0x52 */
	VTAG_RESERVED_STRING_53,		/* 0x53 */
	VTAG_RESERVED_STRING_54,		/* 0x54 */
	VTAG_RESERVED_STRING_55,		/* 0x55 */
	VTAG_RESERVED_STRING_56,		/* 0x56 */
	VTAG_RESERVED_STRING_57,		/* 0x57 */
	VTAG_RESERVED_STRING_58,		/* 0x58 */
	VTAG_RESERVED_STRING_59,		/* 0x59 */
	VTAG_RESERVED_STRING_5A,		/* 0x5a */
	VTAG_RESERVED_STRING_5B,		/* 0x5b */
	VTAG_RESERVED_STRING_5C,		/* 0x5c */
	VTAG_RESERVED_STRING_5D,		/* 0x5d */
	VTAG_RESERVED_STRING_5E,		/* 0x5e */
	VTAG_RESERVED_STRING_5F,		/* 0x5f */
	VTAG_RESERVED_MAX = 0x5f,		/* 0x5f */
	VTAG_MAX = 0x5f,			/* 0x5f */
	VTAG_EXTEND = 0x7f			/* 0x7f */
};

/* Response codes */
enum {
	IPP_OK_MIN = 0x0000,
	IPP_OK = 0x0000,			/* 0x0000 */
	IPP_OK_IGNORED_ATTRIBUTES,		/* 0x0001 */
	IPP_OK_CONFLICTING_ATTRIBUTES,		/* 0x0002 */
	IPP_OK_IGNORED_SUBSCRIPTIONS,		/* 0x0003 */
	IPP_OK_IGNORED_NOTIFICATIONS,		/* 0x0004 */
	IPP_OK_TOO_MANY_EVENTS,			/* 0x0005 */
	IPP_OK_BUT_CANCEL_SUBSCRIPTION,		/* 0x0006 */
	IPP_OK_MAX = IPP_OK_BUT_CANCEL_SUBSCRIPTION,

	IPP_REDIR_MIN = 0x0300,
	IPP_REDIR_OTHER_SIZE = 0x0300,		/* 0x0300 */
	IPP_REDIR_MAX = 0x0300,

	IPP_CERR_MIN = 0x0400,
	IPP_CERR_BAD_REQUEST = 0x0400,		/* 0x0400 */
	IPP_CERR_FORBIDDEN,			/* 0x0401 */
	IPP_CERR_NOT_AUTHENTICATED,		/* 0x0402 */
	IPP_CERR_NOT_AUTHORIZED,		/* 0x0403 */
	IPP_CERR_NOT_POSSIBLE,			/* 0x0404 */
	IPP_CERR_TIMEOUT,			/* 0x0405 */
	IPP_CERR_NOT_FOUND,			/* 0x0406 */
	IPP_CERR_GONE,				/* 0x0407 */
	IPP_CERR_REQUEST_ENTITY,		/* 0x0408 */
	IPP_CERR_REQUEST_VALUE,			/* 0x0409 */
	IPP_CERR_DOCUMENT_FORMAT,		/* 0x040a */
	IPP_CERR_ATTRIBUTES,			/* 0x040b */
	IPP_CERR_URI_SCHEME,			/* 0x040c */
	IPP_CERR_CHARSET,			/* 0x040d */
	IPP_CERR_CONFLICT,			/* 0x040e */
	IPP_CERR_COMPRESSION_NOT_SUPPORTED,	/* 0x040f */
	IPP_CERR_COMPRESSION_ERROR,		/* 0x0410 */
	IPP_CERR_DOCUMENT_FORMAT_ERROR,		/* 0x0411 */
	IPP_CERR_DOCUMENT_ACCESS_ERROR,		/* 0x0412 */
	IPP_CERR_ATTRIBUTES_NOT_SETTABLE,	/* 0x0413 */
	IPP_CERR_IGNORED_ALL_SUBSCRIPTIONS,	/* 0x0414 */
	IPP_CERR_TOO_MANY_SUBSCRIPTIONS,	/* 0x0415 */
	IPP_CERR_IGNORED_ALL_NOTIFICATIONS,	/* 0x0416 */
	IPP_CERR_PRINT_SUPPORT_FILE_NOT_FOUND,	/* 0x0417 */
	IPP_CERR_MAX = IPP_CERR_PRINT_SUPPORT_FILE_NOT_FOUND,

	IPP_SERR_MIN = 0x0500,
	IPP_SERR_INTERNAL = 0x0500,		/* 0x0500 */
	IPP_SERR_OPERATION_NOT_SUPPORTED,	/* 0x0501 */
	IPP_SERR_SERVICE_UNAVAILABLE,		/* 0x0502 */
	IPP_SERR_VERSION_NOT_SUPPORTED,		/* 0x0503 */
	IPP_SERR_DEVICE_ERROR,			/* 0x0504 */
	IPP_SERR_TEMPORARY_ERROR,		/* 0x0505 */
	IPP_SERR_NOT_ACCEPTING,			/* 0x0506 */
	IPP_SERR_BUSY,				/* 0x0507 */
	IPP_SERR_CANCELLED,			/* 0x0508 */
	IPP_SERR_MULTIPLE_DOCS_NOT_SUPPORTED,	/* 0x0509 */
	IPP_SERR_PRINTER_IS_DEACTIVATED,	/* 0x050a */
	IPP_SERR_MAX = IPP_SERR_PRINTER_IS_DEACTIVATED
};

/* Job state codes */
enum {
	IPP_JOB_STATE_PENDING = 3,
	IPP_JOB_STATE_PENDING_HELD = 4,
	IPP_JOB_STATE_PROCESSING = 5,
	IPP_JOB_STATE_PROCESSING_STOPPED = 6,
	IPP_JOB_STATE_CANCELED = 7,
	IPP_JOB_STATE_ABORTED = 8,
	IPP_JOB_STATE_COMPLETED = 9
};

/* exported functions */
extern papi_status_t ipp_read_message(ipp_reader_t iread, void *fd,
					papi_attribute_t ***message, char type);

extern papi_status_t ipp_write_message(ipp_writer_t iwrite, void *fd,
					papi_attribute_t **message);

/* internal functions shared between modules */
extern void ipp_set_status(papi_attribute_t ***message, papi_status_t status,
					char *format, ...);
extern papi_status_t ipp_validate_request(papi_attribute_t **request,
					papi_attribute_t ***response);

extern int ipp_severity(int16_t status);

extern int16_t ipp_charset_supported(char *charset);

extern void *string_to_ipp_attr_value(int8_t type, char *value);

extern char *ipp_uri_to_printer(char *uri);
extern void *papi_attribute_to_ipp_attr(int8_t type, papi_attribute_t *attr);

extern int8_t name_to_ipp_type(char *name);
extern char *job_template[];
extern char *job_description[];
extern char *printer_description[];
extern char *ipp_tag_string(int8_t tag, char *buf, size_t bufsiz);
extern size_t min_val_len(int8_t type, char *name);
extern size_t max_val_len(int8_t type, char *name);
extern int is_keyword(char *value);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_H */
