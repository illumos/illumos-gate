/*
 * *********************************************************************
 * All software on this website is made available under the following
 * terms and conditions. By downloading this software, you agree to
 * abide by these terms and conditions with respect to this software.
 *
 * I2O SIG All rights reserved.
 *
 * These header files are provided, pursuant to your I2O SIG membership
 * agreement, free of charge on an as-is basis without warranty of any
 * kind, either express or implied, including but not limited to,
 * implied warranties or merchantability and fitness for a particular
 * purpose. I2O SIG does not warrant that this program will meet the
 * user's requirements or that the operation of these programs will be
 * uninterrupted or error-free. Acceptance and use of this program
 * constitutes the user's understanding that he will have no recourse
 * to I2O SIG for any actual or consequential damages including, but
 * not limited to, loss profits arising out of use or inability to use
 * this program.
 *
 * Member is permitted to create deriavative works to this header-file
 * program. However, all copies of the program and its derivative
 * works must contain the I2O SIG copyright notice.
 * ********************************************************************
 */

/*
 * ********************************************************************
 * I2OUtil.h -- I2O Utility Class Message defintion file
 *
 * This file contains information presented in Chapter 6 of the I2O
 * Specification.
 * ********************************************************************
 */

/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_I2OUTIL_H
#define	_SYS_I2OUTIL_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	I2OUTIL_REV 1_5_4 /* I2OUtil header file revision string */

#include <sys/i2o/i2omsg.h> /* Include the Base Message file */

/*
 * ********************************************************************
 * NOTES:
 *
 * Gets, reads, receives, etc. are all even numbered functions.
 * Sets, writes, sends, etc. are all odd numbered functions.
 * Functions that both send and receive data can be either but an attempt is
 * made to use the function number that indicates the greater transfer amount.
 * Functions that do not send or receive data use odd function numbers.
 *
 * Some functions are synonyms like read, receive and send, write.
 *
 * All common functions will have a code of less than 0x80.
 * Unique functions to a class will start at 0x80.
 * Executive Functions start at 0xA0.
 *
 * Utility Message function codes range from 0 - 0x1f
 * Base Message function codes range from 0x20 - 0xfe
 * Private Message function code is 0xff.
 * ********************************************************************
 */

/* Utility Message class functions. */

#define	I2O_UTIL_NOP			0x00
#define	I2O_UTIL_ABORT			0x01
#define	I2O_UTIL_CLAIM			0x09
#define	I2O_UTIL_CLAIM_RELEASE		0x0B
#define	I2O_UTIL_CONFIG_DIALOG		0x10
#define	I2O_UTIL_DEVICE_RESERVE		0x0D
#define	I2O_UTIL_DEVICE_RELEASE		0x0F
#define	I2O_UTIL_EVENT_ACKNOWLEDGE	0x14
#define	I2O_UTIL_EVENT_REGISTER		0x13
#define	I2O_UTIL_LOCK			0x17
#define	I2O_UTIL_LOCK_RELEASE		0x19
#define	I2O_UTIL_PARAMS_GET		0x06
#define	I2O_UTIL_PARAMS_SET		0x05
#define	I2O_UTIL_REPLY_FAULT_NOTIFY	0x15

/* ************************************************************************** */

/* ABORT Abort type defines. */

#define	I2O_ABORT_TYPE_EXACT_ABORT		0x00
#define	I2O_ABORT_TYPE_FUNCTION_ABORT		0x01
#define	I2O_ABORT_TYPE_TRANSACTION_ABORT	0x02
#define	I2O_ABORT_TYPE_WILD_ABORT		0x03
#define	I2O_ABORT_TYPE_CLEAN_EXACT_ABORT	0x04
#define	I2O_ABORT_TYPE_CLEAN_FUNCTION_ABORT	0x05
#define	I2O_ABORT_TYPE_CLEAN_TRANSACTION_ABORT	0x06
#define	I2O_ABORT_TYPE_CLEAN_WILD_ABORT		0x07

/* UtilAbort Function Message Frame structure. */

typedef struct i2o_util_abort_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint16_t			reserved;
	uint8_t				AbortType;
	uint8_t				FunctionToAbort;
	i2o_transaction_context_t	TransactionContextToAbort;
} i2o_util_abort_message_t;

typedef struct i2o_util_abort_reply {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			CountOfAbortedMessages;
} i2o_util_abort_reply_t;

/* ************************************************************************** */

/* Claim Flag defines */

#define	I2O_CLAIM_FLAGS_EXCLUSIVE		0x0001 /* Reserved */
#define	I2O_CLAIM_FLAGS_RESET_SENSITIVE		0x0002
#define	I2O_CLAIM_FLAGS_STATE_SENSITIVE		0x0004
#define	I2O_CLAIM_FLAGS_CAPACITY_SENSITIVE	0x0008
#define	I2O_CLAIM_FLAGS_PEER_SERVICE_DISABLED	0x0010
#define	I2O_CLAIM_FLAGS_MGMT_SERVICE_DISABLED	0x0020

/* Claim Type defines */

#define	I2O_CLAIM_TYPE_PRIMARY_USER		0x01
#define	I2O_CLAIM_TYPE_AUTHORIZED_USER		0x02
#define	I2O_CLAIM_TYPE_SECONDARY_USER		0x03
#define	I2O_CLAIM_TYPE_MANAGEMENT_USER		0x04

/* UtilClaim Function Message Frame structure. */

typedef struct i2o_util_claim_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint16_t 			ClaimFlags;
	uint8_t 			reserved;
	uint8_t 			ClaimType;
} i2o_util_claim_message_t;

/* ************************************************************************** */

/* Claim Release Flag defines */

#define	I2O_RELEASE_FLAGS_CONDITIONAL		0x0001

/* UtilClaimRelease Function Message Frame structure. */

typedef struct i2o_util_claim_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint16_t 			ReleaseFlags;
	uint8_t 			reserved;
	uint8_t 			ClaimType;
} i2o_util_claim_release_message_t;

/* ************************************************************************** */

/* UtilConfigDialog Function Message Frame structure */

typedef struct i2o_util_config_dialog_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			PageNumber;
	i2o_sg_element_t			SGL;
} i2o_util_config_dialog_message_t;

/* ************************************************************************** */

/* Event Acknowledge Function Message Frame structure */

typedef struct i2o_util_event_ack_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			EventIndicator;
	uint32_t			EventData[1];
} i2o_util_event_ack_message_t;

/* Event Ack Reply structure */

typedef struct i2o_util_event_ack_reply {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			EventIndicator;
	uint32_t			EventData[1];
} i2o_util_event_ack_reply_t;

/* ************************************************************************** */

/* Event Indicator Mask Flags */

#define	I2O_EVENT_IND_STATE_CHANGE		0x80000000
#define	I2O_EVENT_IND_GENERAL_WARNING		0x40000000
#define	I2O_EVENT_IND_CONFIGURATION_FLAG	0x20000000
/* #define	I2O_EVENT_IND_RESERVE_RELEASE	0x10000000 */
#define	I2O_EVENT_IND_LOCK_RELEASE		0x10000000
#define	I2O_EVENT_IND_CAPABILITY_CHANGE		0x08000000
#define	I2O_EVENT_IND_DEVICE_RESET		0x04000000
#define	I2O_EVENT_IND_EVENT_MASK_MODIFIED	0x02000000
#define	I2O_EVENT_IND_FIELD_MODIFIED		0x01000000
#define	I2O_EVENT_IND_VENDOR_EVENT		0x00800000
#define	I2O_EVENT_IND_DEVICE_STATE		0x00400000

/* Event Data for generic Events */

#define	I2O_EVENT_STATE_CHANGE_NORMAL		0x00
#define	I2O_EVENT_STATE_CHANGE_SUSPENDED	0x01
#define	I2O_EVENT_STATE_CHANGE_RESTART		0x02
#define	I2O_EVENT_STATE_CHANGE_NA_RECOVER	0x03
#define	I2O_EVENT_STATE_CHANGE_NA_NO_RECOVER	0x04
#define	I2O_EVENT_STATE_CHANGE_QUIESCE_REQUEST	0x05
#define	I2O_EVENT_STATE_CHANGE_FAILED		0x10
#define	I2O_EVENT_STATE_CHANGE_FAULTED		0x11

#define	I2O_EVENT_GEN_WARNING_NORMAL		0x00
#define	I2O_EVENT_GEN_WARNING_ERROR_THRESHOLD	0x01
#define	I2O_EVENT_GEN_WARNING_MEDIA_FAULT	0x02

#define	I2O_EVENT_CAPABILITY_OTHER		0x01
#define	I2O_EVENT_CAPABILITY_CHANGED		0x02

#define	I2O_EVENT_SENSOR_STATE_CHANGED		0x01

/* UtilEventRegister Function Message Frame structure */

typedef struct i2o_util_event_register_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			EventMask;
} i2o_util_event_register_message_t;

/* UtilEventRegister Reply structure */

typedef struct i2o_util_event_register_reply {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			EventIndicator;
	uint32_t			EventData[1];
} i2o_util_event_register_reply_t;

/* ************************************************************************** */

/* UtilLock Function Message Frame structure. */

typedef struct i2o_util_lock_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_util_lock_message_t;

/* ************************************************************************** */

/* UtilLockRelease Function Message Frame structure. */

typedef struct i2o_util_lock_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_util_lock_release_message_t;

/* ************************************************************************** */

/* UtilNOP Function Message Frame structure. */

typedef struct i2o_util_nop_message {
	i2o_message_frame_t		StdMessageFrame;
} i2o_util_nop_message_t;

/* ************************************************************************** */

/* UtilParamsGet Message Frame structure. */

typedef struct i2o_util_params_get_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			OperationFlags;
	i2o_sg_element_t		SGL;
} i2o_util_params_get_message_t;

/* ************************************************************************** */

/* UtilParamsSet Message Frame structure. */

typedef struct i2o_util_params_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			OperationFlags;
	i2o_sg_element_t		SGL;
} i2o_util_params_set_message_t;


/* ************************************************************************** */

/* UtilReplyFaultNotify Message for Message Failure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_util_reply_fault_notify_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint8_t 			LowestVersion;
	uint8_t 			HighestVersion;
	uint8_t 			Severity;
	uint8_t 			FailureCode;
	union {
	    struct {
		uint16_t		FailingIOP_ID:12;
		uint16_t		reserved:4;
	    } s;
	    uint16_t			h1;
	} u1;
	uint16_t			FailingHostUnitID;
	uint32_t			AgeLimit;
#if I2O_64BIT_CONTEXT
	i2o_message_frame_t		*OriginalMFA;
#else
	i2o_message_frame_t		*OriginalMFALowPart;
	uint32_t			OriginalMFAHighPart; /* Always 0000 */
#endif
} i2o_util_reply_fault_notify_message_t;

#define	get_i2o_util_FailingIOP_ID(p, hdl)	(p)->u1.s.FailingIOP_ID

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_util_reply_fault_notify_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint8_t 			LowestVersion;
	uint8_t 			HighestVersion;
	uint8_t 			Severity;
	uint8_t 			FailureCode;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		FailingIOP_ID:12;
	    } s;
	    uint32_t			h1;
	} u1;
	uint16_t			FailingHostUnitID;
	uint32_t			AgeLimit;
#if I2O_64BIT_CONTEXT
	i2o_message_frame_t		*OriginalMFA;
#else
	i2o_message_frame_t		*OriginalMFALowPart;
	uint32_t			OriginalMFAHighPart; /* Always 0000 */
#endif
} i2o_util_reply_fault_notify_message_t;

#define	get_i2o_util_FailingIOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u1.h1) & 0xFFF)

#endif

/* ************************************************************************** */

/* Device Reserve Function Message Frame structure. */
/* NOTE: This was previously called the Reserve Message */

typedef struct i2o_util_device_reserve_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_util_device_reserve_message_t;

/* ************************************************************************** */

/* Device Release Function Message Frame structure. */
/* NOTE: This was previously called the ReserveRelease Message */

typedef struct i2o_util_device_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_util_device_release_message_t;

/* ************************************************************************** */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_I2OUTIL_H */
