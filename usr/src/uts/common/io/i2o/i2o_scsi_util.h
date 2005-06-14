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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_I2O_SCSI_UTIL_H
#define	_I2O_SCSI_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Utility msg synchronization condvar
 */
#define	UTIL_MSG_SLEEP		0
#define	UTIL_MSG_WAKEUP		1

/*
 * Utility Parameter's mutex
 */
#define	I2OHBA_UTILPARAM_MUTEX(i2ohba, i)	(&i2ohba->util_param_mutex[i])
#define	I2OHBA_UTILPARAM_CV(i2ohba, i)		(&i2ohba->util_param_cv[i])


/*
 * Defines for parameter size
 */
#define	ONE_PARAM_BLOCK	(sizeof (i2o_param_operations_list_header_t)\
			+ sizeof (i2o_param_operation_specific_template_t) \
			+ sizeof (uint32_t))

#define	ALL_PARAM_BLOCK	(sizeof (i2o_param_operations_list_header_t)\
			+ sizeof (i2o_param_operation_all_template_t) \
			+ sizeof (uint16_t))

/*
 * Utility message's transaction context
 */
struct i2ohba_util {
	int			wakeup; /* value */
	int			status; /* status of reply msg */
	kmutex_t		*mutex; /* per request mutex */
	kcondvar_t		*cv;    /* per request signal */
	void	*i2ohba_util_buffer;    /* result operation block */
	size_t			rlen;   /* length of the result block */
	ddi_dma_cookie_t	dmacookie; /* dma cookie for result block */
	ddi_dma_handle_t	dmahandle; /* dma handle for result block */
	ddi_acc_handle_t	dma_acc_handle; /* dma access handle */
};

/*
 * Util_Params_Get Op on all Parameters
 */

typedef struct i2o_setparam {

	/* i2o_message_frame_t */
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint_t		TargetAddress:12;
		uint_t		InitiatorAddress:12;
		uint_t		Function:8;
	    } s2;
	    uint32_t		w2;
	} u2;
	i2o_initiator_context_t	InitiatorContext;

	/* i2o_util_params_set_message */
	i2o_transaction_context_t	TransactionContext;
	uint32_t			OperationFlags;

	/* SGL: i2o_sge_immediate_data_elememnt */
	i2o_flags_count_t	FlagsCount1; /* 32 bits */
			/* size == ONE_PARAM_BLOCK */
	/* i2o_param_operation_list_header */
	uint16_t		OperationCount;
	uint16_t		Reserved;

	/* i2o_param_operation_specific_template */
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		FieldCount;
	uint16_t		FieldIdx;
	uint16_t		Value; /* not in struct */
	uint16_t		pad; /* not in struct */

	/* SGL: i2o_sge_simple_element */
	i2o_flags_count_t	FlagsCount2; /* 32 bits */
	uint32_t		PhysicalAddress;

} i2o_setparam_t;


typedef struct i2o_setparam_reply {

	/* i2o_param_results_list_header_t */
	uint16_t		ResultCount;
	uint16_t		Reserved;

	/* i2o_param_modify_operation_result */
	uint16_t		BlockSize;
	uint8_t			BlockStatus;
	uint8_t			ErrorInfoSize;
	/* ErrorInformation (if any) */
} i2o_setparam_reply_t;

#define	ALL_UTILPARAMS		0x01
#define	SYNC_UTILPARAM		0x02

/*
 * Util_Params_Get Op on all Parameters
 */

typedef struct i2o_getallparam {

	/* i2o_message_frame_t */
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint_t		TargetAddress:12;
		uint_t		InitiatorAddress:12;
		uint_t		Function:8;
	    } s2;
	    uint32_t		w2;
	} u2;
	i2o_initiator_context_t	InitiatorContext;

	/* i2o_util_params_get_message */
	i2o_transaction_context_t	TransactionContext;
	uint32_t		OperationFlags;

	/* SGL: i2o_sge_immediate_data_elememnt */
	i2o_flags_count_t	FlagsCount1; /* 32 bits */
			/* size == ALL_PARAM_BLOCK */
	/* i2o_param_operation_list_header */
	uint16_t		OperationCount;
	uint16_t		Reserved;

	/* i2o_param_operation_all_template */
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		FieldCount; /* (0xffff) */
	uint16_t		Pad; /* not part of all temp struct */

	/* SGL: i2o_sge_simple_element */
	i2o_flags_count_t	FlagsCount2; /* 32 bits */
	uint32_t		PhysicalAddress;

} i2o_getallparam_t;


typedef struct i2o_getallparam_reply {

	/* i2o_param_results_list_header_t */
	uint16_t		ResultCount;
	uint16_t		Reserved;

	/* i2o_param_read_operation_result */
	uint16_t		BlockSize;
	uint8_t			BlockStatus;
	uint8_t			ErrorInfoSize;

	/* ListOfValues */
	uint8_t			DeviceType;
	uint8_t			Flags;
	uint16_t		Reserved1;
	uint32_t		Identifier;
	uint8_t			LUN[8];
	uint32_t		QueueDepth;
	uint8_t			Reserved2;
	uint8_t			NegOffset;
	uint8_t			NegDataWidth;
	uint8_t			Reserved3;
	uint64_t		NegSyncRate;

} i2o_getallparam_reply_t;


/*
 * Util_Params_Get Op on Synch and Offset
 */
typedef struct i2o_getsyncparam {

	/* i2o_message_frame_t */
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint_t		TargetAddress:12;
		uint_t		InitiatorAddress:12;
		uint_t		Function:8;
	    } s2;
	    uint32_t		w2;
	} u2;
	i2o_initiator_context_t	InitiatorContext;

	/* i2o_util_params_get_message */
	i2o_transaction_context_t	TransactionContext;
	uint32_t		OperationFlags;

	/* SGL: i2o_sge_immediate_data_elememnt */
	i2o_flags_count_t	FlagsCount1; /* 32 bits */
			/* size == ONE_PARAM_BLOCK */
	/* i2o_param_operation_list_header */
	uint16_t		OperationCount;
	uint16_t		Reserved;

	/* i2o_param_operation_specific_template */
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		FieldCount;
	uint16_t		FieldIdx; /* field #10 */
	uint16_t		FieldIdx2; /* field #7 not in struct */
	uint16_t		Pad; /* not in struct */

	/* SGL: i2o_sge_simple_element */
	i2o_flags_count_t	FlagsCount2; /* 32 bits */
	uint32_t		PhysicalAddress;

} i2o_getsyncparam_t;


typedef struct i2o_getsyncparam_reply {

	/* i2o_param_results_list_header_t */
	uint16_t		ResultCount;
	uint16_t		Reserved;

	/* i2o_param_read_operation_result */
	uint16_t		BlockSize;
	uint8_t			BlockStatus;
	uint8_t			ErrorInfoSize;

	/* ListOfValues */
	uint64_t		NegSyncRate;
	uint8_t			NegOffset;

} i2o_getsyncparam_reply_t;

#ifdef	__cplusplus
}
#endif

#endif /* _I2O_SCSI_UTIL_H */
