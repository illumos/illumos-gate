/*
 * *****************************************************************************
 *
 * All software on this website is made available under the following terms and
 * conditions.  By downloading this software, you agree to abide by these terms
 * and conditions with respect to this software.
 *
 * I2O SIG All rights reserved.
 *
 * These header files are provided, pursuant to your I2O SIG membership
 * agreement, free of charge on an as-is basis without warranty of any kind,
 * either express or implied, including but not limited to, implied warranties
 * or merchantability and fitness for a particular purpose.  I2O SIG does not
 * warrant that this program will meet the user's requirements or that the
 * operation of these programs will be uninterrupted or error-free.
 * Acceptance and use of this program constitutes the user's understanding
 * that he will have no recourse to I2O SIG for any actual or consequential
 * damages including, but not limited to, loss profits arising out of use
 * or inability to use this program.
 *
 * Member is permitted to create derivative works to this header-file program.
 * However, all copies of the program and its derivative works must contain the
 * I2O SIG copyright notice.
 *
 * *****************************************************************************
 */

/*
 * ********************************************************************
 * I2OExec.h -- I2O Executive Class Message definition file
 *
 * This file contains information presented in Chapter 4 of the I2O(tm)
 * Specification.
 * ********************************************************************
 */

/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_I2OEXEC_H
#define	_SYS_I2OEXEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/i2o/i2omsg.h>	/* the Base Message file */
#include	<sys/i2o/i2outil.h>
#include	<sys/types.h>


#define	I2OEXEC_REV 1_5_4	/* I2OExec header file revision string */


/*
 * ****************************************************************************
 *  NOTES:
 *
 *   Gets, reads, receives, etc. are all even numbered functions.
 *   Sets, writes, sends, etc. are all odd numbered functions.
 *   Functions that both send and receive data can be either but an attempt
 *   is made to use the function number that indicates the greater transfer
 *   amount.  Functions that do not send or receive data use odd function
 *   numbers.
 *
 *   Some functions are synonyms like read, receive and send, write.
 *
 *   All common functions will have a code of less than 0x80.
 *   Unique functions to a class will start at 0x80.
 *   Executive Functions start at 0xA0.
 *
 *   Utility Message function codes range from 0 - 0x1f
 *   Base Message function codes range from 0x20 - 0xfe
 *   Private Message function code is 0xff.
 * *****************************************************************************
 */

/*  I2O Executive Function Codes.  */

#define	I2O_EXEC_ADAPTER_ASSIGN			0xB3
#define	I2O_EXEC_ADAPTER_READ			0xB2
#define	I2O_EXEC_ADAPTER_RELEASE		0xB5
#define	I2O_EXEC_BIOS_INFO_SET			0xA5
#define	I2O_EXEC_BOOT_DEVICE_SET		0xA7
#define	I2O_EXEC_CONFIG_VALIDATE		0xBB
#define	I2O_EXEC_CONN_SETUP			0xCA
#define	I2O_EXEC_DDM_DESTROY			0xB1
#define	I2O_EXEC_DDM_ENABLE			0xD5
#define	I2O_EXEC_DDM_QUIESCE			0xC7
#define	I2O_EXEC_DDM_RESET			0xD9
#define	I2O_EXEC_DDM_SUSPEND			0xAF
#define	I2O_EXEC_DEVICE_ASSIGN			0xB7
#define	I2O_EXEC_DEVICE_RELEASE			0xB9
#define	I2O_EXEC_HRT_GET			0xA8
#define	I2O_EXEC_IOP_CLEAR			0xBE
#define	I2O_EXEC_IOP_CONNECT			0xC9
#define	I2O_EXEC_IOP_RESET			0xBD
#define	I2O_EXEC_LCT_NOTIFY			0xA2
#define	I2O_EXEC_OUTBOUND_INIT			0xA1
#define	I2O_EXEC_PATH_ENABLE			0xD3
#define	I2O_EXEC_PATH_QUIESCE			0xC5
#define	I2O_EXEC_PATH_RESET			0xD7
#define	I2O_EXEC_STATIC_MF_CREATE		0xDD
#define	I2O_EXEC_STATIC_MF_RELEASE		0xDF
#define	I2O_EXEC_STATUS_GET			0xA0
#define	I2O_EXEC_SW_DOWNLOAD			0xA9
#define	I2O_EXEC_SW_UPLOAD			0xAB
#define	I2O_EXEC_SW_REMOVE			0xAD
#define	I2O_EXEC_SYS_ENABLE			0xD1
#define	I2O_EXEC_SYS_MODIFY			0xC1
#define	I2O_EXEC_SYS_QUIESCE			0xC3
#define	I2O_EXEC_SYS_TAB_SET			0xA3


/* I2O Get Status State values */

#define	I2O_IOP_STATE_INITIALIZING		0x01
#define	I2O_IOP_STATE_RESET			0x02
#define	I2O_IOP_STATE_HOLD			0x04
#define	I2O_IOP_STATE_READY			0x05
#define	I2O_IOP_STATE_OPERATIONAL		0x08
#define	I2O_IOP_STATE_FAILED			0x10
#define	I2O_IOP_STATE_FAULTED			0x11


/* Event Indicator Assignments for the Executive Class. */

#define	I2O_EVENT_IND_RESOURCE_LIMIT		0x00000001
#define	I2O_EVENT_IND_CONNECTION_FAIL		0x00000002
#define	I2O_EVENT_IND_ADAPTER_FAULT		0x00000004
#define	I2O_EVENT_IND_POWER_FAIL		0x00000008
#define	I2O_EVENT_IND_RESET_PENDING		0x00000010
#define	I2O_EVENT_IND_RESET_IMMINENT		0x00000020
#define	I2O_EVENT_IND_HARDWARE_FAIL		0x00000040
#define	I2O_EVENT_IND_XCT_CHANGE		0x00000080
#define	I2O_EVENT_IND_NEW_LCT_ENTRY		0x00000100
#define	I2O_EVENT_IND_MODIFIED_LCT		0x00000200
#define	I2O_EVENT_IND_DDM_AVAILABILITY		0x00000400

/* Resource Limit Event Data */

#define	I2O_EVENT_RESOURCE_LIMIT_LOW_MEMORY		0x00000001
#define	I2O_EVENT_RESOURCE_LIMIT_INBOUND_POOL_LOW	0x00000002
#define	I2O_EVENT_RESOURCE_LIMIT_OUTBOUND_POOL_LOW	0x00000004

/* Connection Fail Event Data */

#define	I2O_EVENT_CONNECTION_FAIL_REPOND_NORMAL		0x00000000
#define	I2O_EVENT_CONNECTION_FAIL_NOT_REPONDING		0x00000001
#define	I2O_EVENT_CONNECTION_FAIL_NO_AVAILABLE_FRAMES	0x00000002

/* Reset Pending Event Data */

#define	I2O_EVENT_RESET_PENDING_POWER_LOSS		0x00000001
#define	I2O_EVENT_RESET_PENDING_CODE_VIOLATION		0x00000002

/* Reset Imminent Event Data */

#define	I2O_EVENT_RESET_IMMINENT_UNKNOWN_CAUSE		0x00000000
#define	I2O_EVENT_RESET_IMMINENT_POWER_LOSS		0x00000001
#define	I2O_EVENT_RESET_IMMINENT_CODE_VIOLATION		0x00000002
#define	I2O_EVENT_RESET_IMMINENT_PARITY_ERROR		0x00000003
#define	I2O_EVENT_RESET_IMMINENT_CODE_EXCEPTION		0x00000004
#define	I2O_EVENT_RESET_IMMINENT_WATCHDOG_TIMEOUT	0x00000005

/* Hardware Fail Event Data */

#define	I2O_EVENT_HARDWARE_FAIL_UNKNOWN_CAUSE		0x00000000
#define	I2O_EVENT_HARDWARE_FAIL_CPU_FAILURE		0x00000001
#define	I2O_EVENT_HARDWARE_FAIL_MEMORY_FAULT		0x00000002
#define	I2O_EVENT_HARDWARE_FAIL_DMA_FAILURE		0x00000003
#define	I2O_EVENT_HARDWARE_FAIL_IO_BUS_FAILURE		0x00000004

/* DDM Availability Event Data */

#define	I2O_EVENT_DDM_AVAILIBILITY_RESPOND_NORMAL	0x00000000
#define	I2O_EVENT_DDM_AVAILIBILITY_CONGESTED		0x00000001
#define	I2O_EVENT_DDM_AVAILIBILITY_NOT_RESPONDING	0x00000002
#define	I2O_EVENT_DDM_AVAILIBILITY_PROTECTION_VIOLATION	0x00000003
#define	I2O_EVENT_DDM_AVAILIBILITY_CODE_VIOLATION	0x00000004


#define	I2O_OPERATION_FLAG_ASSIGN_PERMANENT		0x01

/* ExecAdapterAssign Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_adapter_assign_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DdmTID:12;
		uint32_t		reserved:12;
		uint32_t		OperationFlags:8;
	    } s;
	    uint32_t			w;
	} u1;
    i2o_hrt_entry_t			HRTEntry;
} i2o_exec_adappter_assign_message_t;

/* macros to access the bit fields in exec adapter assign message */

#define	get_i2o_exec_adapter_DdmTID(mp, hdl) \
			(mp)->u1.s.DdmTID
#define	put_i2o_exec_adapter_DdmTID(mp, id, hdl) \
			((mp)->u1.s.DdmTID = (id))
#define	get_i2o_exec_adapter_OperationFlags(mp, hdl) \
			(mp)->u1.s.OperationFlags
#define	put_i2o_exec_adapter_OperationFlags(mp, n, hdl) \
			((mp)->u1.s.OperationFlags = (n))

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_adapter_assign_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		OperationFlags:8;
		uint32_t		reserved:12;
		uint32_t		DdmTID:12;
	    } s;
	    uint32_t			w;
	} u1;
    i2o_hrt_entry_t			HRTEntry;
} i2o_exec_adappter_assign_message_t;

/* macros to access the bit fields in exec adapter assign message */


#define	get_i2o_exec_adapter_OperationFlags(mp, hdl) \
	(mp)->u1.s.OperationFlags
#define	put_i2o_exec_adapter_OperatonFlags(mp, n, hdl) \
	((mp)->u1.s.OperationFlags = (n))

#define	get_i2o_exec_adapter_DdmTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_adapter_DdmTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif

#define	I2O_REQUEST_FLAG_CONFIG_REGISTER	0x00000000
#define	I2O_REQUEST_FLAG_IO_REGISTER		0x00000001
#define	I2O_REQUEST_FLAG_ADAPTER_MEMORY		0x00000002

/* ExecAdapterRead Function Message Frame structure. */

typedef struct i2o_exec_adapter_read_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			AdapterID;
	uint32_t			RequestFlags;
	uint32_t			Offset;
	uint32_t			Length;
	i2o_sg_element_t		SGL;
} i2o_exec_adapter_read_message_t;


#define	I2O_OPERATION_FLAG_RELEASE_PERMANENT	0x01

/* ExecAdapterRelease Function Message Frame structure. */

typedef struct i2o_exec_dapater_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint8_t				reserved[3];
	uint8_t				OperationFlags;
    i2o_hrt_entry_t			HRTEntry;
} i2o_exec_adapter_release_message_t;



/* ExecBiosInfoSet Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_bios_info_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DeviceTID:12;
		uint32_t		reserved:12;
		uint32_t		BiosInfo:8;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_bios_info_set_message_t;

/* macros to access the bit fields in exec bios info set message structure */

#define	get_i2o_exec_bios_DeviceTID(mp, hdl) \
			(mp)->u1.s.DeviceTID
#define	put_i2o_exec_bios_DeviceTID(mp, id, hdl) \
			((mp)->u1.s.DeviceTID = (id))
#define	get_i2o_exec_BiosInfo(mp, hdl) \
			(mp)->u1.s.BiosInfo
#define	put_i2o_exec_BiosInfo(mp, n, hdl) \
			((mp)->u1.s.BiosInfo = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_bios_info_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		BiosInfo:8;
		uint32_t		reserved:12;
		uint32_t		DeviceTID:12;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_bios_info_set_message_t;

/* macros to access the bit fields in exec bios info set message structure */

#define	get_i2o_exec_BiosInfo(mp, hdl) \
	(mp)->u1.s.BiosInfo
#define	put_i2o_exec_BiosInfo(mp, n, hdl) \
	((mp)->u1.s.BiosInfo = (n))

#define	get_i2o_exec_bios_DeviceID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_bios_DeviceID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif


#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

/* ExecBootDeviceSet Function Message Frame structure. */

typedef struct i2o_exec_boot_device_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		BootDevice:12;
		uint32_t		reserved:20;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_boot_device_set_message_t;

/* macros to access the bit fields in exec boot set message structure */

#define	get_i2o_exec_boot_BootDevice(mp, hdl) \
			(mp)->u1.s.BootDevice
#define	put_i2o_exec_boot_BootDevice(mp, id, hdl) \
			((mp)->u1.s.BootDevice = (id))

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_boot_device_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved:20;
		uint32_t		BootDevice:12;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_boot_device_set_message_t;

#define	get_i2o_exec_boot_BootDevice(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_boot_BootDevice(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecConfigValidate Function Message Frame structure. */

typedef struct i2o_exec_config_validate_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_exec_config_validate_message_t;



/* ExecConnSetup Requestor  */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_alias_connect_setup {
	union {
	    struct {
		uint32_t	IOP1AliasForTargetDevice:12;
		uint32_t	IOP2AliasForInitiatorDevice:12;
		uint32_t	reserved:8;
	    } s;
	    uint32_t		w;
	} u1;
} i2o_alias_connect_setup_t;

/* macros to access the bit fields in alias connect setup structure */

#define	get_i2o_exec_setup_IOP1AliasForTargetDevice(mp, hdl) \
			(mp)->u1.s.IOP1AliasForTargetDevice
#define	put_i2o_exec_setup_IOP1AliasForTargetDevice(mp, id, hdl) \
			((mp)->u1.s.IOP1AliasForTargetDevice = (id))
#define	get_i2o_exec_setup_IOP2AliasForInitiatorDevice(mp, hdl) \
			(mp)->u1.s.IOP2AliasForInitiatorDevice
#define	put_i2o_exec_setup_IOP2AliasForInitiatortDevice(mp, n, hdl) \
			((mp)->u1.s.IOP2AliasForInitiatortDevice = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_alias_connect_setup {
	union {
	    struct {
		uint32_t	reserved:8;
		uint32_t	IOP2AliasForInitiatorDevice:12;
		uint32_t	IOP1AliasForTargetDevice:12;
	    } s;
	    uint32_t		w;
	} u1;
} i2o_alias_connect_setup_t;

/* macros to access the bit fields in alias connect setup structure */

#define	get_i2o_exec_setup_IOP2ForInitiatorDevice(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u1.w) >> 12) & 0xFFF)
#define	put_i2o_exec_setup_IOP2ForInitiatorDevice(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, (ddi_get32(hdl, &(mp)->u.w) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))

#define	get_i2o_exec_setup_IOP1AliasForTargetDevice(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_setup_IOP1AliasForTargetDevice(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif


#define	I2O_OPERATION_FLAG_PEER_TO_PEER_BIDIRECTIONAL	0x01

/* ExecConnSetup Object  */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_object_connect_setup {
	union {
	    struct {
		uint32_t	TargetDevice:12;
		uint32_t	InitiatorDevice:12;
		uint32_t	OperationFlags:8;
	    } s;
	    uint32_t		w;
	} u1;
} i2o_object_connect_setup_t;

/* macros to access the bit fields in object connect setup structure */

#define	get_i2o_exec_setup_TargetDevice(mp, hdl) \
			(mp)->u1.s.TargetDevice
#define	put_i2o_exec_setup_TargetDevice(mp, id, hdl) \
			((mp)->u1.s.TargetDevice = (id))
#define	get_i2o_exec_setup_InitiatorDevice(mp, hdl) \
			(mp)->u1.s.InitiatorDevice
#define	put_i2o_exec_setup_InitiatorDevice(mp, n, hdl) \
			((mp)->u1.s.InitiatorDevice = (id))
#define	get_i2o_exec_setup_OperationFlags(mp, hdl) \
			(mp)->u1.s.OpetationFlags
#define	put_i2o_exec_setup_OperationFlags(mp, id, hdl) \
			((mp)->u1.s.OperationFlags = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_object_connect_setup {
	union {
	    struct {
		uint32_t	OperationFlags:8;
		uint32_t	InitiatorDevice:12;
		uint32_t	TargetDevice:12;
	    } s;
	    uint32_t		w;
	} u1;
} i2o_object_connect_setup_t;

/* macros to access the bit fields in object connect setup structure */

#define	get_i2o_exec_setup_OperationFlags(mp, hdl) \
	(mp)->u1.s.OperationFlags
#define	put_i2o_exec_setup_OperationFlags(mp, n, hdl) \
	((mp)->u1.s.OperationFlags = (n))

#define	get_i2o_exec_setup_InitiatorDevice(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u1.w) >> 12) & 0xFFF)
#define	put_i2o_exec_setup_InitiatorDevice(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, (ddi_get32(hdl, &(mp)->u.w) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))

#define	get_i2o_exec_setup_TargetDevice(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_setup_TargetDevice(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecConnSetup Function Message Frame structure. */

typedef struct i2o_exec_conn_setup_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_object_connect_setup_t	ObjectInfo;
	i2o_alias_connect_setup_t	AliasInfo;
	uint16_t			IOP2InboundMFrameSize;
	uint16_t			reserved;
	uint32_t			MessageClass;
} i2o_exec_conn_setup_message_t;


/* ExecConnSetup Object Reply */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_object_connect_reply {
	union {
	    struct {
		uint32_t	TargetDevice:12;
		uint32_t	InitiatorDevice:12;
		uint32_t	ReplyStatusCode:8;
	    } s;
	    uint32_t		w;
	} u1;
} i2o_object_connect_reply_t;

/* macros to access the bit fields in object connect reply structure */

#define	get_connect_reply_TargetDevice(mp, hdl) \
			(mp)->u1.s.TargetDevice
#define	get_connect_reply_InitiatorDevice(mp, hdl) \
			(mp)->u1.s.InitiatorDevice
#define	get_connect_reply_RepluStatus(mp, hdl) \
			(mp)->u1.s.ReplyStatusCode

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_object_connect_reply {
	union {
	    struct {
		uint32_t	ReplyStatusCode:8;
		uint32_t	InitiatorDevice:12;
		uint32_t	TargetDevice:12;
	    } s;
	    uint32_t		w;
	} u1;
} i2o_object_connect_reply_t;

/* macros to access the bit fields in object connect reply structure */

#define	get_connect_reply_ReplyStatusCode(mp, hdl) \
	(mp)->u1.s.ReplyStatusCode

#define	get_connect_reply_InitiatorDevice(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u1.w) >> 12) & 0xFFF)

#define	get_connect_reply_TargetDevice(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)

#endif


/* ExecConnSetup reply structure. */

typedef struct i2o_exec_conn_setup_reply {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_object_connect_reply_t	ObjectInfo;
	i2o_alias_connect_setup_t	AliasInfo;
	uint16_t			IOP2InboundMFrameSize;
	uint16_t			reserved;
} i2o_exec_conn_setup_reply_t;


/* ExecDdmDestroy Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_ddm_destroy_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DdmTID:12;
		uint32_t		reserved:20;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_ddm_destroy_message_t;

/* macros to access the bit fields in exec ddm destroy message structure */

#define	get_i2o_exec_ddm_destroy_DdmTID(mp, hdl) \
			(mp)->u1.s.DdmTID
#define	put_i2o_exec_ddm_destroy_DdmTID(mp, id, hdl) \
			((mp)->u1.s.DdmTID = (id))

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_ddm_destroy_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved:20;
		uint32_t		DdmTID:12;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_ddm_destroy_message_t;

/* macros to access the bit fields in exec ddm destroy message structure */

#define	get_i2o_exec_ddm_destroy_DdmTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_ddm_destroy_DdmTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecDdmEnable Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_ddm_enable_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DeviceTID:12;
		uint32_t		reserved1:20;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_ddm_enable_message_t;

/* macros to access the bit fields in exec ddm enable message structure */

#define	get_i2o_exec_ddm_enable_DeviceTID(mp, hdl) \
			(mp)->u2.s2.DeviceTID
#define	put_i2o_exec_ddm_enable_DeviceTID(mp, id, hdl) \
			((mp)->u2.s2.DeviceTID = (id))

#define	get_i2o_exec_ddm_enable_IOP_ID(mp, hdl) \
			(mp)->u3.s3.IOP_ID
#define	put_i2o_exec_ddm_enable_IOP_ID(mp, id, hdl) \
			((mp)->u3.s3.IOP_ID = (id))

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_ddm_enable_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved1:20;
		uint32_t		DeviceTID:12;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_ddm_enable_message_t;

/* macros to access the bit fields in exec ddm enable message structure */

#define	get_i2o_exec_ddm_enable_DeviceTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_ddm_enable_DeviceTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_ddm_enable_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) & 0xFFF)

#define	put_i2o_exec_ddm_enable_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h1, \
		(ddi_get16(hdl, &(mp)->u3.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif

/* ExecDdmQuiesce Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_ddm_quiesce_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DeviceTID:12;
		uint32_t		reserved1:20;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_ddm_quiesce_message_t;

/* macros to access the bit fields in exec ddm quiesce message structure */

#define	get_i2o_exec_ddm_quiesce_DeviceTID(mp, hdl) \
			(mp)->u2.s2.DeviceTID
#define	put_i2o_exec_ddm_quiesce_DeviceTID(mp, id, hdl) \
			((mp)->u2.s2.DeviceTID = (id))

#define	get_i2o_exec_ddm_quiesce_IOP_ID(mp, hdl) \
			(mp)->u3.s3.IOP_ID
#define	put_i2o_exec_ddm_quiesce_IOP_ID(mp, id, hdl) \
			((mp)->u3.s3.IOP_ID = (id))

#endif


/* ExecDdmQuiesce Function Message Frame structure. */

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_ddm_quiesce_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved1:20;
		uint32_t		DeviceTID:12;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_ddm_quiesce_message_t;

/* macros to access the bit fields in exec ddm quiesce message structure */

#define	get_i2o_exec_ddm_quiesce_DeviceTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_ddm_quiesce_DeviceTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_ddm_quiesce_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) & 0xFFF)

#define	put_i2o_exec_ddm_quiesce_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h1, \
		(ddi_get16(hdl, &(mp)->u3.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecDdmReset Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_ddm_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DeviceTID:12;
		uint32_t		reserved1:20;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_ddm_reset_message_t;

/* macros to access the bit fields in exec ddm reset message structure */

#define	get_i2o_exec_ddm_reset_DeviceTID(mp, hdl) \
			(mp)->u2.s2.DeviceTID
#define	put_i2o_exec_ddm_reset_DeviceTID(mp, id, hdl) \
			((mp)->u2.s2.DeviceTID = (id))

#define	get_i2o_exec_ddm_reset_IOP_ID(mp, hdl) \
			(mp)->u3.s3.IOP_ID
#define	put_i2o_exec_ddm_resetquiesce_IOP_ID(mp, id, hdl) \
			((mp)->u3.s3.IOP_ID = (id))

#endif


/* ExecDdmReset Function Message Frame structure. */

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_ddm_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved1:20;
		uint32_t		DeviceTID:12;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_ddm_reset_message_t;

/* macros to access the bit fields in exec ddm reset message structure */

#define	get_i2o_exec_ddm_reset_DeviceTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_ddm_reset_DeviceTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_ddm_reset_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) & 0xFFF)

#define	put_i2o_exec_ddm_reset_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h1, \
		(ddi_get16(hdl, &(mp)->u3.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecDdmSuspend Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_ddm_suspend_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DdmTID:12;
		uint32_t		reserved:20;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_ddm_suspend_message_t;

/* macros to access the bit fields in exec ddm suspend message structure */

#define	get_i2o_exec_ddm_suspend_DdmTID(mp, hdl) \
			(mp)->u1.s.DdmTID
#define	put_i2o_exec_ddm_suspend_DdmTID(mp, id, hdl) \
			((mp)->u1.s.DdmTID = (id))

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_ddm_suspend_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved:20;
		uint32_t		DdmTID:12;
	    } s;
	    uint32_t			w;
	} u1;
} i2o_exec_ddm_suspend_message_t;

/* macros to access the bit fields in exec ddm suspend message structure */

#define	get_i2o_exec_ddm_suspend_DdmTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u1.w) & 0xFFF)
#define	put_i2o_exec_ddm_suspend_DdmTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u1.w, \
		(ddi_get32(hdl, &(mp)->u1.w) & ~0xFFF) | ((id) & 0xFFF))

#endif


#define	I2O_OPERATION_FLAG_ASSIGN_PERMANENT	0x01


/* ExecDeviceAssign Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_device_assign_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DeviceTID:12;
		uint32_t		DdmTID:12;
		uint32_t		OperationFlags:8;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_device_assign_message_t;


/* macros to access the bit fields in device assign message structure */

#define	get_i2o_exec_device_assign_DeviceTID(mp, hdl) \
			(mp)->u2.s2.DeviceTID
#define	put_i2o_exec_device_assign_DeviceTID(mp, id, hdl) \
			((mp)->u2.s2.DeviceTID = (id))
#define	get_i2o_exec_device_assign_DdmTID(mp, hdl) \
			(mp)->u2.s2.DdmTID
#define	put_i2o_exec_device_assign_DdmTID(mp, n, hdl) \
			((mp)->u2.s2.DdmTID = (id))
#define	get_i2o_exec_device_assign_OperationFlags(mp, hdl) \
			(mp)->u2.s2.OpetationFlags
#define	put_i2o_exec_device_assign_OperationFlags(mp, id, hdl) \
			((mp)->u2.s2.OperationFlags = (id))

#define	get_i2o_exec_device_assign_IOP_ID(mp, hdl) \
			(mp)->u3.s3.IOP_ID
#define	put_i2o_exec_device_assign_IOP_ID(mp, id, hdl) \
			((mp)->u3.s3.IOP_ID = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)


typedef struct i2o_exec_device_assign_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		OperationFlags:8;
		uint32_t		DdmTID:12;
		uint32_t		DeviceTID:12;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_device_assign_message_t;

/* macros to access the bit fields in device assign message structure */

#define	get_i2o_exec_device_assign_OperationFlags(mp, hdl) \
	(mp)->u2.s2.OperationFlags
#define	put_i2o_exec_device_assign_OperationFlags(mp, n, hdl) \
	((mp)->u2.s2.OperationFlags = (n))

#define	get_i2o_exec_device_assign_DdmTID(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u2.w2) >> 12) & 0xFFF)
#define	put_i2o_exec_device_assign_DdmTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, (ddi_get32(hdl, &(mp)->u2.w2) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))

#define	get_i2o_exec_device_assign_DeviceTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_device_assign_DeviceTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_device_assign_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) & 0xFFF)
#define	put_i2o_exec_device_assign_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h1, \
		(ddi_get16(hdl, &(mp)->u3.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


#define	I2O_OPERATION_FLAG_RELEASE_PERMANENT	0x01

/* ExecDeviceRelease Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_device_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		DeviceTID:12;
		uint32_t		DdmTID:12;
		uint32_t		OperationFlags:8;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_device_release_message_t;


/* macros to access the bit fields in device release message structure */

#define	get_i2o_exec_device_release_DeviceTID(mp, hdl) \
			(mp)->u2.s2.DeviceTID
#define	put_i2o_exec_device_release_DeviceTID(mp, id, hdl) \
			((mp)->u2.s2.DeviceTID = (id))
#define	get_i2o_exec_device_release_DdmTID(mp, hdl) \
			(mp)->u2.s2.DdmTID
#define	put_i2o_exec_device_release_DdmTID(mp, n, hdl) \
			((mp)->u2.s2.DdmTID = (id))
#define	get_i2o_exec_device_release_OperationFlags(mp, hdl) \
			(mp)->u2.s2.OpetationFlags
#define	put_i2o_exec_device_release_OperationFlags(mp, id, hdl) \
			((mp)->u2.s2.OperationFlags = (id))

#define	get_i2o_exec_device_release_IOP_ID(mp, hdl) \
			(mp)->u3.s3.IOP_ID
#define	put_i2o_exec_device_release_IOP_ID(mp, id, hdl) \
			((mp)->u3.s3.IOP_ID = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)


typedef struct i2o_exec_device_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		OperationFlags:8;
		uint32_t		DdmTID:12;
		uint32_t		DeviceTID:12;
	    } s2;
	    uint32_t			w2;
	} u2;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s3;
	    uint16_t			h1;
	} u3;
	uint16_t			HostUnitID;
} i2o_exec_device_release_message_t;

/* macros to access the bit fields in device assign message structure */


#define	get_i2o_exec_device_release_OperationFlags(mp, hdl) \
	(mp)->u2.s2.OperationFlags
#define	put_i2o_exec_device_release_OperationFlags(mp, n, hdl) \
	((mp)->u2.s2.OperationFlags = (n))

#define	get_i2o_exec_device_release_DdmTID(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u2.w2) >> 12) & 0xFFF)
#define	put_i2o_exec_device_release_DdmTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, (ddi_get32(hdl, &(mp)->u2.w2) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))

#define	get_i2o_exec_device_release_DeviceTID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_device_release_DeviceTID(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_device_release_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) & 0xFFF)

#define	put_i2o_exec_device_release_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h1, \
		(ddi_get16(hdl, &(mp)->u3.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* HRT Entry Structure defined in I2OMSG.H */

/* ExecHrtGet Function Message Frame structure. */

typedef struct i2o_exec_hrt_get_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_sg_element_t		SGL;
} i2o_exec_hrt_get_message_t;



/* ExecIopClear Function Message Frame structure. */

typedef struct i2o_exec_iop_clear_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_exec_iop_clear_message_t;


/* ExecIopConnect Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_iop_connect_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		reserved:24;
		uint32_t		IOP1MsgerType:8;

	    } s2;
	    uint32_t			w2;
	} u2;
	uint16_t			IOP1InboundMFrameSize;
	union {
	    struct {
		uint16_t		IOP1AliasForIOP2:12;
		uint16_t		reserved1:4;
	    } s3;
	    uint16_t			h2;
	} u3;
	union {
	    struct {
		uint16_t		IOP_ID1:12;
		uint16_t		reserved2:4;
	    } s4;
	    uint16_t			h1;
	} u4;
	uint16_t			HostUnitID1;
} i2o_exec_iop_connect_message_t;


/* macros to access the bit fields in exec iop connect message structure */

#define	get_i2o_exec_iop_connect_IOP1MsgerType(p, hdl) \
		(mp)->u2.s2.IOP1MsgerType

#define	put_i2o_exec_iop_connect_IOP1MsgerType(mp, id, hdl) \
		((mp)->u2.s2.IOP1MsgerType = (id))


#define	get_i2o_exec_iop_connect_IOP1AliasForIOP2(p, hdl) \
		(mp)->u3.s3.IOP1AliasForIOP2

#define	put_i2o_exec_iop_connect_IOP1AliasForIOP2(mp, id, hdl) \
		((mp)->u3.s3.IOP1AliasForIOP2 = (id))

#define	get_i2o_exec_iop_connect_IOP_ID1(p, hdl) \
		(mp)->u4.s4.IOP_ID1

#define	put_i2o_exec_iop_connect_IOP_ID1(mp, id, hdl) \
		((mp)->u4.s4.IOP_ID1 = (id))


#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_iop_connect_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint32_t		IOP1MsgerType:8;
		uint32_t		reserved:24;
	    } s2;
	    uint32_t			w2;
	} u2;

	uint16_t			IOP1InboundMFrameSize;
	union {
	    struct {
		uint16_t		reserved1:8;
		uint16_t		IOP1AliasForIOP2:12;
	    } s3;
	    uint16_t			h2;
	} u3;
	union {
	    struct {
		uint16_t		reserved2:4;
		uint16_t		IOP_ID1:12;
	    } s4;
	    uint16_t			h1;
	} u4;
	uint16_t			HostUnitID1;
} i2o_exec_iop_connect_message_t;

/* macros to access the bit fields in exec iop connect message structure */

#define	get_i2o_exec_iop_connect_IOP1MsgerType(p, hdl) \
	((ddi_get32(hdl, &(p)->u2.w2) >> 24) & 0xFF)

#define	put_i2o_exec_iop_connect_IOP1MsgerType(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFF) | (((id) & 0xFF) << 24))


#define	get_i2o_exec_iop_connect_IOP1AliasForIOP2(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h2) & 0xFFF)

#define	put_i2o_exec_iop_connect_IOP1AliasForIOP2(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h2, \
		(ddi_get16(hdl, &(mp)->u3.h2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_iop_connect_IOP_ID1(p, hdl) \
	(ddi_get32(hdl, &(p)->u4.h1) & 0xFFF)

#define	put_i2o_exec_iop_connect_IOP_ID1(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u4.h1, \
		(ddi_get16(hdl, &(mp)->u4.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecIopConnect reply structure */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_iop_connect_iop_reply {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint16_t			DetailedStatusCode;
	uint8_t				reserved;
	uint8_t				ReqStatus;
	uint16_t			IOP2InboundMFrameSize;
	union {
	    struct {
		uint16_t		IOP2AliasForIOP1:12;
		uint16_t		reserved1:4;
	    } s3;
	    uint16_t			h2;
	} u3;
	union {
	    struct {
		uint16_t		IOP_ID2:12;
		uint16_t		reserved2:4;
	    } s4;
	    uint16_t			w4;
	} u4;
	uint16_t			HostUnitID2;
} i2o_exec_iop_connect_reply_t;

/* macros to access the bit fields in exec iop connect reply structure */

#define	get_i2o_exec_iop_connect_reply_IOP2AliasForIOP1(p, hdl) \
		(mp)->u3.s3.IOP2AliasForIOP1

#define	put_i2o_exec_iop_connect_reply_IOP2AliasForIOP1(mp, id, hdl) \
		((mp)->u3.s3.IOP2AliasForIOP1 = (id))

#define	get_i2o_exec_iop_connect_reply_IOP_ID2(p, hdl) \
		(mp)->u4.s4.IOP_ID2

#define	put_i2o_exec_iop_connect_reply_IOP_ID2(mp, id, hdl) \
		((mp)->u4.s4.IOP_ID2 = (id))

#endif



#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_iop_connect_iop_reply {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint16_t			DetailedStatusCode;
	uint8_t				reserved;
	uint8_t				ReqStatus;
	uint16_t			IOP2InboundMFrameSize;
	union {
	    struct {
		uint16_t		reserved1:8;
		uint16_t		IOP2AliasForIOP1:12;
	    } s3;
	    uint16_t			h2;
	} u3;
	union {
	    struct {
		uint16_t		reserved2:4;
		uint16_t		IOP_ID2:12;
	    } s4;
	    uint16_t			h1;
	} u4;
	uint16_t			HostUnitID2;
} i2o_exec_iop_connect_reply_t;

/* macros to access the bit fields in exec iop connect reply structure */

#define	get_i2o_exec_iop_connect_reply_IOP2AliasForIOP1(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h2) & 0xFFF)

#define	put_i2o_exec_iop_connect_reply_IOP2AliasForIOP1(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u3.h2, \
		(ddi_get16(hdl, &(mp)->u3.h2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_iop_connect_reply_IOP_ID2(p, hdl) \
	(ddi_get32(hdl, &(p)->u4.h1) & 0xFFF)

#define	put_i2o_exec_iop_connect_reply_IOP_ID2(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u4.h1, \
		(ddi_get16(hdl, &(mp)->u4.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


#define	I2O_EXEC_IOP_RESET_RESERVED_SZ	16

#define	I2O_EXEC_IOP_RESET_IN_PROGRESS	0x01
#define	I2O_EXEC_IOP_RESET_REJECTED	0x02

#define	I2O_EXEC_IOP_RESET_STATUS_RESERVED_SZ	3

typedef struct i2o_exec_iop_reset_status {
	volatile uint8_t ResetStatus;
	uint8_t		 reserved[I2O_EXEC_IOP_RESET_STATUS_RESERVED_SZ];
} i2o_exec_iop_reset_status_t;


/* ExecIopReset Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_iop_reset_message {
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint32_t	TargetAddress:12;
		uint32_t	InitiatorAddress:12;
		uint32_t	Function:8;
	    } s2;
	    uint32_t		w2;
	} u2;
	uint8_t			Reserved[I2O_EXEC_IOP_RESET_RESERVED_SZ];
	uint32_t		StatusWordLowAddress;
	uint32_t		StatusWordHighAddress;
} i2o_exec_iop_reset_message_t;

/* macros to access the bit fields in iop reset message */

#define	get_i2o_exec_reset_TargetAddress(mp, hdl) \
			(mp)->u2.s2.TargetAddress
#define	put_i2o_exec_reset_TargetAddress(mp, id, hdl) \
			((mp)->u2.s2.TargetAddress = (id))
#define	get_i2o_exec_reset_InitiatorAddress(mp, hdl) \
			(mp)->u2.s2.InitiatorAddress
#define	put_i2o_exec_reset_InitiatorAddress(mp, id, hdl) \
			((mp)->u2.s2.InitiatorAddress = (id))
#define	get_i2o_exec_reset_Function(mp, hdl) \
			(mp)->u2.s2.Function
#define	put_i2o_exec_reset_Function(mp, n, hdl) \
			((mp)->u2.s2.Function = (n))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_iop_reset_message {
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint32_t	Function:8;
		uint32_t	InitiatorAddress:12;
		uint32_t	TargetAddress:12;
	    } s2;
	    uint32_t		w2;
	} u2;

	uint8_t			Reserved[I2O_EXEC_IOP_RESET_RESERVED_SZ];
	uint32_t		StatusWordLowAddress;
	uint32_t		StatusWordHighAddress;
} i2o_exec_iop_reset_message_t;

/* macros to access the bit fields in iop reset message */

#define	get_i2o_exec_reset_Function(mp, hdl) \
	(mp)->u2.s2.Function
#define	put_i2o_exec_reset_Function(mp, n, hdl) \
	((mp)->u2.s2.Function = (n))

#define	get_i2o_exec_reset_TargetAddress(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_reset_TargetAddress(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_reset_InitiatorAddress(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u2.w2) >> 12) & 0xFFF)
#define	put_i2o_exec_reset_InitiatorAddress(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, (ddi_get32(hdl, &(mp)->u2.w2) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))

#endif


/* LCT Entry Structure defined in I2OMSG.H */

/* ExecLCTNotify Function Message Frame structure. */

typedef struct i2o_exec_lct_notify_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			ClassIdentifier;
	uint32_t			LastReportedChangeIndicator;
	i2o_sg_element_t		SGL;
} i2o_exec_lct_notify_message_t;


/* ExecOutboundInit Function Message Frame structure. */

typedef struct i2o_exec_outbound_init_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint32_t			HostPageFrameSize;
	uint8_t				InitCode;
	uint8_t				reserved;
	uint16_t			OutboundMFrameSize;
	i2o_sg_element_t		SGL;
} i2o_exec_outbound_init_message_t;


#define	I2O_EXEC_OUTBOUND_INIT_IN_PROGRESS	0x01
#define	I2O_EXEC_OUTBOUND_INIT_REJECTED	0x02
#define	I2O_EXEC_OUTBOUND_INIT_FAILED	0x03
#define	I2O_EXEC_OUTBOUND_INIT_COMPLETE	0x04

#define	I2O_EXEC_OUTBOUND_INIT_RESERVED_SZ	3


typedef struct i2o_exec_outbound_init_status {
	uint8_t	InitStatus;
	uint8_t	reserved[I2O_EXEC_OUTBOUND_INIT_RESERVED_SZ];
} i2o_exec_outbound_init_status_t;


typedef struct i2o_exec_outbound_init_reclaim_list {
	uint32_t	MFACount;
	uint32_t	MFAReleaseCount;
	uint32_t	MFAAddress[1];
} i2o_exec_outbound_init_reclaim_list_t;


/* ExecPathEnable Function Message Frame structure. */


#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_path_enable_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
} i2o_exec_path_enable_message_t;

/* macros to access the bit fields in exec path enable message structure */

#define	get_i2o_exec_path_enable_IOP_ID(mp, hdl) \
			(mp)->u2.s2.IOP_ID
#define	put_i2o_exec_path_enable_IOP_ID(mp, id, hdl) \
			((mp)->u2.s2.IOP_ID = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_path_enable_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
} i2o_exec_path_enable_message_t;

/* macros to access the bit fields in exec path enable message structure */

#define	get_i2o_exec_path_enable_IOP_ID(p, hdl) \
	(ddi_get32(hdl, &(p)->u2.h1) & 0xFFF)

#define	put_i2o_exec_path_enable_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u2.h1, \
		(ddi_get16(hdl, &(mp)->u2.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecPathQuiesce Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_path_quiesce_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
} i2o_exec_path_quiesce_message_t;

/* macros to access the bit fields in exec path quiesce message structure */

#define	get_i2o_exec_path_quiesce_IOP_ID(mp, hdl) \
			(mp)->u2.s2.IOP_ID
#define	put_i2o_exec_path_quiesce_IOP_ID(mp, id, hdl) \
			((mp)->u2.s2.IOP_ID = (id))

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_path_quiesce_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
} i2o_exec_path_quiesce_message_t;

/* macros to access the bit fields in exec path quiesce message structure */

#define	get_i2o_exec_path_quiesce_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u2.h1) & 0xFFF)

#define	put_i2o_exec_path_quiesce_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u2.h1, \
		(ddi_get16(hdl, &(mp)->u2.h1) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecPathReset Function Message Frame structure. */


#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_path_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
} i2o_exec_path_reset_message_t;

/* macros to access the bit fields in exec path reset message structure */

#define	get_i2o_exec_path_reset_IOP_ID(mp, hdl) \
			(mp)->u2.s2.IOP_ID
#define	put_i2o_exec_path_reset_IOP_ID(mp, id, hdl) \
			((mp)->u2.s2.IOP_ID = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_path_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
} i2o_exec_path_reset_message_t;

/* macros to access the bit fields in exec path reset message structure */

#define	get_i2o_exec_path_reset_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u2.h1) & 0xFFF)

#define	put_i2o_exec_path_reset_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u2.h1, \
		(ddi_get16(hdl, &(mp)->u2.h1) & ~0xFFF) | ((id) & 0xFFF))


#endif


#define	I2O_EXEC_STATIC_MF_CREATE_RESERVED_SZ	3

/* ExecStaticMfCreate Message Frame  structure */

typedef struct i2o_exec_static_mf_create_message {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint8_t			MaxOutstanding;
	uint8_t			reserved[I2O_EXEC_STATIC_MF_CREATE_RESERVED_SZ];
	i2o_message_frame_t	StaticMessageFrame;
} i2o_exec_static_mf_create_message_t;


/* ExecStaticMfCreate Message Frame reply */

typedef struct i2o_exec_static_mf_create_reply {
	i2o_single_reply_message_frame_t	StdReplyFrame;
	i2o_message_frame_t			StaticMFA;
} i2o_exec_static_mf_create_reply_t;


/* ExecStaticMfRelease Message Frame structure */

typedef struct i2o_exec_static_mf_release_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_message_frame_t		StaticMFA;
} i2o_exec_static_mf_release_message_t;



#define	I2O_EXEC_STATUS_GET_RESERVED_SZ	16

/* ExecStatusGet Function Message Frame structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_status_get_message {
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint32_t	Function:8;
		uint32_t	InitiatorAddress:12;
		uint32_t	TargetAddress:12;
	    } s2;
	    uint32_t		w2;
	} u2;
	uint8_t			Reserved[I2O_EXEC_STATUS_GET_RESERVED_SZ];
	uint32_t		ReplyBufferAddressLow;
	uint32_t		ReplyBufferAddressHigh;
	uint32_t		ReplyBufferLength;
} i2o_exec_status_get_message_t;

/* macros to access the bit fields in i2o exec status get message */

#define	get_i2o_exec_status_TargetAddress(mp, hdl) \
			(mp)->u2.s2.TargetAddress
#define	put_i2o_exec_status_TargetAddress(mp, id, hdl) \
			((mp)->u2.s2.TargetAddress = (id))
#define	get_i2o_exec_status_InitiatorAddress(mp, hdl) \
			(mp)->u2.s2.InitiatorAddress
#define	put_i2o_exec_status_InitiatorAddress(mp, id, hdl) \
			((mp)->u2.s2.InitiatorAddress = (id))
#define	get_i2o_exec_status_Function(mp, hdl) \
			(mp)->u2.s2.Function
#define	put_i2o_exec_status_Function(mp, n, hdl) \
			((mp)->u2.s2.Function = (n))

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_status_get_message {
	uint8_t			VersionOffset;
	uint8_t			MsgFlags;
	uint16_t		MessageSize;
	union {
	    struct {
		uint32_t	Function:8;
		uint32_t	InitiatorAddress:12;
		uint32_t	TargetAddress:12;
	    } s2;
	    uint32_t		w2;
	} u2;
	uint8_t			Reserved[I2O_EXEC_STATUS_GET_RESERVED_SZ];
	uint32_t		ReplyBufferAddressLow;
	uint32_t		ReplyBufferAddressHigh;
	uint32_t		ReplyBufferLength;
} i2o_exec_status_get_message_t;

/* macros to access the bit fields in i2o exec status get message */

#define	get_i2o_exec_status_Function(mp, hdl) \
	(mp)->u2.s2.Function
#define	put_i2o_exec_status_Function(mp, n, hdl) \
	((mp)->u2.s2.Function = (n))

#define	get_i2o_exec_status_TargetAddress(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_i2o_exec_status_TargetAddress(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_status_InitiatorAddress(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u2.w2) >> 12) & 0xFFF)
#define	put_i2o_exec_status_InitiatorAddress(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, (ddi_get32(hdl, &(mp)->u2.w2) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))

#endif


#define	I2O_IOP_STATUS_PROD_ID_STR_SZ		24
#define	I2O_EXEC_STATUS_GET_REPLY_RESERVED_SZ	6

/* ExecStatusGet reply Structure */

#define	I2O_IOP_CAP_CONTEXT_32_ONLY		0x00000000
#define	I2O_IOP_CAP_CONTEXT_64_ONLY		0x00000001
#define	I2O_IOP_CAP_CONTEXT_32_64_NOT_CURRENTLY	0x00000002
#define	I2O_IOP_CAP_CONTEXT_32_64_CURRENTLY	0x00000003
#define	I2O_IOP_CAP_CURRENT_CONTEXT_NOT_CONFIG	0x00000000
#define	I2O_IOP_CAP_CURRENT_CONTEXT_32_ONLY	0x00000004
#define	I2O_IOP_CAP_CURRENT_CONTEXT_64_ONLY	0x00000008
#define	I2O_IOP_CAP_CURRENT_CONTEXT_32_64	0x0000000C
#define	I2O_IOP_CAP_INBOUND_PEER_SUPPORT	0x00000010
#define	I2O_IOP_CAP_OUTBOUND_PEER_SUPPORT	0x00000020
#define	I2O_IOP_CAP_PEER_TO_PEER_SUPPORT	0x00000040


#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_status_get_reply {
	uint16_t		OrganizationID;
	uint16_t		reserved;
	union {
	    struct {
		uint16_t	IOP_ID:12;
		uint16_t	reserved1:4;
	    } s2;
	    uint16_t		h1;
	} u2;
	uint16_t		HostUnitID;
	union {
	    struct {
		uint16_t	SegmentNumber:12;
		uint16_t	I2oVersion:4;
	    } s3;
	    uint16_t		h1;
	} u3;
	uint8_t			IopState;
	uint8_t			MessengerType;
	uint16_t		InboundMFrameSize;
	uint8_t			InitCode;
	uint8_t			reserved2;
	uint32_t		MaxInboundMFrames;
	uint32_t		CurrentInboundMFrames;
	uint32_t		MaxOutboundMFrames;
	uint8_t			ProductIDString[I2O_IOP_STATUS_PROD_ID_STR_SZ];
	uint32_t		ExpectedLCTSize;
	uint32_t		IopCapabilities;
	uint32_t		DesiredPrivateMemSize;
	uint32_t		CurrentPrivateMemSize;
	uint32_t		CurrentPrivateMemBase;
	uint32_t		DesiredPrivateIOSize;
	uint32_t		CurrentPrivateIOSize;
	uint32_t		CurrentPrivateIOBase;
	uint8_t			reserved3[3];
	volatile uint8_t	SyncByte;
} i2o_exec_status_get_reply_t;

#define	get_i2o_exec_status_reply_IOP_ID(p, hdl)	(p)->u2.s2.IOP_ID
#define	get_i2o_exec_status_reply_SegmentNumber(p, hdl)(p)->u3.s3.SegmentNumber
#define	get_i2o_exec_status_reply_I2oVersion(p, hdl)(p)->u3.s3.I2oVersion

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_status_get_reply {
	uint16_t		OrganizationID;
	uint16_t		reserved;
	union {
	    struct {
		uint16_t	reserved1:4;
		uint16_t	IOP_ID:12;
	    } s2;
	    uint16_t		h1;
	} u2;
	uint16_t		HostUnitID;
	union {
	    struct {
		uint16_t	I2oVersion:4;
		uint16_t	SegmentNumber:12;
	    } s3;
	    uint16_t		h1;
	} u3;
	uint8_t			IopState;
	uint8_t			MessengerType;
	uint16_t		InboundMFrameSize;
	uint8_t			InitCode;
	uint8_t			reserved2;
	uint32_t		MaxInboundMFrames;
	uint32_t		CurrentInboundMFrames;
	uint32_t		MaxOutboundMFrames;
	uint8_t			ProductIDString[I2O_IOP_STATUS_PROD_ID_STR_SZ];
	uint32_t		ExpectedLCTSize;
	uint32_t		IopCapabilities;
	uint32_t		DesiredPrivateMemSize;
	uint32_t		CurrentPrivateMemSize;
	uint32_t		CurrentPrivateMemBase;
	uint32_t		DesiredPrivateIOSize;
	uint32_t		CurrentPrivateIOSize;
	uint32_t		CurrentPrivateIOBase;
	uint8_t			reserved3[3];
	uint8_t		SyncByte;
} i2o_exec_status_get_reply_t;

#define	get_i2o_exec_status_reply_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u2.h1) & 0xFFF)

#define	get_i2o_exec_status_reply_I2oVersion(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) >> 4)
#define	get_i2o_exec_staus_reply_SegmentNumber(p, hdl) \
	(ddi_get16(hdl, &(p)->u3.h1) & 0xFFF)

#endif


#define	I2O_EXEC_SW_DOWNLOAD_FLAG_LOAD_MEMORY		0x00
#define	I2O_EXEC_SW_DOWNLOAD_FLAG_PERMANENT_STORE	0x01
#define	I2O_EXEC_SW_DOWNLOAD_FLAG_EXPERIMENTAL		0x00
#define	I2O_EXEC_SW_DOWNLOAD_FLAG_OVERRIDE		0x02

#define	I2O_EXEC_SW_TYPE_DDM				0x01
#define	I2O_EXEC_SW_TYPE_DDM_MPB			0x02
#define	I2O_EXEC_SW_TYPE_DDM_CONFIG_TABLE		0x03
#define	I2O_EXEC_SW_TYPE_IRTOS				0x11
#define	I2O_EXEC_SW_TYPE_IRTOS_PRIVATE_MODULE		0x12
#define	I2O_EXEC_SW_TYPE_IRTOS_DIALOG_TABLE		0x13
#define	I2O_EXEC_SW_TYPE_IOP_PRIVATE_MODULE		0x22
#define	I2O_EXEC_SW_TYPE_IOP_DIALOG_TABLE		0x23


/* I2O ExecSwDownload/Upload/Remove SwID Structure */

typedef struct i2o_sw_id {
	uint16_t	ModuleID;
	uint16_t	OrganizationID;
} i2o_sw_id_t;


/* ExecSwDownload Function Message Frame structure. */

typedef struct i2o_exec_sw_donwload_message {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint8_t			CurrentFragment;
	uint8_t			TotalFragments;
	uint8_t			SwType;
	uint8_t			DownloadFlags;
	uint32_t		SWSize;
	i2o_sw_id_t		SwID;
	i2o_sg_element_t	SGL;
} i2o_exec_sw_download_message_t;




/* ExecSwUpload Function Message Frame structure. */

typedef struct i2o_exec_sw_upload_message {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint8_t			CurrentFragment;
	uint8_t			TotalFragments;
	uint8_t			SwType;
	uint8_t			UploadFlags;
	uint32_t		SWSize;
	i2o_sw_id_t		SwID;
	i2o_sg_element_t	SGL;
} i2o_exec_sw_upload_message_t;


/* ExecSwRemove Function Message Frame structure. */

typedef struct i2o_exec_sw_remove_message {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint16_t		reserved;
	uint8_t			SwType;
	uint8_t			RemoveFlags;
	uint32_t		SWSize;
    i2o_sw_id_t			SwID;
} i2o_exec_sw_remove_message_t;


/* ExecSysEnable Function Message Frame structure. */

typedef struct i2o_exec_sys_enable_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_exec_sys_enable_message_t;


/* ExecSysModify Function Message Frame structure. */

typedef struct i2o_exec_sys_modify_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_sg_element_t		SGL;
} i2o_exec_sys_modify_message_t;


/* ExecSysQuiesce Function Message Frame structure. */

typedef struct i2o_exec_sys_quiesce_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_exec_sys_quiesce_message_t;


/* ExecSysTabSet (System Table) Function Message Frame structure. */

#define	I2O_EXEC_SYS_TAB_IOP_ID_LOCAL_IOP		0x000
#define	I2O_EXEC_SYS_TAB_IOP_ID_LOCAL_HOST		0x001
#define	I2O_EXEC_SYS_TAB_IOP_ID_UNKNOWN_IOP		0xFFF
#define	I2O_EXEC_SYS_TAB_HOST_UNIT_ID_LOCAL_UNIT	0x0000
#define	I2O_EXEC_SYS_TAB_HOST_UNIT_ID_UNKNOWN_UNIT	0xffff
#define	I2O_EXEC_SYS_TAB_SEG_NUMBER_LOCAL_SEGMENT	0x000
#define	I2O_EXEC_SYS_TAB_SEG_NUMBER_UNKNOWN_SEGMENT	0xfff


#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_exec_sys_tab_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		IOP_ID:12;
		uint16_t		reserved:4;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
	union {
	    struct {
		uint32_t		SegmentNumber:12;
		uint32_t		reserved1:20;
	    } s3;
	    uint32_t			w3;
	} u3;
	i2o_sg_element_t		SGL;
} i2o_exec_sys_tab_set_message_t;

/* macros to access the bit fields in exec ddm enable message structure */

#define	get_i2o_exec_sys_tab_set_IOP_ID(mp, hdl) \
			(mp)->u2.s2.IOP_ID
#define	put_i2o_exec_sys_tab_set_IOP_ID(mp, id, hdl) \
			((mp)->u2.s2.IOP_ID = (id))

#define	get_i2o_exec_sys_tab_set_SegmentNumber(mp, hdl) \
			(mp)->u3.s3.SegmentNumber
#define	put_i2o_exec_sys_tab_set_SegmentNumber(mp, id, hdl) \
			((mp)->u3.s3.SegmentNumber = (id))
#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_exec_sys_tab_set_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	union {
	    struct {
		uint16_t		reserved:4;
		uint16_t		IOP_ID:12;
	    } s2;
	    uint16_t			h1;
	} u2;
	uint16_t			HostUnitID;
	union {
	    struct {
		uint32_t		reserved1:20;
		uint32_t		SegmentNumnber:12;
	    } s3;
	    uint32_t			w3;
	} u3;
	i2o_sg_element_t		SGL;
} i2o_exec_sys_tab_set_message_t;

/* macros to access the bit fields in exec ddm enable message structure */

#define	get_i2o_exec_sys_tab_set_IOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u2.h1) & 0xFFF)

#define	put_i2o_exec_sys_tab_set_IOP_ID(mp, id, hdl) \
	ddi_put16(hdl, &(mp)->u2.h1, \
		(ddi_get16(hdl, &(mp)->u2.h1) & ~0xFFF) | ((id) & 0xFFF))

#define	get_i2o_exec_sys_tab_set_SegmentNumber(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u3.w3) & 0xFFF)
#define	put_i2o_exec_sys_tab_set_SegmentNumber(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u3.w3, \
		(ddi_get32(hdl, &(mp)->u3.w3) & ~0xFFF) | ((id) & 0xFFF))

#endif


/* ExecSysTabSet (System Table) Header Reply structure. */

#define	I2O_SET_SYSTAB_RESERVED_SZ	8

typedef struct i2o_set_systab_header {
	uint8_t		NumberEntries;
	uint8_t		SysTabVersion;
	uint16_t	reserved;
	uint32_t	CurrentChangeIndicator;
	uint8_t		reserved1[I2O_SET_SYSTAB_RESERVED_SZ];
/*    I2O_SYSTAB_ENTRY    SysTabEntry[1]; */
} i2o_set_systab_header_t;


#define	I2O_RESOURCE_MANAGER_VERSION	0

typedef struct i2o_messenger_info {
	uint32_t	InboundMessagePortAddressLow;
	uint32_t	InboundMessagePortAddressHigh;
} i2o_messenger_info_t;

/* ExecSysTabSet IOP Descriptor Entry structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_iop_entry {
	uint16_t		OrganizationID;
	uint16_t		reserved;
	union {
	    struct {
		uint32_t	IOP_ID:12;
		uint32_t	reserved1:20;
	    } s2;
	    uint32_t		w2;
	} u2;
	union {
	    struct {
		uint16_t	SegmentNumber:12;
		uint16_t	I2oVersion:4;
	    } s3;
	    uint16_t		h1;
	} u3;
	uint8_t			IopState;
	uint8_t			MessengerType;
	uint16_t		InboundMessageFrameSize;
	uint16_t		reserved2;
	uint32_t		LastChanged;
	uint32_t		IopCapabilities;
    i2o_messenger_info_t	MessengerInfo;
} i2o_iop_entry_t;


#define	get_i2o_iop_entry_IOP_ID(mp, hdl) \
	((mp)->u2.s2.IOP_ID)

#define	put_i2o_iop_entry_IOP_ID(mp, v, hdl) \
	((mp)->u2.s2.IOP_ID) = (v)

#define	get_i2o_iop_entry_SegmentNumber(mp, hdl) \
	((mp)->u3.s3.SegmentNumber)

#define	put_i2o_iop_entry_SegmentNumber(mp, v, hdl) \
	((mp)->u3.s3.SegmentNumber) = (v)

#define	get_i2o_iop_entry_I2oVersion(mp, hdl) \
	((mp)->u3.s3.I2oVersion)

#define	put_i2o_iop_entry_I2oVersion(mp, v, hdl) \
	((mp)->u3.s3.I2oVersion) = (v)

#endif


#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_iop_entry {
	uint16_t		OrganizationID;
	uint16_t		reserved;
	union {
	    struct {
		uint32_t	reserved1:20;
		uint32_t	IOP_ID:12;
	    } s2;
	    uint32_t		w2;
	} u2;
	union {
	    struct {
		uint16_t	I2oVersion:4;
		uint16_t	SegmentNumber:12;
	    } s3;
	    uint16_t		h1;
	} u3;
	uint8_t			IopState;
	uint8_t			MessengerType;
	uint16_t		InboundMessageFrameSize;
	uint16_t		reserved2;
	uint32_t		LastChanged;
	uint32_t		IopCapabilities;
    i2o_messenger_info_t	MessengerInfo;
} i2o_iop_entry_t;


#define	get_i2o_iop_entry_IOP_ID(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)

#define	put_i2o_iop_entry_IOP_ID(mp, v, hdl) \
	(ddi_put32(hdl, &(mp)->u2.w2) & 0xFFF, (v))

#define	get_i2o_iop_entry_SegmentNumber(mp, hdl) \
	(ddi_get16(hdl, &(mp)->u3.h1) & 0xFFF)

#define	put_i2o_iop_entry_SegmentNumber(mp, v, hdl) \
	(ddi_put16(hdl, &(mp)->u3.h1) & 0xFFF, (v))

#define	get_i2o_iop_entry_I2oVersion(mp, hdl) \
	((ddi_get16(hdl, &(mp)->u3.h1) >> 12) & 0xF)

#define	put_i2o_iop_entry_I2oVersion(mp, v, hdl) \
	((ddi_put16(hdl, &(mp)->u3.h1) >> 12) & 0xF, (v))

#endif


/* ************************************************************************** */
/* Executive Parameter Groups */
/* ************************************************************************** */


#define	I2O_EXEC_IOP_HARDWARE_GROUP_NO			0x0000
#define	I2O_EXEC_IOP_MESSAGE_IF_GROUP_NO		0x0001
#define	I2O_EXEC_EXECUTING_ENVIRONMENT_GROUP_NO		0x0002
#define	I2O_EXEC_EXECUTING_DDM_LIST_GROUP_NO		0x0003
#define	I2O_EXEC_DRIVER_STORE_GROUP_NO			0x0004
#define	I2O_EXEC_DRIVER_STORE_TABLE_GROUP_NO		0x0005
#define	I2O_EXEC_IOP_BUS_ATTRIBUTES_GROUP_NO		0x0006
#define	I2O_EXEC_IOP_SW_ATTRIBUTES_GROUP_NO		0x0007
#define	I2O_EXEC_HARDWARE_RESOURCE_TABLE_GROUP_NO	0x0100
#define	I2O_EXEC_LCT_SCALAR_GROUP_NO			0x0101
#define	I2O_EXEC_LCT_TABLE_GROUP_NO			0x0102
#define	I2O_EXEC_SYSTEM_TABLE_GROUP_NO			0x0103
#define	I2O_EXEC_EXTERNAL_CONN_TABLE_GROUP_NO		0x0104


/* EXEC Group 0000h - IOP Hardware Parameter Group */

/* IOP HardWare Capabilities defines */

#define	I2O_IOP_HW_CAP_SELF_BOOT			0x00000001
#define	I2O_IOP_HW_CAP_IRTOS_UPGRADEABLE		0x00000002
#define	I2O_IOP_HW_CAP_DOWNLOADABLE_DDM			0x00000004
#define	I2O_IOP_HW_CAP_INSTALLABLE_DDM			0x00000008
#define	I2O_IOP_HW_CAP_BATTERY_BACKUP_RAM		0x00000010

/* IOP Processor Type defines */

#define	I2O_IOP_PROC_TYPE_INTEL_80960			0x00
#define	I2O_IOP_PROC_TYPE_AMD_29000			0x01
#define	I2O_IOP_PROC_TYPE_MOTOROLA_68000		0x02
#define	I2O_IOP_PROC_TYPE_ARM				0x03
#define	I2O_IOP_PROC_TYPE_MIPS				0x04
#define	I2O_IOP_PROC_TYPE_SPARC				0x05
#define	I2O_IOP_PROC_TYPE_POWER_PC			0x06
#define	I2O_IOP_PROC_TYPE_ALPHA				0x07
#define	I2O_IOP_PROC_TYPE_INTEL_X86			0x08
#define	I2O_IOP_PROC_TYPE_OTHER				0xFF


typedef struct i2o_exec_iop_hardware_scalar {
	uint16_t		I2oVendorID;
	uint16_t		ProductID;
	uint32_t		ProcessorMemory;
	uint32_t		PermMemory;
	uint32_t		HWCapabilities;
	uint8_t			ProcessorType;
	uint8_t			ProcessorVersion;
} i2o_exec_iop_hardware_scalar_t;


/* EXEC Group 0001h - IOP Message Interface Parameter Group */

/* InitCode defines */
#define	I2O_MESSAGE_IF_INIT_CODE_NO_OWNER		0x00
#define	I2O_MESSAGE_IF_INIT_CODE_BIOS			0x10
#define	I2O_MESSAGE_IF_INIT_CODE_OEM_BIOS_EXTENSION	0x20
#define	I2O_MESSAGE_IF_INIT_CODE_ROM_BIOS_EXTENSION	0x30
#define	I2O_MESSAGE_IF_INIT_CODE_OS			0x80

typedef struct i2o_exec_iop_message_if_scalar {
	uint32_t		InboundFrameSize;
	uint32_t		InboundSizeTarget;
	uint32_t		InboundMax;
	uint32_t		InboundTarget;
	uint32_t		InboundPoolCount;
	uint32_t		InboundCurrentFree;
	uint32_t		InboundCurrentPost;
	uint16_t		StaticCount;
	uint16_t		StaticInstanceCount;
	uint16_t		StaticLimit;
	uint16_t		StaticInstanceLimit;
	uint32_t		OutboundFrameSize;
	uint32_t		OutboundMax;
	uint32_t		OutboundMaxTarget;
	uint32_t		OutboundCurrentFree;
	uint32_t		OutboundCurrentPost;
	uint8_t			InitCode;
} i2o_exec_iop_message_if_scalar_t;


/* EXEC Group 0002h - Executing Environment Parameter Group */

typedef struct i2o_exec_execute_environment_scalar {
	uint32_t		MemTotal;
	uint32_t		MemFree;
	uint32_t		PageSize;
	uint32_t		EventQMax;
	uint32_t		EventQCurrent;
	uint32_t		DDMLoadMax;
} i2o_exec_execute_environment_scalar_t;


/* EXEC Group 0003h - Executing DDM's Parameter Group */

/* ModuleType Defines */

#define	I2O_EXEC_DDM_MODULE_TYPE_OTHER		0x00
#define	I2O_EXEC_DDM_MODULE_TYPE_DOWNLOAD	0x01
#define	I2O_EXEC_DDM_MODULE_TYPE_EMBEDDED	0x22


typedef struct i2o_exec_execute_ddm_table {
	uint16_t		DdmTID;
	uint8_t			ModuleType;
	uint8_t			reserved;
	uint16_t		I2oVendorID;
	uint16_t		ModuleID;
	uint8_t			ModuleName[I2O_MODULE_NAME_SZ];
	uint32_t		ModuleVersion;
	uint32_t		DataSize;
	uint32_t		CodeSize;
} i2o_exec_execute_ddm_table_t;


/* EXEC Group 0004h - Driver Store Environment Parameter Group */


typedef struct i2o_exec_driver_store_scalar {
	uint32_t		ModuleLimit;
	uint32_t		ModuleCount;
	uint32_t		CurrentSpace;
	uint32_t		FreeSpace;
} i2o_exec_driver_store_scalar_t;


/* EXEC Group 0005h - Driver Store Parameter Group */


typedef struct i2o_exec_driver_store_table {
	uint16_t		StoredDdmIndex;
	uint8_t			ModuleType;
	uint8_t			reserved;
	uint16_t		I2oVendorID;
	uint16_t		ModuleID;
	uint8_t			ModuleName[I2O_MODULE_NAME_SZ];
	uint32_t		ModuleVersion;
	uint16_t		DateDay;
	uint16_t		DateMonth;
	uint32_t		DateYear;
	uint32_t		ModuleSize;
	uint32_t		MpbSize;
	uint32_t		ModuleFlags;
} i2o_exec_driver_store_table_t;


/* EXEC Group 0006h - IOP's Bus Attributes Parameter Group */

#define	I2O_EXEC_IOP_BUS_ATTRIB_SYSTEM_BUS		0x00
#define	I2O_EXEC_IOP_BUS_ATTRIB_BRIDGED_SYSTEM_BUS	0x01
#define	I2O_EXEC_IOP_BUS_ATTRIB_PRIVATE			0x02

typedef struct i2o_exec_iop_bus_attribute_table {
	uint32_t		BusID;
	uint8_t			BusType;
	uint8_t			MaxAdapters;
	uint8_t			AdapterCount;
	uint8_t			BusAttributes;
} i2o_exec_iop_bus_attribute_table_t;


/* EXEC Group 0007h - IOP's Bus Attributes Parameter Group */

#define	I2O_EXEC_IOP_SW_CAP_IRTOS_I2O_COMPLIANT		0x00000001
#define	I2O_EXEC_IOP_SW_CAP_IRTOS_UPGRADEABLE		0x00000002
#define	I2O_EXEC_IOP_SW_CAP_DOWNLOADABLE_DDM		0x00000004
#define	I2O_EXEC_IOP_SW_CAP_INSTALLABLE_DDM		0x00000008

typedef struct i2o_exec_iop_sw_attributes_scalar {
	uint16_t		I2oVendorID;
	uint16_t		ProductID;
	uint32_t		CodeSize;
	uint32_t		SWCapabilities;
} i2o_exec_iop_sw_attributes_scalar_t;


/* EXEC Group 0100h - Hardware Resource Table Parameter Group */

typedef struct i2o_exec_hardware_resource_table {
	uint32_t		AdapterID;
	uint16_t		StateInfo; /* AdapterState plus Local TID */
	uint8_t			BusNumber;
	uint8_t			BusType;
	u_longlong_t		PhysicalLocation;
	uint32_t		MemorySpace;
	uint32_t		IoSpace;
} i2o_exec_hardware_resource_table_t;

/* EXEC Group 0101h - Logical Configuration Table Scalar Parameter Group */

typedef struct i2o_exec_lct_scalar {
	uint16_t		BootDevice;
	uint32_t		IopFlags;
	uint32_t		CurrentChangeIndicator;
} i2o_exec_lct_scalar_t;

/* EXEC Group 0102h - Logical Configuration Table Parameter Group */

typedef struct i2o_exec_lct_table {
	uint16_t		LocalTID;
	uint16_t		UserTID;
	uint16_t		ParentTID;
	uint16_t		DdmTID;
	uint32_t		ChangeIndicator;
	uint32_t		DeviceFlags;
	uint32_t		ClassID;
	uint32_t		SubClass;
	uint8_t			IdentityTag[I2O_IDENTITY_TAG_SZ];
	uint32_t		EventCapabilities;
	uint8_t			BiosInfo;
} i2o_exec_lct_table_t;

/* EXEC Group 0103h - System Table Parameter Group */

#define	I2O_MESSENGER_TYPE_MEMORY_MAPPED_MESSAGE_UNIT	0x0

typedef struct i2o_exec_system_table {
	uint16_t		IOP_ID;
	uint16_t		OrganizationID;
	uint16_t		SegmentNumber;
	uint8_t			Version;
	uint8_t			IopState;
	uint8_t			MessengerType;
	uint8_t			reserved;
	uint32_t		InboundMessagePortAddress;
	uint16_t		InboundMessageFrameSize;
	uint32_t		IopCapabilities;
    i2o_messenger_info_t	MessengerInfo;
} i2o_exec_system_table_t;


/* EXEC Group 0104h - External Connection Table Parameter Group */

#define	I2O_EXEC_XCT_FLAGS_REMOTE_IOP_CREATED_CONNECTION	0x00
#define	I2O_EXEC_XCT_FLAGS_THIS_IOP_CREATED_CONNECTION		0x01

typedef struct i2o_exec_external_connection_table {
	uint16_t		LocalAliasTID;
	uint16_t		RemoteTID;
	uint16_t		RemoteIOP;
	uint16_t		RemoteUnitID;
	uint8_t			Flags;
	uint8_t			reserved;
} i2o_exec_external_connection_table_t;


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_I2OEXEC_H */
