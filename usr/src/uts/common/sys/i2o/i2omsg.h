/*
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * *************************************************************************
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
 * *************************************************************************
 */

/*
 * *************************************************************************
 * i2omsg.h -- I2O Message defintion file
 *
 * This file contains information presented in Chapter 3, 4 and 6 of
 * the I2O(tm) Specification and most of the I2O Global defines and
 * Typedefs.
 * *************************************************************************
 */

#ifndef _SYS_I2OMSG_H
#define	_SYS_I2OMSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	I2OMSG_REV 1_5_4 /* I2OMsg header file revision string */

/*
 * *************************************************************************
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
 * *************************************************************************
 */

#include <sys/types.h>
#include <sys/dditypes.h>

/* Set to 1 for 64 bit Context Fields */
#define	I2O_64BIT_CONTEXT	0

/* ************************************************************************** */

/* Common functions accross all classes. */

#define	I2O_PRIVATE_MESSAGE			0xFF

/* ************************************************************************** */
/* Class ID and Code Assignments */


#define	I2O_CLASS_VERSION_10			0x00
#define	I2O_CLASS_VERSION_11			0x01

/* Class Code Names: Table 6-1 Class Code Assignments. */

#define	I2O_CLASS_EXECUTIVE			0x000
#define	I2O_CLASS_DDM				0x001
#define	I2O_CLASS_RANDOM_BLOCK_STORAGE		0x010
#define	I2O_CLASS_SEQUENTIAL_STORAGE		0x011
#define	I2O_CLASS_LAN				0x020
#define	I2O_CLASS_WAN				0x030
#define	I2O_CLASS_FIBRE_CHANNEL_PORT		0x040
#define	I2O_CLASS_FIBRE_CHANNEL_PERIPHERAL	0x041
#define	I2O_CLASS_SCSI_PERIPHERAL		0x051
#define	I2O_CLASS_ATE_PORT			0x060
#define	I2O_CLASS_ATE_PERIPHERAL		0x061
#define	I2O_CLASS_FLOPPY_CONTROLLER		0x070
#define	I2O_CLASS_FLOPPY_DEVICE			0x071
#define	I2O_CLASS_BUS_ADAPTER_PORT		0x080
/* Class Codes 0x090 - 0x09f are reserved for Peer-to-Peer classes */
#define	I2O_CLASS_MATCH_ANYCLASS		0xffffffff

#define	I2O_SUBCLASS_i960			0x001
#define	I2O_SUBCLASS_HDM			0x020
#define	I2O_SUBCLASS_ISM			0x021

/* ************************************************************************** */
/* Message Frame defines and structures */

/* Defines for the Version_Status field. */

#define	I2O_VERSION_10				0x00
#define	I2O_VERSION_11				0x01

#define	I2O_VERSION_OFFSET_NUMBER_MASK		0x07
#define	I2O_VERSION_OFFSET_SGL_TRL_OFFSET_MASK	0xF0

/*
 * Defines for the Message Flags Field.
 * Please Note that the FAIL bit is only set in the Transport Fail Message.
 */
#define	I2O_MESSAGE_FLAGS_STATIC		0x01
#define	I2O_MESSAGE_FLAGS_64BIT_CONTEXT		0x02
#define	I2O_MESSAGE_FLAGS_MULTIPLE		0x10
#define	I2O_MESSAGE_FLAGS_FAIL			0x20
#define	I2O_MESSAGE_FLAGS_LAST			0x40
#define	I2O_MESSAGE_FLAGS_REPLY			0x80

/* Defines for Request Status Codes: Table 3-1 Reply Status Codes. */

#define	I2O_REPLY_STATUS_SUCCESS		0x00
#define	I2O_REPLY_STATUS_ABORT_DIRTY		0x01
#define	I2O_REPLY_STATUS_ABORT_NO_DATA_TRANSFER	0x02
#define	I2O_REPLY_STATUS_ABORT_PARTIAL_TRANSFER	0x03
#define	I2O_REPLY_STATUS_ERROR_DIRTY		0x04
#define	I2O_REPLY_STATUS_ERROR_NO_DATA_TRANSFER	0x05
#define	I2O_REPLY_STATUS_ERROR_PARTIAL_TRANSFER	0x06
#define	I2O_REPLY_STATUS_PROCESS_ABORT_DIRTY	0x08
#define	I2O_REPLY_STATUS_PROCESS_ABORT_NO_DATA_TRANSFER	0x09
#define	I2O_REPLY_STATUS_PROCESS_ABORT_PARTIAL_TRANSFER	0x0A
#define	I2O_REPLY_STATUS_TRANSACTION_ERROR	0x0B
#define	I2O_REPLY_STATUS_PROGRESS_REPORT	0x80

/*
 * DetailedStatusCode defines for ALL messages: Table 3-2 Detailed Status Codes.
 */

#define	I2O_DETAIL_STATUS_SUCCESS			0x0000
#define	I2O_DETAIL_STATUS_BAD_KEY			0x0002
#define	I2O_DETAIL_STATUS_TCL_ERROR			0x0003
#define	I2O_DETAIL_STATUS_REPLY_BUFFER_FULL		0x0004
#define	I2O_DETAIL_STATUS_NO_SUCH_PAGE			0x0005
#define	I2O_DETAIL_STATUS_INSUFFICIENT_RESOURCE_SOFT	0x0006
#define	I2O_DETAIL_STATUS_INSUFFICIENT_RESOURCE_HARD	0x0007
#define	I2O_DETAIL_STATUS_CHAIN_BUFFER_TOO_LARGE	0x0009
#define	I2O_DETAIL_STATUS_UNSUPPORTED_FUNCTION		0x000A
#define	I2O_DETAIL_STATUS_DEVICE_LOCKED			0x000B
#define	I2O_DETAIL_STATUS_DEVICE_RESET			0x000C
#define	I2O_DETAIL_STATUS_INAPPROPRIATE_FUNCTION	0x000D
#define	I2O_DETAIL_STATUS_INVALID_INITIATOR_ADDRESS	0x000E
#define	I2O_DETAIL_STATUS_INVALID_MESSAGE_FLAGS		0x000F
#define	I2O_DETAIL_STATUS_INVALID_OFFSET		0x0010
#define	I2O_DETAIL_STATUS_INVALID_PARAMETER		0x0011
#define	I2O_DETAIL_STATUS_INVALID_REQUEST		0x0012
#define	I2O_DETAIL_STATUS_INVALID_TARGET_ADDRESS	0x0013
#define	I2O_DETAIL_STATUS_MESSAGE_TOO_LARGE		0x0014
#define	I2O_DETAIL_STATUS_MESSAGE_TOO_SMALL		0x0015
#define	I2O_DETAIL_STATUS_MISSING_PARAMETER		0x0016
#define	I2O_DETAIL_STATUS_TIMEOUT			0x0017
#define	I2O_DETAIL_STATUS_UNKNOWN_ERROR			0x0018
#define	I2O_DETAIL_STATUS_UNKNOWN_FUNCTION		0x0019
#define	I2O_DETAIL_STATUS_UNSUPPORTED_VERSION		0x001A
#define	I2O_DEATIL_STATUS_DEVICE_BUSY			0x001B
#define	I2O_DETAIL_STATUS_DEVICE_NOT_AVAILABLE		0x001C

/* Common I2O Field sizes */

#define	I2O_TID_SZ			12
#define	I2O_FUNCTION_SZ			8
#define	I2O_UNIT_ID_SZ			16
#define	I2O_SEGMENT_NUMBER_SZ		12

#define	I2O_IOP_ID_SZ			12
#define	I2O_GROUP_ID_SZ			16
#define	I2O_IOP_STATE_SZ		8
#define	I2O_MESSENGER_TYPE_SZ		8

#define	I2O_CLASS_ID_SZ			12
#define	I2O_CLASS_ORGANIZATION_ID_SZ	16

#define	I2O_4BIT_VERSION_SZ		4
#define	I2O_8BIT_FLAGS_SZ		8
#define	I2O_COMMON_LENGTH_FIELD_SZ	16

#define	I2O_DEVID_DESCRIPTION_SZ	16
#define	I2O_DEVID_VENDOR_INFO_SZ	16
#define	I2O_DEVID_PRODUCT_INFO_SZ	16
#define	I2O_DEVID_REV_LEVEL_SZ		8
#define	I2O_MODULE_NAME_SZ		24

#define	I2O_BIOS_INFO_SZ		8

#define	I2O_RESERVED_4BITS		4
#define	I2O_RESERVED_8BITS		8
#define	I2O_RESERVED_12BITS		12
#define	I2O_RESERVED_16BITS		16
#define	I2O_RESERVED_20BITS		20
#define	I2O_RESERVED_24BITS		24
#define	I2O_RESERVED_28BITS		28

typedef uint32_t	I2O_PARAMETER_TID;

#if  I2O_64BIT_CONTEXT

typedef union {
	void		(* i2o_msg_complete)(void *, ddi_acc_handle_t);
	uint64_t	initiator_context_64bits;
} i2o_initiator_context_t;

typedef uint64_t	 i2o_transaction_context_t;

#else

typedef union {
	void		(* i2o_msg_complete)(void *, ddi_acc_handle_t);
	uint32_t	initiator_context_32bits;
} i2o_initiator_context_t;

typedef uint32_t i2o_transaction_context_t;

#endif

/* Serial Number format defines */

#define	I2O_SERIAL_FORMAT_UNKNOWN	0
#define	I2O_SERIAL_FORMAT_BINARY	1
#define	I2O_SERIAL_FORMAT_ASCII		2
#define	I2O_SERIAL_FORMAT_UNICODE	3
#define	I2O_SERIAL_FORMAT_LAN_MAC	4
#define	I2O_SERIAL_FORMAT_WAN		5

/* Special TID Assignments */

#define	I2O_IOP_TID			0
#define	I2O_HOST_TID			1


/* ************************************************************************** */

/* I2O Message Frame common for all messages */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_message_frame {
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
	i2o_initiator_context_t  InitiatorContext;
} i2o_message_frame_t;

/* macros to access the bit fields in Message Frame */

#define	get_msg_TargetAddress(mp, hdl) \
			(mp)->u2.s2.TargetAddress
#define	put_msg_TargetAddress(mp, id, hdl) \
			((mp)->u2.s2.TargetAddress = (id))
#define	get_msg_InitiatorAddress(mp, hdl) \
			(mp)->u2.s2.InitiatorAddress
#define	put_msg_InitiatorAddress(mp, id, hdl) \
			((mp)->u2.s2.InitiatorAddress = (id))
#define	get_msg_Function(mp, hdl) \
			(mp)->u2.s2.Function
#define	put_msg_Function(mp, n, hdl) \
			((mp)->u2.s2.Function = (n))
#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_message_frame {
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
	i2o_initiator_context_t  InitiatorContext;
} i2o_message_frame_t;

/* macros to access the bit fields in Message Frame */

#define	get_msg_Function(mp, hdl) \
	(mp)->u2.s2.Function
#define	put_msg_Function(mp, n, hdl) \
	((mp)->u2.s2.Function = (n))

#define	get_msg_TargetAddress(mp, hdl) \
	(ddi_get32(hdl, &(mp)->u2.w2) & 0xFFF)
#define	put_msg_TargetAddress(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, \
		(ddi_get32(hdl, &(mp)->u2.w2) & ~0xFFF) | ((id) & 0xFFF))

#define	get_msg_InitiatorAddress(mp, hdl) \
	((ddi_get32(hdl, &(mp)->u2.w2) >> 12) & 0xFFF)
#define	put_msg_InitiatorAddress(mp, id, hdl) \
	ddi_put32(hdl, &(mp)->u2.w2, (ddi_get32(hdl, &(mp)->u2.w2) & \
			~0xFFF000) | (((id) & 0xFFF) << 12))
#endif


/* ************************************************************************** */

/* Transaction Reply Lists (TRL) Control Word structure */

#define	I2O_TRL_FLAGS_SINGLE_FIXED_LENGTH	0x00
#define	I2O_TRL_FLAGS_SINGLE_VARIABLE_LENGTH	0x40
#define	I2O_TRL_FLAGS_MULTIPLE_FIXED_LENGTH	0x80

typedef struct i2o_trl_control_word {
	uint8_t			TrlCount;
	uint8_t			TrlElementSize;
	uint8_t			reserved;
	uint8_t			TrlFlags;
#if  I2O_64BIT_CONTEXT
	uint32_t		Padding;	 /* Padding for 64 bit */
#endif
} i2o_trl_control_word_t;

/* ************************************************************************** */

/* I2O Successful Single Transaction Reply Message Frame structure. */

typedef struct i2o_single_reply_message_frame {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint16_t		DetailedStatusCode;
	uint8_t			reserved;
	uint8_t			ReqStatus;
	/*			ReplyPayload	*/
} i2o_single_reply_message_frame_t;

/* ************************************************************************** */

/* I2O Successful Multiple Transaction Reply Message Frame structure. */

typedef struct i2o_multiple_reply_message_frame {
	i2o_message_frame_t	StdMessageFrame;
	i2o_trl_control_word_t	TrlControlWord;
	uint16_t		DetailedStatusCode;
	uint8_t			reserved;
	uint8_t			ReqStatus;
	/*			TransactionDetails[]	*/
} i2o_multiple_reply_message_frame_t;

/* ************************************************************************** */

/* I2O Private Message Frame structure. */

typedef struct i2o_private_message_frame {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint16_t		XFunctionCode;
	uint16_t		OrganizationID;
	/*			PrivatePayload[]	*/
} i2o_private_message_frame_t;

/* ************************************************************************** */

/* Message Failure Severity Codes */

#define	I2O_SEVERITY_FORMAT_ERROR	0x1
#define	I2O_SEVERITY_PATH_ERROR		0x2
#define	I2O_SEVERITY_PATH_STATE		0x4
#define	I2O_SEVERITY_CONGESTION		0x8

/* Transport Failure Codes: Table 3-3 Mesasge Failure Codes */

#define	I2O_FAILURE_CODE_TRANSPORT_SERVICE_SUSPENDED		0x81
#define	I2O_FAILURE_CODE_TRANSPORT_SERVICE_TERMINATED		0x82
#define	I2O_FAILURE_CODE_TRANSPORT_CONGESTION			0x83
#define	I2O_FAILURE_CODE_TRANSPORT_FAIL				0x84
#define	I2O_FAILURE_CODE_TRANSPORT_STATE_ERROR			0x85
#define	I2O_FAILURE_CODE_TRANSPORT_TIME_OUT			0x86
#define	I2O_FAILURE_CODE_TRANSPORT_ROUTING_FAILURE  		0x87
#define	I2O_FAILURE_CODE_TRANSPORT_INVALID_VERSION  		0x88
#define	I2O_FAILURE_CODE_TRANSPORT_INVALID_OFFSET  		0x89
#define	I2O_FAILURE_CODE_TRANSPORT_INVALID_MSG_FLAGS 		0x8A
#define	I2O_FAILURE_CODE_TRANSPORT_FRAME_TOO_SMALL  		0x8B
#define	I2O_FAILURE_CODE_TRANSPORT_FRAME_TOO_LARGE  		0x8C
#define	I2O_FAILURE_CODE_TRANSPORT_INVALID_TARGET_ID 		0x8D
#define	I2O_FAILURE_CODE_TRANSPORT_INVALID_INITIATOR_ID 	0x8E
#define	I2O_FAILURE_CODE_TRANSPORT_INVALID_INITIATOR_CONTEXT 	0x8F
#define	I2O_FAILURE_CODE_TRANSPORT_UNKNOWN_FAILURE  		0xFF

/* IOP_ID and Severity sizes */

#define	I2O_FAILCODE_SEVERITY_SZ	8
#define	I2O_FAILCODE_CODE_SZ		8

/* I2O Transport Message Reply for Message Failure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_failure_reply_message_frame {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint8_t			LowestVersion;
	uint8_t			HighestVersion;
	uint8_t			Severity;
	uint8_t			FailureCode;
	union {
	    struct {
		uint16_t	FailingIOP_ID:12;
		uint16_t	reserved:4;
	    } s;
	    uint16_t		h;
	} u1;
	uint16_t		FailingHostUnitID;
	uint32_t		AgeLimit;
	i2o_message_frame_t	*PreservedMFA;
} i2o_failure_reply_message_frame_t;

/* macros to access the bit field(s) */

#define	get_reply_msg_FailingIOP_ID(p, hdl) \
	((p)->u1.s.FailingIOP_ID)
#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_failure_reply_message_frame {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint8_t			LowestVersion;
	uint8_t			HighestVersion;
	uint8_t			Severity;
	uint8_t			FailureCode;
	union {
	    struct {
		uint16_t	reserved:4;
		uint16_t	FailingIOP_ID:12;
	    } s;
	    uint16_t		h;
	} u1;
	uint16_t		FailingHostUnitID;
	uint32_t		AgeLimit;
	i2o_message_frame_t	*PreservedMFA;
} i2o_failure_reply_message_frame_t;

/* macros to access the bit field(s) */

#define	get_reply_msg_FailingIOP_ID(p, hdl) \
	(ddi_get16(hdl, &(p)->u1.h) & 0xFFF)
#endif

/* I2O Transport Message Reply for Transaction Error. */

typedef struct i2o_transaction_error_reply_message_frame {
	i2o_message_frame_t	StdMessageFrame;
	i2o_transaction_context_t TransactionContext;
	uint16_t		DetailedStatusCode;
	uint8_t			reserved;
	uint8_t			ReqStatus; /* Should Transaction Error */
	uint32_t		ErrorOffset;
	uint8_t			BitOffset;
	uint8_t			reserved1;
	uint16_t		reserved2;
} i2o_transaction_error_reply_message_frame_t;

/* ************************************************************************** */

/* Misc. commonly used structures */

#define	I2O_MAX_SERIAL_NUMBER_SZ		 256

typedef struct i2o_serial_info {
	uint8_t			SerialNumberLength;
	uint8_t			SerialNumberFormat;
	uint8_t			SerialNumber[I2O_MAX_SERIAL_NUMBER_SZ];
} i2o_serial_info_t;


/* ************************************************************************** */
/* Hardware Resource Table (HRT) and Logical Configuration Table (LCT) */
/* ************************************************************************** */

/* Bus Type Code defines */

#define	I2O_LOCAL_BUS			0
#define	I2O_ISA_BUS			1
#define	I2O_EISA_BUS			2
#define	I2O_PCI_BUS			4
#define	I2O_PCMCIA_BUS			5
#define	I2O_NUBUS_BUS			6
#define	I2O_CARDBUS_BUS			7
#define	I2O_OTHER_BUS			0x80

#define	I2O_HRT_STATE_SZ		4
#define	I2O_HRT_BUS_NUMBER_SZ		8
#define	I2O_HRT_BUS_TYPE_SZ		8


/* Bus Structures */

/* PCI Bus */
typedef struct i2o_pci_bus_info {
	uint8_t			PciFunctionNumber;
	uint8_t			PciDeviceNumber;
	uint8_t			PciBusNumber;
	uint8_t			reserved;
	uint16_t		PciVendorID;
	uint16_t		PciDeviceID;
} i2o_pci_bus_info_t;

/* Local Bus */
typedef struct i2o_local_bus_info {
	uint16_t		LbBaseIOPort;
	uint16_t		reserved;
	uint32_t		LbBaseMemoryAddress;
} i2o_local_bus_info_t;

/* ISA Bus */
typedef struct i2o_isa_bus_info {
	uint16_t		IsaBaseIOPort;
	uint8_t			CSN;
	uint8_t			reserved;
	uint32_t		IsaBaseMemoryAddress;
} i2o_isa_bus_info_t;

/* EISA Bus */
typedef struct i2o_eisa_bus_info {
	uint16_t		EisaBaseIOPort;
	uint8_t			reserved;
	uint8_t			EisaSlotNumber;
	uint32_t		EisaBaseMemoryAddress;
} i2o_eisa_bus_info_t;

/* Other Bus */
typedef struct i2o_other_bus_info {
	uint16_t		BaseIOPort;
	uint16_t		reserved;
	uint32_t		BaseMemoryAddress;
} i2o_other_bus_info_t;


/* HRT Entry Block */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_hrt_entry {
	uint32_t		AdapterID;
	union	{
	    struct {
		uint16_t	ControllingTID:12;
		uint16_t	AdapterState:4;
	    } s2;
	    uint16_t		h2;
	} u2;
	uint8_t			BusNumber;
	uint8_t			BusType;
	union {
	    /* PCI Bus */
	    i2o_pci_bus_info_t		PCIBus;

	    /* Local Bus */
	    i2o_local_bus_info_t	LocalBus;

	    /* ISA Bus */
	    i2o_isa_bus_info_t		ISABus;

	    /* EISA Bus */
	    i2o_eisa_bus_info_t		EISABus;

	    /* Other. */
	    i2o_other_bus_info_t	OtherBus;
	} uBus;
} i2o_hrt_entry_t;

/* macros to access the bit fields */

#define	get_hrt_entry_ControllingTID(p, hdl) (p)->u2.s2.ControllingTID
#define	get_hrt_entry_AdapterState(p, hdl) (p)->u2.s2.AdapterState

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_hrt_entry {
	uint32_t		AdapterID;
	union	{
	    struct {
		uint16_t	AdapterState:4;
		uint16_t	ControllingTID:12;
	    } s2;
	    uint16_t		h2;
	} u2;
	uint8_t			BusNumber;
	uint8_t			BusType;
	union {
	    /* PCI Bus */
	    i2o_pci_bus_info_t		PCIBus;

	    /* Local Bus */
	    i2o_local_bus_info_t	LocalBus;

	    /* ISA Bus */
	    i2o_isa_bus_info_t		ISABus;

	    /* EISA Bus */
	    i2o_eisa_bus_info_t		EISABus;

	    /* Other. */
	    i2o_other_bus_info_t	OtherBus;
	} uBus;
} i2o_hrt_entry_t;

/* macros to access the bit fields */

#define	get_hrt_entry_ControllingTID(p, hdl) \
	(ddi_get16(hdl, &(p)->u2.h2) & 0xFFF)
#define	get_hrt_entry_AdapterState(p, hdl) \
	((ddi_get16(hdl, &(p)->u2.h2) >> 12) & 0xF)
#endif

/* I2O Hardware Resource Table structure. */

typedef struct i2o_hrt {
	uint16_t		NumberEntries;
	uint8_t			EntryLength;
	uint8_t			HRTVersion;
	uint32_t		CurrentChangeIndicator;
	i2o_hrt_entry_t		HRTEntry[1];
} i2o_hrt_t;


/* ************************************************************************** */
/* Logical Configuration Table */
/* ************************************************************************** */

/* I2O Logical Configuration Table structures. */

#define	I2O_IDENTITY_TAG_SZ			8

/* I2O Logical Configuration Table Device Flags */

#define	I2O_LCT_DEVICE_FLAGS_CONF_DIALOG_REQUEST	0x01
#define	I2O_LCT_DEVICE_FLAGS_MORE_THAN_1_USER		0x02
#define	I2O_LCT_DEVICE_FLAGS_PEER_SERVICE_DISABLED	0x10
#define	I2O_LCT_DEVICE_FLAGS_MANAGEMENT_SERVICE_DISABLED 0x20

/* LCT Entry Block */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_lct_entry {
	union {
	    struct {
		uint32_t	TableEntrySize:16;
		uint32_t	LocalTID:12;
		uint32_t	reserved:4;
	    } s1;
	    uint32_t		w1;
	} u1;
	uint32_t		ChangeIndicator;
	uint32_t		DeviceFlags;
	union {
	    struct i2o_class_id {
		uint32_t	Class:12;
		uint32_t	Version:4;
		uint32_t	OrganizationID:16;
	    } s4;
	    uint32_t		w4;
	} u4;
	uint32_t		SubClassInfo;
	union {
	    struct {
		uint32_t	UserTID:12;
		uint32_t	ParentTID:12;
		uint32_t	BiosInfo:8;
	    } s6;
	    uint32_t		w6;
	} u6;
	uint8_t			IdentityTag[I2O_IDENTITY_TAG_SZ];
	uint32_t		EventCapabilities;
} i2o_lct_entry_t;

/* macros to access the bit fields */

#define	get_lct_entry_LocalTID(p, hdl) (p)->u1.s1.LocalTID
#define	get_lct_entry_TableEntrySize(p, hdl) (p)->u1.s1.TableEntrySize

#define	get_lct_entry_Class(p, hdl) (p)->u4.s4.Class
#define	get_lct_entry_Version(p, hdl) (p)->u4.s4.Version
#define	get_lct_entry_OrganizationID(p, hdl) (p)->u4.s4.OrganizationID

#define	get_lct_entry_BiosInfo(p, hdl) (p)->u6.s6.BiosInfo
#define	get_lct_entry_ParentTID(p, hdl) (p)->u6.s6.ParentTID
#define	get_lct_entry_UserTID(p, hdl) (p)->u6.s6.UserTID

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_lct_entry {
	union {
	    struct {
		uint32_t	reserved:4;
		uint32_t	LocalTID:12;
		uint32_t	TableEntrySize:16;
	    } s1;
	    uint32_t		w1;
	} u1;
	uint32_t		ChangeIndicator;
	uint32_t		DeviceFlags;
	union {
	    struct i2o_class_id {
		uint32_t	OrganizationID:16;
		uint32_t	Version:4;
		uint32_t	Class:12;
	    } s4;
	    uint32_t		w4;
	} u4;
	uint32_t		SubClassInfo;
	union {
	    struct {
		uint32_t	BiosInfo:8;
		uint32_t	ParentTID:12;
		uint32_t	UserTID:12;
	    } s6;
	    uint32_t		w6;
	} u6;
	uint8_t			IdentityTag[I2O_IDENTITY_TAG_SZ];
	uint32_t		EventCapabilities;
} i2o_lct_entry_t;

/* macros to access the bit fields */

#define	get_lct_entry_TableEntrySize(p, hdl) \
	(ddi_get32(hdl, &(p)->u1.w1) & 0xFFFF)
#define	get_lct_entry_LocalTID(p, hdl) \
	((ddi_get32(hdl, (p)->u1.w1) >> 16) & 0xFFF)

#define	get_lct_entry_OrganizationID(p, hdl) \
	((ddi_get16(hdl, (p)->u4.w4) >> 16) & 0xFFFF)
#define	get_lct_entry_Version(p, hdl) \
	((ddi_get32(hdl, &(p)->u4.w4) >> 12) & 0xF)
#define	get_lct_entry_Class(p, hdl) \
	(ddi_get32(hdl, &(p)->u4.w4) & 0xFFF)

#define	get_lct_entry_BiosInfo(p, hdl) (p)->u6.s6.BiosInfo
#define	get_lct_entry_ParentTID(p, hdl) \
	((ddi_get32(hdtl, &(p)->u6.w6) >> 12) & 0xFFF)
#define	get_lct_entry_UserTID(p, hdl) \
	(ddi_get32(hdtl, &(p)->u6.w6) & 0xFFF)

#endif

/* I2O Logical Configuration Table structure. */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_lct {
	uint16_t		TableSize;
	union {
	    struct {
		uint16_t	BootDeviceTID:12;
		uint16_t	LctVer:4;
	    } s1;
	    uint16_t		h1;
	} u1;
	uint32_t		IopFlags;
	uint32_t		CurrentChangeIndicator;
	i2o_lct_entry_t		LCTEntry[1];
} i2o_lct_t;

/* macros to access the bit fields */

#define	get_lct_BootDeviceTID(p, hdl)	(p)->u1.s1.BootDeviceTID
#define	get_lct_LctVer(p, hdl)		(p)->u1.s1.LctVer

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_lct {
	uint16_t		TableSize;
	union {
	    struct {
		uint16_t	LctVer:4;
		uint16_t	BootDeviceTID:12;
	    } s1;
	    uint16_t		h1;
	} u1;
	uint32_t		IopFlags;
	uint32_t		CurrentChangeIndicator;
	i2o_lct_entry_t		LCTEntry[1];
} i2o_lct_t;

/* macros to access the bit fields */

#define	get_lct_BootDeviceTID(p, hdl) \
		((ddi_get32(hdl, &(p)->u1.w1) >> 16) & 0xFFF)
#define	get_lct_LctVer(p, hdl) \
		((ddi_get32(hdl, &(p)->u1.w1) >> 28) & 0xF)

#endif

/* ************************************************************************** */

/* Memory Addressing structures and defines. */

/* SglFlags defines. */

#define	I2O_SGL_FLAGS_LAST_ELEMENT		0x80
#define	I2O_SGL_FLAGS_END_OF_BUFFER		0x40

#define	I2O_SGL_FLAGS_IGNORE_ELEMENT		0x00
#define	I2O_SGL_FLAGS_TRANSPORT_ELEMENT		0x04
#define	I2O_SGL_FLAGS_BIT_BUCKET_ELEMENT	0x08
#define	I2O_SGL_FLAGS_IMMEDIATE_DATA_ELEMENT	0x0C
#define	I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT	0x10
#define	I2O_SGL_FLAGS_PAGE_LIST_ADDRESS_ELEMENT 0x20
#define	I2O_SGL_FLAGS_CHAIN_POINTER_ELEMENT	0x30
#define	I2O_SGL_FLAGS_LONG_TRANSACTION_ELEMENT  0x40
#define	I2O_SGL_FLAGS_SHORT_TRANSACTION_ELEMENT 0x70
#define	I2O_SGL_FLAGS_SGL_ATTRIBUTES_ELEMENT	0x7C

#define	I2O_SGL_FLAGS_BC0			0x01
#define	I2O_SGL_FLAGS_BC1			0x02
#define	I2O_SGL_FLAGS_DIR			0x04
#define	I2O_SGL_FLAGS_LOCAL_ADDRESS		0x08

#define	I2O_SGL_FLAGS_CONTEXT_COUNT_MASK	0x03
#define	I2O_SGL_FLAGS_ADDRESS_MODE_MASK		0x3C
#define	I2O_SGL_FLAGS_NO_CONTEXT		0x00

/* Scatter/Gather Truth Table */

/*
 *
 * typedef enum _SG_TYPE {
 *	INVALID,
 *	Ignore,
 *	TransportDetails,
 *	BitBucket,
 *	ImmediateData,
 *	Simple,
 *	PageList,
 *	ChainPointer,
 *	ShortTransaction,
 *	LongTransaction,
 *	SGLAttributes,
 *	INVALID/ReservedLongFormat,
 *	INVALID/ReservedShortFormat
 * } SG_TYPE, *PSG_TYPE;
 *
 *
 *	0x00 Ignore;
 *	0x04 TransportDetails;
 *	0x08 BitBucket;
 *	0x0C ImmediateData;
 *	0x10 Simple;
 *	0x14 Simple;
 *	0x18 Simple;
 *	0x1C Simple;
 *	0x20 PageList;
 *	0x24 PageList;
 *	0x28 PageList;
 *	0x2C PageList;
 *	0x30 ChainPointer;
 *	0x34 INVALID;
 *	0x38 ChainPointer;
 *	0x3C INVALID;
 *	0x40 LongTransaction;
 *	0x44 INVALID/ReservedLongFormat;
 *	0x48 BitBucket;
 *	0x4C ImmediateData;
 *	0x50 Simple;
 *	0x54 Simple;
 *	0x58 Simple;
 *	0x5C Simple;
 *	0x60 PageList;
 *	0x64 PageList;
 *	0x68 PageList;
 *	0x6C PageList;
 *	0x70 ShortTransaction;
 *	0x74 INVALID/ReservedShortFormat;
 *	0x78 INVALID/ReservedShortFormat;
 *	0X7C SGLATTRIBUTES;
 */


/* 32 Bit Context Field defines */

#define	I2O_SGL_FLAGS_CONTEXT32_NULL		0x00
#define	I2O_SGL_FLAGS_CONTEXT32_U32		0x01
#define	I2O_SGL_FLAGS_CONTEXT32_U64		0x02
#define	I2O_SGL_FLAGS_CONTEXT32_U96		0x03

#define	I2O_SGL_FLAGS_CONTEXT32_NULL_SZ		0x00
#define	I2O_SGL_FLAGS_CONTEXT32_U32_SZ		0x04
#define	I2O_SGL_FLAGS_CONTEXT32_U64_SZ		0x08
#define	I2O_SGL_FLAGS_CONTEXT32_U96_SZ		0x0C

/* 64 Bit Context Field defines */

#define	I2O_SGL_FLAGS_CONTEXT64_NULL		0x00
#define	I2O_SGL_FLAGS_CONTEXT64_U64		0x01
#define	I2O_SGL_FLAGS_CONTEXT64_U128		0x02
#define	I2O_SGL_FLAGS_CONTEXT64_U192		0x03

#define	I2O_SGL_FLAGS_CONTEXT64_NULL_SZ		0x00
#define	I2O_SGL_FLAGS_CONTEXT64_U64_SZ		0x08
#define	I2O_SGL_FLAGS_CONTEXT64_U128_SZ		0x10
#define	I2O_SGL_FLAGS_CONTEXT64_U192_SZ		0x18

/* SGL Attribute Element defines */

#define	I2O_SGL_ATTRIBUTE_FLAGS_BIT_BUCKET_HINT		0x0400
#define	I2O_SGL_ATTRIBUTE_FLAGS_IMMEDIATE_DATA_HINT	0x0200
#define	I2O_SGL_ATTRIBUTE_FLAGS_LOCAL_ADDRESS_HINT	0x0100
#define	I2O_SGL_ATTRIBUTE_FLAGS_32BIT_TRANSACTION	0x0000
#define	I2O_SGL_ATTRIBUTE_FLAGS_64BIT_TRANSACTION	0x0004
#define	I2O_SGL_ATTRIBUTE_FLAGS_32BIT_LOCAL_ADDRESS	0x0000

/* SG Size defines */

#define	I2O_SG_COUNT_SZ			24
#define	I2O_SG_FLAGS_SZ			8

/* Standard Flags and Count fields for SG Elements */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef union i2o_flags_count {
	struct {
		uint32_t		Count:24;
		uint32_t		Flags:8;
	} flags_count;
	uint32_t			cword;
} i2o_flags_count_t;

#define	get_flags_count_Count(p, hdl)	(p)->flags_count.Count
#define	put_flags_count_Count(p, v, hdl)	((p)->flags_count.Count = (v))
#define	get_flags_count_Flags(p, hdl)	(p)->flags_count.Flags
#define	put_flags_count_Flags(p, v, hdl)	((p)->flags_count.Flags = (v))

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef union i2o_flags_count {
	struct {
		uint32_t		Flags:8;
		uint32_t		Count:24;
	} flags_count;
	uint32_t			cword;
} i2o_flags_count_t;

#define	get_flags_count_Count(p, hdl) \
	(ddi_get32(hdl, &(p)->cword) & 0xFFFFFF)
#define	put_flags_count_Count(p, v, hdl) \
	ddi_put32(hdl, &(p)->cword, \
		(ddi_get32(hdl, &(p)->cword) & ~0xFFFFFF) | \
		((uint32_t)(v) & 0xFFFFFF))
#define	get_flags_count_Flags(p, hdl) \
	((ddi_get32(hdl, &(p)->cword) >> 24) & 0xFF)
#define	put_flags_count_Flags(p, v, hdl) \
	ddi_put32(hdl, &(p)->cword, \
	    (ddi_get32(hdl, &(p)->cword) & ~0xFF000000) | ((uint32_t)(v) << 24))
#endif

/* Bit Bucket Element */

typedef struct i2o_sge_bit_bucket_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		BufferContext;
} i2o_sge_bit_bucket_element_t;

/* Chain Addressing Scatter-Gather Element */

typedef struct i2o_sge_chain_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		PhysicalAddress;
} i2o_sge_chain_element_t;

/* Chain Addressing with Context Scatter-Gather Element */

typedef struct i2o_sge_chain_context_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		Context[1];
	uint32_t		PhysicalAddress;
} i2o_sge_chain_context_element_t;

/* Ignore Scatter-Gather Element */

typedef struct i2o_sge_ignore_element {
	i2o_flags_count_t	FlagsCount;
} i2o_sge_ignore_element_t;

/* Immediate Data Element */

typedef struct i2o_sge_immediate_data_element {
	i2o_flags_count_t	FlagsCount;
} i2o_sge_immediate_data_element_t;

/* Immediate Data with Context Element */

typedef struct i2o_sge_immediate_data_context_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		BufferContext;
} i2o_sge_immediate_data_context_element_t;

/* Long Transaction Parameters Element */

#if defined(_BIT_FIELDS_LTOH) && defined(_LITTLE_ENDIAN)

typedef struct i2o_sge_long_transaction_element {
	union {
		struct {
			uint32_t	LongElementLength:24;
			uint32_t	Flags:8;
		} s1;
		uint32_t		w1;
	} u1;
	uint32_t			BufferContext;
} i2o_sge_long_transaction_element_t;

#define	get_sge_long_LongElementLength(p, hdl) \
	(p)->u1.s1.LongElementLength
#define	put_sge_long_LongElementLength(p, v, hdl) \
	((p)->u1.s1.LongElementLength = (v))
#define	get_sge_long_Flags(p, hdl) \
	(p)->u1.s1.Flags
#define	put_sge_long_Flags(p, v, hdl) \
	((p)->u1.s1.Flags = (v))

#endif

#if defined(_BIT_FIELDS_HTOL) && defined(_BIG_ENDIAN)

typedef struct i2o_sge_long_transaction_element {
	union {
		struct {
			uint32_t	Flags:8;
			uint32_t	LongElementLength:24;
		} s1;
		uint32_t		w1;
	} u1;
	uint32_t			BufferContext;
} i2o_sge_long_transaction_element_t;

#define	get_sge_long_LongElementLength(p, hdl) \
	(ddi_get32(hdl, &(p)->u1.w1) & 0xFFFFFF)
#define	put_sge_long_LongElementLength(p, v, hdl) \
	ddi_put32(hdl, &(p)->u1.w1, \
		(ddi_get32(hdl, &(p)->u1.w1) & ~0xFFFFFF) | \
		((uint32_t)(v) & 0xFFFFFF))
#define	get_sge_long_Flags(p, hdl) \
	(ddi_get32(hdl, &(p)->u1.w1) >> 24)
#define	put_sge_long_Flags(p, v, hdl) \
	ddi_put32(hdl, &(p)->u1.w1, \
		(ddi_get32(hdl, &(p)->u1.w1) & ~0xFF000000) | \
		((uint32_t)(v) << 24))
#endif

/* Page List Scatter-Gather Element */

typedef struct i2o_sge_page_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		PhysicalAddress[1];
} i2o_sge_page_element_t;

/* Page List with Context Scatter-Gather Element */

typedef struct i2o_sge_page_context_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		BufferContext[1];
	uint32_t		PhysicalAddress[1];
} i2o_sge_page_context_element_t;

/* SGL Attribute Element */

typedef struct i2o_sge_sgl_attributes_element {
	uint16_t		SglAttributeFlags;
	uint8_t			ElementLength;
	uint8_t			Flags;
	uint32_t		PageFrameSize;
} i2o_sge_sgl_attributes_element_t;

/* Short Transaction Parameters Element */

typedef struct i2o_sge_short_transaction_element {
	uint16_t		ClassFields;
	uint8_t			ElementLength;
	uint8_t			Flags;
	uint32_t		BufferContext;
} i2o_sge_short_transaction_element_t;

/* Simple Addressing Scatter-Gather Element */

typedef struct i2o_sge_simple_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		PhysicalAddress;
} i2o_sge_simple_element_t;

/* Simple Addressing with Context Scatter-Gather Element */

typedef struct i2o_sge_simple_context_element {
	i2o_flags_count_t	FlagsCount;
	uint32_t		BufferContext[1];
	uint32_t		PhysicalAddress;
} i2o_sge_simple_context_element_t;

/* Transport Detail Element */

typedef struct i2o_sge_transport_element {
	uint_t			LongElementLength:24;
	uint_t			Flags:8;
} i2o_sge_transport_element_t;

typedef struct i2o_sg_element {
	union {
	    /* Bit Bucket Element */
	    i2o_sge_bit_bucket_element_t		BitBucket;

	    /* Chain Addressing Element */
	    i2o_sge_chain_element_t			Chain;

	    /* Chain Addressing with Context Element */
	    i2o_sge_chain_context_element_t		ChainContext;

	    /* Ignore Scatter-Gather Element */
	    i2o_sge_ignore_element_t			Ignore;

	    /* Immediate Data Element */
	    i2o_sge_immediate_data_element_t		ImmediateData;

	    /* Immediate Data with Context Element */
	    i2o_sge_immediate_data_context_element_t	ImmediateDataContext;

	    /* Long Transaction Parameters Element */
	    i2o_sge_long_transaction_element_t		LongTransaction;

	    /* Page List Element */
	    i2o_sge_page_element_t			Page;

	    /* Page List with Context Element */
	    i2o_sge_page_context_element_t		PageContext;

	    /* SGL Attribute Element */
	    i2o_sge_sgl_attributes_element_t		SGLAttribute;

	    /* Short Transaction Parameters Element */
	    i2o_sge_short_transaction_element_t		ShortTransaction;

	    /* Simple Addressing Element */
	    i2o_sge_simple_element_t			Simple[1];

	    /* Simple Addressing with Context Element */
	    i2o_sge_simple_context_element_t		SimpleContext[1];

	    /* Transport Detail Element */
	    i2o_sge_transport_element_t			Transport;
	} u1;
} i2o_sg_element_t;

/* ************************************************************************** */
/* Basic Parameter Group Access */
/* ************************************************************************** */

/* Operation Function Numbers */

#define	I2O_PARAMS_OPERATION_FIELD_GET		0x0001
#define	I2O_PARAMS_OPERATION_LIST_GET		0x0002
#define	I2O_PARAMS_OPERATION_MORE_GET		0x0003
#define	I2O_PARAMS_OPERATION_SIZE_GET		0x0004
#define	I2O_PARAMS_OPERATION_TABLE_GET		0x0005
#define	I2O_PARAMS_OPERATION_FIELD_SET		0x0006
#define	I2O_PARAMS_OPERATION_LIST_SET		0x0007
#define	I2O_PARAMS_OPERATION_ROW_ADD		0x0008
#define	I2O_PARAMS_OPERATION_ROW_DELETE		0x0009
#define	I2O_PARAMS_OPERATION_TABLE_CLEAR	0x000A

/* Operations List Header */

typedef struct i2o_param_operations_list_header {
	uint16_t		OperationCount;
	uint16_t		Reserved;
} i2o_param_operations_list_header_t;

/* Results List Header */

typedef struct i2o_param_results_list_header {
	uint16_t		ResultCount;
	uint16_t		Reserved;
} i2o_param_results_list_header_t;

/* Read Operation Result Block Template Structure */

typedef struct i2o_param_read_operation_result {
	uint16_t		BlockSize;
	uint8_t			BlockStatus;
	uint8_t			ErrorInfoSize;
	/*			Operations Results	*/
	/*			Pad (if any)		*/
	/*			ErrorInformation (if any) */
} i2o_param_read_operation_result_t;

typedef struct i2o_table_read_operation_result {
	uint16_t		BlockSize;
	uint8_t			BlockStatus;
	uint8_t			ErrorInfoSize;
	uint16_t		RowCount;
	uint16_t		MoreFlag;
	/*			Operations Results	*/
	/*			Pad (if any)		*/
	/*			ErrorInformation (if any) */
} i2o_table_read_operation_result_t;

/* Error Information Template Structure */

typedef struct i2o_param_error_info_template {
	uint16_t		OperationCode;
	uint16_t		GroupNumber;
	uint16_t		FieldIdx;
	uint8_t			AdditionalStatus;
	uint8_t			NumberKeys;
	/*			List of Key Values (variable) */
	/*			Pad (if any)		 */
} i2o_param_error_info_template_t;

/* Operation Template for Specific Fields */

typedef struct i2o_param_operation_specific_template {
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		FieldCount;
	uint16_t		FieldIdx[1];
	/*			Pad (if any)		 */
} i2o_param_operation_specific_template_t;

/* Operation Template for All Fields */

typedef struct i2o_param_operation_all_template {
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		FieldCount;
	/*			Pad (if any)		 */
} i2o_param_operation_all_template_t;

/* Operation Template for All List Fields */

typedef struct i2o_param_operation_all_list_template {
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		FieldCount;
	uint16_t		KeyCount;
	uint8_t			KeyValue;
	/*			Pad (if any)		 */
} i2o_param_operation_all_list_template_t;

/* Modify Operation Result Block Template Structure */

typedef struct i2o_param_modify_operation_result {
	uint16_t		BlockSize;
	uint8_t			BlockStatus;
	uint8_t			ErrorInfoSize;
	/*			ErrorInformation (if any) */
} i2o_param_modify_operation_result_t;

/* Operation Template for Row Delete */

typedef struct i2o_param_operation_row_delete_template {
	uint16_t		Operation;
	uint16_t		GroupNumber;
	uint16_t		RowCount;
	uint8_t			KeyValue;
} i2o_param_operation_row_delete_template_t;

/* Operation Template for Table Clear */

typedef struct i2o_param_operation_table_clear_template {
	uint16_t		Operation;
	uint16_t		GroupNumber;
} i2o_param_operation_table_clear_template_t;

/* Status codes and Error Information for Parameter functions */

#define	I2O_PARAMS_STATUS_SUCCESS		0x00
#define	I2O_PARAMS_STATUS_BAD_KEY_ABORT		0x01
#define	I2O_PARAMS_STATUS_BAD_KEY_CONTINUE	0x02
#define	I2O_PARAMS_STATUS_BUFFER_FULL		0x03
#define	I2O_PARAMS_STATUS_BUFFER_TOO_SMALL	0x04
#define	I2O_PARAMS_STATUS_FIELD_UNREADABLE	0x05
#define	I2O_PARAMS_STATUS_FIELD_UNWRITEABLE	0x06
#define	I2O_PARAMS_STATUS_INSUFFICIENT_FIELDS	0x07
#define	I2O_PARAMS_STATUS_INVALID_GROUP_ID	0x08
#define	I2O_PARAMS_STATUS_INVALID_OPERATION	0x09
#define	I2O_PARAMS_STATUS_NO_KEY_FIELD		0x0A
#define	I2O_PARAMS_STATUS_NO_SUCH_FIELD		0x0B
#define	I2O_PARAMS_STATUS_NON_DYNAMIC_GROUP	0x0C
#define	I2O_PARAMS_STATUS_OPERATION_ERROR	0x0D
#define	I2O_PARAMS_STATUS_SCALAR_ERROR		0x0E
#define	I2O_PARAMS_STATUS_TABLE_ERROR		0x0F
#define	I2O_PARAMS_STATUS_WRONG_GROUP_TYPE	0x10


/* ************************************************************************** */
/* GROUP Parameter Groups */
/* ************************************************************************** */

/* GROUP Configuration and Operating Structures and Defines */

/* Groups Numbers */

#define	I2O_UTIL_PARAMS_DESCRIPTOR_GROUP_NO		0xF000
#define	I2O_UTIL_PHYSICAL_DEVICE_TABLE_GROUP_NO 	0xF001
#define	I2O_UTIL_CLAIMED_TABLE_GROUP_NO			0xF002
#define	I2O_UTIL_USER_TABLE_GROUP_NO			0xF003
#define	I2O_UTIL_PRIVATE_MESSAGE_EXTENSIONS_GROUP_NO 	0xF005
#define	I2O_UTIL_AUTHORIZED_USER_TABLE_GROUP_NO  	0xF006
#define	I2O_UTIL_DEVICE_IDENTITY_GROUP_NO		0xF100
#define	I2O_UTIL_DDM_IDENTITY_GROUP_NO			0xF101
#define	I2O_UTIL_USER_INFORMATION_GROUP_NO		0xF102
#define	I2O_UTIL_SGL_OPERATING_LIMITS_GROUP_NO		0xF103
#define	I2O_UTIL_SENSORS_GROUP_NO			0xF200

/* UTIL Group F000h - GROUP DESCRIPTORS Parameter Group */

#define	I2O_UTIL_GROUP_PROPERTIES_GROUP_TABLE		0x01
#define	I2O_UTIL_GROUP_PROPERTIES_ROW_ADDITION		0x02
#define	I2O_UTIL_GROUP_PROPERTIES_ROW_DELETION		0x04
#define	I2O_UTIL_GROUP_PROPERTIES_CLEAR_OPERATION	0x08

typedef struct i2o_util_group_descriptor_table {
	uint16_t		GroupNumber;
	uint16_t		FieldCount;
	uint16_t		RowCount;
	uint8_t			Properties;
	uint8_t			reserved;
} i2o_util_group_descriptor_table_t;

/* UTIL Group F001h - Physical Device Table Parameter Group */

typedef struct i2o_util_physical_device_table {
	uint32_t		AdapterID;
} i2o_util_physical_device_table_t;

/* UTIL Group F002h - Claimed Table Parameter Group */

typedef struct i2o_util_claimed_table {
	uint16_t		ClaimedTID;
} i2o_util_claimed_table_t;

/* UTIL Group F003h - User Table Parameter Group */

typedef struct i2o_util_user_table {
	uint16_t		Instance;
	uint16_t		UserTID;
	uint8_t			ClaimType;
	uint8_t			reserved1;
	uint16_t		reserved2;
} i2o_util_user_table_t;

/* UTIL Group F005h - Private Message Extensions Parameter Group */

typedef struct i2o_util_private_message_extensions_table {
	uint16_t		ExtInstance;
	uint16_t		OrganizationID;
	uint16_t		XFunctionCode;
} i2o_util_private_message_extensions_table_t;

/* UTIL Group F006h - Authorized User Table Parameter Group */

typedef struct i2o_util_authorized_user_table {
	uint16_t		AlternateTID;
} i2o_util_authorized_user_table_t;

/* UTIL Group F100h - Device Identity Parameter Group */

typedef struct i2o_util_device_identity_scalar {
	uint32_t		ClassID;
	uint16_t		OwnerTID;
	uint16_t		ParentTID;
	uint8_t			VendorInfo[I2O_DEVID_VENDOR_INFO_SZ];
	uint8_t			ProductInfo[I2O_DEVID_PRODUCT_INFO_SZ];
	uint8_t			Description[I2O_DEVID_DESCRIPTION_SZ];
	uint8_t			ProductRevLevel[I2O_DEVID_REV_LEVEL_SZ];
	uint8_t			SNFormat;
	uint8_t			SerialNumber[I2O_MAX_SERIAL_NUMBER_SZ];
} i2o_util_device_identity_scalar_t;

/* UTIL Group F101h - DDM Identity Parameter Group */

typedef struct i2o_util_ddm_identity_scalar {
	uint16_t		DdmTID;
	uint8_t			ModuleName[I2O_MODULE_NAME_SZ];
	uint8_t			ModuleRevLevel[I2O_DEVID_REV_LEVEL_SZ];
	uint8_t			SNFormat;
	uint8_t			SerialNumber[I2O_MAX_SERIAL_NUMBER_SZ];
} i2o_util_ddm_identity_scalar_t;

/* UTIL Group F102h - User Information Parameter Group */

#define	I2O_USER_DEVICE_NAME_SZ		64
#define	I2O_USER_SERVICE_NAME_SZ	64
#define	I2O_USER_PHYSICAL_LOCATION_SZ	64

typedef struct i2o_util_user_information_scalar {
	uint8_t			DeviceName[I2O_USER_DEVICE_NAME_SZ];
	uint8_t			ServiceName[I2O_USER_SERVICE_NAME_SZ];
	uint8_t			PhysicalLocation[I2O_USER_PHYSICAL_LOCATION_SZ];
	uint32_t		InstanceNumber;
} i2o_util_user_information_scalar_t;

/* UTIL Group F103h - SGL Operating Limits Parameter Group */

typedef struct i2o_util_sgl_operating_limits_scalar {
	uint32_t		SglChainSize;
	uint32_t		SglChainSizeMax;
	uint32_t		SglChainSizeTarget;
	uint16_t		SglFragCount;
	uint16_t		SglFragCountMax;
	uint16_t		SglFragCountTarget;
} i2o_util_sgl_operating_limits_scalar_t;

/* UTIL Group F200h - Sensors Parameter Group */

#define	I2O_SENSOR_COMPONENT_OTHER		0x00
#define	I2O_SENSOR_COMPONENT_PLANAR_LOGIC_BOARD	0x01
#define	I2O_SENSOR_COMPONENT_CPU		0x02
#define	I2O_SENSOR_COMPONENT_CHASSIS		0x03
#define	I2O_SENSOR_COMPONENT_POWER_SUPPLY	0x04
#define	I2O_SENSOR_COMPONENT_STORAGE		0x05
#define	I2O_SENSOR_COMPONENT_EXTERNAL		0x06

#define	I2O_SENSOR_SENSOR_CLASS_ANALOG		0x00
#define	I2O_SENSOR_SENSOR_CLASS_DIGITAL		0x01

#define	I2O_SENSOR_SENSOR_TYPE_OTHER		0x00
#define	I2O_SENSOR_SENSOR_TYPE_THERMAL		0x01
#define	I2O_SENSOR_SENSOR_TYPE_DC_VOLTAGE	0x02
#define	I2O_SENSOR_SENSOR_TYPE_AC_VOLTAGE	0x03
#define	I2O_SENSOR_SENSOR_TYPE_DC_CURRENT	0x04
#define	I2O_SENSOR_SENSOR_TYPE_AC_CURRENT	0x05
#define	I2O_SENSOR_SENSOR_TYPE_DOOR_OPEN	0x06
#define	I2O_SENSOR_SENSOR_TYPE_FAN_OPERATIONAL  0x07

#define	I2O_SENSOR_SENSOR_STATE_NORMAL		0x00
#define	I2O_SENSOR_SENSOR_STATE_ABNORMAL	0x01
#define	I2O_SENSOR_SENSOR_STATE_UNKNOWN		0x02
#define	I2O_SENSOR_SENSOR_STATE_LOW_CAT		0x03
#define	I2O_SENSOR_SENSOR_STATE_LOW		0x04
#define	I2O_SENSOR_SENSOR_STATE_LOW_WARNING	0x05
#define	I2O_SENSOR_SENSOR_STATE_HIGH_WARNING	0x06
#define	I2O_SENSOR_SENSOR_STATE_HIGH		0x07
#define	I2O_SENSOR_SENSOR_STATE_HIGH_CAT	0x08

#define	I2O_SENSOR_EVENT_ENABLE_STATE_CHANGE	0x0001
#define	I2O_SENSOR_EVENT_ENABLE_LOW_CATASTROPHIC 0x0002
#define	I2O_SENSOR_EVENT_ENABLE_LOW_READING	0x0004
#define	I2O_SENSOR_EVENT_ENABLE_LOW_WARNING	0x0008
#define	I2O_SENSOR_EVENT_ENABLE_CHANGE_TO_NORMAL 0x0010
#define	I2O_SENSOR_EVENT_ENABLE_HIGH_WARNING	0x0020
#define	I2O_SENSOR_EVENT_ENABLE_HIGH_READING	0x0040
#define	I2O_SENSOR_EVENT_ENABLE_HIGH_CATASTROPHIC 0x0080

typedef struct i2o_util_sensors_table {
	uint16_t		SensorInstance;
	uint8_t			Component;
	uint16_t		ComponentInstance;
	uint8_t			SensorClass;
	uint8_t			SensorType;
	int8_t			ScalingExponent;
	int32_t			ActualReading;
	int32_t			MinimumReading;
	int32_t			Low2LowCatThreshold;
	int32_t			LowCat2LowThreshold;
	int32_t			LowWarn2LowThreshold;
	int32_t			Low2LowWarnThreshold;
	int32_t			Norm2LowWarnThreshold;
	int32_t			LowWarn2NormThreshold;
	int32_t			NominalReading;
	int32_t			HiWarn2NormThreshold;
	int32_t			Norm2HiWarnThreshold;
	int32_t			High2HiWarnThreshold;
	int32_t			HiWarn2HighThreshold;
	int32_t			HiCat2HighThreshold;
	int32_t			Hi2HiCatThreshold;
	int32_t			MaximumReading;
	uint8_t			SensorState;
	uint16_t		EventEnable;
} i2o_util_sensors_table_t;

/*
 * *************************************************************************
 * Definitions used in Solaris for I2O Framework support.
 *
 * (NOTE: Current commitment level is PROJECT PRIVATE.)
 * *************************************************************************
 */

#define	I2O_MSG_SLEEP		DDI_DMA_SLEEP
#define	I2O_MSG_DONTWAIT	DDI_DMA_DONTWAIT

typedef void *i2o_iop_handle_t;
typedef void *i2o_msg_handle_t;

int i2o_msg_osm_register(dev_info_t *dip, i2o_iop_handle_t *handlep);
int i2o_msg_get_lct(i2o_iop_handle_t iop, void *buf,
	size_t buf_size, size_t *lct_sizep, size_t *real_sizep);
int i2o_msg_alloc(i2o_iop_handle_t iop, int (*waitfp)(caddr_t), caddr_t arg,
	void **msgp, i2o_msg_handle_t *msg_handlep,
	ddi_acc_handle_t *acc_handlep);
int i2o_msg_send(i2o_iop_handle_t iop, void *msg, i2o_msg_handle_t handle);
void i2o_msg_osm_unregister(i2o_iop_handle_t *iop);

/*
 * PCI Extensions to I2O Spec 1.5.
 *
 * (Note: Should these definitons go into pci.h?)
 */
#define	PCI_I2O_BASE_CLASS		0x0E
#define	PCI_I2O_SUB_CLASS		0x00
#define	PCI_I2O_PROG_CLASS0		0x00	/* no IOP interrupt */
#define	PCI_I2O_PROG_CLASS1		0x01	/* IOP interrupt supported */

/* Offset definitions for FIFO registers in IOP's shared memory */

#define	PCI_IOP_INBOUND_FREELIST_FIFO	0x40
#define	PCI_IOP_INBOUND_POSTLIST_FIFO	0x40
#define	PCI_IOP_OUTBOUND_FREELIST_FIFO	0x44
#define	PCI_IOP_OUTBOUND_POSTLIST_FIFO	0x44

/* Offset definitions for Interrupt Control registers in IOP's shared memory */

#define	PCI_IOP_INTR_MASK_REG		0x34
#define	PCI_IOP_INTR_STATUS_REG		0x30

/* Bit definitions in Interrupt Mask Register */
#define	I2O_OUTBOUND_POSTLIST_SERVICE_INTR_MASK		0x08

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_I2OMSG_H */
