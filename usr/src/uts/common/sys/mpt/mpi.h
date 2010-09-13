/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MPI_H
#define	_SYS_MPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file is based on Version 1.2 of the MPT
 * Specification by LSI Logic, Inc.
 */

/*
 *  MPI Version Definitions
 */
#define	MPI_VERSION_MAJOR	(0x01)
#define	MPI_VERSION_MINOR	(0x05)
#define	MPI_VERSION_MAJOR_MASK	(0xFF00)
#define	MPI_VERSION_MAJOR_SHIFT	(8)
#define	MPI_VERSION_MINOR_MASK	(0x00FF)
#define	MPI_VERSION_MINOR_SHIFT	(0)
#define	MPI_VERSION	((MPI_VERSION_MAJOR << MPI_VERSION_MAJOR_SHIFT) |   \
	MPI_VERSION_MINOR)

#define	MPI_HEADER_VERSION_UNIT	(0x00)
#define	MPI_HEADER_VERSION_DEV	(0x00)
#define	MPI_HEADER_VERSION_UNIT_MASK	(0xFF00)
#define	MPI_HEADER_VERSION_UNIT_SHIFT	(8)
#define	MPI_HEADER_VERSION_DEV_MASK	(0x00FF)
#define	MPI_HEADER_VERSION_DEV_SHIFT	(0)
#define	MPI_HEADER_VERSION ((MPI_HEADER_VERSION_UNIT << 8) |  \
	MPI_HEADER_VERSION_DEV)
/* Note: The major versions of 0xe0 through 0xff are reserved */

/*
 * IOC State Definitions
 */
#define	MPI_IOC_STATE_RESET			0x00000000
#define	MPI_IOC_STATE_READY			0x10000000
#define	MPI_IOC_STATE_OPERATIONAL		0x20000000
#define	MPI_IOC_STATE_FAULT			0x40000000

#define	MPI_IOC_STATE_MASK			0xF0000000
#define	MPI_IOC_STATE_SHIFT			28

/*
 * Fault state codes (product independent range 0x8000-0xFFFF)
 */
#define	MPI_FAULT_REQUEST_MESSAGE_PCI_PARITY_ERROR	0x8111
#define	MPI_FAULT_REQUEST_MESSAGE_PCI_BUS_FAULT		0x8112
#define	MPI_FAULT_REPLY_MESSAGE_PCI_PARITY_ERROR	0x8113
#define	MPI_FAULT_REPLY_MESSAGE_PCI_BUS_FAULT		0x8114
#define	MPI_FAULT_DATA_SEND_PCI_PARITY_ERROR		0x8115
#define	MPI_FAULT_DATA_SEND_PCI_BUS_FAULT		0x8116
#define	MPI_FAULT_DATA_RECEIVE_PCI_PARITY_ERROR		0x8117
#define	MPI_FAULT_DATA_RECEIVE_PCI_BUS_FAULT		0x8118


/*
 * System Doorbell
 */
#define	MPI_DOORBELL_OFFSET			0x00000000
#define	MPI_DOORBELL_ACTIVE			0x08000000
#define	MPI_DOORBELL_USED			MPI_DOORBELL_ACTIVE
#define	MPI_DOORBELL_ACTIVE_SHIFT		27
#define	MPI_DOORBELL_WHO_INIT_MASK		0x07000000
#define	MPI_DOORBELL_WHO_INIT_SHIFT		24
#define	MPI_DOORBELL_FUNCTION_MASK		0xFF000000
#define	MPI_DOORBELL_FUNCTION_SHIFT		24
#define	MPI_DOORBELL_ADD_DWORDS_MASK		0x00FF0000
#define	MPI_DOORBELL_ADD_DWORDS_SHIFT		16
#define	MPI_DOORBELL_DATA_MASK			0x0000FFFF


/*
 * PCI System Interface Registers
 */
#define	MPI_WRITE_SEQUENCE_OFFSET		0x00000004
#define	MPI_WRSEQ_KEY_VALUE_MASK		0x0000000F
#define	MPI_WRSEQ_1ST_KEY_VALUE			0x04
#define	MPI_WRSEQ_2ND_KEY_VALUE			0x0B
#define	MPI_WRSEQ_3RD_KEY_VALUE			0x02
#define	MPI_WRSEQ_4TH_KEY_VALUE			0x07
#define	MPI_WRSEQ_5TH_KEY_VALUE			0x0D

#define	MPI_DIAGNOSTIC_OFFSET			0x00000008
#define	MPI_DIAG_CLEAR_FLASH_BAD_SIG		0x00000400
#define	MPI_DIAG_PREVENT_IOC_BOOT		0x00000200
#define	MPI_DIAG_DRWE				0x00000080
#define	MPI_DIAG_FLASH_BAD_SIG			0x00000040
#define	MPI_DIAG_RESET_HISTORY			0x00000020
#define	MPI_DIAG_RW_ENABLE			0x00000010
#define	MPI_DIAG_RESET_ADAPTER			0x00000004
#define	MPI_DIAG_DISABLE_ARM			0x00000002
#define	MPI_DIAG_MEM_ENABLE			0x00000001

#define	MPI_TEST_BASE_ADDRESS_OFFSET		0x0000000C

#define	MPI_DIAG_RW_DATA_OFFSET			0x00000010

#define	MPI_DIAG_RW_ADDRESS_OFFSET		0x00000014

#define	MPI_HOST_INTERRUPT_STATUS_OFFSET	0x00000030
#define	MPI_HIS_IOP_DOORBELL_STATUS		0x80000000
#define	MPI_HIS_REPLY_MESSAGE_INTERRUPT		0x00000008
#define	MPI_HIS_DOORBELL_INTERRUPT		0x00000001

#define	MPI_HOST_INTERRUPT_MASK_OFFSET		0x00000034
#define	MPI_HIM_RIM				0x00000008
#define	MPI_HIM_DIM				0x00000001

#define	MPI_REQUEST_QUEUE_OFFSET		0x00000040
#define	MPI_REQUEST_POST_FIFO_OFFSET		0x00000040

#define	MPI_REPLY_QUEUE_OFFSET			0x00000044
#define	MPI_REPLY_POST_FIFO_OFFSET		0x00000044
#define	MPI_REPLY_FREE_FIFO_OFFSET		0x00000044

#define	MPI_HI_PRI_REQUEST_QUEUE_OFFSET		0x00000048

/*
 * Message Frame Descriptors
 */
#define	MPI_REQ_MF_DESCRIPTOR_NB_MASK		0x00000003
#define	MPI_REQ_MF_DESCRIPTOR_F_BIT		0x00000004
#define	MPI_REQ_MF_DESCRIPTOR_ADDRESS_MASK	0xFFFFFFF8

#define	MPI_ADDRESS_REPLY_A_BIT			0x80000000
#define	MPI_ADDRESS_REPLY_ADDRESS_MASK		0x7FFFFFFF

#define	MPI_CONTEXT_REPLY_A_BIT			0x80000000
#define	MPI_CONTEXT_REPLY_TYPE_MASK		0x60000000
#define	MPI_CONTEXT_REPLY_TYPE_SCSI_INIT	0x00
#define	MPI_CONTEXT_REPLY_TYPE_SCSI_TARGET	0x01
#define	MPI_CONTEXT_REPLY_TYPE_LAN		0x02
#define	MPI_CONTEXT_REPLY_TYPE_SHIFT		29
#define	MPI_CONTEXT_REPLY_CONTEXT_MASK		0x1FFFFFFF


/*
 * Context Reply macros
 */
#define	MPI_GET_CONTEXT_REPLY_TYPE(x)  \
	(((x) & MPI_CONTEXT_REPLY_TYPE_MASK) \
		>> MPI_CONTEXT_REPLY_TYPE_SHIFT)

#define	MPI_SET_CONTEXT_REPLY_TYPE(x, typ) \
	((x) = ((x) & ~MPI_CONTEXT_REPLY_TYPE_MASK) | \
		(((typ) << MPI_CONTEXT_REPLY_TYPE_SHIFT) & \
			MPI_CONTEXT_REPLY_TYPE_MASK))


/*
 * Message Functions
 *     0x80 -> 0x8F reserved for private message use per product
 */
#define	MPI_FUNCTION_SCSI_IO_REQUEST			0x00
#define	MPI_FUNCTION_SCSI_TASK_MGMT			0x01
#define	MPI_FUNCTION_IOC_INIT				0x02
#define	MPI_FUNCTION_IOC_FACTS				0x03
#define	MPI_FUNCTION_CONFIG				0x04
#define	MPI_FUNCTION_PORT_FACTS				0x05
#define	MPI_FUNCTION_PORT_ENABLE			0x06
#define	MPI_FUNCTION_EVENT_NOTIFICATION			0x07
#define	MPI_FUNCTION_EVENT_ACK				0x08
#define	MPI_FUNCTION_FW_DOWNLOAD			0x09
#define	MPI_FUNCTION_TARGET_CMD_BUFFER_POST		0x0A
#define	MPI_FUNCTION_TARGET_ASSIST			0x0B
#define	MPI_FUNCTION_TARGET_STATUS_SEND			0x0C
#define	MPI_FUNCTION_TARGET_MODE_ABORT			0x0D
#define	MPI_FUNCTION_FC_LINK_SRVC_BUF_POST		0x0E
#define	MPI_FUNCTION_FC_LINK_SRVC_RSP			0x0F
#define	MPI_FUNCTION_FC_EX_LINK_SRVC_SEND		0x10
#define	MPI_FUNCTION_FC_ABORT				0x11
#define	MPI_FUNCTION_FW_UPLOAD				0x12
#define	MPI_FUNCTION_FC_COMMON_TRANSPORT_SEND		0x13
#define	MPI_FUNCTION_FC_PRIMITIVE_SEND			0x14

#define	MPI_FUNCTION_RAID_ACTION			0x15
#define	MPI_FUNCTION_RAID_SCSI_IO_PASSTHROUGH		0x16

#define	MPI_FUNCTION_TOOLBOX				0x17

#define	MPI_FUNCTION_SCSI_ENCLOSURE_PROCESSOR		0x18

#define	MPI_FUNCTION_MAILBOX				0x19

#define	MPI_FUNCTION_SMP_PASSTHROUGH			0x1A
#define	MPI_FUNCTION_SAS_IO_UNIT_CONTROL		0x1B

#define	MPI_DIAG_BUFFER_POST				0x1D
#define	MPI_DIAG_RELEASE				0x1E

#define	MPI_FUNCTION_SCSI_IO_32				0x1F

#define	MPI_FUNCTION_LAN_SEND				0x20
#define	MPI_FUNCTION_LAN_RECEIVE			0x21
#define	MPI_FUNCTION_LAN_RESET				0x22

#define	MPI_FUNCTION_INBAND_BUFFER_POST			0x28
#define	MPI_FUNCTION_INBAND_SEND			0x29
#define	MPI_FUNCTION_INBAND_RSP				0x2A
#define	MPI_FUNCTION_INBAND_ABORT			0x2B

#define	MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET		0x40
#define	MPI_FUNCTION_IO_UNIT_RESET			0x41
#define	MPI_FUNCTION_HANDSHAKE				0x42
#define	MPI_FUNCTION_REPLY_FRAME_REMOVAL		0x43
#define	MPI_FUNCTION_HOST_PAGEBUF_ACCESS_CONTROL	0x44

/*
 * Version format
 */
typedef struct mpi_version_struct {
	uint8_t		Dev;
	uint8_t		Unit;
	uint8_t		Minor;
	uint8_t		Major;
} mpi_version_struct_t;

typedef union mpi_version_format {
	mpi_version_struct_t	Struct;
	uint32_t		Word;
} mpi_version_format_t;

/*
 * Scatter Gather Elements
 */

/*
 * Simple element structures
 */
typedef struct sge_simple32 {
	uint32_t	FlagsLength;
	uint32_t	Address;
} sge_simple32_t;

typedef struct sge_simple64 {
	uint32_t	FlagsLength;
	uint32_t	Address_Low;
	uint32_t	Address_High;
} sge_simple64_t;

typedef struct sge_simple_union {
	uint32_t	FlagsLength;
	union {
		uint32_t	Address32;
		uint32_t	Address64_Low;
		uint32_t	Address64_High;
	} u1;
} sge_simple_union_t;

/*
 * Chain element structures
 */
typedef struct sge_chain32 {
	uint16_t	Length;
	uint8_t		NextChainOffset;
	uint8_t		Flags;
	uint32_t	Address;
} sge_chain32_t;

typedef struct sge_chain64 {
	uint16_t	Length;
	uint8_t		NextChainOffset;
	uint8_t		Flags;
	uint32_t	Address64_Low;
	uint32_t	Address64_High;
} sge_chain64_t;

typedef struct sge_chain_union {
	uint16_t	Length;
	uint8_t		NextChainOffset;
	uint8_t		Flags;
	union {
		uint32_t	Address32;
		uint32_t	Address64_Low;
		uint32_t	Address64_High;
	} u1;
} sge_chain_union_t;

/*
 *  Transaction Context element
 */
typedef struct sge_transaction32 {
	uint8_t		Reserved;
	uint8_t		ContextSize;
	uint8_t		DetailsLength;
	uint8_t		Flags;
	uint32_t	TransactionContext[1];
	uint32_t	TransactionDetails[1];
} sge_transaction32_t;

typedef struct sge_transaction64 {
	uint8_t		Reserved;
	uint8_t		ContextSize;
	uint8_t		DetailsLength;
	uint8_t		Flags;
	uint32_t	TransactionContext[2];
	uint32_t	TransactionDetails[1];
} sge_transaction64_t;

typedef struct sge_transaction96 {
	uint8_t		Reserved;
	uint8_t		ContextSize;
	uint8_t		DetailsLength;
	uint8_t		Flags;
	uint32_t	TransactionContext[3];
	uint32_t	TransactionDetails[1];
} sge_transaction96_t;

typedef struct sge_transaction128 {
	uint8_t		Reserved;
	uint8_t		ContextSize;
	uint8_t		DetailsLength;
	uint8_t		Flags;
	uint32_t	TransactionContext[4];
	uint32_t	TransactionDetails[1];
} sge_transaction128_t;

typedef struct sge_transaction_union {
	uint8_t		Reserved;
	uint8_t		ContextSize;
	uint8_t		DetailsLength;
	uint8_t		Flags;
	union {
		uint32_t	TransactionContext32[1];
		uint32_t	TransactionContext64[2];
		uint32_t	TransactionContext96[3];
		uint32_t	TransactionContext128[4];
	} u1;
	uint32_t	TransactionDetails[1];
} sge_transaction_union_t;


/*
 * SGE IO types union  for IO SGL's
 */
typedef struct sge_io_union {
	union {
		sge_simple_union_t	Simple;
		sge_chain_union_t	Chain;
	} u1;
} sge_io_union_t;

/*
 * SGE union for SGL's with Simple and Transaction elements
 */
typedef struct sge_trans_simple_union {
	union {
		sge_simple_union_t	Simple;
		sge_transaction_union_t	Transaction;
	} u1;
} sge_trans_simple_union_t;

/*
 * All SGE types union
 */
typedef struct sge_mpi_union {
	union {
		sge_simple_union_t	Simple;
		sge_chain_union_t	Chain;
		sge_transaction_union_t	Transaction;
	} u1;
} sge_mpi_union_t;


/*
 * SGE field definition and masks
 */

/*
 * Flags field bit definitions
 */
#define	MPI_SGE_FLAGS_LAST_ELEMENT		0x80
#define	MPI_SGE_FLAGS_END_OF_BUFFER		0x40
#define	MPI_SGE_FLAGS_ELEMENT_TYPE_MASK		0x30
#define	MPI_SGE_FLAGS_LOCAL_ADDRESS		0x08
#define	MPI_SGE_FLAGS_DIRECTION			0x04
#define	MPI_SGE_FLAGS_ADDRESS_SIZE		0x02
#define	MPI_SGE_FLAGS_END_OF_LIST		0x01

#define	MPI_SGE_FLAGS_SHIFT			24

#define	MPI_SGE_LENGTH_MASK			0x00FFFFFF
#define	MPI_SGE_CHAIN_LENGTH_MASK		0x0000FFFF

/*
 * Element Type
 */
#define	MPI_SGE_FLAGS_TRANSACTION_ELEMENT	0x00
#define	MPI_SGE_FLAGS_SIMPLE_ELEMENT		0x10
#define	MPI_SGE_FLAGS_CHAIN_ELEMENT		0x30
#define	MPI_SGE_FLAGS_ELEMENT_MASK		0x30

/*
 * Address location
 */
#define	MPI_SGE_FLAGS_SYSTEM_ADDRESS		0x00

/*
 * Direction
 */
#define	MPI_SGE_FLAGS_IOC_TO_HOST		0x00
#define	MPI_SGE_FLAGS_HOST_TO_IOC		0x04

/*
 * Address Size
 */
#define	MPI_SGE_FLAGS_32_BIT_ADDRESSING		0x00
#define	MPI_SGE_FLAGS_64_BIT_ADDRESSING		0x02

/*
 * Context Size
 */
#define	MPI_SGE_FLAGS_32_BIT_CONTEXT		0x00
#define	MPI_SGE_FLAGS_64_BIT_CONTEXT		0x02
#define	MPI_SGE_FLAGS_96_BIT_CONTEXT		0x04
#define	MPI_SGE_FLAGS_128_BIT_CONTEXT		0x06

#define	MPI_SGE_CHAIN_OFFSET_MASK		0x00FF0000
#define	MPI_SGE_CHAIN_OFFSET_SHIFT		16


/*
 * SGE operation Macros
 */

/*
 * SIMPLE FlagsLength manipulations...
 */
#define	MPI_SGE_SET_FLAGS(f)		((uint32_t)(f) << MPI_SGE_FLAGS_SHIFT)
#define	MPI_SGE_GET_FLAGS(fl) \
	(((fl) & ~MPI_SGE_LENGTH_MASK) >> MPI_SGE_FLAGS_SHIFT)
#define	MPI_SGE_LENGTH(fl)		((fl) & MPI_SGE_LENGTH_MASK)
#define	MPI_SGE_CHAIN_LENGTH(fl)	((fl) & MPI_SGE_CHAIN_LENGTH_MASK)

#define	MPI_SGE_SET_FLAGS_LENGTH(f, l) \
	(MPI_SGE_SET_FLAGS(f) | MPI_SGE_LENGTH(l))

#define	MPI_pSGE_GET_FLAGS(psg)		MPI_SGE_GET_FLAGS((psg)->FlagsLength)
#define	MPI_pSGE_GET_LENGTH(psg)	MPI_SGE_LENGTH((psg)->FlagsLength)
#define	MPI_pSGE_SET_FLAGS_LENGTH(psg, f, l) \
	(psg)->FlagsLength = MPI_SGE_SET_FLAGS_LENGTH(f, l)

/*
 * CAUTION - The following are READ-MODIFY-WRITE!
 */
#define	MPI_pSGE_SET_FLAGS(psg, f) \
	(psg)->FlagsLength |= MPI_SGE_SET_FLAGS(f)
#define	MPI_pSGE_SET_LENGTH(psg, l) \
	(psg)->FlagsLength |= MPI_SGE_LENGTH(l)

#define	MPI_GET_CHAIN_OFFSET(x) \
	((x&MPI_SGE_CHAIN_OFFSET_MASK)>>MPI_SGE_CHAIN_OFFSET_SHIFT)


/*
 * Standard Message Structures
 */

/*
 * Standard message request header for all request messages
 */
typedef struct msg_request_header {
	uint8_t		Reserved[2];	/* function specific */
	uint8_t		ChainOffset;
	uint8_t		Function;
	uint8_t		Reserved1[3];	/* function specific */
	uint8_t		MsgFlags;
	uint32_t	MsgContext;
} msg_request_header_t;


/*
 * Default Reply
 */
typedef struct msg_default_reply {
	uint8_t		Reserved[2];	/* function specific */
	uint8_t		MsgLength;
	uint8_t		Function;
	uint8_t		Reserved1[3];	/* function specific */
	uint8_t		MsgFlags;
	uint32_t	MsgContext;
	uint8_t		Reserved2[2];	/* function specific */
	uint16_t	IOCStatus;
	uint32_t	IOCLogInfo;
} msg_default_reply_t;

/*
 * MsgFlags definition for all replies
 */
#define	MPI_MSGFLAGS_CONTINUATION_REPLY		0x80


/*
 * IOC Status Values
 */

/*
 * Common IOCStatus values for all replies
 */
#define	MPI_IOCSTATUS_SUCCESS				0x0000
#define	MPI_IOCSTATUS_INVALID_FUNCTION			0x0001
#define	MPI_IOCSTATUS_BUSY				0x0002
#define	MPI_IOCSTATUS_INVALID_SGL			0x0003
#define	MPI_IOCSTATUS_INTERNAL_ERROR			0x0004
#define	MPI_IOCSTATUS_RESERVED				0x0005
#define	MPI_IOCSTATUS_INSUFFICIENT_RESOURCES		0x0006
#define	MPI_IOCSTATUS_INVALID_FIELD			0x0007
#define	MPI_IOCSTATUS_INVALID_STATE			0x0008
#define	MPI_IOCSTATUS_OP_STATE_NOT_SUPPORTED		0x0009

/*
 * Config IOCStatus values
 */
#define	MPI_IOCSTATUS_CONFIG_INVALID_ACTION		0x0020
#define	MPI_IOCSTATUS_CONFIG_INVALID_TYPE		0x0021
#define	MPI_IOCSTATUS_CONFIG_INVALID_PAGE		0x0022
#define	MPI_IOCSTATUS_CONFIG_INVALID_DATA		0x0023
#define	MPI_IOCSTATUS_CONFIG_NO_DEFAULTS		0x0024
#define	MPI_IOCSTATUS_CONFIG_CANT_COMMIT		0x0025

/*
 * SCSIIO Reply (SPI & FCP) initiator values
 */
#define	MPI_IOCSTATUS_SCSI_RECOVERED_ERROR		0x0040
#define	MPI_IOCSTATUS_SCSI_INVALID_BUS			0x0041
#define	MPI_IOCSTATUS_SCSI_INVALID_TARGETID		0x0042
#define	MPI_IOCSTATUS_SCSI_DEVICE_NOT_THERE		0x0043
#define	MPI_IOCSTATUS_SCSI_DATA_OVERRUN			0x0044
#define	MPI_IOCSTATUS_SCSI_DATA_UNDERRUN		0x0045
#define	MPI_IOCSTATUS_SCSI_IO_DATA_ERROR		0x0046
#define	MPI_IOCSTATUS_SCSI_PROTOCOL_ERROR		0x0047
#define	MPI_IOCSTATUS_SCSI_TASK_TERMINATED		0x0048
#define	MPI_IOCSTATUS_SCSI_RESIDUAL_MISMATCH		0x0049
#define	MPI_IOCSTATUS_SCSI_TASK_MGMT_FAILED		0x004A
#define	MPI_IOCSTATUS_SCSI_IOC_TERMINATED		0x004B
#define	MPI_IOCSTATUS_SCSI_EXT_TERMINATED		0x004C

/*
 * SCSI Initiator/Target end-to-end data protection
 */
#define	MPI_IOCSTATUS_EEDP_CRC_ERROR			0x004D
#define	MPI_IOCSTATUS_EEDP_LBA_TAG_ERROR		0x004E
#define	MPI_IOCSTATUS_EEDP_APP_TAG_ERROR		0x004F
/*
 * SCSI (SPI & FCP) target values
 */
#define	MPI_IOCSTATUS_TARGET_PRIORITY_IO		0x0060
#define	MPI_IOCSTATUS_TARGET_INVALID_PORT		0x0061
#define	MPI_IOCSTATUS_TARGET_INVALID_IOCINDEX		0x0062
#define	MPI_IOCSTATUS_TARGET_ABORTED			0x0063
#define	MPI_IOCSTATUS_TARGET_NO_CONN_RETRYABLE		0x0064
#define	MPI_IOCSTATUS_TARGET_NO_CONNECTION		0x0065
#define	MPI_IOCSTATUS_TARGET_XFER_COUNT_MISMATCH	0x006A
#define	MPI_IOCSTATUS_TARGET_STS_DATA_NOT_SENT		0x006B

/*
 * Additional FCP target values
 */
#define	MPI_IOCSTATUS_TARGET_FC_ABORTED			0x0066	/* obsolete */
#define	MPI_IOCSTATUS_TARGET_FC_RX_ID_INVALID		0x0067	/* obsolete */
#define	MPI_IOCSTATUS_TARGET_FC_DID_INVALID		0x0068	/* obsolete */
#define	MPI_IOCSTATUS_TARGET_FC_NODE_LOGGED_OUT		0x0069	/* obsolete */

/*
 * Fibre Channel Direct Access values
 */
#define	MPI_IOCSTATUS_FC_ABORTED			0x0066
#define	MPI_IOCSTATUS_FC_RX_ID_INVALID			0x0067
#define	MPI_IOCSTATUS_FC_DID_INVALID			0x0068
#define	MPI_IOCSTATUS_FC_NODE_LOGGED_OUT		0x0069
#define	MPI_IOCSTATUS_FC_EXCHANGE_CANCELED		0x006C

/*
 * LAN values
 */
#define	MPI_IOCSTATUS_LAN_DEVICE_NOT_FOUND		0x0080
#define	MPI_IOCSTATUS_LAN_DEVICE_FAILURE		0x0081
#define	MPI_IOCSTATUS_LAN_TRANSMIT_ERROR		0x0082
#define	MPI_IOCSTATUS_LAN_TRANSMIT_ABORTED		0x0083
#define	MPI_IOCSTATUS_LAN_RECEIVE_ERROR			0x0084
#define	MPI_IOCSTATUS_LAN_RECEIVE_ABORTED		0x0085
#define	MPI_IOCSTATUS_LAN_PARTIAL_PACKET		0x0086
#define	MPI_IOCSTATUS_LAN_CANCELED			0x0087

/*
 * SAS values
 */
#define	MPI_IOCSTATUS_SAS_SMP_REQUEST_FAILED		0x0090
#define	MPI_IOCSTATUS_SAS_SMP_DATA_OVERRUN		0x0091

/*
 * Inband values
 */
#define	MPI_IOCSTATUS_INBAND_ABORTED			0x0098
#define	MPI_IOCSTATUS_INBAND_NO_CONNECTION		0x0099

/*
 * Diagnostic Tools values
 */
#define	MPI_IOCSTATUS_DIAGNOSTIC_RELEASED		0x00A0

/*
 * IOCStatus flag to indicate that log info is available
 */
#define	MPI_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE		0x8000
#define	MPI_IOCSTATUS_MASK				0x7FFF

/*
 * LogInfo Types
 */
#define	MPI_IOCLOGINFO_TYPE_MASK			0xF0000000
#define	MPI_IOCLOGINFO_TYPE_NONE			0x0
#define	MPI_IOCLOGINFO_TYPE_SCSI			0x1
#define	MPI_IOCLOGINFO_TYPE_FC				0x2
#define	MPI_IOCLOGINFO_TYPE_SAS				0x3
#define	MPI_IOCLOGINFO_TYPE_ISCSI			0x4
#define	MPI_IOCLOGINFO_LOG_DATA_MASK			0x0FFFFFFF

/*
 * SMP passthrough messages
 */
typedef struct msg_smp_passthrough {
	uint8_t			Flags;
	uint8_t			PhysicalPort;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint16_t		RequestDataLength;
	uint8_t			ConnectionRate;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			Reserved[4];
	uint64_t		SASAddress;
	uint8_t			Reserved1[8];
} msg_smp_passthrough_t;


/* SMP passthrough Reply */

typedef struct msg_smp_passthrough_reply {
	uint8_t			Flags;
	uint8_t			PhysicalPort;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint16_t		ResponseDataLength;
	uint8_t			Reserved;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			Reserved1;
	uint8_t			SASStatus;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint8_t			Reserved2[4];
} msg_smp_passthrough_reply_t;

#define	MPI_SMP_PT_REQ_CONNECT_RATE_NEGOTIATED	(0x00)
#define	MPI_SMP_PT_REQ_CONNECT_RATE_1_5		(0x08)
#define	MPI_SMP_PT_REQ_CONNECT_RATE_3_0		(0x09)
#define	MPI_SASSTATUS_SUCCESS			0

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MPI_H */
