/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MPI_INIT_H
#define	_SYS_MPI_INIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Initiator Messages
 */

/*
 * SCSI IO messages and assocaited structures
 */
typedef struct msg_scsi_io_request {
	uint8_t			TargetID;
	uint8_t			Bus;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			CDBLength;
	uint8_t			SenseBufferLength;
	uint8_t			Reserved;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			LUN[8];
	uint32_t		Control;
	uint8_t			CDB[16];
	uint32_t		DataLength;
	uint32_t		SenseBufferLowAddr;
	sge_io_union_t		SGL;
} msg_scsi_io_request_t;

/* SCSIO MsgFlags bits */

#define	MPI_SCSIIO_MSGFLGS_SENSE_WIDTH		0x01
#define	MPI_SCSIIO_MSGFLGS_SENSE_WIDTH_32	0x00
#define	MPI_SCSIIO_MSGFLGS_SENSE_WIDTH_64	0x01
#define	MPI_SCSIIO_MSGFLGS_SENSE_LOCATION	0x02
#define	MPI_SCSIIO_MSGFLGS_SENSE_LOC_HOST	0x00
#define	MPI_SCSIIO_MSGFLGS_SENSE_LOC_IOC	0x02

/*
 * SCSIIO LUN fields
 */
#define	MPI_SCSIIO_LUN_FIRST_LEVEL_ADDRESSING	0x0000FFFF
#define	MPI_SCSIIO_LUN_SECOND_LEVEL_ADDRESSING	0xFFFF0000
#define	MPI_SCSIIO_LUN_THIRD_LEVEL_ADDRESSING	0x0000FFFF
#define	MPI_SCSIIO_LUN_FOURTH_LEVEL_ADDRESSING	0xFFFF0000
#define	MPI_SCSIIO_LUN_LEVEL_1_WORD		0xFF00
#define	MPI_SCSIIO_LUN_LEVEL_1_DWORD		0x0000FF00

/*
 * SCSIO Control bits
 */
#define	MPI_SCSIIO_CONTROL_DATADIRECTION_MASK	0x03000000
#define	MPI_SCSIIO_CONTROL_NODATATRANSFER	0x00000000
#define	MPI_SCSIIO_CONTROL_WRITE		0x01000000
#define	MPI_SCSIIO_CONTROL_READ			0x02000000

#define	MPI_SCSIIO_CONTROL_ADDCDBLEN_MASK	0x3C000000
#define	MPI_SCSIIO_CONTROL_ADDCDBLEN_SHIFT	26

#define	MPI_SCSIIO_CONTROL_TASKATTRIBUTE_MASK	0x00000700
#define	MPI_SCSIIO_CONTROL_SIMPLEQ		0x00000000
#define	MPI_SCSIIO_CONTROL_HEADOFQ		0x00000100
#define	MPI_SCSIIO_CONTROL_ORDEREDQ		0x00000200
#define	MPI_SCSIIO_CONTROL_ACAQ			0x00000400
#define	MPI_SCSIIO_CONTROL_UNTAGGED		0x00000500
#define	MPI_SCSIIO_CONTROL_NO_DISCONNECT	0x00000700

#define	MPI_SCSIIO_CONTROL_TASKMANAGE_MASK	0x00FF0000
#define	MPI_SCSIIO_CONTROL_OBSOLETE		0x00800000
#define	MPI_SCSIIO_CONTROL_CLEAR_ACA_RSV	0x00400000
#define	MPI_SCSIIO_CONTROL_TARGET_RESET		0x00200000
#define	MPI_SCSIIO_CONTROL_LUN_RESET_RSV	0x00100000
#define	MPI_SCSIIO_CONTROL_RESERVED		0x00080000
#define	MPI_SCSIIO_CONTROL_CLR_TASK_SET_RSV	0x00040000
#define	MPI_SCSIIO_CONTROL_ABORT_TASK_SET	0x00020000
#define	MPI_SCSIIO_CONTROL_RESERVED2		0x00010000


/*
 * SCSIIO reply structure
 */
typedef struct msg_scsi_io_reply {
	uint8_t			TargetID;
	uint8_t			Bus;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			CDBLength;
	uint8_t			SenseBufferLength;
	uint8_t			Reserved;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			SCSIStatus;
	uint8_t			SCSIState;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint32_t		TransferCount;
	uint32_t		SenseCount;
	uint32_t		ResponseInfo;
	uint16_t		TaskTag;
	uint16_t		Reserved1;
} msg_scsi_io_reply_t;

/*
 * SCSIIO Reply SCSIStatus values (SAM-2 status codes)
 */
#define	MPI_SCSI_STATUS_SUCCESS			0x00
#define	MPI_SCSI_STATUS_CHECK_CONDITION		0x02
#define	MPI_SCSI_STATUS_CONDITION_MET		0x04
#define	MPI_SCSI_STATUS_BUSY			0x08
#define	MPI_SCSI_STATUS_INTERMEDIATE		0x10
#define	MPI_SCSI_STATUS_INTERMEDIATE_CONDMET	0x14
#define	MPI_SCSI_STATUS_RESERVATION_CONFLICT	0x18
#define	MPI_SCSI_STATUS_COMMAND_TERMINATED	0x22
#define	MPI_SCSI_STATUS_TASK_SET_FULL		0x28
#define	MPI_SCSI_STATUS_ACA_ACTIVE		0x30

/*
 * SCSIIO Reply SCSIState values
 */
#define	MPI_SCSI_STATE_AUTOSENSE_VALID		0x01
#define	MPI_SCSI_STATE_AUTOSENSE_FAILED		0x02
#define	MPI_SCSI_STATE_NO_SCSI_STATUS		0x04
#define	MPI_SCSI_STATE_TERMINATED		0x08
#define	MPI_SCSI_STATE_RESPONSE_INFO_VALID	0x10
#define	MPI_SCSI_STATE_QUEUE_TAG_REJECTED	0x20

/*
 * SCSIIO Reply ResponseInfo values
 * (FCP-1 RSP_CODE values and SPI-3 Packetized Failure codes)
 */
#define	MPI_SCSI_RSP_INFO_FUNCTION_COMPLETE	0x00000000
#define	MPI_SCSI_RSP_INFO_FCP_BURST_LEN_ERROR	0x01000000
#define	MPI_SCSI_RSP_INFO_CMND_FIELDS_INVALID	0x02000000
#define	MPI_SCSI_RSP_INFO_FCP_DATA_RO_ERROR	0x03000000
#define	MPI_SCSI_RSP_INFO_TASK_MGMT_UNSUPPORTED	0x04000000
#define	MPI_SCSI_RSP_INFO_TASK_MGMT_FAILED	0x05000000
#define	MPI_SCSI_RSP_INFO_SPI_LQ_INVALID_TYPE	0x06000000

/*
 * SCSI Task Management messages
 */
typedef struct msg_scsi_task_mgmt {
	uint8_t			TargetID;
	uint8_t			Bus;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved;
	uint8_t			TaskType;
	uint8_t			Reserved1;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			LUN[8];
	uint32_t		Reserved2[7];
	uint32_t		TaskMsgContext;
} msg_scsi_task_mgmt_t;

/*
 * TaskType values
 */
#define	MPI_SCSITASKMGMT_TASKTYPE_ABORT_TASK		0x00000001
#define	MPI_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET		0x00000002
#define	MPI_SCSITASKMGMT_TASKTYPE_TARGET_RESET		0x00000003
#define	MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS		0x00000004
#define	MPI_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET	0x00000005

/*
 * MsgFlags bits
 */
#define	MPI_SCSITASKMGMT_MSGFLAGS_TARGET_RESET_OPTION	0x00000000
#define	MPI_SCSITASKMGMT_MSGFLAGS_LIP_RESET_OPTION	0x00000002
#define	MPI_SCSITASKMGMT_MSGFLAGS_LIPRESET_RESET_OPTION	0x00000004

/* SCSI Task Management Reply */

typedef struct msg_scsi_task_mgmt_reply {
	uint8_t			TargetID;
	uint8_t			Bus;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			Reserved;
	uint8_t			TaskType;
	uint8_t			Reserved1;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			Reserved2[2];
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint32_t		TerminationCount;
} msg_scsi_task_mgmt_reply_t;

/*
 * SCSI enclosure processor messages
 */
typedef struct msg_sep_request {
	uint8_t			TargetID;
	uint8_t			Bus;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Action;
	uint8_t			Reserved1;
	uint8_t			Reserved2;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint32_t		SlotStatus;
} msg_sep_request_t;

#define	MPI_SEP_REQ_ACTION_WRITE_STATUS			0x00
#define	MPI_SEP_REQ_ACTION_READ_STATUS			0x01

#define	MPI_SEP_REQ_SLOTSTATUS_NO_ERROR			0x00000001
#define	MPI_SEP_REQ_SLOTSTATUS_DEV_FAULTY		0x00000002
#define	MPI_SEP_REQ_SLOTSTATUS_DEV_REBUILDING		0x00000004

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MPI_INIT_H */
