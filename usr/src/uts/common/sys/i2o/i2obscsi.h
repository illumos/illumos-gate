/*
 * *****************************************************************************
 * I2O SIG All rights reserved.
 *
 * These header files are provided, pursuant to your I2O SIG membership
 * agreement, free of charge on an as-is basis without warranty of any kind,
 * either express or implied, including but not limited to, implied warranties
 * or merchantability and fitness for a particular purpose. I2O SIG does not
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
 * ***************************************************************************
 *
 * I2OBSCSI.h -- I2O Base SCSI Device Class Message defintion file
 *
 * This file contains information presented in Chapter 6, Section 6 & 7 of
 * the I2O Specification.
 *
 * ***************************************************************************
 */

/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_I2OBSCSI_H
#define	_SYS_I2OBSCSI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	I2OBSCSI_REV 1_5_1	/* Header file revision string */

/*
 * NOTES: See i2omsg.h for more info
 */

#include <sys/i2o/i2omsg.h>		/* Include the Base Message file */
#include <sys/types.h>		/* For system types defined */

/*
 * SCSI Peripheral Class specific functions
 *
 * Although the names are SCSI Peripheral class specific, the values
 * assigned are common with other classes when applicable.
 */

#define	I2O_SCSI_DEVICE_RESET	0x27
#define	I2O_SCSI_SCB_ABORT	0x83
#define	I2O_SCSI_SCB_EXEC	0x81

/*
 * Detailed Status Codes for SCSI operations
 *
 * The 16-bit Detailed Status Code field for SCSI operations is divided
 * into two separate 8-bit fields. The lower 8 bits are used to report
 * Device Status information. The upper 8 bits are used to report
 * Adapter Status information. The definitions for these two fields,
 * however, will be consistent with the standard reply message frame
 * structure declaration, which treats this as a single 16-bit field.
 */


/*
 * SCSI Device Completion Status Codes (defined by SCSI-2/3)
 */

#define	I2O_SCSI_DEVICE_DSC_MASK		0x00FF

#define	I2O_SCSI_DSC_SUCCESS			0x0000
#define	I2O_SCSI_DSC_CHECK_CONDITION		0x0002
#define	I2O_SCSI_DSC_BUSY			0x0008
#define	I2O_SCSI_DSC_RESERVATION_CONFLICT	0x0018
#define	I2O_SCSI_DSC_COMMAND_TERMINATED		0x0022
#define	I2O_SCSI_DSC_TASK_SET_FULL		0x0028
#define	I2O_SCSI_DSC_ACA_ACTIVE			0x0030

/*
 * SCSI Adapter Status Codes (based on CAM-1)
 */

#define	I2O_SCSI_HBA_DSC_MASK			0xFF00

#define	I2O_SCSI_HBA_DSC_SUCCESS		0x0000

#define	I2O_SCSI_HBA_DSC_REQUEST_ABORTED	0x0200
#define	I2O_SCSI_HBA_DSC_UNABLE_TO_ABORT	0x0300
#define	I2O_SCSI_HBA_DSC_COMPLETE_WITH_ERROR	0x0400
#define	I2O_SCSI_HBA_DSC_ADAPTER_BUSY		0x0500
#define	I2O_SCSI_HBA_DSC_REQUEST_INVALID	0x0600
#define	I2O_SCSI_HBA_DSC_PATH_INVALID		0x0700
#define	I2O_SCSI_HBA_DSC_DEVICE_NOT_PRESENT	0x0800
#define	I2O_SCSI_HBA_DSC_UNABLE_TO_TERMINATE	0x0900
#define	I2O_SCSI_HBA_DSC_SELECTION_TIMEOUT	0x0A00
#define	I2O_SCSI_HBA_DSC_COMMAND_TIMEOUT	0x0B00

#define	I2O_SCSI_HBA_DSC_MR_MESSAGE_RECEIVED	0x0D00
#define	I2O_SCSI_HBA_DSC_SCSI_BUS_RESET		0x0E00
#define	I2O_SCSI_HBA_DSC_PARITY_ERROR_FAILURE	0x0F00
#define	I2O_SCSI_HBA_DSC_AUTOSENSE_FAILED	0x1000
#define	I2O_SCSI_HBA_DSC_NO_ADAPTER		0x1100
#define	I2O_SCSI_HBA_DSC_DATA_OVERRUN		0x1200
#define	I2O_SCSI_HBA_DSC_UNEXPECTED_BUS_FREE	0x1300
#define	I2O_SCSI_HBA_DSC_SEQUENCE_FAILURE	0x1400
#define	I2O_SCSI_HBA_DSC_REQUEST_LENGTH_ERROR	0x1500
#define	I2O_SCSI_HBA_DSC_PROVIDE_FAILURE	0x1600
#define	I2O_SCSI_HBA_DSC_BDR_MESSAGE_SENT	0x1700
#define	I2O_SCSI_HBA_DSC_REQUEST_TERMINATED	0x1800

#define	I2O_SCSI_HBA_DSC_IDE_MESSAGE_SENT	0x3300
#define	I2O_SCSI_HBA_DSC_RESOURCE_UNAVAILABLE	0x3400
#define	I2O_SCSI_HBA_DSC_UNACKNOWLEDGED_EVENT	0x3500
#define	I2O_SCSI_HBA_DSC_MESSAGE_RECEIVED	0x3600
#define	I2O_SCSI_HBA_DSC_INVALID_CDB		0x3700
#define	I2O_SCSI_HBA_DSC_LUN_INVALID		0x3800
#define	I2O_SCSI_HBA_DSC_SCSI_TID_INVALID	0x3900
#define	I2O_SCSI_HBA_DSC_FUNCTION_UNAVAILABLE	0x3A00
#define	I2O_SCSI_HBA_DSC_NO_NEXUS		0x3B00
#define	I2O_SCSI_HBA_DSC_SCSI_IID_INVALID	0x3C00
#define	I2O_SCSI_HBA_DSC_CDB_RECEIVED		0x3D00
#define	I2O_SCSI_HBA_DSC_LUN_ALREADY_ENABLED	0x3E00
#define	I2O_SCSI_HBA_DSC_BUS_BUSY		0x3F00

#define	I2O_SCSI_HBA_DSC_QUEUE_FROZEN		0x4000

/*
 * SCSI Peripheral Device Parameter Groups
 */

/*
 * SCSI Configuration and Operating Structures and Defines
 */

#define	I2O_SCSI_DEVICE_INFO_GROUP_NO		0x0000
#define	I2O_SCSI_DEVICE_BUS_PORT_INFO_GROUP_NO	0x0001

/*
 * - 0000h - SCSI Device Information Parameters Group defines
 */

/*
 * Device Type
 */

#define	I2O_SCSI_DEVICE_TYPE_DIRECT		0x00
#define	I2O_SCSI_DEVICE_TYPE_SEQUENTIAL		0x01
#define	I2O_SCSI_DEVICE_TYPE_PRINTER		0x02
#define	I2O_SCSI_DEVICE_TYPE_PROCESSOR		0x03
#define	I2O_SCSI_DEVICE_TYPE_WORM		0x04
#define	I2O_SCSI_DEVICE_TYPE_CDROM		0x05
#define	I2O_SCSI_DEVICE_TYPE_SCANNER		0x06
#define	I2O_SCSI_DEVICE_TYPE_OPTICAL		0x07
#define	I2O_SCSI_DEVICE_TYPE_MEDIA_CHANGER	0x08
#define	I2O_SCSI_DEVICE_TYPE_COMM		0x09
#define	I2O_SCSI_DEVICE_GRAPHICS_1		0x0A
#define	I2O_SCSI_DEVICE_GRAPHICS_2		0x0B
#define	I2O_SCSI_DEVICE_TYPE_ARRAY_CONT		0x0C
#define	I2O_SCSI_DEVICE_TYPE_UNKNOWN		0x1F

/*
 * Flags
 */

#define	I2O_SCSI_PERIPHERAL_TYPE_FLAG		0x01
#define	I2O_SCSI_PERIPHERAL_TYPE_PARALLEL	0x00
#define	I2O_SCSI_PERIPHERAL_TYPE_SERIAL		0x01

#define	I2O_SCSI_RESERVED_FLAG			0x02

#define	I2O_SCSI_DISCONNECT_FLAG		0x04
#define	I2O_SCSI_DISABLE_DISCONNECT		0x00
#define	I2O_SCSI_ENABLE_DISCONNECT		0x04

#define	I2O_SCSI_MODE_MASK			0x18
#define	I2O_SCSI_MODE_SET_DATA			0x00
#define	I2O_SCSI_MODE_SET_DEFAULT		0x08
#define	I2O_SCSI_MODE_SET_SAFEST		0x10

#define	I2O_SCSI_DATA_WIDTH_MASK		0x60
#define	I2O_SCSI_DATA_WIDTH_8			0x00
#define	I2O_SCSI_DATA_WIDTH_16			0x20
#define	I2O_SCSI_DATA_WIDTH_32			0x40

#define	I2O_SCSI_SYNC_NEGOTIATION_FLAG		0x80
#define	I2O_SCSI_DISABLE_SYNC_NEGOTIATION	0x00
#define	I2O_SCSI_ENABLE_SYNC_NEGOTIATION	0x80

/*
 * - 0001h - SCSI Device Bus Port Info Parameters Group defines
 */

/*
 * Physical
 */

#define	I2O_SCSI_PORT_PHYS_OTHER		0x01
#define	I2O_SCSI_PORT_PHYS_UNKNOWN		0x02
#define	I2O_SCSI_PORT_PHYS_PARALLEL		0x03
#define	I2O_SCSI_PORT_PHYS_FIBRE_CHANNEL	0x04
#define	I2O_SCSI_PORT_PHYS_SERIAL_P1394		0x05
#define	I2O_SCSI_PORT_PHYS_SERIAL_SSA		0x06

/*
 * Electrical
 */

#define	I2O_SCSI_PORT_ELEC_OTHER		0x01
#define	I2O_SCSI_PORT_ELEC_UNKNOWN		0x02
#define	I2O_SCSI_PORT_ELEC_SINGLE_ENDED		0x03
#define	I2O_SCSI_PORT_ELEC_DIFFERENTIAL		0x04
#define	I2O_SCSI_PORT_ELEC_LOW_VOLT_DIFF	0x05
#define	I2O_SCSI_PORT_ELEC_OPTICAL		0x06

/*
 * Isochronous
 */

#define	I2O_SCSI_PORT_ISOC_NO			0x00
#define	I2O_SCSI_PORT_ISOC_YES			0x01
#define	I2O_SCSI_PORT_ISOC_UNKNOWN		0x02

/*
 * Connector Type
 */

#define	I2O_SCSI_PORT_CONN_OTHER		0x01
#define	I2O_SCSI_PORT_CONN_UNKNOWN		0x02
#define	I2O_SCSI_PORT_CONN_NONE			0x03
#define	I2O_SCSI_PORT_CONN_SHIELDED_A_HD	0x04
#define	I2O_SCSI_PORT_CONN_UNSHIELDED_A_HD	0x05
#define	I2O_SCSI_PORT_CONN_SHIELDED_A_LD	0x06
#define	I2O_SCSI_PORT_CONN_UNSHIELDED_A_LD	0x07
#define	I2O_SCSI_PORT_CONN_SHIELDED_P_HD	0x08
#define	I2O_SCSI_PORT_CONN_UNSHIELDED_P_HD	0x09
#define	I2O_SCSI_PORT_CONN_SCA_I		0x0A
#define	I2O_SCSI_PORT_CONN_SCA_II		0x0B
#define	I2O_SCSI_PORT_CONN_FC_DB9		0x0C
#define	I2O_SCSI_PORT_CONN_FC_FIBRE		0x0D
#define	I2O_SCSI_PORT_CONN_FC_SCA_II_40		0x0E
#define	I2O_SCSI_PORT_CONN_FC_SCA_II_20		0x0F
#define	I2O_SCSI_PORT_CONN_FC_BNC		0x10

/*
 * Connector Gender
 */

#define	I2O_SCSI_PORT_CONN_GENDER_OTHER		0x01
#define	I2O_SCSI_PORT_CONN_GENDER_UNKOWN	0x02
#define	I2O_SCSI_PORT_CONN_GENDER_FEMALE	0x03
#define	I2O_SCSI_PORT_CONN_GENDER_MALE		0x04


/*
 * SCSI Device Group 0000h - Device Information Parameter Group
 */

typedef struct i2o_scsi_device_info_scalar {
	uint8_t		DeviceType;
	uint8_t		Flags;
	uint16_t	Reserved2;
	uint32_t	Identifier;
	uint8_t		LunInfo[8]; /* SCSI2 8-bit scalar LUN goes into */
				    /*  offset 1 */
	uint32_t	QueueDepth;
	uint8_t		Reserved1a;
	uint8_t		NegOffset;
	uint8_t		NegDataWidth;
	uint8_t		Reserved1b;
	uint64_t	NegSyncRate;
} i2o_scsi_device_info_scalar_t;

/*
 * SCSI Device Group 0001h - Bus Port Information Parameter Group
 */

typedef struct i2o_scsi_bus_port_info_scalar {
	uint8_t		PhysicalInterface;
	uint8_t		ElectricalInterface;
	uint8_t		Isochronous;
	uint8_t		ConnectorType;
	uint8_t		ConnectorGender;
	uint8_t		Reserved1;
	uint16_t	Reserved2;
	uint32_t	MaxNumberDevices;
} i2o_scsi_bus_port_info_scalar_t;

/*
 * I2O SCSI Peripheral Event Indicator Assignment
 */

#define	I2O_SCSI_EVENT_SCSI_SMART	0x00000010

/*
 * SCSI Peripheral Class Specific Message Definitions
 */

/*
 * I2O SCSI Peripheral Successful Completion Reply Message Frame
 */

typedef struct i2o_scsi_success_reply_message_frame {
	i2o_single_reply_message_frame_t	StdReplyFrame;
	uint32_t				TransferCount;
} i2o_scsi_success_reply_message_frame_t;



/*
 * I2O SCSI Peripheral Error Report Reply Message Frame
 */

#define	I2O_SCSI_SENSE_DATA_SZ 40

typedef struct i2o_scsi_error_reply_message_frame {
    i2o_single_reply_message_frame_t	StdReplyFrame;
    uint32_t				TransferCount;
    uint32_t				AutoSenseTransferCount;
    uint8_t				SenseData[I2O_SCSI_SENSE_DATA_SZ];
} i2o_scsi_error_reply_message_frame_t;



/*
 * I2O SCSI Device Reset Message Frame
 */

typedef struct i2o_scsi_device_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_scsi_device_reset_message_t;



/*
 * I2O SCSI Control Block Abort Message Frame
 */

typedef struct i2o_scsi_scb_abort_message {
	i2o_message_frame_t 		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_transaction_context_t	TransactionContextToAbort;
} i2o_scsi_scb_abort_message_t;

/*
 * I2O SCSI Control Block Execute Message Frame
 */

#define	 I2O_SCSI_CDB_LENGTH 16

#define	I2O_SCB_FLAG_XFER_DIR_MASK		0xC000
#define	I2O_SCB_FLAG_NO_DATA_XFER		0x0000
#define	I2O_SCB_FLAG_XFER_FROM_DEVICE		0x4000
#define	I2O_SCB_FLAG_XFER_TO_DEVICE		0x8000

#define	I2O_SCB_FLAG_ENABLE_DISCONNECT		0x2000

#define	I2O_SCB_FLAG_TAG_TYPE_MASK		0x0380
#define	I2O_SCB_FLAG_NO_TAG_QUEUEING		0x0000
#define	I2O_SCB_FLAG_SIMPLE_QUEUE_TAG		0x0080
#define	I2O_SCB_FLAG_HEAD_QUEUE_TAG		0x0100
#define	I2O_SCB_FLAG_ORDERED_QUEUE_TAG		0x0180
#define	I2O_SCB_FLAG_ACA_QUEUE_TAG		0x0200

#define	I2O_SCB_FLAG_AUTOSENSE_MASK		0x0060
#define	I2O_SCB_FLAG_DISABLE_AUTOSENSE		0x0000
#define	I2O_SCB_FLAG_SENSE_DATA_IN_MESSAGE	0x0020
#define	I2O_SCB_FLAG_SENSE_DATA_IN_BUFFER	0x0060

typedef struct i2o_scsi_scb_execute_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	uint8_t				CDBLength;
	uint8_t				Reserved;
	uint16_t			SCBFlags;
	uint8_t				CDB[I2O_SCSI_CDB_LENGTH];
	uint32_t			ByteCount;
	i2o_sg_element_t		SGL;
} i2o_scsi_scb_execute_message_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_I2OBSCSI_H */
