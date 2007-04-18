/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

/*
 * **************************************************************************
 *
 * i2oadptr.h -- I2O Adapter Class Message defintion file
 *
 * This file contains information presented in Chapter 6 of
 * the I2o Specification.
 *
 * ***************************************************************************
 */

/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_I2OADPTR_H
#define	_SYS_I2OADPTR_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	I2OADPTR_REV 1_5_1	/* Header file revision string */

/*
 * NOTES: See i2omsg.h for more info
 */

#include <sys/i2o/i2omsg.h>		/* Include the Base Message file */
#include <sys/types.h>		/* For system types defines */



/*
 * BUS ADAPTER CLASS SPECIFIC FUNCTIONS
 */

#define	I2O_HBA_ADAPTER_RESET	0x85
#define	I2O_HBA_BUS_QUIESCE	0x8b
#define	I2O_HBA_BUS_RESET	0x87
#define	I2O_HBA_BUS_SCAN	0x89


/*
 * Detailed Status Codes for HBA operations
 *
 * Note:
 * The 16-bit Detailed Status Code field for HBA operations is divided
 * into two separate 8-bit fields. The lower 8 bits are reserved. The
 * upper 8 bits are used to report Adapter Status information. The
 * definitions for these two fields, however, will be consistent with
 * the standard reply message frame structure declaration, which treats
 * this as a single 16-bit field. In addition, the values used will be
 * consistent with the Adapter Status codes defined for the SCSI
 * Peripheral class. Theses codes are based on CAM-1. In other words,
 * these definitions are a subset of the SCSI peripheral class codes.
 * Where applicable, "SCSI" has been removed from the definition.
 *
 */

#define	I2O_HBA_DSC_MASK			0xFF00

#define	I2O_HBA_DSC_SUCCESS			0x0000
#define	I2O_HBA_DSC_ADAPTER_BUSY		0x0500
#define	I2O_HBA_DSC_COMMAND_TIMEOUT		0x0B00
#define	I2O_HBA_DSC_COMPLETE_WITH_ERROR		0x0400
#define	I2O_HBA_DSC_FUNCTION_UNAVAILABLE	0x3A00
#define	I2O_HBA_DSC_NO_ADAPTER			0x1100
#define	I2O_HBA_DSC_PARITY_ERROR_FAILURE	0x0F00
#define	I2O_HBA_DSC_PATH_INVALID		0x0700
#define	I2O_HBA_DSC_PROVIDE_FAILURE		0x1600
#define	I2O_HBA_DSC_QUEUE_FROZEN		0x4000
#define	I2O_HBA_DSC_REQUEST_ABORTED		0x0200
#define	I2O_HBA_DSC_REQUEST_INVALID		0x0600
#define	I2O_HBA_DSC_REQUEST_LENGTH_ERROR	0x1500
#define	I2O_HBA_DSC_REQUEST_TERMINATED		0x1800
#define	I2O_HBA_DSC_RESOURCE_UNAVAILABLE	0x3400
#define	I2O_HBA_DSC_BUS_BUSY			0x3F00
#define	I2O_HBA_DSC_BUS_RESET			0x0E00
#define	I2O_HBA_DSC_ID_INVALID			0x3900
#define	I2O_HBA_DSC_SEQUENCE_FAILURE		0x1400
#define	I2O_HBA_DSC_UNABLE_TO_ABORT		0x0300
#define	I2O_HBA_DSC_UNABLE_TO_TERMINATE		0x0900
#define	I2O_HBA_DSC_UNACKNOWLEDGED_EVENT	0x3500
#define	I2O_HBA_DSC_UNEXPECTED_BUS_FREE		0x1300

/*
 * Bus Adapter Parameter Groups
 */

#define	 I2O_HBA_CONTROLLER_INFO_GROUP_NO	0x0000
#define	 I2O_HBA_HISTORICAL_STATS_GROUP_NO	0x0100
#define	 I2O_HBA_SCSI_CONTROLLER_INFO_GROUP_NO	0x0200
#define	 I2O_HBA_SCSI_BUS_PORT_INFO_GROUP_NO	0x0201
#define	 I2O_HBA_FCA_CONTROLLER_INFO_GROUP_NO	0x0300
#define	 I2O_HBA_FCA_PORT_INFO_GROUP_NO	0x0301

/*
 * - 0000h - HBA Controller Information Parameter Group
 */

/*
 * Bus Type
 */

#define	 I2O_HBA_BUS_TYPE_GENERIC	0x00
#define	 I2O_HBA_BUS_TYPE_SCSI		0x01
#define	 I2O_HBA_BUS_TYPE_FCA		0x10

typedef struct i2o_hba_controller_info_scalar {
	uint8_t		BusType;
	uint8_t		BusState;
	uint16_t	Reserved2;
	uint8_t		BusName[12];
} i2o_hba_controller_info_scalar_t;

/*
 * - 0100h - HBA Historical Stats Parameter Group
 */

typedef struct i2o_hba_hist_stats_scalar {
	uint32_t	TimeLastPoweredUp;
	uint32_t	TimeLastReset;
} i2o_hba_hist_stats_scalar_t;

/*
 * - 0200h - HBA SCSI Controller Information Parameter Group
 */

/*
 * SCSI Type
 */

#define	I2O_SCSI_TYPE_UNKNOWN	0x00
#define	I2O_SCSI_TYPE_SCSI_1	0x01
#define	I2O_SCSI_TYPE_SCSI_2	0x02
#define	I2O_SCSI_TYPE_SCSI_3	0x03

/*
 * Protection Management
 */

#define	 I2O_SCSI_PORT_PROT_OTHER	0x00
#define	 I2O_SCSI_PORT_PROT_UNKNOWN	0x01
#define	 I2O_SCSI_PORT_PROT_UNPROTECTED	0x02
#define	 I2O_SCSI_PORT_PROT_PROTECTED	0x03
#define	 I2O_SCSI_PORT_PROT_SCC	0x04

/*
 * Settings
 */

#define	 I2O_SCSI_PORT_PARITY_FLAG	0x01
#define	 I2O_SCSI_PORT_PARITY_DISABLED	0x00
#define	 I2O_SCSI_PORT_PARITY_ENABLED	0x01

#define	 I2O_SCSI_PORT_SCAN_ORDER_FLAG	0x02
#define	 I2O_SCSI_PORT_SCAN_LOW_TO_HIGH	0x00
#define	 I2O_SCSI_PORT_SCAN_HIGH_TO_LOW	0x02

#define	 I2O_SCSI_PORT_IID_FLAG		0x04
#define	 I2O_SCSI_PORT_IID_DEFAULT	0x00
#define	 I2O_SCSI_PORT_IID_SPECIFIED	0x04

#define	 I2O_SCSI_PORT_SCAM_FLAG	0x08
#define	 I2O_SCSI_PORT_SCAM_DISABLED	0x00
#define	 I2O_SCSI_PORT_SCAM_ENABLED	0x08

#define	 I2O_SCSI_PORT_TYPE_FLAG	0x80
#define	 I2O_SCSI_PORT_TYPE_PARALLEL	0x00
#define	 I2O_SCSI_PORT_TYPE_SERIAL	0x80

typedef struct i2o_hba_scsi_controller_info_scalar {
	uint8_t		SCSIType;
	uint8_t		ProtectionManagement;
	uint8_t		Settings;
	uint8_t		Reserved1;
	uint32_t	InitiatorID;
	uint64_t	ScanLun0Only;
	uint16_t	DisableDevice;
	uint8_t		MaxOffset;
	uint8_t		MaxDataWidth;
	uint64_t	MaxSyncRate;
} i2o_hba_scsi_controller_info_scalar_t;

/*
 * - 0201h - HBA SCSI Bus Port Information Parameter Group
 */

/*
 * NOTE: Refer to the SCSI Peripheral Class Bus Port Information
 * Parameter Group field definitions for HBA SCSI Bus Port
 * field definitions.
 */

typedef struct i2o_hba_scsi_bus_port_info_scalar {
	uint8_t		PhysicalInterface;
	uint8_t		ElectricalInterface;
	uint8_t		Isochronous;
	uint8_t		ConnectorType;
	uint8_t		ConnectorGender;
	uint8_t		Reserved1;
	uint16_t	Reserved2;
	uint32_t	MaxNumberDevices;
	uint32_t	DeviceIdBegin;
	uint32_t	DeviceIdEnd;
	uint8_t		LunBegin[8];
	uint8_t		LunEnd[8];
} i2o_hba_scsi_bus_port_info_scalar_t;

/*
 * - 0300h - HBA FCA Controller Information Parameters Group defines
 */

/*
 * SCSI Type
 */

#define	I2O_FCA_TYPE_UNKNOWN	0x00
#define	I2O_FCA_TYPE_FCAL	0x01

typedef struct i2o_hba_fca_controller_info_scalar {
	uint8_t		FcaType;
	uint8_t		Reserved1;
	uint16_t	Reserved2;
} i2o_hba_fca_controller_info_scalar_t;

/*
 * - 0301h - HBA FCA Port Information Parameters Group defines
 */

typedef struct i2o_hba_fca_port_info_scalar {
	uint32_t	Reserved4;
} i2o_hba_fca_port_info_scalar_t;

/*
 * I2O BUS ADAPTER CLASS SPECIFIC MESSAGE DEFINITIONS
 */

/*
 * I2O Bus Adapter Class Reply Message Frame
 */

typedef struct i2o_hba_reply_message_frame {
	i2o_single_reply_message_frame_t	StdReplyFrame;
} i2o_hba_reply_message_frame_t;

/*
 * I2O HBA Adapter Reset Message Frame
 */

typedef struct i2o_hba_adapter_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_hba_adapter_reset_message_t;

/*
 * I2O HBA Bus Quiesce Message Frame
 */

typedef	uint32_t i2o_hbq_flags_t;

#define	I2O_HBQ_FLAG_NORMAL	0x0000
#define	I2O_HBQ_FLAG_QUIESCE	0x0001

typedef struct i2o_hba_bus_quiesce_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
	i2o_hbq_flags_t			Flags;
} i2o_hba_bus_quiesce_message_t;

/*
 * I2O HBA Bus Reset Message Frame
 */

typedef struct i2o_hba_bus_reset_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_hba_bus_reset_message_t;

/*
 * I2O HBA Bus Scan Message Frame
 */

/*
 * NOTE: SCSI-2 8-bit scalar LUN goes into offset 1 of Lun arrays
 */

typedef struct i2o_hba_bus_scan_message {
	i2o_message_frame_t		StdMessageFrame;
	i2o_transaction_context_t	TransactionContext;
} i2o_hba_bus_scan_message_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_I2OADPTR_H */
