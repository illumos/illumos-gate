/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MPI_IOC_H
#define	_SYS_MPI_IOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * IOCInit message
 */
typedef struct msg_ioc_init {
	uint8_t			WhoInit;
	uint8_t			Reserved;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Flags;
	uint8_t			MaxDevices;
	uint8_t			MaxBuses;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		ReplyFrameSize;
	uint8_t			Reserved1[2];
	uint32_t		HostMfaHighAddr;
	uint32_t		SenseBufferHighAddr;
	/* following used in new mpi implementations */
	uint32_t		ReplyFifoHostSignalingAddr;
	sge_simple_union_t	HostPageBufferSGE;
	uint16_t		MsgVersion;
	uint16_t		HeaderVersion;
} msg_ioc_init_t;

typedef struct msg_ioc_init_reply {
	uint8_t			WhoInit;
	uint8_t			Reserved;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			Flags;
	uint8_t			MaxDevices;
	uint8_t			MaxBuses;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		Reserved2;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
} msg_ioc_init_reply_t;

/*
 *  WhoInit values
 */
#define	MPI_WHOINIT_NO_ONE			0x00
#define	MPI_WHOINIT_SYSTEM_BIOS			0x01
#define	MPI_WHOINIT_ROM_BIOS			0x02
#define	MPI_WHOINIT_PCI_PEER			0x03
#define	MPI_WHOINIT_HOST_DRIVER			0x04
#define	MPI_WHOINIT_MANUFACTURER		0x05

/*
 * Flags values
 */
#define	MPI_IOCINIT_FLAGS_DISCARD_FW_IMAGE		0x01
#define	MPI_IOCINIT_FLAGS_REPLY_FIFO_HOST_SIGNAL	0x02

#define	MPI_IOCINIT_MSGVERSION_MAJOR_MASK	(0xFF00)
#define	MPI_IOCINIT_MSGVERSION_MAJOR_SHIFT	(8)
#define	MPI_IOCINIT_MSGVERSION_MINOR_MASK	(0x00FF)
#define	MPI_IOCINIT_MSGVERSION_MINOR_SHIFT	(0)

#define	MPI_IOCINIT_HEADERVERSION_UNIT_MASK	(0xFF00)
#define	MPI_IOCINIT_HEADERVERSION_UNIT_SHIFT	(8)
#define	MPI_IOCINIT_HEADERVERSION_DEV_MASK	(0x00FF)
#define	MPI_IOCINIT_HEADERVERSION_DEV_SHIFT	(0)


/*
 * IOC Facts message
 */
typedef struct msg_ioc_facts {
	uint8_t			Reserved[2];
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
} msg_ioc_facts_t;

/*
 * FW version
 */
typedef struct mpi_fw_version_struct {
	uint8_t			Dev;
	uint8_t			Unit;
	uint8_t			Minor;
	uint8_t			Major;
} mpi_fw_version_struct_t;

typedef union mpi_fw_version {
	mpi_fw_version_struct_t	Struct;
	uint32_t		Word;
} mpi_fw_version_t;

/*
 * IOC Facts Reply
 */
typedef struct msg_ioc_facts_reply {
	uint16_t		MsgVersion;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint16_t		HeaderVersion;
	uint8_t			IOCNumber;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		IOCExceptions;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint8_t			MaxChainDepth;
	uint8_t			WhoInit;
	uint8_t			BlockSize;
	uint8_t			Flags;
	uint16_t		ReplyQueueDepth;
	uint16_t		RequestFrameSize;
	uint16_t		Reserved_0101_FWVersion; /* obsolete */
	uint16_t		ProductID;
	uint32_t		CurrentHostMfaHighAddr;
	uint16_t		GlobalCredits;
	uint8_t			NumberOfPorts;
	uint8_t			EventState;
	uint32_t		CurrentSenseBufferHighAddr;
	uint16_t		CurReplyFrameSize;
	uint8_t			MaxDevices;
	uint8_t			MaxBuses;
	uint32_t		FWImageSize;
	uint32_t		IOCCapabilities;
	mpi_fw_version_t	FWVersion;
	/* following used in newer mpi implementations */
	uint16_t		HighPriorityQueueDepth;
	uint16_t		Reserved2;
	sge_simple_union_t	HostPageBufferSGE;
} msg_ioc_facts_reply_t;

#define	MPI_IOCFACTS_MSGVERSION_MAJOR_MASK	0xFF00
#define	MPI_IOCFACTS_MSGVERSION_MINOR_MASK	0x00FF

#define	MPI_IOCFACTS_HEADERVERSION_UNIT_MASK	0xFF00
#define	MPI_IOCFACTS_HEADERVERSION_DEV_MASK	0x00FF

#define	MPI_IOCFACTS_EXCEPT_CONFIG_CHECKSUM_FAIL	0x0001
#define	MPI_IOCFACTS_EXCEPT_RAID_CONFIG_INVALID		0x0002
#define	MPI_IOCFACTS_EXCEPT_FW_CHECKSUM_FAIL		0x0004
#define	MPI_IOCFACTS_EXCEPT_PERSISTENT_TABLE_FULL	0x0008

#define	MPI_IOCFACTS_FLAGS_FW_DOWNLOAD_BOOT	0x01

#define	MPI_IOCFACTS_EVENTSTATE_DISABLED	0x00
#define	MPI_IOCFACTS_EVENTSTATE_ENABLED		0x01

#define	MPI_IOCFACTS_CAPABILITY_HIGH_PRI_Q		0x00000001
#define	MPI_IOCFACTS_CAPABILITY_REPLY_HOST_SIGNAL	0x00000002
#define	MPI_IOCFACTS_CAPABILITY_QUEUE_FULL_HANDLING	0x00000004
#define	MPI_IOCFACTS_CAPABILITY_DIAG_TRACE_BUFFER	0x00000008
#define	MPI_IOCFACTS_CAPABILITY_SNAPSHOT_BUFFER		0x00000010
#define	MPI_IOCFACTS_CAPABILITY_EXTENDED_BUFFER		0x00000020
#define	MPI_IOCFACTS_CAPABILITY_EEDP			0x00000040

/*
 * Port Facts message and Reply
 */
typedef struct msg_port_facts {
	uint8_t			Reserved[2];
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[2];
	uint8_t			PortNumber;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
} msg_port_facts_t;

typedef struct msg_port_facts_reply {
	uint16_t		Reserved;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint16_t		Reserved1;
	uint8_t			PortNumber;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		Reserved2;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint8_t			Reserved3;
	uint8_t			PortType;
	uint16_t		MaxDevices;
	uint16_t		PortSCSIID;
	uint16_t		ProtocolFlags;
	uint16_t		MaxPostedCmdBuffers;
	uint16_t		MaxPersistentIDs;
	uint16_t		MaxLanBuckets;
	uint16_t		Reserved4;
	uint32_t		Reserved5;
} msg_port_facts_reply_t;

/*
 * PortTypes values
 */
#define	MPI_PORTFACTS_PORTTYPE_INACTIVE		0x00
#define	MPI_PORTFACTS_PORTTYPE_SCSI		0x01
#define	MPI_PORTFACTS_PORTTYPE_FC		0x10
#define	MPI_PORTFACTS_PORTTYPE_ISCSI		0x20
#define	MPI_PORTFACTS_PORTTYPE_SAS		0x30

/*
 * ProtocolFlags values
 */
#define	MPI_PORTFACTS_PROTOCOL_LOGBUSADDR	0x01
#define	MPI_PORTFACTS_PROTOCOL_LAN		0x02
#define	MPI_PORTFACTS_PROTOCOL_TARGET		0x04
#define	MPI_PORTFACTS_PROTOCOL_INITIATOR	0x08

/*
 * Port Enable Message
 */
typedef struct msg_port_enable {
	uint8_t			Reserved[2];
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[2];
	uint8_t			PortNumber;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
} msg_port_enable_t;

typedef struct msg_port_enable_reply {
	uint8_t			Reserved[2];
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			Reserved1[2];
	uint8_t			PortNumber;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		Reserved2;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
} msg_port_enable_reply_t;


/*
 * Event Notification messages
 */
typedef struct msg_event_notify {
	uint8_t			Switch;
	uint8_t			Reserved;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
} msg_event_notify_t;

/*
 * Event Notification Reply
 */
typedef struct msg_event_notify_reply {
	uint16_t		EventDataLength;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			Reserved1[2];
	uint8_t			AckRequired;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			Reserved2[2];
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint32_t		Event;
	uint32_t		EventContext;
	uint32_t		Data[1];
} msg_event_notify_reply_t;

/*
 * Event Acknowledge
 */
typedef struct msg_event_ack {
	uint8_t			Reserved[2];
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint32_t		Event;
	uint32_t		EventContext;
} msg_event_ack_t;

typedef struct msg_event_ack_reply {
	uint8_t			Reserved[2];
	uint8_t			Function;
	uint8_t			MsgLength;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		Reserved2;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
} msg_event_ack_reply_t;

/*
 * Switch
 */
#define	MPI_EVENT_NOTIFICATION_SWITCH_OFF	0x00
#define	MPI_EVENT_NOTIFICATION_SWITCH_ON	0x01

/*
 * Event
 */
#define	MPI_EVENT_NONE				0x00000000
#define	MPI_EVENT_LOG_DATA			0x00000001
#define	MPI_EVENT_STATE_CHANGE			0x00000002
#define	MPI_EVENT_UNIT_ATTENTION		0x00000003
#define	MPI_EVENT_IOC_BUS_RESET			0x00000004
#define	MPI_EVENT_EXT_BUS_RESET			0x00000005
#define	MPI_EVENT_RESCAN			0x00000006
#define	MPI_EVENT_LINK_STATUS_CHANGE		0x00000007
#define	MPI_EVENT_LOOP_STATE_CHANGE		0x00000008
#define	MPI_EVENT_LOGOUT			0x00000009
#define	MPI_EVENT_EVENT_CHANGE			0x0000000A
#define	MPI_EVENT_INTEGRATED_RAID		0x0000000B
#define	MPI_EVENT_SCSI_DEVICE_STATUS_CHANGE	0x0000000C
#define	MPI_EVENT_ON_BUS_TIMER_EXPIRED		0x0000000D
#define	MPI_EVENT_QUEUE_FULL			0x0000000E
#define	MPI_EVENT_SAS_DEVICE_STATUS_CHANGE	0x0000000F
#define	MPI_EVENT_SAS_SES			0x00000010
#define	MPI_EVENT_PERSISTENT_TABLE_FULL		0x00000011
#define	MPI_EVENT_SAS_PHY_LINK_STATUS		0x00000012
#define	MPI_EVENT_SAS_DISCOVERY_ERROR		0x00000013
#define	MPI_EVENT_IR_RESYNC_UPDATE		0x00000014
#define	MPI_EVENT_IR2				0x00000015
#define	MPI_EVENT_SAS_DISCOVERY			0x00000016
#define	MPI_EVENT_SAS_BROADCAST_PRIMITIVE	0x00000017
#define	MPI_EVENT_SAS_INIT_DEVICE_STATUS_CHANGE	0x00000018
#define	MPI_EVENT_SAS_INIT_TABLE_OVERFLOW	0x00000019
#define	MPI_EVENT_SAS_SMP_ERROR			0x0000001A
#define	MPI_EVENT_SAS_EXPANDER_STATUS_CHANGE	0x0000001B
#define	MPI_EVENT_LOG_ENTRY_ADDED		0x00000021

/*
 * AckRequired field values
 */
#define	MPI_EVENT_NOTIFICATION_ACK_NOT_REQUIRED	0x00
#define	MPI_EVENT_NOTIFICATION_ACK_REQUIRED	0x01

/*
 * Eventchange event data
 */
typedef struct event_data_event_change {
	uint8_t			EventState;
	uint8_t			Reserved;
	uint16_t		Reserved1;
} event_data_event_change_t;

/*
 * SCSI Event data for Port, Bus and Device forms)
 */
typedef struct event_data_scsi {
	uint8_t			TargetID;
	uint8_t			BusPort;
	uint16_t		Reserved;
} event_data_scsi_t;

/*
 * SCSI Device Status Change Event data
 */
typedef struct event_data_scsi_device_status_change {
	uint8_t			TargetID;
	uint8_t			Bus;
	uint8_t			ReasonCode;
	uint8_t			LUN;
	uint8_t			ASC;
	uint8_t			ASCQ;
	uint16_t		Reserved;
} event_data_scsi_device_status_change_t;

/*
 * SCSI Device Status Change Event data ReasonCode values
 */
#define	MPI_EVENT_SCSI_DEV_STAT_RC_ADDED		0x03
#define	MPI_EVENT_SCSI_DEV_STAT_RC_NOT_RESPONDING	0x04
#define	MPI_EVENT_SCSI_DEV_STAT_RC_SMART_DATA		0x05

/*
 * SAS Device Status Change event data
 */
typedef struct event_data_sas_device_status_change {
	uint8_t		TargetID;
	uint8_t		Bus;
	uint8_t		ReasonCode;
	uint8_t		Reserved;
	uint8_t		ASC;
	uint8_t		ASCQ;
	uint16_t	DevHandle;
	uint32_t	DeviceInfo;
	uint16_t	ParentDevHandle;
	uint8_t		PhyNum;
	uint8_t		Reserved1;
	uint64_t	SASAddress;
} event_data_sas_device_status_change_t;

#define	MPI_EVENT_SAS_DEV_STAT_RC_ADDED			0x03
#define	MPI_EVENT_SAS_DEV_STAT_RC_NOT_RESPONDING	0x04
#define	MPI_EVENT_SAS_DEV_STAT_RC_SMART_DATA		0x05
#define	MPI_EVENT_SAS_DEV_STAT_RC_NO_PERSIST_ADDED	0x06

/*
 * SCSI event data for queue full event
 */
typedef struct event_data_queue_full {
	uint8_t		TargetID;
	uint8_t		Bus;
	uint16_t	CurrentDepth;
} event_data_queue_full_t;

/*
 * MPI Link Status Change Event data
 */
typedef struct event_data_link_status {
	uint8_t			State;
	uint8_t			Reserved;
	uint16_t		Reserved1;
	uint8_t			Reserved2;
	uint8_t			Port;
	uint16_t		Reserved3;
} event_data_link_status_t;

#define	MPI_EVENT_LINK_STATUS_FAILURE		0x00000000
#define	MPI_EVENT_LINK_STATUS_ACTIVE		0x00000001

/* MPI Loop State Change Event data */

typedef struct event_data_loop_state {
	uint8_t			Character4;
	uint8_t			Character3;
	uint8_t			Type;
	uint8_t			Reserved;
	uint8_t			Reserved1;
	uint8_t			Port;
	uint16_t		Reserved2;
} event_data_loop_state_t;

#define	MPI_EVENT_LOOP_STATE_CHANGE_LIP		0x0001
#define	MPI_EVENT_LOOP_STATE_CHANGE_LPE		0x0002
#define	MPI_EVENT_LOOP_STATE_CHANGE_LPB		0x0003

/*
 * MPI LOGOUT Event data
 */
typedef struct event_data_logout {
	uint32_t		NPortID;
	uint8_t			Reserved;
	uint8_t			Port;
	uint16_t		Reserved1;
} event_data_logout_t;

/*
 * MPI RAID Status Change Event Data
 */
typedef struct event_data_raid {
	uint8_t			VolumeID;
	uint8_t			VolumeBus;
	uint8_t			ReasonCode;
	uint8_t			PhysDiskNum;
	uint8_t			ASC;
	uint8_t			ASCQ;
	uint16_t		Reserved;
	uint32_t		SettingsStatus;
} event_data_raid_t;

/* MPI RAID Status Change Event data ReasonCode values */
#define	MPI_EVENT_RAID_RC_VOLUME_CREATED		0x00
#define	MPI_EVENT_RAID_RC_VOLUME_DELETED		0x01
#define	MPI_EVENT_RAID_RC_VOLUME_SETTINGS_CHANGED	0x02
#define	MPI_EVENT_RAID_RC_VOLUME_STATUS_CHANGED		0x03
#define	MPI_EVENT_RAID_RC_VOLUME_PHYSDISK_CHANGED	0x04
#define	MPI_EVENT_RAID_RC_PHYSDISK_CREATED		0x05
#define	MPI_EVENT_RAID_RC_PHYSDISK_DELETED		0x06
#define	MPI_EVENT_RAID_RC_PHYSDISK_SETTINGS_CHANGED	0x07
#define	MPI_EVENT_RAID_RC_PHYSDISK_STATUS_CHANGED	0x08
#define	MPI_EVENT_RAID_RC_DOMAIN_VAL_NEEDED		0x09
#define	MPI_EVENT_RAID_RC_SMART_DATA			0x0A
#define	MPI_EVENT_RAID_RC_REPLACE_ACTION_STARTED	0x0B

/*
 * SAS Phy link down event data
 */
typedef struct event_data_sas_phy_link_status {
	uint8_t		PhyNum;
	uint8_t		LinkRates;
	uint16_t	DevHandle;
	uint64_t	SASAddress;
} event_data_sas_phy_link_status_t;

#define	MPI_EVENT_SAS_PLS_LR_CURRENT_MASK			0xF0
#define	MPI_EVENT_SAS_PLS_LR_CURRENT_SHIFT			4
#define	MPI_EVENT_SAS_PLS_LR_PREVIOUS_MASK			0x0F
#define	MPI_EVENT_SAS_PLS_LR_PREVIOUS_SHIFT			0
#define	MPI_EVENT_SAS_PLS_LR_RATE_UNKNOWN			0x00
#define	MPI_EVENT_SAS_PLS_LR_RATE_PHY_DISABLED			0x01
#define	MPI_EVENT_SAS_PLS_LR_RATE_FAILED_SPEED_NEGOTIATION	0x02
#define	MPI_EVENT_SAS_PLS_LR_RATE_SATA_OOB_COMPLETE		0x03
#define	MPI_EVENT_SAS_PLS_LR_RATE_1_5				0x08
#define	MPI_EVENT_SAS_PLS_LR_RATE_3_0				0x09

/*
 * sas discovery error structure
 */
typedef struct event_data_sas_discovery_error {
	uint32_t	DiscoveryStatus;
	uint8_t		Port;
	uint8_t		Reserved[3];
} event_data_sas_discovery_error_t;

/*
 * values for DiscoveryStatus field of SAS Discovery Error Event Data
 */

#define	MPI_EVENT_SAS_DE_DS_LOOP_DETECTED		0x00000001
#define	MPI_EVENT_SAS_DE_DS_UNADDRESSABLE_DEVICE	0x00000002
#define	MPI_EVENT_SAS_DE_DS_MULTIPLE_PORTS		0x00000004
#define	MPI_EVENT_SAS_DE_DS_EXPANDER_ERR		0x00000008
#define	MPI_EVENT_SAS_DE_DS_SMP_TIMEOUT			0x00000010
#define	MPI_EVENT_SAS_DE_DS_OUT_ROUTE_ENTRIES		0x00000020
#define	MPI_EVENT_SAS_DE_DS_INDEX_NOT_EXIST		0x00000040
#define	MPI_EVENT_SAS_DE_DS_SMP_FUNCTION_FAILED		0x00000080
#define	MPI_EVENT_SAS_DE_DS_SMP_CRC_ERR			0x00000100
#define	MPI_EVENT_SAS_DE_DS_MULTIPLE_SUBTRACTIVE	0x00000200
#define	MPI_EVENT_SAS_DE_DS_TABLE_TO_TABLE		0x00000400
#define	MPI_EVENT_SAS_DE_DS_MULTIPLE_PATHS		0x00000800
#define	MPI_EVENT_SAS_DE_DS_MAX_SATA_TARGS		0x00001000

typedef struct event_data_sas_expander_status_change {
	uint8_t		ReasonCode;
	uint8_t		Reserved1;
	uint16_t	Reserved2;
	uint8_t		PhysicalPort;
	uint8_t		Reserved3;
	uint16_t	EnclosureHandle;
	uint64_t	SASAddress;
	uint32_t	DiscoveryStatus;
	uint16_t	DevHandle;
	uint16_t	ParentDevHandle;
	uint16_t	ExpanderChangeCount;
	uint16_t	ExpanderRouteIndexes;
	uint8_t		NumPhys;
	uint8_t		SASLevel;
	uint8_t		Flags;
	uint8_t		Reserved4;
} event_data_sas_expander_status_change_t;

/*
 * values for ReasonCode field of SAS Expander Status Change Event data
 */
#define	MPI_EVENT_SAS_EXP_RC_ADDED		0x00
#define	MPI_EVENT_SAS_EXP_RC_NOT_RESPONDING	0x01

/*
 * values for DiscoveryStatus field of SAS Expander Status Change Event data
 */
#define	MPI_EVENT_SAS_EXP_DS_LOOP_DETECTED		0x00000001
#define	MPI_EVENT_SAS_EXP_DS_UNADDRESSABLE_DEVICE	0x00000002
#define	MPI_EVENT_SAS_EXP_DS_MULTIPLE_PORTS		0x00000004
#define	MPI_EVENT_SAS_EXP_DS_EXPANDER_ERR		0x00000008
#define	MPI_EVENT_SAS_EXP_DS_SMP_TIMEOUT		0x00000010
#define	MPI_EVENT_SAS_EXP_DS_OUT_ROUTE_ENTRIES		0x00000020
#define	MPI_EVENT_SAS_EXP_DS_INDEX_NOT_EXIST		0x00000040
#define	MPI_EVENT_SAS_EXP_DS_SMP_FUNCTION_FAILED	0x00000080
#define	MPI_EVENT_SAS_EXP_DS_SMP_CRC_ERROR		0x00000100
#define	MPI_EVENT_SAS_EXP_DS_SUBTRACTIVE_LINK		0x00000200
#define	MPI_EVENT_SAS_EXP_DS_TABLE_LINK			0x00000400
#define	MPI_EVENT_SAS_EXP_DS_UNSUPPORTED_DEVICE		0x00000800

/*
 *  values for Flags field of SAS Expander Status Change Event data
 */
#define	MPI_EVENT_SAS_EXP_FLAGS_ROUTE_TABLE_CONFIG	0x02
#define	MPI_EVENT_SAS_EXP_FLAGS_CONFIG_IN_PROGRESS	0x01


/*
 * Firmware Load Messages
 */

/*
 * Firmware download message and associated structures
 */
typedef struct msg_fw_download {
	uint8_t			ImageType;
	uint8_t			Reserved;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	sge_mpi_union_t		SGL;
} msg_fw_download_t;

#define	MPI_FW_DOWNLOAD_MSGFLGS_LAST_SEGMENT	0x01

#define	MPI_FW_DOWNLOAD_ITYPE_RESERVED		0x00
#define	MPI_FW_DOWNLOAD_ITYPE_FW		0x01
#define	MPI_FW_DOWNLOAD_ITYPE_BIOS		0x02
#define	MPI_FW_DOWNLOAD_ITYPE_NVDATA		0x03
#define	MPI_FW_DOWNLOAD_ITYPE_BOOTLOADER	0x04

typedef struct fw_download_tcsge {
	uint8_t			Reserved;
	uint8_t			ContextSize;
	uint8_t			DetailsLength;
	uint8_t			Flags;
	uint32_t		Reserved_0100_Checksum; /* obsolete */
	uint32_t		ImageOffset;
	uint32_t		ImageSize;
} fw_download_tcsge_t;

typedef struct msg_fw_download_reply {
	uint8_t			ImageType;
	uint8_t			Reserved;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		Reserved2;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
} msg_fw_download_reply_t;

/*
 * Firmware upload messages and associated structures
 */
typedef struct msg_fw_upload {
	uint8_t			ImageType;
	uint8_t			Reserved;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	sge_mpi_union_t		SGL;
} msg_fw_upload_t;

#define	MPI_FW_UPLOAD_ITYPE_FW_IOC_MEM	0x00
#define	MPI_FW_UPLOAD_ITYPE_FW_FLASH	0x01
#define	MPI_FW_UPLOAD_ITYPE_BIOS_FLASH	0x02
#define	MPI_FW_UPLOAD_ITYPE_NVDATA	0x03
#define	MPI_FW_UPLOAD_ITYPE_BOOTLOADER	0x04

typedef struct fw_upload_tcsge {
	uint8_t			Reserved;
	uint8_t			ContextSize;
	uint8_t			DetailsLength;
	uint8_t			Flags;
	uint32_t		Reserved1;
	uint32_t		ImageOffset;
	uint32_t		ImageSize;
} fw_upload_tcsge_t;

typedef struct msg_fw_upload_reply {
	uint8_t			ImageType;
	uint8_t			Reserved;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint8_t			Reserved1[3];
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint16_t		Reserved2;
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	uint32_t		ActualImageSize;
} msg_fw_upload_reply_t;

typedef struct msg_fw_header {
	uint32_t		ArmBranchInstruction0;
	uint32_t		Signature0;
	uint32_t		Signature1;
	uint32_t		Signature2;
	uint32_t		ArmBranchInstruction1;
	uint32_t		ArmBranchInstruction2;
	uint32_t		Reserved;
	uint32_t		Checksum;
	uint16_t		VendorId;
	uint16_t		ProductId;
	mpi_fw_version_t	FWVersion;
	uint32_t		SeqCodeVersion;
	uint32_t		ImageSize;
	uint32_t		NextImageHeaderOffset;
	uint32_t		LoadStartAddress;
	uint32_t		IopResetVectorValue;
	uint32_t		IopResetRegAddr;
	uint32_t		VersionNameWhat;
	uint8_t			VersionName[32];
	uint32_t		VendorNameWhat;
	uint8_t			VendorName[32];
} msg_fw_header_t;

#define	MPI_FW_HEADER_WHAT_SIGNATURE			0x29232840

/* defines for using the ProductId field */
#define	MPI_FW_HEADER_PID_TYPE_MASK			0xF000
#define	MPI_FW_HEADER_PID_TYPE_SCSI			0x0000
#define	MPI_FW_HEADER_PID_TYPE_FC			0x1000

#define	MPI_FW_HEADER_PID_PROD_MASK			0x0F00
#define	MPI_FW_HEADER_PID_PROD_INITIATOR_SCSI		0x0100
#define	MPI_FW_HEADER_PID_PROD_TARGET_INITIATOR_SCSI	0x0200
#define	MPI_FW_HEADER_PID_PROD_TARGET_SCSI		0x0300
#define	MPI_FW_HEADER_PID_PROD_IM_SCSI			0x0400
#define	MPI_FW_HEADER_PID_PROD_IS_SCSI			0x0500
#define	MPI_FW_HEADER_PID_PROD_CTX_SCSI			0x0600
#define	MPI_FW_HEADER_PID_PROD_IR_SCSI			0x0700

#define	MPI_FW_HEADER_PID_FAMILY_MASK			0x00FF
#define	MPI_FW_HEADER_PID_FAMILY_1030A0_SCSI		0x0001
#define	MPI_FW_HEADER_PID_FAMILY_1030B0_SCSI		0x0002
#define	MPI_FW_HEADER_PID_FAMILY_1030B1_SCSI		0x0003
#define	MPI_FW_HEADER_PID_FAMILY_1030C0_SCSI		0x0004
#define	MPI_FW_HEADER_PID_FAMILY_1020A0_SCSI		0x0005
#define	MPI_FW_HEADER_PID_FAMILY_1020B0_SCSI		0x0006
#define	MPI_FW_HEADER_PID_FAMILY_1020B1_SCSI		0x0007
#define	MPI_FW_HEADER_PID_FAMILY_1020C0_SCSI		0x0008
#define	MPI_FW_HEADER_PID_FAMILY_1035A0_SCSI		0x0009
#define	MPI_FW_HEADER_PID_FAMILY_1035B0_SCSI		0x000A
#define	MPI_FW_HEADER_PID_FAMILY_1030TA0_SCSI		0x000B
#define	MPI_FW_HEADER_PID_FAMILY_1020TA0_SCSI		0x000C
#define	MPI_FW_HEADER_PID_FAMILY_909_FC			0x0000
#define	MPI_FW_HEADER_PID_FAMILY_919_FC			0x0001
#define	MPI_FW_HEADER_PID_FAMILY_919X_FC		0x0002
#define	MPI_FW_HEADER_PID_FAMILY_1064_SAS		0x0001
#define	MPI_FW_HEADER_PID_FAMILY_1068_SAS		0x0002
#define	MPI_FW_HEADER_PID_FAMILY_1078_SAS		0x0003

typedef struct mpi_ext_image_header {
	uint8_t			ImageType;
	uint8_t			Reserved;
	uint16_t		Reserved1;
	uint32_t		Checksum;
	uint32_t		ImageSize;
	uint32_t		NextImageHeaderOffset;
	uint32_t		LoadStartAddress;
	uint32_t		Reserved2;
} mpi_ext_image_header_t;

#define	MPI_EXT_IMAGE_TYPE_UNSPECIFIED			0x00
#define	MPI_EXT_IMAGE_TYPE_FW				0x01
#define	MPI_EXT_IMAGE_TYPE_NVDATA			0x03
#define	MPI_EXT_IMAGE_TYPE_BOOTLOADER			0x04

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MPI_IOC_H */
