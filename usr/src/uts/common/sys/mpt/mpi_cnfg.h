/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MPI_CNFG_H
#define	_SYS_MPI_CNFG_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Config Message and Structures
 */
typedef struct config_page_header {
	uint8_t		PageVersion;
	uint8_t		PageLength;
	uint8_t		PageNumber;
	uint8_t		PageType;
} config_page_header_t;

typedef union config_page_header_union {
	config_page_header_t	Struct;
	uint8_t			Bytes[4];
	uint16_t		Word16[2];
	uint32_t		Word32;
} config_page_header_union_t;

/*
 * The extended header is used for 1064 and on
 */
typedef struct config_extended_page_header {
	uint8_t			PageVersion;
	uint8_t			Reserved1;
	uint8_t			PageNumber;
	uint8_t			PageType;
	uint16_t		ExtPageLength;
	uint8_t			ExtPageType;
	uint8_t			Reserved2;
} config_extended_page_header_t;

/*
 * PageType field values
 */
#define	MPI_CONFIG_PAGEATTR_READ_ONLY		0x00
#define	MPI_CONFIG_PAGEATTR_CHANGEABLE		0x10
#define	MPI_CONFIG_PAGEATTR_PERSISTENT		0x20
#define	MPI_CONFIG_PAGEATTR_RO_PERSISTENT	0x30
#define	MPI_CONFIG_PAGEATTR_MASK		0xF0

#define	MPI_CONFIG_PAGETYPE_IO_UNIT		0x00
#define	MPI_CONFIG_PAGETYPE_IOC			0x01
#define	MPI_CONFIG_PAGETYPE_BIOS		0x02
#define	MPI_CONFIG_PAGETYPE_SCSI_PORT		0x03
#define	MPI_CONFIG_PAGETYPE_SCSI_DEVICE		0x04
#define	MPI_CONFIG_PAGETYPE_FC_PORT		0x05
#define	MPI_CONFIG_PAGETYPE_FC_DEVICE		0x06
#define	MPI_CONFIG_PAGETYPE_LAN			0x07
#define	MPI_CONFIG_PAGETYPE_RAID_VOLUME		0x08
#define	MPI_CONFIG_PAGETYPE_MANUFACTURING	0x09
#define	MPI_CONFIG_PAGETYPE_RAID_PHYSDISK	0x0A
#define	MPI_CONFIG_PAGETYPE_INBAND		0x0B
#define	MPI_CONFIG_PAGETYPE_EXTENDED		0x0F
#define	MPI_CONFIG_PAGETYPE_MASK		0x0F

#define	MPI_CONFIG_TYPENUM_MASK			0x0FFF

/*
 * ExtPageType field values
 */
#define	MPI_CONFIG_EXTPAGETYPE_SAS_IO_UNIT	0x10
#define	MPI_CONFIG_EXTPAGETYPE_SAS_EXPANDER	0x11
#define	MPI_CONFIG_EXTPAGETYPE_SAS_DEVICE	0x12
#define	MPI_CONFIG_EXTPAGETYPE_SAS_PHY		0x13

/*
 * Page Address field values
 */
#define	MPI_SCSI_PORT_PGAD_PORT_MASK		0x000000FF

#define	MPI_SCSI_DEVICE_TARGET_ID_MASK		0x000000FF
#define	MPI_SCSI_DEVICE_TARGET_ID_SHIFT		0
#define	MPI_SCSI_DEVICE_BUS_MASK		0x0000FF00
#define	MPI_SCSI_DEVICE_BUS_SHIFT		8

#define	MPI_FC_PORT_PGAD_PORT_MASK		0xF0000000
#define	MPI_FC_PORT_PGAD_PORT_SHIFT		28
#define	MPI_FC_PORT_PGAD_FORM_MASK		0x0F000000
#define	MPI_FC_PORT_PGAD_FORM_INDEX		0x01000000
#define	MPI_FC_PORT_PGAD_INDEX_MASK		0x0000FFFF
#define	MPI_FC_PORT_PGAD_INDEX_SHIFT		0

#define	MPI_FC_DEVICE_PGAD_PORT_MASK		0xF0000000
#define	MPI_FC_DEVICE_PGAD_PORT_SHIFT		28
#define	MPI_FC_DEVICE_PGAD_FORM_MASK		0x0F000000
#define	MPI_FC_DEVICE_PGAD_FORM_NEXT_DID	0x00000000
#define	MPI_FC_DEVICE_PGAD_ND_PORT_MASK		0xF0000000
#define	MPI_FC_DEVICE_PGAD_ND_PORT_SHIFT	28
#define	MPI_FC_DEVICE_PGAD_ND_DID_MASK		0x00FFFFFF
#define	MPI_FC_DEVICE_PGAD_ND_DID_SHIFT		0
#define	MPI_FC_DEVICE_PGAD_FORM_BUS_TID		0x01000000
#define	MPI_FC_DEVICE_PGAD_BT_BUS_MASK		0x0000FF00
#define	MPI_FC_DEVICE_PGAD_BT_BUS_SHIFT		8
#define	MPI_FC_DEVICE_PGAD_BT_TID_MASK		0x000000FF
#define	MPI_FC_DEVICE_PGAD_BT_TID_SHIFT		0

#define	MPI_PHYSDISK_PGAD_PHYSDISKNUM_MASK	0x000000FF
#define	MPI_PHYSDISK_PGAD_PHYSDISKNUM_SHIFT	0

#define	MPI_SAS_EXPAND_PGAD_FORM_MASK			0xF0000000
#define	MPI_SAS_EXPAND_PGAD_FORM_SHIFT			28
#define	MPI_SAS_EXPAND_PGAD_FORM_GET_NEXT_HANDLE	0x00000000
#define	MPI_SAS_EXPAND_PGAD_FORM_HANDLE_PHY_NUM		0x00000001
#define	MPI_SAS_EXPAND_PGAD_FORM_HANDLE			0x00000002
#define	MPI_SAS_EXPAND_PGAD_GNH_MASK_HANDLE		0x0000FFFF
#define	MPI_SAS_EXPAND_PGAD_GNH_SHIFT_HANDLE		0
#define	MPI_SAS_EXPAND_PGAD_HPN_MASK_PHY		0x00FF0000
#define	MPI_SAS_EXPAND_PGAD_HPN_SHIFT_PHY		16
#define	MPI_SAS_EXPAND_PGAD_HPN_MASK_HANDLE		0x0000FFFF
#define	MPI_SAS_EXPAND_PGAD_HPN_SHIFT_HANDLE		0
#define	MPI_SAS_EXPAND_PGAD_H_MASK_HANDLE		0x0000FFFF
#define	MPI_SAS_EXPAND_PGAD_H_SHIFT_HANDLE		0

#define	MPI_SAS_DEVICE_PGAD_FORM_MASK			0xF0000000
#define	MPI_SAS_DEVICE_PGAD_FORM_SHIFT			28
#define	MPI_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE	0x00000000
#define	MPI_SAS_DEVICE_PGAD_FORM_BUS_TARGET_ID		0x00000001
#define	MPI_SAS_DEVICE_PGAD_FORM_HANDLE			0x00000002
#define	MPI_SAS_DEVICE_PGAD_GNH_HANDLE_MASK		0x0000FFFF
#define	MPI_SAS_DEVICE_PGAD_GNH_HANDLE_SHIFT		0
#define	MPI_SAS_DEVICE_PGAD_BT_BUS_MASK			0x0000FF00
#define	MPI_SAS_DEVICE_PGAD_BT_BUS_SHIFT		8
#define	MPI_SAS_DEVICE_PGAD_BT_TID_MASK			0x000000FF
#define	MPI_SAS_DEVICE_PGAD_BT_TID_SHIFT		0
#define	MPI_SAS_DEVICE_PGAD_H_HANDLE_MASK		0x0000FFFF
#define	MPI_SAS_DEVICE_PGAD_H_HANDLE_SHIFT		0

#define	MPI_SAS_PHY_PGAD_PHY_NUMBER_MASK		0x000000FF
#define	MPI_SAS_PHY_PGAD_PHY_NUMBER_SHIFT		0

/*
 * Config Message
 */
typedef struct msg_config {
	uint8_t			Action;
	uint8_t			Reserved;
	uint8_t			ChainOffset;
	uint8_t			Function;
	uint16_t		ExtPageLength; /* 1064 only */
	uint8_t			ExtPageType; /* 1064 only */
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			Reserved2[8];
	config_page_header_t	Header;
	uint32_t		PageAddress;
	sge_io_union_t		PageBufferSGE;
} msg_config_t;

/*
 * Action field values
 */
#define	MPI_CONFIG_ACTION_PAGE_HEADER		0x00
#define	MPI_CONFIG_ACTION_PAGE_READ_CURRENT	0x01
#define	MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT	0x02
#define	MPI_CONFIG_ACTION_PAGE_DEFAULT		0x03
#define	MPI_CONFIG_ACTION_PAGE_WRITE_NVRAM	0x04
#define	MPI_CONFIG_ACTION_PAGE_READ_DEFAULT	0x05
#define	MPI_CONFIG_ACTION_PAGE_READ_NVRAM	0x06

/*
 * Config Reply Message
 */
typedef struct msg_config_reply {
	uint8_t			Action;
	uint8_t			Reserved;
	uint8_t			MsgLength;
	uint8_t			Function;
	uint16_t		ExtPageLength;
	uint8_t			ExtPageType;
	uint8_t			MsgFlags;
	uint32_t		MsgContext;
	uint8_t			Reserved2[2];
	uint16_t		IOCStatus;
	uint32_t		IOCLogInfo;
	config_page_header_t	Header;
} msg_config_reply_t;

/*
 * Manufacturing Config pages
 */
#define	MPI_MANUFACTPAGE_VENDORID_LSILOGIC	0x1000
#define	MPI_MANUFACTPAGE_DEVICEID_FC909		0x0621
#define	MPI_MANUFACTPAGE_DEVICEID_FC919		0x0624
#define	MPI_MANUFACTPAGE_DEVICEID_FC929		0x0622
#define	MPI_MANUFACTPAGE_DEVICEID_FC919X	0x0628
#define	MPI_MANUFACTPAGE_DEVICEID_FC929X	0x0626
#define	MPI_MANUFACTPAGE_DEVID_53C1030		0x0030
#define	MPI_MANUFACTPAGE_DEVID_53C1030ZC	0x0031
#define	MPI_MANUFACTPAGE_DEVID_1030_53C1035	0x0032
#define	MPI_MANUFACTPAGE_DEVID_1030ZC_53C1035	0x0033
#define	MPI_MANUFACTPAGE_DEVID_53C1035		0x0040
#define	MPI_MANUFACTPAGE_DEVID_53C1035ZC	0x0041
#define	MPI_MANUFACTPAGE_DEVID_SAS1064		0x0050

typedef struct config_page_manufacturing_0 {
	config_page_header_t	Header;
	uint8_t			ChipName[16];
	uint8_t			ChipRevision[8];
	uint8_t			BoardName[16];
	uint8_t			BoardAssembly[16];
	uint8_t			BoardTracerNumber[16];
} config_page_manufacturing_0_t;

#define	MPI_MANUFACTURING0_PAGEVERSION		0x00

typedef struct config_page_manufacturing_1 {
	config_page_header_t	Header;
	uint8_t			VPD[256];
} config_page_manufacturing_1_t;

#define	MPI_MANUFACTURING1_PAGEVERSION		0x00

typedef struct mpi_chip_revision_id {
	uint16_t		DeviceID;
	uint8_t			PCIRevisionID;
	uint8_t			Reserved;
} mpi_chip_revision_id_t;

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_MAN_PAGE_2_HW_SETTINGS_WORDS
#define	MPI_MAN_PAGE_2_HW_SETTINGS_WORDS	1
#endif

typedef struct config_page_manufacturing_2 {
	config_page_header_t	Header;
	mpi_chip_revision_id_t	ChipId;
	uint32_t		HwSettings[MPI_MAN_PAGE_2_HW_SETTINGS_WORDS];
} config_page_manufacturing_2_t;

#define	MPI_MANUFACTURING2_PAGEVERSION		0x00

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_MAN_PAGE_3_INFO_WORDS
#define	MPI_MAN_PAGE_3_INFO_WORDS		1
#endif

typedef struct config_page_manufacturing_3 {
	config_page_header_t	Header;
	mpi_chip_revision_id_t	ChipId;
	uint32_t		Info[MPI_MAN_PAGE_3_INFO_WORDS];
} config_page_manufacturing_3_t;

#define	MPI_MANUFACTURING3_PAGEVERSION		0x00

typedef struct config_page_manufacturing_4 {
	config_page_header_t	Header;
	uint32_t		Reserved1;
	uint8_t			InfoOffset0;
	uint8_t			InfoSize0;
	uint8_t			InfoOffset1;
	uint8_t			InfoSize1;
	uint8_t			InquirySize;
	uint8_t			Flags;
	uint16_t		Reserved2;
	uint8_t			InquiryData[56];
	uint32_t		ISVolumeSettings;
	uint32_t		IMEVolumeSettings;
	uint32_t		IMVolumeSettings;
} config_page_manufacturing_4_t;

#define	MPI_MANUFACTURING4_PAGEVERSION		0x01
#define	MPI_MANPAGE4_IR_NO_MIX_SAS_SATA		0x01

typedef struct config_page_manufacturing_5 {
	config_page_header_t	Header;
	uint64_t		BaseWWID;
} config_page_manufacturing_5_t;

#define	MPI_MANUFACTURING5_PAGEVERSION		0x00

typedef struct config_page_manufacturing_6 {
	config_page_header_t	Header;
	uint32_t		ProductSpecificInfo;
} config_page_manufacturing_6_t;

#define	MPI_MANUFACTURING6_PAGEVERSION		0x00

/*
 * IO Unit Config Pages
 */
typedef struct config_page_io_unit_0 {
	config_page_header_t	Header;
	uint64_t		UniqueValue;
} config_page_io_unit_0_t;

#define	MPI_IOUNITPAGE0_PAGEVERSION		0x00

typedef struct config_page_io_unit_1 {
	config_page_header_t	Header;
	uint32_t		Flags;
} config_page_io_unit_1_t;

#define	MPI_IOUNITPAGE1_PAGEVERSION		0x01

#define	MPI_IOUNITPAGE1_MULTI_FUNCTION			0x00000000
#define	MPI_IOUNITPAGE1_SINGLE_FUNCTION			0x00000001
#define	MPI_IOUNITPAGE1_MULTI_PATHING			0x00000002
#define	MPI_IOUNITPAGE1_SINGLE_PATHING			0x00000000
#define	MPI_IOUNITPAGE1_IR_USE_STATIC_VOLUME_ID		0x00000004
#define	MPI_IOUNITPAGE1_DISABLE_QUEUE_FULL_HANDLING	0x00000020
#define	MPI_IOUNITPAGE1_DISABLE_IR			0x00000040
#define	MPI_IOUNITPAGE1_FORCE_32			0x00000080
#define	MPI_IOUNITPAGE1_NATIVE_COMMAND_Q_DISABLE	0x00000100

typedef struct mpi_adapter_info {
	uint8_t			PciBusNumber;
	uint8_t			PciDeviceAndFunctionNumber;
	uint16_t		AdapterFlags;
} mpi_adapter_info_t;

#define	MPI_ADAPTER_INFO_FLAGS_EMBEDDED		0x0001
#define	MPI_ADAPTER_INFO_FLAGS_INIT_STATUS	0x0002

typedef struct config_page_io_unit_2 {
	config_page_header_t	Header;
	uint32_t		Flags;
	uint32_t		BiosVersion;
	mpi_adapter_info_t	AdapterOrder[4];
} config_page_io_unit_2_t;

#define	MPI_IOUNITPAGE2_PAGEVERSION		0x00

#define	MPI_IOUNITPAGE2_FLAGS_PAUSE_ON_ERROR	0x00000002
#define	MPI_IOUNITPAGE2_FLAGS_VERBOSE_ENABLE	0x00000004
#define	MPI_IOUNITPAGE2_FLAGS_COLOR_VIDEO_DISABLE 0x00000008
#define	MPI_IOUNITPAGE2_FLAGS_DONT_HOOK_INT_40	0x00000010

#define	MPI_IOUNITPAGE2_FLAGS_DEV_LIST_DISPLAY_MASK	0x000000E0
#define	MPI_IOUNITPAGE2_FLAGS_INSTALLED_DEV_DISPLAY	0x00000000
#define	MPI_IOUNITPAGE2_FLAGS_ADAPTER_DISPLAY		0x00000020
#define	MPI_IOUNITPAGE2_FLAGS_ADAPTER_DEV_DISPLAY	0x00000040

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_IO_UNIT_PAGE_3_GPIO_VAL_MAX
#define	MPI_IO_UNIT_PAGE_3_GPIO_VAL_MAX		1
#endif

typedef struct config_page_io_unit_3 {
	config_page_header_t	Header;
	uint8_t			GPIOCount;
	uint8_t			Reserved1;
	uint16_t		Reserved2;
	uint16_t		GPIOVal[MPI_IO_UNIT_PAGE_3_GPIO_VAL_MAX];
} config_page_io_unit_3_t;

#define	MPI_IOUNITPAGE3_PAGEVERSION		0x01

#define	MPI_IOUNITPAGE3_GPIO_FUNCTION_MASK	0xFC
#define	MPI_IOUNITPAGE3_GPIO_FUNCTION_SHIFT	2
#define	MPI_IOUNITPAGE3_GPIO_SETTING_OFF	0x00
#define	MPI_IOUNITPAGE3_GPIO_SETTING_ON		0x01

/*
 * IOC Config Pages
 */
typedef struct config_page_ioc_0 {
	config_page_header_t	Header;
	uint32_t		TotalNVStore;
	uint32_t		FreeNVStore;
	uint16_t		VendorID;
	uint16_t		DeviceID;
	uint8_t			RevisionID;
	uint8_t			Reserved[3];
	uint32_t		ClassCode;
	uint16_t		SubsystemVendorID;
	uint16_t		SubsystemID;
} config_page_ioc_0_t;

#define	MPI_IOCPAGE0_PAGEVERSION		0x01

typedef struct config_page_ioc_1 {
	config_page_header_t	Header;
	uint32_t		Flags;
	uint32_t		CoalescingTimeout;
	uint8_t			CoalescingDepth;
	uint8_t			PCISlotNum;
	uint8_t			Reserved[2];
} config_page_ioc_1_t;

#define	MPI_IOCPAGE1_PAGEVERSION		0x01
#define	MPI_IOCPAGE1_EEDP_HOST_SUPPORTS_DIF	0x08000000
#define	MPI_IOCPAGE1_EEDP_MODE_MASK		0x07000000
#define	MPI_IOCPAGE1_EEDP_MODE_OFF		0x00000000
#define	MPI_IOCPAGE1_EEDP_MODE_T10		0x01000000
#define	MPI_IOCPAGE1_EEDP_MODE_LSI_1		0x02000000
#define	MPI_IOCPAGE1_EEDP_MODE_LSI_2		0x03000000
#define	MPI_IOCPAGE1_REPLY_COALESCING		0x00000001
#define	MPI_IOCPAGE1_PCISLOTNUM_UNKNOWN		0xFF

typedef struct config_page_ioc_2_raid_vol {
	uint8_t			VolumeID;
	uint8_t			VolumeBus;
	uint8_t			VolumeIOC;
	uint8_t			VolumePageNumber;
	uint8_t			VolumeType;
	uint8_t			Flags;
	uint16_t		Reserved3;
} config_page_ioc_2_raid_vol_t;

#define	MPI_RAID_VOL_TYPE_IS			0x00
#define	MPI_RAID_VOL_TYPE_IME			0x01
#define	MPI_RAID_VOL_TYPE_IM			0x02
#define	MPI_IOCPAGE2_FLAG_VOLUME_INACTIVE	0x08

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_IOC_PAGE_2_RAID_VOLUME_MAX
#define	MPI_IOC_PAGE_2_RAID_VOLUME_MAX		1
#endif

typedef struct config_page_ioc_2 {
	config_page_header_t	Header;
	uint32_t		CapabilitiesFlags;
	uint8_t			NumActiveVolumes;
	uint8_t			MaxVolumes;
	uint8_t			NumActivePhysDisks;
	uint8_t			MaxPhysDisks;
	config_page_ioc_2_raid_vol_t RaidVolume[MPI_IOC_PAGE_2_RAID_VOLUME_MAX];
} config_page_ioc_2_t;

#define	MPI_IOCPAGE2_PAGEVERSION		0x02

/*
 * IOC Page 2 Capabilities flags
 */
#define	MPI_IOCPAGE2_CAP_FLAGS_IS_SUPPORT	0x00000001
#define	MPI_IOCPAGE2_CAP_FLAGS_IME_SUPPORT	0x00000002
#define	MPI_IOCPAGE2_CAP_FLAGS_IM_SUPPORT	0x00000004
#define	MPI_IOCPAGE2_CAP_FLAGS_SES_SUPPORT	0x20000000
#define	MPI_IOCPAGE2_CAP_FLAGS_SAFTE_SUPPORT	0x40000000
#define	MPI_IOCPAGE2_CAP_FLAGS_CROSS_CHANNEL_SUPPORT 0x80000000
#define	MPI_IOCPAGE2_CAP_FLAGS_RAID_64_BIT_ADDRESSING	0x10000000

typedef struct ioc_3_phys_disk {
	uint8_t			PhysDiskID;
	uint8_t			PhysDiskBus;
	uint8_t			PhysDiskIOC;
	uint8_t			PhysDiskNum;
} ioc_3_phys_disk_t;

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_IOC_PAGE_3_PHYSDISK_MAX
#define	MPI_IOC_PAGE_3_PHYSDISK_MAX		1
#endif

typedef struct config_page_ioc_3 {
	config_page_header_t	Header;
	uint8_t			NumPhysDisks;
	uint8_t			Reserved1;
	uint16_t		Reserved2;
	ioc_3_phys_disk_t	PhysDisk[MPI_IOC_PAGE_3_PHYSDISK_MAX];
} config_page_ioc_3_t;

#define	MPI_IOCPAGE3_PAGEVERSION		0x00

typedef struct ioc_4_sep {
	uint8_t			SEPTargetID;
	uint8_t			SEPBus;
	uint16_t		Reserved;
} ioc_4_sep_t;

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_IOC_PAGE_4_SEP_MAX
#define	MPI_IOC_PAGE_4_SEP_MAX			1
#endif

typedef struct config_page_ioc_4 {
	config_page_header_t	Header;
	uint8_t			ActiveSEP;
	uint8_t			MaxSEP;
	uint16_t		Reserved1;
	ioc_4_sep_t		SEP[MPI_IOC_PAGE_4_SEP_MAX];
} config_page_ioc_4_t;

#define	MPI_IOCPAGE4_PAGEVERSION		0x00

/*
 * SCSI Port Config Pages
 */
typedef struct config_page_scsi_port_0 {
	config_page_header_t	Header;
	uint32_t		Capabilities;
	uint32_t		PhysicalInterface;
} config_page_scsi_port_0_t;

#define	MPI_SCSIPORTPAGE0_PAGEVERSION			0x01

/*
 * Capabilities
 */
#define	MPI_SCSIPORTPAGE0_CAP_IU			0x00000001
#define	MPI_SCSIPORTPAGE0_CAP_DT			0x00000002
#define	MPI_SCSIPORTPAGE0_CAP_QAS			0x00000004
#define	MPI_SCSIPORTPAGE0_CAP_PACING_TRANSFERS		0x00000008
#define	MPI_SCSIPORTPAGE0_CAP_MIN_SYNC_PERIOD_MASK	0x0000FF00
#define	MPI_SCSIPORTPAGE0_CAP_MAX_SYNC_OFFSET_MASK	0x00FF0000
#define	MPI_SCSIPORTPAGE0_CAP_WIDE			0x20000000
#define	MPI_SCSIPORTPAGE0_CAP_AIP			0x80000000

/*
 * Physical Interface
 */
#define	MPI_SCSIPORTPAGE0_PHY_SIGNAL_TYPE_MASK		0x00000003
#define	MPI_SCSIPORTPAGE0_PHY_SIGNAL_HVD		0x01
#define	MPI_SCSIPORTPAGE0_PHY_SIGNAL_SE			0x02
#define	MPI_SCSIPORTPAGE0_PHY_SIGNAL_LVD		0x03

typedef struct config_page_scsi_port_1 {
	config_page_header_t	Header;
	uint32_t		Configuration;
	uint32_t		OnBusTimerValue;
} config_page_scsi_port_1_t;

#define	MPI_SCSIPORTPAGE1_PAGEVERSION			0x02

#define	MPI_SCSIPORTPAGE1_CFG_PORT_SCSI_ID_MASK		0x000000FF
#define	MPI_SCSIPORTPAGE1_CFG_PORT_RESPONSE_ID_MASK	0xFFFF0000

typedef struct mpi_device_info {
	uint8_t			Timeout;
	uint8_t			SyncFactor;
	uint16_t		DeviceFlags;
} mpi_device_info_t;

typedef struct config_page_scsi_port_2 {
	config_page_header_t	Header;
	uint32_t		PortFlags;
	uint32_t		PortSettings;
	mpi_device_info_t	DeviceSettings[16];
} config_page_scsi_port_2_t;

#define	MPI_SCSIPORTPAGE2_PAGEVERSION			0x01

#define	MPI_SCSIPORTPAGE2_PORT_FLAGS_SCAN_HIGH_TO_LOW	0x00000001
#define	MPI_SCSIPORTPAGE2_PORT_FLAGS_AVOID_SCSI_RESET	0x00000004
#define	MPI_SCSIPORTPAGE2_PORT_FLAGS_ALTERNATE_CHS	0x00000008
#define	MPI_SCSIPORTPAGE2_PORT_FLAGS_TERMINATION_DISABLE 0x00000010

#define	MPI_SCSIPORTPAGE2_PORT_HOST_ID_MASK		0x0000000F
#define	MPI_SCSIPORTPAGE2_PORT_MASK_INIT_HBA		0x00000030
#define	MPI_SCSIPORTPAGE2_PORT_DISABLE_INIT_HBA		0x00000000
#define	MPI_SCSIPORTPAGE2_PORT_BIOS_INIT_HBA		0x00000010
#define	MPI_SCSIPORTPAGE2_PORT_OS_INIT_HBA		0x00000020
#define	MPI_SCSIPORTPAGE2_PORT_BIOS_OS_INIT_HBA		0x00000030
#define	MPI_SCSIPORTPAGE2_PORT_REMOVABLE_MEDIA		0x000000C0
#define	MPI_SCSIPORTPAGE2_PORT_SPINUP_DELAY_MASK	0x00000F00
#define	MPI_SCSIPORTPAGE2_PORT_MASK_NEGO_MASTER_SETTINGS 0x00003000
#define	MPI_SCSIPORTPAGE2_PORT_NEGO_MASTER_SETTINGS	0x00000000
#define	MPI_SCSIPORTPAGE2_PORT_NONE_MASTER_SETTINGS	0x00001000
#define	MPI_SCSIPORTPAGE2_PORT_ALL_MASTER_SETTINGS	0x00003000

#define	MPI_SCSIPORTPAGE2_DEVICE_DISCONNECT_ENABLE	0x0001
#define	MPI_SCSIPORTPAGE2_DEVICE_ID_SCAN_ENABLE		0x0002
#define	MPI_SCSIPORTPAGE2_DEVICE_LUN_SCAN_ENABLE	0x0004
#define	MPI_SCSIPORTPAGE2_DEVICE_TAG_QUEUE_ENABLE	0x0008
#define	MPI_SCSIPORTPAGE2_DEVICE_WIDE_DISABLE		0x0010
#define	MPI_SCSIPORTPAGE2_DEVICE_BOOT_CHOICE		0x0020

/*
 * SCSI Target Device Config Pages
 */
typedef struct config_page_scsi_device_0 {
	config_page_header_t	Header;
	uint32_t		NegotiatedParameters;
	uint32_t		Information;
} config_page_scsi_device_0_t;

#define	MPI_SCSIDEVPAGE0_PAGEVERSION			0x02

#define	MPI_SCSIDEVPAGE0_NP_IU				0x00000001
#define	MPI_SCSIDEVPAGE0_NP_DT				0x00000002
#define	MPI_SCSIDEVPAGE0_NP_QAS				0x00000004
#define	MPI_SCSIDEVPAGE0_NP_NEG_SYNC_PERIOD_MASK	0x0000FF00
#define	MPI_SCSIDEVPAGE0_NP_NEG_SYNC_OFFSET_MASK	0x00FF0000
#define	MPI_SCSIDEVPAGE0_NP_WIDE			0x20000000
#define	MPI_SCSIDEVPAGE0_NP_AIP				0x80000000
#define	MPI_SCSIDEVPAGE0_NP_IDP				0x08000000

#define	MPI_SCSIDEVPAGE0_INFO_PARAMS_NEGOTIATED		0x00000001
#define	MPI_SCSIDEVPAGE0_INFO_SDTR_REJECTED		0x00000002
#define	MPI_SCSIDEVPAGE0_INFO_WDTR_REJECTED		0x00000004
#define	MPI_SCSIDEVPAGE0_INFO_PPR_REJECTED		0x00000008

typedef struct config_page_scsi_device_1 {
	config_page_header_t	Header;
	uint32_t		RequestedParameters;
	uint32_t		Reserved;
	uint32_t		Configuration;
} config_page_scsi_device_1_t;

#define	MPI_SCSIDEVPAGE1_PAGEVERSION			0x03

#define	MPI_SCSIDEVPAGE1_RP_IU				0x00000001
#define	MPI_SCSIDEVPAGE1_RP_DT				0x00000002
#define	MPI_SCSIDEVPAGE1_RP_QAS				0x00000004
#define	MPI_SCSIDEVPAGE1_RP_MIN_SYNC_PERIOD_MASK	0x0000FF00
#define	MPI_SCSIDEVPAGE1_RP_MAX_SYNC_OFFSET_MASK	0x00FF0000
#define	MPI_SCSIDEVPAGE1_RP_WIDE			0x20000000
#define	MPI_SCSIDEVPAGE1_RP_AIP				0x80000000
#define	MPI_SCSIDEVPAGE1_RP_IDP				0x08000000

#define	MPI_SCSIDEVPAGE1_DV_LVD_DRIVE_STRENGTH_MASK	0x00000003
#define	MPI_SCSIDEVPAGE1_DV_SE_SLEW_RATE_MASK		0x00000300

#define	MPI_SCSIDEVPAGE1_CONF_WDTR_DISALLOWED		0x00000002
#define	MPI_SCSIDEVPAGE1_CONF_SDTR_DISALLOWED		0x00000004

typedef struct config_page_scsi_device_2 {
	config_page_header_t	Header;
	uint32_t		DomainValidation;
	uint32_t		ParityPipeSelect;
	uint32_t		DataPipeSelect;
} config_page_scsi_device_2_t;

#define	MPI_SCSIDEVPAGE2_PAGEVERSION			0x00

#define	MPI_SCSIDEVPAGE2_DV_ISI_ENABLE			0x00000010
#define	MPI_SCSIDEVPAGE2_DV_SECONDARY_DRIVER_ENABLE	0x00000020
#define	MPI_SCSIDEVPAGE2_DV_SLEW_RATE_CTRL		0x00000380
#define	MPI_SCSIDEVPAGE2_DV_PRIM_DRIVE_STR_CTRL		0x00001C00
#define	MPI_SCSIDEVPAGE2_DV_SECOND_DRIVE_STR_CTRL	0x0000E000
#define	MPI_SCSIDEVPAGE2_DV_XCLKH_ST			0x10000000
#define	MPI_SCSIDEVPAGE2_DV_XCLKS_ST			0x20000000
#define	MPI_SCSIDEVPAGE2_DV_XCLKH_DT			0x40000000
#define	MPI_SCSIDEVPAGE2_DV_XCLKS_DT			0x80000000

#define	MPI_SCSIDEVPAGE2_PPS_PPS_MASK			0x00000003

#define	MPI_SCSIDEVPAGE2_DPS_BIT_0_PL_SELECT_MASK	0x00000003
#define	MPI_SCSIDEVPAGE2_DPS_BIT_1_PL_SELECT_MASK	0x0000000C
#define	MPI_SCSIDEVPAGE2_DPS_BIT_2_PL_SELECT_MASK	0x00000030
#define	MPI_SCSIDEVPAGE2_DPS_BIT_3_PL_SELECT_MASK	0x000000C0
#define	MPI_SCSIDEVPAGE2_DPS_BIT_4_PL_SELECT_MASK	0x00000300
#define	MPI_SCSIDEVPAGE2_DPS_BIT_5_PL_SELECT_MASK	0x00000C00
#define	MPI_SCSIDEVPAGE2_DPS_BIT_6_PL_SELECT_MASK	0x00003000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_7_PL_SELECT_MASK	0x0000C000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_8_PL_SELECT_MASK	0x00030000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_9_PL_SELECT_MASK	0x000C0000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_10_PL_SELECT_MASK	0x00300000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_11_PL_SELECT_MASK	0x00C00000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_12_PL_SELECT_MASK	0x03000000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_13_PL_SELECT_MASK	0x0C000000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_14_PL_SELECT_MASK	0x30000000
#define	MPI_SCSIDEVPAGE2_DPS_BIT_15_PL_SELECT_MASK	0xC0000000

/*
 * FC Port Config Pages
 */
typedef struct config_page_fc_port_0 {
	config_page_header_t	Header;
	uint32_t		Flags;
	uint8_t			MPIPortNumber;
	uint8_t			Reserved[3];
	uint32_t		PortIdentifier;
	uint64_t		WWNN;
	uint64_t		WWPN;
	uint32_t		SupportedServiceClass;
	uint32_t		SupportedSpeeds;
	uint32_t		CurrentSpeed;
	uint32_t		MaxFrameSize;
	uint64_t		FabricWWNN;
	uint64_t		FabricWWPN;
	uint32_t		DiscoveredPortsCount;
	uint32_t		MaxInitiators;
} config_page_fc_port_0_t;

#define	MPI_FCPORTPAGE0_PAGEVERSION			0x01

#define	MPI_FCPORTPAGE0_FLAGS_PROT_MASK			0x0000000F
#define	MPI_FCPORTPAGE0_FLAGS_PROT_FCP_INIT \
					MPI_PORTFACTS_PROTOCOL_INITIATOR
#define	MPI_FCPORTPAGE0_FLAGS_PROT_FCP_TARG \
					MPI_PORTFACTS_PROTOCOL_TARGET
#define	MPI_FCPORTPAGE0_FLAGS_PROT_LAN \
					MPI_PORTFACTS_PROTOCOL_LAN
#define	MPI_FCPORTPAGE0_FLAGS_PROT_LOGBUSADDR \
					MPI_PORTFACTS_PROTOCOL_LOGBUSADDR

#define	MPI_FCPORTPAGE0_FLAGS_ALIAS_ALPA_SUPPORTED	0x00000010
#define	MPI_FCPORTPAGE0_FLAGS_ALIAS_WWN_SUPPORTED	0x00000020
#define	MPI_FCPORTPAGE0_FLAGS_FABRIC_WWN_VALID		0x00000030

#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_TYPE_MASK		0x00000F00
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_NO_INIT		0x00000000
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_POINT_TO_POINT	0x00000100
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_PRIVATE_LOOP	0x00000200
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_FABRIC_DIRECT	0x00000400
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_PUBLIC_LOOP	0x00000800

#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_TYPE_MASK		0x00000F00
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_NO_INIT		0x00000000
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_POINT_TO_POINT	0x00000100
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_PRIVATE_LOOP	0x00000200
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_FABRIC_DIRECT	0x00000400
#define	MPI_FCPORTPAGE0_FLAGS_ATTACH_PUBLIC_LOOP	0x00000800

#define	MPI_FCPORTPAGE0_LTYPE_RESERVED			0x00
#define	MPI_FCPORTPAGE0_LTYPE_OTHER			0x01
#define	MPI_FCPORTPAGE0_LTYPE_UNKNOWN			0x02
#define	MPI_FCPORTPAGE0_LTYPE_COPPER			0x03
#define	MPI_FCPORTPAGE0_LTYPE_SINGLE_1300		0x04
#define	MPI_FCPORTPAGE0_LTYPE_SINGLE_1500		0x05
#define	MPI_FCPORTPAGE0_LTYPE_50_LASER_MULTI		0x06
#define	MPI_FCPORTPAGE0_LTYPE_50_LED_MULTI		0x07
#define	MPI_FCPORTPAGE0_LTYPE_62_LASER_MULTI		0x08
#define	MPI_FCPORTPAGE0_LTYPE_62_LED_MULTI		0x09
#define	MPI_FCPORTPAGE0_LTYPE_MULTI_LONG_WAVE		0x0A
#define	MPI_FCPORTPAGE0_LTYPE_MULTI_SHORT_WAVE		0x0B
#define	MPI_FCPORTPAGE0_LTYPE_LASER_SHORT_WAVE		0x0C
#define	MPI_FCPORTPAGE0_LTYPE_LED_SHORT_WAVE		0x0D
#define	MPI_FCPORTPAGE0_LTYPE_1300_LONG_WAVE		0x0E
#define	MPI_FCPORTPAGE0_LTYPE_1500_LONG_WAVE		0x0F

#define	MPI_FCPORTPAGE0_PORTSTATE_UNKNOWN		0x01
#define	MPI_FCPORTPAGE0_PORTSTATE_ONLINE		0x02
#define	MPI_FCPORTPAGE0_PORTSTATE_OFFLINE		0x03
#define	MPI_FCPORTPAGE0_PORTSTATE_BYPASSED		0x04
#define	MPI_FCPORTPAGE0_PORTSTATE_DIAGNOST		0x05
#define	MPI_FCPORTPAGE0_PORTSTATE_LINKDOWN		0x06
#define	MPI_FCPORTPAGE0_PORTSTATE_ERROR			0x07
#define	MPI_FCPORTPAGE0_PORTSTATE_LOOPBACK		0x08

#define	MPI_FCPORTPAGE0_SUPPORT_CLASS_1			0x00000001
#define	MPI_FCPORTPAGE0_SUPPORT_CLASS_2			0x00000002
#define	MPI_FCPORTPAGE0_SUPPORT_CLASS_3			0x00000004

#define	MPI_FCPORTPAGE0_SUPPORT_1GBIT_SPEED		0x00000001
#define	MPI_FCPORTPAGE0_SUPPORT_2GBIT_SPEED		0x00000002
#define	MPI_FCPORTPAGE0_SUPPORT_10GBIT_SPEED		0x00000004

#define	MPI_FCPORTPAGE0_CURRENT_SPEED_1GBIT \
			MPI_FCPORTPAGE0_SUPPORT_1GBIT_SPEED
#define	MPI_FCPORTPAGE0_CURRENT_SPEED_2GBIT \
			MPI_FCPORTPAGE0_SUPPORT_2GBIT_SPEED
#define	MPI_FCPORTPAGE0_CURRENT_SPEED_10GBIT \
			MPI_FCPORTPAGE0_SUPPORT_10GBIT_SPEED

typedef struct config_page_fc_port_1 {
	config_page_header_t	Header;
	uint32_t		Flags;
	uint64_t		NoSEEPROMWWNN;
	uint64_t		NoSEEPROMWWPN;
	uint8_t			HardALPA;
	uint8_t			LinkConfig;
	uint8_t			TopologyConfig;
	uint8_t			Reserved;
} config_page_fc_port_1_t;

#define	MPI_FCPORTPAGE1_PAGEVERSION			0x02

#define	MPI_FCPORTPAGE1_FLAGS_EXT_FCP_STATUS_EN		0x08000000
#define	MPI_FCPORTPAGE1_FLAGS_IMMEDIATE_ERROR_REPLY	0x04000000
#define	MPI_FCPORTPAGE1_FLAGS_SORT_BY_DID		0x00000001
#define	MPI_FCPORTPAGE1_FLAGS_SORT_BY_WWN		0x00000000

/*
 *  Flags used for programming protocol modes in NVStore
 */
#define	MPI_FCPORTPAGE1_FLAGS_PROT_MASK			0xF0000000
#define	MPI_FCPORTPAGE1_FLAGS_PROT_SHIFT		28
#define	MPI_FCPORTPAGE1_FLAGS_PROT_FCP_INIT \
	((uint32_t)MPI_PORTFACTS_PROTOCOL_INITIATOR << \
		MPI_FCPORTPAGE1_FLAGS_PROT_SHIFT)
#define	MPI_FCPORTPAGE1_FLAGS_PROT_FCP_TARG \
	((uint32_t)MPI_PORTFACTS_PROTOCOL_TARGET << \
		MPI_FCPORTPAGE1_FLAGS_PROT_SHIFT)
#define	MPI_FCPORTPAGE1_FLAGS_PROT_LAN \
	((uint32_t)MPI_PORTFACTS_PROTOCOL_LAN << \
		MPI_FCPORTPAGE1_FLAGS_PROT_SHIFT)
#define	MPI_FCPORTPAGE1_FLAGS_PROT_LOGBUSADDR \
	((uint32_t)MPI_PORTFACTS_PROTOCOL_LOGBUSADDR << \
		MPI_FCPORTPAGE1_FLAGS_PROT_SHIFT)

#define	MPI_FCPORTPAGE1_HARD_ALPA_NOT_USED		0xFF

#define	MPI_FCPORTPAGE1_LCONFIG_SPEED_MASK		0x0F
#define	MPI_FCPORTPAGE1_LCONFIG_SPEED_1GIG		0x00
#define	MPI_FCPORTPAGE1_LCONFIG_SPEED_2GIG		0x01
#define	MPI_FCPORTPAGE1_LCONFIG_SPEED_4GIG		0x02
#define	MPI_FCPORTPAGE1_LCONFIG_SPEED_10GIG		0x03
#define	MPI_FCPORTPAGE1_LCONFIG_SPEED_AUTO		0x0F

#define	MPI_FCPORTPAGE1_TOPOLOGY_MASK			0x0F
#define	MPI_FCPORTPAGE1_TOPOLOGY_NLPORT			0x01
#define	MPI_FCPORTPAGE1_TOPOLOGY_NPORT			0x02
#define	MPI_FCPORTPAGE1_TOPOLOGY_AUTO			0x0F

typedef struct config_page_fc_port_2 {
	config_page_header_t	Header;
	uint8_t			NumberActive;
	uint8_t			ALPA[127];
} config_page_fc_port_2_t;

#define	MPI_FCPORTPAGE2_PAGEVERSION			0x01

typedef struct wwn_format {
	uint64_t		WWNN;
	uint64_t		WWPN;
} wwn_format_t;

typedef union fc_port_persistent_physical_id {
	wwn_format_t		WWN;
	uint32_t		Did;
} fc_port_persistent_physical_id_t;

typedef struct fc_port_persistent {
	fc_port_persistent_physical_id_t PhysicalIdentifier;
	uint8_t			TargetID;
	uint8_t			Bus;
	uint16_t		Flags;
} fc_port_persistent_t;

#define	MPI_PERSISTENT_FLAGS_SHIFT			16
#define	MPI_PERSISTENT_FLAGS_ENTRY_VALID		0x0001
#define	MPI_PERSISTENT_FLAGS_SCAN_ID			0x0002
#define	MPI_PERSISTENT_FLAGS_SCAN_LUNS			0x0004
#define	MPI_PERSISTENT_FLAGS_BOOT_DEVICE		0x0008
#define	MPI_PERSISTENT_FLAGS_BY_DID			0x0080

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_FC_PORT_PAGE_3_ENTRY_MAX
#define	MPI_FC_PORT_PAGE_3_ENTRY_MAX			1
#endif

typedef struct config_page_fc_port_3 {
	config_page_header_t	Header;
	fc_port_persistent_t	Entry[MPI_FC_PORT_PAGE_3_ENTRY_MAX];
} config_page_fc_port_3_t;

#define	MPI_FCPORTPAGE3_PAGEVERSION			0x01

typedef struct config_page_fc_port_4 {
	config_page_header_t	Header;
	uint32_t		PortFlags;
	uint32_t		PortSettings;
} config_page_fc_port_4_t;

#define	MPI_FCPORTPAGE4_PAGEVERSION			0x00

#define	MPI_FCPORTPAGE4_PORT_FLAGS_ALTERNATE_CHS	0x00000008

#define	MPI_FCPORTPAGE4_PORT_MASK_INIT_HBA		0x00000030
#define	MPI_FCPORTPAGE4_PORT_DISABLE_INIT_HBA		0x00000000
#define	MPI_FCPORTPAGE4_PORT_BIOS_INIT_HBA		0x00000010
#define	MPI_FCPORTPAGE4_PORT_OS_INIT_HBA		0x00000020
#define	MPI_FCPORTPAGE4_PORT_BIOS_OS_INIT_HBA		0x00000030
#define	MPI_FCPORTPAGE4_PORT_REMOVABLE_MEDIA		0x000000C0
#define	MPI_FCPORTPAGE4_PORT_SPINUP_DELAY_MASK		0x00000F00

typedef struct config_page_fc_port_5_alias_info {
	uint8_t			Flags;
	uint8_t			AliasAlpa;
	uint16_t		Reserved;
	uint64_t		AliasWWNN;
	uint64_t		AliasWWPN;
} config_page_fc_port_5_alias_info_t;

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_FC_PORT_PAGE_5_ALIAS_MAX
#define	MPI_FC_PORT_PAGE_5_ALIAS_MAX			1
#endif

typedef struct config_page_fc_port_5 {
	config_page_header_t	Header;
	config_page_fc_port_5_alias_info_t
			AliasInfo[MPI_FC_PORT_PAGE_5_ALIAS_MAX];
} config_page_fc_port_5_t;

#define	MPI_FCPORTPAGE5_PAGEVERSION			0x00

#define	MPI_FCPORTPAGE5_FLAGS_ALIAS_ALPA_VALID		0x01
#define	MPI_FCPORTPAGE5_FLAGS_ALIAS_WWN_VALID		0x02

typedef struct config_page_fc_port_6 {
	config_page_header_t	Header;
	uint32_t		Reserved;
	uint64_t		TimeSinceReset;
	uint64_t		TxFrames;
	uint64_t		RxFrames;
	uint64_t		TxWords;
	uint64_t		RxWords;
	uint64_t		LipCount;
	uint64_t		NosCount;
	uint64_t		ErrorFrames;
	uint64_t		DumpedFrames;
	uint64_t		LinkFailureCount;
	uint64_t		LossOfSyncCount;
	uint64_t		LossOfSignalCount;
	uint64_t		PrimativeSeqErrCount;
	uint64_t		InvalidTxWordCount;
	uint64_t		InvalidCrcCount;
	uint64_t		FcpInitiatorIoCount;
} config_page_fc_port_6_t;

#define	MPI_FCPORTPAGE6_PAGEVERSION			0x00

typedef struct config_page_fc_port_7 {
	config_page_header_t	Header;
	uint32_t		Reserved;
	uint8_t			PortSymbolicName[256];
} config_page_fc_port_7_t;

#define	MPI_FCPORTPAGE7_PAGEVERSION			0x00

typedef struct config_page_fc_port_8 {
	config_page_header_t	Header;
	uint32_t		BitVector[8];
} config_page_fc_port_8_t;

#define	MPI_FCPORTPAGE8_PAGEVERSION			0x00

typedef struct config_page_fc_port_9 {
	config_page_header_t	Header;
	uint32_t		Reserved;
	uint64_t		GlobalWWPN;
	uint64_t		GlobalWWNN;
	uint32_t		UnitType;
	uint32_t		PhysicalPortNumber;
	uint32_t		NumAttachedNodes;
	uint16_t		IPVersion;
	uint16_t		UDPPortNumber;
	uint8_t			IPAddress[16];
	uint16_t		Reserved1;
	uint16_t		TopologyDiscoveryFlags;
} config_page_fc_port_9_t;

#define	MPI_FCPORTPAGE9_PAGEVERSION			0x00

/*
 * FC Device Config Pages
 */
typedef struct config_page_fc_device_0 {
	config_page_header_t	Header;
	uint64_t		WWNN;
	uint64_t		WWPN;
	uint32_t		PortIdentifier;
	uint8_t			Protocol;
	uint8_t			Flags;
	uint16_t		BBCredit;
	uint16_t		MaxRxFrameSize;
	uint8_t			Reserved1;
	uint8_t			PortNumber;
	uint8_t			FcPhLowestVersion;
	uint8_t			FcPhHighestVersion;
	uint8_t			CurrentTargetID;
	uint8_t			CurrentBus;
} config_page_fc_device_0_t;

#define	MPI_FC_DEVICE_PAGE_0_PAGEVERSION		0x02

#define	MPI_FC_DEVICE_PAGE0_FLAGS_TARGETID_BUS_VALID	0x01

#define	MPI_FC_DEVICE_PAGE_0_PROT_IP			0x01
#define	MPI_FC_DEVICE_PAGE_0_PROT_FCP_TARGET		0x02
#define	MPI_FC_DEVICE_PAGE_0_PROT_FCP_INITIATOR		0x04

#define	MPI_FC_DEVICE_PAGE0_PGAD_PORT_MASK \
			(MPI_FC_DEVICE_PGAD_PORT_MASK)
#define	MPI_FC_DEVICE_PAGE0_PGAD_FORM_MASK \
			(MPI_FC_DEVICE_PGAD_FORM_MASK)
#define	MPI_FC_DEVICE_PAGE0_PGAD_FORM_NEXT_DID \
			(MPI_FC_DEVICE_PGAD_FORM_NEXT_DID)
#define	MPI_FC_DEVICE_PAGE0_PGAD_FORM_BUS_TID \
			(MPI_FC_DEVICE_PGAD_FORM_BUS_TID)
#define	MPI_FC_DEVICE_PAGE0_PGAD_DID_MASK \
			(MPI_FC_DEVICE_PGAD_ND_DID_MASK)
#define	MPI_FC_DEVICE_PAGE0_PGAD_BUS_MASK \
			(MPI_FC_DEVICE_PGAD_BT_BUS_MASK)
#define	MPI_FC_DEVICE_PAGE0_PGAD_BUS_SHIFT \
			(MPI_FC_DEVICE_PGAD_BT_BUS_SHIFT)
#define	MPI_FC_DEVICE_PAGE0_PGAD_TID_MASK \
			(MPI_FC_DEVICE_PGAD_BT_TID_MASK)

/*
 *  RAID Volume Config Pages
 */
typedef struct raid_vol0_phys_disk {
	uint16_t		Reserved;
	uint8_t			PhysDiskMap;
	uint8_t			PhysDiskNum;
} raid_vol0_phys_disk_t;

#define	MPI_RAIDVOL0_PHYSDISK_PRIMARY			0x01
#define	MPI_RAIDVOL0_PHYSDISK_SECONDARY			0x02

typedef struct raid_vol0_status {
	uint8_t			Flags;
	uint8_t			State;
	uint16_t		Reserved;
} raid_vol0_status_t;

/*
 * RAID Volume Page 0 VolumeStatus defines
 */
#define	MPI_RAIDVOL0_STATUS_FLAG_ENABLED		0x01
#define	MPI_RAIDVOL0_STATUS_FLAG_QUIESCED		0x02
#define	MPI_RAIDVOL0_STATUS_FLAG_RESYNC_IN_PROGRESS	0x04
#define	MPI_RAIDVOL0_STATUS_FLAG_VOLUME_INACTIVE	0x08

#define	MPI_RAIDVOL0_STATUS_STATE_OPTIMAL		0x00
#define	MPI_RAIDVOL0_STATUS_STATE_DEGRADED		0x01
#define	MPI_RAIDVOL0_STATUS_STATE_FAILED		0x02
#define	MPI_RAIDVOL0_STATUS_STATE_MISSING		0x03

typedef struct raid_vol0_settings {
	uint16_t		Settings;
	uint8_t			HotSparePool;
	uint8_t			Reserved;
} raid_vol0_settings_t;

/*
 * RAID Volume Page 0 VolumeSettings defines
 */
#define	MPI_RAIDVOL0_SETTING_WRITE_CACHING_ENABLE	0x0001
#define	MPI_RAIDVOL0_SETTING_OFFLINE_ON_SMART		0x0002
#define	MPI_RAIDVOL0_SETTING_AUTO_CONFIGURE		0x0004
#define	MPI_RAIDVOL0_SETTING_PRIORITY_RESYNC		0x0008
#define	MPI_RAIDVOL0_SETTING_MASK_METADATA_SIZE		0x00C0
#define	MPI_RAIDVOL0_SETTING_64MB_METADATA_SIZE		0x0000
#define	MPI_RAIDVOL0_SETTING_512MB_METADATA_SIZE	0x0040
#define	MPI_RAIDVOL0_SETTING_USE_PRODUCT_ID_SUFFIX	0x0010
#define	MPI_RAIDVOL0_SETTING_USE_DEFAULTS		0x8000

/*
 * RAID Volume Page 0 HotSparePool defines, also used in RAID Physical Disk
 */
#define	MPI_RAID_HOT_SPARE_POOL_0			0x01
#define	MPI_RAID_HOT_SPARE_POOL_1			0x02
#define	MPI_RAID_HOT_SPARE_POOL_2			0x04
#define	MPI_RAID_HOT_SPARE_POOL_3			0x08
#define	MPI_RAID_HOT_SPARE_POOL_4			0x10
#define	MPI_RAID_HOT_SPARE_POOL_5			0x20
#define	MPI_RAID_HOT_SPARE_POOL_6			0x40
#define	MPI_RAID_HOT_SPARE_POOL_7			0x80

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this
 * define set to one and check Header.PageLength at runtime.
 */
#ifndef	MPI_RAID_VOL_PAGE_0_PHYSDISK_MAX
#define	MPI_RAID_VOL_PAGE_0_PHYSDISK_MAX		1
#endif

typedef struct config_page_raid_vol_0 {
	config_page_header_t	Header;
	uint8_t			VolumeID;
	uint8_t			VolumeBus;
	uint8_t			VolumeIOC;
	uint8_t			VolumeType;
	raid_vol0_status_t	VolumeStatus;
	raid_vol0_settings_t	VolumeSettings;
	uint32_t		MaxLBA;
	uint32_t		MaxLBAHigh;
	uint32_t		StripeSize;
	uint32_t		Reserved2;
	uint32_t		Reserved3;
	uint8_t			NumPhysDisks;
	uint8_t			Reserved4;
	uint8_t			ResyncRate;
	uint8_t			Reserved5;
	raid_vol0_phys_disk_t	PhysDisk[MPI_RAID_VOL_PAGE_0_PHYSDISK_MAX];
} config_page_raid_vol_0_t;

#define	MPI_RAIDVOLPAGE0_PAGEVERSION			0x00

typedef struct config_page_raid_vol_1
{
	config_page_header_t	Header;		/* 00h */
	uint8_t			VolumeID;	/* 04h */
	uint8_t			VolumeBus;	/* 05h */
	uint8_t			VolumeIOC;	/* 06h */
	uint8_t			Reserved0;	/* 07h */
	uint8_t			GUID[24];	/* 08h */
	uint8_t			Name[32];	/* 20h */
	uint64_t		WWID;		/* 40h */
	uint8_t			Reserved1;	/* 48h */
	uint8_t			Reserved2;	/* 4Ch */
} config_page_raid_vol_1_t;

#define	MPI_RAIDVOLPAGE1_PAGEVERSION			0x01

/*
 * RAID Physical Disk Config Pages
 */
typedef struct raid_phys_disk0_error_data {
	uint8_t			ErrorCdbByte;
	uint8_t			ErrorSenseKey;
	uint16_t		Reserved;
	uint16_t		ErrorCount;
	uint8_t			ErrorASC;
	uint8_t			ErrorASCQ;
	uint16_t		SmartCount;
	uint8_t			SmartASC;
	uint8_t			SmartASCQ;
} raid_phys_disk0_error_data_t;

typedef struct raid_phys_disk_inquiry_data {
	uint8_t			VendorID[8];
	uint8_t			ProductID[16];
	uint8_t			ProductRevLevel[4];
	uint8_t			Info[32];
} raid_phys_disk0_inquiry_data_t;

typedef struct raid_phys_disk0_settings {
	uint8_t			SepID;
	uint8_t			SepBus;
	uint8_t			HotSparePool;
	uint8_t			PhysDiskSettings;
} raid_phys_disk0_settings_t;

typedef struct raid_phys_disk0_status {
	uint8_t			Flags;
	uint8_t			State;
	uint16_t		Reserved;
} raid_phys_disk0_status_t;

/*
 * RAID Volume 2 IM Physical Disk DiskStatus flags
 */
#define	MPI_PHYSDISK0_STATUS_FLAG_OUT_OF_SYNC		0x01
#define	MPI_PHYSDISK0_STATUS_FLAG_QUIESCED		0x02

#define	MPI_PHYSDISK0_STATUS_ONLINE			0x00
#define	MPI_PHYSDISK0_STATUS_MISSING			0x01
#define	MPI_PHYSDISK0_STATUS_NOT_COMPATIBLE		0x02
#define	MPI_PHYSDISK0_STATUS_FAILED			0x03
#define	MPI_PHYSDISK0_STATUS_INITIALIZING		0x04
#define	MPI_PHYSDISK0_STATUS_OFFLINE_REQUESTED		0x05
#define	MPI_PHYSDISK0_STATUS_FAILED_REQUESTED		0x06
#define	MPI_PHYSDISK0_STATUS_OTHER_OFFLINE		0xFF

typedef struct config_page_raid_phys_disk_0 {
	config_page_header_t	Header;
	uint8_t			PhysDiskID;
	uint8_t			PhysDiskBus;
	uint8_t			PhysDiskIOC;
	uint8_t			PhysDiskNum;
	raid_phys_disk0_settings_t PhysDiskSettings;
	uint32_t		Reserved1;
	uint32_t		Reserved2;
	uint32_t		Reserved3;
	uint8_t			DiskIdentifier[16];
	raid_phys_disk0_inquiry_data_t InquiryData;
	raid_phys_disk0_status_t PhysDiskStatus;
	uint32_t		MaxLBA;
	raid_phys_disk0_error_data_t ErrorData;
} config_page_raid_phys_disk_0_t;

#define	MPI_RAIDPHYSDISKPAGE0_PAGEVERSION		0x00

typedef struct raid_phys_disk1_path {
	uint8_t			PhysDiskID;
	uint8_t			PhysDiskBus;
	uint16_t		Reserved1;
	uint64_t		WWID;
	uint64_t		OwnerWWID;
	uint8_t			OwnerIdentifier;
	uint8_t			Reserved2;
	uint16_t		Flags;
} raid_phys_disk1_path_t;

/* RAID Physical Disk Page 1 Flags field defines */

#define	MPI_RAID_PHYSDISK1_FLAG_BROKEN		0x0002
#define	MPI_RAID_PHYSDISK1_FLAG_INVALID		0x0001

#ifndef	MPI_RAID_PHYS_DISK1_PATH_MAX
#define	MPI_RAID_PHYS_DISK1_PATH_MAX		1
#endif

typedef struct config_page_raid_phys_disk_1 {
	config_page_header_t	Header;
	uint8_t			NumPhysDiskPaths;
	uint8_t			PhysDiskNum;
	uint16_t		Reserved2;
	uint32_t		Reserved1;
	raid_phys_disk1_path_t	Path[MPI_RAID_PHYS_DISK1_PATH_MAX];
} config_page_raid_phys_disk_1_t;

#define	MPI_RAIDPHYSDISKPAGE1_PAGEVERSION		0x01
/*
 * LAN Config Pages
 */
typedef struct config_page_lan_0 {
	config_page_header_t	Header;
	uint16_t		TxRxModes;
	uint16_t		Reserved;
	uint32_t		PacketPrePad;
} config_page_lan_0_t;

#define	MPI_LAN_PAGE0_PAGEVERSION			0x01

#define	MPI_LAN_PAGE0_RETURN_LOOPBACK			0x0000
#define	MPI_LAN_PAGE0_SUPPRESS_LOOPBACK			0x0001
#define	MPI_LAN_PAGE0_LOOPBACK_MASK			0x0001

typedef struct config_page_lan_1 {
	config_page_header_t	Header;
	uint16_t		Reserved;
	uint8_t			CurrentDeviceState;
	uint8_t			Reserved1;
	uint32_t		MinPacketSize;
	uint32_t		MaxPacketSize;
	uint32_t		HardwareAddressLow;
	uint32_t		HardwareAddressHigh;
	uint32_t		MaxWireSpeedLow;
	uint32_t		MaxWireSpeedHigh;
	uint32_t		BucketsRemaining;
	uint32_t		MaxReplySize;
	uint32_t		NegWireSpeedLow;
	uint32_t		NegWireSpeedHigh;
} config_page_lan_1_t;

#define	MPI_LAN_PAGE1_PAGEVERSION			0x03

#define	MPI_LAN_PAGE1_DEV_STATE_RESET			0x00
#define	MPI_LAN_PAGE1_DEV_STATE_OPERATIONAL		0x01

/*
 * Inband config pages
 */
typedef struct config_page_inband_0 {
	config_page_header_t	Header;
	mpi_version_format_t	InbandVersion;
	uint16_t		MaximumBuffers;
	uint16_t		Reserved1;
} config_page_inband_0_t;

/*
 * SAS IO Unit config pages
 */
typedef struct mpi_sas_io_unit0_phy_data {
	uint8_t			Port;
	uint8_t			PortFlags;
	uint8_t			PhyFlags;
	uint8_t			NegotiatedLinkRate;
	uint32_t		ControllerPhyDeviceInfo;
	uint16_t		AttachedDeviceHandle;
	uint16_t		ControllerDevHandle;
	uint32_t		Reserved2;
} mpi_sas_io_unit0_phy_data_t;

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this define set to
 * one and check Header.PageLength at runtime.
 */
#ifndef	MPI_SAS_IOUNIT0_PHY_MAX
#define	MPI_SAS_IOUNIT0_PHY_MAX		1
#endif

typedef struct config_page_sas_io_unit_0 {
	config_extended_page_header_t	Header;
	uint16_t			NvdataVersionDefault;
	uint16_t			NvdataVersionPersistent;
	uint8_t				NumPhys;
	uint8_t				Reserved2;
	uint16_t			Reserved3;
	mpi_sas_io_unit0_phy_data_t	PhyData[MPI_SAS_IOUNIT0_PHY_MAX];
} config_page_sas_io_unit_0_t;

#define	MPI_SASIOUNITPAGE0_PAGEVERSION		0x00

#define	MPI_SAS_IOUNIT0_PORT_FLAGS_DISCOVERY_IN_PROGRESS	0x08
#define	MPI_SAS_IOUNIT0_PORT_FLAGS_0_TARGET_IOC_NUM		0x00
#define	MPI_SAS_IOUNIT0_PORT_FLAGS_1_TARGET_IOC_NUM		0x04
#define	MPI_SAS_IOUNIT0_PORT_FLAGS_WAIT_FOR_PORTENABLE		0x02
#define	MPI_SAS_IOUNIT0_PORT_FLAGS_AUTO_PORT_CONFIG		0x01

#define	MPI_SAS_IOUNIT0_PHY_FLAGS_PHY_DISABLED			0x04
#define	MPI_SAS_IOUNIT0_PHY_FLAGS_TX_INVERT			0x02
#define	MPI_SAS_IOUNIT0_PHY_FLAGS_RX_INVERT			0x01

#define	MPI_SAS_IOUNIT0_RATE_UNKNOWN				0x00
#define	MPI_SAS_IOUNIT0_RATE_PHY_DISABLED			0x01
#define	MPI_SAS_IOUNIT0_RATE_FAILED_SPEED_NEGOTIATION		0x02
#define	MPI_SAS_IOUNIT0_RATE_SATA_OOB_COMPLETE			0x03
#define	MPI_SAS_IOUNIT0_RATE_1_5				0x08
#define	MPI_SAS_IOUNIT0_RATE_3_0				0x09

typedef struct mpi_sas_io_unit1_phy_data {
	uint8_t				Port;
	uint8_t				PortFlags;
	uint8_t				PhyFlags;
	uint8_t				MaxMinLinkRate;
	uint32_t			ControllerPhyDeviceInfo;
	uint32_t			Reserved1;
} mpi_sas_io_unit1_phy_data_t;

/*
 * Host code (drivers, BIOS, utilities, etc.) should leave this define set to
 * one and check Header.PageLength at runtime.
 */
#ifndef	MPI_SAS_IOUNIT1_PHY_MAX
#define	MPI_SAS_IOUNIT1_PHY_MAX		1
#endif

typedef struct config_page_sas_io_unit_1 {
	config_extended_page_header_t	Header;
	uint16_t			ControlFlags;
	uint16_t			MaxNumSATATargets;
	uint16_t			AdditionalControlFlags;
	uint16_t			Reserved1;
	uint8_t				NumPhys;
	uint8_t				SATAMaxQDepth;
	uint8_t				ReportMissingDeviceDelay;
	uint8_t				IODeviceMissingDelay;
	mpi_sas_io_unit1_phy_data_t	PhyData[MPI_SAS_IOUNIT1_PHY_MAX];
} config_page_sas_io_unit_1_t;

#define	MPI_SASIOUNITPAGE1_PAGEVERSION		0x00

#define	MPI_SAS_IOUNIT1_PORT_FLAGS_0_TARGET_IOC_NUM		0x00
#define	MPI_SAS_IOUNIT1_PORT_FLAGS_1_TARGET_IOC_NUM		0x04
#define	MPI_SAS_IOUNIT1_PORT_FLAGS_WAIT_FOR_PORTENABLE		0x02
#define	MPI_SAS_IOUNIT1_PORT_FLAGS_AUTO_PORT_CONFIG		0x01

#define	MPI_SAS_IOUNIT1_PHY_FLAGS_PHY_DISABLE			0x04
#define	MPI_SAS_IOUNIT1_PHY_FLAGS_TX_INVERT			0x02
#define	MPI_SAS_IOUNIT1_PHY_FLAGS_RX_INVERT			0x01

#define	MPI_SAS_IOUNIT1_MAX_RATE_MASK				0xF0
#define	MPI_SAS_IOUNIT1_MAX_RATE_1_5				0x80
#define	MPI_SAS_IOUNIT1_MAX_RATE_3_0				0x90
#define	MPI_SAS_IOUNIT1_MIN_RATE_MASK				0x0F
#define	MPI_SAS_IOUNIT1_MIN_RATE_1_5				0x08
#define	MPI_SAS_IOUNIT1_MIN_RATE_3_0				0x09

typedef struct config_page_sas_io_unit_2 {
	config_extended_page_header_t		Header;
	uint32_t				Reserved1;
	uint16_t				MaxPersistentIDs;
	uint16_t				NumPersistentIDsUsed;
	uint8_t					Status;
	uint8_t					Flags;
	uint16_t				Reserved2;
} config_page_sas_io_unit_2_t;

#define	MPI_SASIOUNITPAGE2_PAGEVERSION		0x00

#define	MPI_SAS_IOUNIT2_STATUS_DISABLED_PERSISTENT_MAPPINGS	0x02
#define	MPI_SAS_IOUNIT2_STATUS_FULL_PERSISTENT_MAPPINGS		0x01

#define	MPI_SAS_IOUNIT2_FLAGS_DISABLE_PERSISTENT_MAPPINGS	0x01

#define	MPI_SAS_IOUNIT2_FLAGS_MASK_PHYS_MAP_MODE		0x0E
#define	MPI_SAS_IOUNIT2_FLAGS_SHIFT_PHYS_MAP_MODE		1
#define	MPI_SAS_IOUNIT2_FLAGS_NO_PHYS_MAP			0x00
#define	MPI_SAS_IOUNIT2_FLAGS_DIRECT_ATTACH_PHYS_MAP		0x01
#define	MPI_SAS_IOUNIT2_FLAGS_ENCLOSURE_SLOT_PHYS_MAP		0x02
#define	MPI_SAS_IOUNIT2_FLAGS_HOST_ASSIGNED_PHYS_MAP		0x07

typedef struct config_page_sas_io_unit_3 {
	config_extended_page_header_t		Header;
	uint32_t				Reserved1;
	uint32_t				MaxInvalidDwordCount;
	uint32_t				InvalidDwordCountTime;
	uint32_t				MaxRunningDisparityErrorCount;
	uint32_t				RunningDisparityErrorTime;
	uint32_t				MaxLossDwordSynchCount;
	uint32_t				LossDwordSynchCountTime;
	uint32_t				MaxPhyResetProblemCount;
	uint32_t				PhyResetProblemTime;
} config_page_sas_io_unit_3_t;

#define	MPI_SASIOUNITPAGE3_PAGEVERSION		0x00

typedef struct config_page_sas_expander_0 {
	config_extended_page_header_t	Header;
	uint8_t				PhysicalPort;
	uint8_t				Reserved1;
	uint16_t			EnclosureHandle;
	uint64_t			SASAddress;
	uint32_t			Reserved2;
	uint16_t			DevHandle;
	uint16_t			ParentDevHandle;
	uint16_t			ExpanderChangeCount;
	uint16_t			ExpanderRouteIndexes;
	uint8_t				NumPhys;
	uint8_t				SASLevel;
	uint8_t				Flags;
	uint8_t				Reserved3;
} config_page_sas_expander_0_t;

#define	MPI_SASEXPANDER0_PAGEVERSION		0x00

#define	MPI_SAS_EXPANDER0_FLAGS_ROUTE_TABLE_CONFIG	0x02
#define	MPI_SAS_EXPANDER0_FLAGS_CONFIG_IN_PROGRESS	0x01


typedef struct config_page_sas_expander_1 {
	config_extended_page_header_t	Header;
	uint32_t			Reserved1;
	uint8_t				NumPhys;
	uint8_t				Phy;
	uint16_t			Reserved2;
	uint8_t				ProgrammedLinkRate;
	uint8_t				HwLinkRate;
	uint16_t			AttachedDevHandle;
	uint32_t			PhyInfo;
	uint32_t			AttachedDeviceInfo;
	uint16_t			OwnerDevHandle;
	uint8_t				ChangeCount;
	uint8_t				Reserved3;
	uint8_t				PhyIdentifier;
	uint8_t				AttachedPhyIdentifier;
	uint8_t				NumTableEntriesProg;
	uint8_t				DiscoveryInfo;
	uint32_t			Reserved4;
} config_page_sas_expander_1_t;

#define	MPI_SASEXPANDER1_PAGEVERSION		0x00

/* use MPI_SAS_PHY0_PRATE_ defines for ProgrammedLinkRate */

/* use MPI_SAS_PHY0_HWRATE_ defines for HwLinkRate */

/* use MPI_SAS_PHY0_PHYINFO_ defines for PhyInfo */

/* see mpi_sas.h for values for SAS Expander Page 1 AttachedDeviceInfo values */

/* values for SAS Expander Page 1 DiscoveryInfo field */
#define	MPI_SAS_EXPANDER1_DISCINFO_LINK_STATUS_CHANGE	0x02
#define	MPI_SAS_EXPANDER1_DISCINFO_NO_ROUTING_ENTRIES	0x01

typedef struct config_page_sas_device_0 {
	config_extended_page_header_t	Header;
	uint16_t			Slot;
	uint16_t			EnclosureHandle;
	uint64_t			SASAddress;
	uint16_t			ParentDevHandle;
	uint8_t				PhyNum;
	uint8_t				AccessStatus;
	uint16_t			DevHandle;
	uint8_t				TargetID;
	uint8_t				Bus;
	uint32_t			DeviceInfo;
	uint16_t			Flags;
	uint8_t				PhysicalPort;
	uint8_t				Reserved2;
} config_page_sas_device_0_t;

#define	MPI_SASDEVICE0_PAGEVERSION		0x00

#define	MPI_SAS_DEVICE0_FLAGS_MAPPING_PERSISTENT	0x04
#define	MPI_SAS_DEVICE0_FLAGS_DEVICE_MAPPED		0x02
#define	MPI_SAS_DEVICE0_FLAGS_DEVICE_PRESENT		0x01

typedef struct config_page_sas_device_1 {
	config_extended_page_header_t	Header;
	uint32_t			Reserved1;
	uint64_t			SASAddress;
	uint32_t			Reserved2;
	uint16_t			DevHandle;
	uint8_t				TargetID;
	uint8_t				Bus;
	uint8_t				InitialRegDeviceFIS[20];
} config_page_sas_device_1_t;

#define	MPI_SASDEVICE1_PAGEVERSION		0x00

typedef struct config_page_sas_phy_0 {
	config_extended_page_header_t	Header;
	uint32_t			Reserved1;
	uint64_t			SASAddress;
	uint16_t			AttachedDevHandle;
	uint8_t				AttachedPhyIdentifier;
	uint8_t				Reserved2;
	uint32_t			AttachedDeviceInfo;
	uint8_t				ProgrammedLinkRate;
	uint8_t				HwLinkRate;
	uint8_t				ChangeCount;
	uint8_t				Reserved3;
	uint32_t			PhyInfo;
} config_page_sas_phy_0_t;

#define	MPI_SASPHY0_PAGEVERSION		0x00

#define	MPI_SAS_PHY0_PRATE_MAX_RATE_MASK		0xF0
#define	MPI_SAS_PHY0_PRATE_MAX_RATE_NOT_PROGRAMMABLE	0x00
#define	MPI_SAS_PHY0_PRATE_MAX_RATE_1_5			0x80
#define	MPI_SAS_PHY0_PRATE_MAX_RATE_3_0			0x90
#define	MPI_SAS_PHY0_PRATE_MIN_RATE_MASK		0x0F
#define	MPI_SAS_PHY0_PRATE_MIN_RATE_NOT_PROGRAMMABLE	0x00
#define	MPI_SAS_PHY0_PRATE_MIN_RATE_1_5			0x08
#define	MPI_SAS_PHY0_PRATE_MIN_RATE_3_0			0x09

#define	MPI_SAS_PHY0_HWRATE_MAX_RATE_MASK		0xF0
#define	MPI_SAS_PHY0_HWRATE_MAX_RATE_1_5		0x80
#define	MPI_SAS_PHY0_HWRATE_MAX_RATE_3_0		0x90
#define	MPI_SAS_PHY0_HWRATE_MIN_RATE_MASK		0x0F
#define	MPI_SAS_PHY0_HWRATE_MIN_RATE_1_5		0x08
#define	MPI_SAS_PHY0_HWRATE_MIN_RATE_3_0		0x09

#define	MPI_SAS_PHY0_PHYINFO_SATA_PORT_ACTIVE		0x00004000
#define	MPI_SAS_PHY0_PHYINFO_SATA_PORT_SELECTOR		0x00002000
#define	MPI_SAS_PHY0_PHYINFO_VIRTUAL_PHY		0x00001000

#define	MPI_SAS_PHY0_PHYINFO_MASK_PARTIAL_PATHWAY_TIME	0x00000F00
#define	MPI_SAS_PHY0_PHYINFO_SHIFT_PARTIAL_PATHWAY_TIME	8

#define	MPI_SAS_PHY0_PHYINFO_MASK_ROUTING_ATTRIBUTE	0x000000F0
#define	MPI_SAS_PHY0_PHYINFO_DIRECT_ROUTING		0x00000000
#define	MPI_SAS_PHY0_PHYINFO_SUBTRACTIVE_ROUTING	0x00000010
#define	MPI_SAS_PHY0_PHYINFO_TABLE_ROUTING		0x00000020

#define	MPI_SAS_PHY0_DEVINFO_SATA_DEVICE		0x00000080

#define	MPI_SAS_PHY0_PHYINFO_MASK_LINK_RATE		0x0000000F
#define	MPI_SAS_PHY0_PHYINFO_UNKNOWN_LINK_RATE		0x00000000
#define	MPI_SAS_PHY0_PHYINFO_PHY_DISABLED		0x00000001
#define	MPI_SAS_PHY0_PHYINFO_NEGOTIATION_FAILED		0x00000002
#define	MPI_SAS_PHY0_PHYINFO_SATA_OOB_COMPLETE		0x00000003
#define	MPI_SAS_PHY0_PHYINFO_RATE_1_5			0x00000008
#define	MPI_SAS_PHY0_PHYINFO_RATE_3_0			0x00000009

typedef struct config_page_sas_phy_1 {
	config_extended_page_header_t	Header;
	uint32_t			Reserved1;
	uint32_t			InvalidDwordCount;
	uint32_t			RunningDisparityErrorCount;
	uint32_t			LossDwordSynchCount;
	uint32_t			PhyResetProblemCount;
} config_page_sas_phy_1_t;

#define	MPI_SASPHY1_PAGEVERSION		0x00

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MPI_CNFG_H */
