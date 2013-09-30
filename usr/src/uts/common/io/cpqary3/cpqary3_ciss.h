/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#ifndef	_CPQARY3_CISS_H
#define	_CPQARY3_CISS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	CISS_VERSION		"1.00"

/* General Boundary Defintions */
#define	CISS_INIT_TIME		90	/* Driver Defined Value */
					/* Duration to Wait for the */
					/* controller initialization */
#define	CISS_SENSEINFOBYTES	256	/* Note that this value may vary */
					/* between host implementations */
#define	CISS_MAXSGENTRIES	64
#define	CISS_MAXREPLYQS		256

/* Command Status Value */
#define	CISS_CMD_SUCCESS		0x00
#define	CISS_CMD_TARGET_STATUS		0x01
#define	CISS_CMD_DATA_UNDERRUN		0x02
#define	CISS_CMD_DATA_OVERRUN		0x03
#define	CISS_CMD_INVALID		0x04
#define	CISS_CMD_PROTOCOL_ERR		0x05
#define	CISS_CMD_HARDWARE_ERR		0x06
#define	CISS_CMD_CONNECTION_LOST	0x07
#define	CISS_CMD_ABORTED		0x08
#define	CISS_CMD_ABORT_FAILED		0x09
#define	CISS_CMD_UNSOLICITED_ABORT	0x0A
#define	CISS_CMD_TIMEOUT		0x0B
#define	CISS_CMD_UNABORTABLE		0x0C

/* Transfer Direction */
#define	CISS_XFER_NONE		0x00
#define	CISS_XFER_WRITE		0x01
#define	CISS_XFER_READ		0x02
#define	CISS_XFER_RSVD		0x03

#define	CISS_ATTR_UNTAGGED	0x00
#define	CISS_ATTR_SIMPLE	0x04
#define	CISS_ATTR_HEADOFQUEUE	0x05
#define	CISS_ATTR_ORDERED	0x06

/* CDB Type */
#define	CISS_TYPE_CMD		0x00
#define	CISS_TYPE_MSG		0x01

/* Config Space Register Offsetsp */
#define	CFG_VENDORID		0x00
#define	CFG_DEVICEID		0x02
#define	CFG_I2OBAR		0x10
#define	CFG_MEM1BAR		0x14

/* I2O Space Register Offsets */
#define	I2O_IBDB_SET		0x20
#define	I2O_IBDB_CLEAR		0x70
#define	I2O_INT_STATUS		0x30
#define	I2O_INT_MASK		0x34
#define	I2O_IBPOST_Q		0x40
#define	I2O_OBPOST_Q		0x44
#define	I2O_OBDB_STATUS		0x9C
#define	I2O_OBDB_CLEAR		0xA0
#define	I2O_CTLR_INIT		0xB0	/* not available in CISS specs */

/* Configuration Table */
#define	CFGTBL_CHANGE_REQ	0x00000001l
#define	CFGTBL_ACC_CMDS		0x00000001l

/* Transport Method */
#define	CFGTBL_XPORT_SIMPLE		0x00000002l
#define	CFGTBL_XPORT_PERFORMANT		0x00000004l
#define	CFGTBL_XPORT_MEMQ		0x00000008l

#define	CPQARY3_SIMPLE		CFGTBL_XPORT_SIMPLE
#define	CPQARY3_PERFORMANT	CFGTBL_XPORT_PERFORMANT

/* not being used currently */
#define	CFGTBL_BusType_Ultra2	0x00000001l
#define	CFGTBL_BusType_Ultra3	0x00000002l
#define	CFGTBL_BusType_Fibre1G	0x00000100l
#define	CFGTBL_BusType_Fibre2G	0x00000200l

/* for hard reset of the controller */
#define	CISS_POWER_OFF		0x03	/* Self Defined */
#define	CISS_POWER_ON		0x00	/* Self Defined */
#define	CISS_POWER_REG_OFFSET	0xF4	/* Self Defined */

#define	CT_CFG_OFFSET		0xB4
#define	CT_MEM_OFFSET		0xB8

/*
 * STRUCTURES
 * Command List Structure
 */

#pragma pack(1)

typedef uint64_t QWORD;

/*
 * Structure for Tag field in the controller command structure
 * Bit 0	: Unused
 * Bit 1 	: If set, signifies an error in processing of the command
 * Bits 2 & 3 	: Used by this driver to signify a host of situations
 * Bits 4-31 	: Used by driver to fill in tag and then used by controller
 * Bits 32-63 	: Reserved
 */
#define	CISS_CMD_ERROR		0x2
typedef struct cpqary3_tag {
	uint32_t	reserved:1;
	uint32_t	drvinfo_n_err:3;
	uint32_t	tag_value:28;
	uint32_t	unused;
} cpqary3_tag_t;

typedef union _SCSI3Addr_t {
	struct {
		uint8_t Bus:6;
		uint8_t Mode:2;
		uint8_t Dev;
	} PeripDev;
	struct {
		uint8_t DevMSB:6;
		uint8_t Mode:2;
		uint8_t DevLSB;
	} LogDev;
	struct {
		uint8_t Targ:6;
		uint8_t Mode:2;
		uint8_t Dev:5;
		uint8_t Bus:3;
	} LogUnit;
} SCSI3Addr_t;

typedef struct _PhysDevAddr_t {
	uint32_t    TargetId:24;
	uint32_t    Bus:6;
	uint32_t    Mode:2;
	SCSI3Addr_t Target[2];
} PhysDevAddr_t;

typedef struct _LogDevAddr_t {
	uint32_t	VolId:30;
	uint32_t	Mode:2;
	uint8_t		reserved[4];
} LogDevAddr_t;

typedef union _LUNAddr_t {
	uint8_t		LunAddrBytes[8];
	SCSI3Addr_t	SCSI3Lun[4];
	PhysDevAddr_t	PhysDev;
	LogDevAddr_t	LogDev;
} LUNAddr_t;

typedef struct _CommandListHeader_t {
	uint8_t		ReplyQueue;
	uint8_t		SGList;
	uint16_t	SGTotal;
	cpqary3_tag_t	Tag;
	LUNAddr_t	LUN;			/* 20 */
} CommandListHeader_t;

typedef struct _RequestBlock_t {
	uint8_t	CDBLen;
	struct {
		uint8_t	Type:3;
		uint8_t	Attribute:3;
		uint8_t	Direction:2;
	} Type;
	uint16_t	Timeout;
	uint8_t		CDB[16];		/* 20 */
} RequestBlock_t;

typedef struct _ErrDescriptor_t {
	QWORD		Addr;
	uint32_t	Len;			/* 12 */
} ErrDescriptor_t;

typedef struct _SGDescriptor_t {
	QWORD		Addr;
	uint32_t	Len;
	uint32_t	Ext;			/* 16 */
} SGDescriptor_t;

typedef struct _CommandList_t {
	CommandListHeader_t Header;		/* 20 */
	RequestBlock_t Request;			/* 20, 40 */
	ErrDescriptor_t ErrDesc;		/* 12, 52 */
	SGDescriptor_t SG[CISS_MAXSGENTRIES];	/* 16*SG_MAXENTRIES=512, 564 */
} CommandList_t;

typedef union _MoreErrInfo_t {
	struct {
		uint8_t		Reserved[3];
		uint8_t		Type;
		uint32_t	ErrorInfo;
	} Common_Info;
	struct {
		uint8_t		Reserved[2];
		uint8_t		offense_size;
		uint8_t		offense_num;
		uint32_t	offense_value;
	} Invalid_Cmd;
} MoreErrInfo_t;

typedef struct _ErrorInfo_t {
	uint8_t		ScsiStatus;
	uint8_t		SenseLen;
	uint16_t	CommandStatus;
	uint32_t	ResidualCnt;
	MoreErrInfo_t	MoreErrInfo;
	uint8_t		SenseInfo[CISS_SENSEINFOBYTES]; /* 256 + 24 = 280 */
} ErrorInfo_t;

/* Configuration Table Structure */
typedef struct _HostWrite_t {
	uint32_t	TransportRequest;
	uint32_t	Upper32Addr;
	uint32_t	CoalIntDelay;
	uint32_t	CoalIntCount;
} HostWrite_t;

typedef struct _CfgTable_t {
	uint8_t		Signature[4];
	uint32_t	SpecValence;
	uint32_t	TransportSupport;
	uint32_t	TransportActive;
	HostWrite_t	HostWrite;
	uint32_t	CmdsOutMax;
	uint32_t	BusTypes;
	uint32_t	TransportMethodOffset;
	uint8_t		ServerName[16];
	uint32_t	HeartBeat;
	/* PERF */
	uint32_t	HostDrvrSupport;	/* 0x40 offset from cfg table */
	uint32_t	MaxSGElements;		/* 0x44 offset from cfg table */
	uint32_t	MaxLunSupport;		/* 0x48 offset from cfg table */
	uint32_t	MaxPhyDevSupport;	/* 0x4C offset from cfg table */
	uint32_t	MaxPhyDrvPerLun;	/* 0x50 offset from cfg table */
	uint32_t	MaxPerfModeCmdsOutMax;	/* 0x54 offset from cfg table */
	uint32_t	MaxBlockFetchCount;	/* 0x58 offset from cfg table */
	/* PERF */
} CfgTable_t;

typedef struct _CfgTrans_Perf_t {
	uint32_t	BlockFetchCnt[8];
	uint32_t	ReplyQSize;
	uint32_t	ReplyQCount;
	uint32_t	ReplyQCntrAddrLow32;
	uint32_t	ReplyQCntrAddrHigh32;
	uint32_t	ReplyQAddr0Low32;
	uint32_t	ReplyQAddr0High32;
} CfgTrans_Perf_t;

typedef struct _CfgTrans_MemQ_t {
	uint32_t	BlockFetchCnt[8];
	uint32_t	CmdQSize;
	uint32_t	CmdQOffset;
	uint32_t	ReplyQSize;
	uint32_t	ReplyQCount;
	QWORD		ReplyQCntrAddr;
	QWORD		ReplyQAddr[CISS_MAXREPLYQS];
} CfgTrans_MemQ_t;

typedef union _CfgTrans_t {
	CfgTrans_Perf_t	*Perf;
	CfgTrans_MemQ_t	*MemQ;
} CfgTrans_t;

#define	CPQARY3_REPLYQ_INIT_CYCLIC_IND	0x1
typedef struct cpqary3_drvr_replyq {
	uchar_t		cyclic_indicator;
	uchar_t 	simple_cyclic_indicator;
	caddr_t 	replyq_start_addr;
	uint32_t	replyq_start_paddr;
	uint32_t	*replyq_headptr;
	uint32_t	*replyq_simple_ptr;
	uint32_t	index;
	uint32_t	simple_index;
	uint32_t	max_index;
} cpqary3_drvr_replyq_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif /* _CPQARY3_CISS_H */
