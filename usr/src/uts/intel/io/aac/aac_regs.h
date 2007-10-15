/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2005-06 Adaptec, Inc.
 * Copyright (c) 2005-06 Adaptec Inc., Achim Leubner
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2000-2001 Scott Long
 * Copyright (c) 2000 BSDi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *    $FreeBSD: src/sys/dev/aac/aacreg.h,v 1.23 2005/10/14 16:22:45 scottl Exp $
 */

#ifndef	__AAC_REGS_H__
#define	__AAC_REGS_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Status bits in the doorbell registers */
#define	AAC_DB_SYNC_COMMAND		(1<<0)	/* send/completed synchronous */
						/* FIB */
#define	AAC_DB_COMMAND_READY		(1<<1)	/* posted one or more */
						/* commands */
#define	AAC_DB_RESPONSE_READY		(1<<2)	/* one or more commands	*/
						/* complete */
#define	AAC_DB_COMMAND_NOT_FULL		(1<<3)	/* command queue not full */
#define	AAC_DB_RESPONSE_NOT_FULL	(1<<4)	/* response queue not full */
#define	AAC_DB_PRINTF_READY		(1<<5)	/* adapter requests host */
						/* printf */
#define	AAC_DB_INTR_BITS (AAC_DB_COMMAND_READY | \
	AAC_DB_RESPONSE_READY | AAC_DB_PRINTF_READY)
#define	AAC_DB_INTR_NEW			0x08

/* Status bits in firmware status reg */
#define	AAC_SELF_TEST_FAILED		0x00000004
#define	AAC_MONITOR_PANIC		0x00000020
#define	AAC_KERNEL_UP_AND_RUNNING	0x00000080
#define	AAC_KERNEL_PANIC		0x00000100

/* aac registers definitions */
#define	AAC_OMR0		0x18	/* outbound message register 0 */
#define	AAC_OMR1		0x1c	/* outbound message register 1 */
#define	AAC_IDBR		0x20	/* inbound doorbell reg */
#define	AAC_ODBR		0x2c	/* outbound doorbell reg */
#define	AAC_OIMR		0x34	/* outbound interrupt mask reg */
#define	AAC_IRCSR		0x38	/* inbound dual cores reset (SRL) */
#define	AAC_IQUE		0x40	/* inbound queue */
#define	AAC_OQUE		0x44	/* outbound queue */
#define	AAC_RX_MAILBOX		0x50	/* mailbox, size=20bytes, rx */
#define	AAC_RX_FWSTATUS		0x6c	/* firmware status, rx */
#define	AAC_RKT_MAILBOX		0x1000	/* mailbox, size=20bytes, rkt */
#define	AAC_RKT_FWSTATUS	0x101c	/* firmware status, rkt */

/* Synchronous commands to the monitor/kernel. */
#define	AAC_BREAKPOINT_REQ	0x04
#define	AAC_MONKER_INITSTRUCT	0x05
#define	AAC_MONKER_SYNCFIB	0x0c
#define	AAC_MONKER_GETKERNVER	0x11
#define	AAC_MONKER_GETINFO	0x19
#define	AAC_MONKER_GETDRVPROP	0x23
#define	AAC_MONKER_GETCOMMPREF	0x26
#define	AAC_IOP_RESET		0x1000

/* Sunrise Lake dual core reset */
#define	AAC_IRCSR_CORES_RST	3

#define	AAC_SECTOR_SIZE		512
#define	AAC_NUMBER_OF_HEADS	255
#define	AAC_SECTORS_PER_TRACK	63
#define	AAC_ROTATION_SPEED	10000
#define	AAC_MAX_PFN		0xfffff

#define	AAC_ADDITIONAL_LEN	31
#define	AAC_ANSI_VER		2
#define	AAC_RESP_DATA_FORMAT	2

#define	AAC_MAX_LD		64	/* max number of logical disks */
#define	AAC_BLK_SIZE		AAC_SECTOR_SIZE
#define	AAC_DMA_ALIGN		4
#define	AAC_DMA_ALIGN_MASK	(AAC_DMA_ALIGN - 1)

#define	AAC_MAX_CONTAINERS	AAC_MAX_LD

/*
 * Minimum memory sizes we need to map to address the adapter. Before
 * we know the actual size to map, minimum memory is used instead.
 */
#define	AAC_MAP_SIZE_MIN_RX	4096
#define	AAC_MAP_SIZE_MIN_RKT	8192

/*
 * Options supported by the adapter
 */
#define	AAC_SUPPORTED_SNAPSHOT			0x01
#define	AAC_SUPPORTED_CLUSTERS			0x02
#define	AAC_SUPPORTED_WRITE_CACHE		0x04
#define	AAC_SUPPORTED_64BIT_DATA		0x08
#define	AAC_SUPPORTED_HOST_TIME_FIB		0x10
#define	AAC_SUPPORTED_RAID50			0x20
#define	AAC_SUPPORTED_4GB_WINDOW		0x40
#define	AAC_SUPPORTED_SCSI_UPGRADEABLE		0x80
#define	AAC_SUPPORTED_SOFT_ERR_REPORT		0x100
#define	AAC_SUPPORTED_NOT_RECONDITION		0x200
#define	AAC_SUPPORTED_SGMAP_HOST64		0x400
#define	AAC_SUPPORTED_ALARM			0x800
#define	AAC_SUPPORTED_NONDASD			0x1000
#define	AAC_SUPPORTED_SCSI_MANAGED		0x2000
#define	AAC_SUPPORTED_RAID_SCSI_MODE		0x4000
#define	AAC_SUPPORTED_SUPPLEMENT_ADAPTER_INFO	0x10000
#define	AAC_SUPPORTED_NEW_COMM			0x20000
#define	AAC_SUPPORTED_64BIT_ARRAYSIZE		0x40000
#define	AAC_SUPPORTED_HEAT_SENSOR		0x80000

#pragma	pack(1)

/*
 * FIB (FSA Interface Block) this is the data structure passed between
 * the host and adapter.
 */
struct aac_fib_header {
	uint32_t	XferState;
	uint16_t	Command;
	uint8_t		StructType;
	uint8_t		Flags;
	uint16_t	Size;
	uint16_t	SenderSize;
	uint32_t	SenderFibAddress;
	uint32_t	ReceiverFibAddress;
	uint32_t	SenderData;
	int prev;
	int next;
};

/* FIB completed without error or no data was transferred in the FIB */
#define	AAC_SENDERADDR_MASK_FAST_RESPONSE	0x01
/* The received FIB is an AIF */
#define	AAC_SENDERADDR_MASK_AIF			0x02

#define	AAC_FIB_SIZE		512 /* size of a fib block in byte */
#define	AAC_FIB_DATASIZE	(AAC_FIB_SIZE - sizeof (struct aac_fib_header))

struct aac_fib {
	struct aac_fib_header	Header;
	uint8_t data[AAC_FIB_DATASIZE];
};

/* FIB transfer state */
#define	AAC_FIBSTATE_HOSTOWNED		(1<<0)	/* owned by the host */
#define	AAC_FIBSTATE_ADAPTEROWNED	(1<<1)	/* owned by the adapter */
#define	AAC_FIBSTATE_INITIALISED	(1<<2)	/* has been initialised */
#define	AAC_FIBSTATE_EMPTY		(1<<3)	/* is empty now */
#define	AAC_FIBSTATE_FROMHOST		(1<<5)	/* sent from the host */
#define	AAC_FIBSTATE_FROMADAP		(1<<6)	/* sent from the adapter */
#define	AAC_FIBSTATE_REXPECTED		(1<<7)	/* response is expected */
#define	AAC_FIBSTATE_NOREXPECTED	(1<<8)	/* no response is expected */
#define	AAC_FIBSTATE_DONEADAP		(1<<9)	/* processed by the adapter */
#define	AAC_FIBSTATE_DONEHOST		(1<<10)	/* processed by the host */
#define	AAC_FIBSTATE_NORM		(1<<12)	/* normal priority */
#define	AAC_FIBSTATE_ASYNC		(1<<13)
#define	AAC_FIBSTATE_FAST_RESPONSE	(1<<19)	/* fast response capable */

/* FIB types */
#define	AAC_FIBTYPE_TFIB		1

/*
 * FIB commands
 */

#define	TestCommandResponse		1
#define	TestAdapterCommand		2
/* Lowlevel and comm commands */
#define	LastTestCommand			100
#define	ReinitHostNormCommandQueue	101
#define	ReinitHostHighCommandQueue	102
#define	ReinitHostHighRespQueue		103
#define	ReinitHostNormRespQueue		104
#define	ReinitAdapNormCommandQueue	105
#define	ReinitAdapHighCommandQueue	107
#define	ReinitAdapHighRespQueue		108
#define	ReinitAdapNormRespQueue		109
#define	InterfaceShutdown		110
#define	DmaCommandFib			120
#define	StartProfile			121
#define	TermProfile			122
#define	SpeedTest			123
#define	TakeABreakPt			124
#define	RequestPerfData			125
#define	SetInterruptDefTimer		126
#define	SetInterruptDefCount		127
#define	GetInterruptDefStatus		128
#define	LastCommCommand			129
/* Filesystem commands */
#define	NuFileSystem			300
#define	UFS				301
#define	HostFileSystem			302
#define	LastFileSystemCommand		303
/* Container commands */
#define	ContainerCommand		500
#define	ContainerCommand64		501
#define	RawIo				502
/* Cluster commands */
#define	ClusterCommand			550
/* Scsi Port commands (scsi passthrough) */
#define	ScsiPortCommand			600
#define	ScsiPortCommandU64		601
/* Misc house keeping and generic adapter initiated commands */
#define	AifRequest			700
#define	CheckRevision			701
#define	FsaHostShutdown			702
#define	RequestAdapterInfo		703
#define	IsAdapterPaused			704
#define	SendHostTime			705
#define	RequestSupplementAdapterInfo	706
#define	LastMiscCommand			707
#define	OnLineDiagnostic		800
#define	FduAdapterTest			801

/*
 * Revision number handling
 */
struct FsaRev {
	union {
		struct {
			uint8_t	dash;
			uint8_t	type;
			uint8_t	minor;
			uint8_t	major;
		} comp;
		uint32_t ul;
	} external;
	uint32_t buildNumber;
};

/*
 * Structures used to respond to a RequestAdapterInfo FIB
 */
struct aac_adapter_info {
	uint32_t	PlatformBase;	/* adapter type */
	uint32_t	CpuArchitecture; /* adapter CPU type */
	uint32_t	CpuVariant;	/* adapter CPU subtype */
	uint32_t	ClockSpeed;	/* adapter CPU clockspeed */
	uint32_t	ExecutionMem;	/* adapter Execution Memory size */
	uint32_t	BufferMem;	/* adapter Data Memory */
	uint32_t	TotalMem;	/* adapter Total Memory */
	struct FsaRev	KernelRevision;	/* adapter Kernel Software Revision */
	struct FsaRev	MonitorRevision; /* adapter Monitor Software Revision */
	struct FsaRev	HardwareRevision;
	struct FsaRev	BIOSRevision;	/* adapter BIOS Revision */
	uint32_t	ClusteringEnabled;
	uint32_t	ClusterChannelMask;
	uint64_t	SerialNumber;
	uint32_t	batteryPlatform;
	uint32_t	SupportedOptions; /* supported features */
	uint32_t	OemVariant;
};

/*
 * The following definitions on Supplement Adapter Information
 * come from Adaptec:
 */
struct vpd_info {
	uint8_t		AssemblyPn[8];
	uint8_t		FruPn[8];
	uint8_t		BatteryFruPn[8];
	uint8_t		EcVersionString[8];
	uint8_t		Tsid[12];
};

#define	MFG_PCBA_SERIAL_NUMBER_WIDTH	12
#define	MFG_WWN_WIDTH			8

struct aac_supplement_adapter_info {
	/* The assigned Adapter Type Text, extra byte for null termination */
	int8_t		AdapterTypeText[17+1];
	/* Pad for the text above */
	int8_t		Pad[2];
	/* Size in bytes of the memory that is flashed */
	uint32_t	FlashMemoryByteSize;
	/* The assigned IMAGEID_xxx for this adapter */
	uint32_t	FlashImageId;
	/*
	 * The maximum number of Phys available on a SATA/SAS
	 * Controller, 0 otherwise
	 */
	uint32_t	MaxNumberPorts;
	/* Version of expansion area */
	uint32_t	Version;
	uint32_t	FeatureBits;
	uint8_t		SlotNumber;
	uint8_t		ReservedPad0[3];
	uint8_t		BuildDate[12];
	/* The current number of Ports on a SAS controller, 0 otherwise */
	uint32_t	CurrentNumberPorts;

	struct vpd_info VpdInfo;

	/* Firmware Revision (Vmaj.min-dash.) */
	struct FsaRev	FlashFirmwareRevision;
	uint32_t	RaidTypeMorphOptions;
	/* Firmware's boot code Revision (Vmaj.min-dash.) */
	struct FsaRev	FlashFirmwareBootRevision;
	/* PCBA serial no. from th MFG sector */
	uint8_t		MfgPcbaSerialNo[MFG_PCBA_SERIAL_NUMBER_WIDTH];
	/* WWN from the MFG sector */
	uint8_t		MfgWWNName[MFG_WWN_WIDTH];
	/* Growth Area for future expansion ((7*4) - 12 - 8)/4 = 2 words */
	uint32_t	ReservedGrowth[2];
};

/* Container creation data */
struct aac_container_creation {
	uint8_t		ViaBuildNumber;
	uint8_t		MicroSecond;
	uint8_t		Via;		/* 1 = FSU, 2 = API, etc */
	uint8_t		Years;		/* Since1900 */
	uint32_t	Month:4;	/* 1-12 */
	uint32_t	Day:6;		/* 1-32 */
	uint32_t	Hour:6;		/* 0-23 */
	uint32_t	Minute:6;	/* 0-59 */
	uint32_t	Second:6;	/* 0-59 */
	uint64_t	ViaAdapterSerialNumber;
};

struct aac_mntobj {
	uint32_t		ObjectId;
	char			FileSystemName[16];
	struct aac_container_creation	CreateInfo;
	uint32_t		Capacity;
	uint32_t		VolType;
	uint32_t		ObjType;
	uint32_t		ContentState;
	union {
		uint32_t	pad[8];
	} ObjExtension;
	uint32_t		AlterEgoId;

	uint32_t		CapacityHigh; /* 64-bit LBA */
};

struct aac_mntinfo {
	uint32_t	Command;
	uint32_t	MntType;
	uint32_t	MntCount;
};

struct aac_mntinforesp {
	uint32_t		Status;
	uint32_t		MntType;
	uint32_t		MntRespCount;
	struct aac_mntobj	MntObj;
};

#define	CT_FIB_PARAMS			6
#define	MAX_FIB_PARAMS			10
#define	CT_PACKET_SIZE \
	(AAC_FIB_DATASIZE - sizeof (uint32_t) - \
	((sizeof (uint32_t)) * (MAX_FIB_PARAMS + 1)))

#define	CNT_SIZE			5

/* Container types */
typedef enum {
	CT_NONE = 0,
	CT_VOLUME,
	CT_MIRROR,
	CT_STRIPE,
	CT_RAID5,
	CT_SSRW,
	CT_SSRO,
	CT_MORPH,
	CT_PASSTHRU,
	CT_RAID4,
	CT_RAID10,		/* stripe of mirror */
	CT_RAID00,		/* stripe of stripe */
	CT_VOLUME_OF_MIRRORS,	/* volume of mirror */
	CT_PSEUDO_RAID3,	/* really raid4 */
	CT_RAID50,		/* stripe of raid5 */
	CT_RAID5D,		/* raid5 distributed hot-sparing */
	CT_RAID5D0,
	CT_RAID1E,		/* extended raid1 mirroring */
	CT_RAID6,
	CT_RAID60
} AAC_FSAVolType;

/*
 * Container Configuration Sub-Commands
 */
typedef enum {
	CT_Null = 0,
	CT_GET_SLICE_COUNT,		/* 1 */
	CT_GET_PARTITION_COUNT,		/* 2 */
	CT_GET_PARTITION_INFO,		/* 3 */
	CT_GET_CONTAINER_COUNT,		/* 4 */
	CT_GET_CONTAINER_INFO_OLD,	/* 5 */
	CT_WRITE_MBR,			/* 6 */
	CT_WRITE_PARTITION,		/* 7 */
	CT_UPDATE_PARTITION,		/* 8 */
	CT_UNLOAD_CONTAINER,		/* 9 */
	CT_CONFIG_SINGLE_PRIMARY,	/* 10 */
	CT_READ_CONFIG_AGE,		/* 11 */
	CT_WRITE_CONFIG_AGE,		/* 12 */
	CT_READ_SERIAL_NUMBER,		/* 13 */
	CT_ZERO_PAR_ENTRY,		/* 14 */
	CT_READ_MBR,			/* 15 */
	CT_READ_PARTITION,		/* 16 */
	CT_DESTROY_CONTAINER,		/* 17 */
	CT_DESTROY2_CONTAINER,		/* 18 */
	CT_SLICE_SIZE,			/* 19 */
	CT_CHECK_CONFLICTS,		/* 20 */
	CT_MOVE_CONTAINER,		/* 21 */
	CT_READ_LAST_DRIVE,		/* 22 */
	CT_WRITE_LAST_DRIVE,		/* 23 */
	CT_UNMIRROR,			/* 24 */
	CT_MIRROR_DELAY,		/* 25 */
	CT_GEN_MIRROR,			/* 26 */
	CT_GEN_MIRROR2,			/* 27 */
	CT_TEST_CONTAINER,		/* 28 */
	CT_MOVE2,			/* 29 */
	CT_SPLIT,			/* 30 */
	CT_SPLIT2,			/* 31 */
	CT_SPLIT_BROKEN,		/* 32 */
	CT_SPLIT_BROKEN2,		/* 33 */
	CT_RECONFIG,			/* 34 */
	CT_BREAK2,			/* 35 */
	CT_BREAK,			/* 36 */
	CT_MERGE2,			/* 37 */
	CT_MERGE,			/* 38 */
	CT_FORCE_ERROR,			/* 39 */
	CT_CLEAR_ERROR,			/* 40 */
	CT_ASSIGN_FAILOVER,		/* 41 */
	CT_CLEAR_FAILOVER,		/* 42 */
	CT_GET_FAILOVER_DATA,		/* 43 */
	CT_VOLUME_ADD,			/* 44 */
	CT_VOLUME_ADD2,			/* 45 */
	CT_MIRROR_STATUS,		/* 46 */
	CT_COPY_STATUS,			/* 47 */
	CT_COPY,			/* 48 */
	CT_UNLOCK_CONTAINER,		/* 49 */
	CT_LOCK_CONTAINER,		/* 50 */
	CT_MAKE_READ_ONLY,		/* 51 */
	CT_MAKE_READ_WRITE,		/* 52 */
	CT_CLEAN_DEAD,			/* 53 */
	CT_ABORT_MIRROR_COMMAND,	/* 54 */
	CT_SET,				/* 55 */
	CT_GET,				/* 56 */
	CT_GET_NVLOG_ENTRY,		/* 57 */
	CT_GET_DELAY,			/* 58 */
	CT_ZERO_CONTAINER_SPACE,	/* 59 */
	CT_GET_ZERO_STATUS,		/* 60 */
	CT_SCRUB,			/* 61 */
	CT_GET_SCRUB_STATUS,		/* 62 */
	CT_GET_SLICE_INFO,		/* 63 */
	CT_GET_SCSI_METHOD,		/* 64 */
	CT_PAUSE_IO,			/* 65 */
	CT_RELEASE_IO,			/* 66 */
	CT_SCRUB2,			/* 67 */
	CT_MCHECK,			/* 68 */
	CT_CORRUPT,			/* 69 */
	CT_GET_TASK_COUNT,		/* 70 */
	CT_PROMOTE,			/* 71 */
	CT_SET_DEAD,			/* 72 */
	CT_CONTAINER_OPTIONS,		/* 73 */
	CT_GET_NV_PARAM,		/* 74 */
	CT_GET_PARAM,			/* 75 */
	CT_NV_PARAM_SIZE,		/* 76 */
	CT_COMMON_PARAM_SIZE,		/* 77 */
	CT_PLATFORM_PARAM_SIZE,		/* 78 */
	CT_SET_NV_PARAM,		/* 79 */
	CT_ABORT_SCRUB,			/* 80 */
	CT_GET_SCRUB_ERROR,		/* 81 */
	CT_LABEL_CONTAINER,		/* 82 */
	CT_CONTINUE_DATA,		/* 83 */
	CT_STOP_DATA,			/* 84 */
	CT_GET_PARTITION_TABLE,		/* 85 */
	CT_GET_DISK_PARTITIONS,		/* 86 */
	CT_GET_MISC_STATUS,		/* 87 */
	CT_GET_CONTAINER_PERF_INFO,	/* 88 */
	CT_GET_TIME,			/* 89 */
	CT_READ_DATA,			/* 90 */
	CT_CTR,				/* 91 */
	CT_CTL,				/* 92 */
	CT_DRAINIO,			/* 93 */
	CT_RELEASEIO,			/* 94 */
	CT_GET_NVRAM,			/* 95 */
	CT_GET_MEMORY,			/* 96 */
	CT_PRINT_CT_LOG,		/* 97 */
	CT_ADD_LEVEL,			/* 98 */
	CT_NV_ZERO,			/* 99 */
	CT_READ_SIGNATURE,		/* 100 */
	CT_THROTTLE_ON,			/* 101 */
	CT_THROTTLE_OFF,		/* 102 */
	CT_GET_THROTTLE_STATS,		/* 103 */
	CT_MAKE_SNAPSHOT,		/* 104 */
	CT_REMOVE_SNAPSHOT,		/* 105 */
	CT_WRITE_USER_FLAGS,		/* 106 */
	CT_READ_USER_FLAGS,		/* 107 */
	CT_MONITOR,			/* 108 */
	CT_GEN_MORPH,			/* 109 */
	CT_GET_SNAPSHOT_INFO,		/* 110 */
	CT_CACHE_SET,			/* 111 */
	CT_CACHE_STAT,			/* 112 */
	CT_TRACE_START,			/* 113 */
	CT_TRACE_STOP,			/* 114 */
	CT_TRACE_ENABLE,		/* 115 */
	CT_TRACE_DISABLE,		/* 116 */
	CT_FORCE_CORE_DUMP,		/* 117 */
	CT_SET_SERIAL_NUMBER,		/* 118 */
	CT_RESET_SERIAL_NUMBER,		/* 119 */
	CT_ENABLE_RAID5,		/* 120 */
	CT_CLEAR_VALID_DUMP_FLAG,	/* 121 */
	CT_GET_MEM_STATS,		/* 122 */
	CT_GET_CORE_SIZE,		/* 123 */
	CT_CREATE_CONTAINER_OLD,	/* 124 */
	CT_STOP_DUMPS,			/* 125 */
	CT_PANIC_ON_TAKE_A_BREAK,	/* 126 */
	CT_GET_CACHE_STATS,		/* 127 */
	CT_MOVE_PARTITION,		/* 128 */
	CT_FLUSH_CACHE,			/* 129 */
	CT_READ_NAME,			/* 130 */
	CT_WRITE_NAME,			/* 131 */
	CT_TOSS_CACHE,			/* 132 */
	CT_LOCK_DRAINIO,		/* 133 */
	CT_CONTAINER_OFFLINE,		/* 134 */
	CT_SET_CACHE_SIZE,		/* 135 */
	CT_CLEAN_SHUTDOWN_STATUS,	/* 136 */
	CT_CLEAR_DISKLOG_ON_DISK,	/* 137 */
	CT_CLEAR_ALL_DISKLOG,		/* 138 */
	CT_CACHE_FAVOR,			/* 139 */
	CT_READ_PASSTHRU_MBR,		/* 140 */
	CT_SCRUB_NOFIX,			/* 141 */
	CT_SCRUB2_NOFIX,		/* 142 */
	CT_FLUSH,			/* 143 */
	CT_REBUILD,	/* 144 rma, not really a command, partner to CT_SCRUB */
	CT_FLUSH_CONTAINER,		/* 145 */
	CT_RESTART,			/* 146 */
	CT_GET_CONFIG_STATUS,		/* 147 */
	CT_TRACE_FLAG,			/* 148 */
	CT_RESTART_MORPH,		/* 149 */
	CT_GET_TRACE_INFO,		/* 150 */
	CT_GET_TRACE_ITEM,		/* 151 */
	CT_COMMIT_CONFIG,		/* 152 */
	CT_CONTAINER_EXISTS,		/* 153 */
	CT_GET_SLICE_FROM_DEVT,		/* 154 */
	CT_OPEN_READ_WRITE,		/* 155 */
	CT_WRITE_MEMORY_BLOCK,		/* 156 */
	CT_GET_CACHE_PARAMS,		/* 157 */
	CT_CRAZY_CACHE,			/* 158 */
	CT_GET_PROFILE_STRUCT,		/* 159 */
	CT_SET_IO_TRACE_FLAG,		/* 160 */
	CT_GET_IO_TRACE_STRUCT,		/* 161 */
	CT_CID_TO_64BITS_UID,		/* 162 */
	CT_64BITS_UID_TO_CID,		/* 163 */
	CT_PAR_TO_64BITS_UID,		/* 164 */
	CT_CID_TO_32BITS_UID,		/* 165 */
	CT_32BITS_UID_TO_CID,		/* 166 */
	CT_PAR_TO_32BITS_UID,		/* 167 */
	CT_SET_FAILOVER_OPTION,		/* 168 */
	CT_GET_FAILOVER_OPTION,		/* 169 */
	CT_STRIPE_ADD2,			/* 170 */
	CT_CREATE_VOLUME_SET,		/* 171 */
	CT_CREATE_STRIPE_SET,		/* 172 */
	/* 173	command and partner to scrub and rebuild task types */
	CT_VERIFY_CONTAINER,
	CT_IS_CONTAINER_DEAD,		/* 174 */
	CT_GET_CONTAINER_OPTION,	/* 175 */
	CT_GET_SNAPSHOT_UNUSED_STRUCT,	/* 176 */
	CT_CLEAR_SNAPSHOT_UNUSED_STRUCT,	/* 177 */
	CT_GET_CONTAINER_INFO,		/* 178 */
	CT_CREATE_CONTAINER,		/* 179 */
	CT_CHANGE_CREATIONINFO,		/* 180 */
	CT_CHECK_CONFLICT_UID,		/* 181 */
	CT_CONTAINER_UID_CHECK,		/* 182 */

	/* 183 :RECmm: 20011220 added to support the Babylon */
	CT_IS_CONTAINER_MEATADATA_STANDARD,
	/* 184 :RECmm: 20011220 array imports */
	CT_IS_SLICE_METADATA_STANDARD,

	/* :BIOS_TEST: */
	/* 185 :RECmm: 20020116	added to support BIOS interface for */
	CT_GET_IMPORT_COUNT,
	/* 186 :RECmm: 20020116	metadata conversion */
	CT_CANCEL_ALL_IMPORTS,
	CT_GET_IMPORT_INFO,		/* 187 :RECmm: 20020116	" */
	CT_IMPORT_ARRAY,		/* 188 :RECmm: 20020116	" */
	CT_GET_LOG_SIZE,		/* 189  */

	/* Not BIOS TEST */
	CT_ALARM_GET_STATE,		/* 190 */
	CT_ALARM_SET_STATE,		/* 191 */
	CT_ALARM_ON_OFF,		/* 192 */

	CT_GET_EE_OEM_ID,		/* 193 */

	CT_GET_PPI_HEADERS,		/* 194  get header fields only */
	CT_GET_PPI_DATA,		/* 195  get all ppitable.data */
	/* 196  get only range of entries specified in c_params */
	CT_GET_PPI_ENTRIES,
	/* 197  remove ppitable bundle specified by uid in c_param0 */
	CT_DELETE_PPI_BUNDLE,

	/* 198  current partition structure (not legacy) */
	CT_GET_PARTITION_TABLE_2,
	CT_GET_PARTITION_INFO_2,
	CT_GET_DISK_PARTITIONS_2,

	CT_QUIESCE_ADAPTER,		/* 201  chill dude */
	CT_CLEAR_PPI_TABLE,		/* 202  clear ppi table */

	CT_SET_DEVICE_CACHE_POLICY,	/* 203 */
	CT_GET_DEVICE_CACHE_POLICY,	/* 204 */

	CT_SET_VERIFY_DELAY,		/* 205 */
	CT_GET_VERIFY_DELAY,		/* 206 */

	/* 207 delete all PPI bundles that have an entry for device at devt */
	CT_DELETE_PPI_BUNDLES_FOR_DEVT,

	CT_READ_SW_SECTOR,		/* 208 */
	CT_WRITE_SW_SECTOR,		/* 209 */

	/* 210 added to support firmware cache sync operations */
	CT_GET_CACHE_SYNC_INFO,
	CT_SET_CACHE_SYNC_MODE,		/* 211 */

	CT_LAST_COMMAND			/* last command */
} AAC_CTCommand;

/* General return status */
#define	CT_OK				218

struct aac_fsa_ctm {
	uint32_t	command;
	uint32_t	param[CT_FIB_PARAMS];
	int8_t		data[CT_PACKET_SIZE];
};

struct aac_Container {
	uint32_t		Command;
	struct aac_fsa_ctm	CTCommand;
};

struct aac_fsa_ctr {
	uint32_t	response;
	uint32_t	param[CT_FIB_PARAMS];
	int8_t		data[CT_PACKET_SIZE];
};

struct aac_Container_resp {
	uint32_t		Status;
	struct aac_fsa_ctr	CTResponse;
};

struct aac_cf_status_header {
	uint32_t	action;
	uint16_t	flags;
	int16_t		recordcount;
};

enum aac_cf_action_type {
	CFACT_CONTINUE = 0,		/* Continue without pause */
	CFACT_PAUSE,			/* Pause, then continue */
	CFACT_ABORT			/* Abort */
};

enum aac_mpe {
	AACMPE_OK = 0x0,
	AACMPE_GET_CONFIG_STATUS = 0x1,
	AACMPE_CONFIG_STATUS = 0x2,
	AACMPE_COMMIT_CONFIG = 0x3
};

/*
 * CT_PAUSE_IO is immediate minimal runtime command that is used
 * to restart the applications and cache.
 */
struct aac_pause_command {
	uint32_t	Command;
	uint32_t	Type;
	uint32_t	Timeout;
	uint32_t	Min;
	uint32_t	NoRescan;
	uint32_t	Parm3;
	uint32_t	Parm4;
	uint32_t	Count;
};

/*
 * The following two definitions come from Adaptec:
 *
 * Used to flush drive cache for container "cid"
 */
struct aac_synchronize_command {
	uint32_t	Command;	/* VM_ContainerConfig */
	uint32_t	Type;		/* CT_FLUSH_CACHE */
	uint32_t	Cid;
	uint32_t	Parm1;
	uint32_t	Parm2;
	uint32_t	Parm3;
	uint32_t	Parm4;
	uint32_t	Count;
};

struct aac_synchronize_reply {
	uint32_t	Dummy0;
	uint32_t	Dummy1;
	uint32_t	Status;
	uint32_t	Parm1;
	uint32_t	Parm2;
	uint32_t	Parm3;
	uint32_t	Parm4;
	uint32_t	Parm5;
	uint8_t		Data[16];
};

/*
 * Command status values
 */
typedef enum {
	ST_OK = 0,
	ST_PERM = 1,
	ST_NOENT = 2,
	ST_IO = 5,
	ST_NXIO = 6,
	ST_E2BIG = 7,
	ST_ACCES = 13,
	ST_EXIST = 17,
	ST_XDEV = 18,
	ST_NODEV = 19,
	ST_NOTDIR = 20,
	ST_ISDIR = 21,
	ST_INVAL = 22,
	ST_FBIG = 27,
	ST_NOSPC = 28,
	ST_ROFS = 30,
	ST_MLINK = 31,
	ST_WOULDBLOCK = 35,
	ST_NAMETOOLONG = 63,
	ST_NOTEMPTY = 66,
	ST_DQUOT = 69,
	ST_STALE = 70,
	ST_REMOTE = 71,
	ST_BADHANDLE = 10001,
	ST_NOT_SYNC = 10002,
	ST_BAD_COOKIE = 10003,
	ST_NOTSUPP = 10004,
	ST_TOOSMALL = 10005,
	ST_SERVERFAULT = 10006,
	ST_BADTYPE = 10007,
	ST_JUKEBOX = 10008,
	ST_NOTMOUNTED = 10009,
	ST_MAINTMODE = 10010,
	ST_STALEACL = 10011
} AAC_FSAStatus;

/*
 * Object-Server / Volume-Manager Dispatch Classes
 */
typedef enum {
	VM_Null = 0,
	VM_NameServe,
	VM_ContainerConfig,
	VM_Ioctl,
	VM_FilesystemIoctl,
	VM_CloseAll,
	VM_CtBlockRead,
	VM_CtBlockWrite,
	VM_SliceBlockRead,	/* raw access to configured "storage objects" */
	VM_SliceBlockWrite,
	VM_DriveBlockRead,	/* raw access to physical devices */
	VM_DriveBlockWrite,
	VM_EnclosureMgt,	/* enclosure management */
	VM_Unused,		/* used to be diskset management */
	VM_CtBlockVerify,
	VM_CtPerf,		/* performance test */
	VM_CtBlockRead64,
	VM_CtBlockWrite64,
	VM_CtBlockVerify64,
	VM_CtHostRead64,
	VM_CtHostWrite64,
	VM_NameServe64 = 22,
	MAX_VMCOMMAND_NUM	/* used for sizing stats array - leave last */
} AAC_VMCommand;

/*
 * Host-addressable object types
 */
typedef enum {
	FT_REG = 1,	/* regular file */
	FT_DIR,		/* directory */
	FT_BLK,		/* "block" device - reserved */
	FT_CHR,		/* "character special" device - reserved */
	FT_LNK,		/* symbolic link */
	FT_SOCK,	/* socket */
	FT_FIFO,	/* fifo */
	FT_FILESYS,	/* ADAPTEC's "FSA"(tm) filesystem */
	FT_DRIVE,	/* physical disk - addressable in scsi by b/t/l */
	FT_SLICE,	/* virtual disk - raw volume - slice */
	FT_PARTITION,	/* FSA partition - carved out of a slice - building */
			/* block for containers */
	FT_VOLUME,	/* Container - Volume Set */
	FT_STRIPE,	/* Container - Stripe Set */
	FT_MIRROR,	/* Container - Mirror Set */
	FT_RAID5,	/* Container - Raid 5 Set */
	FT_DATABASE	/* Storage object with "foreign" content manager */
} AAC_FType;

/* Host-side scatter/gather list for 32-bit, 64-bit, raw commands */
struct aac_sg_entry {
	uint32_t	SgAddress;
	uint32_t	SgByteCount;
};

struct aac_sg_entry64 {
	uint64_t	SgAddress;
	uint32_t	SgByteCount;
};

struct aac_sg_entryraw {
	uint32_t	Next;		/* reserved */
	uint32_t	Prev;		/* reserved */
	uint64_t	SgAddress;
	uint32_t	SgByteCount;
	uint32_t	Flags;		/* reserved */
};

struct aac_sg_table {
	uint32_t		SgCount;
	struct aac_sg_entry	SgEntry[1]; /* at least there is one */
					    /* SUN's CC cannot accept [0] */
};

struct aac_sg_table64 {
	uint32_t		SgCount;
	struct aac_sg_entry64	SgEntry64[1];
};

struct aac_sg_tableraw {
	uint32_t		SgCount;
	struct aac_sg_entryraw	SgEntryRaw[1];
};

/*
 * Block read/write operations.
 * These structures are packed into the 'data' area in the FIB.
 */
struct aac_blockread {
	uint32_t		Command;
	uint32_t		ContainerId;
	uint32_t		BlockNumber;
	uint32_t		ByteCount;
	struct aac_sg_table	SgMap;
};

struct aac_blockread64 {
	uint32_t		Command;
	uint16_t		ContainerId;
	uint16_t		SectorCount;
	uint32_t		BlockNumber;
	uint16_t		Pad;
	uint16_t		Flags;
	struct aac_sg_table64	SgMap64;
};

struct aac_blockread_response {
	uint32_t		Status;
	uint32_t		ByteCount;
};

struct aac_blockwrite {
	uint32_t		Command;
	uint32_t		ContainerId;
	uint32_t		BlockNumber;
	uint32_t		ByteCount;
	uint32_t		Stable;
	struct aac_sg_table	SgMap;
};

struct aac_blockwrite64 {
	uint32_t		Command;
	uint16_t		ContainerId;
	uint16_t		SectorCount;
	uint32_t		BlockNumber;
	uint16_t		Pad;
	uint16_t		Flags;
	struct aac_sg_table64	SgMap64;
};

struct aac_blockwrite_response {
	uint32_t		Status;
	uint32_t		ByteCount;
	uint32_t		Committed;
};

struct aac_raw_io {
	uint64_t		BlockNumber;
	uint32_t		ByteCount;
	uint16_t		ContainerId;
	uint16_t		Flags;		/* 0: W, 1: R */
	uint16_t		BpTotal;	/* reserved */
	uint16_t		BpComplete;	/* reserved */
	struct aac_sg_tableraw	SgMapRaw;
};

/*
 * Container shutdown command.
 */
struct aac_close_command {
	uint32_t		Command;
	uint32_t		ContainerId;
};

/* Write 'stability' options */
#define	CSTABLE			1
#define	CUNSTABLE		2

/* Number of FIBs for the controller to send us messages */
#define	AAC_ADAPTER_FIBS	8

/* Number of FIBs for the host I/O request */
#define	AAC_HOST_FIBS		256

/* Size of buffer for text messages from the controller */
#define	AAC_ADAPTER_PRINT_BUFSIZE		256

#define	AAC_INIT_STRUCT_REVISION		3
#define	AAC_INIT_STRUCT_REVISION_4		4
#define	AAC_INIT_STRUCT_MINIPORT_REVISION	1
#define	AAC_INIT_FLAGS_NEW_COMM_SUPPORTED	1
#define	AAC_PAGE_SIZE				4096
struct aac_adapter_init {
	uint32_t	InitStructRevision;
	uint32_t	MiniPortRevision;
	uint32_t	FilesystemRevision;
	uint32_t	CommHeaderAddress;
	uint32_t	FastIoCommAreaAddress;
	uint32_t	AdapterFibsPhysicalAddress;
	uint32_t	AdapterFibsVirtualAddress;
	uint32_t	AdapterFibsSize;
	uint32_t	AdapterFibAlign;
	uint32_t	PrintfBufferAddress;
	uint32_t	PrintfBufferSize;
	uint32_t	HostPhysMemPages;
	uint32_t	HostElapsedSeconds;
	/* ADAPTER_INIT_STRUCT_REVISION_4 begins here */
	uint32_t	InitFlags;
	uint32_t	MaxIoCommands;
	uint32_t	MaxIoSize;
	uint32_t	MaxFibSize;
};

/* ************AAC QUEUE DEFINES (BELOW)*********** */

#define	AAC_QUEUE_ALIGN		16
#define	AAC_QUEUE_COUNT		8
#define	AAC_PRODUCER_INDEX	0
#define	AAC_CONSUMER_INDEX	1

struct aac_queue_entry {
	uint32_t aq_fib_size;	/* FIB size in bytes */
	uint32_t aq_fib_addr;	/* receiver-space address of the FIB */
};

/*
 * Queue names
 *
 * Note that we base these at 0 in order to use them as array indices.
 * Adaptec used base 1 for some unknown reason, and sorted them in a
 * different order.
 */
#define	AAC_HOST_NORM_CMD_Q	0
#define	AAC_HOST_HIGH_CMD_Q	1
#define	AAC_ADAP_NORM_CMD_Q	2
#define	AAC_ADAP_HIGH_CMD_Q	3
#define	AAC_HOST_NORM_RESP_Q	4
#define	AAC_HOST_HIGH_RESP_Q	5
#define	AAC_ADAP_NORM_RESP_Q	6
#define	AAC_ADAP_HIGH_RESP_Q	7

/*
 * We establish 4 command queues and matching response queues. Queues must
 * be 16-byte aligned, and are sized as follows:
 */
/* command adapter->host, normal priority */
#define	AAC_HOST_NORM_CMD_ENTRIES	8
/* command adapter->host, high priority */
#define	AAC_HOST_HIGH_CMD_ENTRIES	4
/* command host->adapter, normal priority */
#define	AAC_ADAP_NORM_CMD_ENTRIES	512
/* command host->adapter, high priority */
#define	AAC_ADAP_HIGH_CMD_ENTRIES	4
/* response, adapter->host, normal priority */
#define	AAC_HOST_NORM_RESP_ENTRIES	512
/* response, adapter->host, high priority */
#define	AAC_HOST_HIGH_RESP_ENTRIES	4
/* response, host->adapter, normal priority */
#define	AAC_ADAP_NORM_RESP_ENTRIES	8
/* response, host->adapter, high priority */
#define	AAC_ADAP_HIGH_RESP_ENTRIES	4

#define	AAC_TOTALQ_LENGTH	(AAC_HOST_HIGH_CMD_ENTRIES + \
				AAC_HOST_NORM_CMD_ENTRIES + \
				AAC_ADAP_HIGH_CMD_ENTRIES + \
				AAC_ADAP_NORM_CMD_ENTRIES + \
				AAC_HOST_HIGH_RESP_ENTRIES + \
				AAC_HOST_NORM_RESP_ENTRIES + \
				AAC_ADAP_HIGH_RESP_ENTRIES + \
				AAC_ADAP_NORM_RESP_ENTRIES)

/*
 * Table of queue indices and queues used to communicate with the
 * controller. This structure must be aligned to AAC_QUEUE_ALIGN.
 */
struct aac_queue_table {
	/* queue consumer/producer indexes (layout mandated by adapter) */
	uint32_t qt_qindex[AAC_QUEUE_COUNT][2];

	/* queue entry structures (layout mandated by adapter) */
	struct aac_queue_entry qt_HostNormCmdQueue \
	    [AAC_HOST_NORM_CMD_ENTRIES];
	struct aac_queue_entry qt_HostHighCmdQueue \
	    [AAC_HOST_HIGH_CMD_ENTRIES];
	struct aac_queue_entry qt_AdapNormCmdQueue \
	    [AAC_ADAP_NORM_CMD_ENTRIES];
	struct aac_queue_entry qt_AdapHighCmdQueue \
	    [AAC_ADAP_HIGH_CMD_ENTRIES];
	struct aac_queue_entry qt_HostNormRespQueue \
	    [AAC_HOST_NORM_RESP_ENTRIES];
	struct aac_queue_entry qt_HostHighRespQueue \
	    [AAC_HOST_HIGH_RESP_ENTRIES];
	struct aac_queue_entry qt_AdapNormRespQueue \
	    [AAC_ADAP_NORM_RESP_ENTRIES];
	struct aac_queue_entry qt_AdapHighRespQueue \
	    [AAC_ADAP_HIGH_RESP_ENTRIES];
};
/* ************AAC QUEUE DEFINES (ABOVE)*********** */

/*
 * NVRAM/Write Cache subsystem battery component states
 */
typedef enum {
	NVBATTSTATUS_NONE = 0,	/* battery has no power or is not present */
	NVBATTSTATUS_LOW,	/* battery is low on power */
	NVBATTSTATUS_OK,	/* battery is okay - normal operation */
				/* possible only in this state */
	NVBATTSTATUS_RECONDITIONING	/* no battery present */
					/* - reconditioning in process */
} AAC_NVBATTSTATUS;

/*
 * Battery transition type
 */
typedef enum {
	NVBATT_TRANSITION_NONE = 0,	/* battery now has no power or is not */
					/* present */
	NVBATT_TRANSITION_LOW,	/* battery is now low on power */
	NVBATT_TRANSITION_OK	/* battery is now okay - normal */
				/* operation possible only in this state */
} AAC_NVBATT_TRANSITION;

/*
 * Data types relating to AIFs
 */

/*
 * Progress Reports
 */
typedef enum {
	AifJobStsSuccess = 1,
	AifJobStsFinished,
	AifJobStsAborted,
	AifJobStsFailed,
	AifJobStsLastReportMarker = 100,	/* All prior mean last report */
	AifJobStsSuspended,
	AifJobStsRunning
} AAC_AifJobStatus;

typedef enum {
	AifJobScsiMin = 1,	/* Minimum value for Scsi operation */
	AifJobScsiZero,		/* SCSI device clear operation */
	AifJobScsiVerify,	/* SCSI device Verify operation NO REPAIR */
	AifJobScsiExercise,	/* SCSI device Exercise operation */
	AifJobScsiVerifyRepair,	/* SCSI device Verify operation WITH repair */
	AifJobScsiWritePattern,	/* write pattern */
	AifJobScsiMax = 99,	/* Max Scsi value */
	AifJobCtrMin,		/* Min Ctr op value */
	AifJobCtrZero,		/* Container clear operation */
	AifJobCtrCopy,		/* Container copy operation */
	AifJobCtrCreateMirror,	/* Container Create Mirror operation */
	AifJobCtrMergeMirror,	/* Container Merge Mirror operation */
	AifJobCtrScrubMirror,	/* Container Scrub Mirror operation */
	AifJobCtrRebuildRaid5,	/* Container Rebuild Raid5 operation */
	AifJobCtrScrubRaid5,	/* Container Scrub Raid5 operation */
	AifJobCtrMorph,		/* Container morph operation */
	AifJobCtrPartCopy,	/* Container Partition copy operation */
	AifJobCtrRebuildMirror,	/* Container Rebuild Mirror operation */
	AifJobCtrCrazyCache,	/* crazy cache */
	AifJobCtrCopyback,	/* Container Copyback operation */
	AifJobCtrCompactRaid5D,	/* Container Compaction operation */
	AifJobCtrExpandRaid5D,	/* Container Expansion operation */
	AifJobCtrRebuildRaid6,	/* Container Rebuild Raid6 operation */
	AifJobCtrScrubRaid6,	/* Container Scrub Raid6 operation */
	AifJobCtrSSBackup,	/* Container snapshot backup task */
	AifJobCtrMax = 199,	/* Max Ctr type operation */
	AifJobFsMin,		/* Min Fs type operation */
	AifJobFsCreate,		/* File System Create operation */
	AifJobFsVerify,		/* File System Verify operation */
	AifJobFsExtend,		/* File System Extend operation */
	AifJobFsMax = 299,	/* Max Fs type operation */
	AifJobApiFormatNTFS,	/* Format a drive to NTFS */
	AifJobApiFormatFAT,	/* Format a drive to FAT */
	AifJobApiUpdateSnapshot, /* update the read/write half of a snapshot */
	AifJobApiFormatFAT32,	/* Format a drive to FAT32 */
	AifJobApiMax = 399,		/* Max API type operation */
	AifJobCtlContinuousCtrVerify,	/* Adapter operation */
	AifJobCtlMax = 499		/* Max Adapter type operation */
} AAC_AifJobType;

struct aac_AifContainers {
	uint32_t	src;		/* from/master */
	uint32_t	dst;		/* to/slave */
};

union aac_AifJobClient {
	struct aac_AifContainers container;	/* For Container and */
						/* filesystem progress ops */
	int32_t scsi_dh;			/* For SCSI progress ops */
};

struct aac_AifJobDesc {
	uint32_t	jobID;	/* DO NOT FILL IN! Will be filled in by AIF */
	AAC_AifJobType	type;	/* Operation that is being performed */
	union aac_AifJobClient	client;	/* Details */
};

struct aac_AifJobProgressReport {
	struct aac_AifJobDesc	jd;
	AAC_AifJobStatus	status;
	uint32_t		finalTick;
	uint32_t		currentTick;
	uint32_t		jobSpecificData1;
	uint32_t		jobSpecificData2;
};

/*
 * Event Notification
 */
typedef enum {
	/* General application notifies start here */
	AifEnGeneric = 1,	/* Generic notification */
	AifEnTaskComplete,	/* Task has completed */
	AifEnConfigChange,	/* Adapter config change occurred */
	AifEnContainerChange,	/* Adapter specific container cfg. change */
	AifEnDeviceFailure,	/* SCSI device failed */
	AifEnMirrorFailover,	/* Mirror failover started */
	AifEnContainerEvent,	/* Significant container event */
	AifEnFileSystemChange,	/* File system changed */
	AifEnConfigPause,	/* Container pause event */
	AifEnConfigResume,	/* Container resume event */
	AifEnFailoverChange,	/* Failover space assignment changed */
	AifEnRAID5RebuildDone,	/* RAID5 rebuild finished */
	AifEnEnclosureManagement,	/* Enclosure management event */
	AifEnBatteryEvent,	/* Significant NV battery event */
	AifEnAddContainer,	/* A new container was created. */
	AifEnDeleteContainer,	/* A container was deleted. */
	AifEnSMARTEvent,	/* SMART Event */
	AifEnBatteryNeedsRecond,	/* The battery needs reconditioning */
	AifEnClusterEvent,		/* Some cluster event */
	AifEnDiskSetEvent,		/* A disk set event occured. */
	AifDriverNotifyStart = 199,	/* Notifies for host driver go here */
	/* Host driver notifications start here */
	AifDenMorphComplete,		/* A morph operation completed */
	AifDenVolumeExtendComplete	/* Volume expand operation completed */
} AAC_AifEventNotifyType;

struct aac_AifEnsGeneric {
	char	text[132];		/* Generic text */
};

struct aac_AifEnsDeviceFailure {
	uint32_t	deviceHandle;	/* SCSI device handle */
};

struct aac_AifEnsMirrorFailover {
	uint32_t	container;	/* Container with failed element */
	uint32_t	failedSlice;	/* Old slice which failed */
	uint32_t	creatingSlice;	/* New slice used for auto-create */
};

struct aac_AifEnsContainerChange {
	uint32_t	container[2];	/* container that changed, -1 if */
					/* no container */
};

struct aac_AifEnsContainerEvent {
	uint32_t	container;	/* container number  */
	uint32_t	eventType;	/* event type */
};

struct aac_AifEnsEnclosureEvent {
	uint32_t	empID;		/* enclosure management proc number  */
	uint32_t	unitID;		/* unitId, fan id, power supply id, */
					/* slot id, tempsensor id. */
	uint32_t	eventType;	/* event type */
};

struct aac_AifEnsBatteryEvent {
	AAC_NVBATT_TRANSITION	transition_type;	/* eg from low to ok */
	AAC_NVBATTSTATUS	current_state;	/* current batt state */
	AAC_NVBATTSTATUS	prior_state;	/* prev batt state */
};

struct aac_AifEnsDiskSetEvent {
	uint32_t	eventType;
	uint64_t	DsNum;
	uint64_t	CreatorId;
};

typedef enum {
	CLUSTER_NULL_EVENT = 0,
	CLUSTER_PARTNER_NAME_EVENT,	/* change in partner hostname or */
					/* adaptername from NULL to non-NULL */
					/* (partner's agent may be up) */
	CLUSTER_PARTNER_NULL_NAME_EVENT	/* change in partner hostname or */
					/* adaptername from non-null to NULL */
					/* (partner has rebooted) */
} AAC_ClusterAifEvent;

struct aac_AifEnsClusterEvent {
	AAC_ClusterAifEvent	eventType;
};

struct aac_AifEventNotify {
	AAC_AifEventNotifyType	type;
	union {
		struct aac_AifEnsGeneric		EG;
		struct aac_AifEnsDeviceFailure		EDF;
		struct aac_AifEnsMirrorFailover		EMF;
		struct aac_AifEnsContainerChange	ECC;
		struct aac_AifEnsContainerEvent		ECE;
		struct aac_AifEnsEnclosureEvent		EEE;
		struct aac_AifEnsBatteryEvent		EBE;
		struct aac_AifEnsDiskSetEvent		EDS;
/*		struct aac_AifEnsSMARTEvent		ES; */
		struct aac_AifEnsClusterEvent		ECLE;
	} data;
};

/*
 * Adapter Initiated FIB command structures. Start with the adapter
 * initiated FIBs that really come from the adapter, and get responded
 * to by the host.
 */
#define	AAC_AIF_REPORT_MAX_SIZE 64

typedef enum {
	AifCmdEventNotify = 1,	/* Notify of event */
	AifCmdJobProgress,	/* Progress report */
	AifCmdAPIReport,	/* Report from other user of API */
	AifCmdDriverNotify,	/* Notify host driver of event */
	AifReqJobList = 100,	/* Gets back complete job list */
	AifReqJobsForCtr,	/* Gets back jobs for specific container */
	AifReqJobsForScsi,	/* Gets back jobs for specific SCSI device */
	AifReqJobReport,	/* Gets back a specific job report or list */
	AifReqTerminateJob,	/* Terminates job */
	AifReqSuspendJob,	/* Suspends a job */
	AifReqResumeJob,	/* Resumes a job */
	AifReqSendAPIReport,	/* API generic report requests */
	AifReqAPIJobStart,	/* Start a job from the API */
	AifReqAPIJobUpdate,	/* Update a job report from the API */
	AifReqAPIJobFinish	/* Finish a job from the API */
} AAC_AifCommand;

struct aac_aif_command {
	AAC_AifCommand	command; /* Tell host what type of notify this is */
	uint32_t	seqNumber;	/* To allow ordering of reports */
					/* (if necessary) */
	union {
		struct aac_AifEventNotify	EN;	/* Event notify */
		struct aac_AifJobProgressReport	PR[1];	/* Progress report */
		uint8_t	AR[AAC_AIF_REPORT_MAX_SIZE];
		uint8_t	data[AAC_FIB_DATASIZE - 8];
	} data;
};

#define	CT_PUP_MISSING_DRIVE	27

/*
 * Cluster Management Commands
 */
typedef enum {
	CL_NULL = 0,		/* 0x00 null */
	/* disk set commands */
	DS_INIT = 1,		/* 0x01 init disk set control block */
	DS_RESCAN,		/* 0x02 refresh drive, disk set, and slice */
				/* structs */
	DS_CREATE,		/* 0x03 create a disk set */
	DS_DELETE,		/* 0x04 delete a disk set */
	DS_ADD_DISK,		/* 0x05 add a disk to an existing disk set */
	DS_REMOVE_DISK,		/* 0x06 remove a disk from an existing disk */
				/* set */
	DS_MOVE_DISK,		/* 0x07 move a disk from one existing disk */
				/* set to another */
	DS_TAKE_OWNERSHIP,	/* 0x08 take ownership of an unowned disk set */
	DS_RELEASE_OWNERSHIP,	/* 0x09 release ownership of a disk set */
	DS_FORCE_OWNERSHIP,	/* 0x0A force ownership of an disk set */
	DS_GET_DISK_SET_PARAM,	/* 0x0B get info on a disk set */
	DS_GET_DRIVE_PARAM,	/* 0x0C get info on a drive */
	DS_GET_SLICE_PARAM,	/* 0x0D get info on a slice */
	DS_GET_DISK_SETS,	/* 0x0E get a list of disk sets */
	DS_GET_DRIVES,		/* 0x0F get a list of drives */
	DS_SET_DISK_SET_PARAM,	/* 0x10 set info of a disk set */
	DS_ONLINE,		/* 0x11 take disk set online */
	DS_OFFLINE,		/* 0x12 take disk set offline */
	DS_ONLINE_CONTAINERS,	/* 0x13 bring containers in diskset online */
	DS_FSAPRINT,		/* 0x14 do an FsaPrint */

	/* config commands */
	CL_CFG_SET_HOST_IDS = 0x100,	/* 0x100 set host ids (host name and */
					/* adapter name) */
	CL_CFG_SET_PARTNER_HOST_IDS,	/* 0x101 set partner host ids (host */
					/* name and adapter name) */
	CL_CFG_GET_CLUSTER_CONFIG,	/* 0x102 get cluster configuration */

	/* cluster comm commands */
	CC_CLI_CLEAR_MESSAGE_BUFFER = 0x200,	/* 0x200 CC - client - clear */
						/* contents of message buffer */
	CC_SRV_CLEAR_MESSAGE_BUFFER,	/* 0x201 CC - server - clear contents */
					/* of message buffer */
	CC_CLI_SHOW_MESSAGE_BUFFER,	/* 0x202 CC - client - show contents */
					/* of message buffer */
	CC_SRV_SHOW_MESSAGE_BUFFER,	/* 0x203 CC - server - show contents */
					/* of message buffer */
	CC_CLI_SEND_MESSAGE,	/* 0x204 CC - client - send (req) message to */
				/* server side */
	CC_SRV_SEND_MESSAGE,	/* 0x205 CC - server - send (reply) message */
				/* to client side */
	CC_CLI_GET_MESSAGE,	/* 0x206 CC - client - read thru read message */
				/* buffer */
	CC_SRV_GET_MESSAGE,	/* 0x207 CC - server - read thru read message */
				/* buffer */
	CC_SEND_TEST_MESSAGE,	/* 0x208 CC - send a special subclass message */
	CC_GET_BUSINFO,		/* 0x209 CC - get bus info */
	CC_GET_PORTINFO,	/* 0x20A CC - get bus,port info */
	CC_GET_NAMEINFO,	/* 0x20B CC - get misc info */
	CC_GET_CONFIGINFO,	/* 0x20C CC - get misc info */
	CQ_QUORUM_OP = 0x300,	/* 0x300 CQ - quorum messages */

	/* last command */
	CL_LAST_COMMAND		/* used for bounds checking */
} AAC_CLCommand;

/*
 * Disk IOCTL Functions
 */
#define	Reserved_IOCTL			0x0000
#define	GetDeviceHandle			0x0001
#define	BusTargetLun_to_DeviceHandle	0x0002
#define	DeviceHandle_to_BusTargetLun	0x0003
#define	RescanBus			0x0004
#define	GetDeviceProbeInfo		0x0005
#define	GetDeviceCapacity		0x0006
#define	GetContainerProbeInfo		0x0007	/* Container, not diskclass */
						/* ioctl */
#define	GetRequestedMemorySize		0x0008
#define	GetBusInfo			0x0009
#define	GetVendorSpecific		0x000a

#define	EnhancedGetDeviceProbeInfo	0x000b
#define	EnhancedGetBusInfo		0x000c

#define	SetupExtendedCounters		0x000d
#define	GetPerformanceCounters		0x000f
#define	ResetPerformanceCounters	0x0010
#define	ReadModePage			0x0011
#define	WriteModePage			0x0012
#define	ReadDriveParameter		0x0013
#define	WriteDriveParameter		0x0014
#define	ResetAdapter			0x0015
#define	ResetBus			0x0016
#define	ResetBusDevice			0x0017
#define	ExecuteSrb			0x0018

#define	Create_IO_Task			0x0030
#define	Delete_IO_Task			0x0031
#define	Get_IO_Task_Info		0x0032
#define	Check_Task_Progress		0x0033

#define	InjectError			0x0040
#define	GetDeviceDefectCounts		0x0041
#define	GetDeviceDefectInfo		0x0042
#define	GetDeviceStatus			0x0043
#define	ClearDeviceStatus		0x0044
#define	DiskSpinControl			0x0045
#define	DiskSmartControl		0x0046
#define	WriteSame			0x0047
#define	ReadWriteLong			0x0048
#define	FormatUnit			0x0049

#define	TargetDeviceControl		0x0050
#define	TargetChannelControl		0x0051

#define	FlashNewCode			0x0052
#define	DiskCheck			0x0053
#define	RequestSense			0x0054
#define	DiskPERControl			0x0055
#define	Read10				0x0056
#define	Write10				0x0057

/*
 * SRB SCSI Status
 * Status codes for SCSI passthrough commands,
 * set in aac_srb->scsi_status
 */
#define	SRB_STATUS_PENDING			0x00
#define	SRB_STATUS_SUCCESS			0x01
#define	SRB_STATUS_ABORTED			0x02
#define	SRB_STATUS_ABORT_FAILED			0x03
#define	SRB_STATUS_ERROR			0x04
#define	SRB_STATUS_BUSY				0x05
#define	SRB_STATUS_INVALID_REQUEST		0x06
#define	SRB_STATUS_INVALID_PATH_ID		0x07
#define	SRB_STATUS_NO_DEVICE			0x08
#define	SRB_STATUS_TIMEOUT			0x09
#define	SRB_STATUS_SELECTION_TIMEOUT		0x0A
#define	SRB_STATUS_COMMAND_TIMEOUT		0x0B
#define	SRB_STATUS_MESSAGE_REJECTED		0x0D
#define	SRB_STATUS_BUS_RESET			0x0E
#define	SRB_STATUS_PARITY_ERROR			0x0F
#define	SRB_STATUS_REQUEST_SENSE_FAILED		0x10
#define	SRB_STATUS_NO_HBA			0x11
#define	SRB_STATUS_DATA_OVERRUN			0x12
#define	SRB_STATUS_UNEXPECTED_BUS_FREE		0x13
#define	SRB_STATUS_PHASE_SEQUENCE_FAILURE	0x14
#define	SRB_STATUS_BAD_SRB_BLOCK_LENGTH		0x15
#define	SRB_STATUS_REQUEST_FLUSHED		0x16
#define	SRB_STATUS_DELAYED_RETRY		0x17
#define	SRB_STATUS_INVALID_LUN			0x20
#define	SRB_STATUS_INVALID_TARGET_ID		0x21
#define	SRB_STATUS_BAD_FUNCTION			0x22
#define	SRB_STATUS_ERROR_RECOVERY		0x23
#define	SRB_STATUS_NOT_STARTED			0x24
#define	SRB_STATUS_NOT_IN_USE			0x30
#define	SRB_STATUS_FORCE_ABORT			0x31
#define	SRB_STATUS_DOMAIN_VALIDATION_FAIL	0x32

/*
 * The following definitions come from Adaptec:
 *
 * SRB is required for the new management tools
 * and non-DASD support.
 */
#define	SRB_DataIn	0x0040
#define	SRB_DataOut	0x0080
struct aac_srb
{
	uint32_t function;
	uint32_t channel;
	uint32_t id;
	uint32_t lun;
	uint32_t timeout;
	uint32_t flags;
	uint32_t count;	/* Data xfer size */
	uint32_t retry_limit;
	uint32_t cdb_size;
	uint8_t cdb[16];
	struct aac_sg_table sg;
};

#define	AAC_SENSE_BUFFERSIZE	 30
struct aac_srb_reply
{
	uint32_t status;
	uint32_t srb_status;
	uint32_t scsi_status;
	uint32_t data_xfer_length;
	uint32_t sense_data_size;
	uint8_t sense_data[AAC_SENSE_BUFFERSIZE];    /* Can this be */
						    /* SCSI_SENSE_BUFFERSIZE */
};

#pragma	pack()

/* AAC Communication Space */
struct aac_comm_space {
	struct aac_fib adapter_fibs[AAC_ADAPTER_FIBS];
	struct aac_adapter_init init_data;
	struct aac_queue_table qtable;
	char qt_align_pad[AAC_QUEUE_ALIGN];
	char adapter_print_buf[AAC_ADAPTER_PRINT_BUFSIZE];
	struct aac_fib sync_fib;
};

#ifdef	__cplusplus
}
#endif

#endif /* __AAC_REGS_H__ */
