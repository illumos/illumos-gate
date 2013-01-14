/*
 * fusion.h
 *
 * Solaris MegaRAID device driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
 *
 * Version:
 * Author:
 *		Swaminathan K S
 *		Arun Chandrashekhar
 *		Manju R
 *		Rasheed
 *		Shakeel Bukhari
 */


#ifndef	_FUSION_H_
#define	_FUSION_H_

#define	U64	uint64_t
#define	U32	uint32_t
#define	U16	uint16_t
#define	U8	uint8_t
#define	S8	char
#define	S16	short
#define	S32	int

/* MPI2 defines */
#define	MPI2_REPLY_POST_HOST_INDEX_OFFSET	(0x6C)
#define	MPI2_FUNCTION_IOC_INIT			(0x02) /* IOC Init */
#define	MPI2_WHOINIT_HOST_DRIVER		(0x04)
#define	MPI2_VERSION_MAJOR			(0x02)
#define	MPI2_VERSION_MINOR			(0x00)
#define	MPI2_VERSION_MAJOR_MASK			(0xFF00)
#define	MPI2_VERSION_MAJOR_SHIFT		(8)
#define	MPI2_VERSION_MINOR_MASK			(0x00FF)
#define	MPI2_VERSION_MINOR_SHIFT		(0)
#define	MPI2_VERSION	((MPI2_VERSION_MAJOR << MPI2_VERSION_MAJOR_SHIFT) | \
			MPI2_VERSION_MINOR)
#define	MPI2_HEADER_VERSION_UNIT		(0x10)
#define	MPI2_HEADER_VERSION_DEV			(0x00)
#define	MPI2_HEADER_VERSION_UNIT_MASK		(0xFF00)
#define	MPI2_HEADER_VERSION_UNIT_SHIFT		(8)
#define	MPI2_HEADER_VERSION_DEV_MASK		(0x00FF)
#define	MPI2_HEADER_VERSION_DEV_SHIFT		(0)
#define	MPI2_HEADER_VERSION			((MPI2_HEADER_VERSION_UNIT \
						<< 8) | \
						MPI2_HEADER_VERSION_DEV)
#define	MPI2_IEEE_SGE_FLAGS_IOCPLBNTA_ADDR	(0x03)
#define	MPI2_SCSIIO_EEDPFLAGS_INC_PRI_REFTAG	(0x8000)
#define	MPI2_SCSIIO_EEDPFLAGS_CHECK_REFTAG	(0x0400)
#define	MPI2_SCSIIO_EEDPFLAGS_CHECK_REMOVE_OP	(0x0003)
#define	MPI2_SCSIIO_EEDPFLAGS_CHECK_APPTAG	(0x0200)
#define	MPI2_SCSIIO_EEDPFLAGS_CHECK_GUARD	(0x0100)
#define	MPI2_SCSIIO_EEDPFLAGS_INSERT_OP		(0x0004)
#define	MPI2_FUNCTION_SCSI_IO_REQUEST		(0x00) /* SCSI IO */
#define	MPI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY	(0x06)
#define	MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO		(0x00)
#define	MPI2_SGE_FLAGS_64_BIT_ADDRESSING	(0x02)
#define	MPI2_SCSIIO_CONTROL_WRITE		(0x01000000)
#define	MPI2_SCSIIO_CONTROL_READ		(0x02000000)
#define	MPI2_REQ_DESCRIPT_FLAGS_TYPE_MASK	(0x0E)
#define	MPI2_RPY_DESCRIPT_FLAGS_UNUSED		(0x0F)
#define	MPI2_RPY_DESCRIPT_FLAGS_SCSI_IO_SUCCESS	(0x00)
#define	MPI2_RPY_DESCRIPT_FLAGS_TYPE_MASK	(0x0F)
#define	MPI2_WRSEQ_FLUSH_KEY_VALUE		(0x0)
#define	MPI2_WRITE_SEQUENCE_OFFSET		(0x00000004)
#define	MPI2_WRSEQ_1ST_KEY_VALUE		(0xF)
#define	MPI2_WRSEQ_2ND_KEY_VALUE		(0x4)
#define	MPI2_WRSEQ_3RD_KEY_VALUE		(0xB)
#define	MPI2_WRSEQ_4TH_KEY_VALUE		(0x2)
#define	MPI2_WRSEQ_5TH_KEY_VALUE		(0x7)
#define	MPI2_WRSEQ_6TH_KEY_VALUE		(0xD)

/* Invader defines */
#define	MPI2_TYPE_CUDA					0x2
#define	MPI25_SAS_DEVICE0_FLAGS_ENABLED_FAST_PATH	0x4000
#define	MR_RL_FLAGS_GRANT_DESTINATION_CPU0			0x00
#define	MR_RL_FLAGS_GRANT_DESTINATION_CPU1			0x10
#define	MR_RL_FLAGS_GRANT_DESTINATION_CUDA			0x80
#define	MR_RL_FLAGS_SEQ_NUM_ENABLE					0x8
#define	MPI2_NSEG_FLAGS_SHIFT						4


#define	MR_PD_INVALID				0xFFFF
#define	MAX_SPAN_DEPTH				8
#define	MAX_RAIDMAP_SPAN_DEPTH			(MAX_SPAN_DEPTH)
#define	MAX_ROW_SIZE				32
#define	MAX_RAIDMAP_ROW_SIZE			(MAX_ROW_SIZE)
#define	MAX_LOGICAL_DRIVES			64
#define	MAX_RAIDMAP_LOGICAL_DRIVES		(MAX_LOGICAL_DRIVES)
#define	MAX_RAIDMAP_VIEWS			(MAX_LOGICAL_DRIVES)
#define	MAX_ARRAYS				128
#define	MAX_RAIDMAP_ARRAYS			(MAX_ARRAYS)
#define	MAX_PHYSICAL_DEVICES			256
#define	MAX_RAIDMAP_PHYSICAL_DEVICES		(MAX_PHYSICAL_DEVICES)

/* get the mapping information of LD */
#define	MR_DCMD_LD_MAP_GET_INFO			0x0300e101

#ifndef	MPI2_POINTER
#define	MPI2_POINTER	*
#endif

#pragma pack(1)

typedef struct _MPI25_IEEE_SGE_CHAIN64
{
	U64	Address;
	U32	Length;
	U16	Reserved1;
	U8	NextChainOffset;
	U8	Flags;
} MPI25_IEEE_SGE_CHAIN64, MPI2_POINTER PTR_MPI25_IEEE_SGE_CHAIN64,
    Mpi25IeeeSgeChain64_t, MPI2_POINTER pMpi25IeeeSgeChain64_t;

typedef struct _MPI2_SGE_SIMPLE_UNION
{
	U32	FlagsLength;
	union
	{
		U32	Address32;
		U64	Address64;
	} u1;
} MPI2_SGE_SIMPLE_UNION, MPI2_POINTER PTR_MPI2_SGE_SIMPLE_UNION,
    Mpi2SGESimpleUnion_t, MPI2_POINTER pMpi2SGESimpleUnion_t;

typedef struct
{
	U8	CDB[20];			/* 0x00 */
	U32	PrimaryReferenceTag;		/* 0x14 */
	U16	PrimaryApplicationTag;		/* 0x18 */
	U16	PrimaryApplicationTagMask;	/* 0x1A */
	U32	TransferLength;			/* 0x1C */
} MPI2_SCSI_IO_CDB_EEDP32, MPI2_POINTER PTR_MPI2_SCSI_IO_CDB_EEDP32,
    Mpi2ScsiIoCdbEedp32_t, MPI2_POINTER pMpi2ScsiIoCdbEedp32_t;

typedef struct _MPI2_SGE_CHAIN_UNION
{
	U16	Length;
	U8	NextChainOffset;
	U8	Flags;
	union
	{
		U32	Address32;
		U64	Address64;
	} u1;
} MPI2_SGE_CHAIN_UNION, MPI2_POINTER PTR_MPI2_SGE_CHAIN_UNION,
    Mpi2SGEChainUnion_t, MPI2_POINTER pMpi2SGEChainUnion_t;

typedef struct _MPI2_IEEE_SGE_SIMPLE32
{
	U32	Address;
	U32	FlagsLength;
} MPI2_IEEE_SGE_SIMPLE32, MPI2_POINTER PTR_MPI2_IEEE_SGE_SIMPLE32,
    Mpi2IeeeSgeSimple32_t, MPI2_POINTER pMpi2IeeeSgeSimple32_t;

typedef struct _MPI2_IEEE_SGE_SIMPLE64
{
	U64	Address;
	U32	Length;
	U16	Reserved1;
	U8	Reserved2;
	U8	Flags;
} MPI2_IEEE_SGE_SIMPLE64, MPI2_POINTER PTR_MPI2_IEEE_SGE_SIMPLE64,
    Mpi2IeeeSgeSimple64_t, MPI2_POINTER pMpi2IeeeSgeSimple64_t;

typedef union _MPI2_IEEE_SGE_SIMPLE_UNION
{
	MPI2_IEEE_SGE_SIMPLE32	Simple32;
	MPI2_IEEE_SGE_SIMPLE64	Simple64;
} MPI2_IEEE_SGE_SIMPLE_UNION, MPI2_POINTER PTR_MPI2_IEEE_SGE_SIMPLE_UNION,
    Mpi2IeeeSgeSimpleUnion_t, MPI2_POINTER pMpi2IeeeSgeSimpleUnion_t;

typedef	MPI2_IEEE_SGE_SIMPLE32	MPI2_IEEE_SGE_CHAIN32;
typedef	MPI2_IEEE_SGE_SIMPLE64	MPI2_IEEE_SGE_CHAIN64;

typedef union _MPI2_IEEE_SGE_CHAIN_UNION
{
	MPI2_IEEE_SGE_CHAIN32	Chain32;
	MPI2_IEEE_SGE_CHAIN64	Chain64;
} MPI2_IEEE_SGE_CHAIN_UNION, MPI2_POINTER PTR_MPI2_IEEE_SGE_CHAIN_UNION,
    Mpi2IeeeSgeChainUnion_t, MPI2_POINTER pMpi2IeeeSgeChainUnion_t;

typedef union _MPI2_SGE_IO_UNION
{
	MPI2_SGE_SIMPLE_UNION		MpiSimple;
	MPI2_SGE_CHAIN_UNION		MpiChain;
	MPI2_IEEE_SGE_SIMPLE_UNION	IeeeSimple;
	MPI2_IEEE_SGE_CHAIN_UNION	IeeeChain;
} MPI2_SGE_IO_UNION, MPI2_POINTER PTR_MPI2_SGE_IO_UNION,
    Mpi2SGEIOUnion_t, MPI2_POINTER pMpi2SGEIOUnion_t;

typedef union
{
	U8				CDB32[32];
	MPI2_SCSI_IO_CDB_EEDP32		EEDP32;
	MPI2_SGE_SIMPLE_UNION		SGE;
} MPI2_SCSI_IO_CDB_UNION, MPI2_POINTER PTR_MPI2_SCSI_IO_CDB_UNION,
    Mpi2ScsiIoCdb_t, MPI2_POINTER pMpi2ScsiIoCdb_t;

/* Default Request Descriptor */
typedef struct _MPI2_DEFAULT_REQUEST_DESCRIPTOR
{
	U8		RequestFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U16		LMID;				/* 0x04 */
	U16		DescriptorTypeDependent;	/* 0x06 */
} MPI2_DEFAULT_REQUEST_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_DEFAULT_REQUEST_DESCRIPTOR,
    Mpi2DefaultRequestDescriptor_t,
    MPI2_POINTER pMpi2DefaultRequestDescriptor_t;

/* High Priority Request Descriptor */
typedef struct _MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR
{
	U8		RequestFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U16		LMID;				/* 0x04 */
	U16		Reserved1;			/* 0x06 */
} MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR,
    Mpi2HighPriorityRequestDescriptor_t,
    MPI2_POINTER pMpi2HighPriorityRequestDescriptor_t;

/* SCSI IO Request Descriptor */
typedef struct _MPI2_SCSI_IO_REQUEST_DESCRIPTOR
{
	U8		RequestFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U16		LMID;				/* 0x04 */
	U16		DevHandle;			/* 0x06 */
} MPI2_SCSI_IO_REQUEST_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_SCSI_IO_REQUEST_DESCRIPTOR,
    Mpi2SCSIIORequestDescriptor_t,
    MPI2_POINTER pMpi2SCSIIORequestDescriptor_t;

/* SCSI Target Request Descriptor */
typedef struct _MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR
{
	U8		RequestFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U16		LMID;				/* 0x04 */
	U16		IoIndex;			/* 0x06 */
} MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR,
    Mpi2SCSITargetRequestDescriptor_t,
    MPI2_POINTER pMpi2SCSITargetRequestDescriptor_t;

/* RAID Accelerator Request Descriptor */
typedef struct _MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR
{
	U8		RequestFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U16		LMID;				/* 0x04 */
	U16		Reserved;			/* 0x06 */
} MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR,
    Mpi2RAIDAcceleratorRequestDescriptor_t,
    MPI2_POINTER pMpi2RAIDAcceleratorRequestDescriptor_t;

/* Default Reply Descriptor */
typedef struct _MPI2_DEFAULT_REPLY_DESCRIPTOR
{
	U8		ReplyFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		DescriptorTypeDependent1;	/* 0x02 */
	U32		DescriptorTypeDependent2;	/* 0x04 */
} MPI2_DEFAULT_REPLY_DESCRIPTOR, MPI2_POINTER PTR_MPI2_DEFAULT_REPLY_DESCRIPTOR,
    Mpi2DefaultReplyDescriptor_t, MPI2_POINTER pMpi2DefaultReplyDescriptor_t;

/* Address Reply Descriptor */
typedef struct _MPI2_ADDRESS_REPLY_DESCRIPTOR
{
	U8		ReplyFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U32		ReplyFrameAddress;		/* 0x04 */
} MPI2_ADDRESS_REPLY_DESCRIPTOR, MPI2_POINTER PTR_MPI2_ADDRESS_REPLY_DESCRIPTOR,
    Mpi2AddressReplyDescriptor_t, MPI2_POINTER pMpi2AddressReplyDescriptor_t;

/* SCSI IO Success Reply Descriptor */
typedef struct _MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR
{
	U8		ReplyFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U16		TaskTag;			/* 0x04 */
	U16		Reserved1;			/* 0x06 */
} MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR,
    Mpi2SCSIIOSuccessReplyDescriptor_t,
    MPI2_POINTER pMpi2SCSIIOSuccessReplyDescriptor_t;

/* TargetAssist Success Reply Descriptor */
typedef struct _MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR
{
	U8		ReplyFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U8		SequenceNumber;			/* 0x04 */
	U8		Reserved1;			/* 0x05 */
	U16		IoIndex;			/* 0x06 */
} MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR,
    Mpi2TargetAssistSuccessReplyDescriptor_t,
    MPI2_POINTER pMpi2TargetAssistSuccessReplyDescriptor_t;

/* Target Command Buffer Reply Descriptor */
typedef struct _MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR
{
	U8		ReplyFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U8		VP_ID;				/* 0x02 */
	U8		Flags;				/* 0x03 */
	U16		InitiatorDevHandle;		/* 0x04 */
	U16		IoIndex;			/* 0x06 */
} MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR,
    Mpi2TargetCommandBufferReplyDescriptor_t,
    MPI2_POINTER pMpi2TargetCommandBufferReplyDescriptor_t;

/* RAID Accelerator Success Reply Descriptor */
typedef struct _MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR
{
	U8		ReplyFlags;			/* 0x00 */
	U8		MSIxIndex;			/* 0x01 */
	U16		SMID;				/* 0x02 */
	U32		Reserved;			/* 0x04 */
} MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR,
    MPI2_POINTER PTR_MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR,
    Mpi2RAIDAcceleratorSuccessReplyDescriptor_t,
    MPI2_POINTER pMpi2RAIDAcceleratorSuccessReplyDescriptor_t;

/* union of Reply Descriptors */
typedef union _MPI2_REPLY_DESCRIPTORS_UNION
{
	MPI2_DEFAULT_REPLY_DESCRIPTOR			Default;
	MPI2_ADDRESS_REPLY_DESCRIPTOR			AddressReply;
	MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR		SCSIIOSuccess;
	MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR	TargetAssistSuccess;
	MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR	TargetCommandBuffer;
	MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR	RAIDAcceleratorSuccess;
	U64						Words;
} MPI2_REPLY_DESCRIPTORS_UNION, MPI2_POINTER PTR_MPI2_REPLY_DESCRIPTORS_UNION,
    Mpi2ReplyDescriptorsUnion_t, MPI2_POINTER pMpi2ReplyDescriptorsUnion_t;

/* IOCInit Request message */
typedef struct _MPI2_IOC_INIT_REQUEST
{
	U8		WhoInit;				/* 0x00 */
	U8		Reserved1;				/* 0x01 */
	U8		ChainOffset;				/* 0x02 */
	U8		Function;				/* 0x03 */
	U16		Reserved2;				/* 0x04 */
	U8		Reserved3;				/* 0x06 */
	U8		MsgFlags;				/* 0x07 */
	U8		VP_ID;					/* 0x08 */
	U8		VF_ID;					/* 0x09 */
	U16		Reserved4;				/* 0x0A */
	U16		MsgVersion;				/* 0x0C */
	U16		HeaderVersion;				/* 0x0E */
	U32		Reserved5;				/* 0x10 */
	U16		Reserved6;				/* 0x14 */
	U8		Reserved7;				/* 0x16 */
	U8		HostMSIxVectors;			/* 0x17 */
	U16		Reserved8;				/* 0x18 */
	U16		SystemRequestFrameSize;			/* 0x1A */
	U16		ReplyDescriptorPostQueueDepth;		/* 0x1C */
	U16		ReplyFreeQueueDepth;			/* 0x1E */
	U32		SenseBufferAddressHigh;			/* 0x20 */
	U32		SystemReplyAddressHigh;			/* 0x24 */
	U64		SystemRequestFrameBaseAddress;		/* 0x28 */
	U64		ReplyDescriptorPostQueueAddress;	/* 0x30 */
	U64		ReplyFreeQueueAddress;			/* 0x38 */
	U64		TimeStamp;				/* 0x40 */
} MPI2_IOC_INIT_REQUEST, MPI2_POINTER PTR_MPI2_IOC_INIT_REQUEST,
    Mpi2IOCInitRequest_t, MPI2_POINTER pMpi2IOCInitRequest_t;


typedef struct _MR_DEV_HANDLE_INFO {

	/* Send bitmap of LDs that are idle with respect to FP */
	U16		curDevHdl;

	/* bitmap of valid device handles. */
	U8		validHandles;
	U8		reserved;
	/* 0x04 dev handles for all the paths. */
	U16		devHandle[2];
} MR_DEV_HANDLE_INFO;				/* 0x08, Total Size */

typedef struct _MR_ARRAY_INFO {
	U16	pd[MAX_RAIDMAP_ROW_SIZE];
} MR_ARRAY_INFO;			/* 0x40, Total Size */

typedef struct _MR_QUAD_ELEMENT {
	U64		logStart;			/* 0x00 */
	U64		logEnd;				/* 0x08 */
	U64		offsetInSpan;			/* 0x10 */
	U32		diff;				/* 0x18 */
	U32		reserved1;			/* 0x1C */
} MR_QUAD_ELEMENT;					/* 0x20, Total size */

typedef struct _MR_SPAN_INFO {
	U32		noElements;			/* 0x00 */
	U32		reserved1;			/* 0x04 */
	MR_QUAD_ELEMENT	quads[MAX_RAIDMAP_SPAN_DEPTH];	/* 0x08 */
} MR_SPAN_INFO;						/* 0x108, Total size */

typedef struct _MR_LD_SPAN_ {				/* SPAN structure */
	/* 0x00, starting block number in array */
	U64		startBlk;

	/* 0x08, number of blocks */
	U64		numBlks;

	/* 0x10, array reference */
	U16		arrayRef;

	U8		reserved[6];	/* 0x12 */
} MR_LD_SPAN;				/* 0x18, Total Size */

typedef struct _MR_SPAN_BLOCK_INFO {
	/* number of rows/span */
	U64		num_rows;

	MR_LD_SPAN	span;				/* 0x08 */
	MR_SPAN_INFO	block_span_info;		/* 0x20 */
} MR_SPAN_BLOCK_INFO;					/* 0x128, Total Size */

typedef struct _MR_LD_RAID {
	struct {
		U32	fpCapable	:1;
		U32	reserved5	:3;
		U32	ldPiMode	:4;
		U32	pdPiMode	:4;

		/* FDE or controller encryption (MR_LD_ENCRYPTION_TYPE) */
		U32	encryptionType	:8;

		U32	fpWriteCapable	:1;
		U32	fpReadCapable	:1;
		U32	fpWriteAcrossStripe:1;
		U32	fpReadAcrossStripe:1;
		U32	reserved4	:8;
	} capability;			/* 0x00 */
	U32	reserved6;
	U64	size;			/* 0x08, LD size in blocks */
	U8	spanDepth;		/* 0x10, Total Number of Spans */
	U8	level;			/* 0x11, RAID level */
	/* 0x12, shift-count to get stripe size (0=512, 1=1K, 7=64K, etc.) */
	U8	stripeShift;
	U8	rowSize;		/* 0x13, number of disks in a row */
	/* 0x14, number of data disks in a row */
	U8	rowDataSize;
	U8	writeMode;		/* 0x15, WRITE_THROUGH or WRITE_BACK */

	/* 0x16, To differentiate between RAID1 and RAID1E */
	U8	PRL;

	U8	SRL;			/* 0x17 */
	U16	targetId;		/* 0x18, ld Target Id. */

	/* 0x1a, state of ld, state corresponds to MR_LD_STATE */
	U8	ldState;

	/* 0x1b, Pre calculate region type requests based on MFC etc.. */
	U8	regTypeReqOnWrite;

	U8	modFactor;		/* 0x1c, same as rowSize */
	/*
	 * 0x1d, region lock type used for read, valid only if
	 * regTypeOnReadIsValid=1
	 */
	U8	regTypeReqOnRead;
	U16	seqNum;			/* 0x1e, LD sequence number */

	struct {
		/* This LD requires sync command before completing */
		U32	ldSyncRequired:1;
		U32	reserved:31;
	} flags;			/* 0x20 */

	U8	reserved3[0x5C];	/* 0x24 */
} MR_LD_RAID;				/* 0x80, Total Size */

typedef struct _MR_LD_SPAN_MAP {
	MR_LD_RAID		ldRaid;	/* 0x00 */

	/* 0x80, needed for GET_ARM() - R0/1/5 only. */
	U8			dataArmMap[MAX_RAIDMAP_ROW_SIZE];

	MR_SPAN_BLOCK_INFO	spanBlock[MAX_RAIDMAP_SPAN_DEPTH]; /* 0xA0 */
} MR_LD_SPAN_MAP;	/* 0x9E0 */

typedef struct _MR_FW_RAID_MAP {
	/* total size of this structure, including this field */
	U32			totalSize;
	union {
		/* Simple method of version checking variables */
		struct {
			U32	maxLd;
			U32	maxSpanDepth;
			U32	maxRowSize;
			U32	maxPdCount;
			U32	maxArrays;
		} validationInfo;
		U32	version[5];
		U32	reserved1[5];
	} u1;

	U32			ldCount;		/* count of lds */
	U32			Reserved1;

	/*
	 * 0x20 This doesn't correspond to
	 * FW Ld Tgt Id to LD, but will purge. For example: if tgt Id is 4
	 * and FW LD is 2, and there is only one LD, FW will populate the
	 * array like this. [0xFF, 0xFF, 0xFF, 0xFF, 0x0.....]. This is to
	 * help reduce the entire structure size if there are few LDs or
	 * driver is looking info for 1 LD only.
	 */
	U8			ldTgtIdToLd[MAX_RAIDMAP_LOGICAL_DRIVES+ \
				MAX_RAIDMAP_VIEWS]; /* 0x20 */
	/* timeout value used by driver in FP IOs */
	U8			fpPdIoTimeoutSec;
	U8			reserved2[7];
	MR_ARRAY_INFO		arMapInfo[MAX_RAIDMAP_ARRAYS];	/* 0x00a8 */
	MR_DEV_HANDLE_INFO	devHndlInfo[MAX_RAIDMAP_PHYSICAL_DEVICES];

	/* 0x28a8-[0 -MAX_RAIDMAP_LOGICAL_DRIVES+MAX_RAIDMAP_VIEWS+1]; */
	MR_LD_SPAN_MAP		ldSpanMap[1];
}MR_FW_RAID_MAP;					/* 0x3288, Total Size */

typedef struct _LD_TARGET_SYNC {
	U8	ldTargetId;
	U8	reserved;
	U16	seqNum;
} LD_TARGET_SYNC;

#pragma pack()

struct IO_REQUEST_INFO {
	U64	ldStartBlock;
	U32	numBlocks;
	U16	ldTgtId;
	U8	isRead;
	U16	devHandle;
	U64	pdBlock;
	U8	fpOkForIo;
	U8	ldPI;
};

#endif /* _FUSION_H_ */
