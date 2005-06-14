/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
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
 *    $FreeBSD: src/sys/dev/aac/aacreg.h,v 1.17 2003/10/17 21:44:06 scottl Exp $
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

/* Status bits in firmware status reg */
#define	AAC_SELF_TEST_FAILED	0x00000004
#define	AAC_READY		0x00000080
#define	AAC_KERNEL_PANIC	0x00000100

/* Aac registers definitions */
#define	AAC_IDBR		0x20	/* inbound doorbell reg */
#define	AAC_ODBR		0x2c	/* outbound doorbell reg */
#define	AAC_OIMR		0x34	/* outbound interrupt mask reg */
#define	AAC_MAILBOX		0x50	/* mailbox, size=20bytes */
#define	AAC_FWSTATUS		0x6c	/* firmware status */

/* Synchronous commands to the monitor/kernel. */
#define	AAC_MONKER_INITSTRUCT	0x05
#define	AAC_MONKER_SYNCFIB	0x0c
#define	AAC_MONKER_GETKERNVER	0x11
#define	AAC_MONKER_GETINFO	0x19

#define	AAC_NSEG		17	/* max number of segments */
#define	AAC_MAX_LD		64	/* max number of logical disks */
#define	AAC_BLK_SIZE		512

#pragma	pack(1)

/*
 * FIB (FSA Interface Block) this is the datastructure passed between
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

#define	AAC_FIB_SIZE		512 /* size of a fib block in byte */
#define	AAC_FIB_DATASIZE	(AAC_FIB_SIZE - sizeof (struct aac_fib_header))

struct aac_fib {
	struct aac_fib_header	Header;
	uint8_t data[AAC_FIB_DATASIZE];
};

/* fib transfer state */
#define	AAC_FIBSTATE_HOSTOWNED		(1<<0)	/* owned by the host */
#define	AAC_FIBSTATE_ADAPTEROWNED	(1<<1)	/* owned by the adapter */
#define	AAC_FIBSTATE_INITIALISED	(1<<2)	/* has been initialised */
#define	AAC_FIBSTATE_EMPTY		(1<<3)	/* is empty now */
#define	AAC_FIBSTATE_FROMHOST		(1<<5)	/* sent from the host */
#define	AAC_FIBSTATE_REXPECTED		(1<<7)	/* response is expected */
#define	AAC_FIBSTATE_NORM		(1<<12)	/* normal priority */
#define	AAC_FIBSTATE_ASYNC		(1<<13)

/* FIB types */
#define	AAC_FIBTYPE_TFIB	1

/* FIB commands */
#define	ContainerCommand	500
#define	RequestAdapterInfo	703

/* Structures used to respond to a RequestAdapterInfo fib */
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
	uint32_t			ObjectId;
	char				FileSystemName[16];
	struct aac_container_creation	CreateInfo;
	uint32_t			Capacity;
	uint32_t			VolType;
	uint32_t			ObjType;
	uint32_t			ContentState;
	union {
		uint32_t		pad[8];
	} ObjExtension;
	uint32_t			AlterEgoId;
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

/* volumn manager commands */
#define	VM_NameServe	1
#define	VM_CtBlockRead	6
#define	VM_CtBlockWrite	7

/* Host-addressable object types */
#define	FT_FILESYS	8

/* Host-side scatter/gather list for 32-bit commands */
struct aac_sg_entry {
	uint32_t	SgAddress;
	uint32_t	SgByteCount;
};

struct aac_sg_table {
	uint32_t		SgCount;
	struct aac_sg_entry	SgEntry[1]; /* at least there is one */
					    /* SUN's CC cannot accept [0] */
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

struct aac_blockwrite {
	uint32_t		Command;
	uint32_t		ContainerId;
	uint32_t		BlockNumber;
	uint32_t		ByteCount;
	uint32_t		Stable;
	struct aac_sg_table	SgMap;
};

/* Write 'stability' options */
#define	CSTABLE 	1
#define	CUNSTABLE 	2

/* Fibs for the controller to send us messages */
#define	AAC_ADAPTER_FIBS 8

/* Fibs for the host I/O request */
#define	AAC_HOST_FIBS 	256

/* buffer for text messages from the controller */
#define	AAC_ADAPTER_PRINT_BUFSIZE 256

#define	AAC_INIT_STRUCT_REVISION		3
#define	AAC_INIT_STRUCT_MINIPORT_REVISION	1
#define	AAC_PAGE_SIZE				4096
struct aac_adapter_init {
	uint32_t	InitStructRevision;
	uint32_t	MiniPortRevision;
	uint32_t	FilesystemRevision;
	uint32_t	CommHeaderAddress;
	uint32_t	FastIoCommAreaAddress;
	uint32_t	AdapterFibsPhysicalAddress;
	uint32_t 	AdapterFibsVirtualAddress;
	uint32_t	AdapterFibsSize;
	uint32_t	AdapterFibAlign;
	uint32_t	PrintfBufferAddress;
	uint32_t	PrintfBufferSize;
	uint32_t	HostPhysMemPages;
	uint32_t	HostElapsedSeconds;
};

/* ************AAC QUEUE DEFINES (BELOW)*********** */

#define	AAC_QUEUE_ALIGN 	16
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
 * We establish 4 command queues and matching response queues.  Queues must
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

#define	AAC_TOTALQ_LENGTH	(AAC_HOST_HIGH_CMD_ENTRIES +	\
				AAC_HOST_NORM_CMD_ENTRIES +	\
				AAC_ADAP_HIGH_CMD_ENTRIES +	\
				AAC_ADAP_NORM_CMD_ENTRIES +	\
				AAC_HOST_HIGH_RESP_ENTRIES +	\
				AAC_HOST_NORM_RESP_ENTRIES +	\
				AAC_ADAP_HIGH_RESP_ENTRIES +	\
				AAC_ADAP_NORM_RESP_ENTRIES)

/*
 * Table of queue indices and queues used to communicate with the
 * controller.  This structure must be aligned to AAC_QUEUE_ALIGN
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
	struct aac_queue_entry qt_HostNormRespQueue\
		[AAC_HOST_NORM_RESP_ENTRIES];
	struct aac_queue_entry qt_HostHighRespQueue\
		[AAC_HOST_HIGH_RESP_ENTRIES];
	struct aac_queue_entry qt_AdapNormRespQueue\
		[AAC_ADAP_NORM_RESP_ENTRIES];
	struct aac_queue_entry qt_AdapHighRespQueue\
		[AAC_ADAP_HIGH_RESP_ENTRIES];
};
/* ************AAC QUEUE DEFINES (ABOVE)*********** */

#pragma	pack()

/* AAC Communication Space */
struct aac_comm_space {
	struct aac_queue_table qtable;
	char qt_align_pad[AAC_QUEUE_ALIGN];
	struct aac_fib adapter_fibs[AAC_ADAPTER_FIBS];
	char	adapter_print_buf[AAC_ADAPTER_PRINT_BUFSIZE];
	struct aac_adapter_init init_data;
	struct aac_fib sync_fib;
};

#ifdef	__cplusplus
}
#endif

#endif /* __AAC_REGS_H__ */
