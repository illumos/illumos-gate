/*
 * Copyright (C) 2007 VMware, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common
 * Development and Distribution License (the "License") version 1.0
 * and no later version.  You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 *         http://www.opensource.org/licenses/cddl1.php
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * vmxnet3_defs.h --
 *
 *      Definitions shared by device emulation and guest drivers for
 *      VMXNET3 NIC
 */

#ifndef _VMXNET3_DEFS_H_
#define	_VMXNET3_DEFS_H_

#include <upt1_defs.h>

/* all registers are 32 bit wide */
/* BAR 1 */
#define	VMXNET3_REG_VRRS	0x0	/* Vmxnet3 Revision Report Selection */
#define	VMXNET3_REG_UVRS	0x8	/* UPT Version Report Selection */
#define	VMXNET3_REG_DSAL	0x10	/* Driver Shared Address Low */
#define	VMXNET3_REG_DSAH	0x18	/* Driver Shared Address High */
#define	VMXNET3_REG_CMD		0x20	/* Command */
#define	VMXNET3_REG_MACL	0x28	/* MAC Address Low */
#define	VMXNET3_REG_MACH	0x30	/* MAC Address High */
#define	VMXNET3_REG_ICR		0x38	/* Interrupt Cause Register */
#define	VMXNET3_REG_ECR		0x40	/* Event Cause Register */

#define	VMXNET3_REG_WSAL	0xF00	/* Wireless Shared Address Lo */
#define	VMXNET3_REG_WSAH	0xF08	/* Wireless Shared Address Hi */
#define	VMXNET3_REG_WCMD	0xF18	/* Wireless Command */

/* BAR 0 */
#define	VMXNET3_REG_IMR		0x0	/* Interrupt Mask Register */
#define	VMXNET3_REG_TXPROD	0x600	/* Tx Producer Index */
#define	VMXNET3_REG_RXPROD	0x800	/* Rx Producer Index for ring 1 */
#define	VMXNET3_REG_RXPROD2	0xA00	/* Rx Producer Index for ring 2 */

#define	VMXNET3_PT_REG_SIZE	4096	/* BAR 0 */
#define	VMXNET3_VD_REG_SIZE	4096	/* BAR 1 */

/*
 * The two Vmxnet3 MMIO Register PCI BARs (BAR 0 at offset 10h and BAR 1 at
 * offset 14h) as well as the MSI-X BAR are combined into one PhysMem region:
 * <-VMXNET3_PT_REG_SIZE-><-VMXNET3_VD_REG_SIZE-><-VMXNET3_MSIX_BAR_SIZE-->
 * -------------------------------------------------------------------------
 * |Pass Thru Registers  | Virtual Dev Registers | MSI-X Vector/PBA Table  |
 * -------------------------------------------------------------------------
 * VMXNET3_MSIX_BAR_SIZE is defined in "vmxnet3Int.h"
 */
#define	VMXNET3_PHYSMEM_PAGES	4

#define	VMXNET3_REG_ALIGN	8	/* All registers are 8-byte aligned. */
#define	VMXNET3_REG_ALIGN_MASK	0x7

/* I/O Mapped access to registers */
#define	VMXNET3_IO_TYPE_PT		0
#define	VMXNET3_IO_TYPE_VD		1
#define	VMXNET3_IO_ADDR(type, reg)	(((type) << 24) | ((reg) & 0xFFFFFF))
#define	VMXNET3_IO_TYPE(addr)		((addr) >> 24)
#define	VMXNET3_IO_REG(addr)		((addr) & 0xFFFFFF)

/*
 * The Sun Studio compiler complains if enums overflow INT_MAX, so we can only
 * use an enum with gcc.  We keep this here for the convenience of merging
 * from upstream.
 */
#ifdef __GNUC__

typedef enum {
	VMXNET3_CMD_FIRST_SET = 0xCAFE0000,
	VMXNET3_CMD_ACTIVATE_DEV = VMXNET3_CMD_FIRST_SET,
	VMXNET3_CMD_QUIESCE_DEV,
	VMXNET3_CMD_RESET_DEV,
	VMXNET3_CMD_UPDATE_RX_MODE,
	VMXNET3_CMD_UPDATE_MAC_FILTERS,
	VMXNET3_CMD_UPDATE_VLAN_FILTERS,
	VMXNET3_CMD_UPDATE_RSSIDT,
	VMXNET3_CMD_UPDATE_IML,
	VMXNET3_CMD_UPDATE_PMCFG,
	VMXNET3_CMD_UPDATE_FEATURE,
	VMXNET3_CMD_STOP_EMULATION,
	VMXNET3_CMD_LOAD_PLUGIN,
	VMXNET3_CMD_ACTIVATE_VF,

	VMXNET3_CMD_FIRST_GET = 0xF00D0000,
	VMXNET3_CMD_GET_QUEUE_STATUS = VMXNET3_CMD_FIRST_GET,
	VMXNET3_CMD_GET_STATS,
	VMXNET3_CMD_GET_LINK,
	VMXNET3_CMD_GET_PERM_MAC_LO,
	VMXNET3_CMD_GET_PERM_MAC_HI,
	VMXNET3_CMD_GET_DID_LO,
	VMXNET3_CMD_GET_DID_HI,
	VMXNET3_CMD_GET_DEV_EXTRA_INFO,
	VMXNET3_CMD_GET_CONF_INTR,
	VMXNET3_CMD_GET_ADAPTIVE_RING_INFO
} Vmxnet3_Cmd;

#else

#define	VMXNET3_CMD_FIRST_SET 0xCAFE0000U
#define	VMXNET3_CMD_ACTIVATE_DEV VMXNET3_CMD_FIRST_SET
#define	VMXNET3_CMD_QUIESCE_DEV (VMXNET3_CMD_FIRST_SET + 1)
#define	VMXNET3_CMD_RESET_DEV (VMXNET3_CMD_FIRST_SET + 2)
#define	VMXNET3_CMD_UPDATE_RX_MODE (VMXNET3_CMD_FIRST_SET + 3)
#define	VMXNET3_CMD_UPDATE_MAC_FILTERS (VMXNET3_CMD_FIRST_SET + 4)
#define	VMXNET3_CMD_UPDATE_VLAN_FILTERS (VMXNET3_CMD_FIRST_SET + 5)
#define	VMXNET3_CMD_UPDATE_RSSIDT (VMXNET3_CMD_FIRST_SET + 6)
#define	VMXNET3_CMD_UPDATE_IML (VMXNET3_CMD_FIRST_SET + 7)
#define	VMXNET3_CMD_UPDATE_PMCFG (VMXNET3_CMD_FIRST_SET + 8)
#define	VMXNET3_CMD_UPDATE_FEATURE (VMXNET3_CMD_FIRST_SET + 9)
#define	VMXNET3_CMD_STOP_EMULATION (VMXNET3_CMD_FIRST_SET + 10)
#define	VMXNET3_CMD_LOAD_PLUGIN (VMXNET3_CMD_FIRST_SET + 11)
#define	VMXNET3_CMD_ACTIVATE_VF (VMXNET3_CMD_FIRST_SET + 12)

#define	VMXNET3_CMD_FIRST_GET 0xF00D0000U
#define	VMXNET3_CMD_GET_QUEUE_STATUS VMXNET3_CMD_FIRST_GET
#define	VMXNET3_CMD_GET_STATS (VMXNET3_CMD_FIRST_GET + 1)
#define	VMXNET3_CMD_GET_LINK (VMXNET3_CMD_FIRST_GET + 2)
#define	VMXNET3_CMD_GET_PERM_MAC_LO (VMXNET3_CMD_FIRST_GET + 3)
#define	VMXNET3_CMD_GET_PERM_MAC_HI (VMXNET3_CMD_FIRST_GET + 4)
#define	VMXNET3_CMD_GET_DID_LO (VMXNET3_CMD_FIRST_GET + 5)
#define	VMXNET3_CMD_GET_DID_HI (VMXNET3_CMD_FIRST_GET + 6)
#define	VMXNET3_CMD_GET_DEV_EXTRA_INFO (VMXNET3_CMD_FIRST_GET + 7)
#define	VMXNET3_CMD_GET_CONF_INTR (VMXNET3_CMD_FIRST_GET + 8)
#define	VMXNET3_CMD_GET_ADAPTIVE_RING_INFO (VMXNET3_CMD_FIRST_GET + 9)

#endif

/* Adaptive Ring Info Flags */
#define	VMXNET3_DISABLE_ADAPTIVE_RING 1

#pragma pack(1)
typedef struct Vmxnet3_TxDesc {
	uint64_t	addr;
	uint32_t	len:14;
	uint32_t	gen:1;		/* generation bit */
	uint32_t	rsvd:1;
	uint32_t	dtype:1;	/* descriptor type */
	uint32_t	ext1:1;
	uint32_t	msscof:14;	/* MSS, checksum offset, flags */
	uint32_t	hlen:10;	/* header len */
	uint32_t	om:2;		/* offload mode */
	uint32_t	eop:1;		/* End Of Packet */
	uint32_t	cq:1;		/* completion request */
	uint32_t	ext2:1;
	uint32_t	ti:1;		/* VLAN Tag Insertion */
	uint32_t	tci:16;		/* Tag to Insert */
} Vmxnet3_TxDesc;
#pragma pack()

/* TxDesc.OM values */
#define	VMXNET3_OM_NONE		0
#define	VMXNET3_OM_CSUM		2
#define	VMXNET3_OM_TSO		3

/* fields in TxDesc we access w/o using bit fields */
#define	VMXNET3_TXD_EOP_SHIFT		12
#define	VMXNET3_TXD_CQ_SHIFT		13
#define	VMXNET3_TXD_GEN_SHIFT		14
#define	VMXNET3_TXD_EOP_DWORD_SHIFT	3
#define	VMXNET3_TXD_GEN_DWORD_SHIFT	2

#define	VMXNET3_TXD_CQ	(1 << VMXNET3_TXD_CQ_SHIFT)
#define	VMXNET3_TXD_EOP	(1 << VMXNET3_TXD_EOP_SHIFT)
#define	VMXNET3_TXD_GEN	(1 << VMXNET3_TXD_GEN_SHIFT)

#define	VMXNET3_TXD_GEN_SIZE	1
#define	VMXNET3_TXD_EOP_SIZE	1

#define	VMXNET3_HDR_COPY_SIZE	128

#pragma pack(1)
typedef struct Vmxnet3_TxDataDesc {
	uint8_t		data[VMXNET3_HDR_COPY_SIZE];
} Vmxnet3_TxDataDesc;
#pragma pack()

#define	VMXNET3_TCD_GEN_SHIFT		31
#define	VMXNET3_TCD_GEN_SIZE		1
#define	VMXNET3_TCD_TXIDX_SHIFT		0
#define	VMXNET3_TCD_TXIDX_SIZE		12
#define	VMXNET3_TCD_GEN_DWORD_SHIFT	3

#pragma pack(1)
typedef struct Vmxnet3_TxCompDesc {
	uint32_t	txdIdx:12;	/* Index of the EOP TxDesc */
	uint32_t	ext1:20;

	uint32_t	ext2;
	uint32_t	ext3;

	uint32_t	rsvd:24;
	uint32_t	type:7;		/* completion type */
	uint32_t	gen:1;		/* generation bit */
} Vmxnet3_TxCompDesc;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_RxDesc {
	uint64_t	addr;
	uint32_t	len:14;
	uint32_t	btype:1;	/* Buffer Type */
	uint32_t	dtype:1;	/* Descriptor type */
	uint32_t	rsvd:15;
	uint32_t	gen:1;		/* Generation bit */
	uint32_t	ext1;
} Vmxnet3_RxDesc;
#pragma pack()

/* values of RXD.BTYPE */
#define	VMXNET3_RXD_BTYPE_HEAD	0	/* head only */
#define	VMXNET3_RXD_BTYPE_BODY	1	/* body only */

/* fields in RxDesc we access w/o using bit fields */
#define	VMXNET3_RXD_BTYPE_SHIFT	14
#define	VMXNET3_RXD_GEN_SHIFT	31

#pragma pack(1)
typedef struct Vmxnet3_RxCompDesc {
	uint32_t	rxdIdx:12;	/* Index of the RxDesc */
	uint32_t	ext1:2;
	uint32_t	eop:1;		/* End of Packet */
	uint32_t	sop:1;		/* Start of Packet */
	uint32_t	rqID:10;	/* rx queue/ring ID */
	uint32_t	rssType:4;	/* RSS hash type used */
	uint32_t	cnc:1;		/* Checksum Not Calculated */
	uint32_t	ext2:1;
	uint32_t	rssHash;	/* RSS hash value */
	uint32_t	len:14;		/* data length */
	uint32_t	err:1;		/* Error */
	uint32_t	ts:1;		/* Tag is stripped */
	uint32_t	tci:16;		/* Tag stripped */
	uint32_t	csum:16;
	uint32_t	tuc:1;		/* TCP/UDP Checksum Correct */
	uint32_t	udp:1;		/* UDP packet */
	uint32_t	tcp:1;		/* TCP packet */
	uint32_t	ipc:1;		/* IP Checksum Correct */
	uint32_t	v6:1;		/* IPv6 */
	uint32_t	v4:1;		/* IPv4 */
	uint32_t	frg:1;		/* IP Fragment */
	uint32_t	fcs:1;		/* Frame CRC correct */
	uint32_t	type:7;		/* completion type */
	uint32_t	gen:1;		/* generation bit */
} Vmxnet3_RxCompDesc;
#pragma pack()

/* fields in RxCompDesc we access via Vmxnet3_GenericDesc.dword[3] */
#define	VMXNET3_RCD_TUC_SHIFT	16
#define	VMXNET3_RCD_IPC_SHIFT	19

/* fields in RxCompDesc we access via Vmxnet3_GenericDesc.qword[1] */
#define	VMXNET3_RCD_TYPE_SHIFT	56
#define	VMXNET3_RCD_GEN_SHIFT	63

/* csum OK for TCP/UDP pkts over IP */
#define	VMXNET3_RCD_CSUM_OK \
	(1 << VMXNET3_RCD_TUC_SHIFT | 1 << VMXNET3_RCD_IPC_SHIFT)

/* value of RxCompDesc.rssType */
#define	VMXNET3_RCD_RSS_TYPE_NONE	0
#define	VMXNET3_RCD_RSS_TYPE_IPV4	1
#define	VMXNET3_RCD_RSS_TYPE_TCPIPV4	2
#define	VMXNET3_RCD_RSS_TYPE_IPV6	3
#define	VMXNET3_RCD_RSS_TYPE_TCPIPV6	4

/* a union for accessing all cmd/completion descriptors */
typedef union Vmxnet3_GenericDesc {
	uint64_t	qword[2];
	uint32_t	dword[4];
	uint16_t	word[8];
	Vmxnet3_TxDesc	txd;
	Vmxnet3_RxDesc	rxd;
	Vmxnet3_TxCompDesc tcd;
	Vmxnet3_RxCompDesc rcd;
} Vmxnet3_GenericDesc;

#define	VMXNET3_INIT_GEN	1

/* Max size of a single tx buffer */
#define	VMXNET3_MAX_TX_BUF_SIZE	(1 << 14)

/* # of tx desc needed for a tx buffer size */
#define	VMXNET3_TXD_NEEDED(size) \
	(((size) + VMXNET3_MAX_TX_BUF_SIZE - 1) / VMXNET3_MAX_TX_BUF_SIZE)

/* max # of tx descs for a non-tso pkt */
#define	VMXNET3_MAX_TXD_PER_PKT	16

/* Max size of a single rx buffer */
#define	VMXNET3_MAX_RX_BUF_SIZE	((1 << 14) - 1)
/* Minimum size of a type 0 buffer */
#define	VMXNET3_MIN_T0_BUF_SIZE	128
#define	VMXNET3_MAX_CSUM_OFFSET	1024

/* Ring base address alignment */
#define	VMXNET3_RING_BA_ALIGN	512
#define	VMXNET3_RING_BA_MASK	(VMXNET3_RING_BA_ALIGN - 1)

/* Ring size must be a multiple of 32 */
#define	VMXNET3_RING_SIZE_ALIGN	32
#define	VMXNET3_RING_SIZE_MASK	(VMXNET3_RING_SIZE_ALIGN - 1)

/* Max ring size */
#define	VMXNET3_TX_RING_MAX_SIZE	4096
#define	VMXNET3_TC_RING_MAX_SIZE	4096
#define	VMXNET3_RX_RING_MAX_SIZE	4096
#define	VMXNET3_RC_RING_MAX_SIZE	8192

/* a list of reasons for queue stop */

#define	VMXNET3_ERR_NOEOP	0x80000000	/* cannot find the */
						/* EOP desc of a pkt */
#define	VMXNET3_ERR_TXD_REUSE	0x80000001	/* reuse a TxDesc before tx */
						/* completion */
#define	VMXNET3_ERR_BIG_PKT	0x80000002	/* too many TxDesc for a pkt */
#define	VMXNET3_ERR_DESC_NOT_SPT 0x80000003	/* descriptor type not */
						/* supported */
#define	VMXNET3_ERR_SMALL_BUF	0x80000004	/* type 0 buffer too small */
#define	VMXNET3_ERR_STRESS	0x80000005	/* stress option firing */
						/* in vmkernel */
#define	VMXNET3_ERR_SWITCH	0x80000006	/* mode switch failure */
#define	VMXNET3_ERR_TXD_INVALID	0x80000007	/* invalid TxDesc */

/* completion descriptor types */
#define	VMXNET3_CDTYPE_TXCOMP	0	/* Tx Completion Descriptor */
#define	VMXNET3_CDTYPE_RXCOMP	3	/* Rx Completion Descriptor */

#define	VMXNET3_GOS_BITS_UNK	0	/* unknown */
#define	VMXNET3_GOS_BITS_32	1
#define	VMXNET3_GOS_BITS_64	2

#define	VMXNET3_GOS_TYPE_UNK	0 /* unknown */
#define	VMXNET3_GOS_TYPE_LINUX	1
#define	VMXNET3_GOS_TYPE_WIN	2
#define	VMXNET3_GOS_TYPE_SOLARIS 3
#define	VMXNET3_GOS_TYPE_FREEBSD 4
#define	VMXNET3_GOS_TYPE_PXE	5

/* All structures in DriverShared are padded to multiples of 8 bytes */

#pragma pack(1)
typedef struct Vmxnet3_GOSInfo {
	uint32_t	gosBits: 2;	/* 32-bit or 64-bit? */
	uint32_t	gosType: 4;	/* which guest */
	uint32_t	gosVer: 16;	/* gos version */
	uint32_t	gosMisc: 10;	/* other info about gos */
} Vmxnet3_GOSInfo;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_DriverInfo {
	uint32_t	version;	/* driver version */
	Vmxnet3_GOSInfo	gos;
	uint32_t	vmxnet3RevSpt;	/* vmxnet3 revision supported */
	uint32_t	uptVerSpt;	/* upt version supported */
} Vmxnet3_DriverInfo;
#pragma pack()

#define	VMXNET3_REV1_MAGIC	0xbabefee1

/*
 * QueueDescPA must be 128 bytes aligned. It points to an array of
 * Vmxnet3_TxQueueDesc followed by an array of Vmxnet3_RxQueueDesc.
 * The number of Vmxnet3_TxQueueDesc/Vmxnet3_RxQueueDesc are specified by
 * Vmxnet3_MiscConf.numTxQueues/numRxQueues, respectively.
 */
#define	VMXNET3_QUEUE_DESC_ALIGN	128

#pragma pack(1)
typedef struct Vmxnet3_MiscConf {
	Vmxnet3_DriverInfo driverInfo;
	uint64_t	uptFeatures;
	uint64_t	ddPA;		/* driver data PA */
	uint64_t	queueDescPA;	/* queue descriptor table PA */
	uint32_t	ddLen;		/* driver data len */
	uint32_t	queueDescLen;	/* queue descriptor table len, bytes */
	uint32_t	mtu;
	uint16_t	maxNumRxSG;
	uint8_t		numTxQueues;
	uint8_t		numRxQueues;
	uint32_t	reserved[4];
} Vmxnet3_MiscConf;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_TxQueueConf {
	uint64_t	txRingBasePA;
	uint64_t	dataRingBasePA;
	uint64_t	compRingBasePA;
	uint64_t	ddPA;		/* driver data */
	uint64_t	reserved;
	uint32_t	txRingSize;	/* # of tx desc */
	uint32_t	dataRingSize;	/* # of data desc */
	uint32_t	compRingSize;	/* # of comp desc */
	uint32_t	ddLen;		/* size of driver data */
	uint8_t		intrIdx;
	uint8_t		_pad[7];
} Vmxnet3_TxQueueConf;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_RxQueueConf {
	uint64_t	rxRingBasePA[2];
	uint64_t	compRingBasePA;
	uint64_t	ddPA;		/* driver data */
	uint64_t	reserved;
	uint32_t	rxRingSize[2];	/* # of rx desc */
	uint32_t	compRingSize;	/* # of rx comp desc */
	uint32_t	ddLen;		/* size of driver data */
	uint8_t		intrIdx;
	uint8_t		_pad[7];
} Vmxnet3_RxQueueConf;
#pragma pack()

enum vmxnet3_intr_mask_mode {
	VMXNET3_IMM_AUTO =	0,
	VMXNET3_IMM_ACTIVE =	1,
	VMXNET3_IMM_LAZY =	2
};

enum vmxnet3_intr_type {
	VMXNET3_IT_AUTO =	0,
	VMXNET3_IT_INTX =	1,
	VMXNET3_IT_MSI =	2,
	VMXNET3_IT_MSIX =	3
};

#define	VMXNET3_MAX_TX_QUEUES	8
#define	VMXNET3_MAX_RX_QUEUES	16
/* addition 1 for events */
#define	VMXNET3_MAX_INTRS	25

/* value of intrCtrl */
#define	VMXNET3_IC_DISABLE_ALL	0x1	/* bit 0 */

#pragma pack(1)
typedef struct Vmxnet3_IntrConf {
	char		autoMask;
	uint8_t		numIntrs;	/* # of interrupts */
	uint8_t		eventIntrIdx;
	uint8_t		modLevels[VMXNET3_MAX_INTRS];	/* moderation level */
							/* for each intr */
	uint32_t	intrCtrl;
	uint32_t	reserved[2];
} Vmxnet3_IntrConf;
#pragma pack()

/* one bit per VLAN ID, the size is in the units of uint32_t */
#define	VMXNET3_VFT_SIZE (4096 / (sizeof (uint32_t) * 8))

#pragma pack(1)
typedef struct Vmxnet3_QueueStatus {
	char		stopped;
	uint8_t		_pad[3];
	uint32_t	error;
} Vmxnet3_QueueStatus;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_TxQueueCtrl {
	uint32_t	txNumDeferred;
	uint32_t	txThreshold;
	uint64_t	reserved;
} Vmxnet3_TxQueueCtrl;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_RxQueueCtrl {
	char		updateRxProd;
	uint8_t		_pad[7];
	uint64_t	reserved;
} Vmxnet3_RxQueueCtrl;
#pragma pack()

#define	VMXNET3_RXM_UCAST	0x01	/* unicast only */
#define	VMXNET3_RXM_MCAST	0x02	/* multicast passing the filters */
#define	VMXNET3_RXM_BCAST	0x04	/* broadcast only */
#define	VMXNET3_RXM_ALL_MULTI	0x08	/* all multicast */
#define	VMXNET3_RXM_PROMISC	0x10	/* promiscuous */

#pragma pack(1)
typedef struct Vmxnet3_RxFilterConf {
	uint32_t	rxMode;		/* VMXNET3_RXM_xxx */
	uint16_t	mfTableLen;	/* size of the multicast filter table */
	uint16_t	_pad1;
	uint64_t	mfTablePA;	/* PA of the multicast filters table */
	uint32_t	vfTable[VMXNET3_VFT_SIZE]; /* vlan filter */
} Vmxnet3_RxFilterConf;
#pragma pack()

#define	VMXNET3_PM_MAX_FILTERS		6
#define	VMXNET3_PM_MAX_PATTERN_SIZE	128
#define	VMXNET3_PM_MAX_MASK_SIZE	(VMXNET3_PM_MAX_PATTERN_SIZE / 8)

#define	VMXNET3_PM_WAKEUP_MAGIC		0x01	/* wake up on magic pkts */
#define	VMXNET3_PM_WAKEUP_FILTER	0x02	/* wake up on pkts matching */
						/* filters */

#pragma pack(1)
typedef struct Vmxnet3_PM_PktFilter {
	uint8_t		maskSize;
	uint8_t		patternSize;
	uint8_t		mask[VMXNET3_PM_MAX_MASK_SIZE];
	uint8_t		pattern[VMXNET3_PM_MAX_PATTERN_SIZE];
	uint8_t		pad[6];
} Vmxnet3_PM_PktFilter;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_PMConf {
	uint16_t	wakeUpEvents;	/* VMXNET3_PM_WAKEUP_xxx */
	uint8_t		numFilters;
	uint8_t		pad[5];
	Vmxnet3_PM_PktFilter filters[VMXNET3_PM_MAX_FILTERS];
} Vmxnet3_PMConf;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_VariableLenConfDesc {
	uint32_t	confVer;
	uint32_t	confLen;
	uint64_t	confPA;
} Vmxnet3_VariableLenConfDesc;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_DSDevRead {
	/* read-only region for device, read by dev in response to a SET cmd */
	Vmxnet3_MiscConf misc;
	Vmxnet3_IntrConf intrConf;
	Vmxnet3_RxFilterConf rxFilterConf;
	Vmxnet3_VariableLenConfDesc rssConfDesc;
	Vmxnet3_VariableLenConfDesc pmConfDesc;
	Vmxnet3_VariableLenConfDesc pluginConfDesc;
} Vmxnet3_DSDevRead;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_TxQueueDesc {
	Vmxnet3_TxQueueCtrl ctrl;
	Vmxnet3_TxQueueConf conf;
	/* Driver read after a GET command */
	Vmxnet3_QueueStatus status;
	UPT1_TxStats	stats;
	uint8_t		_pad[88];	/* 128 aligned */
} Vmxnet3_TxQueueDesc;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_RxQueueDesc {
	Vmxnet3_RxQueueCtrl ctrl;
	Vmxnet3_RxQueueConf conf;
	/* Driver read after a GET command */
	Vmxnet3_QueueStatus status;
	UPT1_RxStats	stats;
	uint8_t		_pad[88];	/* 128 aligned */
} Vmxnet3_RxQueueDesc;
#pragma pack()

#pragma pack(1)
typedef struct Vmxnet3_DriverShared {
	uint32_t	magic;
	uint32_t	pad;		/* make devRead start at */
					/* 64-bit boundaries */
	Vmxnet3_DSDevRead devRead;
	uint32_t	ecr;
	uint32_t	reserved[5];
} Vmxnet3_DriverShared;
#pragma pack()

#define	VMXNET3_ECR_RQERR	(1 << 0)
#define	VMXNET3_ECR_TQERR	(1 << 1)
#define	VMXNET3_ECR_LINK	(1 << 2)
#define	VMXNET3_ECR_DIC		(1 << 3)
#define	VMXNET3_ECR_DEBUG	(1 << 4)

/* flip the gen bit of a ring */
#define	VMXNET3_FLIP_RING_GEN(gen) ((gen) = (gen) ^ 0x1)

/* only use this if moving the idx won't affect the gen bit */
#define	VMXNET3_INC_RING_IDX_ONLY(idx, ring_size) {	\
	(idx)++;					\
	if (UNLIKELY((idx) == (ring_size))) {		\
		(idx) = 0;				\
	}						\
}

#define	VMXNET3_SET_VFTABLE_ENTRY(vfTable, vid) \
	vfTable[vid >> 5] |= (1 << (vid & 31))
#define	VMXNET3_CLEAR_VFTABLE_ENTRY(vfTable, vid) \
	vfTable[vid >> 5] &= ~(1 << (vid & 31))

#define	VMXNET3_VFTABLE_ENTRY_IS_SET(vfTable, vid) \
	((vfTable[vid >> 5] & (1 << (vid & 31))) != 0)

#define	VMXNET3_MAX_MTU		9000
#define	VMXNET3_MIN_MTU		60

#define	VMXNET3_LINK_UP		(10000 << 16 | 1)	/* 10 Gbps, up */
#define	VMXNET3_LINK_DOWN	0

#define	VMXWIFI_DRIVER_SHARED_LEN	8192

#define	VMXNET3_DID_PASSTHRU		0xFFFF

#endif /* _VMXNET3_DEFS_H_ */
