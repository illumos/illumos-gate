/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UNM_NIC_CMN_H_
#define	_UNM_NIC_CMN_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef sun
#include "unm_nic_config.h"
#include "unm_compiler_defs.h"
#endif

#define	IP_ALIGNMENT_BYTES		2  /* make ip aligned on 16byteaddr */
#define	P2_MAX_MTU			(8000)
#define	P3_MAX_MTU			(9600)
#define	NX_ETHERMTU			1500
#define	NX_MAX_ETHERHDR			32 /* This contains some padding */

#define	NX_RX_NORMAL_BUF_MAX_LEN	(NX_MAX_ETHERHDR + NX_ETHERMTU)
#define	NX_P2_RX_JUMBO_BUF_MAX_LEN	(NX_MAX_ETHERHDR + P2_MAX_MTU)
#define	NX_P3_RX_JUMBO_BUF_MAX_LEN	(NX_MAX_ETHERHDR + P3_MAX_MTU)

#define	MAX_RX_LRO_BUFFER_LENGTH	((8*1024) - 512)
#define	RX_LRO_DMA_MAP_LEN		(MAX_RX_LRO_BUFFER_LENGTH -\
					    IP_ALIGNMENT_BYTES)

/* Opcodes to be used with the commands */
#define	TX_ETHER_PKT	0x01
/* The following opcodes are for IP checksum    */
#define	TX_TCP_PKT		0x02
#define	TX_UDP_PKT		0x03
#define	TX_IP_PKT		0x04
#define	TX_TCP_LSO		0x05
#define	TX_IPSEC		0x06
#define	TX_IPSEC_CMD	0x07

#define	NETXEN_MAC_NOOP		0
#define	NETXEN_MAC_ADD		1
#define	NETXEN_MAC_DEL		2

/* The following opcodes are for internal consumption. */
#define	UNM_CONTROL_OP		0x10
#define	PEGNET_REQUEST		0x11
#define	NX_HOST_REQUEST		0x13
#define	NX_NIC_REQUEST		0x14
#define	NX_NIC_LRO_REQUEST	0x15

#define	NX_MAC_EVENT		0x1

enum {
	NX_NIC_H2C_OPCODE_START = 0,
	NX_NIC_H2C_OPCODE_CONFIG_RSS,
	NX_NIC_H2C_OPCODE_CONFIG_RSS_TBL,
	NX_NIC_H2C_OPCODE_CONFIG_INTR_COALESCE,
	NX_NIC_H2C_OPCODE_CONFIG_LED,
	NX_NIC_H2C_OPCODE_CONFIG_PROMISCUOUS,
	NX_NIC_H2C_OPCODE_CONFIG_L2_MAC,
	NX_NIC_H2C_OPCODE_LRO_REQUEST,
	NX_NIC_H2C_OPCODE_GET_SNMP_STATS,
	NX_NIC_H2C_OPCODE_PROXY_START_REQUEST,
	NX_NIC_H2C_OPCODE_PROXY_STOP_REQUEST,
	NX_NIC_H2C_OPCODE_PROXY_SET_MTU,
	NX_NIC_H2C_OPCODE_PROXY_SET_VPORT_MISS_MODE,
	NX_H2P_OPCODE_GET_FINGER_PRINT_REQUEST,
	NX_H2P_OPCODE_INSTALL_LICENSE_REQUEST,
	NX_H2P_OPCODE_GET_LICENSE_CAPABILITY_REQUEST,
	NX_NIC_H2C_OPCODE_GET_NET_STATS,
	NX_NIC_H2C_OPCODE_LAST
};

#define	VPORT_MISS_MODE_DROP			0 /* drop all unmatched */
#define	VPORT_MISS_MODE_ACCEPT_ALL		1 /* accept all packets */
#define	VPORT_MISS_MODE_ACCEPT_MULTI	2 /* accept unmatched multicast */

#ifdef UNM_RSS
#define	RSS_CNTRL_CMD		0x20
#endif
#define	MAX_NUM_CARDS		4
#define	MAX_NUM_PORTS		4 /* Deprecated. donot use this */
#define	MAX_NIU_PORTS		MAX_NUM_PORTS
#define	PORT1				0
#define	PORT2				1
#define	PORT3				2
#define	PORT4				3


#define	DESC_CHAIN		0xFF /* descriptor command continuation */

#define	MAX_BUFFERS_PER_CMD		16
#define	MAX_BUFFERS_PER_DESC	4

#define	NX_P2_C0				0x24
#define	NX_P2_C1				0x25

#define	DUMMY_BUF_UNINIT	0x55555555
#define	DUMMY_BUF_INIT		0

/*
 * Following are the states of the Phantom. Phantom will set them and
 * Host will read to check if the fields are correct.
 */
#define	PHAN_INITIALIZE_START		0xff00
#define	PHAN_INITIALIZE_FAILED		0xffff
#define	PHAN_INITIALIZE_COMPLETE	0xff01

/* Host writes the following to notify that it has done the init-handshake */
#define	PHAN_INITIALIZE_ACK			0xf00f

/* Following defines will be used in the status descriptor */
#define	TX_ETHER_PKT_COMPLETE  0xB  /* same for both commands */

#define	NUM_RCV_DESC_RINGS		3 /* No of Rcv Descriptor contexts */

/* descriptor types */
#define	RCV_DESC_NORMAL			0x01
#define	RCV_DESC_JUMBO			0x02
#define	RCV_DESC_LRO			0x04
#define	RCV_DESC_NORMAL_CTXID	0
#define	RCV_DESC_JUMBO_CTXID	1
#define	RCV_DESC_LRO_CTXID		2

#define	RCV_DESC_TYPE(ID) \
	((ID == RCV_DESC_JUMBO_CTXID) ? RCV_DESC_JUMBO :  \
	    ((ID == RCV_DESC_LRO_CTXID) ? RCV_DESC_LRO : (RCV_DESC_NORMAL)))

#define	RCV_DESC_TYPE_NAME(ID) \
	((ID	==	RCV_DESC_JUMBO_CTXID)	?	"Jumbo"	:	\
	(ID == RCV_DESC_LRO_CTXID)    ? "LRO"    :  \
	(ID == RCV_DESC_NORMAL_CTXID) ? "Normal" : "Unknown")

#define	MAX_CMD_DESCRIPTORS			4096
#define	MAX_CMD_DESCRIPTORS_HOST	(MAX_CMD_DESCRIPTORS / 4)

#define	MAX_RCV_DESCRIPTORS			8192
#define	MAX_JUMBO_RCV_DESCRIPTORS	1024
#define	MAX_LRO_RCV_DESCRIPTORS		16

#define	NX_MAX_SUPPORTED_RDS_SIZE	(32 * 1024)
#define	NX_MAX_SUPPORTED_JUMBO_RDS_SIZE	(4 * 1024)

#define	PHAN_PEG_RCV_INITIALIZED		0xff01
#define	PHAN_PEG_RCV_START_INITIALIZE	0xff00

#define	get_next_index(index, length)  ((((index)  + 1) == length)?0:(index) +1)

#define	get_index_range(index, length, count)	\
	((((index) + (count)) >= length)? \
		(((index)  + (count))-(length)):((index) + (count)))

#define	UNM_FLOW_TICKS_PER_SEC    2048
#define	UNM_FLOW_TO_TV_SHIFT_SEC  11
#define	UNM_FLOW_TO_TV_SHIFT_USEC 9
#define	UNM_FLOW_TICK_USEC   (1000000ULL/UNM_FLOW_TICKS_PER_SEC)
#define	UNM_GLOBAL_TICKS_PER_SEC  (4*UNM_FLOW_TICKS_PER_SEC)
#define	UNM_GLOBAL_TICK_USEC (1000000ULL/UNM_GLOBAL_TICKS_PER_SEC)


/*
 * Following data structures describe the descriptors that will be used.
 * Added fileds of tcpHdrSize and ipHdrSize, The driver needs to do it only when
 * we are doing LSO (above the 1500 size packet) only.
 * This is an overhead but we need it. Let me know if you have questions.
 */

/*
 * the size of reference handle been changed to 16 bits to pass the MSS fields
 * for the LSO packet
 */

#define	FLAGS_CHECKSUM_ENABLED		0x01
#define	FLAGS_LSO_ENABLED			0x02
#define	FLAGS_IPSEC_SA_ADD			0x04
#define	FLAGS_IPSEC_SA_DELETE		0x08
#define	FLAGS_VLAN_TAGGED			0x10

#if UNM_CONF_PROCESSOR == UNM_CONF_X86

#ifndef U64
typedef unsigned long long U64;
typedef uint32_t U32;
typedef uint16_t U16;
typedef uint8_t  U8;
#endif

#endif

#define	NUM_SUPPORTED_RINGSETS	4
#define	MAX_RING_CTX			4
#define	UNM_CTX_SIGNATURE		0xdee0
#define	UNM_CTX_RESET			0xbad0
#define	UNM_CTX_D3_RESET		0xacc0

/* define opcode for ctx_msg */
#define	RX_PRODUCER				0
#define	RX_PRODUCER_JUMBO		1
#define	RX_PRODUCER_LRO			2
#define	TX_PRODUCER				3
#define	UPDATE_STATUS_CONSUMER	4
#define	RESET_CTX				5

#define	NUM_DB_CODE				6

#define	UNM_RCV_PRODUCER(ringid)	(ringid)
#define	UNM_CMD_PRODUCER			TX_PRODUCER
#define	UNM_RCV_STATUS_CONSUMER		UPDATE_STATUS_CONSUMER

typedef struct __msg
{
    __uint32_t  PegId:2,   /* 0x2 for tx and 01 for rx */
			    privId:1, /* must be 1 */
			    Count:15, /* for doorbell */
			    CtxId:10, /* Ctx_id */
			    Opcode:4; /* opcode */
}ctx_msg, CTX_MSG, *PCTX_MSG;

typedef struct __int_msg
{
    __uint32_t  Count:18, /* INT */
			    ConsumerIdx:10,
			    CtxId:4; /* Ctx_id */

}int_msg, INT_MSG, *PINT_MSG;

/* For use in CRB_MPORT_MODE */
#define	MPORT_SINGLE_FUNCTION_MODE	0x1111
#define	MPORT_MULTI_FUNCTION_MODE	0x2222

typedef struct _RcvContext
{
	__uint32_t		RcvRingAddrLo;
	__uint32_t		RcvRingAddrHi;
	__uint32_t		RcvRingSize;
	__uint32_t		Rsrv;
}RcvContext;

typedef struct PREALIGN(64) _RingContext
{

	/* one command ring */
	__uint64_t		CMD_CONSUMER_OFFSET;
	__uint32_t		CmdRingAddrLo;
	__uint32_t		CmdRingAddrHi;
	__uint32_t		CmdRingSize;
	__uint32_t		Rsrv;

	/* three receive rings */
	RcvContext		RcvContext[3];

	/* one status ring */
	__uint32_t		StsRingAddrLo;
	__uint32_t		StsRingAddrHi;
	__uint32_t		StsRingSize;

	__uint32_t		CtxId;

	__uint64_t		D3_STATE_REGISTER;
	__uint32_t		DummyDmaAddrLo;
	__uint32_t		DummyDmaAddrHi;

}POSTALIGN(64) RingContext, RING_CTX, *PRING_CTX;

#ifdef UNM_RSS
/*
 * RSS_SreInfo{} has the information for SRE to calculate the hash value
 * Will be passed by the host=> as part of comd descriptor...
 */

#if UNM_CONF_PROCESSOR == UNM_CONF_X86
typedef struct _RSS_SreInfo {
	U32		HashKeySize;
	U32		HashInformation;
	char	key[40];
}RSS_SreInfo;
#endif

/*
 * The following Descriptor is used to send RSS commands to the
 * PEG.... to be do the SRE registers..
 */
typedef struct PREALIGN(64) _rssCmdDesc
{

	/*
	 * To keep the opcode at the same location as
	 * the cmdDescType0, we will have to breakup the key into
	 * 2 areas.... Dont like it but for now will do... FSL
	 */

#if UNM_CONF_PROCESSOR == UNM_CONF_X86
	U8		Key0[16];

	U64		HashMethod:32,
			HashKeySize:8,
			Unused:	16,
			opcode:8;

	U8		Key1[24];
	U64		Unused1;
	U64		Unused2;
#else

	unm_msgword_t		Key0[2];
	unm_halfmsgword_t	HashMethod;
	unm_halfmsgword_t
						HashKeySize:8,
						Unused:16,
						opcode:8;

	unm_msgword_t    Key1[3];
	unm_msgword_t    Unused1;
	unm_msgword_t    Unused2;

#endif

} POSTALIGN(64) rssCmdDesc_t;


#endif /* UNM_RSS */


typedef struct PREALIGN(64) cmdDescType0
{
	union {
		struct {
			__uint32_t	tcpHdrOffset:8, /* For LSO only */
			ipHdrOffset:8,  /* For LSO only */
			flags:7, /* as defined above */
			/* This location/size must not change... */
			opcode:6,
			Unused:3;
			/* total number of segments (buffers */
			__uint32_t	numOfBuffers:8,
			/* for this packet. (could be more than 4) */

			/* Total size of the packet */
			totalLength:24;
		}s1;
		__uint64_t	word0;
	}u1;

	union {
		struct {
			__uint32_t AddrLowPart2;
			__uint32_t AddrHighPart2;
		}s1;
		__uint64_t AddrBuffer2;
		__uint64_t	word1;
	}u2;

	union {
		struct {
					/* changed to U16 to add mss */
			__uint32_t	referenceHandle:16,
					/* passed by NDIS_PACKET for LSO */
						mss:16;
			__uint32_t	port:4,
						ctx_id:4,
					/* LSO only : MAC+IP+TCP Hdr size */
						totalHdrLength:8,
					/* IPSec offoad only */
						connID:16;
		}s1;
		__uint64_t	word2;
	}u3;

	union {
		struct {
			__uint32_t AddrLowPart3;
			__uint32_t AddrHighPart3;
		}s1;
		__uint64_t AddrBuffer3;
		__uint64_t	word3;
	}u4;

	union {
		struct {
			__uint32_t AddrLowPart1;
			__uint32_t AddrHighPart1;
		}s1;
		__uint64_t AddrBuffer1;
		__uint64_t	word4;
	}u5;

	union {
		struct {
			__uint32_t	buffer1Length:16,
						buffer2Length:16;
			__uint32_t  buffer3Length:16,
						buffer4Length:16;
		}s1;
		__uint64_t	word5;
	}u6;

	union {
		struct {
			__uint32_t AddrLowPart4;
			__uint32_t AddrHighPart4;
		}s1;
		__uint64_t AddrBuffer4;
		__uint64_t	word6;
	}u7;

	__uint64_t unused;

} POSTALIGN(64) cmdDescType0_t;

/* Note: sizeof(rcvDesc) should always be a mutliple of 2 */
typedef struct rcvDesc
{
	__uint32_t	referenceHandle:16,
				flags:16;
	__uint32_t
		/* allocated buffer length (usually 2K) */
				bufferLength:32;
	__uint64_t	AddrBuffer;
}  rcvDesc_t;

/* for status field in statusDesc_t */
#define	STATUS_NEED_CKSUM		(1)
#define	STATUS_CKSUM_OK			(2)
#define	STATUS_CKSUM_NOT_OK		(3)

/* owner bits of statusDesc_t */
#define	STATUS_OWNER_HOST		(1ULL)
#define	STATUS_OWNER_PHANTOM	(2ULL)
#define	HOST_STATUS_DESC		((STATUS_OWNER_HOST) << 48)
#define	PHANTOM_STATUS_DESC		((STATUS_OWNER_PHANTOM) << 48)

#define	UNM_PROT_IP			(1)
#define	UNM_PROT_UNKNOWN	(0)

/* LRO specific bits of statusDesc_t */
#define	LRO_LAST_FRAG			(1)
#define	LRO_NORMAL_FRAG			(0)
#define	LRO_LAST_FRAG_DESC		((LRO_LAST_FRAG)<<63)
#define	LRO_NORMAL_FRAG_DESC	((LRO_NORMAL_FRAG)<<63)

typedef struct PREALIGN(16) statusDesc {
	union {
		struct {
					/* initially to be used but noe now */
			__uint32_t	port:4,
					/* completion status may not have use */
						status:4,
					/* type/index of descriptor ring */
						type:4,
					/* NIC mode...no use yet */
						totalLength:16,
					/* handle for the associated packet */
						referenceHandle_lo:4;
					/* handle for the associated packet */
			__uint32_t	referenceHandle_hi:12,
					/* Pkt protocol */
						prot:4,
						pkt_offset:5,
/*
 * This indicates the num of descriptors part of this descriptor chain.
 */
						descCnt:3,
						owner:2,
						opcode:6;

			__uint32_t	HashValue;
			__uint16_t	vlan;
			__uint8_t	HashType;

		union {
			/*
			 * For LRO count is set
			 * Last LRO fragment is set when it is
			 * the last frag as the name says.
			 */
			__uint8_t	lro_frag:7, last_lro_frag:1;

			/*
			 * Used to indicate direction in case
			 * of captured packets. Egress will
			 * contain EPG input, while ingress
			 * contains an skb copy.
			 */
#define	NX_CAP_DIRN_OUT	1
#define	NX_CAP_DIRN_IN	2
			__uint8_t direction;

			/*
			 * Currently for Legacy this is 0.
			 */
			__uint8_t	nr_frags;
		}u11;

		}s1;
		__uint64_t	 body[2];
		}u1;

} POSTALIGN(16) statusDesc_t;


#define	STATUS_OWNER_NAME(sd) \
	(((sd)->u1.s1.owner == STATUS_OWNER_HOST) ? "Host" : "Phantom")

#ifdef	UNM_IPSECOFFLOAD

#define	MAX_IPSEC_SAS			1024
#define	RECEIVE_IPSEC_SA_BASE	0x8000

/*
 * IPSEC related structures and defines
 */

/* Values for DIrFlag in the ipsec_sa_t structure below: */
#define	UNM_IPSEC_SA_DIR_INBOUND	1
#define	UNM_IPSEC_SA_DIR_OUTBOUND	2

/* Values for Operation Field below: */
#define	UNM_IPSEC_SA_AUTHENTICATE	1
#define	UNM_IPSEC_SA_ENDECRYPT		2

/* COnfidential Algorithm Types: */
#define	UNM_IPSEC_CONF_NONE			0    // NULL encryption?
#define	UNM_IPSEC_CONF_DES			1
#define	UNM_IPSEC_CONF_RESERVED		2
#define	UNM_IPSEC_CONF_3DES			3

/* Integrity algorithm (AH) types: */
#define	UNM_IPSEC_INTEG_NONE	0
#define	UNM_IPSEC_INTEG_MD5		1
#define	UNM_IPSEC_INTEG_SHA1	2

#define	UNM_PROTOCOL_OFFSET		0x9    // from ip header begin, in bytes
#define	UNM_PKT_TYPE_AH			0x33
#define	UNM_PKT_TYPE_ESP		0x32


/* 96 bits of output for MD5/SHA1 algorithms */
#define	UNM_AHOUTPUT_LENGTH		12
/*
 * 8 bytes (64 bits) of ICV value for each block of DES_CBC
 * at the begin of ESP payload
 */
#define	UNM_DES_ICV_LENGTH		8

#if UNM_CONF_PROCESSOR == UNM_CONF_X86

typedef struct PREALIGN(512) s_ipsec_sa {
	U32	SrcAddr;
	U32	SrcMask;
	U32	DestAddr;
	U32	DestMask;
	U32	Protocol:8,
		DirFlag:4,
		IntegCtxInit:2,
		ConfCtxInit:2,
		No_of_keys:8,
		Operation:8;
	U32	IntegAlg:8,
		IntegKeyLen:8,
		ConfAlg:8,
		ConfAlgKeyLen:8;
	U32	SAIndex;
	U32	SPI_Id;
	U64	Key1[124];
} POSTALIGN(512) unm_ipsec_sa_t;

#else

typedef struct PREALIGN(512) s_ipsec_sa {
	unm_halfmsgword_t	SrcAddr;
	unm_halfmsgword_t	SrcMask;
	unm_halfmsgword_t	DestAddr;
	unm_halfmsgword_t	DestMask;
	unm_halfmsgword_t	Protocol:8,
						DirFlag:4,
						IntegCtxInit:2,
						ConfCtxInit:2,
						No_of_keys:8,
						Operation:8;
	unm_halfmsgword_t	IntegAlg:8,
						IntegKeyLen:8,
						ConfAlg:8,
						ConfAlgKeyLen:8;
	unm_halfmsgword_t	SAIndex:32;
	unm_halfmsgword_t	SPI_Id:32;
	/* to round up to 1K of structure */
	unm_msgword_t		Key1[124];
} POSTALIGN(512) unm_ipsec_sa_t;

#endif /* NOT-X86 */

/* Other common header formats that may be needed */

typedef struct _unm_ip_header_s {
	U32	HdrVer:8,
		diffser:8,
		TotalLength:16;
	U32	ipId:16,
		flagfrag:16;
	U32	TTL:8,
		Protocol:8,
		Chksum:16;
	U32	srcaddr;
	U32	destaddr;
} unm_ip_header_t;

typedef struct _unm_ah_header_s {
	U32	NextProto:8,
		length:8,
		reserved:16;
	U32    SPI;
	U32    seqno;
	U16    ICV;
	U16    ICV1;
	U16    ICV2;
	U16    ICV3;
	U16    ICV4;
	U16    ICV5;
} unm_ah_header_t;

typedef struct _unm_esp_hdr_s {
	U32 SPI;
	U32 seqno;
} unm_esp_hdr_t;

#endif /* UNM_IPSECOFFLOAD */

/*
 * Defines for various loop counts. These determine the behaviour of the
 * system. The classic tradeoff between latency and throughput.
 */

/*
 * MAX_DMA_LOOPCOUNT : After how many interations do we start the dma for
 * the status descriptors.
 */
#define	MAX_DMA_LOOPCOUNT    (32)

/*
 * MAX_TX_DMA_LOOP_COUNT : After how many interations do we start the dma for
 * the command descriptors.
 */
#define	MAX_TX_DMA_LOOP_COUNT    1000

/*
 * MAX_RCV_BUFS : Max number Rx packets that can be buffered before DMA/INT
 */
#define	MAX_RCV_BUFS	(4096)

/*
 * XXX;shouldnt be exposed in nic_cmn.h
 * DMA_MAX_RCV_BUFS : Max number Rx packets that can be buffered before DMA
 */
#define	DMA_MAX_RCV_BUFS	(4096)

/*
 * XXX;shouldnt be exposed in nic_cmn.h
 * MAX_DMA_ENTRIES : Max number Rx dma entries can be in dma list
 */
#define	MAX_DMA_ENTRIES		(4096)


/*
 * MAX_INTR_LOOPCOUNT : After how many iterations do we interrupt the
 * host ?
 */
#define	MAX_INTR_LOOPCOUNT		(1024)

/*
 * XMIT_LOOP_THRESHOLD : How many times do we spin before we process the
 * transmit buffers.
 */
#define	XMIT_LOOP_THRESHOLD		0x20

/*
 * XMIT_DESC_THRESHOLD : How many descriptors pending before we process
 * the descriptors.
 */
#define	XMIT_DESC_THRESHOLD		0x4

/*
 * TX_DMA_THRESHOLD : When do we start the dma of the command descriptors.
 * We need these number of command descriptors, or we need to exceed the
 * loop count.   P1 only.
 */
#define	TX_DMA_THRESHOLD		16

#if defined(UNM_IP_FILTER)
/*
 * Commands. Must match the definitions in nic/Linux/include/unm_nic_ioctl.h
 */
enum {
	UNM_IP_FILTER_CLEAR = 1,
	UNM_IP_FILTER_ADD,
	UNM_IP_FILTER_DEL,
	UNM_IP_FILTER_SHOW
};

#define	MAX_FILTER_ENTRIES		16

typedef struct {
	__int32_t count;
	__uint32_t ip_addr[15];
} unm_ip_filter_t;
#endif /* UNM_IP_FILTER */

enum {
	UNM_RCV_PEG_0 = 0,
	UNM_RCV_PEG_1
};

#ifdef __cplusplus
}
#endif

#endif /* !_UNM_NIC_CMN_H_ */
