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
 * upt1_defs.h
 *
 *      Definitions for UPTv1
 *
 *      Some of the defs are duplicated in vmkapi_net_upt.h, because
 *      vmkapi_net_upt.h cannot distribute with OSS yet and vmkapi headers can
 *      only include vmkapi headers. Make sure they are kept in sync!
 */

#ifndef _UPT1_DEFS_H_
#define	_UPT1_DEFS_H_

#define	UPT1_MAX_TX_QUEUES	64
#define	UPT1_MAX_RX_QUEUES	64

#define	UPT1_MAX_INTRS (UPT1_MAX_TX_QUEUES + UPT1_MAX_RX_QUEUES)

#pragma pack(1)
typedef struct UPT1_TxStats {
	uint64_t	TSOPktsTxOK;  /* TSO pkts post-segmentation */
	uint64_t	TSOBytesTxOK;
	uint64_t	ucastPktsTxOK;
	uint64_t	ucastBytesTxOK;
	uint64_t	mcastPktsTxOK;
	uint64_t	mcastBytesTxOK;
	uint64_t	bcastPktsTxOK;
	uint64_t	bcastBytesTxOK;
	uint64_t	pktsTxError;
	uint64_t	pktsTxDiscard;
} UPT1_TxStats;
#pragma pack()

#pragma pack(1)
typedef struct UPT1_RxStats {
	uint64_t	LROPktsRxOK;	/* LRO pkts */
	uint64_t	LROBytesRxOK;	/* bytes from LRO pkts */
	/* the following counters are for pkts from the wire, i.e., pre-LRO */
	uint64_t	ucastPktsRxOK;
	uint64_t	ucastBytesRxOK;
	uint64_t	mcastPktsRxOK;
	uint64_t	mcastBytesRxOK;
	uint64_t	bcastPktsRxOK;
	uint64_t	bcastBytesRxOK;
	uint64_t	pktsRxOutOfBuf;
	uint64_t	pktsRxError;
} UPT1_RxStats;
#pragma pack()

/* interrupt moderation level */
#define	UPT1_IML_NONE		0 /* no interrupt moderation */
#define	UPT1_IML_HIGHEST	7 /* least intr generated */
#define	UPT1_IML_ADAPTIVE	8 /* adpative intr moderation */

/* values for UPT1_RSSConf.hashFunc */
#define	UPT1_RSS_HASH_TYPE_NONE		0x0
#define	UPT1_RSS_HASH_TYPE_IPV4		0x01
#define	UPT1_RSS_HASH_TYPE_TCP_IPV4	0x02
#define	UPT1_RSS_HASH_TYPE_IPV6		0x04
#define	UPT1_RSS_HASH_TYPE_TCP_IPV6	0x08

#define	UPT1_RSS_HASH_FUNC_NONE		0x0
#define	UPT1_RSS_HASH_FUNC_TOEPLITZ	0x01

#define	UPT1_RSS_MAX_KEY_SIZE		40
#define	UPT1_RSS_MAX_IND_TABLE_SIZE	128

#pragma pack(1)
typedef struct UPT1_RSSConf {
	uint16_t	hashType;
	uint16_t	hashFunc;
	uint16_t	hashKeySize;
	uint16_t	indTableSize;
	uint8_t		hashKey[UPT1_RSS_MAX_KEY_SIZE];
	uint8_t		indTable[UPT1_RSS_MAX_IND_TABLE_SIZE];
} UPT1_RSSConf;
#pragma pack()

/* features */
#define	UPT1_F_RXCSUM	0x0001	/* rx csum verification */
#define	UPT1_F_RSS	0x0002
#define	UPT1_F_RXVLAN	0x0004	/* VLAN tag stripping */
#define	UPT1_F_LRO	0x0008

#endif	/* _UPT1_DEFS_H_ */
