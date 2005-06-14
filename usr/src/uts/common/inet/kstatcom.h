/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_KSTATCOM_H
#define	_INET_KSTATCOM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/kstat.h>



typedef struct ip_named_kstat {
	kstat_named_t forwarding;
	kstat_named_t defaultTTL;
	kstat_named_t inReceives;
	kstat_named_t inHdrErrors;
	kstat_named_t inAddrErrors;
	kstat_named_t forwDatagrams;
	kstat_named_t inUnknownProtos;
	kstat_named_t inDiscards;
	kstat_named_t inDelivers;
	kstat_named_t outRequests;
	kstat_named_t outDiscards;
	kstat_named_t outNoRoutes;
	kstat_named_t reasmTimeout;
	kstat_named_t reasmReqds;
	kstat_named_t reasmOKs;
	kstat_named_t reasmFails;
	kstat_named_t fragOKs;
	kstat_named_t fragFails;
	kstat_named_t fragCreates;
	kstat_named_t addrEntrySize;
	kstat_named_t routeEntrySize;
	kstat_named_t netToMediaEntrySize;
	kstat_named_t routingDiscards;
	kstat_named_t inErrs;
	kstat_named_t noPorts;
	kstat_named_t inCksumErrs;
	kstat_named_t reasmDuplicates;
	kstat_named_t reasmPartDups;
	kstat_named_t forwProhibits;
	kstat_named_t udpInCksumErrs;
	kstat_named_t udpInOverflows;
	kstat_named_t rawipInOverflows;
	kstat_named_t ipsecInSucceeded;
	kstat_named_t ipsecInFailed;
	kstat_named_t memberEntrySize;
	kstat_named_t inIPv6;
	kstat_named_t outIPv6;
	kstat_named_t outSwitchIPv6;
} ip_named_kstat_t;


typedef struct ipv6IfStatsEntry_named_kstat {
	kstat_named_t ifIndex;
	kstat_named_t forwarding;
	kstat_named_t defaultHopLimit;
	kstat_named_t ifStatsEntrySize;
	kstat_named_t addrEntrySize;
	kstat_named_t routeEntrySize;
	kstat_named_t netToMediaEntrySize;
	kstat_named_t memberEntrySize;
	kstat_named_t inReceives;
	kstat_named_t inHdrErrors;
	kstat_named_t inTooBigErrors;
	kstat_named_t InUnknownProtos;
	kstat_named_t inTruncatedPkts;
	kstat_named_t inDisards;
	kstat_named_t inDelivers;
	kstat_named_t outForwDatagrams;
	kstat_named_t outRequests;
	kstat_named_t outDiscards;
	kstat_named_t outFragOKs;
	kstat_named_t outFragFails;
	kstat_named_t outFragCreates;
	kstat_named_t reasmReqds;
	kstat_named_t reasmOKs;
	kstat_named_t reasmFails;
	kstat_named_t inMcastPkts;
	kstat_named_t outMcastPkts;
	kstat_named_t outNoRoutes;
	kstat_named_t reasmDuplicates;
	kstat_named_t reasmPartDups;
	kstat_named_t forwProhibits;
	kstat_named_t inChksumerrs;
	kstat_named_t inOverflows;
} ipv6IfStatsEntry_named_kstat_t;


typedef struct ipAddrEntry_named_kstat {
	kstat_named_t addr;
	kstat_named_t ifIndex;
	kstat_named_t netMask;
	kstat_named_t bcastAddr;
	kstat_named_t reasmMaxSize;
	kstat_named_t mtu;
	kstat_named_t metric;
	kstat_named_t broadcast_addr;
	kstat_named_t pp_dst_addr;
	kstat_named_t flags;
	kstat_named_t ibcnt;
	kstat_named_t obcnt;
	kstat_named_t focnt;
	kstat_named_t subnet;
	kstat_named_t subnet_len;
	kstat_named_t src_addr;
} ipAddrEntry_named_kstat_t;


typedef struct ipv6AddrEntry_named_kstat {
	kstat_named_t ifIndex;
	kstat_named_t address;
	kstat_named_t pfxLength;
	kstat_named_t type;
	kstat_named_t anycastFlag;
	kstat_named_t status;
	kstat_named_t mtu;
	kstat_named_t metric;
	kstat_named_t pp_dst_addr;
	kstat_named_t flags;
	kstat_named_t ibcnt;
	kstat_named_t obcnt;
	kstat_named_t focnt;
	kstat_named_t subnet;
	kstat_named_t subnet_len;
	kstat_named_t src_addr;
} ipv6AddrEntry_named_kstat_t;


typedef struct ipRouteEntry_named_kstat {
	kstat_named_t dest;
	kstat_named_t ifIndex;
	kstat_named_t metric1;
	kstat_named_t metric2;
	kstat_named_t metric3;
	kstat_named_t metric4;
	kstat_named_t nextHop;
	kstat_named_t type;
	kstat_named_t proto;
	kstat_named_t age;
	kstat_named_t mask;
	kstat_named_t metric5;
	kstat_named_t max_frag;
	kstat_named_t rtt;
	kstat_named_t ref;
	kstat_named_t frag_flag;
	kstat_named_t src_addr;
	kstat_named_t ire_type;
	kstat_named_t obppkt;
	kstat_named_t ibpkt;
	kstat_named_t flags;
	kstat_named_t in_ill;
	kstat_named_t in_src_addr;
} ipRouteEntry_named_kstat_t;


typedef struct ipv6RouteEntry_named_kstat {
	kstat_named_t dest;
	kstat_named_t pfxLength;
	kstat_named_t index;
	kstat_named_t ifIndex;
	kstat_named_t nextHop;
	kstat_named_t type;
	kstat_named_t protocol;
	kstat_named_t policy;
	kstat_named_t age;
	kstat_named_t nextHopRDI;
	kstat_named_t metric;
	kstat_named_t weight;
	kstat_named_t max_frag;
	kstat_named_t rtt;
	kstat_named_t ref;
	kstat_named_t frag_flag;
	kstat_named_t src_addr;
	kstat_named_t ire_type;
	kstat_named_t obpkt;
	kstat_named_t ibpkt;
	kstat_named_t flags;
} ipv6RouteEntry_named_kstat_t;


typedef struct ipNextToMediaEntry_named_kstat {
	kstat_named_t ifIndex;
	kstat_named_t physAddress;
	kstat_named_t netAddress;
	kstat_named_t type;
	kstat_named_t mask;
	kstat_named_t flags;
} ipNextToMediaEntry_named_kstat_t;

typedef struct ipv6NextToMediaEntry_named_kstat {
	kstat_named_t ifIndex;
	kstat_named_t netAddress;
	kstat_named_t physAddress;
	kstat_named_t type;
	kstat_named_t state;
	kstat_named_t lastUpdated;
} ipv6NextToMediaEntry_named_kstat_t;

typedef struct icmp_named_kstat {
	kstat_named_t inMsgs;
	kstat_named_t inErrors;
	kstat_named_t inDestUnreachs;
	kstat_named_t inTimeExcds;
	kstat_named_t inParmProbs;
	kstat_named_t inSrcQuenchs;
	kstat_named_t inRedirects;
	kstat_named_t inEchos;
	kstat_named_t inEchoReps;
	kstat_named_t inTimestamps;
	kstat_named_t inTimestampReps;
	kstat_named_t inAddrMasks;
	kstat_named_t inAddrMaskReps;
	kstat_named_t outMsgs;
	kstat_named_t outErrors;
	kstat_named_t outDestUnreachs;
	kstat_named_t outTimeExcds;
	kstat_named_t outParmProbs;
	kstat_named_t outSrcQuenchs;
	kstat_named_t outRedirects;
	kstat_named_t outEchos;
	kstat_named_t outEchoReps;
	kstat_named_t outTimestamps;
	kstat_named_t outTimestampReps;
	kstat_named_t outAddrMasks;
	kstat_named_t outAddrMaskReps;
	kstat_named_t inCksumErrs;
	kstat_named_t inUnknowns;
	kstat_named_t inFragNeeded;
	kstat_named_t outFragNeeded;
	kstat_named_t outDrops;
	kstat_named_t inOverflows;
	kstat_named_t inBadRedirects;
} icmp_named_kstat_t;


typedef struct ipv6IfIcmpEntry_named_kstat {
	kstat_named_t ifIndex;
	kstat_named_t entrySize;
	kstat_named_t inMsgs;
	kstat_named_t inErrors;
	kstat_named_t inDestUnreachs;
	kstat_named_t inAdminProhibs;
	kstat_named_t inTimeExcds;
	kstat_named_t inParmProblems;
	kstat_named_t inPktTooBigs;
	kstat_named_t inEchos;
	kstat_named_t inEchoReplies;
	kstat_named_t inRouterSolicits;
	kstat_named_t inRouterAdvertisements;
	kstat_named_t inNeighborSolicits;
	kstat_named_t inNeighborAdvertisements;
	kstat_named_t inRedirects;
	kstat_named_t inGroupMembQueries;
	kstat_named_t inGroupMembResponses;
	kstat_named_t inGroupMembReductions;
	kstat_named_t outMsgs;
	kstat_named_t outErrors;
	kstat_named_t outDestUnreachs;
	kstat_named_t outAdminProhibs;
	kstat_named_t outTimeExcds;
	kstat_named_t outParmProblems;
	kstat_named_t outPktTooBigs;
	kstat_named_t outEchos;
	kstat_named_t outEchoReplies;
	kstat_named_t outRouterSolicits;
	kstat_named_t outRouterAdvertisements;
	kstat_named_t outNeighborSolicits;
	kstat_named_t outNeighborAdvertisements;
	kstat_named_t outRedirects;
	kstat_named_t outGroupMembQueries;
	kstat_named_t outGroupMembResponses;
	kstat_named_t outGroupMembReductions;
	kstat_named_t inOverflows;
	kstat_named_t badHopLimit;
	kstat_named_t inBadNeighborAdvertisemets;
	kstat_named_t inBadNeighborSolicitations;
	kstat_named_t inBadRedirects;
	kstat_named_t inGroupMembBadQueries;
	kstat_named_t inGroupMembBadReports;
	kstat_named_t inGroupMembOurReports;
} ipv6IfIcmpEntry_named_kstat_t;


typedef struct sctp_named_kstat {
	kstat_named_t	sctpRtoAlgorithm;
	kstat_named_t	sctpRtoMin;
	kstat_named_t	sctpRtoMax;
	kstat_named_t	sctpRtoInitial;
	kstat_named_t	sctpMaxAssocs;
	kstat_named_t	sctpValCookieLife;
	kstat_named_t	sctpMaxInitRetr;
	kstat_named_t	sctpCurrEstab;
	kstat_named_t	sctpActiveEstab;
	kstat_named_t	sctpPassiveEstab;
	kstat_named_t	sctpAborted;
	kstat_named_t	sctpShutdowns;
	kstat_named_t	sctpOutOfBlue;
	kstat_named_t	sctpChecksumError;
	kstat_named_t	sctpOutCtrlChunks;
	kstat_named_t	sctpOutOrderChunks;
	kstat_named_t	sctpOutUnorderChunks;
	kstat_named_t	sctpRetransChunks;
	kstat_named_t	sctpOutAck;
	kstat_named_t	sctpOutAckDelayed;
	kstat_named_t	sctpOutWinUpdate;
	kstat_named_t	sctpOutFastRetrans;
	kstat_named_t	sctpOutWinProbe;
	kstat_named_t	sctpInCtrlChunks;
	kstat_named_t	sctpInOrderChunks;
	kstat_named_t	sctpInUnorderChunks;
	kstat_named_t	sctpInAck;
	kstat_named_t	sctpInDupAck;
	kstat_named_t	sctpInAckUnsent;
	kstat_named_t	sctpFragUsrMsgs;
	kstat_named_t	sctpReasmUsrMsgs;
	kstat_named_t	sctpOutSCTPPkts;
	kstat_named_t	sctpInSCTPPkts;
	kstat_named_t	sctpInInvalidCookie;
	kstat_named_t	sctpTimRetrans;
	kstat_named_t	sctpTimRetransDrop;
	kstat_named_t	sctpTimHeartBeatProbe;
	kstat_named_t	sctpTimHeartBeatDrop;
	kstat_named_t	sctpListenDrop;
	kstat_named_t	sctpInClosed;
} sctp_named_kstat_t;


typedef struct tcp_named_kstat {
	kstat_named_t rtoAlgorithm;
	kstat_named_t rtoMin;
	kstat_named_t rtoMax;
	kstat_named_t maxConn;
	kstat_named_t activeOpens;
	kstat_named_t passiveOpens;
	kstat_named_t attemptFails;
	kstat_named_t estabResets;
	kstat_named_t currEstab;
	kstat_named_t inSegs;
	kstat_named_t outSegs;
	kstat_named_t retransSegs;
	kstat_named_t connTableSize;
	kstat_named_t outRsts;
	kstat_named_t outDataSegs;
	kstat_named_t outDataBytes;
	kstat_named_t retransBytes;
	kstat_named_t outAck;
	kstat_named_t outAckDelayed;
	kstat_named_t outUrg;
	kstat_named_t outWinUpdate;
	kstat_named_t outWinProbe;
	kstat_named_t outControl;
	kstat_named_t outFastRetrans;
	kstat_named_t inAckSegs;
	kstat_named_t inAckBytes;
	kstat_named_t inDupAck;
	kstat_named_t inAckUnsent;
	kstat_named_t inDataInorderSegs;
	kstat_named_t inDataInorderBytes;
	kstat_named_t inDataUnorderSegs;
	kstat_named_t inDataUnorderBytes;
	kstat_named_t inDataDupSegs;
	kstat_named_t inDataDupBytes;
	kstat_named_t inDataPartDupSegs;
	kstat_named_t inDataPartDupBytes;
	kstat_named_t inDataPastWinSegs;
	kstat_named_t inDataPastWinBytes;
	kstat_named_t inWinProbe;
	kstat_named_t inWinUpdate;
	kstat_named_t inClosed;
	kstat_named_t rttNoUpdate;
	kstat_named_t rttUpdate;
	kstat_named_t timRetrans;
	kstat_named_t timRetransDrop;
	kstat_named_t timKeepalive;
	kstat_named_t timKeepaliveProbe;
	kstat_named_t timKeepaliveDrop;
	kstat_named_t listenDrop;
	kstat_named_t listenDropQ0;
	kstat_named_t halfOpenDrop;
	kstat_named_t outSackRetransSegs;
	kstat_named_t connTableSize6;
} tcp_named_kstat_t;

typedef struct tcpConnEntry_named_kstat { /* IPv4 and IPv6 unified */
	kstat_named_t state;
	kstat_named_t localAddress;
	kstat_named_t localPort;
	kstat_named_t remAddress;
	kstat_named_t remPort;
	kstat_named_t snxt;
	kstat_named_t suna;
	kstat_named_t swnd;
	kstat_named_t rnxt;
	kstat_named_t rack;
	kstat_named_t rwnd;
	kstat_named_t rto;
	kstat_named_t mss;
	kstat_named_t internalState;
	kstat_named_t ifIndex;
	kstat_named_t version;
	kstat_named_t pid;
} tcpConnEntry_named_kstat_t;

typedef struct udp_named_kstat {
	kstat_named_t inDatagrams;
	kstat_named_t inErrors;
	kstat_named_t outDatagrams;
	kstat_named_t entrySize;
	kstat_named_t entry6Size;
	kstat_named_t outErrors;
} udp_named_kstat_t;

typedef struct udpEntry_named_kstat {
	kstat_named_t localAddress;
	kstat_named_t localPort;
	kstat_named_t state;
	kstat_named_t remoteAddress;
	kstat_named_t remotePort;
} udpEntry_named_kstat_t;


typedef struct udp6Entry_named_kstat {
	kstat_named_t localAddress;
	kstat_named_t localPort;
	kstat_named_t ifIndex;
	kstat_named_t state;
	kstat_named_t remoteAddress;
	kstat_named_t remotePort;
} udp6Entry_named_kstat_t;


typedef struct rawip_named_kstat {
	kstat_named_t inDatagrams;
	kstat_named_t inCksumErrs;
	kstat_named_t inErrors;
	kstat_named_t outDatagrams;
	kstat_named_t outErrors;
} rawip_named_kstat_t;


#define	NUM_OF_FIELDS(S)	(sizeof (S) / sizeof (kstat_named_t))

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_KSTATCOM_H */
