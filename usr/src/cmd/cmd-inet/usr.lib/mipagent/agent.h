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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AGENT_H
#define	_AGENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions for structures used by
 * Mobility Agents (either Home Agents or Foreign Agents)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <synch.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include "mip.h"
#include "hash.h"
#include "aaa.h"

/* Hash types */
#define	HASH_IT				0
#define	MD5_HASH			1

#define	MAX_FN_LEN			256

#define	VERSION_MAJOR			1
#define	VERSION_MINOR			0


/*
 * We do not current support simultaneous bindings
 * due to the new tunnel driver architecture. This
 * is something that we may wish to change in the
 * future.
 */

#define	MAX_SIMULTANEOUS_BINDINGS	7
#define	DEFAULT_MAX_REG_TIME		300
#define	DEFAULT_MAX_ADV_TIME		300
#define	DEFAULT_MAX_INTERVAL		10
#define	DEFAULT_MIN_INTERVAL		1

#define	ADV_INIT_COUNT_DEFAULT		1
#define	ADV_INIT_COUNT_MIN		0
#define	DEFAULT_FRESHNESS_SLACK		300

#define	DEFAULT_ADVERTISEMENT_INTERVAL	5

#define	MIP_PORT			434

/*
 * These are for the IPsec flags in the MobilityAgentEntry.
 */
#define	IPSEC_REQUEST		0x01
#define	IPSEC_REPLY		0x02
#define	IPSEC_TUNNEL		0x04
#define	IPSEC_REVERSE_TUNNEL	0x08

#define	APPLY(x)	(x)
#define	PERMIT(x)	((x) << 4)

/*
 * We define the other way so we can have indexes into validIPsecAction[],
 * and the maIPsec*'s in the MobilityAgentEntry struct, too.
 */
#define	FIRST_IPSEC_ACTION	0
#define	IPSEC_APPLY	0
#define	IPSEC_PERMIT	1
#define	LAST_IPSEC_ACTION	2

#define	REQUEST(a)		(1 << (((int)(a)) * 4))
#define	REPLY(a)		(1 << ((((int)(a)) * 4) + 1))
#define	TUNNEL(a)		(1 << ((((int)(a)) * 4) + 2))
#define	REVERSE_TUNNEL(a)	(1 << ((((int)(a)) * 4) + 3))

/*
 * The above pair of 6 macros yield the following:
 *
 * bit 1 -> APPLY(IPSEC_REQUEST)         = IPSEC_REQUEST_APPLY
 * bit 2 -> APPLY(IPSEC_REPLY)           = IPSEC_REPLY_APPLY
 * bit 3 -> APPLY(IPSEC_TUNNEL)          = IPSEC_TUNNEL_APPLY
 * bit 4 -> APPLY(IPSEC_REVERSE_TUNNEL)  = IPSEC_REVERSE_TUNNEL_APPLY
 * bit 5 -> PERMIT(IPESC_REQUEST)        = IPSEC_REQUEST_PERMIT
 * bit 6 -> PERMIT(IPSEC_REPLY)          = IPSEC_REPLY_PERMIT
 * bit 7 -> PERMIT(IPSEC_TUNNEL)         = IPSEC_TUNNEL_PERMIT
 * bit 8 -> PERMIT(IPSEC_REVERSE_TUNNEL) = IPSEC_REVERSE_TUNNEL_PERMIT
 */
#define	IPSEC_REQUEST_APPLY			0x01
#define	IPSEC_REPLY_APPLY			0x02
#define	IPSEC_TUNNEL_APPLY			0x04
#define	IPSEC_REVERSE_TUNNEL_APPLY		0x08
#define	IPSEC_REQUEST_PERMIT			0x10
#define	IPSEC_REPLY_PERMIT			0x20
#define	IPSEC_TUNNEL_PERMIT			0x40
#define	IPSEC_REVERSE_TUNNEL_PERMIT		0x80

/*
 * Bitmasks for the maIPsecSAFlags[] members of the MobilityAgentEntry struct
 * that we pass to mipagentstat.  As the HA_PEER we use request-permit,
 * reply-apply, tunnel-apply, and reverse-tunnel permit.  This means we have to
 * mask-in reply and tunnel from maIPsecSAFlags[IPSEC_APPLY], and request and
 * reverse tunnel from maIPsecSAFlags[IPSEC_PERMIT].  As an FA_PEER we use
 * request-apply, reply-permit, tunnel-permit, and reverse-tunnel-apply.  This
 * means we have to mask-in request and reverse-tunnel from
 * maIPsecSAFlags[IPSEC_APPLY], and reply and tunnel from
 * maIsecSAFlags[IPSEC_PERMIT].
 */
							/* type: RQRPFTRT */
							/*  SA : AEAEAEAE */
#define	HA_PEER_APPLY_MASK	(IPSEC_REPLY_BOTH | IPSEC_TUNNEL_BOTH)
							/* 0x3c, 00111100b */
#define	FA_PEER_APPLY_MASK	(IPSEC_REQUEST_BOTH | IPSEC_REVERSE_TUNNEL_BOTH)
							/* 0xc3, 11000011b */
#define	HA_PEER_PERMIT_MASK	(IPSEC_REQUEST_BOTH | IPSEC_REVERSE_TUNNEL_BOTH)
							/* 0xc3, 11000011b */
#define	FA_PEER_PERMIT_MASK	(IPSEC_REPLY_BOTH | IPSEC_TUNNEL_BOTH)
							/* 0x3c, 00111100b */

#define	IPSEC_ORDER		2	/* Arrays are 2-by: apply and permit */
#define	MAX_IPSEC_GET_SIZE	1024	/* read()/write() via PF_KEY socket */
#define	FINE_STRUCT_CONST	137	/* Our initial ipsec sequence number */
#define	MAX_IPSEC_POLICY_SIZE	1024    /* Same as MAXLEN in ipsecconf.h */

/* Commands for ipsecconf are "/usr/sbin/ipsecconf -(a|r) /dev/stdin -q" */
#define	IPSEC_CONF_COMMAND_SIZE	37

#define	IPv4_ADDR_LEN	16		/* in dotted-decimal */
#define	CONF_FILE_NAME			"/etc/inet/mipagent.conf"

/* easy flag to index algorithm (warning: use on flags only!) */
#define	IPSEC_POLICY_STRING(x) ipsec_policy_string[ffs(x) - 1]

/* developer-friendly add/remove policy strings */
#define	ADD_POLICY	0
#define	SUB_POLICY	1
#define	IPSEC(x)	ipsec_policy_action[x]


/*
 * Maximum number of visitor entries (accepted + pending) maintained
 * at a Foreign Agent. A foreign agent sets the busy bit 'B' in its
 * advertisements when number of visitors reaches DEFAULT_HIGH_VISITORS
 * and does not reset it till it drops below DEFAULT_LOW_VISITORS.
 * A pending entry is kept in the visitor table for at most
 * DEFAULT_VISITOR_EXPIRY seconds.
 *
 * The new solaris Mobile-IP does not have any such restrictions,
 * therefore we will set the visitor entry threshold to some ungodly
 * large number, which can be overriden by the administrator.
 */
#define	DEFAULT_HIGH_VISITORS		-1
#define	DEFAULT_LOW_VISITORS		-5
#define	DEFAULT_VISITOR_EXPIRY		30

#ifdef FIREWALL_SUPPORT
/* Max number of address intervals for specifying protected domain */
#define	MAX_ADDR_INTERVALS		6

/* Max. number of firewalls */
#define	MAX_FIREWALLS			3
#endif /* FIREWALL_SUPPORT */

#define	MAX_IFNAME_LEN			8
#define	MAX_HWADDR_LEN			sizeof (struct ether_addr)

#define	MAX_TIME_STRING_SIZE		32

/*
 * The following bits are set depending on the value of 'ReverseTunnelAllowed
 * and ReverseTunnelRequired' parameter in the mipagent.conf file. By default
 * the value for each is RT_NONE. It's a policy set by the configuration file
 * to check if Reverse Tunnel bit must be present or NOT in the registration
 * request. For example a FA may only accept registration packet with 'T' bit
 * on while the HA accepts regReq with or without T bit on.  These are for
 * reverse tunnel settings.  We advertise the T-bit on a per-interface level,
 * so discern only on a per-interface, and not a per-agent-per-interface level
 * (e.g. advertise the 'T' bit, but only enforce reverse-tunnel-required on
 * the HA).  These will allow us to do that.
 */
#define	RT_NONE	0x0
#define	RT_HA	0x1
#define	RT_FA	0x2
#define	RT_BOTH	0x3

/*
 * The following are the minimum and maximum values
 * that one can configure for garbage collection. Note
 * that this feature is largely undocumented, and can be
 * used to alter the frequency that the agent attempts to
 * clean up expired data structures.
 */
#define	MIN_GARBAGE_COLLECTION_INTERVAL		5
#define	MAX_GARBAGE_COLLECTION_INTERVAL		120
#define	DEFAULT_GARBAGE_COLLECTION_INTERVAL	15

#define	UNSOLICITED_ADV		1
#define	SOLICITED_ADV		2


/* One such entry for each mobility-supporting interface */
typedef struct {
	/*
	 * The nodeLock field MUST be the first field present in
	 * this structure, and is required by the hashing mobule.
	 */
	rwlock_t	maIfaceNodeLock;
	ipaddr_t	maIfaceAddr;
	uint32_t	maIfaceNetmask;
	uint8_t		maIfaceHWaddr[MAX_HWADDR_LEN]; /* used in proxy-ARPs */
	int8_t		maIfaceName[LIFNAMSIZ];
	uint64_t	maIfaceFlags;	/* interface flags */
	int		maIfaceIcmpSock; /* ICMP socket bound to ifaceAddr */
	int		maIfaceUnicastSock; /* UDP socket bound to IfaceAddr */
	int		maIfaceBcastSock;   /* ... bound to subnet bcastAddr */
	int		maIfaceDirBcastSock; /* ... to directed bcast Addr */
	int		maIfaceAdvMulticastSock; /* ... bound to mcastAddr */
	int		maIfaceRegMulticastSock; /* ... bound to mcastAddr */
	uint32_t	maAdvMaxRegLifetime;
	uint32_t	maAdvAddr;
	uint32_t	maAdvMaxInterval;
	uint32_t	maAdvMinInterval;
	uint32_t	maAdvMaxAdvLifetime;
	/*  boolean	maAdvResponseSolicitationOnly; */
	unsigned short	maAdvSeqNum;
	uint8_t		maAdvServiceFlags;  /* RBHFM[GV]T flags */
	boolean_t	maAdvPrefixLenInclusion;
	uint8_t		maReverseTunnelAllowed;
	uint8_t		maReverseTunnelRequired;
	/* dynamic interface support */
	boolean_t	maAdvDynamicInterface;   /* Used in lookup */
	boolean_t	maAdvLimitUnsolicited;
	uint8_t		maAdvInitCount;	/* Initial Count when */
					/* maAdvLimitUnsolicited is true */
	uint32_t	maAdvInterval;
	time_t		maNextAdvTime;
	uint32_t	maIfindex;	/* Interface index */
} MaAdvConfigEntry;

/*
 * Mobile tunnel specific data
 */
typedef struct {
	rwlock_t	TunlNodeLock;
	uint32_t	tunnelno;
	uint32_t	refcnt;
	ipaddr_t	tunnelsrc;		/* Tunnel source end-point */
	uint32_t	mux_fd;			/* fd associated with tun */
} MipTunlEntry;

/* One entry for each visiting mobile node at a foreign agent. */
typedef struct {
	/*
	 * The nodeLock field MUST be the first field present in
	 * this structure, and is required by the hashing mobule.
	 */
	rwlock_t	faVisitorNodeLock;
	ipaddr_t	faVisitorAddr;
	ipaddr_t	faVisitorIfaceAddr;	/* interface addr through */
						/* which visitor is reachable */
	boolean_t	faVisitorRegIsAccepted;
	int8_t		faVisitorRegFlags;
	in_port_t	faVisitorPort;
	ipaddr_t	faVisitorHomeAddr;
	ipaddr_t	faVisitorHomeAgentAddr;
	ipaddr_t	faVisitorCOAddr;	/* COaddr field in request */
	time_t		faVisitorTimeGranted;	/* only valid if IsAccepted */
	time_t		faVisitorTimeExpires;	/* only valid if IsAccepted */
	uint32_t	faVisitorSPI;
	uint32_t	faVisitorRegIDHigh;
	uint32_t	faVisitorRegIDLow;
	uint8_t		faVisitorMnNAI[MAX_NAI_LENGTH];	/* Mobile Node's NAI */
	uint32_t	faVisitorMnNAILen;
	uint8_t		faVisitorChallengeToHA[ADV_CHALLENGE_LENGTH];
	uint32_t	faVisitorChallengeToHALen;
	uint8_t		faVisitorChallengeAdv[ADV_CHALLENGE_LENGTH];
	uint32_t	faVisitorChallengeAdvLen;
	uint32_t	faVisitorInIfindex;	/* interface index on which */
						/* reg. request is recvd */
	boolean_t	faVisitorIsSllaValid;	/* if the MN's SLLA is legit */
	struct	sockaddr_dl	faVisitorSlla;	/* MN's link layer address */
} FaVisitorEntry;


/*
 * The Home Agent maintains one such entry for each mobility binding.
 * A single mobile node may have multiple bindings.
 */
typedef struct habindingentry {
	ipaddr_t	haBindingMN;	/* Mobile node's home address */
	ipaddr_t	haBindingCOA;	/* Mobile node's care-of address */
	ipaddr_t	haBindingSrcAddr;
	ipaddr_t	haBindingHaAddr;	/* Home Agent address */
	time_t		haBindingTimeGranted;
	time_t		haBindingTimeExpires;
	in_port_t	haBindingSrcPort;
	int8_t		haBindingRegFlags; /* 8 bit - comes from the wire */
	struct habindingentry	*next;		/* Next structure */
} HaBindingEntry;

/*
 * The Home Agent maintains one mobile node entry for each supported Mobile
 * Node. In addition, the Home Agent keeps a MipSecAssocEntry for
 * for every other node with which it shares a mobility security
 * association. By using the interface information, the home agent
 * can filter out broadcast packets that it picks up from subnets
 * other than the mobile node's home subnet.
 */
typedef struct {
	/*
	 * The nodeLock field MUST be the first field present in
	 * this structure, and is required by the hashing mobule.
	 */
	rwlock_t	    haMnNodeLock;
	boolean_t	    haMnIsEntryDynamic;
	ipaddr_t	    haMnAddr;		/* Mobile Node's IP address */
	uint8_t		    haMnNAI[MAX_NAI_LENGTH]; /* Mobile Node NAI */
	uint8_t		    haMnNAILen;		/* Mobile Node NAI Len */
	ipaddr_t	    haBindingIfaceAddr;	/* interface on the mobile */
						/* node's home subnet */
	uint32_t	    haMnRegIDHigh;	/* Stored ID used in replay */
						/* protection */
	uint32_t	    haMnRegIDLow;
	uint32_t	    haMnSPI;
	int		    haMnBindingCnt;    /* Number of current bindings */
#ifdef RADIUS_ENABLED
	char		    *haRadiusState;    /* maintains radius state info */
	time_t		    haRadiusLastLookupTime;
#endif /* RADIUS_ENABLED */
	uint32_t	    haServiceRequestsAcceptedCnt; /* The number of */
						/* successful registrations */
	uint32_t	    haServiceRequestsDeniedCnt; /* The number of */
						/* failed registrations */
	time_t		    haOverallServiceTime; /* The total amount of */
							/*  service time */
	time_t		    haRecentServiceAcceptedTime; /* The last time */
						/* service was provided */
	time_t		    haRecentServiceDeniedTime; /* The last time */
						/* service was denied */
	uint32_t	    haRecentServiceDeniedCode; /* The last failure */
						/* code */
	uint32_t	    haPoolIdentifier;
	HaBindingEntry	    *bindingEntries;
} HaMobileNodeEntry;


/*
 * Mobility Agent Authentication Information.
 */
typedef struct {
	/*
	 * The nodeLock field MUST be the first field present in
	 * this structure, and is required by the hashing mobule.
	 */
	rwlock_t		maNodeLock;
	boolean_t		maIsEntryDynamic;
	ipaddr_t		maAddr;
	uint32_t		maSPI;
	/*
	 * The following value is used during garbage collection to check
	 * if this Mobility Agent has expired.
	 */
	time_t			maExpiration;

	/*
	 * How is IPsec securing traffic to this agent-peer?  Ultimately, all
	 * we should need are the ipsec_req_t structs here, but that wont
	 * happen until either ipsec has an API, or they support multiple
	 * policies per socket.  Until then, we need the char strings to pass
	 * to ipsecconf(1M).  We do use the ipsec_req_t structs for our tunnel
	 * setup, but not at this time for the registration traffic.  Still,
	 * this is setup at init time, so why not parse everything in
	 * anticipation of ipsec support.  Note, also, until ipsec supports
	 * multiple policies per socket, we can only support symmetric tunnel
	 * polices (forward tunnel policy = reverse tunnel policy).  IPSEC_ORDER
	 * here refers to the 'depth' of ipsec protection, that is how many
	 * different actions do we support.  This is done this way for
	 * expandability.
	 */
	ipsec_req_t	maIPsecRequestIPSR[IPSEC_ORDER];
	ipsec_req_t	maIPsecReplyIPSR[IPSEC_ORDER];
	ipsec_req_t	maIPsecTunnelIPSR[IPSEC_ORDER];
	ipsec_req_t	maIPsecReverseTunnelIPSR[IPSEC_ORDER];
	uint8_t		maIPsecFlags; /* what's currently invoked */
	uint8_t		maPeerFlags;  /* 2 for IPsec: ha and fa.  Rest TBD */

	/*
	 * The SA flags are arranged like this:
	 *
	 *  Request  Reply  Tunnel  RTunnel
	 * | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
	 *  AH  ESP AH  ESP AH  ESP AH  ESP
	 *
	 * So bits 0, 1 say whether AH or ESP are protecting requests, but
	 * 2, 3 say whether AH or ESP are protecting replies, etc.
	 * We need one of these SA flag fields for each of our actions.
	 * This way we know which are specific for APPLY = outbound, PERMIT =
	 * inbound, (etc, should there be more someday).
	 */
	uint8_t		maIPsecSAFlags[IPSEC_ORDER];

	/* these are the chars mentioned above that should go away */
	char	maIPsecRequest[IPSEC_ORDER][MAX_IPSEC_POLICY_SIZE];
	char	maIPsecReply[IPSEC_ORDER][MAX_IPSEC_POLICY_SIZE];
} MobilityAgentEntry;

#ifdef FIREWALL_SUPPORT
/* Data structure to store the information regarding protected domain */
typedef struct {
	ipaddr_t addr[MAX_ADDR_INTERVALS];
	uint32_t netmask[MAX_ADDR_INTERVALS];
	uint32_t addrIntervalCnt;
	uint32_t fwAddr[MAX_FIREWALLS];
	uint32_t firewallCnt;
} DomainInfo;
#endif /* FIREWALL_SUPPORT */

/*
 * Counters common to all Mobility Agents
 *
 * Note: We will not be locking this structure before modifying it,
 * even though we know that we are multi-threaded. The worst case
 * scenario is that we will return incorrect statistics to the snmp
 * requestor. The cost of locking and unlocking this structure is
 * simply not worth it.
 */
typedef struct {
	uint32_t maAdvSentCnt;
	uint32_t maAdvSentForSolicitationsCnt;
	uint32_t maSolicitationsRecvdCnt;
} CommonCounters;

/*
 * Counters maintained by Foreign Agents
 *
 * Note: We will not be locking this structure before modifying it,
 * even though we know that we are multi-threaded. The worst case
 * scenario is that we will return incorrect statistics to the snmp
 * requestor. The cost of locking and unlocking this structure is
 * simply not worth it.
 */
typedef struct {
	uint32_t faRegReqRecvdCnt;	/* total valid reg requests received */
	uint32_t faRegReqRelayedCnt;	/* total valid reg reqs relayed to HA */
	uint32_t faReasonUnspecifiedCnt;	/* rejected with code 64 */
	uint32_t faAdmProhibitedCnt;		/* rejected with code 65 */
	uint32_t faInsufficientResourceCnt;	/* rejected with code 66 */
	uint32_t faMNAuthFailureCnt;		/* rejected with code 67 */
	uint32_t faHAAuthFailureCnt;		/* rejected with code 68 */
	uint32_t faRegLifetimeTooLongCnt;	/* rejected with code 69 */
	uint32_t faPoorlyFormedRequestsCnt;	/* rejected with code 70 */
	uint32_t faPoorlyFormedRepliesCnt;	/* rejected with code 71 */
	uint32_t faEncapUnavailableCnt;		/* rejected with code 72 */
	uint32_t faVJCompUnavailableCnt;	/* rejected with code 73 */
	uint32_t faReverseTunnelUnavailableCnt;	/* rejected with code 74 */
	uint32_t faReverseTunnelRequiredCnt;	/* rejected with code 75 */
	uint32_t faMNTooDistantCnt;		/* rejected with code 76 */
	uint32_t faInvalidCareOfAddrCnt;	/* rejected with code 77 */
	uint32_t faRTEncapUnavailableCnt;	/* rejected with code 79 */
	uint32_t faHAUnreachableCnt;	/* rejected with codes 80-95 */
	uint32_t faRegRepliesRecvdCnt;	/* well-formed reg replies received */
	uint32_t faRegRepliesRelayedCnt;	/* well-formed regrep relayd */
	uint32_t faRegRepliesICMPUnreachCnt;	/* replies for ICMP_UNREACH */
	uint32_t faRegRepliesICMPTimxceedCnt;	/* replies for ICMP_TIMXCEED */
	uint32_t faIsBusyCnt;	/* number of times we were too busy */
} ForeignAgentCounters;

/*
 * Counters maintained by Home Agents
 *
 * Note: We will not be locking this structure before modifying it,
 * even though we know that we are multi-threaded. The worst case
 * scenario is that we will return incorrect statistics to the snmp
 * requestor. The cost of locking and unlocking this structure is
 * simply not worth it.
 */
typedef struct {
	uint32_t  haRegAccepted0Cnt;	/* reg requests accepted with code 0 */
	uint32_t  haRegAccepted1Cnt;	/* reg requests accepted with code 1 */
	uint32_t  haReasonUnspecifiedCnt;	/* denied with code 128 */
	uint32_t  haAdmProhibitedCnt;		/* denied with code 129 */
	uint32_t  haInsufficientResourceCnt;	/* denied with code 130 */
	uint32_t  haMNAuthFailureCnt;		/* denied with code 131 */
	uint32_t  haFAAuthFailureCnt;		/* denied with code 132 */
	uint32_t  haIDMismatchCnt;		/* denied with code 133 */
	uint32_t  haPoorlyFormedRequestsCnt;	/* denied with code 134 */
	uint32_t  haTooManyBindingsCnt;		/* denied with code 135 */
	uint32_t  haUnknownHACnt;		/* denied with code 136 */
	uint32_t  haReverseTunnelUnavailableCnt;
						/* denied with code 137 */
	uint32_t  haReverseTunnelRequiredCnt;	/* denied with code 138 */
	uint32_t  haEncapUnavailableCnt;	/* denied with code 139 */
	uint32_t  haGratuitousARPsSentCnt;
	uint32_t  haProxyARPsSentCnt;
	uint32_t  haRegReqRecvdCnt;
	uint32_t  haDeRegReqRecvdCnt;
	uint32_t  haRegRepliesSentCnt;
	uint32_t  haDeRegRepliesSentCnt;
} HomeAgentCounters;

/*
 * Mobile-IP is a simple protocol, with limited extensions. Today
 * the number of extensions in a single message cannot exceed 10.
 */
#define	MAX_EXPECTED_EXTENSIONS		16

/*
 * Mobile IP Packets are relatively small, and cannot really
 * exceed 2k in size.
 */
#define	MAX_PKT_SIZE			2048
/*  Maximum control/data buffer size (in long's) for getmsg() */
#define	MAXDLBUF	8192

typedef struct messagehdr {
	enum {
		MIP_PKT_FROM_FA = 1,
		MIP_PKT_FROM_AAA,
		MIP_PKT_FROM_RADIUS
	} pktSource;
	enum {
		PKT_UDP = 1,
		PKT_ICMP
	} pktType;
	unsigned char	pkt[MAX_PKT_SIZE];
	uint32_t	pktLen;
	ipaddr_t	src;
	in_port_t	srcPort;
	uint8_t		*mnNAI;
	unsigned int    mnNAILen;
	size_t		extCnt;
	uint8_t		extType[MAX_EXPECTED_EXTENSIONS];
	uint16_t	extSubType[MAX_EXPECTED_EXTENSIONS];
	uint8_t		*extIdx[MAX_EXPECTED_EXTENSIONS];
	uint8_t		*extData[MAX_EXPECTED_EXTENSIONS];
	size_t		extHdrLength[MAX_EXPECTED_EXTENSIONS];
	size_t		extLength[MAX_EXPECTED_EXTENSIONS];
	uint32_t	extVendorId[MAX_EXPECTED_EXTENSIONS];
	MaAdvConfigEntry *ifEntry;
	enum {
		ON_UNICAST_SOCK,
		ON_BCAST_SOCK,
		ON_MCAST_SOCK
	} ifType;
	boolean_t	dontDeleteNow;

	/*
	 * The following is some AAA Stuff, and can ONLY be set
	 * if the packet source is AAA.
	 */
	uint32_t	messageHandle;
	unsigned char  *faNAI;
	size_t		faNAILen;
	uint32_t	mnAAASPI;
	uint16_t	algorithm;
	uint32_t	mnHaSPI;
	uint8_t		mnHaKey[MAX_KEY_LEN];
	size_t		mnHaKeyLen;
	uint32_t	mnFaSPI;
	uint8_t		mnFaKey[MAX_KEY_LEN];
	size_t		mnFaKeyLen;
	uint32_t	faHaSPI;
	uint8_t		faHaKey[MAX_KEY_LEN];
	size_t		faHaKeyLen;
	uint32_t	aaaSessionTimeout;
	uint32_t	aaaResultCode;
#ifdef KEY_DISTRIBUTION
	/*
	 * KEY_DISTRIBUTION MUST ONLY BE COMPILED FOR TESTING!!!
	 *
	 * This version of mipagent supports a AAA/DIAMETER
	 * interface. The DIAMETER server generates keying
	 * material that is sent to the Home Agent. The keys
	 * sent are both for the Home Agent, and for the Mobile
	 * Node. The keys for the Mobile Nodes are added to the
	 * registration reply, and the keys for the Home Agent
	 * cause the Home Agent to create a local SA.
	 *
	 * Since DIAMETER/AAA is not currently a product, and key
	 * distribution must still be tested, we have added some
	 * test code in mipagent. When KEY_DISTRIBUTION is enabled,
	 * the home agent creates and encrypts session keys for
	 * the Mobile Node (mimicking DIAMETER), and creates local
	 * SAs. Further, since the session keys MUST also be sent
	 * to the Foreign Agent, the session keys are sent in the
	 * clear to the Foreign Agent through Vendor Specific
	 * extensions.
	 *
	 * Again, this code is for testing purpose only and must not
	 * be enabled for production code, since it hasn't been
	 * fully tested.
	 */
	boolean_t	kdcKeysPresent;
#endif /* KEY_DISTRIBUTION */

	/*
	 * Ancillary data gleaned from the registration request
	 */
	boolean_t	isSllaValid;	/* is SLLA valid/legitimate ? */
	struct	sockaddr_dl	slla;	/* source link layer address */
	uint32_t	inIfindex;	/* Inbound interface index */
	uint8_t		ttl;		/* IP TTL of inbound pkt */

	struct messagehdr	*next;
} MessageHdr;


/*
 * This entry holds the dynamic interface type and the common
 * information that will be applied to all dynamic interfaces
 * of the same type. For example, for an entry of interfacename
 * ppp*, there will be one such entry.
 */
typedef struct dynamicIfacetype {
	struct dynamicIfacetype	*next;
	int		RegLifetime;
	int		AdvLifetime;
	uint32_t	AdvInterval;
	int32_t		AdvServiceflag;
	boolean_t	AdvLimitUnsolicited;
	boolean_t	AdvPrefixflag;
	boolean_t	advertiseOnBcast;
	uint8_t		AdvInitCount;
	uint8_t		RevtunReqd;
	uint8_t		RevtunAllowed;
	char		dynamicIfcetype[LIFNAMSIZ];
} DynamicIfaceTypeEntry;

/* DynamicInterface, dynamicIfaceHead variables are set in  agentInit.c */
boolean_t	DynamicInterface;
DynamicIfaceTypeEntry   *dynamicIfaceHead;

/*
 * This data structure keeps track of existing interfaces
 * at the time of mipagent startup
 */
typedef struct staticIface {
	char			ifacename[LIFNAMSIZ];
	struct staticIface	*next;
} StaticIfaceEntry;

#define	GET_EXT_DATA(messageHdr, counter, extId, ptr, len)             \
	for (counter = 0, len = 0, ptr = NULL;                         \
	    counter < messageHdr->extCnt; counter++) {                 \
		if (messageHdr->extType[counter] == extId) {           \
			/*                                             \
			 * Support for non-traditional                 \
			 * extension header formats                    \
			 *                                             \
			 * Get a pointer to the data and its length    \
			 */                                            \
			ptr = messageHdr->extData[counter];            \
			len = messageHdr->extLength[counter];          \
			break;                                         \
		}                                                      \
	}                                                              \

#define	GET_AUTH_EXT(messageHdr, counter, extId, ptr, len)             \
	for (counter = 0, len = 0, ptr = NULL;                         \
	    counter < messageHdr->extCnt; counter++) {                 \
		if (messageHdr->extType[counter] == extId) {           \
			/*                                             \
			 * Support for non-traditional                 \
			 * extension header formats                    \
			 *                                             \
			 * Get a pointer to the data and its length    \
			 */                                            \
			ptr = (authExt *)messageHdr->extIdx[counter]; \
			len = messageHdr->extLength[counter];        \
			break;                                         \
		}                                                      \
	}                                                              \

/*
 * Support for the latest Challenge/Response I-D
 */
#define	GET_GEN_AUTH_EXT(messageHdr, counter, extId, ptr, len)         \
	for (counter = 0, len = 0, ptr = NULL;                         \
	    counter < messageHdr->extCnt; counter++) {                 \
		if ((messageHdr->extType[counter] ==                   \
			REG_GEN_AUTH_EXT_TYPE) &&                      \
			(messageHdr->extSubType[counter] == extId)) {  \
			/*                                             \
			 * Get a pointer to the data and its length    \
			 */                                            \
			ptr = (genAuthExt *)messageHdr->extIdx[counter]; \
			len = messageHdr->extLength[counter];          \
			break;                                         \
		}                                                      \
	}                                                              \

/*
 * Support for vendor specific extensions.
 */
#define	GET_VEND_KEY_EXT(messageHdr, counter, vendId, extId, ptr, len) \
	for (counter = 0, len = 0, ptr = NULL;                         \
	    counter < messageHdr->extCnt; counter++) {                 \
		if ((messageHdr->extVendorId[counter] == vendId) &&    \
			(messageHdr->extSubType[counter] == extId)) {  \
			/*                                             \
			 * Get a pointer to the data and its length    \
			 */                                            \
			ptr = (keyDataExt *)messageHdr->extData[counter]; \
			len = messageHdr->extLength[counter];          \
			break;                                         \
		}                                                      \
	}                                                              \

#define	GET_TIME(currentTime)                                          \
	{                                                              \
		struct timeval timer;                                  \
		if (gettimeofday(&timer, NULL) == -1) {                \
			currentTime = 0;                               \
		} else {                                               \
			currentTime = timer.tv_sec;                    \
		}                                                      \
	}

#define	GENERATE_NET_BROADCAST_ADDR(entry)                             \
	(entry->maIfaceAddr & entry->maIfaceNetmask) |                 \
	~entry->maIfaceNetmask

/* Common agent functions used by multiple files */
extern boolean_t ConfigEntryHashLookup(void *, uint32_t, uint32_t, uint32_t);
extern int CreateListOfExistingIntfce(void);
extern int startDynamicInterfaceThread(void);
extern int killDynamicInterfaceThread(void);
extern int InitSockets(MaAdvConfigEntry *);
extern void docleanup(void);
extern void disableService(struct hash_table *);
extern int aaaCreateKey(int, unsigned char *, size_t, uint32_t);
extern int haCheckRegReqAuthContinue(MessageHdr *, HaMobileNodeEntry **,
    uint32_t *, uint32_t *);
extern int addHABE(HaMobileNodeEntry *, ipaddr_t, in_port_t,
    MaAdvConfigEntry *, uint8_t, ipaddr_t, ipaddr_t, ipaddr_t, uint32_t,
    boolean_t *, uint32_t *);

#ifdef __cplusplus
}
#endif

#endif /* _AGENT_H */
