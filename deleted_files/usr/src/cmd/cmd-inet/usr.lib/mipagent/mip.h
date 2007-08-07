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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MIP_H
#define	_MIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains definitions for structures used in all
 * Mobile IP-aware entities.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <synch.h>
#include <sys/socket.h>
#include <net/if.h>

#define	mipverbose(a)   if (logVerbosity) (void)printf a

#define	MAX_KEY_LEN		32
#define	MAX_NAI_LENGTH		256

/* Reason why a MN session terminates */
#define	REASON_UNKNOWN	0
#define	REG_EXPIRED	1
#define	REG_REVOKED	2
#define	MN_DEREGISTERED	3

/* Flag to indicate if Reverse Tunneling is Required */
#define	REVTUN_NOTREQUIRED	0
#define	REVTUN_REQUIRED		1

#ifdef LINUX
/*
 * For linux only.
 */
typedef char boolean_t;
#endif

/*
 * The MipSecAssocEntry structure contains information necessary
 * to authenticate messages. Each peer has one security association,
 * which includes a key and replay information.
 */
typedef struct {
	rwlock_t	mipSecNodeLock;
	boolean_t	mipSecIsEntryDynamic;
	uint32_t	mipSecSPI;
	int		mipSecAlgorithmType;
	int		mipSecAlgorithmMode;
	int		mipSecKeyLen;
	unsigned char	mipSecKey[MAX_KEY_LEN];
	int		mipSecReplayMethod;
	time_t		mipSecKeyLifetime;
} MipSecAssocEntry;


/*
 * The MipSecViolationEntry structure is not currently used,
 * but is intended to contain information about security
 * failures from peers.
 */
typedef struct {
	rwlock_t	mipSecNodeLock;
	ipaddr_t	mipSecViolatorAddr;
	uint32_t	mipSecViolationCounter;
	int		mipSecRecentViolationSPI;
	time_t		mipSecRecentViolationTime;
	int		mipSecRecentViolationIDLow;
	int		mipSecRecentViolationIDHigh;
	int		mipSecRecentViolationReason;
} MipSecViolationEntry;

/* Flags used in mobility agent advertisements */
#define	ADV_REVERSE_TUNNEL		0x01
#define	ADV_VJ_COMPRESSION		0x02
#define	ADV_GRE_ENCAP			0x04
#define	ADV_MIN_ENCAP			0x08
#define	ADV_IS_FOREIGN_AGENT		0x10
#define	ADV_IS_HOME_AGENT		0x20
#define	ADV_IS_BUSY			0x40
#define	ADV_REGISTRATION_REQUIRED	0x80

/* Possible addresses for agent advertisements */
#define	LINK_MCAST_ADV_ADDR	"224.0.0.1"
#define	LINK_MCAST_ADV_ADDR2	"224.0.0.2"
#define	LINK_BCAST_ADDR		"255.255.255.255"
#define	LINK_MCAST_REG_ADDR	"224.0.0.11"

/* Boolean values */
#define	TRUE	1
#define	FALSE	0

/* Flags used in registrations */
#define	REG_BIT_UNUSED			0x01
#define	REG_REVERSE_TUNNEL		0x02
#define	REG_VJ_COMPRESSION		0x04
#define	REG_GRE_ENCAP			0x08
#define	REG_MIN_ENCAP			0x10
#define	REG_DECAPSULATION_BY_MN		0x20
#define	REG_FWD_BROADCASTS		0x40
#define	REG_SIMULTANEOUS_BINDINGS	0x80

/* Successful Mobile-IP Codes */
#define	MIP_SUCCESSFUL_REGISTRATION	0
/*
 * Successful, but an indication that simultaneous bindings
 * is not supported.
 */
#define	MIP_SIMULTANEOUS_NOT_SUPPORTED	1

/* Drop the signalling packet due to unknown extension */
#define	MA_DROP_PACKET			-1

/* Rejection codes from Foreign Agent */
#define	FA_REASON_UNSPECIFIED		64
#define	FA_ADM_PROHIBITED		65
#define	FA_INSUFFICIENT_RESOURCES	66
#define	FA_MN_AUTH_FAILURE		67
#define	FA_HA_AUTH_FAILURE		68
#define	FA_REG_LIFETIME_TOO_LONG	69
#define	FA_POORLY_FORMED_REQUEST	70
#define	FA_POORLY_FORMED_REPLY		71
#define	FA_ENCAP_UNAVAILABLE		72
#define	FA_VJ_UNAVAILABLE		73
#define	FA_REVERSE_TUNNEL_UNAVAILABLE	74
#define	FA_REVERSE_TUNNEL_REQUIRED	75
#define	FA_MN_TOO_DISTANT		76
#define	FA_INVALID_CARE_OF_ADDR		77
#define	FA_DELIVERY_STYLE_UNAVAILABLE	79
#define	FA_HA_NET_UNREACHABLE		80
#define	FA_HA_HOST_UNREACHABLE		81
#define	FA_HA_PORT_UNREACHABLE		82
#define	FA_HA_UNREACHABLE		88
/*
 * Support for the error codes defined in the latest
 * challenge/response and NAI I-D.
 */
#define	FA_NONZERO_HOMEADDR_REQD	96
#define	FA_MISSING_NAI			97
#define	FA_MISSING_HOME_AGENT		98
#define	FA_MISSING_HOMEADDR		99
#define	FA_UNKNOWN_CVSE_FROM_MN		100  /* MN extension error at FA */
#define	FA_UNKNOWN_CVSE_FROM_HA		101  /* HA extension error at FA */
#define	FA_UNKNOWN_CHALLENGE		104
#define	FA_MISSING_CHALLENGE		105
#define	FA_STALE_CHALLENGE		106
#define	FA_MISSING_MN_FA_KEY		107

/* Rejection codes from Home Agent */
#define	HA_REASON_UNSPECIFIED		128
#define	HA_ADM_PROHIBITED		129
#define	HA_INSUFFICIENT_RESOURCES	130
#define	HA_MN_AUTH_FAILURE		131
#define	HA_FA_AUTH_FAILURE		132
#define	HA_ID_MISMATCH			133
#define	HA_POORLY_FORMED_REQUEST	134
#define	HA_TOO_MANY_SIMULTANEOUS	135
#define	HA_UNKNOWN_HOME_AGENT		136
#define	HA_REVERSE_TUNNEL_UNAVAILABLE	137
#define	HA_REVERSE_TUNNEL_REQUIRED	138
#define	HA_ENCAPSULATION_UNAVAILABLE	139	/* Used for Reverse Tunnel */
#define	HA_UNKNOWN_CVSE_FROM_MN		140  /* MN extension error at HA */
#define	HA_UNKNOWN_CVSE_FROM_FA		141  /* FA extension error at HA */

#define	NONE				0
/* Authentication algorithm types */
#define	MD5				1

/* Authentication algorithm modes */
#define	PREFIXSUFFIX			1

/* Replay method style */
#define	TIMESTAMPS			1

/* Encapsulation style */
#define	IPIP				1
#define	GRE				2
#define	MINIMAL				3

#ifdef LINUX
/* ICMP messages (we define them here for portability) */
#define	ICMP_UNREACH_PORT		3
#define	ICMP_ROUTERADVERT		9
#define	ICMP_ROUTERSOLICIT		10
#endif

/*
 * We need to redefine the ICMP header here because we need
 * the Mobile-IP router advertisement extension, which is not
 * currently in ip_icmp.h. This should be added in the future.
 */
typedef struct icmphdr {
	unsigned char  type;
	unsigned char  code;
	unsigned short checksum;
	union {
		struct {
			unsigned char u_adv_num_addr;
			unsigned char u_adv_addr_entry_size;
			unsigned short u_adv_lifetime;
		} u_adv;
		uint32_t u_unused;
	} icmphdr_u;
} icmph;

#define	icmpAdvNumAddr		icmphdr_u.u_adv.u_adv_num_addr
#define	icmpAdvAddrEntrySize	icmphdr_u.u_adv.u_adv_addr_entry_size
#define	icmpAdvLifetime		icmphdr_u.u_adv.u_adv_lifetime

/* Mobile IP Agent Advertisement Extension */

#define	ADV_EXT_TYPE			16
#define	ADV_PREFIX_EXT_TYPE		19
#define	ADV_PADDING_EXT_TYPE		0
#define	ADV_CHALLENGE_EXT_TYPE		24
#define	ADV_AGENT_NAI_EXT_TYPE		25

/*
 * The length of our challenges, and the maximum
 * challenge size our Home Agent will accept.
 */
#define	ADV_CHALLENGE_LENGTH		16
#define	ADV_MAX_CHALLENGE_LENGTH	256
#define	ADV_MAX_NAI_LENGTH		256

typedef struct aaext {
	uint8_t  type;
	uint8_t  length;
	uint16_t seqNum;
	uint16_t regLifetime;
	uint8_t  advFlags;
	uint8_t  reserved;
} advExt;

/* Mobile IP Registration Request and Reply */

#define	REG_REQUEST_TYPE		1
#define	REG_REPLY_TYPE			3
#define	REG_MH_AUTH_EXT_TYPE		32
#define	REG_MF_AUTH_EXT_TYPE		33
#define	REG_FH_AUTH_EXT_TYPE		34
/*
 * Support for the latest challenge/response,
 * Vendor Specific and AAA Keys I-D.
 */
#define	REG_GEN_AUTH_EXT_TYPE		36
#define	REG_CRIT_VENDOR_SPEC_EXT_TYPE	38
#define	REG_GEN_MN_FA_KEY_EXT_TYPE	40
#define	REG_GEN_MN_HA_KEY_EXT_TYPE	42
#define	ENCAPSULATING_DELIVERY_TYPE	130  /* for reverse tunneling */
#define	REG_MN_NAI_EXT_TYPE		131
#define	REG_MF_CHALLENGE_EXT_TYPE	132
#define	REG_NORMAL_VENDOR_SPEC_EXT_TYPE	134

typedef struct rreq {
	uint8_t		type;
	uint8_t		regFlags;
	uint16_t	regLifetime;
	uint32_t	homeAddr;
	uint32_t	haAddr;
	uint32_t	COAddr;
	uint32_t	IDHigh;
	uint32_t	IDLow;
} regRequest;

typedef struct rrep {
	uint8_t		type;
	uint8_t		code;
	uint16_t	regLifetime;
	uint32_t	homeAddr;
	uint32_t	haAddr;
	uint32_t	IDHigh;
	uint32_t	IDLow;
} regReply;

#define	MIP_EXT_LENGTH			1
#define	MIP_EXT_DATA			2

typedef struct rrext {
	uint8_t		type;
	uint8_t		length;
} regExt;

typedef struct authext {
	uint8_t		type;
	uint8_t		length;
	uint16_t	SPIhi;
	uint16_t	SPIlo;
} authExt;

#define	KEY_ALG_NONE			0
#define	KEY_ALG_MD5_PREFIXSUFFIX	2
#define	KEY_ALG_HMAC_MD5		3

typedef struct keydataext {
	/*
	 * Key data is a MIER extension, and contains a lifetime
	 */
	uint32_t	lifetime;
	uint32_t	mnAAASPI;
	uint32_t	nodeSPI;
}keyDataExt;

/*
 * Support for the latest challenge/response,
 * Vendor Specific and AAA Keys I-D.
 */
typedef struct keyext {
	uint8_t		type;
	uint8_t		subType;
	uint16_t	length;
	keyDataExt	keyData;
} keyExt;

#define	GEN_KEY_MN_FA			7
#define	GEN_KEY_MN_HA			1

typedef struct mierlongext {
	uint8_t		type;
	uint8_t		subType;
	uint16_t	length;
} mierLongExt;

/*
 * The following are the offsets in the
 * extension header for mier style extensions.
 */
#define	MIP_EXT_GEN_SUB_TYPE		1
#define	MIP_EXT_LONG_LENGTH		2
#define	MIP_EXT_LONG_LENGTH_DATA	4

/*
 * The following structure is the Generalized
 * Authentication Extension, specified in the
 * Challenge/Response I-D.
 */
typedef struct genauthext {
	uint8_t		type;
	uint8_t		subType;
	uint16_t	length;
	uint16_t	SPIhi;
	uint16_t	SPIlo;
} genAuthExt;

#define	GEN_AUTH_MN_AAA			1

#ifdef KEY_DISTRIBUTION
/*
 * Support for vendor specific extensions.
 *
 * The following is the definition of the vendor
 * specific extension. Although we don't really care
 * about this draft, we define it so that we do
 * recognize the critical vendor specific extension,
 * which has a two octet length.
 */
typedef
struct vendorspecext {
	uint8_t		type;
	uint8_t		reserved;
	uint16_t	length;
	uint32_t	vendorId;
	uint16_t	vendorType;
} vendorSpecExt;
#else /* KEY_DISTRIBUTION */
#define	VENDOR_SPEC_EXT_HDR_LEN		10
#endif /* KEY_DISTRIBUTION */
/*
 * The following are the offsets in the
 * extension header for CVSE style extensions.
 */
#define	MIP_EXT_CVSE_VENDOR_ID_TYPE	4
#define	MIP_EXT_CVSE_VENDOR_SUB_TYPE	8
#define	MIP_EXT_CVSE_VENDOR_ID_DATA	10

/*
 * The following are the offsets in the
 * extension header for NVSE style extensions.
 */
#define	MIP_EXT_NVSE_VENDOR_ID_TYPE	3
#define	MIP_EXT_NVSE_VENDOR_SUB_TYPE	4
#define	MIP_EXT_NVSE_VENDOR_ID_DATA	9

/*
 * And a few vendor Id's for your convenience.
 */
#define	VENDOR_ID_CISCO			9
#define	VENDOR_ID_SUN			42
#define	VENDOR_ID_3COM			43

/*
 * And lastly, here are a few vendor specific
 * extension numbers
 */
#define	REG_MN_FA_KEY_EXT		1
#define	REG_FA_HA_KEY_EXT		2

#ifdef __cplusplus
}
#endif

#endif /* _MIP_H */
