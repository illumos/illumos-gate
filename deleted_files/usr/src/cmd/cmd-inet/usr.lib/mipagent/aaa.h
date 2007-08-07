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

#ifndef _AAA_H
#define	_AAA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * aaa.h -- AAA defines and structures (Diameter interface)
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * If the following is defined, the foreign agent will communicate directly
 * with the home agent, (using a proxy) but will still use the diameter API
 * protocol.  The only changes to the code will be the handling the different
 * messages, and the generation of keys.
 *
 * #define	TEST_DIAMETER
 */

/*
 * These constants are used to control where AAA looks for the diameter
 * server.
 */
#define	LOOPBACK "127.0.0.1"
#define	AAA_PORT 769
#define	MAX_SERVER_NAME_LEN 1024

#ifndef MIN
#define	MIN(x, y) (((x) > (y))?(y):(x))
#endif

/*
 * Maximum lengths of NAIs and challenges
 */
#define	MAX_NAI_LEN   256
#define	MAX_CHALLENGE_LEN 16

/* Max size of an incomming or outgoing tcp packet. */
#define	MAX_TCP_LEN 4096

/* biggest key to generate (for debug testing) */
#define	MAX_GENERATE_KEY_LEN 16

/*
 * SPI values to be used with AAA protocols.
 * Currently only Radius is used.
 */
#define	RADIUS_SPI	2

/*
 * Diameter API defines.  (from the specification
 */
typedef enum {
	MOBILE_IP_OPEN_SESSION_REQUEST = 1,		/* 01 */
	MOBILE_IP_OPEN_SESSION_ANSWER,			/* 02 */
	MOBILE_IP_OPEN_SESSION_INDICATION,		/* 03 */
	MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,	/* 04 */
	MOBILE_IP_ACCOUNTING_START_REQUEST,		/* 05 */
	MOBILE_IP_ACCOUNTING_START_ANSWER,		/* 06 */
	MOBILE_IP_ACCOUNTING_INTERIM_REQUEST,		/* 07 */
	MOBILE_IP_ACCOUNTING_INTERIM_ANSWER,		/* 08 */
	MOBILE_IP_ACCOUNTING_STOP_REQUEST,		/* 09 */
	MOBILE_IP_ACCOUNTING_STOP_ANSWER,		/* 10 */
	MOBILE_IP_CLOSE_SESSION_REQUEST,		/* 11 */
	MOBILE_IP_CLOSE_SESSION_ANSWER			/* 12 */
} AAA_CommandCode;

typedef enum {
	MOBILE_NODE_NAI = 1,				/* 01 */
	FOREIGN_AGENT_NAI,				/* 02 */
	REGISTRATION_REQUEST,				/* 03 */
	NUMBER_OF_CHALLENGE_BYTES_IN_RR,		/* 04 */
	MOBILE_NODE_RESPONSE,				/* 05 */
	MOBILE_NODE_HOME_ADDRESS,			/* 06 */
	HOME_AGENT_ADDRESS,				/* 07 */
	RESULT_CODE,					/* 08 */
	REGISTRATION_REPLY,				/* 09 */
	MN_FA_SPI,					/* 10 */
	MN_FA_KEY,					/* 11 */
	FA_HA_SPI,					/* 12 */
	FA_HA_KEY,					/* 13 */
	SESSION_TIMEOUT,				/* 14 */
	HA_FA_KEY,					/* 15 */
	FA_MN_KEY,					/* 16 */
	MN_HA_SPI,					/* 17 */
	MN_HA_KEY,					/* 18 */
	HA_MN_KEY,					/* 19 */
	SESSION_TIMEOUT_1,				/* 20 */
	SESSION_TIME,					/* 21 */
	FOREIGN_AGENT_ADDRESS,				/* 22 */
	MN_AAA_SPI,					/* 23 */
	IS_FROM_HA,					/* 24 */
	REV_TUN,					/* 25 */
	MN_HANDLE,					/* 26 */
	RELEASE_INDICATOR,				/* 27 */
	MN_FA_CHALLENGE_VALUE				/* 28 */
} AAA_AVPCode;

/*
 * This structure is the header of a diameter API message.
 * All items are sent in network-byte-ordering.
 */
typedef struct {
	uint32_t protocol;
	uint32_t commandCode;
	uint32_t handle;
	uint32_t length;
} AAA_Packet;

/*
 * AAA protocols API defines.  (from the specification)
 */
typedef enum {
	AAA_NONE = 0,					/* 00 */
	DIAMETER,					/* 01 */
	RADIUS						/* 02 */
} AAA_Protocol_Code;

/*
 * MIPResultCode is used in the protocol to communicate Mobile-IP
 * specific errors. Per AAA specification.
 */
typedef enum {
	MIP_SUCCESS				= 0,
	MIP_REASON_UNSPECIFIED			= 1,
	MIP_ADMINISTRATIVELY_PROHIBITED		= 2,
	MIP_INSUFFICIENT_RESOURCES		= 3,
	MIP_FAILED_AUTHENTICATION		= 4
} MIPResultCode;

/*
 * This structure refers to an Attribute Value Pair.  The last field, data
 * is really a place holder, rather than a data item.  This structure is either
 * allocated without a sizeof: malloc( sizeof(uint32_t) * 2 + dataLen),
 * or it is used to point to the structure being returned:
 * avpPtr = (AAA_AVP *)buffer;
 *
 * When this is used to point to a buffer, it can be moved along, byte by byte
 * and the data place holder will be able to retrieve the data.  This is
 * necessary, since packets are variable length:
 *
 *
 * Buffer:
 *
 * +-----------------------+
 * |      Header           |
 * +-----------------------+
 * | First Record          |
 * |                       |
 * |_________|-------------|
 * | Second Record         |
 * |______________|--------|
 *
 * So, to parse the above, an AAA_AVP pointer would be set to the first record,
 * the avpCode and Length would be read, and the data copied form the data
 * portion of the record.  Basically, this method is used so that the data
 * Can be read as follows:
 *
 * AAA_Avp_p = (AAA_AVP *)&buffer[offset];
 * code = AAA_Avp_p->code;
 * length = AAA_Avp_p->length);
 * memcpy(data, AAA_Avp_p->data, length - (2 * sizeof (uint32_t));
 * offset += length;
 *
 * It could have also been done with pointer arrithmetic, but I thought it
 * was harder to read/understand:
 *
 * code = *((uint32_t *)&buffer[offset]);
 * ofset += sizeof (uint32_t);
 * length = *((uint32_t *)&buffer[offset]);
 * offset += sizeof (uint32_t);
 * memcpy(data, &buffer[offset], length  - (2 * sizeof (uint32_t));
 * offset += length;
 *
 * (by the way -- the above code does not take into account byte alignment or
 * network byte ordering, so don't cut and paste from these comments!)
 */
typedef struct {
	uint32_t	 avpCode;
	uint32_t	 length;
	unsigned char	 data[1];
} AAA_AVP;

/* This enum defines the current state of the hash node */
typedef enum {
	Initialized = 0,
	WaitingForAuthorization,
	Authorized
} AAA_State;


/* This structure is the structure that is kept in the hash */
typedef struct {
	rwlock_t	aaaNodeLock;
	int32_t		handle;
	char		mnNAI[MAX_NAI_LEN];
	AAA_State	State;
	unsigned char	mnChallenge[MAX_CHALLENGE_LEN];
	ipaddr_t	homeAddress;
	ipaddr_t	homeAgentAddress;
	uint32_t	timeOut;
	void		*messageHdr; /* RegReq from MN, used for Radius */
} AAA_HashEntry;

int startAAATaskThread();
int sendAccountingRecord(AAA_CommandCode, unsigned char *, uint32_t,
    ipaddr_t, ipaddr_t, ipaddr_t, uint32_t, int32_t);
int AAAAuthenticateRegReq(unsigned char *, uint32_t, unsigned char *,
    unsigned int, uint32_t, unsigned char *, uint32_t, uint32_t, ipaddr_t,
    ipaddr_t, boolean_t, uint32_t, void *, unsigned char *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _AAA_H */
