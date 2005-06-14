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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: aaa.c
 *
 * This file processes the Diameter AAA requests from mipagent.
 * This file also contains the routines used to parse and process the
 * Diameter messages.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>

#include "mip.h"
#include "agent.h"
#include "setup.h"
#include "hash.h"
#include "aaa.h"

static int gbl_TCPSocket = -1; /* Global socket */

static int gbl_hashInitialized = 0;
in_port_t gbl_aaaPort = AAA_PORT;
char gbl_aaaHost[MAX_SERVER_NAME_LEN];
static HashTable naiHash;

extern char maNai[];
extern HashTable mipAgentHash;
extern HashTable faVisitorHash;
extern AAA_Protocol_Code aaaProtocol;
extern ForeignAgentCounters faCounters;

static pthread_t aaaThreadId = 0;

/* External prototypes . . . this should be somewhere else -- WORK:todo */
extern int hexdump(char *, unsigned char *, int);
extern void forwardFromFAToHA(MessageHdr *, MaAdvConfigEntry *, boolean_t);
extern void rejectFromFAToMN(MessageHdr *, MaAdvConfigEntry *, int);
extern void FreeMessageHdr(MessageHdr *);
MessageHdr *AllocateMessageHdr();
extern boolean_t forcefullyDeregisterMN(ipaddr_t *, ipaddr_t, ipaddr_t);
extern boolean_t mkPendingFAVEHashLookup(void *, uint32_t, uint32_t, uint32_t);
extern void delFAVE(HashTable *, FaVisitorEntry **, ipaddr_t, uint32_t);
extern void enableService();
/*
 * Internal Prototypes
 */

static int sendCloseSessionAnswer(AAA_Packet *, char *, size_t, boolean_t);
static size_t aaaAddAvp(AAA_AVPCode avpCode, unsigned char *dest,
	size_t destLen, void *data, size_t dataLen);
static AAA_AVP *aaaFindAvpByCode(AAA_Packet *packet, AAA_AVPCode avpCode);

static int readTCPPacket(unsigned char *buffer, uint32_t bufLen);
static void *mainAAAThread();
static int sendTCPPacket(unsigned char *buffer, uint32_t length);
static void processAuthFailure(MessageHdr *msgHdr,
	char *mnNAI, size_t mnNAILen, uint32_t result);
#ifdef TEST_DIAMETER
static void processOpenSessionRequest(AAA_Packet *packet, char *mnNAI,
	size_t mnNAILen);
static void processOpenSessionIndicationResponse(AAA_Packet *packet,
	char *mnNAI, size_t mnNAILen);
static void aaaGenerateKey(unsigned char *buffer, size_t buffLen);
static uint32_t aaaGenerateSpi();
#endif
static void processOpenSessionAnswer(AAA_Packet *packet, char *mnNAI,
	size_t mnNAILen, uint32_t resultCode);
static void processOpenSessionAnswerRadius(AAA_Packet *packet, char *mnNAI,
    size_t mnNAILen, AAA_HashEntry *);
static void processOpenSessionAnswerRadiusHA(AAA_Packet *packet, char *mnNAI,
    size_t mnNAILen, AAA_HashEntry *, uint32_t resultCode);
static void processOpenSessionIndication(AAA_Packet *packet, char *mnNAI,
	size_t mnNAILen);
static void *aaaFindAvpPtr(AAA_Packet *packet, AAA_AVPCode avpCode,
	size_t *length);
static boolean_t aaaFindAvpInt(AAA_Packet *, AAA_AVPCode, int32_t *);
static int sendCloseSession(AAA_Packet *srcPacket, char *mnNAI,
	size_t mnNAILen);
static void aaaSendErrorResponse(uint32_t commandCode, int32_t returnCode,
	char *mnNAI, size_t mnNAILen, uint32_t handle);

/* Not prototyped in .h file for cyclic dependency problems */
int aaaSendRegistrationReply(MessageHdr *, size_t, ipaddr_t, ipaddr_t);


extern int  logVerbosity;  /* WORK -- This should be in a .h file.  PRC? */
extern ipaddr_t getClosestInterfaceAddr(ipaddr_t dest); /* Where? WORK */
extern MaAdvConfigEntry *getFirstInterface(); /* Where? WORK */
extern int dispatchMsgToThread(MessageHdr **messageHdr);
extern boolean_t advBusy;
extern struct hash_table maAdvConfigHash;

/*
 * Function: aaaAddAvp
 *
 * Arguments: unsigned char *dest, size_t destLen, uint32_t avpCode,
 *            void *data, size_t dataLen
 *
 * Description: This function will build an AVP perform all byte-ordering/
 *              copying operations, and will return the length of the
 *              destination AVP.
 *
 * Returns: size_t (length of block added, zero on error)
 */
static size_t
aaaAddAvp(AAA_AVPCode avpCode, unsigned char *dest, size_t destLen,
	void *data, size_t dataLen)
{
	AAA_AVP staticAvp;
	AAA_AVP *avp;
	int32_t TempInt;

	/* First, check to make sure it will fit */
	if ((dataLen + (2 * sizeof (uint32_t))) > destLen) {
		syslog(LOG_ERR, "ERROR: avp will not fit in dest! ("
			"avpSize = %d, destSize = %d, avpCode = %d)",
			dataLen + (2 * sizeof (uint32_t)), destLen, avpCode);
		return (0);
	}

	/* Now, build the avp */
	staticAvp.avpCode = htonl(avpCode);

	/* Note: dataLen = size of header */
	staticAvp.length = htonl(2 * sizeof (uint32_t) + dataLen);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	avp = (AAA_AVP *)dest;
	(void) memcpy(avp, &staticAvp, 2 * sizeof (uint32_t));

	switch (avpCode) {
		/* These fields require no mangling */
	case MOBILE_NODE_NAI:
	case FOREIGN_AGENT_NAI:
	case REGISTRATION_REQUEST:
	case MOBILE_NODE_RESPONSE:
	case REGISTRATION_REPLY:
	case MN_FA_KEY:
	case FA_HA_KEY:
	case HA_FA_KEY:
	case FA_MN_KEY:
	case MN_HA_KEY:
	case HA_MN_KEY:
	case MN_FA_CHALLENGE_VALUE:
		(void) memcpy(avp->data, data, dataLen);
		break;

	/* These fields require mangling (They're 32 bit numbers) */
	case NUMBER_OF_CHALLENGE_BYTES_IN_RR:
	case MOBILE_NODE_HOME_ADDRESS:
	case HOME_AGENT_ADDRESS:
	case RESULT_CODE:
	case MN_FA_SPI:
	case FA_HA_SPI:
	case SESSION_TIMEOUT:
	case MN_HA_SPI:
	case SESSION_TIMEOUT_1:
	case SESSION_TIME:
	case FOREIGN_AGENT_ADDRESS:
	case IS_FROM_HA:
	case MN_AAA_SPI:
	case REV_TUN:
	case MN_HANDLE:
	case RELEASE_INDICATOR:
		if (dataLen != sizeof (uint32_t)) {
			syslog(LOG_ERR, "Internal error: avp should have a "
				"length of %d, not %d!", sizeof (uint32_t),
				dataLen);
			return (0);
		}
		(void) memcpy(&TempInt, data, sizeof (uint32_t));
		TempInt = htonl(TempInt);
		(void) memcpy(avp->data, &TempInt, sizeof (uint32_t));
		break;

	default: /* Error! */
		syslog(LOG_ERR, "ERROR: Invalid AVP Code! <%d>\n", avpCode);
		return (0);
	} /* switch (avpCode) */

	return (ntohl(staticAvp.length));
} /* aaaAddAvp */

/*
 * Function: addNaiToHash
 *
 * Arguments: char *mnNAI, size_t mnNAILen,
 *		unsigned char *mnChallenge, uint32_t mnChallengeLen,
 *		ipaddr_t homeAddress, ipaddr_t homeAgentAddress,
 *		void *messageHdr
 *
 * Description: This function will add the nai to our local hash.  It
 *              checks to make sure the add was successful (value unique)
 *              It is called from the foreign agent or home agent when it first
 *              receives a NAI that it has not seen before.  The has entry is
 *              used to store any interim data that is needed for either
 *              the home or foreign agents.
 *
 * Returns: int (zero on success)
 */
static int
addNaiToHash(char *mnNAI, size_t mnNAILen,
    unsigned char *mnChallenge, uint32_t mnChallengeLen,
    ipaddr_t homeAddress, ipaddr_t homeAgentAddress,
    void *messageHdr)
{
	AAA_HashEntry *p;
	int rc;

	/* Allocate and initialize HashEntry */
	p = (AAA_HashEntry *)malloc(sizeof (AAA_HashEntry));
	if (!p) {
		syslog(LOG_CRIT, "FATAL: Unable to allocate memory!");
		return (-1);
	}

	(void) memset(p, 0, sizeof (AAA_HashEntry));
	(void) strncpy(p->mnNAI, mnNAI, MIN(MAX_NAI_LEN - 1, mnNAILen));
	p->mnNAI[MIN(MAX_NAI_LEN - 1, mnNAILen)] = '\0';
	(void) memcpy(p->mnChallenge, mnChallenge, MIN(MAX_CHALLENGE_LEN - 1,
		mnChallengeLen));

	p->homeAddress = homeAddress;
	p->homeAgentAddress = homeAgentAddress;
	p->timeOut = 0;
	p->handle = 0;
	p->messageHdr = messageHdr;

	/* Now link it. */
	rc = linkHashTableEntryString(&naiHash, (unsigned char *)mnNAI,
		mnNAILen, p, LOCK_NONE);
	if (rc != 0) {
		syslog(LOG_ERR,
			"ERROR: Unable to add entry to hash! (unique?)");
		free(p);
		return (-2);
	}

	return (0);

} /* addNaiToHash */

/*
 * Function: removeFromHash
 *
 * Arguments: char *mnNAI, size_t mnNAILen
 *
 * Description: This function will delete the nai from our local hash.
 *              It is called in the foreign agent when the CloseSession
 *              Answer returns.  It should be called in the home agent when
 *              the Accounting Stop arrives.
 *
 * Returns: int (zero on success)
 */
static int
removeFromHash(char *mnNAI, size_t mnNAILen)
{
	int rc;
	AAA_HashEntry *p;

	/*
	 * Lock it for writing.
	 */
	p = (AAA_HashEntry *)findHashTableEntryString(&naiHash,
		(unsigned char *)mnNAI, mnNAILen, LOCK_WRITE, NULL, NULL, NULL,
		NULL);
	if (!p) {
		syslog(LOG_ERR, "ERROR: Unable to find NAI <%.*s> in hash!",
		    mnNAILen, mnNAI);
		return (-1);
	}
	rc = delHashTableEntryString(&naiHash, p, (unsigned char *)mnNAI,
		mnNAILen, LOCK_NONE);

	/* And, finally, free our data */
	/* WARNING: Check return value xxx WORK */
	(void) rw_unlock(&p->aaaNodeLock);
	(void) rwlock_destroy(&p->aaaNodeLock);
	free(p);

	return (rc);

} /* removeFromHash */

/*
 * Function: aaaUpdateHash
 *
 * Arguments: AAA_Packet *packet, char *mnNAI, size_t mnNAILen
 *
 * Description: This function will update the hash information for the
 *              given node.  It gets called when any response comes from the
 *              AAA server.  The only field that is currently updated is the
 *              handle.  The handle is ONLY updated if our current copy is a
 *              zero.
 *
 *              Also, since we probably sent out accounting messages with a
 *              handle of zero, it accepts any response that contains a handle
 *              of zero (but does not update our local information).
 *
 * Returns: int
 */
static AAA_HashEntry *
aaaUpdateHash(AAA_Packet *packet, char *mnNAI, size_t mnNAILen)
{
	AAA_HashEntry *p;

	/*
	 * Since we only have one thread reading from the socket, and
	 * that thread is the only thread that will update these data
	 * items, no locking is necessary.
	 */
	p = (AAA_HashEntry *)findHashTableEntryString(&naiHash,
		(unsigned char *)mnNAI, mnNAILen, LOCK_WRITE, NULL, NULL,
		NULL, NULL);

	if (p) {
		if (p->handle) {
			/*
			 * We already have a handle .. . check it
			 * But, it's ok if we get a zero . . .just means that
			 * the sender doesn't know that the handle is set yet.
			 */
			if ((p->handle != ntohl(packet->handle)) &&
				(ntohl(packet->handle) != 0)) {
				/* Error! */
				syslog(LOG_ERR,
					"Error: incoming handle does not match"
					" handle in hash: (%d <> %d)\n",
					ntohl(packet->handle),
					p->handle);
				(void) rw_unlock(&p->aaaNodeLock);
				return (NULL);
			}
		} else {
			/* Since we don't have a handle on file, update it */
			p->handle = ntohl(packet->handle);
		}
	} else {
		syslog(LOG_ERR, "Error: Unable to find nai (%*s) in hash!",
			mnNAILen, mnNAI);
		return (NULL);
	}

	return (p);

} /* aaaUpdateHash */

/*
 * Function: aaaLookupHandle
 *
 * Arguments: unsigned char *mnNAI, size_t mnNAILen
 *
 * Description: This function will lookup the NAI in the hash, and will return
 *              the handle associated with it.
 *
 * Returns: int32_t  (-1 on error)
 */
static int32_t
aaaLookupHandle(char *mnNAI, size_t mnNAILen)
{
	AAA_HashEntry *p;
	int32_t handle;

	/*
	 * Since we only have one thread reading from the socket, and
	 * that thread is the only thread that will update these data
	 * items, no locking is necessary.
	 */
	p = (AAA_HashEntry *)findHashTableEntryString(&naiHash, (unsigned
		char *)mnNAI, mnNAILen, LOCK_READ, NULL, NULL, NULL, NULL);

	if (p) {
		handle = p->handle;
		(void) rw_unlock(&p->aaaNodeLock);

		return (handle);
	} else {
		syslog(LOG_ERR, "Error: Unable to find nai (%.*s) in hash!",
			mnNAILen, mnNAI);
		return (-1);
	}

} /* aaaLookupHandle */

/*
 * Function: aaaFindAvpInt
 *
 * Arguments: AAA_Packet *packet, AAA_AVPCode avpCode, int32_t *dest
 *
 * Description: This routine will return the long specified by avpCode.
 *              On error, it will return _B_FALSE.
 *
 * Returns: boolean_t  (B_FALSE on error)
 */
static boolean_t
aaaFindAvpInt(AAA_Packet *packet, AAA_AVPCode avpCode, int32_t *dest)
{
	AAA_AVP *avp, staticAvp;

	avp = aaaFindAvpByCode(packet, avpCode);
	if (!avp)
		return (_B_FALSE);

	/* Make our static copy */
	(void) memcpy(&staticAvp, avp, 2 * sizeof (uint32_t));
	staticAvp.length = ntohl(staticAvp.length);

	/* subtract the header size */
	staticAvp.length -= sizeof (uint32_t) * 2;

	if (staticAvp.length != sizeof (uint32_t)) {
		syslog(LOG_ERR, "Error: aaaFindAvpInt: bad length for int."
			" avp code = %d, length = %d", staticAvp.avpCode,
			staticAvp.length);
		return (_B_FALSE);
	}

	(void) memcpy(dest, avp->data, sizeof (uint32_t));

	return (_B_TRUE);

} /* aaaFindAvpInt */

/*
 * Function: aaaFindAvpPtr
 *
 * Arguments: AAA_Packet *packet, AAA_AVPCode avpCode, size_t *length
 *
 * Description: This routine will return the data specified by avpCode.
 *              It will set the length to the length of the data.
 *              On error, it will return null.
 *
 * Returns: uint32_t  (defaultValue on error)
 */
static void *
aaaFindAvpPtr(AAA_Packet *packet, AAA_AVPCode avpCode, size_t *length)
{
	AAA_AVP *avp, staticAvp;

	*length = 0; /* Initialize this first */

	avp = aaaFindAvpByCode(packet, avpCode);
	if (!avp)
		return (NULL);

	/* Make our static copy */
	(void) memcpy(&staticAvp, avp, 2 * sizeof (uint32_t));
	staticAvp.length = ntohl(staticAvp.length);

	/* subtract the header size */
	staticAvp.length -= sizeof (uint32_t) * 2;

	*length = staticAvp.length;

	return (avp->data);

} /* aaaFindAvpPtr */

/*
 * Function: aaaFindAvpByCode
 *
 * Arguments: packet containing avps, avpCode
 *
 * Description: This function will walk through the AVPS and return a
 *              pointer to the avp that matches the given code.
 *              This function is not efficient, so if the number of
 *              avps expected grows over 15 or so, we should index them
 *              once, then call an indexed lookup.
 *
 * Returns: pointer to the avp, or NULL
 *
 */
static AAA_AVP *
aaaFindAvpByCode(AAA_Packet *packet, AAA_AVPCode avpCode)
{
	AAA_AVP		*avp;
	uint32_t	packetLength;
	uint32_t	currentPosition;
	AAA_AVP		staticAVP;
	unsigned char *buffer;

	/* First, get the length of the packet, so we don't overshoot */
	packetLength = ntohl(packet->length);

	/* Now, set buffer to point to the start of the AVPs */
	buffer = (unsigned char *)&packet[1];

	currentPosition = 0;
	while (currentPosition < (packetLength - (sizeof (AAA_AVP)))) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		avp = (AAA_AVP*)&buffer[currentPosition];

		/*
		 * now avp points to the right place. copy the
		 * data somewhere byte aligned.
		 */

		(void) memcpy(&staticAVP, avp, sizeof (uint32_t)*2);
		staticAVP.length = ntohl(staticAVP.length);
		staticAVP.avpCode = ntohl(staticAVP.avpCode);

		if (staticAVP.length <= (2 * sizeof (uint32_t))) {
			/* Bad packet */
			syslog(LOG_ERR, "Error: bad packet avp code = %d, "
				"length = %d", staticAVP.avpCode,
				staticAVP.length);
			return (NULL);
		}

		if (staticAVP.avpCode == avpCode) {
			/* We found it!  return our position */
			return (avp);
		}


		/* That wasn't it, so move on to the next one */
		currentPosition += staticAVP.length;

	}

	/* We didn't find it! */
	return (NULL);
} /* aaaFindAvpByCode */

/*
 * Function: aaaCreateKey
 *
 * Arguments: AAA_Packet *packet, int spiTag, int keyTag
 *
 * Description: This routine will create the SA for the given key / SPI.
 *              If the SA already exists, and it is dynamic, then replace the
 *              key information.
 *
 * Returns: int (zero on success)
 */
int
aaaCreateKey(int spi, unsigned char *key, size_t keyLen,
	uint32_t sessionTimeout)
{
	MipSecAssocEntry *entry;

	entry = CreateSecAssocEntry(_B_TRUE, spi, TIMESTAMPS, MD5, PREFIXSUFFIX,
			keyLen, (char *)key, sessionTimeout);

	if (entry == NULL) {
		syslog(LOG_ERR,
			"Unable to create SA for Mobile Node (SPI %d)\n", spi);
		return (-1);
	}

	/*
	 * The Create function ends up locking the node, so
	 * we need to free it.
	 */
	(void) rw_unlock(&entry->mipSecNodeLock);
	return (0);

} /* aaaCreateKey */

/*
 * Function: aaaCreateAgent
 *
 * Arguments: AAA_Packet *packet, int addrTag, uint32_t spi,
 *            uint32_t SessionTimeout
 *
 * Description: This function will create an agent from the data in the
 *              packet.  It is used to create bothe the foreign and home
 *              agent entries.  (The FA would create a corresponding HA entry,
 *              and vice versa)
 *
 * Returns: void
 */
static void
aaaCreateAgent(AAA_Packet *packet, int addrTag, uint32_t spi,
	uint32_t sessionTimeout)
{
	MobilityAgentEntry *maEntry;
	ipaddr_t peerAddress;

	/* Check the Agent Address */
	if (!aaaFindAvpInt(packet, addrTag, (int *)&peerAddress)) {
				/* BAD error . . . malformed packet */
		syslog(LOG_ERR, "ERROR: bad packet (no ADDR:%d)", addrTag);
		return;
	}

	/*
	 * On the Foreign Agent, we will need to create the Mobility
	 * Agent entry so that we can find the Home Agent's SPI
	 * when forwarding messages to it.
	 */
	maEntry = CreateMobilityAgentEntry(_B_TRUE, peerAddress, spi,
		sessionTimeout);
	if (maEntry == NULL) {
		/* Find it. */
		maEntry = findHashTableEntryUint(&mipAgentHash, peerAddress,
			LOCK_WRITE, NULL, 0, 0, 0);
		if (maEntry == NULL) {
			/* Error! */
			syslog(LOG_ERR, "Error: Unable to create the maEntry!");
			return;
		}
	}

	/*
	 * Now, make sure the entry is a dynamic one, and update the SPI
	 */
	if (maEntry->maSPI != spi) {
		if (maEntry->maIsEntryDynamic) {
			maEntry->maSPI = spi;
		} else {
		    syslog(LOG_ERR,
			"Error: received an SPI that does not match static"
			" Agent entry");
		}
	}

	/*
	 * The Create function ends up locking the node, so
	 * we need to free it.
	 */
	(void) rw_unlock(&maEntry->maNodeLock);

} /* aaaCreateAgent */

/*
 * Function: checkResultCode
 *
 * Arguments: AAA_Packet *packet
 *
 * Description: This routine checks the ResultCode field of the packet, and
 *              returns it (or -1 or -2 on error)
 *
 * Returns: int (resultCode, -1 or -2 on error)
 */
static int
checkResultCode(AAA_Packet *packet)
{
	int32_t resultCode;

	if (!aaaFindAvpInt(packet, RESULT_CODE, &resultCode)) {
				/* BAD error . . . malformed packet */
		syslog(LOG_ERR, "ERROR: bad packet (no RESULT_CODE)");
	}

	return (resultCode);
} /* checkResultCode */

/*
 * Function: startAAATaskThread
 *
 * Arguments:
 *
 * Description: This function starts our AAA thread.
 *
 * Returns: int (zero on success)
 */
int
startAAATaskThread()
{
	pthread_attr_t pthreadAttribute;
	int result;

	result = pthread_attr_init(&pthreadAttribute);

	if (result) {
		syslog(LOG_CRIT, "Error Initializing AAA pthread.");
		return (-1);
	}

	/*
	 * We now create a thread to deal with all periodic task.
	 */
	result = pthread_create(&aaaThreadId, &pthreadAttribute,
		(void *(*)()) mainAAAThread, (void *)NULL);

	if (result) {
		syslog(LOG_CRIT, "pthread_create() failed.");
		return (-1);
	}

	/*
	 * In order for system resources the be properly cleaned up,
	 * we need to detach the thread. Otherwise, we need to wait for
	 * a pthread_join(), which we do not want.
	 */
	result = pthread_detach(aaaThreadId);

	if (result) {
		syslog(LOG_CRIT, "pthread_detach() failed.");
		return (-1);
	}

	return (0);
} /* StartAAATaskThread */

/*
 * Function: killAAATaskThread
 *
 * Arguments:
 *
 * Description: This function kills our AAA task thread.
 *
 * Returns: int
 */
int
killAAATaskThread()
{
	int result;

	if (aaaThreadId) {
		/*
		 * Next we need to kill the dispatching thread.
		 */
		result = pthread_cancel(aaaThreadId);

		if (result) {
			/*
			 * Well, there's not much we can do here..
			 */
			syslog(LOG_CRIT, "Unable to kill AAA thread");
			return (-1);
		}
	}

	return (0);
} /* killAAATaskThread */

/*
 * Function: mainAAAThread
 *
 * Arguments:
 *
 * Description: This is our main AAA thread.  It receives the messages, and
 *              processes them based on command code.
 *
 * Returns: void *
 */
static void *
mainAAAThread()
{
	unsigned char buffer[MAX_TCP_LEN];
	uint32_t commandCode;
	AAA_Packet *packet;
	AAA_HashEntry *NaiEntry;
	uint32_t resultCode;
	boolean_t result;
	char *mobileNodeNAI;
	size_t mobileNodeNAILen;
	ipaddr_t *homeaddr = NULL;
	ipaddr_t *homeAgentaddr = NULL;
	size_t homeaddrLen;
	MessageHdr *msgHdr;
	int rc;
	uint32_t forHA;

	/* The below is an endless loop that will not give any lint warnings */
	for (; ; ) {
		if ((rc = readTCPPacket(buffer, MAX_TCP_LEN - 1)) <= 0) {
			syslog(LOG_ERR, "Error: <%d> reading packet (%d:%s)",
				rc, errno, strerror(errno));
			mipverbose(("readTCPPacket Failed errno is %d\n",
			    errno));
			(void) sleep(1);
			/*
			 * Clean up MN binding & visitor entries and tunnels
			 * when a down link between mobility agent and AAA
			 * infrastructure is down. readTCPPacket will only
			 * return 0 when this link is initally down. A
			 * reconnection try will result in rc being -1 so
			 * docleanup will only be called once - when link
			 * goes down.
			 */
			if (rc == 0) {
				syslog(LOG_ERR, "AAA readTCPPacket returned 0");
				mipverbose(("AAA readTCPPacket returned 0\n"));
				docleanup();
				disableService(&maAdvConfigHash);
				/*
				 * need to reconnect
				 */
				(void) close(gbl_TCPSocket);
				gbl_TCPSocket = -1;
			}
			continue;
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		packet = (AAA_Packet *)buffer;

		commandCode = ntohl(packet->commandCode);
		/*
		 * First, lookup this in our hash, and update the handle
		 * if necessary.
		 */
		mobileNodeNAI = aaaFindAvpPtr(packet, MOBILE_NODE_NAI,
			&mobileNodeNAILen);
		if ((mobileNodeNAI == NULL) || (mobileNodeNAILen == 0)) {
			/* Malformed packet */
			syslog(LOG_ERR,
				"Error: bad packet(no MOBILE_NODE_NAI)");
			continue;
		}

		switch (commandCode) {
		case MOBILE_IP_OPEN_SESSION_ANSWER:
			/* Update the handle in the hash */

			NaiEntry = aaaUpdateHash(packet, mobileNodeNAI,
			    mobileNodeNAILen);
			if (NaiEntry == NULL) {
				syslog(LOG_ERR,
				    "Error: Received packet for "
				    "non-pending NAI (ANSWER)");
				continue;
			}
			(void) rw_unlock(&NaiEntry->aaaNodeLock);

			/* Check for a good result code */
			resultCode = checkResultCode(packet);
			if (resultCode != 0) {
				mipverbose(("result code was %d\n",
				    resultCode));


				/*
				 * Remember we had preserved the messageHdr
				 * if Radius used, let's free it now.
				 */
				if (aaaProtocol == RADIUS) {
				    (void) rw_wrlock(&NaiEntry->aaaNodeLock);
				    msgHdr = (MessageHdr *)NaiEntry->messageHdr;
				    processAuthFailure(msgHdr, mobileNodeNAI,
					mobileNodeNAILen, resultCode);

				    msgHdr->dontDeleteNow = _B_FALSE;
				    FreeMessageHdr(msgHdr);
				    NaiEntry->messageHdr = NULL;
				    (void) rw_unlock(&NaiEntry->aaaNodeLock);
				}


			}
			if (aaaProtocol == RADIUS) {

				/*
				 * MOBILE_IP_OPEN_SESSION_ANSWER && RADIUS:
				 *
				 * IS_FROM_HA must be present so that
				 * the mobility agent will know that
				 * this is for the Home Agent vs the
				 * Foreign Agent.
				 *
				 * In this case the IS_FROM_HA means
				 * that this packet is for the Home
				 * Agent (if the value of the AVP is 1).
				 * If the packet is for the Home Agent,
				 * call processOpenSessionAnswerRadiusHA.
				 * If the packet is for the Foreign Agent,
				 * callprocessOpenSessionAnswerRadius().
				 */

			if (!aaaFindAvpInt(packet, IS_FROM_HA, (int *)&forHA)) {
				syslog(LOG_ERR, "ERROR: bad packet"
				    " (no IS_FROM_HA)");
				continue;
			}
			if (forHA == 1) { /* HA */
				processOpenSessionAnswerRadiusHA(packet,
				    mobileNodeNAI, mobileNodeNAILen,
				    NaiEntry, resultCode);
			} else { /* FA */
				processOpenSessionAnswerRadius(packet,
				    mobileNodeNAI, mobileNodeNAILen,
				    NaiEntry);
			}

			} else {
				processOpenSessionAnswer(packet, mobileNodeNAI,
				    mobileNodeNAILen, resultCode);
			}
			break;

		case MOBILE_IP_ACCOUNTING_START_ANSWER:
		case MOBILE_IP_ACCOUNTING_INTERIM_ANSWER:
		case MOBILE_IP_ACCOUNTING_STOP_ANSWER:
			/* Check the handle in the hash */
			NaiEntry = aaaUpdateHash(packet, mobileNodeNAI,
			    mobileNodeNAILen);
			if (NaiEntry == NULL) {
				syslog(LOG_ERR,
				    "Error: Received packet for "
				    "non-pending NAI");
				continue;
			}
			(void) rw_unlock(&NaiEntry->aaaNodeLock);

			/* Check the result code */
			resultCode = checkResultCode(packet);
			if (resultCode != 0) {
				syslog(LOG_ERR, "Error: commandCode: %d"
					" resultCode = %d", commandCode,
					resultCode);
			}
			if (commandCode == MOBILE_IP_ACCOUNTING_STOP_ANSWER) {
				(void) sendCloseSession(packet, mobileNodeNAI,
					mobileNodeNAILen);
			}
			break;

		case MOBILE_IP_CLOSE_SESSION_ANSWER:
			/* Check the handle */
			if ((NaiEntry = aaaUpdateHash(packet, mobileNodeNAI,
			    mobileNodeNAILen)) == NULL) {
				syslog(LOG_ERR,
				    "Error: Received packet for "
				    "non-pending NAI");
				continue;
			}
			(void) rw_unlock(&NaiEntry->aaaNodeLock);
			/* Check the result code */
			resultCode = checkResultCode(packet);
			if (resultCode != 0) {
				syslog(LOG_ERR,
					"Error: ACCOUNTING_START_ANSWER"
					" resultCode = %d", resultCode);
			}
			/* And finally, remove the hash entry */
			(void) removeFromHash(mobileNodeNAI, mobileNodeNAILen);
			break;

		case MOBILE_IP_OPEN_SESSION_INDICATION:
			if (aaaProtocol != DIAMETER) {
				syslog(LOG_ERR,
					"Error: "
					"MOBILE_IP_OPEN_SESSION_INDICATION "
					"AAA protocol should be DIAMETER not "
					"%d", aaaProtocol);
				break;
			}
			/*
			 * We get this message from diameter when we are
			 * acting as a home agent.
			 */
			processOpenSessionIndication(packet, mobileNodeNAI,
				mobileNodeNAILen);
			break;

			/* We should not get these. */
#ifdef TEST_DIAMETER
		case MOBILE_IP_OPEN_SESSION_REQUEST:
			/*
			 * We are faking a diameter connection.  Accept the
			 * OPEN_SESSION, and respond with an OPEN_SESSION
			 * response.  Generate keys too.
			 */
			processOpenSessionRequest(packet, mobileNodeNAI,
				mobileNodeNAILen);
			break;

		case MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE:
			/*
			 * We are faking a diameter connection.  Accept the
			 * OPEN_SESSION_INDICATION_RESPONSE as the foreign
			 * agent, and convert it to a OpenSessionAnswer
			 */
			processOpenSessionIndicationResponse(packet,
				mobileNodeNAI, mobileNodeNAILen);
			break;
#else
		case MOBILE_IP_OPEN_SESSION_REQUEST:
		case MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE:
#endif
		case MOBILE_IP_CLOSE_SESSION_REQUEST:
			/*
			 * AAA server can force mipagent to de-register
			 * a MN. No need to send a Accounting Stop, since
			 * AAA already knows this MN is de-registering.
			 * This message applies to both AAAH and AAAF.
			 */
			homeaddr = aaaFindAvpPtr(packet,
			    MOBILE_NODE_HOME_ADDRESS, &homeaddrLen);
			homeAgentaddr = aaaFindAvpPtr(packet,
			    HOME_AGENT_ADDRESS, &homeaddrLen);

			if (homeaddr == NULL || homeAgentaddr == NULL) {
				result = 1;
				syslog(LOG_ERR,
				    "ERROR: bad packet "
				    "(no agent addresses or homeaddr)");
			} else {
				result = forcefullyDeregisterMN(homeaddr,
				    0, *homeAgentaddr);
			}
			result = sendCloseSessionAnswer(packet, mobileNodeNAI,
			    mobileNodeNAILen, result);
			if (result != 0) {
				syslog(LOG_ERR, "sendto failed at mipagent "
				    "while replying to AAA. ");
			}
			break;

		case MOBILE_IP_ACCOUNTING_START_REQUEST:
		case MOBILE_IP_ACCOUNTING_INTERIM_REQUEST:
		case MOBILE_IP_ACCOUNTING_STOP_REQUEST:
		default:
			syslog(LOG_ERR,
				"Error: Received invalid commandCode <%d>",
				commandCode);
		}
	}

	/* LINTED E_STMT_NOT_REACHED */
	return (NULL);
} /* mainAAAThread */

#ifdef TEST_DIAMETER
/*
 * Function: processOpenSessionRequest
 *
 * Arguments: AAA_Packet *packet, char *mnNAI, size_t mnNAILen
 *
 * Description: This is a DEBUG ONLY routine used to test the code without
 *              DIAMETER.  It should normally be conditionally compiled
 *              OUT of the code.  This routine takes an OpenSessionRequest,
 *              and generates a OpenSessionIndication.  It then calls
 *              processOpenSessionIndication.
 *              THIS ROUTINE DISTRUCTIVELY MODIFIES packet IN PLACE
 *
 * Returns: void
 */
static void
processOpenSessionRequest(AAA_Packet *packet, char *mnNAI, size_t mnNAILen)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *response;
	size_t length;
	unsigned char *regReq;
	size_t regReqLen;
	char *faNai;
	size_t faNaiLen;
	uint32_t numChallengeBytes;
	unsigned char *mnResponse;
	size_t mnResponseLen;
	ipaddr_t homeAddress, homeAgentAddress, foreignAgentAddress;
	uint32_t sessionTimeout;
	uint32_t MNFASpi, FAHASpi, MNHASpi;
	unsigned char MNFAKey[MAX_GENERATE_KEY_LEN];
	unsigned char FAHAKey[MAX_GENERATE_KEY_LEN];
	unsigned char MNHAKey[MAX_GENERATE_KEY_LEN];
	/* These are encrypted versions of the above */
	unsigned char HAFAKey[MAX_GENERATE_KEY_LEN];
	unsigned char FAMNKey[MAX_GENERATE_KEY_LEN];
	unsigned char HAMNKey[MAX_GENERATE_KEY_LEN];

	/* FOREIGN_AGENT_NAI */
	faNai = aaaFindAvpPtr(packet, FOREIGN_AGENT_NAI, &faNaiLen);
	if (!faNai || !faNaiLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no FOREIGN_AGENT_NAI)");
		return;
	}

	/* REGISTRATION_REQUEST */
	regReq = aaaFindAvpPtr(packet, REGISTRATION_REQUEST, &regReqLen);
	if (!regReq || !regReqLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no REGISTRATION_REQUEST)");
		return;
	}

	/* NUMBER_OF_CHALLENGE_BYTES_IN_RR */
	if (!aaaFindAvpInt(packet,
	    NUMBER_OF_CHALLENGE_BYTES_IN_RR, &numChallengeBytes)) {
		syslog(LOG_ERR, "ERROR: bad packet (no "
		    "NUMBER_OF_CHALLENGE_BYTES_IN_RR)");
		return;
	}

	/* MOBILE_NODE_RESPONSE */
	mnResponse = aaaFindAvpPtr(packet, MOBILE_NODE_RESPONSE,
		&mnResponseLen);
	if (!mnResponse || !mnResponseLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no MOBILE_NODE_RESPONSE)");
		return;
	}

	/* MOBILE_NODE_HOME_ADDRESS */
	if (!aaaFindAvpInt(packet, MOBILE_NODE_HOME_ADDRESS,
	    &homeAddress)) {
		syslog(LOG_ERR,
		    "ERROR: bad packet (no MOBILE_NODE_HOME_ADDRESS)");
		return;
	}

	/* HOME_AGENT_ADDRESS */
	if (!aaaFindAvpInt(packet, HOME_AGENT_ADDRESS,
	    &homeAgentAddress)) {
		syslog(LOG_ERR, "ERROR: bad packet (no HOME_AGENT_ADDRESS)");
		return;
	}

	/* FOREIGN_AGENT_ADDRESS */
	if (!aaaFindAvpInt(packet, FOREIGN_AGENT_ADDRESS,
	    &foreignAgentAddress)) {
		syslog(LOG_ERR,
			"ERROR: bad packet (no FOREIGN_AGENT_ADDRESS)");
		return;
	}

	/* ******** Build Fake Packet ******** */

	/*
	 * Generate our keys
	 */
	aaaGenerateKey(FAHAKey, MAX_GENERATE_KEY_LEN);
	aaaGenerateKey(MNFAKey, MAX_GENERATE_KEY_LEN);
	aaaGenerateKey(MNHAKey, MAX_GENERATE_KEY_LEN);

	/* These should be computed.  (MD5?)  */
	aaaGenerateKey(HAFAKey, MAX_GENERATE_KEY_LEN);
	aaaGenerateKey(FAMNKey, MAX_GENERATE_KEY_LEN);
	aaaGenerateKey(HAMNKey, MAX_GENERATE_KEY_LEN);

	MNFASpi = aaaGenerateSpi();
	FAHASpi = aaaGenerateSpi();
	MNHASpi = aaaGenerateSpi();


	/* Build our response (An OpenSessionIndication) */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	response = (AAA_Packet *)buffer;
	response->commandCode = htonl(MOBILE_IP_OPEN_SESSION_INDICATION);
	response->handle = packet->handle; /* assume ordered correctly */

	length = sizeof (AAA_Packet);

	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
		MAX_TCP_LEN - length, mnNAI, mnNAILen);

	/* Foreign Agent NAI */
	length += aaaAddAvp(FOREIGN_AGENT_NAI, &buffer[length],
		MAX_TCP_LEN - length, maNai, strlen(maNai));

	/* Foreign Agent Address */
	length += aaaAddAvp(FOREIGN_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &foreignAgentAddress, sizeof (uint32_t));

	/* Registration Request Packet */
	length += aaaAddAvp(REGISTRATION_REQUEST, &buffer[length],
		MAX_TCP_LEN - length, regReq, regReqLen);

	/* Mobile Node Home Address */
	length += aaaAddAvp(MOBILE_NODE_HOME_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAddress, sizeof (uint32_t));

	/* Home Agent Address */
	length += aaaAddAvp(HOME_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAgentAddress, sizeof (uint32_t));

	/* fa-ha spi */
	length += aaaAddAvp(FA_HA_SPI, &buffer[length],
		MAX_TCP_LEN - length, &FAHASpi, sizeof (uint32_t));

	/* FA-HA key */
	length += aaaAddAvp(FA_HA_KEY, &buffer[length],
		MAX_TCP_LEN - length, &FAHAKey, MAX_GENERATE_KEY_LEN);

	/* HA-FA Key */
	length += aaaAddAvp(HA_FA_KEY, &buffer[length],
		MAX_TCP_LEN - length, &HAFAKey, MAX_GENERATE_KEY_LEN);

	/* MN-FA SPI */
	length += aaaAddAvp(MN_FA_SPI, &buffer[length],
		MAX_TCP_LEN - length, &MNFASpi, sizeof (uint32_t));

	/* MN-FA key */
	length += aaaAddAvp(MN_FA_KEY, &buffer[length],
		MAX_TCP_LEN - length, &MNFAKey, MAX_GENERATE_KEY_LEN);

	/* FA-MN Key */
	length += aaaAddAvp(FA_MN_KEY, &buffer[length],
		MAX_TCP_LEN - length, &FAMNKey, MAX_GENERATE_KEY_LEN);

	/* MN-HA SPI */
	length += aaaAddAvp(MN_HA_SPI, &buffer[length],
		MAX_TCP_LEN - length, &MNHASpi, sizeof (uint32_t));

	/* MN-HA key */
	length += aaaAddAvp(MN_HA_KEY, &buffer[length],
		MAX_TCP_LEN - length, &MNHAKey, MAX_GENERATE_KEY_LEN);

	/* HA-MN Key */
	length += aaaAddAvp(HA_MN_KEY, &buffer[length],
		MAX_TCP_LEN - length, &HAMNKey, MAX_GENERATE_KEY_LEN);

	/* Send a fake session time out */
	sessionTimeout = 60;
	length += aaaAddAvp(SESSION_TIMEOUT, &buffer[length],
		MAX_TCP_LEN - length, &sessionTimeout, sizeof (uint32_t));

	response->length = htonl(length);


	processOpenSessionIndication(response, mnNAI, mnNAILen);
} /* processOpenSessionRequest */

/*
 * Function: processOpenSessionIndicationResponse
 *
 * Arguments: AAA_Packet *packet
 *
 * Description: This function will handle converting packets from
 *              OpenSessionIndicationResponses into OpenSessionAnswers,
 *              for testing without diameter.  (This is the foreign agent
 *              side catching the home agent's response.)
 *
 * Returns: void
 */
static void
processOpenSessionIndicationResponse(AAA_Packet *packet, char *mnNAI,
	size_t mnNAILen)
{
	mipverbose(("Processing OpenSessionIndicationResponse (DEBUG)\n"));

	processOpenSessionAnswer(packet, mnNAI, mnNAILen, 0);
} /* processOpenSessionIndicationResponse */
#endif  /* TEST_DIAMETER */

/*
 * Setup the basic message handling fields. I think that we
 * could possibly re-use ifEntry here as a pointer back to the
 * AAA server. Otherwise, we can create a new field in the
 * message header structure.
 */

static void
aaaSetupMessageHdr(MessageHdr *messageHdr, uint32_t resultCode)
{
	messageHdr->pktSource = MIP_PKT_FROM_AAA;
	messageHdr->ifType = ON_UNICAST_SOCK;
	messageHdr->pktType = PKT_UDP;
	messageHdr->ifEntry = getFirstInterface();
	messageHdr->aaaResultCode = resultCode;

} /* aaaSetupMessageHdr */

/*
 * Function: processOpenSessionAnswer
 *
 * Arguments: AAA_Packet *packet
 *
 * Description: This function handles the message to the foreign node, from
 *              DIAMETER.
 *
 * Returns: void
 */
static void
/* LINTED E_FUNC_ARG_UNUSED */
processOpenSessionAnswer(AAA_Packet *packet, char *mnNAI, size_t mnNAILen,
    uint32_t resultCode)
{
	static MessageHdr *messageHdr = NULL;
	unsigned char *FAMNKey, *FAHAKey;
	size_t FAMNKeyLen = 0, FAHAKeyLen = 0;
	uint32_t FAHASpi = 0, FAMNSpi = 0;
	uint32_t sessionTimeout = 0;
	unsigned char *regResponse;
	size_t regResponseLen;

	/* Check the SessionTimeout */
	if (!aaaFindAvpInt(packet, SESSION_TIMEOUT, (int *)&sessionTimeout)) {
		/* BAD error . . . malformed packet */
		syslog(LOG_ERR, "ERROR: bad packet (no SESSION_TIMEOUT)");
	}

	/* Now, make sure we have a response field */
	regResponse = aaaFindAvpPtr(packet, REGISTRATION_REPLY,
		&regResponseLen);

	if (!regResponse) {
		syslog(LOG_ERR, "ERROR: bad packet (no REGISTRATION_REPLY)");
	}

	/* FA-HA Spi */
	if (!aaaFindAvpInt(packet, FA_HA_SPI, (int *)&FAHASpi)) {
		syslog(LOG_ERR, "ERROR: bad packet (no FA_HA_SPI)");
	}
	/* FA-HA Key */
	FAHAKey = aaaFindAvpPtr(packet, FA_HA_KEY, &FAHAKeyLen);
	if (!FAHAKey || !FAHAKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no FA_HA_KEY)");
	}
	/* MN-FA Spi */
	if (!aaaFindAvpInt(packet, MN_FA_SPI, (int *)&FAMNSpi)) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_FA_SPI)");
	}
	/* MN-FA Key */
	FAMNKey = aaaFindAvpPtr(packet, FA_MN_KEY, &FAMNKeyLen);
	if (!FAMNKey || !FAMNKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_FA_KEY)");
	}

	/* Session Timeout */
	if (!aaaFindAvpInt(packet, SESSION_TIMEOUT, (int *)&sessionTimeout)) {
		/* BAD error . . . malformed packet */
		syslog(LOG_ERR, "ERROR: bad packet (no SESSION_TIMEOUT)");
	}

	/*
	 * Create our keys
	 */
	if ((FAMNKeyLen != 0) &&
	    (aaaCreateKey(FAMNSpi, FAMNKey, FAMNKeyLen, sessionTimeout) < 0)) {
		syslog(LOG_ERR, "Error: Invalid MN-FA SPI/Key pair");
	}

	if ((FAHAKeyLen != 0) &&
	    (aaaCreateKey(FAHASpi, FAHAKey, FAHAKeyLen, sessionTimeout) < 0)) {
		syslog(LOG_ERR, "Error: Invalid FA-HA SPI/Key pair");
	}

	aaaCreateAgent(packet, HOME_AGENT_ADDRESS, FAHASpi, sessionTimeout);

	/*
	 * If we don't already have a message header,
	 * allocate one.
	 */
	if (messageHdr == NULL) {
		if ((messageHdr = AllocateMessageHdr()) == NULL) {
			syslog(LOG_CRIT,
				"Unable to allocate a message header");
			return;
		}
	}
	aaaSetupMessageHdr(messageHdr, resultCode);
	(void) memcpy(messageHdr->pkt, regResponse, regResponseLen);
	messageHdr->pktLen = regResponseLen;

	messageHdr->mnFaSPI = FAMNSpi;
	messageHdr->aaaSessionTimeout = sessionTimeout;

	/*
	 * Dispatch the message!
	 */
	(void) dispatchMsgToThread(&messageHdr);
} /* processOpenSessionAnswer */

/*
 * Function: processOpenSessionAnswerRadius
 *
 * Arguments: AAA_Packet *packet, char *mnNAI, size_t mnNAILen
 *
 * Description: This function handles the message to the FA, from
 *              RADIUS.
 *
 * Returns: void
 */
static void
processOpenSessionAnswerRadius(AAA_Packet *packet, char *mnNAI, size_t mnNAILen,
    AAA_HashEntry *NaiEntry)
{
	MessageHdr *msgHdr;
	regRequest *requestPtr;
	uint32_t revtun;
	int code = 0;

	mipverbose(("Processing OpenSessionAnswer for RADIUS (FA Side)\n"));

	/*
	 * We are here after seeing that the FA received a positive response
	 * from the RADIUS server. That completes the auth check for the MN
	 * which is attempting to register through this FA. Now we need to go
	 * back and forward this registration request to HA.
	 *
	 * We shouldn't get any lifetime info from Radius server. FA has been
	 * advertising the lifetime value it's willing to support. It has also
	 * already rejected if MN was asking more than that. Now Radius server
	 * coming along and forcing FA to lower the lifetime doesn't make sense,
	 * and not compliant with RFC2002.
	 *
	 * If we use this function for HA, it's a different story. Radius has
	 * the authority to dictate lifetime.
	 */

	/*
	 * Let's make sure this is not a replay of an already recevied
	 * OpenSessionAnswer. If we had freed the msgHdr before, that means
	 * this is a replay (not necessarily an attack :).
	 */
	(void) rw_rdlock(&(NaiEntry->aaaNodeLock));
	msgHdr = (MessageHdr *)NaiEntry->messageHdr;
	if (msgHdr == NULL) {
		mipverbose(("This was a repeat OpenSessionAnswer\n"));
		(void) rw_unlock(&NaiEntry->aaaNodeLock);
		return;
	}

	/* REV_TUN */
	if (!aaaFindAvpInt(packet, REV_TUN, (int *)&revtun) ||
	    (revtun != REVTUN_REQUIRED && revtun != REVTUN_NOTREQUIRED)) {
		syslog(LOG_ERR,
		    "ERROR: OpenSessionAnswer (no or bad REV_TUN)");
		if (revtun != 0) {
			syslog(LOG_ERR,
			    "ERROR: OpenSessionAnswer bad REV_TUN value %d\n",
			    revtun);
		} else {
			syslog(LOG_ERR,
			    "ERROR: OpenSessionAnswer (no REV_TUN)");
		}
		(void) rw_unlock(&NaiEntry->aaaNodeLock);
		return;
	}
	/*
	 * Check if revtun value matches with T bit value of request.
	 * FAprocessRegRequest already checks first whether
	 * FA supports Reverse tunnel when there is a request
	 * with T bit. According to IS-835, the rule for radius:
	 * revtun = 0; Reverse tunnel is not required
	 * revtun = 1; Reverse tunnel is required
	 * So, if FA is reverse tunnel capable, we allow reverse tunnel
	 * when revtun = REVTUN_NOTREQUIRED(0) and MN requests reverse tunnel
	 */
	mipverbose(("Radius returned REV_TUN value %d", revtun));
	/* LINTED */
	requestPtr = (regRequest *) msgHdr->pkt;
	if (!(requestPtr->regFlags & REG_REVERSE_TUNNEL) &&
	    revtun == REVTUN_REQUIRED) {
		/*
		 * AAA recommends reverse tunnel for this MN, it must
		 * request reverse tunnel in registration request
		 */
		mipverbose(("Mobile node must request reverse tunnel\n"));
		code = FA_REVERSE_TUNNEL_REQUIRED;
		faCounters.faReverseTunnelRequiredCnt++;
	}
	/* Release Read lock now */
	(void) rw_unlock(&NaiEntry->aaaNodeLock);

	if (code == FA_REVERSE_TUNNEL_REQUIRED) {
		FaVisitorEntry *visitor_entry = NULL;

		(void) rw_wrlock(&NaiEntry->aaaNodeLock);
		(void) rejectFromFAToMN(msgHdr, msgHdr->ifEntry, code);

		/* Cleanup the pending visitor entry now */
		visitor_entry = findHashTableEntryString(&faVisitorHash,
		    (unsigned char *)mnNAI, mnNAILen, LOCK_WRITE,
		    mkPendingFAVEHashLookup, _B_FALSE, 0, 0);
		if (visitor_entry != NULL) {
			/* Pending entry found */
			delFAVE(&faVisitorHash, &visitor_entry,
			    requestPtr->homeAddr, REG_REVOKED);
		}
		msgHdr->dontDeleteNow = _B_FALSE;
		FreeMessageHdr(msgHdr);
		NaiEntry->messageHdr = NULL;
		(void) rw_unlock(&NaiEntry->aaaNodeLock);
		return;
	}


	(void) forwardFromFAToHA(msgHdr, msgHdr->ifEntry, _B_TRUE);

	/*
	 * Now we are done with the messageHdr stored in NaiEntry, let's
	 * free it, as we promised before.
	 */
	(void) rw_wrlock(&NaiEntry->aaaNodeLock);
	msgHdr->dontDeleteNow = _B_FALSE;
	FreeMessageHdr(msgHdr);
	NaiEntry->messageHdr = NULL;
	(void) rw_unlock(&NaiEntry->aaaNodeLock);

} /* processOpenSessionAnswerRadius */


/*
 * Function: processOpenSessionAnswerRadiusHA
 *
 * Arguments: AAA_Packet *packet, char *mnNAI, size_t mnNAILen, uint32_t
 *            resultCode
 *
 * Description: This function handles the message to the HA, from
 *              RADIUS client.
 *
 * Returns: void
 */
/* ARGSUSED */
static void
processOpenSessionAnswerRadiusHA(AAA_Packet *packet, char *mnNAI,
    size_t mnNAILen, AAA_HashEntry *NaiEntry, uint32_t resultCode)
{
	static MessageHdr *messageHdr = NULL;
	regRequest *requestPtr;
	uint32_t sessionTimeout = 0;
	uint32_t revtun;
	uint32_t MNHASpi;
	unsigned char *MNHAKey;
	size_t MNHAKeyLen;
	int code = 0;

	/*
	 * AVPs expected to receive:
	 *
	 * SESSION_TIMEOUT
	 * MN_HA_SPI
	 * MN_HA_KEY
	 * HOME AGENT ADDRESS
	 * Mobile Node Home Address
	 */
	mipverbose(("Processing OpenSessionAnswer for RADIUS (HA Side)\n"));

	/*
	 * Let's make sure this is not a replay of an already recevied
	 * OpenSessionAnswer. If we had freed the messsageHdr before, that means
	 * this is a replay (not necessarily an attack :).
	 */
	(void) rw_rdlock(&(NaiEntry->aaaNodeLock));
	messageHdr = (MessageHdr *)NaiEntry->messageHdr;
	if (messageHdr == NULL) {
		mipverbose(("This was a repeat OpenSessionAnswer\n"));
		(void) rw_unlock(&NaiEntry->aaaNodeLock);
		return;
	}
	(void) rw_unlock(&NaiEntry->aaaNodeLock);

	/* Check the SessionTimeout */
	if (!aaaFindAvpInt(packet, SESSION_TIMEOUT, (int *)&sessionTimeout)) {
		/* BAD error . . . malformed packet */
		syslog(LOG_ERR, "ERROR: bad packet (no SESSION_TIMEOUT)");
		code = HA_MN_AUTH_FAILURE;
	}

	/* MN-HA Spi */
	if (!aaaFindAvpInt(packet, MN_HA_SPI, (int *)&MNHASpi)) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_HA_SPI)");
		code = HA_MN_AUTH_FAILURE;
	}
	/* MN-HA Key */
	MNHAKey = aaaFindAvpPtr(packet, MN_HA_KEY, &MNHAKeyLen);
	if (!MNHAKey || !MNHAKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_HA_KEY)");
		code = HA_MN_AUTH_FAILURE;
	}

	/* REV_TUN */
	if (!aaaFindAvpInt(packet, REV_TUN, (int *)&revtun) ||
	    (revtun != REVTUN_REQUIRED && revtun != REVTUN_NOTREQUIRED)) {
		syslog(LOG_ERR,
		    "ERROR: bad packet (no or bad REV_TUN from RADIUS)");
		if (revtun != 0) {
			syslog(LOG_ERR,
			    "ERROR: REV_TUN value %d\n", revtun);
		} else {
			syslog(LOG_ERR,
			    "ERROR: (no REV_TUN from RADIUS)");
		}
		code = HA_MN_AUTH_FAILURE;
	} else {
		mipverbose(("processOpenSessionAnswerHA:"
		    "HA received reverse tunnel value from RADIUS %d\n",
		    revtun));
		/* Found valid revtun entry */
		(void) rw_rdlock(&NaiEntry->aaaNodeLock);
		/* LINTED */
		requestPtr = (regRequest *) messageHdr->pkt;
		if (!(requestPtr->regFlags & REG_REVERSE_TUNNEL) &&
		    revtun == REVTUN_REQUIRED) {
			mipverbose(("processOpenSessionAnswerHA:"
			    "T bit required in regRequest\n"));
			code = HA_REVERSE_TUNNEL_REQUIRED;
		}
		(void) rw_unlock(&NaiEntry->aaaNodeLock);
	}

	if (aaaCreateKey(MNHASpi, MNHAKey, MNHAKeyLen, sessionTimeout) < 0) {
		syslog(LOG_ERR, "Error: Invalid MN-HA SPI/Key pair");
		code = HA_MN_AUTH_FAILURE;
	}

	if (code == 0)
		code = resultCode; /* resultCode is from pkt from Radius */

	(void) rw_wrlock(&NaiEntry->aaaNodeLock);
	messageHdr->pktSource = MIP_PKT_FROM_RADIUS;
	messageHdr->ifType = ON_UNICAST_SOCK;
	messageHdr->pktType = PKT_UDP;
	messageHdr->aaaResultCode = code;

	messageHdr->mnAAASPI = 0;
	messageHdr->algorithm = MD5;
	messageHdr->mnHaSPI = MNHASpi;
	(void) memcpy(messageHdr->mnHaKey, MNHAKey, MNHAKeyLen);
	messageHdr->mnHaKeyLen = MNHAKeyLen;

	messageHdr->aaaSessionTimeout = sessionTimeout;

	(void) rw_unlock(&NaiEntry->aaaNodeLock);

	/*
	 * Dispatch the message!
	 */
	(void) dispatchMsgToThread(&messageHdr);
} /* processOpenSessionAnswerRadiusHA */

/*
 * Function: processOpenSessionIndication
 *
 * Arguments: AAA_Packet *packet, char *mnNAI, size_t mnNAILen
 *
 * Description: This routine will handle the OPEN_SESSION_INDICATION message.
 *              (The message from Diameter to the Home Agent)
 *
 * Returns: void
 */
static void
processOpenSessionIndication(AAA_Packet *packet, char *mnNAI, size_t mnNAILen)
{
	static MessageHdr *messageHdr = NULL;
	unsigned char *regReq;
	size_t regReqLen;
	char *faNai;
	size_t faNaiLen;
	ipaddr_t homeAddress, homeAgentAddress, foreignAgentAddress;
	uint32_t sessionTimeout;
	uint32_t FAHASpi, MNHASpi;
	unsigned char *MNFAKey;
	size_t MNFAKeyLen;
	unsigned char *MNHAKey;
	size_t MNHAKeyLen;
	/* These are encrypted versions of the above */
	unsigned char *HAFAKey;
	size_t HAFAKeyLen;
	unsigned char *HAMNKey;
	size_t HAMNKeyLen;

	/*
	 * Initialize hash on HA side.
	 */
	/* Check to see if we are initialized */
	if (!gbl_hashInitialized) {
		(void) InitHash(&naiHash);
		naiHash.uniqueData = 1; /* Set our unique flag */
		gbl_hashInitialized = 1;
	}

	(void) hexdump("Got message:", (unsigned char *)packet,
		ntohl(packet->length));

	/* FOREIGN_AGENT_NAI */
	faNai = aaaFindAvpPtr(packet, FOREIGN_AGENT_NAI, &faNaiLen);
	if (!faNai || !faNaiLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no FOREIGN_AGENT_NAI)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-1, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* REGISTRATION_REQUEST */
	regReq = aaaFindAvpPtr(packet, REGISTRATION_REQUEST, &regReqLen);
	if (!regReq || !regReqLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no REGISTRATION_REQUEST)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-2, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* MOBILE_NODE_HOME_ADDRESS */
	if (!aaaFindAvpInt(packet, MOBILE_NODE_HOME_ADDRESS,
	    (int *)&homeAddress)) {
		syslog(LOG_ERR,
		    "ERROR: bad packet (no MOBILE_NODE_HOME_ADDRESS)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
		    -3, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* HOME_AGENT_ADDRESS */
	if (!aaaFindAvpInt(packet,
	    HOME_AGENT_ADDRESS, (int *)&homeAgentAddress)) {
		syslog(LOG_ERR, "ERROR: bad packet (no HOME_AGENT_ADDRESS)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-4, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* FOREIGN_AGENT_ADDRESS */
	if (!aaaFindAvpInt(packet, FOREIGN_AGENT_ADDRESS,
	    (int *)&foreignAgentAddress)) {
		syslog(LOG_ERR,
		    "ERROR: bad packet (no FOREIGN_AGENT_ADDRESS)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
		    -5, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* FA-HA Spi */
	if (!aaaFindAvpInt(packet, FA_HA_SPI, (int *)&FAHASpi)) {
		syslog(LOG_ERR, "ERROR: bad packet (no "
			"FA_HA_SPI)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-6, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* HA-FA Key */
	HAFAKey = aaaFindAvpPtr(packet, HA_FA_KEY, &HAFAKeyLen);
	if (!HAFAKey || !HAFAKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no HA_FA_KEY)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-8, mnNAI, mnNAILen, packet->handle);
		return;
	}


	/* MN-FA Key */
	MNFAKey = aaaFindAvpPtr(packet, MN_FA_KEY, &MNFAKeyLen);
	if (!MNFAKey || !MNFAKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_FA_KEY)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-10, mnNAI, mnNAILen, packet->handle);
		return;
	}
	/* MN-HA Spi */
	if (!aaaFindAvpInt(packet, MN_HA_SPI, (int *)&MNHASpi)) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_HA_SPI)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
		    -12, mnNAI, mnNAILen, packet->handle);
		return;
	}
	/* MN-HA Key */
	MNHAKey = aaaFindAvpPtr(packet, MN_HA_KEY, &MNHAKeyLen);
	if (!MNHAKey || !MNHAKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no MN_HA_KEY)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-13, mnNAI, mnNAILen, packet->handle);
		return;
	}
	/* HA-MN Key */
	HAMNKey = aaaFindAvpPtr(packet, HA_MN_KEY, &HAMNKeyLen);
	if (!HAMNKey || !HAMNKeyLen) {
		syslog(LOG_ERR, "ERROR: bad packet (no HA_MN_KEY)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-14, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/* Session Timeout */
	if (!aaaFindAvpInt(packet, SESSION_TIMEOUT, (int *)&sessionTimeout)) {
		/* BAD error . . . malformed packet */
		syslog(LOG_ERR, "ERROR: bad packet (no SESSION_TIMEOUT)");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-15, mnNAI, mnNAILen, packet->handle);
		return;
	}

	/*
	 *
	 * Add NAI to hash on home agent side so accounting messages
	 * can be generated.
	 */
	(void) addNaiToHash(mnNAI, mnNAILen, NULL, 0, homeAddress,
	    homeAgentAddress, messageHdr);

	/*
	 * Create our keys
	 */
	if (aaaCreateKey(FAHASpi, HAFAKey, HAFAKeyLen, sessionTimeout) < 0) {
		syslog(LOG_ERR, "Error: Invalid FA-HA SPI/Key pair");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-17, mnNAI, mnNAILen, packet->handle);
		return;
	}

	if (aaaCreateKey(MNHASpi, HAMNKey, HAMNKeyLen, sessionTimeout) < 0) {
		syslog(LOG_ERR, "Error: Invalid MN-HA SPI/Key pair");
		aaaSendErrorResponse(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
			-18, mnNAI, mnNAILen, packet->handle);
		return;
	}
	aaaCreateAgent(packet, HOME_AGENT_ADDRESS, FAHASpi, sessionTimeout);

	/*
	 * If we don't already have a message header,
	 * allocate one.
	 */
	if (messageHdr == NULL) {
		if ((messageHdr = AllocateMessageHdr()) == NULL) {
			syslog(LOG_CRIT,
				"Unable to allocate a message header");
			aaaSendErrorResponse(
				MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
				-19, mnNAI, mnNAILen, packet->handle);
			return;
		}
	}
	aaaSetupMessageHdr(messageHdr, 0);
	(void) memcpy(messageHdr->pkt, regReq, regReqLen);
	messageHdr->pktLen = regReqLen;

	/* Don't worry about byte ordering this. */
	messageHdr->messageHandle = packet->handle;

	/* Copy our fa NAI */
	messageHdr->faNAI = malloc(faNaiLen + 1);
	if (messageHdr->faNAI == NULL) {
		syslog(LOG_CRIT,
		    "Unable to allocate a faNAI in message header");
		aaaSendErrorResponse(
		    MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE,
		    -20, faNai, faNaiLen, packet->handle);
		return;
	}

	(void) memcpy(messageHdr->faNAI, faNai, faNaiLen);
	messageHdr->faNAI[faNaiLen] = 0; /* Drop the null */
	messageHdr->faNAILen = faNaiLen;

	messageHdr->mnAAASPI = 0; /* WORK - PRC - where do we get this */
	messageHdr->algorithm = MD5;
	messageHdr->mnHaSPI = MNHASpi;
	(void) memcpy(messageHdr->mnHaKey, MNHAKey, MNHAKeyLen);
	messageHdr->mnHaKeyLen = MNHAKeyLen;

	(void) memcpy(messageHdr->mnFaKey, MNFAKey, MNFAKeyLen);
	messageHdr->mnFaKeyLen = MNFAKeyLen;


	messageHdr->faHaSPI = FAHASpi;

	messageHdr->aaaSessionTimeout = sessionTimeout;
	/*
	 * Dispatch the message!
	 */
	(void) dispatchMsgToThread(&messageHdr);
} /* processOpenSessionIndication */

/*
 * Function: processAuthFailure
 *
 * Arguments:
 *		MessageHdr *  - pointer to message hdr
 *		mnNAI         - nai
 *		mnNAILen      - nai len
 *		result        - result code returned by RADIUS
 *
 * Description: This function will handle a failure.  (will send an error)
 *
 * Returns: void
 */
static void
processAuthFailure(MessageHdr *msgHdr, char *mnNAI, size_t mnNAILen,
    uint32_t result)
{
	uint32_t code;

	syslog(LOG_ERR, "Error: processAuthFailure: %*.*",
	    mnNAILen, mnNAILen, mnNAI);

	switch (result) {
	case MIP_ADMINISTRATIVELY_PROHIBITED:
		code = FA_ADM_PROHIBITED;
		break;
	case MIP_INSUFFICIENT_RESOURCES:
		code = FA_INSUFFICIENT_RESOURCES;
		break;
	case MIP_FAILED_AUTHENTICATION:
		code = FA_MN_AUTH_FAILURE;
		break;
	case MIP_REASON_UNSPECIFIED:
	default:
		code = FA_REASON_UNSPECIFIED;
		break;
	}

	rejectFromFAToMN(msgHdr, msgHdr->ifEntry, code);


} /* processAuthFailure */

#ifdef TEST_DIAMETER
static void
aaaGenerateKey(unsigned char *key, size_t keyLen)
{
	static boolean_t initialized = _B_FALSE;
	int32_t *intPtr;
	int i;

	/* Seed the random number generator once */
	if (initialized == _B_FALSE) {
		srand(time(NULL));
		initialized = _B_TRUE;
	}

	if (keyLen % 4) {
		syslog(LOG_ERR,
			"ERROR: Key length must be a multiple of 4 (len = %d)",
			keyLen);
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	intPtr = (int32_t *)key;

	/* Build the key, 4 bytes at a time */
	for (i = 0; i < (keyLen / 4); i++) {
		intPtr[i] = rand();
	}
} /* aaaGenerateKey */

static uint32_t
aaaGenerateSpi()
{
	static uint32_t SPI = 0x80000000;
	return (SPI++);
} /* return a psuedo random spi */
#endif  /* TEST_DIAMETER */

/*
 * Function: aaaSendRegistrationReply
 *
 * Arguments: MessageHdr *messageHdr
 *
 * Description: This function will lookup the relivant data, and send
 *              a response back to DIAMETER.  This function is called from
 *              the HomeAgent, in response to a OpenSessionIndication.
 *
 * Returns: int
 */
int
aaaSendRegistrationReply(MessageHdr *messageHdr, size_t replyLen,
	ipaddr_t homeAddress, ipaddr_t homeAgentAddress)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *packet;
	uint32_t length;
	int resultCode = 0; /* WORK -- pass this in */

	/* Check to see if we are initialized */
	if (!gbl_hashInitialized) {
		(void) InitHash(&naiHash);
		naiHash.uniqueData = 1; /* Set our unique flag */
		gbl_hashInitialized = 1;
	}

	/* Build the message */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	packet = (AAA_Packet *)buffer;
	packet->protocol = htonl(DIAMETER);
	packet->commandCode =
		htonl(MOBILE_IP_OPEN_SESSION_INDICATION_RESPONSE);

	packet->handle = messageHdr->messageHandle;

	length = sizeof (AAA_Packet);

	/* Add our AVPs */

	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
		MAX_TCP_LEN - length, messageHdr->mnNAI,
		messageHdr->mnNAILen);

	/* Foreign Agent NAI */
	length += aaaAddAvp(FOREIGN_AGENT_NAI, &buffer[length],
		MAX_TCP_LEN - length, messageHdr->faNAI,
		messageHdr->faNAILen);

	/* Registration Reply */
	length += aaaAddAvp(REGISTRATION_REPLY, &buffer[length],
		MAX_TCP_LEN - length, messageHdr->pkt,
		replyLen);

	/* Mobile Node Home Address */
	length += aaaAddAvp(MOBILE_NODE_HOME_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAddress,
		sizeof (ipaddr_t));

	/* Home Agent Address */
	length += aaaAddAvp(HOME_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAgentAddress,
		sizeof (ipaddr_t));

	/* Session Timeout */
	length += aaaAddAvp(SESSION_TIMEOUT, &buffer[length],
		MAX_TCP_LEN - length, &messageHdr->aaaSessionTimeout,
		sizeof (uint32_t));

	/* Result Code */
	length += aaaAddAvp(RESULT_CODE, &buffer[length],
		MAX_TCP_LEN - length, &resultCode,
		sizeof (uint32_t));

	packet->length = htonl(length);

	return (sendTCPPacket(buffer, length));
} /* sendRegistrationReply */

/*
 * Function: AAAAuthenticateRegReq
 *
 * Arguments:
 *
 * Description: This function is called from the foreign agent.  It is the
 *              first function that is called for a given mobile node, so
 *              we do all startup code here.  (We add the entry to the
 *              hash.)
 *
 * Returns: int
 *
 */
int
AAAAuthenticateRegReq(unsigned char *reqPtr, uint32_t reqLen,
    unsigned char *mnNAI, size_t mnNAILen, uint32_t aaaSPI,
    unsigned char *mnChallengeResponse, uint32_t mnChallengeResponseLen,
    uint32_t mnChallengeLen,
    ipaddr_t homeAddress, ipaddr_t homeAgentAddress, boolean_t isFromHA,
    uint32_t inIfindex, void *messageHdr, unsigned char *MNFAChallengeValue,
    uint32_t MNFAChallengeValueLen)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *packet;
	uint32_t length;
	ipaddr_t faAddr;
	uint32_t one = 1;
	uint32_t zero = 0;


	/* Check to see if we are initialized */
	if (!gbl_hashInitialized) {
		(void) InitHash(&naiHash);
		naiHash.uniqueData = 1; /* Set our unique flag */
	}

	/* Build the message */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	packet = (AAA_Packet *)buffer;
	packet->protocol = htonl(aaaProtocol);
	packet->commandCode = htonl(MOBILE_IP_OPEN_SESSION_REQUEST);
	packet->handle = htonl(0);

	length = sizeof (AAA_Packet);

	/* Add our AVPs */

	/*
	 * Radius server needs to know if this is coming from HA,
	 * in which case it'll send back the MN-HA key.
	 */
	if (aaaProtocol == RADIUS) {
		length += aaaAddAvp(IS_FROM_HA, &buffer[length],
		    MAX_TCP_LEN - length,
		    (isFromHA) ? &one : &zero, sizeof (uint32_t));
	}

	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
		MAX_TCP_LEN - length, mnNAI, mnNAILen);

	/* Foreign Agent NAI */
	length += aaaAddAvp(FOREIGN_AGENT_NAI, &buffer[length],
		MAX_TCP_LEN - length, maNai, strlen(maNai));

	/* Foreign Agent Address */
	faAddr = getClosestInterfaceAddr(homeAgentAddress);
	length += aaaAddAvp(FOREIGN_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &faAddr, sizeof (uint32_t));

	/* Registration Request Packet */
	length += aaaAddAvp(REGISTRATION_REQUEST, &buffer[length],
		MAX_TCP_LEN - length, reqPtr, reqLen);

	/* Challenge Bytes */
	length += aaaAddAvp(NUMBER_OF_CHALLENGE_BYTES_IN_RR,
	    &buffer[length], MAX_TCP_LEN - length,
	    &mnChallengeLen, sizeof (uint32_t));

	/* Mobile Node Response */
	length += aaaAddAvp(MOBILE_NODE_RESPONSE,
	    &buffer[length], MAX_TCP_LEN - length,
	    mnChallengeResponse, mnChallengeResponseLen);


	/* Mobile Node Home Address */
	length += aaaAddAvp(MOBILE_NODE_HOME_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAddress, sizeof (uint32_t));

	/* Home Agent Address */
	length += aaaAddAvp(HOME_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAgentAddress, sizeof (uint32_t));

	/* MN-AAA SPI */
	length += aaaAddAvp(MN_AAA_SPI, &buffer[length],
		MAX_TCP_LEN - length, &aaaSPI, sizeof (uint32_t));

	/* Radius needs MN-FA Challenge Value for authentication */
	if (aaaProtocol == RADIUS) {
		length += aaaAddAvp(MN_FA_CHALLENGE_VALUE, &buffer[length],
		    MAX_TCP_LEN - length, MNFAChallengeValue,
		    MNFAChallengeValueLen);
	}

	/* MN_HANDLE (only send if from FA in which case inIfindex is nonzero */
	if (inIfindex != 0) {
		length += aaaAddAvp(MN_HANDLE, &buffer[length],
		    MAX_TCP_LEN - length, &inIfindex, sizeof (uint32_t));
	}

	packet->length = htonl(length);

	/* Add entry to hash */
	if (addNaiToHash((char *)mnNAI, mnNAILen, mnChallengeResponse,
	    mnChallengeResponseLen, homeAddress, homeAgentAddress,
	    messageHdr)) {
			/* Error! */
			return (-1);
	}
	return (sendTCPPacket(buffer, length));
} /* AAAAuthenticateRegReq */

/*
 * Function: sendCloseSession
 *
 * Arguments: AAA_Packet *packet, unsigned char *nai, size_t naiLen
 *
 * Description: This function will send the CLOSE_SESSION message
 *              to AAA server.  It is called by the main thread when an
 *              MOBILE_IP_ACCOUNTING_STOP_ANSWER is received.
 *
 * Returns: int
 */
static int
sendCloseSession(AAA_Packet *srcPacket, char *mnNAI, size_t mnNAILen)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *destPacket;
	size_t length;
	int32_t handle;
	char *faNai;
	size_t faNaiLen;
	ipaddr_t homeAgentAddress, homeAddress;
	uint32_t sessionTime;

	/* Lookup the NAI to make sure it exists. */
	handle = aaaLookupHandle(mnNAI, mnNAILen);
	if (handle < 0) {
		syslog(LOG_ERR, "Error: NAI not found!");
		return (handle);
	}

	/* Retrieve Our Fields */
	faNai = (char *)aaaFindAvpPtr(srcPacket, FOREIGN_AGENT_NAI, &faNaiLen);
	if (!faNai) {
		syslog(LOG_ERR, "Error: Foreign Agent NAI not found!");
		return (-1);
	}

	if (!aaaFindAvpInt(srcPacket, MOBILE_NODE_HOME_ADDRESS,
	    (int *)&homeAddress)) {
		syslog(LOG_ERR, "Error: Home Address not found!");
		return (-1);
	}
	if (!aaaFindAvpInt(srcPacket, HOME_AGENT_ADDRESS,
	    (int *)&homeAgentAddress)) {
		syslog(LOG_ERR, "Error: Home Agent Address not found!");
		return (-1);
	}
	if (!aaaFindAvpInt(srcPacket, SESSION_TIME, (int *)&sessionTime)) {
		syslog(LOG_ERR, "Error: Session Time not found!");
		return (-1);
	}

	/* Build the message */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	destPacket = (AAA_Packet *)buffer;
	destPacket->protocol = htonl(aaaProtocol);
	destPacket->commandCode = htonl(MOBILE_IP_CLOSE_SESSION_REQUEST);
	destPacket->handle = htonl(handle);

	length = sizeof (AAA_Packet);

	/* Add our AVPs */
	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
		MAX_TCP_LEN - length, mnNAI, mnNAILen);

	/* Foreign Agent NAI */
	length += aaaAddAvp(FOREIGN_AGENT_NAI, &buffer[length],
		MAX_TCP_LEN - length, faNai, faNaiLen);

	/* Mobile Node Home Address */
	length += aaaAddAvp(MOBILE_NODE_HOME_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAddress, sizeof (uint32_t));

	/* Home Agent Address */
	length += aaaAddAvp(HOME_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAgentAddress, sizeof (uint32_t));

	/* Mobile Node Session Time */
	length += aaaAddAvp(SESSION_TIME, &buffer[length],
		MAX_TCP_LEN - length, &sessionTime, sizeof (uint32_t));

	destPacket->length = htonl(length);

	return (sendTCPPacket(buffer, length));
} /* sendCloseSession */

static int
sendCloseSessionAnswer(AAA_Packet *srcPacket, char *mnNAI, size_t mnNAILen,
    boolean_t result)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *destPacket;
	size_t length;
	uint32_t resultCode;

	/* LINTED */
	destPacket = (AAA_Packet *)buffer;
	destPacket->protocol = htonl(srcPacket->protocol);
	destPacket->commandCode = htonl(MOBILE_IP_CLOSE_SESSION_ANSWER);
	destPacket->handle = srcPacket->handle;

	length = sizeof (AAA_Packet);

	/* Add our AVPs */

	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
	    MAX_TCP_LEN - length, mnNAI, mnNAILen);

	/* Result code */
	resultCode = result ? 0 : 1;
	length += aaaAddAvp(RESULT_CODE, &buffer[length], MAX_TCP_LEN - length,
	    &resultCode, sizeof (uint32_t));

	destPacket->length = htonl(length);

	return (sendTCPPacket(buffer, length));
}




/*
 * Function: sendAccountingRecord
 *
 * Arguments: commandCode record, unsigned char *mnNAI, size_t mnNAILen,
 *            ipaddr_t homeAddr, ipaddr_t coaAddr,
 *            ipaddr_t homeAgentAddr, int32_t sessionLifetime)
 *
 * Description: This function will send an accounting start record.
 *              ToDo: coaAddr is specified in this function calls' prototype,
 *              but it is not in the diameter api protocol. (PRC TODO)
 *
 * Returns: int
 *
 */
int
sendAccountingRecord(AAA_CommandCode code, unsigned char *mnNAI,
	/* LINTED E_FUNC_ARG_UNUSED */
	size_t mnNAILen, ipaddr_t homeAddress, ipaddr_t coaAddr,
	ipaddr_t homeAgentAddress, uint32_t sessionTime, int32_t relindicator)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *packet;
	uint32_t length;
	int32_t handle;

	/* Lookup the NAI to make sure it exists. */
	handle = aaaLookupHandle((char *)mnNAI, mnNAILen);
	if (handle < 0) {
		syslog(LOG_ERR, "Error: NAI not found!");
		return (handle);
	}

	switch (code) {
		/* These codes are good */
	case MOBILE_IP_ACCOUNTING_START_REQUEST:
	case MOBILE_IP_ACCOUNTING_INTERIM_REQUEST:
	case MOBILE_IP_ACCOUNTING_STOP_REQUEST:
		break;
		/* Everything else is an error */
	default:
		syslog(LOG_ERR, "ERROR: invalid code passed to "
			"sendAccountingRecord (%d)", code);
		return (-1);
	} /* switch code */

	/* Build the message */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	packet = (AAA_Packet *)buffer;
	packet->protocol = htonl(aaaProtocol);
	packet->commandCode = htonl(code);
	packet->handle = htonl(handle);

	length = sizeof (AAA_Packet);

	/* Add our AVPs */

	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
		MAX_TCP_LEN - length, mnNAI, mnNAILen);

	/* Foreign Agent NAI */
	length += aaaAddAvp(FOREIGN_AGENT_NAI, &buffer[length],
		MAX_TCP_LEN - length, maNai, strlen(maNai));

	/* Mobile Node Home Address */
	length += aaaAddAvp(MOBILE_NODE_HOME_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAddress, sizeof (uint32_t));

	/* Home Agent Address */
	length += aaaAddAvp(HOME_AGENT_ADDRESS, &buffer[length],
		MAX_TCP_LEN - length, &homeAgentAddress, sizeof (uint32_t));

	/* Mobile Node Session Time */
	length += aaaAddAvp(SESSION_TIME, &buffer[length],
		MAX_TCP_LEN - length, &sessionTime, sizeof (uint32_t));

	/* Release Indicator (RADIUS ONLY) */
	if (aaaProtocol == RADIUS) {
		length += aaaAddAvp(RELEASE_INDICATOR, &buffer[length],
		    MAX_TCP_LEN - length, &relindicator, sizeof (uint32_t));
	}
	packet->length = htonl(length);

	return (sendTCPPacket(buffer, length));

} /* sendAccountingRecord */

void
aaaSendErrorResponse(uint32_t commandCode, int32_t returnCode, char *mnNAI,
	size_t mnNAILen, uint32_t handle)
{
	unsigned char buffer[MAX_TCP_LEN];
	AAA_Packet *packet;
	uint32_t length;

	/*
	 * If we don't already have a handle, look for it.
	 */
	if (handle == 0) {
		/* Lookup the NAI to make sure it exists. */
		handle = aaaLookupHandle(mnNAI, mnNAILen);
		if (((int)handle) < 0) {
			syslog(LOG_ERR, "Error: NAI not found!");
			handle = 0;
		}
	}

	/* Build the message */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	packet = (AAA_Packet *)buffer;
	/* this function is only used for DIAMETER */
	packet->protocol = htonl(DIAMETER);
	packet->commandCode = htonl(commandCode);
	packet->handle = htonl(handle);

	length = sizeof (AAA_Packet);

	/* Mobile Node NAI */
	length += aaaAddAvp(MOBILE_NODE_NAI, &buffer[length],
		MAX_TCP_LEN - length, mnNAI, mnNAILen);

	/* resultCode */
	length += aaaAddAvp(RESULT_CODE, &buffer[length],
		MAX_TCP_LEN - length, &returnCode, sizeof (uint32_t));

	packet->length = htonl(length);

	/* Send packet */
	(void) sendTCPPacket(buffer, length);
} /* aaaSendErrorResponse */

/*
 * Function: initTCPSocket
 *
 * Arguments: in_port_t port
 *
 * Description: This routine binds a TCP socket to the specified port.
 *
 * Returns: int (the socket fd)
 *
 */
static int
initTCPSocket(in_port_t port)
{
	struct sockaddr_in sin;
	int sinLength;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	int rc;

	/*
	 * Make sure only one thread at a time executes this code.
	 */

	rc = pthread_mutex_lock(&lock);
	if (rc < 0) {
		/* Wierd error! */
		syslog(LOG_CRIT, "initTCPSocket: Error: Unable to lock mutex!");
		return (-1);
	}

	if (gbl_TCPSocket != -1) {
		/* We are already initialized.  Exit */
		syslog(LOG_WARNING,
			"initTCPSocket: Warning: socket already initialized");
		(void) pthread_mutex_unlock(&lock);
		return (gbl_TCPSocket);
	}

	/*
	 * Get a socket.
	 */
	if ((gbl_TCPSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_CRIT,
			"initTCPSocket: socket failed (%d:%s)", errno,
			strerror(errno));
		gbl_TCPSocket = -1;
		(void) pthread_mutex_unlock(&lock);
		return (gbl_TCPSocket);
	}

	/*
	 * Initialize the sockaddr.
	 */
	sinLength = sizeof (struct sockaddr_in);
	(void) memset((char *)&sin, '\0', sinLength);

	/*
	 * Get server's listening port number
	 */
	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(gbl_aaaHost);

	if (connect(gbl_TCPSocket, (struct sockaddr *)&sin, sinLength) < 0) {
		syslog(LOG_ERR,
			"initTCPSocket: connect failed (%d:%s)", errno,
			strerror(errno));
		(void) close(gbl_TCPSocket);
		gbl_TCPSocket = -1;
		(void) pthread_mutex_unlock(&lock);
		return (gbl_TCPSocket);
	}

	/*
	 * If connected, advBusy flag should be set to True.
	 * This code will only be invoked when the connection
	 * is first started or a reconnection happens. Thus,
	 * advBusy can be set/unset for other future purposes
	 * in mipagent.
	 */
	if (advBusy == _B_TRUE) {
		enableService();
	}

	/* Success! */
	(void) pthread_mutex_unlock(&lock);
	return (gbl_TCPSocket);

} /* initTCPSocket */


/*
 * Function: sendTCPPacket
 *
 * Arguments: buffer, length
 *
 * Description: Sends the buffer on the TCP socket, and adds it to the queue
 *
 * Returns: int (zero on success)
 *
 */
static int
sendTCPPacket(unsigned char *buffer, uint32_t length)
{

	int rc;

	/* Make sure the socket is open */
	if (gbl_TCPSocket == -1) {
		(void) initTCPSocket(gbl_aaaPort);
		if (gbl_TCPSocket == -1) {
			return (-1);
		}
	}

	/* finally, send it */
	do {
		rc = send(gbl_TCPSocket, buffer, length, 0);
	} while ((rc == -1) && (errno == EINTR));

	if (rc < 0) {
		syslog(LOG_ERR, "sendTCPPacket: Error: send: !(%d:%s)", errno,
			strerror(errno));
		(void) close(gbl_TCPSocket);
		gbl_TCPSocket = -1;  /* Force a re-connect */
		return (rc);
	}
	return (0);
} /* sendTCPPacket */

/*
 * Function: readTCPPacket
 *
 * Arguments: unsigned char *buffer, uint32_t bufLen
 *
 * Description: Reads from the socket, ignoring EINTR, until a record is
 *              read.  If it gets an error, it closes the socket, which will
 *              be re-opened on the next read or write.
 *
 * Returns: int
 */
static int
readTCPPacket(unsigned char *buffer, uint32_t bufLen)
{
	int rc;

	/* Make sure the socket is open */
	if (gbl_TCPSocket == -1) {
		(void) initTCPSocket(gbl_aaaPort);
		if (gbl_TCPSocket == -1) {
			return (-1);
		}
	}

	/* Read, ignoring EINTRs */
	do {
		rc = recv(gbl_TCPSocket, buffer, bufLen, 0);
	} while ((rc == -1) && (errno == EINTR));

	if (rc == -1) {
		syslog(LOG_ERR, "Error %d reading socket (%d:%s)", rc, errno,
			strerror(errno));
		(void) close(gbl_TCPSocket);
		gbl_TCPSocket = -1;  /* Force a re-connect */
	}

	return (rc);
} /* readTCPPacket */




#ifdef TEST_AAA

#define	TEST_NAI1 "test@sun.com"
#define	TEST_NAI2 "test2@sun.com"
#define	FA_NAI "foreignAgent@agents.everywhere.com"

int
main(int argc, char *argv[])
{
	int rc;
	unsigned char reqPtr[] = {
		/* Just some random data for testing */
		0x1, 0x3, 0x1, 0x3, 0x1, 0x3, 0x1, 0x3, 0x1, 0x3,
		0x1, 0x3, 0x1, 0x3, 0x1, 0x3, 0x1, 0x3, 0x1, 0x3,
		0x1, 0x3, 0x1, 0x3, 0x1, 0x3, 0x1, 0x3, 0x1, 0x3,
		0x1, 0x3 };
	unsigned char mnChallenge[] = {
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa
	};
	ipaddr_t homeAddress;
	ipaddr_t homeAgentAddress;

	if (argc != 2) {
		(void) fprintf(stderr, "USAGE: %s <port>\n", argv[0]);
		return (-1);
	}

	homeAddress = inet_addr("192.168.168.2");
	homeAgentAddress = inet_addr("192.168.168.1");
	gbl_aaaPort = (in_port_t)atoi(argv[1]);

	(void) strcpy(maNai, FA_NAI);

	if ((rc = startAAATaskThread()) != 0) {
		(void) fprintf(stderr,
			"Error: rc = %d when calling startAAATaskThread\n",
			rc);
		return (rc);
	}

	rc = AAAAuthenticateRegReq(reqPtr, sizeof (reqPtr),
	    TEST_NAI1, strlen(TEST_NAI1),
	    mnChallenge, sizeof (mnChallenge),
	    homeAddress, homeAgentAddress, _B_FALSE, NULL);
	if (rc != 0) {
		(void) fprintf(stderr,
			"Error: rc = %d when calling"
			" AAAAuthenticatateRegReq\n", rc);
		/* return (rc); */
	}

	rc = sendAccountingStartRecord((unsigned char *)TEST_NAI1,
		strlen(TEST_NAI1), 0, 1, 2, 3);
	if (rc != 0) {
		(void) fprintf(stderr,
			"Error: rc = %d when calling"
			" sendAccountingStartRecord\n",
			rc);
	}

	(void) fprintf(stderr, "Sleeping for 1\n"); fflush(stderr);
	(void) sleep(1);
	rc = sendAccountingInterimRecord((unsigned char *)TEST_NAI1,
		strlen(TEST_NAI1), 0, 1, 2, 3);
	if (rc != 0) {
		(void) fprintf(stderr, "Error: rc = %d when calling "
			"sendAccountingInterimRecord\n", rc);
	}

	rc = sendAccountingInterimRecord((unsigned char *)TEST_NAI2,
		strlen(TEST_NAI1), 0, 1, 2, 3);
	if (rc == 0) {
		(void) fprintf(stderr, "Error: rc = %d when calling "
			"sendAccountingInterimRecord\n", rc);
	}

	rc = sendAccountingStopRecord((unsigned char *)TEST_NAI1,
		strlen(TEST_NAI1), 0, 1, 2, 3);
	if (rc != 0) {
		(void) fprintf(stderr, "Error: rc = %d when calling "
			"sendAccountingStopRecord\n", rc);
	}

	(void) fprintf(stderr, "Sleeping for a sec . . . ");
	(void) sleep(2);
	(void) fprintf(stderr,
		"Sending a straggling message . . . should be an error\n");
	rc = sendAccountingInterimRecord((unsigned char *)TEST_NAI1,
		strlen(TEST_NAI1), 0, 1, 2, 3);
	if (rc == 0) {
		(void) fprintf(stderr, "Error: rc = %d when calling "
			"sendAccountingInterimRecord\n", rc);
	}

	(void) fprintf(stderr, "Thread hanging . . .\n"); fflush(stderr);
	for (;;) {
		(void) sleep(1); fflush(stderr); fflush(stdout);
	}

	return (rc);
} /* main */

#endif  /* TEST_AAA */

/* fin aaa.c */
