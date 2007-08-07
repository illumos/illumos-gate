/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley. The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: agent.c
 *
 * This file contains the routines used to parse and process the
 * Mobile-IP registration request and reply, as well as the routines
 * used to manage the visitor and binding entries.
 *
 * This file contains the main mipagent routine.
 */

#include <stdio.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/sysmacros.h>
#include <md5.h>
#include <locale.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/dlpi.h>
#include <stropts.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "mip.h"
#include "agent.h"
#ifdef RADIUS_ENABLED
#include "radlib.h"
#endif /* RADIUS_ENABLED */
#include "auth.h"
#include "pool.h"
#include "setup.h"
#include "hash.h"
#include "agentKernelIntfce.h"
#include "conflib.h"
#include "mipagentstat_door.h"

/* Controls verbosity of debug messages when compiled w/ "-D MIP_DEBUG" */
int logVerbosity = 0;

int IDfreshnessSlack = DEFAULT_FRESHNESS_SLACK;
/*
 * We no longer use regLifetime global
 */
int advLifetime = DEFAULT_MAX_ADV_TIME;
int periodicInterval = DEFAULT_GARBAGE_COLLECTION_INTERVAL;

int visitorEntryHighWaterMark = DEFAULT_HIGH_VISITORS;
int visitorEntryLowWaterMark = DEFAULT_LOW_VISITORS;
int performanceInterval = 0;
boolean_t faNAIadv = _B_FALSE;		/* Determines whether we advertise */
					/* our NAI */
boolean_t faChallengeAdv = _B_FALSE;	/* Determines whether we advertise */
					/* challenges */
boolean_t mfAuthRequired = _B_FALSE;	/* Is the MF Authentication Ext    */
					/* Required? */
boolean_t fhAuthRequired = _B_FALSE;	/* Is the FH Authentication Ext    */
					/* Required? */
AAA_Protocol_Code aaaProtocol = AAA_NONE;	/* AAA_NONE, DIAMETER, RADIUS */

boolean_t shutdown_flag = _B_FALSE;	/* Are we shutting down? */
boolean_t daemonize = _B_TRUE;		/* By default, we are a daemon */
boolean_t disableSNMP = _B_FALSE;	/* By default, SNMP is enabled */

/* these are the IPsec install and remove policy commands */
char *ipsec_policy_action[] = {
	"/usr/sbin/ipsecconf -a /dev/stdin -q",
	"/usr/sbin/ipsecconf -r /dev/stdin -q",
	NULL
};

/* these expand the same index of policy to what it means to humans */
char *ipsec_policy_string[] = {
	"registration request apply policy",
	"registration reply apply policy",
	"tunnel apply policy",
	"reverse tunnel apply policy",
	"registration request permit policy",
	"registration reply permit policy",
	"tunnel permit policy",
	"reverse tunnel permit policy",
	NULL
};

#define	BUCKET	0   /* Bucket in hashtable to start enumeration at */
#define	OFFSET	1   /* Offset within BUCKET to start enumeration at */
#define	PERF_MSG_SIZE	256

#ifdef RADIUS_ENABLED
/* Radius Variables */
int radiusEnabled = 0;
#define	RADIUS_LOOKUP_TIME	60
#define	RADIUS_DEBUG
char radiusSharedLibrary[MAX_FN_LEN];
int (*radInitializeApi)();
int (*radLookupData)(char **sessionId, char *key, RadData *dest);
int (*radCloseSession)(char *sessionId, char *key, void *accountingInfo);
#endif /* RADIUS_ENABLED */

/*
 * Default Values...
 */
uint32_t defaultPool = 0;
uint32_t defaultNodeSPI = 0;


/* ----------------- Common to all mobility agents ------------------- */
/*
 * This table stores configuration information about agent
 * advertisements. There's one entry for each mobility
 * supporting interface.
 */
HashTable maAdvConfigHash;

/*
 * This table stores all of the Security Violations
 */
HashTable mipSecViolationHash;

/*
 * This table stores all of the Security Assocations
 */
HashTable mipSecAssocHash;

/*
 * This table has one entry for each known Mobility Agent
 */
HashTable mipAgentHash;

/*
 * This table has one entry for each active tunnel number
 */
HashTable mipTunlHash;

/*
 * Counters common to all Mobility Agents
 */
CommonCounters commonCounters;


char maNai[MAX_NAI_LENGTH];

/*
 * This table has one entry for each pool defined in the config file
 */
HashTable mipPoolHash;

/* ------------------ Specific to foreign agents -------------------- */
/*
 * This table stores information about visitors for which this
 * mobility agent is a foreign agent. Some of the entries may
 * correspond to unfulfilled registration requests.
 */
HashTable faVisitorHash;

/*
 * Counters maintained by Foreign Agents
 */
ForeignAgentCounters faCounters;

/*
 * We need to keep track of the last two Challenge Values that
 * we have advertised in order to check for replays.
 */
char faLastChallengeIssued[2][ADV_CHALLENGE_LENGTH];

/* ------------------ Specific to home agents -------------------- */
/*
 * This table has one entry for each mobile node for which a mobility
 * agent offers Home Agent services.
 */

HashTable haMobileNodeHash;


/*
 * Counters maintained by Home Agents
 */
HomeAgentCounters haCounters;

/* Security related stuff */
#ifdef FIREWALL_SUPPORT
DomainInfo domainInfo;
#endif /* FIREWALL_SUPPORT */
/* ----------------------------------------------------------------- */

extern int Initialize(char *configFile);
extern void printBuffer(unsigned char *, int);
extern int  sendUDPmessage(int, unsigned char *, int, ipaddr_t, in_port_t);
extern boolean_t HAisIDok(uint32_t, uint32_t, uint32_t, uint32_t, int);
extern void HAnewID(uint32_t *, uint32_t *, uint32_t, uint32_t, int, boolean_t);
extern void HAstoreID(uint32_t *, uint32_t *, uint32_t, uint32_t, int,
    boolean_t);
extern char *hwAddrWrite(unsigned char *, char *);
extern char *ntoa(uint32_t, char *);
extern char *sprintTime(char *, int);
extern char *sprintRelativeTime(char *, int);
extern char *err2str(int);
extern int restoreAgentState(void);
extern void Finalize(int);
extern void delFAVEptr(FaVisitorEntry *, boolean_t, uint32_t);
extern void delHABEent(HaMobileNodeEntry *, HaBindingEntry *);
extern int startPeriodicTaskThread(void);
extern int startSNMPTaskThread(void);
extern int startDispatcherTaskThread(void);
extern int startStatServer();
static int startPerfTestServer(void);
extern int aaaSendRegistrationReply(MessageHdr *, size_t,
    ipaddr_t, ipaddr_t);
extern MobilityAgentEntry *findMaeFromIp(ipaddr_t address, int lockType);

void forwardFromFAToHA(MessageHdr *, MaAdvConfigEntry *, boolean_t);
void rejectFromFAToMN(MessageHdr *, MaAdvConfigEntry *, int);
void rejectFromICMPToMN(MessageHdr *, ipaddr_t, int);
extern uint32_t getRandomValue();
extern int	gettunnelno(ipaddr_t, ipaddr_t);
extern int arpIfadd(ipaddr_t, char *, uint32_t);
extern int arpIfdel(ipaddr_t, char *, uint32_t);
extern void ifname2devppa(char *, char *, int *);
extern int dlattachreq(int, int);
extern int dlokack(int, char *);
extern int dlbindreq(int, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
extern int dlbindack(int, char *);
static int mip_strioctl(int, int, void *, int, int);
static void HAprocessRegRequestContinue(MessageHdr *, MaAdvConfigEntry *,
    ipaddr_t *, int, HaMobileNodeEntry *, uint32_t, uint32_t);
static void HABuildRegReply(MessageHdr *, MaAdvConfigEntry *,
    int, HaMobileNodeEntry *, uint32_t, MipSecAssocEntry *, int,
    boolean_t, uint32_t, boolean_t);
static boolean_t acceptFAVEHashLookup(void *, uint32_t, uint32_t, uint32_t);

int installIPsecPolicy(char *);

#ifdef FIREWALL_SUPPORT
/*
 * Function: isInsideProtectedDomain
 *
 * Arguments: addr - peer's address.
 *
 * Description:	Check each interval to see if the given addr is inside
 *		the protected domain
 *
 * Returns: boolean - _B_TRUE if the address is inside the protected domain.
 *
 */
boolean_t
isInsideProtectedDomain(ipaddr_t addr)
{
	int i;

	if (domainInfo.addrIntervalCnt == 0)
		return (_B_TRUE);

	for (i = 0; i < domainInfo.addrIntervalCnt; i++) {
	    if (((addr ^ domainInfo.addr[i]) & domainInfo.netmask[i]) == 0)
		return (_B_TRUE);
	}

	return (_B_FALSE);
}
#endif /* FIREWALL_SUPPORT */

/*
 * Function: mkRegExtList
 *
 * Arguments:	messageHdr - Message Control Block
 *		headerLength - length of the Mobile-IP heaeder
 *
 * Description:	Examines the packet in the message header starting at the
 *		packet + the size of the header, which is provided as an
 *		argument. This function will place all the Mobile IP
 *		extensions encountered in the message header's extType[]
 *		and their start points in the extIdx[] field. The maximum
 *		size of these two arrays is stored in the message header's
 *		extCnt field. At termination, the extCnt field contains the
 *		number of extensions found in the message.
 *
 * Returns: int - 0 if successful.
 *
 */
static int
mkRegExtList(MessageHdr *messageHdr, size_t headerLength)
{
	unsigned char *currentPos;
	/*
	 * Support for different extension header formats
	 */
	uint16_t longLength;
	uint8_t shortLength;
	size_t bufLength;
	size_t bytesSeen = 0;
	size_t extSeen = 0;

	currentPos = (unsigned char *)(((char *)messageHdr->pkt) +
	    headerLength);
	bufLength = (int)(((char *)messageHdr->pktLen) - headerLength);

	/*
	 * Protection against packets that have no extensions.
	 */
	if (bufLength == 0) {
		return (0);
	}

	mipverbose(("Found extensions:"));

	while ((bytesSeen < (bufLength - 1)) &&
	    (extSeen < MAX_EXPECTED_EXTENSIONS)) {
		messageHdr->extType[extSeen] = *currentPos;
		messageHdr->extIdx[extSeen] = currentPos;
		mipverbose((" <%d, %d, ...>", messageHdr->extType[extSeen],
		    *(messageHdr->extIdx[extSeen] + MIP_EXT_LENGTH)));

		/*
		 * The latest Mobile IP Extensions have a
		 * different extension header, compliant with, or close to,
		 * the MIER specification. The following checks the
		 * actual extension type in order to determine how to
		 * parse the extension header.
		 */
		switch (messageHdr->extType[extSeen]) {
		case REG_GEN_AUTH_EXT_TYPE:
		case REG_GEN_MN_FA_KEY_EXT_TYPE:
		case REG_GEN_MN_HA_KEY_EXT_TYPE:
			/*
			 * The following handles the generalized Authentication
			 * extension as well as the generalized keying
			 * extensions.
			 */
			messageHdr->extSubType[extSeen] =
			    *(currentPos + MIP_EXT_GEN_SUB_TYPE);
			(void) memcpy(&longLength,
			    currentPos + MIP_EXT_LONG_LENGTH,
			    sizeof (uint16_t));
			longLength = ntohs(longLength);
			messageHdr->extHdrLength[extSeen] =
			    sizeof (mierLongExt);
			messageHdr->extLength[extSeen] = longLength;
			messageHdr->extData[extSeen] =
			    currentPos + MIP_EXT_LONG_LENGTH_DATA;
			break;

		case REG_CRIT_VENDOR_SPEC_EXT_TYPE:
			/*
			 * The Vendor Specific Extension has a
			 * drastically different header, and not supporting
			 * the header would cause us to drop any packets
			 * with such headers. Critical Vendor Specific
			 * Extensions are now supported.
			 */
			(void) memcpy(&messageHdr->extSubType[extSeen],
			    currentPos + MIP_EXT_CVSE_VENDOR_SUB_TYPE,
			    sizeof (uint16_t));
			messageHdr->extSubType[extSeen] =
			    ntohs(messageHdr->extSubType[extSeen]);
			(void) memcpy(&messageHdr->extVendorId[extSeen],
			    currentPos + MIP_EXT_CVSE_VENDOR_ID_TYPE,
			    sizeof (uint32_t));
			messageHdr->extVendorId[extSeen] =
			    ntohl(messageHdr->extVendorId[extSeen]);
			(void) memcpy(&longLength,
			    currentPos + MIP_EXT_LONG_LENGTH,
			    sizeof (uint16_t));
			longLength = ntohs(longLength);
#ifdef KEY_DISTRIBUTION
			messageHdr->extHdrLength[extSeen] =
			    sizeof (vendorSpecExt);
#else /* KEY_DISTRIBUTION */
			messageHdr->extHdrLength[extSeen] =
			    VENDOR_SPEC_EXT_HDR_LEN;
#endif /* KEY_DISTRIBUTION */
			messageHdr->extLength[extSeen] = longLength;
			messageHdr->extData[extSeen] =
			    currentPos + MIP_EXT_CVSE_VENDOR_ID_DATA;
			break;

		case REG_NORMAL_VENDOR_SPEC_EXT_TYPE:
			/*
			 * The Vendor Specific Extension has a
			 * drastically different header, and not supporting
			 * the header would cause us to drop any packets
			 * with such headers. Normal Vendor Specific Extensions
			 * are now supported.
			 */
			(void) memcpy(&shortLength, currentPos + MIP_EXT_LENGTH,
			    sizeof (uint8_t));
			messageHdr->extHdrLength[extSeen] = sizeof (regExt);
			messageHdr->extLength[extSeen] = shortLength;
			messageHdr->extSubType[extSeen] =
			    *(currentPos + MIP_EXT_NVSE_VENDOR_SUB_TYPE);
			messageHdr->extVendorId[extSeen] =
			    *(currentPos + MIP_EXT_NVSE_VENDOR_ID_TYPE);
			messageHdr->extData[extSeen] =
			    currentPos + MIP_EXT_NVSE_VENDOR_ID_DATA;
			break;

		default:
			/*
			 * The following code supports the traditional
			 * extensions.
			 */
			(void) memcpy(&shortLength, currentPos + MIP_EXT_LENGTH,
			    sizeof (uint8_t));
			messageHdr->extHdrLength[extSeen] = sizeof (regExt);
			messageHdr->extLength[extSeen] = shortLength;
			messageHdr->extData[extSeen] = currentPos +
			    MIP_EXT_DATA;
			break;
		}


		/*
		 * protect against bogus packets.
		 */
		if ((messageHdr->extLength[extSeen] +
		    messageHdr->extHdrLength[extSeen]) >
		    (bufLength - bytesSeen)) {
			messageHdr->extCnt = extSeen;
			return (-1);
		}
		bytesSeen += messageHdr->extLength[extSeen] +
		    messageHdr->extHdrLength[extSeen];
		currentPos += messageHdr->extLength[extSeen] +
		    messageHdr->extHdrLength[extSeen];

		extSeen++;
	}
	mipverbose((" (%d exts)\n", messageHdr->extCnt));


	if ((bytesSeen < (bufLength - 1)) &&
	    (extSeen >= MAX_EXPECTED_EXTENSIONS)) {
	    syslog(LOG_ERR, "Too many extensions.");
	    return (-1);
	} else if (bytesSeen != bufLength) {
	    syslog(LOG_ERR, "Extensions buffer too small.");
	    return (-1);
	} else {
	    messageHdr->extCnt = extSeen;
	    return (0);
	}
}

/*
 * Function: IsPacketFromMnValid
 *
 * Arguments: messageHdr - Message Control Block
 *
 * Description: This function is called by the Foreign Agent when a
 *		registration request is received from a Mobile Node
 *		and will step through each extension that was stored
 *		in the message header's extType to ensure that the
 *		packet contains the required extensions and that the
 *		message follows the protocol rules.
 *
 *		The rules are:
 *		1. If the challenge is being advertised, it MUST be
 *		present in the packet.
 *		2. If the MN-AAA is present, then the MN-FA, the
 *		NAI and the challenge extensions MUST be present.
 *		3. If MN-AAA is not present, MN-HA MUST be present.
 *		4. If the MN-FA is present, it MUST be present after
 *		either the MN-HA or the MN-AAA extension.
 *
 * Returns:	returns a Mobile IP error code, zero if successful.
 *		return -1 if packet needs to be dropped.
 *
 */
/*
 * The message parsing routines must be able to return
 * a variety of Mobile IP error codes in order to support all error
 * cases.
 */
static int
IsPacketFromMnValid(MessageHdr *messageHdr)
{
	regRequest *requestPtr;
	boolean_t foundMHauth		= _B_FALSE;
	boolean_t foundMFauth		= _B_FALSE;
	boolean_t foundMAauth		= _B_FALSE;
	boolean_t foundNAI		= _B_FALSE;
	boolean_t foundChallenge	= _B_FALSE;
	int i;

	/* LINTED BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	/*
	 * According to the latest Challenge draft, here is the
	 * rule. If the challenge was advertised, then it MUST
	 * be present in ALL packets. If the Mobile-AAA authentication
	 * extension is present, then the NAI MUST be present.
	 *
	 * Normal RFC 2002 rules apply, with the exception that if
	 * the Mobile-Home authentication is NOT present, then the
	 * Mobile-AAA authentication extension MUST be present.
	 */
	for (i = 0; i < messageHdr->extCnt; i++) {
	    mipverbose(("IsPacketFromMnValid[%d] = %d\n", i,
		messageHdr->extType[i]));
	    switch (messageHdr->extType[i]) {
	    case REG_MH_AUTH_EXT_TYPE:
		/* we should not have seen any other auth extensions */
		if (foundMHauth == _B_TRUE) {
		    syslog(LOG_ERR,
			"Multiple MH or MA Authentication Extensions");
		    return (FA_POORLY_FORMED_REQUEST);
		} else {
		    foundMHauth = _B_TRUE;
		}
		break;

	    case REG_GEN_AUTH_EXT_TYPE:
		/*
		 * The Challenge/Response Internet Draft now
		 * supports a generalized authentication extension, similar
		 * to the MIER specification. When we receive the generalized
		 * authentication extension, we need to check the subtype
		 * field in order to determine the actual extension.
		 */
		switch (messageHdr->extSubType[i]) {
		case GEN_AUTH_MN_AAA:
			/*
			 * The challenge extension MUST be present prior to
			 * the MN-AAA Auth Ext.
			 */
			if (foundChallenge == _B_FALSE) {
				syslog(LOG_ERR, "Missing Challenge before " \
				    "Mobile-AAA Authentication Extension");
				/*
				 * If a challenge was expected,
				 * but not received, we must return a missing
				 * challenge error.
				 */
				return (FA_MISSING_CHALLENGE);
			}

			/*
			 * The draft states that the NAI SHOULD be present if
			 * the M-A authentication extension is present, so we
			 * will enforce this.
			 */

			if (foundNAI == _B_FALSE) {
				syslog(LOG_ERR, "Missing NAI before Mobile-AAA "
				    "Authentication Extension");
				/*
				 * Mipagent didn't return the
				 * error codes specified in the NAI
				 * specification. If an NAI was expected, and
				 * wasn't present, return a MISSING NAI error.
				 */
				return (FA_MISSING_NAI);
			}
			/*
			 * Fixed buffer overrun.  mnNAI is not null
			 * terminated.
			 */
			(void) fprintf(stderr, "Got an NAI of %.*s!\n",
			    messageHdr->mnNAILen, messageHdr->mnNAI);

			/* we should not have seen any other auth extensions */
			if (foundMAauth == _B_TRUE) {
			    syslog(LOG_ERR,
				"Multiple MH or MA Authentication Extensions");
			    return (FA_POORLY_FORMED_REQUEST);
			} else {
			    foundMAauth = _B_TRUE;
			}
			break;

		default:
			syslog(LOG_ERR,
			    "Unknown Generalized Authentication subtype found");
			return (FA_POORLY_FORMED_REQUEST);
		}
		break;

	    case REG_MF_AUTH_EXT_TYPE:
		/* we should have seen MHauth but no MFauth */
		if (foundMHauth == _B_TRUE || foundMAauth == _B_TRUE) {
			if (foundMFauth == _B_TRUE) {
				syslog(LOG_ERR, "Multiple MF Authentication "
				    "Extensions");
				return (FA_POORLY_FORMED_REQUEST);
			} else {
				foundMFauth = _B_TRUE;
			}
		} else {
		    syslog(LOG_ERR,
			    "No MH or MA before MF Authentication Extension");
		    return (FA_POORLY_FORMED_REQUEST);
		}
		break;

	    case REG_MF_CHALLENGE_EXT_TYPE:
		/*
		 * We should only see the challenge if we've
		 * advertised it.
		 */
		if (faChallengeAdv == _B_FALSE) {
			syslog(LOG_ERR, "Challenge should not be present");
			return (FA_POORLY_FORMED_REQUEST);
		}
		if (foundMFauth == _B_TRUE) {
			syslog(LOG_ERR, "Challenge should be before "
			    "MF Authentication Extension");
			return (FA_POORLY_FORMED_REQUEST);
		}
		if (foundChallenge == _B_TRUE) {
			syslog(LOG_ERR, "Multiple Challenges");
			return (FA_POORLY_FORMED_REQUEST);
		} else {
			foundChallenge = _B_TRUE;
		}
		break;

	    case REG_MN_NAI_EXT_TYPE:
		/*
		 * The draft states that the NAI SHOULD be present if
		 * the M-A authentication extension is present, so we
		 * will enforce this.
		 */
		if (foundNAI == _B_TRUE) {
			syslog(LOG_ERR, "Multiple NAIs");
			return (FA_POORLY_FORMED_REQUEST);
		} else {
			/*
			 * Save the pointer to the NAI for future
			 * reference.
			 */
			messageHdr->mnNAI = messageHdr->extData[i];
			messageHdr->mnNAILen = messageHdr->extLength[i];

			if (messageHdr->mnNAILen > MAX_NAI_LENGTH) {
				/*
				 * Protect against buffer overflows...
				 */
				syslog(LOG_ERR, "Excessively large NAI");
				/*
				 * Mipagent didn't return the
				 * error codes specified in the NAI
				 * specification. If an NAI was present, but
				 * larger than expected, return a MISSING NAI
				 * code (the draft doesn't actually state
				 * what should be returned here.
				 */
				return (FA_MISSING_NAI);
			}

			/*
			 * Fixed buffer overrun.  mnNAI is not null
			 * terminated.
			 */
			(void) fprintf(stderr, "Received NAI (%*.*s)!\n",
			    messageHdr->mnNAILen, messageHdr->mnNAILen,
			    messageHdr->mnNAI);
			foundNAI = _B_TRUE;
		}
		break;

	    /* Vendor-specific extension support */
	    case REG_CRIT_VENDOR_SPEC_EXT_TYPE:
		/*
		 * We only care if we've seen the MN-HA/AAA auth, but
		 * haven't seen the MN-FA auth (yet).
		 */
		if (foundMHauth == _B_FALSE && foundMAauth == _B_FALSE) {
			/*
			 * We haven't seen any mobile node authentication
			 * extensions yet, so we're still inside the MN-HA/AAA
			 * authenticator.  These aren't for us, so skip them.
			 */
			break;
		}

		/* This extension is implicitly for us as FA... */
		switch (messageHdr->extSubType[i]) {
			/*
			 * MN-FA auth is not required to be put here by the
			 * MN.  By putting this extension after the MN-HA/AAA
			 * authenticator, the implication is the MN wants us
			 * to look it.  Even if we waited for an MN-FA auth
			 * we're not likely to be returning anything different.
			 */

			/*
			 * Vendor-specific extensions we understand go here!
			 */
			default:
				/*
				 * RFC 3025 says if we understand this
				 * extension type, but we don't understand
				 * the Vendor/Org-ID or Vendor-CVSE-Type,
				 * we MUST send the registration reply with
				 * a HA_UNKNOWN_CVSE_FROM_MN.  Make sure,
				 * though, that this is for us as FA...
				 */
				if ((foundMHauth == _B_TRUE ||
				    foundMAauth == _B_TRUE) &&
				    foundMFauth != _B_TRUE) {
					/*
					 * We've seen some form of Mobile-Home
					 * authentication, so it's not for the
					 * HA, and we haven't seen a MFauth, so
					 * it implies this is for us as FA.
					 */
					syslog(LOG_ERR,
						"Unrecognized CVSE subtype %d "
						"from Mobile Node",
						messageHdr->extSubType[i]);
					return (FA_UNKNOWN_CVSE_FROM_MN);
				}
				break;
		}
		break;

	    case REG_NORMAL_VENDOR_SPEC_EXT_TYPE:
		/*
		 * We only care if we've seen the MN-HA/AAA auth, but
		 * haven't seen the MN-FA auth (yet).
		 */
		if (foundMHauth != _B_TRUE && foundMAauth != _B_TRUE) {
			/*
			 * We haven't seen a mobile-home authenticator yet,
			 * so we're still inside the MN-HA/AAA authenticator.
			 * This isn't for us, so skip them silently.
			 */
			break;
		}

		/* This extension is something the MN wants us to look at */
		switch (messageHdr->extSubType[i]) {
			/*
			 * As we understand specific vendor extensions,
			 * they go in here!
			 */
			default:
				/*
				 * Non-critical vendor specific extensions are
				 * ignored if we don't understand it.  Make
				 * sure we don't log this if it's really for
				 * the HA...
				 */
				if ((foundMHauth == _B_TRUE ||
				    foundMAauth == _B_TRUE) &&
				    foundMFauth != _B_TRUE) {
					/*
					 * If we saw an MFauth, it'd be bad to
					 * process this.  In that case it may
					 * be for someone, just not us...
					 */
					syslog(LOG_ERR,
						"Unrecognized NVSE subtype %d "
						"from Mobile Node, ignoring!",
						messageHdr->extSubType[i]);
				}
				break;
		}
		break;

		/*
		 * If the Encapsulating Delivery Style Extension is present,
		 * the MN MUST be requesting reverse tunneling!  It MUST also
		 * appear after the MN_HA_AUTHENTICATION extension, (and when
		 * we support it we MUST consume it so it isn't forward it to
		 * the HA (this last part can't be done here as we're just
		 * parsing a list of extensions)).
		 *
		 * Hopefully *everything* after the mn-ha auth in the regreq
		 * the mn sent us is removed somewhere before we add fa things,
		 * then the fa-ha auth (if applicable).
		 *
		 * At this time it's OK for a MN to put more than one of these
		 * in, so there's no need to set a foundEDS flag to be checked
		 * later.
		 *
		 * At this time, only IPv4inIPv4 tunnels are supported.  If
		 * there ever comes a time when we support any other type, we
		 * may have to check the tunnel-type request bits to make sure
		 * we support that in the reverse direction too.
		 */
	    case ENCAPSULATING_DELIVERY_TYPE:
		/*
		 * We should have either found a mn-ha authenticator first,
		 * or a AAA MN authentication first and NOT a
		 * mn-fa authenticator (since this has to be between the two).
		 * Note: it may be nicer to break this into two cases if we
		 * want to provide a more specific syslog message.
		 */
		if (((foundMHauth != _B_TRUE) && (foundMAauth != _B_TRUE)) ||
		    (foundMFauth == _B_TRUE)) {
			syslog(LOG_ERR,
			    "Found ENCAPSULATING_DELIVERY_TYPE"
			    " in the wrong location of registration request -"
			    " either before mn-ha or mn AAA authenticator,"
			    " or after mn-fa authenticator.");
			return (FA_POORLY_FORMED_REQUEST);
		}

		/* The 'T' bit MUST be set. */
		if (!(requestPtr->regFlags & REG_REVERSE_TUNNEL)) {
			/* extension is here, but 'T' bit isn't set */
			syslog(LOG_ERR,
			    "Found ENCAPSULATING_DELIVERY_TYPE"
			    " but 'T' bit isn't set.");
			return (FA_POORLY_FORMED_REQUEST);
		}

		/*
		 * OK, looks good, but we don't support this yet.  This is the
		 * only place we can look for this extension, but until we
		 * support type 130 extensions, we'll have to be non-conformant
		 * for this function, too, and return something other than
		 * FA_POORLY_FORMED_REQUEST.
		 */
		faCounters.faRTEncapUnavailableCnt++;
		return (FA_DELIVERY_STYLE_UNAVAILABLE);

	    default:
		if (messageHdr->extType[i] <= 127) {
			/*
			 * Unrecognized extensions in this range cause this
			 * packet be drooped.
			 */
			syslog(LOG_ERR,
			    "Unrecognized ext (ext[%d]= %d)  in range 0-127.",
			    i, messageHdr->extType[i]);
			return (MA_DROP_PACKET);
		}
		/*
		 * Extensions in the range 128-255 should be
		 * skipped.
		 */
		break;
	    }
	}

	/*
	 * Acording to the challenge draft, the rules is as follow:
	 * 1. If the Mobile Node does not have a security association
	 *    with the foreign agent, it MUST include the MN-AAA auth
	 *    ext. The challenge must appear PRIOR to this extension.
	 * 2. If the Mobile Node has a security association with the
	 *    foreign agent, it must include the MN-FA auth ext.
	 *
	 * So in order to enforce this, if the challenge is being
	 * advertised, we will ensure that either the MN-AAA is present
	 * OR the MN-HA AND the MN-FA.
	 */
	if (faChallengeAdv == _B_TRUE) {
		if (foundMAauth == _B_FALSE && (foundMHauth == _B_FALSE ||
		    foundMFauth == _B_FALSE)) {
			syslog(LOG_ERR, "When Challenge is present, either "
			    "the MN-AAA or the MN-HA *and* the MN-FA must "
			    "be present");
			return (FA_POORLY_FORMED_REQUEST);
		}
	}

	/*
	 * The registration request must include either:
	 * 1. Home Address, and/or
	 * 2. NAI.
	 */
	if (requestPtr->homeAddr == INADDR_ANY && foundNAI == _B_FALSE) {
		syslog(LOG_ERR,
			"Mobile Node NAI MUST be present if home address "
			"is set to zero (0)");
		/*
		 * Mipagent didn't return the error codes
		 * specified in the NAI specification. If an NAI was expected,
		 * and wasn't present, return a MISSING NAI error.
		 */
		return (FA_MISSING_NAI);
	}

	/* make sure we have one MHauth */
	if (foundMAauth == _B_TRUE || foundMHauth == _B_TRUE) {
		return (MIP_SUCCESSFUL_REGISTRATION);
	} else {
		syslog(LOG_ERR, "MH or MA Authentication Extension missing");
		return (FA_POORLY_FORMED_REQUEST);
	}
}


/*
 * Function: IsPacketFromCoaValid
 *
 * Arguments: messageHdr - Message Control Block
 *
 * Description: This function is called by the Home Agent when a
 *		registration request is received from a Foreign Agent
 *		and will step through each extension that was stored
 *		in the message header's extType to ensure that the
 *		packet contains the required extensions and that the
 *		message follows the protocol rules.
 *
 *		The rules are:
 *		1. If the MN-AAA is present, then the MN-FA, the
 *		NAI and the challenge extensions MUST be present.
 *		3. If MN-AAA is not present, MN-HA MUST be present.
 *		4. If the FA-HA is present, it must be preceeded by
 *		either the MN-HA or the MN-AAA.
 *
 * Returns:	returns a Mobile IP error code, zero if successful.
 *		return -1 if packet needs to be dropped.
 *
 */
static int
IsPacketFromCoaValid(MessageHdr *messageHdr)
{
	regRequest *requestPtr;
	char addrstr[INET_ADDRSTRLEN];
	boolean_t foundMHauth		= _B_FALSE;
	boolean_t foundFHauth		= _B_FALSE;
	boolean_t foundMAauth		= _B_FALSE;
	boolean_t foundNAI		= _B_FALSE;
	boolean_t foundChallenge	= _B_FALSE;
	int i;

	/* LINTED BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	/*
	 * According to the latest Challenge draft, here is the
	 * rule. If the challenge was advertised, then it MUST
	 * be present in ALL packets. If the Mobile-AAA authentication
	 * extension is present, then the NAI MUST be present.
	 *
	 * Normal RFC 2002 rules apply, with the exception that if
	 * the Mobile-Home authentication is NOT present, then the
	 * Mobile-AAA authentication extension MUST be present.
	 */
	for (i = 0; i < messageHdr->extCnt; i++) {
	    mipverbose(("IsPacketFromCoaValid[%d] = %d\n", i,
		messageHdr->extType[i]));
	    switch (messageHdr->extType[i]) {
	    case REG_MH_AUTH_EXT_TYPE:
		/* we should not have seen any other auth extensions */
		if (foundMHauth == _B_TRUE) {
		    syslog(LOG_ERR,
			"Multiple MH or MA Authentication Extensions");
		    return (HA_POORLY_FORMED_REQUEST);
		} else {
		    foundMHauth = _B_TRUE;
		}
		break;

	    case REG_GEN_AUTH_EXT_TYPE:
		/*
		 * The Challenge/Response Internet Draft now
		 * supports a generalized authentication extension, similar to
		 * the MIER specification. When we receive the generalized
		 * authentication extension, we need to check the subtype
		 * field in order to determine the actual extension.
		 */
		switch (messageHdr->extSubType[i]) {
		case GEN_AUTH_MN_AAA:
			/*
			 * The challenge extension MUST be present prior to
			 * the MN-AAA Auth Ext.
			 */
			if (foundChallenge == _B_FALSE) {
				syslog(LOG_ERR, "Missing Challenge before " \
				    "Mobile-AAA Authentication Extension");
				return (HA_POORLY_FORMED_REQUEST);
			}

			/*
			 * The draft states that the NAI SHOULD be present if
			 * the M-A authentication extension is present, so we
			 * will enforce this.
			 */

			if (foundNAI == _B_FALSE) {
				syslog(LOG_ERR, "Missing NAI before Mobile-AAA "
				    "Authentication Extension");
				/*
				 * Mipagent didn't return the
				 * error codes specified in the NAI
				 * specification. If an NAI was expected, and
				 * wasn't present, return a MISSING NAI error.
				 */
				return (FA_MISSING_NAI);
			}
			/*
			 * Fixed buffer overrun.  mnNAI is not null
			 * terminated.
			 */
			(void) fprintf(stderr, "Got an NAI of (%*.*s)!\n",
			    messageHdr->mnNAILen, messageHdr->mnNAILen,
			    messageHdr->mnNAI);

			/* we should not have seen any other auth extensions */
			if (foundMAauth == _B_TRUE) {
			    syslog(LOG_ERR,
				"Multiple MH or MA Authentication Extensions");
			    return (HA_POORLY_FORMED_REQUEST);
			} else {
			    foundMAauth = _B_TRUE;
			}
			break;

		default:
			syslog(LOG_ERR,
			    "Unknown Generalized Authentication subtype found");
			return (HA_POORLY_FORMED_REQUEST);
		}
		break;


	    case REG_MF_CHALLENGE_EXT_TYPE:
		    if (foundChallenge == _B_TRUE) {
			    syslog(LOG_ERR, "Multiple Challenges");
			    return (HA_POORLY_FORMED_REQUEST);
		    } else {
			    foundChallenge = _B_TRUE;
		    }
		break;

	    case REG_FH_AUTH_EXT_TYPE:
		/*
		 * We should at least make sure that we've seen
		 * the Mobile-Home Authentication Extension before
		 * we see this one.
		 */
		if (foundMAauth == _B_FALSE && foundMHauth == _B_FALSE) {
		    syslog(LOG_ERR,
			"Missing MH or MA Authentication Extension "
			"before FHauth");
		    return (HA_POORLY_FORMED_REQUEST);
		} else {
			/*
			 * we should not have seen any other auth
			 * extensions
			 */
			if (foundFHauth == _B_TRUE) {
				syslog(LOG_ERR, "Multiple FHauth");
				return (HA_POORLY_FORMED_REQUEST);
			} else {
				foundFHauth = _B_TRUE;
			}
		    }
		break;

	    case REG_MN_NAI_EXT_TYPE:
		/*
		 * The draft states that the NAI SHOULD be present if
		 * the M-A authentication extension is present, so we
		 * will enforce this.
		 */
		if (foundNAI == _B_TRUE) {
			syslog(LOG_ERR, "Multiple NAIs");
			return (HA_POORLY_FORMED_REQUEST);
		} else {
			/*
			 * Save the pointer to the NAI for future
			 * reference.
			 */
			messageHdr->mnNAI = messageHdr->extData[i];
			messageHdr->mnNAILen = messageHdr->extLength[i];

			if (messageHdr->mnNAILen > MAX_NAI_LENGTH) {
				/*
				 * Protect against buffer overflows...
				 */
				syslog(LOG_ERR, "Excessively large NAI");
				return (HA_POORLY_FORMED_REQUEST);
			}
			foundNAI = _B_TRUE;
		}
		break;

	    /* Vendor-specific extension support */
	    case REG_CRIT_VENDOR_SPEC_EXT_TYPE:
		/* Examine the subtype, and process accordingly */
		switch (messageHdr->extSubType[i]) {
			/*
			 * As we understand specific vendor extensions,
			 * they go in here!
			 */

			default:
				/*
				 * RFC 3025 says if we understand this type,
				 * but we don't understand the Vendor/Org-ID
				 * or Vendor-CVSE-Type, we MUST send a
				 * registration reply with either
				 * HA_UNKNOWN_CVSE_FROM_MN if it came from
				 * the mobile node, or HA_UNKNOWN_CVSE_FROM_FA
				 * if it came from the foreign agent.
				 *
				 * What we need to worry about now:
				 *
				 * Did this extension come from the MN, or was
				 * it added by an FA?  Note (caveat!): if the
				 * 'D'-bit is set, if an FA was advertising
				 * the 'R'-bit, the MN sent the registration
				 * request to it, so it may have added these
				 * extensions in flight!
				 */
				if (foundMHauth != _B_TRUE &&
				    foundMAauth != _B_TRUE) {
					/*
					 * We haven't seen a MN-HA/AAA
					 * authenticator, so this is in the
					 * MN-to-HA portion of the request
					 */
					syslog(LOG_ERR,
					    "Unrecognized CVSE subtype %d from"
					    " Mobile Node",
					    messageHdr->extSubType[i]);
					return (HA_UNKNOWN_CVSE_FROM_MN);
				} else if (foundFHauth != _B_TRUE) {
					/*
					 * We've seen some form of MN-home
					 * authenticator, so what we're
					 * looking at now appears after it,
					 * and must be from an FA (FA iGs
					 * supposed to strip out anything
					 * after MN-HA/AAA auth from the MN,
					 * so this must have been FA-appended.
					 * That 'if' was a sanity check that we
					 * have NOT seen a FA-HA authenticator,
					 * which would imply this was NOT
					 * added by the FA.
					 */
					syslog(LOG_ERR,
					    "Unrecognized CVSE subtype %d from"
					    " Foreign Agent",
					    messageHdr->extSubType[i]);
					return (HA_UNKNOWN_CVSE_FROM_FA);
				}
				break;
		}
		break;

	case REG_NORMAL_VENDOR_SPEC_EXT_TYPE:
		/* Examine the subtype, and process accordingly */
		switch (messageHdr->extSubType[i]) {
			/*
			 * As we understand specific vendor extensions,
			 * they go in here!
			 */

			default:
				/*
				 * For non-critical vendor specific extensions,
				 * we ignore the entire extension if we don't
				 * understand the sub-type or vendor-ID.
				 *
				 * We need to know if it came from MN or FA...
				 */
				if (foundMHauth != _B_TRUE &&
				    foundMAauth != _B_TRUE) {
					/*
					 * We haven't seen an MN-HA/AAA
					 * authenticator, so it's before it,
					 * and is from the mobile node.
					 */
					syslog(LOG_ERR,
					    "Unrecognized NVSE subtype %d from"
					    " Mobile Node, ignoring!",
					    messageHdr->extSubType[i]);
				} else if (foundFHauth != _B_TRUE) {
					/*
					 * It's after MN-home authenticationon,
					 * but before FA-home authentication,
					 * so the implication is this was put
					 * here by the FA.
					 */
					syslog(LOG_ERR,
					    "Unrecognized NVSE subtype %d from"
					    " Foreign Agent, ignoring!",
					    messageHdr->extSubType[i]);
				}
				break;
		}
		break;

	    case ENCAPSULATING_DELIVERY_TYPE:
		/*
		 * If the MN included the Encapsulating Delivery Style
		 * Extension, the FA MUST consume it.  If it didn't, we'll be
		 * nice and just log an error (there is no "official" error
		 * code which can help a MN figure this out anyway).
		 *
		 * We could make sure we've seen the MN-HA auth.  If not, it's
		 * a poorly formed request (and perhaps why the FA didn't
		 * remove this extension, though it should have denied it with
		 * poorly formed request).  Since this is an FA only thing,
		 * and clearly isn't a security problem, I don't think we
		 * should care.  Denying is likely to lead to no service, so
		 * are we trying to service this guy, or look for reasons to
		 * deny service?
		 *
		 * The icing here is since it's type 130 it's in the ignore
		 * range.  We shouldn't change the way the HA reacts to a FA
		 * only RT extension because it now supports RT.
		 */
		syslog(LOG_WARNING,
		    "Home Agent found ENCAPSULATING_DELIVERY_TYPE extension."
		    "  FA (%s) should have removed it."
		    "  Ignoring (as type>127), and processing registration.",
		    ntoa(requestPtr->COAddr, addrstr));

		break;

	    default:
		if (messageHdr->extType[i] <= 127) {
			/*
			 * Unrecognized extensions in this range cause this
			 * packet be drooped.
			 */
			syslog(LOG_ERR,
			    "Unrecognized ext (ext[%d]= %d)  in range 0-127.",
			    i, messageHdr->extType[i]);
			return (MA_DROP_PACKET);
		}
		/*
		 * Extensions in the range 128-255 should be
		 * skipped.
		 */
		break;
	    }
	}

	/*
	 * The registration request must include either:
	 * 1. Home Address, and/or
	 * 2. NAI.
	 */
	if (requestPtr->homeAddr == INADDR_ANY && foundNAI == _B_FALSE) {
		syslog(LOG_ERR,
			"Mobile Node NAI MUST be present if home address "
			"is set to zero (0)");
		return (HA_POORLY_FORMED_REQUEST);
	}

	/* make sure we have one MHauth */
	if (foundMAauth == _B_TRUE || foundMHauth == _B_TRUE) {
		return (MIP_SUCCESSFUL_REGISTRATION);
	} else {
		syslog(LOG_ERR, "MH or MA Authentication Extension missing");
		return (HA_POORLY_FORMED_REQUEST);
	}
}


/*
 * Function: IsPacketFromHaValid
 *
 * Arguments: messageHdr - Message Control Block
 *
 * Description: This function is called by the Foreign Agent when a
 *		registration reply is received from a Home Agent
 *		and will step through each extension that was stored
 *		in the message header's extType to ensure that the
 *		packet contains the required extensions and that the
 *		message follows the protocol rules.
 *
 *		The rules are:
 *		1. The MN-HA MUST be present.
 *		2. If the FA-HA is present and the challenge
 *		is being advertised, the challenge MUST be present.
 *		3. If the FA-HA is present, it MUST appear after the
 *		the MN-HA extension.
 *
 * Returns:	returns a Mobile IP error code, zero if successful.
 *		return -1 if packet needs to be dropped.
 *
 */
static int
IsPacketFromHaValid(MessageHdr *messageHdr)
{
	regReply *replyPtr;
	boolean_t foundMHauth		= _B_FALSE;
	boolean_t foundFHauth		= _B_FALSE;
	boolean_t foundNAI		= _B_FALSE;
	boolean_t foundChallenge	= _B_FALSE;
	int i;

	/* LINTED BAD_PTR_CAST_ALIGN */
	replyPtr = (regReply *) messageHdr->pkt;

	/*
	 * The NAI MAY be necessary, but right now we have no
	 * way of knowing. This check will have to be handled
	 * later.
	 */
	for (i = 0; i < messageHdr->extCnt; i++) {
	    mipverbose(("IsPacketFromHaValid[%d] = %d\n", i,
		messageHdr->extType[i]));
	    switch (messageHdr->extType[i]) {
	    case REG_MH_AUTH_EXT_TYPE:
		/* we should not have seen any other auth extensions */
		if (foundMHauth == _B_TRUE) {
		    syslog(LOG_ERR,
				"Multiple MH or MA Authentication Extensions");
		    return (FA_POORLY_FORMED_REPLY);
		} else {
		    foundMHauth = _B_TRUE;
		}
		break;

	    case REG_FH_AUTH_EXT_TYPE:
		/* If we are expecting a challenge, check for it. */
		if (faChallengeAdv == _B_TRUE && foundChallenge == _B_FALSE) {
			syslog(LOG_ERR, "Challenge Missing in Reply");
			/*
			 * If a challenge was expected, but
			 * not received, we must return a missing challenge
			 * error.
			 */
			return (FA_MISSING_CHALLENGE);
		}

		/* we should have seen MHauth but no FHauth */
		if (foundMHauth == _B_FALSE) {
		    syslog(LOG_ERR,
			"No MH or MA Authentication Extension before FHauth");
		    return (FA_POORLY_FORMED_REPLY);
		} else if (foundFHauth == _B_TRUE) {
		    syslog(LOG_ERR, "Multiple FHauth");
		    return (FA_POORLY_FORMED_REPLY);
		} else {
		    foundFHauth = _B_TRUE;
		}
		break;

	    case REG_MF_CHALLENGE_EXT_TYPE:
		    if (foundChallenge == _B_TRUE) {
			    syslog(LOG_ERR, "Multiple Challenges");
			    return (FA_POORLY_FORMED_REPLY);
		    } else {
			    foundChallenge = _B_TRUE;
		    }
		break;

	    case REG_MN_NAI_EXT_TYPE:
		/*
		 * The draft states that the NAI SHOULD be present if
		 * the M-A authentication extension is present, so we
		 * will enforce this.
		 */
		if (foundNAI == _B_TRUE) {
			syslog(LOG_ERR, "Multiple NAIs");
			return (FA_POORLY_FORMED_REPLY);
		} else {
			/*
			 * Save the pointer to the NAI for future
			 * reference.
			 */
			messageHdr->mnNAI = messageHdr->extData[i];
			messageHdr->mnNAILen = messageHdr->extLength[i];

			if (messageHdr->mnNAILen > MAX_NAI_LENGTH) {
				/*
				 * Protect against buffer overflows...
				 */
				syslog(LOG_ERR, "Excessively large NAI");
				return (FA_POORLY_FORMED_REPLY);
			}
			foundNAI = _B_TRUE;
		}
		break;

	    case REG_GEN_MN_FA_KEY_EXT_TYPE:
		/*
		 * The AAA Keys Internet Draft now supports
		 * a generalized key extension, similar to the MIER
		 * specification. When we receive the generalized key
		 * extension, we need to check the subtype field in order to
		 * determine the actual extension.
		 */
		switch (messageHdr->extSubType[i]) {
		case GEN_KEY_MN_FA:
			/*
			 * We just need to recognize the extension type,
			 * otherwise it will cause an error.
			 */
			break;

		default:
			syslog(LOG_ERR,
			    "Unrecognized generalized key subtype %d",
			    messageHdr->extSubType[i]);
			return (FA_POORLY_FORMED_REPLY);
		}
		break;

	    case REG_GEN_MN_HA_KEY_EXT_TYPE:
		/*
		 * The AAA Keys Internet Draft now supports
		 * a generalized key extension, similar to the MIER
		 * specification. When we receive the generalized key
		 * extension, we need to check the subtype field in order to
		 * determine the actual extension.
		 */
		switch (messageHdr->extSubType[i]) {
		case GEN_KEY_MN_HA:
			/*
			 * We just need to recognize the extension type,
			 * otherwise it will cause an error.
			 */
			break;

		default:
			syslog(LOG_ERR,
			    "Unrecognized generalized key subtype %d",
			    messageHdr->extSubType[i]);
			return (FA_POORLY_FORMED_REPLY);
		}
		break;

	    case REG_CRIT_VENDOR_SPEC_EXT_TYPE:
		/* Check the subtype and process accordingly */
		switch (messageHdr->extSubType[i]) {
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
		case REG_MN_FA_KEY_EXT:
		case REG_FA_HA_KEY_EXT:
			/*
			 * We just need to recognize the extension type,
			 * otherwise it will cause an error.
			 */
			break;
#endif /* KEY_DISTRIBUTION */

		/*
		 * Insert understood REG_CRIT_VENDOR_SPEC_EXT_TYPEs here!
		 */

		default:
			/*
			 * RFC 3025 says if we don't understand
			 * this subtype we MUST return
			 * FA_UNKNOWN_CVSE_FROM_HA in the
			 * registration reply (to the mobile node,
			 * who'll understand it MUST rereg, and
			 * hopefully do something to change the HA's
			 * mind about replying with that CVSE)!
			 * First, though, make sure it's for us!
			 */
			if (foundMHauth == _B_TRUE && foundFHauth == _B_FALSE) {
				/*
				 * we've seen the MHAUTH, so this is
				 * after it, but not an FHauth, so it's
				 * for us from the HA.
				 */
				syslog(LOG_ERR,
				    "Unrecognized CVSE subtype %d"
				    " from Home Agent.",
				    messageHdr->extSubType[i]);
				    return (FA_UNKNOWN_CVSE_FROM_HA);
			}
		}
		break;

	case REG_NORMAL_VENDOR_SPEC_EXT_TYPE:
		/* Check subtype, and process accordingly */
		switch (messageHdr->extSubType[i]) {
			/*
			 * Understood REG_NORMAL_VENDOR_SPEC_EXT_TYPEs go here!
			 */

			default:
				/*
				 * RFC3025 says silently ignore, but we should
				 * at least log it if it's for us.
				 */
				if (foundMHauth == _B_TRUE &&
				    foundFHauth == _B_FALSE) {
					/*
					 * We've seen the MHauth, so it's not
					 * for the MN, and we haven't seen an
					 * FHauth, so the implication is this
					 * is for us (if we had seen a FAauth,
					 * we'd KNOW it's NOT for us).
					 * Note: there's no check for an
					 * MN-AAAauth in this routine here!
					 */
					syslog(LOG_ERR,
					    "Unrecognized NVSE subtype %d"
					    " from Home Agent, ignoring.",
					    messageHdr->extSubType[i]);
				}
		}
		break;

	    default:
		if (messageHdr->extType[i] <= 127) {
			/*
			 * Unrecognized extensions in this range cause this
			 * packet be drooped.
			 */
			syslog(LOG_ERR,
			    "Unrecognized ext (ext[%d]= %d)  in range 0-127.",
			    i, messageHdr->extType[i]);
			return (MA_DROP_PACKET);
		}
		/*
		 * Extensions in the range 128-255 should be
		 * skipped.
		 */
		break;
	    }
	}

	/*
	 * The Home Address MUST be provided.
	 */
	if (replyPtr->homeAddr == INADDR_ANY) {
		syslog(LOG_ERR, "Mobile Node Home Address MUST be provided");
		/*
		 * Mipagent didn't return the error
		 * codes specified in the NAI specification. If
		 * the reply didn't include a Home Address, we must return
		 * a MISSING HOME ADDRESS error code.
		 */
		return (FA_MISSING_HOMEADDR);
	}


	if (foundMHauth == _B_TRUE) {    /* make sure we have one MHauth */
		return (MIP_SUCCESSFUL_REGISTRATION);
	} else {
		syslog(LOG_ERR, "MH Authentication Extension missing");
		return (FA_POORLY_FORMED_REPLY);
	}
}


#ifdef RADIUS_ENABLED
HaMobileNodeEntry *
radiusCheckUpdate(HaMobileNodeEntry *dest, struct hash_table *htbl,
			ipaddr_t mnAddr)
{
	struct hash_entry *p;
	MipSecAssocEntry *saEntry;
	RadData result;
	char ipString[30];
	int rc;
	char *sessionId;
	struct hash_entry *hash;
	char mipSecKey[MAX_KEY_LEN];
	int i;
	time_t currentTime;

	(void) ntoa(mnAddr, ipString);
	(void) memset(&result, 0, sizeof (result));

	GET_TIME(currentTime);

	/* ToDo: Lock our node */

	if (dest == NULL) {
#ifdef RADIUS_DEBUG
		(void) fprintf(stderr,
		    "radiusCheckUpdate: Looking up 0x%08x\n", mnAddr);
#endif
		rc = radLookupData(&sessionId, ipString, &result);
#ifdef RADIUS_DEBUG
		(void) fprintf(stderr,
		    "radiusCheckUpdate: Finished Looking up 0x%08x  rc=%d\n",
		    mnAddr, rc);
#endif
		if (rc) {
			/*
			 * Since we have nothing, we need to retun null . . .
			 */
			return (NULL);
		}

		if (hexConvert((char *)mipSecKey,
		    result.mipSecretLen/2, result.mipSecret) < 0) {
			return (NULL);
		}

		/*
		 * Now we create the Security Assocation
		 * TODO: This DOES NOT belong here. We want
		 * to take care of this when the SPI is
		 * defined.
		 */
		saEntry = CreateSecAssocEntry(_B_TRUE, result.mipSPI,
		    result.mipSecretReplayMethod, MD5,
		    PREFIXSUFFIX, result.mipSecretLen/2, mipSecKey, 0);

		if (saEntry == NULL) {
			syslog(LOG_ERR,
			    "Unable to create MobileNode SA for %d",
			    result.mipMnAddr);
			return (NULL);
		}

		/*
		 * And we create the Mobile Node
		 */
		dest = CreateMobileNodeEntry(_B_TRUE,
		    result.mipMnAddr, NULL, 0, result.mipBindingIfAddress,
		    result.mipSPI, sessionId, 0);

		if (dest == NULL) {
			syslog(LOG_ERR,
			    "Unable to create MobileNodeEntry for %d",
			    result.mipMnAddr));
			return (NULL);
		}
	} else {
		/*
		 * We have a node already, check to see if it needs an
		 * update
		 */
		if (dest->haRadiusLastLookupTime + RADIUS_LOOKUP_TIME <
		    currentTime) {
			/* Nope, return! */
			return (dest);
		}
#ifdef RADIUS_DEBUG
		(void) fprintf(stderr, "radiusCheckUpdate: Looking up 0x%08x\n",
		    mnAddr);
#endif
		rc = radLookupData(&sessionId, ipString, &result);
#ifdef RADIUS_DEBUG
		(void) fprintf(stderr,
		    "radiusCheckUpdate: Finished Looking up 0x%08x  rc=%d\n",
		    mnAddr, rc);
#endif
		if (rc) {
			/*
			 * This is either an error, or a timeout . . .either
			 * way, return what we already have.
			 */
			return (dest);
		}

		/*
		 * TODO: We need to update the timestamp.
		 */
		dest->haRadiusLastLookupTime = currentTime;

		/*
		 * TODO: This is broken. if the SPI is the same as what
		 * we already had, then update it, otherwise create
		 * a new Security Association Entry.
		 */
	}

	/* Now, update the fields -- everything went well. */
#ifdef RADIUS_DEBUG
	(void) fprintf(stderr, "radiusCheckUpdate: Updating 0x%p\n", dest);
#endif


	dest->haRadiusState = sessionId;
	dest->haRadiusLastLookupTime = currentTime;

#ifdef RADIUS_DEBUG
	(void) fprintf(stderr, "haMnAddr               = 0x%08x\n",
	    dest->haMnAddr);
	(void) fprintf(stderr, "haBindingIfaceAddr     = 0x%08x\n",
						dest->haBindingIfaceAddr);
	(void) fprintf(stderr, "haMnBindingCnt         = %d\n",
	    dest->haMnBindingCnt);
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr,
		"haRadiusState          = 0x%08x\n", dest->haRadiusState);
	(void) fprintf(stderr,
	    "haRadiusLastLookupTime = 0x%08x\n", dest->haRadiusLastLookupTime);

	(void) fprintf(stderr, "radiusCheckUpdate: exiting\n");
#endif

	return (dest);
} /* radiusCheckUpdate */
#endif /* RADIUS_ENABLED */

#ifdef FIREWALL_SUPPORT
/*
 * Find a binding entry for the specified mnAddr and coAddr pair in
 * Hash Table. If a match is found findHABE returns _B_TRUE else _B_FALSE.
 */
int
findHABE(HashTable *htbl, ipaddr_t mnAddr, ipaddr_t COAddr)
{
	boolean_t found = _B_FALSE;
	HaMobileNodeEntry *hamnePtr;
	HaBindingEntry *entry;
	char addrstr1[INET_ADDRSTRLEN];

	if ((hamnePtr = (HaMobileNodeEntry *)findHashTableEntryUint(htbl,
	    mnAddr, LOCK_READ, NULL, 0, 0, 0)) != NULL) {

	    entry = hamnePtr->bindingEntries;

	    while (entry) {
		if ((entry->haBindingMN == mnAddr) &&
		    (entry->haBindingCOA == COAddr))  {
		    found = _B_TRUE;
		    break;
		}
		entry = entry->next;
	    }

	    (void) rw_unlock(&hamnePtr->nodeLock);
	} else {
	    syslog(LOG_ERR, "Unable to find Mobile Node Entry %s",
		ntoa(mnAddr, addrstr1));
	}

	return (found);
}
#endif /* FIREWALL_SUPPORT */

/*
 * Function: findPendingFAVEHashLookup
 *
 * Arguments:	entry - Pointer to visitor entry
 *		p1 - First parameter to match (low 32-bit ID)
 *		p2 - 2nd parameter to match (whether visitor is accepted)
 *		p3 - 3rd parameter to match (unused)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for findPendingFAVE() when looking for pending visitor
 *		entries in the Hash Table, and will be called by
 *		findHashTableEntryUint() and findHashTableEntryString().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
static boolean_t
findPendingFAVEHashLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	FaVisitorEntry *faveEntry = entry;

	if ((faveEntry->faVisitorRegIDLow == p1) &&
	    ((uint32_t)faveEntry->faVisitorRegIsAccepted == p2)) {
		return (_B_TRUE);
	}

	return (_B_FALSE);
}

/*
 * Function: findPendingFAVE
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		mnAddr - Mobile Node's Home Address.
 *		mnNAI - Mobile Node's NAI
 *		IDlo - Low order 32 bit identifier used by Mobile Node
 *
 * Description: Find a visitor entry with faVisitorHomeAddr equal to mnAddr,
 *		faVisitorRegIDLow equal to IDlo and faVisitorRegIsAccepted
 *		equal to _B_FALSE.
 *
 *		Note: The entry returned will be write locked.
 *
 * Returns: Pointer to FaVisitorEntry. NULL if function failed.
 *
 */
static FaVisitorEntry *
findPendingFAVE(HashTable *htbl, ipaddr_t mnAddr, unsigned char *mnNAI,
    uint32_t mnNAILen, uint32_t IDlo)
{
	FaVisitorEntry *entry = NULL;

	if (mnAddr) {
		/*
		 * Let's see if we can find the entry using the Home
		 * Address.
		 */
		entry = findHashTableEntryUint(htbl, mnAddr, LOCK_WRITE,
		    findPendingFAVEHashLookup, IDlo, _B_FALSE, 0);
	}

	if (entry == NULL && mnNAI) {
		/*
		 * Perhaps we will be able to find the visitor entry
		 * using the NAI.
		 */
		entry = findHashTableEntryString(htbl, mnNAI, mnNAILen,
		    LOCK_WRITE, findPendingFAVEHashLookup, IDlo, _B_FALSE, 0);
	}

	return (entry);
}


/*
 * Function: mkPendingFAVEHashLookup
 *
 * Arguments:	entry - Pointer to visitor entry
 *		p1 - First parameter to match (whether visitor is accepted)
 *		p2 - 2nd parameter to match (inIfindex)
 *		p3 - 3rd parameter to match (unused)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for mkPendingFAVE() when looking for pending visitor
 *		entries in the Hash Table, and will be called by
 *		findHashTableEntryUint() and findHashTableEntryString().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
boolean_t
mkPendingFAVEHashLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	FaVisitorEntry *faveEntry = entry;

	if (((uint32_t)faveEntry->faVisitorRegIsAccepted == p1) &&
	    (p2 == 0 || (uint32_t)faveEntry->faVisitorInIfindex == p2)) {
		return (_B_TRUE);
	}

	return (_B_FALSE);
}


/*
 * Function: mkPendingFAVE
 *
 * Arguments:	htbl - Pointer to Hash Table
 *		messageHdr - Message Control Block
 *		localAddress - Local Interface Address
 *		SPI - Mobile Node's SPI
 *		challenge - The Challenge value found in the Reg. Request
 *		challengeLen - The size of the challenge.
 *
 * Description: Create a pending visitor entry in hash table based on
 *		a registration request pointed to in the message header.
 *		The visitor is reachable through the interface iunformation
 *		found in the message header, such as the localAddr and the
 *		request was sent from visitor's port and source address.
 *
 *		Note that the visitor entry, upon return, will be
 *		write locked.
 *
 * Returns:	if successful, the function will return a pointer to
 *		a visitor entry, otherwise NULL.
 *
 */
static FaVisitorEntry *
mkPendingFAVE(HashTable *htbl, MessageHdr *messageHdr, ipaddr_t localAddr,
    uint32_t SPI, unsigned char *challenge, size_t challengeLen)
{
	boolean_t found;
	regRequest *requestPtr;
	FaVisitorEntry *entry = NULL;
	char addrstr1[INET_ADDRSTRLEN];
	time_t currentTime;

	/* LINTED BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *)messageHdr->pkt;

	found = _B_FALSE;

	/*
	 * First, let's check if we already have a visitor entry for this
	 * mobile node. We must match incoming interface, because we may
	 * have an entry for a MN with overlapping private address
	 */
	if (requestPtr->homeAddr) {
		entry = findHashTableEntryUint(htbl, requestPtr->homeAddr,
		    LOCK_WRITE, mkPendingFAVEHashLookup, _B_FALSE,
		    messageHdr->inIfindex, 0);
	}

	if (entry == NULL && messageHdr->mnNAI) {
		entry = findHashTableEntryString(htbl, messageHdr->mnNAI,
		    messageHdr->mnNAILen, LOCK_WRITE, mkPendingFAVEHashLookup,
		    _B_FALSE, messageHdr->inIfindex, 0);
	}

	if (entry == NULL) {
		/*
		 * Since we did not find a hash entry, we need to
		 * re-initialize p to NULL.
		 */
		if ((entry =
		    (FaVisitorEntry *)calloc(1, sizeof (FaVisitorEntry)))
		    == NULL) {
			syslog(LOG_CRIT,
			    "Unable to allocate FaVisitorEntry");
			return (NULL);
		}

		if (rwlock_init(&entry->faVisitorNodeLock, USYNC_THREAD,
		    NULL)) {
			syslog(LOG_ERR, "Unable to init visitor lock");
		}
	} else {
		found = _B_TRUE;
	}

	entry->faVisitorAddr = messageHdr->src;
	entry->faVisitorIfaceAddr = localAddr;
	entry->faVisitorRegIsAccepted = _B_FALSE;
	entry->faVisitorRegFlags = requestPtr->regFlags;
	entry->faVisitorPort = messageHdr->srcPort;
	entry->faVisitorHomeAddr = requestPtr->homeAddr;
	entry->faVisitorHomeAgentAddr = requestPtr->haAddr;
	entry->faVisitorCOAddr = requestPtr->COAddr;
	GET_TIME(currentTime)
	entry->faVisitorTimeExpires =  currentTime +
		DEFAULT_VISITOR_EXPIRY;
	entry->faVisitorRegIDHigh = ntohl(requestPtr->IDHigh);
	entry->faVisitorRegIDLow = ntohl(requestPtr->IDLow);
	entry->faVisitorSPI = SPI;
	entry->faVisitorInIfindex =  messageHdr->inIfindex;
	entry->faVisitorIsSllaValid = messageHdr->isSllaValid;
	if (messageHdr->isSllaValid)
		(void) memcpy(&entry->faVisitorSlla, &messageHdr->slla,
		    sizeof (struct sockaddr_dl));
	else
		(void) memset(&entry->faVisitorSlla, 0,
		    sizeof (struct sockaddr_dl));

	/*
	 * Save the Mobile Node's NAI
	 */
	entry->faVisitorMnNAILen = messageHdr->mnNAILen;
	if (messageHdr->mnNAI) {
		(void) strncpy((char *)entry->faVisitorMnNAI,
			(char *)messageHdr->mnNAI, messageHdr->mnNAILen);
	} else {
		entry->faVisitorMnNAI[0] = 0;
	}

	/*
	 * If necessary, save the challenge
	 */
	if (challengeLen) {
		(void) memcpy(entry->faVisitorChallengeToHA, challenge,
		    challengeLen);
	}
	entry->faVisitorChallengeToHALen = challengeLen;

	if (found == _B_FALSE) {
		if (requestPtr->homeAddr) {
			/*
			 * We will link the entry in the hash table using
			 * the home address.
			 */
			if (linkHashTableEntryUint(htbl, requestPtr->homeAddr,
			    entry, LOCK_WRITE)) {
				syslog(LOG_ERR,
				    "Unable to add visitor entry to hash tabl");
				(void) rwlock_destroy(
					&entry->faVisitorNodeLock);
				free(entry);
				return (NULL);
			}
			mipverbose(("Adding pending visitor entry for %s.%d " \
			    "at pos'n %p.\n",
			    ntoa(requestPtr->homeAddr, addrstr1),
			    messageHdr->srcPort, (void *)entry));
		} else if (messageHdr->mnNAI) {
			/*
			 * We will link the entry in the has htable using
			 * the NAI. Note that this is a temporary measure
			 * and we will update the hash table to make use
			 * of the home address when the reply (which includes
			 * the home address) is received from the Home Agent.
			 */
			if (linkHashTableEntryString(htbl, messageHdr->mnNAI,
			    messageHdr->mnNAILen, entry, LOCK_WRITE)) {
				syslog(LOG_ERR,
				    "Unable to add visitor entry to "
				    "hash table (NAI)");
				(void) rwlock_destroy(
					&entry->faVisitorNodeLock);
				free(entry);
				return (NULL);
			}
			mipverbose(("Adding pending visitor entry for %.*s (%d)"
			    "at pos'n %p.\n", messageHdr->mnNAILen,
			    messageHdr->mnNAI, messageHdr->mnNAILen,
			    (void *)entry));
		} else {
			/*
			 * Well, we need at LEAST a home address or an NAI.
			 */
			syslog(LOG_ERR, "Unable to add visitor entry "
			    "no Home Address or NAI");
			return (NULL);
		}

	}

	return (entry);
}

/*
 * Function: isAcceptedVisitorHashLookup
 *
 * Arguments:	entry - Pointer to visitor entry
 *		p1 - First parameter to match (interface address)
 *		p2 - 2nd parameter to match (whether visitor is accepted)
 *		p3 - 3rd parameter to match (unused)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for isAcceptedVisitor() when looking for accepted visitor
 *		entries in the Hash Table, and will be called by
 *		findHashTableEntryUint() and findHashTableEntryString().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
static boolean_t
isAcceptedVisitorHashLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	FaVisitorEntry *faveEntry = entry;

	if ((faveEntry->faVisitorIfaceAddr == p1) &&
	    ((uint32_t)faveEntry->faVisitorRegIsAccepted == p2)) {
		return (_B_TRUE);
	}

	return (_B_FALSE);
}


/*
 * Function: isAcceptedVisitor
 *
 * Arguments:	htbl - Pointer to hash table.
 *		mnAddr - Mobile Node's Home Address
 *		ifaceAddr - Local Interface Address.
 *
 * Description: Check if mnAddr has an accepted visitor entry with
 *		VisitorIfaceAddr equal to IfaceAddr.
 *
 * Returns: boolean - _B_TRUE if the entry is in the hash table.
 *
 */
static boolean_t
isAcceptedVisitor(HashTable *htbl, ipaddr_t mnAddr, ipaddr_t ifaceAddr)
{
	FaVisitorEntry *entry;

	entry = findHashTableEntryUint(htbl, mnAddr,
	    LOCK_NONE, isAcceptedVisitorHashLookup, ifaceAddr, _B_TRUE, 0);

	if (entry) {
		return (_B_TRUE);
	} else {
		return (_B_FALSE);
	}
}


/*
 * Function: delFAVE
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *		NAIHash - Pointer to the NAI Hash Table
 *		entry - Pointer to the Visitor Entry
 *		mnAddr - Mobile Node's Home Address
 *
 * Description:	Delete a visitor entry matching the specified mnAddr
 *		and coAddr in Hash Table. If the coAddr equals mnAddr,
 *		all entries for that mobile node are deleted.
 *
 * Returns:
 */
void
delFAVE(HashTable *htbl, FaVisitorEntry **entry, ipaddr_t mnAddr,
    uint32_t relind)
{
	/*
	 * TODO: make this efficient, e.g. we could minimize our stay
	 * in the loop if we figure out that COAddr != mnAddr and we
	 * already deleted one entry.
	 */
	if ((*entry)->faVisitorMnNAI[0] != '\0' &&
	    (*entry)->faVisitorHomeAddr == INADDR_ANY) {

		if (delHashTableEntryString(htbl, *entry,
		    (*entry)->faVisitorMnNAI, (*entry)->faVisitorMnNAILen,
		    LOCK_NONE)) {
			/*
			 * Found a match, delete it
			 */
			delFAVEptr(*entry, _B_TRUE, relind);
			(void) rw_unlock(&(*entry)->faVisitorNodeLock);
			(void) rwlock_destroy(&(*entry)->faVisitorNodeLock);
			free(*entry);
			*entry = NULL;
		}
	} else {
		if (delHashTableEntryUint(htbl, *entry, mnAddr, LOCK_NONE)) {
			/*
			 * Found a match, delete it
			 */
			delFAVEptr(*entry, _B_TRUE, relind);
			(void) rw_unlock(&(*entry)->faVisitorNodeLock);
			(void) rwlock_destroy(&(*entry)->faVisitorNodeLock);
			free(*entry);
			*entry = NULL;
		}
	}

}


/*
 * Function: appendExt
 *
 * Arguments:	buffer - Pointer to offset in packet where extension is to
 *			be added.
 *		type - Extension type.
 *		data - Extension data.
 *		dataLen - Length of the extension data.
 *
 * Description: Append an extension to a registration message contained in
 *		buffer. Returns total number of bytes in the extension.
 *
 * Returns: size of the new data added to the packet.
 */
static size_t
appendExt(unsigned char *buffer, int type, unsigned char *data,
    size_t dataLen)
{
	regExt *ext;

	ext = (regExt *)buffer;
	ext->type = (uint8_t)type;
	ext->length = dataLen;
	(void) memcpy(ext + 1, data, dataLen);

	return (dataLen + sizeof (regExt));
}

/*
 * Function: appendMierExt
 *
 * Arguments:	buffer - Pointer to offset in packet where extension is to
 *			be added.
 *		type - Extension type.
 *		subType - MIER Extension subtype
 *		data - Pointer to extension data
 *		dataLen - Length of the data
 *
 * Description: Appends a MIER-style extension to the registration message.
 *		Returns total number of bytes in the extension.
 *
 * Returns:	size of the new data added to the packet.
 */
static size_t
appendMierExt(unsigned char *buffer, int type, int subType,
    unsigned char *data, uint16_t dataLen)
{
	mierLongExt *ext;

	/*
	 * The latest AAA Keys draft now requires that the
	 * key extensions be added as generalized key extensions, so the
	 * code needs to support the MIER-style extension header.
	 */
	/* LINTED BAD_PTR_CAST_ALIGN */
	ext = (mierLongExt *)buffer;
	ext->type = (uint8_t)type;
	ext->subType = (uint8_t)subType;

	dataLen = htons(dataLen);
	(void) memcpy(&ext->length, &dataLen, sizeof (uint16_t));

	/*
	 * We simply copy the blob at the end of the MIER structure.
	 */
	(void) memcpy(ext + 1, data, ntohs(dataLen));

	return (ntohs(dataLen) + sizeof (mierLongExt));
}

#ifdef KEY_DISTRIBUTION
/*
 * Although this function is not intended only for testing purposes, we need
 * to ifdef it, otherwise we will see some lint warnings. When non ifdef'ed
 * code uses this function, we can remove the ifdef.
 */
/*
 * Function: appendCritVendorSpecExt
 *
 * Arguments:	buffer - Pointer to offset in packet where extension is to
 *			be added.
 *		vendorId - Vendor Id
 *		type - Extension type.
 *		data - Pointer to data
 *		keyLen - Length of the data
 *
 * Description: Support for vendor specific extensions.
 *
 * Returns:	size of the new data added to the packet.
 */
static size_t
appendCritVendorSpecExt(unsigned char *buffer, uint32_t vendorId, uint16_t type,
    unsigned char *data, uint16_t dataLen)
{
	vendorSpecExt *ext;

	/*
	 * Grrr.  This is ugly -- we should really fix this interface
	 * to ensure that `buffer' is correctly aligned.  In the meantime,
	 * at least assert() that it's true and then placate lint.
	 */
	assert(IS_P2ALIGNED(buffer, sizeof (uintptr_t)));
	/* LINTED */
	ext = (vendorSpecExt *)buffer;

	/*
	 * Set the extension type, and the reserved field MUST be set
	 * to zero.
	 */
	ext->type = (uint8_t)REG_CRIT_VENDOR_SPEC_EXT_TYPE;
	ext->reserved = 0;

	/*
	 * Set the length, vendor ID and subType. Make sure that they
	 * are in network order.
	 */
	dataLen = htons(dataLen);
	(void) memcpy(&ext->length, &dataLen, sizeof (uint16_t));

	vendorId = htonl(vendorId);
	(void) memcpy(&ext->vendorId, &vendorId, sizeof (uint32_t));

	type = htons(type);
	(void) memcpy(&ext->vendorType, &type, sizeof (uint16_t));

	/*
	 * We simply copy the blob at the end of the MIER structure.
	 */
	(void) memcpy(buffer + sizeof (vendorSpecExt), data, ntohs(dataLen));

	/*
	 * We need to return the size of the extension
	 */
	return (ntohs(dataLen) + sizeof (vendorSpecExt));
}

/*
 * The following defines how long a session key is valid for, and is
 * only used for testing purposes.
 */
#define	KDC_KEY_LIFETIME	200

/*
 * Function: createMNKeyExt
 *
 * Arguments:	buffer - Pointer to offset in packet where extension is to
 *			be added.
 *		type - Extension type.
 *		subType - MIER SubType
 *		key - Pointer to the keys.
 *		keyLen - Length of the keys
 *		nodeSPI - The SPI the Agent will share with the MN
 *		mnAAASPI - SPI shared between the Mobile Node and the AAA
 *		mnNAI - The Mobile Node's NAI, needed for encryption purposes
 *		mnNAILen - Length of the Mobile Node's NAI
 *
 * Description: This function takes a previously generated session key for
 *		the Mobile Node, encrypts it as defined in the AAA-Key
 *		Internet-Draft, and adds the MIER-style extension.
 *		Returns total number of bytes in the extension.
 *
 * Returns: size of the new data added to the packet.
 */
static size_t
createMNKeyExt(uint8_t *buffer, int type, int subType, uint8_t *key,
    size_t keyLen, uint32_t nodeSPI, uint32_t mnAAASPI, uint8_t *mnNAI,
    size_t mnNAILen)
{
	keyDataExt *ext;
	MipSecAssocEntry *msap;
	MD5_CTX context;
	time_t currentTime;
	uint32_t spi;
	uint32_t lifetime;
	int length = 0;
	char mnKey[128];
	size_t i;

	/*
	 * Allocate a temporary buffer
	 */
	ext = (keyDataExt *)malloc(sizeof (keyDataExt) + keyLen);

	if (ext == NULL) {
		syslog(LOG_CRIT, "Unable to allocate memory");
		return (0);
	}


	/*
	 * Add the AAA SPI to the extension. This SPI is used by
	 * the Mobile Node in order to identify the encryption
	 * method.
	 */
	mnAAASPI = htonl(mnAAASPI);
	(void) memcpy(&ext->mnAAASPI, &mnAAASPI, sizeof (uint32_t));

	/*
	 * Add the node SPI, which is the SPI that the Mobile Node
	 * will use to reference this key
	 */
	spi = nodeSPI;
	nodeSPI = htonl(nodeSPI);
	(void) memcpy(&ext->nodeSPI, &nodeSPI, sizeof (uint32_t));

	/*
	 * Add the lifetime of the session key.
	 */
	GET_TIME(currentTime);
	lifetime = currentTime + KDC_KEY_LIFETIME;
	lifetime = htonl(lifetime);
	(void) memcpy(&ext->lifetime, &lifetime, sizeof (uint32_t));

	/*
	 * Find the AAA SPI that we will use to encrypt the data
	 */
	if ((msap =
	    findSecAssocFromSPI(mnAAASPI, LOCK_READ)) != NULL) {
		/*
		 * Create a new Security Association Entry
		 */
		if (aaaCreateKey(spi, key, keyLen, lifetime) < 0) {
			syslog(LOG_CRIT, "Unable to create MN SA");
			free(ext);
			/* remove the READ lock */
			(void) rw_unlock(&msap->mipSecNodeLock);
			return (0);
		}

		/*
		 * Create the hash...
		 */
		MD5Init(&context);
		MD5Update(&context, msap->mipSecKey,
		    (unsigned int) msap->mipSecKeyLen);
		MD5Update(&context, mnNAI, mnNAILen);
		MD5Update(&context, msap->mipSecKey,
		    (unsigned int) msap->mipSecKeyLen);
		MD5Final((uint8_t *)&mnKey, &context);

		/*
		 * XOR the key in the hash output
		 */
		for (i = 0; i < keyLen; i++) {
			mnKey[i] ^= key[i];
		}

		/*
		 * Copy the key and set the length
		 */
		keyLen = sizeof (mnKey);
		length = sizeof (keyDataExt) + keyLen;
		(void) memcpy(ext + sizeof (keyDataExt), mnKey, keyLen);

		/*
		 * Create the MIER extension
		 */
		length = appendMierExt(buffer, type, subType,
		    (unsigned char *)ext, length);

		/*
		 * Unlock the AAA Security Association
		 */
		(void) rw_unlock(&msap->mipSecNodeLock);
	} else {
		syslog(LOG_ERR, "Failed MN-HA authentication - "
		    "No SPI defined");
		haCounters.haMNAuthFailureCnt++;
	}

	/*
	 * Free the previously allocate memory.
	 */
	free(ext);

	return (length);
}

/*
 * Function: createFAKeyExt
 *
 * Arguments:	buffer - Pointer to offset in packet where extension is to
 *			be added.
 *		vendorId - Vendor Identifier
 *		extId - Extension type.
 *		key - Pointer to the keys.
 *		keyLen - Length of the keys
 *		SPI - The SPI the Agent will share with the MN
 *
 * Description: This function takes a previously generated session key for
 *		the Foreign Agent, and adds it as a Critical Vendor Specific
 *		extension. This is only used for testing purposes, since
 *		the normal method for the Foreign Agent to retrieve it's
 *		keys is through the DIAMETER interface.
 *		Returns total number of bytes in the extension.
 *
 * Returns: size of the new data added to the packet.
 */
static int
createFAKeyExt(char *buffer, uint32_t vendorId, uint32_t extId,
    char *key, size_t keyLen, uint32_t SPI)
{
	keyDataExt *ext;
	time_t currentTime;
	uint32_t spi;
	uint32_t lifetime;
	int length = 0;

	/*
	 * Allocate a temporary buffer
	 */

	ext = (keyDataExt *)malloc(sizeof (keyDataExt) + keyLen);

	if (ext == NULL) {
		syslog(LOG_CRIT, "Unable to allocate memory");
		return (0);
	}

	/*
	 * The keys aren't encrypted, so the AAA SPI is set to zero.
	 */
	spi = htonl(0);
	(void) memcpy(&ext->mnAAASPI, &spi, sizeof (uint32_t));

	/*
	 * Add the node SPI, which is the SPI that the Mobile Node
	 * will use to reference this key
	 */
	spi = SPI;
	SPI = htonl(SPI);
	(void) memcpy(&ext->nodeSPI, &SPI, sizeof (uint32_t));

	/*
	 * Add the lifetime of the session key.
	 */
	GET_TIME(currentTime);
	lifetime = currentTime + KDC_KEY_LIFETIME;
	lifetime = htonl(lifetime);
	(void) memcpy(&ext->lifetime, &lifetime, sizeof (uint32_t));

	/*
	 * Copy the key and set the length
	 */
	length = sizeof (keyDataExt) + keyLen;
	(void) memcpy(ext + sizeof (keyDataExt), key, keyLen);

	/*
	 * Create the vendor specific extension
	 */
	length = appendCritVendorSpecExt((uint8_t *)buffer, vendorId, extId,
	    (unsigned char *)ext, length);

	/*
	 * We need to create the SA locally if this is for the FA-HA SA
	 */
	if (extId == REG_FA_HA_KEY_EXT) {
		/*
		 * Create a new Security Association Entry
		 */
		if (aaaCreateKey(spi, (uint8_t *)key, keyLen, lifetime) < 0) {
			syslog(LOG_CRIT, "Unable to create key");
			free(ext);
			return (0);
		}
	}

	/*
	 * Free the previously allocate memory.
	 */
	free(ext);

	return (length);
}
#endif /* KEY_DISTRIBUTION */


/*
 * Function: findFAVEHashLookup
 *
 * Arguments:	entry - Pointer to visitor entry
 *		p1 - First parameter to match (interface address)
 *		p2 - 2nd parameter to match (whether visitor is accepted)
 *		p3 - 3rd parameter to match (unused)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for isAcceptedVisitor() when looking for accepted visitor
 *		entries in the Hash Table, and will be called by
 *		findHashTableEntryUint() and findHashTableEntryString().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
static boolean_t
findFAVEHashLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	FaVisitorEntry *faveEntry = entry;

	if ((faveEntry->faVisitorHomeAgentAddr == p1) &&
	    ((uint32_t)faveEntry->faVisitorRegIsAccepted == p2)) {
		return (_B_TRUE);
	}

	return (_B_FALSE);
}


/*
 * Function:	findAcceptedFAVE
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *		mnAddr - Mobile Node's Home Address
 *		haAddr - Home Agent Address
 *
 * Description:	This function will look for an accepted
 *		visitor entry, and will return the entry.
 *
 * Returns:	If successful, pointer to visitor entry
 */
static FaVisitorEntry *
findAcceptedFAVE(HashTable *htbl, ipaddr_t mnAddr, ipaddr_t haAddr)
{
	FaVisitorEntry *entry;

	/*
	 * Let's see if we can find the entry using the Home
	 * Address. Note that an accepted visitor entry MUST have
	 * a home address, so we do not need to worry about looking
	 * using the NAI.
	 */
	entry = findHashTableEntryUint(htbl, mnAddr, LOCK_WRITE,
	    findFAVEHashLookup, haAddr, _B_TRUE, 0);

	return (entry);
}


/*
 * Function: FAprocessRegRequest
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		entry - Pointer to the Interface Entry.
 *		inAddr - IP address this request received on
 *
 * Description:	Process a registration request received at a foreign
 *		agent. If successful, the request will be forwarded to
 *		the Home Agent. If unsuccessful an error will be returned
 *		to the Mobile Node.
 *
 * Returns: void
 */
void
FAprocessRegRequest(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    ipaddr_t *inAddr)
{
	int code = MIP_SUCCESSFUL_REGISTRATION;
	uint32_t mnSPI;
	boolean_t forwardToHaFlag = _B_TRUE;	/* If FALSE, the request is  */
						/* not forwarded to the Home */
						/* Agent, but is sent to the */
						/* AAA infrastructure instead */
	authExt *mnAuthExt;
	/*
	 * Support for generalized auth extensions.
	 */
	regRequest *requestPtr;
	FaVisitorEntry *favePtr;
	FaVisitorEntry *acceptedFAVE;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char addrstr3[INET_ADDRSTRLEN];
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	unsigned char *challenge;
	int mnAuthExtLen;
	int index;

	size_t challengeLen = 0;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	mipverbose(("\n---- %s (%s) ----\n",
	    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
	    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE)));
	mipverbose(("FA got reg req of length %d [MN %s, HA %s, COA %s]\n",
	    messageHdr->pktLen, ntoa(requestPtr->homeAddr, addrstr1),
	    ntoa(requestPtr->haAddr, addrstr2),
	    ntoa(requestPtr->COAddr, addrstr3)));
	mipverbose(("               [Lifetime %d sec, ID %0#10x : %0#10x]\n",
	    (uint32_t)ntohs(requestPtr->regLifetime),
	    ntohl(requestPtr->IDHigh),
	    ntohl(requestPtr->IDLow)));

	mipverbose(("FAprocessRegRequest called with packet:\n"));
	if (logVerbosity > 2)
		printBuffer(messageHdr->pkt, messageHdr->pktLen);
	mipverbose(("\n"));

	/*
	 * Validate the Care of Address
	 */
	if ((requestPtr->COAddr != *inAddr) &&
	    (messageHdr->ifType != ON_MCAST_SOCK)) {
		/*
		 * It is legal for the Care of Address to be set to the
		 * Mobile Node's address, as long as the lifetime field is
		 * set to zero.
		 */
		if ((requestPtr->homeAddr == requestPtr->COAddr) &&
		    (requestPtr->regLifetime != 0)) {
			/*
			 * Invalid Care of Address.
			 */
			code = FA_INVALID_CARE_OF_ADDR;
			faCounters.faInvalidCareOfAddrCnt++;
			(void) rejectFromFAToMN(messageHdr, entry, code);
			return;
		}
	}

	/*
	 * If the packet has any of the bits that we do not currently
	 * support, return an error.
	 */
	if (requestPtr->regFlags & REG_BIT_UNUSED) {
		code = FA_POORLY_FORMED_REQUEST;
		faCounters.faPoorlyFormedRequestsCnt++;
		(void) rejectFromFAToMN(messageHdr, entry, code);
		return;
	}

	/*
	 * Support for new MIER-style extension header.
	 *
	 * Are extensions ok and in the right order?
	 */
	if (mkRegExtList(messageHdr, sizeof (regRequest)) < 0) {
	    code = FA_POORLY_FORMED_REQUEST;
	    faCounters.faPoorlyFormedRequestsCnt++;
	    (void) rejectFromFAToMN(messageHdr, entry, code);
	    return;
	}


	/*
	 * Packet parsing routines now return error codes.
	 *
	 * Is the packet from the Mobile Node valid?
	 */
	if ((code = IsPacketFromMnValid(messageHdr)) > 0) {
		/* We support Direct Delivery Style only */
		if (code != FA_DELIVERY_STYLE_UNAVAILABLE) {
			/*
			 * We're here because there was a type 130 extension
			 * in the RRQ, and we don't support the encapsulated
			 * delivery style! However, for scalability of the
			 * code, we set the faRTEncapUnavailableCnt counter
			 * in the IsPacketFromMnValid() function. Everything
			 * else increaments faPoorlyFormedRequests counter.
			 * Note: FA_MISSING_* error codes are also considered
			 * as poorly formatted request.
			 */
			faCounters.faPoorlyFormedRequestsCnt++;
		}
		(void) rejectFromFAToMN(messageHdr, entry, code);
		return;
	} else if (code == MA_DROP_PACKET) {
		/* drop the packet */
		return;
	}

	/*
	 * We now compare the lifetime
	 * received in the request with the value
	 * configured on the interface.
	 */
	/* Is lifetime too long? */
	if (ntohs(requestPtr->regLifetime) >
	    (unsigned short) entry->maAdvMaxRegLifetime) {
		code = FA_REG_LIFETIME_TOO_LONG;
		faCounters.faRegLifetimeTooLongCnt++;
		(void) rejectFromFAToMN(messageHdr, entry, code);
		return;
	}

	/* Do we offer the requested encapsulation services? (Minimal Encap) */
	if ((requestPtr->regFlags & REG_MIN_ENCAP) &&
		((entry->maAdvServiceFlags & ADV_MIN_ENCAP) == 0)) {
			code = FA_ENCAP_UNAVAILABLE;
			faCounters.faEncapUnavailableCnt++;
			(void) rejectFromFAToMN(messageHdr, entry, code);
			return;
	}

	/* Do we offer the requested encapsulation services? (GRE) */
	if ((requestPtr->regFlags & REG_GRE_ENCAP) &&
	    ((entry->maAdvServiceFlags & ADV_GRE_ENCAP) == 0)) {
		code = FA_ENCAP_UNAVAILABLE;
		faCounters.faEncapUnavailableCnt++;
		(void) rejectFromFAToMN(messageHdr, entry, code);
		return;
	}

	/* Did the mobile request a reverse tunnel... */
	if (requestPtr->regFlags & REG_REVERSE_TUNNEL) {
		/* ...but we're not advertising it! */
		if ((entry->maAdvServiceFlags & ADV_REVERSE_TUNNEL) == 0) {
			/*
			 * Note: we could have just as easily checked
			 * entry->maReverseTunnelAllowed & RT_FA, but
			 * it seems better to check the wire!
			 * entry->maAdvServiceFlags will be set only if
			 * (entry->maReverseTunnelAllowed & RT_FA).
			 */
			code = FA_REVERSE_TUNNEL_UNAVAILABLE;
			faCounters.faReverseTunnelUnavailableCnt++;
			(void) rejectFromFAToMN(messageHdr, entry, code);
			return;
		}

		/*
		 * Is the MN is too far away?
		 *
		 * Some discussion of this is necessary...
		 *
		 * This is a link-local check.  Basically, if the TTL of the
		 * packet isn't 255, then the potential is there that some
		 * [other] node is trying to get us to setup a reverse tunnel
		 * to the [registered MN's home] subnet (the MN is
		 * required by RFC2344 to set the TTL to 255).
		 */
		if (messageHdr->ttl != 255) {
			code = FA_MN_TOO_DISTANT;
			faCounters.faMNTooDistantCnt++;
			(void) rejectFromFAToMN(messageHdr, entry, code);
			return;
		}
	} else  if (aaaProtocol != RADIUS) {
		/*
		 * MN didn't request a Reverse Tunnel - do we require it?
		 * Note: don't make the user change 2 settings to turn off
		 * reverse tunnels.  Make sure we're advertising, then
		 * check if it's being required.  This way a user can [re]set
		 * reversetunnel=no, and we wont care if reversetunnelrequired
		 * is set (if the fa-bit in reversetunnelrequired is set).
		 */
		if ((entry->maAdvServiceFlags & ADV_REVERSE_TUNNEL) &&
		    (entry->maReverseTunnelRequired & RT_FA)) {
			/*
			 * Again, we instead could have checked
			 * entry->maReverseTunnelAllowed & RT_FA instead of
			 * the AdvServiceFlags, but it's better to check the
			 * the wire.  entry->maAdvServiceFlags will be set
			 * only if (entry->maReverseTunnelAllowed & RT_FA).
			 */
			code = FA_REVERSE_TUNNEL_REQUIRED;
			faCounters.faReverseTunnelRequiredCnt++;
			(void) rejectFromFAToMN(messageHdr, entry, code);
			return;
		    }
	}

	/* Do we offer the requested compression service? */
	if ((requestPtr->regFlags & REG_VJ_COMPRESSION) &&
		((entry->maAdvServiceFlags & ADV_VJ_COMPRESSION) == 0)) {
	    code = FA_VJ_UNAVAILABLE;
	    faCounters.faVJCompUnavailableCnt++;
	    (void) rejectFromFAToMN(messageHdr, entry, code);
	    return;
	}

	/*
	 * TODO: If the HA address specified is the same as the arriving
	 * interface, we MUST not forward this packet. What about
	 * the case when this address belongs to another interface
	 * on this FA, one on which HA services are being offered.
	 */
	if (requestPtr->haAddr == requestPtr->COAddr) {
	    syslog(LOG_ERR,
		"Warning: FA dropping nasty reg req with HAaddr same as COA.");
	    return;
	}

	/*
	 * Let's retrieve the MN-FA SPI information.
	 */
	/*
	 * If a Mobile node Foreign agent authentication extension exists
	 * check it.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_MF_AUTH_EXT_TYPE,
	    mnAuthExt, mnAuthExtLen);

	if (mnAuthExtLen) {
		GET_SPI(mnSPI, mnAuthExt);
	} else {
		mnSPI = 0;
	}

	GET_EXT_DATA(messageHdr, index, REG_MF_CHALLENGE_EXT_TYPE,
	    challenge, challengeLen);

	/* Try creating a visitor list entry ... */
	if ((favePtr = mkPendingFAVE(&faVisitorHash, messageHdr,
	    entry->maIfaceAddr, mnSPI, challenge, challengeLen)) == NULL) {
	    code = FA_INSUFFICIENT_RESOURCES;
	    faCounters.faInsufficientResourceCnt++;
	    (void) rejectFromFAToMN(messageHdr, entry, code);
	    return;
	}

	acceptedFAVE = findAcceptedFAVE(&faVisitorHash, requestPtr->homeAddr,
	    requestPtr->haAddr);

	/*
	 * Support for the latest Challenge/Response I-D.
	 *
	 * Check the message's authentication. This function will set the
	 * forwardToHaFlag field. If disabled, we will silently return
	 * because the Registration Request is being forwarded to the
	 * AAA infrastructure.
	 */
	code = faCheckRegReqAuth(messageHdr, favePtr, acceptedFAVE, challenge,
	    challengeLen, &forwardToHaFlag);

	if (acceptedFAVE) {
		(void) rw_unlock(&acceptedFAVE->faVisitorNodeLock);
	}

	if (code) {
		if (favePtr->faVisitorRegIsAccepted == _B_FALSE) {
			/*
			 * Since the visitor entry isn't accepted, and an
			 * error occured, we can delete it. Otherwise, we
			 * will let the visitor entry expire naturally.
			 */
			delFAVE(&faVisitorHash, &favePtr, requestPtr->homeAddr,
			    REG_REVOKED);
		} else {
			(void) rw_unlock(&favePtr->faVisitorNodeLock);
		}
		(void) rejectFromFAToMN(messageHdr, entry, code);
		return;
	}

	(void) rw_unlock(&favePtr->faVisitorNodeLock);


	faCounters.faRegReqRecvdCnt++;

	if (forwardToHaFlag == _B_TRUE) {
		/* send the registration request to the home agent */
		(void) forwardFromFAToHA(messageHdr, entry, _B_FALSE);
	} else {
		mipverbose(("\n---- %s (%s) ----\n",
		    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
		    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE)));
		mipverbose(("FA relayed reg req from %s.%d to AAA for %.*s\n",
		    ntoa(messageHdr->src, addrstr1), messageHdr->srcPort,
		    (messageHdr == NULL) ? 1 : messageHdr->mnNAILen,
		    (messageHdr == NULL) ? "-" : (char *)messageHdr->mnNAI));

		mipverbose(("Registration relayed by FA is:\n"));
		if (logVerbosity > 2)
			printBuffer(messageHdr->pkt, messageHdr->pktLen);
		mipverbose(("\n"));

		faCounters.faRegReqRelayedCnt++;

	}
}

boolean_t
forcefullyDeregisterMN(ipaddr_t *homeaddr, ipaddr_t COAaddr,
    ipaddr_t homeAgentaddr)
{
	FaVisitorEntry *entry = NULL;
	char tmp_buf[INET_ADDRSTRLEN];
	boolean_t result;


	/*
	 * NOTE: This function is called by aaaMainThread() and always
	 * expects non-NULL mnNAI, as AAA expects NAI.
	 * But we must search by key homeaddr since acceptFAVE() converts
	 * the indexing from NAI to homeaddr after acceptance of the
	 * mobilenode registration. We have to distinguish two private
	 * overlapping addresses. AAA does not have any notion of incoming
	 * interface index in the AVPcode, thus we are matching with
	 * homeagent address. It is expected that the mobilenode is already
	 * registered.
	 */

	entry = findHashTableEntryUint(&faVisitorHash, *homeaddr,
	    LOCK_WRITE, acceptFAVEHashLookup, COAaddr, _B_TRUE,
	    homeAgentaddr);


	if (entry != NULL) {
		result = delHashTableEntryUint(&faVisitorHash, entry,
		    *homeaddr, LOCK_NONE);
		if (result == _B_TRUE) {
			delFAVEptr(entry, _B_FALSE, REG_REVOKED);
			(void) rw_unlock(&entry->faVisitorNodeLock);
			(void) rwlock_destroy(&entry->faVisitorNodeLock);
			free(entry);

			return (_B_TRUE);
		}
	}

	mipverbose(("Couldn't find MN with homeaddr %s to close "
	    "session per AAA's request\n",
	    inet_ntop(AF_INET, (const void*)homeaddr, tmp_buf,
	    sizeof (tmp_buf))));
	return (_B_FALSE);
}

/*
 * Function:	openDeviceStream
 *
 * Arguments:	Ifacename- name of the interface (eg: hme0) to which a device
 *		stream is to be opened in raw mode to send M_DATA.
 *
 * Description:	This function opens a layer 2 raw socket
 * Returns:	-1 on failure, fd on success
 */
int openDeviceStream(char *IfaceName) {
	int fd;
	char device[MAX_IFNAME_LEN + 5];
	int ppa;
	char buf[MAXDLBUF];
	int rval;

	ifname2devppa(IfaceName, device, &ppa);
	if ((fd = open(device, (O_RDWR | O_NDELAY))) < 0) {
		mipverbose(("error opening device %s in openDeviceStream\n",
				IfaceName));
		return (-1);
	}

	/* Attach. */
	if ((rval = dlattachreq(fd, ppa)) != 0) {
		mipverbose(("Error attaching to device in openDeviceStream"
				" with errno %d\n", (-1)*rval));
		(void) close(fd);
		return (-1);
	}

	if ((rval = dlokack(fd, buf)) != 0) {
		mipverbose(("Error in DLPI ack from device in openDeviceStream"
				" with errno %d\n", (-1)*rval));
		(void) close(fd);
		return (-1);
	}

	/* Bind. Use sap=0x0800 for IP. */
	if ((rval = dlbindreq(fd, 0x800, 0, DL_CLDLS, 0, 0)) != 0) {
		mipverbose(("Error in DLPI bind in openDeviceStream"
				" with errno %d\n", (-1)*rval));
		(void) close(fd);
		return (-1);
	}

	if ((rval = dlbindack(fd, buf)) != 0) {
		mipverbose(("Error in DLPI bind ack from devicee in"
				" openDeviceStream with errno %d\n",
				(-1)*rval));
		(void) close(fd);
		return (-1);
	}

	/* Issue DLIOCRAW ioctl */
	if (mip_strioctl(fd, DLIOCRAW, NULL, 0, 0) < 0) {
		(void) close(fd);
		mipverbose(("error processing DLIOCRAW ioctl in"
				" openDeviceStream\n"));
		return (-1);
	}

	return (fd);
}

/*
 * Function:	mip_in_cksum
 *
 * Arguments:	addr- the starting address (eg: start of IP header)
 *		len- number of bytes over which the checksum is to be computed.
 *
 * Description:	This function computes the one's complement checksum.
 * Returns:	The one's complement checksum
 */
static ushort_t
mip_in_cksum(ushort_t *addr, int len)
{
	int nleft = len;
	ushort_t *w = addr;
	ushort_t answer;
	ushort_t odd_byte = 0;
	int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(uchar_t *)(&odd_byte) = *(uchar_t *)w;
		sum += odd_byte;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 * Function:	mip_strioctl
 *
 * Arguments:	fd- the file descriptor
 *		cmd- the ioctl cmd (eg: DLIOCRAW)
 *		ptr- data pointer
 *		ilen- length of data
 *		olen- lenght of returned data
 *
 * Description:	wrapper for STREAMS I_STR ioctl
 * Returns:	-1 on failure, 0 on success
 */
static int
mip_strioctl(int fd, int cmd, void *ptr, int ilen, int olen)
{
	struct strioctl str;

	str.ic_cmd = cmd;
	str.ic_timout = 0;	/* Use default timer; 15 seconds */
	str.ic_len = ilen;
	str.ic_dp = ptr;

	if (ioctl(fd, I_STR, &str) == -1) {
		return (-1);
	}
	if (str.ic_len != olen) {
		return (-1);
	}
	return (0);
}


/*
 * Function:	sendRawPkt
 *
 * Arguments:	messageHdr - the message control block.
 *		entry - the MAAdvConfigEntry of the interface to send the
 *                  registration reply from, and the settings to return
 *		pktlen - length of the Mobile IP packet (eg: sizeof (regReply))
 *
 * Description:	This function is used when sending a reject to the MN when the
 *		home address of the MN is not yet assigned. In this case, the
 *		packet is sent to an IP level broadcast but since this maps to
 *		a link level broadcast (for ethernet) and we don't want this
 *		message to be misinterpreted by other mobiles nodes (as a
 *		message meant for them), a raw packet is constructed with the
 *		IP destination being a broadcast and the link layer destination
 *		being unicast (i.e the correct mobile nodes L2 addr)
 * Returns:	-1 on failure, 0 on success
 */
int
sendRawPkt(MessageHdr *msgHdr, MaAdvConfigEntry *entry, uint_t pktlen) {
	int fd;
	char pkt[MAX_PKT_SIZE], *destaddr;
	struct ether_header *ethp;
	struct ip	*ipp;
	struct udphdr	*udpp;
	struct  strbuf data;
	int	flags;
	uchar_t *mipp;

	if ((fd = openDeviceStream(entry->maIfaceName)) < 0)
		return (-1);

	/* Set up the ethernet header */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ethp = (struct ether_header *)pkt;
	bcopy(msgHdr->slla.sdl_data, ethp->ether_dhost.ether_addr_octet,
	    ETHERADDRL);
	bcopy(entry->maIfaceHWaddr, ethp->ether_shost.ether_addr_octet,
	    ETHERADDRL);
	ethp->ether_type = htons(ETHERTYPE_IP);

	/* Set up the IP header */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ipp = (struct ip *)(pkt + sizeof (struct ether_header));
	ipp->ip_v = IPVERSION;
	ipp->ip_hl = 5;	/* 5 32-bit words == 20 bytes */
	ipp->ip_tos = 0;
	ipp->ip_len = htons(20 + sizeof (struct udphdr) + pktlen);
	ipp->ip_id = htons(1);
	ipp->ip_off = 0;
	ipp->ip_ttl = 1;
	ipp->ip_p = IPPROTO_UDP;
	ipp->ip_sum = mip_in_cksum((ushort_t *)ipp, 20);
	destaddr = "255.255.255.255"; /* IP broadcast */
	(void) inet_pton(AF_INET, destaddr, &ipp->ip_dst.s_addr);
	bcopy(&entry->maIfaceAddr, &ipp->ip_src.s_addr, sizeof (ipaddr_t));

	/* Set up the UDP header */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	udpp = (struct udphdr *)((uchar_t *)ipp + sizeof (struct ip));
	udpp->uh_sport = htons(MIP_PORT);
	udpp->uh_dport = htons(MIP_PORT);
	udpp->uh_ulen = htons(sizeof (struct udphdr) + pktlen);
	udpp->uh_sum = 0; /* udp chksum is optional */

	/* Set up the registration reply */
	mipp = (uchar_t *)((uchar_t *)udpp + sizeof (struct udphdr));
	bcopy(msgHdr->pkt, mipp, pktlen);

	data.buf = (char *)pkt;
	data.maxlen = MAX_PKT_SIZE;
	data.len = sizeof (struct ether_header) + sizeof (struct ip) +
	    + sizeof (struct udphdr) + pktlen;
	flags = 0;

	if (putmsg(fd, NULL, &data, flags) != 0) {
		(void) close(fd);
		return (-1);
	} else {
		(void) close(fd);
		return (0);
	}
}

/*
 * Function:	rejectFromFAToMN
 *
 * Arguments:	messageHdr - the message control block.
 *		entry - the MAAdvConfigEntry of the interface to send the
 *                  registration reply from, and the settings to return.  If
 *                  NULL, indicates there are possibly multiple mobile nodes
 *                  to return an error to due to an ICMP error we've received
 *                  after attempting to pass a registration request onto an HA.
 *                  The registration reply should be returned to all mobile
 *                  nodes with a pending entry to the home agent identified by
 *                  the destination address of the returned IP packet inside
 *                  messageHdr->pkt.
 *		code - the error value to return.
 *
 * Description:	This function will return a registration reply set with the
 *              error set to code on the interface from entry back to the
 *              address identified as the source address of the original
 *              registration reqeust (except when the home address of the MN is
 *		not assigned as yet i.e 0.0.0.0, in which case the packet is
 *		to an IP level broadcast and link layer unicast (i.e MN's L2
 *		addr)
 */
void
rejectFromFAToMN(MessageHdr *messageHdr, MaAdvConfigEntry *entry, int code)
{
	regReply *replyPtr;
	boolean_t visitor_entryExists;
	int val, replyLen = sizeof (regReply);	/* for now... */
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	struct ether_addr ether;

	/*
	 * We will send a denial. Note that we can re-use the same
	 * message header (and buffer) to reply.
	 */
	/* LINTED BAD_PTR_CAST_ALIGN */
	replyPtr = (regReply *) messageHdr->pkt;
	replyPtr->type = REG_REPLY_TYPE;
	replyPtr->code = (uint8_t)code;
	if (code == FA_REG_LIFETIME_TOO_LONG)
		replyPtr->regLifetime = htons(entry->maAdvMaxRegLifetime);

	/*
	 * Copy the identifier from the original Registration Request
	 * into the Registration Reply. Since the headers are different
	 * this requires a bcopy.
	 */
	bcopy(messageHdr->pkt+16, messageHdr->pkt+12, 8);

	/*
	 * TODO: handle extensions? keep in mind that the request is
	 * poorly formed so we may not be able to do the right thing.
	 */
	visitor_entryExists = isAcceptedVisitor(&faVisitorHash,
	    replyPtr->homeAddr, entry->maIfaceAddr);
	if (visitor_entryExists == _B_FALSE) {

		/*
		 * If the source link layer address is valid add an ARP
		 * entry else don't. The entry could be invalid for variety
		 * of reasons (See recvNetworkPacket)
		 */
		if (messageHdr->isSllaValid &&
		    (replyPtr->homeAddr != INADDR_ANY)) {
			/*
			 * Add a temporary ARP entry to prevent the FA from
			 * broadcast ARPing.
			 */
			if ((val = arpIfadd(replyPtr->homeAddr,
			    messageHdr->slla.sdl_data,
			    messageHdr->inIfindex)) < 0) {
				syslog(LOG_ERR, "SIOCSXARP failed... %s",
				    err2str(val));
			}
		}
	}

	/*
	 * If the request was sent from a mobile node whose home address is not
	 * yet configured i.e 0.0.0.0, then the reply should be sent as an IP
	 * level broadcast but with the mobile nodes link layer address as the
	 * destination L2 i.e link layer unicast. This can be done by opening a
	 * link layer raw socket, constructing the various headers and sending
	 * the packet (cf. RFC 3220 section 3.7.2.3)
	 */
	if ((replyPtr->homeAddr == INADDR_ANY) && messageHdr->isSllaValid) {
		if (sendRawPkt(messageHdr, entry, replyLen) == 0) {
			mipverbose(("\n---- %s (%s) ----\n",
					sprintTime(currentTime,
					    MAX_TIME_STRING_SIZE),
					sprintRelativeTime(relativeTime,
					    MAX_TIME_STRING_SIZE)));
			(void) memcpy(ether.ether_addr_octet,
			    messageHdr->slla.sdl_data, ETHERADDRL);
			mipverbose(("FA denied reg req from %s.%d for "
					"MN  %s [MAC: %s] (Code %d)\n",
					ntoa(messageHdr->src, addrstr1),
					messageHdr->srcPort,
					ntoa(replyPtr->homeAddr, addrstr2),
					ether_ntoa(&ether), replyPtr->code));
			mipverbose(("Registration denial sent by FA is:\n"));
			if (logVerbosity > 2)
				printBuffer(messageHdr->pkt, replyLen);
			mipverbose(("\n"));
			return;
		} else {
			mipverbose(("rejectFromFAtoMN: raw send failed at FA to"
					" send denial.\n"));
			return;
		}
	}
	/*
	 * Set socket option IP_XMIT_IF to get the registration reply
	 * unicast to the mobile node...
	 */
	val = messageHdr->inIfindex;
	if (setsockopt(entry->maIfaceUnicastSock, IPPROTO_IP, IP_XMIT_IF,
	    &val, sizeof (val)) < 0) {
		/* There's a problem... */
		mipverbose(("Can't set IP_XMIT_IF socket option for "
		    "registration reply error message to mobile node %s."
		    "at interface index %d\n",
		    ntoa(messageHdr->src, addrstr2), val));
	}


	if (sendUDPmessage(entry->maIfaceUnicastSock, messageHdr->pkt,
	    replyLen, messageHdr->src, messageHdr->srcPort) == 0) {
	    mipverbose(("\n---- %s (%s) ----\n",
		sprintTime(currentTime, MAX_TIME_STRING_SIZE),
		sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE)));
	    mipverbose(("FA denied reg req from %s.%d for MN %s (Code %d)\n",
		ntoa(messageHdr->src, addrstr1), messageHdr->srcPort,
		ntoa(replyPtr->homeAddr, addrstr2), replyPtr->code));

	    mipverbose(("Registration denial sent by FA is:\n"));
	    if (logVerbosity > 2)
		printBuffer(messageHdr->pkt, replyLen);
	    mipverbose(("\n"));

	} else {
	    mipverbose(("sendto failed at FA while sending denial.\n"));
	}

	/* Reset IP_XMIT_IF option */

	val = 0;
	if (setsockopt(entry->maIfaceUnicastSock, IPPROTO_IP, IP_XMIT_IF,
	    &val, sizeof (val)) < 0) {
		/* There's a problem... */
		mipverbose(("Can't unset IP_XMIT_IF socket option"
		    "for socket id %d\n", entry->maIfaceUnicastSock));
	}
	if (visitor_entryExists == _B_FALSE) {

		if (messageHdr->isSllaValid && (replyPtr->homeAddr !=
			INADDR_ANY)) {
			/*
			 * Delete the temporary ARP entry
			 */
			if ((val = arpIfdel(replyPtr->homeAddr,
			    messageHdr->slla.sdl_data,
			    messageHdr->inIfindex)) < 0) {
				/*
				 * If the deletion failed bcos there was no
				 * entry then we don't need to report it
				 */
				if (val != (-1)*ENXIO)
					syslog(LOG_ERR,
					    "SIOCDXARP failed... %s",
					    err2str(val));
			}
		}
	}
	mipverbose(("\n\n"));
}


/*
 * Function:	rejectFromICMPToMN
 *
 * Arguments:	messageHdr - the message control block.  Currently contains
 *		    in messageHdr->pkt an ICMP error generated by our forward
 *		    of a registration request to an unreachable home agent.
 *		haAddr - the address of the home agent that ICMP is telling us
 *                  is unreachable.
 *		code - the error value to return to the mobile node.
 *
 * Description:	This function will return a registration reply with the error
 *              set to code to every *pending* mobile node which has
 *              identified haAddr as that of it's home agent.
 */
void
rejectFromICMPToMN(MessageHdr *messageHdr, ipaddr_t haAddr, int code)
{
	FaVisitorEntry *entry = NULL;
	char srcaddrstr[INET_ADDRSTRLEN];
	char dstaddrstr[INET_ADDRSTRLEN];
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	regReply *replyPtr = (regReply *)messageHdr->pkt; /* reuse it */
	int replyLen = sizeof (regReply);  /* Size of registration reply */
	MipSecAssocEntry *mipSAE;
	uint32_t state[2];		/* For hash-table enumeration */
	char currentTime[MAX_TIME_STRING_SIZE];  /* syslog messages */
	char relativeTime[MAX_TIME_STRING_SIZE]; /* syslog messages */

	/*
	 * Rationale: Who do we send the registration reply to?
	 * ----------------------------------------------------
	 *
	 * The ICMP error is known, send the regreP, but to whom?  What do we
	 * have? [T]Here's the rub: there's nothing of the forwarded regreQ
	 * returned in the ICMP!  RFC792 says ICMP returns the IP header, plus
	 * 64 bits, or in this case just enough to cover the UDP header!  We do
	 * have the IP dstaddr that caused the error - the IPaddr the MN says
	 * is it's HA.  We have the interface the ICMP came in on - the dstaddr
	 * of the ICMP, but we don't know if the MN was using that as CoA.  To
	 * know that we'd need to know if the MN was colocated and using us as
	 * "relay", but simply knowing if the 'R' bit is set on this interface
	 * isn't enough.  The MN could have colocated, and still be registering
	 * with us even if we aren't setting the 'R' bit!  Therefore, our IPaddr
	 * on this interface doesn't give us anything else to search on.
	 *
	 * Summary: all we have to go on is the identified HAaddr, and that the
	 * MN MUST have (a pending?) registration on this interface (note: if
	 * the MN is reregistering, the FA will have a non-pending entry in its
	 * hash, and also a[nother] *pending* entry [for many a good reason]).
	 *
	 * The only thing we can do is send a registration reply to all the
	 * pending MNs [on this interface] requesting service to this HA.  At
	 * least this way bound MNs wont be effected, and those with pending
	 * registrations to another HA are also not effected.  All those that
	 * are registering (pending) to this HA on this interface may then have
	 * to reregister, but everything should eventually get worked out.  In
	 * practice, the number of pending registrations to a particular HA
	 * should be low (in context), with the notable exception of FA-reset
	 * causing *every* MN that was registered [with this HA] to reregister
	 * simultaneously.  Note also, though, that if this HA is unreachable
	 * for one MN, it's likely unreachable for them all!
	 *
	 * One more thing to figure out:
	 *
	 * We need a buffer to send (since we presume there's at least one MN
	 * awaiting our response).  This is the only place in the code we don't
	 * have a regreQ to reuse the bits of.  messageHdr->pkt is here, and
	 * will be free()'d when screenICMPpkt() return, so if it's long
	 * enough, let's us it!
	 *
	 * First order thoughts:
	 * A regreP takes 20 bytes (we don't need to include UDP/IP headers),
	 * plus we potentially need room for the FA-MN auth (authext and hash)
	 * if required which is another 6 + 16 bringing the total to 42 bytes.
	 *
	 * messageHdr->pkt MUST be enough for outerIPhdr, ICMPhdr,
	 * innerIPhdr, + 64bits [the UDP header], which is *at least*
	 * 20 + 8 + 20 + 8 or 56 bytes.
	 *
	 * At this time it appears any ICMP_UNREACH message that contains a
	 * returned registration request (up to the end of UDP) will be big
	 * enough.  Note: at this time challenges don't have to be appended
	 * when there is a registration reply indicating an error.
	 *
	 * The big question is MUST we include an NAIext in this case?  RFC2794
	 * etc, are unclear, but to be nice to multihommed MNs there is an
	 * argument to be made for including it, but it would likely mean a
	 * realloc() of messageHdr->pkt!  For now, we'll skip it.
	 *
	 * Summary: reply is going to a set of pending MN(s) due to an ICMP
	 * error when attempting to forward a registration request to haAddr.
	 * Parse the FaVisitorHash for pending MNs [registering via this
	 * interface] using this HAaddr.
	 *
	 * OK, we're going with it.  Make sure nothing survives of the ICMP!
	 */
	bzero(&messageHdr->pkt, messageHdr->pktLen);

	/* init the Enumerator State */
	initEnumeratorState(&state, sizeof (*(state)));

	/* enumerateAllHashTableEntries() - will return NULL when we're out. */
	while ((entry = enumerateAllHashTableEntries(&faVisitorHash,
	    &(state[BUCKET]), &(state[OFFSET]), LOCK_WRITE)) != NULL) {
		/* LOCK_WRITE because we may accept this entry for removal! */
		int val;

		/*
		 * Is it pending to the same HA [on the same iface]?  Recall,
		 * the HA is the original ip_dst that wasn't reachable.
		 */
		if ((entry->faVisitorRegIsAccepted != _B_FALSE) ||
		    (entry->faVisitorHomeAgentAddr != haAddr)) {
			/* not a MN we need to reply to */

			/* don't forget to unlock this one! */
			(void) rw_unlock(&entry->faVisitorNodeLock);

			/* read on McDuff. */
			continue;
		}

		/* This is someone to reject. */
		mipverbose(("...found a MN to reply to - IP address %s.\n",
		    ntoa(entry->faVisitorAddr, dstaddrstr)));

		/* Accept the entry for expiration (see delFAVEPtr())! */
		entry->faVisitorRegIsAccepted = _B_TRUE;

		/* set the important information */
		replyPtr->type = REG_REPLY_TYPE;
		replyPtr->code = (uint8_t)code;
		replyPtr->regLifetime = 0;
		replyPtr->homeAddr = entry->faVisitorHomeAddr;
		replyPtr->haAddr = entry->faVisitorHomeAgentAddr;
		replyPtr->IDHigh = entry->faVisitorRegIDHigh;
		replyPtr->IDLow = entry->faVisitorRegIDLow;

		/*
		 * The jury's out as to whether we want/should/need/MUST do
		 * this.  For now, let's also include the NAI if it'll fit.
		 */
		if ((entry->faVisitorMnNAILen) &&
		    (messageHdr->pktLen - replyLen >=
		    sizeof (entry->faVisitorMnNAILen))) {
			replyLen += appendExt((messageHdr->pkt + replyLen),
			REG_MN_NAI_EXT_TYPE,
			(unsigned char *)entry->faVisitorMnNAI,
			entry->faVisitorMnNAILen);
		}

		/*
		 * Don't forget the FA-MN authenticator (if configured).
		 * Note appendAuthExt() assumes the authenticator is always
		 * going to be AUTHENTICATOR_LEN bytes!  If you change
		 * auth.c:appendAuthExt(), change this!!!
		 */
		if ((messageHdr->pktLen - replyLen >= AUTHENTICATOR_LEN) &&
		    ((mipSAE = findSecAssocFromSPI(entry->faVisitorSPI,
			    LOCK_READ)) != NULL)) {
				/* formulate an authenticator... */
				replyLen += appendAuthExt(messageHdr->pkt,
				    replyLen, REG_MF_AUTH_EXT_TYPE, mipSAE);

				/* remove the READ lock */
				(void) rw_unlock(&mipSAE->mipSecNodeLock);
		}

		/*
		 * If the source link layer address is valid add an ARP
		 * entry else don't. The entry could be invalid for variety
		 * of reasons (See recvNetworkPacket)
		 */
		if (messageHdr->isSllaValid) {
			/*
			 * Add a temporary ARP entry to prevent the FA from
			 * broadcast ARPing.
			 */
			if ((val = arpIfadd(replyPtr->homeAddr,
			    messageHdr->slla.sdl_data,
			    messageHdr->inIfindex)) < 0) {
				syslog(LOG_ERR, "SIOCSXARP failed... %s",
				    err2str(val));
			}
		}

		/*
		 * Note: we're not including a challenge!  That may mean we'll
		 * run out of buffer, and it's also NOT required by spec.
		 */

		/*
		 * Set socket option IP_XMIT_IF to get the regreP unicast
		 * to the mobile node...
		 */
		val = entry->faVisitorInIfindex;
		if (setsockopt(messageHdr->ifEntry->maIfaceUnicastSock,
		    IPPROTO_IP, IP_XMIT_IF, &val, sizeof (val)) < 0) {
			/* There's a problem... */
			syslog(LOG_ERR,
			    "Can't set IP_XMIT_IF socket option for"
			    " registration reply to mobile node %s.",
			    ntoa(messageHdr->src, srcaddrstr));
		}

		/* may as well try anyway (we do this elsewhere) */
		if (sendUDPmessage(messageHdr->ifEntry->maIfaceUnicastSock,
		    messageHdr->pkt, messageHdr->pktLen, entry->faVisitorAddr,
		    entry->faVisitorPort) == 0) {
			mipverbose(("\n---- %s (%s) ----\n",
			    sprintTime(currentTime,
				MAX_TIME_STRING_SIZE),
			    sprintRelativeTime(relativeTime,
				MAX_TIME_STRING_SIZE)));
			mipverbose(("FA sent ICMP-reply to %s.%d (Code %d)\n",
			    ntoa(entry->faVisitorAddr, dstaddrstr),
			    entry->faVisitorPort, replyPtr->code));
			mipverbose(("FA sent ICMP-reply packet:\n"));
			if (logVerbosity > 2)
				printBuffer(messageHdr->pkt,
				    messageHdr->pktLen);
			mipverbose(("\n"));

		} else {
			syslog(LOG_ERR,
			    "sendto failed while sending ICMP-reply.");
		}

		/* Reset IP_XMIT_IF option on socket */
		val = 0;
		if (setsockopt(messageHdr->ifEntry->maIfaceUnicastSock,
		    IPPROTO_IP, IP_XMIT_IF, &val, sizeof (val)) < 0) {
			syslog(LOG_ERR,
			    "Can't unset socket option IP_XMIT_IF"
			    "which was set for interface index %d",
			    entry->faVisitorInIfindex);
		}

		/* cleanup */
		if (messageHdr->isSllaValid) {
			/*
			 * Delete the temporary ARP entry
			 */
			if ((val = arpIfdel(replyPtr->homeAddr,
			    messageHdr->slla.sdl_data,
			    messageHdr->inIfindex)) < 0) {
				/*
				 * If the deletion failed
				 * because there was no entry
				 * entry then we don't need to
				 * report it.
				 */
				if (val != (-1)*ENXIO) {
					syslog(LOG_ERR,
					    "SIOCDXARP failed %s",
					    err2str(val));
				}
			}
		}

		/*
		 * Should we delete this FAVisitorEntry?  The reason to do so
		 * is if there's multiple MNs to reply to, we're going to send
		 * registration replies to all of them at this time.  When/if
		 * another ICMP comes back from another's registration request,
		 * it would be sloppy (at best) to generate another set of
		 * registration replies.  Generating multiple registration
		 * replies to the same MN in response to a set of registration
		 * requests (in this case ICMPs) may also be considered a
		 * literal violation of 2002-bis:
		 *
		 *	A foreign agent MUST NOT transmit a Registration
		 *	Reply except when relaying a Registration Reply
		 *	received from a mobile node's home agent, or when
		 *	replying to a Registration Request received from
		 *	a mobile node in the case in which the foreign
		 *	agent is denying service to the mobile node.
		 *
		 * The counter-argument to NOT delete this entry, is (bug?)
		 * delFAVEptr() doesn't do anything for pending MNs; we could
		 * let the timers kill off these pending FAVE entries.  These
		 * MNs are likely to re-regreQ anyway, so there's likely some
		 * [performance, etc.] advantage to leaving them around.
		 */

		/*
		 * Think: should we also generate an accounting stop request
		 * (_B_TRUE for now)?  The MN is likely going to reregister
		 * either with the same HA (hopefully in time-fallback), or
		 * another.  Deleting the record is likely only going to
		 * create more work for us when this happens, though it's
		 * unclear if leaving it around may cause AAA auditing issues.
		 * Better to spend the time to clear it up, which comes with
		 * deleting this pending entry.  REASON_UNKNOWN is because
		 * there's no accounting reason for it.
		 */
		delFAVEptr(entry, _B_TRUE, REASON_UNKNOWN);

		/* don't forget to unlock this one! */
		(void) rw_unlock(&entry->faVisitorNodeLock);

	} /* fin looping through pending entries */


	/* we're out of MNs, so we're done reacting to the ICMP */
	return;

} /* rejectFromICMPToMN() */


void
forwardFromFAToHA(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    boolean_t triggeredByRadius)
{
	regRequest *requestPtr;
	/* LINTED E_FUNC_SET_NOT_USED */
	authExt *mnAuthExt;
	MipSecAssocEntry *mipSecAssocEntry;
	MobilityAgentEntry *mae;
	int mnAuthExtLen = 0;
	int index, challengeindex;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char addrstr3[INET_ADDRSTRLEN];
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	int code;
	int maAuthExtLen;
	/* LINTED E_FUNC_SET_NOT_USED */
	genAuthExt *maAuthExt;
	/* LINTED E_FUNC_SET_NOT_USED */
	unsigned char *challenge;
	size_t challengeLen = 0;

	mipverbose(("forwardFromFAToHA..."));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	/*
	 * RFC3012:
	 *
	 * Valid cases:	MH FAC MN-AAA
	 *		FAC MN-AAA
	 *		MH FAC MF
	 *		MH
	 */

	/*
	 * Is Foreign Agent Challenge present?
	 */
	GET_EXT_DATA(messageHdr, index, REG_MF_CHALLENGE_EXT_TYPE,
	    challenge, challengeLen);
	challengeindex = index;

	if (!triggeredByRadius) {
		if (challengeLen == 0) {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			GET_AUTH_EXT(messageHdr, index, REG_MH_AUTH_EXT_TYPE,
			    mnAuthExt, mnAuthExtLen);
		}
	}
	if (mnAuthExtLen == 0 || triggeredByRadius) {
		/*
		 * Support for the generalized
		 * authentication extension.
		 */

		/* LINTED BAD_PTR_CAST_ALIGN */
		GET_GEN_AUTH_EXT(messageHdr, index,
		    GEN_AUTH_MN_AAA, maAuthExt, maAuthExtLen);
		/*
		 * Case where we have:
		 *
		 *	MH FAC MF
		 */
		if (maAuthExtLen == 0 && challengeLen != 0) {
			index = challengeindex;
		}
	}

	/*
	 * Support for different extension header
	 * format.
	 *
	 * Initialize the basic length of the message, which is
	 * everything up to and including the MN Authentication
	 * Extension (index is assumed to be set from above).
	 */
	messageHdr->pktLen = (messageHdr->extIdx[index] - messageHdr->pkt);

	/*
	 * Increase the packet length.
	 */
	messageHdr->pktLen += messageHdr->extHdrLength[index] +
	    messageHdr->extLength[index];

	/*
	 * Do we need to add the FA-HA Auth Extension? Let's not
	 * forget the entry will be locked upon the return, so
	 * it's our responsibility to unlock the security
	 * assocation entry.
	 */
	if ((mipSecAssocEntry =
	    findSecAssocFromIp(requestPtr->haAddr,
		LOCK_READ)) != NULL) {

		messageHdr->pktLen += appendAuthExt(messageHdr->pkt,
		    messageHdr->pktLen, REG_FH_AUTH_EXT_TYPE,
		    mipSecAssocEntry);

		/*
		 * As promised, we unlock the SA
		 */
		(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
	} else {
		/*
		 * Was authentication required?
		 */
		if (fhAuthRequired) {
			syslog(LOG_ERR, "Error: No Sa for Home Agent");
			code = HA_FA_AUTH_FAILURE;
			faCounters.faHAAuthFailureCnt++;
			rejectFromFAToMN(messageHdr, entry, code);
			return;
		}
	}

	/*
	 * We may need to install an "IPsecRequest apply ..." policy that will
	 * protect the registration in the way our SA tells us to, as well as
	 * any "IPsecReply permit ..." policy in anticipation of a response.
	 * Since mobile nodes can share the same HA, we may have already done
	 * this, so check to make sure it's not already in place.
	 */
	if ((mae = findMaeFromIp(requestPtr->haAddr, LOCK_READ)) != NULL) {
		if (((mae->maIPsecFlags & IPSEC_REQUEST_APPLY) == 0) &&
		    (IPSEC_REQUEST_ANY(mae->maIPsecSAFlags[IPSEC_APPLY]))) {
			/* Policy hasn't been installed for this agent-peer */
			char peerAddr[IPv4_ADDR_LEN];

			(void) ntoa(mae->maAddr, peerAddr);

			/* do whatever we do to install the ipsec policy */
			if (installIPsecPolicy(mae->maIPsecRequest[IPSEC_APPLY])
			    < 0) {
				/* failed, log it */
				syslog(LOG_CRIT,
				    "Could not install %s for [Address %s]: %s",
				    IPSEC_POLICY_STRING(IPSEC_REQUEST_APPLY),
				    peerAddr, mae->maIPsecRequest[IPSEC_APPLY]);

				/* unlock */
				(void) rw_unlock(&mae->maNodeLock);

				/* never ignore SAs - fail */
				return;
			}

			/* set the flag */
			mae->maIPsecFlags |= IPSEC_REQUEST_APPLY;
		}

		/*
		 * We're forwarding the registration request to the home agent.
		 * We need to set the reply-permit policy in anticipation of a
		 * registration reply from the home agent.
		 */
		if (((mae->maIPsecFlags & IPSEC_REPLY_PERMIT) == 0) &&
		    (IPSEC_REPLY_ANY(mae->maIPsecSAFlags[IPSEC_PERMIT]))) {
			/* This SA hasn't been installed for this agent-peer */
			char peerAddr[IPv4_ADDR_LEN];

			/* this is for error reporting */
			(void) ntoa(mae->maAddr, peerAddr);

			/* have ipsec add it */
			if (installIPsecPolicy(mae->maIPsecReply[IPSEC_PERMIT])
			    < 0) {
				/* Failed - log it. */
				syslog(LOG_CRIT,
				    "Could not install %s for [Address %s]: %s",
				    IPSEC_POLICY_STRING(IPSEC_REPLY_PERMIT),
				    peerAddr, mae->maIPsecReply[IPSEC_PERMIT]);

				/* unlock */
				(void) rw_unlock(&mae->maNodeLock);

				/* Never send if we can't enforce policy. */
				return;
			}
			/* set the flag */
			mae->maIPsecFlags |= IPSEC_REPLY_PERMIT;
		}

		/* we're sending, so this agent is now officially an HA peer */
		mae->maPeerFlags |= HA_PEER;

		/* unlock */
		(void) rw_unlock(&mae->maNodeLock);
	}

	/* forward to home agent */
	if (sendUDPmessage(entry->maIfaceUnicastSock,
		    messageHdr->pkt, messageHdr->pktLen, requestPtr->haAddr,
		    MIP_PORT) == 0) {
			mipverbose(("\n---- %s (%s) ----\n",
			    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
			    sprintRelativeTime(relativeTime,
				MAX_TIME_STRING_SIZE)));
			mipverbose(("FA relayed reg req from %s.%d to HA "
			    "%s.%d for MN homeaddr %s\n",
			    ntoa(messageHdr->src, addrstr1),
			    messageHdr->srcPort,
			    ntoa(requestPtr->haAddr, addrstr2), MIP_PORT,
			    ntoa(requestPtr->homeAddr, addrstr3)));

			mipverbose(("Registration of length %d relayed by " \
			    "FA is:\n", messageHdr->pktLen));
			if (logVerbosity > 2) {
				printBuffer(messageHdr->pkt,
				    messageHdr->pktLen);
			}
			mipverbose(("\n"));

			faCounters.faRegReqRelayedCnt++;
		} else {
			syslog(LOG_ERR, "sendto failed at FA while relaying "
			    "registration.");
		}

		mipverbose(("\n\n"));
}

/*
 * Function: delHABE
 *
 * Arguments:	hamnePtr - Pointer to a pointer to a mobile node entry.
 *		mnAddr - Mobile Node's Home Address
 *		COAddr - Mobile Node's care of address.
 *		sessionLifeTime - Duration of the session.
 *
 * Description:	Delete a binding entry for the specified mnAddr in Hash
 *		Table. If the care-of address COAddr equals mnAddr, all
 *		bindings for the mobile node are deleted.
 *
 *		Note: It is necessary that the Mobile Node Entry is in a
 *		write locked state when we enter this function.
 *
 * Returns:	Upon successful completion, the sessionLifeTime argument
 *		will contain the number of session the session was active.
 */
static void
delHABE(HaMobileNodeEntry **hamnePtr, ipaddr_t mnAddr, ipaddr_t COAddr,
	uint32_t *sessionLifeTime)
{
	HaBindingEntry *entry;
	HaBindingEntry *prev_entry = NULL;
	time_t currentTime;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];

	*sessionLifeTime = 0;

	mipverbose(("delHABE called for mnAddr %s COAddr %s\n",
		ntoa(mnAddr, addrstr1),
		ntoa(COAddr, addrstr2)));

	entry = (*hamnePtr)->bindingEntries;

	while (entry) {
		if ((entry->haBindingMN == mnAddr) &&
		    (entry->haBindingCOA == COAddr))  {
			/* Found a match, delete it */
			if (prev_entry == NULL) {
				(*hamnePtr)->bindingEntries =
				    entry->next;
			} else {
				prev_entry->next = entry->next;
			}

			delHABEent(*hamnePtr, entry);

			GET_TIME(currentTime);
			*sessionLifeTime += currentTime -
			    entry->haBindingTimeGranted;
			free(entry);
			break;
		}
		prev_entry = entry;
		entry = entry->next;
	}

	/*
	 * We need to delete the Mobile Node Entry if the
	 * entry was dynamic and has no more bindings.
	 */
	if ((*hamnePtr)->haMnBindingCnt == 0 &&
	    (*hamnePtr)->haMnIsEntryDynamic == TRUE) {
		mipverbose(("Deleting Mobile Node #1"));
		/* Expired */
		if (delHashTableEntryUint(&haMobileNodeHash, *hamnePtr,
		    mnAddr, LOCK_NONE) == _B_FALSE) {
			syslog(LOG_ERR, "Unable to delete Mobile Node Entry");
		} else {
			(void) rw_unlock(&(*hamnePtr)->haMnNodeLock);
			(void) rwlock_destroy(&(*hamnePtr)->haMnNodeLock);
			free(*hamnePtr);
			*hamnePtr = NULL;
		}
	}
}


/*
 * Function: addHABE
 *
 * Arguments:	hamnePtr - Pointer to Mobile Node Entry
 *		src - Source Address of the COA
 *		srcPort - Source Port of the COA
 *		ifEntry - Pointer to the Interface Entry (optional)
 *		regFlags - Registration Flags
 *		homeAddr - Home Address
 *		COAddr - Care of Address
 *		haAddr - Home Agent's Address
 *		lifetime - Registration Lifetime
 *		existingBinding - Boolean that is set to _B_TRUE if the
 *				request is renewing an exiting binding
 *				entry.
 *		sessionLifeTime - If the event of a binding renewal,
 *				this argument will return the number
 *				of seconds the binding entry has
 *				been active.
 *
 * Description:	Add a binding for the specified pair of mobile node
 *		and care-of address. By the time we get here, we know
 *		that we are processing a registration and coAddr is
 *		not the same as mnAddr. Note that entry is the the
 *		mobility interface on the mobile node's home network.
 *
 *		Note that this function no longer accepts the
 *		registration request as a parameter, but requires
 *		each individual fields. This is needed in order to
 *		have a single function that creates bindings for both
 *		when a request is received off the wire, and when the
 *		agent attempts to restore bindings from disk.
 *
 *		Note: The caller MUST have write locked the Mobile Node
 *		Entry prior to calling this function.
 *
 * Returns:	int - 0 if the binding entry was successfully added.
 *		Upon successful completion, the sessionLifeTime argument
 *		will contain the number of session the session was
 *		active, and the existingBinding field will be set if the
 *		request is renewing an existing binding entry.
 */
/* ARGSUSED */
int
addHABE(HaMobileNodeEntry *hamnePtr, ipaddr_t src, in_port_t srcPort,
    MaAdvConfigEntry *ifEntry, uint8_t regFlags, ipaddr_t homeAddr,
    ipaddr_t COAddr, ipaddr_t haAddr, uint32_t lifetime,
    boolean_t *existingBinding, uint32_t *sessionLifeTime)
{
	int val;
	time_t currentTime;
	HaBindingEntry *hentry;
	HaBindingEntry *prev_hentry = NULL;
	HaBindingEntry *tmp;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char addrstr3[INET_ADDRSTRLEN];


	*existingBinding = _B_FALSE;
	*sessionLifeTime = 0;

#ifdef NO_SIMULTANEOUS
	/*
	 * If NO_SIMULTANEOUS is defined, we do not allow simultaneous
	 * bindings. This means that a Mobile Node can only have a single
	 * binding. The reason why this feature is not currently supported
	 * is due to the architecture of the new 2.8 tunnel driver. By
	 * clearing this flag, we ensure that all previous bindings will
	 * be cleared
	 */
	regFlags &= ~REG_SIMULTANEOUS_BINDINGS;
#endif

	/*
	 * If the interface was not provided, it is because we are trying
	 * to restore a binding entry... Let's find it.
	 */
	if (ifEntry == NULL) {
		/*
		 * Get the matching maIfaceAddr from mnAdvConfigTable
		 */
		if ((ifEntry = (MaAdvConfigEntry *)findHashTableEntryUint(
			&maAdvConfigHash, hamnePtr->haBindingIfaceAddr,
			    LOCK_NONE, NULL, 0, 0,
			    0)) == NULL) {
			syslog(LOG_ERR, "Unable to find interface in hash " \
			    "table");
			return (-1);
		}
	}

	hentry = hamnePtr->bindingEntries;

	while (hentry) {
		if (hentry->haBindingMN == homeAddr) {
		    if (hentry->haBindingCOA == COAddr) {
				*existingBinding = _B_TRUE;
				hentry->haBindingSrcAddr = src;
				hentry->haBindingHaAddr = haAddr;

				/*
				 * We now compare the lifetime
				 * received in the request with the value
				 * configured on the interface.
				 */
				GET_TIME(currentTime);
				if ((ntohs(lifetime) >
				    (unsigned short)
				    ifEntry->maAdvMaxRegLifetime)) {
					hentry->haBindingTimeExpires =
					    currentTime +
					    (uint32_t)
					    ifEntry->maAdvMaxRegLifetime;
				} else {
					hentry->haBindingTimeExpires =
					    currentTime +
					    (uint32_t)ntohs(
						    lifetime);
				}
				hentry->haBindingSrcPort = srcPort;
				hentry->haBindingRegFlags = regFlags;

				mipverbose((
					"HA renewed binding %s@%s "
					"for %ld sec (Binding cnt %d).\n",
					ntoa(homeAddr, addrstr1),
					ntoa(COAddr, addrstr2),
					hentry->haBindingTimeGranted,
					hamnePtr->haMnBindingCnt));

				GET_TIME(currentTime);
				*sessionLifeTime =  currentTime -
					hentry->haBindingTimeGranted;
				hentry->haBindingTimeGranted = currentTime;
			} else {
				/*
				 * found an entry for this MN with another COA
				 */
				if ((regFlags & REG_SIMULTANEOUS_BINDINGS)
				    == 0) {
				    /* Found a match, delete it */
				    if (prev_hentry == NULL) {
						hamnePtr->bindingEntries =
						    hentry->next;
				    } else {
						prev_hentry->next =
						    hentry->next;
				    }

				    tmp = hentry->next;

				    delHABEent(hamnePtr, hentry);

				    free(hentry);
				    hentry = tmp;
				    continue;
				}
		    }
		}

		prev_hentry = hentry;
		hentry = hentry->next;
	}

	if (*existingBinding == _B_TRUE)
		return (0);

	/*
	 * We did not find an entry, now we create one.
	 */
	if ((hentry =
	    (HaBindingEntry *)calloc(1, sizeof (HaBindingEntry))) == NULL) {
	    return (-1);
	}

	/*
	 * We need to create a new entry ...
	 * update binding count for this mobile node and total bindings
	 */
	hamnePtr->haMnBindingCnt++;

	mipverbose(("At %s, creating tunnel for %s through %s %s\n",
	    ntoa(haAddr, addrstr1), ntoa(homeAddr, addrstr2),
	    ntoa(COAddr, addrstr3),
	    (regFlags & REG_SIMULTANEOUS_BINDINGS) ? "(simultaneous)":""));

	if ((val = encapadd(homeAddr, haAddr, COAddr,
	    (uint8_t)regFlags & REG_REVERSE_TUNNEL)) < 0) {
	    syslog(LOG_ERR, "encapadd failed ... %s", err2str(val));
	}

	/*
	 * Proxy arp only works for non-PPP interfaces.
	 */
	if (((ifEntry->maIfaceFlags & IFF_POINTOPOINT) == 0) &&
	    (hamnePtr->haMnBindingCnt == 1)) {
		mipverbose(("Enabling tunneling for %s.\n",
		    ntoa(homeAddr, addrstr1)));

		mipverbose(("Setting proxy arp for %s at %s\n",
		    ntoa(homeAddr, addrstr1),
		    hwAddrWrite(ifEntry->maIfaceHWaddr, addrstr2)));

		if ((val = arpadd(homeAddr,
		    ifEntry->maIfaceHWaddr, ATF_PUBL)) < 0) {
			syslog(LOG_ERR, "First arpadd (proxy) failed ... %s",
			    err2str(val));
		}

		/*
		 * Solaris 2.8 automatically sends out a gratuitous ARP
		 * when a publishable ARP entry is created and in another
		 * OS, we expect arpadd to do so explicitly.
		 */
		haCounters.haGratuitousARPsSentCnt++;
	}

#ifdef FIREWALL_SUPPORT
	/*
	 * If the care-of-address is outside the protected domain then
	 * encapsulate and redirect those packets to the firewall's internal
	 * address.
	 * TODO: This will likely change since we should not delete the
	 * tunneling of a COA through FW unless *ALL* mobile nodes using that
	 * COA have their bindings expire, i.e. we need to keep a count of
	 * the number of MNs using that COA. We should be OK as long as an
	 * external COA is not shared by multiple mobile nodes.
	 */
	if (isInsideProtectedDomain(COAddr) == FALSE) {
	    mipverbose(("At %s, creating tunnel for %s through firewall %s 0\n",
		ntoa(haAddr, addrstr1), ntoa(COAddr, addrstr2),
		ntoa(domainInfo.fwAddr[0], addrstr3)));

	if ((val = encapadd(COAddr, haAddr, domainInfo.fwAddr[0],
	    (uint8_t)regFlags & REG_REVERSE_TUNNEL)) < 0) {
		syslog(LOG_ERR, "encapadd failed ... %s", err2str(val));
	    }
	}
#endif /* FIREWALL_SUPPORT */

	hentry->haBindingMN = homeAddr;
	hentry->haBindingCOA = COAddr;
	hentry->haBindingSrcAddr = src;
	hentry->haBindingHaAddr = haAddr;

	/*
	 * We now compare the lifetime received in the request with the value
	 * configured on the interface.
	 */
	GET_TIME(hentry->haBindingTimeGranted);
	if (ntohs(lifetime) > (unsigned short) ifEntry->maAdvMaxRegLifetime) {
		hentry->haBindingTimeExpires =
		    hentry->haBindingTimeGranted +
		    (uint32_t)ifEntry->maAdvMaxRegLifetime;
	} else {
		hentry->haBindingTimeExpires =
		    hentry->haBindingTimeGranted +
		    (uint32_t)ntohs(lifetime);
	}
	hentry->haBindingSrcPort = srcPort;
	hentry->haBindingRegFlags = regFlags;

	/*
	 * Add the node to the queue
	 */
	hentry->next = hamnePtr->bindingEntries;
	hamnePtr->bindingEntries = hentry;

	mipverbose(("HA added binding %s@%s at entry %p "
	    "for %ld sec (Binding cnt %d).\n",
	    ntoa(homeAddr, addrstr1), ntoa(COAddr, addrstr2), (void *)hentry,
	    hentry->haBindingTimeGranted, hamnePtr->haMnBindingCnt));

	return (0);
}

#ifdef RADIUS_ENABLED
void
radiusCloseSession(HaMobileNodeEntry *hamnePtr)
{
	char addr[20];
#ifdef RADIUS_DEBUG
	(void) fprintf(stderr, "Closing Session %p\n", hamnePtr->haRadiusState);
#endif
	radCloseSession(hamnePtr->haRadiusState,
				ntoa(hamnePtr->haMnAddr, addr), NULL);
#ifdef RADIUS_DEBUG
	(void) fprintf(stderr, "Finished Closing Session %p\n",
					hamnePtr->haRadiusState);
#endif
	hamnePtr->haRadiusState = NULL;
} /* radiusCloseSession */
#endif /* RADIUS_ENABLED */

/*
 * Function: HAdispatchRadius
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		entry - Pointer to the Interface Entry.
 *		inAddr - IP address this request received on
 *
 * Description:	The HA continues with the processing of the
 *              registration request after the Radius client
 *              responded with an ANSWER to the Open Session
 *              request.
 *
 * Returns:
 */

/* ARGSUSED */
void
HAdispatchRadius(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    ipaddr_t *inAddr)
{
	HaMobileNodeEntry *mnEntry = NULL;
	uint32_t mnSPI = 0;
	uint32_t faSPI = 0;
	int code = 0;

	/* If Auth failure from checking radius Answer (e.g., AVP's wrong) */
	if (messageHdr->aaaResultCode == HA_MN_AUTH_FAILURE) {
		haCounters.haMNAuthFailureCnt++;
		code = HA_MN_AUTH_FAILURE;
	} else if (messageHdr->aaaResultCode == HA_REVERSE_TUNNEL_REQUIRED) {
		haCounters.haReverseTunnelRequiredCnt++;
		code = HA_REVERSE_TUNNEL_REQUIRED;
	}
	if (code == 0) {
	    /* Assume no hamnePtr - no MobileNodeEntry (mnEntry) so far */
		code = haCheckRegReqAuthContinue(messageHdr, &mnEntry, &mnSPI,
		    &faSPI);
	}
	(void) HAprocessRegRequestContinue(messageHdr, messageHdr->ifEntry,
	    inAddr, code, mnEntry, mnSPI, faSPI);
}
/*
 * Function: HAprocessRegRequest
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		entry - Pointer to the Interface Entry.
 *		inAddr - IP address this request received on
 *
 * Description:	Process a registration request received at a home
 *		agent, and return the registration reply to the
 *		foreign agent.
 *
 *		If the Mobile Node was not configured locally,
 *		and the Mobile Node node was successfully
 *		authenticated (either by using the default SPI,
 *		or VIA the AAA infrastructure), we will dynamically
 *		create a Mobile Node Entry.
 *
 *		If the Mobile Node did not specify a Home Address,
 *		by including an NAI in the request and setting the
 *		home address to 0, we will allocate a Home Address
 *		out of an address pool (if configured). If the NAI
 *		was defined in the local configuration file, we will
 *		use the pool defined in the user's profile, otherwise
 *		we will use the default pool.
 *
 *		If successful and this is a request for a new binding,
 *		we will setup the tunnel.
 *
 *		If DIAMETER/RADIUS was enabled, we will issue accounting
 *		records to the AAA.
 *
 * Returns:
 */
/* ARGSUSED */
void
HAprocessRegRequest(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    ipaddr_t *inAddr)
{
	int code = MIP_SUCCESSFUL_REGISTRATION;
	uint32_t faSPI = 0;
	uint32_t mnSPI = 0;
	regRequest *requestPtr;
	HaMobileNodeEntry *mnEntry = NULL;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char addrstr3[INET_ADDRSTRLEN];
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	int okID = _B_FALSE;

	/* LINTED BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	mipverbose(("\n---- %s (%s) ----\n",
	    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
	    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE)));
	mipverbose(("HA got reg req [MN %s, HA %s, COA %s]\n",
	    ntoa(requestPtr->homeAddr, addrstr1),
	    ntoa(requestPtr->haAddr, addrstr2),
	    ntoa(requestPtr->COAddr, addrstr3)));
	mipverbose(("               [Lifetime %d sec, ID %0#10x : %0#10x]\n",
	    (uint32_t)ntohs(requestPtr->regLifetime),
	    ntohl(requestPtr->IDHigh),
	    ntohl(requestPtr->IDLow)));

	mipverbose(("HAprocessRegRequest called for pkt:\n"));
	if (logVerbosity > 2)
		printBuffer(messageHdr->pkt, messageHdr->pktLen);
	mipverbose(("\n"));

	/*
	 * If we are not the home agent, then reject this request.
	 */
	if ((requestPtr->haAddr != *inAddr) &&
	    (messageHdr->ifType != ON_BCAST_SOCK)) {
		code = HA_UNKNOWN_HOME_AGENT;
		haCounters.haUnknownHACnt++;
		HABuildRegReply(messageHdr, messageHdr->ifEntry,
		    code, mnEntry, faSPI, NULL, okID, _B_FALSE, 0,
		    _B_FALSE);
		return;
	}

	/*
	 * If the packet has the unused bit set, or if the home address
	 * is set to the care of address AND the lifetime is not set to
	 * zero, this packet is bad. The addresses can be the same when
	 * the Mobile Node sends an explicit deregistration, which is does
	 * when it enters its home network.
	 */
	if ((requestPtr->regFlags & REG_BIT_UNUSED) ||
	    ((requestPtr->homeAddr == requestPtr->COAddr) &&
		(requestPtr->regLifetime != 0))) {
			code = HA_POORLY_FORMED_REQUEST;
			haCounters.haPoorlyFormedRequestsCnt++;
			HABuildRegReply(messageHdr, messageHdr->ifEntry,
			    code, mnEntry, faSPI, NULL, okID, _B_FALSE, 0,
			    _B_FALSE);
			return;
	}

	/*
	 * Checking for an invalid packet, where the Home Agent's Address
	 * and the Care of Address are set to the same value, AND the lifetime
	 * is set to a non-zero address.
	 */
	if ((requestPtr->haAddr == requestPtr->COAddr) &&
		(requestPtr->regLifetime != 0)) {
			code = HA_POORLY_FORMED_REQUEST;
			haCounters.haPoorlyFormedRequestsCnt++;
			HABuildRegReply(messageHdr, messageHdr->ifEntry,
			    code, mnEntry, faSPI, NULL, okID, _B_FALSE, 0,
			    _B_FALSE);
			return;
	}

	/*
	 * Support for new MIER-style extension header.
	 *
	 * Are extensions ok and in the right order?
	 */
	if (mkRegExtList(messageHdr, sizeof (regRequest)) < 0) {
		code = HA_POORLY_FORMED_REQUEST;
		haCounters.haPoorlyFormedRequestsCnt++;
		HABuildRegReply(messageHdr, messageHdr->ifEntry,
		    code, mnEntry, faSPI, NULL, okID, _B_FALSE, 0, _B_FALSE);
		return;
	}

	/*
	 * Is the packet from Care-of address (FA or colocated MN) valid?
	 */
	if ((code = IsPacketFromCoaValid(messageHdr)) > 0) {
		haCounters.haPoorlyFormedRequestsCnt++;
		HABuildRegReply(messageHdr, messageHdr->ifEntry,
		    code, mnEntry, faSPI, NULL, okID, _B_FALSE,
		    0, _B_FALSE);
		return;
	} else if (code == MA_DROP_PACKET) {
	    /* drop the packet */
	    return;
	}

	/*
	 * Check the message's authentication. Note that this
	 * function will return the Mobile Node Entry in a write
	 * locked state. Therefore, we need to unlock the node
	 * when we are done with it.
	 */
	code = haCheckRegReqAuth(messageHdr, &mnEntry, &mnSPI, &faSPI);

	if (code == HA_MN_AUTH_FAILURE) {
		HABuildRegReply(messageHdr, messageHdr->ifEntry,
		    code, mnEntry, faSPI, NULL, okID, _B_FALSE, 0,
		    _B_FALSE);
		return;
	}

	if (aaaProtocol != RADIUS) {
		HAprocessRegRequestContinue(messageHdr,
		    messageHdr->ifEntry, inAddr, code, mnEntry, mnSPI,
		    faSPI);
	}

}

/*
 * Function: HAprocessRegRequestContinue
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		entry - Pointer to the Interface Entry.
 *		inAddr - IP address this request received on
 *              code - result code from HAprocessRegRequest().
 *              mnEntry - Mobile Node Entry
 *              mnSPI   - Mobile Node SPI
 *              faSPI   - FA SPI
 *
 * Description:	Continue to Process a registration request received
 *		at a home agent, and return the registration reply
 *		to the foreign agent.
 *              If aaaProtocol is Radius, this function is called
 *              after the Radius client returns auth Answer.
 *
 *              Otherwise, if not using Radius, just continue on from
 *              the HAprocessRegRequest() function until reg reply is
 *              sent.
 *
 *		If the Mobile Node was not configured locally,
 *		and the Mobile Node node was successfully
 *		authenticated (either by using the default SPI,
 *		or VIA the AAA infrastructure), we will dynamically
 *		create a Mobile Node Entry.
 *
 *		If the Mobile Node did not specify a Home Address,
 *		by including an NAI in the request and setting the
 *		home address to 0, we will allocate a Home Address
 *		out of an address pool (if configured). If the NAI
 *		was defined in the local configuration file, we will
 *		use the pool defined in the user's profile, otherwise
 *		we will use the default pool.
 *
 *		If successful and this is a request for a new binding,
 *		we will setup the tunnel.
 *
 *		If DIAMETER/RADIUS was enabled, we will issue accounting
 *		records to the AAA.
 *
 * Returns:
 */

/* ARGSUSED */
static void
HAprocessRegRequestContinue(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    ipaddr_t *inAddr, int code, HaMobileNodeEntry *mnEntry, uint32_t mnSPI,
    uint32_t faSPI)
{
	regRequest *requestPtr;
	boolean_t locallyAssignedAddress = _B_FALSE;
	MipSecAssocEntry *mnsae = NULL;
	int okID = _B_FALSE;
	boolean_t existingBindings = _B_FALSE;
	uint32_t sessionLifeTime = 0;
	char addrstr1[INET_ADDRSTRLEN];

	/* LINTED BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	if (code) {
		goto reply;
	}

	/*
	 * If we do not have a Mobile Node entry, let's see if
	 * we can create one.
	 */
	if (mnEntry == NULL) {
		if (requestPtr->regLifetime == 0) {
			/*
			 * A Mobile Node entry is needed for deregistration
			 * purposes. Let's silently discard this one.
			 */
			syslog(LOG_ERR, "Received a deregistration from an "
			    "unknown Mobile Node");
			return;
		}

		/*
		 * Is the Mobile Node requesting an IP Address?
		 */
		if (defaultPool && requestPtr->homeAddr == INADDR_ANY) {
			requestPtr->homeAddr =
			    GetAddressFromPool(defaultPool);

			if (requestPtr->homeAddr == INADDR_ANY) {
				code = HA_INSUFFICIENT_RESOURCES;
				syslog(LOG_ERR, "Unable to allocate address "
				    "from address pool %d",
				    defaultPool);
				haCounters.haInsufficientResourceCnt++;
				goto reply;
			}
			locallyAssignedAddress = _B_TRUE;
		}

		/*
		 * So it's one of those special cases where we need
		 * to create the Mobile Node Entry dynamically. Please
		 * note that the Mobile Node Entry will be write locked
		 * upon return.
		 */
		mipverbose(("Created a dynamic Mobile Node Entry with SPI %d\n",
		    mnSPI));
		mnEntry = CreateMobileNodeEntry(_B_TRUE,
		    requestPtr->homeAddr, (char *)messageHdr->mnNAI,
		    messageHdr->mnNAILen, 0, mnSPI, NULL,
		    (locallyAssignedAddress == _B_TRUE) ? defaultPool : 0);

		if (mnEntry == NULL) {
			/*
			 * We've got some bigger fish to fry...
			 */
			syslog(LOG_CRIT, "Unable to create dynamic MN Entry");
			haCounters.haInsufficientResourceCnt++;
			code = HA_INSUFFICIENT_RESOURCES;
			goto reply;
		}
	} else {
		/*
		 * Is the Mobile Node requesting an IP Address?
		 */
		if (mnEntry->haPoolIdentifier &&
		    requestPtr->homeAddr == INADDR_ANY) {
			/*
			 * If we've already allocated an address, and
			 * the Mobile Node is still requesting one, let's
			 * free what we already have.
			 */
			if (mnEntry->haMnAddr) {
				requestPtr->homeAddr = mnEntry->haMnAddr;
			} else {
				requestPtr->homeAddr = GetAddressFromPool(
					mnEntry->haPoolIdentifier);

				if (requestPtr->homeAddr == INADDR_ANY) {
					code = HA_INSUFFICIENT_RESOURCES;
					syslog(LOG_ERR, "Unable to allocate "
					    "address from address "
					    "pool %d",
					    mnEntry->haPoolIdentifier);
					haCounters.
					    haInsufficientResourceCnt++;
					goto reply;
				}
				/*
				 * Save the allocated address
				 */
				mnEntry->haMnAddr = requestPtr->homeAddr;
				locallyAssignedAddress = _B_TRUE;
			}
		}
	}

	/*
	 * Was HA a broadcast address?
	 */
	if (requestPtr->haAddr != entry->maIfaceAddr) {
		code = HA_UNKNOWN_HOME_AGENT;
		haCounters.haUnknownHACnt++;
		goto reply;
	}

	/*
	 * Check if the number of active bindings exceeds the
	 * maximum allowed.
	 */
	if ((requestPtr->regFlags & REG_SIMULTANEOUS_BINDINGS) &&
	    (mnEntry->haMnBindingCnt == MAX_SIMULTANEOUS_BINDINGS)) {
		code = HA_TOO_MANY_SIMULTANEOUS;
		haCounters.haTooManyBindingsCnt++;
		goto reply;
	}

	/*
	 * Get the Mobile Node's SA, remember that the entry
	 * returned will be read locked, so we need to unlock the
	 * entry when we are done.
	 */
	if ((mnsae = findSecAssocFromSPI(mnEntry->haMnSPI,
	    LOCK_READ)) == NULL) {
		syslog(LOG_ERR, "Unable to find MN SPI for %s",
		    ntoa(requestPtr->homeAddr, addrstr1));
		code = HA_MN_AUTH_FAILURE;
		goto reply;
	}

	/*
	 * Check ID used for replay protection
	 */
	okID = HAisIDok(mnEntry->haMnRegIDHigh, mnEntry->haMnRegIDLow,
			ntohl(requestPtr->IDHigh), ntohl(requestPtr->IDLow),
			mnsae->mipSecReplayMethod);

	if (okID == _B_FALSE) {
		code = HA_ID_MISMATCH;
		haCounters.haIDMismatchCnt++;
		goto reply;
	}


	if (requestPtr->regLifetime == 0) {
		/* Do Radius Close Session */
#ifdef RADIUS_ENABLED
		if (radiusEnabled)
			radiusCloseSession(mnEntry);
#endif /* RADIUS_ENABLED */
		haCounters.haDeRegReqRecvdCnt++;
		delHABE(&mnEntry, requestPtr->homeAddr, requestPtr->COAddr,
			&sessionLifeTime);
	} else {
		haCounters.haRegReqRecvdCnt++;

		/*
		 * We need to make sure we're allowing reverse tunneling.  The
		 * tunnel is bi-directional by default, but we need to make
		 * sure it's OK to set it up!
		 */
		if (requestPtr->regFlags & REG_REVERSE_TUNNEL) {
			/* MNs requesting, are we allowing? */
			if (!(entry->maReverseTunnelAllowed & RT_HA)) {
				/*
				 * Note: we do NOT check ADV_REVERSE_TUNNEL
				 * because that's what we're advertising,
				 * which is FA-centric.  ReverseTunnelAllowed
				 * is specifically designed to distinguish
				 * between HA allowing but FA isn't (and so
				 * reverseTunnel may not be being advertised).
				 */
				code = HA_REVERSE_TUNNEL_UNAVAILABLE;
				haCounters.haReverseTunnelUnavailableCnt++;
				goto reply;
			} /* OK to proceed with the usual tunnel setup... */

		} else if (aaaProtocol != RADIUS) {
			/*
			 * MNs not requesting, are we requiring!
			 * Note: don't check the advertisement bit here!
			 */
			if (entry->maReverseTunnelRequired & RT_HA) {
				code = HA_REVERSE_TUNNEL_REQUIRED;
				haCounters.haReverseTunnelRequiredCnt++;
			} /* OK to proceed with the usual tunnel setup... */

		}

		if (addHABE(mnEntry, messageHdr->src, messageHdr->srcPort,
		    messageHdr->ifEntry, requestPtr->regFlags,
		    requestPtr->homeAddr, requestPtr->COAddr,
		    requestPtr->haAddr, requestPtr->regLifetime,
		    &existingBindings,
		    &sessionLifeTime) < 0) {
			code = HA_INSUFFICIENT_RESOURCES;
			haCounters.haInsufficientResourceCnt++;
			goto reply;
		}
	}

#ifdef NO_SIMULTANEOUS
	if (requestPtr->regFlags & REG_SIMULTANEOUS_BINDINGS) {
		/*
		 * If simultaneous bindings was requested, set the appropriate
		 * acceptance code.
		 */
		code = MIP_SIMULTANEOUS_NOT_SUPPORTED;
	}
#endif

reply:

	HABuildRegReply(messageHdr, messageHdr->ifEntry,
	    code, mnEntry, faSPI, mnsae, okID, locallyAssignedAddress,
	    sessionLifeTime, existingBindings);
}

static void
HABuildRegReply(MessageHdr *messageHdr, MaAdvConfigEntry *entry,
    int code, HaMobileNodeEntry *mnEntry, uint32_t faSPI,
    MipSecAssocEntry *mnsae, int okID, boolean_t locallyAssignedAddress,
    uint32_t sessionLifeTime, boolean_t existingBindings)
{
	regReply *replyPtr;
	regRequest *requestPtr;
	unsigned char *challenge;
	unsigned char challengeBuffer[ADV_MAX_CHALLENGE_LENGTH];
	size_t challengeLen = 0;
	int index;
	ipaddr_t COAddr;
	ipaddr_t haAddr;
	ipaddr_t homeAddr;
	char NAIBuffer[ADV_MAX_NAI_LENGTH];
	uint32_t IDhi;
	uint32_t IDlo;
	time_t localTime;
	int repLen;
	MipSecAssocEntry *mipSecAssocEntry;
	boolean_t ignoreTunnel;
#ifdef FIREWALL_SUPPORT
	uint8_t	tFlags;
	boolean_t encapToFw;
#endif /* FIREWALL_SUPPORT */
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	int val;
	int rc;
	int result;

	mipverbose(("top of HABuildRegReply...\n"));
	/* LINTED BAD_PTR_CAST_ALIGN */
	requestPtr = (regRequest *) messageHdr->pkt;

	/*
	 * Retrieve the Challenge
	 */
	GET_EXT_DATA(messageHdr, index, REG_MF_CHALLENGE_EXT_TYPE,
	    challenge, challengeLen);

	/*
	 * Copy the challenge into a buffer so that we can manipulate it
	 * later...
	 */
	if (challengeLen > 0) {
		if (challengeLen > ADV_MAX_CHALLENGE_LENGTH) {
			syslog(LOG_ERR, "Challenge length exceeds maximum "
			    "supported length");
			code = HA_POORLY_FORMED_REQUEST;
			haCounters.haPoorlyFormedRequestsCnt++;
		} else {
			(void) memcpy(challengeBuffer, challenge, challengeLen);
		}
	}

	/*
	 * For now, we'll create the new packet in place. But not before we
	 * save some of the fields that could get overwritten.
	 */
	COAddr = requestPtr->COAddr;  /* this is the only one we risk losing */
	haAddr = requestPtr->haAddr;
	homeAddr = requestPtr->homeAddr;
#ifdef FIREWALL_SUPPORT
	tFlags = requestPtr->regFlags;
#endif
	/*
	 * If we have an NAI, save it.
	 */
	if (messageHdr->mnNAILen) {
		(void) memcpy(NAIBuffer, messageHdr->mnNAI,
		    messageHdr->mnNAILen);
	}

	/* LINTED BAD_PTR_CAST_ALIGN */
	replyPtr = (regReply *) messageHdr->pkt;
	replyPtr->type = REG_REPLY_TYPE;
	replyPtr->code = (uint8_t)code;
	if (ntohs(requestPtr->regLifetime) > entry->maAdvMaxRegLifetime) {
		replyPtr->regLifetime =
			htons(entry->maAdvMaxRegLifetime);
	} else {
		replyPtr->regLifetime = requestPtr->regLifetime;
	}
	replyPtr->homeAddr = homeAddr;
	replyPtr->haAddr = entry->maIfaceAddr;

	HAnewID(&IDhi, &IDlo, ntohl(requestPtr->IDHigh),
	    ntohl(requestPtr->IDLow),
	    (mnsae == NULL) ? NONE : mnsae->mipSecReplayMethod, okID);
	if (mnEntry != NULL && mnsae != NULL) {
	    HAstoreID(&(mnEntry->haMnRegIDHigh), &(mnEntry->haMnRegIDLow),
		IDhi, IDlo, mnsae->mipSecReplayMethod, okID);
	    GET_TIME(localTime);
	    if (code) {
		mnEntry->haServiceRequestsDeniedCnt++;
		mnEntry->haRecentServiceDeniedCode = code;
		mnEntry->haRecentServiceDeniedTime = localTime;
	    } else {
		mnEntry->haServiceRequestsAcceptedCnt++;
		mnEntry->haRecentServiceAcceptedTime = localTime;
	    }
	}
	replyPtr->IDHigh = htonl(IDhi);
	replyPtr->IDLow = htonl(IDlo);
	repLen = sizeof (regReply);

	/*
	 * The MN-HA MUST follow the MN-AAA Session Keys
	 */
	if (mnsae) {
		/*
		 * Release the lock on the security association in order
		 * to eliminate a potential deadlock situation.
		 */
		(void) rw_unlock(&mnsae->mipSecNodeLock);
	}

	if (messageHdr->mnNAILen) {
		repLen += appendExt((messageHdr->pkt + repLen),
		    REG_MN_NAI_EXT_TYPE, (unsigned char *) NAIBuffer,
		    messageHdr->mnNAILen);
	}

	/*
	 * mnEntry is assumed to be set in some of the statements below.
	 * It is not set whenever authentication has failed.
	 */
	if (mnEntry) {
#ifdef KEY_DISTRIBUTION
	if ((messageHdr->pktSource == MIP_PKT_FROM_AAA &&
	    messageHdr->mnHaKeyLen) ||
	    messageHdr->kdcKeysPresent == _B_TRUE) {
		if (aaaProtocol == AAA_NONE) {
			/*
			 * Support for the Generalized Key extension.
			 *
			 * We have some keying information to send to the Mobile
			 * Node from the AAA Server.
			 */
			repLen += createMNKeyExt((messageHdr->pkt + repLen),
			    REG_GEN_MN_HA_KEY_EXT_TYPE, GEN_KEY_MN_HA,
			    messageHdr->mnHaKey, messageHdr->mnHaKeyLen,
			    messageHdr->mnHaSPI, messageHdr->mnAAASPI,
			    (uint8_t *)NAIBuffer, messageHdr->mnNAILen);
			mnEntry->haMnSPI = messageHdr->mnHaSPI;
		} else {
#else /* KEY_DISTRIBUTION */
	if (messageHdr->pktSource == MIP_PKT_FROM_AAA &&
	    messageHdr->mnHaKeyLen && (aaaProtocol == DIAMETER)) {
#endif /* KEY_DISTRIBUTION */

		/*
		 * We received some keying information from DIAMETER,
		 * and we need to send this to the mobile node.
		 * Support for the Generalized Key extension.
		 */
		repLen += appendMierExt((messageHdr->pkt + repLen),
		    REG_GEN_MN_HA_KEY_EXT_TYPE, GEN_KEY_MN_HA,
		    messageHdr->mnHaKey, messageHdr->mnHaKeyLen);
#ifdef KEY_DISTRIBUTION
		}
#endif /* KEY_DISTRIBUTION */
	}

#ifdef KEY_DISTRIBUTION
	if ((messageHdr->pktSource == MIP_PKT_FROM_AAA &&
	    messageHdr->mnFaKeyLen) ||
	    messageHdr->kdcKeysPresent == _B_TRUE) {
		if (aaaProtocol == AAA_NONE) {
			/*
			 * Support for the Generalized Key extension.
			 *
			 * We have some keying information to send to the Mobile
			 * Node from the AAA Server.
			 */
			repLen += createMNKeyExt((messageHdr->pkt + repLen),
			    REG_GEN_MN_FA_KEY_EXT_TYPE, GEN_KEY_MN_FA,
			    messageHdr->mnFaKey, messageHdr->mnFaKeyLen,
			    messageHdr->mnFaSPI, messageHdr->mnAAASPI,
			    (uint8_t *)NAIBuffer, messageHdr->mnNAILen);
		} else {
#else /* KEY_DISTRIBUTION */
	if (messageHdr->pktSource == MIP_PKT_FROM_AAA &&
	    messageHdr->mnFaKeyLen && aaaProtocol == DIAMETER) {
#endif /* KEY_DISTRIBUTION */

			/*
			 * We received some keying information from DIAMETER,
			 * and we need to send this to the mobile node.
			 * Support for the Generalized Key extension.
			 */
			repLen += appendMierExt((messageHdr->pkt + repLen),
			    REG_GEN_MN_FA_KEY_EXT_TYPE, GEN_KEY_MN_FA,
			    messageHdr->mnFaKey, messageHdr->mnFaKeyLen);
#ifdef KEY_DISTRIBUTION
		}
#endif /* KEY_DISTRIBUTION */
	}

	/*
	 * The MN-HA MUST follow the MN-AAA Session Keys
	 */
	if ((mnsae =
	    findSecAssocFromSPI(mnEntry->haMnSPI, LOCK_READ)) != NULL) {
		repLen += appendAuthExt(messageHdr->pkt, repLen,
		    REG_MH_AUTH_EXT_TYPE, mnsae);

		(void) rw_unlock(&mnsae->mipSecNodeLock);
	}
	} /* Matches if (mnEntry) above */

	/*
	 * If a challenge was present, it MUST be added after the MN-HA
	 * and prior to the MN-FA.
	 */
	if (challengeLen > 0) {
		repLen += appendExt((messageHdr->pkt + repLen),
		    REG_MF_CHALLENGE_EXT_TYPE, challengeBuffer, challengeLen);
	}

#ifdef KEY_DISTRIBUTION
	if (messageHdr->mnFaKeyLen &&
	    messageHdr->kdcKeysPresent == _B_TRUE) {
		/*
		 * Support for the Generalized Key extension.
		 *
		 * We have some keying information to send to the Mobile
		 * Node from the AAA Server.
		 */
		repLen +=
		    createFAKeyExt((char *)(messageHdr->pkt + repLen),
		    VENDOR_ID_SUN, REG_MN_FA_KEY_EXT,
		    (char *)&messageHdr->mnFaKey, messageHdr->mnFaKeyLen,
		    messageHdr->mnFaSPI);

		repLen +=
		    createFAKeyExt((char *)(messageHdr->pkt + repLen),
		    VENDOR_ID_SUN, REG_FA_HA_KEY_EXT,
		    (char *)&messageHdr->faHaKey, messageHdr->faHaKeyLen,
		    messageHdr->faHaSPI);
		faSPI = messageHdr->faHaSPI;
	}
#endif /* KEY_DISTRIBUTION */

	if (faSPI) {
		/*
		 * Now we get the Foreign Agent's Security Association,
		 * which will be read locked upon return.
		 */
		if ((mipSecAssocEntry =
		    findSecAssocFromSPI(faSPI, LOCK_READ)) == NULL) {
			syslog(LOG_ERR, "Unable to add FH Auth - SPI (%d) not"
				"defined", faSPI);
			replyPtr->code = HA_FA_AUTH_FAILURE;

		} else {
			repLen += appendAuthExt(messageHdr->pkt, repLen,
			    REG_FH_AUTH_EXT_TYPE, mipSecAssocEntry);

			/*
			 * And now we must unlock the entry.
			 */
			(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
		}
	} else {
		if (fhAuthRequired) {
			replyPtr->code = HA_FA_AUTH_FAILURE;
			haCounters.haFAAuthFailureCnt++;
			syslog(LOG_ERR, "Cannot add FH Auth - No SA (%d)",
			    faSPI);
		}
	}

	/*
	 * First assume nothing special is needed to ensure that unsuccessful
	 * registrations reach the mobile node.
	 */
#ifdef FIREWALL_SUPPORT
	encapToFw = _B_FALSE;
#endif /* FIREWALL_SUPPORT */
	ignoreTunnel = _B_FALSE;

	/* Is this really the case? */
	if ((replyPtr->code != MIP_SUCCESSFUL_REGISTRATION) &&
	    (replyPtr->code != MIP_SIMULTANEOUS_NOT_SUPPORTED)) {
		/*
		 * For "deregister all" requests, ignore the tunnel to
		 * ensure unsuccessful registrations are sent on the
		 * local (home) network.
		 */
		if ((replyPtr->regLifetime == 0) &&
			(COAddr == homeAddr) &&
				mnEntry && (mnEntry->haMnBindingCnt)) {
			ignoreTunnel = _B_TRUE;
#ifdef RADIUS_ENABLED
			/* Do Radius Close Session */
			if (radiusEnabled)
				radiusCloseSession(mnEntry);
#endif /* RADIUS_ENABLED */
		}

#ifdef FIREWALL_SUPPORT
		/*
		 * If MN is using an external COA and there isn't a tunnel
		 * to FW already, create one temporarily.
		 */
		if ((isInsideProtectedDomain(COAddr) == FALSE) &&
			((findHABE(&haMobileNodeHash, homeAddr,
			    COAddr) == _B_FALSE))) {
				encapToFw = _B_TRUE;
		}
#endif /* FIREWALL_SUPPORT */

		/*
		 * Do we have an assigned Home Address that we need
		 * to free?
		 */
		if (mnEntry && locallyAssignedAddress == _B_TRUE) {
			if (freeAddressFromPool(mnEntry->haPoolIdentifier,
			    mnEntry->haMnAddr) != _B_TRUE) {
				syslog(LOG_ERR, "Unable to free address "
				    "from pool %d",
				    mnEntry->haPoolIdentifier);
			}
			mnEntry->haMnAddr = INADDR_ANY;
		}
	}

#ifdef FIREWALL_SUPPORT
	/*
	 * If needed, set up temporary tunnel to redirect packets for
	 * external COAs at FW.
	 * TODO: Note that this works only when the destination of the
	 * registration request is the COAddr. This is the case
	 * for an MN operating in colocated state so we are fine
	 * for now.
	 */
	if (encapToFw) {
	    mipverbose(("At %s, creating a temporary tunnel for %s through "
		"firewall %s 0\n", ntoa(haAddr, addrstr1),
		ntoa(COAddr, addrstr2),
		ntoa(domainInfo.fwAddr[0], addrstr3)));
		if ((val = encapadd(COAddr, haAddr, domainInfo.fwAddr[0],
		    tFlags & REG_REVERSE_TUNNEL)) < 0) {
			syslog(LOG_ERR, "encapadd failed ... %s",
			    err2str(val));
		}
	}
#endif /* FIREWALL_SUPPORT */

	/* If needed, ignore existing tunnel for MN to COA */
	if (ignoreTunnel) {
	    /* make sure response will be sent locally */
	    mipverbose(("Temporarily deleting ARP entry for %s\n",
				ntoa(replyPtr->homeAddr, addrstr1)));
	    if ((val = arpdel(replyPtr->homeAddr)) < 0) {
		syslog(LOG_ERR, "arpdel failed ... %s", err2str(val));
	    }

	    mipverbose(("Temporarily suspending tunneling for %s\n",
			ntoa(replyPtr->homeAddr, addrstr1)));
	}

	/* If the packet was from AAA, send it back there. */
	if (messageHdr->pktSource == MIP_PKT_FROM_AAA) {
		(void) fprintf(stderr, "AAA Message!\n");
		rc = aaaSendRegistrationReply(messageHdr,
		    repLen, haAddr, homeAddr);
	} else {
		/*
		 * AAA isn't in charge - use IPsec SA's we're configured with.
		 */
		MobilityAgentEntry *mae;

		if ((mae = findMaeFromIp(COAddr, LOCK_READ)) != NULL) {
			/*
			 * Is there an IPSEC_REPLY_APPLY policy
			 * configured that isn't already?
			 */
			if (((mae->maIPsecFlags & IPSEC_REPLY_APPLY) == 0) &&
			    (IPSEC_REPLY_ANY(
			    mae->maIPsecSAFlags[IPSEC_APPLY]))) {
				/* pass it down */
				char peerAddr[IPv4_ADDR_LEN];

				(void) ntoa(mae->maAddr, peerAddr);

				if (installIPsecPolicy(
				    mae->maIPsecReply[IPSEC_APPLY]) < 0) {
					/* problems writing the policy */
					syslog(LOG_CRIT, "Could not install %s "
					    "for [Address %s]: %s",
					    IPSEC_POLICY_STRING(
					    IPSEC_REPLY_APPLY), peerAddr,
					    mae->maIPsecReply[IPSEC_APPLY]);

					/* unlock */
					(void) rw_unlock(&mae->maNodeLock);

					/* don't send a regreP in the clear! */
					return;
				}

				/* set the flag */
				mae->maIPsecFlags |= IPSEC_REPLY_APPLY;
			}

			/*
			 * We're sending a reply, *now* this is an FA-peer.
			 * We didn't do this when setting IPsecRequest permit
			 * because there isn't a binding to this guy at init
			 * (recall, as HA we have to be laying-in-wait for
			 * registration requests from FAs we have an SA with).
			 */
			mae->maPeerFlags |= FA_PEER;

			/* unlock */
			(void) rw_unlock(&mae->maNodeLock);
		}

		rc = sendUDPmessage(entry->maIfaceUnicastSock,
		messageHdr->pkt, repLen, messageHdr->src,
		messageHdr->srcPort);
	}
	if (rc == 0) {

		mipverbose(("\n---- %s (%s) ----\n",
		    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
		    sprintRelativeTime(relativeTime,
			MAX_TIME_STRING_SIZE)));
		mipverbose(("HA sent reg reply to %s.%d (Code %d)\n",
		    ntoa(messageHdr->src, addrstr1),
		    messageHdr->srcPort, replyPtr->code));
		mipverbose((
			"               "
			    "[Lifetime %d sec, ID %0#10x : %0#10x]\n",
			    (uint32_t)ntohs(replyPtr->regLifetime),
			    ntohl(replyPtr->IDHigh),
			    ntohl(replyPtr->IDLow)));

		if (logVerbosity > 2) {
			mipverbose(("HA's reply is:\n"));
			printBuffer((unsigned char *) messageHdr->pkt,
			    repLen);
			mipverbose(("\n"));
		}

		if (replyPtr->regLifetime != 0)
			haCounters.haRegRepliesSentCnt++;
		else
			haCounters.haDeRegRepliesSentCnt++;

	} else {
		syslog(LOG_ERR, "sendto failed at HA while replying.");
	}

	/*
	 * Undo any temporary changes related to "deregistration all"
	 * messages.
	 * Proxy arp works only for non-PPP interfaces.
	 */
	if (((entry->maIfaceFlags & IFF_POINTOPOINT) == 0) && ignoreTunnel) {
		/* restore prior state */
		mipverbose(("Re-enabling tunneling for %s\n",
		    ntoa(replyPtr->homeAddr, addrstr1)));
		mipverbose(("Restoring proxy ARP for %s at %s\n",
		    ntoa(replyPtr->homeAddr, addrstr1),
		    hwAddrWrite(entry->maIfaceHWaddr, addrstr2)));
		if ((val = arpadd(replyPtr->homeAddr,
		    entry->maIfaceHWaddr, ATF_PUBL)) < 0) {
			syslog(LOG_ERR, "arpadd (proxy) failed ... %s",
			    err2str(val));
		}
	}

	/*
	 * If we successfully deregistered all bindings for a MN
	 * we MUST also send out a gratuitous ARP with the MN's correct
	 * mapping taken from our ARP cache.
	 */
	if ((replyPtr->code == MIP_SUCCESSFUL_REGISTRATION) ||
	    (replyPtr->code == MIP_SIMULTANEOUS_NOT_SUPPORTED)) {
		/*
		 * A successful request, we must generate the
		 * appropriate accounting record.
		 */
		if (replyPtr->regLifetime == 0) {
			if (((entry->maIfaceFlags & IFF_POINTOPOINT) == 0) &&
			    (mnEntry != NULL) &&
			    (mnEntry->haMnBindingCnt == 0)) {
				if ((val = arprefresh(mnEntry,
				    replyPtr->homeAddr)) < 0)
					syslog(LOG_ERR,
					    "arprefresh failed ... %s",
					    err2str(val));
			}

			if (aaaProtocol != AAA_NONE) {
				/*
				 * An accounting stop record must be sent.
				 */
				result = sendAccountingRecord(
					MOBILE_IP_ACCOUNTING_STOP_REQUEST,
					(unsigned char *)NAIBuffer,
					    messageHdr->mnNAILen,
					    homeAddr, COAddr, haAddr,
					    sessionLifeTime, MN_DEREGISTERED);

				if (result) {
					syslog(LOG_ERR, "Unable to "
					    "send accounting "
					    "stop record");
				}
			}
		} else {
				/*
				 * Is this a new session, or an existing one?
				 */
			if (aaaProtocol != AAA_NONE) {
			    if (existingBindings == _B_TRUE) {
				/*
				 * An interim accounting
				 * record must be sent.
				 */
				result =
				    sendAccountingRecord(
					MOBILE_IP_ACCOUNTING_INTERIM_REQUEST,
					    (unsigned char *)
					    NAIBuffer,
					    messageHdr->mnNAILen,
					    homeAddr, COAddr,
					    haAddr,
					    sessionLifeTime, 0);

					if (result) {
						/*
						 * PRC: Here we must disconnect
						 * the mobile node since we can
						 * not account for services
						 * rendered.
						 */
						syslog(LOG_ERR,
						    "Unable to send "
						    "accounting interim "
						    "record");
						if (mnEntry) {
							delHABE(&mnEntry,
							    homeAddr,
							    COAddr,
							    &sessionLifeTime);
						}
					}
				} else {
					/*
					 * An accounting start record must
					 * be sent.
					 */
				    result =
					sendAccountingRecord(
					    MOBILE_IP_ACCOUNTING_START_REQUEST,
						(unsigned char *)NAIBuffer,
						messageHdr->mnNAILen,
						homeAddr, COAddr, haAddr, 0, 0);

				    if (result) {
					/*
					 * PRC: Here we must disconnect
					 * the mobile node since we can
					 * not account for services
					 * rendered.
					 */
					    syslog(LOG_ERR,
						"Unable to send "
						"accounting start "
						"record");
					    if (mnEntry) {
						    delHABE(&mnEntry,
							homeAddr,
							COAddr,
							&sessionLifeTime);
					    }
				    }
				}
			}
		}
	} else if (aaaProtocol != AAA_NONE) {
		/*
		 * An accounting stop record must be sent to log the
		 * failed request.
		 */
		result = sendAccountingRecord(
			MOBILE_IP_ACCOUNTING_STOP_REQUEST,
			    (unsigned char *)NAIBuffer,
			    messageHdr->mnNAILen, homeAddr, COAddr, haAddr,
			    sessionLifeTime, REG_EXPIRED);

		if (result) {
		    syslog(LOG_ERR, "Unable to send accounting stop record");
		}
	}

	/*
	 * If we've made it this far, if we have a mobile node
	 * entry, we need to unlock it.
	 */
	if (mnEntry) {
		(void) rw_unlock(&mnEntry->haMnNodeLock);
	}

	mipverbose(("\n\n"));
}



/*
 * Function: acceptFAVEHashLookup
 *
 * Arguments:	entry - Pointer to visitor entry
 *		p1 - First parameter to match (interface address)
 *		p2 - 2nd parameter to match (whether visitor is accepted)
 *		p3 - 3rd parameter to match (homeagentaddr)
 *
 * Description: This function is used as the Hash Table Helper routine
 *		for isAcceptedVisitor() when looking for accepted visitor
 *		entries in the Hash Table, and will be called by
 *		findHashTableEntryUint() and findHashTableEntryString().
 *
 * Returns:	_B_TRUE if the entry matches the desired criteria,
 *		otherwise _B_FALSE.
 */
/* ARGSUSED */
static boolean_t
acceptFAVEHashLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	FaVisitorEntry *faveEntry = entry;

	if ((faveEntry->faVisitorCOAddr == p1 || p1 == 0) &&
	    ((uint32_t)faveEntry->faVisitorRegIsAccepted == p2) &&
	    (p3 == 0 || faveEntry->faVisitorHomeAgentAddr == p3)) {
		return (_B_TRUE);
	}

	return (_B_FALSE);
}

/*
 * Function: acceptFAVE
 *
 * Arguments:	htbl - Pointer to the Hash Table
 *		replyPtr - Pointer to the registration reply
 *		favep - Pointer to a pointer to a visitor entry
 *
 * Description:	If we find an ACCEPTED visitor entry for this MN-COA
 *		pair, update that entry and delete the pending entry.
 *		Otherwise, change the "pending" entry pointed to by
 *		favep to "accepted" with specified lifetime.
 *
 *		If accepted, we will add a host specific route to be
 *		able to forward packets to the Mobile Node and we
 *		will create a tunnel interface for the Home Agent.
 *
 *		NOTE: COA is available in the faVisitorCOAddr field.
 *
 * Returns:
 */
static void
acceptFAVE(HashTable *htbl, regReply *replyPtr, FaVisitorEntry **favep)
{
	int val;
	int in_Ifindex = 0;
	int out_Ifindex = 0;
	int tun_num;
	FaVisitorEntry *entry;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char tun_name[LIFNAMSIZ];
	ipaddr_t mnAddr = replyPtr->homeAddr;
	unsigned short lifetime = ntohs(replyPtr->regLifetime);

	/*
	 * Let's see if we can find the entry using the Home
	 * Address. Note that an accepted visitor entry MUST have
	 * a home address, so we do not need to worry about looking
	 * using the NAI.
	 */
	entry = findHashTableEntryUint(htbl, mnAddr, LOCK_WRITE,
	    acceptFAVEHashLookup, (*favep)->faVisitorCOAddr,
	    _B_TRUE, (*favep)->faVisitorHomeAgentAddr);

	if (entry) {
		/*
		 * We've found a Visitor Entry already accepted in the
		 * Hash Table. We will update the old entry, and delete
		 * this new entry (since we only need one).
		 */
		entry->faVisitorAddr = (*favep)->faVisitorAddr;
		entry->faVisitorIfaceAddr = (*favep)->faVisitorIfaceAddr;
		entry->faVisitorRegFlags = (*favep)->faVisitorRegFlags;
		entry->faVisitorPort = (*favep)->faVisitorPort;
		entry->faVisitorHomeAgentAddr =
				(*favep)->faVisitorHomeAgentAddr;
		GET_TIME(entry->faVisitorTimeGranted);
		entry->faVisitorTimeExpires =
			entry->faVisitorTimeGranted + lifetime;
		mipverbose(("FA renewed visitor %s on iface %s (%d sec).\n",
				ntoa(entry->faVisitorHomeAddr, addrstr1),
				ntoa(entry->faVisitorIfaceAddr, addrstr2),
				lifetime));
		entry->faVisitorRegIDHigh = (*favep)->faVisitorRegIDHigh;
		entry->faVisitorRegIDLow = (*favep)->faVisitorRegIDLow;
		entry->faVisitorInIfindex = (*favep)->faVisitorInIfindex;
		entry->faVisitorIsSllaValid = (*favep)->faVisitorIsSllaValid;
		(void) memcpy(&entry->faVisitorSlla, &(*favep)->faVisitorSlla,
		    sizeof (struct sockaddr_dl));


		entry->faVisitorChallengeAdvLen =
		    (*favep)->faVisitorChallengeAdvLen;
		(void) memcpy(&entry->faVisitorChallengeAdv,
		    &(*favep)->faVisitorChallengeAdv,
		    entry->faVisitorChallengeAdvLen);

		/*
		 * Unlocking the entry here could cause deadlock.
		 * (void) rw_unlock(&entry->faVisitorNodeLock);
		 */

		(void) rw_unlock(&(*favep)->faVisitorNodeLock);

		if (delHashTableEntryUint(htbl, *favep, mnAddr, LOCK_NONE)) {
			/*
			 * Found a match, delete it
			 */
			delFAVEptr(*favep, _B_TRUE, 0);
			(void) rw_unlock(&(*favep)->faVisitorNodeLock);
			(void) rwlock_destroy(&(*favep)->faVisitorNodeLock);
			free(*favep);
			*favep = NULL;
		}
		/*
		 * Return the pointer to the old entry.
		 */
		*favep = entry;
		return;
	}

	/*
	 * OK, we did not find an existing entry. If this entry was
	 * found using the NAI, we need to update the hash table to
	 * use the Mobile Node's Home Address instead.
	 */
	if ((*favep)->faVisitorMnNAI[0] != '\0' &&
		(*favep)->faVisitorHomeAddr == 0) {
		/*
		 * If our Visitor Entry has been hashed using the Mobile Node's
		 * NAI, we want to change it so we can hash it using the Home
		 * Address. From now on we will be using the Home Agent to
		 * find the Visitor Entry.
		 *
		 * This *was* computing strlen(fanai) +1, which added space
		 * for the null.  Since it was not up to spec, and would not
		 * interoperate with other vendors, it was removed.
		 */
		if (changeHashEntryStringToUint(htbl, *favep,
		    (*favep)->faVisitorMnNAI, (*favep)->faVisitorMnNAILen,
		    mnAddr) == _B_FALSE) {
			mipverbose(("Could not find our visitor entry in the " \
			    "hash table\n"));
			return;
		}
		/*
		 * Update the visitor entry with the Mobile Node's
		 * Home Address, and add it to the Hash Table.
		 */
		(*favep)->faVisitorHomeAddr = mnAddr;
		mipverbose(("Moved pending visitor entry for %.*s to %s " \
		    "at pos'n %p.\n",
		    (*favep)->faVisitorMnNAILen, (*favep)->faVisitorMnNAI,
		    ntoa(mnAddr, addrstr1), (void *)entry));
	}


	/*
	 * We did not find an existing ACCEPTED entry.
	 */
	GET_TIME((*favep)->faVisitorTimeGranted);
	(*favep)->faVisitorTimeExpires =
		(*favep)->faVisitorTimeGranted + lifetime;
	mipverbose(("FA accepted visitor %s on iface %s (expires %ld).\n",
			ntoa((*favep)->faVisitorHomeAddr, addrstr1),
			ntoa((*favep)->faVisitorIfaceAddr, addrstr2),
			(*favep)->faVisitorTimeExpires));
	(*favep)->faVisitorRegIsAccepted = _B_TRUE;

	/*
	 * If the source link layer address is valid add an ARP
	 * entry else don't. The entry could be invalid for variety
	 * of reasons (See recvNetworkPacket)
	 */
	if ((*favep)->faVisitorIsSllaValid) {
		/*
		 * Add an ARP entry to prevent the FA from broadcast ARPing
		 */
		if ((val = arpIfadd(mnAddr, (*favep)->faVisitorSlla.sdl_data,
		    (*favep)->faVisitorInIfindex)) < 0) {
			syslog(LOG_ERR, "SIOCSXARP failed... %s",
			    err2str(val));
		}
	}

	mipverbose(("Enabling decapsulation of inner pkts sent to %s\n",
			ntoa((*favep)->faVisitorHomeAddr, addrstr1)));

	if ((val = decapadd((*favep)->faVisitorHomeAgentAddr,
	    (*favep)->faVisitorCOAddr)) < 0) {
		syslog(LOG_ERR, "decapadd failed ... %s", err2str(val));
		/*
		 * The following reply code is a close approximation of why
		 * things might have failed. The main purpose is to let the
		 * MN know.
		 */
		replyPtr->code = FA_INSUFFICIENT_RESOURCES;
		return;
	}

	tun_num = gettunnelno((*favep)->faVisitorHomeAgentAddr,
	    (*favep)->faVisitorCOAddr);
	if (tun_num < 0) {
		syslog(LOG_ERR, "gettunnelno returns -1");
		/*
		 * The following reply code is a close approximation of why
		 * things might have failed. The main purpose is to let the MN
		 * know.
		 */
		replyPtr->code = FA_INSUFFICIENT_RESOURCES;
		return;
	}
	(void) snprintf(tun_name, sizeof (tun_name), "ip.tun%d", tun_num);
	in_Ifindex = if_nametoindex(tun_name);
	if (in_Ifindex == 0) {
		/* if_nametoindex fails... */
		syslog(LOG_ERR, "if_nametoindex fails for tunnel %s"
		    "with error %d", tun_name, errno);
		/*
		 * The following reply code is a close approximation of why
		 * things might have failed. The main purpose is to let the MN
		 * know.
		 */
		replyPtr->code = FA_INSUFFICIENT_RESOURCES;
		return;
	}
	/*
	 * Create forward route to MN and specify that only
	 * packets from in_Ifindex will be forwarded to MN.
	 */

	mipverbose(("Adding direct, local route for visitor %s through %s.\n",
	    ntoa((*favep)->faVisitorHomeAddr, addrstr1),
	    ntoa((*favep)->faVisitorIfaceAddr, addrstr2)));

	if ((val = routeadd((*favep)->faVisitorHomeAddr,
	    (*favep)->faVisitorIfaceAddr, 0, in_Ifindex,
	    (*favep)->faVisitorInIfindex)) < 0) {
		syslog(LOG_ERR, "routeadd failed ... :%s: "
		    "for visitor %s from interface index %d",
		    err2str(val), ntoa((*favep)->faVisitorHomeAddr, addrstr1),
		    in_Ifindex);
		/*
		 * The following reply code is a close approximation of why
		 * things might have failed. The main purpose is to let the MN
		 * know.
		 */
		replyPtr->code = FA_INSUFFICIENT_RESOURCES;
		return;
	}

	/*
	 * If 'T' bit is set, create reverse tunnel route in the MIPRTUN
	 * table. In this routing table the routing selection is based
	 * on visitor's homeaddr and it's incoming interface index.
	 * Outgoing interface index provided in the routeadd function
	 * determines reverse tunnel to visitor's home-agent.
	 */
	if ((*favep)->faVisitorRegFlags & REG_REVERSE_TUNNEL) {

		/* Do we apply an IPsec policy for the reverse tunnel? */
		MobilityAgentEntry *mae;

		if ((mae = findMaeFromIp(replyPtr->haAddr, LOCK_READ))
		    != NULL) {
			/* is there something we shoud set that isn't? */
			if (IPSEC_REVERSE_TUNNEL_ANY(
			    mae->maIPsecSAFlags[IPSEC_APPLY]))
				/*
				 * forward and reverse tunnels share a policy
				 * (socket), so we can't support asymmetric
				 * tunnel policies until ipsec supports
				 * multiple socket policies!  If we install a
				 * global reverse tunnel policy, it will get
				 * processed before we pass it through our
				 * route table, which will indicate it's to go
				 * into the tunnel, but then it'll get dropped
				 * by the forward tunnel policy (presuming it's
				 * a different policy).  Just set the reverse
				 * bit flag to indicate what's being applied.
				 */
				mae->maIPsecFlags |=
				    IPSEC_REVERSE_TUNNEL_APPLY;

			/* unlock */
			(void) rw_unlock(&mae->maNodeLock);
		}

		/* Add reverse tunnel route for MIPRTUN table */
		mipverbose(("Adding reverse tunnel route for visitor %s at"
		    "interface index %d to tunnel index %d\n",
		    ntoa((*favep)->faVisitorHomeAddr, addrstr1),
		    (*favep)->faVisitorInIfindex, in_Ifindex));

		out_Ifindex = in_Ifindex;
		if ((val = routeadd(0, 0,
				    (*favep)->faVisitorHomeAddr,
				    (*favep)->faVisitorInIfindex,
				    out_Ifindex)) < 0) {
			syslog(LOG_ERR, "Reverse Tunnel route-add failed:%s:"
			    " for visitor %s from interface index %d to %d",
			    ntoa((*favep)->faVisitorHomeAddr, addrstr1),
			    (*favep)->faVisitorInIfindex, out_Ifindex,
			    err2str(val));
			/*
			 * The following reply code is a close approximation
			 * of why things might have failed. The main purpose
			 * is to let the MN know.
			 */
			replyPtr->code = FA_INSUFFICIENT_RESOURCES;
		}
	}
}


/*
 * Function: FAprocessRegReply
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		entry - Pointer to the Interface Entry.
 *
 * Description:	Process a registration reply received at a foreign
 *		agent, and forward the reply to the Mobile Node.
 *
 *		If AAA was enabled, we will issue accounting
 *		records to the AAA.
 *
 * Returns:
 */
void
FAprocessRegReply(MessageHdr *messageHdr, MaAdvConfigEntry *entry)
{
	int code = MIP_SUCCESSFUL_REGISTRATION;
	int val;
	int index;
	int result;
	uint32_t challengeBuffer[4];
	/* LINTED E_FUNC_SET_NOT_USED */
	authExt *mnAuthExt;
	int mnAuthExtLen;
	uint32_t sessionLifeTime = 0;
	ipaddr_t COAddr;
	time_t localTime;
	boolean_t visitor_entryExists;
	regReply *replyPtr;
	FaVisitorEntry *favePtr;
	FaVisitorEntry *acceptedFAVE;
	MipSecAssocEntry *mipSecAssocEntry = NULL;
	HashTable *htbl = &faVisitorHash;
	char addrstr1[INET_ADDRSTRLEN];
	char addrstr2[INET_ADDRSTRLEN];
	char currentTime[MAX_TIME_STRING_SIZE];
	char relativeTime[MAX_TIME_STRING_SIZE];
	char NAIBuffer[ADV_MAX_NAI_LENGTH];
	struct ether_addr ether;

	/* LINTED BAD_PTR_CAST_ALIGN */
	replyPtr = (regReply *) messageHdr->pkt;

	mipverbose(("\n---- %s (%s) ----\n",
	    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
	    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE)));
	mipverbose(("FA got reg reply [MN %s, HA %s, Code %d]\n",
	    ntoa(replyPtr->homeAddr, addrstr1),
	    ntoa(replyPtr->haAddr, addrstr2),
	    replyPtr->code));
	mipverbose(("                 [Lifetime %d sec, ID %0#10x : %0#10x]\n",
	    (uint32_t)ntohs(replyPtr->regLifetime), ntohl(replyPtr->IDHigh),
	    ntohl(replyPtr->IDLow)));

	mipverbose(("FAprocessRegReply called for pkt:\n"));
	if (logVerbosity > 2)
		printBuffer(messageHdr->pkt, messageHdr->pktLen);
	mipverbose(("\n"));

	/*
	 * Support for new MIER-style extension header.
	 *
	 * Are extensions ok and in the right order?
	 */
	if (mkRegExtList(messageHdr, sizeof (regReply)) < 0) {
		mipverbose(("FAprocessRegReply: poorly formed reply\n"));
		code = FA_POORLY_FORMED_REQUEST;
		faCounters.faPoorlyFormedRequestsCnt++;
		/*
		 * We no longer return here, instead we
		 * continue, and we will end up returning a failed
		 * reply to the mobile node.
		 */

	}


	/*
	 * Packet parsing routines now return error codes.
	 *
	 * Is the packet from the Home Agent valid?
	 */
	if ((code = IsPacketFromHaValid(messageHdr)) > 0) {
		faCounters.faPoorlyFormedRequestsCnt++;
		/*
		 * We no longer return here, instead we
		 * continue, and we will end up returning a failed
		 * reply to the mobile node.
		 */
	} else if (code == MA_DROP_PACKET) {
		/* drop the packet */
		return;
	}

	/*
	 * Now we retrieve the pending Visitor Entry. Note that the
	 * entry will be write locked upon return, and it is our
	 * responsibility to unlock it before we return.
	 */
	favePtr = findPendingFAVE(&faVisitorHash, replyPtr->homeAddr,
	    messageHdr->mnNAI, messageHdr->mnNAILen, ntohl(replyPtr->IDLow));

	if (favePtr == NULL) {
		/* we wouldn't likewise find a matching ipsec SA anyway. */
		syslog(LOG_ERR, "Did not find matching pending request.");
		return;
	}

	/*
	 * If the code is set to poor request, we will
	 * return a failed reply to the mobile node
	 */
	if (code == FA_POORLY_FORMED_REQUEST) {
		goto reply;
	}

	/*
	 * If we have an NAI, save it.
	 */
	if (messageHdr->mnNAILen) {
		(void) memcpy(NAIBuffer, messageHdr->mnNAI,
		    messageHdr->mnNAILen);
	}

	/*
	 * Check the message's authentication
	 */
	code = faCheckRegRepAuth(messageHdr, favePtr);

	if (code) {
		goto reply;
	}

	/* ... it is a good reply. No need to change the code in pkt. */
	faCounters.faRegRepliesRecvdCnt++;

	/*
	 * TODO: Remove everything after the MN-HA auth ext, add any new
	 * ones and relay the request. For now, we simply strip everything
	 * beyond the MN-HA auth.
	 */

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_MH_AUTH_EXT_TYPE, mnAuthExt,
	    mnAuthExtLen);

	if (mnAuthExtLen) {
		/*
		 * If any extensions appear following the Mobile-Node
		 * Home Agent Extension, let's remove them.
		 */
		messageHdr->pktLen = (messageHdr->extIdx[index] -
		    messageHdr->pkt) + messageHdr->extHdrLength[index] +
		    mnAuthExtLen;
	}

	/*
	 * As per the Challenge/Response Internet Draft, the
	 * Foreign Agent MAY include a new challenge value in the registration
	 * reply, protected by the MN-FA authentication extension (if present).
	 * In our case, if challenge is present, we will always add a new
	 * challenge to the reply.
	 */
	if (faChallengeAdv == _B_TRUE) {
		/*
		 * Generate the challenge value.
		 */
		challengeBuffer[0] = getRandomValue();
		challengeBuffer[1] = getRandomValue();
		challengeBuffer[2] = getRandomValue();
		challengeBuffer[3] = getRandomValue();
		messageHdr->pktLen += appendExt((messageHdr->pkt +
		    messageHdr->pktLen), REG_MF_CHALLENGE_EXT_TYPE,
		    (unsigned char *)&challengeBuffer, ADV_CHALLENGE_LENGTH);

		(void) memcpy(favePtr->faVisitorChallengeAdv,
		    &challengeBuffer, ADV_CHALLENGE_LENGTH);
		favePtr->faVisitorChallengeAdvLen = ADV_CHALLENGE_LENGTH;
	}

	/*
	 * Get our visitor's Security Association, but keep in mind
	 * that the node will be locked upon return.
	 */
	if ((mipSecAssocEntry =
	    findSecAssocFromSPI(favePtr->faVisitorSPI,
		LOCK_READ)) == NULL) {
		/*
		 * TODO: Is this extension required?
		 */
		if (mfAuthRequired) {
			syslog(LOG_ERR,
			    "Error: no SA in Visitor Entry");
			code = FA_MN_AUTH_FAILURE;
			faCounters.faMNAuthFailureCnt++;
			goto reply;
		}
	} else {
		messageHdr->pktLen += appendAuthExt(messageHdr->pkt,
		    messageHdr->pktLen, REG_MF_AUTH_EXT_TYPE,
		    mipSecAssocEntry);
		/*
		 * We need to unlock the node
		 */
		(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
	}

	/*
	 * Check the result code in the messageHdr.  If it is
	 * non zero, and the registrationRequest result is zero,
	 * then set the registration request's code to the code
	 * in the header.
	 */
	if (messageHdr->pktSource == MIP_PKT_FROM_AAA ||
	    messageHdr->pktSource == MIP_PKT_FROM_RADIUS &&
	    aaaProtocol != AAA_NONE &&
	    messageHdr->aaaResultCode != 0 &&
	    replyPtr->code == 0 && code == 0) {
		code = messageHdr->aaaResultCode;
	}


	/* Check for HA returning duplicate homeaddr */
	acceptedFAVE = findAcceptedFAVE(&faVisitorHash,
	    replyPtr->homeAddr, replyPtr->haAddr);
	if ((acceptedFAVE != NULL) &&
	    (acceptedFAVE->faVisitorMnNAI[0] != '\0')) {
		/*
		 * Compare to see that homeaddr and NAI
		 * match and it's not due to some problem
		 * with misbehaving HA assigning duplicate addr
		 */
		if (strncmp((const char *)acceptedFAVE->faVisitorMnNAI,
		    (const char *)favePtr->faVisitorMnNAI,
		    (size_t)acceptedFAVE->faVisitorMnNAILen)) {
			if (code == 0) {
				/* Set to reason unspecified */
				code = FA_REASON_UNSPECIFIED;
				faCounters.faReasonUnspecifiedCnt++;
			}
		}
	}
	if (acceptedFAVE != NULL)
		(void) rw_unlock(&acceptedFAVE->faVisitorNodeLock);

	/* Check for assigned homeaddr validity */
	if (replyPtr->homeAddr == INADDR_ANY ||
	    replyPtr->homeAddr == INADDR_LOOPBACK ||
	    replyPtr->homeAddr == INADDR_BROADCAST) {
		if (code == 0) {
			/* Set to reason unspecified */
			code = FA_REASON_UNSPECIFIED;
			faCounters.faReasonUnspecifiedCnt++;
		}
	}

reply:
	/* Do we need to overwrite the code field? */
	if (code)
		replyPtr->code = (uint8_t)code;

	/*
	 * We need to accept the pending entry before sending the reply
	 * to the MN. The reason being: if the acceptance fails (due
	 * to lack of resources for example) then we need to indicate
	 * this to the MN with the appropriate code set in the reply
	 */
	if (((replyPtr->code == MIP_SUCCESSFUL_REGISTRATION) ||
		(replyPtr->code == MIP_SIMULTANEOUS_NOT_SUPPORTED)) &&
		(replyPtr->regLifetime != 0)) {
		/*
		 * Delete prior accepted entries for this MN and
		 * COA pair and make the "pending" entry "accepted".
		 * The COA is available in the faVisitorCOAddr
		 * field of favePtr.
		 */
		acceptFAVE(&faVisitorHash, replyPtr, &favePtr);
	}
	/*
	 * TODO: Handle extensions properly. For now, we include no
	 * extensions in denials and therefore don't need to change
	 * newLen.
	 */


	visitor_entryExists = isAcceptedVisitor(&faVisitorHash,
	    replyPtr->homeAddr, favePtr->faVisitorIfaceAddr);


	if (visitor_entryExists == _B_FALSE) {

		/*
		 * If the source link layer address is valid add an ARP
		 * entry else don't. The entry could be invalid for variety
		 * of reasons (See recvNetworkPacket)
		 */
		if (favePtr->faVisitorIsSllaValid &&
		    (replyPtr->homeAddr != INADDR_ANY)) {
			/*
			 * Add a temporary ARP entry to prevent the FA from
			 * broadcast ARPing.  This entry is deleted when the
			 * MN is removed from the visitors list. Note, the entry
			 * is marked permanent so the FA does not have worry
			 * about ARP blowing the entry away when it refreshes
			 * it's cache.
			 */
			if ((val = arpIfadd(replyPtr->homeAddr,
			    favePtr->faVisitorSlla.sdl_data,
			    favePtr->faVisitorInIfindex)) < 0) {
				syslog(LOG_ERR, "SIOCSXARP failed... %s",
				    err2str(val));
			}
		}
	}

	/*
	 * If the request was sent from a mobile node whose home address is not
	 * yet configured i.e 0.0.0.0, then the reply should be sent as an IP
	 * level broadcast but with the mobile nodes link layer address as the
	 * destination L2 i.e link layer unicast. This can be done by opening a
	 * link layer raw socket, constructing the various headers and sending
	 * the packet (cf. RFC 3220 section 3.7.2.3)
	 */
	if ((replyPtr->homeAddr == INADDR_ANY) &&
	    favePtr->faVisitorIsSllaValid) {
		if (sendRawPkt(messageHdr, entry, messageHdr->pktLen) == 0) {
			mipverbose(("\n---- %s (%s) ----\n",
					sprintTime(currentTime,
					    MAX_TIME_STRING_SIZE),
					sprintRelativeTime(relativeTime,
					    MAX_TIME_STRING_SIZE)));
			(void) memcpy(ether.ether_addr_octet,
			    favePtr->faVisitorSlla.sdl_data, ETHERADDRL);
			mipverbose(("FA relayed reg reply to "
					"255.255.255.255.%d for MN 0.0.0.0 "
					"[MAC: %s] (Code %d)\n",
					favePtr->faVisitorPort,
					ether_ntoa(&ether),
					replyPtr->code));
			mipverbose(("FA relayed reply packet:\n"));
			if (logVerbosity > 2)
				printBuffer(messageHdr->pkt,
				    messageHdr->pktLen);
			mipverbose(("\n"));
			return;
		} else {
			mipverbose(("FAprocessRegReply: raw send failed at FA"
				" to relay reply.\n"));
			return;
		}
	}

	/*
	 * Set socket option IP_XMIT_IF to get the registration reply
	 * unicast to the mobile node...
	 */
	val = favePtr->faVisitorInIfindex;
	if (setsockopt(entry->maIfaceUnicastSock, IPPROTO_IP, IP_XMIT_IF,
	    &val, sizeof (val)) < 0) {
		/* There's a problem... */
		syslog(LOG_ERR, "Can't set IP_XMIT_IF socket option for "
		    "registration reply to mobile node %s.",
		    ntoa(messageHdr->src, addrstr1));
	}

	if (sendUDPmessage(entry->maIfaceUnicastSock, messageHdr->pkt,
	    messageHdr->pktLen, favePtr->faVisitorHomeAddr,
	    favePtr->faVisitorPort) == 0) {

		mipverbose(("\n---- %s (%s) ----\n",
		    sprintTime(currentTime, MAX_TIME_STRING_SIZE),
		    sprintRelativeTime(relativeTime, MAX_TIME_STRING_SIZE)));
		mipverbose(("FA relayed reg reply to %s.%d (Code %d)\n",
				ntoa(favePtr->faVisitorHomeAddr, addrstr1),
				favePtr->faVisitorPort, replyPtr->code));
		faCounters.faRegRepliesRelayedCnt++;

		mipverbose(("FA relayed reply packet:\n"));
		if (logVerbosity > 2)
			printBuffer(messageHdr->pkt, messageHdr->pktLen);
		mipverbose(("\n"));

	} else {
		syslog(LOG_ERR, "sendto failed at FA while relaying reply.");
	}

	/* Reset IP_XMIT_IF option on socket */
	val = 0;
	if (setsockopt(entry->maIfaceUnicastSock, IPPROTO_IP, IP_XMIT_IF,
	    &val, sizeof (val)) < 0) {
		syslog(LOG_ERR, "Can't unset socket option IP_XMIT_IF"
		    "which was set for interface index %d",
		    favePtr->faVisitorInIfindex);
	}
	if (visitor_entryExists == _B_FALSE) {

		if (favePtr->faVisitorIsSllaValid) {
			/*
			 * Delete the temporary ARP entry
			 */
			if ((val = arpIfdel(replyPtr->homeAddr,
			    favePtr->faVisitorSlla.sdl_data,
			    favePtr->faVisitorInIfindex)) < 0) {
				/*
				 * If the deletion failed bcos there was no
				 * entry then we don't need to report it
				 */
				if (val != (-1)*ENXIO) {
					syslog(LOG_ERR,
					    "SIOCDXARP failed... %s",
					    err2str(val));
				}
			}
		}
	}

	if ((replyPtr->code == MIP_SUCCESSFUL_REGISTRATION) ||
	    (replyPtr->code == MIP_SIMULTANEOUS_NOT_SUPPORTED)) {
	    if (replyPtr->regLifetime == 0) {
			COAddr = favePtr->faVisitorCOAddr;
			GET_TIME(localTime);
			sessionLifeTime =  localTime -
			    favePtr->faVisitorTimeGranted;
			/*
			 * Deregistration ... delete visitor entries for
			 * this MN
			 */
			delFAVE(&faVisitorHash, &favePtr, replyPtr->homeAddr,
			    MN_DEREGISTERED);

			if (aaaProtocol != AAA_NONE) {
				/*
				 * An accounting stop record must be sent.
				 */
				result = sendAccountingRecord(
					MOBILE_IP_ACCOUNTING_STOP_REQUEST,
					    (unsigned char *)NAIBuffer,
					    messageHdr->mnNAILen,
					    replyPtr->homeAddr, COAddr,
					    replyPtr->haAddr,
					    sessionLifeTime, MN_DEREGISTERED);

				if (result) {
				    syslog(LOG_ERR, "Unable to send accounting "
							"stop record");
				}
			}
	    } else {

			if (visitor_entryExists == _B_FALSE &&
			    aaaProtocol != AAA_NONE) {
				/*
				 * An accounting start record must be sent.
				 */
				result = sendAccountingRecord(
					MOBILE_IP_ACCOUNTING_START_REQUEST,
					    (unsigned char *)NAIBuffer,
					    messageHdr->mnNAILen,
					    replyPtr->homeAddr,
					    favePtr->faVisitorCOAddr,
					    replyPtr->haAddr, 0, 0);

				if (result) {
					/*
					 * PRC: Here we must disconnect the
					 * mobile node since we cannot bill
					 * for services rendered, but I am
					 * not sure how this can be done.
					 */
					syslog(LOG_ERR,
						"Unable to send accounting "
						"start record");
				}
			} else if (aaaProtocol != AAA_NONE) {
				/*
				 * An accounting start record must be sent.
				 */
				GET_TIME(localTime);
				result =
				    sendAccountingRecord(
					MOBILE_IP_ACCOUNTING_INTERIM_REQUEST,
					    (unsigned char *)NAIBuffer,
					    messageHdr->mnNAILen,
					    replyPtr->homeAddr,
					    (favePtr) ?
					    favePtr->faVisitorCOAddr : 0,
					    replyPtr->haAddr,
					    localTime -
					    ((favePtr) ?
						favePtr->faVisitorTimeGranted:
						0), 0);

				if (result) {
					/*
					 * PRC: Here we must disconnect the
					 * mobile node since we cannot bill
					 * for services rendered, but I am
					 * not sure how this can be done.
					 */
					syslog(LOG_ERR, "Unable to send "
					    "accounting interim record");
				}
			}
	    }
	} else {
		/*
		 * For denials, simply delete pending entry unless it
		 * corresponds to an HA discovery request; In that case
		 * let the periodic timer delete the request.
		 * TODO: It is better to look at the HA field in the
		 * request but since we don't have the MN's home
		 * netmask, we rely on the returned code.
		 */
		if (replyPtr->code != HA_UNKNOWN_HOME_AGENT) {
			COAddr = favePtr->faVisitorCOAddr;
			if (delHashTableEntryUint(htbl, favePtr,
			    replyPtr->homeAddr, LOCK_NONE)) {
				/*
				 * Found a match, delete it
				 */
				delFAVEptr(favePtr, _B_TRUE, 0);
				(void) rw_unlock(&favePtr->faVisitorNodeLock);
				(void) rwlock_destroy(
					&favePtr->faVisitorNodeLock);
				free(favePtr);
				favePtr = NULL;
			}

			if (aaaProtocol != AAA_NONE) {
				/*
				 * An accounting stop record must be sent
				 * to log a failed request.
				 */
				result = sendAccountingRecord(
					MOBILE_IP_ACCOUNTING_STOP_REQUEST,
					    (unsigned char *)NAIBuffer,
					    messageHdr->mnNAILen,
					    replyPtr->homeAddr, COAddr,
					    replyPtr->haAddr, 0, 0);

				if (result) {
				    syslog(LOG_ERR, "Unable to send accounting "
							"stop record");
				}
			}
		}
	}

	if (favePtr) {
		(void) rw_unlock(&favePtr->faVisitorNodeLock);
	}

	mipverbose(("\n\n"));
}

#ifdef RADIUS_ENABLED
void
loadRadiusLibrary()
{
	void	*handle;
	int	result;
	/*
	 * Open the dynamic library
	 */
	handle = dlopen(radiusSharedLibrary, RTLD_LAZY|RTLD_GLOBAL);
	if (handle == NULL) {
		(void) fprintf(stderr,
		    "Unable to open dynamic library %s (%s)\n",
			radiusSharedLibrary, dlerror());
		radiusEnabled = 0;
		return;
	}

	/*
	 * Setup our function pointers.
	 */
	radInitializeApi = (int (*)())dlsym(handle, "InitializeAPI");
	if (radInitializeApi == NULL) {
	    (void) fprintf(stderr,
		"Unable to resolve initialization function %s (%s)\n",
		radiusSharedLibrary, dlerror());
	    radiusEnabled = 0;
	    dlclose(handle);
	    return;
	}
	radLookupData = (int (*)(char **, char *, RadData *)) dlsym(handle,
							"LookupData");
	if (radLookupData == NULL) {
	    (void) fprintf(stderr,
		"Unable to resolve lookup function %s (%s)\n",
			radiusSharedLibrary, dlerror());
	    radiusEnabled = 0;
	    dlclose(handle);
	    return;
	}
	radCloseSession = (int (*)(char *, char *, void *)) dlsym(handle,
							"CloseSession");
	if (radLookupData == NULL) {
	    (void) fprintf(stderr, "Unable to resolve close function %s (%s)\n",
			radiusSharedLibrary, dlerror());
	    radiusEnabled = 0;
	    dlclose(handle);
	    return;
	}

	/*
	 * Call the module's initialization function.
	 */
	result = radInitializeApi();
	if (result) {
	    (void) fprintf(stderr, "Error initializing dynamic library %s",
			radiusSharedLibrary);
	    radiusEnabled = 0;
	    dlclose(handle);
	    return;
	}

	dlclose(handle);
} /* loadRadiusLibrary */
#endif /* RADIUS_ENABLED */


/*
 * Function: formIPsecBits(int type, char *nodeID, char *ipsecPolicy_p,
 *               char *Filename)
 *
 * Arguments:	type	      - type of IPsec SA we want to install.
 *		nodeID	      - nodeID this policy is for (dotted ipAddr).
 *              ipsecPolicy_p - a pointer to the policy string.  The format's
 *				identical to ipsec's "<action> {properties}"
 *				as set, and parsed, in mipagent.conf.
 *              ipsecPolicy   - the storage for the FULL policy, that is
 *				"{<pattern>} action {<properties>}".
 *		ipsecPolicySize - size of the ipsecPolicy buffer
 * Description: This function builds the complete IPsec Policy for install and
 *		remove functions to ensure consistency between them.
 *              Note: this is the current functional solution until IPsec
 *              supports multiple per-socket policies, or provides an API.
 *
 * Returns:     -1 if bad pointers were passed, or if their was some other
 *	         problem building things.  0 on success, in which case
 *		ipsecPolicy is presumed to contain a good ipsec policy.
 *
 * Note: this function will be unnecessary when ipsec has an API.
 */
int
formIPsecBits(int type, char *nodeID, char *ipsecPolicy_p, char *ipsecPolicy,
    size_t ipsecPolicySize)
{
	/* a quick sanity check */
	if ((nodeID == NULL) || (ipsecPolicy_p == NULL) ||
	    (ipsecPolicy == NULL))
		/* caller's confused */
		return (-1);

	/* build the complete ipSec policy */
	switch (type) {

	case IPSEC_REQUEST_APPLY:
		/* IPsec Policy - FA apply policy for sending regreQ */
		(void) snprintf(ipsecPolicy, ipsecPolicySize,
		    "{daddr %s ulp udp dport %d} %s\n",
		    nodeID, MIP_PORT, ipsecPolicy_p);
		break;

	case IPSEC_REQUEST_PERMIT:
		/* IPsec Policy - HA permit policy for receiving regreQ */
		(void) snprintf(ipsecPolicy, ipsecPolicySize,
		    "{saddr %s ulp udp dport %d} %s\n",
		    nodeID, MIP_PORT, ipsecPolicy_p);
		break;

	case IPSEC_REPLY_APPLY:
		/* IPsec Policy - HA apply policy for sending regreP */
		(void) snprintf(ipsecPolicy, ipsecPolicySize,
		    "{daddr %s ulp udp sport %d} %s\n",
		    nodeID, MIP_PORT, ipsecPolicy_p);
		break;

	case IPSEC_REPLY_PERMIT:
		/* IPsec Policy - FA permit policy for receiving regreQ */
		(void) snprintf(ipsecPolicy, ipsecPolicySize,
		    "{saddr %s ulp udp dport %d} %s\n",
		    nodeID, MIP_PORT, ipsecPolicy_p);
		break;

	/*
	 * tunnel policies are passed directly down via the ipsec_req_t structs
	 * in the MobilityAgentEntry struct and ioctl().  Keep these tags here,
	 * though, for debugging.
	 */
	case IPSEC_TUNNEL_APPLY:
	case IPSEC_TUNNEL_PERMIT:
	case IPSEC_REVERSE_TUNNEL_APPLY:
	case IPSEC_REVERSE_TUNNEL_PERMIT:
		/* syslog() in case we're actually trying to do this! */
		syslog(LOG_WARNING,
		    "Attempt to set global policy for tunnels incorrect.");
		return (-1);

	/* catch all for anything we don't understand! */
	default:
		/* we don't know this type */
		syslog(LOG_WARNING,
		    "Attempt to set global policy for unknown policy type.");
		return (-1);
	}

	return (0);
}



/*
 * Function: installIPsecPolicy
 *
 * Arguments: char *policy - a pointer to the policy string.  The format's
 *		"{pattern} <action> {properties}" as per ipsec.
 *
 * Description: This function does what it takes to install the ipsecPolicy of
 *		the type passed in.  Right now, that means calling popen() to
 *		get "ipsecconf -(a | r) -" going (note: this is a S9 option
 *		only, '-' is stdin (I suppose I could use /dev/stdin for this,
 *		 but it should be symmetric with 'removeIPsecPolicy()', which
 *		also uses an S9-only option, namely -r, see its description)!
 *              In this way we don't need to create a temporary file only to
 *		delete it.  Once "ipsecconf -a -" is up, we write the policy
 *		to it, then pclose().
 *
 * Returns: -1 if bad pointers were passed, or if their was some other problem
 *	invoking the ipSec policy.  0 on success.
 */
int
installIPsecPolicy(char *policy) {
	int ret;
	FILE *fp;

	if (policy == NULL)
		return (-1);

	if ((fp = popen(IPSEC(ADD_POLICY), "w")) == NULL) {
		syslog(LOG_CRIT, "Couldn't start ipsec install process.");
		return (-1);
	}

	/* send the policy to fp == stdin */
	(void) fprintf(fp, "%s", policy);

	/* pclose() will flush, and send the EOF */
	ret = pclose(fp);

	/* if pclose returned 1, there was a problem */
	if (ret == 1)
		/* return in defeat */
		return (-1);

	/* fin */
	return (0);
}


/*
 * Function: removeIPsecPolicy
 *
 * Arguments:	char *policy - a pointer to the policy string.  The format is
 *				identical to ipsec's "<action> {properties}"
 *				as set, and parsed, in mipagent.conf.
 *
 * Description: This function does what it takes to remove the ipsecPolicy of
 *		the type passed in.  Right now, that means calling popen() to
 *		get ipsecconf running, and waiting for the policy to remove,
 *		then passing the policy to have it deleted from IPsec's
 *		pattern table, and finally calling pclose().  Note: ipsecconf's
 *		-r[emove] option is only supported in S9 or later!
 *
 * Returns: -1 if bad pointers were passed, or if their was some other problem
 *	removeing the ipSec policy.  0 on success.
 */
int
removeIPsecPolicy(char *policy) {
	FILE *fp;	/* for file manipulation */
	int ret;

	if (policy == NULL)
		/* caller's confused... */
		return (-1);

	/* pass to ipsec */
	if ((fp = popen(IPSEC(SUB_POLICY), "w")) == NULL)
		return (-1);

	/* write policy to fp == stdin */
	(void) fprintf(fp, "%s", policy);

	/* only write one at a time */
	ret = fclose(fp);

	if (WEXITSTATUS(ret) != 0) {
		syslog(LOG_CRIT, "Couldn't remove IPsec policy %s.", policy);
		return (-1);
	}

	/* fin */
	return (0);

} /* removeIPsecPolicy */



/*
 * Function: main
 *
 * Arguments:	argc - Number of runtime arguments
 *		argv - Pointer to runtime arguments
 *
 * Description:	This function is the main agent routine that gets
 *		called upon startup. This function will:
 *		1. Read the initialization file.
 *		2. Start the SNMP sub-agent thread.
 *		3. Start the periodic task Thread.
 *		4. Start the AAA thread.
 *		5. Start the message dispatching Thread.
 *
 *		This thread will then wait for an incoming signal
 *		(INT and TERM), and will call the shutdown procedure
 *		once such a signal is received.
 *
 * Returns: exits
 */
#ifndef TEST_AAA
int
main(int argc, char *argv[])
{
	sigset_t thread_signals;
	int signal = 0;
	int c;
	int rc;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "d")) != EOF) {
	    switch (c) {
	    case 'd':
		/* private debugging argument */
		daemonize = _B_FALSE;
		break;
	    default:
		/* mipagent has no public arguments */
		(void) fprintf(stderr, "Usage: %s\n", *argv);
		exit(-1);
	    }
	}

	/*
	 * Read the config file name and create internal data
	 * structures.
	 */
	if (Initialize(CONF_FILE_NAME)) {
		syslog(LOG_CRIT, "Error Initializing.");
		exit(-1);
	}

#ifdef RADIUS_ENABLED
	if (radiusEnabled) {
		loadRadiusLibrary();
	}
#endif /* RADIUS_ENABLED */

	(void) restoreAgentState();

	/*
	 * We need to unblock the signals that we care about.
	 */
	(void) sigemptyset(&thread_signals);
	(void) sigaddset(&thread_signals, SIGINT);
	(void) sigaddset(&thread_signals, SIGTERM);
	(void) sigaddset(&thread_signals, SIGUSR1);

	if (pthread_sigmask(SIG_BLOCK, &thread_signals, NULL)) {
		syslog(LOG_ERR, "Unable to set thread signals");
		exit(-1);
	}

	if (disableSNMP == _B_FALSE) {
		/*
		 * Initialize the SNMP Thread.
		 */
		if (startSNMPTaskThread()) {
			syslog(LOG_CRIT, "Error Initializing SNMP.");
			exit(-1);
		}
	}

	/*
	 * Start the AAA thread.
	 */
	if (aaaProtocol != AAA_NONE) {
		if ((rc = startAAATaskThread()) != 0) {
			syslog(LOG_CRIT,
			    "Error: rc = %d when calling startAAATaskThread\n",
			    rc);
			exit(-1);
		}
	}

	/*
	 * Start a thread which will handle all periodic tasks.
	 */
	if (startPeriodicTaskThread()) {
		syslog(LOG_CRIT, "Unable to start periodic thread");
		exit(-1);
	}

	/*
	 * Initialize the multi-thread message dispatcher.
	 */
	if (startDispatcherTaskThread()) {
		syslog(LOG_CRIT, "Unable to initialize the message "
		    "dispatcher");
		exit(-1);
	}

	/*
	 * If DynamicInterface global variable is set, then
	 * start DynamicInterface process thread
	 */
	if (DynamicInterface) {
		/* Make a list of existing interfaces first */
		if (CreateListOfExistingIntfce() != 0) {
			syslog(LOG_ERR,
				"Unable to create a list of interfaces: %m");
			exit(-1);
		}
		if (startDynamicInterfaceThread()) {
			syslog(LOG_CRIT,
			    "Unable to start Dynamic Interface Thread");
			exit(-1);
		}
	}


	/*
	 * Start stat door server.
	 */
	if (startStatServer()) {
		syslog(LOG_ERR, "Unable to create stat server door");
	}

	/*
	 * Let's start the performance test thread
	 */
	if (performanceInterval) {
		syslog(LOG_ERR, "Starting the performance checker");
		if (startPerfTestServer()) {
			syslog(LOG_ERR, "Unable to create performance server");
		}
	}

	/*
	 * We need to unblock the signals that we care about.
	 */
	(void) sigemptyset(&thread_signals);
	(void) sigaddset(&thread_signals, SIGINT);
	(void) sigaddset(&thread_signals, SIGTERM);
	(void) sigaddset(&thread_signals, SIGUSR1);

	if (pthread_sigmask(SIG_UNBLOCK, &thread_signals, NULL)) {
		syslog(LOG_ERR, "Unable to set thread signals");
		exit(-1);
	}

	(void) sigwait(&thread_signals, &signal);

	Finalize(signal);

	return (0);
}
#endif


static void
perf_thread()
{
	time_t startTime;
	time_t stopTime;
	struct timeval tv;
	char buffer[PERF_MSG_SIZE];

	while (faCounters.faRegReqRecvdCnt == 0 &&
	    haCounters.haRegReqRecvdCnt == 0) {
		(void) sleep(1);
	}

	GET_TIME(startTime);
	/* CONSTCOND */
	while (_B_TRUE) {
		tv.tv_sec = performanceInterval;
		tv.tv_usec = 0;
		(void) select(FD_SETSIZE, NULL, NULL, NULL, &tv);
		GET_TIME(stopTime);

		if (haCounters.haRegReqRecvdCnt) {
			(void) sprintf(buffer, "HA Packets per second %ld\n",
			    haCounters.haRegReqRecvdCnt /
			    (stopTime - startTime));
			syslog(LOG_ERR, "%s", buffer);
		}

		if (faCounters.faRegReqRecvdCnt) {
			(void) sprintf(buffer, "FA Packets per second %ld\n",
			    faCounters.faRegReqRecvdCnt /
			    (stopTime - startTime));
			syslog(LOG_ERR, "%s", buffer);
		}
	}
}


static int
startPerfTestServer()
{
	pthread_t threadId = 0;
	pthread_attr_t pthreadAttribute;
	int result;

	result = pthread_attr_init(&pthreadAttribute);

	if (result) {
		syslog(LOG_CRIT, "Error Initializing pthread.");
		return (-1);
	}

	/*
	 * We now create a thread to deal with all periodic task.
	 */
	result = pthread_create(&threadId, &pthreadAttribute,
	    (void *(*)()) perf_thread,
	    (void *)NULL);

	if (result) {
		syslog(LOG_CRIT, "pthread_create() failed.");
		return (-1);
	}

	/*
	 * In order for system resources the be properly cleaned up,
	 * we need to detach the thread. Otherwise, we need to wait for
	 * a pthread_join(), which we do not want.
	 */
	result = pthread_detach(threadId);

	if (result) {
		syslog(LOG_CRIT, "pthread_detach() failed.");
		return (-1);
	}

	return (0);


}

/*
 * Function : ConfigEntryHashLookup
 *
 * Description:
 *	This lookup function matches the interface index of the
 *	entry with the passed value.
 * Returns  _B_TRUE if the entry matches the desired criteria
 *          else _B_FALSE
 */

/* ARGSUSED */
boolean_t
ConfigEntryHashLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	MaAdvConfigEntry	*maAdvEntry = entry;

	if (maAdvEntry->maIfindex == p1)
		return (_B_TRUE);
	else
		return (_B_FALSE);
}
