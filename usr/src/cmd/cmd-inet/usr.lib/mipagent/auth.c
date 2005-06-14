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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: auth.c
 *
 * This function contains all of the routines
 * necessary to authenticate Registration Requests,
 * including the functions which add and validate
 * the authentication extensions, the SPI lookup
 * routines, etc.
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "agent.h"
#include "mip.h"
#include "md5.h"
#include "auth.h"

#include <sys/types.h>
#include <netinet/in.h>


extern char msg[];
extern AAA_Protocol_Code aaaProtocol;
extern boolean_t faChallengeAdv;
extern boolean_t mfAuthRequired;
extern boolean_t fhAuthRequired;
extern int logVerbosity;

/*
 * Default Values...
 */
extern uint32_t defaultPool;
extern uint32_t defaultNodeSPI;

#ifdef RADIUS_ENABLED
HaMobileNodeEntry *radiusCheckUpdate(HaMobileNodeEntry *dest,
    struct hash_table *htbl, ipaddr_t mnAddr);
#endif /* RADIUS_ENABLED */

static boolean_t isAuthExtOk(unsigned char *, int, MipSecAssocEntry *);
extern int hexdump(char *, unsigned char *, int);
extern uint32_t getRandomValue();

/* ----------------- Common to all mobility agents ------------------- */
/*
 * This table stores all of the Security Assocations
 */
extern HashTable mipSecAssocHash;

/*
 * This table has one entry for each known Mobility Agent
 */
extern HashTable mipAgentHash;

/*
 * This table has one entry for each pool defined in the config file
 */
extern HashTable mipPoolHash;

/* ------------------ Specific to foreign agents -------------------- */

/*
 * Counters maintained by Foreign Agents
 */
extern ForeignAgentCounters faCounters;

/*
 * The last two challenges advertised
 */
extern char faLastChallengeIssued[2][ADV_CHALLENGE_LENGTH];


/* ------------------ Specific to home agents -------------------- */
/*
 * This table has one entry for each mobile node for which a mobility
 * agent offers Home Agent services.
 */
extern HashTable haMobileNodeHash;

/*
 * Counters maintained by Home Agents
 */
extern HomeAgentCounters haCounters;

/*
 * Compute authenticator for the data in buffer based on the
 * Mobile IP Security Association pointed to by msaEntry.
 */

/*
 * Function: computeAuth
 *
 * Arguments:	buffer - Pointer to buffer
 *		buflen - Length of data in the buffer
 *		authenticator - Pointer to the output buffer
 *		authenticationlen - length of the output buffer
 *		msa - Pointer to the security association entry.
 *
 * Description:	Compute authenticator for the data in buffer based on the
 *		Mobile IP Security Association pointed to by msaEntry.
 *
 * Returns: void
 */
static void
computeAuth(unsigned char buffer[], int buflen,
		unsigned char authenticator[], int *authenticatorlen,
		MipSecAssocEntry *msa)
{
	MD5_CTX context;

	/*
	 * Initialize the length.
	 */

	if (msa) {
		switch (msa->mipSecAlgorithmType) {
		case MD5:
			if (*authenticatorlen < AUTHENTICATOR_LEN) {
				syslog(LOG_ERR,
				    "Not enough space for MD5 authenticator.");
			} else if (msa->mipSecAlgorithmMode != PREFIXSUFFIX) {
				syslog(LOG_ERR, "Unknown mode specified " \
				    "for MD5 algorithm.");
			} else {
				/*
				 * No longer print MD5 results.
				 */
				*authenticatorlen = 0;
				MD5Init(&context);
				MD5Update(&context, msa->mipSecKey,
				    (unsigned int) msa->mipSecKeyLen);
				MD5Update(&context, buffer,
				    (unsigned int) buflen);
				MD5Update(&context, msa->mipSecKey,
				    (unsigned int) msa->mipSecKeyLen);
				MD5Final(authenticator, &context);
				*authenticatorlen = AUTHENTICATOR_LEN;
			}
			break;

		case NONE:
			/* we leave the contents of authenticator unchanged */
			*authenticatorlen = AUTHENTICATOR_LEN;
			break;

		default:
			/*
			 * Any other authentication transform, which we
			 * currentlydo not support.
			 */
			syslog(LOG_ERR, "Invalid Authentication Type " \
			    "requested");
		}
	}
}


/*
 * Function: appendAuthExt
 *
 * Arguments:	buffer - Pointer to the packet
 *		buflen - Offset in the packet where extension is
 *			to be added.
 *		type - Extension Id
 *		msa - Pointer to the Security Assocation Entry
 *
 * Description: Append authentication extension to a registration
 *		reply contained in buffer based on the Mobile IP
 *		Security Association pointed to by MSA. Returns
 *		total number of bytes in the extension.
 *
 * Returns: The number of bytes added to the packet.
 */
int
appendAuthExt(unsigned char *buffer, size_t buflen, uint8_t type,
    MipSecAssocEntry *msa)
{
	int authlen = 0;
	authExt *aep;
	uint32_t SPI;
	uint16_t tempShort;

	if (msa) {
		/*
		 * TODO:
		 * The length of authenticator actually depends on the
		 * algorithm. For now, we assume AUTHENTICATOR_LEN.
		 */

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		aep = (authExt *)(buffer + buflen);
		aep->type = type;

		/*
		 * We need to set to length to the sizeof the SPI plus the
		 * length of the authenticator.
		 */
		aep->length = (sizeof (SPI) + AUTHENTICATOR_LEN);
		SPI = (msa == NULL) ? 0 : msa->mipSecSPI;
		tempShort = htons(SPI >> AUTHENTICATOR_LEN);
		(void) memcpy(&aep->SPIhi, &tempShort, sizeof (uint16_t));
		tempShort =  htons(SPI & 0xffff);
		(void) memcpy(&aep->SPIlo, &tempShort, sizeof (uint16_t));

		authlen = AUTHENTICATOR_LEN;
		computeAuth(buffer, buflen + sizeof (authExt),
		    buffer + buflen + sizeof (authExt), &authlen, msa);

		if (authlen) {
			authlen += sizeof (authExt);
		}
	}

	return (authlen);
}


/*
 * Function: isAuthOk
 *
 * Arguments:	buffer - Pointer to buffer
 *		buflen - Length of data in the buffer
 *		authenticator - Pointer to hash to compare against
 *		authenticationlen - length of hash buffer
 *		msa - Pointer to the security association entry
 *
 * Description:	This function computes a hash using the buffer and
 *		compares the result with the data in the authenticator.
 *		If both values match, the packet is considered
 *		authenticated.
 *
 * Returns: boolean_t - _B_FALSE if packet is not authenticated.
 */
static boolean_t
isAuthOk(unsigned char buffer[], int buflen,
		unsigned char authenticator[], int authenticatorlen,
		MipSecAssocEntry *msa)
{
	static unsigned char newAuth[32];
	int newAuthLen = 32;
	int i;

	if (msa == NULL) {
		return (_B_FALSE);
	}

	switch (msa->mipSecAlgorithmType) {
	case MD5:
	    computeAuth(buffer, buflen, newAuth, &newAuthLen, msa);
	    mipverbose(("authenticator = %d bytes, newAuth = %d bytes\n",
			authenticatorlen, newAuthLen));
	    if (newAuthLen != authenticatorlen)
		return (_B_FALSE);

	    for (i = 0; i < newAuthLen; i++) {
		if (newAuth[i] != authenticator[i]) {
		    syslog(LOG_ERR,
			"isAuthOk: bad key at position %d (%02X <> %02X)\n",
				i, authenticator[i], newAuth[i]);
		    return (_B_FALSE);
		}
	    }

	    break;

	case NONE:
	    /* No checks required */
	    break;
	}

	return (_B_TRUE);
}


/*
 * Function: isAuthExtOk
 *
 * Arguments:	buffer - Pointer to a packet
 *		buflen - Offset in the packet where the authentication
 *			extension can be found.
 *		msa - Pointer to a Security Assocation Entry
 *
 * Description:	Buffer contains buflen bytes of a registration request
 *		and an immediately following authentication extension.
 *		Check if the authentication extension is correct
 *		according to the given msa.
 *
 * Returns: boolean_t - _B_TRUE if authentication extension was
 *		computed using the protocol security assocation.
 */
static boolean_t
isAuthExtOk(unsigned char buffer[], int buflen, MipSecAssocEntry *msa)
{
	int authLen;
	boolean_t result = _B_FALSE;
	authExt *aep;
	genAuthExt *genAep;
	uint32_t SPI;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	aep = (authExt *) (buffer + buflen);

	/*
	 * Support for the latest Challenge/response draft, which
	 * requires support for the generalized authentication header.
	 */
	switch (aep->type) {
	case REG_MH_AUTH_EXT_TYPE:
	case REG_MF_AUTH_EXT_TYPE:
	case REG_FH_AUTH_EXT_TYPE:
		GET_SPI(SPI, aep);

		if (SPI != msa->mipSecSPI) {
			mipverbose(("Type: %d, Length %d\n", aep->type,
			    aep->length));
			mipverbose(("SPI mismatch got %d had %d.\n",
			    SPI, msa->mipSecSPI));
			result = _B_FALSE;
		} else {
			/* this length includes 4 bytes SPI */
			authLen = aep->length - 4;
			result = isAuthOk(buffer, buflen + sizeof (authExt),
			    (buffer + buflen + sizeof (authExt)),
			    authLen, msa);
		}
		break;

	case REG_GEN_AUTH_EXT_TYPE:
		genAep = (genAuthExt *) aep;

		GET_GEN_AUTH_SPI(SPI, genAep);

		if (SPI != msa->mipSecSPI) {
			mipverbose(("Type: %d, subType: %d, Length %d\n",
			    genAep->type, genAep->subType, genAep->length));
			mipverbose(("SPI mismatch got %d had %d.\n",
			    SPI, msa->mipSecSPI));
			result = _B_FALSE;
		} else {
			/* This length includes 4 bytes SPI */
			authLen = ntohs(genAep->length) - 4;
			result = isAuthOk(buffer, buflen + sizeof (genAuthExt),
			    (buffer + buflen + sizeof (genAuthExt)),
			    authLen, msa);
		}
		break;

	default:
		/*
		 * Unknown authentication type.... reject
		 */
		result = _B_FALSE;
		break;
	}

	return (result);
}

#ifdef TEST_AUTH
/*
 * Function: main
 *
 * Arguments:	argc - Number of command line parameters
 *		argv - Pointer to command line arguments
 *
 * Description: This function is used to validate our MD5 implementation.
 *		It is no longer in use, but is kept in case one needs
 *		to test the authentication computation in this file
 *		stand-alone.
 *
 * Returns: exits
 */
int
main(int argc, char *argv[])
{
	int i;
	unsigned char digest[AUTHENTICATOR_LEN];
	int digestlen = AUTHENTICATOR_LEN;
	MipSecAssocEntry msae = { { 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	    1, 0, MD5, PREFIXSUFFIX, 16,
	    { 0x11, 0x11, 0x11, 0x11,
	    0x11, 0x11, 0x11, 0x11,
	    0x11, 0x11, 0x11, 0x11,
	    0x11, 0x11, 0x11, 0x11
	    },
	    TIMESTAMPS, 0 };

	unsigned char packet[30] = {
	/*
	 *	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	 *	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	 */
		0x01, 0x00, 0x00, 0x28, 0x81, 0x92, 0x7a, 0xcc,
		0x81, 0x92, 0x7a, 0xbf, 0x81, 0x92, 0xc9, 0x09,
		0x00, 0x00, 0x00, 0x00, 0xe4, 0xa8, 0x5f, 0xcb,
		0x20, 0x14, 0x00, 0x00, 0x00, 0x01
	/*
	 *	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	 *	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
	 */
	};
	/*
	 *	0x01, 0x00, 0x01, 0x2c, 0x81, 0x92, 0x7a, 0xc0,
	 *	0x81, 0x92, 0x7a, 0x7b, 0x81, 0x92, 0xc9, 0x09,
	 *	0x00, 0x00, 0x00, 0x00, 0x17, 0xe1, 0x2c, 0x23,
	 *	0x20, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	 *	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	 *	0x11, 0x11
	 * };
	 * unsigned char packet[] = {'J', 'i', 'm'};
	 */

	printMSAE(&msae);
	computeAuth(packet, 30, digest, &digestlen, &msae);
	(void) printf("Authenticator for packet = ");
	printBuffer(digest, digestlen);
	(void) printf("\n");

	/* Simulate data corruption or incorrect MSAE */
	msae.mipSecKeyLen = 2;
	packet[2] = 0x00;
	msae.mipSecKey[0] = 'A';
	printMSAE(&msae);
	if (isAuthOk(packet, 3, digest, digestlen, &msae))
		(void) printf("Check succeeded.\n");

}
#endif /* TEST_AUTH */

/*
 * Function: findSecAssocFromSPI
 *
 * Arguments:	SPI - The Security Parameter Index value
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will look for a security assocation
 *		entry in the hash table matching on the SPI. If
 *		a lock type was requested, upon return the node
 *		will be locked. The caller will be responsible
 *		for unlocking the node when it no longer needs
 *		the security association entry.
 *
 *		If a security association entry was found, and
 *		the entry is marked as dynamic and if the key
 *		has expired, a NULL value will be returned.
 *
 * Returns:	If successful, a pointer to a Security Association
 *		Entry will be returned, otherwise NULL.
 */
MipSecAssocEntry *
findSecAssocFromSPI(uint32_t SPI, int lockType)
{
	MipSecAssocEntry *saEntry = NULL;
	time_t currentTime;

	/*
	 * Let's see if we can find the SA using the SPI.
	 */
	if ((saEntry = findHashTableEntryUint(&mipSecAssocHash,
	    SPI, lockType, NULL, 0, 0, 0)) != NULL) {
		/*
		 * Keys has a defined lifetime, which is set by the
		 * home AAA Server. We need to check whether the
		 * key being used is still valid.
		 */

		GET_TIME(currentTime);
		if (saEntry->mipSecIsEntryDynamic == TRUE &&
		    saEntry->mipSecKeyLifetime < currentTime) {
			/*
			 * The Security Association has expired.
			 * If the node was locked, we need to
			 * unlock it. We will be returning a NULL
			 * to the caller since this is no longer
			 * valid.
			 */
			if (lockType != LOCK_NONE) {
				(void) rw_unlock(&saEntry->mipSecNodeLock);
			}
			saEntry = NULL;
		}
	}

	return (saEntry);
}


/*
 * Note that upon return of a security association entry, the
 * node will be locked. The caller must unlock the node once
 * it is finished with the entry.
 */
/*
 * Function: findSecAssocFromIp
 *
 * Arguments:	address - Peer's IP Address
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will look for a security assocation
 *		entry in the hash table matching on the IP Address.
 *		If a lock type was requested, upon return the node
 *		will be locked. The caller will be responsible
 *		for unlocking the node when it no longer needs
 *		the security association entry.
 *
 *		If a security association entry was found, and
 *		the entry is marked as dynamic, if the key has
 *		expired
 *
 * Returns: If successful, a pointer to a Security Association
 *		Entry will be returned
 *	    If not successful, NULL is returned.
 */
MipSecAssocEntry *
findSecAssocFromIp(ipaddr_t address, int lockType)
{
	MobilityAgentEntry *maEntry;
	MipSecAssocEntry *saEntry = NULL;

	/*
	 * First we need to find the MA structure to get
	 * the SPI value.
	 */
	if ((maEntry = findHashTableEntryUint(&mipAgentHash,
	    address, LOCK_READ, NULL, 0, 0, 0)) != NULL) {
		/*
		 * Good, now let's find the SA itself.
		 */
		saEntry = findSecAssocFromSPI(maEntry->maSPI, lockType);

		(void) rw_unlock(&maEntry->maNodeLock);
	}

	return (saEntry);
}

/*
 * Function: findMaeFromIp
 *
 * Arguments:	address - Peer's IP Address
 *		lockType - The Lock type, which can be:
 *				LOCK_NONE - No Lock
 *				LOCK_READ - Read Lock
 *				LOCK_WRITE - Write Lock
 *
 * Description: This function will look for an IPsec Policy
 *		entry in the hash table matching on the IP Address.
 *		If a lock type was requested, upon return the node
 *		will be locked. The caller will be responsible
 *		for unlocking the node when it no longer needs
 *		the security association entry.
 *
 * Returns: If successful, a pointer to a Security Association
 *		Entry will be returned, otherwise NULL.
 */
MobilityAgentEntry *
findMaeFromIp(ipaddr_t address, int lockType)
{
	MobilityAgentEntry *maEntry;

	/*
	 * First we need to find the MA structure to get
	 * the SPI value.
	 */
	if ((maEntry = findHashTableEntryUint(&mipAgentHash,
	    address, lockType, NULL, 0, 0, 0)) == NULL)
		return (0);

	return (maEntry);
}


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
#define	MAX_SESSION_KEY_LEN	16
/*
 * Function: createSessionKey
 *
 * Arguments:	key - Pointer to session key buffer
 *		keyLen - Pointer to Length of session key
 *		spi - Pointer to SPI
 *
 * Description: This function is used to create pseudo-random
 *		session keys, and SPI values. Note that the
 *		keys created here are by no means random, and
 *		this function is only used for testing purposes.
 *
 * Returns:	none
 */
static void
createSessionKey(uint8_t *key, uint32_t *keyLen, uint32_t *spi)
{
	int i;

	/*
	 * First we create the SPI value.
	 */
	*spi = htonl(getRandomValue());

	/*
	 * Now we create the session key
	 */
	for (i = 0; i < MAX_SESSION_KEY_LEN; i++) {
		key[i] = getRandomValue();
	}

	/*
	 * Set the length
	 */
	*keyLen = MAX_SESSION_KEY_LEN;

}

/*
 * Function: createSessionKey
 *
 * Arguments:	keyData - Pointer to Genrealized key extension
 *		keyLen - Length of key extension
 *		spi - Pointer to SPI
 *
 * Description: This function will create a local Security
 *		association, using the information found in
 *		a generalized key extension. Note that this
 *		function is only used for testing purposes.
 *
 * Returns:	_B_TRUE if successful
 */
static boolean_t
createSecAssocFromKeyData(keyDataExt *keyData, int keyDataLen, uint32_t *SPI)
{
	uint32_t spi;
	uint32_t lifetime;

	/*
	 * Extract the information from the generalized key ext
	 */
	(void) memcpy(&spi, &keyData->nodeSPI, sizeof (uint32_t));
	(void) memcpy(&lifetime, &keyData->lifetime, sizeof (uint32_t));

	/*
	 * Create a new Security Association Entry
	 */
	if (aaaCreateKey(ntohl(spi), (uint8_t *)((char *)keyData) +
	    sizeof (keyDataExt), keyDataLen - sizeof (keyDataExt),
	    ntohl(lifetime))) {
		syslog(LOG_CRIT, "Unable to create SA from keydata");
		return (_B_FALSE);
	}

	/*
	 * Set the SPI value
	 */
	*SPI = ntohl(spi);

	return (_B_TRUE);
}

#endif /* KEY_DISTRIBUTION */

/*
 * Function: faCheckRegReqAuth
 *
 * Arguments:	messageHdr - Pointer to Message Control Block
 *		mnSPI - Pointer to Mobile Node's SPI
 *		mnChallenge - Pointer to the FA Challenge
 *		mnChallengeLen - Length of the Challenge
 *		forwardFlag - Pointer to the forward msg flag.
 *
 * Description: This function is responsible for authenticating
 *		the Registration Request. First, the function
 *		will check whether the Challenge is present, which
 *		MUST be if the agent is configured to advertise
 *		challenges. Next, the Mobile-Foreign is checked
 *		to ensure that the message is authenticated. If
 *		the extension was not found, and the agent is
 *		configured to require this extension, authentication
 *		will fail.
 *
 *		Lastly, if the Mobile-AAA authentication extension
 *		is present, we will send a request to the AAA
 *		infrastructure. If this request is successfully sent,
 *		the forward flag will be set to _B_FALSE to ensure that the
 *		caller does not forward the Registration Request to
 *		the Home Agent.
 *
 * Returns: int - 0 if successful, otherwise the Mobile-IP error code
 *		is returned. The forwardFlag will be set to _B_FALSE if
 *		the message is being sent to the AAA infrastructure.
 */
/* ARGSUSED */
int
faCheckRegReqAuth(MessageHdr *messageHdr, FaVisitorEntry *favePtr,
    FaVisitorEntry *acceptedFave, unsigned char *mnChallenge,
    uint32_t mnChallengeLen, boolean_t *forwardFlag)
{
	regRequest *reqPtr;
	MipSecAssocEntry *mipSecAssocEntry;
	authExt *mnAuthExt;
	/*
	 * Support for the latest Challenge/response draft.
	 */
	genAuthExt *mnAAAAuthExt;
	uint32_t SPI;
	uint32_t aaaSPI;
	size_t length;
	int mnAAAAuthExtLen;
	int mnAuthExtLen;
	int index;
	int result;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	reqPtr = (regRequest *)messageHdr->pkt;
	*forwardFlag = _B_TRUE;

	/*
	 * We have two different authentication types that we need
	 * to worry about. First, and foremost, we need to be able
	 * to support the case where a Mobile-Foreign Security
	 * Association exists. In the AAA world, an authenticated
	 * and authorized Mobile Node would have the keys setup in
	 * the mnFaNodeHash, and this case would apply.
	 *
	 * The next case is when we are unaware of the Mobile Node.
	 * In this case, the Mobile Node should have include the
	 * Challenge/Response extensions which are used for AAA
	 * purposes. When this is found, we issue a call to the local
	 * AAA daemon to authenticate and authorize the MN.
	 */

	if (faChallengeAdv) {
		if (mnChallengeLen == 0) {
			syslog(LOG_ERR,
			    "Missing Challenge Extention");
			faCounters.faMNAuthFailureCnt++;
			/*
			 * Support for the latest Challenge/response draft.
			 * If the challenge was expected, and found present,
			 * return a missing challenge error.
			 */
			return (FA_MISSING_CHALLENGE);
		}

		/*
		 * Obviously, we need to validate the challenge.
		 */
		if (memcmp(faLastChallengeIssued[0], mnChallenge,
		    ADV_CHALLENGE_LENGTH) != 0) {
			/*
			 * Let's try our backup.
			 */
			if (memcmp(faLastChallengeIssued[1],
			    mnChallenge, ADV_CHALLENGE_LENGTH) != 0) {
				/*
				 * If the visitor entry is present, then we
				 * can ALSO check whether a challenge was
				 * previously issued to the mobile node
				 * in a registration reply.
				 */
				if (acceptedFave &&
				    acceptedFave->faVisitorChallengeAdvLen) {
					if (memcmp(
					    acceptedFave->faVisitorChallengeAdv,
					    mnChallenge,
					    acceptedFave-> \
					    faVisitorChallengeAdvLen) != 0) {
					    syslog(LOG_ERR,
						"Invalid Challenge Extention");
					    faCounters.faMNAuthFailureCnt++;
					    return (FA_UNKNOWN_CHALLENGE);
					}
				} else {
					syslog(LOG_ERR,
					    "Invalid Challenge Extention");
					faCounters.faMNAuthFailureCnt++;
					return (FA_UNKNOWN_CHALLENGE);
				}
			}
		}
	}


	mipverbose(("Checking authext"));

	/*
	 * Support for the latest Challenge/Response I-D
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_GEN_AUTH_EXT(messageHdr, index,
	    GEN_AUTH_MN_AAA, mnAAAAuthExt, mnAAAAuthExtLen);

	/*
	 * If a Mobile node Foreign agent authentication extension exists
	 * check it.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_MF_AUTH_EXT_TYPE,
	    mnAuthExt, mnAuthExtLen);

	if (mnAuthExtLen) {
		GET_SPI(SPI, mnAuthExt);

		/*
		 * Remember that the node will be locked upon return.
		 * We need to unlock it when we are done...
		 */
		if ((mipSecAssocEntry =
		    findSecAssocFromSPI(SPI, LOCK_READ)) == NULL) {
			syslog(LOG_ERR, "Error: No SA for Mobile Node");
			faCounters.faMNAuthFailureCnt++;
			return (FA_MN_AUTH_FAILURE);
		}

		if (isAuthExtOk(messageHdr->pkt,
		    (messageHdr->extIdx[index] - messageHdr->pkt),
		    mipSecAssocEntry) == _B_FALSE) {
			(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
			syslog(LOG_ERR, "Failed MN-FA authentication");
			faCounters.faMNAuthFailureCnt++;
			return (FA_MN_AUTH_FAILURE);
		}

		/*
		 * ... and now we are done, let's unlock it.
		 */
		(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);

		/*
		 * Support for differing extension header formats.
		 *
		 * Remove the extension by playing with the
		 * packet's length.
		 */
		messageHdr->pktLen = (messageHdr->extIdx[index-1] -
		    messageHdr->pkt) + messageHdr->extHdrLength[index-1] +
		    messageHdr->extLength[index-1];
	} else {
		/*
		 * If we are advertising challenges, and the Mobile-AAA
		 * authentication extension is present, then the
		 * Mobile-Foreign does not need to be present. If the
		 * Mobile-AAA is NOT present, and we are configured to
		 * require Mobile-Foreign, then we will fail
		 * authentication.
		 */
		if (faChallengeAdv == _B_TRUE && mnChallengeLen &&
		    mnAAAAuthExtLen) {
			mipverbose(("Found a challenge and response\n"));

			/*
			 * First, it is necessary for us to have the NAI in
			 * order to interact with the AAA.
			 */
			if (messageHdr->mnNAI == NULL) {
				syslog(LOG_ERR,
					"MN-AAA present without an NAI");
				faCounters.faMNAuthFailureCnt++;
				return (FA_MN_AUTH_FAILURE);
			}

			/*
			 * Is AAA Enabled?
			 */
			if (aaaProtocol == AAA_NONE) {
				/* WORK  -- why is this here? (PRC?) */
				return (0);
#if 0
				syslog(LOG_ERR,
				    "Not configured to interact with AAA");
				faCounters.faMNAuthFailureCnt++;
				return (FA_MN_AUTH_FAILURE);
#endif
			}

			if (mnAAAAuthExtLen) {
				/*
				 * If the MN-AAA Authentication extension was
				 * present, retrieve the SPI value.
				 */
				GET_GEN_AUTH_SPI(aaaSPI, mnAAAAuthExt);
			}

			/*
			 * If we are using Radius only, then the SPI must be 2.
			 */
			if (aaaProtocol == RADIUS && aaaSPI != RADIUS_SPI) {
				syslog(LOG_ERR, "Failed MN-FA authentication "
				    "- wrong SPI");
				faCounters.faMNAuthFailureCnt++;
				return (FA_MN_AUTH_FAILURE);
			}

			/*
			 * Good, we've made it this far. Now let's go
			 * check with the AAA Infrastructure, if this
			 * was configured.
			 */
			/*
			 * Support for the latest Challenge response I-D
			 */
			length = ((char *)mnAAAAuthExt) -
			    ((char *)messageHdr->pkt) + sizeof (genAuthExt);

			/*
			 * If using Radius, we'd like to preserve messageHdr
			 * until we get a reply from the Radius server
			 */
			if (aaaProtocol == RADIUS)
				messageHdr->dontDeleteNow = _B_TRUE;

			result = AAAAuthenticateRegReq(messageHdr->pkt,
			    messageHdr->pktLen, messageHdr->mnNAI,
			    messageHdr->mnNAILen, aaaSPI,
			    (unsigned char *)&mnAAAAuthExt[1],
			    mnAAAAuthExtLen - sizeof (mnAAAAuthExt), length,
			    reqPtr->homeAddr, reqPtr->haAddr, _B_FALSE,
			    messageHdr->inIfindex,
			    (void *)messageHdr, mnChallenge, mnChallengeLen);

			if (result) {
				/*
				 * Now we look at the result code to determine
				 * what the error was.
				 */
				faCounters.faMNAuthFailureCnt++;
				return (FA_MN_AUTH_FAILURE);
			} else {
				/*
				 * Make sure that we notify the caller that we
				 * should not forward the request to the Home
				 * Agent since:
				 * - if diameter: it is being done via
				 *   diameter server.
				 * - if radius: we need to wait for the auth
				 *   answer.
				 */
				*forwardFlag = _B_FALSE;
			}
		} else if (mfAuthRequired) {
			syslog(LOG_ERR, "Failed MN-FA authentication - No Ext");
			faCounters.faMNAuthFailureCnt++;
			return (FA_MN_AUTH_FAILURE);
		}
	}

	return (0);
}

/*
 * Function: faCheckRegRepAuth
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		favePtr - Pointer to the Visitor Entry
 *
 * Description: This function is used to authenticate a Registration
 *		Reply. If the agent is configured to advertise
 *		challenges, we will make sure that the challenge was
 *		returned by the Home Agent, and that the challenge
 *		value is identical to the value that was used by the
 *		Mobile Node.
 *
 *		Next, if the Foreign-Home Authentication extension
 *		is present, it is authenticated. If it is present and
 *		the agent is configured to require it, we will fail
 *		authentication.
 *
 * Returns: int - 0 if successful, otherwise the Mobile-IP error code
 *		is returned.
 */
int
faCheckRegRepAuth(MessageHdr *messageHdr, FaVisitorEntry *favePtr)
{
	authExt *haAuthExt;
	MipSecAssocEntry *mipSecAssocEntry;
#ifdef KEY_DISTRIBUTION
	keyDataExt *keyData;
	uint32_t keyDataLen;
#endif /* KEY_DISTRIBUTION */
	unsigned char *challenge;
	uint32_t SPI;
	int haAuthExtLen;
	int challengeLen;
	int index;

	/*
	 * If a Challenge was received by the Mobile Node (due to our
	 * advertisement, let's make sure that the same challenge is
	 * present in the response.
	 */
	if (favePtr->faVisitorChallengeToHALen) {
		/*
		 * Retrieve the Challenge
		 */
		GET_EXT_DATA(messageHdr, index, REG_MF_CHALLENGE_EXT_TYPE,
		    challenge, challengeLen);

		if (challengeLen == 0 || challengeLen > ADV_CHALLENGE_LENGTH) {
			/*
			 * Protect against buffer overflows...
			 */
			syslog(LOG_ERR,
				"excessively large or missing Challenge");
			faCounters.faPoorlyFormedRepliesCnt++;
			/*
			 * Support for the latest Challenge/response I-D.
			 * If the challenge was expected and not present,
			 * return a missing challenge error.
			 */
			return (FA_MISSING_CHALLENGE);
		}

		if (memcmp(challenge, favePtr->faVisitorChallengeToHA,
		    challengeLen) != 0) {
			/*
			 * Protect against buffer overflows...
			 */
			syslog(LOG_ERR,
				"invalid Challenge in Registration Reply");
			faCounters.faPoorlyFormedRepliesCnt++;
			/*
			 * Support for the latest Challenge/response I-D.
			 * If the challenge was invalid, return
			 * an unknown challenge error.
			 */
			return (FA_UNKNOWN_CHALLENGE);
		}
	}

#ifdef KEY_DISTRIBUTION
	/*
	 * If KEY_DISTRIBUTION is defined (testing purpose only), we will
	 * extract the FA session keys from the registration reply.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_VEND_KEY_EXT(messageHdr, index, VENDOR_ID_SUN, REG_MN_FA_KEY_EXT,
	    keyData, keyDataLen);

	if (keyDataLen) {
		/*
		 * We have a key!!! Let's create our security assoc.
		 */
		if (createSecAssocFromKeyData(keyData, keyDataLen, &SPI) ==
		    _B_FALSE) {
			syslog(LOG_ERR,
				"unable to create dynamic MN-FA SA");
			return (HA_FA_AUTH_FAILURE);
		}
		favePtr->faVisitorSPI = SPI;
	}

	/*
	 * If KEY_DISTRIBUTION is defined (testing purpose only), we will
	 * extract the FA session keys from the registration reply.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_VEND_KEY_EXT(messageHdr, index, VENDOR_ID_SUN, REG_FA_HA_KEY_EXT,
	    keyData, keyDataLen);

	if (keyDataLen) {
		/*
		 * We have a key!!! Let's create our security assoc.
		 */
		if (createSecAssocFromKeyData(keyData, keyDataLen, &SPI) ==
		    _B_FALSE) {
			syslog(LOG_ERR,
				"unable to create dynamic FA-HA SA");
			return (HA_FA_AUTH_FAILURE);
		}
	}
#endif /* KEY_DISTRIBUTION */

	/*
	 * If a Home agent Foreign agent authentication extension exists
	 * check it.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_FH_AUTH_EXT_TYPE, haAuthExt,
	    haAuthExtLen);

	if (haAuthExtLen) {
		GET_SPI(SPI, haAuthExt);

		/*
		 * Remember that the node will be locked upon return.
		 * We need to unlock it when we are done...
		 */
		if ((mipSecAssocEntry =
		    findSecAssocFromSPI(SPI, LOCK_READ)) == NULL) {
		    syslog(LOG_ERR, "Error: No Home Agent SA (%d)", SPI);
		    faCounters.faHAAuthFailureCnt++;
		    return (HA_FA_AUTH_FAILURE);
		}

		if (isAuthExtOk(messageHdr->pkt,
		    (messageHdr->extIdx[index] - messageHdr->pkt),
		    mipSecAssocEntry) == _B_FALSE) {
			syslog(LOG_ERR, "Failed FA-HA authentication");
			faCounters.faHAAuthFailureCnt++;
			(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
			return (HA_FA_AUTH_FAILURE);
		}
		(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);

		/*
		 * Remove the extension by playing with the
		 * packet's length.
		 */
		messageHdr->pktLen = (messageHdr->extIdx[index-1] -
		    messageHdr->pkt) + messageHdr->extHdrLength[index-1] +
		    messageHdr->extLength[index-1];

		if (aaaProtocol == DIAMETER &&
		    messageHdr->pktSource == MIP_PKT_FROM_AAA) {
			/*
			 * We probably ended up getting a new SPI from the
			 * AAA Server. Update the Visitor Entry with the
			 * new SPI.
			 */
			favePtr->faVisitorSPI = messageHdr->mnFaSPI;
		}
	} else {
		if (fhAuthRequired) {
			faCounters.faHAAuthFailureCnt++;
			return (HA_FA_AUTH_FAILURE);
		}
	}


	return (0);
}


/*
 * Function: haCheckRegReqAuth
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		hamnePtr - Pointer to a pointer to a mobile node entry
 *		mnSPI - Pointer to the Mobile Node SPI
 *		faSPI - Pointe to the Foreign Agent SPI
 *
 * Description: This function is used to authenticate a Registration
 *		request on the Home Agent. First we attempt to find
 *		the Mobile Node Entry using the Home Address. If the
 *		Home Address in the request was set to zero, we will
 *		attempt to find it using the Mobile Node's NAI.
 *
 *		Next we will ensure that either the Mobile-Home or the
 *		Mobile-AAA autentication extension is present. If none
 *		is present, and the packet was marked as being received
 *		by the Foreign Agent (as opposed to the AAA), we will
 *		make sure that the unknown Mobile Node is attempting
 *		to authenticate using the default SPI. If the packet
 *		was received via the AAA infrastructure, we will
 *		not require any authentication from the Mobile Node.
 *
 *		Lastly, we will check the Foreign-Home Authentication
 *		extension. If one was not found, and the packet was
 *		not received by the AAA, we will fail authentication.
 *
 *		Note that if a Mobile Node Entry pointer is returned
 *		by this function, the node will be locked. The caller
 *		is responsible to unlock the node.
 *
 * Returns: int - 0 if successful, otherwise the Mobile-IP error code
 *		is returned.
 */
int
haCheckRegReqAuth(MessageHdr *messageHdr, HaMobileNodeEntry **hamnePtr,
    uint32_t *mnSPI, uint32_t *faSPI)
{
	regRequest *reqPtr;
	int code = 0;
	int result;
	MipSecAssocEntry *mipSecAssocEntry;
	genAuthExt *maAuthExt = NULL;
	authExt *mnAuthExt = NULL;
	authExt *faAuthExt = NULL;
	int mnAuthExtLen;
	int faAuthExtLen;
	int index;
	uint32_t SPI;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	reqPtr = (regRequest *)messageHdr->pkt;
	*hamnePtr = NULL;

#ifdef RADIUS_ENABLED
		if (radiusEnabled) {
			/*
			 * We always have to force a RADIUS lookup.
			 */
			*hamnePtr = radiusCheckUpdate(*hamnePtr,
			    &haMobileNodeHash,
			    reqPtr->homeAddr);
		}
#endif /* RADIUS_ENABLED */

	/*
	 * If a Foreign agent Home Agent authentication extension exists
	 * check it.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_FH_AUTH_EXT_TYPE, faAuthExt,
	    faAuthExtLen);

	if (faAuthExtLen) {
		GET_SPI(SPI, faAuthExt);
		*faSPI = SPI;
		/*
		 * if an SA is returned, the node will be locked so we
		 * need to unlock it when we are done.
		 */
		if ((mipSecAssocEntry =
		    findSecAssocFromSPI(SPI, LOCK_READ)) == NULL) {
			syslog(LOG_ERR,
			    "Failed FA-HA authentication - SPI (%d) "
			    "defined", SPI);
			haCounters.haFAAuthFailureCnt++;
			return (HA_FA_AUTH_FAILURE);
		}

		if (isAuthExtOk(messageHdr->pkt,
		    (messageHdr->extIdx[index] - messageHdr->pkt),
		    mipSecAssocEntry) == _B_FALSE) {
			syslog(LOG_ERR, "Failed FA-HA authentication");
			haCounters.haFAAuthFailureCnt++;
			(void) rw_unlock(
			    &mipSecAssocEntry->mipSecNodeLock);
			return (HA_FA_AUTH_FAILURE);
		}

		(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);

	} else if ((messageHdr->pktSource != MIP_PKT_FROM_AAA) &&
		    (messageHdr->pktSource != MIP_PKT_FROM_RADIUS)) {
		/*
		 * If the packet comes from the AAA, we do not need
		 * the FA-HA auth, otherwise we may be configured
		 * to require it.
		 */
			if (fhAuthRequired) {
				haCounters.haFAAuthFailureCnt++;
				return (HA_FA_AUTH_FAILURE);
			}
		} else {
			*faSPI = messageHdr->faHaSPI;
		}

	/*
	 * If a Mobile Node Home Agent authentication extension exists
	 * check it.
	 */

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_MH_AUTH_EXT_TYPE, mnAuthExt,
	    mnAuthExtLen);

	if (mnAuthExtLen) {
		GET_SPI(SPI, mnAuthExt);
		/*
		 * if an SA is returned, the node will be locked so we
		 * need to unlock it when we are done.
		 */
		if ((mipSecAssocEntry =
		    findSecAssocFromSPI(SPI, LOCK_READ)) == NULL) {
			syslog(LOG_ERR, "Failed MN-HA authentication - "
			    "No SPI defined");
			haCounters.haMNAuthFailureCnt++;
			return (HA_MN_AUTH_FAILURE);
		}
		if ((messageHdr->pktSource == MIP_PKT_FROM_AAA) ||
		    (messageHdr->pktSource == MIP_PKT_FROM_RADIUS)) {
			if (mipSecAssocEntry->mipSecIsEntryDynamic !=
			    TRUE) {
				/*
				 * So the packet came from the AAA. We
				 * need to ensure that the key being
				 * used is in fact a dynamic key.
				 * Otherwise we are leaving a security
				 * hole wide open.
				 */
				(void) rw_unlock(
				    &mipSecAssocEntry->mipSecNodeLock);
				syslog(LOG_WARNING, "A AAA Mobile "
				    "Node is attempting to use a "
				    "static key - security violation!");
				haCounters.haMNAuthFailureCnt++;
				return (HA_MN_AUTH_FAILURE);
			}
		} else if (isAuthExtOk(messageHdr->pkt,
			    (messageHdr->extIdx[index] -
			    messageHdr->pkt), mipSecAssocEntry) ==
			    _B_FALSE) {
				syslog(LOG_ERR, "Failed MN-HA "
				"authentication");
				haCounters.haMNAuthFailureCnt++;
				(void) rw_unlock(
				    &mipSecAssocEntry->mipSecNodeLock);
				return (HA_MN_AUTH_FAILURE);
		}

		(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);

	}
	if (aaaProtocol == RADIUS) {

		/*
		 * Validate MN_AAA ext exists before AAA call
		 * This way if an error we don't need
		 * to call on AAA.
		 */

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		GET_GEN_AUTH_EXT(messageHdr, index,
		    GEN_AUTH_MN_AAA, maAuthExt, mnAuthExtLen);

		if (mnAuthExtLen == 0) {
			syslog(LOG_ERR, "Missing MN AAA Ext");
			haCounters.haMNAuthFailureCnt++;
			return (HA_MN_AUTH_FAILURE);
		}
		/*
		 * Get the MN-AAA SPI
		 */
		GET_GEN_AUTH_SPI(*mnSPI, maAuthExt);

		/*
		 * Make sure SPI used is the Radius SPI (2).
		 */
		if (*mnSPI != RADIUS_SPI) {
			haCounters.haMNAuthFailureCnt++;
			return (HA_MN_AUTH_FAILURE);
		}

		/*
		 * If using Radius, we'd like to preserve messageHdr
		 * until we get a reply from the Radius server
		 */

		messageHdr->dontDeleteNow = _B_TRUE;

		result = AAAAuthenticateRegReq(messageHdr->pkt,
		    messageHdr->pktLen, messageHdr->mnNAI,
		    messageHdr->mnNAILen, *mnSPI,
		    (unsigned char *)NULL, 0, 0,
		    reqPtr->homeAddr, reqPtr->haAddr, _B_TRUE,
		    0, (void *)messageHdr, NULL, 0);

		if (result) {
			/*
			 * Now we look at the result code to determine
			 * what the error was.
			 */
			haCounters.haMNAuthFailureCnt++;
			return (HA_MN_AUTH_FAILURE);
		}

	}

	/*
	 * If talking to RADIUS client, you must wait for a reponse
	 * back (from AAAAuthenticateRegReq() call) before
	 * continuing on with haCheckRegReqAuthContinue().
	 * As such, wait until RADIUS responds then continue on
	 * with authentication process.
	 */

	if (aaaProtocol != RADIUS) {
		code = haCheckRegReqAuthContinue(messageHdr, hamnePtr,
		    mnSPI, faSPI);
		return (code);
	}
	return (0);
}

/*
 * Function: haCheckRegReqAuthContinue
 *
 * Arguments:	messageHdr - Pointer to the Message Control Block
 *		hamnePtr - Pointer to a pointer to a mobile node entry
 *		mnSPI - Pointer to the Mobile Node SPI
 *		faSPI - Pointe to the Foreign Agent SPI
 *
 * Description: This function is used to authenticate a Registration
 *		request on the Home Agent. First we attempt to find
 *		the Mobile Node Entry using the Home Address. If the
 *		Home Address in the request was set to zero, we will
 *		attempt to find it using the Mobile Node's NAI.
 *
 *              if aaaProtocol is RADIUS, this funtion will be called after
 *              an ANSWER is received from the Radius client.
 *              Otherwise, the processing will continue from
 *              haCheckRegReqAuth() function.
 *
 *		Next we will ensure that either the Mobile-Home or the
 *		Mobile-AAA autentication extension is present. If none
 *		is present, and the packet was marked as being received
 *		by the Foreign Agent (as opposed to the AAA), we will
 *		make sure that the unknown Mobile Node is attempting
 *		to authenticate using the default SPI. If the packet
 *		was received via the AAA infrastructure, we will
 *		not require any authentication from the Mobile Node.
 *
 *		Lastly, we will check the Foreign-Home Authentication
 *		extension. If one was not found, and the packet was
 *		not received by the AAA, we will fail authentication.
 *
 *		Note that if a Mobile Node Entry pointer is returned
 *		by this function, the node will be locked. The caller
 *		is responsible to unlock the node.
 *
 * Returns: int - 0 if successful, otherwise the Mobile-IP error code
 *		is returned.
 */
/* ARGSUSED */
int
haCheckRegReqAuthContinue(MessageHdr *messageHdr, HaMobileNodeEntry **hamnePtr,
    uint32_t *mnSPI, uint32_t *faSPI)
{
	regRequest *reqPtr;
	authExt *mnAuthExt = NULL;
	genAuthExt *maAuthExt = NULL;
	MipSecAssocEntry *mipSecAssocEntry;
	uint32_t SPI;
	int index;
	int mnAuthExtLen;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	reqPtr = (regRequest *)messageHdr->pkt;

	if (reqPtr->homeAddr) {
		/*
		 * Find the Mobile Node. Remember that this node will
		 * be locked upon return. As it turns out, the caller
		 * to this function will have to unlock the node since
		 * we are passing it the pointer as part of an argument.
		 */
		*hamnePtr = findHashTableEntryUint(&haMobileNodeHash,
		    reqPtr->homeAddr, LOCK_WRITE, NULL, 0, 0, 0);
	}

	if (*hamnePtr == NULL) {
		/*
		 * Search for the MobileNodeEntry based on the
		 * NAI.
		 */

		*hamnePtr = findHashTableEntryString(&haMobileNodeHash,
		    messageHdr->mnNAI, messageHdr->mnNAILen, LOCK_WRITE,
		    NULL, 0, 0, 0);
	}


	/* LINTED E_BAD_PTR_CAST_ALIGN */
	GET_AUTH_EXT(messageHdr, index, REG_MH_AUTH_EXT_TYPE, mnAuthExt,
	    mnAuthExtLen);

	/*
	 * If aaaProtocol != RADIUS/DIAMETER, then the home agent CAN
	 * accept Mobile-AAA Authentication extensions, so if we cannot
	 * find the Authentication Extension, find the MN-AAA.
	 *
	 * Happy Dave?
	 */
	if ((mnAuthExtLen == 0) && (aaaProtocol == AAA_NONE)) {
		/*
		 * Support for the latest Challenge/Response I-D
		 *
		 * This code does not belong in the HA, this is
		 * really targetted to the AAA Server. We will
		 * include it to fully support the protocol.
		 */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		GET_GEN_AUTH_EXT(messageHdr, index,
		    GEN_AUTH_MN_AAA, maAuthExt, mnAuthExtLen);

		if (mnAuthExtLen == 0) {
			syslog(LOG_ERR, "Missing Challenge or Response");
			haCounters.haMNAuthFailureCnt++;
			return (HA_MN_AUTH_FAILURE);
		}
		/*
		 * Get the MN-AAA SPI
		 */
		GET_GEN_AUTH_SPI(SPI, maAuthExt);
#ifdef KEY_DISTRIBUTION
		/*
		 * If this code is compiled, the Home Agent will provide AAA
		 * like functionality by creating Session Keys for:
		 *	MN-HA
		 *	MN-FA
		 *	FA-HA
		 * The last one is normally not seen by the Home Agent when
		 * keys are received from DIAMETER, but since we are providing
		 * this functionality (mostly for testing purposes) we will
		 * send it to the Foreign Agent as a vendor specific extension.
		 */
		createSessionKey(messageHdr->mnHaKey, &messageHdr->mnHaKeyLen,
		    &messageHdr->mnHaSPI);

		createSessionKey(messageHdr->mnFaKey, &messageHdr->mnFaKeyLen,
		    &messageHdr->mnFaSPI);

		createSessionKey(messageHdr->faHaKey, &messageHdr->faHaKeyLen,
		    &messageHdr->faHaSPI);

		messageHdr->kdcKeysPresent = _B_TRUE;
		messageHdr->mnAAASPI = SPI;
#endif /* KEY_DISTRIBUTION */
	} else if (mnAuthExt) {
		/*
		 * Get the MN-HA SPI
		 */
		GET_SPI(SPI, mnAuthExt);
	} else {
		SPI = 0;
	}

	if (*hamnePtr == NULL) {
		/*
		 * So we have a couple of options here. The first being
		 * where the packet is received by the AAA. In this
		 * case, the Mobile Node will not exist locally, and the
		 * key would have been installed as a dynamic key.
		 * The second option is where the default node is being
		 * used. When this occurs, it is mandatory that the
		 * mobile node use the default SPI.
		 */
		if (messageHdr->pktSource == MIP_PKT_FROM_FA) {
			/*
			 * So, it looks like we don't know who this is. If a
			 * default SA is setup, we will check if we can
			 * create a dynamic Mobile Node Entry.
			 */
			if (defaultNodeSPI == 0 || defaultNodeSPI != SPI) {
				syslog(LOG_ERR,
				    "As far as I'm concerned, this "
				    "mobile node doesn't exist");
				return (HA_ADM_PROHIBITED);
			}
		} else {
			SPI = messageHdr->mnHaSPI;
		}
	} else {
		if ((messageHdr->pktSource == MIP_PKT_FROM_AAA) ||
		    (messageHdr->pktSource == MIP_PKT_FROM_RADIUS)) {
			SPI = messageHdr->mnHaSPI;
			(*hamnePtr)->haMnSPI = SPI;
		} else {
			/*
			 * Did the Mobile Node specify the correct SPI?
			 */
			if ((*hamnePtr)->haMnSPI != SPI) {
				syslog(LOG_ERR, "Failed MN-HA authentication - "
				    "Invalid SPI requested %d, looking for %d",
				    SPI, (*hamnePtr)->haMnSPI);
				haCounters.haMNAuthFailureCnt++;
				return (HA_MN_AUTH_FAILURE);
			}
		}
	}
	*mnSPI = SPI;

	/*
	 * if an SA is returned, the node will be locked so we
	 * need to unlock it when we are done.
	 */
	if ((mipSecAssocEntry =
	    findSecAssocFromSPI(SPI, LOCK_READ)) == NULL) {
		syslog(LOG_ERR, "Failed MN-HA authentication - "
		    "No SPI defined");
		haCounters.haMNAuthFailureCnt++;
		return (HA_MN_AUTH_FAILURE);
	}
	if ((messageHdr->pktSource == MIP_PKT_FROM_AAA) ||
	    (messageHdr->pktSource == MIP_PKT_FROM_RADIUS)) {
		if (mipSecAssocEntry->mipSecIsEntryDynamic != TRUE) {
			/*
			 * So the packet came from the  AAA. We need to
			 * ensure that the key being used is in fact a
			 * dynamic key. Otherwise we are leaving a security
			 * hole wide open.
			 */
			(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
			syslog(LOG_WARNING, "A AAA Mobile Node is attempting"
			    " to use a static key - security violation!");
			haCounters.haMNAuthFailureCnt++;
			return (HA_MN_AUTH_FAILURE);
		}
	} else if (isAuthExtOk(messageHdr->pkt,
		    (messageHdr->extIdx[index] - messageHdr->pkt),
		    mipSecAssocEntry) == _B_FALSE) {
			syslog(LOG_ERR, "Failed MN-HA authentication");
			haCounters.haMNAuthFailureCnt++;
			(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);
			return (HA_MN_AUTH_FAILURE);
	}

	(void) rw_unlock(&mipSecAssocEntry->mipSecNodeLock);

	return (0);
}
