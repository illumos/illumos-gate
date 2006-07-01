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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * FIXME: If this is true we have some problems. draft 15!?
 *
 * This file implements the iSCSI CHAP authentication method based on
 * draft-ietf-ips-iscsi-15.txt.  The code in this file is meant
 * to be platform independent, and makes use of only limited library
 * functions, presently only string.h.  Platform dependent routines
 * are  defined in iscsi_authclient.h, but implemented in another file.
 *
 * This code in this files assumes a single thread of execution
 * for each IscsiAuthClient structure, and does no locking.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL

#include "iscsi.h"

#else

#include <strings.h>
#ifndef TRUE
#define	TRUE 1
#endif

#ifndef FALSE
#define	FALSE 0
#endif

#endif

#include <sys/iscsi_authclient.h>

struct iscsiAuthKeyInfo_t {
	const char *name;
};
typedef struct iscsiAuthKeyInfo_t IscsiAuthKeyInfo;


IscsiAuthClientGlobalStats iscsiAuthClientGlobalStats;

/*
 * Note: The ordering of this table must match the order
 *       defined by IscsiAuthKeyType in iscsiAuthClient.h.
 */
static IscsiAuthKeyInfo iscsiAuthClientKeyInfo[iscsiAuthKeyTypeMaxCount] = {
	{"AuthMethod"},
	{"CHAP_A"},
	{"CHAP_N"},
	{"CHAP_R"},
	{"CHAP_I"},
	{"CHAP_C"}
};

static const char iscsiAuthClientHexString[] = "0123456789abcdefABCDEF";
static const char iscsiAuthClientBase64String[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char iscsiAuthClientAuthMethodChapOptionName[] = "CHAP";


static int
iscsiAuthClientCheckString(const char *s,
    unsigned int maxLength, unsigned int *pOutLength)
{
	unsigned int length;

	if (!s) {
		return (TRUE);
	}

	for (length = 0; length < maxLength; length++) {
		if (*s++ == '\0') {
			if (pOutLength) {
				*pOutLength = length;
			}
			return (FALSE);
		}
	}

	return (TRUE);
}


static int
iscsiAuthClientStringCopy(char *stringOut, const char *stringIn,
    unsigned int length)
{
	if (!stringOut || !stringIn || length == 0) {
		return (TRUE);
	}

	while ((*stringOut++ = *stringIn++) != '\0') {
		if (--length == 0) {
			stringOut--;
			*stringOut = '\0';
			return (TRUE);
		}
	}

	return (FALSE);
}


static int
iscsiAuthClientStringAppend(char *stringOut, const char *stringIn,
    unsigned int length)
{
	if (!stringOut || !stringIn || length == 0) {
		return (TRUE);
	}

	while (*stringOut++ != '\0') {
		if (--length == 0) {
			stringOut--;
			*stringOut = '\0';
			return (TRUE);
		}
	}

	stringOut--;

	while ((*stringOut++ = *stringIn++) != '\0') {
		if (--length == 0) {
			stringOut--;
			*stringOut = '\0';
			return (TRUE);
		}
	}

	return (FALSE);
}


static int
iscsiAuthClientStringIndex(const char *s, int c)
{
	int n = 0;

	while (*s != '\0') {
		if (*s++ == c) {
			return (n);
		}
		n++;
	}

	return (-1);
}


static int
iscsiAuthClientCheckNodeType(int nodeType)
{
	if (nodeType == iscsiAuthNodeTypeInitiator ||
	    nodeType == iscsiAuthNodeTypeTarget) {
		return (FALSE);
	}

	return (TRUE);
}


static int
iscsiAuthClientCheckVersion(int value)
{
	if (value == iscsiAuthVersionDraft8 || value == iscsiAuthVersionRfc) {

		return (FALSE);
	}

	return (TRUE);
}

static int
iscsiAuthClientCheckAuthMethodOption(int value)
{
	if (value == iscsiAuthOptionNone || value == iscsiAuthMethodChap) {

		return (FALSE);
	}

	return (TRUE);
}


static const char *
iscsiAuthClientAuthMethodOptionToText(IscsiAuthClient * client, int value)
{
	const char *s;

	switch (value) {
	case iscsiAuthOptionReject:
		s = client->rejectOptionName;
		break;

	case iscsiAuthOptionNone:
		s = client->noneOptionName;
		break;

	case iscsiAuthMethodChap:
		s = iscsiAuthClientAuthMethodChapOptionName;
		break;

	default:
		s = 0;
	}

	return (s);
}


static int
iscsiAuthClientCheckChapAlgorithmOption(int chapAlgorithm)
{
	if (chapAlgorithm == iscsiAuthOptionNone ||
	    chapAlgorithm == iscsiAuthChapAlgorithmMd5) {
		return (FALSE);
	}

	return (TRUE);
}


static int
iscsiAuthClientDataToHex(unsigned char *data, unsigned int dataLength,
    char *text, unsigned int textLength)
{
	unsigned long n;

	if (!text || textLength == 0) {
		return (TRUE);
	}

	if (!data || dataLength == 0) {
		*text = '\0';
		return (TRUE);
	}

	if (textLength < 3) {
		*text = '\0';
		return (TRUE);
	}

	*text++ = '0';
	*text++ = 'x';

	textLength -= 2;

	while (dataLength > 0) {

		if (textLength < 3) {
			*text = '\0';
			return (TRUE);
		}

		n = *data++;
		dataLength--;

		*text++ = iscsiAuthClientHexString[(n >> 4) & 0xf];
		*text++ = iscsiAuthClientHexString[n & 0xf];

		textLength -= 2;
	}

	*text = '\0';

	return (FALSE);
}


static int
iscsiAuthClientDataToBase64(unsigned char *data, unsigned int dataLength,
    char *text, unsigned int textLength)
{
	unsigned long n;

	if (!text || textLength == 0) {
		return (TRUE);
	}

	if (!data || dataLength == 0) {
		*text = '\0';
		return (TRUE);
	}

	if (textLength < 3) {
		*text = '\0';
		return (TRUE);
	}

	*text++ = '0';
	*text++ = 'b';

	textLength -= 2;

	while (dataLength >= 3) {

		if (textLength < 5) {
			*text = '\0';
			return (TRUE);
		}

		n = *data++;
		n = (n << 8) | *data++;
		n = (n << 8) | *data++;
		dataLength -= 3;

		*text++ = iscsiAuthClientBase64String[(n >> 18) & 0x3f];
		*text++ = iscsiAuthClientBase64String[(n >> 12) & 0x3f];
		*text++ = iscsiAuthClientBase64String[(n >> 6) & 0x3f];
		*text++ = iscsiAuthClientBase64String[n & 0x3f];

		textLength -= 4;
	}

	if (dataLength == 1) {

		if (textLength < 5) {
			*text = '\0';
			return (TRUE);
		}

		n = *data++;
		n = n << 4;

		*text++ = iscsiAuthClientBase64String[(n >> 6) & 0x3f];
		*text++ = iscsiAuthClientBase64String[n & 0x3f];
		*text++ = '=';
		*text++ = '=';

	} else if (dataLength == 2) {

		if (textLength < 5) {
			return (TRUE);
		}

		n = *data++;
		n = (n << 8) | *data++;
		n = n << 2;

		*text++ = iscsiAuthClientBase64String[(n >> 12) & 0x3f];
		*text++ = iscsiAuthClientBase64String[(n >> 6) & 0x3f];
		*text++ = iscsiAuthClientBase64String[n & 0x3f];
		*text++ = '=';
	}

	*text = '\0';

	return (FALSE);
}


static int
iscsiAuthClientDataToText(int base64, unsigned char *data,
    unsigned int dataLength, char *text, unsigned int textLength)
{
	int status;

	if (base64) {
		status = iscsiAuthClientDataToBase64(
		    data, dataLength, text, textLength);
	} else {
		status = iscsiAuthClientDataToHex(
		    data, dataLength, text, textLength);
	}

	return (status);
}


static int
iscsiAuthClientHexToData(const char *text, unsigned int textLength,
    unsigned char *data, unsigned int *pDataLength)
{
	int i;
	unsigned int n1;
	unsigned int n2;
	unsigned int dataLength = *pDataLength;

	if ((textLength % 2) == 1) {
		i = iscsiAuthClientStringIndex(iscsiAuthClientHexString,
		    *text++);
		if (i < 0) {
			return (TRUE);	/* error, bad character */
		}

		if (i > 15)
			i -= 6;
		n2 = i;

		if (dataLength < 1) {
			return (TRUE);	/* error, too much data */
		}

		*data++ = n2;
		dataLength--;
	}

	while (*text != '\0') {

		i = iscsiAuthClientStringIndex(
		    iscsiAuthClientHexString, *text++);
		if (i < 0) {
			return (TRUE);	/* error, bad character */
		}

		if (i > 15)
			i -= 6;
		n1 = i;

		if (*text == '\0') {
			return (TRUE);	/* error, odd string length */
		}

		i = iscsiAuthClientStringIndex(
		    iscsiAuthClientHexString, *text++);
		if (i < 0) {
			return (TRUE);	/* error, bad character */
		}

		if (i > 15)
			i -= 6;
		n2 = i;

		if (dataLength < 1) {
			return (TRUE);	/* error, too much data */
		}

		*data++ = (n1 << 4) | n2;
		dataLength--;
	}

	if (dataLength >= *pDataLength) {
		return (TRUE);	/* error, no data */
	}

	*pDataLength = *pDataLength - dataLength;

	return (FALSE);		/* no error */
}


static int
iscsiAuthClientBase64ToData(const char *text, unsigned int textLength,
    unsigned char *data, unsigned int *pDataLength)
{
	int i;
	unsigned int n;
	unsigned int count;
	unsigned int dataLength = *pDataLength;

	textLength = textLength;	/* not used */

	n = 0;
	count = 0;

	while (*text != '\0' && *text != '=') {

		i = iscsiAuthClientStringIndex(
		    iscsiAuthClientBase64String, *text++);
		if (i < 0) {
			return (TRUE);	/* error, bad character */
		}

		n = (n << 6 | (unsigned int)i);
		count++;

		if (count >= 4) {
			if (dataLength < 3) {
				return (TRUE);	/* error, too much data */
			}
			*data++ = n >> 16;
			*data++ = n >> 8;
			*data++ = n;
			dataLength -= 3;
			n = 0;
			count = 0;
		}
	}

	while (*text != '\0') {
		if (*text++ != '=') {
			return (TRUE);	/* error, bad pad */
		}
	}

	if (count == 0) {
		/*
		 * do nothing
		 */
		/* EMPTY */
	} else if (count == 2) {
		if (dataLength < 1) {
			return (TRUE);	/* error, too much data */
		}
		n = n >> 4;
		*data++ = n;
		dataLength--;
	} else if (count == 3) {
		if (dataLength < 2) {
			return (TRUE);	/* error, too much data */
		}
		n = n >> 2;
		*data++ = n >> 8;
		*data++ = n;
		dataLength -= 2;
	} else {
		return (TRUE);	/* bad encoding */
	}

	if (dataLength >= *pDataLength) {
		return (TRUE);	/* error, no data */
	}

	*pDataLength = *pDataLength - dataLength;

	return (FALSE);		/* no error */
}


static int
iscsiAuthClientTextToData(const char *text, unsigned char *data,
    unsigned int *dataLength)
{
	int status;
	unsigned int textLength;

	status = iscsiAuthClientCheckString(text,
	    2 + 2 * iscsiAuthLargeBinaryMaxLength + 1, &textLength);

	if (status) {
		return (status);
	}

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
		/*
		 * skip prefix
		 */
		text += 2;
		textLength -= 2;
		status = iscsiAuthClientHexToData(text,
		    textLength, data, dataLength);
	} else if (text[0] == '0' && (text[1] == 'b' || text[1] == 'B')) {
		/*
		 * skip prefix
		 */
		text += 2;
		textLength -= 2;
		status = iscsiAuthClientBase64ToData(text,
		    textLength, data, dataLength);
	} else {
		status = TRUE;	/* prefix not recognized. */
	}

	return (status);
}


static IscsiAuthDebugStatus
iscsiAuthClientChapComputeResponse(IscsiAuthClient * client,
    int remoteAuthentication, unsigned int id,
    unsigned char *challengeData, unsigned int challengeLength,
    unsigned char *responseData)
{
	unsigned char idData[1];
	IscsiAuthMd5Context context;
	unsigned char outData[iscsiAuthStringMaxLength];
	unsigned int outLength = iscsiAuthStringMaxLength;

	if (!client->passwordPresent) {
		return (iscsiAuthDebugStatusLocalPasswordNotSet);
	}

	iscsiAuthMd5Init(&context);

	/*
	 * id byte
	 */
	idData[0] = id;
	iscsiAuthMd5Update(&context, idData, 1);

	/*
	 * decrypt password
	 */
	if (iscsiAuthClientData(outData, &outLength,
		client->passwordData, client->passwordLength)) {

		return (iscsiAuthDebugStatusPasswordDecryptFailed);
	}

	if (!remoteAuthentication && !client->ipSec && outLength < 12) {
		return (iscsiAuthDebugStatusPasswordTooShortWithNoIpSec);
	}

	/*
	 * shared secret
	 */
	iscsiAuthMd5Update(&context, outData, outLength);

	/*
	 * clear decrypted password
	 */
	bzero(outData, iscsiAuthStringMaxLength);

	/*
	 * challenge value
	 */
	iscsiAuthMd5Update(&context, challengeData, challengeLength);

	iscsiAuthMd5Final(responseData, &context);

	return (iscsiAuthDebugStatusNotSet);	/* no error */
}


static void
iscsiAuthClientInitKeyBlock(IscsiAuthKeyBlock * keyBlock)
{
	char *stringBlock = keyBlock->stringBlock;

	bzero(keyBlock, sizeof (*keyBlock));
	keyBlock->stringBlock = stringBlock;
}


static void
iscsiAuthClientSetKeyValue(IscsiAuthKeyBlock * keyBlock,
    int keyType, const char *keyValue)
{
	unsigned int length;
	char *string;

	if (keyBlock->key[keyType].valueSet) {
		keyBlock->duplicateSet = TRUE;
		return;
	}

	keyBlock->key[keyType].valueSet = TRUE;

	if (!keyValue) {
		return;
	}

	if (iscsiAuthClientCheckString(keyValue,
	    iscsiAuthStringMaxLength, &length)) {
		keyBlock->stringTooLong = TRUE;
		return;
	}

	length += 1;

	if ((keyBlock->blockLength + length) > iscsiAuthStringBlockMaxLength) {
		keyBlock->tooMuchData = TRUE;
		return;
	}

	string = &keyBlock->stringBlock[keyBlock->blockLength];

	if (iscsiAuthClientStringCopy(string, keyValue, length)) {
		keyBlock->tooMuchData = TRUE;
		return;
	}
	keyBlock->blockLength += length;

	keyBlock->key[keyType].string = string;
	keyBlock->key[keyType].present = TRUE;
}


static const char *
iscsiAuthClientGetKeyValue(IscsiAuthKeyBlock * keyBlock, int keyType)
{
	keyBlock->key[keyType].processed = TRUE;

	if (!keyBlock->key[keyType].present) {
		return (0);
	}

	return (keyBlock->key[keyType].string);
}


static void
iscsiAuthClientCheckKey(IscsiAuthClient * client,
    int keyType,
    int *negotiatedOption,
    unsigned int optionCount,
    int *optionList, const char *(*valueToText) (IscsiAuthClient *, int))
{
	const char *keyValue;
	int length;
	unsigned int i;

	keyValue = iscsiAuthClientGetKeyValue(&client->recvKeyBlock, keyType);
	if (!keyValue) {
		*negotiatedOption = iscsiAuthOptionNotPresent;
		return;
	}

	while (*keyValue != '\0') {

		length = 0;

		while (*keyValue != '\0' && *keyValue != ',') {
			client->scratchKeyValue[length++] = *keyValue++;
		}

		if (*keyValue == ',')
			keyValue++;
		client->scratchKeyValue[length++] = '\0';

		for (i = 0; i < optionCount; i++) {
			const char *s = (*valueToText) (client, optionList[i]);

			if (!s)
				continue;

			if (strcmp(client->scratchKeyValue, s) == 0) {
				*negotiatedOption = optionList[i];
				return;
			}
		}
	}

	*negotiatedOption = iscsiAuthOptionReject;
}


static void
iscsiAuthClientSetKey(IscsiAuthClient * client,
    int keyType,
    unsigned int optionCount,
    int *optionList, const char *(*valueToText) (IscsiAuthClient *, int))
{
	unsigned int i;

	if (optionCount == 0) {
		/*
		 * No valid options to send, but we always want to
		 * send something.
		 */
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock, keyType,
		    client->noneOptionName);
		return;
	}

	if (optionCount == 1 && optionList[0] == iscsiAuthOptionNotPresent) {
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock, keyType, 0);
		return;
	}

	for (i = 0; i < optionCount; i++) {
		const char *s = (*valueToText) (client, optionList[i]);

		if (!s)
			continue;

		if (i == 0) {
		    (void) iscsiAuthClientStringCopy(client->scratchKeyValue,
			    s, iscsiAuthStringMaxLength);
		} else {
		    (void) iscsiAuthClientStringAppend(client->scratchKeyValue,
			    ",", iscsiAuthStringMaxLength);
		    (void) iscsiAuthClientStringAppend(client->scratchKeyValue,
			    s, iscsiAuthStringMaxLength);
		}
	}

	iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
	    keyType, client->scratchKeyValue);
}


static void
iscsiAuthClientCheckAuthMethodKey(IscsiAuthClient * client)
{
	iscsiAuthClientCheckKey(client,
	    iscsiAuthKeyTypeAuthMethod,
	    &client->negotiatedAuthMethod,
	    client->authMethodValidCount,
	    client->authMethodValidList, iscsiAuthClientAuthMethodOptionToText);
}


static void
iscsiAuthClientSetAuthMethodKey(IscsiAuthClient * client,
    unsigned int authMethodCount, int *authMethodList)
{
	iscsiAuthClientSetKey(client, iscsiAuthKeyTypeAuthMethod,
	    authMethodCount, authMethodList,
	    iscsiAuthClientAuthMethodOptionToText);
}


static void
iscsiAuthClientCheckChapAlgorithmKey(IscsiAuthClient * client)
{
	const char *keyValue;
	int length;
	unsigned long number;
	unsigned int i;

	keyValue = iscsiAuthClientGetKeyValue(&client->recvKeyBlock,
	    iscsiAuthKeyTypeChapAlgorithm);
	if (!keyValue) {
		client->negotiatedChapAlgorithm = iscsiAuthOptionNotPresent;
		return;
	}

	while (*keyValue != '\0') {
		length = 0;

		while (*keyValue != '\0' && *keyValue != ',') {
			client->scratchKeyValue[length++] = *keyValue++;
		}

		if (*keyValue == ',')
			keyValue++;
		client->scratchKeyValue[length++] = '\0';

		if (iscsiAuthClientTextToNumber(client->scratchKeyValue,
		    &number)) {
			continue;
		}

		for (i = 0; i < client->chapAlgorithmCount; i++) {

			if (number == (unsigned long)client->
			    chapAlgorithmList[i]) {
				client->negotiatedChapAlgorithm = number;
				return;
			}
		}
	}

	client->negotiatedChapAlgorithm = iscsiAuthOptionReject;
}


static void
iscsiAuthClientSetChapAlgorithmKey(IscsiAuthClient * client,
    unsigned int chapAlgorithmCount, int *chapAlgorithmList)
{
	unsigned int i;

	if (chapAlgorithmCount == 0) {
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapAlgorithm, 0);
		return;
	}

	if (chapAlgorithmCount == 1 &&
	    chapAlgorithmList[0] == iscsiAuthOptionNotPresent) {
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapAlgorithm, 0);
		return;
	}

	if (chapAlgorithmCount == 1 &&
	    chapAlgorithmList[0] == iscsiAuthOptionReject) {
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapAlgorithm, client->rejectOptionName);
		return;
	}

	for (i = 0; i < chapAlgorithmCount; i++) {
		char s[20];

		iscsiAuthClientNumberToText(chapAlgorithmList[i],
		    s, sizeof (s));

		if (i == 0) {
		    (void) iscsiAuthClientStringCopy(client->scratchKeyValue, s,
			    iscsiAuthStringMaxLength);
		} else {
		    (void) iscsiAuthClientStringAppend(client->scratchKeyValue,
			    ",", iscsiAuthStringMaxLength);
		    (void) iscsiAuthClientStringAppend(client->scratchKeyValue,
			    s, iscsiAuthStringMaxLength);
		}
	}

	iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
	    iscsiAuthKeyTypeChapAlgorithm, client->scratchKeyValue);
}


static void
iscsiAuthClientNextPhase(IscsiAuthClient * client)
{
	switch (client->phase) {
	case iscsiAuthPhaseConfigure:
		client->phase = iscsiAuthPhaseNegotiate;
		break;

	case iscsiAuthPhaseNegotiate:
		client->phase = iscsiAuthPhaseAuthenticate;

		if (client->negotiatedAuthMethod ==
		    iscsiAuthOptionReject ||
		    client->negotiatedAuthMethod ==
		    iscsiAuthOptionNotPresent ||
		    client->negotiatedAuthMethod == iscsiAuthOptionNone) {

			client->localState = iscsiAuthLocalStateDone;
			client->remoteState = iscsiAuthRemoteStateDone;

			if (client->authRemote) {
				client->remoteAuthStatus = iscsiAuthStatusFail;
				client->phase = iscsiAuthPhaseDone;
			} else {
				client->remoteAuthStatus = iscsiAuthStatusPass;
			}

			switch (client->negotiatedAuthMethod) {
			case iscsiAuthOptionReject:
				client->debugStatus =
				    iscsiAuthDebugStatusAuthMethodReject;
				break;

			case iscsiAuthOptionNotPresent:
				client->debugStatus =
				    iscsiAuthDebugStatusAuthMethodNotPresent;
				break;

			case iscsiAuthOptionNone:
				client->debugStatus =
				    iscsiAuthDebugStatusAuthMethodNone;
			}

		} else if (client->negotiatedAuthMethod ==
		    iscsiAuthMethodChap) {
			client->localState = iscsiAuthLocalStateSendAlgorithm;
			client->remoteState = iscsiAuthRemoteStateSendAlgorithm;
		} else {
			client->localState = iscsiAuthLocalStateDone;
			client->remoteState = iscsiAuthRemoteStateDone;
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->debugStatus = iscsiAuthDebugStatusAuthMethodBad;
		}

		break;

	case iscsiAuthPhaseAuthenticate:
		client->phase = iscsiAuthPhaseDone;
		break;

	case iscsiAuthPhaseDone:
	case iscsiAuthPhaseError:
	default:
		client->phase = iscsiAuthPhaseError;
	}
}


static void
iscsiAuthClientLocalAuthentication(IscsiAuthClient * client)
{
	unsigned int chapIdentifier;
	unsigned char responseData[iscsiAuthChapResponseLength];
	unsigned long number;
	int status;
	IscsiAuthDebugStatus debugStatus;
	const char *chapIdentifierKeyValue;
	const char *chapChallengeKeyValue;

	switch (client->localState) {
	case iscsiAuthLocalStateSendAlgorithm:
		if (client->nodeType == iscsiAuthNodeTypeInitiator) {
			iscsiAuthClientSetChapAlgorithmKey(
			    client, client->chapAlgorithmCount,
			    client->chapAlgorithmList);
			client->localState = iscsiAuthLocalStateRecvAlgorithm;
			break;
		}

		/* FALLTHRU */

	case iscsiAuthLocalStateRecvAlgorithm:
		iscsiAuthClientCheckChapAlgorithmKey(client);

		if (client->nodeType == iscsiAuthNodeTypeTarget) {

			iscsiAuthClientSetChapAlgorithmKey(client, 1,
			    &client->negotiatedChapAlgorithm);
		}

		/*
		 * Make sure only supported CHAP algorithm is used.
		 */
		if (client->negotiatedChapAlgorithm ==
		    iscsiAuthOptionNotPresent) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapAlgorithmExpected;
			break;

		} else if (client->negotiatedChapAlgorithm ==
		    iscsiAuthOptionReject) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapAlgorithmReject;
			break;

		} else if (client->negotiatedChapAlgorithm !=
		    iscsiAuthChapAlgorithmMd5) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapAlgorithmBad;
			break;
		}

		if (client->nodeType == iscsiAuthNodeTypeTarget) {

			client->localState = iscsiAuthLocalStateRecvChallenge;
			break;
		}

		/* FALLTHRU */

	case iscsiAuthLocalStateRecvChallenge:
		chapIdentifierKeyValue = iscsiAuthClientGetKeyValue(
		    &client->recvKeyBlock, iscsiAuthKeyTypeChapIdentifier);
		chapChallengeKeyValue = iscsiAuthClientGetKeyValue(
		    &client->recvKeyBlock, iscsiAuthKeyTypeChapChallenge);

		if (client->nodeType == iscsiAuthNodeTypeTarget) {
			if (!chapIdentifierKeyValue && !chapChallengeKeyValue) {
				client->localState = iscsiAuthLocalStateDone;
				break;
			}
		}

		if (!chapIdentifierKeyValue) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapIdentifierExpected;
			break;
		}

		if (!chapChallengeKeyValue) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapChallengeExpected;
			break;
		}

		status = iscsiAuthClientTextToNumber(
		    chapIdentifierKeyValue, &number);

		if (status || (255 < number)) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapIdentifierBad;
			break;
		}
		chapIdentifier = number;

		if (client->recvChapChallengeStatus) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapChallengeBad;
			break;
		}

		if (client->nodeType == iscsiAuthNodeTypeTarget &&
		    client->recvChapChallenge.length ==
		    client->sendChapChallenge.length &&
		    bcmp(client->recvChapChallenge.largeBinary,
			client->sendChapChallenge.largeBinary,
			client->sendChapChallenge.length) == 0) {

			client->localState = iscsiAuthLocalStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapChallengeReflected;
			break;
		}

		debugStatus = iscsiAuthClientChapComputeResponse(client,
		    FALSE,
		    chapIdentifier,
		    client->recvChapChallenge.largeBinary,
		    client->recvChapChallenge.length, responseData);

		if (debugStatus != iscsiAuthDebugStatusNotSet) {
			client->localState = iscsiAuthLocalStateError;
			client->debugStatus = debugStatus;
			break;
		}

		(void) iscsiAuthClientDataToText(client->base64,
		    responseData, iscsiAuthChapResponseLength,
		    client->scratchKeyValue, iscsiAuthStringMaxLength);
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapResponse, client->scratchKeyValue);

		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapUsername, client->username);

		client->localState = iscsiAuthLocalStateDone;
		break;

	case iscsiAuthLocalStateDone:
		break;

	case iscsiAuthLocalStateError:
	default:
		client->phase = iscsiAuthPhaseError;
	}
}


static void
iscsiAuthClientRemoteAuthentication(IscsiAuthClient * client)
{
	unsigned char idData[1];
	unsigned char responseData[iscsiAuthStringMaxLength];
	unsigned int responseLength = iscsiAuthStringMaxLength;
	unsigned char myResponseData[iscsiAuthChapResponseLength];
	int status;
	IscsiAuthDebugStatus debugStatus;
	const char *chapResponseKeyValue;
	const char *chapUsernameKeyValue;

	switch (client->remoteState) {
	case iscsiAuthRemoteStateSendAlgorithm:
		if (client->nodeType == iscsiAuthNodeTypeInitiator) {
			client->remoteState = iscsiAuthRemoteStateSendChallenge;
			break;
		}

		/* FALLTHRU */

	case iscsiAuthRemoteStateSendChallenge:
		if (!client->authRemote) {
			client->remoteAuthStatus = iscsiAuthStatusPass;
			client->debugStatus =
			    iscsiAuthDebugStatusAuthRemoteFalse;
			client->remoteState = iscsiAuthRemoteStateDone;
			break;
		}

		iscsiAuthRandomSetData(idData, 1);
		client->sendChapIdentifier = idData[0];

		iscsiAuthClientNumberToText(client->sendChapIdentifier,
		    client->scratchKeyValue, iscsiAuthStringMaxLength);
		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapIdentifier, client->scratchKeyValue);

		client->sendChapChallenge.length = client->chapChallengeLength;
		iscsiAuthRandomSetData(client->sendChapChallenge.largeBinary,
		    client->sendChapChallenge.length);

		iscsiAuthClientSetKeyValue(&client->sendKeyBlock,
		    iscsiAuthKeyTypeChapChallenge, "");

		client->remoteState = iscsiAuthRemoteStateRecvResponse;
		break;

	case iscsiAuthRemoteStateRecvResponse:
		chapResponseKeyValue = iscsiAuthClientGetKeyValue(
		    &client->recvKeyBlock, iscsiAuthKeyTypeChapResponse);

		chapUsernameKeyValue = iscsiAuthClientGetKeyValue(
		    &client->recvKeyBlock, iscsiAuthKeyTypeChapUsername);

		if (!chapResponseKeyValue) {
			client->remoteState = iscsiAuthRemoteStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapResponseExpected;
			break;
		}

		if (!chapUsernameKeyValue) {
			client->remoteState = iscsiAuthRemoteStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapUsernameExpected;
			break;
		}

		status = iscsiAuthClientTextToData(chapResponseKeyValue,
		    responseData, &responseLength);

		if (status) {
			client->remoteState = iscsiAuthRemoteStateError;
			client->debugStatus =
			    iscsiAuthDebugStatusChapResponseBad;
			break;
		}

		if (responseLength == iscsiAuthChapResponseLength) {
			debugStatus = iscsiAuthClientChapComputeResponse(
			    client, TRUE, client->sendChapIdentifier,
			    client->sendChapChallenge.largeBinary,
			    client->sendChapChallenge.length, myResponseData);

			/*
			 * Check if the same CHAP secret is being used for
			 * authentication in both directions.
			 */
			if (debugStatus == iscsiAuthDebugStatusNotSet &&
			    bcmp(myResponseData, responseData,
			    iscsiAuthChapResponseLength) == 0) {

				client->remoteState =
					iscsiAuthRemoteStateError;
				client->debugStatus =
				    iscsiAuthDebugStatusPasswordIdentical;
				break;
			}
		}

		(void) iscsiAuthClientStringCopy(client->chapUsername,
		    chapUsernameKeyValue, iscsiAuthStringMaxLength);

		/* To verify the target's response. */
		status = iscsiAuthClientChapAuthRequest(
		    client, client->chapUsername, client->sendChapIdentifier,
		    client->sendChapChallenge.largeBinary,
		    client->sendChapChallenge.length, responseData,
		    responseLength);

		if (status == iscsiAuthStatusInProgress) {
			iscsiAuthClientGlobalStats.requestSent++;
			client->remoteState = iscsiAuthRemoteStateAuthRequest;
			break;
		}

		client->remoteAuthStatus = (IscsiAuthStatus) status;
		client->authResponseFlag = TRUE;

		/* FALLTHRU */

	case iscsiAuthRemoteStateAuthRequest:
		/*
		 * client->remoteAuthStatus already set
		 */
		if (client->authServerErrorFlag) {
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->debugStatus =
			    iscsiAuthDebugStatusAuthServerError;
		} else if (client->remoteAuthStatus == iscsiAuthStatusPass) {
			client->debugStatus = iscsiAuthDebugStatusAuthPass;
		} else if (client->remoteAuthStatus == iscsiAuthStatusFail) {
			client->debugStatus = iscsiAuthDebugStatusAuthFail;
		} else {
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->debugStatus = iscsiAuthDebugStatusAuthStatusBad;
		}
		client->remoteState = iscsiAuthRemoteStateDone;

		/* FALLTHRU */

	case iscsiAuthRemoteStateDone:
		break;

	case iscsiAuthRemoteStateError:
	default:
		client->phase = iscsiAuthPhaseError;
	}
}


static void
iscsiAuthClientHandshake(IscsiAuthClient * client)
{
	if (client->phase == iscsiAuthPhaseDone) {
		/*
		 * Should only happen if authentication
		 * protocol error occured.
		 */
		return;
	}

	if (client->remoteState == iscsiAuthRemoteStateAuthRequest) {
		/*
		 * Defer until authentication response received
		 * from internal authentication service.
		 */
		return;
	}

	if (client->nodeType == iscsiAuthNodeTypeInitiator) {

		/*
		 * Target should only have set T bit on response if
		 * initiator set it on previous message.
		 */
		if (client->recvKeyBlock.transitBit &&
		    client->transitBitSentFlag == 0) {
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->phase = iscsiAuthPhaseDone;
			client->debugStatus =
			    iscsiAuthDebugStatusTbitSetIllegal;
			return;
		}
	}

	if (client->phase == iscsiAuthPhaseNegotiate) {
		/*
		 * Should only happen if waiting for peer
		 * to send AuthMethod key or set Transit Bit.
		 */
		if (client->nodeType == iscsiAuthNodeTypeInitiator) {
			client->sendKeyBlock.transitBit = TRUE;
		}
		return;
	}

	if (client->remoteState == iscsiAuthRemoteStateRecvResponse ||
	    client->remoteState == iscsiAuthRemoteStateDone) {

		if (client->nodeType == iscsiAuthNodeTypeInitiator) {
			if (client->recvKeyBlock.transitBit) {
				if (client->remoteState !=
				    iscsiAuthRemoteStateDone) {
					goto recvTransitBitError;
				}
				iscsiAuthClientNextPhase(client);
			} else {
				client->sendKeyBlock.transitBit = TRUE;
			}
		} else {
			if (client->remoteState == iscsiAuthRemoteStateDone &&
			    client->remoteAuthStatus != iscsiAuthStatusPass) {

				/*
				 * Authentication failed, don't
				 * do T bit handshake.
				 */
				iscsiAuthClientNextPhase(client);
			} else {

				/*
				 * Target can only set T bit on response if
				 * initiator set it on current message.
				 */
				if (client->recvKeyBlock.transitBit) {
					client->sendKeyBlock.transitBit = TRUE;
					iscsiAuthClientNextPhase(client);
				}
			}
		}
	} else {
		if (client->nodeType == iscsiAuthNodeTypeInitiator) {
			if (client->recvKeyBlock.transitBit) {
				goto recvTransitBitError;
			}
		}
	}

	return;

recvTransitBitError:
	/*
	 * Target set T bit on response but
	 * initiator was not done with authentication.
	 */
	client->remoteAuthStatus = iscsiAuthStatusFail;
	client->phase = iscsiAuthPhaseDone;
	client->debugStatus = iscsiAuthDebugStatusTbitSetPremature;
}


static int
iscsiAuthClientRecvEndStatus(IscsiAuthClient * client)
{
	int authStatus;
	int keyType;

	if (client->phase == iscsiAuthPhaseError) {
		return (iscsiAuthStatusError);
	}

	if (client->phase == iscsiAuthPhaseDone) {

		/*
		 * Perform sanity check against configured parameters.
		 */

		if (client->authRemote && !client->authResponseFlag &&
		    client->remoteAuthStatus == iscsiAuthStatusPass) {

			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->debugStatus =
			    iscsiAuthDebugStatusAuthPassNotValid;
		}

		authStatus = client->remoteAuthStatus;
	} else if (client->remoteState == iscsiAuthRemoteStateAuthRequest) {
		authStatus = iscsiAuthStatusInProgress;
	} else {
		authStatus = iscsiAuthStatusContinue;
	}

	if (authStatus != iscsiAuthStatusInProgress) {
		client->recvInProgressFlag = FALSE;
	}

	if (authStatus == iscsiAuthStatusContinue ||
	    authStatus == iscsiAuthStatusPass) {
		if (client->sendKeyBlock.duplicateSet) {
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->phase = iscsiAuthPhaseDone;
			client->debugStatus =
			    iscsiAuthDebugStatusSendDuplicateSetKeyValue;
			authStatus = iscsiAuthStatusFail;
		} else if (client->sendKeyBlock.stringTooLong) {
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->phase = iscsiAuthPhaseDone;
			client->debugStatus =
			    iscsiAuthDebugStatusSendStringTooLong;
			authStatus = iscsiAuthStatusFail;
		} else if (client->sendKeyBlock.tooMuchData) {
			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->phase = iscsiAuthPhaseDone;
			client->debugStatus =
			    iscsiAuthDebugStatusSendTooMuchData;
			authStatus = iscsiAuthStatusFail;
		} else {
			/*
			 * Check that all incoming keys have been processed.
			 */
			for (keyType = iscsiAuthKeyTypeFirst;
			    keyType < iscsiAuthKeyTypeMaxCount; keyType++) {
				if (client->recvKeyBlock.key[keyType].present &&
				    client->recvKeyBlock.key[keyType].
				    processed == 0) {
					break;
				}
			}

			if (keyType < iscsiAuthKeyTypeMaxCount) {
				client->remoteAuthStatus = iscsiAuthStatusFail;
				client->phase = iscsiAuthPhaseDone;
				client->debugStatus =
				    iscsiAuthDebugStatusUnexpectedKeyPresent;
				authStatus = iscsiAuthStatusFail;
			}
		}
	}

	if (authStatus != iscsiAuthStatusPass &&
	    authStatus != iscsiAuthStatusContinue &&
	    authStatus != iscsiAuthStatusInProgress) {
		int authMethodKeyPresent = FALSE;
		int chapAlgorithmKeyPresent = FALSE;

		/*
		 * Suppress send keys on error, except
		 * for AuthMethod and CHAP_A.
		 */
		if (client->nodeType == iscsiAuthNodeTypeTarget) {
			if (iscsiAuthClientGetKeyValue(&client->sendKeyBlock,
				iscsiAuthKeyTypeAuthMethod)) {
				authMethodKeyPresent = TRUE;
			} else if (iscsiAuthClientGetKeyValue(
			    &client->sendKeyBlock,
			    iscsiAuthKeyTypeChapAlgorithm)) {
				chapAlgorithmKeyPresent = TRUE;
			}
		}

		iscsiAuthClientInitKeyBlock(&client->sendKeyBlock);

		if (client->nodeType == iscsiAuthNodeTypeTarget) {
			if (authMethodKeyPresent &&
			    client->negotiatedAuthMethod ==
			    iscsiAuthOptionReject) {
				iscsiAuthClientSetKeyValue(
				    &client->sendKeyBlock,
				    iscsiAuthKeyTypeAuthMethod,
				    client->rejectOptionName);
			} else if (chapAlgorithmKeyPresent &&
			    client->negotiatedChapAlgorithm ==
			    iscsiAuthOptionReject) {
				iscsiAuthClientSetKeyValue(
				    &client->sendKeyBlock,
				    iscsiAuthKeyTypeChapAlgorithm,
				    client->rejectOptionName);
			}
		}
	}

	return (authStatus);
}


int
iscsiAuthClientRecvBegin(IscsiAuthClient * client)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase == iscsiAuthPhaseError) {
		return (iscsiAuthStatusError);
	}

	if (client->phase == iscsiAuthPhaseDone) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (client->recvInProgressFlag) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->recvInProgressFlag = TRUE;

	if (client->phase == iscsiAuthPhaseConfigure) {
		iscsiAuthClientNextPhase(client);
	}

	client->transitBitSentFlag = client->sendKeyBlock.transitBit;

	iscsiAuthClientInitKeyBlock(&client->recvKeyBlock);
	iscsiAuthClientInitKeyBlock(&client->sendKeyBlock);

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientRecvEnd(IscsiAuthClient * client,
    IscsiAuthClientCallback * callback, void *userHandle, void *messageHandle)
{
	int nextPhaseFlag = FALSE;

	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase == iscsiAuthPhaseError) {
		return (iscsiAuthStatusError);
	}

	if (!callback || !client->recvInProgressFlag) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (client->recvEndCount > iscsiAuthRecvEndMaxCount) {
		client->remoteAuthStatus = iscsiAuthStatusFail;
		client->phase = iscsiAuthPhaseDone;
		client->debugStatus =
		    iscsiAuthDebugStatusRecvMessageCountLimit;
	} else if (client->recvKeyBlock.duplicateSet) {
		client->remoteAuthStatus = iscsiAuthStatusFail;
		client->phase = iscsiAuthPhaseDone;
		client->debugStatus =
		    iscsiAuthDebugStatusRecvDuplicateSetKeyValue;
	} else if (client->recvKeyBlock.stringTooLong) {
		client->remoteAuthStatus = iscsiAuthStatusFail;
		client->phase = iscsiAuthPhaseDone;
		client->debugStatus = iscsiAuthDebugStatusRecvStringTooLong;
	} else if (client->recvKeyBlock.tooMuchData) {
		client->remoteAuthStatus = iscsiAuthStatusFail;
		client->phase = iscsiAuthPhaseDone;
		client->debugStatus = iscsiAuthDebugStatusRecvTooMuchData;
	}

	client->recvEndCount++;

	client->callback = callback;
	client->userHandle = userHandle;
	client->messageHandle = messageHandle;

	switch (client->phase) {
	case iscsiAuthPhaseNegotiate:
		iscsiAuthClientCheckAuthMethodKey(client);

		if (client->authMethodValidNegRole ==
		    iscsiAuthNegRoleResponder) {
			if (client->negotiatedAuthMethod ==
			    iscsiAuthOptionNotPresent) {
				if (client->authRemote ||
				    client->recvKeyBlock.transitBit == 0) {
					/*
					 * No AuthMethod key from peer
					 * on first message, try moving
					 * the process along by sending
					 * the AuthMethod key.
					 */

					client->authMethodValidNegRole =
					    iscsiAuthNegRoleOriginator;

					iscsiAuthClientSetAuthMethodKey(client,
					    client->authMethodValidCount,
					    client->authMethodValidList);
					break;
				}

				/*
				 * Special case if peer sent no
				 * AuthMethod key, but did set Transit
				 * Bit, allowing this side to do a
				 * null authentication, and compelete
				 * the iSCSI security phase without
				 * either side sending the AuthMethod
				 * key.
				 */
			} else {
				/*
				 * Send response to AuthMethod key.
				 */

				iscsiAuthClientSetAuthMethodKey(client, 1,
				    &client->negotiatedAuthMethod);
			}

			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				iscsiAuthClientNextPhase(client);
			} else {
				nextPhaseFlag = TRUE;
			}

		} else {
			if (client->negotiatedAuthMethod ==
			    iscsiAuthOptionNotPresent) {
				client->remoteAuthStatus = iscsiAuthStatusFail;
				client->phase = iscsiAuthPhaseDone;
				client->debugStatus =
				    iscsiAuthDebugStatusAuthMethodExpected;
				break;
			}

			iscsiAuthClientNextPhase(client);
		}
		break;

	case iscsiAuthPhaseAuthenticate:
	case iscsiAuthPhaseDone:
		break;

	default:
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	switch (client->phase) {
	case iscsiAuthPhaseNegotiate:
		if (nextPhaseFlag) {
			iscsiAuthClientNextPhase(client);
		}
		break;

	case iscsiAuthPhaseAuthenticate:
		/*
		 * Must call iscsiAuthClientLocalAuthentication()
		 * before iscsiAuthClientRemoteAuthentication()
		 * to insure processing of the CHAP algorithm key,
		 * and to avoid leaving an in progress request to the
		 * authentication service.
		 */
		iscsiAuthClientLocalAuthentication(client);

		if (client->localState != iscsiAuthLocalStateError) {
			iscsiAuthClientRemoteAuthentication(client);
		}

		if (client->localState == iscsiAuthLocalStateError ||
		    client->remoteState == iscsiAuthRemoteStateError) {

			client->remoteAuthStatus = iscsiAuthStatusFail;
			client->phase = iscsiAuthPhaseDone;
			/*
			 * client->debugStatus should already be set.
			 */
		}
		break;

	case iscsiAuthPhaseDone:
		break;

	default:
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	iscsiAuthClientHandshake(client);

	return (iscsiAuthClientRecvEndStatus(client));
}


#ifdef notused
void
iscsiAuthClientAuthResponse(IscsiAuthClient * client, int authStatus)
{
	iscsiAuthClientGlobalStats.responseReceived++;

	if (!client || client->signature != iscsiAuthClientSignature) {
		return;
	}

	if (!client->recvInProgressFlag ||
	    client->phase != iscsiAuthPhaseAuthenticate ||
	    client->remoteState != iscsiAuthRemoteStateAuthRequest) {

		client->phase = iscsiAuthPhaseError;
		return;
	}

	client->remoteAuthStatus = (IscsiAuthStatus) authStatus;
	client->authResponseFlag = TRUE;

	iscsiAuthClientRemoteAuthentication(client);

	iscsiAuthClientHandshake(client);

	authStatus = iscsiAuthClientRecvEndStatus(client);

	client->callback(client->userHandle, client->messageHandle, authStatus);
}
#endif


const char *
iscsiAuthClientGetKeyName(int keyType)
{
	if (keyType < iscsiAuthKeyTypeFirst || keyType > iscsiAuthKeyTypeLast) {
		return (0);
	}
	return (iscsiAuthClientKeyInfo[keyType].name);
}


int
iscsiAuthClientGetNextKeyType(int *pKeyType)
{
	int keyType = *pKeyType;

	if (keyType >= iscsiAuthKeyTypeLast) {
		return (iscsiAuthStatusError);
	}

	if (keyType < iscsiAuthKeyTypeFirst) {
		keyType = iscsiAuthKeyTypeFirst;
	} else {
		keyType++;
	}

	*pKeyType = keyType;

	return (iscsiAuthStatusNoError);
}


#ifdef notused
int
iscsiAuthClientKeyNameToKeyType(const char *keyName)
{
	int keyType = iscsiAuthKeyTypeNone;

	while (iscsiAuthClientGetNextKeyType(&keyType) ==
	    iscsiAuthStatusNoError) {
		const char *keyName2 = iscsiAuthClientGetKeyName(keyType);

		if (!keyName2) {
			return (iscsiAuthKeyTypeNone);
		}

		if (strcmp(keyName, keyName2) == 0) {
			return (keyType);
		}
	}

	return (iscsiAuthKeyTypeNone);
}
#endif


int
iscsiAuthClientRecvKeyValue(IscsiAuthClient * client, int keyType,
    const char *userKeyValue)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseNegotiate &&
	    client->phase != iscsiAuthPhaseAuthenticate) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (keyType < iscsiAuthKeyTypeFirst || keyType > iscsiAuthKeyTypeLast) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (keyType == iscsiAuthKeyTypeChapChallenge) {
		client->recvChapChallenge.length =
		    iscsiAuthLargeBinaryMaxLength;
		client->recvChapChallengeStatus =
		    iscsiAuthClientTextToData(userKeyValue,
		    client->recvChapChallenge.largeBinary,
		    &client->recvChapChallenge.length);
		userKeyValue = "";
	}

	iscsiAuthClientSetKeyValue(&client->recvKeyBlock,
	    keyType, userKeyValue);

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientSendKeyValue(IscsiAuthClient * client, int keyType,
    int *keyPresent, char *userKeyValue, unsigned int maxLength)
{
	const char *keyValue;

	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure &&
	    client->phase != iscsiAuthPhaseNegotiate &&
	    client->phase != iscsiAuthPhaseAuthenticate &&
	    client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (keyType < iscsiAuthKeyTypeFirst || keyType > iscsiAuthKeyTypeLast) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	keyValue = iscsiAuthClientGetKeyValue(&client->sendKeyBlock, keyType);
	if (keyValue) {
		if (keyType == iscsiAuthKeyTypeChapChallenge) {
			if (iscsiAuthClientDataToText(client->base64,
			    client->sendChapChallenge.largeBinary,
			    client->sendChapChallenge.length,
			    userKeyValue, maxLength)) {
				client->phase = iscsiAuthPhaseError;
				return (iscsiAuthStatusError);
			}
		} else {
			if (iscsiAuthClientStringCopy(userKeyValue,
			    keyValue, maxLength)) {
				client->phase = iscsiAuthPhaseError;
				return (iscsiAuthStatusError);
			}
		}
		*keyPresent = TRUE;
	} else {
		*keyPresent = FALSE;
	}

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientRecvTransitBit(IscsiAuthClient * client, int value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseNegotiate &&
	    client->phase != iscsiAuthPhaseAuthenticate) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (value) {
		client->recvKeyBlock.transitBit = TRUE;
	} else {
		client->recvKeyBlock.transitBit = FALSE;
	}

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientSendTransitBit(IscsiAuthClient * client, int *value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure &&
	    client->phase != iscsiAuthPhaseNegotiate &&
	    client->phase != iscsiAuthPhaseAuthenticate &&
	    client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	*value = client->sendKeyBlock.transitBit;

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientInit(int nodeType, int bufferDescCount,
    IscsiAuthBufferDesc * bufferDesc)
{
	IscsiAuthClient *client;
	IscsiAuthStringBlock *recvStringBlock;
	IscsiAuthStringBlock *sendStringBlock;
	IscsiAuthLargeBinary *recvChapChallenge;
	IscsiAuthLargeBinary *sendChapChallenge;
	int valueList[2];

	if (bufferDescCount != 5 ||
	    bufferDesc == 0) {
		return (iscsiAuthStatusError);
	}

	if (!bufferDesc[0].address ||
	    bufferDesc[0].length != sizeof (*client)) {
		return (iscsiAuthStatusError);
	}
	client = (IscsiAuthClient *) bufferDesc[0].address;

	if (bufferDesc[1].address == 0 ||
	    bufferDesc[1].length != sizeof (*recvStringBlock)) {
		return (iscsiAuthStatusError);
	}
	recvStringBlock = (IscsiAuthStringBlock *) bufferDesc[1].address;

	if (bufferDesc[2].address == 0 ||
	    bufferDesc[2].length != sizeof (*sendStringBlock)) {
		return (iscsiAuthStatusError);
	}
	sendStringBlock = (IscsiAuthStringBlock *) bufferDesc[2].address;

	if (bufferDesc[3].address == 0 ||
	    bufferDesc[3].length != sizeof (*recvChapChallenge)) {
		return (iscsiAuthStatusError);
	}
	recvChapChallenge = (IscsiAuthLargeBinary *) bufferDesc[3].address;

	if (bufferDesc[4].address == 0 ||
	    bufferDesc[4].length != sizeof (*sendChapChallenge)) {
		return (iscsiAuthStatusError);
	}
	sendChapChallenge = (IscsiAuthLargeBinary *) bufferDesc[4].address;

	bzero(client, sizeof (*client));
	bzero(recvStringBlock, sizeof (*recvStringBlock));
	bzero(sendStringBlock, sizeof (*sendStringBlock));
	bzero(recvChapChallenge, sizeof (*recvChapChallenge));
	bzero(sendChapChallenge, sizeof (*sendChapChallenge));

	client->recvKeyBlock.stringBlock = recvStringBlock->stringBlock;
	client->sendKeyBlock.stringBlock = sendStringBlock->stringBlock;
	client->recvChapChallenge.largeBinary = recvChapChallenge->largeBinary;
	client->sendChapChallenge.largeBinary = sendChapChallenge->largeBinary;

	if (iscsiAuthClientCheckNodeType(nodeType)) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->signature = iscsiAuthClientSignature;
	client->nodeType = (IscsiAuthNodeType) nodeType;
	/* Assume bi-directional authentication enabled. */
	client->authRemote = TRUE;
	client->passwordPresent = FALSE;
	client->version = iscsiAuthVersionRfc;
	client->chapChallengeLength = iscsiAuthChapResponseLength;
	client->ipSec = TRUE;
	client->base64 = FALSE;

	client->phase = iscsiAuthPhaseConfigure;
	client->negotiatedAuthMethod = iscsiAuthOptionNotPresent;
	client->negotiatedChapAlgorithm = iscsiAuthOptionNotPresent;

	if (client->nodeType == iscsiAuthNodeTypeInitiator) {
		client->authMethodNegRole = iscsiAuthNegRoleOriginator;
	} else {
		/*
		 * Initial value ignored for Target.
		 */
		client->authMethodNegRole = iscsiAuthNegRoleResponder;
	}

	/* All supported authentication methods */
	valueList[0] = iscsiAuthMethodChap;
	valueList[1] = iscsiAuthOptionNone;

	/*
	 * Must call after setting authRemote, password,
	 * version and authMethodNegRole
	 */
	if (iscsiAuthClientSetAuthMethodList(client, 2, valueList) !=
	    iscsiAuthStatusNoError) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	valueList[0] = iscsiAuthChapAlgorithmMd5;

	if (iscsiAuthClientSetChapAlgorithmList(client, 1, valueList) !=
	    iscsiAuthStatusNoError) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	return (iscsiAuthStatusNoError);
}


#ifdef notused
int
iscsiAuthClientFinish(IscsiAuthClient * client)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	iscsiAuthClientChapAuthCancel(client);

	bzero(client, sizeof (*client));

	return (iscsiAuthStatusNoError);
}
#endif


static int
iscsiAuthClientSetOptionList(IscsiAuthClient * client,
    unsigned int optionCount,
    const int *optionList,
    unsigned int *clientOptionCount,
    int *clientOptionList,
    unsigned int optionMaxCount,
    int (*checkOption) (int),
    int (*checkList) (unsigned int optionCount, const int *optionList))
{
	unsigned int i;
	unsigned int j;

	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    optionCount > optionMaxCount) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	for (i = 0; i < optionCount; i++) {
		if ((*checkOption) (optionList[i])) {
			client->phase = iscsiAuthPhaseError;
			return (iscsiAuthStatusError);
		}
	}

	/*
	 * Check for duplicate entries.
	 */
	for (i = 0; i < optionCount; i++) {
		for (j = 0; j < optionCount; j++) {
			if (j == i)
				continue;
			if (optionList[i] == optionList[j]) {
				client->phase = iscsiAuthPhaseError;
				return (iscsiAuthStatusError);
			}
		}
	}

	/*
	 * Check for key specific constraints.
	 */
	if (checkList) {
		if ((*checkList) (optionCount, optionList)) {
			client->phase = iscsiAuthPhaseError;
			return (iscsiAuthStatusError);
		}
	}

	for (i = 0; i < optionCount; i++) {
		clientOptionList[i] = optionList[i];
	}

	*clientOptionCount = optionCount;

	return (iscsiAuthStatusNoError);
}


static void
iscsiAuthClientSetAuthMethodValid(IscsiAuthClient * client)
{
	static const char rejectOptionNameDraft8[] = "reject";
	static const char rejectOptionNameRfc[] = "Reject";
	static const char noneOptionNameDraft8[] = "none";
	static const char noneOptionNameRfc[] = "None";
	unsigned int i;
	unsigned int j = 0;
	int option = 0;

	if (client->version == iscsiAuthVersionDraft8) {
		client->rejectOptionName = rejectOptionNameDraft8;
		client->noneOptionName = noneOptionNameDraft8;
	} else {
		client->rejectOptionName = rejectOptionNameRfc;
		client->noneOptionName = noneOptionNameRfc;
	}

	/*
	 * Following checks may need to be revised if
	 * authentication options other than CHAP and none
	 * are supported.
	 */

	if (client->nodeType == iscsiAuthNodeTypeInitiator) {

		if (client->authRemote) {
			/*
			 * If initiator doing authentication,
			 * don't offer authentication option none.
			 */
			option = 1;
		} else if (!client->passwordPresent) {
			/*
			 * If initiator password not set,
			 * only offer authentication option none.
			 */
			option = 2;
		}
	}

	if (client->nodeType == iscsiAuthNodeTypeTarget) {

		if (client->authRemote) {
			/*
			 * If target doing authentication,
			 * don't accept authentication option none.
			 */
			option = 1;
		} else {
			/*
			 * If target not doing authentication,
			 * only accept authentication option none.
			 */
			option = 2;
		}
	}

	for (i = 0; i < client->authMethodCount; i++) {

		if (option == 1) {
			if (client->authMethodList[i] == iscsiAuthOptionNone) {
				continue;
			}
		} else if (option == 2) {
			if (client->authMethodList[i] != iscsiAuthOptionNone) {
				continue;
			}
		}

		client->authMethodValidList[j++] = client->authMethodList[i];
	}

	client->authMethodValidCount = j;

	iscsiAuthClientInitKeyBlock(&client->sendKeyBlock);

	if (client->nodeType == iscsiAuthNodeTypeInitiator) {
		if (client->authRemote) {
			/*
			 * Initiator wants to authenticate target,
			 * always send AuthMethod key.
			 */
			client->sendKeyBlock.transitBit = FALSE;
			client->authMethodValidNegRole =
			    iscsiAuthNegRoleOriginator;
		} else {
			client->sendKeyBlock.transitBit = TRUE;
			client->authMethodValidNegRole =
			    client->authMethodNegRole;
		}
	} else {
		client->sendKeyBlock.transitBit = FALSE;
		client->authMethodValidNegRole = iscsiAuthNegRoleResponder;
	}

	if (client->authMethodValidNegRole == iscsiAuthNegRoleOriginator) {
		iscsiAuthClientSetAuthMethodKey(client,
		    client->authMethodValidCount,
		    client->authMethodValidList);
	} else {
		int value = iscsiAuthOptionNotPresent;
		iscsiAuthClientSetAuthMethodKey(client, 1, &value);
	}
}


static int
iscsiAuthClientCheckAuthMethodList(unsigned int optionCount,
    const int *optionList)
{
	unsigned int i;

	if (!optionList || optionCount < 2) {
		return (TRUE);
	}

	if (optionList[optionCount - 1] != iscsiAuthOptionNone) {
		return (TRUE);
	}

	for (i = 0; i < (optionCount - 1); i++) {
		if (optionList[i] != iscsiAuthOptionNone) {
			return (FALSE);
		}
	}

	return (FALSE);
}


int
iscsiAuthClientSetAuthMethodList(IscsiAuthClient * client,
    unsigned int optionCount, const int *optionList)
{
	int status;

	status = iscsiAuthClientSetOptionList(
	    client, optionCount, optionList, &client->authMethodCount,
	    client->authMethodList, iscsiAuthMethodMaxCount,
	    iscsiAuthClientCheckAuthMethodOption,
	    iscsiAuthClientCheckAuthMethodList);

	if (status != iscsiAuthStatusNoError) {
		return (status);
	}

	/*
	 * Setting authMethod affects authMethodValid.
	 */
	iscsiAuthClientSetAuthMethodValid(client);

	return (iscsiAuthStatusNoError);
}

#ifdef notused
int
iscsiAuthClientSetAuthMethodNegRole(IscsiAuthClient * client, int negRole)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    iscsiAuthClientCheckNegRole(negRole) ||
	    client->nodeType != iscsiAuthNodeTypeInitiator) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->authMethodNegRole = (IscsiAuthNegRole) negRole;

	/*
	 * Setting negRole affects authMethodValid.
	 */
	iscsiAuthClientSetAuthMethodValid(client);

	return (iscsiAuthStatusNoError);
}
#endif


static int
iscsiAuthClientCheckChapAlgorithmList(unsigned int optionCount,
    const int *optionList)
{
	if (!optionList || optionCount < 1) {
		return (TRUE);
	}

	return (FALSE);
}


int
iscsiAuthClientSetChapAlgorithmList(IscsiAuthClient * client,
    unsigned int optionCount, const int *optionList)
{
	return (iscsiAuthClientSetOptionList(client,
		optionCount,
		optionList,
		&client->chapAlgorithmCount,
		client->chapAlgorithmList,
		iscsiAuthChapAlgorithmMaxCount,
		iscsiAuthClientCheckChapAlgorithmOption,
		iscsiAuthClientCheckChapAlgorithmList));
}


int
iscsiAuthClientSetUsername(IscsiAuthClient * client, const char *username)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    iscsiAuthClientCheckString(username, iscsiAuthStringMaxLength, 0)) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (iscsiAuthClientStringCopy(client->username, username,
	    iscsiAuthStringMaxLength)) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientSetPassword(IscsiAuthClient * client,
    const unsigned char *passwordData, unsigned int passwordLength)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    passwordLength > iscsiAuthStringMaxLength) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	bcopy(passwordData, client->passwordData, passwordLength);
	client->passwordLength = passwordLength;
	if (client->passwordLength > 0) {
		client->passwordPresent = TRUE;
	} else {
		client->passwordPresent = FALSE;
	}

	/*
	 * Setting password may affect authMethodValid.
	 */
	iscsiAuthClientSetAuthMethodValid(client);

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientSetAuthRemote(IscsiAuthClient * client, int authRemote)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->authRemote = authRemote;

	/*
	 * Setting authRemote may affect authMethodValid.
	 */
	iscsiAuthClientSetAuthMethodValid(client);

	return (iscsiAuthStatusNoError);
}

#ifdef notused
int
iscsiAuthClientSetGlueHandle(IscsiAuthClient * client, void *glueHandle)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure &&
	    client->phase != iscsiAuthPhaseNegotiate &&
	    client->phase != iscsiAuthPhaseAuthenticate) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->glueHandle = glueHandle;

	return (iscsiAuthStatusNoError);
}

int
iscsiAuthClientSetMethodListName(IscsiAuthClient *client,
    const char *methodListName)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    iscsiAuthClientCheckString(methodListName,
	    iscsiAuthStringMaxLength, 0)) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (iscsiAuthClientStringCopy(client->methodListName, methodListName,
		iscsiAuthStringMaxLength)) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	return (iscsiAuthStatusNoError);
}
#endif


int
iscsiAuthClientSetVersion(IscsiAuthClient * client, int version)
{
	if (client == 0 ||
	    client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    iscsiAuthClientCheckVersion(version)) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->version = (IscsiAuthVersion) version;

	iscsiAuthClientSetAuthMethodValid(client);

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientSetIpSec(IscsiAuthClient * client, int ipSec)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->ipSec = ipSec;

	return (iscsiAuthStatusNoError);
}

#ifdef notused
int
iscsiAuthClientSetBase64(IscsiAuthClient * client, int base64)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->base64 = base64;

	return (iscsiAuthStatusNoError);
}

int
iscsiAuthClientSetChapChallengeLength(IscsiAuthClient * client,
    unsigned int chapChallengeLength)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure ||
	    chapChallengeLength < iscsiAuthChapResponseLength ||
	    chapChallengeLength > iscsiAuthLargeBinaryMaxLength) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	client->chapChallengeLength = chapChallengeLength;

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientCheckPasswordNeeded(IscsiAuthClient *client, int *passwordNeeded)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (client->nodeType == iscsiAuthNodeTypeInitiator) {
		if (client->authRemote && !client->passwordPresent) {
			*passwordNeeded = TRUE;
		} else {
			*passwordNeeded = FALSE;
		}
	} else {
		*passwordNeeded = FALSE;
	}

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientGetAuthPhase(IscsiAuthClient * client, int *value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	*value = client->phase;

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientGetAuthStatus(IscsiAuthClient * client, int *value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	*value = client->remoteAuthStatus;

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientAuthStatusPass(int authStatus)
{
	if (authStatus == iscsiAuthStatusPass) {
		return (TRUE);
	}

	return (FALSE);
}


int
iscsiAuthClientGetAuthMethod(IscsiAuthClient * client, int *value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseDone &&
	    client->phase != iscsiAuthPhaseAuthenticate) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	*value = client->negotiatedAuthMethod;

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientGetChapAlgorithm(IscsiAuthClient * client, int *value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	*value = client->negotiatedChapAlgorithm;

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientGetChapUsername(IscsiAuthClient * client,
    char *value, unsigned int maxLength)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (iscsiAuthClientStringCopy(value, client->chapUsername, maxLength)) {
		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	return (iscsiAuthStatusNoError);
}


int
iscsiAuthClientSendStatusCode(IscsiAuthClient * client, int *statusCode)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseConfigure &&
	    client->phase != iscsiAuthPhaseNegotiate &&
	    client->phase != iscsiAuthPhaseAuthenticate &&
	    client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseDone) {
		*statusCode = 0x0000;
		return (iscsiAuthStatusNoError);
	}

	switch (client->remoteAuthStatus) {
	case iscsiAuthStatusPass:
		*statusCode = 0x0000;	/* no error */
		break;

	case iscsiAuthStatusFail:
		switch (client->debugStatus) {
		case iscsiAuthDebugStatusAuthFail:
			/*
			 * Authentication error with peer.
			 */
			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				*statusCode = 0x0300;
				/*
				 * iSCSI Target error
				 */
			} else {
				*statusCode = 0x0201;
				/*
				 * iSCSI Initiator error
				 */
			}
			break;

		case iscsiAuthDebugStatusAuthMethodExpected:
		case iscsiAuthDebugStatusChapAlgorithmExpected:
		case iscsiAuthDebugStatusChapIdentifierExpected:
		case iscsiAuthDebugStatusChapChallengeExpected:
		case iscsiAuthDebugStatusChapResponseExpected:
		case iscsiAuthDebugStatusChapUsernameExpected:
			/*
			 * Missing parameter with peer.
			 */
			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				*statusCode = 0x0300;
				/*
				 * iSCSI Target error
				 */
			} else {
				*statusCode = 0x0207;
				/*
				 * iSCSI Initiator error
				 */
			}
			break;

		case iscsiAuthDebugStatusAuthMethodNotPresent:
		case iscsiAuthDebugStatusAuthMethodReject:
		case iscsiAuthDebugStatusAuthMethodNone:
		case iscsiAuthDebugStatusChapAlgorithmReject:
		case iscsiAuthDebugStatusChapChallengeReflected:
		case iscsiAuthDebugStatusPasswordIdentical:
			/*
			 * Could not authenticate with peer.
			 */
			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				*statusCode = 0x0300;
				/*
				 * iSCSI Target error
				 */
			} else {
				*statusCode = 0x0201;
				/*
				 * iSCSI Initiator error
				 */
			}
			break;

		case iscsiAuthDebugStatusLocalPasswordNotSet:
			/*
			 * Local password not set.
			 */
			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				*statusCode = 0x0200;
				/*
				 * iSCSI Initiator error
				 */
			} else {
				*statusCode = 0x0201;
				/*
				 * iSCSI Target error
				 */
			}
			break;

		case iscsiAuthDebugStatusChapIdentifierBad:
		case iscsiAuthDebugStatusChapChallengeBad:
		case iscsiAuthDebugStatusChapResponseBad:
		case iscsiAuthDebugStatusUnexpectedKeyPresent:
		case iscsiAuthDebugStatusTbitSetIllegal:
		case iscsiAuthDebugStatusTbitSetPremature:
		case iscsiAuthDebugStatusRecvMessageCountLimit:
		case iscsiAuthDebugStatusRecvDuplicateSetKeyValue:
		case iscsiAuthDebugStatusRecvStringTooLong:
		case iscsiAuthDebugStatusRecvTooMuchData:
			/*
			 * Other error with peer.
			 */
			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				*statusCode = 0x0300;
				/*
				 * iSCSI Target error
				 */
			} else {
				*statusCode = 0x0200;
				/*
				 * iSCSI Initiator error
				 */
			}
			break;

		case iscsiAuthDebugStatusNotSet:
		case iscsiAuthDebugStatusAuthPass:
		case iscsiAuthDebugStatusAuthRemoteFalse:
		case iscsiAuthDebugStatusAuthMethodBad:
		case iscsiAuthDebugStatusChapAlgorithmBad:
		case iscsiAuthDebugStatusPasswordDecryptFailed:
		case iscsiAuthDebugStatusPasswordTooShortWithNoIpSec:
		case iscsiAuthDebugStatusAuthServerError:
		case iscsiAuthDebugStatusAuthStatusBad:
		case iscsiAuthDebugStatusAuthPassNotValid:
		case iscsiAuthDebugStatusSendDuplicateSetKeyValue:
		case iscsiAuthDebugStatusSendStringTooLong:
		case iscsiAuthDebugStatusSendTooMuchData:
		default:
			/*
			 * Error on this side.
			 */
			if (client->nodeType == iscsiAuthNodeTypeInitiator) {
				*statusCode = 0x0200;
				/*
				 * iSCSI Initiator error
				 */
			} else {
				*statusCode = 0x0300;
				/*
				 * iSCSI Target error
				 */
			}

		}
		break;

	case iscsiAuthStatusNoError:
	case iscsiAuthStatusError:
	case iscsiAuthStatusContinue:
	case iscsiAuthStatusInProgress:
	default:
		/*
		 * Bad authStatus
		 */
		if (client->nodeType == iscsiAuthNodeTypeInitiator) {
			*statusCode = 0x0200;
			/*
			 * iSCSI Initiator error
			 */
		} else {
			*statusCode = 0x0300;
			/*
			 * iSCSI Target error
			 */
		}
	}

	return (iscsiAuthStatusNoError);
}
#endif


int
iscsiAuthClientGetDebugStatus(IscsiAuthClient * client, int *value)
{
	if (!client || client->signature != iscsiAuthClientSignature) {
		return (iscsiAuthStatusError);
	}

	if (client->phase != iscsiAuthPhaseDone) {

		client->phase = iscsiAuthPhaseError;
		return (iscsiAuthStatusError);
	}

	*value = client->debugStatus;

	return (iscsiAuthStatusNoError);
}


const char *
iscsiAuthClientDebugStatusToText(int debugStatus)
{
	const char *s;

	switch (debugStatus) {
	case iscsiAuthDebugStatusNotSet:
		s = "Debug status not set";
		break;

	case iscsiAuthDebugStatusAuthPass:
		s = "Authentication request passed";
		break;

	case iscsiAuthDebugStatusAuthRemoteFalse:
		s = "Authentication not enabled";
		break;

	case iscsiAuthDebugStatusAuthFail:
		s = "Authentication request failed";
		break;

	case iscsiAuthDebugStatusAuthMethodBad:
		s = "AuthMethod bad";
		break;

	case iscsiAuthDebugStatusChapAlgorithmBad:
		s = "CHAP algorithm bad";
		break;

	case iscsiAuthDebugStatusPasswordDecryptFailed:
		s = "Decrypt password failed";
		break;

	case iscsiAuthDebugStatusPasswordTooShortWithNoIpSec:
		s = "Local password too short with no IPSec";
		break;

	case iscsiAuthDebugStatusAuthServerError:
		s = "Unexpected error from authentication server";
		break;

	case iscsiAuthDebugStatusAuthStatusBad:
		s = "Authentication request status bad";
		break;

	case iscsiAuthDebugStatusAuthPassNotValid:
		s = "Authentication pass status not valid";
		break;

	case iscsiAuthDebugStatusSendDuplicateSetKeyValue:
		s = "Same key set more than once on send";
		break;

	case iscsiAuthDebugStatusSendStringTooLong:
		s = "Key value too long on send";
		break;

	case iscsiAuthDebugStatusSendTooMuchData:
		s = "Too much data on send";
		break;

	case iscsiAuthDebugStatusAuthMethodExpected:
		s = "AuthMethod key expected";
		break;

	case iscsiAuthDebugStatusChapAlgorithmExpected:
		s = "CHAP algorithm key expected";
		break;

	case iscsiAuthDebugStatusChapIdentifierExpected:
		s = "CHAP identifier expected";
		break;

	case iscsiAuthDebugStatusChapChallengeExpected:
		s = "CHAP challenge expected";
		break;

	case iscsiAuthDebugStatusChapResponseExpected:
		s = "CHAP response expected";
		break;

	case iscsiAuthDebugStatusChapUsernameExpected:
		s = "CHAP username expected";
		break;

	case iscsiAuthDebugStatusAuthMethodNotPresent:
		s = "AuthMethod key not present";
		break;

	case iscsiAuthDebugStatusAuthMethodReject:
		s = "AuthMethod negotiation failed";
		break;

	case iscsiAuthDebugStatusAuthMethodNone:
		s = "AuthMethod negotiated to none";
		break;

	case iscsiAuthDebugStatusChapAlgorithmReject:
		s = "CHAP algorithm negotiation failed";
		break;

	case iscsiAuthDebugStatusChapChallengeReflected:
		s = "CHAP challange reflected";
		break;

	case iscsiAuthDebugStatusPasswordIdentical:
		s = "Local password same as remote";
		break;

	case iscsiAuthDebugStatusLocalPasswordNotSet:
		s = "Local password not set";
		break;

	case iscsiAuthDebugStatusChapIdentifierBad:
		s = "CHAP identifier bad";
		break;

	case iscsiAuthDebugStatusChapChallengeBad:
		s = "CHAP challenge bad";
		break;

	case iscsiAuthDebugStatusChapResponseBad:
		s = "CHAP response bad";
		break;

	case iscsiAuthDebugStatusUnexpectedKeyPresent:
		s = "Unexpected key present";
		break;

	case iscsiAuthDebugStatusTbitSetIllegal:
		s = "T bit set on response, but not on previous message";
		break;

	case iscsiAuthDebugStatusTbitSetPremature:
		s = "T bit set on response, but authenticaton not complete";
		break;

	case iscsiAuthDebugStatusRecvMessageCountLimit:
		s = "Message count limit reached on receive";
		break;

	case iscsiAuthDebugStatusRecvDuplicateSetKeyValue:
		s = "Same key set more than once on receive";
		break;

	case iscsiAuthDebugStatusRecvStringTooLong:
		s = "Key value too long on receive";
		break;

	case iscsiAuthDebugStatusRecvTooMuchData:
		s = "Too much data on receive";
		break;

	default:
		s = "Unknown error";
	}

	return (s);
}
