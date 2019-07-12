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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <widec.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <libintl.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <wctype.h>
#include <assert.h>

#include <ima.h>
#include <libsun_ima.h>
#include <sys/iscsi_protocol.h>
#include <sys/scsi/adapters/iscsi_if.h>

#include "cmdparse.h"
#include "sun_ima.h"
#include "iscsiadm.h"

#define	VERSION_STRING_MAX_LEN	10
#define	MAX_LONG_CHAR_LEN 19

#define	MAX_AUTH_METHODS 5
/*
 * Version number:
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"

#define	OPTIONSTRING1	"yes|no"
#define	OPTIONSTRING2	"initiator node name"
#define	OPTIONSTRING3	"initiator node alias"
#define	OPTIONSTRING4	"enable|disable"
#define	OPTIONSTRING5	"key=value,..."
#define	OPTIONSTRING6	"none|CRC32"
#define	OPTIONSTRING7	"CHAP name"
#define	OPTIONSTRING8	"<# sessions>|<IP Address>[,<IP Address>]*"
#define	OPTIONSTRING9	"tunable-prop=value"
#define	OPTIONVAL1	"0 to 3600"
#define	OPTIONVAL2	"512 to 2**24 - 1"
#define	OPTIONVAL3	"1 to 65535"
#define	OPTIONVAL4	"<IP address>[:port]"

#define	MAX_ISCSI_NAME_LEN	    223
#define	MAX_ADDRESS_LEN		    255
#define	MIN_CHAP_SECRET_LEN	    12
#define	MAX_CHAP_SECRET_LEN	    16
#define	DEFAULT_ISCSI_PORT	    3260
#define	ISNS_DEFAULT_SERVER_PORT    3205
#define	DEFAULT_RADIUS_PORT	    1812
#define	MAX_CHAP_NAME_LEN	    512
#define	ISCSI_DEFAULT_RX_TIMEOUT_VALUE		"60"
#define	ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX	"180"
#define	ISCSI_DEFAULT_LOGIN_POLLING_DELAY	"60"

/* For listNode */
#define	INF_ERROR		1
#define	INVALID_NODE_NAME	2

#define	IMABOOLPRINT(prop, option)	 \
	if ((option) == PRINT_CONFIGURED_PARAMS) { \
		(void) fprintf(stdout, "%s/%s\n", \
		(prop).defaultValue == IMA_TRUE ? gettext("yes") : \
			gettext("no"), \
		(prop).currentValueValid == IMA_TRUE ? \
			((prop).currentValue == IMA_TRUE ? \
			gettext("yes"): gettext("no")) : "-"); \
	} else if ((option) == PRINT_NEGOTIATED_PARAMS) { \
		(void) fprintf(stdout, "%s\n", \
		(prop).currentValueValid == IMA_TRUE ? \
		(((prop).currentValue == IMA_TRUE) ? gettext("yes") : \
		gettext("no")) : "-"); \
	}

#define	IMAMINMAXPRINT(prop, option) \
	if ((option) == PRINT_CONFIGURED_PARAMS) { \
		(void) fprintf(stdout, "%d/", (prop).defaultValue); \
		if ((prop).currentValueValid == IMA_TRUE) { \
			(void) fprintf(stdout, "%d\n", (prop).currentValue); \
		} else if ((prop).currentValueValid == IMA_FALSE) { \
			(void) fprintf(stdout, "%s\n", "-"); \
		} \
	} else if ((option) == PRINT_NEGOTIATED_PARAMS) { \
		if ((prop).currentValueValid == IMA_TRUE) { \
			(void) fprintf(stdout, "%d\n", (prop).currentValue); \
		} else if ((prop).currentValueValid == IMA_FALSE) { \
			(void) fprintf(stdout, "%s\n", "-"); \
		} \
	}

/* forward declarations */
#define	PARSE_ADDR_OK				0
#define	PARSE_ADDR_MISSING_CLOSING_BRACKET	1
#define	PARSE_ADDR_PORT_OUT_OF_RANGE		2
#define	PARSE_TARGET_OK				0
#define	PARSE_TARGET_INVALID_TPGT		1
#define	PARSE_TARGET_INVALID_ADDR		2

#define	PRINT_CONFIGURED_PARAMS			1
#define	PRINT_NEGOTIATED_PARAMS			2

typedef enum iSCSINameCheckStatus {
	iSCSINameCheckOK,
	iSCSINameLenZero,
	iSCSINameLenExceededMax,
	iSCSINameUnknownType,
	iSCSINameInvalidCharacter,
	iSCSINameIqnFormatError,
	iSCSINameEUIFormatError,
	iSCSINameIqnDateFormatError,
	iSCSINameIqnSubdomainFormatError,
	iSCSINameIqnInvalidYearError,
	iSCSINameIqnInvalidMonthError,
	iSCSINameIqnFQDNError
} iSCSINameCheckStatusType;

/* Utility functions */
iSCSINameCheckStatusType iSCSINameStringProfileCheck(wchar_t *name);
boolean_t isNaturalNumber(char *numberStr, uint32_t upperBound);
static int parseAddress(char *address_port_str, uint16_t defaultPort,
    char *address_str, size_t address_str_len,
    uint16_t *port, boolean_t *isIpv6);
int parseTarget(char *targetStr,
    wchar_t *targetNameStr,
    size_t targetNameStrLen,
    boolean_t *targetAddressSpecified,
    wchar_t *targetAddressStr,
    size_t targetAddressStrLen,
    uint16_t *port,
    boolean_t *tpgtSpecified,
    uint16_t *tpgt,
    boolean_t *isIpv6);
static int chkConnLoginMaxPollingLoginDelay(IMA_OID oid,
    int key, int uintValue);

/* subcommand functions */
static int addFunc(int, char **, int, cmdOptions_t *, void *, int *);
static int listFunc(int, char **, int, cmdOptions_t *, void *, int *);
static int modifyFunc(int, char **, int, cmdOptions_t *, void *, int *);
static int removeFunc(int, char **, int, cmdOptions_t *, void *, int *);

/* helper functions */
static char *getExecBasename(char *);
static int getNodeProps(IMA_NODE_PROPERTIES *);
static int getSecret(char *, int *, int, int);
static int getTargetAddress(int, char *, IMA_TARGET_ADDRESS *);
static int printLoginParameters(char *, IMA_OID, int);
static void printDiscoveryMethod(char *, IMA_UINT32);
static void printTargetLuns(IMA_OID_LIST *);
static void printSendTargets(SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *);
static void printDigestAlgorithm(SUN_IMA_DIGEST_ALGORITHM_VALUE *, int);
static int setLoginParameter(IMA_OID, int, char *);
static int setLoginParameters(IMA_OID, char *);
static int setTunableParameters(IMA_OID, char *);
static void printLibError(IMA_STATUS);
/* LINTED E_STATIC_UNUSED */
static int sunPluginChk(IMA_OID, boolean_t *);
static int sunInitiatorFind(IMA_OID *);
static int getAuthMethodValue(char *, IMA_AUTHMETHOD *);
static int getLoginParam(char *);
static int getTunableParam(char *);
static void iSCSINameCheckStatusDisplay(iSCSINameCheckStatusType status);
static int modifyIndividualTargetParam(cmdOptions_t *optionList,
    IMA_OID targetOid, int *);
static void listCHAPName(IMA_OID oid);
static int printConfiguredSessions(IMA_OID);
static int printTunableParameters(IMA_OID oid);

/* object functions per subcommand */
static int addAddress(int, int, char *[], int *);
static int addStaticConfig(int, char *[], int *);
static int listDiscovery(int *);
static int listDiscoveryAddress(int, char *[], cmdOptions_t *, int *);
static int listISNSServerAddress(int, char *[], cmdOptions_t *, int *);
static int listNode(int *);
static int listStaticConfig(int, char *[], int *);
static int listTarget(int, char *[], cmdOptions_t *, int *);
static int listTargetParam(int, char *[], cmdOptions_t *, int *);
static int modifyDiscovery(cmdOptions_t *, int *);
static int modifyNodeAuthMethod(IMA_OID, char *, int *);
static int modifyNodeAuthParam(IMA_OID oid, int, char *, int *);
static int modifyNodeRadiusConfig(IMA_OID, char *, int *);
static int modifyNodeRadiusAccess(IMA_OID, char *, int *);
static int modifyNodeRadiusSharedSecret(IMA_OID, int *);
static int modifyNode(cmdOptions_t *, int *);
static int modifyTargetAuthMethod(IMA_OID, char *, int *);
static int modifyTargetAuthParam(IMA_OID oid, int param, char *chapName, int *);
static int modifyTargetParam(cmdOptions_t *, char *, int *);
static int removeAddress(int, int, char *[], int *);
static int removeStaticConfig(int, char *[], int *);
static int removeTargetParam(int, char *[], int *);
static int modifyTargetBidirAuthFlag(IMA_OID, char *, int *);
static int modifyConfiguredSessions(IMA_OID targetOid, char *optarg);

/* LINTED E_STATIC_UNUSED */
static IMA_STATUS getISCSINodeParameter(int paramType,
    IMA_OID *oid,
    void *pProps,
    uint32_t paramIndex);
/* LINTED E_STATIC_UNUSED */
static IMA_STATUS setISCSINodeParameter(int paramType,
    IMA_OID *oid,
    void *pProps,
    uint32_t paramIndex);
/* LINTED E_STATIC_UNUSED */
static IMA_STATUS getDigest(IMA_OID oid, int ioctlCmd,
    SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm);

IMA_STATUS getNegotiatedDigest(int digestType,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm,
	SUN_IMA_CONN_PROPERTIES *connProps);

/* globals */
static char *cmdName;

/*
 * Available option letters:
 *
 * befgijklmnoquwxyz
 *
 * DEFGHIJKLMOQUVWXYZ
 */

/*
 * Add new options here
 */
optionTbl_t longOptions[] = {
	{"static", required_arg, 's', OPTIONSTRING4},
	{"sendtargets", required_arg, 't', OPTIONSTRING4},
	{"iSNS", required_arg, 'i', OPTIONSTRING4},
	{"headerdigest", required_arg, 'h', OPTIONSTRING6},
	{"datadigest", required_arg, 'd', OPTIONSTRING6},
	{"login-param", required_arg, 'p', OPTIONSTRING5},
	{"authentication", required_arg, 'a', "CHAP|none"},
	{"bi-directional-authentication", required_arg, 'B', OPTIONSTRING4},
	{"CHAP-secret", no_arg, 'C', NULL},
	{"CHAP-name", required_arg, 'H', OPTIONSTRING7},
	{"node-name", required_arg, 'N', OPTIONSTRING2},
	{"node-alias", required_arg, 'A', OPTIONSTRING3},
	{"radius-server", required_arg, 'r', OPTIONVAL4},
	{"radius-access", required_arg, 'R', OPTIONSTRING4},
	{"radius-shared-secret", no_arg, 'P', NULL},
	{"verbose", no_arg, 'v', NULL},
	{"scsi-target", no_arg, 'S', NULL},
	{"configured-sessions", required_arg, 'c', OPTIONSTRING8},
	{"tunable-param", required_arg, 'T', OPTIONSTRING9},
	{NULL, 0, 0, 0}
};

parameterTbl_t loginParams[] = {
	{"dataseqinorder", DATA_SEQ_IN_ORDER},
	{"defaulttime2retain", DEFAULT_TIME_2_RETAIN},
	{"defaulttime2wait", DEFAULT_TIME_2_WAIT},
	{"firstburstlength", FIRST_BURST_LENGTH},
	{"immediatedata", IMMEDIATE_DATA},
	{"initialr2t", INITIAL_R2T},
	{"maxburstlength", MAX_BURST_LENGTH},
	{"datapduinorder", DATA_PDU_IN_ORDER},
	{"maxoutstandingr2t", MAX_OUTSTANDING_R2T},
	{"maxrecvdataseglen", MAX_RECV_DATA_SEG_LEN},
	{"maxconnections", MAX_CONNECTIONS},
	{"errorrecoverylevel", ERROR_RECOVERY_LEVEL},
	{NULL, 0}
};

parameterTbl_t tunableParams[] = {
	{"recv-login-rsp-timeout", RECV_LOGIN_RSP_TIMEOUT},
	{"conn-login-max", CONN_LOGIN_MAX},
	{"polling-login-delay", POLLING_LOGIN_DELAY},
	{NULL, 0}
};

/*
 * Add new subcommands here
 */
subcommand_t subcommands[] = {
	{"add", ADD, addFunc},
	{"list", LIST, listFunc},
	{"modify", MODIFY, modifyFunc},
	{"remove", REMOVE, removeFunc},
	{NULL, 0, NULL}
};

/*
 * Add objects here
 */
object_t objects[] = {
	{"discovery", DISCOVERY},
	{"discovery-address", DISCOVERY_ADDRESS},
	{"isns-server", ISNS_SERVER_ADDRESS},
	{"initiator-node", NODE},
	{"static-config", STATIC_CONFIG},
	{"target", TARGET},
	{"target-param", TARGET_PARAM},
	{NULL, 0}
};

/*
 * Rules for subcommands and objects
 */
objectRules_t objectRules[] = {
	{TARGET, 0, LIST, 0, ADD|REMOVE|MODIFY, LIST,
	"target-name"},
	{TARGET_PARAM, MODIFY|REMOVE, LIST, 0, ADD, MODIFY,
	"target-name"},
	{DISCOVERY, 0, 0, LIST|MODIFY, ADD|REMOVE, 0, NULL},
	{NODE, 0, 0, MODIFY|LIST, ADD|REMOVE, 0, NULL},
	{STATIC_CONFIG, ADD|REMOVE, LIST, 0, MODIFY, ADD|REMOVE|LIST,
	"target-name,target-address[:port-number][,tpgt]"},
	{DISCOVERY_ADDRESS, ADD|REMOVE, LIST, 0, MODIFY,
	ADD|REMOVE|LIST, "IP-address[:port-number]"},
	{ISNS_SERVER_ADDRESS, ADD|REMOVE, LIST, 0, MODIFY,
	ADD|REMOVE|LIST, "IP-address[:port-number]"},
	{0, 0, 0, 0, 0, 0}
};

/*
 * list of objects, subcommands, valid short options, required flag and
 * exclusive option string
 *
 * If it's not here, there are no options for that object.
 */
optionRules_t optionRules[] = {
	{DISCOVERY, MODIFY, "sti", B_TRUE, NULL},
	{DISCOVERY_ADDRESS, LIST, "v", B_FALSE, NULL},
	{ISNS_SERVER_ADDRESS, LIST, "v", B_FALSE, NULL},
	{TARGET, LIST, "vS", B_FALSE, NULL},
	{NODE, MODIFY, "NAhdCaRrPHcT", B_TRUE, "CP"},
	{TARGET_PARAM, MODIFY, "ahdBCpcHT", B_TRUE, "C"},
	{TARGET_PARAM, LIST, "v", B_FALSE, NULL},
	{0, 0, 0, 0, 0}
};


static boolean_t
targetNamesEqual(wchar_t *name1, wchar_t *name2)
{
	int i;
	wchar_t wchar1, wchar2;

	if (name1 == NULL || name2 == NULL) {
		return (B_FALSE);
	}

	if (wcslen(name1) != wcslen(name2)) {
		return (B_FALSE);
	}

	/*
	 * Convert names to lower case and compare
	 */
	for (i = 0; i < wcslen(name1); i++) {
		wchar1 = towctrans((wint_t)name1[i], wctrans("tolower"));
		wchar2 = towctrans((wint_t)name2[i], wctrans("tolower"));

		if (wchar1 != wchar2) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
ipAddressesEqual(IMA_TARGET_ADDRESS addr1, IMA_TARGET_ADDRESS addr2)
{
#define	IPV4_ADDR_BYTES 4
#define	IPV6_ADDR_BYTES 16

	int compSize;

	if (addr1.hostnameIpAddress.id.ipAddress.ipv4Address !=
	    addr2.hostnameIpAddress.id.ipAddress.ipv4Address) {
		return (B_FALSE);
	}

	compSize = IPV6_ADDR_BYTES;
	if (addr1.hostnameIpAddress.id.ipAddress.ipv4Address) {
		compSize = IPV4_ADDR_BYTES;
	}

	if (bcmp(addr1.hostnameIpAddress.id.ipAddress.ipAddress,
	    addr2.hostnameIpAddress.id.ipAddress.ipAddress, compSize) == 0) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

static int
getLoginParam(char *arg)
{
	parameterTbl_t *paramp;
	int len;

	for (paramp = loginParams; paramp->name; paramp++) {
		len = strlen(arg);
		if (len == strlen(paramp->name) &&
		    strncasecmp(arg, paramp->name, len) == 0) {
			return (paramp->val);
		}
	}
	return (-1);
}

static int
getTunableParam(char *arg)
{
	parameterTbl_t *paramp;
	int len;

	for (paramp = tunableParams; paramp->name != NULL; paramp++) {
		len = strlen(arg);
		if (len == strlen(paramp->name) &&
		    strncasecmp(arg, paramp->name, len) == 0) {
			return (paramp->val);
		}
	}
	return (-1);
}

static void
printLibError(IMA_STATUS status)
{
	char *errorString;
	switch (status) {
	case IMA_ERROR_NOT_SUPPORTED:
		errorString =
		gettext("Operation currently not supported");
		break;
	case IMA_ERROR_INSUFFICIENT_MEMORY:
		errorString = gettext("Insufficient memory");
		break;
	case IMA_ERROR_UNEXPECTED_OS_ERROR:
		errorString = gettext("unexpected OS error");
		break;
	case IMA_ERROR_UNKNOWN_ERROR:
		errorString = gettext("Unknown error");
		break;
	case IMA_ERROR_LU_IN_USE:
		errorString = gettext("Logical unit in use");
		break;
	case IMA_ERROR_INVALID_PARAMETER:
		errorString = gettext("Invalid parameter specified");
		break;
	case IMA_ERROR_INVALID_OBJECT_TYPE:
		errorString =
		gettext("Internal library error: Invalid oid type specified");
		break;
	case IMA_ERROR_INCORRECT_OBJECT_TYPE:
		errorString =
		gettext("Internal library error: Incorrect oid type specified");
		break;
	case IMA_ERROR_OBJECT_NOT_FOUND:
		errorString = gettext("Internal library error: Oid not found");
		break;
	case IMA_ERROR_NAME_TOO_LONG:
		errorString = gettext("Name too long");
		break;
	default:
		errorString = gettext("Unknown error");
	}
	(void) fprintf(stderr, "%s: %s\n", cmdName, errorString);
}

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 * Returns:
 *  command name portion of execFullName
 */
static char *
getExecBasename(char *execFullname)
{
	char *lastSlash, *execBasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		lastSlash = strrchr(execFullname, '/');
		if (lastSlash == NULL) {
			execBasename = execFullname;
			break;
		} else {
			execBasename = lastSlash + 1;
			if (*execBasename == '\0') {
				*lastSlash = '\0';
				continue;
			}
			break;
		}
	}
	return (execBasename);
}


/*
 * input:
 *  nodeProps - pointer to caller allocated IMA_NODE_PROPERTIES
 *
 * returns:
 *  zero on success
 *  non-zero otherwise
 */
static int
getNodeProps(IMA_NODE_PROPERTIES *nodeProps)
{
	IMA_OID sharedNodeOid;

	IMA_STATUS status = IMA_GetSharedNodeOid(&sharedNodeOid);
	if (!(IMA_SUCCESS(status))) {
		printLibError(status);
		return (INF_ERROR);
	}

	status = IMA_GetNodeProperties(sharedNodeOid, nodeProps);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (INF_ERROR);
	}

	return (0);
}

/*
 * sunInitiatorFind
 * Purpose:
 *  Finds the Sun iSCSI initiator (LHBA). This CLI currently supports only
 *  one initiator.
 *
 * output:
 *  oid of initiator
 *
 * Returns:
 *  zero on success with initiator found
 *  > 0 on success with no initiator found
 *  < 0 on failure
 */
static int
sunInitiatorFind(IMA_OID *oid)
{
	IMA_OID_LIST *lhbaList = NULL;

	IMA_STATUS status = IMA_GetLhbaOidList(&lhbaList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (-1);
	}

	if ((lhbaList == NULL) || (lhbaList->oidCount == 0)) {
		printLibError(IMA_ERROR_OBJECT_NOT_FOUND);
		if (lhbaList != NULL)
			(void) IMA_FreeMemory(lhbaList);
		return (-1);
	}

	*oid = lhbaList->oids[0];
	(void) IMA_FreeMemory(lhbaList);

	return (0);
}

/*
 * input:
 *  wcInput - wide character string containing discovery address
 * output:
 *  address - IMA_TARGET_ADDRESS structure containing valid
 *	discovery address
 * returns:
 *  zero on success
 *  non-zero on failure
 */

static int
getTargetAddress(int addrType, char *ipStr, IMA_TARGET_ADDRESS *address)
{
	char cCol = ':';
	char cBracketL = '['; /* Open Bracket '[' */
	char cBracketR = ']'; /* Close Bracket ']' */
	char *colPos;
	char *startPos;
	unsigned long inputPort;
	int addressType = AF_INET;
	char *tmpStrPtr, tmpStr[SUN_IMA_IP_ADDRESS_PORT_LEN];
	int rval;

	/* Check if this is a ipv6 address */
	if (ipStr[0] == cBracketL) {
		addressType = AF_INET6;
		startPos = strchr(ipStr, cBracketR);
		if (!startPos) {
			(void) fprintf(stderr, "%s: %s: ']' %s\n",
			    cmdName, ipStr, gettext("missing"));
			return (1);
		}
		(void) strlcpy(tmpStr, ipStr+1, startPos-ipStr);
		address->hostnameIpAddress.id.ipAddress.ipv4Address = IMA_FALSE;
		tmpStrPtr = tmpStr;
	} else {
		/* set start position to beginning of input object */
		addressType = AF_INET;
		startPos = ipStr;
		address->hostnameIpAddress.id.ipAddress.ipv4Address = IMA_TRUE;
		tmpStrPtr = ipStr;
	}
	/* wcschr for ':'. If not there, use default port */
	colPos = strchr(startPos, cCol);

	if (!colPos) {
		if (addrType == DISCOVERY_ADDRESS) {
			inputPort = DEFAULT_ISCSI_PORT;
		} else if (addrType == ISNS_SERVER_ADDRESS) {
			inputPort = ISNS_DEFAULT_SERVER_PORT;
		} else {
			*colPos = '\0';
		}
	} else {
		*colPos = '\0';
	}

	rval = inet_pton(addressType, tmpStrPtr,
	    address->hostnameIpAddress.id.ipAddress.ipAddress);
	/* inet_pton returns 1 on success */
	if (rval != 1) {
		(void) fprintf(stderr, "%s: %s: %s\n", cmdName, ipStr,
		    gettext("invalid IP address"));
		return (1);
	}


	if (colPos) {
		char *errchr;

		colPos++;
		if (*colPos == '\0') {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, ipStr,
			    gettext("port number missing"));
			return (1);
		}

		/*
		 * convert port string to unsigned value
		 * Note:  Don't remove errno = 0 as you may get false failures.
		 */
		errno = 0;
		inputPort = strtol(colPos, &errchr, 10);
		if (errno != 0 || inputPort == 0 && errchr != NULL) {
			(void) fprintf(stderr, "%s: %s:%s %s\n",
			    cmdName, ipStr, colPos,
			    gettext("port number invalid"));
			return (1);
		}
		/* make sure it's in the range */
		if (inputPort > USHRT_MAX) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, ipStr,
			    gettext("port number out of range"));
			return (1);
		}
	}
	address->portNumber  = inputPort;

	return (0);
}

/*
 * Print results of send targets command
 */
static void
printSendTargets(SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *pList)
{
	char outBuf[INET6_ADDRSTRLEN];
	int inetSize;
	int af;
	int i;

	for (i = 0; i < pList->keyCount; i++) {
		if (pList->keys[i].address.ipAddress.ipv4Address == IMA_TRUE) {
			af = AF_INET;
			inetSize = INET_ADDRSTRLEN;
		} else {
			af = AF_INET6;
			inetSize = INET6_ADDRSTRLEN;
		}
		(void) fprintf(stdout, gettext("\tTarget name: %ws\n"),
		    pList->keys[i].name);
		(void) fprintf(stdout, "\t\t%s: %15s:%d", "Target address",
		    inet_ntop(af, &(pList->keys[i].address.ipAddress.ipAddress),
		    outBuf, inetSize), pList->keys[i].address.portNumber);
		(void) fprintf(stdout, ", %d", pList->keys[i].tpgt);
		(void) fprintf(stdout, "\n");
	}
}


/*
 * Print all login parameters
 */
static int
printLoginParameters(char *prefix, IMA_OID oid, int printOption)
{
	IMA_STATUS status;
	IMA_BOOL_VALUE propBool;
	IMA_MIN_MAX_VALUE propMinMax;
	char longString[MAX_LONG_CHAR_LEN + 1];
	SUN_IMA_CONN_PROPERTIES	*connProps = NULL;
	IMA_OID_LIST *pConnList;

	(void) memset(longString, 0, sizeof (longString));

	switch (printOption) {
		case PRINT_CONFIGURED_PARAMS:
			(void) fprintf(stdout, "%s%s:\n",
			    prefix,
			    gettext("Login Parameters (Default/Configured)"));
			break;
		case PRINT_NEGOTIATED_PARAMS:
			(void) fprintf(stdout, "%s%s:\n",
			    prefix,
			    gettext("Login Parameters (Negotiated)"));
			status = SUN_IMA_GetConnOidList(
			    &oid,
			    &pConnList);

			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				return (1);
			}

			status = SUN_IMA_GetConnProperties(&pConnList->oids[0],
			    &connProps);
			propBool.currentValueValid = connProps->valuesValid;
			propMinMax.currentValueValid = connProps->valuesValid;
			break;
		default:
			return (1);
	}

	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propBool.currentValue = connProps->dataSequenceInOrder;
	} else {
		status = IMA_GetDataSequenceInOrderProperties(oid, &propBool);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Data Sequence In Order"));
	IMABOOLPRINT(propBool, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propBool.currentValue = connProps->dataPduInOrder;
	} else {
		status = IMA_GetDataPduInOrderProperties(oid, &propBool);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Data PDU In Order"));
	IMABOOLPRINT(propBool, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->defaultTime2Retain;
	} else {
		status = IMA_GetDefaultTime2RetainProperties(oid, &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Default Time To Retain"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->defaultTime2Wait;
	} else {
		status = IMA_GetDefaultTime2WaitProperties(oid, &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Default Time To Wait"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->errorRecoveryLevel;
	} else {
		status = IMA_GetErrorRecoveryLevelProperties(oid, &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Error Recovery Level"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->firstBurstLength;
	} else {
		status = IMA_GetFirstBurstLengthProperties(oid,
		    &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ",
	    prefix, gettext("First Burst Length"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propBool.currentValue = connProps->immediateData;
	} else {
		status = IMA_GetImmediateDataProperties(oid, &propBool);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix, gettext("Immediate Data"));
	IMABOOLPRINT(propBool, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propBool.currentValue = connProps->initialR2T;
	} else {
		status = IMA_GetInitialR2TProperties(oid, &propBool);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Initial Ready To Transfer (R2T)"));
	IMABOOLPRINT(propBool, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->maxBurstLength;
	} else {
		status = IMA_GetMaxBurstLengthProperties(oid, &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix, gettext("Max Burst Length"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->maxOutstandingR2T;
	} else {
		status = IMA_GetMaxOutstandingR2TProperties(oid, &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Max Outstanding R2T"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->maxRecvDataSegmentLength;
	} else {
		status = IMA_GetMaxRecvDataSegmentLengthProperties(oid,
		    &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix,
	    gettext("Max Receive Data Segment Length"));
	IMAMINMAXPRINT(propMinMax, printOption);


	if (printOption == PRINT_NEGOTIATED_PARAMS) {
		propMinMax.currentValue = connProps->maxConnections;
	} else {
		status = IMA_GetMaxConnectionsProperties(oid, &propMinMax);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		(void) IMA_FreeMemory(connProps);
		return (1);
	}
	(void) fprintf(stdout, "%s\t%s: ", prefix, gettext("Max Connections"));
	IMAMINMAXPRINT(propMinMax, printOption);

	(void) IMA_FreeMemory(connProps);
	return (0);
}

/*
 * Print discovery information.
 */
static void
printDiscoveryMethod(char *prefix, IMA_UINT32 discoveryMethodFlags)
{
	(void) fprintf(stdout, "%s%s: ", prefix, gettext("Discovery Method"));
	if (discoveryMethodFlags == IMA_TARGET_DISCOVERY_METHOD_UNKNOWN) {
		(void) fprintf(stdout, "%s\n", gettext("NA"));
	} else {
		if (!((discoveryMethodFlags &
		    IMA_TARGET_DISCOVERY_METHOD_STATIC) ^
		    IMA_TARGET_DISCOVERY_METHOD_STATIC)) {
			(void) fprintf(stdout, "%s ", gettext("Static"));
		}
		if (!((discoveryMethodFlags &
		    IMA_TARGET_DISCOVERY_METHOD_SENDTARGETS) ^
		    IMA_TARGET_DISCOVERY_METHOD_SENDTARGETS)) {
			(void) fprintf(stdout, "%s ", gettext("SendTargets"));
		}
		if (!((discoveryMethodFlags &
		    IMA_TARGET_DISCOVERY_METHOD_ISNS) ^
		    IMA_TARGET_DISCOVERY_METHOD_ISNS)) {
			(void) fprintf(stdout, "%s ", gettext("iSNS"));
		}
		(void) fprintf(stdout, "\n");
	}
}

/*
 * printConnectionList - Prints the conection list provided
 */
static void
printConnectionList(char *prefix, IMA_OID_LIST *pConnList)
{
	IMA_STATUS		imaStatus;
	int			i;
	SUN_IMA_CONN_PROPERTIES	*connProps;
	union {
		char	ipv4[INET_ADDRSTRLEN+1];
		char	ipv6[INET6_ADDRSTRLEN+1];
	} tmp;

	for (i = 0; i < pConnList->oidCount; i++) {
		imaStatus = SUN_IMA_GetConnProperties(&pConnList->oids[i],
		    &connProps);

		if (imaStatus != IMA_STATUS_SUCCESS) {
			continue;
		}

		(void) fprintf(stdout, "%sCID: %d\n", prefix,
		    connProps->connectionID);

		(void) memset(&tmp, 0, sizeof (tmp));
		if (connProps->local.ipAddress.ipv4Address == IMA_TRUE) {
			if (inet_ntop(AF_INET,
			    &connProps->local.ipAddress.ipAddress[0],
			    &tmp.ipv4[0],
			    INET_ADDRSTRLEN)) {
				(void) fprintf(stdout,
				    "%s  %s: %s:%u\n",
				    prefix,
				    gettext("IP address (Local)"),
				    &tmp.ipv4[0],
				    ntohs(connProps->local.portNumber));
			}
		} else {
			if (inet_ntop(AF_INET6,
			    &connProps->local.ipAddress.ipAddress[0],
			    &tmp.ipv6[0],
			    INET6_ADDRSTRLEN)) {
				(void) fprintf(stdout,
				    "%s  %s: [%s]:%u\n",
				    prefix,
				    gettext("IP address (Local)"),
				    &tmp.ipv6[0],
				    ntohs(connProps->local.portNumber));
			}
		}
		if (connProps->peer.ipAddress.ipv4Address == IMA_TRUE) {
			if (inet_ntop(AF_INET,
			    &connProps->peer.ipAddress.ipAddress[0],
			    &tmp.ipv4[0],
			    INET_ADDRSTRLEN)) {
				(void) fprintf(stdout,
				    "%s  %s: %s:%u\n",
				    prefix,
				    gettext("IP address (Peer)"),
				    &tmp.ipv4[0],
				    ntohs(connProps->peer.portNumber));
			}
		} else {
			if (inet_ntop(AF_INET6,
			    &connProps->peer.ipAddress.ipAddress[0],
			    &tmp.ipv6[0],
			    INET6_ADDRSTRLEN)) {
				(void) fprintf(stdout,
				    "%s  %s: [%s]:%u\n",
				    prefix,
				    gettext("IP address (Peer)"),
				    &tmp.ipv6[0],
				    ntohs(connProps->peer.portNumber));
			}
		}

		(void) IMA_FreeMemory(connProps);
	}
}

/*
 * Set login parameters on a target or initiator
 */
static int
setLoginParameter(IMA_OID oid, int optval, char *optarg)
{
	IMA_STATUS status = IMA_STATUS_SUCCESS;
	IMA_UINT uintValue;
	IMA_BOOL boolValue;
	SUN_IMA_DIGEST_ALGORITHM digestAlgList[1];
	IMA_MIN_MAX_VALUE propMinMax;
	char *endptr;

	/*
	 * for clarity, there are two switch statements
	 * The first loads the variable and the second
	 * calls the appropriate API
	 */
	switch (optval) {
		case DATA_SEQ_IN_ORDER:
		case IMMEDIATE_DATA:
		case INITIAL_R2T:
		case DATA_PDU_IN_ORDER:
			/* implement 'default'? */
			if (strcasecmp(optarg, "yes") == 0) {
				boolValue = IMA_TRUE;
			} else if (strcasecmp(optarg, "no") == 0) {
				boolValue = IMA_FALSE;
			} else {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			break;
		case DEFAULT_TIME_2_RETAIN:
		case DEFAULT_TIME_2_WAIT:
			errno = 0;
			uintValue = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			if (uintValue > 3600) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
gettext("value must be between 0 and 3600"));
				return (1);
			}
			break;
		case FIRST_BURST_LENGTH:
		case MAX_BURST_LENGTH:
		case MAX_RECV_DATA_SEG_LEN:
			errno = 0;
			/* implement 'default'? */
			uintValue = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			if (uintValue < 512 || uintValue > 16777215) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
gettext("value must be between 512 and 16777215"));
				return (1);
			}
			break;
		case MAX_OUTSTANDING_R2T:
			errno = 0;
			uintValue = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			if (uintValue < 1 || uintValue > 65535) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
gettext("value must be between 1 and 65535"));
				return (1);
			}
			break;
		case HEADER_DIGEST:
		case DATA_DIGEST:
			if (strcasecmp(optarg, "none") == 0) {
				digestAlgList[0] = SUN_IMA_DIGEST_NONE;
			} else if (strcasecmp(optarg, "CRC32") == 0) {
				digestAlgList[0] = SUN_IMA_DIGEST_CRC32;
			} else {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			break;
		case MAX_CONNECTIONS:
			errno = 0;
			uintValue = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			if (uintValue < 1 || uintValue > 256) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
gettext("value must be between 1 and 256"));
				return (1);
			}
			break;
		case ERROR_RECOVERY_LEVEL:
			errno = 0;
			uintValue = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0' || errno != 0) {
				(void) fprintf(stderr, "%s: %s - %s\n",
				    cmdName,
				    gettext("invalid option argument"),
				    optarg);
				return (1);
			}
			if (uintValue > 2) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
gettext("value must be between 0 and 2"));
				return (1);
			}
			break;
		default:
			(void) fprintf(stderr, "%s: %c: %s\n",
			    cmdName, optval, gettext("unknown option"));
			return (1);
	}

	switch (optval) {
		case DATA_PDU_IN_ORDER:
			status = IMA_SetDataPduInOrder(oid, boolValue);
			break;
		case DATA_SEQ_IN_ORDER:
			status = IMA_SetDataSequenceInOrder(oid, boolValue);
			break;
		case DEFAULT_TIME_2_RETAIN:
			status = IMA_SetDefaultTime2Retain(oid, uintValue);
			break;
		case DEFAULT_TIME_2_WAIT:
			status = IMA_SetDefaultTime2Wait(oid, uintValue);
			break;
		case FIRST_BURST_LENGTH:
			status = IMA_SetFirstBurstLength(oid, uintValue);

			/*
			 * If this call fails check to see if it's because
			 * the requested value is > than maxBurstLength
			 */
			if (!IMA_SUCCESS(status)) {
				status = IMA_GetMaxBurstLengthProperties(oid,
				    &propMinMax);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					return (1);
				}
				if (uintValue > propMinMax.currentValue) {
					(void) fprintf(stderr,
					    "%s: %s\n", cmdName,
					    gettext("firstBurstLength must " \
					    "be less than or equal to than " \
					    "maxBurstLength"));
				}
				return (1);
			}

			break;
		case IMMEDIATE_DATA:
			status = IMA_SetImmediateData(oid, boolValue);
			break;
		case INITIAL_R2T:
			status = IMA_SetInitialR2T(oid, boolValue);
			break;
		case MAX_BURST_LENGTH:
			status = IMA_SetMaxBurstLength(oid, uintValue);
			/*
			 * If this call fails check to see if it's because
			 * the requested value is < than firstBurstLength
			 */
			if (!IMA_SUCCESS(status)) {
				status = IMA_GetFirstBurstLengthProperties(oid,
				    &propMinMax);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					return (1);
				}
				if (uintValue < propMinMax.currentValue) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("maxBurstLength must be " \
					    "greater than or equal to " \
					    "firstBurstLength"));
				}
				return (1);
			}
			break;

		case MAX_OUTSTANDING_R2T:
			status = IMA_SetMaxOutstandingR2T(oid, uintValue);
			break;
		case MAX_RECV_DATA_SEG_LEN:
			status = IMA_SetMaxRecvDataSegmentLength(oid,
			    uintValue);
			break;
		case HEADER_DIGEST:
			status = SUN_IMA_SetHeaderDigest(oid, 1,
			    &digestAlgList[0]);
			break;
		case DATA_DIGEST:
			status = SUN_IMA_SetDataDigest(oid, 1,
			    &digestAlgList[0]);
			break;
		case MAX_CONNECTIONS:
			status = IMA_SetMaxConnections(oid, uintValue);
			break;
		case ERROR_RECOVERY_LEVEL:
			status = IMA_SetErrorRecoveryLevel(oid, uintValue);
			break;
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (1);
	}
	return (0);
}

static void
printDigestAlgorithm(SUN_IMA_DIGEST_ALGORITHM_VALUE *digestAlgorithms,
    int printOption)
{
	int i;

	if (printOption == PRINT_CONFIGURED_PARAMS) {
		for (i = 0; i < digestAlgorithms->defaultAlgorithmCount; i++) {
			if (i > 0) {
				(void) fprintf(stdout, "|");
			}
			switch (digestAlgorithms->defaultAlgorithms[i]) {
				case SUN_IMA_DIGEST_NONE:
					(void) fprintf(stdout,
					    gettext("NONE"));
					break;
				case SUN_IMA_DIGEST_CRC32:
					(void) fprintf(stdout,
					    gettext("CRC32"));
					break;
				default:
					(void) fprintf(stdout,
					    gettext("Unknown"));
					break;
			}
		}
		(void) fprintf(stdout, "/");
		if (digestAlgorithms->currentValid == IMA_TRUE) {
			for (i = 0;
			    i < digestAlgorithms->currentAlgorithmCount; i++) {
				if (i > 0) {
					(void) fprintf(stdout, "|");
				}
				switch (digestAlgorithms->
				    currentAlgorithms[i]) {
					case SUN_IMA_DIGEST_NONE:
						(void) fprintf(stdout,
						    gettext("NONE"));
						break;
					case SUN_IMA_DIGEST_CRC32:
						(void) fprintf(stdout,
						    gettext("CRC32"));
						break;
					default:
						(void) fprintf(stdout,
						    gettext("Unknown"));
						break;
				}
			}
		} else {
			(void) fprintf(stdout, "-");
		}
		(void) fprintf(stdout, "\n");
	} else if (printOption == PRINT_NEGOTIATED_PARAMS) {

		if (digestAlgorithms->negotiatedValid == IMA_TRUE) {
			for (i = 0;
			    i < digestAlgorithms->negotiatedAlgorithmCount;
			    i++) {
				if (i > 0) {
					(void) fprintf(stdout, "|");
				}
				switch (digestAlgorithms->
				    negotiatedAlgorithms[i]) {
					case SUN_IMA_DIGEST_NONE:
						(void) fprintf(stdout,
						    gettext("NONE"));
						break;
					case SUN_IMA_DIGEST_CRC32:
						(void) fprintf(stdout,
						    gettext("CRC32"));
						break;
					default:
						(void) fprintf(stdout,
						    gettext("Unknown"));
						break;
				}
			}
		} else {
			(void) fprintf(stdout, "-");
		}
		(void) fprintf(stdout, "\n");
	}
}

static int
setLoginParameters(IMA_OID oid, char *optarg)
{
	char keyp[MAXOPTARGLEN];
	char valp[MAXOPTARGLEN];
	int key;
	char *nameValueString, *indexp, *delim = NULL;

	if ((nameValueString = strdup(optarg)) == NULL) {
		if (errno == ENOMEM) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, strerror(errno));
		} else {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown error"));
		}
		return (1);
	}

	indexp = nameValueString;

	/*
	 * Retrieve all login params from option argument
	 * Syntax <key=value,...>
	 */
	while (indexp) {
		if (delim = strchr(indexp, ',')) {
			delim[0] = '\0';
		}
		(void) memset(keyp, 0, sizeof (keyp));
		(void) memset(valp, 0, sizeof (valp));
		if (sscanf(indexp, gettext("%[^=]=%s"), keyp, valp) != 2) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    gettext("Unknown param"), indexp);
			if (nameValueString) {
				free(nameValueString);
				nameValueString = NULL;
			}
			return (1);
		}
		if ((key = getLoginParam(keyp)) == -1) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    gettext("Unknown key"), keyp);
			if (nameValueString) {
				free(nameValueString);
				nameValueString = NULL;
			}
			return (1);
		}
		if (setLoginParameter(oid, key, valp) != 0) {
			if (nameValueString) {
				free(nameValueString);
				nameValueString = NULL;
			}
			return (1);
		}
		if (delim) {
			indexp = delim + 1;
		} else {
			indexp = NULL;
		}
	}

	if (nameValueString) {
		free(nameValueString);
		nameValueString = NULL;
	}
	return (0);
}

/*
 * Print logical unit information for a specific target
 */
static void
printTargetLuns(IMA_OID_LIST * lunList)
{
	int	j;
	IMA_STATUS status;
	SUN_IMA_LU_PROPERTIES	lunProps;

	for (j = 0; j < lunList->oidCount; j++) {
		status = SUN_IMA_GetLuProperties(lunList->oids[j],
		    &lunProps);
		if (!IMA_SUCCESS(status)) {
			printLibError(status);
			return;
		}

		(void) fprintf(stdout, "\tLUN: %lld\n",
		    lunProps.imaProps.targetLun);
		(void) fprintf(stdout, "\t     Vendor:  %s\n",
		    lunProps.vendorId);
		(void) fprintf(stdout, "\t     Product: %s\n",
		    lunProps.productId);
		/*
		 * The lun is valid though the os Device Name is not.
		 * Give this information to users for judgement.
		 */
		if (lunProps.imaProps.osDeviceNameValid == IMA_TRUE) {
			(void) fprintf(stdout,
			    gettext("\t     OS Device Name: %ws\n"),
			    lunProps.imaProps.osDeviceName);
		} else {
			(void) fprintf(stdout,
			    gettext("\t     OS Device Name: Not"
			    " Available\n"));
		}
	}
}

/*
 * Retrieve CHAP secret from input
 */
static int
getSecret(char *secret, int *secretLen, int minSecretLen, int maxSecretLen)
{
	char *chapSecret;

	/* get password */
	chapSecret = getpassphrase(gettext("Enter secret:"));

	if (chapSecret == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Unable to get secret"));
		*secret = '\0';
		return (1);
	}

	if (strlen(chapSecret) > maxSecretLen) {
		(void) fprintf(stderr, "%s: %s %d\n", cmdName,
		    gettext("secret too long, maximum length is"),
		    maxSecretLen);
		*secret = '\0';
		return (1);
	}

	if (strlen(chapSecret) < minSecretLen) {
		(void) fprintf(stderr, "%s: %s %d\n", cmdName,
		    gettext("secret too short, minimum length is"),
		    minSecretLen);
		*secret = '\0';
		return (1);
	}

	(void) strcpy(secret, chapSecret);

	chapSecret = getpassphrase(gettext("Re-enter secret:"));

	if (chapSecret == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Unable to get secret"));
		*secret = '\0';
		return (1);
	}

	if (strcmp(secret, chapSecret) != 0) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("secrets do not match, secret not changed"));
		*secret = '\0';
		return (1);
	}
	*secretLen = strlen(chapSecret);
	return (0);
}

/*
 * Lists the discovery attributes
 */
static int
listDiscovery(int *funcRet)
{
	IMA_OID	initiatorOid;
	IMA_DISCOVERY_PROPERTIES discProps;
	int ret;
	IMA_STATUS status;

	assert(funcRet != NULL);


	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	/* Get discovery attributes from IMA */
	status = IMA_GetDiscoveryProperties(initiatorOid, &discProps);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}


	(void) fprintf(stdout, "%s:\n", "Discovery");
	(void) fprintf(stdout, "\tStatic: %s\n",
	    discProps.staticDiscoveryEnabled == IMA_TRUE ? \
	    gettext("enabled") : gettext("disabled"));
	(void) fprintf(stdout, "\tSend Targets: %s\n",
	    discProps.sendTargetsDiscoveryEnabled == IMA_TRUE ? \
	    gettext("enabled") : gettext("disabled"));
	(void) fprintf(stdout, "\tiSNS: %s\n",
	    discProps.iSnsDiscoveryEnabled == IMA_TRUE ? \
	    gettext("enabled") : gettext("disabled"));

	return (0);
}

/*
 * Print all initiator node attributes
 */
static int
listNode(int *funcRet)
{
	IMA_OID	initiatorOid;
	IMA_NODE_PROPERTIES nodeProps;
	IMA_STATUS status;
	int ret;
	IMA_UINT maxEntries = MAX_AUTH_METHODS;
	IMA_AUTHMETHOD	methodList[MAX_AUTH_METHODS];
	SUN_IMA_RADIUS_CONFIG radiusConfig;
	SUN_IMA_DIGEST_ALGORITHM_VALUE digestAlgorithms;
	IMA_BOOL radiusAccess;

	int i;

	assert(funcRet != NULL);

	ret = getNodeProps(&nodeProps);
	if (ret != 0) {
		return (ret);
	}

	if (nodeProps.nameValid == IMA_FALSE) {
		return (INVALID_NODE_NAME);
	}

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}
	/* Begin output */
	(void) fprintf(stdout, gettext("%s: %ws\n"),
	    gettext("Initiator node name"),
	    nodeProps.name);
	(void) fprintf(stdout, gettext("Initiator node alias: "));
	if (nodeProps.aliasValid == IMA_TRUE) {
		(void) fprintf(stdout, gettext("%ws\n"), nodeProps.alias);
	} else {
		(void) fprintf(stdout, "%s\n", "-");
	}
	(void) fprintf(stdout, "\t%s:\n",
	    gettext("Login Parameters (Default/Configured)"));

	/* Get Digest configuration */
	status = SUN_IMA_GetHeaderDigest(initiatorOid, &digestAlgorithms);
	if (IMA_SUCCESS(status)) {
		(void) fprintf(stdout, "\t\t%s: ", gettext("Header Digest"));
		printDigestAlgorithm(&digestAlgorithms,
		    PRINT_CONFIGURED_PARAMS);
	} else {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	status = SUN_IMA_GetDataDigest(initiatorOid, &digestAlgorithms);
	if (IMA_SUCCESS(status)) {
		(void) fprintf(stdout, "\t\t%s: ", gettext("Data Digest"));
		printDigestAlgorithm(&digestAlgorithms,
		    PRINT_CONFIGURED_PARAMS);
	} else {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	/* Get authentication type for this lhba */
	status = IMA_GetInUseInitiatorAuthMethods(initiatorOid, &maxEntries,
	    &methodList[0]);
	(void) fprintf(stdout, "\t%s: ", gettext("Authentication Type"));
	if (!IMA_SUCCESS(status)) {
		/* No authentication method set - default is NONE */
		(void) fprintf(stdout, gettext("NONE"));
	} else {
		for (i = 0; i < maxEntries; i++) {
			if (i > 0) {
				(void) fprintf(stdout, "|");
			}
			switch (methodList[i]) {
				case IMA_AUTHMETHOD_NONE:
					(void) fprintf(stdout, gettext("NONE"));
					break;
				case IMA_AUTHMETHOD_CHAP:
					(void) fprintf(stdout, gettext("CHAP"));
					listCHAPName(initiatorOid);
					break;
				default:
					(void) fprintf(stdout,
					    gettext("unknown type"));
					break;
			}
		}
	}
	(void) fprintf(stdout, "\n");


	/* Get RADIUS configuration */
	status = SUN_IMA_GetInitiatorRadiusConfig(initiatorOid, &radiusConfig);
	(void) fprintf(stdout, "\t%s: ", gettext("RADIUS Server"));
	if (IMA_SUCCESS(status)) {
		if (strlen(radiusConfig.hostnameIpAddress) > 0) {
			(void) fprintf(stdout, "%s:%d",
			    radiusConfig.hostnameIpAddress,
			    radiusConfig.port);
		} else {
			(void) fprintf(stdout, "%s", gettext("NONE"));
		}
	} else {
		(void) fprintf(stdout, "%s", gettext("NONE"));
	}
	(void) fprintf(stdout, "\n");

	status = SUN_IMA_GetInitiatorRadiusAccess(initiatorOid,
	    &radiusAccess);
	(void) fprintf(stdout, "\t%s: ", gettext("RADIUS Access"));
	if (IMA_SUCCESS(status)) {
		if (radiusAccess == IMA_TRUE) {
			(void) fprintf(stdout, "%s", gettext("enabled"));
		} else {
			(void) fprintf(stdout, "%s", gettext("disabled"));
		}
	} else if (status == IMA_ERROR_OBJECT_NOT_FOUND) {
		(void) fprintf(stdout, "%s", gettext("disabled"));
	} else {
		(void) fprintf(stdout, "%s", gettext("unknown"));
	}
	(void) fprintf(stdout, "\n");

	/* print tunable parameters information. */
	ret = printTunableParameters(initiatorOid);

	/* print configured session information. */
	ret = printConfiguredSessions(initiatorOid);

	return (ret);
}

/*
 * Print discovery addresses
 */
static int
listDiscoveryAddress(int objectLen, char *objects[], cmdOptions_t *options,
    int *funcRet)
{
	IMA_OID	initiatorOid;
	SUN_IMA_DISC_ADDR_PROP_LIST *discoveryAddressPropertiesList;
	IMA_DISCOVERY_ADDRESS_PROPERTIES discAddrProps;
	IMA_TARGET_ADDRESS address;
	SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *pList;
	IMA_STATUS status;
	wchar_t wcInputObject[MAX_ADDRESS_LEN + 1];
	int ret;
	boolean_t object = B_FALSE;
	int outerLoop;
	boolean_t found;
	boolean_t verbose = B_FALSE;
	int i, j;
	cmdOptions_t *optionList = options;
	char sAddr[SUN_IMA_IP_ADDRESS_PORT_LEN];

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	/*
	 * If there are multiple objects, execute outer 'for' loop that
	 * many times for each target detail, otherwise, execute it only
	 * once with summaries only
	 */
	if (objectLen > 0) {
		object = B_TRUE;
		outerLoop = objectLen;
	} else {
		object = B_FALSE;
		outerLoop = 1;
	}

	status = SUN_IMA_GetDiscoveryAddressPropertiesList(
	    &discoveryAddressPropertiesList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < outerLoop; i++) {
		if (object) {
			/* initialize */
			(void) memset(&wcInputObject[0], 0,
			    sizeof (wcInputObject));
			(void) memset(&address, 0, sizeof (address));
			if (mbstowcs(wcInputObject, objects[i],
			    (MAX_ADDRESS_LEN + 1)) == (size_t)-1) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
				    gettext("conversion error"));
				ret = 1;
				continue;
			}

			/*
			 * if one or more objects were input,
			 * get the values
			 */
			if (getTargetAddress(DISCOVERY_ADDRESS,
			    objects[i], &address) != 0) {
				ret = 1;
				continue;
			}
		}
		for (found = B_FALSE, j = 0;
		    j < discoveryAddressPropertiesList->discAddrCount;
		    j++) {
			discAddrProps =
			    discoveryAddressPropertiesList->props[j];

			/*
			 * Compare the discovery address with the input if
			 * one was input
			 */
			if (object &&
			    ipAddressesEqual(discAddrProps.discoveryAddress,
			    address) && (discAddrProps.discoveryAddress.
			    portNumber == address.portNumber)) {
				found = B_TRUE;
			}

			if (!object || found) {
				/* Print summary - always */
				if (discAddrProps.discoveryAddress.
				    hostnameIpAddress.id.ipAddress.
				    ipv4Address) {
					(void) inet_ntop(AF_INET, discAddrProps.
					    discoveryAddress.hostnameIpAddress.
					    id.ipAddress.ipAddress, sAddr,
					    sizeof (sAddr));
					(void) fprintf(stdout,
					    "Discovery Address: %s:%u\n",
					    sAddr, discAddrProps.
					    discoveryAddress.portNumber);
				} else {
					(void) inet_ntop(AF_INET6,
					    discAddrProps.
					    discoveryAddress.hostnameIpAddress.
					    id.ipAddress.ipAddress, sAddr,
					    sizeof (sAddr));
					(void) fprintf(stdout,
					    "DiscoveryAddress: [%s]:%u\n",
					    sAddr, discAddrProps.
					    discoveryAddress.portNumber);
				}
			}

			if ((!object || found) && verbose) {
				IMA_NODE_PROPERTIES nodeProps;

				if (getNodeProps(&nodeProps) != 0) {
					break;
				}

				/*
				 * Issue sendTargets only when an addr is
				 * specified.
				 */
				status = SUN_IMA_SendTargets(nodeProps.name,
				    discAddrProps.discoveryAddress, &pList);
				if (!IMA_SUCCESS(status)) {
					(void) fprintf(stderr, "%s\n",
					    gettext("\tUnable to get "\
					    "targets."));
					*funcRet = 1;
					continue;
				}
				printSendTargets(pList);
			}

			if (found) {
				/* we found the discovery address - break */
				break;
			}
		}
		/*
		 * There was an object entered but we didn't
		 * find it.
		 */
		if (object && !found) {
			(void) fprintf(stdout, "%s: %s\n",
			    objects[i], gettext("not found"));
		}
	}
	return (ret);
}

/*
 * Print ISNS Server addresses
 */
static int
listISNSServerAddress(int objectLen, char *objects[], cmdOptions_t *options,
    int *funcRet)
{
	IMA_OID	initiatorOid;
	SUN_IMA_DISC_ADDR_PROP_LIST	    *discoveryAddressPropertiesList;
	IMA_DISCOVERY_ADDRESS_PROPERTIES discAddrProps;
	IMA_TARGET_ADDRESS address;
	SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *pList;
	IMA_STATUS status;
	wchar_t wcInputObject[MAX_ADDRESS_LEN + 1];
	int ret;
	boolean_t object = B_FALSE;
	int outerLoop;
	boolean_t found;
	boolean_t showTarget = B_FALSE;
	int i, j;
	cmdOptions_t *optionList = options;
	char sAddr[SUN_IMA_IP_ADDRESS_PORT_LEN];

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				showTarget = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	/*
	 * If there are multiple objects, execute outer 'for' loop that
	 * many times for each target detail, otherwise, execute it only
	 * once with summaries only
	 */
	if (objectLen > 0) {
		object = B_TRUE;
		outerLoop = objectLen;
	} else {
		object = B_FALSE;
		outerLoop = 1;
	}

	status = SUN_IMA_GetISNSServerAddressPropertiesList(
	    &discoveryAddressPropertiesList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < outerLoop; i++) {
		if (object) {
			/* initialize */
			(void) memset(&wcInputObject[0], 0,
			    sizeof (wcInputObject));
			(void) memset(&address, 0, sizeof (address));
			if (mbstowcs(wcInputObject, objects[i],
			    (MAX_ADDRESS_LEN + 1)) == (size_t)-1) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName,
				    gettext("conversion error"));
				ret = 1;
				continue;
			}

			/*
			 * if one or more objects were input,
			 * get the values
			 */
			if (getTargetAddress(ISNS_SERVER_ADDRESS,
			    objects[i], &address) != 0) {
				ret = 1;
				continue;
			}
		}
		for (found = B_FALSE, j = 0;
		    j < discoveryAddressPropertiesList->discAddrCount;
		    j++) {
			discAddrProps =
			    discoveryAddressPropertiesList->props[j];

			/*
			 * Compare the discovery address with the input if
			 * one was input
			 */
			if (object &&
			    ipAddressesEqual(discAddrProps.discoveryAddress,
			    address) &&
			    (discAddrProps.discoveryAddress.portNumber ==
			    address.portNumber)) {
				found = B_TRUE;
			}

			if (!object || found) {
				/* Print summary - always */
				if (discAddrProps.discoveryAddress.
				    hostnameIpAddress.id.ipAddress.
				    ipv4Address) {
					(void) inet_ntop(AF_INET, discAddrProps.
					    discoveryAddress.hostnameIpAddress.
					    id.ipAddress.ipAddress, sAddr,
					    sizeof (sAddr));
				} else {
					(void) inet_ntop(AF_INET6,
					    discAddrProps.
					    discoveryAddress.hostnameIpAddress.
					    id.ipAddress.ipAddress, sAddr,
					    sizeof (sAddr));
				}
				(void) fprintf(stdout,
				    "iSNS Server IP Address: %s:%u\n",
				    sAddr,
				    discAddrProps.discoveryAddress.portNumber);
			}

			if ((!object || found) && showTarget) {
				IMA_NODE_PROPERTIES nodeProps;

				if (getNodeProps(&nodeProps) != 0) {
					break;
				}

				/*
				 * Issue sendTargets only when an addr is
				 * specified.
				 */
				status = SUN_IMA_RetrieveISNSServerTargets(
				    discAddrProps.discoveryAddress,
				    &pList);
				if (!IMA_SUCCESS(status)) {
					/*
					 * Check if the discovery mode is
					 * disabled.
					 */
					if (status ==
					    IMA_ERROR_OBJECT_NOT_FOUND) {
						(void) fprintf(stderr, "%s\n",
						    gettext("\tiSNS "\
						    "discovery "\
						    "mode "\
						    "disabled. "\
						    "No targets "\
						    "to report."));

					} else {
						(void) fprintf(stderr, "%s\n",
						    gettext("\tUnable "\
						    "to get "\
						    "targets."));
					}
					continue;
				}
				printSendTargets(pList);
			}

			if (found) {
				/* we found the discovery address - break */
				break;
			}
		}
		/*
		 * There was an object entered but we didn't
		 * find it.
		 */
		if (object && !found) {
			(void) fprintf(stdout, "%s: %s\n",
			    objects[i], gettext("not found"));
		}
	}
	return (ret);
}

/*
 * Print static configuration targets
 */
static int
listStaticConfig(int operandLen, char *operand[], int *funcRet)
{
	IMA_STATUS status;
	IMA_OID	initiatorOid;
	IMA_OID_LIST *staticTargetList;
	SUN_IMA_STATIC_TARGET_PROPERTIES staticTargetProps;
	wchar_t staticTargetName[MAX_ISCSI_NAME_LEN + 1];
	wchar_t staticTargetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	wchar_t wcCol;
	char sAddr[SUN_IMA_IP_ADDRESS_PORT_LEN];
	int ret;
	boolean_t object = B_FALSE;
	int outerLoop;
	boolean_t found; /* B_TRUE if a target name is found */
	boolean_t matched; /* B_TRUE if a specific target is found */
	boolean_t targetAddressSpecified = B_FALSE;
	boolean_t tpgtSpecified = B_FALSE;
	boolean_t isIpv6;
	int i, j;
	IMA_UINT16 port = 0;
	IMA_UINT16 tpgt = 0;
	char tmpStr[SUN_IMA_IP_ADDRESS_PORT_LEN];
	wchar_t tmpTargetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	/*
	 * If there are multiple objects, execute outer 'for' loop that
	 * many times for each static config detail, otherwise, execute it only
	 * once with summaries only
	 */
	if (operandLen > 0) {
		object = B_TRUE;
		outerLoop = operandLen;
	} else {
		object = B_FALSE;
		outerLoop = 1;
	}

	/* convert ':' to wide char for wchar string search */
	if (mbtowc(&wcCol, ":", sizeof (wcCol)) == -1) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("conversion error"));
		return (1);
	}

	status = IMA_GetStaticDiscoveryTargetOidList(initiatorOid,
	    &staticTargetList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < outerLoop; i++) {
		if (object) {
			if (parseTarget(operand[i],
			    &staticTargetName[0],
			    MAX_ISCSI_NAME_LEN + 1,
			    &targetAddressSpecified,
			    &staticTargetAddress[0],
			    SUN_IMA_IP_ADDRESS_PORT_LEN,
			    &port,
			    &tpgtSpecified,
			    &tpgt,
			    &isIpv6) != PARSE_TARGET_OK) {
				ret = 1;
				continue;
			}
		}

		for (found = B_FALSE, j = 0; j < staticTargetList->oidCount;
		    j++) {
			boolean_t isIpv6 = B_FALSE;
			IMA_UINT16 stpgt;
			IMA_BOOL defaultTpgt;

			matched = B_FALSE;
			(void) memset(&staticTargetProps, 0,
			    sizeof (staticTargetProps));

			status = SUN_IMA_GetStaticTargetProperties(
			    staticTargetList->oids[j], &staticTargetProps);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				(void) IMA_FreeMemory(staticTargetList);
				*funcRet = 1;
				return (ret);
			}

			stpgt = staticTargetProps.staticTarget.targetAddress.
			    tpgt;

			defaultTpgt = staticTargetProps.staticTarget.
			    targetAddress.defaultTpgt;

			isIpv6 = !staticTargetProps.staticTarget.targetAddress.
			    imaStruct.hostnameIpAddress.id.ipAddress.
			    ipv4Address;

			/*
			 * Compare the static target name with the input if
			 * one was input
			 */

			if (object &&
			    (targetNamesEqual(
			    staticTargetProps.staticTarget.targetName,
			    staticTargetName) == B_TRUE)) {
				/* targetName found - found = B_TRUE */
				found = B_TRUE;
				if (targetAddressSpecified == B_FALSE) {
					matched = B_TRUE;
				} else {

				if (staticTargetProps.staticTarget.
				    targetAddress.imaStruct.
				    hostnameIpAddress.id.ipAddress.
				    ipv4Address == IMA_TRUE) {
					(void) inet_ntop(AF_INET,
					    staticTargetProps.
					    staticTarget.targetAddress.
					    imaStruct.hostnameIpAddress.id.
					    ipAddress.ipAddress, tmpStr,
					    sizeof (tmpStr));
				} else {
					(void) inet_ntop(AF_INET6,
					    staticTargetProps.
					    staticTarget.targetAddress.
					    imaStruct.hostnameIpAddress.id.
					    ipAddress.ipAddress, tmpStr,
					    sizeof (tmpStr));
				}

				if (mbstowcs(tmpTargetAddress, tmpStr,
				    SUN_IMA_IP_ADDRESS_PORT_LEN) ==
				    (size_t)-1) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					gettext("conversion error"));
					ret = 1;
					continue;
				}

				if (wcsncmp(tmpTargetAddress,
				    staticTargetAddress,
				    SUN_IMA_IP_ADDRESS_PORT_LEN)
				    == 0 &&
				    staticTargetProps.
				    staticTarget.targetAddress.
				    imaStruct.portNumber == port) {
					/*
					 * Since an object is
					 * specified, it should also
					 * have a tpgt specified. If
					 * not, that means the object
					 * specified is associated with
					 * the default tpgt. In
					 * either case, a tpgt
					 * comparison should be done
					 * before claiming that a
					 * match is found.
					 */
					if ((tpgt == stpgt &&
					    tpgtSpecified == B_TRUE &&
					    defaultTpgt == IMA_FALSE) ||
					    (tpgt == stpgt &&
					    tpgtSpecified == B_FALSE &&
					    defaultTpgt == IMA_TRUE)) {
						matched = B_TRUE;
					}
				}

				}
			}

			if (!object || matched) {
				/* print summary - always */
				(void) fprintf(stdout, gettext("%s: %ws,"),
				    "Static Configuration Target",
				    staticTargetProps.staticTarget.targetName);

				if (isIpv6 == B_FALSE) {
					(void) inet_ntop(AF_INET,
					    staticTargetProps.
					    staticTarget.targetAddress.
					    imaStruct.hostnameIpAddress.id.
					    ipAddress.ipAddress, sAddr,
					    sizeof (sAddr));
					(void) fprintf(stdout, "%s:%d",
					    sAddr,
					    staticTargetProps.staticTarget.
					    targetAddress.imaStruct.portNumber);
				} else {
					(void) inet_ntop(AF_INET6,
					    staticTargetProps.
					    staticTarget.targetAddress.
					    imaStruct.hostnameIpAddress.id.
					    ipAddress.ipAddress, sAddr,
					    sizeof (sAddr));
					(void) fprintf(stdout, "[%s]:%d",
					    sAddr,
					    staticTargetProps.staticTarget.
					    targetAddress.imaStruct.portNumber);
				}

				if (staticTargetProps.staticTarget.
				    targetAddress.
				    defaultTpgt == IMA_FALSE) {
					(void) fprintf(stdout, ",%d\n",
					    staticTargetProps.
					    staticTarget.targetAddress.tpgt);
				} else {
					(void) fprintf(stdout, "\n");
				}
			}

		}
		/*
		 * No details to display, but if there were:
		 *  if (object && found)...
		 *
		 */

		/*
		 * There was an object entered but we didn't
		 * find it.
		 */
		if (object && !found) {
			(void) fprintf(stdout, "%s: %s\n",
			    operand[i], gettext("not found"));
			ret = 1; /* DIY test fix */
		}
	}
	return (ret);
}

/*
 * Print targets
 */
/*ARGSUSED*/
static int
listTarget(int objectLen, char *objects[], cmdOptions_t *options, int *funcRet)
{
	IMA_OID	initiatorOid;
	IMA_OID_LIST *targetList;
	IMA_OID_LIST *lunList;
	SUN_IMA_TARGET_PROPERTIES targetProps;
	IMA_STATUS status;
	IMA_OID_LIST *pConnList;
	SUN_IMA_CONN_PROPERTIES *connProps;

	int ret;
	wchar_t targetName[MAX_ISCSI_NAME_LEN + 1];
	wchar_t targetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	int outerLoop;
	boolean_t found;
	boolean_t operandEntered = B_FALSE;
	boolean_t verbose = B_FALSE;
	boolean_t scsi_target = B_FALSE;
	boolean_t targetAddressSpecified = B_FALSE;
	boolean_t isIpv6 = B_FALSE;
	int i, j;
	cmdOptions_t *optionList = options;
	boolean_t tpgtSpecified = B_FALSE;
	IMA_UINT16 port = 0;
	uint16_t tpgt;

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'S':
				scsi_target = B_TRUE;
				break;
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	/*
	 * If there are multiple objects, execute outer 'for' loop that
	 * many times for each target detail, otherwise, execute it only
	 * once with summaries only
	 */
	if (objectLen > 0) {
		operandEntered = B_TRUE;
		outerLoop = objectLen;
	} else {
		operandEntered = B_FALSE;
		outerLoop = 1;
	}

	status = SUN_IMA_GetSessionOidList(initiatorOid, &targetList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < outerLoop; i++) {

		tpgtSpecified = B_FALSE;
		if (operandEntered) {
			if (parseTarget(objects[i],
			    &targetName[0],
			    MAX_ISCSI_NAME_LEN + 1,
			    &targetAddressSpecified,
			    &targetAddress[0],
			    SUN_IMA_IP_ADDRESS_PORT_LEN,
			    &port,
			    &tpgtSpecified,
			    &tpgt,
			    &isIpv6) != PARSE_TARGET_OK) {
				ret = 1;
				continue;
			}
		}
		for (found = B_FALSE, j = 0; j < targetList->oidCount; j++) {
			status = SUN_IMA_GetTargetProperties(
			    targetList->oids[j],
			    &targetProps);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				(void) IMA_FreeMemory(targetList);
				*funcRet = 1;
				return (ret);
			}

			/*
			 * Compare the target name with the input if
			 * one was input, if they match, print the target's info
			 *
			 * if no target name was input, continue printing this
			 * target
			 */
			if (operandEntered) {
				if (targetNamesEqual(targetProps.imaProps.name,
				    targetName) == B_TRUE) {
					if (tpgtSpecified == B_TRUE) {
						if (targetProps.
						    defaultTpgtConf ==
						    IMA_FALSE &&
						    targetProps.
						    tpgtConf == tpgt) {
							found = B_TRUE;
						} else {
							/*
							 * tpgt does not match,
							 * move on to next
							 * target
							 */
							continue;
						}
					} else {
						found = B_TRUE;
					}
				} else {
					/*
					 * target name does not match, move on
					 * to next target
					 */
					continue;
				}
			}

			/* print summary - always */
			(void) fprintf(stdout, gettext("%s: %ws\n"),
			    gettext("Target"), targetProps.imaProps.name);

			/* Alias */
			(void) fprintf(stdout, "\t%s: ", gettext("Alias"));
			if (wslen(targetProps.imaProps.alias) > (size_t)0) {
				(void) fprintf(stdout, gettext("%ws\n"),
				    targetProps.imaProps.alias);
			} else {
				(void) fprintf(stdout, "%s\n", "-");
			}

			if (targetProps.defaultTpgtNego != IMA_TRUE) {
				(void) fprintf(stdout, "%s%s: %d\n",
				    "\t", gettext("TPGT"),
				    targetProps.tpgtNego);
			} else if (targetProps.defaultTpgtConf != IMA_TRUE) {
				(void) fprintf(stdout, "%s%s: %d\n",
				    "\t", gettext("TPGT"),
				    targetProps.tpgtConf);
			}

			(void) fprintf(stdout,
			    "%s%s: %02x%02x%02x%02x%02x%02x\n",
			    "\t", gettext("ISID"),
			    targetProps.isid[0], targetProps.isid[1],
			    targetProps.isid[2], targetProps.isid[3],
			    targetProps.isid[4], targetProps.isid[5]);

			pConnList = NULL;
			status = SUN_IMA_GetConnOidList(
			    &targetList->oids[j],
			    &pConnList);

			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				(void) IMA_FreeMemory(targetList);
				*funcRet = 1;
				return (ret);
			}

			(void) fprintf(stdout, "%s%s: %lu\n",
			    "\t",
			    gettext("Connections"),
			    pConnList->oidCount);

			if (verbose) {
				SUN_IMA_DIGEST_ALGORITHM_VALUE digestAlgorithms;

				printConnectionList("\t\t", pConnList);
				printDiscoveryMethod(
				    "\t\t  ",
				    targetProps.imaProps.discoveryMethodFlags);
				(void) printLoginParameters(
				    "\t\t  ",
				    targetList->oids[j],
				    PRINT_NEGOTIATED_PARAMS);

				/* Get Digest configuration */
				status = SUN_IMA_GetConnProperties(
				    &pConnList->oids[0], &connProps);

				(void) getNegotiatedDigest(
				    ISCSI_LOGIN_PARAM_HEADER_DIGEST,
				    &digestAlgorithms, connProps);

				if (IMA_SUCCESS(status)) {
					(void) fprintf(stdout, "\t\t  \t%s: ",
					    gettext("Header Digest"));
					printDigestAlgorithm(
					    &digestAlgorithms,
					    PRINT_NEGOTIATED_PARAMS);
				} else {
					(void) IMA_FreeMemory(pConnList);
					(void) IMA_FreeMemory(targetList);
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}

				(void) getNegotiatedDigest(
				    ISCSI_LOGIN_PARAM_DATA_DIGEST,
				    &digestAlgorithms, connProps);

				if (IMA_SUCCESS(status)) {
					(void) fprintf(stdout, "\t\t  \t%s: ",
					    gettext("Data Digest"));
					printDigestAlgorithm(
					    &digestAlgorithms,
					    PRINT_NEGOTIATED_PARAMS);
				} else {
					(void) IMA_FreeMemory(pConnList);
					(void) IMA_FreeMemory(targetList);
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}

				(void) fprintf(stdout, "\n");
			}

			if (scsi_target) {
				status = SUN_IMA_ReEnumeration(
				    targetList->oids[j]);
				if (!IMA_SUCCESS(status)) {
					/*
					 * Proceeds the listing
					 * but indicates the
					 * error in return value
					 */
					ret = 1;
				}

				status = IMA_GetLuOidList(
				    targetList->oids[j],
				    &lunList);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					(void) IMA_FreeMemory(targetList);
					*funcRet = 1;
					return (ret);
				}
				if (lunList->oidCount != 0) {
					printTargetLuns(lunList);
				}
				(void) fprintf(stdout, "\n");
				(void) IMA_FreeMemory(lunList);
			}
		}
		/*
		 * did we find the object
		 */

		if (operandEntered && !found) {
			(void) fprintf(stdout, "%s: %s\n",
			    objects[i], gettext("not found"));
		}
	}

	(void) IMA_FreeMemory(targetList);
	return (ret);
}


/*
 * Print configured session information
 */
static int
printConfiguredSessions(IMA_OID oid)
{
	IMA_STATUS		status;
	const char		*rtn;
	SUN_IMA_CONFIG_SESSIONS	*pConfigSessions;
	char			address[MAX_ADDRESS_LEN];
	int			out;

	/* Get configured session information */
	status = SUN_IMA_GetConfigSessions(oid, &pConfigSessions);

	if (IMA_SUCCESS(status)) {
		(void) fprintf(stdout, "\t%s: ",
		    gettext("Configured Sessions"));
		if (pConfigSessions->bound == IMA_FALSE) {
			/* default binding */
			(void) fprintf(stdout, "%lu\n", pConfigSessions->out);
		} else {
			/* hardcoded binding */
			for (out = 0;
			    out < pConfigSessions->out; out++) {
				if (pConfigSessions->bindings[out].
				    ipAddress.ipv4Address == IMA_TRUE) {
					rtn = inet_ntop(AF_INET,
					    pConfigSessions->bindings[out].
					    ipAddress.ipAddress, address,
					    MAX_ADDRESS_LEN);
				} else {
					rtn = inet_ntop(AF_INET6,
					    pConfigSessions->bindings[out].
					    ipAddress.ipAddress, address,
					    MAX_ADDRESS_LEN);
				}
				if (rtn != NULL) {
					(void) printf("%s ", address);
				}
			}
			(void) fprintf(stdout, "\n");
		}
	} else {
		free(pConfigSessions);
		printLibError(status);
		return (1);
	}

	free(pConfigSessions);
	return (0);
}

/*
 * Print target parameters
 */
static int
listTargetParam(int operandLen, char *operand[], cmdOptions_t *options,
    int *funcRet)
{
	IMA_STATUS status;
	IMA_OID	initiatorOid;
	IMA_OID_LIST *targetList;
	IMA_AUTHMETHOD	methodList[MAX_AUTH_METHODS];
	SUN_IMA_TARGET_PROPERTIES targetProps;
	IMA_UINT maxEntries = MAX_AUTH_METHODS;
	IMA_BOOL bidirAuth;
	int ret;
	wchar_t targetName[MAX_ISCSI_NAME_LEN + 1];
	wchar_t targetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	boolean_t operandEntered = B_FALSE;
	boolean_t targetAddressSpecified = B_FALSE;
	boolean_t printObject = B_FALSE;
	boolean_t tpgtSpecified = B_FALSE;
	boolean_t isIpv6 = B_FALSE;
	int outerLoop;
	boolean_t found;
	int i, j;
	SUN_IMA_DIGEST_ALGORITHM_VALUE digestAlgorithms;
	boolean_t verbose = B_FALSE;
	cmdOptions_t *optionList = options;
	IMA_UINT16 port = 0;
	IMA_UINT16 tpgt = 0;

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	/*
	 * If there are multiple operands, execute outer 'for' loop that
	 * many times to find each target parameter operand entered, otherwise,
	 * execute it only once for all target parameters returned.
	 */
	if (operandLen > 0) {
		operandEntered = B_TRUE;
		outerLoop = operandLen;
	} else {
		operandEntered = B_FALSE;
		outerLoop = 1;
	}

	/*
	 * Ideally there should be an interface available for obtaining
	 * the list of target-param objects. Since the driver currently
	 * creates a target OID and the associated session structure when
	 * a target-param object is created, we can leverage the target
	 * OID list and use it to manage the target-param objects. When
	 * we stop creating a session for target-param object in the
	 * driver, we will switch to using a different interface to
	 * obtain target-param objects.
	 */
	status = IMA_GetTargetOidList(initiatorOid, &targetList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < outerLoop; i++) {
		if (operandEntered) {
			if (parseTarget(operand[i],
			    &targetName[0],
			    MAX_ISCSI_NAME_LEN + 1,
			    &targetAddressSpecified,
			    &targetAddress[0],
			    SUN_IMA_IP_ADDRESS_PORT_LEN,
			    &port,
			    &tpgtSpecified,
			    &tpgt,
			    &isIpv6) != PARSE_TARGET_OK) {
				ret = 1;
				continue;
			}
		}
		for (j = 0; j < targetList->oidCount; j++) {
			found = B_FALSE;
			printObject = B_FALSE;
			status = SUN_IMA_GetTargetProperties(
			    targetList->oids[j],
			    &targetProps);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				(void) IMA_FreeMemory(targetList);
				*funcRet = 1;
				return (ret);
			}

			/*
			 * Compare the target name with the input if
			 * one was input
			 */
			if (operandEntered &&
			    (targetNamesEqual(targetProps.imaProps.name,
			    targetName) == B_TRUE)) {
				/*
				 * For now, regardless of whether a target
				 * address is specified, we return B_TRUE
				 * because IMA_TARGET_PROPERTIES does not
				 * have a field for specifying address.
				 */
				found = B_TRUE;
			}

			/*
			 * if no operand was entered OR
			 * an operand was entered and it was
			 * found, we want to print
			 */
			if (!operandEntered || found) {
				printObject = B_TRUE;
			}

			if (printObject) {
				(void) fprintf(stdout, gettext("%s: %ws\n"),
				    gettext("Target"),
				    targetProps.imaProps.name);

				(void) fprintf(stdout,
				    "\t%s: ", gettext("Alias"));
				if (wslen(targetProps.imaProps.alias) >
				    (size_t)0) {
					(void) fprintf(stdout,
					    gettext("%ws\n"),
					    targetProps.imaProps.alias);
				} else {
					(void) fprintf(stdout, "%s\n", "-");
				}
			}

			if (printObject && verbose) {
				/* Get bidirectional authentication flag */
				(void) fprintf(stdout, "\t%s: ",
				    gettext("Bi-directional Authentication"));
				status = SUN_IMA_GetTargetBidirAuthFlag(
				    targetList->oids[j],
				    &bidirAuth);
				if (IMA_SUCCESS(status)) {
					if (bidirAuth == IMA_TRUE) {
						(void) fprintf(stdout,
						    gettext("enabled"));
					} else {
						(void) fprintf(stdout,
						    gettext("disabled"));
					}
				} else {
					(void) fprintf(stdout,
					    gettext("disabled"));
				}
				(void) fprintf(stdout, "\n");

				/* Get authentication type for this target */
				status = SUN_IMA_GetTargetAuthMethods(
				    initiatorOid,
				    targetList->oids[j],
				    &maxEntries,
				    &methodList[0]);
				(void) fprintf(stdout, "\t%s: ",
				    gettext("Authentication Type"));
				if (!IMA_SUCCESS(status)) {
					/*
					 * No authentication method define
					 * NONE by default.
					 */
					(void) fprintf(stdout, gettext("NONE"));
				} else {
					for (i = 0; i < maxEntries; i++) {
						if (i > 0) {
							(void) fprintf(stdout,
							    "|");
						}
						switch (methodList[i]) {
						case IMA_AUTHMETHOD_NONE:
							(void) fprintf(stdout,
							    gettext("NONE"));
							break;

						case IMA_AUTHMETHOD_CHAP:
							(void) fprintf(stdout,
							    gettext("CHAP"));
							listCHAPName(
							    targetList->
							    oids[j]);
							break;

						default:
							(void) fprintf(stdout,
							    gettext(
							    "unknown "
							    "type"));
							break;
						}
					}
				}
				(void) fprintf(stdout, "\n");
				if (printLoginParameters("\t",
				    targetList->oids[j],
				    PRINT_CONFIGURED_PARAMS)
				    != 0) {
					(void) IMA_FreeMemory(targetList);
					*funcRet = 1;
					return (ret);
				}

				/* Get Digest configuration */
				status = SUN_IMA_GetHeaderDigest(
				    targetList->oids[j],
				    &digestAlgorithms);
				if (IMA_SUCCESS(status)) {
					(void) fprintf(stdout, "\t\t%s: ",
					    gettext("Header Digest"));
					printDigestAlgorithm(&digestAlgorithms,
					    PRINT_CONFIGURED_PARAMS);
				} else {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}

				status = SUN_IMA_GetDataDigest(
				    targetList->oids[j],
				    &digestAlgorithms);
				if (IMA_SUCCESS(status)) {
					(void) fprintf(stdout, "\t\t%s: ",
					    gettext("Data Digest"));
					printDigestAlgorithm(&digestAlgorithms,
					    PRINT_CONFIGURED_PARAMS);
				} else {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}

				/* print tunable parameters infomation */
				if (printTunableParameters(
				    targetList->oids[j]) != 0) {
					*funcRet = 1;
					return (ret);
				}

				/* print configured session information */
				if (printConfiguredSessions(
				    targetList->oids[j]) != 0) {
					*funcRet = 1;
					return (ret);
				}

				(void) fprintf(stdout, "\n");
			}

			if (found) {
				break;
			}
		}
		if (operandEntered && !found) {
			*funcRet = 1; /* DIY message fix */
			(void) fprintf(stdout, "%s: %s\n",
			    operand[i], gettext("not found"));
		}
	}

	(void) IMA_FreeMemory(targetList);
	return (ret);
}

/*
 * Modify discovery attributes
 */
static int
modifyDiscovery(cmdOptions_t *options, int *funcRet)
{
	IMA_OID oid;
	IMA_STATUS status;
	IMA_BOOL setDiscovery;
	IMA_HOST_ID hostId;

	int ret;
	cmdOptions_t *optionList = options;

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&oid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	for (; optionList->optval; optionList++) {
		/* check optarg and set bool accordingly */
		if (strcasecmp(optionList->optarg, ISCSIADM_ARG_ENABLE) == 0) {
			setDiscovery = IMA_TRUE;
		} else if (strcasecmp(optionList->optarg, ISCSIADM_ARG_DISABLE)
		    == 0) {
			setDiscovery = IMA_FALSE;
		} else {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("invalid option argument"));
			return (1);
		}

		switch (optionList->optval) {
			case 's':
				/* Set static discovery */
				status = IMA_SetStaticDiscovery(oid,
				    setDiscovery);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}
				break;
			case 't':
				/* Set send targets discovery */
				status = IMA_SetSendTargetsDiscovery(oid,
				    setDiscovery);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}
				break;
			case 'i':
				/* Set iSNS discovery */
				(void) memset(&hostId, 0, sizeof (hostId));
				status = IMA_SetIsnsDiscovery(oid, setDiscovery,
				    IMA_ISNS_DISCOVERY_METHOD_STATIC, &hostId);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	return (ret);
}

/*
 * Set the initiator node's authentication method
 */
static int
modifyNodeAuthParam(IMA_OID oid, int param, char *chapName, int *funcRet)
{
	IMA_INITIATOR_AUTHPARMS authParams;
	IMA_STATUS status;
	int ret;
	int secretLen = MAX_CHAP_SECRET_LEN;
	int nameLen = 0;

	IMA_BYTE chapSecret[MAX_CHAP_SECRET_LEN + 1];

	assert(funcRet != NULL);

	/*
	 * Start with existing parameters and modify with the desired change
	 * before passing along.  We ignore any failures as they probably
	 * are caused by non-existence of auth params for the given node.
	 */
	status = IMA_GetInitiatorAuthParms(oid, IMA_AUTHMETHOD_CHAP,
	    &authParams);

	switch (param) {
	case AUTH_NAME:
		if (chapName == NULL) {
			(void) fprintf(stderr, "CHAP name cannot be NULL.\n");
			return (1);
		}
		nameLen = strlen(chapName);
		if (nameLen == 0) {
			(void) fprintf(stderr, "CHAP name cannot be empty.\n");
			return (1);
		}
		if (nameLen > ISCSI_MAX_C_USER_LEN) {
			(void) fprintf(stderr, "CHAP name is too long.\n");
			return (1);
		}
		(void) memset(&authParams.chapParms.name, 0,
		    sizeof (authParams.chapParms.name));
		(void) memcpy(&authParams.chapParms.name,
		    &chapName[0], nameLen);
		authParams.chapParms.nameLength = nameLen;
		break;

	case AUTH_PASSWORD :
		ret = getSecret((char *)&chapSecret[0], &secretLen,
		    MIN_CHAP_SECRET_LEN, MAX_CHAP_SECRET_LEN);

		if (ret != 0) {
			return (ret);
		}

		(void) memset(&authParams.chapParms.challengeSecret, 0,
		    sizeof (authParams.chapParms.challengeSecret));
		(void) memcpy(&authParams.chapParms.challengeSecret,
		    &chapSecret[0], secretLen);
		authParams.chapParms.challengeSecretLength = secretLen;
		break;

	default:
		(void) fprintf(stderr, "Invalid auth parameter %d\n", param);
		return (1);
	}

	status = IMA_SetInitiatorAuthParms(oid, IMA_AUTHMETHOD_CHAP,
	    &authParams);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}
	return (ret);
}

/*
 * Set the target's authentication method
 */
static int
modifyTargetAuthParam(IMA_OID oid, int param, char *chapName, int *funcRet)
{
	IMA_INITIATOR_AUTHPARMS authParams;
	IMA_STATUS status;
	int ret;
	int secretLen = MAX_CHAP_SECRET_LEN;
	int nameLen = 0;

	IMA_BYTE chapSecret[MAX_CHAP_SECRET_LEN + 1];

	assert(funcRet != NULL);

	/*
	 * Start with existing parameters and modify with the desired change
	 * before passing along.  We ignore any get failures as they probably
	 * are caused by non-existence of auth params for the given target.
	 */
	status = SUN_IMA_GetTargetAuthParms(oid, IMA_AUTHMETHOD_CHAP,
	    &authParams);

	switch (param) {
	case AUTH_NAME:
		if (chapName == NULL) {
			(void) fprintf(stderr, "CHAP name cannot be NULL.\n");
			return (1);
		}
		nameLen = strlen(chapName);
		if (nameLen == 0) {
			(void) fprintf(stderr, "CHAP name cannot be empty.\n");
			return (1);
		}
		if (nameLen > ISCSI_MAX_C_USER_LEN) {
			(void) fprintf(stderr, "CHAP name is too long.\n");
			return (1);
		}
		(void) memset(&authParams.chapParms.name, 0,
		    sizeof (authParams.chapParms.name));
		(void) memcpy(&authParams.chapParms.name,
		    &chapName[0], nameLen);
		authParams.chapParms.nameLength = nameLen;
		break;

	case AUTH_PASSWORD :
		ret = getSecret((char *)&chapSecret[0], &secretLen,
		    1, MAX_CHAP_SECRET_LEN);

		if (ret != 0) {
			return (ret);
		}

		(void) memset(&authParams.chapParms.challengeSecret, 0,
		    sizeof (authParams.chapParms.challengeSecret));
		(void) memcpy(&authParams.chapParms.challengeSecret,
		    &chapSecret[0], secretLen);
		authParams.chapParms.challengeSecretLength = secretLen;
		break;

	default:
		(void) fprintf(stderr, "Invalid auth parameter %d\n", param);
		return (1);
	}

	status = SUN_IMA_SetTargetAuthParams(oid, IMA_AUTHMETHOD_CHAP,
	    &authParams);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}
	return (0);
}

static int
modifyTargetBidirAuthFlag(IMA_OID targetOid, char *optarg, int *funcRet)
{
	IMA_BOOL boolValue;
	IMA_STATUS status;

	assert(funcRet != NULL);

	if (strcasecmp(optarg, ISCSIADM_ARG_ENABLE) == 0) {
		boolValue = IMA_TRUE;
	} else if (strcasecmp(optarg, ISCSIADM_ARG_DISABLE) == 0) {
		boolValue = IMA_FALSE;
	} else {
		(void) fprintf(stderr, "%s: %s %s\n",
		    cmdName, gettext("invalid option argument"), optarg);
		return (1);
	}

	status = SUN_IMA_SetTargetBidirAuthFlag(targetOid, &boolValue);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}
	return (0);
}

static int
modifyConfiguredSessions(IMA_OID targetOid, char *optarg)
{
	SUN_IMA_CONFIG_SESSIONS *pConfigSessions;
	IMA_STATUS		status;
	int			sessions;
	int			size;
	char			tmp[1024];
	boolean_t		isIpv6 = B_FALSE;
	uint16_t		port;
	char			address[MAX_ADDRESS_LEN];
	char			*commaPos;
	char			*addressPos;
	int			rtn;

	/*
	 * Strip the first int value from the string.  If we sprintf
	 * this back to a string and it matches the original string
	 * then this command is using default binding.  If not a
	 * match we have hard coded binding or a usage error.
	 */
	sessions = atoi(optarg);
	(void) sprintf(tmp, "%d", sessions);
	if (strcmp(optarg, tmp) == 0) {
		/* default binding */

		/* allocate the required pConfigSessions */
		size = sizeof (SUN_IMA_CONFIG_SESSIONS);
		pConfigSessions = (SUN_IMA_CONFIG_SESSIONS *)calloc(1, size);
		if (pConfigSessions == NULL) {
			return (1);
		}

		/* setup pConfigSessions */
		pConfigSessions->bound	= IMA_FALSE;
		pConfigSessions->in	= sessions;
		pConfigSessions->out	= 0;
	} else {
		/* hardcoded binding */

		/*
		 * First we need to determine how many bindings
		 * are available.  This can be done by scanning
		 * for the number of ',' + 1.
		 */
		sessions = 1;
		commaPos = strchr(optarg, ',');
		while (commaPos != NULL) {
			sessions++;
			commaPos = strchr(++commaPos, ',');
		}

		/* allocate the required pConfigSessions */
		size = sizeof (SUN_IMA_CONFIG_SESSIONS) + ((sessions - 1) *
		    sizeof (IMA_ADDRESS_KEY));
		pConfigSessions = (SUN_IMA_CONFIG_SESSIONS *)calloc(1, size);
		if (pConfigSessions == NULL) {
			return (1);
		}

		/* setup pConfigSessions */
		pConfigSessions->bound	= IMA_TRUE;
		pConfigSessions->in	= sessions;
		pConfigSessions->out	= 0;

		/* Now fill in the binding information.  */
		sessions = 0;
		addressPos = optarg;
		/*
		 * Walk thru possible address strings
		 * stop once all strings are processed.
		 */
		while (addressPos != NULL) {
			/*
			 * Check if there is another address after this
			 * one. If so terminate the current address and
			 * keep a pointer to the next one.
			 */
			commaPos = strchr(addressPos, ',');
			if (commaPos != NULL) {
				*commaPos++ = 0x00;
			}

			/*
			 * Parse current address.  If invalid abort
			 * processing of addresses and free memory.
			 */
			if (parseAddress(addressPos, 0, address,
			    MAX_ADDRESS_LEN, &port, &isIpv6) != PARSE_ADDR_OK) {
				free(pConfigSessions);
				printLibError(IMA_ERROR_INVALID_PARAMETER);
				return (1);
			}

			/* Convert address into binary form */
			if (isIpv6 == B_FALSE) {
				pConfigSessions->bindings[sessions].
				    ipAddress.ipv4Address = IMA_TRUE;
				rtn = inet_pton(AF_INET, address,
				    pConfigSessions->bindings[sessions].
				    ipAddress.ipAddress);
			} else {
				pConfigSessions->bindings[sessions].ipAddress.
				    ipv4Address =
				    IMA_FALSE;
				rtn = inet_pton(AF_INET6, address,
				    pConfigSessions->bindings[sessions].
				    ipAddress.ipAddress);
			}
			if (rtn == 0) {
				/* inet_pton found address invalid */
				free(pConfigSessions);
				printLibError(IMA_ERROR_INVALID_PARAMETER);
				return (1);
			}

			/* update addressPos to next address */
			sessions++;
			addressPos = commaPos;
		}
	}

	/* issue SUN_IMA request */
	status = SUN_IMA_SetConfigSessions(targetOid,
	    pConfigSessions);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		free(pConfigSessions);
		return (1);
	}

	free(pConfigSessions);
	return (0);
}

static int
getAuthMethodValue(char *method, IMA_AUTHMETHOD *value)
{
	if (strcasecmp(method, "chap") == 0) {
		*value = IMA_AUTHMETHOD_CHAP;
		return (0);
	}

	if (strcasecmp(method, "none") == 0) {
		*value =  IMA_AUTHMETHOD_NONE;
		return (0);
	}

	return (1);
}


/*
 * Set the authentication method
 * Currently only supports CHAP and NONE
 */
static int
modifyNodeAuthMethod(IMA_OID oid, char *optarg, int *funcRet)
{
	IMA_AUTHMETHOD methodList[MAX_AUTH_METHODS];
	IMA_UINT methodCount = 0;
	IMA_STATUS status;
	IMA_AUTHMETHOD value;
	char *method;
	char *commaPos;

	assert(funcRet != NULL);

	/*
	 * optarg will be a , delimited set of auth methods, in order
	 * of preference
	 * if any values here are incorrect, return without setting
	 * anything.
	 */
	method = optarg;

	commaPos = strchr(optarg, ',');

	while (commaPos && methodCount < MAX_AUTH_METHODS) {
		*commaPos = '\0';
		if (getAuthMethodValue(method, &value) != 0) {
			(void) fprintf(stderr, "%s: a: %s\n",
			    cmdName, gettext("invalid option argument"));
			return (1);
		}
		methodList[methodCount++] = value;
		commaPos++;
		method = commaPos;
		commaPos = strchr(method, ',');
	}
	/* Should not find more method specified - if found, error */
	if (commaPos) {
		(void) fprintf(stderr, "%s: -a: %s\n",
		    cmdName, gettext("invalid option argument"));
		return (1);
	}
	if (getAuthMethodValue(method, &value) != 0) {
		(void) fprintf(stderr, "%s: -a: %s\n",
		    cmdName, gettext("invalid option argument"));
		return (1);
	}
	methodList[methodCount++] = value;

	status = IMA_SetInitiatorAuthMethods(oid, methodCount, &methodList[0]);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}
	return (0);
}

static int
modifyTargetAuthMethod(IMA_OID oid, char *optarg, int *funcRet)
{
	IMA_AUTHMETHOD methodList[MAX_AUTH_METHODS];
	IMA_UINT methodCount = 0;
	IMA_STATUS status;
	IMA_AUTHMETHOD value;
	char *method;
	char *commaPos;

	assert(funcRet != NULL);

	/*
	 * optarg will be a , delimited set of auth methods, in order
	 * of preference
	 * if any values here are incorrect, return without setting
	 * anything.
	 */
	method = optarg;

	commaPos = strchr(optarg, ',');

	while (commaPos && methodCount < MAX_AUTH_METHODS) {
		*commaPos = '\0';
		if (getAuthMethodValue(method, &value) != 0) {
			(void) fprintf(stderr, "%s: a: %s\n",
			    cmdName, gettext("invalid option argument"));
			return (1);
		}
		methodList[methodCount++] = value;
		commaPos++;
		method = commaPos;
		commaPos = strchr(method, ',');
	}
	/* Should not find more method specified - if found, error */
	if (commaPos) {
		(void) fprintf(stderr, "%s: -a: %s\n",
		    cmdName, gettext("invalid option argument"));
		return (1);
	}
	if (getAuthMethodValue(method, &value) != 0) {
		(void) fprintf(stderr, "%s: -a: %s\n",
		    cmdName, gettext("invalid option argument"));
		return (1);
	}
	methodList[methodCount++] = value;

	status = SUN_IMA_SetTargetAuthMethods(oid, &methodCount,
	    &methodList[0]);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}
	return (0);
}

/*
 * Modify the RADIUS configuration of the initiator node.
 *
 * Return 0 on success.
 */
static int
modifyNodeRadiusConfig(IMA_OID oid, char *optarg, int *funcRet)
{
	SUN_IMA_RADIUS_CONFIG config;
	IMA_STATUS status;
	boolean_t isIpv6 = B_FALSE;
	uint16_t port;

	assert(funcRet != NULL);

	(void) memset(&config, 0, sizeof (SUN_IMA_RADIUS_CONFIG));
	if (parseAddress(optarg, DEFAULT_RADIUS_PORT,
	    &config.hostnameIpAddress[0], SUN_IMA_IP_ADDRESS_PORT_LEN,
	    &port, &isIpv6) !=
	    PARSE_ADDR_OK) {
		return (1);
	}
	config.port = (IMA_UINT16)port;
	config.isIpv6 = (isIpv6 == B_TRUE) ? IMA_TRUE : IMA_FALSE;
	/* Not setting shared secret here. */
	config.sharedSecretValid = IMA_FALSE;

	status = SUN_IMA_SetInitiatorRadiusConfig(oid, &config);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}

	return (0);
}

/*
 * Modify the RADIUS access flag of the initiator node.
 *
 * Return 0 on success.
 */
static int
modifyNodeRadiusAccess(IMA_OID oid, char *optarg, int *funcRet)
{
	IMA_BOOL radiusAccess;
	IMA_OID initiatorOid;
	IMA_STATUS status;
	SUN_IMA_RADIUS_CONFIG radiusConfig;
	int ret;

	assert(funcRet != NULL);

	/* Check if Radius Config is there */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret != 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
		return (1);
	}
	(void) memset(&radiusConfig, 0, sizeof (SUN_IMA_RADIUS_CONFIG));
	status = SUN_IMA_GetInitiatorRadiusConfig(initiatorOid, &radiusConfig);
	if (!IMA_SUCCESS(status)) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("RADIUS server not configured yet"));
		*funcRet = 1;
		return (ret);
	}

	/* Check if Radius Shared is set */
	if (radiusConfig.sharedSecretValid == IMA_FALSE) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("RADIUS server secret not configured yet"));
		return (1);
	}

	if (strcasecmp(optarg, ISCSIADM_ARG_ENABLE) == 0) {
		radiusAccess = IMA_TRUE;
	} else if (strcasecmp(optarg, ISCSIADM_ARG_DISABLE) == 0) {
		radiusAccess = IMA_FALSE;
	} else {
		(void) fprintf(stderr, "%s: %s %s\n",
		    cmdName,
		    gettext("invalid option argument"),
		    optarg);
		return (1);
	}
	status = SUN_IMA_SetInitiatorRadiusAccess(oid, radiusAccess);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}

	return (ret);
}

/*
 * Modify the RADIUS shared secret.
 *
 * Returns:
 *  zero on success.
 *  > 0 on failure.
 */
static int
modifyNodeRadiusSharedSecret(IMA_OID oid, int *funcRet)
{
	IMA_BYTE radiusSharedSecret[SUN_IMA_MAX_RADIUS_SECRET_LEN + 1];
	IMA_OID initiatorOid;
	IMA_STATUS status;
	SUN_IMA_RADIUS_CONFIG radiusConfig;
	int ret;
	int secretLen = SUN_IMA_MAX_RADIUS_SECRET_LEN;

	assert(funcRet != NULL);

	ret = getSecret((char *)&radiusSharedSecret[0], &secretLen,
	    0, SUN_IMA_MAX_RADIUS_SECRET_LEN);
	if (ret != 0) {
		return (1);
	}

	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}
	if (ret != 0) {
		return (1);
	}
	/* First obtain existing RADIUS configuration (if any) */
	(void) memset(&radiusConfig, 0, sizeof (SUN_IMA_RADIUS_CONFIG));
	status = SUN_IMA_GetInitiatorRadiusConfig(initiatorOid, &radiusConfig);
	if (!IMA_SUCCESS(status)) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("RADIUS server not configured yet"));
		return (1);
	}

	/* Modify the shared secret only */
	radiusConfig.sharedSecretLength = secretLen;
	(void) memcpy(&radiusConfig.sharedSecret,
	    &radiusSharedSecret[0], secretLen);
	radiusConfig.sharedSecretValid = IMA_TRUE;
	status = SUN_IMA_SetInitiatorRadiusConfig(oid, &radiusConfig);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
	}

	return (0);
}

/*
 * Set initiator node attributes.
 */
static int
modifyNode(cmdOptions_t *options, int *funcRet)
{
	IMA_NODE_NAME	nodeName;
	IMA_NODE_ALIAS	nodeAlias;
	IMA_OID		oid;
	IMA_STATUS	status;
	cmdOptions_t	*optionList = options;
	int		ret;
	iSCSINameCheckStatusType nameCheckStatus;
	IMA_OID sharedNodeOid;
	int		i;
	int		lowerCase;
	IMA_BOOL	iscsiBoot = IMA_FALSE;
	IMA_BOOL	mpxioEnabled = IMA_FALSE;
	char		*mb_name = NULL;
	int		prefixlen = 0;

	assert(funcRet != NULL);

	/* Get boot session's info */
	(void) SUN_IMA_GetBootIscsi(&iscsiBoot);
	if (iscsiBoot == IMA_TRUE) {
		status = SUN_IMA_GetBootMpxio(&mpxioEnabled);
		if (!IMA_SUCCESS(status)) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unable to get MPxIO info"
			    " of root disk"));
			*funcRet = 1;
			return (1);
		}
	}

	/* Find Sun initiator */
	ret = sunInitiatorFind(&oid);
	if (ret != 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
		return (ret);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'N':
				if (strlen(optionList->optarg) >=
				    MAX_ISCSI_NAME_LEN) {
					(void) fprintf(stderr, "%s: %s %d\n",
					    cmdName,
					    gettext("name too long, \
					    maximum length is:"),
					    MAX_ISCSI_NAME_LEN);
				}

				/* Take the first operand as node name. */
				(void) memset(&nodeName, 0,
				    sizeof (IMA_NODE_NAME));
				if (mbstowcs(nodeName, optionList->optarg,
				    IMA_NODE_NAME_LEN) == (size_t)-1) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("conversion error"));
					return (1);
				}

				prefixlen = strlen(ISCSI_IQN_NAME_PREFIX);
				mb_name = (char *)calloc(1, prefixlen + 1);
				if (mb_name == NULL) {
					return (1);
				}

				if (wcstombs(mb_name, nodeName,
				    prefixlen) == (size_t)-1) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("conversion error"));
					(void) IMA_FreeMemory(mb_name);
					return (1);
				}
				if (strncmp(mb_name, ISCSI_IQN_NAME_PREFIX,
				    prefixlen) == 0) {
					/*
					 * For iqn format, we should map
					 * the upper-case characters to
					 * their lower-case equivalents.
					 */
					for (i = 0; nodeName[i] != 0; i++) {
						lowerCase =
						    tolower(nodeName[i]);
						nodeName[i] = lowerCase;
					}
				}
				(void) IMA_FreeMemory(mb_name);

				/* Perform string profile checks */
				nameCheckStatus =
				    iSCSINameStringProfileCheck(nodeName);
				iSCSINameCheckStatusDisplay(nameCheckStatus);
				if (nameCheckStatus != iSCSINameCheckOK) {
					*funcRet = 1; /* DIY message fix */
					return (1);
				}

				/*
				 * IMA_GetSharedNodeOid(&sharedNodeOid);
				 * if (!IMA_SUCCESS(status)) {
				 *   printLibError(status);
				 *   return (INF_ERROR);
				 * }
				 */
				if (iscsiBoot == IMA_TRUE) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot, not"
					    " allowed to change"
					    " initiator's name"));
					return (1);
				}
				oid.objectType = IMA_OBJECT_TYPE_NODE;
				status = IMA_SetNodeName(oid, nodeName);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}
				break;

			case 'A':
				if (iscsiBoot == IMA_TRUE) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot, not"
					    " allowed to change"
					    " initiator's alias"));
					return (1);
				}
				/* Take the first operand as node alias. */
				if (strlen(optionList->optarg) >=
				    MAX_ISCSI_NAME_LEN) {
					(void) fprintf(stderr, "%s: %s %d\n",
					    cmdName,
					    gettext("alias too long, maximum  \
					    length is:"),
					    MAX_ISCSI_NAME_LEN);
				}

				(void) memset(&nodeAlias, 0,
				    sizeof (IMA_NODE_ALIAS));
				if (mbstowcs(nodeAlias, optionList->optarg,
				    IMA_NODE_ALIAS_LEN) == (size_t)-1) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("conversion error"));
					return (1);
				}

				status = IMA_GetSharedNodeOid(&sharedNodeOid);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}

				status = IMA_SetNodeAlias(sharedNodeOid,
				    nodeAlias);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					*funcRet = 1;
					return (ret);
				}
				break;

			case 'a':
				if (iscsiBoot == IMA_TRUE) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot, not"
					    " allowed to change authentication"
					    " method"));
					return (1);
				}
				if (modifyNodeAuthMethod(oid, options->optarg,
				    funcRet) != 0) {
					return (1);
				}
				break;

			case 'R':
				if (modifyNodeRadiusAccess(oid, options->optarg,
				    funcRet) != 0) {
					return (1);
				}
				break;

			case 'r':
				if (modifyNodeRadiusConfig(oid, options->optarg,
				    funcRet) != 0) {
					return (1);
				}
				break;

			case 'P':
				if (modifyNodeRadiusSharedSecret(oid, funcRet)
				    != 0) {
					return (1);
				}
				break;

			case 'C':
				if (iscsiBoot == IMA_TRUE) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot, not"
					    " allowed to change CHAP secret"));
					return (1);
				}
				if (modifyNodeAuthParam(oid, AUTH_PASSWORD,
				    NULL, funcRet) != 0) {
					return (1);
				}
				break;

			case 'c':
				if (iscsiBoot == IMA_TRUE) {
					if (mpxioEnabled == IMA_FALSE) {
						(void) fprintf(stderr,
						    "%s: %s\n", cmdName,
						    gettext("iscsi"
						    " boot and MPxIO"
						    " is disabled, not allowed"
						    " to change number of"
						    " sessions to be"
						    " configured"));
						return (1);
					}
				}
				if (modifyConfiguredSessions(oid,
				    optionList->optarg) != 0) {
					if (iscsiBoot == IMA_TRUE) {
						(void) fprintf(stderr,
						    "%s: %s\n", cmdName,
						    gettext("iscsi boot,"
						    " fail to set configured"
						    " session"));
					}
					return (1);
				}
				break;


			case 'H':
				if (iscsiBoot == IMA_TRUE) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot, not"
					    " allowed to change CHAP name"));
					return (1);
				}
				if (modifyNodeAuthParam(oid, AUTH_NAME,
				    optionList->optarg, funcRet) != 0) {
					return (1);
				}
				break;


			case 'd':
				if (iscsiBoot == IMA_TRUE) {
					if (mpxioEnabled == IMA_FALSE) {
						(void) fprintf(stderr,
						    "%s: %s\n", cmdName,
						    gettext("iscsi"
						    " boot and MPxIO"
						    " is disabled, not"
						    " allowed to"
						    " change initiator's"
						    " login params"));
						return (1);
					}
				}
				if (setLoginParameter(oid, DATA_DIGEST,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;

			case 'h':
				if (iscsiBoot == IMA_TRUE) {
					if (mpxioEnabled == IMA_FALSE) {
						(void) fprintf(stderr,
						    "%s: %s\n", cmdName,
						    gettext("iscsi"
						    " boot and MPxIO"
						    " is disabled, not"
						    " allowed to"
						    " change initiator's"
						    " login params"));
						return (1);
					}
				}
				if (setLoginParameter(oid, HEADER_DIGEST,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;

			case 'T':
				if (setTunableParameters(oid,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				break;
		}
	}

	return (ret);
}

/*
 * Modify target parameters
 */
static int
modifyTargetParam(cmdOptions_t *options, char *targetName, int *funcRet)
{
	IMA_OID oid;
	IMA_OID targetOid;
	IMA_STATUS status;
	IMA_OID_LIST *targetList;
	SUN_IMA_TARGET_PROPERTIES targetProps;
	wchar_t wcInputObject[MAX_ISCSI_NAME_LEN + 1];
	wchar_t targetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	int ret;
	boolean_t found;
	boolean_t targetAddressSpecified = B_TRUE;
	boolean_t tpgtSpecified = B_FALSE;
	boolean_t isIpv6 = B_FALSE;
	int i;
	iSCSINameCheckStatusType nameCheckStatus;
	IMA_UINT16 port = 0;
	IMA_UINT16 tpgt = 0;

	IMA_NODE_NAME bootTargetName;
	IMA_INITIATOR_AUTHPARMS bootTargetCHAP;
	IMA_BOOL  iscsiBoot;
	IMA_BOOL  mpxioEnabled;

	cmdOptions_t *optionList = options;

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&oid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	if (parseTarget(targetName,
	    &wcInputObject[0],
	    MAX_ISCSI_NAME_LEN + 1,
	    &targetAddressSpecified,
	    &targetAddress[0],
	    SUN_IMA_IP_ADDRESS_PORT_LEN,
	    &port,
	    &tpgtSpecified,
	    &tpgt,
	    &isIpv6) != PARSE_TARGET_OK) {
		return (1);
	}

	/* Perform string profile checks */
	nameCheckStatus = iSCSINameStringProfileCheck(wcInputObject);
	iSCSINameCheckStatusDisplay(nameCheckStatus);
	if (nameCheckStatus != iSCSINameCheckOK) {
		return (1);
	}

	status = IMA_GetTargetOidList(oid, &targetList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (0);
	}

	(void) SUN_IMA_GetBootIscsi(&iscsiBoot);
	if (iscsiBoot == IMA_TRUE) {
		status = SUN_IMA_GetBootMpxio(&mpxioEnabled);
		if (!IMA_SUCCESS(status)) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unable to get MPxIO info"
			    " of root disk"));
			*funcRet = 1;
			return (ret);
		}
		status = SUN_IMA_GetBootTargetName(bootTargetName);
		if (!IMA_SUCCESS(status)) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unable to get boot target's"
			    " name"));
			*funcRet = 1;
			return (ret);
		}
		status = SUN_IMA_GetBootTargetAuthParams(&bootTargetCHAP);
		if (!IMA_SUCCESS(status)) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unable to get boot target's"
			    " auth param"));
			*funcRet = 1;
			return (ret);
		}
	}

	/* find target oid */
	for (found = B_FALSE, i = 0; i < targetList->oidCount; i++) {
		status = SUN_IMA_GetTargetProperties(targetList->oids[i],
		    &targetProps);
		if (!IMA_SUCCESS(status)) {
			printLibError(status);
			(void) IMA_FreeMemory(targetList);
			*funcRet = 1;
			return (ret);
		}

		/*
		 * Compare the target name with the input name
		 */
		if ((targetNamesEqual(wcInputObject, targetProps.imaProps.name)
		    == B_TRUE)) {
			/*
			 * For now, regardless of whether a target address
			 * is specified, we return B_TRUE because
			 * IMA_TARGET_PROPERTIES does not have a field for
			 * specifying address.
			 */
			found = B_TRUE;
			targetOid = targetList->oids[i];

			if ((targetNamesEqual(bootTargetName, wcInputObject)
			    == B_TRUE) && (iscsiBoot == IMA_TRUE)) {
				/*
				 * iscsi booting, need changed target param is
				 * booting target, for auth param, not allow
				 * to change, for others dependent on mpxio
				 */

				if ((optionList->optval == 'C') ||
				    (optionList->optval == 'H') ||
				    (optionList->optval == 'B') ||
				    (optionList->optval == 'a')) {
					/*
					 * -C CHAP secret set
					 * -H CHAP name set
					 * -a authentication
					 * -B bi-directional-authentication
					 */
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot,"
					    " not allowed to modify"
					    " authentication parameters"
					    "  of boot target"));
					return (1);
				}
				if (mpxioEnabled == IMA_FALSE) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("iscsi boot and"
					    " MPxIO is disabled, not allowed"
					    " to modify boot target's"
					    " parameters"));
					return (1);
				}

			}

			if (modifyIndividualTargetParam(optionList, targetOid,
			    funcRet) != 0) {
				return (ret);
			}

			/*
			 * Even after finding a matched target, keep going
			 * since there could be multiple target objects
			 * associated with one target name in the system
			 * because of different TPGTs.
			 */
		}
	}

	/* If the target OID cannot be found create one */
	if (!found) {
		status = SUN_IMA_CreateTargetOid(wcInputObject, &targetOid);
		if (!IMA_SUCCESS(status)) {
			printLibError(status);
			(void) IMA_FreeMemory(targetList);
			*funcRet = 1;
			return (ret);
		}
		if (modifyIndividualTargetParam(optionList, targetOid,
		    funcRet) != 0) {
				return (ret);
		}
	}

	(void) IMA_FreeMemory(targetList);
	return (ret);
}

/*
 * Add one or more addresses
 */
static int
addAddress(int addrType, int operandLen, char *operand[], int *funcRet)
{
	IMA_STATUS status;
	IMA_OID oid, addressOid;
	SUN_IMA_TARGET_ADDRESS address;
	wchar_t wcInputObject[MAX_ADDRESS_LEN + 1];
	int ret;
	int i;

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&oid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	/*
	 * Format of discovery address operand:
	 *
	 * <IP address|hostname>:<port>
	 */
	for (i = 0; i < operandLen; i++) {
		/* initialize */
		(void) memset(&wcInputObject[0], 0, sizeof (wcInputObject));
		(void) memset(&address, 0, sizeof (address));

		if (mbstowcs(wcInputObject, operand[i],
		    (MAX_ADDRESS_LEN + 1)) == (size_t)-1) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("conversion error"));
			ret = 1;
			continue;
		}
		if (getTargetAddress(addrType, operand[i], &address.imaStruct)
		    != 0) {
			ret = 1;
			continue;
		}
		if (addrType == DISCOVERY_ADDRESS) {
			status = IMA_AddDiscoveryAddress(oid,
			    address.imaStruct, &addressOid);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				*funcRet = 1;
				return (ret);
			}
		} else if (addrType == ISNS_SERVER_ADDRESS) {
			status = SUN_IMA_AddISNSServerAddress(address);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				*funcRet = 1;
				return (ret);
			}
		}
	}
	return (ret);
}

/*
 * Add one or more static configuration targets
 */
static int
addStaticConfig(int operandLen, char *operand[], int *funcRet)
{
	int i;
	boolean_t targetAddressSpecified = B_FALSE;
	boolean_t tpgtSpecified = B_FALSE;
	boolean_t isIpv6 = B_FALSE;
	int ret;
	int addrType;
	IMA_STATUS status;
	IMA_OID oid;
	SUN_IMA_STATIC_DISCOVERY_TARGET staticConfig;
	IMA_UINT16 port = 0;
	IMA_UINT16 tpgt = 0;
	wchar_t staticTargetName[MAX_ISCSI_NAME_LEN + 1];
	wchar_t staticTargetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	iSCSINameCheckStatusType nameCheckStatus;
	char sAddr[SUN_IMA_IP_ADDRESS_PORT_LEN];

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&oid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	/*
	 * Format of static config operand:
	 *  <target-name>,<IP address|hostname>[:port][,tpgt]
	 */
	for (i = 0; i < operandLen; i++) {
		if (parseTarget(operand[i],
		    &staticTargetName[0],
		    MAX_ISCSI_NAME_LEN + 1,
		    &targetAddressSpecified,
		    &staticTargetAddress[0],
		    SUN_IMA_IP_ADDRESS_PORT_LEN,
		    &port,
		    &tpgtSpecified,
		    &tpgt,
		    &isIpv6) != PARSE_TARGET_OK) {
			ret = 1;
			continue;
		}

		if (targetAddressSpecified != B_TRUE) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("missing target address"));
			*funcRet = 1; /* DIY message fix */
			return (1);
		}
		/* Perform string profile checks */
		nameCheckStatus = iSCSINameStringProfileCheck(staticTargetName);
		iSCSINameCheckStatusDisplay(nameCheckStatus);
		if (nameCheckStatus != iSCSINameCheckOK) {
			*funcRet = 1; /* DIY message fix */
			return (1);
		}
		(void) wcsncpy(staticConfig.targetName, staticTargetName,
		    MAX_ISCSI_NAME_LEN + 1);

		(void) wcstombs(sAddr, staticTargetAddress, sizeof (sAddr));

		if (isIpv6 == B_TRUE) {
			staticConfig.targetAddress.imaStruct.hostnameIpAddress.
			    id.ipAddress.ipv4Address = B_FALSE;
			addrType = AF_INET6;
		} else {
			staticConfig.targetAddress.imaStruct.hostnameIpAddress.
			    id.ipAddress.ipv4Address = B_TRUE;
			addrType = AF_INET;
		}

		if (inet_pton(addrType, sAddr, staticConfig.targetAddress.
		    imaStruct.hostnameIpAddress.id.ipAddress.ipAddress) != 1) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("static config conversion error"));
			ret = 1;
			continue;
		}

		staticConfig.targetAddress.imaStruct.portNumber = port;
		if (tpgtSpecified == B_TRUE) {
			staticConfig.targetAddress.defaultTpgt = B_FALSE;
			staticConfig.targetAddress.tpgt = tpgt;
		} else {
			staticConfig.targetAddress.defaultTpgt = B_TRUE;
			staticConfig.targetAddress.tpgt = 0;
		}

		status = SUN_IMA_AddStaticTarget(oid, staticConfig, &oid);
		if (!IMA_SUCCESS(status)) {
			printLibError(status);
			*funcRet = 1;
			return (1);
		}
	}

	if (ret != 0) {
		*funcRet = 1;
	}

	return (ret);
}

/*
 * Remove one or more addresses
 */
static int
removeAddress(int addrType, int operandLen, char *operand[], int *funcRet)
{
	IMA_STATUS status;
	IMA_OID initiatorOid;
	SUN_IMA_TARGET_ADDRESS address;
	wchar_t wcInputObject[MAX_ADDRESS_LEN + 1];
	int ret;
	int i;

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	for (i = 0; i < operandLen; i++) {
		/* initialize */
		(void) memset(&wcInputObject[0], 0, sizeof (wcInputObject));
		(void) memset(&address, 0, sizeof (address));

		if (mbstowcs(wcInputObject, operand[i],
		    MAX_ADDRESS_LEN + 1) == (size_t)-1) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("conversion error"));
			ret = 1;
			continue;
		}

		if (getTargetAddress(addrType, operand[i], &address.imaStruct)
		    != 0) {
			ret = 1;
			continue;
		}

		if (addrType == DISCOVERY_ADDRESS) {
			status = SUN_IMA_RemoveDiscoveryAddress(address);
			if (!IMA_SUCCESS(status)) {
				if (status == IMA_ERROR_OBJECT_NOT_FOUND) {
					(void) fprintf(stderr, "%s: %s\n",
					    operand[i], gettext("not found"));
				} else {
					printLibError(status);
				}
				*funcRet = 1;
			}
		} else {
			status = SUN_IMA_RemoveISNSServerAddress(address);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				*funcRet = 1;
			}
		}
	}
	return (ret);
}

/*
 * Remove one or more static configuration targets
 */
static int
removeStaticConfig(int operandLen, char *operand[], int *funcRet)
{
	IMA_STATUS status;
	IMA_OID initiatorOid;
	IMA_OID_LIST *staticTargetList;
	SUN_IMA_STATIC_TARGET_PROPERTIES staticTargetProps;
	wchar_t staticTargetName[MAX_ISCSI_NAME_LEN + 1];
	wchar_t staticTargetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	int ret;
	boolean_t atLeastFoundOne;
	boolean_t matched;
	boolean_t targetAddressSpecified = B_TRUE;
	boolean_t tpgtSpecified = B_FALSE;
	boolean_t isIpv6 = B_FALSE;
	int i, j;
	IMA_UINT16 port = 0;
	IMA_UINT16 tpgt = 0;
	iSCSINameCheckStatusType nameCheckStatus;
	char tmpStr[SUN_IMA_IP_ADDRESS_PORT_LEN];
	wchar_t tmpTargetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	status = IMA_GetStaticDiscoveryTargetOidList(initiatorOid,
	    &staticTargetList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < operandLen; i++) {
		if (parseTarget(operand[i],
		    &staticTargetName[0],
		    MAX_ISCSI_NAME_LEN + 1,
		    &targetAddressSpecified,
		    &staticTargetAddress[0],
		    SUN_IMA_IP_ADDRESS_PORT_LEN,
		    &port,
		    &tpgtSpecified,
		    &tpgt,
		    &isIpv6) != PARSE_TARGET_OK) {
			ret = 1;
			continue;
		}

		/* Perform string profile checks */
		nameCheckStatus = iSCSINameStringProfileCheck(staticTargetName);
		iSCSINameCheckStatusDisplay(nameCheckStatus);
		if (nameCheckStatus != iSCSINameCheckOK) {
			return (1);
		}

		for (atLeastFoundOne = B_FALSE, j = 0;
		    j < staticTargetList->oidCount;
		    j++) {
			IMA_UINT16 stpgt;

			matched = B_FALSE;
			status = SUN_IMA_GetStaticTargetProperties(
			    staticTargetList->oids[j], &staticTargetProps);
			if (!IMA_SUCCESS(status)) {
				if (status == IMA_ERROR_OBJECT_NOT_FOUND) {
					/*
					 * When removing multiple static-config
					 * entries we need to expect get
					 * failures. These failures occur when
					 * we are trying to get entry
					 * information we have just removed.
					 * Ignore the failure and continue.
					 */
					ret = 1;
					continue;
				} else {
					printLibError(status);
					(void) IMA_FreeMemory(staticTargetList);
					*funcRet = 1;
					return (ret);
				}
			}

			stpgt =
			    staticTargetProps.staticTarget.targetAddress.tpgt;

			/*
			 * Compare the static target name with the input if
			 * one was input
			 */
			if ((targetNamesEqual(
			    staticTargetProps.staticTarget.targetName,
			    staticTargetName) == B_TRUE)) {
				if (targetAddressSpecified == B_FALSE) {
					matched = B_TRUE;
				} else {

					if (staticTargetProps.staticTarget.
					    targetAddress.imaStruct.
					    hostnameIpAddress.
					    id.ipAddress.ipv4Address ==
					    IMA_TRUE) {
						(void) inet_ntop(AF_INET,
						    staticTargetProps.
						    staticTarget.targetAddress.
						    imaStruct.hostnameIpAddress.
						    id.ipAddress.ipAddress,
						    tmpStr,
						    sizeof (tmpStr));
					} else {
						(void) inet_ntop(AF_INET6,
						    staticTargetProps.
						    staticTarget.targetAddress.
						    imaStruct.hostnameIpAddress.
						    id.ipAddress.ipAddress,
						    tmpStr,
						    sizeof (tmpStr));
					}

					if (mbstowcs(tmpTargetAddress, tmpStr,
					    SUN_IMA_IP_ADDRESS_PORT_LEN) ==
					    (size_t)-1) {
						(void) fprintf(stderr,
						    "%s: %s\n",
						    cmdName, gettext(
						    "conversion error"));
						ret = 1;
						continue;
					}

					if ((wcsncmp(tmpTargetAddress,
					    staticTargetAddress,
					    SUN_IMA_IP_ADDRESS_PORT_LEN) ==
					    0) && (staticTargetProps.
					    staticTarget.targetAddress.
					    imaStruct.portNumber == port)) {
						if (tpgtSpecified == B_FALSE) {
							matched = B_TRUE;
						} else {
							if (tpgt == stpgt) {
								matched =
								    B_TRUE;
							}
						}
					}
				}

				if (matched) {
					status =
					    IMA_RemoveStaticDiscoveryTarget(
					    staticTargetList->oids[j]);
					if (!IMA_SUCCESS(status)) {
						printLibError(status);
						*funcRet = 1;
						return (ret);
					}
					atLeastFoundOne = B_TRUE;
				}
			}
		}
		if (!atLeastFoundOne) {
			(void) fprintf(stderr, gettext("%ws,%ws: %s\n"),
			    staticTargetName, staticTargetAddress,
			    gettext("not found"));
		}
	}
	return (ret);
}

/*
 * Remove one or more target params.
 */
static int
removeTargetParam(int operandLen, char *operand[], int *funcRet)
{
	char *commaPos;
	IMA_STATUS status;
	IMA_OID initiatorOid;
	IMA_OID_LIST *targetList;
	SUN_IMA_TARGET_PROPERTIES targetProps;
	wchar_t wcInputObject[MAX_ISCSI_NAME_LEN + 1];
	int ret;
	boolean_t found;
	int i, j;
	IMA_NODE_NAME bootTargetName;
	IMA_BOOL	iscsiBoot = IMA_FALSE;
	IMA_BOOL	mpxioEnabled = IMA_FALSE;

	/* Get boot session's info */
	(void) SUN_IMA_GetBootIscsi(&iscsiBoot);
	if (iscsiBoot == IMA_TRUE) {
		status = SUN_IMA_GetBootMpxio(&mpxioEnabled);
		if (!IMA_SUCCESS(status)) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unable to get MPxIO info of"
			    " root disk"));
			*funcRet = 1;
			return (1);
		}
		status = SUN_IMA_GetBootTargetName(bootTargetName);
		if (!IMA_SUCCESS(status)) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unable to get boot"
			    " target's name"));
			*funcRet = 1;
			return (1);
		}
	}

	assert(funcRet != NULL);

	/* Find Sun initiator */
	ret = sunInitiatorFind(&initiatorOid);
	if (ret > 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("no initiator found"));
	}

	if (ret != 0) {
		return (ret);
	}

	status = IMA_GetTargetOidList(initiatorOid, &targetList);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		*funcRet = 1;
		return (ret);
	}

	for (i = 0; i < operandLen; i++) {
		/* initialize */
		commaPos = strchr(operand[i], ',');
		if (commaPos) {
			/* Ignore IP address. */
			*commaPos = '\0';
		}
		(void) memset(&wcInputObject[0], 0, sizeof (wcInputObject));
		if (mbstowcs(wcInputObject, operand[i],
		    MAX_ISCSI_NAME_LEN + 1) == (size_t)-1) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("conversion error"));
			ret = 1;
			continue;
		}

		for (found = B_FALSE, j = 0; j < targetList->oidCount;
		    j++) {
			status = SUN_IMA_GetTargetProperties(
			    targetList->oids[j], &targetProps);
			if (!IMA_SUCCESS(status)) {
				printLibError(status);
				(void) IMA_FreeMemory(targetList);
				*funcRet = 1;
				return (ret);
			}

			/*
			 * Compare the target name with the input if
			 * one was input
			 */
			if (targetNamesEqual(targetProps.imaProps.name,
			    wcInputObject) == B_TRUE) {
				found = B_TRUE;
				if ((targetNamesEqual(bootTargetName,
				    wcInputObject) == B_TRUE) &&
				    (iscsiBoot == IMA_TRUE)) {
					/*
					 * iscsi booting, need changed target
					 * param is booting target, booting
					 * session mpxio disabled, not
					 * allow to update
					 */
					if (mpxioEnabled == IMA_FALSE) {
						(void) fprintf(stderr,
						    "%s: %s\n", cmdName,
						    gettext("iscsi boot"
						    " with MPxIO disabled,"
						    " not allowed to remove"
						    " boot sess param"));
						ret = 1;
						continue;
					}

				}

				status = SUN_IMA_RemoveTargetParam(
				    targetList->oids[j]);
				if (!IMA_SUCCESS(status)) {
					printLibError(status);
					(void) IMA_FreeMemory(targetList);
					*funcRet = 1;
					return (ret);
				}
			}
		}
		if (!found) {
			/* Silently ignoring it? */
			(void) fprintf(stderr, gettext("%ws: %s\n"),
			    wcInputObject, gettext("not found"));
		}
	}

	(void) IMA_FreeMemory(targetList);
	return (ret);
}

/*ARGSUSED*/
static int
addFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs, int *funcRet)
{
	int ret;

	assert(funcRet != NULL);

	switch (object) {
		case DISCOVERY_ADDRESS:
		case ISNS_SERVER_ADDRESS:
			ret = addAddress(object, operandLen, operand, funcRet);
			break;
		case STATIC_CONFIG:
			ret = addStaticConfig(operandLen, operand, funcRet);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
listFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs, int *funcRet)
{
	int ret;

	assert(funcRet != NULL);

	switch (object) {
	case DISCOVERY:
		ret = listDiscovery(funcRet);
		break;
	case DISCOVERY_ADDRESS:
		ret = listDiscoveryAddress(operandLen, operand, options,
		    funcRet);
		break;
	case ISNS_SERVER_ADDRESS:
		ret = listISNSServerAddress(operandLen, operand, options,
		    funcRet);
		break;
	case NODE:
		ret = listNode(funcRet);
		break;
	case STATIC_CONFIG:
		ret = listStaticConfig(operandLen, operand, funcRet);
		break;
	case TARGET:
		ret = listTarget(operandLen, operand, options, funcRet);
		break;
	case TARGET_PARAM:
		ret = listTargetParam(operandLen, operand, options, funcRet);
		break;
	default:
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("unknown object"));
		ret = 1;
		break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
modifyFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs, int *funcRet)
{
	int ret, i;

	assert(funcRet != NULL);

	switch (object) {
	case DISCOVERY:
		ret = modifyDiscovery(options, funcRet);
		break;
	case NODE:
		ret = modifyNode(options, funcRet);
		break;
	case TARGET_PARAM:
		i = 0;
		while (operand[i]) {
			ret = modifyTargetParam(options, operand[i], funcRet);

			if (ret) {
				(void) fprintf(stderr, "%s: %s: %s\n",
				    cmdName, gettext("modify failed"),
				    operand[i]);
				return (ret);
			}
			i++;
		}

		break;
	default:
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("unknown object"));
		ret = 1;
		break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
removeFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs, int *funcRet)
{
	int ret;

	switch (object) {
		case DISCOVERY_ADDRESS:
		case ISNS_SERVER_ADDRESS:
			ret = removeAddress(object, operandLen, operand,
			    funcRet);
			break;
		case STATIC_CONFIG:
			ret = removeStaticConfig(operandLen, operand, funcRet);
			break;
		case TARGET_PARAM:
			ret = removeTargetParam(operandLen, operand, funcRet);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

static void
iSCSINameCheckStatusDisplay(iSCSINameCheckStatusType status)
{
	switch (status) {
		case iSCSINameLenZero:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("empty iSCSI name."));
			break;
		case iSCSINameLenExceededMax:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("iSCSI name exceeded maximum length."));
			break;
		case iSCSINameUnknownType:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown iSCSI name type."));
			break;
		case iSCSINameInvalidCharacter:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName,
			    gettext("iSCSI name invalid character used"));
			break;
		case iSCSINameIqnFormatError:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("iqn formatting error."));
			break;
		case iSCSINameIqnDateFormatError:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("invalid iqn date." \
			    "  format is: YYYY-MM"));
			break;
		case iSCSINameIqnSubdomainFormatError:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("missing subdomain after \":\""));
			break;
		case iSCSINameIqnInvalidYearError:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("invalid year"));
			break;
		case iSCSINameIqnInvalidMonthError:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("invalid month"));
			break;
		case iSCSINameIqnFQDNError:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("missing reversed fully qualified"\
			    " domain name"));
			break;
		case iSCSINameEUIFormatError:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("eui formatting error."));
			break;
	}
}

/*
 * A convenient function to modify the target parameters of an individual
 * target.
 *
 * Return 0 if successful
 * Return 1 if failed
 */
static int
modifyIndividualTargetParam(cmdOptions_t *optionList, IMA_OID targetOid,
    int *funcRet)
{
	assert(funcRet != NULL);

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'a':
				if (modifyTargetAuthMethod(targetOid,
				    optionList->optarg, funcRet) != 0) {
					return (1);
				}
				break;
			case 'B':
				if (modifyTargetBidirAuthFlag(targetOid,
				    optionList->optarg, funcRet) != 0) {
					return (1);
				}
				break;
			case 'C':
				if (modifyTargetAuthParam(targetOid,
				    AUTH_PASSWORD, NULL, funcRet) != 0) {
					return (1);
				}
				break;
			case 'd':
				if (setLoginParameter(targetOid, DATA_DIGEST,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;
			case 'h':
				if (setLoginParameter(targetOid, HEADER_DIGEST,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;
			case 'p':
				/* Login parameter */
				if (setLoginParameters(targetOid,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;
			case 'c':
				/* Modify configure sessions */
				if (modifyConfiguredSessions(targetOid,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;
			case 'H':
				if (modifyTargetAuthParam(targetOid, AUTH_NAME,
				    optionList->optarg, funcRet) != 0) {
					return (1);
				}
				break;
			case 'T':
				if (setTunableParameters(targetOid,
				    optionList->optarg) != 0) {
					return (1);
				}
				break;
		}
	}

	return (0);
}

/*
 * This helper function could go into a utility module for general use.
 */
static int
parseAddress(char *address_port_str,
    uint16_t defaultPort,
    char *address_str,
    size_t address_str_len,
    uint16_t *port,
    boolean_t *isIpv6)
{
	char port_str[64];
	int tmp_port;
	char *errchr;

	if (address_port_str[0] == '[') {
		/* IPv6 address */
		char *close_bracket_pos;
		close_bracket_pos = strchr(address_port_str, ']');
		if (!close_bracket_pos) {
			syslog(LOG_USER|LOG_DEBUG,
			    "IP address format error: %s\n", address_str);
			return (PARSE_ADDR_MISSING_CLOSING_BRACKET);
		}

		*close_bracket_pos = '\0';
		(void) strlcpy(address_str, &address_port_str[1],
		    address_str_len);

		/* Extract the port number */
		close_bracket_pos++;
		if (*close_bracket_pos == ':') {
			close_bracket_pos++;
			if (*close_bracket_pos != '\0') {
				(void) strlcpy(port_str, close_bracket_pos, 64);
				tmp_port = strtol(port_str, &errchr, 10);
				if (tmp_port == 0 && errchr != NULL) {
					(void) fprintf(stderr, "%s: %s:%s %s\n",
					    cmdName, address_str,
					    close_bracket_pos,
					    gettext("port number invalid"));
					return (PARSE_ADDR_PORT_OUT_OF_RANGE);
				}
				if ((tmp_port > 0) && (tmp_port > USHRT_MAX) ||
				    (tmp_port < 0)) {
					/* Port number out of range */
					syslog(LOG_USER|LOG_DEBUG,
					    "Specified port out of range: %d",
					    tmp_port);
					return (PARSE_ADDR_PORT_OUT_OF_RANGE);
				} else {
					*port = (uint16_t)tmp_port;
				}
			} else {
				*port = defaultPort;
			}
		} else {
			*port = defaultPort;
		}

		*isIpv6 = B_TRUE;
	} else {
		/* IPv4 address */
		char *colon_pos;
		colon_pos = strchr(address_port_str, ':');
		if (!colon_pos) {
			/* No port number specified. */
			*port = defaultPort;
			(void) strlcpy(address_str, address_port_str,
			    address_str_len);
		} else {
			*colon_pos = '\0';
			(void) strlcpy(address_str, address_port_str,
			    address_str_len);

			/* Extract the port number */
			colon_pos++;
			if (*colon_pos != '\0') {

				(void) strlcpy(port_str, colon_pos, 64);
				tmp_port = strtol(port_str, &errchr, 10);
				if (tmp_port == 0 && errchr != NULL) {
					(void) fprintf(stderr, "%s: %s:%s %s\n",
					    cmdName, address_str, colon_pos,
					    gettext("port number invalid"));
					return (PARSE_ADDR_PORT_OUT_OF_RANGE);
				}
				if ((tmp_port > 0) && (tmp_port > USHRT_MAX) ||
				    (tmp_port < 0)) {
					/* Port number out of range */
					syslog(LOG_USER|LOG_DEBUG,
					    "Specified port out of range: %d",
					    tmp_port);
					return (PARSE_ADDR_PORT_OUT_OF_RANGE);
				} else {
					*port = (uint16_t)tmp_port;
				}
			} else {
				*port = defaultPort;
			}
		}

		*isIpv6 = B_FALSE;
	}

	return (PARSE_ADDR_OK);
}

/*
 * This helper function could go into a utility module for general use.
 */
iSCSINameCheckStatusType
iSCSINameStringProfileCheck(wchar_t *name)
{
	char mb_name[MAX_ISCSI_NAME_LEN + 1];
	size_t name_len;
	char *tmp;

	(void) wcstombs(mb_name, name, MAX_ISCSI_NAME_LEN + 1);

	if ((name_len = strlen(mb_name)) == 0) {
		return (iSCSINameLenZero);
	} else if (name_len > MAX_ISCSI_NAME_LEN) {
		return (iSCSINameLenExceededMax);
	}

	/*
	 * check for invalid characters
	 * According to RFC 3722 iSCSI name must be either a letter,
	 * a digit or one of the following '-' '.' ':'
	 */
	for (tmp = mb_name; *tmp != '\0'; tmp++) {
		if ((isalnum(*tmp) == 0) &&
		    (*tmp != '-') &&
		    (*tmp != '.') &&
		    (*tmp != ':')) {
			return (iSCSINameInvalidCharacter);
		}
	}

	if (strncmp(mb_name, ISCSI_IQN_NAME_PREFIX,
	    strlen(ISCSI_IQN_NAME_PREFIX)) == 0) {
		/*
		 * If name is of type iqn, check date string and naming
		 * authority.
		 */
		char *strp = NULL;

		/*
		 * Don't allow the string to end with a colon.  If there is a
		 * colon then there must be a subdomain provided.
		 */
		if (mb_name[strlen(mb_name) - 1] == ':') {
			return (iSCSINameIqnSubdomainFormatError);
		}

		/* Date string */
		strp = strtok(&mb_name[3], ".");
		if (strp) {
			char tmpYear[5], tmpMonth[3], *endPtr = NULL;
			int year, month;

			/* Date string should be in YYYY-MM format */
			if (strlen(strp) != strlen("YYYY-MM") ||
			    strp[4] != '-') {
				return (iSCSINameIqnDateFormatError);
			}

			/*
			 * Validate year.  Only validating that the
			 * year can be converted to a number.  No
			 * validation will be done on year's actual
			 * value.
			 */
			(void) strncpy(tmpYear, strp, 4);
			tmpYear[4] = '\0';

			errno = 0;
			year = strtol(tmpYear, &endPtr, 10);
			if (errno != 0 || *endPtr != '\0' ||
			    year < 0 || year > 9999) {
				return (iSCSINameIqnInvalidYearError);
			}

			/*
			 * Validate month is valid.
			 */
			(void) strncpy(tmpMonth, &strp[5], 2);
			tmpMonth[2] = '\0';
			errno = 0;
			month = strtol(tmpMonth, &endPtr, 10);

			if (errno != 0 || *endPtr != '\0' ||
			    month < 1 || month > 12) {
				return (iSCSINameIqnInvalidMonthError);
			}

			/*
			 * A reversed FQDN needs to be provided.  We
			 * will only check for a "." followed by more
			 * than two or more characters.  The list of domains is
			 * too large and changes too frequently to
			 * add validation for.
			 */
			strp = strtok(NULL, ".");
			if (!strp || strlen(strp) < 2) {
				return (iSCSINameIqnFQDNError);
			}

			/* Name authority string */
			strp = strtok(NULL, ":");
			if (strp) {
				return (iSCSINameCheckOK);
			} else {
				return (iSCSINameIqnFQDNError);
			}
		} else {
			return (iSCSINameIqnFormatError);
		}
	} else if (strncmp(mb_name, ISCSI_EUI_NAME_PREFIX,
	    strlen(ISCSI_EUI_NAME_PREFIX)) == 0) {
		/* If name is of type EUI, change its length */

		if (strlen(mb_name) != ISCSI_EUI_NAME_LEN) {
			return (iSCSINameEUIFormatError);
		}

		for (tmp = mb_name + strlen(ISCSI_EUI_NAME_PREFIX) + 1;
		    *tmp != '\0'; tmp++) {
			if (isxdigit(*tmp)) {
				continue;
			}
			return (iSCSINameEUIFormatError);
		}

		return (iSCSINameCheckOK);
	} else {
		return (iSCSINameUnknownType);
	}
}

/*
 * This helper function could go into a utility module for general use.
 *
 * Returns:
 * B_TRUE is the numberStr is an unsigned natural number and within the
 * specified bound.
 * B_FALSE otherwise.
 */
boolean_t
isNaturalNumber(char *numberStr, uint32_t upperBound)
{
	int i;
	int number_str_len;

	if ((number_str_len = strlen(numberStr)) == 0) {
		return (B_FALSE);
	}

	for (i = 0; i < number_str_len; i++) {
		if (numberStr[i] < 060 || numberStr[i] > 071) {
			return (B_FALSE);
		}
	}

	if (atoi(numberStr) > upperBound) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This helper function could go into a utility module for general use.
 * It parses a target string in the format of:
 *
 *	<target_name>,[<ip_address>[:port][,tpgt]]
 *
 * and creates wchar strings for target name and target address. It
 * also populates port and tpgt if found.
 *
 * Returns:
 *	PARSE_TARGET_OK if parsing is successful.
 *	PARSE_TARGET_INVALID_TPGT if the specified tpgt is
 *	invalid.
 *	PARSE_TARGET_INVALID_ADDR if the address specified is
 *	invalid.
 */
int
parseTarget(char *targetStr, wchar_t *targetNameStr, size_t targetNameStrLen,
    boolean_t *targetAddressSpecified, wchar_t *targetAddressStr,
    size_t targetAddressStrLen, uint16_t *port, boolean_t *tpgtSpecified,
    uint16_t *tpgt, boolean_t *isIpv6)
{
	char *commaPos;
	char *commaPos2;
	char targetAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	int i;
	int lowerCase;

	(void) memset(targetNameStr, 0,
	    targetNameStrLen * sizeof (wchar_t));
	(void) memset(targetAddressStr, 0,
	    targetAddressStrLen * sizeof (wchar_t));

	commaPos = strchr(targetStr, ',');
	if (commaPos != NULL) {
		*commaPos = '\0';
		commaPos++;
		*targetAddressSpecified = B_TRUE;

		/*
		 * Checking of tpgt makes sense only when
		 * the target address/port are specified.
		 */
		commaPos2 = strchr(commaPos, ',');
		if (commaPos2 != NULL) {
			*commaPos2 = '\0';
			commaPos2++;
			if (isNaturalNumber(commaPos2, ISCSI_MAX_TPGT_VALUE) ==
			    B_TRUE) {
				*tpgt = atoi(commaPos2);
				*tpgtSpecified = B_TRUE;
			} else {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("parse target invalid TPGT"));
				return (PARSE_TARGET_INVALID_TPGT);
			}
		}

		switch (parseAddress(commaPos, ISCSI_LISTEN_PORT,
		    &targetAddress[0], MAX_ADDRESS_LEN + 1, port, isIpv6)) {
		case PARSE_ADDR_PORT_OUT_OF_RANGE:
			return (PARSE_TARGET_INVALID_ADDR);
		case PARSE_ADDR_OK:
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("cannot parse target name"));
			return (PARSE_TARGET_INVALID_ADDR);
		}
		(void) mbstowcs(targetAddressStr, targetAddress,
		    targetAddressStrLen);
		for (i = 0; targetAddressStr[i] != 0; i++) {
			lowerCase = tolower(targetAddressStr[i]);
			targetAddressStr[i] = lowerCase;
		}
	} else {
		*targetAddressSpecified = B_FALSE;
		*tpgtSpecified = B_FALSE;
	}

	(void) mbstowcs(targetNameStr, targetStr, targetNameStrLen);
	for (i = 0; targetNameStr[i] != 0; i++) {
		lowerCase = tolower(targetNameStr[i]);
		targetNameStr[i] = lowerCase;
	}

	return (PARSE_TARGET_OK);
}

/*ARGSUSED*/
static void
listCHAPName(IMA_OID oid)
{
	IMA_INITIATOR_AUTHPARMS authParams;
	IMA_STATUS status;
	IMA_BYTE chapName [MAX_CHAP_NAME_LEN + 1];

	/* Get Chap Name depending upon oid object type */
	if (oid.objectType == IMA_OBJECT_TYPE_LHBA) {
		status = IMA_GetInitiatorAuthParms(oid,
		    IMA_AUTHMETHOD_CHAP, &authParams);
	} else {
		status = SUN_IMA_GetTargetAuthParms(oid,
		    IMA_AUTHMETHOD_CHAP, &authParams);
	}

	(void) fprintf(stdout, "\n\t\t%s: ", gettext("CHAP Name"));

	if (IMA_SUCCESS(status)) {
		/*
		 * Default chap name will be the node name.  The default will
		 * be set by the driver.
		 */
		if (authParams.chapParms.nameLength != 0) {
			(void) memset(chapName, 0, sizeof (chapName));
			(void) memcpy(chapName, authParams.chapParms.name,
			    authParams.chapParms.nameLength);
			(void) fprintf(stdout, "%s", chapName);

		} else {
			(void) fprintf(stdout, "%s", "-");
		}
	} else {
		(void) fprintf(stdout, "%s", "-");
	}
}

static boolean_t
checkServiceStatus(void)
{
	IMA_STATUS	status	=	IMA_ERROR_UNKNOWN_ERROR;
	IMA_BOOL	enabled =	0;

	status = SUN_IMA_GetSvcStatus(&enabled);

	if (status != IMA_STATUS_SUCCESS) {
		(void) fprintf(stdout, "%s\n%s\n",
		    gettext("Unable to query the service status of"
		    " iSCSI initiator."),
		    gettext("For more information, please refer to"
		    " iscsi(7D)."));
		return (B_FALSE);
	}

	if (enabled == 0) {
		(void) fprintf(stdout, "%s\n%s\n",
		    gettext("iSCSI Initiator Service is disabled,"
		    " try 'svcadm enable network/iscsi/initiator' to"
		    " enable the service."),
		    gettext("For more information, please refer to"
		    " iscsi(7D)."));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Prints out see manual page.
 * Called out through atexit(3C) so is always last thing displayed.
 */
void
seeMan(void)
{
	static int sent = 0;

	if (sent)
		return;

	(void) fprintf(stdout, "%s %s(1M)\n",
	    gettext("For more information, please see"), cmdName);

	sent = 1;
}


/*
 * main calls a parser that checks syntax of the input command against
 * various rules tables.
 *
 * The parser provides usage feedback based upon same tables by calling
 * two usage functions, usage and subUsage, handling command and subcommand
 * usage respectively.
 *
 * The parser handles all printing of usage syntactical errors
 *
 * When syntax is successfully validated, the parser calls the associated
 * function using the subcommands table functions.
 *
 * Syntax is as follows:
 *	command subcommand [options] resource-type [<object>]
 *
 * The return value from the function is placed in funcRet
 */
int
main(int argc, char *argv[])
{
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	int ret;
	int funcRet = 0;
	void *subcommandArgs = NULL;

	if (geteuid() != 0) {
		(void) fprintf(stderr, "%s\n", gettext("permission denied"));
		return (1);
	}

	if (checkServiceStatus() == B_FALSE) {
		return (1);
	}

	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	(void) snprintf(versionString, sizeof (versionString), "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subcommandTbl = &subcommands[0];
	synTables.objectTbl = &objects[0];
	synTables.objectRulesTbl = &objectRules[0];
	synTables.optionRulesTbl = &optionRules[0];

	/* call the CLI parser */
	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret == -1) {
		perror(cmdName);
		ret = 1;
	}

	if (funcRet != 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("Unable to complete operation"));
		ret = 1;
	}
	return (ret);
}

static int
setTunableParameters(IMA_OID oid, char *optarg)
{
	char keyp[MAXOPTARGLEN];
	char valp[MAXOPTARGLEN];
	int key;
	IMA_STATUS status;
	IMA_UINT uintValue;
	ISCSI_TUNABLE_PARAM	tunableObj;
	char *nameValueString, *endptr;

	if ((nameValueString = strdup(optarg)) == NULL) {
		if (errno == ENOMEM) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, strerror(errno));
		} else {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown error"));
		}
		return (1);
	}

	(void) memset(keyp, 0, sizeof (keyp));
	(void) memset(valp, 0, sizeof (valp));
	if (sscanf(nameValueString, gettext("%[^=]=%s"), keyp, valp) != 2) {
		(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
		    gettext("Unknown param"), nameValueString);
		if (nameValueString) {
			free(nameValueString);
			nameValueString = NULL;
		}
		return (1);
	}
	if ((key = getTunableParam(keyp)) == -1) {
		(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
		    gettext("Unknown key"), keyp);
		if (nameValueString) {
			free(nameValueString);
			nameValueString = NULL;
		}
		return (1);
	}
	switch (key) {
	case RECV_LOGIN_RSP_TIMEOUT:
	case CONN_LOGIN_MAX:
	case POLLING_LOGIN_DELAY:
		errno = 0;
		uintValue = strtoul(valp, &endptr, 0);
		if (*endptr != '\0' || errno != 0) {
			(void) fprintf(stderr, "%s: %s - %s\n",
			    cmdName,
			    gettext("invalid option argument"),
			    optarg);
			if (nameValueString) {
				free(nameValueString);
				nameValueString = NULL;
			}
			return (1);
		}
		if (uintValue > 3600) {
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName,
gettext("value must be between 0 and 3600"));
			if (nameValueString) {
				free(nameValueString);
				nameValueString = NULL;
			}
			return (1);
		}

		if (chkConnLoginMaxPollingLoginDelay(oid, key, uintValue) > 0) {
			if (nameValueString) {
				free(nameValueString);
				nameValueString = NULL;
			}
			return (1);
		}

		if (key == RECV_LOGIN_RSP_TIMEOUT) {
			tunableObj.tunable_objectType =
			    ISCSI_RX_TIMEOUT_VALUE;
		} else if (key == CONN_LOGIN_MAX) {
			tunableObj.tunable_objectType =
			    ISCSI_CONN_DEFAULT_LOGIN_MAX;
		} else if (key == POLLING_LOGIN_DELAY) {
			tunableObj.tunable_objectType =
			    ISCSI_LOGIN_POLLING_DELAY;
		}
		tunableObj.tunable_objectValue = valp;
		status = SUN_IMA_SetTunableProperties(oid, &tunableObj);
		break;
	default:
		(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
		    gettext("Unsupported key"), keyp);
		if (nameValueString) {
			free(nameValueString);
			nameValueString = NULL;
		}
		return (1);
	}
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		if (nameValueString) {
			free(nameValueString);
			nameValueString = NULL;
		}
		return (1);
	}

	if (nameValueString) {
		free(nameValueString);
		nameValueString = NULL;
	}
	return (0);
}

/*
 * Print tunable parameters information
 */
static int
printTunableParameters(IMA_OID oid)
{
	ISCSI_TUNABLE_PARAM tunableObj;
	char value[MAXOPTARGLEN] = "\0";
	IMA_STATUS status;

	tunableObj.tunable_objectValue = value;
	(void) fprintf(stdout, "\t%s:\n",
	    gettext("Tunable Parameters (Default/Configured)"));
	tunableObj.tunable_objectType = ISCSI_RX_TIMEOUT_VALUE;
	status = SUN_IMA_GetTunableProperties(oid, &tunableObj);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (1);
	}
	if (value[0] == '\0') {
		value[0] = '-';
		value[1] = '\0';
	}
	(void) fprintf(stdout, "\t\t%s: ",
	    gettext("Session Login Response Time"));
	(void) fprintf(stdout, "%s/%s\n", ISCSI_DEFAULT_RX_TIMEOUT_VALUE,
	    tunableObj.tunable_objectValue);

	value[0] = '\0';
	tunableObj.tunable_objectType = ISCSI_CONN_DEFAULT_LOGIN_MAX;
	status = SUN_IMA_GetTunableProperties(oid, &tunableObj);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (1);
	}
	if (value[0] == '\0') {
		value[0] = '-';
		value[1] = '\0';
	}
	(void) fprintf(stdout, "\t\t%s: ",
	    gettext("Maximum Connection Retry Time"));
	(void) fprintf(stdout, "%s/%s\n", ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX,
	    tunableObj.tunable_objectValue);

	value[0] = '\0';
	tunableObj.tunable_objectType = ISCSI_LOGIN_POLLING_DELAY;
	status = SUN_IMA_GetTunableProperties(oid, &tunableObj);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (1);
	}
	if (value[0] == '\0') {
		value[0] = '-';
		value[1] = '\0';
	}
	(void) fprintf(stdout, "\t\t%s: ",
	    gettext("Login Retry Time Interval"));
	(void) fprintf(stdout, "%s/%s\n", ISCSI_DEFAULT_LOGIN_POLLING_DELAY,
	    tunableObj.tunable_objectValue);
	return (0);
}

/*
 * This is helper function to check conn_login_max and polling_login_delay.
 */
static int
chkConnLoginMaxPollingLoginDelay(IMA_OID oid, int key, int uintValue)
{
	char valuep[MAXOPTARGLEN];
	IMA_STATUS	status;
	IMA_UINT	getValue;
	ISCSI_TUNABLE_PARAM	getObj;
	char *endptr;

	if (key == CONN_LOGIN_MAX) {
		getObj.tunable_objectType = ISCSI_LOGIN_POLLING_DELAY;
	} else if (key == POLLING_LOGIN_DELAY) {
		getObj.tunable_objectType = ISCSI_CONN_DEFAULT_LOGIN_MAX;
	} else {
		return (0);
	}
	valuep[0] = '\0';
	getObj.tunable_objectValue = valuep;
	status = SUN_IMA_GetTunableProperties(oid, &getObj);
	if (!IMA_SUCCESS(status)) {
		printLibError(status);
		return (1);
	}
	if (valuep[0] == '\0') {
		if (key == CONN_LOGIN_MAX) {
			(void) strlcpy(valuep,
			    ISCSI_DEFAULT_LOGIN_POLLING_DELAY,
			    strlen(ISCSI_DEFAULT_LOGIN_POLLING_DELAY) +1);
		} else {
			(void) strlcpy(valuep,
			    ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX,
			    strlen(ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX) +1);
		}
	}

	errno = 0;
	getValue = strtoul(valuep, &endptr, 0);
	if (*endptr != '\0' || errno != 0) {
		(void) fprintf(stderr, "%s: %s - %s\n",
		    cmdName,
		    gettext("cannot convert tunable string"),
		    valuep);
		return (1);
	}
	if (key == CONN_LOGIN_MAX) {
		if (uintValue < getValue) {
			(void) fprintf(stderr, "%s: %s %ld\n",
			    cmdName, gettext("value must larger than"),
			    getValue);
			return (1);
		}
	} else {
		if (uintValue > getValue) {
			(void) fprintf(stderr, "%s: %s %ld\n",
			    cmdName, gettext("value must smaller than"),
			    getValue);
			return (1);
		}
	}
	return (0);
}
