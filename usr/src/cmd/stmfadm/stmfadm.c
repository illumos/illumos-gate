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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <wchar.h>
#include <libintl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <cmdparse.h>
#include <stmfadm.h>
#include <libstmf.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>

static int addHostGroupMemberFunc(int, char **, cmdOptions_t *, void *);
static int addTargetGroupMemberFunc(int, char **, cmdOptions_t *, void *);
static int addViewFunc(int, char **, cmdOptions_t *, void *);
static int createHostGroupFunc(int, char **, cmdOptions_t *, void *);
static int createTargetGroupFunc(int, char **, cmdOptions_t *, void *);
static int deleteHostGroupFunc(int, char **, cmdOptions_t *, void *);
static int deleteTargetGroupFunc(int, char **, cmdOptions_t *, void *);
static int listLuFunc(int, char **, cmdOptions_t *, void *);
static int listTargetFunc(int, char **, cmdOptions_t *, void *);
static int listViewFunc(int, char **, cmdOptions_t *, void *);
static int listHostGroupFunc(int, char **, cmdOptions_t *, void *);
static int listStateFunc(int, char **, cmdOptions_t *, void *);
static int listTargetGroupFunc(int, char **, cmdOptions_t *, void *);
static int offlineTargetFunc(int, char **, cmdOptions_t *, void *);
static int offlineLuFunc(int, char **, cmdOptions_t *, void *);
static int onlineTargetFunc(int, char **, cmdOptions_t *, void *);
static int onlineLuFunc(int, char **, cmdOptions_t *, void *);
static int onlineOfflineTarget(char *, int);
static int onlineOfflineLu(char *, int);
static int removeHostGroupMemberFunc(int, char **, cmdOptions_t *, void *);
static int removeTargetGroupMemberFunc(int, char **, cmdOptions_t *, void *);
static int removeViewFunc(int, char **, cmdOptions_t *, void *);
static char *getExecBasename(char *);
static int parseDevid(char *input, stmfDevid *devid);
static void printGroupProps(stmfGroupProperties *groupProps);
static int checkScsiNameString(wchar_t *, stmfDevid *);
static int checkHexUpper(char *);
static int checkIscsiName(wchar_t *);
static void printLuProps(stmfLogicalUnitProperties *luProps);
static void printGuid(stmfGuid *guid, FILE *printWhere);
static void printTargetProps(stmfTargetProperties *);
static void printSessionProps(stmfSessionList *);



/*
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"
#define	MAX_DEVID_INPUT		    256
#define	GUID_INPUT		    32
#define	MAX_LU_NBR		    16383
#define	ONLINE_LU		    0
#define	OFFLINE_LU		    1
#define	ONLINE_TARGET		    2
#define	OFFLINE_TARGET		    3
#define	PROPS_FORMAT		    "    %-18s: "
#define	VIEW_FORMAT		    "    %-13s: "
#define	LVL3_FORMAT		    "        %s"
#define	LVL4_FORMAT		    "            %s"

/* SCSI Name String length definitions */
#define	SNS_EUI_16		    16
#define	SNS_EUI_24		    24
#define	SNS_EUI_32		    32
#define	SNS_NAA_16		    16
#define	SNS_NAA_32		    32
#define	SNS_WWN_16		    16
#define	SNS_IQN_223		    223

/* tables set up based on cmdparse instructions */

/* add new options here */
optionTbl_t longOptions[] = {
	{"all", no_arg, 'a', NULL},
	{"group-name", required_arg, 'g', "group-name"},
	{"secure-data", no_arg, 's', NULL},
	{"lu-name", required_arg, 'l', "LU-Name"},
	{"lun", required_arg, 'n', "logical-unit-number"},
	{"verbose", no_arg, 'v', NULL},
	{"target-group", required_arg, 't', "group-name"},
	{"host-group", required_arg, 'h', "group-name"},
	{"size", required_arg, 's', "size (k/M/G)"},
	{"force", no_arg, 'r', NULL},
	{"new", no_arg, 'n', NULL},
	{NULL, 0, 0, 0}
};

/*
 * Add new subcommands here
 */
subCommandProps_t subcommands[] = {
	{"add-hg-member", addHostGroupMemberFunc, "g", "g", NULL,
		OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER},
	{"add-tg-member", addTargetGroupMemberFunc, "g", "g", NULL,
		OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER},
	{"add-view", addViewFunc, "nth", NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU},
	{"create-hg", createHostGroupFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME},
	{"create-tg", createTargetGroupFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME},
	{"delete-hg", deleteHostGroupFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME},
	{"delete-tg", deleteTargetGroupFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME},
	{"list-hg", listHostGroupFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_GROUP_NAME},
	{"list-lu", listLuFunc, "v", NULL, NULL, OPERAND_OPTIONAL_MULTIPLE,
		OPERANDSTRING_LU},
	{"list-state", listStateFunc, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{"list-target", listTargetFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_TARGET},
	{"list-tg", listTargetGroupFunc, "v", NULL, NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_GROUP_NAME},
	{"list-view", listViewFunc, "l", "l", NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_VIEW_ENTRY},
	{"online-lu", onlineLuFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU},
	{"offline-lu", offlineLuFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU},
	{"online-target", onlineTargetFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_TARGET},
	{"offline-target", offlineTargetFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_TARGET},
	{"remove-hg-member", removeHostGroupMemberFunc, "g", "g", NULL,
		OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER},
	{"remove-tg-member", removeTargetGroupMemberFunc, "g", "g", NULL,
		OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER},
	{"remove-view", removeViewFunc, "la", "l", NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_VIEW_ENTRY},
	{NULL, 0, NULL, NULL, 0, NULL, 0, NULL}
};

/* globals */
char *cmdName;

/*
 * addHostGroupMemberFunc
 *
 * Add members to a host group
 *
 */
/*ARGSUSED*/
static int
addHostGroupMemberFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfDevid devid;

	for (; options->optval; options++) {
		switch (options->optval) {
			/* host group name */
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	for (i = 0; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfAddToHostGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_EXISTS:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("already exists"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}

/*
 * addTargetGroupMemberFunc
 *
 * Add members to a target group
 *
 */
/*ARGSUSED*/
static int
addTargetGroupMemberFunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfDevid devid;

	for (; options->optval; options++) {
		switch (options->optval) {
			/* target group name */
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	for (i = 0; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfAddToTargetGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_EXISTS:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("already exists"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service must be offline"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}

/*
 * parseDevid
 *
 * Converts char * input to a stmfDevid
 *
 * input - this should be in the following format with either a
 * wwn. iqn. or eui. representation.
 * A name string of the format:
 *	wwn.<WWN> (FC/SAS address)
 *	iqn.<iSCSI name> (iSCSI iqn)
 *	eui.<WWN> (iSCSI eui name)
 *
 * devid - pointer to stmfDevid structure allocated by the caller.
 *
 * Returns:
 *  0 on success
 *  non-zero on failure
 */
static int
parseDevid(char *input, stmfDevid *devid)
{
	wchar_t inputWc[MAX_DEVID_INPUT + 1] = {0};

	/* convert to wcs */
	(void) mbstowcs(inputWc, input, MAX_DEVID_INPUT);

	/*
	 * Check for known scsi name string formats
	 * If one is found, we're done
	 * If not, then it's a failure to parse
	 */
	if (checkScsiNameString(inputWc, devid) == 0) {
		return (0);
	}

	return (-1);
}

/*
 * checkScsiNameString
 *
 * Validates known SCSI name string formats and converts to stmfDevid
 * format
 *
 * input - input SCSI name string
 * devid - pointer to stmfDevid structure allocated by the caller
 *         on successful return, contains the devid based on input
 *
 * returns:
 *         0 on success
 *         -1 on failure
 */
static int
checkScsiNameString(wchar_t *input, stmfDevid *devid)
{
	char *mbString = NULL;
	int mbStringLen;
	int len;
	int i;

	/*
	 * Convert to multi-byte string
	 *
	 * This is used for either eui or naa formats
	 */
	mbString = calloc(1, (mbStringLen = wcstombs(mbString, input, 0)) + 1);
	if (mbString == NULL) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, "Insufficient memory\n");
		return (-1);
	}
	if (wcstombs(mbString, input, mbStringLen) == (size_t)-1) {
		return (-1);
	}

	/*
	 * check for iqn format
	 */
	if (strncmp(mbString, "iqn.", 4) == 0) {
		if ((len = strlen(mbString)) > (SNS_IQN_223)) {
			return (-1);
		}
		for (i = 0; i < len; i++) {
			mbString[i] = tolower(mbString[i]);
		}
		if (checkIscsiName(input + 4) != 0) {
			return (-1);
		}
	} else if (strncmp(mbString, "wwn.", 4) == 0) {
		if ((len = strlen(mbString + 4)) != SNS_WWN_16) {
			return (-1);
		} else if (checkHexUpper(mbString + 4) != 0) {
			return (-1);
		}
	} else if (strncmp(mbString, "eui.", 4) == 0) {
		if ((len = strlen(mbString + 4)) != SNS_EUI_16) {
			return (-1);
		} else if (checkHexUpper(mbString + 4) != 0) {
			return (-1);
		}
	} else {
		return (-1);
	}

	/*
	 * We have a validated name string.
	 * Go ahead and set the length and copy it.
	 */
	devid->identLength = strlen(mbString);
	bzero(devid->ident, STMF_IDENT_LENGTH);
	bcopy(mbString, devid->ident, devid->identLength);

	return (0);
}


/*
 * Checks whether the entire string is in hex and converts to upper
 */
static int
checkHexUpper(char *input)
{
	int i;

	for (i = 0; i < strlen(input); i++) {
		if (isxdigit(input[i])) {
			input[i] = toupper(input[i]);
			continue;
		}
		return (-1);
	}

	return (0);
}

/*
 * checkIscsiName
 *
 * Purpose: Basic string checking on name
 */
static int
checkIscsiName(wchar_t *input)
{
	int i;

	for (i = 0; input[i] != 0; i++) {
		if (!iswalnum(input[i]) && input[i] != '-' &&
		    input[i] != '.' && input[i] != ':') {
			return (-1);
		}
	}

	return (0);
}


/*
 * addViewFunc
 *
 * Adds a view entry to a logical unit
 *
 */
/*ARGSUSED*/
static int
addViewFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	stmfViewEntry viewEntry;
	stmfGuid inGuid;
	unsigned int guid[sizeof (stmfGuid)];
	uint16_t inputLuNbr;
	int ret = 0;
	int stmfRet;
	int i;
	char sGuid[GUID_INPUT + 1];

	bzero(&viewEntry, sizeof (viewEntry));
	/* init view entry structure */
	viewEntry.allHosts = B_TRUE;
	viewEntry.allTargets = B_TRUE;
	viewEntry.luNbrValid = B_FALSE;

	/* check input length */
	if (strlen(operands[0]) != GUID_INPUT) {
		(void) fprintf(stderr, "%s: %s: %s%d%s\n", cmdName, operands[0],
		    gettext("must be "), GUID_INPUT,
		    gettext(" hexadecimal digits"));
		return (1);
	}

	for (; options->optval; options++) {
		switch (options->optval) {
			/* logical unit number */
			case 'n':
				viewEntry.luNbrValid = B_TRUE;
				inputLuNbr = atoi(options->optarg);
				if (inputLuNbr > MAX_LU_NBR) {
					(void) fprintf(stderr, "%s: %d: %s\n",
					    cmdName, inputLuNbr,
					    gettext("Logical unit number"
					    " must be less than 16384"));
					return (1);
				}
				viewEntry.luNbr[0] = inputLuNbr >> 8;
				viewEntry.luNbr[1] = inputLuNbr & 0xff;
				break;
			/* host group */
			case 'h':
				viewEntry.allHosts = B_FALSE;
				bcopy(options->optarg, viewEntry.hostGroup,
				    strlen(options->optarg));
				break;
			/* target group */
			case 't':
				viewEntry.allTargets = B_FALSE;
				bcopy(options->optarg, viewEntry.targetGroup,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	/* convert to lower case for scan */
	for (i = 0; i < 32; i++)
		sGuid[i] = tolower(operands[0][i]);
	sGuid[i] = 0;

	(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
	    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10], &guid[11],
	    &guid[12], &guid[13], &guid[14], &guid[15]);

	for (i = 0; i < sizeof (stmfGuid); i++) {
		inGuid.guid[i] = guid[i];
	}

	/* add the view entry */
	stmfRet = stmfAddViewEntry(&inGuid, &viewEntry);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_EXISTS:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("already exists"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_LUN_IN_USE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("LUN already in use"));
			ret++;
			break;
		case STMF_ERROR_VE_CONFLICT:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("view entry exists"));
			ret++;
			break;
		case STMF_ERROR_CONFIG_NONE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service is not initialized"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		case STMF_ERROR_INVALID_HG:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid host group"));
			ret++;
			break;
		case STMF_ERROR_INVALID_TG:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid target group"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}

/*
 * createHostGroupFunc
 *
 * Create a host group
 *
 */
/*ARGSUSED*/
static int
createHostGroupFunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};

	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call create group */
	stmfRet = stmfCreateHostGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_EXISTS:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("already exists"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    operands[0], gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}

/*
 * createTargetGroupFunc
 *
 * Create a target group
 *
 */
/*ARGSUSED*/
static int
createTargetGroupFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};

	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call create group */
	stmfRet = stmfCreateTargetGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_EXISTS:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("already exists"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}

/*
 * deleteHostGroupFunc
 *
 * Delete a host group
 *
 */
/*ARGSUSED*/
static int
deleteHostGroupFunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};

	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call delete group */
	stmfRet = stmfDeleteHostGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_NOT_FOUND:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("not found"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_GROUP_IN_USE:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint,
			    gettext("group is in use by existing view entry"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}

/*
 * deleteTargetGroupFunc
 *
 * Delete a target group
 *
 */
/*ARGSUSED*/
static int
deleteTargetGroupFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};

	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call delete group */
	stmfRet = stmfDeleteTargetGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_NOT_FOUND:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("not found"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_GROUP_IN_USE:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint,
			    gettext("group is in use by existing view entry"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
			    groupNamePrint, gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}

/*
 * listHostGroupFunc
 *
 * Lists the specified host groups or all if none are specified
 *
 */
/*ARGSUSED*/
static int
listHostGroupFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret = 0;
	int stmfRet;
	int i, j, outerLoop;
	boolean_t verbose = B_FALSE;
	boolean_t found = B_TRUE;
	boolean_t operandEntered;
	stmfGroupList *groupList;
	stmfGroupProperties *groupProps;
	wchar_t operandName[sizeof (stmfGroupName)];
	wchar_t groupNamePrint[sizeof (stmfGroupName)];

	for (; options->optval; options++) {
		switch (options->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	stmfRet = stmfGetHostGroupList(&groupList);
	if (stmfRet != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (i = 0; i < outerLoop; i++) {
		for (found = B_FALSE, j = 0; j < groupList->cnt; j++) {
			(void) mbstowcs(groupNamePrint,
			    (char *)groupList->name[j],
			    sizeof (stmfGroupName) - 1);
			groupNamePrint[sizeof (stmfGroupName) - 1] = 0;
			if (operandEntered) {
				(void) mbstowcs(operandName, operands[i],
				    sizeof (stmfGroupName) - 1);
				operandName[sizeof (stmfGroupName) - 1] = 0;
				if (wcscmp(operandName, groupNamePrint)
				    == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) printf("Host Group: %ws\n",
				    groupNamePrint);
				if (verbose) {
					stmfRet = stmfGetHostGroupMembers(
					    &(groupList->name[j]), &groupProps);
					if (stmfRet != STMF_STATUS_SUCCESS) {
						return (1);
					}
					printGroupProps(groupProps);
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], gettext("not found"));
			ret = 1;
		}
	}
	return (ret);
}

/*
 * printGroupProps
 *
 * Prints group members for target or host groups
 *
 */
static void
printGroupProps(stmfGroupProperties *groupProps)
{
	int i;
	wchar_t memberIdent[sizeof (groupProps->name[0].ident) + 1] = {0};


	for (i = 0; i < groupProps->cnt; i++) {
		(void) mbstowcs(memberIdent, (char *)groupProps->name[i].ident,
		    sizeof (groupProps->name[0].ident));
		(void) printf("\tMember: %ws\n", memberIdent);
	}
}

/*
 * listTargetGroupFunc
 *
 * Lists the specified target groups or all if none are specified
 *
 */
/*ARGSUSED*/
static int
listTargetGroupFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret = 0;
	int stmfRet;
	int i, j, outerLoop;
	boolean_t verbose = B_FALSE;
	boolean_t found = B_TRUE;
	boolean_t operandEntered;
	stmfGroupList *groupList;
	stmfGroupProperties *groupProps;
	wchar_t operandName[sizeof (stmfGroupName)];
	wchar_t groupNamePrint[sizeof (stmfGroupName)];

	for (; options->optval; options++) {
		switch (options->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	stmfRet = stmfGetTargetGroupList(&groupList);
	if (stmfRet != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (i = 0; i < outerLoop; i++) {
		for (found = B_FALSE, j = 0; j < groupList->cnt; j++) {
			(void) mbstowcs(groupNamePrint,
			    (char *)groupList->name[j],
			    sizeof (stmfGroupName) - 1);
			groupNamePrint[sizeof (stmfGroupName) - 1] = 0;
			if (operandEntered) {
				(void) mbstowcs(operandName, operands[i],
				    sizeof (stmfGroupName) - 1);
				operandName[sizeof (stmfGroupName) - 1] = 0;
				if (wcscmp(operandName, groupNamePrint)
				    == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) printf("Target Group: %ws\n",
				    groupNamePrint);
				if (verbose) {
					stmfRet = stmfGetTargetGroupMembers(
					    &(groupList->name[j]), &groupProps);
					if (stmfRet != STMF_STATUS_SUCCESS) {
						return (1);
					}
					printGroupProps(groupProps);
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], gettext("not found"));
			ret = 1;
		}
	}
	return (ret);
}

/*
 * listLuFunc
 *
 * List the logical units and optionally the properties
 *
 */
/*ARGSUSED*/
static int
listLuFunc(int operandLen, char *operands[], cmdOptions_t *options, void *args)
{
	cmdOptions_t *optionList = options;
	boolean_t operandEntered;
	int i, j;
	int ret = 0;
	int stmfRet;
	int outerLoop;
	unsigned int inGuid[sizeof (stmfGuid)];
	stmfGuid cmpGuid;
	boolean_t verbose = B_FALSE;
	boolean_t found;
	char sGuid[GUID_INPUT + 1];
	stmfGuidList *luList;
	stmfLogicalUnitProperties luProps;
	boolean_t invalidInput = B_FALSE;
	stmfViewEntryList *viewEntryList;

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
		}
	}

	if ((stmfRet = stmfGetLogicalUnitList(&luList))
	    != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("list failed"));
				break;
		}
		return (1);
	}

	if (operandLen > 0) {
		operandEntered = B_TRUE;
		outerLoop = operandLen;
	} else {
		operandEntered = B_FALSE;
		outerLoop = 1;
	}


	for (invalidInput = B_FALSE, i = 0; i < outerLoop; i++) {
		if (operandEntered) {
			if (strlen(operands[i]) != GUID_INPUT) {
				invalidInput = B_TRUE;
			} else {
				for (j = 0; j < GUID_INPUT; j++) {
					if (!isxdigit(operands[i][j])) {
						invalidInput = B_TRUE;
						break;
					}
				}
			}
			if (invalidInput) {
				(void) fprintf(stderr, "%s: %s: %s%d%s\n",
				    cmdName, operands[i], gettext("must be "),
				    GUID_INPUT,
				    gettext(" hexadecimal digits long"));
				continue;
			}

			for (j = 0; j < GUID_INPUT; j++) {
				sGuid[j] = tolower(operands[i][j]);
			}
			sGuid[j] = 0;

			(void) sscanf(sGuid,
			    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
			    &inGuid[0], &inGuid[1], &inGuid[2], &inGuid[3],
			    &inGuid[4], &inGuid[5], &inGuid[6], &inGuid[7],
			    &inGuid[8], &inGuid[9], &inGuid[10], &inGuid[11],
			    &inGuid[12], &inGuid[13], &inGuid[14], &inGuid[15]);

			for (j = 0; j < sizeof (stmfGuid); j++) {
				cmpGuid.guid[j] = inGuid[j];
			}
		}

		for (found = B_FALSE, j = 0; j < luList->cnt; j++) {
			if (operandEntered) {
				if (bcmp(luList->guid[j].guid, cmpGuid.guid,
				    sizeof (stmfGuid)) == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) printf("LU Name: ");
				printGuid(&luList->guid[j], stdout);
				(void) printf("\n");

				if (verbose) {
					stmfRet = stmfGetLogicalUnitProperties(
					    &(luList->guid[j]), &luProps);
					if (stmfRet == STMF_STATUS_SUCCESS) {
						printLuProps(&luProps);
					} else {
						(void) fprintf(stderr, "%s:",
						    cmdName);
						printGuid(&luList->guid[j],
						    stderr);
						(void) fprintf(stderr, "%s\n",
						    gettext(" get properties "
						    "failed"));
					}
					stmfRet = stmfGetViewEntryList(
					    &(luList->guid[j]),
					    &viewEntryList);
					(void) printf(PROPS_FORMAT,
					    "View Entry Count");
					if (stmfRet == STMF_STATUS_SUCCESS) {
						(void) printf("%d",
						    viewEntryList->cnt);
					} else if (stmfRet ==
					    STMF_ERROR_NOT_FOUND) {
						(void) printf("0");
					} else {
						(void) printf("unknown");
					}
					(void) printf("\n");
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], gettext("not found"));
			ret = 1;
		}
	}

	return (ret);
}

static void
printGuid(stmfGuid *guid, FILE *stream)
{
	int i;
	for (i = 0; i < 16; i++) {
		(void) fprintf(stream, "%02X", guid->guid[i]);
	}
}


/*
 * printLuProps
 *
 * Prints the properties for a logical unit
 *
 */
static void
printLuProps(stmfLogicalUnitProperties *luProps)
{
	(void) printf(PROPS_FORMAT, "Operational Status");
	switch (luProps->status) {
		case STMF_LOGICAL_UNIT_ONLINE:
			(void) printf("Online");
			break;
		case STMF_LOGICAL_UNIT_OFFLINE:
			(void) printf("Offline");
			break;
		case STMF_LOGICAL_UNIT_ONLINING:
			(void) printf("Onlining");
			break;
		case STMF_LOGICAL_UNIT_OFFLINING:
			(void) printf("Offlining");
			break;
		case STMF_LOGICAL_UNIT_UNREGISTERED:
			(void) printf("unregistered");
			(void) strncpy(luProps->providerName, "unregistered",
			    sizeof (luProps->providerName));
			break;
		default:
			(void) printf("unknown");
			break;
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Provider Name");
	if (luProps->providerName[0] != 0) {
		(void) printf("%s", luProps->providerName);
	} else {
		(void) printf("unknown");
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Alias");
	if (luProps->alias[0] != 0) {
		(void) printf("%s", luProps->alias);
	} else {
		(void) printf("-");
	}
	(void) printf("\n");
}

/*
 * printTargetProps
 *
 * Prints the properties for a target
 *
 */
static void
printTargetProps(stmfTargetProperties *targetProps)
{
	(void) printf(PROPS_FORMAT, "Operational Status");
	switch (targetProps->status) {
		case STMF_TARGET_PORT_ONLINE:
			(void) printf("Online");
			break;
		case STMF_TARGET_PORT_OFFLINE:
			(void) printf("Offline");
			break;
		case STMF_TARGET_PORT_ONLINING:
			(void) printf("Onlining");
			break;
		case STMF_TARGET_PORT_OFFLINING:
			(void) printf("Offlining");
			break;
		default:
			(void) printf("unknown");
			break;
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Provider Name");
	if (targetProps->providerName[0] != 0) {
		(void) printf("%s", targetProps->providerName);
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Alias");
	if (targetProps->alias[0] != 0) {
		(void) printf("%s", targetProps->alias);
	} else {
		(void) printf("-");
	}
	(void) printf("\n");
}

/*
 * printSessionProps
 *
 * Prints the session data
 *
 */
static void
printSessionProps(stmfSessionList *sessionList)
{
	int i;
	char *cTime;
	wchar_t initiator[STMF_IDENT_LENGTH + 1];

	(void) printf(PROPS_FORMAT, "Sessions");
	(void) printf("%d\n", sessionList->cnt);
	for (i = 0; i < sessionList->cnt; i++) {
		(void) mbstowcs(initiator,
		    (char *)sessionList->session[i].initiator.ident,
		    STMF_IDENT_LENGTH);
		initiator[STMF_IDENT_LENGTH] = 0;
		(void) printf(LVL3_FORMAT, "Initiator: ");
		(void) printf("%ws\n", initiator);
		(void) printf(LVL4_FORMAT, "Alias: ");
		if (sessionList->session[i].alias[0] != 0) {
			(void) printf("%s", sessionList->session[i].alias);
		} else {
			(void) printf("-");
		}
		(void) printf("\n");
		(void) printf(LVL4_FORMAT, "Logged in since: ");
		cTime = ctime(&(sessionList->session[i].creationTime));
		if (cTime != NULL) {
			(void) printf("%s", cTime);
		} else {
			(void) printf("unknown\n");
		}
	}
}

/*
 * listStateFunc
 *
 * List the operational and config state of the stmf service
 *
 */
/*ARGSUSED*/
static int
listStateFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret;
	stmfState state;

	if ((ret = stmfGetState(&state)) != STMF_STATUS_SUCCESS) {
		switch (ret) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				ret++;
				break;
		}
		return (1);
	}

	(void) printf("%-18s: ", "Operational Status");
	switch (state.operationalState) {
		case STMF_SERVICE_STATE_ONLINE:
			(void) printf("online");
			break;
		case STMF_SERVICE_STATE_OFFLINE:
			(void) printf("offline");
			break;
		case STMF_SERVICE_STATE_ONLINING:
			(void) printf("onlining");
			break;
		case STMF_SERVICE_STATE_OFFLINING:
			(void) printf("offlining");
			break;
		default:
			(void) printf("unknown");
			break;
	}
	(void) printf("\n");
	(void) printf("%-18s: ", "Config Status");
	switch (state.configState) {
		case STMF_CONFIG_STATE_NONE:
			(void) printf("uninitialized");
			break;
		case STMF_CONFIG_STATE_INIT:
			(void) printf("initializing");
			break;
		case STMF_CONFIG_STATE_INIT_DONE:
			(void) printf("initialized");
			break;
		default:
			(void) printf("unknown");
			break;
	}
	(void) printf("\n");
	return (0);
}

/*
 * listTargetFunc
 *
 * list the targets and optionally their properties
 *
 */
/*ARGSUSED*/
static int
listTargetFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	cmdOptions_t *optionList = options;
	int ret = 0;
	int stmfRet;
	int i, j;
	int outerLoop;
	stmfSessionList *sessionList;
	stmfDevid devid;
	boolean_t operandEntered, found, verbose = B_FALSE;
	stmfDevidList *targetList;
	wchar_t targetIdent[STMF_IDENT_LENGTH + 1];
	stmfTargetProperties targetProps;

	if ((stmfRet = stmfGetTargetList(&targetList)) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_NOT_FOUND:
				ret = 0;
				break;
			case STMF_ERROR_SERVICE_OFFLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service offline"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	for (i = 0; i < outerLoop; i++) {
		if (operandEntered) {
			bzero(&devid, sizeof (devid));
			(void) parseDevid(operands[i], &devid);
		}
		for (found = B_FALSE, j = 0; j < targetList->cnt; j++) {
			if (operandEntered) {
				if (bcmp(&devid, &(targetList->devid[j]),
				    sizeof (devid)) == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) mbstowcs(targetIdent,
				    (char *)targetList->devid[j].ident,
				    STMF_IDENT_LENGTH);
				targetIdent[STMF_IDENT_LENGTH] = 0;
				(void) printf("Target: %ws\n", targetIdent);
				if (verbose) {
					stmfRet = stmfGetTargetProperties(
					    &(targetList->devid[j]),
					    &targetProps);
					if (stmfRet == STMF_STATUS_SUCCESS) {
						printTargetProps(&targetProps);
					} else {
						(void) fprintf(stderr, "%s:",
						    cmdName);
						(void) fprintf(stderr, "%s\n",
						    gettext(" get properties"
						    " failed"));
					}
					stmfRet = stmfGetSessionList(
					    &(targetList->devid[j]),
					    &sessionList);
					if (stmfRet == STMF_STATUS_SUCCESS) {
						printSessionProps(sessionList);
					} else {
						(void) fprintf(stderr, "%s:",
						    cmdName);
						(void) fprintf(stderr, "%s\n",
						    gettext(" get session info"
						    " failed"));
					}
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], "not found");
			ret = 1;
		}
	}
	return (ret);
}

/*
 * listViewFunc
 *
 * list the view entries for the specified logical unit
 *
 */
/*ARGSUSED*/
static int
listViewFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	stmfViewEntryList *viewEntryList;
	stmfGuid inGuid;
	unsigned int guid[sizeof (stmfGuid)];
	int ret = 0;
	int stmfRet;
	int i, j, outerLoop;
	boolean_t found = B_TRUE;
	boolean_t operandEntered;
	uint16_t outputLuNbr;
	wchar_t groupName[sizeof (stmfGroupName)];
	char sGuid[GUID_INPUT + 1];


	for (; options->optval; options++) {
		switch (options->optval) {
			case 'l':
				if (strlen(options->optarg) != GUID_INPUT) {
					(void) fprintf(stderr,
					    "%s: %s: %s%d%s\n",
					    cmdName, options->optarg,
					    gettext("must be "), GUID_INPUT,
					    gettext(" hexadecimal digits"
					    " long"));
					return (1);
				}
				bcopy(options->optarg, sGuid, GUID_INPUT);
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	for (i = 0; i < 32; i++)
		sGuid[i] = tolower(sGuid[i]);
	sGuid[i] = 0;

	(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
	    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10], &guid[11],
	    &guid[12], &guid[13], &guid[14], &guid[15]);

	for (i = 0; i < sizeof (stmfGuid); i++) {
		inGuid.guid[i] = guid[i];
	}

	if ((stmfRet = stmfGetViewEntryList(&inGuid, &viewEntryList))
	    != STMF_STATUS_SUCCESS) {

		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("resource busy"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("no views found"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (i = 0; i < outerLoop; i++) {
		for (found = B_FALSE, j = 0; j < viewEntryList->cnt; j++) {
			if (operandEntered) {
				if (atoi(operands[i]) ==
				    viewEntryList->ve[j].veIndex) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) printf("View Entry: %d\n",
				    viewEntryList->ve[j].veIndex);
				(void) printf(VIEW_FORMAT, "Host group");
				if (viewEntryList->ve[j].allHosts) {
					(void) printf("All\n");
				} else {
					(void) mbstowcs(groupName,
					    viewEntryList->ve[j].hostGroup,
					    sizeof (stmfGroupName) - 1);
					groupName[sizeof (stmfGroupName) - 1]
					    = 0;
					(void) printf("%ws\n", groupName);
				}
				(void) printf(VIEW_FORMAT, "Target group");
				if (viewEntryList->ve[j].allTargets) {
					(void) printf("All\n");
				} else {
					(void) mbstowcs(groupName,
					    viewEntryList->ve[j].targetGroup,
					    sizeof (stmfGroupName) - 1);
					groupName[sizeof (stmfGroupName) - 1]
					    = 0;
					(void) printf("%ws\n", groupName);
				}
				outputLuNbr = ((viewEntryList->ve[j].luNbr[0] &
				    0x3F) << 8) | viewEntryList->ve[j].luNbr[1];
				(void) printf(VIEW_FORMAT, "LUN");
				(void) printf("%d\n", outputLuNbr);
				if (found && operandEntered) {
					break;
				}
			}
		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s, %s: %s\n", cmdName,
			    sGuid, operands[i], gettext("not found"));
			ret = 1;
		}
	}

	return (ret);
}


/*
 * onlineOfflineLu
 *
 * Purpose: Online or offline a logical unit
 *
 * lu - logical unit to online or offline
 *
 * state - ONLINE_LU
 *         OFFLINE_LU
 */
static int
onlineOfflineLu(char *lu, int state)
{
	char sGuid[GUID_INPUT + 1];
	stmfGuid inGuid;
	unsigned int guid[sizeof (stmfGuid)];
	int i;
	int ret = 0;

	if (strlen(lu) != GUID_INPUT) {
		(void) fprintf(stderr, "%s: %s: %s %d %s\n", cmdName, lu,
		    gettext("must be"), GUID_INPUT,
		    gettext("hexadecimal digits long"));
		return (1);
	}

	bcopy(lu, sGuid, GUID_INPUT);

	for (i = 0; i < 32; i++)
		sGuid[i] = tolower(sGuid[i]);
	sGuid[i] = 0;

	(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
	    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10], &guid[11],
	    &guid[12], &guid[13], &guid[14], &guid[15]);

	for (i = 0; i < sizeof (stmfGuid); i++) {
		inGuid.guid[i] = guid[i];
	}

	if (state == ONLINE_LU) {
		ret = stmfOnlineLogicalUnit(&inGuid);
	} else if (state == OFFLINE_LU) {
		ret = stmfOfflineLogicalUnit(&inGuid);
	}
	if (ret != STMF_STATUS_SUCCESS) {
		switch (ret) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    lu, gettext("not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
	}
	return (ret);
}

/*
 * onlineLuFunc
 *
 * Purpose: Online a logical unit
 *
 */
/*ARGSUSED*/
static int
onlineLuFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	return (onlineOfflineLu(operands[0], ONLINE_LU));
}

/*
 * offlineLuFunc
 *
 * Purpose: Offline a logical unit
 *
 */
/*ARGSUSED*/
static int
offlineLuFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	return (onlineOfflineLu(operands[0], OFFLINE_LU));
}

/*
 * onlineOfflineTarget
 *
 * Purpose: Online or offline a target
 *
 * target - target to online or offline
 *
 * state - ONLINE_TARGET
 *         OFFLINE_TARGET
 */
static int
onlineOfflineTarget(char *target, int state)
{
	int ret = 0;
	stmfDevid devid;

	if (parseDevid(target, &devid) != 0) {
		(void) fprintf(stderr, "%s: %s: %s\n",
		    cmdName, target, gettext("unrecognized device id"));
		return (1);
	}
	if (state == ONLINE_TARGET) {
		ret = stmfOnlineTarget(&devid);
	} else if (state == OFFLINE_TARGET) {
		ret = stmfOfflineTarget(&devid);
	}
	if (ret != STMF_STATUS_SUCCESS) {
		switch (ret) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    target, gettext("not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
	}
	return (ret);
}

/*
 * onlineTargetFunc
 *
 * Purpose: Online a target
 *
 */
/*ARGSUSED*/
static int
onlineTargetFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	return (onlineOfflineTarget(operands[0], ONLINE_TARGET));
}

/*
 * offlineTargetFunc
 *
 * Purpose: Offline a target
 *
 */
/*ARGSUSED*/
static int
offlineTargetFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	return (onlineOfflineTarget(operands[0], OFFLINE_TARGET));
}


/*ARGSUSED*/
static int
removeHostGroupMemberFunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	stmfDevid devid;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};

	for (; options->optval; options++) {
		switch (options->optval) {
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	for (i = 0; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfRemoveFromHostGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_MEMBER_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], "resource busy");
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}

/*
 * removeTargetGroupMemberFunc
 *
 * Removes one or more members from a target group
 *
 */
/*ARGSUSED*/
static int
removeTargetGroupMemberFunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	stmfDevid devid;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};

	for (; options->optval; options++) {
		switch (options->optval) {
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	for (i = 0; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfRemoveFromTargetGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_MEMBER_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ws: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}

/*
 * removeViewFunc
 *
 * Removes one or more view entries from a logical unit
 *
 */
/*ARGSUSED*/
static int
removeViewFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	char sGuid[GUID_INPUT + 1];
	stmfViewEntryList *viewEntryList;
	stmfGuid inGuid;
	uint32_t count;
	unsigned int guid[sizeof (stmfGuid)];
	char *endPtr;
	uint32_t veNbr;
	int i;
	boolean_t all = B_FALSE;
	boolean_t luInput = B_FALSE;
	int ret = 0;
	int stmfRet;

	/* Note: 'l' is required */
	for (; options->optval; options++) {
		switch (options->optval) {
			case 'l':
				if (strlen(options->optarg) != GUID_INPUT) {
					(void) fprintf(stderr,
					    "%s: %s: %s %d %s\n",
					    cmdName, options->optarg,
					    gettext("must be"), GUID_INPUT,
					    gettext("hexadecimal digits long"));
					return (1);
				}
				bcopy(options->optarg, sGuid, GUID_INPUT);
				luInput = B_TRUE;
				break;
			case 'a':
				/* removing all view entries for this GUID */
				all = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    "unknown option");
				return (1);
		}
	}

	if (!all && operandLen == 0) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("no view entries specified"));
		return (1);
	}

	if (!luInput) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("logical unit (-l) not specified"));
		return (1);
	}

	for (i = 0; i < 32; i++)
		sGuid[i] = tolower(sGuid[i]);
	sGuid[i] = 0;

	(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
	    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10], &guid[11],
	    &guid[12], &guid[13], &guid[14], &guid[15]);

	for (i = 0; i < sizeof (stmfGuid); i++) {
		inGuid.guid[i] = guid[i];
	}

	if ((stmfRet = stmfGetViewEntryList(&inGuid, &viewEntryList))
	    != STMF_STATUS_SUCCESS) {

		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("resource busy"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("no views found"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("unknown error"));
				break;
		}
		return (1);
	}

	if (all) {
		count = viewEntryList->cnt;
	} else {
		count = operandLen;
	}

	for (i = 0; i < count; i++) {
		if (all) {
			veNbr = viewEntryList->ve[i].veIndex;
		} else {
			endPtr = NULL;
			veNbr = strtol(operands[i], &endPtr, 10);
			if (endPtr && *endPtr != 0) {
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("invalid input"));
				continue;
			}
		}
		stmfRet = stmfRemoveViewEntry(&inGuid, veNbr);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %d: %s\n",
				    cmdName, sGuid, veNbr,
				    gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    sGuid, gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_CONFIG_NONE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service is not initialized"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s, %d: %s",
				    cmdName, sGuid, veNbr,
				    gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 *  copied from usr/src/cmd/zoneadm/zoneadm.c in OS/Net
 *  (changed name to lowerCamelCase to keep consistent with this file)
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

int
main(int argc, char *argv[])
{
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	int ret;
	int funcRet;
	void *subcommandArgs = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	(void) snprintf(versionString, VERSION_STRING_MAX_LEN, "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subCommandPropsTbl = &subcommands[0];

	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret != 0) {
		return (ret);
	}

	return (funcRet);
} /* end main */
