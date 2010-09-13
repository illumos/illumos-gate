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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * mpathadm.c : MP API CLI program
 *
 */

#include <libintl.h>

#include <mpapi.h>
#include "cmdparse.h"
#include "mpathadm_text.h"
#include "mpathadm.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <devid.h>
#include <fcntl.h>

/* helper functions */
static char *getExecBasename(char *);

/* object functions per subcommand */
static int listFunc(int, char **, int, cmdOptions_t *, void *);
static int showFunc(int, char **, int, cmdOptions_t *, void *);
static int modifyFunc(int, char **, int, cmdOptions_t *, void *);
static int enableFunc(int, char **, int, cmdOptions_t *, void *);
static int disableFunc(int, char **, int, cmdOptions_t *, void *);
static int failoverFunc(int, char **, int, cmdOptions_t *, void *);
static int overrideFunc(int, char **, int, cmdOptions_t *, void *);

#define	VERSION_STRING_MAX_LEN	10

#define	OPTIONSTRING_NAME	"name"
#define	OPTIONSTRING_TPNAME	"target-port name"
#define	OPTIONSTRING_ONOFF	"on/off"
#define	OPTIONSTRING_LBTYPE	"loadbalance type"
#define	OPTIONSTRING_IPORT	"initiator-port name"
#define	OPTIONSTRING_LUNIT	"logical-unit name"
#define	OPTIONSTRING_CANCEL	"cancel"
#define	OPTIONSTRING_VALUE	"value"

/*
 * Version number: (copied from iscsiadm)
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"


/* globals */
static char *cmdName;


/*
 * ****************************************************************************
 *
 * getExecBasename - copied from iscsiadm code
 *
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 * Returns:
 *  command name portion of execFullName
 *
 * ****************************************************************************
 */
static char *
getExecBasename(char *execFullname)
{
	char 				*lastSlash, *execBasename;

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
 * Add new options here
 */

/* tables set up based on cmdparse instructions */
optionTbl_t longOptions[] = {
	{"inqname", required_arg, 'n', OPTIONSTRING_NAME},
	{"target-port", required_arg, 't', OPTIONSTRING_TPNAME},
	{"autofailback", required_arg, 'a', OPTIONSTRING_ONOFF},
	{"autoprobe", required_arg, 'p', OPTIONSTRING_ONOFF},
	{"loadbalance", required_arg, 'b', OPTIONSTRING_LBTYPE},
	{"initiator-port", required_arg, 'i', OPTIONSTRING_IPORT},
	{"logical-unit", required_arg, 'l', OPTIONSTRING_LUNIT},
	{"cancel", no_arg, 'c', OPTIONSTRING_CANCEL},
	{"vendor-id", required_arg, 'd', OPTIONSTRING_VALUE},
	{NULL, 0, 0, 0}
};


/*
 * Add new subcommands here
 */
subcommand_t subcommands[] = {
	{"list", LIST, listFunc},
	{"show", SHOW, showFunc},
	{"modify", MODIFY, modifyFunc},
	{"enable", ENABLE, enableFunc},
	{"disable", DISABLE, disableFunc},
	{"failover", FAILOVER, failoverFunc},
	{"override", OVERRIDE, overrideFunc},
	{NULL, 0, NULL}
};

/*
 * Add objects here
 */
object_t objects[] = {
	{"mpath-support", MPATH_SUPPORT},
	{"logical-unit", LOGICAL_UNIT},
	{"LU", LOGICAL_UNIT},
	{"initiator-port", INITIATOR_PORT},
	{"path", PATH},
	{NULL, 0}
};

/*
 * Rules for subcommands and objects
 *
 * command
 *
 * reqOpCmd -> subcommands that must have an operand
 * optOpCmd -> subcommands that may have an operand
 * noOpCmd -> subcommands that will have no operand
 * invCmd -> subcommands that are invalid
 * multOpCmd -> subcommands that can accept multiple operands
 * operandDefinition -> Usage definition for the operand of this object
 */
objectRules_t objectRules[] = {
	{MPATH_SUPPORT, SHOW|MODIFY|ADD, LIST|REMOVE, 0,
	    ENABLE|DISABLE|FAILOVER|OVERRIDE, LIST|SHOW|MODIFY,
	    "mpath-support name"},
	{INITIATOR_PORT, SHOW, LIST, 0,
	    MODIFY|ENABLE|DISABLE|FAILOVER|OVERRIDE|ADD|REMOVE, LIST|SHOW,
	    "initiator-port name"},
	{LOGICAL_UNIT, SHOW|MODIFY|FAILOVER, LIST, 0,
	    ENABLE|DISABLE|OVERRIDE|ADD|REMOVE, LIST|SHOW|MODIFY,
	    "logical-unit name"},
	{PATH, 0, 0, ENABLE|DISABLE|OVERRIDE,
	    SHOW|LIST|MODIFY|FAILOVER|ADD|REMOVE, 0,
	    "initiator-port name"},
	{0, 0, 0, 0, 0, NULL}
};

/*
 * list of objects, subcommands, valid short options, required flag and
 * exclusive option string
 *
 * If it's not here, there are no options for that object.
 */
optionRules_t optionRules[] = {
	{LOGICAL_UNIT, LIST, "nt", B_FALSE, NULL},
	{LOGICAL_UNIT, MODIFY, "apb", B_TRUE, NULL},
	{MPATH_SUPPORT, MODIFY, "apb", B_TRUE, NULL},
	{MPATH_SUPPORT, ADD, "d", B_TRUE, NULL},
	{MPATH_SUPPORT, REMOVE, "d", B_TRUE, NULL},
	{PATH, ENABLE, "itl", B_TRUE, NULL},
	{PATH, DISABLE, "itl", B_TRUE, NULL},
	{PATH, OVERRIDE, "itlc", B_TRUE, NULL},
	{0, 0, 0, 0, 0}
};


/*
 * ****************************************************************************
 *
 * listMpathSupport - mpathadm list mpath-support
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 *
 * ****************************************************************************
 */
int
listMpathSupport(int operandLen, char *operand[])
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_PLUGIN_PROPERTIES			pluginProps;
	MP_OID_LIST				*pPluginOidList;
	boolean_t				shown = B_FALSE;
	/* number of plugins listed */
	int					i, op;

	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
	    != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (mpstatus);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (ERROR_CLI_FAILED);
	}


	/* loop through operands first */
	for (op = 0; (op < operandLen) |
	    ((0 == operandLen) && (B_FALSE == shown)); op++) {
		shown = B_TRUE;
		for (i = 0; i < pPluginOidList->oidCount; i++) {

			(void) memset(&pluginProps, 0,
			    sizeof (MP_PLUGIN_PROPERTIES));
			mpstatus =
			    MP_GetPluginProperties(pPluginOidList->oids[i],
			    &pluginProps);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
			} else {
				if (0 == operandLen) {
					/* if no operands, list them all */
					(void) printf("%s  %s\n",
					    getTextString(
					    TEXT_LB_MPATH_SUPPORT),
					    pluginProps.fileName);
				} else {
					/* if there is an operand... */
					/* ... compare and display if match */
					if (0 ==
					    strcmp(operand[op],
					    pluginProps.fileName)) {
						(void) printf("%s  %s\n",
						    getTextString(
						    TEXT_LB_MPATH_SUPPORT),
						    pluginProps.fileName);
					} else {
				/* begin back-up indentation */
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, getTextString(
				    ERR_CANT_FIND_MPATH_SUPPORT_WITH_NAME),
				    operand[op]);
				/* end back-up indentation */
						(void) printf("\n");
					}
				}
			}
		}
	}

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * showMpathSupport - mpathadm show mpath-support <mpath-support name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 *
 * ****************************************************************************
 */
int
showMpathSupport(int operandLen, char *operand[])
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_PLUGIN_PROPERTIES			pluginProps;
	MP_OID_LIST				*pPluginOidList;
	MP_OID_LIST				*deviceOidListArray;
	MP_DEVICE_PRODUCT_PROPERTIES		devProps;
	boolean_t				bListIt = B_FALSE;
	int					op, i, j;
	MP_LOAD_BALANCE_TYPE 			lb;


	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList)) !=
	    MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s:  %s\n",
		    cmdName, getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (mpstatus);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s:  %s\n",
		    cmdName, getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (ERROR_CLI_FAILED);
	}

	for (op = 0; op < operandLen; op++) {
		bListIt = B_FALSE;

		for (i = 0; i < pPluginOidList->oidCount; i++) {

			(void) memset(&pluginProps, 0,
			    sizeof (MP_PLUGIN_PROPERTIES));
			mpstatus =
			    MP_GetPluginProperties(pPluginOidList->oids[i],
			    &pluginProps);
			if (MP_STATUS_SUCCESS != mpstatus) {
				(void) fprintf(stderr, "%s: %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
				return (mpstatus);
				}

				if (0 == operandLen) {
					/* if no operand, list it */
					bListIt = B_TRUE;
				} else {
					/* ... compare and display if match */
					if (0 ==
					    strcmp(operand[op],
					    pluginProps.fileName)) {
						bListIt = B_TRUE;
				}
			}

			if (B_TRUE != bListIt) {
				break;
			}

			(void) printf("%s  %s\n",
			    getTextString(TEXT_LB_MPATH_SUPPORT),
			    pluginProps.fileName);

			/* display the info for this plugin */
			(void) printf("\t%s  ", getTextString(TEXT_LB_VENDOR));
			displayWideArray(pluginProps.vendor,
			    sizeof (pluginProps.vendor));
			(void) printf("\n\t%s  ",
			    getTextString(TEXT_LB_DRIVER_NAME));
			displayArray(pluginProps.driverName,
			    sizeof (pluginProps.driverName));
			(void) printf("\n\t%s  ",
			    getTextString(TEXT_LB_DEFAULT_LB));
			/* don't ignore load balance type none. */
			if (pluginProps.defaultloadBalanceType == 0) {
				(void) printf("%s",
				    getTextString(TEXT_LBTYPE_NONE));
			} else {
				displayLoadBalanceString(
				    pluginProps.defaultloadBalanceType);
			}
			(void) printf("\n");


			(void) printf("\t%s  \n",
			    getTextString(TEXT_LB_SUPPORTED_LB));
			/* check each bit, display string if found set */
			if (pluginProps.supportedLoadBalanceTypes == 0) {
				(void) printf("\t\t%s\n",
				    getTextString(TEXT_LBTYPE_NONE));
			} else {
				lb = 1;
				do {
					if (0 != (lb & pluginProps.
					    supportedLoadBalanceTypes)) {
						(void) printf("\t\t");
						displayLoadBalanceString(lb &
						    pluginProps.
						    supportedLoadBalanceTypes);
						(void) printf("\n");
					}
					lb = lb<<1;
				} while (lb < 0x80000000);
			}

			(void) printf("\t%s  %s\n",
			    getTextString(TEXT_LB_ALLOWS_ACT_TPG),
			    (MP_TRUE == pluginProps.canSetTPGAccess)?
			    getTextString(TEXT_YES):getTextString(TEXT_NO));
			(void) printf("\t%s  %s\n",
			    getTextString(TEXT_LB_ALLOWS_PATH_OV),
			    (MP_TRUE == pluginProps.canOverridePaths)?
			    getTextString(TEXT_YES):getTextString(TEXT_NO));
			(void) printf("\t%s  %d\n",
			    getTextString(TEXT_LB_SUPP_AUTO_FB),
			    pluginProps.autoFailbackSupport);
			if ((MP_AUTOFAILBACK_SUPPORT_PLUGIN  ==
			    pluginProps.autoFailbackSupport) |
			    (MP_AUTOFAILBACK_SUPPORT_PLUGINANDMPLU
			    == pluginProps.autoFailbackSupport)) {
				(void) printf("\t%s  %s\n",
				    getTextString(TEXT_LB_AUTO_FB),
				    pluginProps.pluginAutoFailbackEnabled?\
				    getTextString(TEXT_ON):
				    getTextString(TEXT_OFF));
				(void) printf("\t%s  %d/%d\n",
				    getTextString(TEXT_LB_FB_POLLING_RATE),
				    pluginProps.currentFailbackPollingRate,
				    pluginProps.failbackPollingRateMax);
			} else {
				(void) printf("\t%s  %s\n",
				    getTextString(TEXT_LB_AUTO_FB),
				    getTextString(TEXT_NA));
				(void) printf("\t%s  %s/%s\n",
				    getTextString(TEXT_LB_FB_POLLING_RATE),
				    getTextString(TEXT_NA),
				    getTextString(TEXT_NA));
			}
			(void) printf("\t%s  %d\n",
			    getTextString(TEXT_LB_SUPP_AUTO_P),
			    pluginProps.autoProbingSupport);
			if ((MP_AUTOPROBING_SUPPORT_PLUGIN  ==
			    pluginProps.autoProbingSupport) |
			    (MP_AUTOPROBING_SUPPORT_PLUGIN ==
			    pluginProps.autoProbingSupport)) {
				(void) printf("\t%s  %s\n",
				    getTextString(TEXT_LB_AUTO_PROB),
				    (MP_TRUE ==
				    pluginProps.pluginAutoProbingEnabled)?\
				    getTextString(TEXT_YES):
				    getTextString(TEXT_NO));
				(void) printf("\t%s  %d/%d\n",
				    getTextString(TEXT_LB_PR_POLLING_RATE),
				    pluginProps.currentProbingPollingRate,
				    pluginProps.probingPollingRateMax);
			} else {
				(void) printf("\t%s  %s\n",
				    getTextString(TEXT_LB_AUTO_PROB),
				    getTextString(TEXT_NA));
				(void) printf("\t%s  %s/%s\n",
				    getTextString(TEXT_LB_PR_POLLING_RATE),
				    getTextString(TEXT_NA),
				    getTextString(TEXT_NA));
			}


			(void) printf("\t%s\n",
			    getTextString(TEXT_LB_SUPP_DEVICES));


			if (MP_TRUE !=
			    pluginProps.onlySupportsSpecifiedProducts) {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) printf(getTextString(TEXT_ANY_DEVICE));
			} else {
				/* if only supports specific products, */
				/* get device product properties supported */

				mpstatus = MP_GetDeviceProductOidList(\
				    pPluginOidList->oids[i],
				    &deviceOidListArray);
				if (mpstatus != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s:  %s\n",
					    cmdName, getTextString(
					    ERR_NO_SUPP_DEVICE_INFO));
					/* can't get any more info, */
					/* so we're done with this one */
					break;
				}

				for (j = 0; j < deviceOidListArray->oidCount;
				    j++) {
				/* begin backup indentation */
				(void) memset(&devProps, 0,
				    sizeof (MP_DEVICE_PRODUCT_PROPERTIES));
				/* end backup indentation */
					if ((mpstatus =
					    MP_GetDeviceProductProperties(\
					    deviceOidListArray->oids[j],
					    &devProps)) == MP_STATUS_SUCCESS) {

						(void) printf("\t\t%s  ",
						    getTextString(
						    TEXT_LB_VENDOR));
						displayArray(devProps.vendor,
						    sizeof (devProps.vendor));
						(void) printf("\n\t\t%s  ",
						    getTextString(
						    TEXT_LB_PRODUCT));
						displayArray(devProps.product,
						    sizeof (devProps.product));
						(void) printf("\n\t\t%s  ",
						    getTextString(
						    TEXT_LB_REVISION));
						displayArray(devProps.revision,
						    sizeof (devProps.revision));

						(void) printf("\n\t\t%s\n",
						    getTextString(
						    TEXT_LB_SUPPORTED_LB));
		/* begin back-up indentation */
		if (devProps.supportedLoadBalanceTypes == 0) {
			(void) printf("\t\t\t%s\n",
			    getTextString(TEXT_LBTYPE_NONE));
		} else {
			lb = 1;
			do {
				if (0 != (lb &
				    devProps.supportedLoadBalanceTypes)) {
					(void) printf("\t\t\t");
					displayLoadBalanceString(lb &
					    devProps.supportedLoadBalanceTypes);
					(void) printf("\n");
				}
				lb = lb<<1;
			} while (lb < 0x80000000);
		}
		/* end back-up indentation */
						(void) printf("\n");

					} else {
						(void) fprintf(stderr,
						    "%s:  %s\n", cmdName,
						    getTextString(
						    ERR_NO_SUPP_DEVICE_INFO));
					}
				} /* for j */
			} /* if only supports specified devices */

		} /* for each plugin */

		if (B_FALSE == bListIt) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr, getTextString(
			    ERR_CANT_FIND_MPATH_SUPPORT_WITH_NAME),
			    operand[op]);
			(void) printf("\n");

		}

	} /* for each operand */


	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * modifyMpathSupport -
 * 	mpathadm modify mpath-support [options] <mpath-support name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
int
modifyMpathSupport(int operandLen, char *operand[], cmdOptions_t *options)
{
	MP_STATUS		mpstatus = MP_STATUS_SUCCESS;
	MP_PLUGIN_PROPERTIES	pluginProps;
	MP_OID_LIST		*pPluginOidList;
	boolean_t		bFoundIt = B_FALSE;
	MP_OID			pluginOid;
	cmdOptions_t 		*optionList = options;
	char			*cmdStr = getTextString(TEXT_UNKNOWN);
	int			op, i, lbValue;

	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
	    != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (mpstatus);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (ERROR_CLI_FAILED);
	}

	for (op = 0; op < operandLen; op++) {
		bFoundIt = B_FALSE;
		for (i = 0;
		    (i < pPluginOidList->oidCount) && (B_TRUE != bFoundIt);
		    i++) {

			(void) memset(&pluginProps, 0,
			    sizeof (MP_PLUGIN_PROPERTIES));
			if ((mpstatus =
			    MP_GetPluginProperties(pPluginOidList->oids[i],
			    &pluginProps)) == MP_STATUS_SUCCESS) {

				if (0 == strcmp(operand[op],
				    pluginProps.fileName)) {
					bFoundIt = B_TRUE;
					pluginOid = pPluginOidList->oids[i];
				}
			} else {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
			}

			if (B_FALSE == bFoundIt) {
				break;
			}

/* begin back-up indentation */
	/* we found the plugin oid */
	/* now change the options requested */
	switch (optionList->optval) {
		case 'a':
			/* modify autofailback */
			cmdStr = getTextString(TEXT_AUTO_FAILBACK);
			if (0 == strcasecmp(optionList->optarg,
			    getTextString(TEXT_ON))) {
				mpstatus =
				    MP_EnableAutoFailback(pluginOid);
			} else if (0 ==
			    strcasecmp(optionList->optarg,
			    getTextString(TEXT_OFF))) {
				mpstatus =
				    MP_DisableAutoFailback(pluginOid);
			} else {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, getTextString(
				    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
				    cmdStr,
				    getTextString(TEXT_ILLEGAL_ARGUMENT));
				(void) printf("\n");
				return (ERROR_CLI_FAILED);
			}
			break;
		case 'p':
			/* modify autoprobing */
			cmdStr = getTextString(TEXT_AUTO_PROBING);
			if (0 == strcasecmp(optionList->optarg,
			    getTextString(TEXT_ON))) {
				mpstatus =
				    MP_EnableAutoProbing(pluginOid);
			} else if (0 ==
			    strcasecmp(optionList->optarg,
			    getTextString(TEXT_OFF))) {
				mpstatus =
				    MP_DisableAutoProbing(pluginOid);
			} else {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, getTextString(
				    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
				    cmdStr,
				    getTextString(TEXT_ILLEGAL_ARGUMENT));
				(void) printf("\n");
				return (ERROR_CLI_FAILED);
			}
			break;
		case 'b':
			/* modify loadbalance type */
			cmdStr = getTextString(TEXT_LOAD_BALANCE);
			/* user of the cli sends text string, we need the int */
			/* value to pass to the mpapi */
			lbValue = getLbValueFromString(optionList->optarg);
			mpstatus =
			    MP_SetPluginLoadBalanceType(pluginOid,
			    lbValue);
			break;

		} /* switch */
		if (MP_STATUS_SUCCESS != mpstatus) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
			    cmdStr, getMpStatusStr(mpstatus));
			(void) printf("\n");
			return (mpstatus);
		}
/* end back-up indentation */

		} /* for each plugin */

		if (B_FALSE == bFoundIt) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
			    cmdStr,
			    getTextString(TEXT_MPATH_SUPPORT_NOT_FOUND));
			(void) printf("\n");
			return (ERROR_CLI_FAILED);
		}

	} /* for each operand */

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * listLogicalUnit -
 * 	mpathadm list {logical-unit | LU} [options] [<logical-unit name>, ...]
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
int
listLogicalUnit(int operandLen, char *operand[], cmdOptions_t *options)
{
	MP_STATUS mpstatus = MP_STATUS_SUCCESS;
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES luProps;
	MP_PLUGIN_PROPERTIES pluginProps;
	MP_TARGET_PORT_PROPERTIES tportProps;
	MP_OID_LIST *pPluginOidList, *pLogicalUnitOidList,
	    *pTpgOidListArray, *pTportOidListArray;
	boolean_t bListIt = B_FALSE, bFoundOperand = B_FALSE,
	    *bFoundOption, bContinue = B_FALSE;
	MP_OID luOid;
	cmdOptions_t *optionList = options;
	int opListCount = 0, i = 0, lu = 0, tpg = 0, opoffset = 0, j = 0,
	    opStart = 0, opEnd = 0, opIndex;

	/* count number of options */
	for (; optionList->optval; optionList++) {
		opListCount++;
	}

	bFoundOption = malloc((sizeof (boolean_t)) * opListCount);
	if (NULL == bFoundOption) {
		(void) fprintf(stdout, "%s\n",
		    getTextString(ERR_MEMORY_ALLOCATION));
		return (ERROR_CLI_FAILED);
	}

	/* list to keep track of multiple options */
	optionList = options;
	for (opIndex = 0; opIndex < opListCount; opIndex++) {
		bFoundOption[opIndex] = B_FALSE;
	}

	optionList = options;

	/* if no operands or options, list everything we find */
	if ((0 == operandLen) && (0 == opListCount)) {
		if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
		    != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
			return (mpstatus);
		}
		if ((NULL == pPluginOidList) ||
		    (pPluginOidList->oidCount < 1)) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
			return (ERROR_CLI_FAILED);
		}

		for (i = 0; i < pPluginOidList->oidCount; i++) {
			/* get properties so we can list the name */
			(void) memset(&pluginProps, 0,
			    sizeof (MP_PLUGIN_PROPERTIES));
			if ((mpstatus =
			    MP_GetPluginProperties(pPluginOidList->oids[i],
			    &pluginProps)) != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
				return (mpstatus);
			}

			/* attempt to find this logical unit */
			mpstatus = MP_GetMultipathLus(pPluginOidList->oids[i],
			    &pLogicalUnitOidList);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_LU_LIST));
				return (mpstatus);
			}

			for (lu = 0; lu < pLogicalUnitOidList->oidCount; lu++) {
			/* begin backup indentation */
			/* get lu properties so we can check the name */
			(void) memset(&luProps, 0,
			    sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));
			/* end backup indentation */
				mpstatus =
				    MP_GetMPLogicalUnitProperties(
				    pLogicalUnitOidList->oids[lu],
				    &luProps);
				if (mpstatus != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s:  %s\n",
					    cmdName,
					    getTextString(ERR_NO_PROPERTIES));
					return (mpstatus);
				}

				luOid = pLogicalUnitOidList->oids[lu];
				if (listIndividualLogicalUnit(luOid, luProps)
				    != 0) {
					return (ERROR_CLI_FAILED);
				}
			} /* for each LU */
		} /* for each plugin */
	} else { /* we have operands and/or options */

		/* check if we have operands */
		if (0 == operandLen) {
			/* no operands */
			opStart = -1;
			opEnd = 0;
		} else {
			/* operands */
			opStart = 0;
			opEnd = operandLen;
		}

		if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
		    != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
			return (mpstatus);
		}
		if ((NULL == pPluginOidList) ||
		    (pPluginOidList->oidCount < 1)) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
			return (ERROR_CLI_FAILED);
		}

		for (opoffset = opStart; opoffset < opEnd; opoffset++) {
			/* loop through operands */
			bFoundOperand = B_FALSE;

			for (i = 0; i < pPluginOidList->oidCount; i++) {

				/*
				 * loop through plugin, and get properties
				 * so we can list the name
				 */
				(void) memset(&pluginProps, 0,
				    sizeof (MP_PLUGIN_PROPERTIES));
				if ((mpstatus =
				    MP_GetPluginProperties(
				    pPluginOidList->oids[i], &pluginProps))
				    != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s:  %s\n",
					    cmdName,
					    getTextString(ERR_NO_PROPERTIES));
					return (mpstatus);
				}

				/* attempt to find this logical unit */
				mpstatus =
				    MP_GetMultipathLus(pPluginOidList->oids[i],
				    &pLogicalUnitOidList);
				if (mpstatus != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s:  %s\n",
					    cmdName,
					    getTextString(ERR_NO_LU_LIST));
					return (mpstatus);
				}

				for (lu = 0;
				    (lu < pLogicalUnitOidList->oidCount);
				    lu++) {
					bListIt = B_FALSE;
			/* begin backup indentation */
			/* get lu props & check the name */
			(void) memset(&luProps, 0,
			    sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));
			/* end backup indentation */
					mpstatus =
					    MP_GetMPLogicalUnitProperties(
					    pLogicalUnitOidList->oids[lu],
					    &luProps);
					if (mpstatus != MP_STATUS_SUCCESS) {
						(void) fprintf(stderr,
						    "%s:  %s\n", cmdName,
						    getTextString(
						    ERR_NO_PROPERTIES));
						return (mpstatus);
					}

					/*
					 * compare operand - is it a match?
					 * If so, continue
					 */

					bContinue = B_TRUE;
					if (operandLen > 0) {
						bContinue =
						    compareLUName(
						    operand[opoffset],
						    luProps.deviceFileName);
					}

					if (B_TRUE == bContinue) {

						if (0 != opListCount) {
							/* check options */


/* begin backup indentation */
optionList = options;

for (opIndex = 0; optionList->optval; optionList++, opIndex++) {
switch (optionList->optval) {
	case 'n':
		if (B_TRUE ==
		    compareLUName(optionList->optarg, luProps.name)) {
			bListIt = B_TRUE;
			bFoundOperand = B_TRUE;
			bFoundOption[opIndex] = B_TRUE;
		}
		break;
	case 't':
		/* get TPG list */
		mpstatus =
		    MP_GetAssociatedTPGOidList(pLogicalUnitOidList->oids[lu],
		    &pTpgOidListArray);
		if (mpstatus !=  MP_STATUS_SUCCESS) {
			(void) fprintf(stderr,  "%s:  %s\n", cmdName,
			    getTextString(ERR_NO_ASSOC_TPGS));
			return (mpstatus);
		}

		/* get target ports */
		for (tpg = 0;
		    (NULL != pTpgOidListArray) &&
		    (tpg < pTpgOidListArray->oidCount) &&
		    (B_FALSE == bListIt); tpg++) {
			mpstatus =
			    MP_GetTargetPortOidList(pTpgOidListArray->oids[tpg],
			    &pTportOidListArray);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName,
				    getTextString(ERR_NO_ASSOC_TPORTS));
				return (mpstatus);
			}

			/* get target port properties for the name */
			for (j = 0; (NULL != pTportOidListArray) &&
			    (j < pTportOidListArray->oidCount) &&
			    (B_FALSE == bListIt); j++) {
				(void) memset(&tportProps, 0,
				    sizeof (MP_TARGET_PORT_PROPERTIES));
				mpstatus =
				    MP_GetTargetPortProperties(
				    pTportOidListArray->oids[j], &tportProps);
				if (mpstatus != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s:  %s\n",
					    cmdName,
					    getTextString(ERR_NO_PROPERTIES));
					return (mpstatus);
				}


				/* check the name */
				if (0 == strcmp(optionList->optarg,
				    tportProps.portID)) {
					bListIt = B_TRUE;
					bFoundOperand = B_TRUE;
					bFoundOption[opIndex] = B_TRUE;
				}
			} /* for each target port */
		} /* for each tpg */
	} /* end switch */
} /* loop through options */
/* end back-up indentation */

						} else {
							/*
							 * if no options,
							 * listit
							 */
							bListIt = B_TRUE;
							bFoundOperand = B_TRUE;
						}
					} /* end bContinue check */

		if (bListIt) {
			(void) printf("%s  %s\n",
			    getTextString(TEXT_LB_MPATH_SUPPORT),
			    pluginProps.fileName);
			luOid = pLogicalUnitOidList->oids[lu];
			if (listIndividualLogicalUnit(luOid, luProps)
			    != 0) {
				return (ERROR_CLI_FAILED);
			}

		}

				} /* end LU loop */
			} /* end plugin loop */
			if ((0 == opListCount) && (0 != operandLen)) {
				if (B_FALSE == bFoundOperand) {
					/* option/operand combo not found */
					/* LINTED E_SEC_PRINTF_VAR_FMT */
					(void) fprintf(stderr,
					    getTextString(
				    ERR_LU_NOT_FOUND_WITH_MISSING_LU_STR),
					    operand[opoffset]);
					(void) fprintf(stderr, "\n");
				}
			}

			optionList = options;
			for (opIndex = 0; optionList->optval; optionList++,
			    opIndex++) {
				if (B_FALSE == bFoundOption[opIndex]) {
					/* LINTED E_SEC_PRINTF_VAR_FMT */
					(void) fprintf(stderr,
					    getTextString(
				    ERR_LU_NOT_FOUND_WITH_MISSING_LU_STR),
					    optionList->optarg);
					(void) fprintf(stderr, "\n");
				}
			}



		} /* end loop through operands */
	} /* we have operands and/or options */


	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * compareLUName -
 * 	compare names directly and via devid if no match directly
 *
 * cmpString		- first string to compare
 * deviceProperty	- string from properties
 * sizeToCompare	- size of deviceProperty
 *
 * returns 	B_TRUE if the strings match either directly or via devid
 *		B_FALSE otherwise
 *
 * ****************************************************************************
 */
boolean_t
compareLUName(MP_CHAR *cmpString, MP_CHAR *deviceProperty)
{

	boolean_t				isSame = B_FALSE;
	int 					fd1, fd2;
	ddi_devid_t				devid1 = NULL, devid2 = NULL;

	if (0 == strcmp(cmpString, deviceProperty)) {
		isSame = B_TRUE;
	} else {
		/* user input didn't match, try via devid */
		/*
		 * I don't see a reason to print the error for
		 * any of these since they'll get the error at
		 * the end anyway
		 */

		fd1 = fd2 = -1;
		if (((fd1 = open(cmpString, O_RDONLY|O_NDELAY)) >= 0) &&
		    ((fd2 = open(deviceProperty, O_RDONLY|O_NDELAY)) >= 0) &&
		    (devid_get(fd1, &devid1) == 0) &&
		    (devid_get(fd2, &devid2) == 0) &&
		    ((NULL != devid1) && (NULL != devid2))) {
			if (0 ==
			    (devid_compare(devid1, devid2))) {
				isSame = B_TRUE;
			}
		}

		if (NULL != devid1) {
			devid_free(devid1);
		}
		if (NULL != devid2) {
			devid_free(devid2);
		}

		if (fd1 >= 0) {
			(void) close(fd1);
		}
		if (fd2 >= 0) {
			(void) close(fd2);
		}
	} /* compare */

	return (isSame);
}


/*
 * ****************************************************************************
 *
 * listIndivudualLogicalUnit -
 * 	Used by list logical unit cli.
 *	Displays info about an LU
 *
 * luOid	- LU to list
 * luProps	- properties of he LU to list
 *
 * ****************************************************************************
 */
int
listIndividualLogicalUnit(MP_OID luOid,
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES luProps)
{
	MP_PATH_LOGICAL_UNIT_PROPERTIES		pathProps;
	MP_OID_LIST				*pPathOidListArray;
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	int					numOperationalPaths, pa;

	(void) printf("\t");
	displayArray(luProps.deviceFileName, sizeof (luProps.deviceFileName));
	(void) printf("\n");

	mpstatus = MP_GetAssociatedPathOidList(luOid,
	    &pPathOidListArray);
	if (mpstatus != MP_STATUS_SUCCESS) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_NO_LU_PATH_INFO_WITH_MISSING_LU_STR),
		    getStringArray(luProps.deviceFileName,
		    sizeof (luProps.deviceFileName)));
		(void) fprintf(stderr, "\n");
		return (mpstatus);
	}
	(void) printf("\t\t%s %d\n",
	    getTextString(TEXT_LB_PATH_COUNT), pPathOidListArray->oidCount);

	numOperationalPaths = 0;
	for (pa = 0; pa < pPathOidListArray->oidCount; pa++) {
		(void) memset(&pathProps, 0,
		    sizeof (MP_PATH_LOGICAL_UNIT_PROPERTIES));
		mpstatus =
		    MP_GetPathLogicalUnitProperties(
		    pPathOidListArray->oids[pa], &pathProps);
		if (mpstatus != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_PROPERTIES));
			return (mpstatus);
		}

		/* cycle through and check status of each for */
		/* operation path count */
		if (MP_PATH_STATE_OKAY == pathProps.pathState) {
			numOperationalPaths++;
		}
	}

	(void) printf("\t\t%s %d\n",
	    getTextString(TEXT_LB_OP_PATH_COUNT), numOperationalPaths);

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * showLogicalUnit -
 * 	mpathadm show {logical-unit | LU} <logical-unit name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 *
 * ****************************************************************************
 */
int
showLogicalUnit(int operandLen, char *operand[])
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES	luProps;
	MP_PLUGIN_PROPERTIES			pluginProps;
	MP_OID					luOid, pluginOid;

	int					op;

	for (op = 0; op < operandLen; op++) {
		if (op > 0) {
			(void) printf("\n");
		}
		if (B_TRUE == getLogicalUnitOid(operand[op], &luOid)) {
			(void) memset(&luProps, 0,
			    sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));
			mpstatus =
			    MP_GetMPLogicalUnitProperties(
			    luOid, &luProps);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
				return (mpstatus);
			}

			mpstatus =
			    MP_GetAssociatedPluginOid(luOid, &pluginOid);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName,
				    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
				return (mpstatus);
			}

			mpstatus =
			    MP_GetPluginProperties(pluginOid, &pluginProps);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
				return (mpstatus);
			}

			if (showIndividualLogicalUnit(luOid, luProps,
			    pluginProps) != 0) {
				return (ERROR_CLI_FAILED);
			}

		} else {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr, getTextString(
			    ERR_LU_NOT_FOUND_WITH_MISSING_LU_STR),
			    operand[op]);
			(void) printf("\n");
		}

	} /* for each operand */

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * showIndivudualLogicalUnit -
 * 	Used by show logical unit cli.
 *	Displays info about an LU
 *
 * luOid	- LU to show
 * luProps	- properties of he LU to show
 * pluginProps	- propertis of the plugin this LU belongs to
 *
 * ****************************************************************************
 */
int
showIndividualLogicalUnit(MP_OID luOid,
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES luProps,
	MP_PLUGIN_PROPERTIES pluginProps)
{
	MP_PATH_LOGICAL_UNIT_PROPERTIES		pathProps;
	MP_TARGET_PORT_GROUP_PROPERTIES		tpgProps;
	MP_TARGET_PORT_PROPERTIES 		tportProps;
	MP_INITIATOR_PORT_PROPERTIES 		initProps;
	MP_OID_LIST	*pPathOidListArray, *pTPGOidListArray,
	    *pTportOidListArray;
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	boolean_t				showTportLabel = B_TRUE;

	int					pa, tpg, tport;

	(void) printf("%s  ", getTextString(TEXT_LB_LOGICAL_UNIT));
	displayArray(luProps.deviceFileName, sizeof (luProps.deviceFileName));
	(void) printf("\n");
	(void) printf("\t%s  %s\n", getTextString(TEXT_LB_MPATH_SUPPORT),
	    pluginProps.fileName);

	(void) printf("\t%s  ", getTextString(TEXT_LB_VENDOR));
	displayArray(luProps.vendor,
	    sizeof (luProps.vendor));
	(void) printf("\n\t%s  ", getTextString(TEXT_LB_PRODUCT));
	displayArray(luProps.product,
	    sizeof (luProps.product));
	(void) printf("\n\t%s  ", getTextString(TEXT_LB_REVISION));
	displayArray(luProps.revision,
	    sizeof (luProps.revision));
	(void) printf("\n\t%s  ", getTextString(TEXT_LB_INQUIRY_NAME_TYPE));
	displayLogicalUnitNameTypeString(luProps.nameType);
	(void) printf("\n\t%s  ", getTextString(TEXT_LB_INQUIRY_NAME));
	displayArray(luProps.name, sizeof (luProps.name));
	(void) printf("\n\t%s  %s\n", getTextString(TEXT_LB_ASYMMETRIC),
	    (MP_TRUE == luProps.asymmetric)?
	    getTextString(TEXT_YES):getTextString(TEXT_NO));

	(void) printf("\t%s  ", getTextString(TEXT_LB_CURR_LOAD_BALANCE));
	/* don't ignore load balance type none. */
	if (luProps.currentLoadBalanceType == 0) {
		(void) printf("%s", getTextString(TEXT_LBTYPE_NONE));
	} else {
		displayLoadBalanceString(luProps.currentLoadBalanceType);
	}
	(void) printf("\n");

	(void) printf("\t%s  ", getTextString(TEXT_LB_LU_GROUP_ID));
	if (0xffffffff == luProps.logicalUnitGroupID) {
		(void) printf("%s\n", getTextString(TEXT_NA));
	} else {
		(void) printf("0x%x\n", luProps.logicalUnitGroupID);
	}

	(void) printf("\t%s  ", getTextString(TEXT_LB_AUTO_FB));
	if (MP_FALSE == pluginProps.autoFailbackSupport) {
		(void) printf("%s\n", getTextString(TEXT_NA));
	} else {
		(void) printf("%s\n", (MP_TRUE == luProps.autoFailbackEnabled)?
		    getTextString(TEXT_ON):getTextString(TEXT_OFF));
	}

	(void) printf("\t%s  ", getTextString(TEXT_LB_AUTO_PROB));
	if (MP_FALSE == pluginProps.autoProbingSupport) {
		(void) printf("%s\n", getTextString(TEXT_NA));
	} else {
		(void) printf("%s\n", (MP_TRUE == luProps.autoProbingEnabled)?
		    getTextString(TEXT_ON):getTextString(TEXT_OFF));
	}


	/* get path info */
	mpstatus = MP_GetAssociatedPathOidList(luOid, &pPathOidListArray);
	if (mpstatus != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s:  %s", cmdName,
		    getTextString(ERR_NO_LU_PATH_INFO));
		displayArray(luProps.deviceFileName,
		    sizeof (luProps.deviceFileName));
		(void) fprintf(stderr, "\n");
		return (mpstatus);
	}

	(void) printf("\n\t%s  \n", getTextString(TEXT_LB_PATH_INFO));

	for (pa = 0; pa < pPathOidListArray->oidCount; pa++) {
		(void) memset(&pathProps, 0,
		    sizeof (MP_PATH_LOGICAL_UNIT_PROPERTIES));
		mpstatus = MP_GetPathLogicalUnitProperties(
		    pPathOidListArray->oids[pa], &pathProps);
		if (mpstatus != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_PROPERTIES));
			return (mpstatus);
		}

		(void) printf("\t\t%s  ",
		    getTextString(TEXT_LB_INIT_PORT_NAME));
		if ((mpstatus =
		    MP_GetInitiatorPortProperties(pathProps.initiatorPortOid,
		    &initProps)) != MP_STATUS_SUCCESS) {
			(void) printf("%s\n", getTextString(TEXT_UNKNOWN));
		} else {
			displayArray(initProps.portID,
			    sizeof (initProps.portID));
			(void) printf("\n");
		}

		(void) printf("\t\t%s  ",
		    getTextString(TEXT_LB_TARGET_PORT_NAME));
		if ((mpstatus =
		    MP_GetTargetPortProperties(pathProps.targetPortOid,
		    &tportProps)) != MP_STATUS_SUCCESS) {
			(void) printf("%s\n", getTextString(TEXT_UNKNOWN));
		} else {
			displayArray(tportProps.portID,
			    sizeof (tportProps.portID));
			(void) printf("\n");
		}

		(void) printf("\t\t%s  ", getTextString(TEXT_LB_OVERRIDE_PATH));
		if (MP_FALSE == pluginProps.canOverridePaths) {
			(void) printf("%s\n", getTextString(TEXT_NA));
		} else if (luProps.overridePath.objectSequenceNumber ==
		    pPathOidListArray->oids[pa].objectSequenceNumber) {
			(void) printf("%s\n", getTextString(TEXT_YES));
		} else {
			(void) printf("%s\n", getTextString(TEXT_NO));
		}

		(void) printf("\t\t%s  %s\n", getTextString(TEXT_LB_PATH_STATE),
		    getPathStateStr(pathProps.pathState));

		(void) printf("\t\t%s  %s\n\n", getTextString(TEXT_LB_DISABLED),
		    pathProps.disabled?getTextString(TEXT_YES):
		    getTextString(TEXT_NO));

	}

	/* get tpg info */
	mpstatus = MP_GetAssociatedTPGOidList(luOid, &pTPGOidListArray);
	if (mpstatus != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s:  %s", cmdName,
		    getTextString(ERR_NO_ASSOC_TPGS));
	} else {

	/* display tpg info only if is assymetric */
	if (MP_TRUE == luProps.asymmetric) {
		(void) printf("\t%s  \n", getTextString(TEXT_LB_TPG_INFO));
	}

		for (tpg = 0; tpg < pTPGOidListArray->oidCount; tpg++) {
			(void) memset(&tpgProps, 0,
			    sizeof (MP_TARGET_PORT_GROUP_PROPERTIES));
			mpstatus = MP_GetTargetPortGroupProperties(
			    pTPGOidListArray->oids[tpg], &tpgProps);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
			} else {
				/* display tpg info only if is assymetric */
				if (tpg > 0) {
					(void) printf("\n");
				}
				if (MP_TRUE == luProps.asymmetric) {
					(void) printf("\t\t%s  %d\n",
					    getTextString(TEXT_LB_ID),
					    tpgProps.tpgID);
					(void) printf("\t\t%s  %s\n",
					    getTextString(
					    TEXT_LB_EXPLICIT_FAILOVER),
					    (MP_TRUE ==
					    tpgProps.explicitFailover)?
					    getTextString(TEXT_YES):
					    getTextString(TEXT_NO));
					(void) printf("\t\t%s  %s\n",
					    getTextString(
					    TEXT_LB_ACCESS_STATE),
					    getAccessStateStr(
					    tpgProps.accessState));
					    /* display label for each tpg. */
					(void) printf("\t\t%s\n",
					    getTextString(TEXT_TPORT_LIST));
				} else {
					/* display label once for symmetric. */
					if (B_TRUE == showTportLabel) {
					/* begin back-up indentation */
					(void) printf("\t%s\n",
					    getTextString(TEXT_TPORT_LIST));
					showTportLabel = B_FALSE;
					/* end back-up indentation */
					}
				}

				/* get target port info */
				mpstatus = MP_GetTargetPortOidList(
				    pTPGOidListArray->oids[tpg],
				    &pTportOidListArray);
				if (mpstatus != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s:  %s",
					    cmdName,
					    getTextString(ERR_NO_ASSOC_TPORTS));
				} else {

/* begin back-up indentation */
	for (tport = 0; tport < pTportOidListArray->oidCount; tport++) {
		(void) memset(&tportProps, 0,
		    sizeof (MP_TARGET_PORT_PROPERTIES));
		if ((mpstatus =
		    MP_GetTargetPortProperties(pTportOidListArray->oids[tport],
		    &tportProps)) != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s",
			    cmdName, getTextString(ERR_NO_PROPERTIES));
		} else {
			if (MP_TRUE == luProps.asymmetric) {
				(void) printf("\t\t\t%s  ",
				    getTextString(TEXT_LB_NAME));
				displayArray(tportProps.portID,
				    sizeof (tportProps.portID));
				(void) printf("\n\t\t\t%s  %d\n",
				    getTextString(TEXT_LB_RELATIVE_ID),
				    tportProps.relativePortID);
			} else {
				(void) printf("\t\t%s  ",
				    getTextString(TEXT_LB_NAME));
				displayArray(tportProps.portID,
				    sizeof (tportProps.portID));
				(void) printf("\n\t\t%s  %d\n",
				    getTextString(TEXT_LB_RELATIVE_ID),
				    tportProps.relativePortID);
			}
			/* insert blank line if not the last target port. */
			if (!(tport == (pTportOidListArray->oidCount - 1))) {
				(void) printf("\n");
			}
		}
	} /* for each target port */
/* end back-up indentation */

				} /* else got target port props */
			} /* else got TPG props */
		} /* for each TPG */
	} /* else got tpg list */


	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * modifyLogicalUnit -
 * 	mpathadm modify {logical-unit | LU} [options] <logical-unit name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
int
modifyLogicalUnit(int operandLen, char *operand[], cmdOptions_t *options)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_OID					luOid;
	cmdOptions_t 				*optionList = options;
	char	*cmdStr = getTextString(TEXT_UNKNOWN);
	int					op;

	for (op = 0; op < operandLen; op++) {
		if (B_TRUE != getLogicalUnitOid(operand[op], &luOid)) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(ERR_LU_NOT_FOUND_WITH_MISSING_LU_STR),
			    operand[op]);
			(void) printf("\n");
			return (ERROR_CLI_FAILED);
		}

		/* we found the lu oid, now change the options requested */
		switch (optionList->optval) {
			case 'a':
				/* modify autofailback */
				cmdStr = getTextString(TEXT_AUTO_FAILBACK);
				if (0 == strcasecmp(optionList->optarg,
				    getTextString(TEXT_ON))) {
					mpstatus =
					    MP_EnableAutoFailback(luOid);
				} else if (0 == strcasecmp(optionList->optarg,
				    getTextString(TEXT_OFF))) {
					mpstatus =
					    MP_DisableAutoFailback(luOid);
				} else {
				/* begin back-up indentation */
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, getTextString(
				    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
				    cmdStr, getTextString(
				    TEXT_ILLEGAL_ARGUMENT));
				(void) printf("\n");
				return (ERROR_CLI_FAILED);
				/* start back-up indentation */
				}
				break;
			case 'p':
				/* modify autoprobing */
				cmdStr = getTextString(TEXT_AUTO_PROBING);
				if (0 == strcasecmp(optionList->optarg,
				    getTextString(TEXT_ON))) {
					mpstatus =
					    MP_EnableAutoProbing(luOid);
				} else if (0 == strcasecmp(optionList->optarg,
				    getTextString(TEXT_OFF))) {
					mpstatus =
					    MP_DisableAutoProbing(luOid);
				} else {
				/* begin back-up indentation */
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr, getTextString(
				    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
				    cmdStr, getTextString(
				    TEXT_ILLEGAL_ARGUMENT));
				(void) printf("\n");
				return (ERROR_CLI_FAILED);
				/* end back-up indentation */
				}
				break;
			case 'b':
				/* modify loadbalance type */
				cmdStr = getTextString(TEXT_LOAD_BALANCE);
				mpstatus =
				    MP_SetLogicalUnitLoadBalanceType(luOid,
				    getLbValueFromString(optionList->optarg));
				break;

		} /* switch */
		if (MP_STATUS_SUCCESS != mpstatus) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON),
			    cmdStr, getMpStatusStr(mpstatus));
			(void) printf("\n");
			return (ERROR_CLI_FAILED);
		}
	} /* for each operand */
	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * failoverLogicalUnit -
 * 	mpathadm failover {logical-unit | LU} <logical-unit name>, ...
 *
 * operand	- pointer to operand list from user
 *
 * ****************************************************************************
 */
int
failoverLogicalUnit(char *operand[])
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_OID					luOid;
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES	luProps;
	MP_TARGET_PORT_GROUP_PROPERTIES		tpgProps;
	MP_OID_LIST				*pTpgOidListArray;
	boolean_t				bFoundIt = B_FALSE;
	MP_TPG_STATE_PAIR			tpgStatePair;

	int					tpg;

	if (B_TRUE != getLogicalUnitOid(operand[0], &luOid)) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr, getTextString(
		    ERR_LU_NOT_FOUND_WITH_MISSING_LU_STR),
		    operand[0]);
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	}

	/* get LUN properties and check to be sure it's asymmetric */
	(void) memset(&luProps, 0,
	    sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));
	mpstatus =
	    MP_GetMPLogicalUnitProperties(luOid, &luProps);
	if (mpstatus != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s:  %s\n",
		    cmdName, getTextString(ERR_NO_PROPERTIES));
		return (mpstatus);
	}

	if (MP_TRUE != luProps.asymmetric) {
		(void) fprintf(stderr, "%s:  %s\n",
		    cmdName, getTextString(ERR_LU_NOT_ASYMMETRIC));
		return (ERROR_CLI_FAILED);
	}

	/* get TPGs for this LUN */
	mpstatus =
	    MP_GetAssociatedTPGOidList(luOid, &pTpgOidListArray);
	if (mpstatus != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s:  %s\n",
		    cmdName, getTextString(ERR_NO_ASSOC_TPGS));
		return (mpstatus);
	}

	/* pick a TPG whose state is active or standby, and change it */
	/* to opposite via MP_SetTPGAccessState */
	bFoundIt = B_FALSE;
	for (tpg = 0; tpg < pTpgOidListArray->oidCount; tpg++) {
		(void) memset(&tpgProps, 0,
		    sizeof (MP_TARGET_PORT_GROUP_PROPERTIES));
		mpstatus =
		    MP_GetTargetPortGroupProperties(
		    pTpgOidListArray->oids[tpg], &tpgProps);
		if (mpstatus != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_PROPERTIES));
			return (ERROR_CLI_FAILED);
		}
		if (MP_FALSE == tpgProps.explicitFailover) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_FAILOVER_ALLOWED));
			return (ERROR_CLI_FAILED);
		}

		/* find one that is standby */
		if ((MP_ACCESS_STATE_STANDBY ==
		    tpgProps.accessState) && (B_FALSE == bFoundIt)) {

			bFoundIt = B_TRUE;

			tpgStatePair.tpgOid =
			    pTpgOidListArray->oids[tpg];
			tpgStatePair.desiredState =
			    MP_ACCESS_STATE_ACTIVE;
			mpstatus =
			    MP_SetTPGAccess(luOid, 1, &tpgStatePair);
			if (MP_STATUS_SUCCESS != mpstatus) {
			/* begin back-up indentation */
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr, getTextString(
			    ERR_FAILED_TO_FAILOVER_WITH_REASON),
			    getMpStatusStr(mpstatus));
			(void) printf("\n");
			return (mpstatus);
			/* end back-up indentation */
			}
		}


	} /* for each tpg */

	if (B_FALSE == bFoundIt) {
		(void) fprintf(stderr, "%s:  %s\n",
		    cmdName, getTextString(ERR_LU_ACCESS_STATE_UNCHANGED));
		return (ERROR_CLI_FAILED);
	}

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * getLogicalUnitOid -
 *	Search through all plugins and get the OID for specified logical unit
 *
 * luFileName	- file name of LU (specified by the user) to find
 * pLuOid	- OID to return
 *
 * ****************************************************************************
 */
boolean_t
getLogicalUnitOid(MP_CHAR *luFileName, MP_OID *pluOid)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES	luProps;
	MP_PLUGIN_PROPERTIES			pluginProps;
	MP_OID_LIST	*pPluginOidList, *pLogicalUnitOidList;
	boolean_t				foundIt = B_FALSE;

	int					i, lu;

	int 					fd1, fd2;
	ddi_devid_t				devid1, devid2;

	if (NULL == pluOid) {
		/* print some kind of error msg here - should never happen */
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr, getTextString(ERR_MEMORY_ALLOCATION));
		(void) printf("\n");
		return (B_FALSE);
	}

	pluOid->objectSequenceNumber = 0;
	pluOid->objectType = 0;
	pluOid->ownerId = 0;

	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
	    != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (B_FALSE);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (ERROR_CLI_FAILED);
	}
	for (i = 0; i < pPluginOidList->oidCount; i++) {

		/* get properties so we can list the name */
		(void) memset(&pluginProps, 0, sizeof (MP_PLUGIN_PROPERTIES));
		if ((mpstatus =
		    MP_GetPluginProperties(pPluginOidList->oids[i],
		    &pluginProps)) != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_PROPERTIES));
			return (B_FALSE);
		}

		/* attempt to find this logical unit */
		mpstatus = MP_GetMultipathLus(pPluginOidList->oids[i],
		    &pLogicalUnitOidList);
		if (mpstatus != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_LU_LIST));
			return (B_FALSE);
		}

		for (lu = 0; (lu < pLogicalUnitOidList->oidCount) &&
		    (B_FALSE == foundIt); lu++) {

			/* get lu properties so we can check the name */
			(void) memset(&luProps, 0,
			    sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));
			mpstatus =
			    MP_GetMPLogicalUnitProperties(
			    pLogicalUnitOidList->oids[lu], &luProps);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
				return (B_FALSE);
			}

			if (compareLUName(luFileName, luProps.deviceFileName)
			    == B_TRUE) {
				foundIt = B_TRUE;
			} else {
				/* user input didn't match, try via devid */
				/*
				 * I don't see a reason to print the error for
				 * any of these since they'll get the error at
				 * the end anyway
				 */

				fd1 = fd2 = -1;
				devid1 = devid2 = NULL;
				if (((fd1 = open(luFileName,
				    O_RDONLY|O_NDELAY)) >= 0) &&
				    ((fd2 = open(luProps.deviceFileName,
				    O_RDONLY|O_NDELAY)) >= 0) &&
				    (devid_get(fd1, &devid1) == 0) &&
				    (devid_get(fd2, &devid2) == 0) &&
				    ((NULL != devid1) && (NULL != devid2))) {
					if (0 ==
					    (devid_compare(devid1, devid2))) {
						foundIt = B_TRUE;
					}
				}

				if (NULL != devid1) {
					devid_free(devid1);
				}
				if (NULL != devid2) {
					devid_free(devid2);
				}

				if (fd1 >= 0) {
					(void) close(fd1);
				}
				if (fd2 >= 0) {
					(void) close(fd2);
				}
			}
			if (B_TRUE == foundIt) {
				pluOid->objectSequenceNumber =
				    pLogicalUnitOidList->
				    oids[lu].objectSequenceNumber;
				pluOid->objectType =
				    pLogicalUnitOidList->
				    oids[lu].objectType;
				pluOid->ownerId =
				    pLogicalUnitOidList->oids[lu].ownerId;
			}
		}
	}

	return (foundIt);
}


/*
 * ****************************************************************************
 *
 * listInitiatorPort -
 * 	mpathadm list initiator-port [<initiator-port name>, ...]
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 *
 * ****************************************************************************
 */
int
listInitiatorPort(int operandLen, char *operand[])
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_INITIATOR_PORT_PROPERTIES 		initProps;
	MP_OID_LIST	*pPluginOidList, *pInitOidList;
	boolean_t				bListIt = B_FALSE;
	boolean_t				*foundOp;

	int		ol, i, iport;

	foundOp = malloc((sizeof (boolean_t)) * operandLen);
	if (NULL == foundOp) {
		(void) fprintf(stdout, "%s\n",
		    getTextString(ERR_MEMORY_ALLOCATION));
		return (ERROR_CLI_FAILED);
	}

	for (ol = 0; ol < operandLen; ol++) {
		foundOp[ol] = B_FALSE;
	}

	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
	    != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (mpstatus);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (ERROR_CLI_FAILED);
	}

	for (i = 0; i < pPluginOidList->oidCount; i++) {
		mpstatus =
		    MP_GetInitiatorPortOidList(pPluginOidList->oids[i],
		    &pInitOidList);
		if (mpstatus != MP_STATUS_SUCCESS) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(ERR_NO_INIT_PORT_LIST_WITH_REASON),
			    getMpStatusStr(mpstatus));
			(void) printf("\n");
		} else if ((NULL == pInitOidList) ||
		    (pInitOidList->oidCount < 1)) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    getTextString(ERR_NO_INIT_PORTS));
		} else {
			for (iport = 0;
			    iport < pInitOidList->oidCount; iport ++) {
				bListIt = B_FALSE;
				if ((mpstatus =
				    MP_GetInitiatorPortProperties(
				    pInitOidList->oids[iport],
				    &initProps)) != MP_STATUS_SUCCESS) {
					(void) fprintf(stderr,
					    "%s: %s\n", cmdName,
					    getTextString(ERR_NO_PROPERTIES));
				} else {
					/* if no operands listed, */
					/* list all we find */
					if (0 == operandLen) {
						bListIt = B_TRUE;
					} else {

						/* check each operand */
						/* Is it */
						/* the one we want to list? */
						for (ol = 0;
						    ol < operandLen; ol++) {
							if (0 ==
							    strcmp(operand[ol],
							    initProps.
							    portID)) {
								bListIt =
								    B_TRUE;
								foundOp[ol] =
								    B_TRUE;
							}
						}
					}
				}

				if (B_TRUE == bListIt) {

					if (listIndividualInitiatorPort(
					    initProps) != 0) {
						return (ERROR_CLI_FAILED);
					}

				} /* list It */

			} /* for each initiator port */
		} /* else found an init port */

	} /* for each plugin */

	for (ol = 0; ol < operandLen; ol++) {
		if (B_FALSE == foundOp[ol]) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr, getTextString(
			    ERR_INIT_PORT_NOT_FOUND_WITH_MISSING_LU_STR),
			    operand[ol]);
			(void) printf("\n");
		}
	}

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * listIndividualInitiatorPort -
 * 	used by listInitiatorPort to list info for one init port
 *
 * initProps	- properties of initiator port to list
 *
 * ****************************************************************************
 */
int
listIndividualInitiatorPort(MP_INITIATOR_PORT_PROPERTIES initProps)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;

	(void) printf("%s  ", getTextString(TEXT_LB_INITATOR_PORT));
	displayArray(initProps.portID,
	    sizeof (initProps.portID));
	(void) printf("\n");

	return (mpstatus);

}


/*
 * ****************************************************************************
 *
 * showInitiatorPort -
 * 	mpathadm show initiator-port <initiator-port name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 *
 * ****************************************************************************
 */
int
showInitiatorPort(int operandLen, char *operand[])
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_INITIATOR_PORT_PROPERTIES 		initProps;
	MP_OID_LIST	*pPluginOidList, *pInitOidList;
	boolean_t	bListIt = B_FALSE, bFoundIt = B_FALSE;
	int		op, i, iport;

	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
	    != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (mpstatus);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (ERROR_CLI_FAILED);
	}

	for (op = 0; op < operandLen; op++) {
	bFoundIt = B_FALSE;

		for (i = 0; i < pPluginOidList->oidCount; i++) {

			mpstatus =
			    MP_GetInitiatorPortOidList(pPluginOidList->oids[i],
			    &pInitOidList);
			if (mpstatus != MP_STATUS_SUCCESS) {
				/* LINTED E_SEC_PRINTF_VAR_FMT */
				(void) fprintf(stderr,
				    getTextString(
				    ERR_NO_INIT_PORT_LIST_WITH_REASON),
				    getMpStatusStr(mpstatus));
				(void) printf("\n");
			} else if ((NULL == pInitOidList) ||
			    (pInitOidList->oidCount < 1)) {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    getTextString(ERR_NO_INIT_PORTS));
			} else {

				for (iport = 0;
				    iport < pInitOidList->oidCount;
				    iport ++) {
					bListIt = B_FALSE;

					if ((mpstatus =
					    MP_GetInitiatorPortProperties(
					    pInitOidList->oids[iport],
					    &initProps))
					    != MP_STATUS_SUCCESS) {
					/* begin back-up indentation */
					(void) fprintf(stderr,
					    "%s: %s\n", cmdName,
					    getTextString(ERR_NO_PROPERTIES));
					/* end back-up indentation */
					} else {
						if (0 == strcmp(operand[op],
						    initProps.portID)) {
							bListIt = B_TRUE;
							bFoundIt = B_TRUE;
						}
					}

					if (B_TRUE == bListIt) {
						mpstatus =
						    showIndividualInitiatorPort(
						    initProps);
						if (0 != mpstatus) {
							return (mpstatus);
						}

					} /* list It */

				} /* for each initiator port */
			} /* else found an init port */

		} /* for each plugin */

		if (B_FALSE == bFoundIt) {
			/* need temp string here since we need to fill in a */
			/* name in the error string */
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr, getTextString(
			    ERR_INIT_PORT_NOT_FOUND_WITH_MISSING_LU_STR),
			    operand[op]);
			(void) printf("\n");
		}

	} /* for each operand */

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * showIndividualInitiatorPort -
 * 	used by showInitiatorPort to show info for one init port
 *
 * initProps	- properties of initiator port to show
 *
 * ****************************************************************************
 */
int
showIndividualInitiatorPort(MP_INITIATOR_PORT_PROPERTIES initProps)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;

	(void) printf("%s  ", getTextString(TEXT_LB_INITATOR_PORT));
	displayArray(initProps.portID,
	    sizeof (initProps.portID));

	(void) printf("\n\t%s  ", getTextString(TEXT_LB_TRANSPORT_TYPE));
	displayTransportTypeString(initProps.portType);
	(void) printf("\n");

	(void) printf("\t%s  ", getTextString(TEXT_LB_OS_DEVICE_FILE));
	displayArray(initProps.osDeviceFile,
	    sizeof (initProps.osDeviceFile));
	(void) printf("\n");

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * enablePath -
 * 	mpathadm enable path -i <initiator-port>
 *		-t <target-port name> -l <logical-unit name>
 *
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
int
enablePath(cmdOptions_t *options)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_OID					pathOid;

	cmdOptions_t 				*optionList = options;
	boolean_t   bHaveInit = B_FALSE, bHaveTarg = B_FALSE, bHaveLu = B_FALSE;

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'i':
				/* have init port name */
				bHaveInit = B_TRUE;
				break;
			case 't':
				/* have target port id */
				bHaveTarg = B_TRUE;
				break;
			case 'l':
				/* have LU name */
				bHaveLu = B_TRUE;
				break;
		}
	}
	if (B_FALSE == bHaveInit) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_ENABLE_PATH_WITH_REASON),
		    getTextString(MISSING_INIT_PORT_NAME));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	} else if (B_FALSE == bHaveTarg) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_ENABLE_PATH_WITH_REASON),
		    getTextString(MISSING_TARGET_PORT_NAME));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	} else if (B_FALSE == bHaveLu) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_ENABLE_PATH_WITH_REASON),
		    getTextString(MISSING_LU_NAME));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	}

	if (B_FALSE == getPathOid(options, &pathOid)) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_ENABLE_PATH_WITH_REASON),
		    getTextString(FAILED_TO_FIND_PATH));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	}

	/* found the path, attempt to enable it */
	mpstatus =  MP_EnablePath(pathOid);
	if (mpstatus != MP_STATUS_SUCCESS) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_ENABLE_PATH_WITH_REASON),
		    getMpStatusStr(mpstatus));
		(void) printf("\n");
		return (mpstatus);
	}

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * disablePath -
 * 	mpathadm disable path -i <initiator-port>
 *		-t <target-port name> -l <logical-unit name>
 *
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
int
disablePath(cmdOptions_t *options)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_OID					pathOid;

	cmdOptions_t 				*optionList = options;
	boolean_t	bHaveInit = B_FALSE, bHaveTarg = B_FALSE,
	    bHaveLu = B_FALSE;

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'i':
				/* have init port name */
				bHaveInit = B_TRUE;
				break;
			case 't':
				/* have target port id */
				bHaveTarg = B_TRUE;
				break;
			case 'l':
				/* have LU name */
				bHaveLu = B_TRUE;
				break;
		}
	}
	if (B_FALSE == bHaveInit) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_DISABLE_PATH_WITH_REASON),
		    getTextString(MISSING_INIT_PORT_NAME));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	} else if (B_FALSE == bHaveTarg) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_DISABLE_PATH_WITH_REASON),
		    getTextString(MISSING_TARGET_PORT_NAME));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	} else if (B_FALSE == bHaveLu) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_DISABLE_PATH_WITH_REASON),
		    getTextString(MISSING_LU_NAME));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	}

	if (B_FALSE == getPathOid(options, &pathOid)) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr,
		    getTextString(ERR_FAILED_TO_DISABLE_PATH_WITH_REASON),
		    getTextString(FAILED_TO_FIND_PATH));
		(void) printf("\n");
		return (ERROR_CLI_FAILED);
	}

	/* found the path, attempt to enable it */
	mpstatus =  MP_DisablePath(pathOid);
	if (MP_STATUS_SUCCESS != mpstatus) {
		/* LINTED E_SEC_PRINTF_VAR_FMT */
		(void) fprintf(stderr, getTextString(
		    ERR_FAILED_TO_DISABLE_PATH_WITH_REASON),
		    getMpStatusStr(mpstatus));
		(void) printf("\n");
		return (mpstatus);
	}


	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * overridePath -
 * 	mpathadm override path {-i <initiator-port>
 *		-t <target-port name> | -c} <logical-unit name>
 *
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
int
overridePath(cmdOptions_t *options)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_OID					pathOid, luOid;
	boolean_t				bCancelOverride = B_FALSE;
	MP_CHAR					pLuDeviceFileName[256];
	cmdOptions_t 				*optionList = options;

	/* First check to see if we have the cancel option, */
	/* May as well save off the lun while we're at it */
	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'c':
				/* we have a cancel */
				bCancelOverride = B_TRUE;
				break;
			case 'l':
				/* we have a lun- save it while we're here */
				(void) memcpy(pLuDeviceFileName,
				    optionList->optarg, 256);
				break;
		}
	}

	if (B_TRUE == bCancelOverride) {
		/* if we have the cancel option, */
		if (getLogicalUnitOid(pLuDeviceFileName, &luOid) == B_FALSE) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_CANCEL_OVERRIDE_PATH_WITH_REASON),
			    getTextString(LU_NOT_FOUND));
			(void) printf("\n");
			return (ERROR_CLI_FAILED);
		}

		/* cancel the override path for the specified LU */
		mpstatus = MP_CancelOverridePath(luOid);
		if (MP_STATUS_SUCCESS != mpstatus) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_CANCEL_OVERRIDE_PATH_WITH_REASON),
			    getMpStatusStr(mpstatus));
			(void) printf("\n");
			return (mpstatus);
		}
	} else {
		/* must be wanting to override the path */
		if (getLogicalUnitOid(pLuDeviceFileName, &luOid) == B_FALSE) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_OVERRIDE_PATH_WITH_REASON),
			    getTextString(LU_NOT_FOUND));
			(void) printf("\n");
			return (ERROR_CLI_FAILED);
		}

		if (B_FALSE == getPathOid(options, &pathOid)) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_OVERRIDE_PATH_WITH_REASON),
			    getTextString(FAILED_TO_FIND_PATH));

			(void) printf("\n");
			return (ERROR_CLI_FAILED);
		}

		/* attempt to set the override path */
		mpstatus =  MP_SetOverridePath(luOid, pathOid);
		if (mpstatus != MP_STATUS_SUCCESS) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) fprintf(stderr,
			    getTextString(
			    ERR_FAILED_TO_OVERRIDE_PATH_WITH_REASON),
			    getMpStatusStr(mpstatus));
			(void) printf("\n");
			return (mpstatus);
		}
	}

	return (mpstatus);
}


/*
 * ****************************************************************************
 *
 * getPathOid -
 *	Search through all plugins and get the OID for specified path
 *
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
boolean_t
getPathOid(cmdOptions_t *options, MP_OID *pPathOid)
{
	MP_STATUS				mpstatus = MP_STATUS_SUCCESS;
	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES 	luProps;
	MP_PATH_LOGICAL_UNIT_PROPERTIES		pathProps;
	MP_INITIATOR_PORT_PROPERTIES		initProps;
	MP_TARGET_PORT_PROPERTIES		targProps;

	MP_OID_LIST	*pPluginOidList, *pLogicalUnitOidList,
	    *pathOidListArray;

	boolean_t				bFoundIt = B_FALSE;
	MP_CHAR					initPortID[256];
	MP_CHAR					targetPortID[256];
	MP_CHAR					luDeviceFileName[256];
	boolean_t	bHaveTarg = B_FALSE, bHaveLu = B_FALSE,
	    bHaveInit = B_FALSE;
	cmdOptions_t 				*optionList = options;

	int					i, lu, pa;
	if (NULL == pPathOid) {
		return (B_FALSE);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'i':
				/* save init port name */
				(void) memcpy(initPortID,
				    optionList->optarg, 256);
				bHaveInit = B_TRUE;
				break;
			case 't':
				/* save target port id */
				(void) memcpy(targetPortID,
				    optionList->optarg, 256);
				bHaveTarg = B_TRUE;
				break;
			case 'l':
				/* save LU name */
				(void) memcpy(luDeviceFileName,
				    optionList->optarg, 256);
				bHaveLu = B_TRUE;
				break;
		}
	}


	if ((B_FALSE == bHaveInit) ||
	    (B_FALSE == bHaveTarg) ||
	    (B_FALSE == bHaveLu)) {
		/* if we don't have all three pieces, we can't find the path */

		return (B_FALSE);
	}

	/* get the plugin ist */
	if ((mpstatus = MP_GetPluginOidList(&pPluginOidList))
	    != MP_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (B_FALSE);
	}
	if ((NULL == pPluginOidList) || (pPluginOidList->oidCount < 1)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    getTextString(ERR_NO_MPATH_SUPPORT_LIST));
		return (B_FALSE);
	}

	for (i = 0; i < pPluginOidList->oidCount; i++) {

		/* get Logical Unit list */
		mpstatus = MP_GetMultipathLus(pPluginOidList->oids[i],
		    &pLogicalUnitOidList);
		if (mpstatus != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n",
			    cmdName, getTextString(ERR_NO_LU_LIST));
			return (B_FALSE);
		}

		for (lu = 0; (lu < pLogicalUnitOidList->oidCount) &&
		    (B_FALSE == bFoundIt); lu++) {

			/* get lu properties so we can check the name */
			(void) memset(&luProps, 0,
			    sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));
			mpstatus =
			    MP_GetMPLogicalUnitProperties(
			    pLogicalUnitOidList->oids[lu], &luProps);
			if (mpstatus != MP_STATUS_SUCCESS) {
				(void) fprintf(stderr, "%s:  %s\n",
				    cmdName, getTextString(ERR_NO_PROPERTIES));
				return (B_FALSE);
			}
			if (compareLUName(luDeviceFileName,
			    luProps.deviceFileName) == B_TRUE) {
				/* get paths for this LU and search from here */
				mpstatus =
				    MP_GetAssociatedPathOidList(
				    pLogicalUnitOidList->oids[lu],
				    &pathOidListArray);
				if (mpstatus != MP_STATUS_SUCCESS) {
					/* LINTED E_SEC_PRINTF_VAR_FMT */
					(void) fprintf(stderr,
					    getTextString(
					    ERR_FAILED_TO_FIND_PATH));
					(void) printf("\n");
					return (B_FALSE);
				}

				for (pa = 0;
				    (pa < pathOidListArray->oidCount) &&
				    (B_FALSE == bFoundIt); pa++) {
					mpstatus =
					    MP_GetPathLogicalUnitProperties
					    (pathOidListArray->oids[pa],
					    &pathProps);
					if (mpstatus != MP_STATUS_SUCCESS) {
						(void) fprintf(stderr,
						    "%s:  %s\n", cmdName,
						    getTextString(
						    ERR_NO_PROPERTIES));
						return (B_FALSE);
					}

					/*
					 * get properties of iniator port and
					 * target port to see if we have the
					 * right path
					 */
					mpstatus =
					    MP_GetInitiatorPortProperties(
					    pathProps.initiatorPortOid,
					    &initProps);

					if (mpstatus != MP_STATUS_SUCCESS) {
						(void) fprintf(stderr,
						    "%s:  %s\n", cmdName,
						    getTextString(
						    ERR_NO_PROPERTIES));
						return (B_FALSE);
					}
	if (0 == strcmp(initPortID, initProps.portID)) {
		/* lu and init port matches, check target port */
		mpstatus = MP_GetTargetPortProperties(pathProps.targetPortOid,
		    &targProps);
		if (mpstatus != MP_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s:  %s\n", cmdName,
			    getTextString(ERR_NO_PROPERTIES));
			return (B_FALSE);
		}

		if (0 == strcmp(targetPortID, targProps.portID)) {
			/* we found our path */
			pPathOid->objectSequenceNumber =
			    pathOidListArray->oids[pa].objectSequenceNumber;
			pPathOid->objectType =
			    pathOidListArray->oids[pa].objectType;
			pPathOid->ownerId = pathOidListArray->oids[pa].ownerId;
			bFoundIt = B_TRUE;
		}
	} /* init port matched */

				} /* for each path associated with this lu */

			} /* lu matched */

		} /* for each lu */

	} /* for each plugin */

	return (bFoundIt);
}


/*
 * ****************************************************************************
 *
 * getLbValueFromString
 * 	Gets the MP_LOAD_BALANCE_TYPE specified load balance type string
 *
 * lbStr	- load balance string defined in the .h file
 *		This is what users will be required to feed into the
 *		modify lu command.
 *
 * ****************************************************************************
 */
MP_LOAD_BALANCE_TYPE
getLbValueFromString(char *lbStr)
{
	MP_LOAD_BALANCE_TYPE		lbVal = MP_LOAD_BALANCE_TYPE_UNKNOWN;

	if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_ROUNDROBIN))) {
		lbVal = MP_LOAD_BALANCE_TYPE_ROUNDROBIN;
	} else if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_LEASTBLOCKS))) {
		lbVal = MP_LOAD_BALANCE_TYPE_LEASTBLOCKS;
	} else if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_LEASTIO))) {
		lbVal = MP_LOAD_BALANCE_TYPE_LEASTIO;
	} else if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_DEVICEPROD))) {
		lbVal = MP_LOAD_BALANCE_TYPE_DEVICE_PRODUCT;
	} else if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_LBAREGION))) {
		lbVal = MP_LOAD_BALANCE_TYPE_LBA_REGION;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_FAILOVER_ONLY))) {
		lbVal = MP_LOAD_BALANCE_TYPE_FAILOVER_ONLY;
	} else if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_UNKNOWN))) {
		lbVal = MP_LOAD_BALANCE_TYPE_UNKNOWN;
	} else if (0 == strcmp(lbStr, getTextString(TEXT_LBTYPE_NONE))) {
		lbVal = 0;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY1))) {
		lbVal = ((MP_UINT32)0x00000001)<<16;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY2))) {
		lbVal = ((MP_UINT32)0x00000001)<<17;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY3))) {
		lbVal = ((MP_UINT32)0x00000001)<<18;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY4))) {
		lbVal = ((MP_UINT32)0x00000001)<<19;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY5))) {
		lbVal = ((MP_UINT32)0x00000001)<<20;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY6))) {
		lbVal = ((MP_UINT32)0x00000001)<<21;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY7))) {
		lbVal = ((MP_UINT32)0x00000001)<<22;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY8))) {
		lbVal = ((MP_UINT32)0x00000001)<<23;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY9))) {
		lbVal = ((MP_UINT32)0x00000001)<<24;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY10))) {
		lbVal = ((MP_UINT32)0x00000001)<<25;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY11))) {
		lbVal = ((MP_UINT32)0x00000001)<<26;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY12))) {
		lbVal = ((MP_UINT32)0x00000001)<<27;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY13))) {
		lbVal = ((MP_UINT32)0x00000001)<<28;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY14))) {
		lbVal = ((MP_UINT32)0x00000001)<<29;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY15))) {
		lbVal = ((MP_UINT32)0x00000001)<<30;
	} else if (0 == strcmp(lbStr,
	    getTextString(TEXT_LBTYPE_PROPRIETARY16))) {
		lbVal = ((MP_UINT32)0x00000001)<<31;
	}

	return (lbVal);


} /* end getLbValueFromString */


/*
 * ****************************************************************************
 *
 * displayLogicalUnitNameTypeString
 * 	Displays the text equivalent string for the MP_LOGICAL_UNIT_NAME_TYPE
 *	specified load balance type
 *
 * typeVal	- load balance type defined in the MPAPI spec
 *
 * ****************************************************************************
 */
void
displayLogicalUnitNameTypeString(MP_LOGICAL_UNIT_NAME_TYPE typeVal)
{

	char					*typeString;

	switch (typeVal) {

		case MP_LU_NAME_TYPE_UNKNOWN:
			typeString = getTextString(TEXT_NAME_TYPE_UNKNOWN);
			break;
		case MP_LU_NAME_TYPE_VPD83_TYPE1:
			typeString = getTextString(TEXT_NAME_TYPE_VPD83_TYPE1);
			break;
		case MP_LU_NAME_TYPE_VPD83_TYPE2:
			typeString = getTextString(TEXT_NAME_TYPE_VPD83_TYPE2);
			break;
		case MP_LU_NAME_TYPE_VPD83_TYPE3:
			typeString = getTextString(TEXT_NAME_TYPE_VPD83_TYPE3);
			break;
		case MP_LU_NAME_TYPE_DEVICE_SPECIFIC:
			typeString =
			    getTextString(TEXT_NAME_TYPE_DEVICE_SPECIFIC);
			break;
		default:
			typeString = getTextString(TEXT_UNKNOWN);
			break;
	}

	(void) printf("%s", typeString);


} /* end displayLogicalUnitNameTypeString */

/*
 * ****************************************************************************
 *
 * displayLoadBalanceString
 * 	Displays the text equivalent string for the MP_LOAD_BALANCE_TYPE
 *	specified load balance type
 *
 * lbVal	- load balance type defined in the MPAPI spec
 *
 * ****************************************************************************
 */
void
displayLoadBalanceString(MP_LOAD_BALANCE_TYPE lbVal)
{

	char					*lbString;

	switch (lbVal) {

		case MP_LOAD_BALANCE_TYPE_UNKNOWN:
			lbString = getTextString(TEXT_LBTYPE_UNKNOWN);
			break;
		case MP_LOAD_BALANCE_TYPE_ROUNDROBIN:
			lbString = getTextString(TEXT_LBTYPE_ROUNDROBIN);
			break;
		case MP_LOAD_BALANCE_TYPE_LEASTBLOCKS:
			lbString = getTextString(TEXT_LBTYPE_LEASTBLOCKS);
			break;
		case MP_LOAD_BALANCE_TYPE_LEASTIO:
			lbString = getTextString(TEXT_LBTYPE_LEASTIO);
			break;
		case MP_LOAD_BALANCE_TYPE_DEVICE_PRODUCT:
			lbString = getTextString(TEXT_LBTYPE_DEVICEPROD);
			break;
		case MP_LOAD_BALANCE_TYPE_LBA_REGION:
			lbString = getTextString(TEXT_LBTYPE_LBAREGION);
			break;
		case MP_LOAD_BALANCE_TYPE_FAILOVER_ONLY:
			lbString = getTextString(TEXT_LBTYPE_FAILOVER_ONLY);
			break;
		case (((MP_UINT32)0x00000001)<<16):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY1);
			break;
		case (((MP_UINT32)0x00000001)<<17):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY2);
			break;
		case (((MP_UINT32)0x00000001)<<18):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY3);
			break;
		case (((MP_UINT32)0x00000001)<<19):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY4);
			break;
		case (((MP_UINT32)0x00000001)<<20):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY5);
			break;
		case (((MP_UINT32)0x00000001)<<21):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY6);
			break;
		case (((MP_UINT32)0x00000001)<<22):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY7);
			break;
		case (((MP_UINT32)0x00000001)<<23):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY8);
			break;
		case (((MP_UINT32)0x00000001)<<24):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY9);
			break;
		case (((MP_UINT32)0x00000001)<<25):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY10);
			break;
		case (((MP_UINT32)0x00000001)<<26):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY11);
			break;
		case (((MP_UINT32)0x00000001)<<27):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY12);
			break;
		case (((MP_UINT32)0x00000001)<<28):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY13);
			break;
		case (((MP_UINT32)0x00000001)<<29):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY14);
			break;
		case (((MP_UINT32)0x00000001)<<30):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY15);
			break;
		case (((MP_UINT32)0x00000001)<<31):
			lbString = getTextString(TEXT_LBTYPE_PROPRIETARY16);
			break;
		default:
			lbString = getTextString(TEXT_UNKNOWN);
			break;
	}

	(void) printf("%s", lbString);


} /* end displayLoadBalanceString */

/*
 * ****************************************************************************
 *
 * displayTransportTypeString
 * 	Displays the text equivalent string for the MP_PORT_TRANSPORT_TYPE
 *	specified load balance type
 *
 * transportTypeVal	- transport type defined in the MPAPI spec
 *
 * ****************************************************************************
 */
void
displayTransportTypeString(MP_PORT_TRANSPORT_TYPE transportTypeVal)
{

	char					*ttypeString;
	switch (transportTypeVal) {

		case MP_PORT_TRANSPORT_TYPE_MPNODE:
			ttypeString =
			    getTextString(TEXT_TRANS_PORT_TYPE_MPNODE);
			break;
		case MP_PORT_TRANSPORT_TYPE_FC:
			ttypeString = getTextString(TEXT_TRANS_PORT_TYPE_FC);
			break;
		case MP_PORT_TRANSPORT_TYPE_SPI:
			ttypeString = getTextString(TEXT_TRANS_PORT_TYPE_SPI);
			break;
		case MP_PORT_TRANSPORT_TYPE_ISCSI:
			ttypeString = getTextString(TEXT_TRANS_PORT_TYPE_ISCSI);
			break;
		case MP_PORT_TRANSPORT_TYPE_IFB:
			ttypeString = getTextString(TEXT_TRANS_PORT_TYPE_IFB);
			break;
		default:
			ttypeString = getTextString(TEXT_UNKNOWN);
			break;
	}

	(void) printf("%s", ttypeString);

} /* end displayTransportTypeString */


/*
 * ****************************************************************************
 *
 * getMpStatusStr
 * 	Gets the string description for the specified load balance type value
 *
 * mpstatus	- MP_STATUS value
 *
 * ****************************************************************************
 */
char *
getMpStatusStr(MP_STATUS mpstatus)
{
	char					*statString;

	switch (mpstatus) {
		case MP_STATUS_SUCCESS:
			statString = getTextString(TEXT_MPSTATUS_SUCCESS);
			break;
		case MP_STATUS_INVALID_PARAMETER:
			statString = getTextString(TEXT_MPSTATUS_INV_PARAMETER);
			break;
		case MP_STATUS_UNKNOWN_FN:
			statString = getTextString(TEXT_MPSTATUS_UNKNOWN_FN);
			break;
		case MP_STATUS_FAILED:
			statString = getTextString(TEXT_MPSTATUS_FAILED);
			break;
		case MP_STATUS_INSUFFICIENT_MEMORY:
			statString = getTextString(TEXT_MPSTATUS_INSUFF_MEMORY);
			break;
		case MP_STATUS_INVALID_OBJECT_TYPE:
			statString = getTextString(TEXT_MPSTATUS_INV_OBJ_TYPE);
			break;
		case MP_STATUS_UNSUPPORTED:
			statString = getTextString(TEXT_MPSTATUS_UNSUPPORTED);
			break;
		case MP_STATUS_OBJECT_NOT_FOUND:
			statString = getTextString(TEXT_MPSTATUS_OBJ_NOT_FOUND);
			break;
		case MP_STATUS_ACCESS_STATE_INVALID:
			statString = getTextString(TEXT_MPSTATUS_UNSUPPORTED);
			break;
		case MP_STATUS_FN_REPLACED:
			statString = getTextString(TEXT_MPSTATUS_FN_REPLACED);
			break;
		case MP_STATUS_PATH_NONOPERATIONAL:
			statString = getTextString(TEXT_MPSTATUS_PATH_NONOP);
			break;
		case MP_STATUS_TRY_AGAIN:
			statString = getTextString(TEXT_MPSTATUS_TRY_AGAIN);
			break;
		case MP_STATUS_NOT_PERMITTED:
			statString = getTextString(TEXT_MPSTATUS_NOT_PERMITTED);
			break;
		default:
			statString = getTextString(TEXT_UNKNOWN);
			break;
	}

	return (statString);
} /* end getMpStatusStr */


/*
 * ****************************************************************************
 *
 * GetPathStateStr
 * 	Gets the string description for the specified path state type value
 *
 * pathState	- MP_PATH_STATE values
 *
 * ****************************************************************************
 */
char *
getPathStateStr(MP_PATH_STATE pathState)
{
	char					*pathString;

	switch (pathState) {
		case MP_PATH_STATE_OKAY:
			pathString = getTextString(TEXT_PATH_STATE_OKAY);
			break;
		case MP_PATH_STATE_PATH_ERR:
			pathString = getTextString(TEXT_PATH_STATE_PATH_ERR);
			break;
		case MP_PATH_STATE_LU_ERR:
			pathString = getTextString(TEXT_PATH_STATE_LU_ERR);
			break;
		case MP_PATH_STATE_RESERVED:
			pathString = getTextString(TEXT_PATH_STATE_RESERVED);
			break;
		case MP_PATH_STATE_REMOVED:
			pathString = getTextString(TEXT_PATH_STATE_REMOVED);
			break;
		case MP_PATH_STATE_TRANSITIONING:
			pathString =
			    getTextString(TEXT_PATH_STATE_TRANSITIONING);
			break;
		case MP_PATH_STATE_OPERATIONAL_CLOSED:
			pathString =
			    getTextString(TEXT_PATH_STATE_OPERATIONAL_CLOSED);
			break;
		case MP_PATH_STATE_INVALID_CLOSED:
			pathString =
			    getTextString(TEXT_PATH_STATE_INVALID_CLOSED);
			break;
		case MP_PATH_STATE_OFFLINE_CLOSED:
			pathString =
			    getTextString(TEXT_PATH_STATE_OFFLINE_CLOSED);
			break;
		default:
			pathString = getTextString(TEXT_UNKNOWN);
			break;
	}

	return (pathString);
} /* end getPathStateStr */



/*
 * ****************************************************************************
 *
 * getAccessStateStr
 * 	Gets the string description for the specified access state type value
 *
 * accessState	- MP_ACCESS_STATE_TYPE values
 *
 * ****************************************************************************
 */
char *
getAccessStateStr(MP_ACCESS_STATE_TYPE accessState)
{
	char					*accessString;

	switch (accessState) {
		case MP_ACCESS_STATE_ACTIVE_OPTIMIZED:
			accessString =
			    getTextString(TEXT_ACCESS_STATE_ACTIVE_OPTIMIZED);
			break;
		case MP_ACCESS_STATE_ACTIVE_NONOPTIMIZED:
			accessString =
			    getTextString(
			    TEXT_ACCESS_STATE_ACTIVE_NONOPTIMIZED);
			break;
		case MP_ACCESS_STATE_STANDBY:
			accessString =
			    getTextString(TEXT_ACCESS_STATE_STANDBY);
			break;
		case MP_ACCESS_STATE_UNAVAILABLE:
			accessString =
			    getTextString(TEXT_ACCESS_STATE_UNAVAILABLE);
			break;
		case MP_ACCESS_STATE_TRANSITIONING:
			accessString =
			    getTextString(TEXT_ACCESS_STATE_TRANSITIONING);
			break;
		case MP_ACCESS_STATE_ACTIVE:
			accessString = getTextString(TEXT_ACCESS_STATE_ACTIVE);
			break;
		default:
			accessString = getTextString(TEXT_UNKNOWN);
			break;
	}
	return (accessString);
} /* end getAccessStateStr */


/*
 * ****************************************************************************
 *
 * displayArray
 * 	Print out the specified array.
 *
 * arrayToDisplay	- array to display
 * arraySize		- size of array to display
 *
 * ****************************************************************************
 */
void
displayArray(MP_CHAR *arrayToDisplay, int arraySize)
{
	int					i;

	for (i = 0; i < arraySize; i++) {
		if ('\0' != arrayToDisplay[i]) {
			(void) fprintf(stdout, "%c", arrayToDisplay[i]);
		}
	}

}


/*
 * ****************************************************************************
 *
 * getStringArray
 * 	Return a null terminated array for the specified array as a string,
 *	This is used for inputting into the %s in formatted strings.
 *
 * arrayToDisplay	- array to display
 * arraySize		- size of array to display
 *
 * ****************************************************************************
 */
MP_CHAR *
getStringArray(MP_CHAR *arrayToDisplay, int arraySize)
{
	MP_CHAR					*newStr;

	int					i;

	newStr = malloc(((sizeof (MP_CHAR)) * arraySize) + 1);
	if (NULL == newStr) {
		(void) fprintf(stdout, "%s\n",
		    getTextString(ERR_MEMORY_ALLOCATION));
	} else {

		for (i = 0; i < arraySize; i++) {
			newStr[i] = arrayToDisplay[i];
		}
		newStr[arraySize] = '\0';
	}

	return (newStr);
}


/*
 * ****************************************************************************
 *
 * displayWideArray
 * 	Print out the specified wide character array as a string,
 * 	adding the null termination
 *
 * arrayToDisplay	- array to display
 * arraySize		- size of array to display
 *
 * ****************************************************************************
 */
void
displayWideArray(MP_WCHAR *arrayToDisplay, int arraySize)
{
	int					i;
	int					numChars = arraySize/4;

	for (i = 0; i < numChars; i++) {
		if (L'\0' != arrayToDisplay[i]) {
			(void) fprintf(stdout, "%wc", arrayToDisplay[i]);
		}
	}
}


/*
 * ****************************************************************************
 *
 * listfunc
 * 	Used by cmdparse for list clis
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
listFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case MPATH_SUPPORT:
			ret = listMpathSupport(operandLen, operand);
			break;
		case LOGICAL_UNIT:
			ret = listLogicalUnit(operandLen, operand, options);
			break;
		case INITIATOR_PORT:
			ret = listInitiatorPort(operandLen, operand);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, getTextString(TEXT_UNKNOWN_OBJECT));
			ret = 1;
			break;
	}

	return (ret);
}


/*
 * ****************************************************************************
 *
 * showFunc
 * 	used bycmdparse for show clis
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
showFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case MPATH_SUPPORT:
			ret = showMpathSupport(operandLen, operand);
			break;
		case LOGICAL_UNIT:
			ret = showLogicalUnit(operandLen, operand);
			break;
		case INITIATOR_PORT:
			ret = showInitiatorPort(operandLen, operand);
			break;
		default:
			ret = 1;
			break;
	}

	return (ret);
}


/*
 * ****************************************************************************
 *
 * modifyFunc
 * 	Used by cmdparse for midify clis
 *
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
modifyFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case MPATH_SUPPORT:
			ret = modifyMpathSupport(operandLen, operand, options);
			break;
		case LOGICAL_UNIT:
			ret = modifyLogicalUnit(operandLen, operand, options);
			break;
		default:
			ret = 1;
			break;
	}


	return (ret);
}


/*
 * ****************************************************************************
 *
 * enableFunc
 * 	Used by cmdpars for enable clis
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
enableFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case PATH:
			ret = enablePath(options);
			break;
		default:
			ret = 1;
			break;
	}

	return (ret);
}


/*
 * ****************************************************************************
 *
 * disableFunc
 * 	Used by cmdpars for disable clis
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
disableFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case PATH:
			ret = disablePath(options);
			break;
		default:
			ret = 1;
			break;
	}

	return (ret);
}


/*
 * ****************************************************************************
 *
 * failoverFunc
 * 	Used by cmdpars for failover clis
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
failoverFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case LOGICAL_UNIT:
			ret = failoverLogicalUnit(operand);
			break;
		default:
			ret = 1;
			break;
	}

	return (ret);
}


/*
 * ****************************************************************************
 *
 * overrideFunc
 * 	Used by cmdpars for override clis
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
overrideFunc(int operandLen, char *operand[],
	int object, cmdOptions_t *options,
    void *addArgs)
{
	int 					ret = 0;

	switch (object) {
		case PATH:
			ret = overridePath(options);
			break;
		default:
			ret = 1;
			break;
	}


	return (ret);
}


/*
 * *************************************************************************
 *
 * main
 *
 * *************************************************************************
 */
int
main(int argc, char *argv[])
{
	synTables_t 			synTables;
	char 				versionString[VERSION_STRING_MAX_LEN];
	int 				ret;
	int 				funcRet;
	void 				*subcommandArgs = NULL;

	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	(void) sprintf(versionString, "%2s.%2s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subcommandTbl = &subcommands[0];
	synTables.objectTbl = &objects[0];
	synTables.objectRulesTbl = &objectRules[0];
	synTables.optionRulesTbl = &optionRules[0];

	ret = cmdParse(argc, argv, /* SUB_COMMAND_ISSUED, */ synTables,
	    subcommandArgs, &funcRet);
	if (ret == 1) {
		(void) fprintf(stdout, "%s %s(1M)\n",
		    getTextString(TEXT_MORE_INFO), cmdName);
		return (ERROR_CLI_FAILED);
	} else if (ret == -1) {
		perror(argv[0]);
		return (1);
	}

	if (funcRet != 0) {
		(void) fprintf(stderr, "%s: %s\n",
		    argv[0], getTextString(TEXT_UNABLE_TO_COMPLETE));
		return (1);
	}
	return (0);

} /* end main */
