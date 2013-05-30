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
#include <libstmf.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>

static char *getExecBasename(char *);
static int setLuStandbyFunc(int, char **, cmdOptions_t *, void *);
static int disableAluaFunc(int, char **, cmdOptions_t *, void *);
static int enableAluaFunc(int, char **, cmdOptions_t *, void *);

#define	OPERANDSTRING_LU	    "LU-name"
#define	OPERANDSTRING_NODE_ID	    "node ID (0 or 1)"

#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"
#define	VERSION_STRING_MAX_LEN	    10

#define	GUID_INPUT		    32

/* tables set up based on cmdparse instructions */

/* add new options here */
optionTbl_t longOptions[] = {
	{NULL, 0, 0, 0}
};

/*
 * Add new subcommands here
 */
subCommandProps_t subcommands[] = {
	{"standby", setLuStandbyFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU, NULL},
	{"disable", disableAluaFunc, NULL, NULL, NULL,
		OPERAND_NONE, NULL, NULL},
	{"enable", enableAluaFunc, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_NODE_ID, NULL},
	{NULL, 0, NULL, NULL, 0, NULL, 0, NULL, NULL}
};

/* globals */
char *cmdName;

/*
 * setLuStandbyFunc
 *
 * Purpose: set lu to standby
 *
 */
/*ARGSUSED*/
static int
setLuStandbyFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	char sGuid[GUID_INPUT + 1];
	stmfGuid inGuid;
	unsigned int guid[sizeof (stmfGuid)];
	int i;
	int ret = 0;

	if (strlen(operands[0]) != GUID_INPUT) {
		(void) fprintf(stderr, "%s: %s: %s %d %s\n", cmdName,
		    operands[0], gettext("must be"), GUID_INPUT,
		    gettext("hexadecimal digits long"));
		return (1);
	}

	bcopy(operands[0], sGuid, GUID_INPUT);

	for (i = 0; i < GUID_INPUT; i++)
		sGuid[i] = tolower(sGuid[i]);
	sGuid[i] = 0;

	(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
	    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10], &guid[11],
	    &guid[12], &guid[13], &guid[14], &guid[15]);

	for (i = 0; i < sizeof (stmfGuid); i++) {
		inGuid.guid[i] = guid[i];
	}

	ret = stmfLuStandby(&inGuid);
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
				    operands[0], gettext("not found"));
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
 * disableAluaFunc
 *
 * Purpose: disable alua mode
 *
 */
/*ARGSUSED*/
static int
disableAluaFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	return (stmfSetAluaState(B_FALSE, 0));
}

/*
 * enableAluaFunc
 *
 * Purpose: enable alua mode
 *
 */
/*ARGSUSED*/
static int
enableAluaFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	uint8_t node_id = 0;
	if (operands[0][0] == '1') {
		node_id = 1;
	}
	return (stmfSetAluaState(B_TRUE, node_id));
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
