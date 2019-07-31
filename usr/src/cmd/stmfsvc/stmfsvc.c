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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
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

static int svcStart(int, char **, cmdOptions_t *, void *);
static int svcStop(int, char **, cmdOptions_t *, void *);
static int online();

/*
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"
#define	VERSION_STRING_MAX_LEN	    10

/* 10 ms sleep in nanoseconds */
#define	TEN_MS_NANOSLEEP  10000000

/* tables set up based on cmdparse instructions */

/* add new options here */
optionTbl_t longOptions[] = {
	{NULL, 0, 0, 0}
};

/*
 * Add new subcommands here
 */
subCommandProps_t subcommands[] = {
	{"start", svcStart, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{"stop", svcStop, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL}
};

/* globals */
char *cmdName;

/*
 * svcStop
 *
 * Offlines the stmf service
 *
 */
/*ARGSUSED*/
static int
svcStop(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet;
	int ret = 0;
	stmfState state;
	boolean_t serviceOffline = B_FALSE;
	struct timespec rqtp;

	bzero(&rqtp, sizeof (rqtp));

	rqtp.tv_nsec = TEN_MS_NANOSLEEP;

	if ((stmfRet = stmfOffline()) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_OFFLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service already offline"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to offline service"));
				break;
		}
		return (1);
	}

	/* wait for service offline */
	while (!serviceOffline) {
		stmfRet = stmfGetState(&state);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			ret = 1;
			break;
		}
		if (state.operationalState == STMF_SERVICE_STATE_OFFLINE) {
			serviceOffline = B_TRUE;
		} else {
			(void) nanosleep(&rqtp, NULL);
		}
	}

	return (ret);
}

/*
 * loadConfig
 *
 * Loads the stmf config from the SMF repository
 *
 */
/*ARGSUSED*/
static int
svcStart(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet;
	int ret = 0;
	(void) stmfLoadStmfProps();
	if ((stmfRet = stmfLoadConfig()) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service must be offline"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("Unable to load the configuration. "
				    "See /var/adm/messages for details"));
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("For information on reverting the "
				    "stmf:default instance to a previously "
				    "running configuration see the man page "
				    "for svccfg(1M)"));
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("After reverting the instance "
				    "you must clear the service maintenance "
				    "state. See the man page for svcadm(1M)"));
				break;
		}
		return (1);
	}
	ret = online();
	return (ret);

}

/*
 * online
 *
 * Onlines the stmf service
 *
 */
/*ARGSUSED*/
static int
online()
{
	int stmfRet;
	int ret = 0;
	stmfState state;
	boolean_t serviceOnline = B_FALSE;
	struct timespec rqtp;

	bzero(&rqtp, sizeof (rqtp));

	rqtp.tv_nsec = TEN_MS_NANOSLEEP;

	if ((stmfRet = stmfOnline()) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service already online"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to online service"));
				break;
		}
		return (1);
	}

	/* wait for service online */
	while (!serviceOnline) {
		stmfRet = stmfGetState(&state);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			ret = 1;
			break;
		}
		if (state.operationalState == STMF_SERVICE_STATE_ONLINE) {
			serviceOnline = B_TRUE;
		} else {
			(void) nanosleep(&rqtp, NULL);
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
