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
#include <stropts.h>
#include <libintl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <cmdparse.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/systeminfo.h>

#include <libiscsit.h>
#include <sys/iscsit/iscsit_common.h>

static int it_enable(int, char **, cmdOptions_t *, void *);
static int it_disable(int, char **, cmdOptions_t *, void *);

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
	{"start", it_enable, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{"stop", it_disable, NULL, NULL, NULL, OPERAND_NONE, NULL},
	{NULL, 0, NULL, NULL, 0, 0, 0, NULL}
};

/* globals */
char *cmdName;

/*
 * Opens the iSCSI Target Node
 *
 * fd - Return the iscsit file descriptor
 */
static int
it_open(int *fd)
{

	int ret = ITADM_SUCCESS;

	*fd = open(ISCSIT_NODE, O_RDONLY);
	if (*fd < 0) {
		if (errno == EPERM) {
			(void) fprintf(stdout, "open failed: EPERM");
			ret = ITADM_PERM;
		} else {
			(void) fprintf(stdout, "open failed: INVALID");
			ret = ITADM_INVALID;
		}
	}

	return (ret);
}

/*
 * Enables the iSCSI Target
 */
/*ARGSUSED*/
static int
it_enable(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int	ret;
	int	fd;
	char	buf[256];
	uint32_t *buflenp;
	char	*fqhnp;
	iscsit_hostinfo_t hostinfo;

	(void) fprintf(stdout, "%s: %s\n", cmdName,
	    gettext("Requesting to enable iscsi target"));

	bzero(buf, 256);
	bzero(hostinfo.fqhn, sizeof (hostinfo.fqhn));

	/* Open the iscsi target node */
	if ((ret = it_open(&fd)) != ITADM_SUCCESS) {
		(void) fprintf(stdout, "Unable to open device %s", ISCSIT_NODE);
		return (ret);
	}

	(void) fprintf(stdout, "it_enable [fd=%d]\n", fd);
	/* enable the iscsi target */
	buflenp = (uint32_t *)((void *)&buf);
	*buflenp = strlen("target_name") + 1;
	(void) strncpy(buf + sizeof (uint32_t), "target_name",
	    256 - sizeof (uint32_t));

	fqhnp = &hostinfo.fqhn[0];

	ret = sysinfo(SI_HOSTNAME, fqhnp, 256);

	if ((ret != -1) && (ret < sizeof (hostinfo.fqhn))) {
		fqhnp += ret;
		hostinfo.length = ret;
		hostinfo.fqhn[ret-1] = '.';
		hostinfo.length += sysinfo(SI_SRPC_DOMAIN, fqhnp,
		    sizeof (hostinfo.fqhn) - ret);
	}

	(void) fprintf(stdout, "it_enable: fqhn = '%s'\n", hostinfo.fqhn);

	if ((ret = ioctl(fd, ISCSIT_IOC_ENABLE_SVC, &hostinfo)) != 0) {
		(void) fprintf(stdout, "Unable to issue ioctl: %d", errno);
		return (ret);
	}
	return (ITADM_SUCCESS);
}


/*
 * Disable the iSCSI target
 */
/* ARGSUSED */
static int
it_disable(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int	ret;
	int	fd;

	(void) fprintf(stdout, "%s: %s\n", cmdName,
	    gettext("Requesting to disable iscsi target"));

	/* Open the iscsi target node */
	if ((ret = it_open(&fd)) != ITADM_SUCCESS) {
		return (ret);
	}

	/* disable the iSCSI target */
	if ((ret = ioctl(fd, ISCSIT_IOC_DISABLE_SVC, NULL)) != 0) {
		return (ret);
	}
	return (ITADM_SUCCESS);
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
