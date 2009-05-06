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
 *
 */

/* $Id: lpc.c 146 2006-03-24 00:26:54Z njacobs $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <papi.h>
#include "common.h"

typedef int (cmd_handler_t)(papi_service_t, char **);

static papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;

/* ARGSUSED0 */
static int
lpc_exit(papi_service_t svc, char **args)
{
	exit(0);
	/* NOTREACHED */
	return (0);
}

static int
lpc_status(papi_service_t svc, char **args)
{
	papi_status_t status;
	papi_printer_t p = NULL;
	char *pattrs[] = { "printer-state", "printer-state-reasons",
				"printer-is-accepting-jobs", NULL };
	char *destination = args[1];

	status = papiPrinterQuery(svc, destination, pattrs, NULL, &p);
	if (status == PAPI_OK) {
		papi_attribute_t **list = papiPrinterGetAttributeList(p);
		char accepting = 0;
		int32_t state = 0;

		printf("%s:\n", destination);

		(void) papiAttributeListGetBoolean(list, NULL,
				"printer-is-accepting-jobs", &accepting);
		printf(gettext("\tqueueing is %s\n"),
			(accepting ? gettext("enabled") : gettext("disabled")));

		(void) papiAttributeListGetInteger(list, NULL,
					"printer-state", &state);
		printf("\tprinting is %s\n",
			((state != 0x05) ? gettext("enabled") :
				gettext("disabled")));

		if (state != 0x03) {	/* !idle */
			papi_job_t *jobs = NULL;
			int i = 0;

			(void) papiPrinterListJobs(svc, destination, NULL,
					PAPI_LIST_JOBS_ALL, 0, &jobs);
			if (jobs != NULL) {
				for (i = 0; jobs[i] != NULL; i++);
				papiJobListFree(jobs);
			}
			printf(gettext("\t%d entries in spool area\n"), i);
		} else
			printf(gettext("\tno entries\n"));

		if (state == 0x04)
			printf(gettext("\tdaemon present\n"));

	} else {
		fprintf(stderr, "%s: %s\n", destination,
			verbose_papi_message(svc, status));
		return (-1);
	}

	papiPrinterFree(p);

	return (0);
}

static int
lpc_abort(papi_service_t svc, char **args)
{
	papi_status_t status;
	char *destination = args[1];

	if (destination == NULL) {
		fprintf(stderr, gettext("Usage: abort (destination)\n"));
		return (-1);
	}

	status = papiPrinterPause(svc, destination, "paused via lpc abort");
	if (status == PAPI_OK) {
		printf(gettext("%s: processing disabled after current job\n"),
			destination);
	} else {
		fprintf(stderr, "%s: %s\n", destination,
			verbose_papi_message(svc, status));
	}

	return (0);
}

static int
lpc_clean(papi_service_t svc, char **args)
{
	papi_status_t status;
	papi_job_t *jobs = NULL;
	char *destination = args[1];

	if (destination == NULL) {
		fprintf(stderr, gettext("Usage: clean (destination)\n"));
		return (-1);
	}

	status = papiPrinterPurgeJobs(svc, destination, &jobs);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("clean: %s: %s\n"), destination,
			verbose_papi_message(svc, status));
		return (-1);
	}

	if (jobs != NULL) {
		int i;

		for (i = 0; jobs[i] != NULL; i++)
			printf(gettext("\t%s-%d: cancelled\n"), destination,
				papiJobGetId(jobs[i]));

		papiJobListFree(jobs);
	}

	return (0);
}

static int
lpc_disable(papi_service_t svc, char **args)
{
	papi_status_t status;
	char *destination = args[1];

	if (destination == NULL) {
		fprintf(stderr, gettext("Usage: disable: (destination)\n"));
		return (-1);
	}

	status = papiPrinterDisable(svc, destination, NULL);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("disable: %s: %s\n"), destination,
			verbose_papi_message(svc, status));
		return (-1);
	}

	return (0);
}

static int
lpc_enable(papi_service_t svc, char **args)
{
	papi_status_t status;
	char *destination = args[1];

	if (destination == NULL) {
		fprintf(stderr, gettext("Usage: enable: (destination)\n"));
		return (-1);
	}

	status = papiPrinterEnable(svc, destination);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("enable: %s: %s\n"), destination,
			verbose_papi_message(svc, status));
		return (-1);
	}

	return (0);
}

static int
lpc_restart(papi_service_t svc, char **args)
{
	int rc = 0;

	rc += lpc_disable(svc, args);
	rc += lpc_enable(svc, args);

	return (rc);
}

static int
lpc_start(papi_service_t svc, char **args)
{
	papi_status_t status;
	char *destination = args[1];

	if (destination == NULL) {
		fprintf(stderr, gettext("Usage: start (destination)\n"));
		return (-1);
	}

	status = papiPrinterResume(svc, destination);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("start: %s: %s\n"), destination,
			verbose_papi_message(svc, status));
		return (-1);
	}

	return (0);
}

static int
lpc_stop(papi_service_t svc, char **args)
{
	papi_status_t status;
	char *destination = args[1];

	if (destination == NULL) {
		fprintf(stderr, gettext("Usage: stop (destination)\n"));
		return (-1);
	}

	status = papiPrinterPause(svc, destination, "paused via lpc");
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("stop: %s: %s\n"), destination,
			verbose_papi_message(svc, status));
		return (-1);
	}

	return (0);
}

static int
lpc_topq(papi_service_t svc, char **args)
{
	papi_status_t status;
	char *destination = args[1];
	char *idstr = args[2];
	int32_t id;

	if (destination == NULL || idstr == NULL) {
		fprintf(stderr, gettext("Usage: topq (destination) (id)\n"));
		return (-1);
	}
	id = atoi(idstr);

	status = papiJobPromote(svc, destination, id);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("topq: %s-%d: %s\n"), destination, id,
		    verbose_papi_message(svc, status));
		return (-1);
	}

	return (0);
}

static int
lpc_up(papi_service_t svc, char **args)
{
	int rc = 0;

	rc += lpc_enable(svc, args);
	rc += lpc_start(svc, args);

	return (rc);
}

static int
lpc_down(papi_service_t svc, char **args)
{
	int rc = 0;

	rc += lpc_disable(svc, args);
	rc += lpc_stop(svc, args);

	return (rc);
}

static int lpc_help(papi_service_t svc, char **args);	/* forward reference */

static char help_help[] = "get help on commands";
static char help_exit[] = "exit lpc";
static char help_status[] = "show status of daemon and queue";
static char help_abort[] =
		"disable print queue terminating any active job processing";
static char help_clean[] = "remove all jobs from a queue";
static char help_disable[] = "turn off spooling to a queue";
static char help_down[] =
		"turn off queueing and printing for a queue and set a reason";
static char help_enable[] = "turn on spooling to a queue";
static char help_restart[] = "restart job processing for a queue";
static char help_start[] = "turn on printing from a queue";
static char help_stop[] = "turn off printing from a queue";
static char help_up[] = "turn on queueing and printing for a queue";
static char help_topq[] = "put a job at the top of the queue";

static struct {
	char *cmd;
	int (*handler)(papi_service_t svc, char **args);
	char *help_string;
	int num_args;
} cmd_tab[] = {
	{ "?",		lpc_help,	help_help,	0 },
	{ "help",	lpc_help,	help_help,	0 },
	{ "exit",	lpc_exit,	help_exit,	0 },
	{ "quit",	lpc_exit,	help_exit,	0 },
	{ "status",	lpc_status,	help_status,	1 },
	{ "abort",	lpc_abort,	help_abort,	1 },
	{ "clean",	lpc_clean,	help_clean,	1 },
	{ "disable",	lpc_disable,	help_disable,	1 },
	{ "down",	lpc_down,	help_down,	2 },
	{ "enable",	lpc_enable,	help_enable,	1 },
	{ "restart",	lpc_restart,	help_restart,	1 },
	{ "start",	lpc_start,	help_start,	1 },
	{ "stop",	lpc_stop,	help_stop,	1 },
	{ "up",		lpc_up,		help_up,	1 },
	{ "topq",	lpc_topq,	help_topq,	2 },
	{ NULL,		NULL,		NULL,		0 }
};

static int
lpc_handler(char *cmd, cmd_handler_t **handler)
{
	int i;

	for (i = 0; cmd_tab[i].cmd != NULL; i++)
		if (strcmp(cmd, cmd_tab[i].cmd) == 0) {
			*handler = cmd_tab[i].handler;
			return (cmd_tab[i].num_args);
		}
	return (-1);
}

static char *
lpc_helptext(char *cmd)
{
	int i;

	for (i = 0; cmd_tab[i].cmd != NULL; i++)
		if (strcmp(cmd, cmd_tab[i].cmd) == 0)
			return (gettext(cmd_tab[i].help_string));
	return (NULL);
}

/* ARGSUSED0 */
static int
lpc_help(papi_service_t svc, char **args)
{
	if (args[1] == NULL) {
		int i;

		printf(gettext("Commands are:\n\n"));
		for (i = 0; cmd_tab[i].cmd != NULL; i++) {
			printf("\t%s", cmd_tab[i].cmd);
			if ((i % 7) == 6)
				printf("\n");
		}
		if ((i % 7) != 6)
			printf("\n");
	} else {
		char *helptext = lpc_helptext(args[1]);

		if (helptext == NULL)
			helptext = gettext("no such command");

		printf("%s: %s\n", args[1], helptext);
	}

	return (0);
}

static int
process_one(int (*handler)(papi_service_t, char **), char **av, int expected)
{
	int rc = -1;
	papi_status_t status = PAPI_OK;
	papi_service_t svc = NULL;
	char *printer = av[1];

	if ((printer != NULL) && (expected != 0)) {
		status = papiServiceCreate(&svc, printer, NULL, NULL,
					cli_auth_callback, encryption, NULL);
		if (status != PAPI_OK) {
			fprintf(stderr, gettext(
				"Failed to contact service for %s: %s\n"),
				printer, verbose_papi_message(svc, status));
		}
	}

	if (status == PAPI_OK)
		rc = handler(svc, av);

	if (svc != NULL)
		papiServiceDestroy(svc);

	return (rc);
}

static int
process_all(int (*handler)(papi_service_t, char **), char **av, int expected)
{
	papi_status_t status;
	papi_service_t svc = NULL;
	char **printers;
	int rc = 0;

	status = papiServiceCreate(&svc, NULL, NULL, NULL, NULL,
				encryption, NULL);
	if (status != PAPI_OK) {
		fprintf(stderr, gettext("Failed to contact service: %s\n"),
			verbose_papi_message(svc, status));
		return (-1);
	}

	if ((printers = interest_list(svc)) != NULL) {
		int i;

		for (i = 0; printers[i] != NULL; i++) {
			av[1] = printers[i];
			rc += process_one(handler, av, expected);
		}
	}

	papiServiceDestroy(svc);

	return (rc);
}

static int
process(int ac, char **av)
{
	int (*handler)(papi_service_t, char **) = NULL;
	int num_args = -1;

	char *printer = av[1];
	int rc = -1;

	if ((num_args = lpc_handler(av[0], &handler)) < 0) {
		printf(gettext("%s: invalid command\n"), av[0]);
		return (-1);
	}

	if (((ac == 0) && (num_args == 1)) ||
	    ((printer != NULL) && strcmp(printer, "all") == 0))
		rc = process_all(handler, av, num_args);
	else if (num_args < ac) {
		int i;
		char *argv[4];

		memset(argv, 0, sizeof (argv));
		argv[0] = av[0];

		if (strcmp(av[0], "topq") == 0) {
			argv[1] = av[1];
			for (i = 2; i <= ac; i++) {
				argv[2] = av[i];
				process_one(handler, argv, num_args);
			}
		} else
			for (i = 1; i <= ac; i++) {
				argv[1] = av[i];
				process_one(handler, argv, num_args);
			}
	} else
		rc = process_one(handler, av, num_args);

	return (rc);
}

static void
usage(char *program)
{
	char *name;

	if ((name = strrchr(program, '/')) == NULL)
		name = program;
	else
		name++;

	fprintf(stdout,
		gettext("Usage: %s [ command [ parameter...]]\n"),
		name);
	exit(1);
}

static void
lpc_shell()
{
	for (;;) {
		char line[256];
		char **av = NULL;
		int ac = 0;

		/* prompt */
		fprintf(stdout, "lpc> ");
		fflush(stdout);

		/* get command */
		if (fgets(line, sizeof (line), stdin) == NULL)
			exit(1);
		if ((av = strsplit(line, " \t\n")) != NULL)
			for (ac = 0; av[ac] != NULL; ac++);
		else
			continue;

		if (ac > 0)
			(void) process(ac - 1, av);
		free(av);
	}
}

int
main(int ac, char *av[])
{
	int result = 0;
	int c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("SUNW_OST_OSCMD");

	while ((c = getopt(ac, av, "E")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_ALWAYS;
			break;
		default:
			usage(av[0]);
		}

	if (optind == ac)
		lpc_shell();
	else
		result = process(ac - optind - 1, &av[optind]);

	return (result);
}
