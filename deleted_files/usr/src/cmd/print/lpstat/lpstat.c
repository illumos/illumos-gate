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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <locale.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif
#include <sys/systeminfo.h>
#include <sys/param.h>
#include <errno.h>
#include <netdb.h>

#include <print/ns.h>
#include <print/network.h>
#include <print/misc.h>
#include <print/list.h>
#include <print/job.h>

#include "parse.h"
#include "sysv-functions.h"
#include "bsd-functions.h"

extern char *optarg;
extern int optind, opterr, optopt;
extern char *getenv(const char *);
extern char *getname(void);

static int exit_code = 0;
static int _processing_all = 0;


static ns_bsd_addr_t **_printer_bindings = NULL;
static ns_bsd_addr_t **_printer_bindings_unique = NULL;


static int sysvVerbose = 0;
static int sysvDesc = 0;
static int sysvLocal = 0;

static int bsdFormat = SHOW_QUEUE_SHORT_REQUEST;
static int bsdInterval = 0;
static char **bsdv;
static int bsdc;

typedef enum _work_type work_type_t;
typedef struct _work_entry work_entry_t;

enum _work_type { ACCEPTING, DEFAULT, ENTRIES, STATUS, RUNNING, RANK, SUMMARY,
		FULL, USER, DEVICE, FORMS, CLASSES, CHAR_SETS, BSD_QUEUE };
struct _work_entry {
	ns_bsd_addr_t *binding;
	char *printer;
	char *user;
	int  id;
	work_type_t type;
};

static work_entry_t **workList = NULL;


static void
work_list_append(char *printer, char *user, int id, work_type_t type)
{
	work_entry_t *tmp = (work_entry_t *)calloc(1, sizeof (work_entry_t));

	if (tmp == NULL)
		return;
	if (user != NULL)
		tmp->user = strdup(user);
	tmp->id = id;
	tmp->type = type;
	if (printer != NULL) {
		tmp->printer = strdup(printer);
		if ((tmp->binding = ns_bsd_addr_get_name(printer)) != NULL)
			workList = (work_entry_t **)list_append(
						(void **)workList,
						(void *)tmp);
		else if (strcmp(printer, NS_NAME_DEFAULT) == 0) {
			(void) fprintf(stderr,
				gettext("No default destination\n"));
			exit_code = 1;
		} else {
			(void) fprintf(stderr, gettext("%s: unknown printer\n"),
				printer);
			exit_code = 1;
		}
	} else
		workList = (work_entry_t **)list_append((void **)workList,
					(void *)tmp);
}


static char *
check_for_req_id(char *name)
{
	char *p;
	char *p1;

	/* request id has the form <name>-<number> */
	p1 = name + strlen(name);
	if (p1 == name)
		return (NULL);
	p = p1 - 1;
	while (p > name && isdigit(*p))
		p--;
	if (*p != '-' || p == name)
		return (NULL);
	else
		return (p);
}

static void
work_list_append_list(char *list, work_type_t type)
{
	char *p;
	char *elem;

	if (list == NULL) {
		work_list_append(NULL, NULL, -1, type);
		return;
	}

	for (elem = strtok(list, "\t ,"); elem != NULL;
	    elem = strtok(NULL, "\t ,")) {
		switch (type) {
		case RANK:
		case ACCEPTING:
		case STATUS:
		case DEVICE:
			work_list_append(elem, NULL, -1, type);
			break;
		case CHAR_SETS:
		case CLASSES:
		case FORMS:
		case USER:
			work_list_append(NULL, elem, -1, type);
			break;
		case ENTRIES:
			if ((p = check_for_req_id(elem)) == NULL)
				work_list_append(elem, NULL, -1, ENTRIES);
			else if (ns_bsd_addr_get_name(elem) != NULL)
				work_list_append(elem, NULL, -1, ENTRIES);
			else {
				*p++ = '\0';
				work_list_append(elem, NULL, atoi(p), ENTRIES);
			}
			break;
		}
	}
}

static char *
lpstat_opt(work_type_t type)
{
	switch (type) {
	case STATUS:
		return ("-p");
	case RANK:
		return ("-R");
	case USER:
		return ("-u");
	case ENTRIES:
		return ("-o");
	default:
		return (NULL);
	}
}

/*
 * This function is for a performance improvement.
 */

static int
is_local_printer(char *server, char *printer)
{
	static char *hostname, hbuf[MAXHOSTNAMELEN];
	char buf[MAXPATHLEN];

	if ((server == NULL) || (printer == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	if (hostname == NULL) {
		sysinfo(SI_HOSTNAME, hbuf, sizeof (hbuf));
		hostname = hbuf;
	}

	if ((strcasecmp(server, hostname) != 0) &&
		(strcasecmp(server, "localhost") != 0))
		return (1);

	snprintf(buf, sizeof (buf), "/etc/lp/printers/%s/configuration",
		printer);
	if (access(buf, F_OK) != 0) {
		/* OK its not a local printer but may be a local class */
		snprintf(buf, sizeof (buf), "/etc/lp/classes/%s", printer);
		if (access(buf, F_OK) != 0)
			return (1);
	}
	return (0);
}

/*
 * Determine if there are any local printers in the list
 */
static int
local_printers(ns_bsd_addr_t **printers)
{
	static int local_printer_found = 0;
	static int already_looked = 0;

	if (already_looked == 0) {
		already_looked = 1;
		if ((printers == NULL) || (*printers == NULL)) {
			return (0);
		}

		/* Step through list and break out if we find a local printer */
		while (*printers != NULL) {
			if (((*printers)->server == NULL) ||
			    ((*printers)->printer == NULL))
				continue;
			if (is_local_printer((*printers)->server,
					(*printers)->printer) == 0)
				break;
			printers++;
		}

		if ((printers != NULL) && (*printers != NULL))
			local_printer_found = 1;
	}

	return (local_printer_found);
}


/*
 * Determine if local status needs to be run.  This is true
 * if there are any local printers in the list with a local
 * printer definition.
 */
static int
need_local_status(ns_bsd_addr_t **printers, ns_bsd_addr_t *binding)
{

	return ((local_printers(_printer_bindings) == 1) ||
		((binding != NULL) &&
		(is_local_printer(binding->server,
		binding->printer) == 0)));
}


static int
work_execute(work_entry_t *work, int verb)
{
	char *printer = NULL;
	char *server = NULL;
	print_queue_t *qp;
	int rank = 0;
	int rc = 0;

	switch (work->type) {
	case RUNNING:
		sysv_running();
		return (0);
	case DEFAULT:
		sysv_default();
		return (0);
	case FORMS:
		return (sysv_local_status("-f", work->user, verb, 0,
			gettext("form listing not supported on client\n")));
	case CLASSES:
		return (sysv_local_status("-c", work->user, 0, 0,
			gettext("class listing not supported on client\n")));
	case CHAR_SETS:
		return (sysv_local_status("-S", work->user, verb, 0,
			gettext("char set listing not supported on client\n")));
	}

	if ((work->binding->printer == NULL) &&
	    (work->binding->server == NULL))
		return (0);

	/*
	 * If the printer is a local LP printer, we can use the local lpstat
	 * and it should be faster than going via the network.
	 */
	if ((is_local_printer(work->binding->server,
			work->binding->printer) == 0) &&
	    ((work->binding->pname == NULL) ||
		(strcmp(work->binding->printer, work->binding->pname) == 0) ||
		(strcmp(work->binding->pname, NS_NAME_DEFAULT) == 0))) {
		char *option = lpstat_opt(work->type);

		if (option != NULL) {
			/*
			 * If we are processing all printers
			 * (ie. -p, -o, -r,
			 * -u, -t), simply return, because the local lpstat
			 * was already run and all local printers were reported
			 * against.
			 */
			if (_processing_all != 0)
				return (0);

			if (work->printer)
				return (sysv_local_status(option,
					work->printer, verb, sysvDesc,
					gettext("can't execute \n")));
			else if (work->user)
				return (sysv_local_status(option,
					work->user, verb, sysvDesc,
					gettext("can't execute \n")));
			else
				return (sysv_local_status(option,
				"", verb, sysvDesc,
				gettext("can't execute \n")));
		}
	}

	if ((printer = strchr(work->binding->printer, '|')) != NULL)
		*printer = NULL;
	printer = work->binding->printer;
	server = work->binding->server;

	switch (work->type) {
	case STATUS:
	case RANK:
	case USER:
	case ENTRIES:
		if ((qp = sysv_get_queue(work->binding, sysvLocal)) != NULL) {
			qp->jobs = job_list_append(qp->jobs, printer,
						server, SPOOL_DIR);
			switch (work->type) {
			case STATUS:
				if (work->binding->pname)
					rc += sysv_queue_state(qp,
						work->binding->pname, verb,
						sysvDesc);
				else
					rc += sysv_queue_state(qp, printer,
						verb, sysvDesc);
				break;
			case ENTRIES:
			case USER:
				rank = -1;
				/*FALLTHRU*/
			case RANK:
				if ((work->binding->pname != NULL) &&
				    (strcmp(work->binding->pname,
				    NS_NAME_DEFAULT) != 0))
				(void) list_iterate((void **)qp->jobs,
					(VFUNC_T)vsysv_queue_entry,
					work->binding->pname, work->user,
					work->id, verb, &rank);
				else
				(void) list_iterate((void **)qp->jobs,
					(VFUNC_T)vsysv_queue_entry, printer,
					work->user, work->id, verb, &rank);
				break;
			}
			if ((qp->state == RAW) && (qp->status != NULL)) {
				(void) printf("%s", qp->status);
				qp->status = NULL;
			}
		}
		break;
	default:
		switch (work->type) {
		case DEVICE:
			rc += sysv_system(work->binding);
			break;
		case ACCEPTING:
			rc += sysv_accept(work->binding);
			break;
		case BSD_QUEUE:
			do {
				int i;

				if (bsdInterval != 0)
					clear_screen();
				if (bsd_queue(work->binding, bsdFormat,
						bsdc, bsdv) != 0)
					break;
				if (bsdInterval != 0)
					(void) sleep(bsdInterval);
			} while (bsdInterval != 0);
			break;
		}
	}

	return (rc);
}


static int
vbinding_execute(ns_bsd_addr_t *binding, va_list ap)
{
	work_entry_t *work = va_arg(ap, work_entry_t *);
	int verbose = va_arg(ap, int);

	work->binding = binding;
	return (work_execute(work, verbose));
}





static int
vwork_list_execute(work_entry_t *work, va_list ap)
{
	int verbose = va_arg(ap, int);
	work_entry_t tmp;
	int rc = 0;

	if ((work->binding == NULL) || ((work->binding->printer == NULL) &&
	    (work->binding->server == NULL))) {
		switch (work->type) {
		case RUNNING:
		case DEFAULT:
		case CLASSES:
		case FORMS:
		case CHAR_SETS:
			rc += work_execute(work, verbose);
			break;
		case STATUS:
		case RANK:
		case ENTRIES:
		case ACCEPTING:
		case DEVICE:
		case SUMMARY:
		case USER:
		case FULL:

			if (_printer_bindings == NULL) {
				if (sysvLocal == 0) {
					_printer_bindings =
					    ns_bsd_addr_get_all(LOCAL_UNIQUE);
					_printer_bindings_unique =
						ns_bsd_addr_get_all(UNIQUE);
				} else {
					_printer_bindings =
					    ns_bsd_addr_get_list(LOCAL_UNIQUE);
					_printer_bindings_unique =
						ns_bsd_addr_get_list(UNIQUE);
				}
			}

			(void) memcpy(&tmp, work, sizeof (tmp));

			if (work->type == FULL || work->type == SUMMARY) {
				tmp.type = RUNNING;
				rc += work_execute(&tmp, verbose);

				tmp.type = DEFAULT;
				rc += work_execute(&tmp, verbose);

				tmp.type = CLASSES;
				rc += work_execute(&tmp, verbose);

				tmp.type = DEVICE;
				rc += list_iterate(
					(void **)_printer_bindings,
					(VFUNC_T)vbinding_execute,
					&tmp, verbose);

				tmp.type = CHAR_SETS;
				rc += work_execute(&tmp, verbose);


				if (work->type == FULL) {
					_processing_all = 1;
					tmp.type = ACCEPTING;
					rc += list_iterate(
					    (void **)_printer_bindings,
					    (VFUNC_T)vbinding_execute,
					    &tmp, verbose);
					if (need_local_status(_printer_bindings,
							work->binding) == 1)
						sysv_local_status("-p", "",
							verbose, sysvDesc,
							gettext(
							"can't execute \n"));

					tmp.type = STATUS;
					rc += list_iterate(
						(void **)_printer_bindings,
						(VFUNC_T)vbinding_execute,
						&tmp, verbose);
					if (need_local_status(_printer_bindings,
							work->binding) == 1)
						sysv_local_status("-o", "",
							verbose, sysvDesc,
							gettext(
							"can't execute \n"));

					tmp.type = ENTRIES;
					rc += list_iterate(
					    (void **)_printer_bindings_unique,
					    (VFUNC_T)vbinding_execute,
					    &tmp, verbose);
					_processing_all = 0;
				}

				/*
				 * Put this here to preserve same ordering
				 * as found in previous releases.
				 */
				if (work->type == FULL ||
				    work->type == SUMMARY) {

					tmp.type = FORMS;
					rc += work_execute(&tmp, verbose);
				}

			} else if ((work->type == ACCEPTING) ||
					(work->type == DEVICE)) {
				tmp.type = work->type;
				rc += list_iterate(
					(void **)_printer_bindings,
					(VFUNC_T)vbinding_execute,
					&tmp, verbose);

			} else if (work->type == USER ||
				work->type == STATUS ||
				work->type == ENTRIES ||
				work->type == RANK) {

				if (need_local_status(_printer_bindings,
						work->binding) == 1) {
					char *option = lpstat_opt(work->type);
					if ((work->type == USER) &&
						(work->user != NULL)) {
						sysv_local_status(option,
							work->user, verbose,
							sysvDesc,
							gettext(
							"can't execute \n"));
					} else {
						sysv_local_status(option, "",
							verbose, sysvDesc,
							gettext(
							"can't execute \n"));
					}
				}

				_processing_all = 1;
				tmp.type = work->type;
				if (work->type == STATUS) {
					rc += list_iterate(
					    (void **)_printer_bindings,
					    (VFUNC_T)vbinding_execute,
					    &tmp, verbose);
				} else {
					rc += list_iterate(
					    (void **)_printer_bindings_unique,
					    (VFUNC_T)vbinding_execute,
					    &tmp, verbose);
				}
				_processing_all = 0;
			} else
				rc += list_iterate(
					(void **)_printer_bindings,
					(VFUNC_T)vbinding_execute, &tmp,
					verbose);
			return (rc);
		default:
			return (rc);
		}
	} else {
		rc += work_execute(work, verbose);
	}
	return (rc);
}

static void
sysv_options(int ac, char *av[])
{
	char	**argv,
		*program;
	int	c;
	int	argc = 0;
	char	*user;

	if ((program = strrchr(av[0], '/')) == NULL)
		program = av[0];
	else
		program++;

	argv = (char **)calloc((ac + 1), sizeof (char *));

	if (argv == NULL) {
		fprintf(stderr, gettext("memory allocation failed\n"));
		exit(1);
	}
	for (argc = 0; argc < ac; argc++)
		argv[argc] = av[argc];
	argv[argc++] = "--";

	while ((c = getopt(argc, argv, "R:a:c:f:o:p:u:v:DLSdlrst")) != EOF) {
		switch (c) {	/* these may or may not have an option */
		case 'R':
		case 'a':
		case 'c':
		case 'f':
		case 'o':
		case 'p':
		case 'u':
		case 'v':
			if (optarg[0] == '-') {
				/* this check stop a possible infinite loop */
				if ((optind > 1) && (argv[optind-1][1] != c))
					optind--;
				optarg = NULL;
			} else if (strcmp(optarg, "all") == 0)
				optarg = NULL;
		}

		switch (c) {
		case 'D':
			sysvDesc++;
			break;
		case 'L':
			sysvLocal++;
			/* undocumented option that keeps it long and local */
			break;
		case 'R':
			work_list_append_list(optarg, RANK);
			break;
		case 'S':
			work_list_append_list(optarg, CHAR_SETS);
			break;
		case 'a':
			work_list_append_list(optarg, ACCEPTING);
			break;
		case 'c':
			work_list_append_list(optarg, CLASSES);
			break;
		case 'd':
			work_list_append(NULL, NULL, -1, DEFAULT);
			break;
		case 'f':
			work_list_append_list(optarg, FORMS);
			break;
		case 'l':
			sysvVerbose++;
			break;
		case 'o':
			work_list_append_list(optarg, ENTRIES);
			break;
		case 'p':
			work_list_append_list(optarg, STATUS);
			break;
		case 'r':
			work_list_append(NULL, NULL, -1, RUNNING);
			break;
		case 's':
			work_list_append(NULL, NULL, -1, SUMMARY);
			break;
		case 't':
			work_list_append(NULL, NULL, -1, FULL);
			break;
		case 'u':
			work_list_append_list(optarg, USER);
			break;
		case 'v':
			work_list_append_list(optarg, DEVICE);
			break;
		default:
			(void) fprintf(stderr,
			    gettext(
				"Usage: %s [-drtslDL] [-R [list]] [-S [list]] "
				"[-a [list]] [-c [list]] [-f [list]] "
				"[-o [list]] [-p [printer]] [-u [list]] "
				"[-v [list]] [list]\n"),
				av[0]);
			exit(1);
		}
	}
	for (argc = optind; argc < ac; argc++)		/* add requests */
		work_list_append_list(av[argc], ENTRIES);

	if ((workList == NULL) && (ac == 1)) {
		user = get_user_name();
		work_list_append(NULL, user, -1, USER);
	}
}


static void
bsd_options(int ac, char **av)
{
	char	*printer;
	int	c;

	if ((bsdv = (char **)calloc(ac, sizeof (char *))) == NULL)
		return;

	if ((printer = getenv((const char *)"PRINTER")) == NULL)
		printer = getenv((const char *)"LPDEST");
	if (printer == NULL)
		printer = NS_NAME_DEFAULT;

	while ((c = getopt(ac, av, "lP:+:")) != EOF)
		switch (c) {
		case 'l':
			bsdFormat = SHOW_QUEUE_LONG_REQUEST;
			break;
		case 'P':
			printer = optarg;
			break;
		default:
			(void) fprintf(stderr,
		gettext("Usage: %s [-P printer] [-l] [+ interval] [list]\n"),
				av[0]);
			exit(1);
		}

	work_list_append(printer, NULL, -1, BSD_QUEUE);

	while (optind < ac)
		if (av[optind][0] == '+')
			bsdInterval = atoi(&av[optind++][1]);
		else
			bsdv[bsdc++] = av[optind++];
}


int
main(int ac, char *av[])
{
	char *program;
	int rc = 0;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((program = strrchr(av[0], '/')) == NULL)
		program = av[0];
	else
		program++;

	openlog(program, LOG_PID, LOG_LPR);

	if (check_client_spool(NULL) < 0) {
		(void) fprintf(stderr, gettext("couldn't validate local spool "
			"area (%s)\n"), SPOOL_DIR);
		return (1);
	}
	(void) chdir(SPOOL_DIR);

	if (strcmp(program, "lpq") == 0)
		bsd_options(ac, av);
	else {
		sysv_options(ac, av);
	}

	rc = list_iterate((void **)workList, (VFUNC_T)vwork_list_execute,
				sysvVerbose, sysvDesc);

	if (exit_code == 0)
		exit_code = rc;

	return (exit_code);
}
