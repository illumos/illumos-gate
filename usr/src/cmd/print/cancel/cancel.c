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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <locale.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif

#include <print/ns.h>
#include <print/network.h>
#include <print/misc.h>
#include <print/list.h>
#include <print/job.h>

#include <cancel_list.h>

extern char *optarg;
extern int optind, opterr, optopt, exit_code = 0;
extern char *getenv(const char *);

static int all = 0;	/* global for canceling everything */



static char *
vappend_list(void ** list)
{
	int current = 0;
	char *  string;
	int stringlen;
	int listlen;
	int strsize = BUFSIZ;


	string = malloc(strsize);
	(void) memset(string, NULL, sizeof (string));

	if (list != NULL) {
		while (list[current] != NULL) {
			stringlen = strlen(string);
			listlen = strlen(list[current]);
			if (strsize < (stringlen + listlen + 2)) {
				strsize = stringlen + listlen + 2;
				string = realloc(string, strsize);
			}

			(void) strcat(string, " ");
			(void) strcat(string, list[current]);
			current++;
		}
	}

	return (string);
}


/*
 *  vcancel_local() attempts to cancel all locally spooled jobs that are
 *	are associated with a cancel_req_t structure.  This function is
 *	intended to be called by list_iterate().
 */
static int
vcancel_local(cancel_req_t *entry, va_list ap)
{
	char	*user = va_arg(ap, char *);
	job_t	**list = NULL;

	list = job_list_append(list, entry->binding->printer,
				entry->binding->server, SPOOL_DIR);
	return (list_iterate((void **)list, (VFUNC_T)vjob_cancel, user,
			entry->binding->printer, entry->binding->server,
			entry->list));
}


/*
 *  vcancel_remote() attempts to send a cancel request to a print server
 *	for any jobs that might be associated with the cancel_req_t structure
 *	passed in.  This function is intended to be called by list_iterate().
 */
static int
vcancel_remote(cancel_req_t *entry, va_list ap)
{
	char	buf[BUFSIZ],
		*user = va_arg(ap, char *),
		*printer = entry->binding->printer,
		*server = entry->binding->server;
	int	nd,
		rc;
	char * string;

	if ((nd = net_open(server, 15)) < 0) {
		(void) fprintf(stderr,
			gettext("could not talk to print service at %s\n"),
			server);
		return (-1);
	}

	(void) memset(buf, NULL, sizeof (buf));

	if (strcmp(user, "-all") != 0)
		string = vappend_list((void *)entry->list);

	syslog(LOG_DEBUG, "vcancel_remote(): %s %s%s", printer, user, string);
	rc = net_printf(nd, "%c%s %s%s\n", REMOVE_REQUEST, printer, user,
		string);
	if (rc < 0)
		syslog(LOG_ERR, "net_printf() failed: %m");

	while (memset(buf, NULL, sizeof (buf)) &&
		(net_read(nd, buf, sizeof (buf)) > 0))
		(void) printf("%s", buf);

	(void) net_close(nd);
	return (0);
}


/*
 *  vsysv_printer() adds an entry to the cancel list with the items supplied.
 */
static void
vsysv_printer(char *printer, va_list ap)
{
	cancel_req_t ***list = va_arg(ap, cancel_req_t ***);
	char	**items = va_arg(ap, char **);

	*list = cancel_list_add_list(*list, printer, items);
}

/*
 *  vsysv_binding() adds an entry to the cancel list with the items supplied.
 */
static void
vsysv_binding(ns_bsd_addr_t *binding, va_list ap)
{
	cancel_req_t ***list = va_arg(ap, cancel_req_t ***);
	char	**items = va_arg(ap, char **);

	*list = cancel_list_add_binding_list(*list, binding, items);
}

/*
 *  sysv_remove() parses the command line arguments as defined for cancel
 *	and builds a list of cancel_req_t structures to return
 */
static cancel_req_t **
sysv_remove(int ac, char **av)
{
	char	*printer,
		**printers = NULL,
		**items = NULL;
	int	c;
	int	user = 0;
	cancel_req_t **list = NULL;

	if (ac == 1) {
		(void) fprintf(stderr,
			gettext("printer, request-id, and/or user required\n"));
		exit(-1);
	}

	if ((printer = getenv((const char *)"LPDEST")) == NULL)
		printer = getenv((const char *)"PRINTER");
	if (printer == NULL)
		printer = NS_NAME_DEFAULT;

	while ((c = getopt(ac, av, "u")) != EOF)
		switch (c) {
		case 'u':
			user++;
			break;
		default:
			(void) fprintf(stderr,
			"Usage:\t%s [-u user-list] [printer-list]\n", av[0]);
			(void) fprintf(stderr,
				"\t%s [request-list] [printer-list]\n", av[0]);
			exit(-1);
		}

	ac--;
	while (optind <= ac) {				/* pull printers off */
		char	*p,
			*q;

		if (((p = strrchr(av[ac], ':')) != NULL) &&
		    ((q = strrchr(p, '-')) != NULL)) {
			int req = 0;
			while (*++q != NULL)
				if (isdigit(*q) == 0)
					req++;
			if (req == 0)
				break;
		}
		if ((ns_bsd_addr_get_name(av[ac])) != NULL) {
			printers = (char **)list_append((void **)printers,
							(void *)av[ac]);
		} else
			break;
		ac--;
	}

	while (optind <= ac) {				/* get reqs or users */
		if (user != 0) {	/* list o users */
			items = (char **)list_append((void **)items,
							(void *)av[ac]);
		} else {		/* list o jobs */
			char *p;

			if ((p = strrchr(av[ac], '-')) != NULL) { /* job-id */
				*(p++) = NULL;
				if (*p == NULL) {
					(void) fprintf(stderr,
					gettext("invalid job id: %s-\n"),
						av[ac]);
					exit(-1);
				}
				list = cancel_list_add_item(list, av[ac], p);
			} else {			/* just a number */
				list = cancel_list_add_item(list, av[ac], NULL);
			}
		}
		ac--;
	}

	if ((printers == NULL) && (items != NULL)) { /* handle "all" printers */
		ns_bsd_addr_t **addrs = NULL;

		if ((addrs = ns_bsd_addr_get_all(UNIQUE)) != NULL)
			(void) list_iterate((void **)addrs,
					(VFUNC_T)vsysv_binding, &list, items);
	}

	if ((list == NULL) && (items == NULL))
		items = (char **)list_append((void **)items, NULL);

	(void) list_iterate((void **)printers, (VFUNC_T)vsysv_printer,
			&list, items);

	return (list);
}


/*
 *  bsd_remove() parses the command line arguments as defined for lprm
 *	and builds a list of cancel_req_t structures to return
 */
static cancel_req_t **
bsd_remove(int ac, char **av)
{
	char	*printer;
	int	c;
	cancel_req_t **list = NULL;

	if ((printer = getenv((const char *)"PRINTER")) == NULL)
		printer = getenv((const char *)"LPDEST");
	if (printer == NULL)
		printer = NS_NAME_DEFAULT;

	while ((c = getopt(ac, av, "P:-")) != EOF)
		switch (c) {
		case 'P':
			printer = optarg;
			break;
		default:
			(void) fprintf(stderr,
		gettext("Usage: %s [-P printer] [-] [job # ...] [username ...]\n"),
				av[0]);
			exit(-1);
		}

	while (optind < ac)
		if (strcmp(av[optind++], "-") == 0) {
			if (getuid() == 0) {
				all = 1;
				list = cancel_list_add_item(list, printer,
							"-all");
			} else {
				list = cancel_list_add_item(list, printer,
							get_user_name());
			}
		} else {
			list = cancel_list_add_item(list, printer,
							av[optind-1]);
		}

	if (list == NULL)
		list = cancel_list_add_item(list, printer, NULL);

	return (list);
}


/*
 *  main() calls the appropriate routine to parse the command line arguments
 *	and then calls the local remove routine, followed by the remote remove
 *	routine to remove jobs.
 */
int
main(int ac, char *av[])
{
	int rc = 0;
	char *program;
	cancel_req_t **list = NULL;

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
		(void) fprintf(stderr,
			gettext("couldn't validate local spool area (%s)\n"),
			    SPOOL_DIR);
		return (-1);
	}

	if (strcmp(program, "lprm") == 0)
		list = bsd_remove(ac, av);
	else
		list = sysv_remove(ac, av);

	(void) chdir(SPOOL_DIR);
	if (list_iterate((void **)list, (VFUNC_T)vcancel_local,
			get_user_name()) != 0)
		start_daemon(1);

	rc = list_iterate((void **)list, (VFUNC_T)vcancel_remote,
				((all == 0) ? get_user_name() : "-all"));

	if (exit_code == 0)
		exit_code = rc;

	return (exit_code);
}
