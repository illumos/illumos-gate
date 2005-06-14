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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif

#include <print/ns.h>
#include <print/list.h>
#include <print/misc.h>
#include <print/job.h>
#include <print/network.h>

#include "parse.h"
#include "sysv-functions.h"

extern char *getenv(const char *);

static print_queue_t **_queue_list = NULL;

static int sysv_displayLocalLPSTAT(char *pname, char *aname);

#define	ALL "all"
static int
compair_user(char *full, char *user, char *host)
{
	char	*u1,
		*h1;

	if (full == NULL)
		return (0);

	if ((strcmp(full, ALL) == 0) || strcmp(full, user) == 0)
		return (0);
	if ((u1 = strchr(full, '!')) == NULL)
		return (-1);
	h1 = strcdup(full, '!');
	u1++;
	if (((strcmp(u1, ALL) == 0) || (strcmp(u1, user) == 0)) &&
	    (strcmp(h1, host) == 0)) {
		free(h1);
		return (0);
	}
	if (((strcmp(h1, ALL) == 0) || (strcmp(h1, host) == 0)) &&
	    (strcmp(u1, user) == 0)) {
		free(h1);
		return (0);
	}
	free(h1);
	return (-1);
}


static int
compair_queue_binding(print_queue_t *queue, ns_bsd_addr_t *binding)
{
	if ((queue == NULL) || (binding == NULL))
		return (-1);
	if ((strcmp(queue->binding->printer, binding->printer) == 0) &&
	    (strcmp(queue->binding->server, binding->server) == 0))
				return (0);
	return (-1);
}



static char *
get_queue_buffer(ns_bsd_addr_t *binding)
{
	char	*q = NULL,
		*p = NULL,
		*server,
		*printer;
	int	nd,
		rc,
		count = 0,
		q_size = 0,
		p_left = 0;

	server = binding->server;
	printer = binding->printer;

	if ((nd = net_open(server, 15)) < 0) {
		char err[128];

		(void) snprintf(err, sizeof (err),
			gettext("server %s not responding\n\n"),
			server);
		return (strdup(err));
	}

	rc = net_printf(nd, "%c%s \n", SHOW_QUEUE_LONG_REQUEST, printer);
	if (rc < 0)
		syslog(LOG_ERR, "net_printf() failed: %m");

	do {
		p += count;
		if ((p_left -= count) < 10) {
			char *t;

#ifdef SUNOS_4
			if (q == NULL) {
				p = q = malloc(BUFSIZ);
				(void) memset(p, NULL, BUFSIZ);
				q_size = BUFSIZ;
			} else {
				q_size += BUFSIZ;
				t = malloc(q_size);
				(void) memset(t, NULL, q_size);
				strcpy(t, q);
				free(q);
				p = t + (p - q);
				q = t;
			}
#else
			if ((t = (char *)realloc(q, q_size += BUFSIZ)) != q) {
				p = t + (p - q);
				q = t;
			}
#endif
			p_left += BUFSIZ;
			(void) memset(p, NULL, p_left);
		}
	} while ((count = net_read(nd, p, p_left)) > 0);

	(void) net_close(nd);

	return (q);
}



print_queue_t *
sysv_get_queue(ns_bsd_addr_t *binding, int local)
{
	print_queue_t *qp = NULL;
	char	*buf;

	if (_queue_list != NULL)	/* did we already get it ? */
		if ((qp = (print_queue_t *)list_locate((void **)_queue_list,
			(COMP_T)compair_queue_binding, binding)) != NULL)
			return (qp);

	if (local == 0)
		buf = (char *)get_queue_buffer(binding);
	else
		buf = strdup("no entries\n");

	if (buf != NULL) {
		qp = parse_bsd_queue(binding, buf, strlen(buf));
		_queue_list = (print_queue_t **)list_append((void **)
						_queue_list, (void *)qp);
	}
	return (qp);
}






	/*
	 *	SYSV (lpstat) specific routines
	 */

static int
vJobfile_size(jobfile_t *file)
{
	if (file != NULL)
		return (file->jf_size);
	return (0);
}


void
vsysv_queue_entry(job_t *job, va_list ap)
{
	char	id[128],
		user[128],
		*printer = va_arg(ap, char *),
		*in_user = va_arg(ap, char *);
	int	in_id = va_arg(ap, int),
		verbose = va_arg(ap, int),
		*rank = va_arg(ap, int *),
		size = 0;

	if ((in_id != -1) && (in_id != job->job_id))
		return;
	if (compair_user(in_user, job->job_user, job->job_host) != 0)
		return;

	(void) sprintf(id, "%.16s-%-5d", printer, job->job_id);
	(void) snprintf(user, sizeof (user), "%s@%s", job->job_user,
	    job->job_host);
	size = list_iterate((void **)job->job_df_list, (VFUNC_T)vJobfile_size);
	if (*rank >= 0)
		(void) printf("%d ", (*rank)++);
	(void) printf("%-*s %-*s %*d %s%s", (*rank >= 0 ? 20 : 22), id, 15,
		user, 7, size, (*rank >= 0 ? "" : "  "), short_date());
	if (verbose == 0) {
		if (*rank == 1)
			(void) printf(" on %s", printer);
			(void) printf("\n");
		} else
			(void) printf("\n\t%s %s\n",
				((*rank > 1) ? "on" : "assigned"), printer);
}


#define	OLD_LPSTAT "/usr/lib/lp/local/lpstat"		/* for -c -f -S */
#ifdef OLD_LPSTAT
static int
local_printer(char *name)
{
	char buf[128];

	(void) snprintf(buf, sizeof (buf),
			"/etc/lp/printers/%s/configuration", name);
	return (access(buf, F_OK));
}

static int
local_class(char *name)
{
	char buf[128];

	(void) snprintf(buf, sizeof (buf),
			"/etc/lp/classes/%s", name);
	return (access(buf, F_OK));
}

int
sysv_local_status(char *option, char *arg, int verbose,
		int description, char *invalid)
{
	pid_t stat;

	if (access(OLD_LPSTAT, F_OK) == 0) {
		char buf[BUFSIZ];

		/*
		 * Need the fflush to preserve output order when
		 * output re-directed to a file. Close of old lpstat
		 * flushes buffers causing old lpstat output to preceed
		 * all other output to the file.
		 */
		(void) fflush(stdout);
		(void) fflush(stderr);
		(void) snprintf(buf, sizeof (buf),
			"%s %s %s%s%s", OLD_LPSTAT, option,
			(arg ? arg : ""), (verbose ? " -l" : ""),
			(description ? " -D" : ""));
		stat = system(buf);
		if (WIFEXITED(stat)) {
			return (WEXITSTATUS(stat));
		} else {
			if (stat == -1)
				return (errno);
			else
				return (ENOMSG);
		}
	} else
		(void) printf("%s", invalid);

	return (0);
}
#endif


int
sysv_queue_state(print_queue_t *qp, char *printer, int verbose, int description)
{
#ifdef OLD_LPSTAT
	pid_t stat;

	if ((local_printer(printer) == 0) && (access(OLD_LPSTAT, F_OK) == 0)) {
		char buf[BUFSIZ];

		/* see sysv_local_status for reason for fflush */
		(void) fflush(stdout);
		(void) fflush(stderr);
		(void) snprintf(buf, sizeof (buf),
			"%s -p %s%s%s", OLD_LPSTAT, printer,
			(verbose ? " -l" : ""), (description ? " -D" : ""));
		stat = system(buf);
		if (WIFEXITED(stat)) {
			return (WEXITSTATUS(stat));
		} else {
			if (stat == -1)
				return (errno);
			else
				return (ENOMSG);
		}


	}
#endif

	(void) printf(gettext("printer %s "), printer);
	switch (qp->state) {
	case IDLE:
		(void) printf(gettext("is idle. "));
		break;
	case PRINTING:
		(void) printf(gettext("now printing %s-%d. "), printer,
			qp->jobs[0]->job_id);
		break;
	case FAULTED:
		(void) printf(gettext("faulted printing %s-%d. "), printer,
			(qp->jobs != NULL ? qp->jobs[0]->job_id : 0));
		break;
	case RAW:
		(void) printf(gettext("unknown state. "));
		break;
	default:
		(void) printf(gettext("disabled. "));
	}
	(void) printf(gettext("enabled since %s. available.\n"), long_date());
	if (qp->state == FAULTED)
		(void) printf("\t%s\n", qp->status);
	if (description != 0) {
		ns_printer_t *pobj;
		char *desc;

		if (((pobj = ns_printer_get_name(qp->binding->printer, NULL))
		    != NULL) &&
		    ((desc = ns_get_value(NS_KEY_DESCRIPTION, pobj)) != NULL))
			(void) printf(gettext("\tDescription: %s\n"), desc);
		else
			(void) printf(gettext("\tDescription: %s@%s\n"),
				qp->binding->printer, qp->binding->server);
	}
	if (verbose != 0)
		(void) printf(
			gettext("\tRemote Name: %s\n\tRemote Server: %s\n"),
			qp->binding->printer, qp->binding->server);

	return (0);
}


int
sysv_accept(ns_bsd_addr_t *binding)
{
#ifdef OLD_LPSTAT
	int result = 0;

	if (((local_printer(binding->printer) == 0) ||
			(local_class(binding->printer) == 0)) &&
			(access(OLD_LPSTAT, F_OK) == 0)) {
		/*
		 * Locally attached printer, so display its accept state using
		 * the old lpstat utility.
		 */
		result = sysv_displayLocalLPSTAT(binding->printer,
							binding->pname);
		return (result);
	}
#endif


	if (binding->pname != NULL)
		(void) printf(gettext("%s accepting requests since %s\n"),
			binding->pname, long_date());
	else
		(void) printf(gettext("%s accepting requests since %s\n"),
			binding->printer, long_date());

	return (0);
}



#ifdef OLD_LPSTAT
/*
 * FUNCTION:    sysv_displayLocalLPSTAT()
 *
 * DESCRIPTION: This function uses the old lpstat (/usr/lib/lp/local/lpstat)
 *              utility to display the accepting state (-a option) for locally
 *              attached printers.
 *              If an alias name is given then the output from lpstat is
 *              captured and modified to show the alias name instead of the
 *              printer's real name. Note: this is done because the old lpstat
 *              can not handle alias names.
 *
 * PARAMETERS:
 * Input:       char *pname - printers real name
 *              char *aname - printers alias name
 *
 * RETURNS:     0 = completed okay, otherwise error
 *
 */

static int
sysv_displayLocalLPSTAT(char *pname, char *aname)

{
	int result = ENOMSG;
	char buf[BUFSIZ];
	FILE *fd = NULL;
	char *tmp = NULL;

	/* see sysv_local_status for reason for fflush */
	(void) fflush(stdout);
	(void) fflush(stderr);

	if (((pname != NULL) && (aname != NULL)) &&
	    (strcmp(pname, aname) != 0))
	{
		/*
		 * This is a request to display status of an aliased local
		 * printer, so capture the output from the local lpstat for the
		 * real printer and then display that output with the alias
		 * name instead of the real name.
		 */

		(void) snprintf(buf, sizeof (buf), "%s -a %s",
				OLD_LPSTAT, pname);

		/* execute the local lpstat utility and display output */

		fd = popen(buf, "r");
		if (fd != NULL)
		{
			tmp = fgets(buf, sizeof (buf), fd);
			if (tmp != NULL)
			{
				result = 0;

				if (strncmp(buf, pname, strlen(pname)) == 0)
				{
					printf("%s", aname);
					printf("%s", &(buf[strlen(pname)]));

					tmp = fgets(buf, sizeof (buf), fd);
				}

				/*
				 * finish reading and displaying the
				 * output from the lpstat utility
				 */

				while (tmp != NULL)
				{
					printf("%s", buf);
					tmp = fgets(buf, sizeof (buf), fd);
				}
			}

			(void) pclose(fd);
		}
	}

	else
	if (pname != NULL)
	{
		/*
		 * Not an alias so directly display output from the
		 * local lpstat utility
		 */
		(void) snprintf(buf, sizeof (buf), "%s -a %s",
				OLD_LPSTAT, pname);
		result = system(buf);

		if (WIFEXITED(result))
		{
			result = WEXITSTATUS(result);
		}
		else
		if (result == -1)
		{
			result = errno;
		}
		else
		{
			result = ENOMSG;
		}
	}

	return (result);
} /* sysv_displayLocalLPSTAT */
#endif



int
sysv_system(ns_bsd_addr_t *binding)
{
	char *host;
	char *printer;
	pid_t stat;

	if (binding->pname)
		printer = binding->pname;
	else
		printer = binding->printer;
	host = binding->server;
#ifdef OLD_LPSTAT

	if ((local_printer(printer) == 0) && (access(OLD_LPSTAT, F_OK) == 0)) {
		char buf[BUFSIZ];

		/* see sysv_local_status for reason for fflush */
		(void) fflush(stdout);
		(void) fflush(stderr);
		(void) snprintf(buf, sizeof (buf),
				"%s -v %s", OLD_LPSTAT, printer);
		stat = system(buf);

		if (WIFEXITED(stat)) {
			return (WEXITSTATUS(stat));
		} else {
			if (stat == -1)
				return (errno);
			else
				return (ENOMSG);
		}
	} else
#endif
	if (printer && host) {
		if (strcmp(printer, binding->printer) == 0)
			(void) printf(gettext("system for %s: %s\n"), printer,
				host);
		else
			(void) printf(
				gettext("system for %s: %s (as printer %s)\n"),
				printer, host, binding->printer);
	}

	return (0);
}


void
sysv_running()
{
	int lock;
	struct stat st;

	lock = stat("/usr/spool/lp/SCHEDLOCK", &st);
	if (lock < 0)
		(void) printf(gettext("scheduler is not running\n"));
	else
		(void) printf(gettext("scheduler is running\n"));
}


void
sysv_default()
{
	char *printer;

	if ((printer = getenv((const char *)"LPDEST")) == NULL)
		printer = getenv((const char *)"PRINTER");
	if (printer == NULL) {
		ns_printer_t *p;

		if ((p = ns_printer_get_name(NS_NAME_DEFAULT, NULL)) != NULL) {
			printer = ns_get_value(NS_KEY_USE, p);
			/*
			 * Fall back to the printer name out of
			 * the "bsdaddr" attribute
			 */
			if (printer == NULL) {
				ns_bsd_addr_t *a =
				    ns_get_value(NS_KEY_BSDADDR, p);
				if ((a != NULL) && (a->printer != NULL)) {
					static char buf[64];
					(void) snprintf(buf, sizeof (buf), "%s",
						a->printer);
					printer = buf;
				}
			}
		}
	}
	if (printer != NULL)
		(void) printf(gettext("system default destination: %s\n"),
			printer);
	else
		(void) printf(gettext("no system default destination\n"));
}
