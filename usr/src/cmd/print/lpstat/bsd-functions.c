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
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif
extern char *getenv(const char *);

#include <print/ns.h>
#include <print/network.h>
#include <print/misc.h>
#include <print/list.h>
#include <print/job.h>

#include "bsd-functions.h"


static char *order[] = {
	"", "st", "nd", "rd", "th", "th", "th", "th", "th", "th", "th" };

static char *
show_rank(int i)
{
	static char rank[12];
	if ((i%100)/10 == 1)
		(void) sprintf(rank, "%dth", i);
	else
		(void) sprintf(rank, "%d%s", i, order[i%10]);
	return (rank);
}


static int
vadd_file(jobfile_t *file, va_list ap)
{
	char *mesg = va_arg(ap, char *);

	if (file != NULL) {
		(void) strlcat(mesg, file->jf_name, BUFSIZ);
		(void) strlcat(mesg, " ", BUFSIZ);
		return (file->jf_size);
	}
	return (0);
}

/*ARGSUSED*/
static int
vprint_file(jobfile_t *file, va_list ap)
{
	if (file != NULL)
		(void) printf("\t%-33.33s%ld bytes\n", file->jf_name,
			file->jf_size);
	return (0);
}

static int
vprint_job(job_t *job, va_list ap)
{
	int	jobSize = 0,
		*rank,
		format,
		curr,
		printIt = 0,
		ac;
	char	fileList[BUFSIZ],
		*printer,
		**av;

	printer = va_arg(ap, char *);
	format = va_arg(ap, int);
	rank = va_arg(ap, int *);
	ac = va_arg(ap, int);
	av = va_arg(ap, char **);

	if (strcmp(job->job_printer, printer) != 0)
		return (0);

	if (ac > 0) {
		for (curr = 0; curr < ac; curr++)
			if ((av[curr][0] >= '0') && (av[curr][0] <= '9') &&
				(job->job_id == atoi(av[curr])) ||
				(strcmp(job->job_user, av[curr]) == 0)) {
					printIt++;
					break;
			}
	} else
		printIt++;

	if (printIt != 0) {
		if (format == SHOW_QUEUE_SHORT_REQUEST) {
			(void) memset(fileList, 0, sizeof (fileList));
			jobSize = list_iterate((void **)job->job_df_list,
				(VFUNC_T)vadd_file, fileList);
			(void) printf(
				"%-7.7s%-8.8s	  %3.3d  %-38.38s%d bytes\n",
				show_rank((*rank)++), job->job_user,
				job->job_id, fileList, jobSize);
		} else {
			(void) printf("%s: %-7.7s \t\t\t\t [job %.3d%s]\n",
				job->job_user, show_rank((*rank)++),
				job->job_id, job->job_host);
			(void) list_iterate((void **)job->job_df_list,
					(VFUNC_T)vprint_file);
			(void) printf("\n");
		}
	}
	return (0);
}

static int
vjob_count(job_t *job, va_list ap)
{
	int	curr,
		ac;
	char	*printer,
		**av;

	printer = va_arg(ap, char *);
	ac = va_arg(ap, int);
	av = va_arg(ap, char **);

	if (strcmp(job->job_printer, printer) != 0)
		return (0);

	if (ac == 0)
		return (1);

	for (curr = 0; curr < ac; curr++)
		if ((av[curr][0] >= '0') && (av[curr][0] <= '9') &&
			(job->job_id == atoi(av[curr])) ||
			(strcmp(job->job_user, av[curr]) == 0))
				return (1);

	return (0);
}


void
clear_screen()	 /* for now use tput rather than link in UCB stuff */
{
	(void) system("/bin/tput clear");
}


int
bsd_queue(ns_bsd_addr_t *binding, int format, int ac, char *av[])
{
	char	*server = NULL,
		*printer = NULL;
	job_t	**list = NULL;
	int	nd = -1,
		idle = 0,
		rc;

	server = binding->server;
	printer = binding->printer;

	if ((nd = net_open(server, 15)) >= 0) {
		char buf[BUFSIZ];

		(void) memset(buf, 0, sizeof (buf));
		while (ac--) { /* potential SEGV if av's are more than BUFSIZ */
			(void) strlcat(buf, av[ac], sizeof (buf));
			if (strlcat(buf, " ", sizeof (buf)) >= sizeof (buf)) {
				syslog(LOG_ERR, "bsd_queue: buffer overflow");
			}
		}

		rc = net_printf(nd, "%c%s %s\n", format, printer, buf);
		if (rc < 0)
			syslog(LOG_ERR, "net_printf() failed: %m");
#ifdef SUNOS_4
		do {
		(void) memset(buf, 0, sizeof (buf));
		if ((ac = net_read(nd, buf, sizeof (buf))) > 0)
			(void) printf("%s", buf);
		} while (ac > 0);
#else
		while (memset(buf, 0, sizeof (buf)) &&
			(net_read(nd, buf, sizeof (buf)) > 0)) {
			(void) printf("%s", buf);
			if (strstr(buf, "no entries") != 0)
				idle = 1;
		}
#endif

		(void) net_close(nd);
	}

	if (nd < 0) {
		if (server != NULL)
			(void) fprintf(stderr, gettext(
				"could not talk to print service at %s\n"),
				server);
		else
			(void) fprintf(stderr, gettext(
				"could not locate server for printer: %s\n"),
				printer);
	}

	if (((list = job_list_append(NULL, printer,
						server, SPOOL_DIR)) != NULL) &&
	    (list_iterate((void **)list, (VFUNC_T)vjob_count, printer,
			ac, av) != 0)) {
		if ((nd < 0) && (format == SHOW_QUEUE_SHORT_REQUEST))
			(void) printf(gettext(
			"Rank\tOwner	Job\tFiles\t\t\t\t\tTotal Size\n"));
	}

	if (format == SHOW_QUEUE_LONG_REQUEST)
		(void) printf("\n");

	nd = 1;
	(void) list_iterate((void **)list, (VFUNC_T)vprint_job, printer, format,
			&nd, ac, av);

	if ((idle == 1) && (list == NULL))
		return (1);
	else
		return (0);
}
