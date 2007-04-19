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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include "netpr.h"
#include "netdebug.h"

static int job_primitive(np_bsdjob_t *, char, char *);
static int create_cfA_file(np_bsdjob_t *);
static char *create_cfname(np_bsdjob_t *);
static char *create_dfname(np_bsdjob_t *);
extern char data_file_type;

np_bsdjob_t *
create_bsd_job(np_job_t *injob, int pr_order, int filesize)
{

	np_bsdjob_t *job;
	char *id;
	int x;
	np_data_t *jobdata;

	if ((injob->request_id == NULL) || (injob->username == NULL) ||
	    (injob->dest == NULL) || (injob->printer ==  NULL)) {
		return (NULL);
	}

	job = (np_bsdjob_t *)malloc(sizeof (np_bsdjob_t));
	ASSERT(job, MALLOC_ERR);
	(void) memset(job, 0, sizeof (np_bsdjob_t));
	job->np_printer = "auto";	/* default "queue" */
	/*
	 * request-id comes in as printer-number
	 * pull apart to create number
	 */
	if ((id = strrchr(injob->request_id, (int)'-')) == NULL) {
		(void) fprintf(stderr,
		gettext("Netpr: request_id in unknown format:<%s>\n"),
			injob->request_id);
		syslog(LOG_DEBUG, "request id in unknown format: %s",
			injob->request_id);
		return (NULL);
	}

	id++;

	/*
	 * 4261563 - A ID collides with an existing one, it plus
	 * 1,000 with the ID causes breaking
	 * Max job id for bsd is 999.
	 */
	job->np_request_id = malloc(4);
	ASSERT(job->np_request_id, MALLOC_ERR);
	errno = 0;
	x = atoi(id);
	if ((errno != 0) || (x < 0)) {
		x = 0;
	}
	(void) snprintf(job->np_request_id, (size_t)4,
	    "%.3d", x % 1000);

	/* seperate the user/host from host!user or user@host */
	if ((id = strchr(injob->username, '@')) != NULL) {
		*id++ = '\0';
		job->np_username = strdup(injob->username);
		job->np_host = strdup(id);
		*--id = '@';
	} else if ((id = strrchr(injob->username, '!')) != NULL) {
		*id++ = '\0';
		job->np_username = strdup(id);
		job->np_host = strdup(injob->username);
		*--id = '!';
	} else {
		syslog(LOG_DEBUG, "using localhost for user %s",
			injob->username);
		job->np_username = strdup(injob->username);
		job->np_host = strdup("localhost");
	}

	job->np_printer = injob->printer;
	job->np_filename = injob->filename;

	job->np_df_letter = 'A';

	/* build cfAfilename: (cfA)(np_request_id)(np_host) */
	if ((job->np_cfAfilename = create_cfname(job)) == NULL) {
		(void) fprintf(stderr,
			gettext("Netpr: System error creating cfAfilename\n"));
			syslog(LOG_DEBUG, "System error creating cfAfilename");
		return (NULL);
	}

	job->np_timeout = injob->timeout;
	job->np_banner = injob->banner;
	job->np_print_order = pr_order;

	if (injob->title == NULL)
		job->np_title = injob->filename;
	else
		job->np_title = injob->title;

	if ((create_cfA_file(job)) == -1) {
		(void) fprintf(stderr,
		gettext("Netpr: Cannot create bsd control file\n"));
		syslog(LOG_DEBUG, "Cannot create bsd control file");
		return (NULL);
	}

	/* Now we have a title, add to the control file */
	if (injob->banner == BANNER) {
		(void) job_primitive(job, 'C', job->np_host);
		(void) job_primitive(job, 'J', job->np_title);
		(void) job_primitive(job, 'L', job->np_username);
	}


	/* create dfname for this file */

	/* allocate the jobdata and initialize what we have so far */
	jobdata = malloc(sizeof (np_data_t));
	ASSERT(jobdata, MALLOC_ERR);
	(void) memset(jobdata, 0, sizeof (np_data_t));

	jobdata->np_path_file = malloc(strlen(job->np_filename) + 1);
	ASSERT(jobdata->np_path_file, MALLOC_ERR);
	(void) strcpy(jobdata->np_path_file, job->np_filename);

	jobdata->np_data_size = filesize;

	if ((jobdata->np_dfAfilename = create_dfname(job)) == NULL) {
		return (NULL);
	}

	/*
	 * data_file_type should contain the RFC-1179 control file message
	 * type for the control file.  The is is set via the "-f" option
	 * to netpr, which get it from the "destination-full-control-file-type"
	 * option passed in.  Normally this will be either 'l' or 'f'.
	 */
	if (data_file_type != 0) {
		(void) job_primitive(job, data_file_type,
				jobdata->np_dfAfilename);
		(void) job_primitive(job, 'U', jobdata->np_dfAfilename);
		(void) job_primitive(job, 'N', "print-data");
	}

	syslog(LOG_DEBUG, "data file info: %s", job->np_cfAfile);

	/*
	 * attach np_data to bsdjob
	 */
	job->np_data = jobdata;

	return (job);
}


/*
 * Create df<x>name for this file
 * df<X><nnn><hostname>
 */
static char *
create_dfname(np_bsdjob_t *job)
{
	char *dfname;

	if (job == NULL)
		return (NULL);

	/* Trying to print too many files */
	if (job->np_df_letter > 'z') {
		errno = ENFILE;
		return (NULL);
	}

	dfname = (char *)malloc(strlen(job->np_host) + 3 + 3 + 1);
	ASSERT(dfname, MALLOC_ERR);
	(void) memset(dfname, 0, strlen(job->np_host) + 3 + 3 + 1);
	(void) sprintf(dfname, "%s%c%s%s", "df", job->np_df_letter,
	    job->np_request_id, job->np_host);

	/* udate np_df_letter for the next caller */
	job->np_df_letter += 1;
	if ((job->np_df_letter > 'Z') && (job->np_df_letter < 'a'))
		job->np_df_letter = 'a';

	return (dfname);
}

static char *
create_cfname(np_bsdjob_t *job)
{
	char *cfname;

	if (job == NULL)
		return (NULL);

	cfname = (char *)malloc(strlen(job->np_host) + 3 + 3 + 1);
	ASSERT(cfname, MALLOC_ERR);
	(void) memset(cfname, 0, strlen(job->np_host) + 3 + 3 + 1);
	(void) sprintf(cfname, "%s%s%s", "cfA",
	job->np_request_id, job->np_host);
	return (cfname);
}

static int
create_cfA_file(np_bsdjob_t *job)
{
	/*
	 * Read through job structure, creating entries
	 * in control file as appropriate
	 */
	if ((job->np_host == NULL) || (job->np_username == NULL)) {
		(void) fprintf(stderr, gettext(
		"Netpr: Missing required data, cannot build control file\n"));
		return (-1);
	}
	(void) job_primitive(job, 'H', job->np_host);
	(void) job_primitive(job, 'P', job->np_username);

	return (0);
}

static int
job_primitive(np_bsdjob_t *job, char option, char *value)
{
	char buf[BUFSIZ];

	if ((job == NULL) || (value == NULL))
		return (-1);

	job->np_cfAfilesize += strlen(value) + 2; /* (opt)(value)\n */
	if (job->np_cfAfile == NULL) {
		/* Always allocate one greater than cfAfilesize for the \0 */
		job->np_cfAfile = calloc(1, job->np_cfAfilesize + 1);
		ASSERT(job->np_cfAfile, MALLOC_ERR);
	} else {
		job->np_cfAfile = realloc(job->np_cfAfile,
			job->np_cfAfilesize + 1);
		ASSERT(job->np_cfAfile, REALLOC_ERR);
	}
	(void) snprintf(buf, sizeof (buf),  "%c%s\n", option, value);
	(void) strcat(job->np_cfAfile, buf);
	syslog(LOG_DEBUG, "adding: %d %s", job->np_cfAfilesize, buf);

	return (0);
}
