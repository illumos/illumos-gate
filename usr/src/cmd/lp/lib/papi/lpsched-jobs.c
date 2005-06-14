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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <pwd.h>

/* lpsched include files */
#include "lp.h"
#include "requests.h"
#include "printers.h"

#include <papi_impl.h>

papi_status_t
job_attributes_to_lpsched_request(papi_service_t svc, REQUEST *r,
		papi_attribute_t **attributes)
{
	papi_attribute_t *attr;
	int i;
	char *s;

	char **options = NULL;
	char **modes = NULL;
	char *class = NULL;
	char *job_name = NULL;

	char pr_filter = 0;
	char *pr_title = NULL;
	int pr_width = -1;
	int pr_indent = -1;
	int numberUp = 0;
	int orientation = 0;
	int lowerPage = 0;
	int upperPage = 0;
	papi_status_t getResult = 0;
	char buf[256];
	void *iterator = NULL;

	char banner = 0;

	if (attributes == NULL)
		return (PAPI_BAD_ARGUMENT);

	papiAttributeListGetString(attributes, NULL, "job-printer",
				&r->destination);

	i = r->copies;
	papiAttributeListGetInteger(attributes, NULL, "copies", &i);
	if (i <= 0)
		i = 1;
	r->copies = i;

	if (papiAttributeListGetInteger(attributes, NULL, "priority", &i)
			== PAPI_OK) {
		if ((i < 1) || (i > 100))
			i = 50;
		i = (i + 1) / 2.5;
		r->priority = i;
	}

	if ((r->priority < 0) || (r->priority > 39))
		r->priority = 20;

	/*
	 * 'media' size should be processed both in the lpsched filter and
	 * the foomatic filter (if present) so that we ensure the result of
	 * other options like 'page-ranges' are consistent.
	 */
/*
 * TODO - I thing we should really have this but I can't get it to filter
 *        so its commented out for now (paulcun)
 *	papiAttributeListGetString(attributes, NULL, "media", &r->form);
 */

#ifndef LP_USE_PAPI_ATTR
	papiAttributeListGetString(attributes, NULL, "page-ranges", &r->pages);
#else
	getResult =
	    papiAttributeListGetRange(attributes, &iterator,
		"page-ranges", &lowerPage, &upperPage);
	while (getResult == PAPI_OK) {
		if (r->pages == NULL) {
			snprintf(buf, sizeof (buf),
				"%d-%d", lowerPage, upperPage);
			r->pages = (char *)strdup(buf);
		}
		else
		{
			snprintf(buf, sizeof (buf), "%s,%d-%d",
				r->pages, lowerPage, upperPage);
			free(r->pages);
			r->pages = (char *)strdup(buf);
		}
		/*
		 * get the next value; note the attribute 'name' is set to
		 * NULL to do this.
		 */
		getResult =
		    papiAttributeListGetRange(attributes, &iterator,
			"page-ranges", &lowerPage, &upperPage);
	}
#endif


	s = NULL;
	papiAttributeListGetString(attributes, NULL, "document-format", &s);
	if (s != NULL)
		r->input_type = strdup(mime_type_to_lp_type(s));

	/*
	 * If we don't have an owner, set one.
	 */
	if (r->user == NULL) {
		uid_t uid = getuid();
		struct passwd *pw;
		char *user = "intruder";
		char *host = NULL;
		char buf[256];

		if ((pw = getpwuid(uid)) != NULL)
			user = pw->pw_name; /* default to the process owner */

		if ((uid == 0) || (uid == 71)) { /* root/lp can forge this */
			papiAttributeListGetString(attributes, NULL,
					"job-host", &host);
			papiAttributeListGetString(attributes, NULL,
					"job-originating-user-name", &user);
			papiAttributeListGetString(attributes, NULL,
					"requesting-user-name", &user);

			snprintf(buf, sizeof (buf), "%s%s%s", user,
					(host ? "@" : ""), (host ? host : ""));
			user = buf;
		}

		r->user = strdup(user);
	}

	s = NULL;
	papiAttributeListGetString(attributes, NULL, "job-hold-until", &s);
	if (s != NULL) {
		if (strcmp(s, "immediate") == 0)
			r->actions |= ACT_IMMEDIATE;
		else if ((strcmp(s, "resume") == 0) ||
			    (strcmp(s, "no-hold") == 0))
			r->actions |= ACT_RESUME;
		else if ((strcmp(s, "hold") == 0) ||
			    (strcmp(s, "indefinite") == 0))
			r->actions |= ACT_HOLD;
	}

	papiAttributeListGetString(attributes, NULL, "lp-charset", &r->charset);

	/* legacy pr(1) filter related garbage "lpr -p" */
	papiAttributeListGetBoolean(attributes, NULL, "pr-filter", &pr_filter);
	papiAttributeListGetString(attributes, NULL, "pr-title", &pr_title);
	papiAttributeListGetInteger(attributes, NULL, "pr-width", &pr_width);
	papiAttributeListGetInteger(attributes, NULL, "pr-indent", &pr_indent);

	if (pr_filter != 0) {
		char buf[128];

		if (pr_title != NULL) {
			snprintf(buf, sizeof (buf), "prtitle='%s'", pr_title);
			appendlist(&modes, buf);
		}

		if (pr_width > 0) {
			snprintf(buf, sizeof (buf), "prwidth=%d", pr_width);
			appendlist(&modes, buf);
		}

		if (pr_indent > 0) {
			snprintf(buf, sizeof (buf), "indent=%d", pr_indent);
			appendlist(&modes, buf);
		}
	} else if ((pr_title != NULL) || (pr_width >= 0) || (pr_indent >= 0))
		detailed_error(svc, gettext(
	"pr(1) filter options specified without enabling pr(1) filter"));

	/* add burst page information */
	papiAttributeListGetBoolean(attributes, NULL, "job-sheets", &banner);
	papiAttributeListGetString(attributes, NULL, "job-class", &class);
	papiAttributeListGetString(attributes, NULL, "job-name", &job_name);

	{
		char buf[128];
		/* burst page is enabled by default, add the title */
		snprintf(buf, sizeof (buf), "%s%s%s",
			(job_name ? job_name : ""),
			(job_name && class ? "\\n#####\\n#####\\t\\t " : ""),
			(class ? class : ""));
		if (buf[0] != '\0') {
			if (r->title != NULL)
				free(r->title);
			r->title = strdup(buf);
		}
	}
	if (banner == 0) /* burst page is disabled via lp "option" */
		appendlist(&options, "nobanner");

	/* add "lp -o" options */
	attr = papiAttributeListFind(attributes, "lp-options");
	if ((attr != NULL) && (attr->type == PAPI_STRING) &&
	    (attr->values != NULL)) {
		int i;

		for (i = 0; attr->values[i] != NULL; i++)
			appendlist(&options, attr->values[i]->string);
	}

	if (options != NULL) {
		if (r->options != NULL)
			free(r->options);
		r->options = sprintlist(options);
		freelist(options);
	}

	/* Convert attribute "number-up" to mode group=n */
	papiAttributeListGetInteger(attributes, NULL, "number-up", &numberUp);
	if ((numberUp >= 2) && ((numberUp % 2) == 0)) {
		snprintf(buf, sizeof (buf), "group=%d", numberUp);
		appendlist(&modes, buf);
	}

	/*
	 * Convert attribute "orientation-requested" to modes
	 * 'landscape', 'portrait', etc.
	 */
	papiAttributeListGetInteger(attributes, NULL,
				    "orientation-requested", &orientation);
	if ((orientation >= 3) && (orientation <= 6)) {
		switch (orientation) {
			case 3:
			{
				/* 3 = portrait */
				appendlist(&modes, "portrait");
				break;
			}

			case 4:
			{
				/* 4 = landscape */
				appendlist(&modes, "landscape");
				break;
			}

			case 5:
			{
				/*
				 * 5 = reverse-landscape - not supported in
				 *    lpsched so just use 'landscape' for now
				 */
				appendlist(&modes, "landscape");
				break;
			}

			case 6:
			{
				/*
				 * 6 = reverse-portrait not supported in
				 *    lpsched so just use 'portrait' for now
				 */
				appendlist(&modes, "portrait");
				break;
			}

			default:
			{
				appendlist(&modes, "portrait");
				break;
			}
		}
	}

	/* add "lp -y" modes */
	attr = papiAttributeListFind(attributes, "lp-modes");
	if ((attr != NULL) && (attr->type == PAPI_STRING) &&
	    (attr->values != NULL)) {
		int i;

		for (i = 0; attr->values[i] != NULL; i++)
			appendlist(&modes, attr->values[i]->string);
	}

	if (modes != NULL) {
		if (r->modes == NULL)
			free(r->modes);
		r->modes = sprintlist(modes);
		freelist(modes);
	}

	return (PAPI_OK);
}

/*
 * Convert REQUEST->outcome (or R_REQUEST_* state) to the equivalent
 * PAPI attribute representation.
 */
static void
lpsched_request_outcome_to_attributes(papi_attribute_t ***attributes,
		unsigned short state)
{
	if (attributes == NULL)
		return;

	if (state & (RS_HELD|RS_ADMINHELD)) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-state", 0x04);	/* held */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"job-state-reasons", "job-hold-until-specified");
	} else if (state & RS_ACTIVE) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-state", 0x05);
		if (state & RS_FILTERING)
			papiAttributeListAddString(attributes,
				PAPI_ATTR_REPLACE,
				"job-state-reasons", "job-transforming");
		else if (state & RS_PRINTING)
			papiAttributeListAddString(attributes,
				PAPI_ATTR_REPLACE,
				"job-state-reasons", "job-printing");
		else
			papiAttributeListAddString(attributes,
				PAPI_ATTR_REPLACE,
				"job-state-reasons", "job-processing");
	} else if (state & RS_CANCELLED) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-state", 0x07);
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"job-state-reasons", "job-canceled-by-user");
	} else if (state & RS_PRINTED) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-state", 0x09);
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"job-state-reasons", "job-complete");
	} else {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-state", 0x03);
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"job-state-reasons", "job-queued");
	}
	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
				"job-hold-until",
		((state & RS_HELD) ? "indefinite" : "no-hold"));
}

/*
 * Convert REQUEST structure to the equivalent PAPI attribute representation.
 */
void
lpsched_request_to_job_attributes(REQUEST *r, job_t *j)
{
	char *tmp;
	int i;

	/* copies */
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
				"copies", r->copies);

	/* destination */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "printer-name",
				r->destination);

	/* file_list */
	addLPStrings(&j->attributes, PAPI_ATTR_REPLACE,
				"lpsched-files", r->file_list);

	/* form */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "media", r->form);

	/* actions */
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
					"lpsched-actions", r->actions);

	/* alert */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "lp-alert", r->alert);

	/* options */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE,
					"lp-options", r->options);

	tmp = (((r->options != NULL) && (strstr(r->options, "nobanner")
		!= NULL)) ? "none" : "standard");
	papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
				"job-sheets", tmp);

	tmp = (((r->options != NULL) && (strstr(r->options, "duplex")
		!= NULL)) ? "two-sized" : "one-sided");
	papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
				"sides", tmp);

	i = (((r->options != NULL) && (strstr(r->options, "landscape")
		!= NULL)) ? 4 : 3);
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
				"orientation-requested", i);

	/* priority (map 0-39 to 1-100) */
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
				"job-priority", (int)((r->priority + 1) * 2.5));

	/* pages */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "page-ranges", r->pages);

	/* charset */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "lp-charset",
				r->charset);

	/* modes */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "lp-modes", r->modes);

	/* title */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE, "job-name", r->title);

	/* input_type */

	/* user */
	addLPString(&j->attributes, PAPI_ATTR_REPLACE,
				"job-originating-user-name", r->user);

	/* outcome */
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
				"lpsched-outcome", r->outcome);
	lpsched_request_outcome_to_attributes(&j->attributes, r->outcome);

	/* version */
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
				"lpsched-version", r->version);

	/* constants, (should be derived from options) */
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
				"number-up", 1);

	papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
				"multiple-document-handling",
				"seperate-documents-collated-copies");
}

/*
 * Convert R_REQUEST_* results to the equivalent PAPI attribute representation.
 */
void
job_status_to_attributes(job_t *job, char *req_id, char *user, size_t size,
		time_t date, short state, char *destination, char *form,
		char *charset, short rank, char *file)
{
	char buf[BUFSIZ];
	char *p;

	addLPString(&job->attributes, PAPI_ATTR_REPLACE,
				"job-originating-user-name", user);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"job-k-octets", size/1024);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"job-octets", size);
	if ((p = strrchr(req_id, '-')) != NULL) {
		papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"job-id", atoi(++p));
	}
	snprintf(buf, sizeof (buf), "lpsched://%s/%d", destination, atoi(p));
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
				"job-uri", buf);
	snprintf(buf, sizeof (buf), "lpsched://%s", destination);
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
				"job-printer-uri", buf);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"job-printer-up-time", time(NULL));
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
				"output-device-assigned", destination);
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
				"printer-name", destination);
	addLPString(&job->attributes, PAPI_ATTR_REPLACE, "media", form);

	lpsched_request_outcome_to_attributes(&job->attributes, state);

	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"time-at-creation", date);
	addLPString(&job->attributes, PAPI_ATTR_REPLACE,
				"lpsched-request-id", req_id);
	addLPString(&job->attributes, PAPI_ATTR_REPLACE,
				"lp-charset", charset);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"lpsched-job-state", state);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
				"number-of-intervening-jobs", rank - 1);
	addLPString(&job->attributes, PAPI_ATTR_REPLACE,
				"lpsched-file", file);
	addLPString(&job->attributes, PAPI_ATTR_EXCL,
				"job-name", file);
}

void
lpsched_read_job_configuration(service_t *svc, job_t *j, char *file)
{
	REQUEST *r;

	if ((r = getrequest(file)) == NULL) {
		detailed_error(svc, gettext("unable to read job data: %s"),
			file);
		return;
	}

	lpsched_request_to_job_attributes(r, j);
}
