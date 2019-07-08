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
	papi_status_t status = PAPI_OK;
	papi_attribute_t *attr;
	papi_attribute_t **unmapped = NULL;
	papi_attribute_t *tmp[2];
	int i;
	char *s;

	char **options = NULL;
	char **modes = NULL;

	char pr_filter = 0;
	char *pr_title = NULL;
	int pr_width = -1;
	int pr_indent = -1;
	int numberUp = 0;
	int orientation = 0;
	int lower = 0;
	int upper = 0;
	char buf[256];
	void *iterator = NULL;
	char *mapped_keys[] = { "copies", "document-format", "form",
			"job-class", "job-hold-until", "job-host", "job-name",
			"job-originating-user-name", "job-printer",
			"job-sheets", "lp-charset", "lp-modes", "number-up",
			"orienttation-requested", "page-ranges", "pr-filter",
			"pr-indent", "pr-title", "pr-width", "job-priority",
			"requesting-user-name", "job-originating-host-name",
			NULL };

	if (attributes == NULL)
		return (PAPI_BAD_ARGUMENT);

	/* replace the current destination */
	papiAttributeListGetLPString(attributes,
	    "job-printer", &r->destination);

	/* set the copies.  We need at least 1 */
	i = r->copies;
	papiAttributeListGetInteger(attributes, NULL, "copies", &i);
	if (i <= 0)
		i = 1;
	r->copies = i;

	/*
	 * set the priority.  PAPI/IPP uses 1-100, lpsched use 0-39, so we
	 * have to convert it.
	 */
	if (papiAttributeListGetInteger(attributes, NULL, "job-priority", &i)
	    == PAPI_OK) {
		if ((i < 1) || (i > 100))
			i = 50;
		i = 40 - (i / 2.5);
		r->priority = i;
	}
	if ((r->priority < 0) || (r->priority > 39))
		r->priority = 20;

	/* set the requested form to print on */
	papiAttributeListGetLPString(attributes, "form", &r->form);

	/* set the page range */
	memset(tmp, 0, sizeof (tmp));
	tmp[0] = papiAttributeListFind(attributes, "page-ranges");
	if (tmp[0] != NULL) {
		char buf[BUFSIZ];

		papiAttributeListToString(tmp, " ", buf, sizeof (buf));
		if ((s = strchr(buf, '=')) != NULL)
			r->pages = (char *)strdup(++s);
	}

	/*
	 * set the document format, converting to old format names as
	 * as needed.
	 */
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

		papiAttributeListGetString(attributes, NULL,
		    "job-originating-host-name", &host);
		papiAttributeListGetString(attributes, NULL,
		    "job-host", &host);
		papiAttributeListGetString(attributes, NULL,
		    "job-originating-user-name", &user);
		papiAttributeListGetString(attributes, NULL,
		    "requesting-user-name", &user);

		snprintf(buf, sizeof (buf), "%s%s%s", user,
		    (host ? "@" : ""), (host ? host : ""));
		user = buf;

		r->user = strdup(user);
	}

	/* set any held state */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "job-hold-until", &s);
	if (s != NULL) {
		r->actions &= ~(ACT_SPECIAL); /* strip immediate/hold/resume */
		if (strcmp(s, "resume") == 0)
			r->actions |= ACT_RESUME;
		else if ((strcmp(s, "immediate") == 0) ||
		    (strcmp(s, "no-hold") == 0))
			r->actions |= ACT_IMMEDIATE;
		else if ((strcmp(s, "indefinite") == 0) ||
		    (strcmp(s, "hold") == 0))
			r->actions |= ACT_HOLD;
	}

	/* set lp charset/printwheel */
	papiAttributeListGetLPString(attributes, "lp-charset", &r->charset);

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
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "job-sheets", &s);
	if ((s != NULL) && (strcasecmp(s, "none") != 0)) {
		char buf[128];
		char *class = NULL;
		char *job_name = NULL;

		papiAttributeListGetLPString(attributes, "job-class", &class);
		papiAttributeListGetLPString(attributes, "job-name", &job_name);

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
	} else if ((s != NULL) && (strcasecmp(s, "none") == 0)) {
		/* burst page is disabled via lp "option" */
		appendlist(&options, "nobanner");
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
		case 4:	/* landscape */
		case 5:	/* reverse-landscape, use landscape instead */
			appendlist(&modes, "landscape");
			break;
		case 3:	/* portrait */
		case 6: /* reverse-portrait, use portrait instead */
		default:
			appendlist(&modes, "portrait");
			break;
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

	/* add any unconsumed attributes to the "options" list */
	split_and_copy_attributes(mapped_keys, attributes, NULL, &unmapped);
	if (unmapped != NULL) {	/* convert them to lp options */
		char *buf = malloc(1024);
		ssize_t size = 1024;

		while (papiAttributeListToString(unmapped, " ", buf, size)
		    != PAPI_OK) {
			size += 1024;
			buf = realloc(buf, size);
		}
		appendlist(&options, buf);
		free(buf);
		papiAttributeListFree(unmapped);
	}

	if (options != NULL) {
		if (r->options != NULL)
			free(r->options);
		r->options = sprintlist(options);
		freelist(options);
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

	if (state & RS_NOTIFYING) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0800);   /* notifying user */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-notifying");
	} else if (state & RS_HELD) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0001);   /* held */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-hold-until-specified");
	} else if (state & RS_CANCELLED) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0040);   /* job cancelled */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-canceled-by-user");
	} else if (state & RS_PRINTED) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0010);   /* finished printing job */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-complete");
	} else if (state & RS_PRINTING) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0008);   /* printing job */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-printing");
	} else if (state & RS_ADMINHELD) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x2000);   /* held by admin */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-hold-until-specified");
	} else if (state & RS_FILTERED) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0004);   /* filtered */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-filtered");
	} else if (state & RS_CHANGING) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0020);   /* job held for changing */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-held-for-change");
	} else if (state & RS_FILTERING) {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x0002);   /* being filtered */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-being-filtered");
	} else {
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-state", 0x4000);   /* else */
		papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
		    "job-state-reasons", "job-queued");
	}



	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
	    "job-hold-until",
	    ((state & RS_HELD) ? "indefinite" : "no-hold"));
}

/*
 * convert user[@host] to papi attributes
 */
static void
lpsched_user_to_job_attributes(papi_attribute_t ***list, char *user)
{
	if ((list != NULL) && (user != NULL) && (user[0] != '\0')) {
		char *host = strrchr(user, '@');

		if (host != NULL) {
			*host = '\0';
			papiAttributeListAddString(list, PAPI_ATTR_REPLACE,
			    "job-originating-user-name", user);
			papiAttributeListAddString(list, PAPI_ATTR_REPLACE,
			    "job-originating-host-name", host + 1);
			*host = '@';
		} else
			papiAttributeListAddString(list, PAPI_ATTR_REPLACE,
			    "job-originating-user-name", user);
	}
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
	papiAttributeListAddLPString(&j->attributes, PAPI_ATTR_REPLACE,
	    "printer-name", r->destination);

	/* form */
	papiAttributeListAddLPString(&j->attributes, PAPI_ATTR_REPLACE,
	    "form", r->form);

	/* options */
	papiAttributeListFromString(&j->attributes, PAPI_ATTR_APPEND,
	    r->options);

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
	    "job-priority",
	    (int)(100 - (r->priority * 2.5)));

	/* pages */
	papiAttributeListAddLPString(&j->attributes, PAPI_ATTR_REPLACE,
	    "page-ranges", r->pages);

	/* charset */
	papiAttributeListAddLPString(&j->attributes, PAPI_ATTR_REPLACE,
	    "lp-charset", r->charset);

	/* modes */
	papiAttributeListAddLPString(&j->attributes, PAPI_ATTR_REPLACE,
	    "lp-modes", r->modes);

	/* title */
	papiAttributeListAddLPString(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-name", r->title);

	/* input_type */

	/* user */
	lpsched_user_to_job_attributes(&j->attributes, r->user);

	/* outcome */
	lpsched_request_outcome_to_attributes(&j->attributes, r->outcome);

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
job_status_to_attributes(job_t *job, char *req_id, char *user, char *slabel,
		size_t size, time_t date, short state, char *destination,
		char *form, char *charset, short rank, char *file)
{
	char buf[BUFSIZ];
	char *p;

	lpsched_user_to_job_attributes(&job->attributes, user);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
	    "job-k-octets", size/1024);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
	    "job-octets", size);
	if ((p = strrchr(req_id, '-')) != NULL) {
		papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
		    "job-id", atoi(++p));
	}
	snprintf(buf, sizeof (buf), "lpsched://localhost/printers/%s/%d",
	    destination, atoi(p));
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
	    "job-uri", buf);
	snprintf(buf, sizeof (buf), "lpsched://localhost/printers/%s",
	    destination);
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
	    "job-printer-uri", buf);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
	    "job-printer-up-time", time(NULL));
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
	    "output-device-assigned", destination);
	papiAttributeListAddString(&job->attributes, PAPI_ATTR_REPLACE,
	    "printer-name", destination);
	papiAttributeListAddLPString(&job->attributes, PAPI_ATTR_REPLACE,
	    "form", form);

	lpsched_request_outcome_to_attributes(&job->attributes, state);

	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
	    "time-at-creation", date);
	papiAttributeListAddLPString(&job->attributes, PAPI_ATTR_REPLACE,
	    "lpsched-request-id", req_id);
	papiAttributeListAddLPString(&job->attributes, PAPI_ATTR_REPLACE,
	    "lp-charset", charset);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
	    "lpsched-job-state", state);
	papiAttributeListAddInteger(&job->attributes, PAPI_ATTR_REPLACE,
	    "number-of-intervening-jobs", rank - 1);
	papiAttributeListAddLPString(&job->attributes, PAPI_ATTR_REPLACE,
	    "lpsched-file", file);
	papiAttributeListAddLPString(&job->attributes, PAPI_ATTR_EXCL,
	    "job-name", file);
	papiAttributeListAddLPString(&job->attributes, PAPI_ATTR_EXCL,
	    "tsol-sensitivity-label", slabel);
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
