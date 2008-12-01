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

/*LINTLIBRARY*/

#include <stdlib.h>
#include <libintl.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>
#include <papi_impl.h>

#include "class.h"

void
lpsched_printer_status_to_attributes(papi_attribute_t ***attrs,
	unsigned short status)
{
	if (attrs == NULL)
		return;

	if (status & (PS_DISABLED|PS_LATER|PS_FAULTED|PS_FORM_FAULT)) {
		papiAttributeListAddInteger(attrs, PAPI_ATTR_REPLACE,
				"printer-state", 0x05); /* stopped */
		if (status & PS_LATER)
			papiAttributeListAddString(attrs, PAPI_ATTR_REPLACE,
				"printer-state-reasons", "moving-to-paused");
		else if (status & PS_FAULTED)
			papiAttributeListAddString(attrs, PAPI_ATTR_REPLACE,
				"printer-state-reasons", "none");
		else if (status & PS_FORM_FAULT)
			papiAttributeListAddString(attrs, PAPI_ATTR_REPLACE,
				"printer-state-reasons",
				"interpreter-resource-unavailable");
		else
			papiAttributeListAddString(attrs, PAPI_ATTR_REPLACE,
				"printer-state-reasons", "paused");
	} else if (status & PS_BUSY) {
		papiAttributeListAddInteger(attrs, PAPI_ATTR_REPLACE,
				"printer-state", 0x04); /* processing */
		papiAttributeListAddString(attrs, PAPI_ATTR_REPLACE,
				"printer-state-reasons", "moving-to-paused");
	} else {
		papiAttributeListAddInteger(attrs, PAPI_ATTR_REPLACE,
				"printer-state", 0x03); /* idle */
	}

	papiAttributeListAddBoolean(attrs, PAPI_ATTR_REPLACE,
			"printer-is-accepting-jobs",
			((status & PS_REJECTED) != PS_REJECTED));
	papiAttributeListAddBoolean(attrs, PAPI_ATTR_REPLACE,
			"printer-is-processing-jobs",
			((status & PS_DISABLED) != PS_DISABLED));
}

void
lpsched_printer_defaults(papi_attribute_t ***attributes)
{
	if (attributes == NULL)
		return;

	papiAttributeListAddBoolean(attributes, PAPI_ATTR_REPLACE,
			"multiple-document-jobs-supported", PAPI_TRUE);
	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"multiple-document-handling-supported",
			"seperate-documents-colated-copies");
	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"pdl-override-supported", "not-attempted");
	papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-priority-supported", 40);
	papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"job-priority-default", 20);
	papiAttributeListAddRange(attributes, PAPI_ATTR_REPLACE,
			"copies-supported", 1, 65535);
	papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"copies-default", 1);
	papiAttributeListAddBoolean(attributes, PAPI_ATTR_REPLACE,
			"page-ranges-supported", PAPI_TRUE);
	papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"number-up-supported", 1);
	papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
			"number-up-default", 1);
	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"job-hold-until-supported", "no-hold");
	papiAttributeListAddString(attributes, PAPI_ATTR_APPEND,
			"job-hold-until-supported", "indefinite");
	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"job-hold-until-default", "no-hold");
	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
			"document-format-default", "application/octet-stream");

}

papi_status_t
lpsched_printer_configuration_to_attributes(service_t *svc, printer_t *p,
	char *dest)
{
	PRINTER *tmp;
	char buf[BUFSIZ+1];
	struct utsname sysname;
	char **allowed = NULL, **denied = NULL;
	char **f_allowed = NULL, **f_denied = NULL;

	if ((svc == NULL) || (p == NULL) || (dest == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* get the configuration DB data */
	if ((tmp = getprinter(dest)) == NULL) {
		detailed_error(svc,
			gettext("unable to read configuration data"));
		return (PAPI_DEVICE_ERROR);
	}

	/* name */
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"printer-name", tmp->name);
	if (tmp->name != NULL) {
		char uri[BUFSIZ];

		snprintf(uri, sizeof (uri), "lpsched://localhost/printers/%s",
				tmp->name);
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_REPLACE,
				"printer-uri-supported", uri);
	}

	/* banner */
	if ((tmp->banner & BAN_OPTIONAL) == BAN_OPTIONAL)
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_APPEND,
				"job-sheets-supported", "optional");
	else if (tmp->banner & BAN_NEVER)
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_APPEND,
				"job-sheets-supported", "none");
	else if (tmp->banner & BAN_ALWAYS)
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_APPEND,
				"job-sheets-supported", "standard");

	/* input_types */
	if (tmp->input_types != NULL) {
		int i;

		for (i = 0; tmp->input_types[i] != NULL; i++)
			papiAttributeListAddLPString(&p->attributes,
				PAPI_ATTR_APPEND, "document-format-supported",
				lp_type_to_mime_type(tmp->input_types[i]));
	}

	/* description */
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"printer-info", tmp->description);

	/* add lpsched specific attributes */
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"device-uri", tmp->device);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-dial-info", tmp->dial_info);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-fault-recovery", tmp->fault_rec);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-interface-script", tmp->interface);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-data-rate", tmp->speed);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-stty", tmp->stty);
	papiAttributeListAddBoolean(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-login-term", tmp->login);
	papiAttributeListAddBoolean(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-daisy", tmp->daisy);
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-charsets", tmp->char_sets);
#ifdef CAN_DO_MODULES
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-modules", tmp->modules);
#endif /* CAN_DO_MODULES */
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-options", tmp->options);
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-printer-type", tmp->printer_types);
	if (tmp->fault_alert.shcmd != NULL) {
		papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-fault-alert-command",
				tmp->fault_alert.shcmd);
		papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-fault-alert-threshold",
				tmp->fault_alert.Q);
		papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-fault-alert-interval",
				tmp->fault_alert.W);
	}
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-cpi-value", tmp->cpi.val);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-cpi-unit", tmp->cpi.sc);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-lpi-value", tmp->lpi.val);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-lpi-unit", tmp->lpi.sc);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-plen-value", tmp->plen.val);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-plen-unit", tmp->plen.sc);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-pwid-value", tmp->pwid.val);
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
				"lpsched-pwid-unit", tmp->pwid.sc);

	/* allow/deny list */
	load_userprinter_access(dest, &allowed, &denied);
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
				"requesting-user-name-allowed", allowed);
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
				"requesting-user-name-denied", denied);

	freelist(allowed);
	freelist(denied);

	/* forms allow/deny list */
	load_formprinter_access(dest, &f_allowed, &f_denied);
	papiAttributeListAddLPStrings(&p->attributes, PAPI_ATTR_REPLACE,
	    "form-supported", f_allowed);

	/*
	 * All forms allowed case
	 * When all forms are allowed forms.allow does not get created but
	 * forms.deny file gets created with no entries
	 */
	if ((f_allowed == NULL) && (f_denied != NULL) && (f_denied[0] == NULL))
		papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
		    "form-supported", "all");

	freelist(f_allowed);
	freelist(f_denied);

#ifdef LP_USE_PAPI_ATTR
	if (tmp->ppd != NULL) {
		int fd;
		struct stat sbuf;

		/* construct the two URIs for the printer's PPD file */
		if (uname(&sysname) < 0) {
			/* failed to get systen name */
			sysname.nodename[0] = 0;
		}
		snprintf(buf, sizeof (buf), "file://%s%s/ppd/%s.ppd",
			sysname.nodename, ETCDIR, tmp->name);
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_REPLACE,
			"ppd-file-uri", buf);

		snprintf(buf, sizeof (buf), "file://%s%s",
			sysname.nodename, tmp->ppd);
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-printer-configure-ppd-uri", buf);
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-ppd-source-path", tmp->ppd);

		snprintf(buf, sizeof (buf), "%s/ppd/%s.ppd", ETCDIR, tmp->name);

		/*
		 * We don't return error on any of the error conditions, we just
		 * silently return without adding the attribute.
		 */
		PPDFileToAttributesList(&p->attributes, buf);
	}
#endif

	freeprinter(tmp);

	return (PAPI_OK);
}

papi_status_t
printer_status_to_attributes(printer_t *p, char *printer, char *form,
		char *character_set, char *disable_reason, char *reject_reason,
		short status, char *request_id,
		long disable_date, long reject_date)
{
	if (p == NULL)
		return (PAPI_BAD_ARGUMENT);

	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"form-ready", form);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-active-job", request_id);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-mounted-char-set", character_set);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-disable-reason", disable_reason);
	papiAttributeListAddDatetime(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-disable-date", disable_date);
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-reject-reason", reject_reason);
	papiAttributeListAddDatetime(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-reject-date", reject_date);

	/* add the current system time */
	papiAttributeListAddDatetime(&p->attributes, PAPI_ATTR_REPLACE,
			"printer-current-time", time(NULL));

	/* add the time since last enabled */
	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
			"printer-up-time", time(NULL));

	/* add the status information */
	lpsched_printer_status_to_attributes(&p->attributes, status);

	papiAttributeListAddString(&p->attributes, PAPI_ATTR_EXCL,
			"printer-state-reasons", "none");

	lpsched_printer_defaults(&p->attributes);

	return (PAPI_OK);
}


/*
 * This puts the class information in only.  It could create a hybrid
 * printer object to return, but that is problematic at best.
 */
papi_status_t
lpsched_class_configuration_to_attributes(service_t *svc, printer_t *p,
	char *dest)
{
	CLASS *tmp;

	if ((svc == NULL) || (p == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* get the configuration DB data */
	if ((tmp = getclass(dest)) == NULL) {
		detailed_error(svc,
			gettext("unable to read configuration data"));
		return (PAPI_DEVICE_ERROR);
	}

	/* name */
	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
				"printer-name", tmp->name);
	if (tmp->name != NULL) {
		char uri[BUFSIZ];

		snprintf(uri, sizeof (uri), "lpsched://localhost/printers/%s",
				tmp->name);
		papiAttributeListAddString(&p->attributes, PAPI_ATTR_REPLACE,
				"printer-uri-supported", uri);
	}

	if (tmp->members != NULL) {
		char **members = tmp->members;
		int i;

		for (i = 0; members[i] != NULL; i++)
			papiAttributeListAddString(&p->attributes,
					PAPI_ATTR_APPEND,
					"member-names", members[i]);
	}

	freeclass(tmp);

	return (PAPI_OK);
}

papi_status_t
class_status_to_attributes(printer_t *p, char *printer, short status,
		char *reject_reason, long reject_date)
{
	if (p == NULL)
		return (PAPI_BAD_ARGUMENT);

	papiAttributeListAddLPString(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-reject-reason", reject_reason);
	papiAttributeListAddDatetime(&p->attributes, PAPI_ATTR_REPLACE,
			"lpsched-reject-date", reject_date);

	/* add the current system time */
	papiAttributeListAddDatetime(&p->attributes, PAPI_ATTR_REPLACE,
			"printer-current-time", time(NULL));

	papiAttributeListAddInteger(&p->attributes, PAPI_ATTR_REPLACE,
			"printer-up-time", time(NULL));

	/* add the status information */
	lpsched_printer_status_to_attributes(&p->attributes, status);

	papiAttributeListAddString(&p->attributes, PAPI_ATTR_EXCL,
			"printer-state-reasons", "none");

	lpsched_printer_defaults(&p->attributes);

	return (PAPI_OK);
}

papi_status_t
attributes_to_printer(papi_attribute_t **attributes, PRINTER *tmp)
{
	papi_status_t status;
	void *iter = NULL;
	char *string = NULL;
	int flags;
	char **list = NULL;

	/* banner needs some conversion to the bitfield */
	iter = NULL, string = NULL; flags = 0;
	for (status = papiAttributeListGetString(attributes, &iter,
				"job-sheets-supported", &string);
	    status == PAPI_OK;
	    status = papiAttributeListGetString(attributes, &iter,
				NULL, &string))
		if (strcasecmp(string, "none") == 0)
			flags |= BAN_NEVER;
		else if (strcasecmp(string, "standard") == 0)
			flags |= BAN_ALWAYS;
	if (flags != 0)
		tmp->banner = flags;

	/* input_types needs mime-type conversion */
	iter = NULL, string = NULL; list = NULL;
	for (status = papiAttributeListGetString(attributes, &iter,
				"document-format-supported", &string);
	    status == PAPI_OK;
	    status = papiAttributeListGetString(attributes, &iter,
				NULL, &string))
		addlist(&list, mime_type_to_lp_type(string));
	if (list != NULL) {
		if (tmp->input_types != NULL)
			freelist(tmp->input_types);
		tmp->input_types = list;
	}

	papiAttributeListGetLPString(attributes,
				"device-uri", &tmp->device);
	papiAttributeListGetLPString(attributes,
				"printer-info", &tmp->description);
	papiAttributeListGetLPString(attributes,
				"lpsched-dial-info", &tmp->dial_info);
	papiAttributeListGetLPString(attributes,
				"lpsched-fault-recovery", &tmp->fault_rec);
	papiAttributeListGetLPString(attributes,
				"lpsched-interface-script", &tmp->interface);
	papiAttributeListGetLPString(attributes,
				"lpsched-data-rate", &tmp->speed);
	papiAttributeListGetLPString(attributes,
				"lpsched-stty", &tmp->stty);
	papiAttributeListGetLPStrings(attributes,
				"lpsched-charsets", &tmp->char_sets);
	papiAttributeListGetLPStrings(attributes,
				"lpsched-printer-types", &tmp->printer_types);
	papiAttributeListGetLPStrings(attributes,
				"lpsched-options", &tmp->options);
	papiAttributeListGetLPStrings(attributes,
				"lpsched-modules", &tmp->modules);
#ifdef LP_USE_PAPI_ATTR
	papiAttributeListGetLPString(attributes,
				"lpsched-printer-ppd-uri", &tmp->ppd);
#endif

	return (PAPI_OK);
}
