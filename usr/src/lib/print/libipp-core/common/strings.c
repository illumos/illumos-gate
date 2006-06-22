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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: strings.c 151 2006-04-25 16:55:34Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipp.h"

static char *tag_strings[] = {
	/* delimiter tags */
	"reserved-delimiter-00",
	"operational-attributes-group",
	"job-attributes-group",
	"end-of-attributes-group",
	"printer-attributes-group",
	"unsupported-attributes-group",
	"subscription-attributes-group",
	"event-notification-attributes-group",
	"reserved-delimiter-08",
	"reserved-delimiter-09",
	"reserved-delimiter-0a",
	"reserved-delimiter-0b",
	"reserved-delimiter-0c",
	"reserved-delimiter-0d",
	"reserved-delimiter-0e",
	"reserved-delimiter-0f",
	/* value tags */
	"unsupported",
	"reserved-default",
	"unknown",
	"no-value",
	"reserved-out-of-band-14",
	"not-settable",
	"delete-attribute",
	"admin-define",
	"reserved-out-of-band-18",
	"reserved-out-of-band-19",
	"reserved-out-of-band-1a",
	"reserved-out-of-band-1b",
	"reserved-out-of-band-1c",
	"reserved-out-of-band-1d",
	"reserved-out-of-band-1e",
	"reserved-out-of-band-1f",
	"reserved",
	"integer",
	"boolean",
	"enum",
	"reserved-integer-type-24",
	"reserved-integer-type-25",
	"reserved-integer-type-26",
	"reserved-integer-type-27",
	"reserved-integer-type-28",
	"reserved-integer-type-29",
	"reserved-integer-type-2a",
	"reserved-integer-type-2b",
	"reserved-integer-type-2c",
	"reserved-integer-type-2d",
	"reserved-integer-type-2e",
	"reserved-integer-type-2f",
	"octetString",
	"dateTime",
	"resolution",
	"rangeOfInteger",
	"begCollection",
	"textWithLanguage",
	"nameWithLanguage",
	"endCollection",
	"reserved-octetString-38",
	"reserved-octetString-39",
	"reserved-octetString-3a",
	"reserved-octetString-3b",
	"reserved-octetString-3c",
	"reserved-octetString-3d",
	"reserved-octetString-3e",
	"reserved-octetString-3f",
	"reserved",
	"textWithoutLanguage",
	"nameWithoutLanguage",
	"reserved",
	"keyword",
	"uri",
	"uriScheme",
	"charset",
	"naturalLanguage",
	"mimeMediaType",
	"memberAttrName",
	"reserved-charString-4b",
	"reserved-charString-4c",
	"reserved-charString-4d",
	"reserved-charString-4e",
	"reserved-charString-4f",
	"reserved-charString-50",
	"reserved-charString-51",
	"reserved-charString-52",
	"reserved-charString-53",
	"reserved-charString-54",
	"reserved-charString-55",
	"reserved-charString-56",
	"reserved-charString-57",
	"reserved-charString-58",
	"reserved-charString-59",
	"reserved-charString-5a",
	"reserved-charString-5b",
	"reserved-charString-5c",
	"reserved-charString-5d",
	"reserved-charString-5e",
	"reserved-charString-5f",
};

static char *opid_strings[] = {
	"reserved-0x0000",
	"reserved-0x0001",
	"Print-Job",
	"Print-URI",
	"Validate-Job",
	"Create-Job",
	"Send-Document",
	"Send-URI",
	"Cancel-Job",
	"Get-Job-Attributes",
	"Get-Jobs",
	"Get-Printer-Attributes",
	"Hold-Job",
	"Release-Job",
	"Restart-Job",
	"reserved-0x000f",
	"Pause-Printer",
	"Resume-Printer",
	"Purge-Jobs",
	"Set-Printer-Attributes",
	"Set-Job-Attributes",
	"Get-Printer-Supported-Values",
	"Create-Printer-Subscription",
	"Create-Job-Subscription",
	"Get-Subscription-Attributes",
	"Get-Subscriptions",
	"Renew-Subscription",
	"Cancel-Subscription",
	"Get-Notifications",
	"Send-Notifications",
	"Get-Resource-Attributes-deleted",
	"Get-Resource-Data-deleted",
	"Get-Resources-deleted",
	"Get-Print-Support-Files",
	"Disable-Printer",
	"Pause-Printer-After-Current-Job",
	"Hold-New-Jobs",
	"Release-Held-New-Jobs",
	"Deactivate-Printer",
	"Activate-Printer",
	"Restart-Printer",
	"Shutdown-Printer",
	"Startup-Printer",
	"Reprocess-Job",
	"Cancel-Current-Job",
	"Suspend-Current-Job",
	"Resume-Job",
	"Promote-Job",
	"Schedule-Job-After",
	NULL
};

static char *res_opid_strings[] = {
	"Microsoft-0x4000",
	"CUPS-Get-Default",
	"CUPS-Get-Printers",
	"CUPS-Add-Printer",
	"CUPS-Delete-Printer",
	"CUPS-Get-Classes",
	"CUPS-Add-Class",
	"CUPS-Delete-Class",
	"CUPS-Accept-Jobs",
	"CUPS-Reject-Jobs",
	"CUPS-Set-Default",
	"CUPS-Get-Devices",
	"CUPS-Get-PPDs",
	"CUPS-Move-Job",
	"CUPS-0x400e",
	"CUPS-0x400f",
	"Peerless-0x4010",
	NULL
};
#define	KNOWN_RESERVED_MIN 0x4000
#define	KNOWN_RESERVED_MAX 0x4010

static char *ok_status_strings[] = {
	"successful-ok",
	"successful-ok-ignored-or-substituted-attributes",
	"successful-ok-conflicting-attributes",
	"successful-ok-ignored-subscriptions",
	"successful-ok-ignored-notifications",
	"successful-ok-too-many-events",
	"successful-ok-but-cancel-subscription"
};

static char *redir_status_strings[] = {
	"redirection-other-site"
};

static char *client_error_status_strings[] = {
	"client-error-bad-request",
	"client-error-forbidden",
	"client-error-not-authenticated",
	"client-error-not-authorized",
	"client-error-not-possible",
	"client-error-timeout",
	"client-error-not-found",
	"client-error-gone",
	"client-error-request-entity-too-large",
	"client-error-request-value-too-long",
	"client-error-document-format-not-supported",
	"client-error-attributes-or-values-not-supported",
	"client-error-uri-scheme-not-supported",
	"client-error-charset-not-supported",
	"client-error-conflicting-attributes",
	"client-error-compression-not-supported",
	"client-error-compression-error",
	"client-error-document-format-error",
	"client-error-document-access-error",
	"client-error-attributes-not-settable",
	"client-error-ignored-all-subscriptions",
	"client-error-too-many-subscriptions",
	"client-error-ignored-all-notifications",
	"client-error-print-support-file-not-found"
};

static char *server_error_status_strings[] = {
	"server-error-internal-error",
	"server-error-operation-not-supported",
	"server-error-service-unavailable",
	"server-error-version-not-supported",
	"server-error-device-error",
	"server-error-temporary-error",
	"server-error-not-accepting-jobs",
	"server-error-busy",
	"server-error-job-canceled",
	"server-error-multiple-document-jobs-not-supported",
	"server-error-printer-is-deactivated"
};

char *
ipp_tag_string(int8_t id, char *ret, size_t len)
{
	if (id < VTAG_MAX)
		(void) strlcpy(ret, tag_strings[id], len);
	else if (id == VTAG_EXTEND)
		(void) strlcpy(ret, "extension", len);
	else
		(void) snprintf(ret, len, "bogus-0x%.2x", id);

	return (ret);
}

char *
ipp_opid_string(int16_t id, char *ret, size_t len)
{
	if (id < OPID_RESERVED_MIN)
		(void) strlcpy(ret, opid_strings[id], len);
	else if (id < OPID_RESERVED_VENDOR_MIN)
		(void) snprintf(ret, len, "reserved-0x%.4x", id);
	else if (id <= KNOWN_RESERVED_MAX)
		(void) strlcpy(ret,
				res_opid_strings[id - KNOWN_RESERVED_MIN], len);
	else /* if (id <= OPID_RESERVED_VENDOR_MAX) */
		(void) snprintf(ret, len, "reserved-vendor-0x%.4x", id);

	return (ret);
}

int16_t
ipp_string_opid(char *string)
{
	int i;

	for (i = 0; opid_strings[i] != NULL; i++)
		if (strcasecmp(opid_strings[i], string) == 0)
			return (i);

	for (i = 0; res_opid_strings[i] != NULL; i++)
		if (strcasecmp(res_opid_strings[i], string) == 0)
			return (0x4000 + i);

	return (-1);
}

char *
ipp_status_string(int16_t id, char *ret, size_t len)
{
	if (id <= IPP_OK_MAX)
		(void) strlcpy(ret, ok_status_strings[id], len);
	else if (id >= IPP_REDIR_MIN && id <= IPP_REDIR_MAX)
		(void) strlcpy(ret,
			redir_status_strings[id - IPP_REDIR_MIN], len);
	else if (id >= IPP_CERR_MIN && id <= IPP_CERR_MAX)
		(void) strlcpy(ret,
			client_error_status_strings[id - IPP_CERR_MIN], len);
	else if (id >= IPP_SERR_MIN && id <= IPP_SERR_MAX)
		(void) strlcpy(ret,
			server_error_status_strings[id - IPP_SERR_MIN], len);
	else
		(void) snprintf(ret, len, "bogus-0x%.4hx", id);

	return (ret);
}



/*
 * attribute template handling routines
 */
char *job_template[] = {
	"copies",
	"finishing",
	"job-hold-until",
	"job-priority",
	"job-sheets",
	"media",
	"multiple-document-handling",
	"number-up",
	"page-ranges-supported",
	"print-quality",
	"printer-resoultion",
	"sides",
	NULL
};

char *job_description[] = {
	"copies-default", "copies-supported",
	"finishing-default", "finishing-supported",
	"job-hold-until-default", "job-hold-until-supported",
	"job-priority-default", "job-priority-supported",
	"job-sheets-default", "job-sheets-supported",
	"media-default", "media-supported",
	"multiple-document-handling-default",
	"multiple-document-handling-supported",
	"number-up-default", "number-up-supported",
	"page-ranges-supported",
	"print-quality-default", "print-quality-supported",
	"printer-resoultion-default", "printer-resoultion-supported",
	"sides-default", "sides-supported",
	NULL
};

char *printer_description[] = {
	"printer-uri-supported",
	"uri-security-supported",
	"uri-authentication-supported",
	"printer-name",
	"printer-location",
	"printer-info",
	"printer-more-info",
	"printer-driver-installer",
	"printer-make-and-model",
	"printer-more-info-manufacturer",
	"printer-state",
	"printer-state-reasons",
	"printer-state-message",
	"ipp-versions-supported",
	"multiple-document-jobs-supported",
	"charset-configured",
	"charset-supported",
	"natural-language-configured",
	"generated-natural-language-supported",
	"document-format-default",
	"document-format-supported",
	"printer-is-accepting-jobs",
	"queued-job-count",
	"printer-message-from-operator",
	"color-supported",
	"reference-uri-schemes-supported",
	"pdl-override-supported",
	"printer-up-time",
	"printer-current-time",
	"multiple-operation-time-out",
	"compression-supported",
	"job-k-octets-supported",
	"job-impressions-supported",
	"job-media-sheets-supported",
	"pages-per-minute",
	"pages-per-minute-color",
	NULL
};
