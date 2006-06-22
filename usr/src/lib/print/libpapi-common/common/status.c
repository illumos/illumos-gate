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

/* $Id: status.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <papi.h>
#include <libintl.h>

char *
papiStatusString(const papi_status_t status)
{
	switch (status) {
	case PAPI_OK:
		return (gettext("ok"));
	case PAPI_OK_SUBST:
		return (gettext("ok-substitution"));
	case PAPI_OK_CONFLICT:
		return (gettext("ok-conflict"));
	case PAPI_OK_IGNORED_SUBSCRIPTIONS:
		return (gettext("ok-ignored-subscriptions"));
	case PAPI_OK_IGNORED_NOTIFICATIONS:
		return (gettext("ok-ignored-notifications"));
	case PAPI_OK_TOO_MANY_EVENTS:
		return (gettext("ok-too-many-events"));
	case PAPI_OK_BUT_CANCEL_SUBSCRIPTION:
		return (gettext("ok-but-cancel-subscription"));
	case PAPI_REDIRECTION_OTHER_SITE:
		return (gettext("redirection-to-other-site"));
	case PAPI_BAD_REQUEST:
		return (gettext("bad-request"));
	case PAPI_FORBIDDEN:
		return (gettext("forbidden"));
	case PAPI_NOT_AUTHENTICATED:
		return (gettext("not-authenticated"));
	case PAPI_NOT_AUTHORIZED:
		return (gettext("not-authorized"));
	case PAPI_NOT_POSSIBLE:
		return (gettext("not-possible"));
	case PAPI_TIMEOUT:
		return (gettext("timeout"));
	case PAPI_NOT_FOUND:
		return (gettext("not-found"));
	case PAPI_GONE:
		return (gettext("gone"));
	case PAPI_REQUEST_ENTITY:
		return (gettext("request-entity"));
	case PAPI_REQUEST_VALUE:
		return (gettext("request-value"));
	case PAPI_DOCUMENT_FORMAT:
		return (gettext("document-format"));
	case PAPI_ATTRIBUTES:
		return (gettext("attributes"));
	case PAPI_URI_SCHEME:
		return (gettext("uri-scheme"));
	case PAPI_CHARSET:
		return (gettext("charset"));
	case PAPI_CONFLICT:
		return (gettext("conflict"));
	case PAPI_COMPRESSION_NOT_SUPPORTED:
		return (gettext("compression-not-supported"));
	case PAPI_COMPRESSION_ERROR:
		return (gettext("compression-error"));
	case PAPI_DOCUMENT_FORMAT_ERROR:
		return (gettext("document-format-error"));
	case PAPI_DOCUMENT_ACCESS_ERROR:
		return (gettext("document-access-error"));
	case PAPI_ATTRIBUTES_NOT_SETTABLE:
		return (gettext("attributes-not-settable"));
	case PAPI_IGNORED_ALL_SUBSCRIPTIONS:
		return (gettext("ignored-all-subscriptions"));
	case PAPI_TOO_MANY_SUBSCRIPTIONS:
		return (gettext("too-many-subscriptions"));
	case PAPI_IGNORED_ALL_NOTIFICATIONS:
		return (gettext("ignored-all-notifications"));
	case PAPI_PRINT_SUPPORT_FILE_NOT_FOUND:
		return (gettext("print-support-file-not-found"));
	case PAPI_INTERNAL_ERROR:
		return (gettext("internal-error"));
	case PAPI_OPERATION_NOT_SUPPORTED:
		return (gettext("operation-not-supported"));
	case PAPI_SERVICE_UNAVAILABLE:
		return (gettext("service-unavailable"));
	case PAPI_VERSION_NOT_SUPPORTED:
		return (gettext("version-not-supported"));
	case PAPI_DEVICE_ERROR:
		return (gettext("device-error"));
	case PAPI_TEMPORARY_ERROR:
		return (gettext("temporary-error"));
	case PAPI_NOT_ACCEPTING:
		return (gettext("not-accepting"));
	case PAPI_PRINTER_BUSY:
		return (gettext("printer-busy"));
	case PAPI_ERROR_JOB_CANCELLED:
		return (gettext("error-job-cancelled"));
	case PAPI_MULTIPLE_JOBS_NOT_SUPPORTED:
		return (gettext("multiple-jobs-not-supported"));
	case PAPI_PRINTER_IS_DEACTIVATED:
		return (gettext("printer-is-deactivated"));
	case PAPI_BAD_ARGUMENT:
		return (gettext("bad-argument"));
	case PAPI_JOB_TICKET_NOT_SUPPORTED:
		return (gettext("job-ticket-not-supported"));
	default:
		return (gettext("unknown-error"));
	}
}
