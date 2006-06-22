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

/* $Id: library.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <alloca.h>
#include <libintl.h>
#include <papi_impl.h>

static char *calls[] = {
	/* Attribute Calls */
	"papiAttributeListAdd",
	"papiAttributeListAddBoolean", "papiAttributeListAddCollection",
	"papiAttributeListAddDatetime", "papiAttributeListAddInteger",
	"papiAttributeListAddMetadata", "papiAttributeListAddRange",
	"papiAttributeListAddResolution", "papiAttributeListAddString",
	"papiAttributeListDelete",
	"papiAttributeListGetValue", "papiAttributeListGetNext",
	"papiAttributeListFind",
	"papiAttributeListGetBoolean", "papiAttributeListGetCollection",
	"papiAttributeListGetDatetime", "papiAttributeListGetInteger",
	"papiAttributeListGetMetadata", "papiAttributeListGetRange",
	"papiAttributeListGetResolution", "papiAttributeListGetString",
	"papiAttributeListFromString", "papiAttributeListToString",
	"papiAttributeListFree",
	/* Job Calls */
	"papiJobSubmit", "papiJobSubmitByReference",
	"papiJobStreamOpen", "papiJobStreamWrite", "papiJobStreamClose",
	"papiJobQuery", "papiJobCancel",
	"papiJobGetAttributeList", "papiJobGetId", "papiJobGetPrinterName",
	"papiJobFree", "papiJobListFree",
	/* Printer Calls */
	"papiPrinterQuery", "papiPrinterPurgeJobs", "papiPrinterListJobs",
	"papiPrinterGetAttributeList", "papiPrinterFree",
	/* Service Calls */
	"papiServiceCreate", "papiServiceDestroy",
	"papiServiceGetStatusMessage",
	/* Misc Calls */
	"papiStatusString",
	"papiLibrarySupportedCall", "papiLibrarySupportedCalls",
	NULL
};

char **
papiLibrarySupportedCalls()
{
	return (calls);
}

char
papiLibrarySupportedCall(char *name)
{
	int i;

	for (i = 0; calls[i] != NULL; i++)
		if (strcmp(name, calls[i]) == 0)
			return (PAPI_TRUE);

	return (PAPI_FALSE);
}
