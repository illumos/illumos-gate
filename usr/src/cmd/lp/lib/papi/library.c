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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <papi.h>

static char *calls[] = {
	/* Attribute Calls */
	"papiAttributeListAddValue",
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
	"papiJobSubmit", "papiJobSubmitByReference", "papiJobValidate",
	"papiJobStreamOpen", "papiJobStreamWrite", "papiJobStreamClose",
	"papiJobQuery", "papiJobModify", "papiJobCancel", "papiJobPromote",
	"papiJobGetAttributeList", "papiJobGetId", "papiJobGetPrinterName",
	"papiJobFree", "papiJobListFree",
	"papiJobHold", "papiJobRelease",
	/* Printer Calls */
	"papiPrintersList", "papiPrinterQuery", "papiPrinterModify",
	"papiPrinterAdd", "papiPrinterRemove",
	"papiPrinterPause", "papiPrinterResume",
	"papiPrinterDisable", "papiPrinterEnable",
	"papiPrinterPurgeJobs", "papiPrinterListJobs",
	"papiPrinterGetAttributeList",
	"papiPrinterFree", "papiPrinterListFree",
	/* Service Calls */
	"papiServiceCreate", "papiServiceDestroy",
	"papiServiceGetAppData",
	"papiServiceGetEncryption", "papiServiceGetPassword",
	"papiServiceGetServiceName", "papiServiceGetUserName",
	"papiServiceSetAppData", "papiServiceSetAuthCB",
	"papiServiceSetEncryption", "papiServiceSetPassword",
	"papiServiceSetUserName",
	"papiServiceGetAttributeList", "papiServiceGetStatusMessage",
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
papiLibrarySupportedCall(const char *name)
{
	int i;

	for (i = 0; calls[i] != NULL; i++)
		if (strcmp(name, calls[i]) == 0)
			return (PAPI_TRUE);

	return (PAPI_FALSE);
}
