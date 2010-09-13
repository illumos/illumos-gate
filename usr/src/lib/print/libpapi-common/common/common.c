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

/* $Id: common.c 151 2006-04-25 16:55:34Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Shared "unsupported" function implementations that can be overridden
 * by libpapi and the various print service modules (psms).
 */

#include <stdlib.h>
#include <papi.h>

static papi_status_t
_unsupported()
{
	return (PAPI_OPERATION_NOT_SUPPORTED);
}

static void *
_unsupported_null_return()
{
	return (NULL);
}

static void
_unsupported_no_return()
{
}

/*
 * Service interfaces
 */
#pragma weak papiServiceCreate = _unsupported
#pragma weak papiServiceDestroy = _unsupported_no_return
#pragma weak papiServiceSetPeer = _unsupported
#pragma weak papiServiceSetUserName = _unsupported
#pragma weak papiServiceSetPassword = _unsupported
#pragma weak papiServiceSetEncryption = _unsupported
#pragma weak papiServiceSetAuthCB = _unsupported
#pragma weak papiServiceSetAppData = _unsupported

#pragma weak papiServiceGetServiceName = _unsupported_null_return
#pragma weak papiServiceGetUserName = _unsupported_null_return
#pragma weak papiServiceGetPassword = _unsupported_null_return
#pragma weak papiServiceGetAppData = _unsupported_null_return

papi_encryption_t
papiServiceGetEncryption(papi_service_t handle)
{
	return (PAPI_ENCRYPT_NEVER);
}

#pragma weak papiServiceGetAttributeList = _unsupported_null_return
#pragma weak papiServiceGetStatusMessage = _unsupported_null_return

/*
 * Printer operations
 */
#pragma weak papiPrintersList = _unsupported
#pragma weak papiPrinterQuery = _unsupported
#pragma weak papiPrinterEnable = _unsupported
#pragma weak papiPrinterDisable = _unsupported
#pragma weak papiPrinterPause = _unsupported
#pragma weak papiPrinterResume = _unsupported
#pragma weak papiPrinterAdd = _unsupported
#pragma weak papiPrinterModify = _unsupported
#pragma weak papiPrinterRemove = _unsupported
#pragma weak papiPrinterPurgeJobs = _unsupported
#pragma weak papiPrinterListJobs = _unsupported
#pragma weak papiPrinterGetAttributeList = _unsupported_null_return
#pragma weak papiPrinterFree = _unsupported_no_return
#pragma weak papiPrinterListFree = _unsupported_no_return

/*
 * Job interfaces
 */
#pragma weak papiJobHold = _unsupported
#pragma weak papiJobRelease = _unsupported
#pragma weak papiJobRestart = _unsupported
#pragma weak papiJobPromote = _unsupported
#pragma weak papiJobModify = _unsupported
#pragma weak papiJobSubmit = _unsupported
#pragma weak papiJobSubmitByReference = _unsupported
#pragma weak papiJobValidate = _unsupported
#pragma weak papiJobStreamOpen = _unsupported
#pragma weak papiJobStreamWrite = _unsupported
#pragma weak papiJobStreamClose = _unsupported
#pragma weak papiJobQuery = _unsupported
#pragma weak papiJobMove = _unsupported
#pragma weak papiJobCancel = _unsupported
#pragma weak papiJobGetAttributeList = _unsupported_null_return
#pragma weak papiJobGetPrinterName = _unsupported_null_return
#pragma weak papiJobCreate = _unsupported
#pragma weak papiJobStreamAdd = _unsupported
#pragma weak papiJobCommit = _unsupported

int
papiJobGetId(papi_job_t job)
{
	return (-1);
}

#pragma weak papiJobGetJobTicket = _unsupported_null_return
#pragma weak papiJobFree = _unsupported_no_return
#pragma weak papiJobListFree = _unsupported_no_return

/* private functions */
#pragma weak getprinterbyname = _unsupported_null_return
