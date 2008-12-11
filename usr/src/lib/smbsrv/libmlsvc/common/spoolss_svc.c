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

/*
 * Printing and Spooling RPC service.
 */

#include <stdlib.h>
#include <strings.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/spoolss.ndl>
#include <smbsrv/nterror.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>

int spoolss_s_OpenPrinter(void *, ndr_xa_t *);
int spoolss_s_stub(void *, ndr_xa_t *);

static ndr_stub_table_t spoolss_stub_table[] = {
	{ spoolss_s_OpenPrinter,	SPOOLSS_OPNUM_OpenPrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_GetJob },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_GetPrinterDriver },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePrinterDriver },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddPrintProcessor },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_GetPrintProcessorDirectory },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AbortPrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_ReadPrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_WaitForPrinterChange },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddForm },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeleteForm },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_GetForm },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_SetForm },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_EnumMonitors },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddPort },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_ConfigurePort },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePort },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_CreatePrinterIc },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_PlayDescriptionPrinterIc },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePrinterIc },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddPrinterConnection },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePrinterConnection },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_PrinterMessageBox },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddMonitor },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeleteMonitor },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePrintProcessor },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddPrintProvider },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_DeletePrintProvider },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_ResetPrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_FindFirstChangeNotify },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_FindNextChangeNotify },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_RouterFindFirstNotify },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_ReplyOpenPrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_RouterReplyPrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_ReplyClosePrinter },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_AddPortEx },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_RemoteFindFirstChangeNotify },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_SpoolerInitialize },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_ResetPrinterEx },
	{ spoolss_s_stub,	SPOOLSS_OPNUM_RouterRefreshChangeNotify },
	{ spoolss_s_OpenPrinter,	SPOOLSS_OPNUM_OpenPrinter2 },
	{0}
};

static ndr_service_t spoolss_service = {
	"SPOOLSS",			/* name */
	"Print Spool Service",		/* desc */
	"\\spoolss",			/* endpoint */
	PIPE_SPOOLSS,			/* sec_addr_port */
	"12345678-1234-abcd-ef000123456789ab",	1,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(spoolss_interface),	/* interface ti */
	spoolss_stub_table		/* stub_table */
};

void
spoolss_initialize(void)
{
	(void) ndr_svc_register(&spoolss_service);
}

int
spoolss_s_OpenPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_OpenPrinter *param = arg;

	bzero(param, sizeof (struct spoolss_OpenPrinter));

	if (mxa == NULL)
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
	else
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);

	return (NDR_DRC_OK);
}

/*ARGSUSED*/
int
spoolss_s_stub(void *arg, ndr_xa_t *mxa)
{
	return (NDR_DRC_FAULT_PARAM_0_UNIMPLEMENTED);
}
