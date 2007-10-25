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

/*
 * Printing and Spooling RPC interface definition.
 * A stub to resolve RPC requests to this service.
 */

#include <smbsrv/ndl/spoolss.ndl>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nmpipes.h>

static mlrpc_stub_table_t spoolss_stub_table[];

static mlrpc_service_t spoolss_service = {
	"SPOOLSS",			/* name */
	"Print Spool Service",		/* desc */
	"\\spoolss",			/* endpoint */
	PIPE_SPOOLSS,			/* sec_addr_port */
	"12345678-1234-abcd-ef000123456789ab", 1,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(spoolss_interface),	/* interface ti */
	spoolss_stub_table		/* stub_table */
};

/*
 * spoolss_initialize
 *
 * This function registers the SPOOLSS RPC interface with the RPC
 * runtime library. It must be called in order to use either the
 * client side or the server side functions.
 */
void
spoolss_initialize(void)
{
	(void) mlrpc_register_service(&spoolss_service);
}

/*
 * spoolss_s_OpenPrinter
 *
 * We don't offer print spooling support. It should be okay to
 * set the status to access denied and return MLRPC_DRC_OK.
 */
static int
spoolss_s_OpenPrinter(void *arg, struct mlrpc_xaction *mxa)
{
	struct spoolss_OpenPrinter *param = arg;

	bzero(param, sizeof (struct spoolss_OpenPrinter));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);

	return (MLRPC_DRC_OK);
}


/*
 * spoolss_s_stub
 */
static int
spoolss_s_stub(void *arg, struct mlrpc_xaction *mxa)
{
	return (MLRPC_DRC_FAULT_PARAM_0_UNIMPLEMENTED);
}

static mlrpc_stub_table_t spoolss_stub_table[] = {
	{ spoolss_s_OpenPrinter, SPOOLSS_OPNUM_OpenPrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_GetJob },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_GetPrinterDriver },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePrinterDriver },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddPrintProcessor },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_GetPrintProcessorDirectory },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AbortPrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_ReadPrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_WaitForPrinterChange },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddForm },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeleteForm },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_GetForm },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_SetForm },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_EnumMonitors },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddPort },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_ConfigurePort },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePort },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_CreatePrinterIc },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_PlayDescriptionPrinterIc },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePrinterIc },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddPrinterConnection },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePrinterConnection },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_PrinterMessageBox },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddMonitor },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeleteMonitor },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePrintProcessor },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddPrintProvider },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_DeletePrintProvider },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_ResetPrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_FindFirstChangeNotify },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_FindNextChangeNotify },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_RouterFindFirstNotify },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_ReplyOpenPrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_RouterReplyPrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_ReplyClosePrinter },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_AddPortEx },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_RemoteFindFirstChangeNotify },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_SpoolerInitialize },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_ResetPrinterEx },
	{ spoolss_s_stub,	 SPOOLSS_OPNUM_RouterRefreshChangeNotify },
	{ spoolss_s_OpenPrinter, SPOOLSS_OPNUM_OpenPrinter2 },
	{0}
};
