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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * NetLogon RPC (NETR) interface definition. This module provides
 * the server side NETR RPC interface and the interface registration
 * function.
 */

#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/netlogon.ndl>
#include <smbsrv/nmpipes.h>
#include <smbsrv/netrauth.h>

static int netr_s_ServerReqChallenge(void *, ndr_xa_t *);
static int netr_s_ServerAuthenticate2(void *, ndr_xa_t *);
static int netr_s_ServerPasswordSet(void *, ndr_xa_t *);
static int netr_s_SamLogon(void *, ndr_xa_t *);
static int netr_s_SamLogoff(void *, ndr_xa_t *);

static ndr_stub_table_t netr_stub_table[] = {
	{ netr_s_ServerReqChallenge,	NETR_OPNUM_ServerReqChallenge },
	{ netr_s_ServerAuthenticate2,	NETR_OPNUM_ServerAuthenticate2 },
	{ netr_s_ServerPasswordSet,	NETR_OPNUM_ServerPasswordSet },
	{ netr_s_SamLogon,		NETR_OPNUM_SamLogon },
	{ netr_s_SamLogoff,		NETR_OPNUM_SamLogoff },
	{0}
};

static ndr_service_t netr_service = {
	"NETR",				/* name */
	"NetLogon",			/* desc */
	"\\netlogon",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"12345678-1234-abcd-ef00-01234567cffb", 1,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(netr_interface),	/* interface ti */
	netr_stub_table			/* stub_table */
};

/*
 * netr_initialize
 *
 * This function registers the NETR RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
netr_initialize(void)
{
	uint32_t flags;

	(void) ndr_svc_register(&netr_service);

	flags = smb_get_netlogon_flags();
	netlogon_init_global(flags);
}

/*
 * netr_s_ServerReqChallenge
 */
/*ARGSUSED*/
static int
netr_s_ServerReqChallenge(void *arg, ndr_xa_t *mxa)
{
	struct netr_ServerReqChallenge *param = arg;

	bzero(param, sizeof (struct netr_ServerReqChallenge));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * netr_s_ServerAuthenticate2
 */
/*ARGSUSED*/
static int
netr_s_ServerAuthenticate2(void *arg, ndr_xa_t *mxa)
{
	struct netr_ServerAuthenticate2 *param = arg;

	bzero(param, sizeof (struct netr_ServerAuthenticate2));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * netr_s_ServerPasswordSet
 */
/*ARGSUSED*/
static int
netr_s_ServerPasswordSet(void *arg, ndr_xa_t *mxa)
{
	struct netr_PasswordSet *param = arg;

	bzero(param, sizeof (struct netr_PasswordSet));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * netr_s_SamLogon
 */
/*ARGSUSED*/
static int
netr_s_SamLogon(void *arg, ndr_xa_t *mxa)
{
	struct netr_SamLogon *param = arg;

	bzero(param, sizeof (struct netr_SamLogon));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * netr_s_SamLogoff
 */
/*ARGSUSED*/
static int
netr_s_SamLogoff(void *arg, ndr_xa_t *mxa)
{
	struct netr_SamLogoff *param = arg;

	bzero(param, sizeof (struct netr_SamLogoff));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * Declare extern references.
 */
DECL_FIXUP_STRUCT(netr_validation_u);
DECL_FIXUP_STRUCT(netr_validation_info);
DECL_FIXUP_STRUCT(netr_SamLogon);
DECL_FIXUP_STRUCT(netr_SamLogonEx);

/*
 * Patch the netr_validation_info union.
 */
static unsigned short
fixup_netr_validation_info(WORD level)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;

	switch (level) {
	case 3:
		/*
		 * The netr_validation_u union contains a pointer, which
		 * is a DWORD in NDR. So we need to set size1 to ensure
		 * that we can correctly decode the remaining parameters.
		 */
		size1 = sizeof (DWORD);
		break;

	default:
		/*
		 * If the request is badly formed or the level is invalid,
		 * the server returns NT_STATUS_INVALID_INFO_CLASS. Size1
		 * must be zero to correctly decode the status.
		 */
		size1 = 0;
		break;
	};

	size2 = size1 + (2 * sizeof (DWORD));

	FIXUP_PDU_SIZE(netr_validation_u, size1);
	FIXUP_PDU_SIZE(netr_validation_info, size2);

	return (size2);
}


/*
 * Patch the netr_SamLogon union.
 * This function is called from mlsvc_netr_ndr.c
 */
void
fixup_netr_SamLogon(struct netr_SamLogon *arg)
{
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	size2 = fixup_netr_validation_info(arg->validation_level);
	/* netr_valid ENC-UNION + hdr + ret_auth PTR + authoritative + status */
	size3 = size2 + sizeof (ndr_request_hdr_t) + 3 * sizeof (DWORD);
	FIXUP_PDU_SIZE(netr_SamLogon, size3);
}

/*
 * Patch the netr_SamLogonEx union.
 * This function is called from mlsvc_netr_ndr.c
 */
void
fixup_netr_SamLogonEx(struct netr_SamLogonEx *arg)
{
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	size2 = fixup_netr_validation_info(arg->validation_level);
	/* netr_valid ENC-UNION + hdr + authoritative + flags + status */
	size3 = size2 + sizeof (ndr_request_hdr_t) + 3 * sizeof (DWORD);

	FIXUP_PDU_SIZE(netr_SamLogonEx, size3);
}
