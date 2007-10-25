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

#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/nterror.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/srvsvc.ndl>

static int wkssvc_s_NetWkstaGetInfo(void *, struct mlrpc_xaction *);

static mlrpc_stub_table_t wkssvc_stub_table[] = {
	{ wkssvc_s_NetWkstaGetInfo,	WKSSVC_OPNUM_NetWkstaGetInfo },
	{0}
};

static mlrpc_service_t wkssvc_service = {
	"Workstation",			/* name (WKSSVC or WKSTA) */
	"Workstation services",		/* desc */
	"\\wkssvc",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"6bffd098-a112-3610-983346c3f87e345a", 1,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(wkssvc_interface),	/* interface ti */
	wkssvc_stub_table		/* stub_table */
};

void
wkssvc_initialize(void)
{
	(void) mlrpc_register_service(&wkssvc_service);
}

/*
 * WKSSVC NetWkstaGetInfo (
 *	IN LPTSTR	servername,
 *	IN DWORD	level,
 *	OUT union switch(level) {
 *		case 100: _WKSTA_INFO_100 *	p100;
 *		case 101: _WKSTA_INFO_101 *	p101;
 *		case 102: _WKSTA_INFO_102 *	p102;
 *	    }		bufptr,
 *	OUT DWORD	status
 *      )
 */
static int
wkssvc_s_NetWkstaGetInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetWkstaGetInfo *param = arg;
	mslm_NetWkstaGetInfo_rb *rb;
	char hostname[MAXHOSTNAMELEN];
	char *resource_domain;
	char *p;
	DWORD status;
	int rc;

	rc = smb_getnetbiosname(hostname, MAXHOSTNAMELEN);
	rb = MLRPC_HEAP_NEW(mxa, mslm_NetWkstaGetInfo_rb);

	if ((rc != 0) || (rb == NULL)) {
		bzero(param, sizeof (struct mslm_NetWkstaGetInfo));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	param->result.level = param->level;
	param->result.bufptr.nullptr = (void *) rb;

	switch (param->level) {
	case 100:
		rb->buf100.wki100_platform_id = SV_PLATFORM_ID_NT;
		rb->buf100.wki100_ver_major = 4;
		rb->buf100.wki100_ver_minor = 0;

		if ((p = MLRPC_HEAP_STRSAVE(mxa, hostname)) == NULL) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		rb->buf100.wki100_computername = (unsigned char *)p;

		smb_config_rdlock();
		resource_domain = smb_config_getstr(SMB_CI_DOMAIN_NAME);

		if ((p = MLRPC_HEAP_STRSAVE(mxa, resource_domain)) == NULL) {
			smb_config_unlock();
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		smb_config_unlock();
		rb->buf100.wki100_langroup = (unsigned char *)p;
		status = ERROR_SUCCESS;
		break;

	default:
		param->result.bufptr.nullptr = 0;
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct mslm_NetWkstaGetInfo));
		param->status = status;
	}

	return (MLRPC_DRC_OK);
}
