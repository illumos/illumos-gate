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
#include <smbsrv/ndl/srvsvc.ndl>

static int wkssvc_s_NetWkstaGetInfo(void *, ndr_xa_t *);
static int wkssvc_s_NetWkstaTransportEnum(void *, ndr_xa_t *);

static ndr_stub_table_t wkssvc_stub_table[] = {
	{ wkssvc_s_NetWkstaGetInfo,	WKSSVC_OPNUM_NetWkstaGetInfo },
	{ wkssvc_s_NetWkstaTransportEnum, WKSSVC_OPNUM_NetWkstaTransportEnum },
	{0}
};

static ndr_service_t wkssvc_service = {
	"Workstation",			/* name (WKSSVC or WKSTA) */
	"Workstation services",		/* desc */
	"\\wkssvc",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"6bffd098-a112-3610-9833-46c3f87e345a", 1,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
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
	(void) ndr_svc_register(&wkssvc_service);
}

/*
 * WKSSVC NetWkstaGetInfo
 */
static int
wkssvc_s_NetWkstaGetInfo(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetWkstaGetInfo *param = arg;
	mslm_NetWkstaGetInfo_rb *rb;
	char hostname[MAXHOSTNAMELEN];
	char resource_domain[SMB_PI_MAX_DOMAIN];
	char *name;
	char *domain;
	DWORD status;
	int rc;

	(void) smb_getdomainname(resource_domain, SMB_PI_MAX_DOMAIN);

	rb = NDR_NEW(mxa, mslm_NetWkstaGetInfo_rb);

	if ((rc = smb_getnetbiosname(hostname, MAXHOSTNAMELEN)) == 0) {
		name = NDR_STRDUP(mxa, hostname);
		domain = NDR_STRDUP(mxa, resource_domain);
	}

	if ((rc != 0) || (rb == NULL) || (name == NULL) || (domain == NULL)) {
		bzero(param, sizeof (struct mslm_NetWkstaGetInfo));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	param->result.level = param->level;
	param->result.bufptr.nullptr = (void *)rb;

	switch (param->level) {
	case 100:
		rb->buf100.wki100_platform_id = SV_PLATFORM_ID_NT;
		rb->buf100.wki100_ver_major = 4;
		rb->buf100.wki100_ver_minor = 0;
		rb->buf100.wki100_computername = (unsigned char *)name;
		rb->buf100.wki100_langroup = (unsigned char *)domain;
		status = ERROR_SUCCESS;
		break;

	case 101:
		rb->buf101.wki101_platform_id = SV_PLATFORM_ID_NT;
		rb->buf101.wki101_ver_major = 4;
		rb->buf101.wki101_ver_minor = 0;
		rb->buf101.wki101_computername = (unsigned char *)name;
		rb->buf101.wki101_langroup = (unsigned char *)domain;
		rb->buf101.wki101_lanroot = (unsigned char *)"";
		status = ERROR_SUCCESS;
		break;

	case 102:
		rb->buf102.wki102_platform_id = SV_PLATFORM_ID_NT;
		rb->buf102.wki102_ver_major = 4;
		rb->buf102.wki102_ver_minor = 0;
		rb->buf102.wki102_computername = (unsigned char *)name;
		rb->buf102.wki102_langroup = (unsigned char *)domain;
		rb->buf102.wki102_lanroot = (unsigned char *)"";
		rb->buf102.wki102_logged_on_users = 1;
		status = ERROR_SUCCESS;
		break;

	case 502:
		bzero(&rb->buf502, sizeof (struct mslm_WKSTA_INFO_502));
		rb->buf502.keep_connection = 600;
		rb->buf502.max_commands = 1024;
		rb->buf502.session_timeout = 5400;
		rb->buf502.size_char_buf = 1024;
		rb->buf502.max_threads = 1024;
		rb->buf502.use_opportunistic_locking = 1;
		rb->buf502.use_unlock_behind = 1;
		rb->buf502.use_close_behind = 1;
		rb->buf502.buf_named_pipes = 1;
		rb->buf502.use_lock_read_unlock = 1;
		rb->buf502.utilize_nt_caching = 1;
		rb->buf502.use_raw_read = 1;
		rb->buf502.use_raw_write = 1;
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

	return (NDR_DRC_OK);
}

/*
 * WKSSVC NetWkstaTransportEnum
 */
static int
wkssvc_s_NetWkstaTransportEnum(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetWkstaTransportEnum *param = arg;
	struct mslm_NetWkstaTransportCtr0 *info0;
	struct mslm_NetWkstaTransportInfo0 *ti0;

	switch (param->info.level) {
	case 0:
		info0 = NDR_NEW(mxa, struct mslm_NetWkstaTransportCtr0);
		ti0 = NDR_NEW(mxa, struct mslm_NetWkstaTransportInfo0);

		if (info0 == NULL || ti0 == NULL) {
			bzero(param, sizeof (struct mslm_NetWkstaGetInfo));
			param->status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		ti0->quality_of_service = 65535;
		ti0->num_vcs = 0;
		ti0->transport_name = (unsigned char *)"\\Device\\NetbiosSmb";
		ti0->transport_address = (unsigned char *)"000000000000";
		ti0->wan_ish = 1024;

		info0->count = 1;
		info0->ti0 = ti0;
		param->info.ru.info0 = info0;
		param->total_entries = 1;

		if (param->resume_handle)
			*param->resume_handle = 0;

		param->status = ERROR_SUCCESS;
		break;

	default:
		bzero(param, sizeof (struct mslm_NetWkstaGetInfo));
		param->status = ERROR_INVALID_LEVEL;
	}

	return (NDR_DRC_OK);
}
