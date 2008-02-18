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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NT Service Control Services (SVCCTL) RPC interface definition.
 * This interface provides remote access to add, remove, start and
 * stop services.
 */

#include <stdio.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nterror.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/winsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/svcctl.ndl>

/*
 * The handle keys for this interface.
 */
static int svcctl_key_manager;
static int svcctl_key_service;

typedef struct {
	char *svc_name;
	char *display_name;
	char *local_name;
} svc_info_t;


/*
 * The list of service we report to Server Manager. Entries don't
 * have to be alphabetically arranged here; Server Manager will
 * sort the list.
 *
 * NOTE: The enumeration list is currently built in a fixed-size,
 * 1024 byte buffer. Be careful not to over-run the buffer.
 */
static svc_info_t svc_info[] = {
	{ "Dhcp",	"DHCP Client",				"dhcpc" },
	{ "EventLog",	"EventLog",				NULL },
	{ "Netlogon",	"Net Logon",				NULL },
	{ "WebAdmin",	"Web Administration",			"httpd" },
	{ "RlgnSvr",	"Remote Login",				"rlogin" },
	{ "RpcSs",	"Remote Procedure Call (RPC) Service",	NULL },
	{ "RshSvr",	"Remote Shell",				"rsh" },
	{ "SshSvr",	"Secure Shell",				"ssh" },
	{ "TlntSvr",	"Telnet",				"telnet" },
	{ "Dnscache",	"DNS Client",				"dns" },
	{ "NisSvr",	"Network Information Services",		NULL },
	{ "NtLmSsp",	"NT LM Security Support Provider",	NULL },
	{ "Samss",	"Security Accounts Manager",		NULL },
	{ "UPS",	"Uninterruptible Power Supply",		"ups" },
	{ "TftpSvr",	"TFTP",					"tftp" }
};

#define	SVCCTL_NUM_SVCS		(sizeof (svc_info)/sizeof (svc_info[0]))


static DWORD svcctl_get_status(const char *);
static DWORD svcctl_validate_service(char *);
static int svcctl_is_admin(struct mlrpc_xaction *);

static int svcctl_s_Close(void *, struct mlrpc_xaction *);
static int svcctl_s_OpenManager(void *, struct mlrpc_xaction *);
static int svcctl_s_OpenService(void *, struct mlrpc_xaction *);
static int svcctl_s_QueryServiceStatus(void *, struct mlrpc_xaction *);
static int svcctl_s_QueryServiceConfig(void *, struct mlrpc_xaction *);
static int svcctl_s_EnumServicesStatus(void *, struct mlrpc_xaction *);

static mlrpc_stub_table_t svcctl_stub_table[] = {
	{ svcctl_s_Close,		SVCCTL_OPNUM_Close },
	{ svcctl_s_OpenManager,		SVCCTL_OPNUM_OpenManager },
	{ svcctl_s_OpenService,		SVCCTL_OPNUM_OpenService },
	{ svcctl_s_QueryServiceStatus,	SVCCTL_OPNUM_QueryServiceStatus },
	{ svcctl_s_QueryServiceConfig,	SVCCTL_OPNUM_QueryServiceConfig },
	{ svcctl_s_EnumServicesStatus,	SVCCTL_OPNUM_EnumServicesStatus },
	{0}
};

static mlrpc_service_t svcctl_service = {
	"SVCCTL",			/* name */
	"Service Control Services",	/* desc */
	"\\svcctl",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"367abb81-9844-35f1-ad3298f038001003", 2,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(svcctl_interface),	/* interface ti */
	svcctl_stub_table		/* stub_table */
};

/*
 * svcctl_initialize
 *
 * This function registers the SVCCTL RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
svcctl_initialize(void)
{
	(void) mlrpc_register_service(&svcctl_service);
}

/*
 * svcctl_s_Close
 *
 * This is a request to close the SVCCTL interface specified by the
 * handle. Free the handle and zero out the result handle for the
 * client.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 */
static int
svcctl_s_Close(void *arg, struct mlrpc_xaction *mxa)
{
	struct svcctl_Close *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	ndr_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (svcctl_handle_t));
	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * svcctl_s_OpenManager
 *
 * Request to open the service control manager.
 * The caller must have administrator rights in order to open this
 * interface.  We don't support write access.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_ACCESS_DENIED
 *
 * On success, returns a handle for use with subsequent svcctl requests.
 */
static int
svcctl_s_OpenManager(void *arg, struct mlrpc_xaction *mxa)
{
	struct svcctl_OpenManager *param = arg;
	ndr_hdid_t *id;
	int rc;

	rc = svcctl_is_admin(mxa);

	if ((rc == 0) || (param->desired_access & SC_MANAGER_LOCK) != 0) {
		bzero(&param->handle, sizeof (svcctl_handle_t));
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	if ((id = ndr_hdalloc(mxa, &svcctl_key_manager)) != NULL) {
		bcopy(id, &param->handle, sizeof (svcctl_handle_t));
		param->status = ERROR_SUCCESS;
	} else {
		bzero(&param->handle, sizeof (svcctl_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	}

	return (MLRPC_DRC_OK);
}

/*
 * svcctl_s_OpenService
 *
 * Return a handle for use with subsequent svcctl requests.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 *	ERROR_SERVICE_DOES_NOT_EXIST
 */
static int
svcctl_s_OpenService(void *arg, struct mlrpc_xaction *mxa)
{
	struct svcctl_OpenService *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->manager_handle;
	ndr_handle_t *hd;
	DWORD status;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &svcctl_key_manager)) {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_INVALID_HANDLE;
		return (MLRPC_DRC_OK);
	}

	status = svcctl_validate_service((char *)param->service_name);
	if (status != ERROR_SUCCESS) {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	if ((id = ndr_hdalloc(mxa, &svcctl_key_service)) != NULL) {
		bcopy(id, &param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_SUCCESS;
	} else {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	}

	return (MLRPC_DRC_OK);
}

/*
 * svcctl_s_QueryServiceStatus
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 */
static int
svcctl_s_QueryServiceStatus(void *arg, struct mlrpc_xaction *mxa)
{
	struct svcctl_QueryServiceStatus *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->service_handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &svcctl_key_service)) {
		bzero(param, sizeof (struct svcctl_QueryServiceStatus));
		param->status = ERROR_INVALID_HANDLE;
		return (MLRPC_DRC_OK);
	}

	param->service_status.service_type = SERVICE_WIN32_SHARE_PROCESS;
	param->service_status.cur_state = SERVICE_RUNNING;
	param->service_status.ctrl_accepted = 0;
	param->service_status.w32_exitcode = 0;
	param->service_status.svc_specified_exitcode = 0;
	param->service_status.check_point = 0;
	param->service_status.wait_hint = 0;

	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * svcctl_s_EnumServicesStatus
 *
 * Enumerate the list of services we support. Currently, this list
 * is built in a fixed-size 1024 byte buffer - be careful not to
 * over-run the buffer.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 */
static int
svcctl_s_EnumServicesStatus(void *arg, struct mlrpc_xaction *mxa)
{
	struct svcctl_EnumServicesStatus *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->manager_handle;
	ndr_handle_t *hd;
	svc_enum_status_t *service_table;
	svc_enum_status_t *svc;
	mts_wchar_t *wide_name;
	char *name;
	int i, namelen;
	int offs;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &svcctl_key_manager)) {
		bzero(param, sizeof (struct svcctl_EnumServicesStatus));
		param->status = ERROR_INVALID_HANDLE;
		return (MLRPC_DRC_OK);
	}

	if (param->buf_size < 1024) {
		param->status = ERROR_MORE_DATA;
		return (MLRPC_DRC_OK);
	}

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	service_table = (svc_enum_status_t *)param->services;
	offs = SVCCTL_NUM_SVCS * sizeof (svc_enum_status_t);

	for (i = 0; i < SVCCTL_NUM_SVCS; i++) {
		svc = &service_table[i];

		svc->svc_name = offs;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		wide_name = (mts_wchar_t *)&param->services[offs];
		name = svc_info[i].svc_name;
		namelen = strlen(name) + 1;
		(void) mts_mbstowcs(wide_name, name, namelen);

		offs += namelen * 2;

		svc->display_name = offs;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		wide_name = (mts_wchar_t *)&param->services[offs];
		name = svc_info[i].display_name;
		namelen = strlen(name) + 1;
		(void) mts_mbstowcs(wide_name, name, namelen);

		offs += namelen * 2;

		name = svc_info[i].local_name;
		if (name)
			svc->svc_status.cur_state = svcctl_get_status(name);
		else
			svc->svc_status.cur_state = SERVICE_RUNNING;

		svc->svc_status.service_type = SERVICE_WIN32_SHARE_PROCESS;
		svc->svc_status.ctrl_accepted = 0;
		svc->svc_status.w32_exitcode = 0;
		svc->svc_status.svc_specified_exitcode = 0;
		svc->svc_status.check_point = 0;
		svc->svc_status.wait_hint = 0;
	}

	param->buf_size = 1024;
	param->bytes_needed = 0;
	param->svc_num = SVCCTL_NUM_SVCS;
	param->resume_handle = 0;
	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * svcctl_s_QueryServiceConfig
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 */
static int
svcctl_s_QueryServiceConfig(void *arg, struct mlrpc_xaction *mxa)
{
	struct svcctl_QueryServiceConfig *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->service_handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &svcctl_key_service)) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->status = ERROR_INVALID_HANDLE;
		return (MLRPC_DRC_OK);
	}

	param->service_cfg.service_type = SERVICE_WIN32_SHARE_PROCESS;
	param->service_cfg.start_type = SERVICE_AUTO_START;
	param->service_cfg.error_control = SERVICE_ERROR_IGNORE;
	param->service_cfg.binary_pathname = 0;
	param->service_cfg.loadorder_group = 0;
	param->service_cfg.tag_id = 0;
	param->service_cfg.dependencies = 0;
	param->service_cfg.service_startname = 0;
	param->service_cfg.display_name = 0;

	param->cfg_bytes = sizeof (svc_config_t);
	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * Check to see whether or not a service is supported. The check is
 * case-insensitive to avoid any naming issues due to the different
 * versions of Windows.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_SERVICE_DOES_NOT_EXIST
 */
static DWORD
svcctl_validate_service(char *svc_name)
{
	int i;

	if (svc_name == NULL)
		return (ERROR_SERVICE_DOES_NOT_EXIST);

	for (i = 0; i < SVCCTL_NUM_SVCS; i++) {
		if (strcasecmp(svc_name, svc_info[i].svc_name) == 0)
			return (ERROR_SUCCESS);
	}

	return (ERROR_SERVICE_DOES_NOT_EXIST);
}

/*
 * Report the service status: SERVICE_PAUSED or SERVICE_RUNNING.
 */
/*ARGSUSED*/
static DWORD
svcctl_get_status(const char *name)
{
	return (SERVICE_RUNNING);
}

/*
 * SVCCTL access is restricted to administrators: members of
 * the Domain Admins or Administrators groups.
 *
 * Returns 1 if the user has admin rights.  Otherwise returns 0.
 */
static int
svcctl_is_admin(struct mlrpc_xaction *mxa)
{
	smb_dr_user_ctx_t *user_ctx = mxa->context->user_ctx;

	if (user_ctx == NULL)
		return (0);

	return (user_ctx->du_flags & SMB_ATF_ADMIN);
}
