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
 * Service Control Services (SVCCTL) RPC interface definition.
 * This interface provides remote access to list SMF services
 * from a Windows client.
 *
 * SVCCTL access is restricted to administrators: members of the
 * Domain Admins or Administrators groups.
 */

#include <stdio.h>
#include <strings.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nmpipes.h>
#include "svcctl_scm.h"

#define	SVCCTL_OPENSVC_OP_UNIMPLEMENTED(S)	\
	((S) & SERVICE_CHANGE_CONFIG)	||	\
	((S) & SERVICE_PAUSE_CONTINUE)	||	\
	((S) & SERVICE_START)		||	\
	((S) & SERVICE_STOP)		||	\
	((S) & SERVICE_ENUMERATE_DEPENDENTS)

static int svcctl_s_Close(void *, ndr_xa_t *);
static int svcctl_s_OpenManager(void *, ndr_xa_t *);
static int svcctl_s_OpenService(void *, ndr_xa_t *);
static int svcctl_s_QueryServiceStatus(void *, ndr_xa_t *);
static int svcctl_s_QueryServiceConfig(void *, ndr_xa_t *);
static int svcctl_s_EnumServicesStatus(void *, ndr_xa_t *);
static int svcctl_s_GetServiceDisplayNameW(void *, ndr_xa_t *);
static int svcctl_s_GetServiceKeyNameW(void *, ndr_xa_t *);
static int svcctl_s_QueryServiceConfig2W(void *, ndr_xa_t *);

static ndr_stub_table_t svcctl_stub_table[] = {
	{ svcctl_s_Close,		SVCCTL_OPNUM_Close },
	{ svcctl_s_OpenManager,		SVCCTL_OPNUM_OpenManager },
	{ svcctl_s_OpenService,		SVCCTL_OPNUM_OpenService },
	{ svcctl_s_QueryServiceStatus,	SVCCTL_OPNUM_QueryServiceStatus },
	{ svcctl_s_QueryServiceConfig,	SVCCTL_OPNUM_QueryServiceConfig },
	{ svcctl_s_EnumServicesStatus,	SVCCTL_OPNUM_EnumServicesStatus },
	{ svcctl_s_GetServiceDisplayNameW,
		SVCCTL_OPNUM_GetServiceDisplayNameW },
	{ svcctl_s_GetServiceKeyNameW,	SVCCTL_OPNUM_GetServiceKeyNameW },
	{ svcctl_s_QueryServiceConfig2W, SVCCTL_OPNUM_QueryServiceConfig2W },
	{0}
};

static ndr_service_t svcctl_service = {
	"SVCCTL",			/* name */
	"Service Control Services",	/* desc */
	"\\svcctl",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"367abb81-9844-35f1-ad32-98f038001003", 2,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
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
	(void) ndr_svc_register(&svcctl_service);
}

/*
 * svcctl_hdlookup
 *
 * Handle lookup wrapper to validate the local service and/or manager context.
 */
static ndr_handle_t *
svcctl_hdlookup(ndr_xa_t *mxa, ndr_hdid_t *id, svcctl_context_type_t type)
{
	ndr_handle_t *hd;
	svcctl_context_t *ctx;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL)
		return (NULL);

	if ((ctx = (svcctl_context_t *)hd->nh_data) == NULL)
		return (NULL);

	if ((ctx->c_type != type) || (ctx->c_ctx.uc_cp == NULL))
		return (NULL);

	return (hd);
}

/*
 * svcctl_hdfree
 *
 * Handle deallocation wrapper to free the local service and/or manager context.
 */
static void
svcctl_hdfree(ndr_xa_t *mxa, ndr_hdid_t *id)
{
	ndr_handle_t *hd;
	svcctl_context_t *ctx;
	svcctl_manager_context_t *mgr_ctx;
	svcctl_service_context_t *svc_ctx;

	if ((hd = ndr_hdlookup(mxa, id)) != NULL) {
		ctx = (svcctl_context_t *)hd->nh_data;

		switch (ctx->c_type) {
		case SVCCTL_MANAGER_CONTEXT:
			mgr_ctx = ctx->c_ctx.uc_mgr;
			svcctl_scm_fini(mgr_ctx);
			svcctl_scm_scf_handle_fini(mgr_ctx);
			free(mgr_ctx);
			break;

		case SVCCTL_SERVICE_CONTEXT:
			svc_ctx = ctx->c_ctx.uc_svc;
			free(svc_ctx->sc_mgrid);
			free(svc_ctx->sc_svcname);
			free(svc_ctx);
			break;

		default:
			break;
		}

		free(ctx);
		ndr_hdfree(mxa, id);
	}
}

/*
 * svcctl_mgr_hdalloc
 *
 * Handle allocation wrapper to setup the local manager context.
 */
static ndr_hdid_t *
svcctl_mgr_hdalloc(ndr_xa_t *mxa)
{
	svcctl_context_t *ctx;
	svcctl_manager_context_t *mgr_ctx;

	if ((ctx = malloc(sizeof (svcctl_context_t))) == NULL)
		return (NULL);
	ctx->c_type = SVCCTL_MANAGER_CONTEXT;

	if ((mgr_ctx = malloc(sizeof (svcctl_manager_context_t))) == NULL) {
		free(ctx);
		return (NULL);
	}
	bzero(mgr_ctx, sizeof (svcctl_manager_context_t));

	if (svcctl_scm_scf_handle_init(mgr_ctx) < 0) {
		free(mgr_ctx);
		free(ctx);
		return (NULL);
	}

	if (svcctl_scm_init(mgr_ctx) < 0) {
		svcctl_scm_scf_handle_fini(mgr_ctx);
		free(mgr_ctx);
		free(ctx);
		return (NULL);
	}

	ctx->c_ctx.uc_mgr = mgr_ctx;

	return (ndr_hdalloc(mxa, ctx));
}

/*
 * svcctl_get_mgr_ctx
 *
 * This function looks up a reference to local manager context.
 */
static svcctl_manager_context_t *
svcctl_get_mgr_ctx(ndr_xa_t *mxa, ndr_hdid_t *mgr_id)
{
	ndr_handle_t *hd;
	svcctl_manager_context_t *mgr_ctx;

	hd = svcctl_hdlookup(mxa, mgr_id, SVCCTL_MANAGER_CONTEXT);
	if (hd == NULL)
		return (NULL);

	mgr_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_mgr;

	return (mgr_ctx);
}

/*
 * svcctl_svc_hdalloc
 *
 * Handle allocation wrapper to setup the local service context.
 */
static ndr_hdid_t *
svcctl_svc_hdalloc(ndr_xa_t *mxa, ndr_hdid_t *mgr_id, char *svc_name)
{
	svcctl_context_t *ctx;
	svcctl_service_context_t *svc_ctx;
	svcctl_manager_context_t *mgr_ctx;
	int max_name_sz = 0;
	char *svcname;

	mgr_ctx = svcctl_get_mgr_ctx(mxa, mgr_id);
	if (mgr_ctx == NULL)
		return (NULL);
	max_name_sz = mgr_ctx->mc_scf_max_fmri_len;

	if ((ctx = malloc(sizeof (svcctl_context_t))) == NULL) {
		svcctl_hdfree(mxa, mgr_id);
		return (NULL);
	}
	ctx->c_type = SVCCTL_SERVICE_CONTEXT;

	if ((svc_ctx = malloc(sizeof (svcctl_service_context_t))) == NULL) {
		svcctl_hdfree(mxa, mgr_id);
		free(ctx);
		return (NULL);
	}
	bzero(svc_ctx, sizeof (svcctl_service_context_t));

	svc_ctx->sc_mgrid = malloc(sizeof (ndr_hdid_t));
	svcname = malloc(max_name_sz);

	if ((svc_ctx->sc_mgrid == NULL) || (svcname == NULL)) {
		free(svc_ctx->sc_mgrid);
		free(svc_ctx);
		svcctl_hdfree(mxa, mgr_id);
		free(ctx);
		return (NULL);
	}

	svc_ctx->sc_svcname = svcname;

	bcopy(mgr_id, svc_ctx->sc_mgrid, sizeof (ndr_hdid_t));
	(void) strlcpy(svc_ctx->sc_svcname, svc_name, max_name_sz);

	ctx->c_ctx.uc_svc = svc_ctx;

	return (ndr_hdalloc(mxa, ctx));
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
svcctl_s_Close(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_Close *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	svcctl_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (svcctl_handle_t));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * svcctl_s_OpenManager
 *
 * Request to open the service control manager.
 * The caller must have administrator rights in order to open this
 * interface.  We don't support write (SC_MANAGER_LOCK) access.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_ACCESS_DENIED
 *
 * On success, returns a handle for use with subsequent svcctl requests.
 */
static int
svcctl_s_OpenManager(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_OpenManager *param = arg;
	ndr_hdid_t *id = NULL;
	int rc;

	rc = ndr_is_admin(mxa);

	if ((rc == 0) || (param->desired_access & SC_MANAGER_LOCK) != 0) {
		bzero(&param->handle, sizeof (svcctl_handle_t));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	id = svcctl_mgr_hdalloc(mxa);
	if (id) {
		bcopy(id, &param->handle, sizeof (svcctl_handle_t));
		param->status = ERROR_SUCCESS;
	} else {
		bzero(&param->handle, sizeof (svcctl_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	}

	return (NDR_DRC_OK);
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
 *	ERROR_CALL_NOT_IMPLEMENTED
 */
static int
svcctl_s_OpenService(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_OpenService *param = arg;
	ndr_hdid_t *mgrid = (ndr_hdid_t *)&param->manager_handle;
	ndr_hdid_t *id = NULL;
	ndr_handle_t *hd;
	DWORD status;
	svcctl_manager_context_t *mgr_ctx;
	char *svc_name = (char *)param->service_name;
	boolean_t unimplemented_operations = B_FALSE;

	/* Allow service handle allocations for only status & config queries */
	unimplemented_operations =
	    SVCCTL_OPENSVC_OP_UNIMPLEMENTED(param->desired_access);

	if (unimplemented_operations) {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_CALL_NOT_IMPLEMENTED;
		return (NDR_DRC_OK);
	}

	hd = svcctl_hdlookup(mxa, mgrid, SVCCTL_MANAGER_CONTEXT);
	if (hd == NULL) {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	mgr_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_mgr;
	status = svcctl_scm_validate_service(mgr_ctx, svc_name);
	if (status != ERROR_SUCCESS) {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = status;
		return (NDR_DRC_OK);
	}

	id = svcctl_svc_hdalloc(mxa, mgrid, svc_name);
	if (id) {
		bcopy(id, &param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_SUCCESS;
	} else {
		bzero(&param->service_handle, sizeof (svcctl_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	}

	return (NDR_DRC_OK);
}

/*
 * svcctl_s_QueryServiceStatus
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 */
static int
svcctl_s_QueryServiceStatus(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_QueryServiceStatus *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->service_handle;
	ndr_handle_t *hd;
	svcctl_manager_context_t *mgr_ctx;
	svcctl_service_context_t *svc_ctx;
	svcctl_svc_node_t *svc;

	hd = svcctl_hdlookup(mxa, id, SVCCTL_SERVICE_CONTEXT);
	if (hd == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceStatus));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	svc_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_svc;
	mgr_ctx = svcctl_get_mgr_ctx(mxa, svc_ctx->sc_mgrid);
	if (mgr_ctx == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	svc = svcctl_scm_find_service(mgr_ctx, svc_ctx->sc_svcname);
	if (svc == NULL || svc->sn_state == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->status = ERROR_SERVICE_DOES_NOT_EXIST;
		return (NDR_DRC_OK);
	}

	param->service_status.service_type = SERVICE_WIN32_SHARE_PROCESS;
	param->service_status.cur_state = svcctl_scm_map_status(svc->sn_state);
	param->service_status.ctrl_accepted = 0;
	param->service_status.w32_exitcode = 0;
	param->service_status.svc_specified_exitcode = 0;
	param->service_status.check_point = 0;
	param->service_status.wait_hint = 0;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
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
 *	ERROR_NOT_ENOUGH_MEMORY
 */
static int
svcctl_s_EnumServicesStatus(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_EnumServicesStatus *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->manager_handle;
	ndr_handle_t *hd;
	int input_bufsize = 0;
	svcctl_manager_context_t *mgr_ctx;

	hd = svcctl_hdlookup(mxa, id, SVCCTL_MANAGER_CONTEXT);
	if (hd == NULL) {
		bzero(param, sizeof (struct svcctl_EnumServicesStatus));
		param->services = NDR_STRDUP(mxa, "");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	mgr_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_mgr;
	if (svcctl_scm_refresh(mgr_ctx) != 0) {
		bzero(param, sizeof (struct svcctl_EnumServicesStatus));
		param->services = NDR_STRDUP(mxa, "");
		param->status = ERROR_INVALID_DATA;
		return (NDR_DRC_OK);
	}

	input_bufsize = param->buf_size;
	param->services = NDR_MALLOC(mxa, input_bufsize);
	if (param->services == NULL) {
		bzero(param, sizeof (struct svcctl_EnumServicesStatus));
		param->services = NDR_STRDUP(mxa, "");
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}
	bzero(param->services, input_bufsize);

	if (input_bufsize <= mgr_ctx->mc_bytes_needed) {
		param->bytes_needed = mgr_ctx->mc_bytes_needed;
		param->svc_num = 0;
		param->resume_handle = 0;
		param->status = ERROR_MORE_DATA;
		return (NDR_DRC_OK);
	}

	svcctl_scm_enum_services(mgr_ctx, param->services);

	param->buf_size = input_bufsize;
	param->bytes_needed = 0;
	param->svc_num = mgr_ctx->mc_scf_numsvcs;
	param->resume_handle = 0;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * svcctl_s_QueryServiceConfig
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 */
static int
svcctl_s_QueryServiceConfig(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_QueryServiceConfig *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->service_handle;
	ndr_handle_t *hd;
	svcctl_manager_context_t *mgr_ctx;
	svcctl_service_context_t *svc_ctx;
	svcctl_svc_node_t *svc;
	int bytes_needed = 0;
	svc_config_t *cfg;

	hd = svcctl_hdlookup(mxa, id, SVCCTL_SERVICE_CONTEXT);
	if (hd == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	svc_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_svc;
	mgr_ctx = svcctl_get_mgr_ctx(mxa, svc_ctx->sc_mgrid);
	if (mgr_ctx == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	svc = svcctl_scm_find_service(mgr_ctx, svc_ctx->sc_svcname);
	if (svc == NULL || svc->sn_fmri == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->status = ERROR_SERVICE_DOES_NOT_EXIST;
		return (NDR_DRC_OK);
	}

	cfg = &param->service_cfg;
	cfg->service_type = SERVICE_WIN32_SHARE_PROCESS;
	cfg->start_type = SERVICE_AUTO_START;
	cfg->error_control = SERVICE_AUTO_START;
	cfg->binary_pathname = NDR_STRDUP(mxa, "");
	cfg->loadorder_group = NDR_STRDUP(mxa, "");
	cfg->tag_id = 0;
	cfg->dependencies = NDR_STRDUP(mxa, "");
	cfg->service_startname = NDR_STRDUP(mxa, "");
	cfg->display_name = NDR_STRDUP(mxa, svc->sn_fmri);

	bytes_needed = sizeof (svc_config_t);
	bytes_needed += SVCCTL_WNSTRLEN((const char *)cfg->binary_pathname);
	bytes_needed += SVCCTL_WNSTRLEN((const char *)cfg->loadorder_group);
	bytes_needed += SVCCTL_WNSTRLEN((const char *)cfg->dependencies);
	bytes_needed += SVCCTL_WNSTRLEN((const char *)cfg->service_startname);
	bytes_needed += SVCCTL_WNSTRLEN(svc->sn_fmri);

	if (param->buf_size < bytes_needed) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig));
		param->cfg_bytes = bytes_needed;
		param->status = ERROR_MORE_DATA;
		return (NDR_DRC_OK);
	}

	param->cfg_bytes = bytes_needed;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * svcctl_s_GetServiceDisplayNameW
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 *	ERROR_SERVICE_DOES_NOT_EXIST
 */
static int
svcctl_s_GetServiceDisplayNameW(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_GetServiceDisplayNameW *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->manager_handle;
	ndr_handle_t *hd;
	svcctl_svc_node_t *svc;
	svcctl_manager_context_t *mgr_ctx;

	hd = svcctl_hdlookup(mxa, id, SVCCTL_MANAGER_CONTEXT);
	if (hd == NULL) {
		bzero(param, sizeof (struct svcctl_GetServiceDisplayNameW));
		param->display_name = NDR_STRDUP(mxa, "");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	mgr_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_mgr;
	svc = svcctl_scm_find_service(mgr_ctx, (char *)param->service_name);
	if (svc == NULL || svc->sn_fmri == NULL) {
		bzero(param, sizeof (struct svcctl_GetServiceDisplayNameW));
		param->display_name = NDR_STRDUP(mxa, "");
		param->status = ERROR_SERVICE_DOES_NOT_EXIST;
		return (NDR_DRC_OK);
	}

	param->display_name = NDR_STRDUP(mxa, svc->sn_fmri);
	if (param->display_name == NULL) {
		bzero(param, sizeof (struct svcctl_GetServiceDisplayNameW));
		param->display_name = NDR_STRDUP(mxa, "");
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	param->buf_size = strlen(svc->sn_fmri);
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * svcctl_s_GetServiceKeyNameW
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 *	ERROR_SERVICE_DOES_NOT_EXIST
 */
static int
svcctl_s_GetServiceKeyNameW(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_GetServiceKeyNameW *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->manager_handle;
	ndr_handle_t *hd;
	svcctl_svc_node_t *svc;
	svcctl_manager_context_t *mgr_ctx;

	hd = svcctl_hdlookup(mxa, id, SVCCTL_MANAGER_CONTEXT);
	if (hd == NULL) {
		bzero(param, sizeof (struct svcctl_GetServiceKeyNameW));
		param->key_name = NDR_STRDUP(mxa, "");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	mgr_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_mgr;
	svc = svcctl_scm_find_service(mgr_ctx, (char *)param->service_name);
	if (svc == NULL || svc->sn_name == NULL) {
		bzero(param, sizeof (struct svcctl_GetServiceKeyNameW));
		param->key_name = NDR_STRDUP(mxa, "");
		param->status = ERROR_SERVICE_DOES_NOT_EXIST;
		return (NDR_DRC_OK);
	}

	param->key_name = NDR_STRDUP(mxa, svc->sn_name);
	if (param->key_name == NULL) {
		bzero(param, sizeof (struct svcctl_GetServiceKeyNameW));
		param->key_name = NDR_STRDUP(mxa, "");
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	param->buf_size = strlen(svc->sn_name);
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * svcctl_s_QueryServiceConfig2W
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_INVALID_HANDLE
 *	ERROR_INVALID_LEVEL
 *	ERROR_NOT_ENOUGH_MEMORY
 */
static int
svcctl_s_QueryServiceConfig2W(void *arg, ndr_xa_t *mxa)
{
	struct svcctl_QueryServiceConfig2W *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->service_handle;
	ndr_handle_t *hd;
	svcctl_manager_context_t *mgr_ctx;
	svcctl_service_context_t *svc_ctx;
	svcctl_svc_node_t *svc;
	svc_description_t *svc_desc;
	svc_failure_actions_t *fac;
	int offset, input_bufsize, bytes_needed = 0;
	mts_wchar_t *wide_desc;
	char *desc;
	DWORD status;

	hd = svcctl_hdlookup(mxa, id, SVCCTL_SERVICE_CONTEXT);
	if (hd == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig2W));
		param->buffer = NDR_STRDUP(mxa, "");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	input_bufsize = param->buf_size;
	param->buffer = NDR_MALLOC(mxa, input_bufsize);
	if (param->buffer == NULL) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig2W));
		param->buffer = NDR_STRDUP(mxa, "");
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}
	bzero(param->buffer, input_bufsize);

	status = ERROR_SUCCESS;
	switch (param->info_level) {
	case SERVICE_CONFIG_DESCRIPTION:
		svc_ctx = ((svcctl_context_t *)hd->nh_data)->c_ctx.uc_svc;
		mgr_ctx = svcctl_get_mgr_ctx(mxa, svc_ctx->sc_mgrid);
		if (mgr_ctx == NULL) {
			param->status = ERROR_INVALID_HANDLE;
			break;
		}

		svc = svcctl_scm_find_service(mgr_ctx, svc_ctx->sc_svcname);
		if (svc == NULL || svc->sn_desc == NULL) {
			status = ERROR_SERVICE_DOES_NOT_EXIST;
			break;
		}

		desc = svc->sn_desc;
		bytes_needed = SVCCTL_WNSTRLEN(desc);

		if (input_bufsize <= bytes_needed) {
			param->bytes_needed = bytes_needed;
			param->status = ERROR_MORE_DATA;
			return (NDR_DRC_OK);
		}

		offset = sizeof (svc_description_t);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		svc_desc = (svc_description_t *)param->buffer;
		svc_desc->desc = offset;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		wide_desc = (mts_wchar_t *)&param->buffer[offset];
		(void) mts_mbstowcs(wide_desc, desc, (strlen(desc) + 1));
		offset = SVCCTL_WNSTRLEN(desc);

		param->bytes_needed = offset;
		break;

	case SERVICE_CONFIG_FAILURE_ACTIONS:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		fac = (svc_failure_actions_t *)param->buffer;
		bzero(fac, sizeof (svc_failure_actions_t));

		param->bytes_needed = input_bufsize;
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct svcctl_QueryServiceConfig2W));
		param->buffer = NDR_STRDUP(mxa, "");
		param->status = status;
		return (NDR_DRC_OK);
	}

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}
