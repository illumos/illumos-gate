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

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <atomic.h>
#include <sys/errno.h>
#include <dlfcn.h>
#include <rpc/rpc.h>

#define	RPCSEC	"rpcsec.so.1"

typedef struct {
	AUTH		*(*rpc_gss_seccreate)();
	bool_t		(*rpc_gss_set_defaults)();
	bool_t		(*rpc_gss_get_principal_name)();
	char		**(*rpc_gss_get_mechanisms)();
	char		**(*rpc_gss_get_mech_info)();
	bool_t		(*rpc_gss_get_versions)();
	bool_t		(*rpc_gss_is_installed)();
	bool_t		(*rpc_gss_set_svc_name)();
	bool_t		(*rpc_gss_set_callback)();
	bool_t		(*rpc_gss_getcred)();
	bool_t		(*rpc_gss_mech_to_oid)();
	bool_t		(*rpc_gss_qop_to_num)();
	enum auth_stat	(*__svcrpcsec_gss)();
	bool_t		(*__rpc_gss_wrap)();
	bool_t		(*__rpc_gss_unwrap)();
	int		(*rpc_gss_max_data_length)();
	int		(*rpc_gss_svc_max_data_length)();
	void		(*rpc_gss_get_error)();
} rpcgss_calls_t;

static rpcgss_calls_t calls;
static mutex_t rpcgss_calls_mutex = DEFAULTMUTEX;
static bool_t initialized = FALSE;

static bool_t
rpcgss_calls_init(void)
{
	void	*handle;
	bool_t	ret = FALSE;

	if (initialized) {
		membar_consumer();
		return (TRUE);
	}
	(void) mutex_lock(&rpcgss_calls_mutex);
	if (initialized) {
		(void) mutex_unlock(&rpcgss_calls_mutex);
		membar_consumer();
		return (TRUE);
	}

	if ((handle = dlopen(RPCSEC, RTLD_LAZY)) == NULL)
		goto done;

	if ((calls.rpc_gss_seccreate = (AUTH *(*)()) dlsym(handle,
					"__rpc_gss_seccreate")) == NULL)
		goto done;
	if ((calls.rpc_gss_set_defaults = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_set_defaults")) == NULL)
		goto done;
	if ((calls.rpc_gss_get_principal_name = (bool_t (*)()) dlsym(handle,
				"__rpc_gss_get_principal_name")) == NULL)
		goto done;
	if ((calls.rpc_gss_get_mechanisms = (char **(*)()) dlsym(handle,
					"__rpc_gss_get_mechanisms")) == NULL)
		goto done;
	if ((calls.rpc_gss_get_mech_info = (char **(*)()) dlsym(handle,
					"__rpc_gss_get_mech_info")) == NULL)
		goto done;
	if ((calls.rpc_gss_get_versions = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_get_versions")) == NULL)
		goto done;
	if ((calls.rpc_gss_is_installed = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_is_installed")) == NULL)
		goto done;
	if ((calls.rpc_gss_set_svc_name = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_set_svc_name")) == NULL)
		goto done;
	if ((calls.rpc_gss_set_callback = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_set_callback")) == NULL)
		goto done;
	if ((calls.rpc_gss_getcred = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_getcred")) == NULL)
		goto done;
	if ((calls.rpc_gss_mech_to_oid = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_mech_to_oid")) == NULL)
		goto done;

	if ((calls.rpc_gss_qop_to_num = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_qop_to_num")) == NULL)
		goto done;
	if ((calls.__svcrpcsec_gss = (enum auth_stat (*)()) dlsym(handle,
					"__svcrpcsec_gss")) == NULL)
		goto done;
	if ((calls.__rpc_gss_wrap = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_wrap")) == NULL)
		goto done;
	if ((calls.__rpc_gss_unwrap = (bool_t (*)()) dlsym(handle,
					"__rpc_gss_unwrap")) == NULL)
		goto done;
	if ((calls.rpc_gss_max_data_length = (int (*)()) dlsym(handle,
					"__rpc_gss_max_data_length")) == NULL)
		goto done;
	if ((calls.rpc_gss_svc_max_data_length = (int (*)()) dlsym(handle,
				"__rpc_gss_svc_max_data_length")) == NULL)
		goto done;
	if ((calls.rpc_gss_get_error = (void (*)()) dlsym(handle,
					"__rpc_gss_get_error")) == NULL)
		goto done;
	ret = TRUE;
done:
	if (!ret) {
		if (handle != NULL)
			(void) dlclose(handle);
	}
	membar_producer();
	initialized = ret;
	(void) mutex_unlock(&rpcgss_calls_mutex);
	return (ret);
}

AUTH *
rpc_gss_seccreate(
	CLIENT			*clnt,		/* associated client handle */
	char			*principal,	/* server service principal */
	char			*mechanism,	/* security mechanism */
	rpc_gss_service_t	service_type,	/* security service */
	char			*qop,		/* requested QOP */
	rpc_gss_options_req_t	*options_req,	/* requested options */
	rpc_gss_options_ret_t	*options_ret)	/* returned options */
{
	if (!rpcgss_calls_init())
		return (NULL);
	return ((*calls.rpc_gss_seccreate)(clnt, principal, mechanism,
				service_type, qop, options_req, options_ret));
}

bool_t
rpc_gss_set_defaults(AUTH *auth, rpc_gss_service_t service, char *qop)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_set_defaults)(auth, service, qop));
}

bool_t
rpc_gss_get_principal_name(
	rpc_gss_principal_t	*principal,
	char			*mechanism,
	char			*user_name,
	char			*node,
	char			*secdomain)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_get_principal_name)(principal, mechanism,
					user_name, node, secdomain));
}

char **
rpc_gss_get_mechanisms(void)
{
	if (!rpcgss_calls_init())
		return (NULL);
	return ((*calls.rpc_gss_get_mechanisms)());
}

char **
rpc_gss_get_mech_info(char *mechanism, rpc_gss_service_t *service)
{
	if (!rpcgss_calls_init())
		return (NULL);
	return ((*calls.rpc_gss_get_mech_info)(mechanism, service));
}

bool_t
rpc_gss_get_versions(uint_t *vers_hi, uint_t *vers_lo)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_get_versions)(vers_hi, vers_lo));
}

bool_t
rpc_gss_is_installed(char *mechanism)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_is_installed)(mechanism));
}

bool_t
rpc_gss_set_svc_name(
	char			*principal, /* server service principal name */
	char			*mechanism,
	uint_t			req_time,
	uint_t			program,
	uint_t			version)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_set_svc_name)(principal, mechanism, req_time,
						program, version));
}

bool_t
rpc_gss_set_callback(rpc_gss_callback_t *cb)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_set_callback)(cb));
}

bool_t
rpc_gss_getcred(struct svc_req *req, rpc_gss_rawcred_t **rcred,
					rpc_gss_ucred_t **ucred, void **cookie)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_getcred)(req, rcred, ucred, cookie));
}

bool_t
rpc_gss_mech_to_oid(char *mech, rpc_gss_OID *oid)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_mech_to_oid)(mech, oid));
}

bool_t
rpc_gss_qop_to_num(char *qop, char *mech, uint_t *num)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.rpc_gss_qop_to_num)(qop, mech, num));
}

enum auth_stat
__svcrpcsec_gss(struct svc_req *rqst, struct rpc_msg *msg, bool_t *no_dispatch)
{
	if (!rpcgss_calls_init())
		return (AUTH_FAILED);
	return ((*calls.__svcrpcsec_gss)(rqst, msg, no_dispatch));
}

bool_t
__rpc_gss_wrap(AUTH *auth, char *buf, uint_t buflen, XDR *out_xdrs,
					bool_t (*xdr_func)(), caddr_t xdr_ptr)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.__rpc_gss_wrap)(auth, buf, buflen, out_xdrs,
							xdr_func, xdr_ptr));
}

bool_t
__rpc_gss_unwrap(AUTH *auth, XDR *in_xdrs, bool_t (*xdr_func)(),
								caddr_t xdr_ptr)
{
	if (!rpcgss_calls_init())
		return (FALSE);
	return ((*calls.__rpc_gss_unwrap)(auth, in_xdrs, xdr_func, xdr_ptr));
}

int
rpc_gss_max_data_length(AUTH *rpcgss_handle, int max_tp_unit_len)
{
	if (!rpcgss_calls_init())
		return (0);
	return ((*calls.rpc_gss_max_data_length)(rpcgss_handle,
					max_tp_unit_len));
}

int
rpc_gss_svc_max_data_length(struct svc_req *req, int max_tp_unit_len)
{
	if (!rpcgss_calls_init())
		return (0);
	return ((*calls.rpc_gss_svc_max_data_length)(req, max_tp_unit_len));
}

void
rpc_gss_get_error(rpc_gss_error_t *error)
{
	if (!rpcgss_calls_init()) {
		error->rpc_gss_error = RPC_GSS_ER_SYSTEMERROR;
		error->system_error = ENOTSUP;
		return;
	}
	(*calls.rpc_gss_get_error)(error);
}
