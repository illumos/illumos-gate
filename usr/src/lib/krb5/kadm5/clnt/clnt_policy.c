/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <rpc/rpc.h> /* SUNWresync121 XXX */
#include    <kadm5/admin.h>
#include    <kadm5/kadm_rpc.h>
#include    "client_internal.h"
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>

kadm5_ret_t
kadm5_create_policy(void *server_handle,
			 kadm5_policy_ent_t policy, long mask)
{
    cpol_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(policy == (kadm5_policy_ent_t) NULL)
	return EINVAL;

    arg.mask = mask;
    arg.api_version = handle->api_version;
    memcpy(&arg.rec, policy, sizeof(kadm5_policy_ent_rec));
    r = create_policy_2(&arg, handle->clnt);
    if(r == NULL)
	return KADM5_RPC_ERROR;

    return r->code;
}

kadm5_ret_t
kadm5_delete_policy(void *server_handle, char *name)
{
    dpol_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(name == NULL)
	return EINVAL;

    arg.name = name;
    arg.api_version = handle->api_version;

    r = delete_policy_2(&arg, handle->clnt);
    if(r == NULL)
	return KADM5_RPC_ERROR;

    return r->code;
}

kadm5_ret_t
kadm5_modify_policy(void *server_handle,
			 kadm5_policy_ent_t policy, long mask)
{
    mpol_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(policy == (kadm5_policy_ent_t) NULL)
	return EINVAL;

    arg.mask = mask;
    arg.api_version = handle->api_version;

    memcpy(&arg.rec, policy, sizeof(kadm5_policy_ent_rec));
    r = modify_policy_2(&arg, handle->clnt);
    if(r == NULL)
	return KADM5_RPC_ERROR;

    return r->code;
}

kadm5_ret_t
kadm5_get_policy(void *server_handle, char *name, kadm5_policy_ent_t ent)
{
    gpol_arg	    arg;
    gpol_ret	    *r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.name = name;
    arg.api_version = handle->api_version;

    if(name == NULL)
	return EINVAL;

    r = get_policy_2(&arg, handle->clnt);
    if(r == NULL)
	return KADM5_RPC_ERROR;
    if (handle->api_version == KADM5_API_VERSION_1) {
	 kadm5_policy_ent_t *entp;

	 entp = (kadm5_policy_ent_t *) ent;
	 if(r->code == 0) {
	      if (!(*entp = (kadm5_policy_ent_t)
		    malloc(sizeof(kadm5_policy_ent_rec))))
		   return ENOMEM;
	      memcpy(*entp, &r->rec, sizeof(**entp));
	 } else {
	      *entp = NULL;
	 }
    } else {
	 if (r->code == 0)
	      memcpy(ent, &r->rec, sizeof(r->rec));
    }

    return r->code;
}

kadm5_ret_t
kadm5_get_policies(void *server_handle,
			  char *exp, char ***pols, int *count)
{
    gpols_arg	arg;
    gpols_ret	*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(pols == NULL || count == NULL)
	return EINVAL;
    arg.exp = exp;
    arg.api_version = handle->api_version;
    r = get_pols_2(&arg, handle->clnt);
    if(r == NULL)
	return KADM5_RPC_ERROR;
    if(r->code == 0) {
	 *count = r->count;
	 *pols = r->pols;
    } else {
	 *count = 0;
	 *pols = NULL;
    }

    return r->code;
}
