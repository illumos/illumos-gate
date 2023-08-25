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
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif
#include	<kadm5/admin.h>
#include	<stdlib.h>
#include	"server_internal.h"

kadm5_ret_t
kadm5_free_principal_ent(void *server_handle,
			      kadm5_principal_ent_t val)
{
    kadm5_server_handle_t	handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(val) {
	if(val->principal)
	    krb5_free_principal(handle->context, val->principal);
	if(val->mod_name)
	    krb5_free_principal(handle->context, val->mod_name);
	if(val->policy)
	    free(val->policy);

	/* XXX free key_data and tl_data */

	if (handle->api_version == KADM5_API_VERSION_1)
	     free(val);
    }
    return KADM5_OK;
}
