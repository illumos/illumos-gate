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
#include	"server_internal.h"
#include	<kadm5/admin.h>
#include	<stdlib.h>

kadm5_ret_t
kadm5_free_policy_ent(void *server_handle, kadm5_policy_ent_t val)
{
    kadm5_server_handle_t	handle = server_handle;

    _KADM5_CHECK_HANDLE(server_handle);

    if(val) {
	if (val->policy)
	    free(val->policy);
	if (handle->api_version == KADM5_API_VERSION_1)
	     free(val);
    }
    return KADM5_OK;
}

kadm5_ret_t
     kadm5_free_name_list(void *server_handle, char **names, int count)
{
    _KADM5_CHECK_HANDLE(server_handle);

    while (count--)
	  free(names[count]);
     free(names);
    return KADM5_OK;
}

/* XXX this ought to be in libkrb5.a, but isn't */
kadm5_ret_t krb5_free_key_data_contents(context, key)
   krb5_context context;
   krb5_key_data *key;
{
     int i, idx;

     idx = (key->key_data_ver == 1 ? 1 : 2);
     for (i = 0; i < idx; i++) {
	  if (key->key_data_contents[i]) {
	       memset(key->key_data_contents[i], 0, key->key_data_length[i]);
	       free(key->key_data_contents[i]);
	  }
     }
     return KADM5_OK;
}

kadm5_ret_t kadm5_free_key_data(void *server_handle,
				krb5_int16 *n_key_data,
				krb5_key_data *key_data)
{
     kadm5_server_handle_t	handle = server_handle;
     int i, nkeys = (int) *n_key_data;

     _KADM5_CHECK_HANDLE(server_handle);

     if (key_data == NULL)
	  return KADM5_OK;

     for (i = 0; i < nkeys; i++)
	  krb5_free_key_data_contents(handle->context, &key_data[i]);
     free(key_data);
     return KADM5_OK;
}

kadm5_ret_t
kadm5_free_principal_ent(void *server_handle,
			      kadm5_principal_ent_t val)
{
    kadm5_server_handle_t	handle = server_handle;
    int i;

    _KADM5_CHECK_HANDLE(server_handle);

    if(val) {
	if(val->principal)
	    krb5_free_principal(handle->context, val->principal);
	if(val->mod_name)
	    krb5_free_principal(handle->context, val->mod_name);
	if(val->policy)
	    free(val->policy);
	if (handle->api_version > KADM5_API_VERSION_1) {
	     if (val->n_key_data) {
		  for (i = 0; i < val->n_key_data; i++)
		       krb5_free_key_data_contents(handle->context,
						   &val->key_data[i]);
		  free(val->key_data);
	     }
	     if (val->tl_data) {
		  krb5_tl_data *tl;

		  while (val->tl_data) {
		       tl = val->tl_data->tl_data_next;
		       free(val->tl_data->tl_data_contents);
		       free(val->tl_data);
		       val->tl_data = tl;
		  }
	     }
	}

	if (handle->api_version == KADM5_API_VERSION_1)
	     free(val);
    }
    return KADM5_OK;
}
