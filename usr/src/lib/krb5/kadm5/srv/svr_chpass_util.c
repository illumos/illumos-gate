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

#include "server_internal.h"
#include <kadm5/admin.h>

kadm5_ret_t kadm5_chpass_principal_util(void *server_handle,
					krb5_principal princ,
					char *new_pw,
					char **ret_pw,
					char *msg_ret,
					unsigned int msg_len)
{
  kadm5_server_handle_t handle = server_handle;

  CHECK_HANDLE(server_handle);
  return _kadm5_chpass_principal_util(handle, handle->lhandle, princ,
				      new_pw, ret_pw, msg_ret, msg_len);
}

kadm5_ret_t
kadm5_chpass_principal_v2(void *server_handle,
			krb5_principal princ,
			char *password,
			kadm5_ret_t *srvr_rsp_code,
			krb5_data *srvr_msg)
{
	/* This method of password changing is not supported by the server */
	return (KADM5_FAILURE);
}

krb5_chgpwd_prot
_kadm5_get_kpasswd_protocol(void *handle)
{
	/*
	 * This has to be here because the higher level doesnt know
	 * the details of the handle structure
	 */
	kadm5_server_handle_t srvrhdl = (kadm5_server_handle_t)handle;

	return (srvrhdl->params.kpasswd_protocol);
}
