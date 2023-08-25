/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _MISC_H
#define	_MISC_H


#ifdef	__cplusplus
extern "C" {
#endif

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
 * Copyright 1994 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

kadm5_ret_t
chpass_principal_wrapper_3(void *server_handle,
			   krb5_principal principal,
			   krb5_boolean keepold,
			   int n_ks_tuple,
			   krb5_key_salt_tuple *ks_tuple,
			   char *password);

kadm5_ret_t
randkey_principal_wrapper_3(void *server_handle,
			    krb5_principal principal,
			    krb5_boolean keepold,
			    int n_ks_tuple,
			    krb5_key_salt_tuple *ks_tuple,
			    krb5_keyblock **keys, int *n_keys);

kadm5_ret_t
schpw_util_wrapper(void *server_handle, krb5_principal princ,
		   char *new_pw, char **ret_pw,
		   char *msg_ret, unsigned int msg_len);

kadm5_ret_t kadm5_get_principal_v1(void *server_handle,
				   krb5_principal principal,
				   kadm5_principal_ent_t_v1 *ent);

kadm5_ret_t kadm5_get_policy_v1(void *server_handle, kadm5_policy_t name,
				kadm5_policy_ent_t *ent);


krb5_error_code process_chpw_request(krb5_context context,
				     void *server_handle,
				     char *realm, int s,
				     krb5_keytab keytab,
				     struct sockaddr_in *sockin,
				     krb5_data *req, krb5_data *rep);

#ifdef SVC_GETARGS
void  kadm_1(struct svc_req *, SVCXPRT *);
#endif

void trunc_name(size_t *len, char **dots);

#ifdef	__cplusplus
}
#endif

#endif	/* !_MISC_H */

