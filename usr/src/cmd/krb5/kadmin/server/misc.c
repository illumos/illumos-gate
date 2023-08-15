/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
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
 */

#include    <k5-int.h>
#include    <krb5/kdb.h>
#include    <kadm5/server_internal.h>
#include    <kadm5/admin.h>
#include    "misc.h"

/*
 * Function: chpass_principal_wrapper_3
 *
 * Purpose: wrapper to kadm5_chpass_principal that checks to see if
 *	    pw_min_life has been reached. if not it returns an error.
 *	    otherwise it calls kadm5_chpass_principal
 *
 * Arguments:
 *	principal	(input) krb5_principals whose password we are
 *				changing
 *	keepold 	(input) whether to preserve old keys
 *	n_ks_tuple	(input) the number of key-salt tuples in ks_tuple
 *	ks_tuple	(input) array of tuples indicating the caller's
 *				requested enctypes/salttypes
 *	password	(input) password we are going to change to.
 * 	<return value>	0 on success error code on failure.
 *
 * Requires:
 *	kadm5_init to have been run.
 *
 * Effects:
 *	calls kadm5_chpass_principal which changes the kdb and the
 *	the admin db.
 *
 */
kadm5_ret_t
chpass_principal_wrapper_3(void *server_handle,
			   krb5_principal principal,
			   krb5_boolean keepold,
			   int n_ks_tuple,
			   krb5_key_salt_tuple *ks_tuple,
			   char *password)
{
    kadm5_ret_t			ret;

    /* Solaris Kerberos */
    ret = kadm5_check_min_life(server_handle, principal, NULL, 0);
    if (ret)
	 return ret;

    return kadm5_chpass_principal_3(server_handle, principal,
				    keepold, n_ks_tuple, ks_tuple,
				    password);
}


/*
 * Function: randkey_principal_wrapper_3
 *
 * Purpose: wrapper to kadm5_randkey_principal which checks the
 *	    password's min. life.
 *
 * Arguments:
 *	principal	    (input) krb5_principal whose password we are
 *				    changing
 *	keepold 	(input) whether to preserve old keys
 *	n_ks_tuple	(input) the number of key-salt tuples in ks_tuple
 *	ks_tuple	(input) array of tuples indicating the caller's
 *				requested enctypes/salttypes
 *	key		    (output) new random key
 * 	<return value>	    0, error code on error.
 *
 * Requires:
 *	kadm5_init	 needs to be run
 *
 * Effects:
 *	calls kadm5_randkey_principal
 *
 */
kadm5_ret_t
randkey_principal_wrapper_3(void *server_handle,
			    krb5_principal principal,
			    krb5_boolean keepold,
			    int n_ks_tuple,
			    krb5_key_salt_tuple *ks_tuple,
			    krb5_keyblock **keys, int *n_keys)
{
    kadm5_ret_t			ret;

    /* Solaris Kerberos */
    ret = kadm5_check_min_life(server_handle, principal, NULL, 0);
    if (ret)
	 return ret;
    return kadm5_randkey_principal_3(server_handle, principal,
				     keepold, n_ks_tuple, ks_tuple,
				     keys, n_keys);
}

kadm5_ret_t
schpw_util_wrapper(void *server_handle, krb5_principal princ,
		   char *new_pw, char **ret_pw,
		   char *msg_ret, unsigned int msg_len)
{
    kadm5_ret_t ret;

    /* Solaris Kerberos */
    ret = kadm5_check_min_life(server_handle, princ, msg_ret, msg_len);
    if (ret)
	return ret;

    return kadm5_chpass_principal_util(server_handle, princ,
				       new_pw, ret_pw,
				       msg_ret, msg_len);
}

kadm5_ret_t
randkey_principal_wrapper(void *server_handle, krb5_principal princ,
			  krb5_keyblock ** keys, int *n_keys)
{
    kadm5_ret_t ret;

    /* Solaris Kerberos */
    ret = kadm5_check_min_life(server_handle, princ, NULL, 0);
	if (ret)
	    return ret;

    return kadm5_randkey_principal(server_handle, princ, keys, n_keys);
}
