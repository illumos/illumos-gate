#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * $Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/kadmin/\
 * server/misc.c,v 1.10 1996/07/22 20:28:55 marc Exp $
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header: /afs/athena.mit.edu/astaff/project/krbdev"
	"/.cvsroot/src/kadmin/server/misc.c,v 1.10 1996/07/22 20:28:55 "
	"marc Exp $";

#endif

#include    <kadm5/adb.h>
#include    <kadm5/server_internal.h>
#include    <krb5/kdb.h>
#include    "misc.h"

/*
 * Function: chpass_principal_wrapper
 *
 * Purpose: wrapper to kadm5_chpass_principal that checks to see if
 *	    pw_min_life has been reached. if not it returns an error.
 *	    otherwise it calls kadm5_chpass_principal
 *
 * Arguments:
 *	principal	(input) krb5_principals whose password we are
 *				changing
 *	passoword	(input) passowrd we are going to change to.
 * 	<return value>	0 on sucsess error code on failure.
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
chpass_principal_wrapper(void *server_handle,
    krb5_principal principal, char *password)
{
	krb5_int32 now;
	kadm5_ret_t ret;
	kadm5_policy_ent_rec pol;
	kadm5_principal_ent_rec princ;
	kadm5_server_handle_t handle = server_handle;

	if (ret = krb5_timeofday(handle->context, &now))
		return (ret);

	if ((ret = kadm5_get_principal(handle->lhandle, principal,
		    &princ,
		    KADM5_PRINCIPAL_NORMAL_MASK)) !=
	    KADM5_OK)
		return (ret);
	if (princ.aux_attributes & KADM5_POLICY) {
		if ((ret = kadm5_get_policy(handle->lhandle,
			    princ.policy, &pol)) != KADM5_OK) {
			(void) kadm5_free_principal_ent(handle->lhandle,
							&princ);
			return (ret);
		}
		if ((now - princ.last_pwd_change) < pol.pw_min_life &&
		    !(princ.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
			(void) kadm5_free_policy_ent(handle->lhandle, &pol);
			(void) kadm5_free_principal_ent(handle->lhandle,
							&princ);
			return (KADM5_PASS_TOOSOON);
		}
		if (ret = kadm5_free_policy_ent(handle->lhandle, &pol)) {
			(void) kadm5_free_principal_ent(handle->lhandle,
							&princ);
			return (ret);
		}
	}
	if (ret = kadm5_free_principal_ent(handle->lhandle, &princ))
		return (ret);

	return (kadm5_chpass_principal(server_handle, principal, password));
}


/*
 * Function: randkey_principal_wrapper
 *
 * Purpose: wrapper to kadm5_randkey_principal which checks the
 *	    passwords min. life.
 *
 * Arguments:
 *	principal	    (input) krb5_principal whose password we are
 *				    changing
 *	key		    (output) new random key
 * 	< return value >    0, error code on error.
 *
 * Requires:
 *	kadm5_init	 needs to be run
 *
 * Effects:
 *	calls kadm5_randkey_principal
 *
 */
kadm5_ret_t
randkey_principal_wrapper(void *server_handle,
    krb5_principal principal,
    krb5_keyblock ** keys, int *n_keys)
{

	krb5_int32 now;
	kadm5_ret_t ret;
	kadm5_policy_ent_rec pol;
	kadm5_principal_ent_rec princ;
	kadm5_server_handle_t handle = server_handle;

	if (ret = krb5_timeofday(handle->context, &now))
		return (ret);

	if ((ret = kadm5_get_principal(handle->lhandle,
		    principal, &princ,
		    KADM5_PRINCIPAL_NORMAL_MASK)) !=
	    OSA_ADB_OK)
		return (ret);
	if (princ.aux_attributes & KADM5_POLICY) {
		if ((ret = kadm5_get_policy(handle->lhandle,
			    princ.policy, &pol)) != KADM5_OK) {
			(void) kadm5_free_principal_ent(handle->lhandle,
							&princ);
			return (ret);
		}
		if ((now - princ.last_pwd_change) < pol.pw_min_life &&
		    !(princ.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
			(void) kadm5_free_policy_ent(handle->lhandle, &pol);
			(void) kadm5_free_principal_ent(handle->lhandle,
							&princ);
			return (KADM5_PASS_TOOSOON);
		}
		if (ret = kadm5_free_policy_ent(handle->lhandle, &pol)) {
			(void) kadm5_free_principal_ent(handle->lhandle,
							&princ);
			return (ret);
		}
	}
	if (ret = kadm5_free_principal_ent(handle->lhandle, &princ))
		return (ret);
	return (kadm5_randkey_principal(server_handle,
					principal, keys, n_keys));
}
