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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id: server_init.c 18584 2006-09-13 20:30:23Z raeburn $
 * $Source$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header: /cvs/krbdev/krb5/src/lib/kadm5/srv/server_init.c,v 1.8 2002/10/15 15:40:49 epeisach Exp $";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <com_err.h>
#include "k5-int.h"		/* needed for gssapiP_krb5.h */
#include <kadm5/admin.h>
#include <krb5.h>
#include "server_internal.h"
#include <kdb/kdb_log.h>

/*
 * Function check_handle
 *
 * Purpose: Check a server handle and return a com_err code if it is
 * invalid or 0 if it is valid.
 *
 * Arguments:
 *
 * 	handle		The server handle.
 */

static int check_handle(void *handle)
{
     CHECK_HANDLE(handle);
     return 0;
}

static int dup_db_args(kadm5_server_handle_t handle, char **db_args)
{
    int count  = 0;
    int ret = 0;

    for (count=0; db_args && db_args[count]; count++);
    if (count == 0) {
	handle->db_args = NULL;
	goto clean_n_exit;
    }

    handle->db_args = calloc(sizeof(char*), count+1);
    if (handle->db_args == NULL) {
	ret=ENOMEM;
	goto clean_n_exit;
    }

    for (count=0; db_args[count]; count++) {
	handle->db_args[count] = strdup(db_args[count]);
	if (handle->db_args[count] == NULL) {
	    ret = ENOMEM;
	    goto clean_n_exit;
	}
    }

 clean_n_exit:
    if (ret && handle->db_args) {
	for (count=0; handle->db_args[count]; count++)
	    free(handle->db_args[count]);

	free(handle->db_args), handle->db_args = NULL;
    }

    return ret;
}

static void free_db_args(kadm5_server_handle_t handle)
{
    int count;

    if (handle->db_args) {
	for (count=0; handle->db_args[count]; count++)
	    free(handle->db_args[count]);

	free(handle->db_args), handle->db_args = NULL;
    }
}

kadm5_ret_t kadm5_init_with_password(char *client_name, char *pass,
				     char *service_name,
				     kadm5_config_params *params,
				     krb5_ui_4 struct_version,
				     krb5_ui_4 api_version,
				     char **db_args,
				     void **server_handle)
{
     return kadm5_init(client_name, pass, service_name, params,
		       struct_version, api_version, db_args,
		       server_handle);
}

kadm5_ret_t kadm5_init_with_creds(char *client_name,
				  krb5_ccache ccache,
				  char *service_name,
				  kadm5_config_params *params,
				  krb5_ui_4 struct_version,
				  krb5_ui_4 api_version,
				  char **db_args,
				  void **server_handle)
{
     /*
      * A program calling init_with_creds *never* expects to prompt the
      * user.  Therefore, always pass a dummy password in case this is
      * KADM5_API_VERSION_1.  If this is KADM5_API_VERSION_2 and
      * MKEY_FROM_KBD is non-zero, return an error.
      */
     if (api_version == KADM5_API_VERSION_2 && params &&
	 (params->mask & KADM5_CONFIG_MKEY_FROM_KBD) &&
	 params->mkey_from_kbd)
	  return KADM5_BAD_SERVER_PARAMS;
     return kadm5_init(client_name, NULL, service_name, params,
		       struct_version, api_version, db_args,
		       server_handle);
}


kadm5_ret_t kadm5_init_with_skey(char *client_name, char *keytab,
				 char *service_name,
				 kadm5_config_params *params,
				 krb5_ui_4 struct_version,
				 krb5_ui_4 api_version,
				 char **db_args,
				 void **server_handle)
{
     /*
      * A program calling init_with_skey *never* expects to prompt the
      * user.  Therefore, always pass a dummy password in case this is
      * KADM5_API_VERSION_1.  If this is KADM5_API_VERSION_2 and
      * MKEY_FROM_KBD is non-zero, return an error.
      */
     if (api_version == KADM5_API_VERSION_2 && params &&
	 (params->mask & KADM5_CONFIG_MKEY_FROM_KBD) &&
	 params->mkey_from_kbd)
	  return KADM5_BAD_SERVER_PARAMS;
     return kadm5_init(client_name, NULL, service_name, params,
		       struct_version, api_version, db_args,
		       server_handle);
}

/*
 * Solaris Kerberos:
 * A private extended version of kadm5_init which potentially
 * returns more information in case of an error.
 */
kadm5_ret_t kadm5_init2(char *client_name, char *pass,
		       char *service_name,
		       kadm5_config_params *params_in,
		       krb5_ui_4 struct_version,
		       krb5_ui_4 api_version,
		       char **db_args,
		       void **server_handle,
		       char **emsg)
{
     int ret;
     kadm5_server_handle_t handle;
     kadm5_config_params params_local; /* for v1 compat */

    if (emsg)
	*emsg = NULL;

    if (! server_handle)
	 return EINVAL;

    if (! client_name)
	 return EINVAL;

    if (! (handle = (kadm5_server_handle_t) malloc(sizeof *handle)))
	 return ENOMEM;
    memset(handle, 0, sizeof(*handle));

    ret = dup_db_args(handle, db_args);
    if (ret) {
	free(handle);
	return ret;
    }

    ret = (int) krb5int_init_context_kdc(&(handle->context));
    if (ret) {
	 free_db_args(handle);
	 free(handle);
	 return(ret);
    }

    handle->magic_number = KADM5_SERVER_HANDLE_MAGIC;
    handle->struct_version = struct_version;
    handle->api_version = api_version;

     /*
      * Verify the version numbers before proceeding; we can't use
      * CHECK_HANDLE because not all fields are set yet.
      */
     GENERIC_CHECK_HANDLE(handle, KADM5_OLD_SERVER_API_VERSION,
			  KADM5_NEW_SERVER_API_VERSION);

     /*
      * Acquire relevant profile entries.  In version 2, merge values
      * in params_in with values from profile, based on
      * params_in->mask.
      *
      * In version 1, we've given a realm (which may be NULL) instead
      * of params_in.  So use that realm, make params_in contain an
      * empty mask, and behave like version 2.
      */
     memset((char *) &params_local, 0, sizeof(params_local));
     if (api_version == KADM5_API_VERSION_1) {
	  params_local.realm = (char *) params_in;
	  if (params_in)
	       params_local.mask = KADM5_CONFIG_REALM;
	  params_in = &params_local;
     }

#if 0 /* Now that we look at krb5.conf as well as kdc.conf, we can
	 expect to see admin_server being set sometimes.  */
#define ILLEGAL_PARAMS (KADM5_CONFIG_ADMIN_SERVER)
     if (params_in && (params_in->mask & ILLEGAL_PARAMS)) {
	  krb5_free_context(handle->context);
	  free_db_args(handle);
	  free(handle);
	  return KADM5_BAD_SERVER_PARAMS;
     }
#endif

     ret = kadm5_get_config_params(handle->context, 1, params_in,
				       &handle->params);
     if (ret) {
	  krb5_free_context(handle->context);
	  free_db_args(handle);
	  free(handle);
	  return(ret);
     }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | KADM5_CONFIG_DBNAME | \
			 KADM5_CONFIG_ADBNAME | \
			 KADM5_CONFIG_ADB_LOCKFILE | \
			 KADM5_CONFIG_ENCTYPE | \
			 KADM5_CONFIG_FLAGS | \
			 KADM5_CONFIG_MAX_LIFE | KADM5_CONFIG_MAX_RLIFE | \
			 KADM5_CONFIG_EXPIRATION | KADM5_CONFIG_ENCTYPES)

     if ((handle->params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
	  kadm5_free_config_params(handle->context, &handle->params);
	  krb5_free_context(handle->context);
	  free_db_args(handle);
	  free(handle);
	  return KADM5_MISSING_CONF_PARAMS;
     }

     ret = krb5_set_default_realm(handle->context, handle->params.realm);
     if (ret) {
	  kadm5_free_config_params(handle->context, &handle->params);
	  krb5_free_context(handle->context);
	  free_db_args(handle);
	  free(handle);
	  return ret;
     }

    ret = krb5_db_open(handle->context, db_args,
		       KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN);
    if (ret) {
	 if (emsg) {
		 const char *m = krb5_get_error_message(handle->context, ret);
		 *emsg = strdup(m);
		 krb5_free_error_message(handle->context, m);
	 }
	 kadm5_free_config_params(handle->context, &handle->params);
	 krb5_free_context(handle->context);
	 free_db_args(handle);
	 free(handle);
	 return(ret);
    }

    if ((ret = krb5_parse_name(handle->context, client_name,
			       &handle->current_caller))) {
	 krb5_db_fini(handle->context);
	 kadm5_free_config_params(handle->context, &handle->params);
	 krb5_free_context(handle->context);
	 free_db_args(handle);
	 free(handle);
	 return ret;
    }

    if (! (handle->lhandle = malloc(sizeof(*handle)))) {
	 krb5_db_fini(handle->context);
	 kadm5_free_config_params(handle->context, &handle->params);
	 krb5_free_context(handle->context);
	 free_db_args(handle);
	 free(handle);
	 return ENOMEM;
    }
    *handle->lhandle = *handle;
    handle->lhandle->api_version = KADM5_API_VERSION_2;
    handle->lhandle->struct_version = KADM5_STRUCT_VERSION;
    handle->lhandle->lhandle = handle->lhandle;

    /* can't check the handle until current_caller is set */
    ret = check_handle((void *) handle);
    if (ret) {
	krb5_db_fini(handle->context);
	kadm5_free_config_params(handle->context, &handle->params);
	krb5_free_context(handle->context);
	free_db_args(handle);
	free(handle);
	return ret;
    }

    /*
     * The KADM5_API_VERSION_1 spec said "If pass (or keytab) is NULL
     * or an empty string, reads the master password from [the stash
     * file].  Otherwise, the non-NULL password is ignored and the
     * user is prompted for it via the tty."  However, the code was
     * implemented the other way: when a non-NULL password was
     * provided, the stash file was used.  This is somewhat more
     * sensible, as then a local or remote client that provides a
     * password does not prompt the user.  This code maintains the
     * previous actual behavior, and not the old spec behavior,
     * because that is how the unit tests are written.
     *
     * In KADM5_API_VERSION_2, this decision is controlled by
     * params.
     *
     * kdb_init_master's third argument is "from_keyboard".
     */
    /*
     * Solaris Kerberos: Setting to an unknown enc type will make the function
     * read the encryption type in the stash file instead of assumming that it
     * is the default type.
     */
    if (handle->params.enctype == DEFAULT_KDC_ENCTYPE)
	handle->params.enctype = ENCTYPE_UNKNOWN;
    ret = kdb_init_master(handle, handle->params.realm,
			  (handle->api_version == KADM5_API_VERSION_1 ?
			   ((pass == NULL) || !(strlen(pass))) :
			   ((handle->params.mask & KADM5_CONFIG_MKEY_FROM_KBD)
			    && handle->params.mkey_from_kbd)
			));
    if (ret) {
	krb5_db_fini(handle->context);
	kadm5_free_config_params(handle->context, &handle->params);
	krb5_free_context(handle->context);
	free_db_args(handle);
	free(handle);
	return ret;
    }
    /*
     * Solaris Kerberos: We used the enc type that was discovered in the stash
     * file to associate with the other magic principals in the database.
     */
    handle->params.enctype = handle->master_keyblock.enctype;

    ret = kdb_init_hist(handle, handle->params.realm);
    if (ret) {
	 krb5_db_fini(handle->context);
	 kadm5_free_config_params(handle->context, &handle->params);
	 krb5_free_context(handle->context);
	 free_db_args(handle);
	 free(handle);
	 return ret;
    }

    ret = init_dict(&handle->params);
    if (ret) {
	 krb5_db_fini(handle->context);
	 krb5_free_principal(handle->context, handle->current_caller);
	 kadm5_free_config_params(handle->context, &handle->params);
	 krb5_free_context(handle->context);
	 free_db_args(handle);
	 free(handle);
	 return ret;
    }

    *server_handle = (void *) handle;

    return KADM5_OK;
}

kadm5_ret_t kadm5_init(char *client_name, char *pass,
		       char *service_name,
		       kadm5_config_params *params_in,
		       krb5_ui_4 struct_version,
		       krb5_ui_4 api_version,
		       char **db_args,
		       void **server_handle) {
	return (kadm5_init2(client_name, pass, service_name, params_in,
	    struct_version, api_version, db_args, server_handle, NULL));

}

kadm5_ret_t kadm5_destroy(void *server_handle)
{
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    destroy_dict();

    adb_policy_close(handle);
    krb5_db_fini(handle->context);
    krb5_free_principal(handle->context, handle->current_caller);
    kadm5_free_config_params(handle->context, &handle->params);
    krb5_free_context(handle->context);
    handle->magic_number = 0;
    free(handle->lhandle);
    free_db_args(handle);
    free(handle);

    return KADM5_OK;
}

kadm5_ret_t kadm5_lock(void *server_handle)
{
    kadm5_server_handle_t handle = server_handle;
    kadm5_ret_t ret;

    CHECK_HANDLE(server_handle);
    ret = krb5_db_lock(handle->context, KRB5_DB_LOCKMODE_EXCLUSIVE);
    if (ret)
	return ret;

    return KADM5_OK;
}

kadm5_ret_t kadm5_unlock(void *server_handle)
{
    kadm5_server_handle_t handle = server_handle;
    kadm5_ret_t ret;

    CHECK_HANDLE(server_handle);
    ret = krb5_db_unlock(handle->context);
    if (ret)
	return ret;

    return KADM5_OK;
}

kadm5_ret_t kadm5_flush(void *server_handle)
{
     kadm5_server_handle_t handle = server_handle;
     kadm5_ret_t ret;

     CHECK_HANDLE(server_handle);

     if ((ret = krb5_db_fini(handle->context)) ||
	 (ret = krb5_db_open(handle->context, handle->db_args,
			     KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_ADMIN)) ||
	 (ret = adb_policy_close(handle)) ||
	 (ret = adb_policy_init(handle))) {
	  (void) kadm5_destroy(server_handle);
	  return ret;
     }
     return KADM5_OK;
}

int _kadm5_check_handle(void *handle)
{
     CHECK_HANDLE(handle);
     return 0;
}

#include "gssapiP_krb5.h"
krb5_error_code kadm5_init_krb5_context (krb5_context *ctx)
{
    /* Solaris Kerberos: not needed */
#if 0 /************** Begin IFDEF'ed OUT *******************************/
    static int first_time = 1;
    if (first_time) {
	krb5_error_code err;
	err = krb5_gss_use_kdc_context();
	if (err)
	    return err;
	first_time = 0;
    }
#endif /**************** END IFDEF'ed OUT *******************************/
    return krb5int_init_context_kdc(ctx);
}

krb5_error_code
kadm5_init_iprop(void *handle)
{
	kadm5_server_handle_t iprop_h;
	krb5_error_code retval;

	iprop_h = handle;
	if (iprop_h->params.iprop_enabled) {
		ulog_set_role(iprop_h->context, IPROP_MASTER);
		if ((retval = ulog_map(iprop_h->context, &iprop_h->params,
		    FKCOMMAND)) != 0)
			return (retval);
	}
	return (0);
}
