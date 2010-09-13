#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_ldap/ldap_create.c
 *
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ldap_main.h"
#include "ldap_realm.h"
#include "ldap_principal.h"
#include "ldap_krbcontainer.h"
#include "ldap_err.h"
#include <libintl.h>

/* 
 * ******************************************************************************
 * DAL functions
 * ******************************************************************************
 */

/*
 * This function will create a krbcontainer and realm on the LDAP Server, with
 * the specified attributes.
 */
krb5_error_code
krb5_ldap_create (krb5_context context, char *conf_section, char **db_args)
{
    krb5_error_code status = 0;
    char  **t_ptr = db_args;
    krb5_ldap_realm_params *rparams = NULL;
    kdb5_dal_handle *dal_handle = NULL;
    krb5_ldap_context *ldap_context=NULL;
    krb5_boolean realm_obj_created = FALSE;
    krb5_boolean krbcontainer_obj_created = FALSE;
    krb5_ldap_krbcontainer_params kparams = {0};
    int srv_cnt = 0;
    int mask = 0;
#ifdef HAVE_EDIRECTORY
    int i = 0, rightsmask = 0;
#endif

    /* Clear the global error string */
    krb5_clear_error_message(context);

    ldap_context = malloc(sizeof(krb5_ldap_context));
    if (ldap_context == NULL) {
	status = ENOMEM;
	goto cleanup;
    }
    memset(ldap_context, 0, sizeof(*ldap_context));

    ldap_context->kcontext = context;

    /* populate ldap_context with ldap specific options */
    while (t_ptr && *t_ptr) {
	char *opt = NULL, *val = NULL;

	if ((status = krb5_ldap_get_db_opt(*t_ptr, &opt, &val)) != 0) {
	    goto cleanup;
	}
	if (opt && !strcmp(opt, "binddn")) {
	    if (ldap_context->bind_dn) {
		free (opt);
		free (val);
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'binddn' missing"));
		goto cleanup;
	    }
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'binddn' value missing"));
		free(opt);
		goto cleanup;
	    }
	    ldap_context->bind_dn = strdup(val);
	    if (ldap_context->bind_dn == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto cleanup;
	    }
	} else if (opt && !strcmp(opt, "nconns")) {
	    if (ldap_context->max_server_conns) {
		free (opt);
		free (val);
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'nconns' missing"));
		goto cleanup;
	    }
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'nconns' value missing"));
		free(opt);
		goto cleanup;
	    }
	    ldap_context->max_server_conns = atoi(val) ? atoi(val) : DEFAULT_CONNS_PER_SERVER;
	} else if (opt && !strcmp(opt, "bindpwd")) {
	    if (ldap_context->bind_pwd) {
		free (opt);
		free (val);
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'bindpwd' missing"));
		goto cleanup;
	    }
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'bindpwd' value missing"));
		free(opt);
		goto cleanup;
	    }
	    ldap_context->bind_pwd = strdup(val);
	    if (ldap_context->bind_pwd == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto cleanup;
	    }
	} else if (opt && !strcmp(opt, "host")) {
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'host' value missing"));
		free(opt);
		goto cleanup;
	    }
	    if (ldap_context->server_info_list == NULL)
		ldap_context->server_info_list =
		    (krb5_ldap_server_info **) calloc(SERV_COUNT+1, sizeof(krb5_ldap_server_info *));

	    if (ldap_context->server_info_list == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto cleanup;
	    }

	    ldap_context->server_info_list[srv_cnt] =
		(krb5_ldap_server_info *) calloc(1, sizeof(krb5_ldap_server_info));
	    if (ldap_context->server_info_list[srv_cnt] == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto cleanup;
	    }

	    ldap_context->server_info_list[srv_cnt]->server_status = NOTSET;

	    ldap_context->server_info_list[srv_cnt]->server_name = strdup(val);
	    if (ldap_context->server_info_list[srv_cnt]->server_name == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto cleanup;
	    }

	    srv_cnt++;
#ifdef HAVE_EDIRECTORY
	} else if (opt && !strcmp(opt, "cert")) {
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'cert' value missing"));
		free(opt);
		goto cleanup;
	    }

	    if (ldap_context->root_certificate_file == NULL) {
		ldap_context->root_certificate_file = strdup(val);
		if (ldap_context->root_certificate_file == NULL) {
		    free (opt);
		    free (val);
		    status = ENOMEM;
		    goto cleanup;
		}
	    } else {
		void *tmp=NULL;
		char *oldstr = NULL;
		unsigned int len=0;

		oldstr = strdup(ldap_context->root_certificate_file);
		if (oldstr == NULL) {
		    free (opt);
		    free (val);
		    status = ENOMEM;
		    goto cleanup;
		}

		tmp = ldap_context->root_certificate_file;
		len = strlen(ldap_context->root_certificate_file) + 2 + strlen(val);
		ldap_context->root_certificate_file = realloc(ldap_context->root_certificate_file,
							      len);
		if (ldap_context->root_certificate_file == NULL) {
		    free (tmp);
		    free (opt);
		    free (val);
		    status = ENOMEM;
		    goto cleanup;
		}
		memset(ldap_context->root_certificate_file, 0, len);
		sprintf(ldap_context->root_certificate_file,"%s %s", oldstr, val);
		free (oldstr);
	    }
#endif
	} else {
	/* ignore hash argument. Might have been passed from create */
	    status = EINVAL;
	    if (opt && !strcmp(opt, "temporary")) {
		/* 
		 * temporary is passed in when kdb5_util load without -update is done.
		 * This is unsupported by the LDAP plugin.
		 */
		krb5_set_error_message (context, status,
		    gettext("creation of LDAP entries aborted, plugin requires -update argument"));
	    } else {
		krb5_set_error_message (context, status, gettext("unknown option \'%s\'"),
					opt?opt:val);
	    }
	    free(opt);
	    free(val);
	    goto cleanup;
	}

	free(opt);
	free(val);
	t_ptr++;
    }

    dal_handle = (kdb5_dal_handle *) context->db_context;
    dal_handle->db_context = (kdb5_dal_handle *) ldap_context;

    status = krb5_ldap_read_server_params(context, conf_section, KRB5_KDB_SRV_TYPE_ADMIN);
    if (status) {
	dal_handle->db_context = NULL;
	prepend_err_str (context, gettext("Error reading LDAP server params: "), status, status);
	goto cleanup;
    }
    status = krb5_ldap_db_init(context, ldap_context);
    if (status) {
	goto cleanup;
    }

    /* read the kerberos container */
    if ((status = krb5_ldap_read_krbcontainer_params(context,
			    &(ldap_context->krbcontainer))) == KRB5_KDB_NOENTRY) {

	/* Read the kerberos container location from configuration file */
	if (ldap_context->conf_section) {
	    if ((status = profile_get_string(context->profile,
					   KDB_MODULE_SECTION, ldap_context->conf_section,
					   "ldap_kerberos_container_dn", NULL,
					   &kparams.DN)) != 0) {
		goto cleanup;
	    }
	}
	if (kparams.DN == NULL) {
	    if ((status = profile_get_string(context->profile,
					   KDB_MODULE_DEF_SECTION,
					   "ldap_kerberos_container_dn", NULL,
					   NULL, &kparams.DN)) != 0) {
		goto cleanup;
	    }
	}

	/* create the kerberos container */
	status = krb5_ldap_create_krbcontainer(context,
					       ((kparams.DN != NULL) ? &kparams : NULL));
	if (status)
	    goto cleanup;

	krbcontainer_obj_created = TRUE;

	status = krb5_ldap_read_krbcontainer_params(context,
						    &(ldap_context->krbcontainer));
	if (status) {
	    krb5_set_error_message(context, status, gettext("while reading kerberos container information"));
	    goto cleanup;
	}

    } else if (status) {
	krb5_set_error_message(context, status, gettext("while reading kerberos container information"));
	goto cleanup;
    }

    rparams = (krb5_ldap_realm_params *) malloc(sizeof(krb5_ldap_realm_params));
    if (rparams == NULL) {
	status = ENOMEM;
	goto cleanup;
    }
    memset(rparams, 0, sizeof(*rparams));
    rparams->realm_name = strdup(context->default_realm);
    if (rparams->realm_name == NULL) {
	status = ENOMEM;
	goto cleanup;
    }

    if ((status = krb5_ldap_create_realm(context, rparams, mask))) {
	krb5_set_error_message(context, status, gettext("while creating realm object entry"));
	goto cleanup;
    }

    /* We just created the Realm container. Here starts our transaction tracking */
    realm_obj_created = TRUE;

    /* verify realm object */
    if ((status = krb5_ldap_read_realm_params(context,
					      rparams->realm_name,
					      &(ldap_context->lrparams),
					      &mask))) {
	krb5_set_error_message(context, status, gettext("while reading realm object entry"));
	goto cleanup;
    }

#ifdef HAVE_EDIRECTORY
    if ((mask & LDAP_REALM_KDCSERVERS) || (mask & LDAP_REALM_ADMINSERVERS) ||
	(mask & LDAP_REALM_PASSWDSERVERS)) {

	rightsmask =0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->kdcservers != NULL)) {
	    for (i=0; (rparams->kdcservers[i] != NULL); i++) {
		if ((status=krb5_ldap_add_service_rights(context,
				     LDAP_KDC_SERVICE, rparams->kdcservers[i],
				     rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    goto cleanup;
		}
	    }
	}

	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->adminservers != NULL)) {
	    for (i=0; (rparams->adminservers[i] != NULL); i++) {
		if ((status=krb5_ldap_add_service_rights(context,
				     LDAP_ADMIN_SERVICE, rparams->adminservers[i],
				     rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    goto cleanup;
		}
	    }
	}

	rightsmask = 0;
	rightsmask |= LDAP_REALM_RIGHTS;
	rightsmask |= LDAP_SUBTREE_RIGHTS;
	if ((rparams != NULL) && (rparams->passwdservers != NULL)) {
	    for (i=0; (rparams->passwdservers[i] != NULL); i++) {
		if ((status=krb5_ldap_add_service_rights(context,
				     LDAP_PASSWD_SERVICE, rparams->passwdservers[i],
				     rparams->realm_name, rparams->subtree, rightsmask)) != 0) {
		    goto cleanup;
		}
	    }
	}
    }
#endif

cleanup:

    /* If the krbcontainer/realm creation is not complete, do the roll-back here */
    if ((krbcontainer_obj_created) && (!realm_obj_created)) {
	int rc;
	rc = krb5_ldap_delete_krbcontainer(context,
		    ((kparams.DN != NULL) ? &kparams : NULL));
	krb5_set_error_message(context, rc,
	    gettext("could not complete roll-back, error deleting Kerberos Container"));
    }

    /* should call krb5_ldap_free_krbcontainer_params() but can't */
    if (kparams.DN != NULL)
	krb5_xfree(kparams.DN);

    if (rparams)
	krb5_ldap_free_realm_params(rparams);

    return(status);
}
