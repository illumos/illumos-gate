/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kdb/kdb_ldap/kdb_ldap.c
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

#include "autoconf.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>
#include "kdb_ldap.h"
#include "ldap_misc.h"
#include "ldap_main.h"
#include <kdb5.h>
#include <kadm5/admin.h>
/* Solaris Kerberos: needed for MAKE_INIT_FUNCTION() */
#include <k5-platform.h>
#include <k5-int.h>
#include <libintl.h>

krb5_error_code
krb5_ldap_get_db_opt(char *input, char **opt, char **val)
{
    char *pos = strchr(input, '=');

    *val = NULL;
    if (pos == NULL) {
	*opt = strdup(input);
	if (*opt == NULL) {
	    return ENOMEM;
	}
    } else {
	int len = pos - input;
	*opt = malloc((unsigned) len + 1);
	if (!*opt) {
	    return ENOMEM;
	}
	memcpy(*opt, input, (unsigned) len);
	/* ignore trailing blanks */
	while (isblank((*opt)[len-1]))
	    --len;
	(*opt)[len] = '\0';

	pos += 1; /* move past '=' */
	while (isblank(*pos))  /* ignore leading blanks */
	    pos += 1;
	if (*pos != '\0') {
	    *val = strdup (pos);
	    if (!*val) {
		free (*opt);
		return ENOMEM;
	    }
	}
    }
    return (0);

}


/*
 * ldap get age
 */
/*ARGSUSED*/
krb5_error_code
krb5_ldap_db_get_age(context, db_name, age)
    krb5_context context;
    char *db_name;
    time_t *age;
{
    time (age);
    return 0;
}

/*
 * read startup information - kerberos and realm container
 */
krb5_error_code
krb5_ldap_read_startup_information(krb5_context context)
{
    krb5_error_code      retval = 0;
    kdb5_dal_handle      *dal_handle=NULL;
    krb5_ldap_context    *ldap_context=NULL;
    int                  mask = 0;

    SETUP_CONTEXT();
    if ((retval=krb5_ldap_read_krbcontainer_params(context, &(ldap_context->krbcontainer)))) {
	prepend_err_str (context, gettext("Unable to read Kerberos container"), retval, retval);
	goto cleanup;
    }

    if ((retval=krb5_ldap_read_realm_params(context, context->default_realm, &(ldap_context->lrparams), &mask))) {
	prepend_err_str (context, gettext("Unable to read Realm"), retval, retval);
	goto cleanup;
    }

    if (((mask & LDAP_REALM_MAXTICKETLIFE) == 0) || ((mask & LDAP_REALM_MAXRENEWLIFE) == 0)
                                                 || ((mask & LDAP_REALM_KRBTICKETFLAGS) == 0)) {
        kadm5_config_params  params_in, params_out;

        memset((char *) &params_in, 0, sizeof(params_in));
        memset((char *) &params_out, 0, sizeof(params_out));

        retval = kadm5_get_config_params(context, 1, &params_in, &params_out);
        if (retval) {
            if ((mask & LDAP_REALM_MAXTICKETLIFE) == 0) {
                ldap_context->lrparams->max_life = 24 * 60 * 60; /* 1 day */
            }
            if ((mask & LDAP_REALM_MAXRENEWLIFE) == 0) {
                ldap_context->lrparams->max_renewable_life = 0;
            }
            if ((mask & LDAP_REALM_KRBTICKETFLAGS) == 0) {
                ldap_context->lrparams->tktflags = KRB5_KDB_DEF_FLAGS;
            }
            retval = 0;
            goto cleanup;
        }

        if ((mask & LDAP_REALM_MAXTICKETLIFE) == 0) {
            if (params_out.mask & KADM5_CONFIG_MAX_LIFE)
                ldap_context->lrparams->max_life = params_out.max_life;
        }

        if ((mask & LDAP_REALM_MAXRENEWLIFE) == 0) {
            if (params_out.mask & KADM5_CONFIG_MAX_RLIFE)
                ldap_context->lrparams->max_renewable_life = params_out.max_rlife;
        }

        if ((mask & LDAP_REALM_KRBTICKETFLAGS) == 0) {
            if (params_out.mask & KADM5_CONFIG_FLAGS)
                ldap_context->lrparams->tktflags = params_out.flags;
        }

        kadm5_free_config_params(context, &params_out);
    }

cleanup:
    return retval;
}


/* Function to check if a LDAP server supports the SASL external mechanism
 *Return values:
 *   0 => supports
 *   1 => does not support
 *   2 => don't know
 */
#define ERR_MSG1 "Unable to check if SASL EXTERNAL mechanism is supported by LDAP server. Proceeding anyway ..."
#define ERR_MSG2 "SASL EXTERNAL mechanism not supported by LDAP server. Can't perform certificate-based bind."

int
has_sasl_external_mech(context, ldap_server)
    krb5_context     context;
    char             *ldap_server;
{
    int               i=0, flag=0, ret=0, retval=0;
    char              *attrs[]={"supportedSASLMechanisms", NULL}, **values=NULL;
    LDAP              *ld=NULL;
    LDAPMessage       *msg=NULL, *res=NULL;

    /*
     * Solaris Kerberos: don't use SSL since we are checking to see if SASL
     * Externnal mech is supported.
     */
    retval = ldap_initialize(&ld, ldap_server, SSL_OFF, NULL);
    if (retval != LDAP_SUCCESS) {
	krb5_set_error_message(context, 2, "%s", ERR_MSG1);
	ret = 2; /* Don't know */
	goto cleanup;
    }

    /* Solaris Kerberos: anon bind not needed */
#if 0 /************** Begin IFDEF'ed OUT *******************************/
    /* Anonymous bind */
    retval = ldap_sasl_bind_s(ld, NULL, NULL, NULL, NULL, NULL, NULL);
    if (retval != LDAP_SUCCESS) {
	krb5_set_error_message(context, 2, "%s", ERR_MSG1);
	ret = 2; /* Don't know */
	goto cleanup;
    }
#endif /**************** END IFDEF'ed OUT *******************************/

    retval = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, NULL, attrs, 0, NULL, NULL, NULL, 0, &res);
    if (retval != LDAP_SUCCESS) {
	krb5_set_error_message(context, 2, "%s", ERR_MSG1);
	ret = 2; /* Don't know */
	goto cleanup;
    }

#if 0 /************** Begin IFDEF'ed OUT *******************************/
    msg = ldap_first_message(ld, res);
#else
    /* Solaris Kerberos: more accurate */
    msg = ldap_first_entry(ld, res);
#endif /**************** END IFDEF'ed OUT *******************************/
    if (msg == NULL) {
	krb5_set_error_message(context, 2, "%s", ERR_MSG1);
	ret = 2; /* Don't know */
	goto cleanup;
    }

    values = ldap_get_values(ld, msg, "supportedSASLMechanisms");
    if (values == NULL) {
	krb5_set_error_message(context, 1, "%s", ERR_MSG2);
	ret = 1; /* Not supported */
	goto cleanup;
    }

    for (i = 0; values[i] != NULL; i++) {
	if (strcmp(values[i], "EXTERNAL"))
	    continue;
	flag = 1;
    }

    if (flag != 1) {
	krb5_set_error_message(context, 1, "%s", ERR_MSG2);
	ret = 1; /* Not supported */
	goto cleanup;
    }

cleanup:

    if (values != NULL)
	ldap_value_free(values);

    if (res != NULL)
	ldap_msgfree(res);

    if (ld != NULL)
	ldap_unbind_ext_s(ld, NULL, NULL);

    return ret;
}

/*ARGSUSED*/
void * krb5_ldap_alloc(krb5_context context, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

/*ARGSUSED*/
void krb5_ldap_free(krb5_context context, void *ptr)

{
    free(ptr);
}

krb5_error_code krb5_ldap_open(krb5_context context,
			       char *conf_section,
			       char **db_args,
			       int mode)
{
    krb5_error_code status  = 0;
    char **t_ptr = db_args;
    krb5_ldap_context *ldap_context=NULL;
    int srv_cnt = 0;
    kdb5_dal_handle *dal_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    ldap_context = calloc(1, sizeof(krb5_ldap_context));
    if (ldap_context == NULL) {
	status = ENOMEM;
	goto clean_n_exit;
    }

    ldap_context->kcontext = context;

    while (t_ptr && *t_ptr) {
	char *opt = NULL, *val = NULL;

	if ((status = krb5_ldap_get_db_opt(*t_ptr, &opt, &val)) != 0) {
	    goto clean_n_exit;
	}
	if (opt && !strcmp(opt, "binddn")) {
	    if (ldap_context->bind_dn) {
		free (opt);
		free (val);
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'binddn' missing"));
		goto clean_n_exit;
	    }
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'binddn' value missing"));
		free(opt);
		goto clean_n_exit;
	    }
	    ldap_context->bind_dn = strdup(val);
	    if (ldap_context->bind_dn == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto clean_n_exit;
	    }
	} else if (opt && !strcmp(opt, "nconns")) {
	    if (ldap_context->max_server_conns) {
		free (opt);
		free (val);
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'nconns' missing"));
		goto clean_n_exit;
	    }
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'nconns' value missing"));
		free(opt);
		goto clean_n_exit;
	    }
	    ldap_context->max_server_conns = atoi(val) ? atoi(val) : DEFAULT_CONNS_PER_SERVER;
	} else if (opt && !strcmp(opt, "bindpwd")) {
	    if (ldap_context->bind_pwd) {
		free (opt);
		free (val);
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'bindpwd' missing"));
		goto clean_n_exit;
	    }
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'bindpwd' value missing"));
		free(opt);
		goto clean_n_exit;
	    }
	    ldap_context->bind_pwd = strdup(val);
	    if (ldap_context->bind_pwd == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto clean_n_exit;
	    }
	} else if (opt && !strcmp(opt, "host")) {
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'host' value missing"));
		free(opt);
		goto clean_n_exit;
	    }
	    if (ldap_context->server_info_list == NULL)
		ldap_context->server_info_list = (krb5_ldap_server_info **) calloc (SERV_COUNT+1, sizeof (krb5_ldap_server_info *)) ;

	    if (ldap_context->server_info_list == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto clean_n_exit;
	    }

	    ldap_context->server_info_list[srv_cnt] = (krb5_ldap_server_info *) calloc (1, sizeof (krb5_ldap_server_info));
	    if (ldap_context->server_info_list[srv_cnt] == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto clean_n_exit;
	    }

	    ldap_context->server_info_list[srv_cnt]->server_status = NOTSET;

	    ldap_context->server_info_list[srv_cnt]->server_name = strdup(val);
	    if (ldap_context->server_info_list[srv_cnt]->server_name == NULL) {
		free (opt);
		free (val);
		status = ENOMEM;
		goto clean_n_exit;
	    }

	    srv_cnt++;
#ifdef HAVE_EDIRECTORY
	} else if (opt && !strcmp(opt, "cert")) {
	    if (val == NULL) {
		status = EINVAL;
		krb5_set_error_message (context, status, gettext("'cert' value missing"));
		free(opt);
		goto clean_n_exit;
	    }

	    if (ldap_context->root_certificate_file == NULL) {
		ldap_context->root_certificate_file = strdup(val);
		if (ldap_context->root_certificate_file == NULL) {
		    free (opt);
		    free (val);
		    status = ENOMEM;
		    goto clean_n_exit;
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
		    goto clean_n_exit;
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
		    goto clean_n_exit;
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
					gettext("open of LDAP directory aborted, plugin requires -update argument"));
	    } else {
		krb5_set_error_message (context, status, gettext("unknown option \'%s\'"),
					opt?opt:val);
	    }
	    free(opt);
	    free(val);
	    goto clean_n_exit;
	}

	free(opt);
	free(val);
	t_ptr++;
    }

    dal_handle = (kdb5_dal_handle *) context->db_context;
    dal_handle->db_context = ldap_context;
    status = krb5_ldap_read_server_params(context, conf_section, mode & 0x0300);
    if (status) {
	if (ldap_context)
	    krb5_ldap_free_ldap_context(ldap_context);
	ldap_context = NULL;
	dal_handle->db_context = NULL;
	prepend_err_str (context, gettext("Error reading LDAP server params: "), status, status);
	goto clean_n_exit;
    }
    if ((status=krb5_ldap_db_init(context, ldap_context)) != 0) {
	goto clean_n_exit;
    }

    if ((status=krb5_ldap_read_startup_information(context)) != 0) {
	goto clean_n_exit;
    }

clean_n_exit:
    /* may be clearing up is not required  db_fini might do it for us, check out */
    if (status) {
	krb5_ldap_close(context);
    }
    return status;
}

#include "ldap_err.h"
int
set_ldap_error (krb5_context ctx, int st, int op)
{
    int translated_st = translate_ldap_error(st, op);
    krb5_set_error_message(ctx, translated_st, "%s", ldap_err2string(st));
    return translated_st;
}

void
prepend_err_str (krb5_context ctx, const char *str, krb5_error_code err,
		 krb5_error_code oerr)
{
    const char *omsg;
    if (oerr == 0) oerr = err;
    omsg = krb5_get_error_message (ctx, err);
    krb5_set_error_message (ctx, err, "%s %s", str, omsg);
    /* Solaris Kerberos: Memleak */
    krb5_free_error_message(ctx, omsg);
}

extern krb5int_access accessor;
MAKE_INIT_FUNCTION(kldap_init_fn);

int kldap_init_fn(void)
{
    /* Global (per-module) initialization.  */
    return krb5int_accessor (&accessor, KRB5INT_ACCESS_VERSION);
}

int kldap_ensure_initialized(void)
{
    return CALL_INIT_FUNCTION (kldap_init_fn);
}
