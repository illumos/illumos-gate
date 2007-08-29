#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_ldap/ldap_pwd_policy.c
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
#include "kdb_ldap.h"
#include "ldap_pwd_policy.h"
#include "ldap_err.h"
#include <libintl.h>

static char *password_policy_attributes[] = { "cn", "krbmaxpwdlife", "krbminpwdlife",
					      "krbpwdmindiffchars", "krbpwdminlength",
					      "krbpwdhistorylength", NULL };

/*
 * Function to create password policy object.
 */

krb5_error_code
krb5_ldap_create_password_policy (context, policy)
    krb5_context                context;
    osa_policy_ent_t            policy;
{
    krb5_error_code 	        st=0;
    LDAP  		        *ld=NULL;
    LDAPMod 		        **mods={NULL};
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    char                        **rdns=NULL, *strval[2]={NULL}, *policy_dn;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (policy == NULL || policy->name == NULL)
	return EINVAL;

    SETUP_CONTEXT();
    GET_HANDLE();

    st = krb5_ldap_name_to_policydn (context, policy->name, &policy_dn);
    if (st != 0)
	goto cleanup;

    /* get the first component of the dn to set the cn attribute */
    rdns = ldap_explode_dn(policy_dn, 1);
    if (rdns == NULL) {
	st = EINVAL;
	krb5_set_error_message(context, st, gettext("Invalid password policy DN syntax"));
	goto cleanup;
    }

    strval[0] = rdns[0];
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "cn", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    strval[0] = "krbPwdPolicy";
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    if (((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxpwdlife", LDAP_MOD_ADD,
				       (signed) policy->pw_max_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbminpwdlife", LDAP_MOD_ADD,
					  (signed) policy->pw_min_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdmindiffchars", LDAP_MOD_ADD,
					  (signed) policy->pw_min_classes)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdminlength", LDAP_MOD_ADD,
					  (signed) policy->pw_min_length)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdhistorylength", LDAP_MOD_ADD,
					  (signed) policy->pw_history_num)) != 0))
	goto cleanup;

    /* password policy object creation */
    if ((st=ldap_add_ext_s(ld, policy_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_ADD);
	goto cleanup;
    }

cleanup:
    if (rdns)
	ldap_value_free(rdns);

    if (policy_dn != NULL)
	free (policy_dn);
    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return(st);
}

/*
 * Function to modify password policy object.
 */

krb5_error_code
krb5_ldap_put_password_policy (context, policy)
    krb5_context                context;
    osa_policy_ent_t            policy;
{
    char                        *policy_dn;
    krb5_error_code 	        st=0;
    LDAP  		        *ld=NULL;
    LDAPMod 		        **mods=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (policy == NULL || policy->name == NULL)
	return EINVAL;

    SETUP_CONTEXT();
    GET_HANDLE();

    st = krb5_ldap_name_to_policydn (context, policy->name, &policy_dn);
    if (st != 0)
	goto cleanup;

    if (((st=krb5_add_int_mem_ldap_mod(&mods, "krbmaxpwdlife", LDAP_MOD_REPLACE,
				       (signed) policy->pw_max_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbminpwdlife", LDAP_MOD_REPLACE,
					  (signed) policy->pw_min_life)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdmindiffchars", LDAP_MOD_REPLACE,
					  (signed) policy->pw_min_classes)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdminlength", LDAP_MOD_REPLACE,
					  (signed) policy->pw_min_length)) != 0)
	|| ((st=krb5_add_int_mem_ldap_mod(&mods, "krbpwdhistorylength", LDAP_MOD_REPLACE,
					  (signed) policy->pw_history_num)) != 0))
	goto cleanup;

    /* modify the password policy object. */
    /*
     * This will fail if the 'policy_dn' is anywhere other than under the realm
     * container. This is correct behaviour. 'kdb5_ldap_util' will support
     * management of only such policy objects.
     */
    if ((st=ldap_modify_ext_s(ld, policy_dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_MOD);
	goto cleanup;
    }

cleanup:
    if (policy_dn != NULL)
	free (policy_dn);
    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return(st);
}

krb5_error_code
populate_policy(krb5_context context,
    LDAP *ld,
    LDAPMessage *ent,
    char *pol_name,
    osa_policy_ent_t pol_entry)
{
    int st = 0;
    char *pol_dn;

    pol_entry->name = strdup(pol_name);
    CHECK_NULL(pol_entry->name);
    pol_entry->version = 1;

    krb5_ldap_get_value(ld, ent, "krbmaxpwdlife", (int *)&(pol_entry->pw_max_life));
    krb5_ldap_get_value(ld, ent, "krbminpwdlife", (int *)&(pol_entry->pw_min_life));
    krb5_ldap_get_value(ld, ent, "krbpwdmindiffchars", (int *)&(pol_entry->pw_min_classes));
    krb5_ldap_get_value(ld, ent, "krbpwdminlength", (int *)&(pol_entry->pw_min_length));
    krb5_ldap_get_value(ld, ent, "krbpwdhistorylength", (int *)&(pol_entry->pw_history_num));

    /* Get the reference count */
    pol_dn = ldap_get_dn(ld, ent);
    st = krb5_ldap_get_reference_count (context, pol_dn, "krbPwdPolicyReference",
	    (int *)&(pol_entry->policy_refcnt), ld);
    ldap_memfree(pol_dn);

cleanup:
    /* Solaris Kerberos: trying to avoid memory leaks */
    if (st != 0) {
	free(pol_entry->name);
	pol_entry->name = NULL;
    }
    return st;
}

krb5_error_code
krb5_ldap_get_password_policy_from_dn (krb5_context context,
    char *pol_name,
    char *pol_dn,
    osa_policy_ent_t *policy,
    int *cnt)
{
    krb5_error_code             st=0, tempst=0;
    LDAP  		        *ld=NULL;
    LDAPMessage                 *result=NULL,*ent=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (pol_dn == NULL)
	return EINVAL;

    *policy = NULL;
    SETUP_CONTEXT();
    GET_HANDLE();

    *cnt = 0;
    *(policy) = (osa_policy_ent_t) malloc(sizeof(osa_policy_ent_rec));
    if (*policy == NULL) {
	st = ENOMEM;
	goto cleanup;
    }
    memset(*policy, 0, sizeof(osa_policy_ent_rec));

    LDAP_SEARCH(pol_dn, LDAP_SCOPE_BASE, "(objectclass=krbPwdPolicy)", password_policy_attributes);
    *cnt = 1;
#if 0 /************** Begin IFDEF'ed OUT *******************************/
    (*policy)->name = strdup(name);
    CHECK_NULL((*policy)->name);
    (*policy)->version = 1;
#endif /**************** END IFDEF'ed OUT *******************************/

    ent=ldap_first_entry(ld, result);
    if (ent != NULL) {
	if ((st = populate_policy(context, ld, ent, pol_name, *policy)) != 0)
	    goto cleanup;
#if 0 /************** Begin IFDEF'ed OUT *******************************/
	krb5_ldap_get_value(ld, ent, "krbmaxpwdlife", &((*policy)->pw_max_life));
	krb5_ldap_get_value(ld, ent, "krbminpwdlife", &((*policy)->pw_min_life));
	krb5_ldap_get_value(ld, ent, "krbpwdmindiffchars", &((*policy)->pw_min_classes));
	krb5_ldap_get_value(ld, ent, "krbpwdminlength", &((*policy)->pw_min_length));
	krb5_ldap_get_value(ld, ent, "krbpwdhistorylength", &((*policy)->pw_history_num));

	/* Get the reference count */
	st = krb5_ldap_get_reference_count (context,
					    name,
					    "krbPwdPolicyReference",
					    &(*policy)->policy_refcnt,
					    ld);
#endif /**************** END IFDEF'ed OUT *******************************/
    }

cleanup:
    ldap_msgfree(result);
    if (st != 0) {
	if (*policy != NULL) {
	    krb5_ldap_free_password_policy(context, *policy);
	    *policy = NULL;
	}
    }

    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

/*
 * Convert 'name' into a directory DN and call
 * 'krb5_ldap_get_password_policy_from_dn'
 */
krb5_error_code
krb5_ldap_get_password_policy (context, name, policy, cnt)
    krb5_context                context;
    char                        *name;
    osa_policy_ent_t            *policy;
    int                         *cnt;
{
    krb5_error_code             st = 0;
    char                        *policy_dn = NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (name == NULL) {
	st = EINVAL;
	goto cleanup;
    }

    st = krb5_ldap_name_to_policydn(context, name, &policy_dn);
    if (st != 0)
	goto cleanup;

    st = krb5_ldap_get_password_policy_from_dn(context, name, policy_dn, policy, cnt);

cleanup:
    if (policy_dn != NULL)
	free (policy_dn);
    return st;
}

krb5_error_code
krb5_ldap_delete_password_policy (context, policy)
    krb5_context                context;
    char                        *policy;
{
    int                         mask = 0;
    char                        *policy_dn = NULL, *class[] = {"krbpwdpolicy", NULL};
    krb5_error_code             st=0;
    LDAP                        *ld=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    /* validate the input parameters */
    if (policy == NULL)
	return EINVAL;

    SETUP_CONTEXT();
    GET_HANDLE();

    st = krb5_ldap_name_to_policydn (context, policy, &policy_dn);
    if (st != 0)
	goto cleanup;

    /* Ensure that the object is a password policy */
    if ((st=checkattributevalue(ld, policy_dn, "objectclass", class, &mask)) != 0)
	goto cleanup;

    if (mask == 0) {
	st = KRB5_KDB_NOENTRY;
	goto cleanup;
    }

    if ((st=ldap_delete_ext_s(ld, policy_dn, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_DEL);
	goto cleanup;
    }

cleanup:
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    if (policy_dn != NULL)
	free (policy_dn);

    return st;
}

krb5_error_code
krb5_ldap_iterate_password_policy(context, match_expr, func, func_arg)
    krb5_context                context;
    char                        *match_expr;
    void                        (*func) (krb5_pointer, osa_policy_ent_t);
    krb5_pointer                func_arg;
{
    osa_policy_ent_rec          *entry=NULL;
    char		        *policy=NULL;
    krb5_error_code             st=0, tempst=0;
    LDAP		        *ld=NULL;
    LDAPMessage	                *result=NULL, *ent=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    SETUP_CONTEXT();
    GET_HANDLE();

    if (ldap_context->lrparams->realmdn == NULL) {
	st = EINVAL;
	goto cleanup;
    }

    LDAP_SEARCH(ldap_context->lrparams->realmdn, LDAP_SCOPE_ONELEVEL, "(objectclass=krbpwdpolicy)", password_policy_attributes);
    for (ent=ldap_first_entry(ld, result); ent != NULL; ent=ldap_next_entry(ld, ent)) {
	krb5_boolean attr_present;

	st = krb5_ldap_get_string(ld, ent, "cn", &policy, &attr_present);
	if (st != 0)
	    goto cleanup;
	if (attr_present == FALSE)
	    continue;

	entry = (osa_policy_ent_t) malloc(sizeof(osa_policy_ent_rec));
	CHECK_NULL(entry);
	memset(entry, 0, sizeof(osa_policy_ent_rec));
	if ((st = populate_policy(context, ld, ent, policy, entry)) != 0)
	    goto cleanup;
#if 0 /************** Begin IFDEF'ed OUT *******************************/
	entry->name = policy;
	entry->version = 1;

	krb5_ldap_get_value(ld, ent, "krbmaxpwdlife", &(entry->pw_max_life));
	krb5_ldap_get_value(ld, ent, "krbminpwdlife", &(entry->pw_min_life));
	krb5_ldap_get_value(ld, ent, "krbpwdmindiffchars", &(entry->pw_min_classes));
	krb5_ldap_get_value(ld, ent, "krbpwdminlength", &(entry->pw_min_length));
	krb5_ldap_get_value(ld, ent, "krbpwdhistorylength", &(entry->pw_history_num));

	/* Get the reference count */
	st = krb5_ldap_get_reference_count (context,
					    policy,
					    "krbPwdPolicyReference",
					    &(entry->policy_refcnt),
					    ld);
#endif /**************** END IFDEF'ed OUT *******************************/

	(*func)(func_arg, entry);
	/* XXX this will free policy so don't free it */
	krb5_ldap_free_password_policy(context, entry);
	entry = NULL;
    }
    ldap_msgfree(result);

cleanup:
    if (entry)
	free (entry);

    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

void
krb5_ldap_free_password_policy (context, entry)
    krb5_context                context;
    osa_policy_ent_t            entry;
{
    if (entry) {
	if (entry->name)
	    free(entry->name);
	free(entry);
    }
    return;
}
