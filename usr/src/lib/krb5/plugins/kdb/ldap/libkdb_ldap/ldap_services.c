#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/kdb/kdb_ldap/ldap_services.c
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

#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_services.h"
#include "ldap_err.h"
#include <libintl.h>

#if defined(HAVE_EDIRECTORY)

static char *realmcontclass[] = {"krbRealmContainer", NULL};

/*
 * create the service object from Directory
 */

krb5_error_code
krb5_ldap_create_service(context, service, mask)
    krb5_context	        context;
    krb5_ldap_service_params    *service;
    int                         mask;
{
    int                         i=0, j=0;
    krb5_error_code             st=0;
    LDAP                        *ld=NULL;
    char                        **rdns=NULL, *realmattr=NULL, *strval[3]={NULL};
    LDAPMod                     **mods=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    char                        errbuf[1024];

    /* validate the input parameter */
    if (service == NULL || service->servicedn == NULL) {
	st = EINVAL;
	krb5_set_error_message (context, st, gettext("Service DN NULL"));
	goto cleanup;
    }

    SETUP_CONTEXT();
    GET_HANDLE();

    /* identify the class that the object should belong to. This depends on the servicetype */
    memset(strval, 0, sizeof(strval));
    strval[0] = "krbService";
    if (service->servicetype == LDAP_KDC_SERVICE) {
	strval[1] = "krbKdcService";
	realmattr = "krbKdcServers";
    } else if (service->servicetype == LDAP_ADMIN_SERVICE) {
	strval[1] = "krbAdmService";
	realmattr = "krbAdmServers";
    } else if (service->servicetype == LDAP_PASSWD_SERVICE) {
	strval[1] = "krbPwdService";
	realmattr = "krbPwdServers";
    } else {
	strval[1] = "krbKdcService";
	realmattr = "krbKdcServers";
    }
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "objectclass", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    rdns = ldap_explode_dn(service->servicedn, 1);
    if (rdns == NULL) {
	st = LDAP_INVALID_DN_SYNTAX;
	goto cleanup;
    }
    memset(strval, 0, sizeof(strval));
    strval[0] = rdns[0];
    if ((st=krb5_add_str_mem_ldap_mod(&mods, "cn", LDAP_MOD_ADD, strval)) != 0)
	goto cleanup;

    if (mask & LDAP_SERVICE_SERVICEFLAG) {
	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbserviceflags", LDAP_MOD_ADD,
					  service->krbserviceflags)) != 0)
	    goto cleanup;
    }

    if (mask & LDAP_SERVICE_HOSTSERVER) {
	if (service->krbhostservers != NULL) {
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbhostserver", LDAP_MOD_ADD,
					      service->krbhostservers)) != 0)
		goto cleanup;
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, gettext("'krbhostserver' argument invalid"));
	    goto cleanup;
	}
    }

    if (mask & LDAP_SERVICE_REALMREFERENCE) {
	if (service->krbrealmreferences != NULL) {
	    unsigned int realmmask=0;

	    /* check for the validity of the values */
	    for (j=0; service->krbrealmreferences[j] != NULL; ++j) {
		st = checkattributevalue(ld, service->krbrealmreferences[j], "ObjectClass",
					 realmcontclass, &realmmask);
		CHECK_CLASS_VALIDITY(st, realmmask, "realm object value: ");
	    }
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbrealmreferences", LDAP_MOD_ADD,
					      service->krbrealmreferences)) != 0)
		goto cleanup;
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, gettext("Server has no 'krbrealmreferences'"));
	    goto cleanup;
	}
    }

    /* ldap add operation */
    if ((st=ldap_add_ext_s(ld, service->servicedn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_ADD);
	goto cleanup;
    }

    /*
     * If the service created has realm/s associated with it, then the realm should be updated
     * to have a reference to the service object just created.
     */
    if (mask & LDAP_SERVICE_REALMREFERENCE) {
	for (i=0; service->krbrealmreferences[i]; ++i) {
	    if ((st=updateAttribute(ld, service->krbrealmreferences[i], realmattr,
				    service->servicedn)) != 0) {
		snprintf (errbuf, sizeof(errbuf), gettext("Error adding 'krbRealmReferences' to %s: "),
			 service->krbrealmreferences[i]);
		prepend_err_str (context, errbuf, st, st);
		/* delete service object, status ignored intentionally */
		ldap_delete_ext_s(ld, service->servicedn, NULL, NULL);
		goto cleanup;
	    }
	}
    }

cleanup:

    if (rdns)
	ldap_value_free (rdns);

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


/*
 * modify the service object from Directory
 */

krb5_error_code
krb5_ldap_modify_service(context, service, mask)
    krb5_context	        context;
    krb5_ldap_service_params    *service;
    int                         mask;
{
    int                         i=0, j=0, count=0;
    krb5_error_code             st=0;
    LDAP                        *ld=NULL;
    char                        **values=NULL, *attr[] = { "krbRealmReferences", NULL};
    char                        *realmattr=NULL;
    char                        **oldrealmrefs=NULL, **newrealmrefs=NULL;
    LDAPMod                     **mods=NULL;
    LDAPMessage                 *result=NULL, *ent=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    /* validate the input parameter */
    if (service == NULL || service->servicedn == NULL) {
	st = EINVAL;
	krb5_set_error_message (context, st, gettext("Service DN is NULL"));
	goto cleanup;
    }

    SETUP_CONTEXT();
    GET_HANDLE();

    if (mask & LDAP_SERVICE_SERVICEFLAG) {
	if ((st=krb5_add_int_mem_ldap_mod(&mods, "krbserviceflags", LDAP_MOD_REPLACE,
					  service->krbserviceflags)) != 0)
	    goto cleanup;
    }

    if (mask & LDAP_SERVICE_HOSTSERVER) {
	if (service->krbhostservers != NULL) {
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbhostserver", LDAP_MOD_REPLACE,
					      service->krbhostservers)) != 0)
		goto cleanup;
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, gettext("'krbhostserver' value invalid"));
	    goto cleanup;
	}
    }

    if (mask & LDAP_SERVICE_REALMREFERENCE) {
	if (service->krbrealmreferences != NULL) {
	    unsigned int realmmask=0;

	    /* check for the validity of the values */
	    for (j=0; service->krbrealmreferences[j]; ++j) {
		st = checkattributevalue(ld, service->krbrealmreferences[j], "ObjectClass",
					 realmcontclass, &realmmask);
		CHECK_CLASS_VALIDITY(st, realmmask, "realm object value: ");
	    }
	    if ((st=krb5_add_str_mem_ldap_mod(&mods, "krbrealmreferences", LDAP_MOD_REPLACE,
					      service->krbrealmreferences)) != 0)
		goto cleanup;


	    /* get the attribute of the realm to be set */
	    if (service->servicetype == LDAP_KDC_SERVICE)
		realmattr = "krbKdcServers";
	    else if (service->servicetype == LDAP_ADMIN_SERVICE)
		realmattr = "krbAdmservers";
	    else if (service->servicetype == LDAP_PASSWD_SERVICE)
		realmattr = "krbPwdServers";
	    else
		realmattr = "krbKdcServers";

	    /* read the existing list of krbRealmreferences. this will needed  */
	    if ((st = ldap_search_ext_s (ld,
					 service->servicedn,
					 LDAP_SCOPE_BASE,
					 0,
					 attr,
					 0,
					 NULL,
					 NULL,
					 NULL,
					 0,
					 &result)) != LDAP_SUCCESS) {
		st = set_ldap_error (context, st, OP_SEARCH);
		goto cleanup;
	    }

	    ent = ldap_first_entry(ld, result);
	    if (ent) {
		if ((values=ldap_get_values(ld, ent, "krbRealmReferences")) != NULL) {
		    count = ldap_count_values(values);
		    if ((st=copy_arrays(values, &oldrealmrefs, count)) != 0)
			goto cleanup;
		    ldap_value_free(values);
		}
	    }
	    ldap_msgfree(result);
	} else {
	    st = EINVAL;
	    krb5_set_error_message (context, st, gettext("'krbRealmReferences' value invalid"));
	    goto cleanup;
	}
    }

    /* ldap modify operation */
    if ((st=ldap_modify_ext_s(ld, service->servicedn, mods, NULL, NULL)) != LDAP_SUCCESS) {
	st = set_ldap_error (context, st, OP_MOD);
	goto cleanup;
    }

    /*
     * If the service modified had realm/s associations changed, then the realm should be
     * updated to reflect the changes.
     */

    if (mask & LDAP_SERVICE_REALMREFERENCE) {
	/* get the count of the new list of krbrealmreferences */
	for (i=0; service->krbrealmreferences[i]; ++i)
	    ;

	/* make a new copy of the krbrealmreferences */
	if ((st=copy_arrays(service->krbrealmreferences, &newrealmrefs, i)) != 0)
	    goto cleanup;

	/* find the deletions/additions to the list of krbrealmreferences */
	if (disjoint_members(oldrealmrefs, newrealmrefs) != 0)
	    goto cleanup;

	/* see if some of the attributes have to be deleted */
	if (oldrealmrefs) {

	    /* update the dn represented by the attribute that is to be deleted */
	    for (i=0; oldrealmrefs[i]; ++i)
		if ((st=deleteAttribute(ld, oldrealmrefs[i], realmattr, service->servicedn)) != 0) {
		    prepend_err_str (context, gettext("Error deleting realm attribute:"), st, st);
		    goto cleanup;
		}
	}

	/* see if some of the attributes have to be added */
	for (i=0; newrealmrefs[i]; ++i)
	    if ((st=updateAttribute(ld, newrealmrefs[i], realmattr, service->servicedn)) != 0) {
		prepend_err_str (context, gettext("Error updating realm attribute: "), st, st);
		goto cleanup;
	    }
    }

cleanup:

    if (oldrealmrefs) {
	for (i=0; oldrealmrefs[i]; ++i)
	    free (oldrealmrefs[i]);
	free (oldrealmrefs);
    }

    if (newrealmrefs) {
	for (i=0; newrealmrefs[i]; ++i)
	    free (newrealmrefs[i]);
	free (newrealmrefs);
    }

    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


krb5_error_code
krb5_ldap_delete_service(context, service, servicedn)
    krb5_context                context;
    krb5_ldap_service_params    *service;
    char                        *servicedn;
{
    krb5_error_code             st = 0;
    LDAP                        *ld=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    SETUP_CONTEXT();
    GET_HANDLE();

    st = ldap_delete_ext_s(ld, servicedn, NULL, NULL);
    if (st != 0) {
	st = set_ldap_error (context, st, OP_DEL);
    }

    /* NOTE: This should be removed now as the backlinks are going off in OpenLDAP */
    /* time to delete krbrealmreferences. This is only for OpenLDAP */
#ifndef HAVE_EDIRECTORY
    {
	int                         i=0;
	char                        *attr=NULL;

	if (service) {
	    if (service->krbrealmreferences) {
		if (service->servicetype == LDAP_KDC_SERVICE)
		    attr = "krbkdcservers";
		else if (service->servicetype == LDAP_ADMIN_SERVICE)
		    attr = "krbadmservers";
		else if (service->servicetype == LDAP_PASSWD_SERVICE)
		    attr = "krbpwdservers";

		for (i=0; service->krbrealmreferences[i]; ++i) {
		    deleteAttribute(ld, service->krbrealmreferences[i], attr, servicedn);
		}
	    }
	}
    }
#endif

cleanup:

    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}


/*
 * This function lists service objects from Directory
 */

krb5_error_code
krb5_ldap_list_services(context, containerdn, services)
    krb5_context	        context;
    char                        *containerdn;
    char                        ***services;
{
    return (krb5_ldap_list(context, services, "krbService", containerdn));
}

/*
 * This function reads the service object from Directory
 */
krb5_error_code
krb5_ldap_read_service(context, servicedn, service, omask)
    krb5_context	        context;
    char                        *servicedn;
    krb5_ldap_service_params    **service;
    int                         *omask;
{
    char                        **values=NULL;
    int                         i=0, count=0, objectmask=0;
    krb5_error_code             st=0, tempst=0;
    LDAPMessage                 *result=NULL,*ent=NULL;
    char                        *attributes[] = {"krbHostServer", "krbServiceflags",
						 "krbRealmReferences", "objectclass", NULL};
    char                        *attrvalues[] = {"krbService", NULL};
    krb5_ldap_service_params    *lservice=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;
    LDAP                        *ld = NULL;

    /* validate the input parameter */
    if (servicedn == NULL) {
	st = EINVAL;
	krb5_set_error_message (context, st, gettext("Service DN NULL"));
	goto cleanup;
    }

    SETUP_CONTEXT();
    GET_HANDLE();

    *omask = 0;

    /* the policydn object should be of the krbService object class */
    st = checkattributevalue(ld, servicedn, "objectClass", attrvalues, &objectmask);
    CHECK_CLASS_VALIDITY(st, objectmask, "service object value: ");

    /* Initialize service structure */
    lservice =(krb5_ldap_service_params *) calloc(1, sizeof(krb5_ldap_service_params));
    if (lservice == NULL) {
	st = ENOMEM;
	goto cleanup;
    }

    /* allocate tl_data structure to store MASK information */
    lservice->tl_data = calloc (1, sizeof(*lservice->tl_data));
    if (lservice->tl_data == NULL) {
	st = ENOMEM;
	goto cleanup;
    }
    lservice->tl_data->tl_data_type = KDB_TL_USER_INFO;

    LDAP_SEARCH(servicedn, LDAP_SCOPE_BASE, "(objectclass=krbService)", attributes);

    lservice->servicedn = strdup(servicedn);
    CHECK_NULL(lservice->servicedn);

    ent=ldap_first_entry(ld, result);
    if (ent != NULL) {

	if ((values=ldap_get_values(ld, ent, "krbServiceFlags")) != NULL) {
	    lservice->krbserviceflags = atoi(values[0]);
	    *omask |= LDAP_SERVICE_SERVICEFLAG;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbHostServer")) != NULL) {
	    count = ldap_count_values(values);
	    if ((st=copy_arrays(values, &(lservice->krbhostservers), count)) != 0)
		goto cleanup;
	    *omask |= LDAP_SERVICE_HOSTSERVER;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "krbRealmReferences")) != NULL) {
	    count = ldap_count_values(values);
	    if ((st=copy_arrays(values, &(lservice->krbrealmreferences), count)) != 0)
		goto cleanup;
	    *omask |= LDAP_SERVICE_REALMREFERENCE;
	    ldap_value_free(values);
	}

	if ((values=ldap_get_values(ld, ent, "objectClass")) != NULL) {
	    for (i=0; values[i]; ++i) {
		if (strcasecmp(values[i], "krbKdcService") == 0) {
		    lservice->servicetype = LDAP_KDC_SERVICE;
		    break;
		}

		if (strcasecmp(values[i], "krbAdmService") == 0) {
		    lservice->servicetype = LDAP_ADMIN_SERVICE;
		    break;
		}

		if (strcasecmp(values[i], "krbPwdService") == 0) {
		    lservice->servicetype = LDAP_PASSWD_SERVICE;
		    break;
		}
	    }
	    ldap_value_free(values);
	}
    }
    ldap_msgfree(result);

cleanup:
    if (st != 0) {
	krb5_ldap_free_service(context, lservice);
	*service = NULL;
    } else {
	store_tl_data(lservice->tl_data, KDB_TL_MASK, omask);
	*service = lservice;
    }

    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}

/*
 * This function frees the krb5_ldap_service_params structure members.
 */

krb5_error_code
krb5_ldap_free_service(context, service)
    krb5_context                context;
    krb5_ldap_service_params    *service;
{
    int                         i=0;

    if (service == NULL)
	return 0;

    if (service->servicedn)
	free (service->servicedn);

    if (service->krbrealmreferences) {
	for (i=0; service->krbrealmreferences[i]; ++i)
	    free (service->krbrealmreferences[i]);
	free (service->krbrealmreferences);
    }

    if (service->krbhostservers) {
	for (i=0; service->krbhostservers[i]; ++i)
	    free (service->krbhostservers[i]);
	free (service->krbhostservers);
    }

    if (service->tl_data) {
	if (service->tl_data->tl_data_contents)
	    free (service->tl_data->tl_data_contents);
	free (service->tl_data);
    }

    free (service);
    return 0;
}

krb5_error_code
krb5_ldap_set_service_passwd(context, service, passwd)
    krb5_context                context;
    char                        *service;
    char                        *passwd;
{
    krb5_error_code             st=0;
    LDAPMod                     **mods=NULL;
    char                        *password[2] = {NULL};
    LDAP                        *ld=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;

    password[0] = passwd;

    SETUP_CONTEXT();
    GET_HANDLE();

    if ((st=krb5_add_str_mem_ldap_mod(&mods, "userPassword", LDAP_MOD_REPLACE, password)) != 0)
	goto cleanup;

    st = ldap_modify_ext_s(ld, service, mods, NULL, NULL);
    if (st) {
	st = set_ldap_error (context, st, OP_MOD);
    }

cleanup:
    ldap_mods_free(mods, 1);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    return st;
}
#endif
