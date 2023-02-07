/*
 * lib/kdb/kdb_ldap/ldap_fetch_mkey.c
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

/*
 * get the master key from the database specific context
 */

krb5_error_code
krb5_ldap_get_mkey (context, key)
    krb5_context               context;
    krb5_keyblock              **key;

{
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    if (ldap_context == NULL || ldap_context->lrparams == NULL)
	return KRB5_KDB_DBNOTINITED;

    *key = &ldap_context->lrparams->mkey;
    return 0;
}


/*
 * set the master key into the database specific context
 */

krb5_error_code
krb5_ldap_set_mkey (context, pwd, key)
    krb5_context                context;
    char                        *pwd;
    krb5_keyblock               *key;
{
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_realm_params      *r_params = NULL;

    /* Clear the global error string */
    krb5_clear_error_message(context);

    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    if (ldap_context == NULL || ldap_context->lrparams == NULL)
	return KRB5_KDB_DBNOTINITED;

    r_params = ldap_context->lrparams;

    if (r_params->mkey.contents) {
	free (r_params->mkey.contents);
	r_params->mkey.contents=NULL;
    }

    r_params->mkey.magic = key->magic;
    r_params->mkey.enctype = key->enctype;
    r_params->mkey.length = key->length;
    r_params->mkey.contents = malloc(key->length);
    if (r_params->mkey.contents == NULL)
	return ENOMEM;

    memcpy(r_params->mkey.contents, key->contents, key->length);
    return 0;
}
