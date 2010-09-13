/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kdb/kdb_ldap/ldap_exp.c
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

#include "k5-int.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include <kdb5.h>
#include "kdb_ldap.h"
#include "ldap_principal.h"
#include "ldap_pwd_policy.h"


/*
 *      Exposed API
 */

kdb_vftabl kdb_function_table = {
  /* major version number 1 */		       1,
  /* minor version number 0 */		       0,
  /* Solaris Kerberos: iprop support */
  /* iprop_supported, not by ldap*/	       0,
  /* init_library */			       krb5_ldap_lib_init,
  /* fini_library */			       krb5_ldap_lib_cleanup,
  /* init_module */			       krb5_ldap_open,
  /* fini_module */			       krb5_ldap_close,
  /* db_create */			       krb5_ldap_create,
  /* db_destroy */			       krb5_ldap_delete_realm_1,
  /* db_get_age */                             krb5_ldap_db_get_age,
  /* db_set_option */			       krb5_ldap_set_option,
  /* db_lock */				       krb5_ldap_lock,
  /* db_unlock */			       krb5_ldap_unlock,
  /* db_get_principal */		       krb5_ldap_get_principal,
  /* Solaris Kerberos: need a nolock for iprop, not used for this plugin */
  /* db_get_principal_nolock */		       krb5_ldap_get_principal,
  /* db_free_principal */		       krb5_ldap_free_principal,
  /* db_put_principal */		       krb5_ldap_put_principal,
  /* db_delete_principal */		       krb5_ldap_delete_principal,
  /* db_iterate */			       krb5_ldap_iterate,
  /* db_create_policy */                       krb5_ldap_create_password_policy,
  /* db_get_policy */                          krb5_ldap_get_password_policy,
  /* db_put_policy */                          krb5_ldap_put_password_policy,
  /* db_iter_policy */                         krb5_ldap_iterate_password_policy,
  /* db_delete_policy */                       krb5_ldap_delete_password_policy,
  /* db_free_policy */                         krb5_ldap_free_password_policy,
  /* db_supported_realms */		       krb5_ldap_supported_realms,
  /* db_free_supported_realms */	       krb5_ldap_free_supported_realms,
  /* errcode_2_string */                       krb5_ldap_errcode_2_string,
  /* release_errcode_string */		       krb5_ldap_release_errcode_string,
  /* db_alloc */                               krb5_ldap_alloc,
  /* db_free */                                krb5_ldap_free,
            /* optional functions */
  /* set_master_key */			       krb5_ldap_set_mkey,
  /* get_master_key */			       krb5_ldap_get_mkey,
  /* setup_master_key_name */		       NULL,
  /* store_master_key */		       NULL,
  /* fetch_master_key */		       NULL /* krb5_ldap_fetch_mkey */,
  /* verify_master_key */		       NULL /* krb5_ldap_verify_master_key */,
  /* Search enc type */                        NULL,
  /* Change pwd   */                           NULL

};
