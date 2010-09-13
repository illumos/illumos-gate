/*
 * lib/kdb/kdb_ldap/ldap_principal.h
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

#ifndef _LDAP_PRINCIPAL_H
#define _LDAP_PRINCIPAL_H 1

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ldap_tkt_policy.h"

#define  KEYHEADER  12

#define  NOOFKEYS(ptr) 		((ptr[10]<<8) | ptr[11])

#define  PRINCIPALLEN(ptr) 	((ptr[0]<<8) | ptr[1])
#define  PRINCIPALNAME(ptr) 	(ptr + KEYHEADER + (NOOFKEYS(ptr) *8))

#define  KEYBODY(ptr)		PRINCIPALNAME(ptr) + PRINCIPALLEN(ptr)

#define  PKEYVER(ptr) 		((ptr[2]<<8) | ptr[3])
#define  MKEYVER(ptr) 		((ptr[4]<<8) | ptr[5])

#define  KEYTYPE(ptr,j) 	((ptr[KEYHEADER+(j*8)]<<8) | ptr[KEYHEADER+1+(j*8)])
#define  KEYLENGTH(ptr,j) 	((ptr[KEYHEADER+2+(j*8)]<<8) | ptr[KEYHEADER+3+(j*8)])
#define  SALTTYPE(ptr,j) 	((ptr[KEYHEADER+4+(j*8)]<<8) | ptr[KEYHEADER+5+(j*8)])
#define  SALTLENGTH(ptr,j) 	((ptr[KEYHEADER+6+(j*8)]<<8) | ptr[KEYHEADER+7+(j*8)])

#define MAX_KEY_LENGTH         1024
#define CONTAINERDN_ARG        "containerdn"
#define USERDN_ARG             "dn"
#define TKTPOLICY_ARG          "tktpolicy"
#define LINKDN_ARG             "linkdn"

/* #define FILTER   "(&(objectclass=krbprincipalaux)(krbprincipalname=" */
 #define FILTER   "(&(|(objectclass=krbprincipalaux)(objectclass=krbprincipal))(krbprincipalname="

#define  KDB_USER_PRINCIPAL    0x01
#define  KDB_SERVICE_PRINCIPAL 0x02
#define KDB_STANDALONE_PRINCIPAL_OBJECT 0x01

/* these will be consumed only by krb5_ldap_delete_principal*/
/* these will be set by krb5_ldap_get_principal and fed into the tl_data */

/* See also attributes_set[] in ldap_principal.c.  */
#define KDB_MAX_LIFE_ATTR                    0x000001
#define KDB_MAX_RLIFE_ATTR                   0x000002
#define KDB_TKT_FLAGS_ATTR                   0x000004
#define KDB_PRINC_EXPIRE_TIME_ATTR           0x000008
#define KDB_POL_REF_ATTR                     0x000010
#define KDB_UP_FLAG_ATTR                     0x000020
#define KDB_PWD_POL_REF_ATTR                 0x000040
#define KDB_PWD_EXPIRE_TIME_ATTR             0x000080
#define KDB_SECRET_KEY_ATTR                  0x000100
#define KDB_LAST_PWD_CHANGE_ATTR             0x000200
#define KDB_EXTRA_DATA_ATTR                  0x000400
#define KDB_LAST_SUCCESS_ATTR                0x000800
#define KDB_LAST_FAILED_ATTR                 0x001000
#define KDB_FAIL_AUTH_COUNT_ATTR             0x002000
extern struct timeval timeout;
extern char *policyclass[];

krb5_error_code
krb5_ldap_put_principal(krb5_context, krb5_db_entry *, int *, char **);

krb5_error_code
krb5_ldap_get_principal(krb5_context , krb5_const_principal ,
                        krb5_db_entry *,int *, krb5_boolean *);

krb5_error_code
krb5_ldap_delete_principal(krb5_context, krb5_const_principal, int *);

krb5_error_code
krb5_ldap_free_principal(krb5_context, krb5_db_entry *, int );

/* Solaris Kerberos: adding support for db_args */
krb5_error_code
krb5_ldap_iterate(krb5_context, char *, krb5_error_code (*) (krb5_pointer, krb5_db_entry *),
                  krb5_pointer/*, int */, char **);

void
krb5_dbe_free_contents(krb5_context, krb5_db_entry *);

krb5_error_code
krb5_ldap_unparse_principal_name(char *);

krb5_error_code
krb5_ldap_parse_principal_name(char *, char **);

krb5_error_code
krb5_decode_krbsecretkey(krb5_context, krb5_db_entry *, struct berval **);

krb5_error_code
berval2tl_data(struct berval *in, krb5_tl_data **out);

krb5_error_code
krb5_read_tkt_policy (krb5_context, krb5_ldap_context *, krb5_db_entry *, char *);
#endif
