/*
 * lib/kdb/kdb_ldap/ldap_services.h
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

#ifndef _LDAP_SERVICE_H
#define _LDAP_SERVICE_H 1

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* service specific mask */
#define LDAP_SERVICE_SERVICEFLAG      0x0001
#define LDAP_SERVICE_HOSTSERVER       0x0002
#define LDAP_SERVICE_REALMREFERENCE   0x0004

/* service type mask */
#define LDAP_KDC_SERVICE              0x0001
#define LDAP_ADMIN_SERVICE            0x0002
#define LDAP_PASSWD_SERVICE           0x0004

/* rights mask */
#define LDAP_SUBTREE_RIGHTS           0x0001
#define LDAP_REALM_RIGHTS             0x0002

/* Types of service flags */
#define SERVICE_FLAGS_AUTO_RESTART          0x0001
#define SERVICE_FLAGS_CHECK_ADDRESSES       0x0002
#define SERVICE_FLAGS_UNIXTIME_OLD_PATYPE   0x0004

/* Service protocol type */
#define SERVICE_PROTOCOL_TYPE_UDP     "0"
#define SERVICE_PROTOCOL_TYPE_TCP     "1"

typedef struct _krb5_ldap_service_params {
        char            *servicedn;
        int             servicetype;
        int             krbserviceflags;
        char            **krbhostservers;
        char            **krbrealmreferences;
        krb5_tl_data    *tl_data;
} krb5_ldap_service_params;

#ifdef HAVE_EDIRECTORY

krb5_error_code
krb5_ldap_read_service( krb5_context, char *, krb5_ldap_service_params **, int *);

krb5_error_code
krb5_ldap_create_service( krb5_context, krb5_ldap_service_params *,int);

krb5_error_code
krb5_ldap_modify_service( krb5_context, krb5_ldap_service_params *, int);

krb5_error_code
krb5_ldap_delete_service( krb5_context, krb5_ldap_service_params *, char *);

krb5_error_code
krb5_ldap_list_services( krb5_context, char *, char ***);

krb5_error_code
krb5_ldap_free_service( krb5_context, krb5_ldap_service_params *);


krb5_error_code
krb5_ldap_set_service_passwd( krb5_context, char *, char *);

krb5_error_code 
krb5_ldap_add_service_rights( krb5_context, int, char *, char *, char **, int);

krb5_error_code
krb5_ldap_delete_service_rights( krb5_context, int, char *, char *, char **, int);
#endif

#endif
