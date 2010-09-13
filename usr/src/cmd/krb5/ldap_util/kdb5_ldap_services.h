/*
 * kadmin/ldap_util/kdb5_ldap_services.h
 */

/* Copyright (c) 2004-2005, Novell, Inc.
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

#ifndef _KDB5_LDAP_SERVICES_H_
#define _KDB5_LDAP_SERVICES_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ldap_misc.h"

#define MAX_DN_CHARS 		256
#define HOST_INFO_DELIMITER 	'#'
#define PROTOCOL_STR_LEN 	3
#define PROTOCOL_NUM_UDP 	0
#define PROTOCOL_NUM_TCP 	1
#define PROTOCOL_DEFAULT_KDC 	PROTOCOL_NUM_UDP
#define PROTOCOL_DEFAULT_ADM 	PROTOCOL_NUM_TCP
#define PROTOCOL_DEFAULT_PWD 	PROTOCOL_NUM_UDP
#define PORT_STR_LEN 		5
#define PORT_DEFAULT_KDC 	88
#define PORT_DEFAULT_ADM 	749
#define PORT_DEFAULT_PWD 	464

#define MAX_LEN 		1024
#define MAX_SERVICE_PASSWD_LEN 	256
#define RANDOM_PASSWD_LEN 	128

/* Solaris Kerberos: default for the service_passwd file is in osconf.h */
#if 0
#define DEF_SERVICE_PASSWD_FILE "/usr/local/var/service_passwd"
#endif

struct data{
    int len;
    unsigned char *value;
};

extern int enc_password(struct data pwd, struct data *enc_key, struct data *enc_pass);
extern int tohex(krb5_data, krb5_data *);

extern void kdb5_ldap_create_service (int argc, char **argv);
extern void kdb5_ldap_modify_service (int argc, char **argv);
extern void kdb5_ldap_destroy_service(int argc, char **argv);
extern void kdb5_ldap_list_services(int argc, char **argv);
extern void kdb5_ldap_view_service(int argc, char **argv);
extern int  kdb5_ldap_set_service_password(int argc, char **argv);
extern void kdb5_ldap_set_service_certificate(int argc, char **argv);
extern void print_service_params(krb5_ldap_service_params *lserparams, int mask);
extern krb5_error_code convert_realm_name2dn_list(char **list, const char *krbcontainer_loc);
extern void kdb5_ldap_stash_service_password(int argc, char **argv);

#endif /* _KDB5_LDAP_SERVICES_H_ */
