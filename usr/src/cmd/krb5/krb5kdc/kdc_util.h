/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * kdc/kdc_util.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Declarations for policy.c
 */

#ifndef __KRB5_KDC_UTIL__
#define __KRB5_KDC_UTIL__


#include "kdb.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct _krb5_fulladdr {
    krb5_address *	address;
    krb5_ui_4		port;
} krb5_fulladdr;

krb5_error_code check_hot_list (krb5_ticket *);
krb5_boolean realm_compare (krb5_principal, krb5_principal);
krb5_boolean krb5_is_tgs_principal (krb5_principal);
krb5_error_code add_to_transited (krb5_data *,
					    krb5_data *,
					    krb5_principal,
					    krb5_principal,
					    krb5_principal);
krb5_error_code compress_transited (krb5_data *,
					      krb5_principal,
					      krb5_data *);
krb5_error_code concat_authorization_data (krb5_authdata **,
						     krb5_authdata **,
						     krb5_authdata ***);
krb5_error_code fetch_last_req_info (krb5_db_entry *,
					       krb5_last_req_entry ***);

krb5_error_code kdc_convert_key (krb5_keyblock *,
					   krb5_keyblock *,
					   int);
krb5_error_code kdc_process_tgs_req
	(krb5_kdc_req *,
	           const krb5_fulladdr *,
	           krb5_data *,
	           krb5_ticket **,
	           krb5_keyblock **);

krb5_error_code kdc_get_server_key (krb5_ticket *,
					      krb5_keyblock **,
					      krb5_kvno *);

int validate_as_request (krb5_kdc_req *, krb5_db_entry,
					  krb5_db_entry, krb5_timestamp,
					  const char **);

int validate_tgs_request (krb5_kdc_req *, krb5_db_entry,
					  krb5_ticket *, krb5_timestamp,
					  const char **);

int fetch_asn1_field (unsigned char *, unsigned int, unsigned int,
				 krb5_data *);

int
dbentry_has_key_for_enctype (krb5_context context,
				       krb5_db_entry *client,
				       krb5_enctype enctype);

int
dbentry_supports_enctype (krb5_context context,
				    krb5_db_entry *client,
				    krb5_enctype enctype);

krb5_enctype
select_session_keytype (krb5_context context,
				  krb5_db_entry *server,
				  int nktypes,
				  krb5_enctype *ktypes);

krb5_error_code
get_salt_from_key (krb5_context, krb5_principal,
			     krb5_key_data *, krb5_data *);

void limit_string (char *name);

void
ktypes2str(char *s, size_t len, int nktypes, krb5_enctype *ktype);

void
rep_etypes2str(char *s, size_t len, krb5_kdc_rep *rep);

/* do_as_req.c */
krb5_error_code process_as_req (krb5_kdc_req *, krb5_data *,
					  const krb5_fulladdr *,
					  krb5_data ** );

/* do_tgs_req.c */
krb5_error_code process_tgs_req (krb5_data *,
					   const krb5_fulladdr *,
					   krb5_data ** );
/* dispatch.c */
krb5_error_code dispatch (krb5_data *,
				    const krb5_fulladdr *,
				    krb5_data **);

/* main.c */
krb5_error_code kdc_initialize_rcache (krb5_context, char *);

krb5_error_code setup_server_realm (krb5_principal);

/* network.c */
krb5_error_code listen_and_process (const char *);
krb5_error_code setup_network (const char *);
krb5_error_code closedown_network (const char *);

/* policy.c */
int against_local_policy_as (krb5_kdc_req *, krb5_db_entry,
					krb5_db_entry, krb5_timestamp,
					const char **);

int against_local_policy_tgs (krb5_kdc_req *, krb5_db_entry,
					krb5_ticket *, const char **);

/* kdc_preauth.c */
const char * missing_required_preauth
    (krb5_db_entry *client, krb5_db_entry *server,
	       krb5_enc_tkt_part *enc_tkt_reply);
void get_preauth_hint_list (krb5_kdc_req * request,
				      krb5_db_entry *client,
				      krb5_db_entry *server,
				      krb5_data *e_data);
krb5_error_code load_preauth_plugins(krb5_context context);
krb5_error_code unload_preauth_plugins(krb5_context context);

krb5_error_code check_padata
    (krb5_context context, krb5_db_entry *client, krb5_data *req_pkt,
	       krb5_kdc_req *request, krb5_enc_tkt_part *enc_tkt_reply,
	       void **padata_context, krb5_data *e_data);

krb5_error_code return_padata
    (krb5_context context, krb5_db_entry *client,
	       krb5_data *req_pkt, krb5_kdc_req *request, krb5_kdc_rep *reply,
	       krb5_key_data *client_key, krb5_keyblock *encrypting_key,
	       void **padata_context);

krb5_error_code free_padata_context
    (krb5_context context, void **padata_context);

/* replay.c */
krb5_boolean kdc_check_lookaside (krb5_data *, krb5_data **);
void kdc_insert_lookaside (krb5_data *, krb5_data *);
void kdc_free_lookaside(krb5_context);

/* which way to convert key? */
#define CONVERT_INTO_DB	0
#define CONVERT_OUTOF_DB 1

#define isflagset(flagfield, flag) (flagfield & (flag))
#define setflag(flagfield, flag) (flagfield |= (flag))
#define clear(flagfield, flag) (flagfield &= ~(flag))

#ifdef KRB5_KRB4_COMPAT
krb5_error_code process_v4 (const krb5_data *,
				      const krb5_fulladdr *,
				      krb5_data **);
void process_v4_mode (const char *, const char *);
void enable_v4_crossrealm(char *);
#else
#define process_v4(foo,bar,quux,foobar)	KRB5KRB_AP_ERR_BADVERSION
#endif

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

#ifdef KRB5_USE_INET6
#define ADDRTYPE2FAMILY(X) \
  ((X) == ADDRTYPE_INET6 ? AF_INET6 : (X) == ADDRTYPE_INET ? AF_INET : -1)
#else
#define ADDRTYPE2FAMILY(X) \
  ((X) == ADDRTYPE_INET ? AF_INET : -1)
#endif

/* RFC 4120: KRB5KDC_ERR_KEY_TOO_WEAK
 * RFC 4556: KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED */
#define KRB5KDC_ERR_KEY_TOO_WEAK KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED

#ifdef	__cplusplus
}
#endif

#endif	/* !__KRB5_KDC_UTIL__ */
