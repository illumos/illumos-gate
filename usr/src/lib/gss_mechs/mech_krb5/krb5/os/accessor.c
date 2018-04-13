/*
 * lib/krb5/os/accessor.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
*/

#include "k5-int.h"
#include "os-proto.h"

/* If this trick gets used elsewhere, move it to k5-platform.h.  */
#ifndef DESIGNATED_INITIALIZERS
/* ANSI/ISO C 1999 supports this...  */
#if __STDC_VERSION__ >= 199901L				\
   /* ...as does GCC, since version 2.something.  */	\
   || (!defined __cplusplus && __GNUC__ >= 3)
#define DESIGNATED_INITIALIZERS	1
#else
#define DESIGNATED_INITIALIZERS	0
#endif
#endif

krb5_error_code KRB5_CALLCONV
krb5int_accessor(krb5int_access *internals, krb5_int32 version)
{
    if (version == KRB5INT_ACCESS_VERSION) {
#if DESIGNATED_INITIALIZERS
#define S(FIELD, VAL)   .FIELD = VAL
	static const krb5int_access internals_temp = {
#else
#define S(FIELD, VAL)   internals_temp.FIELD = VAL
	    krb5int_access internals_temp;
#endif
	    S (free_addrlist, krb5int_free_addrlist),
	    S (krb5_hmac, krb5_hmac),
	    S (md5_hash_provider, &krb5int_hash_md5),
	    S (arcfour_enc_provider, &krb5int_enc_arcfour),
	    S (sendto_udp, &krb5int_sendto),
	    S (add_host_to_list, krb5int_add_host_to_list),
#ifdef KRB5_DNS_LOOKUP
	    S (make_srv_query_realm, krb5int_make_srv_query_realm),
	    S (free_srv_dns_data, krb5int_free_srv_dns_data),
	    S (use_dns_kdc, _krb5_use_dns_kdc),
#else
	    S (make_srv_query_realm, 0),
	    S (free_srv_dns_data, 0),
	    S (use_dns_kdc, 0),
#endif
            S (clean_hostname, krb5int_clean_hostname),

#ifdef KRB5_KRB4_COMPAT
	    S (krb_life_to_time, krb5int_krb_life_to_time),
	    S (krb_time_to_life, krb5int_krb_time_to_life),
	    S (krb524_encode_v4tkt, krb5int_encode_v4tkt),
#else
	    S (krb_life_to_time, 0),
	    S (krb_time_to_life, 0),
	    S (krb524_encode_v4tkt, 0),
#endif
	    S (krb5int_c_mandatory_cksumtype, krb5int_c_mandatory_cksumtype),
	    S (krb5_ser_pack_int64, krb5_ser_pack_int64),
	    S (krb5_ser_unpack_int64, krb5_ser_unpack_int64),
	    S (asn1_ldap_encode_sequence_of_keys, krb5int_ldap_encode_sequence_of_keys),
	    S (asn1_ldap_decode_sequence_of_keys, krb5int_ldap_decode_sequence_of_keys),
	    S (encode_krb5_pa_pk_as_req, encode_krb5_pa_pk_as_req),
	    S (encode_krb5_pa_pk_as_req_draft9, encode_krb5_pa_pk_as_req_draft9),
            S (encode_krb5_pa_pk_as_rep, encode_krb5_pa_pk_as_rep),
	    S (encode_krb5_pa_pk_as_rep_draft9, encode_krb5_pa_pk_as_rep_draft9),
	    S (encode_krb5_auth_pack, encode_krb5_auth_pack),
	    S (encode_krb5_auth_pack_draft9, encode_krb5_auth_pack_draft9),
	    S (encode_krb5_kdc_dh_key_info, encode_krb5_kdc_dh_key_info),
	    S (encode_krb5_reply_key_pack, encode_krb5_reply_key_pack),
	    S (encode_krb5_reply_key_pack_draft9, encode_krb5_reply_key_pack_draft9),
	    S (encode_krb5_typed_data, encode_krb5_typed_data),
	    S (encode_krb5_td_trusted_certifiers, encode_krb5_td_trusted_certifiers),
	    S (encode_krb5_td_dh_parameters, encode_krb5_td_dh_parameters),
	    S (decode_krb5_pa_pk_as_req, decode_krb5_pa_pk_as_req),
	    S (decode_krb5_pa_pk_as_req_draft9, decode_krb5_pa_pk_as_req_draft9),
	    S (decode_krb5_pa_pk_as_rep, decode_krb5_pa_pk_as_rep),
	    S (decode_krb5_pa_pk_as_rep_draft9, decode_krb5_pa_pk_as_rep_draft9),
	    S (decode_krb5_auth_pack, decode_krb5_auth_pack),
	    S (decode_krb5_auth_pack_draft9, decode_krb5_auth_pack_draft9),
	    S (decode_krb5_kdc_dh_key_info, decode_krb5_kdc_dh_key_info),
	    S (decode_krb5_principal_name, decode_krb5_principal_name),
	    S (decode_krb5_reply_key_pack, decode_krb5_reply_key_pack),
	    S (decode_krb5_reply_key_pack_draft9, decode_krb5_reply_key_pack_draft9),
	    S (decode_krb5_typed_data, decode_krb5_typed_data),
	    S (decode_krb5_td_trusted_certifiers, decode_krb5_td_trusted_certifiers),
	    S (decode_krb5_td_dh_parameters, decode_krb5_td_dh_parameters),
	    S (decode_krb5_as_req, decode_krb5_as_req),
	    S (encode_krb5_kdc_req_body, encode_krb5_kdc_req_body),
	    S (krb5_free_kdc_req, krb5_free_kdc_req),
	    S (krb5int_set_prompt_types, krb5int_set_prompt_types),
	    S (encode_krb5_authdata_elt, encode_krb5_authdata_elt),
#if DESIGNATED_INITIALIZERS
	};
#else
	/*LINTED*/
	0;
#endif
	*internals = internals_temp;
	return 0;
    }
    return KRB5_OBSOLETE_FN;
}
