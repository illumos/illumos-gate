/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * src/lib/krb5/asn.1/asn1_k_encode.h
 *
 * Copyright 1994, 2008 by the Massachusetts Institute of Technology.
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
 */

#ifndef __ASN1_ENCODE_KRB5_H__
#define __ASN1_ENCODE_KRB5_H__

#include "k5-int.h"
#include <stdio.h>
#include "asn1buf.h"

/*
**** for simple val's ****
asn1_error_code asn1_encode_asn1_type(asn1buf *buf,
                                      const krb5_type val,
                                      int *retlen);
   requires  *buf is allocated
   effects   Inserts the encoding of val into *buf and
              returns the length of this encoding in *retlen.
             Returns ASN1_MISSING_FIELD if a required field is empty in val.
             Returns ENOMEM if memory runs out.

**** for struct val's ****
asn1_error_code asn1_encode_asn1_type(asn1buf *buf,
                                      const krb5_type *val,
                                      int *retlen);
   requires  *buf is allocated
   effects   Inserts the encoding of *val into *buf and
              returns the length of this encoding in *retlen.
             Returns ASN1_MISSING_FIELD if a required field is empty in val.
             Returns ENOMEM if memory runs out.

**** for array val's ****
asn1_error_code asn1_encode_asn1_type(asn1buf *buf,
                                      const krb5_type **val,
                                      int *retlen);
   requires  *buf is allocated, **val != NULL, *val[0] != NULL,
              **val is a NULL-terminated array of pointers to krb5_type
   effects   Inserts the encoding of **val into *buf and
              returns the length of this encoding in *retlen.
             Returns ASN1_MISSING_FIELD if a required field is empty in val.
             Returns ENOMEM if memory runs out.
*/

/* PKINIT */

asn1_error_code asn1_encode_pk_authenticator
        (asn1buf *buf, const krb5_pk_authenticator *val, unsigned int *retlen);

asn1_error_code asn1_encode_pk_authenticator_draft9
        (asn1buf *buf, const krb5_pk_authenticator_draft9 *val, unsigned int *retlen);

asn1_error_code asn1_encode_algorithm_identifier
        (asn1buf *buf, const krb5_algorithm_identifier *val, unsigned int *retlen);

asn1_error_code asn1_encode_subject_pk_info
        (asn1buf *buf, const krb5_subject_pk_info *val, unsigned int *retlen);

asn1_error_code asn1_encode_sequence_of_algorithm_identifier
        (asn1buf *buf, const krb5_algorithm_identifier **val, unsigned int *retlen);

asn1_error_code asn1_encode_auth_pack
        (asn1buf *buf, const krb5_auth_pack *val, unsigned int *retlen);

asn1_error_code asn1_encode_auth_pack_draft9
        (asn1buf *buf, const krb5_auth_pack_draft9 *val, unsigned int *retlen);

asn1_error_code asn1_encode_external_principal_identifier
        (asn1buf *buf, const krb5_external_principal_identifier *val, unsigned int *retlen);

asn1_error_code asn1_encode_sequence_of_external_principal_identifier
        (asn1buf *buf, const krb5_external_principal_identifier **val, unsigned int *retlen);

asn1_error_code asn1_encode_pa_pk_as_req
        (asn1buf *buf, const krb5_pa_pk_as_req *val, unsigned int *retlen);

asn1_error_code asn1_encode_trusted_ca
        (asn1buf *buf, const krb5_trusted_ca *val, unsigned int *retlen);

asn1_error_code asn1_encode_sequence_of_trusted_ca
        (asn1buf *buf, const krb5_trusted_ca **val, unsigned int *retlen);

asn1_error_code asn1_encode_pa_pk_as_req_draft9
        (asn1buf *buf, const krb5_pa_pk_as_req_draft9 *val, unsigned int *retlen);

asn1_error_code asn1_encode_dh_rep_info
        (asn1buf *buf, const krb5_dh_rep_info *val, unsigned int *retlen);

asn1_error_code asn1_encode_kdc_dh_key_info
        (asn1buf *buf, const krb5_kdc_dh_key_info *val, unsigned int *retlen);

asn1_error_code asn1_encode_reply_key_pack
        (asn1buf *buf, const krb5_reply_key_pack *val, unsigned int *retlen);

asn1_error_code asn1_encode_reply_key_pack_draft9
        (asn1buf *buf, const krb5_reply_key_pack_draft9 *val, unsigned int *retlen);

asn1_error_code asn1_encode_pa_pk_as_rep
        (asn1buf *buf, const krb5_pa_pk_as_rep *val, unsigned int *retlen);

asn1_error_code asn1_encode_pa_pk_as_rep_draft9
        (asn1buf *buf, const krb5_pa_pk_as_rep_draft9 *val, unsigned int *retlen);

asn1_error_code asn1_encode_td_trusted_certifiers
        (asn1buf *buf, const krb5_external_principal_identifier **val, unsigned int *retlen);

asn1_error_code asn1_encode_typed_data
        (asn1buf *buf, const krb5_typed_data *val, unsigned int *retlen);

asn1_error_code asn1_encode_sequence_of_typed_data
        (asn1buf *buf, const krb5_typed_data **val, unsigned int *retlen);

#endif
