/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * src/lib/krb5/asn.1/krb5_encode.c
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

#include "k5-int.h"
#include "asn1_k_encode.h"
#include "asn1_encode.h"
#include "krbasn1.h"
#include "asn1buf.h"
#include "asn1_make.h"

/**************** Macros (these save a lot of typing) ****************/

/* setup() -- create and initialize bookkeeping variables
     retval: stores error codes returned from subroutines
     buf: the coding buffer
     length: length of the most-recently produced encoding
     sum: cumulative length of the entire encoding */
#define krb5_setup()\
  asn1_error_code retval;\
  unsigned int length, sum = 0;\
  asn1buf *buf=NULL;\
  krb5_data *tmpcode;\
\
  *code = NULL;\
\
  if (rep == NULL) return ASN1_MISSING_FIELD;\
\
  retval = asn1buf_create(&buf);\
  if (retval) return retval

/* produce the final output and clean up the workspace */
#define krb5_cleanup()\
  retval = asn12krb5_buf(buf,&tmpcode);\
error:\
  asn1buf_destroy(&buf);\
  if (retval)\
    return retval;\
  *code = tmpcode;\
  return 0

#ifndef DISABLE_PKINIT
krb5_error_code encode_krb5_pa_pk_as_req(const krb5_pa_pk_as_req *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_pa_pk_as_req(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_req_draft9(const krb5_pa_pk_as_req_draft9 *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_pa_pk_as_req_draft9(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_rep(const krb5_pa_pk_as_rep *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_pa_pk_as_rep(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_rep_draft9(const krb5_pa_pk_as_rep_draft9 *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_pa_pk_as_rep_draft9(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_auth_pack(const krb5_auth_pack *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_auth_pack(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_auth_pack_draft9(const krb5_auth_pack_draft9 *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_auth_pack_draft9(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_kdc_dh_key_info(const krb5_kdc_dh_key_info *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_kdc_dh_key_info(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_reply_key_pack(const krb5_reply_key_pack *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_reply_key_pack(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_reply_key_pack_draft9(const krb5_reply_key_pack_draft9 *rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_reply_key_pack_draft9(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_td_trusted_certifiers(const krb5_external_principal_identifier **rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_td_trusted_certifiers(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

krb5_error_code encode_krb5_td_dh_parameters(const krb5_algorithm_identifier **rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_sequence_of_algorithm_identifier(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}
#endif /* DISABLE_PKINIT */

krb5_error_code encode_krb5_typed_data(const krb5_typed_data **rep, krb5_data **code)
{
    krb5_setup();
    retval = asn1_encode_sequence_of_typed_data(buf,rep,&length);
    if (retval) goto error;
    sum += length;
    krb5_cleanup();
}

