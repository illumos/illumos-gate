/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * src/lib/krb5/asn.1/asn1_k_encode.c
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

#include "asn1_k_encode.h"
#include "asn1_make.h"
#include "asn1_encode.h"
#include <assert.h>
#include "k5-platform-store_32.h" /* Solaris Kerberos */

/* helper macros

   These are mostly only needed for PKINIT, but there are three
   basic-krb5 encoders not converted yet.  */

/* setup() -- create and initialize bookkeeping variables
     retval: stores error codes returned from subroutines
     length: length of the most-recently produced encoding
     sum: cumulative length of the entire encoding */
#define asn1_setup()\
  asn1_error_code retval;\
  unsigned int sum=0

/* form a sequence (by adding a sequence header to the current encoding) */
#define asn1_makeseq()\
{ unsigned int length;\
  retval = asn1_make_sequence(buf,sum,&length);\
  if (retval) {\
    return retval; }\
  sum += length; }

/* produce the final output and clean up the workspace */
#define asn1_cleanup()\
  *retlen = sum;\
  return 0

/* asn1_addfield -- add a field, or component, to the encoding */
#define asn1_addfield(value,tag,encoder)\
{ unsigned int length; \
  retval = encoder(buf,value,&length);  \
  if (retval) {\
    return retval; }\
  sum += length;\
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,tag,length,&length);\
  if (retval) {\
    return retval; }\
  sum += length; }

DEFINTTYPE(int32, krb5_int32);
DEFPTRTYPE(int32_ptr, int32);

DEFUINTTYPE(uint, unsigned int);
DEFUINTTYPE(octet, krb5_octet);
DEFUINTTYPE(ui_4, krb5_ui_4);

DEFFNLENTYPE(octetstring, unsigned char *, asn1_encode_octetstring);
DEFFNLENTYPE(s_octetstring, char *, asn1_encode_octetstring);
DEFFNLENTYPE(charstring, char *, asn1_encode_charstring);
DEFFNLENTYPE(generalstring, char *, asn1_encode_generalstring);
DEFFNLENTYPE(u_generalstring, unsigned char *, asn1_encode_generalstring);
DEFFNLENTYPE(opaque, char *, asn1_encode_opaque);

DEFFIELDTYPE(gstring_data, krb5_data,
             FIELDOF_STRING(krb5_data, generalstring, data, length, -1));
DEFPTRTYPE(gstring_data_ptr,gstring_data);

DEFFIELDTYPE(ostring_data, krb5_data,
             FIELDOF_STRING(krb5_data, s_octetstring, data, length, -1));
DEFPTRTYPE(ostring_data_ptr,ostring_data);

DEFFIELDTYPE(opaque_data, krb5_data,
             FIELDOF_STRING(krb5_data, opaque, data, length, -1));

DEFFIELDTYPE(realm_of_principal_data, krb5_principal_data,
             FIELDOF_NORM(krb5_principal_data, gstring_data, realm, -1));
DEFPTRTYPE(realm_of_principal, realm_of_principal_data);


static const struct field_info princname_fields[] = {
    FIELDOF_NORM(krb5_principal_data, int32, type, 0),
    FIELDOF_SEQOF_INT32(krb5_principal_data, gstring_data_ptr, data, length, 1),
};
/* krb5_principal is a typedef for krb5_principal_data*, so this is
   effectively "encode_principal_data_at" with an address arg.  */
DEFSEQTYPE(principal_data, krb5_principal_data, princname_fields, 0);
DEFPTRTYPE(principal, principal_data);

static asn1_error_code
asn1_encode_kerberos_time_at(asn1buf *buf, const krb5_timestamp *val,
                             unsigned int *retlen)
{
    /* Range checking for time_t vs krb5_timestamp?  */
    time_t tval = *val;
    return asn1_encode_generaltime(buf, tval, retlen);
}
DEFFNXTYPE(kerberos_time, krb5_timestamp, asn1_encode_kerberos_time_at);

static const struct field_info address_fields[] = {
    FIELDOF_NORM(krb5_address, int32, addrtype, 0),
    FIELDOF_STRING(krb5_address, octetstring, contents, length, 1),
};
DEFSEQTYPE(address, krb5_address, address_fields, 0);
DEFPTRTYPE(address_ptr, address);

DEFNULLTERMSEQOFTYPE(seq_of_host_addresses, address_ptr);
DEFPTRTYPE(ptr_seqof_host_addresses, seq_of_host_addresses);

static unsigned int
optional_encrypted_data (const void *vptr)
{
    const krb5_enc_data *val = vptr;
    unsigned int optional = 0;

    if (val->kvno != 0)
        optional |= (1u << 1);

    return optional;
}

static const struct field_info encrypted_data_fields[] = {
    FIELDOF_NORM(krb5_enc_data, int32, enctype, 0),
    FIELDOF_OPT(krb5_enc_data, uint, kvno, 1, 1),
    FIELDOF_NORM(krb5_enc_data, ostring_data, ciphertext, 2),
};
DEFSEQTYPE(encrypted_data, krb5_enc_data, encrypted_data_fields,
           optional_encrypted_data);

/* The encode_bitstring function wants an array of bytes (since PKINIT
   may provide something that isn't 32 bits), but krb5_flags is stored
   as a 32-bit integer in host order.  */
static asn1_error_code
asn1_encode_krb5_flags_at(asn1buf *buf, const krb5_flags *val,
                          unsigned int *retlen)
{
    unsigned char cbuf[4];
    store_32_be((krb5_ui_4) *val, cbuf);
    return asn1_encode_bitstring(buf, 4, cbuf, retlen);
}
DEFFNXTYPE(krb5_flags, krb5_flags, asn1_encode_krb5_flags_at);

static const struct field_info authdata_elt_fields[] = {
    /* ad-type[0]               INTEGER */
    FIELDOF_NORM(krb5_authdata, int32, ad_type, 0),
    /* ad-data[1]               OCTET STRING */
    FIELDOF_STRING(krb5_authdata, octetstring, contents, length, 1),
};
DEFSEQTYPE(authdata_elt, krb5_authdata, authdata_elt_fields, 0);
DEFPTRTYPE(authdata_elt_ptr, authdata_elt);
DEFNONEMPTYNULLTERMSEQOFTYPE(auth_data, authdata_elt_ptr);
DEFPTRTYPE(auth_data_ptr, auth_data);

static const struct field_info encryption_key_fields[] = {
    FIELDOF_NORM(krb5_keyblock, int32, enctype, 0),
    FIELDOF_STRING(krb5_keyblock, octetstring, contents, length, 1),
};
DEFSEQTYPE(encryption_key, krb5_keyblock, encryption_key_fields, 0);
DEFPTRTYPE(ptr_encryption_key, encryption_key);

static const struct field_info checksum_fields[] = {
    FIELDOF_NORM(krb5_checksum, int32, checksum_type, 0),
    FIELDOF_STRING(krb5_checksum, octetstring, contents, length, 1),
};
DEFSEQTYPE(checksum, krb5_checksum, checksum_fields, 0);
DEFPTRTYPE(checksum_ptr, checksum);
DEFNULLTERMSEQOFTYPE(seq_of_checksum, checksum_ptr);
DEFPTRTYPE(ptr_seqof_checksum, seq_of_checksum);

static const struct field_info lr_fields[] = {
    FIELDOF_NORM(krb5_last_req_entry, int32, lr_type, 0),
    FIELDOF_NORM(krb5_last_req_entry, kerberos_time, value, 1),
};
DEFSEQTYPE(last_req_ent, krb5_last_req_entry, lr_fields, 0);

DEFPTRTYPE(last_req_ent_ptr, last_req_ent);
DEFNONEMPTYNULLTERMSEQOFTYPE(last_req, last_req_ent_ptr);
DEFPTRTYPE(last_req_ptr, last_req);

static const struct field_info ticket_fields[] = {
    FIELD_INT_IMM(KVNO, 0),
    FIELDOF_NORM(krb5_ticket, realm_of_principal, server, 1),
    FIELDOF_NORM(krb5_ticket, principal, server, 2),
    FIELDOF_NORM(krb5_ticket, encrypted_data, enc_part, 3),
};
DEFSEQTYPE(untagged_ticket, krb5_ticket, ticket_fields, 0);
DEFAPPTAGGEDTYPE(ticket, 1, untagged_ticket);

static const struct field_info pa_data_fields[] = {
    FIELDOF_NORM(krb5_pa_data, int32, pa_type, 1),
    FIELDOF_STRING(krb5_pa_data, octetstring, contents, length, 2),
};
DEFSEQTYPE(pa_data, krb5_pa_data, pa_data_fields, 0);
DEFPTRTYPE(pa_data_ptr, pa_data);

DEFNULLTERMSEQOFTYPE(seq_of_pa_data, pa_data_ptr);
DEFPTRTYPE(ptr_seqof_pa_data, seq_of_pa_data);

DEFPTRTYPE(ticket_ptr, ticket);
DEFNONEMPTYNULLTERMSEQOFTYPE(seq_of_ticket,ticket_ptr);
DEFPTRTYPE(ptr_seqof_ticket, seq_of_ticket);

/* EncKDCRepPart ::= SEQUENCE */
static const struct field_info enc_kdc_rep_part_fields[] = {
    /* key[0]           EncryptionKey */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, ptr_encryption_key, session, 0),
    /* last-req[1]      LastReq */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, last_req_ptr, last_req, 1),
    /* nonce[2]         INTEGER */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, int32, nonce, 2),
    /* key-expiration[3]        KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, kerberos_time, key_exp, 3, 3),
    /* flags[4]         TicketFlags */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, krb5_flags, flags, 4),
    /* authtime[5]      KerberosTime */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, kerberos_time, times.authtime, 5),
    /* starttime[6]     KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, kerberos_time, times.starttime, 6, 6),
    /* endtime[7]               KerberosTime */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, kerberos_time, times.endtime, 7),
    /* renew-till[8]    KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, kerberos_time, times.renew_till, 8, 8),
    /* srealm[9]                Realm */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, realm_of_principal, server, 9),
    /* sname[10]                PrincipalName */
    FIELDOF_NORM(krb5_enc_kdc_rep_part, principal, server, 10),
    /* caddr[11]                HostAddresses OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, ptr_seqof_host_addresses, caddrs,
                11, 11),
    /* encrypted-pa-data[12]    SEQUENCE OF PA-DATA OPTIONAL */
    FIELDOF_OPT(krb5_enc_kdc_rep_part, ptr_seqof_pa_data, enc_padata, 12, 12),
};
static unsigned int optional_enc_kdc_rep_part(const void *p)
{
    const krb5_enc_kdc_rep_part *val = p;
    unsigned int optional = 0;

    if (val->key_exp)
        optional |= (1u << 3);
    if (val->times.starttime)
        optional |= (1u << 6);
    if (val->flags & TKT_FLG_RENEWABLE)
        optional |= (1u << 8);
    if (val->caddrs != NULL && val->caddrs[0] != NULL)
        optional |= (1u << 11);

    return optional;
}
DEFSEQTYPE(enc_kdc_rep_part, krb5_enc_kdc_rep_part, enc_kdc_rep_part_fields,
           optional_enc_kdc_rep_part);

/* Yuck!  Eventually push this *up* above the encoder API and make the
   rest of the library put the realm name in one consistent place.  At
   the same time, might as well add the msg-type field and encode both
   AS-REQ and TGS-REQ through the same descriptor.  */
struct kdc_req_hack {
    krb5_kdc_req v;
    krb5_data *server_realm;
};
static const struct field_info kdc_req_hack_fields[] = {
    FIELDOF_NORM(struct kdc_req_hack, krb5_flags, v.kdc_options, 0),
    FIELDOF_OPT(struct kdc_req_hack, principal, v.client, 1, 1),
    FIELDOF_NORM(struct kdc_req_hack, gstring_data_ptr, server_realm, 2),
    FIELDOF_OPT(struct kdc_req_hack, principal, v.server, 3, 3),
    FIELDOF_OPT(struct kdc_req_hack, kerberos_time, v.from, 4, 4),
    FIELDOF_NORM(struct kdc_req_hack, kerberos_time, v.till, 5),
    FIELDOF_OPT(struct kdc_req_hack, kerberos_time, v.rtime, 6, 6),
    FIELDOF_NORM(struct kdc_req_hack, int32, v.nonce, 7),
    FIELDOF_SEQOF_INT32(struct kdc_req_hack, int32_ptr, v.ktype, v.nktypes, 8),
    FIELDOF_OPT(struct kdc_req_hack, ptr_seqof_host_addresses, v.addresses, 9, 9),
    FIELDOF_OPT(struct kdc_req_hack, encrypted_data, v.authorization_data, 10, 10),
    FIELDOF_OPT(struct kdc_req_hack, ptr_seqof_ticket, v.second_ticket, 11, 11),
};
static unsigned int optional_kdc_req_hack(const void *p)
{
    const struct kdc_req_hack *val2 = p;
    const krb5_kdc_req *val = &val2->v;
    unsigned int optional = 0;

    if (val->second_ticket != NULL && val->second_ticket[0] != NULL)
        optional |= (1u << 11);
    if (val->authorization_data.ciphertext.data != NULL)
        optional |= (1u << 10);
    if (val->addresses != NULL && val->addresses[0] != NULL)
        optional |= (1u << 9);
    if (val->rtime)
        optional |= (1u << 6);
    if (val->from)
        optional |= (1u << 4);
    if (val->server != NULL)
        optional |= (1u << 3);
    if (val->client != NULL)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(kdc_req_body_hack, struct kdc_req_hack, kdc_req_hack_fields,
           optional_kdc_req_hack);
static asn1_error_code
asn1_encode_kdc_req_hack(asn1buf *, const struct kdc_req_hack *,
                         unsigned int *);
MAKE_ENCFN(asn1_encode_kdc_req_hack, kdc_req_body_hack);
static asn1_error_code
asn1_encode_kdc_req_body(asn1buf *buf, const krb5_kdc_req *val,
                         unsigned int *retlen)
{
    struct kdc_req_hack val2;
    val2.v = *val;
    if (val->kdc_options & KDC_OPT_ENC_TKT_IN_SKEY) {
        if (val->second_ticket != NULL && val->second_ticket[0] != NULL) {
            val2.server_realm = &val->second_ticket[0]->server->realm;
        } else return ASN1_MISSING_FIELD;
    } else if (val->server != NULL) {
        val2.server_realm = &val->server->realm;
    } else return ASN1_MISSING_FIELD;
    return asn1_encode_kdc_req_hack(buf, &val2, retlen);
}
DEFFNXTYPE(kdc_req_body, krb5_kdc_req, asn1_encode_kdc_req_body);
/* end ugly hack */

DEFPTRTYPE(ptr_kdc_req_body,kdc_req_body);

static const struct field_info transited_fields[] = {
    FIELDOF_NORM(krb5_transited, octet, tr_type, 0),
    FIELDOF_NORM(krb5_transited, ostring_data, tr_contents, 1),
};
DEFSEQTYPE(transited, krb5_transited, transited_fields, 0);

static const struct field_info krb_safe_body_fields[] = {
    FIELDOF_NORM(krb5_safe, ostring_data, user_data, 0),
    FIELDOF_OPT(krb5_safe, kerberos_time, timestamp, 1, 1),
    FIELDOF_OPT(krb5_safe, int32, usec, 2, 2),
    FIELDOF_OPT(krb5_safe, uint, seq_number, 3, 3),
    FIELDOF_NORM(krb5_safe, address_ptr, s_address, 4),
    FIELDOF_OPT(krb5_safe, address_ptr, r_address, 5, 5),
};
static unsigned int optional_krb_safe_body(const void *p)
{
    const krb5_safe *val = p;
    unsigned int optional = 0;

    if (val->timestamp) {
        optional |= (1u << 1);
        optional |= (1u << 2);
    }
    if (val->seq_number)
        optional |= (1u << 3);
    if (val->r_address != NULL)
        optional |= (1u << 5);

    return optional;
}
DEFSEQTYPE(krb_safe_body, krb5_safe, krb_safe_body_fields,
           optional_krb_safe_body);

static const struct field_info krb_cred_info_fields[] = {
    FIELDOF_NORM(krb5_cred_info, ptr_encryption_key, session, 0),
    FIELDOF_OPT(krb5_cred_info, realm_of_principal, client, 1, 1),
    FIELDOF_OPT(krb5_cred_info, principal, client, 2, 2),
    FIELDOF_OPT(krb5_cred_info, krb5_flags, flags, 3, 3),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.authtime, 4, 4),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.starttime, 5, 5),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.endtime, 6, 6),
    FIELDOF_OPT(krb5_cred_info, kerberos_time, times.renew_till, 7, 7),
    FIELDOF_OPT(krb5_cred_info, realm_of_principal, server, 8, 8),
    FIELDOF_OPT(krb5_cred_info, principal, server, 9, 9),
    FIELDOF_OPT(krb5_cred_info, ptr_seqof_host_addresses, caddrs, 10, 10),
};
static unsigned int optional_krb_cred_info(const void *p)
{
    const krb5_cred_info *val = p;
    unsigned int optional = 0;

    if (val->caddrs != NULL && val->caddrs[0] != NULL)
        optional |= (1u << 10);
    if (val->server != NULL) {
        optional |= (1u << 9);
        optional |= (1u << 8);
    }
    if (val->times.renew_till)
        optional |= (1u << 7);
    if (val->times.endtime)
        optional |= (1u << 6);
    if (val->times.starttime)
        optional |= (1u << 5);
    if (val->times.authtime)
        optional |= (1u << 4);
    if (val->flags)
        optional |= (1u << 3);
    if (val->client != NULL) {
        optional |= (1u << 2);
        optional |= (1u << 1);
    }

    return optional;
}
DEFSEQTYPE(cred_info, krb5_cred_info, krb_cred_info_fields,
           optional_krb_cred_info);
DEFPTRTYPE(cred_info_ptr, cred_info);
DEFNULLTERMSEQOFTYPE(seq_of_cred_info, cred_info_ptr);

DEFPTRTYPE(ptrseqof_cred_info, seq_of_cred_info);



static unsigned int
optional_etype_info_entry(const void *vptr)
{
    const krb5_etype_info_entry *val = vptr;
    unsigned int optional = 0;

    if (val->length >= 0 && val->length != KRB5_ETYPE_NO_SALT)
        optional |= (1u << 1);

    return optional;
}
static const struct field_info etype_info_entry_fields[] = {
    FIELDOF_NORM(krb5_etype_info_entry, int32, etype, 0),
    FIELDOF_OPTSTRING(krb5_etype_info_entry, octetstring, salt, length, 1, 1),
};
DEFSEQTYPE(etype_info_entry, krb5_etype_info_entry, etype_info_entry_fields,
           optional_etype_info_entry);

static unsigned int
optional_etype_info2_entry(const void *vptr)
{
    const krb5_etype_info_entry *val = vptr;
    unsigned int optional = 0;

    if (val->length >= 0 && val->length != KRB5_ETYPE_NO_SALT)
        optional |= (1u << 1);
    if (val->s2kparams.data)
        optional |= (1u << 2);

    return optional;
}

static const struct field_info etype_info2_entry_fields[] = {
    FIELDOF_NORM(krb5_etype_info_entry, int32, etype, 0),
    FIELDOF_OPTSTRING(krb5_etype_info_entry, u_generalstring, salt, length,
                      1, 1),
    FIELDOF_OPT(krb5_etype_info_entry, ostring_data, s2kparams, 2, 2),
};
DEFSEQTYPE(etype_info2_entry, krb5_etype_info_entry, etype_info2_entry_fields,
           optional_etype_info2_entry);

DEFPTRTYPE(etype_info_entry_ptr, etype_info_entry);
DEFNULLTERMSEQOFTYPE(etype_info, etype_info_entry_ptr);

DEFPTRTYPE(etype_info2_entry_ptr, etype_info2_entry);
DEFNULLTERMSEQOFTYPE(etype_info2, etype_info2_entry_ptr);

static const struct field_info passwdsequence_fields[] = {
    FIELDOF_NORM(passwd_phrase_element, ostring_data_ptr, passwd, 0),
    FIELDOF_NORM(passwd_phrase_element, ostring_data_ptr, phrase, 1),
};
DEFSEQTYPE(passwdsequence, passwd_phrase_element, passwdsequence_fields, 0);

DEFPTRTYPE(passwdsequence_ptr, passwdsequence);
DEFNONEMPTYNULLTERMSEQOFTYPE(seqof_passwdsequence, passwdsequence_ptr);
DEFPTRTYPE(ptr_seqof_passwdsequence, seqof_passwdsequence);


static const struct field_info sam_challenge_fields[] = {
    FIELDOF_NORM(krb5_sam_challenge, int32, sam_type, 0),
    FIELDOF_NORM(krb5_sam_challenge, krb5_flags, sam_flags, 1),
    FIELDOF_OPT(krb5_sam_challenge, ostring_data, sam_type_name, 2, 2),
    FIELDOF_OPT(krb5_sam_challenge, ostring_data, sam_track_id,3, 3),
    FIELDOF_OPT(krb5_sam_challenge, ostring_data, sam_challenge_label,4, 4),
    FIELDOF_OPT(krb5_sam_challenge, ostring_data, sam_challenge,5, 5),
    FIELDOF_OPT(krb5_sam_challenge, ostring_data, sam_response_prompt,6, 6),
    FIELDOF_OPT(krb5_sam_challenge, ostring_data, sam_pk_for_sad,7, 7),
    FIELDOF_OPT(krb5_sam_challenge, int32, sam_nonce, 8, 8),
    FIELDOF_OPT(krb5_sam_challenge, checksum, sam_cksum, 9, 9),
};
static unsigned int optional_sam_challenge(const void *p)
{
    const krb5_sam_challenge *val = p;
    unsigned int optional = 0;

    if (val->sam_cksum.length)
        optional |= (1u << 9);

    if (val->sam_nonce)
        optional |= (1u << 8);

    if (val->sam_pk_for_sad.length > 0) optional |= (1u << 7);
    if (val->sam_response_prompt.length > 0) optional |= (1u << 6);
    if (val->sam_challenge.length > 0) optional |= (1u << 5);
    if (val->sam_challenge_label.length > 0) optional |= (1u << 4);
    if (val->sam_track_id.length > 0) optional |= (1u << 3);
    if (val->sam_type_name.length > 0) optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(sam_challenge,krb5_sam_challenge,sam_challenge_fields,
           optional_sam_challenge);

#if 0 /* encoders not used! */
MAKE_ENCFN(asn1_encode_sequence_of_checksum, seq_of_checksum);
static asn1_error_code
asn1_encode_sam_challenge_2(asn1buf *buf, const krb5_sam_challenge_2 *val,
                            unsigned int *retlen)
{
    asn1_setup();
    if ( (!val) || (!val->sam_cksum) || (!val->sam_cksum[0]))
        return ASN1_MISSING_FIELD;

    asn1_addfield(val->sam_cksum, 1, asn1_encode_sequence_of_checksum);

    {
        unsigned int length;

        retval = asn1buf_insert_octetstring(buf, val->sam_challenge_2_body.length,
                                            (unsigned char *)val->sam_challenge_2_body.data);
        if (retval) {
            return retval;
        }
        sum += val->sam_challenge_2_body.length;
        retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0,
                                val->sam_challenge_2_body.length, &length);
        if (retval) {
            return retval;
        }
        sum += length;
    }

    asn1_makeseq();
    asn1_cleanup();
}
DEFFNXTYPE(sam_challenge_2, krb5_sam_challenge_2, asn1_encode_sam_challenge_2);

static const struct field_info sam_challenge_2_body_fields[] = {
    FIELDOF_NORM(krb5_sam_challenge_2_body, int32, sam_type, 0),
    FIELDOF_NORM(krb5_sam_challenge_2_body, krb5_flags, sam_flags, 1),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_type_name, 2, 2),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_track_id,3, 3),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_challenge_label,4, 4),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_challenge,5, 5),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_response_prompt,6, 6),
    FIELDOF_OPT(krb5_sam_challenge_2_body, ostring_data, sam_pk_for_sad,7, 7),
    FIELDOF_NORM(krb5_sam_challenge_2_body, int32, sam_nonce, 8),
    FIELDOF_NORM(krb5_sam_challenge_2_body, int32, sam_etype, 9),
};
static unsigned int optional_sam_challenge_2_body(const void *p)
{
    const krb5_sam_challenge_2_body *val = p;
    unsigned int optional = 0;

    if (val->sam_pk_for_sad.length > 0) optional |= (1u << 7);
    if (val->sam_response_prompt.length > 0) optional |= (1u << 6);
    if (val->sam_challenge.length > 0) optional |= (1u << 5);
    if (val->sam_challenge_label.length > 0) optional |= (1u << 4);
    if (val->sam_track_id.length > 0) optional |= (1u << 3);
    if (val->sam_type_name.length > 0) optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(sam_challenge_2_body,krb5_sam_challenge_2_body,sam_challenge_2_body_fields,
           optional_sam_challenge_2_body);
#endif

static const struct field_info sam_key_fields[] = {
    FIELDOF_NORM(krb5_sam_key, encryption_key, sam_key, 0),
};
DEFSEQTYPE(sam_key, krb5_sam_key, sam_key_fields, 0);

static const struct field_info enc_sam_response_enc_fields[] = {
    FIELDOF_NORM(krb5_enc_sam_response_enc, int32, sam_nonce, 0),
    FIELDOF_NORM(krb5_enc_sam_response_enc, kerberos_time, sam_timestamp, 1),
    FIELDOF_NORM(krb5_enc_sam_response_enc, int32, sam_usec, 2),
    FIELDOF_OPT(krb5_enc_sam_response_enc, ostring_data, sam_sad, 3, 3),
};
static unsigned int optional_enc_sam_response_enc(const void *p)
{
    const krb5_enc_sam_response_enc *val = p;
    unsigned int optional = 0;

    if (val->sam_sad.length > 0) optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(enc_sam_response_enc, krb5_enc_sam_response_enc,
           enc_sam_response_enc_fields, optional_enc_sam_response_enc);

static const struct field_info enc_sam_response_enc_2_fields[] = {
    FIELDOF_NORM(krb5_enc_sam_response_enc_2, int32, sam_nonce, 0),
    FIELDOF_OPT(krb5_enc_sam_response_enc_2, ostring_data, sam_sad, 1, 1),
};
static unsigned int optional_enc_sam_response_enc_2(const void *p)
{
    const krb5_enc_sam_response_enc_2 *val = p;
    unsigned int optional = 0;

    if (val->sam_sad.length > 0) optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(enc_sam_response_enc_2, krb5_enc_sam_response_enc_2,
           enc_sam_response_enc_2_fields, optional_enc_sam_response_enc_2);

static const struct field_info sam_response_fields[] = {
    FIELDOF_NORM(krb5_sam_response, int32, sam_type, 0),
    FIELDOF_NORM(krb5_sam_response, krb5_flags, sam_flags, 1),
    FIELDOF_OPT(krb5_sam_response, ostring_data, sam_track_id, 2, 2),
    FIELDOF_OPT(krb5_sam_response, encrypted_data, sam_enc_key, 3, 3),
    FIELDOF_NORM(krb5_sam_response, encrypted_data, sam_enc_nonce_or_ts, 4),
    FIELDOF_OPT(krb5_sam_response, int32, sam_nonce, 5, 5),
    FIELDOF_OPT(krb5_sam_response, kerberos_time, sam_patimestamp, 6, 6),
};
static unsigned int optional_sam_response(const void *p)
{
    const krb5_sam_response *val = p;
    unsigned int optional = 0;

    if (val->sam_patimestamp)
        optional |= (1u << 6);
    if (val->sam_nonce)
        optional |= (1u << 5);
    if (val->sam_enc_key.ciphertext.length)
        optional |= (1u << 3);
    if (val->sam_track_id.length > 0) optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(sam_response, krb5_sam_response, sam_response_fields,
           optional_sam_response);

static const struct field_info sam_response_2_fields[] = {
    FIELDOF_NORM(krb5_sam_response_2, int32, sam_type, 0),
    FIELDOF_NORM(krb5_sam_response_2, krb5_flags, sam_flags, 1),
    FIELDOF_OPT(krb5_sam_response_2, ostring_data, sam_track_id, 2, 2),
    FIELDOF_NORM(krb5_sam_response_2, encrypted_data, sam_enc_nonce_or_sad, 3),
    FIELDOF_NORM(krb5_sam_response_2, int32, sam_nonce, 4),
};
static unsigned int optional_sam_response_2(const void *p)
{
    const krb5_sam_response_2 *val = p;
    unsigned int optional = 0;

    if (val->sam_track_id.length > 0) optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(sam_response_2, krb5_sam_response_2, sam_response_2_fields,
           optional_sam_response_2);

static const struct field_info predicted_sam_response_fields[] = {
    FIELDOF_NORM(krb5_predicted_sam_response, encryption_key, sam_key, 0),
    FIELDOF_NORM(krb5_predicted_sam_response, krb5_flags, sam_flags, 1),
    FIELDOF_NORM(krb5_predicted_sam_response, kerberos_time, stime, 2),
    FIELDOF_NORM(krb5_predicted_sam_response, int32, susec, 3),
    FIELDOF_NORM(krb5_predicted_sam_response, realm_of_principal, client, 4),
    FIELDOF_NORM(krb5_predicted_sam_response, principal, client, 5),
    FIELDOF_OPT(krb5_predicted_sam_response, ostring_data, msd, 6, 6),
};
static unsigned int optional_predicted_sam_response(const void *p)
{
    const krb5_predicted_sam_response *val = p;
    unsigned int optional = 0;

    if (val->msd.length > 0) optional |= (1u << 6);

    return optional;
}
DEFSEQTYPE(predicted_sam_response, krb5_predicted_sam_response,
           predicted_sam_response_fields,
           optional_predicted_sam_response);

static const struct field_info krb5_authenticator_fields[] = {
    /* Authenticator ::= [APPLICATION 2] SEQUENCE */
    /* authenticator-vno[0]     INTEGER */
    FIELD_INT_IMM(KVNO, 0),
    /* crealm[1]                        Realm */
    FIELDOF_NORM(krb5_authenticator, realm_of_principal, client, 1),
    /* cname[2]                 PrincipalName */
    FIELDOF_NORM(krb5_authenticator, principal, client, 2),
    /* cksum[3]                 Checksum OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, checksum_ptr, checksum, 3, 3),
    /* cusec[4]                 INTEGER */
    FIELDOF_NORM(krb5_authenticator, int32, cusec, 4),
    /* ctime[5]                 KerberosTime */
    FIELDOF_NORM(krb5_authenticator, kerberos_time, ctime, 5),
    /* subkey[6]                        EncryptionKey OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, ptr_encryption_key, subkey, 6, 6),
    /* seq-number[7]            INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, uint, seq_number, 7, 7),
    /* authorization-data[8]    AuthorizationData OPTIONAL */
    FIELDOF_OPT(krb5_authenticator, auth_data_ptr, authorization_data, 8, 8),
};
static unsigned int optional_krb5_authenticator(const void *p)
{
    const krb5_authenticator *val = p;
    unsigned int optional = 0;

    if (val->authorization_data != NULL && val->authorization_data[0] != NULL)
        optional |= (1u << 8);

    if (val->seq_number != 0)
        optional |= (1u << 7);

    if (val->subkey != NULL)
        optional |= (1u << 6);

    if (val->checksum != NULL)
        optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(untagged_krb5_authenticator, krb5_authenticator, krb5_authenticator_fields,
           optional_krb5_authenticator);
DEFAPPTAGGEDTYPE(krb5_authenticator, 2, untagged_krb5_authenticator);

static const struct field_info enc_tkt_part_fields[] = {
    /* EncTicketPart ::= [APPLICATION 3] SEQUENCE */
    /* flags[0]                 TicketFlags */
    FIELDOF_NORM(krb5_enc_tkt_part, krb5_flags, flags, 0),
    /* key[1]                   EncryptionKey */
    FIELDOF_NORM(krb5_enc_tkt_part, ptr_encryption_key, session, 1),
    /* crealm[2]                        Realm */
    FIELDOF_NORM(krb5_enc_tkt_part, realm_of_principal, client, 2),
    /* cname[3]                 PrincipalName */
    FIELDOF_NORM(krb5_enc_tkt_part, principal, client, 3),
    /* transited[4]             TransitedEncoding */
    FIELDOF_NORM(krb5_enc_tkt_part, transited, transited, 4),
    /* authtime[5]              KerberosTime */
    FIELDOF_NORM(krb5_enc_tkt_part, kerberos_time, times.authtime, 5),
    /* starttime[6]             KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, kerberos_time, times.starttime, 6, 6),
    /* endtime[7]                       KerberosTime */
    FIELDOF_NORM(krb5_enc_tkt_part, kerberos_time, times.endtime, 7),
    /* renew-till[8]            KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, kerberos_time, times.renew_till, 8, 8),
    /* caddr[9]                 HostAddresses OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, ptr_seqof_host_addresses, caddrs, 9, 9),
    /* authorization-data[10]   AuthorizationData OPTIONAL */
    FIELDOF_OPT(krb5_enc_tkt_part, auth_data_ptr, authorization_data, 10, 10),
};
static unsigned int optional_enc_tkt_part(const void *p)
{
    const krb5_enc_tkt_part *val = p;
    unsigned int optional = 0;

    if (val->authorization_data != NULL && val->authorization_data[0] != NULL)
        optional |= (1u << 10);
    if (val->caddrs != NULL && val->caddrs[0] != NULL)
        optional |= (1u << 9);
    if (val->times.renew_till)
        optional |= (1u << 8);
    if (val->times.starttime)
        optional |= (1u << 6);

    return optional;
}
DEFSEQTYPE(untagged_enc_tkt_part, krb5_enc_tkt_part, enc_tkt_part_fields,
           optional_enc_tkt_part);
DEFAPPTAGGEDTYPE(enc_tkt_part, 3, untagged_enc_tkt_part);

DEFAPPTAGGEDTYPE(enc_tgs_rep_part, 26, enc_kdc_rep_part);

static const struct field_info as_rep_fields[] = {
    /* AS-REP ::= [APPLICATION 11] KDC-REP */
    /* But KDC-REP needs to know what type it's being encapsulated
       in, so expand each version.  */
    FIELD_INT_IMM(KVNO, 0),
    FIELD_INT_IMM(KRB5_AS_REP, 1),
    FIELDOF_OPT(krb5_kdc_rep, ptr_seqof_pa_data, padata, 2, 2),
    FIELDOF_NORM(krb5_kdc_rep, realm_of_principal, client, 3),
    FIELDOF_NORM(krb5_kdc_rep, principal, client, 4),
    FIELDOF_NORM(krb5_kdc_rep, ticket_ptr, ticket, 5),
    FIELDOF_NORM(krb5_kdc_rep, encrypted_data, enc_part, 6),
};
static unsigned int optional_as_rep(const void *p)
{
    const krb5_kdc_rep *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(untagged_as_rep, krb5_kdc_rep, as_rep_fields, optional_as_rep);
DEFAPPTAGGEDTYPE(as_rep, 11, untagged_as_rep);

static const struct field_info tgs_rep_fields[] = {
    /* TGS-REP ::= [APPLICATION 13] KDC-REP */
    /* But KDC-REP needs to know what type it's being encapsulated
       in, so expand each version.  */
    FIELD_INT_IMM(KVNO, 0),
    FIELD_INT_IMM(KRB5_TGS_REP, 1),
    FIELDOF_OPT(krb5_kdc_rep, ptr_seqof_pa_data, padata, 2, 2),
    FIELDOF_NORM(krb5_kdc_rep, realm_of_principal, client, 3),
    FIELDOF_NORM(krb5_kdc_rep, principal, client, 4),
    FIELDOF_NORM(krb5_kdc_rep, ticket_ptr, ticket, 5),
    FIELDOF_NORM(krb5_kdc_rep, encrypted_data, enc_part, 6),
};
static unsigned int optional_tgs_rep(const void *p)
{
    const krb5_kdc_rep *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(untagged_tgs_rep, krb5_kdc_rep, tgs_rep_fields, optional_tgs_rep);
DEFAPPTAGGEDTYPE(tgs_rep, 13, untagged_tgs_rep);

static const struct field_info ap_req_fields[] = {
    /* AP-REQ ::=       [APPLICATION 14] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0),
    /* msg-type[1]      INTEGER */
    FIELD_INT_IMM(ASN1_KRB_AP_REQ, 1),
    /* ap-options[2]    APOptions */
    FIELDOF_NORM(krb5_ap_req, krb5_flags, ap_options, 2),
    /* ticket[3]                Ticket */
    FIELDOF_NORM(krb5_ap_req, ticket_ptr, ticket, 3),
    /* authenticator[4] EncryptedData */
    FIELDOF_NORM(krb5_ap_req, encrypted_data, authenticator, 4),
};
DEFSEQTYPE(untagged_ap_req, krb5_ap_req, ap_req_fields, 0);
DEFAPPTAGGEDTYPE(ap_req, 14, untagged_ap_req);

static const struct field_info ap_rep_fields[] = {
    /* AP-REP ::=       [APPLICATION 15] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0),
    /* msg-type[1]      INTEGER */
    FIELD_INT_IMM(ASN1_KRB_AP_REP, 1),
    /* enc-part[2]      EncryptedData */
    FIELDOF_NORM(krb5_ap_rep, encrypted_data, enc_part, 2),
};
DEFSEQTYPE(untagged_ap_rep, krb5_ap_rep, ap_rep_fields, 0);
DEFAPPTAGGEDTYPE(ap_rep, 15, untagged_ap_rep);

static const struct field_info ap_rep_enc_part_fields[] = {
    /* EncAPRepPart ::= [APPLICATION 27] SEQUENCE */
    /* ctime[0]         KerberosTime */
    FIELDOF_NORM(krb5_ap_rep_enc_part, kerberos_time, ctime, 0),
    /* cusec[1]         INTEGER */
    FIELDOF_NORM(krb5_ap_rep_enc_part, int32, cusec, 1),
    /* subkey[2]                EncryptionKey OPTIONAL */
    FIELDOF_OPT(krb5_ap_rep_enc_part, ptr_encryption_key, subkey, 2, 2),
    /* seq-number[3]    INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_ap_rep_enc_part, uint, seq_number, 3, 3),
};
static unsigned int optional_ap_rep_enc_part(const void *p)
{
    const krb5_ap_rep_enc_part *val = p;
    unsigned int optional = 0;

    if (val->seq_number)
        optional |= (1u << 3);
    if (val->subkey != NULL)
        optional |= (1u << 2);

    return optional;
}
DEFSEQTYPE(untagged_ap_rep_enc_part, krb5_ap_rep_enc_part,
           ap_rep_enc_part_fields, optional_ap_rep_enc_part);
DEFAPPTAGGEDTYPE(ap_rep_enc_part, 27, untagged_ap_rep_enc_part);

static const struct field_info as_req_fields[] = {
    /* AS-REQ ::= [APPLICATION 10] KDC-REQ */
    FIELD_INT_IMM(KVNO, 1),
    FIELD_INT_IMM(KRB5_AS_REQ, 2),
    FIELDOF_OPT(krb5_kdc_req, ptr_seqof_pa_data, padata, 3, 3),
    FIELDOF_ENCODEAS(krb5_kdc_req, kdc_req_body, 4),
};
static unsigned int optional_as_req(const void *p)
{
    const krb5_kdc_req *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(untagged_as_req, krb5_kdc_req, as_req_fields, optional_as_req);
DEFAPPTAGGEDTYPE(as_req, 10, untagged_as_req);

static const struct field_info tgs_req_fields[] = {
    /* TGS-REQ ::= [APPLICATION 12] KDC-REQ */
    FIELD_INT_IMM(KVNO, 1),
    FIELD_INT_IMM(KRB5_TGS_REQ, 2),
    FIELDOF_OPT(krb5_kdc_req, ptr_seqof_pa_data, padata, 3, 3),
    FIELDOF_ENCODEAS(krb5_kdc_req, kdc_req_body, 4),
};
static unsigned int optional_tgs_req(const void *p)
{
    const krb5_kdc_req *val = p;
    unsigned int optional = 0;

    if (val->padata != NULL && val->padata[0] != NULL)
        optional |= (1u << 3);

    return optional;
}
DEFSEQTYPE(untagged_tgs_req, krb5_kdc_req, tgs_req_fields,
           optional_tgs_req);
DEFAPPTAGGEDTYPE(tgs_req, 12, untagged_tgs_req);

static const struct field_info krb5_safe_fields[] = {
    FIELD_INT_IMM(KVNO, 0),
    FIELD_INT_IMM(ASN1_KRB_SAFE,1),
    FIELD_SELF(krb_safe_body, 2),
    FIELDOF_NORM(krb5_safe, checksum_ptr, checksum, 3),
};
DEFSEQTYPE(untagged_krb5_safe, krb5_safe, krb5_safe_fields, 0);
DEFAPPTAGGEDTYPE(krb5_safe, 20, untagged_krb5_safe);

DEFPTRTYPE(krb_saved_safe_body_ptr, opaque_data);
DEFFIELDTYPE(krb5_safe_checksum_only, krb5_safe,
             FIELDOF_NORM(krb5_safe, checksum_ptr, checksum, -1));
DEFPTRTYPE(krb5_safe_checksum_only_ptr, krb5_safe_checksum_only);
static const struct field_info krb5_safe_with_body_fields[] = {
    FIELD_INT_IMM(KVNO, 0),
    FIELD_INT_IMM(ASN1_KRB_SAFE,1),
    FIELDOF_NORM(struct krb5_safe_with_body, krb_saved_safe_body_ptr, body, 2),
    FIELDOF_NORM(struct krb5_safe_with_body, krb5_safe_checksum_only_ptr, safe, 3),
};
DEFSEQTYPE(untagged_krb5_safe_with_body, struct krb5_safe_with_body,
           krb5_safe_with_body_fields, 0);
DEFAPPTAGGEDTYPE(krb5_safe_with_body, 20, untagged_krb5_safe_with_body);

static const struct field_info priv_fields[] = {
    FIELD_INT_IMM(KVNO, 0),
    FIELD_INT_IMM(ASN1_KRB_PRIV, 1),
    FIELDOF_NORM(krb5_priv, encrypted_data, enc_part, 3),
};
DEFSEQTYPE(untagged_priv, krb5_priv, priv_fields, 0);
DEFAPPTAGGEDTYPE(krb5_priv, 21, untagged_priv);

static const struct field_info priv_enc_part_fields[] = {
    FIELDOF_NORM(krb5_priv_enc_part, ostring_data, user_data, 0),
    FIELDOF_OPT(krb5_priv_enc_part, kerberos_time, timestamp, 1, 1),
    FIELDOF_OPT(krb5_priv_enc_part, int32, usec, 2, 2),
    FIELDOF_OPT(krb5_priv_enc_part, uint, seq_number, 3, 3),
    FIELDOF_NORM(krb5_priv_enc_part, address_ptr, s_address, 4),
    FIELDOF_OPT(krb5_priv_enc_part, address_ptr, r_address, 5, 5),
};
static unsigned int optional_priv_enc_part(const void *p)
{
    const krb5_priv_enc_part *val = p;
    unsigned int optional = 0;

    if (val->timestamp) {
        optional |= (1u << 2);
        optional |= (1u << 1);
    }
    if (val->seq_number)
        optional |= (1u << 3);
    if (val->r_address)
        optional |= (1u << 5);

    return optional;
}
DEFSEQTYPE(untagged_priv_enc_part, krb5_priv_enc_part, priv_enc_part_fields,
           optional_priv_enc_part);
DEFAPPTAGGEDTYPE(priv_enc_part, 28, untagged_priv_enc_part);

static const struct field_info cred_fields[] = {
    /* KRB-CRED ::= [APPLICATION 22] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0),
    /* msg-type[1]      INTEGER, -- KRB_CRED */
    FIELD_INT_IMM(ASN1_KRB_CRED, 1),
    /* tickets[2]       SEQUENCE OF Ticket */
    FIELDOF_NORM(krb5_cred, ptr_seqof_ticket, tickets, 2),
    /* enc-part[3]      EncryptedData */
    FIELDOF_NORM(krb5_cred, encrypted_data, enc_part, 3),
};
DEFSEQTYPE(untagged_cred, krb5_cred, cred_fields, 0);
DEFAPPTAGGEDTYPE(krb5_cred, 22, untagged_cred);

static const struct field_info enc_cred_part_fields[] = {
    /* EncKrbCredPart ::= [APPLICATION 29] SEQUENCE */
    /* ticket-info[0]   SEQUENCE OF KrbCredInfo */
    FIELDOF_NORM(krb5_cred_enc_part, ptrseqof_cred_info, ticket_info, 0),
    /* nonce[1]         INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, int32, nonce, 1, 1),
    /* timestamp[2]     KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, kerberos_time, timestamp, 2, 2),
    /* usec[3]          INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, int32, usec, 3, 3),
    /* s-address[4]     HostAddress OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, address_ptr, s_address, 4, 4),
    /* r-address[5]     HostAddress OPTIONAL */
    FIELDOF_OPT(krb5_cred_enc_part, address_ptr, r_address, 5, 5),
};
static unsigned int optional_enc_cred_part(const void *p)
{
    const krb5_cred_enc_part *val = p;
    unsigned int optional = 0;

    if (val->r_address != NULL)
        optional |= (1u << 5);

    if (val->s_address != NULL)
        optional |= (1u << 4);

    if (val->timestamp) {
        optional |= (1u << 2);
        optional |= (1u << 3);
    }

    if (val->nonce)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(untagged_enc_cred_part, krb5_cred_enc_part, enc_cred_part_fields,
           optional_enc_cred_part);
DEFAPPTAGGEDTYPE(enc_cred_part, 29, untagged_enc_cred_part);

static const struct field_info error_fields[] = {
    /* KRB-ERROR ::= [APPLICATION 30] SEQUENCE */
    /* pvno[0]          INTEGER */
    FIELD_INT_IMM(KVNO, 0),
    /* msg-type[1]      INTEGER */
    FIELD_INT_IMM(ASN1_KRB_ERROR, 1),
    /* ctime[2]         KerberosTime OPTIONAL */
    FIELDOF_OPT(krb5_error, kerberos_time, ctime, 2, 2),
    /* cusec[3]         INTEGER OPTIONAL */
    FIELDOF_OPT(krb5_error, int32, cusec, 3, 3),
    /* stime[4]         KerberosTime */
    FIELDOF_NORM(krb5_error, kerberos_time, stime, 4),
    /* susec[5]         INTEGER */
    FIELDOF_NORM(krb5_error, int32, susec, 5),
    /* error-code[6]    INTEGER */
    FIELDOF_NORM(krb5_error, ui_4, error, 6),
    /* crealm[7]        Realm OPTIONAL */
    FIELDOF_OPT(krb5_error, realm_of_principal, client, 7, 7),
    /* cname[8]         PrincipalName OPTIONAL */
    FIELDOF_OPT(krb5_error, principal, client, 8, 8),
    /* realm[9]         Realm -- Correct realm */
    FIELDOF_NORM(krb5_error, realm_of_principal, server, 9),
    /* sname[10]        PrincipalName -- Correct name */
    FIELDOF_NORM(krb5_error, principal, server, 10),
    /* e-text[11]       GeneralString OPTIONAL */
    FIELDOF_OPT(krb5_error, gstring_data, text, 11, 11),
    /* e-data[12]       OCTET STRING OPTIONAL */
    FIELDOF_OPT(krb5_error, ostring_data, e_data, 12, 12),
};
static unsigned int optional_error(const void *p)
{
    const krb5_error *val = p;
    unsigned int optional = 0;

    if (val->ctime)
        optional |= (1u << 2);
    if (val->cusec)
        optional |= (1u << 3);
    if (val->client) {
        optional |= (1u << 7);
        optional |= (1u << 8);
    }
    if (val->text.data != NULL && val->text.length > 0)
        optional |= (1u << 11);
    if (val->e_data.data != NULL && val->e_data.length > 0)
        optional |= (1u << 12);

    return optional;
}
DEFSEQTYPE(untagged_krb5_error, krb5_error, error_fields, optional_error);
DEFAPPTAGGEDTYPE(krb5_error, 30, untagged_krb5_error);

static const struct field_info alt_method_fields[] = {
    FIELDOF_NORM(krb5_alt_method, int32, method, 0),
    FIELDOF_OPTSTRING(krb5_alt_method, octetstring, data, length, 1, 1),
};
static unsigned int
optional_alt_method(const void *p)
{
    const krb5_alt_method *a = p;
    unsigned int optional = 0;

    if (a->data != NULL && a->length > 0)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(alt_method, krb5_alt_method, alt_method_fields, optional_alt_method);

static const struct field_info pa_enc_ts_fields[] = {
    FIELDOF_NORM(krb5_pa_enc_ts, kerberos_time, patimestamp, 0),
    FIELDOF_OPT(krb5_pa_enc_ts, int32, pausec, 1, 1),
};
static unsigned int
optional_pa_enc_ts(const void *p)
{
    const krb5_pa_enc_ts *val = p;
    unsigned int optional = 0;

    if (val->pausec)
        optional |= (1u << 1);

    return optional;
}
DEFSEQTYPE(pa_enc_ts, krb5_pa_enc_ts, pa_enc_ts_fields, optional_pa_enc_ts);

static const struct field_info pwd_data_fields[] = {
    FIELDOF_NORM(krb5_pwd_data, int32, sequence_count, 0),
    FIELDOF_NORM(krb5_pwd_data, ptr_seqof_passwdsequence, element, 1),
};
DEFSEQTYPE(pwd_data, krb5_pwd_data, pwd_data_fields, 0);

static const struct field_info setpw_req_fields[] = {
    FIELDOF_NORM(struct krb5_setpw_req, ostring_data, password, 0),
    FIELDOF_NORM(struct krb5_setpw_req, principal, target, 1),
    FIELDOF_NORM(struct krb5_setpw_req, realm_of_principal, target, 2),
};

DEFSEQTYPE(setpw_req, struct krb5_setpw_req, setpw_req_fields, 0);

/* [MS-SFU] Section 2.2.1. */
static const struct field_info pa_for_user_fields[] = {
    FIELDOF_NORM(krb5_pa_for_user, principal, user, 0),
    FIELDOF_NORM(krb5_pa_for_user, realm_of_principal, user, 1),
    FIELDOF_NORM(krb5_pa_for_user, checksum, cksum, 2),
    FIELDOF_NORM(krb5_pa_for_user, gstring_data, auth_package, 3),
};

DEFSEQTYPE(pa_for_user, krb5_pa_for_user, pa_for_user_fields, 0);

/* draft-ietf-krb-wg-kerberos-referrals Appendix A. */
static const struct field_info pa_svr_referral_data_fields[] = {
    FIELDOF_NORM(krb5_pa_svr_referral_data, realm_of_principal, principal, 0),
    FIELDOF_OPT(krb5_pa_svr_referral_data, principal, principal, 1, 1),
};

DEFSEQTYPE(pa_svr_referral_data, krb5_pa_svr_referral_data, pa_svr_referral_data_fields, 0);

/* draft-ietf-krb-wg-kerberos-referrals Section 8. */
static const struct field_info pa_server_referral_data_fields[] = {
    FIELDOF_OPT(krb5_pa_server_referral_data, gstring_data_ptr, referred_realm, 0, 0),
    FIELDOF_OPT(krb5_pa_server_referral_data, principal, true_principal_name, 1, 1),
    FIELDOF_OPT(krb5_pa_server_referral_data, principal, requested_principal_name, 2, 2),
    FIELDOF_OPT(krb5_pa_server_referral_data, kerberos_time, referral_valid_until, 3, 3),
    FIELDOF_NORM(krb5_pa_server_referral_data, checksum, rep_cksum, 4),
};

DEFSEQTYPE(pa_server_referral_data, krb5_pa_server_referral_data, pa_server_referral_data_fields, 0);

#if 0
/* draft-brezak-win2k-krb-authz Section 6. */
static const struct field_info pa_pac_request_fields[] = {
    FIELDOF_NORM(krb5_pa_pac_req, boolean, include_pac, 0),
};

DEFSEQTYPE(pa_pac_request, krb5_pa_pac_req, pa_pac_request_fields, 0);
#endif

/* RFC 4537 */
DEFFIELDTYPE(etype_list, krb5_etype_list,
             FIELDOF_SEQOF_INT32(krb5_etype_list, int32_ptr, etypes, length, -1));

/* draft-ietf-krb-wg-preauth-framework-09 */
static const struct field_info fast_armor_fields[] = {
    FIELDOF_NORM(krb5_fast_armor, int32, armor_type, 0),
    FIELDOF_NORM( krb5_fast_armor, ostring_data, armor_value, 1),
};

DEFSEQTYPE( fast_armor, krb5_fast_armor, fast_armor_fields, 0);
DEFPTRTYPE( ptr_fast_armor, fast_armor);

static const struct field_info fast_armored_req_fields[] = {
    FIELDOF_OPT( krb5_fast_armored_req, ptr_fast_armor, armor, 0, 0),
    FIELDOF_NORM( krb5_fast_armored_req, checksum, req_checksum, 1),
    FIELDOF_NORM( krb5_fast_armored_req, encrypted_data, enc_part, 2),
};

static unsigned int fast_armored_req_optional (const void *p) {
    const krb5_fast_armored_req *val = p;
    unsigned int optional = 0;
    if (val->armor)
        optional |= (1u)<<0;
    return optional;
}

DEFSEQTYPE( fast_armored_req, krb5_fast_armored_req, fast_armored_req_fields, fast_armored_req_optional);
DEFFIELDTYPE( pa_fx_fast_request, krb5_fast_armored_req,
              FIELDOF_ENCODEAS( krb5_fast_armored_req, fast_armored_req, 0));

DEFFIELDTYPE(fast_req_padata, krb5_kdc_req,
             FIELDOF_NORM(krb5_kdc_req, ptr_seqof_pa_data, padata, -1));
DEFPTRTYPE(ptr_fast_req_padata, fast_req_padata);

static const struct field_info fast_req_fields[] = {
    FIELDOF_NORM(krb5_fast_req, krb5_flags, fast_options, 0),
    FIELDOF_NORM( krb5_fast_req, ptr_fast_req_padata, req_body, 1),
    FIELDOF_NORM( krb5_fast_req, ptr_kdc_req_body, req_body, 2),
};

DEFSEQTYPE(fast_req, krb5_fast_req, fast_req_fields, 0);


static const struct field_info fast_finished_fields[] = {
    FIELDOF_NORM( krb5_fast_finished, kerberos_time, timestamp, 0),
    FIELDOF_NORM( krb5_fast_finished, int32, usec, 1),
    FIELDOF_NORM( krb5_fast_finished, realm_of_principal, client, 2),
    FIELDOF_NORM(krb5_fast_finished, principal, client, 3),
    FIELDOF_NORM( krb5_fast_finished, checksum, ticket_checksum, 4),
};

DEFSEQTYPE( fast_finished, krb5_fast_finished, fast_finished_fields, 0);

DEFPTRTYPE( ptr_fast_finished, fast_finished);

static const struct field_info fast_response_fields[] = {
    FIELDOF_NORM(krb5_fast_response, ptr_seqof_pa_data, padata, 0),
    FIELDOF_OPT( krb5_fast_response, ptr_encryption_key, strengthen_key, 1, 1),
    FIELDOF_OPT( krb5_fast_response, ptr_fast_finished, finished, 2, 2),
    FIELDOF_NORM(krb5_fast_response, int32, nonce, 3),
};

static unsigned int fast_response_optional (const void *p)
{
    unsigned int optional = 0;
    const krb5_fast_response *val = p;
    if (val->strengthen_key)
        optional |= (1u <<1);
    if (val->finished)
        optional |= (1u<<2);
    return optional;
}
DEFSEQTYPE( fast_response, krb5_fast_response, fast_response_fields, fast_response_optional);

static const struct field_info fast_rep_fields[] = {
  FIELDOF_ENCODEAS(krb5_enc_data, encrypted_data, 0),
};
DEFSEQTYPE(fast_rep, krb5_enc_data, fast_rep_fields, 0);

DEFFIELDTYPE(pa_fx_fast_reply, krb5_enc_data,
             FIELDOF_ENCODEAS(krb5_enc_data, fast_rep, 0));




/* Exported complete encoders -- these produce a krb5_data with
   the encoding in the correct byte order.  */

MAKE_FULL_ENCODER(encode_krb5_authenticator, krb5_authenticator);
MAKE_FULL_ENCODER(encode_krb5_ticket, ticket);
MAKE_FULL_ENCODER(encode_krb5_encryption_key, encryption_key);
MAKE_FULL_ENCODER(encode_krb5_enc_tkt_part, enc_tkt_part);
/* XXX We currently (for backwards compatibility) encode both
   EncASRepPart and EncTGSRepPart with application tag 26.  */
MAKE_FULL_ENCODER(encode_krb5_enc_kdc_rep_part, enc_tgs_rep_part);
MAKE_FULL_ENCODER(encode_krb5_as_rep, as_rep);
MAKE_FULL_ENCODER(encode_krb5_tgs_rep, tgs_rep);
MAKE_FULL_ENCODER(encode_krb5_ap_req, ap_req);
MAKE_FULL_ENCODER(encode_krb5_ap_rep, ap_rep);
MAKE_FULL_ENCODER(encode_krb5_ap_rep_enc_part, ap_rep_enc_part);
MAKE_FULL_ENCODER(encode_krb5_as_req, as_req);
MAKE_FULL_ENCODER(encode_krb5_tgs_req, tgs_req);
MAKE_FULL_ENCODER(encode_krb5_kdc_req_body, kdc_req_body);
MAKE_FULL_ENCODER(encode_krb5_safe, krb5_safe);

/*
 * encode_krb5_safe_with_body
 *
 * Like encode_krb5_safe(), except takes a saved KRB-SAFE-BODY
 * encoding to avoid problems with re-encoding.
 */
MAKE_FULL_ENCODER(encode_krb5_safe_with_body, krb5_safe_with_body);

MAKE_FULL_ENCODER(encode_krb5_priv, krb5_priv);
MAKE_FULL_ENCODER(encode_krb5_enc_priv_part, priv_enc_part);
MAKE_FULL_ENCODER(encode_krb5_cred, krb5_cred);
MAKE_FULL_ENCODER(encode_krb5_enc_cred_part, enc_cred_part);
MAKE_FULL_ENCODER(encode_krb5_error, krb5_error);
MAKE_FULL_ENCODER(encode_krb5_authdata, auth_data);
MAKE_FULL_ENCODER(encode_krb5_authdata_elt, authdata_elt);
MAKE_FULL_ENCODER(encode_krb5_alt_method, alt_method);
MAKE_FULL_ENCODER(encode_krb5_etype_info, etype_info);
MAKE_FULL_ENCODER(encode_krb5_etype_info2, etype_info2);
MAKE_FULL_ENCODER(encode_krb5_enc_data, encrypted_data);
MAKE_FULL_ENCODER(encode_krb5_pa_enc_ts, pa_enc_ts);
/* Sandia Additions */
MAKE_FULL_ENCODER(encode_krb5_pwd_sequence, passwdsequence);
MAKE_FULL_ENCODER(encode_krb5_pwd_data, pwd_data);
MAKE_FULL_ENCODER(encode_krb5_padata_sequence, seq_of_pa_data);
/* sam preauth additions */
MAKE_FULL_ENCODER(encode_krb5_sam_challenge, sam_challenge);
#if 0 /* encoders not used! */
MAKE_FULL_ENCODER(encode_krb5_sam_challenge_2, sam_challenge_2);
MAKE_FULL_ENCODER(encode_krb5_sam_challenge_2_body,
                  sam_challenge_2_body);
#endif
MAKE_FULL_ENCODER(encode_krb5_sam_key, sam_key);
MAKE_FULL_ENCODER(encode_krb5_enc_sam_response_enc,
                  enc_sam_response_enc);
MAKE_FULL_ENCODER(encode_krb5_enc_sam_response_enc_2,
                  enc_sam_response_enc_2);
MAKE_FULL_ENCODER(encode_krb5_sam_response, sam_response);
MAKE_FULL_ENCODER(encode_krb5_sam_response_2, sam_response_2);
MAKE_FULL_ENCODER(encode_krb5_predicted_sam_response,
                  predicted_sam_response);
MAKE_FULL_ENCODER(encode_krb5_setpw_req, setpw_req);
MAKE_FULL_ENCODER(encode_krb5_pa_for_user, pa_for_user);
MAKE_FULL_ENCODER(encode_krb5_pa_svr_referral_data, pa_svr_referral_data);
MAKE_FULL_ENCODER(encode_krb5_pa_server_referral_data, pa_server_referral_data);
MAKE_FULL_ENCODER(encode_krb5_etype_list, etype_list);

MAKE_FULL_ENCODER(encode_krb5_pa_fx_fast_request, pa_fx_fast_request);
MAKE_FULL_ENCODER( encode_krb5_fast_req, fast_req);
MAKE_FULL_ENCODER( encode_krb5_pa_fx_fast_reply, pa_fx_fast_reply);
MAKE_FULL_ENCODER(encode_krb5_fast_response, fast_response);






/*
 * PKINIT
 */

/* This code hasn't been converted to use the above framework yet,
   because we currently have no test cases to validate the new
   version.  It *also* appears that some of the encodings may disagree
   with the specifications, but that's a separate problem.  */

/**** asn1 macros ****/
#if 0
   How to write an asn1 encoder function using these macros:

   asn1_error_code asn1_encode_krb5_substructure(asn1buf *buf,
                                                 const krb5_type *val,
                                                 int *retlen)
   {
     asn1_setup();

     asn1_addfield(val->last_field, n, asn1_type);
     asn1_addfield(rep->next_to_last_field, n-1, asn1_type);
     ...

     /* for OPTIONAL fields */
     if (rep->field_i == should_not_be_omitted)
       asn1_addfield(rep->field_i, i, asn1_type);

     /* for string fields (these encoders take an additional argument,
        the length of the string) */
     addlenfield(rep->field_length, rep->field, i-1, asn1_type);

     /* if you really have to do things yourself... */
     retval = asn1_encode_asn1_type(buf,rep->field,&length);
     if (retval) return retval;
     sum += length;
     retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, tag_number, length,
                             &length);
     if (retval) return retval;
     sum += length;

     ...
     asn1_addfield(rep->second_field, 1, asn1_type);
     asn1_addfield(rep->first_field, 0, asn1_type);
     asn1_makeseq();

     asn1_cleanup();
   }
#endif

/* asn1_addlenfield -- add a field whose length must be separately specified */
#define asn1_addlenfield(len,value,tag,encoder)\
{ unsigned int length; \
  retval = encoder(buf,len,value,&length);      \
  if (retval) {\
    return retval; }\
  sum += length;\
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,tag,length,&length);\
  if (retval) {\
    return retval; }\
  sum += length; }

/* asn1_addfield_implicit -- add an implicitly tagged field, or component, to the encoding */
#define asn1_addfield_implicit(value,tag,encoder)\
{ unsigned int length;\
  retval = encoder(buf,value,&length);\
  if (retval) {\
    return retval; }\
  sum += length;\
  retval = asn1_make_tag(buf,CONTEXT_SPECIFIC,PRIMITIVE,tag,length,&length); \
  if (retval) {\
    return retval; }\
  sum += length; }

/* asn1_insert_implicit_octetstring -- add an octet string with implicit tagging */
#define asn1_insert_implicit_octetstring(len,value,tag)\
{ unsigned int length;\
  retval = asn1buf_insert_octetstring(buf,len,value);\
  if (retval) {\
    return retval; }\
  sum += len;\
  retval = asn1_make_tag(buf,CONTEXT_SPECIFIC,PRIMITIVE,tag,len,&length); \
  if (retval) {\
    return retval; }\
  sum += length; }

/* asn1_insert_implicit_bitstring -- add a bitstring with implicit tagging */
/* needs "length" declared in enclosing context */
#define asn1_insert_implicit_bitstring(len,value,tag)\
{ retval = asn1buf_insert_octetstring(buf,len,value); \
  if (retval) {\
    return retval; }\
  sum += len;\
  retval = asn1buf_insert_octet(buf, 0);\
  if (retval) {\
    return retval; }\
  sum++;\
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,tag,len+1,&length); \
  if (retval) {\
    return retval; }\
  sum += length; }

#ifndef DISABLE_PKINIT

/* Callable encoders for the types defined above, until the PKINIT
   encoders get converted.  */
MAKE_ENCFN(asn1_encode_realm, realm_of_principal_data);
MAKE_ENCFN(asn1_encode_principal_name, principal_data);
MAKE_ENCFN(asn1_encode_encryption_key, encryption_key);
MAKE_ENCFN(asn1_encode_checksum, checksum);

static asn1_error_code
asn1_encode_kerberos_time(asn1buf *buf, const krb5_timestamp val,
                          unsigned int *retlen)
{
    return asn1_encode_kerberos_time_at(buf,&val,retlen);
}

/* Now the real PKINIT encoder functions.  */
asn1_error_code asn1_encode_pk_authenticator(asn1buf *buf, const krb5_pk_authenticator *val, unsigned int *retlen)
{
    asn1_setup();
    asn1_addlenfield(val->paChecksum.length, val->paChecksum.contents, 3, asn1_encode_octetstring);
    asn1_addfield(val->nonce, 2, asn1_encode_integer);
    asn1_addfield(val->ctime, 1, asn1_encode_kerberos_time);
    asn1_addfield(val->cusec, 0, asn1_encode_integer);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_pk_authenticator_draft9(asn1buf *buf, const krb5_pk_authenticator_draft9 *val, unsigned int *retlen)
{
    asn1_setup();

    asn1_addfield(val->nonce, 4, asn1_encode_integer);
    asn1_addfield(val->ctime, 3, asn1_encode_kerberos_time);
    asn1_addfield(val->cusec, 2, asn1_encode_integer);
    asn1_addfield(val->kdcName, 1, asn1_encode_realm);
    asn1_addfield(val->kdcName, 0, asn1_encode_principal_name);

    asn1_makeseq();
    asn1_cleanup();
}


asn1_error_code asn1_encode_algorithm_identifier(asn1buf *buf, const krb5_algorithm_identifier *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->parameters.length != 0) {
        retval = asn1buf_insert_octetstring(buf, val->parameters.length,
                                            val->parameters.data);
        if (retval)
            return retval;
        sum += val->parameters.length;
    }

    {
        unsigned int length;
        retval = asn1_encode_oid(buf, val->algorithm.length,
                                 val->algorithm.data,
                                 &length);

        if (retval)
            return retval;
        sum += length;
    }

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_subject_pk_info(asn1buf *buf, const krb5_subject_pk_info *val, unsigned int *retlen)
{
    asn1_setup();

    {
        unsigned int length;
        asn1_insert_implicit_bitstring(val->subjectPublicKey.length,val->subjectPublicKey.data,ASN1_BITSTRING);
    }

    if (val->algorithm.parameters.length != 0) {
        unsigned int length;

        retval = asn1buf_insert_octetstring(buf, val->algorithm.parameters.length,
                                            val->algorithm.parameters.data);
        if (retval)
            return retval;
        sum += val->algorithm.parameters.length;

        retval = asn1_encode_oid(buf, val->algorithm.algorithm.length,
                                 val->algorithm.algorithm.data,
                                 &length);

        if (retval)
            return retval;
        sum += length;


        retval = asn1_make_etag(buf, UNIVERSAL, ASN1_SEQUENCE,
                                val->algorithm.parameters.length + length,
                                &length);

        if (retval)
            return retval;
        sum += length;
    }

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_algorithm_identifier(asn1buf *buf, const krb5_algorithm_identifier **val, unsigned int *retlen)
{
    asn1_setup();
    int i;

    if (val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

    for (i=0; val[i] != NULL; i++);
    for (i--; i>=0; i--) {
        unsigned int length;
        retval = asn1_encode_algorithm_identifier(buf,val[i],&length);
        if (retval) return retval;
        sum += length;
    }
    asn1_makeseq();

    asn1_cleanup();
}

asn1_error_code asn1_encode_auth_pack(asn1buf *buf, const krb5_auth_pack *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->clientDHNonce.length != 0)
        asn1_addlenfield(val->clientDHNonce.length, val->clientDHNonce.data, 3, asn1_encode_octetstring);
    if (val->supportedCMSTypes != NULL)
        asn1_addfield((const krb5_algorithm_identifier **)val->supportedCMSTypes,2,asn1_encode_sequence_of_algorithm_identifier);
    if (val->clientPublicValue != NULL)
        asn1_addfield(val->clientPublicValue,1,asn1_encode_subject_pk_info);
    asn1_addfield(&(val->pkAuthenticator),0,asn1_encode_pk_authenticator);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_auth_pack_draft9(asn1buf *buf, const krb5_auth_pack_draft9 *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->clientPublicValue != NULL)
        asn1_addfield(val->clientPublicValue, 1, asn1_encode_subject_pk_info);
    asn1_addfield(&(val->pkAuthenticator), 0, asn1_encode_pk_authenticator_draft9);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_external_principal_identifier(asn1buf *buf, const krb5_external_principal_identifier *val, unsigned int *retlen)
{
    asn1_setup();

    /* Verify there is something to encode */
    if (val->subjectKeyIdentifier.length == 0 && val->issuerAndSerialNumber.length == 0 && val->subjectName.length == 0)
        return ASN1_MISSING_FIELD;

    if (val->subjectKeyIdentifier.length != 0)
        asn1_insert_implicit_octetstring(val->subjectKeyIdentifier.length,val->subjectKeyIdentifier.data,2);

    if (val->issuerAndSerialNumber.length != 0)
        asn1_insert_implicit_octetstring(val->issuerAndSerialNumber.length,val->issuerAndSerialNumber.data,1);

    if (val->subjectName.length != 0)
        asn1_insert_implicit_octetstring(val->subjectName.length,val->subjectName.data,0);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_external_principal_identifier(asn1buf *buf, const krb5_external_principal_identifier **val, unsigned int *retlen)
{
    asn1_setup();
    int i;

    if (val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

    for (i=0; val[i] != NULL; i++);
    for (i--; i>=0; i--) {
        unsigned int length;
        retval = asn1_encode_external_principal_identifier(buf,val[i],&length);
        if (retval) return retval;
        sum += length;
    }
    asn1_makeseq();

    asn1_cleanup();
}

asn1_error_code asn1_encode_pa_pk_as_req(asn1buf *buf, const krb5_pa_pk_as_req *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->kdcPkId.length != 0)
        asn1_insert_implicit_octetstring(val->kdcPkId.length,val->kdcPkId.data,2);

    if (val->trustedCertifiers != NULL)
        asn1_addfield((const krb5_external_principal_identifier **)val->trustedCertifiers,1,asn1_encode_sequence_of_external_principal_identifier);

    asn1_insert_implicit_octetstring(val->signedAuthPack.length,val->signedAuthPack.data,0);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_trusted_ca(asn1buf *buf, const krb5_trusted_ca *val, unsigned int *retlen)
{
    asn1_setup();

    switch (val->choice) {
    case choice_trusted_cas_issuerAndSerial:
        asn1_insert_implicit_octetstring(val->u.issuerAndSerial.length,val->u.issuerAndSerial.data,2);
        break;
    case choice_trusted_cas_caName:
        asn1_insert_implicit_octetstring(val->u.caName.length,val->u.caName.data,1);
        break;
    case choice_trusted_cas_principalName:
        asn1_addfield_implicit(val->u.principalName,0,asn1_encode_principal_name);
        break;
    default:
        return ASN1_MISSING_FIELD;
    }

    asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_trusted_ca(asn1buf *buf, const krb5_trusted_ca **val, unsigned int *retlen)
{
    asn1_setup();
    int i;

    if (val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

    for (i=0; val[i] != NULL; i++);
    for (i--; i>=0; i--) {
        unsigned int length;
        retval = asn1_encode_trusted_ca(buf,val[i],&length);
        if (retval) return retval;
        sum += length;
    }
    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_pa_pk_as_req_draft9(asn1buf *buf, const krb5_pa_pk_as_req_draft9 *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->encryptionCert.length != 0)
        asn1_insert_implicit_octetstring(val->encryptionCert.length,val->encryptionCert.data,3);

    if (val->kdcCert.length != 0)
        asn1_insert_implicit_octetstring(val->kdcCert.length,val->kdcCert.data,2);

    if (val->trustedCertifiers != NULL)
        asn1_addfield((const krb5_trusted_ca **)val->trustedCertifiers,1,asn1_encode_sequence_of_trusted_ca);

    asn1_insert_implicit_octetstring(val->signedAuthPack.length,val->signedAuthPack.data,0);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_dh_rep_info(asn1buf *buf, const krb5_dh_rep_info *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->serverDHNonce.length != 0)
        asn1_insert_implicit_octetstring(val->serverDHNonce.length,val->serverDHNonce.data,1);

    asn1_insert_implicit_octetstring(val->dhSignedData.length,val->dhSignedData.data,0);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_dh_key_info(asn1buf *buf, const krb5_kdc_dh_key_info *val, unsigned int *retlen)
{
    asn1_setup();

    if (val->dhKeyExpiration != 0)
        asn1_addfield(val->dhKeyExpiration, 2, asn1_encode_kerberos_time);
    asn1_addfield(val->nonce, 1, asn1_encode_integer);

    {
        unsigned int length;

        asn1_insert_implicit_bitstring(val->subjectPublicKey.length,val->subjectPublicKey.data,3);
        retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0,
                                val->subjectPublicKey.length + 1 + length,
                                &length);
        if (retval)
            return retval;
        sum += length;
    }

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_reply_key_pack(asn1buf *buf, const krb5_reply_key_pack *val, unsigned int *retlen)
{
    asn1_setup();

    asn1_addfield(&(val->asChecksum), 1, asn1_encode_checksum);
    asn1_addfield(&(val->replyKey), 0, asn1_encode_encryption_key);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_reply_key_pack_draft9(asn1buf *buf, const krb5_reply_key_pack_draft9 *val, unsigned int *retlen)
{
    asn1_setup();

    asn1_addfield(val->nonce, 1, asn1_encode_integer);
    asn1_addfield(&(val->replyKey), 0, asn1_encode_encryption_key);

    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_pa_pk_as_rep(asn1buf *buf, const krb5_pa_pk_as_rep *val, unsigned int *retlen)
{
    asn1_setup();

    switch (val->choice)
    {
    case choice_pa_pk_as_rep_dhInfo:
        asn1_addfield(&(val->u.dh_Info), choice_pa_pk_as_rep_dhInfo, asn1_encode_dh_rep_info);
        break;
    case choice_pa_pk_as_rep_encKeyPack:
        asn1_insert_implicit_octetstring(val->u.encKeyPack.length,val->u.encKeyPack.data,1);
        break;
    default:
        return ASN1_MISSING_FIELD;
    }

    asn1_cleanup();
}

asn1_error_code asn1_encode_pa_pk_as_rep_draft9(asn1buf *buf, const krb5_pa_pk_as_rep_draft9 *val, unsigned int *retlen)
{
    asn1_setup();

    switch (val->choice)
    {
    case choice_pa_pk_as_rep_draft9_dhSignedData:
        asn1_insert_implicit_octetstring(val->u.dhSignedData.length,val->u.dhSignedData.data,0);
        break;
    case choice_pa_pk_as_rep_encKeyPack:
        asn1_insert_implicit_octetstring(val->u.encKeyPack.length,val->u.encKeyPack.data,1);
        break;
    default:
        return ASN1_MISSING_FIELD;
    }

    asn1_cleanup();
}

asn1_error_code asn1_encode_td_trusted_certifiers(asn1buf *buf, const krb5_external_principal_identifier **val, unsigned int *retlen)
{
    asn1_setup();
    {
        unsigned int length;
        retval = asn1_encode_sequence_of_external_principal_identifier(buf, val, &length);
        if (retval)
            return retval;
        /* length set but ignored?  sum not updated?  */
    }
    asn1_cleanup();
}

#endif /* DISABLE_PKINIT */

asn1_error_code asn1_encode_sequence_of_typed_data(asn1buf *buf, const krb5_typed_data **val, unsigned int *retlen)
{
    asn1_setup();
    int i;

    if (val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

    for (i=0; val[i] != NULL; i++);
    for (i--; i>=0; i--) {
        unsigned int length;

        retval = asn1_encode_typed_data(buf,val[i],&length);
        if (retval) return retval;
        sum += length;
    }
    asn1_makeseq();

    asn1_cleanup();
}

asn1_error_code asn1_encode_typed_data(asn1buf *buf, const krb5_typed_data *val, unsigned int *retlen)
{
    asn1_setup();
    asn1_addlenfield(val->length, val->data, 1, asn1_encode_octetstring);
    asn1_addfield(val->type, 0, asn1_encode_integer);
    asn1_makeseq();
    asn1_cleanup();
}
