/*
 * src/lib/krb5/asn.1/asn1_k_encode.c
 * 
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
     if(rep->field_i == should_not_be_omitted)
       asn1_addfield(rep->field_i, i, asn1_type);

     /* for string fields (these encoders take an additional argument,
	the length of the string) */
     addlenfield(rep->field_length, rep->field, i-1, asn1_type);

     /* if you really have to do things yourself... */
     retval = asn1_encode_asn1_type(buf,rep->field,&length);
     if(retval) return retval;
     sum += length;
     retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, tag_number, length,
			     &length);
     if(retval) return retval;
     sum += length;

     ...
     asn1_addfield(rep->second_field, 1, asn1_type);
     asn1_addfield(rep->first_field, 0, asn1_type);
     asn1_makeseq();

     asn1_cleanup();
   }
#endif

/* setup() -- create and initialize bookkeeping variables
     retval: stores error codes returned from subroutines
     length: length of the most-recently produced encoding
     sum: cumulative length of the entire encoding */
#define asn1_setup()\
  asn1_error_code retval;\
  unsigned int length, sum=0
  
/* asn1_addfield -- add a field, or component, to the encoding */
#define asn1_addfield(value,tag,encoder)\
{ retval = encoder(buf,value,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length;\
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,tag,length,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* asn1_addlenfield -- add a field whose length must be separately specified */
#define asn1_addlenfield(len,value,tag,encoder)\
{ retval = encoder(buf,len,value,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length;\
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,tag,length,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* asn1_addfield_implicit -- add an implicitly tagged field, or component, to the encoding */
#define asn1_addfield_implicit(value,tag,encoder)\
{ retval = encoder(buf,value,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length;\
  retval = asn1_make_tag(buf,CONTEXT_SPECIFIC,PRIMITIVE,tag,length,&length); \
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* asn1_insert_implicit_octetstring -- add an octet string with implicit tagging */
#define asn1_insert_implicit_octetstring(len,value,tag)\
{ retval = asn1buf_insert_octetstring(buf,len,value);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += len;\
  retval = asn1_make_tag(buf,CONTEXT_SPECIFIC,PRIMITIVE,tag,len,&length); \
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* asn1_insert_implicit_bitstring -- add a bitstring with implicit tagging */
#define asn1_insert_implicit_bitstring(len,value,tag)\
{ retval = asn1buf_insert_octetstring(buf,len,value);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += len;\
  retval = asn1buf_insert_octet(buf, 0);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum++;\
  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,tag,len+1,&length); \
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length; }

/* form a sequence (by adding a sequence header to the current encoding) */
#define asn1_makeseq()\
  retval = asn1_make_sequence(buf,sum,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length

/* add an APPLICATION class tag to the current encoding */
#define asn1_apptag(num)\
  retval = asn1_make_etag(buf,APPLICATION,num,sum,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length

/* produce the final output and clean up the workspace */
#define asn1_cleanup()\
  *retlen = sum;\
  return 0

asn1_error_code asn1_encode_ui_4(asn1buf *buf, const krb5_ui_4 val, unsigned int *retlen)
{
  return asn1_encode_unsigned_integer(buf,val,retlen);
}


asn1_error_code asn1_encode_realm(asn1buf *buf, const krb5_principal val, unsigned int *retlen)
{
  if (val == NULL ||
      (val->realm.length && val->realm.data == NULL))
	  return ASN1_MISSING_FIELD;
  return asn1_encode_generalstring(buf,val->realm.length,val->realm.data,
				   retlen);
}

asn1_error_code asn1_encode_principal_name(asn1buf *buf, const krb5_principal val, unsigned int *retlen)
{
  asn1_setup();
  int n;

  if (val == NULL || val->data == NULL) return ASN1_MISSING_FIELD;

  for(n = (int) ((val->length)-1); n >= 0; n--){
    if (val->data[n].length &&
	val->data[n].data == NULL)
	    return ASN1_MISSING_FIELD;
    retval = asn1_encode_generalstring(buf,
				       (val->data)[n].length,
				       (val->data)[n].data,
				       &length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();
  retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,1,sum,&length);
  if(retval) return retval;
  sum += length;

  asn1_addfield(val->type,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kerberos_time(asn1buf *buf, const krb5_timestamp val, unsigned int *retlen)
{
  return asn1_encode_generaltime(buf,val,retlen);
}

asn1_error_code asn1_encode_host_address(asn1buf *buf, const krb5_address *val, unsigned int *retlen)
{
  asn1_setup();

  if (val == NULL || val->contents == NULL) return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  asn1_addfield(val->addrtype,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_host_addresses(asn1buf *buf, const krb5_address **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++); /* go to end of array */
  for(i--; i>=0; i--){
    retval = asn1_encode_host_address(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_encrypted_data(asn1buf *buf, const krb5_enc_data *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL ||
     (val->ciphertext.length && val->ciphertext.data == NULL))
	  return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->ciphertext.length,val->ciphertext.data,2,asn1_encode_charstring);
  /* krb5_kvno should be int */
  if(val->kvno)
    asn1_addfield((int) val->kvno,1,asn1_encode_integer);
  asn1_addfield(val->enctype,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb5_flags(asn1buf *buf, const krb5_flags val, unsigned int *retlen)
{
  asn1_setup();
  krb5_flags valcopy = val;
  int i;

  for(i=0; i<4; i++){
    retval = asn1buf_insert_octet(buf,(asn1_octet) (valcopy&0xFF));
    if(retval) return retval;
    valcopy >>= 8;
  }
  retval = asn1buf_insert_octet(buf,0);	/* 0 padding bits */
  if(retval) return retval;
  sum = 5;

  retval = asn1_make_tag(buf,UNIVERSAL,PRIMITIVE,ASN1_BITSTRING,sum,
			 &length);
  if(retval) return retval;
  sum += length;

  *retlen = sum;
  return 0;
}

asn1_error_code asn1_encode_ap_options(asn1buf *buf, const krb5_flags val, unsigned int *retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

asn1_error_code asn1_encode_ticket_flags(asn1buf *buf, const krb5_flags val, unsigned int *retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

asn1_error_code asn1_encode_kdc_options(asn1buf *buf, const krb5_flags val, unsigned int *retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

asn1_error_code asn1_encode_authorization_data(asn1buf *buf, const krb5_authdata **val, unsigned int *retlen)
{
  asn1_setup();
  int i;
  
  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;
  
  for(i=0; val[i] != NULL; i++); /* get to the end of the array */
  for(i--; i>=0; i--){
    retval = asn1_encode_krb5_authdata_elt(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb5_authdata_elt(asn1buf *buf, const krb5_authdata *val, unsigned int *retlen)
{
  asn1_setup();

  if (val == NULL ||
     (val->length && val->contents == NULL))
	  return ASN1_MISSING_FIELD;

  /* ad-data[1]		OCTET STRING */
  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  /* ad-type[0]		INTEGER */
  asn1_addfield(val->ad_type,0,asn1_encode_integer);
  /* SEQUENCE */
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_rep(int msg_type, asn1buf *buf, const krb5_kdc_rep *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(&(val->enc_part),6,asn1_encode_encrypted_data);
  asn1_addfield(val->ticket,5,asn1_encode_ticket);
  asn1_addfield(val->client,4,asn1_encode_principal_name);
  asn1_addfield(val->client,3,asn1_encode_realm);
  if(val->padata != NULL && val->padata[0] != NULL)
    asn1_addfield((const krb5_pa_data**)val->padata,2,asn1_encode_sequence_of_pa_data);
  if (msg_type != KRB5_AS_REP && msg_type != KRB5_TGS_REP)
	  return KRB5_BADMSGTYPE;
  asn1_addfield(msg_type,1,asn1_encode_integer);
  asn1_addfield(KVNO,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_enc_kdc_rep_part(asn1buf *buf, const krb5_enc_kdc_rep_part *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  /* caddr[11]		HostAddresses OPTIONAL */
  if(val->caddrs != NULL && val->caddrs[0] != NULL)
    asn1_addfield((const krb5_address**)(val->caddrs),11,asn1_encode_host_addresses);

  /* sname[10]		PrincipalName */
  asn1_addfield(val->server,10,asn1_encode_principal_name);

  /* srealm[9]		Realm */
  asn1_addfield(val->server,9,asn1_encode_realm);

  /* renew-till[8]	KerberosTime OPTIONAL */
  if(val->flags & TKT_FLG_RENEWABLE)
    asn1_addfield(val->times.renew_till,8,asn1_encode_kerberos_time);

  /* endtime[7]		KerberosTime */
  asn1_addfield(val->times.endtime,7,asn1_encode_kerberos_time);

  /* starttime[6]	KerberosTime OPTIONAL */
  if(val->times.starttime)
    asn1_addfield(val->times.starttime,6,asn1_encode_kerberos_time);

  /* authtime[5]	KerberosTime */
  asn1_addfield(val->times.authtime,5,asn1_encode_kerberos_time);

  /* flags[4]		TicketFlags */
  asn1_addfield(val->flags,4,asn1_encode_ticket_flags);

  /* key-expiration[3]	KerberosTime OPTIONAL */
  if(val->key_exp)
    asn1_addfield(val->key_exp,3,asn1_encode_kerberos_time);

  /* nonce[2]		INTEGER */
  asn1_addfield(val->nonce,2,asn1_encode_integer);

  /* last-req[1]	LastReq */
  asn1_addfield((const krb5_last_req_entry**)val->last_req,1,asn1_encode_last_req);

  /* key[0]		EncryptionKey */
  asn1_addfield(val->session,0,asn1_encode_encryption_key);

  /* EncKDCRepPart ::= SEQUENCE */
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_checksum(asn1buf *buf, const krb5_checksum ** val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL) return ASN1_MISSING_FIELD;

  for (i=0; val[i] != NULL; i++);
  for (i--; i>=0; i--){
    retval = asn1_encode_checksum(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_req_body(asn1buf *buf, const krb5_kdc_req *rep, unsigned int *retlen)
{
  asn1_setup();
  
  if(rep == NULL) return ASN1_MISSING_FIELD;

  /* additional-tickets[11]	SEQUENCE OF Ticket OPTIONAL */
  if(rep->second_ticket != NULL && rep->second_ticket[0] != NULL)
    asn1_addfield((const krb5_ticket**)rep->second_ticket,
		  11,asn1_encode_sequence_of_ticket);

  /* enc-authorization-data[10]	EncryptedData OPTIONAL, */
  /* 				-- Encrypted AuthorizationData encoding */
  if(rep->authorization_data.ciphertext.data != NULL)
    asn1_addfield(&(rep->authorization_data),10,asn1_encode_encrypted_data);

  /* addresses[9]		HostAddresses OPTIONAL, */
  if(rep->addresses != NULL && rep->addresses[0] != NULL)
    asn1_addfield((const krb5_address**)rep->addresses,9,asn1_encode_host_addresses);

  /* etype[8]			SEQUENCE OF INTEGER, -- EncryptionType, */
  /* 				-- in preference order */
  asn1_addlenfield(rep->nktypes,rep->ktype,8,asn1_encode_sequence_of_enctype);

  /* nonce[7]			INTEGER, */
  asn1_addfield(rep->nonce,7,asn1_encode_integer);

  /* rtime[6]			KerberosTime OPTIONAL, */
  if(rep->rtime)
    asn1_addfield(rep->rtime,6,asn1_encode_kerberos_time);

  /* till[5]			KerberosTime, */
  asn1_addfield(rep->till,5,asn1_encode_kerberos_time);

  /* from[4]			KerberosTime OPTIONAL, */
  if(rep->from)
  asn1_addfield(rep->from,4,asn1_encode_kerberos_time);

  /* sname[3]			PrincipalName OPTIONAL, */
  if(rep->server != NULL)
    asn1_addfield(rep->server,3,asn1_encode_principal_name);

  /* realm[2]			Realm, -- Server's realm */
  /* 				-- Also client's in AS-REQ */
  if(rep->kdc_options & KDC_OPT_ENC_TKT_IN_SKEY){
    if(rep->second_ticket != NULL && rep->second_ticket[0] != NULL){
      asn1_addfield(rep->second_ticket[0]->server,2,asn1_encode_realm)
    } else return ASN1_MISSING_FIELD;
  }else if(rep->server != NULL){
    asn1_addfield(rep->server,2,asn1_encode_realm);
  }else return ASN1_MISSING_FIELD;

  /* cname[1]			PrincipalName OPTIONAL, */
  /* 				-- Used only in AS-REQ */
  if(rep->client != NULL)
    asn1_addfield(rep->client,1,asn1_encode_principal_name);

  /* kdc-options[0]		KDCOptions, */
  asn1_addfield(rep->kdc_options,0,asn1_encode_kdc_options);

  /* KDC-REQ-BODY ::= SEQUENCE */
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_encryption_key(asn1buf *buf, const krb5_keyblock *val, unsigned int *retlen)
{
  asn1_setup();

  if (val == NULL ||
      (val->length && val->contents == NULL))
	  return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  asn1_addfield(val->enctype,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_checksum(asn1buf *buf, const krb5_checksum *val, unsigned int *retlen)
{
  asn1_setup();

  if (val == NULL ||
     (val->length && val->contents == NULL))
	  return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,1,asn1_encode_octetstring);
  asn1_addfield(val->checksum_type,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_transited_encoding(asn1buf *buf, const krb5_transited *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL ||
     (val->tr_contents.length != 0 && val->tr_contents.data == NULL))
    return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->tr_contents.length,val->tr_contents.data,
		   1,asn1_encode_charstring);
  asn1_addfield(val->tr_type,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_last_req(asn1buf *buf, const krb5_last_req_entry **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++); /* go to end of array */
  for(i--; i>=0; i--){
    retval = asn1_encode_last_req_entry(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_last_req_entry(asn1buf *buf, const krb5_last_req_entry *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(val->value,1,asn1_encode_kerberos_time);
  asn1_addfield(val->lr_type,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_pa_data(asn1buf *buf, const krb5_pa_data **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if (val == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_pa_data(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_pa_data(asn1buf *buf, const krb5_pa_data *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL || (val->length != 0 && val->contents == NULL))
     return ASN1_MISSING_FIELD;

  asn1_addlenfield(val->length,val->contents,2,asn1_encode_octetstring);
  asn1_addfield(val->pa_type,1,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_ticket(asn1buf *buf, const krb5_ticket **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_ticket(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_ticket(asn1buf *buf, const krb5_ticket *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(&(val->enc_part),3,asn1_encode_encrypted_data);
  asn1_addfield(val->server,2,asn1_encode_principal_name);
  asn1_addfield(val->server,1,asn1_encode_realm);
  asn1_addfield(KVNO,0,asn1_encode_integer);
  asn1_makeseq();
  asn1_apptag(1);

  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_enctype(asn1buf *buf, const int len, const krb5_enctype *val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL) return ASN1_MISSING_FIELD;

  for(i=len-1; i>=0; i--){
    retval = asn1_encode_integer(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_kdc_req(int msg_type, asn1buf *buf, const krb5_kdc_req *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  asn1_addfield(val,4,asn1_encode_kdc_req_body);
  if(val->padata != NULL && val->padata[0] != NULL)
    asn1_addfield((const krb5_pa_data**)val->padata,3,asn1_encode_sequence_of_pa_data);
  if (msg_type != KRB5_AS_REQ && msg_type != KRB5_TGS_REQ)
	  return KRB5_BADMSGTYPE;
  asn1_addfield(msg_type,2,asn1_encode_integer);
  asn1_addfield(KVNO,1,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb_safe_body(asn1buf *buf, const krb5_safe *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  if(val->r_address != NULL)
    asn1_addfield(val->r_address,5,asn1_encode_host_address);
  asn1_addfield(val->s_address,4,asn1_encode_host_address);
  if(val->seq_number)
    asn1_addfield(val->seq_number,3,asn1_encode_unsigned_integer);
  if(val->timestamp){
    asn1_addfield(val->usec,2,asn1_encode_integer);
    asn1_addfield(val->timestamp,1,asn1_encode_kerberos_time);
  }
  if (val->user_data.length && val->user_data.data == NULL)
	  return ASN1_MISSING_FIELD;
  asn1_addlenfield(val->user_data.length,val->user_data.data,0,asn1_encode_charstring)
;

  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_krb_cred_info(asn1buf *buf, const krb5_cred_info **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_krb_cred_info(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_krb_cred_info(asn1buf *buf, const krb5_cred_info *val, unsigned int *retlen)
{
  asn1_setup();

  if(val == NULL) return ASN1_MISSING_FIELD;

  if(val->caddrs != NULL && val->caddrs[0] != NULL)
    asn1_addfield((const krb5_address**)val->caddrs,10,asn1_encode_host_addresses);
  if(val->server != NULL){
    asn1_addfield(val->server,9,asn1_encode_principal_name);
    asn1_addfield(val->server,8,asn1_encode_realm);
  }
  if(val->times.renew_till)
    asn1_addfield(val->times.renew_till,7,asn1_encode_kerberos_time);
  if(val->times.endtime)
    asn1_addfield(val->times.endtime,6,asn1_encode_kerberos_time);
  if(val->times.starttime)
    asn1_addfield(val->times.starttime,5,asn1_encode_kerberos_time);
  if(val->times.authtime)
    asn1_addfield(val->times.authtime,4,asn1_encode_kerberos_time);
  if(val->flags)
    asn1_addfield(val->flags,3,asn1_encode_ticket_flags);
  if(val->client != NULL){
    asn1_addfield(val->client,2,asn1_encode_principal_name);
    asn1_addfield(val->client,1,asn1_encode_realm);
  }
  asn1_addfield(val->session,0,asn1_encode_encryption_key);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_etype_info_entry(asn1buf *buf, const krb5_etype_info_entry *val,
					     unsigned int *retlen, int etype_info2)
{
  asn1_setup();

  assert(val->s2kparams.data == NULL || etype_info2);
  if(val == NULL || (val->length > 0 && val->length != KRB5_ETYPE_NO_SALT &&
		     val->salt == NULL))
     return ASN1_MISSING_FIELD;
  if(val->s2kparams.data != NULL) {
      /* Solaris Kerberos */
      asn1_addlenfield(val->s2kparams.length, (const uchar_t *)val->s2kparams.data, 2,
		       asn1_encode_octetstring);
  }
  if (val->length >= 0 && val->length != KRB5_ETYPE_NO_SALT){
      if (etype_info2) {
          /* Solaris Kerberos */
	  asn1_addlenfield(val->length, (const char *)val->salt,1,
			   asn1_encode_generalstring)
      }
      else 	  asn1_addlenfield(val->length,val->salt,1,
				   asn1_encode_octetstring);
  }
asn1_addfield(val->etype,0,asn1_encode_integer);
  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_etype_info(asn1buf *buf, const krb5_etype_info_entry **val,
				       unsigned int *retlen, int etype_info2)
{
    asn1_setup();
    int i;
  
    if (val == NULL) return ASN1_MISSING_FIELD;
  
    for(i=0; val[i] != NULL; i++); /* get to the end of the array */
    for(i--; i>=0; i--){
	retval = asn1_encode_etype_info_entry(buf,val[i],&length, etype_info2);
	if(retval) return retval;
	sum += length;
    }
    asn1_makeseq();
    asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_passwdsequence(asn1buf *buf, const passwd_phrase_element **val, unsigned int *retlen)
{
  asn1_setup();
  int i;
  
  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;
  
  for(i=0; val[i] != NULL; i++); /* get to the end of the array */
  for(i--; i>=0; i--){
    retval = asn1_encode_passwdsequence(buf,val[i],&length);
    if(retval) return retval;
    sum += length;
  }
  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_passwdsequence(asn1buf *buf, const passwd_phrase_element *val, unsigned int *retlen)
{
  asn1_setup();
  asn1_addlenfield(val->phrase->length,val->phrase->data,1,asn1_encode_charstring);
  asn1_addlenfield(val->passwd->length,val->passwd->data,0,asn1_encode_charstring);
  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sam_flags(asn1buf *buf, const krb5_flags val, unsigned int *retlen)
{
  return asn1_encode_krb5_flags(buf,val,retlen);
}

#define add_optstring(val,n,fn) \
     if ((val).length > 0) {asn1_addlenfield((val).length,(val).data,n,fn);}

asn1_error_code asn1_encode_sam_challenge(asn1buf *buf, const krb5_sam_challenge *val, unsigned int *retlen)
{
  asn1_setup();
  /* possibly wrong */
  if (val->sam_cksum.length)
    asn1_addfield(&(val->sam_cksum),9,asn1_encode_checksum);

  if (val->sam_nonce)
    asn1_addfield(val->sam_nonce,8,asn1_encode_integer);

  add_optstring(val->sam_pk_for_sad,7,asn1_encode_charstring);
  add_optstring(val->sam_response_prompt,6,asn1_encode_charstring);
  add_optstring(val->sam_challenge,5,asn1_encode_charstring);
  add_optstring(val->sam_challenge_label,4,asn1_encode_charstring);
  add_optstring(val->sam_track_id,3,asn1_encode_charstring);
  add_optstring(val->sam_type_name,2,asn1_encode_charstring);

  asn1_addfield(val->sam_flags,1,asn1_encode_sam_flags);
  asn1_addfield(val->sam_type,0,asn1_encode_integer);

  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sam_challenge_2(asn1buf *buf, const krb5_sam_challenge_2 *val, unsigned int *retlen)
{
  asn1_setup();
  if ( (!val) || (!val->sam_cksum) || (!val->sam_cksum[0]))
      return ASN1_MISSING_FIELD;

  asn1_addfield((const krb5_checksum **) val->sam_cksum, 1, asn1_encode_sequence_of_checksum);
  retval = asn1buf_insert_octetstring(buf, val->sam_challenge_2_body.length,
				      (unsigned char *)val->sam_challenge_2_body.data);
  if(retval){
	  asn1buf_destroy(&buf);
	  return retval; 
  }
  sum += val->sam_challenge_2_body.length;
  retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0,
			  val->sam_challenge_2_body.length, &length);
  if(retval) {
	  asn1buf_destroy(&buf);
	  return retval;
  }
  sum += length;
  
  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sam_challenge_2_body(asn1buf *buf, const krb5_sam_challenge_2_body *val, unsigned int *retlen)
{
  asn1_setup();

  asn1_addfield(val->sam_etype, 9, asn1_encode_integer);
  asn1_addfield(val->sam_nonce,8,asn1_encode_integer);
  add_optstring(val->sam_pk_for_sad,7,asn1_encode_charstring);
  add_optstring(val->sam_response_prompt,6,asn1_encode_charstring);
  add_optstring(val->sam_challenge,5,asn1_encode_charstring);
  add_optstring(val->sam_challenge_label,4,asn1_encode_charstring);
  add_optstring(val->sam_track_id,3,asn1_encode_charstring);
  add_optstring(val->sam_type_name,2,asn1_encode_charstring);

  asn1_addfield(val->sam_flags,1,asn1_encode_sam_flags);
  asn1_addfield(val->sam_type,0,asn1_encode_integer);

  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sam_key(asn1buf *buf, const krb5_sam_key *val, unsigned int *retlen)
{
  asn1_setup();
  asn1_addfield(&(val->sam_key),0,asn1_encode_encryption_key);

  asn1_makeseq();

  asn1_cleanup();
}


asn1_error_code asn1_encode_enc_sam_response_enc(asn1buf *buf, const krb5_enc_sam_response_enc *val, unsigned int *retlen)
{
  asn1_setup();
  add_optstring(val->sam_sad,3,asn1_encode_charstring);
  asn1_addfield(val->sam_usec,2,asn1_encode_integer);
  asn1_addfield(val->sam_timestamp,1,asn1_encode_kerberos_time);
  asn1_addfield(val->sam_nonce,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_enc_sam_response_enc_2(asn1buf *buf, const krb5_enc_sam_response_enc_2 *val, unsigned int *retlen)
{
  asn1_setup();
  add_optstring(val->sam_sad,1,asn1_encode_charstring);
  asn1_addfield(val->sam_nonce,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sam_response(asn1buf *buf, const krb5_sam_response *val, unsigned int *retlen)
{
  asn1_setup();

  if (val->sam_patimestamp)
    asn1_addfield(val->sam_patimestamp,6,asn1_encode_kerberos_time);
  if (val->sam_nonce)
    asn1_addfield(val->sam_nonce,5,asn1_encode_integer);
  asn1_addfield(&(val->sam_enc_nonce_or_ts),4,asn1_encode_encrypted_data);
  if (val->sam_enc_key.ciphertext.length)
    asn1_addfield(&(val->sam_enc_key),3,asn1_encode_encrypted_data);
  add_optstring(val->sam_track_id,2,asn1_encode_charstring);
  asn1_addfield(val->sam_flags,1,asn1_encode_sam_flags);
  asn1_addfield(val->sam_type,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_sam_response_2(asn1buf *buf, const krb5_sam_response_2 *val, unsigned int *retlen)
{
  asn1_setup();

  asn1_addfield(val->sam_nonce,4,asn1_encode_integer);
  asn1_addfield(&(val->sam_enc_nonce_or_sad),3,asn1_encode_encrypted_data);
  add_optstring(val->sam_track_id,2,asn1_encode_charstring);
  asn1_addfield(val->sam_flags,1,asn1_encode_sam_flags);
  asn1_addfield(val->sam_type,0,asn1_encode_integer);

  asn1_makeseq();

  asn1_cleanup();
}

asn1_error_code asn1_encode_predicted_sam_response(asn1buf *buf, const krb5_predicted_sam_response *val, unsigned int *retlen)
{
  asn1_setup();

  add_optstring(val->msd,6,asn1_encode_charstring);
  asn1_addfield(val->client,5,asn1_encode_principal_name);
  asn1_addfield(val->client,4,asn1_encode_realm);
  asn1_addfield(val->susec,3,asn1_encode_integer);
  asn1_addfield(val->stime,2,asn1_encode_kerberos_time);
  asn1_addfield(val->sam_flags,1,asn1_encode_sam_flags);
  asn1_addfield(&(val->sam_key),0,asn1_encode_encryption_key);

  asn1_makeseq();

  asn1_cleanup();
}

/*
 * Do some ugliness to insert a raw pre-encoded KRB-SAFE-BODY.
 */
asn1_error_code asn1_encode_krb_saved_safe_body(asn1buf *buf, const krb5_data *body, unsigned int *retlen)
{
  asn1_error_code retval;

  retval = asn1buf_insert_octetstring(buf, body->length,
				      (krb5_octet *)body->data);
  if (retval){
    asn1buf_destroy(&buf);
    return retval; 
  }
  *retlen = body->length;
  return 0;
}

/*
 * PKINIT
 */

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
    if(retval) {
      asn1buf_destroy(&buf);
      return retval;
    }
    sum += val->parameters.length;
  }
  
  retval = asn1_encode_oid(buf, val->algorithm.length, 
			   val->algorithm.data,
			   &length);
  
  if(retval) {
    asn1buf_destroy(&buf);
    return retval;
  }
  sum += length;  

  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_subject_pk_info(asn1buf *buf, const krb5_subject_pk_info *val, unsigned int *retlen)
{
  asn1_setup();

  asn1_insert_implicit_bitstring(val->subjectPublicKey.length,val->subjectPublicKey.data,ASN1_BITSTRING);

  if (val->algorithm.parameters.length != 0) {
    retval = asn1buf_insert_octetstring(buf, val->algorithm.parameters.length, 
					val->algorithm.parameters.data);
    if(retval) {
      asn1buf_destroy(&buf);
      return retval;
    }
    sum += val->algorithm.parameters.length;
  }
  
  retval = asn1_encode_oid(buf, val->algorithm.algorithm.length, 
			   val->algorithm.algorithm.data,
			   &length);
  
  if(retval) {
    asn1buf_destroy(&buf);
    return retval;
  }
  sum += length;  
  
  retval = asn1_make_etag(buf, UNIVERSAL, ASN1_SEQUENCE, 
			  val->algorithm.parameters.length + length, 
			  &length);

  if(retval) {
    asn1buf_destroy(&buf);
    return retval;
  }
  sum += length;  

  asn1_makeseq();
  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_algorithm_identifier(asn1buf *buf, const krb5_algorithm_identifier **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_algorithm_identifier(buf,val[i],&length);
    if(retval) return retval;
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

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_external_principal_identifier(buf,val[i],&length);
    if(retval) return retval;
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

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_trusted_ca(buf,val[i],&length);
    if(retval) return retval;
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

  asn1_insert_implicit_bitstring(val->subjectPublicKey.length,val->subjectPublicKey.data,3);
  retval = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0, 
			  val->subjectPublicKey.length + 1 + length,
			  &length);
  if(retval) {
    asn1buf_destroy(&buf);
    return retval;
  }
  sum += length; 

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
  retval = asn1_encode_sequence_of_external_principal_identifier(buf, val, &length);
  if (retval) {
    asn1buf_destroy(&buf);
    return retval;
  }
  asn1_cleanup();
}

asn1_error_code asn1_encode_sequence_of_typed_data(asn1buf *buf, const krb5_typed_data **val, unsigned int *retlen)
{
  asn1_setup();
  int i;

  if(val == NULL || val[0] == NULL) return ASN1_MISSING_FIELD;

  for(i=0; val[i] != NULL; i++);
  for(i--; i>=0; i--){
    retval = asn1_encode_typed_data(buf,val[i],&length);
    if(retval) return retval;
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
