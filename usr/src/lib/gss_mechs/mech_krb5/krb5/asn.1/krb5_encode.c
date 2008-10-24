
/*
 * src/lib/krb5/asn.1/krb5_encode.c
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

#include "k5-int.h"
#include "asn1_k_encode.h"
#include "asn1_encode.h"
#include "krbasn1.h"
#include "asn1buf.h"
#include "asn1_make.h"

/**************** Macros (these save a lot of typing) ****************/

/**** krb5 macros ****/
#if 0
   How to write a krb5 encoder function using these macros:

   asn1_error_code encode_krb5_structure(const krb5_type *rep,
                                         krb5_data **code)
   {
     krb5_setup();

     krb5_addfield(rep->last_field, n, asn1_type);
     krb5_addfield(rep->next_to_last_field, n-1, asn1_type);
     ...

     /* for OPTIONAL fields */
     if(rep->field_i == should_not_be_omitted)
       krb5_addfield(rep->field_i, i, asn1_type);

     /* for string fields (these encoders take an additional argument,
	the length of the string) */
     addlenfield(rep->field_length, rep->field, i-1, asn1_type);

     /* if you really have to do things yourself... */
     retval = asn1_encode_asn1_type(buf,rep->field,&length);
     if(retval) return retval;
     sum += length;
     retval = asn1_make_etag(buf,
			    [UNIVERSAL/APPLICATION/CONTEXT_SPECIFIC/PRIVATE],
			    tag_number, length, &length);
     if(retval) return retval;
     sum += length;

     ...
     krb5_addfield(rep->second_field, 1, asn1_type);
     krb5_addfield(rep->first_field, 0, asn1_type);
     krb5_makeseq();
     krb5_apptag(tag_number);

     krb5_cleanup();
   }
#endif

/* setup() -- create and initialize bookkeeping variables
     retval: stores error codes returned from subroutines
     buf: the coding buffer
     length: length of the most-recently produced encoding
     sum: cumulative length of the entire encoding */
#define krb5_setup()\
  asn1_error_code retval;\
  asn1buf *buf=NULL;\
  unsigned int length, sum=0;\
\
  if(rep == NULL) return ASN1_MISSING_FIELD;\
\
  retval = asn1buf_create(&buf);\
  if(retval) return retval
  
/* krb5_addfield -- add a field, or component, to the encoding */
#define krb5_addfield(value,tag,encoder)\
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

/* krb5_addlenfield -- add a field whose length must be separately specified */
#define krb5_addlenfield(len,value,tag,encoder)\
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

/* form a sequence (by adding a sequence header to the current encoding) */
#define krb5_makeseq()\
  retval = asn1_make_sequence(buf,sum,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length

/* add an APPLICATION class tag to the current encoding */
#define krb5_apptag(num)\
  retval = asn1_make_etag(buf,APPLICATION,num,sum,&length);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  sum += length

/* produce the final output and clean up the workspace */
#define krb5_cleanup()\
  retval = asn12krb5_buf(buf,code);\
  if(retval){\
    asn1buf_destroy(&buf);\
    return retval; }\
  retval = asn1buf_destroy(&buf);\
  if(retval){\
    return retval; }\
\
  return 0

krb5_error_code encode_krb5_authenticator(const krb5_authenticator *rep, krb5_data **code)
{
  krb5_setup();

  /* authorization-data[8]	AuthorizationData OPTIONAL */
  if(rep->authorization_data != NULL &&
     rep->authorization_data[0] != NULL){
    retval = asn1_encode_authorization_data(buf, (const krb5_authdata **)
					    rep->authorization_data,
					    &length);
    if(retval){
      asn1buf_destroy(&buf);
      return retval; }
    sum += length;
    retval = asn1_make_etag(buf,CONTEXT_SPECIFIC,8,length,&length);
    if(retval){
      asn1buf_destroy(&buf);
      return retval; }
    sum += length;
  }

  /* seq-number[7]		INTEGER OPTIONAL */
  if(rep->seq_number != 0)
    krb5_addfield(rep->seq_number,7,asn1_encode_unsigned_integer);

  /* subkey[6]			EncryptionKey OPTIONAL */
  if(rep->subkey != NULL)
    krb5_addfield(rep->subkey,6,asn1_encode_encryption_key);

  /* ctime[5]			KerberosTime */
  krb5_addfield(rep->ctime,5,asn1_encode_kerberos_time);

  /* cusec[4]			INTEGER */
  krb5_addfield(rep->cusec,4,asn1_encode_integer);

  /* cksum[3]			Checksum OPTIONAL */
  if(rep->checksum != NULL)
    krb5_addfield(rep->checksum,3,asn1_encode_checksum);

  /* cname[2]			PrincipalName */
  krb5_addfield(rep->client,2,asn1_encode_principal_name);

  /* crealm[1]			Realm */
  krb5_addfield(rep->client,1,asn1_encode_realm);

  /* authenticator-vno[0]	INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* Authenticator ::= [APPLICATION 2] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(2);

  krb5_cleanup();
}

krb5_error_code encode_krb5_ticket(const krb5_ticket *rep, krb5_data **code)
{
  krb5_setup();

  /* enc-part[3]	EncryptedData */
  krb5_addfield(&(rep->enc_part),3,asn1_encode_encrypted_data);

  /* sname [2]		PrincipalName */
  krb5_addfield(rep->server,2,asn1_encode_principal_name);

  /* realm [1]		Realm */
  krb5_addfield(rep->server,1,asn1_encode_realm);

  /* tkt-vno [0]	INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* Ticket ::= [APPLICATION 1] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(1);

  krb5_cleanup();
}

krb5_error_code encode_krb5_encryption_key(const krb5_keyblock *rep, krb5_data **code)
{
  krb5_setup();

  /* keyvalue[1]	OCTET STRING */
  krb5_addlenfield(rep->length,rep->contents,1,asn1_encode_octetstring);

  /* enctype[0]		INTEGER */
  krb5_addfield(rep->enctype,0,asn1_encode_integer);

  /* EncryptionKey ::= SEQUENCE */
  krb5_makeseq();

  krb5_cleanup();
}

krb5_error_code encode_krb5_enc_tkt_part(const krb5_enc_tkt_part *rep, krb5_data **code)
{
  krb5_setup();

  /* authorization-data[10]	AuthorizationData OPTIONAL */
  if(rep->authorization_data != NULL &&
     rep->authorization_data[0] != NULL)
    krb5_addfield((const krb5_authdata**)rep->authorization_data,
		  10,asn1_encode_authorization_data);

  /* caddr[9]			HostAddresses OPTIONAL */
  if(rep->caddrs != NULL && rep->caddrs[0] != NULL)
    krb5_addfield((const krb5_address**)rep->caddrs,9,asn1_encode_host_addresses);

  /* renew-till[8]		KerberosTime OPTIONAL */
  if(rep->times.renew_till)
    krb5_addfield(rep->times.renew_till,8,asn1_encode_kerberos_time);

  /* endtime[7]			KerberosTime */
  krb5_addfield(rep->times.endtime,7,asn1_encode_kerberos_time);

  /* starttime[6]		KerberosTime OPTIONAL */
  if(rep->times.starttime)
    krb5_addfield(rep->times.starttime,6,asn1_encode_kerberos_time);

  /* authtime[5]		KerberosTime */
  krb5_addfield(rep->times.authtime,5,asn1_encode_kerberos_time);

  /* transited[4]		TransitedEncoding */
  krb5_addfield(&(rep->transited),4,asn1_encode_transited_encoding);

  /* cname[3]			PrincipalName */
  krb5_addfield(rep->client,3,asn1_encode_principal_name);

  /* crealm[2]			Realm */
  krb5_addfield(rep->client,2,asn1_encode_realm);

  /* key[1]			EncryptionKey */
  krb5_addfield(rep->session,1,asn1_encode_encryption_key);

  /* flags[0]			TicketFlags */
  krb5_addfield(rep->flags,0,asn1_encode_ticket_flags);

  /* EncTicketPart ::= [APPLICATION 3] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(3);

  krb5_cleanup();
}

krb5_error_code encode_krb5_enc_kdc_rep_part(const krb5_enc_kdc_rep_part *rep, krb5_data **code)
{
  asn1_error_code retval;
  asn1buf *buf=NULL;
  unsigned int length, sum=0;

  if(rep == NULL) return ASN1_MISSING_FIELD;

  retval = asn1buf_create(&buf);
  if(retval) return retval;

  retval = asn1_encode_enc_kdc_rep_part(buf,rep,&length);
  if(retval) return retval;
  sum += length;

#ifdef KRB5_ENCKRB5KDCREPPART_COMPAT
  krb5_apptag(26);
#else
  /* XXX WRONG!!! Should use 25 || 26, not the outer KDC_REP tags! */
  if (rep->msg_type == KRB5_AS_REP) { krb5_apptag(ASN1_KRB_AS_REP); }
  else if (rep->msg_type == KRB5_TGS_REP) { krb5_apptag(ASN1_KRB_TGS_REP); }
  else return KRB5_BADMSGTYPE;
#endif
  krb5_cleanup();
}

/* yes, the translation is identical to that used for KDC__REP */ 
krb5_error_code encode_krb5_as_rep(const krb5_kdc_rep *rep, krb5_data **code)
{
  krb5_setup();

  /* AS-REP ::= [APPLICATION 11] KDC-REP */
  retval = asn1_encode_kdc_rep(KRB5_AS_REP,buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_apptag(11);

  krb5_cleanup();
}

/* yes, the translation is identical to that used for KDC__REP */ 
krb5_error_code encode_krb5_tgs_rep(const krb5_kdc_rep *rep, krb5_data **code)
{
  krb5_setup();

  /* TGS-REP ::= [APPLICATION 13] KDC-REP */
  retval = asn1_encode_kdc_rep(KRB5_TGS_REP,buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_apptag(13);

  krb5_cleanup();
}

krb5_error_code encode_krb5_ap_req(const krb5_ap_req *rep, krb5_data **code)
{
  krb5_setup();

  /* authenticator[4]	EncryptedData */
  krb5_addfield(&(rep->authenticator),4,asn1_encode_encrypted_data);

  /* ticket[3]		Ticket */
  krb5_addfield(rep->ticket,3,asn1_encode_ticket);

  /* ap-options[2]	APOptions */
  krb5_addfield(rep->ap_options,2,asn1_encode_ap_options);

  /* msg-type[1]	INTEGER */
  krb5_addfield(ASN1_KRB_AP_REQ,1,asn1_encode_integer);

  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* AP-REQ ::=	[APPLICATION 14] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(14);

  krb5_cleanup();
}

krb5_error_code encode_krb5_ap_rep(const krb5_ap_rep *rep, krb5_data **code)
{
  krb5_setup();

  /* enc-part[2]	EncryptedData */
  krb5_addfield(&(rep->enc_part),2,asn1_encode_encrypted_data);
  
  /* msg-type[1]	INTEGER */
  krb5_addfield(ASN1_KRB_AP_REP,1,asn1_encode_integer);
  
  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);
  
  /* AP-REP ::=	[APPLICATION 15] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(15);
  
  krb5_cleanup();
}


krb5_error_code encode_krb5_ap_rep_enc_part(const krb5_ap_rep_enc_part *rep, krb5_data **code)
{
  krb5_setup();

  /* seq-number[3]	INTEGER OPTIONAL */
  if(rep->seq_number)
    krb5_addfield(rep->seq_number,3,asn1_encode_unsigned_integer);

  /* subkey[2]		EncryptionKey OPTIONAL */
  if(rep->subkey != NULL)
    krb5_addfield(rep->subkey,2,asn1_encode_encryption_key);

  /* cusec[1]		INTEGER */
  krb5_addfield(rep->cusec,1,asn1_encode_integer);

  /* ctime[0]		KerberosTime */
  krb5_addfield(rep->ctime,0,asn1_encode_kerberos_time);

  /* EncAPRepPart ::= [APPLICATION 27] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(27);

  krb5_cleanup();
}

krb5_error_code encode_krb5_as_req(const krb5_kdc_req *rep, krb5_data **code)
{
  krb5_setup();

  /* AS-REQ ::= [APPLICATION 10] KDC-REQ */
  retval = asn1_encode_kdc_req(KRB5_AS_REQ,buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_apptag(10);

  krb5_cleanup();
}

krb5_error_code encode_krb5_tgs_req(const krb5_kdc_req *rep, krb5_data **code)
{
  krb5_setup();

  /* TGS-REQ ::= [APPLICATION 12] KDC-REQ */
  retval = asn1_encode_kdc_req(KRB5_TGS_REQ,buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_apptag(12);

  krb5_cleanup();
}

krb5_error_code encode_krb5_kdc_req_body(const krb5_kdc_req *rep, krb5_data **code)
{
  krb5_setup();

  retval = asn1_encode_kdc_req_body(buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_cleanup();
}


krb5_error_code encode_krb5_safe(const krb5_safe *rep, krb5_data **code)
{
  krb5_setup();

  /* cksum[3]		Checksum */
  krb5_addfield(rep->checksum,3,asn1_encode_checksum);

  /* safe-body[2]	KRB-SAFE-BODY */
  krb5_addfield(rep,2,asn1_encode_krb_safe_body);

  /* msg-type[1]	INTEGER */
  krb5_addfield(ASN1_KRB_SAFE,1,asn1_encode_integer);

  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* KRB-SAFE ::= [APPLICATION 20] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(20);

  krb5_cleanup();
}

/*
 * encode_krb5_safe_with_body
 *
 * Like encode_krb5_safe(), except takes a saved KRB-SAFE-BODY
 * encoding to avoid problems with re-encoding.
 */
krb5_error_code encode_krb5_safe_with_body(
  const krb5_safe *rep,
  const krb5_data *body,
  krb5_data **code)
{
  krb5_setup();

  if (body == NULL) {
      asn1buf_destroy(&buf);
      return ASN1_MISSING_FIELD;
  }

  /* cksum[3]		Checksum */
  krb5_addfield(rep->checksum,3,asn1_encode_checksum);

  /* safe-body[2]	KRB-SAFE-BODY */
  krb5_addfield(body,2,asn1_encode_krb_saved_safe_body);

  /* msg-type[1]	INTEGER */
  krb5_addfield(ASN1_KRB_SAFE,1,asn1_encode_integer);

  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* KRB-SAFE ::= [APPLICATION 20] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(20);

  krb5_cleanup();
}

krb5_error_code encode_krb5_priv(const krb5_priv *rep, krb5_data **code)
{
  krb5_setup();

  /* enc-part[3]	EncryptedData */
  krb5_addfield(&(rep->enc_part),3,asn1_encode_encrypted_data);

  /* msg-type[1]	INTEGER */
  krb5_addfield(ASN1_KRB_PRIV,1,asn1_encode_integer);

  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* KRB-PRIV ::= [APPLICATION 21] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(21);

  krb5_cleanup();
}

krb5_error_code encode_krb5_enc_priv_part(const krb5_priv_enc_part *rep, krb5_data **code)
{
  krb5_setup();

  /* r-address[5]	HostAddress OPTIONAL -- recip's addr */
  if(rep->r_address)
    krb5_addfield(rep->r_address,5,asn1_encode_host_address);

  /* s-address[4]	HostAddress -- sender's addr */
  krb5_addfield(rep->s_address,4,asn1_encode_host_address);

  /* seq-number[3]	INTEGER OPTIONAL */
  if(rep->seq_number)
    krb5_addfield(rep->seq_number,3,asn1_encode_unsigned_integer);

  /* usec[2]		INTEGER OPTIONAL */
  if(rep->timestamp){
    krb5_addfield(rep->usec,2,asn1_encode_integer);
    /* timestamp[1]	KerberosTime OPTIONAL */
    krb5_addfield(rep->timestamp,1,asn1_encode_kerberos_time);
  }

  /* user-data[0]	OCTET STRING */
  krb5_addlenfield(rep->user_data.length,rep->user_data.data,0,asn1_encode_charstring);

  /* EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(28);

  krb5_cleanup();
}

krb5_error_code encode_krb5_cred(const krb5_cred *rep, krb5_data **code)
{
  krb5_setup();

  /* enc-part[3]	EncryptedData */
  krb5_addfield(&(rep->enc_part),3,asn1_encode_encrypted_data);

  /* tickets[2]		SEQUENCE OF Ticket */
  krb5_addfield((const krb5_ticket**)rep->tickets,2,asn1_encode_sequence_of_ticket);

  /* msg-type[1]	INTEGER, -- KRB_CRED */
  krb5_addfield(ASN1_KRB_CRED,1,asn1_encode_integer);

  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* KRB-CRED ::= [APPLICATION 22] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(22);

  krb5_cleanup();
}

krb5_error_code encode_krb5_enc_cred_part(const krb5_cred_enc_part *rep, krb5_data **code)
{
  krb5_setup();

  /* r-address[5]	HostAddress OPTIONAL */
  if(rep->r_address != NULL)
    krb5_addfield(rep->r_address,5,asn1_encode_host_address);

  /* s-address[4]	HostAddress OPTIONAL */
  if(rep->s_address != NULL)
    krb5_addfield(rep->s_address,4,asn1_encode_host_address);

  /* usec[3]		INTEGER OPTIONAL */
  if(rep->timestamp){
    krb5_addfield(rep->usec,3,asn1_encode_integer);
    /* timestamp[2]	KerberosTime OPTIONAL */
    krb5_addfield(rep->timestamp,2,asn1_encode_kerberos_time);
  }

  /* nonce[1]		INTEGER OPTIONAL */
  if(rep->nonce)
    krb5_addfield(rep->nonce,1,asn1_encode_integer);

  /* ticket-info[0]	SEQUENCE OF KrbCredInfo */
  krb5_addfield((const krb5_cred_info**)rep->ticket_info,
		0,asn1_encode_sequence_of_krb_cred_info);

  /* EncKrbCredPart ::= [APPLICATION 29] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(29);

  krb5_cleanup();
}

krb5_error_code encode_krb5_error(const krb5_error *rep, krb5_data **code)
{
  krb5_setup();

  /* e-data[12]		OCTET STRING OPTIONAL */
  if(rep->e_data.data != NULL && rep->e_data.length > 0)
    krb5_addlenfield(rep->e_data.length,rep->e_data.data,12,asn1_encode_charstring);

  /* e-text[11]		GeneralString OPTIONAL */
  if(rep->text.data != NULL && rep->text.length > 0)
    krb5_addlenfield(rep->text.length,rep->text.data,11,asn1_encode_generalstring);

  /* sname[10]		PrincipalName -- Correct name */
  krb5_addfield(rep->server,10,asn1_encode_principal_name);

  /* realm[9]		Realm -- Correct realm */
  krb5_addfield(rep->server,9,asn1_encode_realm);

  /* cname[8]		PrincipalName OPTIONAL */
  if(rep->client != NULL){
    krb5_addfield(rep->client,8,asn1_encode_principal_name);
    /* crealm[7]		Realm OPTIONAL */
    krb5_addfield(rep->client,7,asn1_encode_realm);
  }

  /* error-code[6]	INTEGER */
  krb5_addfield(rep->error,6,asn1_encode_ui_4);

  /* susec[5]		INTEGER */
  krb5_addfield(rep->susec,5,asn1_encode_integer);

  /* stime[4]		KerberosTime */
  krb5_addfield(rep->stime,4,asn1_encode_kerberos_time);

  /* cusec[3]		INTEGER OPTIONAL */
  if(rep->cusec)
    krb5_addfield(rep->cusec,3,asn1_encode_integer);

  /* ctime[2]		KerberosTime OPTIONAL */
  if(rep->ctime)
    krb5_addfield(rep->ctime,2,asn1_encode_kerberos_time);

  /* msg-type[1]	INTEGER */
  krb5_addfield(ASN1_KRB_ERROR,1,asn1_encode_integer);

  /* pvno[0]		INTEGER */
  krb5_addfield(KVNO,0,asn1_encode_integer);

  /* KRB-ERROR ::= [APPLICATION 30] SEQUENCE */
  krb5_makeseq();
  krb5_apptag(30);

  krb5_cleanup();
}

krb5_error_code encode_krb5_authdata(const krb5_authdata **rep, krb5_data **code)
{
  asn1_error_code retval;
  asn1buf *buf=NULL;
  unsigned int length;
  
  if(rep == NULL) return ASN1_MISSING_FIELD;

  retval = asn1buf_create(&buf);
  if(retval) return retval;

  retval = asn1_encode_authorization_data(buf,(const krb5_authdata**)rep,
					  &length);
  if(retval) return retval;

  krb5_cleanup();
}

krb5_error_code encode_krb5_authdata_elt(const krb5_authdata *rep, krb5_data **code)
{
  asn1_error_code retval;
  asn1buf *buf=NULL;
  unsigned int length;
  
  if(rep == NULL) return ASN1_MISSING_FIELD;

  retval = asn1buf_create(&buf);
  if(retval) return retval;

  retval = asn1_encode_krb5_authdata_elt(buf,rep, &length);
  if(retval) return retval;

  krb5_cleanup();
}

krb5_error_code encode_krb5_alt_method(const krb5_alt_method *rep, krb5_data **code)
{
  krb5_setup();

  /* method-data[1]		OctetString OPTIONAL */
  if(rep->data != NULL && rep->length > 0)
    krb5_addlenfield(rep->length,rep->data,1,asn1_encode_octetstring);

  /* method-type[0]		Integer */
  krb5_addfield(rep->method,0,asn1_encode_integer);

  krb5_makeseq();

  krb5_cleanup();
}

krb5_error_code encode_krb5_etype_info(const krb5_etype_info_entry **rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_etype_info(buf,rep,&length, 0);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_etype_info2(const krb5_etype_info_entry **rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_etype_info(buf,rep,&length, 1);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}
  

krb5_error_code encode_krb5_enc_data(const krb5_enc_data *rep, krb5_data **code)
{
  krb5_setup();

  retval = asn1_encode_encrypted_data(buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_cleanup();
}

krb5_error_code encode_krb5_pa_enc_ts(const krb5_pa_enc_ts *rep, krb5_data **code)
{
  krb5_setup();

  /* pausec[1]                    INTEGER OPTIONAL */
  if (rep->pausec)
	  krb5_addfield(rep->pausec,1,asn1_encode_integer);

  /* patimestamp[0]               KerberosTime, -- client's time */
  krb5_addfield(rep->patimestamp,0,asn1_encode_kerberos_time);

  krb5_makeseq();

  krb5_cleanup();
}

/* Sandia Additions */
krb5_error_code encode_krb5_pwd_sequence(const passwd_phrase_element *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_passwdsequence(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_pwd_data(const krb5_pwd_data *rep, krb5_data **code)
{
  krb5_setup();
  krb5_addfield((const passwd_phrase_element**)rep->element,1,asn1_encode_sequence_of_passwdsequence);
  krb5_addfield(rep->sequence_count,0,asn1_encode_integer);
  krb5_makeseq();
  krb5_cleanup();
}

krb5_error_code encode_krb5_padata_sequence(const krb5_pa_data **rep, krb5_data **code)
{
  krb5_setup();

  retval = asn1_encode_sequence_of_pa_data(buf,rep,&length);
  if(retval) return retval;
  sum += length;

  krb5_cleanup();
}

/* sam preauth additions */
krb5_error_code encode_krb5_sam_challenge(const krb5_sam_challenge *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sam_challenge(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_sam_challenge_2(const krb5_sam_challenge_2 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sam_challenge_2(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_sam_challenge_2_body(const krb5_sam_challenge_2_body *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sam_challenge_2_body(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_sam_key(const krb5_sam_key *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sam_key(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_enc_sam_response_enc(const krb5_enc_sam_response_enc *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_enc_sam_response_enc(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_enc_sam_response_enc_2(const krb5_enc_sam_response_enc_2 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_enc_sam_response_enc_2(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_sam_response(const krb5_sam_response *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sam_response(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_sam_response_2(const krb5_sam_response_2 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sam_response_2(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_predicted_sam_response(const krb5_predicted_sam_response *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_predicted_sam_response(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_setpw_req(const krb5_principal target,
				      char *password, krb5_data **code)
{
  /* Macros really want us to have a variable called rep which we do not need*/
  const char *rep = "dummy string";

  krb5_setup();

  krb5_addfield(target,2,asn1_encode_realm);
  krb5_addfield(target,1,asn1_encode_principal_name);
  /* Solaris Kerberos */
  krb5_addlenfield(strlen(password), (const unsigned char *)password,0,asn1_encode_octetstring);
  krb5_makeseq();


  krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_req(const krb5_pa_pk_as_req *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_pa_pk_as_req(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_req_draft9(const krb5_pa_pk_as_req_draft9 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_pa_pk_as_req_draft9(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_rep(const krb5_pa_pk_as_rep *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_pa_pk_as_rep(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_pa_pk_as_rep_draft9(const krb5_pa_pk_as_rep_draft9 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_pa_pk_as_rep_draft9(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_auth_pack(const krb5_auth_pack *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_auth_pack(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_auth_pack_draft9(const krb5_auth_pack_draft9 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_auth_pack_draft9(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_kdc_dh_key_info(const krb5_kdc_dh_key_info *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_kdc_dh_key_info(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_reply_key_pack(const krb5_reply_key_pack *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_reply_key_pack(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_reply_key_pack_draft9(const krb5_reply_key_pack_draft9 *rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_reply_key_pack_draft9(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_td_trusted_certifiers(const krb5_external_principal_identifier **rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_td_trusted_certifiers(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_typed_data(const krb5_typed_data **rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sequence_of_typed_data(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}

krb5_error_code encode_krb5_td_dh_parameters(const krb5_algorithm_identifier **rep, krb5_data **code)
{
  krb5_setup();
  retval = asn1_encode_sequence_of_algorithm_identifier(buf,rep,&length);
  if(retval) return retval;
  sum += length;
  krb5_cleanup();
}
