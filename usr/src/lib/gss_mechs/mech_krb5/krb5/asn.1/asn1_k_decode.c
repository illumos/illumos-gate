/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * src/lib/krb5/asn.1/asn1_k_decode.c
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

#include "asn1_k_decode.h"
#include "asn1_decode.h"
#include "asn1_get.h"
#include "asn1_misc.h"

/* Declare useful decoder variables. */
#define setup()					\
  asn1_error_code retval;			\
  asn1_class asn1class;				\
  asn1_construction construction;		\
  asn1_tagnum tagnum;				\
  unsigned int length, taglen

#define unused_var(x) if (0) { x = 0; x = x - x; }

/* This is used for prefetch of next tag in sequence. */
#define next_tag()								\
{ taginfo t2;									\
  retval = asn1_get_tag_2(&subbuf, &t2);					\
  if (retval) return retval;							\
  /* Copy out to match previous functionality, until better integrated.  */	\
  asn1class = t2.asn1class;							\
  construction = t2.construction;						\
  tagnum = t2.tagnum;								\
  taglen = t2.length;								\
  indef = t2.indef;								\
}

/* Force check for EOC tag. */
#define get_eoc()									\
    {											\
	taginfo t3;									\
	retval = asn1_get_tag_2(&subbuf, &t3);						\
	if(retval) return retval;							\
        if (t3.asn1class != UNIVERSAL || t3.tagnum || t3.indef)				\
	    return ASN1_MISSING_EOC;							\
        /* Copy out to match previous functionality, until better integrated.  */	\
	asn1class = t3.asn1class;							\
	construction = t3.construction;							\
	tagnum = t3.tagnum;								\
	taglen = t3.length;								\
	indef = t3.indef;								\
    }

#define alloc_field(var, type)			\
  var = (type*)calloc(1, sizeof(type));		\
  if ((var) == NULL) return ENOMEM

/* Fetch an expected APPLICATION class tag and verify. */
#define apptag(tagexpect)								\
  {											\
      taginfo t1;									\
      retval = asn1_get_tag_2(buf, &t1);						\
      if (retval) return retval;						   	\
      if (t1.asn1class != APPLICATION || t1.construction != CONSTRUCTED ||	   	\
	  t1.tagnum != (tagexpect)) return ASN1_BAD_ID;					\
      /* Copy out to match previous functionality, until better integrated.  */		\
      asn1class = t1.asn1class;								\
      construction = t1.construction;							\
      tagnum = t1.tagnum;								\
      applen = t1.length;								\
  }

/**** normal fields ****/

/*
 * get_field_body
 *
 * Get bare field.  This also prefetches the next tag.  The call to
 * get_eoc() assumes that any values fetched by this macro are
 * enclosed in a context-specific tag.
 */
#define get_field_body(var, decoder)		\
  retval = decoder(&subbuf, &(var));		\
  if (retval) return retval;			\
  if (!taglen && indef) { get_eoc(); }		\
  next_tag()

/*
 * get_field
 *
 * Get field having an expected context specific tag.  This assumes
 * that context-specific tags are monotonically increasing in its
 * verification of tag numbers.
 */
#define get_field(var, tagexpect, decoder)				\
  if (tagnum > (tagexpect)) return ASN1_MISSING_FIELD;			\
  if (tagnum < (tagexpect)) return ASN1_MISPLACED_FIELD;		\
  if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)	\
      && (tagnum || taglen || asn1class != UNIVERSAL))			\
    return ASN1_BAD_ID;							\
  get_field_body(var,decoder)

/*
 * opt_field
 *
 * Get an optional field with an expected context specific tag.
 * Assumes that OPTVAL will have the default value, thus failing to
 * distinguish between absent optional values and present optional
 * values that happen to have the value of OPTVAL.
 */
#define opt_field(var, tagexpect, decoder, optvalue)			\
  if (asn1buf_remains(&subbuf, seqindef)) {				\
    if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)	\
	&& (tagnum || taglen || asn1class != UNIVERSAL))		\
      return ASN1_BAD_ID;						\
    if (tagnum == (tagexpect)) {					\
      get_field_body(var, decoder);					\
    } else var = optvalue;						\
  }
  
/**** fields w/ length ****/

/* similar to get_field_body */
#define get_lenfield_body(len, var, decoder)	\
  retval = decoder(&subbuf, &(len), &(var));	\
  if (retval) return retval;			\
  if (!taglen && indef) { get_eoc(); }		\
  next_tag()

/* similar to get_field_body */
#define get_lenfield(len, var, tagexpect, decoder)			\
  if (tagnum > (tagexpect)) return ASN1_MISSING_FIELD;			\
  if (tagnum < (tagexpect)) return ASN1_MISPLACED_FIELD;		\
  if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)	\
      && (tagnum || taglen || asn1class != UNIVERSAL))			\
    return ASN1_BAD_ID;							\
  get_lenfield_body(len, var, decoder)

/* similar to opt_field */
#define opt_lenfield(len, var, tagexpect, decoder)	\
  if (tagnum == (tagexpect)) {				\
    get_lenfield_body(len, var, decoder);		\
  } else { len = 0; var = 0; }

/*
 * begin_structure
 *
 * Declares some variables for decoding SEQUENCE types.  This is meant
 * to be called in an inner block that ends with a call to
 * end_structure().
 */
#define begin_structure()					\
  asn1buf subbuf;						\
  int seqindef;							\
  int indef;							\
  retval = asn1_get_sequence(buf, &length, &seqindef);		\
  if (retval) return retval;					\
  retval = asn1buf_imbed(&subbuf, buf, length, seqindef);	\
  if (retval) return retval;					\
  next_tag()

/* skip trailing garbage */
#define end_structure()						\
  retval = asn1buf_sync(buf, &subbuf, asn1class, tagnum,	\
			length, indef, seqindef);		\
  if (retval) return retval

/*
 * sequence_of
 *
 * Declares some variables for decoding SEQUENCE OF types.  This is
 * meant to be called in an inner block that ends with a call to
 * end_sequence_of().
 */
#define sequence_of(buf)			\
  unsigned int length, taglen;			\
  asn1_class asn1class;				\
  asn1_construction construction;		\
  asn1_tagnum tagnum;				\
  int indef;					\
  sequence_of_common(buf)

/*
 * sequence_of_no_tagvars
 *
 * This is meant for use inside decoder functions that have an outer
 * sequence structure and thus declares variables of different names
 * than does sequence_of() to avoid shadowing.
 */
#define sequence_of_no_tagvars(buf)		\
  asn1_class eseqclass;				\
  asn1_construction eseqconstr;			\
  asn1_tagnum eseqnum;				\
  unsigned int eseqlen;				\
  int eseqindef;				\
  sequence_of_common(buf)

/*
 * sequence_of_common
 *
 * Fetches the outer SEQUENCE OF length info into {length,seqofindef}
 * and imbeds an inner buffer seqbuf.  Unlike begin_structure(), it
 * does not prefetch the next tag.
 */
#define sequence_of_common(buf)					\
  int size = 0;							\
  asn1buf seqbuf;						\
  int seqofindef;						\
  retval = asn1_get_sequence(buf, &length, &seqofindef);	\
  if (retval) return retval;					\
  retval = asn1buf_imbed(&seqbuf, buf, length, seqofindef);	\
  if (retval) return retval

/*
 * end_sequence_of
 *
 * Attempts to fetch an EOC tag, if any, and to sync over trailing
 * garbage, if any.
 */
#define end_sequence_of(buf)							\
  {										\
      taginfo t4;								\
      retval = asn1_get_tag_2(&seqbuf, &t4);					\
      if (retval) return retval;						\
      /* Copy out to match previous functionality, until better integrated.  */	\
      asn1class = t4.asn1class;							\
      construction = t4.construction;						\
      tagnum = t4.tagnum;							\
      taglen = t4.length;							\
      indef = t4.indef;								\
  }										\
  retval = asn1buf_sync(buf, &seqbuf, asn1class, tagnum,			\
			length, indef, seqofindef);				\
  if (retval) return retval;

/*
 * end_sequence_of_no_tagvars
 *
 * Like end_sequence_of(), but uses the different (non-shadowing)
 * variable names.
 */
#define end_sequence_of_no_tagvars(buf)						\
  {										\
      taginfo t5;								\
      retval = asn1_get_tag_2(&seqbuf, &t5);					\
      if (retval) return retval;						\
      /* Copy out to match previous functionality, until better integrated.  */	\
      eseqclass = t5.asn1class;							\
      eseqconstr = t5.construction;						\
      eseqnum = t5.tagnum;							\
      eseqlen = t5.length;							\
      eseqindef = t5.indef;							\
  }										\
  retval = asn1buf_sync(buf, &seqbuf, eseqclass, eseqnum,			\
			eseqlen, eseqindef, seqofindef);			\
  if (retval) return retval;

#define cleanup()				\
  return 0

/* scalars */
asn1_error_code asn1_decode_kerberos_time(asn1buf *buf, krb5_timestamp *val)
{
    time_t	t;
    asn1_error_code retval;
    
    retval =  asn1_decode_generaltime(buf,&t);
    if (retval)
	return retval;

    *val = t;
    return 0;
}

#define integer_convert(fname,ktype)\
asn1_error_code fname(asn1buf * buf, ktype * val)\
{\
  asn1_error_code retval;\
  long n;\
  retval = asn1_decode_integer(buf,&n);\
  if(retval) return retval;\
  *val = (ktype)n;\
  return 0;\
}
#define unsigned_integer_convert(fname,ktype)\
asn1_error_code fname(asn1buf * buf, ktype * val)\
{\
  asn1_error_code retval;\
  unsigned long n;\
  retval = asn1_decode_unsigned_integer(buf,&n);\
  if(retval) return retval;\
  *val = (ktype)n;\
  return 0;\
}
integer_convert(asn1_decode_int,int)
integer_convert(asn1_decode_int32,krb5_int32)
integer_convert(asn1_decode_kvno,krb5_kvno)
integer_convert(asn1_decode_enctype,krb5_enctype)
integer_convert(asn1_decode_cksumtype,krb5_cksumtype)
integer_convert(asn1_decode_octet,krb5_octet)
integer_convert(asn1_decode_addrtype,krb5_addrtype)
integer_convert(asn1_decode_authdatatype,krb5_authdatatype)
unsigned_integer_convert(asn1_decode_ui_2,krb5_ui_2)
unsigned_integer_convert(asn1_decode_ui_4,krb5_ui_4)

asn1_error_code asn1_decode_seqnum(asn1buf *buf, krb5_ui_4 *val)
{
  asn1_error_code retval;
  unsigned long n;

  retval = asn1_decode_maybe_unsigned(buf, &n);
  if (retval) return retval;
  *val = (krb5_ui_4)n & 0xffffffff;
  return 0;
}

asn1_error_code asn1_decode_msgtype(asn1buf *buf, krb5_msgtype *val)
{
  asn1_error_code retval;
  unsigned long n;
  
  retval = asn1_decode_unsigned_integer(buf,&n);
  if(retval) return retval;
  
  *val = (krb5_msgtype) n;
  return 0;
}


/* structures */
asn1_error_code asn1_decode_realm(asn1buf *buf, krb5_principal *val)
{
  return asn1_decode_generalstring(buf,
				   &((*val)->realm.length),
				   &((*val)->realm.data));
}

asn1_error_code asn1_decode_principal_name(asn1buf *buf, krb5_principal *val)
{
  setup();
  { begin_structure();
    get_field((*val)->type,0,asn1_decode_int32);
  
    { sequence_of_no_tagvars(&subbuf);
      while(asn1buf_remains(&seqbuf,seqofindef) > 0){
	size++;
	if ((*val)->data == NULL)
	  (*val)->data = (krb5_data*)malloc(size*sizeof(krb5_data));
	else
	  (*val)->data = (krb5_data*)realloc((*val)->data,
					     size*sizeof(krb5_data));
	if((*val)->data == NULL) return ENOMEM;
	retval = asn1_decode_generalstring(&seqbuf,
					   &((*val)->data[size-1].length),
			   &((*val)->data[size-1].data));
	if(retval) return retval;
      }
      (*val)->length = size;
      end_sequence_of_no_tagvars(&subbuf);
    }
    if (indef) {
	get_eoc();
    }
    next_tag();
    end_structure();
    (*val)->magic = KV5M_PRINCIPAL;
  }
  cleanup();
}

asn1_error_code asn1_decode_checksum(asn1buf *buf, krb5_checksum *val)
{
  setup();
  { begin_structure();
    get_field(val->checksum_type,0,asn1_decode_cksumtype);
    get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
    end_structure();
    val->magic = KV5M_CHECKSUM;
  }
  cleanup();
}

asn1_error_code asn1_decode_encryption_key(asn1buf *buf, krb5_keyblock *val)
{
  setup();
  { begin_structure();
    get_field(val->enctype,0,asn1_decode_enctype);
    get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
    end_structure();
    val->magic = KV5M_KEYBLOCK;
  }
  cleanup();
}

asn1_error_code asn1_decode_encrypted_data(asn1buf *buf, krb5_enc_data *val)
{
  setup();
  { begin_structure();
    get_field(val->enctype,0,asn1_decode_enctype);
    opt_field(val->kvno,1,asn1_decode_kvno,0);
    get_lenfield(val->ciphertext.length,val->ciphertext.data,2,asn1_decode_charstring);
    end_structure();
    val->magic = KV5M_ENC_DATA;
  }
  cleanup();
}

asn1_error_code asn1_decode_krb5_flags(asn1buf *buf, krb5_flags *val)
{
  asn1_error_code retval;
  asn1_octet unused, o;
  taginfo t;
  int i;
  krb5_flags f=0;
  unsigned int length;

  retval = asn1_get_tag_2(buf, &t);
  if (retval) return retval;
  if (t.asn1class != UNIVERSAL || t.construction != PRIMITIVE ||
      t.tagnum != ASN1_BITSTRING)
      return ASN1_BAD_ID;
  length = t.length;

  retval = asn1buf_remove_octet(buf,&unused); /* # of padding bits */
  if(retval) return retval;

  /* Number of unused bits must be between 0 and 7. */
  if (unused > 7) return ASN1_BAD_FORMAT;
  length--;

  for(i = 0; i < length; i++) {
    retval = asn1buf_remove_octet(buf,&o);
    if(retval) return retval;
    /* ignore bits past number 31 */
    if (i < 4)
      f = (f<<8) | ((krb5_flags)o&0xFF);
  }
  if (length <= 4) {
    /* Mask out unused bits, but only if necessary. */
    f &= ~(krb5_flags)0 << unused;
  }
  /* left-justify */
  if (length < 4)
    f <<= (4 - length) * 8;
  *val = f;
  return 0;
}

asn1_error_code asn1_decode_ticket_flags(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

asn1_error_code asn1_decode_ap_options(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

asn1_error_code asn1_decode_kdc_options(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

asn1_error_code asn1_decode_transited_encoding(asn1buf *buf, krb5_transited *val)
{
  setup();
  { begin_structure();
    get_field(val->tr_type,0,asn1_decode_octet);
    get_lenfield(val->tr_contents.length,val->tr_contents.data,1,asn1_decode_charstring);
    end_structure();
    val->magic = KV5M_TRANSITED;
  }
  cleanup();
}

asn1_error_code asn1_decode_enc_kdc_rep_part(asn1buf *buf, krb5_enc_kdc_rep_part *val)
{
  setup();
  { begin_structure();
    alloc_field(val->session,krb5_keyblock);
    get_field(*(val->session),0,asn1_decode_encryption_key);
    get_field(val->last_req,1,asn1_decode_last_req);
    get_field(val->nonce,2,asn1_decode_int32);
    opt_field(val->key_exp,3,asn1_decode_kerberos_time,0);
    get_field(val->flags,4,asn1_decode_ticket_flags);
    get_field(val->times.authtime,5,asn1_decode_kerberos_time);
    /* Set to authtime if missing */
    opt_field(val->times.starttime,6,asn1_decode_kerberos_time,val->times.authtime);
    get_field(val->times.endtime,7,asn1_decode_kerberos_time);
    opt_field(val->times.renew_till,8,asn1_decode_kerberos_time,0);
    alloc_field(val->server,krb5_principal_data);
    get_field(val->server,9,asn1_decode_realm);
    get_field(val->server,10,asn1_decode_principal_name);
    opt_field(val->caddrs,11,asn1_decode_host_addresses,NULL);
    end_structure();
    val->magic = KV5M_ENC_KDC_REP_PART;
  }
  cleanup();
}

asn1_error_code asn1_decode_ticket(asn1buf *buf, krb5_ticket *val)
{
  setup();
  unsigned int applen;
  apptag(1);
  { begin_structure();
    { krb5_kvno vno;
      get_field(vno,0,asn1_decode_kvno);
      if(vno != KVNO) return KRB5KDC_ERR_BAD_PVNO; }
    alloc_field(val->server,krb5_principal_data);
    get_field(val->server,1,asn1_decode_realm);
    get_field(val->server,2,asn1_decode_principal_name);
    get_field(val->enc_part,3,asn1_decode_encrypted_data);
    end_structure();
    val->magic = KV5M_TICKET;
  }
  if (!applen) {
      taginfo t;
      retval = asn1_get_tag_2(buf, &t);
      if (retval) return retval;
      }
  cleanup();
}

asn1_error_code asn1_decode_kdc_req(asn1buf *buf, krb5_kdc_req *val)
{
  setup();
  { begin_structure();
    { krb5_kvno kvno;
      get_field(kvno,1,asn1_decode_kvno);
      if(kvno != KVNO) return KRB5KDC_ERR_BAD_PVNO; }
    get_field(val->msg_type,2,asn1_decode_msgtype);
    opt_field(val->padata,3,asn1_decode_sequence_of_pa_data,NULL);
    get_field(*val,4,asn1_decode_kdc_req_body);
    end_structure();
    val->magic = KV5M_KDC_REQ;
  }
  cleanup();
}

asn1_error_code asn1_decode_kdc_req_body(asn1buf *buf, krb5_kdc_req *val)
{
  setup();
  { 
    krb5_principal psave;
    begin_structure();
    get_field(val->kdc_options,0,asn1_decode_kdc_options);
    if(tagnum == 1){ alloc_field(val->client,krb5_principal_data); }
    opt_field(val->client,1,asn1_decode_principal_name,NULL);
    alloc_field(val->server,krb5_principal_data);
    get_field(val->server,2,asn1_decode_realm);
    if(val->client != NULL){
      retval = asn1_krb5_realm_copy(val->client,val->server);
      if(retval) return retval; }

    /* If opt_field server is missing, memory reference to server is
       lost and results in memory leak */
    psave = val->server;
    opt_field(val->server,3,asn1_decode_principal_name,NULL);
    if(val->server == NULL){
      if(psave->realm.data) {
	free(psave->realm.data);
	psave->realm.data = NULL;
	psave->realm.length=0;
      }
      free(psave);
    }
    opt_field(val->from,4,asn1_decode_kerberos_time,0);
    get_field(val->till,5,asn1_decode_kerberos_time);
    opt_field(val->rtime,6,asn1_decode_kerberos_time,0);
    get_field(val->nonce,7,asn1_decode_int32);
    get_lenfield(val->nktypes,val->ktype,8,asn1_decode_sequence_of_enctype);
    opt_field(val->addresses,9,asn1_decode_host_addresses,0);
    if(tagnum == 10){
      get_field(val->authorization_data,10,asn1_decode_encrypted_data); }
    else{
      val->authorization_data.magic = KV5M_ENC_DATA;
      val->authorization_data.enctype = 0;
      val->authorization_data.kvno = 0;
      val->authorization_data.ciphertext.data = NULL;
      val->authorization_data.ciphertext.length = 0;
    }
    opt_field(val->second_ticket,11,asn1_decode_sequence_of_ticket,NULL);
    end_structure();
    val->magic = KV5M_KDC_REQ;
  }
  cleanup();
}

asn1_error_code asn1_decode_krb_safe_body(asn1buf *buf, krb5_safe *val)
{
  setup();
  { begin_structure();
    get_lenfield(val->user_data.length,val->user_data.data,0,asn1_decode_charstring);
    opt_field(val->timestamp,1,asn1_decode_kerberos_time,0);
    opt_field(val->usec,2,asn1_decode_int32,0);
    opt_field(val->seq_number,3,asn1_decode_seqnum,0);
    alloc_field(val->s_address,krb5_address);
    get_field(*(val->s_address),4,asn1_decode_host_address);
    if(tagnum == 5){
      alloc_field(val->r_address,krb5_address);
      get_field(*(val->r_address),5,asn1_decode_host_address);
    } else val->r_address = NULL;
    end_structure();
    val->magic = KV5M_SAFE;
  }
  cleanup();
}

asn1_error_code asn1_decode_host_address(asn1buf *buf, krb5_address *val)
{
  setup();
  { begin_structure();
    get_field(val->addrtype,0,asn1_decode_addrtype);
    get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
    end_structure();
    val->magic = KV5M_ADDRESS;
  }
  cleanup();
}

asn1_error_code asn1_decode_kdc_rep(asn1buf *buf, krb5_kdc_rep *val)
{
  setup();
  { begin_structure();
    { krb5_kvno pvno;
      get_field(pvno,0,asn1_decode_kvno);
      if(pvno != KVNO) return KRB5KDC_ERR_BAD_PVNO; }
    get_field(val->msg_type,1,asn1_decode_msgtype);
    opt_field(val->padata,2,asn1_decode_sequence_of_pa_data,NULL);
    alloc_field(val->client,krb5_principal_data);
    get_field(val->client,3,asn1_decode_realm);
    get_field(val->client,4,asn1_decode_principal_name);
    alloc_field(val->ticket,krb5_ticket);
    get_field(*(val->ticket),5,asn1_decode_ticket);
    get_field(val->enc_part,6,asn1_decode_encrypted_data);
    end_structure();
    val->magic = KV5M_KDC_REP;
  }
  cleanup();
}


/* arrays */
#define get_element(element,decoder)\
retval = decoder(&seqbuf,element);\
if(retval) return retval
     
#define array_append(array,size,element,type)\
size++;\
if (*(array) == NULL)\
     *(array) = (type**)malloc((size+1)*sizeof(type*));\
else\
  *(array) = (type**)realloc(*(array),\
			     (size+1)*sizeof(type*));\
if(*(array) == NULL) return ENOMEM;\
(*(array))[(size)-1] = elt
     
#define decode_array_body(type,decoder)\
  asn1_error_code retval;\
  type *elt;\
\
  { sequence_of(buf);\
    while(asn1buf_remains(&seqbuf,seqofindef) > 0){\
      alloc_field(elt,type);\
      get_element(elt,decoder);\
      array_append(val,size,elt,type);\
    }\
    if (*val == NULL)\
	*val = (type **)malloc(sizeof(type*));\
    (*val)[size] = NULL;\
    end_sequence_of(buf);\
  }\
  cleanup()


asn1_error_code asn1_decode_authorization_data(asn1buf *buf, krb5_authdata ***val)
{
  decode_array_body(krb5_authdata,asn1_decode_authdata_elt);
}

asn1_error_code asn1_decode_authdata_elt(asn1buf *buf, krb5_authdata *val)
{
  setup();
  { begin_structure();
    get_field(val->ad_type,0,asn1_decode_authdatatype);
    get_lenfield(val->length,val->contents,1,asn1_decode_octetstring);
    end_structure();
    val->magic = KV5M_AUTHDATA;
  }
  cleanup();
}

asn1_error_code asn1_decode_host_addresses(asn1buf *buf, krb5_address ***val)
{
  decode_array_body(krb5_address,asn1_decode_host_address);
}

asn1_error_code asn1_decode_sequence_of_ticket(asn1buf *buf, krb5_ticket ***val)
{
  decode_array_body(krb5_ticket,asn1_decode_ticket);
}

asn1_error_code asn1_decode_sequence_of_krb_cred_info(asn1buf *buf, krb5_cred_info ***val)
{
  decode_array_body(krb5_cred_info,asn1_decode_krb_cred_info);
}

asn1_error_code asn1_decode_krb_cred_info(asn1buf *buf, krb5_cred_info *val)
{
  setup();
  { begin_structure();
    alloc_field(val->session,krb5_keyblock);
    get_field(*(val->session),0,asn1_decode_encryption_key);
    if(tagnum == 1){
      alloc_field(val->client,krb5_principal_data);
      opt_field(val->client,1,asn1_decode_realm,NULL);
      opt_field(val->client,2,asn1_decode_principal_name,NULL); }
    opt_field(val->flags,3,asn1_decode_ticket_flags,0);
    opt_field(val->times.authtime,4,asn1_decode_kerberos_time,0);
    opt_field(val->times.starttime,5,asn1_decode_kerberos_time,0);
    opt_field(val->times.endtime,6,asn1_decode_kerberos_time,0);
    opt_field(val->times.renew_till,7,asn1_decode_kerberos_time,0);
    if(tagnum == 8){
      alloc_field(val->server,krb5_principal_data);
      opt_field(val->server,8,asn1_decode_realm,NULL);
      opt_field(val->server,9,asn1_decode_principal_name,NULL); }
    opt_field(val->caddrs,10,asn1_decode_host_addresses,NULL);
    end_structure();
    val->magic = KV5M_CRED_INFO;
  }
  cleanup();
}

asn1_error_code asn1_decode_sequence_of_pa_data(asn1buf *buf, krb5_pa_data ***val)
{
  decode_array_body(krb5_pa_data,asn1_decode_pa_data);
}

asn1_error_code asn1_decode_pa_data(asn1buf *buf, krb5_pa_data *val)
{
  setup();
  { begin_structure();
    get_field(val->pa_type,1,asn1_decode_int32);
    get_lenfield(val->length,val->contents,2,asn1_decode_octetstring);
    end_structure();
    val->magic = KV5M_PA_DATA;
  }
  cleanup();
}

asn1_error_code asn1_decode_last_req(asn1buf *buf, krb5_last_req_entry ***val)
{
  decode_array_body(krb5_last_req_entry,asn1_decode_last_req_entry);
}

asn1_error_code asn1_decode_last_req_entry(asn1buf *buf, krb5_last_req_entry *val)
{
  setup();
  { begin_structure();
    get_field(val->lr_type,0,asn1_decode_int32);
    get_field(val->value,1,asn1_decode_kerberos_time);
    end_structure();
    val->magic = KV5M_LAST_REQ_ENTRY;
#ifdef KRB5_GENEROUS_LR_TYPE
    /* If we are only a single byte wide and negative - fill in the
       other bits */
    if((val->lr_type & 0xffffff80U) == 0x80) val->lr_type |= 0xffffff00U;
#endif
  }
  cleanup();
}

asn1_error_code asn1_decode_sequence_of_enctype(asn1buf *buf, int *num, krb5_enctype **val)
{
  asn1_error_code retval;
  { sequence_of(buf);
    while(asn1buf_remains(&seqbuf,seqofindef) > 0){
      size++;
      if (*val == NULL)
        *val = (krb5_enctype*)malloc(size*sizeof(krb5_enctype));
      else
        *val = (krb5_enctype*)realloc(*val,size*sizeof(krb5_enctype));
      if(*val == NULL) return ENOMEM;
      retval = asn1_decode_enctype(&seqbuf,&((*val)[size-1]));
      if(retval) return retval;
    }
    *num = size;
    end_sequence_of(buf);
  }
  cleanup();
}

asn1_error_code asn1_decode_sequence_of_checksum(asn1buf *buf, krb5_checksum ***val)
{
  decode_array_body(krb5_checksum, asn1_decode_checksum);
}

static asn1_error_code asn1_decode_etype_info2_entry(asn1buf *buf, krb5_etype_info_entry *val )
{
  /*
   * Solaris Kerberos:
   * Use a temporary char* (tmpp) in place of val->salt when calling
   * get_lenfield(). val->salt cannot be cast to a char* as casting will not
   * produce an lvalue. Use the new value pointed to by tmpp as the value for
   * val->salt.
   */
  char *tmpp;
  setup();
  { begin_structure();
    get_field(val->etype,0,asn1_decode_enctype);
    if (tagnum == 1) {
      get_lenfield(val->length,tmpp,1,asn1_decode_generalstring);
      val->salt = (krb5_octet*)tmpp;	/* SUNW14resync hack */
    } else {
	    val->length = KRB5_ETYPE_NO_SALT;
	    val->salt = 0;
    }
    if ( tagnum ==2) {
      krb5_octet *params ;
      get_lenfield( val->s2kparams.length, params,
		      2, asn1_decode_octetstring);
      val->s2kparams.data = ( char *) params;
    } else {
	val->s2kparams.data = NULL;
	val->s2kparams.length = 0;
    }
    end_structure();
    val->magic = KV5M_ETYPE_INFO_ENTRY;
  }
  cleanup();
}

static asn1_error_code asn1_decode_etype_info2_entry_1_3(asn1buf *buf, krb5_etype_info_entry *val )
{
  setup();
  { begin_structure();
    get_field(val->etype,0,asn1_decode_enctype);
    if (tagnum == 1) {
	    get_lenfield(val->length,val->salt,1,asn1_decode_octetstring);
    } else {
	    val->length = KRB5_ETYPE_NO_SALT;
	    val->salt = 0;
    }
    if ( tagnum ==2) {
      krb5_octet *params ;
      get_lenfield( val->s2kparams.length, params,
		      2, asn1_decode_octetstring);
      val->s2kparams.data = ( char *) params;
    } else {
	val->s2kparams.data = NULL;
	val->s2kparams.length = 0;
    }
    end_structure();
    val->magic = KV5M_ETYPE_INFO_ENTRY;
  }
  cleanup();
}


static asn1_error_code asn1_decode_etype_info_entry(asn1buf *buf, krb5_etype_info_entry *val )
{
  setup();
  { begin_structure();
    get_field(val->etype,0,asn1_decode_enctype);
    if (tagnum == 1) {
	    get_lenfield(val->length,val->salt,1,asn1_decode_octetstring);
    } else {
	    val->length = KRB5_ETYPE_NO_SALT;
	    val->salt = 0;
    }
    val->s2kparams.data = NULL;
    val->s2kparams.length = 0;
    
    end_structure();
    val->magic = KV5M_ETYPE_INFO_ENTRY;
  }
  cleanup();
}

asn1_error_code asn1_decode_etype_info(asn1buf *buf, krb5_etype_info_entry ***val )
{
  decode_array_body(krb5_etype_info_entry,asn1_decode_etype_info_entry);
}

asn1_error_code asn1_decode_etype_info2(asn1buf *buf, krb5_etype_info_entry ***val ,
					krb5_boolean v1_3_behavior)
{
    if (v1_3_behavior) {
	decode_array_body(krb5_etype_info_entry,
			  asn1_decode_etype_info2_entry_1_3);
    } else {
	decode_array_body(krb5_etype_info_entry,
			  asn1_decode_etype_info2_entry);
    }
}

asn1_error_code asn1_decode_passwdsequence(asn1buf *buf, passwd_phrase_element *val)
{
  setup();
  { begin_structure();
    alloc_field(val->passwd,krb5_data);
    get_lenfield(val->passwd->length,val->passwd->data,
		 0,asn1_decode_charstring);
    val->passwd->magic = KV5M_DATA;
    alloc_field(val->phrase,krb5_data);
    get_lenfield(val->phrase->length,val->phrase->data,
		 1,asn1_decode_charstring);
    val->phrase->magic = KV5M_DATA;
    end_structure();
    val->magic = KV5M_PASSWD_PHRASE_ELEMENT;
  }
  cleanup();
}

asn1_error_code asn1_decode_sequence_of_passwdsequence(asn1buf *buf, passwd_phrase_element ***val)
{
  decode_array_body(passwd_phrase_element,asn1_decode_passwdsequence);
}

asn1_error_code asn1_decode_sam_flags(asn1buf *buf, krb5_flags *val)
{ return asn1_decode_krb5_flags(buf,val); }

#define opt_string(val,n,fn) opt_lenfield((val).length,(val).data,n,fn)
#define opt_cksum(var,tagexpect,decoder)\
if(tagnum == (tagexpect)){\
  get_field_body(var,decoder); }\
else var.length = 0

asn1_error_code asn1_decode_sam_challenge(asn1buf *buf, krb5_sam_challenge *val)
{
  setup();
  { begin_structure();
    get_field(val->sam_type,0,asn1_decode_int32);
    get_field(val->sam_flags,1,asn1_decode_sam_flags);
    opt_string(val->sam_type_name,2,asn1_decode_charstring);
    opt_string(val->sam_track_id,3,asn1_decode_charstring);
    opt_string(val->sam_challenge_label,4,asn1_decode_charstring);
    opt_string(val->sam_challenge,5,asn1_decode_charstring);
    opt_string(val->sam_response_prompt,6,asn1_decode_charstring);
    opt_string(val->sam_pk_for_sad,7,asn1_decode_charstring);
    opt_field(val->sam_nonce,8,asn1_decode_int32,0);
    opt_cksum(val->sam_cksum,9,asn1_decode_checksum);
    end_structure();
    val->magic = KV5M_SAM_CHALLENGE;
  }
  cleanup();
}
asn1_error_code asn1_decode_sam_challenge_2(asn1buf *buf, krb5_sam_challenge_2 *val)
{
  setup();
  { char *save, *end;
    size_t alloclen;
    begin_structure();
    if (tagnum != 0) return ASN1_MISSING_FIELD;
    if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED) 
      return ASN1_BAD_ID;
    save = subbuf.next;
    { sequence_of_no_tagvars(&subbuf);
      unused_var(size);
      end_sequence_of_no_tagvars(&subbuf);
    }
    end = subbuf.next;
    alloclen = end - save;
    if ((val->sam_challenge_2_body.data = (char *) malloc(alloclen)) == NULL)
      return ENOMEM;
    val->sam_challenge_2_body.length = alloclen;
    memcpy(val->sam_challenge_2_body.data, save, alloclen);
    next_tag();
    get_field(val->sam_cksum, 1, asn1_decode_sequence_of_checksum);
    end_structure();
  }
  cleanup();
}
asn1_error_code asn1_decode_sam_challenge_2_body(asn1buf *buf, krb5_sam_challenge_2_body *val)
{
  setup();
  { begin_structure();
    get_field(val->sam_type,0,asn1_decode_int32);
    get_field(val->sam_flags,1,asn1_decode_sam_flags);
    opt_string(val->sam_type_name,2,asn1_decode_charstring);
    opt_string(val->sam_track_id,3,asn1_decode_charstring);
    opt_string(val->sam_challenge_label,4,asn1_decode_charstring);
    opt_string(val->sam_challenge,5,asn1_decode_charstring);
    opt_string(val->sam_response_prompt,6,asn1_decode_charstring);
    opt_string(val->sam_pk_for_sad,7,asn1_decode_charstring);
    get_field(val->sam_nonce,8,asn1_decode_int32);
    get_field(val->sam_etype, 9, asn1_decode_int32);
    end_structure();
    val->magic = KV5M_SAM_CHALLENGE;
  }
  cleanup();
}
asn1_error_code asn1_decode_enc_sam_key(asn1buf *buf, krb5_sam_key *val)
{
  setup();
  { begin_structure();
    /* alloc_field(val->sam_key,krb5_keyblock); */
    get_field(val->sam_key,0,asn1_decode_encryption_key);
    end_structure();
    val->magic = KV5M_SAM_KEY;
  }
  cleanup();
}

asn1_error_code asn1_decode_enc_sam_response_enc(asn1buf *buf, krb5_enc_sam_response_enc *val)
{
  setup();
  { begin_structure();
    opt_field(val->sam_nonce,0,asn1_decode_int32,0);
    opt_field(val->sam_timestamp,1,asn1_decode_kerberos_time,0);
    opt_field(val->sam_usec,2,asn1_decode_int32,0);
    opt_string(val->sam_sad,3,asn1_decode_charstring);
    end_structure();
    val->magic = KV5M_ENC_SAM_RESPONSE_ENC;
  }
  cleanup();
}

asn1_error_code asn1_decode_enc_sam_response_enc_2(asn1buf *buf, krb5_enc_sam_response_enc_2 *val)
{
  setup();
  { begin_structure();
    get_field(val->sam_nonce,0,asn1_decode_int32);
    opt_string(val->sam_sad,1,asn1_decode_charstring);
    end_structure();
    val->magic = KV5M_ENC_SAM_RESPONSE_ENC_2;
  }
  cleanup();
}

#define opt_encfield(fld,tag,fn) \
    if(tagnum == tag){ \
      get_field(fld,tag,fn); } \
    else{\
      fld.magic = 0;\
      fld.enctype = 0;\
      fld.kvno = 0;\
      fld.ciphertext.data = NULL;\
      fld.ciphertext.length = 0;\
    }

asn1_error_code asn1_decode_sam_response(asn1buf *buf, krb5_sam_response *val)
{
  setup();
  { begin_structure();
    get_field(val->sam_type,0,asn1_decode_int32);
    get_field(val->sam_flags,1,asn1_decode_sam_flags);
    opt_string(val->sam_track_id,2,asn1_decode_charstring);
    opt_encfield(val->sam_enc_key,3,asn1_decode_encrypted_data);
    get_field(val->sam_enc_nonce_or_ts,4,asn1_decode_encrypted_data);
    opt_field(val->sam_nonce,5,asn1_decode_int32,0);
    opt_field(val->sam_patimestamp,6,asn1_decode_kerberos_time,0);
    end_structure();
    val->magic = KV5M_SAM_RESPONSE;
  }
  cleanup();
}

asn1_error_code asn1_decode_sam_response_2(asn1buf *buf, krb5_sam_response_2 *val)
{
  setup();
  { begin_structure();
    get_field(val->sam_type,0,asn1_decode_int32);
    get_field(val->sam_flags,1,asn1_decode_sam_flags);
    opt_string(val->sam_track_id,2,asn1_decode_charstring);
    get_field(val->sam_enc_nonce_or_sad,3,asn1_decode_encrypted_data);
    get_field(val->sam_nonce,4,asn1_decode_int32);
    end_structure();
    val->magic = KV5M_SAM_RESPONSE;
  }
  cleanup();
}


asn1_error_code asn1_decode_predicted_sam_response(asn1buf *buf, krb5_predicted_sam_response *val)
{
  setup();
  { begin_structure();
    get_field(val->sam_key,0,asn1_decode_encryption_key);
    get_field(val->sam_flags,1,asn1_decode_sam_flags);
    get_field(val->stime,2,asn1_decode_kerberos_time);
    get_field(val->susec,3,asn1_decode_int32);
    alloc_field(val->client,krb5_principal_data);
    get_field(val->client,4,asn1_decode_realm);
    get_field(val->client,5,asn1_decode_principal_name);
    opt_string(val->msd,6,asn1_decode_charstring); /* should be octet */
    end_structure();
    val->magic = KV5M_PREDICTED_SAM_RESPONSE;
  }
  cleanup();
}
