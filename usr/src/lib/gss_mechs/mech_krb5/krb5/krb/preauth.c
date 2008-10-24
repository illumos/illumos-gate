/*
 * Copyright 1995 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
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

/*
 * This file contains routines for establishing, verifying, and any other
 * necessary functions, for utilizing the pre-authentication field of the 
 * kerberos kdc request, with various hardware/software verification devices.
 */

#include "k5-int.h"
#include <stdio.h>
#include <time.h>

static krb5_error_code obtain_enc_ts_padata
	(krb5_context,
	 krb5_pa_data *,
	 krb5_etype_info,
	 krb5_keyblock *,
	 krb5_error_code ( * )(krb5_context,
			       const krb5_enctype,
			       krb5_data *,
			       krb5_const_pointer,
			       krb5_keyblock **),
	 krb5_const_pointer,
	 krb5_creds *,
	 krb5_kdc_req *,
	 krb5_pa_data **);

static krb5_error_code process_pw_salt
	(krb5_context,
	 krb5_pa_data *,
	 krb5_kdc_req *,
	 krb5_kdc_rep *,
	 krb5_error_code ( * )(krb5_context,
			       const krb5_enctype,
			       krb5_data *,
			       krb5_const_pointer,
			       krb5_keyblock **),
	 krb5_const_pointer,
	 krb5_error_code ( * )(krb5_context,
			       const krb5_keyblock *,
			       krb5_const_pointer,
			       krb5_kdc_rep * ),
	 krb5_keyblock **,
	 krb5_creds *,
	 krb5_int32 *,
	 krb5_int32 *);

static krb5_error_code obtain_sam_padata
	(krb5_context,
	 krb5_pa_data *,
	 krb5_etype_info,
	 krb5_keyblock *, 
	 krb5_error_code ( * )(krb5_context,
			       const krb5_enctype,
			       krb5_data *,
			       krb5_const_pointer,
			       krb5_keyblock **),
	 krb5_const_pointer,
	 krb5_creds *,
	 krb5_kdc_req *,
	 krb5_pa_data **);

static const krb5_preauth_ops preauth_systems[] = {
    {
	KV5M_PREAUTH_OPS,
	KRB5_PADATA_ENC_TIMESTAMP,
        0,
        obtain_enc_ts_padata,
        0,
    },
    {
	KV5M_PREAUTH_OPS,
	KRB5_PADATA_PW_SALT,
        0,
        0,
        process_pw_salt,
    },
    {
	KV5M_PREAUTH_OPS,
	KRB5_PADATA_AFS3_SALT,
        0,
        0,
        process_pw_salt,
    },
    {
	KV5M_PREAUTH_OPS,
	KRB5_PADATA_SAM_CHALLENGE,
        0,
        obtain_sam_padata,
        0,
    },
    { KV5M_PREAUTH_OPS, -1 }
};

static krb5_error_code find_pa_system
    (krb5_preauthtype type, const krb5_preauth_ops **Preauth_proc);

/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) (krb5_context,
					 const krb5_enctype,
					 krb5_data *,
					 krb5_const_pointer,
					 krb5_keyblock **);

typedef krb5_error_code (*git_decrypt_proc) (krb5_context,
					     const krb5_keyblock *,
					     krb5_const_pointer,
					     krb5_kdc_rep *);

krb5_error_code krb5_obtain_padata(krb5_context context, krb5_pa_data **preauth_to_use, git_key_proc key_proc, krb5_const_pointer key_seed, krb5_creds *creds, krb5_kdc_req *request)
{
    krb5_error_code		retval;
    krb5_etype_info	    	etype_info = 0;
    krb5_pa_data **		pa;
    krb5_pa_data **		send_pa_list;
    krb5_pa_data **		send_pa;
    const krb5_preauth_ops	*ops;
    krb5_keyblock *		def_enc_key = 0;
    krb5_enctype 		enctype;
    krb5_data 			salt;
    krb5_data			scratch;
    int				size;
    int				f_salt = 0;

    if (preauth_to_use == NULL)
	return 0;

    for (pa = preauth_to_use, size=0; *pa; pa++, size++) {
	if ((*pa)->pa_type == KRB5_PADATA_ETYPE_INFO) {
	    /* XXX use the first one.  Is there another way to disambiguate? */
	    if (etype_info)
		continue;

	    scratch.length = (*pa)->length;
	    scratch.data = (char *) (*pa)->contents;
	    retval = decode_krb5_etype_info(&scratch, &etype_info);
	    if (retval)
		return retval;
	    if (etype_info[0] == NULL) {
		krb5_free_etype_info(context, etype_info);
		etype_info = NULL;
	    }
	}
    }

    if ((send_pa_list = malloc((size+1) * sizeof(krb5_pa_data *))) == NULL)
	return ENOMEM;

    send_pa = send_pa_list;
    *send_pa = 0;

    enctype = request->ktype[0];
    salt.data = 0;
    salt.length = SALT_TYPE_NO_LENGTH;
    if (etype_info) {
	enctype = etype_info[0]->etype;
	salt.data = (char *) etype_info[0]->salt;
	if(etype_info[0]->length == KRB5_ETYPE_NO_SALT) 
	  salt.length = SALT_TYPE_NO_LENGTH; /* XXX */
	else 
	  salt.length = etype_info[0]->length;
    }
    if (salt.length == SALT_TYPE_NO_LENGTH) {
        /*
	 * This will set the salt length 
	 */
	if ((retval = krb5_principal2salt(context, request->client, &salt)))
	    return(retval);
	f_salt = 1;
    }
    
    if ((retval = (*key_proc)(context, enctype, &salt, key_seed,
			      &def_enc_key)))
	goto cleanup;
    

    for (pa = preauth_to_use; *pa; pa++) {
	if (find_pa_system((*pa)->pa_type, &ops))
	    continue;

	if (ops->obtain == 0)
	    continue;
	
	retval = ((ops)->obtain)(context, *pa, etype_info, def_enc_key,
				 key_proc, key_seed, creds,
				 request, send_pa);
	if (retval)
	    goto cleanup;

	if (*send_pa)
	    send_pa++;
	*send_pa = 0;
    }

    retval = 0;

    if (send_pa_list[0]) {
	request->padata = send_pa_list;
	send_pa_list = 0;
    }

cleanup:
    if (etype_info)
	krb5_free_etype_info(context, etype_info);
    if (f_salt)
	krb5_xfree(salt.data);
    if (send_pa_list)
	krb5_free_pa_data(context, send_pa_list);
    if (def_enc_key)
	krb5_free_keyblock(context, def_enc_key);
    return retval;
    
}

krb5_error_code
krb5_process_padata(krb5_context context, krb5_kdc_req *request, krb5_kdc_rep *as_reply, git_key_proc key_proc, krb5_const_pointer keyseed, git_decrypt_proc decrypt_proc, krb5_keyblock **decrypt_key, krb5_creds *creds, krb5_int32 *do_more)
{
    krb5_error_code		retval = 0;
    const krb5_preauth_ops * 	ops;
    krb5_pa_data **		pa;
    krb5_int32			done = 0;
    
    *do_more = 0;		/* By default, we don't need to repeat... */
    if (as_reply->padata == 0)
	return 0;

    for (pa = as_reply->padata; *pa; pa++) {
	if (find_pa_system((*pa)->pa_type, &ops))
	    continue;

	if (ops->process == 0)
	    continue;
	
	retval = ((ops)->process)(context, *pa, request, as_reply,
				  key_proc, keyseed, decrypt_proc,
				  decrypt_key, creds, do_more, &done);
	if (retval)
	    goto cleanup;
	if (done)
	    break;
    }

cleanup:
    return retval;
}

/*
 * This routine is the "obtain" function for the ENC_TIMESTAMP
 * preauthentication type.  It take the current time and encrypts it
 * in the user's key.
 */
static krb5_error_code
obtain_enc_ts_padata(krb5_context context, krb5_pa_data *in_padata, krb5_etype_info etype_info, krb5_keyblock *def_enc_key, git_key_proc key_proc, krb5_const_pointer key_seed, krb5_creds *creds, krb5_kdc_req *request, krb5_pa_data **out_padata)
{
    krb5_pa_enc_ts		pa_enc;
    krb5_error_code		retval;
    krb5_data *			scratch;
    krb5_enc_data 		enc_data;
    krb5_pa_data *		pa;

    retval = krb5_us_timeofday(context, &pa_enc.patimestamp, &pa_enc.pausec);
    if (retval)
	return retval;

    if ((retval = encode_krb5_pa_enc_ts(&pa_enc, &scratch)) != 0)
	return retval;

    enc_data.ciphertext.data = 0;

    if ((retval = krb5_encrypt_helper(context, def_enc_key,
				      KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS,
				      scratch, &enc_data)))
	goto cleanup;

    krb5_free_data(context, scratch);
    scratch = 0;
    
    if ((retval = encode_krb5_enc_data(&enc_data, &scratch)) != 0)
	goto cleanup;

    if ((pa = malloc(sizeof(krb5_pa_data))) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_ENC_TIMESTAMP;
    pa->length = scratch->length;
    pa->contents = (krb5_octet *) scratch->data;

    *out_padata = pa;

    krb5_xfree(scratch);
    scratch = 0;

    retval = 0;
    
cleanup:
    if (scratch)
	krb5_free_data(context, scratch);
    if (enc_data.ciphertext.data)
	krb5_xfree(enc_data.ciphertext.data);
    return retval;
}

static krb5_error_code
process_pw_salt(krb5_context context, krb5_pa_data *padata, krb5_kdc_req *request, krb5_kdc_rep *as_reply, git_key_proc key_proc, krb5_const_pointer keyseed, git_decrypt_proc decrypt_proc, krb5_keyblock **decrypt_key, krb5_creds *creds, krb5_int32 *do_more, krb5_int32 *done)
{
    krb5_error_code	retval;
    krb5_data		salt;
    
    if (*decrypt_key != 0)
	return 0;

    salt.data = (char *) padata->contents;
    salt.length = 
      (padata->pa_type == KRB5_PADATA_AFS3_SALT)?(SALT_TYPE_AFS_LENGTH):(padata->length);
    
    if ((retval = (*key_proc)(context, as_reply->enc_part.enctype,
			      &salt, keyseed, decrypt_key))) {
	*decrypt_key = 0;
	return retval;
    }

    return 0;
}
    
static krb5_error_code
find_pa_system(krb5_preauthtype type, const krb5_preauth_ops **preauth)
{
    const krb5_preauth_ops *ap = preauth_systems;
    
    while ((ap->type != -1) && (ap->type != type))
	ap++;
    if (ap->type == -1)
	return(KRB5_PREAUTH_BAD_TYPE);
    *preauth = ap;
    return 0;
} 


extern const char *krb5_default_pwd_prompt1;

static krb5_error_code
sam_get_pass_from_user(krb5_context context, krb5_etype_info etype_info, git_key_proc key_proc, krb5_const_pointer key_seed, krb5_kdc_req *request, krb5_keyblock **new_enc_key, const char *prompt)
{
    krb5_enctype 		enctype;
    krb5_error_code		retval;
    const char *oldprompt;

    /* enctype = request->ktype[0]; */
    enctype = ENCTYPE_DES_CBC_MD5;
/* hack with this first! */
    oldprompt = krb5_default_pwd_prompt1;
    krb5_default_pwd_prompt1 = prompt;
    {
      krb5_data newpw;
      newpw.data = 0; newpw.length = 0;
      /* we don't keep the new password, just the key... */
      retval = (*key_proc)(context, enctype, 0, 
			   (krb5_const_pointer)&newpw, new_enc_key);
      krb5_xfree(newpw.data);
    }
    krb5_default_pwd_prompt1 = oldprompt;
    return retval;
}
static 
char *handle_sam_labels(krb5_sam_challenge *sc)
{
    char *label = sc->sam_challenge_label.data;
    unsigned int label_len = sc->sam_challenge_label.length;
    char *prompt = sc->sam_response_prompt.data;
    unsigned int prompt_len = sc->sam_response_prompt.length;
    char *challenge = sc->sam_challenge.data;
    unsigned int challenge_len = sc->sam_challenge.length;
    char *prompt1, *p;
    char *sep1 = ": [";
    char *sep2 = "]\n";
    char *sep3 = ": ";

    if (sc->sam_cksum.length == 0) {
      /* or invalid -- but lets just handle presence now XXX */
      switch (sc->sam_type) {
      case PA_SAM_TYPE_ENIGMA:	/* Enigma Logic */
	label = "Challenge for Enigma Logic mechanism";
	break;
      case PA_SAM_TYPE_DIGI_PATH: /*  Digital Pathways */
      case PA_SAM_TYPE_DIGI_PATH_HEX: /*  Digital Pathways */
	label = "Challenge for Digital Pathways mechanism";
	break;
      case PA_SAM_TYPE_ACTIVCARD_DEC: /*  Digital Pathways */
      case PA_SAM_TYPE_ACTIVCARD_HEX: /*  Digital Pathways */
	label = "Challenge for Activcard mechanism";
	break;
      case PA_SAM_TYPE_SKEY_K0:	/*  S/key where  KDC has key 0 */
	label = "Challenge for Enhanced S/Key mechanism";
	break;
      case PA_SAM_TYPE_SKEY:	/*  Traditional S/Key */
	label = "Challenge for Traditional S/Key mechanism";
	break;
      case PA_SAM_TYPE_SECURID:	/*  Security Dynamics */
	label = "Challenge for Security Dynamics mechanism";
	break;
      case PA_SAM_TYPE_SECURID_PREDICT:	/* predictive Security Dynamics */
	label = "Challenge for Security Dynamics mechanism";
	break;
      }
      prompt = "Passcode";
      label_len = strlen(label);
      prompt_len = strlen(prompt);
    }

    /* example:
       Challenge for Digital Pathways mechanism: [134591]
       Passcode: 
     */
    p = prompt1 = malloc(label_len + strlen(sep1) +
			 challenge_len + strlen(sep2) +
			 prompt_len+ strlen(sep3) + 1);
    if (p == NULL)
	return NULL;
    if (challenge_len) {
	strncpy(p, label, label_len); p += label_len;
	strcpy(p, sep1); p += strlen(sep1);
	strncpy(p, challenge, challenge_len); p += challenge_len;
	strcpy(p, sep2); p += strlen(sep2);
    }
    strncpy(p, prompt, prompt_len); p += prompt_len;
    strcpy(p, sep3); /* p += strlen(sep3); */
    return prompt1;
}

/*
 * This routine is the "obtain" function for the SAM_CHALLENGE
 * preauthentication type.  It presents the challenge...
 */
static krb5_error_code
obtain_sam_padata(krb5_context context, krb5_pa_data *in_padata, krb5_etype_info etype_info, krb5_keyblock *def_enc_key, git_key_proc key_proc, krb5_const_pointer key_seed, krb5_creds *creds, krb5_kdc_req *request, krb5_pa_data **out_padata)
{
    krb5_error_code		retval;
    krb5_data *			scratch;
    krb5_data			tmpsam;
    krb5_pa_data *		pa;
    krb5_sam_challenge		*sam_challenge = 0;
    krb5_sam_response		sam_response;
    /* these two get encrypted and stuffed in to sam_response */
    krb5_enc_sam_response_enc	enc_sam_response_enc;
    krb5_keyblock *		sam_use_key = 0;
    char * prompt;

    tmpsam.length = in_padata->length;
    tmpsam.data = (char *) in_padata->contents;
    retval = decode_krb5_sam_challenge(&tmpsam, &sam_challenge);
    if (retval)
      return retval;

    if (sam_challenge->sam_flags & KRB5_SAM_MUST_PK_ENCRYPT_SAD) {
      return KRB5_SAM_UNSUPPORTED;
    }

    enc_sam_response_enc.sam_nonce = sam_challenge->sam_nonce;
    if (!sam_challenge->sam_nonce) {
      retval = krb5_us_timeofday(context,
                                 &enc_sam_response_enc.sam_timestamp,
                                 &enc_sam_response_enc.sam_usec);
      sam_response.sam_patimestamp = enc_sam_response_enc.sam_timestamp;
    }
    if (retval)
      return retval;
    if (sam_challenge->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD) {
      /* encrypt passcode in key by stuffing it here */
      unsigned int pcsize = 256;
      char *passcode = malloc(pcsize+1);
      if (passcode == NULL)
	return ENOMEM;
      prompt = handle_sam_labels(sam_challenge);
      if (prompt == NULL) {
	free(passcode);
	return ENOMEM;
      }
      retval = krb5_read_password(context, prompt, 0, passcode, &pcsize);
      free(prompt);

      if (retval) {
	free(passcode);
	return retval;
      }
      enc_sam_response_enc.sam_sad.data = passcode;
      enc_sam_response_enc.sam_sad.length = pcsize;
    } else if (sam_challenge->sam_flags & KRB5_SAM_USE_SAD_AS_KEY) {
      prompt = handle_sam_labels(sam_challenge);
      if (prompt == NULL)
	return ENOMEM;
      retval = sam_get_pass_from_user(context, etype_info, key_proc, 
				      key_seed, request, &sam_use_key,
				      prompt);
      free(prompt);
      if (retval)
	return retval;      
      enc_sam_response_enc.sam_sad.length = 0;
    } else {
      /* what *was* it? */
      return KRB5_SAM_UNSUPPORTED;
    }

    /* so at this point, either sam_use_key is generated from the passcode
     * or enc_sam_response_enc.sam_sad is set to it, and we use 
     * def_enc_key instead. */
    /* encode the encoded part of the response */
    if ((retval = encode_krb5_enc_sam_response_enc(&enc_sam_response_enc,
						   &scratch)) != 0)
      return retval;

    if ((retval = krb5_encrypt_data(context, 
				    sam_use_key?sam_use_key:def_enc_key, 
				    0, scratch,
				    &sam_response.sam_enc_nonce_or_ts)))
      goto cleanup;

    krb5_free_data(context, scratch);
    scratch = 0;

    /* sam_enc_key is reserved for future use */
    sam_response.sam_enc_key.ciphertext.length = 0;

    /* copy things from the challenge */
    sam_response.sam_nonce = sam_challenge->sam_nonce;
    sam_response.sam_flags = sam_challenge->sam_flags;
    sam_response.sam_track_id = sam_challenge->sam_track_id;
    sam_response.sam_type = sam_challenge->sam_type;
    sam_response.magic = KV5M_SAM_RESPONSE;

    if ((retval = encode_krb5_sam_response(&sam_response, &scratch)) != 0)
	return retval;
    
    if ((pa = malloc(sizeof(krb5_pa_data))) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_SAM_RESPONSE;
    pa->length = scratch->length;
    pa->contents = (krb5_octet *) scratch->data;
    scratch = 0;		/* so we don't free it! */

    *out_padata = pa;

    retval = 0;
    
cleanup:
    if (scratch)
	krb5_free_data(context, scratch);
    if (sam_challenge)
        krb5_xfree(sam_challenge);
    return retval;
}
