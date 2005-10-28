/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1995, 2003 by the Massachusetts Institute of Technology.  All
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

#include <k5-int.h>

typedef krb5_error_code (*pa_function)(krb5_context,
				       krb5_kdc_req *request,
				       krb5_pa_data *in_padata,
				       krb5_pa_data **out_padata,
				       krb5_data *salt,
				       krb5_data *s2kparams,
				       krb5_enctype *etype,
				       krb5_keyblock *as_key,
				       krb5_prompter_fct prompter_fct,
				       void *prompter_data,
				       krb5_gic_get_as_key_fct gak_fct,
				       void *gak_data);
				 
typedef struct _pa_types_t {
    krb5_preauthtype type;
    pa_function fct;
    int flags;
} pa_types_t;

#define PA_REAL 0x0001
#define PA_INFO 0x0002

/*ARGSUSED*/
static
krb5_error_code pa_salt(krb5_context context,
			krb5_kdc_req *request,
			krb5_pa_data *in_padata,
			krb5_pa_data **out_padata,
			krb5_data *salt,
			krb5_data *s2kparams,
			krb5_enctype *etype,
			krb5_keyblock *as_key,
			krb5_prompter_fct prompter, void *prompter_data,
			krb5_gic_get_as_key_fct gak_fct, void *gak_data)
{
    krb5_data tmp;

    tmp.data = (char *)in_padata->contents;
    tmp.length = in_padata->length;
    krb5_free_data_contents(context, salt);
    krb5int_copy_data_contents(context, &tmp, salt);

    if (in_padata->pa_type == KRB5_PADATA_AFS3_SALT)
	salt->length = -1;

    return(0);
}

/*ARGSUSED*/
static
krb5_error_code pa_enc_timestamp(krb5_context context,
				 krb5_kdc_req *request,
				 krb5_pa_data *in_padata,
				 krb5_pa_data **out_padata,
				 krb5_data *salt,
				 krb5_data *s2kparams,
				 krb5_enctype *etype,
				 krb5_keyblock *as_key,
				 krb5_prompter_fct prompter,
				 void *prompter_data,
				 krb5_gic_get_as_key_fct gak_fct,
				 void *gak_data)
{
    krb5_error_code ret;
    krb5_pa_enc_ts pa_enc;
    krb5_data *tmp;
    krb5_enc_data enc_data;
    krb5_pa_data *pa;
   
    if (as_key->length == 0) {
#ifdef DEBUG
	if (salt != NULL && salt->data != NULL) {
	    fprintf (stderr, "%s:%d: salt len=%d", __FILE__, __LINE__,
		 salt->length);
	    if (salt->length > 0)
	        fprintf (stderr, " '%*s'", salt->length, salt->data);
	    fprintf (stderr, "; *etype=%d request->ktype[0]=%d\n",
		 *etype, request->ktype[0]);
	}
#endif
       if ((ret = ((*gak_fct)(context, request->client,
			     *etype ? *etype : request->ktype[0],
			     prompter, prompter_data,
			     salt, s2kparams, as_key, gak_data))))
           return(ret);
    }

    /* now get the time of day, and encrypt it accordingly */

    if ((ret = krb5_us_timeofday(context, &pa_enc.patimestamp, &pa_enc.pausec)))
	return(ret);

    if ((ret = encode_krb5_pa_enc_ts(&pa_enc, &tmp)))
	return(ret);

#ifdef DEBUG
    fprintf (stderr, "key type %d bytes %02x %02x ...\n",
	     as_key->enctype,
	     as_key->contents[0], as_key->contents[1]);
#endif
    ret = krb5_encrypt_helper(context, as_key,
			      KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS,
			      tmp, &enc_data);
#ifdef DEBUG
    fprintf (stderr, "enc data { type=%d kvno=%d data=%02x %02x ... }\n",
	     enc_data.enctype, enc_data.kvno,
	     0xff & enc_data.ciphertext.data[0],
	     0xff & enc_data.ciphertext.data[1]);
#endif

    krb5_free_data(context, tmp);

    if (ret) {
	krb5_xfree(enc_data.ciphertext.data);
	return(ret);
    }

    ret = encode_krb5_enc_data(&enc_data, &tmp);

    krb5_xfree(enc_data.ciphertext.data);

    if (ret)
	return(ret);

    if ((pa = (krb5_pa_data *) malloc(sizeof(krb5_pa_data))) == NULL) {
	krb5_free_data(context, tmp);
	return(ENOMEM);
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_ENC_TIMESTAMP;
    pa->length = tmp->length;
    pa->contents = (krb5_octet *) tmp->data;

    *out_padata = pa;

    krb5_xfree(tmp);

    return(0);
}

static 
char *sam_challenge_banner(krb5_int32 sam_type)
{
    char *label;

    switch (sam_type) {
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
    default:
	label = "Challenge from authentication server";
	break;
    }

    return(label);
}

/* this macro expands to the int,ptr necessary for "%.*s" in an sprintf */

#define SAMDATA(kdata, str, maxsize) \
	(int)((kdata.length)? \
	      ((((kdata.length)<=(maxsize))?(kdata.length):strlen(str))): \
	      strlen(str)), \
	(kdata.length)? \
	((((kdata.length)<=(maxsize))?(kdata.data):(str))):(str)

/* XXX Danger! This code is not in sync with the kerberos-password-02
   draft.  This draft cannot be implemented as written.  This code is
   compatible with earlier versions of mit krb5 and cygnus kerbnet. */

/*ARGSUSED*/
static
krb5_error_code pa_sam(krb5_context context,
		       krb5_kdc_req *request,
		       krb5_pa_data *in_padata,
		       krb5_pa_data **out_padata,
		       krb5_data *salt,
		       krb5_data *s2kparams,
		       krb5_enctype *etype,
		       krb5_keyblock *as_key,
		       krb5_prompter_fct prompter,
		       void *prompter_data,
		       krb5_gic_get_as_key_fct gak_fct,
		       void *gak_data)
{
    krb5_error_code		ret;
    krb5_data			tmpsam;
    char			name[100], banner[100];
    char			prompt[100], response[100];
    krb5_data			response_data;
    krb5_prompt			kprompt;
    krb5_prompt_type		prompt_type;
    krb5_data			defsalt;
    krb5_sam_challenge		*sam_challenge = 0;
    krb5_sam_response		sam_response;
    /* these two get encrypted and stuffed in to sam_response */
    krb5_enc_sam_response_enc	enc_sam_response_enc;
    krb5_data *			scratch;
    krb5_pa_data *		pa;
    krb5_enc_data *		enc_data;
    size_t			enclen;

    if (prompter == NULL)
	return (EIO);

    tmpsam.length = in_padata->length;
    tmpsam.data = (char *) in_padata->contents;
    if ((ret = decode_krb5_sam_challenge(&tmpsam, &sam_challenge)))
	return(ret);

    if (sam_challenge->sam_flags & KRB5_SAM_MUST_PK_ENCRYPT_SAD) {
	krb5_xfree(sam_challenge);
	return(KRB5_SAM_UNSUPPORTED);
    }
    /* If we need the password from the user (USE_SAD_AS_KEY not set),	*/
    /* then get it here.  Exception for "old" KDCs with CryptoCard	*/
    /* support which uses the USE_SAD_AS_KEY flag, but still needs pwd	*/

    if (!(sam_challenge->sam_flags & KRB5_SAM_USE_SAD_AS_KEY) ||
	(sam_challenge->sam_type == PA_SAM_TYPE_CRYPTOCARD)) {

	/* etype has either been set by caller or by KRB5_PADATA_ETYPE_INFO */
	/* message from the KDC.  If it is not set, pick an enctype that we */
	/* think the KDC will have for us.                                  */

	if (etype && *etype == 0)
           *etype = ENCTYPE_DES_CBC_CRC;

	if ((ret = (gak_fct)(context, request->client, *etype, prompter,
			prompter_data, salt, s2kparams, as_key, gak_data)))
	   return(ret);
    }

    sprintf(name, "%.*s",
	    SAMDATA(sam_challenge->sam_type_name, "SAM Authentication",
		    sizeof(name) - 1));

    sprintf(banner, "%.*s",
	    SAMDATA(sam_challenge->sam_challenge_label,
		    sam_challenge_banner(sam_challenge->sam_type),
		    sizeof(banner)-1));

    /* sprintf(prompt, "Challenge is [%s], %s: ", challenge, prompt); */
    sprintf(prompt, "%s%.*s%s%.*s",
	    sam_challenge->sam_challenge.length?"Challenge is [":"",
	    SAMDATA(sam_challenge->sam_challenge, "", 20),
	    sam_challenge->sam_challenge.length?"], ":"",
	    SAMDATA(sam_challenge->sam_response_prompt, "passcode", 55));

    response_data.data = response;
    response_data.length = sizeof(response);

    kprompt.prompt = prompt;
    kprompt.hidden = 1;
    kprompt.reply = &response_data;
    prompt_type = KRB5_PROMPT_TYPE_PREAUTH;

    /* PROMPTER_INVOCATION */
    krb5int_set_prompt_types(context, &prompt_type);
    if ((ret = ((*prompter)(context, prompter_data, name,
			   banner, 1, &kprompt)))) {
	krb5_xfree(sam_challenge);
	krb5int_set_prompt_types(context, 0);
	return(ret);
    }
    krb5int_set_prompt_types(context, 0);

    enc_sam_response_enc.sam_nonce = sam_challenge->sam_nonce;
    if (sam_challenge->sam_nonce == 0) {
	if ((ret = krb5_us_timeofday(context, 
				&enc_sam_response_enc.sam_timestamp,
				&enc_sam_response_enc.sam_usec))) {
		krb5_xfree(sam_challenge);
		return(ret);
	}

	sam_response.sam_patimestamp = enc_sam_response_enc.sam_timestamp;
    }

    /* XXX What if more than one flag is set?  */
    if (sam_challenge->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD) {

	/* Most of this should be taken care of before we get here.  We */
	/* will need the user's password and as_key to encrypt the SAD	*/
	/* and we want to preserve ordering of user prompts (first	*/
	/* password, then SAM data) so that user's won't be confused.	*/

	if (as_key->length) {
	    krb5_free_keyblock_contents(context, as_key);
	    as_key->length = 0;
	}

	/* generate a salt using the requested principal */

	if ((salt->length == -1) && (salt->data == NULL)) {
	    if ((ret = krb5_principal2salt(context, request->client,
					  &defsalt))) {
		krb5_xfree(sam_challenge);
		return(ret);
	    }

	    salt = &defsalt;
	} else {
	    defsalt.length = 0;
	}

	/* generate a key using the supplied password */

	ret = krb5_c_string_to_key(context, ENCTYPE_DES_CBC_MD5,
				   (krb5_data *)gak_data, salt, as_key);

	if (defsalt.length)
	    krb5_xfree(defsalt.data);

	if (ret) {
	    krb5_xfree(sam_challenge);
	    return(ret);
	}

	/* encrypt the passcode with the key from above */

	enc_sam_response_enc.sam_sad = response_data;
    } else if (sam_challenge->sam_flags & KRB5_SAM_USE_SAD_AS_KEY) {

	/* process the key as password */

	if (as_key->length) {
	    krb5_free_keyblock_contents(context, as_key);
	    as_key->length = 0;
	}

#if 0
	if ((salt->length == -1) && (salt->data == NULL)) {
	    if (ret = krb5_principal2salt(context, request->client,
					  &defsalt)) {
		krb5_xfree(sam_challenge);
		return(ret);
	    }

	    salt = &defsalt;
	} else {
	    defsalt.length = 0;
	}
#else
	defsalt.length = 0;
	salt = NULL;
#endif
	    
	/* XXX As of the passwords-04 draft, no enctype is specified,
	   the server uses ENCTYPE_DES_CBC_MD5. In the future the
	   server should send a PA-SAM-ETYPE-INFO containing the enctype. */

	ret = krb5_c_string_to_key(context, ENCTYPE_DES_CBC_MD5,
				   &response_data, salt, as_key);

	if (defsalt.length)
	    krb5_xfree(defsalt.data);

	if (ret) {
	    krb5_xfree(sam_challenge);
	    return(ret);
	}

	enc_sam_response_enc.sam_sad.length = 0;
    } else {
	/* Eventually, combine SAD with long-term key to get
	   encryption key.  */
	return KRB5_PREAUTH_BAD_TYPE;
    }

    /* copy things from the challenge */
    sam_response.sam_nonce = sam_challenge->sam_nonce;
    sam_response.sam_flags = sam_challenge->sam_flags;
    sam_response.sam_track_id = sam_challenge->sam_track_id;
    sam_response.sam_type = sam_challenge->sam_type;
    sam_response.magic = KV5M_SAM_RESPONSE;

    krb5_xfree(sam_challenge);

    /* encode the encoded part of the response */
    if ((ret = encode_krb5_enc_sam_response_enc(&enc_sam_response_enc,
					       &scratch)))
	return(ret);

    /*
     * Solaris Kerberos:  
     * Using new crypto interface now so we can get rid of the
     * old modules.
     */
    if ((ret = krb5_c_encrypt_length(context, as_key->enctype,
				scratch->length, &enclen))) {
	krb5_free_data(context, scratch);
	return(ret);
    }

    enc_data = &sam_response.sam_enc_nonce_or_ts;
    enc_data->magic = KV5M_ENC_DATA;
    enc_data->kvno = 0;
    enc_data->enctype = as_key->enctype;
    enc_data->ciphertext.length = enclen;

    if ((enc_data->ciphertext.data = MALLOC(enclen)) == NULL) {
	enc_data->ciphertext.length = 0;
	krb5_free_data(context, scratch);
	return(ENOMEM);
    }

    if ((ret = krb5_c_encrypt(context, as_key, 0, 0,
	scratch, enc_data))) {
	FREE(enc_data->ciphertext.data, enclen);
	enc_data->ciphertext.data = NULL;
	enc_data->ciphertext.length = 0;
    }

    krb5_free_data(context, scratch);

    if (ret)
	return(ret);

    /* sam_enc_key is reserved for future use */
    sam_response.sam_enc_key.ciphertext.length = 0;

    if ((pa = malloc(sizeof(krb5_pa_data))) == NULL)
	return(ENOMEM);

    if ((ret = encode_krb5_sam_response(&sam_response, &scratch))) {
	free(pa);
	return(ret);
    }

    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_SAM_RESPONSE;
    pa->length = scratch->length;
    pa->contents = (krb5_octet *) scratch->data;

    *out_padata = pa;

    return(0);
}

static
krb5_error_code pa_sam_2(krb5_context context,
				krb5_kdc_req *request,
				krb5_pa_data *in_padata,
				krb5_pa_data **out_padata,
				krb5_data *salt,
			 krb5_data *s2kparams,
				krb5_enctype *etype,
				krb5_keyblock *as_key,
				krb5_prompter_fct prompter,
				void *prompter_data,
				krb5_gic_get_as_key_fct gak_fct,
				void *gak_data) {

   krb5_error_code retval;
   krb5_sam_challenge_2 *sc2 = NULL;
   krb5_sam_challenge_2_body *sc2b = NULL;
   krb5_data tmp_data;
   krb5_data response_data;
   char name[100], banner[100], prompt[100], response[100];
   krb5_prompt kprompt;
   krb5_prompt_type prompt_type;
   krb5_data defsalt;
   krb5_checksum **cksum;
   krb5_data *scratch = NULL;
   krb5_boolean valid_cksum = 0;
   krb5_enc_sam_response_enc_2 enc_sam_response_enc_2;
   krb5_sam_response_2 sr2;
   size_t ciph_len;
   krb5_pa_data *sam_padata;

   if (prompter == NULL)
	return KRB5_LIBOS_CANTREADPWD;

   tmp_data.length = in_padata->length;
   tmp_data.data = (char *)in_padata->contents;

   if ((retval = decode_krb5_sam_challenge_2(&tmp_data, &sc2)))
	return(retval);

   retval = decode_krb5_sam_challenge_2_body(&sc2->sam_challenge_2_body, &sc2b);

   if (retval)
	return(retval);

   if (!sc2->sam_cksum || ! *sc2->sam_cksum) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	return(KRB5_SAM_NO_CHECKSUM);
   }

   if (sc2b->sam_flags & KRB5_SAM_MUST_PK_ENCRYPT_SAD) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	return(KRB5_SAM_UNSUPPORTED);
   }

   if (!valid_enctype(sc2b->sam_etype)) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	return(KRB5_SAM_INVALID_ETYPE);
   }

   /* All of the above error checks are KDC-specific, that is, they	*/
   /* assume a failure in the KDC reply.  By returning anything other	*/
   /* than KRB5_KDC_UNREACH, KRB5_PREAUTH_FAILED,		*/
   /* KRB5_LIBOS_PWDINTR, or KRB5_REALM_CANT_RESOLVE, the client will	*/
   /* most likely go on to try the AS_REQ against master KDC		*/

   if (!(sc2b->sam_flags & KRB5_SAM_USE_SAD_AS_KEY)) {
	/* We will need the password to obtain the key used for */
	/* the checksum, and encryption of the sam_response.	*/
	/* Go ahead and get it now, preserving the ordering of	*/
	/* prompts for the user.				*/

	retval = (gak_fct)(context, request->client,
			sc2b->sam_etype, prompter,
			prompter_data, salt, s2kparams, as_key, gak_data);
	if (retval) {
	   krb5_free_sam_challenge_2(context, sc2);
	   krb5_free_sam_challenge_2_body(context, sc2b);
	   return(retval);
	}
   }

   sprintf(name, "%.*s",
	SAMDATA(sc2b->sam_type_name, "SAM Authentication",
	sizeof(name) - 1));

   sprintf(banner, "%.*s",
	SAMDATA(sc2b->sam_challenge_label,
	sam_challenge_banner(sc2b->sam_type),
	sizeof(banner)-1));

   sprintf(prompt, "%s%.*s%s%.*s",
	sc2b->sam_challenge.length?"Challenge is [":"",
	SAMDATA(sc2b->sam_challenge, "", 20),
	sc2b->sam_challenge.length?"], ":"",
	SAMDATA(sc2b->sam_response_prompt, "passcode", 55));

   response_data.data = response;
   response_data.length = sizeof(response);
   kprompt.prompt = prompt;
   kprompt.hidden = 1;
   kprompt.reply = &response_data;

   prompt_type = KRB5_PROMPT_TYPE_PREAUTH;
   krb5int_set_prompt_types(context, &prompt_type);

   if ((retval = ((*prompter)(context, prompter_data, name,
				banner, 1, &kprompt)))) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	krb5int_set_prompt_types(context, 0);
	return(retval);
   }

   krb5int_set_prompt_types(context, (krb5_prompt_type *)NULL);

   /* Generate salt used by string_to_key() */
   if ((salt->length == -1) && (salt->data == NULL)) {
	if ((retval =
             krb5_principal2salt(context, request->client, &defsalt))) {
	   krb5_free_sam_challenge_2(context, sc2);
	   krb5_free_sam_challenge_2_body(context, sc2b);
	   return(retval);
	}
        salt = &defsalt;
   } else {
	defsalt.length = 0;
   }

   /* Get encryption key to be used for checksum and sam_response */
   if (!(sc2b->sam_flags & KRB5_SAM_USE_SAD_AS_KEY)) {
	/* as_key = string_to_key(password) */

	if (as_key->length) {
	   krb5_free_keyblock_contents(context, as_key);
	   as_key->length = 0;
	}

        /* generate a key using the supplied password */
	retval = krb5_c_string_to_key(context, sc2b->sam_etype,
                                   (krb5_data *)gak_data, salt, as_key);

	if (retval) {
	   krb5_free_sam_challenge_2(context, sc2);
	   krb5_free_sam_challenge_2_body(context, sc2b);
	   if (defsalt.length) krb5_xfree(defsalt.data);
	   return(retval);
	}

        if (!(sc2b->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD)) {
	   /* as_key = combine_key (as_key, string_to_key(SAD)) */
	   krb5_keyblock tmp_kb;

           retval = krb5_c_string_to_key(context, sc2b->sam_etype,
				&response_data, salt, &tmp_kb);

           if (retval) {
		krb5_free_sam_challenge_2(context, sc2);
		krb5_free_sam_challenge_2_body(context, sc2b);
		if (defsalt.length) krb5_xfree(defsalt.data);
		return(retval);
	   }

           /* This should be a call to the crypto library some day */
	   /* key types should already match the sam_etype */
	   retval = krb5int_c_combine_keys(context, as_key, &tmp_kb, as_key);

           if (retval) {
		krb5_free_sam_challenge_2(context, sc2);
		krb5_free_sam_challenge_2_body(context, sc2b);
		if (defsalt.length) krb5_xfree(defsalt.data);
		return(retval);
	   }
           krb5_free_keyblock_contents(context, &tmp_kb);
	}
        if (defsalt.length)
	   krb5_xfree(defsalt.data);

   } else {
	/* as_key = string_to_key(SAD) */

	if (as_key->length) {
	   krb5_free_keyblock_contents(context, as_key);
	   as_key->length = 0;
	}

        /* generate a key using the supplied password */
	retval = krb5_c_string_to_key(context, sc2b->sam_etype,
				&response_data, salt, as_key);

	if (defsalt.length)
	   krb5_xfree(defsalt.data);

	if (retval) {
	   krb5_free_sam_challenge_2(context, sc2);
	   krb5_free_sam_challenge_2_body(context, sc2b);
	   return(retval);
	}
   }

   /* Now we have a key, verify the checksum on the sam_challenge */

   cksum = sc2->sam_cksum;

   while (*cksum) {
	/* Check this cksum */
	retval = krb5_c_verify_checksum(context, as_key,
			KRB5_KEYUSAGE_PA_SAM_CHALLENGE_CKSUM,
			&sc2->sam_challenge_2_body,
			*cksum, &valid_cksum);
	if (retval) {
	   krb5_free_data(context, scratch);
	   krb5_free_sam_challenge_2(context, sc2);
	   krb5_free_sam_challenge_2_body(context, sc2b);
	   return(retval);
	}
        if (valid_cksum)
	   break;
	cksum++;
   }

   if (!valid_cksum) {

	/* If KRB5_SAM_SEND_ENCRYPTED_SAD is set, then password is only */
	/* source for checksum key.  Therefore, a bad checksum means a	*/
	/* bad password.  Don't give that direct feedback to someone	*/
	/* trying to brute-force passwords.				*/

	if (!(sc2b->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD))
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	/*
         * Note: We return AP_ERR_BAD_INTEGRITY so upper-level applications
	 * can interpret that as "password incorrect", which is probably
	 * the best error we can return in this situation.
	 */
	return(KRB5KRB_AP_ERR_BAD_INTEGRITY);
   }

   /* fill in enc_sam_response_enc_2 */
   enc_sam_response_enc_2.magic = KV5M_ENC_SAM_RESPONSE_ENC_2;
   enc_sam_response_enc_2.sam_nonce = sc2b->sam_nonce;
   if (sc2b->sam_flags & KRB5_SAM_SEND_ENCRYPTED_SAD) {
	enc_sam_response_enc_2.sam_sad = response_data;
   } else {
	enc_sam_response_enc_2.sam_sad.data = NULL;
	enc_sam_response_enc_2.sam_sad.length = 0;
   }

   /* encode and encrypt enc_sam_response_enc_2 with as_key */
   retval = encode_krb5_enc_sam_response_enc_2(&enc_sam_response_enc_2,
		&scratch);
   if (retval) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	return(retval);
   }

   /* Fill in sam_response_2 */
   memset(&sr2, 0, sizeof(sr2));
   sr2.sam_type = sc2b->sam_type;
   sr2.sam_flags = sc2b->sam_flags;
   sr2.sam_track_id = sc2b->sam_track_id;
   sr2.sam_nonce = sc2b->sam_nonce;

   /* Now take care of sr2.sam_enc_nonce_or_sad by encrypting encoded	*/
   /* enc_sam_response_enc_2 from above */

   retval = krb5_c_encrypt_length(context, as_key->enctype, scratch->length,
                                  &ciph_len);
   if (retval) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	return(retval);
   }
   sr2.sam_enc_nonce_or_sad.ciphertext.length = ciph_len;

   sr2.sam_enc_nonce_or_sad.ciphertext.data =
	(char *)malloc(sr2.sam_enc_nonce_or_sad.ciphertext.length);

   if (!sr2.sam_enc_nonce_or_sad.ciphertext.data) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	return(ENOMEM);
   }

   retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_SAM_RESPONSE,
		NULL, scratch, &sr2.sam_enc_nonce_or_sad);
   if (retval) {
	krb5_free_sam_challenge_2(context, sc2);
	krb5_free_sam_challenge_2_body(context, sc2b);
	krb5_free_data(context, scratch);
	krb5_free_data_contents(context, &sr2.sam_enc_nonce_or_sad.ciphertext);
	return(retval);
   }
   krb5_free_data(context, scratch);
   scratch = NULL;

   /* Encode the sam_response_2 */
   retval = encode_krb5_sam_response_2(&sr2, &scratch);
   krb5_free_sam_challenge_2(context, sc2);
   krb5_free_sam_challenge_2_body(context, sc2b);
   krb5_free_data_contents(context, &sr2.sam_enc_nonce_or_sad.ciphertext);

   if (retval) {
	return (retval);
   }

   /* Almost there, just need to make padata !	*/
   sam_padata = malloc(sizeof(krb5_pa_data));
   if (sam_padata == NULL) {
	krb5_free_data(context, scratch);
	return(ENOMEM);
   }

   sam_padata->magic = KV5M_PA_DATA;
   sam_padata->pa_type = KRB5_PADATA_SAM_RESPONSE_2;
   sam_padata->length = scratch->length;
   sam_padata->contents = (krb5_octet *) scratch->data;

   *out_padata = sam_padata;

   return(0);
}


static pa_types_t pa_types[] = {
    {
	KRB5_PADATA_PW_SALT,
	pa_salt,
	PA_INFO,
    },
    {
	KRB5_PADATA_AFS3_SALT,
	pa_salt,
	PA_INFO,
    },
    {
	KRB5_PADATA_ENC_TIMESTAMP,
	pa_enc_timestamp,
	PA_REAL,
    },
    {
     	KRB5_PADATA_SAM_CHALLENGE_2,
	pa_sam_2,
	PA_REAL,
    },
    {
	KRB5_PADATA_SAM_CHALLENGE,
	pa_sam,
	PA_REAL,
    },
    {
	-1,
	NULL,
	0,
    },
};

krb5_error_code
krb5_do_preauth(krb5_context context,
		krb5_kdc_req *request,
		krb5_pa_data **in_padata, krb5_pa_data ***out_padata,
		krb5_data *salt, krb5_data *s2kparams,
		krb5_enctype *etype,
		krb5_keyblock *as_key,
		krb5_prompter_fct prompter, void *prompter_data,
		krb5_gic_get_as_key_fct gak_fct, void *gak_data)
{
    int h, i, j, out_pa_list_size;
    int seen_etype_info2 = 0;
    krb5_pa_data *out_pa = NULL, **out_pa_list = NULL;
    krb5_data scratch;
    krb5_etype_info etype_info = NULL;
    krb5_error_code ret;
    static const int paorder[] = { PA_INFO, PA_REAL };
    int realdone;

    KRB5_LOG0(KRB5_INFO, "krb5_do_preauth() start");

    if (in_padata == NULL) {
	*out_padata = NULL;
	return(0);
    }

#ifdef DEBUG
    if (salt && salt->data && salt->length > 0) {
    	fprintf (stderr, "salt len=%d", salt->length);
	    if (salt->length > 0)
		fprintf (stderr, " '%*s'", salt->length, salt->data);
	    fprintf (stderr, "; preauth data types:");
	    for (i = 0; in_padata[i]; i++) {
		fprintf (stderr, " %d", in_padata[i]->pa_type);
    	}
    	fprintf (stderr, "\n");
    }
#endif

    out_pa_list = NULL;
    out_pa_list_size = 0;

    /* first do all the informational preauths, then the first real one */

    for (h=0; h<(sizeof(paorder)/sizeof(paorder[0])); h++) {
	realdone = 0;
	for (i=0; in_padata[i] && !realdone; i++) {
	    int k, l, etype_found, valid_etype_found;
	    /*
	     * This is really gross, but is necessary to prevent
	     * lossge when talking to a 1.0.x KDC, which returns an
	     * erroneous PA-PW-SALT when it returns a KRB-ERROR
	     * requiring additional preauth.
	     */
	    switch (in_padata[i]->pa_type) {
	    case KRB5_PADATA_ETYPE_INFO:
	    case KRB5_PADATA_ETYPE_INFO2:
	    {
		krb5_preauthtype pa_type = in_padata[i]->pa_type;
		if (etype_info) {
		    if (seen_etype_info2 || pa_type != KRB5_PADATA_ETYPE_INFO2)
			continue;
		    if (pa_type == KRB5_PADATA_ETYPE_INFO2) {
                        krb5_free_etype_info( context, etype_info);
			etype_info = NULL;
                    }
		}

		scratch.length = in_padata[i]->length;
		scratch.data = (char *) in_padata[i]->contents;
		if (pa_type == KRB5_PADATA_ETYPE_INFO2) {
                    seen_etype_info2++;
                    ret = decode_krb5_etype_info2(&scratch, &etype_info);
		}
		else ret = decode_krb5_etype_info(&scratch, &etype_info);
		if (ret) {
                    ret = 0; /*Ignore error and etype_info element*/
                    krb5_free_etype_info( context, etype_info);
                    etype_info = NULL;
                    continue;
		}
		if (etype_info[0] == NULL) {
		    krb5_free_etype_info(context, etype_info);
		    etype_info = NULL;
		    break;
		}
		/*
		 * Select first etype in our request which is also in
		 * etype-info (preferring client request ktype order).
		 */
		for (etype_found = 0, valid_etype_found = 0, k = 0;
		       	!etype_found && k < request->nktypes; k++) {
		    for (l = 0; etype_info[l]; l++) {
			if (etype_info[l]->etype == request->ktype[k]) {
			    etype_found++;
			    break;
			}
			/* check if program has support for this etype for more
			 * precise error reporting.
			 */
			if (valid_enctype(etype_info[l]->etype))
			    valid_etype_found++;
		    }
		}
		if (!etype_found) {
		    KRB5_LOG(KRB5_ERR, "error !etype_found, "
				"valid_etype_found = %d",
				valid_etype_found); 
		    if (valid_etype_found) {
			/* supported enctype but not requested */
			ret = KRB5_CONFIG_ETYPE_NOSUPP;
			goto cleanup;
		    }
		    else {
			/* unsupported enctype */
			ret = KRB5_PROG_ETYPE_NOSUPP;
			goto cleanup;
		    }

		}
		scratch.data = (char *) etype_info[l]->salt;
		scratch.length = etype_info[l]->length;
		krb5_free_data_contents(context, salt);
		if (scratch.length == KRB5_ETYPE_NO_SALT)
		  salt->data = NULL;
		else
                    if ((ret = krb5int_copy_data_contents( context,
				&scratch, salt)) != 0)
			goto cleanup;
		*etype = etype_info[l]->etype;
		krb5_free_data_contents(context, s2kparams);
		if ((ret = krb5int_copy_data_contents(context,
				&etype_info[l]->s2kparams,
				s2kparams)) != 0)
		  goto cleanup;
		break;
	    }
	    case KRB5_PADATA_PW_SALT:
	    case KRB5_PADATA_AFS3_SALT:
		if (etype_info)
		    continue;
		break;
	    default:
		;
	    }
	    for (j=0; pa_types[j].type >= 0; j++) {
		if ((in_padata[i]->pa_type == pa_types[j].type) &&
		    (pa_types[j].flags & paorder[h])) {
		    out_pa = NULL;

		    if ((ret = ((*pa_types[j].fct)(context, request,
					in_padata[i], &out_pa,
					salt, s2kparams, etype, as_key,
					prompter, prompter_data,
					gak_fct, gak_data)))) {
			goto cleanup;
		    }

		    if (out_pa) {
			if (out_pa_list == NULL) {
			    if ((out_pa_list =
				 (krb5_pa_data **)
				 malloc(2*sizeof(krb5_pa_data *)))
				== NULL) {
				ret = ENOMEM;
				goto cleanup;
			     }
			} else {
			    if ((out_pa_list =
				 (krb5_pa_data **)
				 realloc(out_pa_list,
					 (out_pa_list_size+2)*
					 sizeof(krb5_pa_data *)))
				== NULL) {
				/* XXX this will leak the pointers which
				   have already been allocated.  oh well. */
				ret = ENOMEM;
				goto cleanup;
			    }
			}
			
			out_pa_list[out_pa_list_size++] = out_pa;
		    }
		    if (paorder[h] == PA_REAL)
			realdone = 1;
		}
	    }
	}
    }

    if (out_pa_list)
	out_pa_list[out_pa_list_size++] = NULL;

    *out_padata = out_pa_list;
    if (etype_info)
	krb5_free_etype_info(context, etype_info);
   
    KRB5_LOG0(KRB5_INFO, "krb5_do_preauth() end");
    return(0);
cleanup:
    if (out_pa_list) {
	out_pa_list[out_pa_list_size++] = NULL;
	krb5_free_pa_data(context, out_pa_list);
    }
    if (etype_info)
	krb5_free_etype_info(context, etype_info);

    KRB5_LOG0(KRB5_INFO, "krb5_do_preauth() end");
    return (ret);

}
