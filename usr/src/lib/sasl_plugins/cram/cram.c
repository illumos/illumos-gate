/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* CRAM-MD5 SASL plugin
 * Rob Siemborski
 * Tim Martin 
 * $Id: cram.c,v 1.79 2003/02/18 18:27:37 rjs3 Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef macintosh
#include <sys/stat.h>
#endif
#include <fcntl.h>

#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>

#ifdef _SUN_SDK_
#include <unistd.h>
#endif /* _SUN_SDK_ */

#include "plugin_common.h"

#ifdef macintosh
#include <sasl_cram_plugin_decl.h>
#endif

/*****************************  Common Section  *****************************/

#ifndef _SUN_SDK_
static const char plugin_id[] = "$Id: cram.c,v 1.79 2003/02/18 18:27:37 rjs3 Exp $";
#endif /* !_SUN_SDK_ */

/* convert a string of 8bit chars to it's representation in hex
 * using lowercase letters
 */
static char *convert16(unsigned char *in, int inlen, const sasl_utils_t *utils)
{
    static char hex[]="0123456789abcdef";
    int lup;
    char *out;

    out = utils->malloc(inlen*2+1);
    if (out == NULL) return NULL;
    
    for (lup=0; lup < inlen; lup++) {
	out[lup*2] = hex[in[lup] >> 4];
	out[lup*2+1] = hex[in[lup] & 15];
    }

    out[lup*2] = 0;
    return out;
}


/*****************************  Server Section  *****************************/

typedef struct server_context {
    int state;

    char *challenge;
} server_context_t;

static int
crammd5_server_mech_new(void *glob_context __attribute__((unused)),
			sasl_server_params_t *sparams,
			const char *challenge __attribute__((unused)),
			unsigned challen __attribute__((unused)),
			void **conn_context)
{
    server_context_t *text;
    
    /* holds state are in */
    text = sparams->utils->malloc(sizeof(server_context_t));
    if (text == NULL) {
	MEMERROR( sparams->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(server_context_t));
    
    text->state = 1;
    
    *conn_context = text;
    
    return SASL_OK;
}

/*
 * Returns the current time (or part of it) in string form
 *  maximum length=15
 */
static char *gettime(sasl_server_params_t *sparams)
{
    char *ret;
    time_t t;
    
    t=time(NULL);
    ret= sparams->utils->malloc(15);
    if (ret==NULL) return NULL;
    
    /* the bottom bits are really the only random ones so if
       we overflow we don't want to loose them */
    snprintf(ret,15,"%lu",t%(0xFFFFFF));
    
    return ret;
}

static char *randomdigits(sasl_server_params_t *sparams)
{
    unsigned int num;
    char *ret;
    unsigned char temp[5]; /* random 32-bit number */
    
#if defined _DEV_URANDOM && defined _SUN_SDK_
    {
	int fd = open(_DEV_URANDOM, O_RDONLY);
	int nread = 0;

  	if (fd != -1) { 
		nread = read(fd, temp, 4); 
		close(fd); 
	} 
	if (nread != 4)
	    sparams->utils->rand(sparams->utils->rpool,
		(char *) temp, 4);
    }
#else
    sparams->utils->rand(sparams->utils->rpool,(char *) temp,4);
#endif /* _DEV_URANDOM && _SUN_SDK_ */
    num=(temp[0] * 256 * 256 * 256) +
	(temp[1] * 256 * 256) +
	(temp[2] * 256) +
	(temp[3] );
    
    ret = sparams->utils->malloc(15); /* there's no way an unsigned can be longer than this right? */
    if (ret == NULL) return NULL;
    sprintf(ret, "%u", num);
    
    return ret;
}

static int
crammd5_server_mech_step1(server_context_t *text,
			  sasl_server_params_t *sparams,
			  const char *clientin __attribute__((unused)),
			  unsigned clientinlen,
			  const char **serverout,
			  unsigned *serveroutlen,
			  sasl_out_params_t *oparams __attribute__((unused)))
{
    char *time, *randdigits;
	    
    /* we shouldn't have received anything */
    if (clientinlen != 0) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
		"CRAM-MD5 does not accept inital data");
#else
	SETERROR(sparams->utils, "CRAM-MD5 does not accpet inital data");
#endif /* _SUN_SDK_ */
	return SASL_BADPROT;
    }
    
    /* get time and a random number for the nonce */
    time = gettime(sparams);
    randdigits = randomdigits(sparams);
    if ((time == NULL) || (randdigits == NULL)) {
	MEMERROR( sparams->utils );
	return SASL_NOMEM;
    }
    
    /* allocate some space for the challenge */
    text->challenge = sparams->utils->malloc(200 + 1);
    if (text->challenge == NULL) {
	MEMERROR(sparams->utils);
	return SASL_NOMEM;
    }
    
    /* create the challenge */
    snprintf(text->challenge, 200, "<%s.%s@%s>", randdigits, time,
	     sparams->serverFQDN);
    
    *serverout = text->challenge;
    *serveroutlen = strlen(text->challenge);
    
    /* free stuff */
    sparams->utils->free(time);    
    sparams->utils->free(randdigits);    
    
    text->state = 2;
    
    return SASL_CONTINUE;
}
    
static int
crammd5_server_mech_step2(server_context_t *text,
			  sasl_server_params_t *sparams,
			  const char *clientin,
			  unsigned clientinlen,
			  const char **serverout __attribute__((unused)),
			  unsigned *serveroutlen __attribute__((unused)),
			  sasl_out_params_t *oparams)
{
    char *userid = NULL;
    sasl_secret_t *sec = NULL;
    int pos, len;
    int result = SASL_FAIL;
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       "*cmusaslsecretCRAM-MD5",
				       NULL };
    struct propval auxprop_values[3];
    HMAC_MD5_CTX tmphmac;
    HMAC_MD5_STATE md5state;
    int clear_md5state = 0;
    char *digest_str = NULL;
    UINT4 digest[4];
    
    /* extract userid; everything before last space */
    pos = clientinlen-1;
    while ((pos > 0) && (clientin[pos] != ' ')) pos--;
    
    if (pos <= 0) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
		"need authentication name");
#else
	SETERROR( sparams->utils,"need authentication name");
#endif /* _SUN_SDK_ */
	return SASL_BADPROT;
    }
    
    userid = (char *) sparams->utils->malloc(pos+1);
    if (userid == NULL) {
	MEMERROR( sparams->utils);
	return SASL_NOMEM;
    }
    
    /* copy authstr out */
    memcpy(userid, clientin, pos);
    userid[pos] = '\0';
    
    result = sparams->utils->prop_request(sparams->propctx, password_request);
    if (result != SASL_OK) goto done;
    
    /* this will trigger the getting of the aux properties */
    result = sparams->canon_user(sparams->utils->conn,
				 userid, 0, SASL_CU_AUTHID | SASL_CU_AUTHZID,
				 oparams);
    if (result != SASL_OK) goto done;
    
    result = sparams->utils->prop_getnames(sparams->propctx,
					   password_request,
					   auxprop_values);
    if (result < 0 ||
	((!auxprop_values[0].name || !auxprop_values[0].values) &&
	 (!auxprop_values[1].name || !auxprop_values[1].values))) {
	/* We didn't find this username */
#ifdef _INTEGRATED_SOLARIS_
	sparams->utils->seterror(sparams->utils->conn,0,
				 gettext("no secret in database"));
#else
	sparams->utils->seterror(sparams->utils->conn,0,
				 "no secret in database");
#endif /* _INTEGRATED_SOLARIS_ */
	result = SASL_NOUSER;
	goto done;
    }
    
    if (auxprop_values[0].name && auxprop_values[0].values) {
	len = strlen(auxprop_values[0].values[0]);
	if (len == 0) {
#ifdef _INTEGRATED_SOLARIS_
	    sparams->utils->seterror(sparams->utils->conn,0,
				     gettext("empty secret"));
#else
	    sparams->utils->seterror(sparams->utils->conn,0,
				     "empty secret");
#endif /* _INTEGRATED_SOLARIS_ */
	    result = SASL_FAIL;
	    goto done;
	}
	
	sec = sparams->utils->malloc(sizeof(sasl_secret_t) + len);
	if (!sec) goto done;
	
	sec->len = len;
#ifdef _SUN_SDK_
	strncpy((char *)sec->data, auxprop_values[0].values[0], len + 1);   
#else
	strncpy(sec->data, auxprop_values[0].values[0], len + 1);   
#endif /* _SUN_SDK_ */
	
	clear_md5state = 1;
	/* Do precalculation on plaintext secret */
	sparams->utils->hmac_md5_precalc(&md5state, /* OUT */
					 sec->data,
					 sec->len);
    } else if (auxprop_values[1].name && auxprop_values[1].values) {
	/* We have a precomputed secret */
	memcpy(&md5state, auxprop_values[1].values[0],
	       sizeof(HMAC_MD5_STATE));
    } else {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "Have neither type of secret");
#else
	sparams->utils->seterror(sparams->utils->conn, 0,
				 "Have neither type of secret");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }
    
    /* ok this is annoying:
       so we have this half-way hmac transform instead of the plaintext
       that means we half to:
       -import it back into a md5 context
       -do an md5update with the nonce 
       -finalize it
    */
    sparams->utils->hmac_md5_import(&tmphmac, (HMAC_MD5_STATE *) &md5state);
    sparams->utils->MD5Update(&(tmphmac.ictx),
			      (const unsigned char *) text->challenge,
			      strlen(text->challenge));
    sparams->utils->hmac_md5_final((unsigned char *) &digest, &tmphmac);
    
    /* convert to base 16 with lower case letters */
    digest_str = convert16((unsigned char *) digest, 16, sparams->utils);
    
    /* if same then verified 
     *  - we know digest_str is null terminated but clientin might not be
     */
    if (strncmp(digest_str, clientin+pos+1, strlen(digest_str)) != 0) {
#ifdef _INTEGRATED_SOLARIS_
	sparams->utils->seterror(sparams->utils->conn, 0,
				 gettext("incorrect digest response"));
#else
	sparams->utils->seterror(sparams->utils->conn, 0,
				 "incorrect digest response");
#endif /* _INTEGRATED_SOLARIS_ */
	result = SASL_BADAUTH;
	goto done;
    }
    
    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;
    
    result = SASL_OK;
    
  done:
    if (userid) sparams->utils->free(userid);
    if (sec) _plug_free_secret(sparams->utils, &sec);

    if (digest_str) sparams->utils->free(digest_str);
    if (clear_md5state) memset(&md5state, 0, sizeof(md5state));
    
    return result;
}

static int crammd5_server_mech_step(void *conn_context,
				    sasl_server_params_t *sparams,
				    const char *clientin,
				    unsigned clientinlen,
				    const char **serverout,
				    unsigned *serveroutlen,
				    sasl_out_params_t *oparams)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    *serverout = NULL;
    *serveroutlen = 0;
    
    /* this should be well more than is ever needed */
    if (clientinlen > 1024) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
		"CRAM-MD5 input longer than 1024 bytes");
#else
	SETERROR(sparams->utils, "CRAM-MD5 input longer than 1024 bytes");
#endif /* _SUN_SDK_ */
	return SASL_BADPROT;
    }
    
    switch (text->state) {

    case 1:
	return crammd5_server_mech_step1(text, sparams,
					 clientin, clientinlen,
					 serverout, serveroutlen,
					 oparams);

    case 2:
	return crammd5_server_mech_step2(text, sparams,
					 clientin, clientinlen,
					 serverout, serveroutlen,
					 oparams);

    default: /* should never get here */
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			   "Invalid CRAM-MD5 server step %d", text->state);
#else
	sparams->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid CRAM-MD5 server step %d\n", text->state);
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }
    
#ifndef _SUN_SDK_
    return SASL_FAIL; /* should never get here */
#endif /* !_SUN_SDK_ */
}

static void crammd5_server_mech_dispose(void *conn_context,
					const sasl_utils_t *utils)
{
    server_context_t *text = (server_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->challenge) _plug_free_string(utils,&(text->challenge));
    
    utils->free(text);
}

static sasl_server_plug_t crammd5_server_plugins[] = 
{
    {
	"CRAM-MD5",			/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_SERVER_FIRST,		/* features */
	NULL,				/* glob_context */
	&crammd5_server_mech_new,	/* mech_new */
	&crammd5_server_mech_step,	/* mech_step */
	&crammd5_server_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech avail */
	NULL				/* spare */
    }
};

int crammd5_server_plug_init(const sasl_utils_t *utils,
			     int maxversion,
			     int *out_version,
			     sasl_server_plug_t **pluglist,
			     int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
#ifdef _SUN_SDK_
	utils->log(NULL, SASL_LOG_ERR, "CRAM version mismatch");
#else
	SETERROR( utils, "CRAM version mismatch");
#endif /* _SUN_SDK_ */
	return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = crammd5_server_plugins;
    *plugcount = 1;  
    
    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
    char *out_buf;
    unsigned out_buf_len;
#ifdef _INTEGRATED_SOLARIS_
    void *h;
#endif /* _INTEGRATED_SOLARIS_ */
} client_context_t;

static int crammd5_client_mech_new(void *glob_context __attribute__((unused)), 
				   sasl_client_params_t *params,
				   void **conn_context)
{
    client_context_t *text;
    
    /* holds state are in */
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(client_context_t));

    *conn_context = text;
    
    return SASL_OK;
}

static char *make_hashed(sasl_secret_t *sec, char *nonce, int noncelen, 
			 const sasl_utils_t *utils)
{
    char secret[65];
    unsigned char digest[24];  
    int lup;
    char *in16;
    
    if (sec == NULL) return NULL;
    
    if (sec->len < 64) {
	memcpy(secret, sec->data, sec->len);
	
	/* fill in rest with 0's */
	for (lup= sec->len; lup < 64; lup++)
	    secret[lup]='\0';
	
    } else {
	memcpy(secret, sec->data, 64);
    }
    
    /* do the hmac md5 hash output 128 bits */
    utils->hmac_md5((unsigned char *) nonce, noncelen,
		    (unsigned char *) secret, 64, digest);
    
    /* convert that to hex form */
    in16 = convert16(digest, 16, utils);
    if (in16 == NULL) return NULL;
    
    return in16;
}

static int crammd5_client_mech_step(void *conn_context,
				    sasl_client_params_t *params,
				    const char *serverin,
				    unsigned serverinlen,
				    sasl_interact_t **prompt_need,
				    const char **clientout,
				    unsigned *clientoutlen,
				    sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;
    const char *authid;
    sasl_secret_t *password = NULL;
    unsigned int free_password = 0; /* set if we need to free password */
    int auth_result = SASL_OK;
    int pass_result = SASL_OK;
    int result;
    int maxsize;
    char *in16 = NULL;

    *clientout = NULL;
    *clientoutlen = 0;
    
    /* First check for absurd lengths */
    if (serverinlen > 1024) {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "CRAM-MD5 input longer than 1024 bytes");
#else
	params->utils->seterror(params->utils->conn, 0,
				"CRAM-MD5 input longer than 1024 bytes");
#endif /* _SUN_SDK_ */
	return SASL_BADPROT;
    }
    
    /* check if sec layer strong enough */
    if (params->props.min_ssf > params->external_ssf) {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
		"SSF requested of CRAM-MD5 plugin");
#else
	SETERROR( params->utils, "SSF requested of CRAM-MD5 plugin");
#endif /* _SUN_SDK_ */
	return SASL_TOOWEAK;
    }
    
    /* try to get the userid */
    if (oparams->authid == NULL) {
	auth_result=_plug_get_authid(params->utils, &authid, prompt_need);
	
	if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
	    return auth_result;
    }
    
    /* try to get the password */
    if (password == NULL) {
	pass_result=_plug_get_password(params->utils, &password,
				       &free_password, prompt_need);
	
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	    return pass_result;
    }
    
    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }
    
    /* if there are prompts not filled in */
    if ((auth_result == SASL_INTERACT) || (pass_result == SASL_INTERACT)) {
	/* make the prompt list */
	result =
#ifdef _INTEGRATED_SOLARIS_
	    _plug_make_prompts(params->utils, &text->h, prompt_need,
			       NULL, NULL,
			       auth_result == SASL_INTERACT ?
			       convert_prompt(params->utils, &text->h,
			       gettext("Please enter your authentication name"))
					: NULL, NULL,
			       pass_result == SASL_INTERACT ?
			       convert_prompt(params->utils, &text->h,
					gettext("Please enter your password"))
					: NULL, NULL,
			       NULL, NULL, NULL,
			       NULL, NULL, NULL);
#else
	    _plug_make_prompts(params->utils, prompt_need,
			       NULL, NULL,
			       auth_result == SASL_INTERACT ?
			       "Please enter your authentication name" : NULL,
			       NULL,
			       pass_result == SASL_INTERACT ?
			       "Please enter your password" : NULL, NULL,
			       NULL, NULL, NULL,
			       NULL, NULL, NULL);
#endif /* _INTEGRATED_SOLARIS_ */
	if (result != SASL_OK) goto cleanup;
	
	return SASL_INTERACT;
    }
    
    if (!password) {
	PARAMERROR(params->utils);
	return SASL_BADPARAM;
    }
    
    result = params->canon_user(params->utils->conn, authid, 0,
				SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) goto cleanup;
    
    /*
     * username SP digest (keyed md5 where key is passwd)
     */
    
    in16 = make_hashed(password, (char *) serverin, serverinlen,
		       params->utils);
    
    if (in16 == NULL) {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "make_hashed failed");
#else
	SETERROR(params->utils, "whoops, make_hashed failed us this time");
#endif /* _SUN_SDK_ */
	result = SASL_FAIL;
	goto cleanup;
    }
    
    maxsize = 32+1+strlen(oparams->authid)+30;
    result = _plug_buf_alloc(params->utils, &(text->out_buf),
			     &(text->out_buf_len), maxsize);
    if (result != SASL_OK) goto cleanup;
    
    snprintf(text->out_buf, maxsize, "%s %s", oparams->authid, in16);
    
    *clientout = text->out_buf;
    *clientoutlen = strlen(*clientout);
    
    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;
    
    result = SASL_OK;

  cleanup:
    /* get rid of private information */
    if (in16) _plug_free_string(params->utils, &in16);
    
    /* get rid of all sensitive info */
    if (free_password) _plug_free_secret(params-> utils, &password);

    return result;
}

static void crammd5_client_mech_dispose(void *conn_context,
					const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    if (!text) return;
    
#ifdef _INTEGRATED_SOLARIS_
    convert_prompt(utils, &text->h, NULL);
#endif /* _INTEGRATED_SOLARIS_ */
    if (text->out_buf) utils->free(text->out_buf);
    
    utils->free(text);
}

static sasl_client_plug_t crammd5_client_plugins[] = 
{
    {
	"CRAM-MD5",			/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_SERVER_FIRST,		/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&crammd5_client_mech_new,	/* mech_new */
	&crammd5_client_mech_step,	/* mech_step */
	&crammd5_client_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int crammd5_client_plug_init(const sasl_utils_t *utils,
			     int maxversion,
			     int *out_version,
			     sasl_client_plug_t **pluglist,
			     int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
#ifdef _SUN_SDK_
	utils->log(NULL, SASL_LOG_ERR, "CRAM version mismatch");
#else
	SETERROR( utils, "CRAM version mismatch");
#endif /* _SUN_SDK_ */
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = crammd5_client_plugins;
    *plugcount = 1;
    
    return SASL_OK;
}
