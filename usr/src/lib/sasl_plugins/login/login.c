/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/* LOGIN is a PLAIN-like authenticator, but for older deployments. */

/* Login SASL plugin
 * Rob Siemborski (SASLv2 Conversion)
 * contributed by Rainer Schoepf <schoepf@uni-mainz.de>
 * based on PLAIN, by Tim Martin <tmartin@andrew.cmu.edu>
 * $Id: login.c,v 1.25 2003/02/13 19:56:04 rjs3 Exp $
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
#include <stdio.h>
#include <ctype.h>
#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifndef _SUN_SDK_
#ifdef WIN32
/* This must be after sasl.h */
# include "saslLOGIN.h"
#endif /* WIN32 */
#endif /* !_SUN_SDK_ */

/*****************************  Common Section  *****************************/

#ifndef _SUN_SDK_
static const char plugin_id[] = "$Id: login.c,v 1.25 2003/02/13 19:56:04 rjs3 Exp $";
#endif /* !_SUN_SDK_ */

/*****************************  Server Section  *****************************/

typedef struct context {
    int state;

    char *username;
    size_t username_len;
} server_context_t;

static int login_server_mech_new(void *glob_context __attribute__((unused)),
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

#define USERNAME_CHALLENGE "Username:"
#define PASSWORD_CHALLENGE "Password:"

static int login_server_mech_step(void *conn_context,
				  sasl_server_params_t *params,
				  const char *clientin,
				  unsigned clientinlen,
				  const char **serverout,
				  unsigned *serveroutlen,
				  sasl_out_params_t *oparams)
{
    server_context_t *text = (server_context_t *) conn_context;

    *serverout = NULL;
    *serveroutlen = 0;

    switch (text->state) {

    case 1:
	text->state = 2;

	/* Check inlen, (possibly we have already the user name) */
	/* In this case fall through to state 2 */
	if (clientinlen == 0) {
	    /* demand username */

	    *serveroutlen = strlen(USERNAME_CHALLENGE);
	    *serverout = USERNAME_CHALLENGE;

	    return SASL_CONTINUE;
	}
	/* FALLTHROUGH */

    case 2:
	/* Catch really long usernames */
	if (clientinlen > 1024) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		"username too long (>1024 characters)");
#else
	    SETERROR(params->utils, "username too long (>1024 characters)");
#endif	/* _SUN_SDK_ */
	    return SASL_BADPROT;
	}

	/* get username */
	text->username =
	    params->utils->malloc(sizeof(sasl_secret_t) + clientinlen + 1);
	if (!text->username) {
	    MEMERROR( params->utils );
	    return SASL_NOMEM;
	}

	strncpy(text->username, clientin, clientinlen);
	text->username_len = clientinlen;
	text->username[clientinlen] = '\0';

	/* demand password */
	*serveroutlen = strlen(PASSWORD_CHALLENGE);
	*serverout = PASSWORD_CHALLENGE;

	text->state = 3;

	return SASL_CONTINUE;


    case 3: {
	sasl_secret_t *password;
	int result;

	/* Catch really long passwords */
	if (clientinlen > 1024) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		     "clientinlen is > 1024 characters in LOGIN plugin");
#else
	    SETERROR(params->utils,
		     "clientinlen is > 1024 characters in LOGIN plugin");
#endif	/* _SUN_SDK_ */
	    return SASL_BADPROT;
	}

	/* get password */
	password =
	    params->utils->malloc(sizeof(sasl_secret_t) + clientinlen + 1);
	if (!password) {
	    MEMERROR(params->utils);
	    return SASL_NOMEM;
	}

	strncpy((char *)password->data, clientin, clientinlen);
	password->data[clientinlen] = '\0';
	password->len = clientinlen;

	/* canonicalize username first, so that password verification is
	 * done against the canonical id */
	result = params->canon_user(params->utils->conn, text->username,
				    text->username_len,
				    SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK) {
		_plug_free_secret(params->utils, &password);
		return result;
	}

	/* verify_password - return sasl_ok on success */
	result = params->utils->checkpass(params->utils->conn,
					oparams->authid, oparams->alen,
					(char *)password->data, password->len);

	if (result != SASL_OK) {
	    _plug_free_secret(params->utils, &password);
	    return result;
	}

	if (params->transition) {
	    params->transition(params->utils->conn,
			       (char *)password->data, password->len);
	}

	_plug_free_secret(params->utils, &password);

	*serverout = NULL;
	*serveroutlen = 0;

	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->encode = NULL;
	oparams->decode_context = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;

	return SASL_OK;
    }


    default:
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid LOGIN server step %d\n", text->state);
	return SASL_FAIL;
    }

    return SASL_FAIL; /* should never get here */
}

static void login_server_mech_dispose(void *conn_context,
				      const sasl_utils_t *utils)
{
    server_context_t *text = (server_context_t *) conn_context;

    if (!text) return;

    if (text->username) utils->free(text->username);

    utils->free(text);
}

static sasl_server_plug_t login_server_plugins[] =
{
    {
	"LOGIN",			/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOANONYMOUS,		/* security_flags */
	0,				/* features */
	NULL,				/* glob_context */
	&login_server_mech_new,		/* mech_new */
	&login_server_mech_step,	/* mech_step */
	&login_server_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech_avail */
	NULL				/* spare */
    }
};

int login_server_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "LOGIN version mismatch");
	return SASL_BADVERS;
    }

    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = login_server_plugins;
    *plugcount = 1;

    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
    int state;

#ifdef _INTEGRATED_SOLARIS_
    void *h;
#endif /* _INTEGRATED_SOLARIS_ */
    sasl_secret_t *password;
    unsigned int free_password; /* set if we need to free password */
} client_context_t;

static int login_client_mech_new(void *glob_context __attribute__((unused)),
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

    text->state = 1;

    *conn_context = text;

    return SASL_OK;
}

static int login_client_mech_step(void *conn_context,
				  sasl_client_params_t *params,
				  const char *serverin __attribute__((unused)),
				  unsigned serverinlen __attribute__((unused)),
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;

    *clientout = NULL;
    *clientoutlen = 0;

    switch (text->state) {

    case 1: {
	const char *user;
	int auth_result = SASL_OK;
	int pass_result = SASL_OK;
	int result;

	/* check if sec layer strong enough */
	if (params->props.min_ssf > params->external_ssf) {
#ifdef _INTEGRATED_SOLARIS_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		gettext("SSF requested of LOGIN plugin"));
#else
	    SETERROR( params->utils, "SSF requested of LOGIN plugin");
#endif /* _INTEGRATED_SOLARIS_ */
	    return SASL_TOOWEAK;
	}

	/* try to get the userid */
	/* Note: we want to grab the authname and not the userid, which is
	 *       who we AUTHORIZE as, and will be the same as the authname
	 *       for the LOGIN mech.
	 */
	if (oparams->user == NULL) {
	    auth_result = _plug_get_authid(params->utils, &user, prompt_need);

	    if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
		return auth_result;
	}

	/* try to get the password */
	if (text->password == NULL) {
	    pass_result = _plug_get_password(params->utils, &text->password,
					     &text->free_password, prompt_need);

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
		    gettext("Please enter your authentication name") : NULL,
		    NULL,
		    pass_result == SASL_INTERACT ?
		    gettext("Please enter your password") : NULL, NULL,
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
	    if (result != SASL_OK) return result;

	    return SASL_INTERACT;
	}

	if (!text->password) {
	    PARAMERROR(params->utils);
	    return SASL_BADPARAM;
	}

	result = params->canon_user(params->utils->conn, user, 0,
				    SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK) return result;

	/* server should have sent request for username - we ignore it */
	if (!serverin) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		      "Server didn't issue challenge for USERNAME");
#else
	    SETERROR( params->utils,
		      "Server didn't issue challenge for USERNAME");
#endif /* _SUN_SDK_ */
	    return SASL_BADPROT;
	}

	if (!clientout) {
	    PARAMERROR( params->utils );
	    return SASL_BADPARAM;
	}

	if (clientoutlen) *clientoutlen = oparams->alen;
	*clientout = oparams->authid;

	text->state = 2;

	return SASL_CONTINUE;
    }

    case 2:
	/* server should have sent request for password - we ignore it */
	if (!serverin) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		      "Server didn't issue challenge for PASSWORD");
#else
	    SETERROR( params->utils,
		      "Server didn't issue challenge for PASSWORD");
#endif /* _SUN_SDK_ */
	    return SASL_BADPROT;
	}

	if (!clientout) {
	    PARAMERROR(params->utils);
	    return SASL_BADPARAM;
	}

	if (clientoutlen) *clientoutlen = text->password->len;
	*clientout = (char *)text->password->data;

	/* set oparams */
	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->encode = NULL;
	oparams->decode_context = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;

	return SASL_OK;

    default:
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid LOGIN client step %d\n", text->state);
	return SASL_FAIL;
    }

    return SASL_FAIL; /* should never get here */
}

static void login_client_mech_dispose(void *conn_context,
				      const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;

    if (!text) return;

    /* free sensitive info */
    if (text->free_password) _plug_free_secret(utils, &(text->password));
#ifdef _INTEGRATED_SOLARIS_
    convert_prompt(utils, &text->h, NULL);
#endif /* _INTEGRATED_SOLARIS_ */

    utils->free(text);
}

static sasl_client_plug_t login_client_plugins[] =
{
    {
	"LOGIN",			/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_SERVER_FIRST,		/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&login_client_mech_new,		/* mech_new */
	&login_client_mech_step,	/* mech_step */
	&login_client_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int login_client_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_client_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "Version mismatch in LOGIN");
	return SASL_BADVERS;
    }

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = login_client_plugins;
    *plugcount = 1;

    return SASL_OK;
}
