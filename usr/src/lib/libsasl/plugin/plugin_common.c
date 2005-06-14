/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Generic SASL plugin utility functions
 * Rob Siemborski
 * $Id: plugin_common.c,v 1.13 2003/02/13 19:56:05 rjs3 Exp $
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
#ifndef macintosh
#ifdef WIN32
# include <winsock.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /* WIN32 */
#endif /* macintosh */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#include <errno.h>
#include <ctype.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "plugin_common.h"

/* translate IPv4 mapped IPv6 address to IPv4 address */
static void sockaddr_unmapped(
#ifdef IN6_IS_ADDR_V4MAPPED
  struct sockaddr *sa, socklen_t *len
#else
  struct sockaddr *sa __attribute__((unused)),
  socklen_t *len __attribute__((unused))
#endif
)
{
#ifdef IN6_IS_ADDR_V4MAPPED
    struct sockaddr_in6 *sin6;
    struct sockaddr_in *sin4;
    uint32_t addr;
#ifdef _SUN_SDK_
    in_port_t port;
#else
    int port;
#endif /* _SUN_SDK_ */

    if (sa->sa_family != AF_INET6)
	return;
/* LINTED pointer alignment */ 
    sin6 = (struct sockaddr_in6 *)sa;
    if (!IN6_IS_ADDR_V4MAPPED((&sin6->sin6_addr)))
	return;
/* LINTED pointer alignment */ 
    sin4 = (struct sockaddr_in *)sa;
/* LINTED pointer alignment */ 
    addr = *(uint32_t *)&sin6->sin6_addr.s6_addr[12];
    port = sin6->sin6_port;
    memset(sin4, 0, sizeof(struct sockaddr_in));
    sin4->sin_addr.s_addr = addr;
    sin4->sin_port = port;
    sin4->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
    sin4->sin_len = sizeof(struct sockaddr_in);
#endif
    *len = sizeof(struct sockaddr_in);
#else
    return;
#endif
}

int _plug_ipfromstring(const sasl_utils_t *utils, const char *addr,
		       struct sockaddr *out, socklen_t outlen) 
{
    int i, j;
    socklen_t len;
#ifdef WINNT /* _SUN_SDK_ */
    struct sockaddr_in ss;
#else
    struct sockaddr_storage ss;
#endif	/* _SUN_SDK_ */
    struct addrinfo hints, *ai = NULL;
    char hbuf[NI_MAXHOST];
#ifdef _SUN_SDK_
    const char *start, *end, *p;
#endif	/* _SUN_SDK_ */
    
    if(!utils || !addr || !out) {
	if(utils) PARAMERROR( utils );
	return SASL_BADPARAM;
    }

#ifdef _SUN_SDK_
    end = strchr(addr, ']');
    if (end != NULL) {
	/* This an rfc 2732 ipv6 address */
	start = strchr(addr, '[');
	if (start >= end || start == NULL) {
	    if(utils) PARAMERROR( utils );
	    return SASL_BADPARAM;
	}
	for (i = 0, p = start + 1; p < end; p++) {
	    hbuf[i++] = *p;
	    if (i >= NI_MAXHOST)
		break;
	}
	p = strchr(end, ':');
	if (p == NULL)
		p = end + 1;
	else
		p = p + 1;
    } else {
	for (i = 0; addr[i] != '\0' && addr[i] != ';'; ) {
	    hbuf[i] = addr[i];
	    if (++i >= NI_MAXHOST)
		break;
	}
	if (addr[i] == ';')
	     p = &addr[i+1];
	else
	     p = &addr[i];
    }
    if (i >= NI_MAXHOST) {
	if(utils) PARAMERROR( utils );
	return SASL_BADPARAM;
    }
    hbuf[i] = '\0';
    for (j = 0; p[j] != '\0'; j++)
	if (!isdigit((int)(p[j]))) {
	    PARAMERROR( utils );
	    return SASL_BADPARAM;
	}
#else
    /* Parse the address */
    for (i = 0; addr[i] != '\0' && addr[i] != ';'; i++) {
	if (i >= NI_MAXHOST) {
	    if(utils) PARAMERROR( utils );
	    return SASL_BADPARAM;
	}
	hbuf[i] = addr[i];
    }
    hbuf[i] = '\0';

    if (addr[i] == ';')
	i++;
    /* XXX/FIXME: Do we need this check? */
    for (j = i; addr[j] != '\0'; j++)
	if (!isdigit((int)(addr[j]))) {
	    PARAMERROR( utils );
	    return SASL_BADPARAM;
	}
#endif /* _SUN_SDK_ */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

#ifdef _SUN_SDK_
    if (getaddrinfo(hbuf, p, &hints, &ai) != 0) {	
#else
    if (getaddrinfo(hbuf, &addr[i], &hints, &ai) != 0) {	
#endif /* _SUN_SDK_ */
	PARAMERROR( utils );
	return SASL_BADPARAM;
    }

    len = ai->ai_addrlen;
#ifdef _SUN_SDK_
    if (len > sizeof(ss))
	return (SASL_BUFOVER);
#endif /* _SUN_SDK_ */
    memcpy(&ss, ai->ai_addr, len);
    freeaddrinfo(ai);
    sockaddr_unmapped((struct sockaddr *)&ss, &len);
    if (outlen < len) {
	PARAMERROR( utils );
	return SASL_BUFOVER;
    }

    memcpy(out, &ss, len);

    return SASL_OK;
}

int _plug_iovec_to_buf(const sasl_utils_t *utils, const struct iovec *vec,
		       unsigned numiov, buffer_info_t **output) 
{
    unsigned i;
    int ret;
    buffer_info_t *out;
    char *pos;

    if(!utils || !vec || !output) {
	if(utils) PARAMERROR( utils );
	return SASL_BADPARAM;
    }
    
    if(!(*output)) {
	*output = utils->malloc(sizeof(buffer_info_t));
	if(!*output) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	memset(*output,0,sizeof(buffer_info_t));
    }

    out = *output;
    
    out->curlen = 0;
    for(i=0; i<numiov; i++)
	out->curlen += vec[i].iov_len;

    ret = _plug_buf_alloc(utils, &out->data, &out->reallen, out->curlen);

    if(ret != SASL_OK) {
	MEMERROR(utils);
	return SASL_NOMEM;
    }
    
    memset(out->data, 0, out->reallen);
    pos = out->data;
    
    for(i=0; i<numiov; i++) {
	memcpy(pos, vec[i].iov_base, vec[i].iov_len);
	pos += vec[i].iov_len;
    }

    return SASL_OK;
}

/* Basically a conditional call to realloc(), if we need more */
int _plug_buf_alloc(const sasl_utils_t *utils, char **rwbuf,
		    unsigned *curlen, unsigned newlen) 
{
    if(!utils || !rwbuf || !curlen) {
	PARAMERROR(utils);
	return SASL_BADPARAM;
    }

    if(!(*rwbuf)) {
	*rwbuf = utils->malloc(newlen);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
#ifdef _SUN_SDK_
	unsigned needed = 2*(*curlen);
#else
	size_t needed = 2*(*curlen);
#endif /* _SUN_SDK_ */

	while(needed < newlen)
	    needed *= 2;

	*rwbuf = utils->realloc(*rwbuf, needed);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
	*curlen = needed;
    } 

    return SASL_OK;
}

/* copy a string */
int _plug_strdup(const sasl_utils_t * utils, const char *in,
		 char **out, int *outlen)
{
#ifdef _SUN_SDK_
  int len;
#else
  size_t len = strlen(in);
#endif /* _SUN_SDK_ */

  if(!utils || !in || !out) {
      if(utils) PARAMERROR(utils);
      return SASL_BADPARAM;
  }

#ifdef _SUN_SDK_
  len = strlen(in);
#endif /* _SUN_SDK_ */
  *out = utils->malloc(len + 1);
  if (!*out) {
      MEMERROR(utils);
      return SASL_NOMEM;
  }

  strcpy((char *) *out, in);

  if (outlen)
      *outlen = len;

  return SASL_OK;
}

void _plug_free_string(const sasl_utils_t *utils, char **str)
{
  size_t len;

  if (!utils || !str || !(*str)) return;

  len = strlen(*str);

  utils->erasebuffer(*str, len);
  utils->free(*str);

  *str=NULL;
}

void _plug_free_secret(const sasl_utils_t *utils, sasl_secret_t **secret) 
{
    if(!utils || !secret || !(*secret)) return;

#ifdef _SUN_SDK_
    utils->erasebuffer((char *)(*secret)->data, (*secret)->len);
#else
    utils->erasebuffer((*secret)->data, (*secret)->len);
#endif /* _SUN_SDK_ */
    utils->free(*secret);
    *secret = NULL;
}

/* 
 * Trys to find the prompt with the lookingfor id in the prompt list
 * Returns it if found. NULL otherwise
 */
sasl_interact_t *_plug_find_prompt(sasl_interact_t **promptlist,
				   unsigned int lookingfor)
{
    sasl_interact_t *prompt;

    if (promptlist && *promptlist) {
	for (prompt = *promptlist; prompt->id != SASL_CB_LIST_END; ++prompt) {
	    if (prompt->id==lookingfor)
		return prompt;
	}
    }

    return NULL;
}

/*
 * Retrieve the simple string given by the callback id.
 */
int _plug_get_simple(const sasl_utils_t *utils, unsigned int id, int required,
		     const char **result, sasl_interact_t **prompt_need)
{

    int ret = SASL_FAIL;
    sasl_getsimple_t *simple_cb;
    void *simple_context;
    sasl_interact_t *prompt;

    *result = NULL;

    /* see if we were given the result in the prompt */
    prompt = _plug_find_prompt(prompt_need, id);
    if (prompt != NULL) {
	/* We prompted, and got.*/
	
	if (required && !prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}

	*result = prompt->result;
	return SASL_OK;
    }
  
    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, id, &simple_cb, &simple_context);

    if (ret == SASL_FAIL && !required)
	return SASL_OK;

    if (ret == SASL_OK && simple_cb) {
	ret = simple_cb(simple_context, id, result, NULL);
	if (ret != SASL_OK)
	    return ret;

	if (required && !*result) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }
  
    return ret;
}

/*
 * Retrieve the user password.
 */
int _plug_get_password(const sasl_utils_t *utils, sasl_secret_t **password,
		       unsigned int *iscopy, sasl_interact_t **prompt_need)
{
    int ret = SASL_FAIL;
    sasl_getsecret_t *pass_cb;
    void *pass_context;
    sasl_interact_t *prompt;

    *password = NULL;
    *iscopy = 0;

    /* see if we were given the password in the prompt */
    prompt = _plug_find_prompt(prompt_need, SASL_CB_PASS);
    if (prompt != NULL) {
	/* We prompted, and got.*/
	
	if (!prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}
      
	/* copy what we got into a secret_t */
	*password = (sasl_secret_t *) utils->malloc(sizeof(sasl_secret_t) +
						    prompt->len + 1);
	if (!*password) {
	    MEMERROR(utils);
	    return SASL_NOMEM;
	}
      
	(*password)->len=prompt->len;
	memcpy((*password)->data, prompt->result, prompt->len);
	(*password)->data[(*password)->len]=0;

	*iscopy = 1;

	return SASL_OK;
    }

    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, SASL_CB_PASS,
			     &pass_cb, &pass_context);

    if (ret == SASL_OK && pass_cb) {
	ret = pass_cb(utils->conn, pass_context, SASL_CB_PASS, password);
	if (ret != SASL_OK)
	    return ret;

	if (!*password) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }

    return ret;
}

/*
 * Retrieve the string given by the challenge prompt id.
 */
int _plug_challenge_prompt(const sasl_utils_t *utils, unsigned int id,
			   const char *challenge, const char *promptstr,
			   const char **result, sasl_interact_t **prompt_need)
{
    int ret = SASL_FAIL;
    sasl_chalprompt_t *chalprompt_cb;
    void *chalprompt_context;
    sasl_interact_t *prompt;

    *result = NULL;

    /* see if we were given the password in the prompt */
    prompt = _plug_find_prompt(prompt_need, id);
    if (prompt != NULL) {
	/* We prompted, and got.*/
	
	if (!prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}
      
	*result = prompt->result;
	return SASL_OK;
    }

    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, id,
			     &chalprompt_cb, &chalprompt_context);

    if (ret == SASL_OK && chalprompt_cb) {
	ret = chalprompt_cb(chalprompt_context, id,
			    challenge, promptstr, NULL, result, NULL);
	if (ret != SASL_OK)
	    return ret;

	if (!*result) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }

    return ret;
}

/*
 * Retrieve the client realm.
 */
int _plug_get_realm(const sasl_utils_t *utils, const char **availrealms,
		    const char **realm, sasl_interact_t **prompt_need)
{
    int ret = SASL_FAIL;
    sasl_getrealm_t *realm_cb;
    void *realm_context;
    sasl_interact_t *prompt;

    *realm = NULL;

    /* see if we were given the result in the prompt */
    prompt = _plug_find_prompt(prompt_need, SASL_CB_GETREALM);
    if (prompt != NULL) {
	/* We prompted, and got.*/
	
	if (!prompt->result) {
	    SETERROR(utils, "Unexpectedly missing a prompt result");
	    return SASL_BADPARAM;
	}

	*realm = prompt->result;
	return SASL_OK;
    }

    /* Try to get the callback... */
    ret = utils->getcallback(utils->conn, SASL_CB_GETREALM,
			     &realm_cb, &realm_context);

    if (ret == SASL_OK && realm_cb) {
	ret = realm_cb(realm_context, SASL_CB_GETREALM, availrealms, realm);
	if (ret != SASL_OK)
	    return ret;

	if (!*realm) {
	    PARAMERROR(utils);
	    return SASL_BADPARAM;
	}
    }
  
    return ret;
}

/*
 * Make the requested prompts. (prompt==NULL means we don't want it)
 */
int _plug_make_prompts(const sasl_utils_t *utils,
#ifdef _INTEGRATED_SOLARIS_
		      void **h,
#endif /* _INTEGRATED_SOLARIS_ */
		       sasl_interact_t **prompts_res,
		       const char *user_prompt, const char *user_def,
		       const char *auth_prompt, const char *auth_def,
		       const char *pass_prompt, const char *pass_def,
		       const char *echo_chal,
		       const char *echo_prompt, const char *echo_def,
		       const char *realm_chal,
		       const char *realm_prompt, const char *realm_def)
{
    int num = 1;
    int alloc_size;
    sasl_interact_t *prompts;

    if (user_prompt) num++;
    if (auth_prompt) num++;
    if (pass_prompt) num++;
    if (echo_prompt) num++;
    if (realm_prompt) num++;

    if (num == 1) {
	SETERROR( utils, "make_prompts() called with no actual prompts" );
	return SASL_FAIL;
    }

    alloc_size = sizeof(sasl_interact_t)*num;
    prompts = utils->malloc(alloc_size);
    if (!prompts) {
	MEMERROR( utils );
	return SASL_NOMEM;
    }
    memset(prompts, 0, alloc_size);
  
    *prompts_res = prompts;

    if (user_prompt) {
	(prompts)->id = SASL_CB_USER;
#ifdef _INTEGRATED_SOLARIS_
	(prompts)->challenge = convert_prompt(utils, h,
		gettext("Authorization Name"));
#else
	(prompts)->challenge = "Authorization Name";
#endif /* _INTEGRATED_SOLARIS_ */
	(prompts)->prompt = user_prompt;
	(prompts)->defresult = user_def;

	prompts++;
    }

    if (auth_prompt) {
	(prompts)->id = SASL_CB_AUTHNAME;
#ifdef _INTEGRATED_SOLARIS_
	(prompts)->challenge = convert_prompt(utils, h,
		gettext( "Authentication Name"));
#else
	(prompts)->challenge = "Authentication Name";
#endif /* _INTEGRATED_SOLARIS_ */
	(prompts)->prompt = auth_prompt;
	(prompts)->defresult = auth_def;

	prompts++;
    }

    if (pass_prompt) {
	(prompts)->id = SASL_CB_PASS;
#ifdef _INTEGRATED_SOLARIS_
	(prompts)->challenge = convert_prompt(utils, h, gettext("Password"));
#else
	(prompts)->challenge = "Password";
#endif /* _INTEGRATED_SOLARIS_ */
	(prompts)->prompt = pass_prompt;
	(prompts)->defresult = pass_def;

	prompts++;
    }

    if (echo_prompt) {
	(prompts)->id = SASL_CB_ECHOPROMPT;
	(prompts)->challenge = echo_chal;
	(prompts)->prompt = echo_prompt;
	(prompts)->defresult = echo_def;

	prompts++;
    }

    if (realm_prompt) {
	(prompts)->id = SASL_CB_GETREALM;
	(prompts)->challenge = realm_chal;
	(prompts)->prompt = realm_prompt;
	(prompts)->defresult = realm_def;

	prompts++;
    }

    /* add the ending one */
    (prompts)->id = SASL_CB_LIST_END;
    (prompts)->challenge = NULL;
    (prompts)->prompt = NULL;
    (prompts)->defresult = NULL;

    return SASL_OK;
}

/*
 * Decode and concatenate multiple packets using the given function
 * to decode each packet.
 */
int _plug_decode(const sasl_utils_t *utils,
		 void *context,
		 const char *input, unsigned inputlen,
		 char **output,		/* output buffer */
		 unsigned *outputsize,	/* current size of output buffer */
		 unsigned *outputlen,	/* length of data in output buffer */
		 int (*decode_pkt)(void *context,
				   const char **input, unsigned *inputlen,
				   char **output, unsigned *outputlen))
{
    char *tmp = NULL;
    unsigned tmplen = 0;
    int ret;
    
    *outputlen = 0;

    while (inputlen!=0)
    {
	/* no need to free tmp */
      ret = decode_pkt(context, &input, &inputlen, &tmp, &tmplen);

      if(ret != SASL_OK) return ret;

      if (tmp!=NULL) /* if received 2 packets merge them together */
      {
	  ret = _plug_buf_alloc(utils, output, outputsize,
				*outputlen + tmplen + 1);
	  if(ret != SASL_OK) return ret;

	  memcpy(*output + *outputlen, tmp, tmplen);

	  /* Protect stupid clients */
	  *(*output + *outputlen + tmplen) = '\0';

	  *outputlen+=tmplen;
      }
    }

    return SASL_OK;    
}

/* returns the realm we should pretend to be in */
int _plug_parseuser(const sasl_utils_t *utils,
		    char **user, char **realm, const char *user_realm, 
		    const char *serverFQDN, const char *input)
{
    int ret;
#ifdef _SUN_SDK_
    const char *r;
#else
    char *r;
#endif /* _SUN_SDK_ */

    if(!user || !serverFQDN) {
	PARAMERROR( utils );
	return SASL_BADPARAM;
    }

    r = strchr(input, '@');
    if (!r) {
	/* hmmm, the user didn't specify a realm */
	if(user_realm && user_realm[0]) {
	    ret = _plug_strdup(utils, user_realm, realm, NULL);
	} else {
	    /* Default to serverFQDN */
	    ret = _plug_strdup(utils, serverFQDN, realm, NULL);
	}
	
	if (ret == SASL_OK) {
	    ret = _plug_strdup(utils, input, user, NULL);
	}
    } else {
	r++;
	ret = _plug_strdup(utils, r, realm, NULL);
#ifdef _SUN_SDK_
	if (ret == SASL_OK) {
	    *user = utils->malloc(r - input);
	    if (*user) {
		memcpy(*user, input, r - input - 1);
		(*user)[r - input - 1] = '\0';
	    } else {
		MEMERROR( utils );
		ret = SASL_NOMEM;
	    }
	}
#else
	*--r = '\0';
	*user = utils->malloc(r - input + 1);
	if (*user) {
	    strncpy(*user, input, r - input +1);
	} else {
	    MEMERROR( utils );
	    ret = SASL_NOMEM;
	}
	*r = '@';
#endif /* _SUN_SDK_ */
    }

    return ret;
}

#ifdef _INTEGRATED_SOLARIS_
int
use_locale(const char *lang_list, int is_client)
{
    const char *s;
    const char *begin;
    const char *end;
    const char *i_default = "i-default";
    const int i_default_len = 9;

    if (lang_list == NULL)
	return is_client;

    begin = lang_list;

    for (;;) {
	/* skip over leading whitespace and commas */
	while (isspace(*begin) || *begin == ',')
	    begin++;
	if (*begin == '\0')
	    break;

	/* Find the end of the language tag */
	for (end = begin; end[1] != ',' && end[1] != '\0'; end++) {}

	for (s = end; isspace(*s); s--) {}

	if (s == begin && *begin == '*')
	    return 1;

	if (s - begin == (i_default_len - 1) &&
		strncasecmp(begin, i_default, i_default_len) == 0)
	    return 0;

	begin = end + 1;
    }

    return is_client;
}

typedef struct prompt_list {
    char *prompt;
    struct prompt_list *next;
} prompt_list;

const char *
convert_prompt(const sasl_utils_t *utils, void **h, const char *s)
{
    sasl_getsimple_t *simple_cb;
    void *simple_context;
    const char *result = NULL;
    const char *s_locale;
    int ret;
    char *buf;
    const char *ret_buf;
    prompt_list *list;
    prompt_list *next;

    if (utils == NULL || utils->conn == NULL)
	return s;

    if (s == NULL) {
	for (list = (prompt_list *)*h; list != NULL; list = next) {
	    if (list->prompt)
		utils->free(list->prompt);
	    next = list->next;
	    utils->free(list);
	}
	*h = NULL;
	return NULL;
    }

    ret = utils->getcallback(utils->conn, SASL_CB_LANGUAGE, &simple_cb,
	&simple_context);

    if (ret == SASL_OK && simple_cb) {
	ret = simple_cb(simple_context, SASL_CB_LANGUAGE, &result, NULL);
    } else
	ret = SASL_FAIL;
    if (ret == SASL_OK && !use_locale(result, 1))
	return s;
    
    s_locale = dgettext(TEXT_DOMAIN, s);
    if (s == s_locale) {
	return s;
    }

    buf = local_to_utf(utils, s_locale);

    if (buf != NULL) {
	list = utils->malloc(sizeof (prompt_list));
	if (list == NULL) {
	    utils->free(buf);
	    buf = NULL;
	} else {
	    list->prompt = buf;
	    list->next = *h;
	    *h = list;
	}
    }

    ret_buf = (buf == NULL) ? s : buf;

    return ret_buf;
}

#include <iconv.h>
#include <langinfo.h>

/*
 * local_to_utf converts a string in the current codeset to utf-8.
 * If no codeset is specified, then codeset 646 will be used.
 * Upon successful completion, this function will return a non-NULL buffer
 * that is allocated by local_to_utf.
 *
 * If utils is NULL, local_to_utf will use the standard memory allocation
 * functions, otherwise the memory functions defined in sasl_utils_t will
 * be used.
 *
 * local_to_utf will return NULL in the case of any error
 */
char *
local_to_utf(const sasl_utils_t *utils, const char *s)
{
	const char *code_set = nl_langinfo(CODESET);
	iconv_t cd;
	char *buf, *tmp;
	size_t in_len;
	size_t buf_size;
	size_t ileft, oleft;
	const char *inptr;
	char *outptr;
	size_t ret;

	if (s == NULL)
	    return NULL;

	if (code_set == NULL)
	    code_set = "646";

	if (strcasecmp(code_set, "UTF-8") == 0) {
	    if (utils == NULL)
		buf = strdup(s);
	    else {
		if (_plug_strdup(utils, s, &buf, NULL) != SASL_OK)
			buf = NULL;
	    }
	    return buf;
	}
	cd = iconv_open("UTF-8", code_set);
	if (cd == (iconv_t)-1)
	    return NULL;

	in_len = strlen(s);
	buf_size = 4 * (in_len + 1);	/* guess */

	if (utils == NULL)
	    buf = malloc(buf_size);
	else
	    buf = utils->malloc(buf_size);

	if (buf == NULL) {
	    (void) iconv_close(cd);
	    return NULL;
	}
	inptr = s;
	ileft = in_len;
	outptr = buf;
	oleft = buf_size;
	for (;;) {
	    ret = iconv(cd, &inptr, &ileft, &outptr, &oleft);
	    if (ret == (size_t)(-1)) {
		if (errno == E2BIG) {
		    oleft += buf_size;
		    buf_size *= 2;
		    if (utils == NULL)
			tmp = realloc(buf, buf_size);
		    else
			tmp = utils->realloc(buf, buf_size);
		    if (tmp == NULL) {
			oleft = (size_t)(-1);
			break;
		    }
		    outptr = tmp + (outptr-buf);
		    buf = tmp;
		    continue;
		}
		oleft = (size_t)(-1);
		break;
	    }
	    if (inptr == NULL)
		break;
	    inptr = NULL;
	    ileft = 0;
	}
	if (oleft > 0) {
	    *outptr = '\0';
	} else if (oleft != (size_t)(-1)) {
	    if (utils == NULL)
		tmp = realloc(buf, buf_size + 1);
	    else
		tmp = utils->realloc(buf, buf_size + 1);
	    if (tmp == NULL) {
		oleft = (size_t)(-1);
	    } else {
		buf = tmp;
		buf[buf_size] = '\0';
	    }
	}
	if (oleft == (size_t)(-1)) {
	    if (utils == NULL)
		free(buf);
	    else
		utils->free(buf);
	    buf = NULL;
	}

	(void) iconv_close(cd);
	return buf;
}
#endif /* _INTEGRATED_SOLARIS_ */
