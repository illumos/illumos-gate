/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* SASL Config file API
 * Rob Siemborski
 * Tim Martin (originally in Cyrus distribution)
 * $Id: config.c,v 1.13 2003/02/13 19:55:54 rjs3 Exp $
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

/*
 * Current Valid keys:
 *
 * canon_user_plugin: <string>
 * pwcheck_method: <string>
 * auto_transition: <boolean>
 * plugin_list: <string>
 *
 * srvtab: <string>
 */


#include "sasl.h"
#include "saslint.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "config.h"	/* _SUN_SDK_ */

struct configlist {
    char *key;
    char *value;
};

#ifndef _SUN_SDK_
static struct configlist *configlist;
static int nconfiglist;
#endif /* !_SUN_SDK_ */

#define CONFIGLISTGROWSIZE 100

#ifdef _SUN_SDK_
int sasl_config_init(_sasl_global_context_t *gctx, const char *filename)
#else
int sasl_config_init(const char *filename)
#endif /* _SUN_SDK_ */
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *p, *key;
    int result;
#ifdef _SUN_SDK_
    int invalid_line = 0;

    gctx->nconfiglist=0;
#else
    nconfiglist=0;
#endif /* _SUN_SDK_ */

    infile = fopen(filename, "rF");
    if (!infile) {
      return SASL_CONTINUE;
    }
#ifdef _SUN_SDK_
    result = _sasl_strdup(filename, &gctx->config_path, NULL);
    if (result != SASL_OK)
	goto done;
#endif /* _SUN_SDK_ */
    
    while (fgets(buf, sizeof(buf), infile)) {
	lineno++;

	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace((int) *p); p++);
	if (!*p || *p == '#') continue;

	key = p;
	while (*p && (isalnum((int) *p) || *p == '-' || *p == '_')) {
	    if (isupper((int) *p)) *p = tolower(*p);
	    p++;
	}
	if (*p != ':') {
#ifdef _SUN_SDK_
	  invalid_line = 1;
	  goto done;
#else
	  return SASL_FAIL;
#endif /* _SUN_SDK_ */
	}
	*p++ = '\0';

	while (*p && isspace((int) *p)) p++;
	
	if (!*p) {
#ifdef _SUN_SDK_
	  invalid_line = 1;
	  goto done;
#else
	  return SASL_FAIL;
#endif /* _SUN_SDK_ */
	}

#ifdef _SUN_SDK_
	if (gctx->nconfiglist == alloced) {
#else
	if (nconfiglist == alloced) {
#endif /* _SUN_SDK_ */
	    alloced += CONFIGLISTGROWSIZE;
#ifdef _SUN_SDK_
	    gctx->configlist=sasl_REALLOC((char *)gctx->configlist, 
				    alloced * sizeof(struct configlist));
	    if (gctx->configlist==NULL) {
		result = SASL_NOMEM;
		goto done;
	    }
#else
	    configlist=sasl_REALLOC((char *)configlist, 
				    alloced * sizeof(struct configlist));
	    if (configlist==NULL) return SASL_NOMEM;
#endif /* _SUN_SDK_ */
	}



#ifdef _SUN_SDK_
	result = _sasl_strdup(key,
			      &(((struct configlist *)(gctx->configlist))
				[gctx->nconfiglist].key),
			      NULL);
	if (result!=SASL_OK)
	  goto done;
#else
	result = _sasl_strdup(key,
			      &(configlist[nconfiglist].key),
			      NULL);
	if (result!=SASL_OK) return result;
#endif /* _SUN_SDK_ */
#ifdef _SUN_SDK_
	result = _sasl_strdup(p,
			      &(((struct configlist *)(gctx->configlist))
				[gctx->nconfiglist].value),
			      NULL);
	if (result!=SASL_OK) {
	    sasl_FREE(((struct configlist *)(gctx->configlist))
				[gctx->nconfiglist].key);
	    goto done;
	}
#else
	result = _sasl_strdup(p,
			      &(configlist[nconfiglist].value),
			      NULL);
	if (result!=SASL_OK) return result;
#endif /* _SUN_SDK_ */

#ifdef _SUN_SDK_
	(gctx->nconfiglist)++;
#else
	nconfiglist++;
#endif /* _SUN_SDK_ */
    }
#ifdef _SUN_SDK_
    result = SASL_OK;

done:
    fclose(infile);

    if (invalid_line) {
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks,
		   SASL_LOG_ERR, "%s: bad config line: '%s'", filename, buf);
	result = SASL_FAIL;
    }

    return result;
#else
    fclose(infile);

    return SASL_OK;
#endif /* _SUN_SDK_ */
}

#ifdef _SUN_SDK_
/* Releases the resources acquired in sasl_config_init() */
void sasl_config_free(_sasl_global_context_t *gctx)
{
    int i;

    if (gctx->config_path != NULL)
	sasl_FREE(gctx->config_path);
    gctx->config_path = NULL;
    if (gctx->configlist == NULL)
	return;

    for (i = 0; i < gctx->nconfiglist; i++) {
	if ((((struct configlist *)gctx->configlist))[i].key)
	    sasl_FREE(((struct configlist *)gctx->configlist)[i].key);
	if (((struct configlist *)gctx->configlist)[i].value)
	    sasl_FREE(((struct configlist *)gctx->configlist)[i].value);
    }
    sasl_FREE(gctx->configlist);
    gctx->configlist = NULL;
    gctx->nconfiglist = 0;
}

const char *sasl_config_getstring(_sasl_global_context_t *gctx,
	const char *key, const char *def)
{
    int opt;
    struct configlist *clist = (struct configlist *)gctx->configlist;

    for (opt = 0; opt < gctx->nconfiglist; opt++) {
	if (*key == clist[opt].key[0] &&
	    !strcmp(key, clist[opt].key))
	  return clist[opt].value;
    }
    return def;
}
#else
const char *sasl_config_getstring(const char *key,const char *def)
{
    int opt;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (*key == configlist[opt].key[0] &&
	    !strcmp(key, configlist[opt].key))
	  return configlist[opt].value;
    }
    return def;
}
#endif /* _SUN_SDK_ */

#ifdef _SUN_SDK_
int sasl_config_getint(_sasl_global_context_t *gctx, const char *key,int def)
#else
int sasl_config_getint(const char *key,int def)
#endif /* _SUN_SDK_ */
{
#ifdef _SUN_SDK_
    const char *val = sasl_config_getstring(gctx, key, (char *)0);
#else
    const char *val = sasl_config_getstring(key, (char *)0);
#endif /* _SUN_SDK_ */

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return def;
    return atoi(val);
}

#ifdef _SUN_SDK_
int sasl_config_getswitch(_sasl_global_context_t *gctx,const char *key,int def)
#else
int sasl_config_getswitch(const char *key,int def)
#endif /* _SUN_SDK_ */
{
#ifdef _SUN_SDK_
    const char *val = sasl_config_getstring(gctx, key, (char *)0);
#else
    const char *val = sasl_config_getstring(key, (char *)0);
#endif /* _SUN_SDK_ */

    if (!val) return def;

    if (*val == '0' || *val == 'n' ||
	(*val == 'o' && val[1] == 'f') || *val == 'f') {
	return 0;
    }
    else if (*val == '1' || *val == 'y' ||
	     (*val == 'o' && val[1] == 'n') || *val == 't') {
	return 1;
    }
    return def;
}

