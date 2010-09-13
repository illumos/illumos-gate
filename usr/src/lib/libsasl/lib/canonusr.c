/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* canonusr.c - user canonicalization support
 * Rob Siemborski
 * $Id: canonusr.c,v 1.12 2003/02/13 19:55:53 rjs3 Exp $
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
#include <sasl.h>
#include <string.h>
#include <ctype.h>
#include <prop.h>
#include <stdio.h>

#include "saslint.h"

typedef struct canonuser_plug_list 
{
    struct canonuser_plug_list *next;
#ifdef _SUN_SDK_
    char *name;
#else
    char name[PATH_MAX];
#endif /* _SUN_SDK_ */
    const sasl_canonuser_plug_t *plug;
} canonuser_plug_list_t;

#ifndef _SUN_SDK_
static canonuser_plug_list_t *canonuser_head = NULL;
#endif /* !_SUN_SDK_ */

/* default behavior:
 *                   eliminate leading & trailing whitespace,
 *                   null-terminate, and get into the outparams
 *
 *                   (handled by INTERNAL plugin) */
/* Also does auxprop lookups once username is canonoicalized */
/* a zero ulen or alen indicates that it is strlen(value) */
int _sasl_canon_user(sasl_conn_t *conn,
                     const char *user, unsigned ulen,
                     unsigned flags,
                     sasl_out_params_t *oparams)
{
    canonuser_plug_list_t *ptr;
    sasl_server_conn_t *sconn = NULL;
    sasl_client_conn_t *cconn = NULL;
    sasl_canon_user_t *cuser_cb;
    sasl_getopt_t *getopt;
    void *context;
    int result;
    const char *plugin_name = NULL;
    char *user_buf;
    unsigned *lenp;

    if(!conn) return SASL_BADPARAM;    
    if(!user || !oparams) return SASL_BADPARAM;

    if(flags & SASL_CU_AUTHID) {
	user_buf = conn->authid_buf;
	lenp = &(oparams->alen);
    } else if (flags & SASL_CU_AUTHZID) {
	user_buf = conn->user_buf;
	lenp = &(oparams->ulen);
    } else {
	return SASL_BADPARAM;
    }
    
    if(conn->type == SASL_CONN_SERVER) sconn = (sasl_server_conn_t *)conn;
    else if(conn->type == SASL_CONN_CLIENT) cconn = (sasl_client_conn_t *)conn;
    else return SASL_FAIL;
    
    if(!ulen) ulen = (unsigned int)strlen(user);
    
    /* check to see if we have a callback to make*/
    result = _sasl_getcallback(conn, SASL_CB_CANON_USER,
			       &cuser_cb, &context);
    if(result == SASL_OK && cuser_cb) {
	result = cuser_cb(conn, context,
			user, ulen,
			flags, (conn->type == SASL_CONN_SERVER ?
				((sasl_server_conn_t *)conn)->user_realm :
				NULL),
			user_buf, CANON_BUF_SIZE, lenp);
	

	if (result != SASL_OK) return result;

	/* Point the input copy at the stored buffer */
	user = user_buf;
	ulen = *lenp;
    }

    /* which plugin are we supposed to use? */
    result = _sasl_getcallback(conn, SASL_CB_GETOPT,
			       &getopt, &context);
    if(result == SASL_OK && getopt) {
	getopt(context, NULL, "canon_user_plugin", &plugin_name, NULL);
    }

    if(!plugin_name) {
	/* Use Defualt */
	plugin_name = "INTERNAL";
    }
    
#ifdef _SUN_SDK_
    for(ptr = conn->gctx->canonuser_head; ptr; ptr = ptr->next) {
#else
    for(ptr = canonuser_head; ptr; ptr = ptr->next) {
#endif /* _SUN_SDK_ */
	/* A match is if we match the internal name of the plugin, or if
	 * we match the filename (old-style) */
	if((ptr->plug->name && !strcmp(plugin_name, ptr->plug->name))
	   || !strcmp(plugin_name, ptr->name)) break;
    }

    /* We clearly don't have this one! */
    if(!ptr) {
#ifdef _INTEGRATED_SOLARIS_
	if (conn->type == SASL_CONN_CLIENT)
		sasl_seterror(conn, 0,
		      gettext("desired canon_user plugin %s not found"),
		      plugin_name);
	else
		_sasl_log(conn, SASL_LOG_ERR,
		      "desired canon_user plugin %s not found",
		      plugin_name);
#else
	sasl_seterror(conn, 0, "desired canon_user plugin %s not found",
		      plugin_name);
#endif /* _INTEGRATED_SOLARIS_ */
	return SASL_NOMECH;
    }
    
    if(sconn) {
	/* we're a server */
	result = ptr->plug->canon_user_server(ptr->plug->glob_context,
					      sconn->sparams,
					      user, ulen,
					      flags,
					      user_buf,
					      CANON_BUF_SIZE, lenp);
    } else {
	/* we're a client */
	result = ptr->plug->canon_user_client(ptr->plug->glob_context,
					      cconn->cparams,
					      user, ulen,
					      flags,
					      user_buf,
					      CANON_BUF_SIZE, lenp);
    }

    if(result != SASL_OK) return result;

    if((flags & SASL_CU_AUTHID) && (flags & SASL_CU_AUTHZID)) {
	/* We did both, so we need to copy the result into
	 * the buffer for the authzid from the buffer for the authid */
	memcpy(conn->user_buf, conn->authid_buf, CANON_BUF_SIZE);
	oparams->ulen = oparams->alen;
    }
	
    /* Set the appropriate oparams (lengths have already been set by lenp) */
    if(flags & SASL_CU_AUTHID) {
	oparams->authid = conn->authid_buf;
    }

    if (flags & SASL_CU_AUTHZID) {
	oparams->user = conn->user_buf;
    }

#ifndef macintosh
    /* do auxprop lookups (server only) */
    if(sconn) {
	if(flags & SASL_CU_AUTHID) {
	    _sasl_auxprop_lookup(sconn->sparams, 0,
				 oparams->authid, oparams->alen);
	}
	if(flags & SASL_CU_AUTHZID) {
	    _sasl_auxprop_lookup(sconn->sparams, SASL_AUXPROP_AUTHZID,
				 oparams->user, oparams->ulen);
	}
    }
#endif


#ifdef _SUN_SDK_
    return (SASL_OK);
#else
    RETURN(conn, SASL_OK);
#endif /* _SUN_SDK_ */
}

#ifdef _SUN_SDK_
void _sasl_canonuser_free(_sasl_global_context_t *gctx)
{
    canonuser_plug_list_t *ptr, *ptr_next;
    const sasl_utils_t *sasl_global_utils = gctx->sasl_canonusr_global_utils;

    for(ptr = (canonuser_plug_list_t *)gctx->canonuser_head;
		ptr; ptr = ptr_next) {
	ptr_next = ptr->next;
	if(ptr->plug->canon_user_free)
	    ptr->plug->canon_user_free(ptr->plug->glob_context,
				       sasl_global_utils);
	sasl_FREE(ptr->name);
	sasl_FREE(ptr);
    }

    gctx->canonuser_head = NULL;
}
#else
void _sasl_canonuser_free() 
{
    canonuser_plug_list_t *ptr, *ptr_next;
    
    for(ptr = canonuser_head; ptr; ptr = ptr_next) {
	ptr_next = ptr->next;
	if(ptr->plug->canon_user_free)
	    ptr->plug->canon_user_free(ptr->plug->glob_context,
				       sasl_global_utils);
	sasl_FREE(ptr);
    }

    canonuser_head = NULL;
}
#endif /* _SUN_SDK_ */

#ifdef _SUN_SDK_
int sasl_canonuser_add_plugin(const char *plugname,
                              sasl_canonuser_init_t *canonuserfunc)
{
    return (_sasl_canonuser_add_plugin(_sasl_gbl_ctx(), plugname,
        canonuserfunc));
}

int _sasl_canonuser_add_plugin(void *ctx,
                               const char *plugname,
                               sasl_canonuser_init_t *canonuserfunc)
#else
int sasl_canonuser_add_plugin(const char *plugname,
			      sasl_canonuser_init_t *canonuserfunc) 
#endif /* _SUN_SDK_ */
{
    int result, out_version;
    canonuser_plug_list_t *new_item;
    sasl_canonuser_plug_t *plug;
#ifdef _SUN_SDK_
    _sasl_global_context_t *gctx = ctx == NULL ? _sasl_gbl_ctx() : ctx;
    const sasl_utils_t *sasl_global_utils;
    canonuser_plug_list_t *l;

  /* Check to see if this plugin has already been registered */
    for (l = gctx->canonuser_head; l != NULL; l = l->next) {
	if (strcmp(plugname, l->name) == 0) {
	    return SASL_OK;
	}
    }
    sasl_global_utils = gctx->sasl_canonusr_global_utils;
#endif /* _SUN_SDK_ */

    if(!plugname || strlen(plugname) > (PATH_MAX - 1)) {
	sasl_seterror(NULL, 0,
		      "bad plugname passed to sasl_canonuser_add_plugin\n");
	return SASL_BADPARAM;
    }
    
    result = canonuserfunc(sasl_global_utils, SASL_CANONUSER_PLUG_VERSION,
			   &out_version, &plug, plugname);

    if(result != SASL_OK) {
#ifdef _SUN_SDK_
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks == NULL ?
	    	   gctx->client_global_callbacks.callbacks :
	    	   gctx->server_global_callbacks.callbacks,
		   SASL_LOG_ERR, "canonuserfunc error %i\n",result);
#else
	_sasl_log(NULL, SASL_LOG_ERR, "canonuserfunc error %i\n",result);
#endif /* _SUN_SDK_ */
	return result;
    }

    if(!plug->canon_user_server && !plug->canon_user_client) {
	/* We need atleast one of these implemented */
#ifdef _SUN_SDK_
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks == NULL ?
	    	   gctx->client_global_callbacks.callbacks :
	    	   gctx->server_global_callbacks.callbacks, SASL_LOG_ERR,
		   "canonuser plugin without either client or server side");
#else
	_sasl_log(NULL, SASL_LOG_ERR,
		  "canonuser plugin without either client or server side");
#endif /* _SUN_SDK_ */
	return SASL_BADPROT;
    }
    
#ifdef _SUN_SDK_
    /* Check plugin to make sure name is non-NULL */
    if (plug->name == NULL) {
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks == NULL ?
	    	   gctx->client_global_callbacks.callbacks :
	    	   gctx->server_global_callbacks.callbacks,
		   SASL_LOG_ERR, "invalid canonusr plugin %s", plugname);
	return SASL_BADPROT;
    }
#endif /* _SUN_SDK_ */

    new_item = sasl_ALLOC(sizeof(canonuser_plug_list_t));
    if(!new_item) return SASL_NOMEM;

#ifdef _SUN_SDK_
    if(_sasl_strdup(plugname, &new_item->name, NULL) != SASL_OK) {
	sasl_FREE(new_item);
	return SASL_NOMEM;
    }
#else
    strncpy(new_item->name, plugname, PATH_MAX);
#endif /* _SUN_SDK_ */

    new_item->plug = plug;
#ifdef _SUN_SDK_
    new_item->next = gctx->canonuser_head;
    gctx->canonuser_head = new_item;
#else
    new_item->next = canonuser_head;
    canonuser_head = new_item;
#endif /* _SUN_SDK_ */

    return SASL_OK;
}

#ifdef MIN
#undef MIN
#endif
#define MIN(a,b) (((a) < (b))? (a):(b))

static int _canonuser_internal(const sasl_utils_t *utils,
			       const char *user, unsigned ulen,
			       unsigned flags __attribute__((unused)),
			       char *out_user,
			       unsigned out_umax, unsigned *out_ulen) 
{
    unsigned i;
    char *in_buf, *userin;
    const char *begin_u;
    unsigned u_apprealm = 0;
    sasl_server_conn_t *sconn = NULL;

    if(!utils || !user) return SASL_BADPARAM;

#ifdef _SUN_SDK_
    in_buf = utils->malloc((ulen + 2) * sizeof(char));
#else
    in_buf = sasl_ALLOC((ulen + 2) * sizeof(char));
#endif /* _SUN_SDK_ */
    if(!in_buf) return SASL_NOMEM;

    userin = in_buf;

    memcpy(userin, user, ulen);
    userin[ulen] = '\0';
    
    /* Strip User ID */
    for(i=0;isspace((int)userin[i]) && i<ulen;i++);
    begin_u = &(userin[i]);
    if(i>0) ulen -= i;

    for(;ulen > 0 && isspace((int)begin_u[ulen-1]); ulen--);
    if(begin_u == &(userin[ulen])) {
#ifdef _SUN_SDK_
	utils->free(in_buf);
#else
	sasl_FREE(in_buf);
#endif /* _SUN_SDK_ */
#ifdef _INTEGRATED_SOLARIS_
	utils->seterror(utils->conn, 0, gettext("All-whitespace username."));
#else
	utils->seterror(utils->conn, 0, "All-whitespace username.");
#endif /* _INTEGRATED_SOLARIS_ */
	return SASL_FAIL;
    }

    if(utils->conn && utils->conn->type == SASL_CONN_SERVER)
	sconn = (sasl_server_conn_t *)utils->conn;

    /* Need to append realm if necessary (see sasl.h) */
    if(sconn && sconn->user_realm && !strchr(user, '@')) {
	u_apprealm = strlen(sconn->user_realm) + 1;
    }
    
    /* Now Copy */
    memcpy(out_user, begin_u, MIN(ulen, out_umax));
    if(sconn && u_apprealm) {
	if(ulen >= out_umax) return SASL_BUFOVER;
	out_user[ulen] = '@';
	memcpy(&(out_user[ulen+1]), sconn->user_realm,
	       MIN(u_apprealm-1, out_umax-ulen-1));
    }
    out_user[MIN(ulen + u_apprealm,out_umax)] = '\0';

    if(ulen + u_apprealm > out_umax) return SASL_BUFOVER;

    if(out_ulen) *out_ulen = MIN(ulen + u_apprealm,out_umax);
    
#ifdef _SUN_SDK_
    utils->free(in_buf);
#else
    sasl_FREE(in_buf);
#endif /* _SUN_SDK_ */
    return SASL_OK;
}

static int _cu_internal_server(void *glob_context __attribute__((unused)),
			       sasl_server_params_t *sparams,
			       const char *user, unsigned ulen,
			       unsigned flags,
			       char *out_user,
			       unsigned out_umax, unsigned *out_ulen) 
{
    return _canonuser_internal(sparams->utils,
			       user, ulen,
			       flags, out_user, out_umax, out_ulen);
}

static int _cu_internal_client(void *glob_context __attribute__((unused)),
			       sasl_client_params_t *cparams,
			       const char *user, unsigned ulen,
			       unsigned flags,
			       char *out_user,
			       unsigned out_umax, unsigned *out_ulen) 
{
    return _canonuser_internal(cparams->utils,
			       user, ulen,
			       flags, out_user, out_umax, out_ulen);
}

static sasl_canonuser_plug_t canonuser_internal_plugin = {
        0, /* features */
	0, /* spare */
	NULL, /* glob_context */
	"INTERNAL", /* name */
	NULL, /* canon_user_free */
	_cu_internal_server,
	_cu_internal_client,
	NULL,
	NULL,
	NULL
};

int internal_canonuser_init(const sasl_utils_t *utils __attribute__((unused)),
                            int max_version,
                            int *out_version,
                            sasl_canonuser_plug_t **plug,
                            const char *plugname __attribute__((unused))) 
{
    if(!out_version || !plug) return SASL_BADPARAM;

    if(max_version < SASL_CANONUSER_PLUG_VERSION) return SASL_BADVERS;
    
    *out_version = SASL_CANONUSER_PLUG_VERSION;

    *plug = &canonuser_internal_plugin;

    return SASL_OK;
}
