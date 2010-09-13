/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* auxprop.c - auxilliary property support
 * Rob Siemborski
 * $Id: auxprop.c,v 1.10 2003/03/19 18:25:27 rjs3 Exp $
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
#include <prop.h>
#include <ctype.h>
#include "saslint.h"

struct proppool 
{
    struct proppool *next;

    size_t size;          /* Size of Block */
    size_t unused;        /* Space unused in this pool between end
			   * of char** area and beginning of char* area */

    char data[1];         /* Variable Sized */
};

struct propctx  {
    struct propval *values;
    struct propval *prev_val; /* Previous value used by set/setvalues */

    unsigned used_values, allocated_values;

    char *data_end; /* Bottom of string area in current pool */
    char **list_end; /* Top of list area in current pool */

    struct proppool *mem_base;
    struct proppool *mem_cur;
};

typedef struct auxprop_plug_list 
{
    struct auxprop_plug_list *next;
    const sasl_auxprop_plug_t *plug;
#ifdef _SUN_SDK_
    char *plugname;
#endif /* _SUN_SDK_ */
} auxprop_plug_list_t;

#ifndef _SUN_SDK_
static auxprop_plug_list_t *auxprop_head = NULL;
#endif /* !_SUN_SDK_ */

static struct proppool *alloc_proppool(size_t size) 
{
    struct proppool *ret;
    /* minus 1 for the one that is already a part of the array
     * in the struct */
    size_t total_size = sizeof(struct proppool) + size - 1;
#ifdef _SUN_SDK_
    ret = sasl_sun_ALLOC(total_size);
#else
    ret = sasl_ALLOC(total_size);
#endif /* _SUN_SDK_*/
    if(!ret) return NULL;

    memset(ret, 0, total_size);

    ret->size = ret->unused = size;

    return ret;
}

/* Resize a proppool.  Invalidates the unused value for this pool */
static struct proppool *resize_proppool(struct proppool *pool, size_t size)
{
    struct proppool *ret;
    
    if(pool->size >= size) return pool;
#ifdef _SUN_SDK_
    ret = sasl_sun_REALLOC(pool, sizeof(struct proppool) + size);
#else
    ret = sasl_REALLOC(pool, sizeof(struct proppool) + size);
#endif /* _SUN_SDK_*/
    if(!ret) return NULL;

    ret->size = size;

    return ret;
}

static int prop_init(struct propctx *ctx, unsigned estimate) 
{
    const unsigned VALUES_SIZE = PROP_DEFAULT * sizeof(struct propval);

    ctx->mem_base = alloc_proppool(VALUES_SIZE + estimate);
    if(!ctx->mem_base) return SASL_NOMEM;

    ctx->mem_cur = ctx->mem_base;

    ctx->values = (struct propval *)ctx->mem_base->data;
    ctx->mem_base->unused = ctx->mem_base->size - VALUES_SIZE;
    ctx->allocated_values = PROP_DEFAULT;
    ctx->used_values = 0;

    ctx->data_end = ctx->mem_base->data + ctx->mem_base->size;
    ctx->list_end = (char **)(ctx->mem_base->data + VALUES_SIZE);

    ctx->prev_val = NULL;

    return SASL_OK;
}

/* create a property context
 *  estimate -- an estimate of the storage needed for requests & responses
 *              0 will use module default
 * returns NULL on error
 */
struct propctx *prop_new(unsigned estimate) 
{
    struct propctx *new_ctx;

    if(!estimate) estimate = PROP_DEFAULT * 255;

#ifdef _SUN_SDK_
    new_ctx = sasl_sun_ALLOC(sizeof(struct propctx));
#else
    new_ctx = sasl_ALLOC(sizeof(struct propctx));
#endif /* _SUN_SDK_*/
    if(!new_ctx) return NULL;

    if(prop_init(new_ctx, estimate) != SASL_OK) {
	prop_dispose(&new_ctx);
    }

    return new_ctx;
}

/* create new propctx which duplicates the contents of an existing propctx
 * returns -1 on error
 */
int prop_dup(struct propctx *src_ctx, struct propctx **dst_ctx) 
{
    struct proppool *pool;
    struct propctx *retval = NULL;
    unsigned i;
    int result;
    size_t total_size = 0, values_size;
    
    if(!src_ctx || !dst_ctx) return SASL_BADPARAM;

    /* What is the total allocated size of src_ctx? */
    pool = src_ctx->mem_base;
    while(pool) {
	total_size += pool->size;
	pool = pool->next;
    }

    /* allocate the new context */
    retval = prop_new(total_size);
    if(!retval) return SASL_NOMEM;

    retval->used_values = src_ctx->used_values;
    retval->allocated_values = src_ctx->used_values + 1;

    values_size = (retval->allocated_values * sizeof(struct propval));

    retval->mem_base->unused = retval->mem_base->size - values_size;

    retval->list_end = (char **)(retval->mem_base->data + values_size);
    /* data_end should still be OK */

    /* Now dup the values */
    for(i=0; i<src_ctx->used_values; i++) {
	retval->values[i].name = src_ctx->values[i].name;
	result = prop_setvals(retval, retval->values[i].name,
			      src_ctx->values[i].values);
	if(result != SASL_OK)
	    goto fail;
    }

    retval->prev_val = src_ctx->prev_val;

    *dst_ctx = retval;
    return SASL_OK;

    fail:
    if(retval) prop_dispose(&retval);
    return result;
}

/*
 * dispose of property context
 *  ctx      -- is disposed and set to NULL; noop if ctx or *ctx is NULL
 */
void prop_dispose(struct propctx **ctx)
{
    struct proppool *tmp;
    
    if(!ctx || !*ctx) return;

    while((*ctx)->mem_base) {
	tmp = (*ctx)->mem_base;
	(*ctx)->mem_base = tmp->next;
#ifdef _SUN_SDK_
        sasl_sun_FREE(tmp);
#else
	sasl_FREE(tmp);
#endif /* _SUN_SDK_*/
    }
    
#ifdef _SUN_SDK_
    sasl_sun_FREE(*ctx);
#else
    sasl_FREE(*ctx);
#endif /* _SUN_SDK_*/
    *ctx = NULL;

    return;
}

/* Add property names to request
 *  ctx       -- context from prop_new()
 *  names     -- list of property names; must persist until context freed
 *               or requests cleared
 *
 * NOTE: may clear values from context as side-effect
 * returns -1 on error
 */
int prop_request(struct propctx *ctx, const char **names) 
{
    unsigned i, new_values, total_values;

    if(!ctx || !names) return SASL_BADPARAM;

    /* Count how many we need to add */
    for(new_values=0; names[new_values]; new_values++);

    /* Do we need to add ANY? */
    if(!new_values) return SASL_OK;

    /* We always want atleast on extra to mark the end of the array */
    total_values = new_values + ctx->used_values + 1;

    /* Do we need to increase the size of our propval table? */
    if(total_values > ctx->allocated_values) {
	unsigned max_in_pool;

	/* Do we need a larger base pool? */
	max_in_pool = ctx->mem_base->size / sizeof(struct propval);
	
	if(total_values <= max_in_pool) {
	    /* Don't increase the size of the base pool, just use what
	       we need */
	    ctx->allocated_values = total_values;
	    ctx->mem_base->unused =
		ctx->mem_base->size - (sizeof(struct propval)
				       * ctx->allocated_values);
      	} else {
	    /* We need to allocate more! */
	    unsigned new_alloc_length;
	    size_t new_size;

	    new_alloc_length = 2 * ctx->allocated_values;
	    while(total_values > new_alloc_length) {
		new_alloc_length *= 2;
	    }

	    new_size = new_alloc_length * sizeof(struct propval);
	    ctx->mem_base = resize_proppool(ctx->mem_base, new_size);

	    if(!ctx->mem_base) {
		ctx->values = NULL;
		ctx->allocated_values = ctx->used_values = 0;
		return SASL_NOMEM;
	    }

	    /* It worked! Update the structure! */
	    ctx->values = (struct propval *)ctx->mem_base->data;
	    ctx->allocated_values = new_alloc_length;
	    ctx->mem_base->unused = ctx->mem_base->size
		- sizeof(struct propval) * ctx->allocated_values;
	}

	/* Clear out new propvals */
	memset(&(ctx->values[ctx->used_values]), 0,
	       sizeof(struct propval) * (ctx->allocated_values - ctx->used_values));

        /* Finish updating the context -- we've extended the list! */
	/* ctx->list_end = (char **)(ctx->values + ctx->allocated_values); */
	/* xxx test here */
	ctx->list_end = (char **)(ctx->values + total_values);
    }

    /* Now do the copy, or referencing rather */
    for(i=0;i<new_values;i++) {
	unsigned j, flag;

	flag = 0;

	/* Check for dups */
	for(j=0;j<ctx->used_values;j++) {
	    if(!strcmp(ctx->values[j].name, names[i])) {
		flag = 1;
		break;
	    }
	}

	/* We already have it... skip! */
	if(flag) continue;

	ctx->values[ctx->used_values++].name = names[i];
    }

    prop_clear(ctx, 0);

    return SASL_OK;
}

/* return array of struct propval from the context
 *  return value persists until next call to
 *   prop_request, prop_clear or prop_dispose on context
 */
const struct propval *prop_get(struct propctx *ctx) 
{
    if(!ctx) return NULL;
    
    return ctx->values;
}

/* Fill in an array of struct propval based on a list of property names
 *  return value persists until next call to
 *   prop_request, prop_clear or prop_dispose on context
 *  returns -1 on error (no properties ever requested, ctx NULL, etc)
 *  returns number of matching properties which were found (values != NULL)
 *  if a name requested here was never requested by a prop_request, then
 *  the name field of the associated vals entry will be set to NULL
 */
int prop_getnames(struct propctx *ctx, const char **names,
		  struct propval *vals) 
{
    int found_names = 0;
    
    struct propval *cur = vals;
    const char **curname;

    if(!ctx || !names || !vals) return SASL_BADPARAM;
    
    for(curname = names; *curname; curname++) {
	struct propval *val;
	for(val = ctx->values; val->name; val++) {
	    if(!strcmp(*curname,val->name)) { 
		found_names++;
		memcpy(cur, val, sizeof(struct propval));
		goto next;
	    }
	}

	/* If we are here, we didn't find it */
	memset(cur, 0, sizeof(struct propval));
	
	next:
	cur++;
    }

    return found_names;
}


/* clear values and optionally requests from property context
 *  ctx      -- property context
 *  requests -- 0 = don't clear requests, 1 = clear requests
 */
void prop_clear(struct propctx *ctx, int requests) 
{
    struct proppool *new_pool, *tmp;
    unsigned i;

#ifdef _SUN_SDK_
    if(!ctx) return;
#endif /* _SUN_SDK_ */

    /* We're going to need a new proppool once we reset things */
    new_pool = alloc_proppool(ctx->mem_base->size +
			      (ctx->used_values+1) * sizeof(struct propval));

    if(requests) {
	/* We're wiping the whole shebang */
	ctx->used_values = 0;
    } else {
	/* Need to keep around old requets */
	struct propval *new_values = (struct propval *)new_pool->data;
	for(i=0; i<ctx->used_values; i++) {
	    new_values[i].name = ctx->values[i].name;
	}
    }

    while(ctx->mem_base) {
	tmp = ctx->mem_base;
	ctx->mem_base = tmp->next;
#ifdef _SUN_SDK_
	sasl_sun_FREE(tmp);
#else
	sasl_FREE(tmp);
#endif /* _SUN_SDK_ */
    }
    
    /* Update allocation-related metadata */
    ctx->allocated_values = ctx->used_values+1;
    new_pool->unused =
	new_pool->size - (ctx->allocated_values * sizeof(struct propval));

    /* Setup pointers for the values array */
    ctx->values = (struct propval *)new_pool->data;
    ctx->prev_val = NULL;

    /* Setup the pools */
    ctx->mem_base = ctx->mem_cur = new_pool;

    /* Reset list_end and data_end for the new memory pool */
    ctx->list_end =
	(char **)((char *)ctx->mem_base->data + ctx->allocated_values * sizeof(struct propval));
    ctx->data_end = (char *)ctx->mem_base->data + ctx->mem_base->size;

    return;
}

/*
 * erase the value of a property
 */
void prop_erase(struct propctx *ctx, const char *name)
{
    struct propval *val;
    int i;

    if(!ctx || !name) return;

    for(val = ctx->values; val->name; val++) {
	if(!strcmp(name,val->name)) {
	    if(!val->values) break;

	    /*
	     * Yes, this is casting away the const, but
	     * we should be okay because the only place this
	     * memory should be is in the proppool's
	     */
	    for(i=0;val->values[i];i++) {
		memset((void *)(val->values[i]),0,strlen(val->values[i]));
		val->values[i] = NULL;
	    }

	    val->values = NULL;
	    val->nvalues = 0;
	    val->valsize = 0;
	    break;
	}
    }
    
    return;
}

/****fetcher interfaces****/

/* format the requested property names into a string
 *  ctx    -- context from prop_new()/prop_request()
 *  sep    -- separator between property names (unused if none requested)
 *  seplen -- length of separator, if < 0 then strlen(sep) will be used
 *  outbuf -- output buffer
 *  outmax -- maximum length of output buffer including NUL terminator
 *  outlen -- set to length of output string excluding NUL terminator
 * returns 0 on success and amount of additional space needed on failure
 */
int prop_format(struct propctx *ctx, const char *sep, int seplen,
		char *outbuf, unsigned outmax, unsigned *outlen) 
{
    unsigned needed, flag = 0;
    struct propval *val;
    
    if(!ctx || !outbuf) return SASL_BADPARAM;

    if(!sep) seplen = 0;    
    if(seplen < 0) seplen = strlen(sep);

    needed = seplen * (ctx->used_values - 1);
    for(val = ctx->values; val->name; val++) {
	needed += strlen(val->name);
    }
    
    if(!outmax) return (needed + 1); /* Because of unsigned funkiness */
    if(needed > (outmax - 1)) return (needed - (outmax - 1));

    *outbuf = '\0';
    if(outlen) *outlen = needed;

    if(needed == 0) return SASL_OK;

    for(val = ctx->values; val->name; val++) {
	if(seplen && flag) {
	    strncat(outbuf, sep, seplen);
	} else {
	    flag = 1;
	}
	strcat(outbuf, val->name);
    }
    
    return SASL_OK;
}

/* add a property value to the context
 *  ctx    -- context from prop_new()/prop_request()
 *  name   -- name of property to which value will be added
 *            if NULL, add to the same name as previous prop_set/setvals call
 *  value  -- a value for the property; will be copied into context
 *            if NULL, remove existing values
 *  vallen -- length of value, if <= 0 then strlen(value) will be used
 */
int prop_set(struct propctx *ctx, const char *name,
	     const char *value, int vallen)
{
    struct propval *cur;

    if(!ctx) return SASL_BADPARAM;
    if(!name && !ctx->prev_val) return SASL_BADPARAM; 

    if(name) {
	struct propval *val;

	ctx->prev_val = NULL;
	
	for(val = ctx->values; val->name; val++) {
	    if(!strcmp(name,val->name)){
		ctx->prev_val = val;
		break;
	    }
	}

	/* Couldn't find it! */
	if(!ctx->prev_val) return SASL_BADPARAM;
    }

    cur = ctx->prev_val;

    if(name) /* New Entry */ {
	unsigned nvalues = 1; /* 1 for NULL entry */
	const char **old_values = NULL;
	char **tmp, **tmp2;
	size_t size;
	
	if(cur->values) {

	    if(!value) {
		/* If we would be adding a null value, then we are done */
		return SASL_OK;
	    }

	    old_values = cur->values;
	    tmp = (char **)cur->values;
	    while(*tmp) {
		nvalues++;
		tmp++;
	    }

	}

	if(value) {
	    nvalues++; /* for the new value */
	}

	size = nvalues * sizeof(char*);

	if(size > ctx->mem_cur->unused) {
	    size_t needed;

	    for(needed = ctx->mem_cur->size * 2; needed < size; needed *= 2);

	    /* Allocate a new proppool */
	    ctx->mem_cur->next = alloc_proppool(needed);
	    if(!ctx->mem_cur->next) return SASL_NOMEM;

	    ctx->mem_cur = ctx->mem_cur->next;

	    ctx->list_end = (char **)ctx->mem_cur->data;
	    ctx->data_end = ctx->mem_cur->data + needed;
	}

	/* Grab the memory */
	ctx->mem_cur->unused -= size;
	cur->values = (const char **)ctx->list_end;
	cur->values[nvalues - 1] = NULL;

	/* Finish updating the context */
	ctx->list_end = (char **)(cur->values + nvalues);

	/* If we don't have an actual value to fill in, we are done */
	if(!value)
	    return SASL_OK;

	tmp2 = (char **)cur->values;
	if(old_values) {
	    tmp = (char **)old_values;
	    
	    while(*tmp) {
		*tmp2 = *tmp;
		tmp++; tmp2++;
	    }
	}
	    
	/* Now allocate the last entry */
	if(vallen <= 0)
	    size = (size_t)(strlen(value) + 1);
	else
	    size = (size_t)(vallen + 1);

	if(size > ctx->mem_cur->unused) {
	    size_t needed;
	    
	    needed = ctx->mem_cur->size * 2;
	    
	    while(needed < size) {
		needed *= 2;
	    }

	    /* Allocate a new proppool */
	    ctx->mem_cur->next = alloc_proppool(needed);
	    if(!ctx->mem_cur->next) return SASL_NOMEM;

	    ctx->mem_cur = ctx->mem_cur->next;
	    ctx->list_end = (char **)ctx->mem_cur->data;
	    ctx->data_end = ctx->mem_cur->data + needed;
	}

	/* Update the data_end pointer */
	ctx->data_end -= size;
	ctx->mem_cur->unused -= size;

	/* Copy and setup the new value! */
	memcpy(ctx->data_end, value, size-1);
	ctx->data_end[size - 1] = '\0';
	cur->values[nvalues - 2] = ctx->data_end;

	cur->nvalues++;
	cur->valsize += (size - 1);
    } else /* Appending an entry */ {
	char **tmp;
	size_t size;

	/* If we are setting it to be NULL, we are done */
	if(!value) return SASL_OK;

	size = sizeof(char*);

	/* Is it in the current pool, and will it fit in the unused space? */
	if(size > ctx->mem_cur->unused &&
	    (void *)cur->values > (void *)(ctx->mem_cur->data) &&
	    (void *)cur->values < (void *)(ctx->mem_cur->data + ctx->mem_cur->size)) {
	    /* recursively call the not-fast way */
	    return prop_set(ctx, cur->name, value, vallen);
	}

	/* Note the invariant: the previous value list must be
	   at the top of the CURRENT pool at this point */

	/* Grab the memory */
	ctx->mem_cur->unused -= size;
	ctx->list_end++;

	*(ctx->list_end - 1) = NULL;
	tmp = (ctx->list_end - 2);

	/* Now allocate the last entry */
	if(vallen <= 0)
	    size = strlen(value) + 1;
	else
	    size = vallen + 1;

	if(size > ctx->mem_cur->unused) {
	    size_t needed;
	    
	    needed = ctx->mem_cur->size * 2;
	    
	    while(needed < size) {
		needed *= 2;
	    }

	    /* Allocate a new proppool */
	    ctx->mem_cur->next = alloc_proppool(needed);
	    if(!ctx->mem_cur->next) return SASL_NOMEM;

	    ctx->mem_cur = ctx->mem_cur->next;
	    ctx->list_end = (char **)ctx->mem_cur->data;
	    ctx->data_end = ctx->mem_cur->data + needed;
	}

	/* Update the data_end pointer */
	ctx->data_end -= size;
	ctx->mem_cur->unused -= size;

	/* Copy and setup the new value! */
	memcpy(ctx->data_end, value, size-1);
	ctx->data_end[size - 1] = '\0';
	*tmp = ctx->data_end;

	cur->nvalues++;
	cur->valsize += (size - 1);
    }
    
    return SASL_OK;
}


/* set the values for a property
 *  ctx    -- context from prop_new()/prop_request()
 *  name   -- name of property to which value will be added
 *            if NULL, add to the same name as previous prop_set/setvals call
 *  values -- array of values, ending in NULL.  Each value is a NUL terminated
 *            string
 */
int prop_setvals(struct propctx *ctx, const char *name,
		 const char **values)
{
    const char **val = values;
    int result = SASL_OK;

    if(!ctx) return SASL_BADPARAM;

    /* If they want us to add no values, we can do that */
    if(!values) return SASL_OK;
    
    /* Basically, use prop_set to do all our dirty work for us */
    if(name) {
	result = prop_set(ctx, name, *val, 0);
	val++;
    }

    for(;*val;val++) {
	if(result != SASL_OK) return result;
	result = prop_set(ctx, NULL, *val,0);
    }

    return result;
}

/* Request a set of auxiliary properties
 *  conn         connection context
 *  propnames    list of auxiliary property names to request ending with
 *               NULL.  
 *
 * Subsequent calls will add items to the request list.  Call with NULL
 * to clear the request list.
 *
 * errors
 *  SASL_OK       -- success
 *  SASL_BADPARAM -- bad count/conn parameter
 *  SASL_NOMEM    -- out of memory
 */
int sasl_auxprop_request(sasl_conn_t *conn, const char **propnames) 
{
    int result;
    sasl_server_conn_t *sconn;

    if(!conn) return SASL_BADPARAM;
    if(conn->type != SASL_CONN_SERVER)
	PARAMERROR(conn);
    
    sconn = (sasl_server_conn_t *)conn;

    if(!propnames) {
	prop_clear(sconn->sparams->propctx,1);
	return SASL_OK;
    }
    
    result = prop_request(sconn->sparams->propctx, propnames);
    RETURN(conn, result);
}


/* Returns current auxiliary property context.
 * Use functions in prop.h to access content
 *
 *  if authentication hasn't completed, property values may be empty/NULL
 *
 *  properties not recognized by active plug-ins will be left empty/NULL
 *
 *  returns NULL if conn is invalid.
 */
struct propctx *sasl_auxprop_getctx(sasl_conn_t *conn) 
{
    sasl_server_conn_t *sconn;
    
    if(!conn || conn->type != SASL_CONN_SERVER) return NULL;

    sconn = (sasl_server_conn_t *)conn;

    return sconn->sparams->propctx;
}

/* add an auxiliary property plugin */
#ifdef _SUN_SDK_
int sasl_auxprop_add_plugin(const char *plugname,
                            sasl_auxprop_init_t *auxpropfunc)
{
    return (_sasl_auxprop_add_plugin(_sasl_gbl_ctx(), plugname, auxpropfunc));
}

int _sasl_auxprop_add_plugin(void *ctx,
                             const char *plugname,
                             sasl_auxprop_init_t *auxpropfunc)
#else
int sasl_auxprop_add_plugin(const char *plugname,
			    sasl_auxprop_init_t *auxpropfunc)
#endif /* _SUN_SDK_ */
{
    int result, out_version;
    auxprop_plug_list_t *new_item;
    sasl_auxprop_plug_t *plug;
#ifdef _SUN_SDK_
    _sasl_global_context_t *gctx = ctx == NULL ? _sasl_gbl_ctx() : ctx;
    auxprop_plug_list_t *auxprop_head;
    const sasl_utils_t *sasl_global_utils;
    auxprop_plug_list_t *l;

    auxprop_head = gctx->auxprop_head;
    sasl_global_utils = gctx->sasl_server_global_utils;

  /* Check to see if this plugin has already been registered */
    for (l = auxprop_head; l != NULL; l = l->next) {
	if (strcmp(plugname, l->plugname) == 0) {
	    return SASL_OK;
	}
    }
#endif /* _SUN_SDK_ */
    
    result = auxpropfunc(sasl_global_utils, SASL_AUXPROP_PLUG_VERSION,
			 &out_version, &plug, plugname);

    if(result != SASL_OK) {
#ifdef _SUN_SDK_
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks,
		SASL_LOG_ERR, "auxpropfunc error %i\n",result);
#else
	_sasl_log(NULL, SASL_LOG_ERR, "auxpropfunc error %i\n",result);
#endif /* _SUN_SDK_ */
	return result;
    }

    /* We require that this function is implemented */
    if(!plug->auxprop_lookup) return SASL_BADPROT;

#ifdef _SUN_SDK_
    /* Check plugin to make sure name is non-NULL */
    if (plug->name == NULL) {
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks,
		SASL_LOG_ERR, "invalid auxprop plugin %s", plugname);
	return SASL_BADPROT;
    }
#endif /* _SUN_SDK_ */

    new_item = sasl_ALLOC(sizeof(auxprop_plug_list_t));
    if(!new_item) return SASL_NOMEM;    

#ifdef _SUN_SDK_
    if(_sasl_strdup(plugname, &new_item->plugname, NULL) != SASL_OK) {
	sasl_FREE(new_item);
	return SASL_NOMEM;
    }
#endif /* _SUN_SDK_ */
    /* These will load from least-important to most important */
    new_item->plug = plug;
    new_item->next = auxprop_head;
#ifdef _SUN_SDK_
    gctx->auxprop_head = new_item;
#else
    auxprop_head = new_item;
#endif /* _SUN_SDK_ */

    return SASL_OK;
}

#ifdef _SUN_SDK_
void _sasl_auxprop_free(_sasl_global_context_t *gctx)
#else
void _sasl_auxprop_free() 
#endif /* _SUN_SDK_ */
{
    auxprop_plug_list_t *ptr, *ptr_next;
#ifdef _SUN_SDK_
    const sasl_utils_t *sasl_global_utils = gctx->sasl_server_global_utils;

    for(ptr = (auxprop_plug_list_t *)gctx->auxprop_head; ptr; ptr = ptr_next) {
#else
    
    for(ptr = auxprop_head; ptr; ptr = ptr_next) {
#endif /* _SUN_SDK_ */
	ptr_next = ptr->next;
	if(ptr->plug->auxprop_free)
	    ptr->plug->auxprop_free(ptr->plug->glob_context,
				    sasl_global_utils);
#ifdef _SUN_SDK_
	sasl_FREE(ptr->plugname);
#endif /* _SUN_SDK_ */
	sasl_FREE(ptr);
    }

#ifdef _SUN_SDK_
    gctx->auxprop_head = NULL;
#else
    auxprop_head = NULL;
#endif /* _SUN_SDK_ */
}


/* Do the callbacks for auxprop lookups */
void _sasl_auxprop_lookup(sasl_server_params_t *sparams,
			  unsigned flags,
			  const char *user, unsigned ulen) 
{
    sasl_getopt_t *getopt;
    int ret, found = 0;
    void *context;
    const char *plist = NULL;
    auxprop_plug_list_t *ptr;
#ifdef _SUN_SDK_
    _sasl_global_context_t *gctx = sparams->utils->conn->gctx;
    auxprop_plug_list_t *auxprop_head = gctx->auxprop_head;
#endif /* _SUN_SDK_ */

    if(_sasl_getcallback(sparams->utils->conn,
			 SASL_CB_GETOPT, &getopt, &context) == SASL_OK) {
	ret = getopt(context, NULL, "auxprop_plugin", &plist, NULL);
	if(ret != SASL_OK) plist = NULL;
    }

    if(!plist) {
	/* Do lookup in all plugins */
	for(ptr = auxprop_head; ptr; ptr = ptr->next) {
	    found=1;
	    ptr->plug->auxprop_lookup(ptr->plug->glob_context,
				      sparams, flags, user, ulen);
	}
    } else {
	char *pluginlist = NULL, *freeptr = NULL, *thisplugin = NULL;

	if(_sasl_strdup(plist, &pluginlist, NULL) != SASL_OK) return;
	thisplugin = freeptr = pluginlist;
	
	/* Do lookup in all *specified* plugins, in order */
	while(*thisplugin) {
	    char *p;
	    int last=0;
	    
	    while(*thisplugin && isspace((int)*thisplugin)) thisplugin++;
	    if(!(*thisplugin)) break;
	    
	    for(p = thisplugin;*p != '\0' && !isspace((int)*p); p++);
	    if(*p == '\0') last = 1;
	    else *p='\0';
	    
	    for(ptr = auxprop_head; ptr; ptr = ptr->next) {
		/* Skip non-matching plugins */
		if(!ptr->plug->name
		   || strcasecmp(ptr->plug->name, thisplugin))
		    continue;
	    
		found=1;
		ptr->plug->auxprop_lookup(ptr->plug->glob_context,
					  sparams, flags, user, ulen);
	    }

	    if(last) break;

	    thisplugin = p+1;
	}

	sasl_FREE(freeptr);
    }

    if(!found)
	_sasl_log(sparams->utils->conn, SASL_LOG_DEBUG,
		  "could not find auxprop plugin, was searching for '%s'",
		  plist ? plist : "[all]");
}
