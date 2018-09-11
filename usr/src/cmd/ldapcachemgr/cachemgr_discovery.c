/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifdef SLP

/*
 * This file contains all the dynamic server discovery functionality
 * for ldap_cachemgr. SLP is used to query the network for any changes
 * in the set of deployed LDAP servers.
 *
 * The algorithm used is outlined here:
 *
 *   1. Find all naming contexts with SLPFindAttrs. (See
 *      find_all_contexts())
 *   2. For each context, find all servers which serve that context
 *      with SLPFindSrvs. (See foreach_context())
 *   3. For each server, retrieve that server's attributes with
 *      SLPFindAttributes. (See foreach_server())
 *   4. Aggregate the servers' attributes into a config object. There
 *      is one config object associated with each context found in
 *      step 1. (See aggregate_attrs())
 *   5. Update the global config cache for each found context and its
 *      associated servers and attributes. (See update_config())
 *
 * The entry point for ldap_cachemgr is discover(). The actual entry
 * point into the discovery routine is find_all_contexts(); the
 * code thereafter is actually not specific to LDAP, and could also
 * be used to discover YP, or any other server which conforms
 * to the SLP Naming and Directory abstract service type.
 *
 * find_all_attributes() takes as parameters three callback routines
 * which are used to report all information back to the caller. The
 * signatures and synopses of these routines are:
 *
 * void *get_cfghandle(const char *domain);
 *
 *   Returns an opaque handle to a configuration object specific
 *   to the 'domain' parameter. 'domain' will be a naming context
 *   string, i.e. foo.bar.sun.com ( i.e. a secure-RPC domain-
 *   name).
 *
 * void aggregate(void *handle, const char *tag, const char *value);
 *
 *   Adds this tag / value pair to the set of aggregated attributes
 *   associated with the given handle.
 *
 * void set_cfghandle(void *handle);
 *
 *   Sets and destroys the config object; SLP will no longer attempt
 *   to use this handle after this call. Thus, this call marks the
 *   end of configuration information for this handle.
 */

#include <stdio.h>
#include <slp.h>
#include <stdlib.h>
#include <string.h>
#include <door.h>
#include <unistd.h>
#include "ns_sldap.h"
#include "ns_internal.h"
#include "cachemgr.h"

#define	ABSTYPE		"service:naming-directory"
#define	CONTEXT_ATTR	"naming-context"
#define	LDAP_DOMAIN_ATTR "x-sun-rpcdomain"

/* The configuration cookie passed along through all SLP callbacks. */
struct config_cookie {
	SLPHandle	h;		/* An open SLPHandle */
	const char	*type;		/* The full service type to use */
	char		*scopes;	/* A list of scopes to use */
	const char	*context_attr;	/* Which attr to use for the ctx */
	void		*cache_cfg;	/* caller-supplied config object */
	void *(*get_cfghandle)(const char *);
	void (*aggregate)(void *, const char *, const char *);
	void (*set_cfghandle)(void *);
};

extern admin_t current_admin;	/* ldap_cachemgr's admin struct */

/*
 * Utility routine: getlocale():
 * Returns the locale specified by the SLP locale property, or just
 * returns the default SLP locale if the property was not set.
 */
static const char *getlocale() {
	const char *locale = SLPGetProperty("net.slp.locale");
	return (locale ? locale : "en");
}

/*
 * Utility routine: next_attr():
 * Parses an SLP attribute string. On the first call, *type
 * must be set to 0, and *s_inout must point to the beginning
 * of the attr string. The following results are possible:
 *
 *   If the term is of the form 'tag' only, *t_inout is set to tag,
 *     and *v_inout is set to NULL.
 *   If the term is of the form '(tag=val)', *t_inout and *v_inout
 *     are set to the tag and val strings, respectively.
 *   If the term is of the form '(tag=val1,val2,..,valN)', on each
 *     successive call, next_attr will return the next value. On the
 *     first invocation, tag is set to 'tag'; on successive invocations,
 *     tag is set to *t_inout.
 *
 * The string passed in *s_inout is destructively modified; all values
 * returned simply point into the initial string. Hence the caller
 * is responsible for all memory management. The type parameter is
 * for internal use only and should be set to 0 by the caller only
 * on the first invocation.
 *
 * If more attrs are available, returns SLP_TRUE, otherwise returns
 * SLP_FALSE. If SLP_FALSE is returned, all value-result parameters
 * will be undefined, and should not be used.
 */
static SLPBoolean next_attr(char **t_inout, char **v_inout,
			    char **s_inout, int *type) {
	char *end = NULL;
	char *tag = NULL;
	char *val = NULL;
	char *state = NULL;

	if (!t_inout || !v_inout)
	    return (SLP_FALSE);

	if (!s_inout || !*s_inout || !**s_inout)
	    return (SLP_FALSE);

	state = *s_inout;

	/* type: 0 = start, 1 = '(tag=val)' type, 2 = 'tag' type */
	switch (*type) {
	case 0:
	    switch (*state) {
	    case '(':
		*type = 1;
		break;
	    case ',':
		state++;
		*type = 0;
		break;
	    default:
		*type = 2;
	    }
	    *s_inout = state;
	    return (next_attr(t_inout, v_inout, s_inout, type));
	    break;
	case 1:
	    switch (*state) {
	    case '(':
		/* start of attr of the form (tag=val[,val]) */
		state++;
		tag = state;
		end = strchr(state, ')');	/* for sanity checking */
		if (!end)
		    return (SLP_FALSE);	/* fatal parse error */

		state = strchr(tag, '=');
		if (state) {
		    if (state > end)
			return (SLP_FALSE);  /* fatal parse err */
		    *state++ = 0;
		} else {
		    return (SLP_FALSE);	/* fatal parse error */
		}
		/* fallthru to default case, which handles multivals */
	    default:
		/* somewhere in a multivalued attr */
		if (!end) {	/* did not fallthru from '(' case */
		    tag = *t_inout;	/* leave tag as it was */
		    end = strchr(state, ')');
		    if (!end)
			return (SLP_FALSE);	/* fatal parse error */
		}

		val = state;
		state = strchr(val, ',');	/* is this attr multivalued? */
		if (!state || state > end) {
		    /* no, so skip to the next attr */
		    state = end;
		    *type = 0;
		}	/* else attr is multivalued */
		*state++ = 0;
		break;
	    }
	    break;
	case 2:
	    /* attr term with tag only */
	    tag = state;
	    state = strchr(tag, ',');
	    if (state) {
		*state++ = 0;
	    }
	    val = NULL;
	    *type = 0;
	    break;
	default:
	    return (SLP_FALSE);
	}

	*t_inout = tag;
	*v_inout = val;
	*s_inout = state;

	return (SLP_TRUE);
}

/*
 * The SLP callback routine for foreach_server(). Aggregates each
 * server's attributes into the caller-specified config object.
 */
/*ARGSUSED*/
static SLPBoolean aggregate_attrs(SLPHandle h, const char *attrs_in,
				    SLPError errin, void *cookie) {
	char *tag, *val, *state;
	char *unesc_tag, *unesc_val;
	int type = 0;
	char *attrs;
	SLPError err;
	struct config_cookie *cfg = (struct config_cookie *)cookie;

	if (errin != SLP_OK) {
	    return (SLP_TRUE);
	}

	attrs = strdup(attrs_in);
	state = attrs;

	while (next_attr(&tag, &val, &state, &type)) {
	    unesc_tag = unesc_val = NULL;

	    if (tag) {
		if ((err = SLPUnescape(tag, &unesc_tag, SLP_TRUE)) != SLP_OK) {
		    unesc_tag = NULL;
		    if (current_admin.debug_level >= DBG_ALL) {
			(void) logit("aggregate_attrs: ",
				"could not unescape attr tag %s:%s\n",
				tag, slp_strerror(err));
		    }
		}
	    }
	    if (val) {
		if ((err = SLPUnescape(val, &unesc_val, SLP_FALSE))
		    != SLP_OK) {
		    unesc_val = NULL;
		    if (current_admin.debug_level >= DBG_ALL) {
			(void) logit("aggregate_attrs: ",
				"could not unescape attr val %s:%s\n",
				val, slp_strerror(err));
		    }
		}
	    }

	    if (current_admin.debug_level >= DBG_ALL) {
		(void) logit("discovery:\t\t%s=%s\n",
			(unesc_tag ? unesc_tag : "NULL"),
			(unesc_val ? unesc_val : "NULL"));
	    }

	    cfg->aggregate(cfg->cache_cfg, unesc_tag, unesc_val);

	    if (unesc_tag) free(unesc_tag);
	    if (unesc_val) free(unesc_val);
	}

	if (attrs) free(attrs);

	return (SLP_TRUE);
}

/*
 * The SLP callback routine for update_config(). For each
 * server found, retrieves that server's attributes.
 */
/*ARGSUSED*/
static SLPBoolean foreach_server(SLPHandle hin, const char *u,
				unsigned short life,
				SLPError errin, void *cookie) {
	SLPError err;
	struct config_cookie *cfg = (struct config_cookie *)cookie;
	SLPHandle h = cfg->h;	/* an open handle */
	SLPSrvURL *surl = NULL;
	char *url = NULL;

	if (errin != SLP_OK) {
	    return (SLP_TRUE);
	}

	/* dup url so we can slice 'n dice */
	if (!(url = strdup(u))) {
	    (void) logit("foreach_server: no memory");
	    return (SLP_FALSE);
	}

	if ((err = SLPParseSrvURL(url, &surl)) != SLP_OK) {
	    free(url);
	    if (current_admin.debug_level >= DBG_NETLOOKUPS) {
		(void) logit("foreach_server: ",
				"dropping unparsable URL %s: %s\n",
				url, slp_strerror(err));
		return (SLP_TRUE);
	    }
	}

	if (current_admin.debug_level >= DBG_ALL) {
	    (void) logit("discovery:\tserver: %s\n", surl->s_pcHost);
	}

	/* retrieve all attrs for this server */
	err = SLPFindAttrs(h, u, cfg->scopes, "", aggregate_attrs, cookie);
	if (err != SLP_OK) {
	    if (current_admin.debug_level >= DBG_NETLOOKUPS) {
		(void) logit("foreach_server: FindAttrs failed: %s\n",
				slp_strerror(err));
	    }
	    goto cleanup;
	}

	/* add this server and its attrs to the config object */
	cfg->aggregate(cfg->cache_cfg, "_,_xservers_,_", surl->s_pcHost);

cleanup:
	if (url) free(url);
	if (surl) SLPFree(surl);

	return (SLP_TRUE);
}

/*
 * This routine does the dirty work of finding all servers for a
 * given domain and injecting this information into the caller's
 * configuration namespace via callbacks.
 */
static void update_config(const char *context, struct config_cookie *cookie) {
	SLPHandle h = NULL;
	SLPHandle persrv_h = NULL;
	SLPError err;
	char *search = NULL;
	char *unesc_domain = NULL;

	/* Unescape the naming context string */
	if ((err = SLPUnescape(context, &unesc_domain, SLP_FALSE)) != SLP_OK) {
	    if (current_admin.debug_level >= DBG_ALL) {
		(void) logit("update_config: ",
				"dropping unparsable domain: %s: %s\n",
				context, slp_strerror(err));
	    }
	    return;
	}

	cookie->cache_cfg = cookie->get_cfghandle(unesc_domain);

	/* Open a handle which all attrs calls can use */
	if ((err = SLPOpen(getlocale(), SLP_FALSE, &persrv_h)) != SLP_OK) {
	    if (current_admin.debug_level >= DBG_NETLOOKUPS) {
		(void) logit("update_config: SLPOpen failed: %s\n",
				slp_strerror(err));
	    }
	    goto cleanup;
	}

	cookie->h = persrv_h;

	if (current_admin.debug_level >= DBG_ALL) {
	    (void) logit("discovery: found naming context %s\n", context);
	}

	/* (re)construct the search filter form the input context */
	search = malloc(strlen(cookie->context_attr) +
			strlen(context) +
			strlen("(=)") + 1);
	if (!search) {
	    (void) logit("update_config: no memory\n");
	    goto cleanup;
	}
	(void) sprintf(search, "(%s=%s)", cookie->context_attr, context);

	/* Find all servers which serve this context */
	if ((err = SLPOpen(getlocale(), SLP_FALSE, &h)) != SLP_OK) {
	    if (current_admin.debug_level >= DBG_NETLOOKUPS) {
		(void) logit("upate_config: SLPOpen failed: %s\n",
				slp_strerror(err));
	    }
	    goto cleanup;
	}

	err = SLPFindSrvs(h, cookie->type, cookie->scopes,
				search, foreach_server, cookie);
	if (err != SLP_OK) {
	    if (current_admin.debug_level >= DBG_NETLOOKUPS) {
		(void) logit("update_config: SLPFindSrvs failed: %s\n",
				slp_strerror(err));
	    }
	    goto cleanup;
	}

	/* update the config cache with the new info */
	cookie->set_cfghandle(cookie->cache_cfg);

cleanup:
	if (h) SLPClose(h);
	if (persrv_h) SLPClose(persrv_h);
	if (search) free(search);
	if (unesc_domain) free(unesc_domain);
}

/*
 * The SLP callback routine for find_all_contexts(). For each context
 * found, finds all the servers and their attributes.
 */
/*ARGSUSED*/
static SLPBoolean foreach_context(SLPHandle h, const char *attrs_in,
				    SLPError err, void *cookie) {
	char *attrs, *tag, *val, *state;
	int type = 0;

	if (err != SLP_OK) {
	    return (SLP_TRUE);
	}

	/*
	 * Parse out each context. Attrs will be of the following form:
	 *   (naming-context=dc\3deng\2c dc\3dsun\2c dc\3dcom)
	 * Note that ',' and '=' are reserved in SLP, so they are escaped.
	 */
	attrs = strdup(attrs_in);	/* so we can slice'n'dice */
	if (!attrs) {
	    (void) logit("foreach_context: no memory\n");
	    return (SLP_FALSE);
	}
	state = attrs;

	while (next_attr(&tag, &val, &state, &type)) {
	    update_config(val, cookie);
	}

	free(attrs);

	return (SLP_TRUE);
}

/*
 * Initiates server and attribute discovery for the concrete type
 * 'type'. Currently the only useful type is "ldap", but perhaps
 * "nis" and "nisplus" will also be useful in the future.
 *
 * get_cfghandle, aggregate, and set_cfghandle are callback routines
 * used to pass any discovered configuration information back to the
 * caller. See the introduction at the top of this file for more info.
 */
static void find_all_contexts(const char *type,
				void *(*get_cfghandle)(const char *),
				void (*aggregate)(
					void *, const char *, const char *),
				void (*set_cfghandle)(void *)) {
	SLPHandle h = NULL;
	SLPError err;
	struct config_cookie cookie[1];
	char *fulltype = NULL;
	char *scope = (char *)SLPGetProperty("net.slp.useScopes");

	if (!scope || !*scope) {
	    scope = "default";
	}

	/* construct the full type from the partial type parameter */
	fulltype = malloc(strlen(ABSTYPE) + strlen(type) + 2);
	if (!fulltype) {
	    (void) logit("find_all_contexts: no memory");
	    goto done;
	}
	(void) sprintf(fulltype, "%s:%s", ABSTYPE, type);

	/* set up the cookie for this discovery operation */
	memset(cookie, 0, sizeof (*cookie));
	cookie->type = fulltype;
	cookie->scopes = scope;
	if (strcasecmp(type, "ldap") == 0) {
		/* Sun LDAP is special */
	    cookie->context_attr = LDAP_DOMAIN_ATTR;
	} else {
	    cookie->context_attr = CONTEXT_ATTR;
	}
	cookie->get_cfghandle = get_cfghandle;
	cookie->aggregate = aggregate;
	cookie->set_cfghandle = set_cfghandle;

	if ((err = SLPOpen(getlocale(), SLP_FALSE, &h)) != SLP_OK) {
	    if (current_admin.debug_level >= DBG_CANT_FIND) {
		(void) logit("discover: %s",
			    "Aborting discovery: SLPOpen failed: %s\n",
			    slp_strerror(err));
	    }
	    goto done;
	}

	/* use find attrs to get a list of all available contexts */
	err = SLPFindAttrs(h, fulltype, scope, cookie->context_attr,
			    foreach_context, cookie);
	if (err != SLP_OK) {
	    if (current_admin.debug_level >= DBG_CANT_FIND) {
		(void) logit(
		"discover: Aborting discovery: SLPFindAttrs failed: %s\n",
			slp_strerror(err));
	    }
	    goto done;
	}

done:
	if (h) SLPClose(h);
	if (fulltype) free(fulltype);
}

/*
 * This is the ldap_cachemgr entry point into SLP dynamic discovery. The
 * parameter 'r' should be a pointer to an unsigned int containing
 * the requested interval at which the network should be queried.
 */
void discover(void *r) {
	unsigned short reqrefresh = *((unsigned int *)r);

	for (;;) {
	    find_all_contexts("ldap",
				__cache_get_cfghandle,
				__cache_aggregate_params,
				__cache_set_cfghandle);

	    if (current_admin.debug_level >= DBG_ALL) {
		(void) logit(
			"dynamic discovery: using refresh interval %d\n",
			reqrefresh);
	    }

	    (void) sleep(reqrefresh);
	}
}

#endif /* SLP */
