#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/ccbase.c
 *
 * Copyright 1990,2004 by the Massachusetts Institute of Technology.
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
 * 
 *
 * Registration functions for ccache.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "k5-int.h"
#include "k5-thread.h"

#include "fcc.h"
#include "cc-int.h"

struct krb5_cc_typelist {
    const krb5_cc_ops *ops;
    struct krb5_cc_typelist *next;
};
extern const krb5_cc_ops krb5_mcc_ops;

#ifdef _WIN32
extern const krb5_cc_ops krb5_lcc_ops;
static struct krb5_cc_typelist cc_lcc_entry = { &krb5_lcc_ops, NULL };
static struct krb5_cc_typelist cc_mcc_entry = { &krb5_mcc_ops, &cc_lcc_entry };
#else
static struct krb5_cc_typelist cc_mcc_entry = { &krb5_mcc_ops, NULL };
#endif

static struct krb5_cc_typelist cc_fcc_entry = { &krb5_cc_file_ops,
						&cc_mcc_entry };

static struct krb5_cc_typelist *cc_typehead = &cc_fcc_entry;
static k5_mutex_t cc_typelist_lock = K5_MUTEX_PARTIAL_INITIALIZER;

int
krb5int_cc_initialize(void)
{
    int err;

    err = k5_mutex_finish_init(&krb5int_mcc_mutex);
    if (err)
	return err;
    err = k5_mutex_finish_init(&cc_typelist_lock);
    if (err)
	return err;
    err = k5_mutex_finish_init(&krb5int_cc_file_mutex);
    if (err)
	return err;
    return 0;
}

void
krb5int_cc_finalize(void)
{
    struct krb5_cc_typelist *t, *t_next;
    k5_mutex_destroy(&cc_typelist_lock);
    k5_mutex_destroy(&krb5int_cc_file_mutex);
    k5_mutex_destroy(&krb5int_mcc_mutex);
    for (t = cc_typehead; t != &cc_fcc_entry; t = t_next) {
	t_next = t->next;
	free(t);
    }
}


/*
 * Register a new credentials cache type
 * If override is set, replace any existing ccache with that type tag
 */

krb5_error_code KRB5_CALLCONV
krb5_cc_register(krb5_context context, krb5_cc_ops *ops, krb5_boolean override)
{
    struct krb5_cc_typelist *t;
    krb5_error_code err;

    err = k5_mutex_lock(&cc_typelist_lock);
    if (err)
	return err;
    for (t = cc_typehead;t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	if (override) {
	    t->ops = ops;
	    k5_mutex_unlock(&cc_typelist_lock);
	    return 0;
	} else {
	    k5_mutex_unlock(&cc_typelist_lock);
	    return KRB5_CC_TYPE_EXISTS;
	}
    }
    if (!(t = (struct krb5_cc_typelist *) malloc(sizeof(*t)))) {
	k5_mutex_unlock(&cc_typelist_lock);
	return ENOMEM;
    }
    t->next = cc_typehead;
    t->ops = ops;
    cc_typehead = t;
    k5_mutex_unlock(&cc_typelist_lock);
    return 0;
}

/*
 * Resolve a credential cache name into a cred. cache object.
 *
 * The name is currently constrained to be of the form "type:residual";
 *
 * The "type" portion corresponds to one of the predefined credential
 * cache types, while the "residual" portion is specific to the
 * particular cache type.
 */

#include <ctype.h>
krb5_error_code KRB5_CALLCONV
krb5_cc_resolve (krb5_context context, const char *name, krb5_ccache *cache)
{
    struct krb5_cc_typelist *tlist;
    char *pfx, *cp;
    const char *resid;
    unsigned int pfxlen;
    krb5_error_code err;
    
    /* Solaris Kerberos */
    if (!name)
        return KRB5_CC_BADNAME;

    cp = strchr (name, ':');
    if (!cp) {
	if (krb5_cc_dfl_ops)
	    return (*krb5_cc_dfl_ops->resolve)(context, cache, name);
	else
	    return KRB5_CC_BADNAME;
    }

    pfxlen = cp - name;

    if ( pfxlen == 1 && isalpha(name[0]) ) {
        /* We found a drive letter not a prefix - use FILE: */
        pfx = strdup("FILE:");
        if (!pfx)
            return ENOMEM;

        resid = name;
    } else {
        resid = name + pfxlen + 1;

        pfx = malloc (pfxlen+1);
        if (!pfx)
            return ENOMEM;

        memcpy (pfx, name, pfxlen);
        pfx[pfxlen] = '\0';
    }

    *cache = (krb5_ccache) 0;

    err = k5_mutex_lock(&cc_typelist_lock);
    if (err) {
	free(pfx);
	return err;
    }
    for (tlist = cc_typehead; tlist; tlist = tlist->next) {
	if (strcmp (tlist->ops->prefix, pfx) == 0) {
	    krb5_error_code (KRB5_CALLCONV *ccresolver)() = tlist->ops->resolve;
	    k5_mutex_unlock(&cc_typelist_lock);
	    free(pfx);
	    return (*ccresolver)(context, cache, resid);
	}
    }
    k5_mutex_unlock(&cc_typelist_lock);
    if (krb5_cc_dfl_ops && !strcmp (pfx, krb5_cc_dfl_ops->prefix)) {
	free (pfx);
	return (*krb5_cc_dfl_ops->resolve)(context, cache, resid);
    }
    free(pfx);
    return KRB5_CC_UNKNOWN_TYPE;
}
