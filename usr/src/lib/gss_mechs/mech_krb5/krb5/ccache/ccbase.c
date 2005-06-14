/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/ccbase.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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

#include <k5-int.h>

extern krb5_cc_ops *krb5_cc_dfl_ops;
struct krb5_cc_typelist
 {
  krb5_cc_ops *ops;
  struct krb5_cc_typelist *next;
 };
extern krb5_cc_ops krb5_mcc_ops;

static struct krb5_cc_typelist cc_entry = { &krb5_mcc_ops, NULL };

static struct krb5_cc_typelist *cc_typehead = &cc_entry;

/*
 * Register a new credentials cache type
 * If override is set, replace any existing ccache with that type tag
 */

/*ARGSUSED*/
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_cc_register(context, ops, override)
   krb5_context context;
   krb5_cc_ops FAR *ops;
   krb5_boolean override;
{
    struct krb5_cc_typelist *t;
    for (t = cc_typehead;t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	if (override) {
	    t->ops = ops;
	    return 0;
	} else
	    return KRB5_CC_TYPE_EXISTS;
    }
    if (!(t = (struct krb5_cc_typelist *) malloc(sizeof(*t))))
	return ENOMEM;
    t->next = cc_typehead;
    t->ops = ops;
    cc_typehead = t;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_cc_resolve (context, name, cache)
   krb5_context context;
   const char *name;
   krb5_ccache *cache;
{
    struct krb5_cc_typelist *tlist;
    char *pfx, *cp;
    char *resid;
    int pfxlen;

    cp = strchr (name, ':');
    if (!cp) {
	if (krb5_cc_dfl_ops)
	    return (*krb5_cc_dfl_ops->resolve)(context, cache, (char *)name);
	else
	    return KRB5_CC_BADNAME;
    }

    pfxlen = cp - name;
    resid = (char *)name + pfxlen + 1;
	
    pfx = malloc (pfxlen+1);
    if (!pfx)
	return ENOMEM;

    memcpy (pfx, name, pfxlen);
    pfx[pfxlen] = '\0';

    *cache = (krb5_ccache) 0;

    for (tlist = cc_typehead; tlist; tlist = tlist->next) {
	if (strcmp (tlist->ops->prefix, pfx) == 0) {
	    free(pfx);
	    return (*tlist->ops->resolve)(context, cache, resid);
	}
    }
    if (krb5_cc_dfl_ops && !strcmp (pfx, krb5_cc_dfl_ops->prefix)) {
	free (pfx);
	return (*krb5_cc_dfl_ops->resolve)(context, cache, resid);
    }
    free(pfx);
    return KRB5_CC_UNKNOWN_TYPE;
}
