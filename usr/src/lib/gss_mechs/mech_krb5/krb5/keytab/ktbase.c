/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/keytab/ktbase.c
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
 * Registration functions for keytab.
 */

#include "k5-int.h"
#include "k5-thread.h"
#include "kt-int.h"

extern const krb5_kt_ops krb5_ktf_ops;
extern const krb5_kt_ops krb5_ktf_writable_ops;
extern const krb5_kt_ops krb5_kts_ops;

struct krb5_kt_typelist {
    const krb5_kt_ops *ops;
    const struct krb5_kt_typelist *next;
};
/* Solaris Kerberos */
static const struct krb5_kt_typelist krb5_kt_typelist_wrfile  = {
    &krb5_ktf_writable_ops,
    0
};
/* Solaris Kerberos */
static const  struct krb5_kt_typelist krb5_kt_typelist_file  = {
    &krb5_ktf_ops,
    &krb5_kt_typelist_wrfile
};
/* Solaris Kerberos */
static const struct krb5_kt_typelist krb5_kt_typelist_srvtab = {
    &krb5_kts_ops,
    &krb5_kt_typelist_file
};
static const struct krb5_kt_typelist *kt_typehead = &krb5_kt_typelist_srvtab;
/* Lock for protecting the type list.  */
static k5_mutex_t kt_typehead_lock = K5_MUTEX_PARTIAL_INITIALIZER;

int krb5int_kt_initialize(void)
{
    return k5_mutex_finish_init(&kt_typehead_lock);
}

void
krb5int_kt_finalize(void)
{
    struct krb5_kt_typelist *t, *t_next;
    k5_mutex_destroy(&kt_typehead_lock);
    /* Solaris Kerberos */
    for (t = (struct krb5_kt_typelist *)kt_typehead; t != &krb5_kt_typelist_srvtab;
	t = t_next) {
        t_next = (struct krb5_kt_typelist *)t->next;
	free(t);
    }
}


/*
 * Register a new key table type
 * don't replace if it already exists; return an error instead.
 */
/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_kt_register(krb5_context context, const krb5_kt_ops *ops)
{
    const struct krb5_kt_typelist *t;
    struct krb5_kt_typelist *newt;
    krb5_error_code err;

    err = k5_mutex_lock(&kt_typehead_lock);
    if (err)
	return err;
    for (t = kt_typehead; t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	k5_mutex_unlock(&kt_typehead_lock);
	return KRB5_KT_TYPE_EXISTS;
    }
    if (!(newt = (struct krb5_kt_typelist *) malloc(sizeof(*t)))) {
	k5_mutex_unlock(&kt_typehead_lock);
	return ENOMEM;
    }
    newt->next = kt_typehead;
    newt->ops = ops;
    kt_typehead = newt;
    k5_mutex_unlock(&kt_typehead_lock);
    return 0;
}

/*
 * Resolve a key table name into a keytab object.
 *
 * The name is currently constrained to be of the form "type:residual";
 *
 * The "type" portion corresponds to one of the registered key table
 * types, while the "residual" portion is specific to the
 * particular keytab type.
 */

#include <ctype.h>
krb5_error_code KRB5_CALLCONV
krb5_kt_resolve (krb5_context context, const char *name, krb5_keytab *ktid)
{
    const struct krb5_kt_typelist *tlist;
    char *pfx;
    unsigned int pfxlen;
    const char *cp, *resid;
    krb5_error_code err;

    cp = strchr (name, ':');
    if (!cp) {
	    return (*krb5_kt_dfl_ops.resolve)(context, name, ktid);
    }

    pfxlen = cp - name;

    if ( pfxlen == 1 && isalpha((unsigned char) name[0]) ) {
        /* We found a drive letter not a prefix - use FILE */
        pfx = strdup("FILE");
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

    *ktid = (krb5_keytab) 0;

    err = k5_mutex_lock(&kt_typehead_lock);
    if (err)
	return err;
    tlist = kt_typehead;
    /* Don't need to hold the lock, since entries are never modified
       or removed once they're in the list.  Just need to protect
       access to the list head variable itself.  */
    k5_mutex_unlock(&kt_typehead_lock);
    for (; tlist; tlist = tlist->next) {
	if (strcmp (tlist->ops->prefix, pfx) == 0) {
	    free(pfx);
	    return (*tlist->ops->resolve)(context, resid, ktid);
	}
    }
    free(pfx);
    return KRB5_KT_UNKNOWN_TYPE;
}

/*
 * Routines to deal with externalizingt krb5_keytab.
 *	krb5_keytab_size();
 *	krb5_keytab_externalize();
 *	krb5_keytab_internalize();
 */
static krb5_error_code krb5_keytab_size
	(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_keytab_externalize
	(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_keytab_internalize
	(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/*
 * Serialization entry for this type.
 */
static const krb5_ser_entry krb5_keytab_ser_entry = {
    KV5M_KEYTAB,			/* Type			*/
    krb5_keytab_size,			/* Sizer routine	*/
    krb5_keytab_externalize,		/* Externalize routine	*/
    krb5_keytab_internalize		/* Internalize routine	*/
};

static krb5_error_code
krb5_keytab_size(krb5_context kcontext, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    krb5_ser_handle	shandle;

    kret = EINVAL;
    /* Solaris Kerberos */
    keytab = (krb5_keytab) arg;
    shandle = (krb5_ser_handle) keytab->ops->serializer;
    if ((keytab != NULL) && (keytab->ops) &&
	(shandle != NULL) && (shandle->sizer))
	kret = (*shandle->sizer)(kcontext, arg, sizep);
    return(kret);
}

static krb5_error_code
krb5_keytab_externalize(krb5_context kcontext, krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    krb5_ser_handle	shandle;

    kret = EINVAL;
    /* Solaris Kerberos */
    keytab = (krb5_keytab) arg;
    shandle = (krb5_ser_handle) keytab->ops->serializer;
    if ((keytab != NULL) && (keytab->ops) &&
	(shandle != NULL) && (shandle->externalizer))
	kret = (*shandle->externalizer)(kcontext, arg, buffer, lenremain);
    return(kret);
}

static krb5_error_code
krb5_keytab_internalize(krb5_context kcontext, krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_ser_handle	shandle;

    kret = EINVAL;
    /* Solaris Kerberos */
    shandle = (krb5_ser_handle) krb5_kt_dfl_ops.serializer;
    if ((shandle != NULL) && (shandle->internalizer))
	kret = (*shandle->internalizer)(kcontext, argp, buffer, lenremain);
    return(kret);
}

krb5_error_code KRB5_CALLCONV
krb5_ser_keytab_init(krb5_context kcontext)
{
    return(krb5_register_serializer(kcontext, &krb5_keytab_ser_entry));
}
