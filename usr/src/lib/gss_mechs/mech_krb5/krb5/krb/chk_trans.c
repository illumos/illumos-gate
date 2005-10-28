#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/krb/chk_trans.c
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 * krb5_check_transited_list()
 */
#include <k5-int.h>
#include <stdarg.h>

#define MAXLEN 512

static krb5_error_code
process_intermediates (krb5_error_code (*fn)(krb5_data *, void *), void *data,
		       const krb5_data *n1, const krb5_data *n2) {
    unsigned int len1, len2, i;
    char *p1, *p2;

    len1 = n1->length;
    len2 = n2->length;

    /* Simplify...  */
    if (len1 > len2) {
	const krb5_data *p;
	int tmp = len1;
	len1 = len2;
	len2 = tmp;
	p = n1;
	n1 = n2;
	n2 = p;
    }
    /* Okay, now len1 is always shorter or equal.  */
    if (len1 == len2) {
	if (memcmp (n1->data, n2->data, len1)) {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	return 0;
    }
    /* Now len1 is always shorter.  */
    if (len1 == 0)
	/* Shouldn't be possible.  Internal error?  */
	return KRB5KRB_AP_ERR_ILL_CR_TKT;
    p1 = n1->data;
    p2 = n2->data;
    if (p1[0] == '/') {
	/* X.500 style names, with common prefix.  */
	if (p2[0] != '/') {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	if (memcmp (p1, p2, len1)) {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	for (i = len1 + 1; i < len2; i++)
	    if (p2[i] == '/') {
		krb5_data d;
		krb5_error_code r;

		d.data = p2;
		d.length = i;
		r = (*fn) (&d, data);
		if (r)
		    return r;
	    }
    } else {
	/* Domain style names, with common suffix.  */
	if (p2[0] == '/') {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	if (memcmp (p1, p2 + (len2 - len1), len1)) {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	for (i = len2 - len1 - 1; i > 0; i--) {
	    if (p2[i-1] == '.') {
		krb5_data d;
		krb5_error_code r;

		d.data = p2+i;
		d.length = len2 - i;
		r = (*fn) (&d, data);
		if (r)
		    return r;
	    }
	}
    }
    return 0;
}

static krb5_error_code
maybe_join (krb5_data *last, krb5_data *buf, int bufsiz)
{
    if (buf->length == 0)
	return 0;
    if (buf->data[0] == '/') {
	if (last->length + buf->length > bufsiz) {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	memmove (buf->data+last->length, buf->data, buf->length);
	memcpy (buf->data, last->data, last->length);
	buf->length += last->length;
    } else if (buf->data[buf->length-1] == '.') {
	/* We can ignore the case where the previous component was
	   empty; the strcat will be a no-op.  It should probably
	   be an error case, but let's be flexible.  */
	if (last->length+buf->length > bufsiz) {
	    return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
	memcpy (buf->data + buf->length, last->data, last->length);
	buf->length += last->length;
    }
    /* Otherwise, do nothing.  */
    return 0;
}

/* The input strings cannot contain any \0 bytes, according to the
   spec, but our API is such that they may not be \0 terminated
   either.  Thus we keep on treating them as krb5_data objects instead
   of C strings.  */
static krb5_error_code
foreach_realm (krb5_error_code (*fn)(krb5_data *comp,void *data), void *data,
	       const krb5_data *crealm, const krb5_data *srealm,
	       const krb5_data *transit)
{
    char buf[MAXLEN], last[MAXLEN];
    char *p, *bufp;
    int next_lit, intermediates, l;
    krb5_data this_component;
    krb5_error_code r;
    krb5_data last_component;

    /* Invariants:
       - last_component points to last[]
       - this_component points to buf[]
       - last_component has length of last
       - this_component has length of buf when calling out
       Keep these consistent, and we should be okay.  */

    next_lit = 0;
    intermediates = 0;
    memset (buf, 0, sizeof (buf));

    this_component.data = buf;
    last_component.data = last;
    last_component.length = 0;

    if (transit->length == 0) {
	return 0;
    }

    bufp = buf;
    for (p = transit->data, l = transit->length; l; p++, l--) {
	if (next_lit) {
	    *bufp++ = *p;
	    if (bufp == buf+sizeof(buf))
		return KRB5KRB_AP_ERR_ILL_CR_TKT;
	    next_lit = 0;
	} else if (*p == '\\') {
	    next_lit = 1;
	} else if (*p == ',') {
	    if (bufp != buf) {
		this_component.length = bufp - buf;
		r = maybe_join (&last_component, &this_component, sizeof(buf));
		if (r)
		    return r;
		r = (*fn) (&this_component, data);
		if (r)
		    return r;
		if (intermediates) {
		    if (p == transit->data)
			r = process_intermediates (fn, data,
						   &this_component, crealm);
		    else {
			r = process_intermediates (fn, data, &this_component,
						   &last_component);
		    }
		    if (r)
			return r;
		}
		intermediates = 0;
		memcpy (last, buf, sizeof (buf));
		last_component.length = this_component.length;
		memset (buf, 0, sizeof (buf));
		bufp = buf;
	    } else {
		intermediates = 1;
		if (p == transit->data) {
		    if (crealm->length >= MAXLEN)
			return KRB5KRB_AP_ERR_ILL_CR_TKT;
		    memcpy (last, crealm->data, crealm->length);
		    last[crealm->length] = '\0';
		    last_component.length = crealm->length;
		}
	    }
	} else if (*p == ' ' && bufp == buf) {
	    /* This next component stands alone, even if it has a
	       trailing dot or leading slash.  */
	    memset (last, 0, sizeof (last));
	    last_component.length = 0;
	} else {
	    /* Not a special character; literal.  */
	    *bufp++ = *p;
	    if (bufp == buf+sizeof(buf))
		return KRB5KRB_AP_ERR_ILL_CR_TKT;
	}
    }
    /* At end.  Must be normal state.  */
    /* Process trailing element or comma.  */
    if (bufp == buf) {
	/* Trailing comma.  */
	r = process_intermediates (fn, data, &last_component, srealm);
    } else {
	/* Trailing component.  */
	this_component.length = bufp - buf;
	r = maybe_join (&last_component, &this_component, sizeof(buf));
	if (r)
	    return r;
	r = (*fn) (&this_component, data);
	if (r)
	    return r;
	if (intermediates)
	    r = process_intermediates (fn, data, &this_component,
				       &last_component);
    }
    if (r != 0)
	return r;
    return 0;
}


struct check_data {
    krb5_context ctx;
    krb5_principal *tgs;
};

static int
same_data (krb5_data *d1, krb5_data *d2)
{
    return (d1->length == d2->length
	    && !memcmp (d1->data, d2->data, d1->length));
}

static krb5_error_code
check_realm_in_list (krb5_data *realm, void *data)
{
    struct check_data *cdata = data;
    int i;

    for (i = 0; cdata->tgs[i]; i++) {
	if (same_data (krb5_princ_realm (cdata->ctx, cdata->tgs[i]), realm))
	    return 0;
    }
    return KRB5KRB_AP_ERR_ILL_CR_TKT;
}

krb5_error_code
krb5_check_transited_list (krb5_context ctx, const krb5_data *trans_in,
			   const krb5_data *crealm, const krb5_data *srealm)
{
    krb5_data trans;
    struct check_data cdata;
    krb5_error_code r;

    /* 
     * Work around buggy implementations that include NULL terminator in length.
     */
    trans.length = trans_in->length;
    trans.data = (char *) trans_in->data;
    if (trans.length && (trans.data[trans.length-1] == '\0'))
	trans.length--;

    if (trans.length == 0)
	return 0;

    r = krb5_walk_realm_tree (ctx, crealm, srealm, &cdata.tgs,
			      KRB5_REALM_BRANCH_CHAR);
    if (r) {
	return r;
    }
#ifdef DEBUG /* avoid compiler warning about 'd' unused */
    {
	int i;
	for (i = 0; cdata.tgs[i]; i++) {
	    char *name;
	    r = krb5_unparse_name (ctx, cdata.tgs[i], &name);
	    free (name);
	}
    }
#endif
    cdata.ctx = ctx;
    r = foreach_realm (check_realm_in_list, &cdata, crealm, srealm, &trans);
    krb5_free_realm_tree (ctx, cdata.tgs);
    return r;
}
