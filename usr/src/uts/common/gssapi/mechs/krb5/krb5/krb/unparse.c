/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/unparse.c
 *
 * Copyright 1990, 2008 by the Massachusetts Institute of Technology.
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
 * krb5_unparse_name() routine
 *
 * Rewritten by Theodore Ts'o to properly unparse principal names
 * which have the component or realm separator as part of one of their
 * components.
 */


#include "k5-int.h"
#ifndef _KERNEL
#include <stdio.h>
#endif

/*
 * SUNW17PACresync / Solaris Kerberos
 * This realloc works for both Solaris kernel and user space.
 */
void *
krb5int_realloc(
		void *oldp,
		size_t new_size,
		size_t old_size)
{
#ifdef _KERNEL
    char *newp = MALLOC(new_size);

    bcopy(oldp, newp, old_size < new_size ? old_size : new_size);
    FREE(oldp, old_size);

    return (newp);
#else
    return (realloc(oldp, new_size));
#endif
}

/*
 * converts the multi-part principal format used in the protocols to a
 * single-string representation of the name. 
 *  
 * The name returned is in allocated storage and should be freed by
 * the caller when finished.
 *
 * Conventions: / is used to separate components; @ is used to
 * separate the realm from the rest of the name.  If '/', '@', or '\0'
 * appear in any the component, they will be representing using
 * backslash encoding.  ("\/", "\@", or '\0', respectively)
 *
 * returns error
 *	KRB_PARSE_MALFORMED	principal is invalid (does not contain
 *				at least 2 components)
 * also returns system errors
 *	ENOMEM			unable to allocate memory for string
 */

#define REALM_SEP	'@'
#define	COMPONENT_SEP	'/'

static int
component_length_quoted(const krb5_data *src, int flags)
{
    const char *cp = src->data;
    int length = src->length;
    int j;
    int size = length;

    if ((flags & KRB5_PRINCIPAL_UNPARSE_DISPLAY) == 0) {
	int no_realm = (flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) &&
		       !(flags & KRB5_PRINCIPAL_UNPARSE_SHORT);

	for (j = 0; j < length; j++,cp++)
	    if ((!no_realm && *cp == REALM_SEP) ||
		*cp == COMPONENT_SEP ||
		*cp == '\0' || *cp == '\\' || *cp == '\t' ||
		*cp == '\n' || *cp == '\b')
		size++;
    }

    return size;
}

static int
copy_component_quoting(char *dest, const krb5_data *src, int flags)
{
    int j;
    const char *cp = src->data;
    char *q = dest;
    int length = src->length;

    if (flags & KRB5_PRINCIPAL_UNPARSE_DISPLAY) {
        (void) memcpy(dest, src->data, src->length);
	return src->length;
    }

    for (j=0; j < length; j++,cp++) {
	int no_realm = (flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) &&
		       !(flags & KRB5_PRINCIPAL_UNPARSE_SHORT);

	switch (*cp) {
	case REALM_SEP:
	    if (no_realm) {
		*q++ = *cp;
		break;
	    }
	/* FALLTHROUGH */
	case COMPONENT_SEP:
	case '\\':
	    *q++ = '\\';
	    *q++ = *cp;
	    break;
	case '\t':
	    *q++ = '\\';
	    *q++ = 't';
	    break;
	case '\n':
	    *q++ = '\\';
	    *q++ = 'n';
	    break;
	case '\b':
	    *q++ = '\\';
	    *q++ = 'b';
	    break;
#if 0
	/* Heimdal escapes spaces in principal names upon unparsing */
	case ' ':
	    *q++ = '\\';
	    *q++ = ' ';
	    break;
#endif
	case '\0':
	    *q++ = '\\';
	    *q++ = '0';
	    break;
	default:
	    *q++ = *cp;
	}
    }
    /*LINTED*/
    return q - dest;
}

static krb5_error_code
/*LINTED*/
k5_unparse_name(krb5_context context, krb5_const_principal principal,
		int flags, char **name, unsigned int *size)
{
#if 0
	/* SUNW17PACresync - lint - cp/length not used */
        char *cp;
        int	length;
#endif
	char *q;
	int i;
	krb5_int32 nelem;
	unsigned int totalsize = 0;
#ifndef _KERNEL
	/* SUNW17PACresync - princ in kernel will always have realm */
	char *default_realm = NULL;
#endif
	krb5_error_code ret = 0;

	if (!principal || !name)
		return KRB5_PARSE_MALFORMED;

#ifndef _KERNEL
	if (flags & KRB5_PRINCIPAL_UNPARSE_SHORT) {
		/* omit realm if local realm */
		krb5_principal_data p;

		ret = krb5_get_default_realm(context, &default_realm);
		if (ret != 0)
			goto cleanup;

		krb5_princ_realm(context, &p)->length = strlen(default_realm);
		krb5_princ_realm(context, &p)->data = default_realm;

		if (krb5_realm_compare(context, &p, principal))
			flags |= KRB5_PRINCIPAL_UNPARSE_NO_REALM;
	}
#endif
	if ((flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) == 0) {
		totalsize += component_length_quoted(krb5_princ_realm(context,
								      principal),
						     flags);
		totalsize++;		/* This is for the separator */
	}

	nelem = krb5_princ_size(context, principal);
	for (i = 0; i < (int) nelem; i++) {
#if 0
		/* SUNW17PACresync - lint - cp not used */
		cp = krb5_princ_component(context, principal, i)->data;
#endif
		totalsize += component_length_quoted(krb5_princ_component(context, principal, i), flags);
		totalsize++;	/* This is for the separator */
	}
	if (nelem == 0)
		totalsize++;

	/*
	 * Allocate space for the ascii string; if space has been
	 * provided, use it, realloc'ing it if necessary.
	 * 
	 * We need only n-1 seperators for n components, but we need
	 * an extra byte for the NUL at the end.
	 */

        if (size) {
            if (*name && (*size < totalsize)) {
	        /* SUNW17PACresync - works for both kernel&user */
	        *name = krb5int_realloc(*name, totalsize, *size);
            } else {
                *name = MALLOC(totalsize);
            }
            *size = totalsize;
        } else {
            *name = MALLOC(totalsize);
        }

	if (!*name) {
		ret = ENOMEM;
		goto cleanup;
	}

	q = *name;
	
	for (i = 0; i < (int) nelem; i++) {
#if 0
		/* SUNW17PACresync - lint - cp/length not used */
		cp = krb5_princ_component(context, principal, i)->data;
		length = krb5_princ_component(context, principal, i)->length;
#endif
		q += copy_component_quoting(q,
					    krb5_princ_component(context,
								 principal,
								 i),
					    flags);
		*q++ = COMPONENT_SEP;
	}

	if (i > 0)
	    q--;		/* Back up last component separator */
	if ((flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) == 0) {
		*q++ = REALM_SEP;
		q += copy_component_quoting(q, krb5_princ_realm(context, principal), flags);
	}
	*q++ = '\0';

cleanup:
#ifndef _KERNEL
	if (default_realm != NULL)
		krb5_free_default_realm(context, default_realm);
#endif
	return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_unparse_name(krb5_context context, krb5_const_principal principal, register char **name)
{
    if (name != NULL)                      /* name == NULL will return error from _ext */
	*name = NULL;

    return k5_unparse_name(context, principal, 0, name, NULL);
}

krb5_error_code KRB5_CALLCONV
krb5_unparse_name_ext(krb5_context context, krb5_const_principal principal,
		      char **name, unsigned int *size)
{
    return k5_unparse_name(context, principal, 0, name, size);
}

krb5_error_code KRB5_CALLCONV
krb5_unparse_name_flags(krb5_context context, krb5_const_principal principal,
			int flags, char **name)
{
    if (name != NULL)
	*name = NULL;
    return k5_unparse_name(context, principal, flags, name, NULL);
}

krb5_error_code KRB5_CALLCONV
krb5_unparse_name_flags_ext(krb5_context context, krb5_const_principal principal,
			    int flags, char **name, unsigned int *size)
{
    return k5_unparse_name(context, principal, flags, name, size);
}

