/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/unparse.c
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
 * permission.  M.I.T. makes no representations about the suitability of
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
#ifndef	_KERNEL
#include <stdio.h>
#endif

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

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_unparse_name_ext(krb5_context context, krb5_const_principal principal, register char **name, unsigned int *size)
{
	register char *cp, *q;
	register int i,j;
	int	length;
	krb5_int32 nelem;
	register unsigned int totalsize = 0;

	if (!principal || !name)
		return KRB5_PARSE_MALFORMED;

	cp = krb5_princ_realm(context, principal)->data;
	length = krb5_princ_realm(context, principal)->length;
	totalsize += length;
	for (j = 0; j < length; j++,cp++)
		if (*cp == REALM_SEP  || *cp == COMPONENT_SEP ||
		    *cp == '\0' || *cp == '\\' || *cp == '\t' ||
		    *cp == '\n' || *cp == '\b')
			totalsize++;
	totalsize++;		/* This is for the separator */

	nelem = krb5_princ_size(context, principal);
	for (i = 0; i < (int) nelem; i++) {
		cp = krb5_princ_component(context, principal, i)->data;
		length = krb5_princ_component(context, principal, i)->length;
		totalsize += length;
		for (j=0; j < length; j++,cp++)
			if (*cp == REALM_SEP || *cp == COMPONENT_SEP ||
			    *cp == '\0' || *cp == '\\' || *cp == '\t' ||
			    *cp == '\n' || *cp == '\b')
				totalsize++;
		totalsize++;	/* This is for the separator */
	}
	if (nelem == 0)
		totalsize++;

	/*
	 * Allocate space for the ascii string; if space has been
	 * provided, use it, realloc'ing it if necessary.
	 * 
	 * We need only n-1 seperators for n components, but we need
	 * an extra byte for the NULL at the end.
	 */
	/*The realloc case seems to be bogus 
	* We never pass non-null name 
	*/

	/* if (*name) {
		if (*size < (totalsize)) {
			*size = totalsize;
			*name = realloc(*name, totalsize);
		}
	   } else { 
	*/

	*name = MALLOC(totalsize);
	if (size)
		*size = totalsize;
	
	if (!*name)
		return ENOMEM;

	q = *name;
	
	for (i = 0; i < (int) nelem; i++) {
		cp = krb5_princ_component(context, principal, i)->data;
		length = krb5_princ_component(context, principal, i)->length;
		for (j=0; j < length; j++,cp++) {
		    switch (*cp) {
		    case COMPONENT_SEP:
		    case REALM_SEP:
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
		    case '\0':
			*q++ = '\\';
			*q++ = '0';
			break;
		    default:
			*q++ = *cp;
		    }
		}
		*q++ = COMPONENT_SEP;
	}

	if (i > 0)
	    q--;		/* Back up last component separator */
	*q++ = REALM_SEP;
	
	cp = krb5_princ_realm(context, principal)->data;
	length = krb5_princ_realm(context, principal)->length;
	for (j=0; j < length; j++,cp++) {
		switch (*cp) {
		case COMPONENT_SEP:
		case REALM_SEP:
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
		case '\0':
			*q++ = '\\';
			*q++ = '0';
			break;
		default:
			*q++ = *cp;
		}
	}
	*q++ = '\0';
	
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_unparse_name(krb5_context context, krb5_const_principal principal, register char **name)
{
        if (name)                       /* name == NULL will return error from _ext */
            *name = NULL;
	return(krb5_unparse_name_ext(context, principal, name, NULL));
}

