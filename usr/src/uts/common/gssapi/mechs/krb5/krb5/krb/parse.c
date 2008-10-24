/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/parse.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_parse_name() routine.
 *
 * Rewritten by Theodore Ts'o to properly handle arbitrary quoted
 * characters in the principal name.
 */


#include "k5-int.h"

#ifndef _KERNEL
#include <assert.h>
#include <stdarg.h> 
#define ASSERT assert 
#endif

/*
 * converts a single-string representation of the name to the
 * multi-part principal format used in the protocols.
 *
 * principal will point to allocated storage which should be freed by 
 * the caller (using krb5_free_principal) after use.
 * 
 * Conventions:  / is used to separate components.  If @ is present in the
 * string, then the rest of the string after it represents the realm name.
 * Otherwise the local realm name is used.
 * 
 * error return:
 *	KRB5_PARSE_MALFORMED	badly formatted string
 *
 * also returns system errors:
 *	ENOMEM	malloc failed/out of memory
 *
 * get_default_realm() is called; it may return other errors.
 */

#define REALM_SEP	'@'
#define	COMPONENT_SEP	'/'
#define QUOTECHAR	'\\'

#define FCOMPNUM	10


/*
 * May the fleas of a thousand camels infest the ISO, they who think
 * that arbitrarily large multi-component names are a Good Thing.....
 */
/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_parse_name(krb5_context context, const char *name, krb5_principal *nprincipal)
{
	register const char	*cp;
	register char	*q;
	register int    i,c,size;
	int		components = 0;
	const char	*parsed_realm = NULL;
	int		fcompsize[FCOMPNUM];
	unsigned int	realmsize = 0;
#ifndef _KERNEL
	char		*default_realm = NULL;
	int		default_realm_size = 0;
	krb5_error_code retval;
#endif
	char		*tmpdata;
	krb5_principal	principal;

	/*
	 * Pass 1.  Find out how many components there are to the name,
	 * and get string sizes for the first FCOMPNUM components.
	 */
	size = 0;
	/*LINTED*/
	for (i = 0, cp = name; (c = *cp); cp++) {
		if (c == QUOTECHAR) {
			cp++;
			/*LINTED*/
			if (!(c = *cp))
				/*
				 * QUOTECHAR can't be at the last
				 * character of the name!
				 */
				return(KRB5_PARSE_MALFORMED);
			size++;
			continue;
		} else if (c == COMPONENT_SEP) {
			if (parsed_realm)
				/*
				 * Shouldn't see a component separator
				 * after we've parsed out the realm name!
				 */
				return(KRB5_PARSE_MALFORMED);
			if (i < FCOMPNUM) {
				fcompsize[i] = size;
			}
			size = 0;
			i++;
		} else if (c == REALM_SEP) {
			if (parsed_realm)
				/*
				 * Multiple realm separaters
				 * not allowed; zero-length realms are.
				 */
				return(KRB5_PARSE_MALFORMED);
			parsed_realm = cp+1;
			if (i < FCOMPNUM) {
				fcompsize[i] = size;
			}
			size = 0;
		} else
			size++;
	}
	if (parsed_realm)
		realmsize = size;
	else if (i < FCOMPNUM) 
		fcompsize[i] = size;
	components = i + 1;
	/*
	 * Now, we allocate the principal structure and all of its
	 * component pieces
	 */
	principal = (krb5_principal)MALLOC(sizeof(krb5_principal_data));
	if (!principal) {
		return(ENOMEM);
	}
	principal->data = (krb5_data *)MALLOC(sizeof(krb5_data) * components);
	if (!principal->data) {
	    krb5_xfree_wrap((char *)principal, sizeof(krb5_principal_data));
	    return ENOMEM;
	}
	principal->length = components;
	/*
	 * If a realm was not found, then use the defualt realm....
	 */
	/*
	 * In the kernel we import the ctx and it always contains the
	 * default realm
	 */

#ifndef _KERNEL
	if (!parsed_realm) {
	    if (!default_realm) {
		retval = krb5_get_default_realm(context, &default_realm);
		if (retval) {
		    krb5_xfree_wrap(principal->data,
			sizeof (krb5_data) * components);
		    krb5_xfree_wrap((char *)principal,
			sizeof (krb5_principal_data));
		    return(retval);
		}
		default_realm_size = strlen(default_realm);
	    }
	    realmsize = default_realm_size;
	}
#endif
	/*
	 * Pass 2.  Happens only if there were more than FCOMPNUM
	 * component; if this happens, someone should be shot
	 * immediately.  Nevertheless, we will attempt to handle said
	 * case..... <martyred sigh>
	 */
	if (components >= FCOMPNUM) {
		size = 0;
		parsed_realm = NULL;
		/*LINTED*/
		for (i=0,cp = name; (c = *cp); cp++) {
			if (c == QUOTECHAR) {
				cp++;
				size++;
			} else if (c == COMPONENT_SEP) {
				if (krb5_princ_size(context, principal) > i)
					krb5_princ_component(context, principal, i)->length = size;
				size = 0;
				i++;
			} else if (c == REALM_SEP) {
				if (krb5_princ_size(context, principal) > i)
					krb5_princ_component(context, principal, i)->length = size;
				size = 0;
				parsed_realm = cp+1;
			} else
				size++;
		}
		if (parsed_realm)
			krb5_princ_realm(context, principal)->length = size;
		else
			if (krb5_princ_size(context, principal) > i)
				krb5_princ_component(context, principal, i)->length = size;
		if (i + 1 != components) {
#ifndef _KERNEL
#if !defined(_WIN32)
		    fprintf(stderr,
			    "Programming error in krb5_parse_name!");
#endif
		    ASSERT(i + 1 == components);
		    abort();
#else
		    ASSERT(i + 1 == components);
#endif /* !_KERNEL */
		}
	} else {
		/*
		 * If there were fewer than FCOMPSIZE components (the
		 * usual case), then just copy the sizes to the
		 * principal structure
		 */
		for (i=0; i < components; i++)
			krb5_princ_component(context, principal, i)->length = fcompsize[i];
	}
	/*	
	 * Now, we need to allocate the space for the strings themselves.....
	 */
	tmpdata = MALLOC(realmsize+1);
	if (tmpdata == 0) {
		krb5_xfree_wrap(principal->data,
		    sizeof (krb5_data) * components);
		krb5_xfree_wrap((char *)principal,
		    sizeof (krb5_principal_data));
#ifndef _KERNEL
		if (default_realm)
			krb5_xfree_wrap(default_realm, strlen(default_realm));
#endif
		return (ENOMEM);
	}
	krb5_princ_set_realm_length(context, principal, realmsize);
	krb5_princ_set_realm_data(context, principal, tmpdata);
	for (i=0; i < components; i++) {
		char *tmpdata2 =
		  MALLOC(krb5_princ_component(context, principal, i)->length + 1);
		if (!tmpdata2) {
                        /*
                         * Release the principle and realm strings remembering
                         * that we allocated one additional byte beyond the
                         * 'length' to hold the string terminating zero byte.
                         * It's critical that the free size match the malloc
			 * size.
                         */
			for (i--; i >= 0; i--)
				krb5_xfree_wrap(krb5_princ_component(context,
				    principal, i)->data,
				    krb5_princ_component(context,
				    principal, i)->length + 1);
			krb5_xfree_wrap(krb5_princ_realm(context,
			    principal)->data, krb5_princ_realm(context,
			    principal)->length + 1);
			krb5_xfree_wrap(principal->data, principal->length);
			krb5_xfree_wrap(principal, sizeof(krb5_principal_data));
#ifndef _KERNEL
			if (default_realm)
				krb5_xfree_wrap(default_realm,
						strlen(default_realm));
#endif
			return (ENOMEM);
		}
		krb5_princ_component(context, principal, i)->data = tmpdata2;
		krb5_princ_component(context, principal, i)->magic = KV5M_DATA;
	}
	
	/*
	 * Pass 3.  Now we go through the string a *third* time, this
	 * time filling in the krb5_principal structure which we just
	 * allocated.
	 */
	q = krb5_princ_component(context, principal, 0)->data;
	/*LINTED*/
	for (i=0,cp = name; (c = *cp); cp++) {
		if (c == QUOTECHAR) {
			cp++;
			switch (c = *cp) {
			case 'n':
				*q++ = '\n';
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'b':
				*q++ = '\b';
				break;
			case '0':
				*q++ = '\0';
				break;
			default:
				*q++ = (char) c;
			}
		} else if ((c == COMPONENT_SEP) || (c == REALM_SEP)) {
			i++;
			*q++ = '\0';
			if (c == COMPONENT_SEP) 
				q = krb5_princ_component(context, principal, i)->data;
			else
				q = krb5_princ_realm(context, principal)->data;
		} else
			*q++ = (char) c;
	}
	*q++ = '\0';
	if (!parsed_realm)
#ifndef _KERNEL
		(void) strcpy(krb5_princ_realm(context, principal)->data,
			default_realm);
#endif
	/*
	 * Alright, we're done.  Now stuff a pointer to this monstrosity
	 * into the return variable, and let's get out of here.
	 */
	krb5_princ_type(context, principal) = KRB5_NT_PRINCIPAL;
	principal->magic = KV5M_PRINCIPAL;
	principal->realm.magic = KV5M_DATA;
	*nprincipal = principal;
#ifndef _KERNEL
	if (default_realm)
		krb5_xfree_wrap(default_realm, strlen(default_realm));
#endif
	return(0);
}
