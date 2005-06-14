/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/ccdefault.c
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
 * Find default credential cache
 */

#include <k5-int.h>

/*
 * Solaris Kerberos:  the following is specific to the Macintosh
 */
#if defined(USE_LOGIN_LIBRARY) && defined(macintosh)
#include <KerberosLoginInternal.h>
#endif

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_cc_default(context, ccache)
   krb5_context context;
   krb5_ccache FAR *ccache;
{
    krb5_error_code retval;
	krb5_os_context	os_ctx;

	if (!context || context->magic != KV5M_CONTEXT)
		return KV5M_CONTEXT;
	
	os_ctx = context->os_context;
	
    retval = krb5_cc_resolve(context, krb5_cc_default_name(context), ccache);
    if (!retval && ccache && !os_ctx->default_ccprincipal) {
    	/* We got a ccache... remember what principal is associated with it */
    	if (krb5_cc_get_principal (context, *ccache, &os_ctx->default_ccprincipal) != 0)
    		os_ctx->default_ccprincipal = 0;
    }
    return retval;
}

/* This is the internal function which opens the default ccache.  On platforms supporting
   the login library's automatic popup dialog to get tickets, this function also updated the
   library's internal view of the current principal associated with this cache.

   All krb5 and GSS functions which need to open a cache to get a tgt to obtain service tickets
   should call this function, not krb5_cc_default() */

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5int_cc_default(context, ccache)
	krb5_context context;
	krb5_ccache FAR *ccache;
{
/*
 * Solaris Kerberos:  the following is specific to the Macintosh
 */
#if defined(USE_LOGIN_LIBRARY) && defined(macintosh)
	{
		/* make sure the default cache has tix before you open it */
		char 				*outCacheName;
		KLPrincipal			desiredPrincipal = nil;
		krb5_principal		desiredKrb5Principal;
		krb5_error_code 	err;
		krb5_os_context		os_ctx;

		if (!context || context->magic != KV5M_CONTEXT)
			return KV5M_CONTEXT;
	
		os_ctx = context->os_context;
				
		desiredKrb5Principal = os_ctx->default_ccprincipal;
		
		/* do we want a specific client principal? */
		if (desiredKrb5Principal != NULL) {
			char		*desiredName;
			
			err = krb5_unparse_name (context, desiredKrb5Principal, &desiredName);
			if (!err) {
				err = KLCreatePrincipalFromString (desiredName,
								kerberosVersion_V5, &desiredPrincipal);
				krb5_free_unparsed_name (context, desiredName);
				if (err != klNoErr)
					desiredPrincipal = nil;
			}
		}
		
		/* Try to make sure a krb5 tgt is in the cache */
		err = __KLInternalAcquireTicketsForCache (desiredPrincipal, krb5_cc_default_name(context),
			kerberosVersion_V5, nil, &outCacheName);
		if (err == klNoErr) {
			/* This function tries to get tickets and put them in the specified
			   cache, however, if the cache does not exist, it may choose to put
			   them elsewhere (ie: the system default) so we set that here */
			if (strcmp (krb5_cc_default_name (context), outCacheName) != 0) {
				krb5_cc_set_default_name (context, outCacheName);
			}
			KLDisposeString (outCacheName);
		}
		
		if (desiredPrincipal != nil)
			KLDisposePrincipal (desiredPrincipal);
	}
#endif

    return krb5_cc_default (context, ccache);
}
