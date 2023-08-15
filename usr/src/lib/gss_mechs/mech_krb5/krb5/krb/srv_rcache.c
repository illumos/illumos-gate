/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/krb/srv_rcache.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Allocate & prepare a default replay cache for a server.
 */

#include "k5-int.h"
#include <ctype.h>
#include <stdio.h>

/* Macro for valid RC name characters*/
#define isvalidrcname(x) ((!ispunct(x))&&isgraph(x))
krb5_error_code KRB5_CALLCONV
krb5_get_server_rcache(krb5_context context, const krb5_data *piece,
		       krb5_rcache *rcptr)
{
    krb5_rcache rcache = 0;
    char *cachename = 0, *def_env = 0, *cachetype;
    char tmp[4], *full_name;
    krb5_error_code retval;
    int p, i;
    unsigned int len;

#ifdef HAVE_GETEUID
    unsigned long tens;
    unsigned long uid = geteuid();
#endif

    if (piece == NULL)
	return ENOMEM;

    cachetype = krb5_rc_default_type(context);

    /*
     * Solaris Kerberos: Check to see if something other than the default replay
     * cache name will be used.  If so then skip over the construction of
     * said name.
     */
    if ((def_env = krb5_rc_default_name(context)) != 0) {
	cachename = strdup(def_env);
	if (cachename == NULL)
		return (ENOMEM);
	/*
	 * We expect to have the fully qualified rcache name (<type>:<name>),
	 * so we populate the default type here if the type is missing.
	 */
	if (strchr(cachename, ':') == NULL) {
		full_name = malloc(strlen(cachetype) + 1 +
				   strlen(cachename) + 1);
		if (full_name == NULL) {
			free(cachename);
			return(ENOMEM);
		}
		(void) sprintf(full_name, "%s:%s", cachetype, cachename);
		free(cachename);
		cachename = full_name;
	}
	goto skip_create;
    }

    len = piece->length + 3 + 1;
    for (i = 0; i < piece->length; i++) {
	if (piece->data[i] == '-')
	    len++;
	else if (!isvalidrcname((int) piece->data[i]))
	    len += 3;
    }

#ifdef HAVE_GETEUID
    len += 2;	/* _<uid> */
    for (tens = 1; (uid / tens) > 9 ; tens *= 10)
	len++;
#endif

    cachename = malloc(strlen(cachetype) + 5 + len);
    if (!cachename) {
	retval = ENOMEM;
	goto cleanup;
    }
    strcpy(cachename, cachetype);

    p = strlen(cachename);
    cachename[p++] = ':';
    for (i = 0; i < piece->length; i++) {
	if (piece->data[i] == '-') {
	    cachename[p++] = '-';
	    cachename[p++] = '-';
	    continue;
	}
	if (!isvalidrcname((int) piece->data[i])) {
	    sprintf(tmp, "%03o", piece->data[i]);
	    cachename[p++] = '-';
	    cachename[p++] = tmp[0];
	    cachename[p++] = tmp[1];
	    cachename[p++] = tmp[2];
	    continue;
	}
	cachename[p++] = piece->data[i];
    }

#ifdef HAVE_GETEUID
    cachename[p++] = '_';
    while (tens) {
	cachename[p++] = '0' + ((uid / tens) % 10);
	tens /= 10;
    }
#endif

    cachename[p++] = '\0';

skip_create:
    retval = krb5_rc_resolve_full(context, &rcache, cachename);
    if (retval) {
	rcache = 0;
	goto cleanup;
    }

    /*
     * First try to recover the replay cache; if that doesn't work,
     * initialize it.
     */
    retval = krb5_rc_recover_or_initialize(context, rcache, context->clockskew);
    if (retval) {
	krb5_rc_close(context, rcache);
	rcache = 0;
	goto cleanup;
    }

    *rcptr = rcache;
    rcache = 0;
    retval = 0;

cleanup:
    if (rcache)
	krb5_xfree(rcache);
    if (cachename)
	krb5_xfree(cachename);
    return retval;
}
