/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/gssapi/krb5/set_ccache.c
 *
 * Copyright 1999, 2003 by the Massachusetts Institute of Technology.
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
 * Set ccache name used by gssapi, and optionally obtain old ccache
 * name.  Caller should not free returned name.
 */

#include <string.h>
#include "gssapiP_krb5.h"
#include "gss_libinit.h"

OM_uint32 KRB5_CALLCONV
gss_krb5_ccache_name(minor_status, name, out_name)
	OM_uint32 *minor_status;
	const char *name;
	const char **out_name;
{
    char *old_name = NULL;
    OM_uint32 err = 0;
    OM_uint32 minor = 0;
    char *gss_out_name;

    err = gssint_initialize_library();
    if (err) {
	*minor_status = err;
	return GSS_S_FAILURE;
    }

    gss_out_name = k5_getspecific(K5_KEY_GSS_KRB5_SET_CCACHE_OLD_NAME);

    if (out_name) {
        const char *tmp_name = NULL;

        if (!err) {
            kg_get_ccache_name (&err, &tmp_name);
        }
        if (!err) {
            old_name = gss_out_name;
            /* Solaris Kerberos */
            gss_out_name = (char *)tmp_name;
        }
    }
    /* If out_name was NULL, we keep the same gss_out_name value, and
       don't free up any storage (leave old_name NULL).  */

    if (!err)
        kg_set_ccache_name (&err, name);

    minor = k5_setspecific(K5_KEY_GSS_KRB5_SET_CCACHE_OLD_NAME, gss_out_name);
    if (minor) {
	/* Um.  Now what?  */
	if (err == 0) {
	    err = minor;
	}
	free(gss_out_name);
	gss_out_name = NULL;
    }

    if (!err) {
        if (out_name) {
            *out_name = gss_out_name;
        }
    }

    if (old_name != NULL) {
        free (old_name);
    }

    *minor_status = err;
    return (*minor_status == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}
