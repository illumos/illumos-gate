/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/os/ccdefname.c
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
 * Return default cred. cache name.
 */

/*
 * SUNW14resync - because of changes specific to Solaris, future
 * resyncs should leave this file "as is" if possible.
 */

#include <k5-int.h>
#include <stdio.h>

/*
 * Solaris kerberos:  use dirent.h to get maximum filename length MAXNAMLEN
 */
#include <dirent.h>

static krb5_error_code get_from_os(
	char *name_buf,
	int name_size)
{
	krb5_error_code retval;

	/*
	 * Solaris Kerberos
	 * Use krb5_getuid() to select the mechanism to obtain the uid.
	 */
	retval = snprintf(name_buf, name_size, "FILE:/tmp/krb5cc_%d",
	    krb5_getuid());
	KRB5_LOG(KRB5_INFO, "get_from_os() FILE=%s\n", name_buf);
	if (retval < 0)
		return retval;
	else
		return 0;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_cc_set_default_name(
	krb5_context context,
	const char *name)
{
	char name_buf[MAXNAMLEN];
	char *new_name = getenv(KRB5_ENV_CCNAME);
	int name_length;
	krb5_error_code retval;
	krb5_os_context os_ctx;

	if (!context || context->magic != KV5M_CONTEXT)
		return KV5M_CONTEXT;

	os_ctx = context->os_context;
	
	/*
	 * Solaris kerberos:
	 * Use the following in this order
	 *	1) name from arg
	 *	2) name from environment variable
	 *	3) name from os based on UID
	 * resulting string is pointed to by name
	 */

	if (!name) {
		/* use environment variable or default */
		if (new_name != 0) { /* so that it is in env variable */
			name = new_name;
		} else {
			retval = get_from_os(name_buf, sizeof(name_buf));
			if (retval)
				return retval;
			name = name_buf;
		}
	}

	name_length = strlen(name);
	if (name_length >= MAXNAMLEN || name_length <=0) {
		KRB5_LOG(KRB5_ERR, "krb5_cc_set_default_name() "
			"bad file size %d\n", name_length);
		return -1;
	}
	new_name = malloc(name_length+1);
        if (!new_name)
		return ENOMEM;
	strcpy(new_name, name);

	if (os_ctx->default_ccname)
		free(os_ctx->default_ccname);

	os_ctx->default_ccname = new_name;
	return 0;
}

	
const char * KRB5_CALLCONV
krb5_cc_default_name(krb5_context context)
{
	krb5_os_context os_ctx;

	if (!context || context->magic != KV5M_CONTEXT)
		return NULL;

	os_ctx = context->os_context;

	/*
	 * Solaris kerberos:  this is a bug fix for service principals.
	 * We need to always fetch the ccache name.
	 */
	krb5_cc_set_default_name(context, NULL);

	KRB5_LOG(KRB5_INFO, "krb5_cc_default_name() FILE=%s\n",
        	os_ctx->default_ccname);

	return(os_ctx->default_ccname);
}
