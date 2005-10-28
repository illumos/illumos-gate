#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/os/get_krbhst.c
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
 * krb5_get_krbhst() function.
 */

#include <k5-int.h>
#include <stdio.h>
#include <ctype.h>

/*
 Figures out the Kerberos server names for the given realm, filling in a
 pointer to an argv[] style list of names, terminated with a null pointer.
 
 If the realm is unknown, the filled-in pointer is set to NULL.

 The pointer array and strings pointed to are all in allocated storage,
 and should be freed by the caller when finished.

 returns system errors
*/

/*
 * Implementation:  the server names for given realms are stored in a
 * configuration file, 
 * named by krb5_config_file;  the first token (on the first line) in
 * this file is taken as the default local realm name.
 * 
 * Each succeeding line has a realm name as the first token, and a server name
 * as a second token.  Additional tokens may be present on the line, but
 * are ignored by this function.
 *
 * All lines which begin with the desired realm name will have the
 * hostname added to the list returned.
 */

krb5_error_code
krb5_get_krbhst(krb5_context context, const krb5_data *realm, char ***hostlist)
{
    char	**values, **cpp, *cp;
    const char	*realm_kdc_names[4];
    krb5_error_code	retval;
    int	i, count;
    char **rethosts;

    rethosts = 0;

    realm_kdc_names[0] = "realms";
    realm_kdc_names[1] = realm->data;
    realm_kdc_names[2] = "kdc";
    realm_kdc_names[3] = 0;

    if (context->profile == 0)
	return KRB5_CONFIG_CANTOPEN;

    retval = profile_get_values(context->profile, realm_kdc_names, &values);
    if (retval == PROF_NO_SECTION)
	return KRB5_REALM_UNKNOWN;
    if (retval == PROF_NO_RELATION)
	return KRB5_CONFIG_BADFORMAT;
    if (retval)
	return retval;

    /*
     * Do cleanup over the list.  We allow for some extra field to be
     * added to the kdc line later (maybe the port number)
     */
    for (cpp = values; *cpp; cpp++) {
	cp = strchr(*cpp, ' ');
	if (cp)
	    *cp = 0;
	cp = strchr(*cpp, '\t');
	if (cp)
	    *cp = 0;
	cp = strchr(*cpp, ':');
	if (cp)
	    *cp = 0;
    }
    count = cpp - values;
    rethosts = malloc(sizeof(char *) * (count + 1));
    if (!rethosts) {
        retval = ENOMEM;
        goto cleanup;
    }
    for (i = 0; i < count; i++) {
	unsigned int len = strlen (values[i]) + 1;
        rethosts[i] = malloc(len);
        if (!rethosts[i]) {
            retval = ENOMEM;
            goto cleanup;
        }
	memcpy (rethosts[i], values[i], len);
    }
    rethosts[count] = 0;
 cleanup:
    if (retval && rethosts) {
        for (cpp = rethosts; *cpp; cpp++)
            free(*cpp);
        free(rethosts);
	rethosts = 0;
    }
    profile_free_list(values);
    *hostlist = rethosts;
    return retval;
}
