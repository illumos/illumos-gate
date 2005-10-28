/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/keytab/file/ktf_remove.c
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
 * krb5_ktfile_add()
 */

#include <k5-int.h>
#include "ktfile.h"

krb5_error_code KRB5_CALLCONV
krb5_ktfile_remove(context, id, entry)
    krb5_context context;
krb5_keytab id;
krb5_keytab_entry *entry;
{
    krb5_keytab_entry   cur_entry;
    krb5_error_code     kerror;
    krb5_int32          delete_point;

    if ((kerror = krb5_ktfileint_openw(context, id))) {
	return kerror;
    }

    /*
     * For efficiency and simplicity, we'll use a while true that
     * is exited with a break statement.
     */
    /*LINTED*/
    while (TRUE) {
	if ((kerror = krb5_ktfileint_internal_read_entry(context, id,
							 &cur_entry,
							 &delete_point)))
  	    break;

	if ((entry->vno == cur_entry.vno) &&
            (entry->key.enctype == cur_entry.key.enctype) &&
	    krb5_principal_compare(context, entry->principal, cur_entry.principal)) {
	    /* found a match */
            krb5_kt_free_entry(context, &cur_entry);
	    break;
	}
	krb5_kt_free_entry(context, &cur_entry);
    }

    if (kerror == KRB5_KT_END)
	kerror = KRB5_KT_NOTFOUND;

    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
	return kerror;
    }

    kerror = krb5_ktfileint_delete_entry(context, id, delete_point);

    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
    } else {
        kerror = krb5_ktfileint_close(context, id);
    }

    return kerror;
}
