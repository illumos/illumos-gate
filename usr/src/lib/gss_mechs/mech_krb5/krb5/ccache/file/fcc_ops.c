#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_ops.c
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
 * This file contains the structure krb5_fcc_ops.
 */

#define NEED_WINDOWS
#include "fcc.h"

krb5_cc_ops krb5_fcc_ops = {
     0,
     "FILE",
     krb5_fcc_get_name,
     krb5_fcc_resolve,
     krb5_fcc_generate_new,
     krb5_fcc_initialize,
     krb5_fcc_destroy,
     krb5_fcc_close,
     krb5_fcc_store,
     krb5_fcc_retrieve,
     krb5_fcc_get_principal,
     krb5_fcc_start_seq_get,
     krb5_fcc_next_cred,
     krb5_fcc_end_seq_get,
     NULL, /* XXX krb5_fcc_remove, */
     krb5_fcc_set_flags,
};

#if defined(_MSDOS) || defined(_WIN32)

/*
 * krb5_change_cache should be called after the cache changes.
 * A notification message is is posted out to all top level
 * windows so that they may recheck the cache based on the
 * changes made.  We register a unique message type with which
 * we'll communicate to all other processes. 
 */

krb5_error_code 
krb5_change_cache (void) {

    PostMessage(HWND_BROADCAST, krb5_get_notification_message(), 0, 0);

    return 0;
}

KRB5_DLLIMP unsigned int KRB5_CALLCONV
krb5_get_notification_message (void) {
    static unsigned int message = 0;

    if (message == 0)
        message = RegisterWindowMessage(WM_KERBEROS5_CHANGED);

    return message;
}
#else /* _MSDOS || _WIN32 */

krb5_error_code
krb5_change_cache () 
{
    return 0;
}
unsigned int
krb5_get_notification_message ()
{
    return 0;
}

#endif /* _MSDOS || _WIN32 */

