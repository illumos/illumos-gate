#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/file/mcc_ops.c
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
 * This file contains the structure krb5_mcc_ops.
 */

#define NEED_WINDOWS
#include "mcc.h"

krb5_cc_ops krb5_mcc_ops = {
     0,
     "MEMORY",
     krb5_mcc_get_name,
     krb5_mcc_resolve,
     krb5_mcc_generate_new,
     krb5_mcc_initialize,
     krb5_mcc_destroy,
     krb5_mcc_close,
     krb5_mcc_store,
     krb5_mcc_retrieve,
     krb5_mcc_get_principal,
     krb5_mcc_start_seq_get,
     krb5_mcc_next_cred,
     krb5_mcc_end_seq_get,
     NULL, /* XXX krb5_mcc_remove, */
     krb5_mcc_set_flags,
};

krb5_mcc_data *mcc_head=0L;

