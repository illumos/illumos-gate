#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/stdio/scc_ops.c
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
 * This file contains the structure krb5_scc_ops.
 */



#include "scc.h"

krb5_cc_ops krb5_scc_ops = {
     0,
     "STDIO",
     krb5_scc_get_name,
     krb5_scc_resolve,
     krb5_scc_generate_new,
     krb5_scc_initialize,
     krb5_scc_destroy,
     krb5_scc_close,
     krb5_scc_store,
     krb5_scc_retrieve,
     krb5_scc_get_principal,
     krb5_scc_start_seq_get,
     krb5_scc_next_cred,
     krb5_scc_end_seq_get,
     NULL, /* XXX krb5_scc_remove, */
     krb5_scc_set_flags,
};




     



