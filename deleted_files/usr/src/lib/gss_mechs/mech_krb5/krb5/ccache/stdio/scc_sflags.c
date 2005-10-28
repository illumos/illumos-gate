#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/stdio/scc_sflags.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_set_flags.
 */



#include "scc.h"

/*
 * Requires:
 * id is a cred cache returned by krb5_scc_resolve or
 * krb5_scc_generate_new, but has not been opened by krb5_scc_initialize.
 *
 * Modifies:
 * id
 * 
 * Effects:
 * Sets the operational flags of id to flags.
 */
krb5_error_code
krb5_scc_set_flags(context, id, flags)
   krb5_context context;
   krb5_ccache id;
   krb5_flags flags;
{
    krb5_error_code ret = 0;

    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id))
	    ret = krb5_scc_close_file (context, id);
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
	if (OPENCLOSE(id)) {
	    ret = krb5_scc_open_file (context, id, SCC_OPEN_RDWR);
	}
    }

    ((krb5_scc_data *) id->data)->flags = flags;
    return ret;
}

