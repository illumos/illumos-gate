/*
 * kdc/extern.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * allocations of extern stuff
 */



#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "k5-int.h"
#include "extern.h"

/* real declarations of KDC's externs */
kdc_realm_t	**kdc_realmlist = (kdc_realm_t **) NULL;
int		kdc_numrealms = 0;
kdc_realm_t	*kdc_active_realm = (kdc_realm_t *) NULL;
krb5_data empty_string = {0, 0, ""};
krb5_timestamp kdc_infinity = KRB5_KDB_EXPIRATION;
krb5_rcache	kdc_rcache = (krb5_rcache) NULL;
krb5_keyblock	psr_key;

volatile int signal_requests_exit = 0;	/* gets set when signal hits */
volatile int signal_requests_hup = 0;   /* ditto */
