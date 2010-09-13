/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/rcache/rc_common.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */

/*
 * An implementation for the common replay cache functions.
 */
#include "rc_common.h"

/*
 * Local stuff:
 *
 * static int hash(krb5_donot_replay *rep, int hsize)
 *  returns hash value of *rep, between 0 and hsize - 1
 */

int
hash(krb5_donot_replay *rep, int hsize)
{
	return ((int)((((rep->cusec + rep->ctime + *rep->server + *rep->client)
	    % hsize) + hsize) % hsize));
}
