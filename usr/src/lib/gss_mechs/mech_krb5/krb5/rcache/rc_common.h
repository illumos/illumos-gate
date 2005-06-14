/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KRB5_RC_COM_H
#define	_KRB5_RC_COM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mech_krb5/krb5/rcache/rc_common.h
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 */

#include "rc_base.h"
#include "rc_io.h"
#include <k5-int.h>

/*
 * Declarations shared for the file and memory replay cache implementation.
 */

#ifndef HASHSIZE
#define	HASHSIZE 997 /* a convenient prime */
#endif

#define	CMP_MALLOC -3
#define	CMP_EXPIRED -2
#define	CMP_REPLAY -1
#define	CMP_HOHUM 0

/*
 * Solaris: made cmp a macro and removed unused t arg to help perf
 */
#define	cmp(old, new) \
	(((old)->cusec == (new)->cusec) && \
	((old)->ctime == (new)->ctime) && \
	(strcmp((old)->client, (new)->client) == 0) && \
	(strcmp((old)->server, (new)->server) == 0) ? CMP_REPLAY : CMP_HOHUM)

/*
 * Solaris: made alive a macro and time a arg instead of calling
 * krb5_timeofday() for better perf.
 */
#define	alive(context, new, t, time) \
	(((new)->ctime + (t)) < (time) ? CMP_EXPIRED : CMP_HOHUM)

struct authlist {
	krb5_donot_replay rep;
	struct authlist *na;
	struct authlist *nh;
};

int hash(krb5_donot_replay *rep, int hsize);

#ifdef __cplusplus
}
#endif

#endif /* !_KRB5_RC_COM_H */
