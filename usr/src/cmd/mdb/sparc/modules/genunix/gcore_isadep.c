/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * ::gcore is not supported on sparc, so these functions are not
 * implemented.
 */

#ifndef _KMDB

#include <mdb/mdb_gcore.h>

/* ARGSUSED */
uintptr_t
gcore_prgetstackbase(mdb_proc_t *p)
{
	return (0);
}

/* ARGSUSED */
int
gcore_prfetchinstr(mdb_klwp_t *lwp, ulong_t *ip)
{
	return (0);
}

/* ARGSUSED */
int
gcore_prisstep(mdb_klwp_t *lwp)
{
	return (0);
}

/* ARGSUSED */
void
gcore_getgregs(mdb_klwp_t *lwp, gregset_t grp)
{
}

/* ARGSUSED */
int
gcore_prgetrvals(mdb_klwp_t *lwp, long *rval1, long *rval2)
{
	return (0);
}

#endif /* _KMDB */
