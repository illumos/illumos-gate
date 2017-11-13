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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/systm.h>

/*ARGSUSED*/
kstat_t *
kstat_create_zone(const char *ks_module, int ks_instance, const char *ks_name,
    const char *ks_class, uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags,
    zoneid_t ks_zoneid)
{
	return (NULL);
}

/*ARGSUSED*/
kstat_t *
kstat_create(const char *ks_module, int ks_instance, const char *ks_name,
    const char *ks_class, uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags)
{
	return (NULL);
}

/*ARGSUSED*/
void
kstat_named_init(kstat_named_t *knp, const char *name, uchar_t type)
{}

/*ARGSUSED*/
void
kstat_install(kstat_t *ksp)
{}

/*ARGSUSED*/
void
kstat_delete(kstat_t *ksp)
{}

/*ARGSUSED*/
void
kstat_waitq_enter(kstat_io_t *kiop)
{}

/*ARGSUSED*/
void
kstat_waitq_exit(kstat_io_t *kiop)
{}

/*ARGSUSED*/
void
kstat_runq_enter(kstat_io_t *kiop)
{}

/*ARGSUSED*/
void
kstat_runq_exit(kstat_io_t *kiop)
{}

/*ARGSUSED*/
void
kstat_waitq_to_runq(kstat_io_t *kiop)
{}

/*ARGSUSED*/
void
kstat_runq_back_to_waitq(kstat_io_t *kiop)
{}
