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
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Wrappers around the common id_space code, for userland.
 */
#include <sys/id_space.h>

id_t
id_alloc_specific(id_space_t *idp, id_t id)
{
	return (id_alloc_specific_nosleep(idp, id));
}
