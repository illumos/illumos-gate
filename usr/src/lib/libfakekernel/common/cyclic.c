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
 * Copyright 2017 RackTop Systems.
 */

#include <sys/cyclic.h>

/* ARGSUSED */
cyclic_id_t
cyclic_add(cyc_handler_t *hdlr, cyc_time_t *when)
{
	return (1);
}

/* ARGSUSED */
void
cyclic_remove(cyclic_id_t id)
{
}

/* ARGSUSED */
int
cyclic_reprogram(cyclic_id_t id, hrtime_t expiration)
{
	return (1);
}
