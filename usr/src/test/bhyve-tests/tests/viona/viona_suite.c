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
 * Copyright 2024 Oxide Computer Company
 */

#include <fcntl.h>
#include <libdladm.h>
#include <libdllink.h>

#include "viona_suite.h"

int
open_viona(void)
{
	return (open(VIONA_DEV, O_RDWR));
}

/* Convenience helper to get datalink_id_t from an interface name */
dladm_status_t
query_dlid(const char *name, datalink_id_t *dlid)
{
	dladm_handle_t hdl;
	dladm_status_t err;

	err = dladm_open(&hdl);
	if (err != DLADM_STATUS_OK) {
		dladm_close(hdl);
		return (err);
	}

	err = dladm_name2info(hdl, name, dlid, NULL, NULL, NULL);
	dladm_close(hdl);

	return (err);
}
