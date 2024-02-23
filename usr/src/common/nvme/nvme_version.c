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

/*
 * Common definitions and values for NVMe version use.
 */

#include "nvme_common.h"

const nvme_version_t nvme_vers_1v0 = { .v_major = 1, .v_minor = 0 };
const nvme_version_t nvme_vers_1v1 = { .v_major = 1, .v_minor = 1 };
const nvme_version_t nvme_vers_1v2 = { .v_major = 1, .v_minor = 2 };
const nvme_version_t nvme_vers_1v3 = { .v_major = 1, .v_minor = 3 };
const nvme_version_t nvme_vers_1v4 = { .v_major = 1, .v_minor = 4 };
const nvme_version_t nvme_vers_2v0 = { .v_major = 2, .v_minor = 0 };

bool
nvme_vers_atleast(const nvme_version_t *dev, const nvme_version_t *targ)
{
	return (dev->v_major > targ->v_major ||
	    (dev->v_major == targ->v_major && dev->v_minor >= targ->v_minor));
}
