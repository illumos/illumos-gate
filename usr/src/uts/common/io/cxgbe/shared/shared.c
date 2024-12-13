/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/cmn_err.h>

#include "shared.h"

int
cxgb_printf(dev_info_t *dip, int level, char *f, ...)
{
	va_list list;
	char fmt[128];
	int rv;

	rv = snprintf(fmt, sizeof (fmt), "%s%d: %s", ddi_driver_name(dip),
	    ddi_get_instance(dip), f);
	va_start(list, f);
	vcmn_err(level, fmt, list);
	va_end(list);
	return (rv);
}
