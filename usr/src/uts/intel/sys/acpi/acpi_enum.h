/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ACPI enumerator
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

/* some externs */

int acpi_isa_device_enum(dev_info_t *isa_dip);
