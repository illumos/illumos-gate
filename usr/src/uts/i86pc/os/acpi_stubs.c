/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 * This file contains ACPI functions that are needed by the kernel before
 * the ACPI module is loaded.  Any functions or definitions need to be
 * able to deal with the possibility that ACPI doesn't get loaded, or
 * doesn't contain the required method.
 */

int (*acpi_fp_setwake)();

/*
 *
 */
int
acpi_ddi_setwake(dev_info_t *dip, int level)
{
	if (acpi_fp_setwake == NULL)
		return (AE_ERROR);

	return ((*acpi_fp_setwake)(dip, level));
}
