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
 *  Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/note.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/callb.h>
#include <sys/hotplug/pci/pciehpc_impl.h>

extern int pciehpc_acpi_hotplug_enabled(dev_info_t *dip);
extern void pciehpc_acpi_setup_ops(pciehpc_t *ctrl_p);

/*
 * Update ops vector with platform specific (ACPI, CK8-04,...) functions.
 */
void
pciehpc_update_ops(pciehpc_t *ctrl_p)
{
	/* update platform specific (ACPI, CK8-04,...) impl. ops */
	if (pciehpc_acpi_hotplug_enabled(ctrl_p->dip)) {
		/* update ops vector for ACPI mode */
		pciehpc_acpi_setup_ops(ctrl_p);
		ctrl_p->hp_mode = PCIEHPC_ACPI_HP_MODE;
	}
}
