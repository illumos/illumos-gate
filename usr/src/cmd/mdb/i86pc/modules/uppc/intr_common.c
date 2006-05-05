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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "intr_common.h"
#include <sys/multidata.h>
#include <sys/gld.h>
#include <sys/gldpriv.h>


int		option_flags;
uintptr_t	gld_intr_addr;

void
interrupt_help(void)
{
	mdb_printf("Prints the interrupt usage on the system.\n"
	    "By default, only interrupt service routine names are printed.\n\n"
	    "Switches:\n"
	    "  -d   instead of ISR, print <driver_name><instance#>\n"
	    "  -i   show like intrstat, cpu# ISR/<driver_name><instance#>\n");
}

void
interrupt_print_isr(uintptr_t vector, uintptr_t arg1, uintptr_t dip)
{
	uintptr_t	isr_addr = vector;
	struct dev_info	dev_info;

	/*
	 * figure out the real ISR function name from gld_intr()
	 */
	if (isr_addr == gld_intr_addr) {
		gld_mac_info_t 	macinfo;

		if (mdb_vread(&macinfo, sizeof (gld_mac_info_t), arg1) != -1) {
			/* verify gld data structure and get the real ISR */
			if (macinfo.gldm_GLD_version == GLD_VERSION)
				isr_addr = (uintptr_t)macinfo.gldm_intr;
		}
	}

	if ((option_flags & INTR_DISPLAY_DRVR_INST) && dip) {
		char drvr_name[MODMAXNAMELEN + 1];

		if (dip && mdb_devinfo2driver(dip, drvr_name,
		    sizeof (drvr_name)) == 0) {
			(void) mdb_vread(&dev_info, sizeof (dev_info), dip);
			mdb_printf("%s#%d", drvr_name, dev_info.devi_instance);
		} else {
			mdb_printf("%a", isr_addr);
		}

	} else {
		mdb_printf("%a", isr_addr);
	}
}
