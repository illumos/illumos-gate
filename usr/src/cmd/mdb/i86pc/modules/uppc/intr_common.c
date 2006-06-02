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
#include <sys/ddi_intr_impl.h>
#include <sys/cpuvar.h>

int			option_flags;
uintptr_t		gld_intr_addr;
static struct av_head	softvec_tbl[LOCK_LEVEL + 1];

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
soft_interrupt_help(void)
{
	mdb_printf("Prints the soft interrupt usage on the system.\n"
	    "By default, only interrupt service routine names are printed.\n\n"
	    "Switch:\n"
	    "  -d   instead of ISR, print <driver_name><instance#>\n");
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


/*
 * This is copied from avintr.c
 * NOTE: Ensure that this definition stays in sync
 */
typedef struct av_softinfo {
	cpuset_t	av_pending;	/* pending bitmasks */
} av_softinfo_t;

/* ARGSUSED */
int
soft_interrupt_dump(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int			i;
	av_softinfo_t		avsoftinfo;
	struct autovec		avhp;
	ddi_softint_hdl_impl_t	hdlp;

	option_flags = 0;
	if (mdb_getopts(argc, argv, 'd', MDB_OPT_SETBITS,
	    INTR_DISPLAY_DRVR_INST, &option_flags, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&softvec_tbl, "softvect") == -1) {
		mdb_warn("failed to read autovect");
		return (DCMD_ERR);
	}

	/* Print the header first */
	mdb_printf("%<u>ADDR             PEND PIL ARG1             "
	    "ARG2            ISR(s)%</u>\n");

	/* Walk all the entries */
	for (i = 0; i < LOCK_LEVEL + 1; i++) {
		/* Read the entry, if invalid continue */
		if (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)softvec_tbl[i].avh_link) == -1)
			continue;

		do {
			if (!avhp.av_vector ||
			    (mdb_vread(&hdlp, sizeof (ddi_softint_hdl_impl_t),
				(uintptr_t)avhp.av_intr_id) == -1) ||
			    (mdb_vread(&avsoftinfo, sizeof (av_softinfo_t),
				(uintptr_t)hdlp.ih_pending) == -1))
				continue;

			/* Print each soft interrupt entry */
			mdb_printf("%-16p %-2d   %-2d  %-16p %-16p",
			    avhp.av_intr_id, mdb_cpuset_find(
			    (uintptr_t)avsoftinfo.av_pending) != -1 ? 1 : 0,
			    avhp.av_prilevel, avhp.av_intarg1, avhp.av_intarg2);
			interrupt_print_isr((uintptr_t)avhp.av_vector,
			    (uintptr_t)avhp.av_intarg1, (uintptr_t)hdlp.ih_dip);
			mdb_printf("\n");
		} while (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avhp.av_link) != -1);
	}

	return (DCMD_OK);
}
