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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "intr_common.h"

static struct av_head	avec_tbl[APIC_MAX_VECTOR+1];
static uint16_t		shared_tbl[MAX_ISA_IRQ + 1];

static char *
interrupt_print_bus(uintptr_t dip_addr)
{
	char		bind_name[MAXPATHLEN + 1];
	struct dev_info	dev_info;

	if (mdb_vread(&dev_info, sizeof (dev_info), dip_addr) == -1) {
		mdb_warn("failed to read child dip");
		return ("-");
	}

	while (dev_info.devi_parent != 0) {
		if (mdb_vread(&dev_info, sizeof (dev_info),
		    (uintptr_t)dev_info.devi_parent) == -1)
			break;

		(void) mdb_readstr(bind_name, sizeof (bind_name),
		    (uintptr_t)dev_info.devi_binding_name);
		if (strcmp(bind_name, "isa") == 0)
			return ("ISA");
		else if (strcmp(bind_name, "pci") == 0 ||
		    strcmp(bind_name, "npe") == 0)
			return ("PCI");
	}
	return ("-");
}


/*
 * uppc_interrupt_dump:
 *	Dump uppc(4D) interrupt information.
 */
/* ARGSUSED */
int
uppc_interrupt_dump(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int		i, j;
	boolean_t	found = B_FALSE;
	struct autovec	avhp;

	option_flags = 0;
	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, INTR_DISPLAY_DRVR_INST, &option_flags,
	    'i', MDB_OPT_SETBITS, INTR_DISPLAY_INTRSTAT, &option_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&avec_tbl, "autovect") == -1) {
		mdb_warn("failed to read autovect");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&shared_tbl, "uppc_irq_shared_table") == -1) {
		mdb_warn("failed to read uppc_irq_shared_table");
		return (DCMD_ERR);
	}

	/*
	 * By default, on all x86 systems ::interrupts from uppc gets
	 * loaded first. For APIC systems the ::interrupts from either
	 * apix or pcplusmp ought to be executed. Confusion stems as
	 * these three modules export the same dcmd.
	 */
	for (i = 0; i < MAX_ISA_IRQ + 1; i++)
		if (shared_tbl[i]) {
			found = B_TRUE;
			break;
		}

	if (found == B_FALSE) {
		if (mdb_lookup_by_obj("apix", "apixs", NULL) == 0) {
			return (mdb_call_dcmd("apix`interrupts",
			    addr, flags, argc, argv));
		} else if (mdb_lookup_by_obj("pcplusmp", "apic_irq_table",
		    NULL) == 0) {
			return (mdb_call_dcmd("pcplusmp`interrupts",
			    addr, flags, argc, argv));
		}
	}

	/* Print the header first */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%<u>CPU ");
	else
		mdb_printf("%<u>IRQ  Vector IPL(lo/hi) Bus Share ");
	mdb_printf("%s %</u>\n", option_flags & INTR_DISPLAY_DRVR_INST ?
	    "Driver Name(s)" : "ISR(s)");

	/* Walk all the entries */
	for (i = 0; i < MAX_ISA_IRQ + 1; i++) {
		/* Read the entry, if invalid continue */
		if (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avec_tbl[i].avh_link) == -1)
			continue;

		/* Print each interrupt entry */
		if (option_flags & INTR_DISPLAY_INTRSTAT)
			mdb_printf("cpu0\t");
		else
			mdb_printf("%-3d   0x%2x   %4d/%-2d   %-4s %-3d  ",
			    i, i + PIC_VECTBASE, avec_tbl[i].avh_lo_pri,
			    avec_tbl[i].avh_hi_pri, avhp.av_dip ?
			    interrupt_print_bus((uintptr_t)avhp.av_dip) : " - ",
			    shared_tbl[i]);

		if (shared_tbl[i])
			interrupt_print_isr((uintptr_t)avhp.av_vector,
			    (uintptr_t)avhp.av_intarg1, (uintptr_t)avhp.av_dip);

		for (j = 1; j < shared_tbl[i]; j++) {
			if (mdb_vread(&avhp, sizeof (struct autovec),
			    (uintptr_t)avhp.av_link) != -1)  {
				mdb_printf(", ");
				interrupt_print_isr((uintptr_t)avhp.av_vector,
				    (uintptr_t)avhp.av_intarg1,
				    (uintptr_t)avhp.av_dip);
			} else {
				break;
			}
		}
		mdb_printf("\n");
	}

	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 */
static const mdb_dcmd_t dcmds[] = {
	{ "interrupts", "?[-di]", "print interrupts", uppc_interrupt_dump,
	    interrupt_help},
	{ "softint", "?[-d]", "print soft interrupts", soft_interrupt_dump,
	    soft_interrupt_help},
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, NULL };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym	sym;

	if (mdb_lookup_by_name("gld_intr", &sym) != -1)
		if (GELF_ST_TYPE(sym.st_info) == STT_FUNC)
			gld_intr_addr = (uintptr_t)sym.st_value;

	return (&modinfo);
}
