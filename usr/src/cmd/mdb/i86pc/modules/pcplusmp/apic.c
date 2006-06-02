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

/*
 * Globals
 */
static char *businfo_array[] = {
	" ",
	"CBUS",
	"CBUSII",
	"EISA",
	"FUTURE",
	"INTERN",
	"ISA",
	"MBI",
	"MBII",
	" ",
	"MPI",
	"MPSA",
	"NUBUS",
	"PCI",
	"PCMCIA",
	"TC",
	"VL",
	"VME",
	"XPRESS",
	" "
};

static struct av_head	avec_tbl[APIC_MAX_VECTOR+1];

/*
 * get_interrupt_type:
 *
 *	Get some interrupt related useful information
 *
 *	NOTE: a0 is clock, c0/d0/e0 are x-calls, e1 is apic_error_intr
 *	d1/d3 are cbe_fire interrupts
 */
static char *
get_interrupt_type(short index)
{
	if (index == RESERVE_INDEX)
		return ("IPI");
	else if (index == ACPI_INDEX)
		return ("Fixed");
	else if (index == MSI_INDEX)
		return ("MSI");
	else if (index == MSIX_INDEX)
		return ("MSI-X");
	else
		return ("Fixed");
}

/*
 * interrupt_display_info:
 *
 *	Dump interrupt information including shared interrupts.
 */
static void
interrupt_display_info(apic_irq_t irqp, int i)
{
	int		bus_type;
	int		j;
	char		*intr_type;
	char		ioapic_iline[10];
	char		ipl[3];
	char		cpu_assigned[4];
	uchar_t		assigned_cpu;
	struct autovec	avhp;

	/* If invalid index; continue */
	if (!irqp.airq_mps_intr_index || irqp.airq_mps_intr_index == FREE_INDEX)
		return;

	/* Figure out interrupt type and trigger information */
	intr_type = get_interrupt_type(irqp.airq_mps_intr_index);

	/* Figure out IOAPIC number and ILINE number */
	if (APIC_IS_MSI_OR_MSIX_INDEX(irqp.airq_mps_intr_index))
		(void) mdb_snprintf(ioapic_iline, 10, "-    ");
	else {
		if (!irqp.airq_ioapicindex && !irqp.airq_intin_no) {
			if (strcmp(intr_type, "Fixed") == 0)
				(void) mdb_snprintf(ioapic_iline, 10,
				    "0x%x/0x%x", irqp.airq_ioapicindex,
				    irqp.airq_intin_no);
			else if (irqp.airq_mps_intr_index == RESERVE_INDEX)
				(void) mdb_snprintf(ioapic_iline, 10, "-    ");
			else
				(void) mdb_snprintf(ioapic_iline, 10, " ");
		} else
			(void) mdb_snprintf(ioapic_iline, 10, "0x%x/0x%x",
			    irqp.airq_ioapicindex, irqp.airq_intin_no);
	}

	assigned_cpu = irqp.airq_temp_cpu;
	if (assigned_cpu == IRQ_UNINIT || assigned_cpu == IRQ_UNBOUND)
		assigned_cpu = irqp.airq_cpu;
	bus_type = irqp.airq_iflag.bustype;

	if (irqp.airq_mps_intr_index == RESERVE_INDEX) {
		(void) mdb_snprintf(cpu_assigned, 4, "ALL");
		(void) mdb_snprintf(ipl, 3, "%d", avec_tbl[i].avh_hi_pri);
	} else {
		(void) mdb_snprintf(cpu_assigned, 4, "%d", assigned_cpu);
		(void) mdb_snprintf(ipl, 3, "%d", irqp.airq_ipl);
	}

	/* Print each interrupt entry */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("cpu%s\t", cpu_assigned);
	else
		mdb_printf("%-3d  0x%x   %-3s %-5s %-6s%-4s%-3d   %-9s ",
		    i, irqp.airq_vector, ipl,
		    (bus_type ? businfo_array[bus_type] : " "),
		    intr_type, cpu_assigned, irqp.airq_share, ioapic_iline);

	/* If valid dip found; print driver name */
	if (irqp.airq_dip) {
		(void) mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avec_tbl[i].avh_link);

		/*
		 * Loop thru all the shared IRQs
		 */
		if (irqp.airq_share)
			interrupt_print_isr((uintptr_t)avhp.av_vector,
			    (uintptr_t)avhp.av_intarg1, (uintptr_t)avhp.av_dip);

		for (j = 1; irqp.airq_mps_intr_index != FREE_INDEX &&
		    j < irqp.airq_share; j++) {
			if (mdb_vread(&avhp, sizeof (struct autovec),
			    (uintptr_t)avhp.av_link) != -1) {
				mdb_printf(", ");
				interrupt_print_isr((uintptr_t)avhp.av_vector,
				    (uintptr_t)avhp.av_intarg1,
				    (uintptr_t)avhp.av_dip);
			} else {
				break;
			}
		}

	} else {
		if (irqp.airq_mps_intr_index == RESERVE_INDEX &&
		    !irqp.airq_share)
			mdb_printf("poke_cpu");
		else if (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avec_tbl[i].avh_link) != -1)
			mdb_printf("%a", avhp.av_vector);
	}
	mdb_printf("\n");
}


/*
 * interrupt_dump:
 *
 *	Dump interrupt information.
 */
/* ARGSUSED */
int
interrupt_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int		i;
	apic_irq_t	*irq_tbl[APIC_MAX_VECTOR+1], irqp;

	option_flags = 0;
	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, INTR_DISPLAY_DRVR_INST, &option_flags,
	    'i', MDB_OPT_SETBITS, INTR_DISPLAY_INTRSTAT, &option_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&irq_tbl, "apic_irq_table") == -1) {
		mdb_warn("failed to read apic_irq_table");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&avec_tbl, "autovect") == -1) {
		mdb_warn("failed to read autovect");
		return (DCMD_ERR);
	}

	/* Print the header first */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%<u>CPU\t ");
	else
		mdb_printf(
		    "%<u>IRQ  Vector IPL Bus   Type  CPU Share APIC/INT# ");
	mdb_printf("%s %</u>\n", option_flags & INTR_DISPLAY_DRVR_INST ?
	    "Driver Name(s)" : "ISR(s)");

	/* Walk all the entries */
	for (i = 0; i < APIC_MAX_VECTOR + 1; i++) {
		/* Read the entry */
		if (mdb_vread(&irqp, sizeof (apic_irq_t),
		    (uintptr_t)irq_tbl[i]) == -1)
			continue;

		interrupt_display_info(irqp, i);
	}

	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, and a function
 * named _mdb_init to return a pointer to our module information.
 */
static const mdb_dcmd_t dcmds[] = {
	{ "interrupts", "?[-di]", "print interrupts", interrupt_dump,
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
