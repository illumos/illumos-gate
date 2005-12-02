/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/modctl.h>
#include <sys/avintr.h>
#include <io/pcplusmp/apic.h>

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
	int		share_cnt;
	char		*intr_type;
	char		ioapic_iline[10];
	char		ipl[3];
	char		driver_name[MODMAXNAMELEN + 1];
	char		cpu_assigned[4];
	uchar_t		assigned_cpu;
	uintptr_t	dip_addr;
	struct dev_info	dev_info;
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
		(void) mdb_snprintf(cpu_assigned, 4, "0x%x", assigned_cpu);
		(void) mdb_snprintf(ipl, 3, "%d", irqp.airq_ipl);
	}

	/* Print each interrupt entry */
	mdb_printf("%3d  0x%x   %-3s %-5s %-6s%-4s %2d   %-9s ", i,
	    irqp.airq_vector, ipl, (bus_type ? businfo_array[bus_type] : " "),
	    intr_type, cpu_assigned, irqp.airq_share, ioapic_iline);

	/* If valid dip found; print driver name */
	dip_addr = (uintptr_t)irqp.airq_dip;
	if (dip_addr && mdb_devinfo2driver(dip_addr, driver_name,
	    sizeof (driver_name)) == 0) {

		(void) mdb_vread(&dev_info, sizeof (dev_info), dip_addr);
		mdb_printf("%s#%d", driver_name, dev_info.devi_instance);

		share_cnt = irqp.airq_share - 1;
		(void) mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avec_tbl[i].avh_link);

		while (irqp.airq_mps_intr_index != FREE_INDEX &&
		    share_cnt-- > 0) {
			dip_addr = (uintptr_t)avhp.av_dip;
			if (dip_addr && !DDI_CF2(&dev_info) &&
			    mdb_devinfo2driver(dip_addr, driver_name,
			    sizeof (driver_name)) == 0) {
				(void) mdb_vread(&dev_info, sizeof (dev_info),
				    dip_addr);
				mdb_printf(", %s#%d", driver_name,
				    dev_info.devi_instance);
			} else
				mdb_printf(", %a", avhp.av_vector);
			if (mdb_vread(&avhp, sizeof (struct autovec),
			    (uintptr_t)avhp.av_link) == -1)
				continue;
		}
		mdb_printf("\n");

	} else {
		if (irqp.airq_mps_intr_index == RESERVE_INDEX &&
		    !irqp.airq_share)
			mdb_printf("poke_cpu\n");
		else if (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avec_tbl[i].avh_link) == -1)
			mdb_printf("\n");
		else
			mdb_printf("%a\n", avhp.av_vector);
	}
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

	if (mdb_readvar(&irq_tbl, "apic_irq_table") == -1) {
		mdb_warn("failed to read apic_irq_table");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&avec_tbl, "autovect") == -1) {
		mdb_warn("failed to read autovect");
		return (DCMD_ERR);
	}

	/* Print the header first */
	mdb_printf("%<u>IRQ  Vector IPL Bus   Type  CPU Share APIC/INT# "
	    "Driver Name(s)/ISR(s) %</u>\n");

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
	{ "interrupts", NULL, "print interrupts", interrupt_dump, NULL},
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, NULL };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
