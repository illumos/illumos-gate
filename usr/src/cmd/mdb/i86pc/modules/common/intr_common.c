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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

#include "intr_common.h"
#include <sys/multidata.h>
#include <sys/gld.h>
#include <sys/gldpriv.h>

int		option_flags;
uintptr_t	gld_intr_addr;
int		apic_pir_vect;
static struct av_head softvec_tbl[LOCK_LEVEL + 1];

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
	"PCIe",
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
			    (uintptr_t)&avsoftinfo.av_pending) != -1 ? 1 : 0,
			    avhp.av_prilevel, avhp.av_intarg1, avhp.av_intarg2);
			interrupt_print_isr((uintptr_t)avhp.av_vector,
			    (uintptr_t)avhp.av_intarg1, (uintptr_t)hdlp.ih_dip);
			mdb_printf("\n");
		} while (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avhp.av_link) != -1);
	}

	return (DCMD_OK);
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

static char *
get_apix_interrupt_type(short type)
{
	if (type == APIX_TYPE_IPI)
		return ("IPI");
	else if (type == APIX_TYPE_FIXED)
		return ("Fixed");
	else if (type == APIX_TYPE_MSI)
		return ("MSI");
	else if (type == APIX_TYPE_MSIX)
		return ("MSI-X");
	else
		return ("Fixed");
}

void
apic_interrupt_dump(apic_irq_t *irqp, struct av_head *avp,
    int i, ushort_t *evtchnp, char level)
{
	int		bus_type;
	int		j;
	char		*intr_type;
	char		ioapic_iline[10];
	char		ipl[3];
	char		cpu_assigned[4];
	char		evtchn[8];
	uint32_t	assigned_cpu;
	struct autovec	avhp;

	/* If invalid index; continue */
	if (!irqp->airq_mps_intr_index ||
	    irqp->airq_mps_intr_index == FREE_INDEX)
		return;

	/* Figure out interrupt type and trigger information */
	intr_type = get_interrupt_type(irqp->airq_mps_intr_index);

	/* Figure out IOAPIC number and ILINE number */
	if (APIC_IS_MSI_OR_MSIX_INDEX(irqp->airq_mps_intr_index))
		(void) mdb_snprintf(ioapic_iline, 10, "-    ");
	else {
		if (!irqp->airq_ioapicindex && !irqp->airq_intin_no) {
			if (strcmp(intr_type, "Fixed") == 0)
				(void) mdb_snprintf(ioapic_iline, 10,
				    "0x%x/0x%x", irqp->airq_ioapicindex,
				    irqp->airq_intin_no);
			else if (irqp->airq_mps_intr_index == RESERVE_INDEX)
				(void) mdb_snprintf(ioapic_iline, 10, "-    ");
			else
				(void) mdb_snprintf(ioapic_iline, 10, " ");
		} else
			(void) mdb_snprintf(ioapic_iline, 10, "0x%x/0x%x",
			    irqp->airq_ioapicindex, irqp->airq_intin_no);
	}

	evtchn[0] = '\0';
	if (evtchnp != NULL)
		(void) mdb_snprintf(evtchn, 8, "%-7hd", *evtchnp);

	assigned_cpu = irqp->airq_temp_cpu;
	if (assigned_cpu == IRQ_UNINIT || assigned_cpu == IRQ_UNBOUND)
		assigned_cpu = irqp->airq_cpu;
	bus_type = irqp->airq_iflag.bustype;

	if (irqp->airq_mps_intr_index == RESERVE_INDEX) {
		(void) mdb_snprintf(cpu_assigned, 4, "all");
		(void) mdb_snprintf(ipl, 3, "%d", avp->avh_hi_pri);
	} else {
		(void) mdb_snprintf(cpu_assigned, 4, "%d", assigned_cpu);
		(void) mdb_snprintf(ipl, 3, "%d", irqp->airq_ipl);
	}

	/* Print each interrupt entry */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%-4s", cpu_assigned);
	else
		mdb_printf("%-3d  0x%x %s%-3s %-6s %-3s %-6s %-4s%-3d   %-9s ",
		    i, irqp->airq_vector, evtchn, ipl,
		    (bus_type ? businfo_array[bus_type] : " "),
		    (level ? "Lvl" : "Edg"),
		    intr_type, cpu_assigned, irqp->airq_share, ioapic_iline);

	/* If valid dip found; print driver name */
	if (irqp->airq_dip) {
		(void) mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avp->avh_link);

		/*
		 * Loop thru all the shared IRQs
		 */
		if (irqp->airq_share)
			interrupt_print_isr((uintptr_t)avhp.av_vector,
			    (uintptr_t)avhp.av_intarg1, (uintptr_t)avhp.av_dip);

		for (j = 1; irqp->airq_mps_intr_index != FREE_INDEX &&
		    j < irqp->airq_share; j++) {
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
		if (irqp->airq_mps_intr_index == RESERVE_INDEX &&
		    !irqp->airq_share) {
			if (irqp->airq_vector == apic_pir_vect) {
				mdb_printf("pir_ipi");
			} else {
				mdb_printf("poke_cpu");
			}
		} else if (mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avp->avh_link) != -1) {
			mdb_printf("%a", avhp.av_vector);
		}
	}
	mdb_printf("\n");
}

void
apix_interrupt_dump(apix_vector_t *vectp, apic_irq_t *irqp,
    struct autovec *avp, ushort_t *evtchnp, char level)
{
	int		j;
	int		bus_type;
	char		*intr_type;
	char		irq[4];
	char		ioapic_iline[10];
	char		ipl[3];
	char		cpu_assigned[4];
	char		cpu_vector[10];
	char		evtchn[8];


	/* If invalid vector state; continue */
	if (vectp->v_state == APIX_STATE_FREED ||
	    vectp->v_state == APIX_STATE_OBSOLETED)
		return;

	/* use apic_interrupt_ipi_dump for IPIs */
	if (vectp->v_type == APIX_TYPE_IPI)
		return;

	/* Figure out interrupt type and trigger information */
	intr_type = get_apix_interrupt_type(vectp->v_type);

	/* Figure out IOAPIC number and ILINE number */
	if (vectp->v_type != APIX_TYPE_FIXED) {
		level = 0; /* MSI/MSI-X are Edge trigger */
		(void) mdb_snprintf(irq, 4, "-   ");
		(void) mdb_snprintf(ioapic_iline, 10, "-    ");
		if (vectp->v_type == APIX_TYPE_IPI)
			bus_type = BUSTYPE_NONE;
		else
			/* statically assign MSI/X with "PCI" */
			bus_type = BUSTYPE_PCI;
	} else {
		(void) mdb_snprintf(irq, 4, "%d", vectp->v_inum);
		bus_type = irqp->airq_iflag.bustype;
		if (!irqp->airq_ioapicindex && !irqp->airq_intin_no) {
			if (strcmp(intr_type, "Fixed") == 0)
				(void) mdb_snprintf(ioapic_iline, 10,
				    "0x%x/0x%x", irqp->airq_ioapicindex,
				    irqp->airq_intin_no);
			else
				(void) mdb_snprintf(ioapic_iline, 10, "-    ");
		} else
			(void) mdb_snprintf(ioapic_iline, 10, "0x%x/0x%x",
			    irqp->airq_ioapicindex, irqp->airq_intin_no);
	}

	evtchn[0] = '\0';
	if (evtchnp != NULL)
		(void) mdb_snprintf(evtchn, 8, "%-7hd", *evtchnp);

	(void) mdb_snprintf(cpu_assigned, 4, "%d", vectp->v_cpuid);
	(void) mdb_snprintf(cpu_vector, 10, "%d/0x%x",
	    vectp->v_cpuid, vectp->v_vector);

	/* Loop all the shared vectors */
	for (j = 0; j < vectp->v_share; ) {
		/* shared interrupts with one or more ISR removed afterwards */
		if (avp->av_vector == NULL) {
			if (mdb_vread(avp, sizeof (struct autovec),
			    (uintptr_t)avp->av_link) == -1)
				break;
			else
				continue;
		}

		(void) mdb_snprintf(ipl, 3, "%d", avp->av_prilevel);
		/* Print each interrupt entry */
		if (option_flags & INTR_DISPLAY_INTRSTAT)
			mdb_printf("%-4s", cpu_assigned);
		else
			mdb_printf("%-9s %-3s %s%-3s %-6s %-3s %-6s %-3d   "
			    "%-9s ", cpu_vector, irq, evtchn, ipl,
			    (bus_type ? businfo_array[bus_type] : "-"),
			    (level ? "Lvl" : "Edg"),
			    intr_type, vectp->v_share, ioapic_iline);

		interrupt_print_isr((uintptr_t)avp->av_vector,
		    (uintptr_t)avp->av_intarg1, (uintptr_t)avp->av_dip);
		mdb_printf("\n");

		if (++j == vectp->v_share)
			break; /* done */

		if (mdb_vread(avp, sizeof (struct autovec),
		    (uintptr_t)avp->av_link) == -1)
			break;
	}
}

void
apix_interrupt_ipi_dump(apix_vector_t *vectp, struct autovec *avp,
    ushort_t *evtchnp)
{
	char		*intr_type = "IPI";
	char		ioapic_iline[10];
	char		ipl[3];
	char		cpu_assigned[4];
	char		cpu_vector[10];
	char		evtchn[8];

	/* If invalid vector state; continue */
	if (vectp->v_state == APIX_STATE_FREED ||
	    vectp->v_state == APIX_STATE_OBSOLETED)
		return;

	if (vectp->v_type != APIX_TYPE_IPI)
		return;

	/* No IOAPIC number and ILINE number info */
	(void) mdb_snprintf(ioapic_iline, 10, "-    ");

	evtchn[0] = '\0';
	if (evtchnp != NULL)
		(void) mdb_snprintf(evtchn, 8, "%-7hd", *evtchnp);

	/* IPI targeted ALL cpus */
	mdb_snprintf(cpu_assigned, 4, "all");
	(void) mdb_snprintf(cpu_vector, 10, "%s/0x%x",
	    "all", vectp->v_vector);
	/* IPI is not shared interrupt, so we can get the IPL from v_pri */
	(void) mdb_snprintf(ipl, 3, "%d", vectp->v_pri);

	/* Print each interrupt entry */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%-4s", cpu_assigned);
	else
		mdb_printf("%-9s %-3s %s%-3s %-6s %-3s %-6s %-3d   %-9s ",
		    cpu_vector, "-  ", evtchn, ipl, "-   ", "Edg",
		    intr_type, vectp->v_share, ioapic_iline);
	if (!vectp->v_share) {
		if (vectp->v_vector == apic_pir_vect) {
			mdb_printf("pir_ipi");
		} else {
			mdb_printf("poke_cpu");
		}
	} else {
		mdb_printf("%a", avp->av_vector);
	}

	mdb_printf("\n");
}
