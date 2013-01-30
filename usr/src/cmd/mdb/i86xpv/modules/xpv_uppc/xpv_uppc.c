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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>
#include <sys/evtchn_impl.h>

#include "intr_common.h"

typedef struct mdb_shared_info {
	unsigned long evtchn_pending[sizeof (unsigned long) * NBBY];
	unsigned long evtchn_mask[sizeof (unsigned long) * NBBY];
} mdb_shared_info_t;

static mdb_shared_info_t	shared_info;
static struct av_head	avec_tbl[NR_IRQS];
static uint16_t		shared_tbl[MAX_ISA_IRQ + 1];
static irq_info_t	irq_tbl[NR_IRQS];
static mec_info_t	virq_tbl[NR_VIRQS];
static short		evtchn_tbl[NR_EVENT_CHANNELS];

static int
update_tables(void)
{
	uintptr_t shared_info_addr;

	if (mdb_readvar(&irq_tbl, "irq_info") == -1) {
		mdb_warn("failed to read irq_info");
		return (0);
	}

	if (mdb_readvar(&virq_tbl, "virq_info") == -1) {
		mdb_warn("failed to read virq_info");
		return (0);
	}

	if (mdb_readvar(&evtchn_tbl, "evtchn_to_irq") == -1) {
		mdb_warn("failed to read evtchn_to_irq");
		return (0);
	}

	if (mdb_readvar(&avec_tbl, "autovect") == -1) {
		mdb_warn("failed to read autovect");
		return (0);
	}

	if (mdb_readvar(&shared_tbl, "xen_uppc_irq_shared_table") == -1) {
		mdb_warn("failed to read xen_uppc_irq_shared_table");
		return (0);
	}

	if (mdb_readvar(&shared_info_addr, "HYPERVISOR_shared_info") == -1) {
		mdb_warn("failed to read HYPERVISOR_shared_info");
		return (0);
	}

	if (mdb_ctf_vread(&shared_info, "shared_info_t", "mdb_shared_info_t",
	    shared_info_addr, 0) == -1)
		return (0);

	return (1);
}


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

static const char *
virq_type(int irq)
{
	int i;

	for (i = 0; i < NR_VIRQS; i++) {
		if (virq_tbl[i].mi_irq == irq)
			break;
	}

	switch (i) {
	case VIRQ_TIMER:
		return ("virq:timer");
	case VIRQ_DEBUG:
		return ("virq:debug");
	case VIRQ_CONSOLE:
		return ("virq:console");
	case VIRQ_DOM_EXC:
		return ("virq:dom exc");
	case VIRQ_DEBUGGER:
		return ("virq:debugger");
	default:
		break;
	}

	return ("virq:?");
}

static const char *
irq_type(int irq, int extended)
{
	switch (irq_tbl[irq].ii_type) {
	case IRQT_UNBOUND:
		return ("unset");
	case IRQT_PIRQ:
		return ("pirq");
	case IRQT_VIRQ:
		if (extended)
			return (virq_type(irq));
		return ("virq");
	case IRQT_IPI:
		return ("ipi");
	case IRQT_EVTCHN:
		return ("evtchn");
	case IRQT_DEV_EVTCHN:
		return ("device");
	}

	return ("?");
}

static void
print_isr(int i)
{
	struct autovec avhp;

	if (avec_tbl[i].avh_link == NULL)
		return;

	(void) mdb_vread(&avhp, sizeof (struct autovec),
	    (uintptr_t)avec_tbl[i].avh_link);

	interrupt_print_isr((uintptr_t)avhp.av_vector,
	    (uintptr_t)avhp.av_intarg1, (uintptr_t)avhp.av_dip);

	while (avhp.av_link != NULL &&
	    mdb_vread(&avhp, sizeof (struct autovec),
	    (uintptr_t)avhp.av_link) != -1) {
		mdb_printf(", ");
		interrupt_print_isr((uintptr_t)avhp.av_vector,
		    (uintptr_t)avhp.av_intarg1, (uintptr_t)avhp.av_dip);
	}
}

static int
evtchn_masked(int i)
{
	return (TEST_EVTCHN_BIT(i, &shared_info.evtchn_mask[0]) != 0);
}

static int
evtchn_pending(int i)
{
	return (TEST_EVTCHN_BIT(i, &shared_info.evtchn_pending[0]) != 0);
}

static void
pic_interrupt_dump(int i, struct autovec *avhp, int evtchn)
{
	if (option_flags & INTR_DISPLAY_INTRSTAT) {
		mdb_printf("%-3d ", 0);
		print_isr(i);
		mdb_printf("\n");
		return;
	}

	mdb_printf("%-3d  0x%2x %-6d %6d/%-2d  %-3s %-6s %-5d ",
	    i, i + PIC_VECTBASE, evtchn, avec_tbl[i].avh_lo_pri,
	    avec_tbl[i].avh_hi_pri, avhp->av_dip ?
	    interrupt_print_bus((uintptr_t)avhp->av_dip) : "-",
	    irq_type(i, 0), shared_tbl[i]);

	print_isr(i);

	mdb_printf("\n");
}

static void
ec_interrupt_dump(int i)
{
	irq_info_t *irqp = &irq_tbl[i];
	struct autovec avhp;
	char evtchn[8];

	if (irqp->ii_type == IRQT_UNBOUND)
		return;

	if (option_flags & INTR_DISPLAY_INTRSTAT) {
		mdb_printf("%-3d ", 0);
		print_isr(i);
		mdb_printf("\n");
		return;
	}


	memset(&avhp, 0, sizeof (avhp));
	if (avec_tbl[i].avh_link != NULL)
		(void) mdb_vread(&avhp, sizeof (struct autovec),
		    (uintptr_t)avec_tbl[i].avh_link);

	switch (irqp->ii_type) {
	case IRQT_EVTCHN:
	case IRQT_VIRQ:
		if (irqp->ii_u.index == VIRQ_TIMER) {
			strcpy(evtchn, "T");
		} else {
			mdb_snprintf(evtchn, sizeof (evtchn), "%-7d",
			    irqp->ii_u.evtchn);
		}
		break;
	case IRQT_IPI:
		strcpy(evtchn, "I");
		break;
	case IRQT_DEV_EVTCHN:
		strcpy(evtchn, "D");
		break;
	}

	/* IRQ */
	mdb_printf("%3d  ", i);
	/* Vector */
	mdb_printf("-    ");
	/* Evtchn */
	mdb_printf("%-7s", evtchn);
	/* IPL */
	mdb_printf("%6d/%-2d  ", irq_tbl[i].ii_u2.ipl, irq_tbl[i].ii_u2.ipl);
	/* Bus */
	mdb_printf("%-3s ", avhp.av_dip
	    ? interrupt_print_bus((uintptr_t)avhp.av_dip) : "-");
	/* Type */
	mdb_printf("%-6s ", irq_type(i, 0));
	/* Share */
	mdb_printf("-     ");

	print_isr(i);

	mdb_printf("\n");
}

/*
 * uppc_interrupt_dump:
 *	Dump uppc(7d) interrupt information.
 */
/* ARGSUSED */
int
xen_uppc_interrupt_dump(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int		i;
	boolean_t	found = B_FALSE;
	struct autovec	avhp;

	option_flags = 0;
	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, INTR_DISPLAY_DRVR_INST, &option_flags,
	    'i', MDB_OPT_SETBITS, INTR_DISPLAY_INTRSTAT, &option_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!update_tables())
		return (DCMD_ERR);

	/*
	 * By default, on all x86 systems ::interrupts from xen_uppc(7d) gets
	 * loaded first. For APIC systems the ::interrupts from xpv_psm(7d)
	 * ought to be executed. Confusion stems as both modules export the
	 * same dcmd.
	 */
	for (i = 0; i < MAX_ISA_IRQ + 1; i++)
		if (shared_tbl[i]) {
			found = B_TRUE;
			break;
		}

	if (found == B_FALSE) {
		if (mdb_lookup_by_obj("xpv_psm", "apic_irq_table",
		    NULL) == 0) {
			return (mdb_call_dcmd("xpv_psm`interrupts",
			    addr, flags, argc, argv));
		}
	}

	/* Print the header first */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%<u>CPU ");
	else
		mdb_printf("%<u>IRQ  Vect Evtchn IPL(lo/hi) Bus Type   Share ");
	mdb_printf("%s %</u>\n", option_flags & INTR_DISPLAY_DRVR_INST ?
	    "Driver Name(s)" : "ISR(s)");

	for (i = 0; i < NR_IRQS; i++) {
		if (irq_tbl[i].ii_type == IRQT_PIRQ) {
			if (irq_tbl[i].ii_u.evtchn == 0)
				continue;

			/* Read the entry, if invalid continue */
			if (mdb_vread(&avhp, sizeof (struct autovec),
			    (uintptr_t)avec_tbl[i].avh_link) == -1)
				continue;

			pic_interrupt_dump(i, &avhp, irq_tbl[i].ii_u.evtchn);
			continue;
		}

		ec_interrupt_dump(i);
	}

	return (DCMD_OK);
}


static void
evtchn_dump(int i)
{
	int irq = evtchn_tbl[i];

	if (irq == INVALID_IRQ) {
		mdb_printf("%-14s%-7d%-4s%-7s", "unassigned", i, "-", "-");
		mdb_printf("%-4d", 0);
		mdb_printf("%-7d", evtchn_masked(i));
		mdb_printf("%-8d", evtchn_pending(i));
		mdb_printf("\n");
		return;
	}

	/* Type */
	mdb_printf("%-14s", irq_type(irq, 1));
	/* Evtchn */
	mdb_printf("%-7d", i);
	/* IRQ */
	mdb_printf("%-4d", irq);
	/* IPL */
	mdb_printf("%6d/%-2d  ", irq_tbl[irq].ii_u2.ipl,
	    irq_tbl[irq].ii_u2.ipl);
	/* CPU */
	mdb_printf("%-4d", 0);
	/* Masked/Pending */
	mdb_printf("%-7d", evtchn_masked(i));
	mdb_printf("%-8d", evtchn_pending(i));
	/* ISR */
	print_isr(irq);

	mdb_printf("\n");
}

/* ARGSUSED */
static int
evtchns_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int		i;
	boolean_t	found = B_FALSE;

	option_flags = 0;
	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, INTR_DISPLAY_DRVR_INST, &option_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!update_tables())
		return (DCMD_ERR);

	/*
	 * By default, on all x86 systems ::evtchns from xen_uppc(7d) gets
	 * loaded first. For APIC systems the ::evtchns from xpv_psm(7d)
	 * ought to be executed. Confusion stems as both modules export the
	 * same dcmd.
	 */
	for (i = 0; i < MAX_ISA_IRQ + 1; i++)
		if (shared_tbl[i]) {
			found = B_TRUE;
			break;
		}

	if (found == B_FALSE) {
		if (mdb_lookup_by_obj("xpv_psm", "apic_irq_table",
		    NULL) == 0) {
			return (mdb_call_dcmd("xpv_psm`evtchns",
			    addr, flags, argc, argv));
		}
	}

	if (flags & DCMD_ADDRSPEC) {
		/*
		 * Note: we allow the invalid evtchn 0, as it can help catch if
		 * we incorrectly try to configure it.
		 */
		if ((int)addr >= NR_EVENT_CHANNELS) {
			mdb_warn("Invalid event channel %d.\n", (int)addr);
			return (DCMD_ERR);
		}
	}

	mdb_printf("%<u>Type          Evtchn IRQ IPL(lo/hi) CPU "
	    "Masked Pending ");
	mdb_printf("%s %</u>\n", option_flags & INTR_DISPLAY_DRVR_INST ?
	    "Driver Name(s)" : "ISR(s)");

	if (flags & DCMD_ADDRSPEC) {
		evtchn_dump((int)addr);
		return (DCMD_OK);
	}

	for (i = 0; i < NR_EVENT_CHANNELS; i++) {
		if (evtchn_tbl[i] == INVALID_IRQ)
			continue;

		evtchn_dump(i);
	}

	return (DCMD_OK);
}

static void
evtchns_help(void)
{
	mdb_printf("Print valid event channels\n"
	    "If %<u>addr%</u> is given, interpret it as an evtchn to print "
	    "details of.\n"
	    "By default, only interrupt service routine names are printed.\n\n"
	    "Switches:\n"
	    "  -d   instead of ISR, print <driver_name><instance#>\n");
}

/*
 * MDB module linkage information:
 */
static const mdb_dcmd_t dcmds[] = {
	{ "interrupts", "?[-di]", "print interrupts", xen_uppc_interrupt_dump,
	    interrupt_help},
	{ "evtchns", "?[-d]", "print event channels", evtchns_dump,
	    evtchns_help },
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
