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

#include "intr_common.h"

/*
 * Globals
 */
static struct av_head	avec_tbl[APIC_MAX_VECTOR+1];
static apic_irq_t	*irq_tbl[APIC_MAX_VECTOR+1], airq;
static char		level_tbl[APIC_MAX_VECTOR+1];

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

	if (mdb_readvar(&level_tbl, "apic_level_intr") == -1) {
		mdb_warn("failed to read apic_level_intr");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&avec_tbl, "autovect") == -1) {
		mdb_warn("failed to read autovect");
		return (DCMD_ERR);
	}

	/* Print the header first */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%<u>CPU ");
	else
		mdb_printf(
		    "%<u>IRQ  Vect IPL Bus    Trg Type   CPU Share APIC/INT# ");
	mdb_printf("%s %</u>\n", option_flags & INTR_DISPLAY_DRVR_INST ?
	    "Driver Name(s)" : "ISR(s)");

	/* Walk all the entries */
	for (i = 0; i < APIC_MAX_VECTOR + 1; i++) {
		/* Read the entry */
		if (mdb_vread(&airq, sizeof (apic_irq_t),
		    (uintptr_t)irq_tbl[i]) == -1)
			continue;

		apic_interrupt_dump(&airq, &avec_tbl[i], i, NULL, level_tbl[i]);
	}

	return (DCMD_OK);
}

/* Macros for reading/writing the IOAPIC RDT entries */
#define	READ_IOAPIC_RDT_ENTRY_LOW_DWORD(ioapic_ix, ipin) \
	ioapic_read(ioapic_ix, APIC_RDT_CMD + (2 * (ipin)))

#define	READ_IOAPIC_RDT_ENTRY_HIGH_DWORD(ioapic_ix, ipin) \
	ioapic_read(ioapic_ix, APIC_RDT_CMD2 + (2 * (ipin)))

static uint32_t *ioapic_adr[MAX_IO_APIC];

uint32_t
ioapic_read(int ioapic_ix, uint32_t reg)
{
	volatile uint32_t *ioapic;

	ioapic = ioapic_adr[ioapic_ix];
	ioapic[APIC_IO_REG] = reg;
	return (ioapic[APIC_IO_DATA]);
}

/*
 * ioapic dcmd - Print out the ioapic registers, nicely formatted.
 */
/*ARGSUSED*/
static int
ioapic(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint32_t apic_io_max;
	int	reg;
	int	reg_max;
	int	i;


	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&ioapic_adr, "apicioadr") == -1) {
		/*
		 * If the mdb_warn string does not end in a \n, mdb will
		 * automatically append the reason for the failure.
		 */
		mdb_warn("failed to read ioapicadr");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&apic_io_max, "apic_io_max") == -1) {
		/*
		 * If the mdb_warn string does not end in a \n, mdb will
		 * automatically append the reason for the failure.
		 */
		mdb_warn("failed to read apic_io_max");
		return (DCMD_ERR);
	}

	mdb_printf("ioapicadr\t%p\n", ioapic_adr);

	for (i = 0; i < apic_io_max; i++) {
		/* Bits 23-16 define the maximum redirection entries */
		reg_max = ioapic_read(i, APIC_VERS_CMD);
		reg_max = (reg_max >> 16) & 0xff;

		mdb_printf("%4s %8s %8s\n", "reg", "high", " low");
		for (reg = 0; reg <= reg_max; reg++) {
			uint32_t high, low;

			high = READ_IOAPIC_RDT_ENTRY_HIGH_DWORD(i, reg);
			low = READ_IOAPIC_RDT_ENTRY_LOW_DWORD(i, reg);

			mdb_printf("%2d   %8x %8x\n", reg, high, low);
		}

		mdb_printf("\n");

	}

	return (DCMD_OK);
}


/*
 * apic dcmd - Print out the apic registers, nicely formatted.
 */
/*ARGSUSED*/
static int
apic(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint32_t *papic;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&papic, "apicadr") == -1) {
		/*
		 * If the mdb_warn string does not end in a \n, mdb will
		 * automatically append the reason for the failure.
		 */
		mdb_warn("failed to read apicadr");
		return (DCMD_ERR);
	}

	mdb_printf("apicadr\t%p\n", papic);
	mdb_printf("as_task_reg\t%x\n", papic[APIC_TASK_REG]);
	mdb_printf("as_dest_reg\t%x\n", papic[APIC_DEST_REG]);
	mdb_printf("as_format_reg\t%x\n", papic[APIC_FORMAT_REG]);
	mdb_printf("as_local_timer\t%x\n", papic[APIC_LOCAL_TIMER]);
	mdb_printf("as_pcint_vect\t%x\n", papic[APIC_PCINT_VECT]);
	mdb_printf("as_int_vect0\t%x\n", papic[APIC_INT_VECT0]);
	mdb_printf("as_int_vect1\t%x\n", papic[APIC_INT_VECT1]);
	mdb_printf("as_err_vect\t%x\n", papic[APIC_ERR_VECT]);
	mdb_printf("as_init_count\t%x\n", papic[APIC_INIT_COUNT]);
	mdb_printf("as_divide_reg\t%x\n", papic[APIC_DIVIDE_REG]);
	mdb_printf("as_spur_int_reg\t%x\n", papic[APIC_SPUR_INT_REG]);

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
	{ "apic", NULL, "print apic register contents", apic },
	{ "ioapic", NULL, "print ioapic register contents", ioapic },
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
