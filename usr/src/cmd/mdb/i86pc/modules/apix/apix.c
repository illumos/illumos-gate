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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

#include "intr_common.h"

/*
 * Globals
 */
static apic_irq_t	*irq_tbl[APIC_MAX_VECTOR+1];
static char		level_tbl[APIC_MAX_VECTOR+1];
static apix_impl_t *d_apixs[NCPU];
static int d_ncpus = NCPU;


/*
 * Dump interrupt information for apix PSM.
 */
/* ARGSUSED */
int
interrupt_dump_apix(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int i, j;
	apix_impl_t apix;
	apix_vector_t apix_vector;
	struct autovec av;
	apic_irq_t apic_irq;

	option_flags = 0;
	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, INTR_DISPLAY_DRVR_INST, &option_flags,
	    'i', MDB_OPT_SETBITS, INTR_DISPLAY_INTRSTAT, &option_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&d_apixs, "apixs") == -1) {
		mdb_warn("failed to read apixs");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&d_ncpus, "apic_nproc") == -1) {
		mdb_warn("failed to read apic_nproc");
		d_ncpus = NCPU;
	}
	if (d_ncpus == 0 || d_ncpus > NCPU)
		d_ncpus = NCPU;

	if (mdb_readvar(&irq_tbl, "apic_irq_table") == -1) {
		mdb_warn("failed to read apic_irq_table");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&level_tbl, "apic_level_intr") == -1) {
		mdb_warn("failed to read apic_level_intr");
		return (DCMD_ERR);
	}

	/* Print the header first */
	if (option_flags & INTR_DISPLAY_INTRSTAT)
		mdb_printf("%<u>CPU ");
	else
		mdb_printf("%<u>CPU/Vect  IRQ IPL Bus    Trg Type   "
		    "Share APIC/INT# ");
	mdb_printf("%s %</u>\n", option_flags & INTR_DISPLAY_DRVR_INST ?
	    "Driver Name(s)" : "ISR");

	/* Walk all the entries */
	for (i = 0; i < d_ncpus; i++) {
		/* Read the per CPU apix entry */
		if (mdb_vread(&apix, sizeof (apix_impl_t),
		    (uintptr_t)d_apixs[i]) == -1)
			continue;
		for (j = 0; j < APIX_NVECTOR; j++) {
			/* Read the vector entry */
			if (mdb_vread(&apix_vector, sizeof (apix_vector_t),
			    (uintptr_t)apix.x_vectbl[j]) == -1)
				continue;
			/* If invalid vector state; continue */
			if (apix_vector.v_state == APIX_STATE_FREED ||
			    apix_vector.v_state == APIX_STATE_OBSOLETED)
				continue;
			if (apix_vector.v_type == APIX_TYPE_IPI)
				continue;
			if (mdb_vread(&av, sizeof (struct autovec),
			    (uintptr_t)(apix_vector.v_autovect)) == -1)
				continue;
			if ((apix_vector.v_type == APIX_TYPE_FIXED) &&
			    (mdb_vread(&apic_irq, sizeof (apic_irq_t),
			    (uintptr_t)irq_tbl[apix_vector.v_inum]) == -1))
				continue;

			apix_interrupt_dump(&apix_vector, &apic_irq, &av,
			    NULL, level_tbl[apix_vector.v_inum]);
		}
	}
	/* print IPIs */
	if (mdb_vread(&apix, sizeof (apix_impl_t),
	    (uintptr_t)d_apixs[0]) != -1) {
		for (j = 0; j < APIX_NVECTOR; j++) {
			/* Read the vector entry */
			if (mdb_vread(&apix_vector, sizeof (apix_vector_t),
			    (uintptr_t)apix.x_vectbl[j]) == -1)
				continue;
			/* If invalid vector state; continue */
			if (apix_vector.v_state == APIX_STATE_FREED ||
			    apix_vector.v_state == APIX_STATE_OBSOLETED)
				continue;
			if (apix_vector.v_type != APIX_TYPE_IPI)
				continue;
			if (mdb_vread(&av, sizeof (struct autovec),
			    (uintptr_t)(apix_vector.v_autovect)) == -1) {
				/* v_share for poke_cpu is 0 */
				if (apix_vector.v_share != 0)
					continue;
			}
			apix_interrupt_ipi_dump(&apix_vector, &av, NULL);
		}
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
	{ "interrupts", "?[-di]", "print interrupts", interrupt_dump_apix,
	    interrupt_help},
	{ "softint", "?[-d]", "print soft interrupts", soft_interrupt_dump,
	    soft_interrupt_help},
#ifdef _KMDB
	{ "apic", NULL, "print apic register contents", apic },
	{ "ioapic", NULL, "print ioapic register contents", ioapic },
#endif /* _KMDB */
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

	if (mdb_readvar(&apic_pir_vect, "apic_pir_vect") == -1) {
		apic_pir_vect = -1;
	}

	return (&modinfo);
}
