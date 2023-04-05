/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * ISA-independent utility functions for the x86 architecture
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_x86util.h>

#include <sys/controlregs.h>
#include <inttypes.h>

#define	MMU_PAGESHIFT	12
#define	MMU_PAGESIZE	(1 << MMU_PAGESHIFT)
#define	MMU_PAGEOFFSET	(MMU_PAGESIZE - 1)
#define	MMU_PAGEMASK	(~MMU_PAGEOFFSET)

#ifndef _KMDB
static void
mdb_x86_print_desc(const char *name, const mdb_x86_desc_t *desc, uint_t width)
{
	const char *type;
	const mdb_bitmask_t *bits;

	static const mdb_bitmask_t mem_desc_flag_bits[] = {
		{ "P",		0x80,	0x80 },
		{ "16b",	0x6000, 0x0 },
		{ "32b",	0x6000, 0x4000 },
		{ "64b",	0x6000,	0x2000 },
		{ "G",		0x8000,	0x8000 },
		{ "A",		0x1,	0x1 },
		{ NULL,		0,	0 },
	};

	static const char *mem_desc_types[] = {
		"data, up, read-only",
		"data, up, read-write",
		"data, down, read-only",
		"data, down, read-write",
		"code, non-conforming, execute-only",
		"code, non-conforming, execute-read",
		"code, conforming, execute-only",
		"code, conforming, execute-read"
	};

	static const mdb_bitmask_t sys_desc_flag_bits[] = {
		{ "P",		0x80,	0x80 },
		{ "16b",	0x6000, 0x0 },
		{ "32b",	0x6000, 0x4000 },
		{ "64b",	0x6000,	0x2000 },
		{ "G",		0x8000,	0x8000 },
		{ NULL,		0,	0 },
	};

	static const char *sys_desc_types[] = {
		"reserved",
		"16b TSS, available",
		"LDT",
		"16b TSS, busy",
		"16b call gate",
		"task gate",
		"16b interrupt gate",
		"16b trap gate",
		"reserved",
		"32b/64b TSS, available",
		"reserved",
		"32b/64b TSS, busy",
		"32b/64b call gate",
		"reserved",
		"32b/64b interrupt gate"
		"32b/64b trap gate",
	};

	if (desc->d_acc & 0x10) {
		type = mem_desc_types[(desc->d_acc >> 1) & 7];
		bits = mem_desc_flag_bits;
	} else {
		type = sys_desc_types[desc->d_acc & 0xf];
		bits = sys_desc_flag_bits;
	}

	mdb_printf("%%%s = 0x%0*lx/0x%0*x 0x%05x "
	    "<%susable, %s, dpl %d, flags: %b>\n",
	    name, width, desc->d_base, width / 2, desc->d_lim, desc->d_acc,
	    (desc->d_acc >> 16) & 1 ? "un" : "", type,
	    (desc->d_acc >> 5) & 3, desc->d_acc, bits);
}
#endif

void
mdb_x86_print_sysregs(struct sysregs *sregs, boolean_t long_mode)
{
	const uint_t width =
	    2 * (long_mode ? sizeof (uint64_t) : sizeof (uint32_t));


#ifndef _KMDB
	static const mdb_bitmask_t efer_flag_bits[] = {
		{ "SCE",	AMD_EFER_SCE,	AMD_EFER_SCE },
		{ "LME",	AMD_EFER_LME,	AMD_EFER_LME },
		{ "LMA",	AMD_EFER_LMA,	AMD_EFER_LMA },
		{ "NXE",	AMD_EFER_NXE,	AMD_EFER_NXE },
		{ "SVME",	AMD_EFER_SVME,	AMD_EFER_SVME },
		{ "LMSLE",	AMD_EFER_LMSLE,	AMD_EFER_LMSLE },
		{ "FFXSR",	AMD_EFER_FFXSR,	AMD_EFER_FFXSR },
		{ "TCE",	AMD_EFER_TCE,	AMD_EFER_TCE },
		{ "MCOMMIT",	AMD_EFER_MCOMMIT, AMD_EFER_MCOMMIT },
		{ "INTWB",	AMD_EFER_INTWB,	AMD_EFER_INTWB },
		{ "UAIE",	AMD_EFER_UAIE,	AMD_EFER_UAIE },
		{ "AIRBRSE",	AMD_EFER_AIBRSE, AMD_EFER_AIBRSE },
		{ NULL,		0,		0 }
	};
#endif

	static const mdb_bitmask_t cr0_flag_bits[] = {
		{ "PE",		CR0_PE,		CR0_PE },
		{ "MP",		CR0_MP,		CR0_MP },
		{ "EM",		CR0_EM,		CR0_EM },
		{ "TS",		CR0_TS,		CR0_TS },
		{ "ET",		CR0_ET,		CR0_ET },
		{ "NE",		CR0_NE,		CR0_NE },
		{ "WP",		CR0_WP,		CR0_WP },
		{ "AM",		CR0_AM,		CR0_AM },
		{ "NW",		CR0_NW,		CR0_NW },
		{ "CD",		CR0_CD,		CR0_CD },
		{ "PG",		CR0_PG,		CR0_PG },
		{ NULL,		0,		0 }
	};

	static const mdb_bitmask_t cr3_flag_bits[] = {
		{ "PCD",	CR3_PCD,	CR3_PCD },
		{ "PWT",	CR3_PWT,	CR3_PWT },
		{ NULL,		0,		0, }
	};

	static const mdb_bitmask_t cr4_flag_bits[] = {
		{ "VME",	CR4_VME,	CR4_VME },
		{ "PVI",	CR4_PVI,	CR4_PVI },
		{ "TSD",	CR4_TSD,	CR4_TSD },
		{ "DE",		CR4_DE,		CR4_DE },
		{ "PSE",	CR4_PSE,	CR4_PSE },
		{ "PAE",	CR4_PAE,	CR4_PAE },
		{ "MCE",	CR4_MCE,	CR4_MCE },
		{ "PGE",	CR4_PGE,	CR4_PGE },
		{ "PCE",	CR4_PCE,	CR4_PCE },
		{ "OSFXSR",	CR4_OSFXSR,	CR4_OSFXSR },
		{ "OSXMMEXCPT",	CR4_OSXMMEXCPT,	CR4_OSXMMEXCPT },
		{ "UMIP",	CR4_UMIP,	CR4_UMIP },
		{ "LA57",	CR4_LA57,	CR4_LA57 },
		{ "VMXE",	CR4_VMXE,	CR4_VMXE },
		{ "SMXE",	CR4_SMXE,	CR4_SMXE },
		{ "FSGSBASE",	CR4_FSGSBASE,	CR4_FSGSBASE },
		{ "PCIDE",	CR4_PCIDE,	CR4_PCIDE },
		{ "OSXSAVE",	CR4_OSXSAVE,	CR4_OSXSAVE },
		{ "SMEP",	CR4_SMEP,	CR4_SMEP },
		{ "SMAP",	CR4_SMAP,	CR4_SMAP },
		{ "PKE",	CR4_PKE,	CR4_PKE },
		{ NULL,		0,		0 }
	};

#ifndef _KMDB
	mdb_printf("%%efer = 0x%0lx <%b>\n",
	    sregs->sr_efer, sregs->sr_efer, efer_flag_bits);
#endif
	mdb_printf("%%cr0 = 0x%0lx <%b>\n",
	    sregs->sr_cr0, sregs->sr_cr0, cr0_flag_bits);
	mdb_printf("%%cr2 = 0x%0*x <%a>\n", width,
	    sregs->sr_cr2, sregs->sr_cr2);
	mdb_printf("%%cr3 = 0x%0lx <pfn:0x%lx ",
	    sregs->sr_cr3, sregs->sr_cr3 >> MMU_PAGESHIFT);
	if (sregs->sr_cr4 & CR4_PCIDE)
		mdb_printf("pcid:%lu>\n", sregs->sr_cr3 & MMU_PAGEOFFSET);
	else
		mdb_printf("flags:%b>\n", sregs->sr_cr3, cr3_flag_bits);
	mdb_printf("%%cr4 = 0x%0lx <%b>\n",
	    sregs->sr_cr4, sregs->sr_cr4, cr4_flag_bits);

#ifndef _KMDB
	mdb_printf("\n");
	mdb_printf("%%pdpte0 = 0x%0?lx\t%%pdpte2 = 0x%0?lx\n",
	    sregs->sr_pdpte0, sregs->sr_pdpte2);
	mdb_printf("%%pdpte1 = 0x%0?lx\t%%pdpte3 = 0x%0?lx\n",
	    sregs->sr_pdpte1, sregs->sr_pdpte3);
	mdb_printf("\n");

	mdb_printf("%%gdtr = 0x%0*lx/0x%hx\n",
	    width, sregs->sr_gdtr.d_base, sregs->sr_gdtr.d_lim);
#else
	mdb_printf("%%gdtr.base = 0x%0*lx, %%gdtr.limit = 0x%hx\n",
	    width, sregs->sr_gdtr.d_base, sregs->sr_gdtr.d_lim);
#endif
#ifndef _KMDB
	mdb_printf("%%idtr = 0x%0*lx/0x%hx\n",
	    width, sregs->sr_idtr.d_base, sregs->sr_idtr.d_lim);
	mdb_x86_print_desc("ldtr", &sregs->sr_ldtr, width);
	mdb_x86_print_desc("tr  ", &sregs->sr_tr, width);
	mdb_x86_print_desc("cs  ", &sregs->sr_cs, width);
	mdb_x86_print_desc("ss  ", &sregs->sr_ss, width);
	mdb_x86_print_desc("ds  ", &sregs->sr_ds, width);
	mdb_x86_print_desc("es  ", &sregs->sr_es, width);
	mdb_x86_print_desc("fs  ", &sregs->sr_fs, width);
	mdb_x86_print_desc("gs  ", &sregs->sr_gs, width);

	mdb_printf("%%intr_shadow = 0x%lx\n",
	    sregs->sr_intr_shadow);
#endif
}
