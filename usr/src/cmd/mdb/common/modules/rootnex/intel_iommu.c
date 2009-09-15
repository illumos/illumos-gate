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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */
#include <sys/mdb_modapi.h>
#include <sys/list.h>
#include <sys/note.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/intel_iommu.h>
#include <sys/iommulib.h>
#include <stddef.h>

/*
 * Does Intel IOMMU works on this system?
 */
static boolean_t iommu_support = B_FALSE;

static void
iomuvtop_help(void)
{
	mdb_printf("print physical mapping of IO virtual address\n\n"
	    "Usage:\n\n"
	    "  address::iomuvtop <iova>\n\n"
	    "Where, \"address\" is the address of the devinfo node, "
	    "while \"iova\" is the DMA virtual address.\n");
}

static boolean_t
iommu_supported(void)
{
	if (iommu_support == B_FALSE)
		mdb_printf("No Intel IOMMU active on this system\n");
	return (iommu_support);
}

/*
 * print_device_scope_cb()
 *   call back for print_device_scope()
 */
static int
print_device_scope_cb(uintptr_t addr, pci_dev_scope_t *devs, void *cbdata)
{
	_NOTE(ARGUNUSED(addr))

	mdb_printf((char *)cbdata);
	mdb_printf("BDF[%x:%x:%x],type[%x]\n",
	    devs->pds_bus,
	    devs->pds_dev,
	    devs->pds_func,
	    devs->pds_type);

	return (WALK_NEXT);
}

/*
 * print_device_scope()
 *   a common function to print device scope of a drhd or rmrr
 */
static void
print_device_scope(const char *pre, uintptr_t addr)
{
	mdb_pwalk("list",
	    (mdb_walk_cb_t)print_device_scope_cb, (void *)pre, addr);
}

/*
 * parse_hw_capa()
 * parse_hw_excapa()
 *
 *  Given the capability and extension capability register contents,
 *  parse and print supported features in <output>
 *
 *  Please refer to chapter 10.4.2/3 in "Intel virutalization technology
 *  for direct IO specification" for register details
 */
static void
parse_hw_capa(uint64_t capa)
{
	char string[128];
	size_t len;

	strcpy(string, "  Hardware Capability:\t\t");
	if (IOMMU_CAP_GET_DRD(capa))
		strcat(string, "DRD ");
	if (IOMMU_CAP_GET_DWD(capa))
		strcat(string, "DWD ");
	if (IOMMU_CAP_GET_PSI(capa))
		strcat(string, "PSI ");
	if (IOMMU_CAP_GET_ISOCH(capa))
		strcat(string, "ISOCH ");
	if (IOMMU_CAP_GET_ZLR(capa))
		strcat(string, "ZLR ");
	if (IOMMU_CAP_GET_CM(capa))
		strcat(string, "CM ");
	if (IOMMU_CAP_GET_PHMR(capa))
		strcat(string, "PHMR ");
	if (IOMMU_CAP_GET_PLMR(capa))
		strcat(string, "PLMR ");
	if (IOMMU_CAP_GET_RWBF(capa))
		strcat(string, "RWBF ");
	if (IOMMU_CAP_GET_AFL(capa))
		strcat(string, "AFL ");

	len = strlen(string);
	if ((len > 1) &&
	    (string[len - 1] == ' '))
		string[len - 1] = 0;

	strcat(string, "\n");
	mdb_printf(string);
}

static void
parse_hw_excapa(uint64_t excapa)
{
	char string[128];
	size_t len;

	strcpy(string, "  Hardware Ex-Capability:\t");
	if (IOMMU_ECAP_GET_SC(excapa))
		strcat(string, "SC ");
	if (IOMMU_ECAP_GET_PT(excapa))
		strcat(string, "PT ");
	if (IOMMU_ECAP_GET_CH(excapa))
		strcat(string, "CH ");
	if (IOMMU_ECAP_GET_EIM(excapa))
		strcat(string, "EIM ");
	if (IOMMU_ECAP_GET_IR(excapa))
		strcat(string, "IR ");
	if (IOMMU_ECAP_GET_DI(excapa))
		strcat(string, "DI ");
	if (IOMMU_ECAP_GET_QI(excapa))
		strcat(string, "QI ");
	if (IOMMU_ECAP_GET_C(excapa))
		strcat(string, "C ");

	len = strlen(string);
	if ((len > 1) &&
	    (string[len - 1] == ' '))
		string[len - 1] = 0;

	strcat(string, "\n");
	mdb_printf(string);
}

typedef enum {
	ERROR_SCOPE,
	INCLUDE_ALL_SCOPE,
	DEV_SCOPE
} iomu_scope_t;

/*
 * print_iommu_state()
 *  Given an iommu_state structure, parse and print iommu information
 *
 *  Returns:
 *   INCLUDE_ALL_SCOPE if include all is set
 *   DEV_SCOPE if not set
 *   ERROR_SCOPE on error.
 */
static iomu_scope_t
print_iommu_state(intel_iommu_state_t *iommu, drhd_info_t *drhd)
{
	if ((iommu == NULL) || (drhd == NULL)) {
		mdb_warn("Internal error - NULL iommu state pointer passed\n");
		return (ERROR_SCOPE);
	}

	mdb_printf("Intel DMA remapping unit\n");
	mdb_printf("  IOMMU Status:\t\t\t%s\n",
	    (iommu->iu_enabled & DMAR_ENABLE) ? "Enabled" : "Disabled");
	mdb_printf("  Queued Invalid:\t\t%s\n",
	    (iommu->iu_enabled & QINV_ENABLE) ? "Enabled" : "Disabled");
	mdb_printf("  Interrupt remapping:\t\t%s\n",
	    (iommu->iu_enabled & INTRR_ENABLE) ? "Enabled" : "Disabled");
	mdb_printf("  Register Physical Address:\t%p\n",
	    (uintptr_t)drhd->di_reg_base);
	mdb_printf("  Register Virtual Address:\t%p\n",
	    (uintptr_t)iommu->iu_reg_address);
	parse_hw_capa(iommu->iu_capability);
	parse_hw_excapa(iommu->iu_excapability);
	mdb_printf("  Root Entry Table:\t\t%p\n",
	    (uintptr_t)iommu->iu_root_entry_paddr);
	mdb_printf("  Guest Address Width:\t\t%d\n", iommu->iu_gaw);
	mdb_printf("  Adjust Guest Address Width:\t%d\n", iommu->iu_agaw);
	mdb_printf("  Page Table Level:\t\t%d\n", iommu->iu_level);
	mdb_printf("  Max Domain Supported:\t\t%d\n", iommu->iu_max_domain);
	mdb_printf("  System Coherence:\t\t%s\n",
	    iommu->iu_coherency ? "Yes" : "No");
	mdb_printf("  Include All unit:\t\t%s\n",
	    drhd->di_include_all ? "Yes" : "No");
	mdb_printf("  Devinfo Node:\t\t\t%p\n",
	    (intptr_t)drhd->di_dip);

	if (iommu->iu_enabled & QINV_ENABLE) {
		struct inv_queue_state qi_state;
		if (iommu->iu_inv_queue &&
		    mdb_vread(&qi_state, sizeof (qi_state),
		    (intptr_t)iommu->iu_inv_queue) == sizeof (qi_state)) {
			mdb_printf("  Qinv Table:\t\t\tpaddr:%p, "
			    "vaddr:%p, size:%x\n",
			    (uintptr_t)qi_state.iq_table.paddr,
			    (uintptr_t)qi_state.iq_table.vaddr,
			    qi_state.iq_table.size);
			mdb_printf("  Sync Table:\t\t\tpaddr:%p, "
			    "vaddr:%p, size:%x\n",
			    (uintptr_t)qi_state.iq_sync.paddr,
			    (uintptr_t)qi_state.iq_sync.vaddr,
			    qi_state.iq_sync.size);
		} else {
			mdb_warn("failed to read iommu invalidation "
			    "queue state at %p\n",
			    (uintptr_t)iommu->iu_inv_queue);
			return (ERROR_SCOPE);
		}
	}

	return (drhd->di_include_all ? INCLUDE_ALL_SCOPE : DEV_SCOPE);
}

/*
 * dcmd: iomuprt
 */
static int
iomuprt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(argv))
	intel_iommu_state_t iommu;
	drhd_info_t drhd;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if ((argc != 0) || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (!DCMD_HDRSPEC(flags))
		mdb_printf("\n");

	if ((mdb_vread(&iommu, sizeof (iommu), addr) == sizeof (iommu)) &&
	    (iommu.iu_drhd != NULL) &&
	    (mdb_vread(&drhd, sizeof (drhd),
	    (intptr_t)iommu.iu_drhd) == sizeof (drhd))) {
		switch (print_iommu_state(&iommu, &drhd)) {
		case DEV_SCOPE:
			/*
			 * Use actual address of list_t in kernel for walker
			 */
			print_device_scope("  Device Scope:\t\t\t",
			    (uintptr_t)((char *)iommu.iu_drhd +
			    offsetof(drhd_info_t, di_dev_list)));
			break;
		case ERROR_SCOPE:
			return (DCMD_ERR);
		default:
			break;
		}
	} else {
		mdb_warn("failed to read iommu state at %p\n", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * print_iommu_addr()
 * callback to print addresses of IOMMU unit software structures
 */
static int
print_iommu_addr(uintptr_t addr, intel_iommu_state_t *ip, void *cbdata)
{
	_NOTE(ARGUNUSED(cbdata))
	_NOTE(ARGUNUSED(ip))
	intel_iommu_state_t iommu;

	if (mdb_vread(&iommu, sizeof (iommu), addr) != sizeof (iommu)) {
		mdb_warn("failed to read IOMMU structure at %p\n", addr);
		return (WALK_ERR);
	}

	mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*
 * dcmd: iomunits
 */
static int
iomunits(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(addr))
	_NOTE(ARGUNUSED(argv))
	GElf_Sym sym;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if ((flags & DCMD_ADDRSPEC) || (argc != 0)) {
		return (DCMD_USAGE);
	}

	if (mdb_lookup_by_name("iommu_states", &sym) == -1) {
		mdb_warn("failed to find symbol iommu_states\n");
		return (DCMD_ERR);
	}

	addr = (uintptr_t)sym.st_value;
	if (mdb_pwalk("list", (mdb_walk_cb_t)print_iommu_addr, NULL, addr)) {
		mdb_warn("couldn't walk IOMMU state structures\n");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}



/*
 * print_domain_state()
 *   Given an device domain structure, parse and print information
 */
static void
print_domain_state(dmar_domain_state_t *domain)
{
	if (domain == NULL) {
		mdb_warn("Internal error: NULL domain pointer passed\n");
		return;
	}

	mdb_printf("IOMMU device domain:\n");
	mdb_printf("Domain ID:\t\t%d\n", domain->dm_domain_id);
	mdb_printf("Bind IOMMU:\t\t%p\n", (uintptr_t)domain->dm_iommu);
	mdb_printf("DVMA vmem:\t\t%p\n",
	    (uintptr_t)domain->dm_dvma_map);
	mdb_printf("Top Level Page Table:\t%p\n",
	    (uintptr_t)domain->dm_page_table_paddr);
	mdb_printf("Identity Mapping:\t\t%s\n",
	    domain->dm_identity ? "YES" : "NO");
}

/*
 * dcmd: iomudomprt
 */
static int
iomudomprt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(argv))
	dmar_domain_state_t domain;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if ((argc != 0) || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (!DCMD_HDRSPEC(flags))
		mdb_printf("\n");

	if (mdb_vread(&domain, sizeof (domain), addr) == sizeof (domain)) {
		print_domain_state(&domain);
	} else {
		mdb_warn("failed to read domain at %p\n", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * print_domain_addr()
 */
static int
print_domain_addr(uintptr_t addr, dmar_domain_state_t *domp, void *cbdata)
{
	_NOTE(ARGUNUSED(domp))
	_NOTE(ARGUNUSED(cbdata))
	dmar_domain_state_t domain;

	if (iommu_supported() == B_FALSE)
		return (WALK_NEXT);

	if (mdb_vread(&domain, sizeof (domain), addr) != sizeof (domain)) {
		mdb_warn("failed to read domain at %p\n", addr);
		return (WALK_ERR);
	}

	mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*
 * dcmd: iomudoms
 */
static int
iomudoms(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(addr))
	_NOTE(ARGUNUSED(argv))
	GElf_Sym sym;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if ((flags & DCMD_ADDRSPEC) || (argc != 0)) {
		return (DCMD_USAGE);
	}

	if (mdb_lookup_by_name("domain_states", &sym) == -1) {
		mdb_warn("failed to find symbol domain_states\n");
		return (DCMD_ERR);
	}

	addr = (uintptr_t)sym.st_value;
	if (mdb_pwalk("list", (mdb_walk_cb_t)print_domain_addr, NULL, addr))
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*
 * print_rmrr_info()
 */
static void
print_rmrr_info(rmrr_info_t *rmrr)
{
	mdb_printf("Reserved Memory Region Reporting:\n");
	mdb_printf("  Segment:\t%d\n", rmrr->ri_segment);
	mdb_printf("  BaseAddr:\t%p\n", (uintptr_t)rmrr->ri_baseaddr);
	mdb_printf("  LimiAddr:\t%p\n", (uintptr_t)rmrr->ri_limiaddr);
}

/*
 * print_rmrr_addr()
 *   list walk callback for list_rmrr
 */
static int
print_rmrr_addr(uintptr_t addr, rmrr_info_t *rp, void *cbdata)
{
	_NOTE(ARGUNUSED(rp))
	_NOTE(ARGUNUSED(cbdata))
	rmrr_info_t rmrr;

	if (mdb_vread(&rmrr, sizeof (rmrr), addr) != sizeof (rmrr)) {
		mdb_warn("failed to read RMRR structure at %p\n", addr);
		return (WALK_ERR);
	}

	mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*
 * dcmd: iomurmrrs
 */
static int
iomurmrrs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(addr))
	_NOTE(ARGUNUSED(argv))
	GElf_Sym sym;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if ((flags & DCMD_ADDRSPEC) || (argc != 0)) {
		return (DCMD_USAGE);
	}

	if (mdb_lookup_by_name("rmrr_states", &sym) == -1) {
		mdb_warn("failed to find symbol rmrr_states\n");
		return (DCMD_ERR);
	}

	addr = (uintptr_t)sym.st_value;
	if (mdb_pwalk("list", (mdb_walk_cb_t)print_rmrr_addr, NULL, addr))
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*
 * dcmd: iomurmrrprt: Given an RMRR address print the RMRR.
 */
static int
iomurmrrprt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(argv))
	uintptr_t dev_list_addr;
	rmrr_info_t rmrr;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if (!(flags & DCMD_ADDRSPEC) || (argc != 0)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&rmrr, sizeof (rmrr), addr) != sizeof (rmrr)) {
		mdb_warn("failed to read RMRR structure at %p\n", addr);
		return (DCMD_ERR);
	}

	dev_list_addr = addr + offsetof(rmrr_info_t, ri_dev_list);
	print_rmrr_info(&rmrr);
	print_device_scope("  DevScope:\t", dev_list_addr);

	return (DCMD_OK);
}

/*
 * iova_level_to_offset()
 *   Given an iova and page table level, return the corresponding offset
 */
static int
iova_level_to_offset(uintptr_t iova, int level)
{
	int start, offset;

	start = (level - 1) * IOMMU_LEVEL_STRIDE + IOMMU_PAGE_SHIFT;
	offset = (iova >> start) & IOMMU_LEVEL_OFFSET;

	return (offset);
}

/*
 * iovtp_read_table_entry()
 */
static int
iovtp_read_table_entry(uint64_t ptaddr, size_t offset,
    void *ent_buf, size_t ent_size)
{
	if (mdb_pread(ent_buf, ent_size, ptaddr + offset * ent_size)
	    != ent_size) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

/*
 * dcmd: iomuvtop
 */
static int
iomuvtop(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	iommu_private_t private;
	dmar_domain_state_t domain;
	struct dev_info dinfo;
	intel_iommu_state_t iommu;
	int i, level, offset;
	uintptr_t iova;
	uint64_t ptaddr, ptentr;
	int bus, devfn;

	struct root_context_entry {
		uint64_t asr;
		uint64_t pro;
	} rc_entry;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if (!(flags & DCMD_ADDRSPEC) || (argc != 1)) {
		return (DCMD_USAGE);
	}

	iova = (argv[0].a_type == MDB_TYPE_IMMEDIATE) ?
	    (uintptr_t)argv[0].a_un.a_val :
	    (uintptr_t)mdb_strtoull(argv->a_un.a_str);

	/* read iommu private */
	if ((mdb_vread(&dinfo, sizeof (dinfo), addr) != sizeof (dinfo)) ||
	    (dinfo.devi_iommu_private == NULL) ||
	    (mdb_vread(&private, sizeof (private),
	    (uintptr_t)dinfo.devi_iommu_private) != sizeof (private))) {
		mdb_warn("failed to read iommu private structure for "
		    "devinfo node at address %p\n", addr);
		return (DCMD_ERR);
	}

	bus = private.idp_bus;
	devfn = private.idp_devfn;

	/* read domain */
	if (private.idp_intel_domain == NULL) {
		mdb_printf("IOMMU domain for this device has not yet been "
		    "allocated.\nNo mapped physical address for this vaddr\n");
		return (DCMD_OK);
	}

	if (mdb_vread(&domain, sizeof (domain),
	    (uintptr_t)private.idp_intel_domain)
	    != sizeof (domain)) {
		mdb_warn("failed to read domain structure at %p\n",
		    (uintptr_t)private.idp_intel_domain);
		return (DCMD_ERR);
	}

	/* read iommu */
	if (mdb_vread(&iommu, sizeof (iommu), (uintptr_t)domain.dm_iommu)
	    != sizeof (iommu)) {
		mdb_warn("failed to read iommu structure at %p\n",
		    (uintptr_t)domain.dm_iommu);
		return (DCMD_ERR);
	}

	mdb_printf("Level\tPageTableAddress\tOffset\tPageTableEntry\n");

	/* walk and print root context tabls */
	ptaddr = iommu.iu_root_entry_paddr;
	if (iovtp_read_table_entry(ptaddr, bus, &rc_entry, sizeof (rc_entry))
	    == B_FALSE) {
		mdb_warn("failed to read root table entry for bus %x "
		    "at %p\n", bus, (uintptr_t)ptaddr);
		return (DCMD_ERR);
	}
	mdb_printf("Root\t%p\t\t%x\tlow :%p\n", (uintptr_t)ptaddr,
	    bus, (uintptr_t)rc_entry.asr);
	mdb_printf("Root\t%p\t\t%x\thigh:%p\n", (uintptr_t)ptaddr,
	    bus, (uintptr_t)rc_entry.pro);

	ptaddr = rc_entry.asr & IOMMU_PAGE_MASK;
	if (iovtp_read_table_entry(ptaddr, devfn, &rc_entry, sizeof (rc_entry))
	    == B_FALSE) {
		mdb_warn("failed to read context table entry for "
		    "device-function %x at %p\n", devfn, (uintptr_t)ptaddr);
		return (DCMD_ERR);
	}
	mdb_printf("Context\t%p\t\t%x\tlow :%p\n", (uintptr_t)ptaddr,
	    devfn, (uintptr_t)rc_entry.asr);
	mdb_printf("Context\t%p\t\t%x\thigh:%p\n", (uintptr_t)ptaddr,
	    devfn, (uintptr_t)rc_entry.pro);

	/* walk and print page tables */
	ptaddr = rc_entry.asr & IOMMU_PAGE_MASK;

	/*
	 * Toppest level page table address should be the same
	 * as that stored in domain structure
	 */
	if (ptaddr != domain.dm_page_table_paddr) {
		mdb_warn("The top level page table retrieved from context"
		    " table doesn't match that from the domain structure."
		    " Aborting PA lookup.\n");
		return (DCMD_ERR);
	}

	level = iommu.iu_level;
	for (i = level; i > 0; i--) {
		if (!ptaddr) {
			mdb_printf("\nNULL page table entry encountered at "
			" page table level %d. Aborting PA lookup.\n", i);
			return (DCMD_OK);
		}
		offset = iova_level_to_offset(iova, i);
		if (iovtp_read_table_entry(ptaddr, offset, &ptentr,
		    sizeof (ptentr)) == B_FALSE) {
			mdb_warn("failed to read page table entry "
			    "(level %d) at %p\n", i, (uintptr_t)ptaddr);
			return (DCMD_ERR);
		}
		mdb_printf("%x\t%p\t\t%x\t%p\n", i, (uintptr_t)ptaddr,
		    offset, (uintptr_t)ptentr);
		ptaddr = ptentr & IOMMU_PAGE_MASK;
	}

	return (DCMD_OK);
}

typedef struct bdf_cb_data {
	int	dc_seg;
	int	dc_bus;
	int	dc_devfunc;
	int	dc_match;
} bdf_cb_data_t;

/*
 * match_bdf()
 *   call back function that matches BDF
 */
static int
match_bdf(uintptr_t addr, struct dev_info *dev, bdf_cb_data_t *cbdata)
{
	_NOTE(ARGUNUSED(addr))
	/* if there is iommu private, get it */
	if (dev->devi_iommu_private != NULL) {
		iommu_private_t private;
		if (mdb_vread((void*)&private, sizeof (private),
		    (uintptr_t)dev->devi_iommu_private) != sizeof (private)) {
			mdb_warn("failed to read iommu private at %p\n",
			    (uintptr_t)dev->devi_iommu_private);
			return (WALK_ERR);
		}

		if (private.idp_seg == cbdata->dc_seg &&
		    private.idp_bus == cbdata->dc_bus &&
		    private.idp_devfn == cbdata->dc_devfunc) {
			if (cbdata->dc_match == 0) {
				mdb_printf("%p\n", addr);
				cbdata->dc_match = 1;
			} else {
				mdb_warn("More than one devinfo node matches "
				    "a single pci device. Aborting devinfo "
				    "lookup\n");
				return (WALK_ERR);
			}
		}
	}

	return (WALK_NEXT);
}

/*
 * dcmd: bdf2devinfo
 */
static int
bdf2devinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(addr))
	bdf_cb_data_t cbdata;
	uint_t i, bdf[4];

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if ((flags & DCMD_ADDRSPEC) || (argc != 4)) {
		return (DCMD_USAGE);
	}

	for (i = 0; i < 4; i++) {
		bdf[i] = (argv[i].a_type == MDB_TYPE_IMMEDIATE) ?
		    (int)argv[i].a_un.a_val :
		    (int)mdb_strtoull(argv[i].a_un.a_str);
	}

	if ((bdf[0] != 0) || (bdf[1] > 255) || (bdf[2] > 31) || (bdf[3] > 7)) {
		mdb_warn("invalid pci segment, bus, device, function"
		    "tuple (%x, %x, %x, %x)\n", bdf[0], bdf[1], bdf[2], bdf[3]);
		return (DCMD_USAGE);
	}


	cbdata.dc_seg = bdf[0];
	cbdata.dc_bus = bdf[1];
	cbdata.dc_devfunc = bdf[2] << 3 | bdf[3];
	cbdata.dc_match = 0;

	if (mdb_readvar(&addr, "top_devinfo") == -1) {
		mdb_warn("failed to read 'top_devinfo'\n");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("devinfo",
	    (mdb_walk_cb_t)match_bdf, &cbdata, addr)) {
		mdb_warn("couldn't walk devinfo tree\n");
		return (DCMD_ERR);
	}

	if (cbdata.dc_match == 0)
		mdb_printf("No devinfo node found for %x:%x:%x:%x\n",
		    bdf[0], bdf[1], bdf[2], bdf[3]);

	return (DCMD_OK);
}

/*
 * dcmd: iomudip2dom
 */
static int
iomudip2dom(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	_NOTE(ARGUNUSED(argv))
	struct dev_info dinfo;
	iommu_private_t private;

	if (iommu_supported() == B_FALSE)
		return (DCMD_OK);

	if (!(flags & DCMD_ADDRSPEC) || (argc != 0)) {
		return (DCMD_USAGE);
	}

	/* read iommu private */
	if ((mdb_vread(&dinfo, sizeof (dinfo), addr) != sizeof (dinfo)) ||
	    (dinfo.devi_iommu_private == NULL) ||
	    (mdb_vread(&private, sizeof (private),
	    (uintptr_t)dinfo.devi_iommu_private) != sizeof (private))) {
		mdb_warn("failed to read iommu private structure for "
		    "devinfo node at %p\n", addr);
		return (DCMD_ERR);
	}

	/* read domain */
	if (private.idp_intel_domain != NULL) {
		mdb_printf("%p\n", (uintptr_t)private.idp_intel_domain);
	} else {
		mdb_printf("No domain dedicated for this device\n");
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "iomunits", NULL,
		"list addresses of software state structure for all IOMMUs",
		iomunits },
	{ "iomuprt", "?",
		"given an IOMMU's state structure address, print its contents",
		iomuprt},
	{ "iomudoms", NULL,
		"list addresses of all IOMMU domain software structures",
		iomudoms },
	{ "iomudomprt", "?",
		"given an IOMMU's domain struct address, print its contents",
		iomudomprt },
	{ "iomurmrrs", NULL,
		"list addresses of all Intel IOMMU RMRR software structures",
		iomurmrrs },
	{ "iomurmrrprt", NULL,
		"given an IOMMU RMRR structure address, print its contents",
		iomurmrrprt },
	{ "iomuvtop", "?<iova>",
		"print physical address of an IO virtual address",
		iomuvtop, iomuvtop_help },
	{ "bdf2devinfo", "[segment] [bus] [dev] [func]",
		"given its pci segment/bus/dev/func, print the devinfo node",
		bdf2devinfo },
	{ "iomudip2dom", "?",
		"given a devinfo node, print the address of its IOMMU domain",
		iomudip2dom },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	/* check to see if kernel supports iommu */
	if (mdb_lookup_by_name("intel_iommu_support", &sym) != -1) {
		if (mdb_vread(&iommu_support, sizeof (boolean_t),
		    (uintptr_t)sym.st_value) != sizeof (boolean_t)) {
			iommu_support = B_FALSE;
		}
	}

	return (&modinfo);
}
