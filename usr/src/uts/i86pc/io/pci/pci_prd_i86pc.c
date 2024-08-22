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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2019 Western Digital Corporation
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This file contains the x86 PCI platform resource discovery backend. This uses
 * data from a combination of sources, preferring ACPI, if present, and if not,
 * falling back to either the PCI hot-plug resource table or the mps tables.
 *
 * Today, to get information from ACPI we need to start from a dev_info_t. This
 * is partly why the PRD interface has a callback for getting information about
 * a dev_info_t. It also means we cannot initialize the tables with information
 * until all devices have been initially scanned.
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/sunndi.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/plat/pci_prd.h>
#include "mps_table.h"
#include "pcihrt.h"

extern int pci_bios_maxbus;

int pci_prd_debug = 0;
#define	dprintf	if (pci_prd_debug) printf
#define	dcmn_err	if (pci_prd_debug != 0) cmn_err

static int tbl_init = 0;
static uchar_t *mps_extp = NULL;
static uchar_t *mps_ext_endp = NULL;
static struct php_entry *hrt_hpep;
static uint_t hrt_entry_cnt = 0;
static int acpi_cb_cnt = 0;
static pci_prd_upcalls_t *prd_upcalls;

static void mps_probe(void);
static void acpi_pci_probe(void);
static int mps_find_bus_res(uint32_t, pci_prd_rsrc_t, struct memlist **);
static void hrt_probe(void);
static int hrt_find_bus_res(uint32_t, pci_prd_rsrc_t, struct memlist **);
static int acpi_find_bus_res(uint32_t, pci_prd_rsrc_t, struct memlist **);
static uchar_t *find_sig(uchar_t *cp, int len, char *sig);
static int checksum(unsigned char *cp, int len);
static ACPI_STATUS acpi_wr_cb(ACPI_RESOURCE *rp, void *context);
static void acpi_trim_bus_ranges(void);

/*
 * -1 = attempt ACPI resource discovery
 *  0 = don't attempt ACPI resource discovery
 *  1 = ACPI resource discovery successful
 */
volatile int acpi_resource_discovery = -1;

struct memlist *acpi_io_res[PCI_MAX_BUS_NUM];
struct memlist *acpi_mem_res[PCI_MAX_BUS_NUM];
struct memlist *acpi_pmem_res[PCI_MAX_BUS_NUM];
struct memlist *acpi_bus_res[PCI_MAX_BUS_NUM];

/*
 * This indicates whether or not we have a traditional x86 BIOS present or not.
 */
static boolean_t pci_prd_have_bios = B_TRUE;

/*
 * This value is set up as part of PCI configuration space initialization.
 */
extern int pci_bios_maxbus;

static void
acpi_pci_probe(void)
{
	ACPI_HANDLE ah;
	int bus;

	if (acpi_resource_discovery == 0)
		return;

	for (bus = 0; bus <= pci_bios_maxbus; bus++) {
		dev_info_t *dip;

		dip = prd_upcalls->pru_bus2dip_f(bus);
		if (dip == NULL ||
		    (ACPI_FAILURE(acpica_get_handle(dip, &ah))))
			continue;

		(void) AcpiWalkResources(ah, "_CRS", acpi_wr_cb,
		    (void *)(uintptr_t)bus);
	}

	if (acpi_cb_cnt > 0) {
		acpi_resource_discovery = 1;
		acpi_trim_bus_ranges();
	}
}

/*
 * Trim overlapping bus ranges in acpi_bus_res[]
 * Some BIOSes report root-bridges with bus ranges that
 * overlap, for example:"0..255" and "8..255". Lower-numbered
 * ranges are trimmed by upper-numbered ranges (so "0..255" would
 * be trimmed to "0..7", in the example).
 */
static void
acpi_trim_bus_ranges(void)
{
	struct memlist *ranges, *current;
	int bus;

	ranges = NULL;

	/*
	 * Assumptions:
	 *  - there exists at most 1 bus range entry for each bus number
	 *  - there are no (broken) ranges that start at the same bus number
	 */
	for (bus = 0; bus < PCI_MAX_BUS_NUM; bus++) {
		struct memlist *prev, *orig, *new;
		/* skip buses with no range entry */
		if ((orig = acpi_bus_res[bus]) == NULL)
			continue;

		/*
		 * create copy of existing range and overload
		 * 'prev' pointer to link existing to new copy
		 */
		new = pci_memlist_alloc();
		new->ml_address = orig->ml_address;
		new->ml_size = orig->ml_size;
		new->ml_prev = orig;

		/* sorted insertion of 'new' into ranges list */
		for (current = ranges, prev = NULL; current != NULL;
		    prev = current, current = current->ml_next)
			if (new->ml_address < current->ml_address)
				break;

		if (prev == NULL) {
			/* place at beginning of (possibly) empty list */
			new->ml_next = ranges;
			ranges = new;
		} else {
			/* place in list (possibly at end) */
			new->ml_next = current;
			prev->ml_next = new;
		}
	}

	/* scan the list, perform trimming */
	current = ranges;
	while (current != NULL) {
		struct memlist *next = current->ml_next;

		/* done when no range above current */
		if (next == NULL)
			break;

		/*
		 * trim size in original range element
		 * (current->ml_prev points to the original range)
		 */
		if ((current->ml_address + current->ml_size) > next->ml_address)
			current->ml_prev->ml_size =
			    next->ml_address - current->ml_address;

		current = next;
	}

	/* discard the list */
	pci_memlist_free_all(&ranges);	/* OK if ranges == NULL */
}

static int
acpi_find_bus_res(uint32_t bus, pci_prd_rsrc_t type, struct memlist **res)
{
	ASSERT3U(bus, <, PCI_MAX_BUS_NUM);

	switch (type) {
	case PCI_PRD_R_IO:
		*res = acpi_io_res[bus];
		break;
	case PCI_PRD_R_MMIO:
		*res = acpi_mem_res[bus];
		break;
	case PCI_PRD_R_PREFETCH:
		*res = acpi_pmem_res[bus];
		break;
	case PCI_PRD_R_BUS:
		*res = acpi_bus_res[bus];
		break;
	default:
		*res = NULL;
		break;
	}

	/* pci_memlist_count() treats NULL head as zero-length */
	return (pci_memlist_count(*res));
}

static struct memlist **
rlistpp(UINT8 t, UINT8 caching, int bus)
{
	switch (t) {
	case ACPI_MEMORY_RANGE:
		if (caching == ACPI_PREFETCHABLE_MEMORY)
			return (&acpi_pmem_res[bus]);
		else
			return (&acpi_mem_res[bus]);
		break;

	case ACPI_IO_RANGE:
		return (&acpi_io_res[bus]);
		break;

	case ACPI_BUS_NUMBER_RANGE:
		return (&acpi_bus_res[bus]);
		break;
	}

	return (NULL);
}

static void
acpi_dbg(uint_t bus, uint64_t addr, uint64_t len, uint8_t caching, uint8_t type,
    char *tag)
{
	char *s;

	switch (type) {
	case ACPI_MEMORY_RANGE:
		s = "MEM";
		break;
	case ACPI_IO_RANGE:
		s = "IO";
		break;
	case ACPI_BUS_NUMBER_RANGE:
		s = "BUS";
		break;
	default:
		s = "???";
		break;
	}

	dprintf("ACPI: bus %x %s/%s %lx/%lx (Caching: %x)\n", bus,
	    tag, s, addr, len, caching);
}


static ACPI_STATUS
acpi_wr_cb(ACPI_RESOURCE *rp, void *context)
{
	int bus = (intptr_t)context;

	/* ignore consumed resources */
	if (rp->Data.Address.ProducerConsumer == 1)
		return (AE_OK);

	switch (rp->Type) {
	case ACPI_RESOURCE_TYPE_IRQ:
		/* never expect to see a PCI bus produce an Interrupt */
		dprintf("%s\n", "IRQ");
		break;

	case ACPI_RESOURCE_TYPE_DMA:
		/* never expect to see a PCI bus produce DMA */
		dprintf("%s\n", "DMA");
		break;

	case ACPI_RESOURCE_TYPE_START_DEPENDENT:
		dprintf("%s\n", "START_DEPENDENT");
		break;

	case ACPI_RESOURCE_TYPE_END_DEPENDENT:
		dprintf("%s\n", "END_DEPENDENT");
		break;

	case ACPI_RESOURCE_TYPE_IO:
		if (rp->Data.Io.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		pci_memlist_insert(&acpi_io_res[bus], rp->Data.Io.Minimum,
		    rp->Data.Io.AddressLength);
		if (pci_prd_debug != 0) {
			acpi_dbg(bus, rp->Data.Io.Minimum,
			    rp->Data.Io.AddressLength, 0, ACPI_IO_RANGE, "IO");
		}
		break;

	case ACPI_RESOURCE_TYPE_FIXED_IO:
		/* only expect to see this as a consumer */
		dprintf("%s\n", "FIXED_IO");
		break;

	case ACPI_RESOURCE_TYPE_VENDOR:
		dprintf("%s\n", "VENDOR");
		break;

	case ACPI_RESOURCE_TYPE_END_TAG:
		dprintf("%s\n", "END_TAG");
		break;

	case ACPI_RESOURCE_TYPE_MEMORY24:
		/* only expect to see this as a consumer */
		dprintf("%s\n", "MEMORY24");
		break;

	case ACPI_RESOURCE_TYPE_MEMORY32:
		/* only expect to see this as a consumer */
		dprintf("%s\n", "MEMORY32");
		break;

	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
		/* only expect to see this as a consumer */
		dprintf("%s\n", "FIXED_MEMORY32");
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS16:
		if (rp->Data.Address16.Address.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		pci_memlist_insert(rlistpp(rp->Data.Address16.ResourceType,
		    rp->Data.Address.Info.Mem.Caching, bus),
		    rp->Data.Address16.Address.Minimum,
		    rp->Data.Address16.Address.AddressLength);
		if (pci_prd_debug != 0) {
			acpi_dbg(bus,
			    rp->Data.Address16.Address.Minimum,
			    rp->Data.Address16.Address.AddressLength,
			    rp->Data.Address.Info.Mem.Caching,
			    rp->Data.Address16.ResourceType, "ADDRESS16");
		}
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS32:
		if (rp->Data.Address32.Address.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		pci_memlist_insert(rlistpp(rp->Data.Address32.ResourceType,
		    rp->Data.Address.Info.Mem.Caching, bus),
		    rp->Data.Address32.Address.Minimum,
		    rp->Data.Address32.Address.AddressLength);
		if (pci_prd_debug != 0) {
			acpi_dbg(bus,
			    rp->Data.Address32.Address.Minimum,
			    rp->Data.Address32.Address.AddressLength,
			    rp->Data.Address.Info.Mem.Caching,
			    rp->Data.Address32.ResourceType, "ADDRESS32");
		}
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS64:
		if (rp->Data.Address64.Address.AddressLength == 0)
			break;

		acpi_cb_cnt++;
		pci_memlist_insert(rlistpp(rp->Data.Address64.ResourceType,
		    rp->Data.Address.Info.Mem.Caching, bus),
		    rp->Data.Address64.Address.Minimum,
		    rp->Data.Address64.Address.AddressLength);
		if (pci_prd_debug != 0) {
			acpi_dbg(bus,
			    rp->Data.Address64.Address.Minimum,
			    rp->Data.Address64.Address.AddressLength,
			    rp->Data.Address.Info.Mem.Caching,
			    rp->Data.Address64.ResourceType, "ADDRESS64");
		}
		break;

	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
		if (rp->Data.ExtAddress64.Address.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		pci_memlist_insert(rlistpp(rp->Data.ExtAddress64.ResourceType,
		    rp->Data.Address.Info.Mem.Caching, bus),
		    rp->Data.ExtAddress64.Address.Minimum,
		    rp->Data.ExtAddress64.Address.AddressLength);
		if (pci_prd_debug != 0) {
			acpi_dbg(bus,
			    rp->Data.ExtAddress64.Address.Minimum,
			    rp->Data.ExtAddress64.Address.AddressLength,
			    rp->Data.Address.Info.Mem.Caching,
			    rp->Data.ExtAddress64.ResourceType, "EXTADDRESS64");
		}
		break;

	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
		/* never expect to see a PCI bus produce an Interrupt */
		dprintf("%s\n", "EXTENDED_IRQ");
		break;

	case ACPI_RESOURCE_TYPE_GENERIC_REGISTER:
		/* never expect to see a PCI bus produce an GAS */
		dprintf("%s\n", "GENERIC_REGISTER");
		break;
	}

	return (AE_OK);
}

static void
mps_probe(void)
{
	uchar_t *extp;
	struct mps_fps_hdr *fpp = NULL;
	struct mps_ct_hdr *ctp;
	uintptr_t ebda_start, base_end;
	ushort_t ebda_seg, base_size, ext_len, base_len, base_end_seg;

	base_size = *((ushort_t *)(0x413));
	ebda_seg = *((ushort_t *)(0x40e));
	ebda_start = ((uint32_t)ebda_seg) << 4;
	if (ebda_seg != 0) {
		fpp = (struct mps_fps_hdr *)find_sig(
		    (uchar_t *)ebda_start, 1024, "_MP_");
	}
	if (fpp == NULL) {
		base_end_seg = (base_size > 512) ? 0x9FC0 : 0x7FC0;
		if (base_end_seg != ebda_seg) {
			base_end = ((uintptr_t)base_end_seg) << 4;
			fpp = (struct mps_fps_hdr *)find_sig(
			    (uchar_t *)base_end, 1024, "_MP_");
		}
	}
	if (fpp == NULL) {
		fpp = (struct mps_fps_hdr *)find_sig(
		    (uchar_t *)0xF0000, 0x10000, "_MP_");
	}

	if (fpp == NULL) {
		dprintf("MP Spec table doesn't exist");
		return;
	} else {
		dprintf("Found MP Floating Pointer Structure at %p\n",
		    (void *)fpp);
	}

	if (checksum((uchar_t *)fpp, fpp->fps_len * 16) != 0) {
		dprintf("MP Floating Pointer Structure checksum error");
		return;
	}

	ctp = (struct mps_ct_hdr *)(uintptr_t)fpp->fps_mpct_paddr;
	if (ctp->ct_sig != 0x504d4350) { /* check "PCMP" signature */
		dprintf("MP Configuration Table signature is wrong");
		return;
	}

	base_len = ctp->ct_len;
	if (checksum((uchar_t *)ctp, base_len) != 0) {
		dprintf("MP Configuration Table checksum error");
		return;
	}
	if (ctp->ct_spec_rev != 4) { /* not MPSpec rev 1.4 */
		dprintf("MP Spec 1.1 found - extended table doesn't exist");
		return;
	}
	if ((ext_len = ctp->ct_ext_tbl_len) == 0) {
		dprintf("MP Spec 1.4 found - extended table doesn't exist");
		return;
	}
	extp = (uchar_t *)ctp + base_len;
	if (((checksum(extp, ext_len) + ctp->ct_ext_cksum) & 0xFF) != 0) {
		dprintf("MP Extended Table checksum error");
		return;
	}
	mps_extp = extp;
	mps_ext_endp = mps_extp + ext_len;
}


static int
mps_find_bus_res(uint32_t bus, pci_prd_rsrc_t rsrc, struct memlist **res)
{
	struct sasm *sasmp;
	uchar_t *extp;
	int res_cnt, type;

	ASSERT3U(bus, <, PCI_MAX_BUS_NUM);

	if (mps_extp == NULL)
		return (0);

	switch (rsrc) {
	case PCI_PRD_R_IO:
		type = IO_TYPE;
		break;
	case PCI_PRD_R_MMIO:
		type = MEM_TYPE;
		break;
	case PCI_PRD_R_PREFETCH:
		type = PREFETCH_TYPE;
		break;
	case PCI_PRD_R_BUS:
		type = BUSRANGE_TYPE;
		break;
	default:
		*res = NULL;
		return (0);
	}

	extp = mps_extp;
	res_cnt = 0;
	while (extp < mps_ext_endp) {
		switch (*extp) {
		case SYS_AS_MAPPING:
			sasmp = (struct sasm *)extp;
			if (sasmp->sasm_as_type == type &&
			    sasmp->sasm_bus_id == bus) {
				uint64_t base, len;

				base = (uint64_t)sasmp->sasm_as_base |
				    (uint64_t)sasmp->sasm_as_base_hi << 32;
				len = (uint64_t)sasmp->sasm_as_len |
				    (uint64_t)sasmp->sasm_as_len_hi << 32;
				pci_memlist_insert(res, base, len);
				res_cnt++;
			}
			extp += SYS_AS_MAPPING_SIZE;
			break;
		case BUS_HIERARCHY_DESC:
			extp += BUS_HIERARCHY_DESC_SIZE;
			break;
		case COMP_BUS_AS_MODIFIER:
			extp += COMP_BUS_AS_MODIFIER_SIZE;
			break;
		default:
			cmn_err(CE_WARN, "Unknown descriptor type %d"
			    " in BIOS Multiprocessor Spec table.",
			    *extp);
			pci_memlist_free_all(res);
			return (0);
		}
	}
	return (res_cnt);
}

static void
hrt_probe(void)
{
	struct hrt_hdr *hrtp;

	dprintf("search PCI Hot-Plug Resource Table starting at 0xF0000\n");
	if ((hrtp = (struct hrt_hdr *)find_sig((uchar_t *)0xF0000,
	    0x10000, "$HRT")) == NULL) {
		dprintf("NO PCI Hot-Plug Resource Table");
		return;
	}
	dprintf("Found PCI Hot-Plug Resource Table at %p\n", (void *)hrtp);
	if (hrtp->hrt_ver != 1) {
		dprintf("PCI Hot-Plug Resource Table version no. <> 1\n");
		return;
	}
	hrt_entry_cnt = (uint_t)hrtp->hrt_entry_cnt;
	dprintf("No. of PCI hot-plug slot entries = 0x%x\n", hrt_entry_cnt);
	hrt_hpep = (struct php_entry *)(hrtp + 1);
}

static int
hrt_find_bus_res(uint32_t bus, pci_prd_rsrc_t type, struct memlist **res)
{
	int res_cnt;
	struct php_entry *hpep;

	ASSERT3U(bus, <, PCI_MAX_BUS_NUM);

	if (hrt_hpep == NULL || hrt_entry_cnt == 0)
		return (0);
	hpep = hrt_hpep;
	res_cnt = 0;
	for (uint_t i = 0; i < hrt_entry_cnt; i++, hpep++) {
		if (hpep->php_pri_bus != bus)
			continue;
		if (type == PCI_PRD_R_IO) {
			if (hpep->php_io_start == 0 || hpep->php_io_size == 0)
				continue;
			pci_memlist_insert(res, (uint64_t)hpep->php_io_start,
			    (uint64_t)hpep->php_io_size);
			res_cnt++;
		} else if (type == PCI_PRD_R_MMIO) {
			if (hpep->php_mem_start == 0 || hpep->php_mem_size == 0)
				continue;
			pci_memlist_insert(res,
			    ((uint64_t)hpep->php_mem_start) << 16,
			    ((uint64_t)hpep->php_mem_size) << 16);
			res_cnt++;
		} else if (type == PCI_PRD_R_PREFETCH) {
			if (hpep->php_pfmem_start == 0 ||
			    hpep->php_pfmem_size == 0)
				continue;
			pci_memlist_insert(res,
			    ((uint64_t)hpep->php_pfmem_start) << 16,
			    ((uint64_t)hpep->php_pfmem_size) << 16);
			res_cnt++;
		}
	}
	return (res_cnt);
}

static uchar_t *
find_sig(uchar_t *cp, int len, char *sig)
{
	long i;

	/* Search for the "_MP_"  or "$HRT" signature */
	for (i = 0; i < len; i += 16) {
		if (cp[0] == sig[0] && cp[1] == sig[1] &&
		    cp[2] == sig[2] && cp[3] == sig[3])
			return (cp);
		cp += 16;
	}
	return (NULL);
}

static int
checksum(unsigned char *cp, int len)
{
	int i;
	unsigned int cksum;

	for (i = cksum = 0; i < len; i++)
		cksum += (unsigned int) *cp++;

	return ((int)(cksum & 0xFF));
}

uint32_t
pci_prd_max_bus(void)
{
	return ((uint32_t)pci_bios_maxbus);
}

struct memlist *
pci_prd_find_resource(uint32_t bus, pci_prd_rsrc_t rsrc)
{
	struct memlist *res = NULL;

	if (bus > pci_bios_maxbus)
		return (NULL);

	if (tbl_init == 0) {
		tbl_init = 1;
		acpi_pci_probe();
		if (pci_prd_have_bios) {
			hrt_probe();
			mps_probe();
		}
	}

	if (acpi_find_bus_res(bus, rsrc, &res) > 0)
		return (res);

	if (pci_prd_have_bios && hrt_find_bus_res(bus, rsrc, &res) > 0)
		return (res);

	if (pci_prd_have_bios)
		(void) mps_find_bus_res(bus, rsrc, &res);
	return (res);
}

typedef struct {
	pci_prd_root_complex_f	ppac_func;
	void			*ppac_arg;
} pci_prd_acpi_cb_t;

static ACPI_STATUS
pci_process_acpi_device(ACPI_HANDLE hdl, UINT32 level, void *ctx, void **rv)
{
	ACPI_DEVICE_INFO *adi;
	int busnum;
	pci_prd_acpi_cb_t *cb = ctx;

	/*
	 * Use AcpiGetObjectInfo() to find the device _HID
	 * If not a PCI root-bus, ignore this device and continue
	 * the walk
	 */
	if (ACPI_FAILURE(AcpiGetObjectInfo(hdl, &adi)))
		return (AE_OK);

	if (!(adi->Valid & ACPI_VALID_HID)) {
		AcpiOsFree(adi);
		return (AE_OK);
	}

	if (strncmp(adi->HardwareId.String, PCI_ROOT_HID_STRING,
	    sizeof (PCI_ROOT_HID_STRING)) &&
	    strncmp(adi->HardwareId.String, PCI_EXPRESS_ROOT_HID_STRING,
	    sizeof (PCI_EXPRESS_ROOT_HID_STRING))) {
		AcpiOsFree(adi);
		return (AE_OK);
	}

	AcpiOsFree(adi);

	/*
	 * acpica_get_busno() will check the presence of _BBN and
	 * fail if not present. It will then use the _CRS method to
	 * retrieve the actual bus number assigned, it will fall back
	 * to _BBN should the _CRS method fail.
	 */
	if (ACPI_SUCCESS(acpica_get_busno(hdl, &busnum))) {
		/*
		 * Ignore invalid _BBN return values here (rather
		 * than panic) and emit a warning; something else
		 * may suffer failure as a result of the broken BIOS.
		 */
		if (busnum < 0) {
			dcmn_err(CE_NOTE,
			    "pci_process_acpi_device: invalid _BBN 0x%x",
			    busnum);
			return (AE_CTRL_DEPTH);
		}

		if (cb->ppac_func((uint32_t)busnum, cb->ppac_arg))
			return (AE_CTRL_DEPTH);
		return (AE_CTRL_TERMINATE);
	}

	/* PCI and no _BBN, continue walk */
	return (AE_OK);
}

void
pci_prd_root_complex_iter(pci_prd_root_complex_f func, void *arg)
{
	void *rv;
	pci_prd_acpi_cb_t cb;

	cb.ppac_func = func;
	cb.ppac_arg = arg;

	/*
	 * First scan ACPI devices for anything that might be here. After that,
	 * go through and check the old BIOS IRQ routing table for additional
	 * buses. Note, slot naming from the IRQ table comes later.
	 */
	(void) AcpiGetDevices(NULL, pci_process_acpi_device, &cb, &rv);
	pci_bios_bus_iter(func, arg);

}


/*
 * If there is actually a PCI IRQ routing table present, then we want to use
 * this to go back and update the slot name. In particular, if we have no PCI
 * IRQ routing table, then we use the existing slot names that were already set
 * up for us in picex_slot_names_prop() from the capability register. Otherwise,
 * we actually delete all slot-names properties from buses and instead use
 * something from the IRQ routing table if it exists.
 *
 * Note, the property is always deleted regardless of whether or not it exists
 * in the IRQ routing table. Finally, we have traditionally kept "pcie0" names
 * as special as apparently that can't be represented in the IRQ routing table.
 */
void
pci_prd_slot_name(uint32_t bus, dev_info_t *dip)
{
	char slotprop[256];
	int len;
	char *slotcap_name;

	if (pci_irq_nroutes == 0)
		return;

	if (dip != NULL) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pci_bus_res[bus].dip,
		    DDI_PROP_DONTPASS, "slot-names", &slotcap_name) !=
		    DDI_SUCCESS || strcmp(slotcap_name, "pcie0") != 0) {
			(void) ndi_prop_remove(DDI_DEV_T_NONE,
			    pci_bus_res[bus].dip, "slot-names");
		}
	}


	len = pci_slot_names_prop(bus, slotprop, sizeof (slotprop));
	if (len > 0) {
		if (dip != NULL) {
			ASSERT((len % sizeof (int)) == 0);
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
			    pci_bus_res[bus].dip, "slot-names",
			    (int *)slotprop, len / sizeof (int));
		} else {
			cmn_err(CE_NOTE, "!BIOS BUG: Invalid bus number in PCI "
			    "IRQ routing table; Not adding slot-names "
			    "property for incorrect bus %d", bus);
		}
	}
}

boolean_t
pci_prd_multi_root_ok(void)
{
	return (acpi_resource_discovery > 0);
}

/*
 * These compatibility flags generally exist for i86pc. We need to still
 * enumerate ISA bridges and the naming of device nodes and aliases must be kept
 * consistent lest we break boot. See uts/common/io/pciex/pci_props.c theory
 * statement for more information.
 */
pci_prd_compat_flags_t
pci_prd_compat_flags(void)
{
	return (PCI_PRD_COMPAT_ISA | PCI_PRD_COMPAT_PCI_NODE_NAME |
	    PCI_PRD_COMPAT_SUBSYS);
}

int
pci_prd_init(pci_prd_upcalls_t *upcalls)
{
	if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_root_node(), DDI_PROP_DONTPASS,
	    "efi-systab")) {
		pci_prd_have_bios = B_FALSE;
	}

	prd_upcalls = upcalls;

	return (0);
}

void
pci_prd_fini(void)
{
	int bus;

	for (bus = 0; bus <= pci_bios_maxbus; bus++) {
		pci_memlist_free_all(&acpi_io_res[bus]);
		pci_memlist_free_all(&acpi_mem_res[bus]);
		pci_memlist_free_all(&acpi_pmem_res[bus]);
		pci_memlist_free_all(&acpi_bus_res[bus]);
	}
}

static struct modlmisc pci_prd_modlmisc_i86pc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "i86pc PCI Resource Discovery"
};

static struct modlinkage pci_prd_modlinkage_i86pc = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &pci_prd_modlmisc_i86pc, NULL }
};

int
_init(void)
{
	return (mod_install(&pci_prd_modlinkage_i86pc));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pci_prd_modlinkage_i86pc, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&pci_prd_modlinkage_i86pc));
}
