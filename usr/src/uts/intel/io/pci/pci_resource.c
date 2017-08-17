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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Joyent, Inc.
 *
 * pci_resource.c -- routines to retrieve available bus resources from
 *		 the MP Spec. Table and Hotplug Resource Table
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/pci_impl.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include "mps_table.h"
#include "pcihrt.h"

extern int pci_boot_debug;
extern int pci_bios_maxbus;
#define	dprintf	if (pci_boot_debug) printf

static int tbl_init = 0;
static uchar_t *mps_extp = NULL;
static uchar_t *mps_ext_endp = NULL;
static struct php_entry *hrt_hpep;
static int hrt_entry_cnt = 0;
static int acpi_cb_cnt = 0;

static void mps_probe(void);
static void acpi_pci_probe(void);
static int mps_find_bus_res(int, int, struct memlist **);
static void hrt_probe(void);
static int hrt_find_bus_res(int, int, struct memlist **);
static int acpi_find_bus_res(int, int, struct memlist **);
static uchar_t *find_sig(uchar_t *cp, int len, char *sig);
static int checksum(unsigned char *cp, int len);
static ACPI_STATUS acpi_wr_cb(ACPI_RESOURCE *rp, void *context);
void bus_res_fini(void);
static void acpi_trim_bus_ranges(void);

struct memlist *acpi_io_res[256];
struct memlist *acpi_mem_res[256];
struct memlist *acpi_pmem_res[256];
struct memlist *acpi_bus_res[256];

/*
 * -1 = attempt ACPI resource discovery
 *  0 = don't attempt ACPI resource discovery
 *  1 = ACPI resource discovery successful
 */
volatile int acpi_resource_discovery = -1;

struct memlist *
find_bus_res(int bus, int type)
{
	struct memlist *res = NULL;
	boolean_t bios = B_TRUE;

	/* if efi-systab property exist, there is no BIOS */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_root_node(), DDI_PROP_DONTPASS,
	    "efi-systab")) {
		bios = B_FALSE;
	}

	if (tbl_init == 0) {
		tbl_init = 1;
		acpi_pci_probe();
		if (bios) {
			hrt_probe();
			mps_probe();
		}
	}

	if (acpi_find_bus_res(bus, type, &res) > 0)
		return (res);

	if (bios && hrt_find_bus_res(bus, type, &res) > 0)
		return (res);

	if (bios)
		(void) mps_find_bus_res(bus, type, &res);
	return (res);
}


static void
acpi_pci_probe(void)
{
	ACPI_HANDLE ah;
	dev_info_t *dip;
	int bus;

	if (acpi_resource_discovery == 0)
		return;

	for (bus = 0; bus <= pci_bios_maxbus; bus++) {
		/* if no dip or no ACPI handle, no resources to discover */
		dip = pci_bus_res[bus].dip;
		if ((dip == NULL) ||
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
acpi_trim_bus_ranges()
{
	struct memlist *ranges, *current;
	int bus;

	ranges = NULL;

	/*
	 * Assumptions:
	 *  - there exists at most 1 bus range entry for each bus number
	 *  - there are no (broken) ranges that start at the same bus number
	 */
	for (bus = 0; bus < 256; bus++) {
		struct memlist *prev, *orig, *new;
		/* skip buses with no range entry */
		if ((orig = acpi_bus_res[bus]) == NULL)
			continue;

		/*
		 * create copy of existing range and overload
		 * 'prev' pointer to link existing to new copy
		 */
		new = memlist_alloc();
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
	memlist_free_all(&ranges);	/* OK if ranges == NULL */
}

static int
acpi_find_bus_res(int bus, int type, struct memlist **res)
{

	switch (type) {
	case IO_TYPE:
		*res = acpi_io_res[bus];
		break;
	case MEM_TYPE:
		*res = acpi_mem_res[bus];
		break;
	case PREFETCH_TYPE:
		*res = acpi_pmem_res[bus];
		break;
	case BUSRANGE_TYPE:
		*res = acpi_bus_res[bus];
		break;
	default:
		*res = NULL;
		break;
	}

	/* memlist_count() treats NULL head as zero-length */
	return (memlist_count(*res));
}

void
bus_res_fini(void)
{
	int bus;

	for (bus = 0; bus <= pci_bios_maxbus; bus++) {
		memlist_free_all(&acpi_io_res[bus]);
		memlist_free_all(&acpi_mem_res[bus]);
		memlist_free_all(&acpi_pmem_res[bus]);
		memlist_free_all(&acpi_bus_res[bus]);
	}
}


struct memlist **
rlistpp(UINT8 t, UINT8 flags, int bus)
{
	switch (t) {

		case ACPI_MEMORY_RANGE:
			/* is this really the best we've got? */
			if (((flags >> 1) & 0x3) == ACPI_PREFETCHABLE_MEMORY)
				return (&acpi_pmem_res[bus]);
			else
				return (&acpi_mem_res[bus]);

		case ACPI_IO_RANGE:	return &acpi_io_res[bus];
		case ACPI_BUS_NUMBER_RANGE: return &acpi_bus_res[bus];
	}
	return ((struct memlist **)NULL);
}


ACPI_STATUS
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
		memlist_insert(&acpi_io_res[bus], rp->Data.Io.Minimum,
		    rp->Data.Io.AddressLength);
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
		memlist_insert(rlistpp(rp->Data.Address16.ResourceType,
		    rp->Data.Address16.Info.TypeSpecific, bus),
		    rp->Data.Address16.Address.Minimum,
		    rp->Data.Address16.Address.AddressLength);
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS32:
		if (rp->Data.Address32.Address.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		memlist_insert(rlistpp(rp->Data.Address32.ResourceType,
		    rp->Data.Address32.Info.TypeSpecific, bus),
		    rp->Data.Address32.Address.Minimum,
		    rp->Data.Address32.Address.AddressLength);
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS64:
	/*
	 * We comment out this block because we currently cannot deal with
	 * PCI 64-bit addresses. Will revisit this when we add PCI 64-bit MMIO
	 * support.
	 */
#if 0
		if (rp->Data.Address64.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		memlist_insert(rlistpp(rp->Data.Address64.ResourceType,
		    rp->Data.Address64.Info.TypeSpecific, bus),
		    rp->Data.Address64.Minimum,
		    rp->Data.Address64.AddressLength);
#endif
		break;

	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
#if 0	/* Will revisit this when we add PCI 64-bit MMIO support */
		if (rp->Data.ExtAddress64.AddressLength == 0)
			break;
		acpi_cb_cnt++;
		memlist_insert(rlistpp(rp->Data.ExtAddress64.ResourceType,
		    rp->Data.ExtAddress64.Info.TypeSpecific, bus),
		    rp->Data.ExtAddress64.Minimum,
		    rp->Data.ExtAddress64.AddressLength);
#endif
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
mps_probe()
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
mps_find_bus_res(int bus, int type, struct memlist **res)
{
	struct sasm *sasmp;
	uchar_t *extp;
	int res_cnt;

	if (mps_extp == NULL)
		return (0);
	extp = mps_extp;
	res_cnt = 0;
	while (extp < mps_ext_endp) {
		switch (*extp) {
		case SYS_AS_MAPPING:
			sasmp = (struct sasm *)extp;
			if (((int)sasmp->sasm_as_type) == type &&
			    ((int)sasmp->sasm_bus_id) == bus) {
				uint64_t base, len;

				base = (uint64_t)sasmp->sasm_as_base |
				    (uint64_t)sasmp->sasm_as_base_hi << 32;
				len = (uint64_t)sasmp->sasm_as_len |
				    (uint64_t)sasmp->sasm_as_len_hi << 32;
				memlist_insert(res, base, len);
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
			while (*res) {
				struct memlist *tmp = *res;
				*res = tmp->ml_next;
				memlist_free(tmp);
			}
			return (0);
		}
	}
	return (res_cnt);
}

static void
hrt_probe()
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
	hrt_entry_cnt = (int)hrtp->hrt_entry_cnt;
	dprintf("No. of PCI hot-plug slot entries = 0x%x\n", hrt_entry_cnt);
	hrt_hpep = (struct php_entry *)(hrtp + 1);
}

static int
hrt_find_bus_res(int bus, int type, struct memlist **res)
{
	int res_cnt, i;
	struct php_entry *hpep;

	if (hrt_hpep == NULL || hrt_entry_cnt == 0)
		return (0);
	hpep = hrt_hpep;
	res_cnt = 0;
	for (i = 0; i < hrt_entry_cnt; i++, hpep++) {
		if (hpep->php_pri_bus != bus)
			continue;
		if (type == IO_TYPE) {
			if (hpep->php_io_start == 0 || hpep->php_io_size == 0)
				continue;
			memlist_insert(res, (uint64_t)hpep->php_io_start,
			    (uint64_t)hpep->php_io_size);
			res_cnt++;
		} else if (type == MEM_TYPE) {
			if (hpep->php_mem_start == 0 || hpep->php_mem_size == 0)
				continue;
			memlist_insert(res,
			    (uint64_t)(((int)hpep->php_mem_start) << 16),
			    (uint64_t)(((int)hpep->php_mem_size) << 16));
			res_cnt++;
		} else if (type == PREFETCH_TYPE) {
			if (hpep->php_pfmem_start == 0 ||
			    hpep->php_pfmem_size == 0)
				continue;
			memlist_insert(res,
			    (uint64_t)(((int)hpep->php_pfmem_start) << 16),
			    (uint64_t)(((int)hpep->php_pfmem_size) << 16));
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

#ifdef UNUSED_BUS_HIERARY_INFO

/*
 * At this point, the bus hierarchy entries do not appear to
 * provide anything we can't find out from PCI config space.
 * The only interesting bit is the ISA bus number, which we
 * don't care.
 */
int
mps_find_parent_bus(int bus)
{
	struct sasm *sasmp;
	uchar_t *extp;

	if (mps_extp == NULL)
		return (-1);

	extp = mps_extp;
	while (extp < mps_ext_endp) {
		bhdp = (struct bhd *)extp;
		switch (*extp) {
		case SYS_AS_MAPPING:
			extp += SYS_AS_MAPPING_SIZE;
			break;
		case BUS_HIERARCHY_DESC:
			if (bhdp->bhd_bus_id == bus)
				return (bhdp->bhd_parent);
			extp += BUS_HIERARCHY_DESC_SIZE;
			break;
		case COMP_BUS_AS_MODIFIER:
			extp += COMP_BUS_AS_MODIFIER_SIZE;
			break;
		default:
			cmn_err(CE_WARN, "Unknown descriptor type %d"
			    " in BIOS Multiprocessor Spec table.",
			    *extp);
			return (-1);
		}
	}
	return (-1);
}

int
hrt_find_bus_range(int bus)
{
	int i, max_bus, sub_bus;
	struct php_entry *hpep;

	if (hrt_hpep == NULL || hrt_entry_cnt == 0) {
		return (-1);
	}
	hpep = hrt_hpep;
	max_bus = -1;
	for (i = 0; i < hrt_entry_cnt; i++, hpep++) {
		if (hpep->php_pri_bus != bus)
			continue;
		sub_bus = (int)hpep->php_subord_bus;
		if (sub_bus > max_bus)
			max_bus = sub_bus;
	}
	return (max_bus);
}

#endif /* UNUSED_BUS_HIERARY_INFO */
