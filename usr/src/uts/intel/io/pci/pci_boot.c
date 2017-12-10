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
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include <io/pci/mps_table.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/psw.h>
#include "../../../../common/pci/pci_strings.h"
#include <sys/apic.h>
#include <io/pciex/pcie_nvidia.h>
#include <sys/hotplug/pci/pciehpc_acpi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/iommulib.h>
#include <sys/devcache.h>
#include <sys/pci_cfgacc_x86.h>

#define	pci_getb	(*pci_getb_func)
#define	pci_getw	(*pci_getw_func)
#define	pci_getl	(*pci_getl_func)
#define	pci_putb	(*pci_putb_func)
#define	pci_putw	(*pci_putw_func)
#define	pci_putl	(*pci_putl_func)
#define	dcmn_err	if (pci_boot_debug) cmn_err

#define	CONFIG_INFO	0
#define	CONFIG_UPDATE	1
#define	CONFIG_NEW	2
#define	CONFIG_FIX	3
#define	COMPAT_BUFSIZE	512

#define	PPB_IO_ALIGNMENT	0x1000		/* 4K aligned */
#define	PPB_MEM_ALIGNMENT	0x100000	/* 1M aligned */
/* round down to nearest power of two */
#define	P2LE(align)					\
	{						\
		int i = 0;				\
		while (align >>= 1)			\
			i ++;				\
		align = 1 << i;				\
	}						\

/* for is_vga and list_is_vga_only */

enum io_mem {
	IO,
	MEM
};

/* See AMD-8111 Datasheet Rev 3.03, Page 149: */
#define	LPC_IO_CONTROL_REG_1	0x40
#define	AMD8111_ENABLENMI	(uint8_t)0x80
#define	DEVID_AMD8111_LPC	0x7468

struct pci_fixundo {
	uint8_t			bus;
	uint8_t			dev;
	uint8_t			fn;
	void			(*undofn)(uint8_t, uint8_t, uint8_t);
	struct pci_fixundo	*next;
};

struct pci_devfunc {
	struct pci_devfunc *next;
	dev_info_t *dip;
	uchar_t dev;
	uchar_t func;
	boolean_t reprogram;	/* this device needs to be reprogrammed */
};

extern int apic_nvidia_io_max;
extern int pseudo_isa;
extern int pci_bios_maxbus;
static uchar_t max_dev_pci = 32;	/* PCI standard */
int pci_boot_debug = 0;
extern struct memlist *find_bus_res(int, int);
static struct pci_fixundo *undolist = NULL;
static int num_root_bus = 0;	/* count of root buses */
extern volatile int acpi_resource_discovery;
extern uint64_t mcfg_mem_base;
extern void pci_cfgacc_add_workaround(uint16_t, uchar_t, uchar_t);
extern dev_info_t *pcie_get_rc_dip(dev_info_t *);

/*
 * Module prototypes
 */
static void enumerate_bus_devs(uchar_t bus, int config_op);
static void create_root_bus_dip(uchar_t bus);
static void process_devfunc(uchar_t, uchar_t, uchar_t, uchar_t,
    ushort_t, int);
static void add_compatible(dev_info_t *, ushort_t, ushort_t,
    ushort_t, ushort_t, uchar_t, uint_t, int);
static int add_reg_props(dev_info_t *, uchar_t, uchar_t, uchar_t, int, int);
static void add_ppb_props(dev_info_t *, uchar_t, uchar_t, uchar_t, int,
    ushort_t);
static void add_model_prop(dev_info_t *, uint_t);
static void add_bus_range_prop(int);
static void add_bus_slot_names_prop(int);
static void add_ranges_prop(int, int);
static void add_bus_available_prop(int);
static int get_pci_cap(uchar_t bus, uchar_t dev, uchar_t func, uint8_t cap_id);
static void fix_ppb_res(uchar_t, boolean_t);
static void alloc_res_array();
static void create_ioapic_node(int bus, int dev, int fn, ushort_t vendorid,
    ushort_t deviceid);
static void pciex_slot_names_prop(dev_info_t *, ushort_t);
static void populate_bus_res(uchar_t bus);
static void memlist_remove_list(struct memlist **list,
    struct memlist *remove_list);
static void ck804_fix_aer_ptr(dev_info_t *, pcie_req_id_t);

static void pci_scan_bbn(void);
static int pci_unitaddr_cache_valid(void);
static int pci_bus_unitaddr(int);
static void pci_unitaddr_cache_create(void);

static int pci_cache_unpack_nvlist(nvf_handle_t, nvlist_t *, char *);
static int pci_cache_pack_nvlist(nvf_handle_t, nvlist_t **);
static void pci_cache_free_list(nvf_handle_t);

extern int pci_slot_names_prop(int, char *, int);

/* set non-zero to force PCI peer-bus renumbering */
int pci_bus_always_renumber = 0;

/*
 * used to register ISA resource usage which must not be made
 * "available" from other PCI node' resource maps
 */
static struct {
	struct memlist *io_used;
	struct memlist *mem_used;
} isa_res;

/*
 * PCI unit-address cache management
 */
static nvf_ops_t pci_unitaddr_cache_ops = {
	"/etc/devices/pci_unitaddr_persistent",	/* path to cache */
	pci_cache_unpack_nvlist,		/* read in nvlist form */
	pci_cache_pack_nvlist,			/* convert to nvlist form */
	pci_cache_free_list,			/* free data list */
	NULL					/* write complete callback */
};

typedef struct {
	list_node_t	pua_nodes;
	int		pua_index;
	int		pua_addr;
} pua_node_t;

nvf_handle_t	puafd_handle;
int		pua_cache_valid = 0;


/*ARGSUSED*/
static ACPI_STATUS
pci_process_acpi_device(ACPI_HANDLE hdl, UINT32 level, void *ctx, void **rv)
{
	ACPI_BUFFER	rb;
	ACPI_OBJECT	ro;
	ACPI_DEVICE_INFO *adi;
	int		busnum;

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
	 * XXX: ancient Big Bear broken _BBN will result in two
	 * bus 0 _BBNs being found, so we need to handle duplicate
	 * bus 0 gracefully.  However, broken _BBN does not
	 * hide a childless root-bridge so no need to work-around it
	 * here
	 */
	rb.Pointer = &ro;
	rb.Length = sizeof (ro);
	if (ACPI_SUCCESS(AcpiEvaluateObjectTyped(hdl, "_BBN",
	    NULL, &rb, ACPI_TYPE_INTEGER))) {
		busnum = ro.Integer.Value;

		/*
		 * Ignore invalid _BBN return values here (rather
		 * than panic) and emit a warning; something else
		 * may suffer failure as a result of the broken BIOS.
		 */
		if ((busnum < 0) || (busnum > pci_bios_maxbus)) {
			dcmn_err(CE_NOTE,
			    "pci_process_acpi_device: invalid _BBN 0x%x\n",
			    busnum);
			return (AE_CTRL_DEPTH);
		}

		/* PCI with valid _BBN */
		if (pci_bus_res[busnum].par_bus == (uchar_t)-1 &&
		    pci_bus_res[busnum].dip == NULL)
			create_root_bus_dip((uchar_t)busnum);
		return (AE_CTRL_DEPTH);
	}

	/* PCI and no _BBN, continue walk */
	return (AE_OK);
}

/*
 * Scan the ACPI namespace for all top-level instances of _BBN
 * in order to discover childless root-bridges (which enumeration
 * may not find; root-bridges are inferred by the existence of
 * children).  This scan should find all root-bridges that have
 * been enumerated, and any childless root-bridges not enumerated.
 * Root-bridge for bus 0 may not have a _BBN object.
 */
static void
pci_scan_bbn()
{
	void *rv;

	(void) AcpiGetDevices(NULL, pci_process_acpi_device, NULL, &rv);
}

static void
pci_unitaddr_cache_init(void)
{

	puafd_handle = nvf_register_file(&pci_unitaddr_cache_ops);
	ASSERT(puafd_handle);

	list_create(nvf_list(puafd_handle), sizeof (pua_node_t),
	    offsetof(pua_node_t, pua_nodes));

	rw_enter(nvf_lock(puafd_handle), RW_WRITER);
	(void) nvf_read_file(puafd_handle);
	rw_exit(nvf_lock(puafd_handle));
}

/*
 * Format of /etc/devices/pci_unitaddr_persistent:
 *
 * The persistent record of unit-address assignments contains
 * a list of name/value pairs, where name is a string representation
 * of the "index value" of the PCI root-bus and the value is
 * the assigned unit-address.
 *
 * The "index value" is simply the zero-based index of the PCI
 * root-buses ordered by physical bus number; first PCI bus is 0,
 * second is 1, and so on.
 */

/*ARGSUSED*/
static int
pci_cache_unpack_nvlist(nvf_handle_t hdl, nvlist_t *nvl, char *name)
{
	long		index;
	int32_t		value;
	nvpair_t	*np;
	pua_node_t	*node;

	np = NULL;
	while ((np = nvlist_next_nvpair(nvl, np)) != NULL) {
		/* name of nvpair is index value */
		if (ddi_strtol(nvpair_name(np), NULL, 10, &index) != 0)
			continue;

		if (nvpair_value_int32(np, &value) != 0)
			continue;

		node = kmem_zalloc(sizeof (pua_node_t), KM_SLEEP);
		node->pua_index = index;
		node->pua_addr = value;
		list_insert_tail(nvf_list(hdl), node);
	}

	pua_cache_valid = 1;
	return (DDI_SUCCESS);
}

static int
pci_cache_pack_nvlist(nvf_handle_t hdl, nvlist_t **ret_nvl)
{
	int		rval;
	nvlist_t	*nvl, *sub_nvl;
	list_t		*listp;
	pua_node_t	*pua;
	char		buf[13];

	ASSERT(RW_WRITE_HELD(nvf_lock(hdl)));

	rval = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != DDI_SUCCESS) {
		nvf_error("%s: nvlist alloc error %d\n",
		    nvf_cache_name(hdl), rval);
		return (DDI_FAILURE);
	}

	sub_nvl = NULL;
	rval = nvlist_alloc(&sub_nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != DDI_SUCCESS)
		goto error;

	listp = nvf_list(hdl);
	for (pua = list_head(listp); pua != NULL;
	    pua = list_next(listp, pua)) {
		(void) snprintf(buf, sizeof (buf), "%d", pua->pua_index);
		rval = nvlist_add_int32(sub_nvl, buf, pua->pua_addr);
		if (rval != DDI_SUCCESS)
			goto error;
	}

	rval = nvlist_add_nvlist(nvl, "table", sub_nvl);
	if (rval != DDI_SUCCESS)
		goto error;
	nvlist_free(sub_nvl);

	*ret_nvl = nvl;
	return (DDI_SUCCESS);

error:
	nvlist_free(sub_nvl);
	ASSERT(nvl);
	nvlist_free(nvl);
	*ret_nvl = NULL;
	return (DDI_FAILURE);
}

static void
pci_cache_free_list(nvf_handle_t hdl)
{
	list_t		*listp;
	pua_node_t	*pua;

	ASSERT(RW_WRITE_HELD(nvf_lock(hdl)));

	listp = nvf_list(hdl);
	for (pua = list_head(listp); pua != NULL;
	    pua = list_next(listp, pua)) {
		list_remove(listp, pua);
		kmem_free(pua, sizeof (pua_node_t));
	}
}


static int
pci_unitaddr_cache_valid(void)
{

	/* read only, no need for rw lock */
	return (pua_cache_valid);
}


static int
pci_bus_unitaddr(int index)
{
	pua_node_t	*pua;
	list_t		*listp;
	int		addr;

	rw_enter(nvf_lock(puafd_handle), RW_READER);

	addr = -1;	/* default return if no match */
	listp = nvf_list(puafd_handle);
	for (pua = list_head(listp); pua != NULL;
	    pua = list_next(listp, pua)) {
		if (pua->pua_index == index) {
			addr = pua->pua_addr;
			break;
		}
	}

	rw_exit(nvf_lock(puafd_handle));
	return (addr);
}

static void
pci_unitaddr_cache_create(void)
{
	int		i, index;
	pua_node_t	*node;
	list_t		*listp;

	rw_enter(nvf_lock(puafd_handle), RW_WRITER);

	index = 0;
	listp = nvf_list(puafd_handle);
	for (i = 0; i <= pci_bios_maxbus; i++) {
		/* skip non-root (peer) PCI busses */
		if ((pci_bus_res[i].par_bus != (uchar_t)-1) ||
		    (pci_bus_res[i].dip == NULL))
			continue;
		node = kmem_zalloc(sizeof (pua_node_t), KM_SLEEP);
		node->pua_index = index++;
		node->pua_addr = pci_bus_res[i].root_addr;
		list_insert_tail(listp, node);
	}

	(void) nvf_mark_dirty(puafd_handle);
	rw_exit(nvf_lock(puafd_handle));
	nvf_wake_daemon();
}


/*
 * Enumerate all PCI devices
 */
void
pci_setup_tree(void)
{
	uint_t i, root_bus_addr = 0;

	alloc_res_array();
	for (i = 0; i <= pci_bios_maxbus; i++) {
		pci_bus_res[i].par_bus = (uchar_t)-1;
		pci_bus_res[i].root_addr = (uchar_t)-1;
		pci_bus_res[i].sub_bus = i;
	}

	pci_bus_res[0].root_addr = root_bus_addr++;
	create_root_bus_dip(0);
	enumerate_bus_devs(0, CONFIG_INFO);

	/*
	 * Now enumerate peer busses
	 *
	 * We loop till pci_bios_maxbus. On most systems, there is
	 * one more bus at the high end, which implements the ISA
	 * compatibility bus. We don't care about that.
	 *
	 * Note: In the old (bootconf) enumeration, the peer bus
	 *	address did not use the bus number, and there were
	 *	too many peer busses created. The root_bus_addr is
	 *	used to maintain the old peer bus address assignment.
	 *	However, we stop enumerating phantom peers with no
	 *	device below.
	 */
	for (i = 1; i <= pci_bios_maxbus; i++) {
		if (pci_bus_res[i].dip == NULL) {
			pci_bus_res[i].root_addr = root_bus_addr++;
		}
		enumerate_bus_devs(i, CONFIG_INFO);

		/* add slot-names property for named pci hot-plug slots */
		add_bus_slot_names_prop(i);
	}
}

/*
 * >0 = present, 0 = not present, <0 = error
 */
static int
pci_bbn_present(int bus)
{
	ACPI_HANDLE	hdl;
	int	rv;

	/* no dip means no _BBN */
	if (pci_bus_res[bus].dip == NULL)
		return (0);

	rv = -1;	/* default return value in case of error below */
	if (ACPI_SUCCESS(acpica_get_handle(pci_bus_res[bus].dip, &hdl))) {
		switch (AcpiEvaluateObject(hdl, "_BBN", NULL, NULL)) {
		case AE_OK:
			rv = 1;
			break;
		case AE_NOT_FOUND:
			rv = 0;
			break;
		default:
			break;
		}
	}

	return (rv);
}

/*
 * Return non-zero if any PCI bus in the system has an associated
 * _BBN object, 0 otherwise.
 */
static int
pci_roots_have_bbn(void)
{
	int	i;

	/*
	 * Scan the PCI busses and look for at least 1 _BBN
	 */
	for (i = 0; i <= pci_bios_maxbus; i++) {
		/* skip non-root (peer) PCI busses */
		if (pci_bus_res[i].par_bus != (uchar_t)-1)
			continue;

		if (pci_bbn_present(i) > 0)
			return (1);
	}
	return (0);

}

/*
 * return non-zero if the machine is one on which we renumber
 * the internal pci unit-addresses
 */
static int
pci_bus_renumber()
{
	ACPI_TABLE_HEADER *fadt;

	if (pci_bus_always_renumber)
		return (1);

	/* get the FADT */
	if (AcpiGetTable(ACPI_SIG_FADT, 1, (ACPI_TABLE_HEADER **)&fadt) !=
	    AE_OK)
		return (0);

	/* compare OEM Table ID to "SUNm31" */
	if (strncmp("SUNm31", fadt->OemId, 6))
		return (0);
	else
		return (1);
}

/*
 * Initial enumeration of the physical PCI bus hierarchy can
 * leave 'gaps' in the order of peer PCI bus unit-addresses.
 * Systems with more than one peer PCI bus *must* have an ACPI
 * _BBN object associated with each peer bus; use the presence
 * of this object to remove gaps in the numbering of the peer
 * PCI bus unit-addresses - only peer busses with an associated
 * _BBN are counted.
 */
static void
pci_renumber_root_busses(void)
{
	int pci_regs[] = {0, 0, 0};
	int	i, root_addr = 0;

	/*
	 * Currently, we only enable the re-numbering on specific
	 * Sun machines; this is a work-around for the more complicated
	 * issue of upgrade changing physical device paths
	 */
	if (!pci_bus_renumber())
		return;

	/*
	 * If we find no _BBN objects at all, we either don't need
	 * to do anything or can't do anything anyway
	 */
	if (!pci_roots_have_bbn())
		return;

	for (i = 0; i <= pci_bios_maxbus; i++) {
		/* skip non-root (peer) PCI busses */
		if (pci_bus_res[i].par_bus != (uchar_t)-1)
			continue;

		if (pci_bbn_present(i) < 1) {
			pci_bus_res[i].root_addr = (uchar_t)-1;
			continue;
		}

		ASSERT(pci_bus_res[i].dip != NULL);
		if (pci_bus_res[i].root_addr != root_addr) {
			/* update reg property for node */
			pci_bus_res[i].root_addr = root_addr;
			pci_regs[0] = pci_bus_res[i].root_addr;
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
			    pci_bus_res[i].dip, "reg", (int *)pci_regs, 3);
		}
		root_addr++;
	}
}

void
pci_register_isa_resources(int type, uint32_t base, uint32_t size)
{
	(void) memlist_insert(
	    (type == 1) ?  &isa_res.io_used : &isa_res.mem_used,
	    base, size);
}

/*
 * Remove the resources which are already used by devices under a subtractive
 * bridge from the bus's resources lists, because they're not available, and
 * shouldn't be allocated to other buses.  This is necessary because tracking
 * resources for subtractive bridges is not complete.  (Subtractive bridges only
 * track some of their claimed resources, not "the rest of the address space" as
 * they should, so that allocation to peer non-subtractive PPBs is easier.  We
 * need a fully-capable global resource allocator).
 */
static void
remove_subtractive_res()
{
	int i, j;
	struct memlist *list;

	for (i = 0; i <= pci_bios_maxbus; i++) {
		if (pci_bus_res[i].subtractive) {
			/* remove used io ports */
			list = pci_bus_res[i].io_used;
			while (list) {
				for (j = 0; j <= pci_bios_maxbus; j++)
					(void) memlist_remove(
					    &pci_bus_res[j].io_avail,
					    list->ml_address, list->ml_size);
				list = list->ml_next;
			}
			/* remove used mem resource */
			list = pci_bus_res[i].mem_used;
			while (list) {
				for (j = 0; j <= pci_bios_maxbus; j++) {
					(void) memlist_remove(
					    &pci_bus_res[j].mem_avail,
					    list->ml_address, list->ml_size);
					(void) memlist_remove(
					    &pci_bus_res[j].pmem_avail,
					    list->ml_address, list->ml_size);
				}
				list = list->ml_next;
			}
			/* remove used prefetchable mem resource */
			list = pci_bus_res[i].pmem_used;
			while (list) {
				for (j = 0; j <= pci_bios_maxbus; j++) {
					(void) memlist_remove(
					    &pci_bus_res[j].pmem_avail,
					    list->ml_address, list->ml_size);
					(void) memlist_remove(
					    &pci_bus_res[j].mem_avail,
					    list->ml_address, list->ml_size);
				}
				list = list->ml_next;
			}
		}
	}
}

/*
 * Set up (or complete the setup of) the bus_avail resource list
 */
static void
setup_bus_res(int bus)
{
	uchar_t par_bus;

	if (pci_bus_res[bus].dip == NULL)	/* unused bus */
		return;

	/*
	 * Set up bus_avail if not already filled in by populate_bus_res()
	 */
	if (pci_bus_res[bus].bus_avail == NULL) {
		ASSERT(pci_bus_res[bus].sub_bus >= bus);
		memlist_insert(&pci_bus_res[bus].bus_avail, bus,
		    pci_bus_res[bus].sub_bus - bus + 1);
	}

	ASSERT(pci_bus_res[bus].bus_avail != NULL);

	/*
	 * Remove resources from parent bus node if this is not a
	 * root bus.
	 */
	par_bus = pci_bus_res[bus].par_bus;
	if (par_bus != (uchar_t)-1) {
		ASSERT(pci_bus_res[par_bus].bus_avail != NULL);
		memlist_remove_list(&pci_bus_res[par_bus].bus_avail,
		    pci_bus_res[bus].bus_avail);
	}

	/* remove self from bus_avail */;
	(void) memlist_remove(&pci_bus_res[bus].bus_avail, bus, 1);
}

static uint64_t
get_parbus_io_res(uchar_t parbus, uchar_t bus, uint64_t size, uint64_t align)
{
	uint64_t addr = 0;
	uchar_t res_bus;

	/*
	 * Skip root(peer) buses in multiple-root-bus systems when
	 * ACPI resource discovery was not successfully done.
	 */
	if ((pci_bus_res[parbus].par_bus == (uchar_t)-1) &&
	    (num_root_bus > 1) && (acpi_resource_discovery <= 0))
		return (0);

	res_bus = parbus;
	while (pci_bus_res[res_bus].subtractive) {
		if (pci_bus_res[res_bus].io_avail)
			break;
		res_bus = pci_bus_res[res_bus].par_bus;
		if (res_bus == (uchar_t)-1)
			break; /* root bus already */
	}

	if (pci_bus_res[res_bus].io_avail) {
		addr = memlist_find(&pci_bus_res[res_bus].io_avail,
		    size, align);
		if (addr) {
			memlist_insert(&pci_bus_res[res_bus].io_used,
			    addr, size);

			/* free the old resource */
			memlist_free_all(&pci_bus_res[bus].io_avail);
			memlist_free_all(&pci_bus_res[bus].io_used);

			/* add the new resource */
			memlist_insert(&pci_bus_res[bus].io_avail, addr, size);
		}
	}

	return (addr);
}

static uint64_t
get_parbus_mem_res(uchar_t parbus, uchar_t bus, uint64_t size, uint64_t align)
{
	uint64_t addr = 0;
	uchar_t res_bus;

	/*
	 * Skip root(peer) buses in multiple-root-bus systems when
	 * ACPI resource discovery was not successfully done.
	 */
	if ((pci_bus_res[parbus].par_bus == (uchar_t)-1) &&
	    (num_root_bus > 1) && (acpi_resource_discovery <= 0))
		return (0);

	res_bus = parbus;
	while (pci_bus_res[res_bus].subtractive) {
		if (pci_bus_res[res_bus].mem_avail)
			break;
		res_bus = pci_bus_res[res_bus].par_bus;
		if (res_bus == (uchar_t)-1)
			break; /* root bus already */
	}

	if (pci_bus_res[res_bus].mem_avail) {
		addr = memlist_find(&pci_bus_res[res_bus].mem_avail,
		    size, align);
		if (addr) {
			memlist_insert(&pci_bus_res[res_bus].mem_used,
			    addr, size);
			(void) memlist_remove(&pci_bus_res[res_bus].pmem_avail,
			    addr, size);

			/* free the old resource */
			memlist_free_all(&pci_bus_res[bus].mem_avail);
			memlist_free_all(&pci_bus_res[bus].mem_used);

			/* add the new resource */
			memlist_insert(&pci_bus_res[bus].mem_avail, addr, size);
		}
	}

	return (addr);
}

/*
 * given a cap_id, return its cap_id location in config space
 */
static int
get_pci_cap(uchar_t bus, uchar_t dev, uchar_t func, uint8_t cap_id)
{
	uint8_t curcap, cap_id_loc;
	uint16_t status;
	int location = -1;

	/*
	 * Need to check the Status register for ECP support first.
	 * Also please note that for type 1 devices, the
	 * offset could change. Should support type 1 next.
	 */
	status = pci_getw(bus, dev, func, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP)) {
		return (-1);
	}
	cap_id_loc = pci_getb(bus, dev, func, PCI_CONF_CAP_PTR);

	/* Walk the list of capabilities */
	while (cap_id_loc && cap_id_loc != (uint8_t)-1) {
		curcap = pci_getb(bus, dev, func, cap_id_loc);

		if (curcap == cap_id) {
			location = cap_id_loc;
			break;
		}
		cap_id_loc = pci_getb(bus, dev, func, cap_id_loc + 1);
	}
	return (location);
}

/*
 * Does this resource element live in the legacy VGA range?
 */

int
is_vga(struct memlist *elem, enum io_mem io)
{

	if (io == IO) {
		if ((elem->ml_address == 0x3b0 && elem->ml_size == 0xc) ||
		    (elem->ml_address == 0x3c0 && elem->ml_size == 0x20))
			return (1);
	} else {
		if (elem->ml_address == 0xa0000 && elem->ml_size == 0x20000)
			return (1);
	}
	return (0);
}

/*
 * Does this entire resource list consist only of legacy VGA resources?
 */

int
list_is_vga_only(struct memlist *l, enum io_mem io)
{
	do {
		if (!is_vga(l, io))
			return (0);
	} while ((l = l->ml_next) != NULL);
	return (1);
}

/*
 * Assign valid resources to unconfigured pci(e) bridges. We are trying
 * to reprogram the bridge when its
 * 		i)   SECBUS == SUBBUS	||
 * 		ii)  IOBASE > IOLIM	||
 * 		iii) MEMBASE > MEMLIM
 * This must be done after one full pass through the PCI tree to collect
 * all BIOS-configured resources, so that we know what resources are
 * free and available to assign to the unconfigured PPBs.
 */
static void
fix_ppb_res(uchar_t secbus, boolean_t prog_sub)
{
	uchar_t bus, dev, func;
	uchar_t parbus, subbus;
	uint_t io_base, io_limit, mem_base, mem_limit;
	uint_t io_size, mem_size, io_align, mem_align;
	uint64_t addr = 0;
	int *regp = NULL;
	uint_t reglen;
	int rv, cap_ptr, physhi;
	dev_info_t *dip;
	uint16_t cmd_reg;
	struct memlist *list, *scratch_list;

	/* skip root (peer) PCI busses */
	if (pci_bus_res[secbus].par_bus == (uchar_t)-1)
		return;

	/* skip subtractive PPB when prog_sub is not TRUE */
	if (pci_bus_res[secbus].subtractive && !prog_sub)
		return;

	/* some entries may be empty due to discontiguous bus numbering */
	dip = pci_bus_res[secbus].dip;
	if (dip == NULL)
		return;

	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regp, &reglen);
	if (rv != DDI_PROP_SUCCESS || reglen == 0)
		return;
	physhi = regp[0];
	ddi_prop_free(regp);

	func = (uchar_t)PCI_REG_FUNC_G(physhi);
	dev = (uchar_t)PCI_REG_DEV_G(physhi);
	bus = (uchar_t)PCI_REG_BUS_G(physhi);

	/*
	 * If pcie bridge, check to see if link is enabled
	 */
	cap_ptr = get_pci_cap(bus, dev, func, PCI_CAP_ID_PCI_E);
	if (cap_ptr != -1) {
		cmd_reg = pci_getw(bus, dev, func,
		    (uint16_t)cap_ptr + PCIE_LINKCTL);
		if (cmd_reg & PCIE_LINKCTL_LINK_DISABLE) {
			dcmn_err(CE_NOTE,
			    "!fix_ppb_res: ppb[%x/%x/%x] link is disabled.\n",
			    bus, dev, func);
			return;
		}
	}

	subbus = pci_getb(bus, dev, func, PCI_BCNF_SUBBUS);
	parbus = pci_bus_res[secbus].par_bus;
	ASSERT(parbus == bus);
	cmd_reg = pci_getw(bus, dev, func, PCI_CONF_COMM);

	/*
	 * If we have a Cardbus bridge, but no bus space
	 */
	if (pci_bus_res[secbus].num_cbb != 0 &&
	    pci_bus_res[secbus].bus_avail == NULL) {
		uchar_t range;

		/* normally there are 2 buses under a cardbus bridge */
		range = pci_bus_res[secbus].num_cbb * 2;

		/*
		 * Try to find and allocate a bus-range starting at subbus+1
		 * from the parent of the PPB.
		 */
		for (; range != 0; range--) {
			if (memlist_find_with_startaddr(
			    &pci_bus_res[parbus].bus_avail,
			    subbus + 1, range, 1) != NULL)
				break; /* find bus range resource at parent */
		}
		if (range != 0) {
			memlist_insert(&pci_bus_res[secbus].bus_avail,
			    subbus + 1, range);
			subbus = subbus + range;
			pci_bus_res[secbus].sub_bus = subbus;
			pci_putb(bus, dev, func, PCI_BCNF_SUBBUS, subbus);
			add_bus_range_prop(secbus);

			cmn_err(CE_NOTE, "!reprogram bus-range on ppb"
			    "[%x/%x/%x]: %x ~ %x\n", bus, dev, func,
			    secbus, subbus);
		}
	}

	/*
	 * Calculate required IO size and alignment
	 * If bus io_size is zero, we are going to assign 512 bytes per bus,
	 * otherwise, we'll choose the maximum value of such calculation and
	 * bus io_size. The size needs to be 4K aligned.
	 *
	 * We calculate alignment as the largest power of two less than the
	 * the sum of all children's IO size requirements, because this will
	 * align to the size of the largest child request within that size
	 * (which is always a power of two).
	 */
	io_size = (subbus - secbus + 1) * 0x200;
	if (io_size <  pci_bus_res[secbus].io_size)
		io_size = pci_bus_res[secbus].io_size;
	io_size = P2ROUNDUP(io_size, PPB_IO_ALIGNMENT);
	io_align = io_size;
	P2LE(io_align);

	/*
	 * Calculate required MEM size and alignment
	 * If bus mem_size is zero, we are going to assign 1M bytes per bus,
	 * otherwise, we'll choose the maximum value of such calculation and
	 * bus mem_size. The size needs to be 1M aligned.
	 *
	 * For the alignment, refer to the I/O comment above.
	 */
	mem_size = (subbus - secbus + 1) * PPB_MEM_ALIGNMENT;
	if (mem_size < pci_bus_res[secbus].mem_size) {
		mem_size = pci_bus_res[secbus].mem_size;
		mem_size = P2ROUNDUP(mem_size, PPB_MEM_ALIGNMENT);
	}
	mem_align = mem_size;
	P2LE(mem_align);

	/* Subtractive bridge */
	if (pci_bus_res[secbus].subtractive && prog_sub) {
		/*
		 * We program an arbitrary amount of I/O and memory resource
		 * for the subtractive bridge so that child dynamic-resource-
		 * allocating devices (such as Cardbus bridges) have a chance
		 * of success.  Until we have full-tree resource rebalancing,
		 * dynamic resource allocation (thru busra) only looks at the
		 * parent bridge, so all PPBs must have some allocatable
		 * resource.  For non-subtractive bridges, the resources come
		 * from the base/limit register "windows", but subtractive
		 * bridges often don't program those (since they don't need to).
		 * If we put all the remaining resources on the subtractive
		 * bridge, then peer non-subtractive bridges can't allocate
		 * more space (even though this is probably most correct).
		 * If we put the resources only on the parent, then allocations
		 * from children of subtractive bridges will fail without
		 * special-case code for bypassing the subtractive bridge.
		 * This solution is the middle-ground temporary solution until
		 * we have fully-capable resource allocation.
		 */

		/*
		 * Add an arbitrary I/O resource to the subtractive PPB
		 */
		if (pci_bus_res[secbus].io_avail == NULL) {
			addr = get_parbus_io_res(parbus, secbus, io_size,
			    io_align);
			if (addr) {
				add_ranges_prop(secbus, 1);
				pci_bus_res[secbus].io_reprogram =
				    pci_bus_res[parbus].io_reprogram;

				cmn_err(CE_NOTE, "!add io-range on subtractive"
				    " ppb[%x/%x/%x]: 0x%x ~ 0x%x\n",
				    bus, dev, func, (uint32_t)addr,
				    (uint32_t)addr + io_size - 1);
			}
		}
		/*
		 * Add an arbitrary memory resource to the subtractive PPB
		 */
		if (pci_bus_res[secbus].mem_avail == NULL) {
			addr = get_parbus_mem_res(parbus, secbus, mem_size,
			    mem_align);
			if (addr) {
				add_ranges_prop(secbus, 1);
				pci_bus_res[secbus].mem_reprogram =
				    pci_bus_res[parbus].mem_reprogram;

				cmn_err(CE_NOTE, "!add mem-range on "
				    "subtractive ppb[%x/%x/%x]: 0x%x ~ 0x%x\n",
				    bus, dev, func, (uint32_t)addr,
				    (uint32_t)addr + mem_size - 1);
			}
		}

		goto cmd_enable;
	}

	/*
	 * Check to see if we need to reprogram I/O space, either because the
	 * parent bus needed reprogramming and so do we, or because I/O space is
	 * disabled in base/limit or command register.
	 */
	io_base = pci_getb(bus, dev, func, PCI_BCNF_IO_BASE_LOW);
	io_limit = pci_getb(bus, dev, func, PCI_BCNF_IO_LIMIT_LOW);
	io_base = (io_base & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT;
	io_limit = ((io_limit & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT) | 0xfff;
	if ((io_base & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
		uint16_t io_base_hi, io_limit_hi;
		io_base_hi = pci_getw(bus, dev, func, PCI_BCNF_IO_BASE_HI);
		io_limit_hi = pci_getw(bus, dev, func, PCI_BCNF_IO_LIMIT_HI);

		io_base |= (uint_t)io_base_hi << 16;
		io_limit |= (uint_t)io_limit_hi << 16;
	}

	/* Form list of all resources passed (avail + used) */
	scratch_list = memlist_dup(pci_bus_res[secbus].io_avail);
	memlist_merge(&pci_bus_res[secbus].io_used, &scratch_list);

	if ((pci_bus_res[parbus].io_reprogram ||
	    (io_base > io_limit) ||
	    (!(cmd_reg & PCI_COMM_IO))) &&
	    !list_is_vga_only(scratch_list, IO)) {
		if (pci_bus_res[secbus].io_used) {
			memlist_subsume(&pci_bus_res[secbus].io_used,
			    &pci_bus_res[secbus].io_avail);
		}
		if (pci_bus_res[secbus].io_avail &&
		    (!pci_bus_res[parbus].io_reprogram) &&
		    (!pci_bus_res[parbus].subtractive)) {
			/* rechoose old io ports info */
			list = pci_bus_res[secbus].io_avail;
			io_base = 0;
			do {
				if (is_vga(list, IO))
					continue;
				if (!io_base) {
					io_base = (uint_t)list->ml_address;
					io_limit = (uint_t)list->ml_address +
					    list->ml_size - 1;
					io_base =
					    P2ALIGN(io_base, PPB_IO_ALIGNMENT);
				} else {
					if (list->ml_address + list->ml_size >
					    io_limit) {
						io_limit = (uint_t)
						    (list->ml_address +
						    list->ml_size - 1);
					}
				}
			} while ((list = list->ml_next) != NULL);
			/* 4K aligned */
			io_limit = P2ROUNDUP(io_limit, PPB_IO_ALIGNMENT) - 1;
			io_size = io_limit - io_base + 1;
			ASSERT(io_base <= io_limit);
			memlist_free_all(&pci_bus_res[secbus].io_avail);
			memlist_insert(&pci_bus_res[secbus].io_avail,
			    io_base, io_size);
			memlist_insert(&pci_bus_res[parbus].io_used,
			    io_base, io_size);
			(void) memlist_remove(&pci_bus_res[parbus].io_avail,
			    io_base, io_size);
			pci_bus_res[secbus].io_reprogram = B_TRUE;
		} else {
			/* get new io ports from parent bus */
			addr = get_parbus_io_res(parbus, secbus, io_size,
			    io_align);
			if (addr) {
				io_base = addr;
				io_limit = addr + io_size - 1;
				pci_bus_res[secbus].io_reprogram = B_TRUE;
			}
		}
		if (pci_bus_res[secbus].io_reprogram) {
			/* reprogram PPB regs */
			pci_putb(bus, dev, func, PCI_BCNF_IO_BASE_LOW,
			    (uchar_t)((io_base>>8) & 0xf0));
			pci_putb(bus, dev, func, PCI_BCNF_IO_LIMIT_LOW,
			    (uchar_t)((io_limit>>8) & 0xf0));
			pci_putb(bus, dev, func, PCI_BCNF_IO_BASE_HI, 0);
			pci_putb(bus, dev, func, PCI_BCNF_IO_LIMIT_HI, 0);
			add_ranges_prop(secbus, 1);

			cmn_err(CE_NOTE, "!reprogram io-range on"
			    " ppb[%x/%x/%x]: 0x%x ~ 0x%x\n",
			    bus, dev, func, io_base, io_limit);
		}
	}
	memlist_free_all(&scratch_list);

	/*
	 * Check memory space as we did I/O space.
	 */
	mem_base = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_MEM_BASE);
	mem_base = (mem_base & 0xfff0) << 16;
	mem_limit = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_MEM_LIMIT);
	mem_limit = ((mem_limit & 0xfff0) << 16) | 0xfffff;

	scratch_list = memlist_dup(pci_bus_res[secbus].mem_avail);
	memlist_merge(&pci_bus_res[secbus].mem_used, &scratch_list);

	if ((pci_bus_res[parbus].mem_reprogram ||
	    (mem_base > mem_limit) ||
	    (!(cmd_reg & PCI_COMM_MAE))) &&
	    !list_is_vga_only(scratch_list, MEM)) {
		if (pci_bus_res[secbus].mem_used) {
			memlist_subsume(&pci_bus_res[secbus].mem_used,
			    &pci_bus_res[secbus].mem_avail);
		}
		if (pci_bus_res[secbus].mem_avail &&
		    (!pci_bus_res[parbus].mem_reprogram) &&
		    (!pci_bus_res[parbus].subtractive)) {
			/* rechoose old mem resource */
			list = pci_bus_res[secbus].mem_avail;
			mem_base = 0;
			do {
				if (is_vga(list, MEM))
					continue;
				if (mem_base == 0) {
					mem_base = (uint_t)list->ml_address;
					mem_base = P2ALIGN(mem_base,
					    PPB_MEM_ALIGNMENT);
					mem_limit = (uint_t)(list->ml_address +
					    list->ml_size - 1);
				} else {
					if ((list->ml_address + list->ml_size) >
					    mem_limit) {
						mem_limit = (uint_t)
						    (list->ml_address +
						    list->ml_size - 1);
					}
				}
			} while ((list = list->ml_next) != NULL);
			mem_limit = P2ROUNDUP(mem_limit, PPB_MEM_ALIGNMENT) - 1;
			mem_size = mem_limit + 1 - mem_base;
			ASSERT(mem_base <= mem_limit);
			memlist_free_all(&pci_bus_res[secbus].mem_avail);
			memlist_insert(&pci_bus_res[secbus].mem_avail,
			    mem_base, mem_size);
			memlist_insert(&pci_bus_res[parbus].mem_used,
			    mem_base, mem_size);
			(void) memlist_remove(&pci_bus_res[parbus].mem_avail,
			    mem_base, mem_size);
			pci_bus_res[secbus].mem_reprogram = B_TRUE;
		} else {
			/* get new mem resource from parent bus */
			addr = get_parbus_mem_res(parbus, secbus, mem_size,
			    mem_align);
			if (addr) {
				mem_base = addr;
				mem_limit = addr + mem_size - 1;
				pci_bus_res[secbus].mem_reprogram = B_TRUE;
			}
		}

		if (pci_bus_res[secbus].mem_reprogram) {
			/* reprogram PPB MEM regs */
			pci_putw(bus, dev, func, PCI_BCNF_MEM_BASE,
			    (uint16_t)((mem_base>>16) & 0xfff0));
			pci_putw(bus, dev, func, PCI_BCNF_MEM_LIMIT,
			    (uint16_t)((mem_limit>>16) & 0xfff0));
			/*
			 * Disable PMEM window by setting base > limit.
			 * We currently don't reprogram the PMEM like we've
			 * done for I/O and MEM. (Devices that support prefetch
			 * can use non-prefetch MEM.) Anyway, if the MEM access
			 * bit is initially disabled by BIOS, we disable the
			 * PMEM window manually by setting PMEM base > PMEM
			 * limit here, in case there are incorrect values in
			 * them from BIOS, so that we won't get in trouble once
			 * the MEM access bit is enabled at the end of this
			 * function.
			 */
			if (!(cmd_reg & PCI_COMM_MAE)) {
				pci_putw(bus, dev, func, PCI_BCNF_PF_BASE_LOW,
				    0xfff0);
				pci_putw(bus, dev, func, PCI_BCNF_PF_LIMIT_LOW,
				    0x0);
				pci_putl(bus, dev, func, PCI_BCNF_PF_BASE_HIGH,
				    0xffffffff);
				pci_putl(bus, dev, func, PCI_BCNF_PF_LIMIT_HIGH,
				    0x0);
			}

			add_ranges_prop(secbus, 1);

			cmn_err(CE_NOTE, "!reprogram mem-range on"
			    " ppb[%x/%x/%x]: 0x%x ~ 0x%x\n",
			    bus, dev, func, mem_base, mem_limit);
		}
	}
	memlist_free_all(&scratch_list);

cmd_enable:
	if (pci_bus_res[secbus].io_avail)
		cmd_reg |= PCI_COMM_IO | PCI_COMM_ME;
	if (pci_bus_res[secbus].mem_avail)
		cmd_reg |= PCI_COMM_MAE | PCI_COMM_ME;
	pci_putw(bus, dev, func, PCI_CONF_COMM, cmd_reg);
}

void
pci_reprogram(void)
{
	int i, pci_reconfig = 1;
	char *onoff;
	int bus;

	/*
	 * Scan ACPI namespace for _BBN objects, make sure that
	 * childless root-bridges appear in devinfo tree
	 */
	pci_scan_bbn();
	pci_unitaddr_cache_init();

	/*
	 * Fix-up unit-address assignments if cache is available
	 */
	if (pci_unitaddr_cache_valid()) {
		int pci_regs[] = {0, 0, 0};
		int	new_addr;
		int	index = 0;

		for (bus = 0; bus <= pci_bios_maxbus; bus++) {
			/* skip non-root (peer) PCI busses */
			if ((pci_bus_res[bus].par_bus != (uchar_t)-1) ||
			    (pci_bus_res[bus].dip == NULL))
				continue;

			new_addr = pci_bus_unitaddr(index);
			if (pci_bus_res[bus].root_addr != new_addr) {
				/* update reg property for node */
				pci_regs[0] = pci_bus_res[bus].root_addr =
				    new_addr;
				(void) ndi_prop_update_int_array(
				    DDI_DEV_T_NONE, pci_bus_res[bus].dip,
				    "reg", (int *)pci_regs, 3);
			}
			index++;
		}
	} else {
		/* perform legacy processing */
		pci_renumber_root_busses();
		pci_unitaddr_cache_create();
	}

	/*
	 * Do root-bus resource discovery
	 */
	for (bus = 0; bus <= pci_bios_maxbus; bus++) {
		/* skip non-root (peer) PCI busses */
		if (pci_bus_res[bus].par_bus != (uchar_t)-1)
			continue;

		/*
		 * 1. find resources associated with this root bus
		 */
		populate_bus_res(bus);


		/*
		 * 2. Remove used PCI and ISA resources from bus resource map
		 */

		memlist_remove_list(&pci_bus_res[bus].io_avail,
		    pci_bus_res[bus].io_used);
		memlist_remove_list(&pci_bus_res[bus].mem_avail,
		    pci_bus_res[bus].mem_used);
		memlist_remove_list(&pci_bus_res[bus].pmem_avail,
		    pci_bus_res[bus].pmem_used);
		memlist_remove_list(&pci_bus_res[bus].mem_avail,
		    pci_bus_res[bus].pmem_used);
		memlist_remove_list(&pci_bus_res[bus].pmem_avail,
		    pci_bus_res[bus].mem_used);

		memlist_remove_list(&pci_bus_res[bus].io_avail,
		    isa_res.io_used);
		memlist_remove_list(&pci_bus_res[bus].mem_avail,
		    isa_res.mem_used);

		/*
		 * 3. Exclude <1M address range here in case below reserved
		 * ranges for BIOS data area, ROM area etc are wrongly reported
		 * in ACPI resource producer entries for PCI root bus.
		 * 	00000000 - 000003FF	RAM
		 * 	00000400 - 000004FF	BIOS data area
		 * 	00000500 - 0009FFFF	RAM
		 * 	000A0000 - 000BFFFF	VGA RAM
		 * 	000C0000 - 000FFFFF	ROM area
		 */
		(void) memlist_remove(&pci_bus_res[bus].mem_avail, 0, 0x100000);
		(void) memlist_remove(&pci_bus_res[bus].pmem_avail,
		    0, 0x100000);
	}

	memlist_free_all(&isa_res.io_used);
	memlist_free_all(&isa_res.mem_used);

	/* add bus-range property for root/peer bus nodes */
	for (i = 0; i <= pci_bios_maxbus; i++) {
		/* create bus-range property on root/peer buses */
		if (pci_bus_res[i].par_bus == (uchar_t)-1)
			add_bus_range_prop(i);

		/* setup bus range resource on each bus */
		setup_bus_res(i);
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "pci-reprog", &onoff) == DDI_SUCCESS) {
		if (strcmp(onoff, "off") == 0) {
			pci_reconfig = 0;
			cmn_err(CE_NOTE, "pci device reprogramming disabled");
		}
		ddi_prop_free(onoff);
	}

	remove_subtractive_res();

	/* reprogram the non-subtractive PPB */
	if (pci_reconfig)
		for (i = 0; i <= pci_bios_maxbus; i++)
			fix_ppb_res(i, B_FALSE);

	for (i = 0; i <= pci_bios_maxbus; i++) {
		/* configure devices not configured by BIOS */
		if (pci_reconfig) {
			/*
			 * Reprogram the subtractive PPB. At this time, all its
			 * siblings should have got their resources already.
			 */
			if (pci_bus_res[i].subtractive)
				fix_ppb_res(i, B_TRUE);
			enumerate_bus_devs(i, CONFIG_NEW);
		}
	}

	/* All dev programmed, so we can create available prop */
	for (i = 0; i <= pci_bios_maxbus; i++)
		add_bus_available_prop(i);
}

/*
 * populate bus resources
 */
static void
populate_bus_res(uchar_t bus)
{

	/* scan BIOS structures */
	pci_bus_res[bus].pmem_avail = find_bus_res(bus, PREFETCH_TYPE);
	pci_bus_res[bus].mem_avail = find_bus_res(bus, MEM_TYPE);
	pci_bus_res[bus].io_avail = find_bus_res(bus, IO_TYPE);
	pci_bus_res[bus].bus_avail = find_bus_res(bus, BUSRANGE_TYPE);

	/*
	 * attempt to initialize sub_bus from the largest range-end
	 * in the bus_avail list
	 */
	if (pci_bus_res[bus].bus_avail != NULL) {
		struct memlist *entry;
		int current;

		entry = pci_bus_res[bus].bus_avail;
		while (entry != NULL) {
			current = entry->ml_address + entry->ml_size - 1;
			if (current > pci_bus_res[bus].sub_bus)
				pci_bus_res[bus].sub_bus = current;
			entry = entry->ml_next;
		}
	}

	if (bus == 0) {
		/*
		 * Special treatment of bus 0:
		 * If no IO/MEM resource from ACPI/MPSPEC/HRT, copy
		 * pcimem from boot and make I/O space the entire range
		 * starting at 0x100.
		 */
		if (pci_bus_res[0].mem_avail == NULL)
			pci_bus_res[0].mem_avail =
			    memlist_dup(bootops->boot_mem->pcimem);
		/* Exclude 0x00 to 0xff of the I/O space, used by all PCs */
		if (pci_bus_res[0].io_avail == NULL)
			memlist_insert(&pci_bus_res[0].io_avail, 0x100, 0xffff);
	}

	/*
	 * Create 'ranges' property here before any resources are
	 * removed from the resource lists
	 */
	add_ranges_prop(bus, 0);
}


/*
 * Create top-level bus dips, i.e. /pci@0,0, /pci@1,0...
 */
static void
create_root_bus_dip(uchar_t bus)
{
	int pci_regs[] = {0, 0, 0};
	dev_info_t *dip;

	ASSERT(pci_bus_res[bus].par_bus == (uchar_t)-1);

	num_root_bus++;
	ndi_devi_alloc_sleep(ddi_root_node(), "pci",
	    (pnode_t)DEVI_SID_NODEID, &dip);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2);
	pci_regs[0] = pci_bus_res[bus].root_addr;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", (int *)pci_regs, 3);

	/*
	 * If system has PCIe bus, then create different properties
	 */
	if (create_pcie_root_bus(bus, dip) == B_FALSE)
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "pci");

	(void) ndi_devi_bind_driver(dip, 0);
	pci_bus_res[bus].dip = dip;
}

/*
 * For any fixed configuration (often compatability) pci devices
 * and those with their own expansion rom, create device nodes
 * to hold the already configured device details.
 */
void
enumerate_bus_devs(uchar_t bus, int config_op)
{
	uchar_t dev, func, nfunc, header;
	ushort_t venid;
	struct pci_devfunc *devlist = NULL, *entry;

	if (config_op == CONFIG_NEW) {
		dcmn_err(CE_NOTE, "configuring pci bus 0x%x", bus);
	} else if (config_op == CONFIG_FIX) {
		dcmn_err(CE_NOTE, "fixing devices on pci bus 0x%x", bus);
	} else
		dcmn_err(CE_NOTE, "enumerating pci bus 0x%x", bus);

	if (config_op == CONFIG_NEW) {
		devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
		while (devlist) {
			entry = devlist;
			devlist = entry->next;
			if (entry->reprogram ||
			    pci_bus_res[bus].io_reprogram ||
			    pci_bus_res[bus].mem_reprogram) {
				/* reprogram device(s) */
				(void) add_reg_props(entry->dip, bus,
				    entry->dev, entry->func, CONFIG_NEW, 0);
			}
			kmem_free(entry, sizeof (*entry));
		}
		pci_bus_res[bus].privdata = NULL;
		return;
	}

	for (dev = 0; dev < max_dev_pci; dev++) {
		nfunc = 1;
		for (func = 0; func < nfunc; func++) {

			dcmn_err(CE_NOTE, "probing dev 0x%x, func 0x%x",
			    dev, func);

			venid = pci_getw(bus, dev, func, PCI_CONF_VENID);

			if ((venid == 0xffff) || (venid == 0)) {
				/* no function at this address */
				continue;
			}

			header = pci_getb(bus, dev, func, PCI_CONF_HEADER);
			if (header == 0xff) {
				continue; /* illegal value */
			}

			/*
			 * according to some mail from Microsoft posted
			 * to the pci-drivers alias, their only requirement
			 * for a multifunction device is for the 1st
			 * function to have to PCI_HEADER_MULTI bit set.
			 */
			if ((func == 0) && (header & PCI_HEADER_MULTI)) {
				nfunc = 8;
			}

			if (config_op == CONFIG_FIX ||
			    config_op == CONFIG_INFO) {
				/*
				 * Create the node, unconditionally, on the
				 * first pass only.  It may still need
				 * resource assignment, which will be
				 * done on the second, CONFIG_NEW, pass.
				 */
				process_devfunc(bus, dev, func, header,
				    venid, config_op);

			}
		}
	}

	/* percolate bus used resources up through parents to root */
	if (config_op == CONFIG_INFO) {
		int	par_bus;

		par_bus = pci_bus_res[bus].par_bus;
		while (par_bus != (uchar_t)-1) {
			pci_bus_res[par_bus].io_size +=
			    pci_bus_res[bus].io_size;
			pci_bus_res[par_bus].mem_size +=
			    pci_bus_res[bus].mem_size;

			if (pci_bus_res[bus].io_used)
				memlist_merge(&pci_bus_res[bus].io_used,
				    &pci_bus_res[par_bus].io_used);

			if (pci_bus_res[bus].mem_used)
				memlist_merge(&pci_bus_res[bus].mem_used,
				    &pci_bus_res[par_bus].mem_used);

			if (pci_bus_res[bus].pmem_used)
				memlist_merge(&pci_bus_res[bus].pmem_used,
				    &pci_bus_res[par_bus].pmem_used);

			bus = par_bus;
			par_bus = pci_bus_res[par_bus].par_bus;
		}
	}
}

static int
check_pciide_prop(uchar_t revid, ushort_t venid, ushort_t devid,
    ushort_t subvenid, ushort_t subdevid)
{
	static int prop_exist = -1;
	static char *pciide_str;
	char compat[32];

	if (prop_exist == -1) {
		prop_exist = (ddi_prop_lookup_string(DDI_DEV_T_ANY,
		    ddi_root_node(), DDI_PROP_DONTPASS, "pci-ide",
		    &pciide_str) == DDI_SUCCESS);
	}

	if (!prop_exist)
		return (0);

	/* compare property value against various forms of compatible */
	if (subvenid) {
		(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x.%x.%x",
		    venid, devid, subvenid, subdevid, revid);
		if (strcmp(pciide_str, compat) == 0)
			return (1);

		(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x.%x",
		    venid, devid, subvenid, subdevid);
		if (strcmp(pciide_str, compat) == 0)
			return (1);

		(void) snprintf(compat, sizeof (compat), "pci%x,%x",
		    subvenid, subdevid);
		if (strcmp(pciide_str, compat) == 0)
			return (1);
	}
	(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x",
	    venid, devid, revid);
	if (strcmp(pciide_str, compat) == 0)
		return (1);

	(void) snprintf(compat, sizeof (compat), "pci%x,%x", venid, devid);
	if (strcmp(pciide_str, compat) == 0)
		return (1);

	return (0);
}

static int
is_pciide(uchar_t basecl, uchar_t subcl, uchar_t revid,
    ushort_t venid, ushort_t devid, ushort_t subvenid, ushort_t subdevid)
{
	struct ide_table {	/* table for PCI_MASS_OTHER */
		ushort_t venid;
		ushort_t devid;
	} *entry;

	/* XXX SATA and other devices: need a way to add dynamically */
	static struct ide_table ide_other[] = {
		{0x1095, 0x3112},
		{0x1095, 0x3114},
		{0x1095, 0x3512},
		{0x1095, 0x680},	/* Sil0680 */
		{0x1283, 0x8211},	/* ITE 8211F is subcl PCI_MASS_OTHER */
		{0, 0}
	};

	if (basecl != PCI_CLASS_MASS)
		return (0);

	if (subcl == PCI_MASS_IDE) {
		return (1);
	}

	if (check_pciide_prop(revid, venid, devid, subvenid, subdevid))
		return (1);

	if (subcl != PCI_MASS_OTHER && subcl != PCI_MASS_SATA) {
		return (0);
	}

	entry = &ide_other[0];
	while (entry->venid) {
		if (entry->venid == venid && entry->devid == devid)
			return (1);
		entry++;
	}
	return (0);
}

static int
is_display(uint_t classcode)
{
	static uint_t disp_classes[] = {
		0x000100,
		0x030000,
		0x030001
	};
	int i, nclasses = sizeof (disp_classes) / sizeof (uint_t);

	for (i = 0; i < nclasses; i++) {
		if (classcode == disp_classes[i])
			return (1);
	}
	return (0);
}

static void
add_undofix_entry(uint8_t bus, uint8_t dev, uint8_t fn,
    void (*undofn)(uint8_t, uint8_t, uint8_t))
{
	struct pci_fixundo *newundo;

	newundo = kmem_alloc(sizeof (struct pci_fixundo), KM_SLEEP);

	/*
	 * Adding an item to this list means that we must turn its NMIENABLE
	 * bit back on at a later time.
	 */
	newundo->bus = bus;
	newundo->dev = dev;
	newundo->fn = fn;
	newundo->undofn = undofn;
	newundo->next = undolist;

	/* add to the undo list in LIFO order */
	undolist = newundo;
}

void
add_pci_fixes(void)
{
	int i;

	for (i = 0; i <= pci_bios_maxbus; i++) {
		/*
		 * For each bus, apply needed fixes to the appropriate devices.
		 * This must be done before the main enumeration loop because
		 * some fixes must be applied to devices normally encountered
		 * later in the pci scan (e.g. if a fix to device 7 must be
		 * applied before scanning device 6, applying fixes in the
		 * normal enumeration loop would obviously be too late).
		 */
		enumerate_bus_devs(i, CONFIG_FIX);
	}
}

void
undo_pci_fixes(void)
{
	struct pci_fixundo *nextundo;
	uint8_t bus, dev, fn;

	/*
	 * All fixes in the undo list are performed unconditionally.  Future
	 * fixes may require selective undo.
	 */
	while (undolist != NULL) {

		bus = undolist->bus;
		dev = undolist->dev;
		fn = undolist->fn;

		(*(undolist->undofn))(bus, dev, fn);

		nextundo = undolist->next;
		kmem_free(undolist, sizeof (struct pci_fixundo));
		undolist = nextundo;
	}
}

static void
undo_amd8111_pci_fix(uint8_t bus, uint8_t dev, uint8_t fn)
{
	uint8_t val8;

	val8 = pci_getb(bus, dev, fn, LPC_IO_CONTROL_REG_1);
	/*
	 * The NMIONERR bit is turned back on to allow the SMM BIOS
	 * to handle more critical PCI errors (e.g. PERR#).
	 */
	val8 |= AMD8111_ENABLENMI;
	pci_putb(bus, dev, fn, LPC_IO_CONTROL_REG_1, val8);
}

static void
pci_fix_amd8111(uint8_t bus, uint8_t dev, uint8_t fn)
{
	uint8_t val8;

	val8 = pci_getb(bus, dev, fn, LPC_IO_CONTROL_REG_1);

	if ((val8 & AMD8111_ENABLENMI) == 0)
		return;

	/*
	 * We reset NMIONERR in the LPC because master-abort on the PCI
	 * bridge side of the 8111 will cause NMI, which might cause SMI,
	 * which sometimes prevents all devices from being enumerated.
	 */
	val8 &= ~AMD8111_ENABLENMI;

	pci_putb(bus, dev, fn, LPC_IO_CONTROL_REG_1, val8);

	add_undofix_entry(bus, dev, fn, undo_amd8111_pci_fix);
}

static void
set_devpm_d0(uchar_t bus, uchar_t dev, uchar_t func)
{
	uint16_t status;
	uint8_t header;
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint16_t pmcsr;

	status = pci_getw(bus, dev, func, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP))
		return;	/* No capabilities list */

	header = pci_getb(bus, dev, func, PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;
	if (header == PCI_HEADER_CARDBUS)
		cap_ptr = pci_getb(bus, dev, func, PCI_CBUS_CAP_PTR);
	else
		cap_ptr = pci_getb(bus, dev, func, PCI_CONF_CAP_PTR);
	/*
	 * Walk the capabilities list searching for a PM entry.
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL && cap_ptr >= PCI_CAP_PTR_OFF) {
		cap_ptr &= PCI_CAP_PTR_MASK;
		cap_id = pci_getb(bus, dev, func, cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PM) {
			pmcsr = pci_getw(bus, dev, func, cap_ptr + PCI_PMCSR);
			pmcsr &= ~(PCI_PMCSR_STATE_MASK);
			pmcsr |= PCI_PMCSR_D0; /* D0 state */
			pci_putw(bus, dev, func, cap_ptr + PCI_PMCSR, pmcsr);
			break;
		}
		cap_ptr = pci_getb(bus, dev, func, cap_ptr + PCI_CAP_NEXT_PTR);
	}

}

#define	is_isa(bc, sc)	\
	(((bc) == PCI_CLASS_BRIDGE) && ((sc) == PCI_BRIDGE_ISA))

static void
process_devfunc(uchar_t bus, uchar_t dev, uchar_t func, uchar_t header,
    ushort_t vendorid, int config_op)
{
	char nodename[32], unitaddr[5];
	dev_info_t *dip;
	uchar_t basecl, subcl, progcl, intr, revid;
	ushort_t subvenid, subdevid, status;
	ushort_t slot_num;
	uint_t classcode, revclass;
	int reprogram = 0, pciide = 0;
	int power[2] = {1, 1};
	int pciex = 0;
	ushort_t is_pci_bridge = 0;
	struct pci_devfunc *devlist = NULL, *entry = NULL;
	boolean_t slot_valid;
	gfx_entry_t *gfxp;
	pcie_req_id_t bdf;

	ushort_t deviceid = pci_getw(bus, dev, func, PCI_CONF_DEVID);

	switch (header & PCI_HEADER_TYPE_M) {
	case PCI_HEADER_ZERO:
		subvenid = pci_getw(bus, dev, func, PCI_CONF_SUBVENID);
		subdevid = pci_getw(bus, dev, func, PCI_CONF_SUBSYSID);
		break;
	case PCI_HEADER_CARDBUS:
		subvenid = pci_getw(bus, dev, func, PCI_CBUS_SUBVENID);
		subdevid = pci_getw(bus, dev, func, PCI_CBUS_SUBSYSID);
		/* Record the # of cardbus bridges found on the bus */
		if (config_op == CONFIG_INFO)
			pci_bus_res[bus].num_cbb++;
		break;
	default:
		subvenid = 0;
		subdevid = 0;
		break;
	}

	if (config_op == CONFIG_FIX) {
		if (vendorid == VENID_AMD && deviceid == DEVID_AMD8111_LPC) {
			pci_fix_amd8111(bus, dev, func);
		}
		return;
	}

	/* XXX should be use generic names? derive from class? */
	revclass = pci_getl(bus, dev, func, PCI_CONF_REVID);
	classcode = revclass >> 8;
	revid = revclass & 0xff;

	/* figure out if this is pci-ide */
	basecl = classcode >> 16;
	subcl = (classcode >> 8) & 0xff;
	progcl = classcode & 0xff;


	if (is_display(classcode))
		(void) snprintf(nodename, sizeof (nodename), "display");
	else if (!pseudo_isa && is_isa(basecl, subcl))
		(void) snprintf(nodename, sizeof (nodename), "isa");
	else if (subvenid != 0)
		(void) snprintf(nodename, sizeof (nodename),
		    "pci%x,%x", subvenid, subdevid);
	else
		(void) snprintf(nodename, sizeof (nodename),
		    "pci%x,%x", vendorid, deviceid);

	/* make sure parent bus dip has been created */
	if (pci_bus_res[bus].dip == NULL)
		create_root_bus_dip(bus);

	ndi_devi_alloc_sleep(pci_bus_res[bus].dip, nodename,
	    DEVI_SID_NODEID, &dip);

	if (check_if_device_is_pciex(dip, bus, dev, func, &slot_valid,
	    &slot_num, &is_pci_bridge) == B_TRUE)
		pciex = 1;

	bdf = PCI_GETBDF(bus, dev, func);
	/*
	 * Record BAD AMD bridges which don't support MMIO config access.
	 */
	if (IS_BAD_AMD_NTBRIDGE(vendorid, deviceid) ||
	    IS_AMD_8132_CHIP(vendorid, deviceid)) {
		uchar_t secbus = 0;
		uchar_t subbus = 0;

		if ((basecl == PCI_CLASS_BRIDGE) &&
		    (subcl == PCI_BRIDGE_PCI)) {
			secbus = pci_getb(bus, dev, func, PCI_BCNF_SECBUS);
			subbus = pci_getb(bus, dev, func, PCI_BCNF_SUBBUS);
		}
		pci_cfgacc_add_workaround(bdf, secbus, subbus);
	}

	/*
	 * Only populate bus_t if this device is sitting under a PCIE root
	 * complex.  Some particular machines have both a PCIE root complex and
	 * a PCI hostbridge, in which case only devices under the PCIE root
	 * complex will have their bus_t populated.
	 */
	if (pcie_get_rc_dip(dip) != NULL) {
		ck804_fix_aer_ptr(dip, bdf);
		(void) pcie_init_bus(dip, bdf, PCIE_BUS_INITIAL);
	}

	/* add properties */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "device-id", deviceid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "vendor-id", vendorid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "revision-id", revid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "class-code", classcode);
	if (func == 0)
		(void) snprintf(unitaddr, sizeof (unitaddr), "%x", dev);
	else
		(void) snprintf(unitaddr, sizeof (unitaddr),
		    "%x,%x", dev, func);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "unit-address", unitaddr);

	/* add device_type for display nodes */
	if (is_display(classcode)) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "display");
	}
	/* add special stuff for header type */
	if ((header & PCI_HEADER_TYPE_M) == PCI_HEADER_ZERO) {
		uchar_t mingrant = pci_getb(bus, dev, func, PCI_CONF_MIN_G);
		uchar_t maxlatency = pci_getb(bus, dev, func, PCI_CONF_MAX_L);

		if (subvenid != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "subsystem-id", subdevid);
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "subsystem-vendor-id", subvenid);
		}
		if (!pciex)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "min-grant", mingrant);
		if (!pciex)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "max-latency", maxlatency);
	}

	/* interrupt, record if not 0 */
	intr = pci_getb(bus, dev, func, PCI_CONF_IPIN);
	if (intr != 0)
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "interrupts", intr);

	/*
	 * Add support for 133 mhz pci eventually
	 */
	status = pci_getw(bus, dev, func, PCI_CONF_STAT);

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "devsel-speed", (status & PCI_STAT_DEVSELT) >> 9);
	if (!pciex && (status & PCI_STAT_FBBC))
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "fast-back-to-back");
	if (!pciex && (status & PCI_STAT_66MHZ))
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "66mhz-capable");
	if (status & PCI_STAT_UDF)
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "udf-supported");
	if (pciex && slot_valid) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "physical-slot#", slot_num);
		if (!is_pci_bridge)
			pciex_slot_names_prop(dip, slot_num);
	}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "power-consumption", power, 2);

	/* Set the device PM state to D0 */
	set_devpm_d0(bus, dev, func);

	if ((basecl == PCI_CLASS_BRIDGE) && (subcl == PCI_BRIDGE_PCI))
		add_ppb_props(dip, bus, dev, func, pciex, is_pci_bridge);
	else {
		/*
		 * Record the non-PPB devices on the bus for possible
		 * reprogramming at 2nd bus enumeration.
		 * Note: PPB reprogramming is done in fix_ppb_res()
		 */
		devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
		entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
		entry->dip = dip;
		entry->dev = dev;
		entry->func = func;
		entry->next = devlist;
		pci_bus_res[bus].privdata = entry;
	}

	if (IS_CLASS_IOAPIC(basecl, subcl, progcl)) {
		create_ioapic_node(bus, dev, func, vendorid, deviceid);
	}

	/* check for NVIDIA CK8-04/MCP55 based LPC bridge */
	if (NVIDIA_IS_LPC_BRIDGE(vendorid, deviceid) && (dev == 1) &&
	    (func == 0)) {
		add_nvidia_isa_bridge_props(dip, bus, dev, func);
		/* each LPC bridge has an integrated IOAPIC */
		apic_nvidia_io_max++;
	}

	if (pciex && is_pci_bridge)
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
		    (char *)"PCIe-PCI bridge");
	else
		add_model_prop(dip, classcode);

	add_compatible(dip, subvenid, subdevid, vendorid, deviceid,
	    revid, classcode, pciex);

	/*
	 * See if this device is a controller that advertises
	 * itself to be a standard ATA task file controller, or one that
	 * has been hard coded.
	 *
	 * If it is, check if any other higher precedence driver listed in
	 * driver_aliases will claim the node by calling
	 * ddi_compatibile_driver_major.  If so, clear pciide and do not
	 * create a pci-ide node or any other special handling.
	 *
	 * If another driver does not bind, set the node name to pci-ide
	 * and then let the special pci-ide handling for registers and
	 * child pci-ide nodes proceed below.
	 */
	if (is_pciide(basecl, subcl, revid, vendorid, deviceid,
	    subvenid, subdevid) == 1) {
		if (ddi_compatible_driver_major(dip, NULL) == (major_t)-1) {
			(void) ndi_devi_set_nodename(dip, "pci-ide", 0);
			pciide = 1;
		}
	}

	DEVI_SET_PCI(dip);
	reprogram = add_reg_props(dip, bus, dev, func, config_op, pciide);
	(void) ndi_devi_bind_driver(dip, 0);

	/* special handling for pci-ide */
	if (pciide) {
		dev_info_t *cdip;

		/*
		 * Create properties specified by P1275 Working Group
		 * Proposal #414 Version 1
		 */
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "pci-ide");
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#address-cells", 1);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#size-cells", 0);

		/* allocate two child nodes */
		ndi_devi_alloc_sleep(dip, "ide",
		    (pnode_t)DEVI_SID_NODEID, &cdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "reg", 0);
		(void) ndi_devi_bind_driver(cdip, 0);
		ndi_devi_alloc_sleep(dip, "ide",
		    (pnode_t)DEVI_SID_NODEID, &cdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "reg", 1);
		(void) ndi_devi_bind_driver(cdip, 0);

		reprogram = 0;	/* don't reprogram pci-ide bridge */
	}

	if (is_display(classcode)) {
		gfxp = kmem_zalloc(sizeof (*gfxp), KM_SLEEP);
		gfxp->g_dip = dip;
		gfxp->g_prev = NULL;
		gfxp->g_next = gfx_devinfo_list;
		gfx_devinfo_list = gfxp;
		if (gfxp->g_next)
			gfxp->g_next->g_prev = gfxp;
	}

	/* special handling for isa */
	if (!pseudo_isa && is_isa(basecl, subcl)) {
		/* add device_type */
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "isa");
	}

	if (reprogram && (entry != NULL))
		entry->reprogram = B_TRUE;

}

/*
 * Some vendors do not use unique subsystem IDs in their products, which
 * makes the use of form 2 compatible names (pciSSSS,ssss) inappropriate.
 * Allow for these compatible forms to be excluded on a per-device basis.
 */
/*ARGSUSED*/
static boolean_t
subsys_compat_exclude(ushort_t venid, ushort_t devid, ushort_t subvenid,
    ushort_t subdevid, uchar_t revid, uint_t classcode)
{
	/* Nvidia display adapters */
	if ((venid == 0x10de) && (is_display(classcode)))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Set the compatible property to a value compliant with
 * rev 2.1 of the IEEE1275 PCI binding.
 * (Also used for PCI-Express devices).
 *
 *   pciVVVV,DDDD.SSSS.ssss.RR	(0)
 *   pciVVVV,DDDD.SSSS.ssss	(1)
 *   pciSSSS,ssss		(2)
 *   pciVVVV,DDDD.RR		(3)
 *   pciVVVV,DDDD		(4)
 *   pciclass,CCSSPP		(5)
 *   pciclass,CCSS		(6)
 *
 * The Subsystem (SSSS) forms are not inserted if
 * subsystem-vendor-id is 0.
 *
 * NOTE: For PCI-Express devices "pci" is replaced with "pciex" in 0-6 above
 * property 2 is not created as per "1275 bindings for PCI Express Interconnect"
 *
 * Set with setprop and \x00 between each
 * to generate the encoded string array form.
 */
void
add_compatible(dev_info_t *dip, ushort_t subvenid, ushort_t subdevid,
    ushort_t vendorid, ushort_t deviceid, uchar_t revid, uint_t classcode,
    int pciex)
{
	int i = 0;
	int size = COMPAT_BUFSIZE;
	char *compat[13];
	char *buf, *curr;

	curr = buf = kmem_alloc(size, KM_SLEEP);

	if (pciex) {
		if (subvenid) {
			compat[i++] = curr;	/* form 0 */
			(void) snprintf(curr, size, "pciex%x,%x.%x.%x.%x",
			    vendorid, deviceid, subvenid, subdevid, revid);
			size -= strlen(curr) + 1;
			curr += strlen(curr) + 1;

			compat[i++] = curr;	/* form 1 */
			(void) snprintf(curr, size, "pciex%x,%x.%x.%x",
			    vendorid, deviceid, subvenid, subdevid);
			size -= strlen(curr) + 1;
			curr += strlen(curr) + 1;

		}
		compat[i++] = curr;	/* form 3 */
		(void) snprintf(curr, size, "pciex%x,%x.%x",
		    vendorid, deviceid, revid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		compat[i++] = curr;	/* form 4 */
		(void) snprintf(curr, size, "pciex%x,%x", vendorid, deviceid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		compat[i++] = curr;	/* form 5 */
		(void) snprintf(curr, size, "pciexclass,%06x", classcode);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		compat[i++] = curr;	/* form 6 */
		(void) snprintf(curr, size, "pciexclass,%04x",
		    (classcode >> 8));
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;
	}

	if (subvenid) {
		compat[i++] = curr;	/* form 0 */
		(void) snprintf(curr, size, "pci%x,%x.%x.%x.%x",
		    vendorid, deviceid, subvenid, subdevid, revid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		compat[i++] = curr;	/* form 1 */
		(void) snprintf(curr, size, "pci%x,%x.%x.%x",
		    vendorid, deviceid, subvenid, subdevid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		if (subsys_compat_exclude(vendorid, deviceid, subvenid,
		    subdevid, revid, classcode) == B_FALSE) {
			compat[i++] = curr;	/* form 2 */
			(void) snprintf(curr, size, "pci%x,%x", subvenid,
			    subdevid);
			size -= strlen(curr) + 1;
			curr += strlen(curr) + 1;
		}
	}
	compat[i++] = curr;	/* form 3 */
	(void) snprintf(curr, size, "pci%x,%x.%x", vendorid, deviceid, revid);
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	compat[i++] = curr;	/* form 4 */
	(void) snprintf(curr, size, "pci%x,%x", vendorid, deviceid);
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	compat[i++] = curr;	/* form 5 */
	(void) snprintf(curr, size, "pciclass,%06x", classcode);
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	compat[i++] = curr;	/* form 6 */
	(void) snprintf(curr, size, "pciclass,%04x", (classcode >> 8));
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "compatible", compat, i);
	kmem_free(buf, COMPAT_BUFSIZE);
}

/*
 * Adjust the reg properties for a dual channel PCI-IDE device.
 *
 * NOTE: don't do anything that changes the order of the hard-decodes
 * and programmed BARs. The kernel driver depends on these values
 * being in this order regardless of whether they're for a 'native'
 * mode BAR or not.
 */
/*
 * config info for pci-ide devices
 */
static struct {
	uchar_t  native_mask;	/* 0 == 'compatibility' mode, 1 == native */
	uchar_t  bar_offset;	/* offset for alt status register */
	ushort_t addr;		/* compatibility mode base address */
	ushort_t length;	/* number of ports for this BAR */
} pciide_bar[] = {
	{ 0x01, 0, 0x1f0, 8 },	/* primary lower BAR */
	{ 0x01, 2, 0x3f6, 1 },	/* primary upper BAR */
	{ 0x04, 0, 0x170, 8 },	/* secondary lower BAR */
	{ 0x04, 2, 0x376, 1 }	/* secondary upper BAR */
};

static int
pciIdeAdjustBAR(uchar_t progcl, int index, uint_t *basep, uint_t *lenp)
{
	int hard_decode = 0;

	/*
	 * Adjust the base and len for the BARs of the PCI-IDE
	 * device's primary and secondary controllers. The first
	 * two BARs are for the primary controller and the next
	 * two BARs are for the secondary controller. The fifth
	 * and sixth bars are never adjusted.
	 */
	if (index >= 0 && index <= 3) {
		*lenp = pciide_bar[index].length;

		if (progcl & pciide_bar[index].native_mask) {
			*basep += pciide_bar[index].bar_offset;
		} else {
			*basep = pciide_bar[index].addr;
			hard_decode = 1;
		}
	}

	/*
	 * if either base or len is zero make certain both are zero
	 */
	if (*basep == 0 || *lenp == 0) {
		*basep = 0;
		*lenp = 0;
		hard_decode = 0;
	}

	return (hard_decode);
}


/*
 * Add the "reg" and "assigned-addresses" property
 */
static int
add_reg_props(dev_info_t *dip, uchar_t bus, uchar_t dev, uchar_t func,
    int config_op, int pciide)
{
	uchar_t baseclass, subclass, progclass, header;
	ushort_t bar_sz;
	uint_t value = 0, len, devloc;
	uint_t base, base_hi, type;
	ushort_t offset, end;
	int max_basereg, j, reprogram = 0;
	uint_t phys_hi;
	struct memlist **io_avail, **io_used;
	struct memlist **mem_avail, **mem_used;
	struct memlist **pmem_avail, **pmem_used;
	uchar_t res_bus;

	pci_regspec_t regs[16] = {{0}};
	pci_regspec_t assigned[15] = {{0}};
	int nreg, nasgn;

	io_avail = &pci_bus_res[bus].io_avail;
	io_used = &pci_bus_res[bus].io_used;
	mem_avail = &pci_bus_res[bus].mem_avail;
	mem_used = &pci_bus_res[bus].mem_used;
	pmem_avail = &pci_bus_res[bus].pmem_avail;
	pmem_used = &pci_bus_res[bus].pmem_used;

	devloc = (uint_t)bus << 16 | (uint_t)dev << 11 | (uint_t)func << 8;
	regs[0].pci_phys_hi = devloc;
	nreg = 1;	/* rest of regs[0] is all zero */
	nasgn = 0;

	baseclass = pci_getb(bus, dev, func, PCI_CONF_BASCLASS);
	subclass = pci_getb(bus, dev, func, PCI_CONF_SUBCLASS);
	progclass = pci_getb(bus, dev, func, PCI_CONF_PROGCLASS);
	header = pci_getb(bus, dev, func, PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;

	switch (header) {
	case PCI_HEADER_ZERO:
		max_basereg = PCI_BASE_NUM;
		break;
	case PCI_HEADER_PPB:
		max_basereg = PCI_BCNF_BASE_NUM;
		break;
	case PCI_HEADER_CARDBUS:
		max_basereg = PCI_CBUS_BASE_NUM;
		reprogram = 1;
		break;
	default:
		max_basereg = 0;
		break;
	}

	/*
	 * Create the register property by saving the current
	 * value of the base register. Write 0xffffffff to the
	 * base register.  Read the value back to determine the
	 * required size of the address space.  Restore the base
	 * register contents.
	 *
	 * Do not disable I/O and memory access for bridges; this
	 * has the side-effect of making the bridge transparent to
	 * secondary-bus activity (see sections 4.1-4.3 of the
	 * PCI-PCI Bridge Spec V1.2).  For non-bridges, disable
	 * I/O and memory access to avoid difficulty with USB
	 * emulation (see OHCI spec1.0a appendix B
	 * "Host Controller Mapping")
	 */
	end = PCI_CONF_BASE0 + max_basereg * sizeof (uint_t);
	for (j = 0, offset = PCI_CONF_BASE0; offset < end;
	    j++, offset += bar_sz) {
		uint_t	command;

		/* determine the size of the address space */
		base = pci_getl(bus, dev, func, offset);
		if (baseclass != PCI_CLASS_BRIDGE) {
			command = (uint_t)pci_getw(bus, dev, func,
			    PCI_CONF_COMM);
			pci_putw(bus, dev, func, PCI_CONF_COMM,
			    command & ~(PCI_COMM_MAE | PCI_COMM_IO));
		}
		pci_putl(bus, dev, func, offset, 0xffffffff);
		value = pci_getl(bus, dev, func, offset);
		pci_putl(bus, dev, func, offset, base);
		if (baseclass != PCI_CLASS_BRIDGE)
			pci_putw(bus, dev, func, PCI_CONF_COMM, command);

		/* construct phys hi,med.lo, size hi, lo */
		if ((pciide && j < 4) || (base & PCI_BASE_SPACE_IO)) {
			int hard_decode = 0;

			/* i/o space */
			bar_sz = PCI_BAR_SZ_32;
			value &= PCI_BASE_IO_ADDR_M;
			len = ((value ^ (value-1)) + 1) >> 1;

			/* XXX Adjust first 4 IDE registers */
			if (pciide) {
				if (subclass != PCI_MASS_IDE)
					progclass = (PCI_IDE_IF_NATIVE_PRI |
					    PCI_IDE_IF_NATIVE_SEC);
				hard_decode = pciIdeAdjustBAR(progclass, j,
				    &base, &len);
			} else if (value == 0) {
				/* skip base regs with size of 0 */
				continue;
			}

			regs[nreg].pci_phys_hi = PCI_ADDR_IO | devloc |
			    (hard_decode ? PCI_RELOCAT_B : offset);
			regs[nreg].pci_phys_low = hard_decode ?
			    base & PCI_BASE_IO_ADDR_M : 0;
			assigned[nasgn].pci_phys_hi =
			    PCI_RELOCAT_B | regs[nreg].pci_phys_hi;
			regs[nreg].pci_size_low =
			    assigned[nasgn].pci_size_low = len;
			type = base & (~PCI_BASE_IO_ADDR_M);
			base &= PCI_BASE_IO_ADDR_M;
			/*
			 * A device under a subtractive PPB can allocate
			 * resources from its parent bus if there is no resource
			 * available on its own bus.
			 */
			if ((config_op == CONFIG_NEW) && (*io_avail == NULL)) {
				res_bus = bus;
				while (pci_bus_res[res_bus].subtractive) {
					res_bus = pci_bus_res[res_bus].par_bus;
					if (res_bus == (uchar_t)-1)
						break; /* root bus already */
					if (pci_bus_res[res_bus].io_avail) {
						io_avail = &pci_bus_res
						    [res_bus].io_avail;
						break;
					}
				}
			}

			/*
			 * first pass - gather what's there
			 * update/second pass - adjust/allocate regions
			 *	config - allocate regions
			 */
			if (config_op == CONFIG_INFO) {	/* first pass */
				/* take out of the resource map of the bus */
				if (base != 0) {
					(void) memlist_remove(io_avail, base,
					    len);
					memlist_insert(io_used, base, len);
				} else {
					reprogram = 1;
				}
				pci_bus_res[bus].io_size += len;
			} else if ((*io_avail && base == 0) ||
			    pci_bus_res[bus].io_reprogram) {
				base = (uint_t)memlist_find(io_avail, len, len);
				if (base != 0) {
					memlist_insert(io_used, base, len);
					/* XXX need to worry about 64-bit? */
					pci_putl(bus, dev, func, offset,
					    base | type);
					base = pci_getl(bus, dev, func, offset);
					base &= PCI_BASE_IO_ADDR_M;
				}
				if (base == 0) {
					cmn_err(CE_WARN, "failed to program"
					    " IO space [%d/%d/%d] BAR@0x%x"
					    " length 0x%x",
					    bus, dev, func, offset, len);
				}
			}
			assigned[nasgn].pci_phys_low = base;
			nreg++, nasgn++;

		} else {
			/* memory space */
			if ((base & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL) {
				bar_sz = PCI_BAR_SZ_64;
				base_hi = pci_getl(bus, dev, func, offset + 4);
				phys_hi = PCI_ADDR_MEM64;
			} else {
				bar_sz = PCI_BAR_SZ_32;
				base_hi = 0;
				phys_hi = PCI_ADDR_MEM32;
			}

			/* skip base regs with size of 0 */
			value &= PCI_BASE_M_ADDR_M;

			if (value == 0)
				continue;

			len = ((value ^ (value-1)) + 1) >> 1;
			regs[nreg].pci_size_low =
			    assigned[nasgn].pci_size_low = len;

			phys_hi |= (devloc | offset);
			if (base & PCI_BASE_PREF_M)
				phys_hi |= PCI_PREFETCH_B;

			/*
			 * A device under a subtractive PPB can allocate
			 * resources from its parent bus if there is no resource
			 * available on its own bus.
			 */
			if ((config_op == CONFIG_NEW) && (*mem_avail == NULL)) {
				res_bus = bus;
				while (pci_bus_res[res_bus].subtractive) {
					res_bus = pci_bus_res[res_bus].par_bus;
					if (res_bus == (uchar_t)-1)
						break; /* root bus already */
					mem_avail =
					    &pci_bus_res[res_bus].mem_avail;
					pmem_avail =
					    &pci_bus_res [res_bus].pmem_avail;
					/*
					 * Break out as long as at least
					 * mem_avail is available
					 */
					if ((*pmem_avail &&
					    (phys_hi & PCI_PREFETCH_B)) ||
					    *mem_avail)
						break;
				}
			}

			regs[nreg].pci_phys_hi =
			    assigned[nasgn].pci_phys_hi = phys_hi;
			assigned[nasgn].pci_phys_hi |= PCI_RELOCAT_B;
			assigned[nasgn].pci_phys_mid = base_hi;
			type = base & ~PCI_BASE_M_ADDR_M;
			base &= PCI_BASE_M_ADDR_M;

			if (config_op == CONFIG_INFO) {
				/* take out of the resource map of the bus */
				if (base != NULL) {
					/* remove from PMEM and MEM space */
					(void) memlist_remove(mem_avail,
					    base, len);
					(void) memlist_remove(pmem_avail,
					    base, len);
					/* only note as used in correct map */
					if (phys_hi & PCI_PREFETCH_B)
						memlist_insert(pmem_used,
						    base, len);
					else
						memlist_insert(mem_used,
						    base, len);
				} else {
					reprogram = 1;
				}
				pci_bus_res[bus].mem_size += len;
			} else if ((*mem_avail && base == NULL) ||
			    pci_bus_res[bus].mem_reprogram) {
				/*
				 * When desired, attempt a prefetchable
				 * allocation first
				 */
				if (phys_hi & PCI_PREFETCH_B) {
					base = (uint_t)memlist_find(pmem_avail,
					    len, len);
					if (base != NULL) {
						memlist_insert(pmem_used,
						    base, len);
						(void) memlist_remove(mem_avail,
						    base, len);
					}
				}
				/*
				 * If prefetchable allocation was not
				 * desired, or failed, attempt ordinary
				 * memory allocation
				 */
				if (base == NULL) {
					base = (uint_t)memlist_find(mem_avail,
					    len, len);
					if (base != NULL) {
						memlist_insert(mem_used,
						    base, len);
						(void) memlist_remove(
						    pmem_avail, base, len);
					}
				}
				if (base != NULL) {
					pci_putl(bus, dev, func, offset,
					    base | type);
					base = pci_getl(bus, dev, func, offset);
					base &= PCI_BASE_M_ADDR_M;
				} else
					cmn_err(CE_WARN, "failed to program "
					    "mem space [%d/%d/%d] BAR@0x%x"
					    " length 0x%x",
					    bus, dev, func, offset, len);
			}
			assigned[nasgn].pci_phys_low = base;
			nreg++, nasgn++;
		}
	}
	switch (header) {
	case PCI_HEADER_ZERO:
		offset = PCI_CONF_ROM;
		break;
	case PCI_HEADER_PPB:
		offset = PCI_BCNF_ROM;
		break;
	default: /* including PCI_HEADER_CARDBUS */
		goto done;
	}

	/*
	 * Add the expansion rom memory space
	 * Determine the size of the ROM base reg; don't write reserved bits
	 * ROM isn't in the PCI memory space.
	 */
	base = pci_getl(bus, dev, func, offset);
	pci_putl(bus, dev, func, offset, PCI_BASE_ROM_ADDR_M);
	value = pci_getl(bus, dev, func, offset);
	pci_putl(bus, dev, func, offset, base);
	if (value & PCI_BASE_ROM_ENABLE)
		value &= PCI_BASE_ROM_ADDR_M;
	else
		value = 0;

	if (value != 0) {
		regs[nreg].pci_phys_hi = (PCI_ADDR_MEM32 | devloc) + offset;
		assigned[nasgn].pci_phys_hi = (PCI_RELOCAT_B |
		    PCI_ADDR_MEM32 | devloc) + offset;
		base &= PCI_BASE_ROM_ADDR_M;
		assigned[nasgn].pci_phys_low = base;
		len = ((value ^ (value-1)) + 1) >> 1;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = len;
		nreg++, nasgn++;
		/* take it out of the memory resource */
		if (base != NULL) {
			(void) memlist_remove(mem_avail, base, len);
			memlist_insert(mem_used, base, len);
			pci_bus_res[bus].mem_size += len;
		}
	}

	/*
	 * Account for "legacy" (alias) video adapter resources
	 */

	/* add the three hard-decode, aliased address spaces for VGA */
	if ((baseclass == PCI_CLASS_DISPLAY && subclass == PCI_DISPLAY_VGA) ||
	    (baseclass == PCI_CLASS_NONE && subclass == PCI_NONE_VGA)) {

		/* VGA hard decode 0x3b0-0x3bb */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x3b0;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0xc;
		nreg++, nasgn++;
		(void) memlist_remove(io_avail, 0x3b0, 0xc);
		memlist_insert(io_used, 0x3b0, 0xc);
		pci_bus_res[bus].io_size += 0xc;

		/* VGA hard decode 0x3c0-0x3df */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x3c0;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x20;
		nreg++, nasgn++;
		(void) memlist_remove(io_avail, 0x3c0, 0x20);
		memlist_insert(io_used, 0x3c0, 0x20);
		pci_bus_res[bus].io_size += 0x20;

		/* Video memory */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_MEM32 | devloc);
		regs[nreg].pci_phys_low =
		    assigned[nasgn].pci_phys_low = 0xa0000;
		regs[nreg].pci_size_low =
		    assigned[nasgn].pci_size_low = 0x20000;
		nreg++, nasgn++;
		/* remove from MEM and PMEM space */
		(void) memlist_remove(mem_avail, 0xa0000, 0x20000);
		(void) memlist_remove(pmem_avail, 0xa0000, 0x20000);
		memlist_insert(mem_used, 0xa0000, 0x20000);
		pci_bus_res[bus].mem_size += 0x20000;
	}

	/* add the hard-decode, aliased address spaces for 8514 */
	if ((baseclass == PCI_CLASS_DISPLAY) &&
	    (subclass == PCI_DISPLAY_VGA) &&
	    (progclass & PCI_DISPLAY_IF_8514)) {

		/* hard decode 0x2e8 */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x2e8;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x1;
		nreg++, nasgn++;
		(void) memlist_remove(io_avail, 0x2e8, 0x1);
		memlist_insert(io_used, 0x2e8, 0x1);
		pci_bus_res[bus].io_size += 0x1;

		/* hard decode 0x2ea-0x2ef */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x2ea;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x6;
		nreg++, nasgn++;
		(void) memlist_remove(io_avail, 0x2ea, 0x6);
		memlist_insert(io_used, 0x2ea, 0x6);
		pci_bus_res[bus].io_size += 0x6;
	}

done:
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "reg",
	    (int *)regs, nreg * sizeof (pci_regspec_t) / sizeof (int));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses",
	    (int *)assigned, nasgn * sizeof (pci_regspec_t) / sizeof (int));

	return (reprogram);
}

static void
add_ppb_props(dev_info_t *dip, uchar_t bus, uchar_t dev, uchar_t func,
    int pciex, ushort_t is_pci_bridge)
{
	char *dev_type;
	int i;
	uint_t val;
	uint64_t io_range[2], mem_range[2], pmem_range[2];
	uchar_t secbus = pci_getb(bus, dev, func, PCI_BCNF_SECBUS);
	uchar_t subbus = pci_getb(bus, dev, func, PCI_BCNF_SUBBUS);
	uchar_t progclass;

	ASSERT(secbus <= subbus);

	/*
	 * Check if it's a subtractive PPB.
	 */
	progclass = pci_getb(bus, dev, func, PCI_CONF_PROGCLASS);
	if (progclass == PCI_BRIDGE_PCI_IF_SUBDECODE)
		pci_bus_res[secbus].subtractive = B_TRUE;

	/*
	 * Some BIOSes lie about max pci busses, we allow for
	 * such mistakes here
	 */
	if (subbus > pci_bios_maxbus) {
		pci_bios_maxbus = subbus;
		alloc_res_array();
	}

	ASSERT(pci_bus_res[secbus].dip == NULL);
	pci_bus_res[secbus].dip = dip;
	pci_bus_res[secbus].par_bus = bus;

	dev_type = (pciex && !is_pci_bridge) ? "pciex" : "pci";

	/* setup bus number hierarchy */
	pci_bus_res[secbus].sub_bus = subbus;
	/*
	 * Keep track of the largest subordinate bus number (this is essential
	 * for peer busses because there is no other way of determining its
	 * subordinate bus number).
	 */
	if (subbus > pci_bus_res[bus].sub_bus)
		pci_bus_res[bus].sub_bus = subbus;
	/*
	 * Loop through subordinate busses, initializing their parent bus
	 * field to this bridge's parent.  The subordinate busses' parent
	 * fields may very well be further refined later, as child bridges
	 * are enumerated.  (The value is to note that the subordinate busses
	 * are not peer busses by changing their par_bus fields to anything
	 * other than -1.)
	 */
	for (i = secbus + 1; i <= subbus; i++)
		pci_bus_res[i].par_bus = bus;

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", dev_type);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2);

	/*
	 * Collect bridge window specifications, and use them to populate
	 * the "avail" resources for the bus.  Not all of those resources will
	 * end up being available; this is done top-down, and so the initial
	 * collection of windows populates the 'ranges' property for the
	 * bus node.  Later, as children are found, resources are removed from
	 * the 'avail' list, so that it becomes the freelist for
	 * this point in the tree.  ranges may be set again after bridge
	 * reprogramming in fix_ppb_res(), in which case it's set from
	 * used + avail.
	 *
	 * According to PPB spec, the base register should be programmed
	 * with a value bigger than the limit register when there are
	 * no resources available. This applies to io, memory, and
	 * prefetchable memory.
	 */

	/*
	 * io range
	 * We determine i/o windows that are left unconfigured by BIOS
	 * through its i/o enable bit as Microsoft recommends OEMs to do.
	 * If it is unset, we disable i/o and mark it for reconfiguration in
	 * later passes by setting the base > limit
	 */
	val = (uint_t)pci_getw(bus, dev, func, PCI_CONF_COMM);
	if (val & PCI_COMM_IO) {
		val = (uint_t)pci_getb(bus, dev, func, PCI_BCNF_IO_BASE_LOW);
		io_range[0] = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT);
		val = (uint_t)pci_getb(bus, dev, func, PCI_BCNF_IO_LIMIT_LOW);
		io_range[1]  = ((val & PCI_BCNF_IO_MASK) << PCI_BCNF_IO_SHIFT) |
		    0xfff;
		if ((io_range[0] & PCI_BCNF_ADDR_MASK) == PCI_BCNF_IO_32BIT) {
			uint16_t io_base_hi, io_limit_hi;
			io_base_hi = pci_getw(bus, dev, func,
			    PCI_BCNF_IO_BASE_HI);
			io_limit_hi = pci_getw(bus, dev, func,
			    PCI_BCNF_IO_LIMIT_HI);

			io_range[0] |= (uint32_t)io_base_hi << 16;
			io_range[1] |= (uint32_t)io_limit_hi << 16;
		}
	} else {
		io_range[0] = 0x9fff;
		io_range[1] = 0x1000;
		pci_putb(bus, dev, func, PCI_BCNF_IO_BASE_LOW,
		    (uint8_t)((io_range[0] >> 8) & 0xf0));
		pci_putb(bus, dev, func, PCI_BCNF_IO_LIMIT_LOW,
		    (uint8_t)((io_range[1] >> 8) & 0xf0));
		pci_putw(bus, dev, func, PCI_BCNF_IO_BASE_HI, 0);
		pci_putw(bus, dev, func, PCI_BCNF_IO_LIMIT_HI, 0);
	}

	if (io_range[0] != 0 && io_range[0] < io_range[1]) {
		memlist_insert(&pci_bus_res[secbus].io_avail,
		    io_range[0], (io_range[1] - io_range[0] + 1));
		memlist_insert(&pci_bus_res[bus].io_used,
		    io_range[0], (io_range[1] - io_range[0] + 1));
		if (pci_bus_res[bus].io_avail != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].io_avail,
			    io_range[0], (io_range[1] - io_range[0] + 1));
		}
		dcmn_err(CE_NOTE, "bus %d io-range: 0x%" PRIx64 "-%" PRIx64,
		    secbus, io_range[0], io_range[1]);
	}

	/* mem range */
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_MEM_BASE);
	mem_range[0] = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_MEM_LIMIT);
	mem_range[1] = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
	    0xfffff;
	if (mem_range[0] != 0 && mem_range[0] < mem_range[1]) {
		memlist_insert(&pci_bus_res[secbus].mem_avail,
		    (uint64_t)mem_range[0],
		    (uint64_t)(mem_range[1] - mem_range[0] + 1));
		memlist_insert(&pci_bus_res[bus].mem_used,
		    (uint64_t)mem_range[0],
		    (uint64_t)(mem_range[1] - mem_range[0] + 1));
		/* remove from parent resource list */
		(void) memlist_remove(&pci_bus_res[bus].mem_avail,
		    (uint64_t)mem_range[0],
		    (uint64_t)(mem_range[1] - mem_range[0] + 1));
		(void) memlist_remove(&pci_bus_res[bus].pmem_avail,
		    (uint64_t)mem_range[0],
		    (uint64_t)(mem_range[1] - mem_range[0] + 1));
		dcmn_err(CE_NOTE, "bus %d mem-range: 0x%" PRIx64 "-%" PRIx64,
		    secbus, mem_range[0], mem_range[1]);
	}

	/* prefetchable memory range */
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_PF_BASE_LOW);
	pmem_range[0] = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT);
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_PF_LIMIT_LOW);
	pmem_range[1] = ((val & PCI_BCNF_MEM_MASK) << PCI_BCNF_MEM_SHIFT) |
	    0xfffff;
	if ((pmem_range[0] & PCI_BCNF_ADDR_MASK) == PCI_BCNF_PF_MEM_64BIT) {
		uint32_t pf_addr_hi, pf_limit_hi;
		pf_addr_hi = pci_getl(bus, dev, func, PCI_BCNF_PF_BASE_HIGH);
		pf_limit_hi = pci_getl(bus, dev, func, PCI_BCNF_PF_LIMIT_HIGH);
		pmem_range[0] |= (uint64_t)pf_addr_hi << 32;
		pmem_range[1] |= (uint64_t)pf_limit_hi << 32;
	}
	if (pmem_range[0] != 0 && pmem_range[0] < pmem_range[1]) {
		memlist_insert(&pci_bus_res[secbus].pmem_avail,
		    (uint64_t)pmem_range[0],
		    (uint64_t)(pmem_range[1] - pmem_range[0] + 1));
		memlist_insert(&pci_bus_res[bus].pmem_used,
		    (uint64_t)pmem_range[0],
		    (uint64_t)(pmem_range[1] - pmem_range[0] + 1));
		/* remove from parent resource list */
		(void) memlist_remove(&pci_bus_res[bus].pmem_avail,
		    (uint64_t)pmem_range[0],
		    (uint64_t)(pmem_range[1] - pmem_range[0] + 1));
		(void) memlist_remove(&pci_bus_res[bus].mem_avail,
		    (uint64_t)pmem_range[0],
		    (uint64_t)(pmem_range[1] - pmem_range[0] + 1));
		dcmn_err(CE_NOTE, "bus %d pmem-range: 0x%" PRIx64 "-%" PRIx64,
		    secbus, pmem_range[0], pmem_range[1]);
	}

	/*
	 * Add VGA legacy resources to the bridge's pci_bus_res if it
	 * has VGA_ENABLE set.  Note that we put them in 'avail',
	 * because that's used to populate the ranges prop; they'll be
	 * removed from there by the VGA device once it's found.  Also,
	 * remove them from the parent's available list and note them as
	 * used in the parent.
	 */

	if (pci_getw(bus, dev, func, PCI_BCNF_BCNTRL) &
	    PCI_BCNF_BCNTRL_VGA_ENABLE) {

		memlist_insert(&pci_bus_res[secbus].io_avail, 0x3b0, 0xc);

		memlist_insert(&pci_bus_res[bus].io_used, 0x3b0, 0xc);
		if (pci_bus_res[bus].io_avail != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].io_avail,
			    0x3b0, 0xc);
		}

		memlist_insert(&pci_bus_res[secbus].io_avail, 0x3c0, 0x20);

		memlist_insert(&pci_bus_res[bus].io_used, 0x3c0, 0x20);
		if (pci_bus_res[bus].io_avail != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].io_avail,
			    0x3c0, 0x20);
		}

		memlist_insert(&pci_bus_res[secbus].mem_avail, 0xa0000,
		    0x20000);

		memlist_insert(&pci_bus_res[bus].mem_used, 0xa0000, 0x20000);
		if (pci_bus_res[bus].mem_avail != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].mem_avail,
			    0xa0000, 0x20000);
		}
	}
	add_bus_range_prop(secbus);
	add_ranges_prop(secbus, 1);
}

extern const struct pci_class_strings_s class_pci[];
extern int class_pci_items;

static void
add_model_prop(dev_info_t *dip, uint_t classcode)
{
	const char *desc;
	int i;
	uchar_t baseclass = classcode >> 16;
	uchar_t subclass = (classcode >> 8) & 0xff;
	uchar_t progclass = classcode & 0xff;

	if ((baseclass == PCI_CLASS_MASS) && (subclass == PCI_MASS_IDE)) {
		desc = "IDE controller";
	} else {
		for (desc = 0, i = 0; i < class_pci_items; i++) {
			if ((baseclass == class_pci[i].base_class) &&
			    (subclass == class_pci[i].sub_class) &&
			    (progclass == class_pci[i].prog_class)) {
				desc = class_pci[i].actual_desc;
				break;
			}
		}
		if (i == class_pci_items)
			desc = "Unknown class of pci/pnpbios device";
	}

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
	    (char *)desc);
}

static void
add_bus_range_prop(int bus)
{
	int bus_range[2];

	if (pci_bus_res[bus].dip == NULL)
		return;
	bus_range[0] = bus;
	bus_range[1] = pci_bus_res[bus].sub_bus;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "bus-range", (int *)bus_range, 2);
}

/*
 * Add slot-names property for any named pci hot-plug slots
 */
static void
add_bus_slot_names_prop(int bus)
{
	char slotprop[256];
	int len;
	extern int pci_irq_nroutes;
	char *slotcap_name;

	/*
	 * If no irq routing table, then go with the slot-names as set up
	 * in pciex_slot_names_prop() from slot capability register (if any).
	 */
	if (pci_irq_nroutes == 0)
		return;

	/*
	 * Otherise delete the slot-names we already have and use the irq
	 * routing table values as returned by pci_slot_names_prop() instead,
	 * but keep any property of value "pcie0" as that can't be represented
	 * in the irq routing table.
	 */
	if (pci_bus_res[bus].dip != NULL) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pci_bus_res[bus].dip,
		    DDI_PROP_DONTPASS, "slot-names", &slotcap_name) !=
		    DDI_SUCCESS || strcmp(slotcap_name, "pcie0") != 0)
			(void) ndi_prop_remove(DDI_DEV_T_NONE,
			    pci_bus_res[bus].dip, "slot-names");
	}

	len = pci_slot_names_prop(bus, slotprop, sizeof (slotprop));
	if (len > 0) {
		/*
		 * Only create a peer bus node if this bus may be a peer bus.
		 * It may be a peer bus if the dip is NULL and if par_bus is
		 * -1 (par_bus is -1 if this bus was not found to be
		 * subordinate to any PCI-PCI bridge).
		 * If it's not a peer bus, then the ACPI BBN-handling code
		 * will remove it later.
		 */
		if (pci_bus_res[bus].par_bus == (uchar_t)-1 &&
		    pci_bus_res[bus].dip == NULL) {

			create_root_bus_dip(bus);
		}
		if (pci_bus_res[bus].dip != NULL) {
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

/*
 * Handle both PCI root and PCI-PCI bridge range properties;
 * non-zero 'ppb' argument select PCI-PCI bridges versus root.
 */
static void
memlist_to_ranges(void **rp, struct memlist *entry, uint_t type, int ppb)
{
	ppb_ranges_t *ppb_rp = *rp;
	pci_ranges_t *pci_rp = *rp;

	while (entry != NULL) {
		uint_t atype = type;
		if ((type & PCI_REG_ADDR_M) == PCI_ADDR_MEM32 &&
		    (entry->ml_address >= UINT32_MAX ||
		    entry->ml_size >= UINT32_MAX)) {
			atype &= ~PCI_ADDR_MEM32;
			atype |= PCI_ADDR_MEM64;
		}
		if (ppb) {
			ppb_rp->child_high = ppb_rp->parent_high = atype;
			ppb_rp->child_mid = ppb_rp->parent_mid =
			    (uint32_t)(entry->ml_address >> 32);
			ppb_rp->child_low = ppb_rp->parent_low =
			    (uint32_t)entry->ml_address;
			ppb_rp->size_high =
			    (uint32_t)(entry->ml_size >> 32);
			ppb_rp->size_low = (uint32_t)entry->ml_size;
			*rp = ++ppb_rp;
		} else {
			pci_rp->child_high = atype;
			pci_rp->child_mid = pci_rp->parent_high =
			    (uint32_t)(entry->ml_address >> 32);
			pci_rp->child_low = pci_rp->parent_low =
			    (uint32_t)entry->ml_address;
			pci_rp->size_high =
			    (uint32_t)(entry->ml_size >> 32);
			pci_rp->size_low = (uint32_t)entry->ml_size;
			*rp = ++pci_rp;
		}
		entry = entry->ml_next;
	}
}

static void
add_ranges_prop(int bus, int ppb)
{
	int total, alloc_size;
	void	*rp, *next_rp;
	struct memlist *iolist, *memlist, *pmemlist;

	/* no devinfo node - unused bus, return */
	if (pci_bus_res[bus].dip == NULL)
		return;

	iolist = memlist = pmemlist = (struct memlist *)NULL;

	memlist_merge(&pci_bus_res[bus].io_avail, &iolist);
	memlist_merge(&pci_bus_res[bus].io_used, &iolist);
	memlist_merge(&pci_bus_res[bus].mem_avail, &memlist);
	memlist_merge(&pci_bus_res[bus].mem_used, &memlist);
	memlist_merge(&pci_bus_res[bus].pmem_avail, &pmemlist);
	memlist_merge(&pci_bus_res[bus].pmem_used, &pmemlist);

	total = memlist_count(iolist);
	total += memlist_count(memlist);
	total += memlist_count(pmemlist);

	/* no property is created if no ranges are present */
	if (total == 0)
		return;

	alloc_size = total *
	    (ppb ? sizeof (ppb_ranges_t) : sizeof (pci_ranges_t));

	next_rp = rp = kmem_alloc(alloc_size, KM_SLEEP);

	memlist_to_ranges(&next_rp, iolist, PCI_ADDR_IO | PCI_REG_REL_M, ppb);
	memlist_to_ranges(&next_rp, memlist,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M, ppb);
	memlist_to_ranges(&next_rp, pmemlist,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M | PCI_REG_PF_M, ppb);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "ranges", (int *)rp, alloc_size / sizeof (int));

	kmem_free(rp, alloc_size);
	memlist_free_all(&iolist);
	memlist_free_all(&memlist);
	memlist_free_all(&pmemlist);
}

static void
memlist_remove_list(struct memlist **list, struct memlist *remove_list)
{
	while (list && *list && remove_list) {
		(void) memlist_remove(list, remove_list->ml_address,
		    remove_list->ml_size);
		remove_list = remove_list->ml_next;
	}
}

static int
memlist_to_spec(struct pci_phys_spec *sp, struct memlist *list, int type)
{
	int i = 0;

	while (list) {
		/* assume 32-bit addresses */
		sp->pci_phys_hi = type;
		sp->pci_phys_mid = 0;
		sp->pci_phys_low = (uint32_t)list->ml_address;
		sp->pci_size_hi = 0;
		sp->pci_size_low = (uint32_t)list->ml_size;

		list = list->ml_next;
		sp++, i++;
	}
	return (i);
}

static void
add_bus_available_prop(int bus)
{
	int i, count;
	struct pci_phys_spec *sp;

	/* no devinfo node - unused bus, return */
	if (pci_bus_res[bus].dip == NULL)
		return;

	count = memlist_count(pci_bus_res[bus].io_avail) +
	    memlist_count(pci_bus_res[bus].mem_avail) +
	    memlist_count(pci_bus_res[bus].pmem_avail);

	if (count == 0)		/* nothing available */
		return;

	sp = kmem_alloc(count * sizeof (*sp), KM_SLEEP);
	i = memlist_to_spec(&sp[0], pci_bus_res[bus].io_avail,
	    PCI_ADDR_IO | PCI_REG_REL_M);
	i += memlist_to_spec(&sp[i], pci_bus_res[bus].mem_avail,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M);
	i += memlist_to_spec(&sp[i], pci_bus_res[bus].pmem_avail,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M | PCI_REG_PF_M);
	ASSERT(i == count);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "available", (int *)sp,
	    i * sizeof (struct pci_phys_spec) / sizeof (int));
	kmem_free(sp, count * sizeof (*sp));
}

static void
alloc_res_array(void)
{
	static int array_size = 0;
	int old_size;
	void *old_res;

	if (array_size > pci_bios_maxbus + 1)
		return;	/* array is big enough */

	old_size = array_size;
	old_res = pci_bus_res;

	if (array_size == 0)
		array_size = 16;	/* start with a reasonable number */

	while (array_size <= pci_bios_maxbus + 1)
		array_size <<= 1;
	pci_bus_res = (struct pci_bus_resource *)kmem_zalloc(
	    array_size * sizeof (struct pci_bus_resource), KM_SLEEP);

	if (old_res) {	/* copy content and free old array */
		bcopy(old_res, pci_bus_res,
		    old_size * sizeof (struct pci_bus_resource));
		kmem_free(old_res, old_size * sizeof (struct pci_bus_resource));
	}
}

static void
create_ioapic_node(int bus, int dev, int fn, ushort_t vendorid,
    ushort_t deviceid)
{
	static dev_info_t *ioapicsnode = NULL;
	static int numioapics = 0;
	dev_info_t *ioapic_node;
	uint64_t physaddr;
	uint32_t lobase, hibase = 0;

	/* BAR 0 contains the IOAPIC's memory-mapped I/O address */
	lobase = (*pci_getl_func)(bus, dev, fn, PCI_CONF_BASE0);

	/* We (and the rest of the world) only support memory-mapped IOAPICs */
	if ((lobase & PCI_BASE_SPACE_M) != PCI_BASE_SPACE_MEM)
		return;

	if ((lobase & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL)
		hibase = (*pci_getl_func)(bus, dev, fn, PCI_CONF_BASE0 + 4);

	lobase &= PCI_BASE_M_ADDR_M;

	physaddr = (((uint64_t)hibase) << 32) | lobase;

	/*
	 * Create a nexus node for all IOAPICs under the root node.
	 */
	if (ioapicsnode == NULL) {
		if (ndi_devi_alloc(ddi_root_node(), IOAPICS_NODE_NAME,
		    (pnode_t)DEVI_SID_NODEID, &ioapicsnode) != NDI_SUCCESS) {
			return;
		}
		(void) ndi_devi_online(ioapicsnode, 0);
	}

	/*
	 * Create a child node for this IOAPIC
	 */
	ioapic_node = ddi_add_child(ioapicsnode, IOAPICS_CHILD_NAME,
	    DEVI_SID_NODEID, numioapics++);
	if (ioapic_node == NULL) {
		return;
	}

	/* Vendor and Device ID */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, ioapic_node,
	    IOAPICS_PROP_VENID, vendorid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, ioapic_node,
	    IOAPICS_PROP_DEVID, deviceid);

	/* device_type */
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, ioapic_node,
	    "device_type", IOAPICS_DEV_TYPE);

	/* reg */
	(void) ndi_prop_update_int64(DDI_DEV_T_NONE, ioapic_node,
	    "reg", physaddr);
}

/*
 * NOTE: For PCIe slots, the name is generated from the slot number
 * information obtained from Slot Capabilities register.
 * For non-PCIe slots, it is generated based on the slot number
 * information in the PCI IRQ table.
 */
static void
pciex_slot_names_prop(dev_info_t *dip, ushort_t slot_num)
{
	char slotprop[256];
	int len;

	bzero(slotprop, sizeof (slotprop));

	/* set mask to 1 as there is only one slot (i.e dev 0) */
	*(uint32_t *)slotprop = 1;
	len = 4;
	(void) snprintf(slotprop + len, sizeof (slotprop) - len, "pcie%d",
	    slot_num);
	len += strlen(slotprop + len) + 1;
	len += len % 4;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "slot-names",
	    (int *)slotprop, len / sizeof (int));
}

/*
 * Enable reporting of AER capability next pointer.
 * This needs to be done only for CK8-04 devices
 * by setting NV_XVR_VEND_CYA1 (offset 0xf40) bit 13
 * NOTE: BIOS is disabling this, it needs to be enabled temporarily
 *
 * This function is adapted from npe_ck804_fix_aer_ptr(), and is
 * called from pci_boot.c.
 */
static void
ck804_fix_aer_ptr(dev_info_t *dip, pcie_req_id_t bdf)
{
	dev_info_t *rcdip;
	ushort_t cya1;

	rcdip = pcie_get_rc_dip(dip);
	ASSERT(rcdip != NULL);

	if ((pci_cfgacc_get16(rcdip, bdf, PCI_CONF_VENID) ==
	    NVIDIA_VENDOR_ID) &&
	    (pci_cfgacc_get16(rcdip, bdf, PCI_CONF_DEVID) ==
	    NVIDIA_CK804_DEVICE_ID) &&
	    (pci_cfgacc_get8(rcdip, bdf, PCI_CONF_REVID) >=
	    NVIDIA_CK804_AER_VALID_REVID)) {
		cya1 = pci_cfgacc_get16(rcdip, bdf, NVIDIA_CK804_VEND_CYA1_OFF);
		if (!(cya1 & ~NVIDIA_CK804_VEND_CYA1_ERPT_MASK))
			(void) pci_cfgacc_put16(rcdip, bdf,
			    NVIDIA_CK804_VEND_CYA1_OFF,
			    cya1 | NVIDIA_CK804_VEND_CYA1_ERPT_VAL);
	}
}
