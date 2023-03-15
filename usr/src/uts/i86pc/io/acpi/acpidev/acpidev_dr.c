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
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/note.h>
#include <sys/obpdefs.h>
#include <sys/synch.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/memnode.h>	/* for lgrp_plat_node_cnt */
#include <sys/psm_types.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_rsc.h>
#include <sys/acpidev_dr.h>
#include <sys/acpidev_impl.h>

struct acpidev_dr_set_prop_arg {
	uint32_t	level;
	uint32_t	bdnum;
	uint32_t	cpu_id;
	uint32_t	mem_id;
	uint32_t	io_id;
	uint32_t	mod_id;
};

struct acpidev_dr_device_remove_arg {
	uint32_t	level;
};

extern int acpidev_options;

/* User configurable option to enable/disable ACPI based DR operations. */
int acpidev_dr_enable = 1;
int acpidev_dr_hierarchy_name = 1;
uint32_t acpidev_dr_max_segs_per_mem_device = ACPIDEV_DR_SEGS_PER_MEM_DEV;
uint32_t acpidev_dr_max_memlists_per_seg = ACPIDEV_DR_MEMLISTS_PER_SEG;

ACPI_TABLE_SRAT *acpidev_srat_tbl_ptr;
ACPI_TABLE_SLIT *acpidev_slit_tbl_ptr;

/* ACPI based DR operations are unsupported if zero. */
static int acpidev_dr_supported = -1;

/* Failed to initialize support of DR operations if non-zero. */
static int acpidev_dr_failed;

static volatile uint32_t acpidev_dr_boards;
static volatile uint32_t acpidev_dr_board_index;
static uint32_t acpidev_dr_max_cmp_per_board;
static uint32_t acpidev_dr_max_memory_per_board;
static uint32_t acpidev_dr_max_io_per_board;
static uint32_t acpidev_dr_memory_device_cnt;

static ACPI_HANDLE *acpidev_dr_board_handles[ACPIDEV_DR_MAX_BOARDS];

/* Lock to protect/block DR operations at runtime. */
static kmutex_t acpidev_dr_lock;

static acpidev_dr_capacity_t acpidev_dr_capacities[] = {
	{   /* Nehalem-EX */
	    X86_VENDOR_Intel, 0x6, 0x2e, 0x2e, 0, UINT_MAX,
	    B_TRUE,		/* Hotplug capable */
	    1ULL << 30,		/* Align on 1GB boundary */
	},
	{   /* the last item is used to mark end of the table */
	    UINT_MAX, UINT_MAX, UINT_MAX, 0, UINT_MAX, 0,
	    B_FALSE,
	    0,
	},
};

static ACPI_STATUS acpidev_dr_scan_topo(ACPI_HANDLE hdl, UINT32 lvl, void *arg,
    void **retval);

static acpidev_dr_capacity_t *
acpidev_dr_get_capacity(void)
{
	acpidev_dr_capacity_t *cp, *cp1;
	uint_t vendor, family, model, step;
	static acpidev_dr_capacity_t *acpidev_dr_capacity_curr = NULL;

	if (acpidev_dr_capacity_curr != NULL) {
		return (acpidev_dr_capacity_curr);
	}

	kpreempt_disable();
	vendor = cpuid_getvendor(CPU);
	family = cpuid_getfamily(CPU);
	model = cpuid_getmodel(CPU);
	step = cpuid_getstep(CPU);
	kpreempt_enable();

	for (cp = acpidev_dr_capacities; ; cp++) {
		ASSERT(cp < acpidev_dr_capacities +
		    sizeof (acpidev_dr_capacities) / sizeof (*cp));

		/* Check whether it reaches the last item of the table. */
		if (cp->cpu_vendor == UINT_MAX && cp->cpu_family == UINT_MAX &&
		    cp->cpu_model_min == UINT_MAX && cp->cpu_model_max == 0 &&
		    cp->cpu_step_min == UINT_MAX && cp->cpu_step_max == 0) {
			break;
		}
		if (cp->cpu_vendor == vendor && cp->cpu_family == family &&
		    model >= cp->cpu_model_min && model <= cp->cpu_model_max &&
		    step >= cp->cpu_step_min && step <= cp->cpu_step_max) {
			break;
		}
	}

	/* Assume all CPUs in system are homogeneous. */
	cp1 = atomic_cas_ptr(&acpidev_dr_capacity_curr, NULL, cp);
	ASSERT(cp1 == NULL || cp1 == cp);
	if (cp1 != NULL && cp1 != cp) {
		return (NULL);
	}

	return (cp);
}

int
acpidev_dr_capable(void)
{
	uint64_t flags1, flags2;
	acpidev_dr_capacity_t *cp;

	/*
	 * Disable support of DR operations if:
	 * 1) acpidev fails to initialize DR interfaces.
	 * 2) ACPI based DR has been disabled by user.
	 * 3) No DR capable devices have been detected.
	 * 4) The system doesn't support DR operations.
	 * 5) Some acpidev features have been disabled by user.
	 */
	if (acpidev_dr_failed != 0 || acpidev_dr_enable == 0 ||
	    acpidev_dr_supported == 0) {
		return (0);
	}

	flags1 = ACPI_FEATURE_DEVCFG | ACPI_FEATURE_OSI_MODULE;
	flags2 = ACPI_DEVCFG_CPU | ACPI_DEVCFG_MEMORY |
	    ACPI_DEVCFG_CONTAINER | ACPI_DEVCFG_PCI;
	if (acpica_get_core_feature(flags1) != flags1 ||
	    acpica_get_devcfg_feature(flags2) != flags2) {
		cmn_err(CE_CONT,
		    "?acpidev: disable support of ACPI based DR because "
		    "some acpidev features have been disabled by user.\n");
		acpidev_dr_supported = 0;
		return (0);
	}

	cp = acpidev_dr_get_capacity();
	if (cp == NULL || cp->hotplug_supported == B_FALSE) {
		return (0);
	}

	return (1);
}

uint32_t
acpidev_dr_max_boards(void)
{
	return (acpidev_dr_boards);
}

uint32_t
acpidev_dr_max_io_units_per_board(void)
{
	return (acpidev_dr_max_io_per_board);
}

uint32_t
acpidev_dr_max_mem_units_per_board(void)
{
	return (acpidev_dr_max_memory_per_board);
}

uint32_t
acpidev_dr_max_cmp_units_per_board(void)
{
	return (acpidev_dr_max_cmp_per_board);
}

uint32_t
acpidev_dr_max_cpu_units_per_cmp(void)
{
	static int max_cnt;

	if (max_cnt == 0) {
		kpreempt_disable();
		max_cnt = cpuid_get_ncpu_per_chip(CPU);
		kpreempt_enable();
	}

	return (max_cnt);
}

uint32_t
acpidev_dr_max_segments_per_mem_device(void)
{
	if (acpidev_dr_max_segs_per_mem_device < 1) {
		return (ACPIDEV_DR_SEGS_PER_MEM_DEV);
	} else {
		return (acpidev_dr_max_segs_per_mem_device);
	}
}

uint32_t
acpidev_dr_max_memlists_per_segment(void)
{
	if (acpidev_dr_max_memlists_per_seg < ACPIDEV_DR_MEMLISTS_PER_SEG) {
		return (ACPIDEV_DR_MEMLISTS_PER_SEG);
	} else {
		return (acpidev_dr_max_memlists_per_seg);
	}
}

void
acpidev_dr_init(void)
{
	mutex_init(&acpidev_dr_lock, NULL, MUTEX_DRIVER, NULL);
}

static void
acpidev_dr_check_board_type(acpidev_data_handle_t dhdl,
    struct acpidev_dr_set_prop_arg *ap, char *objname)
{
	if (dhdl->aod_class_id == ACPIDEV_CLASS_ID_MEMORY) {
		/* Memory board should have only one memory device. */
		ASSERT(ap->cpu_id == 0);
		ASSERT(ap->mem_id == 1);
		ASSERT(ap->io_id == 0);
		ASSERT(ap->mod_id == 0);
		dhdl->aod_bdtype = ACPIDEV_MEMORY_BOARD;
	} else if (dhdl->aod_class_id == ACPIDEV_CLASS_ID_PCI ||
	    dhdl->aod_class_id == ACPIDEV_CLASS_ID_PCIEX) {
		/* IO board should have only one IO device. */
		ASSERT(ap->cpu_id == 0);
		ASSERT(ap->mem_id == 0);
		ASSERT(ap->io_id == 1);
		ASSERT(ap->mod_id == 0);
		dhdl->aod_bdtype = ACPIDEV_IO_BOARD;
	} else if (dhdl->aod_class_id == ACPIDEV_CLASS_ID_CONTAINER) {
		if (ap->mod_id == 1 && ap->mem_id == 0) {
			dhdl->aod_bdtype = ACPIDEV_CPU_BOARD;
		} else {
			dhdl->aod_bdtype = ACPIDEV_SYSTEM_BOARD;
		}
	} else {
		cmn_err(CE_WARN,
		    "!acpidev: unknown type of hotplug capable board %s.",
		    objname);
		ASSERT(0);
	}
}

/*
 * Check for hotplug capable boards and create environment to support
 * ACPI based DR operations. No need to acquire lock here, it's called
 * from single-threaded context during boot.
 */
void
acpidev_dr_check(acpidev_walk_info_t *infop)
{
	uint_t cmp;
	boolean_t found = B_FALSE;
	ACPI_HANDLE phdl;
	acpidev_data_handle_t dhdl, pdhdl;
	struct acpidev_dr_set_prop_arg arg;

	if (infop == NULL ||
	    infop->awi_op_type != ACPIDEV_OP_BOOT_PROBE) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: invalid parameter to acpidev_dr_check().");
		return;
	}

	if (acpidev_dr_capable() == 0) {
		return;
	}

	dhdl = infop->awi_data;
	ASSERT(dhdl != NULL);

	/* This device has already been handled before. */
	if (ACPIDEV_DR_IS_PROCESSED(dhdl)) {
		return;
	}

	/*
	 * It implies that the device is hotplug capable if ACPI _EJ0 method
	 * is available.
	 */
	if (!ACPIDEV_DR_IS_BOARD(dhdl) &&
	    acpidev_dr_device_hotplug_capable(infop->awi_hdl)) {
		ACPIDEV_DR_SET_BOARD(dhdl);
	}

	/* All things are done if the device isn't hotplug capable. */
	if (!ACPIDEV_DR_IS_BOARD(dhdl)) {
		return;
	}

	/* Check whether hardware topology is supported or not. */
	if (ACPI_FAILURE(acpidev_dr_scan_topo(infop->awi_hdl, 0, NULL,
	    NULL))) {
		ACPIDEV_DR_SET_FAILED(dhdl);
		ACPIDEV_DEBUG(CE_NOTE, "!acpidev: hardware topology under %s "
		    "is unsupported for DR operations.", infop->awi_name);
		return;
	}

	/* Generate board/index/port number for the hotplug capable board. */
	dhdl->aod_bdnum = atomic_inc_32_nv(&acpidev_dr_boards) - 1;
	dhdl->aod_portid = 0;
	phdl = infop->awi_hdl;
	while (ACPI_SUCCESS(AcpiGetParent(phdl, &phdl)) &&
	    phdl != ACPI_ROOT_OBJECT) {
		pdhdl = acpidev_data_get_handle(phdl);
		if (pdhdl != NULL && ACPIDEV_DR_IS_BOARD(pdhdl)) {
			dhdl->aod_bdidx = atomic_inc_32_nv(&pdhdl->aod_chidx);
			found = B_TRUE;
			break;
		}
	}
	if (found == B_FALSE) {
		dhdl->aod_bdidx = atomic_inc_32_nv(&acpidev_dr_board_index);
	}
	dhdl->aod_bdidx -= 1;

	/* Found too many hotplug capable boards. */
	if (dhdl->aod_bdnum >= ACPIDEV_DR_MAX_BOARDS) {
		ACPIDEV_DR_SET_FAILED(dhdl);
		cmn_err(CE_WARN, "!acpidev: too many hotplug capable boards, "
		    "max %d, found %d.",
		    ACPIDEV_DR_MAX_BOARDS, dhdl->aod_bdnum + 1);
		return;
	}

	/* Scan all descendant devices to prepare info for DR operations. */
	bzero(&arg, sizeof (arg));
	arg.bdnum = dhdl->aod_bdnum;
	arg.level = infop->awi_level;
	if (ACPI_FAILURE(acpidev_dr_scan_topo(infop->awi_hdl, 0, &arg,
	    NULL))) {
		ACPIDEV_DR_SET_FAILED(dhdl);
		ACPIDEV_DEBUG(CE_NOTE, "!acpidev: failed to set DR properties "
		    "for descendants of %s.", infop->awi_name);
		return;
	}

	/* Get type of the hotplug capable board. */
	acpidev_dr_check_board_type(dhdl, &arg, infop->awi_name);

	/*
	 * Save ACPI handle of the hotplug capable board to speed up lookup
	 * board handle if caching is enabled.
	 */
	if ((acpidev_options & ACPIDEV_OUSER_NO_CACHE) == 0) {
		acpidev_dr_board_handles[dhdl->aod_bdnum] = infop->awi_hdl;
	}

	/* Update system maximum DR capabilities. */
	cmp = (arg.cpu_id + acpidev_dr_max_cpu_units_per_cmp() - 1);
	cmp /= acpidev_dr_max_cpu_units_per_cmp();
	if (cmp > acpidev_dr_max_cmp_per_board) {
		acpidev_dr_max_cmp_per_board = cmp;
	}
	if (arg.mem_id > acpidev_dr_max_memory_per_board) {
		acpidev_dr_max_memory_per_board = arg.mem_id;
	}
	if (arg.io_id > acpidev_dr_max_io_per_board) {
		acpidev_dr_max_io_per_board = arg.io_id;
	}
}

static void
acpidev_dr_initialize_memory_hotplug(void)
{
	caddr_t buf;
	uint32_t cnt;
	acpidev_dr_capacity_t *cp;

	/*
	 * We have already checked that the platform supports DR operations.
	 */
	cp = acpidev_dr_get_capacity();
	ASSERT(cp != NULL && cp->hotplug_supported);
	ASSERT(ISP2(cp->memory_alignment));
	ASSERT(cp->memory_alignment > MMU_PAGESIZE);
	mem_node_physalign = cp->memory_alignment;

	/* Pre-populate memlist cache. */
	cnt = acpidev_dr_memory_device_cnt;
	cnt *= acpidev_dr_max_segments_per_mem_device();
	cnt *= acpidev_dr_max_memlists_per_segment();
	if (cnt > ACPIDEV_DR_MAX_MEMLIST_ENTRIES) {
		cmn_err(CE_WARN, "!acpidev: attempted to reserve too many "
		    "memlist entries (%u), max %u.  Falling back to %u and "
		    "some memory hot add operations may fail.",
		    cnt, ACPIDEV_DR_MAX_MEMLIST_ENTRIES,
		    ACPIDEV_DR_MAX_MEMLIST_ENTRIES);
		cnt = ACPIDEV_DR_MAX_MEMLIST_ENTRIES;
	}
	cnt *= sizeof (struct memlist);
	buf = kmem_zalloc(cnt, KM_SLEEP);
	memlist_free_block(buf, cnt);
}

/*
 * Create pseudo DR control device node if the system is hotplug capable.
 * No need to acquire lock, it's called from single-threaded context
 * during boot. pdip has been held by the caller.
 */
static ACPI_STATUS
acpidev_dr_create_node(dev_info_t *pdip)
{
	dev_info_t *dip;
	char unit[32];
	char *path;
	char *comps[] = {
		"acpidr_sbd",
	};

	/*
	 * Disable support of DR operations if no hotplug capable board has
	 * been detected.
	 */
	if (acpidev_dr_boards == 0) {
		acpidev_dr_supported = 0;
	} else {
		acpidev_dr_supported = 1;
	}

	/*
	 * Don't create control device node if the system isn't hotplug capable.
	 */
	if (acpidev_dr_capable() == 0) {
		return (AE_SUPPORT);
	}

	/* Cache pointer to the ACPI SLIT table. */
	if (ACPI_FAILURE(AcpiGetTable(ACPI_SIG_SLIT, 1,
	    (ACPI_TABLE_HEADER **)&acpidev_slit_tbl_ptr))) {
		acpidev_slit_tbl_ptr = NULL;
	}
	if (acpidev_srat_tbl_ptr == NULL || acpidev_slit_tbl_ptr == NULL) {
		if (lgrp_plat_node_cnt != 1) {
			/*
			 * Disable support of CPU/memory DR operations if lgrp
			 * is enabled but failed to cache SRAT/SLIT table
			 * pointers.
			 */
			cmn_err(CE_WARN,
			    "!acpidev: failed to get ACPI SRAT/SLIT table.");
			plat_dr_disable_cpu();
			plat_dr_disable_memory();
		}
	}

	ndi_devi_alloc_sleep(pdip, ACPIDEV_NODE_NAME_ACPIDR,
	    (pnode_t)DEVI_PSEUDO_NODEID, &dip);

	/* Set "unit-address" device property. */
	(void) snprintf(unit, sizeof (unit), "%u", 0);
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    ACPIDEV_PROP_NAME_UNIT_ADDR, unit) != NDI_SUCCESS) {
		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		cmn_err(CE_CONT,
		    "?acpidev: failed to set unit-address property for %s.\n",
		    ddi_pathname(dip, path));
		kmem_free(path, MAXPATHLEN);
		(void) ddi_remove_child(dip, 0);
		acpidev_dr_failed = 1;
		return (AE_ERROR);
	}

	/* Set "compatible" device property. */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, dip, OBP_COMPATIBLE,
	    comps, sizeof (comps) / sizeof (comps[0])) != NDI_SUCCESS) {
		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		cmn_err(CE_CONT, "?acpidev: failed to set compatible "
		    "property for %s.\n", ddi_pathname(dip, path));
		kmem_free(path, MAXPATHLEN);
		(void) ddi_remove_child(dip, 0);
		acpidev_dr_failed = 1;
		return (AE_ERROR);
	}

	(void) ndi_devi_bind_driver(dip, 0);

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_initialize(dev_info_t *pdip)
{
	ACPI_STATUS rc;

	rc = acpidev_dr_create_node(pdip);
	if (ACPI_FAILURE(rc)) {
		return (rc);
	}

	/* Initialize support of memory DR operations. */
	if (plat_dr_support_memory()) {
		acpidev_dr_initialize_memory_hotplug();
	}

	/* Mark the DR subsystem is ready for use. */
	plat_dr_enable();

	return (AE_OK);
}

static ACPI_STATUS
acpidev_dr_find_board(ACPI_HANDLE hdl, uint_t lvl, void *ctx, void **retval)
{
	_NOTE(ARGUNUSED(lvl));

	acpidev_data_handle_t dhdl;

	ASSERT(hdl != NULL);
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		/* No data handle available, not ready for DR operations. */
		return (AE_CTRL_DEPTH);
	} else if (ACPIDEV_DR_IS_BOARD(dhdl) && ACPIDEV_DR_IS_WORKING(dhdl) &&
	    dhdl->aod_bdnum == (intptr_t)ctx) {
		ASSERT(retval != NULL);
		*(ACPI_HANDLE *)retval = hdl;
		return (AE_CTRL_TERMINATE);
	}

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_get_board_handle(uint_t board, ACPI_HANDLE *hdlp)
{
	ACPI_STATUS rc = AE_OK;
	ACPI_HANDLE hdl;

	ASSERT(hdlp != NULL);
	if (hdlp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_get_board_handle().");
		return (AE_BAD_PARAMETER);
	}

	if (board >= acpidev_dr_boards) {
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: board number %d is out of range, max %d.",
		    board, acpidev_dr_boards);
		return (AE_NOT_FOUND);
	}

	/* Use cached handles if caching is enabled. */
	if ((acpidev_options & ACPIDEV_OUSER_NO_CACHE) == 0) {
		if (acpidev_dr_board_handles[board] != NULL) {
			hdl = acpidev_dr_board_handles[board];
			if (ACPI_FAILURE(acpidev_dr_find_board(hdl, 1,
			    (void *)(intptr_t)board, (void **)hdlp)) &&
			    *hdlp != NULL) {
				return (AE_OK);
			}
		}
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: board %d doesn't exist.", board);
		*hdlp = NULL;
		return (AE_NOT_FOUND);
	}

	/* All hotplug capable boards should exist under \_SB_. */
	if (ACPI_FAILURE(AcpiGetHandle(ACPI_ROOT_OBJECT,
	    ACPIDEV_OBJECT_NAME_SB, &hdl))) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get handle of %s.",
		    ACPIDEV_OBJECT_NAME_SB);
		return (AE_ERROR);
	}

	*hdlp = NULL;
	if (ACPI_FAILURE(AcpiWalkNamespace(ACPI_TYPE_DEVICE, hdl,
	    ACPIDEV_MAX_ENUM_LEVELS - 1, acpidev_dr_find_board, NULL,
	    (void *)(intptr_t)board, (void **)hdlp))) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to find ACPI handle "
		    "for board %d.", board);
		rc = AE_NOT_FOUND;
	} else if (*hdlp == NULL) {
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: board %d doesn't exist.", board);
		rc = AE_NOT_FOUND;
	}

	return (rc);
}

acpidev_board_type_t
acpidev_dr_get_board_type(ACPI_HANDLE hdl)
{
	acpidev_data_handle_t dhdl;
	acpidev_board_type_t type = ACPIDEV_INVALID_BOARD;

	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_get_board_type().");
		return (type);
	}

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data associated with %p.", hdl);
	} else {
		type = dhdl->aod_bdtype;
	}

	return (type);
}

ACPI_STATUS
acpidev_dr_get_board_number(ACPI_HANDLE hdl, uint32_t *bnump)
{
	acpidev_data_handle_t dhdl;

	if (hdl == NULL || bnump == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_get_board_number().");
		return (AE_BAD_PARAMETER);
	}

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data associated with %p.", hdl);
		return (AE_ERROR);
	}
	*bnump = dhdl->aod_bdnum;

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_get_board_name(ACPI_HANDLE hdl, char *buf, size_t len)
{
	char *fmt;
	int count = 0;
	size_t rlen = 0;
	ACPI_HANDLE thdl;
	acpidev_data_handle_t dhdl;
	acpidev_data_handle_t dhdls[ACPIDEV_MAX_ENUM_LEVELS];

	if (hdl == NULL || buf == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_get_board_name().");
		return (AE_BAD_PARAMETER);
	}

	/* Find ancestors of the device which are hotplug capable. */
	for (thdl = hdl; thdl != NULL; ) {
		dhdl = acpidev_data_get_handle(thdl);
		if (dhdl == NULL) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get data "
			    "associated with %p.", thdl);
			return (AE_ERROR);
		}

		if (!ACPIDEV_DR_IS_BOARD(dhdl)) {
			/* The board itself should be hotplug capable. */
			if (count == 0) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %p is "
				    "not hotplug capable.", thdl);
				return (AE_ERROR);
			}
		} else {
			if (ACPIDEV_DR_IS_FAILED(dhdl)) {
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %p is "
				    "in the FAILED state.", thdl);
			}

			if (count >= ACPIDEV_MAX_ENUM_LEVELS) {
				ACPIDEV_DEBUG(CE_WARN,
				    "!acpidev: recursive level for hotplug "
				    "capable board is too deep.");
				return (AE_ERROR);
			}

			dhdls[count] = dhdl;
			count++;
		}

		if (acpidev_dr_hierarchy_name == 0) {
			thdl = NULL;
		} else if (ACPI_FAILURE(AcpiGetParent(thdl, &thdl))) {
			thdl = NULL;
		}
	}

	/* Generate hierarchy board name for the board. */
	ASSERT(count > 0);
	for (count--; count >= 0 && rlen < len; count--) {
		dhdl = dhdls[count];
		switch (dhdl->aod_bdtype) {
		case ACPIDEV_CPU_BOARD:
			fmt = ACPIDEV_DR_CPU_BD_FMT;
			break;
		case ACPIDEV_MEMORY_BOARD:
			fmt = ACPIDEV_DR_MEMORY_BD_FMT;
			break;
		case ACPIDEV_IO_BOARD:
			fmt = ACPIDEV_DR_IO_BD_FMT;
			break;
		case ACPIDEV_SYSTEM_BOARD:
			fmt = ACPIDEV_DR_SYSTEM_BD_FMT;
			break;
		case ACPIDEV_INVALID_BOARD:
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid board type.");
			return (AE_ERROR);
		default:
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: unknown board type %u.",
			    dhdl->aod_bdtype);
			return (AE_ERROR);
		}

		/* Add "." before component name except first item. */
		if (rlen != 0) {
			rlen += snprintf(buf + rlen, len - rlen, ".");
		}
		if (rlen < len) {
			rlen += snprintf(buf + rlen, len - rlen, fmt,
			    dhdl->aod_bdidx);
		}
	}

	/* Check whether the buffer is sufficient. */
	if (rlen >= len) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: buffer length to "
		    "acpidev_dr_get_board_name() is too small.");
		return (AE_NO_MEMORY);
	}

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_get_attachment_point(ACPI_HANDLE hdl, char *buf, size_t len)
{
	size_t rlen;

	if (hdl == NULL || buf == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_get_attachment_point().");
		return (AE_BAD_PARAMETER);
	}

	rlen = snprintf(buf, len, "/devices/%s/%s@%u:",
	    ACPIDEV_NODE_NAME_ROOT, ACPIDEV_NODE_NAME_ACPIDR, 0);
	if (rlen >= len) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: buffer to "
		    "acpidev_dr_get_attachment_point() is too small.");
		return (AE_NO_MEMORY);
	}

	return (acpidev_dr_get_board_name(hdl, buf + rlen, len - rlen));
}

/*
 * Existence of ACPI _EJ0 method implies that the device is hotplug capable.
 */
int
acpidev_dr_device_hotplug_capable(ACPI_HANDLE hdl)
{
	ACPI_HANDLE ej0;

	ASSERT(hdl != NULL);
	if (ACPI_FAILURE(AcpiGetHandle(hdl, ACPIDEV_METHOD_NAME_EJ0, &ej0))) {
		return (0);
	}

	return (1);
}

int
acpidev_dr_device_has_edl(ACPI_HANDLE hdl)
{
	ACPI_HANDLE edl;

	ASSERT(hdl != NULL);
	if (ACPI_FAILURE(AcpiGetHandle(hdl, ACPIDEV_METHOD_NAME_EDL, &edl))) {
		return (0);
	}

	return (1);
}

int
acpidev_dr_device_is_present(ACPI_HANDLE hdl)
{
	int 		status;

	ASSERT(hdl != NULL);

	status = acpidev_query_device_status(hdl);
	if (acpidev_check_device_present(status)) {
		return (1);
	}

	return (0);
}

int
acpidev_dr_device_is_powered(ACPI_HANDLE hdl)
{
	int 		status;

	ASSERT(hdl != NULL);

	/*
	 * Check device status returned by ACPI _STA method.
	 * It implies that the device is powered if status is both PRESENT
	 * and ENABLED.
	 */
	status = acpidev_query_device_status(hdl);
	if (acpidev_check_device_enabled(status)) {
		return (1);
	}

	return (0);
}

ACPI_STATUS
acpidev_dr_get_mem_alignment(ACPI_HANDLE hdl, uint64_t *ap)
{
	acpidev_dr_capacity_t *cp;

	ASSERT(hdl != NULL);
	ASSERT(ap != NULL);
	if (ap == NULL || hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_get_mem_alignment().");
		return (AE_BAD_PARAMETER);
	}

	cp = acpidev_dr_get_capacity();
	if (cp == NULL || cp->hotplug_supported == B_FALSE) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get memory alignment.");
		return (AE_SUPPORT);
	}
	*ap = cp->memory_alignment;

	return (AE_OK);
}

/*
 * Get the device property for the given name and store it into buf.
 * Returns the amount of data copied to buf if len is large enough to
 * hold all of the data.  If len is not large enough, then the required
 * len would be returned and buf would not be modified.  On any errors,
 * -1 is returned and buf is not modified.
 */
ACPI_STATUS
acpidev_dr_device_get_regspec(ACPI_HANDLE hdl, boolean_t assigned,
    acpidev_regspec_t **regpp, uint_t *cntp)
{
	int *valp;
	uint_t count;
	char *propname;
	dev_info_t *dip;
	acpidev_data_handle_t dhdl;

	ASSERT(hdl != NULL);
	ASSERT(regpp != NULL && cntp != NULL);
	if (hdl == NULL || regpp == NULL || cntp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameters to "
		    "acpidev_dr_device_get_regspec().");
		return (AE_BAD_PARAMETER);
	}

	/* Set default return value. */
	*regpp = NULL;
	*cntp = 0;

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data associated with %p.", hdl);
		return (AE_ERROR);
	} else if ((dip = acpidev_data_get_devinfo(dhdl)) == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get dip associated with %p.", hdl);
		return (AE_NOT_FOUND);
	}

	propname = assigned ? "assigned-addresses" : "reg";
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    propname, &valp, &count) != DDI_PROP_SUCCESS) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to lookup device property %s.", propname);
		return (AE_NOT_FOUND);
	}

	if (count % (sizeof (**regpp) / sizeof (int)) != 0) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: device property %s is invalid.", propname);
		ddi_prop_free(valp);
		return (AE_ERROR);
	}

	*regpp = (acpidev_regspec_t *)valp;
	*cntp = count / (sizeof (**regpp) / sizeof (int));

	return (AE_OK);
}

void
acpidev_dr_device_free_regspec(acpidev_regspec_t *regp, uint_t count)
{
	_NOTE(ARGUNUSED(count));

	if (regp != NULL) {
		ddi_prop_free(regp);
	}
}

/*
 * Return values
 * . negative values on error
 * . size of data copied to buffer if it's bigger enough
 * . size of buffer needed if buffer is too small
 */
int
acpidev_dr_device_getprop(ACPI_HANDLE hdl, char *name, caddr_t buf, size_t len)
{
	int rlen = -1;
	acpidev_data_handle_t dhdl;

	if (hdl == NULL) {
		return (-1);
	}

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		return (-1);
	} else if (!ACPIDEV_DR_IS_WORKING(dhdl)) {
		return (-1);
	}

	if (strcmp(name, ACPIDEV_DR_PROP_PORTID) == 0) {
		if (len >= sizeof (uint32_t)) {
			*(uint32_t *)(void *)buf = dhdl->aod_portid;
		}
		rlen = sizeof (uint32_t);
	} else if (strcmp(name, ACPIDEV_DR_PROP_BOARDNUM) == 0) {
		if (len >= sizeof (uint32_t)) {
			*(uint32_t *)(void *)buf = dhdl->aod_bdnum;
		}
		rlen = sizeof (uint32_t);
	} else if (strcmp(name, ACPIDEV_DR_PROP_DEVNAME) == 0) {
		switch (dhdl->aod_class_id) {
		case ACPIDEV_CLASS_ID_CPU:
			if (len >= sizeof (ACPIDEV_NODE_NAME_CPU)) {
				(void) strlcpy((char *)buf,
				    ACPIDEV_NODE_NAME_CPU, len);
			}
			rlen = sizeof (ACPIDEV_NODE_NAME_CPU);
			break;

		case ACPIDEV_CLASS_ID_MEMORY:
			if (len >= sizeof (ACPIDEV_NODE_NAME_MEMORY)) {
				(void) strlcpy((char *)buf,
				    ACPIDEV_NODE_NAME_MEMORY, len);
			}
			rlen = sizeof (ACPIDEV_NODE_NAME_MEMORY);
			break;

		case ACPIDEV_CLASS_ID_PCI:
		case ACPIDEV_CLASS_ID_PCIEX:
			if (len >= sizeof (ACPIDEV_NODE_NAME_PCI)) {
				(void) strlcpy((char *)buf,
				    ACPIDEV_NODE_NAME_PCI, len);
			}
			rlen = sizeof (ACPIDEV_NODE_NAME_PCI);
			break;

		default:
			break;
		}
	}

	return (rlen);
}

/*
 * Figure out device class of the device.
 * It only supports device classes which may be involved in DR operations.
 */
acpidev_class_id_t
acpidev_dr_device_get_class(ACPI_HANDLE hdl)
{
	ACPI_OBJECT_TYPE type;
	ACPI_DEVICE_INFO *infop;
	acpidev_class_id_t id = ACPIDEV_CLASS_ID_INVALID;

	static char *acpidev_id_cpu[] = {
		ACPIDEV_HID_CPU,
	};
	static char *acpidev_id_mem[] = {
		ACPIDEV_HID_MEMORY,
	};
	static char *acpidev_id_mod[] = {
		ACPIDEV_HID_MODULE,
	};
	static char *acpidev_id_pci[] = {
		ACPIDEV_HID_PCI_HOSTBRIDGE,
	};
	static char *acpidev_id_pciex[] = {
		ACPIDEV_HID_PCIEX_HOSTBRIDGE,
	};

	/* Figure out device type by checking ACPI object type. */
	if (ACPI_FAILURE(AcpiGetType(hdl, &type))) {
		return (ACPIDEV_CLASS_ID_INVALID);
	} else if (type == ACPI_TYPE_PROCESSOR) {
		return (ACPIDEV_CLASS_ID_CPU);
	} else if (type != ACPI_TYPE_DEVICE) {
		return (ACPIDEV_CLASS_ID_INVALID);
	}

	if (ACPI_FAILURE(AcpiGetObjectInfo(hdl, &infop))) {
		return (ACPIDEV_CLASS_ID_INVALID);
	}

	/* Figure out device type by checking _HID and _CID. */
	if (acpidev_match_device_id(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_id_cpu))) {
		id = ACPIDEV_CLASS_ID_CPU;
	} else if (acpidev_match_device_id(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_id_mem))) {
		id = ACPIDEV_CLASS_ID_MEMORY;
	} else if (acpidev_match_device_id(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_id_mod))) {
		id = ACPIDEV_CLASS_ID_CONTAINER;
	} else if (acpidev_match_device_id(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_id_pciex))) {
		id = ACPIDEV_CLASS_ID_PCIEX;
	} else if (acpidev_match_device_id(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_id_pci))) {
		id = ACPIDEV_CLASS_ID_PCI;
	}

	AcpiOsFree(infop);

	return (id);
}

ACPI_STATUS
acpidev_dr_device_get_memory_index(ACPI_HANDLE hdl, uint32_t *idxp)
{
	acpidev_data_handle_t dhdl;

	ASSERT(idxp != NULL);
	ASSERT(hdl != NULL);

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle for %p.", hdl);
		return (AE_ERROR);
	} else if (dhdl->aod_class_id != ACPIDEV_CLASS_ID_MEMORY) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: object %p is not a memory device.", hdl);
		return (AE_ERROR);
	} else {
		*idxp = dhdl->aod_memidx;
	}

	return (AE_OK);
}

int
acpidev_dr_device_is_board(ACPI_HANDLE hdl)
{
	acpidev_data_handle_t dhdl;

	ASSERT(hdl != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_is_board().");
		return (0);
	}

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		return (0);
	} else if (!ACPIDEV_DR_IS_BOARD(dhdl)) {
		return (0);
	}

	return (1);
}

ACPI_STATUS
acpidev_dr_device_walk_edl(ACPI_HANDLE hdl,
    ACPI_WALK_CALLBACK cb, void *arg, void **retval)
{
	ACPI_STATUS rc = AE_OK;
	int i;
	char *objname;
	ACPI_OBJECT *obj;
	ACPI_BUFFER buf;
	char *method = ACPIDEV_METHOD_NAME_EDL;

	ASSERT(hdl != NULL);
	ASSERT(cb != NULL);
	if (hdl == NULL || cb == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_device_walk_edl().");
		return (AE_BAD_PARAMETER);
	}

	objname = acpidev_get_object_name(hdl);
	buf.Length = ACPI_ALLOCATE_BUFFER;
	rc = AcpiEvaluateObjectTyped(hdl, method, NULL, &buf,
	    ACPI_TYPE_PACKAGE);
	if (rc == AE_NOT_FOUND) {
		acpidev_free_object_name(objname);
		return (AE_OK);
	} else if (ACPI_FAILURE(rc)) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to evaluate method %s under %s.",
		    method, objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/* Validate the package structure. */
	obj = buf.Pointer;
	for (i = 0; i < obj->Package.Count; i++) {
		if (obj->Package.Elements[i].Type !=
		    ACPI_TYPE_LOCAL_REFERENCE) {
			cmn_err(CE_WARN, "!acpidev: element %d in package "
			    "returned by %s of %s is not local reference.",
			    i, method, objname);
			AcpiOsFree(buf.Pointer);
			acpidev_free_object_name(objname);
			return (AE_ERROR);
		} else if (obj->Package.Elements[i].Reference.ActualType !=
		    ACPI_TYPE_DEVICE) {
			cmn_err(CE_WARN, "!acpidev: element %d in package "
			    "returned by %s of %s doesn't refer to device.",
			    i, method, objname);
			AcpiOsFree(buf.Pointer);
			acpidev_free_object_name(objname);
			return (AE_ERROR);
		}
	}

	for (i = 0; i < obj->Package.Count; i++) {
		if (obj->Package.Elements[i].Reference.Handle == NULL) {
			cmn_err(CE_WARN, "!acpidev: handle of element %d in "
			    "package returned by %s of %s is NULL.",
			    i, method, objname);
			continue;
		}
		rc = (*cb)(obj->Package.Elements[i].Reference.Handle,
		    UINT32_MAX, arg, retval);
		if (rc == AE_CTRL_DEPTH || rc == AE_CTRL_TERMINATE) {
			rc = AE_OK;
		}
		if (ACPI_FAILURE(rc)) {
			break;
		}
	}

	AcpiOsFree(buf.Pointer);
	acpidev_free_object_name(objname);

	return (rc);
}

ACPI_STATUS
acpidev_dr_device_walk_ejd(ACPI_HANDLE hdl,
    ACPI_WALK_CALLBACK cb, void *arg, void **retval)
{
	ACPI_STATUS rc = AE_OK;
	char *objname;
	ACPI_OBJECT *obj;
	ACPI_BUFFER buf;
	ACPI_HANDLE chdl;
	char *method = ACPIDEV_METHOD_NAME_EJD;

	ASSERT(hdl != NULL);
	ASSERT(cb != NULL);
	if (hdl == NULL || cb == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_device_walk_ejd().");
		return (AE_BAD_PARAMETER);
	}

	objname = acpidev_get_object_name(hdl);
	buf.Length = ACPI_ALLOCATE_BUFFER;
	rc = AcpiEvaluateObjectTyped(hdl, method, NULL, &buf,
	    ACPI_TYPE_STRING);
	if (rc == AE_NOT_FOUND) {
		acpidev_free_object_name(objname);
		return (AE_OK);
	} else if (ACPI_FAILURE(rc)) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to evaluate method %s under %s.",
		    method, objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	obj = buf.Pointer;
	ASSERT(obj->String.Pointer);
	if (ACPI_FAILURE(AcpiGetHandle(NULL, obj->String.Pointer, &chdl))) {
		cmn_err(CE_WARN, "!acpidev: failed to get handle for %s.",
		    obj->String.Pointer);
		rc = AE_ERROR;
	} else {
		rc = (*cb)(chdl, UINT32_MAX, arg, retval);
		if (rc == AE_CTRL_DEPTH || rc == AE_CTRL_TERMINATE) {
			rc = AE_OK;
		}
	}

	AcpiOsFree(buf.Pointer);
	acpidev_free_object_name(objname);

	return (rc);
}

/*
 * Walk all child devices and special devices in the eject device list.
 */
static ACPI_STATUS
acpidev_dr_device_walk_child(ACPI_HANDLE hdl, boolean_t init, uint_t max_lvl,
    ACPI_WALK_CALLBACK cb, void *arg, void **retval)
{
	ACPI_STATUS rc = AE_OK;

	ASSERT(hdl != NULL);
	ASSERT(cb != NULL);
	if (hdl == NULL || cb == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_device_walk_child().");
		return (AE_BAD_PARAMETER);
	}

	/*
	 * Walk the eject device list first when destroying.
	 * According to ACPI spec, devices in _EDL list must be handled first
	 * when the ejecting device.
	 */
	if (init == B_FALSE) {
		rc = acpidev_dr_device_walk_edl(hdl, cb, arg, retval);
		if (ACPI_FAILURE(rc)) {
			ACPIDEV_DEBUG(CE_NOTE,
			    "!acpidev: failed to walk eject device list in "
			    "acpidev_dr_device_walk_child().");
		}
	}

	/* Walk all child ACPI DEVICE objects. */
	if (ACPI_SUCCESS(rc)) {
		rc = AcpiWalkNamespace(ACPI_TYPE_DEVICE, hdl,
		    max_lvl, cb, NULL, arg, retval);
		if (ACPI_FAILURE(rc)) {
			ACPIDEV_DEBUG(CE_NOTE,
			    "!acpidev: failed to walk DEVICE objects in "
			    "acpidev_dr_device_walk_child().");
		}
	}

	/* Walk all child ACPI PROCESSOR objects. */
	if (ACPI_SUCCESS(rc)) {
		rc = AcpiWalkNamespace(ACPI_TYPE_PROCESSOR, hdl,
		    max_lvl, cb, NULL, arg, retval);
		if (ACPI_FAILURE(rc)) {
			ACPIDEV_DEBUG(CE_NOTE,
			    "!acpidev: failed to walk PROCESSOR objects in "
			    "acpidev_dr_device_walk_child().");
		}
	}

	/*
	 * Walk the eject device list last when initializing.
	 */
	if (init == B_TRUE && ACPI_SUCCESS(rc)) {
		rc = acpidev_dr_device_walk_edl(hdl, cb, arg, retval);
		if (ACPI_FAILURE(rc)) {
			ACPIDEV_DEBUG(CE_NOTE,
			    "!acpidev: failed to walk eject device list in "
			    "acpidev_dr_device_walk_child().");
		}
	}

	return (rc);
}

ACPI_STATUS
acpidev_dr_device_walk_device(ACPI_HANDLE hdl, uint_t max_lvl,
    ACPI_WALK_CALLBACK cb, void *arg, void **retval)
{
	ACPI_STATUS rc = AE_OK;
	char *objname;

	ASSERT(hdl != NULL);
	ASSERT(cb != NULL);
	if (hdl == NULL || cb == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter to "
		    "acpidev_dr_walk_device().");
		return (AE_BAD_PARAMETER);
	}

	/* Walk the top object itself first. */
	rc = (*cb)(hdl, 0, arg, retval);
	if (rc == AE_CTRL_DEPTH || rc == AE_CTRL_TERMINATE) {
		rc = AE_OK;
	} else if (ACPI_FAILURE(rc)) {
		objname = acpidev_get_object_name(hdl);
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to handle top node %s "
		    "in acpidev_dr_walk_device().", objname);
		acpidev_free_object_name(objname);
	} else {
		rc = acpidev_dr_device_walk_child(hdl, B_TRUE, max_lvl,
		    cb, arg, retval);
		if (ACPI_FAILURE(rc)) {
			objname = acpidev_get_object_name(hdl);
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to handle descendant nodes of %s "
			    "in acpidev_dr_walk_device().", objname);
			acpidev_free_object_name(objname);
		}
	}

	return (rc);
}

static ACPI_STATUS
acpidev_dr_no_support(ACPI_HANDLE hdl, UINT32 lvl, void *arg, void **retval)
{
	_NOTE(ARGUNUSED(arg, retval));

	char *objname;

	ASSERT(hdl != NULL);

	objname = acpidev_get_object_name(hdl);
	ACPIDEV_DEBUG(CE_NOTE,
	    "!acpidev: device %s at level 0x%x is unsupported.",
	    objname, lvl);
	acpidev_free_object_name(objname);

	return (AE_SUPPORT);
}

static ACPI_STATUS
acpidev_dr_set_prop(ACPI_HANDLE hdl, char *objname,
    struct acpidev_dr_set_prop_arg *ap, uint32_t lvl,
    acpidev_class_id_t clsid, uint_t *devid)
{
	acpidev_data_handle_t dhdl;

	/* Create data handle first if it doesn't exist yet. */
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		uint32_t rlvl;
		ACPI_HANDLE phdl;

		/*
		 * Compute level by walking ACPI namespace if it's a device
		 * from the eject device list.
		 */
		if (lvl == UINT32_MAX) {
			/*
			 * AcpiGetParent() fails when it tries to get
			 * the parent of the ACPI namespace root node.
			 */
			for (rlvl = 0, phdl = hdl;
			    ACPI_SUCCESS(AcpiGetParent(phdl, &phdl));
			    rlvl++) {
				if (phdl == ACPI_ROOT_OBJECT) {
					break;
				}
			}
			if (rlvl == 0) {
				ACPIDEV_DEBUG(CE_WARN,
				    "!acpidev: failed to get level of %s.",
				    objname);
				return (AE_BAD_PARAMETER);
			}
		} else {
			rlvl = ap->level;
		}
		if (rlvl >= ACPIDEV_MAX_ENUM_LEVELS) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: recursive level of %s is too deep.",
			    objname);
			return (AE_SUPPORT);
		}

		dhdl = acpidev_data_create_handle(hdl);
		if (dhdl != NULL) {
			dhdl->aod_hdl = hdl;
			dhdl->aod_level = rlvl;
		}
	}

	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to create data handle "
		    "for device %s.", objname);
		return (AE_NO_MEMORY);
	}

	if (ACPIDEV_DR_IS_READY(dhdl)) {
		/*
		 * The same device may be enumerated twice at most. Once as
		 * child devices, another time from the eject device list.
		 */
		if (dhdl->aod_bdnum == ap->bdnum) {
			return (AE_OK);
		} else {
			/*
			 * A device has been enumerated more than once from
			 * different paths. It's dangerous to support such
			 * a topology. Disable support of DR operations.
			 */
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: device %s has been "
			    "enumerated more than once for DR.", objname);
			acpidev_dr_failed = 1;
			return (AE_SUPPORT);
		}
	}

	/* Set properties for DR operations. */
	dhdl->aod_class_id = clsid;
	dhdl->aod_bdnum = ap->bdnum;
	dhdl->aod_portid = atomic_inc_32_nv(devid) - 1;
	if (clsid == ACPIDEV_CLASS_ID_MEMORY) {
		dhdl->aod_memidx = acpidev_dr_memory_device_cnt;
		ASSERT(dhdl->aod_memidx < ACPI_MEMNODE_DEVID_BOOT);
	}
	ACPIDEV_DR_SET_READY(dhdl);

	return (AE_OK);
}

/*
 * Verify whether the hardware topology is supported by the DR driver.
 * The ACPI specification is so flexible that for safety reasons, only
 * a few well defined topologies are supported.
 * Possible values of parameter lvl:
 * 0:		the device is the board itself.
 * UINT32_MAX:	the device is from the _EDL list of the board.
 * other:	the device is a descendant of the board.
 * Return values:
 * AE_OK: the topology is supported
 * AE_SUPPORT: the topology is unsupported
 * AE_ERROR: other errors
 */
static ACPI_STATUS
acpidev_dr_scan_topo(ACPI_HANDLE hdl, UINT32 lvl, void *arg, void **retval)
{
	_NOTE(ARGUNUSED(retval));

	ACPI_STATUS rc = AE_OK;
	char *objname;
	acpidev_class_id_t cid;
	struct acpidev_dr_set_prop_arg *ap = arg;

	ASSERT(hdl != NULL);
	ASSERT(lvl == 0 || lvl == 1 || lvl == UINT32_MAX);
	objname = acpidev_get_object_name(hdl);

	/*
	 * Validate descendants of the hotplug capable board.
	 * lvl is zero if it's the hotplug capable board itself, otherwise
	 * non-zero for descendants.
	 */
	if (lvl != 0) {
		/*
		 * Skip subtree if the device is hotplug capable.
		 * It will be treated as another hotplug capable board.
		 */
		if (acpidev_dr_device_hotplug_capable(hdl)) {
			acpidev_free_object_name(objname);
			return (AE_CTRL_DEPTH);
		}

		/*
		 * Don't support the _EDL list of a non-hotplug-capable device.
		 */
		if (acpidev_dr_device_has_edl(hdl)) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: non-hotplug-capable "
			    "object %s has _EDL method.", objname);
			acpidev_free_object_name(objname);
			return (AE_SUPPORT);
		}
	}

	cid = acpidev_dr_device_get_class(hdl);
	switch (cid) {
	case ACPIDEV_CLASS_ID_CPU:
		/* Don't support logical CPUs in the _EDL list. */
		if (lvl == UINT32_MAX) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: logical CPU %s in "
			    "_EDL is unsupported.", objname);
			rc = AE_SUPPORT;
			break;
		}

		/* Don't support logical CPUs with children. */
		ap->level++;
		rc = acpidev_dr_device_walk_child(hdl, B_TRUE, 1,
		    acpidev_dr_no_support, arg, NULL);
		ap->level--;
		if (rc == AE_SUPPORT) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: logical CPU %s has "
			    "child or dependent devices.", objname);
			break;
		} else if (ACPI_FAILURE(rc)) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to scan "
			    "children of logical CPU %s.", objname);
			rc = AE_ERROR;
			break;
		} else if (ap != NULL) {
			rc = acpidev_dr_set_prop(hdl, objname, ap, lvl,
			    ACPIDEV_CLASS_ID_CPU, &ap->cpu_id);
		}
		break;

	case ACPIDEV_CLASS_ID_MEMORY:
		/* Don't support memory devices with children. */
		ap->level++;
		rc = acpidev_dr_device_walk_child(hdl, B_TRUE, 1,
		    acpidev_dr_no_support, arg, NULL);
		ap->level--;
		if (rc == AE_SUPPORT) {
			ACPIDEV_DEBUG(CE_NOTE,
			    "!acpidev: memory device %s has child or "
			    "dependent devices.", objname);
		} else if (ACPI_FAILURE(rc)) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to scan children of "
			    "memory device %s.", objname);
			rc = AE_ERROR;
		} else if (ap != NULL) {
			acpidev_dr_memory_device_cnt++;
			rc = acpidev_dr_set_prop(hdl, objname, ap, lvl,
			    ACPIDEV_CLASS_ID_MEMORY, &ap->mem_id);
		}
		break;

	case ACPIDEV_CLASS_ID_PCI:
	case ACPIDEV_CLASS_ID_PCIEX:
		/* Don't scan child/descendant devices of PCI/PCIex devices. */
		if (ap != NULL) {
			rc = acpidev_dr_set_prop(hdl, objname, ap, lvl,
			    cid, &ap->io_id);
		}
		break;

	case ACPIDEV_CLASS_ID_CONTAINER:
		/* Don't support module devices in the _EDL list. */
		if (lvl == UINT32_MAX) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: module device %s in "
			    "_EDL is unsupported.", objname);
			rc = AE_SUPPORT;
			break;
		}

		/* Don't support recurrence of module devices. */
		if (lvl > 0) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: recursion level of "
			    "module device %s is too deep.", objname);
			rc = AE_SUPPORT;
			break;
		}

		ap->level++;
		rc = acpidev_dr_device_walk_child(hdl, B_TRUE, 1,
		    acpidev_dr_scan_topo, arg, NULL);
		ap->level--;
		if (ACPI_SUCCESS(rc) && ap != NULL) {
			rc = acpidev_dr_set_prop(hdl, objname, ap, lvl,
			    ACPIDEV_CLASS_ID_CONTAINER, &ap->mod_id);
		}
		break;

	case ACPIDEV_CLASS_ID_INVALID:
		/*FALLTHROUGH*/
	default:
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: device %s is unsupported.", objname);
		rc = AE_SUPPORT;
		break;
	}

	acpidev_free_object_name(objname);

	return (rc);
}

/* Create walk information structures. */
static ACPI_STATUS
acpidev_dr_create_walk_info(ACPI_HANDLE hdl, acpidev_data_handle_t dhdl,
    char *objname, acpidev_walk_info_t **infopp, acpidev_walk_info_t **cinfopp)
{
	ACPI_HANDLE phdl = NULL;
	dev_info_t *pdip = NULL;
	acpidev_data_handle_t pdhdl, tdhdl;
	acpidev_walk_info_t *infop = NULL, *cinfop = NULL;

	ASSERT(hdl != NULL);
	ASSERT(dhdl != NULL);
	ASSERT(dhdl->aod_class_list != NULL);
	ASSERT(objname != NULL);
	ASSERT(infopp != NULL);
	ASSERT(cinfopp != NULL);

	if (ACPI_FAILURE(AcpiGetParent(hdl, &phdl))) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to get parent object of %s.", objname);
		return (AE_ERROR);
	}

	pdhdl = acpidev_data_get_handle(phdl);
	if (pdhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get data "
		    "associated with parent of %s.", objname);
		return (AE_ERROR);
	}
	if (pdhdl->aod_level >= ACPIDEV_MAX_ENUM_LEVELS - 1) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: recursion level (%d) of %s is too deep.",
		    pdhdl->aod_level, objname);
		return (AE_ERROR);
	}
	ASSERT(pdhdl->aod_class_list != NULL);
	if (pdhdl->aod_class_list == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: class list for parent of %s is NULL.", objname);
		return (AE_ERROR);
	}

	/* Allocate a walk info structure for its parent. */
	infop = acpidev_alloc_walk_info(ACPIDEV_OP_HOTPLUG_PROBE,
	    pdhdl->aod_level, phdl, dhdl->aod_class_list, NULL);
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to allocate walk info "
		    "structure for parent of %s.", objname);
		return (AE_ERROR);
	}

	/* Get the parent dip if it's not ready yet. */
	while (infop->awi_dip == NULL) {
		if (ACPI_FAILURE(AcpiGetParent(phdl, &phdl))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to get parent of object %p.",
			    phdl);
			break;
		}
		tdhdl = acpidev_data_get_handle(phdl);
		if (tdhdl == NULL) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get data "
			    "associated with object %p.", phdl);
			break;
		}
		pdip = acpidev_data_get_devinfo(tdhdl);
		if (pdip != NULL) {
			infop->awi_dip = pdip;
			break;
		}
		/* Give up if reaches the ACPI namespace root node. */
		if (phdl == ACPI_ROOT_OBJECT) {
			break;
		}
	}
	if (infop->awi_dip == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get parent dip of %s.", objname);
		acpidev_free_walk_info(infop);
		return (AE_ERROR);
	}

	/* Allocate a walk info for the child. */
	cinfop = acpidev_alloc_walk_info(ACPIDEV_OP_HOTPLUG_PROBE,
	    infop->awi_level + 1, hdl, NULL, infop);
	if (cinfop == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to allocate walk info "
		    "structure for %s.", objname);
		acpidev_free_walk_info(infop);
		return (AE_ERROR);
	}

	*infopp = infop;
	*cinfopp = cinfop;

	return (AE_OK);
}

static ACPI_STATUS
acpidev_dr_probe_object(ACPI_HANDLE hdl, acpidev_data_handle_t dhdl)
{
	ACPI_STATUS rc = AE_OK;
	char *objname;
	dev_info_t *pdip;
	ACPI_STATUS res;
	ACPI_OBJECT_TYPE type;
	acpidev_class_list_t *it;
	acpidev_walk_info_t *infop, *cinfop;

	ASSERT(hdl != NULL);
	ASSERT(dhdl != NULL);
	if (hdl == NULL || dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: hdl or dhdl is NULL in "
		    "acpidev_dr_probe_object().");
		return (AE_BAD_PARAMETER);
	}
	objname = acpidev_get_object_name(hdl);

	/* Check whether the device is of interest. */
	if (ACPI_FAILURE(AcpiGetType(hdl, &type)) ||
	    type > ACPI_TYPE_NS_NODE_MAX ||
	    BT_TEST(acpidev_object_type_mask, type) == 0) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: ACPI object %s is unsupported.", objname);
		acpidev_free_object_name(objname);
		return (AE_SUPPORT);
	}

	if (dhdl->aod_class_list == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: class list is NULL in data associated with %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	pdip = NULL;
	infop = NULL;
	cinfop = NULL;
	rc = acpidev_dr_create_walk_info(hdl, dhdl, objname, &infop, &cinfop);
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to create walk info structures for %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (rc);
	}
	ASSERT(infop != NULL);
	ASSERT(infop->awi_dip != NULL);
	ASSERT(infop->awi_class_list != NULL);
	ASSERT(cinfop != NULL);
	ASSERT(cinfop->awi_data == dhdl);

	/* Lock the parent dip before touching children. */
	pdip = infop->awi_dip;
	ndi_devi_enter(pdip);
	rw_enter(&acpidev_class_lock, RW_READER);

	/* Call pre-probe callback functions to prepare for probing. */
	for (it = *(infop->awi_class_list); it != NULL; it = it->acl_next) {
		if (it->acl_class->adc_pre_probe == NULL) {
			continue;
		}
		infop->awi_class_curr = it->acl_class;
		if (ACPI_FAILURE(it->acl_class->adc_pre_probe(infop))) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: failed to pre-probe "
			    "device of type %s under %s.",
			    it->acl_class->adc_class_name, infop->awi_name);
		}
	}

	/* Call registered probe callback functions to probe devices. */
	for (it = *(infop->awi_class_list); it != NULL; it = it->acl_next) {
		if (it->acl_class->adc_probe == NULL) {
			continue;
		}
		cinfop->awi_class_curr = it->acl_class;
		res = it->acl_class->adc_probe(cinfop);
		if (ACPI_FAILURE(res)) {
			rc = res;
			ACPIDEV_DEBUG(CE_NOTE,
			    "!acpidev: failed to process object %s under %s.",
			    objname, infop->awi_name);
		}
	}

	/* Call post-probe callback functions to clean up. */
	for (it = *(infop->awi_class_list); it != NULL; it = it->acl_next) {
		if (it->acl_class->adc_post_probe == NULL) {
			continue;
		}
		infop->awi_class_curr = it->acl_class;
		if (ACPI_FAILURE(it->acl_class->adc_post_probe(infop))) {
			ACPIDEV_DEBUG(CE_NOTE, "!acpidev: failed to post-probe "
			    "device of type %s under %s.",
			    it->acl_class->adc_class_name, infop->awi_name);
		}
	}

	rw_exit(&acpidev_class_lock);
	ndi_devi_exit(pdip);

	acpidev_free_walk_info(cinfop);
	acpidev_free_walk_info(infop);
	acpidev_free_object_name(objname);

	return (rc);
}

/*
 * Some PCI/PCIex buses embedded in physical processors may be presented in
 * the eject device list instead of being presented as child devices.
 * This function figures out such devices and create device nodes for them.
 */
static ACPI_STATUS
acpidev_dr_probe_dependent(ACPI_HANDLE hdl, UINT32 lvl, void *ctx,
    void **retval)
{
	_NOTE(ARGUNUSED(retval));

	ACPI_STATUS rc = AE_OK;
	int status;
	char *objname;
	ACPI_HANDLE phdl, thdl;
	acpidev_data_handle_t dhdl;

	ASSERT(lvl == UINT32_MAX);
	ASSERT(hdl != NULL);
	ASSERT(ctx != NULL);
	phdl = ctx;
	objname = acpidev_get_object_name(hdl);

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data associated with %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/*
	 * It should be treated as another board if device is hotplug capable.
	 */
	if (ACPIDEV_DR_IS_BOARD(dhdl)) {
		acpidev_free_object_name(objname);
		return (AE_OK);
	} else if (!ACPIDEV_DR_IS_WORKING(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: %s is unusable for DR operations.", objname);
		acpidev_free_object_name(objname);
		return (AE_SUPPORT);
	}

	/*
	 * Skip hdl if it's a descendant of phdl because it should have
	 * already been handled when handling phdl itself.
	 */
	for (thdl = hdl; ACPI_SUCCESS(AcpiGetParent(thdl, &thdl)); ) {
		/* Return when reaches the phdl. */
		if (thdl == phdl) {
			acpidev_free_object_name(objname);
			return (AE_OK);
		}
		/* Break out when reaches the ACPI namespace root node. */
		if (thdl == ACPI_ROOT_OBJECT) {
			break;
		}
	}

	/*
	 * No support of enumerating PCI/PCIex Host Bridge devices yet.
	 * It will be enabled when PCI/PCIex Host Bridge hotplug is ready.
	 */
	if (dhdl->aod_class_id == ACPIDEV_CLASS_ID_PCI ||
	    dhdl->aod_class_id == ACPIDEV_CLASS_ID_PCIEX) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: PCI/PCIEX host bridge %s is "
		    "unsupported, skip it.", objname);
		acpidev_free_object_name(objname);
		return (AE_OK);
	}

	/* Check whether the device exists and has been enabled. */
	status = acpidev_query_device_status(hdl);
	if (!acpidev_check_device_enabled(status)) {
		ACPIDEV_DEBUG(CE_NOTE, "!acpidev: object %s is disabled/absent "
		    "when trying to connect it.", objname);
		acpidev_free_object_name(objname);
		return (AE_OK);
	}

	/* Probe the device and its children. */
	rc = acpidev_dr_probe_object(hdl, dhdl);
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to probe object %s in eject device list.",
		    objname);
		return (rc);
	}

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_device_insert(ACPI_HANDLE hdl)
{
	ACPI_STATUS rc = AE_OK;
	int status;
	char *objname;
	dev_info_t *dip;
	acpidev_data_handle_t dhdl;

	ASSERT(acpidev_root_node() != NULL);
	ASSERT(hdl != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: parameter hdl to "
		    "acpidev_dr_insert_insert() is NULL.");
		return (AE_BAD_PARAMETER);
	}

	objname = acpidev_get_object_name(hdl);
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle associated with %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/* Validate that the object is hotplug capable. */
	if (!ACPIDEV_DR_BOARD_READY(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: object %s is not hotplug capable.", objname);
		acpidev_free_object_name(objname);
		return (AE_SUPPORT);
	} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %s is in the FAILED "
		    "state, unusable for DR.", objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/* Check whether the device exists and has been enabled. */
	status = acpidev_query_device_status(hdl);
	if (!acpidev_check_device_enabled(status)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %s is disabled/absent "
		    "when trying to connect it.", objname);
		acpidev_free_object_name(objname);
		return (AE_NOT_EXIST);
	}

	/* Check that there's no device node created for object yet. */
	dip = acpidev_data_get_devinfo(dhdl);
	if (dip != NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: device node for object %s "
		    "already exists when trying to connect it.", objname);
		acpidev_free_object_name(objname);
		return (AE_ALREADY_EXISTS);
	}

	/*
	 * Solaris has a limitation that all device nodes for PCI/PCIex host
	 * bridges must exist directly under /devices.
	 * Special care is needed here to deal with hot-adding PCI/PCIex host
	 * bridges to avoid dead lock caused by ndi_devi_enter().
	 * Here the lock on ddi_root_node() is held first, which will break
	 * the dead lock loop.
	 */
	ndi_devi_enter(ddi_root_node());

	rc = acpidev_dr_probe_object(hdl, dhdl);
	if (ACPI_SUCCESS(rc)) {
		rc = acpidev_dr_device_walk_edl(hdl,
		    &acpidev_dr_probe_dependent, hdl, NULL);
	}
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to create device "
		    "nodes for children of %s.", objname);
		cmn_err(CE_WARN, "!acpidev: disable DR support for object %s "
		    "due to failure when creating device nodes for it.",
		    objname);
		ACPIDEV_DR_SET_FAILED(dhdl);
	}

	ndi_devi_exit(ddi_root_node());
	acpidev_free_object_name(objname);

	return (rc);
}

static ACPI_STATUS
acpidev_dr_device_remove_cb(ACPI_HANDLE hdl, UINT32 lvl, void *ctx,
    void **retval)
{
	_NOTE(ARGUNUSED(lvl));

	ACPI_STATUS rc = AE_OK;
	int status;
	char *objname;
	dev_info_t *dip;
	acpidev_data_handle_t dhdl;
	struct acpidev_dr_device_remove_arg *argp;

	ASSERT(hdl != NULL && ctx != NULL);
	if (hdl == NULL || ctx == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: parameter to "
		    "acpidev_dr_device_remove_cb() is NULL.");
		return (AE_BAD_PARAMETER);
	}

	argp = (struct acpidev_dr_device_remove_arg *)ctx;
	objname = acpidev_get_object_name(hdl);
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle associated with %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/* Validate that the object is hotplug capable. */
	/* It's the hotplug capable board itself if level is zero. */
	if (argp->level == 0) {
		if (!ACPIDEV_DR_BOARD_READY(dhdl)) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: object %s is not hotplug capable.",
			    objname);
			acpidev_free_object_name(objname);
			return (AE_SUPPORT);
		} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: object %s is unusable for DR.", objname);
			acpidev_free_object_name(objname);
			return (AE_SUPPORT);
		}
	} else {
		/* It's a device under the hotplug capable board. */
		/*
		 * Skip it if device itself is hotplug capable.
		 * It will be treated as another hotplug capable board.
		 */
		if (ACPIDEV_DR_IS_BOARD(dhdl)) {
			acpidev_free_object_name(objname);
			return (AE_OK);
		}

		if (!ACPIDEV_DR_IS_READY(dhdl)) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: object %s is not hotplug capable.",
			    objname);
			acpidev_free_object_name(objname);
			return (AE_SUPPORT);
		} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: object %s is unusable for DR.", objname);
			acpidev_free_object_name(objname);
			return (AE_SUPPORT);
		}
	}

	/* Skip the device if it hasn't been enabled at all. */
	status = acpidev_data_get_status(dhdl);
	if (!acpidev_check_device_enabled(status)) {
		acpidev_free_object_name(objname);
		return (AE_OK);
	}

	dip = acpidev_data_get_devinfo(dhdl);
	if (dip == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get dev_info associated with %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (AE_SUPPORT);
	}

	/* For safety, only handle supported device types when unconfiguring. */
	switch (dhdl->aod_class_id) {
	case ACPIDEV_CLASS_ID_CONTAINER:
		/*FALLTHROUGH*/
	case ACPIDEV_CLASS_ID_CPU:
		/*FALLTHROUGH*/
	case ACPIDEV_CLASS_ID_MEMORY:
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %s (type %d) doesn't "
		    "support unconfiguration.", objname, dhdl->aod_class_id);
		acpidev_free_object_name(objname);
		return (AE_SUPPORT);
	}

	/* Destroy descendants first. */
	argp->level++;
	rc = acpidev_dr_device_walk_child(hdl, B_FALSE, 1,
	    acpidev_dr_device_remove_cb, ctx, retval);
	argp->level--;
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to destroy descendants of %s.", objname);
		acpidev_free_object_name(objname);
		return (rc);
	}

	/* Untag dip and ACPI object before destroying the dip. */
	if ((dhdl->aod_iflag & ACPIDEV_ODF_DEVINFO_TAGGED) &&
	    ACPI_FAILURE(acpica_untag_devinfo(dip, hdl))) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to untag object %s.", objname);
		/* Mark the node as unusable. */
		ACPIDEV_DR_SET_FAILED(dhdl);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/* Destroy the node itself. */
	if (e_ddi_branch_destroy(dip, NULL, 0) != 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if ((dhdl->aod_iflag & ACPIDEV_ODF_DEVINFO_TAGGED) &&
		    ACPI_FAILURE(acpica_tag_devinfo(dip, hdl))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to retag object %s.", objname);
		}

		/* Mark the node as unusable. */
		ACPIDEV_DR_SET_FAILED(dhdl);

		(void) ddi_pathname(dip, path);
		cmn_err(CE_WARN,
		    "acpidev: failed to remove node %s (%s).", path, objname);
		kmem_free(path, MAXPATHLEN);
		acpidev_free_object_name(objname);

		return (AE_ERROR);
	}

	/* Update status and information associated with the device. */
	dhdl->aod_dip = NULL;
	dhdl->aod_iflag &= ~ACPIDEV_ODF_DEVINFO_CREATED;
	dhdl->aod_iflag &= ~ACPIDEV_ODF_DEVINFO_TAGGED;
	if (dhdl->aod_class != NULL) {
		if (dhdl->aod_class->adc_fini != NULL) {
			(*(dhdl->aod_class->adc_fini))(hdl, dhdl,
			    dhdl->aod_class);
		}
		atomic_dec_32(&(dhdl->aod_class->adc_refcnt));
		dhdl->aod_class = NULL;
	}
	dhdl->aod_iflag &= ~ACPIDEV_ODF_STATUS_VALID;
	dhdl->aod_status = 0;

	acpidev_free_object_name(objname);

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_device_remove(ACPI_HANDLE hdl)
{
	ACPI_STATUS rc = AE_OK;
	char *objname;
	acpidev_data_handle_t dhdl;
	struct acpidev_dr_device_remove_arg arg;

	ASSERT(acpidev_root_node() != NULL);
	ASSERT(hdl != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: parameter hdl to "
		    "acpidev_dr_device_remove() is NULL.");
		return (AE_BAD_PARAMETER);
	}

	objname = acpidev_get_object_name(hdl);
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle associated with %s.",
		    objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/* Validate that the device is hotplug capable. */
	if (!ACPIDEV_DR_BOARD_READY(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: object %s is not hotplug capable.", objname);
		acpidev_free_object_name(objname);
		return (AE_SUPPORT);
	} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %s is in the FAILED "
		    "state, unusable for DR.", objname);
		acpidev_free_object_name(objname);
		return (AE_ERROR);
	}

	/*
	 * Recursively destroy descendants under the top node.
	 * No need to undo what has been done if error happens, it will be
	 * handled by DR driver.
	 */
	/*
	 * Lock ddi_root_node() to avoid deadlock.
	 */
	ndi_devi_enter(ddi_root_node());

	arg.level = 0;
	rc = acpidev_dr_device_remove_cb(hdl, 0, &arg, NULL);
	ASSERT(arg.level == 0);
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to destroy device "
		    "nodes for children of %s.", objname);
		cmn_err(CE_WARN, "!acpidev: disable DR support for object %s "
		    "due to failure when destroying device nodes for it.",
		    objname);
		ACPIDEV_DR_SET_FAILED(dhdl);
	}

	ndi_devi_exit(ddi_root_node());
	acpidev_free_object_name(objname);

	return (rc);
}

ACPI_STATUS
acpidev_dr_device_poweron(ACPI_HANDLE hdl)
{
	acpidev_data_handle_t dhdl;

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle associated with %p.",
		    hdl);
		return (AE_ERROR);
	}

	/* Check whether the device is hotplug capable. */
	if (!ACPIDEV_DR_BOARD_READY(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: object %p is not hotplug capable.", hdl);
		return (AE_SUPPORT);
	} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %p is in the FAILED "
		    "state, unusable for DR.", hdl);
		return (AE_ERROR);
	}

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_device_poweroff(ACPI_HANDLE hdl)
{
	ACPI_STATUS rc;
	acpidev_data_handle_t dhdl;

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle associated with %p.",
		    hdl);
		return (AE_ERROR);
	}

	/* Check whether the device is hotplug capable. */
	if (!ACPIDEV_DR_BOARD_READY(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: object %p is not hotplug capable.", hdl);
		return (AE_SUPPORT);
	} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %p is in the FAILED "
		    "state, unusable for DR.", hdl);
		return (AE_ERROR);
	}

	rc = acpidev_eval_ej0(hdl);
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to evaluate _EJ0 for object %p.", hdl);
	}

	return (rc);
}

ACPI_STATUS
acpidev_dr_device_check_status(ACPI_HANDLE hdl)
{
	acpidev_data_handle_t dhdl;

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data handle associated with %p.",
		    hdl);
		return (AE_ERROR);
	}

	/* Check whether the device is hotplug capable. */
	if (!ACPIDEV_DR_BOARD_READY(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: object %p is not hotplug capable.", hdl);
		return (AE_SUPPORT);
	} else if (ACPIDEV_DR_IS_FAILED(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: object %p is in the FAILED "
		    "state, unusable for DR.", hdl);
		return (AE_ERROR);
	}

	return (AE_OK);
}

void
acpidev_dr_lock_all(void)
{
	mutex_enter(&acpidev_dr_lock);
}

void
acpidev_dr_unlock_all(void)
{
	mutex_exit(&acpidev_dr_lock);
}

ACPI_STATUS
acpidev_dr_allocate_cpuid(ACPI_HANDLE hdl, processorid_t *idp)
{
	int rv;
	processorid_t cpuid;
	uint32_t procid, apicid;
	mach_cpu_add_arg_t arg;
	acpidev_data_handle_t dhdl;
	dev_info_t *dip = NULL;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(hdl != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: parameter hdl to "
		    "acpidev_dr_allocate_cpuid() is NULL.");
		return (AE_BAD_PARAMETER);
	}

	/* Validate that the device is ready for hotplug. */
	if (ACPI_FAILURE(acpica_get_devinfo(hdl, &dip))) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get devinfo for object %p.", hdl);
		return (AE_ERROR);
	}
	ASSERT(dip != NULL);
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get data associated with object %p",
		    hdl);
		return (AE_SUPPORT);
	}
	if (!ACPIDEV_DR_IS_READY(dhdl)) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: dip %p is not hotplug ready.", (void *)dip);
		return (AE_SUPPORT);
	}
	if (ACPIDEV_DR_IS_FAILED(dhdl)) {
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: dip %p is in the FAILED state.", (void *)dip);
		return (AE_SUPPORT);
	}

	/* Query CPU relative information */
	apicid = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, ACPIDEV_PROP_NAME_LOCALAPIC_ID, UINT32_MAX);
	procid = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, ACPIDEV_PROP_NAME_PROCESSOR_ID, UINT32_MAX);
	if (procid == UINT32_MAX || apicid == UINT32_MAX || apicid == 255) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: dip %p is malformed, "
		    "procid(0x%x) or apicid(0x%x) is invalid.",
		    (void *)dip, procid, apicid);
		return (AE_ERROR);
	}

	/* Check whether the CPU device is in offline state. */
	mutex_enter(&(DEVI(dip)->devi_lock));
	if (!DEVI_IS_DEVICE_OFFLINE(dip)) {
		mutex_exit(&DEVI(dip)->devi_lock);
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: dip %p isn't in offline state.", (void *)dip);
		return (AE_ERROR);
	}
	mutex_exit(&DEVI(dip)->devi_lock);

	/* Check whether the CPU already exists. */
	if (ACPI_SUCCESS(acpica_get_cpu_id_by_object(hdl, &cpuid))) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: dip %p already has CPU id(%d) assigned.",
		    (void *)dip, cpuid);
		return (AE_ALREADY_EXISTS);
	}

	/* Allocate cpuid for the CPU */
	arg.arg.apic.apic_id = apicid;
	arg.arg.apic.proc_id = procid;
	if (apicid >= 255) {
		arg.type = MACH_CPU_ARG_LOCAL_X2APIC;
	} else {
		arg.type = MACH_CPU_ARG_LOCAL_APIC;
	}
	rv = mach_cpu_add(&arg, &cpuid);
	if (rv != PSM_SUCCESS) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to allocate cpu id for dip %p.",
		    (void *)dip);
		return (AE_NOT_EXIST);
	}

	ASSERT(cpuid >= 0 && cpuid < NCPU && cpuid < max_ncpus);
	if (idp != NULL) {
		*idp = cpuid;
	}

	return (AE_OK);
}

ACPI_STATUS
acpidev_dr_free_cpuid(ACPI_HANDLE hdl)
{
	ACPI_STATUS rv = AE_OK;
	processorid_t cpuid;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(hdl != NULL);
	if (hdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: parameter hdl to "
		    "acpidev_dr_free_cpuid() is NULL.");
		return (AE_BAD_PARAMETER);
	}

	if (ACPI_FAILURE(acpica_get_cpu_id_by_object(hdl, &cpuid))) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to get cpuid for object %p.", hdl);
		rv = AE_NOT_EXIST;
	} else if (cpuid < 0 || cpuid > max_ncpus) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: cpuid(%d) of object %p is invalid.",
		    cpuid, hdl);
		rv = AE_ERROR;
	} else if (mach_cpu_remove(cpuid) != PSM_SUCCESS) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to free cpuid(%d) for object %p.",
		    cpuid, hdl);
		rv = AE_ERROR;
	}

	return (rv);
}

static ACPI_STATUS
acpidev_dr_get_latency(ACPI_HANDLE hdl, void **hdlpp,
    uint32_t pxmid, uint32_t *slicntp, uchar_t **slipp)
{
	ACPI_STATUS rc;
	ACPI_BUFFER buf;
	uint32_t i, pxmcnt;
	uchar_t *valp, *sp, *ep;

	/* Evaluate the ACPI _SLI method under the object. */
	buf.Length = ACPI_ALLOCATE_BUFFER;
	rc = AcpiEvaluateObjectTyped(hdl, ACPIDEV_METHOD_NAME_SLI, NULL, &buf,
	    ACPI_TYPE_BUFFER);
	if (ACPI_SUCCESS(rc)) {
		valp = (uchar_t *)buf.Pointer;
		if (acpidev_slit_tbl_ptr->LocalityCount > pxmid) {
			pxmcnt = acpidev_slit_tbl_ptr->LocalityCount;
		} else {
			pxmcnt = pxmid + 1;
		}

		/*
		 * Validate data returned by the ACPI _SLI method.
		 * Please refer to 6.2.14 "_SLI (System Locality Information)"
		 * in ACPI4.0 for data format returned by _SLI method.
		 */
		if (buf.Length != pxmcnt * 2 * sizeof (uchar_t)) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: buffer length returned by _SLI method "
			    "under %p is invalid.", hdl);
			AcpiOsFree(buf.Pointer);
		} else if (valp[pxmid] != ACPI_SLIT_SELF_LATENCY ||
		    valp[pxmid + pxmcnt] != ACPI_SLIT_SELF_LATENCY) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: local latency returned by _SLI method "
			    "under %p is not %u.", hdl, ACPI_SLIT_SELF_LATENCY);
			AcpiOsFree(buf.Pointer);
		} else {
			*slicntp = pxmcnt;
			*slipp = (uchar_t *)buf.Pointer;
			*hdlpp = buf.Pointer;
			return (AE_OK);
		}
	} else if (rc != AE_NOT_FOUND) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to evaluate "
		    "_SLI method under object %p.", hdl);
	}

	/* Return data from the ACPI SLIT table. */
	ASSERT(acpidev_slit_tbl_ptr != NULL);
	pxmcnt = acpidev_slit_tbl_ptr->LocalityCount;
	if (pxmid >= pxmcnt) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: proximity domain id "
		    "(%u) is too big, max %u.", pxmid, pxmcnt - 1);
		*slicntp = 0;
		*slipp = NULL;
		return (AE_ERROR);
	} else {
		sp = AcpiOsAllocate(pxmcnt * 2 * sizeof (uchar_t));
		ep = acpidev_slit_tbl_ptr->Entry;
		for (i = 0; i < pxmcnt; i++) {
			sp[i] = ep[pxmcnt * pxmid + i];
			sp[i + pxmcnt] = ep[pxmcnt * i + pxmid];
		}
		*slicntp = pxmcnt;
		*slipp = sp;
		*hdlpp = sp;
		return (AE_OK);
	}
}

/*
 * Query NUMA information for the CPU device.
 * It returns APIC id, Proximity id and latency information of the CPU device.
 */
int
acpidev_dr_get_cpu_numa_info(cpu_t *cp, void **hdlpp, uint32_t *apicidp,
    uint32_t *pxmidp, uint32_t *slicntp, uchar_t **slipp)
{
	dev_info_t *dip = NULL;
	ACPI_HANDLE hdl = NULL;

	ASSERT(cp != NULL);
	ASSERT(hdlpp != NULL);
	ASSERT(apicidp != NULL);
	ASSERT(pxmidp != NULL);
	if (cp == NULL || hdlpp == NULL || apicidp == NULL || pxmidp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameters to "
		    "acpidev_dr_get_cpu_numa_info().");
		return (-1);
	}

	*hdlpp = NULL;
	*apicidp = UINT32_MAX;
	*pxmidp = UINT32_MAX;
	if (lgrp_plat_node_cnt == 1) {
		return (-1);
	}
	ASSERT(acpidev_slit_tbl_ptr != NULL);

	/* Query APIC id and Proximity id from device properties. */
	if (ACPI_FAILURE(acpica_get_cpu_object_by_cpuid(cp->cpu_id, &hdl))) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get ACPI object "
		    "for CPU(%d).", cp->cpu_id);
		return (-1);
	}
	if (ACPI_FAILURE(acpica_get_devinfo(hdl, &dip))) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get device node "
		    "for CPU(%d).", cp->cpu_id);
		return (-1);
	}
	*apicidp = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    ACPIDEV_PROP_NAME_LOCALAPIC_ID, UINT32_MAX);
	*pxmidp = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    ACPIDEV_PROP_NAME_PROXIMITY_ID, UINT32_MAX);
	if (*apicidp == UINT32_MAX || *pxmidp == UINT32_MAX) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get local APIC id "
		    "or proximity id for CPU(%d).", cp->cpu_id);
		return (-1);
	}

	ASSERT((slicntp && slipp) || (!slicntp && !slipp));
	if (slicntp != NULL && slipp != NULL) {
		if (ACPI_FAILURE(acpidev_dr_get_latency(hdl, hdlpp, *pxmidp,
		    slicntp, slipp))) {
			return (-1);
		}
	}

	return (0);
}

void
acpidev_dr_free_cpu_numa_info(void *hdlp)
{
	if (hdlp != NULL) {
		AcpiOsFree(hdlp);
	}
}

static ACPI_STATUS
acpidev_dr_mem_search_srat(struct memlist *ml, uint32_t *pxmidp)
{
	int len, off;
	uint64_t start, end;
	boolean_t found = B_FALSE;
	ACPI_SUBTABLE_HEADER *sp;
	ACPI_SRAT_MEM_AFFINITY *mp;

	ASSERT(ml != NULL);
	ASSERT(pxmidp != NULL);
	ASSERT(acpidev_srat_tbl_ptr != NULL);

	/* Search the static ACPI SRAT table for proximity domain. */
	sp = (ACPI_SUBTABLE_HEADER *)(acpidev_srat_tbl_ptr + 1);
	len = acpidev_srat_tbl_ptr->Header.Length;
	off = sizeof (*acpidev_srat_tbl_ptr);
	while (off < len) {
		if (sp->Type == ACPI_SRAT_TYPE_MEMORY_AFFINITY) {
			mp = (ACPI_SRAT_MEM_AFFINITY *)sp;
			if ((mp->Flags & ACPI_SRAT_MEM_ENABLED) &&
			    (mp->Flags & ACPI_SRAT_MEM_HOT_PLUGGABLE) &&
			    ml->ml_address >= mp->BaseAddress &&
			    ml->ml_address <= mp->BaseAddress + mp->Length) {
				found = B_TRUE;
				break;
			}
		}
		off += sp->Length;
		sp = (ACPI_SUBTABLE_HEADER *)(((char *)sp) + sp->Length);
	}
	if (!found)
		return (AE_NOT_FOUND);

	/*
	 * Verify that all memory regions in the list belong to the same domain.
	 */
	start = mp->BaseAddress;
	end = mp->BaseAddress + mp->Length;
	while (ml) {
		if (ml->ml_address < start ||
		    ml->ml_address + ml->ml_size > end) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: memory for hot-adding doesn't belong "
			    "to the same proximity domain.");
			return (AE_ERROR);
		}
		ml = ml->ml_next;
	}

	return (AE_OK);
}

/*
 * Query lgrp information for a memory device.
 * It returns proximity domain id and latency information of the memory device.
 */
ACPI_STATUS
acpidev_dr_get_mem_numa_info(ACPI_HANDLE hdl, struct memlist *ml,
    void **hdlpp, uint32_t *pxmidp, uint32_t *slicntp, uchar_t **slipp)
{
	ASSERT(ml != NULL);
	ASSERT(hdlpp != NULL);
	ASSERT(pxmidp != NULL);
	if (ml == NULL || hdlpp == NULL || pxmidp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameters to "
		    "acpidev_dr_get_mem_numa_info().");
		return (AE_BAD_PARAMETER);
	}

	*pxmidp = UINT32_MAX;
	if (lgrp_plat_node_cnt == 1) {
		return (AE_SUPPORT);
	}

	if (ACPI_FAILURE(acpidev_eval_pxm(hdl, pxmidp))) {
		/*
		 * Try to get proximity domain id from SRAT table if failed to
		 * evaluate ACPI _PXM method for memory device.
		 */
		if (ACPI_FAILURE(acpidev_dr_mem_search_srat(ml, pxmidp))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to get proximity domain id for "
			    "memory device %p.", hdl);
			return (AE_ERROR);
		}
	}

	ASSERT((slicntp && slipp) || (!slicntp && !slipp));
	if (slicntp != NULL && slipp != NULL) {
		if (ACPI_FAILURE(acpidev_dr_get_latency(hdl, hdlpp, *pxmidp,
		    slicntp, slipp))) {
			return (AE_ERROR);
		}
	}

	return (AE_OK);
}

void
acpidev_dr_free_mem_numa_info(void *hdlp)
{
	if (hdlp != NULL) {
		AcpiOsFree(hdlp);
	}
}
