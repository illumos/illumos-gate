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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/x86_archext.h>
#include <vm/as.h>
#include <vm/hat_i86.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>

#include <sys/vmm_vm.h>
#include <sys/seg_vmm.h>
#include <sys/vmm_kernel.h>
#include <sys/vmm_reservoir.h>
#include <sys/vmm_gpt.h>
#include "vmm_util.h"


/*
 * VMM Virtual Memory
 *
 * History
 *
 * When bhyve was ported to illumos, one significant hole was handling guest
 * memory and memory accesses.  In the original Pluribus port, bhyve itself
 * manually handled the EPT structures for guest memory.  The updated sources
 * (from FreeBSD 11) took a different approach, using the native FreeBSD VM
 * system for memory allocations and management of the EPT structures.  Keeping
 * source differences to a minimum was a priority, so illumos-bhyve implemented
 * a makeshift "VM shim" which exposed the bare minimum of those interfaces to
 * boot and run guests.
 *
 * While the VM shim was successful in getting illumos-bhyve to a functional
 * state on Intel (and later AMD) gear, the FreeBSD-specific nature of the
 * compatibility interfaces made it awkward to use.  As source differences with
 * the upstream kernel code became less of a concern, and upcoming features
 * (such as live migration) would demand more of those VM interfaces, it became
 * clear that an overhaul was prudent.
 *
 * Design
 *
 * The new VM system for bhyve retains a number of the same concepts as what it
 * replaces:
 *
 * - `vmspace_t` is the top-level entity for a guest memory space
 * - `vm_object_t` represents a memory object which can be mapped into a vmspace
 * - `vm_page_t` represents a page hold within a given vmspace, providing access
 *   to the underlying memory page
 *
 * Unlike the old code, where most of the involved structures were exposed via
 * public definitions, this replacement VM interface keeps all involved
 * structures opaque to consumers.  Furthermore, there is a clear delineation
 * between infrequent administrative operations (such as mapping/unmapping
 * regions) and common data-path operations (attempting a page hold at a given
 * guest-physical address).  Those administrative operations are performed
 * directly against the vmspace, whereas the data-path operations are performed
 * through a `vm_client_t` handle.  That VM client abstraction is meant to
 * reduce contention and overhead for frequent access operations and provide
 * debugging insight into how different subcomponents are accessing the vmspace.
 * A VM client is allocated for each vCPU, each viona ring (via the vmm_drv
 * interface) and each VMM userspace segment mapping.
 *
 * Exclusion
 *
 * Making changes to the vmspace (such as mapping or unmapping regions) requires
 * other accessors be excluded while the change is underway to prevent them from
 * observing invalid intermediate states.  A simple approach could use a mutex
 * or rwlock to achieve this, but that risks contention when the rate of access
 * to the vmspace is high.
 *
 * Since vmspace changes (map/unmap) are rare, we can instead do the exclusion
 * at a per-vm_client_t basis.  While this raises the cost for vmspace changes,
 * it means that the much more common page accesses through the vm_client can
 * normally proceed unimpeded and independently.
 *
 * When a change to the vmspace is required, the caller will put the vmspace in
 * a 'hold' state, iterating over all associated vm_client instances, waiting
 * for them to complete any in-flight lookup (indicated by VCS_ACTIVE) before
 * setting VCS_HOLD in their state flag fields.  With VCS_HOLD set, any call on
 * the vm_client which would access the vmspace state (vmc_hold or vmc_fault)
 * will block until the hold condition is cleared.  Once the hold is asserted
 * for all clients, the vmspace change can proceed with confidence.  Upon
 * completion of that operation, VCS_HOLD is cleared from the clients, and they
 * are released to resume vmspace accesses.
 *
 * vCPU Consumers
 *
 * Access to the vmspace for vCPUs running in guest context is different from
 * emulation-related vm_client activity: they solely rely on the contents of the
 * page tables.  Furthermore, the existing VCS_HOLD mechanism used to exclude
 * client access is not feasible when entering guest context, since interrupts
 * are disabled, making it impossible to block entry.  This is not a concern as
 * long as vmspace modifications never place the page tables in invalid states
 * (either intermediate, or final).  The vm_client hold mechanism does provide
 * the means to IPI vCPU consumers which will trigger a notification once they
 * report their exit from guest context.  This can be used to ensure that page
 * table modifications are made visible to those vCPUs within a certain
 * time frame.
 */

typedef struct vmspace_mapping {
	list_node_t	vmsm_node;
	vm_object_t	*vmsm_object;	/* object backing this mapping */
	uintptr_t	vmsm_addr;	/* start addr in vmspace for mapping */
	size_t		vmsm_len;	/* length (in bytes) of mapping */
	off_t		vmsm_offset;	/* byte offset into object */
	uint_t		vmsm_prot;
} vmspace_mapping_t;

#define	VMSM_OFFSET(vmsm, addr)	(			\
	    (vmsm)->vmsm_offset +			\
	    ((addr) - (uintptr_t)(vmsm)->vmsm_addr))

typedef enum vm_client_state {
	VCS_IDLE	= 0,
	/* currently accessing vmspace for client operation (hold or fault) */
	VCS_ACTIVE	= (1 << 0),
	/* client hold requested/asserted */
	VCS_HOLD	= (1 << 1),
	/* vCPU is accessing page tables in guest context */
	VCS_ON_CPU	= (1 << 2),
	/* client has been orphaned (no more access to vmspace) */
	VCS_ORPHANED	= (1 << 3),
	/* client undergoing destroy operation */
	VCS_DESTROY	= (1 << 4),
} vm_client_state_t;

struct vmspace {
	kmutex_t	vms_lock;
	kcondvar_t	vms_cv;
	bool		vms_held;
	uintptr_t	vms_size;	/* immutable after creation */

	/* (nested) page table state */
	vmm_gpt_t	*vms_gpt;
	uint64_t	vms_pt_gen;
	uint64_t	vms_pages_mapped;
	bool		vms_track_dirty;

	list_t		vms_maplist;
	list_t		vms_clients;
};

struct vm_client {
	vmspace_t	*vmc_space;
	list_node_t	vmc_node;

	kmutex_t	vmc_lock;
	kcondvar_t	vmc_cv;
	vm_client_state_t vmc_state;
	int		vmc_cpu_active;
	uint64_t	vmc_cpu_gen;
	bool		vmc_track_dirty;
	vmc_inval_cb_t	vmc_inval_func;
	void		*vmc_inval_data;

	list_t		vmc_held_pages;
};

typedef enum vm_object_type {
	VMOT_NONE,
	VMOT_MEM,
	VMOT_MMIO,
} vm_object_type_t;

struct vm_object {
	uint_t		vmo_refcnt;	/* manipulated with atomic ops */

	/* Fields below are fixed at creation time */
	vm_object_type_t vmo_type;
	size_t		vmo_size;
	void		*vmo_data;
	uint8_t		vmo_attr;
};

/* Convenience consolidation of all flag(s) for validity checking */
#define	VPF_ALL		(VPF_DEFER_DIRTY)

struct vm_page {
	vm_client_t	*vmp_client;
	list_node_t	vmp_node;
	vm_page_t	*vmp_chain;
	uintptr_t	vmp_gpa;
	pfn_t		vmp_pfn;
	uint64_t	*vmp_ptep;
	vm_object_t	*vmp_obj_ref;
	uint8_t		vmp_prot;
	uint8_t		vmp_flags;
};

static vmspace_mapping_t *vm_mapping_find(vmspace_t *, uintptr_t, size_t);
static void vmspace_hold_enter(vmspace_t *);
static void vmspace_hold_exit(vmspace_t *, bool);
static void vmspace_clients_invalidate(vmspace_t *, uintptr_t, size_t);
static int vmspace_ensure_mapped(vmspace_t *, uintptr_t, int, pfn_t *,
    uint64_t *);
static void vmc_space_hold(vm_client_t *);
static void vmc_space_release(vm_client_t *, bool);
static void vmc_space_invalidate(vm_client_t *, uintptr_t, size_t, uint64_t);
static void vmc_space_unmap(vm_client_t *, uintptr_t, size_t, vm_object_t *);
static vm_client_t *vmc_space_orphan(vm_client_t *, vmspace_t *);

bool
vmm_vm_init(void)
{
	if (vmm_is_intel()) {
		extern struct vmm_pte_impl ept_pte_impl;
		return (vmm_gpt_init(&ept_pte_impl));
	} else if (vmm_is_svm()) {
		extern struct vmm_pte_impl rvi_pte_impl;
		return (vmm_gpt_init(&rvi_pte_impl));
	} else {
		/* Caller should have already rejected other vendors */
		panic("Unexpected hypervisor hardware vendor");
	}
}

void
vmm_vm_fini(void)
{
	vmm_gpt_fini();
}

/*
 * Create a new vmspace with a maximum address of `end`.
 */
vmspace_t *
vmspace_alloc(size_t end)
{
	vmspace_t *vms;
	const uintptr_t size = end + 1;

	/*
	 * This whole mess is built on the assumption that a 64-bit address
	 * space is available to work with for the various pagetable tricks.
	 */
	VERIFY(size > 0 && (size & PAGEOFFSET) == 0 &&
	    size <= (uintptr_t)USERLIMIT);

	vms = kmem_zalloc(sizeof (*vms), KM_SLEEP);
	vms->vms_size = size;
	list_create(&vms->vms_maplist, sizeof (vmspace_mapping_t),
	    offsetof(vmspace_mapping_t, vmsm_node));
	list_create(&vms->vms_clients, sizeof (vm_client_t),
	    offsetof(vm_client_t, vmc_node));

	vms->vms_gpt = vmm_gpt_alloc();
	vms->vms_pt_gen = 1;
	vms->vms_track_dirty = false;

	return (vms);
}

/*
 * Destroy a vmspace.  All regions in the space must be unmapped.  Any remaining
 * clients will be orphaned.
 */
void
vmspace_destroy(vmspace_t *vms)
{
	mutex_enter(&vms->vms_lock);
	VERIFY(list_is_empty(&vms->vms_maplist));

	if (!list_is_empty(&vms->vms_clients)) {
		vm_client_t *vmc = list_head(&vms->vms_clients);
		while (vmc != NULL) {
			vmc = vmc_space_orphan(vmc, vms);
		}
		/*
		 * Wait for any clients which were in the process of destroying
		 * themselves to disappear.
		 */
		while (!list_is_empty(&vms->vms_clients)) {
			cv_wait(&vms->vms_cv, &vms->vms_lock);
		}
	}
	VERIFY(list_is_empty(&vms->vms_clients));

	vmm_gpt_free(vms->vms_gpt);
	mutex_exit(&vms->vms_lock);

	mutex_destroy(&vms->vms_lock);
	cv_destroy(&vms->vms_cv);
	list_destroy(&vms->vms_maplist);
	list_destroy(&vms->vms_clients);

	kmem_free(vms, sizeof (*vms));
}

/*
 * Retrieve the count of resident (mapped into the page tables) pages.
 */
uint64_t
vmspace_resident_count(vmspace_t *vms)
{
	return (vms->vms_pages_mapped);
}

/*
 * Perform an operation on the status (accessed/dirty) bits held in the page
 * tables of this vmspace.
 *
 * Such manipulations race against both hardware writes (from running vCPUs) and
 * emulated accesses reflected from userspace.  Safe functionality depends on
 * the VM instance being read-locked to prevent vmspace_map/vmspace_unmap
 * operations from changing the page tables during the walk.
 */
void
vmspace_bits_operate(vmspace_t *vms, const uint64_t gpa, size_t len,
    vmspace_bit_oper_t oper, uint8_t *bitmap)
{
	const bool bit_input = (oper & VBO_FLAG_BITMAP_IN) != 0;
	const bool bit_output = (oper & VBO_FLAG_BITMAP_OUT) != 0;
	const vmspace_bit_oper_t oper_only =
	    oper & ~(VBO_FLAG_BITMAP_IN | VBO_FLAG_BITMAP_OUT);
	vmm_gpt_t *gpt = vms->vms_gpt;

	/*
	 * The bitmap cannot be NULL if the requested operation involves reading
	 * or writing from it.
	 */
	ASSERT(bitmap != NULL || (!bit_input && !bit_output));

	vmm_gpt_iter_t iter;
	vmm_gpt_iter_entry_t entry;
	vmm_gpt_iter_init(&iter, gpt, gpa, len);

	while (vmm_gpt_iter_next(&iter, &entry)) {
		const size_t offset = (entry.vgie_gpa - gpa);
		const uint64_t pfn_offset = offset >> PAGESHIFT;
		const size_t bit_offset = pfn_offset / 8;
		const uint8_t bit_mask = 1 << (pfn_offset % 8);

		if (bit_input && (bitmap[bit_offset] & bit_mask) == 0) {
			continue;
		}

		bool value = false;
		uint64_t *ptep = entry.vgie_ptep;
		if (ptep == NULL) {
			if (bit_output) {
				bitmap[bit_offset] &= ~bit_mask;
			}
			continue;
		}

		switch (oper_only) {
		case VBO_GET_DIRTY:
			value = vmm_gpte_query_dirty(ptep);
			break;
		case VBO_SET_DIRTY: {
			uint_t prot = 0;
			bool present_writable = false;
			pfn_t pfn;

			/*
			 * To avoid blindly setting the dirty bit on otherwise
			 * empty PTEs, we must first check if the entry for the
			 * address in question has been populated.
			 *
			 * Only if the page is marked both Present and Writable
			 * will we permit the dirty bit to be set.
			 */
			if (!vmm_gpte_is_mapped(ptep, &pfn, &prot)) {
				int err = vmspace_ensure_mapped(vms,
				    entry.vgie_gpa, PROT_WRITE, &pfn, ptep);
				if (err == 0) {
					present_writable = true;
				}
			} else if ((prot & PROT_WRITE) != 0) {
				present_writable = true;
			}

			if (present_writable) {
				value = !vmm_gpte_reset_dirty(ptep, true);
			}
			break;
		}
		case VBO_RESET_DIRTY:
			/*
			 * Although at first glance, it may seem like the act of
			 * resetting the dirty bit may require the same care as
			 * setting it, the constraints make for a simpler task.
			 *
			 * Any PTEs with the dirty bit set will have already
			 * been properly populated.
			 */
			value = vmm_gpte_reset_dirty(ptep, false);
			break;
		default:
			panic("unrecognized operator: %d", oper_only);
			break;
		}
		if (bit_output) {
			if (value) {
				bitmap[bit_offset] |= bit_mask;
			} else {
				bitmap[bit_offset] &= ~bit_mask;
			}
		}
	}

	/*
	 * Invalidate the address range potentially effected by the changes to
	 * page table bits, issuing shoot-downs for those who might have it in
	 * cache.
	 */
	vmspace_hold_enter(vms);
	vms->vms_pt_gen++;
	vmspace_clients_invalidate(vms, gpa, len);
	vmspace_hold_exit(vms, true);
}

/*
 * Is dirty-page-tracking enabled for the vmspace?
 */
bool
vmspace_get_tracking(vmspace_t *vms)
{
	mutex_enter(&vms->vms_lock);
	const bool val = vms->vms_track_dirty;
	mutex_exit(&vms->vms_lock);
	return (val);
}

/*
 * Set the state (enabled/disabled) of dirty-page-tracking for the vmspace.
 */
int
vmspace_set_tracking(vmspace_t *vms, bool enable_dirty_tracking)
{
	if (enable_dirty_tracking && !vmm_gpt_can_track_dirty(vms->vms_gpt)) {
		/* Do not allow this to be set if it is not supported */
		return (ENOTSUP);
	}

	vmspace_hold_enter(vms);
	if (vms->vms_track_dirty == enable_dirty_tracking) {
		/* No further effort required if state already matches */
		vmspace_hold_exit(vms, false);
		return (0);
	}

	vms->vms_track_dirty = enable_dirty_tracking;

	/* Configure all existing clients for new tracking behavior */
	for (vm_client_t *vmc = list_head(&vms->vms_clients);
	    vmc != NULL;
	    vmc = list_next(&vms->vms_clients, vmc)) {
		mutex_enter(&vmc->vmc_lock);
		vmc->vmc_track_dirty = enable_dirty_tracking;
		mutex_exit(&vmc->vmc_lock);
	}

	/*
	 * Notify all clients of what is considered an invalidation of the
	 * entire vmspace.
	 */
	vms->vms_pt_gen++;
	vmspace_clients_invalidate(vms, 0, vms->vms_size);

	vmspace_hold_exit(vms, true);
	return (0);
}

static pfn_t
vm_object_pager_reservoir(vm_object_t *vmo, uintptr_t off)
{
	vmmr_region_t *region;
	pfn_t pfn;

	ASSERT3U(vmo->vmo_type, ==, VMOT_MEM);

	region = vmo->vmo_data;
	pfn = vmmr_region_pfn_at(region, off);

	return (pfn);
}

static pfn_t
vm_object_pager_mmio(vm_object_t *vmo, uintptr_t off)
{
	pfn_t pfn;

	ASSERT3U(vmo->vmo_type, ==, VMOT_MMIO);
	ASSERT3P(vmo->vmo_data, !=, NULL);
	ASSERT3U(off, <, vmo->vmo_size);

	pfn = ((uintptr_t)vmo->vmo_data + off) >> PAGESHIFT;

	return (pfn);
}

/*
 * Allocate a VM object backed by VMM reservoir memory.
 */
vm_object_t *
vm_object_mem_allocate(size_t size, bool transient)
{
	int err;
	vmmr_region_t *region = NULL;
	vm_object_t *vmo;

	ASSERT3U(size, !=, 0);
	ASSERT3U(size & PAGEOFFSET, ==, 0);

	err = vmmr_alloc(size, transient, &region);
	if (err != 0) {
		return (NULL);
	}

	vmo = kmem_alloc(sizeof (*vmo), KM_SLEEP);

	/* For now, these are to stay fixed after allocation */
	vmo->vmo_type = VMOT_MEM;
	vmo->vmo_size = size;
	vmo->vmo_attr = MTRR_TYPE_WB;
	vmo->vmo_data = region;
	vmo->vmo_refcnt = 1;

	return (vmo);
}

static vm_object_t *
vm_object_mmio_allocate(size_t size, uintptr_t hpa)
{
	vm_object_t *vmo;

	ASSERT3U(size, !=, 0);
	ASSERT3U(size & PAGEOFFSET, ==, 0);
	ASSERT3U(hpa & PAGEOFFSET, ==, 0);

	vmo = kmem_alloc(sizeof (*vmo), KM_SLEEP);

	/* For now, these are to stay fixed after allocation */
	vmo->vmo_type = VMOT_MMIO;
	vmo->vmo_size = size;
	vmo->vmo_attr = MTRR_TYPE_UC;
	vmo->vmo_data = (void *)hpa;
	vmo->vmo_refcnt = 1;

	return (vmo);
}

/*
 * Allocate a VM object backed by an existing range of physical memory.
 */
vm_object_t *
vmm_mmio_alloc(vmspace_t *vmspace, uintptr_t gpa, size_t len, uintptr_t hpa)
{
	int error;
	vm_object_t *obj;

	obj = vm_object_mmio_allocate(len, hpa);
	if (obj != NULL) {
		error = vmspace_map(vmspace, obj, 0, gpa, len,
		    PROT_READ | PROT_WRITE);
		if (error != 0) {
			vm_object_release(obj);
			obj = NULL;
		}
	}

	return (obj);
}

/*
 * Release a vm_object reference
 */
void
vm_object_release(vm_object_t *vmo)
{
	ASSERT(vmo != NULL);

	uint_t ref = atomic_dec_uint_nv(&vmo->vmo_refcnt);
	/* underflow would be a deadly serious mistake */
	VERIFY3U(ref, !=, UINT_MAX);
	if (ref != 0) {
		return;
	}

	switch (vmo->vmo_type) {
	case VMOT_MEM:
		vmmr_free((vmmr_region_t *)vmo->vmo_data);
		break;
	case VMOT_MMIO:
		break;
	default:
		panic("unexpected object type %u", vmo->vmo_type);
		break;
	}

	vmo->vmo_data = NULL;
	vmo->vmo_size = 0;
	kmem_free(vmo, sizeof (*vmo));
}

/*
 * Increase refcount for vm_object reference
 */
void
vm_object_reference(vm_object_t *vmo)
{
	ASSERT(vmo != NULL);

	uint_t ref = atomic_inc_uint_nv(&vmo->vmo_refcnt);
	/* overflow would be a deadly serious mistake */
	VERIFY3U(ref, !=, 0);
}

/*
 * Get the host-physical PFN for a given offset into a vm_object.
 *
 * The provided `off` must be within the allocated size of the vm_object.
 */
pfn_t
vm_object_pfn(vm_object_t *vmo, uintptr_t off)
{
	const uintptr_t aligned_off = off & PAGEMASK;

	switch (vmo->vmo_type) {
	case VMOT_MEM:
		return (vm_object_pager_reservoir(vmo, aligned_off));
	case VMOT_MMIO:
		return (vm_object_pager_mmio(vmo, aligned_off));
	case VMOT_NONE:
		break;
	}
	panic("unexpected object type %u", vmo->vmo_type);
}

static vmspace_mapping_t *
vm_mapping_find(vmspace_t *vms, uintptr_t addr, size_t size)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size;

	ASSERT3U(addr, <=, range_end);

	if (addr >= vms->vms_size) {
		return (NULL);
	}
	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		const uintptr_t seg_end = vmsm->vmsm_addr + vmsm->vmsm_len;

		if (addr >= vmsm->vmsm_addr && addr < seg_end) {
			if (range_end <= seg_end) {
				return (vmsm);
			} else {
				return (NULL);
			}
		}
	}
	return (NULL);
}

/*
 * Check to see if any mappings reside within [addr, addr + size) span in the
 * vmspace, returning true if that span is indeed empty.
 */
static bool
vm_mapping_gap(vmspace_t *vms, uintptr_t addr, size_t size)
{
	vmspace_mapping_t *vmsm;
	list_t *ml = &vms->vms_maplist;
	const uintptr_t range_end = addr + size - 1;

	ASSERT(MUTEX_HELD(&vms->vms_lock));
	ASSERT(size > 0);

	for (vmsm = list_head(ml); vmsm != NULL; vmsm = list_next(ml, vmsm)) {
		const uintptr_t seg_end = vmsm->vmsm_addr + vmsm->vmsm_len - 1;

		/*
		 * The two ranges do not overlap if the start of either of
		 * them is after the end of the other.
		 */
		if (vmsm->vmsm_addr > range_end || addr > seg_end)
			continue;
		return (false);
	}
	return (true);
}

static void
vm_mapping_remove(vmspace_t *vms, vmspace_mapping_t *vmsm)
{
	list_t *ml = &vms->vms_maplist;

	ASSERT(MUTEX_HELD(&vms->vms_lock));
	ASSERT(vms->vms_held);

	list_remove(ml, vmsm);
	vm_object_release(vmsm->vmsm_object);
	kmem_free(vmsm, sizeof (*vmsm));
}

/*
 * Enter a hold state on the vmspace.  This ensures that all VM clients
 * associated with the vmspace are excluded from establishing new page holds,
 * or any other actions which would require accessing vmspace state subject to
 * potential change.
 *
 * Returns with vmspace_t`vms_lock held.
 */
static void
vmspace_hold_enter(vmspace_t *vms)
{
	mutex_enter(&vms->vms_lock);
	VERIFY(!vms->vms_held);

	vm_client_t *vmc = list_head(&vms->vms_clients);
	for (; vmc != NULL; vmc = list_next(&vms->vms_clients, vmc)) {
		vmc_space_hold(vmc);
	}
	vms->vms_held = true;
}

/*
 * Exit a hold state on the vmspace.  This releases all VM clients associated
 * with the vmspace to be able to establish new page holds, and partake in other
 * actions which require accessing changed vmspace state.  If `kick_on_cpu` is
 * true, then any CPUs actively using the page tables will be IPIed, and the
 * call will block until they have acknowledged being ready to use the latest
 * state of the tables.
 *
 * Requires vmspace_t`vms_lock be held, which is released as part of the call.
 */
static void
vmspace_hold_exit(vmspace_t *vms, bool kick_on_cpu)
{
	ASSERT(MUTEX_HELD(&vms->vms_lock));
	VERIFY(vms->vms_held);

	vm_client_t *vmc = list_head(&vms->vms_clients);
	for (; vmc != NULL; vmc = list_next(&vms->vms_clients, vmc)) {
		vmc_space_release(vmc, kick_on_cpu);
	}
	vms->vms_held = false;
	mutex_exit(&vms->vms_lock);
}

static void
vmspace_clients_invalidate(vmspace_t *vms, uintptr_t gpa, size_t len)
{
	ASSERT(MUTEX_HELD(&vms->vms_lock));
	VERIFY(vms->vms_held);

	for (vm_client_t *vmc = list_head(&vms->vms_clients);
	    vmc != NULL;
	    vmc = list_next(&vms->vms_clients, vmc)) {
		vmc_space_invalidate(vmc, gpa, len, vms->vms_pt_gen);
	}
}

/*
 * Attempt to map a vm_object span into the vmspace.
 *
 * Requirements:
 * - `obj_off`, `addr`, and `len` must be page-aligned
 * - `obj_off` cannot be greater than the allocated size of the object
 * - [`obj_off`, `obj_off` + `len`) span cannot extend beyond the allocated
 *   size of the object
 * - [`addr`, `addr` + `len`) span cannot reside beyond the maximum address
 *   of the vmspace
 */
int
vmspace_map(vmspace_t *vms, vm_object_t *vmo, uintptr_t obj_off, uintptr_t addr,
    size_t len, uint8_t prot)
{
	vmspace_mapping_t *vmsm;
	int res = 0;

	if (len == 0 || (addr + len) < addr ||
	    obj_off >= (obj_off + len) || vmo->vmo_size < (obj_off + len)) {
		return (EINVAL);
	}
	if ((addr + len) >= vms->vms_size) {
		return (ENOMEM);
	}

	vmsm = kmem_alloc(sizeof (*vmsm), KM_SLEEP);

	vmspace_hold_enter(vms);
	if (!vm_mapping_gap(vms, addr, len)) {
		kmem_free(vmsm, sizeof (*vmsm));
		res = ENOMEM;
	} else {
		vmsm->vmsm_object = vmo;
		vmsm->vmsm_addr = addr;
		vmsm->vmsm_len = len;
		vmsm->vmsm_offset = (off_t)obj_off;
		vmsm->vmsm_prot = prot;
		list_insert_tail(&vms->vms_maplist, vmsm);

		/*
		 * Make sure the GPT has tables ready for leaf entries across
		 * the entire new mapping.
		 */
		vmm_gpt_populate_region(vms->vms_gpt, addr, len);
	}
	vmspace_hold_exit(vms, false);
	return (res);
}

/*
 * Unmap a region of the vmspace.
 *
 * Presently the [start, end) span must equal a region previously mapped by a
 * call to vmspace_map().
 */
int
vmspace_unmap(vmspace_t *vms, uintptr_t addr, uintptr_t len)
{
	const uintptr_t end = addr + len;
	vmspace_mapping_t *vmsm;
	vm_client_t *vmc;
	uint64_t gen = 0;

	ASSERT3U(addr, <, end);

	vmspace_hold_enter(vms);
	/* expect to match existing mapping exactly */
	if ((vmsm = vm_mapping_find(vms, addr, len)) == NULL ||
	    vmsm->vmsm_addr != addr || vmsm->vmsm_len != len) {
		vmspace_hold_exit(vms, false);
		return (ENOENT);
	}

	/* Prepare clients (and their held pages) for the unmap. */
	for (vmc = list_head(&vms->vms_clients); vmc != NULL;
	    vmc = list_next(&vms->vms_clients, vmc)) {
		vmc_space_unmap(vmc, addr, len, vmsm->vmsm_object);
	}

	/* Clear all PTEs for region */
	if (vmm_gpt_unmap_region(vms->vms_gpt, addr, len) != 0) {
		vms->vms_pt_gen++;
		gen = vms->vms_pt_gen;
	}
	/* ... and the intermediate (directory) PTEs as well */
	vmm_gpt_vacate_region(vms->vms_gpt, addr, len);

	/*
	 * If pages were actually unmapped from the GPT, provide clients with
	 * an invalidation notice.
	 */
	if (gen != 0) {
		vmspace_clients_invalidate(vms, addr, len);
	}

	vm_mapping_remove(vms, vmsm);
	vmspace_hold_exit(vms, true);
	return (0);
}

/*
 * For a given GPA in the vmspace, ensure that the backing page (if any) is
 * properly mapped as present in the provided PTE.
 */
static int
vmspace_ensure_mapped(vmspace_t *vms, uintptr_t gpa, int req_prot, pfn_t *pfnp,
    uint64_t *leaf_pte)
{
	vmspace_mapping_t *vmsm;
	vm_object_t *vmo;
	pfn_t pfn;

	ASSERT(pfnp != NULL);
	ASSERT(leaf_pte != NULL);

	vmsm = vm_mapping_find(vms, gpa, PAGESIZE);
	if (vmsm == NULL) {
		return (FC_NOMAP);
	}
	if ((req_prot & vmsm->vmsm_prot) != req_prot) {
		return (FC_PROT);
	}

	vmo = vmsm->vmsm_object;
	pfn = vm_object_pfn(vmo, VMSM_OFFSET(vmsm, gpa));
	VERIFY(pfn != PFN_INVALID);

	if (vmm_gpt_map_at(vms->vms_gpt, leaf_pte, pfn, vmsm->vmsm_prot,
	    vmo->vmo_attr)) {
		atomic_inc_64(&vms->vms_pages_mapped);
	}

	*pfnp = pfn;
	return (0);
}

/*
 * Look up the PTE for a given GPA in the vmspace, populating it with
 * appropriate contents (pfn, protection, etc) if it is empty, but backed by a
 * valid mapping.
 */
static int
vmspace_lookup_map(vmspace_t *vms, uintptr_t gpa, int req_prot, pfn_t *pfnp,
    uint64_t **ptepp)
{
	vmm_gpt_t *gpt = vms->vms_gpt;
	uint64_t *entries[MAX_GPT_LEVEL], *leaf;
	pfn_t pfn = PFN_INVALID;
	uint_t prot;

	ASSERT0(gpa & PAGEOFFSET);
	ASSERT((req_prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) != PROT_NONE);

	(void) vmm_gpt_walk(gpt, gpa, entries, LEVEL1);
	leaf = entries[LEVEL1];
	if (leaf == NULL) {
		/*
		 * Since we populated the intermediate tables for any regions
		 * mapped in the GPT, an empty leaf entry indicates there is no
		 * mapping, populated or not, at this GPA.
		 */
		return (FC_NOMAP);
	}

	if (vmm_gpte_is_mapped(leaf, &pfn, &prot)) {
		if ((req_prot & prot) != req_prot) {
			return (FC_PROT);
		}
	} else {
		int err = vmspace_ensure_mapped(vms, gpa, req_prot, &pfn, leaf);
		if (err != 0) {
			return (err);
		}
	}

	ASSERT(pfn != PFN_INVALID && leaf != NULL);
	if (pfnp != NULL) {
		*pfnp = pfn;
	}
	if (ptepp != NULL) {
		*ptepp = leaf;
	}
	return (0);
}

/*
 * Populate (make resident in the page tables) a region of the vmspace.
 *
 * Presently the [start, end) span must equal a region previously mapped by a
 * call to vmspace_map().
 */
int
vmspace_populate(vmspace_t *vms, uintptr_t addr, uintptr_t len)
{
	ASSERT0(addr & PAGEOFFSET);
	ASSERT0(len & PAGEOFFSET);

	vmspace_mapping_t *vmsm;
	mutex_enter(&vms->vms_lock);

	/* For the time being, only exact-match mappings are expected */
	if ((vmsm = vm_mapping_find(vms, addr, len)) == NULL) {
		mutex_exit(&vms->vms_lock);
		return (FC_NOMAP);
	}

	vm_object_t *vmo = vmsm->vmsm_object;
	const int prot = vmsm->vmsm_prot;
	const uint8_t attr = vmo->vmo_attr;
	vmm_gpt_t *gpt = vms->vms_gpt;
	size_t populated = 0;

	vmm_gpt_iter_t iter;
	vmm_gpt_iter_entry_t entry;
	vmm_gpt_iter_init(&iter, gpt, addr, len);
	while (vmm_gpt_iter_next(&iter, &entry)) {
		const pfn_t pfn =
		    vm_object_pfn(vmo, VMSM_OFFSET(vmsm, entry.vgie_gpa));
		VERIFY(pfn != PFN_INVALID);

		if (vmm_gpt_map_at(gpt, entry.vgie_ptep, pfn, prot, attr)) {
			populated++;
		}
	}
	atomic_add_64(&vms->vms_pages_mapped, populated);

	mutex_exit(&vms->vms_lock);
	return (0);
}

/*
 * Allocate a client from a given vmspace.
 */
vm_client_t *
vmspace_client_alloc(vmspace_t *vms)
{
	vm_client_t *vmc;

	vmc = kmem_zalloc(sizeof (vm_client_t), KM_SLEEP);
	vmc->vmc_space = vms;
	mutex_init(&vmc->vmc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vmc->vmc_cv, NULL, CV_DRIVER, NULL);
	vmc->vmc_state = VCS_IDLE;
	vmc->vmc_cpu_active = -1;
	list_create(&vmc->vmc_held_pages, sizeof (vm_page_t),
	    offsetof(vm_page_t, vmp_node));
	vmc->vmc_track_dirty = vms->vms_track_dirty;

	mutex_enter(&vms->vms_lock);
	list_insert_tail(&vms->vms_clients, vmc);
	mutex_exit(&vms->vms_lock);

	return (vmc);
}

/*
 * Get the nested page table root pointer (EPTP/NCR3) value.
 */
uint64_t
vmspace_table_root(vmspace_t *vms)
{
	return (vmm_gpt_get_pmtp(vms->vms_gpt, vms->vms_track_dirty));
}

/*
 * Get the current generation number of the nested page table.
 */
uint64_t
vmspace_table_gen(vmspace_t *vms)
{
	return (vms->vms_pt_gen);
}

/*
 * Mark a vm_client as active.  This will block if/while the client is held by
 * the vmspace.  On success, it returns with vm_client_t`vmc_lock held.  It will
 * fail if the vm_client has been orphaned.
 */
static int
vmc_activate(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY0(vmc->vmc_state & VCS_ACTIVE);
	if ((vmc->vmc_state & VCS_ORPHANED) != 0) {
		mutex_exit(&vmc->vmc_lock);
		return (ENXIO);
	}
	while ((vmc->vmc_state & VCS_HOLD) != 0) {
		cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
	}
	vmc->vmc_state |= VCS_ACTIVE;
	return (0);
}

/*
 * Mark a vm_client as no longer active.  It must be called with
 * vm_client_t`vmc_lock already held, and will return with it released.
 */
static void
vmc_deactivate(vm_client_t *vmc)
{
	ASSERT(MUTEX_HELD(&vmc->vmc_lock));
	VERIFY(vmc->vmc_state & VCS_ACTIVE);

	vmc->vmc_state ^= VCS_ACTIVE;
	if ((vmc->vmc_state & VCS_HOLD) != 0) {
		cv_broadcast(&vmc->vmc_cv);
	}
	mutex_exit(&vmc->vmc_lock);
}

/*
 * Indicate that a CPU will be utilizing the nested page tables through this VM
 * client.  Interrupts (and/or the GIF) are expected to be disabled when calling
 * this function.  Returns the generation number of the nested page table (to be
 * used for TLB invalidations).
 */
uint64_t
vmc_table_enter(vm_client_t *vmc)
{
	vmspace_t *vms = vmc->vmc_space;
	uint64_t gen;

	ASSERT0(vmc->vmc_state & (VCS_ACTIVE | VCS_ON_CPU));
	ASSERT3S(vmc->vmc_cpu_active, ==, -1);

	/*
	 * Since the NPT activation occurs with interrupts disabled, this must
	 * be done without taking vmc_lock like normal.
	 */
	gen = vms->vms_pt_gen;
	vmc->vmc_cpu_active = CPU->cpu_id;
	vmc->vmc_cpu_gen = gen;
	atomic_or_uint(&vmc->vmc_state, VCS_ON_CPU);

	return (gen);
}

/*
 * Indicate that this VM client is not longer (directly) using the underlying
 * page tables.  Interrupts (and/or the GIF) must be enabled prior to calling
 * this function.
 */
void
vmc_table_exit(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);

	ASSERT(vmc->vmc_state & VCS_ON_CPU);
	vmc->vmc_state ^= VCS_ON_CPU;
	vmc->vmc_cpu_active = -1;
	if ((vmc->vmc_state & VCS_HOLD) != 0) {
		cv_broadcast(&vmc->vmc_cv);
	}

	mutex_exit(&vmc->vmc_lock);
}

static void
vmc_space_hold(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY0(vmc->vmc_state & VCS_HOLD);

	/*
	 * Because vmc_table_enter() alters vmc_state from a context where
	 * interrupts are disabled, it cannot pay heed to vmc_lock, so setting
	 * VMC_HOLD must be done atomically here.
	 */
	atomic_or_uint(&vmc->vmc_state, VCS_HOLD);

	/* Wait for client to go inactive */
	while ((vmc->vmc_state & VCS_ACTIVE) != 0) {
		cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
	}
	mutex_exit(&vmc->vmc_lock);
}

static void
vmc_space_release(vm_client_t *vmc, bool kick_on_cpu)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY(vmc->vmc_state & VCS_HOLD);

	if (kick_on_cpu && (vmc->vmc_state & VCS_ON_CPU) != 0) {
		poke_cpu(vmc->vmc_cpu_active);

		while ((vmc->vmc_state & VCS_ON_CPU) != 0) {
			cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
		}
	}

	/*
	 * Because vmc_table_enter() alters vmc_state from a context where
	 * interrupts are disabled, it cannot pay heed to vmc_lock, so clearing
	 * VMC_HOLD must be done atomically here.
	 */
	atomic_and_uint(&vmc->vmc_state, ~VCS_HOLD);
	cv_broadcast(&vmc->vmc_cv);
	mutex_exit(&vmc->vmc_lock);
}

static void
vmc_space_invalidate(vm_client_t *vmc, uintptr_t addr, size_t size,
    uint64_t gen)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY(vmc->vmc_state & VCS_HOLD);
	if ((vmc->vmc_state & VCS_ON_CPU) != 0) {
		/*
		 * Wait for clients using an old generation of the page tables
		 * to exit guest context, where they subsequently flush the TLB
		 * for the new generation.
		 */
		if (vmc->vmc_cpu_gen < gen) {
			poke_cpu(vmc->vmc_cpu_active);

			while ((vmc->vmc_state & VCS_ON_CPU) != 0) {
				cv_wait(&vmc->vmc_cv, &vmc->vmc_lock);
			}
		}
	}
	if (vmc->vmc_inval_func != NULL) {
		vmc_inval_cb_t func = vmc->vmc_inval_func;
		void *data = vmc->vmc_inval_data;

		/*
		 * Perform the actual invalidation call outside vmc_lock to
		 * avoid lock ordering issues in the consumer.  Since the client
		 * is under VCS_HOLD, this is safe.
		 */
		mutex_exit(&vmc->vmc_lock);
		func(data, addr, size);
		mutex_enter(&vmc->vmc_lock);
	}
	mutex_exit(&vmc->vmc_lock);
}

static void
vmc_space_unmap(vm_client_t *vmc, uintptr_t addr, size_t size,
    vm_object_t *vmo)
{
	mutex_enter(&vmc->vmc_lock);
	VERIFY(vmc->vmc_state & VCS_HOLD);

	/*
	 * With the current vCPU exclusion invariants in place, we do not expect
	 * a vCPU to be in guest context during an unmap.
	 */
	VERIFY0(vmc->vmc_state & VCS_ON_CPU);

	/*
	 * Any holds against the unmapped region need to establish their own
	 * reference to the underlying object to avoid a potential
	 * use-after-free.
	 */
	for (vm_page_t *vmp = list_head(&vmc->vmc_held_pages);
	    vmp != NULL;
	    vmp = list_next(&vmc->vmc_held_pages, vmc)) {
		if (vmp->vmp_gpa < addr ||
		    vmp->vmp_gpa >= (addr + size)) {
			/* Hold outside region in question */
			continue;
		}
		if (vmp->vmp_obj_ref == NULL) {
			vm_object_reference(vmo);
			vmp->vmp_obj_ref = vmo;
			/* For an unmapped region, PTE is now meaningless */
			vmp->vmp_ptep = NULL;
		} else {
			/*
			 * Object could have gone through cycle of
			 * unmap-map-unmap before the hold was released.
			 */
			VERIFY3P(vmp->vmp_ptep, ==, NULL);
		}
	}
	mutex_exit(&vmc->vmc_lock);
}

static vm_client_t *
vmc_space_orphan(vm_client_t *vmc, vmspace_t *vms)
{
	vm_client_t *next;

	ASSERT(MUTEX_HELD(&vms->vms_lock));

	mutex_enter(&vmc->vmc_lock);
	VERIFY3P(vmc->vmc_space, ==, vms);
	VERIFY0(vmc->vmc_state & VCS_ORPHANED);
	if (vmc->vmc_state & VCS_DESTROY) {
		/*
		 * This vm_client is currently undergoing destruction, so it
		 * does not need to be orphaned.  Let it proceed with its own
		 * clean-up task.
		 */
		next = list_next(&vms->vms_clients, vmc);
	} else {
		/*
		 * Clients are only orphaned when the containing vmspace is
		 * being torn down.  All mappings from the vmspace should
		 * already be gone, meaning any remaining held pages should have
		 * direct references to the object.
		 */
		for (vm_page_t *vmp = list_head(&vmc->vmc_held_pages);
		    vmp != NULL;
		    vmp = list_next(&vmc->vmc_held_pages, vmp)) {
			ASSERT3P(vmp->vmp_ptep, ==, NULL);
			ASSERT3P(vmp->vmp_obj_ref, !=, NULL);
		}

		/*
		 * After this point, the client will be orphaned, unable to
		 * establish new page holds (or access any vmspace-related
		 * resources) and is in charge of cleaning up after itself.
		 */
		vmc->vmc_state |= VCS_ORPHANED;
		next = list_next(&vms->vms_clients, vmc);
		list_remove(&vms->vms_clients, vmc);
		vmc->vmc_space = NULL;
	}
	mutex_exit(&vmc->vmc_lock);
	return (next);
}

/*
 * Attempt to hold a page at `gpa` inside the referenced vmspace.
 */
vm_page_t *
vmc_hold_ext(vm_client_t *vmc, uintptr_t gpa, int prot, int flags)
{
	vmspace_t *vms = vmc->vmc_space;
	vm_page_t *vmp;
	pfn_t pfn = PFN_INVALID;
	uint64_t *ptep = NULL;

	ASSERT0(gpa & PAGEOFFSET);
	ASSERT((prot & (PROT_READ | PROT_WRITE)) != PROT_NONE);
	ASSERT0(prot & ~PROT_ALL);
	ASSERT0(flags & ~VPF_ALL);

	vmp = kmem_alloc(sizeof (*vmp), KM_SLEEP);
	if (vmc_activate(vmc) != 0) {
		kmem_free(vmp, sizeof (*vmp));
		return (NULL);
	}

	if (vmspace_lookup_map(vms, gpa, prot, &pfn, &ptep) != 0) {
		vmc_deactivate(vmc);
		kmem_free(vmp, sizeof (*vmp));
		return (NULL);
	}
	ASSERT(pfn != PFN_INVALID && ptep != NULL);

	vmp->vmp_client = vmc;
	vmp->vmp_chain = NULL;
	vmp->vmp_gpa = gpa;
	vmp->vmp_pfn = pfn;
	vmp->vmp_ptep = ptep;
	vmp->vmp_obj_ref = NULL;
	vmp->vmp_prot = (uint8_t)prot;
	vmp->vmp_flags = (uint8_t)flags;
	list_insert_tail(&vmc->vmc_held_pages, vmp);
	vmc_deactivate(vmc);

	return (vmp);
}

/*
 * Attempt to hold a page at `gpa` inside the referenced vmspace.
 */
vm_page_t *
vmc_hold(vm_client_t *vmc, uintptr_t gpa, int prot)
{
	return (vmc_hold_ext(vmc, gpa, prot, VPF_DEFAULT));
}

int
vmc_fault(vm_client_t *vmc, uintptr_t gpa, int prot)
{
	vmspace_t *vms = vmc->vmc_space;
	int err;

	err = vmc_activate(vmc);
	if (err == 0) {
		err = vmspace_lookup_map(vms, gpa & PAGEMASK, prot, NULL, NULL);
		vmc_deactivate(vmc);
	}

	return (err);
}

/*
 * Allocate an additional vm_client_t, based on an existing one.  Only the
 * associatation with the vmspace is cloned, not existing holds or any
 * configured invalidation function.
 */
vm_client_t *
vmc_clone(vm_client_t *vmc)
{
	vmspace_t *vms = vmc->vmc_space;

	return (vmspace_client_alloc(vms));
}

/*
 * Register a function (and associated data pointer) to be called when an
 * address range in the vmspace is invalidated.
 */
int
vmc_set_inval_cb(vm_client_t *vmc, vmc_inval_cb_t func, void *data)
{
	int err;

	err = vmc_activate(vmc);
	if (err == 0) {
		vmc->vmc_inval_func = func;
		vmc->vmc_inval_data = data;
		vmc_deactivate(vmc);
	}

	return (err);
}

/*
 * Destroy a vm_client_t instance.
 *
 * No pages held through this vm_client_t may be outstanding when performing a
 * vmc_destroy().  For vCPU clients, the client cannot be on-CPU (a call to
 * vmc_table_exit() has been made).
 */
void
vmc_destroy(vm_client_t *vmc)
{
	mutex_enter(&vmc->vmc_lock);

	VERIFY(list_is_empty(&vmc->vmc_held_pages));
	VERIFY0(vmc->vmc_state & (VCS_ACTIVE | VCS_ON_CPU));

	if ((vmc->vmc_state & VCS_ORPHANED) == 0) {
		vmspace_t *vms;

		/*
		 * Deassociation with the parent vmspace must be done carefully:
		 * The vmspace could attempt to orphan this vm_client while we
		 * release vmc_lock in order to take vms_lock (the required
		 * order).  The client is marked to indicate that destruction is
		 * under way.  Doing so prevents any racing orphan operation
		 * from applying to this client, allowing us to deassociate from
		 * the vmspace safely.
		 */
		vmc->vmc_state |= VCS_DESTROY;
		vms = vmc->vmc_space;
		mutex_exit(&vmc->vmc_lock);

		mutex_enter(&vms->vms_lock);
		mutex_enter(&vmc->vmc_lock);
		list_remove(&vms->vms_clients, vmc);
		/*
		 * If the vmspace began its own destruction operation while we
		 * were navigating the locks, be sure to notify it about this
		 * vm_client being deassociated.
		 */
		cv_signal(&vms->vms_cv);
		mutex_exit(&vmc->vmc_lock);
		mutex_exit(&vms->vms_lock);
	} else {
		VERIFY3P(vmc->vmc_space, ==, NULL);
		mutex_exit(&vmc->vmc_lock);
	}

	mutex_destroy(&vmc->vmc_lock);
	cv_destroy(&vmc->vmc_cv);
	list_destroy(&vmc->vmc_held_pages);

	kmem_free(vmc, sizeof (*vmc));
}

static __inline void *
vmp_ptr(const vm_page_t *vmp)
{
	ASSERT3U(vmp->vmp_pfn, !=, PFN_INVALID);

	const uintptr_t paddr = (vmp->vmp_pfn << PAGESHIFT);
	return ((void *)((uintptr_t)kpm_vbase + paddr));
}

/*
 * Get a readable kernel-virtual pointer for a held page.
 *
 * Only legal to call if PROT_READ was specified in `prot` for the vmc_hold()
 * call to acquire this page reference.
 */
const void *
vmp_get_readable(const vm_page_t *vmp)
{
	ASSERT(vmp->vmp_prot & PROT_READ);

	return (vmp_ptr(vmp));
}

/*
 * Get a writable kernel-virtual pointer for a held page.
 *
 * Only legal to call if PROT_WRITE was specified in `prot` for the vmc_hold()
 * call to acquire this page reference.
 */
void *
vmp_get_writable(const vm_page_t *vmp)
{
	ASSERT(vmp->vmp_prot & PROT_WRITE);

	return (vmp_ptr(vmp));
}

/*
 * Get the host-physical PFN for a held page.
 */
pfn_t
vmp_get_pfn(const vm_page_t *vmp)
{
	return (vmp->vmp_pfn);
}

/*
 * If this page was deferring dirty-marking in the corresponding vmspace page
 * tables, clear such a state so it is considered dirty from now on.
 */
void
vmp_mark_dirty(vm_page_t *vmp)
{
	ASSERT((vmp->vmp_prot & PROT_WRITE) != 0);

	atomic_and_8(&vmp->vmp_flags, ~VPF_DEFER_DIRTY);
}

/*
 * Store a pointer to `to_chain` in the page-chaining slot of `vmp`.
 */
void
vmp_chain(vm_page_t *vmp, vm_page_t *to_chain)
{
	ASSERT3P(vmp->vmp_chain, ==, NULL);

	vmp->vmp_chain = to_chain;
}

/*
 * Retrieve the pointer from the page-chaining in `vmp`.
 */
vm_page_t *
vmp_next(const vm_page_t *vmp)
{
	return (vmp->vmp_chain);
}

static __inline bool
vmp_release_inner(vm_page_t *vmp, vm_client_t *vmc)
{
	ASSERT(MUTEX_HELD(&vmc->vmc_lock));

	bool was_unmapped = false;

	list_remove(&vmc->vmc_held_pages, vmp);
	if (vmp->vmp_obj_ref != NULL) {
		ASSERT3P(vmp->vmp_ptep, ==, NULL);

		vm_object_release(vmp->vmp_obj_ref);
		was_unmapped = true;
	} else {
		ASSERT3P(vmp->vmp_ptep, !=, NULL);

		/*
		 * Track appropriate (accessed/dirty) bits for the guest-virtual
		 * address corresponding to this page, if it is from the vmspace
		 * rather than a direct reference to an underlying object.
		 *
		 * The protection and/or configured flags may obviate the need
		 * for such an update.
		 */
		if ((vmp->vmp_prot & PROT_WRITE) != 0 &&
		    (vmp->vmp_flags & VPF_DEFER_DIRTY) == 0 &&
		    vmc->vmc_track_dirty) {
			(void) vmm_gpte_reset_dirty(vmp->vmp_ptep, true);
		}
	}
	kmem_free(vmp, sizeof (*vmp));
	return (was_unmapped);
}

/*
 * Release held page.  Returns true if page resided on region which was
 * subsequently unmapped.
 */
bool
vmp_release(vm_page_t *vmp)
{
	vm_client_t *vmc = vmp->vmp_client;

	VERIFY(vmc != NULL);

	mutex_enter(&vmc->vmc_lock);
	const bool was_unmapped = vmp_release_inner(vmp, vmc);
	mutex_exit(&vmc->vmc_lock);
	return (was_unmapped);
}

/*
 * Release a chain of pages which were associated via vmp_chain() (setting
 * page-chaining pointer).  Returns true if any pages resided upon a region
 * which was subsequently unmapped.
 *
 * All of those pages must have been held through the same vm_client_t.
 */
bool
vmp_release_chain(vm_page_t *vmp)
{
	vm_client_t *vmc = vmp->vmp_client;
	bool any_unmapped = false;

	ASSERT(vmp != NULL);

	mutex_enter(&vmc->vmc_lock);
	while (vmp != NULL) {
		vm_page_t *next = vmp->vmp_chain;

		/* We expect all pages in chain to be from same client */
		ASSERT3P(vmp->vmp_client, ==, vmc);

		if (vmp_release_inner(vmp, vmc)) {
			any_unmapped = true;
		}
		vmp = next;
	}
	mutex_exit(&vmc->vmc_lock);
	return (any_unmapped);
}


int
vm_segmap_obj(struct vm *vm, int segid, off_t segoff, off_t len,
    struct as *as, caddr_t *addrp, uint_t prot, uint_t maxprot, uint_t flags)
{
	vm_object_t *vmo;
	int err;

	if (segoff < 0 || len <= 0 ||
	    (segoff & PAGEOFFSET) != 0 || (len & PAGEOFFSET) != 0) {
		return (EINVAL);
	}
	if ((prot & PROT_USER) == 0) {
		return (ENOTSUP);
	}
	err = vm_get_memseg(vm, segid, NULL, NULL, &vmo);
	if (err != 0) {
		return (err);
	}

	VERIFY(segoff >= 0);
	VERIFY(len <= vmo->vmo_size);
	VERIFY((len + segoff) <= vmo->vmo_size);

	if (vmo->vmo_type != VMOT_MEM) {
		/* Only support memory objects for now */
		return (ENOTSUP);
	}

	as_rangelock(as);

	err = choose_addr(as, addrp, (size_t)len, 0, ADDR_VACALIGN, flags);
	if (err == 0) {
		segvmm_crargs_t svma;

		svma.prot = prot;
		svma.offset = segoff;
		svma.vmo = vmo;
		svma.vmc = NULL;

		err = as_map(as, *addrp, (size_t)len, segvmm_create, &svma);
	}

	as_rangeunlock(as);
	return (err);
}

int
vm_segmap_space(struct vm *vm, off_t off, struct as *as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags)
{

	const uintptr_t gpa = (uintptr_t)off;
	const size_t size = (uintptr_t)len;
	int err;

	if (off < 0 || len <= 0 ||
	    (gpa & PAGEOFFSET) != 0 || (size & PAGEOFFSET) != 0) {
		return (EINVAL);
	}
	if ((prot & PROT_USER) == 0) {
		return (ENOTSUP);
	}

	as_rangelock(as);

	err = choose_addr(as, addrp, size, off, ADDR_VACALIGN, flags);
	if (err == 0) {
		segvmm_crargs_t svma;

		svma.prot = prot;
		svma.offset = gpa;
		svma.vmo = NULL;
		svma.vmc = vmspace_client_alloc(vm_get_vmspace(vm));

		err = as_map(as, *addrp, len, segvmm_create, &svma);
	}

	as_rangeunlock(as);
	return (err);
}
