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
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/vmsystm.h>
#include <sys/ddi.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/fs/dv_node.h>
#include <sys/cpuset.h>
#include <sys/id_space.h>
#include <sys/fs/sdev_plugin.h>
#include <sys/smt.h>
#include <sys/kstat.h>

#include <sys/kernel.h>
#include <sys/hma.h>
#include <sys/x86_archext.h>
#include <x86/apicreg.h>

#include <sys/vmm.h>
#include <sys/vmm_kernel.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_impl.h>
#include <sys/vmm_drv.h>
#include <sys/vmm_vm.h>
#include <sys/vmm_reservoir.h>

#include <vm/seg_dev.h>

#include "io/ppt.h"
#include "io/vatpic.h"
#include "io/vioapic.h"
#include "io/vrtc.h"
#include "io/vhpet.h"
#include "io/vpmtmr.h"
#include "vmm_lapic.h"
#include "vmm_stat.h"
#include "vmm_util.h"

/*
 * Locking details:
 *
 * Driver-wide data (vmmdev_*) , including HMA and sdev registration, is
 * protected by vmmdev_mtx.  The list of vmm_softc_t instances and related data
 * (vmm_*) are protected by vmm_mtx.  Actions requiring both locks must acquire
 * vmmdev_mtx before vmm_mtx.  The sdev plugin functions must not attempt to
 * acquire vmmdev_mtx, as they could deadlock with plugin unregistration.
 */

static kmutex_t		vmmdev_mtx;
static dev_info_t	*vmmdev_dip;
static hma_reg_t	*vmmdev_hma_reg;
static uint_t		vmmdev_hma_ref;
static sdev_plugin_hdl_t vmmdev_sdev_hdl;

static kmutex_t		vmm_mtx;
static list_t		vmm_list;
static id_space_t	*vmm_minors;
static void		*vmm_statep;

/* temporary safety switch */
int		vmm_allow_state_writes;

static const char *vmmdev_hvm_name = "bhyve";

/* For sdev plugin (/dev) */
#define	VMM_SDEV_ROOT "/dev/vmm"

/* From uts/intel/io/vmm/intel/vmx.c */
extern int vmx_x86_supported(const char **);

/* Holds and hooks from drivers external to vmm */
struct vmm_hold {
	list_node_t	vmh_node;
	vmm_softc_t	*vmh_sc;
	boolean_t	vmh_release_req;
	uint_t		vmh_ioport_hook_cnt;
};

struct vmm_lease {
	list_node_t		vml_node;
	struct vm		*vml_vm;
	vm_client_t		*vml_vmclient;
	boolean_t		vml_expired;
	boolean_t		vml_break_deferred;
	boolean_t		(*vml_expire_func)(void *);
	void			*vml_expire_arg;
	struct vmm_hold		*vml_hold;
};

/* Options for vmm_destroy_locked */
typedef enum vmm_destroy_opts {
	VDO_DEFAULT		= 0,
	/*
	 * Indicate that zone-specific-data associated with this VM not be
	 * cleaned up as part of the destroy.  Skipping ZSD clean-up is
	 * necessary when VM is being destroyed as part of zone destruction,
	 * when said ZSD is already being cleaned up.
	 */
	VDO_NO_CLEAN_ZSD	= (1 << 0),
	/*
	 * Attempt to wait for VM destruction to complete.  This is opt-in,
	 * since there are many normal conditions which could lead to
	 * destruction being stalled pending other clean-up.
	 */
	VDO_ATTEMPT_WAIT	= (1 << 1),
} vmm_destroy_opts_t;

static void vmm_hma_release(void);
static int vmm_destroy_locked(vmm_softc_t *, vmm_destroy_opts_t, bool *);
static int vmm_drv_block_hook(vmm_softc_t *, boolean_t);
static void vmm_lease_block(vmm_softc_t *);
static void vmm_lease_unblock(vmm_softc_t *);
static int vmm_kstat_alloc(vmm_softc_t *, minor_t, const cred_t *);
static void vmm_kstat_init(vmm_softc_t *);
static void vmm_kstat_fini(vmm_softc_t *);

/*
 * The 'devmem' hack:
 *
 * On native FreeBSD, bhyve consumers are allowed to create 'devmem' segments
 * in the vm which appear with their own name related to the vm under /dev.
 * Since this would be a hassle from an sdev perspective and would require a
 * new cdev interface (or complicate the existing one), we choose to implement
 * this in a different manner.  Direct access to the underlying vm memory
 * segments is exposed by placing them in a range of offsets beyond the normal
 * guest memory space.  Userspace can query the appropriate offset to mmap()
 * for a given segment-id with the VM_DEVMEM_GETOFFSET ioctl.
 */

static vmm_devmem_entry_t *
vmmdev_devmem_find(vmm_softc_t *sc, int segid)
{
	vmm_devmem_entry_t *ent = NULL;
	list_t *dl = &sc->vmm_devmem_list;

	for (ent = list_head(dl); ent != NULL; ent = list_next(dl, ent)) {
		if (ent->vde_segid == segid) {
			return (ent);
		}
	}
	return (NULL);
}

static int
vmmdev_get_memseg(vmm_softc_t *sc, struct vm_memseg *mseg)
{
	int error;
	bool sysmem;

	error = vm_get_memseg(sc->vmm_vm, mseg->segid, &mseg->len, &sysmem,
	    NULL);
	if (error || mseg->len == 0)
		return (error);

	if (!sysmem) {
		vmm_devmem_entry_t *de;

		de = vmmdev_devmem_find(sc, mseg->segid);
		if (de != NULL) {
			(void) strlcpy(mseg->name, de->vde_name,
			    sizeof (mseg->name));
		}
	} else {
		bzero(mseg->name, sizeof (mseg->name));
	}

	return (error);
}

static int
vmmdev_devmem_create(vmm_softc_t *sc, struct vm_memseg *mseg, const char *name)
{
	off_t map_offset;
	vmm_devmem_entry_t *entry;

	if (list_is_empty(&sc->vmm_devmem_list)) {
		map_offset = VM_DEVMEM_START;
	} else {
		entry = list_tail(&sc->vmm_devmem_list);
		map_offset = entry->vde_off + entry->vde_len;
		if (map_offset < entry->vde_off) {
			/* Do not tolerate overflow */
			return (ERANGE);
		}
		/*
		 * XXXJOY: We could choose to search the list for duplicate
		 * names and toss an error.  Since we're using the offset
		 * method for now, it does not make much of a difference.
		 */
	}

	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	entry->vde_segid = mseg->segid;
	entry->vde_len = mseg->len;
	entry->vde_off = map_offset;
	(void) strlcpy(entry->vde_name, name, sizeof (entry->vde_name));
	list_insert_tail(&sc->vmm_devmem_list, entry);

	return (0);
}

static boolean_t
vmmdev_devmem_segid(vmm_softc_t *sc, off_t off, off_t len, int *segidp,
    off_t *map_offp)
{
	list_t *dl = &sc->vmm_devmem_list;
	vmm_devmem_entry_t *de = NULL;
	const off_t map_end = off + len;

	VERIFY(off >= VM_DEVMEM_START);

	if (map_end < off) {
		/* No match on overflow */
		return (B_FALSE);
	}

	for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
		const off_t item_end = de->vde_off + de->vde_len;

		if (de->vde_off <= off && item_end >= map_end) {
			*segidp = de->vde_segid;
			*map_offp = off - de->vde_off;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * When an instance is being destroyed, the devmem list of named memory objects
 * can be torn down, as no new mappings are allowed.
 */
static void
vmmdev_devmem_purge(vmm_softc_t *sc)
{
	vmm_devmem_entry_t *entry;

	while ((entry = list_remove_head(&sc->vmm_devmem_list)) != NULL) {
		kmem_free(entry, sizeof (*entry));
	}
}

static int
vmmdev_alloc_memseg(vmm_softc_t *sc, struct vm_memseg *mseg)
{
	int error;
	bool sysmem = true;

	if (VM_MEMSEG_NAME(mseg)) {
		sysmem = false;
	}
	error = vm_alloc_memseg(sc->vmm_vm, mseg->segid, mseg->len, sysmem);

	if (error == 0) {
		/*
		 * Rather than create a whole fresh device from which userspace
		 * can mmap this segment, instead make it available at an
		 * offset above where the main guest memory resides.
		 */
		error = vmmdev_devmem_create(sc, mseg, mseg->name);
		if (error != 0) {
			vm_free_memseg(sc->vmm_vm, mseg->segid);
		}
	}
	return (error);
}

/*
 * Resource Locking and Exclusion
 *
 * Much of bhyve depends on key portions of VM state, such as the guest memory
 * map, to remain unchanged while the guest is running.  As ported from
 * FreeBSD, the initial strategy for this resource exclusion hinged on gating
 * access to the instance vCPUs.  Threads acting on a single vCPU, like those
 * performing the work of actually running the guest in VMX/SVM, would lock
 * only that vCPU during ioctl() entry.  For ioctls which would change VM-wide
 * state, all of the vCPUs would be first locked, ensuring that the
 * operation(s) could complete without any other threads stumbling into
 * intermediate states.
 *
 * This approach is largely effective for bhyve.  Common operations, such as
 * running the vCPUs, steer clear of lock contention.  The model begins to
 * break down for operations which do not occur in the context of a specific
 * vCPU.  LAPIC MSI delivery, for example, may be initiated from a worker
 * thread in the bhyve process.  In order to properly protect those vCPU-less
 * operations from encountering invalid states, additional locking is required.
 * This was solved by forcing those operations to lock the VM_MAXCPU-1 vCPU.
 * It does mean that class of operations will be serialized on locking the
 * specific vCPU and that instances sized at VM_MAXCPU will potentially see
 * undue contention on the VM_MAXCPU-1 vCPU.
 *
 * In order to address the shortcomings of this model, the concept of a
 * read/write lock has been added to bhyve.  Operations which change
 * fundamental aspects of a VM (such as the memory map) must acquire the write
 * lock, which also implies locking all of the vCPUs and waiting for all read
 * lock holders to release.  While it increases the cost and waiting time for
 * those few operations, it allows most hot-path operations on the VM (which
 * depend on its configuration remaining stable) to occur with minimal locking.
 *
 * Consumers of the Driver API (see below) are a special case when it comes to
 * this locking, since they may hold a read lock via the drv_lease mechanism
 * for an extended period of time.  Rather than forcing those consumers to
 * continuously poll for a write lock attempt, the lease system forces them to
 * provide a release callback to trigger their clean-up (and potential later
 * reacquisition) of the read lock.
 */

static void
vcpu_lock_one(vmm_softc_t *sc, int vcpu)
{
	ASSERT(vcpu >= 0 && vcpu < VM_MAXCPU);

	/*
	 * Since this state transition is utilizing from_idle=true, it should
	 * not fail, but rather block until it can be successful.
	 */
	VERIFY0(vcpu_set_state(sc->vmm_vm, vcpu, VCPU_FROZEN, true));
}

static void
vcpu_unlock_one(vmm_softc_t *sc, int vcpu)
{
	ASSERT(vcpu >= 0 && vcpu < VM_MAXCPU);

	VERIFY3U(vcpu_get_state(sc->vmm_vm, vcpu, NULL), ==, VCPU_FROZEN);
	VERIFY0(vcpu_set_state(sc->vmm_vm, vcpu, VCPU_IDLE, false));
}

static void
vmm_read_lock(vmm_softc_t *sc)
{
	rw_enter(&sc->vmm_rwlock, RW_READER);
}

static void
vmm_read_unlock(vmm_softc_t *sc)
{
	rw_exit(&sc->vmm_rwlock);
}

static void
vmm_write_lock(vmm_softc_t *sc)
{
	int maxcpus;

	/* First lock all the vCPUs */
	maxcpus = vm_get_maxcpus(sc->vmm_vm);
	for (int vcpu = 0; vcpu < maxcpus; vcpu++) {
		vcpu_lock_one(sc, vcpu);
	}

	/*
	 * Block vmm_drv leases from being acquired or held while the VM write
	 * lock is held.
	 */
	vmm_lease_block(sc);

	rw_enter(&sc->vmm_rwlock, RW_WRITER);
	/*
	 * For now, the 'maxcpus' value for an instance is fixed at the
	 * compile-time constant of VM_MAXCPU at creation.  If this changes in
	 * the future, allowing for dynamic vCPU resource sizing, acquisition
	 * of the write lock will need to be wary of such changes.
	 */
	VERIFY(maxcpus == vm_get_maxcpus(sc->vmm_vm));
}

static void
vmm_write_unlock(vmm_softc_t *sc)
{
	int maxcpus;

	/* Allow vmm_drv leases to be acquired once write lock is dropped */
	vmm_lease_unblock(sc);

	/*
	 * The VM write lock _must_ be released from the same thread it was
	 * acquired in, unlike the read lock.
	 */
	VERIFY(rw_write_held(&sc->vmm_rwlock));
	rw_exit(&sc->vmm_rwlock);

	/* Unlock all the vCPUs */
	maxcpus = vm_get_maxcpus(sc->vmm_vm);
	for (int vcpu = 0; vcpu < maxcpus; vcpu++) {
		vcpu_unlock_one(sc, vcpu);
	}
}

static int
vmmdev_do_ioctl(vmm_softc_t *sc, int cmd, intptr_t arg, int md,
    cred_t *credp, int *rvalp)
{
	int error = 0, vcpu = -1;
	void *datap = (void *)arg;
	enum vm_lock_type {
		LOCK_NONE = 0,
		LOCK_VCPU,
		LOCK_READ_HOLD,
		LOCK_WRITE_HOLD
	} lock_type = LOCK_NONE;

	/* Acquire any exclusion resources needed for the operation. */
	switch (cmd) {
	case VM_RUN:
	case VM_GET_REGISTER:
	case VM_SET_REGISTER:
	case VM_GET_SEGMENT_DESCRIPTOR:
	case VM_SET_SEGMENT_DESCRIPTOR:
	case VM_GET_REGISTER_SET:
	case VM_SET_REGISTER_SET:
	case VM_INJECT_EXCEPTION:
	case VM_GET_CAPABILITY:
	case VM_SET_CAPABILITY:
	case VM_PPTDEV_MSI:
	case VM_PPTDEV_MSIX:
	case VM_SET_X2APIC_STATE:
	case VM_GLA2GPA:
	case VM_GLA2GPA_NOFAULT:
	case VM_ACTIVATE_CPU:
	case VM_SET_INTINFO:
	case VM_GET_INTINFO:
	case VM_RESTART_INSTRUCTION:
	case VM_SET_KERNEMU_DEV:
	case VM_GET_KERNEMU_DEV:
	case VM_RESET_CPU:
	case VM_GET_RUN_STATE:
	case VM_SET_RUN_STATE:
	case VM_GET_FPU:
	case VM_SET_FPU:
	case VM_GET_CPUID:
	case VM_SET_CPUID:
	case VM_LEGACY_CPUID:
		/*
		 * Copy in the ID of the vCPU chosen for this operation.
		 * Since a nefarious caller could update their struct between
		 * this locking and when the rest of the ioctl data is copied
		 * in, it is _critical_ that this local 'vcpu' variable be used
		 * rather than the in-struct one when performing the ioctl.
		 */
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			return (EFAULT);
		}
		if (vcpu < 0 || vcpu > vm_get_maxcpus(sc->vmm_vm)) {
			return (EINVAL);
		}
		vcpu_lock_one(sc, vcpu);
		lock_type = LOCK_VCPU;
		break;

	case VM_REINIT:
	case VM_BIND_PPTDEV:
	case VM_UNBIND_PPTDEV:
	case VM_MAP_PPTDEV_MMIO:
	case VM_UNMAP_PPTDEV_MMIO:
	case VM_ALLOC_MEMSEG:
	case VM_MMAP_MEMSEG:
	case VM_MUNMAP_MEMSEG:
	case VM_WRLOCK_CYCLE:
	case VM_PMTMR_LOCATE:
	case VM_PAUSE:
	case VM_RESUME:
		vmm_write_lock(sc);
		lock_type = LOCK_WRITE_HOLD;
		break;

	case VM_GET_MEMSEG:
	case VM_MMAP_GETNEXT:
	case VM_LAPIC_IRQ:
	case VM_INJECT_NMI:
	case VM_IOAPIC_ASSERT_IRQ:
	case VM_IOAPIC_DEASSERT_IRQ:
	case VM_IOAPIC_PULSE_IRQ:
	case VM_LAPIC_MSI:
	case VM_LAPIC_LOCAL_IRQ:
	case VM_GET_X2APIC_STATE:
	case VM_RTC_READ:
	case VM_RTC_WRITE:
	case VM_RTC_SETTIME:
	case VM_RTC_GETTIME:
	case VM_PPTDEV_DISABLE_MSIX:
	case VM_DEVMEM_GETOFFSET:
	case VM_TRACK_DIRTY_PAGES:
		vmm_read_lock(sc);
		lock_type = LOCK_READ_HOLD;
		break;

	case VM_DATA_READ:
	case VM_DATA_WRITE:
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			return (EFAULT);
		}
		if (vcpu == -1) {
			/* Access data for VM-wide devices */
			vmm_write_lock(sc);
			lock_type = LOCK_WRITE_HOLD;
		} else if (vcpu >= 0 && vcpu < vm_get_maxcpus(sc->vmm_vm)) {
			/* Access data associated with a specific vCPU */
			vcpu_lock_one(sc, vcpu);
			lock_type = LOCK_VCPU;
		} else {
			return (EINVAL);
		}
		break;

	case VM_GET_GPA_PMAP:
	case VM_IOAPIC_PINCOUNT:
	case VM_SUSPEND:
	case VM_DESC_FPU_AREA:
	case VM_SET_AUTODESTRUCT:
	case VM_DESTROY_SELF:
	case VM_DESTROY_PENDING:
	default:
		break;
	}

	/* Execute the primary logic for the ioctl. */
	switch (cmd) {
	case VM_RUN: {
		struct vm_entry entry;

		if (ddi_copyin(datap, &entry, sizeof (entry), md)) {
			error = EFAULT;
			break;
		}

		if (!(curthread->t_schedflag & TS_VCPU))
			smt_mark_as_vcpu();

		error = vm_run(sc->vmm_vm, vcpu, &entry);

		/*
		 * Unexpected states in vm_run() are expressed through positive
		 * errno-oriented return values.  VM states which expect further
		 * processing in userspace (necessary context via exitinfo) are
		 * expressed through negative return values.  For the time being
		 * a return value of 0 is not expected from vm_run().
		 */
		ASSERT(error != 0);
		if (error < 0) {
			const struct vm_exit *vme;
			void *outp = entry.exit_data;

			error = 0;
			vme = vm_exitinfo(sc->vmm_vm, vcpu);
			if (ddi_copyout(vme, outp, sizeof (*vme), md)) {
				error = EFAULT;
			}
		}
		break;
	}
	case VM_SUSPEND: {
		struct vm_suspend vmsuspend;

		if (ddi_copyin(datap, &vmsuspend, sizeof (vmsuspend), md)) {
			error = EFAULT;
			break;
		}
		error = vm_suspend(sc->vmm_vm, vmsuspend.how);
		break;
	}
	case VM_REINIT: {
		struct vm_reinit reinit;

		if (ddi_copyin(datap, &reinit, sizeof (reinit), md)) {
			error = EFAULT;
			break;
		}
		if ((error = vmm_drv_block_hook(sc, B_TRUE)) != 0) {
			/*
			 * The VM instance should be free of driver-attached
			 * hooks during the reinitialization process.
			 */
			break;
		}
		error = vm_reinit(sc->vmm_vm, reinit.flags);
		(void) vmm_drv_block_hook(sc, B_FALSE);
		break;
	}
	case VM_STAT_DESC: {
		struct vm_stat_desc statdesc;

		if (ddi_copyin(datap, &statdesc, sizeof (statdesc), md)) {
			error = EFAULT;
			break;
		}
		error = vmm_stat_desc_copy(statdesc.index, statdesc.desc,
		    sizeof (statdesc.desc));
		if (error == 0 &&
		    ddi_copyout(&statdesc, datap, sizeof (statdesc), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_STATS_IOC: {
		struct vm_stats vmstats;

		if (ddi_copyin(datap, &vmstats, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		hrt2tv(gethrtime(), &vmstats.tv);
		error = vmm_stat_copy(sc->vmm_vm, vmstats.cpuid, vmstats.index,
		    nitems(vmstats.statbuf),
		    &vmstats.num_entries, vmstats.statbuf);
		if (error == 0 &&
		    ddi_copyout(&vmstats, datap, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_PPTDEV_MSI: {
		struct vm_pptdev_msi pptmsi;

		if (ddi_copyin(datap, &pptmsi, sizeof (pptmsi), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_setup_msi(sc->vmm_vm, pptmsi.vcpu, pptmsi.pptfd,
		    pptmsi.addr, pptmsi.msg, pptmsi.numvec);
		break;
	}
	case VM_PPTDEV_MSIX: {
		struct vm_pptdev_msix pptmsix;

		if (ddi_copyin(datap, &pptmsix, sizeof (pptmsix), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_setup_msix(sc->vmm_vm, pptmsix.vcpu, pptmsix.pptfd,
		    pptmsix.idx, pptmsix.addr, pptmsix.msg,
		    pptmsix.vector_control);
		break;
	}
	case VM_PPTDEV_DISABLE_MSIX: {
		struct vm_pptdev pptdev;

		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_disable_msix(sc->vmm_vm, pptdev.pptfd);
		break;
	}
	case VM_MAP_PPTDEV_MMIO: {
		struct vm_pptdev_mmio pptmmio;

		if (ddi_copyin(datap, &pptmmio, sizeof (pptmmio), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_map_mmio(sc->vmm_vm, pptmmio.pptfd, pptmmio.gpa,
		    pptmmio.len, pptmmio.hpa);
		break;
	}
	case VM_UNMAP_PPTDEV_MMIO: {
		struct vm_pptdev_mmio pptmmio;

		if (ddi_copyin(datap, &pptmmio, sizeof (pptmmio), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_unmap_mmio(sc->vmm_vm, pptmmio.pptfd, pptmmio.gpa,
		    pptmmio.len);
		break;
	}
	case VM_BIND_PPTDEV: {
		struct vm_pptdev pptdev;

		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		error = vm_assign_pptdev(sc->vmm_vm, pptdev.pptfd);
		break;
	}
	case VM_UNBIND_PPTDEV: {
		struct vm_pptdev pptdev;

		if (ddi_copyin(datap, &pptdev, sizeof (pptdev), md)) {
			error = EFAULT;
			break;
		}
		error = vm_unassign_pptdev(sc->vmm_vm, pptdev.pptfd);
		break;
	}
	case VM_GET_PPTDEV_LIMITS: {
		struct vm_pptdev_limits pptlimits;

		if (ddi_copyin(datap, &pptlimits, sizeof (pptlimits), md)) {
			error = EFAULT;
			break;
		}
		error = ppt_get_limits(sc->vmm_vm, pptlimits.pptfd,
		    &pptlimits.msi_limit, &pptlimits.msix_limit);
		if (error == 0 &&
		    ddi_copyout(&pptlimits, datap, sizeof (pptlimits), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_INJECT_EXCEPTION: {
		struct vm_exception vmexc;
		if (ddi_copyin(datap, &vmexc, sizeof (vmexc), md)) {
			error = EFAULT;
			break;
		}
		error = vm_inject_exception(sc->vmm_vm, vcpu, vmexc.vector,
		    vmexc.error_code_valid != 0, vmexc.error_code,
		    vmexc.restart_instruction != 0);
		break;
	}
	case VM_INJECT_NMI: {
		struct vm_nmi vmnmi;

		if (ddi_copyin(datap, &vmnmi, sizeof (vmnmi), md)) {
			error = EFAULT;
			break;
		}
		error = vm_inject_nmi(sc->vmm_vm, vmnmi.cpuid);
		break;
	}
	case VM_LAPIC_IRQ: {
		struct vm_lapic_irq vmirq;

		if (ddi_copyin(datap, &vmirq, sizeof (vmirq), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_intr_edge(sc->vmm_vm, vmirq.cpuid, vmirq.vector);
		break;
	}
	case VM_LAPIC_LOCAL_IRQ: {
		struct vm_lapic_irq vmirq;

		if (ddi_copyin(datap, &vmirq, sizeof (vmirq), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_set_local_intr(sc->vmm_vm, vmirq.cpuid,
		    vmirq.vector);
		break;
	}
	case VM_LAPIC_MSI: {
		struct vm_lapic_msi vmmsi;

		if (ddi_copyin(datap, &vmmsi, sizeof (vmmsi), md)) {
			error = EFAULT;
			break;
		}
		error = lapic_intr_msi(sc->vmm_vm, vmmsi.addr, vmmsi.msg);
		break;
	}

	case VM_IOAPIC_ASSERT_IRQ: {
		struct vm_ioapic_irq ioapic_irq;

		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_assert_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	}
	case VM_IOAPIC_DEASSERT_IRQ: {
		struct vm_ioapic_irq ioapic_irq;

		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_deassert_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	}
	case VM_IOAPIC_PULSE_IRQ: {
		struct vm_ioapic_irq ioapic_irq;

		if (ddi_copyin(datap, &ioapic_irq, sizeof (ioapic_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vioapic_pulse_irq(sc->vmm_vm, ioapic_irq.irq);
		break;
	}
	case VM_IOAPIC_PINCOUNT: {
		int pincount;

		pincount = vioapic_pincount(sc->vmm_vm);
		if (ddi_copyout(&pincount, datap, sizeof (int), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_DESC_FPU_AREA: {
		struct vm_fpu_desc desc;
		void *buf = NULL;

		if (ddi_copyin(datap, &desc, sizeof (desc), md)) {
			error = EFAULT;
			break;
		}
		if (desc.vfd_num_entries > 64) {
			error = EINVAL;
			break;
		}
		const size_t buf_sz = sizeof (struct vm_fpu_desc_entry) *
		    desc.vfd_num_entries;
		if (buf_sz != 0) {
			buf = kmem_zalloc(buf_sz, KM_SLEEP);
		}

		/*
		 * For now, we are depending on vm_fpu_desc_entry and
		 * hma_xsave_state_desc_t having the same format.
		 */
		CTASSERT(sizeof (struct vm_fpu_desc_entry) ==
		    sizeof (hma_xsave_state_desc_t));

		size_t req_size;
		const uint_t max_entries = hma_fpu_describe_xsave_state(
		    (hma_xsave_state_desc_t *)buf,
		    desc.vfd_num_entries,
		    &req_size);

		desc.vfd_req_size = req_size;
		desc.vfd_num_entries = max_entries;
		if (buf_sz != 0) {
			if (ddi_copyout(buf, desc.vfd_entry_data, buf_sz, md)) {
				error = EFAULT;
			}
			kmem_free(buf, buf_sz);
		}

		if (error == 0) {
			if (ddi_copyout(&desc, datap, sizeof (desc), md)) {
				error = EFAULT;
			}
		}
		break;
	}
	case VM_SET_AUTODESTRUCT: {
		/*
		 * Since this has to do with controlling the lifetime of the
		 * greater vmm_softc_t, the flag is protected by vmm_mtx, rather
		 * than the vcpu-centric or rwlock exclusion mechanisms.
		 */
		mutex_enter(&vmm_mtx);
		if (arg != 0) {
			sc->vmm_flags |= VMM_AUTODESTROY;
		} else {
			sc->vmm_flags &= ~VMM_AUTODESTROY;
		}
		mutex_exit(&vmm_mtx);
		break;
	}
	case VM_DESTROY_SELF: {
		bool hma_release = false;

		/*
		 * Just like VMM_DESTROY_VM, but on the instance file descriptor
		 * itself, rather than having to perform a racy name lookup as
		 * part of the destroy process.
		 *
		 * Since vmm_destroy_locked() performs vCPU lock acquisition in
		 * order to kick the vCPUs out of guest context as part of any
		 * destruction, we do not need to worry about it ourself using
		 * the `lock_type` logic here.
		 */
		mutex_enter(&vmm_mtx);
		VERIFY0(vmm_destroy_locked(sc, VDO_DEFAULT, &hma_release));
		mutex_exit(&vmm_mtx);
		if (hma_release) {
			vmm_hma_release();
		}
		break;
	}
	case VM_DESTROY_PENDING: {
		/*
		 * If we have made it this far, then destruction of the instance
		 * has not been initiated.
		 */
		*rvalp = 0;
		break;
	}

	case VM_ISA_ASSERT_IRQ: {
		struct vm_isa_irq isa_irq;

		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_assert_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_assert_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	}
	case VM_ISA_DEASSERT_IRQ: {
		struct vm_isa_irq isa_irq;

		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_deassert_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_deassert_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	}
	case VM_ISA_PULSE_IRQ: {
		struct vm_isa_irq isa_irq;

		if (ddi_copyin(datap, &isa_irq, sizeof (isa_irq), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_pulse_irq(sc->vmm_vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1) {
			error = vioapic_pulse_irq(sc->vmm_vm,
			    isa_irq.ioapic_irq);
		}
		break;
	}
	case VM_ISA_SET_IRQ_TRIGGER: {
		struct vm_isa_irq_trigger isa_irq_trigger;

		if (ddi_copyin(datap, &isa_irq_trigger,
		    sizeof (isa_irq_trigger), md)) {
			error = EFAULT;
			break;
		}
		error = vatpic_set_irq_trigger(sc->vmm_vm,
		    isa_irq_trigger.atpic_irq, isa_irq_trigger.trigger);
		break;
	}

	case VM_MMAP_GETNEXT: {
		struct vm_memmap mm;

		if (ddi_copyin(datap, &mm, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		error = vm_mmap_getnext(sc->vmm_vm, &mm.gpa, &mm.segid,
		    &mm.segoff, &mm.len, &mm.prot, &mm.flags);
		if (error == 0 && ddi_copyout(&mm, datap, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_MMAP_MEMSEG: {
		struct vm_memmap mm;

		if (ddi_copyin(datap, &mm, sizeof (mm), md)) {
			error = EFAULT;
			break;
		}
		error = vm_mmap_memseg(sc->vmm_vm, mm.gpa, mm.segid, mm.segoff,
		    mm.len, mm.prot, mm.flags);
		break;
	}
	case VM_MUNMAP_MEMSEG: {
		struct vm_munmap mu;

		if (ddi_copyin(datap, &mu, sizeof (mu), md)) {
			error = EFAULT;
			break;
		}
		error = vm_munmap_memseg(sc->vmm_vm, mu.gpa, mu.len);
		break;
	}
	case VM_ALLOC_MEMSEG: {
		struct vm_memseg vmseg;

		if (ddi_copyin(datap, &vmseg, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		error = vmmdev_alloc_memseg(sc, &vmseg);
		break;
	}
	case VM_GET_MEMSEG: {
		struct vm_memseg vmseg;

		if (ddi_copyin(datap, &vmseg, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		error = vmmdev_get_memseg(sc, &vmseg);
		if (error == 0 &&
		    ddi_copyout(&vmseg, datap, sizeof (vmseg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GET_REGISTER: {
		struct vm_register vmreg;

		if (ddi_copyin(datap, &vmreg, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_register(sc->vmm_vm, vcpu, vmreg.regnum,
		    &vmreg.regval);
		if (error == 0 &&
		    ddi_copyout(&vmreg, datap, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_REGISTER: {
		struct vm_register vmreg;

		if (ddi_copyin(datap, &vmreg, sizeof (vmreg), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_register(sc->vmm_vm, vcpu, vmreg.regnum,
		    vmreg.regval);
		break;
	}
	case VM_SET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc vmsegd;

		if (ddi_copyin(datap, &vmsegd, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_seg_desc(sc->vmm_vm, vcpu, vmsegd.regnum,
		    &vmsegd.desc);
		break;
	}
	case VM_GET_SEGMENT_DESCRIPTOR: {
		struct vm_seg_desc vmsegd;

		if (ddi_copyin(datap, &vmsegd, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_seg_desc(sc->vmm_vm, vcpu, vmsegd.regnum,
		    &vmsegd.desc);
		if (error == 0 &&
		    ddi_copyout(&vmsegd, datap, sizeof (vmsegd), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GET_REGISTER_SET: {
		struct vm_register_set vrs;
		int regnums[VM_REG_LAST];
		uint64_t regvals[VM_REG_LAST];

		if (ddi_copyin(datap, &vrs, sizeof (vrs), md)) {
			error = EFAULT;
			break;
		}
		if (vrs.count > VM_REG_LAST || vrs.count == 0) {
			error = EINVAL;
			break;
		}
		if (ddi_copyin(vrs.regnums, regnums,
		    sizeof (int) * vrs.count, md)) {
			error = EFAULT;
			break;
		}

		error = 0;
		for (uint_t i = 0; i < vrs.count && error == 0; i++) {
			if (regnums[i] < 0) {
				error = EINVAL;
				break;
			}
			error = vm_get_register(sc->vmm_vm, vcpu, regnums[i],
			    &regvals[i]);
		}
		if (error == 0 && ddi_copyout(regvals, vrs.regvals,
		    sizeof (uint64_t) * vrs.count, md)) {
			error = EFAULT;
		}
		break;
	}
	case VM_SET_REGISTER_SET: {
		struct vm_register_set vrs;
		int regnums[VM_REG_LAST];
		uint64_t regvals[VM_REG_LAST];

		if (ddi_copyin(datap, &vrs, sizeof (vrs), md)) {
			error = EFAULT;
			break;
		}
		if (vrs.count > VM_REG_LAST || vrs.count == 0) {
			error = EINVAL;
			break;
		}
		if (ddi_copyin(vrs.regnums, regnums,
		    sizeof (int) * vrs.count, md)) {
			error = EFAULT;
			break;
		}
		if (ddi_copyin(vrs.regvals, regvals,
		    sizeof (uint64_t) * vrs.count, md)) {
			error = EFAULT;
			break;
		}

		error = 0;
		for (uint_t i = 0; i < vrs.count && error == 0; i++) {
			/*
			 * Setting registers in a set is not atomic, since a
			 * failure in the middle of the set will cause a
			 * bail-out and inconsistent register state.  Callers
			 * should be wary of this.
			 */
			if (regnums[i] < 0) {
				error = EINVAL;
				break;
			}
			error = vm_set_register(sc->vmm_vm, vcpu, regnums[i],
			    regvals[i]);
		}
		break;
	}
	case VM_RESET_CPU: {
		struct vm_vcpu_reset vvr;

		if (ddi_copyin(datap, &vvr, sizeof (vvr), md)) {
			error = EFAULT;
			break;
		}
		if (vvr.kind != VRK_RESET && vvr.kind != VRK_INIT) {
			error = EINVAL;
		}

		error = vcpu_arch_reset(sc->vmm_vm, vcpu, vvr.kind == VRK_INIT);
		break;
	}
	case VM_GET_RUN_STATE: {
		struct vm_run_state vrs;

		bzero(&vrs, sizeof (vrs));
		error = vm_get_run_state(sc->vmm_vm, vcpu, &vrs.state,
		    &vrs.sipi_vector);
		if (error == 0) {
			if (ddi_copyout(&vrs, datap, sizeof (vrs), md)) {
				error = EFAULT;
				break;
			}
		}
		break;
	}
	case VM_SET_RUN_STATE: {
		struct vm_run_state vrs;

		if (ddi_copyin(datap, &vrs, sizeof (vrs), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_run_state(sc->vmm_vm, vcpu, vrs.state,
		    vrs.sipi_vector);
		break;
	}
	case VM_GET_FPU: {
		struct vm_fpu_state req;
		const size_t max_len = (PAGESIZE * 2);
		void *kbuf;

		if (ddi_copyin(datap, &req, sizeof (req), md)) {
			error = EFAULT;
			break;
		}
		if (req.len > max_len || req.len == 0) {
			error = EINVAL;
			break;
		}
		kbuf = kmem_zalloc(req.len, KM_SLEEP);
		error = vm_get_fpu(sc->vmm_vm, vcpu, kbuf, req.len);
		if (error == 0) {
			if (ddi_copyout(kbuf, req.buf, req.len, md)) {
				error = EFAULT;
			}
		}
		kmem_free(kbuf, req.len);
		break;
	}
	case VM_SET_FPU: {
		struct vm_fpu_state req;
		const size_t max_len = (PAGESIZE * 2);
		void *kbuf;

		if (ddi_copyin(datap, &req, sizeof (req), md)) {
			error = EFAULT;
			break;
		}
		if (req.len > max_len || req.len == 0) {
			error = EINVAL;
			break;
		}
		kbuf = kmem_alloc(req.len, KM_SLEEP);
		if (ddi_copyin(req.buf, kbuf, req.len, md)) {
			error = EFAULT;
		} else {
			error = vm_set_fpu(sc->vmm_vm, vcpu, kbuf, req.len);
		}
		kmem_free(kbuf, req.len);
		break;
	}
	case VM_GET_CPUID: {
		struct vm_vcpu_cpuid_config cfg;
		struct vcpu_cpuid_entry *entries = NULL;

		if (ddi_copyin(datap, &cfg, sizeof (cfg), md)) {
			error = EFAULT;
			break;
		}
		if (cfg.vvcc_nent > VMM_MAX_CPUID_ENTRIES) {
			error = EINVAL;
			break;
		}

		const size_t entries_size =
		    cfg.vvcc_nent * sizeof (struct vcpu_cpuid_entry);
		if (entries_size != 0) {
			entries = kmem_zalloc(entries_size, KM_SLEEP);
		}

		vcpu_cpuid_config_t vm_cfg = {
			.vcc_nent = cfg.vvcc_nent,
			.vcc_entries = entries,
		};
		error = vm_get_cpuid(sc->vmm_vm, vcpu, &vm_cfg);

		/*
		 * Only attempt to copy out the resultant entries if we were
		 * able to query them from the instance.  The flags and number
		 * of entries are emitted regardless.
		 */
		cfg.vvcc_flags = vm_cfg.vcc_flags;
		cfg.vvcc_nent = vm_cfg.vcc_nent;
		if (entries != NULL) {
			if (error == 0 && ddi_copyout(entries, cfg.vvcc_entries,
			    entries_size, md) != 0) {
				error = EFAULT;
			}

			kmem_free(entries, entries_size);
		}

		if (ddi_copyout(&cfg, datap, sizeof (cfg), md) != 0) {
			error = EFAULT;
		}
		break;
	}
	case VM_SET_CPUID: {
		struct vm_vcpu_cpuid_config cfg;
		struct vcpu_cpuid_entry *entries = NULL;
		size_t entries_size = 0;

		if (ddi_copyin(datap, &cfg, sizeof (cfg), md)) {
			error = EFAULT;
			break;
		}
		if (cfg.vvcc_nent > VMM_MAX_CPUID_ENTRIES) {
			error = EFBIG;
			break;
		}
		if ((cfg.vvcc_flags & VCC_FLAG_LEGACY_HANDLING) != 0) {
			/*
			 * If we are being instructed to use "legacy" handling,
			 * then no entries should be provided, since the static
			 * in-kernel masking will be used.
			 */
			if (cfg.vvcc_nent != 0) {
				error = EINVAL;
				break;
			}
		} else if (cfg.vvcc_nent != 0) {
			entries_size =
			    cfg.vvcc_nent * sizeof (struct vcpu_cpuid_entry);
			entries = kmem_alloc(entries_size, KM_SLEEP);

			if (ddi_copyin(cfg.vvcc_entries, entries, entries_size,
			    md) != 0) {
				error = EFAULT;
				kmem_free(entries, entries_size);
				break;
			}
		}

		vcpu_cpuid_config_t vm_cfg = {
			.vcc_flags = cfg.vvcc_flags,
			.vcc_nent = cfg.vvcc_nent,
			.vcc_entries = entries,
		};
		error = vm_set_cpuid(sc->vmm_vm, vcpu, &vm_cfg);

		if (entries != NULL) {
			kmem_free(entries, entries_size);
		}
		break;
	}
	case VM_LEGACY_CPUID: {
		struct vm_legacy_cpuid vlc;
		if (ddi_copyin(datap, &vlc, sizeof (vlc), md)) {
			error = EFAULT;
			break;
		}
		vlc.vlc_vcpuid = vcpu;

		legacy_emulate_cpuid(sc->vmm_vm, vcpu, &vlc.vlc_eax,
		    &vlc.vlc_ebx, &vlc.vlc_ecx, &vlc.vlc_edx);

		if (ddi_copyout(&vlc, datap, sizeof (vlc), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_SET_KERNEMU_DEV:
	case VM_GET_KERNEMU_DEV: {
		struct vm_readwrite_kernemu_device kemu;
		size_t size = 0;

		if (ddi_copyin(datap, &kemu, sizeof (kemu), md)) {
			error = EFAULT;
			break;
		}

		if (kemu.access_width > 3) {
			error = EINVAL;
			break;
		}
		size = (1 << kemu.access_width);
		ASSERT(size >= 1 && size <= 8);

		if (cmd == VM_SET_KERNEMU_DEV) {
			error = vm_service_mmio_write(sc->vmm_vm, vcpu,
			    kemu.gpa, kemu.value, size);
		} else {
			error = vm_service_mmio_read(sc->vmm_vm, vcpu,
			    kemu.gpa, &kemu.value, size);
		}

		if (error == 0) {
			if (ddi_copyout(&kemu, datap, sizeof (kemu), md)) {
				error = EFAULT;
				break;
			}
		}
		break;
	}

	case VM_GET_CAPABILITY: {
		struct vm_capability vmcap;

		if (ddi_copyin(datap, &vmcap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_capability(sc->vmm_vm, vcpu, vmcap.captype,
		    &vmcap.capval);
		if (error == 0 &&
		    ddi_copyout(&vmcap, datap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_CAPABILITY: {
		struct vm_capability vmcap;

		if (ddi_copyin(datap, &vmcap, sizeof (vmcap), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_capability(sc->vmm_vm, vcpu, vmcap.captype,
		    vmcap.capval);
		break;
	}
	case VM_SET_X2APIC_STATE: {
		struct vm_x2apic x2apic;

		if (ddi_copyin(datap, &x2apic, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		error = vm_set_x2apic_state(sc->vmm_vm, vcpu, x2apic.state);
		break;
	}
	case VM_GET_X2APIC_STATE: {
		struct vm_x2apic x2apic;

		if (ddi_copyin(datap, &x2apic, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		error = vm_get_x2apic_state(sc->vmm_vm, x2apic.cpuid,
		    &x2apic.state);
		if (error == 0 &&
		    ddi_copyout(&x2apic, datap, sizeof (x2apic), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GET_GPA_PMAP: {
		/*
		 * Until there is a necessity to leak EPT/RVI PTE values to
		 * userspace, this will remain unimplemented
		 */
		error = EINVAL;
		break;
	}
	case VM_GET_HPET_CAPABILITIES: {
		struct vm_hpet_cap hpetcap;

		error = vhpet_getcap(&hpetcap);
		if (error == 0 &&
		    ddi_copyout(&hpetcap, datap, sizeof (hpetcap), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GLA2GPA: {
		struct vm_gla2gpa gg;

		if (ddi_copyin(datap, &gg, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		gg.vcpuid = vcpu;
		error = vm_gla2gpa(sc->vmm_vm, vcpu, &gg.paging, gg.gla,
		    gg.prot, &gg.gpa, &gg.fault);
		if (error == 0 && ddi_copyout(&gg, datap, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_GLA2GPA_NOFAULT: {
		struct vm_gla2gpa gg;

		if (ddi_copyin(datap, &gg, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		gg.vcpuid = vcpu;
		error = vm_gla2gpa_nofault(sc->vmm_vm, vcpu, &gg.paging,
		    gg.gla, gg.prot, &gg.gpa, &gg.fault);
		if (error == 0 && ddi_copyout(&gg, datap, sizeof (gg), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_ACTIVATE_CPU:
		error = vm_activate_cpu(sc->vmm_vm, vcpu);
		break;

	case VM_SUSPEND_CPU:
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			error = EFAULT;
		} else {
			error = vm_suspend_cpu(sc->vmm_vm, vcpu);
		}
		break;

	case VM_RESUME_CPU:
		if (ddi_copyin(datap, &vcpu, sizeof (vcpu), md)) {
			error = EFAULT;
		} else {
			error = vm_resume_cpu(sc->vmm_vm, vcpu);
		}
		break;

	case VM_GET_CPUS: {
		struct vm_cpuset vm_cpuset;
		cpuset_t tempset;
		void *srcp = &tempset;
		int size;

		if (ddi_copyin(datap, &vm_cpuset, sizeof (vm_cpuset), md)) {
			error = EFAULT;
			break;
		}

		/* Be more generous about sizing since our cpuset_t is large. */
		size = vm_cpuset.cpusetsize;
		if (size <= 0 || size > sizeof (cpuset_t)) {
			error = ERANGE;
		}
		/*
		 * If they want a ulong_t or less, make sure they receive the
		 * low bits with all the useful information.
		 */
		if (size <= sizeof (tempset.cpub[0])) {
			srcp = &tempset.cpub[0];
		}

		if (vm_cpuset.which == VM_ACTIVE_CPUS) {
			tempset = vm_active_cpus(sc->vmm_vm);
		} else if (vm_cpuset.which == VM_SUSPENDED_CPUS) {
			tempset = vm_suspended_cpus(sc->vmm_vm);
		} else if (vm_cpuset.which == VM_DEBUG_CPUS) {
			tempset = vm_debug_cpus(sc->vmm_vm);
		} else {
			error = EINVAL;
		}

		ASSERT(size > 0 && size <= sizeof (tempset));
		if (error == 0 &&
		    ddi_copyout(srcp, vm_cpuset.cpus, size, md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_SET_INTINFO: {
		struct vm_intinfo vmii;

		if (ddi_copyin(datap, &vmii, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		error = vm_exit_intinfo(sc->vmm_vm, vcpu, vmii.info1);
		break;
	}
	case VM_GET_INTINFO: {
		struct vm_intinfo vmii;

		vmii.vcpuid = vcpu;
		error = vm_get_intinfo(sc->vmm_vm, vcpu, &vmii.info1,
		    &vmii.info2);
		if (error == 0 &&
		    ddi_copyout(&vmii, datap, sizeof (vmii), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_RTC_WRITE: {
		struct vm_rtc_data rtcdata;

		if (ddi_copyin(datap, &rtcdata, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_nvram_write(sc->vmm_vm, rtcdata.offset,
		    rtcdata.value);
		break;
	}
	case VM_RTC_READ: {
		struct vm_rtc_data rtcdata;

		if (ddi_copyin(datap, &rtcdata, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_nvram_read(sc->vmm_vm, rtcdata.offset,
		    &rtcdata.value);
		if (error == 0 &&
		    ddi_copyout(&rtcdata, datap, sizeof (rtcdata), md)) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_RTC_SETTIME: {
		struct vm_rtc_time rtctime;

		if (ddi_copyin(datap, &rtctime, sizeof (rtctime), md)) {
			error = EFAULT;
			break;
		}
		error = vrtc_set_time(sc->vmm_vm, rtctime.secs);
		break;
	}
	case VM_RTC_GETTIME: {
		struct vm_rtc_time rtctime;

		rtctime.secs = vrtc_get_time(sc->vmm_vm);
		if (ddi_copyout(&rtctime, datap, sizeof (rtctime), md)) {
			error = EFAULT;
			break;
		}
		break;
	}

	case VM_PMTMR_LOCATE: {
		uint16_t port = arg;
		error = vpmtmr_set_location(sc->vmm_vm, port);
		break;
	}

	case VM_RESTART_INSTRUCTION:
		error = vm_restart_instruction(sc->vmm_vm, vcpu);
		break;

	case VM_SET_TOPOLOGY: {
		struct vm_cpu_topology topo;

		if (ddi_copyin(datap, &topo, sizeof (topo), md) != 0) {
			error = EFAULT;
			break;
		}
		error = vm_set_topology(sc->vmm_vm, topo.sockets, topo.cores,
		    topo.threads, topo.maxcpus);
		break;
	}
	case VM_GET_TOPOLOGY: {
		struct vm_cpu_topology topo;

		vm_get_topology(sc->vmm_vm, &topo.sockets, &topo.cores,
		    &topo.threads, &topo.maxcpus);
		if (ddi_copyout(&topo, datap, sizeof (topo), md) != 0) {
			error = EFAULT;
			break;
		}
		break;
	}
	case VM_DEVMEM_GETOFFSET: {
		struct vm_devmem_offset vdo;
		vmm_devmem_entry_t *de;

		if (ddi_copyin(datap, &vdo, sizeof (vdo), md) != 0) {
			error = EFAULT;
			break;
		}

		de = vmmdev_devmem_find(sc, vdo.segid);
		if (de != NULL) {
			vdo.offset = de->vde_off;
			if (ddi_copyout(&vdo, datap, sizeof (vdo), md) != 0) {
				error = EFAULT;
			}
		} else {
			error = ENOENT;
		}
		break;
	}
	case VM_TRACK_DIRTY_PAGES: {
		const size_t max_track_region_len = 8 * PAGESIZE * 8 * PAGESIZE;
		struct vmm_dirty_tracker tracker;
		uint8_t *bitmap;
		size_t len;

		if (ddi_copyin(datap, &tracker, sizeof (tracker), md) != 0) {
			error = EFAULT;
			break;
		}
		if ((tracker.vdt_start_gpa & PAGEOFFSET) != 0) {
			error = EINVAL;
			break;
		}
		if (tracker.vdt_len == 0) {
			break;
		}
		if ((tracker.vdt_len & PAGEOFFSET) != 0) {
			error = EINVAL;
			break;
		}
		if (tracker.vdt_len > max_track_region_len) {
			error = EINVAL;
			break;
		}
		len = roundup(tracker.vdt_len / PAGESIZE, 8) / 8;
		bitmap = kmem_zalloc(len, KM_SLEEP);
		error = vm_track_dirty_pages(sc->vmm_vm, tracker.vdt_start_gpa,
		    tracker.vdt_len, bitmap);
		if (error == 0 &&
		    ddi_copyout(bitmap, tracker.vdt_pfns, len, md) != 0) {
			error = EFAULT;
		}
		kmem_free(bitmap, len);

		break;
	}
	case VM_WRLOCK_CYCLE: {
		/*
		 * Present a test mechanism to acquire/release the write lock
		 * on the VM without any other effects.
		 */
		break;
	}
	case VM_DATA_READ: {
		struct vm_data_xfer vdx;

		if (ddi_copyin(datap, &vdx, sizeof (vdx), md) != 0) {
			error = EFAULT;
			break;
		}
		if ((vdx.vdx_flags & ~VDX_FLAGS_VALID) != 0) {
			error = EINVAL;
			break;
		}
		if (vdx.vdx_len > VM_DATA_XFER_LIMIT) {
			error = EFBIG;
			break;
		}

		const size_t len = vdx.vdx_len;
		void *buf = NULL;
		if (len != 0) {
			const void *udata = vdx.vdx_data;

			buf = kmem_alloc(len, KM_SLEEP);
			if ((vdx.vdx_flags & VDX_FLAG_READ_COPYIN) == 0) {
				bzero(buf, len);
			} else if (ddi_copyin(udata, buf, len, md) != 0) {
				kmem_free(buf, len);
				error = EFAULT;
				break;
			}
		}

		vdx.vdx_result_len = 0;
		vmm_data_req_t req = {
			.vdr_class = vdx.vdx_class,
			.vdr_version = vdx.vdx_version,
			.vdr_flags = vdx.vdx_flags,
			.vdr_len = len,
			.vdr_data = buf,
			.vdr_result_len = &vdx.vdx_result_len,
		};
		error = vmm_data_read(sc->vmm_vm, vdx.vdx_vcpuid, &req);

		if (error == 0 && buf != NULL) {
			if (ddi_copyout(buf, vdx.vdx_data, len, md) != 0) {
				error = EFAULT;
			}
		}

		/*
		 * Copy out the transfer request so that the value of
		 * vdx_result_len can be made available, regardless of any
		 * error(s) which may have occurred.
		 */
		if (ddi_copyout(&vdx, datap, sizeof (vdx), md) != 0) {
			error = (error != 0) ? error : EFAULT;
		}

		if (buf != NULL) {
			kmem_free(buf, len);
		}
		break;
	}
	case VM_DATA_WRITE: {
		struct vm_data_xfer vdx;

		if (ddi_copyin(datap, &vdx, sizeof (vdx), md) != 0) {
			error = EFAULT;
			break;
		}
		if ((vdx.vdx_flags & ~VDX_FLAGS_VALID) != 0) {
			error = EINVAL;
			break;
		}
		if (vdx.vdx_len > VM_DATA_XFER_LIMIT) {
			error = EFBIG;
			break;
		}

		const size_t len = vdx.vdx_len;
		void *buf = NULL;
		if (len != 0) {
			buf = kmem_alloc(len, KM_SLEEP);
			if (ddi_copyin(vdx.vdx_data, buf, len, md) != 0) {
				kmem_free(buf, len);
				error = EFAULT;
				break;
			}
		}

		vdx.vdx_result_len = 0;
		vmm_data_req_t req = {
			.vdr_class = vdx.vdx_class,
			.vdr_version = vdx.vdx_version,
			.vdr_flags = vdx.vdx_flags,
			.vdr_len = len,
			.vdr_data = buf,
			.vdr_result_len = &vdx.vdx_result_len,
		};
		if (vmm_allow_state_writes == 0) {
			/* XXX: Play it safe for now */
			error = EPERM;
		} else {
			error = vmm_data_write(sc->vmm_vm, vdx.vdx_vcpuid,
			    &req);
		}

		if (error == 0 && buf != NULL &&
		    (vdx.vdx_flags & VDX_FLAG_WRITE_COPYOUT) != 0) {
			if (ddi_copyout(buf, vdx.vdx_data, len, md) != 0) {
				error = EFAULT;
			}
		}

		/*
		 * Copy out the transfer request so that the value of
		 * vdx_result_len can be made available, regardless of any
		 * error(s) which may have occurred.
		 */
		if (ddi_copyout(&vdx, datap, sizeof (vdx), md) != 0) {
			error = (error != 0) ? error : EFAULT;
		}

		if (buf != NULL) {
			kmem_free(buf, len);
		}
		break;
	}

	case VM_PAUSE: {
		error = vm_pause_instance(sc->vmm_vm);
		break;
	}
	case VM_RESUME: {
		error = vm_resume_instance(sc->vmm_vm);
		break;
	}

	default:
		error = ENOTTY;
		break;
	}

	/* Release exclusion resources */
	switch (lock_type) {
	case LOCK_NONE:
		break;
	case LOCK_VCPU:
		vcpu_unlock_one(sc, vcpu);
		break;
	case LOCK_READ_HOLD:
		vmm_read_unlock(sc);
		break;
	case LOCK_WRITE_HOLD:
		vmm_write_unlock(sc);
		break;
	default:
		panic("unexpected lock type");
		break;
	}

	return (error);
}

static vmm_softc_t *
vmm_lookup(const char *name)
{
	list_t *vml = &vmm_list;
	vmm_softc_t *sc;

	ASSERT(MUTEX_HELD(&vmm_mtx));

	for (sc = list_head(vml); sc != NULL; sc = list_next(vml, sc)) {
		if (strcmp(sc->vmm_name, name) == 0) {
			break;
		}
	}

	return (sc);
}

/*
 * Acquire an HMA registration if not already held.
 */
static boolean_t
vmm_hma_acquire(void)
{
	ASSERT(MUTEX_NOT_HELD(&vmm_mtx));

	mutex_enter(&vmmdev_mtx);

	if (vmmdev_hma_reg == NULL) {
		VERIFY3U(vmmdev_hma_ref, ==, 0);
		vmmdev_hma_reg = hma_register(vmmdev_hvm_name);
		if (vmmdev_hma_reg == NULL) {
			cmn_err(CE_WARN, "%s HMA registration failed.",
			    vmmdev_hvm_name);
			mutex_exit(&vmmdev_mtx);
			return (B_FALSE);
		}
	}

	vmmdev_hma_ref++;

	mutex_exit(&vmmdev_mtx);

	return (B_TRUE);
}

/*
 * Release the HMA registration if held and there are no remaining VMs.
 */
static void
vmm_hma_release(void)
{
	ASSERT(MUTEX_NOT_HELD(&vmm_mtx));

	mutex_enter(&vmmdev_mtx);

	VERIFY3U(vmmdev_hma_ref, !=, 0);

	vmmdev_hma_ref--;

	if (vmmdev_hma_ref == 0) {
		VERIFY(vmmdev_hma_reg != NULL);
		hma_unregister(vmmdev_hma_reg);
		vmmdev_hma_reg = NULL;
	}
	mutex_exit(&vmmdev_mtx);
}

static int
vmmdev_do_vm_create(const struct vm_create_req *req, cred_t *cr)
{
	vmm_softc_t	*sc = NULL;
	minor_t		minor;
	int		error = ENOMEM;
	size_t		len;
	const char	*name = req->name;

	len = strnlen(name, VM_MAX_NAMELEN);
	if (len == 0) {
		return (EINVAL);
	}
	if (len >= VM_MAX_NAMELEN) {
		return (ENAMETOOLONG);
	}
	if (strchr(name, '/') != NULL) {
		return (EINVAL);
	}

	if (!vmm_hma_acquire())
		return (ENXIO);

	mutex_enter(&vmm_mtx);

	/* Look for duplicate names */
	if (vmm_lookup(name) != NULL) {
		mutex_exit(&vmm_mtx);
		vmm_hma_release();
		return (EEXIST);
	}

	/* Allow only one instance per non-global zone. */
	if (!INGLOBALZONE(curproc)) {
		for (sc = list_head(&vmm_list); sc != NULL;
		    sc = list_next(&vmm_list, sc)) {
			if (sc->vmm_zone == curzone) {
				mutex_exit(&vmm_mtx);
				vmm_hma_release();
				return (EINVAL);
			}
		}
	}

	minor = id_alloc(vmm_minors);
	if (ddi_soft_state_zalloc(vmm_statep, minor) != DDI_SUCCESS) {
		goto fail;
	} else if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		ddi_soft_state_free(vmm_statep, minor);
		goto fail;
	} else if (ddi_create_minor_node(vmmdev_dip, name, S_IFCHR, minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	if (vmm_kstat_alloc(sc, minor, cr) != 0) {
		goto fail;
	}

	error = vm_create(req->flags, &sc->vmm_vm);
	if (error == 0) {
		/* Complete VM intialization and report success. */
		(void) strlcpy(sc->vmm_name, name, sizeof (sc->vmm_name));
		sc->vmm_minor = minor;
		list_create(&sc->vmm_devmem_list, sizeof (vmm_devmem_entry_t),
		    offsetof(vmm_devmem_entry_t, vde_node));

		list_create(&sc->vmm_holds, sizeof (vmm_hold_t),
		    offsetof(vmm_hold_t, vmh_node));
		cv_init(&sc->vmm_cv, NULL, CV_DEFAULT, NULL);

		mutex_init(&sc->vmm_lease_lock, NULL, MUTEX_DEFAULT, NULL);
		list_create(&sc->vmm_lease_list, sizeof (vmm_lease_t),
		    offsetof(vmm_lease_t, vml_node));
		cv_init(&sc->vmm_lease_cv, NULL, CV_DEFAULT, NULL);
		rw_init(&sc->vmm_rwlock, NULL, RW_DEFAULT, NULL);

		sc->vmm_zone = crgetzone(cr);
		zone_hold(sc->vmm_zone);
		vmm_zsd_add_vm(sc);
		vmm_kstat_init(sc);

		list_insert_tail(&vmm_list, sc);
		mutex_exit(&vmm_mtx);
		return (0);
	}

	vmm_kstat_fini(sc);
	ddi_remove_minor_node(vmmdev_dip, name);
fail:
	id_free(vmm_minors, minor);
	if (sc != NULL) {
		ddi_soft_state_free(vmm_statep, minor);
	}
	mutex_exit(&vmm_mtx);
	vmm_hma_release();

	return (error);
}

/*
 * Bhyve 'Driver' Interface
 *
 * While many devices are emulated in the bhyve userspace process, there are
 * others with performance constraints which require that they run mostly or
 * entirely in-kernel.  For those not integrated directly into bhyve, an API is
 * needed so they can query/manipulate the portions of VM state needed to
 * fulfill their purpose.
 *
 * This includes:
 * - Translating guest-physical addresses to host-virtual pointers
 * - Injecting MSIs
 * - Hooking IO port addresses
 *
 * The vmm_drv interface exists to provide that functionality to its consumers.
 * (At this time, 'viona' is the only user)
 */
int
vmm_drv_hold(file_t *fp, cred_t *cr, vmm_hold_t **holdp)
{
	vnode_t *vp = fp->f_vnode;
	const dev_t dev = vp->v_rdev;
	vmm_softc_t *sc;
	vmm_hold_t *hold;
	int err = 0;

	if (vp->v_type != VCHR) {
		return (ENXIO);
	}
	const major_t major = getmajor(dev);
	const minor_t minor = getminor(dev);

	mutex_enter(&vmmdev_mtx);
	if (vmmdev_dip == NULL || major != ddi_driver_major(vmmdev_dip)) {
		mutex_exit(&vmmdev_mtx);
		return (ENOENT);
	}
	mutex_enter(&vmm_mtx);
	mutex_exit(&vmmdev_mtx);

	if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		err = ENOENT;
		goto out;
	}
	/* XXXJOY: check cred permissions against instance */

	if ((sc->vmm_flags & VMM_DESTROY) != 0) {
		err = EBUSY;
		goto out;
	}

	hold = kmem_zalloc(sizeof (*hold), KM_SLEEP);
	hold->vmh_sc = sc;
	hold->vmh_release_req = B_FALSE;

	list_insert_tail(&sc->vmm_holds, hold);
	sc->vmm_flags |= VMM_HELD;
	*holdp = hold;

out:
	mutex_exit(&vmm_mtx);
	return (err);
}

void
vmm_drv_rele(vmm_hold_t *hold)
{
	vmm_softc_t *sc;
	bool hma_release = false;

	ASSERT(hold != NULL);
	ASSERT(hold->vmh_sc != NULL);
	VERIFY(hold->vmh_ioport_hook_cnt == 0);

	mutex_enter(&vmm_mtx);
	sc = hold->vmh_sc;
	list_remove(&sc->vmm_holds, hold);
	kmem_free(hold, sizeof (*hold));

	if (list_is_empty(&sc->vmm_holds)) {
		sc->vmm_flags &= ~VMM_HELD;

		/*
		 * Since outstanding holds would prevent instance destruction
		 * from completing, attempt to finish it now if it was already
		 * set in motion.
		 */
		if ((sc->vmm_flags & VMM_DESTROY) != 0) {
			VERIFY0(vmm_destroy_locked(sc, VDO_DEFAULT,
			    &hma_release));
		}
	}
	mutex_exit(&vmm_mtx);

	if (hma_release) {
		vmm_hma_release();
	}
}

boolean_t
vmm_drv_release_reqd(vmm_hold_t *hold)
{
	ASSERT(hold != NULL);

	return (hold->vmh_release_req);
}

vmm_lease_t *
vmm_drv_lease_sign(vmm_hold_t *hold, boolean_t (*expiref)(void *), void *arg)
{
	vmm_softc_t *sc = hold->vmh_sc;
	vmm_lease_t *lease;

	ASSERT3P(expiref, !=, NULL);

	if (hold->vmh_release_req) {
		return (NULL);
	}

	lease = kmem_alloc(sizeof (*lease), KM_SLEEP);
	list_link_init(&lease->vml_node);
	lease->vml_expire_func = expiref;
	lease->vml_expire_arg = arg;
	lease->vml_expired = B_FALSE;
	lease->vml_break_deferred = B_FALSE;
	lease->vml_hold = hold;
	/* cache the VM pointer for one less pointer chase */
	lease->vml_vm = sc->vmm_vm;
	lease->vml_vmclient = vmspace_client_alloc(vm_get_vmspace(sc->vmm_vm));

	mutex_enter(&sc->vmm_lease_lock);
	while (sc->vmm_lease_blocker != 0) {
		cv_wait(&sc->vmm_lease_cv, &sc->vmm_lease_lock);
	}
	list_insert_tail(&sc->vmm_lease_list, lease);
	vmm_read_lock(sc);
	mutex_exit(&sc->vmm_lease_lock);

	return (lease);
}

static void
vmm_lease_break_locked(vmm_softc_t *sc, vmm_lease_t *lease)
{
	ASSERT(MUTEX_HELD(&sc->vmm_lease_lock));

	list_remove(&sc->vmm_lease_list, lease);
	vmm_read_unlock(sc);
	vmc_destroy(lease->vml_vmclient);
	kmem_free(lease, sizeof (*lease));
}

static void
vmm_lease_block(vmm_softc_t *sc)
{
	mutex_enter(&sc->vmm_lease_lock);
	VERIFY3U(sc->vmm_lease_blocker, !=, UINT_MAX);
	sc->vmm_lease_blocker++;
	if (sc->vmm_lease_blocker == 1) {
		list_t *list = &sc->vmm_lease_list;
		vmm_lease_t *lease = list_head(list);

		while (lease != NULL) {
			void *arg = lease->vml_expire_arg;
			boolean_t (*expiref)(void *) = lease->vml_expire_func;
			boolean_t sync_break = B_FALSE;

			/*
			 * Since the lease expiration notification may
			 * need to take locks which would deadlock with
			 * vmm_lease_lock, drop it across the call.
			 *
			 * We are the only one allowed to manipulate
			 * vmm_lease_list right now, so it is safe to
			 * continue iterating through it after
			 * reacquiring the lock.
			 */
			lease->vml_expired = B_TRUE;
			mutex_exit(&sc->vmm_lease_lock);
			sync_break = expiref(arg);
			mutex_enter(&sc->vmm_lease_lock);

			if (sync_break) {
				vmm_lease_t *next;

				/*
				 * These leases which are synchronously broken
				 * result in vmm_read_unlock() calls from a
				 * different thread than the corresponding
				 * vmm_read_lock().  This is acceptable, given
				 * that the rwlock underpinning the whole
				 * mechanism tolerates the behavior.  This
				 * flexibility is _only_ afforded to VM read
				 * lock (RW_READER) holders.
				 */
				next = list_next(list, lease);
				vmm_lease_break_locked(sc, lease);
				lease = next;
			} else {
				lease = list_next(list, lease);
			}
		}

		/* Process leases which were not broken synchronously. */
		while (!list_is_empty(list)) {
			/*
			 * Although the nested loops are quadratic, the number
			 * of leases is small.
			 */
			lease = list_head(list);
			while (lease != NULL) {
				vmm_lease_t *next = list_next(list, lease);
				if (lease->vml_break_deferred) {
					vmm_lease_break_locked(sc, lease);
				}
				lease = next;
			}
			if (list_is_empty(list)) {
				break;
			}
			cv_wait(&sc->vmm_lease_cv, &sc->vmm_lease_lock);
		}
		/* Wake anyone else waiting for the lease list to be empty  */
		cv_broadcast(&sc->vmm_lease_cv);
	} else {
		list_t *list = &sc->vmm_lease_list;

		/*
		 * Some other thread beat us to the duty of lease cleanup.
		 * Wait until that is complete.
		 */
		while (!list_is_empty(list)) {
			cv_wait(&sc->vmm_lease_cv, &sc->vmm_lease_lock);
		}
	}
	mutex_exit(&sc->vmm_lease_lock);
}

static void
vmm_lease_unblock(vmm_softc_t *sc)
{
	mutex_enter(&sc->vmm_lease_lock);
	VERIFY3U(sc->vmm_lease_blocker, !=, 0);
	sc->vmm_lease_blocker--;
	if (sc->vmm_lease_blocker == 0) {
		cv_broadcast(&sc->vmm_lease_cv);
	}
	mutex_exit(&sc->vmm_lease_lock);
}

void
vmm_drv_lease_break(vmm_hold_t *hold, vmm_lease_t *lease)
{
	vmm_softc_t *sc = hold->vmh_sc;

	VERIFY3P(hold, ==, lease->vml_hold);
	VERIFY(!lease->vml_break_deferred);

	mutex_enter(&sc->vmm_lease_lock);
	if (sc->vmm_lease_blocker == 0) {
		vmm_lease_break_locked(sc, lease);
	} else {
		/*
		 * Defer the lease-breaking to whichever thread is currently
		 * cleaning up all leases as part of a vmm_lease_block() call.
		 */
		lease->vml_break_deferred = B_TRUE;
		cv_broadcast(&sc->vmm_lease_cv);
	}
	mutex_exit(&sc->vmm_lease_lock);
}

boolean_t
vmm_drv_lease_expired(vmm_lease_t *lease)
{
	return (lease->vml_expired);
}

vmm_page_t *
vmm_drv_page_hold(vmm_lease_t *lease, uintptr_t gpa, int prot)
{
	ASSERT(lease != NULL);
	ASSERT0(gpa & PAGEOFFSET);

	return ((vmm_page_t *)vmc_hold(lease->vml_vmclient, gpa, prot));
}


/* Ensure that flags mirrored by vmm_drv interface properly match up */
CTASSERT(VMPF_DEFER_DIRTY == VPF_DEFER_DIRTY);

vmm_page_t *
vmm_drv_page_hold_ext(vmm_lease_t *lease, uintptr_t gpa, int prot, int flags)
{
	ASSERT(lease != NULL);
	ASSERT0(gpa & PAGEOFFSET);

	vmm_page_t *page =
	    (vmm_page_t *)vmc_hold_ext(lease->vml_vmclient, gpa, prot, flags);
	return (page);
}

void
vmm_drv_page_release(vmm_page_t *vmmp)
{
	(void) vmp_release((vm_page_t *)vmmp);
}

void
vmm_drv_page_release_chain(vmm_page_t *vmmp)
{
	(void) vmp_release_chain((vm_page_t *)vmmp);
}

const void *
vmm_drv_page_readable(const vmm_page_t *vmmp)
{
	return (vmp_get_readable((const vm_page_t *)vmmp));
}

void *
vmm_drv_page_writable(const vmm_page_t *vmmp)
{
	return (vmp_get_writable((const vm_page_t *)vmmp));
}

void
vmm_drv_page_mark_dirty(vmm_page_t *vmmp)
{
	return (vmp_mark_dirty((vm_page_t *)vmmp));
}

void
vmm_drv_page_chain(vmm_page_t *vmmp, vmm_page_t *to_chain)
{
	vmp_chain((vm_page_t *)vmmp, (vm_page_t *)to_chain);
}

vmm_page_t *
vmm_drv_page_next(const vmm_page_t *vmmp)
{
	return ((vmm_page_t *)vmp_next((vm_page_t *)vmmp));
}

int
vmm_drv_msi(vmm_lease_t *lease, uint64_t addr, uint64_t msg)
{
	ASSERT(lease != NULL);

	return (lapic_intr_msi(lease->vml_vm, addr, msg));
}

int
vmm_drv_ioport_hook(vmm_hold_t *hold, uint16_t ioport, vmm_drv_iop_cb_t func,
    void *arg, void **cookie)
{
	vmm_softc_t *sc;
	int err;

	ASSERT(hold != NULL);
	ASSERT(cookie != NULL);

	sc = hold->vmh_sc;
	mutex_enter(&vmm_mtx);
	/* Confirm that hook installation is not blocked */
	if ((sc->vmm_flags & VMM_BLOCK_HOOK) != 0) {
		mutex_exit(&vmm_mtx);
		return (EBUSY);
	}
	/*
	 * Optimistically record an installed hook which will prevent a block
	 * from being asserted while the mutex is dropped.
	 */
	hold->vmh_ioport_hook_cnt++;
	mutex_exit(&vmm_mtx);

	vmm_write_lock(sc);
	err = vm_ioport_hook(sc->vmm_vm, ioport, (ioport_handler_t)func,
	    arg, cookie);
	vmm_write_unlock(sc);

	if (err != 0) {
		mutex_enter(&vmm_mtx);
		/* Walk back optimism about the hook installation */
		hold->vmh_ioport_hook_cnt--;
		mutex_exit(&vmm_mtx);
	}
	return (err);
}

void
vmm_drv_ioport_unhook(vmm_hold_t *hold, void **cookie)
{
	vmm_softc_t *sc;

	ASSERT(hold != NULL);
	ASSERT(cookie != NULL);
	ASSERT(hold->vmh_ioport_hook_cnt != 0);

	sc = hold->vmh_sc;
	vmm_write_lock(sc);
	vm_ioport_unhook(sc->vmm_vm, cookie);
	vmm_write_unlock(sc);

	mutex_enter(&vmm_mtx);
	hold->vmh_ioport_hook_cnt--;
	mutex_exit(&vmm_mtx);
}

static void
vmm_drv_purge(vmm_softc_t *sc)
{
	ASSERT(MUTEX_HELD(&vmm_mtx));

	if ((sc->vmm_flags & VMM_HELD) != 0) {
		vmm_hold_t *hold;

		for (hold = list_head(&sc->vmm_holds); hold != NULL;
		    hold = list_next(&sc->vmm_holds, hold)) {
			hold->vmh_release_req = B_TRUE;
		}

		/*
		 * Require that all leases on the instance be broken, now that
		 * all associated holds have been marked as needing release.
		 *
		 * Dropping vmm_mtx is not strictly necessary, but if any of the
		 * lessees are slow to respond, it would be nice to leave it
		 * available for other parties.
		 */
		mutex_exit(&vmm_mtx);
		vmm_lease_block(sc);
		vmm_lease_unblock(sc);
		mutex_enter(&vmm_mtx);
	}
}

static int
vmm_drv_block_hook(vmm_softc_t *sc, boolean_t enable_block)
{
	int err = 0;

	mutex_enter(&vmm_mtx);
	if (!enable_block) {
		VERIFY((sc->vmm_flags & VMM_BLOCK_HOOK) != 0);

		sc->vmm_flags &= ~VMM_BLOCK_HOOK;
		goto done;
	}

	/* If any holds have hooks installed, the block is a failure */
	if (!list_is_empty(&sc->vmm_holds)) {
		vmm_hold_t *hold;

		for (hold = list_head(&sc->vmm_holds); hold != NULL;
		    hold = list_next(&sc->vmm_holds, hold)) {
			if (hold->vmh_ioport_hook_cnt != 0) {
				err = EBUSY;
				goto done;
			}
		}
	}
	sc->vmm_flags |= VMM_BLOCK_HOOK;

done:
	mutex_exit(&vmm_mtx);
	return (err);
}


static void
vmm_destroy_begin(vmm_softc_t *sc, vmm_destroy_opts_t opts)
{
	ASSERT(MUTEX_HELD(&vmm_mtx));
	ASSERT0(sc->vmm_flags & VMM_DESTROY);

	sc->vmm_flags |= VMM_DESTROY;

	/*
	 * Lock and unlock all of the vCPUs to ensure that they are kicked out
	 * of guest context, being unable to return now that the instance is
	 * marked for destruction.
	 */
	const int maxcpus = vm_get_maxcpus(sc->vmm_vm);
	for (int vcpu = 0; vcpu < maxcpus; vcpu++) {
		vcpu_lock_one(sc, vcpu);
		vcpu_unlock_one(sc, vcpu);
	}

	vmmdev_devmem_purge(sc);
	if ((opts & VDO_NO_CLEAN_ZSD) == 0) {
		/*
		 * The ZSD should be cleaned up now, unless destruction of the
		 * instance was initated by destruction of the containing zone,
		 * in which case the ZSD has already been removed.
		 */
		vmm_zsd_rem_vm(sc);
	}
	zone_rele(sc->vmm_zone);

	vmm_drv_purge(sc);
}

static bool
vmm_destroy_ready(vmm_softc_t *sc)
{
	ASSERT(MUTEX_HELD(&vmm_mtx));

	if ((sc->vmm_flags & (VMM_HELD | VMM_IS_OPEN)) == 0) {
		VERIFY(list_is_empty(&sc->vmm_holds));
		return (true);
	}

	return (false);
}

static void
vmm_destroy_finish(vmm_softc_t *sc)
{
	ASSERT(MUTEX_HELD(&vmm_mtx));
	ASSERT(vmm_destroy_ready(sc));

	list_remove(&vmm_list, sc);
	vmm_kstat_fini(sc);
	vm_destroy(sc->vmm_vm);
	ddi_remove_minor_node(vmmdev_dip, sc->vmm_name);
	(void) devfs_clean(ddi_get_parent(vmmdev_dip), NULL, DV_CLEAN_FORCE);

	const minor_t minor = sc->vmm_minor;
	ddi_soft_state_free(vmm_statep, minor);
	id_free(vmm_minors, minor);
}

/*
 * Initiate or attempt to finish destruction of a VMM instance.
 *
 * This is called from several contexts:
 * - An explicit destroy ioctl is made
 * - A vmm_drv consumer releases its hold (being the last on the instance)
 * - The vmm device is closed, and auto-destruct is enabled
 */
static int
vmm_destroy_locked(vmm_softc_t *sc, vmm_destroy_opts_t opts,
    bool *hma_release)
{
	ASSERT(MUTEX_HELD(&vmm_mtx));

	*hma_release = false;

	/*
	 * When instance destruction begins, it is so marked such that any
	 * further requests to operate the instance will fail.
	 */
	if ((sc->vmm_flags & VMM_DESTROY) == 0) {
		vmm_destroy_begin(sc, opts);
	}

	if (vmm_destroy_ready(sc)) {

		/*
		 * Notify anyone waiting for the destruction to finish.  They
		 * must be clear before we can safely tear down the softc.
		 */
		if (sc->vmm_destroy_waiters != 0) {
			cv_broadcast(&sc->vmm_cv);
			while (sc->vmm_destroy_waiters != 0) {
				cv_wait(&sc->vmm_cv, &vmm_mtx);
			}
		}

		/*
		 * Finish destruction of instance.  After this point, the softc
		 * is freed and cannot be accessed again.
		 *
		 * With destruction complete, the HMA hold can be released
		 */
		vmm_destroy_finish(sc);
		*hma_release = true;
		return (0);
	} else if ((opts & VDO_ATTEMPT_WAIT) != 0) {
		int err = 0;

		sc->vmm_destroy_waiters++;
		while (!vmm_destroy_ready(sc) && err == 0) {
			if (cv_wait_sig(&sc->vmm_cv, &vmm_mtx) <= 0) {
				err = EINTR;
			}
		}
		sc->vmm_destroy_waiters--;

		if (sc->vmm_destroy_waiters == 0) {
			/*
			 * If we were the last waiter, it could be that VM
			 * destruction is waiting on _us_ to proceed with the
			 * final clean-up.
			 */
			cv_signal(&sc->vmm_cv);
		}
		return (err);
	} else {
		/*
		 * Since the instance is not ready for destruction, and the
		 * caller did not ask to wait, consider it a success for now.
		 */
		return (0);
	}
}

void
vmm_zone_vm_destroy(vmm_softc_t *sc)
{
	bool hma_release = false;
	int err;

	mutex_enter(&vmm_mtx);
	err = vmm_destroy_locked(sc, VDO_NO_CLEAN_ZSD, &hma_release);
	mutex_exit(&vmm_mtx);

	VERIFY0(err);

	if (hma_release) {
		vmm_hma_release();
	}
}

static int
vmmdev_do_vm_destroy(const struct vm_destroy_req *req, cred_t *cr)
{
	vmm_softc_t *sc;
	bool hma_release = false;
	int err;

	if (crgetuid(cr) != 0) {
		return (EPERM);
	}

	mutex_enter(&vmm_mtx);
	sc = vmm_lookup(req->name);
	if (sc == NULL) {
		mutex_exit(&vmm_mtx);
		return (ENOENT);
	}
	/*
	 * We don't check this in vmm_lookup() since that function is also used
	 * for validation during create and currently vmm names must be unique.
	 */
	if (!INGLOBALZONE(curproc) && sc->vmm_zone != curzone) {
		mutex_exit(&vmm_mtx);
		return (EPERM);
	}

	err = vmm_destroy_locked(sc, VDO_ATTEMPT_WAIT, &hma_release);
	mutex_exit(&vmm_mtx);

	if (hma_release) {
		vmm_hma_release();
	}

	return (err);
}

#define	VCPU_NAME_BUFLEN	32

static int
vmm_kstat_alloc(vmm_softc_t *sc, minor_t minor, const cred_t *cr)
{
	zoneid_t zid = crgetzoneid(cr);
	int instance = minor;
	kstat_t *ksp;

	ASSERT3P(sc->vmm_kstat_vm, ==, NULL);

	ksp = kstat_create_zone(VMM_MODULE_NAME, instance, "vm",
	    VMM_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (vmm_kstats_t) / sizeof (kstat_named_t), 0, zid);

	if (ksp == NULL) {
		return (-1);
	}
	sc->vmm_kstat_vm = ksp;

	for (uint_t i = 0; i < VM_MAXCPU; i++) {
		char namebuf[VCPU_NAME_BUFLEN];

		ASSERT3P(sc->vmm_kstat_vcpu[i], ==, NULL);

		(void) snprintf(namebuf, VCPU_NAME_BUFLEN, "vcpu%u", i);
		ksp = kstat_create_zone(VMM_MODULE_NAME, instance, namebuf,
		    VMM_KSTAT_CLASS, KSTAT_TYPE_NAMED,
		    sizeof (vmm_vcpu_kstats_t) / sizeof (kstat_named_t),
		    0, zid);
		if (ksp == NULL) {
			goto fail;
		}

		sc->vmm_kstat_vcpu[i] = ksp;
	}

	/*
	 * If this instance is associated with a non-global zone, make its
	 * kstats visible from the GZ.
	 */
	if (zid != GLOBAL_ZONEID) {
		kstat_zone_add(sc->vmm_kstat_vm, GLOBAL_ZONEID);
		for (uint_t i = 0; i < VM_MAXCPU; i++) {
			kstat_zone_add(sc->vmm_kstat_vcpu[i], GLOBAL_ZONEID);
		}
	}

	return (0);

fail:
	for (uint_t i = 0; i < VM_MAXCPU; i++) {
		if (sc->vmm_kstat_vcpu[i] != NULL) {
			kstat_delete(sc->vmm_kstat_vcpu[i]);
			sc->vmm_kstat_vcpu[i] = NULL;
		} else {
			break;
		}
	}
	kstat_delete(sc->vmm_kstat_vm);
	sc->vmm_kstat_vm = NULL;
	return (-1);
}

static void
vmm_kstat_init(vmm_softc_t *sc)
{
	kstat_t *ksp;

	ASSERT3P(sc->vmm_vm, !=, NULL);
	ASSERT3P(sc->vmm_kstat_vm, !=, NULL);

	ksp = sc->vmm_kstat_vm;
	vmm_kstats_t *vk = ksp->ks_data;
	ksp->ks_private = sc->vmm_vm;
	kstat_named_init(&vk->vk_name, "vm_name", KSTAT_DATA_STRING);
	kstat_named_setstr(&vk->vk_name, sc->vmm_name);

	for (uint_t i = 0; i < VM_MAXCPU; i++) {
		ASSERT3P(sc->vmm_kstat_vcpu[i], !=, NULL);

		ksp = sc->vmm_kstat_vcpu[i];
		vmm_vcpu_kstats_t *vvk = ksp->ks_data;

		kstat_named_init(&vvk->vvk_vcpu, "vcpu", KSTAT_DATA_UINT32);
		vvk->vvk_vcpu.value.ui32 = i;
		kstat_named_init(&vvk->vvk_time_init, "time_init",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&vvk->vvk_time_run, "time_run",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&vvk->vvk_time_idle, "time_idle",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&vvk->vvk_time_emu_kern, "time_emu_kern",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&vvk->vvk_time_emu_user, "time_emu_user",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&vvk->vvk_time_sched, "time_sched",
		    KSTAT_DATA_UINT64);
		ksp->ks_private = sc->vmm_vm;
		ksp->ks_update = vmm_kstat_update_vcpu;
	}

	kstat_install(sc->vmm_kstat_vm);
	for (uint_t i = 0; i < VM_MAXCPU; i++) {
		kstat_install(sc->vmm_kstat_vcpu[i]);
	}
}

static void
vmm_kstat_fini(vmm_softc_t *sc)
{
	ASSERT(sc->vmm_kstat_vm != NULL);

	kstat_delete(sc->vmm_kstat_vm);
	sc->vmm_kstat_vm = NULL;

	for (uint_t i = 0; i < VM_MAXCPU; i++) {
		ASSERT3P(sc->vmm_kstat_vcpu[i], !=, NULL);

		kstat_delete(sc->vmm_kstat_vcpu[i]);
		sc->vmm_kstat_vcpu[i] = NULL;
	}
}

static int
vmm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;

	/*
	 * Forbid running bhyve in a 32-bit process until it has been tested and
	 * verified to be safe.
	 */
	if (curproc->p_model != DATAMODEL_LP64) {
		return (EFBIG);
	}

	minor = getminor(*devp);
	if (minor == VMM_CTL_MINOR) {
		/*
		 * Master control device must be opened exclusively.
		 */
		if ((flag & FEXCL) != FEXCL || otyp != OTYP_CHR) {
			return (EINVAL);
		}

		return (0);
	}

	mutex_enter(&vmm_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmm_mtx);
		return (ENXIO);
	}

	sc->vmm_flags |= VMM_IS_OPEN;
	mutex_exit(&vmm_mtx);

	return (0);
}

static int
vmm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	const minor_t minor = getminor(dev);
	vmm_softc_t *sc;
	bool hma_release = false;

	if (minor == VMM_CTL_MINOR) {
		return (0);
	}

	mutex_enter(&vmm_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmm_mtx);
		return (ENXIO);
	}

	VERIFY3U(sc->vmm_flags & VMM_IS_OPEN, !=, 0);
	sc->vmm_flags &= ~VMM_IS_OPEN;

	/*
	 * If instance was marked for auto-destruction begin that now.  Instance
	 * destruction may have been initated already, so try to make progress
	 * in that case, since closure of the device is one of its requirements.
	 */
	if ((sc->vmm_flags & VMM_DESTROY) != 0 ||
	    (sc->vmm_flags & VMM_AUTODESTROY) != 0) {
		VERIFY0(vmm_destroy_locked(sc, VDO_DEFAULT, &hma_release));
	}
	mutex_exit(&vmm_mtx);

	if (hma_release) {
		vmm_hma_release();
	}

	return (0);
}

static int
vmm_is_supported(intptr_t arg)
{
	int r;
	const char *msg;

	if (vmm_is_intel()) {
		r = vmx_x86_supported(&msg);
	} else if (vmm_is_svm()) {
		/*
		 * HMA already ensured that the features necessary for SVM
		 * operation were present and online during vmm_attach().
		 */
		r = 0;
	} else {
		r = ENXIO;
		msg = "Unsupported CPU vendor";
	}

	if (r != 0 && arg != (intptr_t)NULL) {
		if (copyoutstr(msg, (char *)arg, strlen(msg) + 1, NULL) != 0)
			return (EFAULT);
	}
	return (r);
}

static int
vmm_ctl_ioctl(int cmd, intptr_t arg, int md, cred_t *cr, int *rvalp)
{
	void *argp = (void *)arg;

	switch (cmd) {
	case VMM_CREATE_VM: {
		struct vm_create_req req;

		if ((md & FWRITE) == 0) {
			return (EPERM);
		}
		if (ddi_copyin(argp, &req, sizeof (req), md) != 0) {
			return (EFAULT);
		}
		return (vmmdev_do_vm_create(&req, cr));
	}
	case VMM_DESTROY_VM: {
		struct vm_destroy_req req;

		if ((md & FWRITE) == 0) {
			return (EPERM);
		}
		if (ddi_copyin(argp, &req, sizeof (req), md) != 0) {
			return (EFAULT);
		}
		return (vmmdev_do_vm_destroy(&req, cr));
	}
	case VMM_VM_SUPPORTED:
		return (vmm_is_supported(arg));
	case VMM_CHECK_IOMMU:
		if (!vmm_check_iommu()) {
			return (ENXIO);
		}
		return (0);
	case VMM_RESV_QUERY:
	case VMM_RESV_SET_TARGET:
		return (vmmr_ioctl(cmd, arg, md, cr, rvalp));
	default:
		break;
	}
	/* No other actions are legal on ctl device */
	return (ENOTTY);
}

static int
vmm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	vmm_softc_t	*sc;
	minor_t		minor;

	/*
	 * Forbid running bhyve in a 32-bit process until it has been tested and
	 * verified to be safe.
	 */
	if (curproc->p_model != DATAMODEL_LP64) {
		return (EFBIG);
	}

	/* The structs in bhyve ioctls assume a 64-bit datamodel */
	if (ddi_model_convert_from(mode & FMODELS) != DDI_MODEL_NONE) {
		return (ENOTSUP);
	}

	/*
	 * Regardless of minor (vmmctl or instance), we respond to queries of
	 * the interface version.
	 */
	if (cmd == VMM_INTERFACE_VERSION) {
		*rvalp = VMM_CURRENT_INTERFACE_VERSION;
		return (0);
	}

	minor = getminor(dev);

	if (minor == VMM_CTL_MINOR) {
		return (vmm_ctl_ioctl(cmd, arg, mode, credp, rvalp));
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc != NULL);

	/*
	 * Turn away any ioctls against an instance when it is being destroyed.
	 * (Except for the ioctl inquiring about that destroy-in-progress.)
	 */
	if ((sc->vmm_flags & VMM_DESTROY) != 0) {
		if (cmd == VM_DESTROY_PENDING) {
			*rvalp = 1;
			return (0);
		}
		return (ENXIO);
	}

	return (vmmdev_do_ioctl(sc, cmd, arg, mode, credp, rvalp));
}

static int
vmm_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    unsigned int prot, unsigned int maxprot, unsigned int flags, cred_t *credp)
{
	vmm_softc_t *sc;
	const minor_t minor = getminor(dev);
	int err;

	if (minor == VMM_CTL_MINOR) {
		return (ENODEV);
	}
	if (off < 0 || (off + len) <= 0) {
		return (EINVAL);
	}
	if ((prot & PROT_USER) == 0) {
		return (EACCES);
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	if (sc->vmm_flags & VMM_DESTROY)
		return (ENXIO);

	/* Grab read lock on the VM to prevent any changes to the memory map */
	vmm_read_lock(sc);

	if (off >= VM_DEVMEM_START) {
		int segid;
		off_t segoff;

		/* Mapping a devmem "device" */
		if (!vmmdev_devmem_segid(sc, off, len, &segid, &segoff)) {
			err = ENODEV;
		} else {
			err = vm_segmap_obj(sc->vmm_vm, segid, segoff, len, as,
			    addrp, prot, maxprot, flags);
		}
	} else {
		/* Mapping a part of the guest physical space */
		err = vm_segmap_space(sc->vmm_vm, off, as, addrp, len, prot,
		    maxprot, flags);
	}

	vmm_read_unlock(sc);
	return (err);
}

static sdev_plugin_validate_t
vmm_sdev_validate(sdev_ctx_t ctx)
{
	const char *name = sdev_ctx_name(ctx);
	vmm_softc_t *sc;
	sdev_plugin_validate_t ret;
	minor_t minor;

	if (sdev_ctx_vtype(ctx) != VCHR)
		return (SDEV_VTOR_INVALID);

	VERIFY3S(sdev_ctx_minor(ctx, &minor), ==, 0);

	mutex_enter(&vmm_mtx);
	if ((sc = vmm_lookup(name)) == NULL)
		ret = SDEV_VTOR_INVALID;
	else if (sc->vmm_minor != minor)
		ret = SDEV_VTOR_STALE;
	else
		ret = SDEV_VTOR_VALID;
	mutex_exit(&vmm_mtx);

	return (ret);
}

static int
vmm_sdev_filldir(sdev_ctx_t ctx)
{
	vmm_softc_t *sc;
	int ret;

	if (strcmp(sdev_ctx_path(ctx), VMM_SDEV_ROOT) != 0) {
		cmn_err(CE_WARN, "%s: bad path '%s' != '%s'\n", __func__,
		    sdev_ctx_path(ctx), VMM_SDEV_ROOT);
		return (EINVAL);
	}

	mutex_enter(&vmm_mtx);
	ASSERT(vmmdev_dip != NULL);
	for (sc = list_head(&vmm_list); sc != NULL;
	    sc = list_next(&vmm_list, sc)) {
		if (INGLOBALZONE(curproc) || sc->vmm_zone == curzone) {
			ret = sdev_plugin_mknod(ctx, sc->vmm_name,
			    S_IFCHR | 0600,
			    makedevice(ddi_driver_major(vmmdev_dip),
			    sc->vmm_minor));
		} else {
			continue;
		}
		if (ret != 0 && ret != EEXIST)
			goto out;
	}

	ret = 0;

out:
	mutex_exit(&vmm_mtx);
	return (ret);
}

/* ARGSUSED */
static void
vmm_sdev_inactive(sdev_ctx_t ctx)
{
}

static sdev_plugin_ops_t vmm_sdev_ops = {
	.spo_version = SDEV_PLUGIN_VERSION,
	.spo_flags = SDEV_PLUGIN_SUBDIR,
	.spo_validate = vmm_sdev_validate,
	.spo_filldir = vmm_sdev_filldir,
	.spo_inactive = vmm_sdev_inactive
};

/* ARGSUSED */
static int
vmm_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)vmmdev_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static int
vmm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sdev_plugin_hdl_t sph;
	hma_reg_t *reg = NULL;
	boolean_t vmm_loaded = B_FALSE;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vmmdev_mtx);
	/* Ensure we are not already attached. */
	if (vmmdev_dip != NULL) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}

	vmm_sol_glue_init();

	/*
	 * Perform temporary HMA registration to determine if the system
	 * is capable.
	 */
	if ((reg = hma_register(vmmdev_hvm_name)) == NULL) {
		goto fail;
	} else if (vmm_mod_load() != 0) {
		goto fail;
	}
	vmm_loaded = B_TRUE;
	hma_unregister(reg);
	reg = NULL;

	/* Create control node.  Other nodes will be created on demand. */
	if (ddi_create_minor_node(dip, "ctl", S_IFCHR,
	    VMM_CTL_MINOR, DDI_PSEUDO, 0) != 0) {
		goto fail;
	}

	sph = sdev_plugin_register(VMM_MODULE_NAME, &vmm_sdev_ops, NULL);
	if (sph == (sdev_plugin_hdl_t)NULL) {
		ddi_remove_minor_node(dip, NULL);
		goto fail;
	}

	ddi_report_dev(dip);
	vmmdev_sdev_hdl = sph;
	vmmdev_dip = dip;
	mutex_exit(&vmmdev_mtx);
	return (DDI_SUCCESS);

fail:
	if (vmm_loaded) {
		VERIFY0(vmm_mod_unload());
	}
	if (reg != NULL) {
		hma_unregister(reg);
	}
	vmm_sol_glue_cleanup();
	mutex_exit(&vmmdev_mtx);
	return (DDI_FAILURE);
}

static int
vmm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Ensure that all resources have been cleaned up.
	 *
	 * To prevent a deadlock with iommu_cleanup() we'll fail the detach if
	 * vmmdev_mtx is already held. We can't wait for vmmdev_mtx with our
	 * devinfo locked as iommu_cleanup() tries to recursively lock each
	 * devinfo, including our own, while holding vmmdev_mtx.
	 */
	if (mutex_tryenter(&vmmdev_mtx) == 0)
		return (DDI_FAILURE);

	mutex_enter(&vmm_mtx);
	if (!list_is_empty(&vmm_list)) {
		mutex_exit(&vmm_mtx);
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}
	mutex_exit(&vmm_mtx);

	if (!vmmr_is_empty()) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}

	VERIFY(vmmdev_sdev_hdl != (sdev_plugin_hdl_t)NULL);
	if (sdev_plugin_unregister(vmmdev_sdev_hdl) != 0) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}
	vmmdev_sdev_hdl = (sdev_plugin_hdl_t)NULL;

	/* Remove the control node. */
	ddi_remove_minor_node(dip, "ctl");
	vmmdev_dip = NULL;

	VERIFY0(vmm_mod_unload());
	VERIFY3U(vmmdev_hma_reg, ==, NULL);
	vmm_sol_glue_cleanup();

	mutex_exit(&vmmdev_mtx);

	return (DDI_SUCCESS);
}

static struct cb_ops vmm_cb_ops = {
	vmm_open,
	vmm_close,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	vmm_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	vmm_segmap,
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops vmm_ops = {
	DEVO_REV,
	0,
	vmm_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	vmm_attach,
	vmm_detach,
	nodev,		/* reset */
	&vmm_cb_ops,
	(struct bus_ops *)NULL
};

static struct modldrv modldrv = {
	&mod_driverops,
	"bhyve vmm",
	&vmm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	error;

	sysinit();

	mutex_init(&vmmdev_mtx, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vmm_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&vmm_list, sizeof (vmm_softc_t),
	    offsetof(vmm_softc_t, vmm_node));
	vmm_minors = id_space_create("vmm_minors", VMM_CTL_MINOR + 1, MAXMIN32);

	error = ddi_soft_state_init(&vmm_statep, sizeof (vmm_softc_t), 0);
	if (error) {
		return (error);
	}

	error = vmmr_init();
	if (error) {
		ddi_soft_state_fini(&vmm_statep);
		return (error);
	}

	vmm_zsd_init();

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&vmm_statep);
		vmm_zsd_fini();
		vmmr_fini();
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error) {
		return (error);
	}

	vmm_zsd_fini();
	vmmr_fini();

	ddi_soft_state_fini(&vmm_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
