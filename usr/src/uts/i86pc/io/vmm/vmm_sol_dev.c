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
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
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
#include <sys/pc_hvm.h>
#include <sys/cpuset.h>
#include <sys/id_space.h>
#include <sys/fs/sdev_plugin.h>

#include <sys/vmm.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_impl.h>
#include <sys/vmm_drv.h>

#include <vm/vm.h>
#include <vm/seg_dev.h>

#include "io/ppt.h"
#include "io/vatpic.h"
#include "io/vioapic.h"
#include "io/vrtc.h"
#include "io/vhpet.h"
#include "vmm_lapic.h"
#include "vmm_stat.h"
#include "vmm_util.h"
#include "vm/vm_glue.h"

/*
 * Locking order:
 *
 * vmmdev_mtx (driver holds etc.)
 *  ->sdev_contents (/dev/vmm)
 *   vmm_mtx (VM list)
 */

static dev_info_t *vmm_dip;
static void *vmm_statep;

static kmutex_t		vmmdev_mtx;
static id_space_t	*vmmdev_minors;
static uint_t		vmmdev_inst_count = 0;
static boolean_t	vmmdev_load_failure;
static kmutex_t		vmm_mtx;
static list_t		vmmdev_list;

static const char *vmmdev_hvm_name = "bhyve";

/*
 * For sdev plugin (/dev)
 */
#define	VMM_SDEV_ROOT "/dev/vmm"
static sdev_plugin_hdl_t vmm_sdev_hdl;

/* From uts/i86pc/io/vmm/intel/vmx.c */
extern int vmx_x86_supported(char **);

/* Holds and hooks from drivers external to vmm */
struct vmm_hold {
	list_node_t	vmh_node;
	vmm_softc_t	*vmh_sc;
	boolean_t	vmh_expired;
	uint_t		vmh_ioport_hook_cnt;
};

static int vmm_drv_block_hook(vmm_softc_t *, boolean_t);

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
		list_t *dl = &sc->vmm_devmem_list;

		for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
			if (de->vde_segid == mseg->segid) {
				break;
			}
		}
		if (de != NULL) {
			(void) strlcpy(mseg->name, de->vde_name,
			    sizeof (mseg->name));
		}
	} else {
		bzero(mseg->name, sizeof (mseg->name));
	}

	return (error);
}

/*
 * The 'devmem' hack:
 *
 * On native FreeBSD, bhyve consumers are allowed to create 'devmem' segments
 * in the vm which appear with their own name related to the vm under /dev.
 * Since this would be a hassle from an sdev perspective and would require a
 * new cdev interface (or complicate the existing one), we choose to implement
 * this in a different manner.  When 'devmem' mappings are created, an
 * identifying off_t is communicated back out to userspace.  That off_t,
 * residing above the normal guest memory space, can be used to mmap the
 * 'devmem' mapping from the already-open vm device.
 */

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
vmmdev_devmem_segid(vmm_softc_t *sc, off_t off, off_t len, int *segidp)
{
	list_t *dl = &sc->vmm_devmem_list;
	vmm_devmem_entry_t *de = NULL;

	VERIFY(off >= VM_DEVMEM_START);

	for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
		/* XXX: Only hit on direct offset/length matches for now */
		if (de->vde_off == off && de->vde_len == len) {
			break;
		}
	}
	if (de == NULL) {
		return (B_FALSE);
	}

	*segidp = de->vde_segid;
	return (B_TRUE);
}

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

	if (error == 0 && VM_MEMSEG_NAME(mseg)) {
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


static int
vcpu_lock_one(vmm_softc_t *sc, int vcpu)
{
	int error;

	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	error = vcpu_set_state(sc->vmm_vm, vcpu, VCPU_FROZEN, true);
	return (error);
}

static void
vcpu_unlock_one(vmm_softc_t *sc, int vcpu)
{
	enum vcpu_state state;

	state = vcpu_get_state(sc->vmm_vm, vcpu, NULL);
	if (state != VCPU_FROZEN) {
		panic("vcpu %s(%d) has invalid state %d", vm_name(sc->vmm_vm),
		    vcpu, state);
	}

	vcpu_set_state(sc->vmm_vm, vcpu, VCPU_IDLE, false);
}

static int
vcpu_lock_all(vmm_softc_t *sc)
{
	int error, vcpu;

	for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++) {
		error = vcpu_lock_one(sc, vcpu);
		if (error)
			break;
	}

	if (error) {
		while (--vcpu >= 0)
			vcpu_unlock_one(sc, vcpu);
	}

	return (error);
}

static void
vcpu_unlock_all(vmm_softc_t *sc)
{
	int vcpu;

	for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++)
		vcpu_unlock_one(sc, vcpu);
}

static int
vmmdev_do_ioctl(vmm_softc_t *sc, int cmd, intptr_t arg, int md,
    cred_t *credp, int *rvalp)
{
	int error = 0, vcpu = -1;
	void *datap = (void *)arg;
	boolean_t locked_one = B_FALSE, locked_all = B_FALSE;

	/*
	 * Some VMM ioctls can operate only on vcpus that are not running.
	 */
	switch (cmd) {
	case VM_RUN:
	case VM_GET_REGISTER:
	case VM_SET_REGISTER:
	case VM_GET_SEGMENT_DESCRIPTOR:
	case VM_SET_SEGMENT_DESCRIPTOR:
	case VM_INJECT_EXCEPTION:
	case VM_GET_CAPABILITY:
	case VM_SET_CAPABILITY:
	case VM_PPTDEV_MSI:
	case VM_PPTDEV_MSIX:
	case VM_SET_X2APIC_STATE:
	case VM_GLA2GPA:
	case VM_ACTIVATE_CPU:
	case VM_SET_INTINFO:
	case VM_GET_INTINFO:
	case VM_RESTART_INSTRUCTION:
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
		if (vcpu < 0 || vcpu >= VM_MAXCPU) {
			error = EINVAL;
			goto done;
		}

		error = vcpu_lock_one(sc, vcpu);
		if (error)
			goto done;
		locked_one = B_TRUE;
		break;

	case VM_MAP_PPTDEV_MMIO:
	case VM_BIND_PPTDEV:
	case VM_UNBIND_PPTDEV:
	case VM_ALLOC_MEMSEG:
	case VM_MMAP_MEMSEG:
	case VM_REINIT:
		/*
		 * All vCPUs must be prevented from running when performing
		 * operations which act upon the entire VM.
		 */
		error = vcpu_lock_all(sc);
		if (error)
			goto done;
		locked_all = B_TRUE;
		break;

	case VM_GET_MEMSEG:
	case VM_MMAP_GETNEXT:
#ifndef __FreeBSD__
	case VM_DEVMEM_GETOFFSET:
#endif
		/*
		 * Lock a vcpu to make sure that the memory map cannot be
		 * modified while it is being inspected.
		 */
		vcpu = VM_MAXCPU - 1;
		error = vcpu_lock_one(sc, vcpu);
		if (error)
			goto done;
		locked_one = B_TRUE;
		break;

	default:
		break;
	}

	switch (cmd) {
	case VM_RUN: {
		struct vm_run vmrun;

		if (ddi_copyin(datap, &vmrun, sizeof (vmrun), md)) {
			error = EFAULT;
			break;
		}
		vmrun.cpuid = vcpu;
		error = vm_run(sc->vmm_vm, &vmrun);
		/*
		 * XXXJOY: I think it's necessary to do copyout, even in the
		 * face of errors, since the exit state is communicated out.
		 */
		if (ddi_copyout(&vmrun, datap, sizeof (vmrun), md)) {
			error = EFAULT;
			break;
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
	case VM_REINIT:
		if ((error = vmm_drv_block_hook(sc, B_TRUE)) != 0) {
			/*
			 * The VM instance should be free of driver-attached
			 * hooks during the reinitialization process.
			 */
			break;
		}
		error = vm_reinit(sc->vmm_vm);
		(void) vmm_drv_block_hook(sc, B_FALSE);
		break;
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

		CTASSERT(MAX_VM_STATS >= MAX_VMM_STAT_ELEMS);
		if (ddi_copyin(datap, &vmstats, sizeof (vmstats), md)) {
			error = EFAULT;
			break;
		}
		hrt2tv(gethrtime(), &vmstats.tv);
		error = vmm_stat_copy(sc->vmm_vm, vmstats.cpuid,
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
		    vmexc.error_code_valid, vmexc.error_code,
		    vmexc.restart_instruction);
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
		struct vm_gpa_pte gpapte;

		if (ddi_copyin(datap, &gpapte, sizeof (gpapte), md)) {
			error = EFAULT;
			break;
		}
#ifdef __FreeBSD__
		/* XXXJOY: add function? */
		pmap_get_mapping(vmspace_pmap(vm_get_vmspace(sc->vmm_vm)),
		    gpapte.gpa, gpapte.pte, &gpapte.ptenum);
#endif
		error = 0;
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

		CTASSERT(PROT_READ == VM_PROT_READ);
		CTASSERT(PROT_WRITE == VM_PROT_WRITE);
		CTASSERT(PROT_EXEC == VM_PROT_EXECUTE);

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
	case VM_ACTIVATE_CPU:
		error = vm_activate_cpu(sc->vmm_vm, vcpu);
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
		if (size <= tempset.cpub[0]) {
			srcp = &tempset.cpub[0];
		}

		if (vm_cpuset.which == VM_ACTIVE_CPUS) {
			tempset = vm_active_cpus(sc->vmm_vm);
		} else if (vm_cpuset.which == VM_SUSPENDED_CPUS) {
			tempset = vm_suspended_cpus(sc->vmm_vm);
		} else {
			error = EINVAL;
		}

		ASSERT(size > 0 && size <= sizeof (tempset));
		if (error == 0 &&
		    ddi_copyout(&tempset, vm_cpuset.cpus, size, md)) {
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

	case VM_RESTART_INSTRUCTION:
		error = vm_restart_instruction(sc->vmm_vm, vcpu);
		break;

#ifndef __FreeBSD__
	case VM_DEVMEM_GETOFFSET: {
		struct vm_devmem_offset vdo;
		list_t *dl = &sc->vmm_devmem_list;
		vmm_devmem_entry_t *de = NULL;

		if (ddi_copyin(datap, &vdo, sizeof (vdo), md) != 0) {
			error = EFAULT;
			break;
		}

		for (de = list_head(dl); de != NULL; de = list_next(dl, de)) {
			if (de->vde_segid == vdo.segid) {
				break;
			}
		}
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
#endif
	default:
		error = ENOTTY;
		break;
	}

	/* Release any vCPUs that were locked for the operation */
	if (locked_one) {
		vcpu_unlock_one(sc, vcpu);
	} else if (locked_all) {
		vcpu_unlock_all(sc);
	}

done:
	/* Make sure that no handler returns a bogus value like ERESTART */
	KASSERT(error >= 0, ("vmmdev_ioctl: invalid error return %d", error));
	return (error);
}

static boolean_t
vmmdev_mod_incr()
{
	ASSERT(MUTEX_HELD(&vmmdev_mtx));

	if (vmmdev_inst_count == 0) {
		/*
		 * If the HVM portions of the module failed initialize on a
		 * previous attempt, do not bother with a retry.  This tracker
		 * is cleared on module attach, allowing subsequent attempts if
		 * desired by the user.
		 */
		if (vmmdev_load_failure) {
			return (B_FALSE);
		}

		if (!hvm_excl_hold(vmmdev_hvm_name)) {
			return (B_FALSE);
		}
		if (vmm_mod_load() != 0) {
			hvm_excl_rele(vmmdev_hvm_name);
			vmmdev_load_failure = B_TRUE;
			return (B_FALSE);
		}
	}

	vmmdev_inst_count++;
	return (B_TRUE);
}

static void
vmmdev_mod_decr(void)
{
	ASSERT(MUTEX_HELD(&vmmdev_mtx));
	ASSERT(vmmdev_inst_count > 0);

	vmmdev_inst_count--;
	if (vmmdev_inst_count == 0) {
		VERIFY0(vmm_mod_unload());
		hvm_excl_rele(vmmdev_hvm_name);
	}
}

static vmm_softc_t *
vmm_lookup(const char *name)
{
	list_t *vml = &vmmdev_list;
	vmm_softc_t *sc;

	ASSERT(MUTEX_HELD(&vmm_mtx));

	for (sc = list_head(vml); sc != NULL; sc = list_next(vml, sc)) {
		if (strcmp(sc->vmm_name, name) == 0) {
			break;
		}
	}

	return (sc);
}

static int
vmmdev_do_vm_create(char *name, cred_t *cr)
{
	vmm_softc_t	*sc = NULL;
	minor_t		minor;
	int		error = ENOMEM;

	if (strnlen(name, VM_MAX_NAMELEN) >= VM_MAX_NAMELEN) {
		return (EINVAL);
	}

	mutex_enter(&vmmdev_mtx);
	if (!vmmdev_mod_incr()) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	mutex_enter(&vmm_mtx);

	/* Look for duplicates names */
	if (vmm_lookup(name) != NULL) {
		mutex_exit(&vmm_mtx);
		vmmdev_mod_decr();
		mutex_exit(&vmmdev_mtx);
		return (EEXIST);
	}

	/* Allow only one instance per non-global zone. */
	if (!INGLOBALZONE(curproc)) {
		for (sc = list_head(&vmmdev_list); sc != NULL;
		    sc = list_next(&vmmdev_list, sc)) {
			if (sc->vmm_zone == curzone) {
				mutex_exit(&vmm_mtx);
				vmmdev_mod_decr();
				mutex_exit(&vmmdev_mtx);
				return (EINVAL);
			}
		}
	}

	minor = id_alloc(vmmdev_minors);
	if (ddi_soft_state_zalloc(vmm_statep, minor) != DDI_SUCCESS) {
		goto fail;
	} else if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		ddi_soft_state_free(vmm_statep, minor);
		goto fail;
	} else if (ddi_create_minor_node(vmm_dip, name, S_IFCHR, minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	error = vm_create(name, &sc->vmm_vm);
	if (error == 0) {
		/* Complete VM intialization and report success. */
		(void) strlcpy(sc->vmm_name, name, sizeof (sc->vmm_name));
		sc->vmm_minor = minor;
		list_create(&sc->vmm_devmem_list, sizeof (vmm_devmem_entry_t),
		    offsetof(vmm_devmem_entry_t, vde_node));
		list_create(&sc->vmm_holds, sizeof (vmm_hold_t),
		    offsetof(vmm_hold_t, vmh_node));
		cv_init(&sc->vmm_cv, NULL, CV_DEFAULT, NULL);

		sc->vmm_zone = crgetzone(cr);
		zone_hold(sc->vmm_zone);
		vmm_zsd_add_vm(sc);

		list_insert_tail(&vmmdev_list, sc);
		mutex_exit(&vmm_mtx);
		mutex_exit(&vmmdev_mtx);
		return (0);
	}

	ddi_remove_minor_node(vmm_dip, name);
fail:
	id_free(vmmdev_minors, minor);
	vmmdev_mod_decr();
	if (sc != NULL) {
		ddi_soft_state_free(vmm_statep, minor);
	}

	mutex_exit(&vmm_mtx);
	mutex_exit(&vmmdev_mtx);
	return (error);
}

int
vmm_drv_hold(file_t *fp, cred_t *cr, vmm_hold_t **holdp)
{
	vnode_t *vp = fp->f_vnode;
	const dev_t dev = vp->v_rdev;
	minor_t minor;
	minor_t major;
	vmm_softc_t *sc;
	vmm_hold_t *hold;
	int err = 0;

	if (vp->v_type != VCHR) {
		return (ENXIO);
	}
	major = getmajor(dev);
	minor = getminor(dev);

	mutex_enter(&vmmdev_mtx);
	if (vmm_dip == NULL) {
		err = ENOENT;
		goto out;
	}
	if (major != ddi_driver_major(vmm_dip) ||
	    (sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		err = ENOENT;
		goto out;
	}
	/* XXXJOY: check cred permissions against instance */

	if ((sc->vmm_flags & (VMM_CLEANUP|VMM_PURGED)) != 0) {
		err = EBUSY;
		goto out;
	}

	hold = kmem_zalloc(sizeof (*hold), KM_SLEEP);
	hold->vmh_sc = sc;
	hold->vmh_expired = B_FALSE;
	list_insert_tail(&sc->vmm_holds, hold);
	sc->vmm_flags |= VMM_HELD;
	*holdp = hold;

out:
	mutex_exit(&vmmdev_mtx);
	return (err);
}

void
vmm_drv_rele(vmm_hold_t *hold)
{
	vmm_softc_t *sc;

	ASSERT(hold != NULL);
	ASSERT(hold->vmh_sc != NULL);
	VERIFY(hold->vmh_ioport_hook_cnt == 0);

	mutex_enter(&vmmdev_mtx);
	sc = hold->vmh_sc;
	list_remove(&sc->vmm_holds, hold);
	if (list_is_empty(&sc->vmm_holds)) {
		sc->vmm_flags &= ~VMM_HELD;
		cv_broadcast(&sc->vmm_cv);
	}
	mutex_exit(&vmmdev_mtx);
	kmem_free(hold, sizeof (*hold));
}

boolean_t
vmm_drv_expired(vmm_hold_t *hold)
{
	ASSERT(hold != NULL);

	return (hold->vmh_expired);
}

void *
vmm_drv_gpa2kva(vmm_hold_t *hold, uintptr_t gpa, size_t sz)
{
	struct vm *vm;
	struct vmspace *vmspace;

	ASSERT(hold != NULL);

	vm = hold->vmh_sc->vmm_vm;
	vmspace = vm_get_vmspace(vm);

	return (vmspace_find_kva(vmspace, gpa, sz));
}

int
vmm_drv_ioport_hook(vmm_hold_t *hold, uint_t ioport, vmm_drv_rmem_cb_t rfunc,
    vmm_drv_wmem_cb_t wfunc, void *arg, void **cookie)
{
	vmm_softc_t *sc;
	int err;

	ASSERT(hold != NULL);
	ASSERT(cookie != NULL);

	sc = hold->vmh_sc;
	mutex_enter(&vmmdev_mtx);
	/* Confirm that hook installation is not blocked */
	if ((sc->vmm_flags & VMM_BLOCK_HOOK) != 0) {
		mutex_exit(&vmmdev_mtx);
		return (EBUSY);
	}
	/*
	 * Optimistically record an installed hook which will prevent a block
	 * from being asserted while the mutex is dropped.
	 */
	hold->vmh_ioport_hook_cnt++;
	mutex_exit(&vmmdev_mtx);

	err = vm_ioport_hook(sc->vmm_vm, ioport, (vmm_rmem_cb_t)rfunc,
	    (vmm_wmem_cb_t)wfunc, arg, cookie);

	if (err != 0) {
		mutex_enter(&vmmdev_mtx);
		/* Walk back optimism about the hook installation */
		hold->vmh_ioport_hook_cnt--;
		mutex_exit(&vmmdev_mtx);
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
	vm_ioport_unhook(sc->vmm_vm, cookie);

	mutex_enter(&vmmdev_mtx);
	hold->vmh_ioport_hook_cnt--;
	mutex_exit(&vmmdev_mtx);
}

int
vmm_drv_msi(vmm_hold_t *hold, uint64_t addr, uint64_t msg)
{
	struct vm *vm;

	ASSERT(hold != NULL);

	vm = hold->vmh_sc->vmm_vm;
	return (lapic_intr_msi(vm, addr, msg));
}

static int
vmm_drv_purge(vmm_softc_t *sc)
{
	ASSERT(MUTEX_HELD(&vmmdev_mtx));

	if ((sc->vmm_flags & VMM_HELD) != 0) {
		vmm_hold_t *hold;

		sc->vmm_flags |= VMM_CLEANUP;
		for (hold = list_head(&sc->vmm_holds); hold != NULL;
		    hold = list_next(&sc->vmm_holds, hold)) {
			hold->vmh_expired = B_TRUE;
		}
		while ((sc->vmm_flags & VMM_HELD) != 0) {
			if (cv_wait_sig(&sc->vmm_cv, &vmmdev_mtx) <= 0) {
				return (EINTR);
			}
		}
		sc->vmm_flags &= ~VMM_CLEANUP;
	}

	VERIFY(list_is_empty(&sc->vmm_holds));
	sc->vmm_flags |= VMM_PURGED;
	return (0);
}

static int
vmm_drv_block_hook(vmm_softc_t *sc, boolean_t enable_block)
{
	int err = 0;

	mutex_enter(&vmmdev_mtx);
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
	mutex_exit(&vmmdev_mtx);
	return (err);
}

static int
vmm_do_vm_destroy_locked(vmm_softc_t *sc, boolean_t clean_zsd)
{
	dev_info_t	*pdip = ddi_get_parent(vmm_dip);
	minor_t		minor;

	ASSERT(MUTEX_HELD(&vmmdev_mtx));
	ASSERT(MUTEX_HELD(&vmm_mtx));

	if (sc->vmm_is_open) {
		return (EBUSY);
	}

	if (clean_zsd) {
		vmm_zsd_rem_vm(sc);
	}

	if (vmm_drv_purge(sc) != 0) {
		return (EINTR);
	}

	/* Clean up devmem entries */
	vmmdev_devmem_purge(sc);

	vm_destroy(sc->vmm_vm);
	list_remove(&vmmdev_list, sc);
	ddi_remove_minor_node(vmm_dip, sc->vmm_name);
	minor = sc->vmm_minor;
	zone_rele(sc->vmm_zone);
	ddi_soft_state_free(vmm_statep, minor);
	id_free(vmmdev_minors, minor);
	(void) devfs_clean(pdip, NULL, DV_CLEAN_FORCE);
	vmmdev_mod_decr();

	return (0);
}

int
vmm_do_vm_destroy(vmm_softc_t *sc, boolean_t clean_zsd)
{
	int 		err;

	mutex_enter(&vmmdev_mtx);
	mutex_enter(&vmm_mtx);
	err = vmm_do_vm_destroy_locked(sc, clean_zsd);
	mutex_exit(&vmm_mtx);
	mutex_exit(&vmmdev_mtx);

	return (err);
}

/* ARGSUSED */
static int
vmmdev_do_vm_destroy(const char *name, cred_t *cr)
{
	vmm_softc_t	*sc;
	int		err;

	if (crgetuid(cr) != 0)
		return (EPERM);

	mutex_enter(&vmmdev_mtx);
	mutex_enter(&vmm_mtx);

	if ((sc = vmm_lookup(name)) == NULL) {
		mutex_exit(&vmm_mtx);
		mutex_exit(&vmmdev_mtx);
		return (ENOENT);
	}
	/*
	 * We don't check this in vmm_lookup() since that function is also used
	 * for validation during create and currently vmm names must be unique.
	 */
	if (!INGLOBALZONE(curproc) && sc->vmm_zone != curzone) {
		mutex_exit(&vmm_mtx);
		mutex_exit(&vmmdev_mtx);
		return (EPERM);
	}
	err = vmm_do_vm_destroy_locked(sc, B_TRUE);

	mutex_exit(&vmm_mtx);
	mutex_exit(&vmmdev_mtx);

	return (err);
}


static int
vmm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;

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

	mutex_enter(&vmmdev_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	sc->vmm_is_open = B_TRUE;
	mutex_exit(&vmmdev_mtx);

	return (0);
}

static int
vmm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	minor_t		minor;
	vmm_softc_t	*sc;

	minor = getminor(dev);
	if (minor == VMM_CTL_MINOR)
		return (0);

	mutex_enter(&vmmdev_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	VERIFY(sc->vmm_is_open);
	sc->vmm_is_open = B_FALSE;
	mutex_exit(&vmmdev_mtx);

	return (0);
}

static int
vmm_is_supported(intptr_t arg)
{
	int r;
	char *msg;

	if (!vmm_is_intel())
		return (ENXIO);

	r = vmx_x86_supported(&msg);
	if (r != 0 && arg != NULL) {
		if (copyoutstr(msg, (char *)arg, strlen(msg), NULL) != 0)
			return (EFAULT);
	}
	return (r);
}

static int
vmm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	vmm_softc_t	*sc;
	minor_t		minor;

	minor = getminor(dev);

	if (minor == VMM_CTL_MINOR) {
		void *argp = (void *)arg;
		char name[VM_MAX_NAMELEN] = { 0 };
		size_t len = 0;

		if ((mode & FKIOCTL) != 0) {
			len = strlcpy(name, argp, sizeof (name));
		} else {
			if (copyinstr(argp, name, sizeof (name), &len) != 0) {
				return (EFAULT);
			}
		}
		if (len >= VM_MAX_NAMELEN) {
			return (ENAMETOOLONG);
		}

		switch (cmd) {
		case VMM_CREATE_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_create(name, credp));
		case VMM_DESTROY_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_destroy(name, credp));
		case VMM_VM_SUPPORTED:
			return (vmm_is_supported(arg));
		default:
			/* No other actions are legal on ctl device */
			return (ENOTTY);
		}
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	return (vmmdev_do_ioctl(sc, cmd, arg, mode, credp, rvalp));
}

static int
vmm_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    unsigned int prot, unsigned int maxprot, unsigned int flags, cred_t *credp)
{
	vmm_softc_t *sc;
	const minor_t minor = getminor(dev);
	struct vm *vm;
	int err;
	vm_object_t vmo = NULL;
	struct vmspace *vms;

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

	/* Get a read lock on the guest memory map by freezing any vcpu. */
	if ((err = vcpu_lock_all(sc)) != 0) {
		return (err);
	}

	vm = sc->vmm_vm;
	vms = vm_get_vmspace(vm);
	if (off >= VM_DEVMEM_START) {
		int segid;

		/* Mapping a devmem "device" */
		if (!vmmdev_devmem_segid(sc, off, len, &segid)) {
			err = ENODEV;
			goto out;
		}
		err = vm_get_memseg(vm, segid, NULL, NULL, &vmo);
		if (err != 0) {
			goto out;
		}
		err = vm_segmap_obj(vms, vmo, as, addrp, prot, maxprot, flags);
	} else {
		/* Mapping a part of the guest physical space */
		err = vm_segmap_space(vms, off, as, addrp, len, prot, maxprot,
		    flags);
	}


out:
	vcpu_unlock_all(sc);
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

	/* Driver not initialized, directory empty. */
	if (vmm_dip == NULL)
		return (0);

	mutex_enter(&vmm_mtx);

	for (sc = list_head(&vmmdev_list); sc != NULL;
	    sc = list_next(&vmmdev_list, sc)) {
		if (INGLOBALZONE(curproc) || sc->vmm_zone == curzone) {
			ret = sdev_plugin_mknod(ctx, sc->vmm_name,
			    S_IFCHR | 0600,
			    makedevice(ddi_driver_major(vmm_dip),
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
		*result = (void *)vmm_dip;
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
	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	vmm_sol_glue_init();

	/*
	 * Create control node.  Other nodes will be created on demand.
	 */
	if (ddi_create_minor_node(dip, "ctl", S_IFCHR,
	    VMM_CTL_MINOR, DDI_PSEUDO, 0) != 0) {
		return (DDI_FAILURE);
	}

	if ((vmm_sdev_hdl = sdev_plugin_register("vmm", &vmm_sdev_ops,
	    NULL)) == NULL) {
		ddi_remove_minor_node(dip, NULL);
		dip = NULL;
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);

	vmm_arena_init();

	vmmdev_load_failure = B_FALSE;
	vmm_dip = dip;

	return (DDI_SUCCESS);
}

static int
vmm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* Ensure that all resources have been cleaned up */
	mutex_enter(&vmmdev_mtx);

	if (vmmdev_inst_count != 0) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}

	mutex_enter(&vmm_mtx);

	if (!list_is_empty(&vmmdev_list)) {
		mutex_exit(&vmm_mtx);
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}

	mutex_exit(&vmm_mtx);

	if (vmm_sdev_hdl != NULL && sdev_plugin_unregister(vmm_sdev_hdl) != 0) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}
	vmm_sdev_hdl = NULL;

	/* Remove the control node. */
	ddi_remove_minor_node(dip, "ctl");
	vmm_dip = NULL;
	vmm_sol_glue_cleanup();
	vmm_arena_fini();

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
	"vmm",
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

	mutex_init(&vmmdev_mtx, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vmm_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&vmmdev_list, sizeof (vmm_softc_t),
	    offsetof(vmm_softc_t, vmm_node));
	vmmdev_minors = id_space_create("vmm_minors", VMM_CTL_MINOR + 1,
	    MAXMIN32);

	error = ddi_soft_state_init(&vmm_statep, sizeof (vmm_softc_t), 0);
	if (error) {
		return (error);
	}

	vmm_zsd_init();

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&vmm_statep);
		vmm_zsd_fini();
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

	ddi_soft_state_fini(&vmm_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
