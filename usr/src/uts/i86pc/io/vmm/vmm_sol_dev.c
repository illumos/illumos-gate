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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/vmsystm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/fs/dv_node.h>
#include <sys/pc_hvm.h>

#include <sys/vmm.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_impl.h>

#include <vm/vm.h>
#include <vm/seg_dev.h>

#include "io/vatpic.h"
#include "io/vioapic.h"
#include "vmm_lapic.h"

static dev_info_t *vmm_dip;
static void *vmm_statep;

static SLIST_HEAD(, vmm_softc) head;

static kmutex_t vmmdev_mtx;
static uint_t vmmdev_inst_count = 0;
static boolean_t vmmdev_load_failure;

static const char *vmmdev_hvm_name = "bhyve";

/*
 * vmm trace ring
 */
int	vmm_dmsg_ring_size = VMM_DMSG_RING_SIZE;
static	vmm_trace_rbuf_t *vmm_debug_rbuf;
static	vmm_trace_dmsg_t *vmm_trace_dmsg_alloc(void);
static	void vmm_trace_dmsg_free(void);
static	void vmm_trace_rbuf_alloc(void);
#if notyet
static	void vmm_trace_rbuf_free(void);
#endif

/*
 * This routine is used to manage debug messages
 * on ring buffer.
 */
static vmm_trace_dmsg_t *
vmm_trace_dmsg_alloc(void)
{
	vmm_trace_dmsg_t *dmsg_alloc, *dmsg = vmm_debug_rbuf->dmsgp;

	if (vmm_debug_rbuf->looped == TRUE) {
		vmm_debug_rbuf->dmsgp = dmsg->next;
		return (vmm_debug_rbuf->dmsgp);
	}

	/*
	 * If we're looping for the first time,
	 * connect the ring.
	 */
	if (((vmm_debug_rbuf->size + (sizeof (vmm_trace_dmsg_t))) >
	    vmm_debug_rbuf->maxsize) && (vmm_debug_rbuf->dmsgh != NULL)) {
		dmsg->next = vmm_debug_rbuf->dmsgh;
		vmm_debug_rbuf->dmsgp = vmm_debug_rbuf->dmsgh;
		vmm_debug_rbuf->looped = TRUE;
		return (vmm_debug_rbuf->dmsgp);
	}

	/* If we've gotten this far then memory allocation is needed */
	dmsg_alloc = kmem_zalloc(sizeof (vmm_trace_dmsg_t), KM_NOSLEEP);
	if (dmsg_alloc == NULL) {
		vmm_debug_rbuf->allocfailed++;
		return (dmsg_alloc);
	} else {
		vmm_debug_rbuf->size += sizeof (vmm_trace_dmsg_t);
	}

	if (vmm_debug_rbuf->dmsgp != NULL) {
		dmsg->next = dmsg_alloc;
		vmm_debug_rbuf->dmsgp = dmsg->next;
		return (vmm_debug_rbuf->dmsgp);
	} else {
		/*
		 * We should only be here if we're initializing
		 * the ring buffer.
		 */
		if (vmm_debug_rbuf->dmsgh == NULL) {
			vmm_debug_rbuf->dmsgh = dmsg_alloc;
		} else {
			/* Something is wrong */
			kmem_free(dmsg_alloc, sizeof (vmm_trace_dmsg_t));
			return (NULL);
		}

		vmm_debug_rbuf->dmsgp = dmsg_alloc;
		return (vmm_debug_rbuf->dmsgp);
	}
}

/*
 * Free all messages on debug ring buffer.
 */
static void
vmm_trace_dmsg_free(void)
{
	vmm_trace_dmsg_t *dmsg_next, *dmsg = vmm_debug_rbuf->dmsgh;

	while (dmsg != NULL) {
		dmsg_next = dmsg->next;
		kmem_free(dmsg, sizeof (vmm_trace_dmsg_t));

		/*
		 * If we've looped around the ring than we're done.
		 */
		if (dmsg_next == vmm_debug_rbuf->dmsgh) {
			break;
		} else {
			dmsg = dmsg_next;
		}
	}
}

static void
vmm_trace_rbuf_alloc(void)
{
	vmm_debug_rbuf = kmem_zalloc(sizeof (vmm_trace_rbuf_t), KM_SLEEP);

	mutex_init(&vmm_debug_rbuf->lock, NULL, MUTEX_DRIVER, NULL);

	if (vmm_dmsg_ring_size > 0) {
		vmm_debug_rbuf->maxsize = vmm_dmsg_ring_size;
	}
}

#if notyet
static void
vmm_trace_rbuf_free(void)
{
	vmm_trace_dmsg_free();
	mutex_destroy(&vmm_debug_rbuf->lock);
	kmem_free(vmm_debug_rbuf, sizeof (vmm_trace_rbuf_t));
}
#endif

static void
vmm_vtrace_log(const char *fmt, va_list ap)
{
	vmm_trace_dmsg_t *dmsg;

	if (vmm_debug_rbuf == NULL) {
		return;
	}

	/*
	 * If max size of ring buffer is smaller than size
	 * required for one debug message then just return
	 * since we have no room for the debug message.
	 */
	if (vmm_debug_rbuf->maxsize < (sizeof (vmm_trace_dmsg_t))) {
		return;
	}

	mutex_enter(&vmm_debug_rbuf->lock);

	/* alloc or reuse on ring buffer */
	dmsg = vmm_trace_dmsg_alloc();

	if (dmsg == NULL) {
		/* resource allocation failed */
		mutex_exit(&vmm_debug_rbuf->lock);
		return;
	}

	gethrestime(&dmsg->timestamp);

	(void) vsnprintf(dmsg->buf, sizeof (dmsg->buf), fmt, ap);

	mutex_exit(&vmm_debug_rbuf->lock);
}

void
vmm_trace_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vmm_vtrace_log(fmt, ap);
	va_end(ap);
}

void
vmmdev_init(void)
{
	vmm_trace_rbuf_alloc();
}

void
vmmdev_cleanup(void)
{
	VERIFY(SLIST_EMPTY(&head));

	vmm_trace_dmsg_free();
}

int
vmmdev_do_ioctl(struct vmm_softc *sc, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int error, vcpu, state_changed;
	struct vm_memory_segment seg;
	struct vm_register vmreg;
	struct vm_seg_desc vmsegdesc;
	struct vm_run vmrun;
	struct vm_lapic_irq vmirq;
	struct vm_lapic_msi vmmsi;
	struct vm_ioapic_irq ioapic_irq;
	struct vm_isa_irq isa_irq;
	struct vm_capability vmcap;
	struct vm_x2apic x2apic;
	struct vm_gla2gpa gg;
	struct vm_activate_cpu vac;
	int pincount;

	vcpu = -1;
	state_changed = 0;

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
	case VM_RESTART_INSTRUCTION:
		/*
		 * XXX fragile, handle with care
		 * Assumes that the first field of the ioctl data is the vcpu.
		 */
		if (ddi_copyin((void *)arg, &vcpu, sizeof (vcpu), mode)) {
			return (EFAULT);
		}
		if (vcpu < 0 || vcpu >= VM_MAXCPU) {
			error = EINVAL;
			goto done;
		}

		error = vcpu_set_state(sc->vm, vcpu, VCPU_FROZEN, true);
		if (error)
			goto done;

		state_changed = 1;
		break;
	case VM_MAP_MEMORY:
		/*
		 * ioctls that operate on the entire virtual machine must
		 * prevent all vcpus from running.
		 */
		error = 0;
		for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++) {
			error = vcpu_set_state(sc->vm, vcpu, VCPU_FROZEN, true);
			if (error)
				break;
		}

		if (error) {
			while (--vcpu >= 0)
				vcpu_set_state(sc->vm, vcpu, VCPU_IDLE, false);
			goto done;
		}

		state_changed = 2;
		break;

	default:
		break;
	}

	switch(cmd) {
	case VM_RUN:
		if (ddi_copyin((void *)arg, &vmrun,
		    sizeof (struct vm_run), mode)) {
			return (EFAULT);
		}
		error = vm_run(sc->vm, &vmrun);
		if (ddi_copyout(&vmrun, (void *)arg,
		    sizeof (struct vm_run), mode)) {
			return (EFAULT);
		}
		break;
	case VM_LAPIC_IRQ:
		if (ddi_copyin((void *)arg, &vmirq,
		    sizeof (struct vm_lapic_irq), mode)) {
			return (EFAULT);
		}
		error = lapic_intr_edge(sc->vm, vmirq.cpuid, vmirq.vector);
		if (ddi_copyout(&vmirq, (void *)arg,
		    sizeof (struct vm_lapic_irq), mode)) {
			return (EFAULT);
		}
		break;
	case VM_LAPIC_LOCAL_IRQ:
		if (ddi_copyin((void *)arg, &vmirq,
		    sizeof (struct vm_lapic_irq), mode)) {
			return (EFAULT);
		}
		error = lapic_set_local_intr(sc->vm, vmirq.cpuid,
		    vmirq.vector);
		if (ddi_copyout(&vmirq, (void *)arg,
		    sizeof (struct vm_lapic_irq), mode)) {
			return (EFAULT);
		}
		break;
	case VM_LAPIC_MSI:
		if (ddi_copyin((void *)arg, &vmmsi,
		    sizeof (struct vm_lapic_msi), mode)) {
			return (EFAULT);
		}
		error = lapic_intr_msi(sc->vm, vmmsi.addr, vmmsi.msg);
		if (ddi_copyout(&vmmsi, (void *)arg,
		    sizeof (struct vm_lapic_msi), mode)) {
			return (EFAULT);
		}
	case VM_IOAPIC_ASSERT_IRQ:
		if (ddi_copyin((void *)arg, &ioapic_irq,
		    sizeof (struct vm_ioapic_irq), mode)) {
			return (EFAULT);
		}
		error = vioapic_assert_irq(sc->vm, ioapic_irq.irq);;
		if (ddi_copyout(&ioapic_irq, (void *)arg,
		    sizeof (struct vm_ioapic_irq), mode)) {
			return (EFAULT);
		}
		break;
	case VM_IOAPIC_DEASSERT_IRQ:
		if (ddi_copyin((void *)arg, &ioapic_irq,
		    sizeof (struct vm_ioapic_irq), mode)) {
			return (EFAULT);
		}
		error = vioapic_deassert_irq(sc->vm, ioapic_irq.irq);
		if (ddi_copyout(&ioapic_irq, (void *)arg,
		    sizeof (struct vm_ioapic_irq), mode)) {
			return (EFAULT);
		}
		break;
	case VM_IOAPIC_PULSE_IRQ:
		if (ddi_copyin((void *)arg, &ioapic_irq,
		    sizeof (struct vm_ioapic_irq), mode)) {
			return (EFAULT);
		}
		error = vioapic_pulse_irq(sc->vm, ioapic_irq.irq);
		if (ddi_copyout(&ioapic_irq, (void *)arg,
		    sizeof (struct vm_ioapic_irq), mode)) {
			return (EFAULT);
		}
		break;
	case VM_IOAPIC_PINCOUNT:
		error = 0;
		pincount = vioapic_pincount(sc->vm);
		if (ddi_copyout(&pincount, (void *)arg, sizeof (int), mode)) {
			return (EFAULT);
		}
		break;
	case VM_ISA_ASSERT_IRQ:
		if (ddi_copyin((void *)arg, &isa_irq,
		    sizeof (struct vm_isa_irq), mode)) {
			return (EFAULT);
		}
		error = vatpic_assert_irq(sc->vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1)
			error = vioapic_assert_irq(sc->vm,
			    isa_irq.ioapic_irq);
		if (ddi_copyout(&isa_irq, (void *)arg,
		    sizeof (struct vm_isa_irq), mode)) {
			return (EFAULT);
		
		}
		break;
	case VM_ISA_DEASSERT_IRQ:
		if (ddi_copyin((void *)arg, &isa_irq,
		    sizeof (struct vm_isa_irq), mode)) {
			return (EFAULT);
		}
		error = vatpic_deassert_irq(sc->vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1)
			error = vioapic_deassert_irq(sc->vm,
			    isa_irq.ioapic_irq);
		if (ddi_copyout(&isa_irq, (void *)arg,
		    sizeof (struct vm_isa_irq), mode)) {
			return (EFAULT);
		
		}
		break;
	case VM_ISA_PULSE_IRQ:
		if (ddi_copyin((void *)arg, &isa_irq,
		    sizeof (struct vm_isa_irq), mode)) {
			return (EFAULT);
		}
		error = vatpic_pulse_irq(sc->vm, isa_irq.atpic_irq);
		if (error == 0 && isa_irq.ioapic_irq != -1)
			error = vioapic_pulse_irq(sc->vm, isa_irq.ioapic_irq);
		if (ddi_copyout(&isa_irq, (void *)arg,
		    sizeof (struct vm_isa_irq), mode)) {
			return (EFAULT);
		
		}
		break;
	case VM_MAP_MEMORY:
		if (ddi_copyin((void *)arg, &seg,
		    sizeof (struct vm_memory_segment), mode)) {
			return (EFAULT);
		}
		error = vm_malloc(sc->vm, seg.gpa, seg.len);
		break;
	case VM_GET_MEMORY_SEG:
		if (ddi_copyin((void *)arg, &seg,
		    sizeof (struct vm_memory_segment), mode)) {
			return (EFAULT);
		}
		seg.len = 0;
		(void)vm_gpabase2memseg(sc->vm, seg.gpa, &seg);
		if (ddi_copyout(&seg, (void *)arg,
		    sizeof (struct vm_memory_segment), mode)) {
			return (EFAULT);
		}
		error = 0;
		break;
	case VM_GET_REGISTER:
		if (ddi_copyin((void *)arg, &vmreg,
		    sizeof (struct vm_register), mode)) {
			return (EFAULT);
		}
		error = vm_get_register(sc->vm, vmreg.cpuid, vmreg.regnum,
					&vmreg.regval);
		if (!error) {
			if (ddi_copyout(&vmreg, (void *)arg,
				 sizeof (struct vm_register), mode)) {
				return (EFAULT);
			}
		}
		break;
	case VM_SET_REGISTER:
		if (ddi_copyin((void *)arg, &vmreg,
		    sizeof (struct vm_register), mode)) {
			return (EFAULT);
		}
		error = vm_set_register(sc->vm, vmreg.cpuid, vmreg.regnum,
					vmreg.regval);
		break;
	case VM_SET_SEGMENT_DESCRIPTOR:
		if (ddi_copyin((void *)arg, &vmsegdesc,
		    sizeof (struct vm_seg_desc), mode)) {
			return (EFAULT);
		}
		error = vm_set_seg_desc(sc->vm, vmsegdesc.cpuid,
					vmsegdesc.regnum,
					&vmsegdesc.desc);
		break;
	case VM_GET_SEGMENT_DESCRIPTOR:
		if (ddi_copyin((void *)arg, &vmsegdesc,
		    sizeof (struct vm_seg_desc), mode)) {
			return (EFAULT);
		}
		error = vm_get_seg_desc(sc->vm, vmsegdesc.cpuid,
					vmsegdesc.regnum,
					&vmsegdesc.desc);
		if (!error) {
			if (ddi_copyout(&vmsegdesc, (void *)arg,
			    sizeof (struct vm_seg_desc), mode)) {
				return (EFAULT);
			}
		}
		break;
	case VM_GET_CAPABILITY:
		if (ddi_copyin((void *)arg, &vmcap,
		    sizeof (struct vm_capability), mode)) {
			return (EFAULT);
		}
		error = vm_get_capability(sc->vm, vmcap.cpuid,
					  vmcap.captype,
					  &vmcap.capval);
		if (!error) {
			if (ddi_copyout(&vmcap, (void *)arg,
			    sizeof (struct vm_capability), mode)) {
				return (EFAULT);
			}
		}
		break;
	case VM_SET_CAPABILITY:
		if (ddi_copyin((void *)arg, &vmcap,
		    sizeof (struct vm_capability), mode)) {
			return (EFAULT);
		}
		error = vm_set_capability(sc->vm, vmcap.cpuid,
					  vmcap.captype,
					  vmcap.capval);
		break;
	case VM_SET_X2APIC_STATE:
		if (ddi_copyin((void *)arg, &x2apic,
		    sizeof (struct vm_x2apic), mode)) {
			return (EFAULT);
		}
		error = vm_set_x2apic_state(sc->vm,
					    x2apic.cpuid, x2apic.state);
		break;
	case VM_GET_X2APIC_STATE:
		if (ddi_copyin((void *)arg, &x2apic,
		    sizeof (struct vm_x2apic), mode)) {
			return (EFAULT);
		}
		error = vm_get_x2apic_state(sc->vm,
					    x2apic.cpuid, &x2apic.state);
		if (!error) {
			if (ddi_copyout(&x2apic, (void *)arg,
			    sizeof (struct vm_x2apic), mode)) {
				return (EFAULT);
			}
		}
		break;
	case VM_GLA2GPA: {
		CTASSERT(PROT_READ == VM_PROT_READ);
		CTASSERT(PROT_WRITE == VM_PROT_WRITE);
		CTASSERT(PROT_EXEC == VM_PROT_EXECUTE);
		if (ddi_copyin((void *)arg, &gg,
		    sizeof (struct vm_gla2gpa), mode)) {
			return (EFAULT);
		}
		error = vm_gla2gpa(sc->vm, gg.vcpuid, &gg.paging, gg.gla,
		    gg.prot, &gg.gpa);
		KASSERT(error == 0 || error == 1 || error == -1,
		    ("%s: vm_gla2gpa unknown error %d", __func__, error));
		if (error >= 0) {
			/*
			 * error = 0: the translation was successful
			 * error = 1: a fault was injected into the guest
			 */
			gg.fault = error;
			error = 0;
			if (ddi_copyout(&gg, (void *)arg,
			    sizeof (struct vm_gla2gpa), mode)) {
				return (EFAULT);
			}
		} else {
			error = EFAULT;
		}
		break;
	}
	case VM_ACTIVATE_CPU:
		if (ddi_copyin((void *)arg, &vac,
		    sizeof (struct vm_activate_cpu), mode)) {
			return (EFAULT);
		}
		error = vm_activate_cpu(sc->vm, vac.vcpuid);
		break;
	case VM_RESTART_INSTRUCTION:
		error = vm_restart_instruction(sc->vm, vcpu);
		break;
	default:
		error = ENOTTY;
		break;
	}

	if (state_changed == 1) {
		vcpu_set_state(sc->vm, vcpu, VCPU_IDLE, false);
	} else if (state_changed == 2) {
		for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++)
			vcpu_set_state(sc->vm, vcpu, VCPU_IDLE, false);
	}

done:
	/* Make sure that no handler returns a bogus value like ERESTART */
	KASSERT(error >= 0, ("vmmdev_ioctl: invalid error return %d", error));
	return (error);
}

static minor_t
vmm_find_free_minor(void)
{
	minor_t		minor;

	for (minor = 1; ; minor++) {
		if (ddi_get_soft_state(vmm_statep, minor) == NULL)
			break;
	}

	return (minor);
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

static int
vmmdev_do_vm_create(dev_info_t *dip, char *name)
{
	struct vmm_softc	*sc = NULL;
	minor_t			minor;
	int			error = ENOMEM;

	if (strlen(name) >= VM_MAX_NAMELEN) {
		return (EINVAL);
	}

	mutex_enter(&vmmdev_mtx);
	if (!vmmdev_mod_incr()) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	minor = vmm_find_free_minor();
	if (ddi_soft_state_zalloc(vmm_statep, minor) != DDI_SUCCESS) {
		goto fail;
	} else if ((sc = ddi_get_soft_state(vmm_statep, minor)) == NULL) {
		ddi_soft_state_free(vmm_statep, minor);
		goto fail;
	} else if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	error = vm_create(name, &sc->vm);
	if (error == 0) {
		/* Complete VM intialization and report success. */
		strcpy(sc->name, name);
		sc->minor = minor;
		SLIST_INSERT_HEAD(&head, sc, link);
		mutex_exit(&vmmdev_mtx);
		return (0);
	}

	ddi_remove_minor_node(dip, name);
fail:
	vmmdev_mod_decr();
	if (sc != NULL) {
		ddi_soft_state_free(vmm_statep, minor);
	}
	mutex_exit(&vmmdev_mtx);
	return (error);
}

static struct vmm_softc *
vmm_lookup(char *name)
{
	struct vmm_softc	*sc;

	SLIST_FOREACH(sc, &head, link) {
		if (strcmp(sc->name, name) == 0) {
			break;
		}
	}

	return (sc);

}

struct vm *
vm_lookup_by_name(char *name)
{
	struct vmm_softc	*sc;

	mutex_enter(&vmmdev_mtx);

	if ((sc = vmm_lookup(name)) == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (NULL);
	}

	mutex_exit(&vmmdev_mtx);

	return (sc->vm);
}

static int
vmmdev_do_vm_destroy(dev_info_t *dip, char *name)
{
	struct vmm_softc	*sc;
	dev_info_t		*pdip = ddi_get_parent(dip);

	mutex_enter(&vmmdev_mtx);

	if ((sc = vmm_lookup(name)) == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENOENT);
	}
	if (sc->open) {
		mutex_exit(&vmmdev_mtx);
		return (EBUSY);
	}

	vm_destroy(sc->vm);
	SLIST_REMOVE(&head, sc, vmm_softc, link);
	ddi_remove_minor_node(dip, name);
	ddi_soft_state_free(vmm_statep, sc->minor);
	(void) devfs_clean(pdip, NULL, DV_CLEAN_FORCE);
	vmmdev_mod_decr();

	mutex_exit(&vmmdev_mtx);

	return (0);
}

int
vmmdev_do_vm_mmap(struct vmm_softc *vmm_sc, off_t off, int nprot)
{
	vm_paddr_t	paddr;

	mutex_enter(&vmmdev_mtx);

	paddr = vm_gpa2hpa(vmm_sc->vm, (vm_paddr_t)off, PAGE_SIZE);
	if (paddr == -1) {
		return (-1);
	}

	mutex_exit(&vmmdev_mtx);

	return (btop(paddr));
}


static int
vmm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t			minor;
	struct vmm_softc	*sc;

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

	if (sc->open) {
		mutex_exit(&vmmdev_mtx);
		return (EBUSY);
	}
	sc->open = B_TRUE;
	mutex_exit(&vmmdev_mtx);

	return (0);
}

static int
vmm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	minor_t			minor;
	struct vmm_softc	*sc;

	minor = getminor(dev);
	if (minor == VMM_CTL_MINOR)
		return (0);

	mutex_enter(&vmmdev_mtx);
	sc = ddi_get_soft_state(vmm_statep, minor);
	if (sc == NULL) {
		mutex_exit(&vmmdev_mtx);
		return (ENXIO);
	}

	sc->open = B_FALSE;
	mutex_exit(&vmmdev_mtx);

	return (0);
}

static int
vmm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct vmm_softc	*sc;
	struct vmm_ioctl	kvi;
	minor_t			minor;

	minor = getminor(dev);

	if (minor == VMM_CTL_MINOR) {
		if (ddi_copyin((void *)arg, &kvi, sizeof (struct vmm_ioctl),
		    mode)) {
			return (EFAULT);
		}
		switch (cmd) {
		case VMM_CREATE_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_create(vmm_dip, kvi.vmm_name));
		case VMM_DESTROY_VM:
			if ((mode & FWRITE) == 0)
				return (EPERM);
			return (vmmdev_do_vm_destroy(vmm_dip, kvi.vmm_name));
		default:
			break;
		}
	}

	sc = ddi_get_soft_state(vmm_statep, minor);
	ASSERT(sc);

	return (vmmdev_do_ioctl(sc, cmd, arg, mode, credp, rvalp));
}

static int
vmm_mmap(dev_t dev, off_t off, int prot)
{
	struct vmm_softc	*sc;

	sc = ddi_get_soft_state(vmm_statep, getminor(dev));
	ASSERT(sc);

	return (vmmdev_do_vm_mmap(sc, off, prot));
}

static int
vmm_segmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
   unsigned int prot, unsigned int maxprot, unsigned int flags, cred_t *credp)
{
	struct segdev_crargs	dev_a;
	int			error;

	as_rangelock(as);

	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		return (error);
	}

	dev_a.mapfunc = vmm_mmap;
	dev_a.dev = dev;
	dev_a.offset = off;
	dev_a.type = (flags & MAP_TYPE);
	dev_a.prot = (uchar_t)prot;
	dev_a.maxprot = (uchar_t)maxprot;
	dev_a.hat_attr = 0;
	dev_a.hat_flags = HAT_LOAD_NOCONSIST;
	dev_a.devmap_data = NULL;

	error = as_map(as, *addrp, len, segdev_create, &dev_a);

	as_rangeunlock(as);

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
	vmmdev_load_failure = B_FALSE;
	vmm_dip = dip;

	/*
	 * Create control node.  Other nodes will be created on demand.
	 */
	if (ddi_create_minor_node(dip, VMM_CTL_MINOR_NODE, S_IFCHR,
	    VMM_CTL_MINOR, DDI_PSEUDO, 0) != 0) {
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);

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
	if (!SLIST_EMPTY(&head) || vmmdev_inst_count != 0) {
		mutex_exit(&vmmdev_mtx);
		return (DDI_FAILURE);
	}

	/* Remove the control node. */
	ddi_remove_minor_node(dip, VMM_CTL_MINOR_NODE);
	vmm_dip = NULL;
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
	vmm_mmap,
	vmm_segmap,
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops vmm_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
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

	error = ddi_soft_state_init(&vmm_statep, sizeof (struct vmm_softc), 0);
	if (error) {
		return (error);
	}

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&vmm_statep);
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
	ddi_soft_state_fini(&vmm_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
