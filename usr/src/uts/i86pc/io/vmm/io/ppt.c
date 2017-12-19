/*-
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/pciio.h>
#ifdef __FreeBSD__
#include <sys/rman.h>
#endif
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#ifdef __FreeBSD__
#include <machine/resource.h>
#endif

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "vmm_lapic.h"
#include "vmm_ktr.h"

#include "iommu.h"
#include "ppt.h"

/* XXX locking */

#define	MAX_MSIMSGS	32

/*
 * If the MSI-X table is located in the middle of a BAR then that MMIO
 * region gets split into two segments - one segment above the MSI-X table
 * and the other segment below the MSI-X table - with a hole in place of
 * the MSI-X table so accesses to it can be trapped and emulated.
 *
 * So, allocate a MMIO segment for each BAR register + 1 additional segment.
 */
#define	MAX_MMIOSEGS	((PCIR_MAX_BAR_0 + 1) + 1)

MALLOC_DEFINE(M_PPTMSIX, "pptmsix", "Passthru MSI-X resources");

struct pptintr_arg {				/* pptintr(pptintr_arg) */
	struct pptdev	*pptdev;
	uint64_t	addr;
	uint64_t	msg_data;
};

struct pptseg {
	vm_paddr_t	gpa;
	size_t		len;
	int		wired;
};

struct pptdev {
	device_t	dev;
	struct vm	*vm;			/* owner of this device */
	TAILQ_ENTRY(pptdev)	next;
	struct pptseg mmio[MAX_MMIOSEGS];
	struct {
		int	num_msgs;		/* guest state */
#ifdef __FreeBSD__
		int	startrid;		/* host state */
		struct resource *res[MAX_MSIMSGS];
		void	*cookie[MAX_MSIMSGS];
#else
		boolean_t is_fixed;
		size_t	inth_sz;
		ddi_intr_handle_t *inth;
#endif
		struct pptintr_arg arg[MAX_MSIMSGS];
	} msi;

	struct {
		int num_msgs;
#ifdef __FreeBSD__
		int startrid;
		int msix_table_rid;
		struct resource *msix_table_res;
		struct resource **res;
		void **cookie;
#else
		size_t inth_sz;
		size_t arg_sz;
		ddi_intr_handle_t *inth;
#endif
		struct pptintr_arg *arg;
	} msix;
};

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, ppt, CTLFLAG_RW, 0, "bhyve passthru devices");

static int num_pptdevs;
SYSCTL_INT(_hw_vmm_ppt, OID_AUTO, devices, CTLFLAG_RD, &num_pptdevs, 0,
    "number of pci passthru devices");

static TAILQ_HEAD(, pptdev) pptdev_list = TAILQ_HEAD_INITIALIZER(pptdev_list);

#ifdef __FreeBSD__
static int
ppt_probe(device_t dev)
{
	int bus, slot, func;
	struct pci_devinfo *dinfo;

	dinfo = (struct pci_devinfo *)device_get_ivars(dev);

	bus = pci_get_bus(dev);
	slot = pci_get_slot(dev);
	func = pci_get_function(dev);

	/*
	 * To qualify as a pci passthrough device a device must:
	 * - be allowed by administrator to be used in this role
	 * - be an endpoint device
	 */
	if ((dinfo->cfg.hdrtype & PCIM_HDRTYPE) != PCIM_HDRTYPE_NORMAL)
		return (ENXIO);
	else if (vmm_is_pptdev(bus, slot, func))
		return (0);
	else
		/*
		 * Returning BUS_PROBE_NOWILDCARD here matches devices that the
		 * SR-IOV infrastructure specified as "ppt" passthrough devices.
		 * All normal devices that did not have "ppt" specified as their
		 * driver will not be matched by this.
		 */
		return (BUS_PROBE_NOWILDCARD);
}
#endif

static int
ppt_attach(device_t dev)
{
	struct pptdev *ppt;

	ppt = device_get_softc(dev);

	num_pptdevs++;
	TAILQ_INSERT_TAIL(&pptdev_list, ppt, next);
	ppt->dev = dev;

#ifdef __FreeBSD__
	if (bootverbose)
		device_printf(dev, "attached\n");
#endif

	return (0);
}

static int
ppt_detach(device_t dev)
{
	struct pptdev *ppt;

	ppt = device_get_softc(dev);

	if (ppt->vm != NULL)
		return (EBUSY);
	num_pptdevs--;
	TAILQ_REMOVE(&pptdev_list, ppt, next);

	return (0);
}

#ifdef __FreeBSD__
static device_method_t ppt_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ppt_probe),
	DEVMETHOD(device_attach,	ppt_attach),
	DEVMETHOD(device_detach,	ppt_detach),
	{0, 0}
};

static devclass_t ppt_devclass;
DEFINE_CLASS_0(ppt, ppt_driver, ppt_methods, sizeof(struct pptdev));
DRIVER_MODULE(ppt, pci, ppt_driver, ppt_devclass, NULL, NULL);
#endif

static void *ppt_state;

static int
ppt_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct pptdev *ppt;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	ddi_soft_state_zalloc(ppt_state, ddi_get_instance(dip));

	ppt = ddi_get_soft_state(ppt_state, ddi_get_instance(dip));
	ppt->dev = dip;

	ddi_set_driver_private(dip, ppt);

	if (ppt_attach(dip) == 0)
			return (DDI_SUCCESS);

	ddi_set_driver_private(dip, NULL);

	ddi_soft_state_free(ppt_state, ddi_get_instance(dip));

	return (DDI_FAILURE);
}

static int
ppt_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (ppt_detach(dip) != 0)
			return (DDI_FAILURE);

	ddi_set_driver_private(dip, NULL);

	ddi_soft_state_free(ppt_state, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

static struct dev_ops ppt_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	ppt_ddi_attach,
	ppt_ddi_detach,
	nodev,		/* reset */
	(struct cb_ops *)NULL,
	(struct bus_ops *)NULL
};

static struct modldrv modldrv = {
	&mod_driverops,
	"ppt",
	&ppt_ops
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

	error = ddi_soft_state_init(&ppt_state, sizeof (struct pptdev), 0);
	if (error)
		return (error);

	error = mod_install(&modlinkage);
	if (error)
		ddi_soft_state_fini(&ppt_state);

	return (error);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	ddi_soft_state_fini(&ppt_state);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static struct pptdev *
ppt_find(int bus, int slot, int func)
{
	device_t dev;
	struct pptdev *ppt;
	int b, s, f;

	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		dev = ppt->dev;
		b = pci_get_bus(dev);
		s = pci_get_slot(dev);
		f = pci_get_function(dev);
		if (bus == b && slot == s && func == f)
			return (ppt);
	}
	return (NULL);
}

static void
ppt_unmap_mmio(struct vm *vm, struct pptdev *ppt)
{
	int i;
	struct pptseg *seg;

	for (i = 0; i < MAX_MMIOSEGS; i++) {
		seg = &ppt->mmio[i];
		if (seg->len == 0)
			continue;
		(void)vm_unmap_mmio(vm, seg->gpa, seg->len);
		bzero(seg, sizeof(struct pptseg));
	}
}

static void
ppt_teardown_msi(struct pptdev *ppt)
{
	int i, rid;
#ifdef __FreeBSD__
	void *cookie;
	struct resource *res;
#endif
	int intr_cap = 0;

	if (ppt->msi.num_msgs == 0)
		return;

	for (i = 0; i < ppt->msi.num_msgs; i++) {
#ifdef __FreeBSD__
		rid = ppt->msi.startrid + i;
		res = ppt->msi.res[i];
		cookie = ppt->msi.cookie[i];

		if (cookie != NULL)
			bus_teardown_intr(ppt->dev, res, cookie);

		if (res != NULL)
			bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, res);
		
		ppt->msi.res[i] = NULL;
		ppt->msi.cookie[i] = NULL;
#else
		(void) ddi_intr_get_cap(ppt->msi.inth[i], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			ddi_intr_block_disable(&ppt->msi.inth[i], 1);
		else
			ddi_intr_disable(ppt->msi.inth[i]);

		ddi_intr_remove_handler(ppt->msi.inth[i]);
		ddi_intr_free(ppt->msi.inth[i]);

		ppt->msi.inth[i] = NULL;
#endif
	}

#ifdef __FreeBSD__
	if (ppt->msi.startrid == 1)
		pci_release_msi(ppt->dev);
#else
	kmem_free(ppt->msi.inth, ppt->msi.inth_sz);
	ppt->msi.inth = NULL;
	ppt->msi.inth_sz = 0;
	ppt->msi.is_fixed = B_FALSE;
#endif

	ppt->msi.num_msgs = 0;
}

static void 
ppt_teardown_msix_intr(struct pptdev *ppt, int idx)
{
#ifdef __FreeBSD__
	int rid;
	struct resource *res;
	void *cookie;

	rid = ppt->msix.startrid + idx;
	res = ppt->msix.res[idx];
	cookie = ppt->msix.cookie[idx];

	if (cookie != NULL) 
		bus_teardown_intr(ppt->dev, res, cookie);

	if (res != NULL) 
		bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, res);

	ppt->msix.res[idx] = NULL;
	ppt->msix.cookie[idx] = NULL;
#else
	if (ppt->msix.inth != NULL && ppt->msix.inth[idx] != NULL) {
		int intr_cap;

		(void) ddi_intr_get_cap(ppt->msix.inth[idx], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			ddi_intr_block_disable(&ppt->msix.inth[idx], 1);
		else
			ddi_intr_disable(ppt->msix.inth[idx]);

		ddi_intr_remove_handler(ppt->msix.inth[idx]);
	}
#endif
}

static void 
ppt_teardown_msix(struct pptdev *ppt)
{
	int i;

	if (ppt->msix.num_msgs == 0) 
		return;

	for (i = 0; i < ppt->msix.num_msgs; i++)
		ppt_teardown_msix_intr(ppt, i);

#ifdef __FreeBSD__
	if (ppt->msix.msix_table_res) {
		bus_release_resource(ppt->dev, SYS_RES_MEMORY, 
				     ppt->msix.msix_table_rid,
				     ppt->msix.msix_table_res);
		ppt->msix.msix_table_res = NULL;
		ppt->msix.msix_table_rid = 0;
	}

	free(ppt->msix.res, M_PPTMSIX);
	free(ppt->msix.cookie, M_PPTMSIX);
	free(ppt->msix.arg, M_PPTMSIX);

	pci_release_msi(ppt->dev);
#else
	if (ppt->msix.inth) {
		for (i = 0; i < ppt->msix.num_msgs; i++)
			ddi_intr_free(ppt->msix.inth[i]);
		kmem_free(ppt->msix.inth, ppt->msix.inth_sz);
		ppt->msix.inth = NULL;
		ppt->msix.inth_sz = 0;
		kmem_free(ppt->msix.arg, ppt->msix.arg_sz);
		ppt->msix.arg = NULL;
		ppt->msix.arg_sz = 0;
	}
#endif

	ppt->msix.num_msgs = 0;
}

int
ppt_avail_devices(void)
{

	return (num_pptdevs);
}

int
ppt_assigned_devices(struct vm *vm)
{
	struct pptdev *ppt;
	int num;

	num = 0;
	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		if (ppt->vm == vm)
			num++;
	}
	return (num);
}

boolean_t
ppt_is_mmio(struct vm *vm, vm_paddr_t gpa)
{
	int i;
	struct pptdev *ppt;
	struct pptseg *seg;

	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		if (ppt->vm != vm)
			continue;

		for (i = 0; i < MAX_MMIOSEGS; i++) {
			seg = &ppt->mmio[i];
			if (seg->len == 0)
				continue;
			if (gpa >= seg->gpa && gpa < seg->gpa + seg->len)
				return (TRUE);
		}
	}

	return (FALSE);
}

int
ppt_assign_device(struct vm *vm, int bus, int slot, int func)
{
	struct pptdev *ppt;

	ppt = ppt_find(bus, slot, func);
	if (ppt != NULL) {
		/*
		 * If this device is owned by a different VM then we
		 * cannot change its owner.
		 */
		if (ppt->vm != NULL && ppt->vm != vm)
			return (EBUSY);

		pci_save_state(ppt->dev);
		pcie_flr(ppt->dev,
		    max(pcie_get_max_completion_timeout(ppt->dev) / 1000, 10),
		    true);
		pci_restore_state(ppt->dev);
		ppt->vm = vm;
		iommu_remove_device(iommu_host_domain(), pci_get_rid(ppt->dev));
		iommu_add_device(vm_iommu_domain(vm), pci_get_rid(ppt->dev));
		return (0);
	}
	return (ENOENT);
}

int
ppt_unassign_device(struct vm *vm, int bus, int slot, int func)
{
	struct pptdev *ppt;

	ppt = ppt_find(bus, slot, func);
	if (ppt != NULL) {
		/*
		 * If this device is not owned by this 'vm' then bail out.
		 */
		if (ppt->vm != vm)
			return (EBUSY);

		pci_save_state(ppt->dev);
		pcie_flr(ppt->dev,
		    max(pcie_get_max_completion_timeout(ppt->dev) / 1000, 10),
		    true);
		pci_restore_state(ppt->dev);
		ppt_unmap_mmio(vm, ppt);
		ppt_teardown_msi(ppt);
		ppt_teardown_msix(ppt);
		iommu_remove_device(vm_iommu_domain(vm), pci_get_rid(ppt->dev));
		iommu_add_device(iommu_host_domain(), pci_get_rid(ppt->dev));
		ppt->vm = NULL;
		return (0);
	}
	return (ENOENT);
}

int
ppt_unassign_all(struct vm *vm)
{
	struct pptdev *ppt;
	int bus, slot, func;
	device_t dev;

	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		if (ppt->vm == vm) {
			dev = ppt->dev;
			bus = pci_get_bus(dev);
			slot = pci_get_slot(dev);
			func = pci_get_function(dev);
			vm_unassign_pptdev(vm, bus, slot, func);
		}
	}

	return (0);
}

int
ppt_map_mmio(struct vm *vm, int bus, int slot, int func,
	     vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	int i, error;
	struct pptseg *seg;
	struct pptdev *ppt;

	ppt = ppt_find(bus, slot, func);
	if (ppt != NULL) {
		if (ppt->vm != vm)
			return (EBUSY);

		for (i = 0; i < MAX_MMIOSEGS; i++) {
			seg = &ppt->mmio[i];
			if (seg->len == 0) {
				error = vm_map_mmio(vm, gpa, len, hpa);
				if (error == 0) {
					seg->gpa = gpa;
					seg->len = len;
				}
				return (error);
			}
		}
		return (ENOSPC);
	}
	return (ENOENT);
}

#ifdef __FreeBSD__
static int
pptintr(void *arg)
#else
static uint_t
pptintr(char *arg, char *unused)
#endif
{
	struct pptdev *ppt;
	struct pptintr_arg *pptarg;
	
	pptarg = (struct pptintr_arg *)arg;
	ppt = pptarg->pptdev;

	if (ppt->vm != NULL)
		lapic_intr_msi(ppt->vm, pptarg->addr, pptarg->msg_data);
	else {
		/*
		 * XXX
		 * This is not expected to happen - panic?
		 */
	}

	/*
	 * For legacy interrupts give other filters a chance in case
	 * the interrupt was not generated by the passthrough device.
	 */
#ifdef __FreeBSD__
	if (ppt->msi.startrid == 0)
		return (FILTER_STRAY);
	else
		return (FILTER_HANDLED);
#else
	return (ppt->msi.is_fixed ? DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
#endif
}

int
ppt_setup_msi(struct vm *vm, int vcpu, int bus, int slot, int func,
	      uint64_t addr, uint64_t msg, int numvec)
{
	int i, rid, flags;
	int msi_count, startrid, error, tmp;
	int intr_type, intr_cap = 0;
	struct pptdev *ppt;

	if (numvec < 0 || numvec > MAX_MSIMSGS)
		return (EINVAL);

	ppt = ppt_find(bus, slot, func);
	if (ppt == NULL)
		return (ENOENT);
	if (ppt->vm != vm)		/* Make sure we own this device */
		return (EBUSY);

	/* Free any allocated resources */
	ppt_teardown_msi(ppt);

	if (numvec == 0)		/* nothing more to do */
		return (0);

#ifdef __FreeBSD__
	flags = RF_ACTIVE;
	msi_count = pci_msi_count(ppt->dev);
	if (msi_count == 0) {
		startrid = 0;		/* legacy interrupt */
		msi_count = 1;
		flags |= RF_SHAREABLE;
	} else
		startrid = 1;		/* MSI */

	/*
	 * The device must be capable of supporting the number of vectors
	 * the guest wants to allocate.
	 */
	if (numvec > msi_count)
		return (EINVAL);

	/*
	 * Make sure that we can allocate all the MSI vectors that are needed
	 * by the guest.
	 */
	if (startrid == 1) {
		tmp = numvec;
		error = pci_alloc_msi(ppt->dev, &tmp);
		if (error)
			return (error);
		else if (tmp != numvec) {
			pci_release_msi(ppt->dev);
			return (ENOSPC);
		} else {
			/* success */
		}
	}
	
	ppt->msi.startrid = startrid;

	/*
	 * Allocate the irq resource and attach it to the interrupt handler.
	 */
	for (i = 0; i < numvec; i++) {
		ppt->msi.num_msgs = i + 1;
		ppt->msi.cookie[i] = NULL;

		rid = startrid + i;
		ppt->msi.res[i] = bus_alloc_resource_any(ppt->dev, SYS_RES_IRQ,
							 &rid, flags);
		if (ppt->msi.res[i] == NULL)
			break;

		ppt->msi.arg[i].pptdev = ppt;
		ppt->msi.arg[i].addr = addr;
		ppt->msi.arg[i].msg_data = msg + i;

		error = bus_setup_intr(ppt->dev, ppt->msi.res[i],
				       INTR_TYPE_NET | INTR_MPSAFE,
				       pptintr, NULL, &ppt->msi.arg[i],
				       &ppt->msi.cookie[i]);
		if (error != 0)
			break;
	}
#else
	if (ddi_intr_get_navail(ppt->dev, DDI_INTR_TYPE_MSI, &msi_count) !=
	    DDI_SUCCESS) {
		if (ddi_intr_get_navail(ppt->dev, DDI_INTR_TYPE_FIXED,
		    &msi_count) != DDI_SUCCESS)
			return (EINVAL);

		intr_type = DDI_INTR_TYPE_FIXED;
		ppt->msi.is_fixed = B_TRUE;
	} else {
		intr_type = DDI_INTR_TYPE_MSI;
	}

	/*
	 * The device must be capable of supporting the number of vectors
	 * the guest wants to allocate.
	 */
	if (numvec > msi_count)
		return (EINVAL);

	ppt->msi.inth_sz = numvec * sizeof (ddi_intr_handle_t);
	ppt->msi.inth = kmem_zalloc(ppt->msi.inth_sz, KM_SLEEP);
	if (ddi_intr_alloc(ppt->dev, ppt->msi.inth, intr_type, 0,
	    numvec, &msi_count, 0) != DDI_SUCCESS) {
		kmem_free(ppt->msi.inth, ppt->msi.inth_sz);
		return (EINVAL);
	}

	/*
	 * Again, make sure we actually got as many vectors as the guest wanted
	 * to allocate.
	 */
	if (numvec != msi_count) {
		ppt_teardown_msi(ppt);
		return (EINVAL);
	}
	/*
	 * Set up & enable interrupt handler for each vector.
	 */
	for (i = 0; i < numvec; i++) {
		ppt->msi.num_msgs = i + 1;
		ppt->msi.arg[i].pptdev = ppt;
		ppt->msi.arg[i].addr = addr;
		ppt->msi.arg[i].msg_data = msg + i;

		if (ddi_intr_add_handler(ppt->msi.inth[i], pptintr,
		    &ppt->msi.arg[i], NULL) != DDI_SUCCESS)
			break;

		(void) ddi_intr_get_cap(ppt->msi.inth[i], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			error = ddi_intr_block_enable(&ppt->msi.inth[i], 1);
		else
			error = ddi_intr_enable(ppt->msi.inth[i]);

		if (error != DDI_SUCCESS)
			break;
	}
#endif
	
	if (i < numvec) {
		ppt_teardown_msi(ppt);
		return (ENXIO);
	}

	return (0);
}

int
ppt_setup_msix(struct vm *vm, int vcpu, int bus, int slot, int func,
	       int idx, uint64_t addr, uint64_t msg, uint32_t vector_control)
{
	struct pptdev *ppt;
	struct pci_devinfo *dinfo;
	int numvec, alloced, rid, error;
	size_t res_size, cookie_size, arg_size;
	int intr_cap;

	ppt = ppt_find(bus, slot, func);
	if (ppt == NULL)
		return (ENOENT);
	if (ppt->vm != vm)		/* Make sure we own this device */
		return (EBUSY);

#ifdef __FreeBSD__
	dinfo = device_get_ivars(ppt->dev);
	if (!dinfo) 
		return (ENXIO);

	/* 
	 * First-time configuration:
	 * 	Allocate the MSI-X table
	 *	Allocate the IRQ resources
	 *	Set up some variables in ppt->msix
	 */
	if (ppt->msix.num_msgs == 0) {
		numvec = pci_msix_count(ppt->dev);
		if (numvec <= 0)
			return (EINVAL);

		ppt->msix.startrid = 1;
		ppt->msix.num_msgs = numvec;

		res_size = numvec * sizeof(ppt->msix.res[0]);
		cookie_size = numvec * sizeof(ppt->msix.cookie[0]);
		arg_size = numvec * sizeof(ppt->msix.arg[0]);

		ppt->msix.res = malloc(res_size, M_PPTMSIX, M_WAITOK | M_ZERO);
		ppt->msix.cookie = malloc(cookie_size, M_PPTMSIX,
					  M_WAITOK | M_ZERO);
		ppt->msix.arg = malloc(arg_size, M_PPTMSIX, M_WAITOK | M_ZERO);

		rid = dinfo->cfg.msix.msix_table_bar;
		ppt->msix.msix_table_res = bus_alloc_resource_any(ppt->dev,
					       SYS_RES_MEMORY, &rid, RF_ACTIVE);

		if (ppt->msix.msix_table_res == NULL) {
			ppt_teardown_msix(ppt);
			return (ENOSPC);
		}
		ppt->msix.msix_table_rid = rid;

		alloced = numvec;
		error = pci_alloc_msix(ppt->dev, &alloced);
		if (error || alloced != numvec) {
			ppt_teardown_msix(ppt);
			return (error == 0 ? ENOSPC: error);
		}
	}
#else
	/*
	 * First-time configuration:
	 * 	Allocate the MSI-X table
	 *	Allocate the IRQ resources
	 *	Set up some variables in ppt->msix
	 */
	if (ppt->msix.num_msgs == 0) {
		if (ddi_intr_get_navail(ppt->dev, DDI_INTR_TYPE_MSIX, &numvec) !=
		    DDI_SUCCESS)
			return (EINVAL);

		ppt->msix.num_msgs = numvec;

		ppt->msix.arg_sz = numvec * sizeof(ppt->msix.arg[0]);
		ppt->msix.arg = kmem_zalloc(ppt->msix.arg_sz, KM_SLEEP);
		ppt->msix.inth_sz = numvec * sizeof(ddi_intr_handle_t);
		ppt->msix.inth = kmem_zalloc(ppt->msix.inth_sz, KM_SLEEP);

		if (ddi_intr_alloc(ppt->dev, ppt->msix.inth, DDI_INTR_TYPE_MSIX,
		    0, numvec, &alloced, 0) != DDI_SUCCESS) {
			kmem_free(ppt->msix.arg, ppt->msix.arg_sz);
			kmem_free(ppt->msix.inth, ppt->msix.inth_sz);
			ppt->msix.arg = NULL;
			ppt->msix.inth = NULL;
			ppt->msix.arg_sz = ppt->msix.inth_sz = 0;
			return (EINVAL);
		}

		if (numvec != alloced) {
			ppt_teardown_msix(ppt);
			return (EINVAL);
		}
	}
#endif
	if (idx >= ppt->msix.num_msgs)
		return (EINVAL);

	if ((vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
		/* Tear down the IRQ if it's already set up */
		ppt_teardown_msix_intr(ppt, idx);

#ifdef __FreeBSD__
		/* Allocate the IRQ resource */
		ppt->msix.cookie[idx] = NULL;
		rid = ppt->msix.startrid + idx;
		ppt->msix.res[idx] = bus_alloc_resource_any(ppt->dev, SYS_RES_IRQ,
							    &rid, RF_ACTIVE);
		if (ppt->msix.res[idx] == NULL)
			return (ENXIO);
#endif
		ppt->msix.arg[idx].pptdev = ppt;
		ppt->msix.arg[idx].addr = addr;
		ppt->msix.arg[idx].msg_data = msg;
	
		/* Setup the MSI-X interrupt */
#ifdef __FreeBSD__
		error = bus_setup_intr(ppt->dev, ppt->msix.res[idx],
				       INTR_TYPE_NET | INTR_MPSAFE,
				       pptintr, NULL, &ppt->msix.arg[idx],
				       &ppt->msix.cookie[idx]);
	
		if (error != 0) {
			bus_teardown_intr(ppt->dev, ppt->msix.res[idx], ppt->msix.cookie[idx]);
			bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, ppt->msix.res[idx]);
			ppt->msix.cookie[idx] = NULL;
			ppt->msix.res[idx] = NULL;
			return (ENXIO);
		}
#else
		if (ddi_intr_add_handler(ppt->msix.inth[idx], pptintr,
		    &ppt->msix.arg[idx], NULL) != DDI_SUCCESS)
			return (ENXIO);

		(void) ddi_intr_get_cap(ppt->msix.inth[idx], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			error = ddi_intr_block_enable(&ppt->msix.inth[idx], 1);
		else
			error = ddi_intr_enable(ppt->msix.inth[idx]);

		if (error != DDI_SUCCESS) {
			ddi_intr_remove_handler(ppt->msix.inth[idx]);
			return (ENXIO);
		}
#endif
	} else {
		/* Masked, tear it down if it's already been set up */
		ppt_teardown_msix_intr(ppt, idx);
	}

	return (0);
}

int
ppt_get_limits(struct vm *vm, int bus, int slot, int func, int *msilimit,
    int *msixlimit)
{
	struct pptdev *ppt;

	ppt = ppt_find(bus, slot, func);
	if (ppt == NULL)
		return (ENOENT);
	if (ppt->vm != vm)		/* Make sure we own this device */
		return (EBUSY);

	if (ddi_intr_get_navail(ppt->dev, DDI_INTR_TYPE_MSI, msilimit) !=
	    DDI_SUCCESS)
		*msilimit = -1;

	if (ddi_intr_get_navail(ppt->dev, DDI_INTR_TYPE_MSIX, msixlimit) !=
	    DDI_SUCCESS)
		*msixlimit = -1;

	return (0);
}
