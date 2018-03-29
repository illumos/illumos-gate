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

/*
 * Copyright 2018 Joyent, Inc
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
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/ppt_dev.h>
#include <sys/mkdev.h>

#include "vmm_lapic.h"
#include "vmm_ktr.h"

#include "iommu.h"
#include "ppt.h"

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

struct pptintr_arg {
	struct pptdev	*pptdev;
	uint64_t	addr;
	uint64_t	msg_data;
};

struct pptseg {
	vm_paddr_t	gpa;
	size_t		len;
	int		wired;
};

struct pptbar {
	uint64_t base;
	uint64_t size;
	uint_t type;
	ddi_acc_handle_t io_handle;
	caddr_t io_ptr;
};

struct pptdev {
	dev_info_t		*pptd_dip;
	list_node_t		pptd_node;
	ddi_acc_handle_t	pptd_cfg;
	struct pptbar		pptd_bars[PCI_BASE_NUM];
	struct vm		*vm;
	struct pptseg mmio[MAX_MMIOSEGS];
	struct {
		int	num_msgs;		/* guest state */
		boolean_t is_fixed;
		size_t	inth_sz;
		ddi_intr_handle_t *inth;
		struct pptintr_arg arg[MAX_MSIMSGS];
	} msi;

	struct {
		int num_msgs;
		size_t inth_sz;
		size_t arg_sz;
		ddi_intr_handle_t *inth;
		struct pptintr_arg *arg;
	} msix;
};


static major_t		ppt_major;
static void		*ppt_state;
static kmutex_t		pptdev_mtx;
static list_t		pptdev_list;

#define	PPT_MINOR_NAME	"ppt"

static ddi_device_acc_attr_t ppt_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC
};

static int
ppt_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	/* XXX: require extra privs? */
	return (0);
}

#define	BAR_TO_IDX(bar)	(((bar) - PCI_CONF_BASE0) / PCI_BAR_SZ_32)
#define	BAR_VALID(b)	(			\
		(b) >= PCI_CONF_BASE0 &&	\
		(b) <= PCI_CONF_BASE5 &&	\
		((b) & (PCI_BAR_SZ_32-1)) == 0)

static int
ppt_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	minor_t minor = getminor(dev);
	struct pptdev *ppt;
	void *data = (void *)arg;

	if ((ppt = ddi_get_soft_state(ppt_state, minor)) == NULL) {
		return (ENOENT);
	}

	switch (cmd) {
	case PPT_CFG_READ: {
		struct ppt_cfg_io cio;
		ddi_acc_handle_t cfg = ppt->pptd_cfg;

		if (ddi_copyin(data, &cio, sizeof (cio), md) != 0) {
			return (EFAULT);
		}
		switch (cio.pci_width) {
		case 4:
			cio.pci_data = pci_config_get32(cfg, cio.pci_off);
			break;
		case 2:
			cio.pci_data = pci_config_get16(cfg, cio.pci_off);
			break;
		case 1:
			cio.pci_data = pci_config_get8(cfg, cio.pci_off);
			break;
		default:
			return (EINVAL);
		}

		if (ddi_copyout(&cio, data, sizeof (cio), md) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	case PPT_CFG_WRITE: {
		struct ppt_cfg_io cio;
		ddi_acc_handle_t cfg = ppt->pptd_cfg;

		if (ddi_copyin(data, &cio, sizeof (cio), md) != 0) {
			return (EFAULT);
		}
		switch (cio.pci_width) {
		case 4:
			pci_config_put32(cfg, cio.pci_off, cio.pci_data);
			break;
		case 2:
			pci_config_put16(cfg, cio.pci_off, cio.pci_data);
			break;
		case 1:
			pci_config_put8(cfg, cio.pci_off, cio.pci_data);
			break;
		default:
			return (EINVAL);
		}

		return (0);
	}
	case PPT_BAR_QUERY: {
		struct ppt_bar_query barg;
		struct pptbar *pbar;

		if (ddi_copyin(data, &barg, sizeof (barg), md) != 0) {
			return (EFAULT);
		}
		if (barg.pbq_baridx >= PCI_BASE_NUM) {
			return (EINVAL);
		}
		pbar = &ppt->pptd_bars[barg.pbq_baridx];

		if (pbar->base == 0 || pbar->size == 0) {
			return (ENOENT);
		}
		barg.pbq_type = pbar->type;
		barg.pbq_base = pbar->base;
		barg.pbq_size = pbar->size;

		if (ddi_copyout(&barg, data, sizeof (barg), md) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	case PPT_BAR_READ: {
		struct ppt_bar_io bio;
		struct pptbar *pbar;
		void *addr;
		uint_t rnum;
		ddi_acc_handle_t cfg;

		if (ddi_copyin(data, &bio, sizeof (bio), md) != 0) {
			return (EFAULT);
		}
		rnum = bio.pbi_bar;
		if (rnum >= PCI_BASE_NUM) {
			return (EINVAL);
		}
		pbar = &ppt->pptd_bars[rnum];
		if (pbar->type != PCI_ADDR_IO || pbar->io_handle == NULL) {
			return (EINVAL);
		}
		addr = pbar->io_ptr + bio.pbi_off;

		switch (bio.pbi_width) {
		case 4:
			bio.pbi_data = ddi_get32(pbar->io_handle, addr);
			break;
		case 2:
			bio.pbi_data = ddi_get16(pbar->io_handle, addr);
			break;
		case 1:
			bio.pbi_data = ddi_get8(pbar->io_handle, addr);
			break;
		default:
			return (EINVAL);
		}

		if (ddi_copyout(&bio, data, sizeof (bio), md) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	case PPT_BAR_WRITE: {
		struct ppt_bar_io bio;
		struct pptbar *pbar;
		void *addr;
		uint_t rnum;
		ddi_acc_handle_t cfg;

		if (ddi_copyin(data, &bio, sizeof (bio), md) != 0) {
			return (EFAULT);
		}
		rnum = bio.pbi_bar;
		if (rnum >= PCI_BASE_NUM) {
			return (EINVAL);
		}
		pbar = &ppt->pptd_bars[rnum];
		if (pbar->type != PCI_ADDR_IO || pbar->io_handle == NULL) {
			return (EINVAL);
		}
		addr = pbar->io_ptr + bio.pbi_off;

		switch (bio.pbi_width) {
		case 4:
			ddi_put32(pbar->io_handle, addr, bio.pbi_data);
			break;
		case 2:
			ddi_put16(pbar->io_handle, addr, bio.pbi_data);
			break;
		case 1:
			ddi_put8(pbar->io_handle, addr, bio.pbi_data);
			break;
		default:
			return (EINVAL);
		}

		return (0);
	}

	default:
		return (ENOTTY);
	}

	return (0);
}


static void
ppt_bar_wipe(struct pptdev *ppt)
{
	uint_t i;

	for (i = 0; i < PCI_BASE_NUM; i++) {
		struct pptbar *pbar = &ppt->pptd_bars[i];
		if (pbar->type == PCI_ADDR_IO && pbar->io_handle != NULL) {
			ddi_regs_map_free(&pbar->io_handle);
		}
	}
	bzero(&ppt->pptd_bars, sizeof (ppt->pptd_bars));
}

static int
ppt_bar_crawl(struct pptdev *ppt)
{
	pci_regspec_t *regs;
	uint_t rcount, i;
	int err = 0, rlen;

	if (ddi_getlongprop(DDI_DEV_T_ANY, ppt->pptd_dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&regs, &rlen) != DDI_PROP_SUCCESS) {
		return (EIO);
	}

	VERIFY3S(rlen, >, 0);
	rcount = (rlen * sizeof (int)) / sizeof (pci_regspec_t);
	for (i = 0; i < rcount; i++) {
		pci_regspec_t *reg = &regs[i];
		struct pptbar *pbar;
		uint_t bar, rnum;

		DTRACE_PROBE1(ppt__crawl__reg, pci_regspec_t *, reg);
		bar = PCI_REG_REG_G(reg->pci_phys_hi);
		if (!BAR_VALID(bar)) {
			continue;
		}

		rnum = BAR_TO_IDX(bar);
		pbar = &ppt->pptd_bars[rnum];
		/* is this somehow already populated? */
		if (pbar->base != 0 || pbar->size != 0) {
			err = EEXIST;
			break;
		}

		pbar->type = reg->pci_phys_hi & PCI_ADDR_MASK;
		pbar->base = ((uint64_t)reg->pci_phys_mid << 32) |
		    (uint64_t)reg->pci_phys_low;
		pbar->size = ((uint64_t)reg->pci_size_hi << 32) |
		    (uint64_t)reg->pci_size_low;
		if (pbar->type == PCI_ADDR_IO) {
			err = ddi_regs_map_setup(ppt->pptd_dip, rnum,
			    &pbar->io_ptr, 0, 0, &ppt_attr, &pbar->io_handle);
			if (err != 0) {
				break;
			}
		}
	}
	kmem_free(regs, rlen);

	if (err != 0) {
		ppt_bar_wipe(ppt);
	}
	return (err);
}

static boolean_t
ppt_bar_verify_mmio(struct pptdev *ppt, uint64_t base, uint64_t size)
{
	const uint64_t map_end = base + size;

	/* Zero-length or overflow mappings are not valid */
	if (map_end <= base) {
		return (B_FALSE);
	}
	/* MMIO bounds should be page-aligned */
	if ((base & PAGEOFFSET) != 0 || (size & PAGEOFFSET) != 0) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < PCI_BASE_NUM; i++) {
		const struct pptbar *bar = &ppt->pptd_bars[i];
		const uint64_t bar_end = bar->base + bar->size;

		/* Only memory BARs can be mapped */
		if (bar->type != PCI_ADDR_MEM32 &&
		    bar->type != PCI_ADDR_MEM64) {
			continue;
		}

		/* Does the mapping fit within this BAR? */
		if (base < bar->base || base >= bar_end ||
		    map_end < bar->base || map_end > bar_end) {
			continue;
		}

		/* This BAR satisfies the provided map */
		return (B_TRUE);
	}
	return (B_FALSE);
}

static int
ppt_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct pptdev *ppt = NULL;
	char name[PPT_MAXNAMELEN];
	int inst;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	inst = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ppt_state, inst) != DDI_SUCCESS) {
		goto fail;
	}
	VERIFY(ppt = ddi_get_soft_state(ppt_state, inst));
	ppt->pptd_dip = dip;
	ddi_set_driver_private(dip, ppt);

	if (pci_config_setup(dip, &ppt->pptd_cfg) != DDI_SUCCESS) {
		goto fail;
	}
	if (ppt_bar_crawl(ppt) != 0) {
		goto fail;
	}

	if (ddi_create_minor_node(dip, PPT_MINOR_NAME, S_IFCHR, inst,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto fail;
	}

	mutex_enter(&pptdev_mtx);
	list_insert_tail(&pptdev_list, ppt);
	mutex_exit(&pptdev_mtx);

	return (DDI_SUCCESS);

fail:
	if (ppt != NULL) {
		ddi_remove_minor_node(dip, NULL);
		if (ppt->pptd_cfg != NULL) {
			pci_config_teardown(&ppt->pptd_cfg);
		}
		ppt_bar_wipe(ppt);
		ddi_soft_state_free(ppt_state, inst);
	}
	return (DDI_FAILURE);
}

static int
ppt_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct pptdev *ppt;
	int inst;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ppt = ddi_get_driver_private(dip);
	inst = ddi_get_instance(dip);

	ASSERT3P(ddi_get_soft_state(ppt_state, inst), ==, ppt);

	mutex_enter(&pptdev_mtx);
	if (ppt->vm != NULL) {
		mutex_exit(&pptdev_mtx);
		return (DDI_FAILURE);
	}
	list_remove(&pptdev_list, ppt);
	mutex_exit(&pptdev_mtx);

	ddi_remove_minor_node(dip, PPT_MINOR_NAME);
	ppt_bar_wipe(ppt);
	pci_config_teardown(&ppt->pptd_cfg);
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(ppt_state, inst);

	return (DDI_SUCCESS);
}

static int
ppt_ddi_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_FAILURE;
	int inst = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO: {
		struct pptdev *ppt = ddi_get_soft_state(ppt_state, inst);

		if (ppt != NULL) {
			*result = (void *)ppt->pptd_dip;
			error = DDI_SUCCESS;
		}
		break;
	}
	case DDI_INFO_DEVT2INSTANCE: {
		*result = (void *)(uintptr_t)inst;
		error = DDI_SUCCESS;
		break;
	}
	default:
		break;
	}
	return (error);
}

static struct cb_ops ppt_cb_ops = {
	ppt_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	ppt_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops ppt_ops = {
	DEVO_REV,
	0,
	ppt_ddi_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	ppt_ddi_attach,
	ppt_ddi_detach,
	nodev,		/* reset */
	&ppt_cb_ops,
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
	int error;

	mutex_init(&pptdev_mtx, NULL, MUTEX_DRIVER, NULL);
	list_create(&pptdev_list, sizeof (struct pptdev),
	    offsetof(struct pptdev, pptd_node));

	error = ddi_soft_state_init(&ppt_state, sizeof (struct pptdev), 0);
	if (error) {
		goto fail;
	}

	error = mod_install(&modlinkage);

	ppt_major = ddi_name_to_major("ppt");
fail:
	if (error) {
		ddi_soft_state_fini(&ppt_state);
	}
	return (error);
}

int
_fini(void)
{
	int error;

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

static boolean_t
ppt_wait_for_pending_txn(dev_info_t *dip, uint_t max_delay_us)
{
	uint16_t cap_ptr, devsts;
	ddi_acc_handle_t hdl;

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS)
		return (B_FALSE);

	if (PCI_CAP_LOCATE(hdl, PCI_CAP_ID_PCI_E, &cap_ptr) != DDI_SUCCESS) {
		pci_config_teardown(&hdl);
		return (B_FALSE);
	}

	devsts = PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVSTS);
	while ((devsts & PCIE_DEVSTS_TRANS_PENDING) != 0) {
		if (max_delay_us == 0) {
			pci_config_teardown(&hdl);
			return (B_FALSE);
		}

		/* Poll once every 100 milliseconds up to the timeout. */
		if (max_delay_us > 100000) {
			delay(drv_usectohz(100000));
			max_delay_us -= 100000;
		} else {
			delay(drv_usectohz(max_delay_us));
			max_delay_us = 0;
		}
		devsts = PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVSTS);
	}

	pci_config_teardown(&hdl);
	return (B_TRUE);
}

static uint_t
ppt_max_completion_tmo_us(dev_info_t *dip)
{
	uint_t timo = 0;
	uint16_t cap_ptr;
	ddi_acc_handle_t hdl;
	uint_t timo_ranges[] = {	/* timeout ranges */
		50000,		/* 50ms */
		100,		/* 100us */
		10000,		/* 10ms */
		0,
		0,
		55000,		/* 55ms */
		210000,		/* 210ms */
		0,
		0,
		900000,		/* 900ms */
		3500000,	/* 3.5s */
		0,
		0,
		13000000,	/* 13s */
		64000000,	/* 64s */
		0
	};

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS)
		return (50000); /* default 50ms */

	if (PCI_CAP_LOCATE(hdl, PCI_CAP_ID_PCI_E, &cap_ptr) != DDI_SUCCESS)
		goto out;

	if ((PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_PCIECAP) &
	    PCIE_PCIECAP_VER_MASK) < PCIE_PCIECAP_VER_2_0)
		goto out;

	if ((PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCAP2) &
	    PCIE_DEVCTL2_COM_TO_RANGE_MASK) == 0)
		goto out;

	timo = timo_ranges[PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCTL2) &
	    PCIE_DEVCAP2_COM_TO_RANGE_MASK];

out:
	if (timo == 0)
		timo = 50000; /* default 50ms */

	pci_config_teardown(&hdl);
	return (timo);
}

static boolean_t
ppt_flr(dev_info_t *dip, boolean_t force)
{
	uint16_t cap_ptr, ctl, cmd;
	ddi_acc_handle_t hdl;
	uint_t compl_delay = 0, max_delay_us;

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS)
		return (B_FALSE);

	if (PCI_CAP_LOCATE(hdl, PCI_CAP_ID_PCI_E, &cap_ptr) != DDI_SUCCESS)
		goto fail;

	if ((PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCAP) & PCIE_DEVCAP_FLR)
	    == 0)
		goto fail;

	max_delay_us = MAX(ppt_max_completion_tmo_us(dip), 10000);

	/*
	 * Disable busmastering to prevent generation of new transactions while
	 * waiting for the device to go idle.  If the idle timeout fails, the
	 * command register is restored which will re-enable busmastering.
	 */
	cmd = pci_config_get16(hdl, PCI_CONF_COMM);
	pci_config_put16(hdl, PCI_CONF_COMM, cmd & ~PCI_COMM_ME);
	if (!ppt_wait_for_pending_txn(dip, max_delay_us)) {
		if (!force) {
			pci_config_put16(hdl, PCI_CONF_COMM, cmd);
			goto fail;
		}
		dev_err(dip, CE_WARN,
		    "?Resetting with transactions pending after %u us\n",
		    max_delay_us);

		/*
		 * Extend the post-FLR delay to cover the maximum Completion
		 * Timeout delay of anything in flight during the FLR delay.
		 * Enforce a minimum delay of at least 10ms.
		 */
		compl_delay = MAX(10, (ppt_max_completion_tmo_us(dip) / 1000));
	}

	/* Initiate the reset. */
	ctl = PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCTL);
	(void) PCI_CAP_PUT16(hdl, NULL, cap_ptr, PCIE_DEVCTL,
	    ctl | PCIE_DEVCTL_INITIATE_FLR);

	/* Wait for at least 100ms */
	delay(drv_usectohz((100 + compl_delay) * 1000));

	pci_config_teardown(&hdl);
	return (B_TRUE);

fail:
	pci_config_teardown(&hdl);
	return (B_FALSE);
}


static struct pptdev *
ppt_findf(int fd)
{
	struct pptdev *ppt = NULL;
	file_t *fp;
	vattr_t va;

	if ((fp = getf(fd)) == NULL) {
		return (NULL);
	}

	va.va_mask = AT_RDEV;
	if (VOP_GETATTR(fp->f_vnode, &va, NO_FOLLOW, fp->f_cred, NULL) != 0 ||
	    getmajor(va.va_rdev) != ppt_major)
		goto fail;

	ppt = ddi_get_soft_state(ppt_state, getminor(va.va_rdev));

	if (ppt != NULL)
		return (ppt);

fail:
	releasef(fd);
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
		(void) vm_unmap_mmio(vm, seg->gpa, seg->len);
		bzero(seg, sizeof (struct pptseg));
	}
}

static void
ppt_teardown_msi(struct pptdev *ppt)
{
	int i;

	if (ppt->msi.num_msgs == 0)
		return;

	for (i = 0; i < ppt->msi.num_msgs; i++) {
		int intr_cap;

		(void) ddi_intr_get_cap(ppt->msi.inth[i], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			ddi_intr_block_disable(&ppt->msi.inth[i], 1);
		else
			ddi_intr_disable(ppt->msi.inth[i]);

		ddi_intr_remove_handler(ppt->msi.inth[i]);
		ddi_intr_free(ppt->msi.inth[i]);

		ppt->msi.inth[i] = NULL;
	}

	kmem_free(ppt->msi.inth, ppt->msi.inth_sz);
	ppt->msi.inth = NULL;
	ppt->msi.inth_sz = 0;
	ppt->msi.is_fixed = B_FALSE;

	ppt->msi.num_msgs = 0;
}

static void
ppt_teardown_msix_intr(struct pptdev *ppt, int idx)
{
	if (ppt->msix.inth != NULL && ppt->msix.inth[idx] != NULL) {
		int intr_cap;

		(void) ddi_intr_get_cap(ppt->msix.inth[idx], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			ddi_intr_block_disable(&ppt->msix.inth[idx], 1);
		else
			ddi_intr_disable(ppt->msix.inth[idx]);

		ddi_intr_remove_handler(ppt->msix.inth[idx]);
	}
}

static void
ppt_teardown_msix(struct pptdev *ppt)
{
	uint_t i;

	if (ppt->msix.num_msgs == 0)
		return;

	for (i = 0; i < ppt->msix.num_msgs; i++)
		ppt_teardown_msix_intr(ppt, i);

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

	ppt->msix.num_msgs = 0;
}

int
ppt_assigned_devices(struct vm *vm)
{
	struct pptdev *ppt;
	uint_t num = 0;

	mutex_enter(&pptdev_mtx);
	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->vm == vm) {
			num++;
		}
	}
	mutex_exit(&pptdev_mtx);
	return (num);
}

boolean_t
ppt_is_mmio(struct vm *vm, vm_paddr_t gpa)
{
	struct pptdev *ppt = list_head(&pptdev_list);

	/* XXX: this should probably be restructured to avoid the lock */
	mutex_enter(&pptdev_mtx);
	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->vm != vm) {
			continue;
		}

		for (uint_t i = 0; i < MAX_MMIOSEGS; i++) {
			struct pptseg *seg = &ppt->mmio[i];

			if (seg->len == 0)
				continue;
			if (gpa >= seg->gpa && gpa < seg->gpa + seg->len) {
				mutex_exit(&pptdev_mtx);
				return (B_TRUE);
			}
		}
	}

	mutex_exit(&pptdev_mtx);
	return (B_FALSE);
}

int
ppt_assign_device(struct vm *vm, int pptfd)
{
	struct pptdev *ppt;
	int err = 0;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_findf(pptfd);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (EBADF);
	}

	/* Only one VM may own a device at any given time */
	if (ppt->vm != NULL && ppt->vm != vm) {
		err = EBUSY;
		goto done;
	}

	if (pci_save_config_regs(ppt->pptd_dip) != DDI_SUCCESS) {
		err = EIO;
		goto done;
	}
	ppt_flr(ppt->pptd_dip, B_TRUE);

	/*
	 * Restore the device state after reset and then perform another save
	 * so the "pristine" state can be restored when the device is removed
	 * from the guest.
	 */
	if (pci_restore_config_regs(ppt->pptd_dip) != DDI_SUCCESS ||
	    pci_save_config_regs(ppt->pptd_dip) != DDI_SUCCESS) {
		err = EIO;
		goto done;
	}

	ppt->vm = vm;
	iommu_remove_device(iommu_host_domain(), pci_get_bdf(ppt->pptd_dip));
	iommu_add_device(vm_iommu_domain(vm), pci_get_bdf(ppt->pptd_dip));

done:
	releasef(pptfd);
	mutex_exit(&pptdev_mtx);
	return (err);
}

static void
ppt_reset_pci_power_state(dev_info_t *dip)
{
	ddi_acc_handle_t cfg;
	uint16_t cap_ptr;

	if (pci_config_setup(dip, &cfg) != DDI_SUCCESS)
		return;

	if (PCI_CAP_LOCATE(cfg, PCI_CAP_ID_PM, &cap_ptr) == DDI_SUCCESS) {
		uint16_t val;

		val = PCI_CAP_GET16(cfg, NULL, cap_ptr, PCI_PMCSR);
		if ((val & PCI_PMCSR_STATE_MASK) != PCI_PMCSR_D0) {
			val = (val & ~PCI_PMCSR_STATE_MASK) | PCI_PMCSR_D0;
			(void) PCI_CAP_PUT16(cfg, NULL, cap_ptr, PCI_PMCSR,
			    val);
		}
	}

	pci_config_teardown(&cfg);
}

static void
ppt_do_unassign(struct pptdev *ppt)
{
	struct vm *vm = ppt->vm;

	ASSERT3P(vm, !=, NULL);
	ASSERT(MUTEX_HELD(&pptdev_mtx));


	ppt_flr(ppt->pptd_dip, B_TRUE);

	/*
	 * Restore from the state saved during device assignment.
	 * If the device power state has been altered, that must be remedied
	 * first, as it will reset register state during the transition.
	 */
	ppt_reset_pci_power_state(ppt->pptd_dip);
	(void) pci_restore_config_regs(ppt->pptd_dip);

	ppt_unmap_mmio(vm, ppt);
	ppt_teardown_msi(ppt);
	ppt_teardown_msix(ppt);
	iommu_remove_device(vm_iommu_domain(vm), pci_get_bdf(ppt->pptd_dip));
	iommu_add_device(iommu_host_domain(), pci_get_bdf(ppt->pptd_dip));
	ppt->vm = NULL;
}

int
ppt_unassign_device(struct vm *vm, int pptfd)
{
	struct pptdev *ppt;
	int err = 0;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_findf(pptfd);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (EBADF);
	}

	/* If this device is not owned by this 'vm' then bail out. */
	if (ppt->vm != vm) {
		err = EBUSY;
		goto done;
	}
	ppt_do_unassign(ppt);

done:
	releasef(pptfd);
	mutex_exit(&pptdev_mtx);
	return (err);
}

int
ppt_unassign_all(struct vm *vm)
{
	struct pptdev *ppt;

	mutex_enter(&pptdev_mtx);
	for (ppt = list_head(&pptdev_list); ppt != NULL;
	    ppt = list_next(&pptdev_list, ppt)) {
		if (ppt->vm == vm) {
			ppt_do_unassign(ppt);
		}
	}
	mutex_exit(&pptdev_mtx);

	return (0);
}

int
ppt_map_mmio(struct vm *vm, int pptfd, vm_paddr_t gpa, size_t len,
    vm_paddr_t hpa)
{
	struct pptdev *ppt;
	int err = 0;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_findf(pptfd);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (EBADF);
	}
	if (ppt->vm != vm) {
		err = EBUSY;
		goto done;
	}

	/*
	 * Ensure that the host-physical range of the requested mapping fits
	 * within one of the MMIO BARs of the device.
	 */
	if (!ppt_bar_verify_mmio(ppt, hpa, len)) {
		err = EINVAL;
		goto done;
	}

	for (uint_t i = 0; i < MAX_MMIOSEGS; i++) {
		struct pptseg *seg = &ppt->mmio[i];

		if (seg->len == 0) {
			err = vm_map_mmio(vm, gpa, len, hpa);
			if (err == 0) {
				seg->gpa = gpa;
				seg->len = len;
			}
			goto done;
		}
	}
	err = ENOSPC;

done:
	releasef(pptfd);
	mutex_exit(&pptdev_mtx);
	return (err);
}

static uint_t
pptintr(caddr_t arg, caddr_t unused)
{
	struct pptintr_arg *pptarg = (struct pptintr_arg *)arg;
	struct pptdev *ppt = pptarg->pptdev;

	if (ppt->vm != NULL) {
		lapic_intr_msi(ppt->vm, pptarg->addr, pptarg->msg_data);
	} else {
		/*
		 * XXX
		 * This is not expected to happen - panic?
		 */
	}

	/*
	 * For legacy interrupts give other filters a chance in case
	 * the interrupt was not generated by the passthrough device.
	 */
	return (ppt->msi.is_fixed ? DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
}

int
ppt_setup_msi(struct vm *vm, int vcpu, int pptfd, uint64_t addr, uint64_t msg,
    int numvec)
{
	int i, msi_count, intr_type;
	struct pptdev *ppt;
	int err = 0;

	if (numvec < 0 || numvec > MAX_MSIMSGS)
		return (EINVAL);

	mutex_enter(&pptdev_mtx);
	ppt = ppt_findf(pptfd);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (EBADF);
	}
	if (ppt->vm != vm) {
		/* Make sure we own this device */
		err = EBUSY;
		goto done;
	}

	/* Free any allocated resources */
	ppt_teardown_msi(ppt);

	if (numvec == 0) {
		/* nothing more to do */
		goto done;
	}

	if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_MSI,
	    &msi_count) != DDI_SUCCESS) {
		if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_FIXED,
		    &msi_count) != DDI_SUCCESS) {
			err = EINVAL;
			goto done;
		}

		intr_type = DDI_INTR_TYPE_FIXED;
		ppt->msi.is_fixed = B_TRUE;
	} else {
		intr_type = DDI_INTR_TYPE_MSI;
	}

	/*
	 * The device must be capable of supporting the number of vectors
	 * the guest wants to allocate.
	 */
	if (numvec > msi_count) {
		err = EINVAL;
		goto done;
	}

	ppt->msi.inth_sz = numvec * sizeof (ddi_intr_handle_t);
	ppt->msi.inth = kmem_zalloc(ppt->msi.inth_sz, KM_SLEEP);
	if (ddi_intr_alloc(ppt->pptd_dip, ppt->msi.inth, intr_type, 0,
	    numvec, &msi_count, 0) != DDI_SUCCESS) {
		kmem_free(ppt->msi.inth, ppt->msi.inth_sz);
		err = EINVAL;
		goto done;
	}

	/* Verify that we got as many vectors as the guest requested */
	if (numvec != msi_count) {
		ppt_teardown_msi(ppt);
		err = EINVAL;
		goto done;
	}

	/* Set up & enable interrupt handler for each vector. */
	for (i = 0; i < numvec; i++) {
		int res, intr_cap = 0;

		ppt->msi.num_msgs = i + 1;
		ppt->msi.arg[i].pptdev = ppt;
		ppt->msi.arg[i].addr = addr;
		ppt->msi.arg[i].msg_data = msg + i;

		if (ddi_intr_add_handler(ppt->msi.inth[i], pptintr,
		    &ppt->msi.arg[i], NULL) != DDI_SUCCESS)
			break;

		(void) ddi_intr_get_cap(ppt->msi.inth[i], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			res = ddi_intr_block_enable(&ppt->msi.inth[i], 1);
		else
			res = ddi_intr_enable(ppt->msi.inth[i]);

		if (res != DDI_SUCCESS)
			break;
	}
	if (i < numvec) {
		ppt_teardown_msi(ppt);
		err = ENXIO;
	}

done:
	releasef(pptfd);
	mutex_exit(&pptdev_mtx);
	return (err);
}

int
ppt_setup_msix(struct vm *vm, int vcpu, int pptfd, int idx, uint64_t addr,
    uint64_t msg, uint32_t vector_control)
{
	struct pptdev *ppt;
	int numvec, alloced;
	int err = 0;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_findf(pptfd);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (EBADF);
	}
	/* Make sure we own this device */
	if (ppt->vm != vm) {
		err = EBUSY;
		goto done;
	}

	/*
	 * First-time configuration:
	 * 	Allocate the MSI-X table
	 *	Allocate the IRQ resources
	 *	Set up some variables in ppt->msix
	 */
	if (ppt->msix.num_msgs == 0) {
		dev_info_t *dip = ppt->pptd_dip;

		if (ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSIX,
		    &numvec) != DDI_SUCCESS) {
			err = EINVAL;
			goto done;
		}

		ppt->msix.num_msgs = numvec;

		ppt->msix.arg_sz = numvec * sizeof (ppt->msix.arg[0]);
		ppt->msix.arg = kmem_zalloc(ppt->msix.arg_sz, KM_SLEEP);
		ppt->msix.inth_sz = numvec * sizeof (ddi_intr_handle_t);
		ppt->msix.inth = kmem_zalloc(ppt->msix.inth_sz, KM_SLEEP);

		if (ddi_intr_alloc(dip, ppt->msix.inth, DDI_INTR_TYPE_MSIX, 0,
		    numvec, &alloced, 0) != DDI_SUCCESS) {
			kmem_free(ppt->msix.arg, ppt->msix.arg_sz);
			kmem_free(ppt->msix.inth, ppt->msix.inth_sz);
			ppt->msix.arg = NULL;
			ppt->msix.inth = NULL;
			ppt->msix.arg_sz = ppt->msix.inth_sz = 0;
			err = EINVAL;
			goto done;
		}

		if (numvec != alloced) {
			ppt_teardown_msix(ppt);
			err = EINVAL;
			goto done;
		}
	}

	if (idx >= ppt->msix.num_msgs) {
		err = EINVAL;
		goto done;
	}

	if ((vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
		int intr_cap, res;

		/* Tear down the IRQ if it's already set up */
		ppt_teardown_msix_intr(ppt, idx);

		ppt->msix.arg[idx].pptdev = ppt;
		ppt->msix.arg[idx].addr = addr;
		ppt->msix.arg[idx].msg_data = msg;

		/* Setup the MSI-X interrupt */
		if (ddi_intr_add_handler(ppt->msix.inth[idx], pptintr,
		    &ppt->msix.arg[idx], NULL) != DDI_SUCCESS) {
			err = ENXIO;
			goto done;
		}

		(void) ddi_intr_get_cap(ppt->msix.inth[idx], &intr_cap);
		if (intr_cap & DDI_INTR_FLAG_BLOCK)
			res = ddi_intr_block_enable(&ppt->msix.inth[idx], 1);
		else
			res = ddi_intr_enable(ppt->msix.inth[idx]);

		if (res != DDI_SUCCESS) {
			ddi_intr_remove_handler(ppt->msix.inth[idx]);
			err = ENXIO;
			goto done;
		}
	} else {
		/* Masked, tear it down if it's already been set up */
		ppt_teardown_msix_intr(ppt, idx);
	}

done:
	releasef(pptfd);
	mutex_exit(&pptdev_mtx);
	return (err);
}

int
ppt_get_limits(struct vm *vm, int pptfd, int *msilimit, int *msixlimit)
{
	struct pptdev *ppt;
	int err = 0;

	mutex_enter(&pptdev_mtx);
	ppt = ppt_findf(pptfd);
	if (ppt == NULL) {
		mutex_exit(&pptdev_mtx);
		return (EBADF);
	}
	if (ppt->vm != vm) {
		err = EBUSY;
		goto done;
	}

	if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_MSI,
	    msilimit) != DDI_SUCCESS) {
		*msilimit = -1;
	}
	if (ddi_intr_get_navail(ppt->pptd_dip, DDI_INTR_TYPE_MSIX,
	    msixlimit) != DDI_SUCCESS) {
		*msixlimit = -1;
	}

done:
	releasef(pptfd);
	mutex_exit(&pptdev_mtx);
	return (err);
}
