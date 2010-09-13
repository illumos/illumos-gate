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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include "px_obj.h"
#include <sys/pci_tools.h>
#include "px_tools_ext.h"
#include "px_tools_var.h"

/*
 * PCI Space definitions.
 */
#define	PCI_CONFIG_SPACE	(PCI_REG_ADDR_G(PCI_ADDR_CONFIG))
#define	PCI_IO_SPACE		(PCI_REG_ADDR_G(PCI_ADDR_IO))
#define	PCI_MEM32_SPACE		(PCI_REG_ADDR_G(PCI_ADDR_MEM32))
#define	PCI_MEM64_SPACE		(PCI_REG_ADDR_G(PCI_ADDR_MEM64))

/*
 * Config space range for a device.  IEEE 1275 spec defines for PCI.
 * Space for PCI-express is multiplied by PX_PCI_BDF_OFFSET_DELTA
 */
#define	DEV_CFG_SPACE_SIZE	\
	(1 << (PCI_REG_FUNC_SHIFT + PX_PCI_BDF_OFFSET_DELTA))

/*
 * Offsets of BARS in config space.  First entry of 0 means config space.
 * Entries here correlate to pcitool_bars_t enumerated type.
 */
uint8_t pci_bars[] = {
	0x0,
	PCI_CONF_BASE0,
	PCI_CONF_BASE1,
	PCI_CONF_BASE2,
	PCI_CONF_BASE3,
	PCI_CONF_BASE4,
	PCI_CONF_BASE5,
	PCI_CONF_ROM
};

int	pci_num_bars = sizeof (pci_bars) / sizeof (pci_bars[0]);


/*ARGSUSED*/
static int
pxtool_intr_info(dev_info_t *dip, void *arg, int mode)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	pcitool_intr_info_t intr_info;
	int rval = SUCCESS;

	/* If we need user_version, and to ret same user version as passed in */
	if (ddi_copyin(arg, &intr_info, sizeof (pcitool_intr_info_t), mode) !=
	    DDI_SUCCESS) {
		return (EFAULT);
	}

	intr_info.ctlr_version = 0;	/* XXX how to get real version? */
	intr_info.ctlr_type = PCITOOL_CTLR_TYPE_RISC;
	if (intr_info.flags & PCITOOL_INTR_FLAG_GET_MSI)
		intr_info.num_intr = msi_state_p->msi_cnt;
	else
		intr_info.num_intr = pxtool_num_inos;

	intr_info.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&intr_info, arg, sizeof (pcitool_intr_info_t), mode) !=
	    DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}


/*
 * Get interrupt information for a given ino.
 * Returns info only for inos mapped to devices.
 *
 * Returned info is valid only when iget.num_devs is returned > 0.
 * If ino is not enabled or is not mapped to a device,
 * iget.num_devs will be returned as = 0.
 */
/*ARGSUSED*/
static int
pxtool_get_intr(dev_info_t *dip, void *arg, int mode)
{
	/* Array part isn't used here, but oh well... */
	pcitool_intr_get_t partial_iget;
	pcitool_intr_get_t *iget = &partial_iget;
	int copyout_rval;
	sysino_t sysino;
	intr_valid_state_t intr_valid_state;
	cpuid_t old_cpu_id;
	px_t *px_p = DIP_TO_STATE(dip);
	size_t	iget_kmem_alloc_size = 0;
	int rval = EIO;

	/* Read in just the header part, no array section. */
	if (ddi_copyin(arg, &partial_iget, PCITOOL_IGET_SIZE(0), mode) !=
	    DDI_SUCCESS)
		return (EFAULT);

	iget->status = PCITOOL_IO_ERROR;

	if (iget->flags & PCITOOL_INTR_FLAG_GET_MSI) {
		px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
		pci_msi_valid_state_t	msi_state;
		msiqid_t	msiq_id;

		if ((iget->msi < msi_state_p->msi_1st_msinum) ||
		    (iget->msi >= (msi_state_p->msi_1st_msinum +
		    msi_state_p->msi_cnt))) {
			iget->status = PCITOOL_INVALID_MSI;
			rval = EINVAL;
			goto done_get_intr;
		}

		if ((px_lib_msi_getvalid(dip, iget->msi,
		    &msi_state) != DDI_SUCCESS) ||
		    (msi_state != PCI_MSI_VALID))
			goto done_get_intr;

		if (px_lib_msi_getmsiq(dip, iget->msi,
		    &msiq_id) != DDI_SUCCESS)
			goto done_get_intr;

		iget->ino = px_msiqid_to_devino(px_p, msiq_id);
	} else {
		iget->msi = (uint32_t)-1;
	}

	/* Validate argument. */
	if (iget->ino > pxtool_num_inos) {
		iget->status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_get_intr;
	}

	/* Caller wants device information returned. */
	if (iget->num_devs_ret > 0) {
		/*
		 * Allocate room.
		 * Note if num_devs == 0 iget remains pointing to
		 * partial_iget.
		 */
		iget_kmem_alloc_size = PCITOOL_IGET_SIZE(iget->num_devs_ret);
		iget = kmem_zalloc(iget_kmem_alloc_size, KM_SLEEP);

		/* Read in whole structure to verify there's room. */
		if (ddi_copyin(arg, iget, iget_kmem_alloc_size, mode) !=
		    SUCCESS) {

			/* Be consistent and just return EFAULT here. */
			kmem_free(iget, iget_kmem_alloc_size);

			return (EFAULT);
		}
	}

	/* Convert leaf-wide intr to system-wide intr */
	if (px_lib_intr_devino_to_sysino(dip, iget->ino, &sysino) !=
	    DDI_SUCCESS) {
		iget->status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_get_intr;
	}

	/* Operate only on inos which are already enabled. */
	if (px_lib_intr_getvalid(dip, sysino, &intr_valid_state) !=
	    DDI_SUCCESS) {
		iget->status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_get_intr;
	}

	/*
	 * Consider all valid inos: those mapped to the root complex itself
	 * as well as those mapped to devices.
	 */
	if (intr_valid_state == INTR_VALID) {
		/*
		 * The following looks up the px_ino and returns
		 * info of devices mapped to this ino.
		 */
		iget->num_devs = pxtool_ib_get_ino_devs(px_p, iget->ino,
		    iget->msi, &iget->num_devs_ret, iget->dev);

		if (px_ib_get_intr_target(px_p, iget->ino,
		    &old_cpu_id) != DDI_SUCCESS) {
			iget->status = PCITOOL_IO_ERROR;
			rval = EIO;
			goto done_get_intr;
		}

		iget->cpu_id = old_cpu_id;
	}

	iget->status = PCITOOL_SUCCESS;
	rval = SUCCESS;

done_get_intr:
	iget->drvr_version = PCITOOL_VERSION;
	copyout_rval =
	    ddi_copyout(iget, arg, PCITOOL_IGET_SIZE(iget->num_devs_ret), mode);

	if (iget_kmem_alloc_size > 0)
		kmem_free(iget, iget_kmem_alloc_size);

	if (copyout_rval != DDI_SUCCESS)
		rval = EFAULT;

	return (rval);
}


/*
 * Associate a new CPU with a given ino.
 *
 * Operate only on inos which are already mapped to devices.
 */
static int
pxtool_set_intr(dev_info_t *dip, void *arg, int mode)
{
	pcitool_intr_set_t iset;
	cpuid_t old_cpu_id;
	sysino_t sysino;
	intr_valid_state_t intr_valid_state;
	px_t *px_p = DIP_TO_STATE(dip);
	msiqid_t msiq_id;
	int rval = EIO;
	int ret = DDI_SUCCESS;
	size_t copyinout_size;

	bzero(&iset, sizeof (pcitool_intr_set_t));

	/* Version 1 of pcitool_intr_set_t doesn't have flags. */
	copyinout_size = (size_t)&iset.flags - (size_t)&iset;

	if (ddi_copyin(arg, &iset, copyinout_size, mode) != DDI_SUCCESS)
		return (EFAULT);

	switch (iset.user_version) {
	case PCITOOL_V1:
		break;

	case PCITOOL_V2:
		copyinout_size = sizeof (pcitool_intr_set_t);
		if (ddi_copyin(arg, &iset, copyinout_size, mode) != DDI_SUCCESS)
			return (EFAULT);
		break;

	default:
		iset.status = PCITOOL_OUT_OF_RANGE;
		rval = ENOTSUP;
		goto done_set_intr;
	}

	if (iset.flags & PCITOOL_INTR_FLAG_SET_GROUP) {
		iset.status = PCITOOL_IO_ERROR;
		rval = ENOTSUP;
		goto done_set_intr;
	}

	iset.status = PCITOOL_IO_ERROR;

	if (iset.flags & PCITOOL_INTR_FLAG_SET_MSI) {
		px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
		pci_msi_valid_state_t	msi_state;

		if ((iset.msi < msi_state_p->msi_1st_msinum) ||
		    (iset.msi >= (msi_state_p->msi_1st_msinum +
		    msi_state_p->msi_cnt))) {
			iset.status = PCITOOL_INVALID_MSI;
			rval = EINVAL;
			goto done_set_intr;
		}

		if ((px_lib_msi_getvalid(dip, iset.msi,
		    &msi_state) != DDI_SUCCESS) ||
		    (msi_state != PCI_MSI_VALID))
			goto done_set_intr;

		if (px_lib_msi_getmsiq(dip, iset.msi,
		    &msiq_id) != DDI_SUCCESS)
			goto done_set_intr;

		iset.ino = px_msiqid_to_devino(px_p, msiq_id);
	} else {
		iset.msi = (uint32_t)-1;
	}

	/* Validate input argument. */
	if (iset.ino > pxtool_num_inos) {
		iset.status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_set_intr;
	}

	/* Convert leaf-wide intr to system-wide intr */
	if (px_lib_intr_devino_to_sysino(dip, iset.ino, &sysino) !=
	    DDI_SUCCESS)
		goto done_set_intr;

	/* Operate only on inos which are already enabled. */
	if ((px_lib_intr_getvalid(dip, sysino, &intr_valid_state) !=
	    DDI_SUCCESS) || (intr_valid_state == INTR_NOTVALID))
		goto done_set_intr;

	/*
	 * Consider all valid inos: those mapped to the root complex itself
	 * as well as those mapped to devices.
	 */
	if (px_lib_intr_gettarget(dip, sysino, &old_cpu_id) != DDI_SUCCESS)
		goto done_set_intr;

	if (iset.flags & PCITOOL_INTR_FLAG_SET_MSI) {
		ddi_intr_handle_impl_t	hdle;

		bzero(&hdle, sizeof (ddi_intr_handle_impl_t));
		if (pxtool_ib_get_msi_info(px_p, iset.ino, iset.msi,
		    &hdle) != DDI_SUCCESS) {
			iset.status = PCITOOL_INVALID_MSI;
			rval = EINVAL;
			goto done_set_intr;
		}

		if ((ret = px_ib_set_msix_target(px_p, &hdle, iset.msi,
		    iset.cpu_id)) == DDI_SUCCESS) {
			(void) px_lib_msi_getmsiq(dip, iset.msi, &msiq_id);
			iset.ino = px_msiqid_to_devino(px_p, msiq_id);
			iset.cpu_id = old_cpu_id;
			iset.status = PCITOOL_SUCCESS;
			rval = SUCCESS;
			goto done_set_intr;
		}
	} else {
		if ((ret = px_ib_set_intr_target(px_p, iset.ino,
		    iset.cpu_id)) == DDI_SUCCESS) {
			iset.cpu_id = old_cpu_id;
			iset.status = PCITOOL_SUCCESS;
			rval = SUCCESS;
			goto done_set_intr;
		}
	}

	switch (ret) {
	case DDI_EPENDING:
		iset.status = PCITOOL_PENDING_INTRTIMEOUT;
		rval = ETIME;
		break;
	case DDI_EINVAL:
		iset.status = PCITOOL_INVALID_CPUID;
		rval = EINVAL;
		break;
	default:
		iset.status = PCITOOL_IO_ERROR;
		rval = EIO;
		break;
	}

done_set_intr:
	iset.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&iset, arg, copyinout_size, mode) != DDI_SUCCESS)
		rval = EFAULT;

	return (rval);
}


/* Main function for handling interrupt CPU binding requests and queries. */
int
pxtool_intr(dev_info_t *dip, void *arg, int cmd, int mode)
{
	int rval = SUCCESS;

	switch (cmd) {

	/* Get system interrupt information. */
	case PCITOOL_SYSTEM_INTR_INFO:
		rval = pxtool_intr_info(dip, arg, mode);
		break;

	/* Get interrupt information for a given ino. */
	case PCITOOL_DEVICE_GET_INTR:
		rval = pxtool_get_intr(dip, arg, mode);
		break;

	/* Associate a new CPU with a given ino. */
	case PCITOOL_DEVICE_SET_INTR:
		rval = pxtool_set_intr(dip, arg, mode);
		break;

	default:
		rval = ENOTTY;
	}

	return (rval);
}


static int
pxtool_validate_barnum_bdf(pcitool_reg_t *prg)
{
	int rval = SUCCESS;

	if (prg->barnum >= (sizeof (pci_bars) / sizeof (pci_bars[0]))) {
		prg->status = PCITOOL_OUT_OF_RANGE;
		rval = EINVAL;

	/* Validate address arguments of bus / dev / func */
	} else if (((prg->bus_no &
	    (PCI_REG_BUS_M >> PCI_REG_BUS_SHIFT)) != prg->bus_no) ||
	    ((prg->dev_no &
	    (PCI_REG_DEV_M >> PCI_REG_DEV_SHIFT)) != prg->dev_no) ||
	    ((prg->func_no &
	    (PCI_REG_FUNC_M >> PCI_REG_FUNC_SHIFT)) != prg->func_no)) {
		prg->status = PCITOOL_INVALID_ADDRESS;
		rval = EINVAL;
	}

	return (rval);
}

/*
 * px_p defines which leaf, space defines which space in that leaf, offset
 * defines the offset within the specified space.
 *
 * This returns the physical address of the corresponding location.
 */
static uintptr_t
pxtool_get_phys_addr(px_t *px_p, int space, uint64_t offset)
{
	uint64_t range_base;
	int rval;
	pci_regspec_t dev_regspec;
	struct regspec xlated_regspec;
	dev_info_t *dip = px_p->px_dip;

	/*
	 * Assume that requested entity is small enough to be on the same page.
	 * PCItool checks alignment so that this will be true for single
	 * accesses.
	 */
	dev_regspec.pci_phys_hi = space << PCI_REG_ADDR_SHIFT;
	if (space == PCI_CONFIG_SPACE) {
		dev_regspec.pci_phys_hi +=
		    (offset & (PCI_REG_BDFR_M ^ PCI_REG_REG_M));
		dev_regspec.pci_phys_low = offset & PCI_REG_REG_M;
		dev_regspec.pci_phys_mid = 0;	/* Not used */
	} else {
		dev_regspec.pci_phys_mid = offset >> 32;
		dev_regspec.pci_phys_low = offset & 0xffffffff;
	}
	dev_regspec.pci_size_hi = 0;	/* Not used. */

	/* Note: object is guaranteed to be within a page. */
	dev_regspec.pci_size_low = 4;

	rval = px_xlate_reg(px_p, &dev_regspec, &xlated_regspec);

	DBG(DBG_TOOLS, dip,
	    "space:0x%d, offset:0x%" PRIx64 "\n", space, offset);

	if (rval != DDI_SUCCESS)
		return (NULL);

	/* Bustype here returns the high order address bits. */
	xlated_regspec.regspec_bustype &= px_get_rng_parent_hi_mask(px_p);

	range_base = (((uint64_t)xlated_regspec.regspec_bustype) << 32) +
	    xlated_regspec.regspec_addr;
	DBG(DBG_TOOLS, dip,
	    "regspec: hi:0x%x, lo:0x%x, sz:0x%x, range base:0x%" PRIx64 "\n",
	    xlated_regspec.regspec_bustype, xlated_regspec.regspec_addr,
	    xlated_regspec.regspec_size, range_base);

	return ((uintptr_t)range_base);
}


static int
pxtool_get_bar(px_t *px_p, pcitool_reg_t *prg_p, uint64_t *bar_p,
    uint32_t *space_p)
{
	int rval;
	uint64_t off_in_space;
	pcitool_reg_t cfg_prg = *prg_p;	/* Make local copy. */
	dev_info_t *dip = px_p->px_dip;

	*space_p = PCI_MEM32_SPACE;
	*bar_p = 0;

	/*
	 * Translate BAR number into offset of the BAR in
	 * the device's config space.
	 */
	cfg_prg.acc_attr =
	    PCITOOL_ACC_ATTR_SIZE_4 | PCITOOL_ACC_ATTR_ENDN_LTL;

	/*
	 * Note: sun4u acc function uses phys_addr which includes offset.
	 * sun4v acc function doesn't use phys_addr but uses cfg_prg.offset.
	 */
	cfg_prg.offset = PCI_BAR_OFFSET((*prg_p));
	off_in_space = PX_GET_BDF(prg_p) + cfg_prg.offset;
	cfg_prg.phys_addr = pxtool_get_phys_addr(px_p, PCI_CONFIG_SPACE,
	    off_in_space);

	DBG(DBG_TOOLS, dip,
	    "off_in_space:0x%" PRIx64 ", phys_addr:0x%" PRIx64 ", barnum:%d\n",
	    off_in_space, cfg_prg.phys_addr, cfg_prg.barnum);

	/*
	 * Get Bus Address Register (BAR) from config space.
	 * cfg_prg.offset is the offset into config space of the
	 * BAR desired.  prg_p->status is modified on error.
	 */
	rval = pxtool_pcicfg_access(px_p, &cfg_prg, bar_p, PX_ISREAD);

	if (rval != SUCCESS) {
		prg_p->status = cfg_prg.status;
		return (rval);
	}

	DBG(DBG_TOOLS, dip, "bar returned is 0x%" PRIx64 "\n", *bar_p);

	/*
	 * BAR has bits saying this space is IO space, unless
	 * this is the ROM address register.
	 */
	if (((PCI_BASE_SPACE_M & *bar_p) == PCI_BASE_SPACE_IO) &&
	    (cfg_prg.offset != PCI_CONF_ROM)) {
		*space_p = PCI_IO_SPACE;
		*bar_p &= PCI_BASE_IO_ADDR_M;

	/*
	 * BAR has bits saying this space is 64 bit memory
	 * space, unless this is the ROM address register.
	 *
	 * The 64 bit address stored in two BAR cells is not
	 * necessarily aligned on an 8-byte boundary.
	 * Need to keep the first 4 bytes read,
	 * and do a separate read of the high 4 bytes.
	 */
	} else if ((PCI_BASE_TYPE_ALL & *bar_p) &&
	    (cfg_prg.offset != PCI_CONF_ROM)) {

		uint32_t low_bytes = (uint32_t)(*bar_p & ~PCI_BASE_TYPE_ALL);

		/* Don't try to read the next 4 bytes past the end of BARs. */
		if (cfg_prg.offset >= PCI_CONF_BASE5) {
			prg_p->status = PCITOOL_OUT_OF_RANGE;
			return (EIO);
		}

		/* Access device.  prg_p->status is modified on error. */
		cfg_prg.phys_addr += sizeof (uint32_t);
		cfg_prg.offset += sizeof (uint32_t);

		rval = pxtool_pcicfg_access(px_p, &cfg_prg, bar_p, PX_ISREAD);
		if (rval != SUCCESS) {
			prg_p->status = cfg_prg.status;
			return (rval);
		}

		/*
		 * Honor the 64 bit BAR as such, only when the upper 32 bits
		 * store a non-zero value.
		 */
		if (*bar_p) {
			*space_p = PCI_MEM64_SPACE;
			*bar_p = (*bar_p << 32) | low_bytes;
		} else
			*bar_p = low_bytes;

	} else if (cfg_prg.offset == PCI_CONF_ROM) { /* ROM requested */

		/*
		 * ROM enabled. Filter ROM enable bit from the BAR.
		 * Treat as Mem32 henceforth.
		 */
		if (!(*bar_p & PCI_BASE_ROM_ENABLE))
			*bar_p ^= PCI_BASE_ROM_ENABLE;

		else {	/* ROM disabled. */
			prg_p->status = PCITOOL_ROM_DISABLED;
			return (EIO);
		}
	}

	/* Accept a bar of 0 only for IO space. */
	if ((*space_p != PCI_IO_SPACE) && (!(*bar_p))) {
		prg_p->status = PCITOOL_INVALID_ADDRESS;
		return (EINVAL);
	}

	return (SUCCESS);
}


/* Perform register accesses on PCI leaf devices. */
int
pxtool_dev_reg_ops(dev_info_t *dip, void *arg, int cmd, int mode)
{
	pcitool_reg_t	prg;
	uint64_t	bar;
	uint32_t	space;
	uint64_t	off_in_space;
	boolean_t	write_flag = B_FALSE;
	px_t		*px_p = DIP_TO_STATE(dip);
	int		rval = 0;

	if (cmd == PCITOOL_DEVICE_SET_REG)
		write_flag = B_TRUE;

	DBG(DBG_TOOLS, dip, "pxtool_dev_reg_ops set/get reg\n");
	if (ddi_copyin(arg, &prg, sizeof (pcitool_reg_t),
	    mode) != DDI_SUCCESS) {
		DBG(DBG_TOOLS, dip, "Error reading arguments\n");
		return (EFAULT);
	}

	if ((rval = pxtool_dev_reg_ops_platchk(dip, &prg)) != SUCCESS) {
		goto done_reg;
	}

	DBG(DBG_TOOLS, dip, "raw bus:0x%x, dev:0x%x, func:0x%x\n",
	    prg.bus_no, prg.dev_no, prg.func_no);
	DBG(DBG_TOOLS, dip, "barnum:0x%x, offset:0x%" PRIx64 ", acc:0x%x\n",
	    prg.barnum, prg.offset, prg.acc_attr);

	if ((rval = pxtool_validate_barnum_bdf(&prg)) != SUCCESS)
		goto done_reg;

	if (prg.barnum == 0) {	/* Proper config space desired. */

		/* Enforce offset limits. */
		if (prg.offset >= DEV_CFG_SPACE_SIZE) {
			DBG(DBG_TOOLS, dip,
			    "Config space offset 0x%" PRIx64 " out of range\n",
			    prg.offset);
			prg.status = PCITOOL_OUT_OF_RANGE;
			rval = EINVAL;
			goto done_reg;
		}

		/*
		 * For sun4v, config space base won't be known.
		 * pxtool_get_phys_addr will return zero.
		 * Note that for sun4v, phys_addr isn't
		 * used for making config space accesses.
		 *
		 * For sun4u, assume that phys_addr will come back valid.
		 */
		/*
		 * Accessed entity is assumed small enough to be on one page.
		 *
		 * Since config space is less than a page and is aligned to
		 * 0x1000, a device's entire config space will be on a single
		 * page.  Pass the device's base config space address here,
		 * then add the offset within that space later.  This works
		 * around an issue in px_xlate_reg (called by
		 * pxtool_get_phys_addr) which accepts only a 256 byte
		 * range within a device.
		 */
		off_in_space = PX_GET_BDF(&prg);
		prg.phys_addr =
		    pxtool_get_phys_addr(px_p, PCI_CONFIG_SPACE, off_in_space);
		prg.phys_addr += prg.offset;

		DBG(DBG_TOOLS, dip,
		    "off_in_space:0x%" PRIx64 ", phys_addr:0x%" PRIx64 ", "
		    "end:%s\n", off_in_space, prg.phys_addr,
		    PCITOOL_ACC_IS_BIG_ENDIAN(prg.acc_attr) ? "big":"ltl");

		/*
		 * Access device.  pr.status is modified.
		 * BDF is assumed valid at this point.
		 */
		rval = pxtool_pcicfg_access(px_p, &prg, &prg.data, write_flag);
		goto done_reg;
	}

	/* IO/ MEM/ MEM64 space. */

	if ((rval = pxtool_get_bar(px_p, &prg, &bar, &space)) != SUCCESS)
		goto done_reg;

	switch (space) {
	case PCI_MEM32_SPACE:

		DBG(DBG_TOOLS, dip, "32 bit mem space\n");

		/* Can't write to ROM */
		if ((PCI_BAR_OFFSET(prg) == PCI_CONF_ROM) && (write_flag)) {
			prg.status = PCITOOL_ROM_WRITE;
			rval = EIO;
			goto done_reg;
		}
		break;

	case PCI_IO_SPACE:
		DBG(DBG_TOOLS, dip, "IO space\n");
		break;

	case PCI_MEM64_SPACE:
		DBG(DBG_TOOLS, dip,
		    "64 bit mem space.  64-bit bar is 0x%" PRIx64 "\n", bar);
		break;

	default:
		DBG(DBG_TOOLS, dip, "Unknown space!\n");
		prg.status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_reg;
	}

	/*
	 * Common code for all IO/MEM range spaces.
	 *
	 * Use offset provided by caller to index into desired space.
	 * Note that prg.status is modified on error.
	 */
	off_in_space = bar + prg.offset;
	prg.phys_addr = pxtool_get_phys_addr(px_p, space, off_in_space);

	DBG(DBG_TOOLS, dip,
	    "addr in bar:0x%" PRIx64 ", offset:0x%" PRIx64 ", "
	    "phys_addr:0x%" PRIx64 "\n", bar, prg.offset, prg.phys_addr);

	rval = pxtool_pciiomem_access(px_p, &prg, &prg.data, write_flag);

done_reg:
	prg.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&prg, arg, sizeof (pcitool_reg_t),
	    mode) != DDI_SUCCESS) {
		DBG(DBG_TOOLS, dip, "Error returning arguments.\n");
		rval = EFAULT;
	}
	return (rval);
}


int
pxtool_init(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);

	if (ddi_create_minor_node(dip, PCI_MINOR_REG, S_IFCHR,
	    PCI_MINOR_NUM(instance, PCI_TOOL_REG_MINOR_NUM),
	    DDI_NT_REGACC, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, PCI_MINOR_INTR, S_IFCHR,
	    PCI_MINOR_NUM(instance, PCI_TOOL_INTR_MINOR_NUM),
	    DDI_NT_INTRCTL, 0) != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, PCI_MINOR_REG);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


void
pxtool_uninit(dev_info_t *dip)
{
	ddi_remove_minor_node(dip, PCI_MINOR_REG);
	ddi_remove_minor_node(dip, PCI_MINOR_INTR);
}
