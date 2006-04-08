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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/hotplug/pci/pcihp.h>
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

/*
 * Validate the cpu_id passed in.
 * A value of 1 will be returned for success and zero for failure.
 */
static int
pxtool_validate_cpuid(uint32_t cpuid)
{
	extern const int _ncpu;
	extern cpu_t	*cpu[];

	ASSERT(mutex_owned(&cpu_lock));

	return ((cpuid < _ncpu) && (cpu[cpuid] && cpu_is_online(cpu[cpuid])));
}


static int
pxtool_intr_get_max_ino(uint32_t *arg, int mode)
{
	if (ddi_copyout(&pxtool_num_inos, arg, sizeof (uint32_t), mode) !=
	    DDI_SUCCESS)
		return (EFAULT);
	else
		return (SUCCESS);
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
	uint32_t ino;
	uint8_t num_devs_ret;
	int copyout_rval;
	sysino_t sysino;
	intr_valid_state_t intr_valid_state;
	cpuid_t old_cpu_id;
	px_t *px_p = DIP_TO_STATE(dip);
	pcitool_intr_get_t *iget = &partial_iget;
	size_t	iget_kmem_alloc_size = 0;
	int rval = SUCCESS;

	/* Read in just the header part, no array section. */
	if (ddi_copyin(arg, &partial_iget, PCITOOL_IGET_SIZE(0), mode) !=
	    DDI_SUCCESS)
		return (EFAULT);

	ino = partial_iget.ino;
	num_devs_ret = partial_iget.num_devs_ret;

	partial_iget.num_devs_ret = 0;		/* Assume error for now. */
	partial_iget.status = PCITOOL_INVALID_INO;
	rval = EINVAL;

	/* Validate argument. */
	if (partial_iget.ino > pxtool_num_inos) {
		goto done_get_intr;
	}

	/* Caller wants device information returned. */
	if (num_devs_ret > 0) {

		/*
		 * Allocate room.
		 * Note if num_devs == 0 iget remains pointing to
		 * partial_iget.
		 */
		iget_kmem_alloc_size = PCITOOL_IGET_SIZE(num_devs_ret);
		iget = kmem_alloc(iget_kmem_alloc_size, KM_SLEEP);

		/* Read in whole structure to verify there's room. */
		if (ddi_copyin(arg, iget, iget_kmem_alloc_size, mode) !=
		    SUCCESS) {

			/* Be consistent and just return EFAULT here. */
			kmem_free(iget, iget_kmem_alloc_size);

			return (EFAULT);
		}
	}

	bzero(iget, PCITOOL_IGET_SIZE(num_devs_ret));
	iget->ino = ino;
	iget->num_devs_ret = num_devs_ret;

	/* Convert leaf-wide intr to system-wide intr */
	if (px_lib_intr_devino_to_sysino(dip, iget->ino, &sysino) ==
	    DDI_FAILURE) {
		iget->status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_get_intr;
	}

	/* Operate only on inos which are already enabled. */
	if (px_lib_intr_getvalid(dip, sysino, &intr_valid_state) ==
	    DDI_FAILURE) {
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
		 * The following looks up the px_ib_ino_info and returns
		 * info of devices mapped to this ino.
		 */
		iget->num_devs = pxtool_ib_get_ino_devs(
		    px_p, ino, &iget->num_devs_ret, iget->dev);

		if (px_lib_intr_gettarget(dip, sysino, &old_cpu_id) ==
		    DDI_FAILURE) {
			iget->status = PCITOOL_IO_ERROR;
			rval = EIO;
			goto done_get_intr;
		}
		iget->cpu_id = old_cpu_id;
	}

	iget->status = PCITOOL_SUCCESS;
	rval = SUCCESS;

done_get_intr:
	copyout_rval =
	    ddi_copyout(iget, arg, PCITOOL_IGET_SIZE(num_devs_ret), mode);

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
	px_t *px_p = DIP_TO_STATE(dip);
	px_ib_t *ib_p = px_p->px_ib_p;
	uint8_t zero = 0;
	int rval = SUCCESS;

	if (ddi_copyin(arg, &iset, sizeof (pcitool_intr_set_t), mode) !=
	    DDI_SUCCESS)
		return (EFAULT);

	iset.status = PCITOOL_INVALID_INO;
	rval = EINVAL;

	/* Validate input argument. */
	if (iset.ino > pxtool_num_inos)
		goto done_set_intr;

	/* Validate that ino given belongs to a device. */
	if (pxtool_ib_get_ino_devs(px_p, iset.ino, &zero, NULL) == 0)
		goto done_set_intr;

	/*
	 * Get lock, validate cpu and write new mapreg value.
	 * Return original cpu value to caller via iset.cpu.
	 */
	mutex_enter(&cpu_lock);
	if (pxtool_validate_cpuid(iset.cpu_id)) {

		DBG(DBG_TOOLS, dip, "Enabling CPU %d\n", iset.cpu_id);

		if (px_lib_intr_devino_to_sysino(dip, iset.ino, &sysino) ==
		    DDI_FAILURE)
			goto done_set_intr;

		if (px_lib_intr_gettarget(dip, sysino, &old_cpu_id) ==
		    DDI_FAILURE)
			goto done_set_intr;

		px_ib_intr_dist_en(dip, iset.cpu_id, iset.ino, B_TRUE);

		px_ib_log_new_cpu(ib_p, old_cpu_id, iset.cpu_id, iset.ino);

		iset.cpu_id = old_cpu_id;
		iset.status = PCITOOL_SUCCESS;
		rval = SUCCESS;

	} else {	/* Invalid cpu.  Restore original register image. */

		DBG(DBG_TOOLS, dip,
		    "Invalid cpuid: writing orig mapreg value\n");

		iset.status = PCITOOL_INVALID_CPUID;
		rval = EINVAL;
	}
	mutex_exit(&cpu_lock);

done_set_intr:
	if (ddi_copyout(&iset, arg, sizeof (pcitool_intr_set_t), mode) !=
	    DDI_SUCCESS)
		rval = EFAULT;

	return (rval);
}


/* Main function for handling interrupt CPU binding requests and queries. */
int
pxtool_intr(dev_info_t *dip, void *arg, int cmd, int mode)
{
	int rval = SUCCESS;

	switch (cmd) {

	/* Return the number of interrupts supported by a PCI bus. */
	case PCITOOL_DEVICE_NUM_INTR:
		rval = pxtool_intr_get_max_ino(arg, mode);
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
	px_ranges_t	*rp;
	uint64_t range_base;
	int rval;
	dev_info_t *dip = px_p->px_dip;
	uint32_t base_offset = 0;
	extern uint64_t px_get_range_prop(px_t *, px_ranges_t *, int);

	/*
	 * Assume that requested entity is small enough to be on the same page.
	 * (Same starting and ending value "offset" passed to px_search_ranges.)
	 * PCItool checks alignment so that this will be true for single
	 * accesses.
	 *
	 * Base_offset is the offset from the specified address, where the
	 * current range begins.  This is nonzero when a PCI space is split and
	 * the address is inside the second or subsequent range.
	 *
	 * NOTE: offset is a uint64_t but px_search_ranges takes a uint32_t.
	 * px_search_ranges should also take a uint64_t for base_offset.
	 * RFE is to have px_search_ranges handle a uint64_t offset.
	 */
	rval = px_search_ranges(px_p, space, offset, offset, &rp,
	    (uint32_t *)&base_offset);
	DBG(DBG_TOOLS, dip,
	    "space:0x%d, offset:0x%" PRIx64 ", base_offset:0x%" PRIx64 "\n",
	    space, offset, base_offset);

	if (rval != DDI_SUCCESS)
		return (NULL);
	else {
		range_base = px_get_range_prop(px_p, rp, 0);
		DBG(DBG_TOOLS, dip, "range base:0x%" PRIx64 "\n", range_base);
		return (base_offset + range_base);
	}
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
	off_in_space = (PX_GET_BDF(prg_p) << PX_PCI_BDF_OFFSET_DELTA) +
	    cfg_prg.offset;
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

		off_in_space = (PX_GET_BDF(&prg) << PX_PCI_BDF_OFFSET_DELTA) +
		    (uint32_t)prg.offset;

		/*
		 * For sun4v, config space base won't be known.
		 * pxtool_get_phys_addr will return zero.
		 * Note that for sun4v, phys_addr isn't
		 * used for making config space accesses.
		 *
		 * For sun4u, assume that phys_addr will come back valid.
		 */

		/* Accessed entity is assumed small enough to be on one page. */
		prg.phys_addr = pxtool_get_phys_addr(px_p, PCI_CONFIG_SPACE,
		    off_in_space);

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
	    PCIHP_AP_MINOR_NUM(instance, PCI_TOOL_REG_MINOR_NUM),
	    DDI_NT_REGACC, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, PCI_MINOR_INTR, S_IFCHR,
	    PCIHP_AP_MINOR_NUM(instance, PCI_TOOL_INTR_MINOR_NUM),
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
