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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/scsi/adapters/smrt/smrt.h>

/*
 * We must locate what the CISS specification describes as the "I2O
 * registers".  The Intelligent I/O (I2O) Architecture Specification describes
 * this somewhat more coherently as "the memory region specified by the first
 * base address configuration register indicating memory space (offset 10h,
 * 14h, and so forth)".
 */
static int
smrt_locate_bar(pci_regspec_t *regs, unsigned nregs,
    unsigned *i2o_bar)
{
	/*
	 * Locate the first memory-mapped BAR:
	 */
	for (unsigned i = 0; i < nregs; i++) {
		unsigned type = regs[i].pci_phys_hi & PCI_ADDR_MASK;

		if (type == PCI_ADDR_MEM32 || type == PCI_ADDR_MEM64) {
			*i2o_bar = i;
			return (DDI_SUCCESS);
		}
	}

	return (DDI_FAILURE);
}

static int
smrt_locate_cfgtbl(smrt_t *smrt, pci_regspec_t *regs, unsigned nregs,
    unsigned *ct_bar, uint32_t *baseaddr)
{
	uint32_t cfg_offset, mem_offset;
	unsigned want_type;
	uint32_t want_bar;

	cfg_offset = smrt_get32(smrt, CISS_I2O_CFGTBL_CFG_OFFSET);
	mem_offset = smrt_get32(smrt, CISS_I2O_CFGTBL_MEM_OFFSET);

	VERIFY3U(cfg_offset, !=, 0xffffffff);
	VERIFY3U(mem_offset, !=, 0xffffffff);

	/*
	 * Locate the Configuration Table.  Three different values read
	 * from two I2O registers allow us to determine the location:
	 * 	- the correct PCI BAR offset is in the low 16 bits of
	 *	  CISS_I2O_CFGTBL_CFG_OFFSET
	 *	- bit 16 is 0 for a 32-bit space, and 1 for 64-bit
	 *	- the memory offset from the base of this BAR is
	 *	  in CISS_I2O_CFGTBL_MEM_OFFSET
	 */
	want_bar = (cfg_offset & 0xffff);
	want_type = (cfg_offset & (1UL << 16)) ? PCI_ADDR_MEM64 :
	    PCI_ADDR_MEM32;

	DTRACE_PROBE4(locate_cfgtbl, uint32_t, want_bar, unsigned,
	    want_type, uint32_t, cfg_offset, uint32_t, mem_offset);

	for (unsigned i = 0; i < nregs; i++) {
		unsigned type = regs[i].pci_phys_hi & PCI_ADDR_MASK;
		unsigned bar = PCI_REG_REG_G(regs[i].pci_phys_hi);

		if (type != PCI_ADDR_MEM32 && type != PCI_ADDR_MEM64) {
			continue;
		}

		if (bar == want_bar) {
			*ct_bar = i;
			*baseaddr = mem_offset;
			return (DDI_SUCCESS);
		}
	}

	return (DDI_FAILURE);
}

static int
smrt_map_device(smrt_t *smrt)
{
	pci_regspec_t *regs;
	uint_t regslen, nregs;
	dev_info_t *dip = smrt->smrt_dip;
	int r = DDI_FAILURE;

	/*
	 * Get the list of PCI registers from the DDI property "regs":
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&regs, &regslen) != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN, "could not load \"reg\" DDI prop");
		return (DDI_FAILURE);
	}
	nregs = regslen * sizeof (int) / sizeof (pci_regspec_t);

	if (smrt_locate_bar(regs, nregs, &smrt->smrt_i2o_bar) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "did not find any memory BARs");
		goto out;
	}

	/*
	 * Map enough of the I2O memory space to enable us to talk to the
	 * device.
	 */
	if (ddi_regs_map_setup(dip, smrt->smrt_i2o_bar, &smrt->smrt_i2o_space,
	    CISS_I2O_MAP_BASE, CISS_I2O_MAP_LIMIT - CISS_I2O_MAP_BASE,
	    &smrt_dev_attributes, &smrt->smrt_i2o_handle) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to map I2O registers");
		goto out;
	}
	smrt->smrt_init_level |= SMRT_INITLEVEL_I2O_MAPPED;

	if (smrt_locate_cfgtbl(smrt, regs, nregs, &smrt->smrt_ct_bar,
	    &smrt->smrt_ct_baseaddr) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not find config table");
		goto out;
	}

	/*
	 * Map the Configuration Table.
	 */
	if (ddi_regs_map_setup(dip, smrt->smrt_ct_bar,
	    (caddr_t *)&smrt->smrt_ct, smrt->smrt_ct_baseaddr,
	    sizeof (CfgTable_t), &smrt_dev_attributes,
	    &smrt->smrt_ct_handle) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not map config table");
		goto out;
	}
	smrt->smrt_init_level |= SMRT_INITLEVEL_CFGTBL_MAPPED;

	r = DDI_SUCCESS;

out:
	ddi_prop_free(regs);
	return (r);
}

int
smrt_device_setup(smrt_t *smrt)
{
	/*
	 * Ensure that the controller is installed in such a fashion that it
	 * may become a DMA master.
	 */
	if (ddi_slaveonly(smrt->smrt_dip) == DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_WARN, "device cannot become DMA "
		    "master");
		return (DDI_FAILURE);
	}

	if (smrt_map_device(smrt) != DDI_SUCCESS) {
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	smrt_device_teardown(smrt);
	return (DDI_FAILURE);
}

void
smrt_device_teardown(smrt_t *smrt)
{
	if (smrt->smrt_init_level & SMRT_INITLEVEL_CFGTBL_MAPPED) {
		ddi_regs_map_free(&smrt->smrt_ct_handle);
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_CFGTBL_MAPPED;
	}

	if (smrt->smrt_init_level & SMRT_INITLEVEL_I2O_MAPPED) {
		ddi_regs_map_free(&smrt->smrt_i2o_handle);
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_I2O_MAPPED;
	}
}

uint32_t
smrt_get32(smrt_t *smrt, offset_t off)
{
	VERIFY3S(off, >=, CISS_I2O_MAP_BASE);
	VERIFY3S(off, <, CISS_I2O_MAP_BASE + CISS_I2O_MAP_LIMIT);

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	uint32_t *addr = (uint32_t *)(smrt->smrt_i2o_space +
	    (off - CISS_I2O_MAP_BASE));

	return (ddi_get32(smrt->smrt_i2o_handle, addr));
}

void
smrt_put32(smrt_t *smrt, offset_t off, uint32_t val)
{
	VERIFY3S(off, >=, CISS_I2O_MAP_BASE);
	VERIFY3S(off, <, CISS_I2O_MAP_BASE + CISS_I2O_MAP_LIMIT);

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	uint32_t *addr = (uint32_t *)(smrt->smrt_i2o_space +
	    (off - CISS_I2O_MAP_BASE));

	ddi_put32(smrt->smrt_i2o_handle, addr, val);
}
